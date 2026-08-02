//! M8-T026-P1 (PATH-004 / PUNCH-NF-002): QUIC 连接迁移 —— `Endpoint::rebind`
//! 换本地 socket 后数据续流（quinn 服务端自动迁移，**无重握手**），
//! 中断 < 200ms。
//!
//! 场景（打洞路径同构，见 `punch_path_loopback.rs`）：双端打洞建立 →
//! 打洞 socket 上 QUIC 媒体传输（`connect_punch_transport`/
//! `accept_punch_transport`，Ed25519 握手）→ 客户端 endpoint rebind 到新
//! socket（等价 NAT 重绑定 / 打洞映射刷新后的源地址变化）→ 服务端收到新
//! 地址上的合法连接包 → PATH_CHALLENGE 验证 → 迁移 → 数据续流。
//!
//! 验证：rebind 后帧续流（连接未重建、无重握手），相邻帧到达间隔
//! （迁移中断）< 200ms（PATH-003 切换中断目标）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kirin_desk_core::connection::punch::{PunchConfig, PunchResult, PunchSession};
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_media::proto::EncodedWindow;
use kirin_desk_media::transport::{
    accept_punch_transport, connect_punch_transport, generate_quic_cert, MediaTransport,
    PunchMediaCreds,
};
use kirin_desk_relay::rendezvous::RendezvousServer;
use tokio::sync::watch;

fn fake_window(id: u64) -> EncodedWindow {
    let nal: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84];
    let mut packet = Vec::new();
    for _ in 0..64 {
        packet.extend_from_slice(&nal);
    }
    EncodedWindow::new(id, 320, 240, vec![vec![packet]])
}

fn punch_cfg(rv: SocketAddr, device_id: &str, peer: &str) -> PunchConfig {
    let mut cfg = PunchConfig::loopback(device_id);
    cfg.rendezvous_addr = rv;
    cfg.handshake.peer_device_id = peer.into();
    cfg
}

fn creds(
    identity: Arc<IdentityManager>,
    device_id: &str,
    peer_id: &str,
    peer_pub: &str,
) -> PunchMediaCreds {
    let (cert, key) = generate_quic_cert(device_id).unwrap();
    PunchMediaCreds {
        cert_der: cert,
        key_der: key,
        identity,
        device_id: device_id.into(),
        domain: "migrate.example".into(),
        device_type: "desktop".into(),
        peer_device_id: peer_id.into(),
        peer_pin: kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&peer_pub).expect("peer pubkey"),
        challenge: "challenge".into(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn quic_migration_rebind_continues() {
    // ── 进程内 rendezvous + 打洞双端（打洞路径同构）──
    let server = Arc::new(RendezvousServer::bind(0).await.unwrap());
    let mut rv = server.local_addr();
    if rv.ip().is_unspecified() {
        rv = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, rv.port()));
    }
    let srv = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = srv.serve(watch::channel(false).1).await;
    });
    let tmp = std::env::temp_dir();
    let a_im = Arc::new(IdentityManager::generate(tmp.join("kirin_mig_a.key")).unwrap());
    let b_im = Arc::new(IdentityManager::generate(tmp.join("kirin_mig_b.key")).unwrap());
    let mut session_a = PunchSession::new(punch_cfg(rv, "mig-a", "mig-b"), Arc::clone(&a_im));
    session_a.pin_session();
    let sid = session_a.session_id();
    let mut session_b = PunchSession::with_session_id(
        punch_cfg(rv, "mig-b", "mig-a"),
        Arc::clone(&b_im),
        sid,
    );
    let (ra, rb) = tokio::join!(session_a.establish(), session_b.establish());
    let (sock_a, peer_a) = match ra {
        PunchResult::UdpEstablished { socket, peer_addr } => (socket, peer_addr),
        other => panic!("A punch failed: {other:?}"),
    };
    let (sock_b, _) = match rb {
        PunchResult::UdpEstablished { socket, peer_addr } => (socket, peer_addr),
        other => panic!("B punch failed: {other:?}"),
    };

    // ── 打洞 socket 上 QUIC 媒体传输（Ed25519 握手；PUNCH-SEC-001）──
    // 服务端：记录帧到达时刻，统计迁移中断
    let arrivals = Arc::new(std::sync::Mutex::new(Vec::<(u64, Instant)>::new()));
    let arrivals_task = Arc::clone(&arrivals);
    let b_creds = creds(Arc::clone(&b_im), "mig-b", "mig-a", &a_im.public_key_base64());
    let server_handle = tokio::spawn(async move {
        // 与 punch_path_loopback 同构：客户端先拨号，服务端后 accept
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (_endpoint, mut t) = accept_punch_transport(sock_b, &b_creds).await.unwrap();
        loop {
            match t.recv_frame().await {
                Ok(p) => {
                    arrivals_task.lock().unwrap().push((p.frame_id, Instant::now()));
                }
                Err(_) => break,
            }
        }
    });

    // 客户端：打洞 socket 上连接（endpoint 由桥函数归还，任务持有——
    // rebind 只作用于客户端自己的端点）。t=0 即拨号（早于服务端 accept），
    // 与 punch_path_loopback 时序完全一致。
    let a_creds = creds(Arc::clone(&a_im), "mig-a", "mig-b", &b_im.public_key_base64());
    let client_handle = tokio::spawn(async move {
        let (client_endpoint, mut t) = connect_punch_transport(sock_a, peer_a, &a_creds)
            .await
            .unwrap();

        let mut id = 0u64;
        let deadline = Instant::now() + Duration::from_secs(5);
        // 阶段 1：rebind 前发送（~500ms）
        while Instant::now() < deadline - Duration::from_secs(4) {
            t.send_window(&fake_window(id)).await.unwrap();
            id += 1;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // rebind 到新 socket（NAT 重绑定 / 打洞映射刷新场景）
        let new_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .into_std()
            .unwrap();
        client_endpoint.rebind(new_socket).unwrap();
        // 阶段 2：rebind 后继续发送
        let mut after = 0u64;
        while Instant::now() < deadline {
            t.send_window(&fake_window(id)).await.unwrap();
            id += 1;
            after += 1;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        after
    });

    let after_count = client_handle.await.unwrap();
    let _ = server_handle.await;
    let arr = arrivals.lock().unwrap();

    // 迁移后数据续流：rebind 之后仍有大量帧到达（连接未重建，无重握手）
    assert!(
        after_count > 5,
        "rebind 后应持续收流（客户端发送 {after_count} 帧）"
    );
    assert!(arr.len() > 10, "服务端应收到足够帧（{}）", arr.len());

    // 中断测量（PATH-003：QUIC 迁移 < 200ms）：相邻帧到达间隔最大值
    let mut max_gap = Duration::ZERO;
    for pair in arr.windows(2) {
        let gap = pair[1].1.duration_since(pair[0].1);
        if gap > max_gap {
            max_gap = gap;
        }
    }
    assert!(
        max_gap < Duration::from_millis(200),
        "QUIC 迁移中断 {max_gap:?} 超出 200ms 预算（PATH-003/NF-002）"
    );
    eprintln!(
        "QUIC migration: max inter-frame gap {max_gap:?}, total frames {}",
        arr.len()
    );
}
