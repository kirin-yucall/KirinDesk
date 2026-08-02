//! M8-T026-P1 (PUNCH-001 / PUNCH-SEC-001 / PUNCH-NF-001): 打洞路径 →
//! QUIC 媒体传输端到端。
//!
//! 全链路（进程内，无真实 NAT、无 FFmpeg）：
//!   进程内 RendezvousServer（候选交换）→ 双端 `PunchSession`（UDP 打洞，
//!   <2s，PUNCH-NF-001）→ 打洞 socket 直接运行 QUIC 媒体传输
//!   （`accept_punch_transport`/`connect_punch_transport`，Ed25519 双向握手
//!   PUNCH-SEC-001）→ VideoFormat + 窗口收发 + 控制反馈往返。
//!
//! 覆盖验收：UDP 打洞成功双端 QUIC 直连 <2s；打洞路径仍完成 Ed25519 握手。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kirin_desk_core::connection::punch::{
    PunchConfig, PunchResult, PunchSession,
};
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_media::proto::EncodedWindow;
use kirin_desk_media::transport::{
    accept_punch_transport, connect_punch_transport, generate_quic_cert, ControlMessage,
    MediaTransport, PunchMediaCreds,
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

/// 打洞媒体凭据（本端 + 对端身份互 pin）。
fn punch_creds(
    identity: Arc<IdentityManager>,
    device_id: &str,
    peer_device_id: &str,
    peer_pub: &str,
) -> PunchMediaCreds {
    let (cert, key) = generate_quic_cert(device_id).unwrap();
    PunchMediaCreds {
        cert_der: cert,
        key_der: key,
        identity,
        device_id: device_id.into(),
        domain: "punch.example".into(),
        device_type: "desktop".into(),
        peer_device_id: peer_device_id.into(),
        peer_pin: kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&peer_pub).expect("peer pubkey"),
        challenge: "challenge".into(),
    }
}

/// 打洞会话配置（回环 + 共享 session 由调用方固定）。
fn punch_cfg(rendezvous: SocketAddr, device_id: &str, peer_device_id: &str) -> PunchConfig {
    let mut cfg = PunchConfig::loopback(device_id);
    cfg.rendezvous_addr = rendezvous;
    cfg.handshake.peer_device_id = peer_device_id.into();
    cfg
}

#[tokio::test(flavor = "multi_thread")]
async fn punch_path_quic_media_e2e() {
    // ── 1. 进程内 rendezvous（PUNCH-006 边界：仅登记/互转）──
    let server = Arc::new(RendezvousServer::bind(0).await.unwrap());
    let mut rv = server.local_addr();
    if rv.ip().is_unspecified() {
        rv = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, rv.port()));
    }
    let srv = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = srv.serve(watch::channel(false).1).await;
    });

    // ── 2. 双端身份与打洞会话（同一 session_id，PUNCH-SEC-003）──
    let tmp = std::env::temp_dir();
    let a_im = Arc::new(IdentityManager::generate(tmp.join("kirin_punch_a.key")).unwrap());
    let b_im = Arc::new(IdentityManager::generate(tmp.join("kirin_punch_b.key")).unwrap());

    let mut session_a =
        PunchSession::new(punch_cfg(rv, "punch-a", "punch-b"), Arc::clone(&a_im));
    // 发起方（A）固定自身 session_id，对端复用（真实流程经现有控制连接告知）
    session_a.pin_session();
    let sid = session_a.session_id();
    let mut session_b = PunchSession::with_session_id(
        punch_cfg(rv, "punch-b", "punch-a"),
        Arc::clone(&b_im),
        sid,
    );

    // ── 3. UDP 打洞（PUNCH-001；<2s，PUNCH-NF-001）──
    let started = std::time::Instant::now();
    let (ra, rb) = tokio::join!(session_a.establish(), session_b.establish());
    let (sock_a, peer_a) = match ra {
        PunchResult::UdpEstablished { socket, peer_addr } => (socket, peer_addr),
        other => panic!("A punch failed: {other:?}"),
    };
    let (sock_b, _peer_b) = match rb {
        PunchResult::UdpEstablished { socket, peer_addr } => (socket, peer_addr),
        other => panic!("B punch failed: {other:?}"),
    };
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "UDP 打洞建连 {elapsed:?} 超出 2s（PUNCH-NF-001）"
    );

    // ── 4. 打洞 socket 上直接运行 QUIC 媒体传输（PUNCH-001）──
    //    服务端（被控端 punch-b）accept；客户端（控制端 punch-a）connect。
    //    endpoint 由各自任务持有到传输使用结束（quinn driver 生命周期）。
    let b_creds = punch_creds(Arc::clone(&b_im), "punch-b", "punch-a", &a_im.public_key_base64());
    let server_handle = tokio::spawn(async move {
    tokio::time::sleep(Duration::from_millis(100)).await;
        let (_endpoint, mut t) = accept_punch_transport(sock_b, &b_creds).await.unwrap();
        // 分辨率推送
        t.send_control(&ControlMessage::VideoFormat { width: 320, height: 240 })
            .await
            .unwrap();
        for i in 0..20u64 {
            t.send_window(&fake_window(i)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        t.conn().close("punch done");
    });

    let a_creds = punch_creds(Arc::clone(&a_im), "punch-a", "punch-b", &b_im.public_key_base64());
    let client_handle = tokio::spawn(async move {
        let (_endpoint, mut t) = connect_punch_transport(sock_a, peer_a, &a_creds).await.unwrap();
        // VideoFormat（Ed25519 握手已完成的证明：控制流可双向）
        let fmt = t.recv_control().await.unwrap();
        eprintln!("punch path client got: {fmt:?}");
        let mut got = 0u64;
        loop {
            match t.recv_frame().await {
                Ok(p) => {
                    got += 1;
                    assert_eq!(p.frame_id, got - 1, "帧序连续");
                }
                Err(_) => break,
            }
        }
        got
    });

    let got = tokio::time::timeout(Duration::from_secs(10), client_handle)
        .await
        .expect("client recv timeout")
        .unwrap();
    let _ = server_handle.await;
    assert!(got >= 20, "应收到全部 20 帧，实际 {got}");
    eprintln!("punch path e2e: {got} frames over punched QUIC path");
}
