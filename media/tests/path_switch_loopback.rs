//! M8-T026-P1 (PATH-003/004 + PUNCH-004): 换路决策与打洞升舱链路。
//!
//! - PATH-003：注入 M8-T014 风格指标（RTT 劣化 >30% / 丢包 >2%）→ 默认阈值
//!   （保持期 2s）内 `evaluate()` 触发换路决策；
//! - PATH-004 执行端：`PunchUpgrade` 事件流 → `punch_upgrade_*_task`
//!   （打洞 socket 建 QUIC 媒体传输）→ 推入会话 swap 通道（热替换），
//!   升舱建连 < 200ms（QUIC 迁移中断预算）。
//!
//! 覆盖验收：注入 RTT 劣化 2s 内触发切换；打洞升舱中断 <200ms。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kirin_desk_core::connection::path_manager::{
    PathKind, PathManager, PathMetrics, SwitchReason,
};
use kirin_desk_core::connection::punch::{PunchConfig, PunchResult, PunchSession};
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_media::transport::{
    generate_quic_cert, punch_upgrade_accept_task, punch_upgrade_connect_task, MediaTransport,
    PunchMediaCreds, PunchUpgrade, PunchUpgradeEvent,
};
use kirin_desk_relay::rendezvous::RendezvousServer;
use tokio::sync::{mpsc, watch};

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
        domain: "switch.example".into(),
        device_type: "desktop".into(),
        peer_device_id: peer_id.into(),
        peer_public_key_base64: peer_pub.into(),
        challenge: "challenge".into(),
    }
}

/// 进程内 rendezvous + 打洞双端（回环；返回身份供媒体凭据复用）。
#[allow(clippy::type_complexity)]
async fn punch_pair(
    dev_a: &str,
    dev_b: &str,
) -> (
    Arc<RendezvousServer>,
    PunchSession,
    PunchSession,
    Arc<IdentityManager>,
    Arc<IdentityManager>,
) {
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
    let im_a = Arc::new(IdentityManager::generate(tmp.join("kirin_sw_a.key")).unwrap());
    let im_b = Arc::new(IdentityManager::generate(tmp.join("kirin_sw_b.key")).unwrap());
    let mut a = PunchSession::new(punch_cfg(rv, dev_a, dev_b), Arc::clone(&im_a));
    a.pin_session();
    let b = PunchSession::with_session_id(punch_cfg(rv, dev_b, dev_a), Arc::clone(&im_b), a.session_id());
    (server, a, b, im_a, im_b)
}

#[tokio::test(flavor = "multi_thread")]
async fn path_manager_switch_within_2s() {
    // PATH-003：默认阈值（保持期 2s）——注入 RTT 劣化后 2s 内触发换路
    let mut m = PathManager::new();
    for k in [PathKind::Relay, PathKind::DirectV6, PathKind::PunchUdp] {
        m.register_path(k);
        m.on_path_state(k, active_state());
    }
    // 确认初始升舱（中继 → 直连）
    let upgrade = m.evaluate();
    assert_eq!(upgrade.len(), 1);
    assert_eq!(upgrade[0].from, PathKind::Relay);
    m.on_switch_completed(upgrade[0]);

    // 最优 DirectV6 RTT 10ms；PunchUdp（控制通道）RTT 30ms → 差 >30% 劣化
    m.on_metrics(PathKind::DirectV6, PathMetrics { rtt_ms: 10.0, loss_rate: 0.0, jitter_us: 0.0 });
    m.on_metrics(PathKind::PunchUdp, PathMetrics { rtt_ms: 30.0, loss_rate: 0.0, jitter_us: 0.0 });
    assert!(m.evaluate().is_empty(), "未到保持期不换路");

    // 劣化确认 + 换路决策：RTT 劣化注入后 ~2s（保持期）内触发
    let started = Instant::now();
    loop {
        let actions = m.evaluate();
        if !actions.is_empty() {
            assert_eq!(actions[0].from, PathKind::PunchUdp);
            assert_eq!(actions[0].to, PathKind::Relay);
            assert_eq!(actions[0].reason, SwitchReason::RttDegraded);
            break;
        }
        if started.elapsed() > Duration::from_secs(5) {
            panic!("2s 保持期内未触发换路（PATH-003）");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1900),
        "换路不应早于保持期（{elapsed:?}）"
    );
    eprintln!("PATH-003: switch decision after {elapsed:?} (hold 2s)");

    // 丢包劣化路径（PATH-003：丢包 >2%）
    let mut m2 = PathManager::new();
    m2.register_path(PathKind::Relay);
    m2.on_path_state(PathKind::Relay, active_state());
    m2.register_path(PathKind::PunchUdp);
    m2.on_path_state(PathKind::PunchUdp, active_state());
    let up = m2.evaluate();
    m2.on_switch_completed(up[0]);
    m2.on_metrics(PathKind::PunchUdp, PathMetrics { rtt_ms: 5.0, loss_rate: 0.03, jitter_us: 0.0 });
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let actions = m2.evaluate();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].reason, SwitchReason::LossDegraded);
}

fn active_state() -> kirin_desk_core::connection::path_manager::PathState {
    kirin_desk_core::connection::path_manager::PathState::Active
}

#[tokio::test(flavor = "multi_thread")]
async fn punch_upgrade_task_swaps_transport() {
    // PATH-004 执行端：打洞成功事件 → 升舱任务建 QUIC 媒体传输 →
    // swap 通道收到热替换；升舱建连 < 200ms（PATH-003 预算）。
    // 会话升舱源：服务端 accept 端 + 客户端 connect 端，各接 swap 通道。
    // 媒体凭据复用**打洞会话同身份**（与 punch_path_loopback 完全同构）。
    let (_server, mut session_a, mut session_b, im_a, im_b) =
        punch_pair("sw-a", "sw-b").await;

    // 打洞（双端并发）→ UDP 建立
    let (ra, rb) = tokio::join!(session_a.establish(), session_b.establish());
    let (sock_a, peer_a) = match ra {
        PunchResult::UdpEstablished { socket, peer_addr } => (socket, peer_addr),
        other => panic!("A punch failed: {other:?}"),
    };
    let (sock_b, _) = match rb {
        PunchResult::UdpEstablished { socket, peer_addr } => (socket, peer_addr),
        other => panic!("B punch failed: {other:?}"),
    };

    let (ev_tx, ev_rx) = mpsc::unbounded_channel::<PunchUpgradeEvent>();
    let (swap_tx, mut swap_rx) = mpsc::unbounded_channel::<Box<dyn MediaTransport>>();
    let stop = Arc::new(AtomicBool::new(false));

    let creds_a = creds(Arc::clone(&im_a), "sw-a", "sw-b", &im_b.public_key_base64());
    let upgrade_a = PunchUpgrade { events: ev_rx, creds: creds_a };
    let stop_a = Arc::clone(&stop);
    tokio::spawn(async move {
        punch_upgrade_connect_task(upgrade_a, swap_tx, stop_a).await;
    });

    let creds_b = creds(Arc::clone(&im_b), "sw-b", "sw-a", &im_a.public_key_base64());
    let (ev_tx_b, ev_rx_b) = mpsc::unbounded_channel::<PunchUpgradeEvent>();
    let (swap_tx_b, mut swap_rx_b) = mpsc::unbounded_channel::<Box<dyn MediaTransport>>();
    let upgrade_b = PunchUpgrade { events: ev_rx_b, creds: creds_b };
    let stop_b = Arc::clone(&stop);
    tokio::spawn(async move {
        punch_upgrade_accept_task(upgrade_b, swap_tx_b, stop_b).await;
    });

    // 注入打洞成功事件（模拟 PunchSession → 媒体层事件流）
    let started = Instant::now();
    ev_tx
        .send(PunchUpgradeEvent::UdpEstablished { socket: sock_a, peer_addr: peer_a })
        .unwrap();
    ev_tx_b
        .send(PunchUpgradeEvent::UdpEstablished { socket: sock_b, peer_addr: peer_a })
        .unwrap();

    // swap 通道收到打洞路径媒体传输（热替换就绪）
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        let _c = swap_rx.recv().await.expect("client swap");
        let _s = swap_rx_b.recv().await.expect("server swap");
    })
    .await
    .expect("upgrade timeout");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(200),
        "打洞升舱建连 {elapsed:?} 超出 200ms 预算（PATH-003/NF-002）"
    );
    stop.store(true, Ordering::Relaxed);
    eprintln!("PATH-004: punch upgrade transports ready in {elapsed:?}");
    let _ = got;
}
