//! M8-T026 T004: 端到端测试（本机回环 TCP + fake 本地服务）。
//!
//! 覆盖验收标准（主文档 §6）：字节流一致 / 并发精确配对 / 心跳判死 /
//! 退避重连 + 全量重注册 / 级联清理 / token 拒绝 / 速率限制封禁 /
//! 审计事件 / 协议版本协商。全部经短间隔参数注入（TNL-STAB-003 单测口径）。

use crate::audit::{AuditSink, TunnelAuditEvent};
use crate::client::{ProxySpec, TunnelClient, TunnelClientConfig};
use crate::protocol::{
    decode_control, encode_control, read_frame, ControlMsg, PROTOCOL_VERSION,
};
use crate::rate_limit::RateLimiterConfig;
use crate::server::{TunnelServer, TunnelServerConfig};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 测试审计收集器。
#[derive(Debug, Default)]
struct AuditCollector(Mutex<Vec<TunnelAuditEvent>>);

impl AuditSink for AuditCollector {
    fn record(&self, event: TunnelAuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

impl AuditCollector {
    fn count(&self, f: impl Fn(&TunnelAuditEvent) -> bool) -> usize {
        self.0.lock().unwrap().iter().filter(|e| f(e)).count()
    }
}

/// 轮询等待条件成立（20ms 间隔）。
async fn wait_for(mut cond: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}

/// fake 本地服务：echo（收到的字节原样返回）。
async fn spawn_echo_service() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// 测试服务端配置（控制端口 0 = 系统分配；短心跳/短 work 超时）。
///
/// 端口范围随机化（M8-T026-P2 起）：多个 e2e 测试并发运行时共享固定
/// `(40000, 40200)` 会互相抢端口导致 flaky —— 每实例取随机 256 端口子范围。
fn server_cfg(token: &str, audit: Option<Arc<dyn AuditSink>>) -> TunnelServerConfig {
    server_cfg_on(0, token, audit)
}

/// 指定控制端口的测试服务端配置（重启测试须复用同端口）。
fn server_cfg_on(
    bind_port: u16,
    token: &str,
    audit: Option<Arc<dyn AuditSink>>,
) -> TunnelServerConfig {
    let range_base = 40000 + (uuid::Uuid::new_v4().as_u128() % 2000) as u16;
    TunnelServerConfig {
        bind_port,
        token: token.to_string(),
        port_range: Some((range_base, range_base + 256)),
        heartbeat_timeout: Duration::from_millis(500),
        work_conn_timeout: Duration::from_secs(2),
        max_proxies: 32,
        max_concurrent_work: 100,
        rate_limit: RateLimiterConfig::default(),
        audit,
        // M8-T026-P2 (ID-SEC-001)：测试用临时服务器密钥，不污染真实 ~/.kirin_desk。
        server_key_path: Some(
            std::env::temp_dir().join(format!(
                "kirin_relay_test_key_{}.der",
                uuid::Uuid::new_v4()
            )),
        ),
    }
}

/// 测试客户端配置（短退避 + 正常心跳）。
fn client_cfg(
    server_port: u16,
    token: &str,
    proxies: Vec<ProxySpec>,
    backoff_base: Duration,
) -> TunnelClientConfig {
    TunnelClientConfig {
        server_addr: format!("[::1]:{}", server_port),
        token: token.to_string(),
        hostname: "test-client".to_string(),
        heartbeat_interval: Duration::from_millis(100),
        heartbeat_timeout: Duration::from_millis(300),
        connect_timeout: Duration::from_secs(2),
        local_dial_timeout: Duration::from_millis(500),
        backoff_base,
        backoff_max: Duration::from_millis(1000),
        proxies,
    }
}

fn echo_proxy(local_port: u16) -> ProxySpec {
    ProxySpec {
        name: "echo".to_string(),
        local_addr: "127.0.0.1".to_string(),
        local_port,
        remote_port: 0, // 服务端分配
    }
}

/// 等待客户端登录并注册全部代理，返回 (name, 公网端口)。
async fn wait_registered(client: &TunnelClient, timeout: Duration) -> Option<(String, u16)> {
    let ok = wait_for(
        || {
            let s = client.status();
            s.connected && !s.proxies.is_empty()
        },
        timeout,
    )
    .await;
    if !ok {
        return None;
    }
    client.status().proxies.into_iter().next()
}

/// 通过公网端口做一次 echo 往返（发送 payload，校验原样返回）。
async fn echo_roundtrip(pub_port: u16, payload: &[u8]) -> bool {
    let mut stream = match TcpStream::connect(format!("[::1]:{}", pub_port)).await {
        Ok(s) => s,
        Err(_) => return false,
    };
    if stream.write_all(payload).await.is_err() {
        return false;
    }
    let mut buf = vec![0u8; payload.len()];
    match tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => buf == payload,
        _ => false,
    }
}

/// 手工登录（返回 LoginResp.ok；连接失败/无应答返回 None）。
async fn raw_login(server_port: u16, token: &str, version: &str) -> Option<bool> {
    let mut stream = TcpStream::connect(format!("[::1]:{}", server_port)).await.ok()?;
    let frame = encode_control(&ControlMsg::Login {
        token: token.to_string(),
        version: version.to_string(),
        hostname: "raw".to_string(),
        device_id: None,
        ed25519_pub: None,
    })
    .ok()?;
    stream.write_all(&frame).await.ok()?;
    let (ty, payload) = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(&mut stream),
    )
    .await
    .ok()?
    .ok()?;
    match decode_control(ty, &payload).ok()? {
        ControlMsg::LoginResp { ok, .. } => Some(ok),
        _ => None,
    }
}

#[tokio::test]
async fn test_end_to_end_echo_and_audit() {
    // 端到端：fake echo 服务 → client → server → 公网端口，字节流一致。
    // 同时验证审计事件序列（TNL-SEC-003）。
    let audit = Arc::new(AuditCollector::default());
    let echo_port = spawn_echo_service().await;
    let server = TunnelServer::bind(server_cfg("secret", Some(audit.clone()))).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());
    let client = Arc::new(TunnelClient::new(client_cfg(
        server_port,
        "secret",
        vec![echo_proxy(echo_port)],
        Duration::from_millis(50),
    )));
    let c = client.clone();
    let cli_task = tokio::spawn(async move { c.run().await });

    let (name, pub_port) = wait_registered(&client, Duration::from_secs(5))
        .await
        .expect("client should register proxy");
    assert_eq!(name, "echo");
    assert!(pub_port > 0);

    // 数据面：公网端口 → 内网 echo 服务，双向字节一致。
    assert!(
        echo_roundtrip(pub_port, b"hello kirin relay").await,
        "echo roundtrip should pass"
    );
    let big = vec![0xABu8; 64 * 1024]; // 64 KiB 大帧
    assert!(
        echo_roundtrip(pub_port, &big).await,
        "large echo roundtrip should pass"
    );

    // 审计事件序列（登录成功 / 代理注册 / work 开 / work 关）。
    assert!(wait_for(
        || {
            audit.count(|e| matches!(e, TunnelAuditEvent::WorkConnOpened { .. })) >= 1
                && audit.count(|e| matches!(e, TunnelAuditEvent::WorkConnClosed { .. })) >= 1
        },
        Duration::from_secs(3)
    )
    .await);
    assert_eq!(
        audit.count(|e| matches!(e, TunnelAuditEvent::LoginSuccess { .. })),
        1
    );
    assert_eq!(
        audit.count(|e| matches!(e, TunnelAuditEvent::ProxyRegistered { .. })),
        1
    );

    client.stop();
    let _ = tokio::time::timeout(Duration::from_secs(3), cli_task).await;
    srv_task.abort();
}

#[tokio::test]
async fn test_concurrent_pairs() {
    // ≥10 并发数据连接按 (session, proxy_name, conn_id) 精确配对（TNL-SERVER-005）。
    let echo_port = spawn_echo_service().await;
    let server = TunnelServer::bind(server_cfg("secret", None)).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());
    let client = Arc::new(TunnelClient::new(client_cfg(
        server_port,
        "secret",
        vec![echo_proxy(echo_port)],
        Duration::from_millis(50),
    )));
    let c = client.clone();
    let cli_task = tokio::spawn(async move { c.run().await });

    let (_name, pub_port) = wait_registered(&client, Duration::from_secs(5))
        .await
        .expect("proxy should register");

    let mut handles = Vec::new();
    for i in 0..10u32 {
        let payload = format!("conn-{:02}-payload", i).into_bytes();
        handles.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(format!("[::1]:{}", pub_port)).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            let mut buf = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(buf, payload, "conn {i} echo mismatch");
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    client.stop();
    let _ = tokio::time::timeout(Duration::from_secs(3), cli_task).await;
    srv_task.abort();
}

#[tokio::test]
async fn test_heartbeat_timeout_cascade_cleanup() {
    // 服务端心跳判死（TNL-SERVER-007/TNL-STAB-002）：客户端注册后不再活跃
    // （长心跳间隔注入），服务端判死 → 级联清理 → 公网端口关闭。
    let audit = Arc::new(AuditCollector::default());
    let echo_port = spawn_echo_service().await;
    let mut cfg = server_cfg("secret", Some(audit.clone()));
    cfg.heartbeat_timeout = Duration::from_millis(200); // 服务端 200ms 判死
    let server = TunnelServer::bind(cfg).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());
    let mut client_cfg = client_cfg(
        server_port,
        "secret",
        vec![echo_proxy(echo_port)],
        Duration::from_secs(60), // 长退避：判死后不立即重连（避免端口复活）
    );
    client_cfg.heartbeat_interval = Duration::from_secs(10); // 客户端不活跃
    client_cfg.heartbeat_timeout = Duration::from_secs(30);
    let client = Arc::new(TunnelClient::new(client_cfg));
    let c = client.clone();
    let cli_task = tokio::spawn(async move { c.run().await });

    let (_name, pub_port) = wait_registered(&client, Duration::from_secs(5))
        .await
        .expect("proxy should register");
    assert!(echo_roundtrip(pub_port, b"alive").await);

    // 服务端 ~200ms 无帧 → 判死 → 级联清理。
    let cleaned = wait_for(
        || {
            std::net::TcpStream::connect_timeout(
                &format!("[::1]:{}", pub_port).parse().unwrap(),
                Duration::from_millis(100),
            )
            .is_err()
        },
        Duration::from_secs(5),
    )
    .await;
    assert!(cleaned, "proxy port should be closed after cascade cleanup");
    assert!(
        wait_for(
            || audit.count(|e| matches!(e, TunnelAuditEvent::ProxyRemoved { .. })) >= 1,
            Duration::from_secs(3)
        )
        .await,
        "cascade cleanup should emit ProxyRemoved audit"
    );

    client.stop();
    let _ = tokio::time::timeout(Duration::from_secs(3), cli_task).await;
    srv_task.abort();
}

#[tokio::test]
async fn test_reconnect_and_reregister() {
    // 退避重连（TNL-STAB-003）：服务端重启 → 客户端判死 → 短退避重连 →
    // 全量重注册 → 数据面恢复。
    let echo_port = spawn_echo_service().await;
    let server = TunnelServer::bind(server_cfg("secret", None)).await.unwrap();
    let server_port = server.port();
    // 优雅关闭句柄须在 run() 移走 server 前取得。
    let server_handle = server.shutdown_handle();
    let srv_task = tokio::spawn(server.run());
    let client = Arc::new(TunnelClient::new(client_cfg(
        server_port,
        "secret",
        vec![echo_proxy(echo_port)],
        Duration::from_millis(50),
    )));
    let c = client.clone();
    let cli_task = tokio::spawn(async move { c.run().await });

    let (_name, pub_port) = wait_registered(&client, Duration::from_secs(5))
        .await
        .expect("first registration");
    assert!(echo_roundtrip(pub_port, b"before restart").await);

    // 服务端重启（同端口）：优雅关闭（TNL-SERVER-006 扩展）→ 会话级联清理
    // → 客户端判死重连 → 新实例绑定原端口。
    server_handle.shutdown();
    srv_task.abort();
    let server2 = TunnelServer::bind(server_cfg_on(server_port, "secret", None))
        .await
        .unwrap();
    let srv2_task = tokio::spawn(server2.run());

    // 客户端应自动重连并全量重注册（退避 50ms 起）。
    let reconnected = wait_for(
        || {
            let s = client.status();
            println!(
                "DBG: status connected={} reconnect={} proxies={:?}",
                s.connected, s.reconnect_count, s.proxies
            );
            s.connected && s.reconnect_count >= 1 && !s.proxies.is_empty()
        },
        Duration::from_secs(8),
    )
    .await;
    assert!(reconnected, "client should reconnect and re-register");
    let (_name2, pub_port2) = client.status().proxies.into_iter().next().unwrap();
    println!("DBG: after restart pub_port2={}", pub_port2);
    let ok = echo_roundtrip(pub_port2, b"after restart").await;
    println!("DBG: after restart echo ok={}", ok);
    assert!(ok);

    client.stop();
    let _ = tokio::time::timeout(Duration::from_secs(3), cli_task).await;
    srv2_task.abort();
}

#[tokio::test]
async fn test_client_disconnect_cascade() {
    // 级联清理（TNL-SERVER-006）：frpc 断开 → frps 全部代理端口关闭。
    let audit = Arc::new(AuditCollector::default());
    let echo_port = spawn_echo_service().await;
    let server = TunnelServer::bind(server_cfg("secret", Some(audit.clone())))
        .await
        .unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());
    let client = Arc::new(TunnelClient::new(client_cfg(
        server_port,
        "secret",
        vec![echo_proxy(echo_port)],
        Duration::from_secs(60), // 长退避：断开后不重连
    )));
    let c = client.clone();
    let cli_task = tokio::spawn(async move { c.run().await });

    let (_name, pub_port) = wait_registered(&client, Duration::from_secs(5))
        .await
        .expect("proxy should register");

    // 强制断开控制连接（abort 客户端任务 = 连接立刻关闭）。
    cli_task.abort();

    let cleaned = wait_for(
        || {
            std::net::TcpStream::connect_timeout(
                &format!("[::1]:{}", pub_port).parse().unwrap(),
                Duration::from_millis(100),
            )
            .is_err()
        },
        Duration::from_secs(5),
    )
    .await;
    assert!(cleaned, "proxy port should close after client disconnect");
    assert!(
        wait_for(
            || audit.count(|e| matches!(e, TunnelAuditEvent::ProxyRemoved { .. })) >= 1,
            Duration::from_secs(3)
        )
        .await,
        "cascade cleanup should emit ProxyRemoved audit"
    );
    srv_task.abort();
}

#[tokio::test]
async fn test_wrong_token_rejected_and_audited() {
    // token 错误 → LoginResp{ok:false} + 审计（TNL-SEC-001/003）。
    let audit = Arc::new(AuditCollector::default());
    let server = TunnelServer::bind(server_cfg("secret", Some(audit.clone())))
        .await
        .unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    assert_eq!(
        raw_login(server_port, "wrong-token", PROTOCOL_VERSION).await,
        Some(false),
        "wrong token should be rejected"
    );
    assert!(wait_for(
        || {
            audit.count(|e| matches!(e, TunnelAuditEvent::LoginFailed { .. })) >= 1
        },
        Duration::from_secs(2)
    )
    .await);
    // 登录被拒 → 无会话建立。
    assert_eq!(audit.count(|e| matches!(e, TunnelAuditEvent::LoginSuccess { .. })), 0);
    srv_task.abort();
}

#[tokio::test]
async fn test_version_mismatch_rejected() {
    // 主版本不兼容 → LoginResp{ok:false}（TNL-PROTO-008）。
    let server = TunnelServer::bind(server_cfg("secret", None)).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    assert_eq!(
        raw_login(server_port, "secret", "0.9.0").await,
        Some(false),
        "incompatible major version should be rejected"
    );
    // 兼容版本应成功。
    assert_eq!(
        raw_login(server_port, "secret", PROTOCOL_VERSION).await,
        Some(true)
    );
    srv_task.abort();
}

#[tokio::test]
async fn test_rate_limit_ban() {
    // 速率限制（TNL-SEC-002）：小阈值参数注入 → 2 次认证失败触发封禁 →
    // 后续连接被直接丢弃（无 LoginResp）+ 审计 RateLimited。
    let audit = Arc::new(AuditCollector::default());
    let mut cfg = server_cfg("secret", Some(audit.clone()));
    cfg.rate_limit = RateLimiterConfig {
        max_attempts: 3,
        attempt_window: Duration::from_secs(30),
        failure_threshold: 2, // 2 次失败即封禁（注入小阈值）
        ban_duration: Duration::from_secs(30),
    };
    let server = TunnelServer::bind(cfg).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    // 第 1、2 次错误 token → 拒绝（LoginResp{ok:false}）。
    assert_eq!(
        raw_login(server_port, "bad", PROTOCOL_VERSION).await,
        Some(false)
    );
    assert_eq!(
        raw_login(server_port, "bad", PROTOCOL_VERSION).await,
        Some(false)
    );
    // 第 3 次：封禁中 → 连接被直接丢弃（读不到 LoginResp）。
    assert!(
        raw_login(server_port, "bad", PROTOCOL_VERSION).await.is_none(),
        "banned client should get no LoginResp"
    );
    assert!(wait_for(
        || audit.count(|e| matches!(e, TunnelAuditEvent::RateLimited { .. })) >= 1,
        Duration::from_secs(3)
    )
    .await);
    // 封禁不影响合法 token（其他 IP 维度不受影响在此不验证，封禁只针对该 IP）。
    srv_task.abort();
}

#[tokio::test]
async fn test_close_proxy_unbinds_port() {
    // CloseProxy（TNL-PROTO-006）：frpc 控制连接发 CloseProxy →
    // 公网端口解绑（TNL-SERVER-003 反向）。
    let server = TunnelServer::bind(server_cfg("secret", None)).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    let pub_port = raw_register_then_close(server_port)
        .await
        .expect("raw session: login → newproxy → closeproxy");
    assert!(pub_port > 0);

    // CloseProxy 后端口应已解绑。
    let unbound = wait_for(
        || {
            std::net::TcpStream::connect_timeout(
                &format!("[::1]:{}", pub_port).parse().unwrap(),
                Duration::from_millis(100),
            )
            .is_err()
        },
        Duration::from_secs(3),
    )
    .await;
    assert!(unbound, "proxy port should be unbound after CloseProxy");
    srv_task.abort();
}

/// 手工控制会话：Login → NewProxy(remote_port=0) → CloseProxy，返回分配端口。
async fn raw_register_then_close(server_port: u16) -> Option<u16> {
    let mut s = TcpStream::connect(format!("[::1]:{}", server_port)).await.ok()?;
    let frame = encode_control(&ControlMsg::Login {
        token: "secret".to_string(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "raw".to_string(),
        device_id: None,
        ed25519_pub: None,
    })
    .ok()?;
    s.write_all(&frame).await.ok()?;
    let (ty, payload) = read_frame(&mut s).await.ok()?;
    if !matches!(
        decode_control(ty, &payload).ok()?,
        ControlMsg::LoginResp { ok: true, .. }
    ) {
        return None;
    }
    let frame = encode_control(&ControlMsg::NewProxy {
        name: "p".to_string(),
        local_addr: "127.0.0.1".to_string(),
        local_port: 1,
        remote_port: 0,
    })
    .ok()?;
    s.write_all(&frame).await.ok()?;
    let (ty, payload) = read_frame(&mut s).await.ok()?;
    let ControlMsg::ProxyResp {
        ok: true,
        assigned_port: Some(port),
        ..
    } = decode_control(ty, &payload).ok()?
    else {
        return None;
    };
    let frame = encode_control(&ControlMsg::CloseProxy { name: "p".to_string() }).ok()?;
    s.write_all(&frame).await.ok()?;
    Some(port)
}



/// M8-T025 打包验收：`[::]` 监听须接受 IPv4 客户端。
/// Windows 裸 AF_INET6 socket 默认 v6-only（bind 成功后 IPv4 连接被拒），
/// `bind_reuseaddr` 已显式 `set_only_v6(false)`；本测试在任何平台验证
/// 双栈可达（若环境禁用 IPv6 走 v4 回退监听，同样可连）。
#[tokio::test]
async fn test_server_dual_stack_accepts_ipv4() {
    let cfg = server_cfg("t", None);
    let server = TunnelServer::bind(cfg).await.unwrap();
    let port = server.port();
    let handle = server.shutdown_handle();
    let task = tokio::spawn(server.run());

    // IPv4 回环连 [::] 监听（双栈修复后 TCP 层应握手成功；首帧非法由
    // 服务端丢弃，本测试只验证可达性）。
    let res = tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await;
    handle.shutdown();
    let _ = task.await;

    assert!(
        matches!(res, Ok(Ok(_))),
        "IPv4 client must reach the [::] tunnel listener (port {port})"
    );
}
