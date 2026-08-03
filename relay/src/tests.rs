//! M8-T026 T004: 端到端测试（本机回环 TCP + fake 本地服务）。
//!
//! 覆盖验收标准（主文档 §6）：字节流一致 / 并发精确配对 / 心跳判死 /
//! 退避重连 + 全量重注册 / 级联清理 / token 拒绝 / 速率限制封禁 /
//! 审计事件 / 协议版本协商。全部经短间隔参数注入（TNL-STAB-003 单测口径）。

use crate::audit::{AuditSink, TunnelAuditEvent};
use crate::auth::{client_digest, random_nonce};
use crate::client::{ProxySpec, TunnelClient, TunnelClientConfig};
use crate::id_client::IdClientError;
use crate::protocol::{
    decode_control, decode_extension, encode_control, encode_extension, read_frame, Candidate,
    CandidateKind, CandidateRegister, ControlMsg, DeviceInfo, PeerCandidates, PunchResult,
    ResolveDevice, TunnelConn, TunnelResp, PROTOCOL_VERSION, TYPE_CANDIDATE_REGISTER,
    TYPE_DEVICE_INFO, TYPE_PEER_CANDIDATES, TYPE_PUNCH_RESULT, TYPE_RESOLVE_DEVICE,
    TYPE_TUNNEL_CONN, TYPE_TUNNEL_RESP,
};
use crate::rate_limit::RateLimiterConfig;
use crate::rendezvous::RendezvousServer;
use crate::server::{TunnelServer, TunnelServerConfig};
use std::net::SocketAddr;
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
        bind_addrs: Vec::new(), // S-24 (F-29)：默认双栈；自测显式回环绑定
        token: token.to_string(),
        port_range: Some((range_base, range_base + 256)),
        heartbeat_timeout: Duration::from_millis(500),
        work_conn_timeout: Duration::from_secs(2),
        max_proxies: 32,
        max_concurrent_work: 100,
        rate_limit: RateLimiterConfig::default(),
        tunnel_conn_rate_limit: RateLimiterConfig::tunnel_conn_default(),
        max_pending_tunnels: 256,
        max_pending_per_target: 16,
        audit,
        // M8-T026-P2 (ID-SEC-001)：测试用临时服务器密钥，不污染真实 ~/.kirin_desk。
        server_key_path: Some(
            std::env::temp_dir().join(format!(
                "kirin_relay_test_key_{}.der",
                uuid::Uuid::new_v4()
            )),
        ),
        // R-08b (S1)：默认不挂载 rendezvous（打洞帧测试用例显式注入）。
        rendezvous: None,
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

/// 手工认证（复用既有流，M8-T026-P3 探测流程）：
/// 探测 Login#1（auth_nonce，token 恒为空）→ 服务器挑战 → 证明 Login#2
/// （auth_digest）→ LoginResp。返回 `(ok, client_nonce, server_nonce, digest)`
/// 供重放等用例捕获；服务器直接应答（legacy / 版本拒绝 / 探测拒绝）→
/// 返回 `(ok, 零值, 零值, 空)`；连接失败/无应答/协议异常 → None。
async fn raw_auth_capture(
    stream: &mut TcpStream,
    token: &str,
    version: &str,
) -> Option<(bool, [u8; 16], [u8; 16], Vec<u8>)> {
    let client_nonce = random_nonce();
    let probe = ControlMsg::Login {
        token: String::new(),
        version: version.to_string(),
        hostname: "raw".to_string(),
        device_id: None,
        ed25519_pub: None,
        auth_nonce: Some(client_nonce),
        auth_digest: None,
    };
    stream.write_all(&encode_control(&probe).ok()?).await.ok()?;
    let (ty, payload) = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(stream),
    )
    .await
    .ok()?
    .ok()?;
    let msg = decode_control(ty, &payload).ok()?;
    match msg {
        ControlMsg::AuthChallenge { nonce: server_nonce } => {
            let digest = client_digest(token.as_bytes(), &server_nonce, &client_nonce);
            let proof = ControlMsg::Login {
                token: String::new(),
                version: version.to_string(),
                hostname: "raw".to_string(),
                device_id: None,
                ed25519_pub: None,
                auth_nonce: Some(client_nonce),
                auth_digest: Some(digest.clone()),
            };
            stream.write_all(&encode_control(&proof).ok()?).await.ok()?;
            let (ty, payload) = tokio::time::timeout(
                Duration::from_secs(2),
                read_frame(stream),
            )
            .await
            .ok()?
            .ok()?;
            match decode_control(ty, &payload).ok()? {
                ControlMsg::LoginResp { ok, .. } => {
                    Some((ok, client_nonce, server_nonce, digest))
                }
                _ => None,
            }
        }
        ControlMsg::LoginResp { ok, .. } => Some((ok, [0u8; 16], [0u8; 16], Vec::new())),
        _ => None,
    }
}

/// 手工登录（返回 LoginResp.ok；连接失败/无应答返回 None）。
async fn raw_login(server_port: u16, token: &str, version: &str) -> Option<bool> {
    let mut stream = TcpStream::connect(format!("[::1]:{}", server_port)).await.ok()?;
    raw_auth_capture(&mut stream, token, version).await.map(|r| r.0)
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
            s.connected && s.reconnect_count >= 1 && !s.proxies.is_empty()
        },
        Duration::from_secs(8),
    )
    .await;
    assert!(reconnected, "client should reconnect and re-register");
    let (_name2, pub_port2) = client.status().proxies.into_iter().next().unwrap();
    let ok = echo_roundtrip(pub_port2, b"after restart").await;
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

/// 手工控制会话：Login（探测流程）→ NewProxy(remote_port=0) → CloseProxy，
/// 返回分配端口。
async fn raw_register_then_close(server_port: u16) -> Option<u16> {
    let mut s = TcpStream::connect(format!("[::1]:{}", server_port)).await.ok()?;
    let (ok, ..) = raw_auth_capture(&mut s, "secret", PROTOCOL_VERSION).await?;
    if !ok {
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

// ════════════════════════════════════════════════════════════
// M8-T026-P3：挑战-响应认证 e2e（TNL-SEC-006~010）
// ════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_plain_token_login_rejected_and_audited() {
    // T1/T6：明文 token 登录（旧客户端 v1.0，无 auth 字段）连口令服务端 →
    // LoginResp{ok:false} + 错误文案含升级提示 + 审计 LoginFailed + 无会话。
    let audit = Arc::new(AuditCollector::default());
    let server = TunnelServer::bind(server_cfg("secret", Some(audit.clone())))
        .await
        .unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    let mut stream = TcpStream::connect(format!("[::1]:{}", server_port)).await.unwrap();
    let frame = encode_control(&ControlMsg::Login {
        token: "secret".to_string(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "raw".to_string(),
        device_id: None,
        ed25519_pub: None,
        auth_nonce: None,
        auth_digest: None,
    })
    .unwrap();
    stream.write_all(&frame).await.unwrap();
    let (ty, payload) = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    let ControlMsg::LoginResp { ok: false, err, .. } = decode_control(ty, &payload).unwrap() else {
        panic!("plain-text login must be rejected");
    };
    let err = err.unwrap_or_default();
    assert!(
        err.contains("upgrade client"),
        "error should hint upgrade: {err}"
    );
    assert!(
        wait_for(
            || audit.count(|e| matches!(e, TunnelAuditEvent::LoginFailed { .. })) >= 1,
            Duration::from_secs(2)
        )
        .await,
        "plain login failure should be audited"
    );
    assert_eq!(
        audit.count(|e| matches!(e, TunnelAuditEvent::LoginSuccess { .. })),
        0
    );
    srv_task.abort();
}

#[tokio::test]
async fn test_digest_as_first_frame_rejected() {
    // T3：digest 作首帧（未挑战先证明）→ 拒绝 + 审计（不进入挑战）。
    let audit = Arc::new(AuditCollector::default());
    let server = TunnelServer::bind(server_cfg("secret", Some(audit.clone())))
        .await
        .unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    let mut stream = TcpStream::connect(format!("[::1]:{}", server_port)).await.unwrap();
    let frame = encode_control(&ControlMsg::Login {
        token: String::new(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "raw".to_string(),
        device_id: None,
        ed25519_pub: None,
        auth_nonce: Some([1u8; 16]),
        auth_digest: Some(vec![1, 2, 3]), // 未挑战先证明
    })
    .unwrap();
    stream.write_all(&frame).await.unwrap();
    let (ty, payload) = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    let ControlMsg::LoginResp { ok: false, .. } = decode_control(ty, &payload).unwrap() else {
        panic!("digest as first frame must be rejected");
    };
    assert!(
        wait_for(
            || audit.count(|e| matches!(e, TunnelAuditEvent::LoginFailed { .. })) >= 1,
            Duration::from_secs(2)
        )
        .await,
        "rejection should be audited"
    );
    srv_task.abort();
}

#[tokio::test]
async fn test_replay_nonce_digest_pair_rejected() {
    // T3/TNL-NF-006：重放旧 (client_nonce, server_nonce, digest) 对 →
    // 新连接 server_nonce 每连接全新 → 验证失败拒绝。
    let audit = Arc::new(AuditCollector::default());
    let server = TunnelServer::bind(server_cfg("secret", Some(audit.clone())))
        .await
        .unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    // 1. 合法登录，捕获 (client_nonce, server_nonce, digest)。
    let mut s1 = TcpStream::connect(format!("[::1]:{}", server_port)).await.unwrap();
    let (ok, client_nonce, server_nonce, digest) = raw_auth_capture(
        &mut s1,
        "secret",
        PROTOCOL_VERSION,
    )
    .await
    .expect("first login should respond");
    assert!(ok, "first login should succeed");

    // 2. 新连接：探测（同一 client_nonce）→ 服务器下发全新 nonce →
    //    用旧 digest 证明 → 拒绝。
    let mut s2 = TcpStream::connect(format!("[::1]:{}", server_port)).await.unwrap();
    let probe = ControlMsg::Login {
        token: String::new(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "raw".to_string(),
        device_id: None,
        ed25519_pub: None,
        auth_nonce: Some(client_nonce),
        auth_digest: None,
    };
    s2.write_all(&encode_control(&probe).unwrap()).await.unwrap();
    let (ty, payload) = read_frame(&mut s2).await.unwrap();
    let ControlMsg::AuthChallenge { nonce: new_nonce } = decode_control(ty, &payload).unwrap()
    else {
        panic!("expected auth challenge");
    };
    assert_ne!(
        new_nonce, server_nonce,
        "server nonce must be fresh per connection"
    );
    let proof = ControlMsg::Login {
        token: String::new(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "raw".to_string(),
        device_id: None,
        ed25519_pub: None,
        auth_nonce: Some(client_nonce),
        auth_digest: Some(digest), // 基于旧 server_nonce 的证明 → 必失败
    };
    s2.write_all(&encode_control(&proof).unwrap()).await.unwrap();
    let (ty, payload) = read_frame(&mut s2).await.unwrap();
    let ControlMsg::LoginResp { ok: false, .. } = decode_control(ty, &payload).unwrap() else {
        panic!("replayed digest must be rejected");
    };
    assert!(
        wait_for(
            || audit.count(|e| matches!(e, TunnelAuditEvent::LoginFailed { .. })) >= 1,
            Duration::from_secs(2)
        )
        .await,
        "replay rejection should be audited"
    );
    srv_task.abort();
}

#[tokio::test]
async fn test_client_forged_receipt_disconnects() {
    // T4 e2e：伪造回执服务器（错误 server_digest）→ 带口令客户端校验失败
    // → ServerAuthFailed（拒绝继续）。
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let token = "secret-token";
    let token_owned = token.to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // 探测 → 挑战。
        let (ty, payload) = read_frame(&mut stream).await.unwrap();
        let ControlMsg::Login {
            auth_nonce: Some(_),
            ..
        } = decode_control(ty, &payload).unwrap()
        else {
            panic!("bad probe");
        };
        let frame = encode_control(&ControlMsg::AuthChallenge { nonce: [9u8; 16] }).unwrap();
        stream.write_all(&frame).await.unwrap();
        // 证明 → 伪造回执。
        let (ty, payload) = read_frame(&mut stream).await.unwrap();
        assert!(matches!(
            decode_control(ty, &payload).unwrap(),
            ControlMsg::Login {
                auth_digest: Some(_),
                ..
            }
        ));
        let frame = encode_control(&ControlMsg::LoginResp {
            ok: true,
            err: None,
            server_version: PROTOCOL_VERSION.to_string(),
            auth_digest: Some(vec![0xde, 0xad, 0xbe, 0xef]), // 伪造
        })
        .unwrap();
        stream.write_all(&frame).await.unwrap();
        let _ = token_owned;
    });
    let err = crate::id_client::resolve_device(
        &format!("127.0.0.1:{}", port),
        token,
        "device-x",
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, IdClientError::ServerAuthFailed(_)),
        "forged receipt must fail closed, got: {err}"
    );
}

#[tokio::test]
async fn test_client_fail_closed_legacy_server() {
    // TNL-SEC-008 e2e：带口令客户端连无口令服务器 → fail-closed 拒绝，
    // 永不建立会话（循环重试也不得注册）。
    let server = TunnelServer::bind(server_cfg("", None)).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());
    let client = Arc::new(TunnelClient::new(client_cfg(
        server_port,
        "secret", // 带口令
        vec![],
        Duration::from_millis(50),
    )));
    let c = client.clone();
    let cli_task = tokio::spawn(async move { c.run().await });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        !client.status().connected,
        "client with token must fail-closed against unauthenticated server"
    );
    client.stop();
    let _ = tokio::time::timeout(Duration::from_secs(3), cli_task).await;
    srv_task.abort();
}

#[tokio::test]
async fn test_client_fail_closed_no_token() {
    // TNL-SEC-008 e2e：无口令客户端连口令服务器 → 拒绝继续（无挑战响应
    // 直接 fail-closed），永不建立会话。
    let server = TunnelServer::bind(server_cfg("secret", None)).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());
    let client = Arc::new(TunnelClient::new(client_cfg(
        server_port,
        "", // 无口令
        vec![],
        Duration::from_millis(50),
    )));
    let c = client.clone();
    let cli_task = tokio::spawn(async move { c.run().await });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        !client.status().connected,
        "client without token must fail-closed against challenged server"
    );
    client.stop();
    let _ = tokio::time::timeout(Duration::from_secs(3), cli_task).await;
    srv_task.abort();
}

#[tokio::test]
async fn test_legacy_no_token_full_flow() {
    // TNL-SEC-010：legacy 无口令全流程不变（无口令客户端 + 无口令服务器，
    // 探测帧被直接应答 → 客户端按 legacy 继续）。
    let echo_port = spawn_echo_service().await;
    let server = TunnelServer::bind(server_cfg("", None)).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());
    let client = Arc::new(TunnelClient::new(client_cfg(
        server_port,
        "",
        vec![echo_proxy(echo_port)],
        Duration::from_millis(50),
    )));
    let c = client.clone();
    let cli_task = tokio::spawn(async move { c.run().await });
    let (_name, pub_port) = wait_registered(&client, Duration::from_secs(5))
        .await
        .expect("legacy client should register");
    assert!(
        echo_roundtrip(pub_port, b"legacy echo").await,
        "legacy flow should pass data"
    );
    client.stop();
    let _ = tokio::time::timeout(Duration::from_secs(3), cli_task).await;
    srv_task.abort();
}

#[tokio::test]
async fn test_legacy_server_accepts_old_client() {
    // TNL-SEC-010：无口令服务端保留 legacy 明文流程——旧客户端（v1.0，
    // 5 字段 Login，无 auth 字段）空 token 直接登录成功（TNL-PROTO-011
    // 回退解码路径）。
    let server = TunnelServer::bind(server_cfg("", None)).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    // 手工构造 v1.0 载荷（5 字段，无 auth 字段；wire = 变体标记 + 字段）。
    #[derive(serde::Serialize)]
    struct OldLogin<'a> {
        token: &'a str,
        version: &'a str,
        hostname: &'a str,
        device_id: Option<&'a str>,
        ed25519_pub: Option<&'a str>,
    }
    let bytes = bincode::serialize(&OldLogin {
        token: "",
        version: "1.0.0",
        hostname: "old-client",
        device_id: None,
        ed25519_pub: None,
    })
    .unwrap();
    let mut wire = 0u32.to_le_bytes().to_vec(); // ControlMsg::Login 变体标记
    wire.extend_from_slice(&bytes);
    let frame = crate::protocol::wrap_frame(crate::protocol::TYPE_CONTROL, &wire);
    let mut stream = TcpStream::connect(format!("[::1]:{}", server_port)).await.unwrap();
    stream.write_all(&frame).await.unwrap();
    let (ty, payload) = read_frame(&mut stream).await.unwrap();
    let ControlMsg::LoginResp { ok: true, .. } = decode_control(ty, &payload).unwrap() else {
        panic!("old client must be accepted by legacy server (TNL-SEC-010)");
    };
    srv_task.abort();
}

// ════════════════════════════════════════════════════════════
// S-03（审计 F-6）：TunnelConn 未认证限速 + pending 上限 e2e
// ════════════════════════════════════════════════════════════

/// 发送一条 `TunnelConn` 首帧并读取服务器 `TunnelResp`。
/// 返回 `(ok, err)`；配对挂起（无应答）或连接被关闭 → `None`。
async fn raw_tunnel_conn(server_port: u16, target: &str) -> Option<(bool, String)> {
    let mut s = TcpStream::connect(format!("[::1]:{}", server_port)).await.ok()?;
    let req = TunnelConn {
        target_peer_id: target.to_string(),
        from_peer: "pc-a".to_string(),
    };
    s.write_all(&encode_extension(TYPE_TUNNEL_CONN, &req).ok()?).await.ok()?;
    let (ty, payload) = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(&mut s),
    )
    .await
    .ok()?
    .ok()?;
    let resp: TunnelResp = decode_extension(ty, &payload, TYPE_TUNNEL_RESP).ok()?;
    Some((resp.ok, resp.err.unwrap_or_default()))
}

/// 手工登录并注册设备（`device_id` 携带注册字段），返回登录流（须保持存活
/// 以维持在线表条目）。
async fn raw_login_device(
    server_port: u16,
    token: &str,
    device_id: &str,
) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(format!("[::1]:{}", server_port)).await.ok()?;
    let client_nonce = random_nonce();
    let probe = ControlMsg::Login {
        token: String::new(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "raw-device".to_string(),
        device_id: Some(device_id.to_string()),
        ed25519_pub: Some("pub-raw".to_string()),
        auth_nonce: Some(client_nonce),
        auth_digest: None,
    };
    stream.write_all(&encode_control(&probe).ok()?).await.ok()?;
    let (ty, payload) = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(&mut stream),
    )
    .await
    .ok()?
    .ok()?;
    let server_nonce = match decode_control(ty, &payload).ok()? {
        ControlMsg::AuthChallenge { nonce } => nonce,
        _ => return None,
    };
    let digest = client_digest(token.as_bytes(), &server_nonce, &client_nonce);
    let proof = ControlMsg::Login {
        token: String::new(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "raw-device".to_string(),
        device_id: Some(device_id.to_string()),
        ed25519_pub: Some("pub-raw".to_string()),
        auth_nonce: Some(client_nonce),
        auth_digest: Some(digest),
    };
    stream.write_all(&encode_control(&proof).ok()?).await.ok()?;
    let (ty, payload) = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(&mut stream),
    )
    .await
    .ok()?
    .ok()?;
    match decode_control(ty, &payload).ok()? {
        ControlMsg::LoginResp { ok: true, .. } => Some(stream),
        _ => None,
    }
}

#[tokio::test]
async fn test_tunnel_conn_unauthenticated_rate_limit() {
    // S-03a / 审计 F-6 验收：未认证脚本连续触发 TunnelConn → 前 10 次放行
    //（目标离线 → ok:false 统一文案），第 11 次起被限速拒绝 + 审计。
    let audit = Arc::new(AuditCollector::default());
    let server = TunnelServer::bind(server_cfg("secret", Some(audit.clone())))
        .await
        .unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    for i in 0..10 {
        let (ok, err) = raw_tunnel_conn(server_port, "ghost")
            .await
            .expect("rate window内应得到 TunnelResp");
        assert!(!ok, "第 {} 次：目标离线应拒绝", i + 1);
        assert!(
            err.contains("device unavailable"),
            "第 {} 次应为统一离线文案，got: {err}",
            i + 1
        );
    }
    // 第 11 次：窗口内超限 → 限速拒绝（独立文案 + 审计）。
    let (ok, err) = raw_tunnel_conn(server_port, "ghost")
        .await
        .expect("限速拒绝应得到 TunnelResp");
    assert!(!ok);
    assert!(
        err.contains("rate limited"),
        "第 11 次应为限速拒绝文案，got: {err}"
    );
    assert!(
        wait_for(
            || audit.count(|e| matches!(e, TunnelAuditEvent::RateLimited { .. })) >= 1,
            Duration::from_secs(3)
        )
        .await,
        "限速拒绝应产生 RateLimited 审计"
    );
    // 前 10 次不应被限速（限速审计恰为 1 条）。
    assert_eq!(
        audit.count(|e| matches!(e, TunnelAuditEvent::RateLimited { .. })),
        1,
        "仅第 11 次被限速"
    );
    srv_task.abort();
}

#[tokio::test]
async fn test_tunnel_conn_pending_limit_per_target() {
    // S-03a / 审计 F-6：每目标设备同时未配对隧道数上限（注入 2）→
    // 3 条并发 TunnelConn 中 1 条被拒（"pending tunnel limit reached for
    // target"）+ 审计；其余 2 条配对挂起至超时（无应答，None）。
    let audit = Arc::new(AuditCollector::default());
    let mut cfg = server_cfg("secret", Some(audit.clone()));
    cfg.tunnel_conn_rate_limit = RateLimiterConfig {
        max_attempts: 1000, // 限速关掉（本用例只验证 pending 上限）
        attempt_window: Duration::from_secs(30),
        failure_threshold: 5,
        ban_duration: Duration::from_secs(60),
    };
    cfg.max_pending_per_target = 2;
    cfg.max_pending_tunnels = 256;
    cfg.heartbeat_timeout = Duration::from_secs(10); // 注册设备期间会话不判死
    cfg.work_conn_timeout = Duration::from_millis(500); // 配对超时加速
    let server = TunnelServer::bind(cfg).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    let _device = raw_login_device(server_port, "secret", "pc-b")
        .await
        .expect("设备注册应成功");

    let mut handles = Vec::new();
    for _ in 0..3 {
        handles.push(tokio::spawn(raw_tunnel_conn(server_port, "pc-b")));
    }
    let mut rejected = 0;
    let mut pending_no_response = 0;
    for h in handles {
        match h.await.unwrap() {
            Some((false, err)) if err.contains("pending tunnel limit reached for target") => {
                rejected += 1;
            }
            None => pending_no_response += 1,
            other => panic!("unexpected tunnel conn outcome: {other:?}"),
        }
    }
    assert_eq!(rejected, 1, "第 3 条并发 TunnelConn 应被 per-target 上限拒绝");
    assert_eq!(pending_no_response, 2, "其余 2 条应挂起至配对超时");
    assert!(
        wait_for(
            || {
                audit.count(|e| matches!(
                    e,
                    TunnelAuditEvent::TunnelRelayClosed { reason, .. }
                        if reason.contains("pending tunnel limit reached for target")
                )) >= 1
            },
            Duration::from_secs(3)
        )
        .await,
        "per-target 上限拒绝应产生审计"
    );
    srv_task.abort();
}

#[tokio::test]
async fn test_tunnel_conn_pending_limit_global() {
    // S-03a / 审计 F-6：pending 表全局硬上限（注入 2）→ 3 个不同目标并发
    // TunnelConn 中 1 条被拒（"pending tunnel limit reached"）+ 审计。
    let audit = Arc::new(AuditCollector::default());
    let mut cfg = server_cfg("secret", Some(audit.clone()));
    cfg.tunnel_conn_rate_limit = RateLimiterConfig {
        max_attempts: 1000, // 限速关掉（本用例只验证 pending 上限）
        attempt_window: Duration::from_secs(30),
        failure_threshold: 5,
        ban_duration: Duration::from_secs(60),
    };
    cfg.max_pending_tunnels = 2;
    cfg.max_pending_per_target = 16;
    cfg.heartbeat_timeout = Duration::from_secs(10);
    cfg.work_conn_timeout = Duration::from_millis(500);
    let server = TunnelServer::bind(cfg).await.unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    // 三条登录流必须同时存活（drop 即离线 → 目标不可用）。
    let mut devices = Vec::new();
    for did in ["pc-b1", "pc-b2", "pc-b3"] {
        let stream = raw_login_device(server_port, "secret", did)
            .await
            .unwrap_or_else(|| panic!("设备注册应成功: {did}"));
        devices.push(stream);
    }

    let mut handles = Vec::new();
    for target in ["pc-b1", "pc-b2", "pc-b3"] {
        handles.push(tokio::spawn(raw_tunnel_conn(server_port, target)));
    }
    let mut rejected = 0;
    let mut pending_no_response = 0;
    for h in handles {
        match h.await.unwrap() {
            Some((false, err)) if err == "pending tunnel limit reached" => rejected += 1,
            None => pending_no_response += 1,
            other => panic!("unexpected tunnel conn outcome: {other:?}"),
        }
    }
    assert_eq!(rejected, 1, "第 3 条并发 TunnelConn 应被全局上限拒绝");
    assert_eq!(pending_no_response, 2, "其余 2 条应挂起至配对超时");
    assert!(
        wait_for(
            || {
                audit.count(|e| matches!(
                    e,
                    TunnelAuditEvent::TunnelRelayClosed { reason, .. }
                        if reason == "pending tunnel limit reached (2)"
                )) >= 1
            },
            Duration::from_secs(3)
        )
        .await,
        "全局上限拒绝应产生审计"
    );
    srv_task.abort();
}

// ════════════════════════════════════════════════════════════
// S-09（审计 F-9）：候选登记归属校验 e2e
// ════════════════════════════════════════════════════════════

/// 手工登录（可指定是否携带 device_id 注册字段），返回登录流
/// （须保持存活以维持会话 / 在线表条目）。
async fn raw_login_any(server_port: u16, token: &str, device_id: Option<&str>) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(format!("[::1]:{}", server_port)).await.ok()?;
    let client_nonce = random_nonce();
    let device_id_owned = device_id.map(|s| s.to_string());
    let probe = ControlMsg::Login {
        token: String::new(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "raw-device".to_string(),
        device_id: device_id_owned.clone(),
        ed25519_pub: Some("pub-raw".to_string()),
        auth_nonce: Some(client_nonce),
        auth_digest: None,
    };
    stream.write_all(&encode_control(&probe).ok()?).await.ok()?;
    let (ty, payload) = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(&mut stream),
    )
    .await
    .ok()?
    .ok()?;
    let server_nonce = match decode_control(ty, &payload).ok()? {
        ControlMsg::AuthChallenge { nonce } => nonce,
        _ => return None,
    };
    let digest = client_digest(token.as_bytes(), &server_nonce, &client_nonce);
    let proof = ControlMsg::Login {
        token: String::new(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "raw-device".to_string(),
        device_id: device_id_owned,
        ed25519_pub: Some("pub-raw".to_string()),
        auth_nonce: Some(client_nonce),
        auth_digest: Some(digest),
    };
    stream.write_all(&encode_control(&proof).ok()?).await.ok()?;
    let (ty, payload) = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(&mut stream),
    )
    .await
    .ok()?
    .ok()?;
    match decode_control(ty, &payload).ok()? {
        ControlMsg::LoginResp { ok: true, .. } => Some(stream),
        _ => None,
    }
}

/// 从登录流发送一条候选登记（`session_id=None` = 注册表候选刷新）。
/// 返回写入是否成功。
async fn send_candidate_register(
    stream: &mut TcpStream,
    device_id: &str,
    candidates: Vec<Candidate>,
) -> bool {
    let reg = CandidateRegister {
        device_id: device_id.to_string(),
        session_id: None,
        candidates,
    };
    match encode_extension(TYPE_CANDIDATE_REGISTER, &reg) {
        Ok(frame) => stream.write_all(&frame).await.is_ok(),
        Err(_) => false,
    }
}

/// 匿名会话解析目标设备（Login 无 device_id → ResolveDevice → DeviceInfo）。
async fn raw_resolve(server_port: u16, device_id: &str) -> Option<DeviceInfo> {
    let mut stream = raw_login_any(server_port, "secret", None).await?;
    let req = ResolveDevice {
        device_id: device_id.to_string(),
    };
    stream
        .write_all(&encode_extension(TYPE_RESOLVE_DEVICE, &req).ok()?)
        .await
        .ok()?;
    let (ty, payload) = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(&mut stream),
    )
    .await
    .ok()?
    .ok()?;
    decode_extension::<DeviceInfo>(ty, &payload, TYPE_DEVICE_INFO).ok()
}

#[tokio::test]
async fn test_candidate_register_cross_device_rejected() {
    // S-09a / 审计 F-9 验收：任意已认证会话不得覆盖/清空其他设备候选列表。
    let audit = Arc::new(AuditCollector::default());
    let server = TunnelServer::bind(server_cfg("secret", Some(audit.clone())))
        .await
        .unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    // 目标设备 pc-b 在线并登记自有候选（正常归属，S-09c 回归基线）。
    let mut dev_b = raw_login_any(server_port, "secret", Some("pc-b"))
        .await
        .expect("pc-b 注册应成功");
    let cand_b = Candidate {
        addr: "192.168.1.5:3389".parse().unwrap(),
        kind: CandidateKind::Tcp,
        priority: 100,
    };
    assert!(
        send_candidate_register(&mut dev_b, "pc-b", vec![cand_b.clone()]).await,
        "pc-b 自身候选登记应成功写入"
    );
    // 恶意会话 pc-a（已认证，但注册的是另一设备）。
    let mut dev_a = raw_login_any(server_port, "secret", Some("pc-a"))
        .await
        .expect("pc-a 注册应成功");

    // 确认 pc-b 自有候选已生效（含服务器观察地址附加）。
    let info = raw_resolve(server_port, "pc-b").await.expect("解析应应答");
    assert!(info.payload.online);
    let addrs: Vec<_> = info.payload.candidates.iter().map(|c| c.addr).collect();
    assert!(
        addrs.contains(&cand_b.addr),
        "pc-b 自有候选应生效"
    );

    // 跨设备覆盖：pc-a 会话为 pc-b 提交候选 → 丢弃 + 审计，pc-b 候选不变。
    let cand_evil = Candidate {
        addr: "6.6.6.6:1".parse().unwrap(),
        kind: CandidateKind::Udp,
        priority: 255,
    };
    assert!(
        send_candidate_register(&mut dev_a, "pc-b", vec![cand_evil.clone()]).await,
        "恶意候选登记帧应成功发送（服务器侧丢弃）"
    );
    assert!(
        wait_for(
            || {
                audit.count(|e| {
                    matches!(e, TunnelAuditEvent::CandidateRegisterRejected { .. })
                }) >= 1
            },
            Duration::from_secs(3)
        )
        .await,
        "跨设备候选覆盖应产生归属拒绝审计"
    );
    let info = raw_resolve(server_port, "pc-b").await.expect("解析应应答");
    let addrs: Vec<_> = info.payload.candidates.iter().map(|c| c.addr).collect();
    assert!(
        !addrs.contains(&cand_evil.addr),
        "pc-b 候选不得被跨设备会话覆盖"
    );
    assert!(
        addrs.contains(&cand_b.addr),
        "pc-b 自有候选应保留（未被投毒/清空）"
    );

    // 会话未注册设备：匿名登录（无 device_id）提交候选 → 同样拒绝 + 审计。
    let mut anon = raw_login_any(server_port, "secret", None)
        .await
        .expect("匿名登录应成功");
    assert!(
        send_candidate_register(&mut anon, "pc-b", vec![cand_evil.clone()]).await,
        "匿名会话候选登记帧应成功发送（服务器侧丢弃）"
    );
    assert!(
        wait_for(
            || {
                audit.count(|e| {
                    matches!(e, TunnelAuditEvent::CandidateRegisterRejected { .. })
                }) >= 2
            },
            Duration::from_secs(3)
        )
        .await,
        "未注册设备会话提交候选应产生归属拒绝审计"
    );
    let info = raw_resolve(server_port, "pc-b").await.expect("解析应应答");
    let addrs: Vec<_> = info.payload.candidates.iter().map(|c| c.addr).collect();
    assert!(
        !addrs.contains(&cand_evil.addr),
        "pc-b 候选不得被未注册设备会话覆盖"
    );

    srv_task.abort();
}

#[tokio::test]
async fn test_candidate_register_same_device_accepted() {
    // S-09c 回归：正常候选登记（同 device_id）不被误伤 —— 设备为自身
    // 提交候选 → 生效（含服务器观察地址附加，ID-002 / PUNCH-PROTO-001）。
    let audit = Arc::new(AuditCollector::default());
    let server = TunnelServer::bind(server_cfg("secret", Some(audit.clone())))
        .await
        .unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    let mut dev_a = raw_login_any(server_port, "secret", Some("pc-a"))
        .await
        .expect("pc-a 注册应成功");
    let cand = Candidate {
        addr: "10.1.2.3:4444".parse().unwrap(),
        kind: CandidateKind::Udp,
        priority: 120,
    };
    assert!(
        send_candidate_register(&mut dev_a, "pc-a", vec![cand.clone()]).await,
        "同 device_id 候选登记帧应成功写入"
    );

    let info = raw_resolve(server_port, "pc-a").await.expect("解析应应答");
    assert!(info.payload.online);
    let addrs: Vec<_> = info.payload.candidates.iter().map(|c| c.addr).collect();
    assert!(
        addrs.contains(&cand.addr),
        "同 device_id 候选登记应生效"
    );
    assert_eq!(
        info.payload.candidates.len(),
        2,
        "候选列表 = 自有候选 + 服务器观察地址"
    );

    // 全程不应出现归属拒绝审计（正常归属不被误伤）。
    assert_eq!(
        audit.count(|e| matches!(e, TunnelAuditEvent::CandidateRegisterRejected { .. })),
        0
    );

    srv_task.abort();
}

// ════════════════════════════════════════════════════════════════
// M8-T039 (P2): 多地址多监听器 / v6-only / 回退语义 单测
// ════════════════════════════════════════════════════════════════

/// 取一个空闲端口（测试用；drop 后可能被并发测试复用，仅用于同批次内）。
async fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

#[tokio::test]
async fn bind_multi_addrs_same_port() {
    // M8-T039 P6/P8：多地址同端口监听 —— `0.0.0.0` 与 `[::]` 两个 listener
    // 并存（v6-only 与 v4 显式监听互不冲突，无 EADDRINUSE）；`port()` 取
    // 首个监听器端口且非 0。数据面：IPv4 客户端走 v4 监听器、IPv6 客户端
    // 走 v6 监听器（本机回环双链路连通）。
    let port = pick_free_port().await;
    assert_ne!(port, 0);
    let mut cfg = server_cfg("secret", None);
    cfg.bind_addrs = vec![
        format!("0.0.0.0:{}", port).parse().unwrap(),
        format!("[::]:{}", port).parse().unwrap(),
    ];
    let server = TunnelServer::bind(cfg)
        .await
        .expect("双地址同端口监听应成功（v6-only 规避 EADDRINUSE）");
    assert_eq!(server.port(), port, "port() 应取首个监听器端口");
    let srv_task = tokio::spawn(server.run());

    let _ = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("IPv4 客户端应连通 v4 监听器（0.0.0.0）");
    let _ = TcpStream::connect(("::1", port))
        .await
        .expect("IPv6 客户端应连通 v6 监听器（[::]，v6-only）");

    srv_task.abort();
}

#[tokio::test]
async fn v6_only_isolated() {
    // M8-T039 P6/P8：set_only_v6 断言 —— 仅绑 `[::1]:0` 时 IPv4 回环连接
    // 必须失败（v6 监听不收 IPv4），IPv6 回环必须连通。
    let mut cfg = server_cfg("secret", None);
    cfg.bind_addrs = vec!["[::1]:0".parse().unwrap()];
    let server = TunnelServer::bind(cfg)
        .await
        .expect("v6-only 单监听绑定应成功");
    let port = server.port();
    assert_ne!(port, 0);
    let srv_task = tokio::spawn(server.run());

    let v4 = tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await;
    assert!(v4.is_err(), "v6-only 监听不得接受 IPv4 连接");
    let _ = TcpStream::connect(("::1", port))
        .await
        .expect("IPv6 客户端应连通 v6-only 监听器");

    srv_task.abort();
}

#[tokio::test]
async fn bind_single_127_regression() {
    // S-24 (F-29) 回归（P2-4 对齐 self-test 语义）：单地址 `127.0.0.1:0`。
    let mut cfg = server_cfg("secret", None);
    cfg.bind_addrs = vec!["127.0.0.1:0".parse().unwrap()];
    let server = TunnelServer::bind(cfg).await.expect("单回环地址绑定应成功");
    let port = server.port();
    assert_ne!(port, 0);
    let srv_task = tokio::spawn(server.run());
    let _ = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("回环客户端应连通");
    srv_task.abort();
}

#[tokio::test]
async fn bind_empty_falls_back_dual_stack() {
    // M8-T039 P7：bind_addrs 空列表 → 旧默认双栈路径（`[::]` 优先 +
    // `0.0.0.0` 回退，语义零变化）；v4 回环连通（本机无 v6 环境时该断言
    // 即够，按平台能力取 v4 断言）。
    let server = TunnelServer::bind(server_cfg("secret", None))
        .await
        .expect("空 bind_addrs 应走默认双栈绑定成功");
    let port = server.port();
    assert_ne!(port, 0);
    let srv_task = tokio::spawn(server.run());
    let _ = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("默认双栈下 v4 回环应连通");
    srv_task.abort();
}

// ════════════════════════════════════════════════════════════════
// R-08b（S1/S2）：打洞两端缝合 —— 帧分发 + rendezvous 部署形态
// ════════════════════════════════════════════════════════════════

/// R-08b 组合部署辅助：进程内装配 TunnelServer + RendezvousServer
/// （对齐 relay-server 二进制形态）。返回 (tunnel 控制端口, rendezvous)。
async fn spawn_composed(audit: Arc<AuditCollector>) -> (u16, Arc<RendezvousServer>) {
    let rz = Arc::new(
        RendezvousServer::bind(0)
            .await
            .unwrap()
            .with_audit(Arc::clone(&audit) as Arc<dyn AuditSink>),
    );
    let mut cfg = server_cfg("secret", Some(audit));
    cfg.rendezvous = Some(rz.clone());
    let server = TunnelServer::bind(cfg).await.unwrap();
    let port = server.port();
    tokio::spawn(server.run());
    (port, rz)
}

/// R-08b：带 session_id（P1 打洞）的候选登记帧（隧道控制连接 / rendezvous 连接通用）。
async fn send_punch_register(
    stream: &mut TcpStream,
    device_id: &str,
    session_id: [u8; 16],
    candidates: Vec<Candidate>,
) -> bool {
    let reg = CandidateRegister {
        device_id: device_id.to_string(),
        session_id: Some(session_id),
        candidates,
    };
    match encode_extension(TYPE_CANDIDATE_REGISTER, &reg) {
        Ok(frame) => stream.write_all(&frame).await.is_ok(),
        Err(_) => false,
    }
}

/// R-08b：读一帧并断言为指定类型，返回解码负载。
async fn read_expect<T: for<'de> serde::Deserialize<'de>>(
    stream: &mut TcpStream,
    ty_expect: u8,
) -> T {
    let (ty, payload) = tokio::time::timeout(Duration::from_secs(2), read_frame(stream))
        .await
        .expect("等待帧超时")
        .expect("连接关闭");
    assert_eq!(ty, ty_expect, "帧类型应为 0x{ty_expect:02x}");
    decode_extension(ty, &payload, ty_expect).unwrap()
}

#[tokio::test]
async fn test_punch_rendezvous_port_candidate_exchange() {
    // R-08b (S2/S3) 部署形态：独立 rendezvous 监听（对齐 relay-server
    // --rendezvous-port）—— 双端候选登记 → 互转 PeerCandidates（含服务器
    // 观察地址）→ PunchResult 透传对端 + 审计；优雅关闭无残留。
    let audit = Arc::new(AuditCollector::default());
    let rz = Arc::new(
        RendezvousServer::bind(0)
            .await
            .unwrap()
            .with_audit(Arc::clone(&audit) as Arc<dyn AuditSink>),
    );
    let mut addr = rz.local_addr();
    if addr.ip().is_unspecified() {
        addr = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, addr.port()));
    }
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let rz_task = tokio::spawn(rz.clone().serve(stop_rx));

    let mut a = TcpStream::connect(addr).await.unwrap();
    let mut b = TcpStream::connect(addr).await.unwrap();
    let cand = Candidate {
        addr: "10.1.2.3:4444".parse().unwrap(),
        kind: CandidateKind::Udp,
        priority: 120,
    };
    assert!(send_punch_register(&mut a, "dev-a", [7; 16], vec![cand.clone()]).await);
    assert!(send_punch_register(&mut b, "dev-b", [7; 16], vec![cand.clone()]).await);

    // 双端互转：候选含服务器观察地址（对端 TCP 地址）+ 自有候选。
    let pc_a: PeerCandidates = read_expect(&mut a, TYPE_PEER_CANDIDATES).await;
    let pc_b: PeerCandidates = read_expect(&mut b, TYPE_PEER_CANDIDATES).await;
    assert_eq!(pc_a.session_id, [7; 16]);
    let b_peer = b.local_addr().unwrap();
    let a_peer = a.local_addr().unwrap();
    assert!(
        pc_a.candidates.iter().any(|c| c.addr == b_peer),
        "A 应收到 B 的观察地址"
    );
    assert!(
        pc_b.candidates.iter().any(|c| c.addr == a_peer),
        "B 应收到 A 的观察地址"
    );

    // PunchResult 透传对端（PUNCH-PROTO-005）。
    let result = PunchResult {
        session_id: [7; 16],
        ok: true,
        path: Some(CandidateKind::Udp),
    };
    a.write_all(&encode_extension(TYPE_PUNCH_RESULT, &result).unwrap())
        .await
        .unwrap();
    let got: PunchResult = read_expect(&mut b, TYPE_PUNCH_RESULT).await;
    assert_eq!(got, result);

    // 审计事件：候选登记 x2 + 互转/透传。
    assert!(
        wait_for(
            || audit.count(|e| matches!(e, TunnelAuditEvent::PunchCandidateRegistered { .. })) >= 2,
            Duration::from_secs(2)
        )
        .await
    );
    assert!(
        audit.count(|e| matches!(e, TunnelAuditEvent::PunchForwarded { .. })) >= 2
    );

    // 优雅关闭（S2 验收）：stop 置位 → serve 任务干净返回，连接任务中止。
    let _ = stop_tx.send(true);
    let res = tokio::time::timeout(Duration::from_secs(2), rz_task)
        .await
        .expect("rendezvous serve 应在 stop 后退出")
        .expect("serve 任务不应 panic");
    assert!(res.is_ok(), "serve 应返回 Ok(())");
}

#[tokio::test]
async fn test_punch_frames_over_tunnel_control() {
    // R-08b (S1)：隧道控制连接上的打洞帧 —— CandidateRegister(session_id=Some)
    // 接入进程内 rendezvous（与既有注册表刷新路径并列），PunchResult /
    // PathProbe 不再落入 `_ =>` 忽略：双端互转 + 透传 + 审计。
    let audit = Arc::new(AuditCollector::default());
    let (server_port, _rz) = spawn_composed(audit.clone()).await;

    let mut dev_a = raw_login_any(server_port, "secret", Some("pc-a"))
        .await
        .expect("pc-a 登录应成功");
    let mut dev_b = raw_login_any(server_port, "secret", Some("pc-b"))
        .await
        .expect("pc-b 登录应成功");

    let cand = Candidate {
        addr: "10.9.8.7:9999".parse().unwrap(),
        kind: CandidateKind::Udp,
        priority: 100,
    };
    assert!(send_punch_register(&mut dev_a, "pc-a", [9; 16], vec![cand.clone()]).await);
    assert!(send_punch_register(&mut dev_b, "pc-b", [9; 16], vec![cand.clone()]).await);

    // 互转：经隧道控制连接收到对端候选（打洞会话配对成功）。
    let pc_a: PeerCandidates = read_expect(&mut dev_a, TYPE_PEER_CANDIDATES).await;
    let pc_b: PeerCandidates = read_expect(&mut dev_b, TYPE_PEER_CANDIDATES).await;
    assert_eq!(pc_a.session_id, [9; 16]);
    assert_eq!(pc_b.session_id, [9; 16]);

    // PunchResult：A → 服务器 → B（透传 + PunchForwarded 审计）。
    let result = PunchResult {
        session_id: [9; 16],
        ok: false,
        path: None,
    };
    dev_a
        .write_all(&encode_extension(TYPE_PUNCH_RESULT, &result).unwrap())
        .await
        .unwrap();
    let got: PunchResult = read_expect(&mut dev_b, TYPE_PUNCH_RESULT).await;
    assert_eq!(got, result);
    assert!(
        wait_for(
            || audit.count(|e| matches!(e, TunnelAuditEvent::PunchForwarded { .. })) >= 1,
            Duration::from_secs(2)
        )
        .await,
        "PunchResult 透传应产生 PunchForwarded 审计"
    );

    // 会话结束 → rendezvous 打洞会话表无残留（新会话同 session_id 可重建配对）。
    drop(dev_a);
    drop(dev_b);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut dev_c = raw_login_any(server_port, "secret", Some("pc-c"))
        .await
        .expect("pc-c 登录应成功");
    let mut dev_d = raw_login_any(server_port, "secret", Some("pc-d"))
        .await
        .expect("pc-d 登录应成功");
    assert!(send_punch_register(&mut dev_c, "pc-c", [9; 16], vec![cand.clone()]).await);
    assert!(send_punch_register(&mut dev_d, "pc-d", [9; 16], vec![cand.clone()]).await);
    let _: PeerCandidates = read_expect(&mut dev_c, TYPE_PEER_CANDIDATES).await;
    let _: PeerCandidates = read_expect(&mut dev_d, TYPE_PEER_CANDIDATES).await;
}

#[tokio::test]
async fn test_punch_frame_without_rendezvous_audited_not_ignored() {
    // R-08b (S1)：无 rendezvous 挂载（库内独立使用）→ 打洞帧解码校验后
    // 审计丢弃（PunchUnknownSession），不静默忽略、连接不判死。
    let audit = Arc::new(AuditCollector::default());
    let server = TunnelServer::bind(server_cfg("secret", Some(audit.clone())))
        .await
        .unwrap();
    let server_port = server.port();
    let srv_task = tokio::spawn(server.run());

    let mut dev = raw_login_any(server_port, "secret", Some("pc-a"))
        .await
        .expect("pc-a 登录应成功");
    let result = PunchResult {
        session_id: [3; 16],
        ok: true,
        path: Some(CandidateKind::Tcp),
    };
    dev.write_all(&encode_extension(TYPE_PUNCH_RESULT, &result).unwrap())
        .await
        .unwrap();
    assert!(
        wait_for(
            || {
                audit.count(|e| {
                    matches!(
                        e,
                        TunnelAuditEvent::PunchUnknownSession { .. }
                    )
                }) >= 1
            },
            Duration::from_secs(2)
        )
        .await,
        "无 rendezvous 时打洞帧应产生 PunchUnknownSession 审计"
    );
    // 连接未判死：仍可 Pong 心跳。
    dev.write_all(&encode_control(&ControlMsg::Ping { ts: 1 }).unwrap())
        .await
        .unwrap();
    let (ty, payload) = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut dev))
        .await
        .expect("Pong 应应答")
        .expect("连接不应被关闭");
    assert!(matches!(
        decode_control(ty, &payload).unwrap(),
        ControlMsg::Pong { ts: 1 }
    ));

    // 坏帧（bincode 解码失败）→ 判死关闭（对齐 rendezvous dispatch / TNL-PROTO-007）。
    let mut dev2 = raw_login_any(server_port, "secret", Some("pc-b"))
        .await
        .expect("pc-b 登录应成功");
    dev2.write_all(&crate::protocol::wrap_frame(TYPE_PUNCH_RESULT, b"garbage"))
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut dev2)).await;
    assert!(
        matches!(closed, Ok(Err(_))),
        "坏打洞帧应导致会话判死关闭，实际 {closed:?}"
    );

    srv_task.abort();
}
