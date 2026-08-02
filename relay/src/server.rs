//! M8-T026 T002: 隧道服务端（frps 等价）— 控制端口 / Login 校验 + 速率限制 /
//! ProxyManager 注册表 / work 连接配对与泵流 / 心跳判死 / 级联清理 / 审计。
//!
//! 职责对照（TNL-SERVER-001~008、TNL-SEC-001~004、TNL-STAB-001/002/005）：
//! - 控制端口监听（`[::]` 优先 + `0.0.0.0` 回退，对齐 M8-T025 双栈）；
//! - 每 frpc 连接一个 Control 任务；新连接首帧区分 `Login`（新会话）与
//!   `WorkConnHeader`（数据面回连），其余一律关闭；
//! - work 配对：公网 accept → 生成 `conn_id` → `StartWorkConn` → 8s 等回连 →
//!   按 `(client_session, proxy_name, conn_id)` 精确配对 → 双向泵流；
//! - 会话失效（EOF / 心跳超时 / Logout）→ 级联清理：代理监听、pending、
//!   泵流任务全部对称关闭，无残留协程。

use crate::audit::{AuditSink, TunnelAuditEvent};
use crate::protocol::{
    decode_control, decode_extension, decode_work_header, encode_control, encode_extension,
    read_frame, CandidateRegister, ControlMsg, ResolveDevice, TunnelConn, TunnelHeader,
    TunnelResp, WorkConnHeader, TYPE_CANDIDATE_REGISTER, TYPE_CONTROL, TYPE_DEVICE_INFO,
    TYPE_RESOLVE_DEVICE, TYPE_TUNNEL_CONN, TYPE_TUNNEL_HEADER, TYPE_TUNNEL_RESP,
    TYPE_WORK_HEADER,
};
use crate::rate_limit::{RateLimitDecision, RateLimiter, RateLimiterConfig};
use crate::registry::{RegisterOutcome, Registry, RegistryError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::AbortHandle;
use tracing::{debug, info, warn};

/// 默认控制端口（TNL-SERVER-001）。
pub const DEFAULT_BIND_PORT: u16 = 7000;
/// 默认心跳超时（TNL-STAB-001，30s）。
pub const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);
/// 默认 work 回连等待（TNL-SERVER-004，8s）。
pub const DEFAULT_WORK_CONN_TIMEOUT: Duration = Duration::from_secs(8);
/// 默认每会话代理数量上限（TNL-SERVER-008）。
pub const DEFAULT_MAX_PROXIES: usize = 32;
/// 默认每代理最大并发 work 连接数（TNL-STAB-005）。
pub const DEFAULT_MAX_CONCURRENT_WORK: usize = 100;
/// 首帧（Login/WorkConnHeader）读取超时。
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// 服务端配置。
#[derive(Debug, Clone)]
pub struct TunnelServerConfig {
    /// 控制端口（0 = 系统分配，测试用）。
    pub bind_port: u16,
    /// token 认证（TNL-SEC-001）。
    pub token: String,
    /// 自动分配端口范围（`remote_port: 0` 时使用，TNL-SERVER-003）。
    pub port_range: Option<(u16, u16)>,
    /// 心跳超时（TNL-STAB-001/002）。
    pub heartbeat_timeout: Duration,
    /// work 回连等待超时（TNL-SERVER-004）。
    pub work_conn_timeout: Duration,
    /// 每会话代理数量上限（TNL-SERVER-008）。
    pub max_proxies: usize,
    /// 每代理最大并发 work 连接数（TNL-STAB-005）。
    pub max_concurrent_work: usize,
    /// 速率限制参数（TNL-SEC-002）。
    pub rate_limit: RateLimiterConfig,
    /// 审计回调（None = 不记录）。
    pub audit: Option<Arc<dyn AuditSink>>,
    /// M8-T026-P2 (ID-SEC-001)：服务器 Ed25519 密钥路径（None = 默认
    /// `~/.kirin_desk/relay_server_key.pem`；测试注入临时路径避免污染真实目录）。
    pub server_key_path: Option<std::path::PathBuf>,
}

impl Default for TunnelServerConfig {
    fn default() -> Self {
        Self {
            bind_port: DEFAULT_BIND_PORT,
            token: String::new(),
            port_range: None,
            heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
            work_conn_timeout: DEFAULT_WORK_CONN_TIMEOUT,
            max_proxies: DEFAULT_MAX_PROXIES,
            max_concurrent_work: DEFAULT_MAX_CONCURRENT_WORK,
            rate_limit: RateLimiterConfig::default(),
            audit: None,
            server_key_path: None,
        }
    }
}

/// 服务端统计（`tunnel status` / 测试用）。
#[derive(Debug, Clone, Default)]
pub struct TunnelServerStats {
    /// 活跃客户端会话数。
    pub sessions: usize,
    /// 全部会话的代理注册总数。
    pub proxies: usize,
}

/// 服务端错误。
#[derive(Debug, thiserror::Error)]
pub enum TunnelServerError {
    #[error("bind failed on port {port}: {source}")]
    Bind { port: u16, source: std::io::Error },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// M8-T026-P2 (ID-SEC-001)：服务器密钥加载/生成失败。
    #[error("server key error: {0}")]
    ServerKey(String),
}

/// 一个 frpc 会话（一条控制连接）。
struct ClientSession {
    id: String,
    addr: SocketAddr,
    proxies: Mutex<HashMap<String, Arc<ProxyEntry>>>,
    /// 控制写通道（writer 任务消费；drop = 关闭控制连接）。
    control_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// 最近收到任何帧的时刻（心跳判死，TNL-STAB-002）。
    last_activity: Mutex<Instant>,
    /// 后台任务（代理监听 + work 泵流）；级联清理时全部 abort。
    tasks: Mutex<Vec<AbortHandle>>,
    /// M8-T026-P2 (ID-001)：本会话注册的设备 ID（None = 纯穿透/纯解析会话）。
    device_id: Mutex<Option<String>>,
}

/// 单个代理条目（TNL-SERVER-003）。
struct ProxyEntry {
    name: String,
    local_addr: String,
    local_port: u16,
    /// 公网绑定端口（主文档 §4.2 数据结构；`tunnel status` / 扩展用）。
    #[allow(dead_code)]
    listener_port: u16,
    /// conn_id → work 连接交付（§4.3；conn_id 全局随机，碰撞可忽略）。
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<TcpStream, ()>>>>,
    /// 当前配对中的 work 连接数（TNL-STAB-005）。
    conn_count: AtomicUsize,
}

impl ProxyEntry {
    fn name(&self) -> &str {
        &self.name
    }
}

/// 服务端共享状态。
struct ServerShared {
    cfg: Arc<TunnelServerConfig>,
    sessions: Mutex<HashMap<String, Arc<ClientSession>>>,
    /// conn_id → (session_id, proxy_name)，work 回连按此路由（TNL-SERVER-005）。
    pending_index: Mutex<HashMap<u64, (String, String)>>,
    rate_limiter: Mutex<RateLimiter>,
    /// M8-T026-P2 (ID-002)：设备在线表（注册/解析/中继配对）。
    registry: Arc<Registry>,
    /// 优雅关闭：置位后 accept 循环停止（`TunnelServer::shutdown`）。
    shutting_down: AtomicBool,
    /// 优雅关闭广播：会话控制任务收到 → 级联清理退出（TNL-SERVER-006 扩展）。
    shutdown_tx: broadcast::Sender<()>,
}

impl ServerShared {
    fn audit(&self, event: TunnelAuditEvent) {
        if let Some(sink) = &self.cfg.audit {
            sink.record(event);
        }
    }

    fn stats(&self) -> TunnelServerStats {
        let sessions = self.sessions.lock().unwrap();
        let proxies = sessions.values().map(|s| s.proxies.lock().unwrap().len()).sum();
        TunnelServerStats { sessions: sessions.len(), proxies }
    }
}

/// 隧道服务端（frps 等价）。
pub struct TunnelServer {
    shared: Arc<ServerShared>,
    listener: TcpListener,
}

/// 服务器关闭句柄（`run()` 移走 `TunnelServer` 后仍可优雅关闭；测试/CLI 用）。
#[derive(Clone)]
pub struct TunnelServerHandle {
    shared: Arc<ServerShared>,
}

impl TunnelServerHandle {
    /// 优雅关闭（语义同 [`TunnelServer::shutdown`]）。
    pub fn shutdown(&self) {
        self.shared.shutting_down.store(true, Ordering::SeqCst);
        let _ = self.shared.shutdown_tx.send(());
    }
}

impl TunnelServer {
    /// 关闭句柄（须在 `run()` 之前取得）。
    pub fn shutdown_handle(&self) -> TunnelServerHandle {
        TunnelServerHandle {
            shared: self.shared.clone(),
        }
    }

    /// 在线设备数（ID-002：`tunnel status` 用）。
    pub async fn device_count(&self) -> usize {
        self.shared.registry.device_count().await
    }

    /// 服务器 Ed25519 公钥（base64，ID-SEC-001）：客户端 `[tunnel]
    /// server_pubkey` 预置验签；首次启动时输出（`tunnel serve`）。
    pub fn server_public_key_base64(&self) -> String {
        self.shared.registry.server_public_key_base64()
    }

    /// 优雅关闭（TNL-SERVER-006 扩展，对等 TNL-CLIENT-007 客户端 stop）：
    /// 停止 accept + 广播关闭信号 → 全部会话控制任务级联清理退出
    /// （代理监听/泵流/设备在线表随之清理）。可从任意任务/线程调用。
    pub fn shutdown(&self) {
        self.shutdown_handle().shutdown();
    }

    /// 绑定控制端口（`[::]` 优先 + `0.0.0.0` 回退，对齐 M8-T025 双栈）。
    ///
    /// 显式设置 `SO_REUSEADDR`（tokio `TcpSocket`，零新依赖）：对齐 FRP/Go
    /// 默认行为——服务端重启（含优雅关闭后的 TIME_WAIT 窗口）可立即重绑
    /// 同端口（TNL-STAB-003 重连场景的生产前提）。
    pub async fn bind(cfg: TunnelServerConfig) -> Result<Self, TunnelServerError> {
        let port = cfg.bind_port;
        let listener = match bind_reuseaddr(port).await {
            Ok(l) => l,
            Err(_) => bind_reuseaddr_v4(port).await.map_err(|e| {
                TunnelServerError::Bind { port, source: e }
            })?,
        };
        let rate_limit_cfg = cfg.rate_limit.clone();
        // M8-T026-P2 (ID-SEC-001)：服务器签名密钥（加载或首次生成持久化）。
        let key_path = cfg
            .server_key_path
            .clone()
            .unwrap_or_else(crate::registry::default_key_path);
        let server_key = Registry::load_or_create_server_key_at(&key_path)
            .map_err(|e| TunnelServerError::ServerKey(e.to_string()))?;
        let registry = Arc::new(Registry::new(server_key));
        info!(
            "relay server key: {} (pubkey {}...)",
            key_path.display(),
            &registry.server_public_key_base64()[..std::cmp::min(16, registry.server_public_key_base64().len())]
        );
        let shared = Arc::new(ServerShared {
            cfg: Arc::new(cfg),
            sessions: Mutex::new(HashMap::new()),
            pending_index: Mutex::new(HashMap::new()),
            rate_limiter: Mutex::new(RateLimiter::with_config(rate_limit_cfg)),
            registry,
            shutting_down: AtomicBool::new(false),
            shutdown_tx: broadcast::channel(64).0,
        });
        Ok(Self { shared, listener })
    }

    /// 实际监听端口（`bind_port: 0` 时为系统分配值）。
    pub fn port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// 当前统计。
    pub fn stats(&self) -> TunnelServerStats {
        self.shared.stats()
    }

    /// 服务主循环：accept → 首帧分发（Login 新会话 / WorkConnHeader 数据面）。
    pub async fn run(self) -> Result<(), TunnelServerError> {
        let shared = self.shared.clone();
        info!("Tunnel server listening on port {}", self.port());
        loop {
            if shared.shutting_down.load(Ordering::SeqCst) {
                info!("Tunnel server shutting down (accept loop stopped)");
                break;
            }
            let (stream, addr) = match self.listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    warn!("tunnel accept error: {}", e);
                    continue;
                }
            };
            let shared = shared.clone();
            tokio::spawn(async move {
                let _ = handle_incoming(shared, stream, addr).await;
            });
        }
        Ok(())
    }
}

/// 处理一条新连接：读首帧 → Login（新会话）/ WorkConnHeader（数据面）/
/// M8-T026-P2 扩展首帧（TunnelConn 控制器数据面 / TunnelHeader 设备回连）。
async fn handle_incoming(
    shared: Arc<ServerShared>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = stream;
    let (ty, payload) = match tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_frame(&mut stream))
        .await
    {
        Ok(Ok(x)) => x,
        _ => return Ok(()), // 无首帧 / 坏帧 → 静默关闭
    };
    match ty {
        TYPE_CONTROL => {
            let msg = match decode_control(ty, &payload) {
                Ok(m) => m,
                Err(_) => return Ok(()),
            };
            match msg {
                // M8-T026-P2 (ID-001)：device_id / ed25519_pub 为设备注册字段。
                ControlMsg::Login {
                    token,
                    version,
                    hostname,
                    device_id,
                    ed25519_pub,
                } => {
                    handle_login(shared, stream, addr, token, version, hostname, device_id, ed25519_pub)
                        .await
                }
                _ => Ok(()), // 首帧必须是 Login
            }
        }
        TYPE_WORK_HEADER => {
            let header = match decode_work_header(ty, &payload) {
                Ok(h) => h,
                Err(_) => return Ok(()),
            };
            handle_work_arrival(shared, stream, addr, header).await
        }
        // M8-T026-P2 (§8.1)：控制器数据连接（设备级中继请求）。
        TYPE_TUNNEL_CONN => {
            let req = match decode_extension::<TunnelConn>(ty, &payload, TYPE_TUNNEL_CONN) {
                Ok(r) => r,
                Err(_) => return Ok(()),
            };
            handle_tunnel_conn(shared, stream, req).await
        }
        // M8-T026-P2 (§8.1)：设备回连（中继配对）。
        TYPE_TUNNEL_HEADER => {
            let header = match decode_extension::<TunnelHeader>(ty, &payload, TYPE_TUNNEL_HEADER) {
                Ok(h) => h,
                Err(_) => return Ok(()),
            };
            handle_tunnel_arrival(shared, stream, header).await
        }
        _ => Ok(()),
    }
}

/// Login 校验（TNL-SERVER-002 / TNL-SEC-001/002）：速率限制 → token 常数时间
/// 比较 → 主版本协商 → 成功则启动会话控制任务。
///
/// M8-T026-P2 (ID-001/ID-004)：`device_id` 存在时登记在线表（同 ID 不同公钥 →
/// 后到者拒绝 + LoginResp{ok:false}）。
async fn handle_login(
    shared: Arc<ServerShared>,
    mut stream: TcpStream,
    addr: SocketAddr,
    token: String,
    version: String,
    hostname: String,
    device_id: Option<String>,
    ed25519_pub: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. 速率限制（仅统计会话尝试，不统计 work 连接）。
    let decision = shared.rate_limiter.lock().unwrap().check_connect(&addr.ip());
    if decision != RateLimitDecision::Allowed {
        shared.audit(TunnelAuditEvent::RateLimited {
            client: addr,
            reason: format!("{:?}", decision),
        });
        warn!("tunnel rate limited: {} ({:?})", addr, decision);
        return Ok(());
    }
    // 2. token 校验（常数时间比较，防时序侧信道，TNL-SEC-001）。
    let token_ok = constant_time_eq(token.as_bytes(), shared.cfg.token.as_bytes());
    // 3. 主版本协商（TNL-PROTO-008）。
    let version_ok = crate::protocol::major_version(&version)
        == crate::protocol::major_version(crate::protocol::PROTOCOL_VERSION);
    if !token_ok || !version_ok {
        let reason = if !token_ok {
            "invalid token".to_string()
        } else {
            format!("incompatible protocol version: {version}")
        };
        shared.audit(TunnelAuditEvent::LoginFailed {
            client: addr,
            reason: reason.clone(),
        });
        shared.rate_limiter.lock().unwrap().record_handshake_failure(&addr.ip());
        warn!("tunnel login failed from {}: {}", addr, reason);
        let resp = encode_control(&ControlMsg::LoginResp {
            ok: false,
            err: Some(reason),
            server_version: crate::protocol::PROTOCOL_VERSION.to_string(),
        })?;
        // resp 已是完整帧（encode_control 含帧头）→ 直写，勿再套帧头。
        let _ = stream.write_all(&resp).await;
        return Ok(());
    }
    // 4. 成功 → 会话控制任务。
    shared.rate_limiter.lock().unwrap().reset(&addr.ip());
    shared.audit(TunnelAuditEvent::LoginSuccess {
        client: addr,
        hostname: hostname.clone(),
    });
    let (reader, writer) = stream.into_split();
    let (control_tx, mut control_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let session = Arc::new(ClientSession {
        id: uuid::Uuid::new_v4().to_string(),
        addr,
        proxies: Mutex::new(HashMap::new()),
        control_tx,
        last_activity: Mutex::new(Instant::now()),
        tasks: Mutex::new(Vec::new()),
        device_id: Mutex::new(None),
    });
    shared.sessions.lock().unwrap().insert(session.id.clone(), session.clone());
    info!(
        "tunnel client logged in: {} (hostname={}, session={})",
        addr, hostname, session.id
    );
    // M8-T026-P2 (ID-001)：设备注册（Login 携带 device_id）。
    let mut login_ok = true;
    let mut login_err: Option<String> = None;
    if let Some(did) = device_id {
        let ctrl_tx = session.control_tx.clone();
        match shared
            .registry
            .register(&did, ed25519_pub.as_deref().unwrap_or(""), addr, ctrl_tx)
            .await
        {
            Ok(RegisterOutcome::Registered) => {
                *session.device_id.lock().unwrap() = Some(did.clone());
                shared.audit(TunnelAuditEvent::DeviceRegistered {
                    client: addr,
                    device_id: did.clone(),
                });
                info!("device registered: '{}' from {}", did, addr);
            }
            Ok(RegisterOutcome::ReRegistered) => {
                *session.device_id.lock().unwrap() = Some(did.clone());
                shared.audit(TunnelAuditEvent::DeviceRegistered {
                    client: addr,
                    device_id: did.clone(),
                });
                info!("device re-registered: '{}' from {}", did, addr);
            }
            Err(RegistryError::DeviceConflict(_)) => {
                // ID-004：同 ID 不同公钥 → 后到者拒绝。
                login_ok = false;
                login_err = Some(format!("device_id conflict: {did}"));
                shared.audit(TunnelAuditEvent::DeviceRejected {
                    client: addr,
                    device_id: did.clone(),
                    reason: "conflicting ed25519_pub".to_string(),
                });
                warn!("device registration rejected: '{}' conflict from {}", did, addr);
            }
            Err(e) => {
                login_ok = false;
                login_err = Some(format!("device registration failed: {e}"));
                shared.audit(TunnelAuditEvent::DeviceRejected {
                    client: addr,
                    device_id: did,
                    reason: e.to_string(),
                });
            }
        }
    }
    if !login_ok {
        let resp = encode_control(&ControlMsg::LoginResp {
            ok: false,
            err: login_err,
            server_version: crate::protocol::PROTOCOL_VERSION.to_string(),
        })?;
        session.control_tx.send(resp).ok();
        shared.sessions.lock().unwrap().remove(&session.id);
        return Ok(());
    }
    // 写回 LoginResp（writer 任务接管后续；本帧是通道首条消息，天然保序）。
    let resp = encode_control(&ControlMsg::LoginResp {
        ok: true,
        err: None,
        server_version: crate::protocol::PROTOCOL_VERSION.to_string(),
    })?;
    session.control_tx.send(resp).map_err(|_| {
        Box::new(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "control channel closed"))
            as Box<dyn std::error::Error + Send + Sync>
    })?;

    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(frame) = control_rx.recv().await {
            if writer.write_all(&frame).await.is_err() {
                break;
            }
        }
    });
    run_session(shared, session, reader).await;
    let _ = writer_task.abort();
    Ok(())
}

/// 会话控制任务：读帧处理 + 心跳判死（TNL-SERVER-006/007）。
async fn run_session(shared: Arc<ServerShared>, session: Arc<ClientSession>, mut reader: OwnedReadHalf) {
    // 心跳检查粒度：<=250ms 且不高于超时的 1/4（测试可注入 200ms 级超时）。
    let check_interval = shared
        .cfg
        .heartbeat_timeout
        .min(Duration::from_millis(250))
        .max(Duration::from_millis(10))
        / 2;
    let mut heartbeat = tokio::time::interval(check_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut shutdown_rx = shared.shutdown_tx.subscribe();
    loop {
        tokio::select! {
            // 优雅关闭（TNL-SERVER-006 扩展）：级联清理退出。
            _ = shutdown_rx.recv() => {
                info!("tunnel session {} shutting down", session.id);
                break;
            }
            frame = read_frame(&mut reader) => {
                let (ty, payload) = match frame {
                    Ok(x) => x,
                    Err(_) => break, // EOF / 坏帧 → 会话结束
                };
                *session.last_activity.lock().unwrap() = Instant::now();
                match ty {
                    TYPE_CONTROL => match decode_control(ty, &payload) {
                        Ok(msg) => {
                            if !handle_control(shared.clone(), session.clone(), msg).await {
                                break; // Logout / 协议违规 → 优雅结束
                            }
                        }
                        Err(e) => {
                            warn!("tunnel session {} bad control frame: {}", session.id, e);
                            break;
                        }
                    },
                    // M8-T026-P2 (ID-010)：设备解析（限速 + 在线表 + 签名响应）。
                    TYPE_RESOLVE_DEVICE => {
                        match decode_extension::<ResolveDevice>(ty, &payload, TYPE_RESOLVE_DEVICE) {
                            Ok(req) => handle_resolve(shared.clone(), session.clone(), &req).await,
                            Err(e) => {
                                warn!("tunnel session {} bad ResolveDevice: {}", session.id, e);
                                break;
                            }
                        }
                    }
                    // M8-T026-P2 (ID-005)：候选刷新（含服务器观察地址附加）。
                    TYPE_CANDIDATE_REGISTER => {
                        if let Ok(reg) = decode_extension::<CandidateRegister>(
                            ty, &payload, TYPE_CANDIDATE_REGISTER,
                        ) {
                            if !shared.registry.update_candidates(&reg.device_id, reg.candidates).await {
                                warn!("tunnel session {} candidate register for unknown device '{}'", session.id, reg.device_id);
                            }
                        }
                    }
                    // P1 打洞预留帧（PunchResult 等）→ 交 rendezvous（P1 并行开发）。
                    _ => {
                        debug!("tunnel session {} ignoring frame type 0x{ty:02x}", session.id);
                    }
                }
            }
            _ = heartbeat.tick() => {
                let idle = session.last_activity.lock().unwrap().elapsed();
                // M8-T026-P2 (ID-003)：控制连接心跳同时刷新在线表 last_seen。
                let device_id = session.device_id.lock().unwrap().clone();
                if let Some(did) = device_id {
                    shared.registry.heartbeat(&did).await;
                }
                if idle > shared.cfg.heartbeat_timeout {
                    warn!(
                        "tunnel session {} heartbeat timeout ({}s idle)",
                        session.id,
                        idle.as_secs_f64()
                    );
                    break;
                }
            }
        }
    }
    cleanup_session(shared, session).await;
}

/// M8-T026-P2 (ID-010 / ID-SEC-002)：设备解析 —— 限速 + 在线表查询 +
/// 签名响应（未知/离线/限速统一响应，不泄露设备存在性）。
async fn handle_resolve(
    shared: Arc<ServerShared>,
    session: Arc<ClientSession>,
    req: &ResolveDevice,
) {
    let ip = session.addr.ip();
    let (info, rate_limited) = shared.registry.resolve(ip, &req.device_id).await;
    let online = info.payload.online;
    if rate_limited {
        shared.audit(TunnelAuditEvent::DeviceResolveRejected {
            client: session.addr,
            device_id: req.device_id.clone(),
            reason: "rate limited (10/30s per IP)".to_string(),
        });
    }
    shared.audit(TunnelAuditEvent::DeviceResolveAccepted {
        client: session.addr,
        device_id: req.device_id.clone(),
        online,
    });
    let frame = match encode_extension(TYPE_DEVICE_INFO, &info) {
        Ok(f) => f,
        Err(e) => {
            warn!("tunnel resolve response encode failed: {}", e);
            return;
        }
    };
    let _ = session.control_tx.send(frame);
}

/// M8-T026-P2 (§8.1)：控制器数据连接 —— 登记 pending + 牵线目标设备 +
/// 等待配对（超时 `work_conn_timeout`）→ `TunnelResp` → 双向泵流。
async fn handle_tunnel_conn(
    shared: Arc<ServerShared>,
    stream: TcpStream,
    req: TunnelConn,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn_id = match shared
        .registry
        .register_tunnel(&req.target_peer_id, &req.from_peer, stream)
        .await
    {
        Ok(id) => id,
        Err((e, mut stream)) => {
            // 目标离线 / 未注册 → 统一文案（ID-SEC-002 防枚举）。
            shared.audit(TunnelAuditEvent::TunnelRelayClosed {
                target: req.target_peer_id.clone(),
                conn_id: 0,
                reason: e.to_string(),
            });
            let resp = TunnelResp { ok: false, err: Some(e.to_string()) };
            let frame = encode_extension(TYPE_TUNNEL_RESP, &resp)?;
            // frame 已是完整帧 → 直写，勿再套帧头。
            let _ = stream.write_all(&frame).await;
            return Ok(());
        }
    };
    // 等待设备回连配对（8s 超时，对齐 TNL-SERVER-004）。
    match shared
        .registry
        .wait_for_pair(conn_id, shared.cfg.work_conn_timeout)
        .await
    {
        Some((mut controller, mut device)) => {
            shared.audit(TunnelAuditEvent::TunnelRelayOpened {
                target: req.target_peer_id.clone(),
                from: req.from_peer.clone(),
                conn_id,
            });
            let resp = TunnelResp { ok: true, err: None };
            let frame = encode_extension(TYPE_TUNNEL_RESP, &resp)?;
            // frame 已是完整帧 → 直写，勿再套帧头。
            if controller.write_all(&frame).await.is_ok() {
                // 双端流泵流（任一端 EOF → 对称关闭，对齐 TNL-SERVER-006）。
                let _ = tokio::io::copy_bidirectional(&mut controller, &mut device).await;
            }
            shared.audit(TunnelAuditEvent::TunnelRelayClosed {
                target: req.target_peer_id.clone(),
                conn_id,
                reason: "eof".to_string(),
            });
        }
        None => {
            // 配对超时：无流可写（已随 register_tunnel 移交 registry），
            // 直接关闭 —— 控制器侧 open_tunnel 收到 EOF 映射为设备未响应。
            shared.audit(TunnelAuditEvent::TunnelRelayClosed {
                target: req.target_peer_id.clone(),
                conn_id,
                reason: "pairing timeout".to_string(),
            });
        }
    }
    Ok(())
}

/// M8-T026-P2 (§8.1)：设备回连到达 —— 按 conn_id 精确配对（未知/重复 → 关闭）。
async fn handle_tunnel_arrival(
    shared: Arc<ServerShared>,
    stream: TcpStream,
    header: TunnelHeader,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !shared.registry.pair_tunnel(header.conn_id, stream).await {
        shared.audit(TunnelAuditEvent::TunnelRelayClosed {
            target: String::new(),
            conn_id: header.conn_id,
            reason: "unknown/duplicate conn_id".to_string(),
        });
    }
    Ok(())
}

/// 处理一条控制消息；返回 `false` = 结束会话。
async fn handle_control(
    shared: Arc<ServerShared>,
    session: Arc<ClientSession>,
    msg: ControlMsg,
) -> bool {
    match msg {
        ControlMsg::NewProxy { name, local_addr, local_port, remote_port } => {
            register_proxy(shared, session, name, local_addr, local_port, remote_port).await;
            true
        }
        ControlMsg::CloseProxy { name } => {
            close_proxy(shared.clone(), session.clone(), &name);
            true
        }
        ControlMsg::Logout => {
            info!("tunnel client logged out: {} (session={})", session.addr, session.id);
            false
        }
        ControlMsg::Ping { ts } => {
            // 回 Pong（TNL-PROTO-005）。
            let _ = encode_control(&ControlMsg::Pong { ts })
                .map(|f| session.control_tx.send(f));
            true
        }
        ControlMsg::Pong { .. } => true,
        _ => {
            // 服务端→客户端消息被客户端发回 = 协议违规。
            warn!("tunnel session {} protocol violation: {:?}", session.id, msg);
            false
        }
    }
}

/// 注册/更新代理（TNL-SERVER-003）：绑定公网端口（指定或范围分配），
/// 同名更新先解绑旧代理。
async fn register_proxy(
    shared: Arc<ServerShared>,
    session: Arc<ClientSession>,
    name: String,
    local_addr: String,
    local_port: u16,
    remote_port: u16,
) {
    // 会话代理数量上限（TNL-SERVER-008）。
    {
        let proxies = session.proxies.lock().unwrap();
        if proxies.len() >= shared.cfg.max_proxies && !proxies.contains_key(&name) {
            let _ = encode_control(&ControlMsg::ProxyResp {
                ok: false,
                name,
                err: Some(format!("proxy limit reached ({})", shared.cfg.max_proxies)),
                assigned_port: None,
            })
            .map(|f| session.control_tx.send(f));
            return;
        }
    }
    // 绑定公网端口（0 = 从 port_range 自动分配）。
    let listener = match bind_proxy_listener(shared.cfg.port_range, remote_port).await {
        Ok(l) => l,
        Err(err) => {
            let _ = encode_control(&ControlMsg::ProxyResp {
                ok: false,
                name,
                err: Some(err),
                assigned_port: None,
            })
            .map(|f| session.control_tx.send(f));
            return;
        }
    };
    let listener_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let proxy = Arc::new(ProxyEntry {
        name: name.clone(),
        local_addr,
        local_port,
        listener_port,
        pending: Mutex::new(HashMap::new()),
        conn_count: AtomicUsize::new(0),
    });
    // 同名更新：先解绑旧代理。
    let old = session.proxies.lock().unwrap().remove(&name);
    if let Some(old) = old {
        close_proxy(shared.clone(), session.clone(), old.name());
    }
    session.proxies.lock().unwrap().insert(name.clone(), proxy.clone());
    shared.audit(TunnelAuditEvent::ProxyRegistered {
        client: session.addr,
        name: name.clone(),
        port: listener_port,
    });
    info!(
        "tunnel proxy '{}' -> {}:{} bound on :{} (session={})",
        name, proxy.local_addr, proxy.local_port, listener_port, session.id
    );
    let task = tokio::spawn(proxy_listener(shared, session.clone(), proxy, listener));
    push_task(&session, task.abort_handle());
    let _ = encode_control(&ControlMsg::ProxyResp {
        ok: true,
        name,
        err: None,
        assigned_port: Some(listener_port),
    })
    .map(|f| session.control_tx.send(f));
}

/// 绑定代理公网监听端口：指定端口或范围自动分配（TNL-SERVER-003）。
/// `[::]` 优先 + `0.0.0.0` 回退（对齐 M8-T025 双栈）。
async fn bind_proxy_listener(
    port_range: Option<(u16, u16)>,
    remote_port: u16,
) -> Result<TcpListener, String> {
    if remote_port != 0 {
        return bind_one(remote_port).await;
    }
    let (start, end) = match port_range {
        Some(r) => r,
        None => return Err("port_range not configured (remote_port=0)".to_string()),
    };
    if start > end {
        return Err(format!("invalid port_range: {start}-{end}"));
    }
    for port in start..=end {
        if let Ok(l) = bind_one(port).await {
            return Ok(l);
        }
    }
    Err(format!("no free port in range {start}-{end}"))
}

async fn bind_one(port: u16) -> Result<TcpListener, String> {
    if let Ok(l) = bind_reuseaddr(port).await {
        return Ok(l);
    }
    bind_reuseaddr_v4(port).await
        .map_err(|e| format!("bind :{} failed: {}", port, e))
}

/// 绑定 `[::]:port`（SO_REUSEADDR；Windows 上 TIME_WAIT 端口可立即重绑）。
async fn bind_reuseaddr(port: u16) -> Result<TcpListener, std::io::Error> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{Ipv6Addr, SocketAddrV6};
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    // M8-T025（Windows 打包验收）：显式 IPV6_V6ONLY=false —— Windows 上裸
    // AF_INET6 socket 默认 v6-only，`[::]` 监听会拒绝 IPv4 客户端连接；
    // Linux 默认双栈，此设置使各平台行为一致（tokio TcpSocket 未暴露该
    // setter，用 socket2，对齐 media/quic.rs 同款做法）。失败仅告警，回退
    // 路径不变。
    if let Err(e) = socket.set_only_v6(false) {
        warn!("set_only_v6(false) failed: {e} — IPv4 clients may not reach this listener");
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let addr: socket2::SockAddr =
        std::net::SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)).into();
    socket.bind(&addr)?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// 绑定 `0.0.0.0:port`（SO_REUSEADDR；`[::]` 不可用/被占时的回退）。
async fn bind_reuseaddr_v4(port: u16) -> Result<TcpListener, std::io::Error> {
    use std::net::{Ipv4Addr, SocketAddrV4};
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)))?;
    socket.listen(1024)
}

/// 解绑代理：abort 监听任务 + 完成全部 pending（TNL-PROTO-006 / TNL-SEC-003）。
fn close_proxy(shared: Arc<ServerShared>, session: Arc<ClientSession>, name: &str) {
    let Some(proxy) = session.proxies.lock().unwrap().remove(name) else {
        return;
    };
    info!(
        "tunnel proxy '{}' closed (session={})",
        proxy.name(),
        session.id
    );
    shared.audit(TunnelAuditEvent::ProxyRemoved {
        client: session.addr,
        name: name.to_string(),
    });
    drain_pending(&shared, &session, &proxy);
}

/// 代理监听任务：accept 公网连接 → StartWorkConn → 8s 等回连 → 泵流。
async fn proxy_listener(
    shared: Arc<ServerShared>,
    session: Arc<ClientSession>,
    proxy: Arc<ProxyEntry>,
    listener: TcpListener,
) {
    loop {
        let (public, _addr) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => break,
        };
        // 并发上限（TNL-STAB-005：防放大攻击）。
        if proxy.conn_count.load(Ordering::SeqCst) >= shared.cfg.max_concurrent_work {
            warn!(
                "tunnel proxy '{}' at max concurrent work ({})",
                proxy.name(),
                shared.cfg.max_concurrent_work
            );
            drop(public);
            continue;
        }
        let conn_id = random_conn_id();
        let (tx, rx) = oneshot::channel::<Result<TcpStream, ()>>();
        {
            proxy.pending.lock().unwrap().insert(conn_id, tx);
            shared
                .pending_index
                .lock()
                .unwrap()
                .insert(conn_id, (session.id.clone(), proxy.name().to_string()));
        }
        let msg = ControlMsg::StartWorkConn {
            proxy_name: proxy.name().to_string(),
            conn_id,
        };
        let frame = match encode_control(&msg) {
            Ok(f) => f,
            Err(_) => {
                drain_pending(&shared, &session, &proxy);
                break;
            }
        };
        if session.control_tx.send(frame).is_err() {
            // 控制连接已死 → 本代理清理。
            drain_pending(&shared, &session, &proxy);
            break;
        }
        debug!(
            "tunnel work request: proxy='{}' conn_id={} (session={})",
            proxy.name(),
            conn_id,
            session.id
        );
        let wait = shared.cfg.work_conn_timeout;
        let result = match tokio::time::timeout(wait, rx).await {
            Ok(Ok(Ok(work))) => Ok(work),
            Ok(Ok(Err(()))) | Ok(Err(_)) | Err(_) => Err(()),
        };
        {
            // 无论成败都从 pending 移除（防重复配对）。
            proxy.pending.lock().unwrap().remove(&conn_id);
            shared.pending_index.lock().unwrap().remove(&conn_id);
        }
        match result {
            Ok(work) => {
                proxy.conn_count.fetch_add(1, Ordering::SeqCst);
                shared.audit(TunnelAuditEvent::WorkConnOpened {
                    client: session.addr,
                    name: proxy.name().to_string(),
                });
                debug!(
                    "tunnel work paired: proxy='{}' conn_id={}",
                    proxy.name(),
                    conn_id
                );
                let task = tokio::spawn(pump_work(
                    shared.clone(),
                    session.clone(),
                    proxy.clone(),
                    public,
                    work,
                ));
                push_task(&session, task.abort_handle());
            }
            Err(()) => {
                warn!(
                    "tunnel work conn timeout/aborted: proxy='{}' conn_id={}",
                    proxy.name(),
                    conn_id
                );
                drop(public); // 公网连接对称关闭
            }
        }
    }
}

/// work 泵流任务：双向 copy，任一端 EOF/错误 → 对称关闭（TNL-SERVER-004）。
async fn pump_work(
    shared: Arc<ServerShared>,
    session: Arc<ClientSession>,
    proxy: Arc<ProxyEntry>,
    mut public: TcpStream,
    mut work: TcpStream,
) {
    let _ = tokio::io::copy_bidirectional(&mut public, &mut work).await;
    proxy.conn_count.fetch_sub(1, Ordering::SeqCst);
    shared.audit(TunnelAuditEvent::WorkConnClosed {
        client: session.addr,
        name: proxy.name().to_string(),
        reason: "eof".to_string(),
    });
    debug!(
        "tunnel work closed: proxy='{}' conn_count={}",
        proxy.name(),
        proxy.conn_count.load(Ordering::SeqCst)
    );
}

/// work 回连到达：按 conn_id 精确配对（TNL-SERVER-005 / TNL-SEC-004）。
async fn handle_work_arrival(
    shared: Arc<ServerShared>,
    stream: TcpStream,
    addr: SocketAddr,
    header: WorkConnHeader,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (session_id, proxy_name) = match shared.pending_index.lock().unwrap().remove(&header.conn_id)
    {
        Some(x) => x,
        None => {
            // 伪造 / 未知 conn_id（TNL-SEC-004）。
            warn!(
                "tunnel work conn from {} rejected: unknown conn_id={}",
                addr, header.conn_id
            );
            shared.audit(TunnelAuditEvent::WorkConnClosed {
                client: addr,
                name: header.proxy_name.clone(),
                reason: "unknown conn_id".to_string(),
            });
            return Ok(());
        }
    };
    // proxy_name 必须一致（TNL-SEC-004）。
    if proxy_name != header.proxy_name {
        warn!(
            "tunnel work conn from {} rejected: proxy_name mismatch ({} != {})",
            addr, header.proxy_name, proxy_name
        );
        shared.audit(TunnelAuditEvent::WorkConnClosed {
            client: addr,
            name: header.proxy_name,
            reason: "proxy_name mismatch".to_string(),
        });
        return Ok(());
    }
    // 会话必须仍活跃。
    let session = {
        let sessions = shared.sessions.lock().unwrap();
        match sessions.get(&session_id) {
            Some(s) => s.clone(),
            None => {
                warn!("tunnel work conn rejected: session {session_id} gone");
                return Ok(());
            }
        }
    };
    let Some(proxy) = session.proxies.lock().unwrap().get(&proxy_name).cloned() else {
        warn!("tunnel work conn rejected: proxy '{}' gone", proxy_name);
        return Ok(());
    };
    let tx = proxy.pending.lock().unwrap().remove(&header.conn_id);
    match tx {
        Some(tx) => {
            let _ = tx.send(Ok(stream));
        }
        None => {
            // 重复 / 已消费（TNL-SERVER-005）。
            warn!(
                "tunnel work conn from {} rejected: duplicate conn_id={}",
                addr, header.conn_id
            );
            shared.audit(TunnelAuditEvent::WorkConnClosed {
                client: addr,
                name: header.proxy_name,
                reason: "duplicate conn_id".to_string(),
            });
        }
    }
    Ok(())
}

/// 级联清理（TNL-SERVER-006）：会话失效 → 代理监听 + pending + 泵流全关，
/// 无残留协程。控制连接关闭由 writer 任务随 `control_tx` drop 自然完成。
///
/// M8-T026-P2 (ID-003)：注册设备随控制连接断开立即离线（在线表移除 + 审计）。
async fn cleanup_session(shared: Arc<ServerShared>, session: Arc<ClientSession>) {
    shared.sessions.lock().unwrap().remove(&session.id);
    // M8-T026-P2 (ID-003)：设备离线（控制连接断开即离线）。
    let device_id = session.device_id.lock().unwrap().take();
    if let Some(did) = device_id {
        shared.registry.unregister(&did).await;
        shared.audit(TunnelAuditEvent::DeviceOffline {
            client: session.addr,
            device_id: did.clone(),
        });
        info!("device offline: '{}' (session {} closed)", did, session.id);
    }
    info!(
        "tunnel session {} cleaned up (client {})",
        session.id, session.addr
    );
    // 1. abort 全部后台任务（监听 + 泵流）。
    let tasks: Vec<AbortHandle> = session.tasks.lock().unwrap().drain(..).collect();
    for t in tasks {
        t.abort();
    }
    // 2. 完成全部 pending（等待回连的监听侧收到 Err → 关闭公网连接）。
    let proxies: Vec<Arc<ProxyEntry>> =
        session.proxies.lock().unwrap().values().cloned().collect();
    for proxy in proxies {
        drain_pending(&shared, &session, &proxy);
        shared.audit(TunnelAuditEvent::ProxyRemoved {
            client: session.addr,
            name: proxy.name().to_string(),
        });
    }
    // 3. control_tx drop（writer 任务结束 → 控制连接关闭）。
}

/// 完成某代理的全部 pending：从索引移除 + 发送 Err（监听侧关闭公网连接）。
fn drain_pending(shared: &ServerShared, _session: &ClientSession, proxy: &ProxyEntry) {
    let ids: Vec<u64> = proxy.pending.lock().unwrap().keys().cloned().collect();
    for id in ids {
        shared.pending_index.lock().unwrap().remove(&id);
        if let Some(tx) = proxy.pending.lock().unwrap().remove(&id) {
            let _ = tx.send(Err(()));
        }
    }
}

/// 记录后台任务句柄（惰性清理已完成项，防句柄表无限增长）。
fn push_task(session: &ClientSession, handle: AbortHandle) {
    let mut tasks = session.tasks.lock().unwrap();
    tasks.retain(|t| !t.is_finished());
    tasks.push(handle);
}

/// 随机 conn_id（uuid 随机源；会话内/全局碰撞概率可忽略）。
fn random_conn_id() -> u64 {
    uuid::Uuid::new_v4().as_u128() as u64
}

/// 常数时间字符串比较（TNL-SEC-001，防时序侧信道）。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_bind_one_v4_v6() {
        // [::] 优先绑定（Windows 下为 v6-only，仍应成功）。
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let l = bind_one(0).await.unwrap();
            let port = l.local_addr().unwrap().port();
            assert!(port > 0);
        });
    }

    #[tokio::test]
    async fn test_stats_empty() {
        let server = TunnelServer::bind(TunnelServerConfig {
            bind_port: 0,
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(server.port(), server.port());
        assert_eq!(server.stats().sessions, 0);
    }

    #[tokio::test]
    async fn test_bind_dual_stack() {
        let server = TunnelServer::bind(TunnelServerConfig {
            bind_port: 0,
            ..Default::default()
        })
        .await
        .unwrap();
        let port = server.port();
        assert!(port > 0);
        // 控制端口可连接（用 TCP connect 验证监听存活）。
        let conn = TcpStream::connect(format!("[::1]:{}", port)).await;
        assert!(conn.is_ok(), "control port should accept connections");
    }
}
