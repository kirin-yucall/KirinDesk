//! M8-T026-P2: 设备侧 ID 注册客户端 + 控制器解析/中继辅助（ID-001/003/005/010/011③）。
//!
//! 与并行开发的 `client.rs`（T003 端口代理 frpc）**职责分离**：本模块只做
//! 设备 ID 模式 —— `Login` 携带 `device_id` 注册在线表 + 心跳保活（与 M8-T026
//! 控制连接心跳**合并**，ID-NF-003 不新增包）+ `CandidateRegister` 候选刷新
//! （ID-005）+ `TunnelRequest` 接收（§8.1 设备级中继兜底）。
//!
//! 控制器侧辅助：
//! - [`resolve_device_verified`]：一次性解析（ID-010）+ 服务器签名验签（ID-SEC-001）；
//! - [`open_tunnel`]：中继数据连接（ID-011③）。

use crate::protocol::{
    decode_control, decode_extension, encode_control, encode_extension, read_frame, Candidate,
    CandidateKind, ControlMsg, DeviceInfo, TunnelConn, TunnelHeader, TunnelRequest, TunnelResp,
    PROTOCOL_VERSION, TYPE_CONTROL, TYPE_DEVICE_INFO, TYPE_TUNNEL_CONN, TYPE_TUNNEL_HEADER,
    TYPE_TUNNEL_RESP,
};
use ed25519_dalek::VerifyingKey;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};

/// 默认心跳间隔（对齐 TNL-STAB-001，10s）。
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// 默认心跳超时（对齐 TNL-STAB-001，30s）。
pub const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);
/// 默认拨号超时（对齐 TNL-CLIENT-001，5s）。
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 默认退避基准（对齐 TNL-STAB-003，1s）。
pub const DEFAULT_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// 默认退避封顶（对齐 TNL-STAB-003，60s）。
pub const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// 本地候选默认优先级。
const LOCAL_CANDIDATE_PRIORITY: u8 = 100;

/// ID 客户端配置。
#[derive(Debug, Clone)]
pub struct IdClientConfig {
    /// 服务器地址：`host:port` / `ipv4:port` / `[ipv6]:port`（支持域名）。
    pub server_addr: String,
    /// token 认证（TNL-SEC-001）。
    pub token: String,
    /// 注册设备 ID（ID-001：显式配置或公钥指纹派生）。
    pub device_id: String,
    /// 本设备 Ed25519 公钥（base64；服务器唯一性校验 ID-004）。
    pub ed25519_pub: String,
    /// 登录上报的主机名（TNL-PROTO-002）。
    pub hostname: String,
    /// 心跳间隔（TNL-STAB-001）。
    pub heartbeat_interval: Duration,
    /// 心跳超时（TNL-STAB-001/002）。
    pub heartbeat_timeout: Duration,
    /// 拨号服务器超时。
    pub connect_timeout: Duration,
    /// 退避基准（TNL-STAB-003）。
    pub backoff_base: Duration,
    /// 退避封顶（TNL-STAB-003）。
    pub backoff_max: Duration,
    /// 本地候选（ID-005；服务器另附加观察地址）。
    pub extra_candidates: Vec<Candidate>,
}

impl Default for IdClientConfig {
    fn default() -> Self {
        Self {
            server_addr: String::new(),
            token: String::new(),
            device_id: String::new(),
            ed25519_pub: String::new(),
            hostname: "kirindesk".to_string(),
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            backoff_base: DEFAULT_BACKOFF_BASE,
            backoff_max: DEFAULT_BACKOFF_MAX,
            extra_candidates: Vec::new(),
        }
    }
}

/// ID 客户端错误。
#[derive(Debug, thiserror::Error)]
pub enum IdClientError {
    #[error("connect to {server} failed: {source}")]
    Connect { server: String, source: std::io::Error },
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("login rejected: {0}")]
    LoginRejected(String),
    /// M8-T026-P3：服务器认证失败（双向认证回执校验失败 / fail-closed
    /// 拒绝，TNL-SEC-007/008）。
    #[error("server authentication failed: {0}")]
    ServerAuthFailed(String),
    #[error("device id conflict: {0}")]
    DeviceConflict(String),
    #[error("device unavailable: {0}")]
    DeviceUnavailable(String),
    #[error("signature verification failed")]
    SignatureVerification,
    #[error("protocol error: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("graceful shutdown")]
    Shutdown,
}

/// 客户端运行状态（`tunnel status` 用）。
#[derive(Debug, Clone, Default)]
pub struct IdClientStatus {
    /// 是否已登录并注册设备 ID。
    pub registered: bool,
    /// 累计重连次数。
    pub reconnect_count: u64,
}

/// 会话内部状态。
struct SessionState {
    last_pong: Instant,
}

/// 客户端共享状态。
struct IdClientState {
    stop: AtomicBool,
    stop_notify: Notify,
    session: Mutex<Option<SessionState>>,
    reconnect_count: AtomicU64,
}

/// 设备侧 ID 注册客户端。
///
/// `on_tunnel_stream` 为设备级中继（§8.1）到达回调：服务器把控制器数据连接与
/// 本设备回连配对后，回调收到设备侧数据流（调用方在此流上执行 KirinDesk
/// 服务端 Ed25519 握手 + 会话处理 —— ID-013 访问控制零降级）。
#[derive(Clone)]
pub struct IdClient {
    cfg: IdClientConfig,
    state: Arc<IdClientState>,
    on_tunnel_stream: Arc<dyn Fn(TcpStream) + Send + Sync>,
}

impl IdClient {
    pub fn new(
        cfg: IdClientConfig,
        on_tunnel_stream: impl Fn(TcpStream) + Send + Sync + 'static,
    ) -> Self {
        Self {
            cfg,
            state: Arc::new(IdClientState {
                stop: AtomicBool::new(false),
                stop_notify: Notify::new(),
                session: Mutex::new(None),
                reconnect_count: AtomicU64::new(0),
            }),
            on_tunnel_stream: Arc::new(on_tunnel_stream),
        }
    }

    /// 请求优雅退出（TNL-CLIENT-007 对齐）：发 `Logout` 后关闭控制连接。
    pub fn stop(&self) {
        self.state.stop.store(true, Ordering::SeqCst);
        self.state.stop_notify.notify_one();
    }

    /// 当前状态（`tunnel status` 用）。
    pub fn status(&self) -> IdClientStatus {
        IdClientStatus {
            registered: self
                .state
                .session
                .lock()
                .unwrap()
                .as_ref()
                .is_some(),
            reconnect_count: self.state.reconnect_count.load(Ordering::SeqCst),
        }
    }

    /// 主循环：连接 → 登录注册 → 候选登记 → 控制循环；会话失效 → 退避重连，
    /// 直到 [`IdClient::stop`]（对齐 TNL-STAB-003）。
    pub async fn run(&self) -> Result<(), IdClientError> {
        let mut attempt: u32 = 0;
        loop {
            if self.state.stop.load(Ordering::SeqCst) {
                return Ok(());
            }
            match self.connect_session().await {
                Ok(()) => {
                    if self.state.stop.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                }
                Err(e) => {
                    match &e {
                        IdClientError::Shutdown => return Ok(()),
                        IdClientError::DeviceConflict(reason) => {
                            warn!("device id registration conflict: {} — retrying", reason);
                        }
                        IdClientError::LoginRejected(reason) => {
                            warn!("id login rejected: {} — retrying", reason);
                        }
                        _ => warn!("id session lost: {}", e),
                    }
                    self.state
                        .reconnect_count
                        .fetch_add(1, Ordering::SeqCst);
                    attempt += 1;
                    let delay = backoff_delay(attempt, &self.cfg);
                    info!("id client reconnect in {:?} (attempt {})", delay, attempt);
                    let delay = tokio::time::sleep(delay);
                    tokio::pin!(delay);
                    tokio::select! {
                        _ = &mut delay => {}
                        _ = self.state.stop_notify.notified() => return Ok(()),
                    }
                }
            }
        }
    }

    /// 建立一次会话：拨号 → Login（带 device_id）→ 候选登记 → 控制循环。
    /// `Ok` = 优雅结束；`Err` = 判死（需重连）。
    async fn connect_session(&self) -> Result<(), IdClientError> {
        let cfg = &self.cfg;
        // 1. 拨号（带超时）。
        let stream = tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(&cfg.server_addr))
            .await
            .map_err(|_| IdClientError::Timeout(format!("connect {}", cfg.server_addr)))?
            .map_err(|e| IdClientError::Connect {
                server: cfg.server_addr.clone(),
                source: e,
            })?;
        debug!("id client connected to {}", cfg.server_addr);
        let (mut reader, mut writer) = stream.into_split();
        // 2. writer 任务（串行写控制帧；含扩展帧 push）。
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let writer_task = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
            }
        });
        // 3. Login（ID-001：携带 device_id + ed25519_pub）— M8-T026-P3
        // 挑战-响应认证（TNL-SEC-006~008）：口令永不明文上线；双向认证
        // 回执校验；带口令客户端遇未认证服务器 fail-closed 拒绝。
        let auth_fields = crate::auth::LoginFields {
            version: PROTOCOL_VERSION.to_string(),
            hostname: cfg.hostname.clone(),
            device_id: Some(cfg.device_id.clone()),
            ed25519_pub: Some(cfg.ed25519_pub.clone()),
        };
        // clone 进 async 块（future 不得借用 send 参数）；引用为 Copy，
        // 外层闭包借引用保持 Fn 语义。
        let auth_send = |msg: &ControlMsg| {
            let msg = msg.clone();
            let tx_ref = &tx;
            async move {
                let frame = encode_control(&msg)?;
                tx_ref.send(frame).map_err(|_| {
                    IdClientError::Io(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "control channel closed",
                    ))
                })
            }
        };
        let outcome = crate::auth::authenticate(
            &mut reader,
            auth_send,
            &cfg.token,
            cfg.connect_timeout,
            &auth_fields,
        )
        .await
        .map_err(map_id_auth_error)?;
        debug!("id client auth outcome: {:?}", outcome);
        // 4. 候选登记（ID-005；本地候选 + 配置 extra）。
        let candidates = collect_local_candidates(&cfg.extra_candidates).await;
        let reg = crate::protocol::CandidateRegister {
            device_id: cfg.device_id.clone(),
            session_id: None, // P1 打洞会话使用；P2 纯注册不携带
            candidates,
        };
        let frame = encode_extension(crate::protocol::TYPE_CANDIDATE_REGISTER, &reg)?;
        tx.send(frame)
            .map_err(|_| IdClientError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "control channel closed",
            )))?;
        // 5. 会话状态 + 控制循环。
        {
            let mut session = self.state.session.lock().unwrap();
            *session = Some(SessionState {
                last_pong: Instant::now(),
            });
        }
        info!(
            "id device registered: '{}' on {}",
            cfg.device_id, cfg.server_addr
        );
        let result = self.control_loop(&mut reader, &tx).await;
        self.state.session.lock().unwrap().take();
        let _ = writer_task.abort();
        result
    }

    /// 控制循环：读帧（心跳超时判死）/ 心跳 Ping / stop 三路 select。
    async fn control_loop(
        &self,
        reader: &mut (impl tokio::io::AsyncRead + Unpin),
        tx: &mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<(), IdClientError> {
        let cfg = &self.cfg;
        let timeout = cfg.heartbeat_timeout.max(cfg.heartbeat_interval + Duration::from_millis(1));
        let mut heartbeat = tokio::time::interval(cfg.heartbeat_interval);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let server_addr = cfg.server_addr.clone();
        let connect_timeout = cfg.connect_timeout;
        let on_tunnel_stream = self.on_tunnel_stream.clone();
        loop {
            tokio::select! {
                _ = self.state.stop_notify.notified() => {
                    if self.state.stop.load(Ordering::SeqCst) {
                        let _ = encode_control(&ControlMsg::Logout)
                            .map(|f| tx.send(f));
                        return Err(IdClientError::Shutdown);
                    }
                }
                frame = read_frame(reader) => {
                    let (ty, payload) = match frame {
                        Ok(x) => x,
                        Err(_) => {
                            // 控制连接 EOF / 坏帧 → 判死重连。
                            return Err(IdClientError::Protocol(
                                crate::protocol::ProtocolError::Bincode(
                                    "control connection closed".to_string(),
                                ),
                            ));
                        }
                    };
                    match ty {
                        TYPE_CONTROL => match decode_control(ty, &payload) {
                            Ok(ControlMsg::Pong { .. }) => {
                                if let Some(s) = self.state.session.lock().unwrap().as_mut() {
                                    s.last_pong = Instant::now();
                                }
                            }
                            // TNL-PROTO-005 双向：服务器 Ping → 回 Pong。
                            Ok(ControlMsg::Ping { ts }) => {
                                let _ = encode_control(&ControlMsg::Pong { ts })
                                    .map(|f| tx.send(f));
                            }
                            Ok(ControlMsg::LoginResp { ok: false, err, .. }) => {
                                // 会话中途被拒（重注册冲突等）→ 判死重连。
                                return Err(IdClientError::LoginRejected(
                                    err.unwrap_or_else(|| "login rejected".to_string()),
                                ));
                            }
                            Ok(_) => {}
                            Err(e) => return Err(IdClientError::Protocol(e)),
                        },
                        crate::protocol::TYPE_TUNNEL_REQUEST => {
                            // §8.1：设备级中继牵线 → 回连 + 首帧 + 交给回调。
                            let req: TunnelRequest = match decode_extension(
                                ty, &payload, crate::protocol::TYPE_TUNNEL_REQUEST,
                            ) {
                                Ok(r) => r,
                                Err(e) => {
                                    warn!("id client bad TunnelRequest frame: {}", e);
                                    continue;
                                }
                            };
                            let conn_id = req.conn_id;
                            let _from = req.from_peer;
                            let server = server_addr.clone();
                            let ctimeout = connect_timeout;
                            let cb = on_tunnel_stream.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_tunnel_request(server, ctimeout, conn_id, cb).await {
                                    warn!("id tunnel request handling failed: {}", e);
                                }
                            });
                        }
                        _ => {
                            // 未知/未处理扩展帧（P1 打洞帧等）→ 忽略。
                            debug!("id client ignoring frame type 0x{ty:02x}");
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    let stale = self.state.session.lock().unwrap().as_ref()
                        .map(|s| s.last_pong.elapsed() > timeout)
                        .unwrap_or(false);
                    if stale {
                        warn!("id heartbeat timeout (no Pong for {:?})", timeout);
                        return Err(IdClientError::Timeout("heartbeat".to_string()));
                    }
                    // ID-NF-003：心跳与 M8-T026 控制连接合并，不新增包。
                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    let _ = encode_control(&ControlMsg::Ping { ts })
                        .map(|f| tx.send(f));
                }
            }
        }
    }
}

/// §8.1 设备侧：回连服务器 → 首帧 `TunnelHeader{conn_id}` → 交回调
/// （回调执行 KirinDesk 服务端握手 + 会话；服务器负责与控制器泵流）。
async fn handle_tunnel_request(
    server_addr: String,
    connect_timeout: Duration,
    conn_id: u64,
    on_tunnel_stream: Arc<dyn Fn(TcpStream) + Send + Sync>,
) -> Result<(), IdClientError> {
    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(&server_addr))
        .await
        .map_err(|_| IdClientError::Timeout("tunnel back-connect".to_string()))?
        .map_err(|e| IdClientError::Connect {
            server: server_addr.clone(),
            source: e,
        })?;
    let header = TunnelHeader { conn_id };
    let frame = encode_extension(TYPE_TUNNEL_HEADER, &header)?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    debug!("id tunnel back-connected: conn_id={conn_id}");
    // 回调接管流（KirinDesk 服务端握手 + 会话处理）。
    on_tunnel_stream(stream);
    Ok(())
}

/// ID-005：本地候选收集 —— 非回环接口地址（TCP 候选）+ 配置 `extra_candidates`，
/// 按优先级降序（服务器另行附加观察地址）。
pub async fn collect_local_candidates(extra: &[Candidate]) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut seen: Vec<std::net::SocketAddr> = Vec::new();
    let mut push = |c: Candidate, seen: &mut Vec<std::net::SocketAddr>| {
        if !seen.contains(&c.addr) {
            seen.push(c.addr);
            out.push(c);
        }
    };
    // 非回环接口地址（get-if-addrs；Windows/Linux/macOS 通用）。
    if let Ok(ifaces) = get_if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            let ip = iface.ip();
            let addr = std::net::SocketAddr::new(ip, 0);
            push(
                Candidate {
                    addr,
                    kind: CandidateKind::Tcp,
                    priority: LOCAL_CANDIDATE_PRIORITY,
                },
                &mut seen,
            );
        }
    }
    for c in extra {
        push(c.clone(), &mut seen);
    }
    out.sort_by(|a, b| b.priority.cmp(&a.priority));
    out
}

/// 认证错误 → ID 客户端错误映射（M8-T026-P3 语义保持：登录被拒保留
/// DeviceConflict 判定；双向认证 / fail-closed → ServerAuthFailed）。
fn map_id_auth_error(e: crate::auth::ClientAuthError) -> IdClientError {
    use crate::auth::ClientAuthError;
    match e {
        ClientAuthError::LoginRejected(reason) => {
            if reason.contains("conflict") || reason.contains("device_id") {
                IdClientError::DeviceConflict(reason)
            } else {
                IdClientError::LoginRejected(reason)
            }
        }
        ClientAuthError::Timeout(t) => IdClientError::Timeout(t),
        ClientAuthError::NoTokenForChallenge => IdClientError::ServerAuthFailed(
            "server requires challenge-response auth, but no token is configured locally (TNL-SEC-008)"
                .to_string(),
        ),
        ClientAuthError::LegacyServerRejected => IdClientError::ServerAuthFailed(
            "server did not issue an auth challenge (unauthenticated server); refusing to continue with token configured (TNL-SEC-008)"
                .to_string(),
        ),
        ClientAuthError::ServerReceiptMismatch => IdClientError::ServerAuthFailed(
            "server auth receipt verification failed (T4)".to_string(),
        ),
        ClientAuthError::ServerReceiptMissing => IdClientError::ServerAuthFailed(
            "server login response lacks auth receipt (T4)".to_string(),
        ),
        other => IdClientError::Protocol(crate::protocol::ProtocolError::Bincode(
            other.to_string(),
        )),
    }
}

/// ID-010：控制器一次性解析（Login 纯控制连接 → ResolveDevice → DeviceInfo）。
pub async fn resolve_device(
    server_addr: &str,
    token: &str,
    device_id: &str,
    connect_timeout: Duration,
) -> Result<DeviceInfo, IdClientError> {
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(server_addr))
        .await
        .map_err(|_| IdClientError::Timeout(format!("connect {server_addr}")))?
        .map_err(|e| IdClientError::Connect {
            server: server_addr.to_string(),
            source: e,
        })?;
    let (mut reader, writer) = stream.into_split();
    // Login（ID-001：纯解析不注册，device_id = None）— M8-T026-P3
    // 挑战-响应认证（TNL-SEC-006~008）：口令永不明文上线；带口令客户端
    // 遇未认证服务器 fail-closed 拒绝。
    let auth_fields = crate::auth::LoginFields {
        version: PROTOCOL_VERSION.to_string(),
        hostname: "resolver".to_string(),
        device_id: None,
        ed25519_pub: None,
    };
    // 写半经 Arc<Mutex> 共享（future 不得借用 send 参数）；完整帧直写
    // （encode_control 已含帧头）。
    let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));
    let auth_writer = writer.clone();
    let auth_send = move |msg: &ControlMsg| {
        let w = auth_writer.clone();
        let msg = msg.clone();
        async move {
            let mut w = w.lock().await;
            let frame = encode_control(&msg).map_err(|e| e.to_string())?;
            w.write_all(&frame).await.map_err(|e| e.to_string())?;
            w.flush().await.map_err(|e| e.to_string())
        }
    };
    crate::auth::authenticate(
        &mut reader,
        auth_send,
        token,
        connect_timeout,
        &auth_fields,
    )
    .await
    .map_err(map_id_auth_error)?;
    // ResolveDevice（ID-010）。
    let req = crate::protocol::ResolveDevice {
        device_id: device_id.to_string(),
    };
    // 完整帧直写（encode_extension 已含帧头）。
    let frame = encode_extension(crate::protocol::TYPE_RESOLVE_DEVICE, &req)?;
    writer.lock().await.write_all(&frame).await?;
    writer.lock().await.flush().await?;
    let (ty, payload) = tokio::time::timeout(connect_timeout, read_frame(&mut reader))
        .await
        .map_err(|_| IdClientError::Timeout("resolve response".to_string()))??;
    let info: DeviceInfo =
        decode_extension(ty, &payload, TYPE_DEVICE_INFO)?;
    Ok(info)
}

/// ID-010 + ID-SEC-001：解析并验签（`verify_key` = 服务器公钥，配置预置）。
pub async fn resolve_device_verified(
    server_addr: &str,
    token: &str,
    device_id: &str,
    verify_key: &VerifyingKey,
    connect_timeout: Duration,
) -> Result<DeviceInfo, IdClientError> {
    let info = resolve_device(server_addr, token, device_id, connect_timeout).await?;
    if !crate::registry::Registry::verify_device_info(verify_key, &info) {
        // ID-SEC-001：伪造/篡改响应 → 拒绝。
        return Err(IdClientError::SignatureVerification);
    }
    Ok(info)
}

/// ID-011③：控制器中继数据连接 —— `TunnelConn` 首帧 → `TunnelResp` → 数据流
/// （在此流上与目标设备执行 Ed25519 双向握手，ID-013）。
///
/// `token` 参数保留（数据连接不认证，TNL-PROTO 对齐）；服务器未应答 /
/// 配对超时（EOF）→ 映射为设备未响应（ID-SEC-002 统一文案）。
pub async fn open_tunnel(
    server_addr: &str,
    _token: &str,
    target: &str,
    from_peer: &str,
    connect_timeout: Duration,
) -> Result<TcpStream, IdClientError> {
    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(server_addr))
        .await
        .map_err(|_| IdClientError::Timeout(format!("connect {server_addr}")))?
        .map_err(|e| IdClientError::Connect {
            server: server_addr.to_string(),
            source: e,
        })?;
    let req = TunnelConn {
        target_peer_id: target.to_string(),
        from_peer: from_peer.to_string(),
    };
    // 完整帧直写（encode_extension 已含帧头）。
    stream
        .write_all(&encode_extension(TYPE_TUNNEL_CONN, &req)?)
        .await?;
    stream.flush().await?;
    let (ty, payload) = tokio::time::timeout(connect_timeout, read_frame(&mut stream))
        .await
        .map_err(|_| IdClientError::Timeout("tunnel response".to_string()))??;
    let resp: TunnelResp = decode_extension(ty, &payload, TYPE_TUNNEL_RESP)?;
    if !resp.ok {
        // 目标离线 / 未注册 → 统一文案（ID-SEC-002）。
        return Err(IdClientError::DeviceUnavailable(
            resp.err.unwrap_or_else(|| "device unavailable".to_string()),
        ));
    }
    Ok(stream)
}

/// 指数退避 + 抖动（TNL-STAB-003）：`base × 2^(attempt-1)` 封顶 `max`，附加 0~1s
/// 抖动。attempt 从 1 起。
pub fn backoff_delay(attempt: u32, cfg: &IdClientConfig) -> Duration {
    let exp = cfg.backoff_base.saturating_mul(1u32 << attempt.saturating_sub(1).min(20));
    let base = exp.min(cfg.backoff_max);
    let jitter_ms = (uuid::Uuid::new_v4().as_u128() % 1001) as u64;
    base + Duration::from_millis(jitter_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_sequence_and_cap() {
        let cfg = IdClientConfig::default();
        assert!(backoff_delay(1, &cfg) >= Duration::from_secs(1));
        assert!(backoff_delay(1, &cfg) < Duration::from_secs(2));
        assert!(backoff_delay(6, &cfg) >= Duration::from_secs(32));
        let capped = backoff_delay(30, &cfg);
        assert!(capped >= Duration::from_secs(60));
        assert!(capped <= Duration::from_secs(61));
    }

    #[tokio::test]
    async fn test_collect_local_candidates() {
        let cands = collect_local_candidates(&[]).await;
        // 本地接口候选非空（CI/本机至少 loopback 被排除后仍可能有接口）。
        assert!(!cands.iter().any(|c| c.addr.ip().is_loopback()));
        // 配置 extra 附加 + 去重。
        let extra = vec![Candidate {
            addr: "203.0.113.1:3389".parse().unwrap(),
            kind: CandidateKind::Tcp,
            priority: 150,
        }];
        let cands2 = collect_local_candidates(&extra).await;
        assert!(cands2.iter().any(|c| c.addr == "203.0.113.1:3389".parse().unwrap()));
        // 优先级降序。
        assert!(cands2.windows(2).all(|w| w[0].priority >= w[1].priority));
    }
}
