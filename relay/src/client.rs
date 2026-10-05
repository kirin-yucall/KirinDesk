//! T003: 隧道客户端（frpc 等价）— Login + 代理注册 / 控制循环 /
//! 心跳与判死 / 指数退避+抖动重连 / StartWorkConn 处理 / 本地拨号 / 泵流。
//!
//! 职责对照（TNL-CLIENT-001~008、TNL-STAB-001~003）：
//! - 启动即连 `server_addr`（域名 / IPv4 / IPv6，拨号带超时）→ `Login` →
//!   等待 `LoginResp{ok}`；失败进入退避重连；
//! - 登录成功后逐条 `NewProxy`（失败重试 ≤3 次，仍失败记日志继续）；
//! - 控制循环：`StartWorkConn` → 查代理表 → 拨本地（2s）→ 回连服务器 →
//!   `WorkConnHeader` → 双向泵流；任一端 EOF → 对称关闭；
//! - 心跳：每 `heartbeat_interval` 发 `Ping`；`heartbeat_timeout` 无 `Pong`
//!   或控制连接 EOF → 判死 → 关闭全部 work 连接 → 退避重连（全量重注册）；
//! - 优雅退出（`stop()`）：发 `Logout` 后关闭控制连接。

use crate::protocol::{
    decode_control, decode_extension, encode_control, encode_extension, encode_work_header,
    read_frame, ControlMsg, DirDelete, DirError, DirErrorCode, DirEntry, DirList, DirListResp,
    DirScope, DirUpsert, WorkConnHeader, TYPE_DIR_DELETE, TYPE_DIR_ERROR, TYPE_DIR_LIST,
    TYPE_DIR_LIST_RESP, TYPE_DIR_UPSERT, PROTOCOL_VERSION,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};
use tokio::task::AbortHandle;
use tracing::{debug, info, warn};

/// 默认心跳间隔（TNL-STAB-001，10s）。
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// 默认心跳超时（TNL-STAB-001，30s = 连续 3 个心跳周期）。
pub const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);
/// 默认拨号超时（TNL-CLIENT-001）。
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 默认本地拨号超时（TNL-CLIENT-003，2s）。
pub const DEFAULT_LOCAL_DIAL_TIMEOUT: Duration = Duration::from_secs(2);
/// 默认退避基准（TNL-STAB-003，1s）。
pub const DEFAULT_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// 默认退避封顶（TNL-STAB-003，60s）。
pub const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// 抖动上限（TNL-STAB-003，0~1s）。
const JITTER_MAX_MS: u64 = 1000;

/// 代理规格（`[tunnel] proxies` 条目）。
#[derive(Debug, Clone)]
pub struct ProxySpec {
    pub name: String,
    pub local_addr: String,
    pub local_port: u16,
    /// 0 = 服务端分配（以 `ProxyResp.assigned_port` 为准）。
    pub remote_port: u16,
}

/// 客户端配置。
#[derive(Debug, Clone)]
pub struct TunnelClientConfig {
    /// 服务器地址：`host:port` / `ipv4:port` / `[ipv6]:port`（支持域名）。
    pub server_addr: String,
    /// token 认证（TNL-SEC-001）。
    pub token: String,
    /// 登录上报的主机名（TNL-PROTO-002）。
    pub hostname: String,
    /// 心跳间隔（TNL-STAB-001）。
    pub heartbeat_interval: Duration,
    /// 心跳超时（TNL-STAB-001/002）。
    pub heartbeat_timeout: Duration,
    /// 拨号服务器超时（TNL-CLIENT-001）。
    pub connect_timeout: Duration,
    /// 本地服务拨号超时（TNL-CLIENT-003）。
    pub local_dial_timeout: Duration,
    /// 退避基准（TNL-STAB-003；默认 1s，测试注入短值）。
    pub backoff_base: Duration,
    /// 退避封顶（TNL-STAB-003；默认 60s）。
    pub backoff_max: Duration,
    /// 待注册代理列表。
    pub proxies: Vec<ProxySpec>,
}

impl Default for TunnelClientConfig {
    fn default() -> Self {
        Self {
            server_addr: String::new(),
            token: String::new(),
            hostname: "kirindesk".to_string(),
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            local_dial_timeout: DEFAULT_LOCAL_DIAL_TIMEOUT,
            backoff_base: DEFAULT_BACKOFF_BASE,
            backoff_max: DEFAULT_BACKOFF_MAX,
            proxies: Vec::new(),
        }
    }
}

/// 客户端错误。
#[derive(Debug, thiserror::Error)]
pub enum TunnelClientError {
    #[error("connect to {server} failed: {source}")]
    Connect { server: String, source: std::io::Error },
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("login rejected: {0}")]
    LoginRejected(String),
    /// 服务器认证失败（双向认证回执校验失败 / fail-closed
    /// 拒绝，TNL-SEC-007/008）。
    #[error("server authentication failed: {0}")]
    ServerAuthFailed(String),
    #[error("protocol error: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("graceful shutdown")]
    Shutdown,
}

/// 客户端运行状态（`tunnel status` 用）。
#[derive(Debug, Clone, Default)]
pub struct ClientStatus {
    /// 是否已建立控制连接并登录成功。
    pub connected: bool,
    /// 代理名 → 公网端口（0 = 尚未注册成功）。
    pub proxies: Vec<(String, u16)>,
    /// 累计重连次数。
    pub reconnect_count: u64,
}

/// 会话内部状态。
struct SessionState {
    connected: bool,
    proxies: HashMap<String, u16>,
    last_pong: Instant,
}

/// 客户端共享状态。
struct ClientState {
    stop: AtomicBool,
    stop_notify: Notify,
    session: Mutex<Option<SessionState>>,
    /// 当前会话的 work 任务（判死/重连时全部关闭，TNL-CLIENT-006）。
    work_tasks: Mutex<Vec<AbortHandle>>,
    /// 本地拨号失败计数（连续 5 次记 WARN，TNL-CLIENT-004）。
    local_failures: Mutex<HashMap<String, u32>>,
    reconnect_count: std::sync::atomic::AtomicU64,
}

/// 隧道客户端（frpc 等价）。
pub struct TunnelClient {
    cfg: TunnelClientConfig,
    state: Arc<ClientState>,
}

impl TunnelClient {
    pub fn new(cfg: TunnelClientConfig) -> Self {
        Self {
            cfg,
            state: Arc::new(ClientState {
                stop: AtomicBool::new(false),
                stop_notify: Notify::new(),
                session: Mutex::new(None),
                work_tasks: Mutex::new(Vec::new()),
                local_failures: Mutex::new(HashMap::new()),
                reconnect_count: std::sync::atomic::AtomicU64::new(0),
            }),
        }
    }

    /// 请求优雅退出（TNL-CLIENT-007）：发 `Logout` 后关闭控制连接。
    /// 可从任意任务/线程调用。
    pub fn stop(&self) {
        self.state.stop.store(true, Ordering::SeqCst);
        self.state.stop_notify.notify_one();
    }

    /// 当前状态（`tunnel status` 用）。
    pub fn status(&self) -> ClientStatus {
        let session = self.state.session.lock().unwrap();
        let mut status = ClientStatus {
            connected: session.as_ref().map(|s| s.connected).unwrap_or(false),
            proxies: session
                .as_ref()
                .map(|s| s.proxies.iter().map(|(k, v)| (k.clone(), *v)).collect())
                .unwrap_or_default(),
            reconnect_count: self.state.reconnect_count.load(Ordering::SeqCst),
        };
        status.proxies.sort();
        status
    }

    /// 主循环（TNL-CLIENT-001/007）：连接 → 登录 → 注册 → 控制循环；
    /// 会话失效 → 退避重连（TNL-STAB-003），直到 `stop()`。
    pub async fn run(&self) -> Result<(), TunnelClientError> {
        let mut attempt: u32 = 0;
        loop {
            if self.state.stop.load(Ordering::SeqCst) {
                return Ok(());
            }
            match self.connect_session().await {
                Ok(()) => {
                    // 优雅退出 / Logout 应答路径。
                    if self.state.stop.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                }
                Err(e) => {
                    self.close_all_work();
                    match &e {
                        TunnelClientError::Shutdown => return Ok(()),
                        TunnelClientError::LoginRejected(reason) => {
                            warn!("tunnel login rejected: {} — retrying", reason);
                        }
                        _ => warn!("tunnel session lost: {}", e),
                    }
                    self.state
                        .reconnect_count
                        .fetch_add(1, Ordering::SeqCst);
                    attempt += 1;
                    let delay = backoff_delay(attempt, &self.cfg);
                    info!("tunnel reconnect in {:?} (attempt {})", delay, attempt);
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

    /// 关闭当前会话的全部 work 连接（TNL-CLIENT-006）。
    fn close_all_work(&self) {
        let tasks: Vec<AbortHandle> = self.state.work_tasks.lock().unwrap().drain(..).collect();
        for t in tasks {
            t.abort();
        }
    }

    /// 建立一次会话：拨号 → 登录 → 注册 → 控制循环。
    /// `Ok` = 优雅结束（Logout / stop）；`Err` = 判死（需重连）。
    async fn connect_session(&self) -> Result<(), TunnelClientError> {
        let cfg = &self.cfg;
        // 1. 拨号（TNL-CLIENT-001，带超时）。
        let stream = tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(&cfg.server_addr))
            .await
            .map_err(|_| TunnelClientError::Timeout(format!("connect {}", cfg.server_addr)))?
            .map_err(|e| TunnelClientError::Connect {
                server: cfg.server_addr.clone(),
                source: e,
            })?;
        debug!("tunnel connected to {}", cfg.server_addr);
        let (mut reader, mut writer) = stream.into_split();
        // 2. writer 任务（串行写控制帧）。
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let writer_task = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
            }
        });
        let send = |tx: &mpsc::UnboundedSender<Vec<u8>>, msg: &ControlMsg| {
            let frame = encode_control(msg)?;
            tx.send(frame)
                .map_err(|_| TunnelClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "control channel closed",
                )))
        };
        // 3. Login（TNL-CLIENT-001 / TNL-PROTO-002）— 挑战-响应
        // 认证（TNL-SEC-006~008）：口令永不明文上线；双向认证回执校验
        // （T4 伪造服务器）；带口令客户端遇未认证服务器 fail-closed 拒绝。
        let auth_fields = crate::auth::LoginFields {
            version: PROTOCOL_VERSION.to_string(),
            hostname: cfg.hostname.clone(),
            device_id: None,
            ed25519_pub: None,
        };
        // clone 进 async 块（future 不得借用 send 参数）；引用为 Copy，
        // 外层闭包借引用保持 Fn 语义。
        let auth_send = |msg: &ControlMsg| {
            let msg = msg.clone();
            let tx_ref = &tx;
            let send_ref = &send;
            async move { send_ref(tx_ref, &msg) }
        };
        let outcome = crate::auth::authenticate(
            &mut reader,
            auth_send,
            &cfg.token,
            cfg.connect_timeout,
            &auth_fields,
            None, // device_id=None：无注册挑战臂（C-1）
        )
        .await
        .map_err(map_auth_error)?;
        match outcome {
            crate::auth::AuthOutcome::Challenged => {
                debug!("tunnel login authenticated (challenge-response, TNL-SEC-006)");
            }
            crate::auth::AuthOutcome::Legacy => {
                debug!("tunnel login accepted (legacy unauthenticated server, no token)");
            }
        }
        // 4. 逐条注册代理（TNL-CLIENT-002，重试 ≤3 次，仍失败继续其余）。
        let mut assigned: HashMap<String, u16> = HashMap::new();
        for p in &cfg.proxies {
            let mut ok = false;
            for attempt in 1..=3u32 {
                send(&tx, &ControlMsg::NewProxy {
                    name: p.name.clone(),
                    local_addr: p.local_addr.clone(),
                    local_port: p.local_port,
                    remote_port: p.remote_port,
                })?;
                match tokio::time::timeout(cfg.connect_timeout, read_frame(&mut reader)).await {
                    Ok(Ok((ty, payload))) => {
                        if let ControlMsg::ProxyResp {
                            ok: resp_ok,
                            name,
                            err,
                            assigned_port,
                        } = decode_control(ty, &payload)?
                        {
                            if resp_ok {
                                assigned.insert(name.clone(), assigned_port.unwrap_or(p.remote_port));
                                info!(
                                    "tunnel proxy '{}' registered on :{}",
                                    name,
                                    assigned_port.unwrap_or(p.remote_port)
                                );
                                ok = true;
                                break;
                            } else {
                                warn!(
                                    "tunnel proxy '{}' registration failed (attempt {}): {}",
                                    name,
                                    attempt,
                                    err.unwrap_or_default()
                                );
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        return Err(TunnelClientError::Protocol(e));
                    }
                    Err(_) => {
                        warn!(
                            "tunnel proxy '{}' registration timeout (attempt {})",
                            p.name, attempt
                        );
                    }
                }
            }
            if !ok {
                warn!("tunnel proxy '{}' not registered after 3 attempts", p.name);
            }
        }
        // 5. 控制循环（心跳 + 消息处理）。
        {
            let mut session = self.state.session.lock().unwrap();
            *session = Some(SessionState {
                connected: true,
                proxies: assigned.clone(),
                last_pong: Instant::now(),
            });
        }
        info!("tunnel session established with {}", cfg.server_addr);
        let result = self
            .control_loop(&mut reader, &tx, send)
            .await;
        // 6. 会话结束：状态复位 + work 清理。
        self.close_all_work();
        self.state.session.lock().unwrap().take();
        let _ = writer_task.abort();
        result
    }

    /// 控制循环：读帧 / 心跳 / stop 三路 select。
    async fn control_loop<S>(
        &self,
        reader: &mut S,
        tx: &mpsc::UnboundedSender<Vec<u8>>,
        send: impl Fn(&mpsc::UnboundedSender<Vec<u8>>, &ControlMsg) -> Result<(), TunnelClientError>,
    ) -> Result<(), TunnelClientError>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let cfg = &self.cfg;
        let mut heartbeat = tokio::time::interval(cfg.heartbeat_interval);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // 心跳超时须 > 心跳间隔（配置校验在 CLI 层提示；这里兜底收敛）。
        let timeout = cfg.heartbeat_timeout.max(cfg.heartbeat_interval + Duration::from_millis(1));
        loop {
            tokio::select! {
                _ = self.state.stop_notify.notified() => {
                    if self.state.stop.load(Ordering::SeqCst) {
                        // 优雅退出：发 Logout 后关闭（TNL-CLIENT-007）。
                        let _ = send(tx, &ControlMsg::Logout);
                        return Err(TunnelClientError::Shutdown);
                    }
                }
                frame = read_frame(reader) => {
                    let (ty, payload) = match frame {
                        Ok(x) => x,
                        Err(_) => {
                            // 控制连接 EOF / 坏帧 → 判死重连（TNL-CLIENT-006）。
                            return Err(TunnelClientError::Protocol(
                                crate::protocol::ProtocolError::Bincode(
                                    "control connection closed".to_string(),
                                ),
                            ));
                        }
                    };
                    match decode_control(ty, &payload) {
                        Ok(msg) => match msg {
                            ControlMsg::Pong { .. } => {
                                if let Some(s) = self.state.session.lock().unwrap().as_mut() {
                                    s.last_pong = Instant::now();
                                }
                            }
                            ControlMsg::StartWorkConn { proxy_name, conn_id } => {
                                self.spawn_work(proxy_name, conn_id);
                            }
                            ControlMsg::ProxyResp { ok, name, assigned_port, .. } => {
                                if let Some(s) = self.state.session.lock().unwrap().as_mut() {
                                    if ok {
                                        s.proxies.insert(name.clone(), assigned_port.unwrap_or(0));
                                    }
                                }
                            }
                            _ => {} // LoginResp 等其余消息在控制循环中无处理
                        },
                        Err(e) => return Err(TunnelClientError::Protocol(e)),
                    }
                }
                _ = heartbeat.tick() => {
                    let stale = self.state.session.lock().unwrap().as_ref()
                        .map(|s| s.last_pong.elapsed() > timeout)
                        .unwrap_or(false);
                    if stale {
                        // 静默链路判死（TNL-CLIENT-006 / TNL-STAB-002）。
                        warn!(
                            "tunnel heartbeat timeout (no Pong for {:?})",
                            timeout
                        );
                        return Err(TunnelClientError::Timeout("heartbeat".to_string()));
                    }
                    // 发 Ping（TNL-CLIENT-005）。
                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    let _ = send(tx, &ControlMsg::Ping { ts });
                }
            }
        }
    }

    /// StartWorkConn 处理（TNL-CLIENT-003/004）：查代理表 → 拨本地（2s）→
    /// 回连服务器发 `WorkConnHeader` → 双向泵流；本地失败不阻塞控制循环。
    fn spawn_work(&self, proxy_name: String, conn_id: u64) {
        let Some(proxy) = self.cfg.proxies.iter().find(|p| p.name == proxy_name).cloned()
        else {
            warn!("tunnel StartWorkConn for unknown proxy '{}'", proxy_name);
            return;
        };
        let state = self.state.clone();
        let server_addr = self.cfg.server_addr.clone();
        let local_dial_timeout = self.cfg.local_dial_timeout;
        let connect_timeout = self.cfg.connect_timeout;
        let task = tokio::spawn(async move {
            // 1. 拨本地服务（2s 超时）。
            let mut local = match tokio::time::timeout(
                local_dial_timeout,
                TcpStream::connect(format!("{}:{}", proxy.local_addr, proxy.local_port)),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => {
                    // TNL-CLIENT-004：本地拨号失败，不回连服务器；连续 5 次 WARN。
                    let mut failures = state.local_failures.lock().unwrap();
                    let n = failures.entry(proxy.name.clone()).or_insert(0);
                    *n += 1;
                    if *n % 5 == 0 {
                        warn!(
                            "tunnel local dial failed {}x for proxy '{}' ({}:{}): not dialing back",
                            n, proxy.name, proxy.local_addr, proxy.local_port
                        );
                    }
                    return;
                }
            };
            // 2. 回连服务器（同一控制端口）并发 WorkConnHeader（TNL-CLIENT-003）。
            let server = match tokio::time::timeout(
                connect_timeout,
                TcpStream::connect(&server_addr),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => {
                    warn!(
                        "tunnel work conn to server failed for proxy '{}'",
                        proxy.name
                    );
                    return;
                }
            };
            let mut server = server;
            let header = WorkConnHeader {
                proxy_name: proxy.name.clone(),
                conn_id,
            };
            if let Err(e) = write_frame_simple(&mut server, &header).await {
                debug!("tunnel work header send failed: {}", e);
                return;
            }
            // 3. 双向泵流（任一端 EOF → 对称关闭）。
            debug!(
                "tunnel work pump started: proxy='{}' conn_id={}",
                proxy.name, conn_id
            );
            let _ = tokio::io::copy_bidirectional(&mut server, &mut local).await;
            state.local_failures.lock().unwrap().remove(&proxy.name);
            debug!(
                "tunnel work pump ended: proxy='{}' conn_id={}",
                proxy.name, conn_id
            );
        });
        let mut tasks = self.state.work_tasks.lock().unwrap();
        tasks.retain(|t| !t.is_finished());
        tasks.push(task.abort_handle());
    }
}

/// work 首帧写入（独立小函数避免 borrow 冲突）。
async fn write_frame_simple(
    stream: &mut TcpStream,
    header: &WorkConnHeader,
) -> Result<(), crate::protocol::ProtocolError> {
    let frame = encode_work_header(header)?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

/// 认证错误 → 客户端错误映射（语义保持：登录被拒 → LoginRejected；
/// 双向认证/ fail-closed → ServerAuthFailed；其余 → 协议错误）。
fn map_auth_error(e: crate::auth::ClientAuthError) -> TunnelClientError {
    use crate::auth::ClientAuthError;
    match e {
        ClientAuthError::LoginRejected(reason) => TunnelClientError::LoginRejected(reason),
        ClientAuthError::Timeout(t) => TunnelClientError::Timeout(t),
        ClientAuthError::NoTokenForChallenge => TunnelClientError::ServerAuthFailed(
            "server requires challenge-response auth, but no token is configured locally (TNL-SEC-008)"
                .to_string(),
        ),
        ClientAuthError::LegacyServerRejected => TunnelClientError::ServerAuthFailed(
            "server did not issue an auth challenge (unauthenticated server); refusing to continue with token configured (TNL-SEC-008)"
                .to_string(),
        ),
        ClientAuthError::ServerReceiptMismatch => TunnelClientError::ServerAuthFailed(
            "server auth receipt verification failed (T4)".to_string(),
        ),
        ClientAuthError::ServerReceiptMissing => TunnelClientError::ServerAuthFailed(
            "server login response lacks auth receipt (T4)".to_string(),
        ),
        other => TunnelClientError::Protocol(crate::protocol::ProtocolError::Bincode(
            other.to_string(),
        )),
    }
}

/// 指数退避 + 抖动（TNL-STAB-003）：`base × 2^(attempt-1)` 封顶 `max`，
/// 附加 0~1s 随机抖动。attempt 从 1 起。
pub fn backoff_delay(attempt: u32, cfg: &TunnelClientConfig) -> Duration {
    let exp = cfg.backoff_base.saturating_mul(1u32 << attempt.saturating_sub(1).min(20));
    let base = exp.min(cfg.backoff_max);
    // 抖动源：uuid 随机字节（避免额外 rand 依赖）。
    let jitter_ms = (uuid::Uuid::new_v4().as_u128() % (JITTER_MAX_MS as u128 + 1)) as u64;
    base + Duration::from_millis(jitter_ms)
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

///
/// **静默（无应答帧）**，客户端「超时内无 `DirError` = 成功」。relay 侧写帧
/// 在会话循环内**同步**处理（`handle_frame` await 后才回到读循环），`DirError`
/// 有则立发——本窗口只容忍网络 RTT + relay 侧处理延迟，宁短勿长（避免把
/// relay 已崩溃的半程态误判成功；UI 层另经 `DirList` 回显复核，双保险）。
pub const DIR_ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// 面 **1.3.0** 的 0x8B~0x8F 帧面实现，**零自创 wire**）。
///
/// 语义锚（v2 §2.2）：`Upsert`/`Delete` 的条目 = **当前远控服务端**的
/// (device_id, domain, target_domain)——「被 `target_domain` 中继允许发现
/// 当前远控服务端」（source=manual）。**服务端执法**：device_id 必须 ==
/// 会话登录身份（不符 = `auth_failed` 判死口径）；`domain`/`target_domain`
/// 双纯 FQDN；单 IP 注册配额（超限 = `quota_exceeded`，不清存量）。
///
/// 枚举复用、payload 随 §2.2）；**会话化调用面**（经 home 中继既有已认证
/// 设备身份会话发帧 + 登录对账 T7）= [`crate::id_client::IdClient::dir`]
#[derive(Debug, Clone, PartialEq)]
pub enum DirRequest {
    /// 增 + 改同帧（upsert，source=manual）。成功 = 静默；失败 = `DirError`。
    /// `domain` = 设备自身 DNS 域（纯 FQDN）；`target_domain` = 被允许发现
    /// 本机的中继域（纯 FQDN，v2 新增）；`ix_token` = 目标中继互联 token
    Upsert {
        device_id: String,
        domain: String,
        target_domain: String,
        ix_token: String,
    },
    /// 删本中继自持行 (device_id, target_domain)（source∈manual/registered）。
    /// 目标仅以 pushed 形态存在 = `DirError{not_found}`（**不跨源删**——
    /// pushed 行由推送方批次删除）；成功 = 静默。
    Delete { device_id: String, target_domain: String },
    /// 直透 wire；生产回读 = `DirList{scope:Local, filter_device:self}`——
    /// T1/T2 添加/删除回读校验 + T7 登录对账）。`refresh` 恒 `false`（运维
    /// 重推触发面 UI 不消费，设计 §3 T3）。空表 = 空数组（非错）。
    List {
        scope: DirScope,
        filter_device: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum DirResponse {
    /// 写操作成功（静默：超时内无应答帧 / 无 `DirError`）。
    Ack,
    /// `DirList` 回显。
    List { entries: Vec<DirEntry>, epoch: u64 },
}

/// 错误帧，`code` = 冻结字符串对应的六码枚举，客户端 i18n 按 code 映射人话）。
#[derive(Debug, thiserror::Error)]
pub enum DirRequestError {
    #[error("connect to {server} failed: {source}")]
    Connect { server: String, source: std::io::Error },
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("login rejected: {0}")]
    LoginRejected(String),
    #[error("server authentication failed: {0}")]
    ServerAuthFailed(String),
    #[error("protocol error: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// 统一显式错误帧（R→C `DirError`；msg 零凭据——只含 device_id/domain/
    /// 错误语义，展示前仍按 code 映射 i18n 人话，msg 只进日志不进文案）。
    #[error("directory error: {code:?}")]
    DirError { code: DirErrorCode, msg: String },
    /// 协议违规（非预期应答帧 / 解码失败 / 未知码值）——判失败不猜
    /// （fail-closed，对齐「未知值 = 协议违规，调用方判死」冻结口径）。
    #[error("protocol violation: {0}")]
    ProtocolViolation(String),
    /// 建立 / 退避重连中 / 已停止）——fail-closed 显式（UI 映射人话「远控
    /// 服务端未在线」，不伪称拨号失败）。
    #[error("no active tunnel session: {0}")]
    NoSession(String),
}

/// 删除双写 + T7 登录对账）改走 **home 中继既有已认证设备身份会话**
/// （[`crate::id_client::IdClient::dir`]；服务端 v2 身份执法 = 会话登录
/// 身份〔Login 携带 device_id〕，一次通会话 device_id=None 的写帧 =
/// **仅测试专用**（钉帧面 / 静默成功 / 超时口径的 wire 级探针），生产
/// 代码零调用（交付报告 grep 门禁）。
///
/// 按帧语义等应答 → 关闭）。
///
/// - `Upsert`/`Delete`：[`DIR_ACK_TIMEOUT`] 内无 `DirError` = `Ok(Ack)`
///   （静默成功，冻结合同口径）；`DirError` = `Err(DirRequestError::DirError)`；
/// - `List`：`connect_timeout` 内等 `DirListResp`；超时 = `Err(Timeout)`
///   （relay 离线/未挂目录后端——UI 映射显式错误，不静默）；
/// - 认证走与 [`TunnelClient`] 完全相同的挑战-应答口径（TNL-SEC-006~008，
///   口令永不明文上线；带口令客户端遇未认证服务器 fail-closed 拒绝）。
pub async fn dir_request(
    server_addr: &str,
    token: &str,
    hostname: &str,
    connect_timeout: Duration,
    req: &DirRequest,
) -> Result<DirResponse, DirRequestError> {
    // 1. 拨号（同 TunnelClient 口径，带超时）。拨号超时 = 不可达（`Connect`
    // 语义，`source` 统一 TimedOut——UI 映射人话「离线或地址有误」；
    // `Timeout` 变体保留给**应答等待**超时 = 目录写入未确认）。
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(server_addr))
        .await
        .map_err(|_| DirRequestError::Connect {
            server: server_addr.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect {server_addr} timed out"),
            ),
        })?
        .map_err(|e| DirRequestError::Connect {
            server: server_addr.to_string(),
            source: e,
        })?;
    let (mut reader, mut writer) = stream.into_split();
    // 2. writer 任务（串行写帧；drop/abort = 关闭控制连接）。
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if writer.write_all(&frame).await.is_err() {
                break;
            }
        }
    });
    // 3. Login 挑战-应答认证（同 TunnelClient；零代理注册的一次通会话）。
    let auth_send = |msg: &ControlMsg| {
        let msg = msg.clone();
        let tx_ref = &tx;
        async move {
            let frame = encode_control(&msg)?;
            tx_ref
                .send(frame)
                .map_err(|_| DirRequestError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "control channel closed".to_string(),
                )))
        }
    };
    crate::auth::authenticate(
        &mut reader,
        auth_send,
        token,
        connect_timeout,
        &crate::auth::LoginFields {
            version: PROTOCOL_VERSION.to_string(),
            hostname: hostname.to_string(),
            device_id: None,
            ed25519_pub: None,
        },
        None, // device_id=None：无注册挑战臂（C-1）
    )
    .await
    .map_err(map_dir_auth_error)?;
    let frame: Vec<u8> = match req {
        DirRequest::Upsert {
            device_id,
            domain,
            target_domain,
            ix_token,
        } => encode_extension(
            TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: device_id.clone(),
                domain: domain.clone(),
                target_domain: target_domain.clone(),
                note: None,
                // 客户端表单/本地节点上交面（空值合法性归 UI 必填门执法）。
                ix_token: ix_token.clone(),
            },
        )?,
        DirRequest::Delete {
            device_id,
            target_domain,
        } => encode_extension(
            TYPE_DIR_DELETE,
            &DirDelete {
                device_id: device_id.clone(),
                target_domain: target_domain.clone(),
            },
        )?,
        DirRequest::List {
            scope,
            filter_device,
        } => encode_extension(
            TYPE_DIR_LIST,
            &DirList {
                scope: scope.clone(),
                refresh: false,
                filter_device: filter_device.clone(),
            },
        )?,
    };
    tx.send(frame).map_err(|_| DirRequestError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "control channel closed".to_string(),
    )))?;
    // 5. 等应答（冻结合同：写操作 = 静默/DirError；DirList = DirListResp）。
    let read_timeout = match req {
        DirRequest::Upsert { .. } | DirRequest::Delete { .. } => DIR_ACK_TIMEOUT,
        DirRequest::List { .. } => connect_timeout.max(DIR_ACK_TIMEOUT),
    };
    let is_write = matches!(req, DirRequest::Upsert { .. } | DirRequest::Delete { .. });
    let outcome = tokio::time::timeout(read_timeout, read_frame(&mut reader)).await;
    let result = match outcome {
        Err(_) => {
            if is_write {
                // 超时内无 DirError = 静默成功（冻结合同口径）。
                Ok(DirResponse::Ack)
            } else {
                Err(DirRequestError::Timeout("dir list".to_string()))
            }
        }
        Ok(Ok((ty, payload))) => match ty {
            TYPE_DIR_ERROR => {
                let e: DirError =
                    decode_extension(ty, &payload, ty)
                        .map_err(|_| DirRequestError::ProtocolViolation(
                            "DirError frame failed to decode (protocol violation)".to_string(),
                        ))?;
                Err(DirRequestError::DirError {
                    code: e.code,
                    msg: e.msg,
                })
            }
            TYPE_DIR_LIST_RESP => {
                if is_write {
                    // 写操作收到 ListResp = 非预期帧（不应发生）——按协议
                    // 违规判失败，不猜语义（fail-closed）。
                    Err(DirRequestError::ProtocolViolation(
                        "unexpected DirListResp to write frame".to_string(),
                    ))
                } else {
                    let r: DirListResp = decode_extension(ty, &payload, ty)?;
                    Ok(DirResponse::List {
                        entries: r.entries,
                        epoch: r.epoch,
                    })
                }
            }
            _ => {
                // 其余帧（本会话不发心跳/不注册代理，不应到达）：写操作忽略
                // （不破坏静默口径）；List = 协议违规判死。
                if is_write {
                    Ok(DirResponse::Ack)
                } else {
                    Err(DirRequestError::ProtocolViolation(format!(
                        "unexpected frame 0x{ty:02x} for DirList"
                    )))
                }
            }
        },
        Ok(Err(e)) => Err(DirRequestError::Protocol(e)),
    };
    // 6. 会话结束（一次通，无持久态；EOF → 服务端级联清理既有口径）。
    let _ = writer_task.abort();
    result
}

/// 认证错误 → 目录信令错误映射（语义与 [`map_auth_error`] 对齐：登录被拒 →
/// LoginRejected；双向认证/fail-closed → ServerAuthFailed；其余 → 协议错误）。
fn map_dir_auth_error(e: crate::auth::ClientAuthError) -> DirRequestError {
    use crate::auth::ClientAuthError;
    match e {
        ClientAuthError::LoginRejected(reason) => DirRequestError::LoginRejected(reason),
        ClientAuthError::Timeout(t) => DirRequestError::Timeout(t),
        ClientAuthError::NoTokenForChallenge => DirRequestError::ServerAuthFailed(
            "server requires challenge-response auth, but no token is configured locally (TNL-SEC-008)"
                .to_string(),
        ),
        ClientAuthError::LegacyServerRejected => DirRequestError::ServerAuthFailed(
            "server did not issue an auth challenge (unauthenticated server); refusing to continue with token configured (TNL-SEC-008)"
                .to_string(),
        ),
        ClientAuthError::ServerReceiptMismatch => DirRequestError::ServerAuthFailed(
            "server auth receipt verification failed (T4)".to_string(),
        ),
        ClientAuthError::ServerReceiptMissing => DirRequestError::ServerAuthFailed(
            "server login response lacks auth receipt (T4)".to_string(),
        ),
        other => DirRequestError::Protocol(crate::protocol::ProtocolError::Bincode(
            other.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_sequence_and_cap() {
        let cfg = TunnelClientConfig::default();
        // 1s → 2s → 4s → … 封顶 60s；抖动 0~1s。
        // 上界断言按闭区间 `<=`（修复前严格 `<` 在抖动恰命中 1000ms 时
        // 概率性失败，P≈1/1001；生产抖动逻辑零改动）。
        assert!(backoff_delay(1, &cfg) >= Duration::from_secs(1));
        assert!(backoff_delay(1, &cfg) <= Duration::from_secs(2));
        assert!(backoff_delay(2, &cfg) >= Duration::from_secs(2));
        assert!(backoff_delay(2, &cfg) <= Duration::from_secs(3));
        assert!(backoff_delay(6, &cfg) >= Duration::from_secs(32));
        // 封顶：60s + 抖动 ≤ 61s。
        let capped = backoff_delay(30, &cfg);
        assert!(capped >= Duration::from_secs(60));
        assert!(capped <= Duration::from_secs(61));
    }

    #[test]
    fn test_backoff_injected_short_base() {
        let cfg = TunnelClientConfig {
            backoff_base: Duration::from_millis(50),
            backoff_max: Duration::from_millis(400),
            ..Default::default()
        };
        let d1 = backoff_delay(1, &cfg);
        assert!(d1 >= Duration::from_millis(50) && d1 <= Duration::from_millis(1050));
        let d3 = backoff_delay(3, &cfg);
        assert!(d3 >= Duration::from_millis(200) && d3 <= Duration::from_millis(1200));
        let d10 = backoff_delay(10, &cfg);
        assert!(d10 >= Duration::from_millis(400) && d10 <= Duration::from_millis(1400));
    }

    #[test]
    fn test_status_default() {
        let client = TunnelClient::new(TunnelClientConfig::default());
        let status = client.status();
        assert!(!status.connected);
        assert!(status.proxies.is_empty());
        assert_eq!(status.reconnect_count, 0);
    }

    // ════════════════════════════════════════════════════════════
    // 全链 = 拨号 → Login 挑战-应答 → 目录帧 → 应答/静默）。
    // ════════════════════════════════════════════════════════════

    /// mock 目录后端（`DirectoryHandler` v2 契约的最小实现）：写操作按
    /// 配置静默成功或回 `DirError`；`DirList` 回固定条目。身份执法不模拟
    /// （一次通会话 device_id=None——v2 生产写路径 = 会话化调用面，
    #[derive(Debug)]
    struct MockDirHandler {
        upsert_err: Option<DirErrorCode>,
        delete_err: Option<DirErrorCode>,
        list_entries: Vec<DirEntry>,
    }

    impl crate::server::DirectoryHandler for MockDirHandler {
        fn handle_frame<'a>(
            &'a self,
            _client: std::net::SocketAddr,
            _session_device_id: Option<String>,
            ty: u8,
            _payload: &'a [u8],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<crate::server::DirectoryFrameOutcome, ()>,
                    > + Send
                    + 'a,
            >,
        > {
            use crate::server::DirectoryFrameOutcome as O;
            Box::pin(async move {
                match ty {
                    TYPE_DIR_UPSERT => match self.upsert_err {
                        Some(code) => Ok(O::Reply(encode_extension(
                            TYPE_DIR_ERROR,
                            &DirError { code, msg: "mock upsert reject".to_string() },
                        )
                        .expect("encode DirError cannot fail"))),
                        None => Ok(O::Silent), // 静默成功（冻结合同口径）
                    },
                    TYPE_DIR_DELETE => match self.delete_err {
                        Some(code) => Ok(O::Reply(encode_extension(
                            TYPE_DIR_ERROR,
                            &DirError { code, msg: "mock delete reject".to_string() },
                        )
                        .expect("encode DirError cannot fail"))),
                        None => Ok(O::Silent),
                    },
                    TYPE_DIR_LIST => {
                        let resp = DirListResp {
                            entries: self.list_entries.clone(),
                            server_ts: 1,
                            epoch: 7,
                        };
                        Ok(O::Reply(encode_extension(
                            TYPE_DIR_LIST_RESP,
                            &resp,
                        )
                        .expect("encode DirListResp cannot fail")))
                    }
                    _ => Err(()), // 坏帧口径（不应到达）
                }
            })
        }
    }

    /// 测试服务端配置（控制端口 0 = 系统分配；短心跳；端口范围随机化防
    /// 并发 flaky——同 tests.rs 先例；临时服务器密钥不污染 ~/.kirin_desk）。
    fn dir_server_cfg(token: &str, directory: Option<std::sync::Arc<dyn crate::server::DirectoryHandler>>) -> crate::server::TunnelServerConfig {
        let range_base = 42000 + (uuid::Uuid::new_v4().as_u128() % 2000) as u16;
        crate::server::TunnelServerConfig {
            bind_port: 0,
            bind_addrs: Vec::new(), // 默认双栈（[::] 优先 + 0.0.0.0 回退）
            token: token.to_string(),
            port_range: Some((range_base, range_base + 256)),
            // 须 > DIR_ACK_TIMEOUT（写操作静默等待窗口）：一次通会话在
            // 等应答期间不发帧，过短心跳会把静默会话判死关连接（early eof）。
            heartbeat_timeout: Duration::from_secs(10),
            work_conn_timeout: Duration::from_secs(2),
            max_proxies: 32,
            max_concurrent_work: 100,
            rate_limit: crate::rate_limit::RateLimiterConfig::default(),
            tunnel_conn_rate_limit: crate::rate_limit::RateLimiterConfig::tunnel_conn_default(),
            max_pending_tunnels: 256,
            max_pending_per_target: 16,
            audit: None,
            server_key_path: Some(
                std::env::temp_dir().join(format!(
                    "kirin_dir_client_test_key_{}.der",
                    uuid::Uuid::new_v4()
                )),
            ),
            rendezvous: None,
            directory,
            ..Default::default()
        }
    }

    async fn spawn_dir_server(
        cfg: crate::server::TunnelServerConfig,
    ) -> (String, crate::server::TunnelServerHandle) {
        let server = crate::server::TunnelServer::bind(cfg)
            .await
            .expect("bind test relay server");
        let handle = server.shutdown_handle();
        let port = server.port();
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        (format!("[::1]:{port}"), handle)
    }

    #[tokio::test]
    async fn test_r137_13_dir_upsert_silent_ack() {
        let handler = std::sync::Arc::new(MockDirHandler {
            upsert_err: None,
            delete_err: None,
            list_entries: Vec::new(),
        });
        let (addr, handle) =
            spawn_dir_server(dir_server_cfg("secret", Some(handler))).await;
        let res = dir_request(
            &addr,
            "secret",
            "dir-test",
            Duration::from_secs(2),
            &DirRequest::Upsert {
                device_id: "my-pc".to_string(),
                domain: "dev.example.com".to_string(),
                target_domain: "b.test.relay".to_string(),
                ix_token: String::new(),
            },
        )
        .await;
        match res {
            Ok(DirResponse::Ack) => {}
            other => panic!("expected silent Ack, got {other:?}"),
        }
        handle.shutdown();
    }

    #[tokio::test]
    async fn test_r137_13_dir_upsert_dir_error_propagated() {
        let handler = std::sync::Arc::new(MockDirHandler {
            upsert_err: Some(DirErrorCode::Busy),
            delete_err: None,
            list_entries: Vec::new(),
        });
        let (addr, handle) =
            spawn_dir_server(dir_server_cfg("secret", Some(handler))).await;
        let res = dir_request(
            &addr,
            "secret",
            "dir-test",
            Duration::from_secs(2),
            &DirRequest::Upsert {
                device_id: "my-pc".to_string(),
                domain: "dev.example.com".to_string(),
                target_domain: "b.test.relay".to_string(),
                ix_token: String::new(),
            },
        )
        .await;
        match res {
            Err(DirRequestError::DirError { code, msg }) => {
                assert_eq!(code, DirErrorCode::Busy);
                assert_eq!(msg, "mock upsert reject");
            }
            other => panic!("expected DirError Busy, got {other:?}"),
        }
        handle.shutdown();
    }

    #[tokio::test]
    async fn test_r137_13_dir_delete_not_found() {
        let handler = std::sync::Arc::new(MockDirHandler {
            upsert_err: None,
            delete_err: Some(DirErrorCode::NotFound),
            list_entries: Vec::new(),
        });
        let (addr, handle) =
            spawn_dir_server(dir_server_cfg("secret", Some(handler))).await;
        let res = dir_request(
            &addr,
            "secret",
            "dir-test",
            Duration::from_secs(2),
            &DirRequest::Delete {
                device_id: "my-pc".to_string(),
                target_domain: "b.test.relay".to_string(),
            },
        )
        .await;
        match res {
            Err(DirRequestError::DirError { code, .. }) => {
                assert_eq!(code, DirErrorCode::NotFound);
            }
            other => panic!("expected DirError NotFound, got {other:?}"),
        }
        handle.shutdown();
    }

    #[tokio::test]
    async fn test_r137_13_dir_list_entries() {
        let handler = std::sync::Arc::new(MockDirHandler {
            upsert_err: None,
            delete_err: None,
            list_entries: vec![DirEntry {
                device_id: "my-pc".to_string(),
                device_domain: "dev.example.com".to_string(),
                target_domain: "b.test.relay".to_string(),
                source: "manual".to_string(),
                source_fp: String::new(),
                updated_at: 123,
                sig_verified: true,
            }],
        });
        let (addr, handle) =
            spawn_dir_server(dir_server_cfg("secret", Some(handler))).await;
        let res = dir_request(
            &addr,
            "secret",
            "dir-test",
            Duration::from_secs(2),
            &DirRequest::List {
                scope: DirScope::All,
                filter_device: None,
            },
        )
        .await;
        match res {
            Ok(DirResponse::List { entries, epoch }) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].device_id, "my-pc");
                assert_eq!(entries[0].source, "manual");
                assert_eq!(epoch, 7);
            }
            other => panic!("expected List response, got {other:?}"),
        }
        handle.shutdown();
    }

    #[tokio::test]
    async fn test_r137_13_dir_no_backend_upsert_ack_list_timeout() {
        // 未挂目录后端（directory: None）：目录帧 = 结构校验 + 审计丢弃
        // （不静默忽略，但对客户端表现为「无应答」）——Upsert 超时窗口内
        // 无 DirError = Ack（静默口径），List 无 DirListResp = Timeout。
        // UI 层以 DirList 回显复核兜住该歧义（未确认 = 显式错误不落本地）。
        let (addr, handle) = spawn_dir_server(dir_server_cfg("secret", None)).await;
        let upsert = dir_request(
            &addr,
            "secret",
            "dir-test",
            Duration::from_secs(2),
            &DirRequest::Upsert {
                device_id: "my-pc".to_string(),
                domain: "dev.example.com".to_string(),
                target_domain: "b.test.relay".to_string(),
                ix_token: String::new(),
            },
        )
        .await;
        assert!(
            matches!(upsert, Ok(DirResponse::Ack)),
            "no-backend upsert should be silent Ack, got {upsert:?}"
        );
        let list = dir_request(
            &addr,
            "secret",
            "dir-test",
            Duration::from_secs(2),
            &DirRequest::List {
                scope: DirScope::All,
                filter_device: None,
            },
        )
        .await;
        assert!(
            matches!(list, Err(DirRequestError::Timeout(_))),
            "no-backend list should time out, got {list:?}"
        );
        handle.shutdown();
    }

    #[tokio::test]
    async fn test_r137_13_dir_wrong_token_rejected() {
        let (addr, handle) =
            spawn_dir_server(dir_server_cfg("secret", None)).await;
        let res = dir_request(
            &addr,
            "wrong-token",
            "dir-test",
            Duration::from_secs(2),
            &DirRequest::List {
                scope: DirScope::All,
                filter_device: None,
            },
        )
        .await;
        assert!(
            matches!(res, Err(DirRequestError::LoginRejected(_))),
            "wrong token should be LoginRejected, got {res:?}"
        );
        handle.shutdown();
    }

    /// Local, filter_device:Some(self)}` 经 wire 到达服务端 = v2 三字段形态
    /// （scope 变体索引零变 + `refresh=false` 恒 + `filter_device` 尾部透传）；
    /// T1/T2 回读校验与 T7 登录对账的定向过滤面 = 本形态。
    #[tokio::test]
    async fn test_r140_4_dir_list_local_filter_wire_shape() {
        #[derive(Debug, Default)]
        struct CaptureList {
            seen: std::sync::Mutex<Option<DirList>>,
        }
        impl crate::server::DirectoryHandler for CaptureList {
            fn handle_frame<'a>(
                &'a self,
                _client: std::net::SocketAddr,
                _session_device_id: Option<String>,
                ty: u8,
                payload: &'a [u8],
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<crate::server::DirectoryFrameOutcome, ()>,
                        > + Send
                        + 'a,
                >,
            > {
                use crate::server::DirectoryFrameOutcome as O;
                // 同步解码捕获（形态校验 + 记录；解码败 = 坏帧口径 Err）。
                let decoded = (ty == TYPE_DIR_LIST)
                    .then(|| decode_extension::<DirList>(ty, payload, ty).ok())
                    .flatten();
                if let Some(d) = &decoded {
                    *self.seen.lock().unwrap() = Some(d.clone());
                }
                Box::pin(async move {
                    if ty == TYPE_DIR_LIST {
                        let resp = DirListResp {
                            entries: Vec::new(),
                            server_ts: 1,
                            epoch: 1,
                        };
                        Ok(O::Reply(encode_extension(
                            TYPE_DIR_LIST_RESP,
                            &resp,
                        )
                        .expect("encode DirListResp cannot fail")))
                    } else {
                        Err(())
                    }
                })
            }
        }
        let handler = std::sync::Arc::new(CaptureList::default());
        let (addr, handle) =
            spawn_dir_server(dir_server_cfg("secret", Some(handler.clone()))).await;
        let res = dir_request(
            &addr,
            "secret",
            "dir-test",
            Duration::from_secs(2),
            &DirRequest::List {
                scope: DirScope::Local,
                filter_device: Some("my-pc".to_string()),
            },
        )
        .await;
        assert!(
            matches!(res, Ok(DirResponse::List { .. })),
            "List(Local, filter) should get DirListResp, got {res:?}"
        );
        let seen = handler
            .seen
            .lock()
            .unwrap()
            .clone()
            .expect("服务端应收到 DirList 帧");
        assert_eq!(seen.scope, DirScope::Local, "scope wire 形态 = Local（变体索引钉死）");
        assert!(!seen.refresh, "refresh 恒 false（运维重推面 UI 不消费）");
        assert_eq!(
            seen.filter_device.as_deref(),
            Some("my-pc"),
            "filter_device 尾部透传（T7 回读定向过滤面）"
        );
        handle.shutdown();
    }
}
