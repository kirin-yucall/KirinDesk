//! M8-T026 T003: 隧道客户端（frpc 等价）— Login + 代理注册 / 控制循环 /
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
    decode_control, encode_control, encode_work_header, read_frame, ControlMsg,
    WorkConnHeader, PROTOCOL_VERSION,
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
    /// M8-T026-P3：服务器认证失败（双向认证回执校验失败 / fail-closed
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
        // 3. Login（TNL-CLIENT-001 / TNL-PROTO-002）— M8-T026-P3 挑战-响应
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

/// 认证错误 → 客户端错误映射（M8-T026-P3 语义保持：登录被拒 → LoginRejected；
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_sequence_and_cap() {
        let cfg = TunnelClientConfig::default();
        // 1s → 2s → 4s → … 封顶 60s；抖动 0~1s。
        assert!(backoff_delay(1, &cfg) >= Duration::from_secs(1));
        assert!(backoff_delay(1, &cfg) < Duration::from_secs(2));
        assert!(backoff_delay(2, &cfg) >= Duration::from_secs(2));
        assert!(backoff_delay(2, &cfg) < Duration::from_secs(3));
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
        assert!(d1 >= Duration::from_millis(50) && d1 < Duration::from_millis(1050));
        let d3 = backoff_delay(3, &cfg);
        assert!(d3 >= Duration::from_millis(200) && d3 < Duration::from_millis(1200));
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
}
