//! 设备侧 ID 注册客户端 + 控制器解析/中继辅助（ID-001/003/005/010/011③）。
//!
//! 与并行开发的 `client.rs`（T003 端口代理 frpc）**职责分离**：本模块只做
//! 设备 ID 模式 —— `Login` 携带 `device_id` 注册在线表 + 心跳保活（与 
//! 控制连接心跳**合并**，ID-NF-003 不新增包）+ `CandidateRegister` 候选刷新
//! （ID-005）+ `TunnelRequest` 接收（§8.1 设备级中继兜底）。
//!
//! 控制器侧辅助：
//! - [`resolve_device_verified`]：一次性解析（ID-010）+ 服务器签名验签（ID-SEC-001）；
//! - [`open_tunnel`]：中继数据连接（ID-011③）。

use crate::protocol::{
    decode_control, decode_extension, encode_control, encode_extension, read_frame, Candidate,
    CandidateKind, ControlMsg, DeviceInfo, DirDelete, DirError, DirList, DirListResp, DirUpsert,
    TunnelConn, TunnelHeader, TunnelRequest, TunnelResp, PROTOCOL_VERSION, TYPE_CONTROL,
    TYPE_DEVICE_INFO, TYPE_DIR_DELETE, TYPE_DIR_ERROR, TYPE_DIR_LIST, TYPE_DIR_LIST_RESP,
    TYPE_DIR_UPSERT, TYPE_TUNNEL_CONN, TYPE_TUNNEL_HEADER, TYPE_TUNNEL_RESP,
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
// 统一见 `crate::lan_candidates` 模块注释。

/// ID 客户端配置。
///
/// [`IdClient::with_reg_signer`]）——本结构体是 mobile/桌面两侧共用的
/// 全字段字面量构造面，尾部追加字段会破坏跨 crate 字面量构造（无
/// `..Default::default()` 兜底）；签名器走 builder 追加，构造面零断代。
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
    /// 候选注册携带真实端口（不再写 0），供控制端直连/打洞寻址（registry
    /// 记录设备候选含真实端口）；`[tunnel] extra_candidates` 仍以更高优先级
    /// 附加覆盖。0 = 端口保持 0（旧行为；调用方应传配置/运行时绑定值）。
    pub local_port: u16,
    /// 默认 true，serde default 兼容旧配置）。false 时仅上报
    /// `extra_candidates`（观察地址仍由服务器附加）——供隐私敏感环境
    /// 关闭本机地址上报。
    pub report_lan_candidates: bool,
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
            local_port: 0,
            report_lan_candidates: true,
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
    /// 服务器认证失败（双向认证回执校验失败 / fail-closed
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

/// 在途请求，`dir_gate` 串行）。
enum DirReplyFrame {
    /// R→C 显式错误帧（0x8F）。
    DirError(DirError),
    /// R→C 列表应答帧（0x8C）。
    DirListResp(DirListResp),
}

/// 客户端共享状态。
struct IdClientState {
    stop: AtomicBool,
    stop_notify: Notify,
    session: Mutex<Option<SessionState>>,
    reconnect_count: AtomicU64,
    /// 会话结束清空）。
    frame_tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    pending_dir: Mutex<Option<tokio::sync::oneshot::Sender<DirReplyFrame>>>,
    dir_gate: tokio::sync::Mutex<()>,
    /// 一次——含重连再登录；对账为全量调和，幂等且代价可忽略）。
    login_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
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
    /// [`crate::protocol::registration_proof_payload`] 载荷的 Ed25519 签名闭包，
    /// 生产入口 = 设备身份私钥）。`None` 时服务器下发注册挑战即 fail-closed
    /// 拒绝（[`crate::auth::ClientAuthError::RegistrationProofUnsupported`]）。
    /// 经 [`IdClient::with_reg_signer`] 追加（不在 [`IdClientConfig`] 字面量
    /// 构造面——跨 crate 全字段字面量零断代，mobile 构造点零触碰）。
    reg_signer: Option<std::sync::Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>>,
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
                frame_tx: Mutex::new(None),
                pending_dir: Mutex::new(None),
                dir_gate: tokio::sync::Mutex::new(()),
                login_hook: Mutex::new(None),
            }),
            on_tunnel_stream: Arc::new(on_tunnel_stream),
            reg_signer: None,
        }
    }

    /// 设备登录携带 `device_id` 时，v2.0.0 服务器在 `LoginResp` 前下发
    /// [`crate::protocol::ControlMsg::RegChallenge`]，本端以该签名器对
    /// [`crate::protocol::registration_proof_payload`] 出 Ed25519 签名回
    /// [`crate::protocol::ControlMsg::RegProof`]；生产入口 = 设备身份私钥
    /// （GUI/CLI 注册路径）。建议 `run()` 前调用。
    pub fn with_reg_signer(
        mut self,
        signer: std::sync::Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,
    ) -> Self {
        self.reg_signer = Some(signer);
        self
    }

    /// 「触发点冻结 = 隧道登录成功一次（WorkConn 建立 + Login ack 后）」；
    /// 重连再登录再次触发，对账全量调和幂等自愈，败 = 弱提示下次登录再试）。
    /// 回调在隧道 runtime 上下文内**同步**调用（调用方自行 spawn 异步任务，
    /// 不得阻塞）。建议 `run()` 前注册（随时可调，下次登录成功生效）。
    pub fn on_login_success(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.state.login_hook.lock().unwrap() = Some(Arc::new(hook));
    }

    /// 新建连；复用 Login 身份 = 服务端 v2 身份执法口径〔`device_id` 必须
    /// == 会话登录身份〕；TunnelClient 代理会话 device_id=None 不承载目录
    /// 写路径——auth_failed 过渡态自本岗起生产面清零）。
    ///
    /// 帧语义（冻结合同，与一次通 `crate::client::dir_request` 同口径）：
    /// - `Upsert`/`Delete`：[`crate::client::DIR_ACK_TIMEOUT`] 内无
    ///   `DirError` = `Ok(Ack)`（静默成功）；`DirError` = 显式错误；
    /// - `List`：`connect_timeout.max(DIR_ACK_TIMEOUT)` 内等 `DirListResp`；
    ///   超时 = `Err(Timeout)`（fail-closed，UI 映射显式错误）；
    /// - 无已建立会话（未登录 / 退避重连中 / 已停止）= `Err(NoSession)`
    ///   （显式，UI 映射「远控服务端未在线」人话）。
    ///
    /// wire 无关联 ID ⇒ 单在途（`dir_gate` 串行，并发调用 FIFO 等待；UI
    /// 添加/删除/对账全经此单入口）。
    pub async fn dir(&self, req: &crate::client::DirRequest) -> Result<crate::client::DirResponse, crate::client::DirRequestError> {
        use crate::client::{DirRequest, DirRequestError, DirResponse, DIR_ACK_TIMEOUT};
        let _gate = self.state.dir_gate.lock().await;
        let Some(tx) = self.state.frame_tx.lock().unwrap().clone() else {
            return Err(DirRequestError::NoSession(
                "id tunnel session not established (not logged in / reconnecting / stopped)"
                    .to_string(),
            ));
        };
        // 1. 单槽登记（**先登记后发帧**——应答到达与登记零竞态）。
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        *self.state.pending_dir.lock().unwrap() = Some(rtx);
        // 2. 发帧（冻结面 0x8B~0x8F；v2 载荷与 client.rs 一次通同口径）。
        let frame = match req {
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
                    // 随会话化帧透传上交 home（空值合法性归 UI 必填门执法；
                    // home 缓存 source='device'，推送时自动携带给目标中继）。
                    ix_token: ix_token.clone(),
                },
            ),
            DirRequest::Delete {
                device_id,
                target_domain,
            } => encode_extension(
                TYPE_DIR_DELETE,
                &DirDelete {
                    device_id: device_id.clone(),
                    target_domain: target_domain.clone(),
                },
            ),
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
            ),
        };
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                *self.state.pending_dir.lock().unwrap() = None;
                return Err(DirRequestError::Protocol(e));
            }
        };
        if tx.send(frame).is_err() {
            *self.state.pending_dir.lock().unwrap() = None;
            return Err(DirRequestError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "control channel closed",
            )));
        }
        // 3. 等应答（帧语义：写 = 静默/DirError；List = DirListResp）。
        let is_write = matches!(req, DirRequest::Upsert { .. } | DirRequest::Delete { .. });
        let read_timeout = if is_write {
            DIR_ACK_TIMEOUT
        } else {
            self.cfg.connect_timeout.max(DIR_ACK_TIMEOUT)
        };
        let outcome = tokio::time::timeout(read_timeout, rrx).await;
        *self.state.pending_dir.lock().unwrap() = None;
        match outcome {
            Err(_) => {
                if is_write {
                    // 超时内无 DirError = 静默成功（冻结合同口径；UI 另经
                    // DirList 回读双保险，未确认不落本地）。
                    Ok(DirResponse::Ack)
                } else {
                    Err(DirRequestError::Timeout("dir list".to_string()))
                }
            }
            Ok(Ok(wire)) => match wire {
                DirReplyFrame::DirError(e) => Err(DirRequestError::DirError {
                    code: e.code,
                    msg: e.msg,
                }),
                DirReplyFrame::DirListResp(r) => {
                    if is_write {
                        // 写操作收到 ListResp = 非预期帧——协议违规判失败，
                        // 不猜语义（fail-closed，一次通同口径）。
                        Err(DirRequestError::ProtocolViolation(
                            "unexpected DirListResp to write frame".to_string(),
                        ))
                    } else {
                        Ok(DirResponse::List {
                            entries: r.entries,
                            epoch: r.epoch,
                        })
                    }
                }
            },
            Ok(Err(_)) => {
                // 单槽被丢弃（会话判死、控制循环退出）→ 判失败不猜。
                Err(DirRequestError::ProtocolViolation(
                    "tunnel session lost while waiting for dir reply".to_string(),
                ))
            }
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
        *self.state.frame_tx.lock().unwrap() = Some(tx.clone());
        // 3. Login（ID-001：携带 device_id + ed25519_pub）— 
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
            self.reg_signer.as_deref(),
        )
        .await
        .map_err(map_id_auth_error)?;
        debug!("id client auth outcome: {:?}", outcome);
        // 4. 候选登记（ID-005；本地候选 + 配置 extra）。
        let candidates =
            collect_local_candidates_with(&cfg.extra_candidates, cfg.local_port, cfg.report_lan_candidates)
                .await;
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
        // 记录与本机现役身份一眼对账（控制端 known_hosts / 指纹确认框
        // 所见即此值；漂移=身份重建，立即可辨）。
        let reg_fp = if cfg.ed25519_pub.is_empty() {
            String::new()
        } else {
            kirin_desk_utils::known_hosts::fingerprint(&cfg.ed25519_pub)
        };
        info!(
            "id device registered: '{}' on {} fingerprint={}",
            cfg.device_id, cfg.server_addr, reg_fp
        );
        // 设备注册完成）触发一次；回调非阻塞（调用方 spawn 异步任务），
        // 对账败 = 弱提示、下次登录再试（设计 §3 T7 触发点冻结口径）。
        if let Some(hook) = self.state.login_hook.lock().unwrap().clone() {
            hook();
        }
        let result = self.control_loop(&mut reader, &tx).await;
        self.state.session.lock().unwrap().take();
        *self.state.frame_tx.lock().unwrap() = None;
        // 会话判死：在途 dir 请求单槽随控制循环退出丢弃（等待方收
        // ProtocolViolation——fail-closed 不猜）。
        let _ = self.state.pending_dir.lock().unwrap().take();
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
                        // → 在途 dir 请求单槽路由（会话化 dir 通道；wire 无
                        // 关联 ID = 单在途串行，`dir_gate` 保证）。无在途请求
                        // （请求超时后的迟到应答等）→ 丢弃不断连（防御性；
                        // 正常时序不可达）。
                        TYPE_DIR_LIST_RESP | TYPE_DIR_ERROR => {
                            let wire: Option<DirReplyFrame> =
                                if ty == TYPE_DIR_LIST_RESP {
                                    decode_extension::<DirListResp>(ty, &payload, ty)
                                        .ok()
                                        .map(DirReplyFrame::DirListResp)
                                } else {
                                    decode_extension::<DirError>(ty, &payload, ty)
                                        .ok()
                                        .map(DirReplyFrame::DirError)
                                };
                            match (wire, self.state.pending_dir.lock().unwrap().take()) {
                                (Some(w), Some(tx)) => {
                                    if tx.send(w).is_err() {
                                        debug!("id client: dir waiter gone (session closing)");
                                    }
                                }
                                _ => debug!(
                                    "id client: directory reply 0x{ty:02x} without pending dir request (dropped)"
                                ),
                            }
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
                    // ID-NF-003：心跳与控制连接合并，不新增包。
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

/// ID-005：本地候选收集 —— 非回环接口地址（TCP 候选，端口 = 被控端实际
/// 优先级降序（服务器另行附加观察地址）。
///
/// [`crate::lan_candidates`] 分类筛选接口地址——排除回环/多播/CGNAT
/// 100.64.0.0/10（跨用户不可路由）/链路本地（v4 169.254 APIPA、v6 fe80
/// 需 zone-id 跨机不可用），RFC1918/ULA 给 LAN 档优先级 210（高于
/// observed 200 / extra 150，同网段对端候选最前），公网 v4/全局 v6 维持
/// LOCAL 档 100。`report_lan = false`（`[network] report_lan_candidates`
/// 关闭）则跳过接口枚举，仅上报 `extra_candidates`。
pub async fn collect_local_candidates_with(
    extra: &[Candidate],
    local_port: u16,
    report_lan: bool,
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut seen: Vec<std::net::SocketAddr> = Vec::new();
    let mut push = |c: Candidate, seen: &mut Vec<std::net::SocketAddr>| {
        if !seen.contains(&c.addr) {
            seen.push(c.addr);
            out.push(c);
        }
    };
    // 非回环接口地址（get-if-addrs；Windows/Linux/macOS 通用）。
    if report_lan {
        if let Ok(ifaces) = get_if_addrs::get_if_addrs() {
            for iface in ifaces {
                if iface.is_loopback() {
                    continue;
                }
                let ip = iface.ip();
                let Some(priority) = crate::lan_candidates::candidate_priority(ip) else {
                    debug!(
                        "id client: skip non-reportable iface addr {} ({:?})",
                        ip,
                        crate::lan_candidates::classify_ip(ip)
                    );
                    continue;
                };
                let addr = std::net::SocketAddr::new(ip, local_port);
                push(
                    Candidate {
                        addr,
                        kind: CandidateKind::Tcp,
                        priority,
                    },
                    &mut seen,
                );
            }
        }
    }
    for c in extra {
        push(c.clone(), &mut seen);
    }
    out.sort_by(|a, b| b.priority.cmp(&a.priority));
    out
}

/// [`collect_local_candidates_with`] 的默认形态（`report_lan = true`；
/// 打洞本地候选枚举沿用，见 `core::connection::punch`）。
pub async fn collect_local_candidates(extra: &[Candidate], local_port: u16) -> Vec<Candidate> {
    collect_local_candidates_with(extra, local_port, true).await
}

/// 认证错误 → ID 客户端错误映射（语义保持：登录被拒保留
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
///
/// 唯一命中返回完整 ID 的在线 `DeviceInfo`（`payload.device_id` = 完整 ID，
/// 服务器签名覆盖）；多义/未命中与未知完整 ID 同一防枚举响应
/// （`online:false`），调用方据此引导用户输入完整 ID（fail-closed）。
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
    // Login（ID-001：纯解析不注册，device_id = None）— 
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
        None, // resolve_device：device_id=None，无注册挑战臂
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
        // 闭区间 `<=`（修复前严格 `<` 抖动恰命中 1000ms 时 P≈1/1001 flake；
        // 生产抖动逻辑零改动）。与 client.rs 同款断言一并修正。
        assert!(backoff_delay(1, &cfg) >= Duration::from_secs(1));
        assert!(backoff_delay(1, &cfg) <= Duration::from_secs(2));
        assert!(backoff_delay(6, &cfg) >= Duration::from_secs(32));
        let capped = backoff_delay(30, &cfg);
        assert!(capped >= Duration::from_secs(60));
        assert!(capped <= Duration::from_secs(61));
    }

    #[tokio::test]
    async fn test_collect_local_candidates() {
        let cands = collect_local_candidates(&[], 0).await;
        // 本地接口候选非空（CI/本机至少 loopback 被排除后仍可能有接口）。
        assert!(!cands.iter().any(|c| c.addr.ip().is_loopback()));
        // 配置 extra 附加 + 去重。
        let extra = vec![Candidate {
            addr: "203.0.113.1:3389".parse().unwrap(),
            kind: CandidateKind::Tcp,
            priority: 150,
        }];
        let cands2 = collect_local_candidates(&extra, 0).await;
        assert!(cands2.iter().any(|c| c.addr == "203.0.113.1:3389".parse().unwrap()));
        // 优先级降序。
        assert!(cands2.windows(2).all(|w| w[0].priority >= w[1].priority));
    }

    /// 被控端实际监听端口（不再写 0）；`[tunnel] extra_candidates` 语义保持
    /// （更高优先级附加，地址不重复仍并入；重复地址去重）。
    #[tokio::test]
    async fn test_collect_local_candidates_injects_local_port() {
        let port: u16 = kirin_desk_utils::config::DEFAULT_NETWORK_PORT;
        let cands = collect_local_candidates(&[], port).await;
        let iface_cands: Vec<&Candidate> = cands.iter().collect();
        // 全部接口候选端口 = 注入端口（非回环接口候选即候选集中优先级 100 者；
        // 本用例无 extra，全部候选即接口候选）。
        assert!(!cands.is_empty(), "本地接口候选不应为空");
        for c in &cands {
            assert_eq!(c.addr.port(), port, "接口候选端口应为被控端监听端口");
        }
        // extra_candidates 覆盖语义保持：不同地址的 extra 附加（优先级更高排前）。
        let extra = vec![Candidate {
            addr: format!("203.0.113.9:{port}").parse().unwrap(),
            kind: CandidateKind::Tcp,
            priority: 150,
        }];
        let cands2 = collect_local_candidates(&extra, port).await;
        assert!(
            cands2
                .iter()
                .any(|c| c.addr == format!("203.0.113.9:{port}").parse().unwrap())
        );
        // 排 extra 之前，extra（150）仍排在全部 LOCAL 档（100）之前。
        let extra_addr: std::net::SocketAddr = format!("203.0.113.9:{port}").parse().unwrap();
        let pos_extra = cands2
            .iter()
            .position(|c| c.addr == extra_addr)
            .expect("extra 候选应在列表中");
        assert!(cands2[..pos_extra].iter().all(|c| c.priority > 150));
        assert!(cands2[pos_extra..].iter().all(|c| c.priority <= 150));
        // 与 extra 相同 ip:port 的接口候选去重（extra 已含该地址则不重复并入）。
        let ip_of_first = cands[0].addr.ip();
        let dup_extra = vec![Candidate {
            addr: std::net::SocketAddr::new(ip_of_first, port),
            kind: CandidateKind::Tcp,
            priority: 150,
        }];
        let cands3 = collect_local_candidates(&dup_extra, port).await;
        let count = cands3
            .iter()
            .filter(|c| c.addr == std::net::SocketAddr::new(ip_of_first, port))
            .count();
        assert_eq!(count, 1, "同 ip:port 候选去重（保留先入的接口候选）");
    }

    /// CGNAT/链路本地），RFC1918/ULA=210、公网 v4/全局 v6=100，列表降序。
    #[tokio::test]
    async fn test_collect_local_candidates_filters_and_priority() {
        let cands = collect_local_candidates(&[], 59990).await;
        use crate::lan_candidates;
        for c in &cands {
            assert!(
                lan_candidates::is_reportable_candidate(c.addr.ip()),
                "不可上报地址混入候选：{}",
                c.addr
            );
            let expect = lan_candidates::candidate_priority(c.addr.ip()).unwrap();
            assert_eq!(c.priority, expect);
            assert_eq!(c.addr.port(), 59990);
        }
        assert!(cands.windows(2).all(|w| w[0].priority >= w[1].priority));
    }

    /// （服务器仍会附加观察地址，见 registry::update_candidates）。
    #[tokio::test]
    async fn test_collect_local_candidates_report_lan_off() {
        let extra = vec![Candidate {
            addr: "203.0.113.20:59990".parse().unwrap(),
            kind: CandidateKind::Tcp,
            priority: 150,
        }];
        let cands = collect_local_candidates_with(&extra, 59990, false).await;
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].addr, "203.0.113.20:59990".parse().unwrap());
    }

    // ════════════════════════════════════════════════════════════
    // 全链 = 拨号 → Login（带 device_id）→ 控制循环建立 → 目录帧经**既
    // 有会话**发送 → 应答/静默（零新建连——连接面 = IdClient 唯一控制
    // 连接，测试断言服务端会话身份 = 注册设备 ID）。
    // ════════════════════════════════════════════════════════════

    /// mock 目录后端：写操作按配置静默/DirError；`DirList` 回固定条目；
    /// **捕获**每帧的〔服务端会话登录身份, 解码帧〕——会话化通道选择核
    /// （v2 身份执法面 = 会话登录身份；T7 回读帧形态面）。
    #[derive(Debug, Default)]
    struct CaptureDirHandler {
        upsert_err: Option<crate::protocol::DirErrorCode>,
        delete_err: Option<crate::protocol::DirErrorCode>,
        list_entries: Vec<crate::protocol::DirEntry>,
        upsert_seen: std::sync::Mutex<Option<(Option<String>, crate::protocol::DirUpsert)>>,
        delete_seen: std::sync::Mutex<Option<(Option<String>, crate::protocol::DirDelete)>>,
        list_seen: std::sync::Mutex<Option<crate::protocol::DirList>>,
    }

    impl crate::server::DirectoryHandler for CaptureDirHandler {
        fn handle_frame<'a>(
            &'a self,
            _client: std::net::SocketAddr,
            session_device_id: Option<String>,
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
            use crate::protocol::{DirDelete, DirError, DirList, DirListResp, DirUpsert};
            use crate::server::DirectoryFrameOutcome as O;
            let reply: Option<Vec<u8>> = match ty {
                crate::protocol::TYPE_DIR_UPSERT => {
                    if let Ok(d) = decode_extension::<DirUpsert>(ty, payload, ty) {
                        *self.upsert_seen.lock().unwrap() =
                            Some((session_device_id.clone(), d.clone()));
                        match self.upsert_err {
                            Some(code) => Some(encode_extension(
                                crate::protocol::TYPE_DIR_ERROR,
                                &DirError { code, msg: "mock upsert reject".to_string() },
                            )
                            .expect("encode DirError")),
                            None => None,
                        }
                    } else {
                        return Box::pin(async { Err(()) });
                    }
                }
                crate::protocol::TYPE_DIR_DELETE => {
                    if let Ok(d) = decode_extension::<DirDelete>(ty, payload, ty) {
                        *self.delete_seen.lock().unwrap() =
                            Some((session_device_id.clone(), d.clone()));
                        match self.delete_err {
                            Some(code) => Some(encode_extension(
                                crate::protocol::TYPE_DIR_ERROR,
                                &DirError { code, msg: "mock delete reject".to_string() },
                            )
                            .expect("encode DirError")),
                            None => None,
                        }
                    } else {
                        return Box::pin(async { Err(()) });
                    }
                }
                crate::protocol::TYPE_DIR_LIST => {
                    if let Ok(d) = decode_extension::<DirList>(ty, payload, ty) {
                        *self.list_seen.lock().unwrap() = Some(d);
                        let resp = DirListResp {
                            entries: self.list_entries.clone(),
                            server_ts: 1,
                            epoch: 9,
                        };
                        Some(encode_extension(
                            crate::protocol::TYPE_DIR_LIST_RESP,
                            &resp,
                        )
                        .expect("encode DirListResp"))
                    } else {
                        return Box::pin(async { Err(()) });
                    }
                }
                _ => return Box::pin(async { Err(()) }),
            };
            Box::pin(async move {
                match reply {
                    Some(f) => Ok(O::Reply(f)),
                    None => Ok(O::Silent), // 静默成功（冻结合同口径）
                }
            })
        }
    }

    fn id_dir_server_cfg(
        directory: Option<std::sync::Arc<dyn crate::server::DirectoryHandler>>,
    ) -> crate::server::TunnelServerConfig {
        let range_base = 43000 + (uuid::Uuid::new_v4().as_u128() % 2000) as u16;
        crate::server::TunnelServerConfig {
            bind_port: 0,
            bind_addrs: Vec::new(),
            token: "secret".to_string(),
            port_range: Some((range_base, range_base + 256)),
            // 须 > DIR_ACK_TIMEOUT（写操作静默等待窗口）。
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
                    "kirin_id_dir_client_test_key_{}.der",
                    uuid::Uuid::new_v4()
                )),
            ),
            rendezvous: None,
            directory,
            ..Default::default()
        }
    }

    /// 签名器)。设备注册必经私钥挑战证明，测试 IdClient 一律携真签名。
    fn test_identity() -> (
        String,
        std::sync::Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,
    ) {
        use base64::Engine as _;
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let pub_b64 = base64::engine::general_purpose::STANDARD
            .encode(key.verifying_key().as_bytes());
        (pub_b64, std::sync::Arc::new(move |p: &[u8]| key.sign(p).to_bytes().to_vec()))
    }

    async fn spawn_id_dir_client(
        device_id: &str,
        addr: &str,
    ) -> (IdClient, tokio::task::JoinHandle<()>) {
        let (pub_b64, signer) = test_identity();
        let cfg = IdClientConfig {
            server_addr: addr.to_string(),
            token: "secret".to_string(),
            device_id: device_id.to_string(),
            ed25519_pub: pub_b64,
            hostname: "id-dir-test".to_string(),
            heartbeat_interval: Duration::from_secs(2),
            heartbeat_timeout: Duration::from_secs(6),
            connect_timeout: Duration::from_secs(2),
            backoff_base: Duration::from_millis(100),
            backoff_max: Duration::from_secs(2),
            extra_candidates: Vec::new(),
            local_port: 0,
            report_lan_candidates: false, // 测试不枚举网卡（零环境依赖）
        };
        let client = IdClient::new(cfg, |_s| {}).with_reg_signer(signer);
        let runner = client.clone();
        let h = tokio::spawn(async move {
            let _ = runner.run().await;
        });
        // 等注册（Login 成功 = 会话建立；T7 触发点同刻）。
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !client.status().registered {
            assert!(
                tokio::time::Instant::now() < deadline,
                "IdClient 5s 内未注册（Login 未成功）"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        (client, h)
    }

    /// **既有设备身份会话**（零新建连）；服务端视角会话登录身份 = 注册
    /// 设备 ID（v2 身份执法面通过核）；静默成功判据不变（窗口内无
    /// DirError = Ack）。
    #[tokio::test]
    async fn test_r140_4_id_dir_upsert_delete_session_identity() {
        use crate::client::{DirRequest, DirResponse};
        let handler = std::sync::Arc::new(CaptureDirHandler::default());
        let cfg = id_dir_server_cfg(Some(handler.clone()));
        let server = crate::server::TunnelServer::bind(cfg)
            .await
            .expect("bind test relay server");
        let handle = server.shutdown_handle();
        let addr = format!("[::1]:{}", server.port());
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        let (client, _h) = spawn_id_dir_client("devtest1", &addr).await;
        //    透传核（表单互联 token 经会话通道上交 home，落 wire 第 5 位）。
        let res = client
            .dir(&DirRequest::Upsert {
                device_id: "devtest1".to_string(),
                domain: "dev.example.com".to_string(),
                target_domain: "b.test.relay".to_string(),
                ix_token: "ix-tok-777".to_string(),
            })
            .await;
        assert!(
            matches!(res, Ok(DirResponse::Ack)),
            "session upsert should be silent Ack, got {res:?}"
        );
        let (sess, up) = handler
            .upsert_seen
            .lock()
            .unwrap()
            .clone()
            .expect("服务端应收到 DirUpsert（经既有会话）");
        assert_eq!(
            sess.as_deref(),
            Some("devtest1"),
            "会话登录身份 = 注册设备 ID（会话化通道选择核）"
        );
        assert_eq!(up.device_id, "devtest1");
        assert_eq!(up.target_domain, "b.test.relay");
        assert_eq!(up.domain, "dev.example.com");
        assert_eq!(up.ix_token, "ix-tok-777");
        // 2) 会话化 Delete = 静默 Ack + target_domain 透传。
        let res = client
            .dir(&DirRequest::Delete {
                device_id: "devtest1".to_string(),
                target_domain: "b.test.relay".to_string(),
            })
            .await;
        assert!(
            matches!(res, Ok(DirResponse::Ack)),
            "session delete should be silent Ack, got {res:?}"
        );
        let (sess, del) = handler
            .delete_seen
            .lock()
            .unwrap()
            .clone()
            .expect("服务端应收到 DirDelete（经既有会话）");
        assert_eq!(sess.as_deref(), Some("devtest1"));
        assert_eq!(del.target_domain, "b.test.relay");
        client.stop();
        handle.shutdown();
    }

    /// filter_device:self}` 经既有会话；wire 形态钉死（scope 变体索引 /
    /// refresh=false / filter_device 尾部透传）；应答 = DirListResp。
    #[tokio::test]
    async fn test_r140_4_id_dir_list_local_filter_session() {
        use crate::client::{DirRequest, DirResponse};
        use crate::protocol::{DirEntry, DirScope};
        let handler = std::sync::Arc::new(CaptureDirHandler {
            list_entries: vec![DirEntry {
                device_id: "devtest1".to_string(),
                device_domain: "dev.example.com".to_string(),
                target_domain: "b.test.relay".to_string(),
                source: "manual".to_string(),
                source_fp: String::new(),
                updated_at: 123,
                sig_verified: true,
            }],
            ..Default::default()
        });
        let cfg = id_dir_server_cfg(Some(handler.clone()));
        let server = crate::server::TunnelServer::bind(cfg)
            .await
            .expect("bind test relay server");
        let handle = server.shutdown_handle();
        let addr = format!("[::1]:{}", server.port());
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        let (client, _h) = spawn_id_dir_client("devtest1", &addr).await;
        let res = client
            .dir(&DirRequest::List {
                scope: DirScope::Local,
                filter_device: Some("devtest1".to_string()),
            })
            .await;
        match res {
            Ok(DirResponse::List { entries, epoch }) => {
                assert_eq!(entries.len(), 1, "回读 = 该设备 target 行（A 侧镜像）");
                assert_eq!(entries[0].target_domain, "b.test.relay");
                assert_eq!(epoch, 9);
            }
            other => panic!("session list should get DirListResp, got {other:?}"),
        }
        let dl = handler.list_seen.lock().unwrap().clone().expect("DirList 帧到达");
        assert_eq!(dl.scope, DirScope::Local, "回读 scope = Local（自持行面）");
        assert!(!dl.refresh, "refresh 恒 false（运维重推面 UI 不消费）");
        assert_eq!(dl.filter_device.as_deref(), Some("devtest1"), "filter_device = self（T7/T1 回读形态）");
        client.stop();
        handle.shutdown();
    }

    /// 专属错误码 = 客户端 i18n 映射键）。
    #[tokio::test]
    async fn test_r140_4_id_dir_quota_error_propagated() {
        use crate::client::{DirRequest, DirRequestError};
        use crate::protocol::DirErrorCode;
        let handler = std::sync::Arc::new(CaptureDirHandler {
            upsert_err: Some(DirErrorCode::QuotaExceeded),
            ..Default::default()
        });
        let cfg = id_dir_server_cfg(Some(handler.clone()));
        let server = crate::server::TunnelServer::bind(cfg)
            .await
            .expect("bind test relay server");
        let handle = server.shutdown_handle();
        let addr = format!("[::1]:{}", server.port());
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        let (client, _h) = spawn_id_dir_client("devtest1", &addr).await;
        let res = client
            .dir(&DirRequest::Upsert {
                device_id: "devtest1".to_string(),
                domain: "dev.example.com".to_string(),
                target_domain: "b.test.relay".to_string(),
                ix_token: String::new(),
            })
            .await;
        match res {
            Err(DirRequestError::DirError { code, msg }) => {
                assert_eq!(code, DirErrorCode::QuotaExceeded);
                assert_eq!(msg, "mock upsert reject");
            }
            other => panic!("expected DirError quota_exceeded, got {other:?}"),
        }
        client.stop();
        handle.shutdown();
    }

    /// 「远控服务端未在线」，不伪称拨号失败）。
    #[tokio::test]
    async fn test_r140_4_id_dir_no_session_before_login() {
        use crate::client::{DirRequest, DirRequestError};
        let client = IdClient::new(IdClientConfig::default(), |_s| {});
        let res = client
            .dir(&DirRequest::Upsert {
                device_id: "devtest1".to_string(),
                domain: "dev.example.com".to_string(),
                target_domain: "b.test.relay".to_string(),
                ix_token: String::new(),
            })
            .await;
        assert!(
            matches!(res, Err(DirRequestError::NoSession(_))),
            "dir before login should be NoSession, got {res:?}"
        );
    }

    /// 注册完成后；未登录不触发）。
    #[tokio::test]
    async fn test_r140_4_id_login_hook_fires_once_on_login_success() {
        let cfg = id_dir_server_cfg(None);
        let server = crate::server::TunnelServer::bind(cfg)
            .await
            .expect("bind test relay server");
        let handle = server.shutdown_handle();
        let addr = format!("[::1]:{}", server.port());
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (pub_b64, signer) = test_identity();
        let client_cfg = IdClientConfig {
            server_addr: addr.clone(),
            token: "secret".to_string(),
            device_id: "devtest2".to_string(),
            ed25519_pub: pub_b64,
            hostname: "id-dir-test".to_string(),
            heartbeat_interval: Duration::from_secs(2),
            heartbeat_timeout: Duration::from_secs(6),
            connect_timeout: Duration::from_secs(2),
            backoff_base: Duration::from_millis(100),
            backoff_max: Duration::from_secs(2),
            extra_candidates: Vec::new(),
            local_port: 0,
            report_lan_candidates: false,
        };
        let client = IdClient::new(client_cfg, |_s| {}).with_reg_signer(signer);
        assert_eq!(fired.load(std::sync::atomic::Ordering::SeqCst), 0);
        let fh = fired.clone();
        client.on_login_success(move || {
            fh.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let runner = client.clone();
        let _h = tokio::spawn(async move {
            let _ = runner.run().await;
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !client.status().registered {
            assert!(
                tokio::time::Instant::now() < deadline,
                "IdClient 5s 内未注册"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // 注册成功 = 登录完成 → hook 恰一次（重连再登录才再次触发）。
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "登录成功触发 T7 hook 恰一次"
        );
        client.stop();
        handle.shutdown();
    }
}
