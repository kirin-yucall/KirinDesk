//! M8-T026-P1: 打洞辅助（PUNCH-001~006、PUNCH-SEC-001~004）。
//!
//! `PunchSession` 打洞状态机：
//! `Idle → Registering → CandidateExchange → Probing → Secured / Failed
//!  → (NAT 老化) Repunching → Probing ...`
//!
//! 职责与边界：
//! - **UDP 打洞（主路径，PUNCH-001）**：bind 本地 UDP socket → `CandidateRegister`
//!   （含服务器观察地址互转）→ 双方**同时互发** `PunchProbe`（各 NAT 建立映射）
//!   → 收到 Ack → `UdpEstablished { socket, peer_addr }` 交还上层（media 层在
//!   该 socket 上直接跑 QUIC）；探测不经服务器（PUNCH-PROTO-004）。
//! - **TCP 同时打开（辅路径，PUNCH-002）**：双方 bind 同端口 + 同时 connect
//!   对方候选 → 完成后**必须走 `SecureChannelGeneric` Ed25519 双向握手**
//!   （PUNCH-SEC-001 红线：任何打洞路径不弱化身份校验；握手角色由 device_id
//!   字典序确定，双方各自判定、无需协商）。
//! - **失败判定（PUNCH-003）**：UDP 5 次探测无 Ack / TCP 超时未建立 →
//!   `PunchResult{ok:false}` → `Failed`（中继承载不受影响，由上层保持）。
//! - **NAT 老化重打洞（PUNCH-004）**：`repunch()` 同一 `session_id` 重新候选
//!   交换 + 探测，不新建会话；连续失败计数由 `PathManager::on_repunch_result`
//!   维护（≥2 保持中继）。
//! - **控制连接保持（PUNCH-005）**：成功后不关闭（承载 PunchResult 上报、
//!   重打洞候选刷新），`drop` 时释放。
//! - 审计（PUNCH-SEC-004）：成功/失败/重打洞写 `utils::audit`（`PathSwitch`
//!   由 PathManager 写）。

use crate::crypto::ed25519::IdentityManager;
use crate::crypto::handshake::{
    client_handshake_generic, server_handshake_verified_with_nickname_generic,
    SecureChannelGeneric,
};
use kirin_desk_relay::protocol::{
    decode_extension, decode_probe, encode_probe, encode_probe_ack, read_frame, write_frame,
    Candidate, CandidateKind, CandidateRegister, PeerCandidates, PunchProbe, PunchProbeAck,
    PunchResult as PunchResultMsg, TYPE_CANDIDATE_REGISTER, TYPE_PEER_CANDIDATES,
    TYPE_PUNCH_RESULT,
};
use kirin_desk_utils::audit::{AuditEvent, AuditLogger};
use rand::RngCore;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

/// 对端候选互转等待上限（对端尚未登记时服务器不互转；超时判失败）。
pub const PEER_CANDIDATES_TIMEOUT: Duration = Duration::from_secs(10);
/// TCP 同时打开重试间隔（双方需"同时"connect，loopback/NAT 下重试对齐）。
const TCP_OPEN_RETRY: Duration = Duration::from_millis(200);
/// 服务器连接/建连超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 本地候选优先级（服务器观察地址优先级 200 更高，探测优先打洞目标）。
const LOCAL_UDP_PRIORITY: u8 = 100;
const LOCAL_TCP_PRIORITY: u8 = 90;

/// 打洞启用的路径模式（测试可单开一路）。
#[derive(Debug, Clone, Copy)]
pub struct PunchModes {
    pub udp: bool,
    pub tcp: bool,
}

impl Default for PunchModes {
    fn default() -> Self {
        Self { udp: true, tcp: true }
    }
}

/// TCP 同时打开路径的 Ed25519 握手凭据（PUNCH-SEC-001：与直连完全一致）。
#[derive(Debug, Clone)]
pub struct PunchHandshake {
    /// 本端域名（服务端白名单按此匹配）。
    pub domain: String,
    /// 本端设备类型。
    pub device_type: String,
    /// 对端设备 ID（服务端握手昵称 / 客户端握手 server_id）。
    pub peer_device_id: String,
    /// 对端 Ed25519 公钥（base64，pin 绑定；known_hosts/DNS TXT 来源）。
    pub peer_public_key_base64: String,
    /// 挑战码（PUNCH-SEC-001：挑战码校验保持生效）。
    pub challenge: String,
}

/// 打洞配置（`M8-T026_接口交互协调.md` §3.4 冻结 API + v3 扩展字段）。
#[derive(Debug, Clone)]
pub struct PunchConfig {
    /// rendezvous 服务器地址（控制连接）。
    pub rendezvous_addr: SocketAddr,
    /// 本端设备 ID（候选登记 + TCP 握手角色判定）。
    pub device_id: String,
    /// UDP/TCP bind 地址（默认 `0.0.0.0`；回环测试传 `127.0.0.1`）。
    pub local_ip: IpAddr,
    /// 探测间隔（默认 3s，PUNCH-PROTO-007）。
    pub probe_interval: Duration,
    /// 最大探测次数（默认 5，PUNCH-PROTO-007）。
    pub max_probes: u8,
    /// TCP 同时打开超时（默认 5s，PUNCH-PROTO-007）。
    pub tcp_open_timeout: Duration,
    /// 对端候选等待上限（默认 10s；测试可调短）。
    pub peer_timeout: Duration,
    /// 最大重打洞尝试（默认 2；与 PathManager 连续失败阈值对齐）。
    pub max_repunch_attempts: u8,
    /// 启用路径（默认 UDP+TCP）。
    pub modes: PunchModes,
    /// TCP 路径握手凭据（PUNCH-SEC-001）。
    pub handshake: PunchHandshake,
}

impl PunchConfig {
    /// 测试用最小配置（回环）。
    pub fn loopback(device_id: &str) -> Self {
        Self {
            rendezvous_addr: "127.0.0.1:1".parse().unwrap(),
            device_id: device_id.into(),
            local_ip: "127.0.0.1".parse().unwrap(),
            probe_interval: Duration::from_millis(50),
            max_probes: 5,
            tcp_open_timeout: Duration::from_secs(2),
            peer_timeout: PEER_CANDIDATES_TIMEOUT,
            max_repunch_attempts: 2,
            modes: PunchModes::default(),
            handshake: PunchHandshake {
                domain: "punch.local".into(),
                device_type: "punch-test".into(),
                peer_device_id: "peer".into(),
                peer_public_key_base64: String::new(),
                challenge: String::new(),
            },
        }
    }
}

/// 打洞结果（冻结 API；UDP 交还 socket 给 media 层跑 QUIC）。
pub enum PunchResult {
    /// UDP 打洞成功：socket（探测已停止，可直接交 QUIC endpoint）与对端地址。
    UdpEstablished {
        socket: std::net::UdpSocket,
        peer_addr: SocketAddr,
    },
    /// TCP 同时打开成功：已完成 Ed25519 双向握手（PUNCH-SEC-001）。
    TcpEstablished { channel: SecureChannelGeneric<TcpStream> },
    /// 全部路径失败（PUNCH-003；中继承载不受影响）。
    Failed { reason: String },
}

impl std::fmt::Debug for PunchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PunchResult::UdpEstablished { socket, peer_addr } => f
                .debug_struct("UdpEstablished")
                .field(
                    "socket",
                    &socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
                )
                .field("peer_addr", peer_addr)
                .finish(),
            PunchResult::TcpEstablished { .. } => f.write_str("TcpEstablished"),
            PunchResult::Failed { reason } => {
                f.debug_struct("Failed").field("reason", reason).finish()
            }
        }
    }
}

/// 打洞状态（PUNCH-001 状态机）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchState {
    Idle,
    Registering,
    CandidateExchange,
    Probing,
    Secured,
    Failed,
    Repunching,
}

/// 打洞会话（每会话一个；控制连接持有至 drop，PUNCH-005）。
pub struct PunchSession {
    cfg: PunchConfig,
    identity: Arc<IdentityManager>,
    /// 128 位随机会话标识（PUNCH-SEC-003：仅双端与服务器知晓）。
    session_id: [u8; 16],
    /// session_id 是否由发起方固定（真实流程：经现有控制连接告知对端）。
    session_pinned: bool,
    state: PunchState,
    /// rendezvous 控制连接（保持；repunch 复用）。
    control: Option<TcpStream>,
    audit: Option<Arc<Mutex<AuditLogger>>>,
    /// 重打洞累计（会话内；与 PathManager 连续失败计数联动）。
    repunch_attempts: u8,
}

fn random_128() -> [u8; 16] {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

impl PunchSession {
    pub fn new(cfg: PunchConfig, identity: Arc<IdentityManager>) -> Self {
        Self {
            cfg,
            identity,
            session_id: random_128(),
            session_pinned: false,
            state: PunchState::Idle,
            control: None,
            audit: None,
            repunch_attempts: 0,
        }
    }

    /// 以**固定 session_id** 构造（PUNCH-SEC-003）：发起方生成 128 位随机
    /// session_id 并经现有控制连接告知对端，双方用同一会话打洞。
    pub fn with_session_id(
        cfg: PunchConfig,
        identity: Arc<IdentityManager>,
        session_id: [u8; 16],
    ) -> Self {
        Self {
            cfg,
            identity,
            session_id,
            session_pinned: true,
            state: PunchState::Idle,
            control: None,
            audit: None,
            repunch_attempts: 0,
        }
    }

    /// 注入审计（PUNCH-SEC-004）。
    pub fn set_audit(&mut self, logger: Arc<Mutex<AuditLogger>>) {
        self.audit = Some(logger);
    }

    /// 固定当前 session_id（PUNCH-SEC-003）：发起方生成会话后调用，
    /// `establish()` 不再重生成，并将该 id 经现有控制连接告知对端。
    pub fn pin_session(&mut self) {
        self.session_pinned = true;
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    pub fn state(&self) -> PunchState {
        self.state
    }

    /// 完整打洞流程（UDP 主路径并行 + TCP 辅路径；PUNCH-001/002/003）。
    /// 未固定 session_id 时每次建立生成新会话。
    pub async fn establish(&mut self) -> PunchResult {
        if !self.session_pinned {
            self.session_id = random_128();
        }
        self.repunch_attempts = 0;
        self.run_punch().await
    }

    /// NAT 老化重打洞（PUNCH-004）：同 session_id 重新候选交换 + 探测。
    /// 连续 `max_repunch_attempts` 次失败返回 `Failed`（上层保持中继）。
    pub async fn repunch(&mut self) -> PunchResult {
        self.state = PunchState::Repunching;
        self.repunch_attempts = self.repunch_attempts.saturating_add(1);
        self.audit(
            AuditEvent::TunnelRepunch,
            &format!("device={} attempt={}", self.cfg.device_id, self.repunch_attempts),
        );
        if self.repunch_attempts > self.cfg.max_repunch_attempts {
            self.state = PunchState::Failed;
            return PunchResult::Failed {
                reason: format!(
                    "repunch attempts exhausted ({}/{}) — keep relay",
                    self.repunch_attempts, self.cfg.max_repunch_attempts
                ),
            };
        }
        self.run_punch().await
    }

    // ── 内部 ──

    fn audit(&self, event: AuditEvent, detail: &str) {
        if let Some(logger) = &self.audit {
            if let Ok(mut l) = logger.lock() {
                let _ = l.record(event, detail);
            }
        }
    }

    fn fail(&mut self, reason: String) -> PunchResult {
        self.state = PunchState::Failed;
        self.audit(
            AuditEvent::TunnelPunchFailed,
            &format!("device={} reason={}", self.cfg.device_id, reason),
        );
        PunchResult::Failed { reason }
    }

    /// 一轮完整打洞（候选交换 + UDP/TCP 并行探测）。
    async fn run_punch(&mut self) -> PunchResult {
        self.state = PunchState::Registering;

        // 控制连接（PUNCH-005：首次建立，repunch 复用；失败即整体失败）。
        // 打洞流程内读写为**顺序**（注册 → 等候选 → 上报），无需 split。
        if self.control.is_none() {
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(self.cfg.rendezvous_addr)).await {
                Ok(Ok(stream)) => {
                    info!("punch: control connected to {}", self.cfg.rendezvous_addr);
                    self.control = Some(stream);
                }
                Ok(Err(e)) => return self.fail(format!("rendezvous connect: {e}")),
                Err(_) => return self.fail("rendezvous connect timeout".into()),
            }
        }
        let mut control = self.control.take().expect("control present");

        // UDP 打洞 socket（每次打洞新建——NAT 老化后新映射）
        let udp_socket = match UdpSocket::bind((self.cfg.local_ip, 0)).await {
            Ok(s) => s,
            Err(e) => return self.fail(format!("udp bind: {e}")),
        };
        let udp_port = udp_socket.local_addr().map(|a| a.port()).unwrap_or(0);
        let local_candidates = vec![
            Candidate {
                addr: SocketAddr::from((self.cfg.local_ip, udp_port)),
                kind: CandidateKind::Udp,
                priority: LOCAL_UDP_PRIORITY,
            },
            Candidate {
                addr: SocketAddr::from((self.cfg.local_ip, udp_port)),
                kind: CandidateKind::Tcp,
                priority: LOCAL_TCP_PRIORITY,
            },
        ];

        // 候选交换（PUNCH-PROTO-001/003）
        self.state = PunchState::CandidateExchange;
        let reg = CandidateRegister {
            device_id: self.cfg.device_id.clone(),
            session_id: Some(self.session_id),
            candidates: local_candidates,
        };
        let payload = match bincode::serialize(&reg) {
            Ok(p) => p,
            Err(e) => return self.fail(format!("candidate encode: {e}")),
        };
        if let Err(e) = write_frame(&mut control, TYPE_CANDIDATE_REGISTER, &payload).await {
            return self.fail(format!("candidate register: {e}"));
        }

        // 等对端候选互转（PUNCH-PROTO-003；期间忽略对端 PunchResult 转发）
        let peer_candidates = match timeout(
            self.cfg.peer_timeout,
            Self::recv_peer_candidates(&mut control, self.session_id),
        )
        .await
        {
            Ok(Ok(cands)) => cands,
            Ok(Err(e)) => return self.fail(format!("peer candidates: {e}")),
            Err(_) => return self.fail("peer candidates timeout".into()),
        };
        self.state = PunchState::Probing;

        // UDP 探测（主路径）与 TCP 同时打开（辅路径）并行，先成功者胜
        let (tx, mut rx) = mpsc::channel::<PunchResult>(2);
        let mut spawned = 0u8;
        let mut udp_handle = None;
        let mut tcp_handle = None;
        if self.cfg.modes.udp {
            let sock = udp_socket;
            let targets: Vec<SocketAddr> = peer_candidates
                .iter()
                .filter(|c| c.kind == CandidateKind::Udp)
                .map(|c| c.addr)
                .collect();
            let interval = self.cfg.probe_interval;
            let max = self.cfg.max_probes;
            let sid = self.session_id;
            let tx_udp = tx.clone();
            spawned += 1;
            udp_handle = Some(tokio::spawn(async move {
                let r = Self::udp_probe(sock, sid, targets, interval, max).await;
                let _ = tx_udp
                    .send(match r {
                        Ok((peer_addr, sock)) => match sock.into_std() {
                            Ok(std_sock) => PunchResult::UdpEstablished {
                                socket: std_sock,
                                peer_addr,
                            },
                            Err(e) => PunchResult::Failed {
                                reason: format!("udp into_std: {e}"),
                            },
                        },
                        Err(reason) => PunchResult::Failed { reason },
                    })
                    .await;
            }));
        }
        if self.cfg.modes.tcp {
            let tcp_targets: Vec<SocketAddr> = peer_candidates
                .iter()
                .filter(|c| c.kind == CandidateKind::Tcp)
                .map(|c| c.addr)
                .collect();
            if !tcp_targets.is_empty() {
                let local_ip = self.cfg.local_ip;
                let open_port = udp_port;
                let open_timeout = self.cfg.tcp_open_timeout;
                let hs = self.cfg.handshake.clone();
                let identity = Arc::clone(&self.identity);
                let device_id = self.cfg.device_id.clone();
                spawned += 1;
                tcp_handle = Some(tokio::spawn(async move {
                    if let Some(r) =
                        Self::tcp_simultaneous_open(
                            local_ip, open_port, tcp_targets, open_timeout, hs, identity, device_id,
                        )
                        .await
                    {
                        let _ = tx.send(r).await;
                    }
                }));
            }
        }

        // 收集所有任务结果，首个 Established 胜出
        let mut results = Vec::with_capacity(spawned as usize);
        for _ in 0..spawned {
            match rx.recv().await {
                Some(r) => results.push(r),
                None => break,
            }
        }
        // 胜利者取第一个 Established；其余任务 abort（释放 socket/连接）
        let result = results
            .into_iter()
            .find(|r| !matches!(r, PunchResult::Failed { .. }))
            .unwrap_or_else(|| {
                PunchResult::Failed {
                    reason: "all punch paths failed (probe timeout / tcp open timeout)".into(),
                }
            });
        if let Some(h) = udp_handle {
            if !matches!(result, PunchResult::UdpEstablished { .. }) {
                h.abort();
            }
        }
        if let Some(h) = tcp_handle {
            if !matches!(result, PunchResult::TcpEstablished { .. }) {
                h.abort();
            }
        }

        // 结果上报服务器（PUNCH-PROTO-005）——控制连接保持（PUNCH-005）
        let (ok, path_kind) = match &result {
            PunchResult::UdpEstablished { .. } => (true, Some(CandidateKind::Udp)),
            PunchResult::TcpEstablished { .. } => (true, Some(CandidateKind::Tcp)),
            PunchResult::Failed { reason } => {
                debug!("punch failed: {reason}");
                (false, None)
            }
        };
        let report = PunchResultMsg {
            session_id: self.session_id,
            ok,
            path: path_kind,
        };
        if let Ok(payload) = bincode::serialize(&report) {
            let _ = write_frame(&mut control, TYPE_PUNCH_RESULT, &payload).await;
        }

        // 审计（PUNCH-SEC-004）
        match &result {
            PunchResult::UdpEstablished { peer_addr, .. } => {
                self.state = PunchState::Secured;
                info!("punch: udp path secured with {peer_addr}");
                self.audit(
                    AuditEvent::TunnelPunchSuccess,
                    &format!("device={} path=udp peer={}", self.cfg.device_id, peer_addr),
                );
            }
            PunchResult::TcpEstablished { .. } => {
                self.state = PunchState::Secured;
                info!("punch: tcp path secured");
                self.audit(
                    AuditEvent::TunnelPunchSuccess,
                    &format!("device={} path=tcp", self.cfg.device_id),
                );
            }
            PunchResult::Failed { reason } => {
                self.state = PunchState::Failed;
                self.audit(
                    AuditEvent::TunnelPunchFailed,
                    &format!("device={} reason={}", self.cfg.device_id, reason),
                );
            }
        }

        // 控制连接归还（PUNCH-005：保持；drop 时释放）
        self.control = Some(control);
        result
    }

    /// 等待服务器互转的对端候选（PUNCH-PROTO-003）。
    async fn recv_peer_candidates(
        ctrl_r: &mut TcpStream,
        session_id: [u8; 16],
    ) -> Result<Vec<Candidate>, String> {
        loop {
            match read_frame(ctrl_r).await {
                Ok((ty, payload)) => {
                    match ty {
                    TYPE_PEER_CANDIDATES => {
                        let pc: PeerCandidates =
                            decode_extension(TYPE_PEER_CANDIDATES, &payload, TYPE_PEER_CANDIDATES)
                                .map_err(|e| format!("peer candidates decode: {e}"))?;
                        if pc.session_id == session_id {
                            return Ok(pc.candidates);
                        }
                        // 其它会话的互转 → 忽略（防串话）
                    }
                    _ => {
                        // 对端 PunchResult 转发等 → 忽略，继续等
                        debug!("punch: ignore frame 0x{ty:02x} during candidate exchange");
                    }
                    }
                }
                Err(e) => return Err(format!("control recv: {e}")),
            }
        }
    }

    /// UDP 探测（PUNCH-001/004）：每轮向全部 UDP 候选发探测，等待 Ack。
    /// 收到对端探测 → 回 `PunchProbeAck`（回显 nonce）；收到本端 nonce 的
    /// Ack → 路径确认。`max_probes` 轮无 Ack → 失败（PUNCH-003）。
    async fn udp_probe(
        socket: UdpSocket,
        session_id: [u8; 16],
        targets: Vec<SocketAddr>,
        interval: Duration,
        max_probes: u8,
    ) -> Result<(SocketAddr, UdpSocket), String> {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let probe = PunchProbe { session_id, nonce };
        let probe_buf = encode_probe(&probe);
        let mut buf = [0u8; 64];

        for round in 0..max_probes {
            // 双方同时互发（PUNCH-001）
            for target in &targets {
                let _ = socket.send_to(&probe_buf, target).await;
            }
            // 等待 Ack / 对端探测（一轮 = interval）
            let mut round_done = false;
            loop {
                tokio::select! {
                    r = socket.recv_from(&mut buf) => {
                        let (n, from) = match r {
                            Ok(v) => v,
                            Err(e) => return Err(format!("udp recv: {e}")),
                        };
                        if let Ok(p) = decode_probe(&buf[..n]) {
                            if p.session_id != session_id {
                                continue; // 陌生会话报文 → 丢弃（PUNCH-SEC-003）
                            }
                            if p.nonce == nonce {
                                debug!("punch: probe ack from {from} (round {})", round + 1);
                                return Ok((from, socket)); // 路径确认
                            }
                            // 对端探测 → 回 Ack（回显其 nonce）
                            let ack = PunchProbeAck { session_id, nonce: p.nonce };
                            let _ = socket.send_to(&encode_probe_ack(&ack), from).await;
                        }
                    }
                    _ = sleep(interval) => {
                        round_done = true;
                    }
                }
                if round_done {
                    break;
                }
            }
        }
        Err(format!("no ack after {max_probes} probes"))
    }

    /// TCP 同时打开（PUNCH-002）：bind 与 UDP 同端口 + 循环 connect 对方
    /// TCP 候选（双方"同时"发起）；连接建立后走 Ed25519 双向握手
    /// （PUNCH-SEC-001；握手角色由 device_id 字典序判定，双方一致）。
    #[allow(clippy::too_many_arguments)]
    async fn tcp_simultaneous_open(
        local_ip: IpAddr,
        port: u16,
        targets: Vec<SocketAddr>,
        open_timeout: Duration,
        handshake: PunchHandshake,
        identity: Arc<IdentityManager>,
        device_id: String,
    ) -> Option<PunchResult> {
        let deadline = tokio::time::Instant::now() + open_timeout;
        let mut attempt = 0u32;
        loop {
            // 每目标新建 socket（connect 消费所有权；同端口 TCP/UDP 可共存）
            for target in &targets {
                let socket = match TcpSocket::new_v4() {
                    Ok(s) => s,
                    Err(_) => return None,
                };
                if socket.bind(SocketAddr::from((local_ip, port))).is_err() {
                    // bind 竞争（上一轮失败连接端口未及时释放）→ 重试整轮
                    break;
                }
                match timeout(Duration::from_millis(500), socket.connect(*target)).await {
                    Ok(Ok(stream)) => {
                        // 握手角色：device_id 字典序小者跑 client（双方一致）
                        let is_client = device_id < handshake.peer_device_id;
                        debug!(
                            "punch: tcp simultaneous open {target} (attempt {}, role {})",
                            attempt + 1,
                            if is_client { "client" } else { "server" }
                        );
                        let hs = handshake.clone();
                        let id = Arc::clone(&identity);
                        let did = device_id.clone();
                        let hs_result = if is_client {
                            client_handshake_generic(
                                stream,
                                &id,
                                &did,
                                &hs.domain,
                                &hs.device_type,
                                &hs.peer_device_id,
                                &hs.peer_public_key_base64,
                                &hs.challenge,
                            )
                            .await
                        } else {
                            server_handshake_verified_with_nickname_generic(
                                stream,
                                &id,
                                &did,
                                &hs.peer_public_key_base64,
                                Some(&hs.peer_device_id),
                                Some(&hs.challenge),
                            )
                            .await
                        };
                        match hs_result {
                            Ok(channel) => {
                                return Some(PunchResult::TcpEstablished { channel });
                            }
                            Err(e) => {
                                warn!("punch: tcp handshake failed: {e}");
                                return None;
                            }
                        }
                    }
                    _ => {
                        // 连接未建立（对端尚未同时 connect）→ 下一轮重试
                    }
                }
            }
            attempt += 1;
            if tokio::time::Instant::now() >= deadline {
                debug!("punch: tcp simultaneous open timeout after {attempt} attempts");
                return None;
            }
            sleep(TCP_OPEN_RETRY).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kirin_desk_relay::rendezvous::RendezvousServer;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::watch;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn tmp_identity() -> Arc<IdentityManager> {
        let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kirin_desk_punch_identity_{}_{}.json",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_file(&path);
        Arc::new(IdentityManager::generate(path).expect("identity"))
    }

    /// 进程内 rendezvous + 两个打洞会话（PUNCH-PROTO-001~007 全链路基底）。
    async fn punch_pair(
        dev_a: &str,
        dev_b: &str,
    ) -> (
        Arc<RendezvousServer>,
        SocketAddr,
        PunchSession,
        PunchSession,
    ) {
        let server = Arc::new(RendezvousServer::bind(0).await.unwrap());
        let mut addr = server.local_addr();
        if addr.ip().is_unspecified() {
            addr = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, addr.port()));
        }
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(watch::channel(false).1).await;
        });

        let mut cfg_a = PunchConfig::loopback(dev_a);
        cfg_a.rendezvous_addr = addr;
        cfg_a.handshake.peer_device_id = dev_b.into();
        let mut cfg_b = PunchConfig::loopback(dev_b);
        cfg_b.rendezvous_addr = addr;
        cfg_b.handshake.peer_device_id = dev_a.into();
        let mut a = PunchSession::new(cfg_a, tmp_identity());
        // 同一打洞会话：session_id 由发起方（A）生成并经控制连接告知对端。
        // 发起方固定自身 session_id（establish 不再重生成），对端复用。
        a.pin_session();
        let b = PunchSession::with_session_id(cfg_b, tmp_identity(), a.session_id());
        (server, addr, a, b)
    }

    #[tokio::test]
    async fn test_udp_punch_loopback_establish() {
        // PUNCH-001/003：双端（回环模拟 NAT 后）UDP 打洞建立 <2s（NF-001）
        let (_server, _addr, mut a, mut b) = punch_pair("dev-a", "dev-b").await;
        let started = std::time::Instant::now();
        let (ra, rb) = tokio::join!(a.establish(), b.establish());
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(2), "punch took {elapsed:?}");

        let (socket_a, peer_a) = match ra {
            PunchResult::UdpEstablished { socket, peer_addr } => (socket, peer_addr),
            other => panic!("A expected udp established, got {other:?}"),
        };
        let (socket_b, peer_b) = match rb {
            PunchResult::UdpEstablished { socket, peer_addr } => (socket, peer_addr),
            other => panic!("B expected udp established, got {other:?}"),
        };

        // 打洞路径上可直接通信（后续交给 QUIC，PUNCH-001）
        let sock_a = tokio::net::UdpSocket::from_std(socket_a).unwrap();
        let sock_b = tokio::net::UdpSocket::from_std(socket_b).unwrap();
        sock_a.send_to(b"ping", peer_a).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = sock_b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, peer_b);
    }

    #[tokio::test]
    async fn test_tcp_simultaneous_open_handshake() {
        // PUNCH-002 + PUNCH-SEC-001：TCP 同时打开 + Ed25519 双向握手
        let (_server, _addr, mut a, mut b) = punch_pair("dev-aa", "dev-bb").await;
        // 双方公钥 pin（真实流程来自 known_hosts/DNS TXT；PUNCH-SEC-001）
        a.cfg.handshake.peer_public_key_base64 = b.identity.public_key_base64();
        b.cfg.handshake.peer_public_key_base64 = a.identity.public_key_base64();
        // 只开 TCP 路径，验证同时打开 + 握手
        a.cfg.modes = PunchModes { udp: false, tcp: true };
        b.cfg.modes = PunchModes { udp: false, tcp: true };
        let (ra, rb) = tokio::join!(a.establish(), b.establish());

        let (mut ch_a, mut ch_b) = match (ra, rb) {
            (
                PunchResult::TcpEstablished { channel: c1 },
                PunchResult::TcpEstablished { channel: c2 },
            ) => (c1, c2),
            (ra, rb) => panic!("expected tcp established, got {ra:?} / {rb:?}"),
        };
        // 加密通道往返（AEAD）
        ch_a.stream.write_all(b"hello-punch").await.unwrap();
        let mut buf = [0u8; 64];
        let n = ch_b.stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-punch");
        // 握手身份：对端 ID 正确
        assert_eq!(ch_a.peer_id, "dev-bb");
        assert_eq!(ch_b.peer_id, "dev-aa");
    }

    #[tokio::test]
    async fn test_udp_probe_failure_judgment() {
        // PUNCH-003：5 次探测无 Ack → 失败判定（打洞 socket 上直发）
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead); // 端口释放后无人监听（探测打不中）
        let started = std::time::Instant::now();
        let r = PunchSession::udp_probe(
            sock,
            [7; 16],
            vec![dead_addr],
            Duration::from_millis(20),
            5,
        )
        .await;
        assert!(r.is_err(), "expected probe failure");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn test_peer_candidates_timeout_fails_cleanly() {
        // PUNCH-003：对端不登记 → 候选交换超时 → Failed（无状态残留）
        let (_server, _addr, mut a, b) = punch_pair("dev-fa", "dev-fb").await;
        drop(b); // 对端不存在
        a.cfg.peer_timeout = Duration::from_millis(200);
        let started = std::time::Instant::now();
        match a.establish().await {
            PunchResult::Failed { reason } => {
                assert!(reason.contains("timeout"), "reason: {reason}");
            }
            other => panic!("expected failed, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(a.state(), PunchState::Failed);
    }

    #[tokio::test]
    async fn test_repunch_same_session_id() {
        // PUNCH-004：NAT 老化 → 重打洞（同 session_id 恢复，不新建会话）
        let (_server, _addr, mut a, mut b) = punch_pair("dev-ra", "dev-rb").await;
        let (ra, _rb) = tokio::join!(a.establish(), b.establish());
        assert!(matches!(ra, PunchResult::UdpEstablished { .. }));
        let sid_before = a.session_id();

        // 模拟映射失效：上层释放旧 socket → repunch 恢复
        let (ra2, rb2) = tokio::join!(a.repunch(), b.repunch());
        match (&ra2, &rb2) {
            (PunchResult::UdpEstablished { .. }, PunchResult::UdpEstablished { .. }) => {}
            _ => panic!("repunch failed: A={ra2:?} B={rb2:?}"),
        }
        assert_eq!(a.session_id(), sid_before, "repunch 不新建会话");
    }

    #[tokio::test]
    async fn test_repunch_exhaustion_keeps_relay() {
        // PUNCH-004：连续 2 次重打洞失败 → 保持中继（Failed，不新建会话）
        let (_server, _addr, mut a, b) = punch_pair("dev-ex", "dev-ey").await;
        drop(b); // 对端不在 → 每次重打洞候选交换超时失败
        a.cfg.peer_timeout = Duration::from_millis(100);
        let r1 = a.repunch().await;
        assert!(matches!(r1, PunchResult::Failed { .. }), "attempt 1");
        let r2 = a.repunch().await;
        assert!(matches!(r2, PunchResult::Failed { .. }), "attempt 2");
        let r3 = a.repunch().await;
        match r3 {
            PunchResult::Failed { reason } => {
                assert!(reason.contains("exhausted"), "reason: {reason}");
            }
            other => panic!("expected exhaustion failure, got {other:?}"),
        }
        assert_eq!(a.state(), PunchState::Failed);
    }

    #[tokio::test]
    async fn test_audit_events_written() {
        // PUNCH-SEC-004：成功/重打洞审计齐全
        let path = std::env::temp_dir().join(format!(
            "kirin_desk_punch_audit_{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let logger = Arc::new(StdMutex::new(AuditLogger::open(&path).expect("audit open")));

        let (_server, _addr, mut a, mut b) = punch_pair("dev-au", "dev-av").await;
        a.set_audit(Arc::clone(&logger));
        let (_ra, _rb) = tokio::join!(a.establish(), b.establish());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("tunnel_punch_success"),
            "audit missing success: {content}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
