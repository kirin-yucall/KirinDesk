//! M8-T026-P1 (PUNCH-006 / PUNCH-PROTO-001~007): 打洞 rendezvous 服务端。
//!
//! 职责边界（PUNCH-006 / PUNCH-SEC-002，红线）：**只登记与转发候选 + 限速 +
//! 审计**，不进入数据面、不落盘流量。打洞探测（`PunchProbe`）为双端在打洞
//! socket 上**直发**（PUNCH-PROTO-004），本服务端不感知、不转发。
//!
//! 处理流程：
//! - `CandidateRegister`（session_id=Some，P1 打洞）：附加**服务器观察地址**
//!   （TCP 连接对端地址，PUNCH-PROTO-001 关键信息）→ 按 session_id 登记双端
//!   → 双端齐 → 互转 `PeerCandidates`（不修改候选内容，仅附加观察地址）；
//!   session_id=None（P2 ID-005 注册表候选刷新）：仅按 device_id 存最新候选。
//! - `PunchResult` / `PathProbe` / `PathProbeAck`：经 conn→session 关联透传对端。
//! - 未知 session_id / 超限候选（>16）→ 丢弃并审计（PUNCH-PROTO-002/007、
//!   PUNCH-SEC-003）；限速（每设备每 5s ≤ 10 次）→ 拒绝并审计。
//! - 其余已知 type（P2 的 Login/ResolveDevice/Tunnel*）→ 交给 [`RendezvousExtension`]
//!   （P2 挂载点）；未知 type → 连接判死（TNL-PROTO-007）。

use crate::audit::{AuditSink, NoopAudit, TunnelAuditEvent};
use crate::protocol::{
    decode_extension, read_frame, wrap_frame, Candidate, CandidateKind, CandidateRegister,
    PathProbe, PathProbeAck, PeerCandidates, PunchResult, TYPE_CANDIDATE_REGISTER,
    TYPE_PATH_PROBE, TYPE_PATH_PROBE_ACK, TYPE_PEER_CANDIDATES, TYPE_PUNCH_RESULT,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

/// 默认打洞限速窗口（PUNCH-006：每设备每 5s ≤ 10 次候选交换）。
pub const DEFAULT_PUNCH_RATE_WINDOW: Duration = Duration::from_secs(5);
/// 默认打洞限速上限（每窗口每设备）。
pub const DEFAULT_PUNCH_RATE_LIMIT: usize = 10;
/// 候选列表上限（PUNCH-PROTO-002：≤ 16 条）。
pub const MAX_CANDIDATES: usize = 16;
/// 服务器观察地址作为候选时的优先级（高于本地候选，是打洞关键信息）。
pub const OBSERVED_PRIORITY: u8 = 200;

// ── 安全审计 R-1：RendezvousServer 资源上限与源 IP 限速加固 ──────────────
// 默认部署即暴露的 7001 端口此前完全无认证且无资源上限：单连接/多连接
// 直接打瘫（无界 task/fd、四张无上限 HashMap）。以下硬上限 + 空闲超时 +
// 源 IP 限速使攻击面受控（打洞是轻量登记/互转协议，合法流量远低于上限）。
/// 并发连接硬上限（防空连永久占用 reader+writer 双 task / fd）。
pub const MAX_RENDEZVOUS_CONNS: usize = 1024;
/// 单连接空闲超时（无帧即关闭，防空连无限驻留）。
pub const RENDEZVOUS_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// 打洞会话表硬上限（防唯一 session_id 撑爆 sessions 表；LRU 淘汰最旧）。
pub const MAX_RENDEZVOUS_SESSIONS: usize = 8192;
/// 注册表候选表（session_id=None 路径）硬上限（满则淘汰任意键）。
pub const MAX_RENDEZVOUS_DEVICE_CANDIDATES: usize = 4096;
/// 限速表（rate/ip_rate）键数硬上限（LRU 淘汰最旧）。
pub const MAX_RENDEZVOUS_RATE_KEYS: usize = 4096;
/// 每源 IP（/24·/64 聚合，复用 `rate_limit::bucket_key`）限速窗口。
pub const DEFAULT_IP_RATE_WINDOW: Duration = Duration::from_secs(30);
/// 每源 IP 每窗口候选交换上限（防 device_id 旋转绕过设备级限速）。
pub const DEFAULT_IP_RATE_LIMIT: usize = 30;

/// 会话一侧的登记信息。
struct PeerSlot {
    conn_id: u64,
    device_id: String,
    /// 含服务器观察地址的候选列表。
    candidates: Vec<Candidate>,
    /// 该连接的发帧通道（**完整帧**；writer task / 隧道会话控制通道独占消费）。
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// 打洞会话（session_id 关联双端，双端齐才互转）。
///
/// 版本号语义（PUNCH-004 重打洞竞态防护）：每次登记/刷新递增本端版本；
/// 仅当**双端都刷新过**（各自版本 > 上次互转版本）才互转——避免把对端
/// 尚未刷新的旧候选（NAT 老化前的失效地址）转发给对方。
///
/// `last_activity`（安全审计 R-1）：会话表 LRU 淘汰依据（表满时淘汰最久
/// 未活跃会话，防唯一 session_id 撑爆 sessions 表）。
struct PunchSessionState {
    a: Option<PeerSlot>,
    b: Option<PeerSlot>,
    a_version: u64,
    b_version: u64,
    forwarded_version: u64,
    last_activity: Instant,
}

impl Default for PunchSessionState {
    fn default() -> Self {
        Self {
            a: None,
            b: None,
            a_version: 0,
            b_version: 0,
            forwarded_version: 0,
            last_activity: Instant::now(),
        }
    }
}

impl PunchSessionState {
    fn slot_mut(&mut self, conn_id: u64) -> Option<&mut PeerSlot> {
        if self.a.as_ref().is_some_and(|s| s.conn_id == conn_id) {
            self.a.as_mut()
        } else if self.b.as_ref().is_some_and(|s| s.conn_id == conn_id) {
            self.b.as_mut()
        } else {
            None
        }
    }

    fn other_slot(&self, conn_id: u64) -> Option<&PeerSlot> {
        if self.a.as_ref().is_some_and(|s| s.conn_id == conn_id) {
            self.b.as_ref()
        } else if self.b.as_ref().is_some_and(|s| s.conn_id == conn_id) {
            self.a.as_ref()
        } else {
            None
        }
    }

    fn remove_conn(&mut self, conn_id: u64) {
        if self.a.as_ref().is_some_and(|s| s.conn_id == conn_id) {
            self.a = None;
        } else if self.b.as_ref().is_some_and(|s| s.conn_id == conn_id) {
            self.b = None;
        }
    }
}

/// 打洞 rendezvous 扩展点（P2 挂载 Login/ResolveDevice/Tunnel* 等非 punch 帧）。
///
/// 返回 `Some(payload)` = 以**同一帧类型**回一条消息（bincode 负载）；
/// `None` = 不回复（消息仍被丢弃）。扩展点不持有连接写权，只做应答。
pub trait RendezvousExtension: Send + Sync {
    fn on_frame(&self, kind: u8, payload: &[u8], peer: SocketAddr, conn_id: u64) -> Option<Vec<u8>>;
}

/// 打洞 rendezvous 服务端（PUNCH-006）。
pub struct RendezvousServer {
    listener: TcpListener,
    /// session_id → 双端登记。
    sessions: Mutex<HashMap<[u8; 16], PunchSessionState>>,
    /// 连接 → session 归属（PunchResult/PathProbe 路由用）。
    conn_session: Mutex<HashMap<u64, [u8; 16]>>,
    /// session_id=None 的注册表候选刷新（P2 ID-005 复用；仅存最新候选）。
    device_candidates: Mutex<HashMap<String, Vec<Candidate>>>,
    /// 每设备滑动窗口限速（PUNCH-006）。
    rate: Mutex<HashMap<String, Vec<Instant>>>,
    /// 每源 IP（/24·/64 聚合）滑动窗口限速（安全审计 R-1：device_id 旋转兜底）。
    ip_rate: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    audit: Arc<dyn AuditSink>,
    extension: Option<Arc<dyn RendezvousExtension>>,
    next_conn_id: AtomicU64,
    /// 并发连接计数（安全审计 R-1：连接硬上限维护，accept 出口增减）。
    active_conns: AtomicUsize,
}

impl std::fmt::Debug for RendezvousServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 仅输出监听地址（其余为运行时状态，不参与 Debug）。
        f.debug_struct("RendezvousServer")
            .field("local_addr", &self.local_addr())
            .finish_non_exhaustive()
    }
}

impl RendezvousServer {
    /// 绑定监听（`[::]:port` 优先，失败回退 `0.0.0.0`，对齐 M8-T025 双栈模式）。
    /// `port = 0` 由系统分配（测试用），经 [`Self::local_addr`] 查询。
    pub async fn bind(port: u16) -> std::io::Result<Self> {
        let listener = match TcpListener::bind(format!("[::]:{port}")).await {
            Ok(l) => l,
            Err(_) => {
                warn!("rendezvous: [::] bind unavailable, fallback 0.0.0.0:{port}");
                TcpListener::bind(format!("0.0.0.0:{port}")).await?
            }
        };
        let local = listener.local_addr()?;
        info!("RendezvousServer bound on {local}");
        Ok(Self {
            listener,
            sessions: Mutex::new(HashMap::new()),
            conn_session: Mutex::new(HashMap::new()),
            device_candidates: Mutex::new(HashMap::new()),
            rate: Mutex::new(HashMap::new()),
            ip_rate: Mutex::new(HashMap::new()),
            audit: Arc::new(NoopAudit),
            extension: None,
            next_conn_id: AtomicU64::new(1),
            active_conns: AtomicUsize::new(0),
        })
    }

    /// 注入审计回调（默认丢弃）。
    pub fn with_audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = audit;
        self
    }

    /// 注入扩展点（P2：Login/ResolveDevice/Tunnel*）。
    pub fn with_extension(mut self, ext: Arc<dyn RendezvousExtension>) -> Self {
        self.extension = Some(ext);
        self
    }

    /// 本地监听地址（测试取端口用）。
    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr().expect("bound listener addr")
    }

    /// 分配进程内唯一连接标识（R-08b S1：隧道服控制会话接入打洞会话表用；
    /// 与自身监听连接共用同一 id 空间，杜绝会话表槽位冲突）。
    pub fn alloc_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    /// R-08b S1：外部会话（隧道服控制连接）打洞帧接入入口 —— 与自身
    /// 监听连接共用同一套登记/互转/限速/审计（PUNCH-006 / PUNCH-SEC-002）。
    /// `conn_id` 由 [`Self::alloc_conn_id`] 分配（调用方缓存复用）；
    /// `send` 为调用方回写通道（**完整帧**，如会话 `control_tx`）。
    /// 返回 `false` = 帧无法处理（调用方应判死，对齐 TNL-PROTO-007）。
    pub async fn handle_external_frame(
        &self,
        conn_id: u64,
        peer: SocketAddr,
        ty: u8,
        payload: &[u8],
        send: &mpsc::UnboundedSender<Vec<u8>>,
    ) -> bool {
        self.dispatch(conn_id, peer, ty, payload, send).await
    }

    /// R-08b S1：外部会话（隧道会话）结束时的清理入口 —— 从打洞会话表
    /// 移除槽位与 conn→session 关联（PUNCH-003 无状态残留）。
    pub fn remove_external_conn(&self, conn_id: u64) {
        self.cleanup_conn(conn_id);
    }

    /// 接受连接直至 `stop` 置位。每连接一个 task（读侧 + writer task）。
    ///
    /// R-08b S2（优雅关闭无泄漏）：连接任务经 `JoinSet` 跟踪，退出前
    /// 全部中止并汇合 —— 不残留协程（部署进程 `Ctrl+C` 后可干净退出）。
    pub async fn serve(self: Arc<Self>, mut stop: watch::Receiver<bool>) -> std::io::Result<()> {
        let mut conns = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = stop.changed() => {
                    if *stop.borrow() {
                        let alive = conns.len();
                        conns.abort_all();
                        while conns.join_next().await.is_some() {}
                        debug!("RendezvousServer stopped ({alive} conns aborted)");
                        return Ok(());
                    }
                }
                r = self.listener.accept() => {
                    let (stream, peer) = match r {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("rendezvous accept error: {e}");
                            continue;
                        }
                    };
                    // 安全审计 R-1：连接硬上限（每连接占 reader+writer 双 task
                    // + fd + 通道；无上限时单点空连可打瘫整个 relay-server）。
                    let prev = self.active_conns.fetch_add(1, Ordering::Relaxed);
                    if prev >= MAX_RENDEZVOUS_CONNS {
                        self.active_conns.fetch_sub(1, Ordering::Relaxed);
                        warn!(
                            "rendezvous connection cap reached ({MAX_RENDEZVOUS_CONNS}), dropping {peer}"
                        );
                        drop(stream);
                        continue;
                    }
                    let srv = Arc::clone(&self);
                    conns.spawn(async move { Self::handle_conn(srv, stream, peer).await });
                }
            }
        }
    }

    /// 单连接事件循环（读侧在此 task；写侧经 mpsc 交给 writer task）。
    async fn handle_conn(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // writer task：独占消费发帧通道（完整帧），避免跨 task 持锁等待写
        let writer_task = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if writer.write_all(&frame).await.is_err() {
                    break; // 对端关闭 → 停止
                }
            }
        });

        loop {
            // 安全审计 R-1：空闲超时——空连不再永久占用 reader+writer 双 task
            // （此前无任何超时，`nc` 空连可无限驻留耗尽 fd/内存）。
            match tokio::time::timeout(RENDEZVOUS_IDLE_TIMEOUT, read_frame(&mut reader)).await {
                Ok(Ok((ty, payload))) => {
                    if !self.dispatch(conn_id, peer, ty, &payload, &tx).await {
                        // 未知 type / 无法处理 → 判死关闭（TNL-PROTO-007）
                        warn!("rendezvous conn {conn_id} ({peer}): unhandled type 0x{ty:02x}, closing");
                        break;
                    }
                }
                Ok(Err(e)) => {
                    debug!("rendezvous conn {conn_id} ({peer}) closed: {e}");
                    break;
                }
                Err(_) => {
                    debug!(
                        "rendezvous conn {conn_id} ({peer}) idle timeout \
                         ({RENDEZVOUS_IDLE_TIMEOUT:?}), closing"
                    );
                    break;
                }
            }
        }
        drop(tx);
        writer_task.abort();
        self.cleanup_conn(conn_id);
        // 归还连接额度（serve 停止时的 abort 路径不归还，属进程退出语义）。
        self.active_conns.fetch_sub(1, Ordering::Relaxed);
    }

    /// 分发一帧；返回 `false` = 连接应判死关闭。
    async fn dispatch(
        &self,
        conn_id: u64,
        peer: SocketAddr,
        ty: u8,
        payload: &[u8],
        tx: &mpsc::UnboundedSender<Vec<u8>>,
    ) -> bool {
        match ty {
            TYPE_CANDIDATE_REGISTER => {
                let msg: CandidateRegister = match decode_extension(TYPE_CANDIDATE_REGISTER, payload, TYPE_CANDIDATE_REGISTER)
                {
                    Ok(m) => m,
                    Err(_) => return false,
                };
                self.on_candidate_register(conn_id, peer, msg, tx);
                true
            }
            TYPE_PUNCH_RESULT => {
                let msg: PunchResult = match decode_extension(TYPE_PUNCH_RESULT, payload, TYPE_PUNCH_RESULT) {
                    Ok(m) => m,
                    Err(_) => return false,
                };
                let sid = msg.session_id;
                let ok = msg.ok;
                self.forward_to_other(conn_id, peer, TYPE_PUNCH_RESULT, payload, "punch_result");
                self.audit.record(TunnelAuditEvent::PunchForwarded {
                    client: peer,
                    device_id: format!(
                        "session {sid:02x?} result={}",
                        if ok { "ok" } else { "failed" }
                    ),
                });
                true
            }
            TYPE_PATH_PROBE | TYPE_PATH_PROBE_ACK => {
                let ok = if ty == TYPE_PATH_PROBE {
                    decode_extension::<PathProbe>(TYPE_PATH_PROBE, payload, TYPE_PATH_PROBE).is_ok()
                } else {
                    decode_extension::<PathProbeAck>(TYPE_PATH_PROBE_ACK, payload, TYPE_PATH_PROBE_ACK).is_ok()
                };
                if !ok {
                    return false;
                }
                self.forward_to_other(conn_id, peer, ty, payload, "path_probe");
                true
            }
            _ => {
                // 其余已知 type（P2 区/控制消息）→ 扩展点；未知 type 判死
                if let Some(ext) = &self.extension {
                    if let Some(reply) = ext.on_frame(ty, payload, peer, conn_id) {
                        let _ = tx.send(wrap_frame(ty, &reply));
                        return true;
                    }
                }
                false
            }
        }
    }

    /// CandidateRegister 处理（PUNCH-PROTO-001/002/007、PUNCH-006）。
    fn on_candidate_register(
        &self,
        conn_id: u64,
        peer: SocketAddr,
        msg: CandidateRegister,
        tx: &mpsc::UnboundedSender<Vec<u8>>,
    ) {
        // 安全审计 R-1：device_id 复用注册表校验（非空、≤128 字节、
        // 字母数字 + `:_-`）——此前无任何长度/字符集限制，超长 device_id
        // 直接进表/限速键，攻击者可撑爆内存与限速表。
        if !crate::registry::Registry::validate_device_id(&msg.device_id) {
            warn!("candidate register from {peer} rejected: invalid device_id");
            self.audit.record(TunnelAuditEvent::RateLimited {
                client: peer,
                reason: "invalid device_id".into(),
            });
            return;
        }
        if msg.candidates.len() > MAX_CANDIDATES {
            warn!(
                "candidate register from {} rejected: {} > {MAX_CANDIDATES} candidates",
                msg.device_id,
                msg.candidates.len()
            );
            self.audit.record(TunnelAuditEvent::RateLimited {
                client: peer,
                reason: "candidate overflow".into(),
            });
            return;
        }
        if !self.allow_rate(&msg.device_id, peer) {
            return;
        }

        // 附加服务器观察地址（PUNCH-PROTO-001：这是打洞关键信息）
        let mut candidates = msg.candidates.clone();
        candidates.insert(
            0,
            Candidate {
                addr: peer,
                kind: CandidateKind::Udp,
                priority: OBSERVED_PRIORITY,
            },
        );

        match msg.session_id {
            Some(sid) => {
                // P1 打洞：按 session 登记双端，齐 → 互转。
                // 同一连接重登记 = 候选刷新（PUNCH-004 重打洞：NAT 映射变化
                // 后重新候选交换，**更新**既有槽位，不当作第三端）。
                let mut sessions = self.sessions.lock().unwrap();
                // 安全审计 R-1：会话表硬上限——新 session 且表满时 LRU 淘汰
                // 最久未活跃会话（防唯一 session_id 撑爆 sessions 表）。
                if !sessions.contains_key(&sid) && sessions.len() >= MAX_RENDEZVOUS_SESSIONS {
                    if let Some(oldest) = sessions
                        .iter()
                        .min_by_key(|(_, s)| s.last_activity)
                        .map(|(k, _)| *k)
                    {
                        sessions.remove(&oldest);
                        warn!(
                            "rendezvous sessions table full ({MAX_RENDEZVOUS_SESSIONS}); \
                             evicted oldest {oldest:02x?}"
                        );
                    }
                }
                let session = sessions.entry(sid).or_default();
                session.last_activity = Instant::now();
                let is_refresh = session
                    .a
                    .as_ref()
                    .is_some_and(|s| s.conn_id == conn_id)
                    || session.b.as_ref().is_some_and(|s| s.conn_id == conn_id);
                if is_refresh {
                    let slot = session.slot_mut(conn_id).expect("refresh slot present");
                    slot.candidates = candidates;
                    slot.device_id = msg.device_id.clone();
                } else if session.a.is_none() {
                    session.a = Some(PeerSlot {
                        conn_id,
                        device_id: msg.device_id.clone(),
                        candidates,
                        tx: tx.clone(),
                    });
                } else if session.b.is_none() {
                    session.b = Some(PeerSlot {
                        conn_id,
                        device_id: msg.device_id.clone(),
                        candidates,
                        tx: tx.clone(),
                    });
                } else {
                    // 同 session 第三端 → 丢弃并审计（session 仅双端知晓）
                    warn!("session {sid:02x?} already has two peers; drop from {peer}");
                    self.audit.record(TunnelAuditEvent::PunchUnknownSession {
                        client: peer,
                        session_id: format!("{sid:02x?}"),
                    });
                    return;
                }
                if session.a.as_ref().is_some_and(|s| s.conn_id == conn_id) {
                    session.a_version += 1;
                } else if session.b.as_ref().is_some_and(|s| s.conn_id == conn_id) {
                    session.b_version += 1;
                }
                self.conn_session.lock().unwrap().insert(conn_id, sid);
                self.audit.record(TunnelAuditEvent::PunchCandidateRegistered {
                    client: peer,
                    device_id: msg.device_id.clone(),
                });

                // 竞态防护（PUNCH-004）：双端都刷新过才互转，杜绝旧候选
                let both_fresh = session.a.is_some()
                    && session.b.is_some()
                    && session.a_version > session.forwarded_version
                    && session.b_version > session.forwarded_version;
                if both_fresh {
                    session.forwarded_version = session.a_version.max(session.b_version);
                    // 互转（PUNCH-PROTO-003：不修改候选内容，仅含观察地址）。
                    // 通道承载**裸 bincode 负载**，writer task 负责加帧头。
                    let (a_tx, b_tx, b_cands, a_cands, a_id, b_id) = {
                        let s = session;
                        let a = s.a.as_ref().unwrap();
                        let b = s.b.as_ref().unwrap();
                        (a.tx.clone(), b.tx.clone(), b.candidates.clone(), a.candidates.clone(), a.device_id.clone(), b.device_id.clone())
                    };
                    drop(sessions);
                    let msg_a = PeerCandidates { session_id: sid, candidates: b_cands };
                    if let Ok(payload) = bincode::serialize(&msg_a) {
                        let _ = a_tx.send(wrap_frame(TYPE_PEER_CANDIDATES, &payload));
                    }
                    let msg_b = PeerCandidates { session_id: sid, candidates: a_cands };
                    if let Ok(payload) = bincode::serialize(&msg_b) {
                        let _ = b_tx.send(wrap_frame(TYPE_PEER_CANDIDATES, &payload));
                    }
                    info!("rendezvous session {sid:02x?} paired: {a_id} <-> {b_id}");
                    self.audit.record(TunnelAuditEvent::PunchForwarded {
                        client: peer,
                        device_id: msg.device_id,
                    });
                }
            }
            None => {
                // P2 ID-005 注册表候选刷新：仅存最新候选，不转发
                let mut dc = self.device_candidates.lock().unwrap();
                // 安全审计 R-1：表硬上限——满则淘汰任意键（本条路径为
                // 无消费方的候选刷新，保底防无限增长）。
                if !dc.contains_key(&msg.device_id) && dc.len() >= MAX_RENDEZVOUS_DEVICE_CANDIDATES
                {
                    if let Some(k) = dc.keys().next().cloned() {
                        dc.remove(&k);
                    }
                }
                dc.insert(msg.device_id, candidates);
                debug!("device candidate refresh from {peer}");
            }
        }
    }

    /// 按 conn→session 关联把帧转发给对端控制连接；未知 session → 丢弃 + 审计。
    fn forward_to_other(&self, conn_id: u64, peer: SocketAddr, ty: u8, payload: &[u8], what: &str) {
        let sid = self.conn_session.lock().unwrap().get(&conn_id).copied();
        let Some(sid) = sid else {
            self.audit.record(TunnelAuditEvent::PunchUnknownSession {
                client: peer,
                session_id: "unregistered-conn".into(),
            });
            return;
        };
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(&sid) else {
            drop(sessions);
            self.audit.record(TunnelAuditEvent::PunchUnknownSession {
                client: peer,
                session_id: format!("{sid:02x?}"),
            });
            return;
        };
        // 安全审计 R-1：会话活跃时间戳（LRU 淘汰依据）。
        session.last_activity = Instant::now();
        let Some(other) = session.other_slot(conn_id) else {
            drop(sessions);
            debug!("{what}: peer of {conn_id} not registered yet");
            return;
        };
        let tx = other.tx.clone();
        drop(sessions);
        if tx.send(wrap_frame(ty, payload)).is_err() {
            debug!("{what}: peer conn of {conn_id} closed");
        }
    }

    /// 限速（PUNCH-006：每设备每窗口 ≤ 上限；安全审计 R-1：另加每源 IP
    /// /24·/64 聚合限速 + 限速表键数硬上限）。超限 → 拒绝 + 审计。
    fn allow_rate(&self, device_id: &str, peer: SocketAddr) -> bool {
        let now = Instant::now();
        // 1. 设备级（键 = 自报 device_id——攻击者可旋转绕过，IP 级兜底见下）。
        {
            let mut rate = self.rate.lock().unwrap();
            // 表键数硬上限：满且为新键 → LRU 淘汰最久未活跃键。
            if !rate.contains_key(device_id) && rate.len() >= MAX_RENDEZVOUS_RATE_KEYS {
                if let Some(oldest) = rate
                    .iter()
                    .min_by_key(|(_, v)| v.last().copied())
                    .map(|(k, _)| k.clone())
                {
                    rate.remove(&oldest);
                }
            }
            let window = rate.entry(device_id.to_string()).or_default();
            window.retain(|t| now.duration_since(*t) < DEFAULT_PUNCH_RATE_WINDOW);
            if window.len() >= DEFAULT_PUNCH_RATE_LIMIT {
                warn!(
                    "rendezvous rate limit hit: {device_id} from {peer} \
                     (>{DEFAULT_PUNCH_RATE_LIMIT} per {DEFAULT_PUNCH_RATE_WINDOW:?})"
                );
                self.audit.record(TunnelAuditEvent::RateLimited {
                    client: peer,
                    reason: format!("punch rate limit: {device_id}"),
                });
                return false;
            }
            window.push(now);
        }
        // 2. 源 IP 级（/24·/64 聚合，复用 rate_limit::bucket_key；对齐 F-10
        //    语义）。device_id 旋转不再能绕过限速，跨租户 DoS 收口。
        //    先 canonical_ip 归一 v4-mapped（双栈监听下 IPv4 客户端呈
        //    `::ffff:` 形态，不归一将全部 IPv4 坍缩进同一桶——R-2 同类）。
        let ip_key =
            crate::rate_limit::bucket_key(crate::rate_limit::canonical_ip(peer.ip()));
        let mut ip_rate = self.ip_rate.lock().unwrap();
        if !ip_rate.contains_key(&ip_key) && ip_rate.len() >= MAX_RENDEZVOUS_RATE_KEYS {
            if let Some(oldest) = ip_rate
                .iter()
                .min_by_key(|(_, v)| v.last().copied())
                .map(|(k, _)| *k)
            {
                ip_rate.remove(&oldest);
            }
        }
        let window = ip_rate.entry(ip_key).or_default();
        window.retain(|t| now.duration_since(*t) < DEFAULT_IP_RATE_WINDOW);
        if window.len() >= DEFAULT_IP_RATE_LIMIT {
            warn!(
                "rendezvous IP rate limit hit: {peer} \
                 (>={DEFAULT_IP_RATE_LIMIT} per {DEFAULT_IP_RATE_WINDOW:?})"
            );
            self.audit.record(TunnelAuditEvent::RateLimited {
                client: peer,
                reason: "punch IP rate limit".into(),
            });
            return false;
        }
        window.push(now);
        true
    }

    /// 连接关闭清理：移除 conn→session 关联与会话槽（PUNCH-003 无状态残留）。
    fn cleanup_conn(&self, conn_id: u64) {
        let sid = self.conn_session.lock().unwrap().remove(&conn_id);
        if let Some(sid) = sid {
            let mut sessions = self.sessions.lock().unwrap();
            if let Some(session) = sessions.get_mut(&sid) {
                session.remove_conn(conn_id);
                if session.a.is_none() && session.b.is_none() {
                    sessions.remove(&sid);
                    debug!("rendezvous session {sid:02x?} released (conns gone)");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditSink;
    use crate::protocol::{
        encode_extension, Candidate, CandidateKind, ResolveDevice, TYPE_RESOLVE_DEVICE,
    };
    use std::sync::Mutex as StdMutex;
    use tokio::io::AsyncWriteExt;

    #[derive(Debug, Default)]
    struct Collect(StdMutex<Vec<TunnelAuditEvent>>);

    impl AuditSink for Collect {
        fn record(&self, event: TunnelAuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    fn candidates() -> Vec<Candidate> {
        vec![Candidate {
            addr: "127.0.0.1:9000".parse().unwrap(),
            kind: CandidateKind::Udp,
            priority: 100,
        }]
    }

    /// 测试用连接地址：`[::]` 监听器在本机不接受 v4 连接，且直接连 `[::]`
    /// 目标在无 IPv6 路由的 Windows 上失败（10049）——统一改写为 `[::1]` 回环。
    fn test_conn_addr(server: &RendezvousServer) -> SocketAddr {
        let mut addr = server.local_addr();
        if addr.ip().is_unspecified() {
            addr = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, addr.port()));
        }
        addr
    }

    /// 起服务端（默认 Noop 审计）+ 两个客户端连接，返回 (server, client_a, client_b)。
    async fn pair(_sid: [u8; 16]) -> (Arc<RendezvousServer>, TcpStream, TcpStream) {
        let server = Arc::new(RendezvousServer::bind(0).await.unwrap());
        let addr = test_conn_addr(&server);
        let a = TcpStream::connect(addr).await.unwrap();
        let b = TcpStream::connect(addr).await.unwrap();
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(watch::channel(false).1).await;
        });
        (server, a, b)
    }

    #[tokio::test]
    async fn test_candidate_exchange_forwards_observed() {
        // PUNCH-PROTO-001/003：双端登记 → 互转候选（含服务器观察地址）
        let (_server, mut a, mut b) = pair([1; 16]).await;
        let a_peer = a.local_addr().unwrap();
        let b_peer = b.local_addr().unwrap();

        let reg_a = CandidateRegister {
            device_id: "dev-a".into(),
            session_id: Some([1; 16]),
            candidates: candidates(),
        };
        let reg_b = CandidateRegister {
            device_id: "dev-b".into(),
            session_id: Some([1; 16]),
            candidates: candidates(),
        };
        a.write_all(&encode_extension(TYPE_CANDIDATE_REGISTER, &reg_a).unwrap())
            .await
            .unwrap();
        b.write_all(&encode_extension(TYPE_CANDIDATE_REGISTER, &reg_b).unwrap())
            .await
            .unwrap();

        // 双端各自收到对端候选
        let (ty_a, payload_a) = read_frame(&mut a).await.unwrap();
        let (ty_b, payload_b) = read_frame(&mut b).await.unwrap();
        assert_eq!(ty_a, TYPE_PEER_CANDIDATES);
        assert_eq!(ty_b, TYPE_PEER_CANDIDATES);
        let pc_a: PeerCandidates = decode_extension(TYPE_PEER_CANDIDATES, &payload_a, TYPE_PEER_CANDIDATES).unwrap();
        let pc_b: PeerCandidates = decode_extension(TYPE_PEER_CANDIDATES, &payload_b, TYPE_PEER_CANDIDATES).unwrap();
        assert_eq!(pc_a.session_id, [1; 16]);

        // 观察地址已附加：服务器视角的 TCP 对端地址
        assert!(pc_a.candidates.iter().any(|c| c.addr == b_peer), "A 应收到 B 的观察地址");
        assert!(pc_b.candidates.iter().any(|c| c.addr == a_peer), "B 应收到 A 的观察地址");
        assert!(pc_a.candidates.iter().any(|c| c.addr == "127.0.0.1:9000".parse().unwrap()));
        // 互转不修改候选内容（本地候选仍在）
        assert!(pc_a.candidates.iter().any(|c| c.priority == 100));
        assert!(pc_a.candidates.iter().any(|c| c.priority == OBSERVED_PRIORITY));
    }

    #[tokio::test]
    async fn test_punch_result_and_path_probe_forwarded() {
        // PUNCH-PROTO-005/006：结果与路径探测透传对端
        let (_server, mut a, mut b) = pair([2; 16]).await;
        let reg = |dev: &str| CandidateRegister {
            device_id: dev.into(),
            session_id: Some([2; 16]),
            candidates: candidates(),
        };
        a.write_all(&encode_extension(TYPE_CANDIDATE_REGISTER, &reg("dev-a")).unwrap())
            .await
            .unwrap();
        b.write_all(&encode_extension(TYPE_CANDIDATE_REGISTER, &reg("dev-b")).unwrap())
            .await
            .unwrap();
        // 消费互转帧
        let _ = read_frame(&mut a).await.unwrap();
        let _ = read_frame(&mut b).await.unwrap();

        // A → 服务器 → B：PunchResult
        let result = PunchResult {
            session_id: [2; 16],
            ok: true,
            path: Some(CandidateKind::Udp),
        };
        a.write_all(&encode_extension(TYPE_PUNCH_RESULT, &result).unwrap())
            .await
            .unwrap();
        let (ty, payload) = read_frame(&mut b).await.unwrap();
        assert_eq!(ty, TYPE_PUNCH_RESULT);
        assert_eq!(
            decode_extension::<PunchResult>(TYPE_PUNCH_RESULT, &payload, TYPE_PUNCH_RESULT).unwrap(),
            result
        );

        // B → 服务器 → A：PathProbe
        let probe = PathProbe { path_id: 1, ts_ms: 123 };
        b.write_all(&encode_extension(TYPE_PATH_PROBE, &probe).unwrap())
            .await
            .unwrap();
        let (ty, payload) = read_frame(&mut a).await.unwrap();
        assert_eq!(ty, TYPE_PATH_PROBE);
        assert_eq!(
            decode_extension::<PathProbe>(TYPE_PATH_PROBE, &payload, TYPE_PATH_PROBE).unwrap(),
            probe
        );
    }

    #[tokio::test]
    async fn test_unknown_session_dropped_and_audited() {
        // PUNCH-SEC-003：未知 session_id → 丢弃 + 审计；连接不判死
        let audit = Arc::new(Collect::default());
        let server = Arc::new(
            RendezvousServer::bind(0)
                .await
                .unwrap()
                .with_audit(Arc::clone(&audit) as Arc<dyn AuditSink>),
        );
        let addr = test_conn_addr(&server);
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(watch::channel(false).1).await;
        });
        let mut c = TcpStream::connect(addr).await.unwrap();

        // 未登记会话的结果上报 → 丢弃（无响应）；连接仍存活
        let result = PunchResult {
            session_id: [99; 16],
            ok: true,
            path: None,
        };
        c.write_all(&encode_extension(TYPE_PUNCH_RESULT, &result).unwrap())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 连接未被判死：再发登记帧仍被受理（服务端不回，靠审计断言）
        let reg = CandidateRegister {
            device_id: "dev-x".into(),
            session_id: Some([99; 16]),
            candidates: candidates(),
        };
        c.write_all(&encode_extension(TYPE_CANDIDATE_REGISTER, &reg).unwrap())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let events = audit.0.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TunnelAuditEvent::PunchUnknownSession { .. })),
            "unknown session should be audited"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_per_device() {
        // PUNCH-006：每设备每 5s ≤ 10 次候选交换；第 11 次拒绝 + 审计
        let audit = Arc::new(Collect::default());
        let server = Arc::new(
            RendezvousServer::bind(0)
                .await
                .unwrap()
                .with_audit(Arc::clone(&audit) as Arc<dyn AuditSink>),
        );
        let addr = test_conn_addr(&server);
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(watch::channel(false).1).await;
        });
        let mut c = TcpStream::connect(addr).await.unwrap();

        for i in 0..DEFAULT_PUNCH_RATE_LIMIT + 1 {
            let reg = CandidateRegister {
                device_id: "dev-ratelimit".into(),
                session_id: Some([i as u8; 16]),
                candidates: candidates(),
            };
            c.write_all(&encode_extension(TYPE_CANDIDATE_REGISTER, &reg).unwrap())
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        let events = audit.0.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TunnelAuditEvent::RateLimited { .. })),
            "11th registration should be rate limited"
        );
    }

    // 安全审计 R-1：非法 device_id（空/含空白/超长）→ 拒绝 + 审计，不建会话。
    #[tokio::test]
    async fn test_invalid_device_id_rejected() {
        let audit = Arc::new(Collect::default());
        let server = Arc::new(
            RendezvousServer::bind(0)
                .await
                .unwrap()
                .with_audit(Arc::clone(&audit) as Arc<dyn AuditSink>),
        );
        let addr = test_conn_addr(&server);
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(watch::channel(false).1).await;
        });
        let mut c = TcpStream::connect(addr).await.unwrap();
        for bad in ["", "has space", &"x".repeat(200)] {
            let reg = CandidateRegister {
                device_id: bad.to_string(),
                session_id: Some([9; 16]),
                candidates: candidates(),
            };
            c.write_all(&encode_extension(TYPE_CANDIDATE_REGISTER, &reg).unwrap())
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        let events = audit.0.lock().unwrap();
        let rate_limited = events
            .iter()
            .filter(|e| matches!(e, TunnelAuditEvent::RateLimited { .. }))
            .count();
        assert!(rate_limited >= 3, "3 个非法 device_id 均应被拒: {rate_limited}");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TunnelAuditEvent::PunchCandidateRegistered { .. })),
            "非法 device_id 不得登记会话"
        );
    }

    // 安全审计 R-1：每源 IP（/24·/64 聚合）限速——唯一 device_id 旋转
    // 不能绕过 IP 级限速；第 (DEFAULT_IP_RATE_LIMIT+1) 次登记被拒 + 审计。
    #[tokio::test]
    async fn test_source_ip_rate_limit() {
        let audit = Arc::new(Collect::default());
        let server = Arc::new(
            RendezvousServer::bind(0)
                .await
                .unwrap()
                .with_audit(Arc::clone(&audit) as Arc<dyn AuditSink>),
        );
        let addr = test_conn_addr(&server);
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(watch::channel(false).1).await;
        });
        let mut c = TcpStream::connect(addr).await.unwrap();
        for i in 0..DEFAULT_IP_RATE_LIMIT + 1 {
            let reg = CandidateRegister {
                device_id: format!("dev-ip-{i}"),
                session_id: None,
                candidates: candidates(),
            };
            c.write_all(&encode_extension(TYPE_CANDIDATE_REGISTER, &reg).unwrap())
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let events = audit.0.lock().unwrap();
        let rate_limited = events
            .iter()
            .filter(|e| matches!(e, TunnelAuditEvent::RateLimited { .. }))
            .count();
        assert!(
            rate_limited >= 1,
            "第 {} 次登记应触发源 IP 限速: {rate_limited}",
            DEFAULT_IP_RATE_LIMIT + 1
        );
    }

    #[tokio::test]
    async fn test_extension_hook() {
        // 扩展点：P2 的 Login/ResolveDevice 挂载（punch 帧不进入扩展点）
        use std::sync::atomic::AtomicUsize;

        #[derive(Debug)]
        struct Ext(AtomicUsize);

        impl RendezvousExtension for Ext {
            fn on_frame(
                &self,
                kind: u8,
                payload: &[u8],
                _peer: SocketAddr,
                _conn_id: u64,
            ) -> Option<Vec<u8>> {
                if kind == TYPE_CANDIDATE_REGISTER {
                    return None; // punch 帧由服务端自己处理
                }
                self.0.fetch_add(1, Ordering::Relaxed);
                Some(payload.to_vec())
            }
        }

        let ext = Arc::new(Ext(AtomicUsize::new(0)));
        let server = Arc::new(
            RendezvousServer::bind(0)
                .await
                .unwrap()
                .with_extension(Arc::clone(&ext) as Arc<dyn RendezvousExtension>),
        );
        let addr = test_conn_addr(&server);
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(watch::channel(false).1).await;
        });
        let mut c = TcpStream::connect(addr).await.unwrap();

        // 0x80（P2 ResolveDevice 区）→ 扩展点应答（同一帧类型回显）
        let request = ResolveDevice { device_id: "pc-a".into() };
        c.write_all(&encode_extension(TYPE_RESOLVE_DEVICE, &request).unwrap())
            .await
            .unwrap();
        let (ty, payload) = read_frame(&mut c).await.unwrap();
        assert_eq!(ty, TYPE_RESOLVE_DEVICE);
        assert_eq!(
            decode_extension::<ResolveDevice>(TYPE_RESOLVE_DEVICE, &payload, TYPE_RESOLVE_DEVICE).unwrap(),
            request
        );

        // CandidateRegister（punch 帧）不应进入扩展点
        let reg = CandidateRegister {
            device_id: "dev-y".into(),
            session_id: Some([5; 16]),
            candidates: candidates(),
        };
        c.write_all(&encode_extension(TYPE_CANDIDATE_REGISTER, &reg).unwrap())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(ext.0.load(Ordering::Relaxed), 1);
    }
}
