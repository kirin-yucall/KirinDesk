//!
//! # 架构（PM 裁定）
//!
//! - **每会话 1 个文件会话任务**（挂 `crate::runtime()` 全局 runtime）：驱动
//!   `SlideWindowSender`/`ChunkReceiver` 状态机（全部在
//!   `core::connection::file_transfer`，零自研）+ 双 `TransferScheduler`
//!   （并发 ≤3 / 队列 ≤128，直接复用 core）。
//! - **收帧任务 = 会话既有接收循环的 0x06 分支**：`SecureChannel` 读半唯一，
//!   不能另立收帧任务；会话接收循环 `tag == ChannelTag::FileTransfer` →
//!   `FileTransferFrame::decode` → mpsc 送文件会话任务（生产接线在
//!   [`crate::orchestration::run_session`] 与 [`crate::server::run_viewer_session`]）。
//! - **单 writer**：与视频/输入发送共用会话既有
//!   `Arc<tokio::sync::Mutex<SecureChannelSender>>`；64 KiB 大帧走
//!   `send_big_packet`（同桌面 `file_packet` 口径）。
//! - **salt** = 排序拼接([本端 `public_key_base64`, `channel.peer_id`])——
//!   与桌面 `ui::file_transfer_salt` 同口径（接收侧从不重算 transfer_id，
//!   取帧内 tid；sender 侧盐稳定 = 同文件跨重连 tid 稳定 = 双端断点可寻址）。
//! - **断点持久化** `transfers_{role}.json` 落 `KIRIN_DATA_DIR`（utils
//!   `config_dir`，env 覆盖）：建链 load（`prune_missing` 清孤儿）、
//!   事件/tick save；**断连即清理按断点口径**——保留 `.part` 与断点记录
//!   供重连续传（同桌面会话退出语义），不删用户数据。
//!
//! # 驱动纪律（PM 裁定 4）
//!
//! core 状态机自身**不**门控 Accept 前取号（`next_unsent_seq` 构造即可用）——
//! 本层驱动显式持 `accepted` 集：收到对端 Accept 帧前绝不发 Data 帧
//! （`fill_window`/`on_tick` 补窗均先查该集）。
//!
//! # 接收侧用户门控（移动端与桌面的差异点）
//!
//! 桌面 GUI 自动 Accept；移动端 Offer 先进 `OfferPending` 队列（≤128，
//! 超限 Reject），等用户经 [`FileTransferHandle::respond_offer`] 决定
//! （B2 岗 JNI 把 Kotlin 给的落盘目录作为入参传入）。**目录不可用/不存在 →
//! 结构化错误 fail-closed，不静默换目录**（Offer 保持 pending，可用合法目录
//! 重试）。
//!
//! # 对 B2 岗（JNI 薄封装）的 API 面
//!
//! [`spawn_session`]（会话装配）+ [`FileTransferHandle`] 四语义：
//! `start_send` / `respond_offer` / `cancel` / `snapshot`。

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kirin_desk_core::connection::file_transfer::{
    block_len, block_offset, derive_transfer_id, sha256_file, validate_block_count,
    ChunkReceiver, FileOfferMeta, FileOp, FileTransferFrame, SlideWindowSender, StoredTransfer,
    TransferScheduler, TransferStore, MAX_QUEUE_LEN,
};
use kirin_desk_core::connection::file_transfer::TransferStatus as CoreStatus;
use kirin_desk_media::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use kirin_desk_media::transport::SecureChannelSender;

// ════════════════════════════════════════════════════════════════
// 基础封装（同桌面口径）
// ════════════════════════════════════════════════════════════════

/// 构造 FileTransfer 帧 `EncodedPacket`（64 KiB 大帧，走 `send_big_packet`）。
/// 同桌面 `ui::file_packet`：`PacketKind::FileTransfer` → wire tag 0x06。
pub(crate) fn file_packet(frame: &FileTransferFrame) -> EncodedPacket {
    EncodedPacket {
        ts: Timestamp::now(),
        kind: PacketKind::FileTransfer,
        data: frame.encode().unwrap_or_default(),
        is_key: false,
    }
}

/// 会话盐（桌面 `ui::file_transfer_salt` 同口径：两端 ID 排序拼接，与计算方
/// 无关）——`my_id` = 本端 `public_key_base64`，`peer_id` = `channel.peer_id`
/// （对端握手自报 ID）。
pub fn session_salt(my_id: &str, peer_id: &str) -> String {
    let mut parts = [my_id.to_string(), peer_id.to_string()];
    parts.sort();
    parts.concat()
}

/// 断点存储路径（`transfers_{role}.json`，双端分文件——同一台设备同时充当
/// 控制端/被控端时不互相覆盖；`role` = "client" / "server"）。
/// 落 `KIRIN_DATA_DIR`（utils `config_dir`，Android 上 = Kotlin `getFilesDir()` 体系）。
pub fn store_path(role: &str) -> PathBuf {
    kirin_desk_utils::config::Config::config_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(format!("transfers_{role}.json"))
}

// ════════════════════════════════════════════════════════════════
// 对外类型（B2 岗 JNI 薄封装的唯一输入）
// ════════════════════════════════════════════════════════════════

/// 传输方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// 本端发出（推文件给对方）。
    Send,
    /// 本端接收（对方推来，落盘本端目录）。
    Recv,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Send => "send",
            Direction::Recv => "recv",
        }
    }
}

/// 任务状态（snapshot 展示；终态 `Failed`/`Cancelled` 带 `reason`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// 发送排队（并发槽未满 3 前不发 Offer）。
    Queued,
    /// Offer 已发，等对端 Accept（驱动门控：期间不发数据块）。
    WaitingAccept,
    /// 入站 Offer 等待用户决定（B2 UI 弹框；`respond_offer` 决断）。
    OfferPending,
    /// 发送中（滑窗在途）。
    Sending,
    /// 接收中（分片落 `.part`）。
    Receiving,
    Completed,
    Failed,
    Cancelled,
}

impl TransferState {
    pub fn as_str(self) -> &'static str {
        match self {
            TransferState::Queued => "queued",
            TransferState::WaitingAccept => "waiting_accept",
            TransferState::OfferPending => "offer_pending",
            TransferState::Sending => "sending",
            TransferState::Receiving => "receiving",
            TransferState::Completed => "completed",
            TransferState::Failed => "failed",
            TransferState::Cancelled => "cancelled",
        }
    }
}

/// snapshot 条目（B2 序列化为 JSON 上抛 Kotlin；字段即建议 JSON 字段）。
#[derive(Debug, Clone)]
pub struct TransferEntry {
    /// 传输 ID（`hash(文件名|大小|盐)`；双端一致，断点键）。
    pub transfer_id: u64,
    /// 文件名（接收侧已消毒后的目标名）。
    pub name: String,
    pub direction: Direction,
    /// 文件总字节数。
    pub size: u64,
    /// 已完成字节数（发送 = 已确认；接收 = 已连续落盘）。
    pub done: u64,
    pub state: TransferState,
    /// 速度（字节/秒；仅活跃任务有意义）。
    pub speed: f64,
    /// 原因（`Failed`/`Cancelled`；其余为空串）。
    pub reason: String,
    /// 最终落盘路径（接收侧完成时；其余 None）。
    pub path: Option<String>,
}

// ════════════════════════════════════════════════════════════════
// 会话句柄（JNI-safe：Send + Sync，全部同步方法，不涉 runtime）
// ════════════════════════════════════════════════════════════════

enum Command {
    StartSend { path: PathBuf },
    RespondOffer {
        transfer_id: u64,
        accept: bool,
        target_dir: PathBuf,
    },
    Cancel { transfer_id: u64 },
}

/// 每会话文件传输句柄（会话生命周期持有；B2 岗 JNI 四语义薄封装）。
///
/// - [`start_send`](Self::start_send)：发本地文件（控制端推/被控端推均可——
///   双向语义）；
/// - [`respond_offer`](Self::respond_offer)：入站 Offer 的用户决定（接受 →
///   落 `target_dir`；拒绝 → Reject 帧）；
/// - [`cancel`](Self::cancel)：本地取消（发 Cancel 帧 + 回滚，删 `.part`）；
/// - [`snapshot`](Self::snapshot)：任务表快照（同步读，零 runtime 参与）。
#[derive(Clone)]
pub struct FileTransferHandle {
    cmd_tx: tokio::sync::mpsc::UnboundedSender<Command>,
    entries: Arc<Mutex<Vec<TransferEntry>>>,
}

impl FileTransferHandle {
    /// 发送本地文件（排队 → Offer → Accept → 滑窗 64 块 → Finish → FinishAck）。
    ///
    /// 同步 fail-closed 预检：文件不可达/非常规文件 → 结构化错误。
    /// 调度级拒绝（重复在途/超大小/SHA-256 失败/队列满 128）经 snapshot
    /// 以 `Failed` 条目呈现（含 reason）。
    pub fn start_send(&self, path: impl Into<PathBuf>) -> Result<(), String> {
        let path = path.into();
        match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => {}
            Ok(_) => {
                return Err(format!("not a regular file: {}", path.display()));
            }
            Err(e) => {
                return Err(format!("file not accessible: {}: {e}", path.display()));
            }
        }
        self.cmd_tx
            .send(Command::StartSend { path })
            .map_err(|_| "file session closed".to_string())
    }

    /// 入站 Offer 的用户决定。
    ///
    /// `accept = true`：开始接收，落 `target_dir`（**必须是已存在的目录**——
    /// 不存在/非目录 → 结构化错误，Offer 保持 pending 可用合法目录重试；
    /// fail-closed 不静默换目录，不自动建目录）。
    /// `accept = false`：发 Reject（"declined by user"），任务终止。
    pub fn respond_offer(
        &self,
        transfer_id: u64,
        accept: bool,
        target_dir: impl Into<PathBuf>,
    ) -> Result<(), String> {
        let target_dir = target_dir.into();
        if accept && !target_dir.is_dir() {
            return Err(format!(
                "target directory unavailable (missing or not a dir): {}",
                target_dir.display()
            ));
        }
        self.cmd_tx
            .send(Command::RespondOffer {
                transfer_id,
                accept,
                target_dir,
            })
            .map_err(|_| "file session closed".to_string())
    }

    /// 本地取消：发送侧 → Cancel 帧 + 回滚；接收侧 → Cancel 帧 + 删 `.part`。
    /// 未知 tid（已完成/已清理）→ 无操作（调用方以 snapshot 为准）。
    pub fn cancel(&self, transfer_id: u64) -> Result<(), String> {
        self.cmd_tx
            .send(Command::Cancel { transfer_id })
            .map_err(|_| "file session closed".to_string())
    }

    /// 任务表快照（同步；含活跃任务 + 近期终态缓存 ≤64 条）。
    pub fn snapshot(&self) -> Vec<TransferEntry> {
        self.entries.lock().unwrap().clone()
    }
}

/// `nativeGetFileTransfers` 返回体；宿主机可单测——jni.rs 仅 android target
/// 编译，故序列化放本模块；`pub` = 宿主机 rlib 单测与 android JNI 共用，
/// 免 dead_code 告警）。
///
/// **格式定稿（一经定稿不得变）**：字段集（恒 9 字段全在，无缺省省略）
/// `transfer_id,name,direction,size,done,state,speed,reason,path`——
/// **键序 = serde_json 确定性字母序**（BTreeMap 底层，跨版本稳定；Kotlin
/// `org.json` 解析与键序无关）：
/// `direction,done,name,path,reason,size,speed,state,transfer_id`；
/// `direction`/`state` = `as_str` 值；`reason` 恒在（非失败/取消条目为空串）；
/// `path` = None 输出 `null`；`speed` 非有限值 → 0.0（fail-closed 不产出
/// 非法 JSON）；空表 = `[]`。转义交 serde_json（`"`/`\`/控制字符/unicode
/// 均合法 JSON 文本）。
pub fn transfers_json(entries: &[TransferEntry]) -> String {
    let arr: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let speed = if e.speed.is_finite() { e.speed } else { 0.0 };
            serde_json::json!({
                "transfer_id": e.transfer_id,
                "name": e.name,
                "direction": e.direction.as_str(),
                "size": e.size,
                "done": e.done,
                "state": e.state.as_str(),
                "speed": speed,
                "reason": e.reason,
                "path": e.path,
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
}

// ════════════════════════════════════════════════════════════════
// 会话装配
// ════════════════════════════════════════════════════════════════

/// 装配并 spawn 本会话的文件传输会话（调用方：会话接收循环建立后）。
///
/// 返回（句柄, 收帧馈送端）：会话接收循环在 `tag == 0x06` 分支
/// `FileTransferFrame::decode` 成功后 `frame_tx.send(frame)`（decode 失败记
/// warn 丢弃——坏帧不断会话）。会话任务在 `frame_tx` 被 drop（接收循环
/// 退出 = 断连）或句柄全部 drop 时退出，退出前按断点口径 save。
///
/// `role` = "client"（控制端）/ "server"（被控端）——仅决定断点文件名
/// `transfers_{role}.json`；`max_file_size` = Offer 阶段单文件上限
/// （fail-closed Reject）。
pub fn spawn_session(
    rt: &tokio::runtime::Runtime,
    sender: Arc<tokio::sync::Mutex<SecureChannelSender>>,
    salt: String,
    role: &'static str,
    max_file_size: u64,
) -> (FileTransferHandle, tokio::sync::mpsc::UnboundedSender<FileTransferFrame>) {
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Command>();
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<FileTransferFrame>();
    let entries: Arc<Mutex<Vec<TransferEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let handle_entries = entries.clone();
    rt.spawn(async move {
        let mut eng = Engine::new(sender, salt, store_path(role), max_file_size, entries);
        // 建链 load：断点 store 载入 + 孤儿记录清理（.part 已不在 → 删记录）。
        eng.load_store();
        eng.sync_entries();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else {
                        // 全部句柄 drop（会话句柄表移除）→ 退出。
                        break;
                    };
                    eng.handle_command(cmd).await;
                }
                frame = frame_rx.recv() => {
                    let Some(frame) = frame else {
                        // 接收循环退出（断连）→ 退出。
                        break;
                    };
                    eng.handle_frame(frame).await;
                }
                _ = tick.tick() => eng.on_tick().await,
            }
        }
        // 会话结束：断点口径（保留 .part 与记录，供重连续传；同桌面）。
        eng.cleanup_on_exit();
        tracing::info!("mobile file: session task exited (role={role})");
    });
    (
        FileTransferHandle {
            cmd_tx,
            entries: handle_entries,
        },
        frame_tx,
    )
}

// ════════════════════════════════════════════════════════════════
// 引擎（会话任务独占；镜像桌面 ui::FileSession 驱动逻辑）
// ════════════════════════════════════════════════════════════════

/// 终态条目缓存上限（snapshot 近期可查；FIFO 淘汰）。
const FINISHED_KEEP: usize = 64;

struct Engine {
    sender: Arc<tokio::sync::Mutex<SecureChannelSender>>,
    salt: String,
    store_path: PathBuf,
    max_file_size: u64,
    entries: Arc<Mutex<Vec<TransferEntry>>>,
    // ── 发送侧 ──
    send_sched: TransferScheduler<u64>,
    senders: HashMap<u64, SlideWindowSender>,
    src_files: HashMap<u64, std::fs::File>,
    /// 发送排队 tid（`send_sched` 无成员查询接口，镜像一份）。
    send_queued: HashSet<u64>,
    /// Offer 帧已发。
    offered: HashSet<u64>,
    /// 对端 Accept 已收（**驱动门控**：集合内才允许发 Data 块）。
    accepted: HashSet<u64>,
    // ── 接收侧 ──
    /// 待用户决定的 Offer（≤ [`MAX_QUEUE_LEN`]，超限 Reject）。
    pending_offers: HashMap<u64, (FileOfferMeta, [u8; 32])>,
    /// 已接受、等并发槽（`recv_sched` 队列内；tid → (meta, 整文件 sha)——
    /// begin 所需材料在 accept 时一次性取齐，不再依赖 pending_offers）。
    recv_queued: HashMap<u64, (FileOfferMeta, [u8; 32])>,
    /// tid → 用户给的落盘目录（accept 时入，start 时出）。
    recv_dirs: HashMap<u64, PathBuf>,
    recv_sched: TransferScheduler<u64>,
    receivers: HashMap<u64, ChunkReceiver>,
    /// 已取消 tid（忽略后续帧/跳过排队启动；会话级，量小不清理）。
    cancelled: HashSet<u64>,
    // ── 终态缓存 ──
    finished: Vec<(u64, TransferEntry)>,
}

impl Engine {
    fn new(
        sender: Arc<tokio::sync::Mutex<SecureChannelSender>>,
        salt: String,
        store_path: PathBuf,
        max_file_size: u64,
        entries: Arc<Mutex<Vec<TransferEntry>>>,
    ) -> Self {
        Self {
            sender,
            salt,
            store_path,
            max_file_size,
            entries,
            send_sched: TransferScheduler::new(),
            senders: HashMap::new(),
            src_files: HashMap::new(),
            send_queued: HashSet::new(),
            offered: HashSet::new(),
            accepted: HashSet::new(),
            pending_offers: HashMap::new(),
            recv_queued: HashMap::new(),
            recv_dirs: HashMap::new(),
            recv_sched: TransferScheduler::new(),
            receivers: HashMap::new(),
            cancelled: HashSet::new(),
            finished: Vec::new(),
        }
    }

    // ── 断点存储（同桌面 save_store 读改写模式；store 很小，全量读写） ──

    fn load_store(&self) {
        let mut store = match TransferStore::load_from(&self.store_path) {
            Ok(s) => s,
            Err(_) => TransferStore::new(), // 首次/无文件：空 store
        };
        store.prune_missing();
        if let Err(e) = store.save_to(&self.store_path) {
            tracing::warn!("mobile file: store load/save failed: {e}");
        }
    }

    fn save_store(&self, f: impl FnOnce(&mut TransferStore)) {
        let mut store =
            TransferStore::load_from(&self.store_path).unwrap_or_default();
        f(&mut store);
        if let Err(e) = store.save_to(&self.store_path) {
            tracing::warn!("mobile file: transfers store save failed: {e}");
        }
    }

    // ── 帧发送（共享单 writer；64 KiB 大帧走 send_big_packet） ──

    async fn send_frame(&self, frame: FileTransferFrame) -> bool {
        let pkt = file_packet(&frame);
        match self.sender.lock().await.send_big_packet(&pkt).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("mobile file: frame send failed: {e}");
                false
            }
        }
    }

    async fn send_reject(&self, tid: u64, reason: &str) {
        let mut rej = FileTransferFrame::simple(tid, FileOp::Reject, 0);
        rej.data = reason.as_bytes().to_vec();
        let _ = self.send_frame(rej).await;
    }

    // ── snapshot 同步 ──

    fn mk_entry(
        tid: u64,
        name: String,
        direction: Direction,
        size: u64,
        state: TransferState,
        reason: impl Into<String>,
    ) -> TransferEntry {
        TransferEntry {
            transfer_id: tid,
            name,
            direction,
            size,
            done: 0,
            state,
            speed: 0.0,
            reason: reason.into(),
            path: None,
        }
    }

    fn sync_entries(&self) {
        let mut v: Vec<TransferEntry> = Vec::with_capacity(
            self.senders
                .len()
                + self.receivers
                    .len()
                    + self.pending_offers
                    .len()
                    + self.recv_queued
                    .len()
                + self.finished
                    .len(),
        );
        for (tid, s) in &self.senders {
            let state = if !self.offered.contains(tid) {
                TransferState::Queued
            } else if !self.accepted.contains(tid) {
                TransferState::WaitingAccept
            } else {
                TransferState::Sending
            };
            v.push(TransferEntry {
                transfer_id: *tid,
                name: s.name.clone(),
                direction: Direction::Send,
                size: s.size,
                done: s.acked_bytes(),
                state,
                speed: s.speed(),
                reason: String::new(),
                path: None,
            });
        }
        for (tid, (meta, _)) in &self.pending_offers {
            v.push(Self::mk_entry(
                *tid,
                meta.name.clone(),
                Direction::Recv,
                meta.size,
                TransferState::OfferPending,
                String::new(),
            ));
        }
        for (tid, (meta, _)) in &self.recv_queued {
            v.push(Self::mk_entry(
                *tid,
                meta.name.clone(),
                Direction::Recv,
                meta.size,
                TransferState::Queued,
                String::new(),
            ));
        }
        for (tid, r) in &self.receivers {
            let (done, _) = r.progress();
            v.push(TransferEntry {
                transfer_id: *tid,
                name: r.name.clone(),
                direction: Direction::Recv,
                size: r.size,
                done,
                state: TransferState::Receiving,
                speed: 0.0,
                reason: String::new(),
                path: Some(r.target_path().to_string_lossy().to_string()),
            });
        }
        for (_, e) in &self.finished {
            v.push(e.clone());
        }
        *self.entries.lock().unwrap() = v;
    }

    fn note_finished(&mut self, e: TransferEntry) {
        self.finished.retain(|(t, _)| *t != e.transfer_id);
        self.finished.push((e.transfer_id, e));
        if self.finished.len() > FINISHED_KEEP {
            self.finished.remove(0);
        }
        self.sync_entries();
    }

    // ── 清理 ──

    fn cleanup_task(&mut self, tid: u64) {
        self.senders.remove(&tid);
        self.src_files.remove(&tid);
        self.send_queued.remove(&tid);
        self.offered.remove(&tid);
        self.accepted.remove(&tid);
        self.receivers.remove(&tid);
        self.recv_dirs.remove(&tid);
        self.recv_queued.remove(&tid);
        self.pending_offers.remove(&tid);
    }

    /// 会话退出（断连/句柄 drop）：断点口径——活跃任务进度存 store；
    /// `.part` 保留（`ChunkReceiver::drop` 不删 = 重连续传口径，同桌面）。
    fn cleanup_on_exit(&self) {
        self.save_store(|st| {
            for (tid, s) in &self.senders {
                if let Some(t) = st.find_mut(*tid) {
                    t.next_seq = s.resume_seq();
                }
            }
            for (tid, r) in &self.receivers {
                if let Some(t) = st.find_mut(*tid) {
                    t.next_seq = r.next_seq();
                }
            }
        });
    }

    // ── 命令（B2 四语义之 start_send/respond_offer/cancel） ──

    async fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::StartSend { path } => self.cmd_start_send(path).await,
            Command::RespondOffer {
                transfer_id,
                accept,
                target_dir,
            } => self
                .cmd_respond_offer(transfer_id, accept, target_dir)
                .await,
            Command::Cancel { transfer_id } => self.cmd_cancel(transfer_id).await,
        }
    }

    async fn cmd_start_send(&mut self, path: PathBuf) {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.is_empty() {
            return;
        }
        let size = match std::fs::metadata(&path).ok().filter(|m| m.is_file()).map(|m| m.len()) {
            Some(s) => s,
            None => {
                let tid = derive_transfer_id(&name, 0, &self.salt);
                self.note_finished(Self::mk_entry(
                    tid,
                    name,
                    Direction::Send,
                    0,
                    TransferState::Failed,
                    format!("file not accessible: {}", path.display()),
                ));
                return;
            }
        };
        let tid = derive_transfer_id(&name, size, &self.salt);
        if size > self.max_file_size {
            self.note_finished(Self::mk_entry(
                tid,
                name,
                Direction::Send,
                size,
                TransferState::Failed,
                format!("file too large: {size} bytes (max {})", self.max_file_size),
            ));
            return;
        }
        // 重复在途（活跃/排队）→ 结构化拒绝（snapshot 可见，不静默覆盖）。
        if self.senders.contains_key(&tid) || self.send_queued.contains(&tid) {
            self.note_finished(Self::mk_entry(
                tid,
                name,
                Direction::Send,
                size,
                TransferState::Failed,
                "already in progress",
            ));
            return;
        }
        // 整文件 SHA-256（阻塞计算移出 runtime 工作线程）。
        let sha_path = path.clone();
        let sha = match tokio::task::spawn_blocking(move || sha256_file(&sha_path)).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                self.note_finished(Self::mk_entry(
                    tid,
                    name,
                    Direction::Send,
                    size,
                    TransferState::Failed,
                    format!("sha256: {e}"),
                ));
                return;
            }
            Err(e) => {
                self.note_finished(Self::mk_entry(
                    tid,
                    name,
                    Direction::Send,
                    size,
                    TransferState::Failed,
                    format!("sha256 task: {e}"),
                ));
                return;
            }
        };
        let mut s = match SlideWindowSender::new(tid, name.clone(), size, sha) {
            Ok(s) => s,
            Err(e) => {
                self.note_finished(Self::mk_entry(
                    tid,
                    name,
                    Direction::Send,
                    size,
                    TransferState::Failed,
                    e.to_string(),
                ));
                return;
            }
        };
        // 断点：本端上次发送进度（transfers_{role}.json，direction=send）。
        let resume = TransferStore::load_from(&self.store_path)
            .ok()
            .and_then(|st| st.find(tid).filter(|t| t.direction == "send").map(|t| t.next_seq))
            .unwrap_or(0);
        s.local_resume_seq = resume;
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                self.note_finished(Self::mk_entry(
                    tid,
                    name,
                    Direction::Send,
                    size,
                    TransferState::Failed,
                    format!("open: {e}"),
                ));
                return;
            }
        };
        if !self.send_sched.push(tid) {
            // 队列满（128）→ 拒绝。
            self.note_finished(Self::mk_entry(
                tid,
                name,
                Direction::Send,
                size,
                TransferState::Failed,
                "send queue full (128)",
            ));
            return;
        }
        self.send_queued.insert(tid);
        self.save_store(|st| {
            st.upsert(StoredTransfer {
                transfer_id: tid,
                name: name.clone(),
                size,
                direction: "send".into(),
                next_seq: resume,
                sha256: Some(sha),
                part_path: None,
            })
        });
        self.senders.insert(tid, s);
        self.src_files.insert(tid, file);
        self.schedule_next_send().await;
    }

    async fn cmd_respond_offer(&mut self, tid: u64, accept: bool, target_dir: PathBuf) {
        let Some((meta, sha)) = self.pending_offers.get(&tid).cloned() else {
            // 未知/已过期 Offer：调用方（B2 UI）已持有同步层错误路径；此处幂等忽略。
            tracing::debug!("mobile file: respond_offer for unknown/expired offer {tid}");
            return;
        };
        if !accept {
            self.pending_offers.remove(&tid);
            self.send_reject(tid, "declined by user").await;
            self.note_finished(Self::mk_entry(
                tid,
                meta.name,
                Direction::Recv,
                meta.size,
                TransferState::Cancelled,
                "declined by user",
            ));
            return;
        }
        // 落盘目录不可用 → 保持 pending（同步层已报结构化错误，可换目录重试）。
        if !target_dir.is_dir() {
            return;
        }
        self.pending_offers.remove(&tid);
        if !self.recv_sched.push(tid) {
            // 理论不可达（pending ≤128 = 队列上限；双保险）。
            self.send_reject(tid, "queue full").await;
            self.note_finished(Self::mk_entry(
                tid,
                meta.name,
                Direction::Recv,
                meta.size,
                TransferState::Failed,
                "receive queue full (128)",
            ));
            return;
        }
        self.recv_queued.insert(tid, (meta, sha));
        self.recv_dirs.insert(tid, target_dir);
        self.sync_entries();
        self.maybe_start_recv().await;
    }

    async fn cmd_cancel(&mut self, tid: u64) {
        if self.senders.contains_key(&tid) {
            let (name, size, done) = self
                .senders
                .get(&tid)
                .map(|s| (s.name.clone(), s.size, s.acked_bytes()))
                .unwrap_or_default();
            let _ = self
                .send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0))
                .await;
            self.save_store(|st| st.remove(tid));
            // 仅已出队（Offer 已发/待发）的任务占并发槽；仍排队的不占槽
            // （无 finish_one，防槽位计数下溢）。
            if !self.send_queued.contains(&tid) {
                self.send_sched.finish_one();
            }
            self.cancelled.insert(tid);
            self.cleanup_task(tid);
            self.note_finished(Self::mk_entry(
                tid,
                name,
                Direction::Send,
                size,
                TransferState::Cancelled,
                format!("cancelled by user (sent {done} bytes)"),
            ));
            self.schedule_next_send().await;
        } else if self.receivers.contains_key(&tid)
            || self.pending_offers.contains_key(&tid)
            || self.recv_queued.contains_key(&tid)
        {
            let (name, size) = self
                .receivers
                .get(&tid)
                .map(|r| (r.name.clone(), r.size))
                .or_else(|| self.pending_offers.get(&tid).map(|(m, _)| (m.name.clone(), m.size)))
                .or_else(|| {
                    self.recv_queued
                        .get(&tid)
                        .map(|(m, _)| (m.name.clone(), m.size))
                })
                .unwrap_or_default();
            let _ = self
                .send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0))
                .await;
            if let Some(r) = self.receivers.get_mut(&tid) {
                // 本地取消 = 回滚：显式删 `.part`（FT-SEC-006）——Drop 是断点
                // 口径（保留 .part），取消口径必须显式 cancel。
                r.cancel();
            }
            self.save_store(|st| st.remove(tid));
            if self.receivers.contains_key(&tid) {
                // 仅已启动的接收占并发槽；排队/待决不占槽（无 finish_one）。
                self.recv_sched.finish_one();
            }
            self.cancelled.insert(tid);
            self.cleanup_task(tid);
            self.note_finished(Self::mk_entry(
                tid,
                name,
                Direction::Recv,
                size,
                TransferState::Cancelled,
                "cancelled by user",
            ));
            self.maybe_start_recv().await;
        }
        // 其余（未知/已终态）→ 无操作。
    }

    // ── 发送侧驱动（Offer → Accept 门控 → 滑窗 → Finish） ──

    /// 发送调度：活跃 <3 时出队并发 Offer。
    async fn schedule_next_send(&mut self) {
        while let Some(tid) = self.send_sched.pop_ready() {
            self.send_queued.remove(&tid);
            if !self.senders.contains_key(&tid) || self.cancelled.contains(&tid) {
                self.send_sched.finish_one();
                continue;
            }
            if !self.send_offer(tid).await {
                let (name, size) = self
                    .senders
                    .get(&tid)
                    .map(|s| (s.name.clone(), s.size))
                    .unwrap_or_default();
                self.send_sched.finish_one();
                self.cancelled.insert(tid);
                self.cleanup_task(tid);
                self.note_finished(Self::mk_entry(
                    tid,
                    name,
                    Direction::Send,
                    size,
                    TransferState::Failed,
                    "offer send failed (channel closed?)",
                ));
            }
        }
    }

    /// 发 Offer（声明文件名、大小、总块数、整文件哈希）。
    async fn send_offer(&mut self, tid: u64) -> bool {
        let Some(s) = self.senders.get(&tid) else {
            return false;
        };
        let meta = FileOfferMeta {
            name: s.name.clone(),
            size: s.size,
        };
        let frame = FileTransferFrame::offer(tid, &meta, s.total_blocks(), s.sha256);
        let ok = self.send_frame(frame).await;
        if ok {
            self.offered.insert(tid);
        }
        self.sync_entries();
        ok
    }

    /// 填满发送窗口（读源文件 → Data 帧 → mark_sent）。
    ///
    /// **驱动门控**：Accept 前绝不发块（PM 裁定 4；core 状态机不门控）。
    async fn fill_window(&mut self, tid: u64) {
        if !self.accepted.contains(&tid) {
            return;
        }
        loop {
            let Some(seq) = self.senders.get(&tid).and_then(|s| s.next_unsent_seq()) else {
                break;
            };
            let (size, total_blocks) = match self.senders.get(&tid) {
                Some(s) => (s.size, s.total_blocks()),
                None => break,
            };
            let read = {
                let Some(file) = self.src_files.get_mut(&tid) else {
                    break;
                };
                let len = block_len(seq, size);
                if len == 0 {
                    break; // 防御：越界块
                }
                if file.seek(SeekFrom::Start(block_offset(seq))).is_err() {
                    tracing::error!("mobile file: seek failed: {tid}#{seq}");
                    break;
                }
                let mut buf = vec![0u8; len];
                if file.read_exact(&mut buf).is_err() {
                    tracing::error!("mobile file: read failed: {tid}#{seq}");
                    break;
                }
                buf
            };
            let frame = FileTransferFrame {
                transfer_id: tid,
                op: FileOp::Data,
                seq,
                total_blocks,
                data: read,
                sha256: [0u8; 32],
            };
            if !self.send_frame(frame).await {
                break;
            }
            if let Some(s) = self.senders.get_mut(&tid) {
                s.mark_sent(seq);
            }
        }
    }

    /// 远端 Accept：续传协商（双方进度取最大）→ 开门控 → 发块。
    async fn on_accept(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let (all_acked, sha, total_blocks) = {
            let Some(sender) = self.senders.get_mut(&tid) else {
                return;
            };
            let remote_next = bincode::deserialize::<u32>(&frame.data).unwrap_or(0);
            sender.on_accept(remote_next);
            (sender.all_acked(), sender.sha256, sender.total_blocks())
        };
        self.accepted.insert(tid);
        if all_acked {
            // 空文件 / 断点已全收：无需发块，直接 Finish。
            let _ = self
                .send_frame(FileTransferFrame {
                    transfer_id: tid,
                    op: FileOp::Finish,
                    seq: 0,
                    total_blocks,
                    data: Vec::new(),
                    sha256: sha,
                })
                .await;
        } else {
            self.fill_window(tid).await;
        }
        self.sync_entries();
    }

    /// 远端 Ack（累积确认）→ 全部确认后发 Finish。
    async fn on_ack(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let (finish_ready, sha, total_blocks) = {
            let Some(sender) = self.senders.get_mut(&tid) else {
                return;
            };
            let was_complete = sender.is_complete();
            sender.on_ack(frame.seq);
            (
                sender.all_acked() && !was_complete,
                sender.sha256,
                sender.total_blocks(),
            )
        };
        if finish_ready {
            let _ = self
                .send_frame(FileTransferFrame {
                    transfer_id: tid,
                    op: FileOp::Finish,
                    seq: 0,
                    total_blocks,
                    data: Vec::new(),
                    sha256: sha,
                })
                .await;
        }
        self.fill_window(tid).await;
        self.sync_entries();
    }

    /// 远端 Nack → 重传区标记 → 补窗。
    async fn on_nack(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        if let Some(s) = self.senders.get_mut(&tid) {
            s.on_nack(frame.seq);
        }
        self.fill_window(tid).await;
    }

    /// 远端 Reject：发送失败（reason = 对端拒绝原因）。
    async fn on_reject(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let reason = String::from_utf8_lossy(&frame.data).to_string();
        let reason = if reason.is_empty() {
            "rejected by peer".to_string()
        } else {
            reason
        };
        let Some(sender) = self.senders.get(&tid) else {
            return; // 未知 tid（已清理/重复帧）：忽略，不动调度槽位。
        };
        let (name, size, _) = (sender.name.clone(), sender.size, sender.acked_bytes());
        self.save_store(|st| st.remove(tid));
        self.send_sched.finish_one();
        self.cleanup_task(tid);
        self.note_finished(Self::mk_entry(
            tid,
            name,
            Direction::Send,
            size,
            TransferState::Failed,
            reason,
        ));
        self.schedule_next_send().await;
    }

    /// 远端 FinishAck：传输完成（data = 接收方落盘路径，展示用）。
    async fn on_finish_ack(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let Some(sender) = self.senders.get(&tid) else {
            return; // 未知 tid（已清理/重复帧）：忽略，不动调度槽位。
        };
        let (name, size) = (sender.name.clone(), sender.size);
        self.save_store(|st| st.remove(tid));
        self.send_sched.finish_one();
        self.cleanup_task(tid);
        let mut e =
            Self::mk_entry(tid, name, Direction::Send, size, TransferState::Completed, String::new());
        e.done = size;
        self.note_finished(e);
        self.schedule_next_send().await;
    }

    // ── 接收侧驱动（Offer → 用户决定 → Accept → 落盘 → 校验 rename） ──

    /// 远端 Offer：校验（fail-closed）→ 待用户决定队列（移动端不自动 Accept）。
    async fn on_offer(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let meta = match bincode::deserialize::<FileOfferMeta>(&frame.data) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("mobile file: offer deserialize failed: {e}");
                let _ = self
                    .send_frame(FileTransferFrame::simple(tid, FileOp::Reject, 0))
                    .await;
                return;
            }
        };
        // FT-SEC-001/002：路径消毒 + 大小限制（core 校验链，fail-closed）。
        let checked = match ChunkReceiver::validate_offer(&meta, self.max_file_size) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("mobile file: offer rejected: {e}");
                self.send_reject(tid, &e.to_string()).await;
                return;
            }
        };
        if let Err(e) = validate_block_count(checked.size, frame.total_blocks) {
            tracing::warn!("mobile file: offer rejected: {e}");
            self.send_reject(tid, &e.to_string()).await;
            return;
        }
        // FT-SEC-004：transfer_id 去重 + 队列上限（128）。
        if self.receivers.contains_key(&tid)
            || self.pending_offers.contains_key(&tid)
            || self.recv_queued.contains_key(&tid)
            || self.cancelled.contains(&tid)
        {
            self.send_reject(tid, "duplicate transfer_id").await;
            return;
        }
        if self.pending_offers.len() >= MAX_QUEUE_LEN {
            self.send_reject(tid, "offer queue full (128)").await;
            return;
        }
        self.pending_offers.insert(tid, (checked, frame.sha256));
        self.sync_entries();
        // 等待用户决定（B2 onFileTransferOffer 回调 → respond_offer）。
    }

    /// 接收调度：活跃 <3 → begin（.part）→ Accept（携带续传进度）。
    async fn maybe_start_recv(&mut self) {
        while let Some(tid) = self.recv_sched.pop_ready() {
            let Some((meta, sha)) = self.recv_queued.remove(&tid) else {
                // 已被取消/清理的排队项：归还槽位。
                self.recv_sched.finish_one();
                continue;
            };
            let dir = self.recv_dirs.remove(&tid).unwrap_or_default();
            if self.cancelled.contains(&tid) {
                self.recv_sched.finish_one();
                continue;
            }
            // 断点：上次接收进度（.part 保留；孤儿记录建链时已清理）。
            let mut resume_from = 0u32;
            {
                let mut store =
                    TransferStore::load_from(&self.store_path).unwrap_or_default();
                store.prune_missing();
                if let Some(t) = store.find(tid).cloned() {
                    if t.direction == "recv" {
                        resume_from = t.next_seq;
                    }
                }
                if let Err(e) = store.save_to(&self.store_path) {
                    tracing::warn!("mobile file: transfers store save failed: {e}");
                }
            }
            let mut recv = ChunkReceiver::new(tid);
            if let Err(e) = recv.begin(&meta, &dir, sha, resume_from) {
                // 目录不可写/磁盘满/断点越界 → 结构化 Reject（fail-closed 不换目录）。
                tracing::warn!("mobile file: receive begin failed: {e}");
                self.send_reject(tid, &e.to_string()).await;
                self.save_store(|st| st.remove(tid));
                self.recv_sched.finish_one();
                self.note_finished(Self::mk_entry(
                    tid,
                    meta.name,
                    Direction::Recv,
                    meta.size,
                    TransferState::Failed,
                    e.to_string(),
                ));
                continue;
            }
            self.save_store(|st| {
                st.upsert(StoredTransfer {
                    transfer_id: tid,
                    name: recv.name.clone(),
                    size: recv.size,
                    direction: "recv".into(),
                    next_seq: recv.next_seq(),
                    sha256: Some(recv.sha256),
                    part_path: Some(recv.part_path().to_string_lossy().to_string()),
                })
            });
            self.receivers.insert(tid, recv);
            // Accept 携带本端续传进度（u32）+ 总块数回执。
            let mut acc = FileTransferFrame::simple(tid, FileOp::Accept, 0);
            acc.data = bincode::serialize(&resume_from).unwrap_or_default();
            acc.total_blocks = self
                .receivers
                .get(&tid)
                .map(|r| r.total_blocks)
                .unwrap_or(0);
            if !self.send_frame(acc).await {
                tracing::error!("mobile file: accept send failed");
                if let Some(r) = self.receivers.get_mut(&tid) {
                    r.cancel();
                }
                self.save_store(|st| st.remove(tid));
                self.recv_sched.finish_one();
                self.cleanup_task(tid);
                self.note_finished(Self::mk_entry(
                    tid,
                    meta.name,
                    Direction::Recv,
                    meta.size,
                    TransferState::Failed,
                    "accept send failed (channel closed?)",
                ));
                continue;
            }
            self.sync_entries();
        }
    }

    /// 远端 Data：落 `.part`（按序，重复块忽略）→ 累积 Ack。
    async fn on_data(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let outcome = {
            let Some(recv) = self.receivers.get_mut(&tid) else {
                return; // 未知/已清理任务：忽略（防御）。
            };
            match recv.on_data(frame.seq, &frame.data) {
                Ok(_dup) => Ok(recv.next_seq()),
                Err(e) => Err(e),
            }
        };
        match outcome {
            Ok(next_seq) => {
                let ack = FileTransferFrame::simple(tid, FileOp::Ack, next_seq.saturating_sub(1));
                let _ = self.send_frame(ack).await;
                self.sync_entries();
            }
            Err(e) => {
                // 顺序破坏/块长异常 → 终止该传输（防御；FT-SEC 口径）。
                tracing::warn!("mobile file: receive error: {e}");
                let _ = self
                    .send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0))
                    .await;
                self.abort_recv(tid, e.to_string()).await;
            }
        }
    }

    /// 远端 Finish：整体 SHA-256 校验 → 原子 rename → FinishAck。
    async fn on_finish(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let Some(recv) = self.receivers.get_mut(&tid) else {
            // 未知任务：FinishAck 收敛（防御，同桌面）。
            let _ = self
                .send_frame(FileTransferFrame::simple(tid, FileOp::FinishAck, 0))
                .await;
            return;
        };
        let (result, name, size) = {
            let result = recv.verify().and_then(|()| recv.commit());
            (result, recv.name.clone(), recv.size)
        };
        match result {
            Ok(final_path) => {
                tracing::info!("mobile file: received OK: {}", final_path.display());
                let mut fa = FileTransferFrame::simple(tid, FileOp::FinishAck, 0);
                fa.data = final_path.to_string_lossy().to_string().into_bytes();
                let _ = self.send_frame(fa).await;
                self.save_store(|st| st.remove(tid));
                self.cleanup_task(tid);
                self.recv_sched.finish_one();
                let mut e = Self::mk_entry(
                    tid,
                    name,
                    Direction::Recv,
                    size,
                    TransferState::Completed,
                    String::new(),
                );
                e.done = size;
                e.path = Some(final_path.to_string_lossy().to_string());
                self.note_finished(e);
                self.maybe_start_recv().await;
            }
            Err(e) => {
                // 校验失败（FT-SEC-003）→ Cancel + 删 .part（fail-closed）。
                tracing::warn!("mobile file: verify/commit FAILED for {tid}: {e}");
                let _ = self
                    .send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0))
                    .await;
                self.abort_recv(tid, e.to_string()).await;
            }
        }
    }

    /// 接收任务中止（校验失败/数据异常/远端取消）：删 `.part` + 清 store。
    async fn abort_recv(&mut self, tid: u64, reason: String) {
        let (name, size) = self
            .receivers
            .get(&tid)
            .map(|r| (r.name.clone(), r.size))
            .unwrap_or_default();
        if let Some(r) = self.receivers.get_mut(&tid) {
            r.cancel(); // 删 .part（FT-SEC-006 无残留泄漏）
        }
        self.save_store(|st| st.remove(tid));
        self.recv_sched.finish_one();
        self.cancelled.insert(tid);
        self.cleanup_task(tid);
        self.note_finished(Self::mk_entry(
            tid,
            name,
            Direction::Recv,
            size,
            TransferState::Failed,
            reason,
        ));
        self.maybe_start_recv().await;
    }

    /// 远端 Cancel：取消对应任务（发送 → 终止；接收 → 回滚删 `.part`）。
    async fn on_cancel(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        if self.senders.contains_key(&tid) {
            let (name, size, _) = self
                .senders
                .get(&tid)
                .map(|s| (s.name.clone(), s.size, s.acked_bytes()))
                .unwrap_or_default();
            self.save_store(|st| st.remove(tid));
            self.send_sched.finish_one();
            self.cancelled.insert(tid);
            self.cleanup_task(tid);
            self.note_finished(Self::mk_entry(
                tid,
                name,
                Direction::Send,
                size,
                TransferState::Cancelled,
                "cancelled by peer",
            ));
            self.schedule_next_send().await;
        } else if self.receivers.contains_key(&tid)
            || self.pending_offers.contains_key(&tid)
            || self.recv_queued.contains_key(&tid)
        {
            let (name, size) = self
                .receivers
                .get(&tid)
                .map(|r| (r.name.clone(), r.size))
                .or_else(|| {
                    self.pending_offers
                        .get(&tid)
                        .map(|(m, _)| (m.name.clone(), m.size))
                })
                .or_else(|| {
                    self.recv_queued
                        .get(&tid)
                        .map(|(m, _)| (m.name.clone(), m.size))
                })
                .unwrap_or_default();
            if let Some(r) = self.receivers.get_mut(&tid) {
                r.cancel();
            }
            self.save_store(|st| st.remove(tid));
            if self.receivers.contains_key(&tid) {
                self.recv_sched.finish_one();
            }
            self.cancelled.insert(tid);
            self.cleanup_task(tid);
            self.note_finished(Self::mk_entry(
                tid,
                name,
                Direction::Recv,
                size,
                TransferState::Cancelled,
                "cancelled by peer",
            ));
            self.maybe_start_recv().await;
        }
    }

    /// 远端帧入口（会话接收循环 0x06 分支馈送）。
    async fn handle_frame(&mut self, frame: FileTransferFrame) {
        // 已本地取消的任务：后续帧全部忽略（防御：取消后对端在途帧）。
        if self.cancelled.contains(&frame.transfer_id) {
            return;
        }
        match frame.op {
            FileOp::Offer => self.on_offer(frame).await,
            FileOp::Accept => self.on_accept(frame).await,
            FileOp::Reject => self.on_reject(frame).await,
            FileOp::Data => self.on_data(frame).await,
            FileOp::Ack => self.on_ack(frame).await,
            FileOp::Nack => self.on_nack(frame).await,
            FileOp::Finish => self.on_finish(frame).await,
            FileOp::FinishAck => self.on_finish_ack(frame).await,
            FileOp::Cancel => self.on_cancel(frame).await,
            // Pause/Resume 仅本端生效，对端无需处理（同桌面）。
            FileOp::Pause | FileOp::Resume => {}
            // v1 不消费 → 与 Pause|Resume 臂同「对端无需处理」语义（穷举 match 无通配，
            // 尾追加变体必须补臂，否则 E0004）；零行为变化/零协议变化。后续安卓文件
            // 管理器直接消费 core FsOp 负载资产，协议零再设计。
            FileOp::FsRequest | FileOp::FsResponse => {}
            // = mobile v1 不消费（同 FS 臂「对端无需处理」语义，零行为变化）。
            FileOp::OfferV2 => {}
            // = mobile v1 不消费（同「对端无需处理」语义，零行为变化）。
            FileOp::PeerConsent => {}
        }
    }

    // ── 周期 tick：重传 + 死链 + 补窗 + 断点持久化（1s 粒度） ──

    async fn on_tick(&mut self) {
        let now = std::time::Instant::now();
        let mut retransmit = Vec::new();
        let mut dead = Vec::new();
        for (tid, s) in self.senders.iter_mut() {
            // 驱动门控：Accept 前不重传/不判死链（in_flight=0 时两者本为假，
            // 显式 skip 以固化语义）。
            if s.is_cancelled()
                || !self.accepted.contains(tid)
                || s.status() != CoreStatus::Sending
            {
                continue;
            }
            retransmit.extend(s.retransmit_due(now).into_iter().map(|seq| (*tid, seq)));
            if s.idle_timeout(now) {
                dead.push(*tid);
            }
        }
        for (tid, _seq) in retransmit {
            self.fill_window(tid).await;
        }
        for tid in dead {
            tracing::warn!("mobile file: transfer {tid} idle timeout — cancelling");
            let (name, size, _) = self
                .senders
                .get(&tid)
                .map(|s| (s.name.clone(), s.size, s.acked_bytes()))
                .unwrap_or_default();
            let _ = self
                .send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0))
                .await;
            self.save_store(|st| st.remove(tid));
            self.send_sched.finish_one();
            self.cancelled.insert(tid);
            self.cleanup_task(tid);
            self.note_finished(Self::mk_entry(
                tid,
                name,
                Direction::Send,
                size,
                TransferState::Failed,
                "connection idle timeout",
            ));
        }
        // 补窗（Ack 推进后空出的槽位）——仅已 Accept 任务。
        let tids: Vec<u64> = self
            .senders
            .keys()
            .copied()
            .filter(|t| self.accepted.contains(t))
            .collect();
        for tid in tids {
            self.fill_window(tid).await;
        }
        // 进度断点持久化（1s 粒度，避免每块全量写 json）。
        let recv_ids: Vec<u64> = self.receivers.keys().copied().collect();
        let send_ids: Vec<u64> = self.senders.keys().copied().collect();
        if !recv_ids.is_empty() || !send_ids.is_empty() {
            self.save_store(|st| {
                for tid in &recv_ids {
                    if let Some(r) = self.receivers.get(tid) {
                        if let Some(t) = st.find_mut(*tid) {
                            t.next_seq = r.next_seq();
                        }
                    }
                }
                for tid in &send_ids {
                    if let Some(s) = self.senders.get(tid) {
                        if let Some(t) = st.find_mut(*tid) {
                            t.next_seq = s.resume_seq();
                        }
                    }
                }
            });
            self.sync_entries();
        }
    }
}

// ════════════════════════════════════════════════════════════════
// Tests（宿主机可跑：纯函数 + 封装口径）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use kirin_desk_media::transport::ChannelTag;

    #[test]
    fn test_session_salt_sorted_both_ends_consistent() {
        // 排序拼接：两端无论哪端先算，结果一致（桌面 file_transfer_salt 同口径）。
        assert_eq!(session_salt("aaa", "bbb"), "aaabbb");
        assert_eq!(session_salt("bbb", "aaa"), "aaabbb");
        assert_eq!(session_salt("", "x"), "x");
        assert_eq!(session_salt("x", ""), "x");
        assert_eq!(session_salt("same", "same"), "samesame");
    }

    #[test]
    fn test_file_packet_wraps_0x06_payload() {
        // EncodedPacket 封装：PacketKind::FileTransfer → wire tag 0x06，
        // payload = frame.encode()（收侧 FileTransferFrame::decode 往返）。
        let frame = FileTransferFrame::simple(7, FileOp::Cancel, 0);
        let pkt = file_packet(&frame);
        assert!(matches!(pkt.kind, PacketKind::FileTransfer));
        assert!(!pkt.is_key);
        assert_eq!(
            ChannelTag::from_packet_kind(pkt.kind),
            ChannelTag::FileTransfer,
            "kind → wire tag 必须是 0x06"
        );
        assert_eq!(pkt.data, frame.encode().unwrap());
        assert_eq!(FileTransferFrame::decode(&pkt.data).unwrap(), frame);
    }

    #[test]
    fn test_transfer_state_and_direction_str() {
        assert_eq!(Direction::Send.as_str(), "send");
        assert_eq!(Direction::Recv.as_str(), "recv");
        assert_eq!(TransferState::Queued.as_str(), "queued");
        assert_eq!(TransferState::WaitingAccept.as_str(), "waiting_accept");
        assert_eq!(TransferState::OfferPending.as_str(), "offer_pending");
        assert_eq!(TransferState::Sending.as_str(), "sending");
        assert_eq!(TransferState::Receiving.as_str(), "receiving");
        assert_eq!(TransferState::Completed.as_str(), "completed");
        assert_eq!(TransferState::Failed.as_str(), "failed");
        assert_eq!(TransferState::Cancelled.as_str(), "cancelled");
    }

    #[test]
    fn test_transfers_json_format_and_escaping() {
        // 空表 = "[]"（Kotlin 侧与「句柄无效」同形，轮询幂等）。
        assert_eq!(transfers_json(&[]), "[]");

        // 字段齐全/顺序定稿 + 转义（文件名含 `"` 与 `\` 与 unicode）+
        // path None → null + reason 空串恒在 + speed 非有限 → 0.0。
        let entries = vec![
            TransferEntry {
                transfer_id: 42,
                name: "文\"件\\b.png".to_string(),
                direction: Direction::Recv,
                size: 100,
                done: 40,
                state: TransferState::Receiving,
                speed: f64::NAN,
                reason: String::new(),
                path: None,
            },
            TransferEntry {
                transfer_id: 7,
                name: "a".to_string(),
                direction: Direction::Send,
                size: 10,
                done: 10,
                state: TransferState::Failed,
                speed: 0.0,
                reason: "declined by user".to_string(),
                path: Some("/storage/emulated/0/Android/data/app/files/a".to_string()),
            },
        ];
        // 键序 = serde_json 确定性字母序（direction,done,name,path,reason,
        // size,speed,state,transfer_id）——格式定稿锚（详见 fn doc）。
        assert_eq!(
            transfers_json(&entries),
            r#"[{"direction":"recv","done":40,"name":"文\"件\\b.png","path":null,"reason":"","size":100,"speed":0.0,"state":"receiving","transfer_id":42},{"direction":"send","done":10,"name":"a","path":"/storage/emulated/0/Android/data/app/files/a","reason":"declined by user","size":10,"speed":0.0,"state":"failed","transfer_id":7}]"#
        );
    }
}
