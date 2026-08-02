//! M13-T006 文件传输：帧协议 + 滑窗发送器 + 分片重组接收器 + 断点续传。
//!
//! 本模块是**纯逻辑层**（不依赖 media / 网络 I/O），与传输解耦：
//!
//! - 帧结构 [`FileTransferFrame`]（bincode 序列化）定义 wire 协议；
//! - [`SlideWindowSender`]：发送侧滑窗状态机（窗口 64 块、Ack/Nack、
//!   超时重传、暂停/恢复/取消、断点续传）；
//! - [`ChunkReceiver`]：接收侧重组状态机（按序落 `.part`、整体 SHA-256
//!   校验、原子 rename、取消回滚）；
//! - [`TransferScheduler`]：会话内并发任务队列（≤3 活跃，FIFO；排队上限
//!   [`MAX_QUEUE_LEN`]，S-10c）；
//! - [`SessionQuota`]：会话级总字节/文件数配额（S-10b）；
//! - [`TransferStore`]：断点状态持久化（`transfers.json`，仅元数据）。
//!
//! I/O 接线（TCP 发送/接收、帧转发）由上层（ui）完成；本模块所有函数
//! 同步、可单测。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ════════════════════════════════════════════════════════════════
// 常量
// ════════════════════════════════════════════════════════════════

/// 文件块大小（64 KiB，避开 EncodedPacket 1200B 小分片路径，走大帧）。
pub const BLOCK_SIZE: u64 = 64 * 1024;

/// 发送滑窗宽度（块数）。
pub const WINDOW_SIZE: usize = 64;

/// 块超时（秒）：发送后未确认 → 重传。
pub const BLOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// 空闲超时（秒）：无任何进展 → 判定死链，交给上层 Cancel + 重连续传。
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// 会话内并发任务上限（收发各 ≤ 3，超量排队 FIFO）。
pub const MAX_CONCURRENT: usize = 3;

/// 单文件大小上限默认值（4 GiB，Offer 阶段拒绝，FT-SEC-002）。
pub const DEFAULT_MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// S-10b (F-11)：单会话累计字节配额默认值（4 GiB，与单文件上限一致——
/// 单文件整传恰好占满预算，不误伤正常大文件传输；对齐
/// `utils::config::FileTransferConfig::default_session_max_bytes`）。
pub const DEFAULT_SESSION_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// S-10b (F-11)：单会话文件数配额默认值（64；对齐
/// `utils::config::FileTransferConfig::default_session_max_files`）。
pub const DEFAULT_SESSION_MAX_FILES: u64 = 64;

/// S-10c (F-11)：调度队列长度上限（排队任务数超过即拒绝入队）。
pub const MAX_QUEUE_LEN: usize = 128;

/// 单文件最大块数兜底（1M 块 = 64 GiB，防止恶意 total_blocks 撑爆内存）。
const MAX_BLOCKS: u64 = 1 << 20;

// ════════════════════════════════════════════════════════════════
// 帧协议（bincode，复用现有序列化）
// ════════════════════════════════════════════════════════════════

/// 文件传输操作码。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOp {
    /// 发送方声明文件（data = bincode([`FileOfferMeta`])）。
    Offer,
    /// 接收方接受（data = bincode(u32 断点 seq)，续传协商）。
    Accept,
    /// 接收方拒绝（data = UTF-8 原因）。
    Reject,
    /// 数据块（payload ≤ [`BLOCK_SIZE`]）。
    Data,
    /// 累积确认（seq = 已连续收至该块）。
    Ack,
    /// 块否定（seq = 需要重传的块）。
    Nack,
    /// 发送方声明全部块已发（sha256 = 整文件哈希回执）。
    Finish,
    /// 接收方确认完成（已整体校验 + 落盘）。
    FinishAck,
    /// 取消（删除 `.part`，回滚）。
    Cancel,
    /// 暂停。
    Pause,
    /// 恢复（data = bincode(u32 next_seq)）。
    Resume,
}

/// 文件传输帧（wire 协议，bincode 序列化）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTransferFrame {
    /// 传输 ID：`hash(文件名|大小|会话盐)` — 断点续传/去重键。
    pub transfer_id: u64,
    /// 操作。
    pub op: FileOp,
    /// 块序号（0 基）；Offer/Finish 时为 0。
    pub seq: u32,
    /// 总块数（Offer/首块时声明；0 = 空文件）。
    pub total_blocks: u32,
    /// Offer = bincode([`FileOfferMeta`])；Accept/Resume = bincode(u32)；
    /// Reject = UTF-8 原因；Data = 块负载。
    pub data: Vec<u8>,
    /// Offer = 整文件 SHA-256；Finish = 回执确认；其余全零。
    pub sha256: [u8; 32],
}

/// Offer 元数据（文件名 + 大小，bincode 置于 Offer.data）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOfferMeta {
    pub name: String,
    pub size: u64,
}

impl FileTransferFrame {
    /// 构造一个简单帧（无负载）。
    pub fn simple(transfer_id: u64, op: FileOp, seq: u32) -> Self {
        Self {
            transfer_id,
            op,
            seq,
            total_blocks: 0,
            data: Vec::new(),
            sha256: [0u8; 32],
        }
    }

    /// 构造 Offer 帧。
    pub fn offer(
        transfer_id: u64,
        meta: &FileOfferMeta,
        total_blocks: u32,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            transfer_id,
            op: FileOp::Offer,
            seq: 0,
            total_blocks,
            data: bincode::serialize(meta).unwrap_or_default(),
            sha256,
        }
    }

    /// 序列化为 wire bytes（bincode）。
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("file frame serialize: {e}"))
    }

    /// 从 wire bytes 反序列化。
    pub fn decode(buf: &[u8]) -> Result<Self, String> {
        bincode::deserialize(buf).map_err(|e| format!("file frame deserialize: {e}"))
    }
}

// ════════════════════════════════════════════════════════════════
// 错误
// ════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, thiserror::Error)]
pub enum FileTransferError {
    #[error("unsafe filename: {0}")]
    UnsafeFilename(String),
    #[error("file too large: {0} bytes (max {1})")]
    FileTooLarge(u64, u64),
    #[error("invalid block count: {0}")]
    InvalidBlockCount(u64),
    #[error("transfer not found: {0}")]
    NotFound(u64),
    #[error("checksum mismatch")]
    ChecksumMismatch,
    #[error("block out of order: got {0}, expected {1}")]
    OutOfOrder(u32, u32),
    #[error("transfer rejected by peer: {0}")]
    Rejected(String),
    /// S-10a (F-11)：`resume_from` 越界（> 总块数）→ 拒绝续传，
    /// 防止恶意断点直接 `set_len(seq*64KiB)` 制造数百 TB 稀疏文件。
    #[error("invalid resume offset {0} (total blocks {1})")]
    InvalidResumeOffset(u32, u32),
    /// S-10b (F-11)：会话级字节配额超限（已预留 {0}，上限 {1}）。
    #[error("session byte quota exceeded: {0} bytes reserved (max {1})")]
    SessionBytesExceeded(u64, u64),
    /// S-10b (F-11)：会话级文件数配额超限（已预留 {0} 个，上限 {1}）。
    #[error("session file quota exceeded: {0} files reserved (max {1})")]
    SessionFilesExceeded(u64, u64),
    /// S-10c (F-11)：调度队列已满，拒绝入队。
    #[error("transfer scheduler queue full (max {0})")]
    QueueFull(usize),
    /// S-10d (F-11)：磁盘剩余空间不足（需 {0} 字节，可用 {1}）。
    #[error("insufficient disk space: need {0} bytes, free {1}")]
    InsufficientDiskSpace(u64, u64),
    #[error("io: {0}")]
    Io(String),
    #[error("cancelled")]
    Cancelled,
}

// ════════════════════════════════════════════════════════════════
// 纯函数：transfer_id / 路径消毒 / 分块计算 / SHA-256
// ════════════════════════════════════════════════════════════════

/// 派生传输 ID：`sha256(name|size|salt)` 前 8 字节（大端 u64）。
///
/// salt 取握手双方一致的材料（如对端 peer_id），保证同文件跨会话 ID 稳定、
/// 不同会话不冲突。
pub fn derive_transfer_id(name: &str, size: u64, salt: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(&size.to_be_bytes());
    hasher.update(salt.as_bytes());
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().unwrap())
}

/// 文件名路径消毒（FT-SEC-001）：只允许裸文件名。
///
/// 拒绝：空名/超长、绝对路径（`/`、`\`、盘符）、任何路径分隔符、`..`、
/// NUL、控制字符、Windows 非法字符 `<>:"|?*`、尾随点/空格、Windows 保留名。
pub fn sanitize_filename(name: &str) -> Result<String, FileTransferError> {
    // 尾随点/空格（Windows 解析歧义）在 trim 前判定，避免被吞掉。
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(FileTransferError::UnsafeFilename(
            "trailing dot or space".into(),
        ));
    }
    let name = name.trim();
    if name.is_empty() {
        return Err(FileTransferError::UnsafeFilename("empty name".into()));
    }
    if name.len() > 255 {
        return Err(FileTransferError::UnsafeFilename("name too long".into()));
    }
    // 绝对路径 / 分隔符 / NUL。
    if name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(FileTransferError::UnsafeFilename(
            "path separators or absolute path".into(),
        ));
    }
    // 盘符（C:）。
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(FileTransferError::UnsafeFilename("drive letter".into()));
    }
    // 相对穿越。
    if name == "." || name == ".." || name.starts_with("..") {
        return Err(FileTransferError::UnsafeFilename("dot-dot".into()));
    }
    // Windows 非法字符 + 控制字符。
    for c in name.chars() {
        if matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') || (c as u32) < 0x20 {
            return Err(FileTransferError::UnsafeFilename(format!(
                "illegal char {c:?}"
            )));
        }
    }
    // Windows 保留名（含扩展名前缀，如 CON.txt）。
    let stem = name.split('.').next().unwrap_or("");
    let upper = stem.to_ascii_uppercase();
    let reserved = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if reserved.contains(&upper.as_str()) {
        return Err(FileTransferError::UnsafeFilename(format!(
            "reserved name {name}"
        )));
    }
    Ok(name.to_string())
}

/// 目标路径去重（FT-SEC-005）：目录下已有同名文件 → 自动改名 `name (1)`、
/// `name (2)`……（默认改名策略，不覆盖已有文件）。
pub fn unique_target_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (name.to_string(), String::new()),
    };
    for i in 1..10_000u32 {
        let alt = dir.join(format!("{stem} ({i}){ext}"));
        if !alt.exists() {
            return alt;
        }
    }
    // 极端情况：全部占用 → 追加时间戳。
    dir.join(format!(
        "{stem} ({}){ext}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    ))
}

/// 计算文件总块数（0 字节文件 = 0 块）。
pub fn total_blocks_for(size: u64) -> u64 {
    size.div_ceil(BLOCK_SIZE)
}

/// 校验块数声明（与大小一致 + 不超兜底上限）。
pub fn validate_block_count(size: u64, blocks: u32) -> Result<(), FileTransferError> {
    let expected = total_blocks_for(size);
    if expected > MAX_BLOCKS || blocks as u64 != expected {
        return Err(FileTransferError::InvalidBlockCount(blocks as u64));
    }
    Ok(())
}

/// 块在文件中的偏移。
pub fn block_offset(seq: u32) -> u64 {
    (seq as u64) * BLOCK_SIZE
}

/// 块的实际长度（末块可能不满）。
pub fn block_len(seq: u32, size: u64) -> usize {
    let offset = block_offset(seq);
    let remain = size.saturating_sub(offset);
    remain.min(BLOCK_SIZE) as usize
}

/// 计算字节流 SHA-256。
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    digest.into()
}

/// 计算文件 SHA-256（同步 std fs；调用方自行选择线程）。
pub fn sha256_file(path: &Path) -> Result<[u8; 32], FileTransferError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| FileTransferError::Io(format!("open {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        use std::io::Read;
        let n = file
            .read(&mut buf)
            .map_err(|e| FileTransferError::Io(format!("read {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// S-10d (F-11)：查询 `path` 所在卷的可用磁盘空间（字节）。
///
/// 最小实现（不新增依赖）：Windows 经 `libloading` 动态调用
/// `GetDiskFreeSpaceExW`；其他平台无 std API 可用 → 返回 `None`
/// （调用方视为「未知」，跳过检查）。
#[cfg(windows)]
pub fn free_disk_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let lib = libloading::Library::new("kernel32.dll").ok()?;
        let get_free: libloading::Symbol<
            unsafe extern "system" fn(*const u16, *mut u64, *mut u64, *mut u64) -> i32,
        > = lib.get(b"GetDiskFreeSpaceExW").ok()?;
        let mut free_bytes_avail: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free: u64 = 0;
        let ok = get_free(
            wide.as_ptr(),
            &mut free_bytes_avail,
            &mut total_bytes,
            &mut total_free,
        );
        if ok == 0 {
            None // 路径不存在/调用失败 → 未知
        } else {
            Some(free_bytes_avail)
        }
    }
}

/// S-10d (F-11)：非 Windows 平台无内建磁盘空间 API（不新增 libc/fs2
/// 依赖）→ 返回 `None`，落盘前检查跳过（尽力而为）。
#[cfg(not(windows))]
pub fn free_disk_space(_path: &Path) -> Option<u64> {
    None
}

// ════════════════════════════════════════════════════════════════
// SlideWindowSender — 发送侧滑窗状态机
// ════════════════════════════════════════════════════════════════

/// 任务状态（UI 展示用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferStatus {
    /// 排队等待（会话内并发已满）。
    Queued,
    /// 传输中。
    Sending,
    /// 暂停。
    Paused,
    /// 完成。
    Completed,
    /// 失败。
    Failed(String),
    /// 已取消。
    Cancelled,
}

/// 发送侧状态机：滑窗（窗口 [`WINDOW_SIZE`] 块）→ Ack 推进 / Nack 重传 /
/// 块超时重传 / 空闲死链判定 / 暂停恢复 / 断点续传。
///
/// 纯逻辑：不持有文件句柄与网络；`mark_sent` 由上层在发帧后调用，
/// `next_unsent_seq` 返回待发块号（含 Nack/超时重传块），上层读源文件
/// 构造 Data 帧。
pub struct SlideWindowSender {
    pub transfer_id: u64,
    pub name: String,
    pub size: u64,
    pub total_blocks: u32,
    pub sha256: [u8; 32],
    /// 本端断点起点（上次已确认进度，续传协商用）。
    pub local_resume_seq: u32,
    /// 发送起点（Accept 协商后确定）。
    start_seq: u32,
    /// 下一个新块游标（Nack/超时块由 `next_unsent_seq` 扫描旧区重发）。
    next_seq: u32,
    /// 已发送（绝对 seq 位图）。
    sent: Vec<bool>,
    /// 已确认（绝对 seq 位图）。
    acked: Vec<bool>,
    /// 已发送未确认块数（窗口占用）。
    in_flight: usize,
    /// 在途块发送时刻（超时重传判定）。
    sent_at: HashMap<u32, Instant>,
    /// 已确认块计数。
    acked_count: u64,
    /// 开始时刻（速度计算）。
    started: Option<Instant>,
    /// 最近一次活动（任何进展）。
    last_activity: Instant,
    paused: bool,
    done: bool,
    failed: Option<String>,
    cancelled: bool,
}

impl SlideWindowSender {
    /// 创建发送器。`sha256` 为整文件哈希（Offer 声明）。
    pub fn new(
        transfer_id: u64,
        name: String,
        size: u64,
        sha256: [u8; 32],
    ) -> Result<Self, FileTransferError> {
        let total_blocks = total_blocks_for(size);
        if total_blocks > MAX_BLOCKS {
            return Err(FileTransferError::InvalidBlockCount(total_blocks));
        }
        let total = total_blocks as usize;
        Ok(Self {
            transfer_id,
            name,
            size,
            total_blocks: total_blocks as u32,
            sha256,
            local_resume_seq: 0,
            start_seq: 0,
            next_seq: 0,
            sent: vec![false; total],
            acked: vec![false; total],
            in_flight: 0,
            sent_at: HashMap::new(),
            acked_count: 0,
            started: None,
            last_activity: Instant::now(),
            paused: false,
            done: false,
            failed: None,
            cancelled: false,
        })
    }

    /// 总块数。
    pub fn total_blocks(&self) -> u32 {
        self.total_blocks
    }

    /// 当前状态。
    pub fn status(&self) -> TransferStatus {
        if self.cancelled {
            return TransferStatus::Cancelled;
        }
        if let Some(e) = &self.failed {
            return TransferStatus::Failed(e.clone());
        }
        if self.done {
            return TransferStatus::Completed;
        }
        if self.paused {
            return TransferStatus::Paused;
        }
        TransferStatus::Sending
    }

    /// 进度 (已确认字节, 总字节)。
    pub fn progress(&self) -> (u64, u64) {
        (self.acked_count * BLOCK_SIZE, self.size)
    }

    /// 平均速度（字节/秒；未开始返回 0）。
    pub fn speed(&self) -> f64 {
        let Some(start) = self.started else {
            return 0.0;
        };
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed <= 0.0 {
            return 0.0;
        }
        self.acked_count as f64 * BLOCK_SIZE as f64 / elapsed
    }

    /// 已确认字节数。
    pub fn acked_bytes(&self) -> u64 {
        self.acked_count * BLOCK_SIZE
    }

    /// 是否完成（全部块已确认）。
    pub fn is_complete(&self) -> bool {
        self.total_blocks > 0 && self.acked_count as u32 >= self.total_blocks
    }

    /// 收到 Accept：`remote_next_seq` = 接收方已有进度（续传协商），
    /// 取双方进度最大值作为发送起点。首传时对端回 0。
    pub fn on_accept(&mut self, remote_next_seq: u32) {
        self.started.get_or_insert_with(Instant::now);
        self.start_seq = self
            .local_resume_seq
            .max(remote_next_seq)
            .min(self.total_blocks);
        self.next_seq = self.start_seq;
        self.sent_at.clear();
        self.in_flight = 0;
        // 起点之前的块视为已发已确认。
        let start = self.start_seq as usize;
        for i in 0..start.min(self.sent.len()) {
            self.sent[i] = true;
            self.acked[i] = true;
        }
        self.acked_count = self.start_seq as u64;
        self.done = self.start_seq >= self.total_blocks && self.size > 0
            || (self.size == 0 && self.total_blocks == 0);
    }

    /// 下一个待发块（优先重传区，其次新块）；`None` = 窗口满/暂停/全部已发。
    pub fn next_unsent_seq(&self) -> Option<u32> {
        if self.paused || self.done || self.failed.is_some() || self.cancelled {
            return None;
        }
        if self.in_flight >= WINDOW_SIZE {
            return None; // 窗口满
        }
        // 重传区：已发送但被 Nack/超时标记为未发的块。
        for seq in self.start_seq..self.next_seq {
            if !self.sent[seq as usize] {
                return Some(seq);
            }
        }
        // 新块。
        if self.next_seq < self.total_blocks {
            return Some(self.next_seq);
        }
        None
    }

    /// 发送一帧后调用（记录发送时刻）。
    pub fn mark_sent(&mut self, seq: u32) {
        if seq >= self.total_blocks {
            return;
        }
        if !self.sent[seq as usize] {
            self.sent[seq as usize] = true;
            self.in_flight += 1;
        }
        self.sent_at.insert(seq, Instant::now());
        if seq == self.next_seq {
            self.next_seq += 1;
        }
        self.last_activity = Instant::now();
    }

    /// 收到累积确认 `Ack(seq)`：确认 `[start_seq, seq]` 全部块，窗口推进。
    /// 返回本次推进的块数（0 = 无进展）。
    pub fn on_ack(&mut self, seq: u32) -> u32 {
        let mut advanced = 0u32;
        while self.start_seq + advanced <= seq && self.start_seq + advanced < self.total_blocks {
            let s = self.start_seq + advanced;
            if !self.acked[s as usize] {
                self.acked[s as usize] = true;
                self.acked_count += 1;
                if self.sent_at.remove(&s).is_some() {
                    self.in_flight = self.in_flight.saturating_sub(1);
                }
            }
            advanced += 1;
        }
        if advanced > 0 {
            self.start_seq += advanced;
            self.last_activity = Instant::now();
        }
        advanced
    }

    /// 收到 Nack(seq)：立即标记未发（调度循环重新取号重传）。
    pub fn on_nack(&mut self, seq: u32) {
        if seq < self.sent.len() as u32 && self.sent[seq as usize] {
            self.sent[seq as usize] = false;
            self.in_flight = self.in_flight.saturating_sub(1);
        }
        self.sent_at.remove(&seq);
        self.last_activity = Instant::now();
    }

    /// 超时重传：返回已超时（[`BLOCK_TIMEOUT`]）未确认的块号列表。
    pub fn retransmit_due(&mut self, now: Instant) -> Vec<u32> {
        let mut due = Vec::new();
        let mut remove = Vec::new();
        for (seq, t) in &self.sent_at {
            if now.duration_since(*t) >= BLOCK_TIMEOUT {
                let seq = *seq;
                if (seq as usize) < self.sent.len() && self.sent[seq as usize] {
                    self.sent[seq as usize] = false;
                    self.in_flight = self.in_flight.saturating_sub(1);
                    due.push(seq);
                }
                remove.push(seq);
            }
        }
        for seq in remove {
            self.sent_at.remove(&seq);
        }
        due
    }

    /// 空闲死链判定：窗口非空且超过 [`IDLE_TIMEOUT`] 无任何进展。
    pub fn idle_timeout(&self, now: Instant) -> bool {
        self.in_flight > 0 && now.duration_since(self.last_activity) >= IDLE_TIMEOUT
    }

    /// 暂停。
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// 恢复。
    pub fn resume(&mut self) {
        self.paused = false;
        self.last_activity = Instant::now();
    }

    /// 取消。
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// 是否已取消。
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// 标记失败。
    pub fn fail(&mut self, msg: String) {
        self.failed = Some(msg);
    }

    /// 全部块已确认（0 块空文件恒真——无需确认，直接 Finish）。
    pub fn all_acked(&self) -> bool {
        self.total_blocks == 0 || self.acked_count as u32 >= self.total_blocks
    }

    /// 断点进度（本地持久化用：已确认的下一块）。
    pub fn resume_seq(&self) -> u32 {
        self.acked_count as u32
    }
}

// ════════════════════════════════════════════════════════════════
// ChunkReceiver — 接收侧重组状态机
// ════════════════════════════════════════════════════════════════

/// 接收侧状态机：按序落 `.part`（可靠流保证顺序，`next_seq` 单调推进）、
/// 重复块忽略、Finish 时整体 SHA-256 校验、原子 rename、取消回滚。
///
/// `.part` 文件由本模块直接管理（同步 std fs，块级写入）。
pub struct ChunkReceiver {
    pub transfer_id: u64,
    pub name: String,
    pub size: u64,
    pub total_blocks: u32,
    pub sha256: [u8; 32],
    /// 下一个期望块（单调；断点续传起点）。
    next_seq: u32,
    received_bytes: u64,
    part_path: PathBuf,
    final_path: PathBuf,
    file: Option<std::fs::File>,
    complete: bool,
    committed: bool,
    cancelled: bool,
}

impl ChunkReceiver {
    /// 创建接收器（空白态，等待 Offer）。
    pub fn new(transfer_id: u64) -> Self {
        Self {
            transfer_id,
            name: String::new(),
            size: 0,
            total_blocks: 0,
            sha256: [0u8; 32],
            next_seq: 0,
            received_bytes: 0,
            part_path: PathBuf::new(),
            final_path: PathBuf::new(),
            file: None,
            complete: false,
            committed: false,
            cancelled: false,
        }
    }

    /// Offer 校验（安全层）：文件名消毒 + 大小限制 + 块数一致。
    pub fn validate_offer(
        meta: &FileOfferMeta,
        max_file_size: u64,
    ) -> Result<FileOfferMeta, FileTransferError> {
        let name = sanitize_filename(&meta.name)?;
        if meta.size > max_file_size {
            return Err(FileTransferError::FileTooLarge(meta.size, max_file_size));
        }
        let blocks = total_blocks_for(meta.size);
        if blocks > MAX_BLOCKS {
            return Err(FileTransferError::InvalidBlockCount(blocks));
        }
        Ok(FileOfferMeta {
            name,
            size: meta.size,
        })
    }

    /// 开始接收：落 `.part` 到 `dir`（自动改名目标名）。
    ///
    /// `resume_from`：续传起点（已有 `.part` 的已收进度，通常来自
    /// [`TransferStore`]）；对应 `.part` 文件须由调用方先还原/确认存在。
    ///
    /// S-10a (F-11)：`resume_from` 必须 ≤ 总块数（由 `meta.size` 派生），
    /// 越界直接拒绝——旧实现无条件 `set_len(seq*64KiB)`，u32 极值可制造
    /// 数百 TB 稀疏文件。截断长度同时以 `meta.size` 为上限（非整块文件
    /// 不会把 `.part` 撑大）。
    pub fn begin(
        &mut self,
        meta: &FileOfferMeta,
        dir: &Path,
        sha256: [u8; 32],
        resume_from: u32,
    ) -> Result<(), FileTransferError> {
        let name = sanitize_filename(&meta.name)?;
        let blocks = total_blocks_for(meta.size) as u32;
        if resume_from > blocks {
            return Err(FileTransferError::InvalidResumeOffset(resume_from, blocks));
        }
        // 断点对应的已收字节（不超声明大小）。
        let written = block_offset(resume_from).min(meta.size);
        std::fs::create_dir_all(dir)
            .map_err(|e| FileTransferError::Io(format!("create dir {}: {e}", dir.display())))?;
        // S-10d (F-11)：落盘前检查磁盘剩余空间（尽力而为；平台不支持时跳过）。
        let needed = meta.size.saturating_sub(written);
        if let Some(free) = free_disk_space(dir) {
            if free < needed {
                return Err(FileTransferError::InsufficientDiskSpace(needed, free));
            }
        }
        let final_path = unique_target_path(dir, &name);
        // .part 用最终名 + ".part" 后缀。
        let mut part = final_path.clone();
        let part_name = format!(
            "{}.part",
            final_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| name.clone())
        );
        part.set_file_name(part_name);
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true)
            .write(true)
            .truncate(resume_from == 0)
            .read(true);
        let file = opts
            .open(&part)
            .map_err(|e| FileTransferError::Io(format!("open part {}: {e}", part.display())))?;
        // 续传时截断到已收长度（以 meta.size 为上限，防残留脏数据 +
        // 防稀疏撑大）；已有 `.part` 比断点还短 → 数据缺失，续传必败，拒绝。
        if resume_from > 0 {
            let actual_len = file
                .metadata()
                .map_err(|e| FileTransferError::Io(format!("part metadata: {e}")))?
                .len();
            if actual_len < written {
                return Err(FileTransferError::Io(format!(
                    "part file {} shorter ({actual_len}) than resume offset {written}",
                    part.display()
                )));
            }
            if written > 0 {
                file.set_len(written)
                    .map_err(|e| FileTransferError::Io(format!("truncate part: {e}")))?;
            }
        }
        self.name = name;
        self.size = meta.size;
        self.total_blocks = blocks;
        self.sha256 = sha256;
        self.next_seq = resume_from;
        self.received_bytes = written;
        self.part_path = part;
        self.final_path = final_path;
        self.file = Some(file);
        // 空文件（0 块）或断点已全收 → 视为完整，直接等 Finish 校验。
        self.complete = blocks == 0 || resume_from >= blocks;
        Ok(())
    }

    /// 接收一个数据块（顺序写入 `.part`）。
    ///
    /// 返回 `Ok(true)` = 重复块（已收，忽略未写）；`Ok(false)` = 正常写入。
    pub fn on_data(&mut self, seq: u32, data: &[u8]) -> Result<bool, FileTransferError> {
        if self.cancelled {
            return Err(FileTransferError::Cancelled);
        }
        if seq < self.next_seq {
            return Ok(true); // 重传/重复块：忽略，不落盘。
        }
        if seq > self.next_seq {
            return Err(FileTransferError::OutOfOrder(seq, self.next_seq));
        }
        let expected_len = block_len(seq, self.size);
        if data.len() as u64 != expected_len as u64 {
            return Err(FileTransferError::Io(format!(
                "block {seq} length mismatch: got {}, expected {expected_len}",
                data.len()
            )));
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| FileTransferError::Io("no part file".into()))?;
        use std::io::{Seek, SeekFrom, Write};
        file.seek(SeekFrom::Start(block_offset(seq)))
            .map_err(|e| FileTransferError::Io(format!("seek part: {e}")))?;
        file.write_all(data)
            .map_err(|e| FileTransferError::Io(format!("write part: {e}")))?;
        self.received_bytes += data.len() as u64;
        self.next_seq += 1;
        if self.next_seq >= self.total_blocks {
            self.complete = true;
        }
        Ok(false)
    }

    /// 是否所有块已收齐。
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// 已收字节数。
    pub fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// 进度 (已收, 总)。
    pub fn progress(&self) -> (u64, u64) {
        (self.received_bytes, self.size)
    }

    /// 续传进度（持久化用）。
    pub fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// 当前 `.part` 路径。
    pub fn part_path(&self) -> &Path {
        &self.part_path
    }

    /// 整体 SHA-256 校验（与 Offer 声明比对）。
    pub fn verify(&self) -> Result<(), FileTransferError> {
        if !self.complete {
            return Err(FileTransferError::Io("not complete".into()));
        }
        if self.received_bytes != self.size {
            return Err(FileTransferError::Io(format!(
                "size mismatch: received {}, declared {}",
                self.received_bytes, self.size
            )));
        }
        let actual = sha256_file(&self.part_path)?;
        if actual != self.sha256 {
            return Err(FileTransferError::ChecksumMismatch);
        }
        Ok(())
    }

    /// 原子落盘：`.part` → 最终名（校验通过后由上层调用）。
    pub fn commit(&mut self) -> Result<PathBuf, FileTransferError> {
        if self.committed {
            return Ok(self.final_path.clone());
        }
        // 关闭句柄后才能 rename。
        self.file.take();
        std::fs::rename(&self.part_path, &self.final_path).map_err(|e| {
            FileTransferError::Io(format!(
                "rename {} → {}: {e}",
                self.part_path.display(),
                self.final_path.display()
            ))
        })?;
        self.committed = true;
        Ok(self.final_path.clone())
    }

    /// 取消回滚：删除 `.part`（FT-SEC-006 无残留泄漏）。
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.file.take();
        let _ = std::fs::remove_file(&self.part_path);
    }

    /// 是否已取消。
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// 最终路径（完成/提交后有效）。
    pub fn final_path(&self) -> Option<&Path> {
        if self.committed {
            Some(&self.final_path)
        } else {
            None
        }
    }

    /// 目标路径（Accept 时告知 UI 的落盘名）。
    pub fn target_path(&self) -> &Path {
        &self.final_path
    }
}

impl Drop for ChunkReceiver {
    fn drop(&mut self) {
        // 未完成也未提交 → 清句柄（不删 .part：断点续传保留）。
        self.file.take();
    }
}

// ════════════════════════════════════════════════════════════════
// SessionQuota — 会话级传输配额（S-10b）
// ════════════════════════════════════════════════════════════════

/// S-10b (F-11)：会话级传输配额——单会话累计字节 + 文件数双上限。
///
/// 语义：每个新 Offer 在接受前 `try_reserve(meta.size)`，超限 → 拒绝；
/// 传输取消/失败（未完成）时 `release(size)` 归还预算。
/// `max_bytes == 0` 表示字节不设限；`max_files == 0` 表示文件数不设限。
///
/// 默认值 [`DEFAULT_SESSION_MAX_BYTES`]（4 GiB，与单文件上限一致，
/// 单文件整传恰好占满预算，不误伤正常大文件）+
/// [`DEFAULT_SESSION_MAX_FILES`]（64 个）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionQuota {
    max_bytes: u64,
    max_files: u64,
    reserved_bytes: u64,
    reserved_files: u64,
}

impl SessionQuota {
    /// 创建配额（`0` = 该维度不设限）。
    pub fn new(max_bytes: u64, max_files: u64) -> Self {
        Self {
            max_bytes,
            max_files,
            reserved_bytes: 0,
            reserved_files: 0,
        }
    }

    /// 预留一个文件（`size` 字节）。字节或文件数任一超限 → 拒绝（不扣减）。
    pub fn try_reserve(&mut self, size: u64) -> Result<(), FileTransferError> {
        if self.max_files > 0 && self.reserved_files >= self.max_files {
            return Err(FileTransferError::SessionFilesExceeded(
                self.reserved_files,
                self.max_files,
            ));
        }
        if self.max_bytes > 0 {
            let remaining = self.max_bytes.saturating_sub(self.reserved_bytes);
            if size > remaining {
                return Err(FileTransferError::SessionBytesExceeded(
                    self.reserved_bytes,
                    self.max_bytes,
                ));
            }
        }
        self.reserved_bytes += size;
        self.reserved_files += 1;
        Ok(())
    }

    /// 归还预算（取消/失败时调用；饱和减，防溢出）。
    pub fn release(&mut self, size: u64) {
        self.reserved_bytes = self.reserved_bytes.saturating_sub(size);
        self.reserved_files = self.reserved_files.saturating_sub(1);
    }

    /// 已预留字节。
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    /// 已预留文件数。
    pub fn reserved_files(&self) -> u64 {
        self.reserved_files
    }

    /// 剩余可用字节（`max_bytes == 0` → u64::MAX 表示不设限）。
    pub fn remaining_bytes(&self) -> u64 {
        if self.max_bytes == 0 {
            u64::MAX
        } else {
            self.max_bytes.saturating_sub(self.reserved_bytes)
        }
    }

    /// 剩余可用文件数（`max_files == 0` → u64::MAX 表示不设限）。
    pub fn remaining_files(&self) -> u64 {
        if self.max_files == 0 {
            u64::MAX
        } else {
            self.max_files.saturating_sub(self.reserved_files)
        }
    }
}

// ════════════════════════════════════════════════════════════════
// TransferScheduler — 会话内并发任务队列（≤3，FIFO）
// ════════════════════════════════════════════════════════════════

/// 并发任务调度：活跃任务 ≤ [`MAX_CONCURRENT`]，超量入队 FIFO；
/// 队列长度上限 [`MAX_QUEUE_LEN`]（S-10c/F-11：满则拒绝入队）。
///
/// 发送与接收各持一个实例（收发并发互不干扰）。
#[derive(Debug, Default)]
pub struct TransferScheduler<T> {
    queue: VecDeque<T>,
    active: usize,
}

impl<T> TransferScheduler<T> {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            active: 0,
        }
    }

    /// 入队（若活跃未满则立即出队返回）。队列已满（≥ [`MAX_QUEUE_LEN`]）
    /// 时**拒绝入队**（丢弃该任务，返回 `false`）——防恶意 Offer 撑爆内存。
    ///
    /// 需要显式拒绝语义（如回 Reject 帧）时用 [`Self::try_push`]。
    pub fn push(&mut self, item: T) -> bool {
        if self.queue.len() >= MAX_QUEUE_LEN {
            return false;
        }
        self.queue.push_back(item);
        true
    }

    /// 入队并返回显式结果：队列满 → [`FileTransferError::QueueFull`]。
    pub fn try_push(&mut self, item: T) -> Result<(), FileTransferError> {
        if self.queue.len() >= MAX_QUEUE_LEN {
            return Err(FileTransferError::QueueFull(MAX_QUEUE_LEN));
        }
        self.queue.push_back(item);
        Ok(())
    }

    /// 取出下一个可运行任务（活跃 < 上限时出队）。
    pub fn pop_ready(&mut self) -> Option<T> {
        if self.active >= MAX_CONCURRENT {
            return None;
        }
        let item = self.queue.pop_front()?;
        self.active += 1;
        Some(item)
    }

    /// 一个任务完成/失败/取消后调用，归还并发槽位。
    pub fn finish_one(&mut self) {
        self.active = self.active.saturating_sub(1);
    }

    /// 活跃任务数。
    pub fn active(&self) -> usize {
        self.active
    }

    /// 排队任务数。
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// 是否还有排队任务。
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }
}

// ════════════════════════════════════════════════════════════════
// TransferStore — transfers.json 断点状态持久化（仅元数据）
// ════════════════════════════════════════════════════════════════

/// 持久化的单任务元数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTransfer {
    pub transfer_id: u64,
    pub name: String,
    pub size: u64,
    /// 方向："send"（本端发送）/ "recv"（本端接收）。
    pub direction: String,
    /// 断点：下一块序号。
    pub next_seq: u32,
    /// 整文件 SHA-256（续传核对）。
    pub sha256: Option<[u8; 32]>,
    /// 接收侧 `.part` 路径。
    pub part_path: Option<String>,
}

/// transfers.json 存储（load 容 NotFound，save 幂等，仿 devices.json 模式）。
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TransferStore {
    pub transfers: Vec<StoredTransfer>,
}

impl TransferStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 从 JSON 加载；文件不存在 → 空存储。
    pub fn load_from(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                serde_json::from_str(&content).map_err(|e| format!("transfers.json parse: {e}"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(format!("transfers.json read: {e}")),
        }
    }

    /// 保存为 pretty JSON（创建父目录）。
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create dir: {e}"))?;
        }
        let content = serde_json::to_string_pretty(self).map_err(|e| format!("serialize: {e}"))?;
        std::fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))
    }

    pub fn find(&self, transfer_id: u64) -> Option<&StoredTransfer> {
        self.transfers.iter().find(|t| t.transfer_id == transfer_id)
    }

    pub fn find_mut(&mut self, transfer_id: u64) -> Option<&mut StoredTransfer> {
        self.transfers
            .iter_mut()
            .find(|t| t.transfer_id == transfer_id)
    }

    /// 新增或更新（按 transfer_id 去重）。
    pub fn upsert(&mut self, entry: StoredTransfer) {
        if let Some(existing) = self.find_mut(entry.transfer_id) {
            *existing = entry;
        } else {
            self.transfers.push(entry);
        }
    }

    /// 删除记录。
    pub fn remove(&mut self, transfer_id: u64) {
        self.transfers.retain(|t| t.transfer_id != transfer_id);
    }

    /// 清理孤儿记录（`part_path` 文件已不存在且未完成）。
    pub fn prune_missing(&mut self) {
        self.transfers.retain(|t| match &t.part_path {
            Some(p) => Path::new(p).exists(),
            None => true,
        });
    }
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    // ---- transfer_id 派生 ----

    #[test]
    fn test_transfer_id_stable_and_salted() {
        let a = derive_transfer_id("report.pdf", 1024, "salt-1");
        let b = derive_transfer_id("report.pdf", 1024, "salt-1");
        let c = derive_transfer_id("report.pdf", 1024, "salt-2");
        let d = derive_transfer_id("report.pdf", 2048, "salt-1");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    // ---- 路径消毒（FT-SEC-001）----

    #[test]
    fn test_sanitize_accepts_plain_names() {
        for name in [
            "report.pdf",
            "中文报告.pdf",
            "a b.txt",
            "with-dash_under.1",
            "CONFIG.toml", // 非保留名（CONFIG 不是 CON）
        ] {
            assert_eq!(sanitize_filename(name).unwrap(), name);
        }
    }

    #[test]
    fn test_sanitize_rejects_traversal() {
        for name in [
            "..\\..\\evil",
            "../../evil",
            "..",
            "...",
            "/etc/passwd",
            "\\windows\\system32",
            "C:\\evil.exe",
            "c:/evil.exe",
            "dir/file.txt",
            "a\\b",
        ] {
            assert!(sanitize_filename(name).is_err(), "should reject {name:?}");
        }
    }

    #[test]
    fn test_sanitize_rejects_illegal_chars() {
        for name in [
            "a<b",
            "a>b",
            "a:b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
            "a\0b",
            "line\nbreak",
            "trailing.",
            "trailing ",
            "CON",
            "NUL",
            "COM1",
            "LPT9.txt",
            "",
            "    ",
        ] {
            assert!(sanitize_filename(name).is_err(), "should reject {name:?}");
        }
    }

    // ---- 分块计算 ----

    #[test]
    fn test_block_calcs() {
        assert_eq!(total_blocks_for(0), 0);
        assert_eq!(total_blocks_for(1), 1);
        assert_eq!(total_blocks_for(BLOCK_SIZE), 1);
        assert_eq!(total_blocks_for(BLOCK_SIZE + 1), 2);
        assert_eq!(total_blocks_for(4 * 1024 * 1024), 64);
        assert_eq!(block_len(0, BLOCK_SIZE), BLOCK_SIZE as usize);
        assert_eq!(block_len(1, BLOCK_SIZE + 5), 5);
        assert_eq!(block_len(2, BLOCK_SIZE + 5), 0);
        assert!(validate_block_count(BLOCK_SIZE + 5, 2).is_ok());
        assert!(validate_block_count(BLOCK_SIZE + 5, 3).is_err());
    }

    // ---- 目标路径去重 ----

    #[test]
    fn test_unique_target_path() {
        let dir = std::env::temp_dir().join(format!("kirin_ft_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 同名不存在 → 原名。
        let p1 = unique_target_path(&dir, "x.txt");
        assert_eq!(p1.file_name().unwrap().to_string_lossy(), "x.txt");
        // 已存在 → 改名 (1)。
        std::fs::write(p1, b"a").unwrap();
        let p2 = unique_target_path(&dir, "x.txt");
        assert_eq!(p2.file_name().unwrap().to_string_lossy(), "x (1).txt");
        std::fs::write(&p2, b"b").unwrap();
        let p3 = unique_target_path(&dir, "x.txt");
        assert_eq!(p3.file_name().unwrap().to_string_lossy(), "x (2).txt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- SlideWindowSender ----

    fn make_sender(size: u64) -> SlideWindowSender {
        SlideWindowSender::new(
            derive_transfer_id("f.bin", size, "test"),
            "f.bin".into(),
            size,
            [0xAB; 32],
        )
        .unwrap()
    }

    #[test]
    fn test_sender_accept_and_window() {
        let mut s = make_sender(BLOCK_SIZE * 200); // 200 块
        s.on_accept(0);
        assert_eq!(s.total_blocks(), 200);
        // 窗口 64：可发 64 块后窗口满。
        for _ in 0..WINDOW_SIZE {
            assert!(s.next_unsent_seq().is_some(), "window should have room");
            let seq = s.next_unsent_seq().unwrap();
            s.mark_sent(seq);
        }
        assert!(s.next_unsent_seq().is_none(), "window full at 64");
        // Ack 推进 32 块。
        let advanced = s.on_ack(31);
        assert_eq!(advanced, 32);
        for _ in 0..32 {
            assert!(s.next_unsent_seq().is_some());
            let seq = s.next_unsent_seq().unwrap();
            s.mark_sent(seq);
        }
        assert!(s.next_unsent_seq().is_none());
        assert_eq!(s.progress().0, 32 * BLOCK_SIZE);
        assert!(!s.is_complete());
    }

    #[test]
    fn test_sender_ack_all_completes() {
        let mut s = make_sender(BLOCK_SIZE * 5);
        s.on_accept(0);
        for _ in 0..5 {
            let seq = s.next_unsent_seq().unwrap();
            s.mark_sent(seq);
        }
        assert!(!s.is_complete());
        let advanced = s.on_ack(4);
        assert_eq!(advanced, 5);
        assert!(s.is_complete());
        assert!(s.all_acked());
    }

    #[test]
    fn test_sender_nack_retransmit() {
        let mut s = make_sender(BLOCK_SIZE * 70);
        s.on_accept(0);
        // 填满窗口（64 块）。
        for _ in 0..WINDOW_SIZE {
            let seq = s.next_unsent_seq().unwrap();
            s.mark_sent(seq);
        }
        assert!(s.next_unsent_seq().is_none(), "window full at 64");
        // Nack 块 2 → 优先重传区重新可发。
        s.on_nack(2);
        assert_eq!(s.next_unsent_seq(), Some(2));
        s.mark_sent(2);
        assert!(s.next_unsent_seq().is_none(), "window full again");
        // Ack 推进 32 块 → 窗口腾位，新块 64 可发。
        let advanced = s.on_ack(31);
        assert_eq!(advanced, 32);
        assert_eq!(s.acked_count, 32);
        assert_eq!(s.next_unsent_seq(), Some(64));
        s.mark_sent(64);
        assert_eq!(s.resume_seq(), 32);
    }

    #[test]
    fn test_sender_timeout_retransmit() {
        let mut s = make_sender(BLOCK_SIZE * 5);
        s.on_accept(0);
        for _ in 0..5 {
            let seq = s.next_unsent_seq().unwrap();
            s.mark_sent(seq);
        }
        let future = Instant::now() + BLOCK_TIMEOUT + StdDuration::from_millis(1);
        let due = s.retransmit_due(future);
        assert_eq!(due.len(), 5);
        assert!(due.contains(&0) && due.contains(&4));
    }

    #[test]
    fn test_sender_pause_resume_cancel() {
        let mut s = make_sender(BLOCK_SIZE * 5);
        s.on_accept(0);
        assert_eq!(s.status(), TransferStatus::Sending);
        s.pause();
        assert_eq!(s.status(), TransferStatus::Paused);
        assert!(s.next_unsent_seq().is_none(), "paused: no new blocks");
        s.resume();
        assert!(s.next_unsent_seq().is_some());
        s.cancel();
        assert_eq!(s.status(), TransferStatus::Cancelled);
        assert!(s.next_unsent_seq().is_none());
    }

    #[test]
    fn test_sender_resume_negotiation() {
        // 发送方断点在块 20，接收方已有 15 → 从 20 续发。
        let mut s = make_sender(BLOCK_SIZE * 100);
        s.local_resume_seq = 20;
        s.on_accept(15);
        assert_eq!(s.next_unsent_seq(), Some(20));
        assert_eq!(s.resume_seq(), 20);
        // 接收方进度更靠前（30）→ 从 30 续发。
        let mut s2 = make_sender(BLOCK_SIZE * 100);
        s2.local_resume_seq = 20;
        s2.on_accept(30);
        assert_eq!(s2.next_unsent_seq(), Some(30));
        // 全部已收 → 直接完成态（不再发块）。
        let mut s3 = make_sender(BLOCK_SIZE * 100);
        s3.on_accept(100);
        assert!(s3.next_unsent_seq().is_none());
    }

    #[test]
    fn test_sender_idle_timeout() {
        let mut s = make_sender(BLOCK_SIZE * 5);
        s.on_accept(0);
        let seq = s.next_unsent_seq().unwrap();
        s.mark_sent(seq);
        assert!(!s.idle_timeout(Instant::now()));
        let far = Instant::now() + IDLE_TIMEOUT + StdDuration::from_millis(1);
        assert!(s.idle_timeout(far));
    }

    // ---- ChunkReceiver ----

    /// 构造一个随机内容文件并返回 (路径, 内容, sha256)。
    fn make_source_file(dir: &Path, name: &str, size: u64) -> (PathBuf, Vec<u8>, [u8; 32]) {
        let path = dir.join(name);
        let mut rng = 0x1234_5678u64;
        let mut content = Vec::new();
        while (content.len() as u64) < size {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            content.push((rng >> 33) as u8);
        }
        std::fs::write(&path, &content).unwrap();
        let sha = sha256_bytes(&content);
        (path, content, sha)
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kirin_ft_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 模拟发送方发完整文件（含分块）。
    fn send_file_via_receiver(
        recv: &mut ChunkReceiver,
        content: &[u8],
    ) -> Result<(), FileTransferError> {
        let size = content.len() as u64;
        let blocks = total_blocks_for(size);
        for seq in 0..blocks as u32 {
            let off = block_offset(seq);
            let len = block_len(seq, size);
            let data = &content[off as usize..(off as usize + len)];
            recv.on_data(seq, data)?;
        }
        Ok(())
    }

    #[test]
    fn test_receiver_reassembly_and_commit() {
        let dir = tmp_dir("reassembly");
        let src_dir = dir.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        let (src, content, sha) = make_source_file(&src_dir, "big.bin", BLOCK_SIZE * 3 + 1234);
        let size = content.len() as u64;
        let meta = FileOfferMeta {
            name: "big.bin".into(),
            size,
        };
        // 校验通过。
        let checked = ChunkReceiver::validate_offer(&meta, DEFAULT_MAX_FILE_SIZE).unwrap();
        assert_eq!(checked.name, "big.bin");
        // 接收（源目录与接收目录分离，避免同名改名干扰）。
        let mut recv = ChunkReceiver::new(derive_transfer_id("big.bin", size, "test"));
        recv.begin(&meta, &dir, sha, 0).unwrap();
        send_file_via_receiver(&mut recv, &content).unwrap();
        assert!(recv.is_complete());
        assert_eq!(recv.progress(), (size, size));
        // 整体校验 + 原子落盘。
        recv.verify().unwrap();
        let final_path = recv.commit().unwrap();
        assert_eq!(final_path.file_name().unwrap().to_string_lossy(), "big.bin");
        assert_eq!(sha256_file(&final_path).unwrap(), sha);
        assert_eq!(std::fs::read(&final_path).unwrap(), content);
        // 无 .part 残留。
        assert!(!recv.part_path().exists());
        let _ = src;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_receiver_duplicate_blocks_ignored() {
        let dir = tmp_dir("duplicate");
        let (_, content, sha) = make_source_file(&dir, "dup.bin", BLOCK_SIZE * 2);
        let size = content.len() as u64;
        let meta = FileOfferMeta {
            name: "dup.bin".into(),
            size,
        };
        let mut recv = ChunkReceiver::new(1);
        recv.begin(&meta, &dir, sha, 0).unwrap();
        recv.on_data(0, &content[..BLOCK_SIZE as usize]).unwrap();
        // 重复块 0 → 忽略不落盘。
        let dup = recv.on_data(0, &content[..BLOCK_SIZE as usize]).unwrap();
        assert!(dup);
        assert_eq!(recv.next_seq(), 1);
        // 乱序（跳号）→ 错误。
        assert!(recv
            .on_data(2, &content[2 * BLOCK_SIZE as usize..])
            .is_err());
        // 顺序完成。
        recv.on_data(1, &content[BLOCK_SIZE as usize..]).unwrap();
        recv.verify().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_receiver_tamper_detected() {
        let dir = tmp_dir("tamper");
        let (_, mut content, sha) = make_source_file(&dir, "t.bin", BLOCK_SIZE * 2);
        let size = content.len() as u64;
        let meta = FileOfferMeta {
            name: "t.bin".into(),
            size,
        };
        let mut recv = ChunkReceiver::new(1);
        recv.begin(&meta, &dir, sha, 0).unwrap();
        // 篡改块 1 的一个字节（模拟中间人/损坏）。
        let idx = (BLOCK_SIZE + 10) as usize;
        content[idx] ^= 0xFF;
        send_file_via_receiver(&mut recv, &content).unwrap();
        assert!(recv.is_complete());
        assert!(matches!(
            recv.verify(),
            Err(FileTransferError::ChecksumMismatch)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_receiver_resume_and_cancel() {
        let dir = tmp_dir("resume");
        let (_, content, sha) = make_source_file(&dir, "r.bin", BLOCK_SIZE * 4);
        let size = content.len() as u64;
        let meta = FileOfferMeta {
            name: "r.bin".into(),
            size,
        };
        // 第一段：收到前 2 块后中断（模拟进程被杀），.part 保留。
        let mut recv = ChunkReceiver::new(7);
        recv.begin(&meta, &dir, sha, 0).unwrap();
        recv.on_data(0, &content[..BLOCK_SIZE as usize]).unwrap();
        recv.on_data(1, &content[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize])
            .unwrap();
        let resume_from = recv.next_seq();
        assert_eq!(resume_from, 2);
        assert!(recv.part_path().exists());
        // Drop（连接断开）。
        drop(recv);
        // 重连：新接收器从断点续收（同一 .part 文件，截断到已收长度）。
        let part = dir.join("r (1).bin.part");
        let mut recv2 = ChunkReceiver::new(7);
        recv2.begin(&meta, &dir, sha, resume_from).unwrap();
        assert_eq!(recv2.next_seq(), 2);
        // 续发剩余块。
        send_file_via_receiver(&mut recv2, &content).unwrap();
        assert_eq!(recv2.next_seq(), 4);
        recv2.verify().unwrap();
        let final_path = recv2.commit().unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), content);
        assert!(!part.exists());
        let _ = std::fs::remove_dir_all(&dir);

        // 取消 → .part 删除。
        let dir2 = tmp_dir("cancel");
        let (_, content2, sha2) = make_source_file(&dir2, "c.bin", BLOCK_SIZE * 2);
        let size2 = content2.len() as u64;
        let meta2 = FileOfferMeta {
            name: "c.bin".into(),
            size: size2,
        };
        let mut recv3 = ChunkReceiver::new(8);
        recv3.begin(&meta2, &dir2, sha2, 0).unwrap();
        recv3.on_data(0, &content2[..BLOCK_SIZE as usize]).unwrap();
        let part = recv3.part_path().to_path_buf();
        assert!(part.exists());
        recv3.cancel();
        assert!(!part.exists());
        assert!(recv3.is_cancelled());
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn test_receiver_size_limits() {
        // 超限文件在 Offer 阶段即拒绝（FT-SEC-002）。
        let meta = FileOfferMeta {
            name: "huge.bin".into(),
            size: 5 * 1024 * 1024 * 1024,
        };
        let err = ChunkReceiver::validate_offer(&meta, DEFAULT_MAX_FILE_SIZE).unwrap_err();
        assert!(matches!(err, FileTransferError::FileTooLarge(_, _)));
        // 可配置限制。
        let meta2 = FileOfferMeta {
            name: "ok.bin".into(),
            size: 1024,
        };
        let err2 = ChunkReceiver::validate_offer(&meta2, 512).unwrap_err();
        assert!(matches!(err2, FileTransferError::FileTooLarge(_, _)));
    }

    // ---- S-10a: resume_from 越界校验（F-11）----

    #[test]
    fn test_begin_rejects_resume_out_of_range() {
        // S-10a：resume_from > total_blocks → 拒绝（旧实现直接
        // set_len(seq*64KiB)，u32 极值可造数百 TB 稀疏文件）。
        let dir = tmp_dir("resume_guard");
        let size = BLOCK_SIZE * 2;
        let meta = FileOfferMeta {
            name: "g.bin".into(),
            size,
        };
        let mut recv = ChunkReceiver::new(1);
        let err = recv.begin(&meta, &dir, [0u8; 32], 3).unwrap_err();
        assert!(matches!(err, FileTransferError::InvalidResumeOffset(3, 2)));
        // u32 极值 → 拒绝。
        let mut recv2 = ChunkReceiver::new(2);
        let err2 = recv2
            .begin(&meta, &dir, [0u8; 32], u32::MAX)
            .unwrap_err();
        assert!(matches!(err2, FileTransferError::InvalidResumeOffset(_, 2)));
        // 拒绝时不创建任何 .part 文件。
        assert!(!dir.join("g.bin.part").exists(), "no part file created");
        // 0 字节文件（0 块）：resume_from=0 合法；>0 拒绝。
        let meta0 = FileOfferMeta {
            name: "z.bin".into(),
            size: 0,
        };
        let mut recv4 = ChunkReceiver::new(4);
        let err4 = recv4.begin(&meta0, &dir, [0u8; 32], 1).unwrap_err();
        assert!(matches!(err4, FileTransferError::InvalidResumeOffset(1, 0)));
        recv4.begin(&meta0, &dir, [0u8; 32], 0).unwrap();
        // 边界：resume_from == total_blocks 合法（.part 数据齐备 → 等 Finish 校验）。
        let (_, content, sha) = make_source_file(&dir, "src_ok.bin", size);
        let meta_ok = FileOfferMeta {
            name: "ok.bin".into(),
            size,
        };
        {
            let mut phase1 = ChunkReceiver::new(3);
            phase1.begin(&meta_ok, &dir, sha, 0).unwrap();
            send_file_via_receiver(&mut phase1, &content).unwrap();
        } // drop：.part 保留。
        let mut recv3 = ChunkReceiver::new(3);
        recv3.begin(&meta_ok, &dir, sha, 2).unwrap();
        assert!(recv3.is_complete());
        assert_eq!(recv3.next_seq(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_begin_resume_never_exceeds_declared_size() {
        // S-10a 核心：set_len/已收字节以 meta.size 为上限——旧实现对非整块
        // 对齐文件（BLOCK+100）resume_from==total_blocks 时 set_len(2*64KiB)
        // 把 .part 撑到 131072 且 received_bytes 虚高（整体校验必败）。
        let dir = tmp_dir("resume_clamp");
        let size = BLOCK_SIZE + 100; // 2 块，非整块对齐。
        let (_, content, sha) = make_source_file(&dir, "src_c.bin", size);
        let meta = FileOfferMeta {
            name: "c.bin".into(),
            size,
        };
        // 阶段 1：收完全部 2 块（.part 长度 = size）。
        {
            let mut phase1 = ChunkReceiver::new(5);
            phase1.begin(&meta, &dir, sha, 0).unwrap();
            send_file_via_receiver(&mut phase1, &content).unwrap();
            assert!(phase1.is_complete());
        } // drop：.part 保留。
        // 阶段 2：从断点 2（== total_blocks）续传 → 截断长度被钳制到 size。
        let mut recv = ChunkReceiver::new(5);
        recv.begin(&meta, &dir, sha, 2).unwrap();
        assert!(recv.is_complete());
        assert_eq!(recv.received_bytes(), size, "received_bytes clamped to size");
        assert_eq!(
            std::fs::metadata(recv.part_path()).unwrap().len(),
            size,
            "part exactly {size} bytes, not 131072"
        );
        // 合法续传不回归：整体 SHA-256 校验通过并原子落盘。
        recv.verify().unwrap();
        let final_path = recv.commit().unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), content);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_begin_rejects_resume_with_shorter_part() {
        // 已有 .part 实际长度 < 断点声明的已收字节 → 数据缺失，续传必败，
        // begin 提前拒绝（不静默 set_len 补零）。
        let dir = tmp_dir("resume_short");
        let size = BLOCK_SIZE * 4;
        let meta = FileOfferMeta {
            name: "s.bin".into(),
            size,
        };
        let (_, content, sha) = make_source_file(&dir, "s_src.bin", size);
        // 阶段 1：只收到 1 块。
        let mut recv = ChunkReceiver::new(7);
        recv.begin(&meta, &dir, sha, 0).unwrap();
        recv.on_data(0, &content[..BLOCK_SIZE as usize]).unwrap();
        drop(recv);
        // 阶段 2：store 声称断点 3（实际只有 1 块数据）→ 拒绝。
        let mut recv2 = ChunkReceiver::new(7);
        let err = recv2.begin(&meta, &dir, sha, 3).unwrap_err();
        assert!(matches!(err, FileTransferError::Io(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- SessionQuota (S-10b) ----

    #[test]
    fn test_session_quota_bytes_and_files() {
        let mut q = SessionQuota::new(100, 3);
        assert_eq!(q.remaining_bytes(), 100);
        assert_eq!(q.remaining_files(), 3);
        q.try_reserve(40).unwrap();
        q.try_reserve(40).unwrap();
        // 字节超限 → 拒绝（不扣减）。
        assert!(matches!(
            q.try_reserve(30),
            Err(FileTransferError::SessionBytesExceeded(80, 100))
        ));
        assert_eq!((q.reserved_bytes(), q.reserved_files()), (80, 2));
        // 释放后恢复。
        q.release(40);
        assert_eq!((q.reserved_bytes(), q.reserved_files()), (40, 1));
        q.try_reserve(30).unwrap(); // bytes 70, files 2
        q.try_reserve(1).unwrap(); // bytes 71, files 3
        // 文件数超限 → 拒绝（第 4 个）。
        assert!(matches!(
            q.try_reserve(1),
            Err(FileTransferError::SessionFilesExceeded(3, 3))
        ));
        assert_eq!((q.reserved_bytes(), q.reserved_files()), (71, 3));
        // release 饱和减，不泄底。
        q.release(999);
        q.release(999);
        q.release(999);
        assert_eq!((q.reserved_bytes(), q.reserved_files()), (0, 0));
    }

    #[test]
    fn test_session_quota_defaults_do_not_hurt_large_files() {
        // 默认值（4 GiB + 64 文件）：单文件整传恰好占满字节预算 → 允许；
        // 再多 1 字节 → 拒绝（验收 §5：不误伤正常大文件传输）。
        let mut q = SessionQuota::new(DEFAULT_SESSION_MAX_BYTES, DEFAULT_SESSION_MAX_FILES);
        assert!(q.try_reserve(DEFAULT_SESSION_MAX_BYTES).is_ok());
        assert!(matches!(
            q.try_reserve(1),
            Err(FileTransferError::SessionBytesExceeded(_, _))
        ));
        // 文件数维度：64 个 1 字节文件 OK，第 65 个拒绝。
        let mut q2 = SessionQuota::new(DEFAULT_SESSION_MAX_BYTES, DEFAULT_SESSION_MAX_FILES);
        for _ in 0..DEFAULT_SESSION_MAX_FILES {
            q2.try_reserve(1).unwrap();
        }
        assert!(matches!(
            q2.try_reserve(1),
            Err(FileTransferError::SessionFilesExceeded(64, 64))
        ));
    }

    #[test]
    fn test_session_quota_zero_means_unlimited() {
        // 0 = 该维度不设限（配置语义）。
        let mut q = SessionQuota::new(0, 0);
        q.try_reserve(1 << 40).unwrap(); // 1 TiB
        q.try_reserve(1 << 40).unwrap();
        assert_eq!(q.remaining_bytes(), u64::MAX);
        assert_eq!(q.remaining_files(), u64::MAX);
        // 只限字节不限文件数。
        let mut q2 = SessionQuota::new(10, 0);
        q2.try_reserve(10).unwrap();
        assert!(matches!(
            q2.try_reserve(1),
            Err(FileTransferError::SessionBytesExceeded(_, _))
        ));
        // 只限文件数不限字节。
        let mut q3 = SessionQuota::new(0, 1);
        q3.try_reserve(10).unwrap();
        assert!(matches!(
            q3.try_reserve(0),
            Err(FileTransferError::SessionFilesExceeded(_, _))
        ));
    }

    // ---- TransferScheduler ----

    #[test]
    fn test_scheduler_concurrency_and_fifo() {
        let mut sched = TransferScheduler::new();
        for i in 0..5 {
            sched.push(i);
        }
        // 前 3 个立即运行（并发 ≤3）。
        let mut got = Vec::new();
        for _ in 0..MAX_CONCURRENT {
            got.push(sched.pop_ready().unwrap());
        }
        assert_eq!(got, vec![0, 1, 2]);
        assert!(sched.pop_ready().is_none(), "concurrency cap reached");
        assert_eq!(sched.queued(), 2);
        // 完成一个 → 下一个 FIFO 出队。
        sched.finish_one();
        assert_eq!(sched.pop_ready(), Some(3));
        sched.finish_one();
        sched.finish_one();
        assert_eq!(sched.pop_ready(), Some(4));
        // 全部出队后：最后两个任务仍在活跃（未 finish）。
        assert_eq!(sched.active(), 2);
        assert!(sched.pop_ready().is_none());
        sched.finish_one();
        sched.finish_one();
        assert_eq!(sched.active(), 0);
    }

    #[test]
    fn test_scheduler_queue_cap() {
        // S-10c (F-11)：队列长度上限 MAX_QUEUE_LEN，满则拒绝入队。
        let mut sched = TransferScheduler::new();
        // 先占满并发槽位（3 个活跃）。
        for i in 0..MAX_CONCURRENT {
            sched.try_push(i).unwrap();
            sched.pop_ready().unwrap();
        }
        // 队列可容纳 MAX_QUEUE_LEN 个。
        for i in 0..MAX_QUEUE_LEN {
            assert!(sched.try_push(i).is_ok(), "queue has room for {i}");
        }
        assert_eq!(sched.queued(), MAX_QUEUE_LEN);
        // 满 → try_push Err(QueueFull)，push 返回 false 且不增长。
        assert!(matches!(
            sched.try_push(999),
            Err(FileTransferError::QueueFull(MAX_QUEUE_LEN))
        ));
        assert!(!sched.push(999));
        assert_eq!(sched.queued(), MAX_QUEUE_LEN);
        // 出队一个 → 恢复可入队（FIFO 顺序保持）。
        sched.finish_one();
        assert_eq!(sched.pop_ready(), Some(0));
        assert!(sched.try_push(42).is_ok());
        assert_eq!(sched.queued(), MAX_QUEUE_LEN);
    }

    // ---- TransferStore ----

    #[test]
    fn test_store_roundtrip() {
        let dir = tmp_dir("store");
        let path = dir.join("transfers.json");
        let mut store = TransferStore::new();
        store.upsert(StoredTransfer {
            transfer_id: 42,
            name: "a.bin".into(),
            size: 12345,
            direction: "recv".into(),
            next_seq: 3,
            sha256: Some([1u8; 32]),
            part_path: Some(dir.join("a.bin.part").to_string_lossy().to_string()),
        });
        store.save_to(&path).unwrap();
        let loaded = TransferStore::load_from(&path).unwrap();
        assert_eq!(loaded.transfers.len(), 1);
        assert_eq!(loaded.transfers[0].transfer_id, 42);
        assert_eq!(loaded.transfers[0].next_seq, 3);
        assert_eq!(loaded.transfers[0].sha256, Some([1u8; 32]));
        // upsert 去重。
        let mut l2 = loaded;
        l2.upsert(StoredTransfer {
            transfer_id: 42,
            name: "a.bin".into(),
            size: 12345,
            direction: "recv".into(),
            next_seq: 4,
            sha256: Some([1u8; 32]),
            part_path: None,
        });
        assert_eq!(l2.transfers.len(), 1);
        assert_eq!(l2.transfers[0].next_seq, 4);
        // remove。
        l2.remove(42);
        assert!(l2.transfers.is_empty());
        // 文件不存在 → 空。
        let missing = TransferStore::load_from(&dir.join("nope.json")).unwrap();
        assert!(missing.transfers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- 帧编解码 ----

    #[test]
    fn test_frame_roundtrip() {
        let frame = FileTransferFrame::offer(
            7,
            &FileOfferMeta {
                name: "x.bin".into(),
                size: 1000,
            },
            1,
            [9u8; 32],
        );
        let bytes = frame.encode().unwrap();
        let decoded = FileTransferFrame::decode(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_sha256_file_matches() {
        let dir = tmp_dir("sha");
        let (path, content, sha) = make_source_file(&dir, "s.bin", 100_000);
        assert_eq!(sha256_file(&path).unwrap(), sha);
        assert_eq!(sha, sha256_bytes(&content));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
