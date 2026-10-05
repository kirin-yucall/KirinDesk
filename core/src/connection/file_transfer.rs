//! 文件传输：帧协议 + 滑窗发送器 + 分片重组接收器 + 断点续传。
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

use super::path_manager::PathKind;
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

///
/// Offer 已发出但**零在途**、对端未回 Accept/Reject（对端接收臂缺失/
/// 会话已拆/帧被丢）→ 超过该窗口判定死链。修复前 [`SlideWindowSender::
/// idle_timeout`] 仅覆盖 `in_flight > 0`，此状态无限挂起、零报错静默。
pub const OFFER_TIMEOUT: Duration = Duration::from_secs(60);

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


/// FS 单请求超时（§1.2）：到期 → 请求方本地判 Timeout（不产生 wire 帧）。
pub const FS_REQ_TIMEOUT: Duration = Duration::from_secs(10);

/// FS 未决请求并发上限（S8：防 UI 刷新自旋与恶意高频探测）。
pub const FS_MAX_PENDING: usize = 8;

/// FS 请求限速（S8：20 req/s 滑动窗，超限回 [`FsErrCode::RateLimited`]）。
pub const FS_RATE_PER_SEC: usize = 20;

/// FS 单响应硬上限 512 KiB（§1.2：list 500 条目 × 条目上限 ≈150KiB 富余；
/// 超限 → List 截断 + `has_more`，其余 op 回 `FsErrCode::Io`）。
pub const FS_RESPONSE_MAX_BYTES: usize = 512 * 1024;

/// FS 路径 wire 上限 512 字节（S6：> → 先于 IO 拒；Win 长路径内核开关未启用时
/// canonicalize 失败走「父目录 canonicalize + 尾组件拼接」回退）。
pub const FS_PATH_MAX_BYTES: usize = 512;

/// FS List 默认条目数（§1.2：limit 默认 500）。
pub const FS_LIST_LIMIT_DEFAULT: u32 = 500;

/// FS List 条目数硬上限（§1.2/S8：limit ≤ 1000）。
pub const FS_LIST_LIMIT_MAX: u32 = 1000;

/// 条目硬上限 255（FILEMETA `MAX_META_ENTRIES` 255 条目先例同口径；超限 =
/// 发送端 UI 拆多请求 = 逐批一框，§8.6）。
pub const TRANSFER_REQUEST_MAX_ENTRIES: usize = 255;

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
    /// bincode 无字段枚举 = 变体索引，0-10 不重排）。
    ///
    /// 帧承载（`FileTransferFrame` 字段布局逐位不变，禁加字段）：
    /// - `transfer_id` 复用承载 `req_id`（会话内单调 u32，高位 0）——该字段在
    /// - `seq`/`total_blocks`/`sha256` = 0（未用）；
    /// - `data` = bincode([`FsRequestPayload`])。
    ///
    /// 旧端收到本帧 = bincode 未知变体 → 单帧解码失败丢弃（既有
    /// `file frame decode failed` 日志锚点），传输帧不受影响（browse 优雅降级）。
    FsRequest = 11,
    ///
    /// `transfer_id` = 对应请求的 `req_id`；`data` = bincode([`FsResponsePayload`])。
    FsResponse = 12,
    /// Offer 变体，**尾追加**（判别值 13；既有 0-12 字节零变化，判别值钉死
    /// 测试扩展 §12.6-8 同族）。
    ///
    /// 帧承载（`FileTransferFrame` 布局零变化——§12.7 verbatim「避免破既有
    /// 布局」）：`data` = bincode([`FileOfferV2Meta`])（**独立于 v1**
    /// [`FileOfferMeta`]=仅 name+size，v1 struct 零改动）；`sha256` = 整文件
    /// SHA-256（与 v1 Offer 同）；`total_blocks` = 块数（同 v1）。
    ///
    /// **版本语义（§12.2/§12.7，D-4）**：仅对 peer `proto_ver == 3` 发送
    ///（0x06 与 shell 双载体同帧体，§12.7 wire 路径）；旧端收到本帧 =
    /// bincode 未知变体 → 单帧解码失败丢弃（0x06 既有行为，§8）；shell
    /// 通道由版本门控根本不发（§12.3-3）。
    OfferV2 = 13,
    /// 状态通告，**尾追加**（判别值 14；既有 0-13 字节零变化，判别值钉死
    /// 测试同族扩展）。
    ///
    /// **语义** = 服务端角色（受控端）向客户端角色通告**自身**两权限开关
    /// （`clipboard_allowed` / `file_transfer_allowed`），客户端按**对端值**
    /// 做会话内剪贴板门控与文件传输窗/会话窗提示展示（「权限判定与提示
    /// 以对端受控机设置为准」——用户指正点 = 旧实现读客户端所在设备自身
    /// server 配置）。值源 = 服务端 FileSession 构造 consent 快照
    ///
    /// 帧承载（`FileTransferFrame` 字段布局逐位不变，禁加字段）：
    /// `transfer_id`/`seq`/`total_blocks`/`sha256` = 0（未用）；
    /// `data` = bincode([`PeerConsentPayload`])。
    ///
    /// **版本语义（D-4 同族）**：仅对 peer `proto_ver == 3` 发送（发送侧
    /// 显式版本门 + shell 通道 `send_frame` 既有门，legacy-0 零发送
    /// fail-closed）；旧端收到本帧 = bincode 未知变体 → 单帧解码失败丢弃
    ///（既有 `file frame decode failed` 日志锚点，会话存活，与 FsRequest/
    /// OfferV2 同构）；新端收不到旧端本帧 = 对端态未知 = **fail-closed 按
    /// OFF** + 显式提示（红线⑤，不静默放行）。
    PeerConsent = 14,
}

/// op = [`FileOp::PeerConsent`]）。字段序钉死（bincode 位置格式，单测
/// 回环）；`clipboard_allowed` 在前（消费侧 = s→c 剪贴板门控主路径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConsentPayload {
    /// 对端（受控端）`[file_transfer].clipboard_allowed` 开关态。
    pub clipboard_allowed: bool,
    /// 对端（受控端）`[file_transfer].file_transfer_allowed` 开关态。
    pub file_transfer_allowed: bool,
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

/// [`FileOfferMeta`]，v1 struct 零改动；bincode 置于
/// [`FileOp::OfferV2`] 帧的 `data`）。
///
/// 字段语义（§12.7 表，verbatim 落定）：
/// - `name`：文件名（与 v1 meta 同；[`sanitize_filename`] 保留名表链适用）；
/// - `size`：文件大小（与 v1 meta 同；4GiB 上限 / 配额 / 写根门链适用）；
/// - `target_dir`：**客户端指定远端落盘目录**（shell 会话远端栏当前目录，
///   **root 相对路径**；服务端 [`sanitize_fs_path`] 全链回检 S1-S6 + 写根门
///   [`check_write_root_gate`] 适用，列外 = `Reject` 原因可读 /
///   [`FsErrCode::PathOutsideRoot`] 码）；
/// - `overwrite`：**「真覆盖」语义**（=true 目标已存在 = 覆盖写——v1 结构上
///   静默覆盖不可能〔§1.5 S13 ② 恒 [`unique_target_path`] 自动改名〕，本
///   字段即 v2 正解）；=false → [`unique_target_path`] 自动改名（v1 同口径
///   保守回退）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOfferV2Meta {
    pub name: String,
    pub size: u64,
    pub target_dir: String,
    pub overwrite: bool,
}

// ────────────────────────────────────────────────────────────
// ────────────────────────────────────────────────────────────

/// FS 请求负载（bincode 置于 `FileTransferFrame::data`，op = [`FileOp::FsRequest`]）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsRequestPayload {
    pub op: FsOp,
}

/// `TransferRequest`；bincode 枚举，同尾追加纪律）。
///
/// 上传（⬆）不走 FsOp——走既有 Offer 管线（K1 写权限作用于服务端落盘点）；
/// `Fetch` = 服务端读（⬇ wire 触发：消毒全链后复用发送管线对该文件发起 Offer）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsOp {
    /// 列目录。`limit` 默认 500、硬上限 1000（`FS_LIST_LIMIT_MAX`）；
    /// 空路径 `""` = 根（§1.3）。
    List { path: String, offset: u32, limit: u32 },
    /// 元数据。空路径 `""` = 根本身（返回根条目元数据）。
    Stat { path: String },
    /// 建目录（单级，无 `-p` 语义；父目录不存在 → NotFound）。
    Mkdir { path: String },
    /// 改名。目标已存在 → [`FsErrCode::AlreadyExists`]（v1 跨平台统一，S13）。
    Rename { from: String, to: String },
    /// 删除。目标为符号链接 → [`FsErrCode::NotSupported`]（v1 不跟随，S4/S12）。
    Delete { path: String, recursive: bool },
    /// ⬇ 取文件（v1.1 wire 触发勘定）：服务端消毒全链后复用发送管线发起 Offer；
    /// 落盘目录 = 客户端会话状态（`recv_landing_dir`），零 wire 改动。
    Fetch { path: String },
    /// **元数据通告**——文件管理器 ⬆ 发送 = 先发本元帧（name/size 清单，**零
    /// 内容**），接收端三选【接收/另存为/取消】；**确认之前零内容帧**（不确认 =
    /// 不落盘 = fail-closed 结构性保证，§8.7①：Offer 内容帧只在对端显式 Fetch
    /// 单测钉死）。
    ///
    /// wire 语义（§8.3）：`entries` ≤ [`TRANSFER_REQUEST_MAX_ENTRIES`]（255，
    /// FILEMETA 先例同口径；超限 = 发送端 UI 拆多请求逐批一框）；`truncated` =
    /// 截断标记（FILEMETA `truncated` 同口径：wire 只承载 bool）；接收端【接收】
    /// = 逐条目派发 [`FsOp::Fetch`]（Fetch 到达即同意回执——**无单独 ok 回执帧**）；
    /// 【取消】= 回执 `FsResponse{ok:false, err:[FsErrCode::Declined]}`（零落盘、
    /// 零内容帧、零 `.part`）。
    ///
    /// 旧端行为（§8.4/§8.7⑥，零新情形）：旧端 bincode 解本变体 = 未知变体 →
    /// 内层帧解码失败 → **单帧丢弃、会话存活**（既有 `file frame decode failed
    /// (dropped)` 臂；「能力缺失 = 现状行为，非故障」）；`FileOp` 11/12/13 与
    /// 帧头布局零变化。
    TransferRequest { entries: Vec<TransferEntry>, truncated: bool },
}

///（[`FsOp::TransferRequest`] 负载元素）——元数据帧仅承载 **root 相对路径 +
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferEntry {
    /// root 相对路径（如 `docs/report.pdf`；接收端确认框清单行渲染用）。
    pub rel_path: String,
    /// 字节数（确认框清单行大小显示；与后续 Fetch/Offer meta size 同源）。
    pub size: u64,
}

/// FS 目录条目（List/Stat 负载元素）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsEntry {
    /// 裸名称（不含分隔符）。
    pub name: String,
    /// 字节数（目录 = 0）。
    pub size: u64,
    /// mtime（UNIX 秒；不可得 = 0）。
    pub mtime: i64,
    pub is_dir: bool,
    /// 符号链接上报（List 不跟随、不展开子树，S4）。
    pub is_symlink: bool,
}

/// FS 结构化错误码（wire 有序：u32 尾追加；**S10：对端只见码，细节留本端日志**）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsErrCode {
    /// 成功（与 `FsResponsePayload::ok = true` 同现）。
    Ok = 0,
    /// 目标不存在（含根条目失效）。
    NotFound,
    /// 目标不是目录（对文件执行 List 等）。
    NotADirectory,
    /// 目标是目录（对目录执行 Stat 期望文件等）。
    IsADirectory,
    /// 目标已存在（rename 冲突，S13 跨平台统一）。
    AlreadyExists,
    /// 本地 OS 权限拒绝（系统级，含 OS DACL）。
    PermissionDenied,
    /// 归一化/canonicalize 回检逃逸允许根（fail-closed 主码；v1.1 亦含逃逸写根）。
    PathOutsideRoot,
    /// 路径 > [`FS_PATH_MAX_BYTES`] 字节或含非法字符（S3/S6，细节在日志）。
    PathTooLong,
    /// 其余 IO 错误（不向对端泄露 OS 细节；含非 List op 响应超限）。
    Io,
    /// v1.1：符号链接 delete/rename / 策略禁用（如 fs_write_roots 全条目不可用）。
    /// **v1.0「headless 写操作」语义作废**（K1 修订版：headless 写 = 执行，S9）。
    NotSupported,
    /// 超限限速（8 未决 / 20 req/s 滑动窗，S8）。
    RateLimited,
    /// 内部错误（不泄露细节）。
    Internal,
    /// 请求被拒，declined）——经既有 [`FsResponsePayload{ok:false, err:Self,
    /// payload:空}`] 承载，**零新负载结构**（§8.4）。尾追加（索引 12；既有
    Declined,
}

/// FS 响应负载（bincode 置于 `FileTransferFrame::data`，op = [`FileOp::FsResponse`]）。
///
/// `ok = true`：`err = FsErrCode::Ok`，`payload` = bincode(op 专属结果)——
/// List → [`FsListPayload`]；Stat → [`FsEntry`]；Mkdir/Rename/Delete/Fetch → 空。
/// `ok = false`：`err` = 结构化码，`payload` 空。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsResponsePayload {
    pub ok: bool,
    pub err: FsErrCode,
    pub payload: Vec<u8>,
}

/// List 响应负载（bincode 置于 [`FsResponsePayload::payload`]）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsListPayload {
    pub entries: Vec<FsEntry>,
    /// 截断标记（服务端 [`FS_RESPONSE_MAX_BYTES`] 上限 / offset+limit 未取尽）。
    pub has_more: bool,
    /// 根显示名 = 根路径 `file_stem`（如 `C:\Users\dev` → `yu`；**只发 stem 不发
    /// 盘符全路径**，§1.3）——面包屑首段渲染用，服务端每 List 响应恒携带。
    pub root_display: String,
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

    /// +「真覆盖」语义。`data` = bincode([`FileOfferV2Meta`])；帧布局与
    /// v1 Offer 同（21B 帧头零变化），仅 `op` 判别值 13 + meta 结构不同。
    pub fn offer_v2(
        transfer_id: u64,
        meta: &FileOfferV2Meta,
        total_blocks: u32,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            transfer_id,
            op: FileOp::OfferV2,
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
    /// `code` = 回 wire 的结构化码（S10：对端只见码）；`detail` = 本地日志细节
    /// （**不向对端回传路径回显/OS 错误串**）。
    #[error("fs security reject: {code:?} — {detail}")]
    FsReject {
        code: FsErrCode,
        detail: String,
    },
}

impl FileTransferError {
    /// 构造 FS 安全拒绝（细节仅本地日志，S10）。
    pub fn fs_reject(code: FsErrCode, detail: impl Into<String>) -> Self {
        Self::FsReject {
            code,
            detail: detail.into(),
        }
    }
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
    if is_windows_reserved_name(name) {
        return Err(FileTransferError::UnsafeFilename(format!(
            "reserved name {name}"
        )));
    }
    Ok(name.to_string())
}

/// `sanitize_fs_path` 组件级检查共用，S5）。含扩展名前缀（如 `CON.txt` → 命中
/// `CON`）。跨平台恒启用（保留名在 unix 上亦无合法语义，fail-closed 统一）。
pub(crate) fn is_windows_reserved_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("");
    let upper = stem.to_ascii_uppercase();
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED.contains(&upper.as_str())
}

// ════════════════════════════════════════════════════════════════
// FsRouter / FsPolicy —— 全部 fail-closed；纯逻辑 + 本地 FS 回检，可单测
// ════════════════════════════════════════════════════════════════

/// + canonicalize 回检**后于** IO，互不替代）。
///
/// Wire 语义（§1.3）：请求内路径 = **相对允许根**（如 `Documents/report.pdf`）；
/// 空路径 `""` = 根本身（`Stat` 返回根条目元数据）。`root` **必须**为
/// canonicalized 绝对根（会话建立时一次性解析，§1.4）；本函数不重解析根。
///
/// 防线顺序（= 执行顺序）：
/// - S1 绝对路径/盘符（`/`、`\`、`^[A-Za-z]:` 开头）→ [`FsErrCode::PathOutsideRoot`]；
/// - S3 ASCII 控制字符 + NUL（UTF-8 合法宽松放行，与 `sanitize_filename` 同族）
///   → [`FsErrCode::PathTooLong`]（非法字符归此码，细节在日志）；
/// - S6 长度 > [`FS_PATH_MAX_BYTES`] → PathTooLong（先于 IO）；
/// - S2 dotdot/空/`.` 组件（按 `/`+`\` 切，任一命中即拒——**不尝试"抵消"再回检**）
///   → PathOutsideRoot；
/// - S5 组件级 Windows 保留名（[`is_windows_reserved_name`] 复用）→ PathOutsideRoot；
/// - S4/S12 canonicalize 回检：存在 → canonicalize（解析**全部中间**符号链接）→
///   必须以根为前缀（Windows 大小写不敏感）→ 否则 PathOutsideRoot；不存在
///   （如 Mkdir 目标）→ 逐级上探至最深存在祖先 canonicalize + 前缀检查后拼回尾
///   组件，任一步失败 → 拒（不猜）。
pub fn sanitize_fs_path(root: &Path, req: &str) -> Result<PathBuf, FileTransferError> {
    // 根前置条件：必须存在（会话建立已解析；缺失 = fail-closed 不猜）。
    if !root.is_dir() {
        return Err(FileTransferError::fs_reject(
            FsErrCode::NotFound,
            format!("fs root missing: {}", root.display()),
        ));
    }
    // "" = 根本身（§1.3）。
    if req.is_empty() {
        return Ok(root.to_path_buf());
    }
    // S6：wire 上限（先于一切 IO）。
    if req.len() > FS_PATH_MAX_BYTES {
        return Err(FileTransferError::fs_reject(
            FsErrCode::PathTooLong,
            format!("fs path {} bytes > {FS_PATH_MAX_BYTES}", req.len()),
        ));
    }
    // S1：绝对路径/盘符（wire 禁绝对路径，root 相对）。
    let bytes = req.as_bytes();
    if req.starts_with('/')
        || req.starts_with('\\')
        || (bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic())
    {
        return Err(FileTransferError::fs_reject(
            FsErrCode::PathOutsideRoot,
            "fs path is absolute (wire 禁绝对路径，root 相对)",
        ));
    }
    // S3：ASCII 控制字符 + NUL（UTF-8 合法宽松放行）。
    for c in req.chars() {
        let n = c as u32;
        if n < 0x20 || n == 0x7F {
            return Err(FileTransferError::fs_reject(
                FsErrCode::PathTooLong,
                format!("fs path illegal char {c:?}"),
            ));
        }
    }
    // S2/S5：组件归一化（.. / . / 空 / 保留名 → 拒，不尝试抵消再回检）。
    let mut joined = root.to_path_buf();
    for comp in req.split(['/', '\\']) {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(FileTransferError::fs_reject(
                FsErrCode::PathOutsideRoot,
                format!("fs path bad component {comp:?}"),
            ));
        }
        if is_windows_reserved_name(comp) {
            return Err(FileTransferError::fs_reject(
                FsErrCode::PathOutsideRoot,
                format!("fs path reserved name {comp:?}"),
            ));
        }
        joined = joined.join(comp);
    }
    // S4/S12：canonicalize 回检（解析全部符号链接，含中间组件）。
    if joined.exists() {
        let canon = canonicalize_within_root(&joined, root)?;
        if !within_root(&canon, root) {
            return Err(FileTransferError::fs_reject(
                FsErrCode::PathOutsideRoot,
                "fs path escapes root via symlink (canonicalize recheck)",
            ));
        }
        return Ok(canon);
    }
    // 目标不存在（Mkdir 等）：逐级上探至最深存在祖先，canonicalize + 前缀检查，拼回尾。
    let mut tail: VecDeque<&std::ffi::OsStr> = VecDeque::new();
    let mut cur = joined.as_path();
    while cur != root && !cur.exists() {
        let name = cur.file_name().ok_or_else(|| {
            FileTransferError::fs_reject(FsErrCode::NotFound, "fs path has no file name")
        })?;
        tail.push_front(name);
        cur = cur.parent().ok_or_else(|| {
            FileTransferError::fs_reject(FsErrCode::NotFound, "fs path parent missing")
        })?;
    }
    let canon = canonicalize_within_root(cur, root)?;
    if !within_root(&canon, root) {
        return Err(FileTransferError::fs_reject(
            FsErrCode::PathOutsideRoot,
            "fs path ancestor escapes root via symlink (canonicalize recheck)",
        ));
    }
    let mut out = canon;
    for name in tail {
        out = out.join(name);
    }
    Ok(out)
}

/// S6 回退：canonicalize 失败（如 Win MAX_PATH 内核开关未启用的长路径）→
/// 「父目录 canonicalize + 尾组件拼接」再前缀检查（父不存在 → NotFound，不猜）。
fn canonicalize_within_root(p: &Path, root: &Path) -> Result<PathBuf, FileTransferError> {
    match std::fs::canonicalize(p) {
        Ok(c) => Ok(c),
        Err(_) => {
            let (parent, tail) = match (p.parent(), p.file_name()) {
                (Some(pa), Some(f)) => (pa, f),
                _ => {
                    return Err(FileTransferError::fs_reject(
                        FsErrCode::NotFound,
                        format!("fs canonicalize fallback: no parent for {}", p.display()),
                    ))
                }
            };
            if !parent.exists() {
                return Err(FileTransferError::fs_reject(
                    FsErrCode::NotFound,
                    format!("fs canonicalize fallback: parent missing {}", parent.display()),
                ));
            }
            let pc = std::fs::canonicalize(parent).map_err(|e| {
                FileTransferError::fs_reject(
                    FsErrCode::NotFound,
                    format!("fs canonicalize parent {}: {e}", parent.display()),
                )
            })?;
            if !within_root(&pc, root) {
                return Err(FileTransferError::fs_reject(
                    FsErrCode::PathOutsideRoot,
                    "fs path escapes root (canonicalize fallback recheck)",
                ));
            }
            Ok(pc.join(tail))
        }
    }
}

/// 根前缀检查（组件级，非字符串前缀）：Windows 大小写不敏感（S5），unix 敏感。
/// 两侧应为 canonicalized（或 canonicalized 源的拼接）。
fn within_root(candidate: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        let root_comps: Vec<_> = root.components().collect();
        let cand_comps: Vec<_> = candidate.components().collect();
        cand_comps.len() >= root_comps.len()
            && cand_comps
                .iter()
                .zip(root_comps.iter())
                .all(|(a, b)| a.as_os_str().eq_ignore_ascii_case(b.as_os_str()))
    }
    #[cfg(not(windows))]
    {
        candidate.starts_with(root)
    }
}

/// [`FsErrCode::AlreadyExists`]，**无静默覆盖**——Windows `std::fs::rename` 目标
/// 存在即失败 / unix `rename(2)` 静默覆盖，此处统一 fail-closed 确定性）。
pub fn fs_rename_target_check(to: &Path) -> Result<(), FileTransferError> {
    if to.exists() {
        return Err(FileTransferError::fs_reject(
            FsErrCode::AlreadyExists,
            format!("rename target exists: {}", to.display()),
        ));
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────
// 允许根配置解析（§1.4）：fs_roots 浏览根 / fs_write_roots 写根
// ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct FsRootResolution {
    /// 可用（canonicalized、去重、稳定排序）根。
    pub roots: Vec<PathBuf>,
    /// 不可用条目 + 原因（WARN 已落本地日志；**不阻塞会话建立**，§1.4）。
    pub unavailable: Vec<(String, String)>,
}

/// 逐条目 `~` 展开（仅首位 `~`/`~/`/`~\`；`~user` 形态不展开——按字面处理，
/// 不存在自然落不可用）；**含 `%` 条目拒绝**（环境变量注入面，fail-closed +
/// WARN）；canonicalize（解析符号链接）；条目不存在 → 不可用（WARN）；
/// Windows 大小写不敏感去重 + 稳定排序（unix 大小写敏感）。
pub fn resolve_fs_root_entries(entries: &[String]) -> FsRootResolution {
    let mut res = FsRootResolution::default();
    let mut seen: Vec<PathBuf> = Vec::new();
    for raw in entries {
        let e = raw.trim();
        if e.is_empty() {
            res.unavailable.push((raw.clone(), "empty entry".into()));
            continue;
        }
        if e.contains('%') {
            tracing::warn!(
                entry = %e,
                "fs root entry rejected: env var (%) not expanded (fail-closed)"
            );
            res.unavailable.push((raw.clone(), "env var entry (%) rejected".into()));
            continue;
        }
        let expanded: Option<PathBuf> = if e == "~" {
            dirs_next::home_dir()
        } else if let Some(rest) = e.strip_prefix("~/").or_else(|| e.strip_prefix("~\\")) {
            dirs_next::home_dir().map(|h| h.join(rest))
        } else {
            Some(PathBuf::from(e))
        };
        let expanded = match expanded {
            Some(p) if p.as_os_str().is_empty() => {
                res.unavailable.push((raw.clone(), "empty entry".into()));
                continue;
            }
            Some(p) => p,
            None => {
                res.unavailable.push((raw.clone(), "no home dir for ~".into()));
                continue;
            }
        };
        if !expanded.exists() {
            tracing::warn!(entry = %e, "fs root entry unavailable: path missing");
            res.unavailable.push((raw.clone(), "path missing".into()));
            continue;
        }
        match std::fs::canonicalize(&expanded) {
            Ok(c) => {
                #[cfg(windows)]
                let dup = seen
                    .iter()
                    .any(|s| s.as_os_str().eq_ignore_ascii_case(c.as_os_str()));
                #[cfg(not(windows))]
                let dup = seen.iter().any(|s| s == &c);
                if dup {
                    continue;
                }
                seen.push(c);
            }
            Err(e2) => {
                tracing::warn!(
                    entry = %e,
                    error = %e2,
                    "fs root entry unavailable: canonicalize failed"
                );
                res.unavailable.push((raw.clone(), format!("canonicalize: {e2}")));
            }
        }
    }
    #[cfg(windows)]
    seen.sort_by(|a, b| {
        a.to_string_lossy()
            .to_ascii_lowercase()
            .cmp(&b.to_string_lossy().to_ascii_lowercase())
    });
    #[cfg(not(windows))]
    seen.sort();
    res.roots = seen;
    res
}

/// 非"全盘"——fail-closed 性质由解析期检查承担，默认值只决定"可见面"）。
pub fn resolve_fs_browse_roots(entries: &[String]) -> FsRootResolution {
    if !entries.is_empty() {
        return resolve_fs_root_entries(entries);
    }
    let mut res = FsRootResolution::default();
    match dirs_next::home_dir() {
        Some(h) => match std::fs::canonicalize(&h) {
            Ok(c) => res.roots.push(c),
            Err(e) => res.unavailable.push(("~".into(), format!("canonicalize: {e}"))),
        },
        None => res.unavailable.push(("~".into(), "no home dir".into())),
    }
    res
}

/// OS DACL 约束——与浏览根 "[home]" 默认刻意不对称）；无 home 回落。
/// 非空 = 写根门启用（Mkdir/Rename/Delete/上传落盘仅允许列内根，§1.4 执行点）。
pub fn resolve_fs_write_roots(entries: &[String]) -> FsRootResolution {
    resolve_fs_root_entries(entries)
}

///
/// - `write_roots` **空 = 门禁用** → Ok（不额外限写根，§1.4）；
/// - 门启用 → `target`（canonicalized 绝对路径：[`sanitize_fs_path`] 返回值或
///   `canonicalize(download_dir)`）须落在某写根内（Windows 大小写不敏感前缀）
///   → 列外 = [`FsErrCode::PathOutsideRoot`]（日志 "fs write outside write
///   roots"，对端只见码——S10）。
pub fn check_write_root_gate(target: &Path, write_roots: &[PathBuf]) -> Result<(), FileTransferError> {
    if write_roots.is_empty() {
        return Ok(());
    }
    if write_roots.iter().any(|r| within_root(target, r)) {
        return Ok(());
    }
    Err(FileTransferError::fs_reject(
        FsErrCode::PathOutsideRoot,
        "fs write outside write roots",
    ))
}

// ────────────────────────────────────────────────────────────
// FsRouter（§1.2/§1.5 S8）：请求-响应关联 + 超时 + 限速
// ────────────────────────────────────────────────────────────

/// 请求方与服务端共用同型）。
///
/// - **请求方**：[`Self::admit`]（S8 双门：[`FS_MAX_PENDING`] 未决 +
///   [`FS_RATE_PER_SEC`]/s 滑动窗，超限 → [`FsErrCode::RateLimited`]）→ 发帧 →
///   [`Self::bind`]（deadline = now + [`FS_REQ_TIMEOUT`]）；收响应
///   [`Self::deliver`]（req_id 查无 = 超时迟到/重复 → **静默丢弃**，防"超时后的
///   迟到成功"引发 UI 状态漂移）；tick [`Self::expire`]（到期 → drop oneshot，
///   请求方收 RecvError = 本地判 `Timeout`，**不产生 wire 帧**）。
/// - **服务端**：收 FsRequest 后 [`Self::admit_inbound`]（超限 → 回
///   [`Self::complete`]（best-effort 出账）。
#[derive(Debug)]
pub struct FsRouter {
    next_req_id: u32,
    /// req_id → (deadline, 请求方 oneshot；服务端条目 = None)。
    pending: HashMap<u32, (Instant, Option<tokio::sync::oneshot::Sender<FsResponsePayload>>)>,
    /// 滑动窗：最近请求时间戳（S8 20 req/s）。
    rate_window: VecDeque<Instant>,
}

impl Default for FsRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl FsRouter {
    pub fn new() -> Self {
        Self {
            next_req_id: 1,
            pending: HashMap::new(),
            rate_window: VecDeque::new(),
        }
    }

    /// S8 准入（请求方）：双门检查 → 分配 req_id（会话内单调、从 1 起、高位 0；
    /// u32 回绕 → 重启 1，不用 0 以免与未用值歧义）。准入失败的请求不占速率预算。
    pub fn admit(&mut self, now: Instant) -> Result<u32, FsErrCode> {
        self.prune_rate_window(now);
        if self.rate_window.len() >= FS_RATE_PER_SEC || self.pending.len() >= FS_MAX_PENDING {
            return Err(FsErrCode::RateLimited);
        }
        let id = self.next_req_id;
        self.next_req_id = self.next_req_id.wrapping_add(1).max(1);
        self.rate_window.push_back(now);
        Ok(id)
    }

    /// S8 准入（服务端，req_id 由请求帧承载）：同双门；成功即计入未决（响应
    /// 经 wire 直发，无本地 oneshot）。
    pub fn admit_inbound(&mut self, req_id: u32, now: Instant) -> Result<(), FsErrCode> {
        self.prune_rate_window(now);
        if self.rate_window.len() >= FS_RATE_PER_SEC || self.pending.len() >= FS_MAX_PENDING {
            return Err(FsErrCode::RateLimited);
        }
        self.rate_window.push_back(now);
        self.pending.insert(req_id, (now + FS_REQ_TIMEOUT, None));
        Ok(())
    }

    /// 请求方：绑定 oneshot（deadline = now + [`FS_REQ_TIMEOUT`]）。
    pub fn bind(
        &mut self,
        req_id: u32,
        now: Instant,
        sender: tokio::sync::oneshot::Sender<FsResponsePayload>,
    ) {
        self.pending.insert(req_id, (now + FS_REQ_TIMEOUT, Some(sender)));
    }

    /// 请求方：响应关联。req_id 命中 → 投递 oneshot + 出账，返回 true；
    /// 查无（超时迟到/重复/已过期）→ **静默丢弃**，返回 false（不报错）。
    pub fn deliver(&mut self, req_id: u32, payload: FsResponsePayload) -> bool {
        match self.pending.remove(&req_id) {
            Some((_, Some(tx))) => tx.send(payload).is_ok(),
            _ => false,
        }
    }

    /// 服务端：执行完成出账（best-effort；已过期/未知 req_id 无副作用——
    /// 迟到响应仍发 wire，请求方按「静默丢弃」处理）。
    pub fn complete(&mut self, req_id: u32) {
        self.pending.remove(&req_id);
    }

    /// 超时扫描（请求方 tick / 服务端 S14 观测）：到期条目出账 + drop oneshot
    /// （请求方收 RecvError = 本地判 Timeout，不产生 wire 帧）。返回到期 req_id。
    pub fn expire(&mut self, now: Instant) -> Vec<u32> {
        let due: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, (deadline, _))| *deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in &due {
            self.pending.remove(id);
        }
        due
    }

    /// 未决请求数（S8 并发上限判据）。
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// 滑动窗清理（≥1s 的旧时间戳出窗）。
    fn prune_rate_window(&mut self, now: Instant) {
        while let Some(&front) = self.rate_window.front() {
            if now.duration_since(front) >= Duration::from_secs(1) {
                self.rate_window.pop_front();
            } else {
                break;
            }
        }
    }
}

// ────────────────────────────────────────────────────────────
// 响应上限（§1.2）：512 KiB
// ────────────────────────────────────────────────────────────

/// 自尾部截断 entries 至 `bincode(FsResponsePayload{payload: FsListPayload})`
/// 装入上限（二分，O(log n) 次序列化）；`has_more = true` 标记截断。
/// 返回 `(FsResponse.data 字节, has_more)`。
pub fn pack_list_response(entries: Vec<FsEntry>, root_display: &str) -> (Vec<u8>, bool) {
    let size_of = |n: usize| -> usize {
        let list = FsListPayload {
            entries: entries[..n].to_vec(),
            has_more: false,
            root_display: root_display.to_string(),
        };
        let resp = FsResponsePayload {
            ok: true,
            err: FsErrCode::Ok,
            payload: bincode::serialize(&list).unwrap_or_default(),
        };
        bincode::serialize(&resp).map(|b| b.len()).unwrap_or(usize::MAX)
    };
    let total = entries.len();
    let (mut lo, mut hi) = (0usize, total);
    while lo < hi {
        let mid = lo + (hi - lo + 1) / 2;
        if size_of(mid) <= FS_RESPONSE_MAX_BYTES {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let has_more = lo < total;
    let list = FsListPayload {
        entries: entries[..lo].to_vec(),
        has_more,
        root_display: root_display.to_string(),
    };
    let resp = FsResponsePayload {
        ok: true,
        err: FsErrCode::Ok,
        payload: bincode::serialize(&list).unwrap_or_default(),
    };
    (
        bincode::serialize(&resp).unwrap_or_default(),
        has_more,
    )
}

/// [`FsErrCode::Io`]（List 走 [`pack_list_response`] 截断语义）。
/// 返回可直接置于 `FileTransferFrame::data` 的字节。
pub fn build_fs_response(ok: bool, err: FsErrCode, payload: Vec<u8>) -> Result<Vec<u8>, FsErrCode> {
    let resp = FsResponsePayload { ok, err, payload };
    let data = bincode::serialize(&resp).map_err(|_| FsErrCode::Internal)?;
    if data.len() > FS_RESPONSE_MAX_BYTES {
        return Err(FsErrCode::Io);
    }
    Ok(data)
}

// ────────────────────────────────────────────────────────────
// FsPolicy（§1.6）：Gui / Headless
// ────────────────────────────────────────────────────────────

///
/// **v1.1（K1 修订版，S9）：Gui/Headless 写行为一致（均执行）**——写操作
/// （Mkdir/Rename/Delete/上传落盘）双侧同执行臂；授权来源 = **会话级授权**
/// （挑战码 + 指纹确认 + 加密通道建立 = 授权边界，WinSCP/RDP 语义，不逐项
/// 弹窗审批）。两变体差异**仅审计通道标记**（Headless = 无人在场，日志文件
/// 强制 = 唯一审计轨迹；GUI = tracing + 面板通知（可选，v2））。
/// v1.0「headless 只读（NotSupported）」分支自 v1.1 废止；`policy.rs:254`
/// 「无审批通道 = 审批拒绝」先例在连接准入层继续有效，与 FS 层不矛盾（S9）。
#[derive(Debug, Clone)]
pub enum FsPolicy {
    /// GUI 服务端（FileSession 任务构造点）。
    Gui {
        /// 浏览根（canonicalized；空配置 = `[用户主目录]`，§1.4）。
        roots: Vec<PathBuf>,
        /// 写根（canonicalized；**空 = 门禁用**，§1.4）。
        write_roots: Vec<PathBuf>,
    },
    /// Headless 服务端（cli serve 构造点；写 = 执行，与 Gui 同臂 + 审计日志强制）。
    Headless {
        roots: Vec<PathBuf>,
        write_roots: Vec<PathBuf>,
    },
}

impl FsPolicy {
    /// 会话建立：由配置字符串一次性解析（§1.4：浏览根空 = `[home]`；写根空 =
    /// 门禁用；条目失效 → WARN 不阻塞会话建立）。
    pub fn gui(fs_roots: &[String], fs_write_roots: &[String]) -> Self {
        let write = resolve_fs_write_roots(fs_write_roots);
        note_write_roots_availability(fs_write_roots, &write);
        Self::Gui {
            roots: resolve_fs_browse_roots(fs_roots).roots,
            write_roots: write.roots,
        }
    }

    /// 同 [`Self::gui`]（headless serve 构造点；写行为 = 执行，S9）。
    pub fn headless(fs_roots: &[String], fs_write_roots: &[String]) -> Self {
        let write = resolve_fs_write_roots(fs_write_roots);
        note_write_roots_availability(fs_write_roots, &write);
        Self::Headless {
            roots: resolve_fs_browse_roots(fs_roots).roots,
            write_roots: write.roots,
        }
    }

    /// 浏览根（远端栏根选择器）。
    pub fn roots(&self) -> &[PathBuf] {
        match self {
            Self::Gui { roots, .. } => roots,
            Self::Headless { roots, .. } => roots,
        }
    }

    /// 写根（**空 = 门禁用**，§1.4）。
    pub fn write_roots(&self) -> &[PathBuf] {
        match self {
            Self::Gui { write_roots, .. } => write_roots,
            Self::Headless { write_roots, .. } => write_roots,
        }
    }

    /// v1.1（K1/S9）：写操作放行？= **两变体均 true（均执行）**——保留为单一
    pub fn write_allowed(&self) -> bool {
        true
    }

    /// S9 审计通道标记：Headless = 无人在场 → 日志文件强制（唯一审计轨迹）；
    /// GUI = tracing（+ 面板通知可选，v2）。审计行 = 操作类型 + root 相对路径
    /// + 结果码（**不记文件内容**，凭据零落盘同精神）。
    pub fn audit_to_log_file(&self) -> bool {
        matches!(self, Self::Headless { .. })
    }
}

/// §1.4：门启用且全部列内根不可用 = 写操作实际全拒（会话建立 INFO 一行）。
fn note_write_roots_availability(raw: &[String], res: &FsRootResolution) {
    if !raw.is_empty() && res.roots.is_empty() {
        tracing::info!(
            "fs write roots: all {} configured entries unavailable — write ops effectively denied (fail-closed)",
            raw.len()
        );
    }
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
    offer_sent_at: Option<Instant>,
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
            offer_sent_at: None,
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

    /// 自此进入「等待对端 Accept」态，[`Self::idle_timeout`] 按
    /// [`OFFER_TIMEOUT`] 判定死链（不再仅依赖 `in_flight > 0`）。
    pub fn mark_offer_sent(&mut self) {
        self.offer_sent_at = Some(Instant::now());
    }

    pub fn offer_pending(&self) -> bool {
        self.offer_sent_at.is_some()
    }

    /// 收到 Accept：`remote_next_seq` = 接收方已有进度（续传协商），
    /// 取双方进度最大值作为发送起点。首传时对端回 0。
    pub fn on_accept(&mut self, remote_next_seq: u32) {
        self.started.get_or_insert_with(Instant::now);
        self.offer_sent_at = None;
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
    ///
    /// 注意：状态机**不**门控 Accept 前取号（构造后即可取块）——Offer→
    /// Accept 顺序由驱动层保证（桌面 FileSession 的 `on_tick` 补窗口对
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

    /// 空闲死链判定（生产默认阈值：[`IDLE_TIMEOUT`] / [`OFFER_TIMEOUT`]）。
    pub fn idle_timeout(&self, now: Instant) -> bool {
        self.idle_timeout_with(now, IDLE_TIMEOUT, OFFER_TIMEOUT)
    }

    ///
    /// ① **在途死链**（原有语义）：窗口非空且超过 `idle` 无任何进展；
    ///    未获 Accept——修复前此状态（对端接收臂缺失/会话已拆/帧被丢）
    ///    `in_flight == 0` → 永不超时、无限挂起且零报错。
    pub fn idle_timeout_with(&self, now: Instant, idle: Duration, offer: Duration) -> bool {
        if self.in_flight > 0 && now.duration_since(self.last_activity) >= idle {
            return true;
        }
        if let Some(t) = self.offer_sent_at {
            return self.in_flight == 0 && !self.done && now.duration_since(t) >= offer;
        }
        false
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

    /// 开始接收：落 `.part` 到 `dir`（自动改名目标名，v1 口径）。
    ///
    /// ——静默覆盖在 v1 结构上不可能，既有调用点行为零变化）；「真覆盖」语义
    /// 经 [`Self::begin_with`]（K4 v2 Offer 接收链专用）。
    pub fn begin(
        &mut self,
        meta: &FileOfferMeta,
        dir: &Path,
        sha256: [u8; 32],
        resume_from: u32,
    ) -> Result<(), FileTransferError> {
        self.begin_with(meta, dir, sha256, resume_from, false)
    }

    ///
    /// `overwrite`：
    /// - `false`（v1 同口径）→ [`unique_target_path`] 自动改名（`name (1)` 族）；
    /// - `true`（「真覆盖」）→ 最终名 = `dir/name`（已存在 = `.part` 覆盖写
    ///   替换；断点协商 / re-Offer 退避同口径 §4）。
    ///
    /// `resume_from`：续传起点（已有 `.part` 的已收进度，通常来自
    /// [`TransferStore`]）；对应 `.part` 文件须由调用方先还原/确认存在。
    ///
    /// S-10a (F-11)：`resume_from` 必须 ≤ 总块数（由 `meta.size` 派生），
    /// 越界直接拒绝——旧实现无条件 `set_len(seq*64KiB)`，u32 极值可制造
    /// 数百 TB 稀疏文件。截断长度同时以 `meta.size` 为上限（非整块文件
    /// 不会把 `.part` 撑大）。S10d 磁盘空间检查同链。`name` 恒经
    /// [`sanitize_filename`]（无分隔符 → `dir.join(name)` 不逃逸 `dir`）。
    pub fn begin_with(
        &mut self,
        meta: &FileOfferMeta,
        dir: &Path,
        sha256: [u8; 32],
        resume_from: u32,
        overwrite: bool,
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
        // 已存在 = 覆盖写替换）；=false = v1 同口径 unique_target_path 自动改名。
        let final_path = if overwrite {
            dir.join(&name)
        } else {
            unique_target_path(dir, &name)
        };
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

    ///
    /// - **P2P**（`path.is_p2p()` = direct-ipv6/ipv4 + punch-udp/tcp）：
    ///   **字节维度不设限**（`max_bytes` 置 `0` = [`SessionQuota::new`] 的
    ///   0 语义）——用户指令仅限字节维度；
    /// - **Relay**：原配置上限**零变化**（4 GiB 默认）。
    ///
    /// **文件数维度两种路径均保留**（`quota_files=64` 不变）——用户指令
    /// 不放宽文件数。`max_files` 原样透传。
    pub fn new_for_path(path: PathKind, max_bytes: u64, max_files: u64) -> Self {
        Self::new(if path.is_p2p() { 0 } else { max_bytes }, max_files)
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

    /// （path 维度后 P2P 会话为 `0` = 不限，UI 走 `filepanel.quota.unlimited`
    /// 键；此前 UI 自 config 源读上限，P2P 字节不限时会误显 4 GiB 上限）。
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
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

    /// 判死链（修复前：`in_flight == 0` → 永不超时、无限挂起、零报错静默）。
    #[test]
    fn test_sender_offer_timeout_waiting_accept() {
        let mut s = make_sender(BLOCK_SIZE * 5);
        s.mark_offer_sent();
        assert!(s.offer_pending(), "mark_offer_sent 后必须处于等待接受态");
        assert!(!s.idle_timeout(Instant::now()), "刚发出 Offer 不得立即超时");
        assert!(
            !s.idle_timeout(Instant::now() + OFFER_TIMEOUT - StdDuration::from_secs(1)),
            "未到 OFFER_TIMEOUT 不得超时"
        );
        let far = Instant::now() + OFFER_TIMEOUT + StdDuration::from_millis(1);
        assert!(s.idle_timeout(far), "Offer 未响应超时后必须判死链");
        assert!(
            s.idle_timeout_with(far, IDLE_TIMEOUT, OFFER_TIMEOUT),
            "阈值注入入口与默认入口一致"
        );
        // 对端 Accept → 退出等待态，Offer 超时分支不再触发（不误杀）。
        s.on_accept(0);
        assert!(!s.offer_pending(), "Accept 必须清除等待接受态");
        assert!(
            !s.idle_timeout(Instant::now() + OFFER_TIMEOUT + StdDuration::from_millis(1)),
            "Accept 后（零在途）不得误判 Offer 超时"
        );
        // 在途空闲分支语义不变（既有 IDLE_TIMEOUT 行为）。
        let seq = s.next_unsent_seq().unwrap();
        s.mark_sent(seq);
        assert!(!s.idle_timeout(Instant::now()));
        assert!(
            s.idle_timeout(Instant::now() + IDLE_TIMEOUT + StdDuration::from_millis(1)),
            "在途空闲超时语义不变"
        );
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


    #[test]
    fn test_session_quota_path_dimension_p2p_bytes_unlimited() {
        // P2P（direct-ipv4，用户 179 场景实机路径）：单文件 >4 GiB 不被
        // 字节配额拒绝——字节维度置 0 = 不设限。
        let mut q = SessionQuota::new_for_path(
            PathKind::DirectV4,
            DEFAULT_SESSION_MAX_BYTES,
            DEFAULT_SESSION_MAX_FILES,
        );
        assert_eq!(q.max_bytes(), 0, "P2P 字节上限 = 0（不限）");
        let big = DEFAULT_SESSION_MAX_BYTES + (1 << 30); // 5 GiB 单文件
        assert!(
            q.try_reserve(big).is_ok(),
            "P2P 单文件 >4 GiB 不得被字节配额拒绝"
        );
        assert_eq!(q.reserved_bytes(), big);
        assert_eq!(q.remaining_bytes(), u64::MAX);
        // 累积多文件跨 4 GiB 边界同样不拒（10 × 1 GiB = 10 GiB）。
        for _ in 0..10 {
            q.try_reserve(1 << 30).unwrap();
        }
        assert_eq!(q.reserved_bytes(), big + 10 * (1 << 30));
    }

    #[test]
    fn test_session_quota_path_dimension_punch_is_p2p() {
        // 打洞路径（PunchUdp/PunchTcp）同为 P2P = 字节不设限。
        for kind in [PathKind::PunchUdp, PathKind::PunchTcp, PathKind::DirectV6] {
            let mut q =
                SessionQuota::new_for_path(kind, DEFAULT_SESSION_MAX_BYTES, DEFAULT_SESSION_MAX_FILES);
            assert_eq!(q.max_bytes(), 0, "{kind:?} 应判 P2P = 字节不限");
            assert!(q.try_reserve(1u64 << 40).is_ok()); // 1 TiB
        }
    }

    #[test]
    fn test_session_quota_path_dimension_files_dimension_preserved() {
        // 文件数维度不受 path 影响——P2P 下 `quota_files=64` 保留（用户
        // 指令仅限字节维度）。
        let mut q = SessionQuota::new_for_path(
            PathKind::DirectV4,
            DEFAULT_SESSION_MAX_BYTES,
            DEFAULT_SESSION_MAX_FILES,
        );
        for _ in 0..DEFAULT_SESSION_MAX_FILES {
            q.try_reserve(1).unwrap();
        }
        assert!(matches!(
            q.try_reserve(1),
            Err(FileTransferError::SessionFilesExceeded(64, 64))
        ));
        // 显式小文件数上限同样生效。
        let mut q2 = SessionQuota::new_for_path(PathKind::DirectV6, 0, 2);
        assert!(q2.try_reserve(1).is_ok());
        assert!(q2.try_reserve(1).is_ok());
        assert!(matches!(
            q2.try_reserve(1),
            Err(FileTransferError::SessionFilesExceeded(2, 2))
        ));
    }

    #[test]
    fn test_session_quota_path_dimension_relay_unchanged() {
        // Relay：配额**零变化**——4 GiB 字节上限仍拒 5 GiB 单文件；
        // 恰好 4 GiB 整传允许（既有 default 口径，不误伤）；64 文件第 65
        // 个仍拒。
        let mut q = SessionQuota::new_for_path(
            PathKind::Relay,
            DEFAULT_SESSION_MAX_BYTES,
            DEFAULT_SESSION_MAX_FILES,
        );
        assert_eq!(
            q.max_bytes(),
            DEFAULT_SESSION_MAX_BYTES,
            "Relay 字节上限 = config 原值"
        );
        let big = DEFAULT_SESSION_MAX_BYTES + (1 << 30); // 5 GiB
        assert!(matches!(
            q.try_reserve(big),
            Err(FileTransferError::SessionBytesExceeded(_, _))
        ), "Relay 单文件 >4 GiB 仍拒（与 path 维度引入前逐位一致）");
        assert_eq!((q.reserved_bytes(), q.reserved_files()), (0, 0), "拒绝不预留");
        assert!(q.try_reserve(DEFAULT_SESSION_MAX_BYTES).is_ok());
        // 文件数维度：64 个 1 字节文件 OK，第 65 个拒绝。
        let mut q2 = SessionQuota::new_for_path(
            PathKind::Relay,
            DEFAULT_SESSION_MAX_BYTES,
            DEFAULT_SESSION_MAX_FILES,
        );
        for _ in 0..DEFAULT_SESSION_MAX_FILES {
            q2.try_reserve(1).unwrap();
        }
        assert!(matches!(
            q2.try_reserve(1),
            Err(FileTransferError::SessionFilesExceeded(64, 64))
        ));
        // 与既有 `SessionQuota::new(DEFAULT.., DEFAULT..)` 逐位一致
        // （relay 行为零变化红线）。
        let mut qa = SessionQuota::new(DEFAULT_SESSION_MAX_BYTES, DEFAULT_SESSION_MAX_FILES);
        let mut qb = SessionQuota::new_for_path(
            PathKind::Relay,
            DEFAULT_SESSION_MAX_BYTES,
            DEFAULT_SESSION_MAX_FILES,
        );
        for sz in [3u64, 1 << 20, 1 << 32 - 1] {
            assert_eq!(qa.try_reserve(sz).is_ok(), qb.try_reserve(sz).is_ok());
        }
        assert_eq!(qa.remaining_bytes(), qb.remaining_bytes());
        assert_eq!(qa.remaining_files(), qb.remaining_files());
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

    // ────────────────────────────────────────────────────────────
    // ────────────────────────────────────────────────────────────

    fn fs_code(e: &FileTransferError) -> FsErrCode {
        match e {
            FileTransferError::FsReject { code, .. } => *code,
            other => panic!("expected FsReject, got {other:?}"),
        }
    }

    // ---- S11 旧帧回归：FileOp 判别值 wire 钉死（0-10 不重排，11/12 尾追加）----

    #[test]
    fn test_r92_fileop_discriminants_wire_pinned() {
        // bincode：帧 = [u64 transfer_id LE][u32 op 索引 LE][u32 seq][u32 total_blocks]
        // [Vec<u8> data（u32 len + 字节）][u8;32 sha] → op 索引恒在 offset 8。
        for (op, expected) in [
            (FileOp::Offer, 0u32),
            (FileOp::Accept, 1),
            (FileOp::Reject, 2),
            (FileOp::Data, 3),
            (FileOp::Ack, 4),
            (FileOp::Nack, 5),
            (FileOp::Finish, 6),
            (FileOp::FinishAck, 7),
            (FileOp::Cancel, 8),
            (FileOp::Pause, 9),
            (FileOp::Resume, 10),
            (FileOp::FsRequest, 11),
            (FileOp::FsResponse, 12),
            (FileOp::OfferV2, 13),
            // 判别值 14 钉死（既有 0-13 零重排，防未来插值）。
            (FileOp::PeerConsent, 14),
        ] {
            let bytes = FileTransferFrame::simple(1, op, 0).encode().unwrap();
            let idx = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            assert_eq!(idx, expected, "FileOp::{op:?} 判别值漂移");
            // 编解码回环（S11 逐位回归）。
            assert_eq!(FileTransferFrame::decode(&bytes).unwrap().op, op);
        }
        // 未知变体（旧端视角的 255）：解码必 Err（单帧丢弃），且不影响后续帧。
        let mut bad = FileTransferFrame::simple(1, FileOp::Offer, 0).encode().unwrap();
        bad[8..12].copy_from_slice(&255u32.to_le_bytes());
        assert!(FileTransferFrame::decode(&bad).is_err(), "未知变体必须解码 Err");
        let good = FileTransferFrame::simple(2, FileOp::Offer, 0).encode().unwrap();
        assert!(FileTransferFrame::decode(&good).is_ok(), "后续帧解帧不受影响");
    }

    /// meta 结构独立性（v1 `FileOfferMeta` 仅 name+size 零改动，v2 meta =
    /// 4 字段独立结构——「避免破既有布局」直接落实）。
    #[test]
    fn test_r92s2_offer_v2_roundtrip_and_meta_independent() {
        let meta = FileOfferV2Meta {
            name: "report.xlsx".into(),
            size: 64 * 1024,
            target_dir: "docs/2026".into(),
            overwrite: true,
        };
        let frame = FileTransferFrame::offer_v2(42, &meta, 1, [0x5A; 32]);
        assert_eq!(frame.op, FileOp::OfferV2);
        assert_eq!(frame.transfer_id, 42);
        assert_eq!(frame.total_blocks, 1);
        assert_eq!(frame.sha256, [0x5A; 32]);
        let wire = frame.encode().unwrap();
        let back = FileTransferFrame::decode(&wire).unwrap();
        assert_eq!(back, frame);
        // data = bincode(FileOfferV2Meta) 独立结构（非 v1 FileOfferMeta）。
        let parsed: FileOfferV2Meta = bincode::deserialize(&back.data).unwrap();
        assert_eq!(parsed, meta);
        // 同字节按 v1 meta 解析不应得到等值 name+size 之外的语义（结构独立
        // 钉死：v1 仅 2 字段——此断言防未来误把 v2 meta 塞进 v1 路径）。
        let as_v1: FileOfferMeta = bincode::deserialize(&back.data).unwrap();
        assert_eq!(as_v1.name, meta.name);
        assert_eq!(as_v1.size, meta.size);
        assert_eq!(
            bincode::serialized_size(&meta).unwrap(),
            bincode::serialized_size(&as_v1).unwrap()
                + bincode::serialized_size(&meta.target_dir).unwrap()
                + 1, // bool 占 1 字节
            "v2 meta = v1 两字段 + target_dir + overwrite（独立结构逐位核算）"
        );
    }

    /// 构造/往返（两 bool 值域全测）+ 帧字段约定（transfer_id/seq/
    /// total_blocks/sha256 = 0，data = bincode([`PeerConsentPayload`])）。
    #[test]
    fn test_r137_1_peer_consent_roundtrip() {
        for (clip, ft) in [(true, true), (true, false), (false, true), (false, false)] {
            let payload = PeerConsentPayload {
                clipboard_allowed: clip,
                file_transfer_allowed: ft,
            };
            let frame = FileTransferFrame {
                transfer_id: 0,
                op: FileOp::PeerConsent,
                seq: 0,
                total_blocks: 0,
                data: bincode::serialize(&payload).unwrap(),
                sha256: [0u8; 32],
            };
            let wire = frame.encode().unwrap();
            let back = FileTransferFrame::decode(&wire).unwrap();
            assert_eq!(back.op, FileOp::PeerConsent);
            assert_eq!(back.transfer_id, 0);
            assert_eq!(back.seq, 0);
            assert_eq!(back.total_blocks, 0);
            assert_eq!(back.sha256, [0u8; 32]);
            let parsed: PeerConsentPayload = bincode::deserialize(&back.data).unwrap();
            assert_eq!(
                parsed,
                payload,
                "PeerConsent 负载回环（clip={clip}, ft={ft}）"
            );
        }
        // Err（既有 `file frame decode failed` 丢弃臂触发前提），紧随其
        // 后合法帧解帧不受影响（独立成帧，长度在密文外）。
        let new_frame = FileTransferFrame {
            transfer_id: 0,
            op: FileOp::PeerConsent,
            seq: 0,
            total_blocks: 0,
            data: bincode::serialize(&PeerConsentPayload {
                clipboard_allowed: true,
                file_transfer_allowed: false,
            })
            .unwrap(),
            sha256: [0u8; 32],
        };
        // 旧端 bincode 枚举反序列化对索引 14 必 Err。
        let wire = new_frame.encode().unwrap();
        let idx = u32::from_le_bytes(wire[8..12].try_into().unwrap());
        assert_eq!(idx, 14, "PeerConsent 判别值 = 14（> 旧端最大 13 = 未知变体）");
        let good = FileTransferFrame::simple(2, FileOp::Offer, 0).encode().unwrap();
        assert!(FileTransferFrame::decode(&good).is_ok(), "后续帧解帧不受影响");
    }

    /// `overwrite=false` = v1 同口径 unique_target_path 自动改名；
    /// `overwrite=true` = 真覆盖（同名已存在 = 覆盖写，最终名不变）。
    #[test]
    fn test_r92s2_begin_with_overwrite_semantics() {
        let dir = std::env::temp_dir().join(format!("kirin_ft_v2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let meta = FileOfferMeta {
            name: "a.txt".into(),
            size: 5,
        };
        // 预置同名文件（内容 X）。
        std::fs::write(dir.join("a.txt"), b"X").unwrap();
        // overwrite=false → 改名 a (1).txt（v1 同口径，零覆盖）。
        let mut r1 = ChunkReceiver::new(1);
        r1.begin(&meta, &dir, [0u8; 32], 0).unwrap();
        assert_eq!(
            r1.final_path.file_name().unwrap().to_string_lossy(),
            "a (1).txt",
            "overwrite=false 必须自动改名"
        );
        r1.cancel();
        // overwrite=true → 最终名 = dir/a.txt（真覆盖）。
        let mut r2 = ChunkReceiver::new(2);
        r2.begin_with(&meta, &dir, [0u8; 32], 0, true).unwrap();
        assert_eq!(
            r2.final_path,
            dir.join("a.txt"),
            "overwrite=true 必须真覆盖（最终名 = 原名）"
        );
        r2.cancel();
        // begin（v1 薄封装）= begin_with(false) 行为恒等（回归钉死）。
        std::fs::write(dir.join("a (1).txt"), b"Y").unwrap();
        let mut r3 = ChunkReceiver::new(3);
        r3.begin(&meta, &dir, [0u8; 32], 0).unwrap();
        assert_eq!(
            r3.final_path.file_name().unwrap().to_string_lossy(),
            "a (2).txt",
            "begin 薄封装 = 自动改名链零变化"
        );
        r3.cancel();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- sanitize_fs_path：S1-S6 全向量 ----

    // 每次调用独立临时根（并行测试同 tag 会互踩——remove_dir_all 竞态）。
    static FS_ROOT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn fs_root() -> PathBuf {
        let seq = FS_ROOT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("kirin_ft_fsroot_{}_{}", std::process::id(), seq));
        std::fs::create_dir_all(&dir).unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();
        let _ = std::fs::create_dir_all(root.join("Documents").join("sub"));
        std::fs::write(root.join("Documents").join("report.pdf"), b"x").unwrap();
        root
    }

    #[test]
    fn test_r92_sanitize_rejects_absolute_and_drive() {
        // S1：绝对路径/盘符 → PathOutsideRoot（不进入解析）。
        let root = fs_root();
        for req in [
            "C:\\Windows\\x",
            "c:/evil",
            "D:",
            "/etc/passwd",
            "\\windows\\system32",
            "/Documents/report.pdf",
        ] {
            let e = sanitize_fs_path(&root, req).unwrap_err();
            assert_eq!(fs_code(&e), FsErrCode::PathOutsideRoot, "S1 {req:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_r92_sanitize_rejects_dotdot_and_empty_components() {
        // S2：dotdot/空/`.` 组件 → 拒（不尝试"抵消"再回检）。
        let root = fs_root();
        for req in [
            "..\\..\\evil",
            "../../evil",
            "../Documents/report.pdf",
            ".",
            "..",
            "Documents/../..",
            "a//b",      // 空组件
            "a/b/",      // 尾随分隔符 → 空组件
        ] {
            let e = sanitize_fs_path(&root, req).unwrap_err();
            assert_eq!(fs_code(&e), FsErrCode::PathOutsideRoot, "S2 {req:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_r92_sanitize_rejects_control_chars() {
        // S3：ASCII 控制字符 + NUL → PathTooLong（非法字符归此码，细节在日志）。
        let root = fs_root();
        for req in ["a\0b", "a\x01b", "a\x1fb", "a\x7fb"] {
            let e = sanitize_fs_path(&root, req).unwrap_err();
            assert_eq!(fs_code(&e), FsErrCode::PathTooLong, "S3 {req:?}");
        }
        // UTF-8 合法宽松放行（同族 sanitize_filename 口径）。
        assert!(sanitize_fs_path(&root, "中文报告.pdf").is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_r92_sanitize_rejects_overlong() {
        // S6：> 512 字节 → PathTooLong（先于 IO）。
        let root = fs_root();
        let long = format!("Documents/{}", "a".repeat(FS_PATH_MAX_BYTES));
        let e = sanitize_fs_path(&root, &long).unwrap_err();
        assert_eq!(fs_code(&e), FsErrCode::PathTooLong, "S6 overlong");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_r92_sanitize_rejects_reserved_components() {
        // S5：组件级 Windows 保留名（复用 sanitize_filename 保留名表）。
        let root = fs_root();
        for req in ["CON", "con.txt", "COM1", "Documents\\NUL", "aux"] {
            let e = sanitize_fs_path(&root, req).unwrap_err();
            assert_eq!(fs_code(&e), FsErrCode::PathOutsideRoot, "S5 {req:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_r92_sanitize_accepts_valid_relative() {
        // 合法相对路径 → Ok（canonicalized 绝对路径）；"" = 根本身（§1.3）。
        let root = fs_root();
        let p = sanitize_fs_path(&root, "Documents/report.pdf").unwrap();
        assert!(p.starts_with(&root));
        assert!(p.ends_with("Documents/report.pdf"));
        assert!(p.exists());
        // "" = 根。
        assert_eq!(sanitize_fs_path(&root, "").unwrap(), root);
        // 不存在的 Mkdir 目标（父存在）→ Ok（最深存在祖先回检后拼回尾）。
        let m = sanitize_fs_path(&root, "Documents/sub/newdir").unwrap();
        assert!(!m.exists());
        assert!(m.to_string_lossy().starts_with(root.to_string_lossy().as_ref()));
        // 深层缺失（父亦不存在）→ 逐级上探，仍 Ok。
        let d = sanitize_fs_path(&root, "no/such/deep").unwrap();
        assert!(!d.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_r92_sanitize_root_missing_notfound() {
        // 根前置条件缺失 → NotFound（fail-closed 不猜）。
        let dir = tmp_dir("fsrootmissing");
        let missing = dir.join("nope");
        let e = sanitize_fs_path(&missing, "a").unwrap_err();
        assert_eq!(fs_code(&e), FsErrCode::NotFound);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_r92_sanitize_symlink_escape_rejected() {
        // S4：home 内符号链接指向根外 → canonicalize 回检拒（PathOutsideRoot）。
        let dir = tmp_dir("fssym");
        let root = std::fs::canonicalize(&dir.join("root")).unwrap_or_else(|e| {
            std::fs::create_dir_all(dir.join("root")).unwrap();
            std::fs::canonicalize(dir.join("root")).unwrap_or_else(|_| panic!("{e}"))
        });
        let outside = std::fs::canonicalize(&dir.join("outside")).unwrap_or_else(|e| {
            std::fs::create_dir_all(dir.join("outside")).unwrap();
            std::fs::canonicalize(dir.join("outside")).unwrap_or_else(|_| panic!("{e}"))
        });
        std::fs::write(outside.join("secret.txt"), b"s").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        // 链接指向根外：经链接的路径逃逸 → 拒。
        let e = sanitize_fs_path(&root, "link/secret.txt").unwrap_err();
        assert_eq!(fs_code(&e), FsErrCode::PathOutsideRoot, "S4 symlink escape");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_r92_sanitize_symlink_intermediate_rejected() {
        // S12：中间组件为指向根外的符号链接（尾部不存在）→ 逐级上探时
        // 祖先 canonicalize 逃逸 → 拒（删除穿越同链）。
        let dir = tmp_dir("fssymmid");
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let outside = std::fs::canonicalize(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("mid")).unwrap();
        let e = sanitize_fs_path(&root, "mid/does/not/exist.txt").unwrap_err();
        assert_eq!(fs_code(&e), FsErrCode::PathOutsideRoot, "S12 intermediate symlink");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- rename 冲突（S13）----

    #[test]
    fn test_r92_rename_conflict_already_exists() {
        let dir = tmp_dir("fsrename");
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        // 目标已存在 → AlreadyExists（跨平台统一，无静默覆盖）。
        let e = fs_rename_target_check(&dir.join("a.txt")).unwrap_err();
        assert_eq!(fs_code(&e), FsErrCode::AlreadyExists);
        // 目标不存在 → Ok。
        assert!(fs_rename_target_check(&dir.join("b.txt")).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- 写根门（§1.4）----

    #[test]
    fn test_r92_write_root_gate_in_out() {
        // 门启用（非空）：列内 Ok / 列外 PathOutsideRoot。
        let dir = tmp_dir("fswrgate");
        let inside = std::fs::canonicalize(&dir.join("share")).unwrap_or_else(|e| {
            std::fs::create_dir_all(dir.join("share")).unwrap();
            std::fs::canonicalize(dir.join("share")).unwrap_or_else(|_| panic!("{e}"))
        });
        let outside = std::fs::canonicalize(&dir.join("other")).unwrap_or_else(|e| {
            std::fs::create_dir_all(dir.join("other")).unwrap();
            std::fs::canonicalize(dir.join("other")).unwrap_or_else(|_| panic!("{e}"))
        });
        let gate = vec![inside.clone()];
        assert!(check_write_root_gate(&inside, &gate).is_ok(), "列内应放行");
        // 列内深层路径亦放行（前缀语义）。
        let deep = inside.join("a").join("b.txt");
        assert!(check_write_root_gate(&deep, &gate).is_ok(), "列内深层应放行");
        let e = check_write_root_gate(&outside, &gate).unwrap_err();
        assert_eq!(fs_code(&e), FsErrCode::PathOutsideRoot, "列外必须拒");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r92_write_root_gate_empty_disabled() {
        // 空语义 = 门禁用（§1.4：不额外限写根，受会话授权 × OS 权限约束）。
        let dir = tmp_dir("fswrgateempty");
        let p = dir.join("anywhere").join("x.txt");
        assert!(check_write_root_gate(&p, &[]).is_ok(), "空写根 = 门禁用");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r92_root_entries_env_pct_rejected_and_tilde() {
        // §1.4：含 % 条目拒绝（env 注入面，fail-closed）；~ 展开；不存在 → 不可用。
        let dir = tmp_dir("fsentries");
        let share = dir.join("share");
        std::fs::create_dir_all(&share).unwrap();
        let entries: Vec<String> = vec![
            share.to_string_lossy().to_string(),
            format!("%USERPROFILE%\\x"), // % 拒绝
            dir.join("missing").to_string_lossy().to_string(), // 不存在 → 不可用
        ];
        let res = resolve_fs_root_entries(&entries);
        assert_eq!(res.roots.len(), 1, "仅合法条目入列: {res:?}");
        assert_eq!(res.unavailable.len(), 2, "两条不可用（% + 缺失）: {res:?}");
        assert!(res.unavailable[0].1.contains("%"), "拒因 = env var");
        // ~ 展开（home 必存在）。
        let home_res = resolve_fs_browse_roots(&["~".to_string()]);
        assert_eq!(home_res.roots.len(), 1, "~ 应展开为 home: {home_res:?}");
        assert!(home_res.roots[0].is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r92_root_entries_dedup_and_sort_and_browse_default() {
        // §1.4：去重 + 稳定排序；浏览根空 = [home]（写根空 = 门禁用，无回落）。
        let dir = tmp_dir("fsdedup");
        let a = dir.join("aaa");
        let b = dir.join("bbb");
        let a2 = dir.join("Aaa");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        // a2 与 a 同路径（Windows 大小写同条目；unix 为不同条目——用 a 自身重复测去重）。
        let _ = a2;
        let entries: Vec<String> = vec![
            b.to_string_lossy().to_string(),
            a.to_string_lossy().to_string(),
            b.to_string_lossy().to_string(), // 重复
            a.to_string_lossy().to_string(), // 重复
        ];
        let res = resolve_fs_root_entries(&entries);
        assert_eq!(res.roots.len(), 2, "去重后两条目: {res:?}");
        assert!(res.roots[0] <= res.roots[1], "稳定排序");
        // 浏览根空配置 = [home] 单条目（§1.4 默认口径）。
        let browse = resolve_fs_browse_roots(&[]);
        assert_eq!(browse.roots.len(), 1, "浏览根默认 = [home]: {browse:?}");
        assert!(browse.roots[0].is_dir());
        // 写根空 = 空（门禁用），无 home 回落（刻意不对称）。
        let write = resolve_fs_write_roots(&[]);
        assert!(write.roots.is_empty(), "写根空 = 门禁用（无 home 回落）");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- FsRouter（§1.2/S8）----

    #[test]
    fn test_r92_router_rate_limit_sliding_window() {
        // S8：20 req/s 滑动窗（超限 RateLimited；1s 后出窗恢复）。
        let mut r = FsRouter::new();
        let t0 = Instant::now();
        for i in 0..FS_RATE_PER_SEC {
            assert_eq!(r.admit(t0).unwrap(), i as u32 + 1, "req_id 单调从 1 起");
        }
        assert_eq!(r.admit(t0), Err(FsErrCode::RateLimited), "第 21 个必须限速");
        // 1s 后滑动窗出窗 → 恢复。
        let t1 = t0 + Duration::from_secs(1);
        assert!(r.admit(t1).is_ok(), "窗口出窗后应放行");
    }

    #[test]
    fn test_r92_router_pending_cap() {
        // S8：未决 ≤ 8（第 9 个 RateLimited；complete 出账后恢复）。
        let mut r = FsRouter::new();
        let t0 = Instant::now();
        for i in 0..FS_MAX_PENDING {
            r.admit_inbound(1000 + i as u32, t0).unwrap();
        }
        assert_eq!(r.in_flight(), FS_MAX_PENDING);
        assert_eq!(r.admit_inbound(2000, t0), Err(FsErrCode::RateLimited));
        // 请求方 admit 同门（共享未决上限）。
        assert_eq!(r.admit(t0), Err(FsErrCode::RateLimited));
        // 出账后恢复。
        r.complete(1000);
        assert!(r.admit_inbound(2000, t0).is_ok());
    }

    #[test]
    fn test_r92_router_timeout_and_late_response() {
        // §1.2：单请求超时 10s → 到期 drop oneshot（请求方本地 Timeout，不产生
        // wire 帧）；迟到响应 → 静默丢弃（不报错）。
        let mut r = FsRouter::new();
        let t0 = Instant::now();
        let req_id = r.admit(t0).unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        r.bind(req_id, t0, tx);
        // 未到期：不超时。
        assert!(r.expire(t0 + Duration::from_secs(9)).is_empty());
        // 到期：出账 + drop（请求方 RecvError = 本地 Timeout 判据）。
        let due = r.expire(t0 + FS_REQ_TIMEOUT);
        assert_eq!(due, vec![req_id]);
        assert!(
            rx.try_recv().is_err(),
            "超时后 oneshot 必须关闭（请求方本地 Timeout）"
        );
        // 迟到响应：静默丢弃（false，不 panic 不报错）。
        let late = FsResponsePayload {
            ok: true,
            err: FsErrCode::Ok,
            payload: Vec::new(),
        };
        assert!(!r.deliver(req_id, late), "迟到响应必须静默丢弃");
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn test_r92_router_deliver_success() {
        // 正常关联：deliver 命中 → oneshot 收到 payload。
        let mut r = FsRouter::new();
        let t0 = Instant::now();
        let req_id = r.admit(t0).unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        r.bind(req_id, t0, tx);
        let payload = FsResponsePayload {
            ok: true,
            err: FsErrCode::Ok,
            payload: vec![1, 2, 3],
        };
        assert!(r.deliver(req_id, payload.clone()), "命中必须投递");
        assert_eq!(rx.try_recv().unwrap(), payload);
        assert_eq!(r.in_flight(), 0);
    }

    // ---- 响应上限 512 KiB（§1.2）----

    #[test]
    fn test_r92_pack_list_response_truncates_at_cap() {
        // 512KiB 硬上限：截断 + has_more；小列表不截断。
        let small: Vec<FsEntry> = (0..10)
            .map(|i| FsEntry {
                name: format!("f{i:03}.bin"),
                size: 100,
                mtime: 0,
                is_dir: false,
                is_symlink: false,
            })
            .collect();
        let (data, has_more) = pack_list_response(small.clone(), "root");
        assert!(!has_more, "小列表不截断");
        assert!(data.len() <= FS_RESPONSE_MAX_BYTES);
        let resp: FsResponsePayload = bincode::deserialize(&data).unwrap();
        let list: FsListPayload = bincode::deserialize(&resp.payload).unwrap();
        assert_eq!(list.entries.len(), 10);
        assert_eq!(list.root_display, "root");

        // 大列表（每条目名 64B，~8000 条目必然超 512KiB）→ 截断 + has_more。
        let big: Vec<FsEntry> = (0..8000)
            .map(|i| FsEntry {
                name: format!("{}.{}", i, "x".repeat(56)),
                size: 100,
                mtime: 0,
                is_dir: false,
                is_symlink: false,
            })
            .collect();
        let (data2, has_more2) = pack_list_response(big, "root");
        assert!(has_more2, "大列表必须 has_more");
        assert!(
            data2.len() <= FS_RESPONSE_MAX_BYTES,
            "超限必须截断: {}B",
            data2.len()
        );
        let resp2: FsResponsePayload = bincode::deserialize(&data2).unwrap();
        let list2: FsListPayload = bincode::deserialize(&resp2.payload).unwrap();
        assert!(list2.entries.len() < 8000 && !list2.entries.is_empty());
    }

    #[test]
    fn test_r92_build_fs_response_over_cap_io() {
        // 非 List op 超限 → Io（List 走截断语义）。
        assert!(build_fs_response(true, FsErrCode::Ok, vec![]).is_ok());
        let e = build_fs_response(true, FsErrCode::Ok, vec![0u8; FS_RESPONSE_MAX_BYTES + 1]);
        assert_eq!(e, Err(FsErrCode::Io), "超限必须回 Io");
    }

    // ---- FsPolicy（§1.6，v1.1 K1 修订版：两变体写行为一致）----

    #[test]
    fn test_r92_fs_policy_write_semantics_and_audit() {
        // v1.1（S9/K1）：Gui/Headless 写行为一致 = 均执行（非 NotSupported）；
        // 差异仅审计通道标记（Headless = 日志文件强制）。
        let dir = tmp_dir("fspolicy");
        let share = dir.join("share");
        std::fs::create_dir_all(&share).unwrap();
        let roots = vec![share.to_string_lossy().to_string()];
        let write = vec![share.to_string_lossy().to_string()];
        let gui = FsPolicy::gui(&roots, &write);
        let headless = FsPolicy::headless(&roots, &write);
        assert!(gui.write_allowed(), "GUI 写 = 执行（v1.1）");
        assert!(headless.write_allowed(), "Headless 写 = 执行（v1.1 K1 修订版，S9）");
        assert!(!gui.audit_to_log_file(), "GUI 审计 = tracing（非日志文件强制）");
        assert!(headless.audit_to_log_file(), "Headless 审计 = 日志文件强制");
        // 根解析一致（浏览根 = 配置列内；写根 = 配置列内，门启用）。
        assert_eq!(gui.roots().len(), 1);
        assert_eq!(headless.roots().len(), 1);
        assert_eq!(gui.write_roots().len(), 1);
        assert_eq!(headless.write_roots().len(), 1);
        // 写根空 = 门禁用（write_roots 空）。
        let open = FsPolicy::headless(&roots, &[]);
        assert!(open.write_roots().is_empty(), "写根空 = 门禁用");
        assert!(open.write_allowed(), "门禁用不影响写执行语义");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ────────────────────────────────────────────────────────────
    // ────────────────────────────────────────────────────────────

    /// 尾追加判别值 6 = `TransferRequest`（设计 §8.4「第 7 变体」）。bincode
    /// `FsRequestPayload` = `{ op }` 首 4B = 变体索引 u32 LE（单字段结构无
    /// 前缀——与旧端解法同字节）。
    #[test]
    fn test_r110p_fsop_discriminants_wire_pinned() {
        let idx = |op: FsOp| -> u32 {
            let b = bincode::serialize(&FsRequestPayload { op }).unwrap();
            u32::from_le_bytes(b[0..4].try_into().unwrap())
        };
        assert_eq!(
            idx(FsOp::List { path: "".into(), offset: 0, limit: 0 }),
            0
        );
        assert_eq!(idx(FsOp::Stat { path: "".into() }), 1);
        assert_eq!(idx(FsOp::Mkdir { path: "".into() }), 2);
        assert_eq!(idx(FsOp::Rename { from: "a".into(), to: "b".into() }), 3);
        assert_eq!(idx(FsOp::Delete { path: "a".into(), recursive: false }), 4);
        assert_eq!(idx(FsOp::Fetch { path: "a".into() }), 5);
        assert_eq!(
            idx(FsOp::TransferRequest {
                entries: Vec::new(),
                truncated: false
            }),
            6,
            "FsOp::TransferRequest 判别值漂移（尾追加 = 6，防未来重排/插值）"
        );
    }

    /// `Ok=0` 显式锚定不漂移、尾追加索引 12 = `Declined`；编解码回环。
    #[test]
    fn test_r110p_fserrcode_discriminants_wire_pinned_and_ok_anchor() {
        let idx = |c: FsErrCode| -> u32 {
            let b = bincode::serialize(&c).unwrap();
            assert_eq!(b.len(), 4, "FsErrCode 单元变体 wire = 4B u32");
            u32::from_le_bytes(b.as_slice().try_into().unwrap())
        };
        assert_eq!(idx(FsErrCode::Ok), 0, "Ok=0 显式锚定漂移");
        assert_eq!(idx(FsErrCode::NotFound), 1);
        assert_eq!(idx(FsErrCode::NotADirectory), 2);
        assert_eq!(idx(FsErrCode::IsADirectory), 3);
        assert_eq!(idx(FsErrCode::AlreadyExists), 4);
        assert_eq!(idx(FsErrCode::PermissionDenied), 5);
        assert_eq!(idx(FsErrCode::PathOutsideRoot), 6);
        assert_eq!(idx(FsErrCode::PathTooLong), 7);
        assert_eq!(idx(FsErrCode::Io), 8);
        assert_eq!(idx(FsErrCode::NotSupported), 9);
        assert_eq!(idx(FsErrCode::RateLimited), 10);
        assert_eq!(idx(FsErrCode::Internal), 11);
        assert_eq!(
            idx(FsErrCode::Declined),
            12,
            "Declined 尾追加 = 12（既有 12 值 0-11 不重排；任务书「第 12 值」\
             按 Ok 锚定后第 12 个错误值计，位置序以实测尾追加位钉死）"
        );
        // 编解码回环（S11 逐位回归同族）。
        let back: FsErrCode =
            bincode::deserialize(&bincode::serialize(&FsErrCode::Declined).unwrap()).unwrap();
        assert_eq!(back, FsErrCode::Declined);
    }

    /// `entries: Vec<TransferEntry{rel_path,size}>` + `truncated`，FILEMETA
    /// 255 先例同口径；§8.7④ 元数据仅承载相对路径+大小，零内容）。
    #[test]
    fn test_r110p_transfer_request_payload_roundtrip() {
        assert_eq!(TRANSFER_REQUEST_MAX_ENTRIES, 255, "FILEMETA 255 条目先例同口径");
        let op = FsOp::TransferRequest {
            entries: vec![
                TransferEntry {
                    rel_path: "docs/report.pdf".into(),
                    size: 21 * 1024 * 1024,
                },
                TransferEntry {
                    rel_path: "config.toml".into(),
                    size: 4096,
                },
            ],
            truncated: false,
        };
        let payload = FsRequestPayload { op };
        let wire = bincode::serialize(&payload).unwrap();
        let back: FsRequestPayload = bincode::deserialize(&wire).unwrap();
        assert_eq!(back, payload);
        // 上限边界形态（255 条目 + truncated=true）同契约可解。
        let full = FsRequestPayload {
            op: FsOp::TransferRequest {
                entries: (0..TRANSFER_REQUEST_MAX_ENTRIES)
                    .map(|i| TransferEntry {
                        rel_path: format!("f{i}.bin"),
                        size: i as u64,
                    })
                    .collect(),
                truncated: true,
            },
        };
        let back2: FsRequestPayload =
            bincode::deserialize(&bincode::serialize(&full).unwrap()).unwrap();
        assert_eq!(back2, full);
    }

    /// 零新负载结构）：`ok=false` + `err=Declined` + `payload` 空，经
    /// [`build_fs_response`] 契约路径产出；wire 字节可再序列化（契约一致性，
    /// S10 单帧丢弃口径依赖）。
    #[test]
    fn test_r110p_declined_receipt_roundtrip() {
        let data = build_fs_response(false, FsErrCode::Declined, Vec::new()).unwrap();
        let resp: FsResponsePayload = bincode::deserialize(&data).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.err, FsErrCode::Declined);
        assert!(resp.payload.is_empty());
        assert_eq!(bincode::serialize(&resp).unwrap(), data);
    }

    /// 模拟旧端解码新端 wire 字节流 = 未知变体 Err → **单帧丢弃、会话存活**
    ///（先例同族：`test_r92_fileop_discriminants_wire_pinned` 未知变体 Err
    /// 断言 + ui `file frame decode failed (dropped)` 臂）；既有 op/码 →
    /// 旧端透明解码（防重排反证）。
    #[test]
    fn test_r110p_old_peer_decode_fallback_single_frame_drop() {
        #[derive(Deserialize, PartialEq, Debug)]
        enum LegacyFsOp {
            List { path: String, offset: u32, limit: u32 },
            Stat { path: String },
            Mkdir { path: String },
            Rename { from: String, to: String },
            Delete { path: String, recursive: bool },
            Fetch { path: String },
        }
        #[derive(Deserialize, PartialEq, Debug)]
        enum LegacyFsErrCode {
            Ok,
            NotFound,
            NotADirectory,
            IsADirectory,
            AlreadyExists,
            PermissionDenied,
            PathOutsideRoot,
            PathTooLong,
            Io,
            NotSupported,
            RateLimited,
            Internal,
        }
        #[derive(Deserialize)]
        struct LegacyFsResponse {
            ok: bool,
            err: LegacyFsErrCode,
            payload: Vec<u8>,
        }
        // ① 旧端收新端 TransferRequest 通告帧 = 内层解码失败（单帧丢弃、会话存活）。
        let req = FsRequestPayload {
            op: FsOp::TransferRequest {
                entries: vec![TransferEntry {
                    rel_path: "a.pdf".into(),
                    size: 21 * 1024 * 1024,
                }],
                truncated: false,
            },
        };
        // FsRequestPayload 单字段 → wire 与 op 字节流同（旧端解 op 字段同字节）。
        let wire = bincode::serialize(&req).unwrap();
        assert!(
            bincode::deserialize::<LegacyFsOp>(&wire).is_err(),
            "旧端（6 变体索引集）解 TransferRequest 必须失败 = 单帧丢弃前提"
        );
        // ② 既有 6 op → 旧端透明解码（防重排反证；match 逐字段读取 = 旧端
        //    形态一致性断言）。
        let cases: [FsOp; 6] = [
            FsOp::List { path: "d".into(), offset: 0, limit: 500 },
            FsOp::Stat { path: "f".into() },
            FsOp::Mkdir { path: "m".into() },
            FsOp::Rename { from: "a".into(), to: "b".into() },
            FsOp::Delete { path: "x".into(), recursive: true },
            FsOp::Fetch { path: "y".into() },
        ];
        for op in cases {
            let wire = bincode::serialize(&FsRequestPayload { op }).unwrap();
            let legacy: LegacyFsOp = bincode::deserialize(&wire).unwrap();
            match legacy {
                LegacyFsOp::List { path, offset, limit } => {
                    assert_eq!((path, offset, limit), ("d".to_string(), 0, 500))
                }
                LegacyFsOp::Stat { path } => assert_eq!(path, "f"),
                LegacyFsOp::Mkdir { path } => assert_eq!(path, "m"),
                LegacyFsOp::Rename { from, to } => {
                    assert_eq!((from, to), ("a".to_string(), "b".to_string()))
                }
                LegacyFsOp::Delete { path, recursive } => {
                    assert_eq!((path, recursive), ("x".to_string(), true))
                }
                LegacyFsOp::Fetch { path } => assert_eq!(path, "y"),
            }
        }
        // ③ 旧端收 Declined 负回执 = 解码失败（单帧丢弃）；既有码（Ok）→
        //    透明（Ok=0 锚定不漂移反证）。
        let declined = FsResponsePayload {
            ok: false,
            err: FsErrCode::Declined,
            payload: Vec::new(),
        };
        let wire = bincode::serialize(&declined).unwrap();
        assert!(
            bincode::deserialize::<LegacyFsResponse>(&wire).is_err(),
            "旧端（0-11 索引集）解 Declined 必须失败 = 单帧丢弃前提"
        );
        let ok_resp = FsResponsePayload {
            ok: true,
            err: FsErrCode::Ok,
            payload: Vec::new(),
        };
        let legacy: LegacyFsResponse =
            bincode::deserialize(&bincode::serialize(&ok_resp).unwrap()).unwrap();
        assert!(legacy.ok);
        assert_eq!(legacy.err, LegacyFsErrCode::Ok);
        assert!(legacy.payload.is_empty());
    }
}
