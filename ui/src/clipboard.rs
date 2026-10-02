//! M13-T003: 客户端剪贴板共享 — 轮询本地变更 → 推送；接收远端推送 → 写入本地。
//!
//! 传输格式：`EncodedPacket { kind: PacketKind::Clipboard, data: <分片负载> }`，
//! 复用 SecureChannel 键鼠同款可靠发送路径（`ChannelTag::Clipboard = 0x05`）。
//! 分片负载 = `[flags: u8][chunk bytes]`：
//! - `flags & 0x01` = START（首片）；`flags & 0x02` = END（末片）；
//! - 单片消息 flags = START|END；大文本按 [`MAX_CLIP_CHUNK`] 分片（SecureChannel
//!   单帧 payload 上限 ~1200B，分片大小为其留余量）；
//!   body = `bincode(FileClipMetaFragment)`，分片号带内自描述，**不置 START/END 位**
//!   = 唯一旧端安全形态：旧客户端重组缓冲恒不激活 → 零日志零写板零状态副作用，
//!   §2.3 逐步推导）。判别：`flags & 0x04 != 0` → 元数据路径；否则既有文本路径
//!   （0/1/2 位组合逐位不变）。两路径互斥、互不共享重组缓冲。
//!
//! 防回环策略：
//! - 本地轮询（500ms）只推送**非空**且与上次不同的文本；
//! - 远端推送写入本地后进入冷却窗口（1s），冷却期内本地回读到的同一文本
//!   不重复上推（否则形成 ping-pong 循环）；
//!   ②服务端 CF_HDROP 签名去重（同 sig 不重推）③服务端不给自板设占位（占位是
//!   客户端需要，结构上不存在服务端自占位回环）④文本↔文件切换推 CLEAR（单次沿，
//!   无 ping-pong）。

use kirin_desk_media::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `#[path]` = 显式锚定本目录（非 mod-rs 风格的子模块目录约定会把子模块解析
/// 到 `ui/src/clipboard/` 子目录，与本岗声明文件集 `ui/src/clipboard_files.rs`
/// 冲突；lib.rs 零改动约束下用 path 属性解决）。
#[path = "clipboard_files.rs"]
mod clipboard_files;
pub use clipboard_files::read_local_files;
// 写板面 `write_cf_hdrop` + 序号 `clipboard_sequence_number` 需被 lib.rs
// （on_finish 落盘写板 / 轮询 tick 序号基线）调用——私有模块对 crate 根不可见
// （E0603），无此 re-export 则任务书「函数在 clipboard_files.rs + lib.rs 调用」
// 探测）需被 lib.rs（会话窗无事件形态接管判据「本板无文本」）调用——同一
// E0603 约束。读/写面逻辑零 diff。
pub use clipboard_files::{clipboard_sequence_number, has_cf_unicode_text, write_cf_hdrop};
// 写板素材布局钉死）调用——同一 E0603 约束。序列化本体零 diff；仅测试
// 构建可见（生产零消费 = 零告警漂移）。
#[cfg(test)]
pub(crate) use clipboard_files::build_hdrop_payload;
// （防回环守卫行为断言——延迟板本进程读面短路）仅测试构建可见（生产消费
// 面在 clipboard_files 内部经 crate 路径直连）。序列化/读面本体零 diff。
#[cfg(test)]
pub(crate) use clipboard_files::{has_cf_hdrop as r194_has_cf_hdrop, read_cf_hdrop as r194_read_cf_hdrop};
// （延迟渲染应答 = 真实路径 HDROP 组板）——同 E0603 约束；序列化本体
// 零 diff。
pub(crate) use clipboard_files::build_hdrop_payload as r194_build_hdrop_payload;
// （聚焦 Explorer 目录探测，纯读/有界/fail-closed）需被 lib.rs（臂 ②
// 粘贴拉取落点 / 文件会话接收落点两消费点）调用——同一 E0603 约束。
// 读/写面逻辑零 diff。
pub use clipboard_files::probe_focused_explorer_dir;

/// 本地剪贴板轮询间隔。
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// 远端写入后的回环抑制窗口（毫秒）。
pub const ECHO_SUPPRESS_MS: u64 = 1000;

/// 单帧剪贴板分片负载上限（SecureChannel 单帧 ~1200B，留帧头/加密余量）。
pub const MAX_CLIP_CHUNK: usize = 1000;

/// 远端单次推送总长度上限（8 MiB，防内存膨胀）。
/// S-11a（F-13）：该上限为**累计**语义——START→END 期间重组缓冲总长不得超过
/// 此值（原实现只校验单片，START + 永不发 END 的分片流可无界增长）。
/// 取值依据（任务文档 §7 执行记录）：发送侧无总长裁剪，合法大文本/图片
/// base64 剪贴板可超过 1MB 以分片形式到达——8 MiB 覆盖此类合法用例且与
/// 本批次 S-11c 的媒体单帧上限 `MAX_FRAME_BYTES`(8 MiB) 口径一致；超出
/// 部分属异常输入，逐片累计超限即清空重组缓冲（单连接内存上界 8 MiB）。
pub const MAX_CLIP_TOTAL: usize = 8 * 1024 * 1024;

/// 分片标志：START（首片）。
pub const CLIP_FLAG_START: u8 = 0x01;
/// 分片标志：END（末片）。
pub const CLIP_FLAG_END: u8 = 0x02;
/// `bincode(FileClipMetaFragment{seq,total,payload})`）。**不置 START/END 位**：
/// 旧客户端重组缓冲恒不激活（写板必须 END 位）→ 零日志零写板零状态副作用
/// （§2.3 逐步推导）= 唯一旧端安全形态。flags 0/1/2 位组合逐位不变。
pub const CLIP_FLAG_FILEMETA: u8 = 0x04;

/// 「累计有界」同型）。超限 = 丢弃本次元数据 + WARN 30s 节流（不 panic 不挂起）。
pub const MAX_META_TOTAL: usize = 64 * 1024;
pub const MAX_META_ENTRIES: usize = 255;
pub const MAX_META_FRAGMENTS: usize = 255;
pub const MAX_REL_PATH_BYTES: usize = 512;
pub const FILEMETA_VERSION: u8 = 1;

/// 格式」等持续性读错每 tick 一次，不节流必刷屏（30s 内至多一行）。
pub const CLIP_READ_ERR_WARN_THROTTLE: Duration = Duration::from_secs(30);

/// 绝对路径 + size + is_dir）。仅本端内存使用——**绝对路径永不出 wire**
/// （wire 面 = root 相对路径 + size + is_dir + fetchable，§2.2/§7.4 零内容红线）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsFileBoard {
    pub entries: Vec<OsFileEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsFileEntry {
    /// 绝对路径（仅本端内存，不出 wire）。
    pub abs_path: String,
    /// 文件大小（字节；读取失败 = 0，Fetch 侧按实际文件重推 tid）。
    pub size: u64,
    /// 是否目录（v1 目录不可拉取：占位显示、Ctrl+V 跳过；§2.2）。
    pub is_dir: bool,
}

/// Windows 剪贴板可同板并存 CF_HDROP + CF_UNICODETEXT → 判定优先级
/// File > Text > Other（文件优先，与 §3.2 拦截优先级同构）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BoardKind {
    /// 无文件、无（非空）文本——空板 / 图片等其他格式 / 尚未观测。
    #[default]
    Other,
    /// 有（非空）文本。
    Text,
    /// 有 CF_HDROP 文件清单（非空）。
    File,
}

/// version 字段保演进）。零内容：只带 root 相对路径 + size + is_dir +
/// 复制的目录内部披露，零根外枚举；顶层布局零变化）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileClipMeta {
    /// = [`FILEMETA_VERSION`]（1）；接收侧未知版本 fail-closed 丢弃。
    pub version: u8,
    /// true = 服务端板已无文件 → 客户端清 pending（本机占位文本不主动擦除，§2.6）。
    pub cleared: bool,
    /// 条目超上限截断（占位显示「…更多」）。
    pub truncated: bool,
    /// 文件清单（上限 [`MAX_META_ENTRIES`]）。
    pub entries: Vec<FileClipEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileClipEntry {
    /// 相对 fs_roots 根的相对路径（**零绝对路径/零盘符/零 UNC**，§2.2/§7.2）。
    /// 文件在全部根外 → `fetchable=false` 且此处 = 仅文件名（占位仍显示）。
    pub rel_path: String,
    /// 文件大小（字节）。
    pub size: u64,
    /// 是否目录（v1 目录不可拉取：占位显示、Ctrl+V 跳过；目录树拉取 = v2 口）。
    pub is_dir: bool,
    /// false = 文件在 fs_roots 全部根之外（占位显示、Ctrl+V 跳过 + 提示，§2.2）。
    pub fetchable: bool,
}

/// 不依赖 START/END 位）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileClipMetaFragment {
    /// 分片序号（1 起）。
    pub seq: u8,
    /// 总片数（1..=255）。
    pub total: u8,
    /// 本片 `bincode(FileClipMeta)` 字节段。
    pub payload: Vec<u8>,
}

/// 本地剪贴板抽象（平台实现：arboard；测试：内存假件）。
pub trait ClipboardIo: Send + 'static {
    /// 读取当前剪贴板文本（无文本/读取失败 → None）。
    fn get_text(&mut self) -> Option<String>;
    /// 写入剪贴板文本，返回是否成功。
    fn set_text(&mut self, text: &str) -> bool;
    ///
    /// 默认实现 = `None`（无文件能力，fail-closed）：测试假件（`FakeClipboard`/
    /// `FakeSrvClip`）零改动零编译波及；unix `OsClipboard` 经 [`clipboard_files`]
    /// 空实现同样 `None` 保构建绿；Windows `OsClipboard` 走 winapi 直读。
    fn get_file_meta(&mut self) -> Option<OsFileBoard> {
        None
    }
}

/// arboard 平台实现（Windows / macOS / Linux X11+Wayland）。
pub struct OsClipboard {
    inner: arboard::Clipboard,
    last_get_err_warn: std::time::Instant,
    /// 窗口 → 首次失败必告警）。
    last_file_err_warn: std::time::Instant,
}

impl OsClipboard {
    /// 初始化系统剪贴板；不可用（如 headless 环境）返回 None。
    pub fn new() -> Option<Self> {
        arboard::Clipboard::new().ok().map(|inner| {
            let now = std::time::Instant::now();
            Self {
                inner,
                last_get_err_warn: now - CLIP_READ_ERR_WARN_THROTTLE,
                last_file_err_warn: now - CLIP_READ_ERR_WARN_THROTTLE,
            }
        })
    }
}

impl ClipboardIo for OsClipboard {
    fn get_text(&mut self) -> Option<String> {
        match self.inner.get_text() {
            Ok(t) => Some(t),
            // 日志零 clipboard 行」的盲区之一）；30s 节流防轮询刷屏。
            Err(e) => {
                if self.last_get_err_warn.elapsed() >= CLIP_READ_ERR_WARN_THROTTLE {
                    self.last_get_err_warn = std::time::Instant::now();
                    tracing::warn!(
                    );
                }
                None
            }
        }
    }

    fn set_text(&mut self, text: &str) -> bool {
        self.inner.set_text(text.to_string()).is_ok()
    }

    ///
    /// - 板无 CF_HDROP 格式 = **常态无文件**（多数 tick）→ 静默 `None`，不告警；
    /// - 格式在但读取失败（他进程持板 / Winlogon 锁 / session 0）→ `None` +
    ///   不重试风暴（tick 内零重试；500ms 轮询下 tick 自然再读）；
    /// - 只读不写板（`CloseClipboard` 即复原，不碰既有格式）；文本通道独立
    ///   不受影响（两读独立）。
    fn get_file_meta(&mut self) -> Option<OsFileBoard> {
        if !clipboard_files::has_cf_hdrop() {
            return None;
        }
        match clipboard_files::read_cf_hdrop() {
            Some(board) if !board.entries.is_empty() => Some(board),
            _ => {
                if self.last_file_err_warn.elapsed() >= CLIP_READ_ERR_WARN_THROTTLE {
                    self.last_file_err_warn = std::time::Instant::now();
                    tracing::warn!(
                         this tick treated as no change (throttled 30s — 窗口内持续失败不再重复记录，不重试风暴)"
                    );
                }
                None
            }
        }
    }
}

/// 将文本编码为剪贴板分片负载序列（首个 START、末个 END；单片 = START|END）。
/// 空文本 → 空序列（不推送）。
pub fn encode_clipboard_payloads(text: &str, max_chunk: usize) -> Vec<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || max_chunk == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        let end = (offset + max_chunk).min(bytes.len());
        let mut flags = 0u8;
        if offset == 0 {
            flags |= CLIP_FLAG_START;
        }
        if end == bytes.len() {
            flags |= CLIP_FLAG_END;
        }
        let mut chunk = Vec::with_capacity(1 + (end - offset));
        chunk.push(flags);
        chunk.extend_from_slice(&bytes[offset..end]);
        out.push(chunk);
        offset = end;
        if end == bytes.len() {
            break;
        }
    }
    out
}

/// 有界：累计 payload ≤ [`MAX_META_TOTAL`]（S-11a 同型）、分片数 ≤ 255。
#[derive(Debug)]
struct MetaRecv {
    /// 本流总片数（1..=255）。
    total: u8,
    /// 按 seq（1 起）在位的片（同 seq 重复帧幂等覆盖，乱序可合并）。
    parts: Vec<Option<Vec<u8>>>,
    /// 累计 payload 字节数（超限检查）。
    acc_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipApplyEvent {
    /// 一份完整文本到达并已写入本地（含防回环记录）——既有语义。
    TextApplied(String),
    /// 一份完整文件元数据到达（`cleared=true` = CLEAR；否则文件清单），
    /// 占位写板 + 防回环记录已完成（CLEAR 不写板）。
    MetaApplied(FileClipMeta),
    /// 本帧未产生 apply 结果（未完成分片 / 超限丢弃 / 坏帧 / 无事件）。
    Silent,
}

/// 剪贴板同步状态机（纯逻辑，可单测：不依赖 OS 剪贴板）。
pub struct ClipboardSyncState {
    /// 本地最近一次已推送内容（去重）。
    last_pushed: Option<String>,
    /// 远端最近一次写入内容（防回环比对）。
    last_remote_set: Option<String>,
    /// 远端写入冷却截止（epoch ms）。
    suppress_until_ms: u64,
    /// 远端分片重组缓冲（START→END 期间累积）。
    reassembly: Option<Vec<u8>>,
    //    既有 12 例剪贴板单测零断言变化）──
    /// §2.6：上一 tick 观测到的板状态（沿检测）。
    last_board_kind: BoardKind,
    /// §2.5 条 2：已推文件元数据签名（sig = entries 序列 (rel_path,size) 稳定
    /// 哈希，顺序敏感）；同 sig 不重推（服务端 CF_HDROP 不重播）。
    last_pushed_meta_sig: Option<u64>,
    /// §2.5：客户端 apply 元数据后记录的签名（`cleared` → None）。
    last_applied_meta_sig: Option<u64>,
    /// 清 pending 比对：本机板 ≠ 占位 = 用户复制了新内容）。
    placeholder_text: Option<String>,
    /// §2.1：FILEMETA 帧重组缓冲（独立于文本重组，两路径互斥）。
    meta_rx: Option<MetaRecv>,
    /// 窗口 → 首次失败必告警，30s 内至多一行，§8.1 日志纪律）。
    last_meta_warn: std::time::Instant,
}

impl ClipboardSyncState {
    pub fn new() -> Self {
        let now = std::time::Instant::now();
        Self {
            last_pushed: None,
            last_remote_set: None,
            suppress_until_ms: 0,
            reassembly: None,
            last_board_kind: BoardKind::Other,
            last_pushed_meta_sig: None,
            last_applied_meta_sig: None,
            placeholder_text: None,
            meta_rx: None,
            last_meta_warn: now - CLIP_READ_ERR_WARN_THROTTLE,
        }
    }

    /// 一行节流；旧客户端丢帧 = 零日志——本方法只被新客户端元数据路径调用）。
    fn warn_meta_throttled(&mut self, msg: &str) {
        if self.last_meta_warn.elapsed() >= CLIP_READ_ERR_WARN_THROTTLE {
            self.last_meta_warn = std::time::Instant::now();
        }
    }

    /// 轮询本地剪贴板：返回应推送的文本（None = 无变化 / 冷却回环 / 空内容）。
    ///
    /// **零改动**（客户端不推元数据，元数据通道严格服务端→客户端单向，§6.1）。
    pub fn poll_local(&mut self, now_ms: u64, io: &mut dyn ClipboardIo) -> Option<String> {
        let text = io.get_text()?;
        self.decide_local_push(now_ms, &text)
    }

    /// 复用，避免同 tick 二次读板）。语义与 `poll_local` 逐位一致：
    /// 空内容 / 冷却回环 / 无变化 → None；否则记 `last_pushed` 并返回文本。
    fn decide_local_push(&mut self, now_ms: u64, text: &str) -> Option<String> {
        if text.is_empty() {
            return None; // 空剪贴板不推送
        }
        // 冷却期内远端刚写入的同一文本 → 不回推（防 ping-pong）。
        if now_ms < self.suppress_until_ms
            && self.last_remote_set.as_deref() == Some(text)
        {
            return None;
        }
        if self.last_pushed.as_deref() == Some(text) {
            return None; // 无变化
        }
        self.last_pushed = Some(text.to_string());
        Some(text.to_string())
    }

    /// 处理一帧远端剪贴板负载（分片感知）。
    ///
    /// 返回 `Some(完整文本)` = 本帧使一份完整内容到达并已写入本地（含防回环
    /// 记录）——供调用方打 apply 成功 INFO（低频：仅内容变更时）：
    /// - 文本帧（flags 0/1/2 位，既有语义逐位不变）→ `Some(文本)`；
    ///   防回环记录完成）；CLEAR 元数据帧 → `None`（不写板）；
    /// - `None` 亦覆盖 = 未完成分片 / 超限丢弃 / 空文本 / 坏 UTF-8 / 坏元数据帧
    ///   （不写入）。
    ///
    /// 同构复用；既有单测断言零变化，仅调用点补 `let _ =`）。
    /// （返回类型扩展 = 事件枚举）；本方法保持既有签名（`Option<String>`）=
    /// 事件方法以接线 `pending_clip_meta`（§8.2 边界表）。
    pub fn apply_remote_frame(
        &mut self,
        now_ms: u64,
        payload: &[u8],
        io: &mut dyn ClipboardIo,
    ) -> Option<String> {
        match self.apply_remote_frame_event(now_ms, payload, io) {
            ClipApplyEvent::TextApplied(text) => Some(text),
            // 占位文本 = 与写板内容同源（纯函数确定性再生成，零额外状态）。
            ClipApplyEvent::MetaApplied(meta) => {
                if meta.cleared {
                    None // CLEAR 不写板（本机占位文本不主动擦除，§2.6）
                } else {
                    Some(clip_meta_placeholder(&meta))
                }
            }
            ClipApplyEvent::Silent => None,
        }
    }

    ///
    /// 判别（§2.1）：`flags & CLIP_FLAG_FILEMETA != 0` → 元数据路径（自含分片，
    /// 独立重组缓冲）；否则 → 既有文本路径（flags 0/1/2 位组合**逐位不变**）。
    /// 两路径互斥、互不共享重组缓冲。
    pub fn apply_remote_frame_event(
        &mut self,
        now_ms: u64,
        payload: &[u8],
        io: &mut dyn ClipboardIo,
    ) -> ClipApplyEvent {
        let Some((&flags, chunk)) = payload.split_first() else {
            return ClipApplyEvent::Silent;
        };
        if flags & CLIP_FLAG_FILEMETA != 0 {
            return self.apply_meta_frame(now_ms, chunk, io);
        }
        if chunk.len() > MAX_CLIP_TOTAL {
            self.reassembly = None;
            return ClipApplyEvent::Silent;
        }
        if flags & CLIP_FLAG_START != 0 {
            // 新拷贝开始 → 丢弃旧的未完成缓冲。
            self.reassembly = Some(Vec::new());
        }
        if let Some(buf) = self.reassembly.as_mut() {
            // S-11a（F-13）：追加前累计上限检查——重组缓冲 + 本片不得超过
            // MAX_CLIP_TOTAL，超限清空缓冲并丢弃本次流（缓冲有界）。
            // 合法用例不受影响：编码侧单片 ≤ MAX_CLIP_CHUNK(1000B)，总长
            // ≤ MAX_CLIP_TOTAL 的合法分片流逐片追加必然通过本检查（取值依据
            // 见任务文档 §7）。
            if buf.len().saturating_add(chunk.len()) > MAX_CLIP_TOTAL {
                self.reassembly = None;
                return ClipApplyEvent::Silent;
            }
            buf.extend_from_slice(chunk);
        }
        if flags & CLIP_FLAG_END != 0 {
            let bytes = self.reassembly.take().unwrap_or_default();
            // 空文本不写入（与发送侧"空剪贴板不推送"策略一致）。
            if !bytes.is_empty() {
                match String::from_utf8(bytes) {
                    Ok(text) => {
                        self.apply_remote(now_ms, &text, io);
                        return ClipApplyEvent::TextApplied(text);
                    }
                    Err(e) => {
                        tracing::debug!(
                            "[M13-T003] remote clipboard payload not valid UTF-8 ({} bytes) — dropped",
                            e.as_bytes().len()
                        );
                    }
                }
            }
        }
        ClipApplyEvent::Silent
    }

    /// fail-closed：任何解码失败/形态非法/超限 = 丢弃该流 + WARN 30s 节流 +
    /// 状态机复位（**绝不把元数据字节当文本写板**，S-11a 有界重组同型）。
    fn apply_meta_frame(
        &mut self,
        now_ms: u64,
        body: &[u8],
        io: &mut dyn ClipboardIo,
    ) -> ClipApplyEvent {
        // 1) 分片解码（body = bincode(FileClipMetaFragment)）。
        let frag = match bincode::deserialize::<FileClipMetaFragment>(body) {
            Ok(f) => f,
            Err(_) => {
                self.meta_rx = None;
                self.warn_meta_throttled("metadata fragment bincode decode failed — frame dropped");
                return ClipApplyEvent::Silent;
            }
        };
        // 2) 形态校验（fail-closed：seq/total 越界 = 坏帧，复位不合并）。
        if frag.total == 0
            || frag.total as usize > MAX_META_FRAGMENTS
            || frag.seq == 0
            || frag.seq > frag.total
        {
            self.meta_rx = None;
            self.warn_meta_throttled("metadata fragment malformed (seq/total out of range) — dropped");
            return ClipApplyEvent::Silent;
        }
        // 3) 新流 / total 变化 → 重建重组槽（旧缓冲不跨流；同 total 乱序/重复帧合并）。
        if self
            .meta_rx
            .as_ref()
            .map_or(true, |r| r.total != frag.total)
        {
            self.meta_rx = Some(MetaRecv {
                total: frag.total,
                parts: vec![None; frag.total as usize],
                acc_len: 0,
            });
        }
        let slot = frag.seq as usize - 1;
        // 4) 累计上限检查（S-11a 同型：缓冲有界，超限丢弃整流）——
        //    读检查与写复位分离，避免可变借用交叉。
        let present = self
            .meta_rx
            .as_ref()
            .expect("just initialized above")
            .parts[slot]
            .is_some();
        if !present {
            let pl = frag.payload.len();
            let acc = self.meta_rx.as_ref().expect("just initialized above").acc_len;
            if pl == 0 || acc.saturating_add(pl) > MAX_META_TOTAL {
                self.meta_rx = None;
                self.warn_meta_throttled("metadata reassembly over 64KiB bound — stream dropped");
                return ClipApplyEvent::Silent;
            }
            let rx = self.meta_rx.as_mut().expect("just initialized above");
            rx.acc_len += pl;
            rx.parts[slot] = Some(frag.payload);
        }
        // 5) 流未完成 → 静默（无日志：正常分片到达节奏，§8.1 日志纪律）。
        let complete = self
            .meta_rx
            .as_ref()
            .expect("just initialized above")
            .parts
            .iter()
            .all(Option::is_some);
        if !complete {
            return ClipApplyEvent::Silent;
        }
        // 6) 齐片 → 按 seq 序拼接 → 解码 FileClipMeta（取走即复位重组槽）。
        let rx = self.meta_rx.take().expect("just initialized above");
        let mut joined = Vec::with_capacity(rx.acc_len);
        for part in rx.parts {
            joined.extend_from_slice(&part.expect("validated: all parts present"));
        }
        let meta = match bincode::deserialize::<FileClipMeta>(&joined) {
            Ok(m) => m,
            Err(_) => {
                self.warn_meta_throttled("metadata body bincode decode failed — stream dropped");
                return ClipApplyEvent::Silent;
            }
        };
        if meta.version != FILEMETA_VERSION {
            // 未知版本 → fail-closed 丢弃（不猜语义；version 字段保演进的代价）。
            self.warn_meta_throttled(&format!(
                "metadata version {} unknown (current {}) — dropped",
                meta.version, FILEMETA_VERSION
            ));
            return ClipApplyEvent::Silent;
        }
        if meta.cleared {
            // 7a) CLEAR（§2.6）：客户端清 pending（`pending_clip_meta` 槽在
            // 惰性文本（无 pending → Ctrl+V 不拦截；用户复制任何新内容自然覆盖）。
            self.last_applied_meta_sig = None;
            self.placeholder_text = None;
            return ClipApplyEvent::MetaApplied(meta);
        }
        // 7b) 文件清单：占位写本机板 + 防回环记录（§2.5 条 1：占位同步
        // last_pushed + last_remote_set + 冷却窗 ECHO_SUPPRESS_MS，与 apply_remote
        // 同语义）→ 本机 500ms 轮询回读占位 = 去重命中 → 不回推（零新逻辑）。
        let sig = filemeta_sig(&meta);
        let placeholder = clip_meta_placeholder(&meta);
        self.last_applied_meta_sig = Some(sig);
        self.last_remote_set = Some(placeholder.clone());
        self.suppress_until_ms = now_ms + ECHO_SUPPRESS_MS;
        self.last_pushed = Some(placeholder.clone());
        // 低频：仅元数据 apply 时，非轮询节奏）。
        if !io.set_text(&placeholder) {
            tracing::warn!(
                 remote file meta NOT written to local board",
                meta.entries.len()
            );
        }
        self.placeholder_text = Some(placeholder);
        ClipApplyEvent::MetaApplied(meta)
    }

    /// 应用完整远端文本：写入本地并记录冷却，防回环。
    fn apply_remote(&mut self, now_ms: u64, text: &str, io: &mut dyn ClipboardIo) {
        self.last_remote_set = Some(text.to_string());
        self.suppress_until_ms = now_ms + ECHO_SUPPRESS_MS;
        // 同步 last_pushed，避免远端内容随后被本地轮询误判为"新内容"。
        if !text.is_empty() {
            self.last_pushed = Some(text.to_string());
        }
        // 实际未上板但状态机已记录冷却，后续该文本永远不再补推）。
        if !io.set_text(text) {
            tracing::warn!(
                text.len()
            );
        }
    }
}

/// 构造剪贴板推送包列表（分片 → EncodedPacket，供 `SecureChannelSender::send_packets`）。
pub fn clipboard_packets(text: &str) -> Vec<EncodedPacket> {
    encode_clipboard_payloads(text, MAX_CLIP_CHUNK)
        .into_iter()
        .map(|data| EncodedPacket {
            ts: Timestamp::now(),
            kind: PacketKind::Clipboard,
            data,
            is_key: false,
        })
        .collect()
}

//
// wire 面 = 0x05 Clipboard 通道 flags 扩展 0x04（FILEMETA，自含分片、不置
// START/END）；body 结构 `FileClipMeta/FileClipMetaFragment` = ui 层私有，
// bincode 位置序列化 + version 字段（§8.1：ChannelTag/PacketKind 零新增，

/// 变文本/空时推送（§2.6 沿动作），客户端据此清 pending。
pub fn filemeta_clear_meta() -> FileClipMeta {
    FileClipMeta {
        version: FILEMETA_VERSION,
        cleared: true,
        truncated: false,
        entries: Vec::new(),
    }
}

///
/// 逐条：绝对路径对 `fs_roots` 逐根前缀匹配（Windows 大小写不敏感）→
/// `rel_path`（相对根，`/` 分隔）+ `fetchable=true`；全部根外 →
/// `fetchable=false` + `rel_path` = 文件名（占位仍显示，Ctrl+V 跳过 + 提示）。
///
/// 上限（fail-closed，§2.2）：
/// - 单条 `rel_path` > 512B → **丢弃该条**（路径截断 = 改路径，绝不；
///   `truncated=true`）；
/// - 条目 > 255 → 前 255 条 + `truncated=true`；
/// - （64KiB 总长门在 [`encode_filemeta_packets`]，超限 = 整份丢弃 + WARN）。
/// ——树行 = FileClipEntry 复用；展开上限触顶 = `truncated=true`，主控端
/// 直贴据此回退两段式；详见 [`r166_walk_dir`]）。
/// **wire 面边界（阶段二修订，如实记档）**：仍零绝对路径/零盘符/零 UNC/
/// 零 mtime（§7.4 主体不变）；但**目录条目内部的相对布局**随树行出线
/// （阶段二裁定：目录整树直贴的必要披露面——仅限用户主动复制的目录内部，
/// 零额外枚举根外内容）。
pub fn filemeta_from_board(board: &OsFileBoard, fs_roots: &[PathBuf]) -> FileClipMeta {
    let mut entries = Vec::with_capacity(board.entries.len().min(MAX_META_ENTRIES));
    let mut truncated = false;
    for entry in &board.entries {
        if entries.len() >= MAX_META_ENTRIES {
            truncated = true; // 条目先截断（前 255 条，§2.2）
            break;
        }
        let (rel_path, fetchable) = match rel_path_under_roots(&entry.abs_path, fs_roots) {
            Some(rel) => (rel, true),
            // 解析失败（全部根外）→ 占位仍显示文件名（§7.2）。
            None => (display_name(&entry.abs_path), false),
        };
        if rel_path.len() > MAX_REL_PATH_BYTES {
            // 超 512B → 丢弃该条（fail-closed，不截断路径串）。
            truncated = true;
            continue;
        }
        entries.push(FileClipEntry {
            rel_path,
            size: entry.size,
            is_dir: entry.is_dir,
            fetchable,
        });
    }
    // Explorer 递归复制语义对齐；零 wire schema 变更 = FileClipEntry 行复用，
    // version 零 bump：旧主控端把树行当普通行消费〔平铺语义〕，新主控端按
    // 覆盖判定结构落位）。任一上限触顶（条目数/路径长/深度/字节预算/读失败）
    // = `truncated=true` 且**停止追加**（不完整树绝不佯装完整）——主控端直贴
    if !truncated {
        let mut budget = R166_TREE_META_BUDGET;
        let mut tree = ClipDirTreeRows {
            rows: Vec::new(),
            truncated: false,
        };
        for top in &board.entries {
            if !top.is_dir || tree.truncated {
                continue;
            }
            // 根外目录零展开（fetchable=false 顶层行 = 占位；§7.2 既有口径）。
            let Some(top_rel) = rel_path_under_roots(&top.abs_path, fs_roots) else {
                continue;
            };
            r166_walk_dir(
                Path::new(&top.abs_path),
                &top_rel,
                1,
                entries.len(),
                &mut budget,
                &mut tree,
            );
        }
        truncated = tree.truncated;
        entries.extend(tree.rows);
    }
    FileClipMeta {
        version: FILEMETA_VERSION,
        cleared: false,
        truncated,
        entries,
    }
}

/// 16B/行）。独立于 [`MAX_META_TOTAL`]（64KiB 整帧门在
/// `encode_filemeta_packets`，超限 = 整份丢弃）：本预算**先于**编码收敛体
/// 量，触顶 = `truncated=true` → 主控端直贴回退两段式，而非整份元数据丢弃
/// （两者皆 fail-closed，前者可用性更优）。
const R166_TREE_META_BUDGET: usize = 48 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClipDirTreeRows {
    /// 追加行（子目录结构行 `is_dir=true` + 树内文件行 `is_dir=false`；根
    /// 相对 `/` 分隔；**不含**顶层条目——顶层行由既有主循环产出）。
    pub rows: Vec<FileClipEntry>,
    /// true = 任一上限触顶（条目数/路径长/深度/字节预算/读目录失败）——
    /// 树不完整，主控端直贴须整批回退两段式。
    pub truncated: bool,
}

/// 置 `truncated` 并整枝剪断——调用方逐层短路）。
/// - 子目录行 `is_dir=true`（结构承载 + 纯空目录保留——RustDesk
/// - 防护（fail-closed）：条目总数 [`MAX_META_ENTRIES`]（`reserved` = 顶层
///   已占额）、单条路径长 [`MAX_REL_PATH_BYTES`]、深度
///   [`crate::file_manager::FOLDER_MAX_DEPTH`]、字节预算 `budget`；
/// - 符号链接/联接跳过（S4 既有口径——不跟随不展开）；
/// - 读目录失败（权限/竞态删除）= 树不完整 → `truncated=true`。
fn r166_walk_dir(
    dir: &Path,
    rel: &str,
    depth: usize,
    reserved: usize,
    budget: &mut usize,
    out: &mut ClipDirTreeRows,
) {
    if out.truncated {
        return;
    }
    if depth > crate::file_manager::FOLDER_MAX_DEPTH {
        out.truncated = true; // 深度上限：不完整树如实申报（不佯装完整）
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        out.truncated = true; // 读失败（权限/竞态删除）= 不完整
        return;
    };
    for e in rd.flatten() {
        if out.truncated {
            return;
        }
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue; // S4：符号链接/联接不跟随不展开
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let child_rel = format!("{rel}/{name}");
        if child_rel.len() > MAX_REL_PATH_BYTES {
            out.truncated = true;
            return;
        }
        if reserved + out.rows.len() >= MAX_META_ENTRIES {
            out.truncated = true;
            return;
        }
        let row_bytes = child_rel.len() + 16;
        if row_bytes > *budget {
            out.truncated = true;
            return;
        }
        *budget -= row_bytes;
        let is_dir = ft.is_dir();
        out.rows.push(FileClipEntry {
            rel_path: child_rel.clone(),
            size: if is_dir {
                0
            } else {
                e.metadata().map(|m| m.len()).unwrap_or(0)
            },
            is_dir,
            fetchable: true,
        });
        if is_dir {
            r166_walk_dir(&e.path(), &child_rel, depth + 1, reserved, budget, out);
        }
    }
}

/// Windows = 大小写不敏感（含盘符大小写）；unix = 精确。根未展开/未规范化
fn rel_path_under_roots(abs: &str, roots: &[PathBuf]) -> Option<String> {
    let p = Path::new(abs);
    for root in roots {
        let Some(stripped) = strip_prefix_ci(p, root) else {
            continue;
        };
        if stripped.as_os_str().is_empty() {
            continue; // abs == root（无文件级余量）
        }
        let rel = stripped.to_string_lossy().replace('\\', "/");
        if !rel.is_empty() {
            return Some(rel);
        }
    }
    None
}

/// Windows 大小写不敏感 / unix 精确的路径前缀剥离（组件级）。
///
/// 板侧路径 = `DragQueryFileW` 裸形态 `C:\…`，fs_roots 出口 = canonicalize
/// verbatim 形态 `\\?\C:\…`——Windows Prefix 组件 `VerbatimDisk ≠ Disk` 在
/// 修前逐组件比较恒不等 → Explorer 复制的文件**全部** `fetchable=false`
/// 大小写不敏感（**fail-closed 不降级**——只修匹配形式，白名单执法语义
/// 零迁移，全根未中 = 显式根外臂原样）。UNC 对齐：`\\?\UNC\srv\share` 与
/// 裸 `\\srv\share` 组件同形。unix = 精确组件匹配（既有行为零漂移）。
fn strip_prefix_ci(p: &Path, root: &Path) -> Option<PathBuf> {
    if cfg!(windows) {
        let pc = r194_deverbatim_components(p);
        let rc = r194_deverbatim_components(root);
        if pc.len() <= rc.len() {
            return None;
        }
        for (i, rc_c) in rc.iter().enumerate() {
            if !pc[i].eq_ignore_ascii_case(rc_c) {
                return None;
            }
        }
        let mut rel = PathBuf::new();
        for c in &pc[rc.len()..] {
            rel.push(c);
        }
        return Some(rel);
    }
    let root_comps: Vec<_> = root.components().collect();
    let comps: Vec<_> = p.components().collect();
    if comps.len() <= root_comps.len() {
        return None;
    }
    for (i, rc) in root_comps.iter().enumerate() {
        let pc = &comps[i];
        let equal = if cfg!(windows) {
            pc.as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&rc.as_os_str().to_string_lossy())
        } else {
            pc.as_os_str() == rc.as_os_str()
        };
        if !equal {
            return None;
        }
    }
    let mut rel = PathBuf::new();
    for c in &comps[root_comps.len()..] {
        rel.push(c.as_os_str());
    }
    Some(rel)
}

/// 同族判据，clipboard.rs 本地面零跨模块依赖）。
fn r194_deverbatim_components(p: &Path) -> Vec<String> {
    let s = p.to_string_lossy();
    let mut comps: Vec<String> = s
        .split(['\\', '/'])
        .filter(|c| !c.is_empty())
        .map(|c| c.to_string())
        .collect();
    if comps.first().map(|c| c.as_str()) == Some("?") {
        comps.remove(0);
        if comps
            .first()
            .map(|c| c.eq_ignore_ascii_case("unc"))
            .unwrap_or(false)
        {
            comps.remove(0);
        }
    }
    comps
}

/// 调用方 512B 门承担）。
fn display_name(abs: &str) -> String {
    Path::new(abs)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| abs.to_string())
}

/// 稳定哈希（**顺序敏感**、跨进程/跨运行确定）——同 sig 不重推（服务端
/// CF_HDROP 不重播；用户重粘同一清单 = 同 sig = 不重推，§2.5）。
pub fn filemeta_sig(meta: &FileClipMeta) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    for e in &meta.entries {
        for b in e.rel_path.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h ^= 0xff; // (rel_path, size) 字段分隔
        h = h.wrapping_mul(FNV_PRIME);
        for b in e.size.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }
    }
    h
}

/// 内容同源）。占位**明示来源**（覆盖本机原剪贴板文本 = 路线 B 固有成本）；
/// `truncated` 显示「…更多」（丢弃条目数不在 wire 上，§2.2 只有 bool）。
pub fn clip_meta_placeholder(meta: &FileClipMeta) -> String {
    if meta.cleared {
        return String::new(); // CLEAR 无占位（不写板）
    }
    let mut s = format!(
        "[KirinDesk 远端文件剪贴板 / remote files] {} 个文件（会话窗 Ctrl+V 拉取）\n",
        meta.entries.len()
    );
    for e in &meta.entries {
        // 组合标注（两事实独立：v1 目录恒不可拉取 §2.2；根外恒不可拉取 §7.2）
        let tag = if e.is_dir {
            if e.fetchable {
                "，目录（v1 不可拉取）"
            } else {
                "，目录、根外不可拉取"
            }
        } else if e.fetchable {
            ""
        } else {
            "，根外不可拉取"
        };
        s.push_str(&format!("- {} ({} B{})\n", e.rel_path, e.size, tag));
    }
    if meta.truncated {
        s.push_str("…（更多，截断显示）\n");
    }
    s
}

///
/// - 序列化 > [`MAX_META_TOTAL`]（64KiB）→ `None`（调用方 WARN 30s 节流；
///   条目截断已在 [`filemeta_from_board`] 先行）；
/// - 分片：`bincode(FileClipMeta)` 字节按 (999 - 分片 bincode 开销) 切段 →
///   每帧 `data = [0x04][bincode(FileClipMetaFragment{seq,total,payload})]`，
///   **flags 恒 = 0x04（不置 START/END，§2.1 唯一旧端安全形态）**；
///   body ≤ 999B（`MAX_CLIP_CHUNK` 同约束，比文本帧 1000B body 更保守）；
/// - 单帧（≤cap）= `seq=1, total=1`；分片数 > 255 → `None`（防御性，64KiB
///   上限下实际 ≤ 66 片，不可达）。
pub fn encode_filemeta_packets(meta: &FileClipMeta) -> Option<Vec<EncodedPacket>> {
    let bytes = bincode::serialize(meta).ok()?;
    if bytes.len() > MAX_META_TOTAL {
        return None;
    }
    // bincode 分片开销（seq:u8 + total:u8 + payload:Vec<u8> = u64 len + bytes）。
    let overhead = bincode::serialize(&FileClipMetaFragment {
        seq: 1,
        total: 1,
        payload: Vec::new(),
    })
    .ok()?
    .len();
    let body_max = MAX_CLIP_CHUNK - 1; // data = [flags:1][body ≤ 999]
    let cap = body_max.saturating_sub(overhead);
    if cap == 0 {
        return None;
    }
    let total = (bytes.len() + cap - 1) / cap;
    if total == 0 || total > MAX_META_FRAGMENTS {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    for (i, chunk) in bytes.chunks(cap).enumerate() {
        let frag = FileClipMetaFragment {
            seq: (i + 1) as u8,
            total: total as u8,
            payload: chunk.to_vec(),
        };
        let frag_bytes = bincode::serialize(&frag).ok()?;
        let mut data = Vec::with_capacity(1 + frag_bytes.len());
        // 0x04 位独占：不置 START/END（§2.1——旧客户端重组缓冲恒不激活）。
        data.push(CLIP_FLAG_FILEMETA);
        data.extend_from_slice(&frag_bytes);
        if data.len() > MAX_CLIP_CHUNK {
            return None; // 防御（cap 计算保证 ≤ MAX_CLIP_CHUNK）
        }
        out.push(EncodedPacket {
            ts: Timestamp::now(),
            kind: PacketKind::Clipboard,
            data,
            is_key: false,
        });
    }
    Some(out)
}

/// 服务端 shell 会话推送复用点——`ShellMessage::ClipMeta` 载荷 = 整体
/// `bincode(FileClipMeta)`，免 0x05 分片形态）。
///
/// 语义 = 客户端分片重组臂（§2.2）同源：逐片剥 1B flags 头 →
/// `bincode(FileClipMetaFragment)` → **seq 升序拼接** payload → 整体解码 →
/// 版本门（未知版本 fail-closed `None`，同客户端重组臂）。片序乱序/缺片/
/// 非 FILEMETA 首帧/解码失败 = `None`（调用点零推送，fail-closed）。
pub fn filemeta_from_packets(pkts: &[EncodedPacket]) -> Option<FileClipMeta> {
    if pkts.is_empty() || pkts.first()?.data.first() != Some(&CLIP_FLAG_FILEMETA) {
        return None;
    }
    let mut frags: Vec<(u8, u8, Vec<u8>)> = Vec::with_capacity(pkts.len());
    for p in pkts {
        let data = &p.data;
        if data.first() != Some(&CLIP_FLAG_FILEMETA) {
            return None; // 混入非元数据帧（调用点同批同帧种保证；防御）
        }
        let frag: FileClipMetaFragment = bincode::deserialize(&data[1..]).ok()?;
        frags.push((frag.seq, frag.total, frag.payload));
    }
    let total = frags[0].1;
    if total == 0 || frags.len() != total as usize {
        return None; // 缺片/超片（批内自含保证；防御）
    }
    frags.sort_by_key(|(seq, _, _)| *seq);
    let mut joined = Vec::new();
    for (i, (seq, _, payload)) in frags.iter().enumerate() {
        if *seq != (i + 1) as u8 {
            return None; // 排序后 seq 仍非 1..=total 连续 = 缺片/重片
        }
        joined.extend_from_slice(payload);
    }
    let meta: FileClipMeta = bincode::deserialize(&joined).ok()?;
    if meta.version != FILEMETA_VERSION {
        return None; // 版本门（同客户端重组臂 fail-closed）
    }
    Some(meta)
}

/// file 会话接收臂消费点；**版本门** = 未知版本 fail-closed `None`，同
/// 0x05 重组臂口径；解码失败 = `None`，调用点单帧丢弃会话存活）。
pub fn decode_clip_meta(bytes: &[u8]) -> Option<FileClipMeta> {
    let meta: FileClipMeta = bincode::deserialize(bytes).ok()?;
    if meta.version != FILEMETA_VERSION {
        return None;
    }
    Some(meta)
}

///
/// `gate_open` = **轮询启停条件**——服务端口径：至少一个活跃 viewer 在看
/// （会话建立/断开联动）。
/// - 门控关（无 viewer）：**不读板、不推送**（返回 None）——最后一个 viewer
///   退出即停止采集（省资源 + 无会话时不触剪贴板/不误发）；
/// - 门控开（有 viewer）：tick 内**先 `get_file_meta()` 再 `get_text()`**
///   改动）/ 元数据帧 / CLEAR 元数据帧 / 无（`None`）。
///
/// 客户端既有轮询（`ui/src/lib.rs` connect 尾部内联）门控恒开（任务存活 =
/// 会话在），不迁移本函数（客户端既有实现零重写口径；客户端不推元数据——
/// 元数据通道严格服务端→客户端单向，§6.1）。
///
/// 切换为传入配置 `fs_roots` 的 roots 版本）。返回类型不变
/// （`Option<Vec<EncodedPacket>>`）——文本帧/元数据帧/CLEAR 帧同为
/// `EncodedPacket{kind: Clipboard}`，既有广播路径（`broadcast_packet`）
/// 零新机制复用（§2.1/§3.3）。
pub fn clip_poll_tick(
    st: &mut ClipboardSyncState,
    now_ms: u64,
    io: &mut dyn ClipboardIo,
    gate_open: bool,
) -> Option<Vec<EncodedPacket>> {
    clip_poll_tick_roots(st, now_ms, io, gate_open, &[])
}

///
/// `fs_roots` = 配置 `fs_roots`（已展开的根路径列表）：CF_HDROP 绝对路径
/// 逐根前缀匹配（Windows 大小写不敏感）解析 `rel_path`；解析失败（全部根外）
/// → 该条目 `fetchable=false`、`rel_path` = 文件名（占位仍显示，§7.2）。
///
/// 板状态机沿动作（`last_board_kind` → 本 tick 判定，优先级 File > Text > Other）：
/// - `_ → File`（sig 变化）：推元数据帧（自含分片，0x04，不置 START/END）；
///   `last_pushed_meta_sig = sig`（签名去重：同 sig 不重推，§2.5 条 2）；
/// - `File → File`（sig 同）：无；
/// - `File → Text / Other`：推 CLEAR 元数据帧（`cleared=true, entries=[]`）；
///   `last_pushed_meta_sig = None`（单次沿，无 ping-pong，§2.5 条 4）；
/// - `Text/Other → Text(变化)`：既有文本推送（零改动：`decide_local_push`）；
/// - 其余（空板等）：无（空板不推，既有语义）。
pub fn clip_poll_tick_roots(
    st: &mut ClipboardSyncState,
    now_ms: u64,
    io: &mut dyn ClipboardIo,
    gate_open: bool,
    fs_roots: &[PathBuf],
) -> Option<Vec<EncodedPacket>> {
    if !gate_open {
        return None;
    }
    // 先文件板（CF_HDROP，只读）再文本——两读独立，文件读失败不影响文本通道
    // （§2.4 fail-closed：本 tick 按无变化处理）。
    let board = io.get_file_meta();
    let text = io.get_text();
    let kind = board_kind(&board, &text);
    let prev = st.last_board_kind;
    st.last_board_kind = kind;
    match (prev, kind) {
        // _ → File（sig 变化）：推元数据帧；File→File 同 sig：不重推（§2.5 条 2）。
        (_, BoardKind::File) => {
            let board = board.expect("kind == File ⟺ board 非空（board_kind 判定同源）");
            let meta = filemeta_from_board(&board, fs_roots);
            let sig = filemeta_sig(&meta);
            if st.last_pushed_meta_sig == Some(sig) {
                return None;
            }
            st.last_pushed_meta_sig = Some(sig);
            match encode_filemeta_packets(&meta) {
                Some(pkts) => Some(pkts),
                // 条目已先截断（255 条）仍超 64KiB → 丢弃本次元数据（§2.2；
                // sig 已记录 → 同板不重推不重告警，确定性超限无重试价值）。
                None => {
                    st.warn_meta_throttled(
                        "file meta exceeds 64KiB after entry truncation — dropped",
                    );
                    None
                }
            }
        }
        // File → Text/Other：推 CLEAR（cleared=true）；单次沿（§2.5 条 4）。
        (BoardKind::File, BoardKind::Text) | (BoardKind::File, BoardKind::Other) => {
            st.last_pushed_meta_sig = None;
            Some(encode_filemeta_packets(&filemeta_clear_meta()).expect(
                "CLEAR 元数据恒单帧且远小于上限（version+2bool+空 entries）",
            ))
        }
        // Text/Other → Text(变化)：既有文本推送（零改动语义）。
        (_, BoardKind::Text) => {
            let text = text.expect("kind == Text ⟺ text 非空（board_kind 判定同源）");
            st.decide_local_push(now_ms, &text)
                .map(|text| clipboard_packets(&text))
        }
        // Other：无（空板不推，既有语义）。
        _ => None,
    }
}

/// 同板并存 CF_HDROP + CF_UNICODETEXT，文件优先，与 §3.2 拦截优先级同构）。
fn board_kind(board: &Option<OsFileBoard>, text: &Option<String>) -> BoardKind {
    if board.as_ref().is_some_and(|b| !b.entries.is_empty()) {
        BoardKind::File
    } else if text.as_deref().is_some_and(|t| !t.is_empty()) {
        BoardKind::Text
    } else {
        BoardKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 内存剪贴板假件（可注入）。
    struct FakeClipboard {
        text: Option<String>,
        last_set: Option<String>,
        set_calls: usize,
        get_calls: usize,
        /// 同语义；>255 截断 / read 失败 None 等边界经此注入，§9.1 C 岗门禁）。
        file_board: Option<OsFileBoard>,
    }

    impl FakeClipboard {
        fn new() -> Self {
            Self {
                text: None,
                last_set: None,
                set_calls: 0,
                get_calls: 0,
                file_board: None,
            }
        }
    }

    impl ClipboardIo for FakeClipboard {
        fn get_text(&mut self) -> Option<String> {
            self.get_calls += 1;
            self.text.clone()
        }

        fn set_text(&mut self, text: &str) -> bool {
            self.set_calls += 1;
            self.last_set = Some(text.to_string());
            self.text = Some(text.to_string());
            true
        }

        fn get_file_meta(&mut self) -> Option<OsFileBoard> {
            self.file_board.clone()
        }
    }

    fn fake_board(paths: &[&str]) -> OsFileBoard {
        OsFileBoard {
            entries: paths
                .iter()
                .map(|p| OsFileEntry {
                    abs_path: (*p).to_string(),
                    size: 1234,
                    is_dir: false,
                })
                .collect(),
        }
    }

    /// `encode_filemeta_packets` 对称的测试逆运算）。
    /// 顺带断言 §2.1 旧端安全形态：flags 恒 = 0x04（零 START/零 END 位）。
    fn reassemble_filemeta_pkts(pkts: &[EncodedPacket]) -> FileClipMeta {
        assert!(!pkts.is_empty());
        let mut parts: Vec<(u8, u8, Vec<u8>)> = Vec::new();
        for p in pkts {
            assert_eq!(p.kind, PacketKind::Clipboard);
            assert_eq!(p.data[0] & CLIP_FLAG_START, 0, "FILEMETA 帧不得置 START 位（§2.1 唯一旧端安全形态）");
            assert_eq!(p.data[0] & CLIP_FLAG_END, 0, "FILEMETA 帧不得置 END 位（§2.1）");
            assert_eq!(p.data[0] & !CLIP_FLAG_FILEMETA, 0, "flags 仅含 0x04 位");
            let frag: FileClipMetaFragment =
                bincode::deserialize(&p.data[1..]).expect("fragment bincode");
            assert!((1..=MAX_META_FRAGMENTS as u8).contains(&frag.seq));
            parts.push((frag.seq, frag.total, frag.payload));
        }
        parts.sort_by_key(|(seq, _, _)| *seq);
        let total = parts[0].1;
        assert!(parts.windows(2).all(|w| w[0].1 == w[1].1), "total 必须一致");
        assert_eq!(parts.len() as u8, total, "seq 必须 1..=total 无缺无重");
        let mut joined = Vec::new();
        for (_, _, payload) in &parts {
            joined.extend_from_slice(payload);
        }
        bincode::deserialize(&joined).expect("FileClipMeta bincode")
    }

    fn reassemble_packets(pkts: &[EncodedPacket]) -> String {
        let mut out = Vec::new();
        for p in pkts {
            assert_eq!(p.kind, PacketKind::Clipboard);
            out.extend_from_slice(&p.data[1..]);
        }
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn test_poll_only_pushes_changes() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();

        // 无内容 → None
        assert_eq!(st.poll_local(0, &mut io), None);

        // 首次变化 → 推送
        io.text = Some("hello".to_string());
        assert_eq!(st.poll_local(0, &mut io).as_deref(), Some("hello"));

        // 无变化 → None
        assert_eq!(st.poll_local(100, &mut io), None);

        // 新内容 → 推送
        io.text = Some("world".to_string());
        assert_eq!(st.poll_local(200, &mut io).as_deref(), Some("world"));
    }

    #[test]
    fn test_empty_clipboard_not_pushed() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        io.text = Some(String::new());
        assert_eq!(st.poll_local(0, &mut io), None);
    }

    #[test]
    fn test_remote_apply_suppresses_echo() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();

        // 远端推送 "remote-text"（单帧 START|END）→ 写入本地
        let frames = encode_clipboard_payloads("remote-text", MAX_CLIP_CHUNK);
        assert_eq!(frames.len(), 1);
        let _ = st.apply_remote_frame(1000, &frames[0], &mut io);
        assert_eq!(io.last_set.as_deref(), Some("remote-text"));
        assert_eq!(io.set_calls, 1);

        // 冷却期内本地轮询回读到同一文本 → 不回推（防 ping-pong）
        assert_eq!(st.poll_local(1200, &mut io), None);

        // 冷却结束后同一文本仍与 last_pushed 相同 → 不回推
        assert_eq!(st.poll_local(3000, &mut io), None);

        // 本地用户复制新内容 → 正常推送
        io.text = Some("user-copy".to_string());
        assert_eq!(st.poll_local(3100, &mut io).as_deref(), Some("user-copy"));
    }

    #[test]
    fn test_encode_and_reassemble_large_text() {
        // 2.5KB 文本 → 分片 → 重组 → 完整一致
        let text: String = "KirinDesk 剪贴板 ".repeat(120);
        let frames = encode_clipboard_payloads(&text, MAX_CLIP_CHUNK);
        assert!(frames.len() > 1, "large text must be chunked");

        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        for f in &frames {
            let _ = st.apply_remote_frame(1000, f, &mut io);
        }
        assert_eq!(io.last_set.as_deref(), Some(text.as_str()));
        assert_eq!(io.set_calls, 1);

        // 编码首片 START、末片 END、中间片无标志
        let first_flags = frames.first().unwrap()[0];
        let last_flags = frames.last().unwrap()[0];
        assert_ne!(first_flags & CLIP_FLAG_START, 0);
        assert_ne!(last_flags & CLIP_FLAG_END, 0);
        assert_eq!(first_flags & CLIP_FLAG_END, 0); // 大文本首片不是末片
    }

    #[test]
    fn test_interrupted_stream_discarded_on_new_start() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();

        // 第一份拷贝：只发 START 片（不完整）
        let frames = encode_clipboard_payloads("first-copy-内容很长", 5);
        let _ = st.apply_remote_frame(1000, &frames[0], &mut io);
        assert_eq!(io.set_calls, 0, "未收到 END 不应写入");

        // 第二份拷贝 START → 旧缓冲丢弃，只保留新内容
        let frames2 = encode_clipboard_payloads("second", MAX_CLIP_CHUNK);
        for f in &frames2 {
            let _ = st.apply_remote_frame(2000, f, &mut io);
        }
        assert_eq!(io.last_set.as_deref(), Some("second"));
    }

    #[test]
    fn test_empty_payload_ignored() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        let _ = st.apply_remote_frame(0, &[], &mut io);
        let _ = st.apply_remote_frame(0, &[CLIP_FLAG_START | CLIP_FLAG_END], &mut io);
        assert_eq!(io.set_calls, 0);
    }

    #[test]
    fn test_packets_wire_format() {
        let pkts = clipboard_packets("你好 KirinDesk");
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, PacketKind::Clipboard);
        assert!(!pkts[0].is_key);
        // 首字节 = START|END（单片）
        assert_eq!(pkts[0].data[0], CLIP_FLAG_START | CLIP_FLAG_END);
        assert_eq!(&pkts[0].data[1..], "你好 KirinDesk".as_bytes());
    }

    #[test]
    fn test_malicious_stream_bounded_by_total_limit() {
        // S-11d（F-13）：START + 永不发 END 的恶意分片流 → 累计超过
        // MAX_CLIP_TOTAL 后重组缓冲被清空：不写入本地、内存有界、不 panic。
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();

        // START 片（首片，无 END）：文本须超过单片容量，首片才不带 END。
        let start_text = "x".repeat(MAX_CLIP_CHUNK + 1);
        let start = encode_clipboard_payloads(&start_text, MAX_CLIP_CHUNK);
        assert_eq!(start.len(), 2, "超单片容量文本拆 2 片");
        assert_eq!(start[0][0] & CLIP_FLAG_END, 0, "首片不得带 END");
        let _ = st.apply_remote_frame(0, &start[0], &mut io);
        assert_eq!(io.set_calls, 0);

        // 中间片（无 START/END 标志），持续追加直到累计超限
        let mut mid_payload = Vec::with_capacity(1 + MAX_CLIP_CHUNK);
        mid_payload.push(0u8); // flags = 0
        mid_payload.resize(1 + MAX_CLIP_CHUNK, b'z');
        let mut sent = MAX_CLIP_CHUNK;
        let mut exceeded = false;
        for _ in 0..(MAX_CLIP_TOTAL / MAX_CLIP_CHUNK + 2) {
            let _ = st.apply_remote_frame(0, &mid_payload, &mut io);
            sent += MAX_CLIP_CHUNK;
            if sent > MAX_CLIP_TOTAL {
                exceeded = true;
                break;
            }
        }
        assert!(exceeded, "测试必须覆盖超限场景");
        assert_eq!(io.set_calls, 0, "未收到 END 且超限 → 不应写入本地");

        // 缓冲已清空：随后的合法 START→END 流可正常重组（无残留污染）
        let good = encode_clipboard_payloads("after-overflow-ok", MAX_CLIP_CHUNK);
        for f in &good {
            let _ = st.apply_remote_frame(1000, f, &mut io);
        }
        assert_eq!(io.last_set.as_deref(), Some("after-overflow-ok"));
    }

    #[test]
    fn test_legal_total_at_limit_still_reassembles() {
        // S-11d（回归）：恰好等于 MAX_CLIP_TOTAL 的合法分片文本不受累计检查影响。
        let text = "K".repeat(MAX_CLIP_TOTAL);
        let frames = encode_clipboard_payloads(&text, MAX_CLIP_CHUNK);
        assert!(frames.len() > 1, "8 MiB 文本必须分片");

        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        for f in &frames {
            let _ = st.apply_remote_frame(0, f, &mut io);
        }
        assert_eq!(io.last_set.as_deref(), Some(text.as_str()));
        assert_eq!(io.set_calls, 1);
    }

    #[test]
    fn test_legal_large_transfer_over_1mb_reassembles() {
        // S-11d（回归，取值依据）：合法大文本超过 1MB（2 MiB，分片到达）
        // 不得被累计上限误伤——MAX_CLIP_TOTAL(8 MiB) 需覆盖此类合法用例。
        let text = "KirinDesk 剪贴板大文本".repeat(60_000); // ~2.1 MiB
        assert!(text.len() > 1024 * 1024, "用例必须超过旧 1MB 上限");
        let frames = encode_clipboard_payloads(&text, MAX_CLIP_CHUNK);
        assert!(frames.len() > 1000, "2 MiB 文本拆千余片");

        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        for f in &frames {
            let _ = st.apply_remote_frame(0, f, &mut io);
        }
        assert_eq!(io.last_set.as_deref(), Some(text.as_str()));
        assert_eq!(io.set_calls, 1);
    }

    /// 防回环决策（纯逻辑）：单片/多片重组仅 END 片产 apply；远端刚写入的
    /// 内容在冷却期与冷却后均不被本地轮询回推；本地新内容正常可推。
    #[test]
    fn r83d_server_arm_reassembly_and_echo_suppress() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();

        // 单片（START|END）→ apply 成功（返回完整文本，供 INFO 打点）
        let frames = encode_clipboard_payloads("from-client", MAX_CLIP_CHUNK);
        assert_eq!(frames.len(), 1);
        assert_eq!(
            st.apply_remote_frame(1000, &frames[0], &mut io).as_deref(),
            Some("from-client")
        );
        assert_eq!(io.last_set.as_deref(), Some("from-client"));
        assert_eq!(io.set_calls, 1);

        // 多片重组：中间片不 apply（None），仅 END 片返回完整文本
        let big: String = "srv-clip-".repeat(300); // ~2.7KB → 3 片
        let frames = encode_clipboard_payloads(&big, MAX_CLIP_CHUNK);
        assert!(frames.len() > 1, "大文本必须分片");
        for f in &frames[..frames.len() - 1] {
            assert_eq!(st.apply_remote_frame(2000, f, &mut io), None, "未完成流不得 apply");
        }
        assert_eq!(
            st.apply_remote_frame(2000, &frames[frames.len() - 1], &mut io).as_deref(),
            Some(big.as_str())
        );
        assert_eq!(io.set_calls, 2, "整份文本只写一次板");

        // 防回环：服务端轮询在冷却期内回读同一文本 → 不回推（防 ping-pong）
        assert_eq!(st.poll_local(2500, &mut io), None);
        // 冷却结束后同一文本 == last_pushed → 仍不回推
        assert_eq!(st.poll_local(4000, &mut io), None);
        // 服务端用户复制新内容 → 正常可推
        io.text = Some("user-copy".to_string());
        assert_eq!(
            st.poll_local(4100, &mut io).as_deref(),
            Some("user-copy")
        );
    }

    /// `clip_poll_tick`）：门控关（无活跃 viewer）不读板不推送；门控开
    /// （有 viewer）采集变更；最后 viewer 退出（门控再关）即停采集——
    /// 期间剪贴板变化不读不推；viewer 重连（门控再开）采集当前内容。
    #[test]
    fn r83d_clip_poll_gate_start_stop() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        io.text = Some("A".to_string());

        // 无 viewer（门控关）：不采集——零读板、零推送
        assert!(clip_poll_tick(&mut st, 0, &mut io, false).is_none());
        assert_eq!(io.get_calls, 0, "门控关期间不得读板（无会话不采集）");

        // 首个 viewer 接入（门控开）：首次推送
        let pkts = clip_poll_tick(&mut st, 100, &mut io, true)
            .expect("门控开 + 内容变更 → 必推送");
        assert_eq!(reassemble_packets(&pkts), "A");

        // 无变化 → 不推送
        assert!(clip_poll_tick(&mut st, 600, &mut io, true).is_none());

        // 新内容 → 推送
        io.text = Some("B".to_string());
        let pkts = clip_poll_tick(&mut st, 1100, &mut io, true)
            .expect("内容变更 → 必推送");
        assert_eq!(reassemble_packets(&pkts), "B");

        // 最后 viewer 退出（门控关）：剪贴板变化也不采集
        io.text = Some("C".to_string());
        assert!(clip_poll_tick(&mut st, 1600, &mut io, false).is_none());
        let reads_after_close = io.get_calls;
        assert_eq!(io.get_calls, reads_after_close, "停止后不得再读板");

        // viewer 重连（门控再开）：采集当前板内容
        let pkts = clip_poll_tick(&mut st, 2100, &mut io, true)
            .expect("门控再开 + 相对已推内容有变化 → 必推送");
        assert_eq!(reassemble_packets(&pkts), "C");
    }


    /// START/零 END 位，§2.1 唯一旧端安全形态）；wire 往返逐位一致。
    #[test]
    fn r91c_filemeta_single_fragment_roundtrip() {
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![FileClipEntry {
                rel_path: "docs/report.docx".to_string(),
                size: 12345,
                is_dir: false,
                fetchable: true,
            }],
        };
        let pkts = encode_filemeta_packets(&meta).expect("小元数据必可编码");
        assert_eq!(pkts.len(), 1, "单帧（seq=1, total=1）");
        assert_eq!(pkts[0].data[0], CLIP_FLAG_FILEMETA, "flags 逐位 = 0x04（零 START/零 END）");
        let frag: FileClipMetaFragment =
            bincode::deserialize(&pkts[0].data[1..]).expect("fragment");
        assert_eq!(frag.seq, 1);
        assert_eq!(frag.total, 1);
        assert_eq!(reassemble_filemeta_pkts(&pkts), meta, "wire 往返逐位一致");
    }

    /// 逐帧重组 → 末帧返回占位文本（= 既有调用点 INFO 路径自然复用）+ 占位写板
    /// 一次 + 防回环记录；事件方法对中间帧 = Silent。
    #[test]
    fn r91c_filemeta_multi_fragment_reassemble_apply() {
        let entries: Vec<FileClipEntry> = (0..25)
            .map(|i| FileClipEntry {
                rel_path: format!("dir-{i:02}/{}", "p".repeat(90)),
                size: i as u64 + 1,
                is_dir: i % 5 == 0,
                fetchable: true,
            })
            .collect();
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries,
        };
        let pkts = encode_filemeta_packets(&meta).expect("必可编码");
        assert!(pkts.len() > 1, "2.9KB+ 元数据必多帧");

        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        // 中间帧：事件方法 = Silent（未完成流不 apply）
        for p in &pkts[..pkts.len() - 1] {
            assert_eq!(
                st.apply_remote_frame_event(1000, &p.data, &mut io),
                ClipApplyEvent::Silent
            );
        }
        assert_eq!(io.set_calls, 0, "未完成流不得写板");
        // 末帧：走既有签名 wrapper（生产调用点形态）→ Some(占位文本)
        let placeholder = clip_meta_placeholder(&meta);
        assert_eq!(
            st.apply_remote_frame(1000, &pkts[pkts.len() - 1].data, &mut io)
                .as_deref(),
            Some(placeholder.as_str())
        );
        assert_eq!(io.last_set.as_deref(), Some(placeholder.as_str()), "占位写入本机板");
        assert_eq!(io.set_calls, 1, "整份元数据只写一次板");
        assert_eq!(st.last_applied_meta_sig, Some(filemeta_sig(&meta)));
        assert_eq!(st.placeholder_text.as_deref(), Some(placeholder.as_str()));
        // 重组槽已复位（无残留）
        assert!(st.meta_rx.is_none());
    }

    #[test]
    fn r91c_filemeta_out_of_order_and_duplicate_fragments() {
        let entries: Vec<FileClipEntry> = (0..25)
            .map(|i| FileClipEntry {
                rel_path: format!("dir-{i:02}/{}", "q".repeat(90)),
                size: 1,
                is_dir: false,
                fetchable: true,
            })
            .collect();
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries,
        };
        let mut pkts = encode_filemeta_packets(&meta).expect("必可编码");
        assert!(pkts.len() >= 3);
        // 固定乱序：逆序 + 首片移到尾
        pkts.reverse();
        let first = pkts.pop().expect("≥2 片");
        pkts.push(first);
        // 重复中间帧一次
        let dup = pkts[pkts.len() / 2].clone();
        pkts.insert(pkts.len() / 2, dup);

        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        let mut applied = 0;
        for p in &pkts {
            if matches!(
                st.apply_remote_frame_event(1000, &p.data, &mut io),
                ClipApplyEvent::MetaApplied(_)
            ) {
                applied += 1;
            }
        }
        assert_eq!(applied, 1, "整份只 apply 一次");
        assert_eq!(io.set_calls, 1);
        assert_eq!(io.last_set.as_deref(), Some(clip_meta_placeholder(&meta).as_str()));
    }

    /// (a) 编码侧：条目截断后仍 >64KiB → None；
    /// (b) 接收侧：伪造 >64KiB 分片流 → 中途丢弃整流 + 状态复位，**不 panic
    ///     不挂起**，且后续合法流仍可正常 apply（无残留污染）。
    #[test]
    fn r91c_filemeta_total_limit_dropped() {
        // (a) 编码侧：255 条 × 512B rel_path ≈ 135KB > 64KiB
        let fat = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: true,
            entries: vec![
                FileClipEntry {
                    rel_path: "x".repeat(MAX_REL_PATH_BYTES),
                    size: 1,
                    is_dir: false,
                    fetchable: true
                };
                MAX_META_ENTRIES
            ],
        };
        assert!(
            bincode::serialize(&fat).unwrap().len() > MAX_META_TOTAL,
            "用例前提：序列化必超 64KiB"
        );
        assert!(
            encode_filemeta_packets(&fat).is_none(),
            "超限 → 丢弃（调用方 WARN 节流）"
        );

        // (b) 接收侧：70 片 × 1000B ≈ 70KB > 64KiB 的伪造流（acc 越过
        // 65536 于第 66 片 → 整流丢弃 + 重组槽复位；后续片重启新流但不齐片
        // → 全程零 apply、零写板、不 panic 不挂起）
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        for i in 1..=70u8 {
            let frag = FileClipMetaFragment {
                seq: i,
                total: 70,
                payload: vec![b'z'; 1000],
            };
            let mut frame = vec![CLIP_FLAG_FILEMETA];
            frame.extend_from_slice(&bincode::serialize(&frag).unwrap());
            let ev = st.apply_remote_frame_event(0, &frame, &mut io);
            assert!(
                matches!(ev, ClipApplyEvent::Silent),
                "i={i}：伪造超限流任何帧都不得 apply"
            );
        }
        assert_eq!(io.set_calls, 0, "绝不把元数据字节当文本写板");

        // 后续合法流不受污染
        let meta = filemeta_clear_meta();
        let pkts = encode_filemeta_packets(&meta).unwrap();
        for p in &pkts {
            let _ = st.apply_remote_frame_event(1000, &p.data, &mut io);
        }
        assert_eq!(io.set_calls, 0, "CLEAR 不写板（§2.6 占位不主动擦除）");
    }

    #[test]
    fn r91c_filemeta_entries_truncated_at_255() {
        let paths: Vec<String> = (0..300).map(|i| format!("C:\\root\\file_{i}.txt")).collect();
        let board = OsFileBoard {
            entries: paths
                .into_iter()
                .map(|p| OsFileEntry {
                    abs_path: p,
                    size: 1,
                    is_dir: false,
                })
                .collect(),
        };
        let meta = filemeta_from_board(&board, &[]);
        assert_eq!(meta.entries.len(), MAX_META_ENTRIES, "前 255 条");
        assert!(meta.truncated, "截断标记必置");
        assert_eq!(meta.entries[0].rel_path, "file_0.txt", "根外 → 文件名占位");
        assert!(!meta.entries[0].fetchable);
        assert_eq!(meta.entries[254].rel_path, "file_254.txt", "第 255 条 = file_254");
    }

    /// + truncated=true；其余合法条目保留。
    #[test]
    fn r91c_filemeta_long_rel_path_entry_dropped() {
        let root = "C:\\root";
        let long_rel = "a".repeat(600); // 600B > 512B
        let board = OsFileBoard {
            entries: vec![
                OsFileEntry {
                    abs_path: format!("{root}\\{long_rel}"),
                    size: 1,
                    is_dir: false,
                },
                OsFileEntry {
                    abs_path: format!("{root}\\ok.txt"),
                    size: 2,
                    is_dir: false,
                },
            ],
        };
        let meta = filemeta_from_board(&board, &[PathBuf::from(root)]);
        assert_eq!(meta.entries.len(), 1, "超长条目丢弃，合法条目保留");
        assert!(meta.truncated);
        assert_eq!(meta.entries[0].rel_path, "ok.txt");
        assert!(meta.entries[0].fetchable);
    }

    /// 流中间：文本重组逐位完成（零污染），元数据重组独立进行，互不共享缓冲。
    #[test]
    fn r91c_old_flags_bitwise_compat_mutual_exclusive() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();

        // 文本流（既有编码）拆 3 片；中间插入 2 个 0x04 元数据帧
        let text_frames = encode_clipboard_payloads("alpha-bravo-charlie", 7);
        assert_eq!(text_frames.len(), 3);
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![FileClipEntry {
                rel_path: "f.txt".to_string(),
                size: 5,
                is_dir: false,
                fetchable: true,
            }],
        };
        let meta_frames = encode_filemeta_packets(&meta).unwrap();

        let events: Vec<ClipApplyEvent> = [
            (text_frames[0].as_slice(), 0),
            (meta_frames[0].data.as_slice(), 1),
            (text_frames[1].as_slice(), 2),
            (meta_frames[0].data.as_slice(), 3), // 重复元数据帧（同流幂等）
            (text_frames[2].as_slice(), 4),
        ]
        .into_iter()
        .map(|(f, _i)| st.apply_remote_frame_event(0, f, &mut io))
        .collect();

        // 文本：首/中片 Silent，末片（END）TextApplied = 完整文本（零元数据污染）
        assert_eq!(events[0], ClipApplyEvent::Silent);
        assert_eq!(events[2], ClipApplyEvent::Silent);
        assert_eq!(events[4], ClipApplyEvent::TextApplied("alpha-bravo-charlie".to_string()));
        // 元数据：单片流（total=1）第 1 帧即完整 → MetaApplied；重复帧 = 新流重放 → 再次 MetaApplied（幂等语义：同内容）
        assert!(matches!(events[1], ClipApplyEvent::MetaApplied(ref m) if m.entries.len() == 1));
        // 板内容 = 占位被末片文本覆盖（时间序：文本帧最后 apply）
        assert_eq!(io.last_set.as_deref(), Some("alpha-bravo-charlie"));
        // 元数据重组槽无残留（末片已取走；重复帧开启的新流在同帧完成）
        assert!(st.meta_rx.is_none());
        // 旧 flags 逐位：START|END 单片文本 = 既有语义（对照既有 12 例，零变化）
        let single = encode_clipboard_payloads("solo", MAX_CLIP_CHUNK);
        assert_eq!(single[0][0], CLIP_FLAG_START | CLIP_FLAG_END);
    }

    /// `apply_remote_frame` 文本路径逻辑（逐行复刻）为「旧客户端」，喂**真实
    /// 编码器产出的 0x04 帧**：零写板、零日志（结构性质：旧路径对无 START/END
    /// 帧无任何 tracing 调用）、悬挂缓冲有界且被下个 START 重置（无残留污染）。
    #[test]
    fn r91c_old_client_zero_side_effect_sim() {
        struct OldClient {
            reassembly: Option<Vec<u8>>,
            writes: usize,
            last_written: Option<Vec<u8>>,
        }
        impl OldClient {
            fn apply(&mut self, payload: &[u8]) {
                let Some((&flags, chunk)) = payload.split_first() else {
                    return;
                };
                // ① chunk 长度检查（§2.3 步骤 1）
                if chunk.len() > MAX_CLIP_TOTAL {
                    self.reassembly = None;
                    return;
                }
                // ② flags & START（§2.3 步骤 2）
                if flags & CLIP_FLAG_START != 0 {
                    self.reassembly = Some(Vec::new());
                }
                // ③ 悬挂缓冲追加（§2.3 步骤 3）
                if let Some(buf) = self.reassembly.as_mut() {
                    if buf.len().saturating_add(chunk.len()) > MAX_CLIP_TOTAL {
                        self.reassembly = None;
                        return;
                    }
                    buf.extend_from_slice(chunk);
                }
                // ④ flags & END → 写板（§2.3 步骤 4）
                if flags & CLIP_FLAG_END != 0 {
                    let bytes = self.reassembly.take().unwrap_or_default();
                    if !bytes.is_empty() {
                        self.writes += 1;
                        self.last_written = Some(bytes);
                    }
                }
            }
        }

        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![FileClipEntry {
                rel_path: "C-rel\\report.bin".to_string(),
                size: 999,
                is_dir: false,
                fetchable: true,
            }],
        };
        let frames = encode_filemeta_packets(&meta).expect("必可编码");

        // 形态 a：无悬挂流 —— 0x04 帧逐个喂旧客户端
        let mut old = OldClient {
            reassembly: None,
            writes: 0,
            last_written: None,
        };
        for f in &frames {
            old.apply(&f.data);
        }
        assert_eq!(old.writes, 0, "零写板（写板必须 END 位，0x04 帧无 END）");
        assert!(old.reassembly.is_none(), "无 START 位 → 重组缓冲恒不激活");

        // 形态 b：恰有悬挂文本流（此前 END 帧被背压丢弃）——最坏情形
        let mut old = OldClient {
            reassembly: None,
            writes: 0,
            last_written: None,
        };
        let mut dangling = vec![CLIP_FLAG_START]; // 只发 START（无 END = 悬挂）
        dangling.extend_from_slice(b"dangling");
        old.apply(&dangling);
        assert!(old.reassembly.is_some(), "悬挂流在位（前提）");
        for f in &frames {
            old.apply(&f.data);
        }
        assert_eq!(old.writes, 0, "悬挂 + 元数据字节追加 ≠ 写板（无 END 位，§2.3 步骤 3）");
        let buf_len = old.reassembly.as_ref().map(Vec::len).unwrap_or(0);
        assert!(buf_len <= MAX_CLIP_TOTAL, "悬挂缓冲有界（8MiB 既有上界）");

        // 下个真实文本推送首片带 START → 悬挂缓冲整体重置（无残留污染）
        let good = encode_clipboard_payloads("after-reset", MAX_CLIP_CHUNK);
        for g in &good {
            old.apply(g);
        }
        assert_eq!(old.writes, 1, "仅真实 END 触发一次写板");
        assert_eq!(
            old.last_written.as_deref(),
            Some("after-reset".as_bytes()),
            "写板内容 = 纯新文本（悬挂 + 元数据字节全被 START 重置）"
        );
    }

    /// 冷却窗 + last_pushed 同步 → 冷却期内轮询回读占位 = 不回推；冷却后同
    /// last_pushed 去重 = 仍不回推；用户复制新内容 = 正常推（零新逻辑）。
    #[test]
    fn r91c_client_placeholder_no_echo() {
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![FileClipEntry {
                rel_path: "a.txt".to_string(),
                size: 10,
                is_dir: false,
                fetchable: true,
            }],
        };
        let pkts = encode_filemeta_packets(&meta).unwrap();
        let placeholder = clip_meta_placeholder(&meta);

        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        for p in &pkts {
            let _ = st.apply_remote_frame(1000, &p.data, &mut io);
        }
        assert_eq!(io.last_set.as_deref(), Some(placeholder.as_str()));

        // 冷却期内（1s）本地轮询回读占位 → 不回推
        assert_eq!(st.poll_local(1500, &mut io), None, "冷却窗内回环抑制");
        // 冷却结束后同一文本 == last_pushed → 去重命中 → 仍不回推
        assert_eq!(st.poll_local(3000, &mut io), None, "last_pushed 去重（零新逻辑）");
        // 用户本机复制新内容 → 正常推送
        io.text = Some("user-copy".to_string());
        assert_eq!(st.poll_local(3100, &mut io).as_deref(), Some("user-copy"));
    }

    /// 轮询只推一次；清单变化（新 sig）再推；CLEAR 后同清单可再推（sig 复位）。
    #[test]
    fn r91c_server_sig_dedup_no_replay() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();

        // tick 1：首次文件清单 → 推元数据帧
        io.file_board = Some(fake_board(&["C:\\r\\a.txt"]));
        let pkts = clip_poll_tick(&mut st, 0, &mut io, true).expect("首沿必推");
        let meta = reassemble_filemeta_pkts(&pkts);
        assert_eq!(meta.entries.len(), 1);
        assert_eq!(st.last_pushed_meta_sig, Some(filemeta_sig(&meta)));

        // tick 2：同板同 sig（500ms 轮询回读）→ 不重推
        assert!(clip_poll_tick(&mut st, 500, &mut io, true).is_none());

        // tick 3：清单变化（新 sig）→ 再推
        io.file_board = Some(fake_board(&["C:\\r\\a.txt", "C:\\r\\b.txt"]));
        let pkts = clip_poll_tick(&mut st, 1000, &mut io, true).expect("sig 变化必推");
        assert_eq!(reassemble_filemeta_pkts(&pkts).entries.len(), 2);

        // tick 4：文件被移除（板 = 文本）→ CLEAR
        io.file_board = None;
        io.text = Some("T".to_string());
        let pkts = clip_poll_tick(&mut st, 1500, &mut io, true).expect("File→Text 必推 CLEAR");
        let cleared = reassemble_filemeta_pkts(&pkts);
        assert!(cleared.cleared);
        assert!(cleared.entries.is_empty());
        assert_eq!(st.last_pushed_meta_sig, None, "CLEAR 后 sig 复位");

        // tick 5：同一清单回来 → 可再推（无 ping-pong：单次沿）
        io.file_board = Some(fake_board(&["C:\\r\\a.txt"]));
        assert!(clip_poll_tick(&mut st, 2000, &mut io, true).is_some());
        assert!(clip_poll_tick(&mut st, 2500, &mut io, true).is_none(), "再次同 sig 不重推");
    }

    /// 服务端推 `cleared=true, entries=[]` 单帧；客户端 apply 后
    /// `last_applied_meta_sig`/`placeholder_text` 复位、**不写板**
    /// （本机占位文本不主动擦除 = 惰性文本，§2.6）。
    #[test]
    fn r91c_clear_edge_and_apply_semantics() {
        // ── 服务端：File → Text 沿推 CLEAR ──
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        io.file_board = Some(fake_board(&["C:\\r\\a.txt"]));
        assert!(clip_poll_tick(&mut st, 0, &mut io, true).is_some());
        io.file_board = None;
        io.text = Some("T".to_string());
        let pkts = clip_poll_tick(&mut st, 500, &mut io, true).expect("CLEAR 必推");
        assert_eq!(pkts.len(), 1, "CLEAR 恒单帧");
        let cleared = reassemble_filemeta_pkts(&pkts);
        assert!(cleared.cleared && cleared.entries.is_empty() && !cleared.truncated);

        // ── 客户端：apply 文件清单 → apply CLEAR ──
        let cli_st = &mut ClipboardSyncState::new();
        let mut cli_io = FakeClipboard::new();
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![FileClipEntry {
                rel_path: "a.txt".to_string(),
                size: 10,
                is_dir: false,
                fetchable: true,
            }],
        };
        for p in &encode_filemeta_packets(&meta).unwrap() {
            assert!(matches!(
                cli_st.apply_remote_frame_event(0, &p.data, &mut cli_io),
                ClipApplyEvent::MetaApplied(_)
            ));
        }
        let sig_before = cli_st.last_applied_meta_sig;
        let set_calls_before = cli_io.set_calls;
        assert!(sig_before.is_some() && set_calls_before == 1);

        // 事件方法：CLEAR = MetaApplied(cleared)；旧签名 wrapper = None（不写板）
        let clear_pkts = encode_filemeta_packets(&filemeta_clear_meta()).unwrap();
        assert_eq!(
            cli_st.apply_remote_frame_event(1000, &clear_pkts[0].data, &mut cli_io),
            ClipApplyEvent::MetaApplied(filemeta_clear_meta())
        );
        assert_eq!(
            cli_st.apply_remote_frame(2000, &clear_pkts[0].data, &mut cli_io),
            None,
            "wrapper：CLEAR → None（不写板）"
        );
        assert_eq!(cli_st.last_applied_meta_sig, None, "CLEAR 清 sig");
        assert_eq!(cli_st.placeholder_text, None, "CLEAR 清占位记录");
        assert_eq!(
            cli_io.set_calls, set_calls_before,
            "CLEAR 不写板（占位变惰性文本，不主动擦除，§2.6）"
        );
        assert_eq!(
            cli_io.last_set.as_deref(),
            Some(clip_meta_placeholder(&meta).as_str()),
            "板内容保留占位（擦板侵入性高，设计不擦）"
        );
    }

    #[test]
    fn r91c_board_kind_matrix() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        // tick 输出分类：none / text / meta(n) / clear
        let classify = |pkts: Option<Vec<EncodedPacket>>| -> String {
            match pkts {
                None => "none".to_string(),
                Some(p) if p[0].data[0] & CLIP_FLAG_FILEMETA != 0 => {
                    let m = reassemble_filemeta_pkts(&p);
                    if m.cleared {
                        "clear".to_string()
                    } else {
                        format!("meta({})", m.entries.len())
                    }
                }
                Some(p) => format!("text({})", reassemble_packets(&p)),
            }
        };

        // ① Other→Other（空板）：不推（既有语义）
        assert_eq!(classify(clip_poll_tick(&mut st, 0, &mut io, true)), "none");
        // ② Other→Text：推文本
        io.text = Some("T1".to_string());
        assert_eq!(
            classify(clip_poll_tick(&mut st, 500, &mut io, true)),
            "text(T1)"
        );
        // ③ Text→Text 无变化：不推
        assert_eq!(classify(clip_poll_tick(&mut st, 1000, &mut io, true)), "none");
        // ④ Text→Text 变化：推文本
        io.text = Some("T2".to_string());
        assert_eq!(
            classify(clip_poll_tick(&mut st, 1500, &mut io, true)),
            "text(T2)"
        );
        // ⑤ Text→File（CF_HDROP+文本并存 → 文件优先）：推元数据
        io.file_board = Some(fake_board(&["C:\\r\\a.txt"]));
        assert_eq!(
            classify(clip_poll_tick(&mut st, 2000, &mut io, true)),
            "meta(1)"
        );
        // ⑥ File→File 同 sig：不重推
        assert_eq!(classify(clip_poll_tick(&mut st, 2500, &mut io, true)), "none");
        // ⑦ File→File sig 变化：再推
        io.file_board = Some(fake_board(&["C:\\r\\a.txt", "C:\\r\\b.txt"]));
        assert_eq!(
            classify(clip_poll_tick(&mut st, 3000, &mut io, true)),
            "meta(2)"
        );
        // ⑧ File→Text：推 CLEAR（单次沿）
        io.file_board = None;
        assert_eq!(classify(clip_poll_tick(&mut st, 3500, &mut io, true)), "clear");
        // ⑨ Text→Text（CLEAR 后文本未变）：不推（last_pushed 仍 = T2）
        assert_eq!(classify(clip_poll_tick(&mut st, 4000, &mut io, true)), "none");
        // ⑩ Text→Text 变化：推文本
        io.text = Some("T3".to_string());
        assert_eq!(
            classify(clip_poll_tick(&mut st, 4500, &mut io, true)),
            "text(T3)"
        );
        // ⑪ Text→File：再推元数据（sig 已随 CLEAR 复位）
        io.file_board = Some(fake_board(&["C:\\r\\a.txt"]));
        assert_eq!(
            classify(clip_poll_tick(&mut st, 5000, &mut io, true)),
            "meta(1)"
        );
        // ⑫ File→Other（文件移除且无文本）：推 CLEAR
        io.file_board = None;
        io.text = None;
        assert_eq!(classify(clip_poll_tick(&mut st, 5500, &mut io, true)), "clear");
        // ⑬ Other→Other：不推
        assert_eq!(classify(clip_poll_tick(&mut st, 6000, &mut io, true)), "none");
    }

    /// 元数据帧；(b) 读板失败（get_file_meta None）+ 无文本 → 无变化
    /// （fail-closed：不确定 = 不触发，§7.1）。
    #[test]
    fn r91c_cf_hdrop_fake_over255_and_read_failure() {
        // (a) 300 条注入（>255 截断，§2.4/§2.2 同口径）
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        let paths: Vec<String> = (0..300).map(|i| format!("C:\\r\\f{i}.txt")).collect();
        io.file_board = Some(OsFileBoard {
            entries: paths
                .into_iter()
                .map(|p| OsFileEntry {
                    abs_path: p,
                    size: 1,
                    is_dir: false,
                })
                .collect(),
        });
        let pkts = clip_poll_tick(&mut st, 0, &mut io, true).expect("文件板必推");
        let meta = reassemble_filemeta_pkts(&pkts);
        assert_eq!(meta.entries.len(), MAX_META_ENTRIES, "300 → 255 截断");
        assert!(meta.truncated);
        // 截断后仍须可编码（300×~40B 远小于 64KiB）
        assert!(encode_filemeta_packets(&meta).is_some());

        // (b) 读板失败 None + 无文本 → 无变化（不推不 CLEAR：Other 态）
        let mut st2 = ClipboardSyncState::new();
        let mut io2 = FakeClipboard::new();
        io2.file_board = None; // 读板失败形态（fail-closed）
        io2.text = None;
        assert!(clip_poll_tick(&mut st2, 0, &mut io2, true).is_none());
        assert_eq!(io2.get_calls, 1, "门控开恰读一次文本");
    }

    /// 名/大小/截断标记；sig 顺序敏感（换序必变）/内容敏感（size 变必变）/
    /// 确定性（同输入同 sig）。
    #[test]
    fn r91c_placeholder_and_sig_properties() {
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: true,
            entries: vec![
                FileClipEntry {
                    rel_path: "docs\\a.txt".to_string(),
                    size: 1234,
                    is_dir: false,
                    fetchable: true,
                },
                FileClipEntry {
                    rel_path: "b.bin".to_string(),
                    size: 9,
                    is_dir: true,
                    fetchable: false,
                },
            ],
        };
        let ph = clip_meta_placeholder(&meta);
        assert!(ph.contains("KirinDesk"), "占位明示来源（R7）");
        assert!(ph.contains("2 个文件"), "数量");
        assert!(ph.contains("docs\\a.txt") && ph.contains("1234 B"), "文件名 + 大小");
        assert!(ph.contains("目录"), "is_dir 标注");
        assert!(ph.contains("根外不可拉取"), "fetchable=false 标注");
        assert!(ph.contains("…（更多，截断显示）"), "truncated 标注");
        assert_eq!(clip_meta_placeholder(&filemeta_clear_meta()), "", "CLEAR 无占位");

        // sig：确定性
        assert_eq!(filemeta_sig(&meta), filemeta_sig(&meta));
        // sig：顺序敏感（换序必变）
        let mut swapped = meta.clone();
        swapped.entries.swap(0, 1);
        assert_ne!(filemeta_sig(&swapped), filemeta_sig(&meta));
        // sig：size 变必变
        let mut resized = meta.clone();
        resized.entries[0].size += 1;
        assert_ne!(filemeta_sig(&resized), filemeta_sig(&meta));
    }

    /// is_dir + fetchable 而已：**零绝对路径/零盘符/零 UNC/零 mtime**；
    /// Windows 大小写不敏感根匹配；根外 = 仅文件名 + fetchable=false。
    #[test]
    fn r91c_wire_no_absolute_path_leak() {
        let roots = vec![PathBuf::from("C:\\Users\\me")];
        let board = OsFileBoard {
            entries: vec![
                OsFileEntry {
                    abs_path: "C:\\Users\\me\\docs\\report.docx".to_string(),
                    size: 12345,
                    is_dir: false,
                },
                OsFileEntry {
                    // 大小写不敏感匹配（c:/users/me ≠ C:\Users\me 的字面但同根）
                    abs_path: "c:/users/me/pic.png".to_string(),
                    size: 77,
                    is_dir: false,
                },
                OsFileEntry {
                    // 全部根外 → fetchable=false + 仅文件名
                    abs_path: "D:\\elsewhere\\secret.txt".to_string(),
                    size: 9,
                    is_dir: true,
                },
            ],
        };
        let meta = filemeta_from_board(&board, &roots);
        assert_eq!(meta.entries.len(), 3);
        assert_eq!(meta.entries[0].rel_path, "docs/report.docx", "root 相对 + / 分隔");
        assert!(meta.entries[0].fetchable);
        assert_eq!(meta.entries[1].rel_path, "pic.png", "大小写不敏感根匹配");
        assert!(meta.entries[1].fetchable);
        assert_eq!(meta.entries[2].rel_path, "secret.txt", "根外 = 仅文件名");
        assert!(!meta.entries[2].fetchable);
        assert!(meta.entries[2].is_dir);

        // wire 字节面：零绝对路径/零盘符（盘符形态 `X:` 一律不出现）
        let wire = bincode::serialize(&meta).expect("serialize");
        for forbidden in [
            b"C:\\Users\\me".as_slice(),
            b"c:/users/me".as_slice(),
            b"D:\\elsewhere".as_slice(),
            b"\\Users\\".as_slice(),
            b"C:".as_slice(),
            b"D:".as_slice(),
        ] {
            let leaked = wire
                .windows(forbidden.len())
                .any(|w| w == forbidden);
            assert!(!leaked, "wire 不得出现 {forbidden:?}");
        }
    }

    /// 流 = 丢弃 + 状态复位（不猜语义），后续 v1 流正常 apply。
    #[test]
    fn r91c_meta_unknown_version_dropped() {
        let unknown = FileClipMeta {
            version: 2,
            cleared: false,
            truncated: false,
            entries: vec![],
        };
        let frag = FileClipMetaFragment {
            seq: 1,
            total: 1,
            payload: bincode::serialize(&unknown).unwrap(),
        };
        let mut frame = vec![CLIP_FLAG_FILEMETA];
        frame.extend_from_slice(&bincode::serialize(&frag).unwrap());

        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        assert_eq!(
            st.apply_remote_frame_event(0, &frame, &mut io),
            ClipApplyEvent::Silent,
            "未知版本 = 丢弃"
        );
        assert!(st.meta_rx.is_none(), "状态复位");
        assert_eq!(io.set_calls, 0);
        assert_eq!(st.last_applied_meta_sig, None);

        // 后续合法 v1 流不受影响
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![FileClipEntry {
                rel_path: "ok.txt".to_string(),
                size: 1,
                is_dir: false,
                fetchable: true,
            }],
        };
        for p in &encode_filemeta_packets(&meta).unwrap() {
            assert!(matches!(
                st.apply_remote_frame_event(1000, &p.data, &mut io),
                ClipApplyEvent::MetaApplied(_)
            ));
        }
        assert_eq!(io.set_calls, 1);
    }


    /// 逆运算（**fail-safe**：畸形输入 = None，零 panic）——单帧与多帧
    /// 往返逐位一致；CLEAR 形态（cleared=true 空条目）同口径。
    #[test]
    fn r147_filemeta_from_packets_roundtrip() {
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![
                FileClipEntry {
                    rel_path: "docs/report.docx".to_string(),
                    size: 12345,
                    is_dir: false,
                    fetchable: true,
                },
                FileClipEntry {
                    rel_path: "out/exe/app.bin".to_string(),
                    size: 0,
                    is_dir: true,
                    fetchable: true,
                },
            ],
        };
        let pkts = encode_filemeta_packets(&meta).expect("小元数据必可编码");
        assert_eq!(filemeta_from_packets(&pkts), Some(meta.clone()), "单帧往返");
        // 多帧（大清单 → 分片）。
        let big = FileClipMeta {
            entries: (0..40)
                .map(|i| FileClipEntry {
                    rel_path: format!("dir-{i:02}/{}", "x".repeat(120)),
                    size: i as u64,
                    is_dir: false,
                    fetchable: i % 3 == 0,
                })
                .collect(),
            ..meta.clone()
        };
        let big_pkts = encode_filemeta_packets(&big).expect("必可编码");
        assert!(big_pkts.len() > 1, "大清单必多帧");
        assert_eq!(filemeta_from_packets(&big_pkts), Some(big), "多帧往返");
        // CLEAR 形态（空条目 + cleared=true）。
        let clear_pkts = encode_filemeta_packets(&filemeta_clear_meta()).expect("CLEAR 恒可编码");
        assert_eq!(filemeta_from_packets(&clear_pkts), Some(filemeta_clear_meta()));
    }

    /// None）：空序列 / 非 FILEMETA 标志 / 缺片 / 乱序重号 / 版本不符 /
    /// 拼接体非合法 bincode。
    #[test]
    fn r147_filemeta_from_packets_malformed_fail_safe() {
        assert!(filemeta_from_packets(&[]).is_none(), "空序列 = None");
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![FileClipEntry {
                rel_path: "a/b.txt".to_string(),
                size: 1,
                is_dir: false,
                fetchable: true,
            }],
        };
        let mut pkts = encode_filemeta_packets(&meta).unwrap();
        // 非 FILEMETA 标志（文本帧混入）= None。
        let mut text_pkt = pkts[0].clone();
        text_pkt.data[0] = 0x00;
        assert!(filemeta_from_packets(&[text_pkt]).is_none(), "非 FILEMETA 标志 = None");
        // 缺片（多帧序列丢一片）= None。
        let big = FileClipMeta {
            entries: (0..40)
                .map(|i| FileClipEntry {
                    rel_path: format!("d-{i:02}/{}", "y".repeat(120)),
                    size: 0,
                    is_dir: false,
                    fetchable: true,
                })
                .collect(),
            ..meta.clone()
        };
        let big_pkts = encode_filemeta_packets(&big).unwrap();
        assert!(big_pkts.len() > 1);
        let truncated_seq = big_pkts[..big_pkts.len() - 1].to_vec();
        assert!(
            filemeta_from_packets(&truncated_seq).is_none(),
            "缺片 = None（total 不一致）"
        );
        // 乱序输入仍按 seq 重组（生产调用点不保证到达序 = 帧序的防御）。
        let mut shuffled = big_pkts.clone();
        let last = shuffled.len() - 1;
        shuffled.swap(0, last);
        assert_eq!(filemeta_from_packets(&shuffled), Some(big), "乱序 = 按 seq 重组");
        // 版本不符（未来 v2 元数据）= None（fail-closed）。
        let mut future = meta.clone();
        future.version = 2;
        let future_pkts = encode_filemeta_packets(&future).unwrap();
        assert!(filemeta_from_packets(&future_pkts).is_none(), "未知版本 = None");
        // 拼接体非合法 bincode（分片体截断 = 定式非法：flag + 4B 不足以
        // 承载 FileClipMetaFragment bincode）= None（零 panic）。
        let mut corrupt = pkts.clone();
        corrupt[0].data.truncate(5);
        assert!(filemeta_from_packets(&corrupt).is_none(), "payload 截断 = None（零 panic）");
    }

    /// `bincode(FileClipMeta)` 单消息形态——**无需 0x05 分片**）：往返 +
    /// 版本门 + 垃圾 fail-safe（零 panic）。
    #[test]
    fn r147_decode_clip_meta_roundtrip_and_fail_safe() {
        let meta = FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![FileClipEntry {
                rel_path: "recv/clip.dat".to_string(),
                size: 7,
                is_dir: false,
                fetchable: true,
            }],
        };
        let bytes = bincode::serialize(&meta).unwrap();
        assert_eq!(decode_clip_meta(&bytes), Some(meta.clone()), "单消息往返");
        // 版本不符 = None。
        let mut future = meta.clone();
        future.version = 9;
        assert!(
            decode_clip_meta(&bincode::serialize(&future).unwrap()).is_none(),
            "未知版本 = None"
        );
        // 垃圾 = None（零 panic）。
        assert!(decode_clip_meta(b"not-bincode").is_none());
        assert!(decode_clip_meta(&[]).is_none());
        // 空字节 bincode 单元（`()` 形态）= 结构不符 → None。
        assert!(decode_clip_meta(&[0u8]).is_none());
    }
}


/// 测试板条目（自由形态：abs/size/is_dir）。
#[cfg(test)]
fn r166_board_entry(abs: &str, size: u64, is_dir: bool) -> OsFileEntry {
    OsFileEntry {
        abs_path: abs.to_string(),
        size,
        is_dir,
    }
}

/// （rel + size，`/` 分隔）+ 纯空目录保留；truncated=false；顶层散文件
/// 零追加行。
#[test]
fn r166_filemeta_tree_expand_normal() {
    let base = std::env::temp_dir().join(format!("kirin_r166_tree_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let top = base.join("top");
    std::fs::create_dir_all(top.join("sub")).unwrap();
    std::fs::create_dir_all(top.join("empty")).unwrap();
    std::fs::write(top.join("a.txt"), b"AAAA").unwrap();
    std::fs::write(top.join("sub").join("b.txt"), b"BB").unwrap();
    let root = base.clone();
    let board = OsFileBoard {
        entries: vec![
            r166_board_entry(top.to_string_lossy().as_ref(), 0, true),
            r166_board_entry(base.join("loose.txt").to_string_lossy().as_ref(), 3, false),
        ],
    };
    let meta = filemeta_from_board(&board, &[root]);
    assert!(!meta.truncated, "正常树 = 不截断");
    let rows: Vec<(String, bool)> = meta
        .entries
        .iter()
        .map(|e| (e.rel_path.clone(), e.is_dir))
        .collect();
    // 顶层行（既有循环）+ 树行（追加）。
    assert!(rows.contains(&("top".to_string(), true)), "顶层目录行保留：{rows:?}");
    assert!(rows.contains(&("loose.txt".to_string(), false)));
    assert!(rows.contains(&("top/sub".to_string(), true)), "子目录结构行");
    assert!(rows.contains(&("top/empty".to_string(), true)), "纯空目录保留");
    let a = meta.entries.iter().find(|e| e.rel_path == "top/a.txt").unwrap();
    assert_eq!(a.size, 4, "文件 size 随行");
    assert!(!a.is_dir && a.fetchable, "树内文件 = fetchable");
    assert!(
        meta.entries.iter().any(|e| e.rel_path == "top/sub/b.txt"),
        "深层文件行"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn r166_filemeta_tree_depth_cap() {
    let base = std::env::temp_dir().join(format!("kirin_r166_deep_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    // 嵌套深度 > FOLDER_MAX_DEPTH 的树。
    let mut p = base.clone();
    for i in 0..=crate::file_manager::FOLDER_MAX_DEPTH + 2 {
        p = p.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("deep.txt"), b"x").unwrap();
    let board = OsFileBoard {
        entries: vec![r166_board_entry(base.join("d0").to_string_lossy().as_ref(), 0, true)],
    };
    let meta = filemeta_from_board(&board, &[base.clone()]);
    assert!(meta.truncated, "深度超限 = 截断旗标");
    let _ = std::fs::remove_dir_all(&base);
}

/// → truncated=true（fail-closed 不佯装完整）。
#[test]
fn r166_filemeta_tree_root_outside_and_unreadable() {
    // 根外目录：零树行、零截断（顶层占位行既有循环产出）。
    let board = OsFileBoard {
        entries: vec![r166_board_entry("Q:/definitely/outside", 0, true)],
    };
    let meta = filemeta_from_board(&board, &[]);
    assert!(!meta.truncated, "根外 = 既有占位口径非截断");
    assert!(meta.entries.iter().all(|e| !e.fetchable), "根外 = 占位");
    // 不存在目录（读失败）→ truncated=true。
    let board2 = OsFileBoard {
        entries: vec![r166_board_entry("/nonexistent/kirin/r166/ghost", 0, true)],
    };
    let meta2 = filemeta_from_board(&board2, &[PathBuf::from("/")]);
    assert!(meta2.truncated, "读失败 = 不完整树如实申报");
}

//
// 板侧路径 = DragQueryFileW 裸形态；fs_roots 出口 = canonicalize verbatim
// 形态。修前 VerbatimDisk ≠ Disk 组件恒不等 → fetchable=false 全军覆没
// （实机从未成功）。夹具形态与生产同源（根 = verbatim，板 = 裸），防测试
// 形态再漂移。

/// verbatim 盘根 × 裸路径：fetchable=true + rel 归一（`/` 分隔）。
#[cfg(windows)]
#[test]
fn r194_verbatim_root_bare_path_fetchable() {
    let board = OsFileBoard {
        entries: vec![crate::clipboard::OsFileEntry {
            abs_path: r"C:\Users\dev\doc\r194 sample.txt".into(),
            size: 7,
            is_dir: false,
        }],
    };
    let meta = filemeta_from_board(&board, &[PathBuf::from(r"\\?\C:\Users\dev")]);
    assert_eq!(meta.entries.len(), 1);
    let e = &meta.entries[0];
    assert!(e.fetchable, "verbatim 根 × 裸路径必须可解析（R193 §2 根因）");
    assert_eq!(e.rel_path, "doc/r194 sample.txt");
    assert_eq!(e.size, 7);
}

/// verbatim UNC × 裸 UNC 组件对齐；盘符大小写不敏感。
#[cfg(windows)]
#[test]
fn r194_verbatim_unc_and_drive_case_insensitive() {
    let board = OsFileBoard {
        entries: vec![crate::clipboard::OsFileEntry {
            abs_path: r"\\srv\share\proj\x.bin".into(),
            size: 1,
            is_dir: false,
        }],
    };
    let meta = filemeta_from_board(&board, &[PathBuf::from(r"\\?\UNC\srv\share\proj")]);
    assert!(meta.entries[0].fetchable, "verbatim UNC × 裸 UNC 对齐");
    assert_eq!(meta.entries[0].rel_path, "x.bin");
    // 盘符大小写互异（c: × C:）。
    let board2 = OsFileBoard {
        entries: vec![crate::clipboard::OsFileEntry {
            abs_path: r"d:\Data\a.txt".into(),
            size: 1,
            is_dir: false,
        }],
    };
    let meta2 = filemeta_from_board(&board2, &[PathBuf::from(r"\\?\D:\DATA")]);
    assert!(meta2.entries[0].fetchable, "组件级大小写不敏感");
    assert_eq!(meta2.entries[0].rel_path, "a.txt");
}

/// 双形态根并存（verbatim + 裸）逐根命中；全根未中 = fetchable=false
/// 占位（fail-closed 语义零迁移）。
#[cfg(windows)]
#[test]
fn r194_mixed_roots_and_outside_fail_closed() {
    let roots = vec![
        PathBuf::from(r"\\?\C:\Users\dev"),
        PathBuf::from(r"D:\pub"),
    ];
    let board = OsFileBoard {
        entries: vec![
            crate::clipboard::OsFileEntry {
                abs_path: r"C:\Users\dev\in1.txt".into(),
                size: 1,
                is_dir: false,
            },
            crate::clipboard::OsFileEntry {
                abs_path: r"d:\pub\in2.txt".into(),
                size: 2,
                is_dir: false,
            },
            crate::clipboard::OsFileEntry {
                abs_path: r"E:\elsewhere\out.txt".into(),
                size: 3,
                is_dir: false,
            },
        ],
    };
    let meta = filemeta_from_board(&board, &roots);
    assert_eq!(meta.entries.len(), 3);
    assert!(meta.entries[0].fetchable && meta.entries[0].rel_path == "in1.txt");
    assert!(meta.entries[1].fetchable && meta.entries[1].rel_path == "in2.txt");
    assert!(!meta.entries[2].fetchable, "全根未中 = 占位（白名单执法零迁移）");
    assert_eq!(meta.entries[2].rel_path, "out.txt", "根外 = 纯文件名占位");
}

/// 形态，与 `resolve_fs_browse_roots` 生产口径同源），板 = 裸路径
/// （DragQueryFileW 形态）。钉死「真实生产两形态交汇」而非手工字面量。
#[cfg(windows)]
#[test]
fn r194_canonicalized_root_production_form() {
    let base = std::env::temp_dir().join(format!("r194_prod_form_{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let verbatim_root = std::fs::canonicalize(&base).unwrap();
    assert!(
        verbatim_root.to_string_lossy().starts_with(r"\\?\"),
        "前置：canonicalize 出口应为 verbatim 形态（生产根同源）——got={}",
        verbatim_root.display()
    );
    let board = OsFileBoard {
        entries: vec![crate::clipboard::OsFileEntry {
            abs_path: base.join("live.txt").to_string_lossy().into_owned(),
            size: 3,
            is_dir: false,
        }],
    };
    let meta = filemeta_from_board(&board, &[verbatim_root]);
    assert!(meta.entries[0].fetchable, "生产同形根×板必须可解析");
    assert_eq!(meta.entries[0].rel_path, "live.txt");
    let _ = std::fs::remove_dir_all(&base);
}
