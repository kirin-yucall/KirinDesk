//! M13-T003: 客户端剪贴板共享 — 轮询本地变更 → 推送；接收远端推送 → 写入本地。
//!
//! 传输格式：`EncodedPacket { kind: PacketKind::Clipboard, data: <分片负载> }`，
//! 复用 SecureChannel 键鼠同款可靠发送路径（`ChannelTag::Clipboard = 0x05`）。
//! 分片负载 = `[flags: u8][chunk bytes]`：
//! - `flags & 0x01` = START（首片）；`flags & 0x02` = END（末片）；
//! - 单片消息 flags = START|END；大文本按 [`MAX_CLIP_CHUNK`] 分片（SecureChannel
//!   单帧 payload 上限 ~1200B，分片大小为其留余量）。
//!
//! 防回环策略：
//! - 本地轮询（500ms）只推送**非空**且与上次不同的文本；
//! - 远端推送写入本地后进入冷却窗口（1s），冷却期内本地回读到的同一文本
//!   不重复上推（否则形成 ping-pong 循环）。

use kirin_desk_media::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use std::time::Duration;

/// 本地剪贴板轮询间隔。
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// 远端写入后的回环抑制窗口（毫秒）。
pub const ECHO_SUPPRESS_MS: u64 = 1000;

/// 单帧剪贴板分片负载上限（SecureChannel 单帧 ~1200B，留帧头/加密余量）。
pub const MAX_CLIP_CHUNK: usize = 1000;

/// 远端单次推送总长度上限（1MB，防内存膨胀）。
pub const MAX_CLIP_TOTAL: usize = 1024 * 1024;

/// 分片标志：START（首片）。
pub const CLIP_FLAG_START: u8 = 0x01;
/// 分片标志：END（末片）。
pub const CLIP_FLAG_END: u8 = 0x02;

/// 本地剪贴板抽象（平台实现：arboard；测试：内存假件）。
pub trait ClipboardIo: Send + 'static {
    /// 读取当前剪贴板文本（无文本/读取失败 → None）。
    fn get_text(&mut self) -> Option<String>;
    /// 写入剪贴板文本，返回是否成功。
    fn set_text(&mut self, text: &str) -> bool;
}

/// arboard 平台实现（Windows / macOS / Linux X11+Wayland）。
pub struct OsClipboard {
    inner: arboard::Clipboard,
}

impl OsClipboard {
    /// 初始化系统剪贴板；不可用（如 headless 环境）返回 None。
    pub fn new() -> Option<Self> {
        arboard::Clipboard::new().ok().map(|inner| Self { inner })
    }
}

impl ClipboardIo for OsClipboard {
    fn get_text(&mut self) -> Option<String> {
        self.inner.get_text().ok()
    }

    fn set_text(&mut self, text: &str) -> bool {
        self.inner.set_text(text.to_string()).is_ok()
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
}

impl ClipboardSyncState {
    pub fn new() -> Self {
        Self {
            last_pushed: None,
            last_remote_set: None,
            suppress_until_ms: 0,
            reassembly: None,
        }
    }

    /// 轮询本地剪贴板：返回应推送的文本（None = 无变化 / 冷却回环 / 空内容）。
    pub fn poll_local(&mut self, now_ms: u64, io: &mut dyn ClipboardIo) -> Option<String> {
        let text = io.get_text()?;
        if text.is_empty() {
            return None; // 空剪贴板不推送
        }
        // 冷却期内远端刚写入的同一文本 → 不回推（防 ping-pong）。
        if now_ms < self.suppress_until_ms
            && self.last_remote_set.as_deref() == Some(text.as_str())
        {
            return None;
        }
        if self.last_pushed.as_deref() == Some(text.as_str()) {
            return None; // 无变化
        }
        self.last_pushed = Some(text.clone());
        Some(text)
    }

    /// 处理一帧远端剪贴板负载（分片感知）。完整文本到达时写入本地并防回环。
    pub fn apply_remote_frame(&mut self, now_ms: u64, payload: &[u8], io: &mut dyn ClipboardIo) {
        let Some((&flags, chunk)) = payload.split_first() else {
            return;
        };
        if chunk.len() > MAX_CLIP_TOTAL {
            self.reassembly = None;
            return;
        }
        if flags & CLIP_FLAG_START != 0 {
            // 新拷贝开始 → 丢弃旧的未完成缓冲。
            self.reassembly = Some(Vec::new());
        }
        if let Some(buf) = self.reassembly.as_mut() {
            buf.extend_from_slice(chunk);
        }
        if flags & CLIP_FLAG_END != 0 {
            let bytes = self.reassembly.take().unwrap_or_default();
            // 空文本不写入（与发送侧"空剪贴板不推送"策略一致）。
            if !bytes.is_empty() {
                if let Ok(text) = String::from_utf8(bytes) {
                    self.apply_remote(now_ms, &text, io);
                }
            }
        }
    }

    /// 应用完整远端文本：写入本地并记录冷却，防回环。
    fn apply_remote(&mut self, now_ms: u64, text: &str, io: &mut dyn ClipboardIo) {
        self.last_remote_set = Some(text.to_string());
        self.suppress_until_ms = now_ms + ECHO_SUPPRESS_MS;
        // 同步 last_pushed，避免远端内容随后被本地轮询误判为"新内容"。
        if !text.is_empty() {
            self.last_pushed = Some(text.to_string());
        }
        io.set_text(text);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 内存剪贴板假件（可注入）。
    struct FakeClipboard {
        text: Option<String>,
        last_set: Option<String>,
        set_calls: usize,
    }

    impl FakeClipboard {
        fn new() -> Self {
            Self {
                text: None,
                last_set: None,
                set_calls: 0,
            }
        }
    }

    impl ClipboardIo for FakeClipboard {
        fn get_text(&mut self) -> Option<String> {
            self.text.clone()
        }

        fn set_text(&mut self, text: &str) -> bool {
            self.set_calls += 1;
            self.last_set = Some(text.to_string());
            self.text = Some(text.to_string());
            true
        }
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
        st.apply_remote_frame(1000, &frames[0], &mut io);
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
            st.apply_remote_frame(1000, f, &mut io);
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
        st.apply_remote_frame(1000, &frames[0], &mut io);
        assert_eq!(io.set_calls, 0, "未收到 END 不应写入");

        // 第二份拷贝 START → 旧缓冲丢弃，只保留新内容
        let frames2 = encode_clipboard_payloads("second", MAX_CLIP_CHUNK);
        for f in &frames2 {
            st.apply_remote_frame(2000, f, &mut io);
        }
        assert_eq!(io.last_set.as_deref(), Some("second"));
    }

    #[test]
    fn test_empty_payload_ignored() {
        let mut st = ClipboardSyncState::new();
        let mut io = FakeClipboard::new();
        st.apply_remote_frame(0, &[], &mut io);
        st.apply_remote_frame(0, &[CLIP_FLAG_START | CLIP_FLAG_END], &mut io);
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
}
