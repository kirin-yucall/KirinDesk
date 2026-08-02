//! 单通道连接复用（M13-T005）。
//!
//! # 目标
//!
//! 控制、视频、音频、输入四类消息复用**单一字节流**传输（如 TCP
//! `SecureChannel` 回退路径），避免每条媒体类型独占一个连接/通道。
//!
//! # Wire 格式
//!
//! 每条消息 = `[type:u8][len:u32 大端][payload]`，类型前缀：
//!
//! | 值 | 通道 | 常量 |
//! |----|------|------|
//! | `0x01` | Control（控制信令） | [`TYPE_CONTROL`] |
//! | `0x02` | Video（视频媒体） | [`TYPE_VIDEO`] |
//! | `0x03` | Audio（音频媒体） | [`TYPE_AUDIO`] |
//! | `0x04` | Input（键鼠输入） | [`TYPE_INPUT`] |
//!
//! 接收端用 [`Multiplexer::recv`] 解析出 `(MultiplexType, payload)`，经
//! [`Demultiplexer::route`] 按类型分发到不同处理路径（每类型一个 sink 队列）。
//!
//! # 用法
//!
//! ```ignore
//! // 发送端（AsyncWrite 流）
//! let mut mux = Multiplexer::new(stream_write_half);
//! mux.send(MultiplexType::Control, &control_bytes).await?;
//! mux.send(MultiplexType::Video, &nal_bytes).await?;
//!
//! // 接收端（AsyncRead 流 + 后台分发 task）
//! let mut demux = Demultiplexer::new();
//! demux.add_sink(MultiplexType::Video, video_tx);
//! demux.add_sink(MultiplexType::Control, control_tx);
//! spawn_demux_loop(Multiplexer::new(stream_read_half), demux);
//! ```
//!
//! 泛型不要求 `S` 同时实现读写：`send` 仅在 `S: AsyncWrite` 时可用，
//! `recv` 仅在 `S: AsyncRead` 时可用（方法级 trait 约束）——可与
//! `SecureChannel::into_split()` 的读写半通道配合。

use std::collections::HashMap;
use std::io;
use std::sync::mpsc::Sender;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 通道类型前缀：Control（控制信令）。
pub const TYPE_CONTROL: u8 = 0x01;
/// 通道类型前缀：Video（视频媒体）。
pub const TYPE_VIDEO: u8 = 0x02;
/// 通道类型前缀：Audio（音频媒体）。
pub const TYPE_AUDIO: u8 = 0x03;
/// 通道类型前缀：Input（键鼠输入）。
pub const TYPE_INPUT: u8 = 0x04;

/// 默认最大帧长（16MB）。防超长帧拖垮接收缓冲 / 防损坏流中的伪长度头。
pub const DEFAULT_MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// 帧头长度：1 字节类型 + 4 字节大端长度。
pub const FRAME_HEADER_LEN: usize = 5;

// ════════════════════════════════════════════════════════════════
// MultiplexType — 逻辑通道类型
// ════════════════════════════════════════════════════════════════

/// 逻辑通道类型（wire 类型前缀的强类型表示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MultiplexType {
    /// 控制信令（`0x01`）
    Control,
    /// 视频媒体（`0x02`）
    Video,
    /// 音频媒体（`0x03`）
    Audio,
    /// 键鼠输入（`0x04`）
    Input,
}

impl MultiplexType {
    /// wire 类型前缀。
    pub fn code(self) -> u8 {
        match self {
            MultiplexType::Control => TYPE_CONTROL,
            MultiplexType::Video => TYPE_VIDEO,
            MultiplexType::Audio => TYPE_AUDIO,
            MultiplexType::Input => TYPE_INPUT,
        }
    }

    /// 从 wire 前缀解析（未知值返回 None）。
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            TYPE_CONTROL => Some(MultiplexType::Control),
            TYPE_VIDEO => Some(MultiplexType::Video),
            TYPE_AUDIO => Some(MultiplexType::Audio),
            TYPE_INPUT => Some(MultiplexType::Input),
            _ => None,
        }
    }

    /// 通道名（日志）。
    pub fn name(self) -> &'static str {
        match self {
            MultiplexType::Control => "Control",
            MultiplexType::Video => "Video",
            MultiplexType::Audio => "Audio",
            MultiplexType::Input => "Input",
        }
    }
}

// ════════════════════════════════════════════════════════════════
// MultiplexError
// ════════════════════════════════════════════════════════════════

/// 复用层错误。
#[derive(Debug, thiserror::Error)]
pub enum MultiplexError {
    /// wire 上出现未知类型前缀。
    #[error("invalid channel type byte: 0x{0:02x}")]
    InvalidType(u8),
    /// 帧长超过上限（防超长帧）。
    #[error("frame too large: {0} bytes > max {1}")]
    FrameTooLarge(u32, u32),
    /// 底层 IO 错误（含流关闭）。
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// 分发时该通道没有注册 sink。
    #[error("no sink registered for channel {0:?}")]
    NoSink(MultiplexType),
}

// ════════════════════════════════════════════════════════════════
// 帧编解码原语（纯函数，可独立测试）
// ════════════════════════════════════════════════════════════════

/// 编码一帧：`[type:u8][len:u32 BE][payload]`。
///
/// 调用方需保证 `payload.len() ≤ max_frame_len`（见 [`Multiplexer::send`]；
/// 本函数不做长度校验，纯编码）。
pub fn encode_frame(kind: MultiplexType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.push(kind.code());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// 解析帧头（前 5 字节）→ `(通道类型, 负载长度)`。
///
/// 校验类型前缀合法性 + 长度上限（超限返回 [`FrameTooLarge`](MultiplexError::FrameTooLarge)）。
pub fn decode_header(
    header: &[u8],
    max_frame_len: u32,
) -> Result<(MultiplexType, u32), MultiplexError> {
    if header.len() < FRAME_HEADER_LEN {
        return Err(MultiplexError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "multiplex header too short",
        )));
    }
    let kind = MultiplexType::from_code(header[0]).ok_or(MultiplexError::InvalidType(header[0]))?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if len > max_frame_len {
        return Err(MultiplexError::FrameTooLarge(len, max_frame_len));
    }
    Ok((kind, len))
}

// ════════════════════════════════════════════════════════════════
// Multiplexer — 单流复用器
// ════════════════════════════════════════════════════════════════

/// 单流复用器：在一条字节流上承载四种逻辑通道。
///
/// 方法级 trait 约束：`send` 需 `S: AsyncWrite`，`recv` 需 `S: AsyncRead`——
/// 同一结构可同时支持（`S: AsyncRead + AsyncWrite`，如 TcpStream 整流），
/// 也可分别包装读写半通道。
pub struct Multiplexer<S> {
    inner: S,
    max_frame_len: u32,
}

impl<S> Multiplexer<S> {
    /// 创建复用器（默认帧长上限 16MB）。
    pub fn new(inner: S) -> Self {
        Self::with_max_frame(inner, DEFAULT_MAX_FRAME_LEN)
    }

    /// 创建复用器（自定义帧长上限）。
    pub fn with_max_frame(inner: S, max_frame_len: u32) -> Self {
        Self {
            inner,
            max_frame_len,
        }
    }

    /// 取回底层流。
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// 当前帧长上限。
    pub fn max_frame_len(&self) -> u32 {
        self.max_frame_len
    }
}

impl<S: AsyncWrite + Unpin> Multiplexer<S> {
    /// 发送一条带类型前缀的消息。
    ///
    /// 负载超过帧长上限返回 [`FrameTooLarge`](MultiplexError::FrameTooLarge)（不写流）。
    pub async fn send(
        &mut self,
        kind: MultiplexType,
        payload: &[u8],
    ) -> Result<(), MultiplexError> {
        if payload.len() as u32 > self.max_frame_len {
            return Err(MultiplexError::FrameTooLarge(
                payload.len() as u32,
                self.max_frame_len,
            ));
        }
        self.inner.write_all(&encode_frame(kind, payload)).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> Multiplexer<S> {
    /// 接收一条消息并解复用：返回 `(通道类型, 负载)`。
    ///
    /// 流关闭（对端关闭写半 / EOF）返回 [`Io`](MultiplexError::Io)（UnexpectedEof）。
    pub async fn recv(&mut self) -> Result<(MultiplexType, Vec<u8>), MultiplexError> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        self.inner.read_exact(&mut header).await?;
        let (kind, len) = decode_header(&header, self.max_frame_len)?;
        let mut payload = vec![0u8; len as usize];
        self.inner.read_exact(&mut payload).await?;
        Ok((kind, payload))
    }
}

// ════════════════════════════════════════════════════════════════
// Demultiplexer — 接收端类型分发
// ════════════════════════════════════════════════════════════════

/// 接收端分发器：把 `(MultiplexType, payload)` 按类型路由到各自的 sink 队列。
///
/// 每通道一个 `std::sync::mpsc::Sender`（同步队列，解复用循环投递、处理
/// task 消费；未注册 sink 的通道 → [`NoSink`](MultiplexError::NoSink) 错误，
/// 由上层决定丢弃或终止）。
pub struct Demultiplexer {
    sinks: HashMap<MultiplexType, Sender<Vec<u8>>>,
}

impl Demultiplexer {
    /// 创建分发器。
    pub fn new() -> Self {
        Self {
            sinks: HashMap::new(),
        }
    }

    /// 注册某通道的接收队列（重复注册替换旧队列）。
    pub fn add_sink(&mut self, kind: MultiplexType, tx: Sender<Vec<u8>>) {
        self.sinks.insert(kind, tx);
    }

    /// 某通道的接收队列（未注册 → None）。
    pub fn sink(&self, kind: MultiplexType) -> Option<&Sender<Vec<u8>>> {
        self.sinks.get(&kind)
    }

    /// 路由一条消息到对应通道队列。
    ///
    /// 队列已关闭（接收端已 drop）→ 返回 [`Io`](MultiplexError::Io)（BrokenPipe）。
    pub fn route(&self, kind: MultiplexType, payload: Vec<u8>) -> Result<(), MultiplexError> {
        match self.sinks.get(&kind) {
            Some(tx) => tx.send(payload).map_err(|_| {
                MultiplexError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "sink closed"))
            }),
            None => Err(MultiplexError::NoSink(kind)),
        }
    }
}

impl Default for Demultiplexer {
    fn default() -> Self {
        Self::new()
    }
}

/// 启动解复用循环：持续 `recv` 并按类型投递（后台 task）。
///
/// 流关闭 / 未知类型 / 未注册通道 → task 结束并返回首个错误。
pub fn spawn_demux_loop<S>(
    mux: Multiplexer<S>,
    demux: Demultiplexer,
) -> tokio::task::JoinHandle<Result<(), MultiplexError>>
where
    S: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut mux = mux;
        loop {
            let (kind, payload) = mux.recv().await?;
            demux.route(kind, payload)?;
        }
    })
}

// ── 测试 ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use tokio::io::duplex;

    // ── 帧编解码原语 ───────────────────────────────────────────

    /// 帧布局：[type:u8][len:u32 BE][payload]。
    #[test]
    fn test_encode_frame_layout() {
        let frame = encode_frame(MultiplexType::Video, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(frame[0], TYPE_VIDEO);
        assert_eq!(&frame[1..5], &3u32.to_be_bytes());
        assert_eq!(&frame[5..], &[0xAA, 0xBB, 0xCC]);
    }

    /// 空负载帧：len=0。
    #[test]
    fn test_encode_frame_empty_payload() {
        let frame = encode_frame(MultiplexType::Control, &[]);
        assert_eq!(frame.len(), FRAME_HEADER_LEN);
        assert_eq!(&frame[1..5], &0u32.to_be_bytes());
    }

    /// decode_header 往返 + 全部四种类型。
    #[test]
    fn test_decode_header_roundtrip() {
        for kind in [
            MultiplexType::Control,
            MultiplexType::Video,
            MultiplexType::Audio,
            MultiplexType::Input,
        ] {
            let frame = encode_frame(kind, &[1, 2, 3]);
            let (k, len) =
                decode_header(&frame[..FRAME_HEADER_LEN], DEFAULT_MAX_FRAME_LEN).unwrap();
            assert_eq!(k, kind);
            assert_eq!(len, 3);
        }
    }

    /// 未知类型前缀 → InvalidType。
    #[test]
    fn test_decode_header_invalid_type() {
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = 0x09;
        let err = decode_header(&header, DEFAULT_MAX_FRAME_LEN).unwrap_err();
        assert!(matches!(err, MultiplexError::InvalidType(0x09)));
    }

    /// 超长帧头 → FrameTooLarge。
    #[test]
    fn test_decode_header_too_large() {
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = TYPE_VIDEO;
        header[1..5].copy_from_slice(&(1024u32).to_be_bytes());
        let err = decode_header(&header, 512).unwrap_err();
        assert!(matches!(err, MultiplexError::FrameTooLarge(1024, 512)));
    }

    // ── Multiplexer（tokio duplex）─────────────────────────────

    /// 四种通道交错发送 → 按序原样收到（类型 + 负载）。
    #[tokio::test]
    async fn test_multiplexer_duplex_roundtrip() {
        let (a, b) = duplex(64 * 1024);
        let mut sender = Multiplexer::new(a);
        let mut receiver = Multiplexer::new(b);

        sender.send(MultiplexType::Control, b"hello").await.unwrap();
        sender
            .send(MultiplexType::Video, &[0u8; 100])
            .await
            .unwrap();
        sender.send(MultiplexType::Audio, b"audio").await.unwrap();
        sender.send(MultiplexType::Input, b"keys").await.unwrap();

        assert_eq!(
            receiver.recv().await.unwrap(),
            (MultiplexType::Control, b"hello".to_vec())
        );
        assert_eq!(
            receiver.recv().await.unwrap(),
            (MultiplexType::Video, vec![0u8; 100])
        );
        assert_eq!(
            receiver.recv().await.unwrap(),
            (MultiplexType::Audio, b"audio".to_vec())
        );
        assert_eq!(
            receiver.recv().await.unwrap(),
            (MultiplexType::Input, b"keys".to_vec())
        );
    }

    /// 帧头跨多个写入块（逐字节写）→ 接收端 read_exact 仍能正确组帧。
    #[tokio::test]
    async fn test_multiplexer_header_split_across_writes() {
        let (mut a, b) = duplex(64 * 1024);
        let mut receiver = Multiplexer::new(b);

        let frame = encode_frame(MultiplexType::Video, &[1, 2, 3, 4, 5]);
        // 逐字节写入，模拟网络分片。
        for byte in &frame {
            a.write_all(&[*byte]).await.unwrap();
        }
        a.flush().await.unwrap();

        assert_eq!(
            receiver.recv().await.unwrap(),
            (MultiplexType::Video, vec![1, 2, 3, 4, 5])
        );
    }

    /// 大帧：负载 16MB 以内可传；超过上限在 send 侧即拒绝。
    #[tokio::test]
    async fn test_multiplexer_frame_too_large_rejected() {
        let (a, _b) = duplex(64 * 1024);
        let mut sender = Multiplexer::with_max_frame(a, 8);
        let err = sender
            .send(MultiplexType::Video, &[0u8; 9])
            .await
            .unwrap_err();
        assert!(matches!(err, MultiplexError::FrameTooLarge(9, 8)));
    }

    /// wire 上出现未知类型 → recv 报 InvalidType。
    #[tokio::test]
    async fn test_multiplexer_recv_invalid_type() {
        let (mut a, b) = duplex(64 * 1024);
        let mut receiver = Multiplexer::new(b);
        a.write_all(&[0x77, 0, 0, 0, 0]).await.unwrap();
        a.flush().await.unwrap();
        let err = receiver.recv().await.unwrap_err();
        assert!(matches!(err, MultiplexError::InvalidType(0x77)));
    }

    /// 对端关闭 → recv 返回 EOF 类错误（不是 panic/挂死）。
    #[tokio::test]
    async fn test_multiplexer_recv_eof() {
        let (a, b) = duplex(64 * 1024);
        let mut receiver = Multiplexer::new(b);
        drop(a); // 关闭写半
        let err = receiver.recv().await.unwrap_err();
        assert!(matches!(err, MultiplexError::Io(_)));
    }

    // ── Demultiplexer 分发 ─────────────────────────────────────

    /// 各通道路由到自己的 sink；未注册 → NoSink。
    #[test]
    fn test_demultiplexer_routing() {
        let mut demux = Demultiplexer::new();
        let (ctrl_tx, ctrl_rx) = mpsc::channel();
        let (video_tx, video_rx) = mpsc::channel();
        demux.add_sink(MultiplexType::Control, ctrl_tx);
        demux.add_sink(MultiplexType::Video, video_tx);

        demux.route(MultiplexType::Control, b"c1".to_vec()).unwrap();
        demux.route(MultiplexType::Video, b"v1".to_vec()).unwrap();
        demux.route(MultiplexType::Video, b"v2".to_vec()).unwrap();

        assert_eq!(ctrl_rx.recv().unwrap(), b"c1");
        assert_eq!(video_rx.recv().unwrap(), b"v1");
        assert_eq!(video_rx.recv().unwrap(), b"v2");
        // 队列独立：控制队列已空。
        assert!(ctrl_rx.try_recv().is_err());

        // 未注册通道 → NoSink。
        let err = demux.route(MultiplexType::Audio, vec![]).unwrap_err();
        assert!(matches!(err, MultiplexError::NoSink(MultiplexType::Audio)));
    }

    /// sink 被消费方 drop 后路由 → BrokenPipe（Io 错误）。
    #[test]
    fn test_demultiplexer_closed_sink() {
        let mut demux = Demultiplexer::new();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        demux.add_sink(MultiplexType::Input, tx);
        drop(rx); // 接收端关闭 → Sender::send 失败
        let err = demux.route(MultiplexType::Input, vec![1]).unwrap_err();
        assert!(matches!(err, MultiplexError::Io(_)));
    }

    /// 端到端：duplex 上的后台解复用循环 → 各通道 sink 收到正确数据。
    ///
    /// 注意：std mpsc 的阻塞 `recv()` 不能直接放在 tokio 单线程运行时里
    /// （会饿死后台 demux task），消费侧用 `spawn_blocking` 接出。
    #[tokio::test]
    async fn test_demux_loop_end_to_end() {
        let (a, b) = duplex(64 * 1024);
        let mut sender = Multiplexer::new(a);

        let mut demux = Demultiplexer::new();
        let (ctrl_tx, ctrl_rx) = mpsc::channel();
        let (video_tx, video_rx) = mpsc::channel();
        demux.add_sink(MultiplexType::Control, ctrl_tx);
        demux.add_sink(MultiplexType::Video, video_tx);
        let task = spawn_demux_loop(Multiplexer::new(b), demux);

        sender.send(MultiplexType::Video, b"frame1").await.unwrap();
        sender.send(MultiplexType::Control, b"cfg").await.unwrap();
        sender.send(MultiplexType::Video, b"frame2").await.unwrap();
        // 关流结束循环。
        drop(sender);

        let (f1, c1, f2) = tokio::task::spawn_blocking(move || {
            (
                video_rx.recv().unwrap(),
                ctrl_rx.recv().unwrap(),
                video_rx.recv().unwrap(),
            )
        })
        .await
        .unwrap();
        assert_eq!(f1, b"frame1");
        assert_eq!(c1, b"cfg");
        assert_eq!(f2, b"frame2");
        // 循环随 EOF 结束（内部返回 Io 错误，task 本身未 panic）。
        let inner = task.await.unwrap();
        assert!(inner.is_err(), "demux loop should end with EOF error");
    }
}
