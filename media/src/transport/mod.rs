//! QUIC 传输层（Phase 3）+ P1F 传输集成（EncodedPacket → SecureChannel / QUIC）。
//!
//! # 模块
//!
//! | 模块 | 职责 |
//! |------|------|
//! | `quic` | QUIC 最小端点封装（自签名 Ed25519 证书，仅协议合规） |
//! | `datagram` | 媒体帧分片、加密/解密、DATAGRAM 收发 |
//! | `control` | 控制消息加密传输（可靠流） |
//! | `reassembly` | DATAGRAM 分片重组缓冲区（乱序到达、超时清理） |
//! | `loss_detection` | 基于 frame_id 连续性的丢包检测 |
//! | `transport` | MediaTransport trait + QuicMediaTransport + SecureChannelTransport（tag 分帧/输入通道） |
//! | `stream` | P1F：EncodedPacket 帧头（Annex B）+ 通道分派（SecureChannel 前缀 / QUIC DATAGRAM） |
//! | `priority` | P1F：DATAGRAM 优先级调度（键鼠 > 音频 > 视频；拥塞丢视频） |
pub mod bi_stream;
pub mod control;
pub mod datagram;
pub mod loss_detection;
pub mod priority;
pub mod quic;
pub mod reassembly;
pub mod stream;
pub mod transport;

// ── 重新导出 ───────────────────────────────────────────
pub use control::ControlMessage;
pub use datagram::FramePacket;
pub use loss_detection::{LossDetector, LossStats};
pub use priority::{Priority, PriorityQueue};
pub use quic::{generate_quic_cert, MediaCipher, QuicConnection, QuicEndpoint};
pub use stream::{
    frame_packet, parse_frame, ChannelTag, PacketHeader, PacketKindWire, QuicKind, TransError,
    FLAG_EXTRADATA, FLAG_INCREMENTAL, FLAG_KEY, HEADER_MAGIC, HEADER_SIZE, HEADER_VERSION,
    MAX_PACKET_PAYLOAD,
};
pub use transport::{
    accept_quic_transport, connect_quic_transport, QuicMediaTransport, SecureChannelReceiver,
    SecureChannelSender, SecureChannelTransport,
};

use crate::proto::EncodedWindow;
use async_trait::async_trait;

/// 传输层错误。
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("SecureChannel error: {0}")]
    SecureChannel(String),

    #[error("AEAD encryption/decryption error: {0}")]
    Crypto(String),

    #[error("Short datagram: got {got} bytes, need at least {need}")]
    ShortDatagram { got: usize, need: usize },

    #[error("Incomplete frame: frame_id={frame_id}")]
    IncompleteFrame { frame_id: u64 },

    #[error("Connection closed: {reason}")]
    ConnectionClosed { reason: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Handshake error: {0}")]
    Handshake(String),

    #[error("Invalid frame: {0}")]
    InvalidFrame(String),

    #[error("Timeout")]
    Timeout,
}

/// 传输层抽象——对所有上层透明。
///
/// 实现者：QuicMediaTransport（主路径）或 SecureChannel 回退。
#[async_trait]
pub trait MediaTransport: Send {
    /// 发送一个编码窗口。
    async fn send_window(&mut self, window: &EncodedWindow) -> Result<(), TransportError>;

    /// 接收一个帧（已解密、已重组）。
    async fn recv_frame(&mut self) -> Result<FramePacket, TransportError>;

    /// 发送控制消息。
    async fn send_control(&mut self, msg: &ControlMessage) -> Result<(), TransportError>;

    /// 接收控制消息。
    async fn recv_control(&mut self) -> Result<ControlMessage, TransportError>;

    /// 是否存活。
    fn is_alive(&self) -> bool;

    /// 当前 RTT（毫秒）。
    fn rtt(&self) -> u64;

    /// 主动关闭。
    async fn close(self: Box<Self>) -> Result<(), TransportError>;
}
