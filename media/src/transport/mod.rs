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
//!
//! # S-17 QUIC 接线门禁（F-22 · 接线前必读）
//!
//! `quic` 模块的 rustls 客户端校验（`SkipServerVerification`）**全放行是有意设计**
//! （仅协议合规），安全完全依赖上层 Ed25519 握手（审计报告 2026-08-02 §4 F-22）。
//! 因此**任何未来把 QUIC 传输接入主流程的改动，必须先满足下方门禁，否则禁止接线**：
//!
//! 1. **服务端策略层校验**：白名单 / 审批 / pin 校验，与 `accept_quic_transport`
//!    （`server_handshake_verified_with_nickname_generic`）对齐，不得绕过或占位；
//! 2. **客户端侧服务端身份校验**：`connect_quic_transport` 必须携带强制校验的
//!    `server_pin: PinExpectation`（R-02 已把旧的 `_server_pubkey_base64` 占位参数
//!    改为类型化强制校验，不存在"无期望跳过"路径）——禁止恢复"空串 / 忽略 pin"
//!    之类的快捷方式；
//! 3. 保持职责分离现状不变：TLS 全放行 + 上层 Ed25519 强制 pin 校验。
//!
//! 完整门禁注释见 `pub mod quic;` 声明处。
pub mod bi_stream;
pub mod control;
pub mod datagram;
pub mod loss_detection;
pub mod priority;
pub mod punch_bridge; // M8-T026-P1: 打洞路径 → 媒体传输桥（PATH-004 升舱）
/// # S-17 接线门禁（F-22 · 接线前必读）
///
/// 本模块（`quic.rs`）的 rustls 客户端校验 `SkipServerVerification` 全放行
/// 是**有意设计**（仅协议合规，`quic.rs` 模块文档有完整说明）——安全完全由
/// 上层 Ed25519 握手承担（审计报告 2026-08-02 §4 F-22，当前
/// `accept_media_transport` 无生产调用方，为 dead code）。
///
/// 任何未来把 QUIC 传输接入主流程（session / 主传输选择路径）的改动，
/// **必须先满足以下门禁，否则禁止接线**：
///
/// 1. **服务端策略层校验**：接入服务端接受路径前必须先补策略层校验——
///    白名单 / 审批 / pin，与 `accept_quic_transport` 的
///    `server_handshake_verified_with_nickname_generic` 对齐（该握手已含
///    服务端对客户端公钥的策略校验与挑战码校验），不得绕过或替换为空实现；
/// 2. **客户端侧服务端身份校验**：客户端拨号必须携带强制校验的服务端身份——
///    `connect_quic_transport` 的 `server_pin: PinExpectation`（R-02 已取消旧的
///    `_server_pubkey_base64` 下划线占位参数，改为类型化强制校验，core 握手层
///    无"无期望跳过"路径）——**禁止**以任何形式恢复"空串 / 忽略 pin"的快捷方式；
/// 3. 保持 F-22 职责分离现状不变：TLS 层全放行 + 上层 Ed25519 强制 pin 校验。
///
/// 违反门禁的接线 = 回归 F-22 全放行风险。
pub mod quic;
pub mod reassembly;
pub mod stream;
pub mod tcp_fallback;
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
pub use tcp_fallback::TcpMediaTransport;
pub use transport::{
    accept_media_transport, accept_quic_transport, bind_dual_stack_tcp_listener,
    connect_media_transport, connect_quic_transport, connect_quic_transport_on,
    QuicMediaTransport, SecureChannelReceiver, SecureChannelSender, SecureChannelTransport,
};
// M8-T026-P1: 打洞桥导出（PATH-004 升舱 + 打洞 socket 媒体传输）
pub use punch_bridge::{
    accept_punch_transport, connect_punch_transport, punch_upgrade_accept_task,
    punch_upgrade_connect_task, PunchMediaCreds, PunchUpgrade, PunchUpgradeEvent,
};

use crate::encoder::types::EncodedPacket;
use crate::proto::EncodedWindow;
use async_trait::async_trait;
use std::sync::mpsc;

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

/// 传输模式（P5 会话层按模式分支自适应与 UI 显示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// QUIC（主路径，DATAGRAM + 可靠流）。
    Quic,
    /// TCP（SecureChannel 优雅降级路径，M8-T025 P4）。
    Tcp,
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

    /// R-04：发送一批音频包（`PacketKind::Audio`，Opus 帧）。
    ///
    /// 实现者：
    /// - QUIC：音频走独立 DATAGRAM（中优先级，可丢，单包 ≤
    ///   [`MAX_PACKET_PAYLOAD`]），DATAGRAM 头带 kind 字节区分视频。
    /// - TCP：`ChannelTag::Audio` 前缀（与 SecureChannel 阶段既有字节流兼容）。
    ///
    /// 默认实现返回"不支持"（外部/桩实现零改动）。
    async fn send_audio(&mut self, pkts: &[EncodedPacket]) -> Result<(), TransportError> {
        let _ = pkts;
        Err(TransportError::InvalidFrame(
            "audio send not supported by this transport".into(),
        ))
    }

    /// R-04：拆出音频包接收端（媒体接收循环内部按 type 分流——`recv_frame`
    /// 遇到音频包转入本通道，返回视频帧）。
    ///
    /// - 返回 `Some(rx)`：音频**接收已启用**——接收循环把音频包缓冲进通道
    ///   （会话把它交给 `AudioDecodePipeline`）。
    /// - 返回 `None`：未启用（音频开关关闭）——接收循环**丢弃**音频包，
    ///   不缓冲（避免无消费者时通道无界增长）。
    ///
    /// 同一传输只可调用一次（再次调用返回 `None`）；传输被 drop 时通道关闭，
    /// 消费端 `recv` 返回错误 → 音频线程干净退出。
    fn take_audio_receiver(&mut self) -> Option<mpsc::Receiver<crate::decoder::AudioPacket>> {
        None
    }

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

    /// 当前传输模式。默认 Quic（既有实现零改动；`TcpMediaTransport` 覆写为 Tcp）。
    fn mode(&self) -> TransportMode {
        TransportMode::Quic
    }

    /// 类型擦除下转（P5 会话层按 `mode()` 下转具体实现，取 QUIC 专属能力：
    /// 控制流拆分 / cipher / 连接统计）。默认 `None`；两个实现均覆写为 `Some(self)`。
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        None
    }
}
