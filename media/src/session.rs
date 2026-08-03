//! 端到端媒体会话（M8-T009 集成层 + M8-T025 P5 传输抽象化/降级接线）。
//!
//! 把已有组件串成完整闭环，**传输层对会话透明**（P5 契约）：
//!
//! ```text
//! 服务端: capture → WindowPipeline → MediaTransport(QUIC DATAGRAM / TCP) → 客户端
//!         ↑                                    │ FeedbackReport
//!         └── AdaptiveEngine ←─ 控制流 ─────────┘ (可靠流 / 控制 tag)
//!
//! 客户端: MediaTransport(DATAGRAM 重组 / TCP) → VideoDecoderPipeline → on_frame 回调
//!         │ FeedbackReport (ReportGenerator + LossDetector)
//!         └──→ 控制流 → 服务端 AdaptiveEngine
//! ```
//!
//! - 媒体走 QUIC DATAGRAM（14B 头 + AEAD 加密，分片重组，允许丢包）或 TCP
//!   （SecureChannel，tag 分派，无丢包）
//! - 控制走 QUIC 可靠流 / TCP Control tag（VideoFormat / FeedbackReport / Disconnect）
//! - 自适应：按 [`TransportMode`] 分支——QUIC 完整闭环（编码超时保护 + 状态机 +
//!   恢复策略）；TCP 固定默认档（M8-T025 §3.5，避免基于伪数据的错误降级）
//! - M8-T025 P5-3 中途降级：QUIC 失效（`is_alive` 轮询 / 连接级错误）→ 客户端
//!   以同一凭据重拨 TCP（`connect_media_transport`），服务端降级接收任务持续
//!   accept + 完整握手 → 传输热替换（`Box<dyn MediaTransport>` swap）+ 强制 IDR，
//!   会话不中断、帧计数不归零；不自动升级回 QUIC（B3）
//!
//! UI 层只需：
//! - 服务端：`QuicEndpoint::bind` + `accept_media_transport` + `run_server_session`
//! - 客户端：`connect_media_transport` + `run_client_session`

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake as core_handshake;
use kirin_desk_core::crypto::handshake::PinExpectation;

use crate::adaptive::{AdaptiveEngine, FeedbackReport, ReportGenerator};
use crate::capture::{CaptureError, ScreenCaptureSource};
use crate::decoder::factory::create_video_decoder;
use crate::decoder::{frame_id_to_pts, DecoderPacket};
use crate::encoder::types::Codec;
use crate::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use crate::encoder::VideoEncoderPipeline;
use crate::proto::{EncodeConfig, EncodedWindow, RawFrame, WindowConfig};
use crate::transport::{
    control, punch_upgrade_accept_task, punch_upgrade_connect_task, ChannelTag, ControlMessage,
    MediaCipher, MediaTransport, PunchUpgrade, QuicMediaTransport, SecureChannelReceiver,
    SecureChannelSender, TcpMediaTransport, TransportError, TransportMode, MAX_PACKET_PAYLOAD,
};
use crate::window_pipeline::WindowPipeline;

// ════════════════════════════════════════════════════════════════
// 会话配置与统计
// ════════════════════════════════════════════════════════════════

/// PTS 线性近似用的目标帧率（P2A §T1.1 方案 A；SessionConfig 暂无 fps 字段，
/// 客户端单帧率场景取 60 足够；P2G 基准若 lip-sync 不达标再升级方案 B）。
const TARGET_FPS: u32 = 60;

/// P5-3：触发降级后服务端等待 TCP 热替换的最长时间（客户端重连超时 + 余量；
/// 超时未注入 → 会话以错误结束）。
const SERVER_DEGRADE_WAIT_TIMEOUT: Duration = Duration::from_secs(20);

/// R-04：会话级音频配置（M8-T008-P1D / M12 参数）。
///
/// 服务端据此创建音频捕获+编码流水线（`AudioPipeline`），客户端据此创建
/// 解码+播放流水线（`AudioDecodePipeline`）。无音频设备/初始化失败 → info
/// 降级（视频/键鼠不断），不阻断建连。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioConfig {
    /// 是否启用音频（默认开；`--no-audio` / Settings 开关置 false）。
    pub enabled: bool,
    /// 采样率（48000，M12）。
    pub sample_rate: u32,
    /// 声道数（2，stereo，M12）。
    pub channels: u16,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_rate: crate::encoder::audio::SAMPLE_RATE,
            channels: crate::encoder::audio::CHANNELS,
        }
    }
}

/// 媒体会话配置。
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// 窗口配置（70ms / 最大帧数 / 空闲超时）
    pub window: WindowConfig,
    /// 初始编码配置
    pub encode: EncodeConfig,
    /// 客户端反馈上报周期（毫秒，默认 100）
    pub feedback_interval_ms: u64,
    /// M8-T025 P5-3：中途降级开关（true = QUIC 失效自动 TCP 重建续传；
    /// false = 直接断连，现状行为）。仅当会话附带了降级参数时生效。
    pub graceful_degrade: bool,
    /// M8-T025 §3.5：TCP 模式反馈上报周期（毫秒，默认 500——可靠传输无丢包
    /// 语义，放宽周期减少无意义流量）。
    pub tcp_feedback_interval_ms: u64,
    /// R-04：音频开关与参数（默认开；`--no-audio` / Settings 置 `enabled=false`）。
    pub audio: AudioConfig,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            window: WindowConfig::default(),
            encode: EncodeConfig::default(),
            feedback_interval_ms: 100,
            graceful_degrade: true,
            tcp_feedback_interval_ms: 500,
            audio: AudioConfig::default(),
        }
    }
}

/// 服务端会话统计（自适应闭环状态，UI 诊断用）。
#[derive(Debug, Clone, Default)]
pub struct ServerSessionStats {
    /// 已编码窗口数
    pub windows_encoded: u64,
    /// 静默窗口数（无变化）
    pub silent_windows: u64,
    /// 编码总帧数
    pub frames_encoded: u64,
    /// 上次编码耗时（毫秒）
    pub last_encode_ms: f64,
    /// 当前 QP
    pub active_qp: u32,
    /// 当前帧保留比例
    pub active_frame_ratio: f64,
    /// 最近 RTT（毫秒）
    pub last_rtt_ms: u64,
    /// 客户端反馈丢包率（0.0~1.0）
    pub last_loss_rate: f64,
    /// 客户端反馈接收带宽（bps）
    pub last_bandwidth_bps: u64,
    /// 当前网络状态
    pub network_state: String,
    /// 恢复阶段
    pub recovery_phase: String,
    /// 收到的反馈报告数
    pub feedback_reports: u64,
    /// M8-T025 P5-1：当前传输模式（"QUIC"/"TCP"）
    pub transport_mode: String,
    /// M8-T025 P5-3：传输切换事件计数（QUIC → TCP 降级次数）
    pub transport_switches: u64,
    /// R-04：音频是否启用并成功启动（无设备/初始化失败 → false，会话照常）。
    pub audio_enabled: bool,
    /// R-04：已发送的音频包数（Opus 帧）。
    pub audio_packets_sent: u64,
}

/// 客户端会话统计。
#[derive(Debug, Clone, Default)]
pub struct ClientSessionStats {
    /// 接收并解码的帧数
    pub frames_decoded: u64,
    /// 丢弃帧数（解码失败 / 窗口不完整）
    pub frames_dropped: u64,
    /// 当前丢包率（0.0~1.0）
    pub loss_rate: f64,
    /// 最近 RTT（毫秒）
    pub rtt_ms: u64,
    /// 接收带宽（bps）
    pub bandwidth_bps: u64,
    /// 平均解码耗时（毫秒）
    pub avg_decode_ms: f64,
    /// 最近解码的分辨率
    pub video_w: u32,
    pub video_h: u32,
    /// 发送的反馈报告数
    pub feedback_sent: u64,
    /// M8-T025 P5-1：当前传输模式（"QUIC"/"TCP"）
    pub transport_mode: String,
    /// M8-T025 P5-3：传输切换事件计数（QUIC → TCP 降级次数）
    pub transport_switches: u64,
    /// R-04：音频是否启用并成功启动（无解码器/播放设备 → false，会话照常）。
    pub audio_enabled: bool,
    /// R-04：jitter 静音补帧数（抖动间隙补齐，日志/诊断用）。
    pub audio_silence_inserted: u64,
    /// R-04：jitter 丢弃包数（迟到/重复/溢出，日志/诊断用）。
    pub audio_packets_dropped: u64,
}

// ════════════════════════════════════════════════════════════════
// R-03 (R03-S3)：断线重连后的会话续接
// ════════════════════════════════════════════════════════════════

/// R-03 (R03-S3)：断线重连成功后的会话续接参数。
///
/// 上层（UI/CLI）在重连成功、新传输就绪后调用 [`apply_session_resume`]，
/// 通知媒体会话立即恢复画面：
/// - 服务端：下一窗口强制 IDR（`force_idr`，与 P5-3 传输热替换同机制）；
/// - 客户端：收到 IDR 即 `decoder.flush()` 重同步（既有逻辑，无需动作）。
///
/// GUI M9 路径的重连以**全新会话**续接（首窗口天然 IDR，`windows_encoded == 0`），
/// 本入口面向媒体会话（P5-3 热替换）路径在传输重建后的显式续接；两路径均
/// 满足"断线恢复后画面 2s 内续上"。与 R-04（音频接线）按函数级分块，互不触碰。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionResume {
    /// 是否请求服务端立即发送 IDR（默认 true）。
    pub request_idr: bool,
}

impl Default for SessionResume {
    fn default() -> Self {
        Self { request_idr: true }
    }
}

impl SessionResume {
    /// 续接并请求 IDR（推荐默认）。
    pub fn with_idr() -> Self {
        Self::default()
    }
}

/// 应用续接信号：置位服务端共享 `force_idr` 标记（P5-3 同机制——下一窗口
/// 强制关键帧，客户端 `decoder.flush()` 后即重同步，画面快速恢复）。
pub fn apply_session_resume(resume: SessionResume, force_idr: &AtomicBool) {
    if resume.request_idr {
        force_idr.store(true, Ordering::Relaxed);
    }
    info!(
        "[Session] resume signal applied (request_idr={})",
        resume.request_idr
    );
}

// ════════════════════════════════════════════════════════════════
// 控制收发源（P5：QUIC 拆出的控制流 / TCP 拆出的半通道）
// ════════════════════════════════════════════════════════════════

/// 控制**接收**源：QUIC = 拆出的控制可靠流（cipher 解密）；TCP = 读半通道
/// （`SecureChannelReceiver` 自解密，Control tag 分派）。服务端控制 task 独占。
enum ControlSource {
    Quic {
        stream: quinn::RecvStream,
        cipher: Arc<MediaCipher>,
    },
    Tcp(SecureChannelReceiver),
}

impl ControlSource {
    async fn recv(&mut self) -> Result<ControlMessage, TransportError> {
        match self {
            ControlSource::Quic { stream, cipher } => {
                control::recv_control_msg(stream, cipher).await
            }
            ControlSource::Tcp(reader) => {
                let (tag, _header, payload) = reader.recv_tagged().await?;
                match tag {
                    ChannelTag::Control => bincode::deserialize(&payload).map_err(|e| {
                        TransportError::SecureChannel(format!("bincode deserialize: {e}"))
                    }),
                    other => Err(TransportError::InvalidFrame(format!(
                        "expected Control tag, got {other:?}"
                    ))),
                }
            }
        }
    }
}

/// 控制**发送**源：QUIC = 拆出的控制可靠流（cipher 加密）；TCP = 写半通道
/// （`SecureChannelSender`，Control tag 分派）。客户端反馈 task 独占。
enum ControlSink {
    Quic {
        stream: quinn::SendStream,
        cipher: Arc<MediaCipher>,
    },
    Tcp(SecureChannelSender),
}

impl ControlSink {
    async fn send(&mut self, msg: &ControlMessage) -> Result<(), TransportError> {
        match self {
            ControlSink::Quic { stream, cipher } => {
                control::send_control_msg(stream, cipher, msg).await
            }
            // 与 TcpMediaTransport::send_control 同 wire 格式（bincode → Control tag）
            ControlSink::Tcp(sender) => {
                let plain = bincode::serialize(msg).map_err(|e| {
                    TransportError::SecureChannel(format!("bincode serialize: {e}"))
                })?;
                let pkt = EncodedPacket {
                    ts: Timestamp::now(),
                    kind: PacketKind::Control,
                    data: plain,
                    is_key: false,
                };
                if pkt.data.len() > MAX_PACKET_PAYLOAD {
                    sender.send_big_packet(&pkt).await
                } else {
                    sender.send_packets(&[pkt]).await
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════
// 降级参数（M8-T025 P5-3）
// ════════════════════════════════════════════════════════════════

/// 服务端降级回退接收：会话期间持续 accept TCP 回退连接（完整握手，凭据与
/// 初始连接一致），成功后经热替换通道注入会话。`None` = 服务端不接收降级。
///
/// `tcp_listener` 建议用 [`crate::transport::bind_dual_stack_tcp_listener`] 创建
/// （同一监听器可先交给 `accept_media_transport` 做初始双监听，再交给会话）。
#[derive(Debug, Clone)]
pub struct ServerDegrade {
    /// TCP 回退监听器（会话期间持续 accept）
    pub tcp_listener: Arc<tokio::net::TcpListener>,
    /// 服务端身份（握手签名）
    pub server_identity: Arc<IdentityManager>,
    /// 服务端设备 ID
    pub server_id: String,
    /// 白名单校验的客户端公钥（base64）
    pub client_pubkey_base64: String,
    /// 期望昵称（可选）
    pub expected_nickname: Option<String>,
    /// 期望挑战码（可选）
    pub expected_challenge: Option<String>,
}

/// 客户端降级重连参数：QUIC 失效后以**同一凭据**重拨 TCP（单向降级，B3）。
#[derive(Debug, Clone)]
pub struct ClientDegrade {
    /// 重连目标地址（P1 `select_connect_addr` 产出）
    pub addr: SocketAddr,
    /// 客户端身份（握手签名）
    pub client_identity: Arc<IdentityManager>,
    /// 客户端设备 ID
    pub client_id: String,
    /// 客户端域名（服务端白名单按此匹配）
    pub client_domain: String,
    /// 客户端设备类型
    pub client_device_type: String,
    /// 服务端设备 ID（握手昵称）
    pub server_id: String,
    /// 服务端公钥 pin（R-02 强类型：known_hosts / DNS TXT 来源 `Exact`，
    /// 无"空串跳过"形态——重连凭据与初次连接一致）。
    pub server_pin: PinExpectation,
    /// 挑战码
    pub challenge: String,
    /// 建连超时（QUIC/TCP 共用，默认 3s）
    pub connect_timeout: Duration,
}

// ════════════════════════════════════════════════════════════════
// 传输槽辅助（P5：Box<dyn MediaTransport> 按 mode 下转取具体能力）
// ════════════════════════════════════════════════════════════════

/// 下转当前传输为 QUIC（仅 QUIC 模式返回 `Some`）。
fn quic_mut(slot: &mut Box<dyn MediaTransport>) -> Option<&mut QuicMediaTransport> {
    slot.as_any_mut()
        .and_then(|a| a.downcast_mut::<QuicMediaTransport>())
}

/// 下转当前传输为 TCP（仅 TCP 模式返回 `Some`）。
fn tcp_mut(slot: &mut Box<dyn MediaTransport>) -> Option<&mut TcpMediaTransport> {
    slot.as_any_mut()
        .and_then(|a| a.downcast_mut::<TcpMediaTransport>())
}

/// 把新注入的传输拆出控制源（服务端：读半 → 控制 task）并重新装箱回槽。
///
/// 仅在 QUIC → TCP 热替换时调用（`new_mode` 恒为 Tcp；Quic 分支仅防御）。
fn split_server_control_source(
    new_transport: Box<dyn MediaTransport>,
) -> Result<(Box<dyn MediaTransport>, ControlSource), String> {
    let mut slot = new_transport;
    match slot.mode() {
        TransportMode::Quic => {
            let q = quic_mut(&mut slot)
                .ok_or_else(|| "server swap: QUIC downcast failed".to_string())?;
            let stream = q
                .take_control_receiver()
                .ok_or_else(|| "server swap: no QUIC control receiver".to_string())?;
            let cipher = q.cipher_handle();
            Ok((slot, ControlSource::Quic { stream, cipher }))
        }
        TransportMode::Tcp => {
            let t =
                tcp_mut(&mut slot).ok_or_else(|| "server swap: TCP downcast failed".to_string())?;
            let reader = t
                .take_receiver()
                .ok_or_else(|| "server swap: no TCP read half".to_string())?;
            Ok((slot, ControlSource::Tcp(reader)))
        }
    }
}

/// 把新注入的传输拆出控制发送源（客户端：写半 → 反馈 task）并重新装箱回槽。
fn split_client_control_sink(
    new_transport: Box<dyn MediaTransport>,
) -> Result<(Box<dyn MediaTransport>, ControlSink), String> {
    let mut slot = new_transport;
    match slot.mode() {
        TransportMode::Quic => {
            let q = quic_mut(&mut slot)
                .ok_or_else(|| "client swap: QUIC downcast failed".to_string())?;
            let stream = q
                .take_control_sender()
                .ok_or_else(|| "client swap: no QUIC control sender".to_string())?;
            let cipher = q.cipher_handle();
            Ok((slot, ControlSink::Quic { stream, cipher }))
        }
        TransportMode::Tcp => {
            let t =
                tcp_mut(&mut slot).ok_or_else(|| "client swap: TCP downcast failed".to_string())?;
            let sender = t
                .take_sender()
                .ok_or_else(|| "client swap: no TCP write half".to_string())?;
            Ok((slot, ControlSink::Tcp(sender)))
        }
    }
}

// ════════════════════════════════════════════════════════════════
// 服务端会话
// ════════════════════════════════════════════════════════════════

/// 捕获+编码任务（阻塞线程）→ 异步发送循环 的输出。
enum ServerOut {
    /// 非空窗口（含编码耗时，供自适应引擎使用）
    Window(EncodedWindow),
    /// 静默窗口（无变化，不发送媒体）
    Silent {
        window_id: u64,
        encode_duration_ms: f64,
    },
    /// R-04：音频捕获+编码任务产出的 Opus 包批次（主循环经 `send_audio` 发送）。
    Audio(Vec<crate::encoder::types::EncodedPacket>),
    /// M8-T018：显示器切换结果（Ok=新分辨率，Err=失败原因 → Nack）。
    MonitorSwitched(Result<(u32, u32), String>),
    /// 致命错误（捕获不可用等 → 会话终止）
    Fatal(String),
}

/// M8-T018：控制任务 → 主循环 的显示器控制响应（经控制流发出）。
enum DisplayResp {
    /// 显示器列表（`DisplayListReq` 的响应负载）。
    List(Vec<crate::proto::DisplayInfo>),
    /// 切换拒绝原因（越界索引 → `DisplaySelectNack`）。
    Nack(String),
}

/// 判断连接级错误（降级触发用）：QUIC 连接错误 / 对端关闭 / 会话级失败。
/// 不包括 `Timeout`——QUIC 静默窗口期间正常返回 `Timeout`（媒体暂停 ≠ 连接
/// 失效；连接失效由 `is_alive` 轮询 + idle 超时（10s）判定，见 P5-3）。
fn is_connection_error(e: &TransportError) -> bool {
    matches!(
        e,
        TransportError::Quic(_)
            | TransportError::ConnectionClosed { .. }
            | TransportError::Handshake(_)
            | TransportError::InvalidFrame(_)
    )
}

/// 运行服务端媒体会话：捕获 → 窗口编码 → 发送（QUIC DATAGRAM / TCP）+
/// 反馈自适应闭环。传输以 `Box<dyn MediaTransport>` 注入（P5 契约），
/// 会话内部按 [`TransportMode`] 分支；QUIC 失效且配置了
/// [`ServerDegrade`] 时支持 TCP 热替换续传（P5-3）。
///
/// 内部并发结构：
/// - 捕获+编码 task（`spawn_blocking`）：屏幕捕获与 FFmpeg 编码均为**阻塞调用**，
///   必须离开 tokio worker 线程——否则 worker 被占死后 quinn 连接驱动任务被
///   饿死，服务器停止 ACK/发送，整个 QUIC 连接静默冻结（端到端回归
///   `quic_loopback` 曾以「客户端解码 0 帧」暴露此问题）。编码窗口经 mpsc
///   通道送达异步主循环。
/// - 主循环（异步）：接收编码窗口 → `send_window` + 自适应统计；持有
///   `Box<dyn MediaTransport>` 槽，热替换时 swap。
/// - 控制 task：`recv_control`（FeedbackReport）→ `AdaptiveEngine::on_feedback`
///   → 更新共享编码配置（恢复策略 / 状态机 / 编码超时保护均在此闭环内生效）。
/// - 降级接收 task（可选）：持续 accept TCP 回退连接 + 完整握手 → 注入热替换。
///
/// `stop` 置 true 后会话在下个窗口边界退出。
pub async fn run_server_session(
    mut slot: Box<dyn MediaTransport>,
    capture: Box<dyn ScreenCaptureSource>,
    encoder: VideoEncoderPipeline,
    config: SessionConfig,
    degrade: Option<ServerDegrade>,
    // M8-T026-P1 (PATH-004): 打洞升舱源（中继 → 打洞 QUIC 热替换）。
    punch_upgrade: Option<PunchUpgrade>,
    stop: Arc<AtomicBool>,
) -> Result<ServerSessionStats, String> {
    let (w, h) = capture.resolution();
    info!("server session: capture {}x{}", w, h);

    // P5-1：按模式拆控制接收源（QUIC = 控制流 + cipher；TCP = 读半）。
    let mut mode = slot.mode();
    let control_source = match mode {
        TransportMode::Quic => {
            let q = quic_mut(&mut slot)
                .ok_or_else(|| "server session: QUIC transport downcast failed".to_string())?;
            let stream = q
                .take_control_receiver()
                .ok_or_else(|| "server session: no QUIC control receiver".to_string())?;
            let cipher = q.cipher_handle();
            ControlSource::Quic { stream, cipher }
        }
        TransportMode::Tcp => {
            let t = tcp_mut(&mut slot)
                .ok_or_else(|| "server session: TCP transport downcast failed".to_string())?;
            let reader = t
                .take_receiver()
                .ok_or_else(|| "server session: no TCP read half".to_string())?;
            ControlSource::Tcp(reader)
        }
    };
    info!("server session: transport mode = {mode:?}");

    // 推送分辨率（客户端解码 DATAGRAM/控制流重组帧需要；wire 帧头不携带宽高）
    slot.send_control(&ControlMessage::VideoFormat {
        width: w,
        height: h,
    })
    .await
    .map_err(|e| format!("send VideoFormat: {e}"))?;

    // P5-1：自适应按模式分支（TCP = 固定默认档，跳过状态机/恢复）。
    let engine = Arc::new(Mutex::new(AdaptiveEngine::new_with_mode(w, h, mode)));
    let shared_config = Arc::new(Mutex::new(config.encode.clone()));
    let stats = Arc::new(Mutex::new(ServerSessionStats::default()));
    // P5-3：热替换后强制下一窗口 IDR（捕获 task 消费）。
    let force_idr = Arc::new(AtomicBool::new(false));

    // ── M8-T018: 显示器控制通道 ─────────────────────────────────
    // 控制任务 → 主循环：显示器列表 / 切换拒绝（主循环持有 transport 发送）。
    let (display_resp_tx, mut display_resp_rx) =
        tokio::sync::mpsc::unbounded_channel::<DisplayResp>();
    // 控制任务 → 捕获任务：待切换的显示器索引（热切换，无需重连）。
    let (switch_tx, mut switch_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();
    // 控制任务 → 主循环：TCP 连接级错误（无降级目标 → 会话结束）。
    let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    // ── 控制接收 task（客户端反馈 → 自适应引擎）──────────────────
    //    读错误：QUIC → 静默退出（降级触发后由主循环在热替换时重启 task）；
    //    TCP → 上报致命（TCP 无降级目标，连接级错误 = 会话结束）。
    spawn_server_control_task(
        control_source,
        Arc::clone(&engine),
        Arc::clone(&shared_config),
        Arc::clone(&stats),
        Arc::clone(&stop),
        display_resp_tx.clone(),
        switch_tx.clone(),
        fatal_tx.clone(),
    );

    // ── 捕获 + 编码 task（阻塞线程）──────────────────────────────
    //
    // capture.wait_for_frame() 与 FFmpeg 编码是阻塞调用。若在异步主循环里
    // 直接调用，会长时间占用 tokio worker 线程（捕获节拍 33ms + 编码耗时
    // 几乎占满一个 worker 且不 yield）→ quinn 连接驱动任务被饿死，连接
    // 静默冻结。因此整体搬到 blocking 线程池，仅把编码结果经通道送回。
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<ServerOut>(4);
    // R-04：音频任务复用同一输出通道（在 out_tx 被捕获任务 move 前克隆）。
    let audio_out_tx = out_tx.clone();
    let pipeline_stop = Arc::clone(&stop);
    let pipeline_config = Arc::clone(&shared_config);
    let force_idr_capture = Arc::clone(&force_idr);
    tokio::task::spawn_blocking(move || {
        let mut pipeline = WindowPipeline::new(config.window.clone(), encoder);
        pipeline.update_encode_config(config.encode.clone());
        let mut capture = capture;
        let mut windows_encoded: u64 = 0;
        // M8-T018（SRV-CAP-MON-003）与 P5-3：显示器切换 / 传输热替换后，
        // 下一窗口强制 IDR（主循环置位，本线程消费）。
        let mut force_idr_next = false;

        loop {
            if pipeline_stop.load(Ordering::Relaxed) {
                info!("server session: stopping by user request");
                break;
            }

            // M8-T018（SRV-CAP-MON-002）：显示器切换命令 —— 会话内热切换
            // （重建捕获源，无需重连）。阻塞捕获源重建放本线程执行。
            if let Ok(idx) = switch_rx.try_recv() {
                match capture.switch_monitor(idx as usize) {
                    Ok(()) => {
                        let (sw, sh) = capture.resolution();
                        info!(
                            "[Session] capture switched to monitor {idx} ({}x{})",
                            sw, sh
                        );
                        force_idr_next = true; // 下一窗口 IDR，无需客户端等花屏
                                               // 主循环：推送新 VideoFormat（分辨率变更 → 客户端重建解码上下文）
                        let _ = out_tx.blocking_send(ServerOut::MonitorSwitched(Ok((sw, sh))));
                    }
                    Err(e) => {
                        warn!("[Session] switch monitor {idx} failed: {e} — keeping current");
                        let _ = out_tx.blocking_send(ServerOut::MonitorSwitched(Err(format!(
                            "switch monitor {idx} failed: {e}"
                        ))));
                    }
                }
            }

            // 应用最新自适应配置（异步主循环可能已更新）
            {
                let shared = pipeline_config.lock().unwrap();
                let cur = pipeline.encode_config().clone();
                if shared.qp != cur.qp
                    || (shared.frame_ratio - cur.frame_ratio).abs() > 1e-9
                    || shared.preset != cur.preset
                {
                    pipeline.update_encode_config(shared.clone());
                    debug!(
                        "[Session] apply config: QP={}, ratio={:.3}",
                        shared.qp, shared.frame_ratio
                    );
                }
            }

            // M8-T018（MON-NF-002）：带超时等待——静默屏幕（无帧到达）时
            // 定期醒来轮询切换命令，切换延迟与屏幕活动度解耦（目标 <500ms）。
            let frame = match capture.wait_for_frame_timeout(Duration::from_millis(100)) {
                Ok(f) => f,
                Err(CaptureError::Timeout) => continue,
                Err(e) => {
                    // 捕获失败：AccessLost 重建，其它重试（与 UI 旧循环语义一致）
                    match &e {
                        CaptureError::AccessLost => {
                            warn!("[Session] capture access lost — recreating");
                            if capture.recreate().is_err() {
                                let _ = out_tx.blocking_send(ServerOut::Fatal(format!(
                                    "capture recreate failed"
                                )));
                                break;
                            }
                            continue;
                        }
                        CaptureError::NoMonitor | CaptureError::InvalidMonitor => {
                            let _ = out_tx.blocking_send(ServerOut::Fatal(format!(
                                "capture unavailable: {e}"
                            )));
                            break;
                        }
                        _ => {
                            warn!("[Session] capture error: {e} — retrying");
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                    }
                }
            };

            let raw = RawFrame {
                data: Arc::new(frame.data().to_vec()),
                width: frame.width(),
                height: frame.height(),
                timestamp: std::time::SystemTime::now(),
                dirty_rects: frame.dirty_rects().to_vec(),
                // 首帧 / 显示器切换后 / 传输热替换后 → 强制 IDR（下一帧可解码，
                // 无花屏等待）。
                force_key: windows_encoded == 0
                    || force_idr_next
                    || force_idr_capture.swap(false, Ordering::Relaxed),
            };
            force_idr_next = false;

            match pipeline.push_frame(raw) {
                Ok(Some(window)) => {
                    windows_encoded = window.window_id;
                    let is_empty = window.is_empty();
                    let msg = if is_empty {
                        ServerOut::Silent {
                            window_id: window.window_id,
                            encode_duration_ms: window.encode_duration_ms,
                        }
                    } else {
                        ServerOut::Window(window)
                    };
                    if out_tx.blocking_send(msg).is_err() {
                        // 异步主循环已退出（连接关闭）→ 结束捕获
                        break;
                    }
                }
                Ok(None) => { /* 窗口仍在收集帧 */ }
                Err(e) => {
                    warn!("[Session] window pipeline error: {e} — retrying");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    });

    // ── R-04：音频捕获 + 编码 task（阻塞线程，可选）───────────────
    // 独立于视频/键鼠（优先级 键鼠 > 音频 > 视频）：创建/启动失败（无环回
    // 设备、libopus 缺失）→ info 降级，视频会话照常。捕获线程经 `next_packets`
    // 非阻塞消费 → 批次经 `ServerOut::Audio` 送达主循环发送（发送失败只记
    // 日志，音频故障不中断视频）。
    if config.audio.enabled {
        let audio_out_tx = audio_out_tx.clone();
        let audio_stop = Arc::clone(&stop);
        tokio::task::spawn_blocking(move || {
            // 创建（WASAPI 环回 + libopus）与启动（捕获线程）均可能失败——
            // 任一失败即放弃音频（视频/键鼠不受影响）。
            let mut pipeline = match crate::encoder::audio::AudioPipeline::new() {
                Ok(p) => p,
                Err(e) => {
                    info!("[Session] audio disabled (pipeline init failed): {e}");
                    return;
                }
            };
            if let Err(e) = pipeline.start() {
                info!("[Session] audio disabled (capture start failed): {e}");
                return;
            }
            info!(
                "[Session] audio pipeline started ({}Hz/{}ch, 20ms opus frames)",
                pipeline.sample_rate(),
                pipeline.channels()
            );
            loop {
                if audio_stop.load(Ordering::Relaxed) {
                    break;
                }
                match pipeline.next_packets() {
                    Ok(pkts) if !pkts.is_empty() => {
                        // 批次发送；通道满（主循环忙）→ 丢新包保视频（音频
                        // 可丢，jitter 静音补帧），不阻塞捕获线程。
                        if audio_out_tx.try_send(ServerOut::Audio(pkts)).is_err() {
                            debug!("[Session] audio batch dropped (main loop busy)");
                        }
                    }
                    Ok(_) => {
                        // 无新 PCM：非阻塞轮询节拍（20ms 帧 → 5ms 粒度足够）。
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => {
                        warn!("[Session] audio pipeline error: {e} — stopping audio");
                        break;
                    }
                }
            }
            // 会话结束：AudioPipeline drop → 捕获线程停止、编码器释放。
            info!("[Session] audio pipeline stopped");
        });
    }

    // ── P5-3 降级回退 accept task（可选）─────────────────────────
    // 会话期间持续监听 TCP：收到连接 → 完整握手（凭据同初始连接）→ 注入热替换。
    // 注意：主循环只消费热替换（`swap_rx`），发送端由 accept task 独占持有。
    // M8-T026-P1 (PATH-004)：有降级**或**打洞升舱源时创建热替换通道；
    // 打洞升舱任务与降级 accept 任务并存（各自独立消费事件/连接）。
    let (_swap_tx, mut swap_rx) = if degrade.is_some() || punch_upgrade.is_some() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Box<dyn MediaTransport>>();
        if let Some(d) = &degrade {
            let d_owned = d.clone();
            let tx_task = tx.clone();
            let stop_task = Arc::clone(&stop);
            tokio::spawn(async move {
                server_fallback_accept_task(d_owned, tx_task, stop_task).await;
            });
        }
        if let Some(up) = punch_upgrade {
            let tx_task = tx.clone();
            let stop_task = Arc::clone(&stop);
            tokio::spawn(async move {
                punch_upgrade_accept_task(up, tx_task, stop_task).await;
            });
        }
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    // 降级可用：配置开关 + 会话附带降级参数（mode 在循环内逐次判定）。
    let degrade_enabled = config.graceful_degrade && swap_rx.is_some() && degrade.is_some();

    // ── 异步主循环：窗口接收 → 自适应统计 → 发送 / 热替换 ────────
    //    M8-T018：与显示器控制响应（列表/切换拒绝）并行——控制任务发来的
    //    响应统一经本循环经 transport.send_control 发回客户端。
    let mut windows_encoded: u64 = 0;
    let mut frames_encoded: u64 = 0;
    let mut silent_windows: u64 = 0;
    let mut last_encode_ms: f64 = 0.0;
    let mut transport_switches: u64 = 0;
    // R-04：已发送音频包数（Opus 帧，统计快照用）。
    let mut audio_packets_sent: u64 = 0;
    // P5-3：降级等待中（停止媒体发送，编码/捕获管线保留；等热替换或超时）。
    let mut degrading = false;
    let mut degrade_deadline: Option<Instant> = None;

    loop {
        // P5-3 触发检测：QUIC 存活轮询（每帧返回节奏驱动，~33ms 级）
        if mode == TransportMode::Quic && degrade_enabled && !slot.is_alive() && !degrading {
            warn!(
                "[Session] QUIC connection dead (is_alive=false, reason: {}) — degrading to TCP",
                quic_mut(&mut slot)
                    .map(|q| q.conn().close_reason_str())
                    .unwrap_or_default()
            );
            degrading = true;
            degrade_deadline = Some(Instant::now() + SERVER_DEGRADE_WAIT_TIMEOUT);
        }

        // P5-3：降级等待分支——不发媒体，只等热替换或超时。
        if degrading {
            let timed_out = degrade_deadline
                .map(|d| Instant::now() >= d)
                .unwrap_or(false);
            if timed_out {
                warn!("server session: degrade wait timed out — ending session");
                break;
            }
            let swap_recv = async {
                match swap_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                new = swap_recv => {
                    match new {
                        Some(t) => {
                            if apply_server_swap(
                                t,
                                &mut slot,
                                &mut mode,
                                &mut transport_switches,
                                &force_idr,
                                &engine,
                                &shared_config,
                                &stats,
                                &stop,
                                &display_resp_tx,
                                &switch_tx,
                                &fatal_tx,
                            )
                            .is_err()
                            {
                                warn!("server session: degrade swap failed — ending session");
                                break;
                            }
                            // R-03 缺陷修复（ZM-05 回归暴露）：swap 应用后必须
                            // 复位 degrading——否则服务端永久停在降级等待分支，
                            // 不再发送媒体（与客户端侧同缺陷，见 apply 调用处）。
                            degrading = false;
                        }
                        None => break, // 调用方不再注入（会话结束）
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            continue;
        }

        tokio::select! {
            out = out_rx.recv() => {
                let Some(out) = out else { break };
                if stop.load(Ordering::Relaxed) {
                    info!("server session: stopping by user request");
                    break;
                }

                let mut new_config: Option<EncodeConfig> = None;
                match out {
                    ServerOut::Window(window) => {
                        windows_encoded = window.window_id;
                        frames_encoded += window.frame_count as u64;
                        last_encode_ms = window.encode_duration_ms;
                        {
                            // 编码耗时 → 超时保护（锁内计算，不跨 await）
                            let mut engine_guard = engine.lock().unwrap();
                            engine_guard.on_active_window();
                            new_config = engine_guard.on_encode_complete(window.encode_duration_ms);
                        }

                        debug!("[Session] send_window enter id={}", window.window_id);
                        match slot.send_window(&window).await {
                            Ok(()) => {}
                            Err(e) => {
                                // P5-3：QUIC 连接级发送错误 → 触发降级；否则报错
                                if mode == TransportMode::Quic
                                    && degrade_enabled
                                    && is_connection_error(&e)
                                {
                                    warn!("[Session] send_window failed ({e}) — degrading to TCP");
                                    degrading = true;
                                    degrade_deadline = Some(
                                        Instant::now() + SERVER_DEGRADE_WAIT_TIMEOUT,
                                    );
                                } else {
                                    return Err(format!(
                                        "send_window {}: {e}",
                                        window.window_id
                                    ));
                                }
                            }
                        }
                        debug!("[Session] send_window exit id={}", window.window_id);
                    }
                    ServerOut::Silent {
                        window_id,
                        encode_duration_ms,
                    } => {
                        windows_encoded = window_id;
                        silent_windows += 1;
                        last_encode_ms = encode_duration_ms;
                        {
                            let mut engine_guard = engine.lock().unwrap();
                            engine_guard.on_silent_window();
                            new_config = engine_guard.on_encode_complete(encode_duration_ms);
                        }
                    }
                    ServerOut::Fatal(reason) => {
                        warn!("[Session] capture/pipeline fatal: {reason}");
                        break;
                    }
                    ServerOut::Audio(pkts) => {
                        // R-04：音频批次发送。失败只记日志（音频故障不中断
                        // 视频；QUIC 连接级错误仍由视频路径驱动降级）。
                        match slot.send_audio(&pkts).await {
                            Ok(()) => {
                                audio_packets_sent += pkts.len() as u64;
                            }
                            Err(e) => {
                                warn!("[Session] send audio batch failed: {e} — audio degraded");
                            }
                        }
                    }
                    ServerOut::MonitorSwitched(result) => {
                        // M8-T018（SRV-CAP-MON-003）：切换成功 → 重推 VideoFormat
                        // （分辨率变更 → 客户端解码上下文重建 + 坐标基数跟随）；
                        // 失败 → DisplaySelectNack（客户端提示并保持当前屏）。
                        match result {
                            Ok((sw, sh)) => {
                                info!("[Session] monitor switched → VideoFormat {}x{}", sw, sh);
                                if let Err(e) = slot
                                    .send_control(&ControlMessage::VideoFormat {
                                        width: sw,
                                        height: sh,
                                    })
                                    .await
                                {
                                    warn!("[Session] send VideoFormat after switch: {e}");
                                }
                            }
                            Err(reason) => {
                                warn!("[Session] monitor switch rejected: {reason}");
                                if let Err(e) = slot
                                    .send_control(&ControlMessage::DisplaySelectNack { reason })
                                    .await
                                {
                                    warn!("[Session] send DisplaySelectNack: {e}");
                                }
                            }
                        }
                    }
                }

                // QUIC 统计（RTT / cwnd）→ 状态机 + 恢复条件 C（TCP 模式跳过：§3.5）
                if mode == TransportMode::Quic {
                    let rtt = slot.rtt();
                    let cwnd = quic_mut(&mut slot)
                        .map(|q| q.conn().congestion_window())
                        .unwrap_or(0);
                    {
                        let mut eng = engine.lock().unwrap();
                        if let Some(cfg) = eng.on_quic_stats(rtt as f64, cwnd) {
                            new_config = Some(cfg);
                        }
                        {
                            let mut st = stats.lock().unwrap();
                            st.network_state = format!("{:?}", eng.network_state());
                            st.recovery_phase = format!("{:?}", eng.recovery_phase());
                            st.last_rtt_ms = rtt;
                        }
                    }
                    // 诊断：每 10 个窗口打印一次 QUIC 收发统计
                    if windows_encoded % 10 == 0 {
                        if let Some(q) = quic_mut(&mut slot) {
                            let (tx_dg, tx_b, rx_dg, rx_b) = q.conn().udp_stats();
                            debug!(
                                "[Session] diag window={} udp tx={} dg/{}B rx={} dg/{}B cwnd={}",
                                windows_encoded, tx_dg, tx_b, rx_dg, rx_b, cwnd
                            );
                        }
                    }
                }
                if let Some(cfg) = new_config {
                    let mut shared = shared_config.lock().unwrap();
                    shared.qp = cfg.qp;
                    shared.frame_ratio = cfg.frame_ratio;
                    shared.preset = cfg.preset.clone();
                }
            }
            resp = display_resp_rx.recv() => {
                // M8-T018：控制任务 → 主循环 的显示器响应（列表 / 切换拒绝）。
                let Some(resp) = resp else { continue };
                if stop.load(Ordering::Relaxed) {
                    info!("server session: stopping by user request");
                    break;
                }
                let msg = match resp {
                    DisplayResp::List(displays) => {
                        ControlMessage::DisplayListResp { displays }
                    }
                    DisplayResp::Nack(reason) => {
                        ControlMessage::DisplaySelectNack { reason }
                    }
                };
                if let Err(e) = slot.send_control(&msg).await {
                    warn!("[Session] send display control response: {e}");
                }
            }
            fatal = fatal_rx.recv() => {
                // None 不会发生：本函数作用域持有的 fatal_tx 使通道常开
                if let Some(reason) = fatal {
                    warn!("[Session] fatal control channel error: {reason}");
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                if stop.load(Ordering::Relaxed) {
                    info!("server session: stopping by user request");
                    break;
                }
            }
        }
    }

    // 收尾：QUIC 关闭连接（TCP 直接 drop）
    if mode == TransportMode::Quic {
        if let Some(q) = quic_mut(&mut slot) {
            let udp = q.conn().udp_stats();
            info!(
                "server session ended: udp tx={} dg/{} B, rx={} dg/{} B",
                udp.0, udp.1, udp.2, udp.3
            );
            q.conn().close("server session end");
        }
    }
    let _ = slot.close().await;

    // 合并统计
    let mut st = stats.lock().unwrap();
    st.windows_encoded = windows_encoded;
    st.silent_windows = silent_windows;
    st.frames_encoded = frames_encoded;
    st.last_encode_ms = last_encode_ms;
    st.active_qp = shared_config.lock().unwrap().qp;
    st.active_frame_ratio = shared_config.lock().unwrap().frame_ratio;
    st.transport_mode = match mode {
        TransportMode::Quic => "QUIC".to_string(),
        TransportMode::Tcp => "TCP".to_string(),
    };
    st.transport_switches = transport_switches;
    // R-04：音频统计（enabled 为配置意图；实际启动结果见会话日志的
    // "audio disabled" / "audio pipeline started" 行）。
    st.audio_enabled = config.audio.enabled;
    st.audio_packets_sent = audio_packets_sent;
    Ok(st.clone())
}

/// 服务端热替换：注入的新传输接管发送槽 + 重启控制 task + 强制 IDR。
///
/// 仅在 QUIC → TCP 降级时调用；失败（下转异常）返回 Err，由调用方结束会话。
#[allow(clippy::too_many_arguments)]
fn apply_server_swap(
    new_transport: Box<dyn MediaTransport>,
    slot: &mut Box<dyn MediaTransport>,
    mode: &mut TransportMode,
    transport_switches: &mut u64,
    force_idr: &Arc<AtomicBool>,
    engine: &Arc<Mutex<AdaptiveEngine>>,
    shared_config: &Arc<Mutex<EncodeConfig>>,
    stats: &Arc<Mutex<ServerSessionStats>>,
    stop: &Arc<AtomicBool>,
    display_resp_tx: &tokio::sync::mpsc::UnboundedSender<DisplayResp>,
    switch_tx: &tokio::sync::mpsc::UnboundedSender<u32>,
    fatal_tx: &tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<(), String> {
    let (new_slot, new_source) = split_server_control_source(new_transport)?;
    // 关闭旧 QUIC（通知对端；TCP 槽直接 drop）
    if let Some(q) = quic_mut(slot) {
        q.conn().close("degrade to TCP");
    }
    *slot = new_slot;
    *mode = slot.mode();
    *transport_switches += 1;
    // R-03 (R03-S3)：续接信号——强制下一窗口 IDR（P5-3 同机制）。
    apply_session_resume(SessionResume::with_idr(), force_idr);
    spawn_server_control_task(
        new_source,
        Arc::clone(engine),
        Arc::clone(shared_config),
        Arc::clone(stats),
        Arc::clone(stop),
        display_resp_tx.clone(),
        switch_tx.clone(),
        fatal_tx.clone(),
    );
    info!("[Session] transport switched QUIC → TCP (total {transport_switches}) — IDR forced");
    Ok(())
}

/// 服务端降级接收 task：持续 accept TCP 回退连接 → 完整握手 → 注入热替换通道。
///
/// 握手凭据（昵称/挑战码/白名单）与初始连接一致（主文档 §3.4：不引入新协议字段）。
/// 握手失败（如陌生设备）仅告警并继续 accept——服务端无状态，回退由客户端驱动。
async fn server_fallback_accept_task(
    d: ServerDegrade,
    swap_tx: tokio::sync::mpsc::UnboundedSender<Box<dyn MediaTransport>>,
    stop: Arc<AtomicBool>,
) {
    info!("server fallback accept: listening TCP for degrade reconnect");
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let stream = tokio::select! {
            r = d.tcp_listener.accept() => match r {
                Ok((s, _)) => s,
                Err(e) => {
                    warn!("fallback accept error: {e}");
                    break;
                }
            },
            // 定期醒来检查 stop（会话结束 → 退出）
            _ = tokio::time::sleep(Duration::from_millis(500)) => continue,
        };
        let ch = core_handshake::server_handshake_verified_with_nickname_generic(
            stream,
            &d.server_identity,
            &d.server_id,
            &d.client_pubkey_base64,
            d.expected_nickname.as_deref(),
            d.expected_challenge.as_deref(),
        )
        .await;
        let transport = match ch {
            Ok(ch) => TcpMediaTransport::from_generic(ch),
            Err(e) => {
                warn!("fallback handshake failed: {e} — continuing to listen");
                continue;
            }
        };
        info!("fallback accept: TCP handshake OK — injecting degrade transport");
        if swap_tx.send(Box::new(transport)).is_err() {
            break; // 会话已结束（接收端已 drop）
        }
    }
}

/// 生成服务端控制接收 task（会话启动与热替换后共用）。
///
/// 读错误：QUIC → 静默退出（降级时由主循环在热替换后重启 task）；TCP → 上报
/// 致命（TCP 无降级目标，连接级错误 = 会话结束）。
#[allow(clippy::too_many_arguments)]
fn spawn_server_control_task(
    source: ControlSource,
    engine: Arc<Mutex<AdaptiveEngine>>,
    shared_config: Arc<Mutex<EncodeConfig>>,
    stats: Arc<Mutex<ServerSessionStats>>,
    stop: Arc<AtomicBool>,
    display_resp_tx: tokio::sync::mpsc::UnboundedSender<DisplayResp>,
    switch_tx: tokio::sync::mpsc::UnboundedSender<u32>,
    fatal_tx: tokio::sync::mpsc::UnboundedSender<String>,
) {
    let mut source = source;
    let source_is_tcp = matches!(source, ControlSource::Tcp(_));
    tokio::spawn(async move {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match source.recv().await {
                Ok(ControlMessage::DisplayListReq) => {
                    // M8-T018（SRV-MON-002）：枚举显示器 → 响应。
                    // 每次请求返回最新列表（热插拔后客户端可手动刷新，MON-NF-001）。
                    let displays = crate::capture::factory::enumerate_monitors();
                    info!("[Session] DisplayListReq → {} display(s)", displays.len());
                    let _ = display_resp_tx.send(DisplayResp::List(displays));
                }
                Ok(ControlMessage::DisplaySelect { index }) => {
                    // M8-T018（SRV-MON-003）：越界 → Nack（保持当前屏）；
                    // 合法 → 捕获线程热切换（重建捕获源 + 下一窗口 IDR）。
                    let displays = crate::capture::factory::enumerate_monitors();
                    if index as usize >= displays.len() {
                        warn!(
                            "[Session] DisplaySelect({index}) out of range ({} available) — Nack",
                            displays.len()
                        );
                        let _ = display_resp_tx.send(DisplayResp::Nack(format!(
                            "invalid monitor index {index} ({} display(s) available)",
                            displays.len()
                        )));
                    } else {
                        info!("[Session] DisplaySelect({index}) → switching capture");
                        let _ = switch_tx.send(index);
                    }
                }
                Ok(ControlMessage::FeedbackReport {
                    loss_rate,
                    rtt_ms,
                    received_bitrate,
                    frame_id,
                    missing_frames,
                }) => {
                    let report = FeedbackReport {
                        loss_rate,
                        rtt_ms: rtt_ms as f64,
                        jitter_us: 0.0,
                        bandwidth_bps: received_bitrate,
                        last_frame_id: frame_id,
                        missing_frames,
                        urgent_reduce: loss_rate > 0.1,
                        decode_stats: None,
                    };
                    // ⚠️ 锁顺序与主循环保持一致：engine → stats。
                    // 若此处先锁 stats 再锁 engine，首次反馈到达时与主循环
                    // （engine → stats）构成 ABBA 死锁，整个 QUIC 会话冻结。
                    let new_config = {
                        let mut eng = engine.lock().unwrap();
                        eng.on_feedback(&report)
                    };
                    if let Some(cfg) = new_config {
                        let mut shared = shared_config.lock().unwrap();
                        shared.qp = cfg.qp;
                        shared.frame_ratio = cfg.frame_ratio;
                        shared.preset = cfg.preset.clone();
                        info!(
                            "[Session] adaptive config: QP={}, ratio={:.3}, preset={}",
                            cfg.qp, cfg.frame_ratio, cfg.preset
                        );
                    }
                    {
                        let eng = engine.lock().unwrap();
                        let mut st = stats.lock().unwrap();
                        st.feedback_reports += 1;
                        st.last_loss_rate = loss_rate;
                        st.last_bandwidth_bps = received_bitrate;
                        st.network_state = format!("{:?}", eng.network_state());
                        st.recovery_phase = format!("{:?}", eng.recovery_phase());
                    }
                }
                Ok(ControlMessage::Disconnect { reason }) => {
                    info!("[Session] client disconnect: {}", reason);
                    break;
                }
                Ok(_) => { /* 忽略其它控制消息 */ }
                Err(e) => {
                    if source_is_tcp {
                        let _ = fatal_tx.send(format!("control channel lost: {e}"));
                    }
                    debug!("[Session] control stream closed: {e}");
                    break;
                }
            }
        }
    });
}

// ════════════════════════════════════════════════════════════════
// 客户端会话
// ════════════════════════════════════════════════════════════════

/// 运行客户端媒体会话：接收（QUIC DATAGRAM 重组 / TCP）→ 解码 → 渲染回调 +
/// 反馈上报。传输以 `Box<dyn MediaTransport>` 注入（P5 契约）；QUIC 失效且
/// 配置了 [`ClientDegrade`] 时自动重拨 TCP 并热替换续传（P5-3）。
///
/// 内部并发结构：
/// - 主循环：`recv_frame`（含分片重组 + 丢包检测）→ `VideoDecoderPipeline` → `on_frame(w, h, rgba)`
/// - 反馈 task：每反馈周期上报 `FeedbackReport`（QUIC = 拆出的控制流 + 共享
///   LossDetector；TCP = 写半，无丢包语义）
/// - 重连 task（可选）：QUIC 失效 → `connect_media_transport(addr, Tcp)` →
///   热替换注入主循环
///
/// `on_frame` 在 tokio task 内被调用，**必须尽快返回**（渲染上传由调用方处理）。
pub async fn run_client_session<F>(
    mut slot: Box<dyn MediaTransport>,
    mut on_frame: F,
    config: SessionConfig,
    degrade: Option<ClientDegrade>,
    // M8-T026-P1 (PATH-004): 打洞升舱源（中继 → 打洞 QUIC 热替换）。
    punch_upgrade: Option<PunchUpgrade>,
    stop: Arc<AtomicBool>,
) -> Result<ClientSessionStats, String>
where
    F: FnMut(u32, u32, &[u8]) + Send + 'static,
{
    // P5-1：按模式拆控制发送源（QUIC = 控制流 + cipher；TCP = 写半）。
    let mut mode = slot.mode();
    let control_sink = match mode {
        TransportMode::Quic => {
            let q = quic_mut(&mut slot)
                .ok_or_else(|| "client session: QUIC transport downcast failed".to_string())?;
            let stream = q
                .take_control_sender()
                .ok_or_else(|| "client session: no QUIC control sender".to_string())?;
            let cipher = q.cipher_handle();
            ControlSink::Quic { stream, cipher }
        }
        TransportMode::Tcp => {
            let t = tcp_mut(&mut slot)
                .ok_or_else(|| "client session: TCP transport downcast failed".to_string())?;
            let sender = t
                .take_sender()
                .ok_or_else(|| "client session: no TCP write half".to_string())?;
            ControlSink::Tcp(sender)
        }
    };
    // QUIC 专用共享句柄（丢包检测；TCP 无丢包语义）
    let loss_detector = match mode {
        TransportMode::Quic => quic_mut(&mut slot).map(|q| q.loss_detector_shared()),
        TransportMode::Tcp => None,
    };
    info!("client session: transport mode = {mode:?}");

    // 1. 等待服务端推送分辨率（会话开始时，10s 超时）
    let (w, h) = match tokio::time::timeout(Duration::from_secs(10), slot.recv_control()).await {
        Ok(Ok(ControlMessage::VideoFormat { width, height })) => (width, height),
        Ok(Ok(other)) => {
            warn!("[Session] expected VideoFormat, got {:?}", other);
            (0, 0)
        }
        Ok(Err(e)) => return Err(format!("recv VideoFormat: {e}")),
        Err(_) => return Err("timeout waiting for VideoFormat from server".into()),
    };
    if w == 0 || h == 0 {
        return Err("invalid VideoFormat from server".into());
    }
    info!("client session: video {}x{}", w, h);

    // 2. 解码器（回退链：qsv→cuvid→d3d11va→vt→vaapi→软解；P2B 流式管线）。
    //    旧逻辑（hw 打开成功但首帧失败 → 整体回退软解）由新管线的连续错误
    //    → flush + IDR 请求机制取代（P2B §T2.3 IDR 恢复策略）。
    let mut decoder = match create_video_decoder(Codec::H264) {
        Ok(d) => {
            info!(
                "client session: decoder '{}' (hw={})",
                d.name(),
                d.is_hardware()
            );
            d
        }
        Err(e) => return Err(format!("create H.264 decoder: {e}")),
    };

    let stats = Arc::new(Mutex::new(ClientSessionStats::default()));

    // 3. 反馈上报 task（QUIC = 100ms 默认；TCP = tcp_feedback_interval_ms §3.5）
    let feedback_interval = if mode == TransportMode::Tcp {
        config.tcp_feedback_interval_ms
    } else {
        config.feedback_interval_ms
    };
    spawn_client_feedback_task(
        control_sink,
        loss_detector.clone(),
        Arc::clone(&stats),
        Arc::clone(&stop),
        Duration::from_millis(feedback_interval),
    );

    // 3.5 R-04：音频解码 + 播放任务（独立阻塞线程）。
    //    传输接收循环（`recv_frame`）内部按 type 分流音频包到缓冲通道；
    //    无解码器/播放设备 → info 降级（解码完成但静音 / 完全放弃音频），
    //    视频/键鼠不受影响。热替换（P5-3 降级 / 打洞升舱）后由
    //    [`apply_client_swap`] 用新传输的通道重启管线。
    let mut client_audio = if config.audio.enabled {
        match slot.take_audio_receiver() {
            Some(rx) => Some(start_client_audio(
                rx,
                Arc::clone(&stop),
                Arc::clone(&stats),
            )),
            None => {
                info!("[Session] audio receive unavailable on transport — degraded");
                None
            }
        }
    } else {
        None
    };

    // 4. 降级热替换通道（P5-3）：QUIC 失效 → 重连 task 经此注入 TCP 传输。
    //    M8-T026-P1 (PATH-004)：打洞升舱同样经此通道热替换（强制 IDR）。
    let (swap_tx, mut swap_rx) = if degrade.is_some() || punch_upgrade.is_some() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Box<dyn MediaTransport>>();
        if let Some(up) = punch_upgrade {
            let tx_task = tx.clone();
            let stop_task = Arc::clone(&stop);
            tokio::spawn(async move {
                punch_upgrade_connect_task(up, tx_task, stop_task).await;
            });
        }
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let degrade_wait_timeout = degrade
        .as_ref()
        .map(|d| d.connect_timeout + Duration::from_secs(10))
        .unwrap_or(Duration::from_secs(20));
    // 降级可用：配置开关 + 会话附带重连参数（mode 在循环内逐次判定）。
    let degrade_enabled = config.graceful_degrade && swap_rx.is_some() && degrade.is_some();

    // 5. 主循环：接收 → 解码 → 渲染回调
    let mut bandwidth_accum: u64 = 0;
    let mut bandwidth_window = Instant::now();
    let mut decode_accum: f64 = 0.0;
    let mut decode_count: u64 = 0;
    let mut transport_switches: u64 = 0;
    let mut degrading = false;
    let mut degrade_deadline: Option<Instant> = None;

    loop {
        if stop.load(Ordering::Relaxed) {
            info!("client session: stopping by user request");
            break;
        }

        // P5-3 触发检测：QUIC 存活轮询（每帧返回节奏驱动）
        if mode == TransportMode::Quic && degrade_enabled && !slot.is_alive() && !degrading {
            trigger_client_degrade(
                &mut degrading,
                &mut degrade_deadline,
                degrade_wait_timeout,
                swap_tx.clone(),
                degrade.as_ref(),
                &mut slot,
            );
            continue;
        }

        // P5-3：降级等待分支——不读旧传输，只等热替换或超时。
        if degrading {
            let timed_out = degrade_deadline
                .map(|d| Instant::now() >= d)
                .unwrap_or(false);
            if timed_out {
                warn!("client session: TCP reconnect wait timed out — ending session");
                break;
            }
            let swap_recv = async {
                match swap_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                new = swap_recv => {
                    match new {
                        Some(t) => {
                            apply_client_swap(
                                t,
                                &mut slot,
                                &mut mode,
                                &mut transport_switches,
                                &stats,
                                &stop,
                                config.tcp_feedback_interval_ms,
                                &mut client_audio,
                                config.audio.enabled,
                            );
                            // R-03 缺陷修复（ZM-05 回归暴露）：swap 应用后必须
                            // 复位 degrading——否则主循环永久停在降级等待分支
                            // （swap_rx 已空），媒体不流动，直到 13s 超时误报
                            // "TCP reconnect wait timed out" 结束会话。
                            degrading = false;
                        }
                        None => break,
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            continue;
        }

        // 带宽估算（字节累计 → bps）
        {
            let mut st = stats.lock().unwrap();
            let elapsed = bandwidth_window.elapsed().as_secs_f64();
            if elapsed >= 1.0 {
                st.bandwidth_bps = (bandwidth_accum as f64 * 8.0 / elapsed) as u64;
                bandwidth_accum = 0;
                bandwidth_window = Instant::now();
            }
            st.rtt_ms = slot.rtt();
        }

        let recv = tokio::select! {
            frame = slot.recv_frame() => frame,
            // 防御分支：热替换也可自发到达（如服务端主动重推）
            new = async {
                match swap_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match new {
                    Some(t) => {
                        apply_client_swap(
                            t,
                            &mut slot,
                            &mut mode,
                            &mut transport_switches,
                            &stats,
                            &stop,
                            config.tcp_feedback_interval_ms,
                            &mut client_audio,
                            config.audio.enabled,
                        );
                        continue;
                    }
                    None => break,
                }
            }
        };

        match recv {
            Ok(frame) => {
                debug!("[Session] recv_frame exit got frame {}", frame.frame_id);
                bandwidth_accum += (frame.data.len() + 14) as u64;
                let is_key = frame.flags & 0x01 != 0;
                if is_key {
                    // IDR 到达：清旧参考帧（seek/丢包后安全重同步）。
                    decoder.flush();
                }
                // PTS 方案 A（P2A §T1.1）：frame_id 线性近似。
                let pkt = DecoderPacket {
                    pts: frame_id_to_pts(frame.frame_id, TARGET_FPS),
                    data: frame.data.clone(),
                    is_key,
                    extradata: None,
                };
                let start = Instant::now();
                match decoder.decode(&pkt) {
                    Ok(frames) => {
                        let ms = start.elapsed().as_secs_f64() * 1000.0;
                        decode_accum += ms;
                        decode_count += 1;
                        {
                            let mut st = stats.lock().unwrap();
                            st.frames_decoded += frames.len() as u64;
                            st.avg_decode_ms = if decode_count > 0 {
                                decode_accum / decode_count as f64
                            } else {
                                0.0
                            };
                            st.loss_rate = loss_detector
                                .as_ref()
                                .map(|ld| ld.lock().unwrap().loss_rate())
                                .unwrap_or(0.0);
                            st.video_w = w;
                            st.video_h = h;
                        }
                        // 流式：一包可能产出 0..N 帧（0 帧 = 参考帧缓冲中）。
                        for df in &frames {
                            on_frame(df.width, df.height, &df.rgba);
                        }
                    }
                    Err(e) => {
                        // 连续错误达阈值（≥3）→ 内部已 flush + idr_requests++，
                        // 上层（自适应反馈）据此让服务端强制下一帧 IDR。
                        if decoder.report_error() {
                            warn!(
                                "[Session] decode errors exceeded threshold — keyframe requested, awaiting IDR"
                            );
                        }
                        stats.lock().unwrap().frames_dropped += 1;
                        warn!("[Session] decode frame failed: {e}");
                    }
                }
            }
            Err(TransportError::Timeout) => {
                // 静默窗口期间无媒体数据 → 继续等待
                continue;
            }
            Err(e) => {
                // P5-3：QUIC 连接级错误 → 触发降级（TCP 重建续传）；否则结束会话
                if mode == TransportMode::Quic && degrade_enabled && is_connection_error(&e) {
                    warn!("[Session] recv failed ({e}) — degrading to TCP");
                    trigger_client_degrade(
                        &mut degrading,
                        &mut degrade_deadline,
                        degrade_wait_timeout,
                        swap_tx.clone(),
                        degrade.as_ref(),
                        &mut slot,
                    );
                } else {
                    debug!("[Session] recv ended: {e}");
                    break;
                }
            }
        }
    }

    // 收尾：QUIC 关闭连接（TCP 直接 drop）
    if mode == TransportMode::Quic {
        if let Some(q) = quic_mut(&mut slot) {
            let udp = q.conn().udp_stats();
            info!(
                "client session ended: udp tx={} dg/{} B, rx={} dg/{} B",
                udp.0, udp.1, udp.2, udp.3
            );
            q.conn().close("client session end");
        }
    }
    let _ = slot.close().await;

    // R-04：音频收尾——slot drop 已关闭音频通道（rx 端 recv 返回 Err → 管线
    // 线程正常退出）；带超时 join，避免播放设备释放卡住会话返回。
    if let Some(audio) = client_audio.as_mut() {
        let _ = tokio::time::timeout(Duration::from_secs(3), &mut audio.task).await;
    }

    let mut st = stats.lock().unwrap();
    st.transport_mode = match mode {
        TransportMode::Quic => "QUIC".to_string(),
        TransportMode::Tcp => "TCP".to_string(),
    };
    st.transport_switches = transport_switches;
    // R-04：音频统计快照（管线退出日志 + 共享句柄最终值）。
    st.audio_enabled = client_audio.is_some();
    if let Some(audio) = &client_audio {
        let s = audio.stats.lock().unwrap().clone();
        st.audio_silence_inserted = s.silence_inserted;
        st.audio_packets_dropped = s.packets_dropped;
    }
    Ok(st.clone())
}

/// R-04：客户端音频会话状态（管线阻塞任务 + 共享抖动统计）。
struct ClientAudio {
    /// 管线任务（`run()` 在音频通道关闭时正常返回——会话结束 / 热替换旧
    /// 传输 drop 均触发；会话收尾带超时 join）。
    task: tokio::task::JoinHandle<()>,
    /// 共享抖动统计（管线每 ~100 帧刷新；会话读取快照）。
    stats: Arc<Mutex<crate::decoder::audio::AudioJitterStats>>,
}

/// R-04：启动客户端音频管线（独立阻塞线程）+ 周期抖动统计日志任务。
///
/// 创建失败（无 libopus）→ info 降级；播放设备缺失 → info 提示后仍解码
/// （静音）。`run()` 阻塞在音频通道，发送端关闭（会话结束/热替换）即返回。
#[allow(clippy::too_many_arguments)]
fn start_client_audio(
    rx: std::sync::mpsc::Receiver<crate::decoder::AudioPacket>,
    stop: Arc<AtomicBool>,
    session_stats: Arc<Mutex<ClientSessionStats>>,
) -> ClientAudio {
    let stats: Arc<Mutex<crate::decoder::audio::AudioJitterStats>> = Arc::new(Mutex::new(
        crate::decoder::audio::AudioJitterStats::default(),
    ));
    let stats_task = Arc::clone(&stats);
    // 管线退出标志（tokio JoinHandle 无 Clone 且不可经 Arc 变借——日志任务
    // 用共享标志轮询退出，join 句柄留给会话收尾）。
    let exited = Arc::new(AtomicBool::new(false));
    let exited_task = Arc::clone(&exited);
    let task = tokio::task::spawn_blocking(move || {
        let mut pipe = match crate::decoder::audio::AudioDecodePipeline::new(rx) {
            Ok(p) => p,
            Err(e) => {
                info!("[Session] audio decode disabled (pipeline init failed): {e}");
                exited_task.store(true, Ordering::Relaxed);
                return;
            }
        };
        pipe.set_jitter_stats_shared(stats_task);
        if let Err(e) = pipe.start_playback() {
            info!("[Session] audio playback unavailable ({e}) — decode-only (silent)");
        }
        // run()：rx 关闭（会话结束 / 热替换旧传输 drop）→ Ok 正常返回。
        let _ = pipe.run();
        exited_task.store(true, Ordering::Relaxed);
        let s = pipe.jitter_stats();
        info!(
            "[Session] audio pipeline exited: silence_inserted={} packets_dropped={}",
            s.silence_inserted, s.packets_dropped
        );
    });
    let logger_task = Arc::clone(&exited);
    let logger_stats = Arc::clone(&stats);
    let logger_stop = Arc::clone(&stop);
    let logger_sess = Arc::clone(&session_stats);
    // 周期日志任务：自终止（stop / 管线退出）→ 句柄即弃（detached）。
    let _ = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            if logger_stop.load(Ordering::Relaxed) {
                break;
            }
            // 管线已退出（会话结束 / 热替换后旧管线收尾）→ 本任务退出。
            if logger_task.load(Ordering::Relaxed) {
                break;
            }
            let s = logger_stats.lock().unwrap().clone();
            if s.silence_inserted > 0 || s.packets_dropped > 0 {
                info!(
                    "[Session] audio jitter stats: silence_inserted={} packets_dropped={}",
                    s.silence_inserted, s.packets_dropped
                );
            }
            {
                let mut st = logger_sess.lock().unwrap();
                st.audio_silence_inserted = s.silence_inserted;
                st.audio_packets_dropped = s.packets_dropped;
            }
        }
    });
    ClientAudio { task, stats }
}

/// 客户端热替换：注入的新传输接管接收槽 + 重启反馈 task（TCP 写半）+
/// R-04 音频管线（新传输的音频通道，旧管线随旧传输 drop 退出）。
#[allow(clippy::too_many_arguments)]
fn apply_client_swap(
    new_transport: Box<dyn MediaTransport>,
    slot: &mut Box<dyn MediaTransport>,
    mode: &mut TransportMode,
    transport_switches: &mut u64,
    stats: &Arc<Mutex<ClientSessionStats>>,
    stop: &Arc<AtomicBool>,
    tcp_feedback_interval_ms: u64,
    client_audio: &mut Option<ClientAudio>,
    audio_enabled: bool,
) {
    let (new_slot, new_sink) = match split_client_control_sink(new_transport) {
        Ok(pair) => pair,
        Err(e) => {
            warn!("client swap failed: {e} — dropping injected transport");
            return;
        }
    };
    // 关闭旧 QUIC（通知对端；TCP 槽直接 drop）
    if let Some(q) = quic_mut(slot) {
        q.conn().close("degraded to TCP");
    }
    *slot = new_slot;
    *mode = slot.mode();
    *transport_switches += 1;
    // 新反馈 task（TCP 写半；无 loss detector）
    spawn_client_feedback_task(
        new_sink,
        None,
        Arc::clone(stats),
        Arc::clone(stop),
        Duration::from_millis(tcp_feedback_interval_ms),
    );
    // R-04：热替换后音频重启——新传输的音频通道尚未被取走；旧管线随旧
    // 传输 drop 自动退出（rx 关闭），旧日志任务在下个 tick 收尾。
    if audio_enabled {
        if let Some(rx) = slot.take_audio_receiver() {
            *client_audio = Some(start_client_audio(rx, Arc::clone(stop), Arc::clone(stats)));
            info!("[Session] audio pipeline restarted on new transport");
        } else {
            warn!("[Session] audio receive unavailable on new transport — audio degraded");
        }
    }
    info!("[Session] transport switched QUIC → TCP (total {transport_switches}) — awaiting IDR");
}

/// 触发客户端降级：置降级等待状态 + 以同一凭据重拨 TCP（单向降级，不自动
/// 升级回 QUIC——B3）。
#[allow(clippy::too_many_arguments)]
fn trigger_client_degrade(
    degrading: &mut bool,
    degrade_deadline: &mut Option<Instant>,
    wait_timeout: Duration,
    swap_tx: Option<tokio::sync::mpsc::UnboundedSender<Box<dyn MediaTransport>>>,
    degrade: Option<&ClientDegrade>,
    slot: &mut Box<dyn MediaTransport>,
) {
    // R-28（审计 §4-1）：防重入——recv 失败与 is_alive 轮询两处触发点可能
    // 相继命中（42.327/42.398 模式），不守卫会 spawn 多个重拨任务重复建连。
    // 已在降级等待中 → 忽略重复触发（降级等待分支会等 swap 或超时收尾）。
    if *degrading {
        warn!("[Session] degrade already in progress — ignoring repeated trigger");
        return;
    }
    let reason = quic_mut(slot)
        .map(|q| q.conn().close_reason_str())
        .unwrap_or_default();
    warn!("[Session] QUIC connection dead (reason: {reason}) — reconnecting over TCP");
    *degrading = true;
    *degrade_deadline = Some(Instant::now() + wait_timeout);

    let Some(d) = degrade else {
        warn!("[Session] no reconnect params — ending session");
        return;
    };
    let Some(tx) = swap_tx else {
        return;
    };
    let d = d.clone();
    tokio::spawn(async move {
        // 同一凭据重拨 TCP（完整握手；失败由降级等待超时兜底结束会话）。
        let result = crate::transport::connect_media_transport(
            d.addr,
            TransportMode::Tcp,
            false, // 已确定 QUIC 不可用，不再回退
            &d.client_identity,
            &d.client_id,
            &d.client_domain,
            &d.client_device_type,
            &d.server_id,
            d.server_pin.clone(),
            &d.challenge,
            d.connect_timeout,
        )
        .await;
        match result {
            Ok(t) => {
                let _ = tx.send(t);
            }
            Err(e) => warn!("[Session] TCP fallback reconnect failed: {e}"),
        }
    });
}

/// 生成客户端反馈上报 task（会话启动与热替换后共用）。
fn spawn_client_feedback_task(
    mut sink: ControlSink,
    loss_detector: Option<Arc<std::sync::Mutex<crate::transport::LossDetector>>>,
    stats: Arc<Mutex<ClientSessionStats>>,
    stop: Arc<AtomicBool>,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut report_gen = ReportGenerator::new(interval);
        if let Some(ld) = loss_detector {
            report_gen.set_loss_detector(ld);
        }
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(interval).await;
            {
                let st = stats.lock().unwrap();
                report_gen.update_rtt(st.rtt_ms.saturating_mul(1000));
                report_gen.update_bandwidth(st.bandwidth_bps);
            }
            if let Some(msg) = report_gen.generate_control_msg() {
                if sink.send(&msg).await.is_err() {
                    // 发送失败（QUIC 连接失效 / TCP 断链）→ 退出；
                    // 降级场景由主循环在热替换后重启本 task。
                    break;
                }
                stats.lock().unwrap().feedback_sent += 1;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    // R-03 (R03-S3): 续接信号 → 服务端强制 IDR 标记；request_idr=false 不置位。
    #[test]
    fn test_session_resume_requests_idr() {
        let flag = AtomicBool::new(false);
        apply_session_resume(SessionResume::default(), &flag);
        assert!(
            flag.load(Ordering::Relaxed),
            "default resume must force IDR"
        );
        assert_eq!(SessionResume::with_idr(), SessionResume::default());

        flag.store(false, Ordering::Relaxed);
        apply_session_resume(SessionResume { request_idr: false }, &flag);
        assert!(
            !flag.load(Ordering::Relaxed),
            "no-IDR resume must not set flag"
        );
    }
}
