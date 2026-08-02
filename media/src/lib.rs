//! KirinDesk 媒体模块。
//!
//! # 架构
//!
//! ```text
//! Phase 1 (捕获层)              Phase 2 (窗口编码)              Phase 3 (QUIC 传输)
//! capture/mod.rs ──RawFrame──→  window_pipeline.rs ──EncodedWindow──→ transport/
//!   └── windows_capture.rs          ├── proto.rs (数据结构)            ├── quic.rs
//!       (唯一后端, M8-T008)         └── encoder/video/                ├── datagram.rs
//!   zed-scap (Linux/macOS,              ├── pipeline.rs (决策分发)     ├── control.rs
//!   Phase 5/6 待实现)                   ├── ffmpeg_hw.rs (HW 编码)     ├── reassembly.rs
//!                                       └── ffmpeg_sw.rs (软编回退)    ├── loss_detection.rs
//!                                                                      └── (tcp_fallback.rs Phase 3)
//! ```
//!
//! # 模块
//!
//! | 模块 | 职责 |
//! |------|------|
//! | `capture` | 屏幕捕获：windows-capture (Windows 唯一后端)；zed-scap (Linux/macOS, Phase 5/6) |
//! | `window_pipeline` | 70ms 窗口管理器 + 编码调度 |
//! | `proto` | RawFrame、EncodeConfig、EncodedWindow 等数据结构 |
//! | `encoder` | H.264/H.265 编码：FFmpeg libavcodec 进程内（ffmpeg_hw 硬编 + ffmpeg_sw 软编回退 + VideoEncoderPipeline 决策分发） |
//! | `ffmpeg` | FFmpeg 动态加载 FFI 绑定 |
//! | `decoder` | 解码层：接口层 + `video/`（ffmpeg_hw/ffmpeg_sw 流式实现）+ audio/audio_playback/render（P2B，M8-T015） |
//! | `transport` | QUIC 传输层 |

pub mod adaptive;
pub mod capture;
pub mod encoder;
pub mod ffmpeg;
// M8-T030（修复任务 R-06）：单 GPU 适配器选择 + 虚拟设备过滤。
// 运行时枚举本机真实 GPU（DXGI），按偏好选一个绑定到 FFmpeg HW 编解码；
// 虚拟显示器从捕获列表剔除（含索引一致性）；详见 gpu/mod.rs。
pub mod gpu;
pub mod proto;
pub mod session;
pub mod transport;
pub mod window_pipeline;

// 解码层（M8-T015 P2A：接口层 + 模块骨架；P2B 起多层级：video/ + audio/ + render/）。
pub mod decoder;

// ── 重新导出 ───────────────────────────────────────────────────

pub use capture::{
    create_capture_source, list_monitors, CaptureError, CaptureFrame, MonitorInfo,
    ScreenCaptureSource,
};

// M8-T030（R-06）：重新导出 GPU 类型与偏好注入入口（设计文档 §3.1）。
pub use gpu::{
    apply_preferences, hwdevice_candidates, AdapterInfo, AdapterKind, GpuPreference,
    GpuPreferences,
};

pub use proto::DirtyRect;

pub use adaptive::AdaptiveEngine;
pub use encoder::{
    AudioCapture, AudioEncoder, AudioPcm, AudioPipeline, Codec, EncodeError, FfmpegHwEncoder,
    FfmpegSwEncoder, OpusEncoder, VideoEncoder, VideoEncoderPipeline,
};
pub use proto::{EncodeConfig, EncodedWindow, RawFrame, WindowConfig};
pub use session::{
    apply_session_resume, run_client_session, run_server_session, AudioConfig,
    ClientDegrade, ClientSessionStats, ServerDegrade, ServerSessionStats, SessionConfig,
    SessionResume,
};
pub use window_pipeline::WindowPipeline;
// 解码层音频（M8-T015 P2C，对称 P1D 编码侧）：客户端接入音频播放流水线。
// 注：`decoder::audio::AudioPcm` 与编码层 `AudioPcm` 同名不同结构
// （解码侧含 pts+samples），不在此重导出（消费者用全路径）。
// 解码层渲染（M8-T015 P2D）：`RenderBridge` 连接解码线程与 UI 线程
// （抖动缓冲 + 通道投递），UI 层经 `pop_render` 消费 `DecodedFrame`。
pub use decoder::{
    audio::{AudioDecodePipeline, AudioJitterBuffer, AudioJitterStats, OpusDecoder},
    audio_playback::AudioPlayback,
    AudioPacket, DecodeError, DecodedFrame, DecoderPacket, RenderBridge,
};
