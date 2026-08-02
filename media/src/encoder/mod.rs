//! 编码层入口（P1C 重构：硬件编码层 + 软编回退 + 决策分发）。
//!
//! # 架构（P1C 完成后）
//!
//! ```text
//! capture (RGBA/GpuTexture) ──→ VideoEncoderPipeline ──→ EncodedPacket
//!                                  ├── TileDiff (Static/Incremental/FullFrame)
//!                                  └── VideoEncoder trait
//!                                       ├── FfmpegHwEncoder (h264_nvenc/amf/qsv/...; HW DLL/GPU 就绪时)
//!                                       └── FfmpegSwEncoder (libx264/libx265; 软编回退)
//! ```
//!
//! # 历史清理
//!
//! P1C 删除的旧后端：
//!   - `ffmpeg.rs`（旧 `FfmpegEncoder`，签名 `encode(&[u8], w, h)`）→ 迁移到
//!     `video/ffmpeg_sw.rs`（软编，新 trait）
//!   - `qsv.rs` / `mf_h264.rs` / `sw_h264.rs`（P1A 已删）
//!
//! 旧的 `VideoEncoder` trait、`AutoEncoder`、`Codec`（含 `Jpeg`）、
//! `EncodeError`（struct）已全部移除；本模块仅 re-export 新接口层符号，
//! 保持 `crate::encoder::{VideoEncoder, EncodeError, Codec, ...}` 路径可用。
//!
//! # 模块
//!
//! | 子模块 | 职责 |
//! |--------|------|
//! | [`types`] | 接口层纯数据类型（Timestamp/DirtyTileMap/Codec/EncodedPacket/GpuTexture/EncodeDecision） |
//! | [`video`] | 新 `VideoEncoder`/`AudioEncoder` trait + 新 `EncodeError` enum |
//! | [`video::ffmpeg_hw`] | FFmpeg 硬件编码后端（hw device / hwframes / ROI / Annex B） |
//! | [`video::ffmpeg_sw`] | libx264/libx265 软编回退 |
//! | [`video::pipeline`] | 决策分发入口（VideoEncoderPipeline） |
//! | [`video::tile_diff`] | 决策逻辑（Static/Incremental/FullFrame）+ GpuKernel trait |
//! | [`factory`] | 后端检测与回退链（真实探测 + OnceLock 缓存） |
//! | [`audio`] | 音频编码占位（P1D） |
//! | [`gpu_ffi`] | C++ GPU 内核 FFI 绑定（P1B） |

pub mod audio;
pub mod factory;
pub mod gpu_ffi;
pub mod types;
pub mod video;

// ── 兼容 re-export（保持既有路径 `crate::encoder::X` 可用） ──────
//
// P1C 把旧 trait/enum/struct 移除后，下列符号统一指向新接口层
// （`types` / `video`），让 window_pipeline / decoder / ui 经路径迁移即可。

pub use types::{
    Codec, DirtyTileMap, EncodeDecision, EncodedPacket, GpuTexture, PacketKind, TileRegion,
    Timestamp,
};
pub use video::ffmpeg_hw::FfmpegHwEncoder;
pub use video::ffmpeg_sw::FfmpegSwEncoder;
pub use video::pipeline::VideoEncoderPipeline;
pub use video::{preprocess_encode, AudioEncoder, EncodeError, VideoEncoder};
// ── 音频流水线（P1D） ──
pub use audio::{AudioCapture, AudioPcm, AudioPipeline, OpusEncoder};

/// Codec 字符串常量（握手协商用）。
pub const CODEC_H264: &str = "h264";
pub const CODEC_H265: &str = "h265";

/// 检测本机可用编码（握手用：返回 codec 字符串列表，按优先级）。
///
/// 与 [`factory::detect_supported_codecs`]（返回 FFmpeg 编码器名回退链）
/// 语义不同——本函数返回**协商用 codec 字符串**（`"h264"` / `"h265"`），
/// 服务于传输握手。
pub fn detect_supported_codecs() -> Vec<&'static str> {
    let mut codecs = Vec::new();
    if factory::create_video_encoder(Codec::H264, None).is_ok() {
        codecs.push(CODEC_H264);
    }
    if factory::create_video_encoder(Codec::H265, None).is_ok() {
        codecs.push(CODEC_H265);
    }
    codecs
}
