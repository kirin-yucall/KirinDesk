//! 视频编码入口 + 接口层 trait（P1A §T1.1 → P1C 完成）。
//!
//! 承载编码层接口层：
//! - [`VideoEncoder`] trait（新签名：`encode(tex, ts, decision)`）
//! - [`AudioEncoder`] trait（P1D 实现者接入）
//! - 新 [`EncodeError`] enum（按变体带 message）
//!
//! # 历史（P1C 已完成迁移）
//!
//! 旧 `encoder::VideoEncoder` trait（签名 `encode(&mut self, rgba, w, h)`）
//! 与旧 `FfmpegEncoder` 已在 P1C 移除：硬件/软编后端迁移到本 trait 的
//! [`ffmpeg_hw::FfmpegHwEncoder`] / [`ffmpeg_sw::FfmpegSwEncoder`]，决策
//! 分发入口为 [`pipeline::VideoEncoderPipeline`]。`crate::encoder::{VideoEncoder,
//! EncodeError, Codec}` 路径经 re-export 仍可用，但指向本模块的新类型。

pub mod tile_diff;

// ── P1C 后端实现者 ──────────────────────────────────────────
pub mod ffmpeg_hw;
pub mod ffmpeg_sw;
pub mod pipeline;

use crate::encoder::types::{Codec, EncodeDecision, EncodedPacket, GpuTexture, Timestamp};
use crate::proto::EncodeConfig;

// ════════════════════════════════════════════════════════════════
// EncodeError — 新的错误枚举（按变体带 message）
// ════════════════════════════════════════════════════════════════

/// 编码层错误（接口层定义，P1C 已合并为唯一错误类型）。
#[derive(Debug, Clone)]
pub enum EncodeError {
    /// 编码器初始化失败（hw device / avcodec_open2）。
    InitFailed(String),
    /// 不支持该后端/编码标准。
    Unsupported(String),
    /// 编码过程失败（send/receive）。
    EncodeFailed(String),
    /// GPU 内核失败（`kgpu_*` 返回非 0）。
    GpuKernel(String),
    /// 配置非法（分辨率/参数）。
    InvalidConfig(String),
    /// 当前平台不支持该能力（如 macOS/Linux 暂无音频环回捕获实现，音频禁用，
    /// 视频/键鼠不受影响）。与 [`Unsupported`](Self::Unsupported) 区分：后者
    /// 指后端/编码标准缺失，本变体指平台级能力缺失。
    UnsupportedPlatform(String),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::InitFailed(m) => write!(f, "encoder init failed: {}", m),
            EncodeError::Unsupported(m) => write!(f, "unsupported: {}", m),
            EncodeError::EncodeFailed(m) => write!(f, "encode failed: {}", m),
            EncodeError::GpuKernel(m) => write!(f, "GPU kernel failed: {}", m),
            EncodeError::InvalidConfig(m) => write!(f, "invalid config: {}", m),
            EncodeError::UnsupportedPlatform(m) => write!(f, "unsupported platform: {}", m),
        }
    }
}

impl std::error::Error for EncodeError {}

impl From<String> for EncodeError {
    fn from(s: String) -> Self {
        EncodeError::EncodeFailed(s)
    }
}

impl From<&str> for EncodeError {
    fn from(s: &str) -> Self {
        EncodeError::EncodeFailed(s.to_string())
    }
}

// ════════════════════════════════════════════════════════════════
// VideoEncoder trait
// ════════════════════════════════════════════════════════════════

/// 视频编码器接口（GPU 纹理 + 决策驱动）。
///
/// 实现者：P1C 的 `ffmpeg_hw::FfmpegHwEncoder` / `ffmpeg_sw::FfmpegSwEncoder`。
pub trait VideoEncoder: Send {
    /// 编码一帧：`tex` 为 GPU 纹理，`decision` 决定走哪条路径。
    ///
    /// 返回 0..n 个码流包（可能为空：全静/被跳过）。
    ///
    /// # 边界
    /// - `tex.handle == null` → [`EncodeError::InvalidConfig`]，不 panic
    /// - `decision == Static` → 返回 `Ok(vec![])`，**不触碰编码器**
    fn encode(
        &mut self,
        tex: &GpuTexture,
        ts: Timestamp,
        decision: EncodeDecision,
    ) -> Result<Vec<EncodedPacket>, EncodeError>;

    /// 编码标准：H264（默认）| H265（协商）。
    fn codec(&self) -> Codec;

    /// 是否为硬件编码器。
    fn is_hardware(&self) -> bool;

    /// 诊断名（`"h264_nvenc"` | `"libx264"` | ...）。
    fn name(&self) -> &'static str;

    /// 分辨率变更 / 参数重配。
    fn reconfigure(&mut self, cfg: &EncodeConfig) -> Result<(), EncodeError>;

    /// CPU RGBA 路径入口（软编回退适配，P1C §T3.6）。
    ///
    /// 捕获层（`windows_capture`）当前产出 RGBA 字节而非 `GpuTexture` 句柄
    /// ——P1B GPU 内核桥不可用时，编码器需在 CPU 上吃 RGBA。调用方在
    /// [`encode`](Self::encode) 前调用本方法把当前帧 RGBA 喂入；`encode`
    /// 内由实现者（仅 [`ffmpeg_sw::FfmpegSwEncoder`]）读取该缓冲走 swscale
    /// 软编。
    ///
    /// 默认空实现：硬件编码器（`ffmpeg_hw::FfmpegHwEncoder`）走 GPU 纹理零
    /// 拷贝路径，不消费 CPU RGBA，故不覆盖。
    ///
    /// - `rgba`：RGBA 像素（行主序，stride = `w * 4`）
    /// - `force_idr`：客户端请求 / 会话首帧 → 强制下一帧 IDR
    fn set_cpu_frame(&mut self, _rgba: &[u8], _w: u32, _h: u32, _force_idr: bool) {}

    /// 清空编码器内部参考帧与未输出缓冲（窗口边界调用，M8-T011 T2.3）。
    ///
    /// 窗口式编码器要求**每个窗口自包含**（IDR per window，无跨窗口参考
    /// 依赖）：窗口间调用本方法丢弃上一窗口残留的参考帧 / lookahead 缓冲，
    /// 配合「下一帧强制 IDR」保证解码端无需任何跨窗口状态即可重建。
    ///
    /// 实现者注意：`avcodec_flush_buffers` 后编码器内部状态被重置，
    /// **下一帧必须是 IDR**（窗口首帧强制 IDR 已满足该约束）。
    ///
    /// 默认空实现：无缓冲后端的实现者（测试桩等）无需覆盖。
    fn flush_buffers(&mut self) {}
}

// ════════════════════════════════════════════════════════════════
// AudioEncoder trait
// ════════════════════════════════════════════════════════════════

/// 音频编码器接口：PCM(float32, 48kHz stereo interleaved) → Opus。
///
/// 实现者：P1D（`encoder/audio.rs`）。
pub trait AudioEncoder: Send {
    /// PCM(float32, 48000Hz stereo interleaved) → Opus 包。
    fn encode_pcm(&mut self, pcm: &[f32], ts: Timestamp)
        -> Result<Vec<EncodedPacket>, EncodeError>;

    /// 采样率（48000）。
    fn sample_rate(&self) -> u32;

    /// 声道数（2）。
    fn channels(&self) -> u16;
}

// ════════════════════════════════════════════════════════════════
// 静态决策的通用预处理（trait 实现者复用）
// ════════════════════════════════════════════════════════════════

/// 决策预处理：把接口层 Edge Cases 固化为单一函数，trait 实现者在 `encode`
/// 开头调用。
///
/// - `tex.handle == null` → `Err(InvalidConfig("null texture"))`
/// - `decision == Static` → `Ok(Some(vec![]))`（调用方直接返回空包，不触碰编码器）
/// - 其它 → `Ok(None)`（调用方继续走真实编码路径）
///
/// 单独抽出便于本阶段在无实现者的情况下对 Edge Cases 做单测。
pub fn preprocess_encode(
    tex: &GpuTexture,
    decision: &EncodeDecision,
) -> Result<Option<Vec<EncodedPacket>>, EncodeError> {
    if tex.is_null() {
        return Err(EncodeError::InvalidConfig("null texture".into()));
    }
    if matches!(decision, EncodeDecision::Static) {
        return Ok(Some(Vec::new()));
    }
    Ok(None)
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::types::{GpuTexture, TileRegion};
    use std::ptr;

    /// P1A Tests：Static 决策 → 空包，不 panic。
    #[test]
    fn test_encode_static_zero_output() {
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        let decision = EncodeDecision::Static;
        match preprocess_encode(&tex, &decision) {
            Ok(Some(packets)) => {
                assert!(packets.is_empty(), "Static 决策应零输出");
            }
            other => panic!("Static 应返回 Some(vec![])，实际: {:?}", other),
        }
    }

    /// P1A Tests：null 纹理 → InvalidConfig。
    #[test]
    fn test_encode_null_texture() {
        let tex = GpuTexture::new(ptr::null_mut(), 0, 0);
        let decision = EncodeDecision::Incremental(vec![TileRegion::single(0, 0)]);
        let err = preprocess_encode(&tex, &decision).unwrap_err();
        match err {
            EncodeError::InvalidConfig(msg) => assert!(msg.contains("null texture")),
            other => panic!("期望 InvalidConfig，实际: {:?}", other),
        }
    }

    #[test]
    fn test_preprocess_non_static_passes_through() {
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        let decision = EncodeDecision::FullFrame(crate::encoder::types::DirtyTileMap::default());
        // 非 Static + 非空纹理 → None（交给实现者处理）。
        assert!(preprocess_encode(&tex, &decision).unwrap().is_none());
    }

    #[test]
    fn test_encode_error_display_per_variant() {
        assert!(EncodeError::InitFailed("avcodec_open2".into())
            .to_string()
            .contains("init failed"));
        assert!(EncodeError::Unsupported("no encoder".into())
            .to_string()
            .contains("unsupported"));
        assert!(EncodeError::EncodeFailed("send".into())
            .to_string()
            .contains("encode failed"));
        assert!(EncodeError::GpuKernel("tile_hash".into())
            .to_string()
            .contains("GPU kernel failed"));
        assert!(EncodeError::InvalidConfig("null".into())
            .to_string()
            .contains("invalid config"));
        assert!(EncodeError::UnsupportedPlatform("macos".into())
            .to_string()
            .contains("unsupported platform"));
    }

    #[test]
    fn test_encode_error_from_string() {
        let e: EncodeError = "boom".to_string().into();
        assert!(matches!(e, EncodeError::EncodeFailed(_)));
        let e2: EncodeError = "boom".into();
        assert!(matches!(e2, EncodeError::EncodeFailed(_)));
    }

    #[test]
    fn test_encode_error_is_std_error() {
        fn takes_err(e: &dyn std::error::Error) -> String {
            e.to_string()
        }
        let e = EncodeError::Unsupported("x".into());
        assert!(takes_err(&e).contains("unsupported"));
    }
}
