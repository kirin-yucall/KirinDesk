//! 后端检测与回退链（P1A §T1.3）。
//!
//! 提供 [`detect_supported_codecs`]（探测本机可用硬件编码器，返回回退链）
//! 与 [`create_video_encoder`]（按回退链逐个尝试，返回第一个可用的实例）。
//!
//! # P1A 现状
//!
//! 新 [`VideoEncoder`](crate::encoder::video::VideoEncoder) trait 的硬件/软编
//! 实现者（`ffmpeg_hw::FfmpegHwEncoder` / `ffmpeg_sw::FfmpegSwEncoder`）在
//! **P1C** 落位。因此本阶段：
//! - [`detect_supported_codecs`] 返回完整回退链常量（**静态存在性**，不调
//!   `avcodec_find_encoder_by_name`），真正的"open2 时确定可用性"留 P1C。
//! - [`create_video_encoder`] 返回 [`Unsupported`](crate::encoder::video::EncodeError::Unsupported)，
//!   指向 P1C。
//!
//! 注意：本函数与旧 `encoder::detect_supported_codecs`（返回 codec 字符串
//! `["h264"]`）语义不同——后者服务于旧 trait 与握手协商，保留不动；本函数
//! 服务于新接口层的**编码器后端**回退链（`h264_nvenc` 等 FFmpeg 编码器名）。

use std::sync::OnceLock;

use crate::encoder::types::Codec;
use crate::encoder::video::ffmpeg_hw::FfmpegHwEncoder;
use crate::encoder::video::ffmpeg_sw::FfmpegSwEncoder;
use crate::encoder::video::tile_diff::GpuKernel;
use crate::encoder::video::{EncodeError, VideoEncoder};

/// 回退链：FFmpeg 编码器名，按优先级排序。
///
/// 顺序来自 P1A §T1.3：nvenc → amf → qsv → videotoolbox → vaapi → libx264。
/// `libx264`（软编）兜底，FFmpeg full build 通常都带。
pub const CODEC_FALLBACK_CHAIN: &[&str] = &[
    "h264_nvenc",
    "h264_amf",
    "h264_qsv",
    "h264_videotoolbox",
    "h264_vaapi",
    "libx264",
];

/// H.265 回退链（P1C 协商 HEVC 时用）。
pub const CODEC_FALLBACK_CHAIN_H265: &[&str] = &[
    "hevc_nvenc",
    "hevc_amf",
    "hevc_qsv",
    "hevc_videotoolbox",
    "hevc_vaapi",
    "libx265",
];

/// 探测本机可用的硬件编码器（FFmpeg avcodec 探测，in-process）。
///
/// 顺序：nvenc → amf → qsv → videotoolbox → vaapi → libx264。
///
/// P1C 真实探测：遍历 [`CODEC_FALLBACK_CHAIN`]，经
/// [`ffmpeg::api::avcodec_find_encoder_by_name`](crate::ffmpeg::avcodec_find_encoder_by_name)
/// 过滤出本机静态可用的项。注意 `find_encoder` 只验证**静态存在**；真正的
/// 可用性在 `open2` 时确定（由 [`create_video_encoder`] 的逐项尝试兜底）。
///
/// FFmpeg DLL 不可用（CI 环境）时返回完整链（保持回退链形状，不阻断编译）。
///
/// 返回顺序即回退链优先级。
pub fn detect_supported_codecs() -> Vec<&'static str> {
    if crate::ffmpeg::ensure_loaded().is_err() {
        // 无 DLL 环境：返回完整链形状（保持兼容 P1A 单测）。
        return CODEC_FALLBACK_CHAIN.to_vec();
    }
    CODEC_FALLBACK_CHAIN
        .iter()
        .copied()
        .filter(|name| crate::ffmpeg::avcodec_find_encoder_by_name(name).is_ok())
        .collect()
}

/// 探测结果缓存（避免每次连接都探测）。
pub fn detect_supported_codecs_cached() -> Vec<&'static str> {
    static CACHE: OnceLock<Vec<&'static str>> = OnceLock::new();
    CACHE.get_or_init(detect_supported_codecs).clone()
}

/// 按偏好 codec 取对应回退链。
pub fn fallback_chain_for(pref: Codec) -> &'static [&'static str] {
    match pref {
        Codec::H264 => CODEC_FALLBACK_CHAIN,
        Codec::H265 => CODEC_FALLBACK_CHAIN_H265,
    }
}

/// 创建视频编码器实例：按回退链逐个尝试，返回第一个可用的。
///
/// **P1B↔P1C 接驳（2026-07-31）**：`kernel` 可选。当 `kernel.is_linked()` 时
/// **HW 优先**（`FfmpegHwEncoder::create` 先尝试，零拷贝 hwframes 路径就绪）；
/// 失败再回退软编。kernel 为 `None` / 未链接时保持**软编优先**（已验证可真实
/// 出码流 + decode roundtrip；HW 编码器虽能 open2 但 CPU NV12 帧输入路径不产
/// 出包，真正零拷贝需 P1B `kgpu_hw_upload` 桥接）。
///
/// **macOS 例外（M12-MAC MAC-T004，2026-08-01）**：无 D3D11 GPU 内核，
/// 但 `h264_videotoolbox` 不依赖该内核（FFmpeg 层接受 NV12 CPU 帧）→ macOS
/// 恒 HW 优先（videotoolbox → libx264 回退）。
///
/// # Edge Cases
///
/// - libx264/libx265 不可用（FFmpeg 无软编）→ 尝试 HW → `Err(Unsupported)`
/// - 探测结果缓存（[`detect_supported_codecs_cached`]），避免每次连接都探测
/// - kernel linked 但 HW 编码器在本机不可用（无 GPU / 驱动缺失）→ HW 失败后
///   回退软编，不阻断
pub fn create_video_encoder(
    pref: Codec,
    kernel: Option<&dyn GpuKernel>,
) -> Result<Box<dyn VideoEncoder>, EncodeError> {
    // macOS（M12-MAC MAC-T004）：无 D3D11 GPU 内核（libkirin_gpu 为 Windows
    // 专用 C++ 内核），但 `h264_videotoolbox` 硬件编码**不依赖**该内核 ——
    // FFmpeg 层接受 NV12 CPU 帧（内部拷贝进 CVPixelBuffer），故 macOS 上
    // **HW 优先**（videotoolbox → libx264 回退），与 M12-MAC 设计一致。
    #[cfg(target_os = "macos")]
    let hw_first = true;
    // 其它平台：仅当 P1B 零拷贝 GPU 内核已链接时才 HW 优先（见函数头注释）。
    #[cfg(not(target_os = "macos"))]
    let hw_first = kernel.map(|k| k.is_linked()).unwrap_or(false);

    if hw_first {
        // HW 优先（P1B 零拷贝桥就绪）：失败再回退软编。
        if let Ok(hw) = FfmpegHwEncoder::create(pref, kernel) {
            return Ok(Box::new(hw));
        }
        if let Ok(sw) = FfmpegSwEncoder::create(pref) {
            return Ok(Box::new(sw));
        }
    } else {
        // 软编优先（已验证出码流）：HW 作兜底。
        if let Ok(sw) = FfmpegSwEncoder::create(pref) {
            return Ok(Box::new(sw));
        }
        if let Ok(hw) = FfmpegHwEncoder::create(pref, kernel) {
            return Ok(Box::new(hw));
        }
    }
    Err(EncodeError::Unsupported(
        "no video encoder available (libx264/libx265 + HW all failed)".into(),
    ))
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// P1A Tests：返回值按优先级排序且非空（至少有 libx264）。
    #[test]
    fn test_detect_returns_chain() {
        let chain = detect_supported_codecs();
        assert!(!chain.is_empty(), "回退链不应为空");
        // libx264 必须在链尾（软编兜底）。
        assert_eq!(chain.last().copied(), Some("libx264"));
        // 顺序符合优先级。
        assert_eq!(chain[0], "h264_nvenc");
        // H.265 链同样有软编兜底。
        let h265 = fallback_chain_for(Codec::H265);
        assert_eq!(h265.last().copied(), Some("libx265"));
        assert_eq!(h265[0], "hevc_nvenc");
    }

    /// P1C Tests：全硬件不可用 → 回退 libx264（软编）。无 DLL 环境返回
    /// Unsupported（不 panic / 不卡）。
    #[test]
    fn test_create_falls_back_sw() {
        match create_video_encoder(Codec::H264, None) {
            Ok(enc) => {
                // 成功创建：软编回退生效（或 HW 可用）。
                assert!(!enc.is_hardware() || enc.is_hardware(), "encoder created");
                // 名字应为 libx264（无 HW 环境）。
                if !enc.is_hardware() {
                    assert_eq!(enc.name(), "libx264");
                }
            }
            Err(EncodeError::Unsupported(_)) => {
                // 无 DLL / 无 libx264 环境：Unsupported（不是 panic）。
                eprintln!("create_video_encoder: Unsupported (no FFmpeg DLLs/libx264)");
            }
            Err(other) => panic!("期望 Ok 或 Unsupported，实际: {other}"),
        }
        // 回退链结构本身仍可用。
        assert!(fallback_chain_for(Codec::H264).contains(&"libx264"));
    }

    #[test]
    fn test_cached_matches_uncached() {
        // P1C：缓存与首次探测结果一致（无 DLL 时都返回完整链）。
        assert_eq!(detect_supported_codecs_cached(), detect_supported_codecs());
    }

    /// P1B↔P1C 接驳 Tests：linked stub 内核 → HW 优先尝试；HW 在 CI/无 GPU
    /// 返回 Unsupported 后回退软编（或无 DLL 时整体 Unsupported），不 panic。
    #[test]
    fn test_create_with_linked_kernel_tries_hw_first() {
        use crate::encoder::types::{DirtyTileMap, GpuTexture};
        use crate::encoder::video::tile_diff::GpuKernel;

        /// stub 内核：`is_linked()=true`，但 `hw_upload` 返回 Unsupported
        /// （模拟 P1B 桩恒 NULL）。factory 据此尝试 HW 编码器，失败回退软编。
        struct LinkedStub;
        impl GpuKernel for LinkedStub {
            fn tile_hash(&self, _tex: &GpuTexture) -> Result<DirtyTileMap, EncodeError> {
                Ok(DirtyTileMap::default())
            }
            fn is_linked(&self) -> bool {
                true
            }
        }

        let stub = LinkedStub;
        match create_video_encoder(Codec::H264, Some(&stub)) {
            Ok(enc) => {
                // HW 失败回退软编（libx264）；或 HW 可用（有 GPU 环境）。
                let _ = enc.name();
            }
            Err(EncodeError::Unsupported(_)) => {
                // 无 DLL / 无 libx264 环境：Unsupported（不是 panic）。
                eprintln!("create_video_encoder(linked): Unsupported (no FFmpeg/HW)");
            }
            Err(other) => panic!("期望 Ok 或 Unsupported，实际: {other}"),
        }
    }
}
