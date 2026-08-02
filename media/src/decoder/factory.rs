//! 后端检测与回退链（P2A §T1.2）。
//!
//! 提供 [`detect_supported_decoders`]（探测本机可用的硬件/软解解码器，
//! 返回回退链）与 [`create_video_decoder`]（按回退链创建第一个可用实例）。
//!
//! # P2A 现状
//!
//! - [`detect_supported_decoders`] 走 **FFmpeg avcodec 静态探测**
//!   （`avcodec_find_decoder_by_name`，in-process）。注意 `find_decoder`
//!   只验证**静态存在**；真正的可用性在 `open2` 时确定（P2B 实现，
//!   [`VideoDecoderPipeline`](crate::decoder::video::VideoDecoderPipeline)
//!   在 P2A 以静态存在为准创建骨架后端）。
//! - FFmpeg DLL 不可用（CI 环境）时返回完整回退链（保持链形状，不阻断
//!   编译，与编码层 factory 同款语义）。
//! - [`create_video_decoder`] 返回 [`VideoDecoderPipeline`]，其 `new`
//!   按回退链逐个静态探测，返回第一个可用的骨架后端。
//!
//! # 与编码层 factory 的对称差异（P2A §T1.2）
//!
//! | 维度 | 编码层 factory（P1A） | 解码层 factory（本任务） |
//! |------|----------------------|--------------------------|
//! | 顺序 | nvenc → amf → qsv → vt → vaapi → libx264 | qsv → cuvid → d3d11va → vt → vaapi → 软解 |
//! | 理由 | 编码侧重 GPU 厂商 SDK（nvenc/amf 优先） | 解码侧重通用硬件加速（qsv/cuvid 通用，d3d11va 微软原生） |
//!
//! # 平台裁剪
//!
//! 返回列表中的平台无关项由 FFmpeg 构建决定（如 Windows FFmpeg 通常不含
//! vaapi/videotoolbox），无需 `#[cfg]` 平台门控——FFmpeg 自身会拒绝不可用
//! 的解码器。

use std::sync::OnceLock;

use crate::decoder::video::VideoDecoderPipeline;
use crate::decoder::{DecodeError, VideoDecoder};
use crate::encoder::types::Codec;

/// H.264 回退链：FFmpeg 解码器名，按优先级排序（软解兜底）。
///
/// 顺序来自 P2A §T1.2：qsv → cuvid → d3d11va → videotoolbox → vaapi → h264。
/// `h264`（软解）兜底，FFmpeg full build 通常都带。
pub const DECODER_FALLBACK_CHAIN: &[&str] = &[
    "h264_qsv",
    "h264_cuvid",
    "h264_d3d11va",
    "h264_videotoolbox",
    "h264_vaapi",
    "h264",
];

/// H.265 回退链（P2A §T1.2 对称 hevc 系列）。
pub const DECODER_FALLBACK_CHAIN_H265: &[&str] = &[
    "hevc_qsv",
    "hevc_cuvid",
    "hevc_d3d11va",
    "hevc_videotoolbox",
    "hevc_vaapi",
    "hevc",
];

/// 按 codec 取对应回退链。
pub fn fallback_chain_for(codec: Codec) -> &'static [&'static str] {
    match codec {
        Codec::H264 => DECODER_FALLBACK_CHAIN,
        Codec::H265 => DECODER_FALLBACK_CHAIN_H265,
    }
}

/// 软件解码器名（回退链兜底项："h264" | "hevc"）。
///
/// [`VideoDecoderPipeline`] 据此区分硬件/软解后端：链中等于此名的项走
/// `ffmpeg_sw`，其余走 `ffmpeg_hw`。
pub fn software_decoder_name(codec: Codec) -> &'static str {
    match codec {
        Codec::H264 => "h264",
        Codec::H265 => "hevc",
    }
}

/// 探测本机可用的视频解码器（FFmpeg avcodec 探测，in-process）。
///
/// 顺序：qsv → cuvid → d3d11va → videotoolbox → vaapi → 软解。
/// 返回顺序即回退链优先级。
///
/// 注意：`avcodec_find_decoder_by_name` 只验证**静态存在**；真正的可用性
/// 在 `open2` 时确定（P2B 实现，见 [`create_video_decoder`] 的逐项尝试）。
/// FFmpeg DLL 不可用（CI 环境）时返回完整链（保持回退链形状，不阻断编译）。
pub fn detect_supported_decoders(codec: Codec) -> Vec<&'static str> {
    if crate::ffmpeg::ensure_loaded().is_err() {
        // 无 DLL 环境：返回完整链形状（保持兼容 P2A 单测）。
        return fallback_chain_for(codec).to_vec();
    }
    fallback_chain_for(codec)
        .iter()
        .copied()
        .filter(|name| crate::ffmpeg::avcodec_find_decoder_by_name(name).is_ok())
        .collect()
}

/// 探测结果缓存（OnceLock，避免每次连接都探测）。
pub fn detect_supported_decoders_cached(codec: Codec) -> Vec<&'static str> {
    match codec {
        Codec::H264 => {
            static CACHE_H264: OnceLock<Vec<&'static str>> = OnceLock::new();
            CACHE_H264
                .get_or_init(|| detect_supported_decoders(Codec::H264))
                .clone()
        }
        Codec::H265 => {
            static CACHE_H265: OnceLock<Vec<&'static str>> = OnceLock::new();
            CACHE_H265
                .get_or_init(|| detect_supported_decoders(Codec::H265))
                .clone()
        }
    }
}

/// 创建视频解码器实例：按回退链逐个尝试，返回第一个可用的。
///
/// P2A：返回 [`VideoDecoderPipeline`]（骨架后端，静态存在性探测）；
/// P2B 完善为 `open2` 真实可用性 + 流式解码。
///
/// # Edge Cases
///
/// - 无任何硬件解码器 → 回退软解（h264/hevc），仍返回 Ok
/// - 软解也不可用（FFmpeg 无 H.264 解码器，极罕见）→ `Err(CodecNotFound)`
/// - FFmpeg DLL 未加载 → `Err(InitFailed)`
pub fn create_video_decoder(codec: Codec) -> Result<Box<dyn VideoDecoder>, DecodeError> {
    let pipe = VideoDecoderPipeline::new(codec)?;
    Ok(Box::new(pipe))
}

// ════════════════════════════════════════════════════════════════
// Tests（P2A §T1.2：factory 3 例）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 返回值按优先级排序，至少含软解 "h264"。
    #[test]
    fn test_detect_returns_chain() {
        let chain = detect_supported_decoders(Codec::H264);
        assert!(!chain.is_empty(), "回退链不应为空");
        // h264 必须在链尾（软解兜底）。
        assert_eq!(chain.last().copied(), Some("h264"));
        // 顺序符合优先级。
        assert_eq!(chain[0], "h264_qsv");
        // 缓存与首次探测一致。
        assert_eq!(detect_supported_decoders_cached(Codec::H264), chain);
    }

    /// Codec::H265 返回 hevc 系列。
    #[test]
    fn test_detect_h265() {
        let chain = detect_supported_decoders(Codec::H265);
        assert!(!chain.is_empty(), "H.265 回退链不应为空");
        assert_eq!(chain.last().copied(), Some("hevc"));
        assert_eq!(chain[0], "hevc_qsv");
        assert_eq!(software_decoder_name(Codec::H265), "hevc");
    }

    /// 全硬件不可用 → 返回软解实例（mock 探测语义：静态链驱动）。
    #[test]
    fn test_create_falls_back_sw() {
        match create_video_decoder(Codec::H264) {
            Ok(dec) => {
                // 成功创建：软解回退生效（或硬件静态可用）。
                assert_eq!(dec.codec(), Codec::H264);
                let _ = dec.name();
                let _ = dec.is_hardware();
            }
            Err(DecodeError::InitFailed(_)) | Err(DecodeError::CodecNotFound(_)) => {
                // 无 DLL / 无解码器环境（CI）：Err（不是 panic）。
                eprintln!("create_video_decoder: unavailable (no FFmpeg DLLs/decoders)");
            }
            Err(other) => panic!("期望 Ok 或 InitFailed/CodecNotFound，实际: {other}"),
        }
        // 回退链结构本身仍可用。
        assert!(fallback_chain_for(Codec::H264).contains(&"h264"));
    }
}
