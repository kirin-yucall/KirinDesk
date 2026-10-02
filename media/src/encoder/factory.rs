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

///
/// 均软编（AV1 HW 编码器 av1_nvenc/av1_qsv/av1_amf 依赖 GPU 内核/驱动，
/// ——跨 codec 兜底（AV1 不可用 → H.264/libx264）由
/// 自动回退 H264 且无报错）。
pub const CODEC_FALLBACK_CHAIN_AV1: &[&str] = &["libsvtav1", "libaom_av1", "librav1e"];

/// 探测指定偏好 codec 本机可用的编码器（FFmpeg avcodec 探测，in-process）。
///
/// `avcodec_find_encoder_by_name` 过滤出静态存在的项。旧实现只探测 H264
/// 链且 `FfmpegHwEncoder::create` 对所有 codec 都从 H264 链取候选——
/// `pref=H265` 请求会误试 `h264_*` 编码器（codec 错配）；本函数按 pref
/// 分离候选链。
///
/// 注意 `find_encoder` 只验证**静态存在**；真正的可用性在 `open2` 时
/// 确定（由 [`create_video_encoder`] 的逐项尝试兜底）。
///
/// FFmpeg DLL 不可用（CI 环境）时返回该 codec 的完整链（保持回退链形状，
/// 不阻断编译）。
///
/// 返回顺序即回退链优先级。
pub fn detect_supported_codecs_for(pref: Codec) -> Vec<&'static str> {
    let chain = fallback_chain_for(pref);
    if crate::ffmpeg::ensure_loaded().is_err() {
        // 无 DLL 环境：返回完整链形状（保持兼容 P1A 单测）。
        return chain.to_vec();
    }
    chain
        .iter()
        .copied()
        .filter(|name| crate::ffmpeg::avcodec_find_encoder_by_name(name).is_ok())
        .collect()
}

/// 探测本机可用的编码器（FFmpeg avcodec 探测，in-process）——H.264 链。
///
/// 顺序：nvenc → amf → qsv → videotoolbox → vaapi → libx264。
///
/// P1C 真实探测：遍历 [`CODEC_FALLBACK_CHAIN`]，经
/// [`ffmpeg::api::avcodec_find_encoder_by_name`](crate::ffmpeg::avcodec_find_encoder_by_name)
/// 过滤出本机静态可用的项。
///
/// （保留旧签名/语义；其它 codec 候选见后者）。
///
/// FFmpeg DLL 不可用（CI 环境）时返回完整链（保持回退链形状，不阻断编译）。
///
/// 返回顺序即回退链优先级。
pub fn detect_supported_codecs() -> Vec<&'static str> {
    detect_supported_codecs_for(Codec::H264)
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
        Codec::AV1 => CODEC_FALLBACK_CHAIN_AV1,
    }
}

/// 上限（宽，px）——**≤960 宽**。
///
/// ~29ms/帧贴满 30fps 帧距（33ms）→ 门控随机拒绝 + 2 帧批窗 + 各段尖峰
/// 叠加 → e2e p95 255ms 尾巴。压到 ≤960 宽（1080p 像素量 -56%）恢复帧率
/// 预算（enc 目标 ≤15ms/帧）。**HW 路径不受本上限影响**（消费点按
/// `is_hardware()` 分治）；观众显式请求的更窄 `max_width` 优先（取小者）。
pub const SW_FALLBACK_MAX_WIDTH: u32 = 960;

/// `output_dims_for` 类「只降不升」尺寸计算消费）。
///
/// - `viewer_max_width == 0`（观众未请求降采样）→ 本上限 960；
/// - `viewer_max_width > 0` → 与观众请求取小者（观众自请更窄则从观众）；
/// - 返回 0 不会发生（本上限恒 >0）。
pub fn sw_fallback_output_width(viewer_max_width: u32) -> u32 {
    if viewer_max_width == 0 {
        SW_FALLBACK_MAX_WIDTH
    } else {
        viewer_max_width.min(SW_FALLBACK_MAX_WIDTH)
    }
}

/// → H.264（libx264 兜底）。H.264/H.265 保持原语义（无跨 codec 回退，
/// 避免改变既有协商行为）。
fn cross_fallback_chain(pref: Codec) -> &'static [Codec] {
    match pref {
        Codec::AV1 => &[Codec::AV1, Codec::H264],
        Codec::H264 => &[Codec::H264],
        Codec::H265 => &[Codec::H265],
    }
}

/// 创建视频编码器实例：按回退链逐个尝试，返回第一个可用的。
///
/// （libsvtav1 → libaom_av1 → librav1e）不可用 → 自动回退 H.264（libx264
/// 兜底），**返回 Ok 而非报错**（验收：无 AV1 编码器 → 自动回退 H264 且无
/// 报错）。H.264/H.265 行为不变（无跨 codec 回退）。
///
///
/// **全平台恒 HW 优先**（HW 候选链 → 全失败回退软编），不再按
/// `kernel.is_linked()` 门控。`kernel` 只影响 encode 时**输入路径**偏好
/// （linked 且真实 GPU 纹理 → 零拷贝 `hw_upload`；未链接 → CPU NV12
/// `set_cpu_frame`），不再决定编码器后端档位。
///
/// 历史口径（P1B↔P1C 接驳 2026-07-31 / macOS 例外 M12-MAC 2026-08-01）：
/// 非 macOS 仅 kernel 链接时 HW 优先，kernel=None 时软编优先——理由是
/// 「HW 编码器 CPU NV12 帧输入路径不产出包」。该理由已**失效**：CPU NV12
/// 输入路径（`set_cpu_frame` → sws RGBA→NV12 → send_frame）是 macOS
/// 生产路径（M12-MAC 无 D3D11 内核即恒 HW 优先 videotoolbox），且
/// h264_qsv 经 ZM-01 S2（2026-08-02，Intel UHD 770 实机，含
/// flush 边界）验证。旧门控致发行 Windows 包（`gpu-kernel` feature
/// off → kernel=None）**恒落 libx264、h264_qsv 从未被探测**——2026-09-04
/// open2 崩溃在子进程隔离，qsv 探测失败返回干净错误不崩进程）。
///
/// # Edge Cases
///
/// - libx264/libx265 不可用（FFmpeg 无软编）且 HW 全失败 → `Err(Unsupported)`
/// - 探测结果缓存（[`detect_supported_codecs_cached`]），避免每次连接都探测
/// - HW 编码器在本机不可用（无 GPU / 驱动缺失）→ HW 失败后回退软编，不阻断
pub fn create_video_encoder(
    pref: Codec,
    kernel: Option<&dyn GpuKernel>,
) -> Result<Box<dyn VideoEncoder>, EncodeError> {
    let mut last_err: Option<EncodeError> = None;
    for attempt in cross_fallback_chain(pref) {
        if attempt != &pref {
            tracing::warn!(
                last_err.as_ref().map(|e| e.to_string()).unwrap_or_default()
            );
        }
        match create_video_encoder_single(*attempt, kernel) {
            Ok(enc) => return Ok(enc),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        EncodeError::Unsupported("no video encoder available (all codec chains failed)".into())
    }))
}

/// [`create_video_encoder`] 的单 codec 实现（不跨 codec 回退）。
fn create_video_encoder_single(
    pref: Codec,
    kernel: Option<&dyn GpuKernel>,
) -> Result<Box<dyn VideoEncoder>, EncodeError> {
    // 与 AV1 不匹配（pref=AV1 会误开 h264 HW 编码器 → codec() 报 AV1 但码流
    // 实为 H.264）。AV1 走软编（SVT-AV1），HW AV1（av1_nvenc/av1_qsv/av1_amf）
    let hw_capable = pref != Codec::AV1;

    // → 软编优先」门控废止——它让发行 Windows 包（gpu-kernel feature off）
    // 恒选 libx264、h264_qsv 从未被探测（2026-09-04 被控端 1080p 软编
    // 瓶颈根因，详见 [`create_video_encoder`] 文档「后端优先序」）。
    // kernel=None 时 HW 编码器走 CPU NV12 输入路径（macOS 生产路径同款）。
    if hw_capable {
        // HW 优先：失败再回退软编。
        if let Ok(hw) = FfmpegHwEncoder::create(pref, kernel) {
            return Ok(Box::new(hw));
        }
        if let Ok(sw) = FfmpegSwEncoder::create(pref) {
            return Ok(Box::new(sw));
        }
    } else {
        // AV1：软编 only（HW AV1 链未接入，见上）。
        if let Ok(sw) = FfmpegSwEncoder::create(pref) {
            return Ok(Box::new(sw));
        }
    }
    // HW all failed"，AV1 链失败时误导排查）；该文本经 last_err 传入
    // [`create_video_encoder`] 的跨 codec 兜底 warn（:142），并携带
    Err(EncodeError::Unsupported(
        encoder_unavailable_msg(pref, hw_capable).into(),
    ))
}

///
/// 旧实现恒报 `"no video encoder available (libx264/libx265 + HW all
/// failed)"`——AV1 链失败（软编 libsvtav1 不可用且 AV1 HW 链未接入）时该
/// 文案误导排查。此消息经 `last_err` 传入 [`create_video_encoder`] 的跨
/// codec 兜底 warn（factory.rs:142），须点名真实失败的软编名。
fn encoder_unavailable_msg(pref: Codec, hw_capable: bool) -> String {
    let sw_name = pref.ffmpeg_sw_name();
    if hw_capable {
        format!("no video encoder available ({sw_name} + HW all failed)")
    } else {
    }
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

    #[test]
    fn test_av1_fallback_chain_and_cross_fallback() {
        // AV1 链：SVT-AV1 优先，libaom/rav1e 候补（软编；无链尾兜底——跨
        // codec 兜底由 create_video_encoder 协商路径负责）。
        let av1 = fallback_chain_for(Codec::AV1);
        assert_eq!(av1, CODEC_FALLBACK_CHAIN_AV1);
        assert_eq!(av1[0], "libsvtav1");
        assert_eq!(av1.last().copied(), Some("librav1e"));
        // 跨 codec 兜底：AV1 → H.264（libx264 兜底）；H.264/H.265 无跨 codec。
        assert_eq!(cross_fallback_chain(Codec::AV1), &[Codec::AV1, Codec::H264]);
        assert_eq!(cross_fallback_chain(Codec::H264), &[Codec::H264]);
        assert_eq!(cross_fallback_chain(Codec::H265), &[Codec::H265]);
    }

    /// 编码器（老构建/无 DLL）→ 自动回退 H.264（libx264 兜底），仍返回 Ok。
    #[test]
    fn test_create_av1_falls_back_without_error() {
        match create_video_encoder(Codec::AV1, None) {
            Ok(enc) => {
                if enc.codec() == Codec::AV1 {
                    // AV1 编码器可用：SVT-AV1 优先（本机捆绑 8.1.1 full build
                    // 含 libsvtav1，静态编入 avcodec-62.dll）。
                    assert!(
                        matches!(enc.name(), "libsvtav1" | "libaom_av1" | "librav1e"),
                        "AV1 encoder name unexpected: {}",
                        enc.name()
                    );
                    assert!(!enc.is_hardware(), "AV1 当前走软编（SVT-AV1）");
                } else {
                    // 回退链生效：无 AV1 编码器 → H.264 兜底，无报错。
                    assert_eq!(enc.codec(), Codec::H264);
                }
            }
            Err(EncodeError::Unsupported(_)) => {
                // 无 FFmpeg DLL / 全链不可用环境：Unsupported（不是 panic）。
                eprintln!("create_video_encoder(AV1): Unsupported (no FFmpeg DLLs/encoders)");
            }
            Err(other) => panic!("期望 Ok 或 Unsupported，实际: {other}"),
        }
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

    /// kernel=None 恒软编先手，QSV 从未被探测，2026-09-04 被控端瓶颈根因）：
    /// 有 HW 环境（实机 exe 语境，QSV 探测通过）→ 选 HW（QSV 优先重排）；
    /// 不识别 --probe-hw-encoder 以非零退出 → 候选全部判不可用）→ libx264
    /// 兜底。两分支均允许，但名字必须落在各自契约集合内（HW 名字不得是
    /// 软编名、软编名字必须是 libx264）。
    #[test]
    fn test_r76d_h264_selection_hw_or_sw_contract() {
        match create_video_encoder(Codec::H264, None) {
            Ok(enc) => {
                if enc.is_hardware() {
                    assert!(
                        matches!(
                            enc.name(),
                            "h264_qsv"
                                | "h264_nvenc"
                                | "h264_amf"
                                | "h264_videotoolbox"
                                | "h264_vaapi"
                        ),
                        "HW 编码器名字超契约: {}",
                        enc.name()
                    );
                } else {
                    assert_eq!(enc.name(), "libx264", "软编兜底必须是 libx264");
                }
            }
            Err(EncodeError::Unsupported(_)) => {
                // 无 DLL / 全链不可用环境（CI）：Unsupported（不是 panic）。
                eprintln!("create_video_encoder(H264): Unsupported (no FFmpeg/encoders)");
            }
            Err(other) => panic!("期望 Ok 或 Unsupported，实际: {other}"),
        }
    }

    /// H264 链，H265 请求误试 h264_* 编码器=codec 错配）；H264 链不得含
    /// hevc_*。
    #[test]
    fn test_r76d_candidates_separated_by_pref() {
        let h265 = detect_supported_codecs_for(Codec::H265);
        assert!(
            h265
                .iter()
                .all(|n| n.starts_with("hevc") || *n == "libx265"),
            "H265 候选链不得含 h264_*: {h265:?}"
        );
        assert!(
            h265.iter().any(|n| *n == "libx265" || n.starts_with("hevc")),
            "H265 候选链非空: {h265:?}"
        );
        let h264 = detect_supported_codecs_for(Codec::H264);
        assert!(
            h264
                .iter()
                .all(|n| n.starts_with("h264") || *n == "libx264"),
            "H264 候选链不得含 hevc_*: {h264:?}"
        );
        assert_eq!(detect_supported_codecs(), h264, "旧签名=H264 链（包装语义保持）");
    }

    /// libsvtav1 + 注明 HW 链未接入，不再报 "libx264/libx265 + HW all
    /// failed"；H264/H265 点名各自软编名。
    #[test]
    fn test_r76d_error_message_per_codec() {
        let av1 = encoder_unavailable_msg(Codec::AV1, false);
        assert!(av1.contains("libsvtav1"), "AV1 消息应点名 libsvtav1: {av1}");
        assert!(av1.contains("AV1 HW 链未接入"), "{av1}");
        assert!(!av1.contains("libx264"), "AV1 消息不得混入 H264 软编名: {av1}");
        assert_eq!(
            encoder_unavailable_msg(Codec::H264, true),
            "no video encoder available (libx264 + HW all failed)"
        );
        assert_eq!(
            encoder_unavailable_msg(Codec::H265, true),
            "no video encoder available (libx265 + HW all failed)"
        );
    }

    /// 960；观众请求更窄 → 从观众；相等边界。
    #[test]
    fn test_r88b3_sw_fallback_output_width() {
        assert_eq!(SW_FALLBACK_MAX_WIDTH, 960, "上限钉死 ≤960 宽");
        assert_eq!(sw_fallback_output_width(0), 960, "观众未请求 → 软编上限 960");
        assert_eq!(sw_fallback_output_width(1920), 960, "观众请求 > 上限 → 上限");
        assert_eq!(sw_fallback_output_width(1280), 960, "1280 请求压到 960");
        assert_eq!(sw_fallback_output_width(960), 960, "相等边界");
        assert_eq!(sw_fallback_output_width(720), 720, "观众请求更窄 → 从观众");
    }
}
