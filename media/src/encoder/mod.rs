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
pub const CODEC_AV1: &str = "av1";

/// 检测本机可用编码（握手用：返回 codec 字符串列表，按优先级）。
///
/// 与 [`factory::detect_supported_codecs`]（返回 FFmpeg 编码器名回退链）
/// 语义不同——本函数返回**协商用 codec 字符串**（`"h264"` / `"h265"` /
/// `"av1"`），服务于传输握手。
///
/// 内部已含「AV1 不可用 → 回退 H.264」兜底，此处仅按**实际选中 codec**
/// 上报——即 AV1 协商成功仅当编码器真的落在 AV1 上）。
pub fn detect_supported_codecs() -> Vec<&'static str> {
    let mut codecs = Vec::new();
    // 优先级：AV1（码率效率 ~6×，探索结论）→ H.265 → H.264 兜底。
    if let Ok(enc) = factory::create_video_encoder(Codec::AV1, None) {
        if enc.codec() == Codec::AV1 {
            codecs.push(CODEC_AV1);
        }
    }
    if factory::create_video_encoder(Codec::H265, None).is_ok() {
        codecs.push(CODEC_H265);
    }
    if factory::create_video_encoder(Codec::H264, None).is_ok() {
        codecs.push(CODEC_H264);
    }
    codecs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapProbeOutcome {
    /// 命中：直接返回缓存值，不探测。
    Hit,
    /// 未命中：需真实探测（结果写回缓存）。
    Miss,
}

///
/// 旧实现为 `OnceLock` 盲缓存——缓存键不含任何开关：进程生命周期内若
/// 影响探测结果的开关变化（测试/生产互染场景），会恒返回首个结果。
/// `KIRIN_NOHW_HW_DECODE`）；键变化 → 必未命中 → 重新探测（保守
/// 方向：绝不对异键返回旧值）。
pub(crate) struct CapProbeCache {
    entry: std::sync::Mutex<Option<(String, Vec<&'static str>)>>,
}

impl CapProbeCache {
    fn new() -> Self {
        Self {
            entry: std::sync::Mutex::new(None),
        }
    }

    /// 查找 + 探测决策（单一点）：键一致 → [`CapProbeOutcome::Hit`]
    /// （不调 `probe`）；首调或键不一致 → [`CapProbeOutcome::Miss`]
    /// （调 `probe` 并写回）。
    fn get_or_probe(
        &self,
        key: &str,
        probe: impl FnOnce() -> Vec<&'static str>,
    ) -> (Vec<&'static str>, CapProbeOutcome) {
        {
            let guard = self.entry.lock().unwrap();
            if let Some((k, v)) = guard.as_ref() {
                if k == key {
                    return (v.clone(), CapProbeOutcome::Hit);
                }
            }
        }
        let v = probe();
        *self.entry.lock().unwrap() = Some((key.to_string(), v.clone()));
        (v, CapProbeOutcome::Miss)
    }
}

///
/// - `KIRIN_NOHW_HW_DECODE`（PM 裁定至少含；生效值口径与
///   [`crate::decoder::factory::hw_decode_disabled`] 一致）；
/// - `KIRIN_HW_PROBE_DISABLE`（存在即逃生开关：全部 HW 候选视不可用，
///   `ffmpeg_hw::hw_encoder_available`——探测结果形状改变）；
/// - `KIRIN_GPU_PREFER`（探测子进程按该偏好对齐 GPU 适配器
///   （`ffmpeg_hw::probe_child_main`）→ 影响 HW 可用性结果）。
///
/// 语义：取值全同 → 键相同（可命中）；任一开关变化 → 键不同 →
/// 绕过缓存重新探测（防测试/生产互染）。
pub(crate) fn cap_probe_cache_key(
    disable_hw_decode: bool,
    hw_probe_disable: bool,
    gpu_prefer: Option<&str>,
) -> String {
    format!(
        "KIRIN_NOHW_HW_DECODE={disable_hw_decode};KIRIN_HW_PROBE_DISABLE={hw_probe_disable};KIRIN_GPU_PREFER={}",
        gpu_prefer.map(|s| s.trim().to_ascii_lowercase()).unwrap_or_default()
    )
}

/// 不经此处，避免并行测试改 env 互染）。
fn current_cap_probe_key() -> String {
    cap_probe_cache_key(
        crate::decoder::factory::hw_decode_disabled(),
        std::env::var_os("KIRIN_HW_PROBE_DISABLE").is_some(),
        std::env::var("KIRIN_GPU_PREFER").ok().as_deref(),
    )
}

/// [`detect_supported_codecs`] 的缓存版（服务端每次握手避免重复创建编码器）。
///
/// （QSV 机器 ~1.3s，一次性可接受——PM 裁定）→ 缓存；后续握手直接
/// 命中（µs 级，不建 hwdevice）。缓存键含影响探测结果的开关（至少
/// `KIRIN_NOHW_HW_DECODE`）——开关变化 → 键变 → 重新探测（缓存值
/// 恒尊重开关当前值，命中≠降低协商正确性）。日志：未命中一行含耗时、
/// 命中一行（用户复测对账「第二次连接响应 50ms 级」）。
///
/// 协商语义不变：首个会话仍按实际探测结果协商（首连必为真实探测）。
/// 探测本身不改（AV1→H265→H264 顺序/次数不动）。
pub fn detect_supported_codecs_cached() -> Vec<&'static str> {
    static CACHE: std::sync::OnceLock<CapProbeCache> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(CapProbeCache::new);
    let key = current_cap_probe_key();
    let started = std::time::Instant::now();
    let (caps, outcome) = cache.get_or_probe(&key, detect_supported_codecs);
    match outcome {
        CapProbeOutcome::Hit => {
        }
        CapProbeOutcome::Miss => tracing::info!(
            caps,
            started.elapsed().as_millis(),
        ),
    }
    caps
}

// ════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// （真实探测被调 1 次）；同键再调必命中（探测闭包不再被调、
    /// 命中值与探测结果一致）。
    #[test]
    fn r83e_cap_probe_cache_hit_miss_pure_logic() {
        let cache = CapProbeCache::new();
        let key = cap_probe_cache_key(false, false, None);
        let mut probe_calls = 0u32;
        let (v1, o1) = cache.get_or_probe(&key, || {
            probe_calls += 1;
            vec!["av1", "h265", "h264"]
        });
        assert_eq!(o1, CapProbeOutcome::Miss, "首调必未命中（真实探测）");
        assert_eq!(probe_calls, 1);
        assert_eq!(v1, vec!["av1", "h265", "h264"]);

        let (v2, o2) = cache.get_or_probe(&key, || {
            probe_calls += 1;
            vec!["av1", "h265", "h264"]
        });
        assert_eq!(o2, CapProbeOutcome::Hit, "同键必命中");
        assert_eq!(probe_calls, 1, "命中不得再调探测闭包");
        assert_eq!(v2, v1, "命中值与探测结果一致");
    }

    /// 键变 → 绕过缓存重新探测（旧 `OnceLock` 盲缓存会恒返回首个
    /// 结果=测试/生产互染）；`KIRIN_HW_PROBE_DISABLE` 存在性同样改键；
    /// 同值键稳定（可命中）；单槽语义：异键恒重新探测、绝不对异键
    /// 返回旧值（保守方向）。
    #[test]
    fn r83e_cap_probe_cache_switch_sensitivity() {
        // 键纯逻辑：同值→同键；任一开关变→异键。
        let off = cap_probe_cache_key(false, false, None);
        let on = cap_probe_cache_key(true, false, None);
        assert_ne!(off, on, "KIRIN_NOHW_HW_DECODE 翻转必改键");
        assert_ne!(
            cap_probe_cache_key(false, false, None),
            cap_probe_cache_key(false, true, None),
            "KIRIN_HW_PROBE_DISABLE 存在性必改键"
        );
        assert_ne!(
            cap_probe_cache_key(false, false, None),
            cap_probe_cache_key(false, false, Some("discrete")),
            "KIRIN_GPU_PREFER 变化必改键"
        );
        assert_eq!(off, cap_probe_cache_key(false, false, None), "同值键稳定（可命中）");
        assert!(
            on.contains("KIRIN_NOHW_HW_DECODE=true"),
            "键含开关名与值（可追溯）"
        );

        // 缓存行为：开关翻转 → 键变 → 未命中（绕过重探）。
        let cache = CapProbeCache::new();
        let mut probe_calls = 0u32;
        let (_, o1) = cache.get_or_probe(&off, || {
            probe_calls += 1;
            vec!["h264"]
        });
        assert_eq!(o1, CapProbeOutcome::Miss);
        let (_, o2) = cache.get_or_probe(&on, || {
            probe_calls += 1;
            vec!["h264"]
        });
        assert_eq!(o2, CapProbeOutcome::Miss, "开关翻转必绕过缓存（重探，不返回旧值）");
        assert_eq!(probe_calls, 2);
        // 翻转回来 → 仍未命中（单槽缓存保守重探；写回后同键再调命中）。
        let (_, o3) = cache.get_or_probe(&off, || {
            probe_calls += 1;
            vec!["h264"]
        });
        assert_eq!(o3, CapProbeOutcome::Miss);
        assert_eq!(probe_calls, 3);
        let (_, o4) = cache.get_or_probe(&off, || {
            probe_calls += 1;
            vec!["h264"]
        });
        assert_eq!(o4, CapProbeOutcome::Hit, "重探写回后同键命中");
        assert_eq!(probe_calls, 3);
    }
}
