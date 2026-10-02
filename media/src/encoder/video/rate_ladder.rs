//!
//! # 根因（用户实测：桌面↔桌面 IP 直连画质极差，13900ES 日志
//! `VBV maxrate specified, but no bufsize`）
//!
//! 修复前会话编码参数与分辨率**完全脱钩**：
//! - 软编（`ffmpeg_sw.rs`）：`b = maxrate = 2 Mbps` 硬编码、无 `bufsize`
//!   （x264 告警并忽略 maxrate，但 ABR 目标 `b` 仍把均值压死在 2M）——
//!   4K（3840×2160）@ ~10fps 下 bits-per-pixel ≈ 2e6 / (3840·2160·10) ≈
//!   **0.024 bpp**（可用画质通常需 ≥0.05 bpp）→ 必然糊成马赛克；
//! - 硬编（`ffmpeg_hw.rs`）：会话分辨率重开路径（`ensure_codec_dims`）从不
//!   应用码率/低延迟参数（探测 ctx 的 4M 配置随探测 ctx 一起丢弃）→ 编码器
//!   默认参数裸奔，码率不可控；
//! - `EncodeConfig.qp` 全链路无消费者（`reconfigure` no-op），qp26 从未生效。
//!
//! # 阶梯口径（用户裁定）
//!
//! | 输出分辨率（像素数口径，天然兼容竖屏/带鱼屏） | 目标码率 | 30fps 下 bpp |
//! |---|---|---|
//! | ≤ 720p（≤ ~1.2M px） | 4 Mbps | 0.19 |
//! | ≤ 1080p（≤ ~2.6M px） | 10 Mbps | 0.16 |
//! | ≤ 1440p / 1440 带鱼（≤ ~5.3M px） | 16 Mbps | 0.10 |
//! | > 1440p（4K 8.3M px 等） | 32 Mbps | 0.13 |
//!
//! 配套：`bufsize = b`（1 秒 VBV 窗口，修复「maxrate 无 bufsize」告警并使
//! 软编=无 HW 机器兜底路径，实时性优先——HW 优先路径不受影响）。
//!
//! 码率为**目标值**不是上限封顶：内容简单时编码器自然低于目标（桌面静态
//! 场景 + 窗口式编码，码率随内容波动），复杂时允许贴近目标——这正是
//! 修复「2M 一刀切压死 4K」的关键。

/// ≤ 此像素数 → 720p 档（1280×720 = 0.92M；含小幅上采样如 1366×768）。
const P_MAX_720P: u64 = 1_200_000;
/// ≤ 此像素数 → 1080p 档（1920×1080 = 2.07M；含 2048×1152 等）。
const P_MAX_1080P: u64 = 2_600_000;
/// ≤ 此像素数 → 1440p 档（2560×1440 = 3.69M；3440×1440 带鱼 = 4.96M）。
const P_MAX_1440P: u64 = 5_300_000;

///
/// 像素数口径 `w × h` 而非高度口径：竖屏（2160×3840）与带鱼屏
/// （3440×1440）无需特判。极端超大分辨率（5K+ = 14.7M px）同样落在 4K 档
pub fn bitrate_for_resolution(w: u32, h: u32) -> u64 {
    let px = w as u64 * h as u64;
    if px == 0 {
        // 异常兜底：探测/测试路径的最小合法档。
        return 4_000_000;
    }
    if px <= P_MAX_720P {
        4_000_000
    } else if px <= P_MAX_1080P {
        10_000_000
    } else if px <= P_MAX_1440P {
        16_000_000
    } else {
        32_000_000
    }
}

/// 软编（libx264/libx265）preset 阶梯。
///
/// HW 优先后，软编成为**全 HW 候选失败的机器**（无 GPU / 驱动异常 / 老机器）
/// testsrc2@30 CLI 基准 veryfast+t2 3.68x → ultrafast+t4 10.1x（≈2.7×
/// 提速，单帧 ~8ms → ~3ms，30fps 裕度充足）→ 统一 `ultrafast`。分辨率
/// 阶梯结构保留（函数签名不变，4K 档未来可独立调档）。码率阶梯
pub fn preset_for_resolution(_w: u32, _h: u32) -> &'static str {
    "ultrafast"
}

///
/// `bpp = bitrate / (w × h × fps)`。经验阈值：桌面内容 ≥ 0.05 bpp 可用、
/// ≥ 0.10 bpp 良好（本模块阶梯各档 30fps 下均 ≥ 0.10，720p/1080p 达 0.16+）。
/// 供单测断言与 codec_bench 数据输出共用。
pub fn bpp(bitrate_bps: u64, w: u32, h: u32, fps: f64) -> f64 {
    let px = w as u64 * h as u64;
    if px == 0 || fps <= 0.0 {
        return 0.0;
    }
    bitrate_bps as f64 / (px as f64 * fps)
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 阶梯映射：常见分辨率 → 目标档（含竖屏/带鱼屏/异常兜底）。
    #[test]
    fn test_bitrate_ladder_mapping() {
        // 720p 档。
        assert_eq!(bitrate_for_resolution(1280, 720), 4_000_000);
        assert_eq!(bitrate_for_resolution(1366, 768), 4_000_000);
        // 1080p 档。
        assert_eq!(bitrate_for_resolution(1920, 1080), 10_000_000);
        assert_eq!(bitrate_for_resolution(2048, 1152), 10_000_000);
        // 1440p 档（含带鱼屏 3440×1440 = 4.96M px）。
        assert_eq!(bitrate_for_resolution(2560, 1440), 16_000_000);
        assert_eq!(bitrate_for_resolution(3440, 1440), 16_000_000);
        // 4K 档（3840×2160 = 8.29M px；竖屏同像素数同档）。
        assert_eq!(bitrate_for_resolution(3840, 2160), 32_000_000);
        assert_eq!(bitrate_for_resolution(2160, 3840), 32_000_000);
        // 异常兜底：零尺寸 → 最小合法档（不 panic）。
        assert_eq!(bitrate_for_resolution(0, 0), 4_000_000);
    }

    /// 阶梯单调：像素数越多目标码率不降。
    #[test]
    fn test_bitrate_ladder_monotonic() {
        let cases = [
            (640u32, 360u32),
            (1280, 720),
            (1600, 900),
            (1920, 1080),
            (2560, 1440),
            (3200, 1800),
            (3840, 2160),
        ];
        for w in cases.windows(2) {
            let (a, b) = (w[0], w[1]);
            assert!(
                bitrate_for_resolution(b.0, b.1) >= bitrate_for_resolution(a.0, a.1),
                "ladder must be non-decreasing: {a:?} -> {b:?}"
            );
        }
    }

    /// 各档 30fps 下 bpp ≥ 0.05（可用画质下限；实际各档 ≥ 0.10）。
    /// 修复前 4K@2Mbps ≈ 0.024 bpp（远低于阈值）——本断言防再次"能通但糊"。
    #[test]
    fn test_ladder_bpp_floor() {
        for (w, h) in [(1280u32, 720u32), (1920, 1080), (2560, 1440), (3840, 2160)] {
            let b = bitrate_for_resolution(w, h);
            assert!(
                bpp(b, w, h, 30.0) >= 0.05,
                "{w}x{h} @ {b}bps: bpp {} 低于 0.05 可用下限",
                bpp(b, w, h, 30.0)
            );
        }
        // 修复前口径回归钉：2M 一刀切在 4K/10fps 下必然低于阈值。
        assert!(bpp(2_000_000, 3840, 2160, 10.0) < 0.05);
        assert!(bpp(2_000_000, 3840, 2160, 30.0) < 0.05);
    }

    #[test]
    fn test_preset_ladder() {
        assert_eq!(preset_for_resolution(1280, 720), "ultrafast");
        assert_eq!(preset_for_resolution(1920, 1080), "ultrafast");
        assert_eq!(preset_for_resolution(2560, 1440), "ultrafast");
        assert_eq!(preset_for_resolution(3440, 1440), "ultrafast");
        assert_eq!(preset_for_resolution(3840, 2160), "ultrafast");
    }

    /// bpp 边界：零尺寸/零 fps → 0（不 panic、不除零）。
    #[test]
    fn test_bpp_edge_cases() {
        assert_eq!(bpp(1_000_000, 0, 0, 30.0), 0.0);
        assert_eq!(bpp(1_000_000, 100, 100, 0.0), 0.0);
    }

    /// 实测量化（FFmpeg DLL 可用时）：阶梯码率下软编输出 bpp 不低于
    /// 0.05（复杂内容 + 首帧 IDR，ABR 已收敛方向）——修复"2M 压死 4K"
    /// 的端到端断言。
    #[test]
    fn test_sw_encoder_bpp_with_ladder() {
        use crate::encoder::types::{GpuTexture, Timestamp};
        use crate::encoder::video::pipeline::VideoEncoderPipeline;
        use crate::encoder::Codec;

        if crate::ffmpeg::ensure_loaded().is_err() {
            eprintln!("FFmpeg libraries not available; bpp test skipped");
            return;
        }
        let w = 1920u32;
        let h = 1080u32;
        let mut enc = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("SW encoder unavailable: {e}; bpp test skipped");
                return;
            }
        };
        // 伪随机内容（确定性 xorshift64*）——非纯色，逼迫编码器真实出码；
        // 相邻帧内容不同，避免 classify 判 Static 零输出。
        let mut seed = 0x2545F4914F6CDD1Du64;
        let frames = 30u32;
        let mut total_bytes = 0usize;
        // PTS 按生产节奏 +33ms/帧（WindowPipeline encode_current_window 的
        // pts_base 累加同款）：x264 ABR 的每帧比特预算由 PTS 间隔折算——
        // 若用 Timestamp::now()，帧间隔=实际编码耗时（不稳），30 帧的
        // 码率预算随耗时漂移，bpp 断言失真。
        let capture_instant = std::time::Instant::now();
        for i in 0..frames {
            seed = seed.rotate_left(13) ^ (i as u64 + 1);
            let mut rgba = Vec::with_capacity((w * h * 4) as usize);
            for _ in 0..(w * h) {
                seed ^= seed >> 12;
                seed ^= seed << 25;
                seed ^= seed >> 27;
                let r = (seed.wrapping_mul(0x2545F4914F6CDD1D)) as u8;
                rgba.extend_from_slice(&[r, r.wrapping_mul(3), r.wrapping_mul(7), 0xFF]);
            }
            enc.set_cpu_frame(&rgba, w, h, i == 0);
            let tex = GpuTexture::new(0x1usize as *mut _, w, h);
            let ts = Timestamp::new(capture_instant, i as u64 * 33);
            let pkts = enc.on_frame(&tex, ts).expect("encode");
            total_bytes += pkts.iter().map(|p| p.data.len()).sum::<usize>();
        }
        let bits = total_bytes as f64 * 8.0;
        let bpp = bits / (w as f64 * h as f64 * frames as f64);
        eprintln!(
        );
        assert!(
            bpp >= 0.05,
            "阶梯码率下软编输出 bpp={bpp:.4} 低于 0.05（疑似码率未按分辨率生效）"
        );
    }
}
