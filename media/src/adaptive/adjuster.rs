//! QP/帧率调整计算 + 编码超时保护。
//!
//! `Adjuster` 根据网络状态和编码耗时，计算下一窗口的编码配置。
//! 超时保护独立于网络拥塞——编码器性能不足时主动降级。
//!
//! # M13-T003 带宽自适应
//!
//! 除状态机（丢包率 + RTT）驱动的档位外，`compute_config` 还叠加
//! **低带宽 / 高延迟**即时降质：
//!
//! - 低带宽（客户端接收速率 < [`LOW_BANDWIDTH_BPS`] 5Mbps）→ QP+2、帧率 ×0.7
//! - 高延迟（RTT ≥ [`HIGH_RTT_MS`] 100ms）→ QP+2、帧率 ×0.7
//! - 两者叠加 ≤ QP 35、帧率 ≥ 0.1；良好条件（带宽足 + 低 RTT）全力发送
//!
//! "更少 tile"的语义由 QP/跳帧承担——tile 粒度裁剪属编码器前置决策层
//! （`TileDiff`，仅变化区域送入窗口），此处不重复实现。

use crate::adaptive::state_machine::HIGH_RTT_MS;
use crate::adaptive::NetworkSample;
use crate::adaptive::NetworkState;
use crate::proto::EncodeConfig;

/// 低带宽阈值（bps）：客户端接收速率低于此值追加降质（M13-T003，<5Mbps）。
pub const LOW_BANDWIDTH_BPS: u64 = 5_000_000;

/// 低带宽追加的 QP 增量。
const LOW_BANDWIDTH_QP_PENALTY: u32 = 2;
/// 低带宽 / 高延迟追加的帧率衰减系数。
const DEGRADE_RATIO_FACTOR: f64 = 0.7;

// ════════════════════════════════════════════════════════════════
// QP 映射
// ════════════════════════════════════════════════════════════════

/// 根据网络状态返回基础 QP。
pub fn base_qp_for_state(state: NetworkState) -> u32 {
    match state {
        NetworkState::Good => 22,
        NetworkState::MildCongestion => 28,
        NetworkState::SevereCongestion => 32,
    }
}

/// 根据网络状态返回帧保留比例。
pub fn base_frame_ratio_for_state(state: NetworkState) -> f64 {
    match state {
        NetworkState::Good => 1.0,
        NetworkState::MildCongestion => 0.5,
        NetworkState::SevereCongestion => 0.2,
    }
}

/// 根据网络状态返回编码器预设。
pub fn base_preset_for_state(state: NetworkState) -> &'static str {
    match state {
        NetworkState::Good => "veryfast",
        NetworkState::MildCongestion => "ultrafast",
        NetworkState::SevereCongestion => "ultrafast",
    }
}

// ════════════════════════════════════════════════════════════════
// 帧选择（纯函数）
// ════════════════════════════════════════════════════════════════

/// 根据 frame_ratio 计算窗口内保留帧的索引。
///
/// # 语义
///
/// - `ratio = 1.0` — 全部保留
/// - `ratio = 0.5` — 隔一帧取一帧
/// - `ratio ≤ 0.2` — 仅首帧（严重拥塞 / 极低质量）
///
/// # 示例
///
/// ```
/// # use kirin_desk_media::adaptive::adjuster::select_frames;
/// assert_eq!(select_frames(8, 1.0), vec![0, 1, 2, 3, 4, 5, 6, 7]);
/// assert_eq!(select_frames(8, 0.5), vec![0, 2, 4, 6]);
/// assert_eq!(select_frames(8, 0.2), vec![0]);           // 严重拥塞：仅首帧
/// assert_eq!(select_frames(8, 0.0), vec![0]);           // 0 被 clamp
/// ```
pub fn select_frames(frame_count: usize, frame_ratio: f64) -> Vec<usize> {
    if frame_ratio <= 0.2 {
        // 严重拥塞 / 极低质量：仅保留第一帧（IDR 帧）
        return vec![0];
    }
    let step = (1.0 / frame_ratio.max(0.1)).ceil() as usize;
    (0..frame_count).step_by(step).collect()
}

// ════════════════════════════════════════════════════════════════
// Adjuster
// ════════════════════════════════════════════════════════════════

/// 编码参数调整器。
pub struct Adjuster {
    /// 当前屏幕宽度（像素）
    pub screen_w: u32,
    /// 当前屏幕高度（像素）
    pub screen_h: u32,
    /// 上次编码耗时 (ms)
    pub last_encode_ms: f64,
    /// 上次使用的 QP
    pub last_qp: u32,
    /// 上次使用的 frame_ratio
    pub last_ratio: f64,
    /// 上次使用的 preset
    pub last_preset: String,
}

impl Adjuster {
    /// 创建新的调整器。
    pub fn new(screen_w: u32, screen_h: u32) -> Self {
        Self {
            screen_w,
            screen_h,
            last_encode_ms: 0.0,
            last_qp: EncodeConfig::default().qp,
            last_ratio: EncodeConfig::default().frame_ratio,
            last_preset: EncodeConfig::default().preset,
        }
    }

    /// 根据网络状态 + 采样，计算下一窗口的编码配置。
    pub fn compute_config(&mut self, state: NetworkState, sample: &NetworkSample) -> EncodeConfig {
        // 1. 基础 QP
        let mut qp = base_qp_for_state(state);

        // 2. 按丢包率微调 QP（每 1% 丢包 +1 QP）
        if sample.loss_rate > 0.0 {
            let extra = (sample.loss_rate * 100.0) as u32;
            qp = (qp + extra).min(35);
        }

        // 3. frame_ratio
        let mut frame_ratio = base_frame_ratio_for_state(state);

        // 4. preset
        let preset = base_preset_for_state(state).to_string();

        // 5. M13-T003 带宽/延迟自适应（叠加降质，上限 QP 35 / 帧率 ≥ 0.1）：
        //    - 低带宽（<5Mbps）→ 降低码率（QP+2）+ 降低帧率（×0.7）
        //    - 高延迟（RTT ≥ 100ms）→ 同样降质（M13 文档：高延迟降质量/帧率）
        if sample.received_bitrate_bps < LOW_BANDWIDTH_BPS as f64 {
            qp = (qp + LOW_BANDWIDTH_QP_PENALTY).min(35);
            frame_ratio *= DEGRADE_RATIO_FACTOR;
        }
        if sample.rtt_ms >= HIGH_RTT_MS {
            qp = (qp + LOW_BANDWIDTH_QP_PENALTY).min(35);
            frame_ratio *= DEGRADE_RATIO_FACTOR;
        }
        frame_ratio = frame_ratio.max(0.1);

        // 6. 保存
        self.last_qp = qp;
        self.last_ratio = frame_ratio;
        self.last_preset = preset.clone();

        EncodeConfig {
            qp,
            force_idr: false,
            frame_ratio,
            preset,
        }
    }

    /// 处理编码超时。
    ///
    /// 在 `AdaptiveEngine::on_encode_complete()` 中调用。
    /// 返回降级后的配置。
    pub fn handle_encode_timeout(&mut self, encode_ms: f64) -> EncodeConfig {
        self.last_encode_ms = encode_ms;

        if encode_ms > 70.0 {
            // 超时 → 显著降级
            let new_qp = (self.last_qp + 4).min(40);
            let new_ratio = (self.last_ratio * 0.5).max(0.1);

            self.last_qp = new_qp;
            self.last_ratio = new_ratio;
            self.last_preset = "ultrafast".into();

            EncodeConfig {
                qp: new_qp,
                frame_ratio: new_ratio,
                force_idr: false,
                preset: "ultrafast".into(),
            }
        } else if encode_ms > 50.0 {
            // 接近超时 → 轻度降级
            let new_ratio = (self.last_ratio * 0.75).max(0.2);

            self.last_ratio = new_ratio;

            EncodeConfig {
                qp: self.last_qp,
                frame_ratio: new_ratio,
                force_idr: false,
                preset: self.last_preset.clone(),
            }
        } else {
            // 正常——返回当前配置（调用者应忽略）
            EncodeConfig {
                qp: self.last_qp,
                frame_ratio: self.last_ratio,
                force_idr: false,
                preset: self.last_preset.clone(),
            }
        }
    }

    /// 逐步恢复 QP（快速恢复）。
    ///
    /// 每次编码耗时正常时调用一次。QP 每次降 2 直到目标值。
    pub fn recover_qp(&mut self, state: NetworkState) {
        let target_qp = base_qp_for_state(state);
        if self.last_qp > target_qp {
            self.last_qp = self.last_qp.saturating_sub(2).max(target_qp);
        }
    }

    /// 获取当前分辨率。
    pub fn resolution(&self) -> (u32, u32) {
        (self.screen_w, self.screen_h)
    }
}

// ── 测试 ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn sample(loss_rate: f64) -> NetworkSample {
        NetworkSample {
            loss_rate,
            rtt_ms: 30.0,
            jitter_us: 500.0,
            received_bitrate_bps: 8_000_000.0,
            timestamp: Instant::now(),
        }
    }

    #[test]
    fn test_select_frames_all() {
        assert_eq!(select_frames(8, 1.0), vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_select_frames_half() {
        assert_eq!(select_frames(8, 0.5), vec![0, 2, 4, 6]);
    }

    #[test]
    fn test_select_frames_minimal() {
        let result = select_frames(8, 0.2);
        // 严重拥塞：仅首帧
        assert_eq!(result, vec![0]);
    }

    #[test]
    fn test_select_frames_extreme() {
        assert_eq!(select_frames(8, 0.15), vec![0]); // < 0.2 → 仅首帧
        assert_eq!(select_frames(8, 0.0), vec![0]); // 0 被 clamp → 仅首帧
    }

    #[test]
    fn test_select_frames_single() {
        assert_eq!(select_frames(1, 0.5), vec![0]);
    }

    #[test]
    fn test_select_frames_zero_is_clamped() {
        let result = select_frames(8, 0.0);
        assert_eq!(result, vec![0]); // clamped to 0.1 → 0.1 ≤ 0.2 → 仅首帧
    }

    #[test]
    fn test_qp_mapping_good() {
        assert_eq!(base_qp_for_state(NetworkState::Good), 22);
    }

    #[test]
    fn test_qp_mapping_mild() {
        assert_eq!(base_qp_for_state(NetworkState::MildCongestion), 28);
    }

    #[test]
    fn test_qp_mapping_severe() {
        assert_eq!(base_qp_for_state(NetworkState::SevereCongestion), 32);
    }

    #[test]
    fn test_compute_config_good() {
        let mut adj = Adjuster::new(1920, 1080);
        let config = adj.compute_config(NetworkState::Good, &sample(0.003));
        assert_eq!(config.qp, 22);
        assert_eq!(config.frame_ratio, 1.0);
        assert_eq!(config.preset, "veryfast");
        assert!(!config.force_idr);
    }

    #[test]
    fn test_compute_config_mild() {
        let mut adj = Adjuster::new(1920, 1080);
        let config = adj.compute_config(NetworkState::MildCongestion, &sample(0.025));
        assert_eq!(config.qp, 28 + 2); // 2.5% → extra=2
        assert_eq!(config.frame_ratio, 0.5);
        assert_eq!(config.preset, "ultrafast");
    }

    #[test]
    fn test_compute_config_severe() {
        let mut adj = Adjuster::new(1920, 1080);
        let config = adj.compute_config(NetworkState::SevereCongestion, &sample(0.08));
        // 32 + 8 = 40, clamped at 35
        assert_eq!(config.qp, 35);
        assert_eq!(config.frame_ratio, 0.2);
    }

    #[test]
    fn test_timeout_normal_no_change() {
        let mut adj = Adjuster::new(1920, 1080);
        adj.compute_config(NetworkState::Good, &sample(0.003));
        let config = adj.handle_encode_timeout(30.0);
        assert_eq!(config.qp, 22);
        assert_eq!(config.frame_ratio, 1.0);
    }

    #[test]
    fn test_timeout_near_threshold() {
        let mut adj = Adjuster::new(1920, 1080);
        adj.compute_config(NetworkState::Good, &sample(0.003));
        let config = adj.handle_encode_timeout(55.0);
        assert_eq!(config.qp, 22); // QP 不变
        assert_eq!(config.frame_ratio, 0.75); // 1.0 * 0.75
    }

    #[test]
    fn test_timeout_exceeded() {
        let mut adj = Adjuster::new(1920, 1080);
        adj.compute_config(NetworkState::Good, &sample(0.003));
        let config = adj.handle_encode_timeout(85.0);
        assert_eq!(config.qp, 26); // 22 + 4
        assert_eq!(config.frame_ratio, 0.5); // 1.0 * 0.5
        assert_eq!(config.preset, "ultrafast");
    }

    #[test]
    fn test_recover_qp() {
        let mut adj = Adjuster::new(1920, 1080);
        adj.last_qp = 35;
        adj.recover_qp(NetworkState::Good);
        assert_eq!(adj.last_qp, 33); // 35 - 2
        adj.recover_qp(NetworkState::Good);
        assert_eq!(adj.last_qp, 31); // 33 - 2
    }

    #[test]
    fn test_recover_qp_at_target() {
        let mut adj = Adjuster::new(1920, 1080);
        adj.last_qp = 22;
        adj.recover_qp(NetworkState::Good);
        assert_eq!(adj.last_qp, 22); // 不变
    }

    #[test]
    fn test_resolution() {
        let adj = Adjuster::new(1920, 1080);
        assert_eq!(adj.resolution(), (1920, 1080));
    }

    #[test]
    fn test_base_frame_ratio() {
        assert!((base_frame_ratio_for_state(NetworkState::Good) - 1.0).abs() < 1e-6);
        assert!((base_frame_ratio_for_state(NetworkState::MildCongestion) - 0.5).abs() < 1e-6);
        assert!((base_frame_ratio_for_state(NetworkState::SevereCongestion) - 0.2).abs() < 1e-6);
    }

    // ── M13-T003：低带宽 / 高延迟降质 ───────────────────────────

    /// 低带宽（<5Mbps）→ QP+2、帧率 ×0.7。
    #[test]
    fn test_compute_config_low_bandwidth() {
        let mut adj = Adjuster::new(1920, 1080);
        let mut s = sample(0.0);
        s.received_bitrate_bps = 3_000_000.0;
        let config = adj.compute_config(NetworkState::Good, &s);
        assert_eq!(config.qp, 22 + 2);
        assert!((config.frame_ratio - 0.7).abs() < 1e-9);
    }

    /// 高延迟（RTT ≥ 100ms）→ QP+2、帧率 ×0.7。
    #[test]
    fn test_compute_config_high_rtt() {
        let mut adj = Adjuster::new(1920, 1080);
        let mut s = sample(0.0);
        s.rtt_ms = 120.0;
        let config = adj.compute_config(NetworkState::Good, &s);
        assert_eq!(config.qp, 22 + 2);
        assert!((config.frame_ratio - 0.7).abs() < 1e-9);
    }

    /// 低带宽 + 高延迟叠加 → QP+4、帧率 ×0.49。
    #[test]
    fn test_compute_config_low_bandwidth_high_rtt_stack() {
        let mut adj = Adjuster::new(1920, 1080);
        let mut s = sample(0.0);
        s.received_bitrate_bps = 2_000_000.0;
        s.rtt_ms = 150.0;
        let config = adj.compute_config(NetworkState::Good, &s);
        assert_eq!(config.qp, 22 + 4);
        assert!((config.frame_ratio - 0.49).abs() < 1e-9); // 1.0 × 0.7 × 0.7
    }

    /// 良好条件（带宽足 + 低 RTT）→ 全力发送，不降质。
    #[test]
    fn test_compute_config_good_conditions_full_send() {
        let mut adj = Adjuster::new(1920, 1080);
        let config = adj.compute_config(NetworkState::Good, &sample(0.0));
        assert_eq!(config.qp, 22);
        assert!((config.frame_ratio - 1.0).abs() < 1e-9);
    }

    /// 低带宽叠加严重拥塞 → QP 封顶 35、帧率不低于 0.1。
    #[test]
    fn test_compute_config_degradation_caps() {
        let mut adj = Adjuster::new(1920, 1080);
        let mut s = sample(0.08);
        s.received_bitrate_bps = 1_000_000.0;
        let config = adj.compute_config(NetworkState::SevereCongestion, &s);
        assert_eq!(config.qp, 35, "QP 封顶 35");
        assert!(config.frame_ratio >= 0.1, "帧率下限 0.1");
    }
}
