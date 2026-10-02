//! 网络状态机 + 迟滞切换逻辑。
//!
//! # 状态图
//!
//! ```text
//!        loss > 1.5% 或 RTT ≥ 100ms (3周期)      [M13-T003: RTT 高延迟降质]
//!  Good ──────────────────────────────────────▶ MildCongestion
//!    ◀─────────────────────────────────────────
//!        loss < 0.5% 且 RTT < 100ms (3周期)
//!
//!        loss > 6% (3周期)
//!  Good ──────────────────────────────────────▶ SevereCongestion
//!
//!        loss > 6% (3周期)
//!  MildCongestion ─────────────────────────────▶ SevereCongestion
//!    ◀──────────────────────────────────────────
//!        loss < 3% 且 RTT < 100ms (3周期)
//!
//!  SevereCongestion ───────────────────────────▶ MildCongestion (loss < 3% 且 RTT < 100ms, 3周期)
//!  SevereCongestion ───────────────────────────▶ Good (loss < 0.5% 且 RTT < 100ms, 5周期)
//! ```
//!
//! # M13-T003 扩展：RTT 作为拥塞信号
//!
//! 状态切换原只由丢包率驱动；M13-T003 把 **RTT ≥ 100ms** 追加为轻度拥塞
//! 信号（对应"高延迟 → 自动降质"）：
//!
//! - **降级**：Good 状态下，丢包 >1.5% **或** RTT ≥100ms 连续 3 周期 → Mild；
//!   RTT 不触发 Severe（高延迟只降一档，语义与 M13 文档一致）。
//! - **升级**：需要丢包率与 RTT **同时**回落（RTT 迟滞：≥100ms 的采样阻止
//!   升级，与降级阈值对齐，防边界振荡）。

use std::collections::VecDeque;
use std::time::Instant;

/// 高延迟阈值（毫秒）：RTT ≥ 此值视为轻度拥塞（M13-T003）。
pub const HIGH_RTT_MS: f64 = 100.0;

/// 网络状态等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkState {
    /// 良好：无拥塞，全帧率高画质
    Good,
    /// 轻度拥塞：丢包 1%~5%，减半帧率
    MildCongestion,
    /// 严重拥塞：丢包 >5%，仅保留关键帧
    SevereCongestion,
}

impl NetworkState {
    /// 返回当前状态的名称（用于日志）。
    pub fn name(&self) -> &'static str {
        match self {
            NetworkState::Good => "Good",
            NetworkState::MildCongestion => "MildCongestion",
            NetworkState::SevereCongestion => "SevereCongestion",
        }
    }
}

/// 单个反馈周期的网络采样。
#[derive(Debug, Clone)]
pub struct NetworkSample {
    /// 丢包率 (0.0 ~ 1.0)
    pub loss_rate: f64,
    /// RTT（毫秒）
    pub rtt_ms: f64,
    /// 包间延迟抖动（微秒）
    pub jitter_us: f64,
    /// 接收带宽（bps）
    pub received_bitrate_bps: f64,
    /// 采样时间戳
    pub timestamp: Instant,
}

/// 自适应状态机。
pub struct AdaptiveStateMachine {
    /// 当前网络状态
    current: NetworkState,
    /// 历史采样窗口（最近 N 个报告周期）
    history: VecDeque<NetworkSample>,
    /// 状态稳定计数器（连续满足条件才切换）
    stable_count: u32,
    /// 切换所需连续周期数（默认 3）
    required_stable: u32,
    /// 最大历史窗口大小
    max_history: usize,
    /// 上次切换前的状态（日志用）
    previous_state: NetworkState,
}

impl AdaptiveStateMachine {
    /// 创建新的状态机。
    pub fn new() -> Self {
        Self {
            current: NetworkState::Good,
            history: VecDeque::new(),
            stable_count: 0,
            required_stable: 3,
            max_history: 30,
            previous_state: NetworkState::Good,
        }
    }

    /// 当前网络状态。
    pub fn current(&self) -> NetworkState {
        self.current
    }

    /// 上次切换前的状态（用于日志）。
    pub fn history_state(&self) -> NetworkState {
        self.previous_state
    }

    /// 推入一个采样，返回是否发生了状态切换。
    ///
    /// 降级优先于升级。稳定计数器在满足条件时递增，不满足时清零。
    /// 达到 `required_stable` 周期后触发切换。
    pub fn feed_sample(&mut self, sample: &NetworkSample) -> bool {
        // 1. 推入历史
        self.history.push_back(sample.clone());
        while self.history.len() > self.max_history {
            self.history.pop_front();
        }

        // 2. 获取最近 required_stable 个采样的丢包率集合
        let recent = self.recent_samples();
        let has_enough = recent.len() >= self.required_stable as usize;

        // 3. 降级评估（优先）
        //    检查条件是否满足，不涉及 stable_count
        let downgrade_target = if has_enough {
            self.evaluate_downgrade(&recent)
        } else {
            None
        };

        if let Some(target) = downgrade_target {
            // 条件满足 → 递增稳定计数器
            self.stable_count += 1;
            if self.stable_count >= self.required_stable {
                self.transition_to(target);
                return true;
            }
            return false;
        }

        // 4. 升级评估
        //    返回 (目标状态, 需要的稳定周期数)
        let upgrade = if has_enough {
            self.evaluate_upgrade(&recent)
        } else {
            None
        };

        if let Some((target, needed)) = upgrade {
            self.stable_count += 1;
            if self.stable_count >= needed {
                self.transition_to(target);
                return true;
            }
            return false;
        }

        // 5. 既不降级也不升级——重置稳定计数器
        self.stable_count = 0;
        false
    }

    /// 检查降级条件（不涉及 stable_count）。
    /// 返回应降级到的目标状态，或 None。
    ///
    /// M13-T003：采样满足 `loss > threshold` **或** `rtt_ms ≥ HIGH_RTT_MS`
    /// 即视为该周期拥塞。RTT 只驱动 Good→Mild（高延迟降一档，不触发 Severe）。
    fn evaluate_downgrade(&self, recent: &[&NetworkSample]) -> Option<NetworkState> {
        let all_above = |threshold: f64| -> bool { recent.iter().all(|s| s.loss_rate > threshold) };
        let all_high_rtt = || -> bool { recent.iter().all(|s| s.rtt_ms >= HIGH_RTT_MS) };

        match self.current {
            NetworkState::Good => {
                // Good → SevereCongestion: 连续 3 周期 > 6%
                if all_above(0.06) {
                    return Some(NetworkState::SevereCongestion);
                }
                // Good → MildCongestion: 连续 3 周期 > 1.5%（迟滞）
                // 或 RTT ≥ 100ms（M13-T003 高延迟降质）
                if all_above(0.015) || all_high_rtt() {
                    return Some(NetworkState::MildCongestion);
                }
            }
            NetworkState::MildCongestion => {
                // MildCongestion → SevereCongestion: 连续 3 周期 > 6%
                if all_above(0.06) {
                    return Some(NetworkState::SevereCongestion);
                }
            }
            NetworkState::SevereCongestion => {
                // 不能再降级
            }
        }
        None
    }

    /// 检查升级条件（不涉及 stable_count）。
    /// 返回 (目标状态, 需要的稳定周期数)。
    ///
    /// M13-T003：升级需丢包率与 RTT **同时**回落（RTT ≥ 100ms 的采样阻止
    /// 升级，与降级阈值对齐形成迟滞）。
    fn evaluate_upgrade(&self, recent: &[&NetworkSample]) -> Option<(NetworkState, u32)> {
        let all_healthy = |threshold: f64| -> bool {
            recent
                .iter()
                .all(|s| s.loss_rate < threshold && s.rtt_ms < HIGH_RTT_MS)
        };

        match self.current {
            NetworkState::Good => None, // 已是最高
            NetworkState::MildCongestion => {
                // MildCongestion → Good: 连续 3 周期 < 0.5%（迟滞）
                if all_healthy(0.005) {
                    Some((NetworkState::Good, self.required_stable))
                } else {
                    None
                }
            }
            NetworkState::SevereCongestion => {
                // SevereCongestion → MildCongestion: 连续 3 周期 < 3%
                if all_healthy(0.03) {
                    return Some((NetworkState::MildCongestion, self.required_stable));
                }
                // SevereCongestion → Good: 连续 5 周期 < 0.5%（更严）
                if all_healthy(0.005) {
                    return Some((NetworkState::Good, 5));
                }
                None
            }
        }
    }

    /// 执行状态切换。
    fn transition_to(&mut self, target: NetworkState) {
        self.previous_state = self.current;
        self.current = target;
        self.stable_count = 0;
    }

    /// 获取最近 required_stable 个采样（丢包率 + RTT 联合评估，M13-T003）。
    fn recent_samples(&self) -> Vec<&NetworkSample> {
        self.history
            .iter()
            .rev()
            .take(self.required_stable as usize)
            .collect()
    }

    /// 重置到指定状态（连接建立/重置时）。
    pub fn reset(&mut self, state: NetworkState) {
        self.current = state;
        self.history.clear();
        self.stable_count = 0;
        self.previous_state = state;
    }
}

impl Default for AdaptiveStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ── 测试 ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_initial_state() {
        let sm = AdaptiveStateMachine::new();
        assert_eq!(sm.current(), NetworkState::Good);
    }

    #[test]
    fn test_good_stays_good() {
        let mut sm = AdaptiveStateMachine::new();
        for _ in 0..5 {
            assert!(!sm.feed_sample(&sample(0.003))); // 0.3% loss
        }
        assert_eq!(sm.current(), NetworkState::Good);
    }

    #[test]
    fn test_good_to_mild() {
        let mut sm = AdaptiveStateMachine::new();
        // 前 2 次不满足 3 周期要求（has_enough=false → stable_count 不变）
        assert!(!sm.feed_sample(&sample(0.025)));
        assert_eq!(sm.stable_count, 0);
        assert!(!sm.feed_sample(&sample(0.025)));
        assert_eq!(sm.stable_count, 0);
        // 第 3 次：has_enough=true，条件满足→stable_count=1
        assert!(!sm.feed_sample(&sample(0.025)));
        assert_eq!(sm.stable_count, 1);
        // 第 4 次：stable_count=2
        assert!(!sm.feed_sample(&sample(0.025)));
        // 第 5 次：stable_count=3 → 切换
        assert!(sm.feed_sample(&sample(0.025)));
        assert_eq!(sm.current(), NetworkState::MildCongestion);
    }

    #[test]
    fn test_good_to_severe() {
        let mut sm = AdaptiveStateMachine::new();
        assert!(!sm.feed_sample(&sample(0.08))); // 1/3 warmup
        assert!(!sm.feed_sample(&sample(0.08))); // 2/3 warmup
        assert!(!sm.feed_sample(&sample(0.08))); // 3/3 → has_enough, stable=1
        assert!(!sm.feed_sample(&sample(0.08))); // stable=2
        assert!(sm.feed_sample(&sample(0.08))); // stable=3 → 切换
        assert_eq!(sm.current(), NetworkState::SevereCongestion);
    }

    #[test]
    fn test_hysteresis_downgrade() {
        let mut sm = AdaptiveStateMachine::new();
        // 1.2% loss 在 1%~1.5% 迟滞区内，条件不满足→stable_count 被清零
        for _ in 0..3 {
            assert!(!sm.feed_sample(&sample(0.012)));
        }
        assert_eq!(sm.current(), NetworkState::Good);
    }

    #[test]
    fn test_hysteresis_upgrade() {
        let mut sm = AdaptiveStateMachine::new();
        // 先降级到 Mild（需要 5 次 2.5% 采样）
        for _ in 0..5 {
            sm.feed_sample(&sample(0.025));
        }
        assert_eq!(sm.current(), NetworkState::MildCongestion);

        // 0.6% loss 在 0.5%~1% 迟滞区内，不升级（条件不满足→清零）
        for _ in 0..3 {
            assert!(!sm.feed_sample(&sample(0.006)));
        }
        assert_eq!(sm.current(), NetworkState::MildCongestion);
    }

    #[test]
    fn test_mild_to_severe() {
        let mut sm = AdaptiveStateMachine::new();
        // 先降级到 Mild（5 次 2.5%）
        for _ in 0..5 {
            sm.feed_sample(&sample(0.025));
        }
        assert_eq!(sm.current(), NetworkState::MildCongestion);

        // 再从 Mild 到 Severe（5 次 >6%）
        for _ in 0..4 {
            assert!(!sm.feed_sample(&sample(0.08)));
        }
        assert!(sm.feed_sample(&sample(0.08)));
        assert_eq!(sm.current(), NetworkState::SevereCongestion);
    }

    #[test]
    fn test_severe_to_mild() {
        let mut sm = AdaptiveStateMachine::new();
        // 先降级到 Severe（5 次 >6%）
        for _ in 0..5 {
            sm.feed_sample(&sample(0.08));
        }
        assert_eq!(sm.current(), NetworkState::SevereCongestion);

        // 恢复：丢包率降到 2%（< 3%），连续 5 周期
        // 前 2 次 recent 混有旧 0.08 → 条件不满足
        assert!(!sm.feed_sample(&sample(0.02)));
        assert!(!sm.feed_sample(&sample(0.02)));
        // 第 3 次起：recent=[0.02,0.02,0.02]，条件满足
        assert!(!sm.feed_sample(&sample(0.02))); // stable=1
        assert!(!sm.feed_sample(&sample(0.02))); // stable=2
                                                 // 第 5 次：stable=3 → 切换
        assert!(sm.feed_sample(&sample(0.02)));
        assert_eq!(sm.current(), NetworkState::MildCongestion);
    }

    #[test]
    fn test_severe_to_good() {
        let mut sm = AdaptiveStateMachine::new();
        // 降级到 Severe（5 次 >6%）
        for _ in 0..5 {
            sm.feed_sample(&sample(0.08));
        }
        // 先恢复到 Mild（5 次 2%）
        for _ in 0..5 {
            sm.feed_sample(&sample(0.02));
        }
        assert_eq!(sm.current(), NetworkState::MildCongestion);

        // 再到 Good（需要 3 周期 < 0.5%，required_stable=3）
        // 前 2 次 recent 混有旧 0.02 → 条件不满足
        assert!(!sm.feed_sample(&sample(0.003)));
        assert!(!sm.feed_sample(&sample(0.003)));
        // 第 3 次起：recent=[0.003,0.003,0.003]，条件满足
        assert!(!sm.feed_sample(&sample(0.003))); // stable=1
        assert!(!sm.feed_sample(&sample(0.003))); // stable=2
                                                  // 第 5 次：stable=3 → 切换
        assert!(sm.feed_sample(&sample(0.003)));
        assert_eq!(sm.current(), NetworkState::Good);
    }

    #[test]
    fn test_no_oscillation() {
        let mut sm = AdaptiveStateMachine::new();
        // 单个高丢包尖刺不应该导致状态切换
        sm.feed_sample(&sample(0.08)); // spike — 条件满足，stable_count=1，但不切换
        assert_eq!(sm.current(), NetworkState::Good);
        sm.feed_sample(&sample(0.003)); // 恢复正常——stable_count 被清零
        assert_eq!(sm.current(), NetworkState::Good);
        sm.feed_sample(&sample(0.003));
        assert_eq!(sm.current(), NetworkState::Good);
    }

    #[test]
    fn test_reset() {
        let mut sm = AdaptiveStateMachine::new();
        for _ in 0..5 {
            sm.feed_sample(&sample(0.025));
        }
        assert_eq!(sm.current(), NetworkState::MildCongestion);

        sm.reset(NetworkState::Good);
        assert_eq!(sm.current(), NetworkState::Good);
        assert!(sm.history.is_empty());
        assert_eq!(sm.stable_count, 0);
    }

    #[test]
    fn test_state_name() {
        assert_eq!(NetworkState::Good.name(), "Good");
        assert_eq!(NetworkState::MildCongestion.name(), "MildCongestion");
        assert_eq!(NetworkState::SevereCongestion.name(), "SevereCongestion");
    }

    // ── M13-T003：RTT 拥塞信号 ─────────────────────────────────

    fn sample_rtt(loss_rate: f64, rtt_ms: f64) -> NetworkSample {
        NetworkSample {
            loss_rate,
            rtt_ms,
            jitter_us: 500.0,
            received_bitrate_bps: 8_000_000.0,
            timestamp: Instant::now(),
        }
    }

    /// 高延迟（RTT ≥ 100ms）连续 3 周期 → Good 降级到 Mild（即使丢包率很低）。
    #[test]
    fn test_high_rtt_downgrade_to_mild() {
        let mut sm = AdaptiveStateMachine::new();
        // 2 次热身（recent < 3）+ 3 次确认 → 第 5 次触发切换。
        for i in 0..5 {
            let changed = sm.feed_sample(&sample_rtt(0.001, 120.0));
            if i == 4 {
                assert!(changed, "第 5 个高 RTT 采样应触发切换");
            }
        }
        assert_eq!(sm.current(), NetworkState::MildCongestion);
        // 高 RTT 只降一档：不触发 Severe。
        assert_ne!(sm.current(), NetworkState::SevereCongestion);
    }

    /// RTT ≥ 100ms 阻塞升级（迟滞）：丢包回落但 RTT 仍高 → 保持降级状态；
    /// RTT 回落后才恢复升级。
    #[test]
    fn test_high_rtt_blocks_upgrade_until_rtt_recovers() {
        let mut sm = AdaptiveStateMachine::new();
        // 高 RTT 降级到 Mild。
        for _ in 0..5 {
            sm.feed_sample(&sample_rtt(0.001, 120.0));
        }
        assert_eq!(sm.current(), NetworkState::MildCongestion);

        // 丢包低但 RTT 仍高 → 不升级（可能因 Mild→Severe 无 RTT 信号而稳定）。
        for _ in 0..10 {
            let _ = sm.feed_sample(&sample_rtt(0.001, 120.0));
        }
        assert_ne!(sm.current(), NetworkState::Good, "RTT 未回落不得升级");

        // RTT 回落（60ms）→ 连续 3 周期 < 0.5% → 恢复 Good。
        let mut upgraded = false;
        for _ in 0..10 {
            if sm.feed_sample(&sample_rtt(0.001, 60.0)) {
                upgraded = true;
                break;
            }
        }
        assert!(upgraded, "RTT 回落后应恢复升级");
        assert_eq!(sm.current(), NetworkState::Good);
    }

    /// RTT 在阈值边界（<100ms）不触发降级。
    #[test]
    fn test_rtt_below_threshold_no_downgrade() {
        let mut sm = AdaptiveStateMachine::new();
        for _ in 0..5 {
            assert!(!sm.feed_sample(&sample_rtt(0.001, 95.0)));
        }
        assert_eq!(sm.current(), NetworkState::Good);
    }
}
