//! 恢复策略（T009 §6.6 / Sub-phase 4c）。
//!
//! 在拥塞缓解后，从当前质量等级**逐步**恢复到目标等级，避免恢复过快导致
//! 二次拥塞（cascade oscillation），也避免过慢导致用户感知无改善。
//!
//! # 与状态机（state_machine.rs）的关系（§6.6.7）
//!
//! ```text
//! state_machine: 决定「何时切换状态」（Good / Mild / Severe，迟滞阈值）
//! recovery:      决定「切换后如何分步恢复参数」（QP/帧率阶梯，急停回退）
//! ```
//!
//! # 核心规则（§6.6.2 ~ §6.6.6）
//!
//! - 恢复触发需同时满足三条件，持续 N 个反馈周期（当前等级越低要求越严）：
//!   A. 丢包率 < MIN(升档阈值, 当前降档阈值 × 0.7)
//!   B. 带宽余量：bandwidth > 目标码率 × 1.5
//!   C. cwnd 趋势：连续 2 周期增长 > 0
//! - 渐进阶梯恢复：逐级升档，每级停留周期按带宽余量自适应（1/2/4 周期）
//! - 帧率滞后恢复：QP 先恢复，帧率滞后一级（§6.6.5）
//! - 急停 & 回退安全阀：丢包冲高 / RTT 突增 >30% / urgent_reduce → 立即回退
//!   到恢复前的最高安全等级，冷却 ≥2 周期后才可重新评估（§6.6.6）
//! - 快速路径：cwnd 增幅 > 30% 时 极低 → 中（跳过低），稳定 3 周期
//! - 静默窗口加速：2 个连续静默窗口 → 直接跳至良好（无数据产生则无所谓拥塞）

use std::collections::VecDeque;

use crate::adaptive::report::FeedbackReport;
use crate::proto::EncodeConfig;

// ════════════════════════════════════════════════════════════════
// QualityLevel — 质量等级（QP + 帧率目标 + 估算码率 + 急停阈值）
// ════════════════════════════════════════════════════════════════

/// 质量等级（§6.3 的 QP/码率映射）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QualityLevel {
    /// 极低：QP 35，~0.8 Mbps（严重拥塞）
    ExtremeLow,
    /// 低：QP 32，~1.5 Mbps
    Low,
    /// 中：QP 28，~3 Mbps（轻度拥塞）
    Medium,
    /// 高：QP 22，~8 Mbps（良好）
    High,
}

impl QualityLevel {
    /// 该等级的 QP。
    pub fn qp(self) -> u32 {
        match self {
            QualityLevel::ExtremeLow => 35,
            QualityLevel::Low => 32,
            QualityLevel::Medium => 28,
            QualityLevel::High => 22,
        }
    }

    /// 该等级的帧保留比例（窗口内帧数目标：8→4→2→1）。
    pub fn frame_ratio(self) -> f64 {
        match self {
            QualityLevel::ExtremeLow => 0.125, // 窗口 10 帧取 1~2
            QualityLevel::Low => 0.25,         // 2 帧
            QualityLevel::Medium => 0.5,       // 4 帧
            QualityLevel::High => 1.0,         // 8 帧
        }
    }

    /// 该等级在 1080p 下的预期码率（bps，§6.3 表）。
    pub fn estimated_bitrate_bps(self) -> u64 {
        match self {
            QualityLevel::ExtremeLow => 800_000,
            QualityLevel::Low => 1_500_000,
            QualityLevel::Medium => 3_000_000,
            QualityLevel::High => 8_000_000,
        }
    }

    /// 急停阈值（§6.6.6）：恢复期间丢包率冲高到该值 → 立即中止恢复。
    ///
    /// 「恢复在'中'档时丢包 > 3% → 回退'低'档」为文档给定示例，
    /// 低/极低档沿用状态机的 6% 降级阈值。
    pub fn halt_threshold(self) -> f64 {
        match self {
            QualityLevel::ExtremeLow => 0.06,
            QualityLevel::Low => 0.06,
            QualityLevel::Medium => 0.03,
            QualityLevel::High => 0.015,
        }
    }

    /// 向上一级（None 表示已是最高等级）。
    pub fn next(self) -> Option<QualityLevel> {
        match self {
            QualityLevel::ExtremeLow => Some(QualityLevel::Low),
            QualityLevel::Low => Some(QualityLevel::Medium),
            QualityLevel::Medium => Some(QualityLevel::High),
            QualityLevel::High => None,
        }
    }

    /// 向下一级（None 表示已是最低等级）。
    pub fn prev(self) -> Option<QualityLevel> {
        match self {
            QualityLevel::ExtremeLow => None,
            QualityLevel::Low => Some(QualityLevel::ExtremeLow),
            QualityLevel::Medium => Some(QualityLevel::Low),
            QualityLevel::High => Some(QualityLevel::Medium),
        }
    }

    /// 等级名称（日志）。
    pub fn name(self) -> &'static str {
        match self {
            QualityLevel::ExtremeLow => "extreme-low",
            QualityLevel::Low => "low",
            QualityLevel::Medium => "medium",
            QualityLevel::High => "high",
        }
    }

    /// 从网络状态映射基准等级（状态机降级后进入的恢复起点）。
    pub fn from_state(state: crate::adaptive::NetworkState) -> QualityLevel {
        match state {
            crate::adaptive::NetworkState::Good => QualityLevel::High,
            crate::adaptive::NetworkState::MildCongestion => QualityLevel::Medium,
            crate::adaptive::NetworkState::SevereCongestion => QualityLevel::ExtremeLow,
        }
    }

    /// 从 QP 映射到最近的质量等级（用于编码超时降级后的恢复起点）。
    pub fn from_qp(qp: u32) -> QualityLevel {
        if qp >= 35 {
            QualityLevel::ExtremeLow
        } else if qp >= 32 {
            QualityLevel::Low
        } else if qp >= 28 {
            QualityLevel::Medium
        } else {
            QualityLevel::High
        }
    }
}

// ════════════════════════════════════════════════════════════════
// RecoveryPhase — 恢复阶段（§6.6.8 实现要点）
// ════════════════════════════════════════════════════════════════

/// 恢复阶段枚举。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecoveryPhase {
    /// 非恢复状态（网络良好或初始降级中）。
    Idle,
    /// 在某个等级稳定等待升级。
    ///
    /// `qp_target` / `ratio_target` 为两个独立的推进维度（§6.6.5 帧率滞后恢复）：
    /// QP 先升，帧率滞后一级追上。
    Climbing {
        /// 恢复起点（恢复前的最高安全等级，急停时回退到这里）。
        base: QualityLevel,
        /// QP 推进目标。
        qp_target: QualityLevel,
        /// 帧率推进目标（滞后于 qp_target）。
        ratio_target: QualityLevel,
        /// 当前等级已持续的反馈周期数。
        cycles_at_level: u8,
        /// 需持续多少周期才可升级。
        required_cycles: u8,
    },
    /// 急停回退挂起（§6.6.6）：冷却期内不评估恢复。
    Halted {
        /// 回退到的安全等级。
        fallback: QualityLevel,
        /// 冷却计数。
        cooldown_cycles: u8,
        /// 最少冷却周期（默认 2）。
        min_cooldown: u8,
    },
}

// ════════════════════════════════════════════════════════════════
// RecoveryAction — 引擎收到的恢复动作
// ════════════════════════════════════════════════════════════════

/// 恢复评估产出的动作。
#[derive(Debug, Clone)]
pub enum RecoveryAction {
    /// 无需变化。
    None,
    /// 升一级（QP/帧率按滞后策略推进）。
    StepUp { config: EncodeConfig },
    /// 快速路径 / 静默窗口加速：直接跳至良好等级。
    JumpToGood(EncodeConfig),
    /// 急停回退：回到恢复前的最高安全等级，冷却期开始。
    Halt { config: EncodeConfig },
}

// ════════════════════════════════════════════════════════════════
// RecoveryController
// ════════════════════════════════════════════════════════════════

/// 恢复控制器——驱动 Climbing / Halted 阶段的状态推进。
pub struct RecoveryController {
    /// 当前阶段。
    phase: RecoveryPhase,
    /// cwnd 历史（条件 C：连续 2 周期增长）。
    cwnd_history: VecDeque<u64>,
    /// 连续静默窗口计数（≥2 触发跳级）。
    silent_windows: u32,
    /// 上次恢复评估的 RTT（RTT 突增检测，§6.6.6）。
    last_recovery_rtt_ms: Option<f64>,
}

impl RecoveryController {
    /// 创建恢复控制器（初始 Idle）。
    pub fn new() -> Self {
        Self {
            phase: RecoveryPhase::Idle,
            cwnd_history: VecDeque::new(),
            silent_windows: 0,
            last_recovery_rtt_ms: None,
        }
    }

    /// 当前恢复阶段。
    pub fn phase(&self) -> &RecoveryPhase {
        &self.phase
    }

    /// 是否处于恢复中（Climbing 或 Halted）。
    pub fn is_recovering(&self) -> bool {
        !matches!(self.phase, RecoveryPhase::Idle)
    }

    /// 开始恢复（状态机降级到 Mild/Severe 时调用）。
    ///
    /// `from` — 降级后的基准等级（恢复起点 = 恢复前的最高安全等级）。
    pub fn start_recovery(&mut self, from: QualityLevel) {
        if from == QualityLevel::High {
            self.phase = RecoveryPhase::Idle;
            return;
        }
        // 需求持续周期（§6.6.2）：当前等级越低要求越严
        let required = match from {
            QualityLevel::ExtremeLow => 4,
            QualityLevel::Low => 3,
            QualityLevel::Medium => 2,
            QualityLevel::High => 0,
        };
        self.phase = RecoveryPhase::Climbing {
            base: from,
            qp_target: from,
            ratio_target: from,
            cycles_at_level: 0,
            required_cycles: required,
        };
        self.silent_windows = 0;
        self.last_recovery_rtt_ms = None;
    }

    /// 取消恢复（状态机直接升回 Good / 连接重置时）。
    pub fn cancel(&mut self) {
        self.phase = RecoveryPhase::Idle;
        self.silent_windows = 0;
        self.last_recovery_rtt_ms = None;
    }

    /// 记录 cwnd（由引擎 on_quic_stats 调用）。
    pub fn record_cwnd(&mut self, cwnd: u64) {
        self.cwnd_history.push_back(cwnd);
        while self.cwnd_history.len() > 8 {
            self.cwnd_history.pop_front();
        }
    }

    /// 记录一个静默窗口（无变化窗口，由服务端会话调用）。
    pub fn record_silent_window(&mut self) {
        if matches!(self.phase, RecoveryPhase::Climbing { .. }) {
            self.silent_windows += 1;
        }
    }

    /// 记录一个活跃窗口（静默计数清零）。
    pub fn record_active_window(&mut self) {
        self.silent_windows = 0;
    }

    /// 评估恢复（每个反馈周期调用一次）。
    ///
    /// `cwnd` — 当前 QUIC 拥塞窗口（字节）；`bandwidth` 取自反馈报告。
    pub fn evaluate(&mut self, report: &FeedbackReport, cwnd: Option<u64>) -> RecoveryAction {
        // ── 1. Halted：冷却期计数 ────────────────────────────────
        if let RecoveryPhase::Halted {
            fallback,
            cooldown_cycles,
            min_cooldown,
        } = self.phase
        {
            if cooldown_cycles < min_cooldown {
                // 冷却期：仅计数，不评估
                self.phase = RecoveryPhase::Halted {
                    fallback,
                    cooldown_cycles: cooldown_cycles + 1,
                    min_cooldown,
                };
                return RecoveryAction::None;
            }
            // 冷却结束 → 从回退等级重新开始爬升
            self.start_recovery(fallback);
            return RecoveryAction::None;
        }

        // ── 2. 快照 Climbing 状态（全部 Copy，避免借用冲突）──────
        let RecoveryPhase::Climbing {
            base,
            qp_target,
            ratio_target,
            cycles_at_level,
            required_cycles,
        } = self.phase
        else {
            return RecoveryAction::None;
        };

        // 静默窗口加速（§6.6.3）：2 个连续静默窗口 → 直接跳良好。
        if self.silent_windows >= 2 {
            self.silent_windows = 0;
            let config = EncodeConfig {
                qp: QualityLevel::High.qp(),
                frame_ratio: QualityLevel::High.frame_ratio(),
                force_idr: false,
                preset: "veryfast".into(),
            };
            self.phase = RecoveryPhase::Idle;
            return RecoveryAction::JumpToGood(config);
        }

        // ── 3. 急停检查（§6.6.6）：任一条件 → 立即回退 ──────────
        let rtt_surged = self.rtt_surge(report.rtt_ms);
        let halt =
            report.loss_rate > qp_target.halt_threshold() || report.urgent_reduce || rtt_surged;

        if halt {
            let fallback = base; // 恢复前的最高安全等级（非逐级回退）
            let config = EncodeConfig {
                qp: fallback.qp(),
                frame_ratio: fallback.frame_ratio(),
                force_idr: false,
                preset: "ultrafast".into(),
            };
            tracing::warn!(
                "[Adaptive] Recovery HALT: loss={:.1}% urgent={} rtt_surge={} → fallback to {}",
                report.loss_rate * 100.0,
                report.urgent_reduce,
                rtt_surged,
                fallback.name(),
            );
            self.phase = RecoveryPhase::Halted {
                fallback,
                cooldown_cycles: 0,
                min_cooldown: 2,
            };
            self.silent_windows = 0;
            self.last_recovery_rtt_ms = Some(report.rtt_ms);
            return RecoveryAction::Halt { config };
        }

        // ── 4. 恢复三条件检测（§6.6.2）─────────────────────────
        // A. 丢包率 < MIN(升档阈值, 当前降档阈值 × 0.7)
        let upgrade_threshold = self.upgrade_threshold(qp_target);
        let cond_a = report.loss_rate < upgrade_threshold;
        // B. 带宽余量：bandwidth > 当前编码码率 × 1.5（§6.6.2「当前码率」= 当前等级码率）
        let cond_b = report.bandwidth_bps as f64 > qp_target.estimated_bitrate_bps() as f64 * 1.5;
        // C. cwnd 趋势：连续 2 周期增长 > 0（无 cwnd 数据时视为满足——TCP 回退/测试场景）
        let cond_c = match cwnd {
            Some(c) => self.cwnd_growing_2_cycles(c),
            None => true,
        };

        if !(cond_a && cond_b && cond_c) {
            self.phase = RecoveryPhase::Climbing {
                base,
                qp_target,
                ratio_target,
                cycles_at_level: 0,
                required_cycles,
            };
            self.last_recovery_rtt_ms = Some(report.rtt_ms);
            return RecoveryAction::None;
        }

        // ── 5. 持续周期计数 ────────────────────────────────────
        if cycles_at_level + 1 < required_cycles {
            self.phase = RecoveryPhase::Climbing {
                base,
                qp_target,
                ratio_target,
                cycles_at_level: cycles_at_level + 1,
                required_cycles,
            };
            self.last_recovery_rtt_ms = Some(report.rtt_ms);
            return RecoveryAction::None;
        }

        // ── 6. 升一级（§6.6.3 + §6.6.5 帧率滞后）───────────────
        // 快速路径（§6.6.3）：cwnd 增幅 > 30% 时 极低 → 中（跳过低），稳定 3 周期。
        let fast_path = qp_target == QualityLevel::ExtremeLow && self.cwnd_surge_30_pct();

        let next_qp = if fast_path {
            Some(QualityLevel::Medium)
        } else {
            qp_target.next()
        };

        match next_qp {
            Some(new_qp_level) => {
                // QP 先推进；帧率滞后一级（§6.6.5）：
                //   ratio_target 最多追到 new_qp_level 的上一级
                let lag_cap = new_qp_level.prev().unwrap_or(new_qp_level);
                let mut new_ratio = ratio_target;
                if new_ratio < lag_cap {
                    new_ratio = lag_cap;
                }

                let config = EncodeConfig {
                    qp: new_qp_level.qp(),
                    frame_ratio: new_ratio.frame_ratio(),
                    force_idr: false,
                    preset: "ultrafast".into(),
                };

                // 每级停留周期（§6.6.4 恢复速度自适应）
                let required = self.speed_cycles(report.bandwidth_bps as f64, new_qp_level);

                tracing::info!(
                    "[Adaptive] Recovery step-up: {} → {} (qp={} ratio={:.3}, {} cycles, fast={})",
                    qp_target.name(),
                    new_qp_level.name(),
                    config.qp,
                    config.frame_ratio,
                    required,
                    fast_path,
                );

                self.phase = RecoveryPhase::Climbing {
                    base,
                    qp_target: new_qp_level,
                    ratio_target: new_ratio,
                    cycles_at_level: 0,
                    required_cycles: required,
                };
                self.last_recovery_rtt_ms = Some(report.rtt_ms);
                RecoveryAction::StepUp { config }
            }
            None => {
                // qp_target 已到 High：只需补帧率（若还滞后）
                if ratio_target < QualityLevel::High {
                    let config = EncodeConfig {
                        qp: QualityLevel::High.qp(),
                        frame_ratio: QualityLevel::High.frame_ratio(),
                        force_idr: false,
                        preset: "veryfast".into(),
                    };
                    tracing::info!(
                        "[Adaptive] Recovery ratio catch-up → high (ratio={})",
                        config.frame_ratio,
                    );
                    self.phase = RecoveryPhase::Climbing {
                        base,
                        qp_target: QualityLevel::High,
                        ratio_target: QualityLevel::High,
                        cycles_at_level: 0,
                        required_cycles: self
                            .speed_cycles(report.bandwidth_bps as f64, QualityLevel::High),
                    };
                    self.last_recovery_rtt_ms = Some(report.rtt_ms);
                    return RecoveryAction::StepUp { config };
                }
                // 完全恢复
                let config = EncodeConfig {
                    qp: QualityLevel::High.qp(),
                    frame_ratio: QualityLevel::High.frame_ratio(),
                    force_idr: false,
                    preset: "veryfast".into(),
                };
                tracing::info!("[Adaptive] Recovery complete → high (qp=22 ratio=1.0)");
                self.phase = RecoveryPhase::Idle;
                self.last_recovery_rtt_ms = None;
                RecoveryAction::StepUp { config }
            }
        }
    }

    // ── 内部辅助 ───────────────────────────────────────────────

    /// 恢复触发条件 A 的升档阈值（§6.6.2：升档条件比降档更严）。
    fn upgrade_threshold(&self, level: QualityLevel) -> f64 {
        let upgrade: f64 = match level {
            // 状态机升级阈值：Mild→Good 0.5%；Severe→Mild 3%
            QualityLevel::ExtremeLow | QualityLevel::Low => 0.03,
            QualityLevel::Medium => 0.005,
            QualityLevel::High => 0.005,
        };
        let downgrade_x0_7: f64 = level.halt_threshold() * 0.7;
        upgrade.min(downgrade_x0_7)
    }

    /// 每级停留周期（§6.6.4 恢复速度自适应）。
    fn speed_cycles(&self, bandwidth_bps: f64, target: QualityLevel) -> u8 {
        let target_bitrate = target.estimated_bitrate_bps() as f64;
        let margin = bandwidth_bps / target_bitrate;
        if margin > 3.0 {
            1 // 带宽充裕（> 3×）：1 周期快速恢复
        } else if margin > 1.8 {
            2 // 带宽适中（1.8~3×）：标准渐进
        } else {
            4 // 带宽临界（~1.5×）：需观察带宽是否稳定
        }
    }

    /// 条件 C：cwnd 连续 2 周期增长 > 0（最近两个周期 + 当前值均递增）。
    fn cwnd_growing_2_cycles(&self, cwnd: u64) -> bool {
        let mut it = self.cwnd_history.iter().rev();
        let most_recent = it.next();
        let second_recent = it.next();
        match (most_recent, second_recent) {
            (Some(&m), Some(&s)) => cwnd > m && m > s,
            _ => true, // 历史不足 → 视为满足（保守放行，避免恢复卡死）
        }
    }

    /// 快速路径判定：cwnd 相对上一个恢复周期增幅 > 30%。
    fn cwnd_surge_30_pct(&self) -> bool {
        if self.cwnd_history.len() < 3 {
            return false;
        }
        let recent = *self.cwnd_history.back().unwrap();
        let oldest = *self.cwnd_history.front().unwrap();
        oldest > 0 && (recent as f64 - oldest as f64) / oldest as f64 > 0.30
    }

    /// RTT 突增检测（§6.6.6）：与上一个恢复周期相比 > 30%。
    fn rtt_surge(&self, rtt_ms: f64) -> bool {
        match self.last_recovery_rtt_ms {
            Some(prev) if prev > 0.0 => (rtt_ms - prev) / prev > 0.30,
            _ => false,
        }
    }
}

impl Default for RecoveryController {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════
// 测试
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn report(loss_rate: f64, bandwidth_bps: u64, rtt_ms: f64) -> FeedbackReport {
        FeedbackReport {
            loss_rate,
            rtt_ms,
            jitter_us: 0.0,
            bandwidth_bps,
            last_frame_id: 100,
            missing_frames: vec![],
            urgent_reduce: false,
            decode_stats: None,
        }
    }

    /// 制造一个满足三条件的反馈（带宽 8Mbps > 中档 3Mbps×1.5）。
    fn good_report() -> FeedbackReport {
        report(0.002, 8_000_000, 30.0)
    }

    /// 从 ExtremeLow 开始恢复的控制器（模拟严重拥塞降级后）。
    fn severe_controller() -> RecoveryController {
        let mut c = RecoveryController::new();
        c.start_recovery(QualityLevel::ExtremeLow);
        c
    }

    #[test]
    fn test_level_qp_mapping() {
        assert_eq!(QualityLevel::ExtremeLow.qp(), 35);
        assert_eq!(QualityLevel::Low.qp(), 32);
        assert_eq!(QualityLevel::Medium.qp(), 28);
        assert_eq!(QualityLevel::High.qp(), 22);
    }

    #[test]
    fn test_level_next_prev() {
        assert_eq!(QualityLevel::ExtremeLow.next(), Some(QualityLevel::Low));
        assert_eq!(QualityLevel::Low.next(), Some(QualityLevel::Medium));
        assert_eq!(QualityLevel::Medium.next(), Some(QualityLevel::High));
        assert_eq!(QualityLevel::High.next(), None);
        assert_eq!(QualityLevel::ExtremeLow.prev(), None);
        assert_eq!(QualityLevel::High.prev(), Some(QualityLevel::Medium));
    }

    #[test]
    fn test_start_recovery_idle_when_high() {
        let mut c = RecoveryController::new();
        c.start_recovery(QualityLevel::High);
        assert!(!c.is_recovering());
    }

    /// 恢复触发需要持续周期：极低档 4 周期（§6.6.2）。
    #[test]
    fn test_recovery_requires_sustained_cycles() {
        let mut c = severe_controller();
        // 前 3 周期：条件满足但不升
        for _ in 0..3 {
            let action = c.evaluate(&good_report(), Some(64_000));
            assert!(matches!(action, RecoveryAction::None));
        }
        // 第 4 周期：升到低（QP 35→32，帧率保持极低——滞后恢复）
        let action = c.evaluate(&good_report(), Some(64_000));
        match action {
            RecoveryAction::StepUp { config } => {
                assert_eq!(config.qp, 32);
                assert_eq!(config.frame_ratio, QualityLevel::ExtremeLow.frame_ratio());
            }
            other => panic!("expected StepUp, got {other:?}"),
        }
    }

    /// 渐进阶梯恢复（§6.6.3 + §6.6.5 帧率滞后）：极低 → 低 → 中 → 高。
    /// QP 序列 32/28/22/22，帧率序列滞后一级 0.125/0.25/0.5/1.0。
    /// 带宽 20Mbps（对各级均充裕，且可支撑高档 8Mbps 的 1.5× 条件）。
    #[test]
    fn test_recovery_progressive_ladder_with_frame_rate_lag() {
        let mut c = severe_controller();
        let rpt = report(0.002, 20_000_000, 30.0);
        let mut qps = Vec::new();
        let mut ratios = Vec::new();
        for _ in 0..10 {
            if let RecoveryAction::StepUp { config } = c.evaluate(&rpt, Some(64_000)) {
                qps.push(config.qp);
                ratios.push(config.frame_ratio);
            }
        }
        // 前 4 步：QP 35→32→28→22→22；帧率滞后一级 0.125→0.25→0.5→1.0
        assert_eq!(qps[..4], [32, 28, 22, 22]);
        assert_eq!(ratios[..4], [0.125, 0.25, 0.5, 1.0]);
        // 完全恢复后 Idle
        assert!(!c.is_recovering());
    }

    /// 带宽适中（1.8~3× 当前码率）→ 每级停留 2 周期（§6.6.4）。
    #[test]
    fn test_recovery_speed_adaptation_medium_bandwidth() {
        let mut c = severe_controller();
        // 7Mbps vs 中档 3Mbps = 2.33× → 中档停留 2 周期
        let rpt = report(0.002, 7_000_000, 30.0);
        // 极低档 4 周期 → 升到低（QP 32）
        for _ in 0..3 {
            assert!(matches!(
                c.evaluate(&rpt, Some(64_000)),
                RecoveryAction::None
            ));
        }
        let a = c.evaluate(&rpt, Some(64_000));
        assert!(matches!(a, RecoveryAction::StepUp { .. }));
        // 低档 4.67× 充裕 → 1 周期 → 升到中（QP 28）
        let a = c.evaluate(&rpt, Some(64_000));
        assert!(matches!(a, RecoveryAction::StepUp { .. }));
        // 中档 2.33× → 2 周期停留
        assert!(matches!(
            c.evaluate(&rpt, Some(64_000)),
            RecoveryAction::None
        ));
        let a = c.evaluate(&rpt, Some(64_000));
        assert!(matches!(a, RecoveryAction::StepUp { .. }));
    }

    /// 带宽临界（~1.5× 当前码率）→ 每级停留 4 周期（§6.6.4）。
    #[test]
    fn test_recovery_speed_adaptation_critical_bandwidth() {
        let mut c = severe_controller();
        // 4.6Mbps vs 中档 3Mbps = 1.53× → 中档停留 4 周期
        let rpt = report(0.002, 4_600_000, 30.0);
        // 极低档 4 周期 → 低（QP 32）
        for _ in 0..3 {
            assert!(matches!(
                c.evaluate(&rpt, Some(64_000)),
                RecoveryAction::None
            ));
        }
        assert!(matches!(
            c.evaluate(&rpt, Some(64_000)),
            RecoveryAction::StepUp { .. }
        ));
        // 低档 3.07× 充裕 → 1 周期 → 中（QP 28）
        assert!(matches!(
            c.evaluate(&rpt, Some(64_000)),
            RecoveryAction::StepUp { .. }
        ));
        // 中档临界 1.53× → 4 周期停留（恰 1.5× 需观察带宽是否稳定）
        for _ in 0..3 {
            assert!(matches!(
                c.evaluate(&rpt, Some(64_000)),
                RecoveryAction::None
            ));
        }
        let a = c.evaluate(&rpt, Some(64_000));
        assert!(matches!(a, RecoveryAction::StepUp { .. }));
    }

    /// 三条件缺一不可（§6.6.2）：带宽不足时不恢复。
    #[test]
    fn test_recovery_condition_b_bandwidth() {
        let mut c = severe_controller();
        let rpt = report(0.002, 1_000_000, 30.0); // 1Mbps < 中档 3Mbps × 1.5
        for _ in 0..10 {
            assert!(matches!(
                c.evaluate(&rpt, Some(64_000)),
                RecoveryAction::None
            ));
        }
        assert!(c.is_recovering());
    }

    /// 三条件缺一不可：丢包率不达标时不恢复（条件 A）。
    #[test]
    fn test_recovery_condition_a_loss() {
        let mut c = severe_controller();
        // 极低档：MIN(3%, 6%×0.7=4.2%) = 3%；0.04 不满足
        let rpt = report(0.04, 8_000_000, 30.0);
        for _ in 0..10 {
            assert!(matches!(
                c.evaluate(&rpt, Some(64_000)),
                RecoveryAction::None
            ));
        }
    }

    /// 急停：恢复期间丢包率冲高 → 回退到恢复前安全等级 + 冷却（§6.6.6）。
    #[test]
    fn test_recovery_halt_on_loss_surge() {
        let mut c = severe_controller();
        // 升到低（QP 32）
        for _ in 0..4 {
            c.evaluate(&good_report(), Some(64_000));
        }
        // 丢包冲高 7% > 低档 6% 阈值
        let action = c.evaluate(&report(0.07, 8_000_000, 30.0), Some(64_000));
        match action {
            RecoveryAction::Halt { config } => {
                // 回退到恢复前的最高安全等级 = 极低（QP 35）
                assert_eq!(config.qp, 35);
                assert_eq!(config.frame_ratio, QualityLevel::ExtremeLow.frame_ratio());
            }
            other => panic!("expected Halt, got {other:?}"),
        }
        // 冷却期（2 周期）内不评估
        for _ in 0..2 {
            assert!(matches!(
                c.evaluate(&good_report(), Some(64_000)),
                RecoveryAction::None
            ));
        }
        // 冷却结束后从极低重新爬升
        assert!(c.is_recovering());
        let mut saw_step = false;
        for _ in 0..8 {
            if let RecoveryAction::StepUp { config } = c.evaluate(&good_report(), Some(64_000)) {
                assert_eq!(config.qp, 32);
                saw_step = true;
                break;
            }
        }
        assert!(saw_step, "recovery should resume from fallback level");
    }

    /// 急停：RTT 突增 > 30%（§6.6.6）。
    #[test]
    fn test_recovery_halt_on_rtt_surge() {
        let mut c = severe_controller();
        for _ in 0..4 {
            c.evaluate(&good_report(), Some(64_000));
        }
        // RTT 从 30ms 突增到 45ms（+50%）
        let action = c.evaluate(&report(0.002, 8_000_000, 45.0), Some(64_000));
        assert!(matches!(action, RecoveryAction::Halt { .. }));
    }

    /// 急停：urgent_reduce 标记（§6.6.6）。
    #[test]
    fn test_recovery_halt_on_urgent() {
        let mut c = severe_controller();
        for _ in 0..4 {
            c.evaluate(&good_report(), Some(64_000));
        }
        let mut rpt = good_report();
        rpt.urgent_reduce = true;
        let action = c.evaluate(&rpt, Some(64_000));
        assert!(matches!(action, RecoveryAction::Halt { .. }));
    }

    /// 快速路径：cwnd 增幅 > 30% → 极低 → 中（跳过低），稳定 3 周期（§6.6.3）。
    #[test]
    fn test_recovery_fast_path() {
        let mut c = severe_controller();
        // 喂 cwnd 历史（递增 40%）
        c.record_cwnd(10_000);
        c.record_cwnd(13_000);
        c.record_cwnd(14_000);
        // 带宽 20Mbps：快速路径后仍可继续爬到高档
        let rpt = report(0.002, 20_000_000, 30.0);
        // 极低档 4 周期 → 升（快速路径：直接到中 QP 28）
        let mut action = RecoveryAction::None;
        for _ in 0..4 {
            action = c.evaluate(&rpt, Some(15_000));
        }
        match action {
            RecoveryAction::StepUp { config } => {
                assert_eq!(config.qp, 28, "fast path skips low level");
            }
            other => panic!("expected fast StepUp, got {other:?}"),
        }
        // 中档稳定后继续爬到高（qp=22）
        let mut saw_high = false;
        for _ in 0..8 {
            if let RecoveryAction::StepUp { config } = c.evaluate(&rpt, Some(15_000)) {
                if config.qp == 22 {
                    saw_high = true;
                }
            }
        }
        assert!(saw_high, "should reach high after fast path");
    }

    /// 静默窗口加速：2 个连续静默窗口 → 直接跳良好（§6.6.3）。
    #[test]
    fn test_recovery_silent_window_jump() {
        let mut c = severe_controller();
        c.record_silent_window();
        let a1 = c.evaluate(&good_report(), Some(64_000));
        assert!(matches!(a1, RecoveryAction::None));
        c.record_silent_window();
        let a2 = c.evaluate(&good_report(), Some(64_000));
        match a2 {
            RecoveryAction::JumpToGood(config) => {
                assert_eq!(config.qp, 22);
                assert_eq!(config.frame_ratio, 1.0);
            }
            other => panic!("expected JumpToGood, got {other:?}"),
        }
        assert!(!c.is_recovering());
    }

    /// 活跃窗口清零静默计数。
    #[test]
    fn test_silent_counter_reset_on_active() {
        let mut c = severe_controller();
        c.record_silent_window();
        c.record_active_window();
        c.record_silent_window();
        let action = c.evaluate(&good_report(), Some(64_000));
        assert!(
            matches!(action, RecoveryAction::None),
            "counter reset by active window"
        );
    }

    /// cwnd 不增长（条件 C 不满足）→ 不恢复。
    #[test]
    fn test_recovery_condition_c_cwnd_stagnant() {
        let mut c = severe_controller();
        c.record_cwnd(64_000);
        c.record_cwnd(64_000);
        for _ in 0..10 {
            assert!(matches!(
                c.evaluate(&good_report(), Some(64_000)),
                RecoveryAction::None
            ));
        }
    }

    /// 无 cwnd 数据（TCP 回退 / 测试）→ 条件 C 视为满足，不卡死恢复。
    #[test]
    fn test_recovery_without_cwnd_data() {
        let mut c = severe_controller();
        let mut stepped = false;
        for _ in 0..8 {
            if let RecoveryAction::StepUp { .. } = c.evaluate(&good_report(), None) {
                stepped = true;
                break;
            }
        }
        assert!(stepped, "recovery should proceed without cwnd data");
    }

    /// 取消恢复（状态机直接升回 Good）。
    #[test]
    fn test_cancel() {
        let mut c = severe_controller();
        assert!(c.is_recovering());
        c.cancel();
        assert!(!c.is_recovering());
        assert!(matches!(
            c.evaluate(&good_report(), Some(64_000)),
            RecoveryAction::None
        ));
    }
}
