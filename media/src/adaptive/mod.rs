//! 自适应反馈闭环（Phase 4）
//!
//! # 架构
//!
//! ```text
//! 客户端: LossDetector → ReportGenerator → ControlMessage::FeedbackReport
//!     → QUIC 可靠流 → 服务端 recv_control()
//!     → AdaptiveEngine::on_feedback() → Adjuster::compute_config()
//!     → ControlMessage::AdaptiveConfig → QUIC 可靠流
//!     → 客户端 recv_control() → WindowPipeline::update_encode_config()
//! ```
//!
//! # 模块
//!
//! | 模块 | 职责 |
//! |------|------|
//! | `mod.rs` | `AdaptiveEngine` 主入口 + 共享类型 |
//! | `state_machine.rs` | 网络状态机 + 迟滞切换 |
//! | `adjuster.rs` | QP/帧率调整 + 超时保护 |
//! | `report.rs` | 客户端 `ReportGenerator` + `DecodeStats` |
//! | `fps_governor.rs` | M13-T002 可变帧率（内容活动度 → 1/10/30fps 档位） |

pub mod adjuster;
pub mod fps_governor;
pub mod recovery;
pub mod report;
pub mod state_machine;

use std::time::Instant;

use crate::proto::EncodeConfig;

pub use adjuster::select_frames;
pub use adjuster::Adjuster;
pub use fps_governor::{tile_activity, FpsGovernor, FpsGovernorConfig};
pub use recovery::{QualityLevel, RecoveryAction, RecoveryController, RecoveryPhase};
pub use report::{DecodeStats, FeedbackReport, ReportGenerator};
pub use state_machine::{AdaptiveStateMachine, NetworkSample, NetworkState};

// ── AdaptiveEngine ─────────────────────────────────────────────

/// 自适应策略引擎——核心入口。
pub struct AdaptiveEngine {
    /// 网络状态机
    state_machine: AdaptiveStateMachine,
    /// 编码调整器
    adjuster: Adjuster,
    /// 当前编码配置
    current_config: EncodeConfig,
    /// 上次采样时间
    #[allow(dead_code)]
    last_sample_time: Instant,
    /// 连续超时计数（用于逐步降级）
    consecutive_timeouts: u32,
    /// 恢复控制器（T009 §6.6：降级后的渐进阶梯恢复 + 急停回退）
    recovery: RecoveryController,
    /// 最近一次 QUIC 拥塞窗口（恢复条件 C 用）
    last_cwnd: Option<u64>,
}

impl AdaptiveEngine {
    /// 创建引擎。
    pub fn new(screen_w: u32, screen_h: u32) -> Self {
        Self {
            state_machine: AdaptiveStateMachine::new(),
            adjuster: Adjuster::new(screen_w, screen_h),
            current_config: EncodeConfig::default(),
            last_sample_time: Instant::now(),
            consecutive_timeouts: 0,
            recovery: RecoveryController::new(),
            last_cwnd: None,
        }
    }

    /// 收到客户端反馈报告时调用。
    ///
    /// 返回 `Some(EncodeConfig)` 表示配置需要更新。
    pub fn on_feedback(&mut self, report: &FeedbackReport) -> Option<EncodeConfig> {
        // 1. 构建 NetworkSample
        let sample = NetworkSample {
            loss_rate: report.loss_rate,
            rtt_ms: report.rtt_ms,
            jitter_us: report.jitter_us,
            received_bitrate_bps: report.bandwidth_bps as f64,
            timestamp: Instant::now(),
        };

        // 2. 推入状态机
        let state_changed = self.state_machine.feed_sample(&sample);

        // 3. 如果状态变化则重新计算配置
        if state_changed {
            let current_state = self.state_machine.current();
            let new_config = self.adjuster.compute_config(current_state, &sample);
            tracing::info!(
                "[Adaptive] State: {:?} -> {:?} (loss={:.1}%, rtt={:.0}ms)",
                self.state_machine.history_state(),
                current_state,
                report.loss_rate * 100.0,
                report.rtt_ms,
            );
            self.current_config = new_config.clone();
            self.consecutive_timeouts = 0;
            // 恢复策略挂钩（T009 §6.6.7）：
            // - 降级 → 从新状态的基准等级开始恢复
            // - 直接升回 Good → 取消恢复
            if current_state == NetworkState::Good {
                self.recovery.cancel();
            } else {
                self.recovery
                    .start_recovery(QualityLevel::from_state(current_state));
            }
            return Some(new_config);
        }

        // 4. 非状态切换：降级状态下推进恢复阶梯（T009 §6.6）
        if self.state_machine.current() != NetworkState::Good {
            let action = self.recovery.evaluate(report, self.last_cwnd);
            return match action {
                RecoveryAction::StepUp { config }
                | RecoveryAction::JumpToGood(config)
                | RecoveryAction::Halt { config } => {
                    self.current_config = config.clone();
                    Some(config)
                }
                RecoveryAction::None => None,
            };
        }

        None
    }

    /// 收到 QUIC 连接统计时调用（RTT、CWND）。
    ///
    /// `cwnd` 单位为字节。当拥塞窗口小于一个 MTU 时强制降级。
    pub fn on_quic_stats(&mut self, rtt_ms: f64, cwnd: u64) -> Option<EncodeConfig> {
        const MIN_CWND: u64 = 1200; // 1 个 MTU

        // 恢复策略的 cwnd 趋势（条件 C / 快速路径）
        self.last_cwnd = Some(cwnd);
        self.recovery.record_cwnd(cwnd);

        if cwnd < MIN_CWND {
            // 严重拥塞——强制最低配置
            let config = EncodeConfig {
                qp: 35,
                force_idr: false,
                frame_ratio: 0.1,
                preset: "ultrafast".into(),
            };
            tracing::warn!(
                "[Adaptive] QUIC CWND critical: {} < {} — force min config",
                cwnd,
                MIN_CWND
            );
            self.current_config = config.clone();
            // cwnd 崩溃：恢复从极低档重新开始
            self.recovery.start_recovery(QualityLevel::ExtremeLow);
            Some(config)
        } else {
            // 仅记录 RTT，不主动变更
            tracing::debug!("[Adaptive] QUIC stats: rtt={:.0}ms cwnd={}", rtt_ms, cwnd);
            None
        }
    }

    /// 记录一个静默窗口（无变化，未产生媒体数据）。
    ///
    /// 恢复期间连续 2 个静默窗口 → 直接跳至良好（T009 §6.6.3 静默窗口加速）。
    pub fn on_silent_window(&mut self) {
        self.recovery.record_silent_window();
    }

    /// 记录一个活跃窗口（重置静默计数）。
    pub fn on_active_window(&mut self) {
        self.recovery.record_active_window();
    }

    /// 当前恢复阶段（诊断/日志）。
    pub fn recovery_phase(&self) -> &RecoveryPhase {
        self.recovery.phase()
    }

    /// 是否处于恢复中（Climbing / Halted）。
    pub fn is_recovering(&self) -> bool {
        self.recovery.is_recovering()
    }

    /// 当前网络状态（诊断/日志）。
    pub fn network_state(&self) -> NetworkState {
        self.state_machine.current()
    }

    /// 通知编码结束（含耗时）。
    ///
    /// 当编码超时（>70ms）时自动降级。
    pub fn on_encode_complete(&mut self, encode_ms: f64) -> Option<EncodeConfig> {
        if encode_ms > 70.0 {
            self.consecutive_timeouts += 1;
            let new_config = self.adjuster.handle_encode_timeout(encode_ms);
            tracing::warn!(
                "[Adaptive] Encode timeout! {:.0}ms consecutive={}",
                encode_ms,
                self.consecutive_timeouts
            );
            self.current_config = new_config.clone();
            Some(new_config)
        } else if encode_ms > 50.0 {
            let new_config = self.adjuster.handle_encode_timeout(encode_ms);
            tracing::info!(
                "[Adaptive] Encode near timeout: {:.0}ms, reduce ratio {:.2}",
                encode_ms,
                new_config.frame_ratio,
            );
            self.current_config = new_config.clone();
            Some(new_config)
        } else {
            // 编码正常——逐步恢复 QP
            self.consecutive_timeouts = 0;
            let current_state = self.state_machine.current();
            self.adjuster.recover_qp(current_state);
            None
        }
    }

    /// 当前编码配置。
    pub fn current_config(&self) -> &EncodeConfig {
        &self.current_config
    }

    /// 重置（连接重置/新建时调用）。
    pub fn reset(&mut self, screen_w: u32, screen_h: u32) {
        self.state_machine.reset(NetworkState::Good);
        self.adjuster = Adjuster::new(screen_w, screen_h);
        self.current_config = EncodeConfig::default();
        self.last_sample_time = Instant::now();
        self.consecutive_timeouts = 0;
        self.recovery.cancel();
        self.last_cwnd = None;
    }
}

// ── 测试 ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_new() {
        let engine = AdaptiveEngine::new(1920, 1080);
        assert_eq!(engine.current_config.qp, 22);
        assert_eq!(engine.current_config.frame_ratio, 1.0);
        assert_eq!(engine.state_machine.current(), NetworkState::Good);
    }

    #[test]
    fn test_engine_on_feedback_good() {
        let mut engine = AdaptiveEngine::new(1920, 1080);
        let report = FeedbackReport {
            loss_rate: 0.003,
            rtt_ms: 30.0,
            jitter_us: 500.0,
            bandwidth_bps: 8_000_000,
            last_frame_id: 100,
            missing_frames: vec![],
            urgent_reduce: false,
            decode_stats: None,
        };
        // Good 状态不变化，不应返回配置
        for _ in 0..5 {
            let result = engine.on_feedback(&report);
            assert!(result.is_none(), "Good state should not produce new config");
        }
        assert_eq!(engine.state_machine.current(), NetworkState::Good);
    }

    #[test]
    fn test_engine_on_feedback_mild() {
        let mut engine = AdaptiveEngine::new(1920, 1080);
        let report = FeedbackReport {
            loss_rate: 0.025,
            rtt_ms: 60.0,
            jitter_us: 2000.0,
            bandwidth_bps: 3_000_000,
            last_frame_id: 50,
            missing_frames: vec![],
            urgent_reduce: false,
            decode_stats: None,
        };

        let mut switched = false;
        // 5 次: 2 warmup + 3 stable → 第 5 次触发切换
        for _ in 0..10 {
            if let Some(config) = engine.on_feedback(&report) {
                // base 28 + 丢包 2.5%（+2）= 30；M13-T003 低带宽 3Mbps（<5M）
                // 追加 +2 → 32，帧率 0.5 × 0.7 = 0.35。
                assert_eq!(config.qp, 32);
                assert!((config.frame_ratio - 0.35).abs() < 1e-9);
                switched = true;
                break;
            }
        }
        assert!(switched, "Should downgrade to MildCongestion");
        assert_eq!(engine.state_machine.current(), NetworkState::MildCongestion);
    }

    #[test]
    fn test_engine_on_encode_complete_timeout() {
        let mut engine = AdaptiveEngine::new(1920, 1080);
        let result = engine.on_encode_complete(85.0);
        assert!(result.is_some());
        let config = result.unwrap();
        assert_eq!(config.qp, 22 + 4); // last_qp(22=default) + 4
        assert_eq!(config.frame_ratio, 0.5); // 1.0 * 0.5
        assert_eq!(config.preset, "ultrafast");
        assert_eq!(engine.consecutive_timeouts, 1);
    }

    #[test]
    fn test_engine_on_quic_stats_cwnd_critical() {
        let mut engine = AdaptiveEngine::new(1920, 1080);
        let result = engine.on_quic_stats(100.0, 800);
        assert!(result.is_some());
        let config = result.unwrap();
        assert_eq!(config.qp, 35);
        assert_eq!(config.frame_ratio, 0.1);
    }

    #[test]
    fn test_engine_on_quic_stats_normal() {
        let mut engine = AdaptiveEngine::new(1920, 1080);
        let result = engine.on_quic_stats(30.0, 64000);
        assert!(result.is_none());
    }

    #[test]
    fn test_engine_reset() {
        let mut engine = AdaptiveEngine::new(1920, 1080);
        engine.on_encode_complete(85.0); // timeout -> set qp=30
        engine.reset(1280, 720);
        assert_eq!(engine.current_config.qp, 22); // reset → EncodeConfig::default()，默认 QP=22（M8-T016）
        assert_eq!(engine.current_config.frame_ratio, 1.0);
        assert_eq!(engine.state_machine.current(), NetworkState::Good);
        assert_eq!(engine.consecutive_timeouts, 0);
        assert!(!engine.is_recovering());
    }

    // ── 恢复策略集成（T009 §6.6）────────────────────────────────

    fn make_report(loss_rate: f64, bandwidth_bps: u64, rtt_ms: f64) -> FeedbackReport {
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

    /// 降级后引擎进入恢复：持续低丢包 + 带宽充足 → 阶梯恢复并返回配置。
    #[test]
    fn test_engine_recovery_after_downgrade() {
        let mut engine = AdaptiveEngine::new(1920, 1080);

        // 降级到 Severe（连续 5 周期 > 6% 丢包）
        for _ in 0..5 {
            engine.on_feedback(&make_report(0.08, 1_000_000, 60.0));
        }
        assert_eq!(
            engine.state_machine.current(),
            NetworkState::SevereCongestion
        );
        assert!(engine.is_recovering(), "downgrade should start recovery");

        // 恢复条件满足（丢包低、带宽足）→ 逐步升档
        let report = make_report(0.002, 8_000_000, 30.0);
        let mut stepped_qps: Vec<u32> = Vec::new();
        let mut last_qp = 35;
        for _ in 0..30 {
            if let Some(config) = engine.on_feedback(&report) {
                if config.qp != last_qp {
                    last_qp = config.qp;
                    stepped_qps.push(config.qp);
                }
            }
        }
        // QP 阶梯：35 → 32 → 28 → 22（最终到高）
        assert_eq!(stepped_qps.first().copied(), Some(32));
        assert_eq!(*stepped_qps.last().unwrap(), 22);
        assert!(!engine.is_recovering(), "recovery completes at high");
    }

    /// 恢复期间丢包回升 → 急停回退到恢复前安全等级（QP 35）+ 冷却。
    #[test]
    fn test_engine_recovery_halt() {
        let mut engine = AdaptiveEngine::new(1920, 1080);
        // 降级到 Severe
        for _ in 0..5 {
            engine.on_feedback(&make_report(0.08, 1_000_000, 60.0));
        }
        // 开始恢复（升 1 级到低 QP 32）
        let report = make_report(0.002, 8_000_000, 30.0);
        let mut stepped = false;
        for _ in 0..8 {
            if let Some(config) = engine.on_feedback(&report) {
                if config.qp == 32 {
                    stepped = true;
                    break;
                }
            }
        }
        assert!(stepped, "should step up to low first");

        // 丢包冲高 → 急停回退到极低（QP 35）
        let mut surge = make_report(0.07, 8_000_000, 30.0);
        let mut halted = false;
        for _ in 0..2 {
            if let Some(config) = engine.on_feedback(&surge) {
                if config.qp == 35 {
                    halted = true;
                    break;
                }
            }
            surge = make_report(0.07, 8_000_000, 30.0);
        }
        assert!(halted, "surge should halt recovery back to QP 35");
    }

    /// 静默窗口加速：恢复期间 2 个连续静默窗口 → 直接跳良好。
    #[test]
    fn test_engine_recovery_silent_jump() {
        let mut engine = AdaptiveEngine::new(1920, 1080);
        for _ in 0..5 {
            engine.on_feedback(&make_report(0.08, 1_000_000, 60.0));
        }
        assert!(engine.is_recovering());

        engine.on_silent_window();
        engine.on_silent_window();
        let config = engine
            .on_feedback(&make_report(0.002, 8_000_000, 30.0))
            .expect("silent jump should produce config");
        assert_eq!(config.qp, 22);
        assert_eq!(config.frame_ratio, 1.0);
        assert!(!engine.is_recovering());
    }

    /// 活跃窗口清零静默计数。
    #[test]
    fn test_engine_silent_reset_on_active() {
        let mut engine = AdaptiveEngine::new(1920, 1080);
        for _ in 0..5 {
            engine.on_feedback(&make_report(0.08, 1_000_000, 60.0));
        }
        engine.on_silent_window();
        engine.on_active_window();
        engine.on_silent_window();
        let result = engine.on_feedback(&make_report(0.002, 8_000_000, 30.0));
        // 静默计数被活跃窗口清零 → 不跳级；可能因阶梯升级返回配置，但不会是 JumpToGood
        if let Some(config) = result {
            assert!(
                !(config.qp == 22 && config.frame_ratio == 1.0),
                "silent jump should not trigger after active window"
            );
        }
    }

    /// QUIC cwnd 崩溃 → 强制最低配置并重启恢复。
    #[test]
    fn test_engine_cwnd_crash_restarts_recovery() {
        let mut engine = AdaptiveEngine::new(1920, 1080);
        let config = engine.on_quic_stats(50.0, 800);
        assert!(config.is_some());
        assert_eq!(config.unwrap().qp, 35);
        assert!(engine.is_recovering());
    }
}
