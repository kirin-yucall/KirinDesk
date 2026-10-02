//! 丢包检测。
//!
//! 通过 DATAGRAM frame_id 连续性检测丢包，生成 FeedbackReport。
//! 供 Phase 4 自适应控制器消费。

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// 丢包统计。
#[derive(Debug, Clone, Default)]
pub struct LossStats {
    /// 当前滑动窗口丢包率 (0.0 ~ 1.0)
    pub loss_rate: f64,
    /// 累计收到的帧数
    pub total_received: u64,
    /// 累计丢失的帧数
    pub total_lost: u64,
    /// 最近收到的 frame_id
    pub last_received: u64,
}

/// S-11b（F-14）：frame_id 间隙超过该阈值时不再逐项登记丢失帧，
/// 直接快进 `last_received` 并计 1 次丢失（防对端发 `u64::MAX`
/// 触发 2^64 次循环的 CPU 挂死）。
const MAX_TRACKED_GAP: u64 = 1024;

/// S-11b（F-14）：`missing_frames` 容量上限，登记满即停止追加（内存有界）。
const MAX_MISSING_FRAMES: usize = 256;

/// 基于 frame_id 连续性的丢包检测器。
pub struct LossDetector {
    /// 最近收到的 frame_id
    last_received: u64,
    /// 可能丢失的 frame_id（收到的间隙）
    missing_frames: VecDeque<u64>,
    /// 统计信息
    stats: LossStats,
    /// 统计窗口时长（毫秒）
    window_ms: u64,
    /// 当前窗口开始时间
    window_start: Instant,
    /// 当前窗口总帧数
    window_total: u64,
    /// 当前窗口丢失帧数
    window_lost: u64,
}

impl LossDetector {
    /// 创建新的丢包检测器。
    ///
    /// `window_ms` — 统计窗口时长（毫秒），默认 1000ms。
    pub fn new(window_ms: u64) -> Self {
        Self {
            last_received: 0,
            missing_frames: VecDeque::new(),
            stats: LossStats::default(),
            window_ms,
            window_start: Instant::now(),
            window_total: 0,
            window_lost: 0,
        }
    }

    /// 记录收到的 frame_id。
    ///
    /// 检测间隙：如果 `frame_id` 与 `last_received` 不连续，
    /// 中间的帧被标记为丢失。
    ///
    /// S-11b（F-14）：间隙 > [`MAX_TRACKED_GAP`] 时直接快进（计 1 次丢失，
    /// 不逐项循环）；`missing_frames` 满 [`MAX_MISSING_FRAMES`] 即停止登记。
    pub fn record_frame(&mut self, frame_id: u64) {
        if self.last_received > 0 {
            let gap = frame_id.saturating_sub(self.last_received);
            if gap > 1 {
                if gap > MAX_TRACKED_GAP {
                    // 巨大间隙（如 frame_id=u64::MAX）：只计 1 次丢失事件，
                    // 不逐项登记（2^64 次循环 → 立即收敛）。
                    self.window_lost += 1;
                } else {
                    // 常规间隙：逐项登记丢失帧；满 MAX_MISSING_FRAMES 即 break。
                    for missing_id in (self.last_received + 1)..frame_id {
                        if self.missing_frames.len() >= MAX_MISSING_FRAMES {
                            break;
                        }
                        self.missing_frames.push_back(missing_id);
                        self.window_lost += 1;
                    }
                }
            }
        }

        self.last_received = frame_id;
        self.window_total += 1;
        self.stats.total_received += 1;
        self.stats.last_received = frame_id;
    }

    /// 生成反馈报告（供 Phase 4 自适应用）。
    ///
    /// 返回当前统计窗口内的丢包率、RTT、丢失帧列表等。
    pub fn generate_report(&self) -> (f64, u64, Vec<u64>) {
        let loss_rate = if self.window_total > 0 {
            self.window_lost as f64 / self.window_total as f64
        } else {
            0.0
        };

        let missing: Vec<u64> = self
            .missing_frames
            .iter()
            .copied()
            .take(64) // 最多报告 64 个丢失帧
            .collect();

        (loss_rate, self.last_received, missing)
    }

    /// 重置统计窗口（每秒调用一次）。
    pub fn reset_window(&mut self) {
        let loss_rate = if self.window_total > 0 {
            self.window_lost as f64 / self.window_total as f64
        } else {
            0.0
        };

        self.stats.loss_rate = loss_rate;
        self.stats.total_lost += self.window_lost;

        self.window_total = 0;
        self.window_lost = 0;
        self.window_start = Instant::now();
    }

    /// 自动重置：如果距离上次重置超过 window_ms，则重置。
    pub fn auto_reset(&mut self) {
        if self.window_start.elapsed() >= Duration::from_millis(self.window_ms) {
            self.reset_window();
        }
    }

    /// 当前丢包率（最近的统计窗口）。
    pub fn loss_rate(&self) -> f64 {
        if self.window_total > 0 {
            self.window_lost as f64 / self.window_total as f64
        } else {
            self.stats.loss_rate
        }
    }

    /// 获取统计信息。
    pub fn stats(&self) -> &LossStats {
        &self.stats
    }

    /// 获取丢失帧列表引用。
    pub fn missing_frames(&self) -> &VecDeque<u64> {
        &self.missing_frames
    }

    /// 重置检测器状态（连接重建时）。
    pub fn clear(&mut self) {
        self.last_received = 0;
        self.missing_frames.clear();
        self.stats = LossStats::default();
        self.window_total = 0;
        self.window_lost = 0;
        self.window_start = Instant::now();
    }
}

impl Default for LossDetector {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loss_detector_sequential() {
        let mut ld = LossDetector::new(1000);

        for id in 1..=100 {
            ld.record_frame(id);
        }

        let (loss_rate, last, _) = ld.generate_report();
        assert_eq!(loss_rate, 0.0);
        assert_eq!(last, 100);
    }

    #[test]
    fn test_loss_detector_gap() {
        let mut ld = LossDetector::new(1000);

        ld.record_frame(1);
        ld.record_frame(2);
        ld.record_frame(5); // gap: 3, 4

        let (loss_rate, last, missing) = ld.generate_report();
        assert!(loss_rate > 0.0);
        assert_eq!(last, 5);
        assert_eq!(missing, vec![3, 4]);
    }

    #[test]
    fn test_loss_detector_reset() {
        let mut ld = LossDetector::new(1000);

        ld.record_frame(1);
        ld.record_frame(3); // lost: 2
        ld.reset_window();

        let (loss_rate, _, _) = ld.generate_report();
        assert_eq!(loss_rate, 0.0); // reset clears window counters
    }

    #[test]
    fn test_loss_detector_clear() {
        let mut ld = LossDetector::new(1000);

        ld.record_frame(1);
        ld.record_frame(3);
        ld.clear();

        let (loss_rate, last, missing) = ld.generate_report();
        assert_eq!(loss_rate, 0.0);
        assert_eq!(last, 0);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_loss_detector_multiple_gaps() {
        let mut ld = LossDetector::new(1000);

        ld.record_frame(10);
        ld.record_frame(15); // lost: 11, 12, 13, 14
        ld.record_frame(16);
        ld.record_frame(20); // lost: 17, 18, 19

        let (_, _, missing) = ld.generate_report();
        assert_eq!(missing, vec![11, 12, 13, 14, 17, 18, 19]);
        assert_eq!(missing.len(), 7);
    }

    #[test]
    fn test_loss_detector_single_frame() {
        let mut ld = LossDetector::new(1000);

        ld.record_frame(1);

        let (loss_rate, last, _) = ld.generate_report();
        assert_eq!(loss_rate, 0.0);
        assert_eq!(last, 1);
    }

    #[test]
    fn test_loss_detector_huge_gap_fast_forwards() {
        // S-11d（F-14）：巨大 frame_id 间隙（u64::MAX）→ 立即收敛，
        // 不逐项循环（原实现 2^64 次 → CPU 挂死），只计 1 次丢失。
        let mut ld = LossDetector::new(1000);

        ld.record_frame(1);
        let (loss_rate, last, _) = ld.generate_report();
        assert_eq!(loss_rate, 0.0);
        assert_eq!(last, 1);

        ld.record_frame(u64::MAX);

        let (loss_rate, last, missing) = ld.generate_report();
        assert_eq!(last, u64::MAX, "last_received 直接快进");
        assert!(missing.is_empty(), "巨大间隙不逐项登记丢失帧");
        assert_eq!(ld.window_lost, 1, "只记 1 次丢失统计");
        assert!(loss_rate > 0.0);
    }

    #[test]
    fn test_loss_detector_missing_frames_capped() {
        // S-11d（F-14）：missing_frames 登记满 MAX_MISSING_FRAMES 即停止，
        // 不继续分配（内存有界）。
        let mut ld = LossDetector::new(1000);
        ld.record_frame(1);

        // 4 段常规间隙（每段 300 帧缺失），累计远超上限
        for i in 0..4u64 {
            ld.record_frame(301 + i * 300);
        }

        assert_eq!(ld.missing_frames().len(), 256, "登记满 256 即 break");
        assert!(ld.window_lost <= 256, "丢失计数不超过登记容量");

        // 报告只取前 64 帧
        let (_, _, missing) = ld.generate_report();
        assert_eq!(missing.len(), 64);
    }

    #[test]
    fn test_loss_detector_boundary_gap_1024_still_tracked() {
        // S-11d（回归）：间隙恰好 ≤ 1024 仍走逐项登记路径（上限内不误伤）
        let mut ld = LossDetector::new(1000);
        ld.record_frame(1);
        ld.record_frame(1 + MAX_TRACKED_GAP); // 间隙恰为 1024

        let (_, _, missing) = ld.generate_report();
        assert_eq!(missing.len(), 64, "报告取前 64");
        assert_eq!(ld.missing_frames().len(), 256, "1024 帧缺失被 256 上限截断");
        assert!(ld.window_lost >= 256);
    }
}
