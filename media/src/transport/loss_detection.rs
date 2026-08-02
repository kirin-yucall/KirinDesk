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
    pub fn record_frame(&mut self, frame_id: u64) {
        if self.last_received > 0 {
            let gap = frame_id.saturating_sub(self.last_received);
            if gap > 1 {
                // 检测到丢失
                for missing_id in (self.last_received + 1)..frame_id {
                    self.missing_frames.push_back(missing_id);
                    self.window_lost += 1;
                }
            }
        }

        self.last_received = frame_id;
        self.window_total += 1;
        self.stats.total_received += 1;
        self.stats.last_received = frame_id;

        // 限制 missing_frames 大小
        while self.missing_frames.len() > 256 {
            self.missing_frames.pop_front();
        }
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
}
