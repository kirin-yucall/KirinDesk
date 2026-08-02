//! FeedbackReport 生成与解码统计。
//!
//! `ReportGenerator` 在客户端运行，从 `LossDetector` 和接收组件收集统计数据，
//! 定期生成 `ControlMessage::FeedbackReport` 发送给服务端。

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::transport::control::ControlMessage;
use crate::transport::LossDetector;

// ════════════════════════════════════════════════════════════════
// DecodeStats
// ════════════════════════════════════════════════════════════════

/// 解码统计（可选）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DecodeStats {
    /// 平均解码耗时（毫秒）
    pub avg_decode_ms: f64,
    /// 最大解码耗时（毫秒）
    pub max_decode_ms: f64,
    /// 已解码帧数
    pub frames_decoded: u64,
    /// 丢弃帧数
    pub frames_dropped: u64,
}

// ════════════════════════════════════════════════════════════════
// FeedbackReport（内部类型）
// ════════════════════════════════════════════════════════════════

/// 解析后的反馈报告（引擎内部使用）。
///
/// 由 `ReportGenerator` 产出，也可以从 `ControlMessage::FeedbackReport` 转换而来。
#[derive(Debug, Clone)]
pub struct FeedbackReport {
    /// 滑动窗口丢包率 (0.0~1.0)
    pub loss_rate: f64,
    /// RTT（毫秒）
    ///
    /// 注意：此处精度 ~1ms。微秒级精度需要在 wire 格式 `ControlMessage::FeedbackReport.rtt_ms`
    /// 上增加 u64 微秒字段，当前 Phase 4 阶段 1ms 精度对远程桌面自适应足够。
    pub rtt_ms: f64,
    /// 包间延迟抖动（微秒）
    pub jitter_us: f64,
    /// 客户端测得的接收带宽 (bps)
    pub bandwidth_bps: u64,
    /// 最近收到的帧 ID
    pub last_frame_id: u64,
    /// 丢失帧 ID 列表
    pub missing_frames: Vec<u64>,
    /// 快速降级标志
    pub urgent_reduce: bool,
    /// 解码统计（可选）
    pub decode_stats: Option<DecodeStats>,
}

impl From<&ControlMessage> for FeedbackReport {
    /// 从 wire 格式的 `ControlMessage::FeedbackReport` 转换。
    fn from(msg: &ControlMessage) -> Self {
        match msg {
            ControlMessage::FeedbackReport {
                loss_rate,
                rtt_ms,
                received_bitrate,
                frame_id,
                missing_frames,
            } => FeedbackReport {
                loss_rate: *loss_rate,
                rtt_ms: *rtt_ms as f64,
                jitter_us: 0.0, // wire 格式暂未携带
                bandwidth_bps: *received_bitrate,
                last_frame_id: *frame_id,
                missing_frames: missing_frames.clone(),
                urgent_reduce: *loss_rate > 0.1,
                decode_stats: None,
            },
            _ => panic!("FeedbackReport::from expects ControlMessage::FeedbackReport"),
        }
    }
}

// ════════════════════════════════════════════════════════════════
// ReportGenerator
// ════════════════════════════════════════════════════════════════

/// 客户端反馈报告生成器。
///
/// 从 `LossDetector` 和接收组件收集统计数据，定期产出 `FeedbackReport`。
pub struct ReportGenerator {
    /// 丢包检测器（从 Phase 3 注入）
    loss_detector: Option<Arc<Mutex<LossDetector>>>,
    /// 解码统计
    decode_stats: DecodeStats,
    /// RTT 估计（由 QUIC 连接提供，微秒）
    rtt_estimate_us: u64,
    /// 接收带宽估计 (bps)
    bandwidth_estimate_bps: u64,
    /// 报告周期（默认 100ms）
    interval: Duration,
    /// 上次报告时间
    last_report: Instant,
    /// 当前解码耗时累积（毫秒）
    decode_ms_accum: f64,
    /// 当前解码计数
    decode_count: u64,
}

impl ReportGenerator {
    /// 创建报告生成器。
    ///
    /// `interval` — 报告周期（推荐 100ms 即 10次/秒）。
    pub fn new(interval: Duration) -> Self {
        Self {
            loss_detector: None,
            decode_stats: DecodeStats::default(),
            rtt_estimate_us: 0,
            bandwidth_estimate_bps: 0,
            interval,
            last_report: Instant::now(),
            decode_ms_accum: 0.0,
            decode_count: 0,
        }
    }

    /// 注入 LossDetector 引用。
    pub fn set_loss_detector(&mut self, detector: Arc<Mutex<LossDetector>>) {
        self.loss_detector = Some(detector);
    }

    /// 更新 RTT 估计（由 QUIC 连接回调）。
    pub fn update_rtt(&mut self, rtt_us: u64) {
        self.rtt_estimate_us = rtt_us;
    }

    /// 更新带宽估计。
    pub fn update_bandwidth(&mut self, bps: u64) {
        self.bandwidth_estimate_bps = bps;
    }

    /// 记录解码一帧。
    pub fn record_decoded_frame(&mut self, decode_ms: f64) {
        self.decode_ms_accum += decode_ms;
        self.decode_count += 1;
        self.decode_stats.frames_decoded += 1;
    }

    /// 记录丢弃帧。
    pub fn record_dropped_frame(&mut self) {
        self.decode_stats.frames_dropped += 1;
    }

    /// 检查是否需要发送报告（基于间隔）。
    pub fn should_report(&self) -> bool {
        self.last_report.elapsed() >= self.interval
    }

    /// 生成报告（每次报告周期调用一次）。
    ///
    /// 重置解码统计计数器。
    pub fn generate(&mut self) -> FeedbackReport {
        // 1. 从 LossDetector 获取丢包数据
        let (loss_rate, last_received, missing_frames) = match &self.loss_detector {
            Some(detector) => {
                let ld = detector.lock().unwrap();
                // auto_reset 在 Phase 3 接收循环中由外部调用
                // 此处只读 read
                if ld.stats().total_received > 0 {
                    (ld.loss_rate(), ld.stats().last_received, {
                        let missing: Vec<u64> =
                            ld.missing_frames().iter().copied().take(64).collect();
                        missing
                    })
                } else {
                    (0.0, 0, vec![])
                }
            }
            None => (0.0, 0, vec![]),
        };

        // 2. 计算解码耗时平均值
        let avg_decode_ms = if self.decode_count > 0 {
            self.decode_ms_accum / self.decode_count as f64
        } else {
            0.0
        };
        self.decode_stats.avg_decode_ms = avg_decode_ms;

        // 3. 构建报告
        let report = FeedbackReport {
            loss_rate,
            rtt_ms: self.rtt_estimate_us as f64 / 1000.0,
            jitter_us: 0.0,
            bandwidth_bps: self.bandwidth_estimate_bps,
            last_frame_id: last_received,
            missing_frames,
            urgent_reduce: loss_rate > 0.1,
            decode_stats: Some(self.decode_stats.clone()),
        };

        // 4. 重置当前周期计数器
        self.decode_ms_accum = 0.0;
        self.decode_count = 0;
        self.decode_stats = DecodeStats {
            frames_decoded: self.decode_stats.frames_decoded, // 保留累计值
            frames_dropped: self.decode_stats.frames_dropped,
            ..Default::default()
        };
        self.last_report = Instant::now();

        report
    }

    /// 直接生成 `ControlMessage`（用于发送）。
    ///
    /// 如果 `should_report()` 为 false，返回 `None`。
    pub fn generate_control_msg(&mut self) -> Option<ControlMessage> {
        if !self.should_report() {
            return None;
        }

        let report = self.generate();

        Some(ControlMessage::FeedbackReport {
            loss_rate: report.loss_rate,
            rtt_ms: report.rtt_ms as u64,
            received_bitrate: report.bandwidth_bps,
            frame_id: report.last_frame_id,
            missing_frames: report.missing_frames,
        })
    }
}

// ── 测试 ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::loss_detection::LossDetector;

    #[test]
    fn test_report_generator_new() {
        let rg = ReportGenerator::new(Duration::from_millis(100));
        assert!(!rg.should_report()); // just created, not elapsed yet
    }

    #[test]
    fn test_report_should_report() {
        let rg = ReportGenerator::new(Duration::from_millis(0)); // 0 interval → always ready
        assert!(rg.should_report());
    }

    #[test]
    fn test_report_generate_no_detector() {
        let mut rg = ReportGenerator::new(Duration::from_millis(0));
        let report = rg.generate();
        assert_eq!(report.loss_rate, 0.0);
        assert!(!report.urgent_reduce);
        assert!(report.decode_stats.is_some());
    }

    #[test]
    fn test_record_decoded_frame() {
        let mut rg = ReportGenerator::new(Duration::from_millis(0));
        rg.record_decoded_frame(5.0);
        rg.record_decoded_frame(15.0);

        let report = rg.generate();
        let stats = report.decode_stats.unwrap();
        assert!((stats.avg_decode_ms - 10.0).abs() < 1e-6);
        assert_eq!(rg.decode_stats.frames_decoded, 2); // 保留累计
    }

    #[test]
    fn test_record_dropped_frame() {
        let mut rg = ReportGenerator::new(Duration::from_millis(0));
        rg.record_dropped_frame();
        rg.record_dropped_frame();
        rg.record_dropped_frame();

        let report = rg.generate();
        let stats = report.decode_stats.unwrap();
        assert_eq!(stats.frames_dropped, 3);
    }

    #[test]
    fn test_generate_control_msg() {
        let mut rg = ReportGenerator::new(Duration::from_millis(0));
        let msg = rg.generate_control_msg();
        assert!(msg.is_some());

        match msg.unwrap() {
            ControlMessage::FeedbackReport { loss_rate, .. } => {
                assert_eq!(loss_rate, 0.0);
            }
            _ => panic!("Expected FeedbackReport"),
        }
    }

    #[test]
    fn test_generate_control_msg_not_ready() {
        let mut rg = ReportGenerator::new(Duration::from_secs(60)); // 60s interval
        let msg = rg.generate_control_msg();
        assert!(msg.is_none()); // should_report() returns false
    }

    #[test]
    fn test_from_control_message() {
        let msg = ControlMessage::FeedbackReport {
            loss_rate: 0.03,
            rtt_ms: 45,
            received_bitrate: 2_500_000,
            frame_id: 1024,
            missing_frames: vec![1010, 1015],
        };

        let report = FeedbackReport::from(&msg);
        assert!((report.loss_rate - 0.03).abs() < 1e-6);
        assert!((report.rtt_ms - 45.0).abs() < 1e-6);
        assert_eq!(report.bandwidth_bps, 2_500_000);
        assert_eq!(report.last_frame_id, 1024);
        assert_eq!(report.missing_frames, vec![1010, 1015]);
        assert!(!report.urgent_reduce); // 3% < 10%
        assert!(report.decode_stats.is_none());
    }

    #[test]
    fn test_urgent_reduce() {
        let msg = ControlMessage::FeedbackReport {
            loss_rate: 0.15,
            rtt_ms: 100,
            received_bitrate: 500_000,
            frame_id: 50,
            missing_frames: vec![],
        };
        let report = FeedbackReport::from(&msg);
        assert!(report.urgent_reduce); // 15% > 10%
    }

    #[test]
    fn test_generate_with_detector() {
        let detector = Arc::new(Mutex::new(LossDetector::new(1000)));
        {
            let mut ld = detector.lock().unwrap();
            ld.record_frame(1);
            ld.record_frame(2);
            ld.record_frame(5); // gap: 3, 4
        }

        let mut rg = ReportGenerator::new(Duration::from_millis(0));
        rg.set_loss_detector(detector);

        let report = rg.generate();
        assert!(report.loss_rate > 0.0);
        assert_eq!(report.last_frame_id, 5);
        assert_eq!(report.missing_frames, vec![3, 4]);
    }
}
