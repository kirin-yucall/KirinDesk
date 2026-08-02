//! 70ms 窗口管理器——将捕获帧按时间窗口批量送编码器。
//!
//! # 核心流程
//!
//! 1. `push_frame(frame)` → 帧入队
//! 2. 检查窗口到期条件：时长 ≥ 70ms || 帧数 ≥ 上限 || 空闲超时
//! 3. 窗口到期 → `encode_current_window()` → 返回 `EncodedWindow`
//! 4. 每个窗口自包含（flush → IDR → N×P帧 → flush）
//!
//! # M13 优化
//!
//! - **M13-T002 可变帧率**：`FpsGovernor` 按内容活动度（相邻帧 tile 采样
//!   比较）把目标帧率分三档（静止 1fps / 中间 10fps / 运动 30fps）。静态
//!   场景下窗口在编码前被门控跳过（返回空窗口，不触碰编码器），带宽与
//!   CPU 消耗随内容自动收敛。
//! - **M13-T004 零拷贝**：无 padding 时直接引用 `RawFrame` 的 `Arc` 缓冲
//!   （原实现每帧 `to_vec()` 全量拷贝 RGBA，1080p 单帧 8MB）；跳帧选择
//!   改为索引引用，不再 clone。

use crate::adaptive::{tile_activity, FpsGovernor, FpsGovernorConfig};
use crate::encoder::types::{Codec, Timestamp};
use crate::encoder::video::EncodeError;
use crate::encoder::VideoEncoderPipeline;
use crate::proto::{EncodeConfig, EncodedWindow, RawFrame, WindowConfig};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

/// 窗口管理器。
pub struct WindowPipeline {
    /// 当前窗口状态
    state: WindowState,
    /// 编码管线（P1C：VideoEncoderPipeline，替代旧 FfmpegEncoder）
    encoder: VideoEncoderPipeline,
    /// 窗口配置
    config: WindowConfig,
    /// 当前编码配置
    encode_config: EncodeConfig,
    /// 窗口计数器
    window_id: u64,
    /// 上一帧时间
    last_frame_time: Option<SystemTime>,
    /// M13-T002 可变帧率控制器（内容活动度 → 目标帧率档位 + 频率门控）
    fps_governor: FpsGovernor,
    /// 上一帧像素缓冲（Arc 零拷贝引用，用于静帧/运动检测）
    prev_frame: Option<(Arc<Vec<u8>>, u32, u32)>,
}

struct WindowState {
    /// 窗口内待编码帧
    frames: Vec<RawFrame>,
    /// 窗口是否已关闭（等待编码）
    closed: bool,
    /// 此窗口是否需要 IDR
    needs_idr: bool,
    /// 窗口开始时间
    start: Option<SystemTime>,
}

impl WindowPipeline {
    /// 创建新窗口管道。
    ///
    /// # 参数
    ///
    /// * `config` — 窗口配置（时长、最大帧数、空闲超时）
    /// * `encoder` — 已初始化的编码管线（VideoEncoderPipeline）
    pub fn new(config: WindowConfig, encoder: VideoEncoderPipeline) -> Self {
        Self {
            state: WindowState {
                frames: Vec::new(),
                closed: false,
                needs_idr: false,
                start: None,
            },
            encoder,
            config,
            encode_config: EncodeConfig::default(),
            window_id: 0,
            last_frame_time: None,
            fps_governor: FpsGovernor::new(),
            prev_frame: None,
        }
    }

    /// 设置可变帧率控制器配置（M13-T002；默认档位 1/10/30fps 已可用，
    /// 需要自定义阈值时调用本方法）。
    pub fn set_fps_governor_config(&mut self, cfg: FpsGovernorConfig) {
        self.fps_governor = FpsGovernor::with_config(cfg);
    }

    /// 当前目标帧率（M13-T002，诊断/日志）。
    pub fn target_fps(&self) -> f64 {
        self.fps_governor.target_fps()
    }

    /// 当前内容活动度（0.0~1.0，M13-T002，诊断/日志）。
    pub fn activity(&self) -> f64 {
        self.fps_governor.activity()
    }

    /// 推入一帧捕获数据。
    ///
    /// 返回 `Some(EncodedWindow)` 当当前窗口关闭（到期/满额/超时/分辨率变化）。
    /// M13-T002：窗口到期但频率门控不放行（静态场景降频）时返回 `Ok(None)`，
    /// 窗口保持打开继续收集最新帧，恢复编码时内容仍最新。
    pub fn push_frame(&mut self, frame: RawFrame) -> Result<Option<EncodedWindow>, String> {
        // M13-T002 静帧/运动检测：与上一帧做 tile 采样比较（零拷贝，
        // 仅 ~10KB 读取；分辨率变化 / 首帧视为大动）。
        let activity = match &self.prev_frame {
            Some((prev, pw, ph)) if *pw == frame.width && *ph == frame.height => {
                tile_activity(
                    &frame.data,
                    prev,
                    frame.width,
                    frame.height,
                    crate::adaptive::fps_governor::DEFAULT_TILE_W,
                    crate::adaptive::fps_governor::DEFAULT_TILE_H,
                )
            }
            _ => 1.0,
        };
        self.fps_governor.feed(activity);
        // Arc 引用（零拷贝）保留上一帧用于下次比较。
        self.prev_frame = Some((Arc::clone(&frame.data), frame.width, frame.height));

        // 更新 IDR 标记
        if frame.force_key {
            self.state.needs_idr = true;
        }

        let now = frame.timestamp;

        // 分辨率变化（注意事项 4）：先 flush 当前窗口，新帧以新尺寸开新窗口。
        // 编码器侧 ensure_codec_dims 会自动释放旧 ctx + 重开（软编），无需
        // 上层重建。
        if let Some(base) = self.state.frames.first() {
            if base.width != frame.width || base.height != frame.height {
                tracing::debug!(
                    "WindowPipeline: resolution change {}x{} -> {}x{}; flushing current window",
                    base.width,
                    base.height,
                    frame.width,
                    frame.height
                );
                // 旧窗口立即编码（帧数 ≥1，必产 Some）。
                let flushed = self.encode_current_window()?.expect(
                    "window with buffered frames must produce an EncodedWindow",
                );
                // 新窗口从本帧开始。
                self.state.start = Some(now);
                self.state.frames.push(frame);
                self.last_frame_time = Some(now);
                return Ok(Some(flushed));
            }
        }

        // 检查是否需要开始新窗口
        if self.state.start.is_none() {
            self.state.start = Some(now);
        }

        // 推入帧
        self.state.frames.push(frame);

        // 检查空闲超时
        let idle_expired = self
            .last_frame_time
            .and_then(|t| now.duration_since(t).ok())
            .map(|d| d.as_millis() >= self.config.idle_timeout_ms as u128)
            .unwrap_or(false);

        self.last_frame_time = Some(now);

        // 检查窗口关闭条件
        let should_close = self.is_window_expired(now)
            || self.state.frames.len() >= self.config.max_frames_per_window as usize
            || idle_expired;

        if should_close {
            // M13-T002 频率门控：静态降频时跳过本窗口编码（返回 None，
            // 窗口保持打开）。flush_window 显式请求不经门控。
            if self.fps_governor.should_encode(Instant::now()) {
                self.encode_current_window()
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// 强制关闭当前窗口并编码。
    pub fn flush_window(&mut self) -> Result<Option<EncodedWindow>, String> {
        if self.state.frames.is_empty() {
            return Ok(None);
        }
        self.encode_current_window()
    }

    /// 更新编码配置（由自适应策略调用）。
    pub fn update_encode_config(&mut self, config: EncodeConfig) {
        self.encode_config = config;
    }

    /// 获取当前编码配置引用。
    pub fn encode_config(&self) -> &EncodeConfig {
        &self.encode_config
    }

    /// 获取编码管线引用（用于直接调用 name/codec 等诊断）。
    pub fn encoder(&mut self) -> &mut VideoEncoderPipeline {
        &mut self.encoder
    }

    /// 检查窗口是否到期。
    fn is_window_expired(&self, now: SystemTime) -> bool {
        self.state
            .start
            .and_then(|t| now.duration_since(t).ok())
            .map(|d| d.as_millis() >= self.config.window_duration_ms as u128)
            .unwrap_or(false)
    }

    /// 编码当前窗口并返回结果。
    fn encode_current_window(&mut self) -> Result<Option<EncodedWindow>, String> {
        let frames = std::mem::take(&mut self.state.frames);
        let needs_idr = self.state.needs_idr;
        self.state.closed = false;
        self.state.needs_idr = false;
        self.state.start = None;

        if frames.is_empty() {
            // 空窗口 → 无数据
            let wid = self.window_id;
            self.window_id += 1;
            return Ok(Some(EncodedWindow {
                window_id: wid,
                frame_count: 0,
                base_w: 0,
                base_h: 0,
                aligned_w: 0,
                aligned_h: 0,
                nalus: vec![],
                frame_nalu_counts: vec![],
                frames: vec![],
                encode_duration_ms: 0.0,
            }));
        }

        // T2.3：窗口边界 flush —— 清空上一窗口残留的参考帧 / 内部缓冲，
        // 配合首帧强制 IDR，保证本窗口完全自包含（无跨窗口参考依赖）。
        // 编码器实现在 flush 后自动置位 force_idr_next（双保险）。
        self.encoder.flush_buffers();

        // 基准分辨率（以第一帧为准）
        let base_w = frames[0].width;
        let base_h = frames[0].height;

        // 16 像素对齐（最低 64x64 满足 HW 编码器要求）
        let align = |v: u32| ((v + 15) / 16) * 16;
        let aligned_w = align(base_w).max(64);
        let aligned_h = align(base_h).max(64);

        // 准备帧数据（pad 到对齐尺寸）—— M13-T004 零拷贝：
        // 无需 pad 时直接借用 RawFrame 的 Arc 缓冲（原实现每帧 to_vec()
        // 全量拷贝，1080p 单帧 8MB）；pad 仅在确实需要时分配。
        let need_pad = base_w != aligned_w || base_h != aligned_h;
        let padded: Vec<Vec<u8>> = if need_pad {
            frames
                .iter()
                .map(|f| pad_rgba(&f.data, base_w, base_h, aligned_w, aligned_h))
                .collect()
        } else {
            Vec::new()
        };
        // 帧视图：无 pad 时借用 frames 内的 Arc 缓冲（frames 存活至编码结束，
        // 零拷贝）；pad 时引用 padded。
        let views: Vec<&[u8]> = if need_pad {
            padded.iter().map(|p| p.as_slice()).collect()
        } else {
            frames.iter().map(|f| f.data.as_slice()).collect()
        };

        // 应用跳帧策略（复用 adaptive::select_frames 保持算法一致）。
        // 保留的是帧视图的**索引**而非 clone 出的像素（M13-T004）。
        let kept: Vec<usize> = if self.encode_config.frame_ratio < 1.0 {
            let indices =
                crate::adaptive::select_frames(views.len(), self.encode_config.frame_ratio);
            // 跳帧后自动强制 IDR：防止接收端 P 帧依赖被丢弃的参考帧
            self.state.needs_idr = true;
            indices
        } else {
            (0..views.len()).collect()
        };

        // 构建编码配置
        let enc_cfg = EncodeConfig {
            qp: self.encode_config.qp,
            force_idr: needs_idr,
            frame_ratio: 1.0,
            preset: self.encode_config.preset.clone(),
        };
        // 应用自适应配置（force_idr 标记 + 未来码率/分辨率联动）。
        let _ = self.encoder.reconfigure(&enc_cfg);

        // 编码（P1C：逐帧经 VideoEncoderPipeline；CPU RGBA 路径）。
        // windows_capture 产 RGBA 字节而非 GpuTexture 句柄，故 on_frame 传入
        // 非空哨兵纹理（pipeline 据此走 classify → 无 GPU 内核降级 FullFrame +
        // 读 set_cpu_frame 喂入的 RGBA）。注：handle 必须非空，否则 preprocess_encode
        // 的 null-texture 校验会拒绝。
        let cpu_tex =
            crate::encoder::types::GpuTexture::new(0x1usize as *mut _, aligned_w, aligned_h);
        let encode_start = Instant::now();
        // T2.6 编码超时保护：单窗口编码预算 = window_duration_ms。逐帧编码后
        // 检查累计耗时，超预算即打断剩余帧（首帧永远编码，避免空窗口），防止
        // 慢编码器把窗口拖长导致端到端延迟雪崩。被打断的帧未送入编码器，
        // 无跨窗口参考依赖（下一窗口首帧仍强制 IDR）。
        let timeout_budget = self.config.window_duration_ms;
        let mut encoded_frames: Vec<Vec<Vec<u8>>> = Vec::with_capacity(kept.len());
        let mut pts_base: u64 = 0;
        let capture_instant = Instant::now();
        for (i, &idx) in kept.iter().enumerate() {
            if i > 0 && encode_start.elapsed().as_millis() >= timeout_budget as u128 {
                tracing::debug!(
                    "WindowPipeline: encode timeout ({}ms >= {}ms budget); \
                     dropping {} remaining frame(s)",
                    encode_start.elapsed().as_millis(),
                    timeout_budget,
                    kept.len() - i
                );
                break;
            }
            // force_idr：窗口首帧 / 自适应跳帧后强制刷新参考帧。
            let force_idr = i == 0 || needs_idr;
            let rgba = views[idx];
            self.encoder
                .set_cpu_frame(rgba, aligned_w, aligned_h, force_idr);
            let ts = Timestamp::new(capture_instant, pts_base);
            pts_base = pts_base.saturating_add(33); // ~30fps 占位 PTS（毫秒）。
            let packets = self
                .encoder
                .on_frame(&cpu_tex, ts)
                .map_err(|e: EncodeError| format!("encode frame[{i}]: {e}"))?;
            // 把每帧产出的 EncodedPacket.data 收为一个子 Vec（保持
            // EncodedWindow.frames = Vec<Vec<Vec<u8>>> 的旧形状）。
            let frame_nalus: Vec<Vec<u8>> = packets.into_iter().map(|p| p.data).collect();
            encoded_frames.push(frame_nalus);
        }
        let encode_duration = encode_start.elapsed().as_secs_f64() * 1000.0;
        // M13-T002：记录本次编码时间（频率门控基准）。
        self.fps_governor.mark_encoded(Instant::now());

        let wid = self.window_id;
        self.window_id += 1;

        Ok(Some(EncodedWindow {
            window_id: wid,
            frame_count: kept.len() as u32,
            base_w,
            base_h,
            aligned_w,
            aligned_h,
            nalus: vec![],
            frame_nalu_counts: vec![],
            frames: encoded_frames,
            encode_duration_ms: encode_duration,
        }))
    }
}

/// 将 RGBA 数据 pad 到指定尺寸（底部和右侧填充 0）。
fn pad_rgba(src: &[u8], src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Vec<u8> {
    let src_stride = (src_w * 4) as usize;
    let dst_stride = (dst_w * 4) as usize;
    let mut dst = vec![0u8; dst_stride * dst_h as usize];

    let copy_h = src_h.min(dst_h) as usize;
    let copy_w = ((src_w * 4) as usize).min(dst_stride);

    for y in 0..copy_h {
        let src_off = y * src_stride;
        let dst_off = y * dst_stride;
        dst[dst_off..dst_off + copy_w].copy_from_slice(&src[src_off..src_off + copy_w]);
    }

    dst
}

// ════════════════════════════════════════════════════════════════
// P1F §T6.3 桥接：EncodedWindow → EncodedPacket 流
// ════════════════════════════════════════════════════════════════
//
// 把 WindowPipeline 的输出（EncodedWindow，旧 Vec<Vec<Vec<u8>>> 形状）转成
// 传输层 [`crate::transport::stream`] 消费的 EncodedPacket 流（kind=Video）。
// 上层（服务端主循环）拿到 Vec<EncodedPacket> 后推入 SecureChannelTransport
// 或 QuicMediaTransport 的 PriorityQueue 发送。
//
// 设计上保留 EncodedWindow 旧形状不变（解码侧 / UI 仍依赖），本桥接为纯转换，
// 不破坏现有契约。PTS 取会话相对毫秒（与音频同轴）；空窗口返回空 Vec（全静零输出，
// 心跳归 dns/heartbeat.rs）。

/// 会话起点 PTS 基准（毫秒）。0 表示从会话起始起算。
///
/// 由调用方在会话建立时设置（连接管理器重置时清零）；本桥接只负责把窗口内
/// 各帧按 ~33ms（30fps 占位）累加到基准之上，与 audio 流水线的 pts 同轴。
pub fn window_to_packets(
    window: &EncodedWindow,
    session_pts_base_ms: u64,
) -> Vec<crate::encoder::types::EncodedPacket> {
    use crate::encoder::types::{EncodedPacket, PacketKind, Timestamp};
    use std::time::Instant;

    // 空窗口：frame_count=0 或 frames 全空。EncodedWindow.is_empty() 只看 nalus
    // 扁平字段，但旧 window_pipeline 仍把数据填进 frames（nalus 为空），故这里
    // 兼容判断 frames 与 frame_count。
    if window.frame_count == 0 && window.frames.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(window.frame_count as usize);
    let capture_instant = Instant::now();
    for (frame_idx, frame_nalus) in window.frames.iter().enumerate() {
        // 合并该帧所有 NAL 为单条 Annex B 字节流。
        let mut data = Vec::new();
        for nal in frame_nalus {
            data.extend_from_slice(nal);
        }
        if data.is_empty() {
            continue;
        }
        // PTS：每帧 +33ms（~30fps 占位，与 encode_current_window 内的 pts_base 累加一致）。
        let pts = session_pts_base_ms.saturating_add((frame_idx as u64) * 33);
        out.push(EncodedPacket {
            ts: Timestamp::new(capture_instant, pts),
            kind: PacketKind::Video,
            data,
            // 窗口首帧为 IDR（window_pipeline 强制 force_idr on i==0）。
            is_key: frame_idx == 0,
        });
    }
    out
}

#[cfg(test)]
mod bridge_tests {
    use super::*;
    use crate::encoder::types::PacketKind;

    /// 空窗口 → 0 包（全静零输出，心跳归 dns）。
    #[test]
    fn test_window_to_packets_empty() {
        let empty = EncodedWindow {
            window_id: 0,
            frame_count: 0,
            base_w: 0,
            base_h: 0,
            aligned_w: 0,
            aligned_h: 0,
            nalus: vec![],
            frame_nalu_counts: vec![],
            frames: vec![],
            encode_duration_ms: 0.0,
        };
        assert!(window_to_packets(&empty, 0).is_empty());
    }

    /// 多帧窗口 → 每帧一个 EncodedPacket（kind=Video），首帧 is_key=true，
    /// PTS 单调（基准 + 帧序*33ms）。
    #[test]
    fn test_window_to_packets_multi_frame() {
        let window = EncodedWindow {
            window_id: 1,
            frame_count: 2,
            base_w: 640,
            base_h: 480,
            aligned_w: 640,
            aligned_h: 480,
            nalus: vec![],
            frame_nalu_counts: vec![],
            frames: vec![vec![vec![0xAA; 10], vec![0xBB; 5]], vec![vec![0xCC; 8]]],
            encode_duration_ms: 1.0,
        };
        let pkts = window_to_packets(&window, 100);
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0].kind, PacketKind::Video);
        assert!(pkts[0].is_key, "first frame is IDR");
        assert!(!pkts[1].is_key, "subsequent frame is P");
        // 数据合并：第一帧 10+5=15B，第二帧 8B。
        assert_eq!(pkts[0].data.len(), 15);
        assert_eq!(pkts[1].data.len(), 8);
        // PTS 单调（基准 100 → 100, 133）。
        assert_eq!(pkts[0].ts.pts, 100);
        assert_eq!(pkts[1].ts.pts, 133);
    }

    /// 跳过空 NAL 帧（不产空包）。
    #[test]
    fn test_window_to_packets_skips_empty_frame() {
        let window = EncodedWindow {
            window_id: 1,
            frame_count: 2,
            base_w: 640,
            base_h: 480,
            aligned_w: 640,
            aligned_h: 480,
            nalus: vec![],
            frame_nalu_counts: vec![],
            frames: vec![vec![], vec![vec![0xDD; 4]]],
            encode_duration_ms: 0.0,
        };
        let pkts = window_to_packets(&window, 0);
        // 第一帧空 → 跳过；只产出第二帧 1 个包。
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].data, vec![0xDD; 4]);
        // 第二帧 frame_idx=1 → PTS=33（不是 0），保持时间轴连续。
        assert_eq!(pkts[0].ts.pts, 33);
    }
}

// ════════════════════════════════════════════════════════════════
// 测试
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::RawFrame;
    use std::sync::Arc;
    use std::time::Duration;

    fn make_test_frame(w: u32, h: u32, fill: u8) -> RawFrame {
        let data = vec![fill; (w * h * 4) as usize];
        RawFrame {
            data: Arc::new(data),
            width: w,
            height: h,
            timestamp: SystemTime::now(),
            dirty_rects: vec![],
            force_key: false,
        }
    }

    #[test]
    fn test_pad_rgba() {
        let src = vec![42u8; 100 * 100 * 4];
        let padded = pad_rgba(&src, 100, 100, 128, 128);
        assert_eq!(padded.len(), 128 * 128 * 4);
        // 前 100 行应保留原始数据
        for y in 0..100 {
            let src_off = y * 100 * 4;
            let dst_off = y * 128 * 4;
            assert_eq!(
                &padded[dst_off..dst_off + 400],
                &src[src_off..src_off + 400]
            );
        }
        // 填充区应为 0
        for y in 0..128 {
            let off = y * 128 * 4 + 400;
            if y < 100 {
                assert_eq!(padded[off..off + (128 - 100) * 4], vec![0u8; (28 * 4)]);
            } else {
                let start = y * 128 * 4;
                assert_eq!(padded[start..start + 128 * 4], vec![0u8; 128 * 4]);
            }
        }
    }

    #[test]
    fn test_window_pipeline_empty() {
        // 没有编码器无法实际编码，只测试空窗口
        // encode_window 的完整测试需要在有 FFmpeg DLL 的环境运行
    }

    #[test]
    fn test_window_pipeline_flush_empty() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig::default();
        let mut pipe = WindowPipeline::new(config, encoder);

        // flush 空窗口 → None
        let result = pipe.flush_window().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_window_pipeline_single_frame() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 1,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        let frame = make_test_frame(640, 480, 128);
        let result = pipe.push_frame(frame).unwrap();

        assert!(result.is_some(), "should close window after 1 frame");
        let window = result.unwrap();
        assert_eq!(window.frame_count, 1);
        assert_eq!(window.base_w, 640);
        assert_eq!(window.base_h, 480);
        assert!(!window.frames.is_empty(), "should have encoded packets");
        assert!(
            !window.frames[0].is_empty(),
            "first frame should have packets"
        );
    }

    #[test]
    fn test_window_pipeline_multi_frame() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 3,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        // push 2 frames → 不应关闭 (2 < max 3)
        let f1 = make_test_frame(640, 480, 128);
        let r1 = pipe.push_frame(f1).unwrap();
        assert!(r1.is_none(), "1 frame < max 3, window should stay open");

        let f2 = make_test_frame(640, 480, 200);
        let r2 = pipe.push_frame(f2).unwrap();
        assert!(r2.is_none(), "2 frames < max 3, window should stay open");

        // push 第 3 帧 → 触发关闭 (3 >= max 3)
        let f3 = make_test_frame(640, 480, 64);
        let r3 = pipe.push_frame(f3).unwrap();
        assert!(r3.is_some(), "3 frames >= max 3, window should close");
        let window = r3.unwrap();
        assert_eq!(window.frame_count, 3);
    }

    // ════════════════════════════════════════════════════════════
    // M8-T011 T2.7 测试：窗口到期 / IDR / P 帧 / 跳帧 / 对齐 / 配置更新
    // ════════════════════════════════════════════════════════════

    /// 解析 Annex B 字节流中的所有 NAL type（跳过 00 00 01 / 00 00 00 01 起始码）。
    /// H.264 NAL type：1=P slice，5=IDR slice，7=SPS，8=PPS。
    fn annex_b_nal_types(data: &[u8]) -> Vec<u8> {
        let mut types = Vec::new();
        let mut i = 0usize;
        while i + 3 < data.len() {
            if data[i] == 0 && data[i + 1] == 0 {
                let mut j = i + 2;
                while j < data.len() && data[j] == 0 {
                    j += 1;
                }
                if j + 1 < data.len() && data[j] == 1 {
                    // NAL header 在起始码后：forbidden(1) | nri(2) | type(5)。
                    types.push(data[j + 1] & 0x1F);
                    i = j + 1;
                    continue;
                }
            }
            i += 1;
        }
        types
    }

    /// 合并帧内所有包并解析 NAL type 列表。
    fn frame_nal_types(frame: &[Vec<u8>]) -> Vec<u8> {
        let mut all = Vec::new();
        for p in frame {
            all.extend_from_slice(p);
        }
        annex_b_nal_types(&all)
    }

    /// 构造指定时间戳的测试帧。
    fn make_test_frame_at(w: u32, h: u32, fill: u8, ts: SystemTime) -> RawFrame {
        let data = vec![fill; (w * h * 4) as usize];
        RawFrame {
            data: Arc::new(data),
            width: w,
            height: h,
            timestamp: ts,
            dirty_rects: vec![],
            force_key: false,
        }
    }

    /// 窗口到期（时长 ≥ 70ms）：间隔 100ms 的两帧 → 第二帧触发关闭。
    #[test]
    fn test_window_pipeline_expiry() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 10, // 不触发 max_frames
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        let now = SystemTime::now();
        // 第一帧时间戳在 100ms 前（模拟慢捕获节拍）。
        let f1 = make_test_frame_at(640, 480, 128, now - Duration::from_millis(100));
        let r1 = pipe.push_frame(f1).unwrap();
        assert!(r1.is_none(), "first frame opens window, no close yet");

        // 第二帧：与窗口开始间隔 100ms ≥ 70ms → 到期关闭。
        let f2 = make_test_frame_at(640, 480, 200, now);
        let r2 = pipe.push_frame(f2).unwrap();
        let window = r2.expect("window should close on expiry");
        assert_eq!(window.frame_count, 2);
    }

    /// 窗口首帧必须产出 IDR（NAL type 5 + SPS/PPS 前置）。
    #[test]
    fn test_encode_window_idr_first() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 2,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        let f1 = make_test_frame(640, 480, 128);
        let r1 = pipe.push_frame(f1).unwrap();
        assert!(r1.is_none(), "1 frame < max 2");
        let f2 = make_test_frame(640, 480, 200);
        let window = pipe.push_frame(f2).unwrap().expect("2 frames -> close");

        assert_eq!(window.frame_count, 2);
        let first_types = frame_nal_types(&window.frames[0]);
        assert!(
            first_types.contains(&5),
            "first frame must be IDR (NAL type 5), got {:?}",
            first_types
        );
    }

    /// 窗口第二帧为 P 帧（非 IDR，无跨窗口 IDR 依赖之外的参考帧）。
    #[test]
    fn test_encode_window_p_frame() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 2,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        let f1 = make_test_frame(640, 480, 128);
        let _ = pipe.push_frame(f1).unwrap();
        let f2 = make_test_frame(640, 480, 200);
        let window = pipe.push_frame(f2).unwrap().expect("2 frames -> close");

        let second_types = frame_nal_types(&window.frames[1]);
        assert!(
            !second_types.contains(&5),
            "second frame must not be IDR, got {:?}",
            second_types
        );
    }

    /// frame_ratio < 1.0 → 跳帧：4 帧按 0.5 保留 2 帧（select_frames step=2）。
    #[test]
    fn test_encode_window_skip_frames() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 10,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);
        pipe.update_encode_config(EncodeConfig {
            frame_ratio: 0.5,
            ..Default::default()
        });

        for i in 0..4u8 {
            let r = pipe.push_frame(make_test_frame(640, 480, i * 40 + 20)).unwrap();
            assert!(r.is_none(), "4 frames < max 10, no close yet");
        }
        let window = pipe.flush_window().unwrap().expect("flush should encode");
        // select_frames(4, 0.5) = step 2 → 保留 [0, 2]。
        assert_eq!(window.frame_count, 2, "frame_ratio 0.5 of 4 frames = 2");
    }

    /// 非 16 对齐尺寸 → 自动 pad 到 16 的倍数（且 ≥ 64）。
    #[test]
    fn test_encode_window_alignment() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 1,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        let window = pipe
            .push_frame(make_test_frame(100, 100, 64))
            .unwrap()
            .expect("1 frame -> close");
        assert_eq!(window.base_w, 100);
        assert_eq!(window.base_h, 100);
        assert_eq!(window.aligned_w, 112, "100 -> align to 112");
        assert_eq!(window.aligned_h, 112, "100 -> align to 112");
    }

    /// 动态更新编码配置（QP）→ encode_config 生效且编码链路无错。
    #[test]
    fn test_encode_config_update() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 1,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        pipe.update_encode_config(EncodeConfig {
            qp: 20,
            preset: "veryfast".into(),
            ..Default::default()
        });
        assert_eq!(pipe.encode_config().qp, 20);
        assert_eq!(pipe.encode_config().preset, "veryfast");

        // 新配置经 reconfigure 传入编码器；编码成功即链路无错。
        let window = pipe
            .push_frame(make_test_frame(640, 480, 128))
            .unwrap()
            .expect("1 frame -> close");
        assert_eq!(window.frame_count, 1);
    }

    /// 窗口 ID 单调连续递增（跨多个窗口）。
    ///
    /// M13-T002 注：快速连续推送（<33ms）可能被频率门控节流（push_frame
    /// 返回 None、窗口保持打开）——显式 `flush_window` 请求不经门控，
    /// 保证窗口 ID 按序推进。
    #[test]
    fn test_window_id_sequential() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 1, // 每帧一个窗口
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        for expected in 0..3u64 {
            let r = pipe
                .push_frame(make_test_frame(640, 480, 32 + expected as u8 * 40))
                .unwrap();
            let window = match r {
                Some(w) => w,
                // 频率门控节流 → 显式 flush（不经门控）编码当前窗口。
                None => pipe.flush_window().unwrap().expect("flush should encode"),
            };
            assert_eq!(window.window_id, expected, "window id must be sequential");
        }
    }

    /// 分辨率变化 → 自动 flush 当前窗口，新帧以新尺寸开新窗口。
    #[test]
    fn test_window_pipeline_resolution_change() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 10, // 不触发 max_frames
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        // 640x480 帧入窗（未关闭）。
        let r1 = pipe.push_frame(make_test_frame(640, 480, 128)).unwrap();
        assert!(r1.is_none());

        // 1280x720 帧 → 分辨率变化 → 旧窗口（640x480）立即 flush 返回。
        let r2 = pipe.push_frame(make_test_frame(1280, 720, 200)).unwrap();
        let old_window = r2.expect("resolution change must flush current window");
        assert_eq!(old_window.base_w, 640);
        assert_eq!(old_window.base_h, 480);

        // 新尺寸帧继续入新窗口（不关闭），flush 后新窗口为新尺寸。
        let r3 = pipe.push_frame(make_test_frame(1280, 720, 64)).unwrap();
        assert!(r3.is_none(), "same-size frames stay in new window");
        let new_window = pipe.flush_window().unwrap().expect("flush should encode");
        assert_eq!(new_window.base_w, 1280);
        assert_eq!(new_window.base_h, 720);
        assert_eq!(new_window.frame_count, 2);
    }

    /// flush_window 编码当前窗口（有帧时）。
    #[test]
    fn test_window_pipeline_flush_encodes() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 10,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        let r1 = pipe.push_frame(make_test_frame(640, 480, 128)).unwrap();
        assert!(r1.is_none());
        let r2 = pipe.push_frame(make_test_frame(640, 480, 200)).unwrap();
        assert!(r2.is_none());

        let window = pipe.flush_window().unwrap().expect("flush should encode");
        assert_eq!(window.frame_count, 2);
    }

    // ════════════════════════════════════════════════════════════
    // M8-T011 T2.6 测试：编码超时保护
    // ════════════════════════════════════════════════════════════

    /// 慢编码器（超时保护测试注入）：每帧固定 sleep，产出 1 个假包。
    /// 经 `VideoEncoderPipeline::from_parts` 注入，WindowPipeline 对编码
    /// 耗时可控。
    struct SlowEncoder {
        per_frame_ms: u64,
    }

    impl crate::encoder::video::VideoEncoder for SlowEncoder {
        fn encode(
            &mut self,
            _tex: &crate::encoder::types::GpuTexture,
            ts: crate::encoder::types::Timestamp,
            _decision: crate::encoder::types::EncodeDecision,
        ) -> Result<Vec<crate::encoder::types::EncodedPacket>, crate::encoder::video::EncodeError>
        {
            std::thread::sleep(Duration::from_millis(self.per_frame_ms));
            Ok(vec![crate::encoder::types::EncodedPacket {
                ts,
                kind: crate::encoder::types::PacketKind::Video,
                data: vec![0x00, 0x00, 0x00, 0x01, 0x41], // Annex B P-slice 占位
                is_key: false,
            }])
        }

        fn codec(&self) -> Codec {
            Codec::H264
        }

        fn is_hardware(&self) -> bool {
            false
        }

        fn name(&self) -> &'static str {
            "slow-test"
        }

        fn reconfigure(&mut self, _cfg: &EncodeConfig) -> Result<(), crate::encoder::video::EncodeError> {
            Ok(())
        }
    }

    /// 单窗口编码累计耗时 ≥ 窗口预算 → 打断剩余帧（至少保留首帧）。
    /// 慢编码器 30ms/帧 + 预算 50ms → 2 帧（60ms）后必打断。
    #[test]
    fn test_encode_window_timeout_break() {
        if crate::ffmpeg::ensure_loaded().is_err() {
            eprintln!("Skipping: no FFmpeg DLLs available");
            return;
        }
        let slow = Box::new(SlowEncoder { per_frame_ms: 30 });
        let pipeline = match VideoEncoderPipeline::from_parts(None, slow) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Skipping: pipeline from_parts failed: {e}");
                return;
            }
        };
        let config = WindowConfig {
            window_duration_ms: 50, // 预算 50ms
            max_frames_per_window: 10,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, pipeline);

        for i in 0..5u8 {
            let r = pipe.push_frame(make_test_frame(640, 480, i * 40)).unwrap();
            assert!(r.is_none(), "5 frames < max 10, no close yet");
        }
        let window = pipe.flush_window().unwrap().expect("flush should encode");
        // 5 帧 × 30ms = 150ms >> 50ms 预算 → 必然打断。
        assert!(
            window.frame_count < 5,
            "timeout protection must drop frames, got {}",
            window.frame_count
        );
        // 首帧永远编码（避免空窗口）。
        assert!(window.frame_count >= 1);
    }

    /// 超时保护不误伤正常窗口：预算充足时所有帧完整编码。
    #[test]
    fn test_encode_window_timeout_preserves_normal_path() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 3,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        for i in 0..3u8 {
            let r = pipe.push_frame(make_test_frame(640, 480, i * 40)).unwrap();
            if i < 2 {
                assert!(r.is_none(), "frame {} should not close window", i);
            }
        }
        let window = pipe
            .push_frame(make_test_frame(640, 480, 120))
            .unwrap()
            .expect("3 frames -> close");
        assert_eq!(window.frame_count, 3, "normal window encodes all frames");
    }

    // ════════════════════════════════════════════════════════════
    // M13-T002 测试：可变帧率（静帧降频门控 + 运动恢复）
    // ════════════════════════════════════════════════════════════

    /// 静帧场景：首窗口编码后，后续相同内容窗口被频率门控节流
    /// （push 返回 None、不触碰编码器）；flush 显式编码不受门控。
    #[test]
    fn test_fps_governor_static_throttles() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 1,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        // 首窗口：无编码历史 → 必编码。
        let r1 = pipe.push_frame(make_test_frame(640, 480, 128)).unwrap();
        assert!(r1.is_some(), "first window must encode");
        assert_eq!(pipe.target_fps(), 30.0, "初始运动档");

        // 连续推送相同内容：目标帧率降至静态档，窗口被节流（None）。
        let mut throttled = 0;
        for _ in 0..5 {
            if pipe.push_frame(make_test_frame(640, 480, 128)).unwrap().is_none() {
                throttled += 1;
            }
        }
        assert!(throttled >= 4, "静态场景应被节流, got {throttled}");
        assert!(
            pipe.target_fps() <= 10.0,
            "静态内容目标帧率应降至中间档以下, got {}",
            pipe.target_fps()
        );
        assert!(
            pipe.activity() <= 0.001,
            "静态内容活动度应接近 0, got {}",
            pipe.activity()
        );
        // flush 显式编码不受门控。
        let w = pipe.flush_window().unwrap().expect("flush encodes");
        assert!(w.frame_count >= 1);
    }

    /// 运动恢复：内容变化 → 目标帧率立即回升到 30fps。
    #[test]
    fn test_fps_governor_motion_recovers() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 1,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        // 静态一段时间（降频确认）。
        for _ in 0..6 {
            let _ = pipe.push_frame(make_test_frame(640, 480, 64)).unwrap();
        }
        assert!(pipe.target_fps() <= 10.0, "静态后应降频");
        // 运动帧 → 立即升回 30fps。
        let _ = pipe.push_frame(make_test_frame(640, 480, 200)).unwrap();
        assert_eq!(pipe.target_fps(), 30.0);
    }

    /// 分辨率变化 → 活动度按大动处理（目标帧率保持运动档）。
    #[test]
    fn test_fps_governor_resolution_change_is_motion() {
        let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: no FFmpeg encoder available");
                return;
            }
        };
        let config = WindowConfig {
            max_frames_per_window: 10,
            ..Default::default()
        };
        let mut pipe = WindowPipeline::new(config, encoder);

        let _ = pipe.push_frame(make_test_frame(640, 480, 64)).unwrap();
        // 尺寸变化帧：prev_frame 尺寸不同 → 活动度 1.0 → 运动档。
        let _ = pipe.push_frame(make_test_frame(1280, 720, 64)).unwrap();
        assert_eq!(pipe.target_fps(), 30.0);
    }
}
