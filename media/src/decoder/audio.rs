//! 音频解码（M8-T015 P2C）：libopus 解码 + jitter buffer + 解码流水线。
//!
//! 对称编码层 P1D `encoder/audio`：本模块实现
//! - [`OpusDecoder`]：FFmpeg `libopus` 经 avcodec 解码（`avcodec_find_decoder
//!   (AV_CODEC_ID_OPUS)`），输入 Opus 包（20ms），输出 PCM float32 interleaved
//!   stereo，实现接口层 [`AudioDecoder`] trait。
//! - [`AudioJitterBuffer`]：3~5 帧抗抖动，乱序包按 PTS 排序、缺帧静音补帧、
//!   迟到包丢弃（编码层 §8 同款策略）。
//! - [`AudioDecodePipeline`]：接收 Opus 包 → 解码 → jitter → 播放的独立流水线
//!   （调用方为其开独立线程，与视频/UI 完全隔离）。
//!
//! # 解码参数（与编码层 P1D / M12 严格一致）
//!
//! | 参数 | 值 |
//! |------|-----|
//! | sample_rate | 48000 |
//! | channels | 2（stereo） |
//! | 帧长 | 20ms（960 samples/ch） |
//! | 格式 | float32（AV_SAMPLE_FMT_FLT，FFmpeg opus 解码器输出 packed） |
//! | 输入码率 | 64kbps（编码侧） |
//!
//! # 关键约束
//!
//! - libopus 统一走 FFmpeg avcodec（与视频同栈、同 DLL 加载路径），不直接
//!   链接 opus SDK、不 spawn 进程。
//! - 播放端平台原生 API（Windows WASAPI 共享渲染，见
//!   [`crate::decoder::audio_playback`]；macOS/Linux 留桩：解码完成但静音）。
//! - 音频独立流水线：故障不影响视频/键鼠。

use std::ffi::c_void;
use std::sync::mpsc;

use crate::decoder::{AudioDecoder, AudioPacket, DecodeError};
use crate::ffmpeg;

// ════════════════════════════════════════════════════════════════
// 解码参数（与编码层 P1D / M12 一致）
// ════════════════════════════════════════════════════════════════

/// 采样率：48000Hz（M12）。
pub const SAMPLE_RATE: u32 = 48_000;
/// 声道数：2（stereo，M12）。
pub const CHANNELS: u16 = 2;
/// 帧长：20ms（M12）。
pub const FRAME_MS: u64 = 20;
/// 每帧每声道采样数：960（48000 × 20ms / 1000）。
pub const FRAME_SAMPLES: usize = (SAMPLE_RATE as usize) * (FRAME_MS as usize) / 1000; // 960
/// 每帧 interleaved float32 样本数（960 × 2 声道 = 1920）。
pub const FRAME_INTERLEAVED: usize = FRAME_SAMPLES * (CHANNELS as usize); // 1920

// ════════════════════════════════════════════════════════════════
// AudioPcm — 解码后的 PCM 帧（含 PTS）
// ════════════════════════════════════════════════════════════════

/// 缓冲内的 PCM（含 PTS）。
///
/// `samples` 为 **interleaved stereo float32**（`[L0,R0,L1,R1,...]`，
/// 48000Hz，20ms = 1920 个样本）。
#[derive(Debug, Clone)]
pub struct AudioPcm {
    /// 会话相对毫秒 PTS（与视频同轴，lip-sync 用）。
    pub pts: u64,
    /// interleaved stereo float32 PCM。
    pub samples: Vec<f32>,
}

// ════════════════════════════════════════════════════════════════
// OpusDecoder — FFmpeg libopus 解码（P2C T3.1）
// ════════════════════════════════════════════════════════════════

/// FFmpeg libopus 解码器（in-process 常驻，会话级复用）。
///
/// 对称编码层 P1D `OpusEncoder`：输入 Opus 包（20ms），输出 PCM float32
/// interleaved stereo。一个 Opus 包固定解码出 960 samples/ch × 2ch =
/// 1920 float32（20ms @48000）。
///
/// # 解码器容错
///
/// - 损坏 Opus 包（AVERROR_INVALIDDATA）→ 跳过该包，返回空 vec（不重建
///   上下文，opus 解码器容错强）。
/// - 静音包（opus DTX 极小包）→ 正常解码为静音 PCM，时间轴连续。
/// - 包乱序到达 → 由 jitter buffer（[`AudioJitterBuffer`]）排序后送解码，
///   解码器不感知乱序。
pub struct OpusDecoder {
    /// AVCodecContext*（opus；不透明，配置走 av_opt_set*）。
    ctx: *mut ffmpeg::AVCodecContext,
    /// AVCodec*（opus decoder；仅持有引用，不释放）。
    decoder: *const ffmpeg::AVCodec,
    /// 复用 AVFrame（解码输出 float32 packed）。
    frame: *mut ffmpeg::AVFrame,
    /// 复用 AVPacket。
    packet: *mut ffmpeg::AVPacket,
    /// 单调 PTS（会话毫秒，与视频同轴；从首个包起算，仅作时钟跟踪）。
    next_pts: u64,
}

// 解码器在单线程解码任务中独占使用；裸指针的 Send 由调用方保证（与
// FfmpegSwDecoder / OpusEncoder 一致）。
unsafe impl Send for OpusDecoder {}

impl OpusDecoder {
    /// 创建：`avcodec_find_decoder(AV_CODEC_ID_OPUS)` → `avcodec_alloc_context3`
    /// → 设 sample_rate / ch_layout=stereo → `avcodec_open2`。
    pub fn new() -> Result<Self, DecodeError> {
        ffmpeg::ensure_loaded().map_err(|e| DecodeError::InitFailed(format!("DLLs: {e}")))?;
        let decoder = ffmpeg::avcodec_find_decoder(ffmpeg::AV_CODEC_ID_OPUS).map_err(|_| {
            DecodeError::CodecNotFound(
                "opus decoder not in ffmpeg build (需 --enable-libopus)".into(),
            )
        })?;
        let ctx = ffmpeg::avcodec_alloc_context3(decoder)?;

        // 配置（best-effort：libopus 不认的项忽略，不阻断 open2）。
        // opus 解码输出由码流决定，但显式声明 48k/stereo 与编码侧对称
        // （FFmpeg 8.x 用 ch_layout，字符串 "stereo" 解析为 NATIVE 立体声）。
        let obj = ctx as *mut c_void;
        let _ = ffmpeg::av_opt_set_int(obj, "sample_rate", SAMPLE_RATE as i64);
        let _ = ffmpeg::av_opt_set(obj, "ch_layout", "stereo");

        if let Err(e) = ffmpeg::avcodec_open2(ctx, decoder) {
            let mut ctx_opt = ctx;
            ffmpeg::avcodec_free_context(&mut ctx_opt);
            return Err(DecodeError::AvError(e));
        }
        let frame = ffmpeg::av_frame_alloc()?;
        let packet = ffmpeg::av_packet_alloc().map_err(|e| {
            let mut f = frame;
            ffmpeg::av_frame_free(&mut f);
            e
        })?;

        tracing::info!(
            "OpusDecoder: opened libopus via avcodec ({}Hz/stereo/{}ms)",
            SAMPLE_RATE,
            FRAME_MS
        );

        Ok(Self {
            ctx,
            decoder,
            frame,
            packet,
            next_pts: 0,
        })
    }

    /// 解码一个 Opus 包（20ms）→ PCM float32 interleaved stereo。
    ///
    /// 返回 `[L0,R0,L1,R1,...]`（960 samples/ch × 2ch = 1920 float32）。
    /// 损坏包（send/receive 报 INVALIDDATA）→ `Ok(vec![])`（跳过，不重建）。
    pub fn decode(&mut self, packet: &AudioPacket) -> Result<Vec<f32>, DecodeError> {
        if packet.data.is_empty() {
            return Err(DecodeError::InvalidData("empty opus packet".into()));
        }
        unsafe {
            (*self.packet).data = packet.data.as_ptr() as *mut u8;
            (*self.packet).size = packet.data.len() as std::ffi::c_int;
            (*self.packet).pts = packet.pts as i64;
            (*self.packet).dts = packet.pts as i64;
        }

        // send（EAGAIN 时先 drain；损坏包返回 false → 跳过）。
        if !self.send_with_drain()? {
            ffmpeg::av_packet_unref(self.packet);
            return Ok(Vec::new());
        }

        // 循环 receive（Opus 通常 1 包 → 1 帧，但保持流式一致性）。
        let mut pcm_out = Vec::new();
        loop {
            match ffmpeg::avcodec_receive_frame(self.ctx, self.frame) {
                Ok(()) => {
                    unsafe {
                        let nb_samples = (*self.frame).nb_samples as usize;
                        // 兼容 FFmpeg 两种 opus 解码器输出格式：
                        // - FLT（packed，libopus wrapper）：data[0] 即
                        //   interleaved L,R,L,R,...；
                        // - FLTP（planar，native decoder）：data[0]=L 平面、
                        //   data[1]=R 平面（各 nb_samples），须逐样本交织——
                        //   否则按 interleaved 读会越界（UB）。
                        match (*self.frame).format {
                            ffmpeg::AV_SAMPLE_FMT_FLT => {
                                // 声道数取 frame->ch_layout（防御：损坏包可能
                                // 解出 mono，读 2ch 会越界）。
                                let channels = frame_channels(self.frame) as usize;
                                let samples = nb_samples.saturating_mul(channels.max(1));
                                let ptr = (*self.frame).data[0] as *const f32;
                                if !ptr.is_null() && nb_samples > 0 {
                                    let slice = std::slice::from_raw_parts(ptr, samples);
                                    pcm_out.extend_from_slice(slice);
                                }
                            }
                            ffmpeg::AV_SAMPLE_FMT_FLTP => {
                                let l = (*self.frame).data[0] as *const f32;
                                let r = (*self.frame).data[1] as *const f32;
                                if nb_samples > 0 && !l.is_null() && !r.is_null() {
                                    for i in 0..nb_samples {
                                        pcm_out.push(*l.add(i));
                                        pcm_out.push(*r.add(i));
                                    }
                                }
                            }
                            other => {
                                // 非 float32 输出（S16 兜底等）→ 跳过该帧
                                // （不 panic；时间轴由 jitter 静音补帧）。
                                tracing::warn!("opus decoder unexpected sample format: {other}");
                            }
                        }
                    }
                    ffmpeg::av_frame_unref(self.frame);
                }
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => break,
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EOF)) => break,
                // 损坏帧（包可送但解码失败）→ 跳过该帧，解码器保持可用。
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_INVALIDDATA)) => {
                    ffmpeg::av_frame_unref(self.frame);
                    continue;
                }
                Err(e) => return Err(DecodeError::AvError(e)),
            }
        }
        ffmpeg::av_packet_unref(self.packet);

        // 时钟跟踪：与视频同轴，从首个包起算、只进不退（乱序包不产生回拨）。
        self.next_pts = self.next_pts.max(packet.pts.saturating_add(FRAME_MS));
        Ok(pcm_out)
    }

    /// `avcodec_send_packet`（EAGAIN 时先 drain 再重试）。
    ///
    /// 返回 `Ok(true)` 已送入；`Ok(false)` 包损坏被跳过（不重建上下文）；
    /// `Err` 为真实失败（DLL/上下文损坏等）。
    fn send_with_drain(&mut self) -> Result<bool, DecodeError> {
        loop {
            match ffmpeg::avcodec_send_packet(self.ctx, self.packet) {
                Ok(()) => return Ok(true),
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => {
                    // 解码器缓冲满：取空输出再重试。正常路径不会触发——每次
                    // decode 已取尽（opus 1 包 → 1 帧）；防御性 drain 并丢弃
                    // 残留帧（属于前一个包，理应不存在）。
                    loop {
                        match ffmpeg::avcodec_receive_frame(self.ctx, self.frame) {
                            Ok(()) => ffmpeg::av_frame_unref(self.frame),
                            Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => break,
                            Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EOF)) => break,
                            Err(_) => {
                                ffmpeg::av_frame_unref(self.frame);
                                break;
                            }
                        }
                    }
                }
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_INVALIDDATA)) => {
                    // 损坏 Opus 包：跳过（返回 false，由调用方返回空 vec）。
                    return Ok(false);
                }
                Err(e) => return Err(DecodeError::AvError(e)),
            }
        }
    }
}

/// 读 `AVFrame.ch_layout.nb_channels`（FFmpeg 8.x 字段偏移 384，与
/// `av_frame_set_ch_layout` 共用；见 `ffmpeg/api.rs` 该偏移注释）。
///
/// # Safety
/// `frame` 必须指向合法的 AVFrame（av_frame_alloc 分配）。偏移 384 仅对
/// FFmpeg ≥ 7 的 Win64 ABI 成立；读取失败/越界由调用方防御（不 deref）。
unsafe fn frame_channels(frame: *mut ffmpeg::AVFrame) -> i32 {
    let p = (frame as *mut u8).add(384).add(4).cast::<i32>();
    let nb = p.read_unaligned();
    if (1..=8).contains(&nb) {
        nb
    } else {
        ffmpeg::AVChannelLayout::stereo().nb_channels
    }
}

impl AudioDecoder for OpusDecoder {
    /// Opus 包（20ms）→ PCM（float32 interleaved stereo）。
    fn decode(&mut self, packet: &AudioPacket) -> Result<Vec<f32>, DecodeError> {
        self.decode(packet)
    }

    fn sample_rate(&self) -> u32 {
        SAMPLE_RATE
    }

    fn channels(&self) -> u16 {
        CHANNELS
    }
}

impl Drop for OpusDecoder {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // Flush：发送 null packet 触发输出缓冲帧，再 drain（对称编码层 Drop）。
            let _ = ffmpeg::avcodec_send_null_packet(self.ctx);
            loop {
                match ffmpeg::avcodec_receive_frame(self.ctx, self.frame) {
                    Ok(()) => ffmpeg::av_frame_unref(self.frame),
                    Err(_) => break,
                }
            }
            ffmpeg::avcodec_free_context(&mut self.ctx);
        }
        let mut frame = self.frame;
        if !frame.is_null() {
            ffmpeg::av_frame_free(&mut frame);
        }
        let mut packet = self.packet;
        if !packet.is_null() {
            ffmpeg::av_packet_free(&mut packet);
        }
    }
}

// ════════════════════════════════════════════════════════════════
// AudioJitterBuffer — 音频抖动缓冲（P2C T3.2）
// ════════════════════════════════════════════════════════════════

/// 音频抖动缓冲：抗网络抖动，按 PTS 排序输出。
///
/// 深度 3~5 帧（60~100ms）。乱序包按 PTS 插入；超时未到的间隙静音补帧
/// （不阻塞播放）；迟到/重复包丢弃。
///
/// # 行为
///
/// - 预热：缓冲未达 `depth` 时 `pop` 返回 `None`（先攒够深度再起播）。
/// - 首包锚定：首次达到缓冲深度时以队首（最早）PTS 为起点，首包非 0 时
///   不会静音补帧风暴。
/// - PTS 跳变（编码侧重置，差距 > 100ms）：flush 缓冲并重锚 `next_pts`。
/// - 缓冲溢出（pending > 2×depth）：丢弃最旧包，避免延迟累积。
pub struct AudioJitterBuffer {
    /// 待输出包队列（按 pts 升序）。
    pending: std::collections::VecDeque<AudioPcm>,
    /// 下一个期望输出的 PTS（毫秒）。
    next_pts: u64,
    /// 缓冲深度（帧数，默认 3 = 60ms）。
    depth: usize,
    /// 单帧时长（毫秒，20ms）。
    frame_ms: u64,
    /// 已输出的最后 PTS（用于检测跳变/迟到）。
    last_output_pts: Option<u64>,
    /// 统计：静音补帧数。
    silence_inserted: u64,
    /// 统计：丢弃包数（迟到/重复/溢出）。
    packets_dropped: u64,
}

impl AudioJitterBuffer {
    pub fn new(depth: usize) -> Self {
        Self {
            pending: Default::default(),
            next_pts: 0,
            depth,
            frame_ms: FRAME_MS,
            last_output_pts: None,
            silence_inserted: 0,
            packets_dropped: 0,
        }
    }

    /// 插入一个解码后的 PCM（已解码，待排序输出）。
    /// 迟到（pts < 已播时刻）或重复的包（pts == 已播时刻）被丢弃。
    pub fn push(&mut self, pcm: AudioPcm) {
        // 丢弃过期包（pts 已过播放时刻，含重复包：<= last 即已播出）。
        if let Some(last) = self.last_output_pts {
            if pcm.pts <= last {
                self.packets_dropped += 1;
                return;
            }
        }
        // PTS 跳变（编码侧重置，差距 > 100ms）：flush 缓冲 + 重锚，避免
        // 对旧时间轴持续静音补帧。
        if let Some(last) = self.last_output_pts {
            if pcm.pts > last.saturating_add(100) {
                self.pending.clear();
                self.next_pts = pcm.pts;
                self.last_output_pts = None;
            }
        }
        // 按 pts 升序插入（VecDeque 保持有序）。
        let pos = self
            .pending
            .iter()
            .position(|p| p.pts > pcm.pts)
            .unwrap_or(self.pending.len());
        self.pending.insert(pos, pcm);
        // 缓冲溢出（pending > 4×depth）：丢弃最旧包（避免延迟累积）。
        // 阈值取 4×depth（depth=3 → 12 帧）：2×depth 对网络突发（一次
        // 到达 7~8 帧）过紧，会误丢正常帧（P2C 文档行为示例「乱序 7 包全
        // 输出」）；4×depth 是抗抖动裕量的 2 倍，正常 jitter 窗口内不触发。
        if self.pending.len() > self.depth.saturating_mul(4) {
            self.pending.pop_front();
            self.packets_dropped += 1;
        }
    }

    /// 取出下一帧 PCM 供播放。
    ///
    /// - 首个输出前缓冲未达 depth → `None`（预热阶段；播放端写静音保持
    ///   时间轴）。起播后不再受 depth 门槛限制。
    /// - 期望 PTS 的包在队列 → 弹出返回。
    /// - 期望 PTS 的包缺失（间隙）→ 静音补帧（`silence_inserted`++）。
    /// - 队首 pts < 期望（push 已丢弃，防御）→ 丢弃返回 `None`，调用方
    ///   再次 pop。
    pub fn pop(&mut self) -> Option<AudioPcm> {
        // 预热：首个输出前须缓冲达 depth（起播即抗抖动）。起播后不再受
        // depth 门槛限制——间隙/末尾的帧照常弹出（缺帧静音补帧保持时间轴，
        // 与文档示例「队列 20,40,80,100,... 时 pop 返回 60 静音帧」一致）。
        if self.last_output_pts.is_none() && self.pending.len() < self.depth {
            return None;
        }

        // 首包锚定：首次达到缓冲深度时以队首（最早）PTS 为起点。
        // 避免「首包非 pts=0 → 对 0..首包 区间静音补帧」的起播风暴；也
        // 覆盖首包乱序（先到高 PTS、后到低 PTS）场景。
        if self.last_output_pts.is_none() {
            if let Some(front) = self.pending.front() {
                self.next_pts = front.pts;
            }
        }

        loop {
            let expected_pts = self.next_pts;

            // 队首 pts == 期望 → 正常弹出。
            if self.pending.front().map(|p| p.pts) == Some(expected_pts) {
                let pcm = self.pending.pop_front().unwrap();
                self.last_output_pts = Some(expected_pts);
                self.next_pts = self.next_pts.saturating_add(self.frame_ms);
                return Some(pcm);
            }

            // 队首 pts > 期望 → 间隙，静音补帧（保持时间轴连续，不阻塞播放）。
            if self.pending.front().map(|p| p.pts) > Some(expected_pts) {
                self.silence_inserted += 1;
                let silence = AudioPcm {
                    pts: expected_pts,
                    samples: vec![0.0f32; FRAME_INTERLEAVED], // 20ms 静音
                };
                self.last_output_pts = Some(expected_pts);
                self.next_pts = self.next_pts.saturating_add(self.frame_ms);
                return Some(silence);
            }

            // 队首 pts < 期望 → 过期（应在 push 时已丢弃，防御）→ 丢弃后
            // **循环重试**（不返回 None 让调用方空转）；队列已空 → 正常结束
            // （不是丢弃包，不计数）。
            match self.pending.pop_front() {
                Some(_) => {
                    self.packets_dropped += 1;
                }
                None => return None,
            }
        }
    }

    /// 统计：静音补帧数。
    pub fn silence_inserted(&self) -> u64 {
        self.silence_inserted
    }

    /// 统计：丢弃包数（迟到/重复/溢出）。
    pub fn packets_dropped(&self) -> u64 {
        self.packets_dropped
    }

    /// 当前缓冲帧数（测试/诊断用）。
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

// ════════════════════════════════════════════════════════════════
// AudioDecodePipeline — 音频解码流水线入口（P2C T3.4）
// ════════════════════════════════════════════════════════════════

/// 音频独立解码流水线：接收 Opus 包 → 解码 → jitter buffer → 播放。
///
/// 调用方为其开**独立线程**（与视频解码线程、UI 线程完全隔离）：
///
/// ```text
/// 传输层接收循环 ──rx──> run()（本线程）：recv → 解码 → jitter → tx
///                                                    │
///                                        播放线程（AudioPlayback）
/// ```
///
/// 音频故障（DLL/设备/线程崩溃）不影响视频/键鼠：`run` 返回 `Err` 后调用方
/// 放弃音频线程即可。
pub struct AudioDecodePipeline {
    decoder: OpusDecoder,
    jitter: AudioJitterBuffer,
    /// 播放端（None = 无播放设备/平台桩，解码完成但静音）。
    playback: Option<Box<dyn crate::decoder::audio_playback::AudioPlayback>>,
    /// 向播放线程投递排序后 PCM 的发送端（start_playback 时建立）。
    tx: Option<mpsc::Sender<AudioPcm>>,
    /// 接收 Opus 包（来自传输层可靠流/DATAGRAM）。
    rx: mpsc::Receiver<AudioPacket>,
}

impl AudioDecodePipeline {
    /// 创建：Opus 解码器 + jitter buffer（深度 3 帧 = 60ms）。
    ///
    /// 任一失败返回 `Err`（调用方在独立线程里创建，失败即放弃音频，不
    /// 影响视频/键鼠）。
    pub fn new(rx: mpsc::Receiver<AudioPacket>) -> Result<Self, DecodeError> {
        Ok(Self {
            decoder: OpusDecoder::new()?,
            jitter: AudioJitterBuffer::new(3),
            playback: None,
            tx: None,
            rx,
        })
    }

    /// 启动平台播放设备（绑定 jitter buffer 输出）。
    ///
    /// 无播放设备（无声卡/被占用）→ `Err(InitFailed)`，**不影响视频/键鼠**
    /// （调用方可选择忽略，解码完成但静音）。
    pub fn start_playback(&mut self) -> Result<(), DecodeError> {
        self.attach_playback(crate::decoder::audio_playback::create_default_playback()?)
    }

    /// 注入播放后端（测试 mock / 集成替换用）。
    fn attach_playback(
        &mut self,
        pb: Box<dyn crate::decoder::audio_playback::AudioPlayback>,
    ) -> Result<(), DecodeError> {
        if self.playback.is_some() {
            return Ok(()); // 幂等。
        }
        let (tx, pb_rx) = mpsc::channel::<AudioPcm>();
        let mut pb = pb;
        pb.start(pb_rx)?;
        self.tx = Some(tx);
        self.playback = Some(pb);
        Ok(())
    }

    /// 主循环（独立线程跑）：阻塞在 `rx.recv()`，无包时等待（不消耗 CPU）。
    ///
    /// 1. `rx.recv()` → AudioPacket
    /// 2. `decoder.decode(packet)` → PCM（损坏包 → 空，跳过）
    /// 3. `jitter.push(PCM)`
    /// 4. `while let Some(pcm) = jitter.pop()` → 投递播放线程
    ///
    /// 发送端关闭（会话结束）→ `Ok(())` 正常返回。
    pub fn run(&mut self) -> Result<(), DecodeError> {
        loop {
            let packet = match self.rx.recv() {
                Ok(p) => p,
                Err(_) => return Ok(()), // 发送端关闭 → 正常结束。
            };
            let pcm_out = self.decoder.decode(&packet)?;
            if pcm_out.is_empty() {
                continue; // 损坏包被跳过（时间轴留白，播放端静音补位）。
            }
            self.jitter.push(AudioPcm {
                pts: packet.pts,
                samples: pcm_out,
            });

            if let Some(tx) = &self.tx {
                // 投递全部就绪帧；播放端已停止（send 失败）→ 丢弃输出继续
                // 解码（不阻塞，与「音频故障不影响视频」一致）。
                while let Some(pcm) = self.jitter.pop() {
                    if tx.send(pcm).is_err() {
                        break;
                    }
                }
            } else {
                // 无播放设备（macOS/Linux 桩 / start_playback 失败）：
                // 解码完成但静音——仍消耗 jitter 保持时间轴状态。
                while self.jitter.pop().is_some() {}
            }
        }
    }

    /// 停止播放，释放渲染设备（幂等）。
    pub fn stop(&mut self) {
        self.tx = None;
        if let Some(mut pb) = self.playback.take() {
            pb.stop();
        }
    }
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::decoder::audio_playback::AudioPlayback as _;
    use crate::encoder::audio::OpusEncoder as TestOpusEncoder;
    use crate::encoder::types::Timestamp;
    use crate::encoder::video::AudioEncoder as _;

    // ── 公共测试工具 ────────────────────────────────────────────

    /// FFmpeg DLL + libopus 编解码器可用才跑（否则 skip）。
    fn opus_available() -> bool {
        if ffmpeg::ensure_loaded().is_err() {
            return false;
        }
        TestOpusEncoder::new().is_ok() && OpusDecoder::new().is_ok()
    }

    /// 编码 N 帧 440Hz 正弦波（幅 0.3），返回 (帧 pts 列表, 原始 interleaved PCM)。
    fn encode_sine(n_frames: usize) -> (Vec<u64>, Vec<f32>, Vec<AudioPacket>) {
        let mut enc = TestOpusEncoder::new().unwrap();
        let mut pcm = Vec::with_capacity(FRAME_INTERLEAVED * n_frames);
        let freq = 440.0f32;
        for i in 0..(FRAME_SAMPLES * n_frames) {
            let t = i as f32 / SAMPLE_RATE as f32;
            let s = (t * freq * 2.0 * std::f32::consts::PI).sin() * 0.3;
            pcm.push(s); // L
            pcm.push(s); // R
        }
        let pkts = enc.encode_pcm(&pcm, Timestamp::now()).unwrap();
        let pts: Vec<u64> = pkts.iter().map(|p| p.ts.pts).collect();
        let packets = pkts
            .into_iter()
            .map(|p| AudioPacket {
                pts: p.ts.pts,
                data: p.data,
            })
            .collect();
        (pts, pcm, packets)
    }

    /// 两个等长序列的 Pearson 相关系数（波形相似度）。
    fn pearson(a: &[f32], b: &[f32]) -> f64 {
        let n = a.len().min(b.len());
        if n == 0 {
            return 0.0;
        }
        let mean_a: f64 = a[..n].iter().map(|&x| x as f64).sum::<f64>() / n as f64;
        let mean_b: f64 = b[..n].iter().map(|&x| x as f64).sum::<f64>() / n as f64;
        let mut num = 0.0;
        let mut den_a = 0.0;
        let mut den_b = 0.0;
        for i in 0..n {
            let (x, y) = (a[i] as f64 - mean_a, b[i] as f64 - mean_b);
            num += x * y;
            den_a += x * x;
            den_b += y * y;
        }
        if den_a <= 0.0 || den_b <= 0.0 {
            0.0
        } else {
            num / (den_a * den_b).sqrt()
        }
    }

    // ── T3.1 OpusDecoder ────────────────────────────────────────

    /// 创建成功（FFmpeg 含 libopus 时）。
    #[test]
    fn test_opus_decoder_create() {
        if !opus_available() {
            eprintln!("libopus not available; test_opus_decoder_create skipped");
            return;
        }
        let dec = OpusDecoder::new().unwrap();
        assert_eq!(dec.sample_rate(), 48_000);
        assert_eq!(dec.channels(), 2);
    }

    /// 编码 960 samples/ch → 解码 → 输出 ~1920 float32（20ms @48k stereo）。
    #[test]
    fn test_opus_decode_20ms_frame() {
        if !opus_available() {
            eprintln!("libopus not available; test_opus_decode_20ms_frame skipped");
            return;
        }
        let (_, _, packets) = encode_sine(1);
        assert_eq!(packets.len(), 1, "20ms frame → 1 opus packet");
        let mut dec = OpusDecoder::new().unwrap();
        let out = dec.decode(&packets[0]).unwrap();
        assert!(!out.is_empty(), "decoded PCM must be non-empty");
        // 恰好 1 帧 20ms：1920 interleaved 样本。
        assert_eq!(out.len(), FRAME_INTERLEAVED, "1 packet → 1920 floats");
    }

    /// 编码 → 解码 → 波形相似度 > 0.9（Pearson 相关系数）。
    #[test]
    fn test_opus_roundtrip_waveform() {
        if !opus_available() {
            eprintln!("libopus not available; test_opus_roundtrip_waveform skipped");
            return;
        }
        let n_frames = 20; // 400ms
        let (_, original, packets) = encode_sine(n_frames);
        let mut dec = OpusDecoder::new().unwrap();
        let mut decoded = Vec::new();
        for p in &packets {
            decoded.extend(dec.decode(p).unwrap());
        }
        assert!(!decoded.is_empty());
        // L 声道波形对比（interleaved 取偶数位）。
        let orig_l: Vec<f32> = original.iter().step_by(2).copied().collect();
        let dec_l: Vec<f32> = decoded.iter().step_by(2).copied().collect();
        let r = pearson(&orig_l, &dec_l);
        assert!(
            r > 0.9,
            "roundtrip waveform correlation must be > 0.9, got {r:.4}"
        );
    }

    /// 连续静音包 → 输出连续静音 PCM（DTX 极小包正常解码）。
    #[test]
    fn test_opus_silence_continuous() {
        if !opus_available() {
            eprintln!("libopus not available; test_opus_silence_continuous skipped");
            return;
        }
        let mut enc = TestOpusEncoder::new().unwrap();
        let silence = vec![0.0f32; FRAME_INTERLEAVED * 3]; // 3 帧 = 60ms
        let pkts = enc.encode_pcm(&silence, Timestamp::now()).unwrap();
        assert!(!pkts.is_empty());
        let mut dec = OpusDecoder::new().unwrap();
        let mut total = 0usize;
        for p in &pkts {
            let out = dec
                .decode(&AudioPacket {
                    pts: p.ts.pts,
                    data: p.data.clone(),
                })
                .unwrap();
            assert!(!out.is_empty(), "DTX silence packet must still decode");
            assert_eq!(out.len(), FRAME_INTERLEAVED);
            assert!(
                out.iter().all(|&s| s.abs() < 1e-3),
                "silence must decode to (near-)zero PCM"
            );
            total += out.len();
        }
        assert_eq!(
            total,
            FRAME_INTERLEAVED * 3,
            "timeline continuous: 3 frames"
        );
    }

    /// 损坏包 → 不 panic，返回空 vec（解码器保持可用）。
    #[test]
    fn test_opus_corrupt_packet_skipped() {
        if !opus_available() {
            eprintln!("libopus not available; test_opus_corrupt_packet_skipped skipped");
            return;
        }
        let mut dec = OpusDecoder::new().unwrap();
        // 无效 Opus TOC（config 27 为保留值）→ send/receive 应报 INVALIDDATA。
        let corrupt = AudioPacket {
            pts: 0,
            data: vec![0xD8, 0x00, 0x00, 0x00],
        };
        let out = dec.decode(&corrupt);
        assert!(
            out.is_ok(),
            "corrupt packet must not panic: {:?}",
            out.err()
        );
        assert!(out.unwrap().is_empty(), "corrupt packet → empty vec");
        // 解码器不重建，后续正常包仍可解。
        let (_, _, packets) = encode_sine(2);
        let ok_out = dec.decode(&packets[0]).unwrap();
        assert_eq!(
            ok_out.len(),
            FRAME_INTERLEAVED,
            "decoder usable after corrupt packet"
        );
    }

    /// sample_rate=48000 / channels=2 与 M12 一致。
    #[test]
    fn test_opus_params_m12() {
        assert_eq!(SAMPLE_RATE, 48_000);
        assert_eq!(CHANNELS, 2);
        assert_eq!(FRAME_MS, 20);
        assert_eq!(FRAME_SAMPLES, 960);
        assert_eq!(FRAME_INTERLEAVED, 1920);
        if opus_available() {
            let dec = OpusDecoder::new().unwrap();
            assert_eq!(dec.sample_rate(), 48_000);
            assert_eq!(dec.channels(), 2);
        }
    }

    // ── T3.2 AudioJitterBuffer ──────────────────────────────────

    fn pcm_at(pts: u64) -> AudioPcm {
        AudioPcm {
            pts,
            samples: vec![1.0f32; FRAME_INTERLEAVED],
        }
    }

    /// 缓冲 < depth 时 pop 返回 None（预热）。
    #[test]
    fn test_jitter_warmup() {
        let mut jb = AudioJitterBuffer::new(3);
        jb.push(pcm_at(0));
        jb.push(pcm_at(20));
        assert!(jb.pop().is_none(), "2 < depth 3 → warmup");
        jb.push(pcm_at(40));
        let p = jb.pop().unwrap();
        assert_eq!(p.pts, 0, "first output anchored to earliest pts");
    }

    /// 顺序到达 → 顺序输出。
    #[test]
    fn test_jitter_in_order() {
        let mut jb = AudioJitterBuffer::new(3);
        for pts in [0u64, 20, 40, 60, 80, 100] {
            jb.push(pcm_at(pts));
        }
        let mut out = Vec::new();
        while let Some(p) = jb.pop() {
            out.push(p.pts);
        }
        assert_eq!(out, vec![0, 20, 40, 60, 80, 100]);
        assert_eq!(jb.silence_inserted(), 0);
        assert_eq!(jb.packets_dropped(), 0);
    }

    /// 乱序到达 → push 排序后顺序输出。
    #[test]
    fn test_jitter_out_of_order() {
        let mut jb = AudioJitterBuffer::new(3);
        for pts in [40u64, 20, 60, 80, 100, 120, 140] {
            jb.push(pcm_at(pts));
        }
        let mut out = Vec::new();
        while let Some(p) = jb.pop() {
            out.push(p.pts);
        }
        assert_eq!(out, vec![20, 40, 60, 80, 100, 120, 140]);
        assert_eq!(jb.silence_inserted(), 0);
    }

    /// 缺帧 → 静音补帧（silence_inserted++），时间轴连续。
    #[test]
    fn test_jitter_gap_silence() {
        let mut jb = AudioJitterBuffer::new(3);
        // pts=60 丢失：20,40,[60 缺],80,100,120,140,160,180
        for pts in [20u64, 40, 80, 100, 120, 140, 160, 180] {
            jb.push(pcm_at(pts));
        }
        let mut out = Vec::new();
        while let Some(p) = jb.pop() {
            out.push(p.pts);
        }
        // 起播后不再受 depth 门槛：间隙补静音 60，末尾 180 照常弹出。
        assert_eq!(out, vec![20, 40, 60, 80, 100, 120, 140, 160, 180]);
        assert_eq!(jb.silence_inserted(), 1, "gap at 60 filled with silence");
        // 补帧为静音数据。
        // （补帧在 pop 内部已返回；验证统计即可）
    }

    /// 迟到包（pts < 已播时刻）→ 丢弃。
    #[test]
    fn test_jitter_late_dropped() {
        let mut jb = AudioJitterBuffer::new(3);
        for pts in [0u64, 20, 40, 60, 80, 100] {
            jb.push(pcm_at(pts));
        }
        // 播到 40。
        assert_eq!(jb.pop().unwrap().pts, 0);
        assert_eq!(jb.pop().unwrap().pts, 20);
        assert_eq!(jb.pop().unwrap().pts, 40);
        // 迟到包 pts=40（重复）与 pts=20 → 丢弃。
        jb.push(pcm_at(40));
        jb.push(pcm_at(20));
        assert!(jb.packets_dropped() >= 1, "late packets must be dropped");
        // 后续播放不受影响。
        assert_eq!(jb.pop().unwrap().pts, 60);
    }

    /// PTS 跳变 > 100ms → flush + reset next_pts（不静音补帧旧时间轴）。
    #[test]
    fn test_jitter_pts_jump_reset() {
        let mut jb = AudioJitterBuffer::new(3);
        for pts in [0u64, 20, 40, 60, 80, 100] {
            jb.push(pcm_at(pts));
        }
        // 播完旧时间轴（last_output=100）。
        while jb.pop().is_some() {}
        assert_eq!(jb.last_output_pts, Some(100));

        // 编码侧重置：新包 pts=1000（跳变 > 100ms）。
        jb.push(pcm_at(1000));
        jb.push(pcm_at(1020));
        jb.push(pcm_at(1040));
        // flush 后重新预热（depth=3），从新轴起播。
        let mut out = Vec::new();
        while let Some(p) = jb.pop() {
            out.push(p.pts);
        }
        assert_eq!(out, vec![1000, 1020, 1040], "reset to new axis");
        assert_eq!(jb.silence_inserted(), 0, "no silence storm on jump");
    }

    /// 首包非 pts=0 → 从首包（或最早包）锚定起播。
    #[test]
    fn test_jitter_first_packet_not_zero() {
        let mut jb = AudioJitterBuffer::new(3);
        // 首包 pts=40（网络首达即高 PTS），随后 20、60。
        jb.push(pcm_at(40));
        jb.push(pcm_at(20));
        jb.push(pcm_at(60));
        let p = jb.pop().unwrap();
        assert_eq!(p.pts, 20, "anchor to earliest pts, not silence from 0");
        assert_eq!(jb.silence_inserted(), 0);
    }

    // ── T3.4 AudioDecodePipeline ────────────────────────────────

    /// 测试用播放 mock：把通道里的 PCM 收进共享 Vec（可断言输出 PTS）。
    struct MockPlayback {
        stop_flag: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
        collected: Arc<Mutex<Vec<AudioPcm>>>,
    }

    impl MockPlayback {
        fn new() -> Self {
            Self {
                stop_flag: Arc::new(AtomicBool::new(false)),
                thread: None,
                collected: Arc::new(Mutex::new(Vec::new())),
            }
        }
        fn collected(&self) -> Vec<AudioPcm> {
            self.collected.lock().unwrap().clone()
        }
    }

    impl crate::decoder::audio_playback::AudioPlayback for MockPlayback {
        fn start(&mut self, src: mpsc::Receiver<AudioPcm>) -> Result<(), DecodeError> {
            self.stop_flag.store(false, Ordering::SeqCst);
            let stop_flag = self.stop_flag.clone();
            let collected = self.collected.clone();
            self.thread = Some(
                thread::Builder::new()
                    .name("mock-playback".into())
                    .spawn(move || {
                        while !stop_flag.load(Ordering::SeqCst) {
                            match src.recv_timeout(Duration::from_millis(20)) {
                                Ok(pcm) => collected.lock().unwrap().push(pcm),
                                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(mpsc::RecvTimeoutError::Disconnected) => return,
                            }
                        }
                    })
                    .map_err(|e| DecodeError::InitFailed(format!("spawn mock playback: {e}")))?,
            );
            Ok(())
        }

        fn stop(&mut self) {
            self.stop_flag.store(true, Ordering::SeqCst);
            if let Some(h) = self.thread.take() {
                let _ = h.join();
            }
        }

        fn sample_rate(&self) -> u32 {
            SAMPLE_RATE
        }

        fn channels(&self) -> u16 {
            CHANNELS
        }
    }

    impl Drop for MockPlayback {
        fn drop(&mut self) {
            self.stop();
        }
    }

    /// 无包时 rx.recv() 阻塞，不报错（run 线程存活，发送端关闭后正常返回）。
    #[test]
    fn test_audio_pipeline_empty_no_block() {
        if !opus_available() {
            eprintln!("libopus not available; test_audio_pipeline_empty_no_block skipped");
            return;
        }
        let (tx, rx) = mpsc::channel::<AudioPacket>();
        let mut pipe = AudioDecodePipeline::new(rx).unwrap();
        let handle = thread::spawn(move || pipe.run());
        // 100ms 内无包：run 阻塞在 recv，线程不退出、不报错。
        thread::sleep(Duration::from_millis(100));
        assert!(!handle.is_finished(), "run must block on empty channel");
        // 发送端关闭 → run 正常返回 Ok。
        drop(tx);
        assert!(handle.join().unwrap().is_ok());
    }

    /// 输出 PCM 的 PTS 单调递增。
    #[test]
    fn test_audio_pipeline_pts_monotonic() {
        if !opus_available() {
            eprintln!("libopus not available; test_audio_pipeline_pts_monotonic skipped");
            return;
        }
        let (_, _, packets) = encode_sine(10); // 200ms
        let (tx, rx) = mpsc::channel::<AudioPacket>();
        let mut pipe = AudioDecodePipeline::new(rx).unwrap();
        // 注入 mock 播放（无真实设备也能验证输出）。
        let mock = MockPlayback::new();
        let collected = mock.collected.clone();
        pipe.attach_playback(Box::new(mock)).unwrap();

        let mut run_handle = None;
        {
            let mut pipe = pipe;
            run_handle = Some(thread::spawn(move || pipe.run()));
        }
        for p in packets {
            let _ = tx.send(p);
        }
        thread::sleep(Duration::from_millis(300));
        drop(tx);
        run_handle.unwrap().join().unwrap();

        let out = collected.lock().unwrap().clone();
        assert!(!out.is_empty(), "pipeline must output PCM");
        for w in out.windows(2) {
            assert!(
                w[1].pts >= w[0].pts,
                "output PTS must be monotonic: {} then {}",
                w[0].pts,
                w[1].pts
            );
        }
    }

    /// 每帧输出恰好 1920 个 interleaved 样本（20ms @48k stereo）。
    #[test]
    fn test_audio_pipeline_frame_size() {
        if !opus_available() {
            eprintln!("libopus not available; test_audio_pipeline_frame_size skipped");
            return;
        }
        let (_, _, packets) = encode_sine(5);
        let (tx, rx) = mpsc::channel::<AudioPacket>();
        let mut pipe = AudioDecodePipeline::new(rx).unwrap();
        let mock = MockPlayback::new();
        let collected = mock.collected.clone();
        pipe.attach_playback(Box::new(mock)).unwrap();
        let run_handle = thread::spawn(move || pipe.run());
        for p in packets {
            let _ = tx.send(p);
        }
        thread::sleep(Duration::from_millis(200));
        drop(tx);
        run_handle.join().unwrap();
        let out = collected.lock().unwrap().clone();
        assert!(!out.is_empty());
        for pcm in &out {
            assert_eq!(
                pcm.samples.len(),
                FRAME_INTERLEAVED,
                "each frame = 1920 floats"
            );
        }
    }

    /// sample_rate=48000 / channels=2 与 M12 一致。
    #[test]
    fn test_audio_pipeline_params_m12() {
        assert_eq!(SAMPLE_RATE, 48_000);
        assert_eq!(CHANNELS, 2);
        if opus_available() {
            let (_, rx) = mpsc::channel::<AudioPacket>();
            let pipe = AudioDecodePipeline::new(rx).unwrap();
            assert_eq!(pipe.decoder.sample_rate(), 48_000);
            assert_eq!(pipe.decoder.channels(), 2);
        }
    }

    /// lip-sync：视频/音频 PTS 同轴（mock 验证偏移 < 50ms）。
    ///
    /// 音频输出 PTS 必须落在编码侧时间轴（20ms 网格）上，且相对输入偏移
    /// < 50ms（预热/锚定后应精确相等）。
    #[test]
    fn test_audio_pipeline_lip_sync() {
        if !opus_available() {
            eprintln!("libopus not available; test_audio_pipeline_lip_sync skipped");
            return;
        }
        let (fed_pts, _, packets) = encode_sine(10);
        let (tx, rx) = mpsc::channel::<AudioPacket>();
        let mut pipe = AudioDecodePipeline::new(rx).unwrap();
        let mock = MockPlayback::new();
        let collected = mock.collected.clone();
        pipe.attach_playback(Box::new(mock)).unwrap();
        let run_handle = thread::spawn(move || pipe.run());
        for p in packets {
            let _ = tx.send(p);
        }
        thread::sleep(Duration::from_millis(300));
        drop(tx);
        run_handle.join().unwrap();

        let out = collected.lock().unwrap().clone();
        assert!(!out.is_empty());
        // 每个输出 PTS 都落在输入网格上（同轴）：偏移 = |out.pts - fed|
        // 中最近的网格点，必须 < 50ms。
        for pcm in &out {
            let nearest = fed_pts
                .iter()
                .map(|&f| (pcm.pts as i64 - f as i64).abs())
                .min()
                .unwrap();
            assert!(
                nearest < 50,
                "lip-sync: output pts {} off grid by {}ms (≥50ms)",
                pcm.pts,
                nearest
            );
        }
        // 且输出 PTS 精确等于输入网格点（有序播放，无重排）。
        let out_pts: Vec<u64> = out.iter().map(|p| p.pts).collect();
        assert!(
            out_pts.windows(2).all(|w| w[1] - w[0] == FRAME_MS),
            "output pts must step exactly 20ms on the shared axis: {:?}",
            out_pts
        );
    }
}
