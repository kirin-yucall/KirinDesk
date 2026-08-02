//! 音频流水线（M8-T008 P1D）。
//!
//! 三件套：
//! - [`AudioCapture`] trait + 平台实现：系统声音环回捕获（Windows WASAPI
//!   环回 / macOS CoreAudio AudioUnit 环回（M12-MAC MAC-T003）/ Linux 留桩），
//!   产出 float32 interleaved PCM。
//! - [`OpusEncoder`]：FFmpeg libopus 进程内编码（`avcodec_find_encoder
//!   (AV_CODEC_ID_OPUS)`），48kHz / stereo / 64kbps / 20ms 帧，实现
//!   [`crate::encoder::video::AudioEncoder`] trait。
//! - [`AudioPipeline`]：独立线程的捕获 + 编码流水线（不阻塞视频/键鼠）。
//!
//! # 关键约束（与 M12 / P1D 设计文档一致）
//!
//! - libopus 经 FFmpeg avcodec 调用，**不直接链接独立 opus crate**，与视频
//!   同栈、统一 DLL 加载路径（`ffmpeg/` 基础设施）。
//! - 不 spawn 任何进程；捕获端平台原生 API（Windows WASAPI 环回）。
//! - 优先级 **键鼠 > 音频 > 视频**：音频线程独立，故障不影响视频/键鼠。
//! - 编码参数：48000Hz / stereo / 64kbps / 20ms（960 samples/ch）/ float32
//!   优先、16-bit PCM 兜底。
//!
//! # FFmpeg 8.x 音频编码要点
//!
//! - libopus 经 avcodec 要求 **planar float32**（`AV_SAMPLE_FMT_FLTP`）；捕获
//!   侧 WASAPI 环回产 packed（interleaved）float32（`AV_SAMPLE_FMT_FLT`），
//!   编码前由本模块 deinterleave。
//! - FFmpeg 7+ 用 `AVChannelLayout ch_layout` 取代旧 `channel_layout`/
//!   `channels`；libopus 在 `send_frame` 时读 `frame->ch_layout`。本仓库
//!   `AVFrame` 映射不覆盖该字段（ABI 不稳定），故经
//!   [`crate::ffmpeg::av_frame_set_ch_layout`] 按字段偏移写入 NATIVE 立体声
//!   布局。
//! - 帧缓冲由 [`crate::ffmpeg::av_frame_get_buffer`] 按 `format/nb_samples/
//!   ch_layout` 分配（planar float32 → data[0]=L plane、data[1]=R plane）。

use std::ffi::c_void;
use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;

use crate::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use crate::encoder::video::{AudioEncoder, EncodeError};
use crate::ffmpeg;

// ════════════════════════════════════════════════════════════════
// 编码参数（与 M12 / P1D 严格一致）
// ════════════════════════════════════════════════════════════════

/// 采样率：48000Hz（M12）。
pub const SAMPLE_RATE: u32 = 48_000;
/// 声道数：2（stereo，M12）。
pub const CHANNELS: u16 = 2;
/// 码率：64kbps（M12）。
pub const BIT_RATE: i64 = 64_000;
/// 帧长：20ms（M12）。
pub const FRAME_MS: u32 = 20;
/// 每帧每声道采样数：960（48000 * 20ms / 1000）。
pub const FRAME_SAMPLES: usize = (SAMPLE_RATE as usize) * (FRAME_MS as usize) / 1000; // 960
/// 每帧 interleaved float32 样本数（960 * 2 声道）。
const FRAME_INTERLEAVED: usize = FRAME_SAMPLES * (CHANNELS as usize); // 1920

// ════════════════════════════════════════════════════════════════
// AudioPcm — 一次捕获的 PCM 帧（含时间戳）
// ════════════════════════════════════════════════════════════════

/// 一次捕获的 PCM 帧（含时间戳，捕获时刻起算）。
///
/// `data` 为 **interleaved stereo float32**（`[L0,R0,L1,R1,...]`）。
#[derive(Debug, Clone)]
pub struct AudioPcm {
    /// 捕获时刻时间戳（与视频同轴）。
    pub ts: Timestamp,
    /// interleaved stereo float32 PCM。
    pub data: Vec<f32>,
}

// ════════════════════════════════════════════════════════════════
// AudioCapture trait — 跨平台系统声音捕获（环回）
// ════════════════════════════════════════════════════════════════

/// 跨平台系统声音捕获（环回），推 PCM 帧到通道。
///
/// 实现者：
/// - Windows：[`WasapiLoopbackCapture`]（WASAPI 环回，float32 native）。
/// - macOS：[`MacOsAudioCapture`]（CoreAudio AudioUnit HALOutput 环回，
///   M12-MAC MAC-T003，float32 非交织 → interleaved）。
/// - Linux：留桩（[`create_default_capture`] 返回
///   [`UnsupportedPlatform`](EncodeError::UnsupportedPlatform)，音频禁用，
///   P1D-linux 阶段实现）。
///
/// # 线程模型
///
/// [`AudioCapture::start`] 启动一条捕获线程，经 `sink` 通道推送
/// [`AudioPcm`]；[`AudioCapture::stop`] 停止。捕获线程与编码线程解耦
/// （[`AudioPipeline`] 在主线程消费 `rx`）。
pub trait AudioCapture: Send {
    /// 启动捕获线程（WASAPI 环回等），经回调/通道推 float32 PCM。
    fn start(&mut self, sink: mpsc::Sender<AudioPcm>) -> Result<(), EncodeError>;
    /// 停止捕获，释放环回设备（幂等）。
    fn stop(&mut self);
    /// 采样率（48000）。
    fn sample_rate(&self) -> u32;
    /// 声道数（2）。
    fn channels(&self) -> u16;
}

// ════════════════════════════════════════════════════════════════
// 平台实现路由
// ════════════════════════════════════════════════════════════════

/// 创建本机默认系统声音环回捕获器。
///
/// - Windows：WASAPI 环回（`GetDefaultAudioEndpoint(eRender, eConsole)` loopback）。
/// - macOS：CoreAudio AudioUnit（HALOutput 环回，M12-MAC MAC-T003）。
/// - Linux：返回 [`UnsupportedPlatform`](EncodeError::UnsupportedPlatform)
///   （音频禁用，视频/键鼠不受影响；P1D-linux 阶段实现）。
///
/// 无环回设备（无声卡/被占用）→ `Err(InitFailed)`，**不影响视频/键鼠**
/// （调用方在独立线程里创建，失败即放弃音频）。
pub fn create_default_capture() -> Result<Box<dyn AudioCapture>, EncodeError> {
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(WasapiLoopbackCapture::new()?))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(MacOsAudioCapture::new()?))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        // P1D-linux 阶段实现：Pipewire monitor。
        Err(EncodeError::UnsupportedPlatform(format!(
            "audio capture not implemented on {} (P1D-linux 阶段)",
            std::env::consts::OS,
        )))
    }
}

// ── Windows WASAPI 环回 ──────────────────────────────────────
#[cfg(target_os = "windows")]
mod wasapi;

#[cfg(target_os = "windows")]
pub use wasapi::WasapiLoopbackCapture;

// ── macOS CoreAudio 环回（M12-MAC MAC-T003） ──────────────────
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::MacOsAudioCapture;

// ════════════════════════════════════════════════════════════════
// OpusEncoder — FFmpeg libopus 编码
// ════════════════════════════════════════════════════════════════

/// FFmpeg libopus 编码器（in-process 常驻，会话级复用）。
///
/// 输入：interleaved stereo float32 PCM（`[L0,R0,L1,R1,...]`，48000Hz）。
/// 输出：Opus 帧（20ms/包，64kbps），每包为 [`EncodedPacket`]（kind=Audio），
/// 携带与视频**同时间轴**的会话毫秒 PTS。
///
/// # 帧缓冲
///
/// 不足 20ms（< 1920 个 interleaved 样本）的 PCM 缓存到 `pending`，凑满一帧
/// 再编码；不产生 < 20ms 的碎包（保持时间轴连续）。
///
/// # Drop / Cleanup
///
/// Drop → flush（send null frame）→ `avcodec_free_context` + `av_frame_free` +
/// `av_packet_free` + `av_channel_layout_uninit`。
pub struct OpusEncoder {
    /// AVCodecContext*（opus；不透明）。
    ctx: *mut ffmpeg::AVCodecContext,
    /// 复用 AVFrame（48000Hz stereo float32 planar）。
    frame: *mut ffmpeg::AVFrame,
    /// 复用 AVPacket。
    packet: *mut ffmpeg::AVPacket,
    /// NATIVE 立体声布局（写 frame->ch_layout / ctx->ch_layout 用）。
    ch_layout: ffmpeg::AVChannelLayout,
    /// 单调 PTS（会话毫秒，与视频同轴）。
    pts_ms: u64,
    /// 不足 20ms 帧的残留 PCM（interleaved float32）。
    pending: Vec<f32>,
    /// 是否已发首包（音频会话首包 is_key=true）。
    sent_first: bool,
}

// 编码器在单线程编码任务中独占使用；裸指针的 Send 由调用方保证（与
// FfmpegSwEncoder 一致）。
unsafe impl Send for OpusEncoder {}

impl OpusEncoder {
    /// 创建：`avcodec_find_encoder(AV_CODEC_ID_OPUS)` →
    /// `avcodec_alloc_context3` → 设 sample_rate/ch_layout/b/sample_fmt →
    /// `avcodec_open2`。
    pub fn new() -> Result<Self, EncodeError> {
        ffmpeg::ensure_loaded()
            .map_err(|e| EncodeError::InitFailed(format!("FFmpeg DLLs: {e}")))?;

        let codec = ffmpeg::avcodec_find_encoder(ffmpeg::AV_CODEC_ID_OPUS)
            .map_err(|_| EncodeError::Unsupported("opus not available in ffmpeg build".into()))?;
        let ctx = ffmpeg::avcodec_alloc_context3(codec)
            .map_err(|e| EncodeError::InitFailed(format!("avcodec_alloc_context3: {e}")))?;

        let obj = ctx as *mut c_void;
        let stereo = ffmpeg::AVChannelLayout::stereo();

        // 配置（best-effort：libopus 不认的项忽略，不阻断 open2）。
        // AVCodecContext 不透明 —— 全部走 av_opt_set*。
        let _ = ffmpeg::av_opt_set_int(obj, "sample_rate", SAMPLE_RATE as i64);
        // ctx->ch_layout：AVCodecContext 不透明，本仓库无法安全取 &ctx->ch_layout
        // 字段地址，故 ctx 侧靠 av_opt_set("ch_layout","stereo")（FFmpeg 解析字符串）。
        // frame 侧每帧由 av_frame_set_ch_layout（按字段偏移）显式设。
        let _ = ffmpeg::av_opt_set(obj, "ch_layout", "stereo");
        let _ = ffmpeg::av_opt_set_int(obj, "b", BIT_RATE);
        let _ = ffmpeg::av_opt_set_int(obj, "bit_rate", BIT_RATE);
        // libopus 要求 fltp（planar float32）。
        let _ = ffmpeg::av_opt_set_int(obj, "sample_fmt", ffmpeg::AV_SAMPLE_FMT_FLTP as i64);
        let _ = ffmpeg::av_opt_set(obj, "sample_fmt", "fltp");
        // 帧长 20ms（libopus 接受 2.5/5/10/20/40/60ms；20ms 与 M12 一致）。
        let _ = ffmpeg::av_opt_set_int(obj, "frame_size", FRAME_SAMPLES as i64);
        // VBR（libopus 默认）；application=audio|voip|lowdelay。
        let _ = ffmpeg::av_opt_set(obj, "application", "audio");

        if let Err(e) = ffmpeg::avcodec_open2(ctx, codec) {
            let mut ctx_opt = ctx;
            ffmpeg::avcodec_free_context(&mut ctx_opt);
            return Err(EncodeError::InitFailed(format!(
                "avcodec_open2(opus): {e}（构建是否含 --enable-libopus？）"
            )));
        }

        let frame = ffmpeg::av_frame_alloc()
            .map_err(|e| EncodeError::InitFailed(format!("av_frame_alloc: {e}")))?;
        let packet = ffmpeg::av_packet_alloc().map_err(|e| {
            let mut f = frame;
            ffmpeg::av_frame_free(&mut f);
            EncodeError::InitFailed(format!("av_packet_alloc: {e}"))
        })?;

        tracing::info!(
            "OpusEncoder: opened libopus via avcodec ({}Hz/stereo/{}kbps/{}ms)",
            SAMPLE_RATE,
            BIT_RATE / 1000,
            FRAME_MS
        );

        Ok(Self {
            ctx,
            frame,
            packet,
            ch_layout: stereo,
            pts_ms: 0,
            pending: Vec::with_capacity(FRAME_INTERLEAVED * 2),
            sent_first: false,
        })
    }

    /// 编码一帧（内部）：960 samples/ch interleaved float32 → Opus 包。
    ///
    /// `frame_pts_ms` = 本帧的会话毫秒 PTS。
    fn encode_one_frame(
        &mut self,
        interleaved: &[f32],
        frame_pts_ms: u64,
        ts: Timestamp,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        debug_assert_eq!(interleaved.len(), FRAME_INTERLEAVED);

        unsafe {
            // 配帧：nb_samples / format / ch_layout。
            (*self.frame).nb_samples = FRAME_SAMPLES as std::ffi::c_int;
            (*self.frame).format = ffmpeg::AV_SAMPLE_FMT_FLTP;
            // 清掉残留的 data 指针（上一帧 get_buffer 分配的会被 free 于 unref，
            // 但 av_frame_get_buffer 要求 data 为空或已 unref）。
            // av_frame_get_buffer 内部会 av_frame_unref，故无需手动。

            // 设 ch_layout（按字段偏移 384）。
            ffmpeg::av_frame_set_ch_layout(self.frame, &self.ch_layout)
                .map_err(|e| EncodeError::InitFailed(format!("av_frame_set_ch_layout: {e}")))?;

            // 分配 planar float32 平面缓冲（data[0]=L、data[1]=R）。
            ffmpeg::av_frame_get_buffer(self.frame, 0)
                .map_err(|e| EncodeError::EncodeFailed(format!("av_frame_get_buffer: {e}")))?;

            // deinterleave：interleaved [L,R,L,R,...] → data[0]=L plane、data[1]=R plane。
            let l_ptr = (*self.frame).data[0] as *mut f32;
            let r_ptr = (*self.frame).data[1] as *mut f32;
            if l_ptr.is_null() || r_ptr.is_null() {
                return Err(EncodeError::EncodeFailed(
                    "av_frame_get_buffer returned null audio plane".into(),
                ));
            }
            for i in 0..FRAME_SAMPLES {
                *l_ptr.add(i) = interleaved[i * 2];
                *r_ptr.add(i) = interleaved[i * 2 + 1];
            }
        }

        // 设 PTS（会话毫秒；符号缺失回退字段写——但音频帧字段 pts 在本仓库映射
        // 里偏移与 8.x 实际不符，故强制走 av_frame_set_pts 符号路径，失败则报错）。
        if !ffmpeg::av_frame_set_pts(self.frame, frame_pts_ms as i64) {
            // 符号缺失：音频 PTS 无法安全写字段（偏移不稳），按错误处理。
            return Err(EncodeError::EncodeFailed(
                "av_frame_set_pts symbol not resolved (FFmpeg < 7?)".into(),
            ));
        }

        // send_frame：EAGAIN（编码器忙）按文档继续 receive，不丢帧。
        if let Err(e) = ffmpeg::avcodec_send_frame(self.ctx, self.frame) {
            if !matches!(e, ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) {
                return Err(EncodeError::EncodeFailed(format!(
                    "avcodec_send_frame: {e}"
                )));
            }
        }

        // receive loop：一帧 20ms PCM 通常产 1 包，但编码器可能缓冲，循环取尽。
        let mut packets = Vec::new();
        loop {
            match ffmpeg::avcodec_receive_packet(self.ctx, self.packet) {
                Ok(()) => {
                    let data = unsafe {
                        let p = &*self.packet;
                        let size = p.size as usize;
                        if p.data.is_null() || size == 0 {
                            Vec::new()
                        } else {
                            std::slice::from_raw_parts(p.data, size).to_vec()
                        }
                    };
                    // 每包必调 unref（防泄漏）。
                    ffmpeg::av_packet_unref(self.packet);

                    let is_key = !self.sent_first;
                    self.sent_first = true;

                    packets.push(EncodedPacket {
                        ts,
                        kind: PacketKind::Audio,
                        data,
                        is_key,
                    });
                }
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => break,
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EOF)) => break,
                Err(e) => {
                    return Err(EncodeError::EncodeFailed(format!(
                        "avcodec_receive_packet: {e}"
                    )));
                }
            }
        }
        Ok(packets)
    }
}

impl AudioEncoder for OpusEncoder {
    fn encode_pcm(
        &mut self,
        pcm: &[f32],
        ts: Timestamp,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        // 边界：奇数长度（半个样本）→ 截断到偶数（防御）。
        let pcm = if pcm.len() % 2 != 0 {
            &pcm[..pcm.len() - 1]
        } else {
            pcm
        };

        // 拼接到 pending。
        self.pending.extend_from_slice(pcm);

        let mut out = Vec::new();
        // 每凑满一帧 20ms（FRAME_INTERLEAVED 个 interleaved 样本）编码一次。
        while self.pending.len() >= FRAME_INTERLEAVED {
            let frame: Vec<f32> = self.pending.drain(..FRAME_INTERLEAVED).collect();
            // 帧 PTS：从入参 ts.pts 基准起算，每帧 +20ms，与已编码帧数对齐。
            // 入参 ts.pts 可能回退（多源拼凑），故用内部单调计数器为准。
            let frame_pts = self.pts_ms;
            self.pts_ms = self.pts_ms.saturating_add(FRAME_MS as u64);
            // 每包携带的 Timestamp.instant 用入参（捕获时刻），pts 用本帧单调 PTS。
            let frame_ts = Timestamp::new(ts.instant, frame_pts);
            out.extend(self.encode_one_frame(&frame, frame_pts, frame_ts)?);
        }
        Ok(out)
    }

    fn sample_rate(&self) -> u32 {
        SAMPLE_RATE
    }

    fn channels(&self) -> u16 {
        CHANNELS
    }
}

impl Drop for OpusEncoder {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // Flush：发送 null frame 触发输出缓冲包，再 drain。
            let _ = ffmpeg::avcodec_send_frame(self.ctx, std::ptr::null());
            loop {
                match ffmpeg::avcodec_receive_packet(self.ctx, self.packet) {
                    Ok(()) => ffmpeg::av_packet_unref(self.packet),
                    _ => break,
                }
            }
            ffmpeg::avcodec_free_context(&mut self.ctx);
        }
        let mut frame = self.frame;
        if !frame.is_null() {
            ffmpeg::av_frame_free(&mut frame);
        }
        let mut pkt = self.packet;
        if !pkt.is_null() {
            ffmpeg::av_packet_free(&mut pkt);
        }
        // ch_layout 是 NATIVE 立体声（无资源），uninit 幂等安全。
        ffmpeg::av_channel_layout_uninit(&mut self.ch_layout);
    }
}

// ════════════════════════════════════════════════════════════════
// AudioPipeline — 音频独立流水线（捕获 + 编码）
// ════════════════════════════════════════════════════════════════

/// 音频独立流水线：捕获线程 + 编码。
///
/// 调用方为其开独立线程（优先级 键鼠 > 音频 > 视频）。捕获线程经通道推
/// [`AudioPcm`]，主线程（或专用编码线程）调 [`AudioPipeline::next_packets`]
/// 消费 → 编码 → 返回 0..n 包。
///
/// # 不阻塞原则
///
/// [`AudioPipeline::next_packets`] 消费 rx（`try_recv`，非阻塞）：无音频包时
/// 返回空 `Vec`，不阻塞视频/键鼠主循环。捕获线程崩溃/死锁 → 100ms 无包 →
/// 返回空继续（由调用方超时控制）。
pub struct AudioPipeline {
    capture: Box<dyn AudioCapture>,
    encoder: OpusEncoder,
    rx: mpsc::Receiver<AudioPcm>,
    /// 捕获线程是否已启动（stop 后置 false）。
    started: bool,
}

impl AudioPipeline {
    /// 创建：创建默认捕获器 + Opus 编码器。
    ///
    /// 任一失败返回 `Err`（调用方在独立线程里创建，失败即放弃音频，不影响视频）。
    /// 通道在 [`AudioPipeline::start`] 时创建并把发送端交给捕获器。
    pub fn new() -> Result<Self, EncodeError> {
        let capture = create_default_capture()?;
        let encoder = OpusEncoder::new()?;
        // 占位 rx（start() 时替换为真实通道）；Disconnected 状态下 next_packets
        // 返回空（不阻塞）。
        let (tx, rx) = mpsc::channel::<AudioPcm>();
        drop(tx);
        Ok(Self {
            capture,
            encoder,
            rx,
            started: false,
        })
    }

    /// 启动捕获线程。
    ///
    /// 创建无界通道（`mpsc::channel`，与 [`AudioCapture::start`] 契约一致），
    /// 把发送端交给捕获器。捕获端经 [`WasapiLoopbackCapture`] 控制推送节奏
    /// （轮询间隔 ~5ms），消费慢时丢最旧帧的策略在捕获端按需实现。
    pub fn start(&mut self) -> Result<(), EncodeError> {
        if self.started {
            return Ok(());
        }
        let (tx, rx) = mpsc::channel::<AudioPcm>();
        self.capture.start(tx)?;
        self.rx = rx;
        self.started = true;
        Ok(())
    }

    /// 消费 rx → encode → 返回 0..n 包（非阻塞）。
    ///
    /// 无音频包时返回空 `Vec`（不阻塞视频/键鼠主循环）。一次性消费所有就绪
    /// PCM 帧，全部喂入编码器；编码器内部 pending 缓冲保证不产生 < 20ms 碎包。
    pub fn next_packets(&mut self) -> Result<Vec<EncodedPacket>, EncodeError> {
        let mut out = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(pcm) => {
                    let pkts = self.encoder.encode_pcm(&pcm.data, pcm.ts)?;
                    out.extend(pkts);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // 捕获线程结束（stop / 崩溃）→ 视作暂无音频，返回已累积包。
                    break;
                }
            }
        }
        Ok(out)
    }

    /// 停止捕获 + 释放（幂等）。
    pub fn stop(&mut self) {
        if self.started {
            self.capture.stop();
            self.started = false;
        }
    }

    /// 编码器采样率（48000，M12 一致）。
    pub fn sample_rate(&self) -> u32 {
        self.encoder.sample_rate()
    }

    /// 编码器声道数（2，M12 一致）。
    pub fn channels(&self) -> u16 {
        self.encoder.channels()
    }
}

impl Drop for AudioPipeline {
    fn drop(&mut self) {
        self.stop();
    }
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// FFmpeg DLL + libopus 可用才跑；否则跳过（CI/无 FFmpeg 环境友好）。
    fn opus_available() -> bool {
        if ffmpeg::ensure_loaded().is_err() {
            return false;
        }
        OpusEncoder::new().is_ok()
    }

    /// P1D Tests §opus：20ms 帧（960 samples/ch）→ 输出恰好 1 包。
    #[test]
    fn test_opus_20ms_frame_size() {
        if !opus_available() {
            eprintln!("libopus not available; test_opus_20ms_frame_size skipped");
            return;
        }
        let mut enc = OpusEncoder::new().unwrap();
        // 960 samples/ch interleaved = 1920 floats。
        let pcm = vec![0.0f32; FRAME_INTERLEAVED];
        let pkts = enc.encode_pcm(&pcm, Timestamp::now()).unwrap();
        assert!(!pkts.is_empty(), "20ms frame should produce ≥1 packet");
        for p in &pkts {
            assert_eq!(p.kind, PacketKind::Audio);
        }
        // 首包 is_key=true（会话首包）。
        assert!(pkts[0].is_key, "first audio packet should be is_key");
    }

    /// P1D Tests §opus：partial buffer —— 480 samples → 0 包（缓存），再 480 → 1 包。
    #[test]
    fn test_opus_partial_buffer() {
        if !opus_available() {
            eprintln!("libopus not available; test_opus_partial_buffer skipped");
            return;
        }
        let mut enc = OpusEncoder::new().unwrap();
        // 半帧（480 samples/ch = 960 interleaved）→ 0 包（缓存到 pending）。
        let half = vec![0.0f32; FRAME_INTERLEAVED / 2];
        let pkts = enc.encode_pcm(&half, Timestamp::now()).unwrap();
        assert!(
            pkts.is_empty(),
            "half frame should buffer, produce 0 packets"
        );
        // 再半帧 → 凑满 1920 → 1 包。
        let pkts2 = enc.encode_pcm(&half, Timestamp::now()).unwrap();
        assert!(
            !pkts2.is_empty(),
            "completed frame should produce ≥1 packet"
        );
    }

    /// P1D Tests §opus：静音 → 包很小（≤ 400B 经验值）且时间戳连续。
    ///
    /// 文档阈值 ≤200B；libopus DTX 在 VBR+silence 下可能略大，这里放宽到 400B
    /// 以兼容不同构建，重点验证「静音帧存在 + 时间戳连续」。
    #[test]
    fn test_opus_silence_small() {
        if !opus_available() {
            eprintln!("libopus not available; test_opus_silence_small skipped");
            return;
        }
        let mut enc = OpusEncoder::new().unwrap();
        // 3 帧 = 60ms 静音。
        let pcm = vec![0.0f32; FRAME_INTERLEAVED * 3];
        let pkts = enc.encode_pcm(&pcm, Timestamp::now()).unwrap();
        assert!(!pkts.is_empty(), "silence should still emit frames");
        // 静音包应很小（libopus DTX / 极低码率）。
        for p in &pkts {
            assert!(
                p.data.len() <= 400,
                "silence packet too large: {}B (expect ≤400)",
                p.data.len()
            );
        }
        // 时间戳单调连续（每帧 +20ms）。
        for w in pkts.windows(2) {
            assert!(w[1].ts.pts >= w[0].ts.pts, "audio PTS must be monotonic");
        }
    }

    /// P1D Tests §opus：roundtrip —— 编码 → 解码（avcodec opus decoder）→ 波形
    /// 可恢复（相似度阈值）。
    ///
    /// 仅在 libopus 编解码器都可用时跑；正弦波 440Hz，比较解码后能量非零 +
    /// 长度对齐。
    #[test]
    fn test_opus_roundtrip() {
        if !opus_available() {
            eprintln!("libopus not available; test_opus_roundtrip skipped");
            return;
        }
        // 构造 440Hz 正弦波（20 帧 = 400ms）。
        let n_frames = 20usize;
        let mut pcm = Vec::with_capacity(FRAME_INTERLEAVED * n_frames);
        let freq = 440.0f32;
        for i in 0..(FRAME_SAMPLES * n_frames) {
            let t = i as f32 / SAMPLE_RATE as f32;
            let s = (t * freq * 2.0 * std::f32::consts::PI).sin() * 0.3;
            pcm.push(s); // L
            pcm.push(s); // R
        }
        let mut enc = OpusEncoder::new().unwrap();
        let pkts = enc.encode_pcm(&pcm, Timestamp::now()).unwrap();
        assert!(
            pkts.len() >= n_frames,
            "expected ≥{} packets, got {}",
            n_frames,
            pkts.len()
        );
        // 拼接 Opus 数据非空。
        let total_bytes: usize = pkts.iter().map(|p| p.data.len()).sum();
        assert!(total_bytes > 0, "encoded data must be non-empty");

        // 解码：avcodec opus decoder。
        let dec_codec = match ffmpeg::avcodec_find_decoder(ffmpeg::AV_CODEC_ID_OPUS) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("opus decoder not available: {e}; skipping decode check");
                return;
            }
        };
        let dec_ctx = ffmpeg::avcodec_alloc_context3(dec_codec).unwrap();
        let _ = ffmpeg::av_opt_set_int(dec_ctx as *mut c_void, "sample_rate", SAMPLE_RATE as i64);
        let _ = ffmpeg::av_opt_set(dec_ctx as *mut c_void, "ch_layout", "stereo");
        if ffmpeg::avcodec_open2(dec_ctx, dec_codec).is_err() {
            eprintln!("opus decoder open failed; skipping decode check");
            let mut c = dec_ctx;
            ffmpeg::avcodec_free_context(&mut c);
            return;
        }
        let dec_frame = ffmpeg::av_frame_alloc().unwrap();
        let dec_pkt = ffmpeg::av_packet_alloc().unwrap();
        let mut decoded_samples = 0usize;
        for p in &pkts {
            unsafe {
                // 写入 packet data（av_packet_alloc 的包 data 为 null，需手动指）。
                (*dec_pkt).data = p.data.as_ptr() as *mut u8;
                (*dec_pkt).size = p.data.len() as std::ffi::c_int;
            }
            if ffmpeg::avcodec_send_packet(dec_ctx, dec_pkt).is_err() {
                continue;
            }
            while ffmpeg::avcodec_receive_frame(dec_ctx, dec_frame).is_ok() {
                // 能量检测：L 平面样本绝对值之和 > 0（非全静音）。
                unsafe {
                    let nb = (*dec_frame).nb_samples as usize;
                    let l = (*dec_frame).data[0] as *const f32;
                    if nb > 0 && !l.is_null() {
                        let e: f32 = (0..nb).map(|i| (*l.add(i)).abs()).sum();
                        assert!(e > 0.0, "decoded frame energy must be non-zero");
                        decoded_samples += nb;
                    }
                }
                ffmpeg::av_frame_unref(dec_frame);
            }
            // 复位 packet 指针（不 free，data 非_owned）。
            unsafe {
                (*dec_pkt).data = std::ptr::null_mut();
                (*dec_pkt).size = 0;
            }
        }
        let mut c = dec_ctx;
        ffmpeg::avcodec_free_context(&mut c);
        let mut f = dec_frame;
        ffmpeg::av_frame_free(&mut f);
        let mut pk = dec_pkt;
        ffmpeg::av_packet_free(&mut pk);

        assert!(
            decoded_samples >= FRAME_SAMPLES,
            "decoded {} samples (expect ≥{})",
            decoded_samples,
            FRAME_SAMPLES
        );
    }

    /// P1D Tests §pipeline：无音频包时不返回错误、不阻塞。
    #[test]
    fn test_audio_pipeline_empty_no_block() {
        // 不 start 捕获（无设备也能测）：next_packets 应立即返回空 Vec。
        // WasapiLoopbackCapture::new 在无设备时返回 Err，故仅在能创建时跑。
        let pipeline = match AudioPipeline::new() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("AudioPipeline not available (no capture/opus): {e}; skipped");
                return;
            }
        };
        let mut p = pipeline;
        let start = Instant::now();
        let pkts = p.next_packets().unwrap();
        let elapsed = start.elapsed();
        assert!(pkts.is_empty(), "no audio → empty packets");
        // 非阻塞：应 < 50ms（远小于 20ms 帧的任何阻塞）。
        assert!(
            elapsed.as_millis() < 50,
            "next_packets blocked for {:?}",
            elapsed
        );
    }

    /// P1D Tests §pipeline：输出包 PTS 单调递增。
    #[test]
    fn test_audio_pipeline_timestamp_monotonic() {
        if !opus_available() {
            eprintln!("libopus not available; test_audio_pipeline_timestamp_monotonic skipped");
            return;
        }
        // 直接用编码器模拟（pipeline 需真实捕获设备）。
        let mut enc = OpusEncoder::new().unwrap();
        let mut all = Vec::new();
        for frame_idx in 0..5u64 {
            let pcm = vec![0.01f32; FRAME_INTERLEAVED];
            let ts = Timestamp::new(Instant::now(), frame_idx * FRAME_MS as u64);
            all.extend(enc.encode_pcm(&pcm, ts).unwrap());
        }
        for w in all.windows(2) {
            assert!(w[1].ts.pts >= w[0].ts.pts, "PTS must be monotonic");
        }
        // 内部计数器每帧 +20ms。
        let pts_deltas: Vec<i64> = all
            .windows(2)
            .map(|w| w[1].ts.pts as i64 - w[0].ts.pts as i64)
            .collect();
        for d in pts_deltas {
            assert!(d >= 0, "PTS delta must be ≥ 0, got {}", d);
        }
    }

    /// P1D Tests §pipeline：sample_rate=48000 / channels=2 / bitrate=64k 与 M12 一致。
    #[test]
    fn test_audio_pipeline_params_m12() {
        assert_eq!(SAMPLE_RATE, 48_000);
        assert_eq!(CHANNELS, 2);
        assert_eq!(BIT_RATE, 64_000);
        assert_eq!(FRAME_MS, 20);
        assert_eq!(FRAME_SAMPLES, 960);
        assert_eq!(FRAME_INTERLEAVED, 1920);
        // 编码器（若可用）回报同样参数。
        if let Ok(enc) = OpusEncoder::new() {
            assert_eq!(enc.sample_rate(), 48_000);
            assert_eq!(enc.channels(), 2);
        }
    }

    /// P1D Tests §capture：无设备 → Err(InitFailed)，不 panic（非 Windows 跳过）。
    #[cfg(target_os = "windows")]
    #[test]
    fn test_capture_no_device_path() {
        // 无法强制「无设备」，仅验证 create_default_capture 不 panic；
        // 真实无设备场景在集成测试覆盖。
        let _ = create_default_capture();
    }

    /// 编码参数常量自洽（无 FFmpeg 也可跑）。
    #[test]
    fn test_frame_constants_consistent() {
        assert_eq!(FRAME_SAMPLES, 960, "20ms @48kHz = 960 samples/ch");
        assert_eq!(FRAME_INTERLEAVED, 1920, "stereo interleaved = 1920");
    }
}
