//! Linux PipeWire 音频播放（M8-T015 P2C T3.3 Linux 侧 / R-14-S4）。
//!
//! # 方案
//!
//! `pw_stream`（Output 方向，MediaCategory=Playback）自动连接默认 sink，
//! process 回调里把解码侧投递的 48k/stereo/float32 PCM 写入图缓冲：
//!
//! ```text
//! jitter buffer ──► mpsc<AudioPcm> ──► process 回调 ──► pw_stream(Output/Audio)
//!                       │                    │
//!                   48k/2ch f32         转换到设备协商格式（重采样/声道/位深）
//! ```
//!
//! # 格式适配
//!
//! PipeWire 图通常协商为 F32LE/48k/2ch（直通）；设备采样率/声道数不同时
//! 在 Rust 侧软件适配（线性重采样 + 声道映射 + S16 转换，与 WASAPI 播放
//! 的 `frame_to_mix_bytes` 同思路），保证时间轴对齐（每 20ms 输入恰好
//! 20ms 输出）。
//!
//! # 故障语义
//!
//! 无 PipeWire / 无音频图（纯无头服务器）→ `start` 失败返回 Err，**不影响
//! 视频/键鼠**（调用方独立线程创建，失败即放弃音频，与编码侧 P1D 同款
//! 原则）。

#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pipewire as pw;
use pw::spa;

use crate::decoder::audio::{AudioPcm, CHANNELS, FRAME_INTERLEAVED, SAMPLE_RATE};
use crate::decoder::audio_playback::AudioPlayback;
use crate::decoder::DecodeError;

// ════════════════════════════════════════════════════════════════
// 播放后端
// ════════════════════════════════════════════════════════════════

/// Linux PipeWire 播放（R-14-S4）。
///
/// `start` 在独立线程内建立 PipeWire 连接与播放流；`stop` 停循环 + join
/// （幂等）。
pub struct PipeWirePlayback {
    stop_flag: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl PipeWirePlayback {
    /// 创建（轻量；真正连接在 `start` 线程内，失败由该线程报告）。
    pub fn new() -> Result<Self, DecodeError> {
        Ok(Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            thread: None,
        })
    }
}

impl AudioPlayback for PipeWirePlayback {
    fn start(&mut self, src: mpsc::Receiver<AudioPcm>) -> Result<(), DecodeError> {
        if self.thread.is_some() {
            return Ok(()); // 幂等。
        }
        self.stop_flag.store(false, Ordering::SeqCst);
        let stop_flag = self.stop_flag.clone();
        let handle = thread::Builder::new()
            .name("kirin-audio-render".into())
            .spawn(move || {
                if let Err(e) = run_playback_loop(&stop_flag, &src) {
                    tracing::warn!("PipeWire playback thread exiting: {e}");
                }
            })
            .map_err(|e| DecodeError::InitFailed(format!("spawn playback thread: {e}")))?;
        self.thread = Some(handle);
        Ok(())
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            // 播放线程 ≤50ms 轮询观察标志退出；join 不阻塞过久。
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

impl Drop for PipeWirePlayback {
    fn drop(&mut self) {
        self.stop();
    }
}

// ════════════════════════════════════════════════════════════════
// 播放线程
// ════════════════════════════════════════════════════════════════

/// 回调用户数据：协商格式 + 输入通道 + 待写缓冲。
struct PlaybackUserData {
    /// 最终协商的音频格式（param_changed 填充，process 消费）。
    format: spa::param::audio::AudioInfoRaw,
    src: mpsc::Receiver<AudioPcm>,
    /// 待写样本（48k/stereo/interleaved f32；消费慢时上限裁剪，不阻塞）。
    pending: Vec<f32>,
    /// 缓冲溢出防御上限（64 帧 ≈ 1.28s）。
    max_pending: usize,
}

fn run_playback_loop(
    stop_flag: &Arc<AtomicBool>,
    src: &mpsc::Receiver<AudioPcm>,
) -> Result<(), DecodeError> {
    let thread_loop =
        unsafe { pw::thread_loop::ThreadLoop::new(Some("kirin-audio-playback"), None) }
            .map_err(|e| DecodeError::InitFailed(format!("pw_thread_loop_new: {e}")))?;
    let context = pw::context::Context::new(&thread_loop)
        .map_err(|e| DecodeError::InitFailed(format!("pw_context_new: {e}")))?;
    let core = context
        .connect(None)
        .map_err(|e| DecodeError::InitFailed(format!("pw_core_connect: {e}")))?;

    let props = pw::properties::properties! {
        *pw::keys::MEDIA_TYPE => "Audio",
        *pw::keys::MEDIA_CATEGORY => "Playback",
        *pw::keys::MEDIA_ROLE => "Music",
    };
    let stream = pw::stream::Stream::new(&core, "kirin-audio-playback", props)
        .map_err(|e| DecodeError::InitFailed(format!("pw_stream_new: {e}")))?;

    let user_data = PlaybackUserData {
        format: spa::param::audio::AudioInfoRaw::new(),
        src: src.clone(),
        pending: Vec::with_capacity(FRAME_INTERLEAVED * 16),
        max_pending: FRAME_INTERLEAVED * 64,
    };
    let _listener = stream
        .add_local_listener_with_user_data(user_data)
        .param_changed(|_, user_data, id, param| on_param_changed(user_data, id, param))
        .process(|stream, user_data| on_process(stream, user_data))
        .register()
        .map_err(|e| DecodeError::InitFailed(format!("pw_stream listener: {e}")))?;

    let mut params = build_audio_format_pod()?;
    stream
        .connect(
            spa::utils::Direction::Output,
            None,
            pw::stream::StreamFlags::AUTOCONNECT
                | pw::stream::StreamFlags::MAP_BUFFERS
                | pw::stream::StreamFlags::RT_PROCESS,
            &mut params,
        )
        .map_err(|e| DecodeError::InitFailed(format!("pw_stream_connect: {e}")))?;
    thread_loop.start();

    while !stop_flag.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(50));
    }
    thread_loop.stop();
    Ok(())
}

/// `param_changed`：记录协商格式（rate/channels/format）。
fn on_param_changed(user_data: &mut PlaybackUserData, id: u32, param: Option<&spa::pod::Pod>) {
    let Some(param) = param else {
        return;
    };
    if id != spa::param::ParamType::Format.as_raw() {
        return;
    }
    let Ok((media_type, media_subtype)) = spa::param::format_utils::parse_format(param) else {
        return;
    };
    if media_type != spa::param::format::MediaType::Audio
        || media_subtype != spa::param::format::MediaSubtype::Raw
    {
        return;
    }
    if user_data.format.parse(param).is_ok() {
        tracing::info!(
            "PipeWire playback: negotiated format={} {}Hz {}ch",
            user_data.format.format().as_raw(),
            user_data.format.rate(),
            user_data.format.channels()
        );
    }
}

/// `process`（内部线程）：消费输入 → 转设备格式 → 写入缓冲（不足写静音，
/// 保持时间轴连续；Buffer Drop 自动 queue 归还）。
fn on_process(stream: &pw::stream::StreamRef, user_data: &mut PlaybackUserData) {
    let Some(mut buffer) = stream.dequeue_buffer() else {
        return;
    };
    let datas = buffer.datas_mut();
    if datas.is_empty() {
        return;
    }
    let data = &mut datas[0];
    let Some(out_bytes) = data.data() else {
        return;
    };
    let capacity = data.chunk().size() as usize; // 可写字节数（maxsize）。
    if capacity == 0 {
        return;
    }

    // 1. 消费输入通道（非阻塞；Disconnected 视作暂无数据）。
    while let Ok(pcm) = user_data.src.try_recv() {
        user_data.pending.extend_from_slice(&pcm.samples);
    }
    // 2. 缓冲溢出防御（消费过慢）→ 丢最旧帧，不阻塞解码侧。
    if user_data.pending.len() > user_data.max_pending {
        user_data
            .pending
            .drain(..user_data.pending.len() - user_data.max_pending);
    }

    // 3. 转设备格式（48k/2ch → 协商格式；不足静音补零）。
    let fmt = user_data.format;
    let rate = fmt.rate();
    let ch = fmt.channels().max(1) as u16;
    let bytes = pcm_to_device(&user_data.pending, rate, ch, fmt.format(), capacity);
    let n = bytes.len().min(capacity);
    if n > 0 {
        out_bytes[..n].copy_from_slice(&bytes[..n]);
    }
    if capacity > n {
        out_bytes[n..capacity].fill(0);
    }
    // 已写帧数记回 chunk（PipeWire 按 chunk.size 播放）。
    *data.chunk_mut().size_mut() = capacity as u32;
    // 消费掉已写部分（按字节换算回 48k/2ch 样本数）。
    let consumed = (n / 4).min(user_data.pending.len());
    if consumed > 0 {
        user_data.pending.drain(..consumed);
    }
}

// ════════════════════════════════════════════════════════════════
// 格式转换（平台无关逻辑，供单测）
// ════════════════════════════════════════════════════════════════

/// 48k/stereo/interleaved f32 → 设备格式字节（F32LE/S16LE + 重采样 + 声道
/// 映射），长度 ≤ `capacity`（不足由调用方静音补零）。
///
/// 算法同 WASAPI 播放的 `frame_to_mix_bytes`（linear_resample + 声道映射 +
/// 位深转换），保持 20ms 时间轴对齐。
fn pcm_to_device(
    pcm: &[f32],
    dev_rate: u32,
    dev_ch: u16,
    dev_fmt: spa::param::audio::AudioFormat,
    capacity: usize,
) -> Vec<u8> {
    if pcm.len() < 2 {
        return Vec::new();
    }
    let dev_rate = if dev_rate == 0 { SAMPLE_RATE } else { dev_rate };
    let dev_ch = dev_ch.max(1) as usize;

    // 1. 重采样（48000 → dev_rate；保持 interleaved 帧对）。
    let stereo: Vec<f32> = if dev_rate == SAMPLE_RATE {
        pcm.to_vec()
    } else {
        resample_stereo(pcm, SAMPLE_RATE, dev_rate)
    };
    let frames = stereo.len() / 2;

    // 2. 声道映射：2 → 直通；1 → (L+R)/2 下混；>2 → L/R 填前两槽、其余 0。
    let mut mixed = Vec::with_capacity(frames * dev_ch);
    for f in 0..frames {
        let l = stereo[f * 2];
        let r = stereo[f * 2 + 1];
        for c in 0..dev_ch {
            mixed.push(match (dev_ch, c) {
                (1, 0) => (l + r) * 0.5,
                (_, 0) => l,
                (_, 1) => r,
                _ => 0.0,
            });
        }
    }

    // 3. 位深转换（F32LE / S16LE；其余格式静音兜底，不阻断播放）。
    let raw = dev_fmt.as_raw();
    let out: Vec<u8> = if raw == spa::param::audio::AudioFormat::F32LE.as_raw() {
        mixed.iter().flat_map(|s| s.to_le_bytes()).collect()
    } else if raw == spa::param::audio::AudioFormat::S16LE.as_raw() {
        let mut b = Vec::with_capacity(mixed.len() * 2);
        for s in mixed {
            let v = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
            b.extend_from_slice(&v.to_le_bytes());
        }
        b
    } else {
        vec![0u8; mixed.len() * 2]
    };
    // 4. 截断到 capacity（调用方负责静音补零）。
    if out.len() > capacity {
        out[..capacity].to_vec()
    } else {
        out
    }
}

/// 立体声 interleaved 线性插值重采样（`src_rate` → `dst_rate`）。
///
/// 输出帧数 = `src_frames × dst_rate / src_rate`（时间轴对齐，与
/// `decoder/audio_playback.rs::linear_resample` 同算法）。
fn resample_stereo(stereo: &[f32], src_rate: u32, dst_rate: u32) -> Vec<f32> {
    if stereo.len() < 2 || src_rate == 0 {
        return Vec::new();
    }
    let src_frames = stereo.len() / 2;
    let dst_frames = ((src_frames as u64) * (dst_rate as u64) / (src_rate as u64)) as usize;
    let mut out = Vec::with_capacity(dst_frames * 2);
    for i in 0..dst_frames {
        let pos = (i as f64) * (src_rate as f64) / (dst_rate as f64);
        let idx0 = pos as usize;
        let idx1 = (idx0 + 1).min(src_frames - 1);
        let frac = (pos - idx0 as f64) as f32;
        let l0 = stereo[idx0 * 2];
        let r0 = stereo[idx0 * 2 + 1];
        let l1 = stereo[idx1 * 2];
        let r1 = stereo[idx1 * 2 + 1];
        out.push(l0 + (l1 - l0) * frac);
        out.push(r0 + (r1 - r0) * frac);
    }
    out
}

/// EnumFormat POD：F32LE / 48000Hz / 2ch（请求；图不满足时报实际值）。
fn build_audio_format_pod() -> Result<Vec<spa::pod::Pod>, DecodeError> {
    use pw::spa::param::audio::AudioFormat;
    use pw::spa::param::format::{FormatProperties, MediaSubtype, MediaType};

    let mut info = spa::param::audio::AudioInfoRaw::new();
    info.set_format(AudioFormat::F32LE);
    info.set_rate(SAMPLE_RATE);
    info.set_channels(CHANNELS as u32);

    let mut props = vec![
        pw::spa::pod::Property::new(
            FormatProperties::MediaType.as_raw(),
            pw::spa::pod::Value::Id(pw::spa::utils::Id(MediaType::Audio.as_raw())),
        ),
        pw::spa::pod::Property::new(
            FormatProperties::MediaSubtype.as_raw(),
            pw::spa::pod::Value::Id(pw::spa::utils::Id(MediaSubtype::Raw.as_raw())),
        ),
    ];
    props.extend(info.into());
    let obj = pw::spa::pod::Object {
        type_: pw::spa::utils::SpaTypes::ObjectParamFormat.as_raw(),
        id: pw::spa::param::ParamType::EnumFormat.as_raw(),
        properties: props,
    };
    let values: Vec<u8> = spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(obj),
    )
    .map_err(|e| DecodeError::InitFailed(format!("serialize EnumFormat pod: {e}")))?
    .0
    .into_inner();
    Ok(vec![spa::pod::Pod::from_bytes(&values).map_err(|e| {
        DecodeError::InitFailed(format!("Pod::from_bytes: {e}"))
    })?])
}

// ════════════════════════════════════════════════════════════════
// Tests（环境无关：格式转换与 POD 构造）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 48k/2ch/F32LE → 直通字节。
    #[test]
    fn test_pcm_to_device_identity() {
        let pcm: Vec<f32> = (0..FRAME_INTERLEAVED).map(|i| (i as f32) * 0.001).collect();
        let bytes = pcm_to_device(&pcm, 48000, 2, AudioFormat::F32LE, usize::MAX);
        assert_eq!(bytes.len(), FRAME_INTERLEAVED * 4);
        for (i, b) in bytes.chunks_exact(4).enumerate() {
            assert_eq!(f32::from_le_bytes([b[0], b[1], b[2], b[3]]), pcm[i]);
        }
    }

    /// 48k/2ch → 44100：882 帧/20ms，时间轴对齐。
    #[test]
    fn test_pcm_to_device_resample_44100() {
        let pcm = vec![0.0f32; FRAME_INTERLEAVED];
        let bytes = pcm_to_device(&pcm, 44100, 2, AudioFormat::F32LE, usize::MAX);
        assert_eq!(bytes.len(), 882 * 2 * 4);
    }

    /// 48k/stereo → S16LE：位深转换 + 值域钳位。
    #[test]
    fn test_pcm_to_device_s16() {
        let pcm: Vec<f32> = (0..FRAME_INTERLEAVED)
            .map(|i| (i as f32) * 0.0005)
            .collect();
        let bytes = pcm_to_device(&pcm, 48000, 2, AudioFormat::S16LE, usize::MAX);
        assert_eq!(bytes.len(), FRAME_INTERLEAVED * 2);
        let v = i16::from_le_bytes([bytes[0], bytes[1]]) as f32 / 32767.0;
        assert!((v - pcm[0]).abs() < 0.001);
    }

    /// S16 钳位（超出 [-1,1] 不环绕爆音）。
    #[test]
    fn test_pcm_to_device_s16_clamps() {
        let pcm = vec![5.0f32; FRAME_INTERLEAVED];
        let bytes = pcm_to_device(&pcm, 48000, 2, AudioFormat::S16LE, usize::MAX);
        let v = i16::from_le_bytes([bytes[0], bytes[1]]) as f32 / 32767.0;
        assert!((v - 1.0).abs() < 0.001);
    }

    /// 48k/stereo → mono：下混 (L+R)/2。
    #[test]
    fn test_pcm_to_device_mono() {
        let pcm: Vec<f32> = (0..FRAME_INTERLEAVED).map(|i| i as f32).collect();
        let bytes = pcm_to_device(&pcm, 48000, 1, AudioFormat::F32LE, usize::MAX);
        assert_eq!(bytes.len(), FRAME_SAMPLES * 4);
        let v = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert!((v - (pcm[0] + pcm[1]) / 2.0).abs() < 1e-4);
    }

    /// capacity 截断：超出部分裁掉（调用方静音补零）。
    #[test]
    fn test_pcm_to_device_capacity_limited() {
        let pcm = vec![0.1f32; FRAME_INTERLEAVED];
        let cap = 64usize;
        let bytes = pcm_to_device(&pcm, 48000, 2, AudioFormat::F32LE, cap);
        assert_eq!(bytes.len(), cap);
    }

    /// 候选 POD 可解析为 Audio/Raw（rate=48000、channels=2）。
    #[test]
    fn test_build_audio_format_pod() {
        let params = build_audio_format_pod().expect("pod");
        let (mt, ms) = spa::param::format_utils::parse_format(&params[0])
            .expect("parse_format on our own pod");
        assert_eq!(mt, MediaType::Audio);
        assert_eq!(ms, MediaSubtype::Raw);
        let mut info = spa::param::audio::AudioInfoRaw::new();
        info.parse(&params[0]).expect("parse AudioInfoRaw");
        assert_eq!(info.rate(), 48000);
        assert_eq!(info.channels(), 2);
    }
}
