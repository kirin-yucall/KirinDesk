//! Linux PipeWire 系统声音环回捕获（M13-T001 Linux 侧 / R-14-S4）。
//!
//! # 方案
//!
//! `pw_stream`（Input 方向）+ `STREAM_CAPTURE_SINK=true` 属性 —— PipeWire
//! 据此自动把流连接到默认 sink 的 monitor 端口（等价 Windows WASAPI 环回 /
//! PulseAudio `.monitor` 源语义），捕获系统输出声音：
//!
//! ```text
//! pw_thread_loop + pw_context.connect() + pw_stream(Input/Audio, capture_sink)
//!      ▼
//! process 回调 ── float32 样本 ──► AudioPcm{ts, data} ──► mpsc ──► OpusEncoder
//! ```
//!
//! # 格式
//!
//! EnumFormat 候选：`F32LE / 48000Hz / 2ch`（与 P1D 的 48k/stereo/float32
//! 管线契约一致）。PipeWire 图通常直接满足；协商结果不同（设备采样率 /
//! 声道数不匹配）时在 Rust 侧转换：线性重采样 + 声道映射 → 恒输出
//! 48k/stereo/interleaved float32（与 WASAPI 环回输出同构）。
//!
//! # 故障语义
//!
//! 无 PipeWire / 无音频图（纯无头服务器）→ `start` 失败返回 Err，**不影响
//! 视频/键鼠**（调用方独立线程里创建，失败即放弃音频，P1D 同款原则）。
//!
//! # 依赖
//!
//! 同 `capture/linux_pipewire.rs`：pipewire =0.8.0（libpipewire-0.3）。

#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use pipewire as pw;
use pw::spa;

use crate::encoder::audio::{AudioCapture, AudioPcm, CHANNELS, SAMPLE_RATE};
use crate::encoder::types::Timestamp;
use crate::encoder::video::EncodeError;

// ════════════════════════════════════════════════════════════════
// 捕获后端
// ════════════════════════════════════════════════════════════════

/// Linux PipeWire 环回捕获（R-14-S4）。
///
/// `start` 在独立线程内建立 PipeWire 连接与捕获流（pw_thread_loop 内部
/// 自带线程跑事件循环）；`stop` 停循环 + join（幂等）。
pub struct PipeWireCapture {
    stop_flag: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl PipeWireCapture {
    /// 创建（轻量探测，不连 PipeWire——真正连接在 `start` 线程内）。
    pub fn new() -> Result<Self, EncodeError> {
        Ok(Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            thread: None,
        })
    }
}

impl AudioCapture for PipeWireCapture {
    fn start(&mut self, sink: mpsc::Sender<AudioPcm>) -> Result<(), EncodeError> {
        if self.thread.is_some() {
            return Ok(()); // 幂等。
        }
        self.stop_flag.store(false, Ordering::SeqCst);
        let stop_flag = self.stop_flag.clone();
        let handle = thread::Builder::new()
            .name("kirin-audio-capture".into())
            .spawn(move || {
                if let Err(e) = run_capture_loop(&stop_flag, &sink) {
                    tracing::warn!("PipeWire capture thread exiting: {e}");
                }
            })
            .map_err(|e| EncodeError::InitFailed(format!("spawn capture thread: {e}")))?;
        self.thread = Some(handle);
        Ok(())
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            // 捕获线程 ≤50ms 轮询观察标志退出（pw_thread_loop.stop 由线程内
            // Drop 路径处理）；join 不阻塞过久。
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

impl Drop for PipeWireCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

// ════════════════════════════════════════════════════════════════
// 捕获线程
// ════════════════════════════════════════════════════════════════

/// 回调用户数据：协商格式 + 样本投递通道。
struct CaptureUserData {
    /// 最终协商的音频格式（param_changed 填充，process 消费）。
    format: spa::param::audio::AudioInfoRaw,
    sink: mpsc::Sender<AudioPcm>,
    /// 单调 PTS（会话毫秒，与视频同轴；每发送一帧按实际样本数推进）。
    pts_ms: u64,
    /// 上次投递时刻（计算 PTS 增量用）。
    last_send: Option<Instant>,
}

fn run_capture_loop(
    stop_flag: &Arc<AtomicBool>,
    sink: &mpsc::Sender<AudioPcm>,
) -> Result<(), EncodeError> {
    let thread_loop =
        unsafe { pw::thread_loop::ThreadLoop::new(Some("kirin-audio-capture"), None) }
            .map_err(|e| EncodeError::InitFailed(format!("pw_thread_loop_new: {e}")))?;
    let context = pw::context::Context::new(&thread_loop)
        .map_err(|e| EncodeError::InitFailed(format!("pw_context_new: {e}")))?;
    // 音频不走 portal：默认 socket 直连本会话 PipeWire 图。
    let core = context
        .connect(None)
        .map_err(|e| EncodeError::InitFailed(format!("pw_core_connect: {e}")))?;

    // 环回捕获关键属性：STREAM_CAPTURE_SINK=true → 自动连接默认 sink 的
    // monitor 端口（系统输出声音，非麦克风）。
    let mut props = pw::properties::properties! {
        *pw::keys::MEDIA_TYPE => "Audio",
        *pw::keys::MEDIA_CATEGORY => "Capture",
        *pw::keys::MEDIA_ROLE => "Music",
    };
    props.insert(*pw::keys::STREAM_CAPTURE_SINK, "true");

    let stream = pw::stream::Stream::new(&core, "kirin-audio-capture", props)
        .map_err(|e| EncodeError::InitFailed(format!("pw_stream_new: {e}")))?;

    let user_data = CaptureUserData {
        format: spa::param::audio::AudioInfoRaw::new(),
        sink: sink.clone(),
        pts_ms: 0,
        last_send: None,
    };
    let _listener = stream
        .add_local_listener_with_user_data(user_data)
        .param_changed(|_, user_data, id, param| on_param_changed(user_data, id, param))
        .process(|stream, user_data| on_process(stream, user_data))
        .register()
        .map_err(|e| EncodeError::InitFailed(format!("pw_stream listener: {e}")))?;

    // EnumFormat：F32LE / 48000 / 2ch（请求；图不满足时 param_changed 报实际值）。
    let mut params = build_audio_format_pod()?;
    stream
        .connect(
            spa::utils::Direction::Input,
            None,
            pw::stream::StreamFlags::AUTOCONNECT
                | pw::stream::StreamFlags::MAP_BUFFERS
                | pw::stream::StreamFlags::RT_PROCESS,
            &mut params,
        )
        .map_err(|e| EncodeError::InitFailed(format!("pw_stream_connect: {e}")))?;
    thread_loop.start();

    // 主循环：等待停止标志（process 在内部线程执行）。
    while !stop_flag.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(50));
    }
    thread_loop.stop();
    Ok(())
}

/// `param_changed`：协商 Format 时记录实际 rate/channels/format。
fn on_param_changed(user_data: &mut CaptureUserData, id: u32, param: Option<&spa::pod::Pod>) {
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
            "PipeWire capture: negotiated format={} {}Hz {}ch",
            user_data.format.format().as_raw(),
            user_data.format.rate(),
            user_data.format.channels()
        );
    }
}

/// `process`（内部线程）：读 f32 样本 → 转换 48k/stereo → 投递 AudioPcm。
fn on_process(stream: &pw::stream::StreamRef, user_data: &mut CaptureUserData) {
    let Some(mut buffer) = stream.dequeue_buffer() else {
        return;
    };
    // buffer drop 时自动 pw_stream_queue_buffer 归还。
    let datas = buffer.datas_mut();
    if datas.is_empty() {
        return;
    }
    let data = &datas[0];
    let Some(bytes) = data.data() else {
        return;
    };
    let chunk_size = data.chunk().size() as usize;
    if chunk_size == 0 {
        return;
    }
    let src = &bytes[..chunk_size.min(bytes.len())];

    let rate = user_data.format.rate();
    let ch = user_data.format.channels().max(1) as u16;
    let fmt = user_data.format.format();
    let samples = decode_to_f32(src, fmt);

    // 转 48k/stereo/interleaved（与 WASAPI 环回输出同构）。
    let converted = if rate == SAMPLE_RATE && ch == CHANNELS {
        samples
    } else {
        convert_to_48k_stereo(&samples, rate, ch)
    };
    if converted.is_empty() {
        return;
    }

    // PTS：按样本数推进（20ms = 960 samples/ch @48k；不足整帧由编码器缓冲）。
    let now = Instant::now();
    let pts_ms = user_data.pts_ms;
    if let Some(last) = user_data.last_send {
        // 用实际时间差与样本数双重推进取 max，保证时间轴单调。
        let elapsed = now.duration_since(last).as_millis() as u64;
        let by_samples = (converted.len() as u64 / 2) * 1000 / SAMPLE_RATE as u64;
        user_data.pts_ms = user_data.pts_ms.saturating_add(elapsed.max(by_samples));
    } else {
        user_data.pts_ms = 0;
    }
    user_data.last_send = Some(now);

    let pcm = AudioPcm {
        ts: Timestamp::new(now, pts_ms),
        data: converted,
    };
    // 投递失败（pipeline 已销毁）→ 忽略。
    let _ = user_data.sink.send(pcm);
}

// ════════════════════════════════════════════════════════════════
// 格式转换（平台无关逻辑，供单测）
// ════════════════════════════════════════════════════════════════

/// 解码缓冲 → interleaved float32 样本（F32LE 直拷 / S16LE 转换；其余格式
/// 返回空——协商阶段已限定 Raw 家族，防御路径）。
fn decode_to_f32(src: &[u8], fmt: spa::param::audio::AudioFormat) -> Vec<f32> {
    let raw = fmt.as_raw();
    if raw == spa::param::audio::AudioFormat::F32LE.as_raw() {
        let n = src.len() / 4;
        let mut out = Vec::with_capacity(n);
        for b in src[..n * 4].chunks_exact(4) {
            out.push(f32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        }
        out
    } else if raw == spa::param::audio::AudioFormat::S16LE.as_raw() {
        let n = src.len() / 2;
        let mut out = Vec::with_capacity(n);
        for b in src[..n * 2].chunks_exact(2) {
            out.push(i16::from_le_bytes([b[0], b[1]]) as f32 / 32767.0);
        }
        out
    } else {
        Vec::new()
    }
}

/// 任意采样率/声道 interleaved float32 → 48k/stereo interleaved float32。
///
/// - 采样率：线性插值重采样（算法同 decoder 侧 `linear_resample`；
///   WASAPI 播放路径同款，保持时间轴对齐语义）；
/// - 声道：2 → 直通；1 → 复制双声道；>2 → 取前两声道。
pub fn convert_to_48k_stereo(samples: &[f32], src_rate: u32, src_ch: u16) -> Vec<f32> {
    if samples.is_empty() || src_rate == 0 {
        return Vec::new();
    }
    // 1. 声道映射 → 立体声帧。
    let ch = src_ch.max(1) as usize;
    let n_frames = samples.len() / ch;
    let mut stereo = Vec::with_capacity(n_frames * 2);
    for f in 0..n_frames {
        let l = samples[f * ch];
        let r = if ch == 1 { l } else { samples[f * ch + 1] };
        stereo.push(l);
        stereo.push(r);
    }
    // 2. 采样率重采样（src_rate → 48000）。
    if src_rate == SAMPLE_RATE {
        return stereo;
    }
    let src_frames = n_frames;
    let dst_frames = ((src_frames as u64) * (SAMPLE_RATE as u64) / (src_rate as u64)) as usize;
    let mut out = Vec::with_capacity(dst_frames * 2);
    for i in 0..dst_frames {
        let pos = (i as f64) * (src_rate as f64) / (SAMPLE_RATE as f64);
        let idx0 = pos as usize;
        let idx1 = (idx0 + 1).min(src_frames.saturating_sub(1));
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

/// EnumFormat POD：F32LE / 48000Hz / 2ch。
///
/// 属性列表 = MediaType/MediaSubtype（Id 变体）+ AudioInfoRaw 展开
/// （format/rate/channels；`From<AudioInfoRaw> for Vec<Property>`）。
fn build_audio_format_pod() -> Result<Vec<spa::pod::Pod>, EncodeError> {
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
    .map_err(|e| EncodeError::InitFailed(format!("serialize EnumFormat pod: {e}")))?
    .0
    .into_inner();
    Ok(vec![spa::pod::Pod::from_bytes(&values).map_err(|e| {
        EncodeError::InitFailed(format!("Pod::from_bytes: {e}"))
    })?])
}

// ════════════════════════════════════════════════════════════════
// Tests（环境无关：格式转换与 POD 构造）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// F32LE 解码：字节 → f32 原样。
    #[test]
    fn test_decode_f32le() {
        let src = 1.0f32.to_le_bytes();
        let out = decode_to_f32(&src, AudioFormat::F32LE);
        assert_eq!(out, vec![1.0]);
    }

    /// S16LE 解码：32767 → 1.0（钳位域）。
    #[test]
    fn test_decode_s16le() {
        let src = 32767i16.to_le_bytes();
        let out = decode_to_f32(&src, AudioFormat::S16LE);
        assert!((out[0] - 1.0).abs() < 1e-4);
    }

    /// 48000/2ch → 直通（无需转换）。
    #[test]
    fn test_convert_identity() {
        let samples = vec![0.1f32, -0.2, 0.3, -0.4];
        let out = convert_to_48k_stereo(&samples, 48000, 2);
        assert_eq!(out, samples);
    }

    /// 单声道 → 双声道复制。
    #[test]
    fn test_convert_mono_to_stereo() {
        let samples = vec![0.5f32, -0.5];
        let out = convert_to_48k_stereo(&samples, 48000, 1);
        assert_eq!(out, vec![0.5, 0.5, -0.5, -0.5]);
    }

    /// 44100 → 48000 重采样：时长对齐（帧数比 ≈ 48/44.1），首样本保真。
    #[test]
    fn test_convert_resample_44100() {
        // 4410 帧（100ms）→ 4800 帧。
        let samples: Vec<f32> = (0..4410 * 2).map(|i| (i as f32) * 0.001).collect();
        let out = convert_to_48k_stereo(&samples, 44100, 2);
        assert_eq!(out.len(), 4800 * 2, "48000/44100 帧数比");
        assert!((out[0] - samples[0]).abs() < 0.01);
    }

    /// 4 声道 → 取前两声道。
    #[test]
    fn test_convert_4ch_to_stereo() {
        // 帧 [L,R,C,Ls]。
        let samples = vec![1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let out = convert_to_48k_stereo(&samples, 48000, 4);
        assert_eq!(out, vec![1.0, 2.0, 5.0, 6.0]);
    }

    /// 候选 POD 可序列化并解析为 Audio/Raw。
    #[test]
    fn test_build_audio_format_pod() {
        let params = build_audio_format_pod().expect("pod");
        assert_eq!(params.len(), 1);
        let (mt, ms) = spa::param::format_utils::parse_format(&params[0])
            .expect("parse_format on our own pod");
        assert_eq!(mt, MediaType::Audio);
        assert_eq!(ms, MediaSubtype::Raw);
        // 完整解析：rate=48000、channels=2。
        let mut info = spa::param::audio::AudioInfoRaw::new();
        info.parse(&params[0]).expect("parse AudioInfoRaw");
        assert_eq!(info.rate(), 48000);
        assert_eq!(info.channels(), 2);
    }
}
