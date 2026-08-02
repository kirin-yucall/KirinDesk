//! Windows WASAPI 环回/麦克风捕获（P1D §T4.1 + M8-T032）。
//!
//! 两种捕获共用一个骨架（见 [`run_capture_loop_common`]）：
//! - **环回**（[`WasapiLoopbackCapture`]，系统声音）：取默认渲染端点
//!   （`eRender`/`eConsole`），`IAudioClient` 以
//!   `AUDCLNT_SHAREMODE_SHARED` + `AUDCLNT_STREAMFLAGS_LOOPBACK` 初始化环回捕获；
//! - **麦克风**（[`WasapiMicCapture`]，M8-T032 客户端 talkback）：取默认
//!   捕获端点（`eCapture`/`eCommunications`，即通话麦克风），**无** loopback
//!   标志；其余（GetMixFormat → Initialize → GetBuffer 轮询 → 格式适配）共用。
//!
//! 两者都经 `IAudioCaptureClient::GetBuffer` 拉 float32 PCM，推到通道。
//!
//! # 格式适配
//!
//! WASAPI 环回**只能**用 mix format（系统音频引擎格式）；麦克风同理用设备
//! 默认格式。现代 Windows mix format 通常为 48000Hz/stereo/float32（正合 M12
//! 目标）。若系统设为 44100Hz/单声道/24-bit 等，本模块在 Rust 侧做：
//! - float32（IEEE_FLOAT，tag=3）或 extensible 的 KSDATAFORMAT_SUBTYPE_IEEE_FLOAT
//!   → 直接用；S16/S32 PCM → 转 float32；
//! - 重采样到 48000Hz（简单线性插值）；
//! - 单声道 → 复制到 stereo。
//!
//! # 线程模型
//!
//! [`AudioCapture::start`] spawn 一条捕获线程：CoInitializeEx(MTA)
//! → 建 enumerator → Activate IAudioClient → Initialize(loopback 按需) →
//! GetService(IAudioCaptureClient) → Start → 轮询 GetBuffer（10ms 间隔）→
//! 推 [`AudioPcm`] → stop 时 Stop+Release+CoUninitialize。

#![cfg(target_os = "windows")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Media::Audio::{
    eCapture, eCommunications, eConsole, eRender, EDataFlow, ERole, IAudioCaptureClient,
    IAudioClient, IMMDeviceEnumerator, MMDeviceEnumerator, AUDCLNT_BUFFERFLAGS_SILENT,
    AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, WAVEFORMATEX, WAVEFORMATEXTENSIBLE,
};
use windows::Win32::Media::KernelStreaming::WAVE_FORMAT_EXTENSIBLE;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_ALL,
    COINIT_MULTITHREADED,
};

/// `WAVE_FORMAT_IEEE_FLOAT`（= 3）。windows crate 把它放在
/// `Win32::Media::Multimedia`（需额外 feature），故这里直接用数值常量。
const WAVE_FORMAT_IEEE_FLOAT: u32 = 3;

use super::{AudioCapture, AudioPcm};
use crate::encoder::audio::{CHANNELS, FRAME_MS, SAMPLE_RATE};
use crate::encoder::video::EncodeError;

// KSDATAFORMAT_SUBTYPE_IEEE_FLOAT GUID（{00000003-0000-0010-8000-00aa00389b71}）。
// WAVEFORMATEXTENSIBLE.SubFormat == 此值 → mix 为 float32。
const KSDATAFORMAT_SUBTYPE_IEEE_FLOAT: windows::core::GUID =
    windows::core::GUID::from_u128(0x00000003_0000_0010_8000_00aa00389b71);

/// WASAPI 环回系统声音捕获器。
///
/// 创建时只做轻量校验（能否取到默认渲染端点）；真正的捕获在 [`AudioCapture::start`]
/// spawn 的线程里进行。stop 通过原子标志通知线程退出 + 释放 COM 资源。
pub struct WasapiLoopbackCapture {
    /// 捕获线程退出标志。
    stop_flag: Arc<AtomicBool>,
    /// 捕获线程句柄（start 后才有）。
    thread: Option<thread::JoinHandle<()>>,
}

impl WasapiLoopbackCapture {
    /// 创建：探测默认渲染端点是否可达（不启动捕获）。
    ///
    /// 无声卡 / 无默认渲染端点 → `Err(InitFailed)`。
    pub fn new() -> Result<Self, EncodeError> {
        // 探测：能否 CoCreate IMMDeviceEnumerator + GetDefaultAudioEndpoint。
        // 在 MTA 初始化（临时，探测完 Uninitialize）。
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        // S_OK(0) / S_FALSE(1, 已初始化) 都可继续；失败才报错。
        let co_init_ok = hr.is_ok() || hr == windows::Win32::Foundation::S_FALSE;
        let probe = if co_init_ok {
            probe_endpoint(eRender, eConsole)
        } else {
            Err(EncodeError::InitFailed(format!("CoInitializeEx: {hr}")))
        };
        // 平衡 CoInitializeEx：只有本次真正初始化（S_OK）才 Uninitialize。
        if hr == windows::Win32::Foundation::S_OK {
            unsafe { CoUninitialize() };
        }
        // 探测结果即返回（不保留 COM 对象——线程里重建）。
        probe.map(|_| Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            thread: None,
        })
    }
}

impl AudioCapture for WasapiLoopbackCapture {
    fn start(&mut self, sink: mpsc::Sender<AudioPcm>) -> Result<(), EncodeError> {
        if self.thread.is_some() {
            return Ok(()); // 幂等。
        }
        // 再次探测默认端点（确认 start 时仍可用）。
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let co_init_ok = hr.is_ok() || hr == windows::Win32::Foundation::S_FALSE;
        if hr == windows::Win32::Foundation::S_OK {
            unsafe { CoUninitialize() };
        }
        if !co_init_ok {
            return Err(EncodeError::InitFailed(format!("CoInitializeEx: {hr}")));
        }

        self.stop_flag.store(false, Ordering::SeqCst);
        let stop_flag = self.stop_flag.clone();
        let handle = thread::Builder::new()
            .name("kirin-audio-wasapi".into())
            .spawn(move || {
                run_capture_loop(stop_flag, sink);
            })
            .map_err(|e| EncodeError::InitFailed(format!("spawn capture thread: {e}")))?;
        self.thread = Some(handle);
        Ok(())
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            // 不阻塞 join 过久：捕获线程在 ≤10ms 轮询间隔内观察标志退出。
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

impl Drop for WasapiLoopbackCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// WASAPI 麦克风捕获器（M8-T032：客户端 talkback 回传）。
///
/// 与 [`WasapiLoopbackCapture`] 同骨架，差别仅在端点（`eCapture`/
/// `eCommunications`，默认通话麦克风）与初始化标志（**无** loopback）。
/// 创建时只做轻量校验（能否取到默认捕获端点）；真正的捕获在
/// [`AudioCapture::start`] spawn 的线程里进行。
pub struct WasapiMicCapture {
    /// 捕获线程退出标志。
    stop_flag: Arc<AtomicBool>,
    /// 捕获线程句柄（start 后才有）。
    thread: Option<thread::JoinHandle<()>>,
}

impl WasapiMicCapture {
    /// 创建：探测默认捕获端点是否可达（不启动捕获）。
    ///
    /// 无麦克风 / 无默认捕获端点 → `Err(InitFailed)`。
    pub fn new() -> Result<Self, EncodeError> {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let co_init_ok = hr.is_ok() || hr == windows::Win32::Foundation::S_FALSE;
        let probe = if co_init_ok {
            probe_endpoint(eCapture, eCommunications)
        } else {
            Err(EncodeError::InitFailed(format!("CoInitializeEx: {hr}")))
        };
        if hr == windows::Win32::Foundation::S_OK {
            unsafe { CoUninitialize() };
        }
        probe.map(|_| Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            thread: None,
        })
    }
}

impl AudioCapture for WasapiMicCapture {
    fn start(&mut self, sink: mpsc::Sender<AudioPcm>) -> Result<(), EncodeError> {
        if self.thread.is_some() {
            return Ok(()); // 幂等。
        }
        // 再次探测默认捕获端点（确认 start 时仍可用）。
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let co_init_ok = hr.is_ok() || hr == windows::Win32::Foundation::S_FALSE;
        if hr == windows::Win32::Foundation::S_OK {
            unsafe { CoUninitialize() };
        }
        if !co_init_ok {
            return Err(EncodeError::InitFailed(format!("CoInitializeEx: {hr}")));
        }

        self.stop_flag.store(false, Ordering::SeqCst);
        let stop_flag = self.stop_flag.clone();
        let handle = thread::Builder::new()
            .name("kirin-audio-mic".into())
            .spawn(move || {
                run_mic_capture_loop(stop_flag, sink);
            })
            .map_err(|e| EncodeError::InitFailed(format!("spawn mic capture thread: {e}")))?;
        self.thread = Some(handle);
        Ok(())
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            // 不阻塞 join 过久：捕获线程在 ≤10ms 轮询间隔内观察标志退出。
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

impl Drop for WasapiMicCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 探测默认端点（临时 COM 上下文里；`flow`/`role` 决定环回或麦克风）。
fn probe_endpoint(flow: EDataFlow, role: ERole) -> Result<(), EncodeError> {
    let enumerator: IMMDeviceEnumerator = unsafe {
        CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
    }
    .map_err(|e| EncodeError::InitFailed(format!("CoCreateInstance(MMDeviceEnumerator): {e}")))?;
    let dev = unsafe { enumerator.GetDefaultAudioEndpoint(flow, role) }
        .map_err(|e| EncodeError::InitFailed(format!("GetDefaultAudioEndpoint: {e}")))?;
    // 确认能 Activate IAudioClient。
    let _client: IAudioClient = unsafe { dev.Activate::<IAudioClient>(CLSCTX_ALL, None) }
        .map_err(|e| EncodeError::InitFailed(format!("IMMDevice::Activate(IAudioClient): {e}")))?;
    Ok(())
}

/// 环回捕获线程主循环：端点 `eRender`/`eConsole` + loopback 标志。
fn run_capture_loop(stop_flag: Arc<AtomicBool>, sink: mpsc::Sender<AudioPcm>) {
    run_capture_loop_common("loopback", eRender, eConsole, true, stop_flag, sink);
}

/// 麦克风捕获线程主循环：端点 `eCapture`/`eCommunications`、无 loopback。
fn run_mic_capture_loop(stop_flag: Arc<AtomicBool>, sink: mpsc::Sender<AudioPcm>) {
    run_capture_loop_common("mic", eCapture, eCommunications, false, stop_flag, sink);
}

/// 捕获线程主循环（环回/麦克风共用骨架）：建 COM → enumerator → device →
/// client → initialize（loopback 按需）→ capture client → Start → 轮询
/// GetBuffer → 适配到 48000/stereo/float32 → 推通道。
fn run_capture_loop_common(
    label: &'static str,
    flow: EDataFlow,
    role: ERole,
    loopback: bool,
    stop_flag: Arc<AtomicBool>,
    sink: mpsc::Sender<AudioPcm>,
) {
    // 线程私有 COM 上下文（MTA）。
    let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    let co_inited = hr == windows::Win32::Foundation::S_OK;
    // S_FALSE（已初始化）也可用，但本线程是新线程，正常应为 S_OK。
    if !hr.is_ok() && hr != windows::Win32::Foundation::S_FALSE {
        tracing::warn!("WASAPI capture({label}): CoInitializeEx failed: {hr}");
        return;
    }

    // 任何提前 return 都要 CoUninitialize。
    let _guard = CoUninitGuard { inited: co_inited };

    if let Err(e) = run_capture_inner(label, flow, role, loopback, &stop_flag, &sink) {
        tracing::warn!("WASAPI capture({label}) thread exiting: {e}");
    }
    // 通道 drop（sink 离开作用域）→ 接收端 next_packets 收到 Disconnected。
}

struct CoUninitGuard {
    inited: bool,
}
impl Drop for CoUninitGuard {
    fn drop(&mut self) {
        if self.inited {
            unsafe { CoUninitialize() };
        }
    }
}

fn run_capture_inner(
    label: &'static str,
    flow: EDataFlow,
    role: ERole,
    loopback: bool,
    stop_flag: &Arc<AtomicBool>,
    sink: &mpsc::Sender<AudioPcm>,
) -> Result<(), EncodeError> {
    // 1. enumerator + default endpoint（环回 = eRender/eConsole；mic = eCapture/eCommunications）。
    let enumerator: IMMDeviceEnumerator =
        unsafe { CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL) }
            .map_err(|e| EncodeError::InitFailed(format!("CoCreateInstance: {e}")))?;
    let dev = unsafe { enumerator.GetDefaultAudioEndpoint(flow, role) }
        .map_err(|e| EncodeError::InitFailed(format!("GetDefaultAudioEndpoint: {e}")))?;

    // 2. Activate IAudioClient。
    let client: IAudioClient = unsafe { dev.Activate::<IAudioClient>(CLSCTX_ALL, None) }
        .map_err(|e| EncodeError::InitFailed(format!("Activate(IAudioClient): {e}")))?;

    // 3. GetMixFormat（环回只能用 mix format；麦克风取设备默认格式）。
    let mix_ptr: *mut WAVEFORMATEX = unsafe { client.GetMixFormat() }
        .map_err(|e| EncodeError::InitFailed(format!("GetMixFormat: {e}")))?;
    if mix_ptr.is_null() {
        return Err(EncodeError::InitFailed("GetMixFormat returned null".into()));
    }
    // 解析格式（borrow mix_ptr 期间不释放）。
    let fmt_desc = parse_format(mix_ptr);

    // 4. Initialize（共享 + 20ms 帧对齐缓冲；环回加 loopback 标志）。
    // hnsBufferDuration = 20ms = 200000 (100ns 单位)；hnsPeriodicity = 0（共享必须 0）。
    let hns_buffer: i64 = (FRAME_MS as i64) * 10_000; // 20ms in 100ns units
    let flags = if loopback {
        AUDCLNT_STREAMFLAGS_LOOPBACK
    } else {
        0 // 麦克风捕获无 loopback（AUDCLNT_STREAMFLAGS_NONE）。
    };
    let init_res = unsafe {
        client.Initialize(AUDCLNT_SHAREMODE_SHARED, flags, hns_buffer, 0, mix_ptr, None)
    };
    // mix_ptr 不再需要，释放（GetMixFormat 分配的需 CoTaskMemFree）。
    unsafe { CoTaskMemFree(Some(mix_ptr as *const _)) };
    init_res
        .map_err(|e| EncodeError::InitFailed(format!("IAudioClient::Initialize: {e}")))?;

    // 5. GetService IAudioCaptureClient + Start。
    let capture: IAudioCaptureClient = unsafe { client.GetService::<IAudioCaptureClient>() }
        .map_err(|e| EncodeError::InitFailed(format!("GetService(IAudioCaptureClient): {e}")))?;
    unsafe { client.Start() }
        .map_err(|e| EncodeError::InitFailed(format!("IAudioClient::Start: {e}")))?;

    tracing::info!(
        "WASAPI {label} capture started: mix={}Hz/{}ch/{}bit float={} -> convert to {}Hz/stereo",
        fmt_desc.sample_rate,
        fmt_desc.channels,
        fmt_desc.bits_per_sample,
        fmt_desc.is_float,
        SAMPLE_RATE
    );

    // 6. 轮询 GetBuffer。
    let poll_interval = Duration::from_millis(5);
    let session_start = Instant::now();
    while !stop_flag.load(Ordering::SeqCst) {
        // 取所有就绪 packet。
        match drain_capture(&capture, &fmt_desc, sink, session_start) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!("WASAPI capture GetBuffer error: {e}");
                // 短暂退避，避免错误风暴。
                thread::sleep(Duration::from_millis(20));
            }
        }
        thread::sleep(poll_interval);
    }

    // 7. 停止：Stop（不 Reset，避免丢缓冲）。client/capture 经 COM Release 自动释放。
    let _ = unsafe { client.Stop() };
    // 显式 drop COM 对象（确保本线程释放，而非依赖 Drop 顺序）。
    let _ = capture;
    let _ = client;
    Ok(())
}

/// 解析 WAVEFORMATEX（含 extensible 子格式判定 float32）。
fn parse_format(p: *const WAVEFORMATEX) -> FormatDesc {
    unsafe {
        let w = &*p;
        let (is_float, real_channels, real_rate, real_bits) =
            if w.wFormatTag as u32 == WAVE_FORMAT_EXTENSIBLE {
                // WAVEFORMATEXTENSIBLE 紧跟 WAVEFORMATEX；其为 packed 结构，SubFormat
                // 字段需经 read_unaligned 读取（避免 misaligned reference UB）。
                let ext_ptr = p as *const WAVEFORMATEXTENSIBLE;
                let sub_format = std::ptr::addr_of!((*ext_ptr).SubFormat).read_unaligned();
                let is_f = sub_format == KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;
                (is_f, w.nChannels, w.nSamplesPerSec, w.wBitsPerSample)
            } else {
                let is_f = w.wFormatTag as u32 == WAVE_FORMAT_IEEE_FLOAT;
                (is_f, w.nChannels, w.nSamplesPerSec, w.wBitsPerSample)
            };
        FormatDesc {
            sample_rate: real_rate,
            channels: real_channels,
            bits_per_sample: real_bits,
            is_float,
        }
    }
}

#[derive(Clone, Copy)]
struct FormatDesc {
    sample_rate: u32,
    channels: u16,
    bits_per_sample: u16,
    is_float: bool,
}

/// 排空当前就绪的捕获包，适配到 48000/stereo/float32 推通道。
fn drain_capture(
    capture: &IAudioCaptureClient,
    fmt: &FormatDesc,
    sink: &mpsc::Sender<AudioPcm>,
    session_start: Instant,
) -> Result<(), EncodeError> {
    unsafe {
        // 循环处理所有 packet（GetNextPacketSize = 0 表示无更多）。
        loop {
            let packet_frames = capture
                .GetNextPacketSize()
                .map_err(|e| EncodeError::EncodeFailed(format!("GetNextPacketSize: {e}")))?;
            if packet_frames == 0 {
                break;
            }
            let mut data: *mut u8 = std::ptr::null_mut();
            let mut frames: u32 = 0;
            let mut flags: u32 = 0;
            capture
                .GetBuffer(&mut data, &mut frames, &mut flags, None, None)
                .map_err(|e| EncodeError::EncodeFailed(format!("GetBuffer: {e}")))?;

            // AUDCLNT_BUFFERFLAGS_SILENT → 推静音帧（保持时间轴连续）。
            let silent = (flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32) != 0;

            // 把原始帧转 interleaved float32（按 fmt）。
            let raw = if silent || data.is_null() || frames == 0 {
                Vec::new()
            } else {
                raw_to_interleaved_f32(data, frames as usize, fmt)
            };

            // 适配到 48000/stereo。
            let adapted = adapt_to_target(raw, fmt, frames as usize, silent);

            // ReleaseBuffer（标记已读）。
            let _ = capture.ReleaseBuffer(frames);

            // 推通道（即使静音也推，保持时间轴）。
            if !adapted.is_empty() {
                let pts = session_start.elapsed().as_millis() as u64;
                let ts = crate::encoder::types::Timestamp::new(Instant::now(), pts);
                let pcm = AudioPcm { ts, data: adapted };
                // send 失败 = 接收端 drop（pipeline stop）→ 退出。
                if sink.send(pcm).is_err() {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

/// 原始 PCM（按 fmt）→ interleaved float32（仍按 fmt 的声道/采样率）。
///
/// 支持 float32 / S16 / S32 PCM。不在此做重采样（留给 [`adapt_to_target`]）。
unsafe fn raw_to_interleaved_f32(data: *mut u8, frames: usize, fmt: &FormatDesc) -> Vec<f32> {
    let ch = fmt.channels as usize;
    if ch == 0 || frames == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(frames * ch);
    match (fmt.is_float, fmt.bits_per_sample) {
        (true, 32) => {
            let p = data as *const f32;
            for i in 0..(frames * ch) {
                out.push(*p.add(i));
            }
        }
        (false, 16) => {
            let p = data as *const i16;
            for i in 0..(frames * ch) {
                out.push(*p.add(i) as f32 / 32768.0);
            }
        }
        (false, 32) => {
            let p = data as *const i32;
            for i in 0..(frames * ch) {
                out.push(*p.add(i) as f32 / 2147483648.0);
            }
        }
        // 其它格式（24-bit 等）回退静音，不阻断（M12 float32 优先 / 16-bit 兜底）。
        _ => {
            out.resize(frames * ch, 0.0);
        }
    }
    out
}

/// 把 interleaved float32（fmt 声道/采样率）适配到 48000Hz/stereo interleaved。
///
/// - 声道：1（mono）→ 复制到 stereo；2 → 原样；其它 → 取前两声道。
/// - 采样率：≠48000 → 简单线性插值重采样。
/// - `silent` 时按 frames 产对应静音 stereo（保持时间轴）。
fn adapt_to_target(input: Vec<f32>, fmt: &FormatDesc, frames: usize, silent: bool) -> Vec<f32> {
    let src_ch = fmt.channels.max(1) as usize;
    // 1. 声道数适配 → stereo interleaved。
    let stereo: Vec<f32> = if silent {
        vec![0.0; frames * CHANNELS as usize]
    } else if input.is_empty() {
        vec![0.0; frames * CHANNELS as usize]
    } else {
        let n_frames = input.len() / src_ch;
        let mut s = Vec::with_capacity(n_frames * 2);
        for f in 0..n_frames {
            let l = input[f * src_ch];
            let r = if src_ch >= 2 {
                input[f * src_ch + 1]
            } else {
                l
            };
            s.push(l);
            s.push(r);
        }
        s
    };
    // 2. 采样率适配 → 48000。
    if fmt.sample_rate == SAMPLE_RATE {
        stereo
    } else if fmt.sample_rate == 0 {
        stereo // 防御。
    } else {
        linear_resample(&stereo, fmt.sample_rate, SAMPLE_RATE)
    }
}

/// 立体声 interleaved 线性插值重采样（`src_rate` → `dst_rate`）。
fn linear_resample(stereo: &[f32], src_rate: u32, dst_rate: u32) -> Vec<f32> {
    if stereo.is_empty() {
        return Vec::new();
    }
    let src_frames = stereo.len() / 2;
    let dst_frames = ((src_frames as u64) * (dst_rate as u64) / (src_rate as u64)) as usize;
    let mut out = Vec::with_capacity(dst_frames * 2);
    for i in 0..dst_frames {
        // src 帧位置（浮点）。
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

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_resample_identity() {
        let s = vec![0.0f32, 0.0, 1.0, 1.0, 0.5, 0.5]; // 3 frames stereo
        let out = linear_resample(&s, 48000, 48000);
        assert_eq!(out.len(), s.len());
        assert_eq!(out, s);
    }

    #[test]
    fn test_linear_resample_upsample() {
        // 1 frame stereo → 2 frames @ 2x rate。
        let s = vec![0.0f32, 0.0, 1.0, 1.0]; // 2 frames
        let out = linear_resample(&s, 24000, 48000);
        // 2 src frames * 48000/24000 = 4 dst frames。
        assert_eq!(out.len() / 2, 4);
        // 中点（idx=2 对应 src pos=1.0）应接近 src[1]=1.0。
        let mid_l = out[2 * 2];
        assert!((mid_l - 1.0).abs() < 0.01, "mid sample L={mid_l}");
    }

    #[test]
    fn test_adapt_mono_to_stereo() {
        let fmt = FormatDesc {
            sample_rate: 48000,
            channels: 1,
            bits_per_sample: 32,
            is_float: true,
        };
        // mono input: 3 frames [0.1, 0.2, 0.3]
        let input = vec![0.1f32, 0.2, 0.3];
        let out = adapt_to_target(input, &fmt, 3, false);
        // 3 frames stereo。
        assert_eq!(out.len(), 6);
        assert!((out[0] - 0.1).abs() < 1e-6);
        assert!((out[1] - 0.1).abs() < 1e-6); // R == L（mono 复制）
        assert!((out[4] - 0.3).abs() < 1e-6);
    }

    #[test]
    fn test_adapt_silent_keeps_timeline() {
        let fmt = FormatDesc {
            sample_rate: 48000,
            channels: 2,
            bits_per_sample: 32,
            is_float: true,
        };
        let out = adapt_to_target(vec![], &fmt, 4, true);
        // 4 frames silent stereo。
        assert_eq!(out.len(), 8);
        assert!(out.iter().all(|&x| x == 0.0));
    }

    #[test]
    fn test_adapt_resamples_44100_to_48000() {
        let fmt = FormatDesc {
            sample_rate: 44100,
            channels: 2,
            bits_per_sample: 32,
            is_float: true,
        };
        // 441 frames stereo @ 44100Hz = 10ms。
        let frames = 441;
        let input: Vec<f32> = (0..frames)
            .flat_map(|i| [i as f32 * 0.001, i as f32 * 0.001])
            .collect();
        let out = adapt_to_target(input, &fmt, frames, false);
        // 441 * 48000/44100 ≈ 480 dst frames。
        let dst_frames = out.len() / 2;
        assert!(
            (dst_frames as i64 - 480).abs() <= 1,
            "dst_frames={dst_frames}"
        );
    }

    /// M8-T032：麦克风捕获器创建/析构冒烟（eCapture 端点探测；无麦克风
    /// 设备 → Err(InitFailed)，不 panic、不泄漏 COM 上下文）。
    #[test]
    fn test_mic_capture_create_drop() {
        let mic = WasapiMicCapture::new();
        // 有/无麦克风都允许：有 → 可创建（不 start）；无 → InitFailed。
        if let Ok(mut mic) = mic {
            mic.stop(); // 析构前 stop（幂等），验证 Drop 不 panic。
        }
    }
}
