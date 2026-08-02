//! 平台音频播放（M8-T015 P2C T3.3）：跨平台共享渲染，消费 float32 PCM。
//!
//! - [`AudioPlayback`]：播放抽象 trait（`start` 启动播放线程，从通道消费
//!   [`AudioPcm`] 帧并写入平台播放设备；`stop` 幂等释放）。
//! - [`create_default_playback`]：平台路由。
//!   - Windows：**WASAPI 共享渲染**（`IMMDeviceEnumerator` + `IAudioClient` +
//!     `IAudioRenderClient`，float32 native）——首选；与编码侧 P1D WASAPI
//!     环回捕获同栈对称（同一 `windows` crate）。
//!   - macOS：CoreAudio AudioUnit（DefaultOutputUnit）——留桩（返回
//!     [`UnsupportedPlatform`](DecodeError::UnsupportedPlatform)，解码完成但
//!     静音，视频/控制不受影响），P2C-mac 阶段实现。
//!   - Linux：Pipewire / PulseAudio（`pw_stream` render）——留桩（同上），
//!     P2C-linux 阶段实现。
//!
//! # WASAPI 共享渲染要点
//!
//! - 客户端流格式用 **mix format**（`GetMixFormat`）：现代 Windows 通常为
//!   48000Hz/stereo/float32（正合目标）。若系统为 44100/单声道/16-bit 等，
//!   本模块在 Rust 侧做软件适配（重采样/声道映射/位深转换），保证时间轴
//!   对齐（每 20ms 输入恰好 20ms 输出）。
//! - 缓冲 ~100ms 容纳 jitter buffer 输出；消费不足时写静音帧（保持时间轴
//!   连续，避免 underrun 咔哒声）；消费过慢时丢最旧帧（不阻塞 jitter）。
//! - 无播放设备（无声卡/被占用）→ `Err(InitFailed)`，**不影响视频/键鼠**
//!   （独立线程原则，与编码层 P1D 同款）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::decoder::audio::{AudioPcm, CHANNELS, FRAME_INTERLEAVED, FRAME_SAMPLES, SAMPLE_RATE};
use crate::decoder::DecodeError;

// ════════════════════════════════════════════════════════════════
// AudioPlayback trait
// ════════════════════════════════════════════════════════════════

/// 跨平台音频播放（共享渲染），消费 float32 PCM。
///
/// 实现者：
/// - Windows：[`WasapiPlayback`]（WASAPI 共享渲染，float32 native）。
/// - macOS/Linux：留桩（[`create_default_playback`] 返回
///   [`UnsupportedPlatform`](DecodeError::UnsupportedPlatform)，音频静音，
///   解码流水线继续，P2C-mac/linux 阶段实现）。
///
/// # 线程模型
///
/// [`AudioPlayback::start`] 启动一条播放线程，经 `src` 通道消费已排序的
/// [`AudioPcm`]；[`AudioPlayback::stop`] 停止并释放渲染设备（幂等）。
/// 播放线程与解码线程解耦；播放故障只影响音频，不影响视频/键鼠。
pub trait AudioPlayback: Send {
    /// 启动播放线程，从通道消费 PCM 帧。
    fn start(&mut self, src: mpsc::Receiver<AudioPcm>) -> Result<(), DecodeError>;
    /// 停止播放，释放渲染设备（幂等）。
    fn stop(&mut self);
    /// 采样率（48000）。
    fn sample_rate(&self) -> u32;
    /// 声道数（2）。
    fn channels(&self) -> u16;
}

/// 创建本机默认播放器（共享渲染）。
///
/// - Windows：WASAPI 共享渲染（`GetDefaultAudioEndpoint(eRender, eConsole)`）。
/// - macOS/Linux：返回 [`UnsupportedPlatform`](DecodeError::UnsupportedPlatform)
///   （音频静音，视频/键鼠不受影响；P2C-mac/linux 阶段实现）。
///
/// 无播放设备（无声卡/被占用）→ `Err(InitFailed)`，**不影响视频/键鼠**
/// （调用方在独立线程里创建，失败即放弃音频）。
pub fn create_default_playback() -> Result<Box<dyn AudioPlayback>, DecodeError> {
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(WasapiPlayback::new()?))
    }
    #[cfg(not(target_os = "windows"))]
    {
        // P2C-mac / P2C-linux 阶段实现：CoreAudio DefaultOutputUnit /
        // Pipewire pw_stream render。
        Err(DecodeError::UnsupportedPlatform(format!(
            "audio playback not implemented on {} (P2C-{os} 阶段)",
            std::env::consts::OS,
            os = if cfg!(target_os = "macos") {
                "mac"
            } else {
                "linux"
            }
        )))
    }
}

// ════════════════════════════════════════════════════════════════
// 格式适配（平台无关：48000/stereo/float32 → 设备 mix 格式）
// ════════════════════════════════════════════════════════════════

/// 设备 mix 格式描述（`GetMixFormat` 解析结果；与 `WAVEFORMATEX` 解耦，
/// 便于跨平台测试）。
#[derive(Debug, Clone, Copy)]
struct FormatDesc {
    sample_rate: u32,
    channels: u16,
    bits_per_sample: u16,
    is_float: bool,
}

impl FormatDesc {
    /// 每帧字节数（block align）。
    fn block_align(&self) -> usize {
        (self.channels.max(1) as usize) * (self.bits_per_sample as usize).max(8) / 8
    }
}

/// 每次 20ms 数据块对应设备端帧数（48000 → 960；44100 → 882；96000 → 1920）。
///
/// 时间轴对齐的关键：无论设备采样率，每个 20ms 输入块恰好写出 20ms 输出。
fn frames_per_chunk(device_rate: u32) -> usize {
    if device_rate == 0 {
        FRAME_SAMPLES
    } else {
        ((FRAME_SAMPLES as u64) * (device_rate as u64) / (SAMPLE_RATE as u64)) as usize
    }
}

/// 把目标帧（48000Hz/stereo/float32 interleaved，`FRAME_INTERLEAVED` 样本）
/// 转成设备 mix 格式字节（声道映射 + 采样率重采样 + 位深转换）。
///
/// 返回长度 = `frames_per_chunk(device_rate)` × `block_align`（不足由调用方
/// 零填充兜底）。
fn frame_to_mix_bytes(pcm: &[f32], fmt: &FormatDesc) -> Vec<u8> {
    if pcm.len() < 2 {
        return Vec::new();
    }
    // 1. 采样率适配（48000 → mix rate；重采样保持 interleaved 帧对）。
    let stereo: Vec<f32> = if fmt.sample_rate == SAMPLE_RATE {
        pcm.to_vec()
    } else if fmt.sample_rate == 0 {
        pcm.to_vec() // 防御。
    } else {
        linear_resample(pcm, SAMPLE_RATE, fmt.sample_rate)
    };
    let frames = stereo.len() / 2;

    // 2. 声道映射：2 → 直通；1 → (L+R)/2 下混；>2 → L/R 填前两槽、其余 0。
    let ch = fmt.channels.max(1) as usize;
    let mut mixed = Vec::with_capacity(frames * ch);
    for f in 0..frames {
        let l = stereo[f * 2];
        let r = stereo[f * 2 + 1];
        for c in 0..ch {
            mixed.push(match (ch, c) {
                // mono：L/R 等权下混（避免单侧丢失）。
                (1, 0) => (l + r) * 0.5,
                (_, 0) => l,
                (_, 1) => r,
                _ => 0.0,
            });
        }
    }

    // 3. 位深适配（float32 / S16 / S32；其余格式静音兜底，不阻断播放）。
    match (fmt.is_float, fmt.bits_per_sample) {
        (true, 32) => mixed.iter().flat_map(|s| s.to_le_bytes()).collect(),
        (false, 16) => {
            let mut b = Vec::with_capacity(mixed.len() * 2);
            for s in mixed {
                let v = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
                b.extend_from_slice(&v.to_le_bytes());
            }
            b
        }
        (false, 32) => {
            let mut b = Vec::with_capacity(mixed.len() * 4);
            for s in mixed {
                let v = (s.clamp(-1.0, 1.0) * 2147483647.0) as i32;
                b.extend_from_slice(&v.to_le_bytes());
            }
            b
        }
        // 24-bit 等少见格式：写静音兜底（避免格式错位产生爆音）。
        _ => vec![0u8; mixed.len() * 2],
    }
}

/// 立体声 interleaved 线性插值重采样（`src_rate` → `dst_rate`）。
///
/// 输出帧数 = `src_frames × dst_rate / src_rate`，与 [`frames_per_chunk`]
/// 一致，保证时间轴对齐。
fn linear_resample(stereo: &[f32], src_rate: u32, dst_rate: u32) -> Vec<f32> {
    if stereo.is_empty() || stereo.len() < 2 {
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

// ── Windows WASAPI 共享渲染 ─────────────────────────────────────
#[cfg(target_os = "windows")]
mod wasapi {
    use super::*;
    use std::collections::VecDeque;

    use windows::Win32::Foundation::S_FALSE;
    use windows::Win32::Media::Audio::{
        eConsole, eRender, IAudioClient, IAudioRenderClient, IMMDeviceEnumerator,
        MMDeviceEnumerator, AUDCLNT_SHAREMODE_SHARED, WAVEFORMATEX, WAVEFORMATEXTENSIBLE,
    };
    use windows::Win32::Media::KernelStreaming::WAVE_FORMAT_EXTENSIBLE;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_ALL,
        COINIT_MULTITHREADED,
    };

    /// `WAVE_FORMAT_IEEE_FLOAT`（= 3）。windows crate 把它放在
    /// `Win32::Media::Multimedia`（需额外 feature），故这里直接用数值常量。
    const WAVE_FORMAT_IEEE_FLOAT: u32 = 3;

    // KSDATAFORMAT_SUBTYPE_IEEE_FLOAT GUID（{00000003-0000-0010-8000-00aa00389b71}）。
    // WAVEFORMATEXTENSIBLE.SubFormat == 此值 → mix 为 float32。
    const KSDATAFORMAT_SUBTYPE_IEEE_FLOAT: windows::core::GUID =
        windows::core::GUID::from_u128(0x00000003_0000_0010_8000_00aa00389b71);

    /// 播放缓冲时长：~100ms（容纳 jitter buffer 输出；100ns 单位）。
    const BUFFER_HNS: i64 = 100 * 10_000; // 100ms

    /// WASAPI 共享渲染播放器。
    ///
    /// 创建时只做轻量校验（能否取到默认渲染端点）；真正的渲染在
    /// [`AudioPlayback::start`] spawn 的线程里进行。stop 通过原子标志通知
    /// 线程退出 + 释放 COM 资源。
    pub struct WasapiPlayback {
        /// 播放线程退出标志。
        stop_flag: Arc<AtomicBool>,
        /// 播放线程句柄（start 后才有）。
        thread: Option<thread::JoinHandle<()>>,
    }

    impl WasapiPlayback {
        /// 创建：探测默认渲染端点是否可达（不启动播放）。
        ///
        /// 无声卡 / 无默认渲染端点 → `Err(InitFailed)`。
        pub fn new() -> Result<Self, DecodeError> {
            // 探测：能否 CoCreate IMMDeviceEnumerator + GetDefaultAudioEndpoint。
            // 在 MTA 初始化（临时，探测完 Uninitialize）。
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            // S_OK(0) / S_FALSE(1, 已初始化) 都可继续；失败才报错。
            let co_init_ok = hr.is_ok() || hr == S_FALSE;
            let probe = if co_init_ok {
                probe_default_endpoint()
            } else {
                Err(DecodeError::InitFailed(format!("CoInitializeEx: {hr}")))
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

    impl AudioPlayback for WasapiPlayback {
        fn start(&mut self, src: mpsc::Receiver<AudioPcm>) -> Result<(), DecodeError> {
            if self.thread.is_some() {
                return Ok(()); // 幂等。
            }
            self.stop_flag.store(false, Ordering::SeqCst);
            let stop_flag = self.stop_flag.clone();
            let handle = thread::Builder::new()
                .name("kirin-audio-render".into())
                .spawn(move || {
                    run_render_loop(stop_flag, src);
                })
                .map_err(|e| DecodeError::InitFailed(format!("spawn playback thread: {e}")))?;
            self.thread = Some(handle);
            Ok(())
        }

        fn stop(&mut self) {
            self.stop_flag.store(true, Ordering::SeqCst);
            if let Some(h) = self.thread.take() {
                // 不阻塞 join 过久：播放线程在 ≤5ms 轮询间隔内观察标志退出。
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

    impl Drop for WasapiPlayback {
        fn drop(&mut self) {
            self.stop();
        }
    }

    /// 探测默认渲染端点（临时 COM 上下文里）。
    fn probe_default_endpoint() -> Result<(), DecodeError> {
        let enumerator: IMMDeviceEnumerator =
            unsafe { CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL) }.map_err(|e| {
                DecodeError::InitFailed(format!("CoCreateInstance(MMDeviceEnumerator): {e}"))
            })?;
        let dev =
            unsafe { enumerator.GetDefaultAudioEndpoint(eRender, eConsole) }.map_err(|e| {
                DecodeError::InitFailed(format!("GetDefaultAudioEndpoint(eRender): {e}"))
            })?;
        // 确认能 Activate IAudioClient。
        let _client: IAudioClient = unsafe { dev.Activate::<IAudioClient>(CLSCTX_ALL, None) }
            .map_err(|e| {
                DecodeError::InitFailed(format!("IMMDevice::Activate(IAudioClient): {e}"))
            })?;
        Ok(())
    }

    /// 播放线程主循环：建 COM → enumerator → device → client → initialize
    /// (shared render) → render client → Start → 循环写帧 → Stop。
    fn run_render_loop(stop_flag: Arc<AtomicBool>, rx: mpsc::Receiver<AudioPcm>) {
        // 线程私有 COM 上下文（MTA）。
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let co_inited = hr == windows::Win32::Foundation::S_OK;
        if !hr.is_ok() && hr != S_FALSE {
            tracing::warn!("WASAPI render: CoInitializeEx failed: {hr}");
            return;
        }
        // 任何提前 return 都要 CoUninitialize。
        let _guard = CoUninitGuard { inited: co_inited };

        if let Err(e) = run_render_inner(&stop_flag, &rx) {
            tracing::warn!("WASAPI render thread exiting: {e}");
        }
        // 通道 drop（rx 离开作用域）→ 发送端 pipeline 收到 Disconnected。
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

    fn run_render_inner(
        stop_flag: &Arc<AtomicBool>,
        rx: &mpsc::Receiver<AudioPcm>,
    ) -> Result<(), DecodeError> {
        // 1. enumerator + default render endpoint。
        let enumerator: IMMDeviceEnumerator =
            unsafe { CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL) }
                .map_err(|e| DecodeError::InitFailed(format!("CoCreateInstance: {e}")))?;
        let dev = unsafe { enumerator.GetDefaultAudioEndpoint(eRender, eConsole) }
            .map_err(|e| DecodeError::InitFailed(format!("GetDefaultAudioEndpoint: {e}")))?;

        // 2. Activate IAudioClient。
        let client: IAudioClient = unsafe { dev.Activate::<IAudioClient>(CLSCTX_ALL, None) }
            .map_err(|e| DecodeError::InitFailed(format!("Activate(IAudioClient): {e}")))?;

        // 3. GetMixFormat（共享渲染用系统 mix format 最稳）。
        let mix_ptr: *mut WAVEFORMATEX = unsafe { client.GetMixFormat() }
            .map_err(|e| DecodeError::InitFailed(format!("GetMixFormat: {e}")))?;
        if mix_ptr.is_null() {
            return Err(DecodeError::InitFailed("GetMixFormat returned null".into()));
        }
        let fmt = parse_format(mix_ptr);

        // 4. Initialize（共享渲染 + ~100ms 缓冲）。
        // hnsPeriodicity = 0（共享模式必须 0）。
        let init_res = unsafe {
            client.Initialize(
                AUDCLNT_SHAREMODE_SHARED,
                0, // streamflags：共享渲染无特殊标志（0.62 中为裸 u32）。
                BUFFER_HNS,
                0,
                mix_ptr,
                None,
            )
        };
        // mix_ptr 不再需要，释放（GetMixFormat 分配的需 CoTaskMemFree）。
        unsafe { CoTaskMemFree(Some(mix_ptr as *const _)) };
        init_res.map_err(|e| {
            DecodeError::InitFailed(format!("IAudioClient::Initialize(shared): {e}"))
        })?;

        // 5. GetService IAudioRenderClient + 缓冲帧数。
        let render: IAudioRenderClient = unsafe { client.GetService::<IAudioRenderClient>() }
            .map_err(|e| DecodeError::InitFailed(format!("GetService(IAudioRenderClient): {e}")))?;
        let buf_frames = unsafe { client.GetBufferSize() }
            .map_err(|e| DecodeError::InitFailed(format!("GetBufferSize: {e}")))?
            as usize;
        unsafe { client.Start() }
            .map_err(|e| DecodeError::InitFailed(format!("IAudioClient::Start: {e}")))?;

        tracing::info!(
            "WASAPI shared render started: mix={}Hz/{}ch/{}bit float={} (buffer {} frames)",
            fmt.sample_rate,
            fmt.channels,
            fmt.bits_per_sample,
            fmt.is_float,
            buf_frames
        );

        // 6. 渲染循环：drain rx → 写帧（数据/静音）→ 轮询间隔 5ms。
        let chunk_frames = frames_per_chunk(fmt.sample_rate).max(1);
        let mut pending: VecDeque<f32> = VecDeque::with_capacity(FRAME_INTERLEAVED * 8);
        while !stop_flag.load(Ordering::SeqCst) {
            // 6a. 消费通道（已 jitter buffer 排序的 20ms 帧）。
            while let Ok(pcm) = rx.try_recv() {
                pending.extend(pcm.samples);
            }
            // 6b. 缓冲溢出防御（消费过慢）→ 丢最旧帧，不阻塞 jitter buffer。
            while pending.len() > FRAME_INTERLEAVED * 8 {
                pending.drain(..FRAME_INTERLEAVED);
            }
            // 6c. 计算可写帧数（GetCurrentPadding → 剩余可写）。
            let padding = unsafe { client.GetCurrentPadding() }
                .map_err(|e| DecodeError::InitFailed(format!("GetCurrentPadding: {e}")))?
                as usize;
            let mut writable = buf_frames.saturating_sub(padding);

            // 6d. 写数据帧（整块 20ms）。
            while writable >= chunk_frames && pending.len() >= FRAME_INTERLEAVED {
                let frame: Vec<f32> = pending.drain(..FRAME_INTERLEAVED).collect();
                write_frame(&render, &frame, chunk_frames, &fmt)?;
                writable -= chunk_frames;
            }
            // 6e. 数据不足 → 写静音（保持时间轴连续，避免 underrun 咔哒声；
            //     首个音频包到达前同样由静音预热）。
            while writable >= chunk_frames && pending.len() < FRAME_INTERLEAVED {
                write_frame(&render, &[], chunk_frames, &fmt)?;
                writable -= chunk_frames;
            }

            thread::sleep(Duration::from_millis(5));
        }

        // 7. 停止：Stop（不 Reset，避免丢缓冲）。render/client 经 COM Release
        //    自动释放。
        let _ = unsafe { client.Stop() };
        let _ = render;
        let _ = client;
        Ok(())
    }

    /// 写一个 20ms 数据块到设备缓冲。
    ///
    /// `samples` 为空 → 静音块。`chunk_frames` = 设备端帧数
    /// （[`frames_per_chunk`]，保证时间轴对齐）。
    fn write_frame(
        render: &IAudioRenderClient,
        samples: &[f32],
        chunk_frames: usize,
        fmt: &FormatDesc,
    ) -> Result<(), DecodeError> {
        // 0.62 中 GetBuffer 直接返回缓冲指针（非 out-param）。
        let data = unsafe { render.GetBuffer(chunk_frames as u32) }
            .map_err(|e| DecodeError::InitFailed(format!("GetBuffer: {e}")))?;
        if data.is_null() {
            return Err(DecodeError::InitFailed(
                "IAudioRenderClient::GetBuffer returned null".into(),
            ));
        }
        // 48000/stereo/float32 → mix 格式字节。
        let bytes = frame_to_mix_bytes(samples, fmt);
        let block = fmt.block_align().max(1);
        let total = chunk_frames * block;
        // 拷贝（可能小于整块——重采样余量/静音），剩余补零。
        let n = bytes.len().min(total);
        if n > 0 {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), data, n) };
        }
        if total > n {
            unsafe { std::ptr::write_bytes(data.add(n), 0u8, total - n) };
        }
        // dwflags=0：数据已写入（含静音零填充），无需 SILENT 标记。
        unsafe { render.ReleaseBuffer(chunk_frames as u32, 0) }
            .map_err(|e| DecodeError::InitFailed(format!("ReleaseBuffer: {e}")))?;
        Ok(())
    }

    /// 解析 WAVEFORMATEX（含 extensible 子格式判定 float32）。
    fn parse_format(p: *const WAVEFORMATEX) -> FormatDesc {
        unsafe {
            let w = &*p;
            let (is_float, real_channels, real_rate, real_bits) =
                if w.wFormatTag as u32 == WAVE_FORMAT_EXTENSIBLE {
                    // WAVEFORMATEXTENSIBLE 紧跟 WAVEFORMATEX；其为 packed 结构，
                    // SubFormat 字段需经 read_unaligned 读取（避免 misaligned
                    // reference UB）。
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
}

#[cfg(target_os = "windows")]
pub use wasapi::WasapiPlayback;

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── 格式适配（平台无关） ────────────────────────────────────

    fn fmt_48000_stereo_f32() -> FormatDesc {
        FormatDesc {
            sample_rate: 48000,
            channels: 2,
            bits_per_sample: 32,
            is_float: true,
        }
    }

    /// 48000/stereo/float32 → 字节直通（现代 Windows 默认 mix 格式）。
    #[test]
    fn test_convert_float32_identity() {
        let fmt = fmt_48000_stereo_f32();
        let pcm: Vec<f32> = (0..FRAME_INTERLEAVED).map(|i| (i as f32) * 0.001).collect();
        let bytes = frame_to_mix_bytes(&pcm, &fmt);
        assert_eq!(bytes.len(), FRAME_INTERLEAVED * 4, "1920 floats × 4B");
        for (i, b) in bytes.chunks_exact(4).enumerate() {
            assert_eq!(f32::from_le_bytes([b[0], b[1], b[2], b[3]]), pcm[i]);
        }
        // 帧数对齐：960 设备帧。
        assert_eq!(frames_per_chunk(48000), FRAME_SAMPLES);
    }

    /// 48000/stereo → 44100：每块 882 帧，时间轴对齐（20ms @44100）。
    #[test]
    fn test_convert_resample_44100() {
        let fmt = FormatDesc {
            sample_rate: 44100,
            channels: 2,
            bits_per_sample: 32,
            is_float: true,
        };
        let pcm = vec![0.0f32; FRAME_INTERLEAVED];
        let bytes = frame_to_mix_bytes(&pcm, &fmt);
        // 960 × 44100/48000 = 882 帧 × 4B × 2ch。
        assert_eq!(bytes.len(), 882 * 2 * 4);
        assert_eq!(frames_per_chunk(44100), 882);
    }

    /// 48000/stereo → S16：位深转换，值域钳位到 [-1, 1]。
    #[test]
    fn test_convert_s16() {
        let fmt = FormatDesc {
            sample_rate: 48000,
            channels: 2,
            bits_per_sample: 16,
            is_float: false,
        };
        // 幅值 ≤ 1.0（超过会触发钳位，见下个用例）。
        let pcm: Vec<f32> = (0..FRAME_INTERLEAVED)
            .map(|i| (i as f32) * 0.0005)
            .collect();
        let bytes = frame_to_mix_bytes(&pcm, &fmt);
        assert_eq!(bytes.len(), FRAME_INTERLEAVED * 2);
        for (i, b) in bytes.chunks_exact(2).enumerate() {
            let v = i16::from_le_bytes([b[0], b[1]]) as f32 / 32767.0;
            assert!((v - pcm[i]).abs() < 0.001, "S16 conversion mismatch at {i}");
        }
    }

    /// S16 转换对超出 [-1,1] 的样本钳位（不产生环绕爆音）。
    #[test]
    fn test_convert_s16_clamps() {
        let fmt = FormatDesc {
            sample_rate: 48000,
            channels: 2,
            bits_per_sample: 16,
            is_float: false,
        };
        let pcm = vec![5.0f32; FRAME_INTERLEAVED]; // 远超上限。
        let bytes = frame_to_mix_bytes(&pcm, &fmt);
        let v = i16::from_le_bytes([bytes[0], bytes[1]]) as f32 / 32767.0;
        assert!((v - 1.0).abs() < 0.001, "S16 must clamp to 1.0, got {v}");
    }

    /// 48000/stereo → mono：下混 (L+R)/2。
    #[test]
    fn test_convert_mono_downmix() {
        let fmt = FormatDesc {
            sample_rate: 48000,
            channels: 1,
            bits_per_sample: 32,
            is_float: true,
        };
        let pcm: Vec<f32> = (0..FRAME_INTERLEAVED).map(|i| i as f32).collect();
        let bytes = frame_to_mix_bytes(&pcm, &fmt);
        assert_eq!(bytes.len(), FRAME_SAMPLES * 4, "960 mono frames × 4B");
        for (i, b) in bytes.chunks_exact(4).enumerate() {
            let v = f32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let expect = (pcm[i * 2] + pcm[i * 2 + 1]) / 2.0;
            assert!((v - expect).abs() < 1e-4, "mono downmix mismatch at {i}");
        }
    }

    /// 48000/stereo → 5.1（6ch）：L/R 填前两槽，其余 0。
    #[test]
    fn test_convert_multi_channel() {
        let fmt = FormatDesc {
            sample_rate: 48000,
            channels: 6,
            bits_per_sample: 32,
            is_float: true,
        };
        let pcm: Vec<f32> = (0..FRAME_INTERLEAVED).map(|i| i as f32).collect();
        let bytes = frame_to_mix_bytes(&pcm, &fmt);
        assert_eq!(bytes.len(), FRAME_SAMPLES * 6 * 4);
        for f in 0..FRAME_SAMPLES {
            let base = f * 6 * 4;
            let l = f32::from_le_bytes(bytes[base..base + 4].try_into().unwrap());
            let r = f32::from_le_bytes(bytes[base + 4..base + 8].try_into().unwrap());
            let c = f32::from_le_bytes(bytes[base + 8..base + 12].try_into().unwrap());
            assert!((l - pcm[f * 2]).abs() < 1e-4, "FL = L");
            assert!((r - pcm[f * 2 + 1]).abs() < 1e-4, "FR = R");
            assert_eq!(c, 0.0, "FC = 0");
        }
    }

    // ── WASAPI 播放（Windows） ──────────────────────────────────

    /// 真实设备 1 秒播放（静音帧）→ 无报错（Windows 环境；无设备 skip）。
    #[cfg(target_os = "windows")]
    #[test]
    fn test_wasapi_playback_smoke() {
        let mut pb = match WasapiPlayback::new() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("no playback device: {e}; test_wasapi_playback_smoke skipped");
                return;
            }
        };
        let (tx, rx) = mpsc::channel::<AudioPcm>();
        if let Err(e) = pb.start(rx) {
            eprintln!("start failed: {e}; skipped");
            return;
        }
        // 1 秒静音帧（50 × 20ms）——无 audible 声音。
        for i in 0..50u64 {
            let pcm = AudioPcm {
                pts: i * 20,
                samples: vec![0.0f32; FRAME_INTERLEAVED],
            };
            let _ = tx.send(pcm);
        }
        thread::sleep(Duration::from_millis(1200));
        pb.stop();
        assert_eq!(pb.sample_rate(), 48_000);
        assert_eq!(pb.channels(), 2);
    }

    /// 无设备 → Err(InitFailed)，不 panic。
    #[cfg(target_os = "windows")]
    #[test]
    fn test_playback_no_device() {
        // 无法强制「无设备」，仅验证 create_default_playback 不 panic；
        // 真实无设备场景在集成测试覆盖。
        let _ = create_default_playback();
    }

    /// Drop 后无泄漏/无残留线程（stop 幂等，join 不阻塞）。
    #[cfg(target_os = "windows")]
    #[test]
    fn test_playback_drop_stops() {
        let mut pb = match WasapiPlayback::new() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("no playback device: {e}; test_playback_drop_stops skipped");
                return;
            }
        };
        let (_tx, rx) = mpsc::channel::<AudioPcm>();
        let _ = pb.start(rx);
        pb.stop(); // 幂等。
        pb.stop();
        drop(pb); // Drop 路径再 stop（已停，不 hang）。
    }
}
