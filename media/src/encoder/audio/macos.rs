//! macOS CoreAudio 环回捕获（M12-MAC MAC-T003，P1D-mac 阶段补全）。
//!
//! 系统声音环回：AudioUnit（`kAudioUnitType_Output` / `kAudioUnitSubType_HALOutput`）
//! 挂默认输出设备（`kAudioHardwarePropertyDefaultOutputDevice`）的输入侧，捕获
//! 系统正在播放的 PCM。产出 **interleaved stereo float32**（48000Hz），与
//! [`AudioPcm`] 契约一致（P1D：float32 优先，Opus 编码侧 deinterleave）。
//!
//! # FFI 方式（架构红线：dlopen，不静态链接系统框架）
//!
//! `libloading` 动态加载：
//! - `/System/Library/Frameworks/CoreAudio.framework/CoreAudio`（AudioObject*）
//! - `/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox`（AudioUnit*）
//!
//! # 线程模型（与 WASAPI 后端对称）
//!
//! [`AudioCapture::start`] 启动捕获线程：初始化 AudioUnit → 注册 render 回调 →
//! `AudioOutputUnitStart` → 轮询 stop_flag（50ms）→ 退出前 stop + uninitialize +
//! dispose。render 回调运行在音频实时线程，经 `inRefCon` 访问捕获线程栈上的
//! `CaptureCtx`（生命周期安全：线程退出前先停 unit，停后回调不再触发，见
//! [`run_capture_loop`] 的清理顺序注释）。
//!
//! # 权限
//!
//! 捕获系统输出音频无需 TCC 权限（与麦克风 `NSMicrophoneUsageDescription` 无关，
//! 但 Info.plist 仍声明该项以备后续输入设备捕获，见 M14-T004 补充字段）。

#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::OnceLock;
use std::thread;

use libloading::{Library, Symbol};

use crate::encoder::audio::{AudioCapture, AudioPcm, CHANNELS, SAMPLE_RATE};
use crate::encoder::types::Timestamp;
use crate::encoder::video::EncodeError;

// ════════════════════════════════════════════════════════════════
// 常量（与 <AudioToolbox/AudioUnitProperties.h> / <CoreAudio/AudioHardware.h> 对齐）
// ════════════════════════════════════════════════════════════════

/// 系统 framework 路径。
const CORE_AUDIO_FW: &str = "/System/Library/Frameworks/CoreAudio.framework/CoreAudio";
const AUDIO_TOOLBOX_FW: &str =
    "/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox";

/// FourCC 组件/属性常量（'abcd' 大端字节序 → u32）。
pub mod fourcc {
    /// kAudioUnitType_Output = 'auou'
    pub const UNIT_TYPE_OUTPUT: u32 = 0x6175_6F75;
    /// kAudioUnitSubType_HALOutput = 'ahal'
    pub const UNIT_SUBTYPE_HAL_OUTPUT: u32 = 0x6168_616C;
    /// kAudioUnitManufacturer_Apple = 'appl'
    pub const MANUFACTURER_APPLE: u32 = 0x6170_706C;
    /// kAudioOutputUnitProperty_EnableIO = 'enab'
    pub const PROP_ENABLE_IO: u32 = 0x656E_6162;
    /// kAudioOutputUnitProperty_CurrentDevice = 'cdev'
    pub const PROP_CURRENT_DEVICE: u32 = 0x6364_6576;
    /// kAudioUnitProperty_StreamFormat = 'asbd'
    pub const PROP_STREAM_FORMAT: u32 = 0x6173_6264;
    /// kAudioUnitProperty_SetRenderCallback = 'srcb'
    pub const PROP_SET_RENDER_CALLBACK: u32 = 0x7372_6362;
    /// kAudioHardwarePropertyDefaultOutputDevice = 'dOut'
    pub const HW_PROP_DEFAULT_OUTPUT_DEVICE: u32 = 0x644F_7574;
    /// kAudioObjectPropertyScopeGlobal = 'glob'
    pub const SCOPE_GLOBAL: u32 = 0x676C_6F62;
    /// kAudioFormatLinearPCM = 'lpcm'
    pub const FORMAT_LINEAR_PCM: u32 = 0x6C70_636D;
}

/// kAudioUnitScope_Global / Input / Output。
pub mod unit_scope {
    pub const GLOBAL: u32 = 0;
    pub const INPUT: u32 = 1;
    pub const OUTPUT: u32 = 2;
}

/// kAudioObjectSystemObject（默认输出设备查询入口）。
pub const SYSTEM_OBJECT: u32 = 1;
/// kAudioObjectPropertyElementMain。
pub const ELEMENT_MAIN: u32 = 0;

/// kAudioFormatFlags（线性 PCM 子标志）。
pub mod fmt_flags {
    pub const IS_FLOAT: u32 = 1 << 0;
    pub const NATIVE_ENDIAN: u32 = 1 << 12;
    pub const IS_NON_INTERLEAVED: u32 = 1 << 6;
}

/// noErr。
pub const NOERR: i32 = 0;

/// 捕获线程轮询 stop_flag 的间隔。
const POLL_MS: u64 = 50;

// ════════════════════════════════════════════════════════════════
// C 结构体（repr(C)，仅 ABI 传递用；AudioTimeStamp 不透明，不 deref）
// ════════════════════════════════════════════════════════════════

/// AudioStreamBasicDescription（40 字节）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AudioStreamBasicDescription {
    pub m_sample_rate: f64,
    pub m_format_id: u32,
    pub m_format_flags: u32,
    pub m_bytes_per_packet: u32,
    pub m_frames_per_packet: u32,
    pub m_bytes_per_frame: u32,
    pub m_channels_per_frame: u32,
    pub m_bits_per_channel: u32,
    pub m_reserved: u32,
}

impl AudioStreamBasicDescription {
    /// 48000Hz / 2ch / float32 非交织（AudioUnit render 回调的规范输入格式）。
    pub const fn pcm_float32_non_interleaved(sample_rate: f64, channels: u32) -> Self {
        Self {
            m_sample_rate: sample_rate,
            m_format_id: fourcc::FORMAT_LINEAR_PCM,
            m_format_flags: fmt_flags::IS_FLOAT | fmt_flags::NATIVE_ENDIAN | fmt_flags::IS_NON_INTERLEAVED,
            // 非交织 float32：每包 1 帧、每帧 4 字节（单声道视角）。
            m_bytes_per_packet: 4,
            m_frames_per_packet: 1,
            m_bytes_per_frame: 4,
            m_channels_per_frame: channels,
            m_bits_per_channel: 32,
            m_reserved: 0,
        }
    }
}

/// AudioComponentDescription（20 字节）。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AudioComponentDescription {
    pub component_type: u32,
    pub component_subtype: u32,
    pub component_manufacturer: u32,
    pub component_flags: u32,
    pub component_flags_mask: u32,
}

/// AudioBuffer（16 字节，64 位：3×u32 + padding + 指针）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AudioBuffer {
    pub m_number_channels: u32,
    pub m_data_byte_size: u32,
    pub m_data: *mut c_void,
}

/// AudioBufferList（24 字节，64 位：u32 + padding + AudioBuffer[1]）。
#[repr(C)]
pub struct AudioBufferList {
    pub m_number_buffers: u32,
    pub m_buffers: [AudioBuffer; 1],
}

/// AURenderCallbackStruct（16 字节：函数指针 + refCon）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AURenderCallbackStruct {
    pub input_proc: Option<AudioRenderCallback>,
    pub input_proc_ref_con: *mut c_void,
}

/// AudioObjectPropertyAddress（12 字节）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AudioObjectPropertyAddress {
    pub m_selector: u32,
    pub m_scope: u32,
    pub m_element: u32,
}

// ════════════════════════════════════════════════════════════════
// FFI 函数指针表（dlopen 解析一次，进程内常驻）
// ════════════════════════════════════════════════════════════════

/// AudioUnit render 回调（音频实时线程调用）。
pub type AudioRenderCallback = unsafe extern "C" fn(
    in_ref_con: *mut c_void,
    io_action_flags: *mut u32,
    in_time_stamp: *const c_void, // AudioTimeStamp（不透明）
    in_bus_number: u32,
    in_number_frames: u32,
    io_data: *mut AudioBufferList,
) -> i32;

type AudioComponentFindNextFn = unsafe extern "C" fn(
    in_component: *mut c_void,
    in_desc: *const AudioComponentDescription,
) -> *mut c_void;
type AudioComponentInstanceNewFn =
    unsafe extern "C" fn(in_component: *mut c_void, out_instance: *mut *mut c_void) -> i32;
type AudioComponentInstanceDisposeFn = unsafe extern "C" fn(in_instance: *mut c_void) -> i32;
type AudioUnitInitializeFn = unsafe extern "C" fn(in_unit: *mut c_void) -> i32;
type AudioUnitUninitializeFn = unsafe extern "C" fn(in_unit: *mut c_void) -> i32;
type AudioUnitSetPropertyFn = unsafe extern "C" fn(
    in_unit: *mut c_void,
    in_id: u32,
    in_scope: u32,
    in_element: u32,
    in_data: *const c_void,
    in_data_size: u32,
) -> i32;
type AudioOutputUnitStartFn = unsafe extern "C" fn(in_unit: *mut c_void) -> i32;
type AudioOutputUnitStopFn = unsafe extern "C" fn(in_unit: *mut c_void) -> i32;
type AudioObjectGetPropertyDataFn = unsafe extern "C" fn(
    in_object_id: u32,
    in_address: *const AudioObjectPropertyAddress,
    in_qualifier_data_size: u32,
    in_qualifier_data: *const c_void,
    io_data_size: *mut u32,
    out_data: *mut c_void,
) -> i32;

/// 已解析的 CoreAudio/AudioToolbox 函数表。
struct CoreAudioDlls {
    _core_audio: Library,
    _audio_toolbox: Library,
    audio_component_find_next: AudioComponentFindNextFn,
    audio_component_instance_new: AudioComponentInstanceNewFn,
    audio_component_instance_dispose: AudioComponentInstanceDisposeFn,
    audio_unit_initialize: AudioUnitInitializeFn,
    audio_unit_uninitialize: AudioUnitUninitializeFn,
    audio_unit_set_property: AudioUnitSetPropertyFn,
    audio_output_unit_start: AudioOutputUnitStartFn,
    audio_output_unit_stop: AudioOutputUnitStopFn,
    audio_object_get_property_data: AudioObjectGetPropertyDataFn,
}

static CORE_AUDIO: OnceLock<Result<CoreAudioDlls, String>> = OnceLock::new();

impl CoreAudioDlls {
    fn get() -> Result<&'static CoreAudioDlls, EncodeError> {
        CORE_AUDIO
            .get_or_init(Self::load)
            .as_ref()
            .map_err(|e| EncodeError::InitFailed(format!("CoreAudio dlopen: {e}")))
    }

    fn load() -> Result<Self, String> {
        // SAFETY: 系统固定路径，加载后仅 dlsym 取符号。
        let core_audio = unsafe { Library::new(CORE_AUDIO_FW) }
            .map_err(|e| format!("dlopen CoreAudio: {e}"))?;
        let audio_toolbox = unsafe { Library::new(AUDIO_TOOLBOX_FW) }
            .map_err(|e| format!("dlopen AudioToolbox: {e}"))?;

        macro_rules! sym {
            ($lib:expr, $name:literal, $ty:ty) => {
                // SAFETY: 符号名与类型均来自 AudioUnit / AudioHardware 头文件。
                unsafe { $lib.get::<$ty>($name.as_bytes()) }
                    .map(|s: Symbol<'_, $ty>| *s)
                    .map_err(|e| format!("symbol '$name': {e}"))? as $ty
            };
        }

        Ok(Self {
            audio_component_find_next: sym!(
                &audio_toolbox,
                "AudioComponentFindNext",
                AudioComponentFindNextFn
            ),
            audio_component_instance_new: sym!(
                &audio_toolbox,
                "AudioComponentInstanceNew",
                AudioComponentInstanceNewFn
            ),
            audio_component_instance_dispose: sym!(
                &audio_toolbox,
                "AudioComponentInstanceDispose",
                AudioComponentInstanceDisposeFn
            ),
            audio_unit_initialize: sym!(
                &audio_toolbox,
                "AudioUnitInitialize",
                AudioUnitInitializeFn
            ),
            audio_unit_uninitialize: sym!(
                &audio_toolbox,
                "AudioUnitUninitialize",
                AudioUnitUninitializeFn
            ),
            audio_unit_set_property: sym!(
                &audio_toolbox,
                "AudioUnitSetProperty",
                AudioUnitSetPropertyFn
            ),
            audio_output_unit_start: sym!(
                &audio_toolbox,
                "AudioOutputUnitStart",
                AudioOutputUnitStartFn
            ),
            audio_output_unit_stop: sym!(
                &audio_toolbox,
                "AudioOutputUnitStop",
                AudioOutputUnitStopFn
            ),
            audio_object_get_property_data: sym!(
                &core_audio,
                "AudioObjectGetPropertyData",
                AudioObjectGetPropertyDataFn
            ),
            _core_audio: core_audio,
            _audio_toolbox: audio_toolbox,
        })
    }

    /// 查询默认输出设备 id（AudioDeviceID = u32）。
    fn default_output_device(&self) -> Result<u32, EncodeError> {
        let address = AudioObjectPropertyAddress {
            m_selector: fourcc::HW_PROP_DEFAULT_OUTPUT_DEVICE,
            m_scope: fourcc::SCOPE_GLOBAL,
            m_element: ELEMENT_MAIN,
        };
        let mut device_id: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        // SAFETY: 查询 kAudioObjectSystemObject 的属性，输出槽 4 字节。
        let status = unsafe {
            (self.audio_object_get_property_data)(
                SYSTEM_OBJECT,
                &address,
                0,
                std::ptr::null(),
                &mut size,
                &mut device_id as *mut u32 as *mut c_void,
            )
        };
        if status != NOERR {
            return Err(EncodeError::InitFailed(format!(
                "AudioObjectGetPropertyData(default output device): OSStatus={status}"
            )));
        }
        if device_id == 0 {
            return Err(EncodeError::InitFailed(
                "no default output audio device (kAudioObjectUnknown)".into(),
            ));
        }
        Ok(device_id)
    }
}

// ════════════════════════════════════════════════════════════════
// CaptureCtx — render 回调共享状态（捕获线程栈上，见线程模型注释）
// ════════════════════════════════════════════════════════════════

/// render 回调上下文：把非交织 float32 平面合并为 interleaved 后推送。
///
/// `pending` 预分配复用（回调高频触发，避免实时线程反复分配）。
struct CaptureCtx {
    sink: mpsc::Sender<AudioPcm>,
    /// 复用缓冲（interleaved float32，容量对齐一个回调的帧数）。
    pending: Vec<f32>,
}

impl CaptureCtx {
    fn new(sink: mpsc::Sender<AudioPcm>) -> Self {
        // 默认回调缓冲 512 帧（@48k ≈ 10.7ms）或 1024 帧；预分配 4096 个样本
        // （2048 帧 stereo）足够，超出按需扩容（异常缓冲大小一次）。
        Self {
            sink,
            pending: Vec::with_capacity(4096),
        }
    }

    /// 把回调的 `ioData` 转 interleaved float32 并推送。
    ///
    /// - 非交织（2 个 buffer）：L 平面 + R 平面交替。
    /// - 单 buffer（防御）：按交织处理。
    fn push(&mut self, io_data: *mut AudioBufferList, frames: u32) {
        // SAFETY: ioData 由 AudioUnit 在回调期间保证有效。
        let list = unsafe { &*io_data };
        let nbuf = list.m_number_buffers;
        let mut out = std::mem::take(&mut self.pending);

        if nbuf >= 2 {
            // SAFETY: 非交织布局下 buffer[i] 为该声道平面。
            let l = unsafe { &list.m_buffers[0] };
            let r = unsafe { &list.m_buffers[1] };
            let l_data = l.m_data as *const f32;
            let r_data = r.m_data as *const f32;
            if !l_data.is_null() && !r_data.is_null() {
                let n = frames as usize;
                out.clear();
                out.reserve(n * 2);
                for i in 0..n {
                    // SAFETY: 平面长度 ≥ frames（由设备按流格式提供）。
                    unsafe {
                        out.push(*l_data.add(i));
                        out.push(*r_data.add(i));
                    }
                }
            }
        } else if nbuf == 1 {
            // 防御：单 buffer 交织（格式设置失败时）。
            // SAFETY: 单 buffer 布局，数据按交织读取。
            let buf = unsafe { &list.m_buffers[0] };
            let data = buf.m_data as *const f32;
            let bytes = buf.m_data_byte_size as usize;
            if !data.is_null() {
                let n = (bytes / 4).min(frames as usize * 2);
                out.clear();
                out.reserve(n);
                for i in 0..n {
                    unsafe { out.push(*data.add(i)) };
                }
            }
        } else {
            tracing::warn!("CoreAudio render callback: unexpected buffer count {nbuf}");
        }

        if !out.is_empty() {
            let _ = self.sink.send(AudioPcm {
                ts: Timestamp::now(),
                data: std::mem::take(&mut out),
            });
        }
        self.pending = out;
    }
}

/// AudioUnit render 回调（音频实时线程）。
///
/// 只做拷贝 + channel send，不分配/不锁/不日志（实时安全）。错误静默
/// （发送失败 = 消费者已退出，丢弃该帧）。
unsafe extern "C" fn audio_render_callback(
    in_ref_con: *mut c_void,
    _io_action_flags: *mut u32,
    _in_time_stamp: *const c_void,
    _in_bus_number: u32,
    in_number_frames: u32,
    io_data: *mut AudioBufferList,
) -> i32 {
    if in_ref_con.is_null() || io_data.is_null() {
        return NOERR;
    }
    // SAFETY: inRefCon 指向捕获线程栈上的 CaptureCtx（生命周期由 run_capture_loop
    // 的清理顺序保证：停 unit 后回调不再触发，线程才退出）。
    let ctx = &mut *(in_ref_con as *mut CaptureCtx);
    ctx.push(io_data, in_number_frames);
    NOERR
}

// ════════════════════════════════════════════════════════════════
// MacOsAudioCapture — AudioCapture trait 实现
// ════════════════════════════════════════════════════════════════

/// CoreAudio AudioUnit 环回捕获器（与 WASAPI 后端对称）。
pub struct MacOsAudioCapture {
    stop_flag: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MacOsAudioCapture {
    /// 创建：轻量校验（CoreAudio 可 dlopen + 默认输出设备存在），不启动捕获。
    ///
    /// 无输出设备（无声卡/被占用）→ `Err(InitFailed)`，**不影响视频/键鼠**
    /// （调用方在独立线程里创建，失败即放弃音频）。
    pub fn new() -> Result<Self, EncodeError> {
        let dlls = CoreAudioDlls::get()?;
        // 探测默认输出设备（start 时再次探测，与 WASAPI 后端同模式）。
        let _ = dlls.default_output_device()?;
        Ok(Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            thread: None,
        })
    }
}

impl AudioCapture for MacOsAudioCapture {
    fn start(&mut self, sink: mpsc::Sender<AudioPcm>) -> Result<(), EncodeError> {
        if self.thread.is_some() {
            return Ok(()); // 幂等。
        }
        self.stop_flag.store(false, Ordering::SeqCst);
        let stop_flag = self.stop_flag.clone();
        let handle = thread::Builder::new()
            .name("kirin-audio-coreaudio".into())
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
            // 线程在 ≤50ms 轮询间隔内观察标志退出（退出前先停 unit）。
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

impl Drop for MacOsAudioCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 捕获线程主体：初始化 HALOutput 环回 → start → 轮询退出 → 逆序清理。
///
/// 清理顺序（实时回调安全的关键）：
/// `AudioOutputUnitStop`（回调不再触发）→ `AudioUnitUninitialize` →
/// `AudioComponentInstanceDispose`（unit 释放）→ 线程返回。
/// `CaptureCtx` 在线程闭包栈上，其生命周期严格覆盖 unit 使用期，无 UAF。
fn run_capture_loop(stop_flag: Arc<AtomicBool>, sink: mpsc::Sender<AudioPcm>) {
    let dlls = match CoreAudioDlls::get() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("CoreAudio unavailable: {e}; audio capture disabled");
            return;
        }
    };
    let device_id = match dlls.default_output_device() {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!("{e}; audio capture disabled");
            return;
        }
    };

    // Step 1: 找 HALOutput 组件。
    let desc = AudioComponentDescription {
        component_type: fourcc::UNIT_TYPE_OUTPUT,
        component_subtype: fourcc::UNIT_SUBTYPE_HAL_OUTPUT,
        component_manufacturer: fourcc::MANUFACTURER_APPLE,
        component_flags: 0,
        component_flags_mask: 0,
    };
    // SAFETY: desc 为栈上局部，find_next 不持有。
    let component = unsafe { (dlls.audio_component_find_next)(std::ptr::null_mut(), &desc) };
    if component.is_null() {
        tracing::warn!("AudioComponentFindNext(HALOutput) failed; audio capture disabled");
        return;
    }

    // Step 2: 创建 AudioUnit 实例。
    let mut unit: *mut c_void = std::ptr::null_mut();
    // SAFETY: unit 为输出槽。
    let status = unsafe { (dlls.audio_component_instance_new)(component, &mut unit) };
    if status != NOERR || unit.is_null() {
        tracing::warn!("AudioComponentInstanceNew: OSStatus={status}; audio capture disabled");
        return;
    }
    let unit = unit;

    // 局部清理守卫：任何后续失败都逆序释放 unit（不泄漏）。
    let mut unit_alive = true;
    macro_rules! fail {
        ($($arg:tt)*) => {{
            tracing::warn!($($arg)*);
            if unit_alive {
                unsafe { (dlls.audio_component_instance_dispose)(unit) };
                unit_alive = false;
            }
            return;
        }};
    }

    // Step 3: 启用输入侧 IO（element 1），禁用输出侧 IO（环回只捕获不播放）。
    let one: u32 = 1;
    let zero: u32 = 0;
    // SAFETY: 属性写入 4 字节标量。
    let status = unsafe {
        (dlls.audio_unit_set_property)(
            unit,
            fourcc::PROP_ENABLE_IO,
            unit_scope::INPUT,
            1,
            &one as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        )
    };
    if status != NOERR {
        fail!("AudioUnitSetProperty(EnableIO input): OSStatus={status}");
    }
    let status = unsafe {
        (dlls.audio_unit_set_property)(
            unit,
            fourcc::PROP_ENABLE_IO,
            unit_scope::OUTPUT,
            0,
            &zero as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        )
    };
    if status != NOERR {
        fail!("AudioUnitSetProperty(EnableIO output): OSStatus={status}");
    }

    // Step 4: 输入侧挂默认输出设备（系统环回）。
    let status = unsafe {
        (dlls.audio_unit_set_property)(
            unit,
            fourcc::PROP_CURRENT_DEVICE,
            unit_scope::INPUT,
            1,
            &device_id as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        )
    };
    if status != NOERR {
        fail!("AudioUnitSetProperty(CurrentDevice): OSStatus={status}");
    }

    // Step 5: 流格式 48000Hz / stereo / float32 非交织（P1D 参数，M12 一致）。
    let format = AudioStreamBasicDescription::pcm_float32_non_interleaved(SAMPLE_RATE as f64, CHANNELS as u32);
    let status = unsafe {
        (dlls.audio_unit_set_property)(
            unit,
            fourcc::PROP_STREAM_FORMAT,
            unit_scope::INPUT,
            1,
            &format as *const AudioStreamBasicDescription as *const c_void,
            std::mem::size_of::<AudioStreamBasicDescription>() as u32,
        )
    };
    if status != NOERR {
        fail!("AudioUnitSetProperty(StreamFormat): OSStatus={status}");
    }

    // Step 6: 注册 render 回调（Global scope, element 0）。
    let mut ctx = CaptureCtx::new(sink);
    let callback = AURenderCallbackStruct {
        input_proc: Some(audio_render_callback),
        input_proc_ref_con: &mut ctx as *mut CaptureCtx as *mut c_void,
    };
    let status = unsafe {
        (dlls.audio_unit_set_property)(
            unit,
            fourcc::PROP_SET_RENDER_CALLBACK,
            unit_scope::GLOBAL,
            0,
            &callback as *const AURenderCallbackStruct as *const c_void,
            std::mem::size_of::<AURenderCallbackStruct>() as u32,
        )
    };
    if status != NOERR {
        fail!("AudioUnitSetProperty(SetRenderCallback): OSStatus={status}");
    }

    // Step 7: initialize + start。
    let status = unsafe { (dlls.audio_unit_initialize)(unit) };
    if status != NOERR {
        fail!("AudioUnitInitialize: OSStatus={status}");
    }
    let status = unsafe { (dlls.audio_output_unit_start)(unit) };
    if status != NOERR {
        // 初始化失败：uninitialize + dispose。
        tracing::warn!("AudioOutputUnitStart: OSStatus={status}; audio capture disabled");
        unsafe { (dlls.audio_unit_uninitialize)(unit) };
        unsafe { (dlls.audio_component_instance_dispose)(unit) };
        return;
    }
    unit_alive = false; // 交给下方退出路径清理。
    tracing::info!("CoreAudio loopback capture started ({}Hz/stereo/float32)", SAMPLE_RATE);

    // Step 8: 轮询退出标志（回调在音频实时线程异步推送）。
    while !stop_flag.load(Ordering::SeqCst) {
        thread::sleep(std::time::Duration::from_millis(POLL_MS));
    }

    // Step 9: 逆序清理（顺序见函数头注释）。
    unsafe {
        (dlls.audio_output_unit_stop)(unit);
        (dlls.audio_unit_uninitialize)(unit);
        (dlls.audio_component_instance_dispose)(unit);
    }
    tracing::info!("CoreAudio loopback capture stopped");
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// ASBD 布局（40 字节）与 ABI 对齐；字段值正确。
    #[test]
    fn test_asbd_layout_and_values() {
        assert_eq!(std::mem::size_of::<AudioStreamBasicDescription>(), 40);
        let fmt = AudioStreamBasicDescription::pcm_float32_non_interleaved(48_000.0, 2);
        assert_eq!(fmt.m_sample_rate, 48_000.0);
        assert_eq!(fmt.m_format_id, fourcc::FORMAT_LINEAR_PCM);
        assert_ne!(fmt.m_format_flags & fmt_flags::IS_FLOAT, 0);
        assert_ne!(fmt.m_format_flags & fmt_flags::IS_NON_INTERLEAVED, 0);
        assert_eq!(fmt.m_channels_per_frame, 2);
        assert_eq!(fmt.m_bits_per_channel, 32);
    }

    /// AudioBufferList 布局（64 位：24 字节）——回调 ABI 对齐。
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn test_audiobufferlist_layout() {
        assert_eq!(std::mem::size_of::<AudioBuffer>(), 16);
        assert_eq!(std::mem::size_of::<AudioBufferList>(), 24);
        assert_eq!(std::mem::size_of::<AudioObjectPropertyAddress>(), 12);
        assert_eq!(std::mem::size_of::<AURenderCallbackStruct>(), 16);
    }

    /// FourCC 常量自检（'auou'/'ahal'/'appl'/'dOut' 等）。
    #[test]
    fn test_fourcc_constants() {
        assert_eq!(fourcc::UNIT_TYPE_OUTPUT, 0x6175_6F75);
        assert_eq!(fourcc::UNIT_SUBTYPE_HAL_OUTPUT, 0x6168_616C);
        assert_eq!(fourcc::MANUFACTURER_APPLE, 0x6170_706C);
        assert_eq!(fourcc::HW_PROP_DEFAULT_OUTPUT_DEVICE, 0x644F_7574);
        assert_eq!(fourcc::PROP_SET_RENDER_CALLBACK, 0x7372_6362);
        assert_eq!(fourcc::FORMAT_LINEAR_PCM, 0x6C70_636D);
    }
}
