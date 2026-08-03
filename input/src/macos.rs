//! macOS CGEvent 注入实现（M12-MAC MAC-T002，替代 P1E 阶段桩）。
//!
//! 实现路径（与 `共享层/M12-MAC_macOS支持.md` MAC-T002 一致）：
//! - 鼠标：`CGEventCreateMouseEvent(nil, type, CGPoint, button)` + `CGEventPost(kCGHIDEventTap)`
//! - 滚轮：`CGEventCreateScrollWheelEvent2`（`kCGScrollEventUnitPixel`）
//! - 键盘：`CGEventCreateKeyboardEvent(nil, keycode, pressed)` + 修饰键 flags
//! - 文本：`CGEventKeyboardSetUnicodeString`（UTF-16，IME 中文/粘贴路径）
//! - 权限：`AXIsProcessTrusted()`（Accessibility / TCC）；缺失 → [`InjectError::UnsupportedPlatform`]
//!   （沿用 P1E 桩契约：上游捕获并丢弃事件、不崩溃，由 UI 层引导授权）
//!
//! # FFI 方式（架构红线：dlopen，不静态链接系统框架）
//!
//! `libloading` 动态加载：
//! - `/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics`（CGEvent*）
//! - `/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation`（CFRelease）
//! - `/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices`（AXIsProcessTrusted）
//!
//! # 坐标
//!
//! 上游 [`crate::injector::InputInjector`] 已把 `ev.x/ev.y` 缩放到服务端像素空间。
//! CGEvent 使用 **point** 坐标（Retina 与像素存在 scale 因子），本模块经
//! `CGDisplayPixelsWide/High` + `CGDisplayBounds` 求每屏 scale 换算，并叠加
//! 多屏布局偏移（R-21b）：选中显示器按像素分辨率匹配（M8-T018 归一化基数
//! = 所选屏分辨率），副屏在左/上时全局坐标为负、右/下时为正
//! （[`to_global_point`]）。
//!
//! # 键码
//!
//! [`Key`] 判别式即 **HID usage code**（0x04='A' … 0x52=Up），本模块映射到
//! macOS **kVK**（虚拟键码）。修饰键（Ctrl/Shift/Alt/Super）不在 [`Key`] 枚举
//! 内，经事件 `modifiers` 位标志映射为 CGEventFlags（[`modifier_flags`]）。

use std::ffi::c_void;
use std::sync::OnceLock;

use libloading::{Library, Symbol};

#[cfg_attr(not(target_os = "macos"), allow(unused_imports))]
use crate::injector::{
    button, modifier, InjectError, InputEvent as PipeEvent, InputKind, Key, SpecialCombo,
};

// ════════════════════════════════════════════════════════════════
// 常量（与 CoreGraphics / HIToolbox 头文件对齐）
// ════════════════════════════════════════════════════════════════

/// 系统 framework 路径（dlopen 全路径，不依赖 DYLD_FRAMEWORK_PATH）。
///
/// 非 macOS 平台上为死代码（`#[cfg_attr]` 抑制警告，同 linux.rs 模式）。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const CORE_GRAPHICS_FW: &str =
    "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const CORE_FOUNDATION_FW: &str =
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const APPLICATION_SERVICES_FW: &str =
    "/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices";

/// CGEventType（kCGEvent*）。
pub mod cg_type {
    pub const LEFT_MOUSE_DOWN: i32 = 1;
    pub const LEFT_MOUSE_UP: i32 = 2;
    pub const RIGHT_MOUSE_DOWN: i32 = 3;
    pub const RIGHT_MOUSE_UP: i32 = 4;
    pub const MOUSE_MOVED: i32 = 5;
    pub const KEY_DOWN: i32 = 10;
    pub const KEY_UP: i32 = 11;
    pub const OTHER_MOUSE_DOWN: i32 = 25;
    pub const OTHER_MOUSE_UP: i32 = 26;
}

/// CGMouseButton。
pub mod cg_mouse_button {
    pub const LEFT: i32 = 0;
    pub const RIGHT: i32 = 1;
    pub const CENTER: i32 = 2;
}

/// CGEventField（kCGEvent* 字段枚举）。
pub mod cg_field {
    pub const MOUSE_EVENT_CLICK_STATE: i32 = 8;
    pub const MOUSE_EVENT_DELTA_X: i32 = 11;
    pub const MOUSE_EVENT_DELTA_Y: i32 = 12;
    pub const KEYBOARD_EVENT_AUTOREPEAT: i32 = 88;
    pub const KEYBOARD_EVENT_KEYCODE: i32 = 89;
    pub const KEYBOARD_EVENT_UNICODE_STRING: i32 = 91;
    pub const KEYBOARD_EVENT_UNICODE_STRING_LENGTH: i32 = 92;
}

/// CGEventFlags（kCGEventFlagMask*）。
pub mod cg_flags {
    pub const SHIFT: u64 = 1 << 17;
    pub const CONTROL: u64 = 1 << 18;
    pub const ALTERNATE: u64 = 1 << 19;
    pub const COMMAND: u64 = 1 << 20;
}

/// CGEventTapLocation。
pub const TAP_HID: i32 = 0; // kCGHIDEventTap
pub const TAP_SESSION: i32 = 1; // kCGSessionEventTap

/// CGScrollEventUnit。
pub const SCROLL_UNIT_PIXEL: u32 = 0; // kCGScrollEventUnitPixel

// ════════════════════════════════════════════════════════════════
// C 结构体（repr(C)，仅 ABI 传递用）
// ════════════════════════════════════════════════════════════════

/// CGPoint（64 位 macOS：两个 f64）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CGPoint {
    pub x: f64,
    pub y: f64,
}

impl CGPoint {
    pub const fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// CGSize。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CGSize {
    pub width: f64,
    pub height: f64,
}

/// CGRect。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CGRect {
    pub origin: CGPoint,
    pub size: CGSize,
}

// ════════════════════════════════════════════════════════════════
// FFI 函数指针表（dlopen 解析一次，进程内常驻）
// ════════════════════════════════════════════════════════════════

type CGEventCreateMouseEventFn = unsafe extern "C" fn(
    source: *mut c_void,
    mouse_type: i32,
    mouse_pos: CGPoint,
    mouse_button: i32,
) -> *mut c_void; // CGEventRef
type CGEventCreateScrollWheelEvent2Fn = unsafe extern "C" fn(
    source: *mut c_void,
    units: u32,
    wheel_count: u32,
    wheel1: i32,
    wheel2: i32,
    wheel3: i32,
) -> *mut c_void;
type CGEventCreateKeyboardEventFn =
    unsafe extern "C" fn(source: *mut c_void, keycode: u16, key_down: bool) -> *mut c_void;
type CGEventPostFn = unsafe extern "C" fn(tap: i32, event: *mut c_void);
type CGEventSetIntegerValueFieldFn = unsafe extern "C" fn(event: *mut c_void, field: i32, value: i64);
type CGEventSetFlagsFn = unsafe extern "C" fn(event: *mut c_void, flags: u64);
type CGEventKeyboardSetUnicodeStringFn =
    unsafe extern "C" fn(event: *mut c_void, length: usize, chars: *const u16);
type CFReleaseFn = unsafe extern "C" fn(cf: *const c_void);
type AXIsProcessTrustedFn = unsafe extern "C" fn() -> bool;
type CGMainDisplayIDFn = unsafe extern "C" fn() -> u32;
type CGDisplayPixelsWideFn = unsafe extern "C" fn(display: u32) -> usize;
type CGDisplayPixelsHighFn = unsafe extern "C" fn(display: u32) -> usize;
type CGDisplayBoundsFn = unsafe extern "C" fn(display: u32) -> CGRect;
type CGGetActiveDisplayListFn = unsafe extern "C" fn(
    max_displays: u32,
    active_displays: *mut u32,
    display_count: *mut u32,
) -> i32; // CGError（0 = kCGErrorSuccess）

/// 已解析的 framework 函数表。
///
/// Library 句柄以字段持有，保证符号在进程生命周期内有效（与 `ffmpeg/dlls.rs`
/// 同模式）。非 macOS 平台上仅用于符号校验（死代码，`#[cfg_attr]` 抑制）。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct CGDlls {
    _cg: Library,
    _cf: Library,
    _as: Library,
    cg_event_create_mouse_event: CGEventCreateMouseEventFn,
    cg_event_create_scroll_wheel_event2: CGEventCreateScrollWheelEvent2Fn,
    cg_event_create_keyboard_event: CGEventCreateKeyboardEventFn,
    cg_event_post: CGEventPostFn,
    cg_event_set_integer_value_field: CGEventSetIntegerValueFieldFn,
    cg_event_set_flags: CGEventSetFlagsFn,
    cg_event_keyboard_set_unicode_string: CGEventKeyboardSetUnicodeStringFn,
    cf_release: CFReleaseFn,
    ax_is_process_trusted: AXIsProcessTrustedFn,
    cg_main_display_id: CGMainDisplayIDFn,
    cg_display_pixels_wide: CGDisplayPixelsWideFn,
    cg_display_pixels_high: CGDisplayPixelsHighFn,
    cg_display_bounds: CGDisplayBoundsFn,
    cg_get_active_display_list: CGGetActiveDisplayListFn,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
static CG_DLLS: OnceLock<Result<CGDlls, InjectError>> = OnceLock::new();

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl CGDlls {
    /// 加载并解析全部符号（进程内一次）。加载失败 → [`InjectError::UnsupportedPlatform`]
    /// （非 macOS 系统上 dlopen 必然失败，符合桩契约）。
    fn get() -> Result<&'static CGDlls, InjectError> {
        CG_DLLS
            .get_or_init(|| Self::load().map_err(|e| InjectError::UnsupportedPlatform(e)))
            .as_ref()
            .map_err(|e| e.clone())
    }

    fn load() -> Result<Self, String> {
        // dlopen 全路径 framework（不依赖 DYLD 搜索路径）。
        // SAFETY: 路径为系统固定路径，加载后仅 dlsym 取符号。
        let cg = unsafe { Library::new(CORE_GRAPHICS_FW) }
            .map_err(|e| format!("dlopen CoreGraphics: {e}"))?;
        let cf = unsafe { Library::new(CORE_FOUNDATION_FW) }
            .map_err(|e| format!("dlopen CoreFoundation: {e}"))?;
        let as_ = unsafe { Library::new(APPLICATION_SERVICES_FW) }
            .map_err(|e| format!("dlopen ApplicationServices: {e}"))?;

        macro_rules! sym {
            ($lib:expr, $name:literal, $ty:ty) => {
                // SAFETY: 符号名与类型均来自 CoreGraphics 头文件（CGEvent.h 等）。
                unsafe { $lib.get::<$ty>($name.as_bytes()) }
                    .map(|s: Symbol<'_, $ty>| *s)
                    .map_err(|e| format!("symbol '{}$' not found: {e}", $name))? as $ty
            };
        }

        Ok(Self {
            cg_event_create_mouse_event: sym!(
                &cg,
                "CGEventCreateMouseEvent",
                CGEventCreateMouseEventFn
            ),
            cg_event_create_scroll_wheel_event2: sym!(
                &cg,
                "CGEventCreateScrollWheelEvent2",
                CGEventCreateScrollWheelEvent2Fn
            ),
            cg_event_create_keyboard_event: sym!(
                &cg,
                "CGEventCreateKeyboardEvent",
                CGEventCreateKeyboardEventFn
            ),
            cg_event_post: sym!(&cg, "CGEventPost", CGEventPostFn),
            cg_event_set_integer_value_field: sym!(
                &cg,
                "CGEventSetIntegerValueField",
                CGEventSetIntegerValueFieldFn
            ),
            cg_event_set_flags: sym!(&cg, "CGEventSetFlags", CGEventSetFlagsFn),
            cg_event_keyboard_set_unicode_string: sym!(
                &cg,
                "CGEventKeyboardSetUnicodeString",
                CGEventKeyboardSetUnicodeStringFn
            ),
            cf_release: sym!(&cf, "CFRelease", CFReleaseFn),
            ax_is_process_trusted: sym!(&as_, "AXIsProcessTrusted", AXIsProcessTrustedFn),
            cg_main_display_id: sym!(&cg, "CGMainDisplayID", CGMainDisplayIDFn),
            cg_display_pixels_wide: sym!(&cg, "CGDisplayPixelsWide", CGDisplayPixelsWideFn),
            cg_display_pixels_high: sym!(&cg, "CGDisplayPixelsHigh", CGDisplayPixelsHighFn),
            cg_display_bounds: sym!(&cg, "CGDisplayBounds", CGDisplayBoundsFn),
            cg_get_active_display_list: sym!(
                &cg,
                "CGGetActiveDisplayList",
                CGGetActiveDisplayListFn
            ),
            _cg: cg,
            _cf: cf,
            _as: as_,
        })
    }

    /// Accessibility 权限检查（每次注入调用，权限中途授予即生效）。
    fn trusted(&self) -> bool {
        // SAFETY: AXIsProcessTrusted(void) -> Boolean（1 字节），无参数。
        unsafe { (self.ax_is_process_trusted)() }
    }
}

// ════════════════════════════════════════════════════════════════
// 纯函数映射（跨平台可单测，同 linux.rs 的 build_events 模式）
// ════════════════════════════════════════════════════════════════

/// [`Key`]（HID usage code）→ macOS kVK（虚拟键码）。
///
/// 字母 A–Z：kVK 连续（kVK_ANSI_A=0x00 … kVK_ANSI_Z=0x0D），kVK = hid - 4。
/// 数字 1–0：kVK_ANSI_1=0x12 … kVK_ANSI_0=0x1D，kVK = 0x12 + (hid - 0x1E)。
/// 控制/导航键：显式映射表（kVK 不连续，如 F1..F12）。
/// 未覆盖键 → `None`（上层报 [`InjectError::InvalidEvent`]）。
pub fn map_kvk(key: u32) -> Option<u16> {
    // 字母 A-Z（HID 0x04..=0x1D）。
    if (Key::A as u32..=Key::Z as u32).contains(&key) {
        return Some((key - Key::A as u32) as u16); // kVK_ANSI_A=0x00
    }
    // 数字 1-9（HID 0x1E..=0x26）：kVK_ANSI_1=0x12 起线性。
    if (Key::Num1 as u32..=Key::Num9 as u32).contains(&key) {
        return Some((0x12 + (key - Key::Num1 as u32)) as u16);
    }
    // 数字 0（HID 0x27）→ kVK_ANSI_0=0x1D（与 9 之间有间隔：0x1B Minus / 0x1C Equal）。
    if key == Key::Num0 as u32 {
        return Some(0x1D);
    }
    Some(match key {
        k if k == Key::Enter as u32 => 0x24, // kVK_Return
        k if k == Key::Esc as u32 => 0x35,   // kVK_Escape
        k if k == Key::Backspace as u32 => 0x33, // kVK_Delete
        k if k == Key::Tab as u32 => 0x30,   // kVK_Tab
        k if k == Key::Space as u32 => 0x31, // kVK_Space
        k if k == Key::CapsLock as u32 => 0x39, // kVK_CapsLock
        k if k == Key::F1 as u32 => 0x7A,
        k if k == Key::F2 as u32 => 0x78,
        k if k == Key::F3 as u32 => 0x63,
        k if k == Key::F4 as u32 => 0x76,
        k if k == Key::F5 as u32 => 0x60,
        k if k == Key::F6 as u32 => 0x61,
        k if k == Key::F7 as u32 => 0x62,
        k if k == Key::F8 as u32 => 0x64,
        k if k == Key::F9 as u32 => 0x65,
        k if k == Key::F10 as u32 => 0x6D,
        k if k == Key::F11 as u32 => 0x67,
        k if k == Key::F12 as u32 => 0x6F,
        k if k == Key::Insert as u32 => 0x72, // kVK_Help（macOS 无 Insert）
        k if k == Key::Home as u32 => 0x73,   // kVK_Home
        k if k == Key::PageUp as u32 => 0x74, // kVK_PageUp
        k if k == Key::Delete as u32 => 0x75, // kVK_ForwardDelete
        k if k == Key::End as u32 => 0x77,    // kVK_End
        k if k == Key::PageDown as u32 => 0x79, // kVK_PageDown
        k if k == Key::Right as u32 => 0x7C,  // kVK_RightArrow
        k if k == Key::Left as u32 => 0x7B,   // kVK_LeftArrow
        k if k == Key::Down as u32 => 0x7D,   // kVK_DownArrow
        k if k == Key::Up as u32 => 0x7E,     // kVK_UpArrow
        _ => return None,
    })
}

/// 修饰键位标志（`InputEvent::modifiers`）→ CGEventFlags。
pub fn modifier_flags(mods: u8) -> u64 {
    let mut flags = 0u64;
    if mods & modifier::CTRL != 0 {
        flags |= cg_flags::CONTROL;
    }
    if mods & modifier::SHIFT != 0 {
        flags |= cg_flags::SHIFT;
    }
    if mods & modifier::ALT != 0 {
        flags |= cg_flags::ALTERNATE;
    }
    if mods & modifier::SUPER != 0 {
        flags |= cg_flags::COMMAND;
    }
    flags
}

/// 鼠标按键位标志 → `(CGEventType, CGMouseButton)`。
///
/// `button::RELEASE`（bit 7）置位 = 抬起。未知按键位 → `InvalidEvent`。
pub fn mouse_event_type(button_bits: u8) -> Result<(i32, i32), InjectError> {
    let released = button_bits & button::RELEASE != 0;
    if button_bits & button::LEFT != 0 {
        Ok(if released {
            (cg_type::LEFT_MOUSE_UP, cg_mouse_button::LEFT)
        } else {
            (cg_type::LEFT_MOUSE_DOWN, cg_mouse_button::LEFT)
        })
    } else if button_bits & button::RIGHT != 0 {
        Ok(if released {
            (cg_type::RIGHT_MOUSE_UP, cg_mouse_button::RIGHT)
        } else {
            (cg_type::RIGHT_MOUSE_DOWN, cg_mouse_button::RIGHT)
        })
    } else if button_bits & button::MIDDLE != 0 {
        Ok(if released {
            (cg_type::OTHER_MOUSE_UP, cg_mouse_button::CENTER)
        } else {
            (cg_type::OTHER_MOUSE_DOWN, cg_mouse_button::CENTER)
        })
    } else {
        Err(InjectError::InvalidEvent(format!(
            "mouse button event with no button bit: {}",
            button_bits
        )))
    }
}

// ════════════════════════════════════════════════════════════════
// 多显示器布局偏移换算（R-21b，对齐 M8-T018 坐标映射；跨平台纯函数）
// ════════════════════════════════════════════════════════════════

/// 单块显示器的布局快照（`CGDisplayBounds` 全局原点 + 像素/逻辑尺寸）。
///
/// 坐标映射（M8-T018 CLI-MON-010 / SRV-MON-010）：客户端归一化坐标基数 =
/// **所选显示器像素分辨率**；服务端注入侧把事件缩放到该屏像素空间
/// （显示器局部坐标），注入时叠加该屏在全局布局中的原点偏移。
///
/// - `origin`：全局坐标空间原点（point）。主屏固定为 (0,0)；副屏在
///   主屏**左/上**时为负、**右/下**时为正（`CGDisplayBounds` 语义）。
/// - `width_px` / `height_px`：像素分辨率（Retina 下大于逻辑尺寸）。
/// - `bounds`：逻辑尺寸（point，`CGDisplayBounds` 的 size）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DisplayRect {
    /// 全局坐标空间原点（point）。
    pub origin: CGPoint,
    /// 像素分辨率宽（注入坐标基数，M8-T018）。
    pub width_px: u32,
    /// 像素分辨率高。
    pub height_px: u32,
    /// 逻辑尺寸（point）。
    pub bounds: CGSize,
}

impl DisplayRect {
    /// 每 point 像素数（Retina scale）。
    ///
    /// `min(px_w / bounds_w, px_h / bounds_h)`：两方向取小，规避旋转/异常
    /// 布局下的极端值；尺寸非法（宽或高为 0）时回退 1:1（与修复前
    /// `to_display_point` 的 1:1 回退语义一致，不除零）。
    pub fn scale(&self) -> f64 {
        if self.width_px > 0
            && self.height_px > 0
            && self.bounds.width > 0.0
            && self.bounds.height > 0.0
        {
            (self.width_px as f64 / self.bounds.width)
                .min(self.height_px as f64 / self.bounds.height)
        } else {
            1.0
        }
    }
}

/// 显示器局部像素坐标 → 全局 CGEvent point 坐标（多屏布局偏移换算）。
///
/// 公式：`global = display.origin + local_px / display.scale`。
/// - 主屏（origin = (0,0)）：即修复前既有行为 `local_px / scale`（无偏移特例）；
/// - 副屏：叠加该屏全局原点偏移——副屏在**左/上**时全局坐标为负、
///   在**右/下**时为正（R-21b 修复：此前恒以主屏为原点，副屏注入偏移缺失）。
pub fn to_global_point(local_x_px: u32, local_y_px: u32, display: &DisplayRect) -> CGPoint {
    let s = display.scale();
    CGPoint::new(
        display.origin.x + local_x_px as f64 / s,
        display.origin.y + local_y_px as f64 / s,
    )
}

/// 布局表内选择"选中显示器"：按像素分辨率精确匹配。
///
/// M8-T018：归一化坐标基数 = 所选屏分辨率，注入侧 `dst_w/dst_h` 即所选屏
/// 分辨率（`InputInjector::set_resolution` 在显示器切换时同步更新），由此
/// 识别目标屏。返回首个精确匹配索引；无匹配 → `None`（调用方回退主屏）。
/// 同分辨率多屏取首个匹配（注入接口未携带屏索引，分辨率匹配为最小可行
/// 方案；实机验证项登记 R-26b J03）。
pub fn select_display_by_resolution(
    displays: &[DisplayRect],
    width_px: u32,
    height_px: u32,
) -> Option<usize> {
    displays
        .iter()
        .position(|d| d.width_px == width_px && d.height_px == height_px)
}

/// 主屏索引：全局原点 (0,0) 者（`CGDisplayBounds` 语义，主屏必为 (0,0)）。
///
/// 布局表无 (0,0) 项时回退首屏；表为空 → `None`（调用方兜底）。
pub fn primary_display_index(displays: &[DisplayRect]) -> Option<usize> {
    displays
        .iter()
        .position(|d| d.origin.x == 0.0 && d.origin.y == 0.0)
        .or_else(|| (!displays.is_empty()).then_some(0))
}

/// 活跃显示器数量上限（`CGGetActiveDisplayList` 输出缓冲大小；macOS 实际
/// 上限 16，取 32 留余量）。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MAX_ACTIVE_DISPLAYS: u32 = 32;

// ════════════════════════════════════════════════════════════════
// 注入入口（macOS 真实实现）
// ════════════════════════════════════════════════════════════════

/// 注入流水线入口（MAC-T002）：把一条 [`PipeEvent`] 注入 macOS（CGEvent）。
///
/// `ev.x / ev.y` 已由 [`crate::injector::InputInjector`] 缩放到 `dst_w × dst_h`
/// 像素空间，此处换算到 CGEvent point 坐标后经 `kCGHIDEventTap` 注入。
///
/// 错误语义（沿用 P1E 桩契约）：
/// - Accessibility 权限缺失 → [`InjectError::UnsupportedPlatform`]（UI 层引导授权）。
/// - dlopen/符号缺失 → [`InjectError::UnsupportedPlatform`]（非 macOS 系统）。
/// - 未知键码/非法参数 → [`InjectError::InvalidEvent`]。
#[cfg(target_os = "macos")]
pub fn inject(ev: &PipeEvent, dst_w: u32, dst_h: u32) -> Result<(), InjectError> {
    // M8-T020 SRV-SKEY-014: 特殊键走独立路径——锁屏（CGSession）在
    // 分辨率未知时也应可用，先于分辨率校验处理。
    if ev.kind == InputKind::SpecialKey {
        return inject_special_key(ev.combo);
    }

    if dst_w == 0 || dst_h == 0 {
        return Err(InjectError::InvalidEvent(format!(
            "zero resolution: {dst_w}x{dst_h}"
        )));
    }
    let dlls = CGDlls::get()?;
    if !dlls.trusted() {
        return Err(InjectError::UnsupportedPlatform(
            "Accessibility permission not granted — System Settings → Privacy & Security → \
             Accessibility（注入被 macOS 拒绝，请添加 KirinDesk 并重新启动）"
                .to_string(),
        ));
    }

    let event = build_event(dlls, ev, dst_w, dst_h)?;
    if event.is_null() {
        return Err(InjectError::InjectFailed(
            "CGEventCreate returned NULL".to_string(),
        ));
    }

    // SAFETY: event 为本进程创建的 CGEventRef（引用计数 1），post 后 CFRelease。
    unsafe {
        (dlls.cg_event_post)(TAP_HID, event);
        (dlls.cf_release)(event as *const c_void);
    }
    Ok(())
}

/// 非 macOS 平台桩：注入不可用（不阻断编译，返回明确错误）。
#[cfg(not(target_os = "macos"))]
pub fn inject(_ev: &PipeEvent, _dst_w: u32, _dst_h: u32) -> Result<(), InjectError> {
    Err(InjectError::UnsupportedPlatform(
        "macOS CGEvent injection not available on this target".to_string(),
    ))
}

// ════════════════════════════════════════════════════════════════
// M8-T020 特殊键注入（SRV-SKEY-013/014/016）
// ════════════════════════════════════════════════════════════════

/// 纯函数：`SpecialCombo` → kVK 序列（修饰键按住 → 主键 → 修饰键抬起）。
///
/// 平台翻译（SRV-SKEY-014「kVK 组合映射」）：`Win` → `Command`（macOS 超级键）；
/// `Alt+F4` → `Cmd+W`（语义翻译：关闭窗口）。返回 `None` 的变体由上层处理：
/// `AltTab` 不可靠（Cmd+Tab 是系统 UI）→ 不支持；`LockScreen` → CGSession 调用。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn kvk_sequence(combo: SpecialCombo) -> Option<Vec<(u16, bool)>> {
    // kVK 常量（HIToolbox/Events.h）。
    const CMD: u16 = 0x37; // kVK_Command
    const CTRL: u16 = 0x3B; // kVK_Control
    const SHIFT: u16 = 0x38; // kVK_Shift
    const ESC: u16 = 0x35; // kVK_Escape
    const W: u16 = 0x0D; // kVK_ANSI_W
    const E: u16 = 0x0E;
    const D: u16 = 0x02;
    const L: u16 = 0x25;
    const R: u16 = 0x0F;

    let mut v = Vec::new();
    let mut k = |code: u16, down: bool| v.push((code, down));
    match combo {
        SpecialCombo::WinE => {
            k(CMD, true);
            k(E, true);
            k(E, false);
            k(CMD, false);
        }
        SpecialCombo::WinD => {
            k(CMD, true);
            k(D, true);
            k(D, false);
            k(CMD, false);
        }
        SpecialCombo::WinL => {
            k(CMD, true);
            k(L, true);
            k(L, false);
            k(CMD, false);
        }
        SpecialCombo::WinR => {
            k(CMD, true);
            k(R, true);
            k(R, false);
            k(CMD, false);
        }
        SpecialCombo::CtrlShiftEsc => {
            k(CTRL, true);
            k(SHIFT, true);
            k(ESC, true);
            k(ESC, false);
            k(SHIFT, false);
            k(CTRL, false);
        }
        SpecialCombo::AltF4 => {
            // 语义翻译：Alt+F4（关闭窗口）→ Cmd+W。
            k(CMD, true);
            k(W, true);
            k(W, false);
            k(CMD, false);
        }
        SpecialCombo::CtrlEsc => {
            k(CTRL, true);
            k(ESC, true);
            k(ESC, false);
            k(CTRL, false);
        }
        // Cmd+Tab 是系统 UI，注入不可靠（SRV-SKEY-014）；锁屏走 CGSession（非注入）。
        SpecialCombo::AltTab | SpecialCombo::LockScreen => return None,
    }
    Some(v)
}

/// 执行特殊键注入（macOS 真实实现）。
///
/// - `AltTab` → [`InjectError::UnsupportedPlatform`]（Cmd+Tab 系统 UI，不可靠，不注入）。
/// - `LockScreen` → `CGSession -suspend`（非注入路径，SKEY-SEC-003 单一实现）。
/// - 其余 → kVK 序列逐键 `CGEventPost`（Accessibility 权限同普通注入）。
#[cfg(target_os = "macos")]
fn inject_special_key(combo: Option<SpecialCombo>) -> Result<(), InjectError> {
    use crate::injector::SpecialCombo as SC;
    let combo = combo.ok_or_else(|| {
        InjectError::InvalidEvent("SpecialKey event without combo".to_string())
    })?;

    match combo {
        SC::AltTab => Err(InjectError::UnsupportedPlatform(
            "AltTab unreliable on macOS (Cmd+Tab is system UI); not injected".to_string(),
        )),
        SC::LockScreen => crate::lock::lock_screen(),
        _ => {
            let dlls = CGDlls::get()?;
            if !dlls.trusted() {
                return Err(InjectError::UnsupportedPlatform(
                    "Accessibility permission not granted — System Settings → Privacy & Security → \
                     Accessibility（注入被 macOS 拒绝，请添加 KirinDesk 并重新启动）"
                        .to_string(),
                ));
            }
            // 序列逐键注入：每键独立 CGEvent，post 后立即释放（SRV-SKEY-016
            // 释放步在序列末尾，任何中间失败也只影响该键）。
            for &(kvk, down) in kvk_sequence(combo).ok_or_else(|| {
                InjectError::InvalidEvent(format!("no kVK sequence for {combo:?}"))
            })? {
                let e = unsafe {
                    (dlls.cg_event_create_keyboard_event)(std::ptr::null_mut(), kvk, down)
                };
                if e.is_null() {
                    return Err(InjectError::InjectFailed(
                        "CGEventCreateKeyboardEvent returned NULL".to_string(),
                    ));
                }
                // SAFETY: event 为本进程创建（引用计数 1），post 后 CFRelease。
                unsafe {
                    (dlls.cg_event_post)(TAP_HID, e);
                    (dlls.cf_release)(e as *const c_void);
                }
            }
            Ok(())
        }
    }
}

/// 按事件种类构建 CGEventRef（已设修饰键 flags；调用方负责 post + release）。
///
/// `ev.x / ev.y` 已由上游缩放到服务端像素空间（坐标换算见 [`to_display_point`]，
/// 含多屏布局偏移）。
#[cfg(target_os = "macos")]
fn build_event(
    dlls: &CGDlls,
    ev: &PipeEvent,
    dst_w: u32,
    dst_h: u32,
) -> Result<*mut c_void, InjectError> {
    let flags = modifier_flags(ev.modifiers);
    let event = match ev.kind {
        InputKind::MouseMove => {
            let p = to_display_point(dlls, ev.x, ev.y, dst_w, dst_h);
            // SAFETY: NULL source（默认 source），类型/按键为上述常量。
            unsafe {
                (dlls.cg_event_create_mouse_event)(
                    std::ptr::null_mut(),
                    cg_type::MOUSE_MOVED,
                    p,
                    cg_mouse_button::LEFT,
                )
            }
        }
        InputKind::MouseButton => {
            let (event_type, button) = mouse_event_type(ev.button)?;
            let p = to_display_point(dlls, ev.x, ev.y, dst_w, dst_h);
            let e = unsafe {
                (dlls.cg_event_create_mouse_event)(
                    std::ptr::null_mut(),
                    event_type,
                    p,
                    button,
                )
            };
            if !e.is_null() {
                // 点击状态 = 1（默认 0，某些应用不认 0 状态点击）。
                unsafe {
                    (dlls.cg_event_set_integer_value_field)(
                        e,
                        cg_field::MOUSE_EVENT_CLICK_STATE,
                        1,
                    );
                }
            }
            e
        }
        InputKind::MouseWheel => {
            // pixel 单位滚轮：wheel1 垂直（正 = 向上，与 InputEvent 语义一致），
            // wheel2/wheel3 水平/辅助轴置 0（本管线只有 wheel_delta 一轴）。
            unsafe {
                (dlls.cg_event_create_scroll_wheel_event2)(
                    std::ptr::null_mut(),
                    SCROLL_UNIT_PIXEL,
                    1,
                    ev.wheel_delta,
                    0,
                    0,
                )
            }
        }
        InputKind::Text => {
            let e = unsafe {
                (dlls.cg_event_create_keyboard_event)(std::ptr::null_mut(), 0, true)
            };
            if !e.is_null() && !ev.text.is_empty() {
                let utf16: Vec<u16> = ev.text.encode_utf16().collect();
                // SAFETY: utf16 在本调用内保活；length = 字符数（不是字节数）。
                unsafe {
                    (dlls.cg_event_keyboard_set_unicode_string)(
                        e,
                        utf16.len(),
                        utf16.as_ptr(),
                    );
                }
            }
            e
        }
        InputKind::KeyDown | InputKind::KeyUp | InputKind::KeyRepeat => {
            let kvk = map_kvk(ev.key).ok_or_else(|| {
                InjectError::InvalidEvent(format!("no kVK mapping for key {}", ev.key))
            })?;
            let key_down = matches!(ev.kind, InputKind::KeyDown | InputKind::KeyRepeat);
            let e = unsafe {
                (dlls.cg_event_create_keyboard_event)(std::ptr::null_mut(), kvk, key_down)
            };
            if !e.is_null() && matches!(ev.kind, InputKind::KeyRepeat) {
                // KeyRepeat：置 autorepeat 位（系统在按住场景下自行重复，此处显式标记）。
                unsafe {
                    (dlls.cg_event_set_integer_value_field)(
                        e,
                        cg_field::KEYBOARD_EVENT_AUTOREPEAT,
                        1,
                    );
                }
            }
            e
        }
        // M8-T020: 特殊键由 [`inject`] 提前拦截走 [`inject_special_key`]
        // （多事件序列/锁屏调用），不会到达单事件构建；此处为穷尽匹配兜底。
        InputKind::SpecialKey => {
            return Err(InjectError::InvalidEvent(
                "SpecialKey must be handled by inject_special_key".to_string(),
            ));
        }
    };

    if !event.is_null() && flags != 0 {
        // SAFETY: event 非空，flags 为 CGEventFlags（u64）。
        unsafe { (dlls.cg_event_set_flags)(event, flags) };
    }
    Ok(event)
}

/// 查询单块显示器的布局快照（像素分辨率 + `CGDisplayBounds`）。
#[cfg(target_os = "macos")]
fn display_rect(dlls: &CGDlls, id: u32) -> DisplayRect {
    // SAFETY: 单参查询函数（CGDisplayPixelsWide/High/Bounds）。
    let px_w = unsafe { (dlls.cg_display_pixels_wide)(id) } as u32;
    let px_h = unsafe { (dlls.cg_display_pixels_high)(id) } as u32;
    let bounds = unsafe { (dlls.cg_display_bounds)(id) };
    DisplayRect {
        origin: bounds.origin,
        width_px: px_w,
        height_px: px_h,
        bounds: bounds.size,
    }
}

/// 像素坐标 → CGEvent point 坐标（每屏 scale 换算 + 多屏布局偏移，R-21b）。
///
/// CGEvent 使用 point（逻辑点）：Retina 下 1 point = scale 像素，各屏
/// scale 独立（`scale = pixels / bounds`）。`dst_w/dst_h` 为**选中显示器**
/// 分辨率（M8-T018 归一化基数 = 所选屏分辨率）——`CGGetActiveDisplayList`
/// 枚举活跃显示器布局后按像素分辨率匹配目标屏（[`select_display_by_resolution`]），
/// 取其全局原点叠加偏移（[`to_global_point`]）：副屏在左/上时注入点为负
/// 全局坐标、右/下为正。无匹配/枚举失败回退主显示器（`CGMainDisplayID`，
/// 与修复前行为一致——不因布局查询异常而崩溃）。
#[cfg(target_os = "macos")]
fn to_display_point(dlls: &CGDlls, x_px: u32, y_px: u32, dst_w: u32, dst_h: u32) -> CGPoint {
    // SAFETY: 输出缓冲固定 MAX_ACTIVE_DISPLAYS 项（maxDisplays 同值），
    // displayCount 由系统写入（<= maxDisplays）。
    let mut ids = [0u32; MAX_ACTIVE_DISPLAYS as usize];
    let mut count: u32 = 0;
    let err = unsafe {
        (dlls.cg_get_active_display_list)(MAX_ACTIVE_DISPLAYS, ids.as_mut_ptr(), &mut count)
    };

    let mut layouts: Vec<DisplayRect> = Vec::with_capacity(MAX_ACTIVE_DISPLAYS as usize);
    if err == 0 {
        for &id in ids.iter().take(count.min(MAX_ACTIVE_DISPLAYS) as usize) {
            layouts.push(display_rect(dlls, id));
        }
    }

    let target =
        match select_display_by_resolution(&layouts, dst_w, dst_h).and_then(|i| layouts.get(i)) {
            Some(d) => *d,
            None => {
                // SAFETY: 无参查询函数（CGMainDisplayID）。
                let main = unsafe { (dlls.cg_main_display_id)() };
                display_rect(dlls, main)
            }
        };
    to_global_point(x_px, y_px, &target)
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 字母 A-Z → kVK 连续（kVK_ANSI_A=0x00 起）。
    #[test]
    fn test_map_kvk_letters() {
        assert_eq!(map_kvk(Key::A as u32), Some(0x00));
        assert_eq!(map_kvk(Key::B as u32), Some(0x01));
        assert_eq!(map_kvk(Key::Z as u32), Some(0x19));
    }

    /// 数字 1-0 → kVK_ANSI_1=0x12 起。
    #[test]
    fn test_map_kvk_digits() {
        assert_eq!(map_kvk(Key::Num1 as u32), Some(0x12));
        assert_eq!(map_kvk(Key::Num5 as u32), Some(0x16));
        assert_eq!(map_kvk(Key::Num0 as u32), Some(0x1D));
    }

    /// 控制/导航键显式映射。
    #[test]
    fn test_map_kvk_special() {
        assert_eq!(map_kvk(Key::Enter as u32), Some(0x24)); // kVK_Return
        assert_eq!(map_kvk(Key::Esc as u32), Some(0x35)); // kVK_Escape
        assert_eq!(map_kvk(Key::Backspace as u32), Some(0x33)); // kVK_Delete
        assert_eq!(map_kvk(Key::Tab as u32), Some(0x30)); // kVK_Tab
        assert_eq!(map_kvk(Key::Space as u32), Some(0x31)); // kVK_Space
        assert_eq!(map_kvk(Key::Left as u32), Some(0x7B)); // kVK_LeftArrow
        assert_eq!(map_kvk(Key::Right as u32), Some(0x7C));
        assert_eq!(map_kvk(Key::Up as u32), Some(0x7E));
        assert_eq!(map_kvk(Key::Down as u32), Some(0x7D));
        assert_eq!(map_kvk(Key::Delete as u32), Some(0x75)); // ForwardDelete
        // F 键非连续（kVK_F1=0x7A … kVK_F12=0x6F）。
        assert_eq!(map_kvk(Key::F1 as u32), Some(0x7A));
        assert_eq!(map_kvk(Key::F5 as u32), Some(0x60));
        assert_eq!(map_kvk(Key::F12 as u32), Some(0x6F));
        // 未知键 → None（上层报 InvalidEvent）。
        assert_eq!(map_kvk(0xFFFF_FFFF), None);
    }

    /// 修饰键位 → CGEventFlags 映射。
    #[test]
    fn test_modifier_flags() {
        assert_eq!(modifier_flags(0), 0);
        assert_eq!(modifier_flags(modifier::CTRL), cg_flags::CONTROL);
        assert_eq!(modifier_flags(modifier::SHIFT), cg_flags::SHIFT);
        assert_eq!(modifier_flags(modifier::ALT), cg_flags::ALTERNATE);
        assert_eq!(modifier_flags(modifier::SUPER), cg_flags::COMMAND);
        assert_eq!(
            modifier_flags(modifier::CTRL | modifier::SHIFT),
            cg_flags::CONTROL | cg_flags::SHIFT
        );
    }

    /// 鼠标按键位 → (type, button) 映射（含 RELEASE 方向）。
    #[test]
    fn test_mouse_event_type() {
        assert!(matches!(
            mouse_event_type(button::LEFT),
            Ok((t, b)) if t == cg_type::LEFT_MOUSE_DOWN && b == cg_mouse_button::LEFT
        ));
        assert!(matches!(
            mouse_event_type(button::RIGHT | button::RELEASE),
            Ok((t, b)) if t == cg_type::RIGHT_MOUSE_UP && b == cg_mouse_button::RIGHT
        ));
        assert!(matches!(
            mouse_event_type(button::MIDDLE),
            Ok((t, b)) if t == cg_type::OTHER_MOUSE_DOWN && b == cg_mouse_button::CENTER
        ));
        assert!(matches!(
            mouse_event_type(0),
            Err(InjectError::InvalidEvent(_))
        ));
    }

    /// 非 mac 平台（当前 CI/开发主机）走桩：明确错误，不 panic。
    #[test]
    fn test_macos_stub_unsupported() {
        // 桩契约：返回 UnsupportedPlatform → 上游捕获/丢弃，不崩溃。
        let ev = PipeEvent {
            kind: InputKind::MouseMove,
            x: 0,
            y: 0,
            button: 0,
            key: 0,
            wheel_delta: 0,
            modifiers: 0,
            text: String::new(),
            combo: None,
        };
        let err = inject(&ev, 1920, 1080).unwrap_err();
        assert!(
            matches!(err, InjectError::UnsupportedPlatform(_)),
            "stub contract: must be UnsupportedPlatform, got {err:?}"
        );
    }

    /// M8-T020 T003: Win 组合 → Cmd 序列（按住→点按→释放，释放步最后）。
    #[test]
    fn test_kvk_sequence_win_combos() {
        let seq = kvk_sequence(SpecialCombo::WinE).unwrap();
        assert_eq!(seq, vec![(0x37, true), (0x0E, true), (0x0E, false), (0x37, false)]);
        // 末尾为修饰键抬起（SRV-SKEY-016）。
        assert_eq!(seq.last(), Some(&(0x37, false)));

        for combo in [SpecialCombo::WinD, SpecialCombo::WinL, SpecialCombo::WinR] {
            let seq = kvk_sequence(combo).unwrap();
            assert_eq!(seq[0], (0x37, true), "{combo:?}: Cmd down first");
            assert_eq!(seq.last(), Some(&(0x37, false)), "{combo:?}: Cmd up last");
        }
    }

    /// M8-T020 T003: Ctrl+Shift+Esc 六步；Alt+F4 → Cmd+W（语义翻译）。
    #[test]
    fn test_kvk_sequence_misc() {
        let seq = kvk_sequence(SpecialCombo::CtrlShiftEsc).unwrap();
        assert_eq!(seq.len(), 6);
        assert_eq!(seq[0], (0x3B, true)); // Ctrl down
        assert_eq!(seq[2], (0x35, true)); // Esc down
        assert_eq!(seq[5], (0x3B, false)); // Ctrl up last

        let seq = kvk_sequence(SpecialCombo::AltF4).unwrap();
        assert_eq!(seq[0], (0x37, true)); // Cmd down（Alt+F4 → Cmd+W）
        assert_eq!(seq[1], (0x0D, true)); // W down
        assert_eq!(seq[3], (0x37, false));

        let seq = kvk_sequence(SpecialCombo::CtrlEsc).unwrap();
        assert_eq!(seq.len(), 4);
        assert_eq!(seq[0], (0x3B, true)); // Ctrl down
        assert_eq!(seq[1], (0x35, true)); // Esc down
        assert_eq!(seq[2], (0x35, false)); // Esc up
        assert_eq!(seq[3], (0x3B, false)); // Ctrl up last
    }

    /// M8-T020 T003: AltTab / LockScreen 无 kVK 序列（上层分别返回不支持/走锁屏）。
    #[test]
    fn test_kvk_sequence_unsupported_variants() {
        assert_eq!(kvk_sequence(SpecialCombo::AltTab), None);
        assert_eq!(kvk_sequence(SpecialCombo::LockScreen), None);
    }

    /// CGPoint 布局（16 字节，两个 f64）——与 CoreGraphics ABI 对齐。
    #[test]
    fn test_cgpoint_layout() {
        assert_eq!(std::mem::size_of::<CGPoint>(), 16);
        assert_eq!(std::mem::align_of::<CGPoint>(), 8);
        let p = CGPoint::new(1.5, 2.5);
        assert_eq!(p.x, 1.5);
        assert_eq!(p.y, 2.5);
    }

    // ════════════════════════════════════════════════════════════
    // R-21b: 多显示器布局偏移换算（副屏在左/上/右/下四象限）
    // ════════════════════════════════════════════════════════════

    /// 主屏布局（1920x1080，1:1 scale，全局原点 (0,0)）。
    fn primary() -> DisplayRect {
        DisplayRect {
            origin: CGPoint::new(0.0, 0.0),
            width_px: 1920,
            height_px: 1080,
            bounds: CGSize {
                width: 1920.0,
                height: 1080.0,
            },
        }
    }

    /// 副屏布局（1920x1080，1:1 scale，全局原点 (ox, oy)）。
    fn secondary(ox: f64, oy: f64) -> DisplayRect {
        DisplayRect {
            origin: CGPoint::new(ox, oy),
            width_px: 1920,
            height_px: 1080,
            bounds: CGSize {
                width: 1920.0,
                height: 1080.0,
            },
        }
    }

    /// 主屏无偏移回归：局部坐标 == 全局坐标（修复前既有行为不变）。
    #[test]
    fn test_global_point_primary_no_offset() {
        assert_eq!(
            to_global_point(960, 540, &primary()),
            CGPoint::new(960.0, 540.0)
        );
        // 全范围边界（局部 max 像素）。
        assert_eq!(
            to_global_point(1919, 1079, &primary()),
            CGPoint::new(1919.0, 1079.0)
        );
        // 左上角。
        assert_eq!(to_global_point(0, 0, &primary()), CGPoint::new(0.0, 0.0));
    }

    /// 副屏在右：原点 (1920, 0)——局部坐标整体右移主屏宽。
    #[test]
    fn test_global_point_secondary_right() {
        // 局部中心 → 全局 (1920+960, 0+540)。
        assert_eq!(
            to_global_point(960, 540, &secondary(1920.0, 0.0)),
            CGPoint::new(2880.0, 540.0)
        );
        // 副屏左上角（局部 0,0）→ 全局 (1920, 0)。
        assert_eq!(
            to_global_point(0, 0, &secondary(1920.0, 0.0)),
            CGPoint::new(1920.0, 0.0)
        );
        // 副屏右下角（局部 max）→ 全局 (1920+1919, 1079)。
        assert_eq!(
            to_global_point(1919, 1079, &secondary(1920.0, 0.0)),
            CGPoint::new(3839.0, 1079.0)
        );
    }

    /// 副屏在左：原点 (-1920, 0)——局部坐标映射为**负**全局坐标。
    #[test]
    fn test_global_point_secondary_left() {
        assert_eq!(
            to_global_point(960, 540, &secondary(-1920.0, 0.0)),
            CGPoint::new(-960.0, 540.0)
        );
        // 副屏左上角 → 全局 (-1920, 0)。
        assert_eq!(
            to_global_point(0, 0, &secondary(-1920.0, 0.0)),
            CGPoint::new(-1920.0, 0.0)
        );
        // 副屏右下角 → 全局 (-1, 1079)（紧贴主屏左缘）。
        assert_eq!(
            to_global_point(1919, 1079, &secondary(-1920.0, 0.0)),
            CGPoint::new(-1.0, 1079.0)
        );
    }

    /// 副屏在上：原点 (0, -1080)。
    #[test]
    fn test_global_point_secondary_above() {
        assert_eq!(
            to_global_point(960, 540, &secondary(0.0, -1080.0)),
            CGPoint::new(960.0, -540.0)
        );
        assert_eq!(
            to_global_point(0, 0, &secondary(0.0, -1080.0)),
            CGPoint::new(0.0, -1080.0)
        );
        // 副屏下缘（局部 max y）→ 全局 y = -1。
        assert_eq!(
            to_global_point(960, 1079, &secondary(0.0, -1080.0)),
            CGPoint::new(960.0, -1.0)
        );
    }

    /// 副屏在下：原点 (0, 1080)。
    #[test]
    fn test_global_point_secondary_below() {
        assert_eq!(
            to_global_point(960, 540, &secondary(0.0, 1080.0)),
            CGPoint::new(960.0, 1620.0)
        );
        assert_eq!(
            to_global_point(0, 0, &secondary(0.0, 1080.0)),
            CGPoint::new(0.0, 1080.0)
        );
        assert_eq!(
            to_global_point(1919, 1079, &secondary(0.0, 1080.0)),
            CGPoint::new(1919.0, 2159.0)
        );
    }

    /// Retina 副屏：2560x1440 像素 / 1280x720 point（scale=2）——
    /// 局部像素先缩为逻辑点再叠加原点偏移。
    #[test]
    fn test_global_point_retina_scale() {
        let retina = DisplayRect {
            origin: CGPoint::new(1920.0, 0.0),
            width_px: 2560,
            height_px: 1440,
            bounds: CGSize {
                width: 1280.0,
                height: 720.0,
            },
        };
        assert_eq!(retina.scale(), 2.0);
        // 右下角（局部 max 像素）→ 全局 (1920+1280, 0+720)。
        assert_eq!(
            to_global_point(2560, 1440, &retina),
            CGPoint::new(3200.0, 720.0)
        );
        // 中心 → (1920+640, 0+360)。
        assert_eq!(
            to_global_point(1280, 720, &retina),
            CGPoint::new(2560.0, 360.0)
        );
    }

    /// scale 回退：尺寸非法（宽/高 0）→ 1:1，不除零。
    #[test]
    fn test_display_rect_scale_fallback() {
        let d = DisplayRect {
            origin: CGPoint::new(0.0, 0.0),
            width_px: 0,
            height_px: 0,
            bounds: CGSize {
                width: 0.0,
                height: 0.0,
            },
        };
        assert_eq!(d.scale(), 1.0);
        assert_eq!(to_global_point(100, 200, &d), CGPoint::new(100.0, 200.0));
    }

    /// 选中显示器 = 像素分辨率匹配（M8-T018 基数跟随）；无匹配 → None。
    #[test]
    fn test_select_display_by_resolution() {
        // 屏0 主 1920x1080；屏1 右 2560x1440（Retina 逻辑 1280x720）。
        let right = DisplayRect {
            origin: CGPoint::new(1920.0, 0.0),
            width_px: 2560,
            height_px: 1440,
            bounds: CGSize {
                width: 1280.0,
                height: 720.0,
            },
        };
        let displays = [primary(), right];
        // 选中屏 = 主屏（基数 1920x1080，set_resolution 未切换前）。
        assert_eq!(select_display_by_resolution(&displays, 1920, 1080), Some(0));
        // 选中屏 = 副屏（基数 2560x1440，切换后换算基准同步更新）。
        assert_eq!(select_display_by_resolution(&displays, 2560, 1440), Some(1));
        // 无匹配（如捕获上报分辨率与 CGDisplayPixels 不一致）→ None（回退主屏）。
        assert_eq!(select_display_by_resolution(&displays, 3840, 2160), None);
        // 空表 → None（不 panic）。
        assert_eq!(select_display_by_resolution(&[], 1920, 1080), None);
    }

    /// 主屏索引：全局原点 (0,0) 者；无则回退首屏；空表 → None。
    #[test]
    fn test_primary_display_index() {
        // 副屏在左 → 主屏 → 副屏在下：主屏为索引 1。
        let displays = [secondary(-1920.0, 0.0), primary(), secondary(0.0, 1080.0)];
        assert_eq!(primary_display_index(&displays), Some(1));
        // 布局表无 (0,0) 项 → 回退首屏。
        let no_primary = [secondary(-1920.0, 0.0), secondary(0.0, 1080.0)];
        assert_eq!(primary_display_index(&no_primary), Some(0));
        // 空表 → None。
        assert_eq!(primary_display_index(&[]), None);
    }
}
