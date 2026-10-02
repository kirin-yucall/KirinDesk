//! Linux uinput 注入实现（M8-T008_P1E，Task T5.3）。
//!
//! 能力：绝对坐标（EV_ABS / ABS_X|ABS_Y）、鼠标按键（EV_KEY / BTN_*）、
//! 滚轮（EV_REL / REL_WHEEL）、键盘（EV_KEY / KEY_*）。
//!
//! 权限：需要 `uinput` 组或 root 才能打开 `/dev/uinput`；
//! 无权限 / 无设备 → [`InjectError::UnsupportedPlatform`]，不 panic。
//!
//! 注意：本文件定义的 [`input_event`] 结构体与常量在所有平台都参与编译（供单测校验布局），
//! 仅实际写入 `/dev/uinput` 的 `inject()` 在非 Linux 平台走桩返回 [`InjectError::UnsupportedPlatform`]。

use crate::injector::{
    button, InjectError, InputEvent as PipeEvent, InputKind, Key, SpecialCombo,
};
use std::os::raw::{c_int, c_uint, c_ulong};

// ----------------------------------------------------------------------------
// uinput 相关常量与结构（与内核 <linux/uinput.h> / <linux/input-event-codes.h> 对齐）
// ----------------------------------------------------------------------------

/// 事件类型。
pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;

/// EV_ABS 轴。
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;

/// EV_REL 轴。
pub const REL_WHEEL: u16 = 0x08;

/// 鼠标按键（input-event-codes.h）。
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;

/// uinput ioctl（<asm-generic/ioctl.h>：_IOW 为 0x5500+）。
pub const UI_SET_EVBIT: c_ulong = 0x40045564;
pub const UI_SET_KEYBIT: c_ulong = 0x40045565;
pub const UI_SET_ABSBIT: c_ulong = 0x40045567;
pub const UI_SET_RELBIT: c_ulong = 0x40045566;
pub const UI_DEV_CREATE: c_ulong = 0x5501;
pub const UI_DEV_DESTROY: c_ulong = 0x5502;

/// 内核 `struct input_event`（64 位 ABI：24 字节，含尾部 4 字节 padding）。
///
/// 字段顺序与 <linux/input.h> 一致：`timeval { tv_sec, tv_usec }` 后跟 type/code/value。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct input_event {
    pub tv_sec: i64,
    pub tv_usec: i64,
    pub kind: u16, // type_（`type` 是 Rust 关键字）
    pub code: u16,
    pub value: i32,
}

impl input_event {
    /// 构造一条 input_event（时间戳置 0，由内核打戳）。
    pub const fn new(kind: u16, code: u16, value: i32) -> Self {
        Self { tv_sec: 0, tv_usec: 0, kind, code, value }
    }
}

/// `struct uinput_user_dev` 的最小可写字段集（前两个名称 + 4 个事件位图）。
/// 实际写设备前需 memset 为 0；这里只保证大小与字段偏移用于 setup。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct uinput_user_dev {
    pub name: [u8; UINPUT_MAX_NAME_SIZE],
    pub id: input_id,
    pub ff_effects_max: c_uint,
    pub absmin: [c_int; ABS_CNT],
    pub absmax: [c_int; ABS_CNT],
    pub absfuzz: [c_int; ABS_CNT],
    pub absflat: [c_int; ABS_CNT],
}

pub const UINPUT_MAX_NAME_SIZE: usize = 80;
pub const ABS_CNT: usize = 0x40;

/// `struct input_id`。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct input_id {
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

// ----------------------------------------------------------------------------
// 注入入口
// ----------------------------------------------------------------------------

/// 注入流水线入口（Task T5.3）：把一条 [`PipeEvent`] 注入 Linux（uinput）。
///
/// `ev.x / ev.y` 已由 [`crate::injector::InputInjector`] 缩放到 `dst_w × dst_h` 像素空间，
/// 这里直接作为 EV_ABS 绝对值写入（需在 setup 阶段把 ABS_X/ABS_Y 的 absmax 设为 dst-1）。
#[cfg(target_os = "linux")]
pub fn inject(ev: &PipeEvent, dst_w: u32, dst_h: u32) -> Result<(), InjectError> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;

    // uinput 只能发 EV_KEY 等内核事件，无法注入任意 Unicode 文本
    // （需 XTEST/wayland 合成，超出本实现范围）→ 明确报 UnsupportedPlatform，不崩溃。
    if ev.kind == InputKind::Text {
        return Err(InjectError::UnsupportedPlatform(
            "Linux uinput cannot inject Unicode text (needs XTEST)".to_string(),
        ));
    }

    // M8-T020 SRV-SKEY-013: 特殊键处理——
    // - 锁屏走 `loginctl lock-session`（非注入路径，无需 uinput 设备）；
    // - 其余组合键由 build_events 展开为 EV_KEY 序列（走下方 uinput 设备）。
    if ev.kind == InputKind::SpecialKey {
        match ev.combo {
            Some(SpecialCombo::LockScreen) => {
                return crate::lock::lock_screen();
            }
            Some(_) => {}
            None => {
                return Err(InjectError::InvalidEvent(
                    "SpecialKey event without combo".to_string(),
                ));
            }
        }
    }

    // 打开 /dev/uinput：无设备 / 无权限 → UnsupportedPlatform / InjectFailed（不 panic）。
    let mut dev = match OpenOptions::new().write(true).open("/dev/uinput") {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(InjectError::UnsupportedPlatform(format!(
                "/dev/uinput not found: {e}"
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(InjectError::UnsupportedPlatform(format!(
                "/dev/uinput permission denied (need uinput group/root): {e}"
            )));
        }
        Err(e) => {
            return Err(InjectError::InjectFailed(format!("open /dev/uinput: {e}")));
        }
    };
    let fd = dev.as_raw_fd();

    // ioctl FFI 封装。
    extern "C" {
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    }
    // SAFETY: fd 来自已打开的 /dev/uinput，request 为已知合法 uinput ioctl。
    unsafe fn ioctl_set(fd: c_int, req: c_ulong, arg: c_int) -> std::io::Result<()> {
        let r = ioctl(fd, req, arg);
        if r < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    // 注册设备能力。
    unsafe {
        ioctl_set(fd, UI_SET_EVBIT, EV_KEY as c_int)
            .map_err(|e| InjectError::InjectFailed(format!("UI_SET_EVBIT EV_KEY: {e}")))?;
        ioctl_set(fd, UI_SET_EVBIT, EV_ABS as c_int)
            .map_err(|e| InjectError::InjectFailed(format!("UI_SET_EVBIT EV_ABS: {e}")))?;
        ioctl_set(fd, UI_SET_EVBIT, EV_REL as c_int)
            .map_err(|e| InjectError::InjectFailed(format!("UI_SET_EVBIT EV_REL: {e}")))?;
        ioctl_set(fd, UI_SET_KEYBIT, BTN_LEFT as c_int)
            .map_err(|e| InjectError::InjectFailed(format!("UI_SET_KEYBIT BTN_LEFT: {e}")))?;
        ioctl_set(fd, UI_SET_KEYBIT, BTN_RIGHT as c_int)
            .map_err(|e| InjectError::InjectFailed(format!("UI_SET_KEYBIT BTN_RIGHT: {e}")))?;
        ioctl_set(fd, UI_SET_KEYBIT, BTN_MIDDLE as c_int)
            .map_err(|e| InjectError::InjectFailed(format!("UI_SET_KEYBIT BTN_MIDDLE: {e}")))?;
        ioctl_set(fd, UI_SET_ABSBIT, ABS_X as c_int)
            .map_err(|e| InjectError::InjectFailed(format!("UI_SET_ABSBIT ABS_X: {e}")))?;
        ioctl_set(fd, UI_SET_ABSBIT, ABS_Y as c_int)
            .map_err(|e| InjectError::InjectFailed(format!("UI_SET_ABSBIT ABS_Y: {e}")))?;
        ioctl_set(fd, UI_SET_RELBIT, REL_WHEEL as c_int)
            .map_err(|e| InjectError::InjectFailed(format!("UI_SET_RELBIT REL_WHEEL: {e}")))?;
    }

    // 写 uinput_user_dev：name + absmin/absmax（ABS_X/ABS_Y 范围 = [0, dst-1]）。
    let mut udev = uinput_user_dev {
        name: [0u8; UINPUT_MAX_NAME_SIZE],
        id: input_id { bustype: 0x03, vendor: 0x1234, product: 0x5678, version: 1 },
        ff_effects_max: 0,
        absmin: [0; ABS_CNT],
        absmax: [0; ABS_CNT],
        absfuzz: [0; ABS_CNT],
        absflat: [0; ABS_CNT],
    };
    let name = b"KirinDesk";
    udev.name[..name.len()].copy_from_slice(name);
    if dst_w > 0 {
        udev.absmax[ABS_X as usize] = (dst_w - 1) as c_int;
    }
    if dst_h > 0 {
        udev.absmax[ABS_Y as usize] = (dst_h - 1) as c_int;
    }
    // 写整个结构体（repr(C)，可直接按字节写）。
    {
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &udev as *const _ as *const u8,
                std::mem::size_of::<uinput_user_dev>(),
            )
        };
        dev.write_all(bytes)
            .map_err(|e| InjectError::InjectFailed(format!("write uinput_user_dev: {e}")))?;
    }

    // 创建设备。
    unsafe {
        let r = ioctl(dev.as_raw_fd(), UI_DEV_CREATE);
        if r < 0 {
            return Err(InjectError::InjectFailed(format!(
                "UI_DEV_CREATE: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    // 写事件。
    let events = build_events(ev);
    let buf: &[u8] = unsafe {
        std::slice::from_raw_parts(
            events.as_ptr() as *const u8,
            events.len() * std::mem::size_of::<input_event>(),
        )
    };
    dev.write_all(buf)
        .map_err(|e| InjectError::InjectFailed(format!("write input_event: {e}")))?;

    // 销毁设备（保持简单：一次性设备；高频场景应由上层复用设备句柄）。
    unsafe {
        ioctl(dev.as_raw_fd(), UI_DEV_DESTROY);
    }
    Ok(())
}

/// [`Key`]（管线自定义判别式，HID usage code 惯例）→ Linux 内核键码
///（<linux/input-event-codes.h> `KEY_*`）。
///
/// 与 `windows::map_scan_code` / `macos::map_kvk` 同风格）。修复前
/// `build_events` 把 `Key` 判别式**直接**当 EV_KEY 码（`ev.key as u16`）——
/// 判别式 ≠ Linux 键码（如 `Key::A`=0x04 vs `KEY_A`=30、`Key::Period`=0x57
/// vs `KEY_DOT`=52），普通键/新标点在本平台均会被注入为错键；本函数一并
/// 修正（非生产平台，行为对齐其余两平台的「映射表全覆盖」口径）。
///
/// 取值对照 <linux/input-event-codes.h>；XT 布局区段（字母 / 数字 / 标点 /
/// F1-F10 等）与 PS/2 Set 1 scan code 逐一相等——与 `windows::map_scan_code`
/// 交叉核验一致（MINUS=12 / EQUAL=13 / LEFTBRACE=26 / RIGHTBRACE=27 /
/// SEMICOLON=39 / APOSTROPHE=40 / GRAVE=41 / BACKSLASH=43 / COMMA=51 /
/// DOT=52 / SLASH=53）。未覆盖键 → `None`（`build_events` 对该键不产生
/// 事件，优于旧实现发出垃圾码）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn map_keycode(key: u32) -> Option<u16> {
    // 数字 1-9（KEY_1=2=0x02 起连续 9 位）。
    if (Key::Num1 as u32..=Key::Num9 as u32).contains(&key) {
        return Some((0x02 + (key - Key::Num1 as u32)) as u16);
    }
    Some(match key {
        // 字母 A-Z（Linux 键码按**物理键位**（QWERTY 行序）排布，≠ 字母序——
        // KEY_A=30… 但 KEY_Z=44；与 PS/2 Set 1 物理序逐一相等，与
        // `windows::map_scan_code` 字母表互证）。
        k if k == Key::Q as u32 => 0x10,   // KEY_Q
        k if k == Key::W as u32 => 0x11,   // KEY_W
        k if k == Key::E as u32 => 0x12,   // KEY_E
        k if k == Key::R as u32 => 0x13,   // KEY_R
        k if k == Key::T as u32 => 0x14,   // KEY_T
        k if k == Key::Y as u32 => 0x15,   // KEY_Y
        k if k == Key::U as u32 => 0x16,   // KEY_U
        k if k == Key::I as u32 => 0x17,   // KEY_I
        k if k == Key::O as u32 => 0x18,   // KEY_O
        k if k == Key::P as u32 => 0x19,   // KEY_P
        k if k == Key::A as u32 => 0x1E,   // KEY_A
        k if k == Key::S as u32 => 0x1F,   // KEY_S
        k if k == Key::D as u32 => 0x20,   // KEY_D
        k if k == Key::F as u32 => 0x21,   // KEY_F
        k if k == Key::G as u32 => 0x22,   // KEY_G
        k if k == Key::H as u32 => 0x23,   // KEY_H
        k if k == Key::J as u32 => 0x24,   // KEY_J
        k if k == Key::K as u32 => 0x25,   // KEY_K
        k if k == Key::L as u32 => 0x26,   // KEY_L
        k if k == Key::Z as u32 => 0x2C,   // KEY_Z
        k if k == Key::X as u32 => 0x2D,   // KEY_X
        k if k == Key::C as u32 => 0x2E,   // KEY_C
        k if k == Key::V as u32 => 0x2F,   // KEY_V
        k if k == Key::B as u32 => 0x30,   // KEY_B
        k if k == Key::N as u32 => 0x31,   // KEY_N
        k if k == Key::M as u32 => 0x32,   // KEY_M
        k if k == Key::Num0 as u32 => 0x0B,   // KEY_0
        k if k == Key::Enter as u32 => 0x1C,  // KEY_ENTER
        k if k == Key::Esc as u32 => 0x01,    // KEY_ESC
        k if k == Key::Backspace as u32 => 0x0E, // KEY_BACKSPACE
        k if k == Key::Tab as u32 => 0x0F,    // KEY_TAB
        k if k == Key::Space as u32 => 0x39,  // KEY_SPACE
        k if k == Key::CapsLock as u32 => 0x3A, // KEY_CAPSLOCK
        k if k == Key::F1 as u32 => 0x3B,     // KEY_F1
        k if k == Key::F2 as u32 => 0x3C,
        k if k == Key::F3 as u32 => 0x3D,
        k if k == Key::F4 as u32 => 0x3E,
        k if k == Key::F5 as u32 => 0x3F,
        k if k == Key::F6 as u32 => 0x40,
        k if k == Key::F7 as u32 => 0x41,
        k if k == Key::F8 as u32 => 0x42,
        k if k == Key::F9 as u32 => 0x43,
        k if k == Key::F10 as u32 => 0x44,
        k if k == Key::F11 as u32 => 0x57,    // KEY_F11（≡ Set 1 0x57，与 windows 表一致）
        k if k == Key::F12 as u32 => 0x58,    // KEY_F12
        k if k == Key::Insert as u32 => 0x6E, // KEY_INSERT
        k if k == Key::Home as u32 => 0x66,   // KEY_HOME
        k if k == Key::PageUp as u32 => 0x68, // KEY_PAGEUP
        k if k == Key::Delete as u32 => 0x6F, // KEY_DELETE
        k if k == Key::End as u32 => 0x6B,    // KEY_END
        k if k == Key::PageDown as u32 => 0x6D, // KEY_PAGEDOWN
        k if k == Key::Right as u32 => 0x6A,  // KEY_RIGHT
        k if k == Key::Left as u32 => 0x69,   // KEY_LEFT
        k if k == Key::Down as u32 => 0x6C,   // KEY_DOWN
        k if k == Key::Up as u32 => 0x67,     // KEY_UP
        k if k == Key::Shift as u32 => 0x2A,  // KEY_LEFTSHIFT
        k if k == Key::Ctrl as u32 => 0x1D,   // KEY_LEFTCTRL
        k if k == Key::Alt as u32 => 0x38,    // KEY_LEFTALT
        k if k == Key::Super as u32 => 0x7D,  // KEY_LEFTMETA
        k if k == Key::Minus as u32 => 0x0C,      // KEY_MINUS
        k if k == Key::Equals as u32 => 0x0D,     // KEY_EQUAL
        k if k == Key::OpenBracket as u32 => 0x1A, // KEY_LEFTBRACE
        k if k == Key::CloseBracket as u32 => 0x1B, // KEY_RIGHTBRACE
        k if k == Key::Semicolon as u32 => 0x27,  // KEY_SEMICOLON
        k if k == Key::Quote as u32 => 0x28,      // KEY_APOSTROPHE
        k if k == Key::Backtick as u32 => 0x29,   // KEY_GRAVE
        k if k == Key::Backslash as u32 => 0x2B,  // KEY_BACKSLASH
        k if k == Key::Comma as u32 => 0x33,      // KEY_COMMA
        k if k == Key::Period as u32 => 0x34,     // KEY_DOT
        k if k == Key::Slash as u32 => 0x35,      // KEY_SLASH
        // 无独立物理键（Shift 组合语义，Shift 由独立修饰键事件表达）：
        // 相邻物理键键码（与 windows/macOS 别名口径一致）。
        k if k == Key::Colon as u32 => 0x27,       // → KEY_SEMICOLON
        k if k == Key::Pipe as u32 => 0x2B,        // → KEY_BACKSLASH
        k if k == Key::Questionmark as u32 => 0x35, // → KEY_SLASH
        // NumpadAdd）→ KEY_KPPLUS=78=0x4E（≡ Set 1 KpAdd，与本表
        k if k == Key::Plus as u32 => 0x4E,        // KEY_KPPLUS
        // KEY_KPASTERISK=55=0x37（input-event-codes.h 中紧邻
        // KEY_LEFTALT=56=0x38 之前——本表 Alt=0x38 锚点互证）；
        // KEY_KPDOT=83=0x53（小键盘块尾，F11=87=0x57 之前 0x54-0x56
        // 空位区——本表 F11=0x57 锚点互证）。
        k if k == Key::KpMultiply as u32 => 0x37,  // KEY_KPASTERISK
        k if k == Key::KpDecimal as u32 => 0x53,   // KEY_KPDOT
        // ⚠ **V2-C 别名钉死**：Linux 头文件中 KEY_NUMLOCK 与 KEY_KPPLUS
        // 为**同值别名**（均 0x4E=78）→ 本行与上方 `Key::Plus` 臂
        // （KEY_KPPLUS，:353）刻意同值——两物理键共用一个内核键码，由
        // Key 判别式区分，**不是**映射冲突。未来映射调整不得把「同值」
        // 当冲突改掉任一臂；语义由单测 `r89_map_keycode_numlock` 钉死
        // （Windows 主战场无此别名：Set 1 0x45 非扩展域空位）。
        k if k == Key::NumLock as u32 => 0x4E,     // KEY_NUMLOCK（≡ KEY_KPPLUS 同值别名）
        _ => return None,
    })
}

/// 把一条 [`PipeEvent`] 展开成 `input_event` 序列（纯函数，可跨平台单测）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn build_events(ev: &PipeEvent) -> Vec<input_event> {
    let mut out = Vec::new();
    match ev.kind {
        InputKind::MouseMove => {
            out.push(input_event::new(EV_ABS, ABS_X, ev.x as i32));
            out.push(input_event::new(EV_ABS, ABS_Y, ev.y as i32));
            out.push(input_event::new(EV_SYN, 0, 0));
        }
        InputKind::MouseButton => {
            // button 低 3 位选按键，bit 7（RELEASE）= 抬起（value=0）。
            let released = ev.button & button::RELEASE != 0;
            let code = if ev.button & button::LEFT != 0 {
                BTN_LEFT
            } else if ev.button & button::RIGHT != 0 {
                BTN_RIGHT
            } else if ev.button & button::MIDDLE != 0 {
                BTN_MIDDLE
            } else {
                return out; // 无按键位：上层应已拒绝
            };
            out.push(input_event::new(EV_KEY, code, if released { 0 } else { 1 }));
            out.push(input_event::new(EV_SYN, 0, 0));
        }
        InputKind::MouseWheel => {
            out.push(input_event::new(EV_REL, REL_WHEEL, ev.wheel_delta));
            out.push(input_event::new(EV_SYN, 0, 0));
        }
        // 恒等映射把管线判别式当内核键码 = 普通键错键；未覆盖键不产生
        // 事件，优于旧实现的垃圾码）。
        InputKind::KeyDown | InputKind::KeyUp | InputKind::KeyRepeat => {
            let Some(code) = map_keycode(ev.key) else {
                return out; // 未覆盖键：不注入（上层/审计面同 button 分支口径）
            };
            let value = match ev.kind {
                InputKind::KeyDown => 1,
                InputKind::KeyUp => 0,
                InputKind::KeyRepeat => 2,
                _ => unreachable!("build_events 键盘分支已穷尽键事件 kind"),
            };
            out.push(input_event::new(EV_KEY, code, value));
            out.push(input_event::new(EV_SYN, 0, 0));
        }
        // M8-T020 SRV-SKEY-013: 特殊键组合序列（uinput EV_KEY + SYN）。
        // LockScreen 由 inject() 提前拦截走 loginctl，不会到达这里（空序列兜底）。
        InputKind::SpecialKey => {
            out.extend(special_key_events(ev.combo));
        }
        // Text：inject() 入口已提前拦截（UnsupportedPlatform），此处为穷尽匹配留空。
        InputKind::Text => {}
    }
    out
}

/// 纯函数：`SpecialCombo` → `input_event` 序列（EV_KEY + SYN，可跨平台单测）。
///
/// 序列为「修饰键按住 → 主键按下 → 主键抬起 → 修饰键抬起」（SRV-SKEY-016：
/// 释放步固定最后）。`None`（SpecialKey 缺 combo，由 inject() 拦截）或
/// `LockScreen`（非注入路径）→ 空序列。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn special_key_events(combo: Option<SpecialCombo>) -> Vec<input_event> {
    // input-event-codes.h：KEY_LEFTMETA=0x7D / KEY_LEFTCTRL=0x1D / KEY_LEFTSHIFT=0x2A /
    // KEY_LEFTALT=0x38 / KEY_TAB=0x0F / KEY_ESC=0x01 / KEY_F4=0x3E / KEY_E=0x12 /
    // KEY_D=0x20 / KEY_L=0x26 / KEY_R=0x13。
    const KEY_LEFTMETA: u16 = 0x7D;
    const KEY_LEFTCTRL: u16 = 0x1D;
    const KEY_LEFTSHIFT: u16 = 0x2A;
    const KEY_LEFTALT: u16 = 0x38;
    const KEY_TAB: u16 = 0x0F;
    const KEY_ESC: u16 = 0x01;
    const KEY_F4: u16 = 0x3E;
    const KEY_E: u16 = 0x12;
    const KEY_D: u16 = 0x20;
    const KEY_L: u16 = 0x26;
    const KEY_R: u16 = 0x13;

    let seq: &[(u16, i32)] = match combo {
        Some(SpecialCombo::WinE) => {
            &[(KEY_LEFTMETA, 1), (KEY_E, 1), (KEY_E, 0), (KEY_LEFTMETA, 0)]
        }
        Some(SpecialCombo::WinD) => {
            &[(KEY_LEFTMETA, 1), (KEY_D, 1), (KEY_D, 0), (KEY_LEFTMETA, 0)]
        }
        Some(SpecialCombo::WinL) => {
            &[(KEY_LEFTMETA, 1), (KEY_L, 1), (KEY_L, 0), (KEY_LEFTMETA, 0)]
        }
        Some(SpecialCombo::WinR) => {
            &[(KEY_LEFTMETA, 1), (KEY_R, 1), (KEY_R, 0), (KEY_LEFTMETA, 0)]
        }
        Some(SpecialCombo::AltTab) => {
            &[(KEY_LEFTALT, 1), (KEY_TAB, 1), (KEY_TAB, 0), (KEY_LEFTALT, 0)]
        }
        Some(SpecialCombo::CtrlShiftEsc) => &[
            (KEY_LEFTCTRL, 1),
            (KEY_LEFTSHIFT, 1),
            (KEY_ESC, 1),
            (KEY_ESC, 0),
            (KEY_LEFTSHIFT, 0),
            (KEY_LEFTCTRL, 0),
        ],
        Some(SpecialCombo::AltF4) => {
            &[(KEY_LEFTALT, 1), (KEY_F4, 1), (KEY_F4, 0), (KEY_LEFTALT, 0)]
        }
        Some(SpecialCombo::CtrlEsc) => {
            &[(KEY_LEFTCTRL, 1), (KEY_ESC, 1), (KEY_ESC, 0), (KEY_LEFTCTRL, 0)]
        }
        // 锁屏走 loginctl（inject() 提前拦截）；缺 combo 由 inject() 拒绝。
        Some(SpecialCombo::LockScreen) | None => &[],
    };
    let mut out = Vec::with_capacity(seq.len() * 2);
    for &(code, value) in seq {
        out.push(input_event::new(EV_KEY, code, value));
        out.push(input_event::new(EV_SYN, 0, 0));
    }
    out
}

/// 非 Linux 平台桩：注入不可用（不阻断编译，返回明确错误）。
#[cfg(not(target_os = "linux"))]
pub fn inject(_ev: &PipeEvent, _dst_w: u32, _dst_h: u32) -> Result<(), InjectError> {
    Err(InjectError::UnsupportedPlatform(
        "Linux uinput injection not available on this target".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uinput_event_layout() {
        // input_event 结构体字段值 / 布局正确（64 位 ABI：24 字节）。
        let ev = input_event::new(EV_KEY, BTN_LEFT, 1);
        assert_eq!(ev.kind, EV_KEY);
        assert_eq!(ev.code, BTN_LEFT);
        assert_eq!(ev.value, 1);
        // 常量值与内核对齐。
        assert_eq!(EV_KEY, 0x01);
        assert_eq!(EV_ABS, 0x03);
        assert_eq!(EV_REL, 0x02);
        assert_eq!(ABS_X, 0x00);
        assert_eq!(ABS_Y, 0x01);
        assert_eq!(REL_WHEEL, 0x08);
        assert_eq!(BTN_LEFT, 0x110);
        assert_eq!(BTN_RIGHT, 0x111);
        assert_eq!(BTN_MIDDLE, 0x112);
        // 大小检查（64 位 Linux ABI 为 24 字节；此处仅断言已知值，不强制跨平台一致）。
        #[cfg(target_pointer_width = "64")]
        assert_eq!(std::mem::size_of::<input_event>(), 24);
    }

    #[test]
    fn test_uinput_no_device() {
        // 无 /dev/uinput（Windows 主机走 not-linux 桩）→ 明确错误，不 panic。
        let ev = PipeEvent {
            kind: InputKind::MouseMove,
            x: 100,
            y: 100,
            button: 0,
            key: 0,
            wheel_delta: 0,
            modifiers: 0,
            text: String::new(),
            combo: None,
        };
        let res = inject(&ev, 1920, 1080);
        let err = res.unwrap_err();
        assert!(
            matches!(err, InjectError::UnsupportedPlatform(_)),
            "expected UnsupportedPlatform, got {err:?}"
        );
    }

    #[test]
    fn test_build_events_move() {
        // Move → ABS_X + ABS_Y + SYN。
        let ev = PipeEvent {
            kind: InputKind::MouseMove,
            x: 500,
            y: 250,
            button: 0,
            key: 0,
            wheel_delta: 0,
            modifiers: 0,
            text: String::new(),
            combo: None,
        };
        let evs = build_events(&ev);
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0], input_event::new(EV_ABS, ABS_X, 500));
        assert_eq!(evs[1], input_event::new(EV_ABS, ABS_Y, 250));
        assert_eq!(evs[2], input_event::new(EV_SYN, 0, 0));
    }

    #[test]
    fn test_build_events_button() {
        let ev = PipeEvent {
            kind: InputKind::MouseButton,
            x: 0,
            y: 0,
            button: button::RIGHT,
            key: 0,
            wheel_delta: 0,
            modifiers: 0,
            text: String::new(),
            combo: None,
        };
        let evs = build_events(&ev);
        assert_eq!(evs[0], input_event::new(EV_KEY, BTN_RIGHT, 1));
    }

    /// M8-T020 T003: Win 组合 → KEY_LEFTMETA + 主键（按住→点按→释放）。
    #[test]
    fn test_special_key_events_win_combos() {
        let evs = special_key_events(Some(SpecialCombo::WinE));
        assert_eq!(evs.len(), 8); // 4 步 × (EV_KEY + SYN)
        assert_eq!(evs[0], input_event::new(EV_KEY, 0x7D, 1)); // KEY_LEFTMETA down
        assert_eq!(evs[1], input_event::new(EV_SYN, 0, 0));
        assert_eq!(evs[2], input_event::new(EV_KEY, 0x12, 1)); // KEY_E down
        assert_eq!(evs[4], input_event::new(EV_KEY, 0x12, 0)); // KEY_E up
        assert_eq!(evs[6], input_event::new(EV_KEY, 0x7D, 0)); // KEY_LEFTMETA up（最后释放）
        assert_eq!(evs[7], input_event::new(EV_SYN, 0, 0));
    }

    // ========================================================================
    // ========================================================================

    /// XT 区段 ≡ PS/2 Set 1，与 `windows::map_scan_code` 交叉核验值一致）
    /// + 4 无独立物理键别名 + 既有键映射零回归抽查。
    #[test]
    fn r85d_map_keycode_punctuation() {
        assert_eq!(map_keycode(Key::Minus as u32), Some(0x0C), "KEY_MINUS");
        assert_eq!(map_keycode(Key::Equals as u32), Some(0x0D), "KEY_EQUAL");
        assert_eq!(map_keycode(Key::OpenBracket as u32), Some(0x1A), "KEY_LEFTBRACE");
        assert_eq!(map_keycode(Key::CloseBracket as u32), Some(0x1B), "KEY_RIGHTBRACE");
        assert_eq!(map_keycode(Key::Semicolon as u32), Some(0x27), "KEY_SEMICOLON");
        assert_eq!(map_keycode(Key::Quote as u32), Some(0x28), "KEY_APOSTROPHE");
        assert_eq!(map_keycode(Key::Backtick as u32), Some(0x29), "KEY_GRAVE");
        assert_eq!(map_keycode(Key::Backslash as u32), Some(0x2B), "KEY_BACKSLASH");
        assert_eq!(map_keycode(Key::Comma as u32), Some(0x33), "KEY_COMMA");
        assert_eq!(map_keycode(Key::Period as u32), Some(0x34), "KEY_DOT");
        assert_eq!(map_keycode(Key::Slash as u32), Some(0x35), "KEY_SLASH");
        // 3 无独立物理键 → 相邻物理键键码（与 windows/macOS 别名口径一致）。
        assert_eq!(map_keycode(Key::Colon as u32), Some(0x27), "':' → KEY_SEMICOLON");
        assert_eq!(map_keycode(Key::Pipe as u32), Some(0x2B), "'|' → KEY_BACKSLASH");
        assert_eq!(map_keycode(Key::Questionmark as u32), Some(0x35), "'?' → KEY_SLASH");
        // 断言随定案修改，见 `r86_map_keycode_plus_kp_and_kpdecimal`。
        // 既有键零回归抽查（修复前恒等映射为错键：Key::A=0x04 ≠ KEY_A=30）。
        assert_eq!(map_keycode(Key::A as u32), Some(0x1E), "KEY_A");
        assert_eq!(map_keycode(Key::Z as u32), Some(0x2C), "KEY_Z");
        assert_eq!(map_keycode(Key::Num1 as u32), Some(0x02), "KEY_1");
        assert_eq!(map_keycode(Key::Num0 as u32), Some(0x0B), "KEY_0");
        assert_eq!(map_keycode(Key::Enter as u32), Some(0x1C), "KEY_ENTER");
        assert_eq!(map_keycode(Key::Space as u32), Some(0x39), "KEY_SPACE");
        assert_eq!(map_keycode(Key::Ctrl as u32), Some(0x1D), "KEY_LEFTCTRL");
        assert_eq!(map_keycode(Key::Shift as u32), Some(0x2A), "KEY_LEFTSHIFT");
        assert_eq!(map_keycode(Key::Alt as u32), Some(0x38), "KEY_LEFTALT");
        assert_eq!(map_keycode(Key::Super as u32), Some(0x7D), "KEY_LEFTMETA");
        // 未覆盖键 → None（不发垃圾码）。
        assert_eq!(map_keycode(0xFFFF_FFFF), None);
    }

    // ========================================================================
    // ========================================================================

    /// 互证）+ 小键盘专用键 KEY_KPASTERISK=0x37（Alt=0x38 锚点）/
    /// KEY_KPDOT=0x53（F11=0x57 空位区锚点）；既有键零回归抽查。
    #[test]
    fn r86_map_keycode_plus_kp_and_kpdecimal() {
        assert_eq!(map_keycode(Key::Plus as u32), Some(0x4E), "KEY_KPPLUS");
        assert_eq!(map_keycode(Key::KpMultiply as u32), Some(0x37), "KEY_KPASTERISK");
        assert_eq!(map_keycode(Key::KpDecimal as u32), Some(0x53), "KEY_KPDOT");
        // 既有键零回归（锚点键位保持）。
        assert_eq!(map_keycode(Key::Alt as u32), Some(0x38), "KEY_LEFTALT（0x37 邻键）");
        assert_eq!(map_keycode(Key::F11 as u32), Some(0x57), "KEY_F11（0x53 块后）");
        assert_eq!(map_keycode(Key::Equals as u32), Some(0x0D), "KEY_EQUAL 保持");
        assert_eq!(map_keycode(Key::A as u32), Some(0x1E), "KEY_A");
        // 未覆盖键 → None。
        assert_eq!(map_keycode(0xFFFF_FFFF), None);
    }

    /// 核验）+ **V2-C 别名钉死**——Linux 头文件 KEY_NUMLOCK 与 KEY_KPPLUS
    /// 同值（0x4E=78，两物理键共用一个内核键码）：本测试断言两判别式
    /// 映射**同值**，防未来映射调整把别名当冲突改掉任一臂（Windows
    /// 主战场无此别名，见 windows.rs `r89_map_scan_code_numlock`）。
    #[test]
    fn r89_map_keycode_numlock() {
        assert_eq!(map_keycode(Key::NumLock as u32), Some(0x4E), "KEY_NUMLOCK");
        // V2-C 别名钉死：NumLock 与 Plus(KpAdd) 同值 = 权威表 KEY_NUMLOCK
        // ≡ KEY_KPPLUS 同值别名的映射层表达。
        assert_eq!(
            map_keycode(Key::NumLock as u32),
            map_keycode(Key::Plus as u32),
            "V2-C：KEY_NUMLOCK ≡ KEY_KPPLUS 同值别名（0x4E）"
        );
        assert_eq!(map_keycode(Key::Plus as u32), Some(0x4E), "KEY_KPPLUS 保持");
        // 既有键零回归（邻键锚点）。
        assert_eq!(map_keycode(Key::KpMultiply as u32), Some(0x37), "KEY_KPASTERISK 保持");
        assert_eq!(map_keycode(Key::KpDecimal as u32), Some(0x53), "KEY_KPDOT 保持");
        assert_eq!(map_keycode(Key::CapsLock as u32), Some(0x3A), "KEY_CAPSLOCK（toggle 对）");
        // 未覆盖键 → None。
        assert_eq!(map_keycode(0xFFFF_FFFF), None);
    }

    /// EV_KEY(KEY_DOT, 1) + SYN（修复前为 `ev.key as u16`=0x57 错键码）。
    #[test]
    fn r85d_build_events_keydown_uses_mapped_code() {
        let ev = PipeEvent::key(InputKind::KeyDown, Key::Period, 0);
        let evs = build_events(&ev);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0], input_event::new(EV_KEY, 0x34, 1)); // KEY_DOT down
        assert_eq!(evs[1], input_event::new(EV_SYN, 0, 0));

        let ev = PipeEvent::key(InputKind::KeyUp, Key::Comma, 0);
        let evs = build_events(&ev);
        assert_eq!(evs[0], input_event::new(EV_KEY, 0x33, 0)); // KEY_COMMA up

        // 未知键码 → 空序列（不发垃圾码）。
        let unknown = PipeEvent {
            kind: InputKind::KeyDown,
            x: 0,
            y: 0,
            button: 0,
            key: 0xFFFF_FFFF,
            wheel_delta: 0,
            modifiers: 0,
            text: String::new(),
            combo: None,
        };
        assert!(build_events(&unknown).is_empty());
    }

    /// M8-T020 T003: Ctrl+Shift+Esc 六步序列；LockScreen/缺 combo → 空序列。
    #[test]
    fn test_special_key_events_misc() {
        let evs = special_key_events(Some(SpecialCombo::CtrlShiftEsc));
        assert_eq!(evs.len(), 12);
        assert_eq!(evs[0], input_event::new(EV_KEY, 0x1D, 1)); // KEY_LEFTCTRL
        assert_eq!(evs[2], input_event::new(EV_KEY, 0x2A, 1)); // KEY_LEFTSHIFT
        assert_eq!(evs[4], input_event::new(EV_KEY, 0x01, 1)); // KEY_ESC
        // 释放序：ESC → SHIFT → CTRL（逆序释放，末尾修饰键抬起）。
        assert_eq!(evs[10], input_event::new(EV_KEY, 0x1D, 0));

        let evs = special_key_events(Some(SpecialCombo::AltTab));
        assert_eq!(evs.len(), 8);
        assert_eq!(evs[0], input_event::new(EV_KEY, 0x38, 1)); // KEY_LEFTALT
        assert_eq!(evs[6], input_event::new(EV_KEY, 0x38, 0));

        // LockScreen 非注入路径（inject() 拦截走 loginctl）；缺 combo 空序列。
        assert!(special_key_events(Some(SpecialCombo::LockScreen)).is_empty());
        assert!(special_key_events(None).is_empty());
    }
}
