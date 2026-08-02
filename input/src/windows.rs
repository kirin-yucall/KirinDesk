// 注：`MouseButton` 仅 cfg(windows) 的 inject_input 使用；非 Windows target 上
// 为死导入（同 linux.rs 的 cfg_attr 模式，抑制警告）。
#[cfg_attr(not(target_os = "windows"), allow(unused_imports))]
use crate::capture::{InputEvent, MouseButton};

/// Inject a remote input event on Windows using SendInput.
#[cfg(target_os = "windows")]
pub fn inject_input(event: &InputEvent) -> Result<(), String> {
    use winapi::um::winuser::{
        SendInput, INPUT, INPUT_KEYBOARD, INPUT_MOUSE,
        KEYBDINPUT, MOUSEINPUT,
        MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
        MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP,
        MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
        MOUSEEVENTF_WHEEL,
        KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
        INPUT_u,
    };

    let mut inputs: Vec<INPUT> = Vec::new();

    match event {
        InputEvent::MouseMove { x, y } => {
            let abs_x = (x * 65535.0) as u32;
            let abs_y = (y * 65535.0) as u32;
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe { *u.mi_mut() = MOUSEINPUT {
                dx: abs_x as i32,
                dy: abs_y as i32,
                mouseData: 0,
                dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                time: 0,
                dwExtraInfo: 0,
            }; }
            inputs.push(INPUT { type_: INPUT_MOUSE, u });
        }
        InputEvent::MouseButton { button, pressed } => {
            let flags = match (button, pressed) {
                (MouseButton::Left, true) => MOUSEEVENTF_LEFTDOWN,
                (MouseButton::Left, false) => MOUSEEVENTF_LEFTUP,
                (MouseButton::Right, true) => MOUSEEVENTF_RIGHTDOWN,
                (MouseButton::Right, false) => MOUSEEVENTF_RIGHTUP,
                (MouseButton::Middle, true) => MOUSEEVENTF_MIDDLEDOWN,
                (MouseButton::Middle, false) => MOUSEEVENTF_MIDDLEUP,
            };
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe { *u.mi_mut() = MOUSEINPUT { dx: 0, dy: 0, mouseData: 0, dwFlags: flags, time: 0, dwExtraInfo: 0 }; }
            inputs.push(INPUT { type_: INPUT_MOUSE, u });
        }
        InputEvent::MouseWheel { delta } => {
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe { *u.mi_mut() = MOUSEINPUT { dx: 0, dy: 0, mouseData: *delta as u32, dwFlags: MOUSEEVENTF_WHEEL, time: 0, dwExtraInfo: 0 }; }
            inputs.push(INPUT { type_: INPUT_MOUSE, u });
        }
        InputEvent::Key { key, pressed } => {
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe { *u.ki_mut() = KEYBDINPUT { wVk: *key, wScan: 0, dwFlags: if *pressed { 0 } else { KEYEVENTF_KEYUP }, time: 0, dwExtraInfo: 0 }; }
            inputs.push(INPUT { type_: INPUT_KEYBOARD, u });
        }
        InputEvent::Text { chars } => {
            for ch in chars.encode_utf16() {
                let mut u1 = unsafe { std::mem::zeroed::<INPUT_u>() };
                unsafe { *u1.ki_mut() = KEYBDINPUT { wVk: 0, wScan: ch, dwFlags: KEYEVENTF_UNICODE, time: 0, dwExtraInfo: 0 }; }
                inputs.push(INPUT { type_: INPUT_KEYBOARD, u: u1 });

                let mut u2 = unsafe { std::mem::zeroed::<INPUT_u>() };
                unsafe { *u2.ki_mut() = KEYBDINPUT { wVk: 0, wScan: ch, dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, time: 0, dwExtraInfo: 0 }; }
                inputs.push(INPUT { type_: INPUT_KEYBOARD, u: u2 });
            }
        }
    }

    unsafe {
        SendInput(inputs.len() as u32, inputs.as_mut_ptr(), std::mem::size_of::<INPUT>() as i32);
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn inject_input(_event: &InputEvent) -> Result<(), String> {
    Err("Input injection requires Windows".to_string())
}

// ============================================================================
// 注入流水线 API（M8-T008_P1E，Task T5.2）：面向 `injector::InputEvent`
// 与上面的旧 `inject_input(&capture::InputEvent)` 并列独立。
// ============================================================================

#[cfg_attr(not(target_os = "windows"), allow(unused_imports))]
use crate::injector::{button, InjectError, InputEvent as PipeEvent, InputKind, Key, SpecialCombo};

/// 把服务端像素坐标归一化到 SendInput 的 `0..=65535` 绝对坐标空间。
///
/// 公式（spec Task T5.2）：`x * 65535 / (dst - 1)`，配合 `MOUSEEVENTF_ABSOLUTE`。
/// - `dst <= 1`（退化分辨率）→ 返回 `0`，避免除零。
/// - 调用方应已将 `x` clamp 到 `[0, dst-1]`；此处再做一次防御性 clamp。
#[cfg(target_os = "windows")]
pub fn normalize_coord(x: u32, dst: u32) -> u32 {
    if dst <= 1 {
        return 0;
    }
    let clamped = x.min(dst - 1);
    // u32 乘法可能溢出（65535 * 大 dst），用 u64 计算。
    ((clamped as u64 * 65535) / (dst as u64 - 1)) as u32
}

/// 非 Windows 平台同款纯函数（供跨平台单测；注入本身由 `inject` 桩拒绝）。
#[cfg(not(target_os = "windows"))]
pub fn normalize_coord(x: u32, dst: u32) -> u32 {
    if dst <= 1 {
        return 0;
    }
    let clamped = x.min(dst - 1);
    ((clamped as u64 * 65535) / (dst as u64 - 1)) as u32
}

/// [`Key`] → PS/2 scan code（用于 `KEYEVENTF_SCANCODE`，不受键盘布局影响）。
///
/// 返回 `Some(u16)`：普通键为 set 1 make code；扩展键（方向/导航）高位带 `0xE0` 标记，
/// 注入时配合 `KEYEVENTF_EXTENDEDKEY`。未覆盖键 → `None`（上层报 [`InjectError::InvalidEvent`]）。
pub fn map_scan_code(key: u32) -> Option<u16> {
    // 扩展键前缀标记：放在高位字节（scan = 0xE0xx），注入时拆出低字节 + KEYEVENTF_EXTENDEDKEY。
    const EXTENDED: u16 = 0xE000;
    Some(match key {
        // 字母 A-Z
        k if k == Key::A as u32 => 0x1E,
        k if k == Key::B as u32 => 0x30,
        k if k == Key::C as u32 => 0x2E,
        k if k == Key::D as u32 => 0x20,
        k if k == Key::E as u32 => 0x12,
        k if k == Key::F as u32 => 0x21,
        k if k == Key::G as u32 => 0x22,
        k if k == Key::H as u32 => 0x23,
        k if k == Key::I as u32 => 0x17,
        k if k == Key::J as u32 => 0x24,
        k if k == Key::K as u32 => 0x25,
        k if k == Key::L as u32 => 0x26,
        k if k == Key::M as u32 => 0x32,
        k if k == Key::N as u32 => 0x31,
        k if k == Key::O as u32 => 0x18,
        k if k == Key::P as u32 => 0x19,
        k if k == Key::Q as u32 => 0x10,
        k if k == Key::R as u32 => 0x13,
        k if k == Key::S as u32 => 0x1F,
        k if k == Key::T as u32 => 0x14,
        k if k == Key::U as u32 => 0x16,
        k if k == Key::V as u32 => 0x2F,
        k if k == Key::W as u32 => 0x11,
        k if k == Key::X as u32 => 0x2D,
        k if k == Key::Y as u32 => 0x15,
        k if k == Key::Z as u32 => 0x2C,
        // 数字 0-9
        k if k == Key::Num1 as u32 => 0x02,
        k if k == Key::Num2 as u32 => 0x03,
        k if k == Key::Num3 as u32 => 0x04,
        k if k == Key::Num4 as u32 => 0x05,
        k if k == Key::Num5 as u32 => 0x06,
        k if k == Key::Num6 as u32 => 0x07,
        k if k == Key::Num7 as u32 => 0x08,
        k if k == Key::Num8 as u32 => 0x09,
        k if k == Key::Num9 as u32 => 0x0A,
        k if k == Key::Num0 as u32 => 0x0B,
        // 控制键
        k if k == Key::Enter as u32 => 0x1C,
        k if k == Key::Esc as u32 => 0x01,
        k if k == Key::Backspace as u32 => 0x0E,
        k if k == Key::Tab as u32 => 0x0F,
        k if k == Key::Space as u32 => 0x39,
        k if k == Key::CapsLock as u32 => 0x3A,
        // F1-F12
        k if k == Key::F1 as u32 => 0x3B,
        k if k == Key::F2 as u32 => 0x3C,
        k if k == Key::F3 as u32 => 0x3D,
        k if k == Key::F4 as u32 => 0x3E,
        k if k == Key::F5 as u32 => 0x3F,
        k if k == Key::F6 as u32 => 0x40,
        k if k == Key::F7 as u32 => 0x41,
        k if k == Key::F8 as u32 => 0x42,
        k if k == Key::F9 as u32 => 0x43,
        k if k == Key::F10 as u32 => 0x44,
        k if k == Key::F11 as u32 => 0x57,
        k if k == Key::F12 as u32 => 0x58,
        // 扩展键（导航 / 方向）
        k if k == Key::Insert as u32 => EXTENDED | 0x52,
        k if k == Key::Home as u32 => EXTENDED | 0x47,
        k if k == Key::PageUp as u32 => EXTENDED | 0x49,
        k if k == Key::Delete as u32 => EXTENDED | 0x53,
        k if k == Key::End as u32 => EXTENDED | 0x4F,
        k if k == Key::PageDown as u32 => EXTENDED | 0x51,
        k if k == Key::Right as u32 => EXTENDED | 0x4D,
        k if k == Key::Left as u32 => EXTENDED | 0x4B,
        k if k == Key::Down as u32 => EXTENDED | 0x50,
        k if k == Key::Up as u32 => EXTENDED | 0x48,
        _ => return None,
    })
}

/// 注入流水线入口（Task T5.2）：把一条 [`PipeEvent`] 注入 Windows。
///
/// - `ev.x / ev.y` 已由 [`crate::injector::InputInjector`] 缩放到 `dst_w × dst_h` 像素空间。
/// - 一次 `SendInput` 批量注入（同事件合并，减 IPC / 内核往返）。
/// - 键盘使用 scan code（`KEYEVENTF_SCANCODE`，不受布局影响）；扩展键加 `KEYEVENTF_EXTENDEDKEY`。
/// - `SendInput` 返回 0（注入失败，如 UIPI 权限 / RDP 会话拒绝）→ [`InjectError::InjectFailed`]。
#[cfg(target_os = "windows")]
pub fn inject(ev: &PipeEvent, dst_w: u32, dst_h: u32) -> Result<(), InjectError> {
    use winapi::shared::minwindef::DWORD;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::winuser::{
        SendInput, INPUT, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, MOUSEINPUT, INPUT_u,
        KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE,
        MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
        MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
        MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_WHEEL,
    };

    let mut inputs: Vec<INPUT> = Vec::new();

    match ev.kind {
        InputKind::MouseMove => {
            let abs_x = normalize_coord(ev.x, dst_w);
            let abs_y = normalize_coord(ev.y, dst_h);
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe {
                *u.mi_mut() = MOUSEINPUT {
                    dx: abs_x as i32,
                    dy: abs_y as i32,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                    time: 0,
                    dwExtraInfo: 0,
                };
            }
            inputs.push(INPUT { type_: INPUT_MOUSE, u });
        }
        InputKind::MouseButton => {
            // button 低 3 位选按键（1/2/4），bit 7（RELEASE）= 抬起。
            let released = ev.button & button::RELEASE != 0;
            let flags: DWORD = if ev.button & button::LEFT != 0 {
                if released { MOUSEEVENTF_LEFTUP } else { MOUSEEVENTF_LEFTDOWN }
            } else if ev.button & button::RIGHT != 0 {
                if released { MOUSEEVENTF_RIGHTUP } else { MOUSEEVENTF_RIGHTDOWN }
            } else if ev.button & button::MIDDLE != 0 {
                if released { MOUSEEVENTF_MIDDLEUP } else { MOUSEEVENTF_MIDDLEDOWN }
            } else {
                // 无按键位：非法事件。
                return Err(InjectError::InvalidEvent(format!(
                    "mouse button event with no button bit: {}",
                    ev.button
                )));
            };
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe {
                *u.mi_mut() = MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                };
            }
            inputs.push(INPUT { type_: INPUT_MOUSE, u });
        }
        InputKind::MouseWheel => {
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe {
                *u.mi_mut() = MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: ev.wheel_delta as u32,
                    dwFlags: MOUSEEVENTF_WHEEL,
                    time: 0,
                    dwExtraInfo: 0,
                };
            }
            inputs.push(INPUT { type_: INPUT_MOUSE, u });
        }
        InputKind::Text => {
            // Unicode 文本（IME 中文/粘贴）：KEYEVENTF_UNICODE 逐 UTF-16 单元注入。
            // 与上游旧 inject_input 的 Text 分支同模式。
            let mut count = 0u32;
            for unit in ev.text.encode_utf16() {
                let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
                unsafe {
                    *u.ki_mut() = KEYBDINPUT {
                        wVk: 0,
                        wScan: unit,
                        dwFlags: KEYEVENTF_UNICODE,
                        time: 0,
                        dwExtraInfo: 0,
                    };
                }
                inputs.push(INPUT { type_: INPUT_KEYBOARD, u });
                count += 1;
            }
            if count == 0 {
                return Err(InjectError::InvalidEvent(
                    "Text event with empty text".to_string(),
                ));
            }
        }
        InputKind::KeyDown | InputKind::KeyUp | InputKind::KeyRepeat => {
            let scan = map_scan_code(ev.key).ok_or_else(|| {
                InjectError::InvalidEvent(format!("no scan code mapping for key {}", ev.key))
            })?;
            // 扩展键（方向/导航）：scan 高字节为 0xE0（如 0xE04D=Right）→ 用低字节 + EXTENDEDKEY 标志。
            let (scan_lo, mut flags): (u16, DWORD) = if (scan & 0xFF00) == 0xE000 {
                (scan & 0x00FF, KEYEVENTF_EXTENDEDKEY)
            } else {
                (scan, 0)
            };
            flags |= KEYEVENTF_SCANCODE;
            // 抬起：KeyUp。KeyRepeat 由系统按键重复机制产生（同 down + 持续），这里发 down。
            if matches!(ev.kind, InputKind::KeyUp) {
                flags |= KEYEVENTF_KEYUP;
            }
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe {
                *u.ki_mut() = KEYBDINPUT {
                    wVk: 0,
                    wScan: scan_lo,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                };
            }
            inputs.push(INPUT { type_: INPUT_KEYBOARD, u });
        }
        InputKind::SpecialKey => {
            // M8-T020: 系统组合键——独立序列注入（含 Alt+Tab 延迟 / 锁屏非注入路径）。
            let combo = ev.combo.ok_or_else(|| {
                InjectError::InvalidEvent("SpecialKey event without combo".to_string())
            })?;
            return inject_special_key(combo);
        }
    }

    // 一次 SendInput 批注入（合并同批，减内核往返）。
    let sent = unsafe {
        SendInput(
            inputs.len() as u32,
            inputs.as_mut_ptr(),
            std::mem::size_of::<INPUT>() as i32,
        )
    };
    if sent == 0 {
        let err = unsafe { GetLastError() };
        // SendInput 返回 0：UIPI 权限 / RDP 注入被拒等 → 记日志不重试（用户操作不可重放）。
        return Err(InjectError::InjectFailed(format!(
            "SendInput returned 0 (GetLastError={})",
            err
        )));
    }
    Ok(())
}

// ============================================================================
// M8-T020 特殊键注入（SRV-SKEY-010/011/012/016）
// ============================================================================

/// PS/2 Set 1 扫描码（KEYEVENTF_SCANCODE 注入，规避 Windows 10+ 对
/// Win 键组合注入的拦截）。`0xE0` 前缀键（左 Win）走 `extended` 标记。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod scan {
    pub const LWIN: u16 = 0x5B; // 扩展键（E0 5B）
    pub const LCTRL: u16 = 0x1D;
    pub const LSHIFT: u16 = 0x2A;
    pub const LALT: u16 = 0x38;
    pub const TAB: u16 = 0x0F;
    pub const ESC: u16 = 0x01;
    pub const F4: u16 = 0x3E;
    pub const E: u16 = 0x12;
    pub const D: u16 = 0x20;
    pub const L: u16 = 0x26;
    pub const R: u16 = 0x13;
}

/// Alt+Tab 序列批间延迟（Alt 按下 → 100ms → Tab 按下，SRV-SKEY-011）。
const ALT_TAB_DELAY_MS: u64 = 100;

/// 一次键盘注入动作（扫描码 → KEYBDINPUT）。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kbd {
    /// PS/2 Set 1 make code 低字节。
    pub scan_lo: u16,
    /// 扩展键（0xE0 前缀，如左 Win 键）。
    pub extended: bool,
    /// 抬起（KEYEVENTF_KEYUP）。
    pub up: bool,
}

impl Kbd {
    pub const fn down(scan_lo: u16) -> Self {
        Self { scan_lo, extended: false, up: false }
    }
    pub const fn up(scan_lo: u16) -> Self {
        Self { scan_lo, extended: false, up: true }
    }
    /// 扩展键按下（0xE0 前缀键，如左 Win）。
    pub const fn ext_down(scan_lo: u16) -> Self {
        Self { scan_lo, extended: true, up: false }
    }
    /// 扩展键抬起。
    pub const fn ext_up(scan_lo: u16) -> Self {
        Self { scan_lo, extended: true, up: true }
    }
}

/// 特殊键注入计划：一或多批按键（每批一次 SendInput）+ 批间延迟。
/// `Lock` 为系统锁屏调用（非注入路径，SRV-SKEY-012）。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialKeyPlan {
    Keys {
        batches: Vec<Vec<Kbd>>,
        /// 批间延迟 ms（仅 AltTab > 0，SRV-SKEY-011）。
        inter_batch_delay_ms: u64,
    },
    Lock,
}

/// 纯函数：`SpecialCombo` → Windows 注入计划（跨平台可单测，T002）。
///
/// 序列均为「修饰键按住 → 主键按下 → 主键抬起 → 修饰键抬起」；
/// 释放步固定位于最后（SRV-SKEY-016：修饰键状态不粘连）。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn plan_special_key(combo: SpecialCombo) -> SpecialKeyPlan {
    use scan::*;
    use SpecialCombo::*;
    match combo {
        // Win 键组合：LWIN 是扩展键（0xE0 5B），其余键非扩展。
        WinE => keys4(Kbd::ext_down(LWIN), Kbd::ext_up(LWIN), E),
        WinD => keys4(Kbd::ext_down(LWIN), Kbd::ext_up(LWIN), D),
        WinL => keys4(Kbd::ext_down(LWIN), Kbd::ext_up(LWIN), L),
        WinR => keys4(Kbd::ext_down(LWIN), Kbd::ext_up(LWIN), R),
        // Alt+Tab：Alt 独立首批 → 100ms → Tab down/up + Alt up（释放批必达）。
        AltTab => SpecialKeyPlan::Keys {
            batches: vec![
                vec![Kbd::down(LALT)],
                vec![Kbd::down(TAB), Kbd::up(TAB), Kbd::up(LALT)],
            ],
            inter_batch_delay_ms: ALT_TAB_DELAY_MS,
        },
        // 任务管理器直达（CAC 替代路径）。
        CtrlShiftEsc => SpecialKeyPlan::Keys {
            batches: vec![vec![
                Kbd::down(LCTRL),
                Kbd::down(LSHIFT),
                Kbd::down(ESC),
                Kbd::up(ESC),
                Kbd::up(LSHIFT),
                Kbd::up(LCTRL),
            ]],
            inter_batch_delay_ms: 0,
        },
        AltF4 => keys3(LALT, F4),
        CtrlEsc => keys3(LCTRL, ESC),
        // 锁屏：非注入路径（LockWorkStation，SKEY-SEC-003 单一实现）。
        LockScreen => SpecialKeyPlan::Lock,
    }
}

/// 修饰键（按下）+ 主键（按下→抬起）+ 修饰键（抬起）单批序列。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn keys4(mod_down: Kbd, mod_up: Kbd, main: u16) -> SpecialKeyPlan {
    SpecialKeyPlan::Keys {
        batches: vec![vec![mod_down, Kbd::down(main), Kbd::up(main), mod_up]],
        inter_batch_delay_ms: 0,
    }
}

/// 非扩展修饰键 + 主键（同 [`keys4`]，修饰键无 0xE0 前缀）。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn keys3(mod_scan: u16, main: u16) -> SpecialKeyPlan {
    keys4(Kbd::down(mod_scan), Kbd::up(mod_scan), main)
}

/// 执行特殊键注入计划。
///
/// 失败语义（SRV-SKEY-015/016）：批间失败不中断后续批——**释放批必定执行**，
/// 保证任何异常路径下修饰键不粘连（Win 键不会卡在按下状态）。
#[cfg(target_os = "windows")]
fn inject_special_key(combo: SpecialCombo) -> Result<(), InjectError> {
    match plan_special_key(combo) {
        SpecialKeyPlan::Lock => crate::lock::lock_screen(),
        SpecialKeyPlan::Keys { batches, inter_batch_delay_ms } => {
            let mut first_err = None;
            for (i, batch) in batches.iter().enumerate() {
                if i > 0 && inter_batch_delay_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(inter_batch_delay_ms));
                }
                if let Err(e) = send_kbd_batch(batch) {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
            match first_err {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }
}

/// 一次 SendInput 批量注入（扫描码，无布局依赖）。
#[cfg(target_os = "windows")]
fn send_kbd_batch(keys: &[Kbd]) -> Result<(), InjectError> {
    use winapi::shared::minwindef::DWORD;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::winuser::{
        SendInput, INPUT, INPUT_KEYBOARD, KEYBDINPUT, INPUT_u, KEYEVENTF_EXTENDEDKEY,
        KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE,
    };
    let mut inputs: Vec<INPUT> = Vec::with_capacity(keys.len());
    for k in keys {
        let mut flags: DWORD = KEYEVENTF_SCANCODE;
        if k.extended {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        if k.up {
            flags |= KEYEVENTF_KEYUP;
        }
        let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
        unsafe {
            *u.ki_mut() = KEYBDINPUT {
                wVk: 0,
                wScan: k.scan_lo,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            };
        }
        inputs.push(INPUT { type_: INPUT_KEYBOARD, u });
    }
    let sent = unsafe {
        SendInput(
            inputs.len() as u32,
            inputs.as_mut_ptr(),
            std::mem::size_of::<INPUT>() as i32,
        )
    };
    if sent == 0 {
        let err = unsafe { GetLastError() };
        return Err(InjectError::InjectFailed(format!(
            "SendInput returned 0 (GetLastError={})",
            err
        )));
    }
    Ok(())
}

/// 非 Windows 平台桩：注入不可用（不阻断编译，返回明确错误）。
#[cfg(not(target_os = "windows"))]
pub fn inject(_ev: &PipeEvent, _dst_w: u32, _dst_h: u32) -> Result<(), InjectError> {
    Err(InjectError::UnsupportedPlatform(
        "Windows SendInput injection not available on this target".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_serialization() {
        let event = InputEvent::MouseMove { x: 0.5, y: 0.5 };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("MouseMove"));
    }

    #[test]
    fn test_key_event() {
        let event = InputEvent::Key { key: 0x41, pressed: true };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""key":65"#));
    }

    #[test]
    fn test_mouse_button_roundtrip() {
        let event = InputEvent::MouseButton { button: MouseButton::Left, pressed: true };
        let json = serde_json::to_string(&event).unwrap();
        let deser: InputEvent = serde_json::from_str(&json).unwrap();
        match deser {
            InputEvent::MouseButton { button, pressed } => {
                assert_eq!(button, MouseButton::Left);
                assert!(pressed);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_sendinput_absolute_coord() {
        // 归一化公式边界：x*65535/(dst-1)。
        // dst=1920：0→0，1919→65535，中间值单调递增。
        assert_eq!(normalize_coord(0, 1920), 0);
        assert_eq!(normalize_coord(1919, 1920), 65535);
        let mid_lo = normalize_coord(959, 1920);
        let mid_hi = normalize_coord(960, 1920);
        assert!(mid_lo <= mid_hi, "normalize should be monotonic");
        // 越界已 clamp 到 dst-1，故归一化为 65535。
        assert_eq!(normalize_coord(5000, 1920), 65535);
        // dst<=1（退化）→ 0，避免除零。
        assert_eq!(normalize_coord(5, 1), 0);
        assert_eq!(normalize_coord(5, 0), 0);
    }

    #[test]
    fn test_sendinput_scan_code() {
        // 关键键的 PS/2 scan code 映射正确。
        assert_eq!(map_scan_code(Key::A as u32), Some(0x1E));
        assert_eq!(map_scan_code(Key::Enter as u32), Some(0x1C));
        assert_eq!(map_scan_code(Key::Space as u32), Some(0x39));
        assert_eq!(map_scan_code(Key::Esc as u32), Some(0x01));
        // 扩展键：高字节 0xE0 + 低字节 code（Left=0x4B / Right=0x4D）。
        assert_eq!(map_scan_code(Key::Left as u32), Some(0xE04B));
        assert_eq!(map_scan_code(Key::Right as u32), Some(0xE04D));
        assert_eq!(map_scan_code(Key::Up as u32), Some(0xE048));
        assert_eq!(map_scan_code(Key::Down as u32), Some(0xE050));
        assert_eq!(map_scan_code(Key::Delete as u32), Some(0xE053));
        // 未知 key → None（上层报 InvalidEvent）。
        assert_eq!(map_scan_code(0xFFFF_FFFF), None);
    }

    /// M8-T020 T002: 修饰键 + 主键 四步序列（按住→点按→释放）。
    fn plan_keys(combo: SpecialCombo) -> Vec<Kbd> {
        match plan_special_key(combo) {
            SpecialKeyPlan::Keys { batches, inter_batch_delay_ms } => {
                assert_eq!(inter_batch_delay_ms, 0, "{combo:?} should be single batch");
                assert_eq!(batches.len(), 1);
                batches.into_iter().next().unwrap()
            }
            SpecialKeyPlan::Lock => panic!("{combo:?} is Lock plan"),
        }
    }

    /// 序列末 4 步 = 主键 up → 修饰键 up（释放在最后，修饰键不粘连）。
    fn assert_release_last(seq: &[Kbd]) {
        assert!(seq.len() >= 4);
        assert!(seq[seq.len() - 2].up, "main key must be released");
        assert!(seq[seq.len() - 1].up, "modifier must be released last");
        // 第一个动作是修饰键按下。
        assert!(!seq[0].up);
    }

    #[test]
    fn test_plan_win_combos() {
        // Win+E: [LWIN down(extended)] → [E down] → [E up] → [LWIN up]。
        let seq = plan_keys(SpecialCombo::WinE);
        assert_eq!(seq.len(), 4);
        assert_eq!(seq[0], Kbd::ext_down(scan::LWIN));
        assert_eq!(seq[1], Kbd::down(scan::E));
        assert_eq!(seq[2], Kbd::up(scan::E));
        assert_eq!(seq[3], Kbd::ext_up(scan::LWIN));
        assert_release_last(&seq);

        for combo in [SpecialCombo::WinD, SpecialCombo::WinL, SpecialCombo::WinR] {
            let seq = plan_keys(combo);
            assert_eq!(seq[0], Kbd::ext_down(scan::LWIN), "{combo:?}");
            assert_eq!(seq[3], Kbd::ext_up(scan::LWIN), "{combo:?}");
            assert_release_last(&seq);
        }
    }

    #[test]
    fn test_plan_alt_tab_delayed_sequence() {
        // Alt+Tab: 两批，批间 100ms；释放批 = Tab up + Alt up（SRV-SKEY-011）。
        match plan_special_key(SpecialCombo::AltTab) {
            SpecialKeyPlan::Keys { batches, inter_batch_delay_ms } => {
                assert_eq!(inter_batch_delay_ms, ALT_TAB_DELAY_MS);
                assert_eq!(batches.len(), 2);
                assert_eq!(batches[0], vec![Kbd::down(scan::LALT)]);
                assert_eq!(
                    batches[1],
                    vec![
                        Kbd::down(scan::TAB),
                        Kbd::up(scan::TAB),
                        Kbd::up(scan::LALT),
                    ]
                );
                // 释放（Alt up）在最后。
                assert!(batches[1].last().unwrap().up);
            }
            SpecialKeyPlan::Lock => panic!("AltTab must not be Lock plan"),
        }
    }

    #[test]
    fn test_plan_ctrl_shift_esc() {
        // Ctrl+Shift+Esc: 6 步单批（任务管理器直达，CAC 替代）。
        let seq = plan_keys(SpecialCombo::CtrlShiftEsc);
        assert_eq!(seq.len(), 6);
        assert_eq!(
            seq,
            vec![
                Kbd::down(scan::LCTRL),
                Kbd::down(scan::LSHIFT),
                Kbd::down(scan::ESC),
                Kbd::up(scan::ESC),
                Kbd::up(scan::LSHIFT),
                Kbd::up(scan::LCTRL),
            ]
        );
        assert_release_last(&seq);
    }

    #[test]
    fn test_plan_alt_f4_and_ctrl_esc() {
        let seq = plan_keys(SpecialCombo::AltF4);
        assert_eq!(seq[0], Kbd::down(scan::LALT));
        assert_eq!(seq[1], Kbd::down(scan::F4));
        assert_release_last(&seq);

        let seq = plan_keys(SpecialCombo::CtrlEsc);
        assert_eq!(seq[0], Kbd::down(scan::LCTRL));
        assert_eq!(seq[1], Kbd::down(scan::ESC));
        assert_release_last(&seq);
    }

    #[test]
    fn test_plan_lock_screen_is_non_injection() {
        // 锁屏不是注入路径（LockWorkStation，SKEY-SEC-003）。
        assert_eq!(plan_special_key(SpecialCombo::LockScreen), SpecialKeyPlan::Lock);
    }
}
