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
// 注入流水线 API（Task T5.2）：面向 `injector::InputEvent`
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
        // LWin=0x5B 扩展键——与 `scan` 模块口径一致）。桌面端独立
        // down/up 事件经此表走 KEYEVENTF_SCANCODE = 物理层键流同流，被控端
        // IME 的 Shift 中英文切换 / Ctrl+Space 检测直接监听（IME 切换快捷键
        // 修复的关键注入参数；VK-only 补按路仅保留给移动端 flag-only 路径）。
        k if k == Key::Shift as u32 => 0x2A,
        k if k == Key::Ctrl as u32 => 0x1D,
        k if k == Key::Alt as u32 => 0x38,
        k if k == Key::Super as u32 => EXTENDED | 0x5B,
        // PS/2 **Set 1（XT）**——与本表既有键同口径（交叉核验：既有表数字
        // 排 0x02-0x0A / A=0x1E / Z=0x2C / Enter=0x1C / Backspace=0x0E /
        // Space=0x39 / F1=0x3B / LShift=0x2A / LCtrl=0x1D / LAlt=0x38 全为
        // Set 1 标准值；与 Linux input-event-codes.h 键码逐一相等——
        // XT 键盘 Linux keycode ≡ Set 1 scan code，MINUS=12 / EQUAL=13 /
        // COMMA=51 / DOT=52 / SLASH=53 / SEMICOLON=39 / APOSTROPHE=40 /
        // GRAVE=41 / LEFTBRACE=26 / RIGHTBRACE=27 / BACKSLASH=43）。
        // 归因建议的 5 值 Minus=0x12/Equals=0x18/Comma=0x41/Period=0x47/
        // Slash=0x4F 为**异口径混入**：与本表 E(0x12)/O(0x18)/F7(0x41)/
        // Home(0xE047)/End(0xE04F) 撞码 = 注入错键（按「-」出 E），弃用。
        k if k == Key::Minus as u32 => 0x0C,
        k if k == Key::Equals as u32 => 0x0D,
        k if k == Key::OpenBracket as u32 => 0x1A,
        k if k == Key::CloseBracket as u32 => 0x1B,
        k if k == Key::Semicolon as u32 => 0x27,
        k if k == Key::Quote as u32 => 0x28,
        k if k == Key::Backtick as u32 => 0x29,
        k if k == Key::Backslash as u32 => 0x2B,
        k if k == Key::Comma as u32 => 0x33,
        k if k == Key::Period as u32 => 0x34,
        k if k == Key::Slash as u32 => 0x35,
        // 表达，不在此层合成）：映射到相邻物理键。
        k if k == Key::Colon as u32 => 0x27,    // → Semicolon（; 键）
        k if k == Key::Pipe as u32 => 0x2B,     // → Backslash（\ 键）
        k if k == Key::Questionmark as u32 => 0x35, // → Slash（/ 键）
        // 物理来源 = 小键盘 +（egui-winit `NumpadAdd => Key::Plus`；主排 =
        // 走 Key::Equals）→ 注入 KpAdd：Set 1 **非扩展 0x4E**（标准表
        // 0x4A=KP- / 0x4E=KP+ / 0x53=KP. 与导航簇同块）。既有表锚点自查
        // Left=0xE04B/Right=0xE04D/End=0xE04F/Down=0xE050/PageDown=0xE051/
        // Insert=0xE052/Delete=0xE053 的低字节 0x47-0x53 即 84 键位小键盘
        // 7/8/9/-/4/6/1/2/3/0/. 簇（0x4C=5、0x4E=KP+ 在簇内）→ 0x4E 非扩展
        // Equals（`Key::Equals => 0x0D`）= 错键，废弃。
        k if k == Key::Plus as u32 => 0x4E,     // KpAdd（小键盘 +，非扩展）
        // 同修）：小键盘专用键，egui 架构不可达（egui 0.28 `Key` 枚举无
        // 对应变体、egui-winit 两表零臂）→ 仅会话窗 UI 补偿按钮路径发送。
        // Set 1 非扩展：KP\*=0x37（标准表 0x36=RShift / **0x37=KP\*** /
        // 0x38=LAlt / 0x39=Space / 0x3A=CapsLock——本表 Alt=0x38 /
        // Space=0x39 / CapsLock=0x3A 三邻键锚点互证）；KP.=0x53（与
        // 既有 Delete=0xE053 同低字节：Set 1 非扩展 0x53 = KP.〔84 键
        // "del"〕、扩展 0xE0 0x53 = 导航 Delete，仅扩展位区分——既有表
        // 已使用 0xE053 即锚点；F11=0x57/F12=0x58 紧随小键盘块后，与
        // 标准表布局一致）。
        k if k == Key::KpMultiply as u32 => 0x37, // KPMultiply（小键盘 *，非扩展）
        k if k == Key::KpDecimal as u32 => 0x53,  // KPDecimal（小键盘 .，非扩展）
        // 小键盘块 0x47-0x53 之前的锁定键位，与 CapsLock=0x3A 同族）。
        // 既有表锚点自查：0x45 低字节在既有臂中零出现（导航簇扩展低字节
        // 0x47/48/49/4B/4D/4F/50/51/52/53 不含 0x45），非扩展域 0x45
        // NumLock 与 KeypadClear 物理同键，标准表 0x45 为其唯一映射）。
        k if k == Key::NumLock as u32 => 0x45,    // NumLock（非扩展）
        _ => return None,
    })
}

///
/// 映射**（平台无关、零 IO，与 [`map_scan_code`] 同表位同口径：本管线注入走
/// scan code，VK 仅观测行用；未覆盖键 → `None`，观测行显示 `-`）。
///
/// 口径说明：无独立物理键的 Shift 组合键（Colon/Pipe/Questionmark）与其映射
/// 目标物理键同 VK（与 [`map_scan_code`] 的 scan 同值同构——观测口径 = 「注入
/// 将作用于哪个键位」）；Super = `VK_LWIN`（0x5B，左右 Win 同 VK 口径）；
/// 字母/数字 = `VK_A`..`VK_Z` / `VK_0`..`VK_9` 标准段。
pub fn map_vk(key: u32) -> Option<u16> {
    Some(match key {
        // 字母 A-Z（VK_A..VK_Z = 0x41..0x5A）
        k if k == Key::A as u32 => 0x41,
        k if k == Key::B as u32 => 0x42,
        k if k == Key::C as u32 => 0x43,
        k if k == Key::D as u32 => 0x44,
        k if k == Key::E as u32 => 0x45,
        k if k == Key::F as u32 => 0x46,
        k if k == Key::G as u32 => 0x47,
        k if k == Key::H as u32 => 0x48,
        k if k == Key::I as u32 => 0x49,
        k if k == Key::J as u32 => 0x4A,
        k if k == Key::K as u32 => 0x4B,
        k if k == Key::L as u32 => 0x4C,
        k if k == Key::M as u32 => 0x4D,
        k if k == Key::N as u32 => 0x4E,
        k if k == Key::O as u32 => 0x4F,
        k if k == Key::P as u32 => 0x50,
        k if k == Key::Q as u32 => 0x51,
        k if k == Key::R as u32 => 0x52,
        k if k == Key::S as u32 => 0x53,
        k if k == Key::T as u32 => 0x54,
        k if k == Key::U as u32 => 0x55,
        k if k == Key::V as u32 => 0x56,
        k if k == Key::W as u32 => 0x57,
        k if k == Key::X as u32 => 0x58,
        k if k == Key::Y as u32 => 0x59,
        k if k == Key::Z as u32 => 0x5A,
        // 数字 0-9（VK_0..VK_9 = 0x30..0x39）
        k if k == Key::Num1 as u32 => 0x31,
        k if k == Key::Num2 as u32 => 0x32,
        k if k == Key::Num3 as u32 => 0x33,
        k if k == Key::Num4 as u32 => 0x34,
        k if k == Key::Num5 as u32 => 0x35,
        k if k == Key::Num6 as u32 => 0x36,
        k if k == Key::Num7 as u32 => 0x37,
        k if k == Key::Num8 as u32 => 0x38,
        k if k == Key::Num9 as u32 => 0x39,
        k if k == Key::Num0 as u32 => 0x30,
        // 控制键
        k if k == Key::Enter as u32 => 0x0D,
        k if k == Key::Esc as u32 => 0x1B,
        k if k == Key::Backspace as u32 => 0x08,
        k if k == Key::Tab as u32 => 0x09,
        k if k == Key::Space as u32 => 0x20,
        // winuser.h `VK_CAPITAL: 0x14` 权威值）；旧值 0x1A = **VK_SPACE** =
        k if k == Key::CapsLock as u32 => 0x14, // VK_CAPITAL
        // F1-F12（VK_F1..VK_F12 = 0x70..0x7B）
        k if k == Key::F1 as u32 => 0x70,
        k if k == Key::F2 as u32 => 0x71,
        k if k == Key::F3 as u32 => 0x72,
        k if k == Key::F4 as u32 => 0x73,
        k if k == Key::F5 as u32 => 0x74,
        k if k == Key::F6 as u32 => 0x75,
        k if k == Key::F7 as u32 => 0x76,
        k if k == Key::F8 as u32 => 0x77,
        k if k == Key::F9 as u32 => 0x78,
        k if k == Key::F10 as u32 => 0x79,
        k if k == Key::F11 as u32 => 0x7A,
        k if k == Key::F12 as u32 => 0x7B,
        // 方向 / 导航
        // winuser.h 权威值）；m9 小修值 0x15 实为 **VK_KANA** = 二次错位
        // （原 0x52 = 扩展 scan 低字节混入 = VK_R 别名，m9 改 0x15 仍偏离，
        // 本岗 SDK 交叉核验定案）。
        k if k == Key::Insert as u32 => 0x2D, // VK_INSERT
        k if k == Key::Home as u32 => 0x24,
        k if k == Key::PageUp as u32 => 0x21,
        k if k == Key::Delete as u32 => 0x2E,
        k if k == Key::End as u32 => 0x23,
        k if k == Key::PageDown as u32 => 0x22,
        k if k == Key::Right as u32 => 0x27,
        k if k == Key::Left as u32 => 0x25,
        k if k == Key::Down as u32 => 0x28,
        k if k == Key::Up as u32 => 0x26,
        // 修饰键（左右同 VK 通用口径）
        k if k == Key::Shift as u32 => 0x10,
        k if k == Key::Ctrl as u32 => 0x11,
        k if k == Key::Alt as u32 => 0x12,
        k if k == Key::Super as u32 => 0x5B, // VK_LWIN
        // 标点
        k if k == Key::Period as u32 => 0xBE, // VK_OEM_PERIOD（US 主排 . 键；m9+map_vk 小修：原 0xDE = Quote 臂同值别名 = VK_OEM_102 口径，MSDN 偏离）
        k if k == Key::Comma as u32 => 0xBC,
        k if k == Key::Semicolon as u32 => 0xBA,
        k if k == Key::Slash as u32 => 0xBF,
        k if k == Key::Minus as u32 => 0xBD,
        k if k == Key::Equals as u32 => 0xBB,
        k if k == Key::OpenBracket as u32 => 0xDB,
        k if k == Key::CloseBracket as u32 => 0xDD,
        k if k == Key::Backslash as u32 => 0xDC,
        k if k == Key::Quote as u32 => 0xDE,
        k if k == Key::Backtick as u32 => 0xC0,
        // 无独立物理键（Shift 组合语义）：与映射目标物理键同 VK
        k if k == Key::Colon as u32 => 0xBA,     // → Semicolon
        k if k == Key::Pipe as u32 => 0xDC,      // → Backslash
        k if k == Key::Questionmark as u32 => 0xBF, // → Slash
        // 小键盘
        k if k == Key::Plus as u32 => 0x6B,      // VK_ADD
        k if k == Key::KpMultiply as u32 => 0x6A, // VK_MULTIPLY
        k if k == Key::KpDecimal as u32 => 0x6E,  // VK_DECIMAL
        k if k == Key::NumLock as u32 => 0x90,   // VK_NUMLOCK
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
            // 系统组合键——独立序列注入（含 Alt+Tab 延迟 / 锁屏非注入路径）。
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
// 特殊键注入（SRV-SKEY-010/011/012/016）
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

// ============================================================================
// ============================================================================

/// 查询/释放侧）。
///
///（`VK_CONTROL`/`VK_SHIFT`/`VK_MENU` 同时反映左右——RMenu 等右修饰键已经
/// 覆盖；`VK_LWIN` 只反映左 Win）——查询/释放侧必须一并覆盖 `VK_RWIN`，
/// 否则 RWin 残留既测不出也放不掉（卫生释放对 RWin 卡键失效）；按下侧
#[cfg(target_os = "windows")]
fn modifier_vks(bit: u8, down: bool) -> &'static [u16] {
    use winapi::um::winuser::{VK_CONTROL, VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT};
    match bit {
        crate::injector::modifier::CTRL => &[VK_CONTROL as u16],
        crate::injector::modifier::SHIFT => &[VK_SHIFT as u16],
        crate::injector::modifier::ALT => &[VK_MENU as u16],
        crate::injector::modifier::SUPER => {
            if down {
                &[VK_LWIN as u16]
            } else {
                &[VK_LWIN as u16, VK_RWIN as u16]
            }
        }
        _ => &[],
    }
}

/// 只为置位生成；非法位忽略）。`down=true` = 补按序列（SUPER → 仅 LWIN，
#[cfg(target_os = "windows")]
pub(crate) fn modifier_vk_sequence(bits: u8, down: bool) -> Vec<u16> {
    let mut vks = Vec::new();
    for bit in [
        crate::injector::modifier::CTRL,
        crate::injector::modifier::SHIFT,
        crate::injector::modifier::ALT,
        crate::injector::modifier::SUPER,
    ] {
        if bits & bit != 0 {
            vks.extend_from_slice(modifier_vks(bit, down));
        }
    }
    vks
}

/// 查询修饰键**物理按下态**（`GetAsyncKeyState` 高位），按位组合返回
///（`InputInjector::modifier_sync` 判定「已按下不重复按」用——桌面端独立
/// Ctrl 等键事件路径天然去重，漏发无副作用）。
///
/// 仅查 `VK_LWIN` 会漏 RWin 残留）；CTRL/SHIFT/ALT 经通用 VK 已含左右。
#[cfg(target_os = "windows")]
pub(crate) fn modifier_physical_state() -> u8 {
    use winapi::um::winuser::GetAsyncKeyState;
    let mut state = 0u8;
    for bit in [
        crate::injector::modifier::CTRL,
        crate::injector::modifier::SHIFT,
        crate::injector::modifier::ALT,
        crate::injector::modifier::SUPER,
    ] {
        // 高位（0x8000）= 按下；低位 = 自上次查询后是否按过（不关心）。
        if modifier_vks(bit, false)
            .iter()
            .any(|vk| unsafe { GetAsyncKeyState(*vk as i32) } as u16 & 0x8000 != 0)
        {
            state |= bit;
        }
    }
    state
}

/// 按位标志注入修饰键按下/释放（一次 SendInput 批；VK 注入——修饰键
/// 无布局差异）。失败只记日志（修饰键补按为 best-effort，主键事件照常）。
///
/// 返回 `true` = 全部事件已发送（或无需发送）；`false` = SendInput 返回 0
#[cfg(target_os = "windows")]
pub(crate) fn send_modifier_keys(bits: u8, down: bool) -> bool {
    use winapi::um::winuser::{
        SendInput, INPUT, INPUT_KEYBOARD, KEYBDINPUT, INPUT_u, KEYEVENTF_KEYUP,
    };
    let mut inputs: Vec<INPUT> = Vec::new();
    for &vk in &modifier_vk_sequence(bits, down) {
        let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
        unsafe {
            *u.ki_mut() = KEYBDINPUT {
                wVk: vk,
                wScan: 0,
                dwFlags: if down { 0 } else { KEYEVENTF_KEYUP },
                time: 0,
                dwExtraInfo: 0,
            };
        }
        inputs.push(INPUT { type_: INPUT_KEYBOARD, u });
    }
    if inputs.is_empty() {
        return true;
    }
    let sent = unsafe {
        SendInput(
            inputs.len() as u32,
            inputs.as_mut_ptr(),
            std::mem::size_of::<INPUT>() as i32,
        )
    };
    if sent == 0 {
        tracing::debug!("send_modifier_keys: SendInput returned 0 (bits={bits:#x}, down={down})");
        return false;
    }
    true
}

/// CTRL→SHIFT→ALT→SUPER，SUPER 展开 LWIN+RWIN；未知位经
/// [`crate::injector::hygiene_release_plan`] 掩掉）。`send_modifier_keys(
/// plan, false)` 实发序列 = 本序列（单测锁「位图→释放计划」映射；SendInput
/// 实调用无单测面）。
#[cfg(target_os = "windows")]
pub fn hygiene_release_vks(residual: u8) -> Vec<u16> {
    modifier_vk_sequence(crate::injector::hygiene_release_plan(residual), false)
}

///（`GetAsyncKeyState`，含左右 Win）→ 释放计划（仅四个已定义位）→ 一次
/// SendInput 批全释放（KEYUP，L/R Win 均发）。
///
/// 返回 `(plan, sent_ok)`：`plan = 0` = clean（不产生事件，调用方记
/// `input hygiene: clean` 对账行）；`plan ≠ 0` 且 `sent_ok = false` =
/// SendInput 失败（调用方 WARN 继续——失败不阻断会话）。幂等：重复调用
/// 只是再读一次物理态，up 未按下键为无害 no-op。
#[cfg(target_os = "windows")]
pub fn hygiene_release_residual_modifiers() -> (u8, bool) {
    let residual = modifier_physical_state();
    let plan = crate::injector::hygiene_release_plan(residual);
    if plan == 0 {
        return (0, true);
    }
    let ok = send_modifier_keys(plan, false);
    (plan, ok)
}

/// 非 Windows 平台桩：无物理键态（同 `modifier_sync` no-op 口径）——
/// 返回 `(0, true)` = clean。
#[cfg(not(target_os = "windows"))]
pub fn hygiene_release_residual_modifiers() -> (u8, bool) {
    (0, true)
}

// ============================================================================
// ============================================================================

/// 查询实际光标位置（`GetCursorPos`——**纯查询 API**，严禁 `SetWindowsHookEx`
/// 等系统级钩子；本修复不引入任何钩子）。
///
/// 失败（如会话无输入桌面）返回 `None` → 调用方（injector Move 守卫）退化
/// 现状行为（照常注入）+ debug 日志；体验机制不做 fail-closed。
#[cfg(target_os = "windows")]
pub(crate) fn cursor_pos() -> Option<(i32, i32)> {
    use winapi::shared::windef::POINT;
    use winapi::um::winuser::GetCursorPos;
    let mut p = POINT { x: 0, y: 0 };
    if unsafe { GetCursorPos(&mut p) } != 0 {
        Some((p.x, p.y))
    } else {
        None
    }
}

/// 非 Windows 平台桩：无光标查询能力 → `None`（调用方退化现状行为）。
#[cfg(not(target_os = "windows"))]
pub(crate) fn cursor_pos() -> Option<(i32, i32)> {
    None
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
        assert_eq!(map_scan_code(Key::Shift as u32), Some(0x2A));
        assert_eq!(map_scan_code(Key::Ctrl as u32), Some(0x1D));
        assert_eq!(map_scan_code(Key::Alt as u32), Some(0x38));
        assert_eq!(map_scan_code(Key::Super as u32), Some(0xE05B));
        assert_eq!(map_scan_code(0xFFFF_FFFF), None);
    }

    // ========================================================================
    // ========================================================================

    /// 见 `map_scan_code` 注释的交叉核验口径）+ 4 个无独立物理键的相邻
    /// 物理键别名（Colon→; / Pipe→\ / ?→/ / +→=）。
    #[test]
    fn r85d_map_scan_code_punctuation_set1() {
        // 11 独立物理键（PM 核验修正后的 Set 1 值——归因建议的 5 个可疑值
        // Minus=0x12/Equals=0x18/Comma=0x41/Period=0x47/Slash=0x4F 弃用：
        // 与本表 E/O/F8/Home/End 撞码 = 注入错键）。
        assert_eq!(map_scan_code(Key::Minus as u32), Some(0x0C), "'-'");
        assert_eq!(map_scan_code(Key::Equals as u32), Some(0x0D), "'='");
        assert_eq!(map_scan_code(Key::OpenBracket as u32), Some(0x1A), "'['");
        assert_eq!(map_scan_code(Key::CloseBracket as u32), Some(0x1B), "']'");
        assert_eq!(map_scan_code(Key::Semicolon as u32), Some(0x27), "';'");
        assert_eq!(map_scan_code(Key::Quote as u32), Some(0x28), "'\\''");
        assert_eq!(map_scan_code(Key::Backtick as u32), Some(0x29), "'`'");
        assert_eq!(map_scan_code(Key::Backslash as u32), Some(0x2B), "'\\'");
        assert_eq!(map_scan_code(Key::Comma as u32), Some(0x33), "','");
        assert_eq!(map_scan_code(Key::Period as u32), Some(0x34), "'.'");
        assert_eq!(map_scan_code(Key::Slash as u32), Some(0x35), "'/'");
        // 4 无独立物理键 → 相邻物理键 scan code（Shift 语义由修饰键帧差
        // 事件表达，不在此层合成）。
        assert_eq!(
            map_scan_code(Key::Colon as u32),
            map_scan_code(Key::Semicolon as u32),
            "':' 无独立物理键 → ';'"
        );
        assert_eq!(
            map_scan_code(Key::Pipe as u32),
            map_scan_code(Key::Backslash as u32),
            "'|' 无独立物理键 → '\\'"
        );
        assert_eq!(
            map_scan_code(Key::Questionmark as u32),
            map_scan_code(Key::Slash as u32),
            "'?' 无独立物理键 → '/'"
        );
        // 断言随定案修改，见 `r86_map_scan_code_plus_is_kpadd`。
        // 既有键决策表零回归（抽查与弃用值撞码的键位：E/O/F7 不得被新臂
        // 遮蔽，新值不得与既有值撞码）。
        assert_eq!(map_scan_code(Key::E as u32), Some(0x12), "弃用值 0x12 = E");
        assert_eq!(map_scan_code(Key::O as u32), Some(0x18), "弃用值 0x18 = O");
        assert_eq!(map_scan_code(Key::F7 as u32), Some(0x41), "弃用值 0x41 = F7");
    }

    // ========================================================================
    // Ctrl+C/X/V 无效 / CapsLock 无效；用户 2026-09-06 复测原话）
    // ========================================================================

    /// （修复前 0x0D = 主排 Equals = 错键，「输入小键盘的 + 号变 = 号」
    /// 的服务端根因）；且既有 E/O/F7/标点决策表**零回归**（0x4E 不得与
    /// 既有值撞码——本表 0x4E 低字节在既有臂中零出现〔导航簇扩展低字节
    /// 0x47/48/49/4B/4D/4F/50/51/52/53 不含 0x4E〕，非扩展域 0x4E 空位）。
    #[test]
    fn r86_map_scan_code_plus_is_kpadd() {
        assert_eq!(map_scan_code(Key::Plus as u32), Some(0x4E), "KpAdd 非扩展");
        assert_eq!(map_scan_code(Key::E as u32), Some(0x12), "E");
        assert_eq!(map_scan_code(Key::O as u32), Some(0x18), "O");
        assert_eq!(map_scan_code(Key::F7 as u32), Some(0x41), "F7");
        assert_eq!(map_scan_code(Key::PageDown as u32), Some(0xE051), "PageDown 扩展键保持");
        assert_eq!(map_scan_code(Key::Equals as u32), Some(0x0D), "主排 = 保持 0x0D");
        // 新值 0x4E/0x37/0x53 非扩展域不得遮蔽既有非扩展键（RShift=0x36 邻键抽查 + 全部字母/数字）。
        assert_eq!(map_scan_code(Key::Alt as u32), Some(0x38), "LAlt（0x37 邻键）");
        assert_eq!(map_scan_code(Key::Space as u32), Some(0x39), "Space（0x37 邻键）");
        assert_eq!(map_scan_code(Key::CapsLock as u32), Some(0x3A), "CapsLock");
        assert_eq!(map_scan_code(Key::A as u32), Some(0x1E), "A");
        assert_eq!(map_scan_code(Key::Num0 as u32), Some(0x0B), "0");
    }

    /// 非扩展值——KP\*=0x37（LAlt=0x38/Space=0x39/CapsLock=0x3A 三邻键
    /// 锚点）、KP.=0x53（与 Delete=0xE053 同低字节、仅扩展位区分；
    /// F11=0x57/F12=0x58 紧随小键盘块后）。
    #[test]
    fn r86_map_scan_code_kp_multiply_and_decimal() {
        assert_eq!(map_scan_code(Key::KpMultiply as u32), Some(0x37), "KP*");
        assert_eq!(map_scan_code(Key::KpDecimal as u32), Some(0x53), "KP.");
        // 未知键仍 None（尾臂不被新臂遮蔽）。
        assert_eq!(map_scan_code(0xFFFF_FFFF), None);
    }

    /// 既有臂中零出现（导航簇扩展低字节 0x47-0x53 不含 0x45），非扩展域
    #[test]
    fn r89_map_scan_code_numlock() {
        assert_eq!(map_scan_code(Key::NumLock as u32), Some(0x45), "NumLock 非扩展");
        // 既有键零回归（小键盘块邻键 + toggle 对键）。
        assert_eq!(map_scan_code(Key::KpMultiply as u32), Some(0x37), "KP* 保持");
        assert_eq!(map_scan_code(Key::KpDecimal as u32), Some(0x53), "KP. 保持");
        assert_eq!(map_scan_code(Key::Plus as u32), Some(0x4E), "KpAdd 保持");
        assert_eq!(map_scan_code(Key::CapsLock as u32), Some(0x3A), "CapsLock（toggle 对）");
        assert_eq!(map_scan_code(Key::F12 as u32), Some(0x58), "F12（小键盘块后）");
        // 0x45 不得遮蔽既有扩展臂（导航簇低字节不变）。
        assert_eq!(map_scan_code(Key::Home as u32), Some(0xE047), "Home 扩展保持");
        // 未知键仍 None（尾臂不被新臂遮蔽）。
        assert_eq!(map_scan_code(0xFFFF_FFFF), None);
    }

    /// T002: 修饰键 + 主键 四步序列（按住→点按→释放）。
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

    /// 不做 `is_some()` 强断言——无桌面会话（headless）下返回 None 是合法
    /// 退化语义（由 injector 守卫消费），此处只保证调用安全。
    #[test]
    fn r74b_cursor_pos_pure_query() {
        let _ = cursor_pos();
    }

    // ========================================================================
    // ========================================================================

    /// `GetAsyncKeyState`/`SendInput` 实调用无单测面——真实键态/注入效果
    /// 以用户复测 `input hygiene:` 对账行覆盖）。锁：全空 → 无事件；含
    /// Win → **LWIN+RWIN 均发**（RWin 残留释放口径，Win 键无通用 VK）；
    /// 含多键 → 位扫描序 CTRL→SHIFT→ALT→SUPER、SUPER 展开；未知位 → 掩掉；
    /// 集 = 释放集（SUPER 查 L/R Win 两键）。
    #[cfg(target_os = "windows")]
    #[test]
    fn r81g_hygiene_release_vk_sequence_three_states() {
        use winapi::um::winuser::{VK_CONTROL, VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT};
        use crate::injector::modifier as m;
        // 全空：无释放事件（调用方记 clean 行）。
        assert_eq!(hygiene_release_vks(0), Vec::<u16>::new());
        // 含 Win：LWIN+RWIN 均发（只放 LWIN = RWin 卡键残留修复失效）。
        assert_eq!(
            hygiene_release_vks(m::SUPER),
            vec![VK_LWIN as u16, VK_RWIN as u16]
        );
        // 含多键：位扫描序 + SUPER 展开。
        assert_eq!(
            hygiene_release_vks(m::CTRL | m::SUPER),
            vec![VK_CONTROL as u16, VK_LWIN as u16, VK_RWIN as u16]
        );
        assert_eq!(
            hygiene_release_vks(m::SHIFT | m::ALT),
            vec![VK_SHIFT as u16, VK_MENU as u16]
        );
        // 未知位：不进序列（`hygiene_release_plan` 掩掉）。
        assert_eq!(hygiene_release_vks(0b1111_0000), Vec::<u16>::new());
        // 按下侧：SUPER = 仅 LWIN（补按语义零回退——不同时按两 Win）。
        assert_eq!(modifier_vk_sequence(m::SUPER, true), vec![VK_LWIN as u16]);
        assert_eq!(
            modifier_vk_sequence(m::CTRL | m::SUPER, true),
            vec![VK_CONTROL as u16, VK_LWIN as u16]
        );
        // 物理态查询集 = 释放集：SUPER 查 L/R Win 两键（RWin 残留可检出）；
        // CTRL/SHIFT/ALT 通用 VK 各一（含左右，RMenu 无需单独覆盖）。
        assert_eq!(modifier_vks(m::SUPER, false), &[VK_LWIN as u16, VK_RWIN as u16]);
        assert_eq!(modifier_vks(m::CTRL, false), &[VK_CONTROL as u16]);
        assert_eq!(modifier_vks(m::SHIFT, false), &[VK_SHIFT as u16]);
        assert_eq!(modifier_vks(m::ALT, false), &[VK_MENU as u16]);
    }

    // ========================================================================
    // ========================================================================

    /// （vk/scan 同一 Key 双观测口径互证），常用键段抽查，未知键 → `None`
    /// （观测行显示 `-`，不阻塞注入）。
    #[test]
    fn r129_map_vk_table() {
        // 五盲区键 vk/scan 跨表对账（PS/2 Set 1 ↔ MSDN Virtual Key Codes）。
        // 旧钉值 0x1A = VK_SPACE 为常量错位，本岗修）。
        assert_eq!(map_vk(Key::CapsLock as u32), Some(0x14));
        assert_eq!(map_scan_code(Key::CapsLock as u32), Some(0x3A));
        assert_eq!(map_vk(Key::KpMultiply as u32), Some(0x6A));
        assert_eq!(map_scan_code(Key::KpMultiply as u32), Some(0x37));
        assert_eq!(map_vk(Key::KpDecimal as u32), Some(0x6E));
        assert_eq!(map_scan_code(Key::KpDecimal as u32), Some(0x53));
        assert_eq!(map_vk(Key::NumLock as u32), Some(0x90));
        assert_eq!(map_scan_code(Key::NumLock as u32), Some(0x45));
        assert_eq!(map_vk(Key::Super as u32), Some(0x5B));
        assert_eq!(map_scan_code(Key::Super as u32), Some(0xE05B));
        // 常用键段抽查（字母/数字/控制/方向/标点/小键盘 + ）。
        assert_eq!(map_vk(Key::A as u32), Some(0x41));
        assert_eq!(map_vk(Key::Z as u32), Some(0x5A));
        assert_eq!(map_vk(Key::Num0 as u32), Some(0x30));
        assert_eq!(map_vk(Key::Num9 as u32), Some(0x39));
        assert_eq!(map_vk(Key::Enter as u32), Some(0x0D));
        assert_eq!(map_vk(Key::Esc as u32), Some(0x1B));
        assert_eq!(map_vk(Key::Space as u32), Some(0x20));
        assert_eq!(map_vk(Key::F1 as u32), Some(0x70));
        assert_eq!(map_vk(Key::F12 as u32), Some(0x7B));
        assert_eq!(map_vk(Key::Left as u32), Some(0x25));
        assert_eq!(map_vk(Key::Right as u32), Some(0x27));
        assert_eq!(map_vk(Key::Delete as u32), Some(0x2E));
        // **0x2D**（SDK 权威值；m9 小修值 0x15 实为 VK_KANA = 二次错位，本岗修）。
        assert_eq!(map_vk(Key::Insert as u32), Some(0x2D));
        assert_eq!(map_vk(Key::Shift as u32), Some(0x10));
        assert_eq!(map_vk(Key::Ctrl as u32), Some(0x11));
        assert_eq!(map_vk(Key::Alt as u32), Some(0x12));
        assert_eq!(map_vk(Key::Period as u32), Some(0xBE));
        assert_eq!(map_vk(Key::Backtick as u32), Some(0xC0));
        assert_eq!(map_vk(Key::Plus as u32), Some(0x6B));
        // 无独立物理键（Shift 组合语义）：与映射目标物理键同 VK。
        assert_eq!(map_vk(Key::Colon as u32), Some(0xBA));
        assert_eq!(map_vk(Key::Pipe as u32), Some(0xDC));
        assert_eq!(map_vk(Key::Questionmark as u32), Some(0xBF));
        // 未知 key → None（观测行 `-`）。
        assert_eq!(map_vk(0xFFFF_FFFF), None);
        assert_eq!(map_vk(0), None);
    }

    // ========================================================================

    /// 观测 VK → 注入 scan，四段同键互证 + 客户端命中行 VK 与服务端 srv-in 行
    /// VK 跨表对账）。
    ///
    /// 口径 = MSDN "Virtual Key Codes" / PS/2 Set 1（SDK `winapi` winuser.h 权威
    /// 值交叉核验）：本岗取证定案三处常量错位（`map_vk` CapsLock 0x1A=VK_SPACE
    /// →0x14=VK_CAPITAL / `map_vk` Insert 0x15=VK_KANA →0x2D=VK_INSERT /
    /// `kbd_hook::blind_key_vk` KpDecimal 0x6B=VK_ADD →0x6E=VK_DECIMAL）后
    #[test]
    fn r135_2_blind_key_vk_scan_matrix_pinned() {
        use crate::injector::{InputEvent, InputKind, Key, r132_4_kp_star_expand};
        use crate::kbd_hook::{
            blind_key_vk, scan_code_to_blind_key, SCAN_CAPS_LOCK, SCAN_KP_DECIMAL,
            SCAN_KP_MULTIPLY, SCAN_NUM_LOCK, SCAN_WIN,
        };

        // (捕获 scan, 扩展位, wire Key, 观测 VK〔SDK 权威值〕, 注入 scan)
        let rows: [(u16, bool, Key, u16, u16); 5] = [
            (SCAN_CAPS_LOCK, false, Key::CapsLock, 0x14, 0x3A),      // VK_CAPITAL
            (SCAN_KP_MULTIPLY, false, Key::KpMultiply, 0x6A, 0x37),  // VK_MULTIPLY
            (SCAN_KP_DECIMAL, false, Key::KpDecimal, 0x6E, 0x53),    // VK_DECIMAL
            (SCAN_NUM_LOCK, false, Key::NumLock, 0x90, 0x45),        // VK_NUMLOCK
            (SCAN_WIN, true, Key::Super, 0x5B, 0xE05B),              // VK_LWIN（扩展）
        ];
        for (scan, ext, key, vk, inj_scan) in rows {
            let wire = key as u32;
            // ① 捕获白名单正例（scan + 扩展位形态钉死）。
            assert_eq!(
                scan_code_to_blind_key(scan, ext),
                Some(key),
                "捕获 scan {scan:#04X} ext={ext} → wire"
            );
            // ② wire 判别式零改（既有值钉死：CapsLock=0x39 / KpMultiply=0x66 /
            // KpDecimal=0x67 / NumLock=0x68 / Super=0x56）。
            assert!(
                matches!(wire, 0x39 | 0x56 | 0x66 | 0x67 | 0x68),
                "wire 判别式越界: {wire:#04X}"
            );
            // ③ 观测 VK（srv-in 行 `vk` 字段；MSDN 对照钉死——本岗修复位点）。
            assert_eq!(map_vk(wire), Some(vk), "map_vk(wire {wire:#04X}) 观测 VK");
            // ④ 客户端命中行 VK（`blind_key_vk`）与服务端 srv-in 行 VK 跨表同值
            // （两端观测口径一致 = 用户 grep 对账锚点）。
            assert_eq!(blind_key_vk(key), vk, "blind_key_vk ↔ map_vk 跨表对账（wire {wire:#04X}）");
            // ⑤ 注入 scan（注入管线走 scan code；扩展 = 0xE0 前缀形态）。
            assert_eq!(map_scan_code(wire), Some(inj_scan), "注入 scan（wire {wire:#04X}）");
        }

        // 扩展位反例：非扩展 4 键带扩展位 = 不在白名单（0x53 扩展 = 导航 Delete、
        // 0x37/0x3A/0x45 无标准扩展形态）；Super 要求扩展位（非扩展 0x5B 不在表）。
        for scan in [SCAN_KP_MULTIPLY, SCAN_KP_DECIMAL, SCAN_CAPS_LOCK, SCAN_NUM_LOCK] {
            assert_eq!(scan_code_to_blind_key(scan, true), None, "扩展位 {scan:#04X} 反例");
        }
        assert_eq!(scan_code_to_blind_key(SCAN_WIN, false), None, "非扩展 0x5B 反例");

        // 本岗三处常量错位修复位点回归锚（SDK 权威值；旧错值注释在案）。
        assert_eq!(map_vk(Key::CapsLock as u32), Some(0x14), "VK_CAPITAL=0x14（旧 0x1A=VK_SPACE）");
        assert_eq!(map_vk(Key::Insert as u32), Some(0x2D), "VK_INSERT=0x2D（m9 值 0x15=VK_KANA）");
        assert_eq!(blind_key_vk(Key::KpDecimal), 0x6E, "VK_DECIMAL=0x6E（旧 0x6B=VK_ADD）");

        // （被控端无小键盘时打出 `*`）——序列形态 + 成分注入 scan 钉死。
        let down = InputEvent::key(InputKind::KeyDown, Key::KpMultiply, 0);
        let (a, b) = r132_4_kp_star_expand(&down).expect("KP* down 必展开");
        let b = b.expect("第二步必达");
        assert_eq!((a.key, a.kind), (Key::Shift as u32, InputKind::KeyDown));
        assert_eq!((b.key, b.kind), (Key::Num8 as u32, InputKind::KeyDown));
        let up = InputEvent::key(InputKind::KeyUp, Key::KpMultiply, 0);
        let (a, b) = r132_4_kp_star_expand(&up).expect("KP* up 必展开");
        let b = b.expect("释放步必达");
        assert_eq!((a.key, a.kind), (Key::Num8 as u32, InputKind::KeyUp));
        assert_eq!((b.key, b.kind), (Key::Shift as u32, InputKind::KeyUp));
        assert_eq!(map_scan_code(Key::Shift as u32), Some(0x2A));
        assert_eq!(map_scan_code(Key::Num8 as u32), Some(0x09));

        // CapsLock = 直透注入（零展开；toggle 语义 = down+up 单对由两端钩子/注入
        // 既有路径表达，远端硬件/系统完成状态翻转 = 远端即 ground truth）。
        let caps = InputEvent::key(InputKind::KeyDown, Key::CapsLock, 0);
        assert_eq!(r132_4_kp_star_expand(&caps), None, "CapsLock 不得展开");
    }
}
