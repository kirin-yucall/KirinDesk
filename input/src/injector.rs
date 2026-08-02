//! 键鼠注入器：接收可靠流事件 → 平台 HID 注入（服务端侧）。
//!
//! 设计要点（参见 M8-T008_P1E）：
//! - 事件经 **加密可靠流**（SecureChannel / QUIC reliable stream）到达，本模块只消费事件，
//!   **不开任何裸 TCP/UDP 端口**（裸端口无 AEAD 加密，违反安全模型）。
//! - 可靠流保证不丢 / 不重 / 不乱序；本模块不重发用户操作（注入失败仅记日志）。
//! - 坐标缩放：客户端/服务端分辨率不同时按比例换算（向下取整 + clamp）。
//! - 优先级：键鼠指令为最高优先级（[`INPUT_PRIORITY`]），拥塞调度由 P1F（M8-T009）实现。
//!
//! 注意：本模块的 [`InputEvent`] 是**服务端注入管线 wire 格式**，与
//! [`crate::capture::InputEvent`]（客户端捕获格式）并列独立，互不替代。

use serde::{Deserialize, Serialize};

/// 键鼠指令优先级标记。`0` = 最高。
///
/// 本模块仅暴露该元数据供传输层（P1F，M8-T009）调度使用；调度实现不在本任务范围。
/// 拥塞时优先丢弃视频（DATAGRAM 可丢），键鼠可靠流不丢。
pub const INPUT_PRIORITY: u8 = 0;

/// 修饰键位标志（`InputEvent::modifiers`）。
pub mod modifier {
    pub const CTRL: u8 = 1 << 0;
    pub const SHIFT: u8 = 1 << 1;
    pub const ALT: u8 = 1 << 2;
    pub const SUPER: u8 = 1 << 3;
}

/// 鼠标按键位标志（Windows 惯例：1=左 2=右 4=中）。
///
/// 方向编码：`InputKind::MouseButton` 在 spec 的 `InputKind` 枚举里是单一变体（无独立 Up/Down，
/// 与键盘的 KeyDown/KeyUp 不同）。为同时表达按下与抬起，约定 [`InputEvent::button`] 的
/// 低 3 位选择按键（[`LEFT`]/[`RIGHT`]/[`MIDDLE`]），bit 7（[`RELEASE`]）置位表示抬起。
/// 即：按下 = `1`/`2`/`4`，抬起 = `0x81`/`0x82`/`0x84`。
pub mod button {
    pub const LEFT: u8 = 1;
    pub const RIGHT: u8 = 2;
    pub const MIDDLE: u8 = 4;
    /// 抬起方向位（与 LEFT/RIGHT/MIDDLE 组合：`LEFT | RELEASE` = 左键抬起）。
    pub const RELEASE: u8 = 0x80;
}

/// 平台无关的键码常量（[`InputEvent::key`] 取值）。
///
/// 这些是本管线自定义的稳定枚举值（`Key` 的判别式），与平台无关；
/// 各平台注入实现负责把它们映射到本地的 scan code / virtual key / keycode。
/// 映射表覆盖常见键；未覆盖的键由平台层返回 [`InjectError::InvalidEvent`]。
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Key {
    // 字母 A-Z
    A = 0x04,
    B = 0x05,
    C = 0x06,
    D = 0x07,
    E = 0x08,
    F = 0x09,
    G = 0x0A,
    H = 0x0B,
    I = 0x0C,
    J = 0x0D,
    K = 0x0E,
    L = 0x0F,
    M = 0x10,
    N = 0x11,
    O = 0x12,
    P = 0x13,
    Q = 0x14,
    R = 0x15,
    S = 0x16,
    T = 0x17,
    U = 0x18,
    V = 0x19,
    W = 0x1A,
    X = 0x1B,
    Y = 0x1C,
    Z = 0x1D,
    // 数字 0-9（顶排）
    Num1 = 0x1E,
    Num2 = 0x1F,
    Num3 = 0x20,
    Num4 = 0x21,
    Num5 = 0x22,
    Num6 = 0x23,
    Num7 = 0x24,
    Num8 = 0x25,
    Num9 = 0x26,
    Num0 = 0x27,
    // 控制键
    Enter = 0x28,
    Esc = 0x29,
    Backspace = 0x2A,
    Tab = 0x2B,
    Space = 0x2C,
    // 修饰键
    CapsLock = 0x39,
    F1 = 0x3A,
    F2 = 0x3B,
    F3 = 0x3C,
    F4 = 0x3D,
    F5 = 0x3E,
    F6 = 0x3F,
    F7 = 0x40,
    F8 = 0x41,
    F9 = 0x42,
    F10 = 0x43,
    F11 = 0x44,
    F12 = 0x45,
    // 方向 / 导航
    Insert = 0x49,
    Home = 0x4A,
    PageUp = 0x4B,
    Delete = 0x4C,
    End = 0x4D,
    PageDown = 0x4E,
    Right = 0x4F,
    Left = 0x50,
    Down = 0x51,
    Up = 0x52,
}

/// 特殊键组合（M8-T020 SRV-SKEY-002）：跨平台语义统一，平台注入层翻译。
///
/// 注意：**没有** `CtrlAltDel`（CAC）变体——CAC 是系统安全注意序列（SAS），
/// 普通进程无法注入（Windows 硬限制），UI 以 [`Self::LockScreen`] 替代
/// （SRV-SKEY-002 / UI-SKEY-002，不提供无效的 CAC 注入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpecialCombo {
    /// Win+E（打开文件资源管理器）。
    WinE,
    /// Win+D（显示桌面）。
    WinD,
    /// Win+L（锁屏，可注入）。
    WinL,
    /// Win+R（运行对话框）。
    WinR,
    /// Alt+Tab（切换窗口；被控端前台需无捕获窗口）。
    AltTab,
    /// Ctrl+Shift+Esc（任务管理器直达，CAC 的替代路径之一）。
    CtrlShiftEsc,
    /// Alt+F4（关闭前台窗口）。
    AltF4,
    /// Ctrl+Esc（开始菜单）。
    CtrlEsc,
    /// 锁屏（**非注入路径**：平台原生锁屏调用，见 `crate::lock`）。
    LockScreen,
}

impl SpecialCombo {
    /// 面板按钮文案（客户端工具栏使用，UI-SKEY-001）。
    pub fn label(&self) -> &'static str {
        match self {
            Self::WinE => "Win+E",
            Self::WinD => "Win+D",
            Self::WinL => "Win+L",
            Self::WinR => "Win+R",
            Self::AltTab => "Alt+Tab",
            Self::CtrlShiftEsc => "Ctrl+Shift+Esc",
            Self::AltF4 => "Alt+F4",
            Self::CtrlEsc => "Ctrl+Esc",
            Self::LockScreen => "锁屏",
        }
    }

    /// 按钮 tooltip（UI-SKEY-003）。
    pub fn hint(&self) -> &'static str {
        match self {
            Self::WinE => "打开文件资源管理器",
            Self::WinD => "显示桌面",
            Self::WinL => "锁定（Win+L 可注入）",
            Self::WinR => "打开运行对话框",
            Self::AltTab => "切换窗口（被控端前台无捕获窗口时）",
            Self::CtrlShiftEsc => "打开任务管理器",
            Self::AltF4 => "关闭前台窗口",
            Self::CtrlEsc => "打开开始菜单",
            Self::LockScreen => "系统限制（Ctrl+Alt+Del 不可注入），以锁屏代替",
        }
    }
}

/// 事件种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputKind {
    MouseMove,
    MouseButton,
    MouseWheel,
    KeyDown,
    KeyUp,
    KeyRepeat,
    /// Unicode 文本（IME 合成/粘贴，如中文）。注入侧逐字符处理，
    /// 平台无 Unicode 注入能力（uinput 等）→ [`InjectError::UnsupportedPlatform`]。
    Text,
    /// M8-T020: 系统组合键（Win/Alt+Tab/任务管理器/锁屏），
    /// 实际组合取 [`InputEvent::combo`]（普通键鼠事件不含）。
    SpecialKey,
}

/// 键鼠事件（跨平台统一格式，来自客户端）。
///
/// 经 bincode 序列化后在加密可靠流上传输。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputEvent {
    pub kind: InputKind,
    /// 客户端屏幕坐标（注入前按 `src_w/src_h → dst_w/dst_h` 缩放到服务端分辨率）。
    pub x: u32,
    pub y: u32,
    /// 鼠标按键位标志（[`button`]）：1=左 2=右 4=中。
    pub button: u8,
    /// 平台无关键码，取 [`Key`] 的判别式值。
    pub key: u32,
    /// 滚轮增量（正/负表示方向）。
    pub wheel_delta: i32,
    /// 修饰键位标志（[`modifier`]）：Ctrl/Shift/Alt/Super。
    pub modifiers: u8,
    /// Unicode 文本（仅 [`InputKind::Text`] 使用；其余种类为空串）。
    #[serde(default)]
    pub text: String,
    /// M8-T020: 特殊键组合（仅 [`InputKind::SpecialKey`] 使用；其余为 `None`）。
    #[serde(default)]
    pub combo: Option<SpecialCombo>,
}

impl InputEvent {
    /// 便捷构造：鼠标移动（客户端像素坐标，注入前按分辨率缩放）。
    pub fn mouse_move(x: u32, y: u32) -> Self {
        Self { kind: InputKind::MouseMove, x, y, button: 0, key: 0, wheel_delta: 0, modifiers: 0, text: String::new(), combo: None }
    }

    /// 便捷构造：鼠标按键。`button_bits` 取 [`button`] 常量
    /// （`LEFT|RELEASE` = 左键抬起）。
    pub fn mouse_button(button_bits: u8, x: u32, y: u32) -> Self {
        Self { kind: InputKind::MouseButton, x, y, button: button_bits, key: 0, wheel_delta: 0, modifiers: 0, text: String::new(), combo: None }
    }

    /// 便捷构造：滚轮（正/负 = 上/下）。
    pub fn mouse_wheel(delta: i32, x: u32, y: u32) -> Self {
        Self { kind: InputKind::MouseWheel, x, y, button: 0, key: 0, wheel_delta: delta, modifiers: 0, text: String::new(), combo: None }
    }

    /// 便捷构造：键盘事件（`kind` 取 KeyDown/KeyUp/KeyRepeat）。
    pub fn key(kind: InputKind, key: Key, modifiers: u8) -> Self {
        Self { kind, x: 0, y: 0, button: 0, key: key as u32, wheel_delta: 0, modifiers, text: String::new(), combo: None }
    }

    /// 便捷构造：Unicode 文本（IME/粘贴，中文路径）。
    pub fn text(chars: impl Into<String>) -> Self {
        Self { kind: InputKind::Text, x: 0, y: 0, button: 0, key: 0, wheel_delta: 0, modifiers: 0, text: chars.into(), combo: None }
    }

    /// 便捷构造：M8-T020 特殊键组合（如 `WinE` / `LockScreen`）。
    ///
    /// 传输复用 `ChannelTag::Input` 通道（SRV-SKEY-003），无新通道/端口。
    pub fn special_key(combo: SpecialCombo) -> Self {
        Self { kind: InputKind::SpecialKey, x: 0, y: 0, button: 0, key: 0, wheel_delta: 0, modifiers: 0, text: String::new(), combo: Some(combo) }
    }
}

/// 注入错误。注入失败不自动重试（用户操作不可重放，可靠流不重发）。
#[derive(Debug, Clone, thiserror::Error)]
pub enum InjectError {
    /// 平台注入调用失败（SendInput 返回 0 / uinput write 失败）。
    #[error("input injection failed: {0}")]
    InjectFailed(String),
    /// 参数非法（分辨率 0、未知 key、越界无法修正等）。
    #[error("invalid input event: {0}")]
    InvalidEvent(String),
    /// 平台未实现或缺少所需权限（如无 uinput 设备）。
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
}

/// 把客户端坐标按分辨率比例缩放到服务端坐标，并 clamp 到 `[0, dst_dim-1]`。
///
/// 计算：`src_val * dst_dim / src_dim`（整数向下取整）。
/// - `src_dim == 0` 或 `dst_dim == 0`（异常分辨率）→ 返回 `None`（上层应报 `InvalidEvent`）。
/// - `src_val >= src_dim`（越界）→ clamp 到 `dst_dim - 1`。
pub fn scale_coord(src_val: u32, src_dim: u32, dst_dim: u32) -> Option<u32> {
    if src_dim == 0 || dst_dim == 0 {
        return None;
    }
    let clamped_src = src_val.min(src_dim.saturating_sub(1));
    let scaled = (clamped_src as u64 * dst_dim as u64 / src_dim as u64) as u32;
    Some(scaled.min(dst_dim.saturating_sub(1)))
}

/// 键鼠注入器：接收可靠流事件 → 完成坐标换算 → 平台 HID 注入。
#[derive(Debug, Clone)]
pub struct InputInjector {
    src_w: u32,
    src_h: u32,
    dst_w: u32,
    dst_h: u32,
}

impl InputInjector {
    /// 新建注入器。`src_w/src_h` 为客户端分辨率，`dst_w/dst_h` 为服务端分辨率。
    pub fn new(src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Self {
        Self { src_w, src_h, dst_w, dst_h }
    }

    /// 服务端分辨率变更（如热插拔显示器）后更新目标基准。
    pub fn set_dst_resolution(&mut self, dst_w: u32, dst_h: u32) {
        self.dst_w = dst_w;
        self.dst_h = dst_h;
    }

    /// M8-T018（SRV-MON-010）：显示器切换后更新换算基准。
    ///
    /// 切换显示器后客户端发送坐标的基数 = 新显示器分辨率（客户端按新窗口
    /// base_w/base_h 归一化），服务端注入侧换算基准同步更新——一次调用
    /// 同时刷新 src/dst（两者均为当前所选显示器分辨率）。
    pub fn set_resolution(&mut self, w: u32, h: u32) {
        self.src_w = w;
        self.src_h = h;
        self.dst_w = w;
        self.dst_h = h;
    }

    /// 处理一条事件（可靠流已保证有序不丢；本方法内完成坐标换算 + 平台注入）。
    ///
    /// 失败（无权限 / 注入被拒 / 非法参数）→ [`InjectError`]，由上层记日志，
    /// **不重试**（可靠流不重发用户操作）。
    pub fn handle(&mut self, ev: InputEvent) -> Result<(), InjectError> {
        // M8-T020: 特殊键不依赖坐标/分辨率——锁屏等在捕获未启动
        // （分辨率未知）时也应可用，直接平台分派。
        if ev.kind == InputKind::SpecialKey {
            return self.dispatch(&ev);
        }

        // Step 1: 校验分辨率非零（异常 → InvalidEvent，不 panic）。
        if self.src_w == 0 || self.src_h == 0 || self.dst_w == 0 || self.dst_h == 0 {
            return Err(InjectError::InvalidEvent(format!(
                "zero resolution: src={}x{} dst={}x{}",
                self.src_w, self.src_h, self.dst_w, self.dst_h
            )));
        }

        // Step 2: 坐标换算 src → dst（向下取整 + clamp）。
        let scaled_x = scale_coord(ev.x, self.src_w, self.dst_w)
            .ok_or_else(|| InjectError::InvalidEvent(format!("x scale failed: x={}", ev.x)))?;
        let scaled_y = scale_coord(ev.y, self.src_h, self.dst_h)
            .ok_or_else(|| InjectError::InvalidEvent(format!("y scale failed: y={}", ev.y)))?;

        let mut scaled = ev;
        scaled.x = scaled_x;
        scaled.y = scaled_y;

        // Step 3: 平台分派。
        self.dispatch(&scaled)
    }

    /// 平台分派（Windows/Linux/macOS；无后端 target 编译期报 UnsupportedPlatform）。
    fn dispatch(&self, ev: &InputEvent) -> Result<(), InjectError> {
        #[cfg(target_os = "windows")]
        {
            crate::windows::inject(ev, self.dst_w, self.dst_h)
        }
        #[cfg(target_os = "linux")]
        {
            crate::linux::inject(ev, self.dst_w, self.dst_h)
        }
        #[cfg(target_os = "macos")]
        {
            crate::macos::inject(ev, self.dst_w, self.dst_h)
        }
        // 无上述目标：编译期明确报 UnsupportedPlatform（不 panic）。
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = (ev, self.dst_w, self.dst_h);
            Err(InjectError::UnsupportedPlatform(
                "no HID injection backend for this target".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coord_scale_2x() {
        // 1920x1080 → 3840x2160（2 倍）。
        let inj = InputInjector::new(1920, 1080, 3840, 2160);
        assert_eq!(scale_coord(0, inj.src_w, inj.dst_w), Some(0));
        assert_eq!(scale_coord(960, inj.src_w, inj.dst_w), Some(1920));
        assert_eq!(scale_coord(100, inj.src_w, inj.dst_w), Some(200));
        // src 中最大有效像素索引（src_dim-1）→ 向下取整得 dst_dim-2。
        assert_eq!(scale_coord(1919, inj.src_w, inj.dst_w), Some(3838));
        // 越界（>= src_dim）先 clamp 到 src_dim-1=1919，再缩放 → 同 3838。
        assert_eq!(scale_coord(1920, inj.src_w, inj.dst_w), Some(3838));
        assert_eq!(scale_coord(5000, inj.src_w, inj.dst_w), Some(3838));
    }

    #[test]
    fn test_coord_scale_downscale() {
        // 3840x2160 → 1920x1080（缩小一半）。
        assert_eq!(scale_coord(3839, 3840, 1920), Some(1919));
        assert_eq!(scale_coord(1920, 3840, 1920), Some(960));
        assert_eq!(scale_coord(1, 3840, 1920), Some(0)); // 向下取整
    }

    #[test]
    fn test_coord_scale_non_integer() {
        // 非整数倍：1920→2560。 1920/2 * 2560/1920 ... 用具体值校验取整。
        // 960 * 2560 / 1920 = 1280（恰好整）。
        assert_eq!(scale_coord(960, 1920, 2560), Some(1280));
        // 100 * 2560 / 1920 = 133.33 → 向下取整 133。
        assert_eq!(scale_coord(100, 1920, 2560), Some(133));
    }

    #[test]
    fn test_resolution_zero() {
        // 分辨率为 0 → InvalidEvent（不 panic）。
        let mut inj = InputInjector::new(0, 0, 1920, 1080);
        let err = inj.handle(InputEvent::mouse_move(10, 10)).unwrap_err();
        assert!(matches!(err, InjectError::InvalidEvent(_)));

        // scale_coord 也应返回 None。
        assert_eq!(scale_coord(10, 0, 1920), None);
        assert_eq!(scale_coord(10, 1920, 0), None);
    }

    #[test]
    fn test_event_deserialize_roundtrip() {
        // bincode 序列化 → 反序列化一致（可靠流 wire 格式）。
        let ev = InputEvent {
            kind: InputKind::KeyDown,
            x: 1234,
            y: 567,
            button: button::LEFT,
            key: Key::A as u32,
            wheel_delta: -3,
            modifiers: modifier::CTRL | modifier::SHIFT,
            text: String::new(),
            combo: None,
        };
        let data = bincode::serialize(&ev).expect("serialize");
        let back: InputEvent = bincode::deserialize(&data).expect("deserialize");
        assert_eq!(ev, back);

        // InputKind 往返。
        for kind in [
            InputKind::MouseMove,
            InputKind::MouseButton,
            InputKind::MouseWheel,
            InputKind::KeyDown,
            InputKind::KeyUp,
            InputKind::KeyRepeat,
            InputKind::Text,
            InputKind::SpecialKey,
        ] {
            let mut e = ev.clone();
            e.kind = kind;
            if kind == InputKind::SpecialKey {
                e.combo = Some(SpecialCombo::CtrlShiftEsc);
            }
            let bytes = bincode::serialize(&e).unwrap();
            let r: InputEvent = bincode::deserialize(&bytes).unwrap();
            assert_eq!(r.kind, kind);
        }
    }

    #[test]
    fn test_text_event_roundtrip_and_default() {
        // Text 事件携带 unicode 字符串往返一致（IME 中文路径）。
        let ev = InputEvent {
            kind: InputKind::Text,
            x: 0,
            y: 0,
            button: 0,
            key: 0,
            wheel_delta: 0,
            modifiers: 0,
            text: "你好, KirinDesk! 🚀".into(),
            combo: None,
        };
        let data = bincode::serialize(&ev).expect("serialize");
        let back: InputEvent = bincode::deserialize(&data).expect("deserialize");
        assert_eq!(back.kind, InputKind::Text);
        assert_eq!(back.text, "你好, KirinDesk! 🚀");

        // 非 Text 事件 text 字段为空串（便捷构造器保证）。
        assert!(InputEvent::mouse_move(1, 2).text.is_empty());
        assert!(InputEvent::key(InputKind::KeyDown, Key::A, 0).text.is_empty());
        // serde default：JSON 等自描述格式缺字段可解析（bincode 位置格式不可省略尾字段）。
        let json = serde_json::to_string(&ev).unwrap();
        let stripped = json.replace(r#","text":"你好, KirinDesk! 🚀""#, "");
        let back: InputEvent = serde_json::from_str(&stripped).expect("json without text field");
        assert!(back.text.is_empty());
    }

    #[test]
    fn test_input_priority_is_max() {
        // 键鼠指令最高优先级（0）。
        assert_eq!(INPUT_PRIORITY, 0);
    }

    /// M8-T020 T001: SpecialCombo 全部变体 bincode 往返一致（wire 格式）。
    #[test]
    fn test_special_combo_roundtrip_all_variants() {
        let combos = [
            SpecialCombo::WinE,
            SpecialCombo::WinD,
            SpecialCombo::WinL,
            SpecialCombo::WinR,
            SpecialCombo::AltTab,
            SpecialCombo::CtrlShiftEsc,
            SpecialCombo::AltF4,
            SpecialCombo::CtrlEsc,
            SpecialCombo::LockScreen,
        ];
        for c in combos {
            let data = bincode::serialize(&c).expect("serialize");
            let back: SpecialCombo = bincode::deserialize(&data).expect("deserialize");
            assert_eq!(back, c, "roundtrip failed for {c:?}");
        }
        // 普通事件与特殊键事件区分（判别式不同）。
        assert_ne!(bincode::serialize(&SpecialCombo::WinE).unwrap(), bincode::serialize(&SpecialCombo::WinD).unwrap());
    }

    /// M8-T020 T001: 特殊键事件构造 + wire 往返（复用 ChannelTag::Input 通道）。
    #[test]
    fn test_special_key_event_wire_roundtrip() {
        let ev = InputEvent::special_key(SpecialCombo::AltTab);
        assert_eq!(ev.kind, InputKind::SpecialKey);
        assert_eq!(ev.combo, Some(SpecialCombo::AltTab));
        // 普通事件 combo 为 None（不携带）。
        assert_eq!(InputEvent::key(InputKind::KeyDown, Key::A, 0).combo, None);

        for combo in [
            SpecialCombo::WinE,
            SpecialCombo::CtrlShiftEsc,
            SpecialCombo::LockScreen,
        ] {
            let ev = InputEvent::special_key(combo);
            let data = bincode::serialize(&ev).expect("serialize");
            let back: InputEvent = bincode::deserialize(&data).expect("deserialize");
            assert_eq!(back, ev);
        }
    }

    /// M8-T020 UI-SKEY-001/002: 面板文案（label）与提示（hint）齐全。
    #[test]
    fn test_special_combo_labels() {
        assert_eq!(SpecialCombo::WinE.label(), "Win+E");
        assert_eq!(SpecialCombo::CtrlShiftEsc.label(), "Ctrl+Shift+Esc");
        assert_eq!(SpecialCombo::LockScreen.label(), "锁屏");
        // 锁屏 tooltip 明确标注 CAC 限制（UI-SKEY-002：不提供无效 CAC 注入）。
        assert!(SpecialCombo::LockScreen.hint().contains("Ctrl+Alt+Del"));
        assert!(!SpecialCombo::LockScreen.hint().is_empty());
        for c in [
            SpecialCombo::WinD,
            SpecialCombo::WinL,
            SpecialCombo::WinR,
            SpecialCombo::AltTab,
            SpecialCombo::AltF4,
            SpecialCombo::CtrlEsc,
        ] {
            assert!(!c.label().is_empty());
            assert!(!c.hint().is_empty());
        }
    }

    /// M8-T020: 特殊键注入不依赖分辨率——分辨率未知（0）时
    /// 平台分派正常进入（Windows 上会真实注入，故仅验证桩平台/错误语义：
    /// 非三平台 → UnsupportedPlatform，而不是分辨率 InvalidEvent）。
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_special_key_ignores_zero_resolution() {
        let mut inj = InputInjector::new(0, 0, 0, 0);
        let ev = InputEvent::special_key(SpecialCombo::LockScreen);
        // 分辨率 0 时普通事件报 InvalidEvent，特殊键则走到平台分派（报 UnsupportedPlatform）。
        let err = inj.handle(ev).unwrap_err();
        assert!(matches!(err, InjectError::UnsupportedPlatform(_)));
    }

    /// 真实注入 1 条 Move(0,0) 到本机 SendInput。
    /// 默认 skip（会真实移动鼠标），留给本机手动验证。
    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "real HID injection moves the cursor; run manually with --ignored"]
    fn test_inject_smoke() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        let ev = InputEvent::mouse_move(0, 0);
        inj.handle(ev).expect("smoke inject should succeed");
    }

    // ════════════════════════════════════════════════════════════
    // M8-T018（SRV-MON-010）：按所选显示器分辨率的坐标换算
    // ════════════════════════════════════════════════════════════

    /// 屏0（主，1920x1080）全范围换算：客户端基数 = 屏0 分辨率时，坐标
    /// 注入点 = 客户端像素（1:1，向下取整 + clamp 边界）。
    #[test]
    fn test_scale_coord_monitor0_full_range() {
        // src == dst == 屏0（1920x1080）：同分辨率注入。
        let inj = InputInjector::new(1920, 1080, 1920, 1080);
        assert_eq!(scale_coord(0, inj.src_w, inj.dst_w), Some(0));
        assert_eq!(scale_coord(1919, inj.src_w, inj.dst_w), Some(1919));
        // 越界 clamp 到 dst_dim-1。
        assert_eq!(scale_coord(1920, inj.src_w, inj.dst_w), Some(1919));
        assert_eq!(scale_coord(0, inj.src_h, inj.dst_h), Some(0));
        assert_eq!(scale_coord(1079, inj.src_h, inj.dst_h), Some(1079));
    }

    /// 屏1（2560x1440）全范围换算：客户端基数 = 屏1 分辨率时，坐标注入
    /// 点 = 客户端像素（1:1）；与屏0 基数区分（不同分辨率不同换算）。
    #[test]
    fn test_scale_coord_monitor1_full_range() {
        let inj = InputInjector::new(2560, 1440, 2560, 1440);
        assert_eq!(scale_coord(0, inj.src_w, inj.dst_w), Some(0));
        assert_eq!(scale_coord(2559, inj.src_w, inj.dst_w), Some(2559));
        assert_eq!(scale_coord(2560, inj.src_w, inj.dst_w), Some(2559)); // 越界 clamp
        assert_eq!(scale_coord(0, inj.src_h, inj.dst_h), Some(0));
        assert_eq!(scale_coord(1439, inj.src_h, inj.dst_h), Some(1439));
        // 归一化同一点（50%）在不同屏基数下的像素坐标不同：
        // 屏0 基数 1920 → 960；屏1 基数 2560 → 1280（CLI-MON-010 基数跟随）。
        assert_eq!(scale_coord(960, 1920, 1920), Some(960));
        assert_eq!(scale_coord(1280, 2560, 2560), Some(1280));
    }

    /// 非 1:1 视口：归一化坐标基数 = 所选显示器分辨率，视口按此缩放。
    /// （客户端窗口 960x540 视口 → 屏1 2560x1440：同一归一化点换算一致。）
    #[test]
    fn test_scale_coord_viewport_to_monitor() {
        // 视口 960x540 → 屏1 2560x1440（2.666x 放大）。
        assert_eq!(scale_coord(480, 960, 2560), Some(1280));
        assert_eq!(scale_coord(270, 540, 1440), Some(720));
        // 视口 960x540 → 屏0 1920x1080（2x 放大）。
        assert_eq!(scale_coord(480, 960, 1920), Some(960));
        assert_eq!(scale_coord(270, 540, 1080), Some(540));
    }

    /// set_resolution：显示器切换后换算基准同步更新（src/dst 均为新屏分辨率）。
    #[test]
    fn test_set_resolution_after_monitor_switch() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        // 切换前：屏0 基数（1:1 全范围）。
        assert_eq!(scale_coord(1919, inj.src_w, inj.dst_w), Some(1919));
        // 切换 → 屏1（2560x1440）：基准立即更新（CLI-MON-010 切换后立即生效）。
        inj.set_resolution(2560, 1440);
        assert_eq!(inj.src_w, 2560);
        assert_eq!(inj.src_h, 1440);
        assert_eq!(inj.dst_w, 2560);
        assert_eq!(inj.dst_h, 1440);
        // 屏1 基数下全范围 1:1。
        assert_eq!(scale_coord(2559, inj.src_w, inj.dst_w), Some(2559));
        // 同一数值在不同屏基数下的边界语义不同：1920 在屏0 基数下越界
        // clamp 到 1919；在屏1 基数下仍在界内（→1920）。
        assert_eq!(scale_coord(1920, 1920, 1920), Some(1919));
        assert_eq!(scale_coord(1920, 2560, 2560), Some(1920));
        // set_dst_resolution（仅改目标基准）仍可用：缩放到新基准。
        inj.set_dst_resolution(3840, 2160);
        assert_eq!(scale_coord(1920, inj.src_w, inj.dst_w), Some(2880));
    }
}
