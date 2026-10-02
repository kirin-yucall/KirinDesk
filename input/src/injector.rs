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

///
/// 实际光标位置（`GetCursorPos`）与上次注入目标坐标在任一轴上的偏差**超过**
/// 该阈值，判定本地用户在物理操作鼠标 → 开启抑制窗口
/// （[`LOCAL_INPUT_SUPPRESS_MS`]）。8px ≈ 100% DPI 下 1 个物理像素
/// （高 DPI / 多显示器场景可调，见 CHANGELOG 遗留清单）。
pub const LOCAL_ACTIVITY_THRESHOLD_PX: i32 = 8;

///
/// 检测到本地物理活动时开启：窗口内**丢弃远端 MouseMove**（按钮 / 键盘 /
/// 滚轮不抑制——避免远端拖拽 / 打字状态混乱）；窗口过后恢复正常注入
/// （自然重新对齐；本地活动持续时下次注入前会再次检测并重新开窗）。
///
/// 2000ms 保留**——本地活动 → 挂起远端指针注入（窗口内丢弃）；本地静止
/// 超时（≥2000ms）→ 恢复客户端注入（客户端下一次移动按绝对坐标自然
/// 的校正注入），本窗口即本地优先语义的全部机制面。
pub const LOCAL_INPUT_SUPPRESS_MS: u64 = 2000;

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
    // 注入——被控端 IME 的中英文切换〔Shift / Ctrl+Space〕监听的就是这条
    // 物理层键流）。判别式**追加**在枚举尾部 = bincode wire 向后兼容
    // （旧端遇到新判别式仅该包反序列化失败丢弃，不动既有键值）。
    Shift = 0x53,
    Ctrl = 0x54,
    Alt = 0x55,
    Super = 0x56,
    // 兼容：旧端遇到新判别式仅该包反序列化失败丢弃）。前 11 个有独立物理键
    // （各平台注入层映射到本地 scan code / kVK / keycode）；Colon/Pipe/
    // Questionmark 无独立物理键，映射到相邻物理键语义（Colon→Semicolon /
    // Pipe→Backslash / Questionmark→Slash），Shift 语义由既有独立修饰键帧差
    // 事件表达（不在此层合成）。
    Period = 0x57,
    Comma = 0x58,
    Semicolon = 0x59,
    Slash = 0x5A,
    Minus = 0x5B,
    Equals = 0x5C,
    OpenBracket = 0x5D,
    CloseBracket = 0x5E,
    Backslash = 0x5F,
    Quote = 0x60,
    Backtick = 0x61,
    // 无独立物理键（Shift 组合语义）：注入层映射到相邻物理键。
    Colon = 0x62,
    Pipe = 0x63,
    Questionmark = 0x64,
    // 小键盘 +（egui-winit 0.28.1 `NumpadAdd => Key::Plus`，全文件唯一
    // 来源；主排 = 走 `Key::Equals`）→ 注入层映射小键盘加号 KpAdd
    // （Windows Set 1 非扩展 0x4E / Linux KEY_KPPLUS 0x4E / macOS
    // **废弃**（0x0D 是主排 = 键 scan code，注入 = 错键）。
    Plus = 0x65,
    // 「小键盘 . 零命中」）：小键盘专用键，**egui 架构不可达**（egui 0.28
    // `Key` 枚举无 Asterisk/Decimal 变体，egui-winit 两表对
    // NumpadMultiply/NumpadDecimal 零臂）→ 仅会话窗 UI 补偿按钮路径发送。
    // 数值/顺序零改动，bincode wire 向后兼容：旧端遇到新判别式仅该包
    // 反序列化失败丢弃）。
    KpMultiply = 0x66,
    KpDecimal = 0x67,
    // down+up 单对（远端硬件/系统完成状态翻转，远端即 ground truth；与
    // （`InputEvent.key` 为 `u32` 字段，无变体校验）→ 旧端平台映射表无此
    // 行 → `map_scan_code` = `None` → `InjectError::InvalidEvent` → 该事件
    // 丢弃 + WARN（会话不中断；「反序列化失败」分支本场景不可达）。
    NumLock = 0x68,
}

pub fn modifier_bit_for_key(key: u32) -> u8 {
    match key {
        k if k == Key::Shift as u32 => modifier::SHIFT,
        k if k == Key::Ctrl as u32 => modifier::CTRL,
        k if k == Key::Alt as u32 => modifier::ALT,
        k if k == Key::Super as u32 => modifier::SUPER,
        _ => 0,
    }
}

///
/// 供 [`InputInjector::handle`]「自位排除」使用：桌面端独立修饰键事件路径
/// 的 down/up 由 `dispatch` 按 scan code 注入（与物理键同流、IME 直接
/// 监听）；`modifier_sync` 不得再对该键做 VK 补按 / 释放——重复 down 在
pub fn self_modifier_bit(ev: &InputEvent) -> u8 {
    match ev.kind {
        InputKind::KeyDown | InputKind::KeyUp | InputKind::KeyRepeat => modifier_bit_for_key(ev.key),
        _ => 0,
    }
}

///
/// - `release`：本路径已补按（`we_pressed`）且本事件 flags 不再需要的位；
/// - `press`：flags 需要、且物理未按下（`physical`，如 `GetAsyncKeyState`
///   查询结果——桌面端独立修饰键事件路径在此天然去重）、且尚未补按的位。
///
/// 返回 `(press, release)`。原实现内联在 [`InputInjector::modifier_sync`]
/// 中断言（见 `r77c_*`）。
pub fn modifier_sync_plan(we_pressed: u8, flags: u8, physical: u8) -> (u8, u8) {
    let release = we_pressed & !flags;
    let press = flags & !physical & !we_pressed;
    (press, release)
}

///
/// 输入 = 修饰键**物理按下态**位图（Windows 经
/// [`crate::windows::modifier_physical_state`] 读 `GetAsyncKeyState`；非 Windows
/// 平台无该状态 = 0）；输出 = 需经 `send_modifier_keys(plan, false)` 一次
/// 释放的位集合。
///
/// 口径：
/// - **只保留四个已定义修饰键位**（CTRL/SHIFT/ALT/SUPER）——未知位污染
///   （位图来源异常）掩掉，防误释放；
/// - **四位全释放（含 Win/SUPER）**——会话启动时被控端本地残留的物理
///   按下态（旧包 LWIN VK 补按路径 + 持 Ctrl 异常断连可残留；或物理卡键）
///   一律视为无效整体释放：残留 Win 使 `Ctrl+O` 变成系统热键 `Ctrl+Win+O`
///   误弹 OSK、残留修饰键使 `Ctrl+C`/`Ctrl+V` 语义错乱（用户两轮复测并存
///   现象，与「Win 键残留按下态」假设自洽）；
/// - `residual = 0` → `plan = 0`（不产生事件，调用方记 `clean` 对账行）。
///
/// （we_pressed vs flags vs physical），本函数管**会话边界**的整体复位
pub fn hygiene_release_plan(residual: u8) -> u8 {
    residual & (modifier::CTRL | modifier::SHIFT | modifier::ALT | modifier::SUPER)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveGuardVerdict {
    /// 照常注入（调用方在注入成功后负责更新注入基线）。
    Inject,
    /// 丢弃：本地物理活动抑制窗口生效（含本次检测刚开窗）。
    /// 按钮 / 键盘 / 滚轮不受本守卫影响（不走此路径）。
    DroppedSuppressed,
    /// 跳过：去重命中（与上次注入坐标相同且按键状态无变化）。
    DroppedDedup,
}

/// 本地活动优先级**转换**（纯观测记账，零决策参与——`move_guard` 在
/// 观测行后槽即空，不双发）。
///
/// - [`Suspended`]：本地物理活动检测命中 → 抑制窗口开启 = **挂起远端
///   指针注入**（窗口内客户端 Move 全部丢弃；坐标 = 检测时刻**实际
///   光标位置**，与基线重置值同源）；
/// - [`Resumed`]：抑制窗口过期 = **恢复客户端注入**（坐标 = 触发本次
///   判定的客户端 Move **绝对坐标**——客户端下一次移动按绝对坐标自然
///   就位，**无任何向客户端锚点的校正 / 拉回注入**）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPriorityTransition {
    /// 本地活动 → 远端指针注入挂起（抑制窗口开启）。
    Suspended,
    /// 本地静止超时 → 客户端注入恢复（抑制窗口过期）。
    Resumed,
}

/// LEFT→RIGHT→MIDDLE）。
///
/// - 仅为**按下**的位生成 up（未按下位不生成——对未按下键发 up 是无害
///   no-op，但不生成更干净；`release_all` 的幂等性据此成立）；
/// - `pos` = 释放位置（取最后注入基线）：Windows 按钮事件不消费坐标
///   （`SendInput` 无 `MOUSEEVENTF_MOVE` 位时位置不变），其他平台避免
///   把光标 warp 到 (0,0)；
/// - wire 协议 [`button`] 仅定义 LEFT/RIGHT/MIDDLE（**无 X1/X2**）；
///   未来协议新增按键时同步扩展本表。
pub fn release_all_up_events(bits: u8, pos: (u32, u32)) -> Vec<InputEvent> {
    let mut out = Vec::new();
    for bit in [button::LEFT, button::RIGHT, button::MIDDLE] {
        if bits & bit != 0 {
            out.push(InputEvent::mouse_button(bit | button::RELEASE, pos.0, pos.1));
        }
    }
    out
}

/// 纯函数——修饰键强制释放的 KeyUp 事件序列（canonical 顺序
/// Ctrl→Shift→Alt→Super，`modifiers` 全 0）。
///
/// - **4 键无条件全生成**（不按位过滤）：对未按下键发 up 为无害 no-op
///   （PS/2 make/break 对已抬起键无副作用），与 [`InputInjector::release_all`]
///   桌面端独立修饰键事件（`Key::Shift/Ctrl/Alt/Super` down/up）由
///   `dispatch` 经 scan code 直接注入、**不进入** `mods_we_pressed`，
///   故「持 Ctrl 断连」时旧 `release_all`（仅释放鼠标键 + `mods_we_pressed`
/// - 事件走常规 Key 分派（平台映射表 → scan code / kVK / keycode 的
///   KEYUP，与物理键同流、布局无关）；
/// - 按钮路径 [`release_all_up_events`] 的「仅按下位生成」口径保留
///   （按钮有 `last_button_bits` 状态可依，两路径各按自身状态机最干净
///   形态生成）。
pub fn release_all_modifier_up_events() -> Vec<InputEvent> {
    [Key::Ctrl, Key::Shift, Key::Alt, Key::Super]
        .iter()
        .map(|k| InputEvent::key(InputKind::KeyUp, *k, 0))
        .collect()
}


/// 跨平台可单测）。
///
/// 由**被控端本地** caps 态决定，而用户预期由**主控端本地** caps 态决定——
/// 两端 caps 不同步且无补偿时，一端 caps 开/另一端关 → 打出的字母大小写与
/// 本地键位语义不一致（用户 09-18 复测 §4）。
///
/// 决策（推导见交付报告）：用户预期大小写翻转 = `local XOR s`（s=事件自带
/// shift），远端实际 = `remote XOR s XOR o`（o=补偿叠加 shift）→ 令两者相等
/// → **`o = local XOR remote`，与 s 无关**——两端 caps 异或为 1 时，对 26 字母
/// 的 KeyDown/KeyRepeat **恒**叠加 shift（用户已持 shift 时双 shift 相消 =
/// 恰为预期的非 caps 大小写）。
///
/// 口径：
/// - 仅 `KeyDown`/`KeyRepeat`（`KeyUp` **不**叠加——shift 释放时序由既有
///   flags 帧差状态机管，up 叠加 = 用户松键后无后续事件时 shift 粘连）；
/// - 26 字母 = `Key::A..=Key::Z` 判别式区间（0x04..=0x1D 连续，单测钉死）；
/// - 叠加 = `modifiers |= SHIFT`，**注入机制零新增**：后续 `modifier_sync`
///   既有物理态去重（`GetAsyncKeyState`）完成补按/释放——注入仍走
///   `injector::InputEvent`（§0-① 第 6 条红线）；
/// - 两端态一致（含**旧端默认 `remote_caps=false`** 场景）→ 原事件零改动
///   返回（现状行为，零回归）。
///
/// 消费点 = `ui/src/lib.rs` 服务端 Input 臂（per-session `peer_caps` × 本端
/// `r129_local_caps_state`）——共享注入器多观众共用，per-session 态不落注入器
/// 字段（落字段 = 最后推送者覆盖 = 多客户端互串，交付报告记档）。
pub fn r132_4_caps_compensate(ev: InputEvent, local_caps: bool, remote_caps: bool) -> InputEvent {
    let letter_down =
        matches!(ev.kind, InputKind::KeyDown | InputKind::KeyRepeat)
            && ((Key::A as u32)..=(Key::Z as u32)).contains(&ev.key);
    if letter_down && local_caps != remote_caps {
        let mut ev = ev;
        ev.modifiers |= modifier::SHIFT;
        ev
    } else {
        ev
    }
}

/// 跨平台可单测）。
///
/// 注入 numpad multiply（scan 0x37 / VK 0x6A）无法稳定打出 `*`；主键盘
/// `Shift+8` = 全 QWERTY 布局通用的 `*` 产生路径 → KP* 的**语义**（打出 `*`）
/// 改由 Shift+8 表达。
///
/// 落点 = 注入侧（本注入器 `handle` 内展开）而非捕获侧（`kbd_hook.rs:517`
/// `scan_code_to_blind_key`）——理由：① 单一生产点全覆盖（KP* 生产方 = 钩子
/// 同样生效）；② **wire 零改动**（线上仍 `Key::KpMultiply` 0x66 既有判别式，
/// 旧服务端行为逐位不变 = 零回归；新服务端展开 = 新包才生效，出包两端同换
/// 后 179 复测即终判）；③ 展开产物 = 既有判别式（`Key::Shift` 0x53 /
/// `Key::Num8` 0x25）事件序列，旧格式兼容（`InputEvent` 零新增字段）。
///
/// 形态（物理键流同构：修饰键按下→主键按下→主键抬起→修饰键抬起，释放步
/// 必达不粘连——M8-T020 `plan_special_key` 同纪律）：
/// - `KpMultiply` `KeyDown`/`KeyRepeat` → `[Shift↓, Num8↓]`（auto-repeat 期间
///   重复 down 再发 Shift↓ = Windows 已按下键的无害 no-op，状态无关）；
/// - `KpMultiply` `KeyUp` → `[Num8↑, Shift↑]`；
/// - 其余一切事件 → `None`（调用方直接用原事件，**热路径零分配**）。
///
/// 失败语义（`handle` 接线处）：展开序列任一步失败**不中断**后续步
/// （释放步必达，防 shift 粘连；M8-T020「释放批必定执行」同语义），返回
/// 首个错误。
pub fn r132_4_kp_star_expand(ev: &InputEvent) -> Option<(InputEvent, Option<InputEvent>)> {
    if ev.key != Key::KpMultiply as u32 {
        return None;
    }
    match ev.kind {
        InputKind::KeyDown | InputKind::KeyRepeat => {
            Some((InputEvent::key(InputKind::KeyDown, Key::Shift, 0), Some(InputEvent::key(InputKind::KeyDown, Key::Num8, 0))))
        }
        InputKind::KeyUp => {
            Some((InputEvent::key(InputKind::KeyUp, Key::Num8, 0), Some(InputEvent::key(InputKind::KeyUp, Key::Shift, 0))))
        }
        _ => None,
    }
}

/// 自己的时间，不走本函数）。
fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
    ///（移动端 nativeSendKey2 只带 mod 位标志、无独立修饰键事件——注入
    /// 前补按缺失修饰键；后续事件 flags 撤销时释放）。物理上已按下的
    /// 修饰键（桌面端独立 Ctrl 等键事件路径）不在此列，不会被本注入器
    /// 误释放。
    mods_we_pressed: u8,
    /// `mods_we_pressed` 同型状态机）：MouseButton 按下置位 / 抬起清位；
    /// [`Self::release_all`] 依据它只释放真正按下的按钮（对未按下键发 up
    /// 为无害 no-op）。
    last_button_bits: u8,
    ///（`None` = 基线 (0,0)，本会话尚未注入过 Move = 首帧未到）。
    /// 双重职责：本地活动判定比对基线 + Move 去重比对基线。
    last_injected_move: Option<(u32, u32)>,
    last_move_button_bits: u8,
    suppress_until_ms: Option<u64>,
    /// 判定）——纯观测记账（srv-in 行 x/y/g 字段源；只读，不参与任何
    /// 注入决策，去重/抑制语义零变化）。非 Move 事件清槽（防 srv-in 行
    /// 跨事件带出陈旧坐标）；dst (0,0) 早退丢弃臂显式清槽。
    last_move_observation: Option<(u32, u32, MoveGuardVerdict)>,
    /// `None` = 无待取转换 / 已被调用点取走）。写入点 = `move_guard`
    /// 抑制窗口开启（Suspended）/ 过期（Resumed）；清点与
    /// `last_move_observation` 同点同清（非 Move 事件 / dst(0,0) 早退 /
    /// 守卫状态重置），防跨事件带出陈旧转换。
    last_local_priority: Option<(LocalPriorityTransition, (u32, u32))>,
}

impl InputInjector {
    /// 新建注入器。`src_w/src_h` 为客户端分辨率，`dst_w/dst_h` 为服务端分辨率。
    pub fn new(src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Self {
        Self {
            src_w,
            src_h,
            dst_w,
            dst_h,
            mods_we_pressed: 0,
            last_button_bits: 0,
            last_injected_move: None,
            last_move_button_bits: 0,
            suppress_until_ms: None,
            last_move_observation: None,
            last_local_priority: None,
        }
    }

    /// 服务端分辨率变更（如热插拔显示器）后更新目标基准。
    ///
    /// 基线）重置；按键 / 修饰键**物理**状态（分辨率无关）保留。
    pub fn set_dst_resolution(&mut self, dst_w: u32, dst_h: u32) {
        self.dst_w = dst_w;
        self.dst_h = dst_h;
        self.reset_move_guard_state();
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
        self.reset_move_guard_state();
    }

    /// 按键 / 修饰键物理状态（`last_button_bits` / `mods_we_pressed`）
    /// 分辨率无关，不在本方法内重置（由 `release_all` 统一释放）。
    fn reset_move_guard_state(&mut self) {
        self.last_injected_move = None;
        self.last_move_button_bits = 0;
        self.suppress_until_ms = None;
        // 基准下的陈旧坐标；与去重基线同点同清）。
        self.last_move_observation = None;
        self.last_local_priority = None;
    }

    /// `None` = 尚无观测 / 已被非 Move 事件清槽）。纯只读，不参与任何
    /// 注入决策（去重/抑制语义零变化）。
    pub fn last_move_observation(&self) -> Option<(u32, u32, MoveGuardVerdict)> {
        self.last_move_observation
    }

    /// `None` = 本事件无转换 / 已被取走。纯观测记账，不参与任何注入
    /// 决策（去重/抑制语义零变化）。调用点 = 服务端 Input 臂（注入器
    pub fn take_local_priority_event(
        &mut self,
    ) -> Option<(LocalPriorityTransition, (u32, u32))> {
        self.last_local_priority.take()
    }

    /// [`Self::take_local_priority_event`] 消费口径）。
    pub fn last_local_priority(&self) -> Option<(LocalPriorityTransition, (u32, u32))> {
        self.last_local_priority
    }

    /// 坐标换算 + 平台注入）。
    ///
    /// 失败（无权限 / 注入被拒 / 非法参数）→ [`InjectError`]，由上层记日志，
    /// **不重试**（可靠流不重发用户操作）。
    ///
    /// 展开为 Shift+主键盘 8 序列（被控端无小键盘时打出 `*`，见该函数 doc）；
    /// 其余事件 `None` 直透（热路径零分配、行为逐位不变）。展开序列任一步
    /// 失败不中断后续步（**释放步必达**，防 shift 粘连——M8-T020「释放批
    /// 必定执行」同语义），返回首个错误。
    pub fn handle(&mut self, ev: InputEvent) -> Result<(), InjectError> {
        match r132_4_kp_star_expand(&ev) {
            None => self.handle_one(ev),
            Some((first, second)) => {
                let mut first_err: Option<InjectError> = None;
                if let Err(e) = self.handle_one(first) {
                    first_err = Some(e);
                }
                if let Some(second) = second {
                    if let Err(e) = self.handle_one(second) {
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

    /// 单事件处理管线（[`Self::handle`] 的展开内层——坐标换算 + 平台注入）。
    fn handle_one(&mut self, ev: InputEvent) -> Result<(), InjectError> {
        // 最近 Move 观测，跨事件不清 = 非移动事件行带出陈旧移动坐标
        // （观测面污染；注入决策零触碰）。
        // 产生；非 Move 事件不得带出陈旧转换）。
        if ev.kind != InputKind::MouseMove {
            self.last_move_observation = None;
            self.last_local_priority = None;
        }

        // M8-T020: 特殊键不依赖坐标/分辨率——锁屏等在捕获未启动
        // （分辨率未知）时也应可用，直接平台分派。
        if ev.kind == InputKind::SpecialKey {
            return self.dispatch(&ev);
        }

        // 修饰键先补按（跟踪进 `mods_we_pressed`）；此前补按、现已不被 flags
        // 需要的修饰键释放。物理已按下的（桌面端独立 Ctrl 等键事件路径）不动——
        // `modifier_sync` 内部按实际键态判定，漏发无副作用。非 Windows 平台
        // 暂为 no-op（沿用旧语义，仅位标志不被消费）。
        // 路径，`Key::Shift/Ctrl/Alt/Super`）由下方 `dispatch` 以 scan code
        // 注入（KEYEVENTF_SCANCODE，与物理键同流、IME 直接监听），此处从
        // flags 中排除，避免 `modifier_sync` 再按 VK 补按一次 = 同一修饰键
        // 双份 down（「按每次 keydown 切换」的 IME 会双切换 = 无效）。
        self.modifier_sync(ev.modifiers & !self_modifier_bit(&ev));

        // mobile/src/jni.rs：base=(0,0)=首帧未到，移动事件丢弃）：dst 分辨率
        // (0,0) = 服务端捕获首帧未到（坐标基准无效）→ 丢弃 Move 事件（不误
        // 注入 (0,0)、不把光标拽到屏幕角）；非 Move 事件仍走下方原有
        // InvalidEvent 语义（协议错误，非时序问题）。
        if ev.kind == InputKind::MouseMove && (self.dst_w == 0 || self.dst_h == 0) {
            tracing::debug!(
                "r74b: drop mouse move (dst={}x{}, first frame not arrived)",
                self.dst_w, self.dst_h
            );
            self.last_move_observation = None;
            self.last_local_priority = None;
            return Ok(());
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

        // 置位 / 抬起清位；`release_all` 与 Move 去重依据此状态。
        if ev.kind == InputKind::MouseButton {
            let which = ev.button & 0x07;
            if ev.button & button::RELEASE != 0 {
                self.last_button_bits &= !which;
            } else {
                self.last_button_bits |= which;
            }
        }

        let mut scaled = ev;
        scaled.x = scaled_x;
        scaled.y = scaled_y;

        // 时间 / 光标位置经参数注入可单测）。GetCursorPos 失败（None）→
        // 退化现状行为 = 照常注入 + debug 日志（体验机制不做 fail-closed）。
        if scaled.kind == InputKind::MouseMove {
            let now = now_epoch_ms();
            let cursor = crate::windows::cursor_pos();
            if cursor.is_none() {
                tracing::debug!(
                    "r74b: cursor_pos unavailable — local priority check degraded (inject as-is)"
                );
            }
            let verdict = self.move_guard((scaled.x, scaled.y), now, cursor);
            self.last_move_observation = Some((scaled.x, scaled.y, verdict));
            match verdict {
                MoveGuardVerdict::Inject => {}
                MoveGuardVerdict::DroppedSuppressed | MoveGuardVerdict::DroppedDedup => {
                    return Ok(());
                }
            }
        }

        // Step 3: 平台分派。
        let result = self.dispatch(&scaled);

        // 实际移动，保留旧基线更准确；按钮状态机已在注入前更新，不受影响）。
        if scaled.kind == InputKind::MouseMove && result.is_ok() {
            self.last_injected_move = Some((scaled.x, scaled.y));
            self.last_move_button_bits = self.last_button_bits;
        }
        result
    }

    ///
    /// 语义（详见 `handle` 内调用点注释）：
    /// - **补按**：flags 置位且该修饰键物理未按下（`GetAsyncKeyState` 查询，
    ///   已按下的不重复按——桌面端独立 Ctrl 键事件路径天然去重）→ 注入
    ///   keydown，位记入 `mods_we_pressed`；
    /// - **释放**：`mods_we_pressed` 置位且本事件 flags 已撤销 → 注入 keyup，
    ///   位清除（物理按下的修饰键永不因本路径释放——它的释放来自对端
    ///   独立的修饰键 KeyUp 事件）。
    /// - 非 Windows：no-op。
    fn modifier_sync(&mut self, flags: u8) {
        #[cfg(target_os = "windows")]
        {
            // 不受影响）。
            let (press, release) =
                modifier_sync_plan(self.mods_we_pressed, flags, crate::windows::modifier_physical_state());
            if release != 0 {
                crate::windows::send_modifier_keys(release, false);
                let after = self.mods_we_pressed & !release;
                // 变化）各记一行 INFO（每次组合按/释周期至多两行，低频）；
                // 普通按键/组合键不逐条记（吸取 Capture 逐帧刷屏教训）。
                tracing::info!(
                    self.mods_we_pressed,
                    after
                );
                self.mods_we_pressed = after;
            }
            if press != 0 {
                crate::windows::send_modifier_keys(press, true);
                let after = self.mods_we_pressed | press;
                tracing::info!(
                    self.mods_we_pressed,
                    after
                );
                self.mods_we_pressed = after;
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = flags;
        }
    }

    /// 注入，单测无需依赖 GetCursorPos / 真实时钟）。
    ///
    /// 本函数及注入器内不存在任何「向客户端锚点」的校正 / 拉回注入路径，
    /// 注入坐标恒 = 客户端 Move 事件自身换算后绝对坐标）：
    /// - 本地活动 → 挂起远端指针注入（抑制窗口，[`LOCAL_INPUT_SUPPRESS_MS`]
    ///   现值 2000ms 保留）；
    /// - 本地静止超时 → 恢复客户端注入（客户端下一次移动按绝对坐标自然
    ///   就位，无需拉回）。
    ///
    /// 判定顺序：
    /// ① **抑制窗口生效**（[`LOCAL_INPUT_SUPPRESS_MS`]）→ 丢弃本条 Move
    ///    （窗口仅作用于 MouseMove；按钮 / 键盘 / 滚轮不走本守卫，避免
    ///    远端拖拽 / 打字状态混乱）；窗口**过期** → 清窗口、恢复正常注入
    ///    （自然重新对齐）+ 记 [`LocalPriorityTransition::Resumed`] 观测
    ///    （坐标 = 本条客户端 Move 绝对坐标）；
    /// ② **本地物理活动检测**（`cursor_px` = GetCursorPos 纯查询结果；
    ///    `None` = 查询失败 / 非 Windows → 退化现状行为，不判定不误抑制）：
    ///    与上次注入基线（`last_injected_move`）任一轴偏差**超过**
    ///    [`LOCAL_ACTIVITY_THRESHOLD_PX`] → 本地用户在物理操作鼠标 →
    ///    开启抑制窗口 + **注入坐标基线重置为当前实际光标位置**（后续比对
    ///    以实际位置为基准，不重复误判）→ 丢弃本条 Move + 记
    ///    [`LocalPriorityTransition::Suspended`] 观测（坐标 = 检测时刻实际
    ///    光标位置，与基线重置值同源）；
    /// ③ **Move 去重**：与上次注入坐标相同且按键状态（`last_button_bits`
    ///    vs `last_move_button_bits`）无变化 → 跳过（省一次 SendInput 调用，
    /// 其余 → [`MoveGuardVerdict::Inject`]（`handle` 在注入成功后更新基线；
    /// 注入坐标 = 客户端 Move 自身换算后坐标，绝对坐标自然就位）。
    fn move_guard(
        &mut self,
        px: (u32, u32),
        now_ms: u64,
        cursor_px: Option<(i32, i32)>,
    ) -> MoveGuardVerdict {
        // ① 抑制窗口内 → 丢弃；过期 → 清窗口、恢复正常注入（自然重新对齐）
        //    + Resumed 观测（客户端注入恢复，坐标 = 本条 Move 绝对坐标）。
        if let Some(until) = self.suppress_until_ms {
            if now_ms < until {
                return MoveGuardVerdict::DroppedSuppressed;
            }
            self.suppress_until_ms = None;
            self.last_local_priority = Some((LocalPriorityTransition::Resumed, px));
        }
        // ② 本地物理活动检测（无基线 = 首帧未到 / 本会话首条 Move：无比对
        // 基准，首条 Move 照常注入并建立基线）→ 开窗 + Suspended 观测
        //    （本地活动挂起注入，坐标 = 实际光标位置）+ 基线重置。
        if let (Some((cx, cy)), Some((lx, ly))) = (cursor_px, self.last_injected_move) {
            let dx = (cx - lx as i32).abs();
            let dy = (cy - ly as i32).abs();
            if dx > LOCAL_ACTIVITY_THRESHOLD_PX || dy > LOCAL_ACTIVITY_THRESHOLD_PX {
                self.suppress_until_ms =
                    Some(now_ms.saturating_add(LOCAL_INPUT_SUPPRESS_MS));
                let actual = (cx.max(0) as u32, cy.max(0) as u32);
                self.last_injected_move = Some(actual);
                self.last_local_priority = Some((LocalPriorityTransition::Suspended, actual));
                return MoveGuardVerdict::DroppedSuppressed;
            }
        }
        // ③ 去重：同坐标 + 按键状态无变化 → 跳过。
        if self.last_injected_move == Some(px) && self.last_move_button_bits == self.last_button_bits
        {
            return MoveGuardVerdict::DroppedDedup;
        }
        MoveGuardVerdict::Inject
    }

    /// 停止 / 媒体会话收尾，多路径可重复调用）。
    ///
    /// - **按钮**：按 `last_button_bits` 只释放真正按下的按键（canonical
    ///   顺序 LEFT→RIGHT→MIDDLE，纯函数 [`release_all_up_events`]）——对
    ///   未按下键发 up 为无害 no-op，故本方法**幂等**：已释放状态下再次
    ///   调用不产生任何事件；
    ///   `send_modifier_keys(bits, false)`；非 Windows 无该状态，no-op）；
    ///   （canonical 顺序 Ctrl→Shift→Alt→Super，纯函数
    ///   修饰键事件路径（scan code 直接注入、不进 `mods_we_pressed`）：
    ///   持 Ctrl 异常断连时旧实现对其零覆盖，残留被控端直到下一会话
    /// - **Move 守卫状态**：重置（去重基线 / 抑制窗口 / 按键基线），新会话
    ///   从零开始（新会话首帧保护重新生效）。
    ///
    /// 按钮 / 修饰键释放为 best-effort：单条失败仅记 debug 日志、不中断
    /// 后续释放、不重试（与主路径注入失败语义一致——用户操作不可重放）。
    pub fn release_all(&mut self) {
        let bits = self.last_button_bits;
        let pos = self.last_injected_move.unwrap_or((0, 0));
        self.last_button_bits = 0;
        self.reset_move_guard_state();
        for ev in release_all_up_events(bits, pos) {
            if let Err(e) = self.dispatch(&ev) {
                tracing::debug!("r74b release_all: button up not injected: {e}");
            }
        }
        // ——无论该修饰键是本注入器补按的〔mods_we_pressed〕、桌面端独立
        // 按下，KEYUP 都经正常 Key 分派下发）。
        for ev in release_all_modifier_up_events() {
            if let Err(e) = self.dispatch(&ev) {
                tracing::debug!("r85d release_all: modifier key up not injected: {e}");
            }
        }
        #[cfg(target_os = "windows")]
        {
            if self.mods_we_pressed != 0 {
                crate::windows::send_modifier_keys(self.mods_we_pressed, false);
                self.mods_we_pressed = 0;
            }
        }
    }

    /// 本地优先抑制、去重），保留分辨率校验 + 坐标换算后直接平台注入。
    ///
    /// 真实注入自检 `test_inject_smoke`（Move(0,0)，`--ignored` 手动跑）走
    /// 本方法，不被保护逻辑误杀（自测命令是门禁）；**不更新**守卫状态
    /// （去重基线 / 按键状态机 / 抑制窗口），不影响会话守卫语义。
    pub fn handle_raw(&mut self, ev: &InputEvent) -> Result<(), InjectError> {
        if ev.kind == InputKind::SpecialKey {
            return self.dispatch(ev);
        }
        if self.src_w == 0 || self.src_h == 0 || self.dst_w == 0 || self.dst_h == 0 {
            return Err(InjectError::InvalidEvent(format!(
                "zero resolution: src={}x{} dst={}x{}",
                self.src_w, self.src_h, self.dst_w, self.dst_h
            )));
        }
        let scaled_x = scale_coord(ev.x, self.src_w, self.dst_w)
            .ok_or_else(|| InjectError::InvalidEvent(format!("x scale failed: x={}", ev.x)))?;
        let scaled_y = scale_coord(ev.y, self.src_h, self.dst_h)
            .ok_or_else(|| InjectError::InvalidEvent(format!("y scale failed: y={}", ev.y)))?;
        let mut scaled = ev.clone();
        scaled.x = scaled_x;
        scaled.y = scaled_y;
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

    // ========================================================================
    // ========================================================================

    /// （该键由 `dispatch` scan code 注入）；非键盘事件 / 非修饰键 → 0。
    #[test]
    fn r77c_self_bit_excluded_from_flag_sync() {
        // Ctrl down 事件（flags=CTRL，自位=CTRL）→ 排除后 sync flags=0。
        let ev = InputEvent::key(InputKind::KeyDown, Key::Ctrl, modifier::CTRL);
        assert_eq!(self_modifier_bit(&ev), modifier::CTRL);
        let (press, release) = modifier_sync_plan(0, ev.modifiers & !self_modifier_bit(&ev), 0);
        assert_eq!(press, 0, "自位不得补按（避免 IME 双切换）");
        assert_eq!(release, 0);

        // Space 事件（flags=CTRL，无自位，Ctrl 物理已按）→ 不重复按。
        let ev = InputEvent::key(InputKind::KeyDown, Key::Space, modifier::CTRL);
        assert_eq!(self_modifier_bit(&ev), 0);
        let (press, release) = modifier_sync_plan(0, ev.modifiers, modifier::CTRL);
        assert_eq!(press, 0, "Ctrl 物理已按 → 不补按");
        assert_eq!(release, 0);

        // 非键盘事件 / 非修饰键 → 0。
        assert_eq!(self_modifier_bit(&InputEvent::mouse_move(1, 1)), 0);
        assert_eq!(modifier_bit_for_key(Key::Space as u32), 0);
    }

    /// 事件（scan code 流），flags 路径**零插入**；最终注入序 =
    /// Ctrl↓ → Space↓ → Space↑ → Ctrl↑（事件序 = 注入序）：Ctrl 按在 Space
    /// 前、Ctrl 释在 Space 后——被控端 IME 据此检测到 Ctrl+Space。
    #[test]
    fn r77c_ctrl_space_sequence_no_flag_path_injection() {
        let seq: [(InputKind, Key, u8); 4] = [
            (InputKind::KeyDown, Key::Ctrl, modifier::CTRL),   // Ctrl↓（帧快照含 CTRL）
            (InputKind::KeyDown, Key::Space, modifier::CTRL),  // Space↓（逐事件标志带 CTRL）
            (InputKind::KeyUp, Key::Space, modifier::CTRL),    // Space↑（Ctrl 仍按住）
            (InputKind::KeyUp, Key::Ctrl, 0),                  // Ctrl↑（快照已撤 CTRL）
        ];
        let mut we = 0u8;
        let mut physical = 0u8;
        let mut actions: Vec<String> = Vec::new();
        for (kind, key, _flags) in seq {
            let ev = InputEvent::key(kind, key, _flags);
            let sync_flags = ev.modifiers & !self_modifier_bit(&ev);
            let (press, release) = modifier_sync_plan(we, sync_flags, physical);
            assert_eq!(press, 0, "{kind:?} {key:?}: flags 路径不得补按（修饰键走 scan code 事件）");
            assert_eq!(release, 0, "{kind:?} {key:?}: flags 路径不得释放（修饰键走 scan code 事件）");
            we = (we | press) & !release;
            // 模拟 GetAsyncKeyState 视角：本事件键的注入立即生效。
            let bit = self_modifier_bit(&ev);
            if bit != 0 {
                if kind == InputKind::KeyUp {
                    physical &= !bit;
                } else {
                    physical |= bit;
                }
            }
            actions.push(format!("{kind:?} Key::{key:?}"));
        }
        // 完整注入序（flags 路径零插入 = 事件序即最终序列）。
        assert_eq!(
            actions,
            vec![
                "KeyDown Key::Ctrl",
                "KeyDown Key::Space",
                "KeyUp Key::Space",
                "KeyUp Key::Ctrl",
            ]
        );
        let ctrl_down = actions.iter().position(|a| a == "KeyDown Key::Ctrl").unwrap();
        let space_down = actions.iter().position(|a| a == "KeyDown Key::Space").unwrap();
        let space_up = actions.iter().position(|a| a == "KeyUp Key::Space").unwrap();
        let ctrl_up = actions.iter().position(|a| a == "KeyUp Key::Ctrl").unwrap();
        assert!(ctrl_down < space_down, "Ctrl 按下必须在 Space 前");
        assert!(ctrl_up > space_up, "Ctrl 释放必须在 Space 后");
    }

    /// 独立修饰键事件）、撤销释放；物理已按不重复。
    #[test]
    fn r77c_mobile_flag_only_path_preserved() {
        // 带 CTRL 的 Space（Ctrl 物理未按、未补按过）→ 补按 CTRL。
        let (press, release) = modifier_sync_plan(0, modifier::CTRL, 0);
        assert_eq!(press, modifier::CTRL);
        assert_eq!(release, 0);
        // 下一事件 flags=0 → 释放 CTRL。
        let (press, release) = modifier_sync_plan(press, 0, modifier::CTRL);
        assert_eq!(release, modifier::CTRL);
        assert_eq!(press, 0);
        let (press, release) = modifier_sync_plan(0, modifier::CTRL, modifier::CTRL);
        assert_eq!(press, 0, "物理已按 → 不重复按");
        assert_eq!(release, 0);
    }

    // ========================================================================
    // ========================================================================

    /// SendInput 无单测面——真实键态读取与释放效果以用户复测对账行
    /// `input hygiene:` 覆盖）：全空 → 无需释放（clean）；含 Win → SUPER 位
    /// 必入释放集（本修复核心——残留 Win 使 Ctrl+O = 系统热键 Ctrl+Win+O
    /// 误弹 OSK）；含多键 → 全部释放不遗漏；未知位污染 → 掩掉；幂等（释放
    /// 后二次读 = 空计划）。
    #[test]
    fn r81g_hygiene_release_plan_three_states() {
        // 全空：plan = 0（调用方记 clean 行、不产生事件）。
        assert_eq!(hygiene_release_plan(0), 0, "全空 → 无需释放");
        // 含 Win：SUPER 位必须释放（只放 Ctrl/Shift/Alt 不放 Win = 修复失效）。
        assert_eq!(hygiene_release_plan(modifier::SUPER), modifier::SUPER);
        // 含多键：CTRL+ALT+SUPER 全量释放（与退出侧 release_all 同口径——
        // 整体复位，不做选择性保留）。
        let multi = modifier::CTRL | modifier::ALT | modifier::SUPER;
        assert_eq!(hygiene_release_plan(multi), multi);
        // 未知位污染：掩到四个已定义位（不误释放、不 panic）。
        assert_eq!(
            hygiene_release_plan(0xFF),
            modifier::CTRL | modifier::SHIFT | modifier::ALT | modifier::SUPER
        );
        assert_eq!(hygiene_release_plan(0b1111_0000), 0, "仅未知位 → 无释放");
        // 幂等：释放成功后物理态不再含 plan 位 → 二次读计划 = 0
        // （重复调用只多一行 clean 日志，无事件、无副作用）。
        let physical = multi | 0b1111_0000;
        let plan = hygiene_release_plan(physical);
        assert_eq!(plan, multi);
        assert_eq!(
            hygiene_release_plan(physical & !plan),
            0,
            "释放后二次读 → 空计划（幂等）"
        );
    }

    // ========================================================================
    // ========================================================================

    /// 恰生成 4 条（Ctrl→Shift→Alt→Super canonical 序、`modifiers=0`、
    /// 桌面端独立修饰键 scan code 事件 / 被控端本地物理），会话结束都收到
    /// 一次物理层 KEYUP。纯函数级断言（Win32 `SendInput` 实调用无单测面，
    /// 与 `release_all_up_events` 既有单测口径一致）。
    #[test]
    fn r85d_release_all_modifier_up_events_exact_four_keyups() {
        let evs = release_all_modifier_up_events();
        assert_eq!(evs.len(), 4, "恰 4 条修饰键 KeyUp（无条件全生成）");
        let seq: Vec<(InputKind, u32, u8)> =
            evs.iter().map(|e| (e.kind, e.key, e.modifiers)).collect();
        assert_eq!(
            seq,
            vec![
                (InputKind::KeyUp, Key::Ctrl as u32, 0),
                (InputKind::KeyUp, Key::Shift as u32, 0),
                (InputKind::KeyUp, Key::Alt as u32, 0),
                (InputKind::KeyUp, Key::Super as u32, 0),
            ],
            "canonical 顺序 Ctrl→Shift→Alt→Super，modifiers 全 0"
        );
        // 幂等口径：对未按下键发 up 无害 no-op = 本路径不依赖任何注入器
        // 状态（重复调用 release_all 仍产生同形 4 事件序列，无副作用状态）。
        let evs2 = release_all_modifier_up_events();
        assert_eq!(
            evs2.iter().map(|e| (e.kind, e.key, e.modifiers)).collect::<Vec<_>>(),
            seq,
            "二次生成序列一致（无状态依赖 = 幂等可重复调用）"
        );
    }

    // ========================================================================
    // ========================================================================

    /// 数字/控制/F/导航/修饰/标点各段各抽代表值），且新键事件 bincode
    /// 往返一致（可靠流 wire 格式，同 `test_key_event` 口径）。
    #[test]
    fn r86_key_enum_tail_append_wire_compatible() {
        assert_eq!(Key::A as u32, 0x04, "字母段");
        assert_eq!(Key::Z as u32, 0x1D, "字母段");
        assert_eq!(Key::Num1 as u32, 0x1E, "数字段");
        assert_eq!(Key::Num0 as u32, 0x27, "数字段");
        assert_eq!(Key::Enter as u32, 0x28, "控制段");
        assert_eq!(Key::CapsLock as u32, 0x39, "控制段");
        assert_eq!(Key::F1 as u32, 0x3A, "F 段");
        assert_eq!(Key::F12 as u32, 0x45, "F 段");
        assert_eq!(Key::Insert as u32, 0x49, "导航段");
        assert_eq!(Key::Up as u32, 0x52, "导航段");
        assert_eq!(Key::KpMultiply as u32, 0x66, "尾追加 +1");
        assert_eq!(Key::KpDecimal as u32, 0x67, "尾追加 +2");
        // 新键 wire 事件 bincode 往返（旧端遇到 0x66/0x67 仅该包反序列化
        for key in [Key::KpMultiply, Key::KpDecimal] {
            let ev = InputEvent::key(InputKind::KeyDown, key, 0);
            let data = bincode::serialize(&ev).expect("serialize");
            let back: InputEvent = bincode::deserialize(&data).expect("deserialize");
            assert_eq!(back.kind, InputKind::KeyDown);
            assert_eq!(back.key, key as u32);
            assert_eq!(back.modifiers, 0);
        }
    }

    // ========================================================================
    // ========================================================================

    /// 0x66-0x67 各段锚点逐一钉死——防止未来改动插队改序），且新键
    /// down/up 事件 bincode 往返一致（toggle 语义 = down+up 单对，
    /// 混连口径见 `Key::NumLock` 判别式注释：旧端反序列化恒成功）。
    #[test]
    fn r89_key_enum_tail_append_wire_compatible() {
        assert_eq!(Key::A as u32, 0x04, "字母段");
        assert_eq!(Key::Z as u32, 0x1D, "字母段");
        assert_eq!(Key::Num1 as u32, 0x1E, "数字段");
        assert_eq!(Key::Num0 as u32, 0x27, "数字段");
        assert_eq!(Key::Enter as u32, 0x28, "控制段");
        assert_eq!(Key::CapsLock as u32, 0x39, "控制段");
        assert_eq!(Key::F1 as u32, 0x3A, "F 段");
        assert_eq!(Key::F12 as u32, 0x45, "F 段");
        assert_eq!(Key::Insert as u32, 0x49, "导航段");
        assert_eq!(Key::Up as u32, 0x52, "导航段");
        assert_eq!(Key::NumLock as u32, 0x68, "尾追加 +1");
        // 新键 wire 事件 bincode 往返（toggle = down/up 各一条；
        // `key` 字段为 `u32` 无变体校验 → 旧端反序列化必然成功）。
        for kind in [InputKind::KeyDown, InputKind::KeyUp] {
            let ev = InputEvent::key(kind, Key::NumLock, 0);
            let data = bincode::serialize(&ev).expect("serialize");
            let back: InputEvent = bincode::deserialize(&data).expect("deserialize");
            assert_eq!(back.kind, kind);
            assert_eq!(back.key, Key::NumLock as u32);
            assert_eq!(back.modifiers, 0);
        }
    }

    // ========================================================================
    // ========================================================================

    /// 连续 26 值（补偿判据 `range.contains` 的正确性前提）；区间外相邻
    /// 判别式零误纳（Num1=0x1E / CapsLock=0x39 恰在区间外）。
    #[test]
    fn r132_4_letter_range_contiguous_and_exclusive() {
        assert_eq!(Key::A as u32, 0x04);
        assert_eq!(Key::Z as u32, 0x1D);
        let range = (Key::A as u32)..=(Key::Z as u32);
        let letters: Vec<u32> = (0x04u32..=0x1D).collect();
        assert_eq!(letters.len(), 26, "恰 26 字母");
        // 既有 Key 判别式中落区间内的恰为 A-Z（抽各段代表值反证零误纳）。
        for k in [
            Key::Num1 as u32,   // 0x1E = Z+1（区间外紧邻）
            Key::Num0 as u32,
            Key::Enter as u32,
            Key::CapsLock as u32,
            Key::F1 as u32,
            Key::Up as u32,
            Key::Shift as u32,
            Key::Plus as u32,
            Key::KpMultiply as u32,
        ] {
            assert!(!range.contains(&k), "非字母判别式 {k:#04x} 不得落区间");
        }
        // 区间内每个值都是某字母（无空洞/无他键混入 = A..=Z 枚举值逐位核对）。
        let letter_vals: Vec<u32> = [
            Key::A, Key::B, Key::C, Key::D, Key::E, Key::F, Key::G, Key::H, Key::I, Key::J,
            Key::K, Key::L, Key::M, Key::N, Key::O, Key::P, Key::Q, Key::R, Key::S, Key::T,
            Key::U, Key::V, Key::W, Key::X, Key::Y, Key::Z,
        ]
        .iter()
        .map(|k| *k as u32)
        .collect();
        assert_eq!(letter_vals, letters, "A-Z 判别式恰为 0x04..=0x1D 连续段");
    }

    /// 26 字母注入大小写与本地键位语义一致」的决策层单测面）：
    /// - `local XOR remote = 1` 且 KeyDown/KeyRepeat → 恰叠加 SHIFT 位；
    /// - 异或 = 0（两端同态，含旧端默认 false 场景）→ 事件零改动；
    /// - KeyUp **恒不**叠加（shift 释放时序归 flags 帧差状态机，防粘连）；
    /// - 既有修饰键位保留（CTRL 与补偿 SHIFT 并存）；非字母 / 非键盘事件
    ///   零触碰。
    #[test]
    fn r132_4_caps_compensate_decision_matrix() {
        let letters: Vec<Key> = [
            Key::A, Key::B, Key::C, Key::D, Key::E, Key::F, Key::G, Key::H, Key::I, Key::J,
            Key::K, Key::L, Key::M, Key::N, Key::O, Key::P, Key::Q, Key::R, Key::S, Key::T,
            Key::U, Key::V, Key::W, Key::X, Key::Y, Key::Z,
        ]
        .iter()
        .copied()
        .collect();
        let caps_states = [(false, false), (false, true), (true, false), (true, true)];
        for key in &letters {
            for &(local, remote) in &caps_states {
                let xor = local != remote;
                for kind in [InputKind::KeyDown, InputKind::KeyRepeat, InputKind::KeyUp] {
                    let ev = InputEvent::key(kind, *key, 0);
                    let out = r132_4_caps_compensate(ev.clone(), local, remote);
                    let expect_shift = xor && kind != InputKind::KeyUp;
                    if expect_shift {
                        assert_eq!(
                            out.modifiers,
                            modifier::SHIFT,
                            "{key:?} {kind:?} local={local} remote={remote} 应恰叠加 SHIFT"
                        );
                    } else {
                        assert_eq!(out, ev, "{key:?} {kind:?} local={local} remote={remote} 应零改动");
                    }
                }
            }
        }
        // 既有修饰键保留：CTRL+字母 + 异或 = CTRL|SHIFT（叠加非替换）。
        let ev = InputEvent::key(InputKind::KeyDown, Key::A, modifier::CTRL);
        let out = r132_4_caps_compensate(ev, true, false);
        assert_eq!(out.modifiers, modifier::CTRL | modifier::SHIFT);
        // 非字母键盘事件零触碰（异或 = 1 亦不叠加）。
        for key in [Key::Num8, Key::Space, Key::CapsLock, Key::KpMultiply] {
            let ev = InputEvent::key(InputKind::KeyDown, key, 0);
            assert_eq!(
                r132_4_caps_compensate(ev.clone(), true, false),
                ev,
                "{key:?} 非字母不得叠加"
            );
        }
        // 非键盘事件零触碰。
        let mv = InputEvent::mouse_move(1, 2);
        assert_eq!(r132_4_caps_compensate(mv.clone(), true, false), mv);
        let tx = InputEvent::text("hi");
        assert_eq!(r132_4_caps_compensate(tx.clone(), true, false), tx);
        // 用户已持 shift（flags 已含 SHIFT）+ 异或 = 1 → 位或幂等不双计
        // （modifier_sync 物理态去重后 = 单次 shift，双 shift 相消语义由
        // 「事件 flags 仅一位」结构保证）。
        let ev = InputEvent::key(InputKind::KeyDown, Key::A, modifier::SHIFT);
        let out = r132_4_caps_compensate(ev, true, false);
        assert_eq!(out.modifiers, modifier::SHIFT);
    }

    /// KP* 语义可打出 *」的决策层单测面）：形态 = 修饰键按住→主键按下→
    /// 主键抬起→修饰键抬起（释放步必达不粘连）；展开产物 = **既有判别式**
    /// （Shift=0x53 / Num8=0x25）事件（wire 兼容 = 旧格式可解，单测钉死）；
    /// 非 KP* 事件 `None` 直透（热路径零分配，调用方用原事件）。
    #[test]
    fn r132_4_kp_star_expand_matrix_and_wire_compat() {
        // KeyDown / KeyRepeat（auto-repeat）→ [Shift↓, Num8↓]。
        for kind in [InputKind::KeyDown, InputKind::KeyRepeat] {
            let ev = InputEvent::key(kind, Key::KpMultiply, 0);
            let (a, b) = r132_4_kp_star_expand(&ev).expect("KP* 必展开");
            assert_eq!(
                (a.kind, a.key, a.modifiers),
                (InputKind::KeyDown, Key::Shift as u32, 0),
                "{kind:?} 展开首步 = Shift↓"
            );
            assert_eq!(
                b.as_ref().map(|e| (e.kind, e.key, e.modifiers)),
                Some((InputKind::KeyDown, Key::Num8 as u32, 0)),
                "{kind:?} 展开次步 = Num8↓"
            );
        }
        // KeyUp → [Num8↑, Shift↑]（释放步必达：Shift↑ 恒为末步）。
        let ev = InputEvent::key(InputKind::KeyUp, Key::KpMultiply, 0);
        let (a, b) = r132_4_kp_star_expand(&ev).expect("KP* up 必展开");
        assert_eq!((a.kind, a.key), (InputKind::KeyUp, Key::Num8 as u32));
        assert_eq!(
            b.as_ref().map(|e| (e.kind, e.key)),
            Some((InputKind::KeyUp, Key::Shift as u32)),
            "Shift↑ 必为末步（不粘连）"
        );
        // 非 KP* 键零展开（白名单同族键逐一反证 + 常规键）。
        for key in [
            Key::A,
            Key::Num8,
            Key::Shift,
            Key::CapsLock,
            Key::KpDecimal,
            Key::NumLock,
            Key::Super,
        ] {
            for kind in [InputKind::KeyDown, InputKind::KeyUp] {
                let ev = InputEvent::key(kind, key, 0);
                assert!(r132_4_kp_star_expand(&ev).is_none(), "{key:?} {kind:?} 不得展开");
            }
        }
        let mv = InputEvent::mouse_move(3, 4);
        assert!(r132_4_kp_star_expand(&mv).is_none(), "鼠标事件不得展开");
        // 且 bincode 往返一致（旧格式可解 = 旧端收到即按既有 Shift/8 语义
        // 注入 —— 旧服务端对 KP* 帧行为零变化，映射仅新服务端生效）。
        let ev = InputEvent::key(InputKind::KeyDown, Key::KpMultiply, 0);
        let (a, b) = r132_4_kp_star_expand(&ev).unwrap();
        let b = b.expect("第二步（Num8）必在");
        assert_eq!(b.key, 0x25, "Num8 判别式 = 既有 0x25");
        for e in [a, b] {
            let data = bincode::serialize(&e).expect("serialize");
            let back: InputEvent = bincode::deserialize(&data).expect("deserialize");
            assert_eq!(back, e, "展开产物 wire 往返一致（旧格式兼容）");
        }
    }

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
    /// 不被保护逻辑误杀（自测命令是门禁）。
    /// 默认 skip（会真实移动鼠标），留给本机手动验证。
    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "real HID injection moves the cursor; run manually with --ignored"]
    fn test_inject_smoke() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        let ev = InputEvent::mouse_move(0, 0);
        inj.handle_raw(&ev).expect("smoke inject should succeed");
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

    // ════════════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════════════

    /// release-all 纯序列：仅对按下的位生成 up（canonical 顺序
    /// LEFT→RIGHT→MIDDLE）；未按下不生成（幂等性基础）；未知高位忽略。
    #[test]
    fn r74b_release_all_up_events_only_pressed() {
        // 仅左键按下 → 仅左键 up（释放位置 = 最后注入基线）。
        let evs = release_all_up_events(button::LEFT, (100, 50));
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, InputKind::MouseButton);
        assert_eq!(evs[0].button, button::LEFT | button::RELEASE);
        assert_eq!((evs[0].x, evs[0].y), (100, 50));
        // 左 + 中按下 → 2 条 up，canonical 顺序，无右键。
        let evs = release_all_up_events(button::LEFT | button::MIDDLE, (0, 0));
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].button, button::LEFT | button::RELEASE);
        assert_eq!(evs[1].button, button::MIDDLE | button::RELEASE);
        // 无按下 → 空（第二次 release_all = 零事件，幂等依据）。
        assert!(release_all_up_events(0, (0, 0)).is_empty());
        // 全按下 → 3 条 up，canonical 顺序。
        let evs = release_all_up_events(button::LEFT | button::RIGHT | button::MIDDLE, (7, 8));
        assert_eq!(
            evs.iter().map(|e| e.button).collect::<Vec<_>>(),
            vec![
                button::LEFT | button::RELEASE,
                button::RIGHT | button::RELEASE,
                button::MIDDLE | button::RELEASE,
            ]
        );
        // 未知高位（含 RELEASE 位本身）忽略——wire 协议仅 3 键。
        assert_eq!(release_all_up_events(0xFF, (0, 0)).len(), 3);
    }

    /// release_all：全状态释放 + 幂等（二次调用零事件、无 panic）。
    /// 注：测试机按钮物理未按下，OS 级 LEFTUP/MIDDLEUP 为无害 no-op
    ///（对未按下键发 up 无害）；修饰键位 0，无真实按键事件。
    #[test]
    fn r74b_release_all_resets_state_and_is_idempotent() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        // 模拟：左 / 中键持有 + 注入基线 + 抑制窗口生效中。
        inj.last_button_bits = button::LEFT | button::MIDDLE;
        inj.last_injected_move = Some((1000, 500));
        inj.last_move_button_bits = button::LEFT;
        inj.suppress_until_ms = Some(u64::MAX);
        inj.release_all();
        assert_eq!(inj.last_button_bits, 0);
        assert_eq!(inj.last_move_button_bits, 0);
        assert_eq!(inj.last_injected_move, None);
        assert_eq!(inj.suppress_until_ms, None);
        // 二次调用：幂等 no-op（无按下位 → 无 up；状态保持全零）。
        inj.release_all();
        assert_eq!(inj.last_button_bits, 0);
        assert_eq!(inj.last_injected_move, None);
        assert_eq!(inj.suppress_until_ms, None);
    }

    /// (0,0)/首帧基线保护：dst 分辨率 (0,0) = 首帧未到 → Move 静默丢弃
    ///（Ok 而非 error、不注入、不建基线）；非 Move 事件保留 InvalidEvent。
    #[test]
    fn r74b_first_frame_guard_drops_move_only() {
        let mut inj = InputInjector::new(1920, 1080, 0, 0);
        // Move：丢弃（守卫若回归，光标将被拽到 (0,0) 屏幕角 + 建立基线，
        // 「基线未建立」断言兜住）。
        let r = inj.handle(InputEvent::mouse_move(640, 360));
        assert!(r.is_ok(), "首帧未到 Move 应静默丢弃而非报错: {r:?}");
        assert_eq!(
            inj.last_injected_move, None,
            "被丢弃的 Move 不得建立注入基线"
        );
        // 非 Move：原有协议错误语义（零分辨率 → InvalidEvent）不变。
        let e = inj.handle(InputEvent::mouse_button(button::LEFT, 0, 0));
        assert!(matches!(e, Err(InjectError::InvalidEvent(_))));
    }

    /// 本地活动判定：任一轴偏差 > 阈值 → 开抑制窗口 + 基线重置为实际光标位置。
    #[test]
    fn r74b_local_activity_opens_window_and_resets_baseline() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        inj.last_injected_move = Some((1000, 500));
        let now = 1_000_000u64;
        // x 轴偏差 10px > 8 → 本地物理活动。
        let v = inj.move_guard((1000, 500), now, Some((1010, 500)));
        assert_eq!(v, MoveGuardVerdict::DroppedSuppressed);
        assert_eq!(inj.suppress_until_ms, Some(now + LOCAL_INPUT_SUPPRESS_MS));
        // 注入坐标基线重置为当前实际光标位置（不重复误判）。
        assert_eq!(inj.last_injected_move, Some((1010, 500)));
        // y 轴偏差同样判定（10px 向下）。
        let mut inj2 = InputInjector::new(1920, 1080, 1920, 1080);
        inj2.last_injected_move = Some((1000, 500));
        let v = inj2.move_guard((1000, 500), now, Some((1000, 491)));
        assert_eq!(v, MoveGuardVerdict::DroppedSuppressed);
        assert_eq!(inj2.last_injected_move, Some((1000, 491)));
    }

    /// 阈值边界：偏差恰为 8px → 非本地活动（「超过阈值」为严格 >）。
    #[test]
    fn r74b_local_activity_threshold_boundary() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        inj.last_injected_move = Some((1000, 500));
        // 光标偏 8px（不超）+ 目标与基线不同（不去重）→ 注入。
        let v = inj.move_guard((1001, 500), 0, Some((1008, 500)));
        assert_eq!(v, MoveGuardVerdict::Inject, "恰 8px 偏差不算本地活动（严格 >）");
        assert_eq!(inj.suppress_until_ms, None, "未开抑制窗口");
    }

    /// 抑制窗口开 / 关 + 退化行为：窗口内丢弃；过期恢复正常注入（自然
    /// 重新对齐）；GetCursorPos 失败（None）退化现状不抑制；首帧未到
    /// （基线 None）不误杀首条 Move。
    #[test]
    fn r74b_suppress_window_and_degraded_behavior() {
        let now = 1_000_000u64;
        // 窗口生效中 → 丢弃（即使光标仍在基线处、目标也变化）。
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        inj.last_injected_move = Some((1000, 500));
        inj.suppress_until_ms = Some(now + LOCAL_INPUT_SUPPRESS_MS);
        assert_eq!(
            inj.move_guard((2000, 900), now, Some((1000, 500))),
            MoveGuardVerdict::DroppedSuppressed
        );
        // 窗口过期（now > until）→ 正常决策路径（光标 = 基线 → 无本地活动
        // → 目标不同不去重 → 注入）+ 窗口清零。
        inj.suppress_until_ms = Some(now - 1);
        assert_eq!(
            inj.move_guard((2000, 900), now, Some((1000, 500))),
            MoveGuardVerdict::Inject
        );
        assert_eq!(inj.suppress_until_ms, None, "过期窗口应清零");

        // GetCursorPos 失败（None，含非 Windows / 查询异常）→ 退化现状行为：
        // 不做本地活动判定、不误抑制（体验机制不做 fail-closed）。
        let mut inj2 = InputInjector::new(1920, 1080, 1920, 1080);
        inj2.last_injected_move = Some((1000, 500));
        assert_eq!(inj2.move_guard((1500, 700), now, None), MoveGuardVerdict::Inject);
        assert_eq!(inj2.suppress_until_ms, None);

        // 首帧未到（基线 None）+ 光标远离原点 → 无比对基准，首条 Move 照常
        // 注入（由 handle 在成功后建立基线）——首帧保护只挡「基准无效」，
        // 不误杀会话首条 Move。
        let mut inj3 = InputInjector::new(1920, 1080, 1920, 1080);
        assert_eq!(
            inj3.move_guard((50, 60), now, Some((9999, 9999))),
            MoveGuardVerdict::Inject
        );
    }

    /// Move 去重：同坐标 + 按键状态无变化 → 跳过；按键状态变化或坐标变化
    /// → 注入。
    #[test]
    fn r74b_move_dedup() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        inj.last_injected_move = Some((1000, 500));
        inj.last_move_button_bits = 0;
        inj.last_button_bits = 0;
        assert_eq!(
            inj.move_guard((1000, 500), 0, None),
            MoveGuardVerdict::DroppedDedup
        );
        // 同坐标 + 按钮按下（按键状态变化）→ 不去重（拖拽中持续对齐）。
        inj.last_button_bits = button::LEFT;
        assert_eq!(inj.move_guard((1000, 500), 0, None), MoveGuardVerdict::Inject);
        // 坐标变化 → 不去重。
        inj.last_button_bits = 0;
        assert_eq!(inj.move_guard((1001, 500), 0, None), MoveGuardVerdict::Inject);
    }

    /// 分辨率变更（显示器切换）→ Move 守卫状态重置（旧基线失效）；按键 /
    /// 修饰键物理状态保留（分辨率无关）。
    #[test]
    fn r74b_set_resolution_resets_guard_state() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        inj.last_injected_move = Some((1000, 500));
        inj.last_move_button_bits = button::LEFT;
        inj.last_button_bits = button::LEFT;
        inj.suppress_until_ms = Some(42);
        inj.set_resolution(2560, 1440);
        assert_eq!(inj.last_injected_move, None);
        assert_eq!(inj.last_move_button_bits, 0);
        assert_eq!(inj.suppress_until_ms, None);
        assert_eq!(inj.last_button_bits, button::LEFT, "按键物理状态分辨率无关，保留");
        // set_dst_resolution 同款重置语义。
        let mut inj2 = InputInjector::new(1920, 1080, 1920, 1080);
        inj2.last_injected_move = Some((1000, 500));
        inj2.set_dst_resolution(3840, 2160);
        assert_eq!(inj2.last_injected_move, None);
    }

    /// 自检豁免路径 handle_raw：分辨率校验不绕过（零分辨率仍 InvalidEvent）；
    /// 有效分辨率下直达平台分派（不被守卫误杀为 Ok）——用未知键触发
    /// 分派侧 InvalidEvent 反证（避免门禁期间真实注入）。真实 Move(0,0)
    /// 注入由 `--ignored` 的 `test_inject_smoke` 覆盖（走 handle_raw）。
    #[test]
    fn r74b_handle_raw_validates_and_reaches_dispatch() {
        let mut inj = InputInjector::new(0, 0, 0, 0);
        let e = inj.handle_raw(&InputEvent::mouse_move(0, 0));
        assert!(matches!(e, Err(InjectError::InvalidEvent(_))));
        // 守卫若误拦截会返回 Ok（丢弃）；平台分派的 InvalidEvent 证明直达
        // 注入路径。
        let mut inj2 = InputInjector::new(1920, 1080, 1920, 1080);
        let e2 = inj2.handle_raw(&InputEvent {
            kind: InputKind::KeyDown,
            key: 0xFFFF_FFFF,
            ..InputEvent::key(InputKind::KeyDown, Key::A, 0)
        });
        assert!(matches!(e2, Err(InjectError::InvalidEvent(_))));
        // handle_raw 不更新守卫状态（自检不污染会话语义）。
        assert_eq!(inj2.last_injected_move, None);
        assert_eq!(inj2.last_button_bits, 0);
    }

    // ========================================================================
    // ========================================================================

    /// （分辨率变更同源入口 `reset_move_guard_state`）→ 观测槽一并清（srv-in
    /// 行不得带出旧坐标系的陈旧观测）。**不调 `handle`**——本单测面在 Windows
    /// 测试机上走 `handle` 即真实 SendInput，观测槽的状态转移经字段直写 +
    /// 只读 getter 钉死（生产写入点 = `handle_one` Move 臂，行为不变式由
    #[test]
    fn r137_7_move_observation_reset_and_initial() {
        let mut inj = InputInjector::new(100, 100, 1920, 1080);
        assert_eq!(inj.last_move_observation(), None, "初态 = 无观测");
        // 模拟一次守卫判定后的观测写入（handle_one Move 臂同形态）。
        inj.last_move_observation = Some((10, 20, MoveGuardVerdict::Inject));
        assert_eq!(
            inj.last_move_observation(),
            Some((10, 20, MoveGuardVerdict::Inject))
        );
        // 分辨率变更 → 守卫状态重置 → 观测槽同点同清。
        inj.set_resolution(2560, 1440);
        assert_eq!(
            inj.last_move_observation(),
            None,
            "reset_move_guard_state → 观测槽一并清"
        );
    }

    // ════════════════════════════════════════════════════════════
    // （任何路径不得产生「向客户端锚点」的校正注入：注入坐标恒 =
    // 客户端 Move 事件自身换算后绝对坐标）
    // ════════════════════════════════════════════════════════════

    /// v2-① 本地活动 → 注入挂起且零拉回注入：本地物理活动（任一轴偏差 >
    /// 阈值）→ 开抑制窗（2000ms 现值保留）+ 基线重置为实际光标位置 +
    /// Suspended 转换观测（带检测时刻实际坐标）；窗内**任何**客户端 Move
    /// （含本地活动前的旧锚点坐标）= 挂起丢弃——零注入、无任何向锚点的
    /// 校正注入（拉回方向不存在）。
    #[test]
    fn r141_3_v2_local_activity_suspends_and_zero_yankback() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        inj.last_injected_move = Some((1000, 500)); // 客户端上次注入（旧锚点）
        let now = 1_000_000u64;
        // 本地物理活动（x 偏差 500px > 8）→ 开窗 + 基线重置 + 挂起。
        let v = inj.move_guard((200, 100), now, Some((1500, 800)));
        assert_eq!(v, MoveGuardVerdict::DroppedSuppressed);
        assert_eq!(
            inj.suppress_until_ms,
            Some(now + LOCAL_INPUT_SUPPRESS_MS),
            "抑制窗 2000ms 现值保留"
        );
        assert_eq!(inj.last_injected_move, Some((1500, 800)));
        // 挂起转换观测 = 检测时刻实际光标位置（与基线重置值同源）。
        assert_eq!(
            inj.last_local_priority(),
            Some((LocalPriorityTransition::Suspended, (1500, 800)))
        );
        // 窗内：任何客户端 Move（含旧锚点 (1000,500)）全部挂起——
        // 零注入、零拉回（向任何锚点的校正注入不存在）。
        for tgt in [(200, 100), (1000, 500), (50, 60)] {
            assert_eq!(
                inj.move_guard(tgt, now + 100, Some((1500, 800))),
                MoveGuardVerdict::DroppedSuppressed,
                "抑制窗内客户端 Move {tgt:?} 必须挂起（零拉回注入）"
            );
        }
        // 窗内挂起不产生新的转换观测（Suspended 仅开窗沿记一次）。
        assert_eq!(
            inj.last_local_priority(),
            Some((LocalPriorityTransition::Suspended, (1500, 800)))
        );
    }

    /// v2-② 本地静止超时 → 注入恢复：窗口过期 → Resumed 转换观测（坐标 =
    /// 触发判定的客户端 Move 绝对坐标）+ 窗口清零；客户端移动按绝对坐标
    /// 自然就位（换算后坐标直通注入，无校正、无拉回）。退化臂：过期时
    /// 目标恰 = 重置后基线（光标已就位）→ 去重丢弃，窗口仍清零 + Resumed
    /// 观测（恢复语义 = 窗口不再生效，与是否实际注入解耦）。
    #[test]
    fn r141_3_v2_idle_timeout_resumes_injection() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        inj.last_injected_move = Some((1500, 800)); // 基线 = 本地活动重置位
        let now = 1_000_000u64;
        inj.suppress_until_ms = Some(now + LOCAL_INPUT_SUPPRESS_MS);
        // 窗口生效中 → 挂起。
        assert_eq!(
            inj.move_guard((320, 200), now, Some((1500, 800))),
            MoveGuardVerdict::DroppedSuppressed
        );
        // 静止超时（now ≥ until，恰 2000ms 边界）→ 注入恢复 + Resumed 观测。
        let v = inj.move_guard(
            (320, 200),
            now + LOCAL_INPUT_SUPPRESS_MS,
            Some((1500, 800)),
        );
        assert_eq!(
            v,
            MoveGuardVerdict::Inject,
            "窗口过期 = 注入恢复（客户端移动按绝对坐标自然就位）"
        );
        assert_eq!(inj.suppress_until_ms, None, "过期窗口应清零");
        assert_eq!(
            inj.last_local_priority(),
            Some((LocalPriorityTransition::Resumed, (320, 200))),
            "Resumed 坐标 = 客户端 Move 绝对坐标（无拉回）"
        );

        // 退化臂：过期时目标 = 基线（光标已就位）→ 去重丢弃 + 窗口仍清零
        // + Resumed 观测（恢复语义 = 窗口不再生效）。
        let mut inj2 = InputInjector::new(1920, 1080, 1920, 1080);
        inj2.last_injected_move = Some((1500, 800));
        let now2 = 2_000_000u64;
        inj2.suppress_until_ms = Some(now2 + LOCAL_INPUT_SUPPRESS_MS);
        assert_eq!(
            inj2.move_guard((1500, 800), now2, Some((1500, 800))),
            MoveGuardVerdict::DroppedSuppressed
        );
        assert_eq!(
            inj2.move_guard((1500, 800), now2 + LOCAL_INPUT_SUPPRESS_MS, Some((1500, 800))),
            MoveGuardVerdict::DroppedDedup
        );
        assert_eq!(inj2.suppress_until_ms, None);
        assert_eq!(inj2.last_local_priority(), Some((LocalPriorityTransition::Resumed, (1500, 800))));
    }

    /// v2-③ 客户端移动 → 绝对坐标正常注入（无本地活动）+ 去重零回归：
    /// 守卫零坐标改写——注入坐标恒 = 客户端 Move 事件自身换算后坐标
    /// 既有 r74b 矩阵在位）。
    #[test]
    fn r141_3_v2_client_move_absolute_injection() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        inj.last_injected_move = Some((1000, 500));
        let now = 1_000_000u64;
        // 无本地活动（光标 = 基线）+ 坐标变化 → 注入（绝对坐标直通）。
        assert_eq!(
            inj.move_guard((320, 200), now, Some((1000, 500))),
            MoveGuardVerdict::Inject
        );
        assert!(
            inj.last_local_priority().is_none(),
            "无本地活动 = 无转换观测（零事件不刷行）"
        );
        // wire）；坐标变化 → 注入。
        inj.last_injected_move = Some((320, 200));
        assert_eq!(
            inj.move_guard((320, 200), now + 1, None),
            MoveGuardVerdict::DroppedDedup
        );
        assert_eq!(inj.move_guard((321, 200), now + 2, None), MoveGuardVerdict::Inject);
    }

    /// v2-④ 转换观测槽生命周期（与 `last_move_observation` 同点同清 +
    /// take 消费不双发）：初态 None / Suspended 写入 / take 取走 / 分辨率
    /// 变更重置清 / 非 Move 事件清（防跨事件带出陈旧转换——单测面经字段
    /// 直写 + 只读 getter / dst(0,0) 零注入臂钉死，同 r137_7 观测槽先例）。
    #[test]
    fn r141_3_v2_transition_slot_lifecycle() {
        let mut inj = InputInjector::new(1920, 1080, 1920, 1080);
        assert_eq!(inj.last_local_priority(), None, "初态 = 无转换");
        inj.last_injected_move = Some((1000, 500));
        // 挂起（开窗沿）→ 槽写入。
        let v = inj.move_guard((10, 10), 5_000, Some((1200, 700)));
        assert_eq!(v, MoveGuardVerdict::DroppedSuppressed);
        assert_eq!(
            inj.last_local_priority(),
            Some((LocalPriorityTransition::Suspended, (1200, 700)))
        );
        // take 消费 → 槽空（调用点输出一行后不双发）。
        assert_eq!(
            inj.take_local_priority_event(),
            Some((LocalPriorityTransition::Suspended, (1200, 700)))
        );
        assert_eq!(inj.last_local_priority(), None, "take 后槽空（不双发）");
        // 分辨率变更 → 守卫状态重置 → 转换槽同点同清。
        inj.last_local_priority = Some((LocalPriorityTransition::Resumed, (1, 2)));
        inj.set_resolution(2560, 1440);
        assert_eq!(inj.last_local_priority(), None, "reset_move_guard_state → 转换槽同点同清");
        // 非 Move 事件 → 转换槽同清（dst (0,0) 臂无真实注入面，走
        // InvalidEvent 语义——同 r74b 首帧守卫单测口径）。
        let mut inj2 = InputInjector::new(1920, 1080, 0, 0);
        inj2.last_local_priority = Some((LocalPriorityTransition::Suspended, (3, 4)));
        let e = inj2.handle(InputEvent::mouse_button(button::LEFT, 0, 0));
        assert!(matches!(e, Err(InjectError::InvalidEvent(_))));
        assert_eq!(inj2.last_local_priority(), None, "非 Move 事件清转换槽");
    }
}
