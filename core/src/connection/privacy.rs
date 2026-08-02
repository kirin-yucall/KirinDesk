//! M8-T019: 隐私模式（被控端黑屏 / 锁屏）状态机与服务端执行器。
//!
//! 设计红线（见 `task_docs/共享层/M8-T019_隐私模式_黑屏与锁屏.md` §1）：
//! - **黑屏 ≠ 发送黑帧**：被控端本地屏幕隐藏，但捕获/编码/传输不受影响——
//!   本模块完全不触碰捕获链路，黑屏覆盖由 UI 层绘制（`ui/src/privacy.rs`）；
//! - **黑屏期间输入注入持续有效**（Level 1）；锁屏期间注入暂停、解锁后自动恢复
//!   （Level 2，[`PrivacyController::poll_unlock`]）；
//! - **断连自动恢复（安全红线 SRV-PRIV-014）**：连接断开/心跳超时/进程退出 →
//!   纯本地状态复位，**不依赖任何网络消息**（[`PrivacyController::on_connection_lost`]）；
//! - 纯系统级"不锁屏黑屏"（黑掉显示器输出）需要驱动/服务，**不做**（红线：不自造系统级注入）。
//!
//! 平台能力（SRV-PRIV-012）：
//! - Windows：`LockWorkStation()`（user32，普通用户权限可调）；
//! - macOS：优先 `CGSession -suspend`，回退 `osascript`（Ctrl+Cmd+Q 锁屏）；
//! - Linux：`loginctl lock-session`（systemd）。
//!
//! 平台分派函数（锁屏/锁屏检测）为可注入钩子（[`PrivacyController::with_hooks`]），
//! 便于测试与嵌入式场景替换，不锁真实机器。

use serde::{Deserialize, Serialize};

/// 隐私模式等级（SRV-PRIV-001/002 wire 类型，bincode 序列化）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyLevel {
    /// Level 1 黑屏：被控端屏幕被全屏纯黑覆盖窗口遮挡，
    /// 远程操作继续可见可感 → 输入注入照常（SRV-PRIV-015）。
    Black,
    /// Level 2 锁屏：系统锁屏 → 锁屏后普通进程无法注入输入；
    /// 注入自动暂停并在解锁后恢复（SRV-PRIV-015）。
    Lock,
}

impl PrivacyLevel {
    /// 审计/日志用的短名。
    pub fn as_str(self) -> &'static str {
        match self {
            PrivacyLevel::Black => "black",
            PrivacyLevel::Lock => "lock",
        }
    }

    /// 客户端 toast / 提示条展示名。
    pub fn display(self) -> &'static str {
        match self {
            PrivacyLevel::Black => "黑屏",
            PrivacyLevel::Lock => "锁屏",
        }
    }
}

/// 隐私模式请求处理结果（SRV-PRIV-002 Ack 内容来源）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyOutcome {
    /// 已激活。`active` 为**真实生效**等级——Black 请求在无 GUI 环境
    /// 自动降级为 Lock（SRV-PRIV-013），由调用方通过 Ack 告知客户端。
    Activated(PrivacyLevel),
    /// 已关闭（恢复屏幕）。
    Off,
    /// 被拒绝（平台锁屏调用失败等，SRV-PRIV-012）。携带原因供审计/日志。
    Rejected(String),
}

/// 平台锁屏调用钩子（默认 [`platform_lock_screen`]）。
pub type LockScreenFn = Box<dyn FnMut() -> Result<(), String> + Send>;
/// 平台锁屏状态检测钩子（默认 [`platform_is_locked`]）。
pub type IsLockedFn = Box<dyn Fn() -> Result<bool, String> + Send>;

/// 隐私模式控制器：状态机 + 降级 + 断连恢复（SRV-PRIV-010/013/014/015）。
///
/// 线程安全由调用方保证（服务端每会话一个，UI 线程与接收任务经 `Mutex` 共享，
/// 见 `ui/src/lib.rs::server_privacy_controller`）。关键路径（request/on_connection_lost）
/// 无 I/O——平台锁屏只在 `Lock` 请求时同步调用一次。
pub struct PrivacyController {
    /// 当前生效等级（None = 无隐私模式）。
    active: Option<PrivacyLevel>,
    /// 无 GUI（headless Server 模式）：Black 请求自动降级 Lock（SRV-PRIV-013）。
    headless: bool,
    /// 锁屏生效中（注入暂停，SRV-PRIV-015）。
    lock_requested: bool,
    /// 平台锁屏调用。
    lock: LockScreenFn,
    /// 平台锁屏状态检测（解锁自动恢复）。
    is_locked: IsLockedFn,
}

impl PrivacyController {
    /// 新建控制器。`headless = true`（无 GUI，如 CLI Server 模式）时
    /// Black 请求自动降级为 Lock（SRV-PRIV-013）；GUI 模式传 `false`。
    pub fn new(headless: bool) -> Self {
        Self::with_hooks(
            headless,
            Box::new(platform_lock_screen),
            Box::new(platform_is_locked),
        )
    }

    /// 注入平台钩子的构造器（测试与嵌入式场景用；默认路径走 [`Self::new`]）。
    pub fn with_hooks(headless: bool, lock: LockScreenFn, is_locked: IsLockedFn) -> Self {
        Self {
            active: None,
            headless,
            lock_requested: false,
            lock,
            is_locked,
        }
    }

    /// 当前生效等级（UI 黑屏覆盖轮询用；`Some(Black)` → 显示覆盖窗口）。
    pub fn active_level(&self) -> Option<PrivacyLevel> {
        self.active
    }

    /// 锁屏生效期间输入注入必须暂停（SRV-PRIV-015：SendInput 对安全桌面无效）。
    /// 黑屏期间返回 `false`（注入照常）。
    pub fn injection_paused(&self) -> bool {
        self.lock_requested
    }

    /// 处理一条隐私模式请求（SRV-PRIV-001/010）。
    ///
    /// - `on = true, Black`：无 GUI → 自动降级 Lock；GUI → 激活黑屏。
    /// - `on = true, Lock`：调用平台锁屏；失败 → [`PrivacyOutcome::Rejected`]。
    /// - `on = false`：关闭（恢复屏幕），状态复位。
    pub fn request(&mut self, level: PrivacyLevel, on: bool) -> PrivacyOutcome {
        if !on {
            self.active = None;
            self.lock_requested = false;
            return PrivacyOutcome::Off;
        }
        // 降级：Black 请求但无 GUI 可绘制覆盖窗口 → Lock（SRV-PRIV-013）。
        let effective = if level == PrivacyLevel::Black && self.headless {
            PrivacyLevel::Lock
        } else {
            level
        };
        match effective {
            PrivacyLevel::Black => {
                self.active = Some(PrivacyLevel::Black);
                self.lock_requested = false;
                PrivacyOutcome::Activated(PrivacyLevel::Black)
            }
            PrivacyLevel::Lock => match (self.lock)() {
                Ok(()) => {
                    self.active = Some(PrivacyLevel::Lock);
                    self.lock_requested = true;
                    PrivacyOutcome::Activated(PrivacyLevel::Lock)
                }
                Err(e) => PrivacyOutcome::Rejected(format!("lock screen failed: {e}")),
            },
        }
    }

    /// 断连自动恢复（SRV-PRIV-014 安全红线）：连接断开/心跳超时/进程退出时
    /// 立即复位本地状态（黑屏覆盖随之关闭），**不依赖任何网络消息**。
    ///
    /// 返回恢复前的活跃等级（`None` = 本来就不活跃）。幂等：重复调用返回 `None`。
    pub fn on_connection_lost(&mut self) -> Option<PrivacyLevel> {
        let was = self.active.take();
        self.lock_requested = false;
        was
    }

    /// 锁屏后被控端本地用户解锁 → 自动恢复注入（SRV-PRIV-015，无需重连）。
    ///
    /// 返回 `true` 表示状态从"锁屏中"恢复为"无隐私"（调用方应审计 +
    /// 通知客户端恢复输入）。平台无法检测锁屏状态（Err）→ 视为仍锁定，
    /// 保持暂停，直到显式关闭或断连。
    pub fn poll_unlock(&mut self) -> bool {
        if !self.lock_requested {
            return false;
        }
        match (self.is_locked)() {
            Ok(false) => {
                self.lock_requested = false;
                self.active = None;
                true
            }
            // Ok(true) = 仍锁定；Err = 平台不支持检测 → 保持暂停。
            _ => false,
        }
    }

    /// 本地逃生舱（SRV-PRIV-016，P1）：被控端本地人按住 Esc 3 秒或
    /// Ctrl+Alt+F9 → 本地退出黑屏。只清除本地状态、**不通知远端**
    /// （这是紧急操作，远端仍认为黑屏生效）。
    ///
    /// 返回是否曾处于黑屏（供审计）。
    pub fn local_escape(&mut self) -> bool {
        let was_black = self.active == Some(PrivacyLevel::Black);
        self.active = None;
        self.lock_requested = false;
        was_black
    }
}

/// 平台锁屏（SRV-PRIV-012）：
/// - Windows：`LockWorkStation()`（user32，普通用户权限可调）；
/// - macOS：优先 `CGSession -suspend`（无需辅助功能权限），
///   回退 `osascript`（System Events → Ctrl+Cmd+Q 锁屏）；
/// - Linux：`loginctl lock-session`（systemd）。
pub fn platform_lock_screen() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        lock_screen_windows()
    }
    #[cfg(target_os = "linux")]
    {
        run_loginctl(&["lock-session"])
    }
    #[cfg(target_os = "macos")]
    {
        lock_screen_macos()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err("no screen-lock backend for this target".to_string())
    }
}

/// 平台锁屏状态检测（SRV-PRIV-015 解锁自动恢复）。
///
/// - Windows：`OpenInputDesktop` 在安全桌面（锁屏）上返回 NULL；
/// - Linux：`loginctl show-session <id> -p LockedHint`（systemd）；
/// - macOS：无公开 API → `Err`（调用方视为仍锁定，保持注入暂停）。
pub fn platform_is_locked() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        is_locked_windows()
    }
    #[cfg(target_os = "linux")]
    {
        is_locked_linux()
    }
    #[cfg(target_os = "macos")]
    {
        Err("macOS lock-state detection unavailable (no public API)".to_string())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err("no lock-state backend for this target".to_string())
    }
}

// ════════════════════════════════════════════════════════════════
// 平台实现
// ════════════════════════════════════════════════════════════════

// Windows: LockWorkStation（user32，普通用户权限可调）。
// OpenInputDesktop/CloseDesktop 用于锁屏状态检测（安全桌面 → NULL）。
#[cfg(target_os = "windows")]
#[link(name = "user32")]
extern "system" {
    fn LockWorkStation() -> i32;
    fn OpenInputDesktop(
        dw_flags: u32,
        f_inherit: i32,
        dw_desired_access: u32,
    ) -> *mut std::ffi::c_void;
    fn CloseDesktop(h_desktop: *mut std::ffi::c_void) -> i32;
}

#[cfg(target_os = "windows")]
fn lock_screen_windows() -> Result<(), String> {
    // SAFETY: 无参数系统调用；失败返回 0（不可用/无交互桌面）。
    let ok = unsafe { LockWorkStation() } != 0;
    if ok {
        Ok(())
    } else {
        Err(format!(
            "LockWorkStation returned 0 (last error {})",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "windows")]
fn is_locked_windows() -> Result<bool, String> {
    // 安全桌面（锁屏/登录界面）上 OpenInputDesktop 返回 NULL。
    // DESKTOP_READOBJECTS = 0x0001；DESKTOP_SWITCHDESKTOP 需要权限，此处取最低请求位。
    const DESKTOP_READOBJECTS: u32 = 0x0001;
    // SAFETY: 标准系统调用；返回值句柄用 CloseDesktop 释放（非 NULL 时）。
    let handle = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
    if handle.is_null() {
        Ok(true)
    } else {
        unsafe { CloseDesktop(handle) };
        Ok(false)
    }
}

/// Linux: systemd-logind 命令执行（`lock-session` / `show-session`）。
#[cfg(target_os = "linux")]
fn run_loginctl(args: &[&str]) -> Result<(), String> {
    use std::process::Command;
    let out = Command::new("loginctl")
        .args(args)
        .output()
        .map_err(|e| format!("loginctl spawn failed: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(target_os = "linux")]
fn is_locked_linux() -> Result<bool, String> {
    use std::process::Command;
    // 取首个会话 id（无 root 权限时也能读自己的会话）。
    let list = Command::new("loginctl")
        .args(["list-sessions", "--no-legend", "--no-ask-password"])
        .output()
        .map_err(|e| format!("loginctl list-sessions failed: {e}"))?;
    if !list.status.success() {
        return Err(String::from_utf8_lossy(&list.stderr).trim().to_string());
    }
    let text = String::from_utf8_lossy(&list.stdout);
    let session = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| l.split_whitespace().next())
        .ok_or_else(|| "no active session found".to_string())?;
    let show = Command::new("loginctl")
        .args(["show-session", session, "-p", "LockedHint", "--value"])
        .output()
        .map_err(|e| format!("loginctl show-session failed: {e}"))?;
    Ok(String::from_utf8_lossy(&show.stdout).trim() == "yes")
}

/// macOS: 优先 CGSession -suspend（无辅助功能权限要求），回退 osascript。
#[cfg(target_os = "macos")]
fn lock_screen_macos() -> Result<(), String> {
    use std::process::Command;
    // 1) CGSession（系统自带的锁屏工具）。
    let cg = Command::new(
        "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession",
    )
    .arg("-suspend")
    .output();
    if let Ok(out) = cg {
        if out.status.success() {
            return Ok(());
        }
    }
    // 2) osascript 回退：Ctrl+Cmd+Q（需辅助功能权限，仍失败 → Err）。
    let osa = Command::new("osascript")
        .arg("-e")
        .arg(r#"tell application "System Events" to keystroke "q" using {control down, command down}"#)
        .output()
        .map_err(|e| format!("osascript spawn failed: {e}"))?;
    if osa.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&osa.stderr).trim().to_string())
    }
}

// ════════════════════════════════════════════════════════════════
// Tests（M8-T019-T004：状态机 / 降级 / 断连恢复 / 解锁恢复——全部用注入钩子，
// 不锁真实机器）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;

    /// 构造带钩子的控制器：`lock_ok` 控制锁屏调用成败，`locked` 控制检测结果。
    fn controller(headless: bool, lock_ok: bool, locked: Arc<AtomicBool>) -> PrivacyController {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_cb = calls.clone();
        let lock = Box::new(move || {
            calls_cb.fetch_add(1, Ordering::SeqCst);
            if lock_ok {
                Ok(())
            } else {
                Err("mock lock failure".to_string())
            }
        });
        let is_locked = Box::new(move || Ok(locked.load(Ordering::SeqCst)));
        PrivacyController::with_hooks(headless, lock, is_locked)
    }

    #[test]
    fn test_black_activate_and_off() {
        let locked = Arc::new(AtomicBool::new(false));
        let mut c = controller(false, true, locked);
        assert_eq!(c.active_level(), None);
        // 开启黑屏 → 激活；注入不暂停（黑屏期间注入照常，SRV-PRIV-015）。
        assert_eq!(
            c.request(PrivacyLevel::Black, true),
            PrivacyOutcome::Activated(PrivacyLevel::Black)
        );
        assert_eq!(c.active_level(), Some(PrivacyLevel::Black));
        assert!(!c.injection_paused());
        // 关闭 → Off，状态复位。
        assert_eq!(c.request(PrivacyLevel::Black, false), PrivacyOutcome::Off);
        assert_eq!(c.active_level(), None);
        assert!(!c.injection_paused());
    }

    #[test]
    fn test_headless_black_degrades_to_lock() {
        // SRV-PRIV-013：无 GUI（headless）→ Black 自动降级 Lock。
        let locked = Arc::new(AtomicBool::new(false));
        let mut c = controller(true, true, locked);
        assert_eq!(
            c.request(PrivacyLevel::Black, true),
            PrivacyOutcome::Activated(PrivacyLevel::Lock)
        );
        assert_eq!(c.active_level(), Some(PrivacyLevel::Lock));
        // 降级为锁屏 → 注入暂停。
        assert!(c.injection_paused());
    }

    #[test]
    fn test_lock_failure_rejected_keeps_state() {
        // SRV-PRIV-012：平台锁屏调用失败 → Rejected，状态不变。
        let locked = Arc::new(AtomicBool::new(false));
        let mut c = controller(false, false, locked);
        assert!(matches!(
            c.request(PrivacyLevel::Lock, true),
            PrivacyOutcome::Rejected(_)
        ));
        assert_eq!(c.active_level(), None);
        assert!(!c.injection_paused());
        // 失败后仍可正常开启黑屏。
        assert_eq!(
            c.request(PrivacyLevel::Black, true),
            PrivacyOutcome::Activated(PrivacyLevel::Black)
        );
    }

    #[test]
    fn test_injection_paused_only_during_lock() {
        let locked = Arc::new(AtomicBool::new(false));
        let mut c = controller(false, true, locked);
        // Lock 激活 → 暂停。
        assert_eq!(
            c.request(PrivacyLevel::Lock, true),
            PrivacyOutcome::Activated(PrivacyLevel::Lock)
        );
        assert!(c.injection_paused());
        // 关闭 → 恢复。
        assert_eq!(c.request(PrivacyLevel::Lock, false), PrivacyOutcome::Off);
        assert!(!c.injection_paused());
        // 锁屏中再请求黑屏 → 覆盖为黑屏，注入恢复（黑屏期间注入照常）。
        assert_eq!(
            c.request(PrivacyLevel::Lock, true),
            PrivacyOutcome::Activated(PrivacyLevel::Lock)
        );
        assert!(c.injection_paused());
        assert_eq!(
            c.request(PrivacyLevel::Black, true),
            PrivacyOutcome::Activated(PrivacyLevel::Black)
        );
        assert!(!c.injection_paused());
    }

    #[test]
    fn test_connection_lost_restores_state_idempotent() {
        // SRV-PRIV-014 安全红线：断连复位无网络依赖；幂等。
        let locked = Arc::new(AtomicBool::new(false));
        let mut c = controller(false, true, locked);
        c.request(PrivacyLevel::Lock, true);
        assert!(c.injection_paused());
        assert_eq!(c.on_connection_lost(), Some(PrivacyLevel::Lock));
        assert_eq!(c.active_level(), None);
        assert!(!c.injection_paused());
        // 重复调用幂等。
        assert_eq!(c.on_connection_lost(), None);
        assert_eq!(c.on_connection_lost(), None);
    }

    #[test]
    fn test_poll_unlock_resumes_injection() {
        // SRV-PRIV-015：解锁 → 自动恢复注入（无需重连）。
        let locked = Arc::new(AtomicBool::new(true));
        let mut c = controller(false, true, locked.clone());
        c.request(PrivacyLevel::Lock, true);
        assert!(c.injection_paused());
        // 仍锁定 → 保持暂停。
        assert!(!c.poll_unlock());
        assert!(c.injection_paused());
        // 本地用户解锁 → 恢复。
        locked.store(false, Ordering::SeqCst);
        assert!(c.poll_unlock());
        assert!(!c.injection_paused());
        assert_eq!(c.active_level(), None);
        // 恢复后不再变化。
        assert!(!c.poll_unlock());
    }

    #[test]
    fn test_poll_unlock_ignored_when_not_locked() {
        let locked = Arc::new(AtomicBool::new(true));
        let mut c = controller(false, true, locked);
        // 黑屏状态下 poll_unlock 无效（黑屏不是锁屏）。
        c.request(PrivacyLevel::Black, true);
        assert!(!c.poll_unlock());
        assert_eq!(c.active_level(), Some(PrivacyLevel::Black));
    }

    #[test]
    fn test_local_escape_clears_black() {
        // SRV-PRIV-016：本地逃生舱只清状态、不通知远端。
        let locked = Arc::new(AtomicBool::new(false));
        let mut c = controller(false, true, locked);
        c.request(PrivacyLevel::Black, true);
        assert!(c.local_escape());
        assert_eq!(c.active_level(), None);
        // 非黑屏时逃生返回 false（无变化）。
        assert!(!c.local_escape());
    }

    #[test]
    fn test_privacy_level_serde_roundtrip() {
        // wire 类型（SRV-PRIV-001/002）bincode 往返一致。
        for level in [PrivacyLevel::Black, PrivacyLevel::Lock] {
            let data = bincode::serialize(&level).unwrap();
            let back: PrivacyLevel = bincode::deserialize(&data).unwrap();
            assert_eq!(level, back);
        }
        assert_eq!(PrivacyLevel::Black.as_str(), "black");
        assert_eq!(PrivacyLevel::Lock.as_str(), "lock");
        assert_eq!(PrivacyLevel::Black.display(), "黑屏");
        assert_eq!(PrivacyLevel::Lock.display(), "锁屏");
    }
}
