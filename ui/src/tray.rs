//!
//! guard / 隐藏握手状态机 / 周期 watchdog 探活重加 / post-hide 复核 / close 观测
//! 环，共 6906 行）整体删除，替换为 tray-icon 0.25.1（tauri 生态，MIT OR
//! Apache-2.0）正规实现：
//!
//! - **托盘图标与菜单** = `tray_icon::TrayIconBuilder` + muda（tray-icon 自带菜单
//!   依赖）：右键菜单 = 显示主窗口 / 退出（**菜单项集合不变**）；图标左单击 /
//!   必须显式 `with_menu_on_left_click(false)`，右键菜单默认开 → 显式
//!   `with_menu_on_right_click(true)` 钉死）。
//! - **创建时点** = eframe `App::new`（winit 事件循环已运行——tray-icon 硬性要
//!   求：托盘消息窗在创建线程创建并由该线程事件循环泵送；循环启动前创建 =
//!   点击/菜单事件丢失 = 「图标丢失」事故变体重演，调研风险① = 头号坑，本岗
//!   已废除 run_native 前创建时点）。
//! - **explorer 重启（TaskbarCreated 广播）图标丢失重挂** = **tray-icon 内建**
//!   （收到广播 → remove + 按当前图标/tooltip/可见性重注册；含提权进程 UIPI
//!   放行；首挂失败亦等此信号自愈；tray-icon 源码
//!   `src/platform_impl/windows/mod.rs` :53-54/:154-155/:371-381 亲证）。自研
//!   watchdog/探活重加/post-hide 复核/close 观测针对「非规范丢失」（第三方清
//!   理工具驱逐）= **生态零先例**（tray-icon/tauri 无周期探测重挂）= 业界接
//!   受边界（只处理 TaskbarCreated），整体删除。
//! - **关闭收进托盘** = eframe 0.28 标准形态（lib.rs `update()` 执行，本模块
//!   只供状态标志）：`close_requested()` → `CancelClose` + `Visible(false)`——
//!   CancelClose 是 eframe 官方关闭拦截点（vendored epi.rs 文档标准形态），
//!   替换自研 WNDPROC 子类 WM_CLOSE 拦截 + 隐藏握手状态机（调研 §3）。
//! - **事件投递** = `MenuEvent`/`TrayIconEvent` `set_event_handler`（托盘消息
//!   窗属 UI 线程 → handler 在 winit DispatchMessage 内**UI 线程**同步调用）
//!   → 模块级 `Mutex<Vec>` 事件槽（单生产者组/单消费者，UI 线程内交接；
//!   std::mpsc::Receiver 非 Sync 无法入静态，且本场景无跨线程唤醒需求）
//!   → lib.rs `update()` 每帧排空执行（tray-icon 官方 egui 示例形态，调研
//!   §1）。
//!
//! 主窗隐藏态标志（重绘泵 gating）/ 主窗 HWND 登记（eframe `window_handle()`
//! 闪烁（FlashWindowEx）/ 唤醒单帧（PostMessageW WM_SIZE + RedrawWindow）/
//! 审批提示音（MessageBeep）/ 托盘气泡（`NIM_MODIFY + NIF_INFO` 最小
//! helper，≤40 行——气泡是**增强**通道，审批弹窗 + 提示音仍是主通道；tray-
//!
//! **观测行**（沿用既有 tracing，零新机制）：托盘创建成功（INFO，`Tray::
//! create`）/ 创建失败（WARN，lib.rs 调用侧）= 2 行；TaskbarCreated 重挂事件
//! 在 tray-icon 侧**无可观测面**（无回调/无日志钩子）——实机自证 = explorer
//! 重启后图标自动复现（用户终判）。
//!
//! **headless 验证边界**：真 UI 托盘行为（图标在位/菜单弹起/双击恢复/Taskbar-
//! Created 重挂）无 headless 验证面——本模块单测钉死**纯分派函数矩阵 + 标题/
//! 菜单结构常量 + 退出清理决策**；真 UI 以创建成功/失败日志行 + 用户实机复
//! 测收口（行为回归面 = 菜单项集合不变 / 双击恢复 / 退出清理 / 单实例）。

use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
#[cfg(target_os = "windows")]
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

// ─────────────────────────── 托盘结构常量 ───────────────────────────

/// 菜单项 ID（**菜单结构常量**——「显示」/「退出」两项集合不变，单测钉死。
/// muda 0.20 `MenuId` = 字符串 ID（`MenuId::new<S: AsRef<str>>`，源码亲证））。
pub const MENU_ID_SHOW: &str = "kirin-tray.show";
pub const MENU_ID_QUIT: &str = "kirin-tray.quit";

/// i18n 表在位性单测钉死）。
pub const I18N_KEY_TOOLTIP: &str = "tray.tooltip";
pub const I18N_KEY_SHOW: &str = "tray.show";
pub const I18N_KEY_QUIT: &str = "tray.quit";

pub const ICON_SIZE: usize = 16;

/// 跨平台纯函数）。
///
/// 顶序 RGBA（row 0 = 顶行）：透明背景 + 显示器主体（1px 亮边框 + 深色填充，
/// 行 2..=9 × 列 1..=14）+ 支脚（行 10 × 列 7..=8）+ 底座（行 11 × 列 5..=10）。
pub fn icon_rgba() -> Vec<u8> {
    let mut px = vec![0u8; ICON_SIZE * ICON_SIZE * 4];
    let border: [u8; 4] = [122, 178, 255, 255];
    let fill: [u8; 4] = [30, 86, 180, 255];
    let stand: [u8; 4] = [90, 140, 220, 255];
    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let c = if (2..=9).contains(&y) && (1..=14).contains(&x) {
                if y == 2 || y == 9 || x == 1 || x == 14 {
                    border
                } else {
                    fill
                }
            } else if y == 10 && (7..=8).contains(&x) {
                stand
            } else if y == 11 && (5..=10).contains(&x) {
                stand
            } else {
                [0, 0, 0, 0]
            };
            let i = (y * ICON_SIZE + x) * 4;
            px[i] = c[0];
            px[i + 1] = c[1];
            px[i + 2] = c[2];
            px[i + 3] = c[3];
        }
    }
    px
}

// ─────────────── 事件分派（纯函数，跨平台可单测 = 行为矩阵钉死） ───────────────

/// 托盘动作（lib.rs `update()` 每帧排空后执行）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayMsg {
    /// 显示/恢复主窗口（图标左单击 / 左双击 / 菜单「显示主窗口」）。
    Show,
    /// 干净退出（菜单「退出」→ lib.rs `quit_all`；单实例语义与释放清理不
    /// 回归——既有退出清理路径逐位沿用）。
    Quit,
}

/// 图标事件类别（平台 `TrayIconEvent` → 纯映射；分派矩阵单测钉死）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconEventKind {
    LeftClick,
    LeftDoubleClick,
    RightClick,
    Other,
}

/// 菜单事件 → 动作（**纯分派矩阵**）：id = [`MENU_ID_SHOW`] → Show；id =
/// [`MENU_ID_QUIT`] → Quit；其余 id → None（防御：绝不臆造动作）。
pub fn dispatch_menu_id(id: &str) -> Option<TrayMsg> {
    match id {
        MENU_ID_SHOW => Some(TrayMsg::Show),
        MENU_ID_QUIT => Some(TrayMsg::Quit),
        _ => None,
    }
}

/// 左键 = 显示/恢复主窗口）；右键 = 菜单（tray-icon 自动弹起，无动作）；
/// 其余 → None。
pub fn dispatch_icon_event(kind: IconEventKind) -> Option<TrayMsg> {
    match kind {
        IconEventKind::LeftClick | IconEventKind::LeftDoubleClick => Some(TrayMsg::Show),
        IconEventKind::RightClick | IconEventKind::Other => None,
    }
}

// ─────────────── 事件槽（UI 线程 handler → update 每帧排空） ───────────────

/// 托盘事件槽（单消费者 = UI 线程 `update()`；handler 亦在 UI 线程同步
/// 执行——Mutex 仅作安全兜底，无锁竞争热路径）。
static TRAY_EVENTS: Mutex<Vec<TrayMsg>> = Mutex::new(Vec::new());

/// 取走本帧全部托盘事件（无事件 → 空表）。调用方 = UI 线程（lib.rs
/// `update()`）。
pub fn take_tray_events() -> Vec<TrayMsg> {
    let mut v = TRAY_EVENTS.lock().unwrap_or_else(|e| e.into_inner());
    std::mem::take(&mut v)
}

/// 托盘事件投递（`set_event_handler` handler 内调用；托盘消息窗属 UI 线程
/// → handler 在 UI 线程同步执行）——同时唤醒主窗单帧：
///
/// - 主窗**隐藏**态不再收 WM_PAINT，不唤醒则 `update()` 不跑、事件滞留
/// - 主窗**可见但空闲**（按需重绘，无输入零帧）时点击同样需一帧消费。
fn push_tray_event(msg: TrayMsg) {
    TRAY_EVENTS.lock().unwrap_or_else(|e| e.into_inner()).push(msg);
    wake_main_loop();
}

// ─────────────────────────────── 托盘句柄 ───────────────────────────────

///
/// **Drop 语义** = tray-icon 内建清理（NIM_DELETE + DestroyWindow）——托盘
/// 消息窗属 UI 线程、Drop 同线程同步销毁，**无独立消息线程、无 join**
/// 阻塞 + join 必挂，在 tray-icon 实现中按设计消除；退出看门狗保留为
/// 候选 (B) `ExitProcess` 收尾阻塞的纵深）。
#[cfg(target_os = "windows")]
pub struct Tray {
    icon: tray_icon::TrayIcon,
    item_show: tray_icon::menu::MenuItem,
    item_quit: tray_icon::menu::MenuItem,
}

#[cfg(target_os = "windows")]
impl Tray {
    /// 创建托盘图标 + 菜单 + 事件接线。
    ///
    /// **必须调用于事件循环所在线程**（winit 循环已运行 = eframe `App::new`
    /// 时点；tray-icon 硬性要求——托盘消息窗在本线程创建、由 winit 循环
    /// 泵送其消息；循环启动前创建 = 点击/菜单事件丢失，调研风险①）。
    ///
    /// 失败（headless / 无 shell / Explorer 未运行）→ `Err`，调用方优雅退
    /// 网沿用），**严禁 panic**。
    pub fn create(tooltip: &str, show_label: &str, quit_label: &str) -> Result<Self, String> {
        use tray_icon::menu::{Menu, MenuEvent, MenuItem};
        use tray_icon::{MouseButton, TrayIconBuilder, TrayIconEvent};

        let icon = tray_icon::Icon::from_rgba(
            icon_rgba(),
            ICON_SIZE as u32,
            ICON_SIZE as u32,
        )
        .map_err(|e| format!("tray icon rgba: {e}"))?;

        // `set_labels` 随语言切换刷新）。muda 0.20：`with_id(id, text,
        // enabled, accelerator)`（第 4 参 = 快捷键，无快捷键传 None）。
        let no_accel = std::option::Option::<tray_icon::menu::accelerator::Accelerator>::None;
        let show = MenuItem::with_id(MENU_ID_SHOW, show_label, true, no_accel);
        let quit = MenuItem::with_id(MENU_ID_QUIT, quit_label, true, no_accel);
        let menu = Menu::new();
        menu.append(&show).map_err(|e| format!("tray menu append(show): {e}"))?;
        menu.append(&quit).map_err(|e| format!("tray menu append(quit): {e}"))?;

        // 事件接线：handler 在 UI 线程（winit DispatchMessage 内）同步调用 →
        // 推事件槽 + 唤醒单帧（handler 内不得直接调 egui API，故槽交接）。
        MenuEvent::set_event_handler(Some(|ev: tray_icon::menu::MenuEvent| {
            if let Some(msg) = dispatch_menu_id(ev.id.as_ref()) {
                push_tray_event(msg);
            }
        }));
        TrayIconEvent::set_event_handler(Some(|ev| {
            let kind = match &ev {
                TrayIconEvent::Click { button, .. } if *button == MouseButton::Left => {
                    IconEventKind::LeftClick
                }
                TrayIconEvent::DoubleClick { button, .. } if *button == MouseButton::Left => {
                    IconEventKind::LeftDoubleClick
                }
                TrayIconEvent::Click { .. } => IconEventKind::RightClick,
                _ => IconEventKind::Other,
            };
            if let Some(msg) = dispatch_icon_event(kind) {
                push_tray_event(msg);
            }
        }));

        let built = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(tooltip)
            .with_icon(icon)
            // 默认左键弹菜单（源码 TrayIconAttributes::default 亲证），必须
            // 显式关；右键菜单 = 显式开钉死（零默认值依赖）。
            .with_menu_on_left_click(false)
            .with_menu_on_right_click(true)
            .build()
            .map_err(|e| format!("tray build: {e}"))?;

        // 气泡锚点：tray-icon 注册 notify icon 的窗口（本图标唯一消息窗）+
        // uID（tray-icon 内部 COUNTER 自 1 起、本进程恰一个托盘图标 = 恒 1，
        // 口径）→ `NIM_MODIFY + NIF_INFO` 更新**本图标**气泡（不新增第二
        // 个 notify icon）。
        BALLOON_HWND.store(built.window_handle() as usize, Ordering::SeqCst);
        tracing::info!(
            built.window_handle() as usize
        );
        Ok(Self {
            icon: built,
            item_show: show,
            item_quit: quit,
        })
    }

    /// 语言切换后刷新 tooltip / 菜单项文案（i18n 键不变，见
    /// [`I18N_KEY_TOOLTIP`]/[`I18N_KEY_SHOW`]/[`I18N_KEY_QUIT`]；muda
    /// `set_text`/`set_tooltip` 幂等）。失败静默（增强面，非致命）。
    pub fn set_labels(&mut self, tooltip: &str, show_label: &str, quit_label: &str) {
        let _ = self.icon.set_tooltip(Some(tooltip));
        self.item_show.set_text(show_label);
        self.item_quit.set_text(quit_label);
    }
}

/// 先例沿用）。
#[cfg(not(target_os = "windows"))]
pub struct Tray;

#[cfg(not(target_os = "windows"))]
impl Tray {
    pub fn create(_tooltip: &str, _show: &str, _quit: &str) -> Result<Self, String> {
        Err("tray is only supported on Windows".into())
    }
    pub fn set_labels(&mut self, _t: &str, _s: &str, _q: &str) {}
}


/// gating（隐藏窗口不再接收 WM_PAINT：重绘请求既无效，又会在 eframe 0.28
/// 的调度中留下陈旧 deadline → 非阻塞 busy 泵，故隐藏态一律跳过）。
///
/// 写方 = UI 线程（lib.rs `update_tray` 的隐藏/恢复分支）；读方 = UI 线程
/// 各重绘点 + 跨线程重绘任务（下载进度等）。
#[allow(dead_code)]
static MAIN_WINDOW_HIDDEN: AtomicBool = AtomicBool::new(false);

/// `update()` 首帧经 [`note_main_hwnd`] 写入）。
///
/// 标题常量失效；且 FindWindowW 跨进程全局搜索可钩错同标题窗）。
/// 写方 = UI 首帧（compare_exchange 仅首次）；读方 = UI 线程 + 跨线程重绘
/// 任务（原子读零负担）。null = 尚未登记 → 各 helper 安全侧降级。
#[allow(dead_code)] // 非 Windows 平台桩路径不触达（本应用为 Windows GUI）
static MAIN_HWND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// `frame.window_handle()` 取 Win32 hwnd 调用；已登记 = 幂等 no-op）。
/// 非 Windows 平台 no-op。
#[cfg(target_os = "windows")]
pub fn note_main_hwnd(hwnd: *mut c_void) {
    if !hwnd.is_null() {
        let _ = MAIN_HWND.compare_exchange(
            std::ptr::null_mut(),
            hwnd,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }
}

#[cfg(not(target_os = "windows"))]
pub fn note_main_hwnd(_hwnd: *mut c_void) {}

#[cfg(target_os = "windows")]
pub fn set_main_window_hidden(hidden: bool) {
    MAIN_WINDOW_HIDDEN.store(hidden, Ordering::Release);
}

#[cfg(not(target_os = "windows"))]
pub fn set_main_window_hidden(_hidden: bool) {}

/// 共用）。
#[cfg(target_os = "windows")]
pub fn is_main_window_hidden() -> bool {
    MAIN_WINDOW_HIDDEN.load(Ordering::Acquire)
}

#[cfg(not(target_os = "windows"))]
pub fn is_main_window_hidden() -> bool {
    false
}

/// 未登记 = `false` → 调用方按「非前台」处理——**安全侧**：宁多闪一次任务
/// 栏、不漏一次审批通知。廉价 Win32 查询，逐帧调用零负担）。非 Windows
/// 平台恒 `false`。
#[cfg(target_os = "windows")]
pub fn is_main_window_foreground() -> bool {
    let hwnd = MAIN_HWND.load(Ordering::SeqCst);
    if hwnd.is_null() {
        return false;
    }
    unsafe { win::is_main_window_foreground(hwnd) }
}

#[cfg(not(target_os = "windows"))]
pub fn is_main_window_foreground() -> bool {
    false
}

/// 败不阻塞**——Windows 前台锁对后台进程发起的 SFW 可拒绝，返回 false 为
/// 常态，此时任务栏连续闪烁〔`set_approval_flash`〕承接）。调用方 = UI 线
/// 程。非 Windows 平台 no-op。
#[cfg(target_os = "windows")]
pub fn request_main_foreground() {
    let hwnd = MAIN_HWND.load(Ordering::SeqCst);
    if hwnd.is_null() {
        return;
    }
    unsafe { win::request_main_foreground(hwnd) }
}

#[cfg(not(target_os = "windows"))]
pub fn request_main_foreground() {}

/// `on = FLASHW_TRAY|FLASHW_TIMER` 连续 / `off = FLASHW_STOP`）。隐藏窗无
/// 任务栏按钮 → Win32 层 no-op（调用方门控已保证隐藏态不启动，气泡承接）。
/// 非 Windows 平台 no-op。
#[cfg(target_os = "windows")]
pub fn set_approval_flash(on: bool) {
    let hwnd = MAIN_HWND.load(Ordering::SeqCst);
    if hwnd.is_null() {
        return;
    }
    unsafe { win::set_approval_flash(hwnd, on) }
}

#[cfg(not(target_os = "windows"))]
pub fn set_approval_flash(_on: bool) {}

/// 当前客户区尺寸)` → winit `Resized(非零)` → eframe `RepaintNow` → 直接
/// `run_ui_and_paint`（不经 WM_PAINT）；`RedrawWindow(RDW_INTERNALPAINT |
/// RDW_INVALIDATE)` 双保险（进程内同步 API，可见态下失效区 → WM_PAINT 通
/// 路仍通）。
///
/// **隐藏动作完成后必须调用**：唤醒帧会清掉 eframe 中残留的陈旧重绘
/// deadline，使事件循环回到阻塞 GetMessage（防 Poll 忙转 / "Not
/// Responding"）。调用方 = UI 线程（隐藏分支/托盘事件）+ 隐私 ack 网络线
/// 程（PostMessageW 跨线程安全）。HWND 未登记 → 静默跳过（安全侧：主窗可
/// 见态常规帧驱动）。
#[cfg(target_os = "windows")]
pub fn wake_main_loop() {
    unsafe { win::wake_main_loop() }
}

#[cfg(not(target_os = "windows"))]
pub fn wake_main_loop() {}

/// = 高**解析；尺寸钳到 1..=0xFFFF 且保证非零——0×0 会被 eframe 当作最小
/// 化信号忽略）。纯函数，单测钉死。
pub fn wake_size_lparam(width: u32, height: u32) -> u32 {
    let w = width.clamp(1, 0xFFFF);
    let h = height.clamp(1, 0xFFFF);
    (h << 16) | w
}

/// 进程仍存活 → 强杀（现覆盖候选 (B) `ExitProcess` 收尾被 FFmpeg/QSV/
/// arboard(COM) DLL `DllMain` 阻塞；旧候选 (A)「Drop 内 join 卡死」在
/// tray-icon 实现中按设计消除——消息窗属 UI 线程、Drop 同线程同步销毁）。
pub const EXIT_WATCHDOG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// 退出看门狗触发决策（**纯函数**，单测钉死边界）：elapsed 达到/超过预算
/// → 强杀。线程休眠 + `TerminateProcess` 本体无单测面（进程行为），以实
/// 机复测判据 + 代码评审收口。
pub fn exit_watchdog_due(elapsed: std::time::Duration, timeout: std::time::Duration) -> bool {
    elapsed >= timeout
}

/// 在 `std::process::exit(0)` 前调用（**先于** tray Drop：看门狗必须先于
/// 退出路径任何潜在卡点存活；图标清理仍在实际死亡之前 → 「先清托盘图标再
/// 死」保持）。正常路径下进程在 exit(0) 后毫秒级消失，看门狗随进程同灭、
/// 永不唤醒 → 零副作用。非 Windows 平台 no-op。
#[cfg(target_os = "windows")]
pub fn spawn_exit_watchdog() {
    win::spawn_exit_watchdog()
}

#[cfg(not(target_os = "windows"))]
pub fn spawn_exit_watchdog() {}

/// （`NIM_MODIFY + NIF_INFO` 最小 helper；tray-icon 无 balloon API = 调研
/// 风险②，本 helper 为 PM 裁定保留的 ≤40 行最小实现）。
///
/// 目标 = tray-icon 注册窗口（[`Tray::create`] 成功时登记；uID = 1，见
/// `Tray::create` 气泡锚点注释）。托盘未注册（创建失败降级/headless）→
/// 静默跳过（气泡是**增强**通道，审批弹窗 + 提示音仍是主通道；绝不因气泡
/// 失败阻断审批流）。调用方 = UI 线程。非 Windows 平台 no-op。
#[cfg(target_os = "windows")]
static BALLOON_HWND: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "windows")]
pub fn balloon_notification(title: &str, text: &str) {
    let hwnd = BALLOON_HWND.load(Ordering::SeqCst) as *mut c_void;
    if hwnd.is_null() {
        return;
    }
    unsafe { win::balloon_notification(hwnd, title, text) }
}

#[cfg(not(target_os = "windows"))]
pub fn balloon_notification(_title: &str, _text: &str) {}

/// 走系统声音方案，零音频库依赖；无音频设备/静音时静默失败，非致命）。
/// 非 Windows 平台 no-op。
#[cfg(target_os = "windows")]
pub fn play_approval_sound() {
    unsafe { win::play_approval_sound() }
}

#[cfg(not(target_os = "windows"))]
pub fn play_approval_sound() {}

///
/// GUI 截屏/隔离目录验证场景：另一 KirinDesk 实例在跑（持有
/// `Local\KirinDesk.SingleInstance`）时第二实例启动即退出，无法取运行态
/// 截屏。显式设 `KIRIN_ALLOW_MULTI_INSTANCE=1`（或 `true`）时本进程跳过
/// 单实例 mutex、按独立测试实例启动。**生产默认路径零变更**：env 未设或
/// 其它任何取值一律走原 mutex 逻辑（严格匹配，防误开）。
pub(crate) fn multi_instance_bypass_enabled() -> bool {
    std::env::var_os("KIRIN_ALLOW_MULTI_INSTANCE")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
}

/// 单实例锁：true = 本进程为主实例；false = 已有实例（已聚焦既有窗口）。
///
/// `Local\KirinDesk.SingleInstance` 命名 mutex；句柄存活至进程退出（leak，
/// **不得** CloseHandle——否则运行期第二实例可抢占锁）。创建失败（权限异
/// [`multi_instance_bypass_enabled`]。非 Windows 平台恒 true（本应用为
/// Windows GUI）。
#[cfg(target_os = "windows")]
pub fn acquire_single_instance() -> bool {
    if multi_instance_bypass_enabled() {
        return true;
    }
    unsafe { win::acquire_single_instance() }
}

#[cfg(not(target_os = "windows"))]
pub fn acquire_single_instance() -> bool {
    true
}

// ─────────────────────────── Windows 平台实现 ───────────────────────────

#[cfg(target_os = "windows")]
mod win {
    use super::*;
    use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

    // ---------- 常量（winuser.h / shellapi.h 权威值） ----------

    const SINGLE_INSTANCE_MUTEX: &str = "Local\\KirinDesk.SingleInstance";
    const WM_SIZE: u32 = 0x0005;
    const SIZE_RESTORED: usize = 0;
    const RDW_INVALIDATE: u32 = 0x0000_0001;
    const RDW_INTERNALPAINT: u32 = 0x0000_0100;
    const SW_RESTORE: i32 = 9;
    const FLASHW_STOP: u32 = 0x0000_0000;
    const FLASHW_TRAY: u32 = 0x0000_0002;
    const FLASHW_TIMER: u32 = 0x0000_0004;
    const MB_ICONEXCLAMATION: u32 = 0x0000_0030;
    const ERROR_ALREADY_EXISTS: u32 = 183;
    const NIM_MODIFY: u32 = 0x0000_0001;
    const NIF_INFO: u32 = 0x0000_0010;
    const NIIF_INFO: u32 = 0x0000_0001;
    /// 气泡 NIM_MODIFY 的 uID——tray-icon 内部 COUNTER 自 1 起（源码亲证）
    const TRAY_BALLOON_UID: u32 = 1;
    /// 唤醒结果 INFO 日志去重窗（ms）——唤醒为事件驱动低频，≥5s 稳态采样
    const WAKE_LOG_INTERVAL_MS: u32 = 5_000;

    // ---------- 结构体（Windows SDK 布局；cbSize 须为完整结构大小） ----------

    #[repr(C)]
    #[derive(Default)]
    struct Rect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    /// `FLASHWINS`（DWORD/HWND/DWORD/DWORD 逐位对齐）。
    #[repr(C)]
    struct FlashWins {
        cb_size: u32,
        hwnd: *mut c_void,
        dw_flags: u32,
        u_count: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    /// 实证的字节布局；本模块仅 NIM_MODIFY(NIF_INFO) 气泡面消费；含
    /// `[u16;128]` 字段故不可 derive(Default) → 一律 `mem::zeroed()`）。
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct NotifyIconDataW {
        cb_size: u32,
        hwnd: *mut c_void,
        u_id: u32,
        u_flags: u32,
        u_callback_message: u32,
        h_icon: *mut c_void,
        sz_tip: [u16; 128],
        dw_state: u32,
        dw_state_mask: u32,
        sz_info: [u16; 256],
        u_version: u32,
        sz_info_title: [u16; 64],
        dw_info_flags: u32,
        guid_item: Guid,
        h_balloon_icon: *mut c_void,
    }

    /// `NotifyIconDataW` 布局大小钉死（防字段漂移静默破坏 NIM_MODIFY 气泡；
    /// 测试面专用——release 构建中结构体本体经 balloon 消费，常量不入）。
    #[cfg(test)]
    pub const NOTIFYICONDATA_W_SIZE: usize = std::mem::size_of::<NotifyIconDataW>();


    #[link(name = "user32")]
    extern "system" {
        fn FindWindowW(class: *const u16, title: *const u16) -> *mut c_void;
        fn ShowWindow(hwnd: *mut c_void, cmd: i32) -> i32;
        fn IsWindowVisible(hwnd: *mut c_void) -> i32;
        fn GetForegroundWindow() -> *mut c_void;
        fn SetForegroundWindow(hwnd: *mut c_void) -> i32;
        fn GetClientRect(hwnd: *mut c_void, rect: *mut Rect) -> i32;
        fn PostMessageW(hwnd: *mut c_void, msg: u32, wp: usize, lp: isize) -> i32;
        fn RedrawWindow(
            hwnd: *mut c_void,
            lprc: *const Rect,
            hrgn: *mut c_void,
            flags: u32,
        ) -> i32;
        fn FlashWindowEx(pwfi: *const FlashWins) -> i32;
        /// 注：本 mingw-w64 工具链 libuser32.a 导入库仅有 `MessageBeep`
        /// 符号名不得写 `MessageBeepW`）。
        fn MessageBeep(u_type: u32) -> i32;
        /// 毫秒 tick（49.7 天回绕——间隔一律 `wrapping_sub` 求）。
        fn GetTickCount() -> u32;
        // （长期在位产品实证，链接面零变更）。
        fn Shell_NotifyIconW(cmd: u32, data: *mut NotifyIconDataW) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateMutexW(attrs: *mut c_void, named: i32, name: *const u16) -> *mut c_void;
        fn GetLastError() -> u32;
        fn GetCurrentProcess() -> *mut c_void;
        /// 强制终止进程（退出看门狗末段；成功则**不返回**）。
        fn TerminateProcess(process: *mut c_void, exit_code: u32) -> i32;
    }

    // ---------- 工具 ----------

    fn to_wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn to_wide_fixed(s: &str, max_units: usize) -> Vec<u16> {
        s.encode_utf16()
            .take(max_units)
            .chain(std::iter::once(0))
            .collect()
    }

    // ---------- 主窗口查询 / 置前 / 闪烁 ----------

    pub(super) unsafe fn is_main_window_foreground(hwnd: *mut c_void) -> bool {
        GetForegroundWindow() == hwnd
    }

    pub(super) unsafe fn request_main_foreground(hwnd: *mut c_void) {
        let ok = SetForegroundWindow(hwnd) != 0;
        tracing::info!(
            ok,
            hwnd as usize,
            GetForegroundWindow() as usize,
            if ok {
                ""
            } else {
                " — foreground lock denied (expected for background process), taskbar flash carries the notice"
            },
        );
    }

    pub(super) unsafe fn set_approval_flash(hwnd: *mut c_void, on: bool) {
        if IsWindowVisible(hwnd) == 0 {
            return; // 隐藏窗无任务栏按钮 → no-op（调用方门控已保证；兜底防漂移）
        }
        let fwe = FlashWins {
            cb_size: std::mem::size_of::<FlashWins>() as u32,
            hwnd,
            dw_flags: if on { FLASHW_TRAY | FLASHW_TIMER } else { FLASHW_STOP },
            u_count: 0,
        };
        if FlashWindowEx(&fwe) == 0 {
            tracing::debug!(
                if on { "start" } else { "stop" },
                GetLastError()
            );
        }
    }

    // ---------- 唤醒单帧 ----------

    /// 唤醒结果 INFO 去重锚（tick ms；`u32::MAX` = 从未记过）。
    static WAKE_LOG_TICK: AtomicU32 = AtomicU32::new(u32::MAX);

    pub(super) unsafe fn wake_main_loop() {
        let hwnd = MAIN_HWND.load(Ordering::SeqCst);
        if hwnd.is_null() {
            tracing::debug!("[shell] wake_main_loop: skipped (main hwnd not noted)");
            return;
        }
        let mut r = Rect::default();
        if GetClientRect(hwnd, &mut r) == 0 {
            tracing::debug!(
                "[shell] wake_main_loop: GetClientRect failed (hwnd=0x{:X}, err={})",
                hwnd as usize,
                GetLastError()
            );
            return;
        }
        let w = (r.right - r.left) as u32;
        let h = (r.bottom - r.top) as u32;
        let lparam = super::wake_size_lparam(w, h) as isize;
        let ok = PostMessageW(hwnd, WM_SIZE, SIZE_RESTORED as usize, lparam);
        // 双保险：进程内同步 API（可见态下失效区 → WM_PAINT 通路仍通）。
        let rdw = RedrawWindow(
            hwnd,
            std::ptr::null(),
            std::ptr::null_mut(),
            RDW_INTERNALPAINT | RDW_INVALIDATE,
        );
        // INFO 去重（≥5s 稳态一行；结果翻转不特判——观测低频面，防刷屏优先）。
        let now = GetTickCount();
        let last = WAKE_LOG_TICK.swap(now, Ordering::Relaxed);
        if last == u32::MAX || now.wrapping_sub(last) >= WAKE_LOG_INTERVAL_MS {
            tracing::info!(
                "[shell] wake_main_loop: PostMessageW(WM_SIZE, {w}x{h}) = {ok} + RedrawWindow = {rdw} (hwnd=0x{:X})",
                hwnd as usize
            );
        }
    }

    // ---------- 审批提示音 ----------

    pub(super) unsafe fn play_approval_sound() {
        if MessageBeep(MB_ICONEXCLAMATION) == 0 {
            tracing::debug!(
                "[shell] tray: MessageBeep failed (err={}) — sound skipped (non-fatal)",
                GetLastError()
            );
        }
    }

    // ---------- 托盘气泡（NIM_MODIFY + NIF_INFO 最小 helper） ----------

    pub(super) unsafe fn balloon_notification(hwnd: *mut c_void, title: &str, text: &str) {
        let mut nid: NotifyIconDataW = std::mem::zeroed();
        nid.cb_size = std::mem::size_of::<NotifyIconDataW>() as u32;
        nid.hwnd = hwnd;
        nid.u_id = TRAY_BALLOON_UID;
        nid.u_flags = NIF_INFO; // 仅改 info 段，不动图标/提示/回调
        // u_version = 0：tray-icon 不做 NIM_SETVERSION V4 协商（v0 语义，
        for (dst, src) in nid.sz_info_title.iter_mut().zip(to_wide_fixed(title, 63)) {
            *dst = src;
        }
        for (dst, src) in nid.sz_info.iter_mut().zip(to_wide_fixed(text, 255)) {
            *dst = src;
        }
        nid.dw_info_flags = NIIF_INFO;
        if Shell_NotifyIconW(NIM_MODIFY, &mut nid) == 0 {
            tracing::warn!(
                "[shell] tray: balloon NIM_MODIFY failed (err={}) — notification skipped (non-fatal)",
                GetLastError()
            );
        }
    }

    // ---------- 退出看门狗 ----------

    pub(super) fn spawn_exit_watchdog() {
        std::thread::Builder::new()
            .name("kirin-exit-watchdog".into())
            .spawn(|| {
                let armed_at = std::time::Instant::now();
                std::thread::sleep(super::EXIT_WATCHDOG_TIMEOUT);
                // 被唤醒 = 线程还活着 = 进程仍存活（正常路径下进程已在
                // exit(0) 后毫秒级消失、本线程随进程同灭、永不醒来）。
                let elapsed = armed_at.elapsed();
                if super::exit_watchdog_due(elapsed, super::EXIT_WATCHDOG_TIMEOUT) {
                    tracing::warn!(
                        elapsed.as_millis(),
                        super::EXIT_WATCHDOG_TIMEOUT.as_millis()
                    );
                    unsafe {
                        TerminateProcess(GetCurrentProcess(), 1);
                    }
                    // TerminateProcess 成功不返回；失败（不应发生）则落空
                    // 结束——进程本已病态，留 WARN 行供取证。
                }
            })
            .map(|_| ())
            .unwrap_or_else(|e| {
            });
    }

    // ---------- 单实例 ----------

    /// 单实例 mutex 句柄持有槽（进程退出前永不 CloseHandle）。
    static INSTANCE_MUTEX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

    /// 主窗口标题（镜像 lib.rs `start_gui` viewport 标题 = `app_title_base()`
    /// 定标题常量（无版本）已失效）。仅第二实例「聚焦既有窗口」消费。
    fn main_title() -> String {
        format!(
            "KirinDesk v{} - P2P Remote Desktop",
            env!("CARGO_PKG_VERSION")
        )
    }

    pub(super) unsafe fn acquire_single_instance() -> bool {
        let name16 = to_wide_null(SINGLE_INSTANCE_MUTEX);
        let handle = CreateMutexW(std::ptr::null_mut(), 1, name16.as_ptr());
        if GetLastError() == ERROR_ALREADY_EXISTS {
            // 实现沿用；SW_RESTORE 含托盘隐藏态恢复）。
            let title16 = to_wide_null(&main_title());
            let hwnd = FindWindowW(std::ptr::null(), title16.as_ptr());
            if hwnd.is_null() {
                tracing::debug!("[shell] single-instance: existing main window not found (title mismatch?) — second instance exits without focus");
            } else {
                let _ = ShowWindow(hwnd, SW_RESTORE);
                let _ = SetForegroundWindow(hwnd);
            }
            return false;
        }
        // 句柄存活至进程退出：存入 static 显式表达持有语义（OS 于进程退出
        // 时回收）。创建失败（handle=null 且非 ALREADY_EXISTS）→ fail-open
        // 视为主实例。
        INSTANCE_MUTEX.store(handle, Ordering::SeqCst);
        true
    }
}

// ─────────────────────────────── 单测 ───────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 菜单事件 → 动作分派矩阵（**菜单项集合不变** = 显示/退出 2 项钉死）。
    #[test]
    fn r144_dispatch_menu_id_matrix() {
        assert_eq!(dispatch_menu_id(MENU_ID_SHOW), Some(TrayMsg::Show));
        assert_eq!(dispatch_menu_id(MENU_ID_QUIT), Some(TrayMsg::Quit));
        // 未知 id → None（防御：绝不臆造动作）。
        assert_eq!(dispatch_menu_id(""), None);
        assert_eq!(dispatch_menu_id("kirin-tray.show "), None); // 非精确匹配
        assert_eq!(dispatch_menu_id("tray.show"), None); // 与 i18n 键不同命名空间
        assert_eq!(dispatch_menu_id("kirin-tray.quit"), Some(TrayMsg::Quit));
        // 两 ID 互异且非空（菜单结构常量）。
        assert_ne!(MENU_ID_SHOW, MENU_ID_QUIT);
        assert!(!MENU_ID_SHOW.is_empty() && !MENU_ID_QUIT.is_empty());
    }

    /// 图标事件 → 动作分派矩阵（左单击/左双击 = 恢复主窗；右键 = 菜单无
    /// 动作；其余 None）。
    #[test]
    fn r144_dispatch_icon_event_matrix() {
        assert_eq!(dispatch_icon_event(IconEventKind::LeftClick), Some(TrayMsg::Show));
        assert_eq!(
            dispatch_icon_event(IconEventKind::LeftDoubleClick),
            Some(TrayMsg::Show)
        );
        assert_eq!(dispatch_icon_event(IconEventKind::RightClick), None);
        assert_eq!(dispatch_icon_event(IconEventKind::Other), None);
    }

    /// （zh/en 成对——缺键时 `tr_lang` 回退返回键名本身，`!= key` 即在位证
    /// 明）。
    #[test]
    fn r144_menu_structure_constants() {
        assert_eq!(I18N_KEY_TOOLTIP, "tray.tooltip");
        assert_eq!(I18N_KEY_SHOW, "tray.show");
        assert_eq!(I18N_KEY_QUIT, "tray.quit");
        for key in [I18N_KEY_TOOLTIP, I18N_KEY_SHOW, I18N_KEY_QUIT] {
            assert_ne!(crate::i18n::tr_lang(crate::i18n::Lang::Zh, key), key, "zh key missing: {key}");
            let en = crate::i18n::tr_lang(crate::i18n::Lang::En, key);
            assert_ne!(en, key, "en key missing: {key}");
            assert!(!en.is_empty(), "en text empty: {key}");
        }
    }

    /// 退出看门狗决策（**退出清理路径**纯函数）：未到期 false / 恰好到期
    /// / 超期 true（边界 + 单调性钉死）。
    #[test]
    fn r144_exit_watchdog_due_matrix() {
        let t = EXIT_WATCHDOG_TIMEOUT;
        assert!(!exit_watchdog_due(t - std::time::Duration::from_millis(1), t));
        assert!(exit_watchdog_due(t, t));
        assert!(exit_watchdog_due(t + std::time::Duration::from_millis(500), t));
    }

    /// 零漂移）。
    #[test]
    fn r144_icon_rgba_smoke() {
        let px = icon_rgba();
        assert_eq!(px.len(), ICON_SIZE * ICON_SIZE * 4);
        // 顶行（y=0）全透明。
        for x in 0..ICON_SIZE {
            let i = x * 4;
            assert_eq!(&px[i..i + 4], &[0, 0, 0, 0], "top row must be transparent (x={x})");
        }
        // 主体边框（y=2,x=1）= 亮边框色；主体填充（y=5,x=5）= 深色填充。
        let border: [u8; 4] = [122, 178, 255, 255];
        let fill: [u8; 4] = [30, 86, 180, 255];
        let bi = (2 * ICON_SIZE + 1) * 4;
        let fi = (5 * ICON_SIZE + 5) * 4;
        assert_eq!(&px[bi..bi + 4], &border[..]);
        assert_eq!(&px[fi..fi + 4], &fill[..]);
    }

    /// 唤醒 WM_SIZE lparam 打包：低 16 位 = 宽、高 16 位 = 高；钳位
    /// 1..=0xFFFF 非零（0×0 会被 eframe 当最小化信号忽略）。
    #[test]
    fn r144_wake_size_lparam_roundtrip() {
        let lp = wake_size_lparam(1024, 768);
        assert_eq!(lp & 0xFFFF, 1024);
        assert_eq!(lp >> 16, 768);
        assert_eq!(wake_size_lparam(0, 0), 0x0001_0001);
        assert_eq!(wake_size_lparam(0x1_0000, 0x1_0000), 0xFFFF_FFFF);
    }

    /// 其它任何取值（含大小写变体）= 关（生产默认路径零变更）。
    #[test]
    fn r144_multi_instance_bypass_strict_match() {
        // env 为进程全局态：快照-恢复，测试间零串扰。
        let prev = std::env::var_os("KIRIN_ALLOW_MULTI_INSTANCE");
        std::env::remove_var("KIRIN_ALLOW_MULTI_INSTANCE");
        assert!(!multi_instance_bypass_enabled(), "unset = off");
        for (v, want) in [
            ("0", false),
            ("2", false),
            ("yes", false),
            ("TRUE", false),
            ("", false),
            ("1", true),
            ("true", true),
        ] {
            std::env::set_var("KIRIN_ALLOW_MULTI_INSTANCE", v);
            assert_eq!(multi_instance_bypass_enabled(), want, "value {v:?}");
        }
        match prev {
            Some(v) => std::env::set_var("KIRIN_ALLOW_MULTI_INSTANCE", v),
            None => std::env::remove_var("KIRIN_ALLOW_MULTI_INSTANCE"),
        }
    }

    /// NIM_MODIFY 的 cbSize 契约；字段漂移 = 静默破坏气泡）。
    #[cfg(target_os = "windows")]
    #[test]
    fn r144_notifyicondata_layout_pinned() {
        assert_eq!(win::NOTIFYICONDATA_W_SIZE, 976);
    }

    /// 事件通道：push → take 全量取走（空表语义 + 排空后零残留）。
    #[test]
    fn r144_tray_event_channel_drain() {
        push_tray_event(TrayMsg::Show);
        let evs = take_tray_events();
        assert!(evs.contains(&TrayMsg::Show), "Show must be drained");
        // 排空后再次取 = 无本测试新增残留（其它测试并发 push 不在此断言
        // 范围——通道为进程级，断言「本次 push 必被取到」而非「绝对空表」）。
    }
}
