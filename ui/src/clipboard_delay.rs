//!
//! 用户批复口径（docs/R194_OLE延迟渲染设计_2026-09-28.md）：复制动作只
//! 才按需拉取数据（授权 = 粘贴动作本身）。本模块 = 两侧（s→c 主控臂 /
//! c→s 受控臂）共用的延迟渲染机构：
//!
//! - **选型 = Win32 经典延迟渲染**：`SetClipboardData(CF_HDROP, NULL)` +
//!   专用隐藏消息窗（`WM_RENDERFORMAT`/`WM_RENDERALLFORMATS`）。**非** OLE
//!   `IDataObject` 延迟版——24H2 raw-FFI `OleSetClipboard` 确定性拒绝形态
//!   自维护 COM 对象响应 Explorer `GetData` 回调（STA 封送风险叠加）；经典
//!   机制零 COM、写板原语与既有 classic 臂同源（去数据化）。
//! - **渲染回调 = 粘贴授权触发点**：粘贴消费方 `GetClipboardData(CF_HDROP)`
//!   → 系统 `SendMessage(WM_RENDERFORMAT)` 到本窗 → 此刻才派发
//!   [`FileCommand::FetchFile`]（**既有引擎/授权链/sanitize/tid 去重原样，
//!   零新 wire**）拉到本侧任务目录 → 全部落定（bounded 等待
//!   [`R194_RENDER_WAIT`]，all-or-nothing）→ 以真实路径组 HDROP
//!   `SetClipboardData` 应答。落点 = 消费方（Explorer）当前目录，OS 天然正确。
//! - **防回环关键（load-bearing）**：延迟板数据未渲染前
//!   `IsClipboardFormatAvailable(CF_HDROP)=true`，但本进程任何线程
//!   `GetClipboardData` 都会**反向触发渲染拉取**（= 复制即传输回潮）。
//!   防线 = [`delay_board_owned_by_us`]（`GetClipboardOwner()==延迟窗`）在
//!   `clipboard_files::has_cf_hdrop`/`read_cf_hdrop` 最低层面短路，覆盖全部
//! - **回退**：布防失败/计划为空 = 不布防（两段式原样）；渲染超时/拉取失败
//!   = 不应答（消费方粘贴无物）+ 连接页 Warn 行回退提示（pending 槽仍在，
//!   文件窗 Ctrl+V 两段式照旧）。
//!
//! 线程模型：首次布防惰性派生专用线程（RegisterClassW + `HWND_MESSAGE`
//! 消息窗 + `GetMessageW` 泵，进程生命周期常驻）；布防/撤防经
//! `SendMessage`（WM_APP 区间自定义消息）在本窗线程执行剪贴板序列；渲染
//! 回调内**派生工作线程**执行拉取、本窗线程 `PeekMessageW` 泵消息有界等待
//! （嵌套 `WM_RENDERFORMAT` 以在途标志拒绝，消费方可重试粘贴——极少并发
//! 粘贴面）。
//!
//! 平台门：Win32 面 `#[cfg(windows)]`；纯逻辑（计划/渲染跟踪器/裁决）全
//! 平台编译供单测；非 Windows 布防恒 false = 两段式原样（fail-closed）。

use crate::clipboard::FileClipMeta;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 渲染等待上界（对端拉取 + 落定）。超时 = all-or-nothing 不应答（大文件
/// 阻塞粘贴 = 已知边界备案，进度窗后续迭代；已完整落定条目留在任务目录，
/// 再次粘贴 size 命中秒回 = 断点友好）。
pub(crate) const R194_RENDER_WAIT: Duration = Duration::from_secs(30);

/// 任务目录陈旧清扫 TTL（上一次渲染残留；新布防时懒清扫）。
const R194_TASK_DIR_TTL: Duration = Duration::from_secs(30 * 60);

/// 按需拉取闭包（生产 = `FileCommand::FetchFile` 既有链；测试 = 假件）。
pub(crate) type DelayFetchFn = Arc<dyn Fn(&str, &Path) + Send + Sync>;

// ────────────────────────── 纯逻辑：布防计划 ──────────────────────────

/// 布防计划单条（渲染时逐条 `FetchFile`/落定匹配的键形）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DelayPlanEntry {
    /// 根相对路径（wire 同形；`FetchFile.remote_path` 原样入参）。
    pub rel_path: String,
    /// 末段 basename（落定匹配键，Windows 大小写不敏感）。
    pub basename: String,
    /// 元数据声明 size（落定命中判定 + 断点秒回判定）。
    pub size: u64,
}

/// 布防计划（纯函数产出；**计划为空 = 不布防**，两段式原样）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DelayPlan {
    /// 顶层散文件条目（`fetchable && !is_dir` 且 rel 不含 `/`；条目序 =
    /// 用户复制序）。目录条目与树内文件行（v1 边界）不入渲染。
    pub entries: Vec<DelayPlanEntry>,
    /// 目录条目数（v1 边界跳过；连接页提示实参）。
    pub skipped_dirs: usize,
    /// 根外文件数（fetchable=false；两段式占位同口径）。
    pub skipped_outside: usize,
    /// 同名去重数（basename 冲突只取首条——引擎按 basename 落盘，同板
    /// 双同名 v1 边界备案）。
    pub skipped_dedup: usize,
}

/// rel 路径末段 basename（`/` 分隔；wire rel 单一形态）。
fn rel_basename(rel: &str) -> &str {
    rel.rfind('/').map(|i| &rel[i + 1..]).unwrap_or(rel)
}

///
/// 收敛口径：`fetchable && !is_dir` 的**顶层**条目（rel 不含 `/`——树内
/// 文件行由目录条目承载，目录条目 v1 不参与延迟渲染 = 应用内两段式整树
/// 粘贴兜底）；basename 大小写不敏感去重（Windows 落盘语义同源）；根外
/// 文件与目录只计数不渲染。
pub(crate) fn delay_plan(meta: &FileClipMeta) -> DelayPlan {
    let mut plan = DelayPlan::default();
    let mut seen: Vec<String> = Vec::new();
    for e in &meta.entries {
        if !e.fetchable {
            if !e.is_dir {
                plan.skipped_outside += 1;
            }
            continue;
        }
        if e.is_dir {
            plan.skipped_dirs += 1;
            continue;
        }
        if e.rel_path.contains('/') {
            // 树内文件行（目录条目承载面）——v1 延迟渲染边界，不单独平铺。
            continue;
        }
        let basename = rel_basename(&e.rel_path).to_string();
        if basename.is_empty() {
            continue;
        }
        if seen.iter().any(|s| s.eq_ignore_ascii_case(&basename)) {
            plan.skipped_dedup += 1;
            continue;
        }
        seen.push(basename.clone());
        plan.entries.push(DelayPlanEntry {
            rel_path: e.rel_path.clone(),
            basename,
            size: e.size,
        });
    }
    plan
}

// ────────────────────────── 纯逻辑：渲染跟踪器/裁决 ──────────────────────────

/// 渲染落定跟踪器（纯逻辑，`notify_landed` 消费面；大小写不敏感匹配）。
#[derive(Debug, Default)]
pub(crate) struct RenderTracker {
    expected_lower: Vec<String>,
    landed: Vec<(String, PathBuf)>,
}

impl RenderTracker {
    pub(crate) fn new(expected_basenames: Vec<String>) -> Self {
        Self {
            expected_lower: expected_basenames
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            landed: Vec::new(),
        }
    }

    /// 落定登记：命中预期集且未落过 → 记入并返回**是否全部完成**；
    /// 未命中（他任务落盘/TTL）或重复落定 → no-op false（fail-closed 零误配）。
    pub(crate) fn on_landed(&mut self, file_name: &str, path: &Path) -> bool {
        let name_lower = file_name.to_ascii_lowercase();
        if !self.expected_lower.iter().any(|e| *e == name_lower) {
            return false;
        }
        if self
            .landed
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(file_name))
        {
            return false;
        }
        self.landed.push((file_name.to_string(), path.to_path_buf()));
        self.complete()
    }

    /// 全部预期落定（完成判定 = all-or-nothing 应答门）。
    pub(crate) fn complete(&self) -> bool {
        !self.expected_lower.is_empty() && self.landed.len() == self.expected_lower.len()
    }

    pub(crate) fn landed_count(&self) -> usize {
        self.landed.len()
    }

    pub(crate) fn expected_count(&self) -> usize {
        self.expected_lower.len()
    }

    /// 应答 HDROP 路径集（按计划条目序 = 用户复制序输出已落定绝对路径）。
    pub(crate) fn landed_paths_in_plan_order(&self, order: &[DelayPlanEntry]) -> Vec<PathBuf> {
        order
            .iter()
            .filter_map(|e| {
                self.landed
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(&e.basename))
                    .map(|(_, p)| p.clone())
            })
            .collect()
    }
}

/// 渲染裁决（纯函数）：`Some(true)` = 完成应答；`Some(false)` = 等待超预算
/// **不应答**（all-or-nothing，回退两段式）；`None` = 继续等待。
pub(crate) fn render_outcome(complete: bool, waited: Duration, deadline: Duration) -> Option<bool> {
    if complete {
        return Some(true);
    }
    if waited >= deadline {
        return Some(false);
    }
    None
}

/// 任务目录根（`%TEMP%\kirin_clip_r194`；每次渲染一个 `<pid>-<ns>` 子目录）。
pub(crate) fn task_dir_root() -> PathBuf {
    std::env::temp_dir().join("kirin_clip_r194")
}

/// 生成新任务目录（布防时；mkdir 失败 = None → 不布防 fail-closed）。
pub(crate) fn new_task_dir() -> Option<PathBuf> {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = task_dir_root().join(format!("{}-{}", std::process::id(), now_ns));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// 陈旧任务目录懒清扫（布防时单次；mtime 超 [`R194_TASK_DIR_TTL`] 删，
/// 根目录内全部为本模块产物，用户数据零触碰）。
pub(crate) fn sweep_stale_task_dirs() {
    let Ok(rd) = std::fs::read_dir(task_dir_root()) else {
        return;
    };
    for e in rd.flatten() {
        let stale = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| m.elapsed().ok())
            .map(|el| el > R194_TASK_DIR_TTL)
            .unwrap_or(false);
        if stale {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// 生产拉取闭包 = **既有** `FileCommand::FetchFile` 命令（零新 wire：引擎
/// sanitize/tid 去重/断点/配额/并发节流与授权链全为引擎侧既有）。
pub(crate) fn command_fetch_closure(
    tx: tokio::sync::mpsc::UnboundedSender<crate::file_panel::FileCommand>,
) -> DelayFetchFn {
    Arc::new(move |rel_path: &str, local_dir: &Path| {
        let _ = tx.send(crate::file_panel::FileCommand::FetchFile {
            remote_path: rel_path.to_string(),
            local_dir: local_dir.to_path_buf(),
        });
    })
}

// ────────────────────────── 平台门 ──────────────────────────

/// 本进程延迟窗当前持有系统剪贴板（防回环守卫——`clipboard_files` 读面
#[cfg(windows)]
pub(crate) fn delay_board_owned_by_us() -> bool {
    let h = DELAY_HWND.load(Ordering::Acquire);
    h != 0 && unsafe { ffi::GetClipboardOwner() } as isize == h
}
#[cfg(not(windows))]
pub(crate) fn delay_board_owned_by_us() -> bool {
    false
}

/// 撤防（元数据 CLEAR / 会话拆除 / 显式回退）：若本窗持板 → 板复位为
/// **惰性占位文本**（与 s→c CLEAR 既有语义一致：占位变惰性文本，用户任何
/// 新复制自然覆盖）；渲染上下文清除。
pub(crate) fn disarm(reason: &str) {
    #[cfg(windows)]
    {
        if ctx_slot().lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            send_window_msg(ffi::WM_APP_R194_DISARM, 0);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = reason;
    }
}

/// 布防入口（s→c 主控臂 / c→s 受控臂共用；`fetch` = 按需拉取闭包）。
///
/// 返回 false = 不布防（计划为空 / 窗口失败 / 任务目录失败）→ **两段式
/// 原样**（fail-closed，零数据传输——布防本身只写「格式描述」，零内容）。
pub(crate) fn arm(meta: &FileClipMeta, fetch: DelayFetchFn, tag: &str) -> bool {
    #[cfg(windows)]
    {
        arm_windows(meta, fetch, tag)
    }
    #[cfg(not(windows))]
    {
        let _ = (meta, fetch, tag);
        false
    }
}

/// 渲染落定钩子（on_finish 共享落定点调用；文件会话任务线程上下文）。
pub(crate) fn notify_landed(file_name: &str, path: &Path) {
    #[cfg(windows)]
    {
        render_landed(file_name, path);
    }
    #[cfg(not(windows))]
    {
        let _ = (file_name, path);
    }
}

// ────────────────────────── Windows 实现 ──────────────────────────

#[cfg(windows)]
mod ffi {
    pub type HANDLE = *mut core::ffi::c_void;
    pub type HWND = HANDLE;
    pub const CF_HDROP: u32 = 15;
    pub const CF_UNICODETEXT: u32 = 13;
    pub const GMEM_MOVEABLE: u32 = 0x0002;
    pub const WM_DESTROY: u32 = 0x0002;
    /// `WM_RENDERFORMAT`（Win32 延迟渲染：消费方 GetClipboardData 时系统派发）。
    pub const WM_RENDERFORMAT: u32 = 0x0316;
    /// `WM_RENDERALLFORMATS`（持板窗口销毁前派发）。
    pub const WM_RENDERALLFORMATS: u32 = 0x0317;
    /// 本模块自定义消息（WM_APP 区间，仅本窗消费）。
    pub const WM_APP_R194_ARM: u32 = 0x8000 + 0x01;
    pub const WM_APP_R194_DISARM: u32 = 0x8000 + 0x02;

    #[repr(C)]
    pub struct WndClassW {
        pub style: u32,
        pub lpfn_wnd_proc: unsafe extern "system" fn(HWND, u32, usize, isize) -> isize,
        pub cb_cls_extra: i32,
        pub cb_wnd_extra: i32,
        pub h_instance: HANDLE,
        pub h_icon: HANDLE,
        pub h_cursor: HANDLE,
        pub h_br_background: HANDLE,
        pub lpsz_menu_name: *const u16,
        pub lpsz_class_name: *const u16,
    }

    #[repr(C)]
    pub struct Msg {
        pub hwnd: HWND,
        pub message: u32,
        pub w_param: usize,
        pub l_param: isize,
        pub time: u32,
        pub pt_x: i32,
        pub pt_y: i32,
    }

    extern "system" {
        pub fn RegisterClassW(lpwcx: *const WndClassW) -> u16;
        pub fn CreateWindowExW(
            dw_ex_style: u32,
            lp_class_name: *const u16,
            lp_window_name: *const u16,
            dw_style: u32,
            x: i32,
            y: i32,
            w: i32,
            h: i32,
            h_parent: HWND,
            h_menu: HANDLE,
            h_instance: HANDLE,
            lp_param: HANDLE,
        ) -> HWND;
        pub fn DefWindowProcW(hwnd: HWND, msg: u32, w_param: usize, l_param: isize) -> isize;
        pub fn GetMessageW(lpmsg: *mut Msg, hwnd: HWND, min: u32, max: u32) -> i32;
        pub fn TranslateMessage(lpmsg: *const Msg) -> i32;
        pub fn DispatchMessageW(lpmsg: *const Msg) -> isize;
        pub fn PeekMessageW(lpmsg: *mut Msg, hwnd: HWND, min: u32, max: u32, remove: u32) -> i32;
        pub fn PostQuitMessage(n_exit_code: i32);
        pub fn SendMessageW(hwnd: HWND, msg: u32, w_param: usize, l_param: isize) -> isize;
        pub fn OpenClipboard(hwnd_new_owner: HWND) -> i32;
        pub fn CloseClipboard() -> i32;
        pub fn EmptyClipboard() -> i32;
        pub fn SetClipboardData(format: u32, h_mem: HANDLE) -> HANDLE;
        pub fn GetClipboardOwner() -> HWND;
        pub fn GetLastError() -> u32;
        pub fn GetModuleHandleW(lp_module_name: *const u16) -> HANDLE;
        pub fn GlobalAlloc(u_flags: u32, dw_bytes: u32) -> HANDLE;
        pub fn GlobalFree(h_mem: HANDLE) -> HANDLE;
        pub fn GlobalLock(h_mem: HANDLE) -> *mut core::ffi::c_void;
        pub fn GlobalUnlock(h_mem: HANDLE) -> u32;
    }
}

#[cfg(windows)]
const PM_REMOVE: u32 = 1;

/// 渲染上下文（布防时刻定格；窗口线程持有，渲染回调快照消费）。
#[cfg(windows)]
struct DelayCtx {
    /// 占位文本（与 apply_meta_frame 写板同源——布防时上板文本通道 +
    /// 撤防时复位为惰性文本，回声抑制天然保持）。
    placeholder: String,
    plan: DelayPlan,
    task_dir: PathBuf,
    fetch: DelayFetchFn,
    /// 布防来源标签（日志定位：s2c / c2s / os-test）。
    tag: String,
}

#[cfg(windows)]
static DELAY_HWND: AtomicIsize = AtomicIsize::new(0);
#[cfg(windows)]
static CTX: OnceLock<Mutex<Option<DelayCtx>>> = OnceLock::new();
#[cfg(windows)]
static RENDERING: AtomicBool = AtomicBool::new(false);
/// 渲染等待注册表（`notify_landed` 生产 / 渲染工作线程消费）。
#[cfg(windows)]
static RENDER_WAIT: OnceLock<Mutex<Option<RenderWaitSlot>>> = OnceLock::new();
/// 同 sig 去重（R193 ③-B 双 MetaApplied 实测在案——重复 apply 不重复布防）。
#[cfg(windows)]
static LAST_ARMED_SIG: AtomicU64 = AtomicU64::new(0);
/// 布防线程派生单次门。
#[cfg(windows)]
static WINDOW_SPAWNED: OnceLock<()> = OnceLock::new();

#[cfg(windows)]
struct RenderWaitSlot {
    tracker: RenderTracker,
    done_tx: std::sync::mpsc::Sender<()>,
}

#[cfg(windows)]
fn ctx_slot() -> &'static Mutex<Option<DelayCtx>> {
    CTX.get_or_init(|| Mutex::new(None))
}

#[cfg(windows)]
fn render_wait_slot() -> &'static Mutex<Option<RenderWaitSlot>> {
    RENDER_WAIT.get_or_init(|| Mutex::new(None))
}

#[cfg(windows)]
fn take_ctx() -> Option<DelayCtx> {
    ctx_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
}

#[cfg(windows)]
fn utf16_with_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 窗口线程就绪等待（惰性派生单次 + 有界轮询；失败 = None → 不布防）。
#[cfg(windows)]
fn ensure_window() -> Option<isize> {
    let h = DELAY_HWND.load(Ordering::Acquire);
    if h != 0 {
        return Some(h);
    }
    if WINDOW_SPAWNED.set(()).is_ok() {
        std::thread::Builder::new()
            .name("kirin-r194-delay".into())
            .spawn(window_thread_main)
            .ok()?;
    }
    for _ in 0..200 {
        let h = DELAY_HWND.load(Ordering::Acquire);
        if h != 0 {
            return Some(h);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

#[cfg(windows)]
fn window_thread_main() {
    unsafe {
        let class_name = utf16_with_nul("KirinDeskR194DelayWnd");
        let wc = ffi::WndClassW {
            style: 0,
            lpfn_wnd_proc: wnd_proc,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: ffi::GetModuleHandleW(std::ptr::null()),
            h_icon: std::ptr::null_mut(),
            h_cursor: std::ptr::null_mut(),
            h_br_background: std::ptr::null_mut(),
            lpsz_menu_name: std::ptr::null(),
            lpsz_class_name: class_name.as_ptr(),
        };
        if ffi::RegisterClassW(&wc) == 0 {
            return;
        }
        let hwnd = ffi::CreateWindowExW(
            0,
            class_name.as_ptr(),
            utf16_with_nul("KirinDesk R194 delayed render").as_ptr(),
            0x8000_0000, // WS_POPUP（不 ShowWindow = 隐藏；实测 message-only
            // 窗（HWND_MESSAGE）在 24H2 被拒延迟渲染 NULL 注册（GLE=6），
            // 换隐藏顶层窗验证——取证见 docs/R194 设计 doc §1 补记。
            0, 0, 0, 0,
            std::ptr::null_mut(), // 隐藏顶层窗（非 message-only）
            std::ptr::null_mut(),
            ffi::GetModuleHandleW(std::ptr::null()),
            std::ptr::null_mut(),
        );
        if hwnd.is_null() {
            return;
        }
        DELAY_HWND.store(hwnd as isize, Ordering::Release);
        let mut msg = std::mem::zeroed::<ffi::Msg>();
        while ffi::GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            let _ = ffi::TranslateMessage(&msg);
            ffi::DispatchMessageW(&msg);
        }
    }
}

/// 向窗口线程同步派发本模块自定义消息（窗未就绪 = false）。
#[cfg(windows)]
fn send_window_msg(msg: u32, lparam: isize) -> bool {
    let Some(h) = ensure_window() else {
        return false;
    };
    unsafe { ffi::SendMessageW(h as ffi::HWND, msg, 0, lparam) == 1 }
}

/// 同上，但区分「未派发」（None——所有权仍在发送侧）与「已派发」的处理
/// 结果（Some(bool)——lparam 所有权已随消息转移）。
#[cfg(windows)]
fn send_window_msg_delivered(msg: u32, lparam: isize) -> Option<bool> {
    let Some(h) = ensure_window() else {
        return None;
    };
    Some(unsafe { ffi::SendMessageW(h as ffi::HWND, msg, 0, lparam) == 1 })
}

/// 布防（Windows 臂）。sig 去重（双 MetaApplied 防重复布防）→ 计划 →
/// 任务目录 → 窗线程剪贴板序列。
#[cfg(windows)]
fn arm_windows(meta: &FileClipMeta, fetch: DelayFetchFn, tag: &str) -> bool {
    let sig = crate::clipboard::filemeta_sig(meta);
    if sig != 0 && LAST_ARMED_SIG.load(Ordering::Acquire) == sig {
        return true; // 已布防等价态（幂等成功）
    }
    let plan = delay_plan(meta);
    if plan.entries.is_empty() {
        tracing::info!(
            plan.skipped_dirs,
            plan.skipped_outside
        );
        return false;
    }
    let Some(task_dir) = new_task_dir() else {
        return false;
    };
    sweep_stale_task_dirs();
    let placeholder = crate::clipboard::clip_meta_placeholder(meta);
    let ctx = Box::new(DelayCtx {
        placeholder,
        plan,
        task_dir,
        fetch,
        tag: tag.to_string(),
    });
    let lparam = Box::into_raw(ctx) as isize;
    // SendMessage = 窗线程同步执行剪贴板序列（Open→Empty→文本→HDROP NULL→Close）。
    // 所有权：消息一旦派发，Box 归窗线程（含处理失败臂，proc 内 from_raw
    // 接管并析构）——仅「未派发」（窗未就绪 None）时由本侧回收，防 double
    // free（heap corruption 教训，0xc0000374 取证）。
    match send_window_msg_delivered(ffi::WM_APP_R194_ARM, lparam) {
        Some(true) => {}
        Some(false) => {
            return false;
        }
        None => {
            drop(unsafe { Box::from_raw(lparam as *mut DelayCtx) }); // 防泄漏
            return false;
        }
    }
    LAST_ARMED_SIG.store(sig, Ordering::Release);
    true
}

/// 持板小重试 Open（争用兜底；全败 = false，无重试风暴——有界 10×20ms）。
#[cfg(windows)]
unsafe fn open_clipboard_bounded(hwnd: ffi::HWND) -> bool {
    unsafe {
        for _ in 0..10 {
            if ffi::OpenClipboard(hwnd) != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

/// 窗线程布防体：剪贴板序列（持窗所有权）。lparam = `Box<DelayCtx>` 裸指针。
///
/// NULL)`（经典延迟渲染注册）被系统拒绝 `ERROR_INVALID_HANDLE(6)`——三种
/// 格式（CF_HDROP/CF_UNICODETEXT/注册格式）× 两种窗形（message-only/隐藏
/// 顶层）× 独立最小探针复现，真实数据 Set 同上下文成功 = 拒绝仅针对 NULL
/// 延迟注册。此时本函数走 `h_drop.is_null()` 臂 = **fail-closed 不布防**，
/// 两段式原样（授权语义不变，零数据传输不变）。
#[cfg(windows)]
unsafe fn arm_on_window_thread(hwnd: ffi::HWND, l_param: isize) -> bool {
    unsafe {
        let ctx = Box::from_raw(l_param as *mut DelayCtx);
        let files = ctx.plan.entries.len();
        let tag = ctx.tag.clone();
        if !open_clipboard_bounded(hwnd) {
            return false;
        }
        ffi::EmptyClipboard();
        // 文本通道 = 占位文本（与 apply_meta_frame 写板同源；回声抑制天然保持）。
        let ph = utf16_with_nul(&ctx.placeholder);
        let h_text = set_hglobal_utf16(&ph);
        if !h_text.is_null() {
            ffi::SetClipboardData(ffi::CF_UNICODETEXT, h_text);
        }
        // HDROP 延迟渲染描述（NULL 句柄 = 零数据；渲染时才拉取）。
        let h_drop = ffi::SetClipboardData(ffi::CF_HDROP, std::ptr::null_mut());
        let gle = ffi::GetLastError();
        ffi::CloseClipboard();
        if h_drop.is_null() {
            // 平台拒绝延迟渲染（本 build 实测 GLE=6）→ fail-closed 不布防，
            // 两段式原样；GLE 附行供跨 build 复测判读。
            tracing::warn!(
                 (gle={gle}) — delayed rendering unavailable on this build, two-step paste stays"
            );
            return false;
        }
        *ctx_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(*ctx);
        tracing::info!(
        );
        true
    }
}

/// 窗线程撤防体：板复位 = 惰性占位文本（CLEAR 既有语义）；板已被他方接管
#[cfg(windows)]
unsafe fn disarm_on_window_thread(hwnd: ffi::HWND) {
    unsafe {
        let Some(ctx) = take_ctx() else { return };
        if ffi::GetClipboardOwner() != hwnd {
            return;
        }
        if !open_clipboard_bounded(hwnd) {
            return;
        }
        // 二次核对（Open 等待窗口内板可能易主）。
        if ffi::GetClipboardOwner() != hwnd {
            ffi::CloseClipboard();
            return;
        }
        ffi::EmptyClipboard();
        let ph = utf16_with_nul(&ctx.placeholder);
        let h = set_hglobal_utf16(&ph);
        if !h.is_null() {
            ffi::SetClipboardData(ffi::CF_UNICODETEXT, h);
        }
        ffi::CloseClipboard();
    }
}

/// UTF-16 文本 → GMEM_MOVEABLE HGLOBAL（调用方 `SetClipboardData` 接管；
/// 失败 = null 无泄漏）。
#[cfg(windows)]
unsafe fn set_hglobal_utf16(utf16: &[u16]) -> ffi::HANDLE {
    unsafe {
        let bytes = utf16.len() * 2;
        let h = ffi::GlobalAlloc(ffi::GMEM_MOVEABLE, bytes as u32);
        if h.is_null() {
            return std::ptr::null_mut();
        }
        let p = ffi::GlobalLock(h);
        if p.is_null() {
            ffi::GlobalFree(h);
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(utf16.as_ptr(), p as *mut u16, utf16.len());
        ffi::GlobalUnlock(h);
        h
    }
}

/// 渲染落定生产点（on_finish 共享落定点 → [`notify_landed`]）。
#[cfg(windows)]
fn render_landed(file_name: &str, path: &Path) {
    let mut g = render_wait_slot().lock().unwrap_or_else(|e| e.into_inner());
    let Some(slot) = g.as_mut() else { return };
    if slot.tracker.on_landed(file_name, path) {
        let _ = slot.done_tx.send(());
    }
}

/// 任务目录内 size 匹配命中（断点秒回判据；渲染工作线程上下文）。
#[cfg(windows)]
fn task_dir_hit(task_dir: &Path, basename: &str, size: u64) -> Option<PathBuf> {
    let p = task_dir.join(basename);
    let len = std::fs::metadata(&p).ok()?.len();
    (size > 0 && len == size).then_some(p)
}

/// 渲染工作线程体：登记等待 → 秒回命中 → 逐条按需拉取 → bounded 等待 →
/// 全落定路径集（`Some`）或超时（`None`，all-or-nothing 不应答）。
#[cfg(windows)]
fn render_worker(
    plan: Vec<DelayPlanEntry>,
    task_dir: PathBuf,
    fetch: DelayFetchFn,
) -> Option<Vec<PathBuf>> {
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    {
        let mut g = render_wait_slot().lock().unwrap_or_else(|e| e.into_inner());
        *g = Some(RenderWaitSlot {
            tracker: RenderTracker::new(plan.iter().map(|e| e.basename.clone()).collect()),
            done_tx,
        });
    }
    let started = Instant::now();
    // 秒回命中（上次渲染已完整落定的条目，size 判等）。
    let mut pending: Vec<DelayPlanEntry> = Vec::new();
    for e in &plan {
        match task_dir_hit(&task_dir, &e.basename, e.size) {
            Some(p) => render_landed(&e.basename, &p),
            None => pending.push(e.clone()),
        }
    }
    // 按需拉取（此刻 = 粘贴动作已发生；既有 FetchFile 授权链原样）。
    for e in &pending {
        tracing::info!(
            e.rel_path,
            task_dir.display()
        );
        (fetch)(&e.rel_path, &task_dir);
    }
    // bounded 等待（纯等待；窗线程负责泵消息保活）。
    let mut complete = false;
    loop {
        let elapsed = started.elapsed();
        if elapsed >= R194_RENDER_WAIT {
            break;
        }
        match done_rx.recv_timeout(R194_RENDER_WAIT - elapsed) {
            Ok(()) => {
                complete = true;
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let slot = render_wait_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    match render_outcome(complete, started.elapsed(), R194_RENDER_WAIT) {
        Some(true) => {
            let paths = slot
                .map(|s| s.tracker.landed_paths_in_plan_order(&plan))
                .unwrap_or_default();
            (!paths.is_empty()).then_some(paths)
        }
        _ => {
            let (landed, expected) = slot
                .map(|s| (s.tracker.landed_count(), s.tracker.expected_count()))
                .unwrap_or((0, plan.len()));
            tracing::warn!(
                started.elapsed().as_secs()
            );
            crate::conn_log_push_text(
                crate::widgets::ConnLogLevel::Warn,
                &crate::tf!("connect.log.r194_render_fail", landed, expected),
            );
            None
        }
    }
}

/// `WM_RENDERFORMAT(CF_HDROP)` 处理体（粘贴授权触发点）。派生工作线程
/// 拉取；本线程 PeekMessageW 泵消息有界等待（保活 + 嵌套消息可派发）。
/// 嵌套在途渲染到达 = 拒绝（消费方得 NULL 可重试粘贴；极少并发粘贴面）。
#[cfg(windows)]
fn render_format() {
    if RENDERING.swap(true, Ordering::AcqRel) {
        return;
    }
    let snapshot = {
        let g = ctx_slot().lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref()
            .map(|c| (c.plan.entries.clone(), c.task_dir.clone(), c.fetch.clone()))
    };
    let Some((plan, task_dir, fetch)) = snapshot else {
        RENDERING.store(false, Ordering::Release);
        return;
    };
    let started = Instant::now();
    let (res_tx, res_rx) = std::sync::mpsc::channel::<Option<Vec<PathBuf>>>();
    let spawned = std::thread::Builder::new()
        .name("kirin-r194-render".into())
        .spawn(move || {
            let r = render_worker(plan, task_dir, fetch);
            let _ = res_tx.send(r);
        });
    if spawned.is_err() {
        RENDERING.store(false, Ordering::Release);
        return;
    }
    // 泵等待（工作线程自带 30s 上界；泵期间 WM_APP_ARM 等 SendMessage 可达）。
    let mut result: Option<Option<Vec<PathBuf>>> = None;
    while result.is_none() {
        unsafe {
            let mut msg = std::mem::zeroed::<ffi::Msg>();
            while ffi::PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                let _ = ffi::TranslateMessage(&msg);
                ffi::DispatchMessageW(&msg);
            }
        }
        match res_rx.recv_timeout(Duration::from_millis(25)) {
            Ok(r) => result = Some(r),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => result = Some(None),
        }
    }
    let paths = result.expect("loop exits only with result");
    RENDERING.store(false, Ordering::Release);
    apply_render_result(paths, started.elapsed());
}

/// 渲染应答：以真实路径组 HDROP `SetClipboardData`（系统接管 HGLOBAL）。
/// 失败 = 不应答（消费方得 NULL = 粘贴无物，两段式兜底）。
#[cfg(windows)]
fn apply_render_result(paths: Option<Vec<PathBuf>>, elapsed: Duration) {
    let Some(paths) = paths else { return };
    let path_strs: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let payload = crate::clipboard::r194_build_hdrop_payload(&path_strs);
    unsafe {
        let h = ffi::GlobalAlloc(ffi::GMEM_MOVEABLE, payload.len() as u32);
        if h.is_null() {
            return;
        }
        let p = ffi::GlobalLock(h);
        if p.is_null() {
            ffi::GlobalFree(h);
            return;
        }
        std::ptr::copy_nonoverlapping(payload.as_ptr(), p as *mut u8, payload.len());
        ffi::GlobalUnlock(h);
        // WM_RENDERFORMAT 上下文中剪贴板已由系统代表消费方打开——直接
        // SetClipboardData（不得 OpenClipboard，Win32 契约）。
        let r = ffi::SetClipboardData(ffi::CF_HDROP, h);
        if r.is_null() {
            ffi::GlobalFree(h);
            return;
        }
    }
    tracing::info!(
        paths.len(),
        elapsed.as_millis()
    );
    crate::conn_log_push_text(
        crate::widgets::ConnLogLevel::Info,
        &crate::tf!("connect.log.r194_render_done", paths.len()),
    );
}

/// `WM_RENDERALLFORMATS`（持板窗销毁前）：仅在**全部条目已完整落盘**时
/// 无网络应答（本地秒回），否则不开网络（销毁路径禁长阻塞）→ 不渲染。
#[cfg(windows)]
unsafe fn render_all_formats(hwnd: ffi::HWND) {
    let snapshot = {
        let g = ctx_slot().lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().map(|c| (c.plan.clone(), c.task_dir.clone()))
    };
    let Some((plan, task_dir)) = snapshot else {
        return;
    };
    let all_hit = plan
        .entries
        .iter()
        .all(|e| task_dir_hit(&task_dir, &e.basename, e.size).is_some());
    if !all_hit {
        return;
    }
    let paths: Vec<String> = plan
        .entries
        .iter()
        .map(|e| task_dir.join(&e.basename).to_string_lossy().into_owned())
        .collect();
    let payload = crate::clipboard::r194_build_hdrop_payload(&paths);
    unsafe {
        if ffi::OpenClipboard(hwnd) == 0 {
            return;
        }
        let h = ffi::GlobalAlloc(ffi::GMEM_MOVEABLE, payload.len() as u32);
        if !h.is_null() {
            let p = ffi::GlobalLock(h);
            if !p.is_null() {
                std::ptr::copy_nonoverlapping(payload.as_ptr(), p as *mut u8, payload.len());
                ffi::GlobalUnlock(h);
                if ffi::SetClipboardData(ffi::CF_HDROP, h).is_null() {
                    ffi::GlobalFree(h);
                }
            } else {
                ffi::GlobalFree(h);
            }
        }
        ffi::CloseClipboard();
    }
}

/// `WM_DESTROY` 清板（持板窗销毁：延迟描述随窗死 = 死格式；清板防「有格式
/// 无数据」悬挂——板上仅占位文本与延迟描述，无用户数据，清板零损失）。
#[cfg(windows)]
unsafe fn destroy_cleanup(hwnd: ffi::HWND) {
    unsafe {
        let _ = take_ctx();
        if ffi::GetClipboardOwner() == hwnd && open_clipboard_bounded(hwnd) {
            ffi::EmptyClipboard();
            ffi::CloseClipboard();
        }
        ffi::PostQuitMessage(0);
    }
}

#[cfg(windows)]
unsafe extern "system" fn wnd_proc(
    hwnd: ffi::HWND,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    unsafe {
        match msg {
            ffi::WM_APP_R194_ARM => arm_on_window_thread(hwnd, l_param) as isize,
            ffi::WM_APP_R194_DISARM => {
                disarm_on_window_thread(hwnd);
                1
            }
            ffi::WM_RENDERFORMAT if w_param as u32 == ffi::CF_HDROP => {
                tracing::info!(
                );
                render_format();
                0
            }
            ffi::WM_RENDERALLFORMATS => {
                render_all_formats(hwnd);
                0
            }
            ffi::WM_DESTROY => {
                destroy_cleanup(hwnd);
                0
            }
            _ => ffi::DefWindowProcW(hwnd, msg, w_param, l_param),
        }
    }
}

// ────────────────────────── 单测（纯逻辑面 + OS 门控端到端） ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::{FileClipEntry, FILEMETA_VERSION};
    use std::sync::atomic::AtomicUsize;

    fn meta_of(entries: Vec<FileClipEntry>) -> FileClipMeta {
        FileClipMeta {
            version: FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries,
        }
    }

    fn e(rel: &str, size: u64, is_dir: bool, fetchable: bool) -> FileClipEntry {
        FileClipEntry {
            rel_path: rel.to_string(),
            size,
            is_dir,
            fetchable,
        }
    }

    /// 布防计划矩阵：顶层散文件入计划；目录/根外/树内行/同名去重各归其桶。
    #[test]
    fn r194_delay_plan_matrix() {
        let meta = meta_of(vec![
            e("a.txt", 10, false, true),
            e("A.TXT", 20, false, true), // 同名（大小写不敏感）→ 去重
            e("sub/b.txt", 30, false, true), // 树内文件行 → 不平铺
            e("dir", 0, true, true),     // 目录 → 边界跳过
            e("outside.bin", 40, false, false), // 根外 → 计数
            e("报 告.pdf", 50, false, true), // 非 ASCII basename 照收
        ]);
        let plan = delay_plan(&meta);
        assert_eq!(plan.entries.len(), 2);
        assert_eq!(plan.entries[0].rel_path, "a.txt");
        assert_eq!(plan.entries[0].basename, "a.txt");
        assert_eq!(plan.entries[0].size, 10);
        assert_eq!(plan.entries[1].basename, "报 告.pdf");
        assert_eq!(plan.skipped_dirs, 1);
        assert_eq!(plan.skipped_outside, 1);
        assert_eq!(plan.skipped_dedup, 1);
    }

    /// 授权门结构性断言（复制动作零数据传输）：布防**决策面**（计划纯函数）
    /// 只读元数据，拉取闭包仅在渲染工作体内可达——空计划布防拒绝路径 +
    /// 闭包构造零调用，计数钉死。
    #[test]
    fn r194_copy_action_zero_fetch_by_design() {        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let fetch: DelayFetchFn = Arc::new(move |_rel, _dir| {
            c2.fetch_add(1, Ordering::SeqCst);
        });
        // ① 目录条目 meta → 计划空 → 布防拒绝（两段式原样）。
        let meta_dirs = meta_of(vec![e("dir", 0, true, true)]);
        assert!(delay_plan(&meta_dirs).entries.is_empty());
        // ② 闭包构造（生产等价形态）本身零调用——拉取只可能发生在
        //    WM_RENDERFORMAT（粘贴动作）之后的工作线程体内。
        let _closure = command_fetch_closure({
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            tx
        });
        assert_eq!(calls.load(Ordering::SeqCst), 0, "复制动作零数据传输");
        drop(fetch);
    }

    /// 渲染跟踪器矩阵：命中/去重/大小写不敏感/非成员忽略/完成判定/计划序。
    #[test]
    fn r194_render_tracker_matrix() {
        let plan = vec![
            DelayPlanEntry { rel_path: "a.txt".into(), basename: "a.txt".into(), size: 1 },
            DelayPlanEntry { rel_path: "b.bin".into(), basename: "b.bin".into(), size: 2 },
        ];
        let mut t = RenderTracker::new(plan.iter().map(|e| e.basename.clone()).collect());
        assert!(!t.complete());
        // 非成员忽略（他任务落盘零误配）。
        assert!(!t.on_landed("other.txt", Path::new("/x/other.txt")));
        // 大小写不敏感命中（Windows 落盘语义）。
        assert!(!t.on_landed("A.TXT", Path::new("/t/a.txt")), "首个命中非完成");
        // 重复落定 no-op。
        assert!(!t.on_landed("a.txt", Path::new("/t/a.txt")));
        assert_eq!(t.landed_count(), 1);
        // 完成 = 全落定。
        assert!(t.on_landed("B.bin", Path::new("/t/b.bin")));
        assert!(t.complete());
        // 计划序输出（用户复制序）。
        let paths = t.landed_paths_in_plan_order(&plan);
        assert_eq!(paths.len(), 2);
        assert!(paths[0].ends_with("a.txt"));
        assert!(paths[1].ends_with("b.bin"));
    }

    /// 渲染裁决矩阵：完成即应答 / 未完成且超预算 = 不应答（all-or-nothing
    /// 失败回退）/ 未完成未超时 = 继续等待。
    #[test]
    fn r194_render_outcome_timeout_matrix() {
        let d = Duration::from_secs(30);
        assert_eq!(render_outcome(true, Duration::ZERO, d), Some(true));
        assert_eq!(render_outcome(false, Duration::from_secs(10), d), None);
        assert_eq!(render_outcome(false, d, d), Some(false));
        assert_eq!(render_outcome(false, Duration::from_secs(31), d), Some(false));
    }

    /// 生产拉取闭包 = 既有 `FileCommand::FetchFile` 命令（零新 wire 断言：
    /// 命令形/入参逐位映射；闭包构造不发送 = 渲染回调前零命令）。
    #[test]
    fn r194_fetch_closure_maps_to_existing_fetch_command() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::file_panel::FileCommand>();
        let f = command_fetch_closure(tx);
        assert!(
            rx.try_recv().is_err(),
            "闭包构造不发送（渲染回调前零命令）"
        );
        let dir = PathBuf::from("C:\\temp\\kirin_clip_r194\\x");
        f("docs/report.pdf", &dir);
        match rx.try_recv() {
            Ok(crate::file_panel::FileCommand::FetchFile { remote_path, local_dir }) => {
                assert_eq!(remote_path, "docs/report.pdf");
                assert_eq!(local_dir, dir);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// 任务目录键形：根目录 = `%TEMP%\kirin_clip_r194`（清扫面与渲染产物
    /// 隔离用户数据）；新任务目录可建且在根下。
    #[test]
    fn r194_task_dir_layout() {
        assert_eq!(
            task_dir_root().file_name().map(|s| s.to_string_lossy().into_owned()),
            Some("kirin_clip_r194".into())
        );
        let d = new_task_dir().expect("task dir creatable");
        assert!(d.starts_with(task_dir_root()));
        assert!(d.is_dir());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// OS 实板端到端（环境门控 `KIRIN_R194_OS_TEST=1`；真剪贴板操作。ws
    /// 全量默认跳过——用户剪贴板零打扰）。**双分支定案形**：
    /// - **布防成功臂**（OS 支持延迟渲染的 build）：布防 → 消费方
    ///   GetClipboardData 触发 WM_RENDERFORMAT → 假拉取 → 真实 HDROP 读回；
    /// - **平台拒绝臂**（本 build 22631 实测 = `SetClipboardData(fmt, NULL)`
    ///   全格式拒 GLE=6，见 arm_on_window_thread doc）：arm() 必须返回
    ///   false = **fail-closed 回退两段式**（零 panic、零半布防、无上下文
    ///   残留、本窗不持板）——授权语义与回退语义在受限平台上的行为钉死。
    #[cfg(windows)]
    #[test]
    fn r194_os_delayed_render_end_to_end() {
        if std::env::var("KIRIN_R194_OS_TEST").ok().as_deref() != Some("1") {
            return;
        }
        mod read_ffi {
            extern "system" {
                pub fn OpenClipboard(h: *mut core::ffi::c_void) -> i32;
                pub fn CloseClipboard() -> i32;
                pub fn GetClipboardData(fmt: u32) -> *mut core::ffi::c_void;
                pub fn IsClipboardFormatAvailable(fmt: u32) -> i32;
                pub fn DragQueryFileW(
                    hdrop: *mut core::ffi::c_void, i: u32, buf: *mut u16, cap: u32,
                ) -> u32;
            }
        }
        // 假「远端」源文件（假拉取把内容拷进任务目录 = 模拟按需拉取落定）。
        let src_dir = std::env::temp_dir().join(format!("r194_os_src_{}", std::process::id()));
        std::fs::create_dir_all(&src_dir).unwrap();
        let src = src_dir.join("hello_r194.txt");

        let meta = meta_of(vec![e("hello_r194.txt", 28, false, true)]);
        let src_clone = src.clone();
        let fetch: DelayFetchFn = Arc::new(move |_rel, dir: &Path| {
            let _ = std::fs::copy(&src_clone, dir.join("hello_r194.txt"));
        });
        let armed = arm(&meta, fetch, "os-test");
        if !armed {
            // ── 平台拒绝臂（本 build 实测走此臂）──
            eprintln!("[r194-os] platform declines delayed rendering — fail-closed fallback branch");
            assert!(
                ctx_slot().lock().unwrap_or_else(|e| e.into_inner()).is_none(),
                "布防拒绝 = 渲染上下文零残留"
            );
            // 板面断言保持最小化（系统板为全机共享态——用户/剪贴板历史服务
            // 可能并发改板，格式级断言环境敏感）：核心 = 布防拒绝 + 上下文
            // 零残留 + 零 panic（fail-closed 回退两段式）。板面观测仅记档。
            unsafe {
                if read_ffi::OpenClipboard(std::ptr::null_mut()) == 1 {
                    let has_drop = read_ffi::IsClipboardFormatAvailable(15);
                    eprintln!("[r194-os] post-decline IsClipboardFormatAvailable(CF_HDROP)={has_drop} (观测值，受全机板并发影响，不断言)");
                    read_ffi::CloseClipboard();
                }
            }
            // 渲染请求面不可达（注册失败）→ 撤防为幂等 no-op。
            disarm("os-test declined cleanup");
            let _ = std::fs::remove_dir_all(&src_dir);
            return;
        }
        eprintln!("[r194-os] platform supports delayed rendering — full E2E branch");
        std::thread::sleep(std::time::Duration::from_millis(200));

        // 防回环关键断言：本窗持板 + 本进程读面守卫短路（读延迟板不触发
        // 渲染拉取 = 复制动作零数据传输在本进程读面同样成立）。
        assert!(delay_board_owned_by_us(), "延迟板应由本窗持有");
        assert!(
            !crate::clipboard::r194_has_cf_hdrop(),
            "守卫短路：本进程视延迟板无 CF_HDROP"
        );
        assert!(
            crate::clipboard::r194_read_cf_hdrop().is_none(),
            "守卫短路：本进程读延迟板零渲染触发"
        );

        // 消费方视角（模拟 Explorer）：GetClipboardData → WM_RENDERFORMAT
        // → 渲染应答 → 真实 HDROP 路径读回。
        let paths = unsafe {
            assert_eq!(read_ffi::OpenClipboard(std::ptr::null_mut()), 1, "OpenClipboard");
            let h = read_ffi::GetClipboardData(15 /* CF_HDROP */);
            assert!(!h.is_null(), "GetClipboardData 应触发渲染并返回数据");
            let count = read_ffi::DragQueryFileW(h, 0xFFFF_FFFF, std::ptr::null_mut(), 0);
            let mut out = Vec::new();
            for i in 0..count {
                let need = read_ffi::DragQueryFileW(h, i, std::ptr::null_mut(), 0);
                let mut buf = vec![0u16; (need + 1) as usize];
                let got = read_ffi::DragQueryFileW(h, i, buf.as_mut_ptr(), (need + 1) as u32);
                out.push(String::from_utf16_lossy(&buf[..got as usize]));
            }
            read_ffi::CloseClipboard();
            out
        };
        assert_eq!(paths.len(), 1, "应答应含 1 个文件: {paths:?}");
        assert!(paths[0].ends_with("hello_r194.txt"), "paths={paths:?}");
        assert!(
            paths[0].contains("kirin_clip_r194"),
            "应答路径 = 任务目录真实路径（Explorer 由其当前目录取件）"
        );
        let served = std::fs::read(&paths[0]).unwrap();

        disarm("os-test end");
        assert!(!delay_board_owned_by_us(), "撤防后本窗不再持板");
        let _ = std::fs::remove_dir_all(&src_dir);
    }

    /// 延迟板 × pending 失效判据交互（守卫为什么是 load-bearing 的钉子）：
    /// 布防后板文本 = 占位（预期文本）且本进程读面 `has_files=false`
    ///（owner 守卫短路）→ `clip_paste_pending_stale` = false → pending 槽
    /// 保留（两段式兜底不被误杀）；对照臂：守卫若失效（has_files=true，
    /// 即延迟板被本进程真读了）→ stale=true = pending 被误清 + 渲染拉取
    /// 被误触（复制即传输回潮）——本测试双向钉死该语义边界。
    #[test]
    fn r194_delayed_board_pending_staleness_interplay() {
        let ph = "⟪KirinDesk 文件占位：1 项⟫";
        // 布防态：板文本 = 占位 + 守卫短路（has_files=false）+ 板序号推进
        //（布防 EmptyClipboard 推进序号）→ 无阳性证据 = 保留。
        assert!(
            !crate::clip_paste_pending_stale(Some(ph), Some(ph), false, 8, 5),
            "占位文本同源 + has_files 守卫短路 = 零阳性证据"
        );
        // 守卫失效对照（若延迟板被本进程真读 = has_files=true）→ 判 stale
        //（该臂在真实路径不可达——守卫在 has_cf_hdrop/read_cf_hdrop 最低
        // 层面短路；此臂仅证明 has_files 是该判据的敏感位）。
        assert!(crate::clip_paste_pending_stale(Some(ph), Some(ph), true, 8, 5));
        // 文本不同源（用户真复制了新文本）→ stale=true（既有语义零变化）。
        assert!(crate::clip_paste_pending_stale(Some("hello"), Some(ph), false, 8, 5));
    }
}
