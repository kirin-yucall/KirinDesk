//! 被控端黑屏覆盖窗口（SRV-PRIV-011/016）与客户端隐私状态显示。
//!
//! # 黑屏覆盖（服务端）
//!
//! - 黑屏 = **应用内全屏纯黑 egui viewport** + 中央提示条。只绘制纯黑与提示文字，
//!   **不渲染任何真实屏幕内容**（PRIV-SEC-003）；捕获/编码/传输不受影响
//!   （红线：黑屏 ≠ 发送黑帧，见 `core/src/connection/privacy.rs`）。
//! - 覆盖窗口**不响应本地键鼠**（无任何可交互控件），仅支持本地逃生舱
//!   （SRV-PRIV-016）：**按住 Esc 3 秒** 或 **Ctrl+Alt+F9** → 本地退出黑屏。
//! - 显示状态由服务端 [`PrivacyController`]（core）驱动：UI 每帧轮询控制器
//!   `active_level == Black` → 显示；`!=` → 自动关闭——因此**断连恢复
//!   无需任何网络消息**（SRV-PRIV-014 安全红线）。
//!
//! # 客户端隐私状态（控制端）
//!
//! [`PrivacyAckState`] 为客户端接收 `PrivacyModeAck` 后的共享状态（徽标 /
//! 锁屏输入禁用 / toast 提示），见 `ui/src/lib.rs::client_privacy_state`。

use std::sync::Mutex;
use std::time::{Duration, Instant};

use egui::{Align2, FontId, Key, Rect, Vec2};
use kirin_desk_core::connection::privacy::PrivacyLevel;

/// 逃生舱：按住 Esc 的时长阈值（SRV-PRIV-016）。
pub const ESCAPE_ESC_HOLD: Duration = Duration::from_secs(3);
/// 逃生舱：Ctrl+Alt+F9 组合（SRV-PRIV-016）。
pub const ESCAPE_COMBO: (&str, &str, &str) = ("Ctrl", "Alt", "F9");

/// Esc 按住起始时刻（跨帧保持；松键即清）。
fn esc_hold_start() -> &'static Mutex<Option<Instant>> {
    static T: Mutex<Option<Instant>> = Mutex::new(None);
    &T
}

/// 黑屏覆盖渲染结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayOutcome {
    /// 覆盖窗口未显示（控制器无活跃黑屏）。
    Inactive,
    /// 覆盖窗口正在显示。
    Active,
    /// 本地逃生舱触发（本帧退出黑屏）。
    Escaped,
}

/// 服务端黑屏覆盖窗口（SRV-PRIV-011/016）：全屏纯黑 + 提示条 + 本地逃生舱。
///
/// 由 `KirinDeskApp::update()` 每帧调用；控制器无活跃黑屏时立即返回
/// （覆盖窗口随之关闭）。`Escaped` 时调用方应复位控制器状态并审计
/// （见 `ui/src/lib.rs` 调用点）。
pub fn show_black_overlay(ctx: &egui::Context) -> OverlayOutcome {
    // 读取服务端控制器：仅当 Black 活跃时绘制覆盖窗口。
    let active = overlay_required_from_slot();
    if !active {
        // 状态已退出 → 清逃生舱计时，覆盖窗口本帧不再渲染即自动关闭。
        *esc_hold_start().lock().unwrap() = None;
        note_overlay_in_place(false);
        return OverlayOutcome::Inactive;
    }

    let viewport_id = egui::ViewportId::from_hash_of("kirin_privacy_overlay");
    let mut escaped = false;
    ctx.show_viewport_immediate(
        viewport_id,
        egui::ViewportBuilder::default()
            .with_title("KirinDesk - Privacy")
            .with_fullscreen(true)
            .with_decorations(false)
            .with_taskbar(false)
            .with_always_on_top(),
        |ctx, _class| {
            // 黑屏覆盖：纯黑画布 + 提示条（PRIV-SEC-003：无任何真实内容）。
            // 逐位 == 迁移前字面量，纯黑安全语义不变）。
            super::theme::ensure_fonts(ctx);
            let pal = super::theme::TERMINAL_PALETTE;
            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(pal.privacy_bg))
                .show(ctx, |ui| {
                    let rect = Rect::from_center_size(
                        ui.max_rect().center(),
                        Vec2::new(ui.max_rect().width().min(560.0), 150.0),
                    );
                    let painter = ui.painter_at(rect);
                    // 提示条底板（深灰卡片，非纯黑以便辨识）。
                    painter.rect_filled(rect, 10.0, pal.privacy_card);
                    painter.text(
                        rect.center_top() + Vec2::new(0.0, 22.0),
                        Align2::CENTER_TOP,
                        "屏幕已被远程用户隐藏 - KirinDesk",
                        FontId::proportional(22.0),
                        pal.privacy_title,
                    );
                    painter.text(
                        rect.center() + Vec2::new(0.0, 52.0),
                        Align2::CENTER_CENTER,
                        "远程会话进行中：输入操作照常生效",
                        FontId::proportional(15.0),
                        pal.privacy_body,
                    );
                    // 逃生舱：Esc 按住计时 / Ctrl+Alt+F9 立即触发。
                    let (esc_down, combo) = ctx.input(|i| {
                        (
                            i.key_down(Key::Escape),
                            i.key_pressed(Key::F9) && i.modifiers.ctrl && i.modifiers.alt,
                        )
                    });
                    if combo {
                        escaped = true;
                    }
                    if esc_down {
                        let start = *esc_hold_start().lock().unwrap();
                        let elapsed = match start {
                            Some(t) => t.elapsed(),
                            None => {
                                *esc_hold_start().lock().unwrap() = Some(Instant::now());
                                Duration::ZERO
                            }
                        };
                        if elapsed >= ESCAPE_ESC_HOLD {
                            escaped = true;
                        }
                        // 倒计时提示（仅剩 2 秒内显示倒计时）。
                        let remain = ESCAPE_ESC_HOLD.saturating_sub(elapsed);
                        if remain < Duration::from_secs(2) {
                            painter.text(
                                rect.center() + Vec2::new(0.0, 84.0),
                                Align2::CENTER_CENTER,
                                format!(
                                    "本地恢复：松开再按住 {} 秒（或 {}+{}+{}）",
                                    remain.as_secs() + 1,
                                    ESCAPE_COMBO.0,
                                    ESCAPE_COMBO.1,
                                    ESCAPE_COMBO.2
                                ),
                                FontId::proportional(13.0),
                                pal.privacy_hint,
                            );
                        } else {
                            painter.text(
                                rect.center() + Vec2::new(0.0, 84.0),
                                Align2::CENTER_CENTER,
                                format!(
                                    "本地恢复：按住 Esc {} 秒（或 {}+{}+{}）",
                                    3, ESCAPE_COMBO.0, ESCAPE_COMBO.1, ESCAPE_COMBO.2
                                ),
                                FontId::proportional(13.0),
                                pal.privacy_hint,
                            );
                        }
                    } else {
                        *esc_hold_start().lock().unwrap() = None;
                        painter.text(
                            rect.center() + Vec2::new(0.0, 84.0),
                            Align2::CENTER_CENTER,
                            format!(
                                "本地恢复：按住 Esc {} 秒（或 {}+{}+{}）",
                                3, ESCAPE_COMBO.0, ESCAPE_COMBO.1, ESCAPE_COMBO.2
                            ),
                            FontId::proportional(13.0),
                            pal.privacy_hint,
                        );
                    }
                });
            if escaped {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        },
    );
    if escaped {
        // 已在内容闭包内发出）→ 在位状态置否，网络侧对账/唤醒门随之收敛。
        note_overlay_in_place(false);
        OverlayOutcome::Escaped
    } else {
        note_overlay_in_place(true);
        OverlayOutcome::Active
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════
//
// 主窗隐藏到托盘（SW_HIDE）后**不再接收 `WM_PAINT`** → winit 无
// 先例：`lib.rs::main_repaint` 隐藏态 gating 与本节同口径）。对隐藏窗的
// `request_repaint`/`request_redraw` **同样无效**（eframe 0.28.1 `run.rs`
// `UserEvent::RequestRepaint`→`RepaintAt`→deadline→`window.request_redraw()`
// = winit `RedrawWindow(RDW_INTERNALPAINT)` → 仍依赖 `WM_PAINT`，隐藏窗永
// `show_black_overlay` 唯一调用点在**主窗 update 内**（`lib.rs`）→ 隐藏期
// 覆盖窗永不创建；而隐私状态机 + `PrivacyModeAck` 在**网络分发线程**
// （控制器槽置位 / `handle_server_privacy_message` / ack 发送）→ 「ack
// ok=true active=Black 但物理屏未黑」= 安全功能静默失效（**fail-open**）。
// **扩展发现（同根因）**：覆盖窗是 immediate viewport——eframe glow
// `run_ui_and_paint` 对非 ROOT immediate viewport 返回 `RepaintNext(parent)`
// （其输入与帧更新**全部依赖父窗〔主窗〕帧**）→ 主窗隐藏期即便覆盖窗已
// 创建，**本地逃生舱（Esc 3s / Ctrl+Alt+F9）同样停摆**；且 Black 关闭/
// 断连恢复时覆盖窗**永不关闭**（同一「主窗帧停摆」根因）。
//
// 修复（候选 A，最小改动 + 可测试；协议零改动——ack wire 不动）：
// ① **事件驱动即时唤醒**——网络侧状态迁移点（隐私请求 ack / 断连恢复）
//    若「主窗隐藏 ∧ 覆盖窗 需要/在位 失配」，经 [`crate::tray::wake_main_loop`]
//    显式唤醒主窗事件循环单帧（`PostMessageW(主窗, WM_SIZE)` → winit
//    `Resized(非零)` → eframe glow `repaint_asap` → `EventResult::RepaintNow`
//    → **直接 `run_ui_and_paint`**，不经 `WM_PAINT`——隐藏窗唯一可靠单帧
//    `show_black_overlay`（覆盖窗 native 窗同帧同步创建+绘制，eframe glow
//    `render_immediate_viewport` → `initialize_window`）→ 黑屏即时上屏。
// ② **看门狗线程**（[`spawn_overlay_watchdog`]，500ms tick）：
//    a. **keep-alive**——隐藏 ∧ Black ∧ 覆盖窗在位 → 每 [`OVERLAY_KEEPALIVE_INTERVAL`]
//       唤醒单帧（驱动覆盖窗输入消费：逃生舱 Esc 按住计时/倒计时文本/
//       `Ctrl+Alt+F9`——无父窗帧则逃生舱在隐藏态死亡，见上「扩展发现」）；
//    b. **fail-open 对账**——ack ok=Black 后 [`OVERLAY_ACK_GRACE`] 内覆盖窗
//       仍未在位 → **WARN 一次**（服务端日志可对账「ack ok 时覆盖窗是否
//       真在位」；对账闭合时在位 → INFO）。ack 语义/协议**零改动**。
//
// 判据函数全部纯函数化（[`overlay_required`] / [`should_wake_main_loop`] /
// [`overlay_watch_tick`] / [`ack_reconcile_op`]）供单测钉死；共享状态
// （[`overlay_watch_state`]）UI 线程/网络线程/看门狗线程三方经 Mutex 访问，
// 无跨锁嵌套（与 `server_privacy_controller` 锁序一致，无死锁面）。

/// 超期仍在位失败 = fail-open → WARN 一次（[`overlay_watch_tick`]）。
pub const OVERLAY_ACK_GRACE: Duration = Duration::from_secs(2);
/// 间隔（逃生舱 Esc 按住阈值 3s，1s 间隔下按住 ~4 帧内必达阈值）。
pub const OVERLAY_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);
pub const OVERLAY_WATCH_TICK: Duration = Duration::from_millis(500);

///
/// 仅 `Black` 需要应用内覆盖窗；`Lock` = 系统级锁屏（无覆盖窗）；
/// `None` = 未激活。
pub fn overlay_required(active: Option<PrivacyLevel>) -> bool {
    active == Some(PrivacyLevel::Black)
}

/// [`show_black_overlay`] 读取同构——覆盖窗的实际行为由槽内控制器决定）。
pub fn overlay_required_from_slot() -> bool {
    super::server_privacy_controller()
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|(_, c)| overlay_required(c.lock().unwrap().active_level()))
}

///
/// 「应在位 ∧ 不在位」（需创建）或「不应在位 ∧ 在位」（需关闭）= 失配；
/// 主窗**隐藏**（帧不会自动来——P-1 病机）→ 必须显式唤醒。主窗可见时
/// 常规帧管线自愈，无需唤醒（唤醒也无必要：`wake_main_loop` 对可见窗
/// 幂等但属无谓扰动）。
pub fn should_wake_main_loop(
    main_window_hidden: bool,
    overlay_needed: bool,
    overlay_in_place: bool,
) -> bool {
    main_window_hidden && overlay_needed != overlay_in_place
}

//
// 后无 WM_PAINT → 帧停摆，WM_SIZE 唤醒 = 隐藏窗唯一可靠单帧通路）。用户
// 09-09 复测 3 次 Black **全部** `main_hidden=false` 且 FAIL-OPEN：主窗
// **可见但空闲**（操作在控制端另一台机，服务端本机零输入）→ eframe 0.28
// 按需重绘 → 零事件零重绘 → `update()` 不跑 → `show_black_overlay` 不执行
// → 覆盖视口永不创建 → 物理屏不黑，而 ack 路径对可见主窗**无 repaint 请求**。
//
// 可见窗与隐藏窗的关键差异：可见窗 `WM_PAINT` 正常派发 → egui
// `Context::request_repaint()` **可达**（eframe `UserEvent::RequestRepaint`
// → `window.request_redraw()` → `RedrawWindow(RDW_INTERNALPAINT)` → WM_PAINT
// clone + headless `request_repaint` 形态已在本仓实证可编译可运行）。故：
// ack 记账路径（网络线程）对「主窗**可见** ∧ 覆盖窗 需要/在位 失配」显式
// 内置隐藏态门控），驱动单帧执行既有 `show_black_overlay`（覆盖视口同帧
// 创建/关闭）。看门狗对账逻辑**不变**（隐藏态唤醒/keep-alive/FAIL-OPEN WARN
// 全保留——若可见窗 repaint 实测仍不可达，看门狗 Wake 对可见窗幂等无害，
// 为 fallback 备注项）。

///
/// `!hidden ∧ 失配`（需要/在位 不一致）= 请求；主窗隐藏 → `false`
/// （走 [`should_wake_main_loop`] 的 WM_SIZE 唤醒通路，`request_repaint` 对
/// 无失配 → `false`（帧侧已同步，无谓重绘）。
pub fn should_request_visible_repaint(
    main_window_hidden: bool,
    overlay_needed: bool,
    overlay_in_place: bool,
) -> bool {
    !main_window_hidden && overlay_needed != overlay_in_place
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayWatchAction {
    /// 无需动作。
    Idle,
    /// 唤醒主窗单帧（失配创建/关闭，或 keep-alive 驱动覆盖窗输入）。
    Wake,
    /// ack 待对账且覆盖窗已在位 → 对账闭合（清 pending）。
    Confirm,
    /// ack ok=Black 超宽限期仍未在位 → WARN fail-open（一次性闩防刷屏）。
    FailOpenWarn,
}

///
/// 优先级：`FailOpenWarn` > 失配 `Wake` > `Confirm` > keep-alive `Wake` > `Idle`。
/// `FailOpenWarn` 置首的原因：覆盖窗**永不出现**时（P-2 类 native 窗创建
/// 失败等）失配 `Wake` 会每 tick 命中，若 warn 排在失配之后将被**永久饿
/// 死**——而该场景恰是必须可观测的 fail-open 本身。
pub fn overlay_watch_tick(
    main_window_hidden: bool,
    overlay_needed: bool,
    overlay_in_place: bool,
    ack_pending_age: Option<Duration>,
    warn_emitted: bool,
    keepalive_due: bool,
) -> OverlayWatchAction {
    if let Some(age) = ack_pending_age {
        if !overlay_in_place && age >= OVERLAY_ACK_GRACE && !warn_emitted {
            return OverlayWatchAction::FailOpenWarn;
        }
    }
    if should_wake_main_loop(main_window_hidden, overlay_needed, overlay_in_place) {
        return OverlayWatchAction::Wake;
    }
    if ack_pending_age.is_some() && overlay_in_place {
        return OverlayWatchAction::Confirm;
    }
    if main_window_hidden && overlay_needed && overlay_in_place && keepalive_due {
        return OverlayWatchAction::Wake;
    }
    OverlayWatchAction::Idle
}

// ─────────────────────── 共享状态（UI/网络/看门狗三方） ───────────────────────

struct OverlayWatchShared {
    /// 主窗 `update()` 每帧写入（[`show_black_overlay`] 尾）：本帧覆盖窗
    /// 在位。隐藏态主窗冻结 = 该值保持最后已知态——恰是对账所需的「最后
    /// 在位凭证」。
    overlay_in_place: bool,
    /// 网络线程 ack 后写入（[`note_privacy_ack`]）：「ack ok=Black」待对账
    /// 时刻（None = 无待对账）。
    ack_pending_since: Option<Instant>,
    /// 当前 pending 的 FailOpenWarn 是否已发（一次性闩；新 ack 复位）。
    warn_emitted: bool,
    /// 最近一次唤醒时刻（事件驱动与看门狗共用；keep-alive 间隔判据）。
    last_wake: Option<Instant>,
}

fn overlay_watch_state() -> &'static Mutex<OverlayWatchShared> {
    static T: Mutex<OverlayWatchShared> = Mutex::new(OverlayWatchShared {
        overlay_in_place: false,
        ack_pending_since: None,
        warn_emitted: false,
        last_wake: None,
    });
    &T
}

/// [`show_black_overlay`] 内——唯一帧侧观测点）。
pub fn note_overlay_in_place(in_place: bool) {
    overlay_watch_state().lock().unwrap().overlay_in_place = in_place;
}

pub fn overlay_in_place_now() -> bool {
    overlay_watch_state().lock().unwrap().overlay_in_place
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckReconcileOp {
    /// ack ok=Black：新起对账 pending（覆盖窗应在位，待帧侧确认）。
    NewPending,
    /// ack ok 且非 Black（off / 降级 Lock）：Black 主张已撤回 → 清 pending。
    ClearPending,
    /// ack 失败（ok=false）：状态机未因本请求变更 → 既有 pending 保持
    /// （它针对的是此前已生效的 Black 主张，不能因一次失败请求抹掉）。
    Unchanged,
}

pub fn ack_reconcile_op(ok: bool, active: Option<PrivacyLevel>) -> AckReconcileOp {
    if !ok {
        return AckReconcileOp::Unchanged;
    }
    if overlay_required(active) {
        AckReconcileOp::NewPending
    } else {
        AckReconcileOp::ClearPending
    }
}

pub fn note_privacy_ack(ok: bool, active: Option<PrivacyLevel>) {
    let mut st = overlay_watch_state().lock().unwrap();
    match ack_reconcile_op(ok, active) {
        AckReconcileOp::NewPending => {
            st.ack_pending_since = Some(Instant::now());
            st.warn_emitted = false;
        }
        AckReconcileOp::ClearPending => {
            st.ack_pending_since = None;
        }
        AckReconcileOp::Unchanged => {}
    }
}

/// 无新 ack → 清对账 pending + warn 闩（覆盖窗的关闭由唤醒门处理）。
pub fn note_privacy_recovered() {
    let mut st = overlay_watch_state().lock().unwrap();
    st.ack_pending_since = None;
    st.warn_emitted = false;
}

pub fn note_wake(now: Instant) {
    overlay_watch_state().lock().unwrap().last_wake = Some(now);
}

/// `(in_place, ack_pending_since, warn_emitted, last_wake)`。
pub fn watch_snapshot() -> (bool, Option<Instant>, bool, Option<Instant>) {
    let st = overlay_watch_state().lock().unwrap();
    (st.overlay_in_place, st.ack_pending_since, st.warn_emitted, st.last_wake)
}

pub fn clear_ack_pending() {
    let mut st = overlay_watch_state().lock().unwrap();
    st.ack_pending_since = None;
    st.warn_emitted = false;
}

pub fn set_warn_emitted() {
    overlay_watch_state().lock().unwrap().warn_emitted = true;
}

///
/// 500ms tick：读（主窗隐藏态 / 覆盖窗 需要·在位 / ack pending）→
/// [`overlay_watch_tick`] 纯判定 → 执行（唤醒 / 清对账 / WARN）。
/// 仅 Windows 实体化（唤醒机制 [`crate::tray::wake_main_loop`] 为 Win32
/// 实现；非 Windows 平台桩为空——本应用为 Windows GUI）。
#[cfg(target_os = "windows")]
pub fn spawn_overlay_watchdog() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let spawned = std::thread::Builder::new()
            .name("kirin-privacy-overlay-watch".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(OVERLAY_WATCH_TICK);
                    let now = Instant::now();
                    let hidden = super::tray::is_main_window_hidden();
                    let needed = overlay_required_from_slot();
                    let (in_place, ack_since, warn_emitted, last_wake) = watch_snapshot();
                    let ack_age = ack_since.map(|t| now.saturating_duration_since(t));
                    let keepalive_due = last_wake
                        .map_or(true, |t| now.saturating_duration_since(t) >= OVERLAY_KEEPALIVE_INTERVAL);
                    match overlay_watch_tick(
                        hidden, needed, in_place, ack_age, warn_emitted, keepalive_due,
                    ) {
                        OverlayWatchAction::Wake => {
                            super::tray::wake_main_loop();
                            note_wake(now);
                            tracing::debug!(
                                hidden, needed, in_place
                            );
                        }
                        OverlayWatchAction::Confirm => {
                            if let Some(since) = ack_since {
                                tracing::info!(
                                    now.saturating_duration_since(since).as_millis()
                                );
                            }
                            clear_ack_pending();
                        }
                        OverlayWatchAction::FailOpenWarn => {
                            tracing::warn!(
                                ack_age.map(|d| d.as_millis()).unwrap_or(0),
                                hidden
                            );
                            set_warn_emitted();
                        }
                        OverlayWatchAction::Idle => {}
                    }
                }
            })
            .ok();
        if spawned.is_none() {
            tracing::warn!(
            );
        }
    });
}

#[cfg(not(target_os = "windows"))]
pub fn spawn_overlay_watchdog() {}

// ════════════════════════════════════════════════════════════════
// 客户端隐私状态（UI-PRIV-002/004）
// ════════════════════════════════════════════════════════════════

/// 客户端收到的隐私模式响应（服务端 `PrivacyModeAck`，UI-PRIV-002）。
#[derive(Debug, Clone)]
pub struct PrivacyAckState {
    /// 服务端当前生效等级（None = 已恢复/关闭）。
    pub level: Option<PrivacyLevel>,
    /// 递增序号（每次 ack 自增；连接窗口据此只弹一次 toast）。
    pub seq: u64,
    /// toast 文案（空串 = 不提示）。
    pub toast: String,
}

/// 根据客户端请求与服务端响应生成 toast 文案。
///
/// - 请求 Black 但生效 Lock → 降级提示（SRV-PRIV-013）；
/// - `ok = false` → 失败提示（平台锁屏调用失败等，SRV-PRIV-012）。
pub fn ack_toast(
    ok: bool,
    active: Option<PrivacyLevel>,
    requested: Option<PrivacyLevel>,
) -> String {
    match (ok, active) {
        (true, Some(level)) if Some(level) == requested => {
            format!("隐私模式已开启：{}", level.display())
        }
        (true, Some(level)) => format!("黑屏不可用，已降级为{}", level.display()),
        (true, None) => "被控端屏幕已恢复".to_string(),
        (false, _) => "隐私操作失败（服务端拒绝或锁屏调用失败）".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack_toast_direct_activate() {
        // 请求 Black → 生效 Black：直接开启提示。
        let t = ack_toast(true, Some(PrivacyLevel::Black), Some(PrivacyLevel::Black));
        assert!(t.contains("黑屏"));
        let t = ack_toast(true, Some(PrivacyLevel::Lock), Some(PrivacyLevel::Lock));
        assert!(t.contains("锁屏"));
    }

    #[test]
    fn test_ack_toast_degraded() {
        // 请求 Black → 生效 Lock（无 GUI 降级，SRV-PRIV-013）：降级提示。
        let t = ack_toast(true, Some(PrivacyLevel::Lock), Some(PrivacyLevel::Black));
        assert!(t.contains("降级"));
        assert!(t.contains("锁屏"));
    }

    #[test]
    fn test_ack_toast_off_and_fail() {
        assert!(ack_toast(true, None, None).contains("恢复"));
        assert!(ack_toast(false, None, Some(PrivacyLevel::Lock)).contains("失败"));
        // 未请求时收到降级/其它响应 → 也提示降级（不应产生空文案）。
        let t = ack_toast(true, Some(PrivacyLevel::Black), None);
        assert!(t.contains("黑屏"));
    }

    #[test]
    fn test_escape_constants() {
        assert_eq!(ESCAPE_ESC_HOLD, Duration::from_secs(3));
        assert_eq!(ESCAPE_COMBO, ("Ctrl", "Alt", "F9"));
    }


    #[test]
    fn r95_overlay_required_matrix() {
        // 仅 Black 需要应用内覆盖窗；Lock = 系统级锁屏（无覆盖窗）；None = 未激活。
        assert!(overlay_required(Some(PrivacyLevel::Black)));
        assert!(!overlay_required(Some(PrivacyLevel::Lock)));
        assert!(!overlay_required(None));
    }

    #[test]
    fn r95_should_wake_main_loop_matrix() {
        // 主窗可见 → 恒不唤醒（常规帧管线自愈；唤醒无必要）。
        for (needed, in_place) in [(false, false), (false, true), (true, false), (true, true)] {
            assert!(
                !should_wake_main_loop(false, needed, in_place),
                "visible: needed={needed} in_place={in_place}"
            );
        }
        // 隐藏态：仅失配唤醒（应在位未位=创建；不应在位而在=关闭）；一致不唤。
        assert!(should_wake_main_loop(true, true, false)); // 创建
        assert!(should_wake_main_loop(true, false, true)); // 关闭
        assert!(!should_wake_main_loop(true, true, true)); // 已在位
        assert!(!should_wake_main_loop(true, false, false)); // 无需且不在位
    }

    /// （09-09 三次 Black FAIL-OPEN 全 main_hidden=false 的根因分支）；
    /// 可见 ∧ 一致 = 不请求（帧侧已同步）；隐藏 = 恒不请求（走 WM_SIZE
    #[test]
    fn r95b_visible_repaint_matrix() {
        // ① 可见 + 失配（创建方向：Black on 后空闲可见窗）→ 请求。
        assert!(should_request_visible_repaint(false, true, false));
        // ② 可见 + 失配（关闭方向：off/断连后覆盖窗仍在位）→ 请求。
        assert!(should_request_visible_repaint(false, false, true));
        // ③ 可见 + 一致（在位/无需 两侧同步）→ 不请求。
        assert!(!should_request_visible_repaint(false, true, true));
        assert!(!should_request_visible_repaint(false, false, false));
        // ④ 隐藏 → 恒不请求（WM_SIZE 唤醒通路接管）。
        for (needed, in_place) in [(false, false), (false, true), (true, false), (true, true)] {
            assert!(
                !should_request_visible_repaint(true, needed, in_place),
                "hidden: needed={needed} in_place={in_place}"
            );
        }
    }

    #[test]
    fn r95_ack_reconcile_op_matrix() {
        assert_eq!(
            ack_reconcile_op(true, Some(PrivacyLevel::Black)),
            AckReconcileOp::NewPending
        );
        assert_eq!(ack_reconcile_op(true, None), AckReconcileOp::ClearPending);
        // 降级 Lock（headless，SRV-PRIV-013）→ Black 主张撤回 → 清 pending。
        assert_eq!(
            ack_reconcile_op(true, Some(PrivacyLevel::Lock)),
            AckReconcileOp::ClearPending
        );
        // ok=false（状态机未因本请求变更）→ 既有 pending 不动。
        assert_eq!(
            ack_reconcile_op(false, Some(PrivacyLevel::Black)),
            AckReconcileOp::Unchanged
        );
        assert_eq!(ack_reconcile_op(false, None), AckReconcileOp::Unchanged);
        assert_eq!(
            ack_reconcile_op(false, Some(PrivacyLevel::Lock)),
            AckReconcileOp::Unchanged
        );
    }

    #[test]
    fn r95_overlay_watch_tick_matrix() {
        let grace = OVERLAY_ACK_GRACE;
        // ① fail-open：ack ok=Black 超宽限期且未位 → WARN（优先级最高——
        //    覆盖窗永不出现时不得被失配 Wake 饿死）。
        assert_eq!(
            overlay_watch_tick(true, true, false, Some(grace + Duration::from_secs(1)), false, true),
            OverlayWatchAction::FailOpenWarn
        );
        // 宽限期内 → 不 warn，落失配 Wake（创建重试继续）。
        assert_eq!(
            overlay_watch_tick(true, true, false, Some(grace - Duration::from_millis(100)), false, true),
            OverlayWatchAction::Wake
        );
        // warn 闩已置 → 不再重复 warn（防刷屏），落失配 Wake。
        assert_eq!(
            overlay_watch_tick(true, true, false, Some(grace + Duration::from_secs(5)), true, true),
            OverlayWatchAction::Wake
        );
        // ② 失配 Wake（创建/关闭）。
        assert_eq!(
            overlay_watch_tick(true, true, false, None, false, false),
            OverlayWatchAction::Wake
        );
        assert_eq!(
            overlay_watch_tick(true, false, true, None, false, false),
            OverlayWatchAction::Wake
        );
        // ③ 主窗可见 → 恒不 Wake（但 Reconcile 仍可发生）。
        assert_eq!(
            overlay_watch_tick(false, true, false, None, false, true),
            OverlayWatchAction::Idle
        );
        assert_eq!(
            overlay_watch_tick(false, false, true, None, false, true),
            OverlayWatchAction::Idle
        );
        // ④ 对账：pending + 在位 → Confirm（隐藏/可见均成立）。
        assert_eq!(
            overlay_watch_tick(true, true, true, Some(Duration::from_millis(50)), false, false),
            OverlayWatchAction::Confirm
        );
        assert_eq!(
            overlay_watch_tick(false, true, true, Some(grace), false, true),
            OverlayWatchAction::Confirm
        );
        // ⑤ keep-alive：隐藏 ∧ Black ∧ 在位 ∧ 到期 → Wake；未到期 → Idle。
        assert_eq!(
            overlay_watch_tick(true, true, true, None, false, true),
            OverlayWatchAction::Wake
        );
        assert_eq!(
            overlay_watch_tick(true, true, true, None, false, false),
            OverlayWatchAction::Idle
        );
        // 主窗可见 + Black 在位（无需 keep-alive）+ 无 pending → Idle。
        assert_eq!(
            overlay_watch_tick(false, true, true, None, false, true),
            OverlayWatchAction::Idle
        );
        // 隐藏 + 一致（在位/无需）+ 无 pending + keep-alive 未到期 → Idle。
        assert_eq!(
            overlay_watch_tick(true, false, false, None, false, false),
            OverlayWatchAction::Idle
        );
    }

    #[test]
    fn r95_overlay_watch_state_roundtrip() {
        // 共享状态记账语义（单线程测试上下文）：在位写读 / ack pending 迁移
        // / warn 闩 / 断连恢复复位 / 唤醒记录。
        note_overlay_in_place(false);
        assert!(!overlay_in_place_now());
        note_overlay_in_place(true);
        assert!(overlay_in_place_now());

        note_privacy_ack(true, Some(PrivacyLevel::Black));
        let (in_place, since, warn_emitted, last_wake) = watch_snapshot();
        assert!(in_place);
        assert!(since.is_some());
        assert!(!warn_emitted);
        assert!(last_wake.is_none());

        // off ack → 清 pending。
        note_privacy_ack(true, None);
        let (_, since, _, _) = watch_snapshot();
        assert!(since.is_none());

        // Black ack 重新武装 → 置 warn 闩 → 断连恢复全清。
        note_privacy_ack(true, Some(PrivacyLevel::Black));
        set_warn_emitted();
        let (_, since, warn_emitted, _) = watch_snapshot();
        assert!(since.is_some());
        assert!(warn_emitted);
        note_privacy_recovered();
        let (_, since, warn_emitted, _) = watch_snapshot();
        assert!(since.is_none());
        assert!(!warn_emitted);

        // note_wake 记录最近唤醒。
        note_wake(Instant::now());
        let (_, _, _, last_wake) = watch_snapshot();
        assert!(last_wake.is_some());
        clear_ack_pending();
        note_overlay_in_place(false);
    }
}
