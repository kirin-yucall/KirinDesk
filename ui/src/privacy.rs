//! M8-T019: 被控端黑屏覆盖窗口（SRV-PRIV-011/016）与客户端隐私状态显示。
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

use egui::{Align2, Color32, FontId, Key, Rect, Vec2};
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
    let active = super::server_privacy_controller()
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|c| c.lock().unwrap().active_level() == Some(PrivacyLevel::Black));
    if !active {
        // 状态已退出 → 清逃生舱计时，覆盖窗口本帧不再渲染即自动关闭。
        *esc_hold_start().lock().unwrap() = None;
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
            super::theme::ensure_fonts(ctx);
            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(Color32::BLACK))
                .show(ctx, |ui| {
                    let rect = Rect::from_center_size(
                        ui.max_rect().center(),
                        Vec2::new(ui.max_rect().width().min(560.0), 150.0),
                    );
                    let painter = ui.painter_at(rect);
                    // 提示条底板（深灰卡片，非纯黑以便辨识）。
                    painter.rect_filled(rect, 10.0, Color32::from_gray(22));
                    painter.text(
                        rect.center_top() + Vec2::new(0.0, 22.0),
                        Align2::CENTER_TOP,
                        "屏幕已被远程用户隐藏 - KirinDesk",
                        FontId::proportional(22.0),
                        Color32::from_gray(220),
                    );
                    painter.text(
                        rect.center() + Vec2::new(0.0, 52.0),
                        Align2::CENTER_CENTER,
                        "远程会话进行中：输入操作照常生效",
                        FontId::proportional(15.0),
                        Color32::from_gray(150),
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
                                Color32::from_gray(120),
                            );
                        } else {
                            painter.text(
                                rect.center() + Vec2::new(0.0, 84.0),
                                Align2::CENTER_CENTER,
                                format!("本地恢复：按住 Esc {} 秒（或 {}+{}+{}）", 3, ESCAPE_COMBO.0, ESCAPE_COMBO.1, ESCAPE_COMBO.2),
                                FontId::proportional(13.0),
                                Color32::from_gray(120),
                            );
                        }
                    } else {
                        *esc_hold_start().lock().unwrap() = None;
                        painter.text(
                            rect.center() + Vec2::new(0.0, 84.0),
                            Align2::CENTER_CENTER,
                            format!("本地恢复：按住 Esc {} 秒（或 {}+{}+{}）", 3, ESCAPE_COMBO.0, ESCAPE_COMBO.1, ESCAPE_COMBO.2),
                            FontId::proportional(13.0),
                            Color32::from_gray(120),
                        );
                    }
                });
            if escaped {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        },
    );
    if escaped {
        OverlayOutcome::Escaped
    } else {
        OverlayOutcome::Active
    }
}

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
pub fn ack_toast(ok: bool, active: Option<PrivacyLevel>, requested: Option<PrivacyLevel>) -> String {
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
}
