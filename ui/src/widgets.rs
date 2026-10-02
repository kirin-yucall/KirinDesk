//! M15-T008: 通用 UI 组件库（纯 egui 函数，令牌驱动，零裸色值）。
//!
//! 规则：组件只允许经 [`Theme`] 取色/取字号；仅允许 hover/pressed/selected
//! 状态色切换，无任何持续动画（保 UI-NF-001 60fps）。本文件不依赖 lib.rs，
//! 可独立单测（`egui::Context` 可 headless 跑布局）。

use eframe::egui;
use egui::{Color32, RichText, Stroke, Ui};

use crate::theme::Theme;
// M8-T038 (P6): 组件默认 tooltip 文案走 t!()（i18n/widgets.rs 分区表）。
use crate::t;

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

///
/// 根因（用户定案「编辑按钮点开后的页面会持续向右延申」）：`egui::Window`
/// `.resizable(false)` 的 auto-size = 内容理想宽，叠加 `resize.rs` auto-expand
/// 棘轮（`desired = max(desired, last)`，只涨不缩）+ 长文本不截断（设备 ID
/// 只读行 79 字符指纹 monospace ≈ 850–900px）→ 窗宽逐帧右移；
/// `labeled_input` 的 `desired_width(available_width)` 与窗宽循环依赖固化。
/// 修法：`min_size`/`max_size` 硬约束 + 长文本 `TextWrapMode::Truncate`
/// 截断到受限宽 → 弹窗宽稳定落在 [`DIALOG_MIN_WIDTH`]–[`DIALOG_MAX_WIDTH`]，
/// 逐帧不右移（`max_size` 在棘轮前后各 clamp 一次，硬顶 420）。
pub const DIALOG_MIN_WIDTH: f32 = 340.0;
pub const DIALOG_MAX_WIDTH: f32 = 420.0;

// ════════════════════════════════════════════════════════════════
// 徽标 / 状态点
// ════════════════════════════════════════════════════════════════

/// 徽标语义（§4 Badge：kind ∈ {success, warning, danger, info, neutral}）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BadgeKind {
    Success,
    Warning,
    Danger,
    Info,
    Neutral,
}

impl BadgeKind {
    pub fn color(self, theme: &Theme) -> Color32 {
        match self {
            BadgeKind::Success => theme.success,
            BadgeKind::Warning => theme.warning,
            BadgeKind::Danger => theme.danger,
            BadgeKind::Info => theme.info,
            BadgeKind::Neutral => theme.fg_weak,
        }
    }
}

/// 胶囊徽标：`bg_strong` 底 + 语义色文字，4px 圆角。
pub fn badge(ui: &mut Ui, theme: &Theme, text: &str, kind: BadgeKind) -> egui::Response {
    let color = kind.color(theme);
    egui::Frame::none()
        .fill(theme.bg_strong)
        .rounding(theme.rounding_badge)
        .inner_margin(egui::Margin::symmetric(8.0, 2.0))
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(RichText::new(text).size(theme.small_size).color(color))
                    .selectable(false),
            )
        })
        .inner
}

/// 状态点：`●` + 同色文字（§4 StatusDot；语义色统一 success/warning/danger/fg_weak）。
pub fn status_dot(ui: &mut Ui, color: Color32, text: &str) -> egui::Response {
    status_dot_char(ui, color, "●", text)
}

/// 状态点变体：显式指定圆点字符（保留既有 `○ Stopped` 等文案）。
pub fn status_dot_char(ui: &mut Ui, color: Color32, dot: &str, text: &str) -> egui::Response {
    ui.add(egui::Label::new(RichText::new(format!("{dot} {text}")).color(color)).selectable(false))
}

// ════════════════════════════════════════════════════════════════
// 按钮
// ════════════════════════════════════════════════════════════════

/// 按钮语义（§4 Primary/Secondary/Danger；Success 用于审批 Accept 绿底）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Success,
    Danger,
}

/// 按钮状态：Busy = `⏳` 前缀 + 禁用；Disabled = 灰化（fg_weak 于 bg_strong）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ButtonState {
    Enabled,
    Busy,
    Disabled,
}

/// 内 IP 模式三钮单行：3×148+2×8=460<480〔V 岗⑤：3×160+2×8=496>480 不可行〕；
/// 长文案按钮不受影响，egui min_size 为下限，标签更宽时自动撑开）。
/// 布局判定单一事实源（`lib.rs` `connect_button_row_fits` 单测消费）。
pub const ACTION_BUTTON_MIN_WIDTH: f32 = 148.0;

/// 统一动作按钮：min_size([`ACTION_BUTTON_MIN_WIDTH`],40)、圆角 6px；hover 走
/// 状态色切换（令牌驱动）。
///
/// 实现说明：egui 0.28 的 `Button::fill` 会覆盖 hover 效果，因此这里在调用点
/// 临时改写 `ui.visuals()` 的 widget 状态色，add 后立即还原——组件外无副作用。
pub fn action_button(
    ui: &mut Ui,
    theme: &Theme,
    kind: ButtonKind,
    text: &str,
    state: ButtonState,
) -> egui::Response {
    let (fill, hover, fg) = match state {
        ButtonState::Enabled => match kind {
            ButtonKind::Primary => (theme.primary, theme.primary_hover, theme.on_primary),
            ButtonKind::Secondary => (theme.bg_strong, theme.bg_panel, theme.fg),
            ButtonKind::Success => (theme.success, theme.success, theme.on_primary),
            ButtonKind::Danger => (theme.danger, theme.danger, theme.on_primary),
        },
        ButtonState::Busy | ButtonState::Disabled => {
            (theme.bg_strong, theme.bg_strong, theme.fg_weak)
        }
    };
    let label = match state {
        ButtonState::Busy => format!("⏳ {text}"),
        _ => text.to_owned(),
    };
    let saved = ui.visuals().clone();
    {
        let v = ui.visuals_mut();
        for w in [
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
        ] {
            w.bg_fill = fill;
            w.weak_bg_fill = fill;
            w.bg_stroke = Stroke::new(theme.border_width, theme.border);
            w.rounding = egui::Rounding::same(theme.rounding_control);
            w.fg_stroke = Stroke::new(1.0_f32, fg);
        }
        v.widgets.hovered.bg_fill = hover;
        v.widgets.active.bg_fill = hover;
        if kind == ButtonKind::Secondary {
            v.widgets.hovered.bg_stroke = Stroke::new(theme.border_width, theme.primary);
        }
    }
    let resp = ui.add_enabled(
        state == ButtonState::Enabled,
        egui::Button::new(RichText::new(label).size(theme.button_size))
            .min_size(egui::vec2(ACTION_BUTTON_MIN_WIDTH, 40.0)),
    );
    *ui.visuals_mut() = saved;
    resp
}

/// 导航/分段选中胶囊：选中 = 品牌色底 + 对比文字；未选中 hover 高亮。
/// 调用点传 0.0 零行为变化）；>0 = 统一宽（顶栏 6 tab 等宽用）。
pub fn selectable_pill(
    ui: &mut Ui,
    theme: &Theme,
    text: &str,
    selected: bool,
    min_width: f32,
) -> egui::Response {
    let saved = ui.visuals().clone();
    {
        let v = ui.visuals_mut();
        let (fill, fg) = if selected {
            (theme.primary, theme.on_primary)
        } else {
            (theme.bg_panel, theme.fg)
        };
        for w in [
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
        ] {
            w.bg_fill = fill;
            w.weak_bg_fill = fill;
            w.rounding = egui::Rounding::same(theme.rounding_control);
            w.fg_stroke = Stroke::new(1.0_f32, fg);
            w.bg_stroke = Stroke::new(theme.border_width, theme.border);
        }
        if !selected {
            v.widgets.hovered.bg_fill = theme.bg_strong;
            v.widgets.hovered.bg_stroke = Stroke::new(theme.border_width, theme.primary);
        }
    }
    let resp = ui.add(
        egui::Button::new(RichText::new(text).size(theme.button_size))
            .min_size(egui::vec2(min_width.max(0.0), 36.0)),
    );
    *ui.visuals_mut() = saved;
    resp
}

/// 分段控件（§4 SegmentedControl）：选中项品牌色底；返回是否变更。
pub fn segmented_control(ui: &mut Ui, theme: &Theme, items: &[&str], selected: &mut usize) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        for (i, item) in items.iter().enumerate() {
            let sel = *selected == i;
            if selectable_pill(ui, theme, item, sel, 0.0).clicked() && !sel {
                *selected = i;
                changed = true;
            }
        }
    });
    changed
}

// ════════════════════════════════════════════════════════════════
// 展开态工具条上的全部按钮统一半透明（不能影响画面展示；对比度纪律
// ════════════════════════════════════════════════════════════════

/// 0.70~0.85 区间；修前 = 不透明 255）。悬停态恢复 `theme.bg_panel`
/// 不透明底（既有 hovered 臂原样）= 更高不透明度便于点击辨识（可选
/// 增强，egui 悬停自动切档，零自管状态）。单测钉死区间与取值。
pub const TOOLBAR_WIDGET_ALPHA: u8 = 200;

/// 不透明度（rgba unmultiplied，与 lib.rs `toolbar_bar_fill` 同式）。
pub fn toolbar_widget_fill(theme: &Theme, alpha: u8) -> Color32 {
    let [r, g, b, _] = theme.bg_strong.to_srgba_unmultiplied();
    Color32::from_rgba_unmultiplied(r, g, b, alpha)
}

/// 工具栏图标按钮（§4 ToolbarButton）：hover 高亮 + tooltip 显示快捷键。
/// 不透明 `bg_panel`（既有 hovered 臂，更高不透明度档）。前景/描边
pub fn toolbar_button(ui: &mut Ui, theme: &Theme, icon: &str, tooltip: &str) -> egui::Response {
    let saved = ui.visuals().clone();
    {
        let v = ui.visuals_mut();
        for w in [
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
        ] {
            w.bg_fill = toolbar_widget_fill(theme, TOOLBAR_WIDGET_ALPHA);
            w.rounding = egui::Rounding::same(theme.rounding_control);
            w.fg_stroke = Stroke::new(1.0_f32, theme.fg);
            w.bg_stroke = Stroke::new(theme.border_width, theme.border);
        }
        v.widgets.hovered.bg_fill = theme.bg_panel;
        v.widgets.hovered.bg_stroke = Stroke::new(theme.border_width, theme.primary);
    }
    let resp = ui.add(
        egui::Button::new(RichText::new(icon).size(theme.button_size))
            .min_size(egui::vec2(36.0, 32.0)),
    );
    *ui.visuals_mut() = saved;
    resp.on_hover_text(tooltip)
}

/// 小复制按钮（📋，M8-T028）：点击把文本写入剪贴板。
/// - `text` 为空 → 禁用（灰化不可点，UI-BTY-023）；
/// - 点击后按钮瞬态显示 ✓（1.5s 自动还原；按按钮 id 记忆，无持续动画，UI-BTY-028）；
/// - 返回 `(Response, bool)`：`bool` = 本帧发生复制（调用方用于状态栏浮出提示）。
pub fn copy_button(ui: &mut Ui, theme: &Theme, text: &str) -> (egui::Response, bool) {
    // 先取本按钮的 auto id（下一个 widget 会消耗它），据此查询上次点击时刻：
    // 1.5s 内显示 ✓ 而非 📋（跨帧瞬态，不引入持续动画）。
    // 过期条目不主动清理——每个按钮 id 至多一条，总量有界（约 12 处按钮）。
    let id = ui.next_auto_id();
    let show_ok = ui.ctx().data(|d| {
        d.get_temp::<std::time::Instant>(id)
            .is_some_and(|t| t.elapsed() < COPY_BUTTON_FEEDBACK)
    });
    let icon = if show_ok { "✓" } else { "📋" };
    let resp = ui
        .add_enabled(
            !text.is_empty(),
            egui::Button::new(RichText::new(icon).size(12.0)).min_size(egui::vec2(26.0, 20.0)),
        )
        .on_hover_text(t!("widgets.copy"));
    let mut copied = false;
    if resp.clicked() {
        ui.output_mut(|o| o.copied_text = text.to_owned());
        ui.ctx()
            .data_mut(|d| d.insert_temp(resp.id, std::time::Instant::now()));
        copied = true;
        ui.ctx().request_repaint(); // ✓ 瞬态自下一帧起可见
    }
    let _ = theme;
    (resp, copied)
}

/// M8-T028 (UI-BTY-028): 📋 复制成功反馈持续时间（按钮 ✓ 瞬态）。
const COPY_BUTTON_FEEDBACK: std::time::Duration = std::time::Duration::from_millis(1500);

/// M8-T036: 状态按钮（开/关二态颜色切换）——ON = 品牌蓝填充 + `on_primary`
/// 文字，OFF = `bg_strong` 灰填充 + `fg_weak` 文字（与 `toggle_switch` 语义
/// 一致：灰=停用，蓝=启用）。状态由调用方持有（`on` 为只读快照，点击后自行
/// 翻转并持久化）。
pub fn state_button(ui: &mut Ui, theme: &Theme, label: &str, on: bool) -> egui::Response {
    let btn = egui::Button::new(
        egui::RichText::new(label).color(if on { theme.on_primary } else { theme.fg_weak }),
    );
    let saved = ui.visuals().clone();
    {
        let v = ui.visuals_mut();
        for w in [
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
        ] {
            w.bg_fill = if on { theme.primary } else { theme.bg_strong };
            w.rounding = egui::Rounding::same(theme.rounding_control);
        }
    }
    let resp = ui.add(btn);
    *ui.visuals_mut() = saved;
    resp
}

// ════════════════════════════════════════════════════════════════
// 滑动开关（M8-T034）
// ════════════════════════════════════════════════════════════════

/// 滑动开关（M8-T034）：自绘圆角轨道 + 滑动圆钮，状态由调用方持有
/// （`on` 为只读快照；调用方读 `.clicked()` 后自行翻转并持久化）。
/// - ON = 品牌主色轨道 + `on_primary` 圆钮；OFF = `bg_strong` 轨道 +
///   `fg_weak` 圆钮；仅 hover/pressed 状态色切换，无持续动画（UI-NF-001）；
/// - `status` 渲染于开关右侧（small_size 弱色）——「连接状态放按钮上」。
pub fn toggle_switch(
    ui: &mut Ui,
    theme: &Theme,
    label: &str,
    on: bool,
    status: Option<&str>,
) -> egui::Response {
    const TRACK_W: f32 = 44.0;
    const TRACK_H: f32 = 24.0;
    const KNOB_D: f32 = 18.0;

    ui.horizontal(|ui| {
        ui.add(
            egui::Label::new(RichText::new(label).size(theme.body_size).color(theme.fg))
                .selectable(false),
        );
        ui.add_space(4.0);
        let (rect, resp) = ui.allocate_exact_size(
            egui::vec2(TRACK_W, TRACK_H),
            egui::Sense::click(),
        );
        let hovered = resp.hovered() || resp.highlighted();
        let track_color = if on {
            if hovered {
                theme.primary_hover
            } else {
                theme.primary
            }
        } else if hovered {
            theme.bg_panel
        } else {
            theme.bg_strong
        };
        let knob_color = if on { theme.on_primary } else { theme.fg_weak };
        let painter = ui.painter();
        painter.rect_filled(rect, TRACK_H / 2.0, track_color);
        painter.rect_stroke(
            rect,
            TRACK_H / 2.0,
            Stroke::new(theme.border_width, theme.border),
        );
        // 圆钮位置：ON 靠右 / OFF 靠左（瞬时跳变，无持续动画）。
        let cx = if on {
            rect.right() - KNOB_D / 2.0 - 3.0
        } else {
            rect.left() + KNOB_D / 2.0 + 3.0
        };
        painter.circle_filled(egui::pos2(cx, rect.center().y), KNOB_D / 2.0, knob_color);
        if let Some(status) = status {
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(
                    RichText::new(status)
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
        }
        resp
    })
    .inner
}

// ════════════════════════════════════════════════════════════════
// 输入
// ════════════════════════════════════════════════════════════════

/// 输入合法性（§4 LabeledInput：None 中性 / Valid 绿边 / Invalid 红边 + 提示）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Validity {
    None,
    Valid,
    Invalid(&'static str),
}

/// 标签上置 + 输入框（占位符 + 校验反馈边框）。
/// - `secret`：圆点遮蔽 + 👁 切换（Connect 挑战码、Settings API Secret/验证码）。
/// - `mono`：IPv6/IP/端口/挑战码/日志等按方案 §3.2 用等宽字体。
pub fn labeled_input(
    ui: &mut Ui,
    theme: &Theme,
    label: &str,
    value: &mut String,
    placeholder: &str,
    validity: Validity,
    secret: Option<&mut bool>,
    mono: bool,
) -> egui::Response {
    ui.vertical(|ui| {
        ui.add(
            egui::Label::new(
                RichText::new(label)
                    .size(theme.small_size)
                    .color(theme.fg_weak),
            )
            .selectable(false),
        );
        let resp = ui
            .horizontal(|ui| {
                // 密文模式：编辑「•」缓冲；追加/回删启发式同步回真实值。
                // 注：`as_ref()` 借用，避免 move 掉 `secret`（后续 👁 切换还要用）。
                let show = secret.as_ref().map(|s| **s).unwrap_or(true);
                let mut masked = String::new();
                let prev_masked: String;
                let target: &mut String = if secret.is_some() && !show {
                    prev_masked = "•".repeat(value.chars().count());
                    masked = prev_masked.clone();
                    &mut masked
                } else {
                    prev_masked = String::new();
                    value
                };
                let mut te = egui::TextEdit::singleline(target)
                    .hint_text(placeholder)
                    .desired_width(
                        (ui.available_width() - if secret.is_some() { 44.0 } else { 0.0 })
                            .max(120.0),
                    );
                if mono {
                    te = te.font(egui::TextStyle::Monospace);
                }
                let border_color = match validity {
                    Validity::Valid => theme.success,
                    Validity::Invalid(_) => theme.danger,
                    Validity::None => theme.border,
                };
                let saved = ui.visuals().clone();
                {
                    let v = ui.visuals_mut();
                    for w in [
                        &mut v.widgets.inactive,
                        &mut v.widgets.hovered,
                        &mut v.widgets.active,
                    ] {
                        w.bg_fill = theme.bg_panel;
                        w.bg_stroke = Stroke::new(theme.border_width, border_color);
                        w.rounding = egui::Rounding::same(theme.rounding_control);
                    }
                    v.widgets.hovered.bg_fill = theme.bg_strong;
                }
                let resp = ui.add(te);
                *ui.visuals_mut() = saved;

                // 密文编辑 → 真实值同步（仅支持追加/回删，光标中段编辑忽略）。
                if secret.is_some() && !show && masked != prev_masked {
                    let prev_len = value.chars().count();
                    let new_len = masked.chars().count();
                    if new_len > prev_len
                        && masked
                            .chars()
                            .take(prev_len)
                            .eq(prev_masked.chars().take(prev_len))
                    {
                        for c in masked.chars().skip(prev_len) {
                            value.push(c);
                        }
                    } else if new_len < prev_len
                        && prev_masked.chars().take(new_len).eq(masked.chars())
                    {
                        let new_val: String = value.chars().take(new_len).collect();
                        *value = new_val;
                    }
                }
                // 👁 可见性切换
                if let Some(show) = secret {
                    let eye = ui
                        .add_sized(
                            [32.0, 28.0],
                            egui::Button::new(RichText::new("👁").size(theme.small_size)),
                        )
                        .on_hover_text(if *show {
                            t!("widgets.secret.hide")
                        } else {
                            t!("widgets.secret.show")
                        });
                    if eye.clicked() {
                        *show = !*show;
                    }
                }
                resp
            })
            .inner;
        if let Validity::Invalid(msg) = validity {
            ui.add(
                egui::Label::new(
                    RichText::new(msg)
                        .size(theme.small_size)
                        .color(theme.danger),
                )
                .selectable(false),
            );
        }
        resp
    })
    .inner
}

// ════════════════════════════════════════════════════════════════
// 卡片 / 步骤条 / 日志
// ════════════════════════════════════════════════════════════════

/// StatCard 一行：键（弱色 Small）+ 值（Body/Mono）+ 可选行尾状态点 + 可选复制按钮。
/// `small`（M8-T034）：值改用 `theme.small_size`（身份卡整体小字号）。
/// `dot`（M8-T037）：`Some((color, tooltip))` → 值后渲染彩色「●」状态点
/// （无文字，行内紧凑；如公网检测红/绿点），`None` 不渲染（既有调用点零影响）。
pub struct StatRow<'a> {
    pub key: &'a str,
    pub value: String,
    pub mono: bool,
    pub copy: bool,
    pub small: bool,
    pub dot: Option<(Color32, &'static str)>,
    /// （`None` = 不渲染 hover，既有调用点零影响）。信息不丢失：hover 可见全文。
    pub tip: Option<String>,
}

/// 信息卡片（§4 StatCard）：标题栏（Small 弱色）+ 分隔线 + 键值行。
/// 返回本帧被复制的内容（`None` = 未复制；M8-T028 状态栏浮出提示用）。
// 本入口无调用者——保留（组件库对称 API，供后续卡面复用）并标注。
#[allow(dead_code)]
pub fn stat_card(ui: &mut Ui, theme: &Theme, title: &str, rows: &[StatRow<'_>]) -> Option<String> {
    stat_card_impl(ui, theme, title, rows, None)
}

/// 信息卡片 + 底部提示行（M8-T037：公网检测建议「无公网地址建议开启内网穿透
/// 或端口转发」等随卡展示的提示）。`footer = Some((color, text))` → 卡底渲染
/// 一行小字号彩色提示（无圆点）；`None` → 与 `stat_card` 完全一致。
pub fn stat_card_with_footer(
    ui: &mut Ui,
    theme: &Theme,
    title: &str,
    rows: &[StatRow<'_>],
    footer: Option<(Color32, String)>,
) -> Option<String> {
    stat_card_impl(ui, theme, title, rows, footer)
}

fn stat_card_impl(
    ui: &mut Ui,
    theme: &Theme,
    title: &str,
    rows: &[StatRow<'_>],
    footer: Option<(Color32, String)>,
) -> Option<String> {
    let mut copied: Option<String> = None;
    egui::Frame::none()
        .fill(theme.bg_panel)
        .stroke(Stroke::new(theme.border_width, theme.border))
        .rounding(theme.rounding_card)
        .inner_margin(egui::Margin::same(theme.card_padding))
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(
                    RichText::new(title)
                        .size(theme.small_size)
                        .strong()
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            ui.add_space(2.0);
            ui.separator();
            for row in rows {
                // 其 `response` 覆盖整行 rect（`ui.horizontal` 的闭包返回
                // `InnerResponse<()>` 无整区 Response，故经 Frame 取整行响应）。
                let row_frame = egui::Frame::none().show(ui, |ui| {
                    ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(row.key)
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                    ui.add_space(6.0);
                    let mut rt = RichText::new(&row.value).color(theme.fg);
                    if row.mono {
                        rt = rt.monospace();
                    }
                    // M8-T034: `small` → small_size（身份卡小字号）；否则按
                    // mono/body 既有字号。
                    rt = rt.size(if row.small {
                        theme.small_size
                    } else if row.mono {
                        theme.mono_size
                    } else {
                        theme.body_size
                    });
                    ui.add(egui::Label::new(rt).selectable(true));
                    // M8-T037: 行尾状态点（值后、复制按钮前；如公网检测红/绿点）。
                    if let Some((color, tip)) = row.dot {
                        let dot = ui.add(
                            egui::Label::new(
                                RichText::new("●")
                                    .size(if row.small {
                                        theme.small_size
                                    } else {
                                        theme.body_size
                                    })
                                    .color(color),
                            )
                            .selectable(false),
                        );
                        dot.on_hover_text(tip);
                    }
                        if row.copy {
                            let (_, was_copied) = copy_button(ui, theme, &row.value);
                            if was_copied {
                                copied = Some(row.value.clone());
                            }
                        }
                    });
                });
                // 行解释「别名 ≠ 连接用 ID」、监听端口行解释 NAT 端口转发）——
                // Frame 的 Response 仅为 hover 挂点，不拦截行内点击
                // （复制按钮/可选值交互不受影响）。
                if let Some(tip) = &row.tip {
                    row_frame.response.on_hover_text(tip.as_str());
                }
            }
            // M8-T037: 卡底提示行（公网检测建议等）。
            if let Some((color, text)) = footer {
                ui.add_space(2.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(text)
                            .size(theme.small_size)
                            .color(color),
                    )
                    .selectable(false),
                );
            }
        });
    copied
}

/// 通用卡片容器（服务器控制卡等非键值内容用）。
pub fn card(ui: &mut Ui, theme: &Theme, title: &str, add_contents: impl FnOnce(&mut Ui)) {
    card_with_title_tip(ui, theme, title, None, add_contents)
}

/// hover，如 Dashboard「服务端设置」卡的生效时机/凭据语义说明）。
/// `title_tip = None` 时与 [`card`] 逐位一致。
pub fn card_with_title_tip(
    ui: &mut Ui,
    theme: &Theme,
    title: &str,
    title_tip: Option<&str>,
    add_contents: impl FnOnce(&mut Ui),
) {
    egui::Frame::none()
        .fill(theme.bg_panel)
        .stroke(Stroke::new(theme.border_width, theme.border))
        .rounding(theme.rounding_card)
        .inner_margin(egui::Margin::same(theme.card_padding))
        .show(ui, |ui| {
            let title_resp = ui.add(
                egui::Label::new(
                    RichText::new(title)
                        .size(theme.small_size)
                        .strong()
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            if let Some(tip) = title_tip {
                title_resp.on_hover_text(tip);
            }
            ui.add_space(2.0);
            ui.separator();
            add_contents(ui);
        });
}

/// 步骤条（§4 Stepper）：已完成 = success，当前 = primary，未到 = fg_weak。
pub fn stepper(ui: &mut Ui, theme: &Theme, steps: &[&str], current: usize) {
    ui.horizontal(|ui| {
        for (i, step) in steps.iter().enumerate() {
            if i > 0 {
                ui.add(
                    egui::Label::new(
                        RichText::new("→")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            }
            let (dot, color) = if i < current {
                ("●", theme.success)
            } else if i == current {
                ("●", theme.primary)
            } else {
                ("○", theme.fg_weak)
            };
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{dot} {step}"))
                        .size(theme.small_size)
                        .color(color),
                )
                .selectable(false),
            );
        }
    });
}

/// LogView 选项。
pub struct LogViewOptions<'a> {
    /// 头部标题（沿用既有文案，如 "Live Log" / "Connection Log:"）。
    pub title: &'a str,
    /// 空内容占位文案。
    pub empty: &'a str,
    pub max_height: f32,
    /// 是否显示「Clear」按钮（点击调用 `clear` 回调）。
    pub clearable: bool,
    /// 清空回调（无借用冲突的 `fn()`，如 `crate::clear_gui_log`）。
    pub clear: Option<fn()>,
}

/// 日志视图（§4 LogView）：等宽 16px；按行前缀解析级别着色
/// （INFO=fg_weak、WARN=warning、ERROR=danger）；`stick_to_bottom`；右上角 Clear/Copy。
pub fn log_view(ui: &mut Ui, theme: &Theme, text: &str, opts: &LogViewOptions<'_>) {
    ui.horizontal(|ui| {
        ui.add(
            egui::Label::new(
                RichText::new(opts.title)
                    .size(theme.small_size)
                    .strong()
                    .color(theme.fg_weak),
            )
            .selectable(false),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Copy").clicked() {
                ui.output_mut(|o| o.copied_text = text.to_owned());
            }
            if opts.clearable {
                if ui.small_button("Clear").clicked() {
                    if let Some(clear) = opts.clear {
                        clear();
                    }
                }
            }
        });
    });
    egui::ScrollArea::vertical()
        .max_height(opts.max_height)
        .stick_to_bottom(true)
        .show(ui, |ui| {
            if text.is_empty() {
                ui.add(
                    egui::Label::new(
                        RichText::new(opts.empty)
                            .monospace()
                            .size(theme.mono_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                return;
            }
            for line in text.lines() {
                let color = level_color(theme, line);
                ui.add(
                    egui::Label::new(
                        RichText::new(line)
                            .monospace()
                            .size(theme.mono_size)
                            .color(color),
                    )
                    .selectable(true),
                );
            }
        });
}

fn level_color(theme: &Theme, line: &str) -> Color32 {
    if line.contains("ERROR") {
        theme.danger
    } else if line.contains(" WARN ") {
        theme.warning
    } else if line.contains(" INFO ") || line.contains("DEBUG") || line.contains("TRACE") {
        theme.fg_weak
    } else {
        theme.fg
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// 文本标记启发式；raw 日志行经文本标记判级后入同一模型）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnLogLevel {
    /// 进行中提示 / 一般页级提示。
    Info,
    /// 成功终态（连接成功 / 传输完成）。
    Success,
    /// WARN 级 raw 日志行。
    Warn,
    /// 错误终态 / ERROR 级 raw 日志行 / 传输失败。
    Error,
}

impl ConnLogLevel {
    /// 级别 → 主题色（组件层零裸值）。
    pub fn color(self, theme: &Theme) -> Color32 {
        match self {
            ConnLogLevel::Info => theme.fg_weak,
            ConnLogLevel::Success => theme.success,
            ConnLogLevel::Warn => theme.warning,
            ConnLogLevel::Error => theme.danger,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnLogSeg {
    /// 纯文本段。
    Text(String),
    /// 「目录」段（品牌蓝、可点击）：`path` = 点击复制的具体路径
    /// （本机端 = 本机目录全路径；对端 = 根相对路径 / `root` 标记——
    Dir { path: String },
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConnLogLine {
    pub level: ConnLogLevel,
    pub segments: Vec<ConnLogSeg>,
    /// 连续同事件合并计数（1 = 首发；>1 渲染追加「 ×N」）。
    pub count: u32,
    /// 一次性复制反馈（Dir 段点击复制后置位 → 行尾「 ✓」）。
    pub copied: bool,
}

impl ConnLogLine {
    /// 纯文本形态（整框 Copy 按钮 / 测试断言）：Dir 段按显示文案（「目录」）
    /// 展开，计数/复制标记同渲染口径追加。
    pub fn plain_text(&self) -> String {
        let mut s = String::new();
        for seg in &self.segments {
            match seg {
                ConnLogSeg::Text(t) => s.push_str(t),
                ConnLogSeg::Dir { .. } => s.push_str(&t!("connect.log.dir")),
            }
        }
        if self.count > 1 {
            s.push_str(" ×");
            s.push_str(&self.count.to_string());
        }
        if self.copied {
            s.push_str(" ✓");
        }
        s
    }
}

pub const CONN_LOG_CAPACITY: usize = 500;
pub const CONN_LOG_MERGE_CAP: u32 = 999;

/// 会话引擎线程 / UI 线程并发写——`Mutex` 内锁不跨帧）。
pub struct ConnLogBuffer {
    inner: std::sync::Mutex<ConnLogBufferInner>,
}

struct ConnLogBufferInner {
    lines: std::collections::VecDeque<ConnLogLine>,
    capacity: usize,
}

impl ConnLogBuffer {
    pub fn new(capacity: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            inner: std::sync::Mutex::new(ConnLogBufferInner {
                lines: std::collections::VecDeque::with_capacity(capacity),
                capacity,
            }),
        })
    }

    /// 推入一行：**尾部连续同级别同段行 = 合并计数**（`count` 封顶
    /// [`CONN_LOG_MERGE_CAP`] 后**冻结**——长时重复事件恒单行不碎片化，
    /// 重复行不刷屏）；否则追加新行 + 环形逐出最旧。
    /// 入参 `count`/`copied` 一律归零（新事件 = count 1、未复制）。
    pub fn push(&self, line: ConnLogLine) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(last) = inner.lines.back_mut() {
            if last.level == line.level && last.segments == line.segments {
                last.count = last.count.saturating_add(1).min(CONN_LOG_MERGE_CAP);
                return;
            }
        }
        let mut line = line;
        line.count = 1;
        line.copied = false;
        while inner.lines.len() >= inner.capacity {
            inner.lines.pop_front();
        }
        inner.lines.push_back(line);
    }

    /// 全量快照（渲染用；与缓冲顺序一致，下标可回写 [`Self::mark_copied`]）。
    pub fn snapshot(&self) -> Vec<ConnLogLine> {
        self.inner.lock().unwrap().lines.iter().cloned().collect()
    }

    /// M15-T008 同档：清空（连接日志框 Clear 按钮）。
    pub fn clear(&self) {
        self.inner.lock().unwrap().lines.clear();
    }

    /// 置「已复制」一次性反馈（按下标 = 快照/渲染序）。
    pub fn mark_copied(&self, line_idx: usize) {
        if let Some(l) = self.inner.lock().unwrap().lines.get_mut(line_idx) {
            l.copied = true;
        }
    }
}

///
/// 用户草图：`从（本机|<设备id>）目录 到（本机|<设备id>）目录 文件或文件夹（<名称>）`
/// —— 两处「目录」二字 = [`ConnLogSeg::Dir`] 段（品牌蓝、点击复制该端具体
/// 路径、悬停 1s 提示「点击复制路径」）；`from_local` 决定两端标识归属
/// （true = 本机→对端〔上传〕，false = 对端→本机〔下载〕）。
/// 行首方向定性词 = `上传：`/`下载：`（按 `from_local` 择键，与从/到两侧
/// 归属同源判定、零固定侧）；失败行同带方向词。
/// `failed_reason` = `Some` → 行尾追加失败原因后缀 + 级别 Error；
/// `None` = 级别 Success（完成）。
pub fn build_transfer_line(
    from_local: bool,
    local_label: &str,
    peer_label: &str,
    from_dir: &str,
    to_dir: &str,
    name: &str,
    failed_reason: Option<&str>,
) -> ConnLogLine {
    let (from_side, to_side) = if from_local {
        (local_label, peer_label)
    } else {
        (peer_label, local_label)
    };
    let level = match failed_reason {
        Some(_) => ConnLogLevel::Error,
        None => ConnLogLevel::Success,
    };
    let mut segments = vec![
        ConnLogSeg::Text(crate::i18n::tr_fmt(
            if from_local {
                "connect.log.transfer.dir_upload"
            } else {
                "connect.log.transfer.dir_download"
            },
            &[],
        )),
        ConnLogSeg::Text(crate::i18n::tr_fmt(
            "connect.log.transfer.from",
            &[from_side.to_string()],
        )),
        ConnLogSeg::Dir {
            path: from_dir.to_string(),
        },
        ConnLogSeg::Text(crate::i18n::tr_fmt(
            "connect.log.transfer.to",
            &[to_side.to_string()],
        )),
        ConnLogSeg::Dir {
            path: to_dir.to_string(),
        },
        ConnLogSeg::Text(crate::i18n::tr_fmt(
            "connect.log.transfer.what",
            &[name.to_string()],
        )),
    ];
    if let Some(reason) = failed_reason {
        segments.push(ConnLogSeg::Text(crate::i18n::tr_fmt(
            "connect.log.transfer.failed",
            &[reason.to_string()],
        )));
    }
    ConnLogLine {
        level,
        segments,
        count: 1,
        copied: false,
    }
}

/// 槽字符串：busy 前缀 = Info（进行中提示）；终态按失败/成功标记分色
/// （`FAILED/ERROR/MISMATCH/refused/declined/aborted` → Error；
/// `Connected/SUCCESS` → Success；无标记 → Info）。
pub fn conn_prompt_level(status: &str) -> ConnLogLevel {
    if crate::policy::is_connect_status_busy(status) {
        return ConnLogLevel::Info;
    }
    let s = status.strip_prefix("[shell] ").unwrap_or(status);
    const FAIL_MARKERS: &[&str] = &[
        "FAILED",
        "ERROR",
        "MISMATCH",
        "refused",
        "declined",
        "aborted",
    ];
    if FAIL_MARKERS.iter().any(|m| s.contains(m)) {
        ConnLogLevel::Error
    } else if s.contains("Connected") || s.contains("SUCCESS") {
        ConnLogLevel::Success
    } else {
        ConnLogLevel::Info
    }
}

/// 提示「点击复制路径」——经 [`crate::hover_hint`] 延迟参数化入口实现，
/// 状态机去抖/迟滞/指针区域排除语义零变化）。
pub const CONN_LOG_DIR_TIP_DELAY: f64 = 1.0;

pub struct ConnLogViewOptions<'a> {
    /// 头部标题（沿用既有文案 `connect.log.title`）。
    pub title: &'a str,
    /// 空内容占位文案。
    pub empty: &'a str,
    pub max_height: f32,
    /// 是否显示「Clear」按钮（点击调用 `clear` 回调）。
    pub clearable: bool,
    /// 清空回调（无借用冲突的 `fn()`）。
    pub clear: Option<fn()>,
    pub dir_tip: &'a str,
}

///
/// - 级别着色（[`ConnLogLevel::color`]）；等宽 [`Theme::mono_size`]；
/// - [`ConnLogSeg::Dir`] 段 = 品牌蓝（`theme.primary`，链接语义）+ 可点击：
///   点击调 `on_dir_click(line_idx, path)`（调用点 = 剪贴板写入 +
///   [`ConnLogBuffer::mark_copied`] 一次性 ✓ 反馈）；悬停满
///   [`CONN_LOG_DIR_TIP_DELAY`]（1s）→ tooltip `opts.dir_tip`
///   （[`crate::hover_hint::hover_hint_delay`] 1s 门控入口）；
/// - 合并计数「 ×N」（count>1）/ 已复制「 ✓」行尾追加；
/// - `stick_to_bottom` + `max_height`（同旧 `log_view` 口径；长列表渲染
///   成本 = ScrollArea 视口虚拟化，仅可视段布局）。
/// `probe` = 测试/布局探针（Dir 段 rect 采集；生产传 `None` 零开销）。
pub fn conn_log_view(
    ui: &mut Ui,
    theme: &Theme,
    lines: &[ConnLogLine],
    opts: &ConnLogViewOptions<'_>,
    on_dir_click: &mut dyn FnMut(usize, &str),
    mut probe: Option<&mut dyn FnMut(usize, usize, egui::Rect)>,
) {
    ui.horizontal(|ui| {
        ui.add(
            egui::Label::new(
                RichText::new(opts.title)
                    .size(theme.small_size)
                    .strong()
                    .color(theme.fg_weak),
            )
            .selectable(false),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Copy").clicked() {
                let all = lines
                    .iter()
                    .map(|l| l.plain_text())
                    .collect::<Vec<_>>()
                    .join("\n");
                ui.output_mut(|o| o.copied_text = all);
            }
            if opts.clearable {
                if ui.small_button("Clear").clicked() {
                    if let Some(clear) = opts.clear {
                        clear();
                    }
                }
            }
        });
    });
    egui::ScrollArea::vertical()
        .max_height(opts.max_height)
        .stick_to_bottom(true)
        .show(ui, |ui| {
            if lines.is_empty() {
                ui.add(
                    egui::Label::new(
                        RichText::new(opts.empty)
                            .monospace()
                            .size(theme.mono_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                return;
            }
            for (li, line) in lines.iter().enumerate() {
                ui.horizontal_wrapped(|ui| {
                    let row_color = line.level.color(theme);
                    for (si, seg) in line.segments.iter().enumerate() {
                        match seg {
                            ConnLogSeg::Text(t) => {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(t)
                                            .monospace()
                                            .size(theme.mono_size)
                                            .color(row_color),
                                    )
                                    .selectable(true),
                                );
                            }
                            ConnLogSeg::Dir { path } => {
                                let resp = ui.add(
                                    egui::Label::new(
                                        RichText::new(t!("connect.log.dir"))
                                            .monospace()
                                            .size(theme.mono_size)
                                            .strong()
                                            .color(theme.primary),
                                    )
                                    .selectable(false)
                                    .sense(egui::Sense::click() | egui::Sense::hover()),
                                );
                                if let Some(p) = probe.as_deref_mut() {
                                    p(li, si, resp.rect);
                                }
                                if resp.clicked() {
                                    on_dir_click(li, path);
                                }
                                // 悬停 1s 门控 tooltip（per-段 id；状态存
                                // hover_hint temp 域，去抖/迟滞/指针排除同
                                let id = conn_log_dir_hover_id(li, si);
                                crate::hover_hint::hover_hint_delay(
                                    ui.ctx(),
                                    id,
                                    &resp,
                                    theme,
                                    opts.dir_tip,
                                    CONN_LOG_DIR_TIP_DELAY,
                                );
                            }
                        }
                    }
                    if line.count > 1 {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(" ×{}", line.count))
                                    .monospace()
                                    .size(theme.mono_size)
                                    .color(theme.fg_weak),
                            )
                            .selectable(false),
                        );
                    }
                    if line.copied {
                        ui.add(
                            egui::Label::new(
                                RichText::new(" ✓")
                                    .monospace()
                                    .size(theme.mono_size)
                                    .color(theme.success),
                            )
                            .selectable(false),
                        );
                    }
                });
            }
        });
}

pub(crate) fn conn_log_dir_hover_id(line_idx: usize, seg_idx: usize) -> egui::Id {
    egui::Id::new((0x5231_3432_3144u64, line_idx, seg_idx))
}

// ════════════════════════════════════════════════════════════════
// 单测（headless egui Context，验证组件可布局不 panic）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 两套主题下把全部组件跑一遍布局（纯函数冒烟，验证无 panic/无限布局）。
    #[test]
    fn test_widgets_smoke_both_themes() {
        for theme in [Theme::LIGHT, Theme::DARK] {
            let ctx = egui::Context::default();
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let t = &theme;
                    let mut text = "secret-value".to_owned();
                    let mut show = false;
                    let mut sel = 0usize;
                    badge(ui, t, "v0.1.0", BadgeKind::Neutral);
                    badge(ui, t, "API: Ready", BadgeKind::Success);
                    status_dot(ui, t.success, "Server: Listening");
                    status_dot_char(ui, t.fg_weak, "○", "Stopped");
                    action_button(ui, t, ButtonKind::Primary, "Connect", ButtonState::Enabled);
                    action_button(ui, t, ButtonKind::Secondary, "Connect Shell", ButtonState::Busy);
                    action_button(ui, t, ButtonKind::Success, "✓ Accept", ButtonState::Enabled);
                    action_button(ui, t, ButtonKind::Danger, "✗ Reject", ButtonState::Disabled);
                    selectable_pill(ui, t, "🏠 Dashboard", true, 0.0);
                    selectable_pill(ui, t, "🖥 Devices", false, 0.0);
                    segmented_control(ui, t, &["IP Mode", "Domain Mode"], &mut sel);
                    toolbar_button(ui, t, "▣", "Fullscreen (F11)");
                    toolbar_button(ui, t, "✖", "Disconnect");
                    copy_button(ui, t, "2001:db8::1");
                    copy_button(ui, t, ""); // 空值禁用（UI-BTY-023）
                    labeled_input(
                        ui,
                        t,
                        "IPv6 Address:",
                        &mut text,
                        "2001:db8::1",
                        Validity::Valid,
                        None,
                        true,
                    );
                    labeled_input(
                        ui,
                        t,
                        "Challenge:",
                        &mut text,
                        "required",
                        Validity::Invalid("Challenge is required"),
                        Some(&mut show),
                        false,
                    );
                    stepper(ui, t, &["Discovering", "Connecting", "Handshaking", "Connected"], 2);
                    stat_card(
                        ui,
                        t,
                        "Identity",
                        &[
                        StatRow {
                            key: "Device ID:",
                            value: "my-pc".to_owned(),
                            mono: true,
                            copy: true,
                            small: true,
                            dot: None,
                            tip: None,
                        },
                        StatRow {
                            key: "IPv6:",
                            value: "2001:db8::1".to_owned(),
                            mono: true,
                            copy: true,
                            small: true,
                            dot: Some((t.success, "公网地址，可直连")),
                            tip: None,
                        },
                        StatRow {
                            key: "API:",
                            value: "Ready".to_owned(),
                            mono: false,
                            copy: false,
                            small: false,
                            dot: None,
                        },
                        ],
                    );
                    card(ui, t, "Server", |ui| {
                        status_dot(ui, t.success, "Listening");
                    });
                    card_with_title_tip(
                        ui,
                        t,
                        "Server settings",
                        Some("Read at server start — takes effect on next start."),
                        |ui| {
                            status_dot(ui, t.success, "Listening");
                        },
                    );
                    log_view(
                        ui,
                        t,
                        "2026-08-01T00:00:00Z  INFO module: hello\n2026-08-01T00:00:00Z  WARN module: careful\n2026-08-01T00:00:00Z ERROR module: boom\nplain line",
                        &LogViewOptions {
                            title: "Live Log",
                            empty: "(no log output yet)",
                            max_height: 120.0,
                            clearable: true,
                            clear: None,
                        },
                    );
                    log_view(
                        ui,
                        t,
                        "",
                        &LogViewOptions {
                            title: "Connection Log:",
                            empty: "(no connection log yet)",
                            max_height: 60.0,
                            clearable: false,
                            clear: None,
                        },
                    );
                });
            });
        }
    }

    /// M8-T028 (UI-BTY-023/028): 点击 📋 → 剪贴板写入 + 返回 (Response, bool) 上抛
    /// + ✓ 瞬态记忆；空值按钮禁用（headless 模拟按下/释放）。
    #[test]
    fn test_copy_button_click_and_disabled() {
        let ctx = egui::Context::default();
        let mut btn_id = egui::Id::NULL;
        let mut btn_rect = egui::Rect::NOTHING;
        // 帧 1：布局并记录按钮位置/id；空值按钮为禁用态。
        ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let t = &Theme::LIGHT;
                let (r, copied) = copy_button(ui, t, "hello");
                btn_id = r.id;
                btn_rect = r.rect;
                assert!(r.enabled());
                assert!(!copied);
                let (r2, _) = copy_button(ui, t, "");
                assert!(!r2.enabled());
            });
        });
        // 帧 2：按下 + 释放（同一帧）——点击当帧生效（egui 帧末结算快照，
        // 同帧 get_response 即可读到 clicked()）；end_frame 会 mem::take 走
        // viewport.output → 从该帧 FullOutput 读剪贴板内容。
        let press = |pressed: bool| egui::Event::PointerButton {
            pos: btn_rect.center(),
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::default(),
        };
        let full = ctx.run(
            egui::RawInput {
                events: vec![press(true), press(false)],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let (r, copied) = copy_button(ui, &Theme::LIGHT, "hello");
                    assert!(r.clicked());
                    assert!(copied); // 复制发生 → 上抛（调用方据此浮出提示）
                });
            },
        );
        assert_eq!(full.platform_output.copied_text, "hello");
        // ✓ 瞬态记忆已按按钮 id 写入（1.5s 内下一帧起显示 ✓）。
        assert!(ctx.data(|d| d.get_temp::<std::time::Instant>(btn_id).is_some()));
        // 帧 3：无点击 → 不再写入。
        ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let (r, copied) = copy_button(ui, &Theme::LIGHT, "hello");
                assert!(!r.clicked());
                assert!(!copied);
            });
        });
    }

    /// M8-T034: 滑动开关 headless 行为——正常渲染（含状态文字）不 panic、
    /// 无点击不上抛；帧 2 点击轨道 → `clicked()` 上抛（on 翻转由调用方完成，
    /// 组件本身只报点击）。
    #[test]
    fn test_toggle_switch_click_and_layout() {
        let ctx = egui::Context::default();
        let mut switch_rect = egui::Rect::NOTHING;
        ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let t = &Theme::LIGHT;
                let r = toggle_switch(ui, t, "允许受控", true, Some("监听中 :3389"));
                switch_rect = r.rect;
                assert!(r.enabled());
                assert!(!r.clicked());
                let r2 = toggle_switch(ui, t, "临时连接", false, None);
                assert!(!r2.clicked());
            });
        });
        // 帧 2：按下 + 释放（同一帧）→ 点击当帧生效。
        let press = |pressed: bool| egui::Event::PointerButton {
            pos: switch_rect.center(),
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::default(),
        };
        ctx.run(
            egui::RawInput {
                events: vec![press(true), press(false)],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let r = toggle_switch(ui, &Theme::LIGHT, "允许受控", true, Some("监听中 :3389"));
                    assert!(r.clicked());
                });
            },
        );
    }

    /// 区间（178..=217 = ×255 量化）；②`toolbar_widget_fill` = 主题
    /// `bg_strong` RGB × 传入 alpha（rgba unmultiplied）；③静止档低于
    /// 悬停档（悬停恢复不透明 `bg_panel` = 更高不透明度，点击辨识）；
    /// ④headless 渲染冒烟（半透明底不 panic/不无限布局，双主题）。
    #[test]
    fn test_r165_toolbar_widget_alpha() {
        // ①区间钉死（0.70×255≈178.5、0.85×255≈216.75）。
        assert_eq!(TOOLBAR_WIDGET_ALPHA, 200);
        assert!((178..=217).contains(&TOOLBAR_WIDGET_ALPHA));
        for theme in [Theme::LIGHT, Theme::DARK] {
            // ②RGB 同源 + alpha 透传。
            let f = toolbar_widget_fill(&theme, TOOLBAR_WIDGET_ALPHA);
            let [r, g, b, _] = theme.bg_strong.to_srgba_unmultiplied();
            assert_eq!(
                f,
                egui::Color32::from_rgba_unmultiplied(r, g, b, TOOLBAR_WIDGET_ALPHA)
            );
            assert_eq!(toolbar_widget_fill(&theme, 0).a(), 0);
            // ③静止半透明 < 悬停不透明（恢复链路语义）。
            assert!(f.a() < 255);
            assert_eq!(theme.bg_panel.a(), 255);
        }
        // ④headless 冒烟：toolbar_button 半透明底双帧零 panic。
        let ctx = egui::Context::default();
        for _ in 0..2 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    toolbar_button(ui, &Theme::LIGHT, "▣", "Fullscreen (F11)");
                });
            });
        }
    }

    /// 密文编辑启发式：追加/回删同步真实值。
    #[test]
    fn test_secret_sync_heuristic() {        let mut value = "abc".to_owned();
        let prev: String = "•".repeat(value.chars().count());
        // 追加
        let mut edited = prev.clone();
        edited.push('x');
        let prev_len = value.chars().count();
        if edited
            .chars()
            .take(prev_len)
            .eq(prev.chars().take(prev_len))
        {
            for c in edited.chars().skip(prev_len) {
                value.push(c);
            }
        }
        assert_eq!(value, "abcx");
        // 回删
        let mut edited2 = "••".to_owned();
        let prev2: String = "•".repeat(value.chars().count());
        if prev2.chars().take(2).eq(edited2.chars()) {
            let new_val: String = value.chars().take(2).collect();
            value = new_val;
        }
        assert_eq!(value, "ab");
    }

    /// 运行时「宽稳定 ≤ 420 逐帧不右移」由 `max_size` 双 clamp + 手工判据
    #[test]
    fn test_r86u_dialog_width_constants() {
        assert!(DIALOG_MIN_WIDTH > 0.0 && DIALOG_MAX_WIDTH.is_finite());
        assert!(
            DIALOG_MIN_WIDTH < DIALOG_MAX_WIDTH,
            "min 必须小于 max（否则 Window min/max 冲突）"
        );
        // 量化验收锚：上界 = 420px（用户「持续向右延申」的硬顶）。
        assert_eq!(DIALOG_MAX_WIDTH, 420.0);
        // 下界须容得下标签列 + 输入框最小宽（`labeled_input` 字段
        // `max(120.0)` 下界 + 窗内边距 2×12），否则受限宽内字段被挤破。
        assert!(DIALOG_MIN_WIDTH >= 120.0 + 2.0 * 12.0);
    }

    ///
    /// 门禁③诊断复盘：隔离目录截屏一度「行 tip 不弹」，根因是探针坐标偏离线顶
    /// 数个 px（窗口位置变化后的陈旧坐标），挂点本身无恙——文本级 ground
    /// truth（egui 层状态 `widget_with_tooltip` = 行 widget id）+ 像素级截屏
    /// （tip 全文可见、行面干净）双重确认。本测试固化**实际在用的挂点**：
    /// 指针进入 → 静置 3s（> `tooltip_delay` 1.5s）→ `is_tooltip_open` 必须
    /// 为真。每个挂点独立新建 `Context`（egui「每层一个 tooltip、先到先占」
    /// 门禁下，共用 ctx 会互相抑制，造成假阴性）。
    #[test]
    fn test_r88b4_row_tip_anchor_opens() {
        use egui::{CentralPanel, RawInput};

        fn hover_pattern(build: impl Fn(&mut egui::Ui) -> egui::Response) -> bool {
            let ctx = egui::Context::default();
            let mut target_rect = egui::Rect::NOTHING;
            // F0：布局并记录目标 rect。
            ctx.run(RawInput::default(), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    target_rect = build(ui).rect;
                });
            });
            // F1：指针移到目标中心（last_movement = t100）。
            ctx.run(
                RawInput {
                    time: Some(100.0),
                    events: vec![egui::Event::PointerMoved(target_rect.center())],
                    ..Default::default()
                },
                |ctx| {
                    CentralPanel::default().show(ctx, |ui| {
                        let _ = build(ui);
                    });
                },
            );
            // F2：静置 3s（> tooltip_delay 1.5s）→ tooltip 应在本帧渲染。
            ctx.run(
                RawInput {
                    time: Some(103.0),
                    ..Default::default()
                },
                |ctx| {
                    CentralPanel::default().show(ctx, |ui| {
                        let _ = build(ui);
                    });
                },
            );
            // F3：查「上一帧 tooltip 是否打开」（反映 F2 的渲染结果）。
            let mut open = false;
            ctx.run(
                RawInput {
                    time: Some(103.5),
                    ..Default::default()
                },
                |ctx| {
                    CentralPanel::default().show(ctx, |ui| {
                        open = build(ui).is_tooltip_open();
                    });
                },
            );
            open
        }

        fn row_content(ui: &mut egui::Ui) {
            ui.add(
                egui::Label::new(egui::RichText::new("设备别名（DNS 设备名）：")).selectable(false),
            );
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(egui::RichText::new("4DT5PQAFE4").monospace())
                    .selectable(true),
            );
            ui.add_space(80.0);
        }


        // ① 对照：按钮挂点（pill/toggle 同类件——`on_hover_text` 链式挂接）。
        assert!(
            hover_pattern(|ui| {
                let r = ui.add(
                    egui::Button::new(egui::RichText::new("对照按钮"))
                        .min_size(egui::vec2(80.0, 24.0)),
                );
                r.on_hover_text(TIP)
            }),
            "对照：按钮挂点必须能打开 tooltip（harness 自检）"
        );
        // ② 生产挂点：行 `Frame` 的 Response——`stat_card_impl` 行级收纳
        // （widgets.rs，`row_frame.response.on_hover_text`）实际在用的挂点。
        assert!(
            hover_pattern(|ui| {
                let fr = egui::Frame::none().show(ui, |ui| {
                    ui.horizontal(|ui| row_content(ui));
                });
                fr.response.on_hover_text(TIP)
            }),
            "行 Frame::none().show().response 挂点必须能打开行级 hover 提示"
        );
        // ③ 子件挂点：行内值 Label 自身 Response（状态点行 `dot.on_hover_text`
        // 同类挂点）——tooltip 状态须查子响应本身（非外层 horizontal 响应）。
        assert!(
            hover_pattern(|ui| {
                // 闭包返回 R = 值 Label 的 Response；取 `InnerResponse::inner`
                // （不是 horizontal 自身的 `.response`——tooltip 挂在子件上）。
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(egui::RichText::new("设备别名（DNS 设备名）："))
                            .selectable(false),
                    );
                    ui.add_space(6.0);
                    let v = ui.add(
                        egui::Label::new(egui::RichText::new("4DT5PQAFE4").monospace())
                            .selectable(true),
                    );
                    ui.add_space(80.0);
                    v.on_hover_text(TIP)
                })
                .inner
            }),
            "行内子 Label 挂点（dot 行同类）必须能打开 hover 提示"
        );
    }

    // ────────────────────────────────────────────────────────────────
    // ────────────────────────────────────────────────────────────────

    /// （上传/下载 × 成功/失败）——**行首方向词 + 从/到两侧按事件真实
    /// 方向归属（零固定侧）** + 段结构 + 两处 Dir 段复制路径提取 + 级别 +
    /// 先例）。
    #[test]
    fn r142_1_transfer_line_matrix() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);

        // ① 上传成功：「上传：从（本机）目录 到（DEV123）目录 文件或
        //    文件夹（a.txt）」（本机端全路径 / 对端根相对）。
        let up = build_transfer_line(
            true,
            "本机",
            "DEV123",
            "D:\\src\\a",
            "docs/b",
            "a.txt",
            None,
        );
        assert!(matches!(up.level, ConnLogLevel::Success));
        assert_eq!(
            up.segments,
            vec![
                ConnLogSeg::Text("上传：".to_string()),
                ConnLogSeg::Text("从（本机）".to_string()),
                ConnLogSeg::Dir {
                    path: "D:\\src\\a".to_string(),
                },
                ConnLogSeg::Text(" 到（DEV123）".to_string()),
                ConnLogSeg::Dir {
                    path: "docs/b".to_string(),
                },
                ConnLogSeg::Text(" 文件或文件夹（a.txt）".to_string()),
            ]
        );
        // 复制路径 = Dir 段 path 字段按段序提取（本机全路径、对端根相对）。
        let dirs: Vec<&str> = up
            .segments
            .iter()
            .filter_map(|s| match s {
                ConnLogSeg::Dir { path } => Some(path.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(dirs, vec!["D:\\src\\a", "docs/b"]);
        // plain_text：Dir 段按显示文案「目录」展开（整框 Copy 口径）。
        assert_eq!(
            up.plain_text(),
            "上传：从（本机）目录 到（DEV123）目录 文件或文件夹（a.txt）"
        );

        // ② 上传失败：方向词 + 两侧归属同①，级别 Error + 失败原因后缀
        //    （失败行同带方向词——用户口径第 2 条）。
        let up_fail = build_transfer_line(
            true,
            "本机",
            "DEV123",
            "D:\\src\\a",
            "docs/b",
            "a.txt",
            Some("io"),
        );
        assert!(matches!(up_fail.level, ConnLogLevel::Error));
        assert_eq!(
            up_fail.segments,
            vec![
                ConnLogSeg::Text("上传：".to_string()),
                ConnLogSeg::Text("从（本机）".to_string()),
                ConnLogSeg::Dir {
                    path: "D:\\src\\a".to_string(),
                },
                ConnLogSeg::Text(" 到（DEV123）".to_string()),
                ConnLogSeg::Dir {
                    path: "docs/b".to_string(),
                },
                ConnLogSeg::Text(" 文件或文件夹（a.txt）".to_string()),
                ConnLogSeg::Text(" —— 失败：io".to_string()),
            ]
        );
        assert!(up_fail.plain_text().starts_with("上传："));
        assert!(up_fail.plain_text().ends_with(" —— 失败：io"));

        // ③ 下载成功：「下载：从（DEV123）目录 到（本机）目录 文件或
        //    文件夹（c.bin）」——两侧归属与上传**互换**（从/到随事件真实
        //    方向，零固定侧）；对端端根相对、本机端全路径。
        let down = build_transfer_line(
            false,
            "本机",
            "DEV123",
            "docs/b",
            "E:\\dl",
            "c.bin",
            None,
        );
        assert!(matches!(down.level, ConnLogLevel::Success));
        assert_eq!(
            down.segments,
            vec![
                ConnLogSeg::Text("下载：".to_string()),
                ConnLogSeg::Text("从（DEV123）".to_string()),
                ConnLogSeg::Dir {
                    path: "docs/b".to_string(),
                },
                ConnLogSeg::Text(" 到（本机）".to_string()),
                ConnLogSeg::Dir {
                    path: "E:\\dl".to_string(),
                },
                ConnLogSeg::Text(" 文件或文件夹（c.bin）".to_string()),
            ]
        );
        assert_eq!(
            down.plain_text(),
            "下载：从（DEV123）目录 到（本机）目录 文件或文件夹（c.bin）"
        );

        // ④ 下载失败：方向词 + 两侧归属同③，Error + 失败原因后缀。
        let down_fail = build_transfer_line(
            false,
            "本机",
            "DEV123",
            "root/x",
            "E:\\dl\\sub",
            "b.bin",
            Some("quota_exceeded"),
        );
        assert!(matches!(down_fail.level, ConnLogLevel::Error));
        assert_eq!(
            down_fail.segments,
            vec![
                ConnLogSeg::Text("下载：".to_string()),
                ConnLogSeg::Text("从（DEV123）".to_string()),
                ConnLogSeg::Dir {
                    path: "root/x".to_string(),
                },
                ConnLogSeg::Text(" 到（本机）".to_string()),
                ConnLogSeg::Dir {
                    path: "E:\\dl\\sub".to_string(),
                },
                ConnLogSeg::Text(" 文件或文件夹（b.bin）".to_string()),
                ConnLogSeg::Text(" —— 失败：quota_exceeded".to_string()),
            ]
        );
        assert!(down_fail.plain_text().ends_with(" —— 失败：quota_exceeded"));
        // 新行 count/copied 恒归 1/false（合并/反馈态不入构建函数）。
        assert_eq!(down_fail.count, 1);
        assert!(!down_fail.copied);
    }

    /// Connected/SUCCESS→Success；无标记→Info；`[shell] ` 前缀剥离）。
    #[test]
    fn r142_1_conn_prompt_level_matrix() {
        assert!(matches!(
            conn_prompt_level("Connecting: 2001:db8::1"),
            ConnLogLevel::Info
        ));
        assert!(matches!(
            conn_prompt_level("[shell] Handshaking: …"),
            ConnLogLevel::Info
        ));
        assert!(matches!(
            conn_prompt_level("Connection FAILED: refused"),
            ConnLogLevel::Error
        ));
        assert!(matches!(
            conn_prompt_level("ERROR: challenge mismatch"),
            ConnLogLevel::Error
        ));
        assert!(matches!(
            conn_prompt_level("Connected: session established"),
            ConnLogLevel::Success
        ));
        assert!(matches!(
            conn_prompt_level("SUCCESS: fingerprint verified"),
            ConnLogLevel::Success
        ));
        assert!(matches!(
            conn_prompt_level("节点配置已应用"),
            ConnLogLevel::Info
        ));
    }

    /// mark_copied / clear（headless，无 IO）。
    #[test]
    fn r142_1_conn_log_ring_merge_cap() {
        let buf = ConnLogBuffer::new(5);
        let mk = |s: &str| ConnLogLine {
            level: ConnLogLevel::Info,
            segments: vec![ConnLogSeg::Text(s.to_string())],
            count: 1,
            copied: false,
        };
        // 连续同事件合并（count 递增，不新增行）。
        buf.push(mk("a"));
        buf.push(mk("a"));
        buf.push(mk("a"));
        // 不同事件 = 新行；隔行同事件不合并（仅尾部连续）。
        buf.push(mk("b"));
        buf.push(mk("a"));
        let snap = buf.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].count, 3);
        assert!(!snap[0].copied);
        assert_eq!(snap[1].count, 1);
        assert_eq!(snap[2].count, 1);
        // 合并封顶：连续 1500 次 → count = CONN_LOG_MERGE_CAP 后冻结。
        let buf2 = ConnLogBuffer::new(5);
        let x = mk("x");
        for _ in 0..1500 {
            buf2.push(x.clone());
        }
        let s2 = buf2.snapshot();
        assert_eq!(s2.len(), 1);
        assert_eq!(s2[0].count, CONN_LOG_MERGE_CAP);
        // 封顶后再推同事件 = 冻结（不 panic、不越界）。
        buf2.push(x);
        assert_eq!(buf2.snapshot()[0].count, CONN_LOG_MERGE_CAP);
        // 环形逐出：容量 5，推 7 行不同事件 → 最旧 2 行逐出。
        let buf3 = ConnLogBuffer::new(5);
        for i in 0..7 {
            buf3.push(mk(&format!("L{i}")));
        }
        let s3 = buf3.snapshot();
        assert_eq!(s3.len(), 5);
        assert_eq!(
            s3[0].segments[0],
            ConnLogSeg::Text("L2".to_string())
        );
        assert_eq!(
            s3[4].segments[0],
            ConnLogSeg::Text("L6".to_string())
        );
        // mark_copied 按下标（快照序 = 缓冲序）；越界静默（不 panic）。
        buf3.mark_copied(0);
        buf3.mark_copied(999);
        let s4 = buf3.snapshot();
        assert!(s4[0].copied);
        assert!(!s4[1].copied);
        assert!(s4[0].plain_text().ends_with(" ✓"));
        // 新行 copied 恒 false（复制反馈不继承）。
        buf3.push(mk("fresh"));
        assert!(!buf3.snapshot().last().unwrap().copied);
        // clear 归零（Clear 按钮口径）。
        buf3.clear();
        assert!(buf3.snapshot().is_empty());
    }

    /// Dir 段按「目录」展开）。
    #[test]
    fn r142_1_plain_text_suffixes() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let mut line = ConnLogLine {
            level: ConnLogLevel::Warn,
            segments: vec![
                ConnLogSeg::Text("从（本机）".to_string()),
                ConnLogSeg::Dir {
                    path: "D:\\a".to_string(),
                },
            ],
            count: 42,
            copied: false,
        };
        assert_eq!(line.plain_text(), "从（本机）目录 ×42");
        line.copied = true;
        assert_eq!(line.plain_text(), "从（本机）目录 ×42 ✓");
        line.count = 1;
        line.copied = false;
        assert_eq!(line.plain_text(), "从（本机）目录");
    }

    /// `on_dir_click(line_idx, path)` 上抛（剪贴板写入由调用点闭包完成）。
    #[test]
    fn r142_1_conn_log_view_dir_click() {
        // 渲染含 `t!`（Dir 段文案）→ 与切语言测试串行化（r92ti 纪律）。
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let ctx = egui::Context::default();
        let lines = vec![
            ConnLogLine {
                level: ConnLogLevel::Info,
                segments: vec![ConnLogSeg::Text("Connecting: …".to_string())],
                count: 1,
                copied: false,
            },
            build_transfer_line(
                true,
                "本机",
                "DEV123",
                "D:\\src\\a",
                "docs/b",
                "a.txt",
                None,
            ),
        ];
        let opts = ConnLogViewOptions {
            title: "连接日志：",
            empty: "（暂无连接日志）",
            max_height: 200.0,
            clearable: false,
            clear: None,
            dir_tip: "点击复制路径",
        };
        let mut dir_rect = egui::Rect::NOTHING;
        // 帧 1：布局 + probe 采 Dir 段 rect（第 2 行第 1 个 Dir 段；
        ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let mut probe = |li: usize, si: usize, r: egui::Rect| {
                    if li == 1 && si == 2 {
                        dir_rect = r;
                    }
                };
                conn_log_view(
                    ui,
                    &Theme::LIGHT,
                    &lines,
                    &opts,
                    &mut |_, _| {},
                    Some(&mut probe),
                );
            });
        });
        assert_ne!(dir_rect, egui::Rect::NOTHING, "probe 应采到 Dir 段 rect");
        // 帧 2：按下+释放 Dir 段中心 → on_dir_click(1, "D:\\src\\a")。
        let press = |pressed: bool| egui::Event::PointerButton {
            pos: dir_rect.center(),
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::default(),
        };
        let mut clicked: Option<(usize, String)> = None;
        ctx.run(
            egui::RawInput {
                events: vec![press(true), press(false)],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    conn_log_view(ui, &Theme::LIGHT, &lines, &opts, &mut |li, path| {
                        clicked = Some((li, path.to_string()));
                    }, None);
                });
            },
        );
        assert_eq!(clicked, Some((1usize, "D:\\src\\a".to_string())));
    }

    /// 0.99s 无 tooltip；恰满 1s → tooltip 在位（文本 = `dir_tip`，
    /// 经 shapes 的 Text 字形断言——tooltip 为 `Order::Tooltip` 层纯绘制
    /// 覆盖层，`FullOutput.shapes` 全层 drain 可捕获）。
    #[test]
    fn r142_1_conn_log_dir_hover_one_second_gate() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let ctx = egui::Context::default();
        let lines = vec![build_transfer_line(
            true,
            "本机",
            "DEV123",
            "D:\\src\\a",
            "docs/b",
            "a.txt",
            None,
        )];
        let opts = ConnLogViewOptions {
            title: "连接日志：",
            empty: "（暂无连接日志）",
            max_height: 200.0,
            clearable: false,
            clear: None,
            dir_tip: "点击复制路径",
        };
        let has_tip = |out: &egui::FullOutput| {
            out.shapes.iter().any(|cs| {
                matches!(
                    &cs.shape,
                    egui::Shape::Text(t) if t.galley.job.text.contains("点击复制路径")
                )
            })
        };
        // 方向词段后 si = 2）。
        let mut dir_rect = egui::Rect::NOTHING;
        ctx.run(
            egui::RawInput {
                time: Some(99.0),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let mut probe = |li: usize, si: usize, r: egui::Rect| {
                        if li == 0 && si == 2 {
                            dir_rect = r;
                        }
                    };
                    conn_log_view(
                        ui,
                        &Theme::LIGHT,
                        &lines,
                        &opts,
                        &mut |_, _| {},
                        Some(&mut probe),
                    );
                });
            },
        );
        assert_ne!(dir_rect, egui::Rect::NOTHING);
        // 帧 1（t=100.0）：指针落 Dir 段中心（Arming 起点）。
        let center = dir_rect.center();
        ctx.run(
            egui::RawInput {
                time: Some(100.0),
                events: vec![egui::Event::PointerMoved(center)],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    conn_log_view(ui, &Theme::LIGHT, &lines, &opts, &mut |_, _| {}, None);
                });
            },
        );
        // 帧 2（t=100.99）：静置 0.99s < 1s 门控 → 无 tooltip。
        let out = ctx.run(
            egui::RawInput {
                time: Some(100.99),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    conn_log_view(ui, &Theme::LIGHT, &lines, &opts, &mut |_, _| {}, None);
                });
            },
        );
        assert!(!has_tip(&out), "0.99s 未满 1s 门控，tooltip 不应出现");
        // 帧 3（t=101.0）：恰满 1s → tooltip 在位。
        let out = ctx.run(
            egui::RawInput {
                time: Some(101.0),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    conn_log_view(ui, &Theme::LIGHT, &lines, &opts, &mut |_, _| {}, None);
                });
            },
        );
        assert!(has_tip(&out), "满 1s 后 tooltip 应在位（点击复制路径）");
    }
}
