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

/// 统一动作按钮：min_size(160,40)、圆角 6px；hover 走状态色切换（令牌驱动）。
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
            w.fg_stroke = Stroke::new(1.0, fg);
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
            .min_size(egui::vec2(160.0, 40.0)),
    );
    *ui.visuals_mut() = saved;
    resp
}

/// 导航/分段选中胶囊：选中 = 品牌色底 + 对比文字；未选中 hover 高亮。
pub fn selectable_pill(ui: &mut Ui, theme: &Theme, text: &str, selected: bool) -> egui::Response {
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
            w.fg_stroke = Stroke::new(1.0, fg);
            w.bg_stroke = Stroke::new(theme.border_width, theme.border);
        }
        if !selected {
            v.widgets.hovered.bg_fill = theme.bg_strong;
            v.widgets.hovered.bg_stroke = Stroke::new(theme.border_width, theme.primary);
        }
    }
    let resp = ui.add(
        egui::Button::new(RichText::new(text).size(theme.button_size))
            .min_size(egui::vec2(0.0, 36.0)),
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
            if selectable_pill(ui, theme, item, sel).clicked() && !sel {
                *selected = i;
                changed = true;
            }
        }
    });
    changed
}

/// 工具栏图标按钮（§4 ToolbarButton）：hover 高亮 + tooltip 显示快捷键。
pub fn toolbar_button(ui: &mut Ui, theme: &Theme, icon: &str, tooltip: &str) -> egui::Response {
    let saved = ui.visuals().clone();
    {
        let v = ui.visuals_mut();
        for w in [
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
        ] {
            w.bg_fill = theme.bg_strong;
            w.rounding = egui::Rounding::same(theme.rounding_control);
            w.fg_stroke = Stroke::new(1.0, theme.fg);
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
}

/// 信息卡片（§4 StatCard）：标题栏（Small 弱色）+ 分隔线 + 键值行。
/// 返回本帧被复制的内容（`None` = 未复制；M8-T028 状态栏浮出提示用）。
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
                    selectable_pill(ui, t, "🏠 Dashboard", true);
                    selectable_pill(ui, t, "🖥 Devices", false);
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
                            },
                            StatRow {
                                key: "IPv6:",
                                value: "2001:db8::1".to_owned(),
                                mono: true,
                                copy: true,
                                small: true,
                                dot: Some((t.success, "公网地址，可直连")),
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
}
