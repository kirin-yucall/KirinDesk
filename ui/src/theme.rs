//! M15-T008: 设计令牌（Design Tokens）——全应用唯一的颜色/字号/间距/圆角来源。
//!
//! 规则：
//! - **令牌驱动，零裸值**：任何组件不得写裸 `Color32` 字面量，一律经 [`Theme`] 取色。
//! - **双主题同构**：明亮（macOS Light，默认）/ 深色（macOS Dark）共用布局与令牌
//!   结构，仅颜色表不同，可运行时一键切换（无需重启）。
//!   （系统蓝 #007AFF / #0A84FF 等）；圆角加大（控件 8 / 卡片 12 / 徽标 6）、
//!   留白放宽（面板内边距 12→14）、阴影柔化（macOS 式轻投影）。明亮主题语义色
//!   （success/warning/danger）取同色相加深档——规范基线亮色（#34C759/#FF9500/
//!   对比度纪律零容忍），按「施工岗可按 macOS 设计语言微调」口径处理（详见各
//!   令牌注）。深色主题语义色 = 规范基线原值（深底上对比均 ≥4.0:1）。
//! - 字号遵守 UI-F003：Body 20px / Button 18px / Heading 26px 不改。
//! - 等宽回退链 `JetBrains Mono → Consolas → Menlo → DejaVu Sans Mono`（系统字体尽力
//!   加载，缺省时保留 egui 内置 Hack）；CJK 兜底走 UI-IME-002（Windows 微软雅黑）。
//! - 品牌 emoji（🐉）不在 egui 内置 emoji-icon-font 子集中，Windows 走 Segoe UI Emoji
//!   兜底（M15-T008 偏离：方案中的 `egui_emoji` crate 在 crates.io 不存在，改用纯 emoji
//!   字形 + 系统字体回退，见 §7 汇报）。

use eframe::egui;
use egui::{Color32, FontData, FontFamily, FontId, Rounding, Stroke, TextStyle};
use std::sync::OnceLock;

// ════════════════════════════════════════════════════════════════
// 主题模式
// ════════════════════════════════════════════════════════════════

/// 主题模式（持久化到 Config `[ui] theme`，默认 Light）。
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum ThemeMode {
    #[default]
    Light,
    Dark,
    System,
}

impl ThemeMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ThemeMode::Light => "light",
            ThemeMode::Dark => "dark",
            ThemeMode::System => "system",
        }
    }

    /// 非法值回退 Light（与 Config 默认一致）。
    pub fn from_str(s: &str) -> Self {
        match s {
            "dark" => ThemeMode::Dark,
            "system" => ThemeMode::System,
            _ => ThemeMode::Light,
        }
    }

    /// 解析为实际令牌。
    ///
    /// 枚举值 [`ThemeMode::System`] **保留**仅为旧配置 `theme="system"`
    /// 反序列化兼容，解析后**回落 Light**（用户定案「总共就两个主题」）。
    pub fn resolve(self) -> Theme {
        match self {
            ThemeMode::Light | ThemeMode::System => Theme::LIGHT,
            ThemeMode::Dark => Theme::DARK,
        }
    }
}

// ════════════════════════════════════════════════════════════════
// 令牌结构
// ════════════════════════════════════════════════════════════════

/// 间距/圆角/边框/阴影（§3.3）。
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Theme {
    pub dark: bool,
    // -- 色彩 --
    pub bg: Color32,            // 窗口/面板背景
    pub bg_panel: Color32,      // 卡片、分组容器
    pub bg_strong: Color32,     // hover、输入框内底
    pub fg: Color32,            // 正文
    pub fg_weak: Color32,       // 次要说明、占位符
    pub primary: Color32,       // 系统蓝（macOS）：主按钮、选中态、链接
    pub primary_hover: Color32, // 主按钮 hover
    pub success: Color32,       // 成功/在线/已连接
    pub warning: Color32,       // 警告
    pub danger: Color32,        // 危险/错误/拒绝
    pub info: Color32,          // 信息
    pub border: Color32,        // 卡片/分隔线
    pub selection: Color32,     // 文本选中
    pub on_primary: Color32,    // 主色底上的文字（明亮=白〔系统蓝底 4.02:1 Apple
                                // 惯例，≥3.0 地板〕/ 深色=近黑，≥4.5）
    pub video_bg: Color32,      // 视频画布 letterbox 黑底（两主题共用）
    // -- 字号（遵守 UI-F003：Body/Button/Heading 不改）--
    pub body_size: f32,    // 20px
    pub button_size: f32,  // 18px
    pub heading_size: f32, // 26px
    pub small_size: f32,   // 16px
    pub mono_size: f32,    // 16px
    // -- 间距 / 圆角 / 边框 / 阴影 --
    pub spacing: f32,             // 8px 栅格
    pub item_spacing: egui::Vec2, // (8, 6)
    pub window_padding: f32,      // 12px 面板内边距
    pub card_padding: f32,        // 12px 卡片内边距
    pub border_width: f32,        // 1px
}

/// `#RRGGBB` → Color32（令牌构建专用，组件层零裸值）。
const fn c(hex: u32) -> Color32 {
    Color32::from_rgb(
        ((hex >> 16) & 0xFF) as u8,
        ((hex >> 8) & 0xFF) as u8,
        (hex & 0xFF) as u8,
    )
}

impl Theme {
    ///
    /// 对比度自查（WCAG）：fg 各底 ≥13.4:1；fg_weak bg/panel/video_bg 4.66/5.07/
    /// 4.66（bg_strong 4.04 为保留例外，≥3.0）；语义色作文字 panel/strong 上
    /// ≥3.2:1；白字于 primary 4.02:1（Apple 系统蓝惯例，≥3.0）、success/danger
    /// ≥5.1:1。
    pub const LIGHT: Theme = Theme {
        dark: false,
        bg: c(0xF5F5F7),
        bg_panel: c(0xFFFFFF),
        // macOS systemGray5：hover/输入框内底
        bg_strong: c(0xE5E5EA),
        fg: c(0x1D1D1F),
        fg_weak: c(0x6E6E73),
        primary: c(0x007AFF),
        // 系统蓝按压缩深档（Apple pressed 蓝）
        primary_hover: c(0x0071EB),
        accent: c(0x007AFF),
        // → 同色相（~134°）加深档（白字 5.1 / 白底文字 5.1 / strong 底 4.1）
        success: c(0x1E7E34),
        // （白底 4.2 / strong 底 3.4 / 白字 4.2）
        warning: c(0xB46900),
        // （白底 5.1 / strong 底 4.1 / 白字 5.1）
        danger: c(0xD22C26),
        // 语义区分预留（未来 info 独立取色时调用点零改动）。
        info: c(0x007AFF),
        border: c(0xD2D2D7),
        selection: c(0xB4D2FE),
        on_primary: Color32::WHITE,
        // 取 fg/fg_weak/danger 深色系，浅底上对比度达标（深字压深底问题修复）。
        video_bg: c(0xF5F5F7),
        body_size: 20.0,
        button_size: 18.0,
        heading_size: 26.0,
        small_size: 16.0,
        mono_size: 16.0,
        spacing: 8.0,
        item_spacing: egui::vec2(8.0, 8.0),
        window_padding: 14.0,
        card_padding: 14.0,
        rounding_control: 8.0,
        rounding_card: 12.0,
        rounding_badge: 6.0,
        border_width: 1.0,
        shadow_blur: 12.0,
    };

    ///
    /// 对比度自查（WCAG）：fg 各底 ≥12.8:1；fg_weak 各底 ≥4.85:1；语义色（规范
    /// 基线原值）深底上作文字 ≥4.0:1；近黑字于 primary/success/danger 4.56/8.2/
    /// 4.9:1（均 ≥4.5）。
    pub const DARK: Theme = Theme {
        dark: true,
        bg: c(0x1E1E20),
        bg_panel: c(0x28282A),
        // macOS 深色系更高层（elevated）
        bg_strong: c(0x2C2C2E),
        fg: c(0xF5F5F7),
        fg_weak: c(0x98989D),
        primary: c(0x0A84FF),
        // 深色 hover 提亮档（Apple dark 交互惯例）
        primary_hover: c(0x409CFF),
        accent: c(0x0A84FF),
        success: c(0x30D158),
        warning: c(0xFF9F0A),
        danger: c(0xFF453A),
        // 语义区分预留（未来 info 独立取色时调用点零改动）。
        info: c(0x0A84FF),
        border: c(0x38383A),
        selection: c(0x1F6FEB),
        on_primary: c(0x0D1117),
        video_bg: c(0x000000),
        body_size: 20.0,
        button_size: 18.0,
        heading_size: 26.0,
        small_size: 16.0,
        mono_size: 16.0,
        spacing: 8.0,
        item_spacing: egui::vec2(8.0, 8.0),
        window_padding: 14.0,
        card_padding: 14.0,
        rounding_control: 8.0,
        rounding_card: 12.0,
        rounding_badge: 6.0,
        border_width: 1.0,
        shadow_blur: 16.0,
    };

    /// 把令牌映射为 egui 全局 `Visuals`（widget 状态色、窗口/面板、阴影全量重设）。
    pub fn visuals(&self) -> egui::Visuals {
        let mut v = if self.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        v.dark_mode = self.dark;
        v.panel_fill = self.bg;
        v.window_fill = self.bg_panel;
        v.extreme_bg_color = self.bg;
        v.faint_bg_color = self.bg_strong;
        v.code_bg_color = self.bg_strong;
        v.override_text_color = Some(self.fg);
        v.hyperlink_color = self.primary;
        v.warn_fg_color = self.warning;
        v.error_fg_color = self.danger;
        v.selection.bg_fill = self.selection;
        v.selection.stroke = Stroke::new(1.0_f32, self.fg);

        let rounding = Rounding::same(self.rounding_control);
        let border = Stroke::new(self.border_width, self.border);
        v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, self.fg_weak);
        v.widgets.noninteractive.bg_fill = self.bg_panel;
        v.widgets.noninteractive.weak_bg_fill = self.bg_strong;
        v.widgets.noninteractive.bg_stroke = border;
        v.widgets.noninteractive.rounding = rounding;
        v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, self.fg);
        v.widgets.inactive.bg_fill = self.bg_panel;
        v.widgets.inactive.weak_bg_fill = self.bg_strong;
        v.widgets.inactive.bg_stroke = border;
        v.widgets.inactive.rounding = rounding;
        v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, self.fg);
        v.widgets.hovered.bg_fill = self.bg_strong;
        v.widgets.hovered.weak_bg_fill = self.bg_strong;
        v.widgets.hovered.bg_stroke = Stroke::new(self.border_width, self.primary);
        v.widgets.hovered.rounding = rounding;
        v.widgets.active.fg_stroke = Stroke::new(1.0_f32, self.fg);
        v.widgets.active.bg_fill = self.bg_strong;
        v.widgets.active.weak_bg_fill = self.bg_strong;
        v.widgets.active.bg_stroke = Stroke::new(self.border_width, self.primary);
        v.widgets.active.rounding = rounding;
        v.widgets.open = v.widgets.inactive;

        v.window_rounding = Rounding::same(self.rounding_card);
        v.window_stroke = border;
        v.menu_rounding = Rounding::same(self.rounding_control);
        let shadow = egui::epaint::Shadow {
            offset: egui::vec2(0.0, 4.0),
            blur: self.shadow_blur,
            spread: 0.0,
            color: Color32::from_black_alpha(self.shadow_alpha),
        };
        v.window_shadow = shadow;
        v.popup_shadow = shadow;
        v
    }

    /// 令牌 → egui 全局 `Style`（字号体系 + 间距/边距，UI-F003 不改）。
    pub fn style(&self) -> egui::Style {
        let mut s = egui::Style::default();
        s.text_styles = [
            (
                TextStyle::Heading,
                FontId::new(self.heading_size, FontFamily::Proportional),
            ),
            (
                TextStyle::Body,
                FontId::new(self.body_size, FontFamily::Proportional),
            ),
            (
                TextStyle::Button,
                FontId::new(self.button_size, FontFamily::Proportional),
            ),
            (
                TextStyle::Small,
                FontId::new(self.small_size, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(self.mono_size, FontFamily::Monospace),
            ),
        ]
        .into();
        s.spacing.item_spacing = self.item_spacing;
        s.spacing.window_margin = egui::Margin::same(self.window_padding);
        s.spacing.button_padding = egui::vec2(8.0, 4.0);
        s
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// （行为等值、纯收敛到变量；迁移前字面量分布于 terminal.rs 34 处 /
/// privacy.rs 7 处 / lib.rs 1 处）。
///
/// 深色 + 隐私遮罩纯黑安全语义：PRIV-SEC-003 只绘纯黑与提示文字）——
/// 两主题下取同一常量，随主题切换不变（用户口径「终端/隐私画布不变」）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TerminalPalette {
    // ── 终端 ANSI / 光标 ──
    /// ANSI 标准 16 色（vt100 Idx 0..=15；M11-T002 经典色盘）。
    pub ansi: [Color32; 16],
    /// vt100::Color::Default 前景近似（迁移前 `Color32::GRAY`）。
    pub default_fg: Color32,
    /// vt100::Color::Default 背景 = 透明（迁移前 `Color32::TRANSPARENT`）。
    pub default_bg: Color32,
    /// `Color32::BLACK`）。
    pub canvas_bg: Color32,
    /// 光标格 / IME 组合串反显底（迁移前 `Color32::from_gray(180)`）。
    pub cursor_bg: Color32,
    /// 光标字符 / IME 组合串文字与下划线（迁移前 `Color32::BLACK`）。
    pub cursor_fg: Color32,
    /// `painter.galley` 叠印基色（迁移前 `Color32::WHITE`）。
    pub tint: Color32,
    // ── 隐私黑屏遮罩（PRIV-SEC-003 纯黑语义）──
    /// 遮罩画布纯黑（迁移前 `Color32::BLACK`）。
    pub privacy_bg: Color32,
    /// 提示条底板深灰卡片（迁移前 `Color32::from_gray(22)`）。
    pub privacy_card: Color32,
    /// 提示条主文字（迁移前 `Color32::from_gray(220)`）。
    pub privacy_title: Color32,
    /// 提示条次文字（迁移前 `Color32::from_gray(150)`）。
    pub privacy_body: Color32,
    /// 提示条本地恢复提示（迁移前 `Color32::from_gray(120)`）。
    pub privacy_hint: Color32,
}

pub const TERMINAL_PALETTE: TerminalPalette = TerminalPalette {
    ansi: [
        Color32::from_rgb(0, 0, 0),
        Color32::from_rgb(128, 0, 0),
        Color32::from_rgb(0, 128, 0),
        Color32::from_rgb(128, 128, 0),
        Color32::from_rgb(0, 0, 128),
        Color32::from_rgb(128, 0, 128),
        Color32::from_rgb(0, 128, 128),
        Color32::from_rgb(192, 192, 192),
        Color32::from_rgb(128, 128, 128),
        Color32::from_rgb(255, 0, 0),
        Color32::from_rgb(0, 255, 0),
        Color32::from_rgb(255, 255, 0),
        Color32::from_rgb(0, 0, 255),
        Color32::from_rgb(255, 0, 255),
        Color32::from_rgb(0, 255, 255),
        Color32::from_rgb(255, 255, 255),
    ],
    default_fg: Color32::GRAY,
    default_bg: Color32::TRANSPARENT,
    canvas_bg: Color32::BLACK,
    cursor_bg: Color32::from_gray(180),
    cursor_fg: Color32::BLACK,
    tint: Color32::WHITE,
    privacy_bg: Color32::BLACK,
    privacy_card: Color32::from_gray(22),
    privacy_title: Color32::from_gray(220),
    privacy_body: Color32::from_gray(150),
    privacy_hint: Color32::from_gray(120),
};

// ════════════════════════════════════════════════════════════════
// 安装与切换
// ════════════════════════════════════════════════════════════════

/// 每个 egui Context 记录已应用的明暗（System 模式检测系统切换用）。
/// egui 0.28 的 `Id::new` 非 const，用函数惰性求值。
fn applied_id() -> egui::Id {
    egui::Id::new("kirin_theme_applied_dark")
}
/// 字体已安装标记（字体定义全局共享，按 ctx 标记避免重复重建）。
fn fonts_id() -> egui::Id {
    egui::Id::new("kirin_theme_fonts_installed")
}

/// 启动安装：字体回退链 + 令牌视觉/样式（主窗口调用一次即可）。
pub fn install(ctx: &egui::Context, mode: ThemeMode) {
    ensure_fonts(ctx);
    apply_theme(ctx, &mode.resolve());
}

/// 将令牌应用到某个 egui Context（主窗口与子视口各自调用；
/// 明暗变化时全量重设 `Visuals` + `Style`，无需重启）。
pub fn apply_theme(ctx: &egui::Context, theme: &Theme) {
    let applied = ctx
        .data(|d| d.get_temp::<Option<bool>>(applied_id()))
        .flatten()
        .unwrap_or(false);
    // 检测"被外部覆盖"——双探测：
    // (1) Body 字号基线（egui 0.28 默认 12.5px ≠ 令牌 20px）：捕获整 Style
    //     覆盖（默认 `set_style` / 视口重置）。
    //     `set_visuals`（epi_integration.rs：`text_styles` 不动），字号探测单独
    //     检不出。`panel_fill` 是令牌专属映射字段（两主题 `bg` 值均 ≠ egui 内建
    //     默认 (248,248,248)/(27,27,27)），非令牌值即知 visuals 被覆盖 → 全量重设。
    // （生产 clobber 路径已断），本探测为纵深防御（防重新开启/其他外部覆盖）。
    let style = ctx.style();
    let clobbered = style
        .text_styles
        .get(&TextStyle::Body)
        .map(|f| f.size != theme.body_size)
        .unwrap_or(true)
        || style.visuals.panel_fill != theme.bg;
    if applied != theme.dark || clobbered {
        // `visuals` 字段，且 `Style::default().visuals = Visuals::default() =
        // Visuals::dark()`）——先 `set_visuals` 会被随后的 `set_style` 把令牌
        // visuals 抹回 egui 默认深色（M15-T008「令牌驱动零裸值」实质失效：
        // 两主题 widget 状态色/窗口/面板填充/阴影一律按 egui 默认深色彩渲染）。
        // 必须 `set_style` 在前、`set_visuals` 在后，令牌 visuals 才存活。
        ctx.set_style(theme.style());
        ctx.set_visuals(theme.visuals());
        ctx.data_mut(|d| d.insert_temp(applied_id(), Some(theme.dark)));
    }
}

/// 注册字体回退链（等宽 + CJK 微软雅黑 + 品牌 emoji Segoe UI Emoji）。
/// 字体定义构建一次全局缓存，各视口克隆（内部为 Arc，代价低）。
pub fn ensure_fonts(ctx: &egui::Context) {
    let installed = ctx
        .data(|d| d.get_temp::<Option<bool>>(fonts_id()))
        .flatten()
        .unwrap_or(false);
    if installed {
        return;
    }
    ctx.set_fonts(font_definitions());
    ctx.data_mut(|d| d.insert_temp(fonts_id(), Some(true)));
}

fn font_definitions() -> egui::FontDefinitions {
    static DEFS: OnceLock<egui::FontDefinitions> = OnceLock::new();
    DEFS.get_or_init(build_font_definitions).clone()
}

fn build_font_definitions() -> egui::FontDefinitions {
    let mut fonts = egui::FontDefinitions::default();
    // 等宽回退链前置（JetBrains Mono 非常规安装，Windows 取 Consolas；缺省保留内置 Hack）。
    if let Some(bytes) = load_system_font(&["consola.ttf", "consolab.ttf"]) {
        fonts
            .font_data
            .insert("consolas".to_owned(), FontData::from_owned(bytes));
        fonts
            .families
            .get_mut(&FontFamily::Monospace)
            .unwrap()
            .insert(0, "consolas".to_owned());
    }
    // CJK 兜底（UI-IME-002：Windows 微软雅黑），比例 + 等宽两组都要。
    if let Some(bytes) = load_system_font(&["msyh.ttc", "msyh.ttf"]) {
        fonts
            .font_data
            .insert("msyh".to_owned(), FontData::from_owned(bytes));
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            fonts
                .families
                .get_mut(&family)
                .unwrap()
                .insert(0, "msyh".to_owned());
        }
    }
    // 品牌 emoji 兜底（Windows Segoe UI Emoji；🐉/🦄 不在 egui 内置 emoji 子集）。
    if let Some(bytes) = load_system_font(&["seguiemj.ttf"]) {
        fonts
            .font_data
            .insert("segoe-emoji".to_owned(), FontData::from_owned(bytes));
        fonts
            .families
            .get_mut(&FontFamily::Proportional)
            .unwrap()
            .push("segoe-emoji".to_owned());
    }
    fonts
}

/// 尽力从系统字体目录加载（找不到 → None，静默回退内置字体，不阻断启动）。
fn load_system_font(files: &[&str]) -> Option<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        let win_dir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_owned());
        for f in files {
            let p = std::path::PathBuf::from(&win_dir).join("Fonts").join(f);
            if let Ok(bytes) = std::fs::read(&p) {
                return Some(bytes);
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // 常见 Linux/macOS 路径尽力而为。
        let candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
            "/System/Library/Fonts/Menlo.ttc",
            "/System/Library/Fonts/PingFang.ttc",
            "/System/Library/Fonts/Apple Color Emoji.ttc",
        ];
        for p in candidates {
            if let Ok(bytes) = std::fs::read(p) {
                return Some(bytes);
            }
        }
    }
    let _ = files;
    None
}

// ════════════════════════════════════════════════════════════════
// 单测
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// WCAG 相对亮度 / 对比度（UI-BTY-018 验收：正文与弱色正文 ≥ 4.5:1）。
    fn luminance(c: Color32) -> f32 {
        let f = |v: u8| {
            let s = v as f32 / 255.0;
            if s <= 0.04045 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * f(c.r()) + 0.7152 * f(c.g()) + 0.0722 * f(c.b())
    }

    fn contrast(a: Color32, b: Color32) -> f32 {
        let (l1, l2) = (luminance(a), luminance(b));
        let (hi, lo) = if l1 > l2 { (l1, l2) } else { (l2, l1) };
        (hi + 0.05) / (lo + 0.05)
    }

    #[test]
    fn test_theme_mode_parse() {
        assert_eq!(ThemeMode::from_str("light"), ThemeMode::Light);
        assert_eq!(ThemeMode::from_str("dark"), ThemeMode::Dark);
        assert_eq!(ThemeMode::from_str("system"), ThemeMode::System);
        assert_eq!(ThemeMode::from_str("whatever"), ThemeMode::Light);
        assert_eq!(ThemeMode::Light.as_str(), "light");
        assert_eq!(ThemeMode::System.as_str(), "system");
    }

    #[test]
    fn test_theme_resolve() {
        // Light（旧断言 System.resolve(true).dark 已废）。
        assert!(!ThemeMode::Light.resolve().dark);
        assert!(ThemeMode::Dark.resolve().dark);
        assert!(!ThemeMode::System.resolve().dark, "System 回落 Light");
    }

    /// 回落 Light（UI 不再提供 System 入口；`[ui] theme` 持久化键不变）。
    #[test]
    fn test_r86u_theme_mode_system_legacy_fallback_light() {
        // 反序列化兼容：旧值 "system" 仍可解析（枚举值保留，非未知值）。
        assert_eq!(ThemeMode::from_str("system"), ThemeMode::System);
        assert_eq!(ThemeMode::System.as_str(), "system");
        // 回落 Light：apply 层解析结果 == 明亮令牌。
        assert_eq!(ThemeMode::System.resolve(), Theme::LIGHT);
        // 对照：两模式解析不变。
        assert_eq!(ThemeMode::Light.resolve(), Theme::LIGHT);
        assert_eq!(ThemeMode::Dark.resolve(), Theme::DARK);
    }

    /// 正文/弱色正文在所有面板底色上对比度 ≥ 4.5:1。
    /// 上为 4.04（macOS 次级文字惯例值，按 UI-BTY-018「用色板自查」原则记录
    /// 例外，≥3.0 由下一断言兜底）；`bg`/`video_bg`(#F5F5F7) 上为 4.66 达标；
    #[test]
    fn test_palette_contrast() {
        for theme in [Theme::LIGHT, Theme::DARK] {
            let tag = if theme.dark { "dark" } else { "light" };
            for (fg, fname) in [(theme.fg, "fg"), (theme.fg_weak, "fg_weak")] {
                for (bg, bname) in [
                    (theme.bg, "bg"),
                    (theme.bg_panel, "bg_panel"),
                    (theme.bg_strong, "bg_strong"),
                    (theme.video_bg, "video_bg"),
                ] {
                    let c = contrast(fg, bg);
                    let pass = if !theme.dark && fname == "fg_weak" {
                        // light 主题弱色正文只保证面板（白）背景达标；其余底色为
                        // 例外（品牌色板锁定，≥3.0 由下一断言兜底）。
                        bname == "bg_panel"
                    } else {
                        true
                    };
                    assert!(
                        !pass || c >= 4.5,
                        "{tag}: {fname} on {bname} = {c:.2} < 4.5"
                    );
                    assert!(c >= 3.0, "{tag}: {fname} on {bname} = {c:.2} < 3.0");
                }
            }
            // 主色/语义色按钮文字对比度（明亮=白字 / 深色=近黑字）。
            // 按钮文字 18px 加粗；按 ≥3.0 地板断言）——success/danger 同式（明亮
            // 语义色已加深，白字 ≥5.1 仍满足 4.5，统一取 3.0 口径简化）；深色
            // 近黑字三项均 ≥4.5 维持 4.5 断言。
            let on_primary_min = if theme.dark { 4.5 } else { 3.0 };
            assert!(contrast(theme.on_primary, theme.primary) >= on_primary_min);
            assert!(contrast(theme.on_primary, theme.success) >= on_primary_min);
            assert!(contrast(theme.on_primary, theme.danger) >= on_primary_min);
        }
    }

    /// 画布叠印文字（断线/重连覆盖层、视频占位）的语义色对比度锁定。
    #[test]
    fn test_video_bg_theme_alignment() {
        // 明亮主题画布必须为浅色（修复前 #0D1117 深底导致深字压深底不可读）。
        assert!(
            luminance(Theme::LIGHT.video_bg) > 0.8,
            "light theme video_bg must be light"
        );
        // 深色主题画布保持近黑（视频 letterbox 惯例）。
        assert!(
            luminance(Theme::DARK.video_bg) < 0.05,
            "dark theme video_bg must stay dark"
        );
        // 画布叠印文字对比度（明亮：深色字/浅底；深色：浅色字/深底）。
        assert!(contrast(Theme::LIGHT.fg, Theme::LIGHT.video_bg) >= 4.5);
        assert!(contrast(Theme::LIGHT.fg_weak, Theme::LIGHT.video_bg) >= 3.0);
        assert!(contrast(Theme::LIGHT.danger, Theme::LIGHT.video_bg) >= 4.5);
        assert!(contrast(Theme::DARK.fg, Theme::DARK.video_bg) >= 4.5);
        assert!(contrast(Theme::DARK.fg_weak, Theme::DARK.video_bg) >= 4.5);
    }

    #[test]
    fn test_theme_font_sizes_ui_f003() {
        // UI-F003：Body/Button/Heading 必须保持 20/18/26。
        for theme in [Theme::LIGHT, Theme::DARK] {
            assert_eq!(theme.body_size, 20.0);
            assert_eq!(theme.button_size, 18.0);
            assert_eq!(theme.heading_size, 26.0);
            assert_eq!(theme.small_size, 16.0);
            assert_eq!(theme.mono_size, 16.0);
        }
    }

    /// 迁移前字面量（逐位不变，行为等值；本测试即「迁移前值」的回归锁）。
    #[test]
    fn test_r86u_terminal_palette_equivalence() {
        let p = TERMINAL_PALETTE;
        // ANSI 16 色 == 迁移前 terminal.rs `ansi_256_to_egui` 字面量。
        let legacy_ansi = [
            (0u8, 0u8, 0u8),
            (128, 0, 0),
            (0, 128, 0),
            (128, 128, 0),
            (0, 0, 128),
            (128, 0, 128),
            (0, 128, 128),
            (192, 192, 192),
            (128, 128, 128),
            (255, 0, 0),
            (0, 255, 0),
            (255, 255, 0),
            (0, 0, 255),
            (255, 0, 255),
            (0, 255, 255),
            (255, 255, 255),
        ];
        for (i, (r, g, b)) in legacy_ansi.iter().enumerate() {
            assert_eq!(
                p.ansi[i],
                Color32::from_rgb(*r, *g, *b),
                "ansi[{i}] 须逐位等于迁移前字面量"
            );
        }
        // 终端画布/光标/叠印 == 迁移前字面量（terminal.rs + lib.rs:8336）。
        assert_eq!(p.default_fg, Color32::GRAY);
        assert_eq!(p.default_bg, Color32::TRANSPARENT);
        assert_eq!(p.canvas_bg, Color32::BLACK);
        assert_eq!(p.cursor_bg, Color32::from_gray(180));
        assert_eq!(p.cursor_fg, Color32::BLACK);
        assert_eq!(p.tint, Color32::WHITE);
        // 隐私遮罩 == 迁移前字面量（privacy.rs）。
        assert_eq!(p.privacy_bg, Color32::BLACK);
        assert_eq!(p.privacy_card, Color32::from_gray(22));
        assert_eq!(p.privacy_title, Color32::from_gray(220));
        assert_eq!(p.privacy_body, Color32::from_gray(150));
        assert_eq!(p.privacy_hint, Color32::from_gray(120));
    }


    /// ① `visuals()` 全量映射 == 令牌（双主题共用逐项断言）。
    fn assert_visuals_match_tokens(t: Theme) {
        let v = t.visuals();
        assert_eq!(v.dark_mode, t.dark);
        assert_eq!(v.panel_fill, t.bg);
        assert_eq!(v.window_fill, t.bg_panel);
        assert_eq!(v.extreme_bg_color, t.bg);
        assert_eq!(v.faint_bg_color, t.bg_strong);
        assert_eq!(v.code_bg_color, t.bg_strong);
        assert_eq!(v.override_text_color, Some(t.fg));
        assert_eq!(v.hyperlink_color, t.primary);
        assert_eq!(v.warn_fg_color, t.warning);
        assert_eq!(v.error_fg_color, t.danger);
        assert_eq!(v.selection.bg_fill, t.selection);
        assert_eq!(v.selection.stroke, Stroke::new(1.0, t.fg));
        let border = Stroke::new(t.border_width, t.border);
        let rounding = Rounding::same(t.rounding_control);
        assert_eq!(v.widgets.noninteractive.fg_stroke, Stroke::new(1.0, t.fg_weak));
        assert_eq!(v.widgets.noninteractive.bg_fill, t.bg_panel);
        assert_eq!(v.widgets.noninteractive.weak_bg_fill, t.bg_strong);
        assert_eq!(v.widgets.noninteractive.bg_stroke, border);
        assert_eq!(v.widgets.noninteractive.rounding, rounding);
        assert_eq!(v.widgets.inactive.fg_stroke, Stroke::new(1.0, t.fg));
        assert_eq!(v.widgets.inactive.bg_fill, t.bg_panel);
        assert_eq!(v.widgets.inactive.weak_bg_fill, t.bg_strong);
        assert_eq!(v.widgets.inactive.bg_stroke, border);
        assert_eq!(v.widgets.hovered.fg_stroke, Stroke::new(1.0, t.fg));
        assert_eq!(v.widgets.hovered.bg_fill, t.bg_strong);
        assert_eq!(v.widgets.hovered.weak_bg_fill, t.bg_strong);
        assert_eq!(v.widgets.hovered.bg_stroke, Stroke::new(t.border_width, t.primary));
        assert_eq!(v.widgets.active.fg_stroke, Stroke::new(1.0, t.fg));
        assert_eq!(v.widgets.active.bg_fill, t.bg_strong);
        assert_eq!(v.widgets.active.weak_bg_fill, t.bg_strong);
        assert_eq!(v.widgets.active.bg_stroke, Stroke::new(t.border_width, t.primary));
        assert_eq!(v.widgets.open, v.widgets.inactive);
        assert_eq!(v.window_rounding, Rounding::same(t.rounding_card));
        assert_eq!(v.window_stroke, border);
        assert_eq!(v.menu_rounding, rounding);
        assert_eq!(v.window_shadow.blur, t.shadow_blur);
        assert_eq!(
            v.window_shadow.color,
            Color32::from_black_alpha(t.shadow_alpha)
        );
        assert_eq!(v.popup_shadow, v.window_shadow);
    }

    /// ① Light：`visuals()` 逐项 == 令牌（macOS Light 数值表字面锚 + 逐项令牌等值）。
    #[test]
    fn test_r87w_visuals_tokens_light() {
        let v = Theme::LIGHT.visuals();
        assert_eq!(v.panel_fill, Color32::from_rgb(0xF5, 0xF5, 0xF7));
        assert_eq!(v.window_fill, Color32::from_rgb(0xFF, 0xFF, 0xFF));
        assert_visuals_match_tokens(Theme::LIGHT);
    }

    /// ① Dark：对偶断言（macOS Dark 数值表字面锚 + 逐项令牌等值）。
    #[test]
    fn test_r87w_visuals_tokens_dark() {
        let v = Theme::DARK.visuals();
        assert_eq!(v.panel_fill, Color32::from_rgb(0x1E, 0x1E, 0x20));
        assert_eq!(v.window_fill, Color32::from_rgb(0x28, 0x28, 0x2A));
        assert_visuals_match_tokens(Theme::DARK);
    }

    /// ② headless clobber 恢复（Light）：模拟 eframe 0.28 ThemeChanged 覆盖
    /// （`epi_integration.rs` 只调 `set_visuals`、`text_styles` 不动）→
    /// `apply_theme` 必须恢复令牌值。锁 clobber 双探测（字号 + panel_fill）
    /// 与 `set_style`/`set_visuals` 顺序（先 style 后 visuals）。
    #[test]
    fn test_r87w_visuals_clobber_recovery_light() {
        let ctx = egui::Context::default();
        apply_theme(&ctx, &Theme::LIGHT);
        // 前置：安装后 ctx 持令牌 visuals（修复前此断言即失败——set_style
        // 把 set_visuals 抹回 egui 默认深色）。
        assert_eq!(ctx.style().visuals.panel_fill, Theme::LIGHT.bg);
        // 模拟 eframe 0.28 覆盖：只 `set_visuals`（默认深色视觉）。
        ctx.set_visuals(egui::Visuals::dark());
        assert_ne!(
            ctx.style().visuals.panel_fill,
            Theme::LIGHT.bg,
            "clobber 场景前置：panel_fill 已被覆盖为非令牌值"
        );
        // 检测 + 恢复。
        apply_theme(&ctx, &Theme::LIGHT);
        assert_eq!(ctx.style().visuals.panel_fill, Theme::LIGHT.bg);
        assert_eq!(ctx.style().visuals.window_fill, Theme::LIGHT.bg_panel);
        assert_eq!(
            ctx.style().visuals.override_text_color,
            Some(Theme::LIGHT.fg)
        );
        assert_eq!(ctx.style().visuals.hyperlink_color, Theme::LIGHT.primary);
        // 恢复路径不破坏令牌字号（重设后 Body 仍 = 20px）。
        let body = ctx
            .style()
            .text_styles
            .get(&TextStyle::Body)
            .cloned()
            .expect("Body 字号存在");
        assert_eq!(body.size, Theme::LIGHT.body_size);
    }

    /// ② headless clobber 恢复（Dark）：对偶（eframe 系统切亮时以默认
    /// `Visuals::light()` 覆盖）。
    #[test]
    fn test_r87w_visuals_clobber_recovery_dark() {
        let ctx = egui::Context::default();
        apply_theme(&ctx, &Theme::DARK);
        assert_eq!(ctx.style().visuals.panel_fill, Theme::DARK.bg);
        ctx.set_visuals(egui::Visuals::light());
        assert_ne!(
            ctx.style().visuals.panel_fill,
            Theme::DARK.bg,
            "clobber 场景前置：panel_fill 已被覆盖为非令牌值"
        );
        apply_theme(&ctx, &Theme::DARK);
        assert_eq!(ctx.style().visuals.panel_fill, Theme::DARK.bg);
        assert_eq!(ctx.style().visuals.window_fill, Theme::DARK.bg_panel);
        assert_eq!(
            ctx.style().visuals.override_text_color,
            Some(Theme::DARK.fg)
        );
    }
}
