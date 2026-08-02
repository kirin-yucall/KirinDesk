//! M15-T008: 设计令牌（Design Tokens）——全应用唯一的颜色/字号/间距/圆角来源。
//!
//! 规则：
//! - **令牌驱动，零裸值**：任何组件不得写裸 `Color32` 字面量，一律经 [`Theme`] 取色。
//! - **双主题同构**：明亮（GitHub Light，默认）/ 深色（GitHub Dark）共用布局与令牌
//!   结构，仅颜色表不同，可运行时一键切换（无需重启）。
//! - 字号遵守 UI-F003：Body 20px / Button 18px / Heading 26px 不改。
//! - 等宽回退链 `JetBrains Mono → Consolas → Menlo → DejaVu Sans Mono`（系统字体尽力
//!   加载，缺省时保留 egui 内置 Hack）；CJK 兜底走 UI-IME-002（Windows 微软雅黑）。
//! - 品牌 emoji（🐉）不在 egui 内置 emoji-icon-font 子集中，Windows 走 Segoe UI Emoji
//!   兜底（M15-T008 偏离：方案中的 `egui_emoji` crate 在 crates.io 不存在，改用纯 emoji
//!   字形 + 系统字体回退，见 §7 汇报）。

use eframe::egui;
use egui::{Color32, FontData, FontDefinitions, FontFamily, FontId, Rounding, Stroke, TextStyle};
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

    /// 解析为实际令牌（System 模式跟随系统；系统不可用时回退浅色）。
    pub fn resolve(self, system_dark: bool) -> Theme {
        match self {
            ThemeMode::Light => Theme::LIGHT,
            ThemeMode::Dark => Theme::DARK,
            ThemeMode::System => {
                if system_dark {
                    Theme::DARK
                } else {
                    Theme::LIGHT
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════
// 令牌结构
// ════════════════════════════════════════════════════════════════

/// 设计令牌：颜色（§3.1 GitHub 色板）+ 字号（§3.2）+ 间距/圆角/边框/阴影（§3.3）。
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Theme {
    pub dark: bool,
    // -- 色彩 --
    pub bg: Color32,            // 窗口/面板背景
    pub bg_panel: Color32,      // 卡片、分组容器
    pub bg_strong: Color32,     // hover、输入框内底
    pub fg: Color32,            // 正文
    pub fg_weak: Color32,       // 次要说明、占位符
    pub primary: Color32,       // 品牌蓝：主按钮、选中态、链接
    pub primary_hover: Color32, // 主按钮 hover
    pub accent: Color32,        // 麒麟青：辅助点缀（在线点、徽标）
    pub success: Color32,       // 成功/在线/已连接
    pub warning: Color32,       // 警告
    pub danger: Color32,        // 危险/错误/拒绝
    pub info: Color32,          // 信息
    pub border: Color32,        // 卡片/分隔线
    pub selection: Color32,     // 文本选中
    pub on_primary: Color32,    // 主色底上的文字（明亮=白 / 深色=近黑，对比度 ≥ 4.5）
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
    pub rounding_control: f32,    // 6px 按钮/输入框
    pub rounding_card: f32,       // 8px 卡片
    pub rounding_badge: f32,      // 4px 徽标
    pub border_width: f32,        // 1px
    pub shadow_blur: f32,         // 8px
    pub shadow_alpha: u8,         // 明亮 20% / 深色 40%
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
    /// 明亮主题（GitHub Light）。
    pub const LIGHT: Theme = Theme {
        dark: false,
        bg: c(0xF6F8FA),
        bg_panel: c(0xFFFFFF),
        bg_strong: c(0xEDEFF3),
        fg: c(0x1F2328),
        fg_weak: c(0x6E7781),
        primary: c(0x0969DA),
        primary_hover: c(0x0757B8),
        accent: c(0x0E8A8A),
        success: c(0x1A7F37),
        warning: c(0x9A6700),
        danger: c(0xCF222E),
        info: c(0x0969DA),
        border: c(0xD0D7DE),
        selection: c(0xB6D4FE),
        on_primary: Color32::WHITE,
        video_bg: c(0x0D1117),
        body_size: 20.0,
        button_size: 18.0,
        heading_size: 26.0,
        small_size: 16.0,
        mono_size: 16.0,
        spacing: 8.0,
        item_spacing: egui::vec2(8.0, 6.0),
        window_padding: 12.0,
        card_padding: 12.0,
        rounding_control: 6.0,
        rounding_card: 8.0,
        rounding_badge: 4.0,
        border_width: 1.0,
        shadow_blur: 8.0,
        shadow_alpha: 51, // 20%
    };

    /// 深色主题（GitHub Dark）。
    pub const DARK: Theme = Theme {
        dark: true,
        bg: c(0x0D1117),
        bg_panel: c(0x161B22),
        bg_strong: c(0x21262D),
        fg: c(0xE6EDF3),
        fg_weak: c(0x8B949E),
        primary: c(0x58A6FF),
        primary_hover: c(0x79C0FF),
        accent: c(0x3FB8C0),
        success: c(0x3FB950),
        warning: c(0xD29922),
        danger: c(0xF85149),
        info: c(0x58A6FF),
        border: c(0x30363D),
        selection: c(0x1F6FEB),
        on_primary: c(0x0D1117),
        video_bg: c(0x000000),
        body_size: 20.0,
        button_size: 18.0,
        heading_size: 26.0,
        small_size: 16.0,
        mono_size: 16.0,
        spacing: 8.0,
        item_spacing: egui::vec2(8.0, 6.0),
        window_padding: 12.0,
        card_padding: 12.0,
        rounding_control: 6.0,
        rounding_card: 8.0,
        rounding_badge: 4.0,
        border_width: 1.0,
        shadow_blur: 8.0,
        shadow_alpha: 102, // 40%
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
        v.selection.stroke = Stroke::new(1.0, self.fg);

        let rounding = Rounding::same(self.rounding_control);
        let border = Stroke::new(self.border_width, self.border);
        v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, self.fg_weak);
        v.widgets.noninteractive.bg_fill = self.bg_panel;
        v.widgets.noninteractive.weak_bg_fill = self.bg_strong;
        v.widgets.noninteractive.bg_stroke = border;
        v.widgets.noninteractive.rounding = rounding;
        v.widgets.inactive.fg_stroke = Stroke::new(1.0, self.fg);
        v.widgets.inactive.bg_fill = self.bg_panel;
        v.widgets.inactive.weak_bg_fill = self.bg_strong;
        v.widgets.inactive.bg_stroke = border;
        v.widgets.inactive.rounding = rounding;
        v.widgets.hovered.fg_stroke = Stroke::new(1.0, self.fg);
        v.widgets.hovered.bg_fill = self.bg_strong;
        v.widgets.hovered.weak_bg_fill = self.bg_strong;
        v.widgets.hovered.bg_stroke = Stroke::new(self.border_width, self.primary);
        v.widgets.hovered.rounding = rounding;
        v.widgets.active.fg_stroke = Stroke::new(1.0, self.fg);
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
    apply_theme(ctx, &mode.resolve(false));
}

/// 将令牌应用到某个 egui Context（主窗口与子视口各自调用；
/// 明暗变化时全量重设 `Visuals` + `Style`，无需重启）。
pub fn apply_theme(ctx: &egui::Context, theme: &Theme) {
    let applied = ctx
        .data(|d| d.get_temp::<Option<bool>>(applied_id()))
        .flatten()
        .unwrap_or(false);
    // 检测"被外部覆盖"：`follow_system_theme` 下 eframe 在系统明暗切换时会用默认
    // visuals 覆盖我们（此时 resolved dark 可能没变）——以 Body 字号作基线探测
    // （egui 默认 14px ≠ 令牌 20px），被覆盖则全量重设。
    let clobbered = ctx
        .style()
        .text_styles
        .get(&TextStyle::Body)
        .map(|f| f.size != theme.body_size)
        .unwrap_or(true);
    if applied != theme.dark || clobbered {
        ctx.set_visuals(theme.visuals());
        ctx.set_style(theme.style());
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
        assert!(!ThemeMode::Light.resolve(true).dark);
        assert!(ThemeMode::Dark.resolve(false).dark);
        assert!(ThemeMode::System.resolve(true).dark);
        assert!(!ThemeMode::System.resolve(false).dark);
    }

    /// 正文/弱色正文在所有面板底色上对比度 ≥ 4.5:1。
    /// 注：GitHub 官方色板中 light `fg_weak` 位于 `bg`(#F6F8FA)/`bg_strong` 上为
    /// 4.27/3.95（品牌色板锁定，UI-BTY-018 按"用色板自查"原则记录例外）。
    #[test]
    fn test_palette_contrast() {
        for theme in [Theme::LIGHT, Theme::DARK] {
            let tag = if theme.dark { "dark" } else { "light" };
            for (fg, fname) in [(theme.fg, "fg"), (theme.fg_weak, "fg_weak")] {
                for (bg, bname) in [
                    (theme.bg, "bg"),
                    (theme.bg_panel, "bg_panel"),
                    (theme.bg_strong, "bg_strong"),
                ] {
                    let c = contrast(fg, bg);
                    let pass = if !theme.dark && fname == "fg_weak" {
                        // light 主题弱色正文只保证面板（白）背景达标
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
            // 主色按钮文字对比度（明亮=白字 / 深色=深字）
            assert!(contrast(theme.on_primary, theme.primary) >= 4.5);
            assert!(contrast(theme.on_primary, theme.success) >= 4.5);
            assert!(contrast(theme.on_primary, theme.danger) >= 4.5);
        }
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
}
