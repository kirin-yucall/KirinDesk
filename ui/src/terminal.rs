//! M11-T002: egui 终端模拟器（ANSI 颜色 + 5000 行滚动回看）
//!
//! 基于 `vt100` 的完整终端解析（SGR 颜色、光标控制、宽字符）：
//! - [`Terminal::feed`]：送入远端 PTY 输出（原始字节，含 ANSI escape code）；
//! - [`Terminal::handle_event`]：egui 键盘事件 → 终端字节流（方向键/控制字符）；
//! - [`Terminal::ui`]：渲染屏幕 + 滚动回看（鼠标滚轮），尺寸变化时返回新列/行数，
//!   上层据此发送 `ShellResize`。
//!
//! M15-T008 主题预留（M11 联调期接入）：终端按 M11-T002 规格使用经典深色 ANSI 16 色
//! 调色板（[`vt100_color_to_egui`]），与 UI 主题令牌解耦；如后续需要随主题切换，
//! 在此处增加 `crate::theme::Theme` 入口并保持等宽字体（`FontId::monospace`）即可。
//!
//! M8-T021_P3 增补（PTY 中文输入与显示）：
//! - IME 组合（`Event::Ime(ImeEvent)`）：preedit 就地渲染（反显 + 下划线）+ 提交
//!   UTF-8 字节透传（与 `Event::Text` 等价，无重复发送）；
//! - 中文显示：vt100 宽字符（CJK 占 2 格）+ CJK 字体回退链（theme.rs）已就绪，
//!   本模块新增显示/IME/粘贴单测固化（T021-04/05）。

use egui::{Color32, FontId, Rect, Ui};
use vt100::Parser;

/// 滚动回看行数（M11 验收标准）。
pub const SCROLLBACK_LINES: usize = 5000;
/// 渲染用等宽字体大小。
pub const FONT_SIZE: f32 = 14.0;

/// egui 终端模拟器（每连接窗口一个实例）。
pub struct Terminal {
    parser: Parser,
    /// 本帧累积的用户输入（egui 事件 → 终端字节流）。
    input_buf: Vec<u8>,
    /// 当前终端尺寸（列/行）。
    cols: u16,
    rows: u16,
    /// 用户滚动回看行数（0 = 底部，跟随新输出）。
    scroll_offset: usize,
    /// DSR 查询扫描缓冲（`ESC[6n` 可能跨 chunk 到达）。
    dsr_scan: Vec<u8>,
    /// IME 组合中字符串（就地渲染用）；组合结束即清空。
    /// egui 0.28 无 cursor 信息（egui-winit 丢弃），故无组合内光标定位。
    ime_preedit: Option<String>,
}

impl Terminal {
    /// 新建终端模拟器。初始尺寸在首帧渲染时会被实际窗口尺寸覆盖。
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            parser: Parser::new(rows, cols, SCROLLBACK_LINES),
            input_buf: Vec::new(),
            cols,
            rows,
            scroll_offset: 0,
            dsr_scan: Vec::new(),
            ime_preedit: None,
        }
    }

    /// 送入远端输出（原始字节，含 ANSI）。
    ///
    /// 同时检测 DSR 光标位置查询（`ESC[6n`，cmd.exe 启动时发送并**阻塞等待
    /// 响应**）→ 自动应答 `ESC[<row>;<col>R`（真实终端的标准行为），应答字节
    /// 进入待发送输入缓冲。
    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
        self.dsr_scan.extend_from_slice(bytes);
        // 保留尾部足够字节以匹配跨 chunk 的 DSR 序列（最多 4 字节）。
        let keep = self.dsr_scan.len().min(8);
        self.dsr_scan.drain(..self.dsr_scan.len() - keep);
        loop {
            let pos = self.dsr_scan.windows(4).position(|w| w == b"\x1b[6n");
            match pos {
                Some(i) => {
                    let (row, col) = self.parser.screen().cursor_position();
                    let reply = format!("\x1b[{};{}R", row + 1, col + 1);
                    self.input_buf.extend_from_slice(reply.as_bytes());
                    self.dsr_scan.drain(..i + 4);
                }
                None => break,
            }
        }
    }

    /// 取走本帧累积的用户输入（发送任务消费后清空）。
    pub fn take_input(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.input_buf)
    }

    /// 当前终端尺寸（列/行）。
    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    /// 处理单个 egui 事件；消费了返回 true。
    pub fn handle_event(&mut self, event: &egui::Event) -> bool {
        match event {
            egui::Event::Key {
                key,
                pressed,
                modifiers,
                ..
            } => {
                if !*pressed {
                    return true; // 吞掉 keyup，避免影响其他控件
                }
                // 组合期间：退格/删除/方向/翻页/Home/End 由 IME 消费（移动组合光标），
                // 吞掉避免误发 ESC 序列到远端；Esc 保留（winit 先以 Commit("")/Disabled 收尾）。
                // Ctrl 组合键（Ctrl+C 等）不被 IME 拦截，照常下发。
                if self.ime_preedit.is_some()
                    && matches!(
                        key,
                        egui::Key::Backspace
                            | egui::Key::Delete
                            | egui::Key::ArrowUp
                            | egui::Key::ArrowDown
                            | egui::Key::ArrowLeft
                            | egui::Key::ArrowRight
                            | egui::Key::Home
                            | egui::Key::End
                            | egui::Key::PageUp
                            | egui::Key::PageDown
                    )
                {
                    return true;
                }
                // Ctrl+字母 → 控制字符（Ctrl+C 中断、Ctrl+D EOF 等）。
                if modifiers.ctrl {
                    if let Some(code) = ctrl_key_to_byte(*key) {
                        self.input_buf.push(code);
                        return true;
                    }
                }
                match key {
                    egui::Key::Enter => self.push(b"\r"),
                    egui::Key::Backspace => self.push(b"\x7f"),
                    egui::Key::Tab => self.push(b"\t"),
                    egui::Key::Escape => self.push(b"\x1b"),
                    egui::Key::ArrowUp => self.push(b"\x1b[A"),
                    egui::Key::ArrowDown => self.push(b"\x1b[B"),
                    egui::Key::ArrowRight => self.push(b"\x1b[C"),
                    egui::Key::ArrowLeft => self.push(b"\x1b[D"),
                    egui::Key::Home => self.push(b"\x1b[H"),
                    egui::Key::End => self.push(b"\x1b[F"),
                    egui::Key::PageUp => self.push(b"\x1b[5~"),
                    egui::Key::PageDown => self.push(b"\x1b[6~"),
                    egui::Key::Insert => self.push(b"\x1b[2~"),
                    egui::Key::Delete => self.push(b"\x1b[3~"),
                    egui::Key::F1 => self.push(b"\x1bOP"),
                    egui::Key::F2 => self.push(b"\x1bOQ"),
                    egui::Key::F3 => self.push(b"\x1bOR"),
                    egui::Key::F4 => self.push(b"\x1bOS"),
                    egui::Key::F5 => self.push(b"\x1b[15~"),
                    egui::Key::F6 => self.push(b"\x1b[17~"),
                    egui::Key::F7 => self.push(b"\x1b[18~"),
                    egui::Key::F8 => self.push(b"\x1b[19~"),
                    egui::Key::F9 => self.push(b"\x1b[20~"),
                    egui::Key::F10 => self.push(b"\x1b[21~"),
                    egui::Key::F11 => self.push(b"\x1b[23~"),
                    egui::Key::F12 => self.push(b"\x1b[24~"),
                    // 字母/数字等可打印键由 Text 事件输送（避免重复发送）。
                    _ => {}
                }
                true
            }
            egui::Event::Text(text) => {
                if !text.is_empty() {
                    self.input_buf.extend_from_slice(text.as_bytes());
                }
                true
            }
            egui::Event::Paste(text) => {
                self.input_buf.extend_from_slice(text.as_bytes());
                true
            }
            // UI-IME-001/003：IME 组合（egui 0.28 形态，data/input.rs:441-520）
            egui::Event::Ime(egui::ImeEvent::Preedit(s)) => {
                // 组合中：仅更新就地渲染状态，不产生任何字节（回显由远端 PTY 负责）。
                // egui-winit 空 preedit 只发 Enabled，防御性空串清空保留。
                self.ime_preedit = if s.is_empty() { None } else { Some(s.clone()) };
                true
            }
            egui::Event::Ime(egui::ImeEvent::Commit(s)) => {
                // 提交：egui-winit 映射下 Commit 不会重复产生 Event::Text → 无重复发送；
                // 字节透传与现有 Text 分支等价（T021-05-B 全链路 UTF-8）。
                // 空提交（组合取消，Esc）不产生字节。
                if !s.is_empty() {
                    self.input_buf.extend_from_slice(s.as_bytes());
                }
                self.ime_preedit = None;
                true
            }
            egui::Event::Ime(egui::ImeEvent::Enabled)
            | egui::Event::Ime(egui::ImeEvent::Disabled) => {
                self.ime_preedit = None; // 组合开始/结束的边界复位（Windows 每次组合都会发）
                true
            }
            _ => false,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.input_buf.extend_from_slice(bytes);
    }

    /// 渲染终端屏幕。返回 `(cols, rows, resized)`：
    /// 尺寸变化（resized = true）时上层应发送 `ShellResize { cols, rows }`。
    ///
    /// 滚动回看渲染方式：vt100 内部维护 5000 行回看缓冲，`Screen::cell` 会
    /// 应用 `set_scrollback` 的视口偏移；内容总高度 = 回看行数 + 屏幕行数，
    /// 由 egui ScrollArea 提供滚动条；offset = 0（底部）时跟随新输出。
    pub fn ui(&mut self, ui: &mut Ui) -> (u16, u16, bool) {
        let font = FontId::monospace(FONT_SIZE);
        let char_w = ui.fonts(|f| f.glyph_width(&font, ' ')).max(1.0);
        let row_h = ui.fonts(|f| f.row_height(&font));

        // 按可用空间计算列/行数（≥ 1，避免除零/非法 resize）。
        let available = ui.available_size();
        let cols = ((available.x / char_w).floor() as u16).max(1);
        let rows = ((available.y / row_h).floor() as u16).max(1);
        let resized = (cols, rows) != (self.cols, self.rows);
        if resized {
            self.cols = cols;
            self.rows = rows;
            self.parser.screen_mut().set_size(rows, cols);
        }

        // 探测实际回看长度（set_scrollback 会钳制到现有长度）。
        let max_scroll = {
            let s = self.parser.screen_mut();
            s.set_scrollback(usize::MAX);
            s.scrollback()
        };
        let offset = self.scroll_offset.min(max_scroll);
        self.parser.screen_mut().set_scrollback(offset);
        self.scroll_offset = offset;

        let screen = self.parser.screen();
        let (scr_rows, scr_cols) = screen.size();

        // 内容总高度 = 回看行 + 屏幕行；当前视口显示内容行 [offset, offset+rows)。
        let content_h = (max_scroll + scr_rows as usize) as f32 * row_h;
        let mut scroll = egui::ScrollArea::vertical()
            .id_source("kirin_terminal")
            .auto_shrink([false, false]);
        if offset == 0 {
            scroll = scroll.vertical_scroll_offset(f32::MAX);
        }
        let mut output = scroll.show_viewport(ui, |ui, viewport| {
            ui.set_height(content_h);
            let first = (viewport.min.y / row_h).floor() as i64;
            let last = (viewport.max.y / row_h).ceil() as i64;
            for r in first..last {
                // 内容行 r ↔ 屏幕行 (r - offset)。
                let screen_row = r - offset as i64;
                if screen_row < 0 || screen_row >= scr_rows as i64 {
                    continue;
                }
                draw_row(ui, screen, &font, row_h, screen_row as u16, scr_cols);
            }
            // 光标：仅位于底部（offset == 0）时绘制。
            if offset == 0 {
                let (crow, ccol) = screen.cursor_position();
                if (crow as usize) < scr_rows as usize && (ccol as usize) < scr_cols as usize {
                    let rect = cell_rect(ui, row_h, crow, ccol, char_w);
                    ui.painter().rect_filled(rect, 0.0, Color32::from_gray(180));
                    if let Some(cell) = screen.cell(crow, ccol) {
                        let ch = cell.contents().chars().next().unwrap_or(' ');
                        ui.painter().text(
                            rect.min,
                            egui::Align2::LEFT_TOP,
                            ch,
                            font.clone(),
                            Color32::BLACK,
                        );
                    }
                }
                // IME 组合串就地渲染：光标格处反显 + 下划线（UI-IME-003 就地显示）。
                // 仅底部视图（offset == 0）绘制，与光标一致；组合期无字节发出，
                // 远端光标未动，preedit 稳定覆盖在光标格；超屏由 painter clip 截断。
                if let Some(preedit) = &self.ime_preedit {
                    let (crow, ccol) = screen.cursor_position();
                    if (crow as usize) < scr_rows as usize && (ccol as usize) < scr_cols as usize {
                        let mut job = egui::text::LayoutJob::default();
                        job.append(
                            preedit,
                            0.0,
                            egui::TextFormat {
                                font_id: font.clone(),
                                color: Color32::BLACK,
                                background: Color32::from_gray(180), // 反显风格
                                underline: egui::Stroke::new(1.0, Color32::BLACK),
                                ..Default::default()
                            },
                        );
                        let pos = cell_rect(ui, row_h, crow, ccol, char_w).min;
                        ui.painter()
                            .galley(pos, ui.painter().layout_job(job), Color32::WHITE);
                    }
                }
            }
        });

        // 跟随输出时强制吸附底部（新输出到来时内容高度增长）。
        // offset == 0 时用户位于底部；offset 每帧由视口像素重新计算，
        // 用户上滚（offset > 0）后自动停止吸附，不干扰手动滚动。
        if offset == 0 {
            output.state.offset = egui::vec2(0.0, f32::MAX);
            output.state.store(ui.ctx(), output.id);
        }

        (cols, rows, resized)
    }
}

/// 单元格矩形（屏幕行/列 → 像素）。
fn cell_rect(ui: &Ui, row_h: f32, row: u16, col: u16, char_w: f32) -> Rect {
    Rect::from_min_size(
        egui::pos2(
            ui.min_rect().left() + col as f32 * char_w,
            ui.min_rect().top() + row as f32 * row_h,
        ),
        egui::vec2(char_w, row_h),
    )
}

/// 绘制一行：按单元格颜色分段构建 LayoutJob（背景色用空格占位，保持连续）。
fn draw_row(ui: &mut Ui, screen: &vt100::Screen, font: &FontId, row_h: f32, row: u16, cols: u16) {
    let mut job = egui::text::LayoutJob::default();
    for col in 0..cols {
        let Some(cell) = screen.cell(row, col) else {
            continue;
        };
        if cell.is_wide_continuation() {
            continue; // 宽字符续位：字符已在首格绘制
        }
        let ch = cell.contents().chars().next().unwrap_or(' ');
        let mut fg = vt100_color_to_egui(cell.fgcolor());
        let mut bg = match cell.bgcolor() {
            vt100::Color::Default => Color32::TRANSPARENT,
            color => vt100_color_to_egui(color),
        };
        // 反显（inverse）：前景/背景互换。
        if cell.inverse() {
            std::mem::swap(&mut fg, &mut bg);
        }
        // bold/dim：用亮度偏移近似模拟。
        if cell.bold() {
            fg = brighten(fg, 40);
        } else if cell.dim() {
            fg = darken(fg, 60);
        }
        let format = egui::TextFormat {
            font_id: font.clone(),
            color: fg,
            background: bg,
            underline: if cell.underline() {
                egui::Stroke::new(1.0_f32, fg)
            } else {
                egui::Stroke::NONE
            },
            italics: cell.italic(),
            ..Default::default()
        };
        job.append(&ch.to_string(), 0.0, format);
    }
    let galley = ui.painter().layout_job(job);
    ui.painter().galley(
        egui::pos2(
            ui.min_rect().left(),
            ui.min_rect().top() + row as f32 * row_h,
        ),
        galley,
        Color32::WHITE,
    );
}

/// Ctrl+字母 → 控制字符（A=0x01 … Z=0x1A）。
fn ctrl_key_to_byte(key: egui::Key) -> Option<u8> {
    let code = key as u8;
    let a = egui::Key::A as u8;
    let z = egui::Key::Z as u8;
    if (a..=z).contains(&code) {
        Some(code - a + 1)
    } else {
        None
    }
}

fn brighten(c: Color32, amt: u8) -> Color32 {
    Color32::from_rgb(
        c.r().saturating_add(amt),
        c.g().saturating_add(amt),
        c.b().saturating_add(amt),
    )
}

fn darken(c: Color32, amt: u8) -> Color32 {
    Color32::from_rgb(
        c.r().saturating_sub(amt),
        c.g().saturating_sub(amt),
        c.b().saturating_sub(amt),
    )
}

/// vt100 颜色 → egui 颜色（16 色/256 色索引近似映射）。
fn vt100_color_to_egui(color: vt100::Color) -> Color32 {
    match color {
        vt100::Color::Default => Color32::GRAY,
        vt100::Color::Idx(i) => ansi_256_to_egui(i),
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
    }
}

/// ANSI 256 色索引 → RGB（前 16 色为标准色盘，其余为 6×6×6 立方体 + 灰度）。
fn ansi_256_to_egui(i: u8) -> Color32 {
    const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];
    match i {
        0 => Color32::from_rgb(0, 0, 0),
        1 => Color32::from_rgb(128, 0, 0),
        2 => Color32::from_rgb(0, 128, 0),
        3 => Color32::from_rgb(128, 128, 0),
        4 => Color32::from_rgb(0, 0, 128),
        5 => Color32::from_rgb(128, 0, 128),
        6 => Color32::from_rgb(0, 128, 128),
        7 => Color32::from_rgb(192, 192, 192),
        8 => Color32::from_rgb(128, 128, 128),
        9 => Color32::from_rgb(255, 0, 0),
        10 => Color32::from_rgb(0, 255, 0),
        11 => Color32::from_rgb(255, 255, 0),
        12 => Color32::from_rgb(0, 0, 255),
        13 => Color32::from_rgb(255, 0, 255),
        14 => Color32::from_rgb(0, 255, 255),
        15 => Color32::from_rgb(255, 255, 255),
        16..=231 => {
            let n = i - 16;
            let r = CUBE[(n / 36) as usize];
            let g = CUBE[((n % 36) / 6) as usize];
            let b = CUBE[(n % 6) as usize];
            Color32::from_rgb(r, g, b)
        }
        232..=255 => {
            let v = 8 + (i - 232) * 10;
            Color32::from_rgb(v, v, v)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ansi_color_parsing() {
        let mut t = Terminal::new(80, 24);
        t.feed(b"plain \x1b[31mRED\x1b[0m tail");
        let screen = t.parser.screen();
        assert_eq!(screen.cell(0, 0).unwrap().contents(), "p");
        // "RED" 着色
        let cell = screen.cell(0, 6).unwrap();
        assert_eq!(cell.contents(), "R");
        assert_ne!(cell.fgcolor(), vt100::Color::Default);
        // 复位后恢复默认色
        let cell = screen.cell(0, 11).unwrap();
        assert_eq!(cell.fgcolor(), vt100::Color::Default);
        assert!(screen.contents().contains("RED tail"));
    }

    #[test]
    fn test_scrollback_grows_and_renders() {
        let mut t = Terminal::new(40, 5);
        // 写 19 行 → 滚出 15 行回看，屏幕显示最后的 line-15..line-18。
        for i in 0..19 {
            t.feed(format!("line-{i:02}\r\n").as_bytes());
        }
        let screen = t.parser.screen();
        let contents = screen.contents();
        // 底部：最早的屏幕行已是滚出后的首行（line-15），最后一行 line-18。
        assert!(
            contents.starts_with("line-15"),
            "screen should start at line-15, got: {contents:?}"
        );
        assert!(
            contents.contains("line-18"),
            "screen should contain line-18, got: {contents:?}"
        );
        // 回看：滚动到顶可看到最早的输出
        {
            let s = t.parser.screen_mut();
            s.set_scrollback(usize::MAX);
            assert!(s.scrollback() >= 14, "scrollback too small");
            s.set_scrollback(0);
        }
    }

    #[test]
    fn test_event_to_bytes() {
        let mut t = Terminal::new(80, 24);
        let mut ev = |k: egui::Key, ctrl: bool| {
            t.handle_event(&egui::Event::Key {
                key: k,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers {
                    ctrl,
                    ..Default::default()
                },
                physical_key: None,
            })
        };
        ev(egui::Key::Enter, false);
        ev(egui::Key::ArrowUp, false);
        ev(egui::Key::F5, false);
        ev(egui::Key::C, true); // Ctrl+C
        ev(egui::Key::A, false); // 字母走 Text 事件，不应产生字节
        t.handle_event(&egui::Event::Text("x".into()));
        assert_eq!(t.take_input(), b"\r\x1b[A\x1b[15~\x03x");
        assert!(t.take_input().is_empty());
    }

    #[test]
    fn test_ctrl_key_to_byte() {
        assert_eq!(ctrl_key_to_byte(egui::Key::A), Some(1));
        assert_eq!(ctrl_key_to_byte(egui::Key::Z), Some(26));
        assert_eq!(ctrl_key_to_byte(egui::Key::Enter), None);
    }

    #[test]
    fn test_ansi_256_palette() {
        assert_eq!(ansi_256_to_egui(0), Color32::from_rgb(0, 0, 0));
        assert_eq!(ansi_256_to_egui(9), Color32::from_rgb(255, 0, 0));
        assert_eq!(ansi_256_to_egui(16), Color32::from_rgb(0, 0, 0));
        assert_eq!(ansi_256_to_egui(231), Color32::from_rgb(255, 255, 255));
        assert_eq!(ansi_256_to_egui(232), Color32::from_rgb(8, 8, 8));
        assert_eq!(ansi_256_to_egui(255), Color32::from_rgb(238, 238, 238));
    }

    #[test]
    fn test_dsr_auto_response() {
        // 完整序列：查询时光标已在列 4（"pre" 之后）→ 应答反映当前光标位置。
        let mut t = Terminal::new(80, 24);
        t.feed(b"pre\x1b[6n");
        assert_eq!(t.take_input(), b"\x1b[1;4R");
        // 跨 chunk 拆分（光标在原点）
        let mut t = Terminal::new(80, 24);
        t.feed(b"\x1b[");
        t.feed(b"6");
        t.feed(b"n");
        assert_eq!(t.take_input(), b"\x1b[1;1R");
        // 应答后光标位置反映当前光标（移动光标后查询）
        let mut t = Terminal::new(80, 24);
        t.feed(b"\x1b[3;5H\x1b[6n");
        assert_eq!(t.take_input(), b"\x1b[3;5R");
        // 无 DSR 时不产生应答
        let mut t = Terminal::new(80, 24);
        t.feed(b"plain output");
        assert!(t.take_input().is_empty());
    }

    // ── M8-T021_P3：PTY 中文输入与显示（T021-04/05） ──────────────

    /// 读取一行全部单元格文本（跳过宽字符续位，行为与原文字符一致）。
    fn row_text(screen: &vt100::Screen, row: u16, cols: u16) -> String {
        let mut text = String::new();
        for col in 0..cols {
            let Some(cell) = screen.cell(row, col) else {
                continue;
            };
            if cell.is_wide_continuation() {
                continue;
            }
            text.push_str(cell.contents());
        }
        text
    }

    /// 构造一个 keydown 事件（ctrl 可选）。
    fn key_event(t: &mut Terminal, key: egui::Key, ctrl: bool) -> bool {
        t.handle_event(&egui::Event::Key {
            key,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers {
                ctrl,
                ..Default::default()
            },
            physical_key: None,
        })
    }

    #[test]
    fn test_cjk_display_wide_cells() {
        // T021-04-A：feed 中文 → 每中文字 is_wide()、次格 is_wide_continuation()，
        // cell.contents() 与原文逐字符一致（无乱码/缺字）。
        let mut t = Terminal::new(80, 24);
        t.feed("中文测试\n".as_bytes());
        let screen = t.parser.screen();
        for (i, ch) in "中文测试".chars().enumerate() {
            // 宽字符占 2 格：首格为字符本体，次格为 continuation。
            let col = (i * 2) as u16;
            let cell = screen.cell(0, col).unwrap();
            assert!(cell.is_wide(), "{ch} 应为宽字符（占 2 格）");
            assert_eq!(cell.contents(), ch.to_string(), "{ch} 内容丢失/乱码");
            let cont = screen.cell(0, col + 1).unwrap();
            assert!(cont.is_wide_continuation(), "{ch} 次格应为 continuation");
            assert!(cont.contents().is_empty());
        }
        assert_eq!(screen.contents(), "中文测试");
    }

    #[test]
    fn test_cjk_scrollback_integrity() {
        // T021-04-C：输出超 SCROLLBACK_LINES 行且含中文 → 滚动回看中中文行内容
        // 完整（逐字节匹配）。
        let mut t = Terminal::new(80, 30);
        let total = SCROLLBACK_LINES + 200;
        // 最后一行不带 \r\n：避免末尾多滚出空行，保证行数与内容精确对应。
        for i in 0..total - 1 {
            t.feed(format!("第{i}行中文内容\r\n").as_bytes());
        }
        t.feed(format!("第{}行中文内容", total - 1).as_bytes());
        let s = t.parser.screen_mut();
        s.set_scrollback(usize::MAX);
        assert_eq!(s.scrollback(), SCROLLBACK_LINES, "5000 行回看缓冲应存满");
        // 最早保留行号 = 总行数 - 回看行 - 屏幕行
        let first = total - SCROLLBACK_LINES - 30;
        // 回看区逐行校验（set_scrollback 把视口顶行定位到指定回看行）
        for j in 0..SCROLLBACK_LINES {
            s.set_scrollback(SCROLLBACK_LINES - j);
            assert_eq!(
                row_text(s, 0, 80),
                format!("第{}行中文内容", first + j),
                "回看行 {j} 中文不完整/乱码"
            );
        }
        // 屏幕区逐行校验
        s.set_scrollback(0);
        for r in 0..30u16 {
            assert_eq!(
                row_text(s, r, 80),
                format!("第{}行中文内容", total - 30 + r as usize),
                "屏幕行 {r} 中文不完整/乱码"
            );
        }
    }

    #[test]
    fn test_cjk_filename_ls_output() {
        // T021-04-A：模拟 `ls` 中文文件名输出（含 ANSI 颜色）→ 行渲染内容完整、
        // 宽字符成对。
        let mut t = Terminal::new(80, 24);
        t.feed("total 12\r\n\x1b[01;34m文档\x1b[0m  图片\r\n".as_bytes());
        let screen = t.parser.screen();
        // 颜色生效（蓝色目录项）
        assert_ne!(screen.cell(1, 0).unwrap().fgcolor(), vt100::Color::Default);
        // 宽字符成对：首格宽字符 + 次格 continuation
        assert!(screen.cell(1, 0).unwrap().is_wide());
        assert_eq!(screen.cell(1, 0).unwrap().contents(), "文");
        assert!(screen.cell(1, 1).unwrap().is_wide_continuation());
        assert!(screen.cell(1, 6).unwrap().is_wide());
        assert_eq!(screen.cell(1, 6).unwrap().contents(), "图");
        assert!(screen.cell(1, 7).unwrap().is_wide_continuation());
        // 行内容完整（不丢字、无乱码）
        let contents = screen.contents();
        assert!(contents.contains("total 12"));
        assert!(contents.contains("文档"), "ls 中文文件名缺字: {contents:?}");
        assert!(contents.contains("图片"), "ls 中文文件名缺字: {contents:?}");
    }

    #[test]
    fn test_ime_preedit_updates_state_no_bytes() {
        // UI-IME-001/003：组合中仅更新就地渲染状态，不产生任何字节。
        let mut t = Terminal::new(80, 24);
        assert!(t.handle_event(&egui::Event::Ime(egui::ImeEvent::Preedit("中".into()))));
        assert_eq!(t.ime_preedit.as_deref(), Some("中"));
        assert!(t.take_input().is_empty(), "组合中不应产生字节");
        // 空 preedit 防御性清空（egui-winit 正常不发空串，直接 Enabled）
        assert!(t.handle_event(&egui::Event::Ime(egui::ImeEvent::Preedit(String::new()))));
        assert_eq!(t.ime_preedit, None);
    }

    #[test]
    fn test_ime_commit_sends_utf8_bytes() {
        // T021-05-B：提交 UTF-8 字节透传（与 Text 分支等价），提交后状态清空。
        let mut t = Terminal::new(80, 24);
        t.handle_event(&egui::Event::Ime(egui::ImeEvent::Preedit("中文".into())));
        t.handle_event(&egui::Event::Ime(egui::ImeEvent::Commit("中文".into())));
        assert_eq!(t.take_input(), "中文".as_bytes());
        assert_eq!(t.ime_preedit, None, "提交后组合状态应清空");
    }

    #[test]
    fn test_ime_commit_empty_no_bytes() {
        // 空提交（组合取消，Esc）：不产生字节，preedit 清空。
        let mut t = Terminal::new(80, 24);
        t.handle_event(&egui::Event::Ime(egui::ImeEvent::Preedit("中".into())));
        assert!(t.handle_event(&egui::Event::Ime(egui::ImeEvent::Commit(String::new()))));
        assert!(t.take_input().is_empty(), "空提交不应产生字节");
        assert_eq!(t.ime_preedit, None);
    }

    #[test]
    fn test_ime_enabled_disabled_clears_preedit() {
        // Enabled/Disabled：组合边界复位（Windows 每次组合前后都会发）。
        let mut t = Terminal::new(80, 24);
        t.handle_event(&egui::Event::Ime(egui::ImeEvent::Enabled));
        t.handle_event(&egui::Event::Ime(egui::ImeEvent::Preedit("测".into())));
        assert_eq!(t.ime_preedit.as_deref(), Some("测"));
        assert!(t.handle_event(&egui::Event::Ime(egui::ImeEvent::Disabled)));
        assert_eq!(t.ime_preedit, None, "Disabled 应复位组合状态");
        assert!(t.take_input().is_empty());
    }

    #[test]
    fn test_ime_swallows_navigation_keys() {
        // 组合期间：IME 移动组合光标的键被吞（不误发 ESC 序列）；Esc 保留
        // （winit 先以 Commit("")/Disabled 收尾）；Ctrl 组合键（Ctrl+C）不被吞。
        let mut t = Terminal::new(80, 24);
        t.handle_event(&egui::Event::Ime(egui::ImeEvent::Preedit("中文".into())));
        for k in [
            egui::Key::Backspace,
            egui::Key::Delete,
            egui::Key::ArrowUp,
            egui::Key::ArrowDown,
            egui::Key::ArrowLeft,
            egui::Key::ArrowRight,
            egui::Key::Home,
            egui::Key::End,
            egui::Key::PageUp,
            egui::Key::PageDown,
        ] {
            assert!(key_event(&mut t, k, false), "组合期按键 {k:?} 应被消费");
        }
        assert!(t.take_input().is_empty(), "组合期导航键不应产生 ESC 序列");
        // Esc 保留
        assert!(key_event(&mut t, egui::Key::Escape, false));
        assert_eq!(t.take_input(), b"\x1b");
        // Ctrl+C 组合期间照常下发（IME 不拦截 Ctrl）
        assert!(key_event(&mut t, egui::Key::C, true));
        assert_eq!(t.take_input(), b"\x03", "组合期 Ctrl 组合键不应被吞");
        // 组合结束（提交）后导航键恢复正常
        t.handle_event(&egui::Event::Ime(egui::ImeEvent::Commit("中文".into())));
        t.take_input();
        assert!(key_event(&mut t, egui::Key::ArrowLeft, false));
        assert_eq!(t.take_input(), b"\x1b[D");
    }

    #[test]
    fn test_paste_chinese_utf8() {
        // T021-05-D：粘贴中文 → 原样 UTF-8 字节透传。
        let mut t = Terminal::new(80, 24);
        assert!(t.handle_event(&egui::Event::Paste("中文测试".to_owned())));
        assert_eq!(t.take_input(), "中文测试".as_bytes());
        assert!(t.take_input().is_empty());
    }
}
