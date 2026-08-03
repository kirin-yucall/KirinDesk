//! M13-T006 文件传输面板：任务列表 + 进度条 + 控制按钮 + 拖拽发送。
//!
//! 纯状态机（[`FilePanelState`]）可单测；egui 渲染（[`show_file_panel`]）
//! 由连接窗口/服务器面板调用。任务进度由会话任务经共享
//! `OnceLock<Mutex<FilePanelState>>` 更新，UI 每帧读取。

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use egui::{RichText, Ui};

use crate::theme::Theme;
use crate::t;
use crate::tf;
use crate::widgets::{action_button, badge, status_dot, BadgeKind, ButtonKind, ButtonState};

// ════════════════════════════════════════════════════════════════
// UI → 会话任务命令
// ════════════════════════════════════════════════════════════════

/// UI 线程 → 会话文件任务（unbounded channel，经 `file_tx` 发送）。
#[derive(Debug, Clone)]
pub enum FileCommand {
    /// 发送本地文件（拖拽/选择器）。
    SendFile { path: PathBuf },
    /// 取消任务（已写块回滚：删 `.part`）。
    Cancel { transfer_id: u64 },
    /// 暂停任务。
    Pause { transfer_id: u64 },
    /// 恢复任务。
    Resume { transfer_id: u64 },
}

// ════════════════════════════════════════════════════════════════
// 任务模型
// ════════════════════════════════════════════════════════════════

/// 传输方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileDirection {
    /// 本端发送（上传/推送）。
    Upload,
    /// 本端接收（下载/落盘）。
    Download,
}

impl FileDirection {
    pub fn label(self) -> &'static str {
        match self {
            Self::Upload => t!("filepanel.dir.upload"),
            Self::Download => t!("filepanel.dir.download"),
        }
    }
}

/// 任务状态（UI 展示；与 core 侧 [`TransferStatus`] 映射）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileTaskStatus {
    /// 排队等待（会话并发已满）。
    Queued,
    /// Offer 已发，等待对方接受。
    WaitingAccept,
    /// 传输中。
    Sending,
    /// 暂停。
    Paused,
    /// 完成。
    Completed,
    /// 失败。
    Failed(String),
    /// 已取消。
    Cancelled,
}

/// 文件任务条目（UI 模型）。
#[derive(Debug, Clone)]
pub struct FileTask {
    pub transfer_id: u64,
    pub name: String,
    pub size: u64,
    pub direction: FileDirection,
    pub done: u64,
    pub status: FileTaskStatus,
    /// 瞬时速度（bytes/s，由 [`FilePanelState::upsert`] 按增量自动计算）。
    pub speed: f64,
    /// 完成/失败后的落盘路径（「在文件夹中显示」）。
    pub path: Option<PathBuf>,
}

impl FileTask {
    /// 新任务（排队态）。
    pub fn queued(transfer_id: u64, name: String, size: u64, direction: FileDirection) -> Self {
        Self {
            transfer_id,
            name,
            size,
            direction,
            done: 0,
            status: FileTaskStatus::Queued,
            speed: 0.0,
            path: None,
        }
    }

    /// 进度比例 0..=1。
    pub fn progress_fraction(&self) -> f32 {
        if self.size == 0 {
            return 1.0;
        }
        (self.done as f32 / self.size as f32).clamp(0.0, 1.0)
    }
}

// ════════════════════════════════════════════════════════════════
// FilePanelState — 任务列表状态机（会话任务更新 + UI 读取）
// ════════════════════════════════════════════════════════════════

/// 文件面板状态（全局共享 `OnceLock<Mutex<FilePanelState>>`）。
#[derive(Debug, Default)]
pub struct FilePanelState {
    pub tasks: Vec<FileTask>,
    /// 速度采样：transfer_id → (上次 done 字节, 上次时刻 ms)。
    last_sample: HashMap<u64, (u64, u64)>,
}

impl FilePanelState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn find(&self, transfer_id: u64) -> Option<&FileTask> {
        self.tasks.iter().find(|t| t.transfer_id == transfer_id)
    }

    pub fn find_mut(&mut self, transfer_id: u64) -> Option<&mut FileTask> {
        self.tasks.iter_mut().find(|t| t.transfer_id == transfer_id)
    }

    /// 新增或更新任务；`done` 增量用于计算瞬时速度。
    pub fn upsert(&mut self, mut task: FileTask) {
        let now_ms = epoch_ms();
        if let Some(prev) = self.last_sample.get(&task.transfer_id) {
            let (prev_done, prev_ms) = *prev;
            if task.done >= prev_done && now_ms > prev_ms {
                let dt = (now_ms - prev_ms) as f64 / 1000.0;
                if dt > 0.0 {
                    task.speed = (task.done - prev_done) as f64 / dt;
                }
            }
        }
        self.last_sample
            .insert(task.transfer_id, (task.done, now_ms));
        if let Some(existing) = self.find_mut(task.transfer_id) {
            *existing = task;
        } else {
            self.tasks.push(task);
        }
    }

    /// 移除任务（清理完成/取消条目）。
    pub fn remove(&mut self, transfer_id: u64) {
        self.tasks.retain(|t| t.transfer_id != transfer_id);
        self.last_sample.remove(&transfer_id);
    }

    /// 活跃任务数（发送中/等待接受）。
    pub fn active_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| {
                matches!(
                    t.status,
                    FileTaskStatus::Sending
                        | FileTaskStatus::WaitingAccept
                        | FileTaskStatus::Paused
                )
            })
            .count()
    }

    /// 排队任务数。
    pub fn queued_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.status == FileTaskStatus::Queued)
            .count()
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ════════════════════════════════════════════════════════════════
// 格式化辅助
// ════════════════════════════════════════════════════════════════

/// 字节数 → 人类可读（B/KB/MB/GB）。
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// 速度 → 人类可读（bytes/s → `x.x MB/s`）。
pub fn format_speed(bytes_per_sec: f64) -> String {
    if bytes_per_sec <= 0.0 {
        return "—".to_string();
    }
    format!("{}/s", format_size(bytes_per_sec as u64))
}

// ════════════════════════════════════════════════════════════════
// egui 渲染
// ════════════════════════════════════════════════════════════════

/// 渲染文件面板（任务列表）。
///
/// `tx`：会话文件命令通道（`None` = 会话未连接/已断开，按钮禁用）。
pub fn show_file_panel(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FilePanelState,
    tx: Option<&tokio::sync::mpsc::UnboundedSender<FileCommand>>,
) {
    ui.horizontal(|ui| {
        ui.add(
            egui::Label::new(
                RichText::new(t!("filepanel.title"))
                    .size(theme.small_size)
                    .color(theme.fg_weak),
            )
            .selectable(false),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            badge(
                ui,
                theme,
                &tf!(
                    "filepanel.active_fmt",
                    state.active_count(),
                    state.queued_count()
                ),
                BadgeKind::Neutral,
            );
        });
    });
    ui.add_space(theme.spacing);

    if state.tasks.is_empty() {
        ui.add_space(theme.spacing * 2.0);
        ui.centered_and_justified(|ui| {
            ui.add(
                egui::Label::new(
                    RichText::new(t!("filepanel.empty"))
                        .size(theme.body_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
        });
        return;
    }

    let mut commands = Vec::new();
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let mut remove_ids = Vec::new();
            for task in &mut state.tasks {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&task.name).size(theme.body_size).strong(),
                            )
                            .selectable(false),
                        );
                        ui.add_space(8.0);
                        badge(
                            ui,
                            theme,
                            task.direction.label(),
                            match task.direction {
                                FileDirection::Upload => BadgeKind::Info,
                                FileDirection::Download => BadgeKind::Neutral,
                            },
                        );
                        let (label, kind) = match &task.status {
                            FileTaskStatus::Queued => (t!("filepanel.status.queued"), BadgeKind::Neutral),
                            FileTaskStatus::WaitingAccept => (t!("filepanel.status.waiting"), BadgeKind::Neutral),
                            FileTaskStatus::Sending => (t!("filepanel.status.sending"), BadgeKind::Info),
                            FileTaskStatus::Paused => (t!("filepanel.status.paused"), BadgeKind::Warning),
                            FileTaskStatus::Completed => (t!("filepanel.status.completed"), BadgeKind::Success),
                            FileTaskStatus::Failed(_) => (t!("filepanel.status.failed"), BadgeKind::Danger),
                            FileTaskStatus::Cancelled => (t!("filepanel.status.cancelled"), BadgeKind::Neutral),
                        };
                        badge(ui, theme, label, kind);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            // 控制按钮（行内小按钮）。
                            let connected = tx.is_some();
                            match &task.status {
                                FileTaskStatus::Sending | FileTaskStatus::WaitingAccept => {
                                    if connected {
                                        if ui
                                            .add(egui::Button::new(
                                                RichText::new(t!("filepanel.btn.pause"))
                                                    .size(theme.small_size),
                                            ))
                                            .clicked()
                                        {
                                            commands.push(FileCommand::Pause {
                                                transfer_id: task.transfer_id,
                                            });
                                        }
                                    }
                                    if connected
                                        && ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new(t!("filepanel.btn.cancel"))
                                                        .size(theme.small_size),
                                                )
                                                .fill(theme.bg_strong),
                                            )
                                            .clicked()
                                    {
                                        commands.push(FileCommand::Cancel {
                                            transfer_id: task.transfer_id,
                                        });
                                    }
                                }
                                FileTaskStatus::Paused => {
                                    if connected
                                        && ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new(t!("filepanel.btn.resume"))
                                                        .size(theme.small_size),
                                                )
                                                .fill(theme.bg_strong),
                                            )
                                            .clicked()
                                    {
                                        commands.push(FileCommand::Resume {
                                            transfer_id: task.transfer_id,
                                        });
                                    }
                                    if connected
                                        && ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new(t!("filepanel.btn.cancel"))
                                                        .size(theme.small_size),
                                                )
                                                .fill(theme.bg_strong),
                                            )
                                            .clicked()
                                    {
                                        commands.push(FileCommand::Cancel {
                                            transfer_id: task.transfer_id,
                                        });
                                    }
                                }
                                FileTaskStatus::Queued => {
                                    if connected
                                        && ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new(t!("filepanel.btn.cancel_queue"))
                                                        .size(theme.small_size),
                                                )
                                                .fill(theme.bg_strong),
                                            )
                                            .clicked()
                                    {
                                        commands.push(FileCommand::Cancel {
                                            transfer_id: task.transfer_id,
                                        });
                                    }
                                }
                                FileTaskStatus::Completed => {
                                    if let Some(path) = &task.path {
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new(t!(
                                                        "filepanel.btn.show_in_folder"
                                                    ))
                                                    .size(theme.small_size),
                                                )
                                                .fill(theme.bg_strong),
                                            )
                                            .clicked()
                                        {
                                            show_in_folder(path);
                                        }
                                    }
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new(t!("filepanel.btn.clear"))
                                                    .size(theme.small_size),
                                            )
                                            .fill(theme.bg_strong),
                                        )
                                        .clicked()
                                    {
                                        remove_ids.push(task.transfer_id);
                                    }
                                }
                                FileTaskStatus::Failed(_) | FileTaskStatus::Cancelled => {
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new(t!("filepanel.btn.clear"))
                                                    .size(theme.small_size),
                                            )
                                            .fill(theme.bg_strong),
                                        )
                                        .clicked()
                                    {
                                        remove_ids.push(task.transfer_id);
                                    }
                                }
                            }
                        });
                    });
                    // 进度行：进度条 + 字节 + 速度。
                    let frac = task.progress_fraction();
                    let mut bar = egui::ProgressBar::new(frac)
                        .desired_width(ui.available_width() - 200.0)
                        .text(format!(
                            "{}%  {}/{}",
                            (frac * 100.0) as u32,
                            format_size(task.done),
                            format_size(task.size)
                        ));
                    let color = match task.status {
                        FileTaskStatus::Completed => theme.success,
                        FileTaskStatus::Failed(_) => theme.danger,
                        _ => theme.primary,
                    };
                    bar = bar.fill(color);
                    ui.add(bar);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format_speed(task.speed)).size(theme.small_size),
                            )
                            .selectable(false),
                        );
                        if let FileTaskStatus::Failed(msg) = &task.status {
                            status_dot(ui, theme.danger, msg);
                        } else if let FileTaskStatus::Cancelled = &task.status {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(t!("filepanel.cancelled_note"))
                                        .size(theme.small_size),
                                )
                                .selectable(false),
                            );
                        }
                    });
                });
                ui.add_space(theme.spacing);
            }
            for id in remove_ids {
                state.remove(id);
            }
        });

    if let Some(tx) = tx {
        for cmd in commands {
            let _ = tx.send(cmd);
        }
    }
}

/// 拖拽文件 → 路径列表（egui 0.28 `raw.dropped_files`）。
pub fn dropped_file_paths(ctx: &egui::Context) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    ctx.input(|i| {
        for f in &i.raw.dropped_files {
            if let Some(p) = &f.path {
                if p.is_file() {
                    paths.push(p.clone());
                }
            }
        }
    });
    paths
}

/// 在系统文件管理器中显示文件（Windows explorer /select）。
#[cfg(target_os = "windows")]
pub fn show_in_folder(path: &PathBuf) {
    use std::process::Command;
    let _ = Command::new("explorer").arg("/select,").arg(path).spawn();
}

/// 在系统文件管理器中显示文件（macOS open -R）。
#[cfg(target_os = "macos")]
pub fn show_in_folder(path: &PathBuf) {
    use std::process::Command;
    let _ = Command::new("open").arg("-R").arg(path).spawn();
}

/// 在系统文件管理器中显示文件（Linux xdg-open 所在目录）。
#[cfg(all(unix, not(target_os = "macos")))]
pub fn show_in_folder(path: &PathBuf) {
    use std::process::Command;
    if let Some(dir) = path.parent() {
        let _ = Command::new("xdg-open").arg(dir).spawn();
    }
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upsert_add_and_update() {
        let mut st = FilePanelState::new();
        st.upsert(FileTask::queued(
            1,
            "a.bin".into(),
            1000,
            FileDirection::Upload,
        ));
        assert_eq!(st.tasks.len(), 1);
        assert_eq!(st.active_count(), 0);
        // 更新为传输中。
        let mut t = st.find(1).unwrap().clone();
        t.status = FileTaskStatus::Sending;
        t.done = 500;
        st.upsert(t);
        assert_eq!(st.find(1).unwrap().done, 500);
        assert_eq!(st.active_count(), 1);
        // 完成。
        let mut t = st.find(1).unwrap().clone();
        t.status = FileTaskStatus::Completed;
        t.done = 1000;
        st.upsert(t);
        assert_eq!(st.active_count(), 0);
        // 移除。
        st.remove(1);
        assert!(st.tasks.is_empty());
    }

    #[test]
    fn test_speed_computation() {
        let mut st = FilePanelState::new();
        let mut t = FileTask::queued(1, "a.bin".into(), 100_000, FileDirection::Download);
        t.done = 1000;
        st.upsert(t);
        // 立即重复 upsert（同一毫秒内）→ 速度为 0 不误报。
        let mut t2 = st.find(1).unwrap().clone();
        t2.done = 2000;
        st.upsert(t2);
        assert!(st.find(1).unwrap().speed >= 0.0);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(64 * 1024), "64.0 KB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn test_progress_fraction() {
        let t = FileTask::queued(1, "a".into(), 0, FileDirection::Upload);
        assert_eq!(t.progress_fraction(), 1.0);
        let t2 = FileTask::queued(1, "a".into(), 100, FileDirection::Upload);
        assert_eq!(t2.progress_fraction(), 0.0);
    }
}
