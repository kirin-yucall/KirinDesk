//! M8-T038 (P6): 组件默认文案键值表（zh 基线 + en 全量）。
//! 本分区文件由 M8-T038_P6 独占认领。
//!
//! 仅收录组件自带默认文案（调用方传入的 text/tooltip 由各页任务负责）；
//! 文件面板（file_panel.rs）为会话窗口组件，键亦归本表。

pub static TABLE: &[(&str, &str, &str)] = &[
    ("widgets.copy", "复制", "Copy"),
    ("widgets.secret.hide", "隐藏", "Hide"),
    ("widgets.secret.show", "显示", "Show"),

    // ── 文件面板（file_panel.rs）──
    ("filepanel.dir.upload", "↑ 发送", "↑ Send"),
    ("filepanel.dir.download", "↓ 接收", "↓ Receive"),
    ("filepanel.title",
     "📁 文件传输 — 拖拽文件到窗口即可发送（并发 ≤ 3，其余排队）",
     "📁 File transfer — drag files into the window to send (max 3 concurrent, the rest queue)"),
    ("filepanel.active_fmt", "{0} 活跃 / {1} 排队", "{0} active / {1} queued"),
    ("filepanel.empty",
     "暂无传输任务\n拖拽文件到此窗口立即发送",
     "No transfers yet\nDrag files into this window to send immediately"),
    ("filepanel.status.queued", "排队中", "Queued"),
    ("filepanel.status.waiting", "等待接受", "Waiting to accept"),
    ("filepanel.status.sending", "传输中", "Sending"),
    ("filepanel.status.paused", "已暂停", "Paused"),
    ("filepanel.status.completed", "已完成", "Completed"),
    ("filepanel.status.failed", "失败", "Failed"),
    ("filepanel.status.cancelled", "已取消", "Cancelled"),
    ("filepanel.btn.pause", "暂停", "Pause"),
    ("filepanel.btn.cancel", "取消", "Cancel"),
    ("filepanel.btn.resume", "恢复", "Resume"),
    ("filepanel.btn.cancel_queue", "取消排队", "Cancel queue"),
    ("filepanel.btn.show_in_folder", "在文件夹中显示", "Show in folder"),
    ("filepanel.btn.clear", "清除", "Clear"),
    ("filepanel.cancelled_note", "已取消 — 无残留文件", "Cancelled — no leftover files"),
];
