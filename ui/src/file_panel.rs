//! M13-T006 文件传输面板：任务列表 + 进度条 + 控制按钮 + 拖拽发送。
//!
//! 纯状态机（[`FilePanelState`]）可单测；egui 渲染（[`show_file_workspace`]
//! 双 tab 工作区 / [`show_tasks_tab`] 全部任务 tab）由连接窗口/服务器面板
//! 调用。任务进度由会话任务经共享
//! `OnceLock<Mutex<FilePanelState>>` 更新，UI 每帧读取。
//!
//! `workspace_gate` Desktop 分支）随 Desktop 窗旧面板与仪表盘文件传输卡
//! 移除——文件传输入口 = 文件传输模式（Shell 窗双栏）+ ctrl+cv 剪贴板链。

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use egui::{RichText, Ui};

use crate::theme::Theme;
use crate::t;
use crate::tf;
use crate::widgets::{badge, status_dot, BadgeKind};

use kirin_desk_core::connection::file_transfer::{
    FsOp, StoredTransfer, TransferStore, total_blocks_for, BLOCK_SIZE,
};

// ════════════════════════════════════════════════════════════════
// UI → 会话任务命令
// ════════════════════════════════════════════════════════════════

/// UI 线程 → 会话文件任务（unbounded channel，经 `file_tx` 发送）。
///
/// **非 wire 帧**——wire 侧 `FileTransferFrame`/`FileOfferMeta` 字段序列逐位
/// 不变（零协议改动）；既有 4 变体零变化，新变体**尾追加**。
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
    /// `FileSession::cmd_fs_request`：`fs_router.admit`（S8 本地准入）+
    /// `bind` oneshot + 发既有 `FsRequest` 帧（零新帧格式）；响应经
    /// `take_fs_response` 取回（E 岗 UI 消费）。
    Fs { op: FsOp },
    /// 目录前置位（客户端会话状态 `recv_landing_dir`，`maybe_start_recv`
    /// 消费，该 Offer 完成/取消/拒绝后复位；同名冲突走既有 `unique_target_path`
    /// 自动改名）+ 服务端经既有 `FsOp::Fetch` 读出并复用发送管线发起 Offer。
    FetchFile {
        /// 远端 root 相对路径（wire 上以既有 FsRequest 帧承载）。
        remote_path: String,
        /// 本地落盘目录（本地栏当前目录；客户端本地状态，不上 wire）。
        local_dir: PathBuf,
    },
    /// 条目——引擎侧删 store 条目 + 删 `.part`（复用 cancel 清理语义；**零 wire
    /// 帧**、零任务态变更；在途任务〔senders/receivers/pending_offers〕=
    /// fail-closed no-op——UI 侧去重已排除，此为纵深防御）。
    DiscardResume { transfer_id: u64 },
    /// 发送——引擎臂映射既有 `FileSession::cmd_send_with_consent`（与
    /// `FileMgrCommand::SendWithConsent` 同一引擎面，零新机制）：`TransferRequest`
    /// 元数据通告（零内容帧 fail-closed）→ 对端文件传输开关裁决（开 = 自动
    /// 绝对路径（逐文件引擎侧校验/根相对化）；远端落点 = 空（root 相对空 base
    /// = 对端根下，`remote_join` 空 base 口径）——拖拽/仪表盘无「远端栏当前
    /// 目录」语境，K4 语义不适用。**零 wire**：wire 帧全部既有
    /// （`TransferRequest`/回执，P 协议已交付面）。
    ///
    /// （= Desktop 会话窗 OS 拖入臂）时空落点不再钉死「对端根」（≡home，
    /// 用户实测落 `C:\Users\dev` 断点）——对端 Fetch 命中后**不登记 V2** =
    /// 探测臂决落点（探测命中 = 受控关注目录；未命中 = 既有
    /// `download_dir` 回退 + 提示行）。非 Desktop 拖入面（Shell/File 窗）
    /// 与仪表盘 = `false` = 既有语义零变化。ui 内部标记，**零 wire**。
    SendWithConsent {
        paths: Vec<PathBuf>,
        /// 条目路由 v1 Offer（受控端聚焦 Explorer 探测决落点）。
        focus_probe_target: bool,
    },
    /// **远端显式目录**（目标 = 同 peer Shell 窗文件传输模式远端栏选中/当前
    /// 目录，root 相对；客户端本地状态，**零新 wire**——引擎臂映射既有
    /// 服务端 `on_offer_v2` 全链（sanitize + 写根门 + 落点）零变化）。
    /// 无目标语境（同 peer 无在位 FM 上下文）= 调用点不构造本变体，走既有
    /// `SendFile` v1 链（服务端聚焦层/download_dir 回退，零变化）。
    SendFileV2 {
        path: PathBuf,
        /// 远端落点目录（root 相对；`""` = 对端 fs 根）。
        target_dir: String,
    },
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

/// 并发场景取最近建立会话标识，报告备案；客户端/服务端各自独立状态各
/// 自注入）。
#[derive(Debug, Clone, Default)]
pub struct SessionLogCtx {
    /// 对端显示名（`dashboard_target_label` 口径：「昵称 (设备 ID)」/ 裸设备 ID）。
    pub peer_label: String,
    /// 本机默认接收目录（下载失败/落点未知时日志行本机目录回退值）。
    pub download_dir: PathBuf,
}

/// 文件面板状态（全局共享 `OnceLock<Mutex<FilePanelState>>`）。
#[derive(Debug, Default)]
pub struct FilePanelState {
    pub tasks: Vec<FileTask>,
    /// 默认空 = 日志行对端标识回退占位）。
    pub session_ctx: SessionLogCtx,
    /// `(used_bytes, used_files)`——引擎 `FileSession::on_tick` 按 1s tick
    /// 粒度发布；`None` = 尚无会话发布（配额条隐藏）。
    pub quota_used: Option<(u64, u64)>,
    /// 与 `quota_used` 同一 1s tick 发布（`FileSession::on_tick`）。配额条
    /// 呈现本值（path 维度后 P2P 会话有效上限 = 0 = 不限，走
    /// `filepanel.quota.unlimited` 键；此前 UI 自 config 源读上限，P2P
    /// 字节不限时会误显 4 GiB 上限）。文件数上限无 path 维度，仍自 config
    /// 源读取。`None` = 尚无会话发布（回退 config 原值，与旧口径一致）。
    pub quota_max_bytes: Option<u64>,
    /// ≤ [`RESUME_SCAN_INTERVAL`] 一次扫描，防每帧磁盘读）。
    pub(crate) resume_scan_at: Option<Instant>,
    pub(crate) resume_store_cache: Vec<StoredTransfer>,
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
    ///
    /// 时发连接页传输日志行（全部引擎 upsert 调用点共用本入口，零逐点
    /// 接线）；终态 → 终态（重复 upsert）不重复发（同事件由缓冲合并计数
    /// 兜底，此处先行拦截）。
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
        let prev_status = self.find(task.transfer_id).map(|t| t.status.clone());
        if let Some(existing) = self.find_mut(task.transfer_id) {
            *existing = task.clone();
        } else {
            self.tasks.push(task.clone());
        }
        let emit = matches!(
            task.status,
            FileTaskStatus::Completed | FileTaskStatus::Failed(_)
        ) && prev_status
            .as_ref()
            .map_or(true, |s| !crate::file_manager::is_terminal_status(s));
        if emit {
            self.emit_transfer_log(&task);
        }
    }

    pub fn set_session_ctx(&mut self, peer_label: String, download_dir: PathBuf) {
        self.session_ctx = SessionLogCtx {
            peer_label,
            download_dir,
        };
    }

    ///
    /// 数据点：`name`/`direction`/`path`（下载落盘）+ 会话上下文（对端标识/
    /// 默认接收目录）+ 进程级登记（上传源目录 = `send_source_registry`
    /// **对端目录仅根相对形态**（wire 协议隐私设计：对端绝对根不可知）——
    /// 未知 = `connect.log.dir_root` 标记（报告向用户备案口径）。
    fn emit_transfer_log(&self, task: &FileTask) {
        use crate::widgets::build_transfer_line;
        let local_label = t!("connect.log.side_local");
        let root_marker = t!("connect.log.dir_root");
        let peer_label = if self.session_ctx.peer_label.is_empty() {
            t!("connect.log.side_peer").to_string()
        } else {
            self.session_ctx.peer_label.clone()
        };
        // 本机端目录（全路径）：下载 = 落点父目录（失败回退默认接收目录）；
        // 上传 = 源文件父目录（发送源注册表；查无 = "-" 防御占位）。
        //（`\\?\C:\…` → `C:\…`；下载落点经 canonicalize 根解析 = verbatim
        let local_dir_str = match task.direction {
            FileDirection::Download => {
                let p = task
                    .path
                    .as_ref()
                    .and_then(|p| p.parent().map(|q| q.to_path_buf()))
                    .unwrap_or_else(|| self.session_ctx.download_dir.clone());
                crate::r192_display_path(&p)
            }
            FileDirection::Upload => crate::send_source_registry()
                .lock()
                .ok()
                .and_then(|g| g.get(&(task.name.clone(), task.size)).cloned())
                .and_then(|p| p.parent().map(|q| q.to_path_buf()))
                .map(|p| crate::r192_display_path(&p))
                .unwrap_or_else(|| "-".to_string()),
        };
        // 对端目录（根相对；None = 对端根）。
        let peer_dir = match task.direction {
            FileDirection::Upload => crate::peer_send_dir_registry()
                .lock()
                .ok()
                .and_then(|g| g.get(&(task.name.clone(), task.size)).cloned())
                .unwrap_or_else(|| root_marker.to_string()),
            FileDirection::Download => crate::peer_fetch_dir_registry()
                .lock()
                .ok()
                .and_then(|mut g| g.remove(&task.name))
                .unwrap_or_else(|| root_marker.to_string()),
        };
        let (from_local, from_dir, to_dir) = match task.direction {
            FileDirection::Upload => (
                true,
                local_dir_str.clone(),
                peer_dir,
            ),
            FileDirection::Download => (false, peer_dir, local_dir_str.clone()),
        };
        let line = build_transfer_line(
            from_local,
            &local_label,
            &peer_label,
            &from_dir,
            &to_dir,
            &task.name,
            match &task.status {
                FileTaskStatus::Failed(r) => Some(r.as_str()),
                _ => None,
            },
        );
        crate::conn_log_buffer().push(line);
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

    /// 失败/进行中/排队/已取消不受影响（对应速度采样同步清理）。
    /// fail-closed：不提供盲删 `.part` 按钮（设计 R8：防误删）。
    pub fn clear_completed(&mut self) -> usize {
        let ids: Vec<u64> = self
            .tasks
            .iter()
            .filter(|t| matches!(t.status, FileTaskStatus::Completed))
            .map(|t| t.transfer_id)
            .collect();
        for id in &ids {
            self.remove(*id);
        }
        ids.len()
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
// 文件夹成组 / 待续传 / 配额（纯函数层可单测；零引擎改动、零 wire）
// ════════════════════════════════════════════════════════════════

/// 文件工作区 tab（双 tab 容器，设计 v1.4 §2.1/§2.3/§2.6 框图 2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceTab {
    /// tab 1 = 文件管理器（E1 双栏本体；容器接线，本体零改动）。
    Manager,
    /// tab 2 = 全部任务（既有队列视图增强版 = 框图 2）。
    Tasks,
}

// Shell = 双 tab 容器 / Desktop = 旧 📁 队列面板）随 Desktop 旧面板分支
// 移除——`show_file_workspace` 唯一存活挂载 = Shell 窗（双 tab 容器恒可达，
// 门控坍缩为常量，结构体零读点〔`dual_tab_container` 原仅单测断言〕，
// 单测引用矩阵在案）。

/// 有活跃/中断任务（非终态：Queued/WaitingAccept/Sending/Paused）。
pub fn has_live_tasks(panel: &FilePanelState) -> bool {
    panel
        .tasks
        .iter()
        .any(|t| !crate::file_manager::is_terminal_status(&t.status))
}

/// tab 默认态规则单一（设计 §2.3：有活跃/中断任务 → 「全部任务」；
/// 否则 → 「文件管理器」）。
pub fn default_workspace_tab(panel: &FilePanelState) -> WorkspaceTab {
    if has_live_tasks(panel) {
        WorkspaceTab::Tasks
    } else {
        WorkspaceTab::Manager
    }
}

/// 解析本帧 tab：用户手动选择（一次会话内记住，§2.3）优先；否则
/// 回落默认态规则。
pub fn resolve_workspace_tab(
    manual: Option<WorkspaceTab>,
    panel: &FilePanelState,
) -> WorkspaceTab {
    manual.unwrap_or_else(|| default_workspace_tab(panel))
}

/// 队列五组切分（框图 2：进行中/排队/失败/完成；已取消 = 终态但非完成，
/// 独立组仅非空时呈现——UI 语义自裁，见交付报告）。
#[derive(Debug, Default)]
pub struct TaskGroups<'a> {
    /// 进行中（Sending/WaitingAccept/Paused）。
    pub running: Vec<&'a FileTask>,
    /// 排队（Queued；并发 ≤3 = 引擎侧既有保证）。
    pub queued: Vec<&'a FileTask>,
    /// 失败（Failed）。
    pub failed: Vec<&'a FileTask>,
    /// 已取消（Cancelled）。
    pub cancelled: Vec<&'a FileTask>,
    /// 完成（本会话）（Completed）。
    pub completed: Vec<&'a FileTask>,
}

/// 全局任务列表 → 框图 2 五组切分（稳定序 = 面板插入序）。
pub fn partition_tasks(panel: &FilePanelState) -> TaskGroups<'_> {
    let mut g = TaskGroups::default();
    for t in &panel.tasks {
        match &t.status {
            FileTaskStatus::Sending
            | FileTaskStatus::WaitingAccept
            | FileTaskStatus::Paused => g.running.push(t),
            FileTaskStatus::Queued => g.queued.push(t),
            FileTaskStatus::Failed(_) => g.failed.push(t),
            FileTaskStatus::Cancelled => g.cancelled.push(t),
            FileTaskStatus::Completed => g.completed.push(t),
        }
    }
    g
}

// ── 文件夹任务成组展示（§2.6.1② E2 落点；展示层零引擎改动）──

/// 文件夹 job → 传输方向（ToRemote = 本端发送 / ToLocal = 本端接收）。
pub fn job_direction(job: &crate::file_manager::FolderJob) -> FileDirection {
    match job.direction {
        crate::file_manager::FolderDirection::ToRemote => FileDirection::Upload,
        crate::file_manager::FolderDirection::ToLocal => FileDirection::Download,
    }
}

/// 任务是否属于某文件夹 job（**匹配口径与 E1 `batch_all_terminal` 同源**：
/// basename + size + direction；E1 移交①=数据层无欠账——任务条目经既有
/// `FileTask` upsert（key=transfer_id）已可成组，本函数只做展示层归属判定）。
pub fn task_in_folder_job(
    job: &crate::file_manager::FolderJob,
    task: &FileTask,
) -> bool {
    if task.direction != job_direction(job) {
        return false;
    }
    // `task_file_basename`（双分隔符同收）+ size + direction（同源不漂移）。
    job.files.iter().any(|(p, size, _sub)| {
        crate::file_manager::task_file_basename(p) == task.name && *size == task.size
    })
}

/// 文件夹 job 组进度 `(completed 数, 总文件数)`（匹配口径同上）。
pub fn folder_job_progress(
    job: &crate::file_manager::FolderJob,
    panel: &FilePanelState,
) -> (usize, usize) {
    let dir = job_direction(job);
    let total = job.files.len();
    let done = job
        .files
        .iter()
        // `task_file_basename`（双分隔符同收）+ size + direction。
        .filter(|(p, size, _sub)| {
            panel.tasks.iter().any(|t| {
                t.name == crate::file_manager::task_file_basename(p)
                    && t.size == *size
                    && t.direction == dir
                    && matches!(t.status, FileTaskStatus::Completed)
            })
        })
        .count();
    (done, total)
}

/// 组头文件夹名（源末段；分隔符兼容 `/` 与 `\`〔Windows 本地绝对路径〕；
/// 根/空 = 保留原文）。
pub fn folder_group_name(source: &str) -> String {
    let trimmed = source.trim_end_matches(|c| c == '/' || c == '\\');
    if trimmed.is_empty() {
        return source.to_string();
    }
    if let Some(i) = trimmed.rfind(|c| c == '/' || c == '\\') {
        if i + 1 < trimmed.len() {
            return trimmed[i + 1..].to_string();
        }
    }
    source.to_string()
}

// ── 待续传组（设计 §4.2/§4.3；UI 侧 store 扫描 + 进程级发送源注册表）──

/// 断点 store UI 侧扫描间隔（≤ 每间隔一次，防每帧磁盘读）。
pub const RESUME_SCAN_INTERVAL: Duration = Duration::from_secs(2);

/// 待续传候选（UI 展示模型；数据源 = 断点 store 扫描 + 进程级发送源
/// 注册表〔fail-closed：查无 = 不猜不重发，D2 既有口径〕；零 wire、
/// 零引擎改动）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeCandidate {
    pub transfer_id: u64,
    pub name: String,
    pub size: u64,
    /// 断点字节（`next_seq × BLOCK_SIZE`，capped by size）。
    pub done: u64,
    pub direction: FileDirection,
    /// `direction=send` 且源文件在位（注册表命中 + 文件存在）=
    /// `[▶ 续传]` 按钮可用（= `FileCommand::SendFile{path}` 重发，§4.2）。
    pub resumable: bool,
    /// 续传源路径（`None` = 无续传按钮，fail-closed）。
    pub source: Option<PathBuf>,
}

/// 待续传候选收集（设计 §4.2/§4.3，E2 落点；纯函数）：
/// - send 条目中断（`0 < next_seq < 总块数`）：
///   - 源文件在位（注册表命中 + 存在）→ `resumable` 候选（「待续传」组，
///     `[▶ 续传]`/`[✕ 放弃]`）；
///   - 源文件缺失（stale）→ 非 resumable 候选（渲染入「失败」组「源文件
///     不存在」，无续传按钮，§4.3）；
/// - recv 条目中断（`.part` 残留）→「等待对方重发 Offer」（无按钮——协议：
///   接收方不主动，§4.2 框图 2 verbatim）；
/// - 面板中已有 name+size+direction 匹配的非终态任务 = 任务视图已呈现，
///   去重排除（防双列）。
pub fn collect_resume_candidates(
    entries: &[StoredTransfer],
    registry: &HashMap<(String, u64), PathBuf>,
    panel: &FilePanelState,
) -> Vec<ResumeCandidate> {
    let mut out = Vec::new();
    for e in entries {
        let total = total_blocks_for(e.size);
        if !(e.next_seq as u64 > 0 && (e.next_seq as u64) < total) {
            continue; // 未中断（未开始/已完成）。
        }
        let direction = if e.direction == "send" {
            FileDirection::Upload
        } else {
            FileDirection::Download
        };
        let live = panel.tasks.iter().any(|t| {
            t.name == e.name
                && t.size == e.size
                && t.direction == direction
                && !crate::file_manager::is_terminal_status(&t.status)
        });
        if live {
            continue; // 在途（含排队）= 任务视图已呈现。
        }
        let done = (e.next_seq as u64).saturating_mul(BLOCK_SIZE).min(e.size);
        let source = if direction == FileDirection::Upload {
            registry
                .get(&(e.name.clone(), e.size))
                .filter(|p| p.is_file())
                .cloned()
        } else {
            None
        };
        out.push(ResumeCandidate {
            transfer_id: e.transfer_id,
            name: e.name.clone(),
            size: e.size,
            done,
            direction,
            resumable: source.is_some(),
            source,
        });
    }
    out
}

/// 断点残留计数（设计 §4.3：面板底行「断点残留 N 项」仅统计 store 条目
/// = 中断条目；孤儿 `.part`〔store 无条目〕不呈现、不提供盲删，R8）。
pub fn breakpoint_residue_count(entries: &[StoredTransfer]) -> usize {
    entries
        .iter()
        .filter(|e| {
            let total = total_blocks_for(e.size);
            e.next_seq as u64 > 0 && (e.next_seq as u64) < total
        })
        .count()
}

/// 配额条文案（框图 1/2 头行右，`filepanel.quota` 既有键——占位符一一对应：
/// {0}/{1} = 字节已用/上限，{2}/{3} = 文件数已用/上限；`0` = 不限占位）。
pub fn format_quota_bar(
    used_bytes: u64,
    used_files: u64,
    max_bytes: u64,
    max_files: u64,
) -> String {
    let unlimited = crate::i18n::tr("filepanel.quota.unlimited").to_string();
    let b_max = if max_bytes == 0 {
        unlimited.clone()
    } else {
        format_size(max_bytes)
    };
    let f_max = if max_files == 0 {
        unlimited
    } else {
        max_files.to_string()
    };
    tf!(
        "filepanel.quota",
        format_size(used_bytes),
        b_max,
        used_files,
        f_max
    )
}

// （`file_panel_close_visible`）+ 旧队列面板渲染体（`show_file_panel`，
// M13-T006 UI-FT-001/002）随 Desktop 窗旧面板与仪表盘文件传输卡移除——
// 两消费点（`show_file_workspace` Desktop 分支 / 仪表盘卡）全数随移除，
// 零他消费（grep 矩阵在案）；i18n 专属键十枚同批移除（清单入交付报告）。

// ════════════════════════════════════════════════════════════════
// 渲染体已移除）
// ════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

///
/// 双 tab 容器（文件管理器｜全部任务）；tab 1 =
/// `file_manager::show_file_manager`（E1 本体零改动，仅容器接线）。
/// 渲染体）随旧面板移除坍缩为单一 Shell 形态——`is_shell`/`panel_visible`
/// 两死参摘除（原唯一调用点恒 true/None，grep 矩阵在案）。
///
/// `manual_tab`/`out_manual_tab`：用户手动 tab 选择（一次会话内记住，§2.3）；
/// `file_mgr_focus`/`out_focus`：E1 焦点切分协议（全部任务 tab 帧 = 文件管理器
/// 不请求持焦——键盘归终端）。
///
/// 返回 = 本帧解析后的 tab（窗口层消费：非 Manager tab 帧清除 `file_mgr_focus`）。
pub fn show_file_workspace(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FilePanelState,
    tx: Option<&tokio::sync::mpsc::UnboundedSender<FileCommand>>,
    mgr: &mut crate::file_manager::FileManagerState,
    fm_tx: Option<&tokio::sync::mpsc::UnboundedSender<crate::file_manager::FileMgrCommand>>,
    file_mgr_focus: bool,
    out_focus: &mut bool,
    manual_tab: Option<WorkspaceTab>,
    out_manual_tab: &mut Option<WorkspaceTab>,
) -> WorkspaceTab {
    let resolved = resolve_workspace_tab(manual_tab, state);
    // ── tab 行（框图 2 头行：[ 文件管理器 | 全部任务 ]）──
    // 字节/文件数配额不再执法；`format_quota_bar`/i18n 键 `filepanel.quota*`
    // 保留向后兼容 + 既有单测不删，渲染面退役）。
    ui.horizontal(|ui| {
        render_workspace_tab_button(ui, "filemgr.tab.manager", resolved == WorkspaceTab::Manager, out_manual_tab, WorkspaceTab::Manager);
        render_workspace_tab_button(ui, "filemgr.tab.tasks", resolved == WorkspaceTab::Tasks, out_manual_tab, WorkspaceTab::Tasks);
    });
    ui.add_space(theme.spacing);
    match resolved {
        WorkspaceTab::Manager => {
            // tab 1 = E1 双栏本体（零改动；容器接线——tick 由 show_file_manager
            // 内部驱动，每帧一次）。
            crate::file_manager::show_file_manager(
                ui,
                theme,
                mgr,
                tx,
                fm_tx,
                &*state,
                file_mgr_focus,
                out_focus,
            );
        }
        WorkspaceTab::Tasks => {
            // 全部任务 tab 帧：文件管理器不请求持焦（键盘归终端；Tasks
            // tab 无键盘捕获面）。
            *out_focus = false;
            // 文件夹任务推进仍由渲染帧驱动（tick 语义同 E1：每帧恰一次，
            // 零双 tick——Manager tab 帧由 show_file_manager 内部 tick）。
            mgr.tick(&*state, tx, fm_tx);
            show_tasks_tab(ui, theme, state, tx, mgr);
        }
    }
    resolved
}

/// tab 行按钮（选中 = 强字 + faint 底；点击 = 写入手动选择，§2.3 记住）。
fn render_workspace_tab_button(
    ui: &mut Ui,
    key: &'static str,
    active: bool,
    out_manual_tab: &mut Option<WorkspaceTab>,
    tab: WorkspaceTab,
) {
    let text = if active {
        RichText::new(crate::i18n::tr(key)).strong()
    } else {
        RichText::new(crate::i18n::tr(key))
    };
    let fill = if active {
        ui.visuals().faint_bg_color
    } else {
        egui::Color32::TRANSPARENT
    };
    if ui.add(egui::Button::new(text).fill(fill)).clicked() {
        *out_manual_tab = Some(tab);
    }
}

/// 五组（进行中/排队/待续传/失败/完成）+ 文件夹任务成组展示（§2.6.1②：
/// 组头 = 文件夹名 + 组内计数 + 组进度）+ 底行（🧹 清除已完成 + 断点残留
/// N 项）。行视觉与旧队列面板行同构（状态徽标由组头承担，行内省略；
pub fn show_tasks_tab(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FilePanelState,
    tx: Option<&tokio::sync::mpsc::UnboundedSender<FileCommand>>,
    mgr: &crate::file_manager::FileManagerState,
) {
    let connected = tx.is_some();
    // ── 断点 store UI 侧扫描（节流 ≤ [`RESUME_SCAN_INTERVAL`]；读失败 =
    //    保持上次缓存，fail-closed 零崩溃）──
    let now = Instant::now();
    let due = state
        .resume_scan_at
        .map(|t| now.duration_since(t) >= RESUME_SCAN_INTERVAL)
        .unwrap_or(true);
    if due {
        state.resume_scan_at = Some(now);
        match TransferStore::load_from(&crate::transfers_store_path("client")) {
            Ok(store) => state.resume_store_cache = store.transfers,
            Err(e) => tracing::debug!("resume store scan: {e}"),
        }
    }
    let registry = crate::send_source_registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let candidates = collect_resume_candidates(&state.resume_store_cache, &registry, state);
    let residue = breakpoint_residue_count(&state.resume_store_cache);

    let mut commands: Vec<FileCommand> = Vec::new();
    let mut remove_ids: Vec<u64> = Vec::new();
    {
        let groups = partition_tasks(state);
        // 文件夹任务成组上下文（§2.6.1②：至多一个活动 job，E1 既有约束）。
        let job_ctx = mgr.job.as_ref().map(|j| {
            (j, folder_group_name(&j.source), folder_job_progress(j, state))
        });
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // [ 进行中 ]
                render_task_group_section(
                    ui,
                    theme,
                    t!("filepanel.group.running"),
                    &groups.running,
                    job_ctx.as_ref(),
                    connected,
                    &registry,
                    &mut commands,
                    &mut remove_ids,
                );
                // [ 排队 ]（并发 ≤3）
                render_task_group_section(
                    ui,
                    theme,
                    t!("filepanel.group.queued"),
                    &groups.queued,
                    job_ctx.as_ref(),
                    connected,
                    &registry,
                    &mut commands,
                    &mut remove_ids,
                );
                // [ 待续传（断点）]：send resumable（[▶ 续传][✕ 放弃]）+
                // recv（「等待对方重发 Offer」无按钮，框图 2 verbatim）。
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(t!("filepanel.group.pending"))
                                .strong()
                                .size(theme.small_size),
                        )
                        .selectable(false),
                    );
                });
                render_resume_rows(
                    ui,
                    theme,
                    &candidates,
                    true,
                    connected,
                    &mut commands,
                );
                // [ 失败 ]：失败任务 + stale 断点条目（源文件不存在，§4.3）。
                render_task_group_section(
                    ui,
                    theme,
                    t!("filepanel.group.failed"),
                    &groups.failed,
                    None,
                    connected,
                    &registry,
                    &mut commands,
                    &mut remove_ids,
                );
                render_resume_rows(
                    ui,
                    theme,
                    &candidates,
                    false,
                    connected,
                    &mut commands,
                );
                // [ 已取消 ]：框图 2 五组之外，仅非空时呈现（UI 语义自裁）。
                if !groups.cancelled.is_empty() {
                    render_task_group_section(
                        ui,
                        theme,
                        t!("filepanel.group.cancelled"),
                        &groups.cancelled,
                        None,
                        connected,
                        &registry,
                        &mut commands,
                        &mut remove_ids,
                    );
                }
                // [ 完成（本会话）]
                render_task_group_section(
                    ui,
                    theme,
                    t!("filepanel.group.completed"),
                    &groups.completed,
                    None,
                    connected,
                    &registry,
                    &mut commands,
                    &mut remove_ids,
                );
            });
    }
    // ── 底行（框图 2 底行 verbatim：🧹 清除已完成 + 断点残留 N 项）──
    ui.horizontal(|ui| {
        if ui
            .add(
                egui::Button::new(
                    RichText::new(t!("filepanel.btn.clear_completed"))
                        .size(theme.small_size),
                )
                .fill(theme.bg_strong),
            )
            .clicked()
        {
            state.clear_completed();
        }
        ui.add_space(16.0);
        ui.add(
            egui::Label::new(
                RichText::new(tf!("filepanel.residue_fmt", residue))
                    .size(theme.small_size)
                    .color(theme.fg_weak),
            )
            .selectable(false),
        );
    });

    if let Some(tx) = tx {
        for cmd in commands {
            let _ = tx.send(cmd);
        }
    }
    for id in remove_ids {
        state.remove(id);
    }
}

/// 任务组节（组头 + 文件夹任务成组〔若该组含 job 任务〕+ 独立任务行）。
fn render_task_group_section(
    ui: &mut Ui,
    theme: &Theme,
    title: &str,
    tasks: &[&FileTask],
    job_ctx: Option<&(&crate::file_manager::FolderJob, String, (usize, usize))>,
    connected: bool,
    registry: &HashMap<(String, u64), PathBuf>,
    commands: &mut Vec<FileCommand>,
    remove_ids: &mut Vec<u64>,
) {
    ui.horizontal(|ui| {
        ui.add(
            egui::Label::new(RichText::new(title).strong().size(theme.small_size))
                .selectable(false),
        );
    });
    let job = job_ctx.map(|(j, _, _)| *j);
    // 文件夹任务成组（§2.6.1②：组头 = 文件夹名 + 组内计数 + 组进度）。
    if let Some((_, name, (done, total))) = job_ctx {
        let job_tasks: Vec<&&FileTask> = tasks
            .iter()
            .filter(|t| task_in_folder_job(job.unwrap(), **t))
            .collect();
        if !job_tasks.is_empty() {
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(tf!("filepanel.group.folder_fmt", name, done, total))
                            .size(theme.small_size),
                    )
                    .selectable(false),
                );
            });
            for t in job_tasks {
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    render_task_row(
                        ui,
                        theme,
                        t,
                        connected,
                        registry,
                        commands,
                        remove_ids,
                    );
                });
            }
        }
    }
    // 独立任务行（job 成员已在成组区渲染，防双列）。
    for t in tasks {
        if job.map(|j| task_in_folder_job(j, t)).unwrap_or(false) {
            continue;
        }
        render_task_row(ui, theme, t, connected, registry, commands, remove_ids);
    }
    ui.add_space(theme.spacing);
}

/// 任务行（全部任务 tab）：名称 + 方向徽标 + 组内按钮（右）+ 进度条 +
/// 速度/失败原因/取消注。视觉与旧队列面板行同构（「既有面板
/// 增强版」；状态徽标省略——组头已承担状态语义）。
fn render_task_row(
    ui: &mut Ui,
    theme: &Theme,
    task: &&FileTask,
    connected: bool,
    registry: &HashMap<(String, u64), PathBuf>,
    commands: &mut Vec<FileCommand>,
    remove_ids: &mut Vec<u64>,
) {
    let task = *task;
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
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                match &task.status {
                    FileTaskStatus::Sending | FileTaskStatus::WaitingAccept => {
                        if connected
                            && ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(t!("filepanel.btn.pause"))
                                            .size(theme.small_size),
                                    ),
                                )
                                .clicked()
                        {
                            commands.push(FileCommand::Pause {
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
                            let p = path.clone();
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
                                show_in_folder(&p);
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
                    FileTaskStatus::Failed(_) => {
                        // 重试 = 重发源文件（既有 `SendFile` 路径：tid 稳定
                        // 重推导 → 双方 store 取 max 自动断点协商全复用，
                        // 设计 §3.1/§4.2）；注册表查无/文件失效 = 无按钮
                        //（fail-closed：不猜）。
                        let retry_path = if task.direction == FileDirection::Upload {
                            registry
                                .get(&(task.name.clone(), task.size))
                                .filter(|p| p.is_file())
                                .cloned()
                        } else {
                            None
                        };
                        if connected {
                            if let Some(p) = retry_path {
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new(t!("filepanel.btn.retry"))
                                                .size(theme.small_size),
                                        )
                                        .fill(theme.bg_strong),
                                    )
                                    .clicked()
                                {
                                    commands.push(FileCommand::SendFile { path: p });
                                }
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
                    FileTaskStatus::Cancelled => {
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
    ui.add_space(theme.spacing / 2.0);
}

/// 待续传/断点残留行（设计 §4.2/§4.3）：`pending=true` = 「待续传」组
/// （send resumable → [▶ 续传][✕ 放弃]；recv = 「等待对方重发 Offer」
/// 无按钮）；`pending=false` = stale 断点条目（send + 源文件不存在）渲染
/// 入「失败」组（仅 [✕ 放弃]——fail-closed 无续传按钮）。
fn render_resume_rows(
    ui: &mut Ui,
    theme: &Theme,
    candidates: &[ResumeCandidate],
    pending: bool,
    connected: bool,
    commands: &mut Vec<FileCommand>,
) {
    let rows: Vec<&ResumeCandidate> = candidates
        .iter()
        .filter(|c| {
            if c.direction == FileDirection::Download {
                pending // recv = 等待对方重发 Offer（仅「待续传」组）。
            } else {
                pending == c.resumable // send：resumable = 待续传；stale = 失败。
            }
        })
        .collect();
    for c in &rows {
        render_resume_row(ui, theme, *c, connected, commands);
    }
    if !rows.is_empty() {
        ui.add_space(theme.spacing);
    }
}

/// 单条待续传/断点残留行（仅经命令通道：续传 = `SendFile`/放弃 =
/// `DiscardResume`，无 UI 行级删除）。
fn render_resume_row(
    ui: &mut Ui,
    theme: &Theme,
    c: &ResumeCandidate,
    connected: bool,
    commands: &mut Vec<FileCommand>,
) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            let glyph = if c.direction == FileDirection::Upload {
                "↑"
            } else {
                "↓"
            };
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{glyph} {}", c.name))
                        .size(theme.body_size)
                        .strong(),
                )
                .selectable(false),
            );
            ui.add_space(8.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if c.direction == FileDirection::Upload {
                    if c.resumable {
                        if let (true, Some(p)) = (connected, c.source.clone()) {
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(t!("filepanel.btn.resume"))
                                            .size(theme.small_size),
                                    )
                                    .fill(theme.bg_strong),
                                )
                                .clicked()
                            {
                                commands.push(FileCommand::SendFile { path: p });
                            }
                        }
                    }
                    // ✕ 放弃 = 引擎侧删 store 条目 + 删 `.part`（§4.2；
                    // 零 wire 帧；在途任务引擎侧守卫 no-op）。
                    if connected
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new(t!("filepanel.btn.discard"))
                                        .size(theme.small_size),
                                )
                                .fill(theme.bg_strong),
                            )
                            .clicked()
                    {
                        commands.push(FileCommand::DiscardResume {
                            transfer_id: c.transfer_id,
                        });
                    }
                }
                // recv = 无按钮（框图 2 verbatim：「等待对方重发 Offer
                // （无按钮）」）。
            });
        });
        let frac = if c.size == 0 {
            1.0
        } else {
            (c.done as f32 / c.size as f32).clamp(0.0, 1.0)
        };
        let bar = egui::ProgressBar::new(frac)
            .desired_width(ui.available_width() - 200.0)
            .text(format!(
                "{}%  {}/{}",
                (frac * 100.0) as u32,
                format_size(c.done),
                format_size(c.size)
            ));
        ui.add(bar.fill(theme.primary));
        ui.horizontal(|ui| {
            let note = if c.direction == FileDirection::Upload {
                if c.resumable {
                    t!("filepanel.resume.last_session")
                } else {
                    t!("filepanel.resume.source_missing")
                }
            } else {
                t!("filepanel.resume.waiting_offer")
            };
            let color = if c.direction == FileDirection::Upload && !c.resumable {
                theme.danger
            } else {
                theme.fg_weak
            };
            ui.add(
                egui::Label::new(
                    RichText::new(note).size(theme.small_size).color(color),
                )
                .selectable(false),
            );
        });
    });
    ui.add_space(theme.spacing / 2.0);
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

    //    配额条 / 待续传（纯函数族）──

    fn set_status(
        id: u64,
        name: &str,
        size: u64,
        dir: FileDirection,
        status: FileTaskStatus,
    ) -> FileTask {
        let mut t = FileTask::queued(id, name.into(), size, dir);
        t.status = status;
        t
    }

    // 移除（Desktop 旧面板分支退役，门控坍缩）。

    #[test]
    fn test_default_tab_rule_single() {
        // 无任务 → 文件管理器。
        let st = FilePanelState::new();
        assert_eq!(default_workspace_tab(&st), WorkspaceTab::Manager);
        // 活跃任务（Sending）→ 全部任务。
        let mut st_live = FilePanelState::new();
        st_live.upsert(set_status(
            1,
            "a.bin",
            100,
            FileDirection::Upload,
            FileTaskStatus::Sending,
        ));
        assert_eq!(default_workspace_tab(&st_live), WorkspaceTab::Tasks);
        // 排队（中断）→ 全部任务。
        let mut st_q = FilePanelState::new();
        st_q.upsert(FileTask::queued(
            2,
            "b.bin".into(),
            100,
            FileDirection::Upload,
        ));
        assert_eq!(default_workspace_tab(&st_q), WorkspaceTab::Tasks);
        // 仅终态（Completed/Failed）≠ 活跃/中断 → 文件管理器。
        let mut st_term = FilePanelState::new();
        st_term.upsert(set_status(
            3,
            "c.bin",
            100,
            FileDirection::Upload,
            FileTaskStatus::Completed,
        ));
        st_term.upsert(set_status(
            4,
            "d.bin",
            100,
            FileDirection::Upload,
            FileTaskStatus::Failed("x".into()),
        ));
        assert_eq!(default_workspace_tab(&st_term), WorkspaceTab::Manager);
        // 手动选择优先（一次会话内记住，§2.3）。
        assert_eq!(
            resolve_workspace_tab(Some(WorkspaceTab::Manager), &st_live),
            WorkspaceTab::Manager
        );
        assert_eq!(
            resolve_workspace_tab(Some(WorkspaceTab::Tasks), &FilePanelState::new()),
            WorkspaceTab::Tasks
        );
        assert_eq!(
            resolve_workspace_tab(None, &st_term),
            WorkspaceTab::Manager
        );
    }

    #[test]
    fn test_partition_tasks_five_groups() {
        let mut st = FilePanelState::new();
        st.upsert(set_status(1, "r.bin", 10, FileDirection::Upload, FileTaskStatus::Sending));
        st.upsert(set_status(2, "w.bin", 10, FileDirection::Upload, FileTaskStatus::WaitingAccept));
        st.upsert(set_status(3, "p.bin", 10, FileDirection::Upload, FileTaskStatus::Paused));
        st.upsert(set_status(4, "q.bin", 10, FileDirection::Upload, FileTaskStatus::Queued));
        st.upsert(set_status(5, "f.bin", 10, FileDirection::Upload, FileTaskStatus::Failed("x".into())));
        st.upsert(set_status(6, "c.bin", 10, FileDirection::Upload, FileTaskStatus::Completed));
        st.upsert(set_status(7, "x.bin", 10, FileDirection::Upload, FileTaskStatus::Cancelled));
        let g = partition_tasks(&st);
        assert_eq!(
            g.running.iter().map(|t| t.transfer_id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            g.queued.iter().map(|t| t.transfer_id).collect::<Vec<_>>(),
            vec![4]
        );
        assert_eq!(
            g.failed.iter().map(|t| t.transfer_id).collect::<Vec<_>>(),
            vec![5]
        );
        assert_eq!(
            g.completed.iter().map(|t| t.transfer_id).collect::<Vec<_>>(),
            vec![6]
        );
        assert_eq!(
            g.cancelled.iter().map(|t| t.transfer_id).collect::<Vec<_>>(),
            vec![7]
        );
    }

    fn test_job() -> crate::file_manager::FolderJob {
        crate::file_manager::FolderJob {
            direction: crate::file_manager::FolderDirection::ToRemote,
            source: "proj".into(),
            target_remote_dir: "dl".into(),
            target_local_dir: PathBuf::new(),
            files: vec![
                (
                    r"C:\Users\dev\Downloads\proj\a.bin".to_string(),
                    100u64,
                    String::new(),
                ),
                (
                    r"C:\Users\dev\Downloads\proj\sub\b.bin".to_string(),
                    200u64,
                    "sub".to_string(),
                ),
            ],
            depth_capped: Vec::new(),
            next_idx: 0,
            batch_head: 0,
            collecting: false,
            collect_queue: std::collections::VecDeque::new(),
            finished: false,
            started: std::time::Instant::now(),
            consent_pending: false,
            consent_req_id: None,
            target_dirs: Vec::new(),
            visit: std::collections::HashSet::new(),
            failed: Vec::new(),
            cycle_skipped: Vec::new(),
            summary_emitted: false,
            mkdir_queue: std::collections::VecDeque::new(),
        }
    }

    #[test]
    fn test_folder_job_grouping_no_cross() {
        let job = test_job();
        let mut st = FilePanelState::new();
        st.upsert(FileTask::queued(1, "a.bin".into(), 100, FileDirection::Upload));
        st.upsert(FileTask::queued(2, "b.bin".into(), 200, FileDirection::Upload));
        st.upsert(FileTask::queued(3, "a.bin".into(), 100, FileDirection::Download));
        st.upsert(FileTask::queued(4, "b.bin".into(), 300, FileDirection::Upload));
        st.upsert(FileTask::queued(5, "standalone.bin".into(), 50, FileDirection::Upload));
        // 组内（top-level 名 + 子目录 basename 匹配；匹配口径 = E1 batch_all_terminal）。
        assert!(task_in_folder_job(&job, st.find(1).unwrap()));
        assert!(task_in_folder_job(&job, st.find(2).unwrap()));
        // 混合任务列表不串组（方向/大小/名称不符 = 非成员）。
        assert!(!task_in_folder_job(&job, st.find(3).unwrap()));
        assert!(!task_in_folder_job(&job, st.find(4).unwrap()));
        assert!(!task_in_folder_job(&job, st.find(5).unwrap()));
        // 组进度（completed/total）。
        assert_eq!(folder_job_progress(&job, &st), (0, 2));
        let mut t = st.find(1).unwrap().clone();
        t.status = FileTaskStatus::Completed;
        t.done = 100;
        st.upsert(t);
        assert_eq!(folder_job_progress(&job, &st), (1, 2));
    }

    #[test]
    fn test_folder_group_name() {
        assert_eq!(folder_group_name(r"C:\Users\dev\Downloads\proj"), "proj");
        assert_eq!(folder_group_name("/root/sub"), "sub");
        assert_eq!(folder_group_name("/"), "/");
        assert_eq!(folder_group_name(""), "");
        assert_eq!(folder_group_name("plain"), "plain");
    }

    #[test]
    fn test_clear_completed_only_completed_group() {
        let mut st = FilePanelState::new();
        st.upsert(set_status(1, "done1.bin", 10, FileDirection::Upload, FileTaskStatus::Completed));
        st.upsert(set_status(2, "done2.bin", 10, FileDirection::Upload, FileTaskStatus::Completed));
        st.upsert(set_status(3, "fail.bin", 10, FileDirection::Upload, FileTaskStatus::Failed("x".into())));
        st.upsert(set_status(4, "send.bin", 10, FileDirection::Upload, FileTaskStatus::Sending));
        st.upsert(set_status(5, "queue.bin", 10, FileDirection::Upload, FileTaskStatus::Queued));
        st.upsert(set_status(6, "cancel.bin", 10, FileDirection::Upload, FileTaskStatus::Cancelled));
        let n = st.clear_completed();
        assert_eq!(n, 2);
        assert!(st.find(1).is_none());
        assert!(st.find(2).is_none());
        // 失败/进行中/排队/已取消不受影响。
        assert!(st.find(3).is_some());
        assert!(st.find(4).is_some());
        assert!(st.find(5).is_some());
        assert!(st.find(6).is_some());
        assert_eq!(st.tasks.len(), 4);
    }

    #[test]
    fn test_quota_bar_placeholders_one_to_one() {
        // {0}/{1} = 字节已用/上限，{2}/{3} = 文件数已用/上限——占位符一一对应。
        let s = format_quota_bar(1024, 3, 4 * 1024 * 1024, 64);
        assert!(s.contains("1.0 KB"), "字节已用: {s}");
        assert!(s.contains("4.0 MB"), "字节上限: {s}");
        assert!(s.contains("3"), "文件数已用: {s}");
        assert!(s.contains("64"), "文件数上限: {s}");
        assert!(!s.contains('{'), "零未填充占位符: {s}");
        // 0 = 不限占位（语言无关：经同一 tr 通道取当前语言值对账）。
        let unlimited = crate::i18n::tr("filepanel.quota.unlimited").to_string();
        let s = format_quota_bar(10, 1, 0, 0);
        assert!(s.contains(&unlimited), "{s} 应含不限占位 {unlimited}");
        assert!(!s.contains('{'), "{s}");
    }

    #[test]
    fn test_resume_candidates_and_residue() {
        let dir = std::env::temp_dir().join(format!("kirin_e2_resume_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let src = dir.join("big.mp4");
        std::fs::write(&src, vec![0u8; 16]).unwrap();
        let part = dir.join("half.bin.part");
        std::fs::write(&part, vec![0u8; 8]).unwrap();
        let mut reg = HashMap::new();
        reg.insert(("big.mp4".to_string(), 200_000u64), src.clone());

        let size: u64 = 200_000; // = 4 块（64KiB/块）。
        let entries = vec![
            // send 中断 + 源文件在位 = resumable。
            StoredTransfer {
                transfer_id: 1,
                name: "big.mp4".into(),
                size,
                direction: "send".into(),
                next_seq: 1,
                sha256: None,
                part_path: None,
            },
            // send 中断 + 源文件缺失（注册表查无）= stale。
            StoredTransfer {
                transfer_id: 2,
                name: "gone.bin".into(),
                size,
                direction: "send".into(),
                next_seq: 1,
                sha256: None,
                part_path: None,
            },
            // recv 中断（.part 残留）= 等待对方重发 Offer。
            StoredTransfer {
                transfer_id: 3,
                name: "half.bin".into(),
                size,
                direction: "recv".into(),
                next_seq: 1,
                sha256: None,
                part_path: Some(part.to_string_lossy().into()),
            },
            // send 已完成（next_seq = 总块数）= 非中断。
            StoredTransfer {
                transfer_id: 4,
                name: "full.bin".into(),
                size,
                direction: "send".into(),
                next_seq: 4,
                sha256: None,
                part_path: None,
            },
        ];
        let st = FilePanelState::new();
        let cands = collect_resume_candidates(&entries, &reg, &st);
        assert_eq!(cands.len(), 3);
        let c1 = cands.iter().find(|c| c.transfer_id == 1).unwrap();
        assert!(c1.resumable);
        assert_eq!(c1.source.as_ref(), Some(&src));
        assert_eq!(c1.done, BLOCK_SIZE); // 1 块 × 64KiB（< size 200_000）。
        let c2 = cands.iter().find(|c| c.transfer_id == 2).unwrap();
        assert!(!c2.resumable);
        assert!(c2.source.is_none());
        let c3 = cands.iter().find(|c| c.transfer_id == 3).unwrap();
        assert_eq!(c3.direction, FileDirection::Download);
        assert!(!c3.resumable);
        // 断点残留 = 中断条目（3；已完成不计）。
        assert_eq!(breakpoint_residue_count(&entries), 3);
        // 在途去重：面板已有 name+size+direction 匹配的非终态任务 → 排除。
        let mut st2 = FilePanelState::new();
        st2.upsert(FileTask::queued(1, "big.mp4".into(), size, FileDirection::Upload));
        let cands2 = collect_resume_candidates(&entries, &reg, &st2);
        assert_eq!(cands2.iter().filter(|c| c.transfer_id == 1).count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }


    // ────────────────────────────────────────────────────────────────
    // ────────────────────────────────────────────────────────────────

    /// 1 行（本机端全路径 = 发送源注册表 / 对端根相对 = v2 登记）；
    /// 终态 → 终态重复 upsert 不重复发。
    #[test]
    fn r142_1_upsert_terminal_transition_upload_success() {
        // 全局 conn 缓冲/注册表读写 + `t!` → r92ti 锁域串行化 + 中文基线。
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        crate::r142_1_test_reset();
        crate::send_source_registry()
            .lock()
            .unwrap()
            .insert(
                ("a.bin".to_string(), 1000u64),
                PathBuf::from("D:\\src\\a\\a.bin"),
            );
        crate::peer_send_dir_registry()
            .lock()
            .unwrap()
            .insert(("a.bin".to_string(), 1000u64), "docs/b".to_string());

        let mut st = FilePanelState::new();
        st.set_session_ctx("DEV123".to_string(), PathBuf::from("E:\\dl"));

        // 非终态：新任务 + 进度推进 = 零行。
        st.upsert(FileTask::queued(1, "a.bin".into(), 1000, FileDirection::Upload));
        assert!(crate::conn_log_buffer().snapshot().is_empty());
        let mut t = st.find(1).unwrap().clone();
        t.status = FileTaskStatus::Sending;
        t.done = 500;
        st.upsert(t);
        assert!(crate::conn_log_buffer().snapshot().is_empty());

        // 非终态 → Completed：恰好 1 行（上传：本机全路径 / 对端根相对）。
        let mut t = st.find(1).unwrap().clone();
        t.status = FileTaskStatus::Completed;
        t.done = 1000;
        st.upsert(t);
        let snap = crate::conn_log_buffer().snapshot();
        assert_eq!(snap.len(), 1);
        use crate::widgets::{ConnLogLine, ConnLogLevel, ConnLogSeg};
        assert_eq!(
            snap[0],
            ConnLogLine {
                level: ConnLogLevel::Success,
                segments: vec![
                    ConnLogSeg::Text("上传：".to_string()),
                    ConnLogSeg::Text("从（本机）".to_string()),
                    ConnLogSeg::Dir {
                        path: "D:\\src\\a".to_string(),
                    },
                    ConnLogSeg::Text(" 到（DEV123）".to_string()),
                    ConnLogSeg::Dir {
                        path: "docs/b".to_string(),
                    },
                    ConnLogSeg::Text(" 文件或文件夹（a.bin）".to_string()),
                ],
                count: 1,
                copied: false,
            }
        );

        // 终态 → 终态（重复 upsert）：不重复发。
        st.upsert(st.find(1).unwrap().clone());
        assert_eq!(crate::conn_log_buffer().snapshot().len(), 1);
        crate::r142_1_test_reset();
    }

    /// canonicalize 根解析 = `\\?\` 形态，终态传输日志行本机目录段必须
    /// 呈现 plain 形态（零 verbatim 前缀）；普通 plain 路径零漂移。
    #[test]
    fn r192_transfer_log_local_dir_deverbatim() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        crate::r142_1_test_reset();
        let mut st = FilePanelState::new();
        st.set_session_ctx("DEV123".to_string(), PathBuf::from("E:\\dl"));

        // 下载终态：落点路径 = verbatim 形态（引擎 canonicalize 根解析同源）。
        st.upsert(FileTask {
            transfer_id: 1921,
            name: "c.bin".into(),
            size: 7,
            direction: FileDirection::Download,
            done: 7,
            status: FileTaskStatus::Completed,
            speed: 0.0,
            path: Some(PathBuf::from(r"\\?\C:\dl\sub\c.bin")),
        });
        let snap = crate::conn_log_buffer().snapshot();
        assert_eq!(snap.len(), 1, "终态跃迁恰 1 行");
        use crate::widgets::ConnLogSeg;
        let dirs: Vec<&String> = snap[0]
            .segments
            .iter()
            .filter_map(|s| match s {
                ConnLogSeg::Dir { path } => Some(path),
                _ => None,
            })
            .collect();
        assert!(
            dirs.iter().any(|d| d.as_str() == r"C:\dl\sub"),
            "本机目录段 = plain 归一形态: {dirs:?}"
        );
        let seg_strs: Vec<&str> = snap[0]
            .segments
            .iter()
            .map(|s| match s {
                ConnLogSeg::Text(t) => t.as_str(),
                ConnLogSeg::Dir { path } => path.as_str(),
            })
            .collect();
        assert!(
            seg_strs.iter().all(|s| !s.contains(r"\?\")),
            "整行零 verbatim 前缀: {seg_strs:?}"
        );
        crate::r142_1_test_reset();
    }

    /// 本机目录 = 落点父目录）+ 失败原因后缀。
    #[test]
    fn r142_1_upsert_download_failed_fetch_registry() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        crate::r142_1_test_reset();
        crate::peer_fetch_dir_registry()
            .lock()
            .unwrap()
            .insert("b.bin".to_string(), "root/x".to_string());

        let mut st = FilePanelState::new();
        st.set_session_ctx("DEV123".to_string(), PathBuf::from("E:\\dl"));

        // 新任务直接终态（prev None = 跃迁）→ 发 1 行 + Fetch 登记消费。
        st.upsert(FileTask {
            transfer_id: 2,
            name: "b.bin".into(),
            size: 7,
            direction: FileDirection::Download,
            done: 0,
            status: FileTaskStatus::Failed("quota_exceeded".into()),
            speed: 0.0,
            path: Some(PathBuf::from("E:\\dl\\sub\\b.bin")),
        });
        let snap = crate::conn_log_buffer().snapshot();
        assert_eq!(snap.len(), 1);
        use crate::widgets::{ConnLogLine, ConnLogLevel, ConnLogSeg};
        assert_eq!(
            snap[0],
            ConnLogLine {
                level: ConnLogLevel::Error,
                segments: vec![
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
                ],
                count: 1,
                copied: false,
            }
        );
        // 消费即除：登记条目已被取走（防跨周期残留误归属同名文件）。
        assert!(crate::peer_fetch_dir_registry()
            .lock()
            .unwrap()
            .is_empty());
        crate::r142_1_test_reset();
    }

    /// 占位；下载落点缺 = 默认接收目录（会话上下文）。
    #[test]
    fn r142_1_upsert_fallbacks_root_marker_and_peer_placeholder() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        crate::r142_1_test_reset();

        let mut st = FilePanelState::new();
        st.set_session_ctx(String::new(), PathBuf::from("E:\\dl"));
        st.upsert(FileTask {
            transfer_id: 3,
            name: "c.bin".into(),
            size: 8,
            direction: FileDirection::Download,
            done: 0,
            status: FileTaskStatus::Failed("io".into()),
            speed: 0.0,
            path: None,
        });
        let snap = crate::conn_log_buffer().snapshot();
        assert_eq!(snap.len(), 1);
        use crate::widgets::{ConnLogLine, ConnLogLevel, ConnLogSeg};
        assert_eq!(
            snap[0],
            ConnLogLine {
                level: ConnLogLevel::Error,
                segments: vec![
                    ConnLogSeg::Text("下载：".to_string()),
                    ConnLogSeg::Text("从（对端）".to_string()),
                    ConnLogSeg::Dir {
                        path: "根".to_string(),
                    },
                    ConnLogSeg::Text(" 到（本机）".to_string()),
                    ConnLogSeg::Dir {
                        path: "E:\\dl".to_string(),
                    },
                    ConnLogSeg::Text(" 文件或文件夹（c.bin）".to_string()),
                    ConnLogSeg::Text(" —— 失败：io".to_string()),
                ],
                count: 1,
                copied: false,
            }
        );
        crate::r142_1_test_reset();
    }
}
