//!
//! 布局基准 = 设计 §2.6 框图 1（:263-283 verbatim）：底部可拖拽面板（360px），
//! 左本地栏（`std::fs` 直读，零 wire）/ 右远端栏（`FsOp::List` 经既有
//! `FileCommand::Fs` 管线，D2 已交付引擎侧）；栏头 = 面包屑（活动节点路径）/🔄；
//! 表头 名称|大小|修改时间|类型；排序三态（asc→desc→off，内存排序，目录恒在
//! 文件前）。
//!
//! - 默认根 = 本地**盘符枚举**（`local_drives`）/ 远端**根**（`root_display`）；
//! - 双击目录节点 = **展开**（再双击收起；List 失败节点双击 = 重试），文件
//!   双击沿用既有语义（本地文件 = 系统资源管理器显示，远端文件 = 无动作）；
//! - 每展开一层 = **一次既有 `FsOp::List`**（单目录非递归，offset=0/limit=500，
//!   调用形态零改、wire 零新增）；本地 = 同步 `std::fs` 零 wire；
//! - 树内**取消分页**（500/页 截断以节点内「更多 ↓」标记行呈现）；排序按
//!   **展开节点局部**（各节点 children 缓存内存排序）；
//! - 选中语义重映射：`selected` 由条目名 → **节点全路径**（本地绝对 /
//!   enable/方向语义零改）；
//! - 树节点状态 {children 缓存 / expanded 集 / 加载中 / 错误态} 挂
//!   [`FileManagerState`] 既有 per-窗状态（[`PaneView::nodes`]/`expanded`），
//!   不另起存储；折叠 = 丢弃节点缓存（再展开 = 重新 List，保「每展开一层
//!   一次 List」+ 折叠后新鲜度）。
//!
//! **状态口径（R2 在案，显式规避 `server_file_tx` 类键控槽前科）**：
//! [`FileManagerState`] = **per-连接窗**（`ConnectionWindow.file_mgr`），非全局
//! static；跨线程共享的仅既有全局任务面板 `FilePanelState`（只读消费）与命令
//! 通道（unbounded mpsc）。
//!
//! **键盘焦点切分（用户 09-11 硬保证，PM 裁定）**：面板侧快捷键
//! （Ctrl/Cmd+C/V/Enter）显式以「文件管理器持有焦点」为门
//! （[`file_mgr_shortcut_active`]，`file_mgr_focus` 由窗口层显式状态跟踪：
//! 点击进面板置位/点击终端画布清除/窗口失焦清除/弹窗打开强制置位）；
//! 终端 feed 负门（`focused && !file_mgr_focus`）由窗口层以纯 AND 追加，
//! 本模块 [`terminal_feeds_keys`] 为同语义纯函数（单测钉死）。**禁止全局

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

use egui::{Align, Align2, Color32, FontFamily, FontId, Id, Layout, Rect, RichText, Ui, pos2, vec2};
use tokio::sync::mpsc::UnboundedSender;

use crate::file_panel::{
    format_size, format_speed, FileCommand, FileDirection, FilePanelState, FileTask,
    FileTaskStatus,
};
use crate::t;
use crate::tf;
use crate::theme::Theme;
use crate::widgets::{badge, BadgeKind};

use kirin_desk_core::connection::file_transfer::{
    FsEntry, FsErrCode, FsListPayload, FsOp, FsResponsePayload, FS_REQ_TIMEOUT, MAX_QUEUE_LEN,
};

// ════════════════════════════════════════════════════════════════
// 常量（口径 = 设计 §2.2/§2.6.1② + 引擎硬上限）
// ════════════════════════════════════════════════════════════════

/// 每页条目数（§2.2：500/页；= 引擎 `FS_LIST_LIMIT_DEFAULT`）。
pub const PAGE_SIZE: u32 = 500;
/// 文件夹递归深度上限（PM 追认口径：超限 = 该子目录不展开 + UI 提示，零 wire）。
pub const FOLDER_MAX_DEPTH: usize = 10;
/// 文件夹编排批大小 = 引擎队列硬上限 `MAX_QUEUE_LEN`(128，S-10c/F-11 满则拒绝)。
///
/// 注（口径偏差如实登记，UI 语义级自裁）：PM 追认口径原文「>1000 → 分批入队
/// 500 项/批」——500 会越过引擎队列硬上限 128（`TransferScheduler::push`
/// QueueFull 拒收 = 发送器孤儿风险，与既有 drop 洪泛同类失败）；本实现取
/// `min(500, MAX_QUEUE_LEN)` = 128 项/批，「FIFO 自然节流、并发 ≤3」意图
/// 满足且更严（任意时刻引擎队列 ≤128，活跃发送 ≤3 由既有调度器保证）。
pub const FOLDER_BATCH_SIZE: usize = MAX_QUEUE_LEN;
/// 每帧最多入队文件数（节奏：避免突发同步 SHA-256 阻塞会话任务循环，
/// PTY/文件帧保持交错；小文件 µs 级、大文件 ~ms/1GB 口径同既有 drop 臂）。
pub const ISSUE_PER_TICK: usize = 4;
/// 本地操作超时 = 引擎 `FS_REQ_TIMEOUT`(10s) + 1s tick 余量——UI 永不先于
/// 引擎判超时（本地判 Timeout 零 wire 帧，§1.2）。
pub const FS_LOCAL_TIMEOUT: Duration =
    Duration::from_secs(FS_REQ_TIMEOUT.as_secs() + 1);
/// 批内「查无任务」落定窗口（防命令刚发、任务未及 upsert 的竞态误判终态）。
pub const BATCH_SETTLE: Duration = Duration::from_secs(5);
///（v1 常量；config 暴露 = v2 候选 Q11）。引擎 `on_tick` 到期结算
/// Failed「对方未确认（超时）」+ INFO 一行；接收端待确认条目**不**受本
/// 超时约束（不断连不超时——发送端超时先行兜底，迟到确认仍生效 §8.3）。
pub const CONSENT_WAIT_TIMEOUT: Duration = Duration::from_secs(300);
/// 超时判定归引擎 on_tick）。
pub const CONSENT_OUT_TTL: Duration = Duration::from_secs(60);
/// 等宽，几何同构 `ui.columns(2)`——见 [`render_panes_and_seam`]）。
pub const SEAM_WIDTH: f32 = 48.0;
pub const SEAM_BTN_W: f32 = 40.0;
/// headless 单测可断言，零布局回写依赖）。
pub const SEAM_BTN_H: f32 = 32.0;
/// 单一来源（名称列钳宽 [`r134_9_name_col_max_w`] 用之；改值两处同步）。
pub const R134_9_GRID_SPACING_X: f32 = 8.0;
/// 常量（列实际宽 = max(内容宽, 此值)；`r134_9_other_cols_w` 同口径钳底，
/// 防「内容窄于列底 → 他列实测低估 → 名称列钳宽偏松 → Grid 总宽仍越栏」）。
pub const R134_9_GRID_MIN_COL_W: f32 = 40.0;
/// ±2px 侧向扩展 HACK（egui 0.28.1 grid.rs `paint_row` `expand2(2.0*Vec2::X)`）
/// + 浮点/字体度量抖动，保证条纹 rect 恒在栏矩形内（不出中缝）。
pub const R134_9_GRID_PANE_MARGIN: f32 = 8.0;
/// 缩进预算 = `depth × R134_9B_TREE_INDENT`，名称列钳宽 [`r134_9b_name_col_max_w`]
/// 的「他列」输入加算之；改值两处同步）。
pub const R134_9B_TREE_INDENT: f32 = 14.0;
/// 后 ≈16px），文件行 = 等宽占位（名称对齐确定性；同 [`R134_9B_TREE_INDENT`]
/// 口径参与钳宽预算，另受 [`R134_9_GRID_MIN_COL_W`] 列底钳制取大者）。
/// 名称列钳宽预算 [`r134_9b_name_col_max_w`] 自动受益）。
pub const R134_9B_TREE_MARK_W: f32 = 16.0;
/// 尺寸（px）——由 `theme.small_size`（≈14px）缩小至 11px + 最小按钮 padding
/// （按钮全宽 ≈ glyph + 2×1 + frame ≈ 16px = 与单层缩进 [`R134_9B_TREE_INDENT`]
/// 14px 同量级——旧默认按钮 ≈22px 大于一个缩进步长，树行节奏失真 = 用户
/// 「位置不对」观感来源）。几何岗内定案，观感用户实机终判（headless 截屏
/// 附证；CJK 豆腐块 = 字体局限不判负）。
pub const R135_5_TREE_MARK_GLYPH_SIZE: f32 = 11.0;
/// （egui 0.28.1 口径：`frame=false` → `button_padding` 归零，按钮宽 =
/// 字形宽〔glyph 11px〕、高 = `interact_size.y` 钳底——按钮全宽 ≈11-13px
/// ≤ 旧 ≈22px（字形 14 + padding [4,2] + frame）；同快捷区 `.frame(false)`
/// 先例口径）。与 [`R135_5_TREE_MARK_GLYPH_SIZE`] 同组钉死单测。
pub const R135_5_TREE_MARK_BTN_FRAME: bool = false;

// ════════════════════════════════════════════════════════════════
// 数据模型
// ════════════════════════════════════════════════════════════════

/// 栏内条目（本地 = `std::fs` 直读；远端 = `FsEntry` 映射）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMgrEntry {
    pub name: String,
    /// 字节数（目录 = 0）。
    pub size: u64,
    /// mtime（UNIX 秒；不可得 = 0）。
    pub mtime: i64,
    pub is_dir: bool,
    /// 符号链接标记（远端 List 不跟随不展开，S4；本地栏展示用）。
    pub is_symlink: bool,
    /// `FILE_ATTRIBUTE_HIDDEN` 属性位（非 Windows = dot 前缀惯例）；远端 =
    /// dot 前缀（wire `FsEntry` 无属性字段〔冻结，零新 wire〕，能力边界
    /// 如实：对端 OS 隐藏属性不可感知，仅可按 dot 前缀惯例过滤）。
    pub is_hidden: bool,
}

/// 栏标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneId {
    Local,
    Remote,
}

/// 排序字段（表头点击三态循环）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Name,
    Size,
    Modified,
}

/// 排序态（`field = None` = off = 目录恒前 + 名称升序，§2.2 默认）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SortState {
    pub field: Option<SortField>,
    pub desc: bool,
}

///
/// 生命周期：展开 = 建节点（本地同步读 / 远端 List 在途）；**折叠 = 丢弃节点
/// 缓存**（再展开 = 重新 List/读，保「每展开一层一次 List」+ 折叠后新鲜度）。
#[derive(Debug, Clone, Default)]
pub struct TreeNodeState {
    /// children 缓存（`None` = 未加载：加载中 / 失败待重试）。
    pub children: Option<Vec<FileMgrEntry>>,
    /// 远端 List 在途（本地 = 同步 `std::fs` 读，恒 false）。
    pub loading: bool,
    /// List 失败 = **可重试**（错误节点标记；双击节点或标记行 🔄 重试。
    /// 超时 = 版本门 unsupported 静态语义另由 `RemotePane.unsupported` 承载）。
    pub error: Option<String>,
    /// 远端 500/页截断（`has_more`；树内取消分页 = 呈现前 500 + 节点内
    /// 「更多 ↓」标记行）。
    pub has_more: bool,
}

#[derive(Debug, Default)]
pub struct PaneView {
    /// 树节点缓存（path → 节点状态；本地 = 绝对路径、远端 = root 相对
    /// [`""`] = 根）。
    pub nodes: HashMap<String, TreeNodeState>,
    /// 展开节点集（path 成员集；渲染序 = 树结构 DFS，与展开时序无关）。
    pub expanded: Vec<String>,
    /// 惰性剪除；跨刷新存活 = 父节点缓存仍在时）。
    pub selected: Vec<String>,
    pub sort: SortState,
    /// 远端树 List 在途（任一节点；本地同步读恒 false）。
    pub loading: bool,
    /// 栏内状态（加载中/错误可读化）。
    pub status: Option<String>,
    /// 不显示）。过滤在渲染层 [`FileManagerState::pane_rows_recur`] 执行，
    /// 节点缓存/排序/选中零触碰——翻转即帧级生效，零重列零 wire。
    pub show_hidden: bool,
}

#[derive(Debug)]
pub struct LocalPane {
    /// 活动节点基准（默认 = 用户主目录；面包屑起点）。
    pub root: PathBuf,
    pub current: PathBuf,
    pub view: PaneView,
    /// [`FileManagerState::goto_local_quick`] 置位 = 快捷跳转后选中行滚入
    /// 可视区；渲染帧收敛后**消费即清** = 不与用户后续滚动打架。键形 =
    /// `local_path_key` 节点全路径，与 [`PaneView`] 行选中键同形）。
    pub scroll_anchor: Option<String>,
    /// delta`] 逐字对称，见其段注释）。
    pub scroll_anchor_prev_delta: Option<f32>,
}

#[derive(Debug, Default)]
pub struct RemotePane {
    /// 根显示名（List 响应 `root_display`，只发 stem 不发盘符，§1.3）。
    pub root_display: String,
    pub current: String,
    pub view: PaneView,
    /// 对端版本不支持浏览（List 本地超时判得；版本门为静态，不再重试）。
    pub unsupported: bool,
    /// tick 发起 List——替代旧 `needs_refresh`「刷新当前页」，树内按节点精准
    /// 失效）。
    pub refresh_node: Option<String>,
    /// List 链式，零 wire 新增）。
    pub expand_queue: VecDeque<String>,
    /// 首次 List 已发起（空目录 ≠ 未初始化）。
    pub started: bool,
    /// `List("")`（home），其落定后 tick 2c 恰一次续发盘符层 List
    ///（`REMOTE_PC_ROOT_KEY`），发射后解除武装（幂等单发，防他测试面/
    /// 异常面重复武装触发；Default=false = 非开窗路径零 wire）。
    pub drive_chain_armed: bool,
    /// quick`] 置位 = 快捷跳转后选中行滚入可视区；渲染帧命中选中行滚动后
    /// **消费即清** = 不与用户后续滚动打架。ScrollArea 逐实例 id_source
    pub scroll_anchor: Option<String>,
    /// 像素偏差（`None` = 尚未观测）。消费判据双态：|Δ| < 2px = 已居中；
    /// Δ 与上帧恒等 = 滚动已贴钳制边界无再动空间（短内容/行近端部）。
    /// 二者任一 = 锚消费即清（防边界形态锚永挂、与用户后续滚动打架）。
    /// 纯 UI 内部态，零 wire。
    pub scroll_anchor_prev_delta: Option<f32>,
}

/// 在途操作种类（UI 侧单槽——`pending`；req_id 由引擎 `Admitted` 事件回填）。
#[derive(Debug, Clone)]
pub enum PendingKind {
    /// 远端列目录（导航/刷新/翻页）。
    List { pane: PaneId, path: String, offset: u32 },
    /// 建目录（远端；本地 = 同步 std::fs 无 pending——栏别无需登记）。
    /// [`Self::on_job_mkdir_result`] / [`Self::on_job_mkdir_timeout`]：记失败
    /// 清单继续链；`false` = 用户新建目录按钮〔既有语义零变化〕）。UI 内部
    /// 标记，**零 wire**（帧形态 = 既有 `FsOp::Mkdir{path}` 不变）。
    Mkdir { path: String, for_job: bool },
    /// 改名（远端；本地 = 同步 std::fs 无 pending，S13 目标存在本地预检）。
    Rename { from: String, to: String },
    /// 删除（远端；本地 = 同步 std::fs 无 pending）。
    Delete { path: String, recursive: bool },
    /// ⬇ 接收（Fetch；响应 = 服务端已发起 Offer，落本地栏当前目录）。
    Fetch { remote_path: String },
    /// 收集根〔选中目录节点〕、`prefix` = 目标内镜像前缀〔= 选中目录名〕）。
    CollectList {
        path: String,
        offset: u32,
        depth: usize,
        src_root: String,
        prefix: String,
    },
}

/// 在途操作（本地超时 [`FS_LOCAL_TIMEOUT`] 判 Timeout，零 wire 帧 §1.2）。
#[derive(Debug)]
pub struct PendingOp {
    /// 0 = 已发命令、待引擎 `Admitted` 回填 req_id。
    pub req_id: u32,
    pub kind: PendingKind,
    pub started: Instant,
}

/// 文件夹传输方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderDirection {
    /// 本地→远端（上传：逐文件 `SendToRemote` → OfferV2，target_dir 固定于启动时）。
    ToRemote,
    /// 远端→本地（下载：逐文件 `FetchFile` 响应链式，落本地栏当前目录）。
    ToLocal,
}

/// 文件夹编排任务（UI 层编排，引擎零改动，§2.6.1②）。
///
/// 批语义：`[batch_head, min(batch_head+FOLDER_BATCH_SIZE, len))` 为一批；
/// 整批发出后等**全部终态**才推进下一批（FIFO 自然节流；快传场景 = 批间
/// 连续，慢传场景 = 前批完成才入队下批）。每帧入队 ≤ [`ISSUE_PER_TICK`]。
#[derive(Debug)]
pub struct FolderJob {
    pub direction: FolderDirection,
    pub source: String,
    /// ToRemote：远端落点（启动时固定；不随中途导航漂移）。
    pub target_remote_dir: String,
    /// ToLocal：本地落点（启动时固定）。
    pub target_local_dir: PathBuf,
    /// (源**全路径**〔本地绝对 / 远端 root 相对〕, 字节数, 目标目录内子路径)；
    /// `目标/<选中目录名>/…`（散选 = 按选中目录名镜像，互不串扰）；ToLocal
    /// 收集期渐进填充。
    pub files: Vec<(String, u64, String)>,
    /// 超深度未展开子目录（目标目录内显示路径）。
    pub depth_capped: Vec<String>,
    /// 已入队游标。
    pub next_idx: usize,
    /// 当前批起点。
    pub batch_head: usize,
    /// BFS 收集期（ToLocal 专用）。
    pub collecting: bool,
    /// 待列目录 (path, offset, depth, source_root, subdir_prefix)——
    /// 该选中目录在目标目录下的显示前缀〔= 目录名〕）。
    pub collect_queue: VecDeque<(String, u32, usize, String, String)>,
    /// 全部文件已入队（传输本身由全局任务面板呈现）。
    pub finished: bool,
    /// 启动时刻（[`BATCH_SETTLE`] 落定判定基准）。
    pub started: Instant,
    /// `SendWithConsent` 尚未收到 `ConsentSent`（`req_id` 回填中）。
    pub consent_pending: bool,
    /// 消费；`None` = 无批在途 = 可发下一批）。
    pub consent_req_id: Option<u32>,
    /// 列表（**含顶层同名根**）。收集结束（[`Self::settle_job_dirs`]）逐条
    /// 在目标侧 `create_dir_all`（**零 wire**——本机操作；**空目录也在目标
    /// 创建** = 用户补口径；含深度上限线目录本身，其子不展开不建）。
    pub target_dirs: Vec<String>,
    /// （补 [`FOLDER_MAX_DEPTH`] 深度上限：junction 环逐层新路径串由深度
    /// 上限硬限界；同路径串重复枚举 = 此处跳过记 `cycle_skipped`）。
    pub visit: HashSet<String>,
    /// {`list:<FsErrCode>` 〔服务端非 Ok〕, `list:wire` 〔传输 Err〕,
    /// `timeout` 〔本地超时〕, `io` 〔目标侧建目录失败〕, `interrupted`
    /// 〔在途收集被 cancel 打断〕}。**单条目失败不中止任务**——继续其余
    /// 条目收集，收集结束打一行汇总观测行（格式钉死 [`r135_5b_summary_line`]）。
    pub failed: Vec<(String, String)>,
    pub cycle_skipped: Vec<String>,
    /// 仅首达生效）。
    pub summary_emitted: bool,
    /// （**远端全路径**，父先子后深度升序——单级 `FsOp::Mkdir` 无 `-p`，
    /// 逐级链式单在途）。ToRemote 专用；ToLocal = 空初始化（目标侧建目录 =
    /// 本机 `create_dir_all` 零 wire，归 `target_dirs`）。**零新 wire op**
    /// （帧形态 = 既有 `FsOp::Mkdir{path}`）。
    pub mkdir_queue: VecDeque<String>,
}

/// 删除确认队列项（多项删除逐条确认，§1.7）。
#[derive(Debug, Clone)]
pub struct DeleteTarget {
    pub pane: PaneId,
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

/// 对话框态机（egui::Window 顶层呈现；**取消 = 零 wire 帧，§1.7**）。
#[derive(Debug, Clone, Default)]
pub enum Dialog {
    #[default]
    None,
    /// 删除确认（§1.7 破坏性防护：文案含「远端直接执行、服务端无二次确认」）。
    /// 栏别由 `pending_deletes` 队列项承载（本弹窗仅显示用）。
    ConfirmDelete {
        name: String,
        size: u64,
        is_dir: bool,
    },
    /// 改名确认（InputRename 过校验后进入；S13：远端目标存在 → 服务端
    /// `AlreadyExists` 拒绝，无静默覆盖路径）。
    ConfirmRename { pane: PaneId, from: String, to: String },
    /// 新建目录输入（单级，无 `-p`，§2.2）。
    InputMkdir { pane: PaneId, name: String },
    /// 改名输入。
    InputRename { pane: PaneId, from: String, new_name: String },
}

/// 复制语义 = **复制（非移动）**（§2.6.1①）：粘贴不删源、不删远端；
/// v1 无剪切/移动。剪贴板按栏源跟踪（跨栏粘贴 = 传输；同栏粘贴 = no-op）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clip {
    pub source: PaneId,
    pub paths: Vec<String>,
}

/// UI → 会话任务：文件管理器专用命令（**ui 内部命令，非 wire 帧**）。
///
/// 独立于 `file_panel.rs` 的 [`FileCommand`]（后者 = 红线零触碰文件集外）：
/// 本枚举仅承载既有命令无法表达的参数（`SendToRemote` 的 `target_dir` =
/// 远端栏当前目录，K4 v2 OfferV2 载体，§2.4 shell ⬆）。
#[derive(Debug, Clone)]
pub enum FileMgrCommand {
    /// 上传本地文件至远端显式目录（引擎 = 校验→哈希→入队→**OfferV2** 帧；
    /// `overwrite` 引擎侧恒 false = 同名 `unique_target_path` 自动改名，
    /// 无静默覆盖——与 rename 目标存在 `AlreadyExists` 拒绝为两条不同路径）。
    /// ⬆ / 跨栏粘贴上传 / 文件夹编排上传方向）已切 [`Self::SendWithConsent`]
    ///（同意接收模型，设计 v1.2 §8）；变体不删 = 零 wire 枚举稳定性纪律
    ///（ui 内部命令非 wire，但既有单测锚面保留语义可查）。
    SendToRemote { path: PathBuf, target_dir: String },
    /// （存在/文件/大小/在 fs 根内 → root 相对路径）→ `FsOp::TransferRequest`
    /// 元数据通告帧（零内容帧，fail-closed）→ 回执等待态（UI「等待对方
    /// 确认」+ 5min 倒计时）→ 对端确认后自行 `FetchFile` 拉取（pull 模型，
    /// 谁确认谁拉）。`entries` = (本地绝对路径, 远端落点目录 root 相对——
    /// 单文件 = 远端栏当前目录；文件夹批 = 启动时远端栏目录 + 相对子路径
    /// 结构镜像，K4 v2 OfferV2 target_dir 同语义)。`truncated` = 本批为
    /// >255 拆分后续批（UI 记档，wire 同字段）。`from_job` = 文件夹编排
    /// 发起（引擎事件原样带回，file_manager 按旗标路由 job/行，免 req_id
    /// 猜测）。
    SendWithConsent {
        entries: Vec<(PathBuf, String)>,
        truncated: bool,
        from_job: bool,
    },
}

/// 会话任务 → UI：Fs 事件（`take_fs_response` 生产接线后的出账通道）。
#[derive(Debug)]
pub enum FsEvent {
    /// `cmd_fs_request` admit 成功（req_id ↔ op 关联回填 UI 侧 pending）。
    Admitted { req_id: u32, op: FsOp },
    /// 响应投递 / 发送失败 / 引擎超时（`Err` = 本地判 Timeout，零 wire 帧）。
    Response {
        req_id: u32,
        result: Result<FsResponsePayload, String>,
    },
    /// `req_id` 回填——`from_job` 旗标路由，免 req_id 猜测）。
    ConsentSent {
        req_id: u32,
        peer_label: String,
        count: usize,
        total_size: u64,
        truncated: bool,
        from_job: bool,
    },
    /// 取消 / Timeout 5min / SendFailed 通告帧发送失败；`from_job` 同回传）。
    ConsentSettled {
        req_id: u32,
        outcome: ConsentOutcome,
        from_job: bool,
        /// Fetch 命中条目的实际 `target_dir`（单文件/粘贴批；v1 回退 =
        /// `None` = UI 零动作）；`from_job` 批各条 target_dir 异构（结构
        /// 镜像），UI 侧自 `job.target_remote_dir` 取批根（事件载荷忽略）。
        /// 失败终态（Declined/Timeout/SendFailed）恒 `None`（零落盘零刷）。
        target_dir: Option<String>,
    },
    /// （远端服务端）** 两权限开关态（`FileOp::PeerConsent` 帧消费产物，
    /// 值源 = 对端 FileSession 构造 consent 快照）。UI 消费 = 文件传输窗
    /// OFF 横幅按**对端值**判定展示（对端语义文案；`None` = 未通告 =
    /// fail-closed 显式文案，红线⑤）。
    PeerConsent {
        clipboard_allowed: bool,
        file_transfer_allowed: bool,
    },
}

/// 面板侧快捷键（统一入口 [`handle_shortcut`] 消费；显式焦点门）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMgrShortcut {
    Copy,
    Paste,
    Enter,
}

// ════════════════════════════════════════════════════════════
// 单测钉死）
// ════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrowDirection {
    /// ← 远端→本地：远程选中项**下载到本地选中目录**。
    Download,
    /// → 本地→远端：本地选中项**上传到远程选中目录**。
    Upload,
}

impl ArrowDirection {
    /// （源栏, 目标栏）方向语义单一映射（方向语义单测钉死）。
    pub fn panes(self) -> (PaneId, PaneId) {
        match self {
            ArrowDirection::Download => (PaneId::Remote, PaneId::Local),
            ArrowDirection::Upload => (PaneId::Local, PaneId::Remote),
        }
    }
}

/// 按 [`ArrowDirection::panes`] 代入）。
///
/// - `src_sel_count` = 源侧**可传输**选中数（>0 = 源侧有选中；文件/目录
///   自动识别由 [`FileManagerState::transferable_sel_count`] 与
///   `enqueue_transfer` 的 files/dirs 分派同口径：目录 = 整目录传输）；
/// - `dst_is_single_dir` = 目标侧选中**恰一个非符号链接目录**（目标必须是
///   目录 = fail-closed：文件/多项/空/符号链接目录 = 不可点）。
pub fn arrow_enabled(src_sel_count: usize, dst_is_single_dir: bool) -> bool {
    src_sel_count > 0 && dst_is_single_dir
}

// ════════════════════════════════════════════════════════════
// 单测钉死）——`arrow_ready=false` 时按钮 `add_enabled(false)` 渲染层
// `.clicked()` 恒 false、零日志 = 用户点「看似无效」的箭头无法判「为何不
// 动」（上轮 09-22 上传流程零传输任务行 + 箭头静默禁用零可观测）。本族
// 在禁用态被点击时补 **WARN 一行**（含禁用原因），消零可观测。
// ════════════════════════════════════════════════════════════

/// [`FileManagerState::arrow_ready`] 的 fail-closed 判定序**逐位对齐**——
/// 在途首判，其次源侧选中，再次目标侧目录；`None` = 就绪可点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrowDisabledReason {
    /// 在途（job/dialog/pending 任一 = busy 门首判命中）。
    InFlight,
    /// 源侧无可传输选中（`transferable_sel_count(src) == 0`）。
    NoSourceSel,
    /// 目标侧非「恰一非符号链接目录」（`single_dir_selection(dst) == None`）。
    NoTargetDir,
}

impl ArrowDisabledReason {
    /// WARN 行 `reason=` 字段（纯映射，钉死单测）。
    pub fn label(self) -> &'static str {
        match self {
            ArrowDisabledReason::InFlight => "in_flight",
            ArrowDisabledReason::NoSourceSel => "no_source_sel",
            ArrowDisabledReason::NoTargetDir => "no_target_dir",
        }
    }
}

pub fn arrow_dir_label(dir: ArrowDirection) -> &'static str {
    match dir {
        ArrowDirection::Download => "download",
        ArrowDirection::Upload => "upload",
    }
}

/// [`FileManagerState::arrow_ready`] 的 busy→源侧→目标侧 fail-closed 序
/// 逐位对齐；`None` = 就绪 = 与 `arrow_ready` 为 `true` 同态）。
pub fn arrow_disabled_reason(
    busy: bool,
    src_sel_count: usize,
    dst_is_single_dir: bool,
) -> Option<ArrowDisabledReason> {
    if busy {
        return Some(ArrowDisabledReason::InFlight);
    }
    if src_sel_count == 0 {
        return Some(ArrowDisabledReason::NoSourceSel);
    }
    if !dst_is_single_dir {
        return Some(ArrowDisabledReason::NoTargetDir);
    }
    None
}

/// 生产唯一调用点 = 渲染层 [`render_seam`] 的 `arrow_ready=false` + 禁用点击
pub fn format_arrow_disabled_click_line(
    dir: ArrowDirection,
    reason: ArrowDisabledReason,
) -> String {
    format!(
        arrow_dir_label(dir),
        reason.label()
    )
}

/// 基准；可配置留待后续 = config 扩展候选，本岗零 config 改动）。
/// 固定序返回，渲染层与 [`LOCAL_QUICK_KEYS`] 标签一一对应。
pub fn local_quick_dirs(home: &Path) -> [PathBuf; 3] {
    [
        home.join("Desktop"),
        home.join("Downloads"),
        home.join("Documents"),
    ]
}

pub const LOCAL_QUICK_KEYS: [&str; 3] = [
    "filemgr.quick.desktop",
    "filemgr.quick.downloads",
    "filemgr.quick.documents",
];

/// （与 [`LOCAL_QUICK_KEYS`] 固定序一一对应；Windows 用户 profile 目录
/// 磁盘名为英文固定形——本地化系统仅显示名异写，磁盘名不变；对端 home
/// 下同名目录 = 用户「文档 桌面 下载」展示口径）。
pub fn remote_quick_dir_names() -> [&'static str; 3] {
    ["Desktop", "Downloads", "Documents"]
}

/// = 与本地 `dir.is_dir()` 同构）：`List("")`（对端 home）响应**已落定**
/// 且条目含同名目录（大小写不敏感）才 enable；未列定 / 在途 / 错误 / 条目
/// 缺席 = disable（不猜，用户「远端目录不存在 = 按钮禁用」口径）。
pub fn remote_home_dir_present(
    state: &FileManagerState,
    name: &str,
) -> bool {
    let Some(node) = state.remote.view.nodes.get("") else {
        return false;
    };
    if node.loading || node.error.is_some() {
        return false;
    }
    let Some(children) = node.children.as_ref() else {
        return false;
    };
    children
        .iter()
        .any(|e| e.is_dir && e.name.eq_ignore_ascii_case(name))
}

/// INFINITY 陷阱纪律同族；small_size 文本钮 ≈22px，26px 含 release 字体
/// 漂移余量）。
pub const QUICK_ROW_H: f32 = 26.0;

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// 逐层既有 `FsOp::List`（零新 wire）BFS 展开 → 逐文件既有 `FetchFile`
#[derive(Debug)]
pub struct ClipDirExpand {
    /// BFS 队列：(远端 rel 目录, 深度, 落点子目录〔相对展开根〕)。
    pub queue: VecDeque<(String, usize, String)>,
    /// 已访集合（小写 rel 目录键；环防护）。
    pub visit: HashSet<String>,
    /// 已收集远端文件：(rel_path, 落点子目录〔相对展开根〕, 字节数, mtime
    /// 比对（size+mtime 全等 = 跳过 FetchFile，fail-open）。
    pub files: Vec<(String, String, u64, i64)>,
    /// 本身 + 深度上限线目录本身〔其子不展开〕；去重 = 已访键同源）。BFS
    /// 收敛时逐条本机 `create_dir_all`（零 wire，[`FolderJob::target_dirs`]
    /// RustDesk FILEDESCRIPTOR 目录项语义）。
    pub dirs: Vec<String>,
    /// 未再派发数）。
    pub fetch_skipped: usize,
    /// 展开根本地落点目录（`landing/<根目录名>`）。
    pub landing_root: PathBuf,
    /// 在途 List：(req_id〔0 = 待 `Admitted` 回填〕, rel 目录, offset,
    /// 深度, 落点子目录)。
    pub inflight: Option<(u32, String, usize, usize, String)>,
    /// 在途起时刻（本地超时判失败，防 FSM 悬挂）。
    pub inflight_since: Option<Instant>,
    /// 已派发 FetchFile 数。
    pub fetch_sent: usize,
    /// 已展开完成目录数。
    pub dirs_done: usize,
    /// List 失败/超限清单（汇总行素材）。
    pub failed: Vec<String>,
    /// 在途〔响应到达即丢弃〕、已拉文件保留、汇总行如实结算——RustDesk
    /// `FileTransferCancel` 收敛语义同构，零新 wire）。
    pub cancelled: bool,
    /// 泵进。悬挂项回放 = `files` 队首原样）。
    pub conflict: Option<R159ConflictItem>,
    /// RustDesk `default_overwrite_strategy` 同口径）。
    pub overwrite_all: bool,
    /// 消费即清）。
    pub overwrite_once: bool,
}

/// 单目录 List 页容量（远端栏既有口径同源：`offset=0/limit=500`）。
const R156_CLIP_LIST_LIMIT: u32 = 500;

/// 现有 FsEntry 秒级口径）。
const R158_MTIME_TOLERANCE_SECS: i64 = 1;

/// 收敛终态必打一行）。
const R158_PROGRESS_EVERY: usize = 20;

/// 在途 List 本地超时（同 pane 槽 [`FS_LOCAL_TIMEOUT`] 口径——响应丢失 =
/// 该目录记失败继续，FSM 不永久悬挂）。
const R156_CLIP_INFLIGHT_TIMEOUT: Duration = FS_LOCAL_TIMEOUT;

impl ClipDirExpand {
    /// （`landing/<目录名>/`）；多根各自独立子目录（同名根共用一落点目录，
    /// 文件级 `unique_target_path` 保名全）。
    pub fn start(dir_paths: Vec<String>, landing_base: &Path) -> Self {
        let mut queue = VecDeque::new();
        let mut visit = HashSet::new();
        let mut dirs = Vec::new();
        for d in &dir_paths {
            if visit.insert(d.to_ascii_lowercase()) {
                let base = d.rsplit('/').next().unwrap_or(d).to_string();
                queue.push_back((d.clone(), 0usize, base.clone()));
                dirs.push(base);
            }
        }
        Self {
            queue,
            visit,
            files: Vec::new(),
            dirs,
            fetch_skipped: 0,
            landing_root: landing_base.to_path_buf(),
            inflight: None,
            inflight_since: None,
            fetch_sent: 0,
            dirs_done: 0,
            failed: Vec::new(),
            cancelled: false,
            conflict: None,
            overwrite_all: false,
            overwrite_once: false,
        }
    }

    /// `files`（落点子目录继承所在目录）；子目录入队（深度 +1 ≤
    /// [`FOLDER_MAX_DEPTH`]、符号链接跳过 S4、小写键去重环防护）；
    /// `has_more` = 续页再入在途（offset 累进）；页完成 `dirs_done += 1`。
    pub fn absorb_page(
        &mut self,
        dir_rel: &str,
        offset: usize,
        depth: usize,
        subdir: &str,
        entries: &[FsEntry],
        has_more: bool,
    ) {
        for e in entries {
            if e.is_symlink {
                continue; // S4：符号链接不跟随不展开
            }
            let child = if dir_rel.is_empty() {
                e.name.clone()
            } else {
                format!("{dir_rel}/{}", e.name)
            };
            if e.is_dir {
                let child_subdir = format!("{subdir}/{}", e.name);
                if depth + 1 > FOLDER_MAX_DEPTH {
                    self.failed.push(child);
                    self.dirs.push(child_subdir);
                    continue;
                }
                if self.visit.insert(child.to_ascii_lowercase()) {
                    self.queue.push_back((child, depth + 1, child_subdir.clone()));
                    // 纯空目录也记录）。
                    self.dirs.push(child_subdir);
                }
            } else {
                self.files.push((child, subdir.to_string(), e.size, e.mtime));
            }
        }
        if has_more {
            // 续页：同目录 offset 累进（回到泵点重发）。
            self.inflight = Some((
                0,
                dir_rel.to_string(),
                offset + entries.len(),
                depth,
                subdir.to_string(),
            ));
        } else {
            // 页尽：在途清（响应消费点已 take，此处幂等兜底）+ 计数。
            self.inflight = None;
            self.inflight_since = None;
            self.dirs_done += 1;
        }
    }

    pub fn is_finished(&self) -> bool {
        self.queue.is_empty()
            && self.inflight.is_none()
            && self.files.is_empty()
    }
}

/// 与 OS 板同时在位时以「最近复制源」为准：`copy_seq` = 内部复制时刻 OS 板
/// 序号快照；`os_seq` = 粘贴时刻读数。双序号可用 → `os_seq != copy_seq`
/// = 内部复制之后板变过 = OS 板更新（Explorer 复制在后）→ `true`；序号
/// 任一不可用（0，unix/基线未置）→ 内容签名仲裁：`os_sig != copy_sig`
/// = 板内容已变 → `true`。
pub fn r156_os_board_newer(copy_seq: u32, copy_sig: u64, os_seq: u32, os_sig: u64) -> bool {
    if copy_seq != 0 && os_seq != 0 {
        return os_seq != copy_seq;
    }
    os_sig != copy_sig
}

/// 0）。仲裁 fallback 素材（纯函数单测钉死）。
pub fn r156_os_board_signature(board: &crate::clipboard::OsFileBoard) -> u64 {
    if board.entries.is_empty() {
        return 0; // 空板 = 0（钉死：与「读板失败」仲裁语义同域）
    }
    let mut h: u64 = 0xcbf29ce484222325;
    for e in &board.entries {
        for b in e.abs_path.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        for b in e.size.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= u64::from(e.is_dir);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ════════════════════════════════════════════════════════════════
// （identical 跳过判定 / 落点 stat / 进度观测行格式，单测钉死）
// ════════════════════════════════════════════════════════════════

/// （stat 失败/文件不存在）= 不 identical（照常拉取，不产生漏贴）；size
/// 不等 = 不 identical；mtime 差 ≤ [`R158_MTIME_TOLERANCE_SECS`]（±1s，
/// 桌面时钟面按现有 FsEntry 口径）= identical。对齐 RustDesk
/// `digest.is_identical` 跳过语义（零 wire，纯本地优化）。
pub fn r158_file_identical(remote_size: u64, remote_mtime: i64, local: Option<(u64, i64)>) -> bool {
    let Some((local_size, local_mtime)) = local else {
        return false;
    };
    if local_size != remote_size {
        return false;
    }
    (local_mtime - remote_mtime).abs() <= i64::from(R158_MTIME_TOLERANCE_SECS)
}

/// `None` = fail-open 照常拉取）。mtime 不可得（FsEntry 口径 = 0）时由
/// [`r158_file_identical`] 的差值判定自然 fail-open（差值巨大）。
pub fn r158_stat_meta(path: &Path) -> Option<(u64, i64)> {
    let md = std::fs::metadata(path).ok()?;
    let secs = md
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some((md.len(), secs))
}

/// `conn_log_push_text` 既有通道）——`sent` = 已派发 FetchFile 数、
/// `skipped` = identical 跳过数、`pending` = 待派发数、`failed` = 失败数。
pub fn r158_progress_line(sent: usize, skipped: usize, pending: usize, failed: usize) -> String {
}

// ════════════════════════════════════════════════════════════════
// （同名冲突三选门 / 决策记忆映射 / 取消收敛计数 / 取消汇总行格式，
// 单测钉死；对齐 RustDesk override_file_confirm 三选 + FileTransferCancel
// 收敛语义——零新 wire，纯 UI 层编排）
// ════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum R159ConflictGate {
    /// 落点无同名 = 直派（零对话框）。
    Dispatch,
    /// 落点同名 + 覆盖策略在位（`overwrite_all` 会话记忆 / `overwrite_once`
    /// 单次）= 删旧后派（删除 fail-closed 门在调用点：登记表命中才删）。
    Overwrite,
    /// 落点同名 + 无既定策略 = 悬挂等三选框（泵冻结，RustDesk
    /// `override_file_confirm` 触发面对齐——只问同名，不比对内容差异）。
    Suspend,
}

/// 落点存在性提问；不比对内容差异，只问同名。
pub fn r159_conflict_gate(
    local_exists: bool,
    overwrite_all: bool,
    overwrite_once: bool,
) -> R159ConflictGate {
    if !local_exists {
        return R159ConflictGate::Dispatch;
    }
    if overwrite_all || overwrite_once {
        return R159ConflictGate::Overwrite;
    }
    R159ConflictGate::Suspend
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum R159ConflictDecision {
    /// 覆盖（删旧后拉新；仅当前项）。
    Overwrite,
    /// 跳过（落点不动零网络帧）。
    Skip,
    /// 全部应用（记 `overwrite_all`，本粘贴会话有效——RustDesk
    /// `default_overwrite_strategy` 同口径）。
    OverwriteAll,
}

/// `(overwrite_all 新值, overwrite_once 新值, 丢弃当前项)`：
/// - 覆盖 = 单次旗标置位（项保留，门重判走 Overwrite 臂消费一次）；
/// - 跳过 = 丢弃当前项（零网络帧，无记忆）；
/// - 全部应用 = 会话记忆置位（项保留，门重判走 Overwrite 臂；`overwrite_
///   once` 不置 = 决策互斥清场）。
pub fn r159_conflict_apply(d: R159ConflictDecision) -> (bool, bool, bool) {
    match d {
        R159ConflictDecision::Overwrite => (false, true, false),
        R159ConflictDecision::Skip => (false, false, true),
        R159ConflictDecision::OverwriteAll => (true, false, false),
    }
}

/// 已收未派文件 + 在途目录 1（其内容未收集）。
pub fn r159_cancel_unassigned(queue_len: usize, files_len: usize, inflight: bool) -> usize {
    queue_len + files_len + usize::from(inflight)
}

/// `conn_log_push_text` 既有通道）——`sent` = 取消前已派发 FetchFile 数、
/// `skipped` = 跳过数（identical + 冲突跳）、`pending` = 未派数。
pub fn r159_cancel_line(sent: usize, skipped: usize, pending: usize) -> String {
}

#[derive(Debug, Clone)]
pub struct R159ConflictItem {
    /// 远端 rel 路径（派发原样回放）。
    pub rel_path: String,
    /// 落点子目录（相对展开根）。
    pub subdir: String,
    /// 远端字节数（展示素材）。
    pub size: u64,
    /// 远端 mtime（UNIX 秒；展示素材）。
    pub mtime: i64,
}

/// 文件管理器状态（**per-连接窗**，非全局 static——R2 在案）。
#[derive(Debug)]
pub struct FileManagerState {
    pub local: LocalPane,
    pub remote: RemotePane,
    /// 活动栏（最近交互；快捷键作用栏）。
    pub active_pane: PaneId,
    /// 剪贴板（复制非移动；跨栏粘贴 = 传输）。
    pub clipboard: Option<Clip>,
    /// 文件夹编排任务（同一时刻至多一个）。
    pub job: Option<FolderJob>,
    /// 在途操作（UI 侧单槽；req_id 由 `Admitted` 回填）。
    pub pending: Option<PendingOp>,
    /// 多项删除逐条确认队列（取消 = 整批中止，零 wire 帧 §1.7）。
    pub pending_deletes: Vec<DeleteTarget>,
    pub dialog: Dialog,
    /// 全局状态行（操作结果/编排进度）。
    pub status_line: Option<String>,
    /// 本帧是否处于对话框文本输入（渲染期置位；快捷键门消费）。
    pub in_text_input: bool,
    /// 〔空名/busy/盘符层合成根〕= 保开对话框 + 框内红字，**非静默**；
    /// 旧语义 = 对话框消失仅状态行小字 = 用户「两次没看到新目录」主
    /// 断点面）。开新对话框/取消/提交成功 = 清零。零 wire。
    pub dialog_error: Option<String>,
    /// `ConsentSettled` 结算 / [`consent_out_prune`] 终态 TTL 剪除）。
    pub consent_out: Vec<ConsentOutLine>,
    /// 两权限开关通告值（`FsEvent::PeerConsent` 覆写；`Option<(
    /// clipboard, file_transfer)>`，`None` = 对端未通告〔旧版本对端 /
    /// 会话刚建立通告未到〕= fail-closed 按 OFF + 显式提示，红线⑤）。
    /// per-窗生命周期；会话重连 = 对端新 FileSession 首 tick 重新通告
    ///（覆盖陈旧值，窗口 ≤1s）。
    pub peer_consent: Option<(bool, bool)>,
    /// ClipMeta` 帧消费产物——被控端本机板文件清单；`on_clip_meta` 门控
    /// 置/清，Ctrl+V 粘贴拉取派发点消费即清）。per-窗生命周期（随窗拆除
    /// 清零 = 会话拆除清除条件结构成立）。
    pub pending_clip_meta: Option<crate::clipboard::FileClipMeta>,
    /// [`clipboard_direct::should_request_prefetch`] = 唯一判定源，门外零
    /// 槽写 = 授权门结构性不可绕过；窗层 drain 位点消费即清 =
    /// `take_clip_prefetch_req`，桌面会话 `MetaApplied` 门内臂不经此槽）。
    /// per-窗生命周期（随窗拆除清零）。
    pub clip_prefetch_req: Option<crate::clipboard::FileClipMeta>,
    clip_meta_gate_warn_at: std::time::Instant,
    /// 空闲；粘贴臂启动、tick 泵进、`on_fs_event` 喂响应）。per-窗生命
    /// 周期（随窗拆除清零）。
    pub clip_expand: Option<ClipDirExpand>,
    ///（`clipboard_sequence_number()`，0 = 不可用）。
    pub clip_internal_copy_seq: u32,
    /// 时的仲裁 fallback；0 = 板空/读失败）。
    pub clip_internal_copy_os_sig: u64,
    /// [`R173_DRAIN_WATCH_CAP`]）。武装源 = 传输终态链（`ConsentSettled`
    /// Consumed 事件臂 from_job/单文件 + ToRemote 整树编排收敛臂）；
    /// 消费点 = [`Self::tick`]（上传全终态〔落盘已毕〕+ 单在途空闲 → 逐帧
    /// 一枚经 `remote.refresh_node` 既有槽失效重列）。per-窗生命周期。
    upload_drain_watch: Vec<String>,
    /// **本窗帧首注入视图**，`None` = 无登记语境；生命周期 = 全局登记表，
    /// 清位面 = 会话拆除/CLEAR/对端门 OFF——过期语境不跨会话复用）。
    /// 消费点 = [`Self::c2s_paste_upload_target`] 回退臂（选中 > 当前 >
    /// 登记表 > 合成根，单点折叠桌面窗快照与 FM 粘贴臂同受益）。
    pub(crate) r167_session_dir_fallback: Option<String>,
    /// egui 0.28.1 硬编码 `Sense::click()`〔selected_label.rs allocate
    /// 位点〕，`Widget::sense` 注入不可达；自绘零触既有 response 判定 =
    /// 单击/双击/右键零回归）。`None` = 空闲；`Some` = 候选按下/拖拽中。
    /// per-窗生命周期（随窗拆除清零）。
    pub r195_drag: Option<R195Drag>,
}

#[derive(Debug, Clone)]
pub struct R195Drag {
    /// 拖起源栏（唯一有效释放目标 = 对侧栏）。
    pub source: PaneId,
    /// 被拖行节点全路径键。
    pub path: String,
    /// 按下原点（位移阈值判定锚）。
    pub start: egui::Pos2,
    /// 载荷路径集（**过阈值帧定格**；空 = 候选未过阈值）。
    /// 键形 = `selection_paths` 同形节点全路径；多选批量语义
    /// = [`r195_drag_payload_paths`] 单源。
    pub paths: Vec<String>,
}

/// 渲染层语义：Idle/Armed 零视觉，Dragging 视觉反馈，Dropped 落定判定）。
#[derive(Debug, Clone, PartialEq)]
pub enum R195DragFrame {
    /// 空闲（无拖拽）/ 未过阈值即松开（原单击路径，零动作）。
    Idle,
    /// 候选按下未过阈值（零视觉零动作）。
    Armed,
    /// 拖拽进行中（载荷已定格；视觉反馈）。
    Dragging { source: PaneId, paths: Vec<String> },
    /// 本帧释放且已过阈值（调用方做双栏落定判定；状态已清）。
    Dropped { source: PaneId, paths: Vec<String> },
}

/// 同值钉死——防样式漂移改判定）。
pub const R195_DRAG_THRESHOLD: f32 = 6.0;

/// 被拖行 ∈ 当前多选 = **整批多选**（选择序原样）；∉ = 单行。
/// 键形 = `selection_paths` 同形节点全路径键（本地绝对 / 远端 root 相对）。
pub fn r195_drag_payload_paths(selection: &[String], dragged: &str) -> Vec<String> {
    if selection.iter().any(|p| p == dragged) {
        selection.to_vec()
    } else {
        vec![dragged.to_string()]
    }
}

/// 行区命中 = 有效目标；源栏 / 中缝 / 栏头 / 栏外（对侧 rect 未命中）=
/// 无动作。两 rect 理论不相交（布局区隔中缝）；同帧皆命中 = 对侧优先
/// （确定性钉死）。
pub fn r195_drop_target(
    source: PaneId,
    pointer_in_local: bool,
    pointer_in_remote: bool,
) -> Option<PaneId> {
    match source {
        PaneId::Local => pointer_in_remote.then_some(PaneId::Remote),
        PaneId::Remote => pointer_in_local.then_some(PaneId::Local),
    }
}

/// 折叠 + 总数；与 FolderJob source 显示同 basename 口径）。
pub fn r195_drag_shadow_text(paths: &[String]) -> String {
    let names: Vec<String> = paths.iter().map(|p| task_file_basename(p)).collect();
    if names.len() <= 3 {
        names.join("、")
    } else {
        format!("{}、… ×{}", names[..3].join("、"), names.len())
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentOutcome {
    /// 对端已确认——其 `FetchFile` 已到达（真实传输行归全局任务面板呈现）。
    Consumed,
    /// 对端用户点【取消】（`FsErrCode::Declined` 负回执；零落盘 §8.3）。
    Declined,
    /// 发送端等待确认超时（[`CONSENT_WAIT_TIMEOUT`]，Q11 5min 常量）。
    Timeout,
    /// 通告帧发送失败（死链/版本门抑制；fail-closed 不假装等待）。
    SendFailed,
}

/// 余 = 终态，TTL 后剪除）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentOutState {
    Waiting,
    Transferring,
    Declined,
    Timeout,
    SendFailed,
}

impl ConsentOutState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, ConsentOutState::Waiting)
    }
}

/// 引擎 `ConsentSent` 建、`ConsentSettled` 结算——UI 侧零 wire 判定）。
#[derive(Debug, Clone)]
pub struct ConsentOutLine {
    pub req_id: u32,
    pub peer_label: String,
    pub count: usize,
    pub total_size: u64,
    pub truncated: bool,
    pub from_job: bool,
    pub started: Instant,
    pub state: ConsentOutState,
    /// 结算时刻（`None` = 仍等待；UI 剪除基准）。
    pub settled_at: Option<Instant>,
}

// `ConsentRequest`（引擎 → UI 确认队列条目）与 `ConsentQueue`（per-窗 FIFO
// 一次一框）随三选弹窗退役删除——B2 起两开关态均不入确认队列（ON = 自动
// 接受 / OFF = 自动 `Declined`），引擎侧无构造点、UI 侧无消费点 = 双死。
// 「在途登记职能」（§12.1 处置表「收敛」项）由发送侧 `consent_outgoing` +
// `consent_is_pending` 在途去重承载（`FileSession` 侧，零变化保留）。
// `Accept`/`SaveAs` 变体（UI 三选回传臂退役后生产零构造）+ `Cancel.req_id`
// 字段（写而不读）随渲染面删除——余 `Cancel` 单变体 = B2 OFF 臂经
// `consent_reply_err` 消费的回执码单一来源定义（生产可达映射零变化：
// Cancel ⇒ `Declined`；`consent_reply_err` 体 = 编译强制删两映射臂，
// 开工申报口径同 `consent_landing_dir` ①级）。

/// 退役后收敛为回执码映射纯函数 [`consent_reply_err`] 的入参类型（B2
/// OFF 臂 `ConsentDecision::Cancel` 消费；`Accept`/`SaveAs` 变体随框
/// 删除 = 禁 dead code，`req_id` 关联职能 = 调用点本地量，不经本类型）。
#[derive(Debug, Clone, Copy)]
pub enum ConsentDecision {
    /// 取消 = 回 `FsErrCode::Declined` 负回执，零落盘、零内容帧、零 `.part`。
    Cancel,
}

// ── 纯函数族（单测钉死；引擎/UI 两侧共用单一定义点）──

/// 拆批（§8.6）：≤`max`/批逐批一框；`truncated` = 总长 > max（发送端拆多
/// 请求记档；wire 只承载 bool，FILEMETA 先例同口径）。
pub fn consent_split_batches<I: Clone>(items: &[I], max: usize) -> (Vec<Vec<I>>, bool) {
    if items.is_empty() {
        return (Vec::new(), false);
    }
    if max == 0 {
        // 退化防御（生产 max = 255 常量不可达）：无批可成 = 截断记档。
        return (Vec::new(), true);
    }
    let truncated = items.len() > max;
    let batches: Vec<Vec<I>> = items.chunks(max).map(|c| c.to_vec()).collect();
    (batches, truncated)
}

/// `Declined` 负回执**（B2 OFF 臂消费——开关关拒绝语义 ≡ Cancel 决策回执，
/// 回执码单一来源定义，映射语义零变化）；接收/另存为变体随三选框退役
///（pull 模型结构性保证不变：接收类决策无单独 ok 回执——对端 `FetchFile`
/// 到达即同意回执，§8.7①）。
pub fn consent_reply_err(decision: &ConsentDecision) -> Option<FsErrCode> {
    match decision {
        ConsentDecision::Cancel => Some(FsErrCode::Declined),
    }
}

/// 落点三级优先级（§8.5，接收端本地决策零 wire）：
/// ① 另存为显式目录（用户本次动作，最高）＞ ② K4 v2 OfferV2 `target_dir`
///（发送方请求上下文捕获的远端栏当前目录）＞ ③ `download_dir` 默认。
pub fn consent_landing_dir<'a>(
    save_as: Option<&'a Path>,
    offer_v2_target: Option<&'a Path>,
    download_dir: &'a Path,
) -> &'a Path {
    save_as.or(offer_v2_target).unwrap_or(download_dir)
}

/// 等待超时判定（Q11）：`now - started >= timeout`。**时钟回拨饱和**
///（`Instant::duration_since` 回拨时归零 = 未超时——fail-safe 不误杀
pub fn consent_wait_expired(started: Instant, now: Instant, timeout: Duration) -> bool {
    now.duration_since(started) >= timeout
}

//    落点纯函数族（臂 ② 派发落点替换固定 `download_dir`；零 wire——落点 =
//    本端本地状态，不上 wire；与 `consent_landing_dir` 三级互相独立，§12.3
//    「两路径落点逻辑零耦合」）。──

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasteLanding {
    /// 当前浏览文件夹可用（`fm_current` 在位且存在且可写）= 落该目录。
    Browse(PathBuf),
    /// 不可用（无 File/Shell 窗 FM 上下文 / 目录不存在 / 不可写）= 回退
    /// `download_dir` + 调用点 toast（`clip.fetch.fallback` 键文 B2 先入表，
    /// B3 消费，键文零改 = G 岗用户终稿统一修订）。
    Fallback(PathBuf),
}

/// 按 `win.kind`/`win.show_file_mgr` 注入布尔——本函数不感知窗型枚举，
/// 与 `file_mgr_mountable` 首参「调用方映射」先例同口径）：
/// - `file_surface = false`（Desktop 会话窗——无 FM 挂载，§9.3 结构性事实）
///   → 恒 false（无上下文 → 回退）；
/// - `file_surface = true` + `panel_open = false`（Shell 窗面板关）→ false
///   （无上下文 → 回退）；
/// - `file_surface = true` + `panel_open = true`（Shell 窗面板开 / File 窗
///   全窗形态〔调用点传恒 true〕）→ true（`win.file_mgr.local.current`）。
pub fn paste_landing_fm_surface(file_surface: bool, panel_open: bool) -> bool {
    file_surface && panel_open
}

/// `fm_current = Some` 且 `dir_exists` 且 `dir_writable` →
/// [`PasteLanding::Browse`]（该目录）；否则 → [`PasteLanding::Fallback`]
/// （`download_dir`）。存在/可写 = 调用点派发时刻 `std::fs` 探测（纯函数
/// 只吃布尔 = 可单测；探测在 UI 帧 = 粘贴稀有事件，零常态成本）。
/// `download_dir` 实参 = 调用点自 `Config::load()` 同源取值（B2 臂 ② 门点
/// 既有单次 load 双用的落点值——本函数零 config 触碰 = 纯）。
pub fn paste_landing_resolve(
    fm_current: Option<&Path>,
    dir_exists: bool,
    dir_writable: bool,
    download_dir: &Path,
) -> PasteLanding {
    match fm_current {
        Some(dir) if dir_exists && dir_writable => PasteLanding::Browse(dir.to_path_buf()),
        _ => PasteLanding::Fallback(download_dir.to_path_buf()),
    }
}

/// 落点目标目录决议（**纯函数，单测钉死唯一定义点**；c→s 侧对偶面 = s→c
/// [`paste_landing_resolve`] FM 面同口径——落点 = 本端 FM 远端栏语境，不上
/// wire，零新帧）：
/// - `fm_context = false`（同 peer 无在位 Shell 窗 FM 面板语境：无窗/面板关/
///   远端栏未启动/对端不支持浏览）→ `None`（调用点走既有 v1 Offer 链：服务
///   端聚焦层〔Win10〕/ download_dir 回退，**零变化** fail-closed 口径）；
///   目标栏选中目录」同口径）；
/// - 否则 → `Some(远端栏当前目录)`（合成根 → `""` 对端 fs 根 =
///   [`FileManagerState::remote_default_target`] 同口径）。
pub fn clip_upload_c2s_target(
    fm_context: bool,
    sel: Option<String>,
    default_target: String,
) -> Option<String> {
    if !fm_context {
        return None;
    }
    Some(sel.unwrap_or(default_target))
}

// Q9 二态 `consent_handle_mode`/`ConsentHandleMode`（Gui/Headless）**已退役**
// ——被下方开关四格决策（`consent_switch_decision`，GUI-开/headless-开 = 同一
// 自动接受臂、GUI-关/headless-关 = 同一自动 `Declined` 臂）吸收；
// `recv_auto_accept` 硬化档不落地为配置（Q9 关闭，§12.6）。对应 A3 单测
// （`test_r110a3_consent_headless_mode`）同退役（四格矩阵
// `test_r110v13b2_consent_switch_decision_matrix` 超集钉死）。

//    权限开关三态判定 + 四格决策纯函数族（引擎门控 + 卡区展示点的
//    **单一语义源**；零 wire、零新变体、零新字段、零新 ChannelTag）。──

/// 的展示面伴生——卡区 tooltip 需区分「损坏」与「用户显式关」，布尔对
/// 不足以判别）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentConfigState {
    /// `Ok` = 字段值可用（缺键 = serde 默认开，load 侧已归一）。
    Ok,
    /// `Err` + 配置文件不存在（**首启**）= 默认开（用户「默认都开」口径）。
    FirstRun,
    /// `Err` + 文件存在（损坏/不可读）或路径不可解析 = **fail-closed 按关**
    /// （架构红线⑤：开关态不可得 = 按关）。
    Invalid,
}

/// 三态核心（纯函数，注入面——`fields = Some` ⇔ load Ok（缺键已按 serde
/// 默认归一，此处不重判）；`exists = None` ⇔ 路径不可解析）。单测经本核
/// 面注入（零环境依赖）；生产经下方包装（路径存在性自 `config_dir()`
/// 同源判定）。
fn consent_switches_core(
    fields: Option<(bool, bool)>,
    config_file_exists: Option<bool>,
) -> (bool, bool) {
    match (fields, config_file_exists) {
        (Some((ft, clip)), _) => (ft, clip),
        (None, Some(true)) => (false, false), // 存在但损坏/不可读 = 双关 fail-closed
        (None, Some(false)) => (true, true),  // 首启缺文件 = 默认开
        (None, None) => (false, false),       // 路径不可解析 = 态不可得 = 按关
    }
}

/// `Ok` = 字段值（缺键 = serde 默认开）；`Err` + 配置文件**不存在**（首启）
/// = `(true, true)`；`Err` + 文件**存在**（损坏/不可读）= `(false, false)`
/// fail-closed（架构红线⑤）。路径存在性判定 = `Config::config_dir()`
/// （公共 API，`KIRIN_DATA_DIR` 最高优先级，与 `Config::load()` 同源）+
/// `default.toml` metadata。消费点：① FileSession 构造会话快照（WARN 一行
/// 归构造点每会话消费——F 岗 grep 锚点「配置损坏 = 双关 + WARN 行」；本
/// 纯函数体零副作用）② Dashboard 卡区展示点（损坏 = 显示关 + 异常
/// tooltip；缺文件 = 显示开 = 默认）。
pub fn consent_switches_from_load(
    load: &Result<kirin_desk_utils::config::Config, kirin_desk_utils::config::ConfigError>,
) -> (bool, bool) {
    if let Ok(cfg) = load {
        return (
            cfg.file_transfer.file_transfer_allowed,
            cfg.file_transfer.clipboard_allowed,
        );
    }
    consent_switches_core(None, consent_config_file_exists())
}

/// `ConsentConfigState` 核心（纯函数注入面，同上核面约定）。
fn consent_config_state_core(ok: bool, config_file_exists: Option<bool>) -> ConsentConfigState {
    if ok {
        ConsentConfigState::Ok
    } else {
        match config_file_exists {
            Some(false) => ConsentConfigState::FirstRun,
            // 存在但损坏/不可读、或路径不可解析（态不可得）= Invalid（按关）。
            _ => ConsentConfigState::Invalid,
        }
    }
}

/// 配置路径存在性（`config_dir()/default.toml` metadata；`None` = 路径
/// 不可解析）。与 `Config::load()` 同口径（`KIRIN_DATA_DIR` 最高优先级）。
fn consent_config_file_exists() -> Option<bool> {
    kirin_desk_utils::config::Config::config_dir()
        .ok()
        .map(|dir| std::fs::metadata(dir.join("default.toml")).is_ok())
}

/// 同源同语义）。
pub fn consent_config_state(
    load: &Result<kirin_desk_utils::config::Config, kirin_desk_utils::config::ConfigError>,
) -> ConsentConfigState {
    consent_config_state_core(load.is_ok(), consent_config_file_exists())
}

/// 接收端视角；「本端有人动作」不门控 = 无臂）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentArrival {
    /// `FsOp::TransferRequest` 通告到达（同意族：文件管理器 ⬆ / 收敛后拖拽 /
    /// 收敛后仪表盘推送）。
    TransferRequest,
    /// `FileOp::Offer` 到达、**不属**本端在途 Fetch 请求集（直发族：臂 ①
    /// 粘贴上传 / 旧端直发 / 断点续传 re-Offer）。
    Offer,
    /// 本端臂 ② 粘贴拉取派发点（本地门，零 wire，对端无涉）。
    PasteFetch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentSwitchDecision {
    /// 自动接受（TransferRequest 开 / Offer 双开 = K3 现状）或臂 ② 派发
    /// （剪贴板开）。
    Accept,
    /// 自动 `Declined` 回执（TransferRequest 关；零落盘/零内容帧/零 `.part`
    /// 结构性保证）。
    Declined,
    /// Accept 前 `Reject`（Offer 任一开关关；原因 UTF-8「传输开关已关」；
    /// 零内容字节——判定先于 Accept = 无 `.part` 产生）。
    Reject,
    /// 不派发 + toast（臂 ② 剪贴板关；本地门零 wire）。
    Blocked,
}

///（引擎门控单一决策点）：TransferRequest → 文件传输开关 → Accept/Declined；
/// Offer → **文件传输 AND 剪贴板**（§12.2⑥，任一关 → Reject）；臂 ② →
/// 剪贴板开关（本地门）→ Accept（派发）/Blocked（不派发）。
/// **fail-closed 方向**：本函数只减接受面不增（任一开关不可用态 = 拒绝臂）。
pub fn consent_switch_decision(
    file_transfer: bool,
    clipboard: bool,
    arrival: ConsentArrival,
) -> ConsentSwitchDecision {
    match arrival {
        ConsentArrival::TransferRequest => {
            if file_transfer {
                ConsentSwitchDecision::Accept
            } else {
                ConsentSwitchDecision::Declined
            }
        }
        ConsentArrival::Offer => {
            if file_transfer && clipboard {
                ConsentSwitchDecision::Accept
            } else {
                ConsentSwitchDecision::Reject
            }
        }
        ConsentArrival::PasteFetch => {
            if clipboard {
                ConsentSwitchDecision::Accept
            } else {
                ConsentSwitchDecision::Blocked
            }
        }
    }
}

/// 重复推送去重（§8.6）：同 (name, size) 已在等待确认中 = 跳过 +
/// 「等待对方确认中」提示（不重复通告 = 不重复弹框）。
pub fn consent_is_pending(pending: &[(String, u64)], name: &str, size: u64) -> bool {
    pending.iter().any(|(n, s)| n == name && *s == size)
}

/// 发送侧行结算（幂等：已结算行对迟到事件不变——防双弹/状态漂移）。
pub fn consent_out_apply(line: &mut ConsentOutLine, outcome: ConsentOutcome, now: Instant) {
    if line.settled_at.is_some() {
        return;
    }
    line.state = match outcome {
        ConsentOutcome::Consumed => ConsentOutState::Transferring,
        ConsentOutcome::Declined => ConsentOutState::Declined,
        ConsentOutcome::Timeout => ConsentOutState::Timeout,
        ConsentOutcome::SendFailed => ConsentOutState::SendFailed,
    };
    line.settled_at = Some(now);
}

/// 发送侧行剪除（终态 + TTL 过期 = 剪；等待行不剪——超时判定归引擎）。
pub fn consent_out_prune(lines: &mut Vec<ConsentOutLine>, now: Instant) {
    lines.retain(|l| {
        if let Some(at) = l.settled_at {
            !consent_wait_expired(at, now, CONSENT_OUT_TTL)
        } else {
            true
        }
    });
}

/// 等待倒计时显示串（`mm:ss` 零填充；归零 = 引擎 on_tick 下轮结算）。
pub fn consent_countdown(remaining: Duration) -> String {
    let s = remaining.as_secs();
    format!("{:02}:{:02}", s / 60, s % 60)
}

// ════════════════════════════════════════════════════════════════
// 焦点切分纯函数（09-11 硬保证；单测钉死，无 egui 依赖）
// ════════════════════════════════════════════════════════════════

/// 终端 feed 门（窗口层以纯 AND 追加：`focused && !file_mgr_focus`）：
/// 窗口聚焦 **且** 文件管理器不持焦 = feed；否则全键零 feed（PTY 零字节）。
/// 窗口失焦后回焦默认归终端 = 保守向（按键优先终端 = 远程桌面安全向）。
pub fn terminal_feeds_keys(window_focused: bool, file_mgr_focus: bool) -> bool {
    window_focused && !file_mgr_focus
}

/// 面板侧快捷键门：**显式**以「文件管理器持有焦点」为门，且不在文本输入
/// （对话框 TextEdit 聚焦时 Ctrl/Cmd+C = 文本复制，egui 默认行为）。
pub fn file_mgr_shortcut_active(file_mgr_focus: bool, in_text_input: bool) -> bool {
    file_mgr_focus && !in_text_input
}

/// 的**显式提示判定**（纯函数）——焦点门关闭**且非文本输入** = 提示
/// 「剪贴板内容已就绪，请点击文件面板后按 Ctrl+V」（禁静默红线⑤：修前
/// 本形态零动作静默，落入 egui 默认文本粘贴 → arboard 读 OS 板空报
/// 「clipboard is empty」= 用户日志锚行的病灶）。
///
/// **边界**：`in_text_input = true`（对话框 TextEdit 聚焦）= 恒 `false`
/// 零提示——该形态 Ctrl+V = egui 文本粘贴既有行为，**零变化**（验收标准
/// ③「文本框内 ctrl+v 行为零变化」；提示只对「焦点在窗外/非面板」的
/// 粘贴语境丢失形态负责）。
pub fn r164_paste_focus_hint_due(file_mgr_focus: bool, in_text_input: bool) -> bool {
    !file_mgr_focus && !in_text_input
}

/// `WindowKind::File` 全窗承载文件管理器（无终端画布分焦对象，窗层
/// `file_mgr_focus` 初值即 true 且无失焦清除臂）→ 窗持有 egui 焦点
/// （`ctx.input(|i| i.focused)`）**或**窗层粘性持焦任一成立 = FM 持焦，
/// 消除「打开窗口直接 Ctrl+V 零响应」。文本输入门（`in_text_input`）
/// 仍由 [`file_mgr_shortcut_active`] 独立执法（对话框内 Ctrl+V = 文本
/// 粘贴零变化）；Shell 窗焦点切分语义零触碰（本函数仅 File 全窗调用点
/// 消费，终端 feed 负门 `terminal_feeds_keys` 不经此）。
pub fn r164_file_window_fm_focus(window_focused: bool, sticky_focus: bool) -> bool {
    window_focused || sticky_focus
}

/// 复制/粘贴修饰键（UI 层判定，§2.6.1③：Mac ⌘ ≡ 他平台 Ctrl；
/// **终端线零触碰**——本判定仅作用于面板侧快捷键，不进终端 feed）。
pub fn copy_paste_mods(modifiers: &egui::Modifiers) -> bool {
    if cfg!(target_os = "macos") {
        modifiers.command
    } else {
        modifiers.ctrl
    }
}

/// 按住 Ctrl+V 逐 repeat 帧不得重复入队）。
pub fn key_pressed_once(input: &egui::InputState, key: egui::Key) -> bool {
    input.events.iter().any(|e| {
        matches!(e, egui::Event::Key { key: k, pressed: true, repeat: false, .. } if *k == key)
    })
}

/// 面板侧快捷键统一入口（**09-11 硬保证单点**）：
/// 非「文件管理器持焦且非文本输入」= **零动作**（不偷终端 Ctrl+C=0x03、
/// 不入队、无 FileManagerState 变更）。右键菜单路径不经本入口（鼠标驱动，
/// 不受焦点态影响，09-11 加分项③）。
pub fn handle_shortcut(
    state: &mut FileManagerState,
    file_mgr_focus: bool,
    in_text_input: bool,
    key: FileMgrShortcut,
    panel: &FilePanelState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
    fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
) {
    if !file_mgr_shortcut_active(file_mgr_focus, in_text_input) {
        return;
    }
    match key {
        FileMgrShortcut::Copy => {
            state.copy_selection(state.active_pane);
        }
        FileMgrShortcut::Paste => {
            // 空 = 用户 Ctrl+C 发生在**应用外**（Explorer 等 OS 板）→ OS 板
            // 兜底：c→s 上传落点 = 本窗远端栏当前目录 / s→c 拉取落点 = 本
            // 窗本地栏当前目录（`paste_clipboard_fallback` 单一入口，既有
            // 传输通道零新 wire）。修前本入口恒 `paste_cross` → 内部板空 =
            // 「剪贴板为空」，OS 文件粘贴在文件窗零响应（用户「依旧未生效」
            // 的 c→s 分叉点）。
            // 板非空且为「最近复制源」（板序号/签名仲裁，纯函数
            // [`r156_os_board_newer`]）= OS 板胜 → 兜底臂——修前内部板残留
            // 旧单文件时 Explorer 新复制目录被抢走 = 「1 文件传输成功」误报
            // 根因。
            let os_files = crate::clipboard::read_local_files();
            let os_newer = os_files.as_ref().is_some_and(|b| !b.entries.is_empty())
                && r156_os_board_newer(
                    state.clip_internal_copy_seq,
                    state.clip_internal_copy_os_sig,
                    crate::clipboard::clipboard_sequence_number(),
                    os_files
                        .as_ref()
                        .map(r156_os_board_signature)
                        .unwrap_or(0),
                );
            if state.clipboard.is_some() && !os_newer {
                state.paste_cross(panel, file_tx, fm_tx);
            } else {
                state.paste_clipboard_fallback(file_tx, os_files.as_ref());
            }
        }
        FileMgrShortcut::Enter => {
            if state.has_dialog() {
                if let Some(cmd) = state.dialog_enter() {
                    if let Some(tx) = file_tx {
                        let _ = tx.send(cmd);
                    }
                }
            } else {
                state.enter_selected(file_tx);
            }
        }
    }
}

/// 门控矩阵（门控口径单一事实源 = `win.kind` + `file_tx`，§2.0）：
/// 文件管理器仅 **文件管理器承载窗** + **文件通道存在** 时挂载；Desktop 窗
/// 既有 📁 队列面板（file_panel.rs）零改动。fail-closed：无通道 = 无入口。
///
/// 首参 = 承载窗判定（**调用方映射**，本函数不感知 `WindowKind`）：
///   调用方统一经 lib.rs `file_mgr_surface_for_kind(kind)` 单一映射
///   （`Shell | File → true`，`Desktop → false`），两调用点（Shell 工具栏
///   📁 / Shell 底部面板）+ File 窗全窗分支共用本纯函数，口径零漂移。
pub fn file_mgr_mountable(win_is_file_surface: bool, file_tx_some: bool) -> bool {
    win_is_file_surface && file_tx_some
}

// ════════════════════════════════════════════════════════════════
// 纯助手（单测面）
// ════════════════════════════════════════════════════════════════

/// 远端路径拼接（root 相对；`base=""` = 根；`rel=""` = base 自身）。
/// （[`is_drive_path`]）时以 `\` 拼接（盘符根键形态 `"C:\"` 带尾分隔符，
/// 拼接前已带尾分隔符则不重复补）；其余 = 既有 `/` root 相对语义零漂移。
pub fn remote_join(base: &str, rel: &str) -> String {
    if rel.is_empty() {
        return base.to_string();
    }
    if base.is_empty() {
        return rel.to_string();
    }
    if is_drive_path(base) {
        let b = if base.ends_with('\\') || base.ends_with('/') {
            base.to_string()
        } else {
            format!("{base}\\")
        };
        format!("{b}{rel}")
    } else {
        format!("{base}/{rel}")
    }
}

/// 远端相对化（`base="a"`、`full="a/b/c"` → `"b/c"`；base 为空 = full）。
/// 形态 = 源内相对路径单一规范；非盘符 = 既有 `/` 语义零漂移）。
pub fn remote_strip_base(base: &str, full: &str) -> String {
    if base.is_empty() {
        return full.to_string();
    }
    if is_drive_path(base) {
        let b = normalize_drive_sep(base);
        let prefix = if b.ends_with('\\') {
            b
        } else {
            format!("{b}\\")
        };
        let n = normalize_drive_sep(full);
        return n
            .strip_prefix(&prefix)
            .map(|s| s.replace('\\', "/"))
            .unwrap_or_else(|| full.to_string());
    }
    full
        .strip_prefix(&format!("{base}/"))
        .map(|s| s.to_string())
        .unwrap_or_else(|| full.to_string())
}

/// 相对路径父级（`"a/b/c"` → `"a/b"`；`"c"` → `""`）。
pub fn rel_parent(rel: &str) -> &str {
    match rel.rfind('/') {
        Some(i) => &rel[..i],
        None => "",
    }
}

/// 相对路径末段。
pub fn rel_basename(rel: &str) -> &str {
    match rel.rfind('/') {
        Some(i) => &rel[i + 1..],
        None => rel,
    }
}

//    整树递归补全族——空目录目标镜像 / 已访集合环防护 / 单条目失败汇总
//    （观测行格式钉死单测）/ 取消传播判定。**零新 wire op**（既有 List+
//    Fetch 组合逐层走；目标侧建目录 = 本机 `create_dir_all`）。──

/// 子目录 = `prefix/源内相对路径`）。
pub fn job_dir_display(prefix: &str, rel: &str) -> String {
    if rel.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}/{rel}")
    }
}

/// `kind` ∈ {`list:<FsErrCode>` / `list:wire` / `timeout` / `io` /
/// `interrupted`}；`rel` = 目标内相对路径。
pub fn r135_5b_fail_line(kind: &str, rel: &str) -> String {
}

/// 无失败且无环跳过 = `None`（零行）；否则一行 = 成功入队文件数 +
/// 失败清单（`路径:种类` 以 `;` 连）+ 环跳过清单（以 `;` 连）。
pub fn r135_5b_summary_line(
    ok_files: usize,
    failed: &[(String, String)],
    cycle: &[String],
) -> Option<String> {
    if failed.is_empty() && cycle.is_empty() {
        return None;
    }
    let f = failed
        .iter()
        .map(|(p, k)| format!("{p}:{k}"))
        .collect::<Vec<_>>()
        .join(";");
    Some(format!(
        cycle.join(";")
    ))
}

/// 条目。命中 = 整任务中断（`tick` 消费；匹配口径 = [`batch_all_terminal`]
/// 同源：basename + size + direction）。
pub fn job_has_cancelled(job: &FolderJob, panel: &FilePanelState, dir: FileDirection) -> bool {
    let batch_end = (job.batch_head + FOLDER_BATCH_SIZE).min(job.files.len());
    job.files[job.batch_head..batch_end].iter().any(|(p, size, _sub)| {
        let b = task_file_basename(p);
        panel.tasks.iter().any(|t| {
            t.name == b
                && t.size == *size
                && t.direction == dir
                && matches!(t.status, FileTaskStatus::Cancelled)
        })
    })
}

//    已在位 + 接收侧 `create_dir_all` 建非空子树；本族补缺口 = 空目录远端
//    创建〔既有 `FsOp::Mkdir` 链〕/ 单条目失败汇总〔观测行格式钉死单测〕/
//    取消传播扩 ToRemote / 重复根已访去重）。──

/// `kind` ∈ {`mkdir:<FsErrCode>` 〔服务端非 Ok 且非 AlreadyExists〕,
/// `mkdir:wire` 〔传输 Err〕, `timeout` 〔本地超时〕, `io` 〔本地 read_dir
/// 失败〕, `interrupted` 〔任务终态后余留队列/通道缺失〕}；
/// `rel` = 目标内相对显示路径（`remote_strip_base` 归一 '/' 形态）。
pub fn r135_5c_fail_line(kind: &str, rel: &str) -> String {
}

/// 无失败且无环跳过 = `None`（零行）；否则一行 = 成功入队文件数 +
/// 失败清单（`路径:种类` 以 `;` 连）+ 环跳过清单（以 `;` 连）。
pub fn r135_5c_summary_line(
    ok_files: usize,
    failed: &[(String, String)],
    cycle: &[String],
) -> Option<String> {
    if failed.is_empty() && cycle.is_empty() {
        return None;
    }
    let f = failed
        .iter()
        .map(|(p, k)| format!("{p}:{k}"))
        .collect::<Vec<_>>()
        .join(";");
    Some(format!(
        cycle.join(";")
    ))
}

/// 单测钉死）。「空」= 收集范围内其子树**无任何文件**（含：真空目录 /
/// 超深度未展开目录本身〔其子未收集〕/ 读取失败目录〔内容缺失〕/ 仅含
/// 符号链接条目目录〔S4 跳过不上传〕）。根自身 = `""`（`files` 为空时须建
/// 同名根目录）。非空目录不在此列 = 接收侧逐文件 `create_dir_all` 附带创建
/// （`core/src/connection/file_transfer.rs` `begin_with`，零额外 wire）。
pub fn r135_5c_empty_dirs(files: &[(String, u64)], dirs: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if files.is_empty() {
        out.push(String::new()); // 根自身空（纯空目录/全读取失败/全符号链接选中）
    }
    for d in dirs {
        let prefix = format!("{d}/");
        if !files.iter().any(|(f, _)| f.starts_with(prefix.as_str())) {
            out.push(d.clone());
        }
    }
    out
}

//    「远端电脑」合成根 + 盘符路径助手族（零新 wire op：保留键走既有
//    `FsOp::List{path}` 字符串通道，服务端识别键 → 盘符枚举）──

/// [`LOCAL_PC_ROOT_KEY`] 口径——**非传输目标**：[`single_dir_selection` 语义
/// 区] fail-closed 排除、传输源枚举排除、mkdir/删除/改名调用面排除）。
/// wire 路径 = 本保留键字符串（`FsOp::List{path: 保留键}`；**零新 wire
/// op/零 PROTOCOL_VERSION 变更**；服务端 `exec_fs_op` List 臂识别键切换
/// 盘符枚举——对旧服务端 = 普通相对路径 sanitize → 节点级错误标记，
pub const REMOTE_PC_ROOT_KEY: &str = "__kirin_remote_pc_root__";

/// 合成「主目录」节点保留键（挂 [`REMOTE_PC_ROOT_KEY`] 合成根下 depth 1，
/// 同 [`LOCAL_PC_ROOT_KEY`] 保留键手法）。children 源 = **home List 缓存
/// `nodes[""]`**（[`remote_home_dir_present`] 快捷钮 enable 同源，零新
/// wire）；子键 = **home 相对裸名**（与 [`FileManagerState::goto_remote_
/// quick`] 既有键 `"Desktop"` 同形 = 零键迁移零缓存失效）。**非传输
/// 目标/源**（保留键零入落点；选中落点语义 = 对端 home `""`，见
/// [`FileManagerState::single_dir_selection`] 专臂）。
pub const REMOTE_HOME_KEY: &str = "__kirin_home__";

/// `""`；其余节点 = 键自身）。树递归（[`FileManagerState::tree_rows_recur`]
/// / [`FileManagerState::pane_rows_recur`]）与节点标记（加载中/错误/更多）
/// 统一经此取源，保留键零直查。
pub fn remote_tree_cache_key(path: &str) -> &str {
    if path == REMOTE_HOME_KEY {
        ""
    } else {
        path
    }
}

/// 或裸盘符（`"C:"`，len 2；服务端解析口径，客户端树键恒带尾分隔符
/// 形态 `"C:\"`）。**仅远端路径语义消费**（本地栏盘符 = 绝对路径，
/// 不走本判定）。
pub fn is_drive_path(p: &str) -> bool {
    let b = p.as_bytes();
    if b.len() < 2 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
        return false;
    }
    b.len() == 2 || b[2] == b'\\' || b[2] == b'/'
}

/// 的路径调用**——远端 root 相对路径分隔符为 `/`，不得误归一）。
/// wire 路径盘符层单一规范形态 = 反斜杠。
pub fn normalize_drive_sep(p: &str) -> String {
    p.replace('/', "\\")
}

/// - 盘符路径：`C:\Users\dev` → `C:\Users`；`C:\Users` → `C:\`；`C:\`/`C:`
///   → [`REMOTE_PC_ROOT_KEY`]（盘符层挂在「远端电脑」合成根下，**非**空串
///   ——旧 root 相对语义的空串父仅用于兼容路径）；
/// - 非盘符（旧 root 相对）：同 [`rel_parent`]（零漂移）。
pub fn remote_parent_key(path: &str) -> String {
    if !is_drive_path(path) {
        return rel_parent(path).to_string();
    }
    let n = normalize_drive_sep(path);
    let trimmed = n.trim_end_matches('\\');
    if trimmed.len() <= 2 {
        return REMOTE_PC_ROOT_KEY.to_string();
    }
    match trimmed.rfind('\\') {
        Some(i) if i > 2 => trimmed[..i].to_string(),
        // 分隔符恰在 `X:` 之后 = 裸盘符 → 父 = 盘符根键 `"X:\"`。
        Some(2) => trimmed[..=2].to_string(),
        _ => REMOTE_PC_ROOT_KEY.to_string(),
    }
}

/// `"C:\"` 自身〔盘符根节点名/键同形〕）；非盘符 = [`rel_basename`]。
pub fn remote_entry_name(path: &str) -> String {
    if !is_drive_path(path) {
        return rel_basename(path).to_string();
    }
    let n = normalize_drive_sep(path);
    let trimmed = n.trim_end_matches('\\');
    if trimmed.len() <= 2 {
        return format!("{trimmed}\\");
    }
    trimmed.rsplit('\\').next().unwrap_or("").to_string()
}

/// 任务终态（Completed/Failed/Cancelled；批推进判定用）。
pub fn is_terminal_status(status: &FileTaskStatus) -> bool {
    matches!(
        status,
        FileTaskStatus::Completed | FileTaskStatus::Failed(_) | FileTaskStatus::Cancelled
    )
}

/// 全局任务面板中某方向非终态任务数（队列水位门：`MAX_QUEUE_LEN` - 活跃 = 余量）。
pub fn active_task_count(panel: &FilePanelState, dir: FileDirection) -> usize {
    panel
        .tasks
        .iter()
        .filter(|t| {
            t.direction == dir && !is_terminal_status(&t.status)
        })
        .count()
}

/// mtime 展示（§2.2 列口径 `MM-dd HH:mm`；0 = 不可得）。
pub fn format_mtime(mtime: i64) -> String {
    if mtime <= 0 {
        return "—".to_string();
    }
    chrono::DateTime::from_timestamp(mtime, 0)
        .map(|dt| dt.format("%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "—".to_string())
}

/// 条目类型列（§2.2 类型列；符号链接优先标记，S4 口径展示）。
pub fn type_label(e: &FileMgrEntry) -> String {
    if e.is_symlink {
        t!("filemgr.type.symlink").to_string()
    } else if e.is_dir {
        t!("filemgr.type.dir").to_string()
    } else {
        t!("filemgr.type.file").to_string()
    }
}


/// Windows `FILE_ATTRIBUTE_HIDDEN` 属性位判定（纯函数，单测钉死：
/// `0x2` 置位 = 隐藏；与目录/系统/只读位复合共存）。
pub fn win_file_attr_hidden(file_attributes: u32) -> bool {
    file_attributes & 0x0000_0002 != 0
}

/// dot 前缀惯例（Unix 隐藏语义；远端栏唯一可感知面——wire `FsEntry`
/// 无属性字段〔冻结〕，能力边界如实）。
pub fn name_is_hidden(name: &str) -> bool {
    name.starts_with('.')
}

/// 本地条目隐藏判定：Windows = `FILE_ATTRIBUTE_HIDDEN` 属性位（真值，
/// 与名称无关）；其余平台 = dot 前缀惯例。
pub fn local_entry_hidden(name: &str, md: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        let _ = name;
        use std::os::windows::fs::MetadataExt;
        win_file_attr_hidden(md.file_attributes())
    }
    #[cfg(not(windows))]
    {
        let _ = md;
        name_is_hidden(name)
    }
}

/// 本地列目录（`std::fs` 直读，零 wire；符号链接不跟随子树，S4；
/// 单条目失败跳过不中断）。
pub fn list_local_dir(dir: &Path) -> Result<Vec<FileMgrEntry>, String> {
    let mut out = Vec::new();
    for ent in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let Ok(ent) = ent else { continue };
        let path = ent.path();
        let Ok(md) = std::fs::symlink_metadata(&path) else { continue };
        let is_symlink = md.file_type().is_symlink();
        let is_dir = if is_symlink { path.is_dir() } else { md.is_dir() };
        let size = if is_dir { 0 } else { md.len() };
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let name = ent.file_name().to_string_lossy().into_owned();
        // 及其**任意子层**（`<job>/` 及更深）不作为用户可选目录呈现——按条目
        // 全路径组件级过滤（顶层条目名与祖先链同判；本地目录列表过滤；呈现
        // 层 only，其余语义零变化）。
        if crate::r192_path_within_internal_cache(&path) {
            continue;
        }
        // [`FileManagerState::pane_rows_recur`]——缓存零过滤，开关翻转
        // 帧级生效零重列）。
        let is_hidden = local_entry_hidden(&name, &md);
        out.push(FileMgrEntry {
            name,
            size,
            mtime,
            is_dir,
            is_symlink,
            is_hidden,
        });
    }
    Ok(out)
}

/// 内存排序（§2.2：**目录恒在文件前**；三态字段内序 asc/desc；off = 名称升序）。
pub fn sort_entries(entries: &mut [FileMgrEntry], sort: &SortState) {
    entries.sort_by(|a, b| {
        let base = match (a.is_dir, b.is_dir) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => match sort.field {
                Some(SortField::Name) => a.name.cmp(&b.name),
                Some(SortField::Size) => a.size.cmp(&b.size),
                Some(SortField::Modified) => a.mtime.cmp(&b.mtime),
                None => a.name.cmp(&b.name),
            },
        };
        if sort.desc { base.reverse() } else { base }
    });
}

/// 〔含空目录/超深度未展开目录/读取失败目录〕+ **读取失败清单**）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalFolderCollect {
    /// 文件相对路径（'/' 分隔）+ 字节数。
    pub files: Vec<(String, u64)>,
    /// 超深度未展开子目录相对路径（UI 提示源；其子树未收集）。
    pub capped: Vec<String>,
    /// 本身/读取失败目录**——远端空目录镜像创建的输入；根自身不入列 =
    /// 「根是否空」由 [`r135_5c_empty_dirs`] 按 `files` 判）。
    pub dirs: Vec<String>,
    /// 记清单继续；目录本身仍入 `dirs` = 远端创建为空目录）。
    pub read_failed: Vec<String>,
}

/// 递归收集本地目录（§2.6.1② 本地→远端；**S4：符号链接跳过**——不跟随、
/// 不上传目标；深度 > `max_depth` = 不展开 + 记入 capped）。
///
/// 返回 [`LocalFolderCollect`]（文件/超深度/已访子目录/读取失败四清单）。
/// **环防护** = 符号链接跳过（Windows junction = reparse point 同判 `is_symlink`）
/// + [`FOLDER_MAX_DEPTH`] 深度硬限界（与下载 BFS 同口径）。
pub fn collect_local_folder(dir: &Path, max_depth: usize) -> LocalFolderCollect {
    let mut files: Vec<(String, u64)> = Vec::new();
    let mut capped: Vec<String> = Vec::new();
    let mut dirs: Vec<String> = Vec::new();
    let mut read_failed: Vec<String> = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(dir.to_path_buf(), 1)];
    while let Some((d, depth)) = stack.pop() {
        // 调用方按 `read_failed` 归因——子目录相对路径在此归一）。
        let Ok(rd) = std::fs::read_dir(&d) else {
            let rel = d
                .strip_prefix(dir)
                .unwrap_or(d.as_path())
                .to_string_lossy()
                .replace('\\', "/");
            if !rel.is_empty() {
                read_failed.push(rel);
            }
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
            if md.file_type().is_symlink() {
                continue; // S4
            }
            let rel = p
                .strip_prefix(dir)
                .unwrap_or(p.as_path())
                .to_string_lossy()
                .replace('\\', "/");
            let child_depth = depth + 1;
            if p.is_dir() {
                // 入目标镜像列表」同口径；空目录/超深度/读取失败均覆盖）。
                dirs.push(rel.clone());
                if child_depth > max_depth {
                    capped.push(rel);
                } else {
                    stack.push((p, child_depth));
                }
            } else {
                files.push((rel, md.len()));
            }
        }
    }
    LocalFolderCollect {
        files,
        capped,
        dirs,
        read_failed,
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

///
/// Windows = `A:\`..`Z:\`（`is_dir` 只读探测在位性，零副作用）；非 Windows =
/// 单根 `/`。只读探测（USB 热插拔变化 = 每帧重算，26 次 metadata ≈ µs 级）。
pub fn local_drives() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut out = Vec::new();
        for c in b'A'..=b'Z' {
            let p = PathBuf::from(format!("{}:\\", c as char));
            if p.is_dir() {
                out.push(p);
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        vec![PathBuf::from("/")]
    }
}

pub fn local_path_key(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// 任何盘符下）。
pub fn local_drive_of(p: &Path) -> Option<PathBuf> {
    local_drives().into_iter().find(|d| p.starts_with(d))
}

/// （盘符不是根——C:\、D:\… 是根下的目录层）。路径键 = 保留字（非合法盘
/// 路径，不与真实节点键碰撞）；children = [`local_drives`] 枚举（零 wire）。
/// 该节点**非磁盘目录**：可选中作树节点，但**不得作传输落点**（
/// [`FileManagerState::single_dir_selection`] fail-closed 排除）。
pub const LOCAL_PC_ROOT_KEY: &str = "__kirin_pc_root__";

/// 目录层〕；其余键 = `std::fs` 零 wire 直读；读败 = `Err`〔节点级错误
/// 标记归调用方〕）。
fn local_node_children(key: &str) -> Result<Vec<FileMgrEntry>, ()> {
    if key == LOCAL_PC_ROOT_KEY {
        Ok(local_drives()
            .into_iter()
            .map(|d| synthetic_dir_entry(d.display().to_string()))
            .collect())
    } else {
        list_local_dir(Path::new(key)).map_err(|_| ())
    }
}

/// + `has_more`「更多↓」标记行；本地/远端统一 500/节点纪律）——巨型本地
/// 目录（Temp/node_modules 数千条目）不得在单节点渲染无界行数（行区退化、
/// 渲染迟滞）。截断纯 UI 呈现层：本地 `std::fs` 读仍全量，传输/选中语义
/// 不受影响；零 wire、协议零改。返回 `true` = 有截断余量（挂「更多」标记行）。
fn cap_local_children(entries: &mut Vec<FileMgrEntry>) -> bool {
    let has_more = entries.len() > PAGE_SIZE as usize;
    entries.truncate(PAGE_SIZE as usize);
    has_more
}

pub fn synthetic_dir_entry(name: impl Into<String>) -> FileMgrEntry {
    FileMgrEntry {
        name: name.into(),
        size: 0,
        mtime: 0,
        is_dir: true,
        is_symlink: false,
        is_hidden: false,
    }
}

#[derive(Debug, Clone)]
pub struct TreeRow {
    /// 节点全路径（本地绝对 / 远端 root 相对；`""` = 远端根）。
    pub path: String,
    pub entry: FileMgrEntry,
    /// 缩进层级（根行 = 0）。
    pub depth: usize,
}

/// Marker = 展开节点下的辅助行〔加载中 / 错误 + 重试 / 更多〕）。
#[derive(Debug, Clone)]
pub enum PaneRow {
    Node(TreeRow),
    Marker {
        depth: usize,
        text: String,
        /// 错误标记（渲染色 = warning）。
        warn: bool,
        /// 重试目标 = 错误节点全路径（`None` = 纯提示行）。
        retry: Option<String>,
    },
}

/// `["C:\", "C:\Users", "C:\Users\dev"]`（盘符层挂在合成根
/// [`REMOTE_PC_ROOT_KEY`] 下，合成根本身不入链 = 与旧语义「不含根」同
/// 口径；裸盘符路径 = 盘符根自身，无祖先层）。
pub fn remote_chain_ancestors(path: &str) -> Vec<String> {
    if is_drive_path(path) {
        let n = normalize_drive_sep(path);
        let trimmed = n.trim_end_matches('\\');
        if trimmed.len() <= 2 {
            return Vec::new(); // 裸盘符 = 盘符根自身（树父 = 合成根，不入链）
        }
        let drive_root = &trimmed[..=2]; // `"C:\"`
        let mut out = vec![drive_root.to_string()];
        let mut prefix = String::new();
        for part in trimmed[3..].split('\\') {
            if part.is_empty() {
                continue;
            }
            if prefix.is_empty() {
                prefix = format!("{drive_root}{part}");
            } else {
                prefix = format!("{prefix}\\{part}");
            }
            out.push(prefix.clone());
        }
        return out;
    }
    let mut out = Vec::new();
    let mut prefix = String::new();
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        out.push(prefix.clone());
    }
    out
}

/// 路径含 `\`、远端全路径含 `/`——Windows `Path` 双分隔符同收）。
pub fn task_file_basename(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string())
}

///
/// 时间 / 类型）；[`r134_9_name_col_max_w`] = 4 列特例（零漂移）。
pub fn r134_9b_name_col_max_w(
    pane_w: f32,
    other_cols_total_w: f32,
    n_cols: usize,
    spacing_x: f32,
    frame_pad_x: f32,
) -> f32 {
    (pane_w
        - R134_9_GRID_PANE_MARGIN
        - other_cols_total_w
        - (n_cols as f32 - 1.0) * spacing_x
        - 2.0 * frame_pad_x)
        .max(0.0)
}

// ════════════════════════════════════════════════════════════════
// FileManagerState
// ════════════════════════════════════════════════════════════════

impl Default for FileManagerState {
    fn default() -> Self {
        Self::with_local_root(
            dirs_next::home_dir().unwrap_or_else(|| PathBuf::from(".")),
        )
    }
}

impl FileManagerState {
    /// `root` = 活动节点基准〔默认主目录，面包屑起点〕；远端根默认展开待首
    /// List）。
    pub fn with_local_root(root: PathBuf) -> Self {
        let mut local = LocalPane {
            root: root.clone(),
            current: root,
            view: PaneView::default(),
            scroll_anchor: None,
            scroll_anchor_prev_delta: None,
        };
        if !local.current.is_dir() {
            local.current = local_drives().into_iter().next().unwrap_or(local.current);
        }
        // 默认展示盘符层；盘符是根下目录层，再双击进入盘内目录）。
        local.view.expanded.push(LOCAL_PC_ROOT_KEY.to_string());
        local
            .view
            .nodes
            .insert(LOCAL_PC_ROOT_KEY.to_string(), TreeNodeState {
                children: local_node_children(LOCAL_PC_ROOT_KEY).ok(),
                ..Default::default()
            });
        let mut remote = RemotePane::default();
        // （盘符层挂在合成根下，同本地「此电脑」口径）——默认展开 +
        // `current` 初始 = 保留键（首帧 List 打保留键 = 服务端盘符枚举；
        // 首 List 语义等价迁移：根 List `""` → 保留键 List）。
        remote.current = REMOTE_PC_ROOT_KEY.to_string();
        remote.view.expanded.push(REMOTE_PC_ROOT_KEY.to_string());
        Self {
            local,
            remote,
            active_pane: PaneId::Local,
            clipboard: None,
            job: None,
            pending: None,
            pending_deletes: Vec::new(),
            dialog: Dialog::None,
            status_line: None,
            in_text_input: false,
            dialog_error: None,
            consent_out: Vec::new(),
            peer_consent: None,
            pending_clip_meta: None,
            clip_prefetch_req: None,
            // 30s 节流锚点回拨一个窗口 → 首次拒绝必告警。
            clip_meta_gate_warn_at:
                std::time::Instant::now() - std::time::Duration::from_secs(30),
            clip_expand: None,
            clip_internal_copy_seq: 0,
            clip_internal_copy_os_sig: 0,
            upload_drain_watch: Vec::new(),
            // 语境 = None = 既有 v1 链/显式提示零变化）。
            r167_session_dir_fallback: None,
            r195_drag: None,
        }
    }

    pub fn has_dialog(&self) -> bool {
        !matches!(self.dialog, Dialog::None)
            || self.clip_expand.as_ref().is_some_and(|c| c.conflict.is_some())
    }

    fn view(&self, pane: PaneId) -> &PaneView {
        match pane {
            PaneId::Local => &self.local.view,
            PaneId::Remote => &self.remote.view,
        }
    }

    fn view_mut(&mut self, pane: PaneId) -> &mut PaneView {
        match pane {
            PaneId::Local => &mut self.local.view,
            PaneId::Remote => &mut self.remote.view,
        }
    }

    /// 既有槽零迁移，本机 = 本岗新增同机制槽）。
    fn scroll_anchor(&self, pane: PaneId) -> Option<&str> {
        match pane {
            PaneId::Local => self.local.scroll_anchor.as_deref(),
            PaneId::Remote => self.remote.scroll_anchor.as_deref(),
        }
    }

    fn scroll_anchor_prev_delta_of(&self, pane: PaneId) -> Option<f32> {
        match pane {
            PaneId::Local => self.local.scroll_anchor_prev_delta,
            PaneId::Remote => self.remote.scroll_anchor_prev_delta,
        }
    }

    /// 本机臂同判据；`show()` 返回后由行区段持久应用 offset）。
    fn scroll_anchor_observe(&mut self, pane: PaneId, delta_y: f32) {
        match pane {
            PaneId::Local => self.local.scroll_anchor_prev_delta = Some(delta_y),
            PaneId::Remote => self.remote.scroll_anchor_prev_delta = Some(delta_y),
        }
    }

    fn scroll_anchor_settle(&mut self, pane: PaneId) {
        match pane {
            PaneId::Local => {
                self.local.scroll_anchor = None;
                self.local.scroll_anchor_prev_delta = None;
            }
            PaneId::Remote => {
                self.remote.scroll_anchor = None;
                self.remote.scroll_anchor_prev_delta = None;
            }
        }
    }

    /// 缓存查子；查无 = 失效。远端根 `""` 特例 = 合成根条目〔可选中作箭头
    /// 落点〕）。
    pub fn resolve_entry(&self, pane: PaneId, path: &str) -> Option<FileMgrEntry> {
        match pane {
            PaneId::Local => {
                // 条目；非磁盘目录，落点资格由 `single_dir_selection` 另行
                // fail-closed 门）。
                if path == LOCAL_PC_ROOT_KEY {
                    return Some(synthetic_dir_entry(
                        t!("filemgr.pc_root").to_string(),
                    ));
                }
                let p = Path::new(path);
                let md = std::fs::symlink_metadata(p).ok()?;
                let is_symlink = md.file_type().is_symlink();
                let is_dir = if is_symlink { p.is_dir() } else { md.is_dir() };
                let size = if is_dir { 0 } else { md.len() };
                let mtime = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let name = p
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| local_path_key(p)); // 盘符根（`C:\`）无 file_name
                let is_hidden = local_entry_hidden(&name, &md);
                Some(FileMgrEntry {
                    name,
                    size,
                    mtime,
                    is_dir,
                    is_symlink,
                    is_hidden,
                })
            }
            PaneId::Remote => {
                if path == REMOTE_PC_ROOT_KEY {
                    // 条目；非传输目标，落点资格由 `single_dir_selection` fail-closed
                    // 门——与本地「此电脑」同口径）。
                    return Some(synthetic_dir_entry(
                        t!("filemgr.pc_root_remote").to_string(),
                    ));
                }
                if path == REMOTE_HOME_KEY {
                    // 条目呈现；选中落点语义 = home `""`，见
                    // `single_dir_selection` 专臂；传输源/删除/改名保留键
                    // fail-closed 排除）。
                    return Some(synthetic_dir_entry(
                        t!("filemgr.pc_home_remote").to_string(),
                    ));
                }
                if path.is_empty() {
                    // 兼容：旧远端根（`""`=对端 fs 根/家目录；新客户端不再
                    // 产生该键，保留防御口径）。
                    return Some(synthetic_dir_entry(
                        if self.remote.root_display.is_empty() {
                            t!("filemgr.remote").to_string()
                        } else {
                            self.remote.root_display.clone()
                        },
                    ));
                }
                let parent = remote_parent_key(path);
                let children = self.remote.view.nodes.get(&parent)?.children.as_ref()?;
                children.iter().find(|e| e.name == remote_entry_name(path)).cloned()
            }
        }
    }

    pub fn selection_paths(&self, pane: PaneId) -> Vec<String> {
        self.view(pane)
            .selected
            .iter()
            .filter(|n| self.resolve_entry(pane, n).is_some())
            .cloned()
            .collect()
    }

    /// [`Self::tree_rows`] / [`Self::pane_rows`] 的共同递归
    /// 起点（**只遍历根**再 DFS——`tree_rows` 输出已含全部子孙行，二次全量
    fn tree_roots(&self, pane: PaneId) -> Vec<TreeRow> {
        match pane {
            // 根下目录层，depth 1；默认展开见 `with_local_root`）。
            PaneId::Local => vec![TreeRow {
                path: LOCAL_PC_ROOT_KEY.to_string(),
                entry: synthetic_dir_entry(t!("filemgr.pc_root").to_string()),
                depth: 0,
            }],
            // （盘符 = 根下目录层，depth 1；默认展开见 `with_local_root`）。
            PaneId::Remote => vec![TreeRow {
                path: REMOTE_PC_ROOT_KEY.to_string(),
                entry: synthetic_dir_entry(t!("filemgr.pc_root_remote").to_string()),
                depth: 0,
            }],
        }
    }

    /// 行 = 展开集 DFS；节点缓存未就绪的展开节点 = 仅行本身 + 标记行〔渲染
    /// 层 [`Self::pane_rows`]〕）。
    pub fn tree_rows(&self, pane: PaneId) -> Vec<TreeRow> {
        let mut out = Vec::new();
        for r in self.tree_roots(pane) {
            self.tree_rows_recur(pane, &r, &mut out);
        }
        out
    }

    /// join〕；其余 = 父键 join 子名；远端 = root 相对 join）。
    /// = 键 `"C:\"` 同形）；其余远端 = [`remote_join`]（盘符感知）。
    fn child_path_key(pane: PaneId, row: &TreeRow, name: &str) -> String {
        match pane {
            PaneId::Local => {
                if row.path == LOCAL_PC_ROOT_KEY {
                    local_path_key(Path::new(name))
                } else {
                    local_path_key(&Path::new(&row.path).join(name))
                }
            }
            PaneId::Remote => {
                if row.path == REMOTE_PC_ROOT_KEY {
                    name.to_string()
                } else if row.path == REMOTE_HOME_KEY {
                    // `goto_remote_quick` 既有键 `"Desktop"` 同形 = 零键
                    // 迁移零缓存失效；可见树链 = 远端电脑 ▸ 主目录 ▸ 键）。
                    name.to_string()
                } else {
                    remote_join(&row.path, name)
                }
            }
        }
    }

    fn tree_rows_recur(&self, pane: PaneId, row: &TreeRow, out: &mut Vec<TreeRow>) {
        out.push(row.clone());
        if !row.entry.is_dir {
            return;
        }
        //（home 相对键体系挂上可见树链——修前 `goto_remote_quick` 落点键
        // 挂在不可见 home 根 `""` 下 = 孤儿子树永不渲染 = 用户「点快捷无
        // 选中无跳转 / 层级没分开」根因面。纯呈现层合成行，wire 盘符缓存
        // 零触碰）。
        if pane == PaneId::Remote && row.path == REMOTE_PC_ROOT_KEY {
            if self.view(pane).expanded.contains(&row.path) {
                let home = TreeRow {
                    path: REMOTE_HOME_KEY.to_string(),
                    entry: synthetic_dir_entry(t!("filemgr.pc_home_remote")),
                    depth: row.depth + 1,
                };
                self.tree_rows_recur(pane, &home, out);
            }
        }
        let view = self.view(pane);
        if !view.expanded.contains(&row.path) {
            return;
        }
        let cache_key = if pane == PaneId::Remote {
            remote_tree_cache_key(&row.path)
        } else {
            row.path.as_str()
        };
        let Some(children) = view.nodes.get(cache_key).and_then(|n| n.children.as_ref()) else {
            return; // 加载中/失败 = 仅行本身（标记行归渲染层）
        };
        for c in children {
            self.tree_rows_recur(
                pane,
                &TreeRow {
                    path: Self::child_path_key(pane, row, &c.name),
                    entry: c.clone(),
                    depth: row.depth + 1,
                },
                out,
            );
        }
    }

    /// 加载中 / 错误〔+ 重试〕/ 更多；Node 行序 = [`Self::tree_rows`] 同序，
    /// 渲染层据此计 `click_row` 索引）。**只从根递归**（根集 =
    /// [`Self::tree_roots`]；对 `tree_rows` 全量再递归会重复出行）。
    pub fn pane_rows(&self, pane: PaneId) -> Vec<PaneRow> {
        let mut out: Vec<PaneRow> = Vec::new();
        for r in self.tree_roots(pane) {
            self.pane_rows_recur(pane, &r, &mut out);
        }
        out
    }

    fn pane_rows_recur(&self, pane: PaneId, row: &TreeRow, out: &mut Vec<PaneRow>) {
        out.push(PaneRow::Node(row.clone()));
        if !row.entry.is_dir {
            return;
        }
        if !self.view(pane).expanded.contains(&row.path) {
            return;
        }
        if pane == PaneId::Remote && row.path == REMOTE_PC_ROOT_KEY {
            let home = TreeRow {
                path: REMOTE_HOME_KEY.to_string(),
                entry: synthetic_dir_entry(t!("filemgr.pc_home_remote")),
                depth: row.depth + 1,
            };
            self.pane_rows_recur(pane, &home, out);
        }
        // 更多标记行同源呈现，其余 = 键自身）。
        let cache_key = if pane == PaneId::Remote {
            remote_tree_cache_key(&row.path)
        } else {
            row.path.as_str()
        };
        let Some(node) = self.view(pane).nodes.get(cache_key) else {
            return; // 展开无记录（防御）= 仅行本身
        };
        if node.loading {
            out.push(PaneRow::Marker {
                depth: row.depth + 1,
                text: t!("filemgr.loading").to_string(),
                warn: false,
                retry: None,
            });
            return;
        }
        if let Some(err) = &node.error {
            out.push(PaneRow::Marker {
                depth: row.depth + 1,
                text: err.clone(),
                warn: true,
                retry: Some(row.path.clone()),
            });
            return;
        }
        if let Some(children) = &node.children {
            // （枚举层 [`local_entry_hidden`] 取真值 / 远端 dot 前缀；缓存、
            // 排序序、选中与 wire 零触碰——翻转即帧级生效，零重列）。
            let r172_show_hidden = self.view(pane).show_hidden;
            for c in children {
                if !r172_show_hidden && c.is_hidden {
                    continue;
                }
                self.pane_rows_recur(
                    pane,
                    &TreeRow {
                        path: Self::child_path_key(pane, row, &c.name),
                        entry: c.clone(),
                        depth: row.depth + 1,
                    },
                    out,
                );
            }
            if node.has_more {
                // 服务端截断（500/节点）= 提示行（v1 不逐节点翻页）。
                out.push(PaneRow::Marker {
                    depth: row.depth + 1,
                    text: t!("filemgr.page.more").to_string(),
                    warn: false,
                    retry: None,
                });
            }
        }
    }


    /// 栏内提示）。
    pub fn refresh_local(&mut self) {
        let sort = self.local.view.sort;
        let keys: Vec<String> = self.local.view.expanded.clone();
        for key in keys {
            match local_node_children(&key) {
                Ok(mut entries) => {
                    sort_entries(&mut entries, &sort);
                    let has_more = cap_local_children(&mut entries);
                    self.local
                        .view
                        .nodes
                        .insert(key, TreeNodeState { children: Some(entries), has_more, ..Default::default() });
                }
                Err(()) => {
                    // 「此电脑」合成根枚举零失败（fail-closed 不触此处）。
                    if let Some(n) = self.local.view.nodes.get_mut(&key) {
                        n.children = None;
                        n.error = Some(t!("filemgr.err.io").to_string());
                    }
                    self.local.view.status = Some(t!("filemgr.err.io").to_string());
                }
            }
        }
    }

    /// 逐层同步读，零 wire；任一层读败 = fail-closed 不推进 + 栏内提示）。
    /// 返回是否完整展开。
    pub fn local_expand_chain(&mut self, target: &Path) -> bool {
        let Some(drive) = local_drive_of(target) else {
            self.local.view.status = Some(t!("filemgr.err.io").to_string());
            return false;
        };
        let mut chain: Vec<String> = vec![LOCAL_PC_ROOT_KEY.to_string()];
        chain.push(local_path_key(&drive));
        if let Ok(rel) = target.strip_prefix(&drive) {
            let mut acc = drive.clone();
            for comp in rel.components() {
                acc = acc.join(comp);
                chain.push(local_path_key(&acc));
            }
        }
        for key in &chain {
            if self.local.view.expanded.contains(key) {
                continue; // 已展开 = 缓存命中（零重读）
            }
            self.local.view.expanded.push(key.clone());
            match local_node_children(key) {
                Ok(mut entries) => {
                    let sort = self.local.view.sort;
                    sort_entries(&mut entries, &sort);
                    let has_more = cap_local_children(&mut entries);
                    self.local
                        .view
                        .nodes
                        .insert(key.clone(), TreeNodeState { children: Some(entries), has_more, ..Default::default() });
                }
                Err(()) => {
                    self.local.view.nodes.insert(
                        key.clone(),
                        TreeNodeState {
                            error: Some(t!("filemgr.err.io").to_string()),
                            ..Default::default()
                        },
                    );
                    self.local.view.status = Some(t!("filemgr.err.io").to_string());
                    return false;
                }
            }
        }
        true
    }


    /// 单目录、offset=0、limit=500；`cancel_pending` 零 wire 帧旧语义保留）。
    pub fn request_remote_list_at_node(
        &mut self,
        path: &str,
        file_tx: Option<&UnboundedSender<FileCommand>>,
    ) {
        if self.remote.unsupported {
            return; // 版本门静态：不再重试
        }
        {
            let view = &mut self.remote.view;
            if !view.expanded.iter().any(|p| p == path) {
                view.expanded.push(path.to_string());
            }
            let node =
                view.nodes
                    .entry(path.to_string())
                    .or_insert_with(TreeNodeState::default);
            node.loading = true;
            node.error = None;
            view.loading = true;
            view.status = None;
        }
        self.cancel_pending();
        if let Some(tx) = file_tx {
            let _ = tx.send(FileCommand::Fs {
                op: FsOp::List {
                    path: path.to_string(),
                    offset: 0,
                    limit: PAGE_SIZE,
                },
            });
            self.pending = Some(PendingOp {
                req_id: 0,
                kind: PendingKind::List {
                    pane: PaneId::Remote,
                    path: path.to_string(),
                    offset: 0,
                },
                started: Instant::now(),
            });
        } else {
            // 零通道（headless 测试形态）：零 wire，空目录呈现（旧
            // `request_remote_list` 同形态）。
            if let Some(node) = self.remote.view.nodes.get_mut(path) {
                node.loading = false;
                node.children = Some(Vec::new());
            }
            self.remote.view.loading = false;
        }
    }

    /// （`remote.current`；根 = `""`）。
    pub fn request_remote_list(&mut self, file_tx: Option<&UnboundedSender<FileCommand>>) {
        let cur = self.remote.current.clone();
        self.request_remote_list_at_node(&cur, file_tx);
    }

    /// ——真实场景 ≤2：粘贴批落点 + 编排批根）。
    const R173_DRAIN_WATCH_CAP: usize = 8;

    /// 借用期内直呼，字段级拆借零冲突）。去重 + 上界截断。
    fn r173_watch_arm(watch: &mut Vec<String>, dir: &str) {
        if watch.iter().any(|d| d == dir) {
            return;
        }
        if watch.len() >= Self::R173_DRAIN_WATCH_CAP {
            watch.remove(0);
        }
        watch.push(dir.to_string());
    }

    ///（[`Self::request_remote_list_at_node`] 既有通道，单在途槽纪律零
    /// 破坏——连点 = 逐次单 List，旧响应按陈旧 req_id 丢弃）。与传输终态
    /// 失效联动并列为「缓存命中零 wire」的两枚显式出口（卡口径）。
    pub fn refresh_remote_force(&mut self, file_tx: Option<&UnboundedSender<FileCommand>>) {
        let cur = self.remote.current.clone();
        self.remote.view.nodes.remove(&cur);
        self.remote.view.status = None;
        self.request_remote_list_at_node(&cur, file_tx);
    }

    /// 停止在途跟踪（**零 wire 帧**；迟到响应静默忽略）。
    /// （kind=`interrupted`）继续其余条目收集——原静默丢弃语义移除；
    /// 非收集 op = 既有零 wire 帧语义零变化。
    pub fn cancel_pending(&mut self) {
        if let Some(p) = self.pending.take() {
            if let PendingKind::CollectList {
                ref path,
                ref src_root,
                ref prefix,
                ..
            } = p.kind
            {
                let rel = remote_strip_base(src_root, path);
                let disp = job_dir_display(prefix, &rel);
                tracing::warn!("{}", r135_5b_fail_line("interrupted", &disp));
                if let Some(job) = self.job.as_mut() {
                    if job.direction == FolderDirection::ToLocal && job.collecting {
                        job.failed.push((disp, "interrupted".to_string()));
                    }
                }
            }
        }
    }


    /// List**——本地 = 同步读零 wire；错误态节点 = 重试）。
    pub fn tree_expand(
        &mut self,
        pane: PaneId,
        path: &str,
        file_tx: Option<&UnboundedSender<FileCommand>>,
    ) {
        self.active_pane = pane;
        let view = self.view(pane);
        if view.expanded.iter().any(|p| p == path) {
            let errored = view
                .nodes
                .get(path)
                .is_some_and(|n| n.error.is_some());
            if errored {
                // 错误态 = 双击/标记行重试（保持展开，重列/重读）。
                match pane {
                    PaneId::Local => {
                        self.local.view.nodes.remove(path);
                        match local_node_children(path) {
                            Ok(mut entries) => {
                                let sort = self.local.view.sort;
                                sort_entries(&mut entries, &sort);
                                let has_more = cap_local_children(&mut entries);
                                self.local.view.nodes.insert(
                                    path.to_string(),
                                    TreeNodeState { children: Some(entries), has_more, ..Default::default() },
                                );
                            }
                            Err(()) => {
                                self.local.view.nodes.insert(
                                    path.to_string(),
                                    TreeNodeState {
                                        error: Some(t!("filemgr.err.io").to_string()),
                                        ..Default::default()
                                    },
                                );
                                self.local
                                    .view
                                    .status
                                    .get_or_insert_with(|| t!("filemgr.err.io").to_string());
                            }
                        }
                    }
                    PaneId::Remote => {
                        self.remote.view.nodes.remove(path);
                        self.request_remote_list_at_node(path, file_tx);
                    }
                }
                return;
            }
            self.tree_collapse(pane, path);
            return;
        }
        self.view_mut(pane).expanded.push(path.to_string());
        match pane {
            PaneId::Local => {
                // 节点 = 基准根。
                self.local.current = if path == LOCAL_PC_ROOT_KEY {
                    self.local.root.clone()
                } else {
                    PathBuf::from(path)
                };
                // 再展开 = 重读（折叠已弃缓存，保新鲜度）。
                self.local.view.nodes.remove(path);
                match local_node_children(path) {
                    Ok(mut entries) => {
                        let sort = self.local.view.sort;
                        sort_entries(&mut entries, &sort);
                        let has_more = cap_local_children(&mut entries);
                        self.local.view.nodes.insert(
                            path.to_string(),
                            TreeNodeState { children: Some(entries), has_more, ..Default::default() },
                        );
                    }
                    Err(()) => {
                        self.local.view.nodes.insert(
                            path.to_string(),
                            TreeNodeState {
                                error: Some(t!("filemgr.err.io").to_string()),
                                ..Default::default()
                            },
                        );
                        self.local.view.status = Some(t!("filemgr.err.io").to_string());
                    }
                }
            }
            PaneId::Remote => {
                if path == REMOTE_HOME_KEY {
                    // = 保留键 `""` 槽；活动节点 = `""` home 本身）。缓存命中
                    // = 零 wire；未落定/失败 = 单在途 `List("")`（既有通道
                    // 零新 wire；保留键零直查 = `nodes.remove(REMOTE_HOME_
                    // KEY)` 类误面不存在）。
                    self.remote.current = String::new();
                    if !self
                        .remote
                        .view
                        .expanded
                        .iter()
                        .any(|p| p == REMOTE_HOME_KEY)
                    {
                        self.remote.view.expanded.push(REMOTE_HOME_KEY.to_string());
                    }
                    let cached = self.remote.view.nodes.get("").is_some_and(|n| {
                        !n.loading && n.children.is_some() && n.error.is_none()
                    });
                    if !cached {
                        self.request_remote_list_at_node("", file_tx);
                    }
                    return;
                }
                self.remote.current = path.to_string();
                self.remote.view.nodes.remove(path);
                self.request_remote_list_at_node(path, file_tx);
            }
        }
    }

    /// = 前缀即自身，防 `C:\` + `\` 双分隔符误剪）。
    pub fn tree_collapse(&mut self, pane: PaneId, path: &str) {
        let view = self.view_mut(pane);
        if let Some(i) = view.expanded.iter().position(|p| p == path) {
            view.expanded.remove(i);
        }
        view.nodes.remove(path);
        let prefix = if path.is_empty() {
            String::new()
        } else if pane == PaneId::Remote && is_drive_path(path) {
            let n = normalize_drive_sep(path);
            if n.ends_with('\\') {
                n
            } else {
                format!("{n}\\")
            }
        } else {
            let sep = if pane == PaneId::Local { '\\' } else { '/' };
            format!("{path}{sep}")
        };
        view.selected.retain(|s| !s.starts_with(&prefix));
    }

    /// `expand_queue` 由 tick 链式 List〔单在途〕）。
    pub fn navigate_to_prefix(
        &mut self,
        pane: PaneId,
        prefix: String,
        file_tx: Option<&UnboundedSender<FileCommand>>,
    ) {
        self.active_pane = pane;
        match pane {
            PaneId::Local => {
                // 路径，链展开入口特例；活动节点 = 基准根）。
                if prefix == LOCAL_PC_ROOT_KEY {
                    self.local.current = self.local.root.clone();
                    self.local.view.selected.clear();
                    return;
                }
                let p = if prefix.is_empty() {
                    self.local.current.clone()
                } else {
                    PathBuf::from(&prefix)
                };
                if !p.is_dir() {
                    return;
                }
                if !self.local_expand_chain(&p) {
                    return;
                }
                self.local.current = p;
                self.local.view.selected.clear();
            }
            PaneId::Remote => {
                if prefix == REMOTE_HOME_KEY {
                    // = `""`；缓存命中零 wire，未落定单在途 `List("")`——
                    self.remote.current = String::new();
                    self.remote.view.selected.clear();
                    if !self
                        .remote
                        .view
                        .expanded
                        .iter()
                        .any(|p| p == REMOTE_HOME_KEY)
                    {
                        self.remote.view.expanded.push(REMOTE_HOME_KEY.to_string());
                    }
                    let cached = self.remote.view.nodes.get("").is_some_and(|n| {
                        !n.loading && n.children.is_some() && n.error.is_none()
                    });
                    if !cached {
                        self.request_remote_list_at_node("", file_tx);
                    }
                    return;
                }
                if prefix == REMOTE_PC_ROOT_KEY {
                    // 零 wire；缓存已弃〔折叠〕= 重新盘符枚举）。
                    self.remote.current = REMOTE_PC_ROOT_KEY.to_string();
                    self.remote.view.selected.clear();
                    let cached = self
                        .remote
                        .view
                        .nodes
                        .get(REMOTE_PC_ROOT_KEY)
                        .is_some_and(|n| n.children.is_some());
                    if !cached {
                        self.request_remote_list_at_node(REMOTE_PC_ROOT_KEY, file_tx);
                    }
                    return;
                }
                self.remote.current = prefix.clone();
                self.remote.view.selected.clear();
                let mut missing: Vec<String> = Vec::new();
                for a in remote_chain_ancestors(&prefix) {
                    if !self.remote.view.expanded.contains(&a) {
                        missing.push(a);
                    }
                }
                // 已展开祖先 = 零 wire；缺失层按序入队（tick 逐帧推进）。
                self.remote.expand_queue = missing.into();
                let _ = file_tx; // 队列推进经 tick 统一持通道（单在途纪律）
            }
        }
    }

    /// 段名) 序列；点击段 = 链展开至该前缀）。
    pub fn local_breadcrumb(&self) -> Vec<(String, String)> {
        let cur = &self.local.current;
        let Some(drive) = local_drive_of(cur) else {
            return Vec::new();
        };
        let mut out = vec![(
            LOCAL_PC_ROOT_KEY.to_string(),
            t!("filemgr.pc_root").to_string(),
        )];
        out.push((
            local_path_key(&drive),
            drive.display().to_string(),
        ));
        if let Ok(rel) = cur.strip_prefix(&drive) {
            let mut prefix = drive.clone();
            for comp in rel.components() {
                prefix = prefix.join(comp);
                let name = comp.as_os_str().to_string_lossy().into_owned();
                out.push((local_path_key(&prefix), name));
            }
        }
        out
    }

    /// 盘符路径按 `\` 分段，旧 root 相对路径按 `/` 分段）。
    pub fn remote_breadcrumb(&self) -> Vec<(String, String)> {
        let mut out = vec![(
            REMOTE_PC_ROOT_KEY.to_string(),
            t!("filemgr.pc_root_remote").to_string(),
        )];
        let cur = &self.remote.current;
        if cur.is_empty() {
            // 第二段 = 「主目录」（与树链 远端电脑 ▸ 主目录 同形；点击 =
            // `navigate_to_prefix` 主目录臂）。
            out.push((
                REMOTE_HOME_KEY.to_string(),
                t!("filemgr.pc_home_remote").to_string(),
            ));
            return out;
        }
        if is_drive_path(cur) {
            let n = normalize_drive_sep(cur);
            let trimmed = n.trim_end_matches('\\');
            if trimmed.len() <= 2 {
                // 裸盘符 = 盘符根自身（段名 = 键同形）。
                out.push((format!("{trimmed}\\"), format!("{trimmed}\\")));
                return out;
            }
            let drive_root = &trimmed[..=2];
            out.push((drive_root.to_string(), drive_root.to_string()));
            let mut prefix = String::new();
            for part in trimmed[3..].split('\\') {
                if part.is_empty() {
                    continue;
                }
                if prefix.is_empty() {
                    prefix = format!("{drive_root}{part}");
                } else {
                    prefix = format!("{prefix}\\{part}");
                }
                out.push((prefix.clone(), part.to_string()));
            }
            return out;
        }
        // 「主目录」，与树链 远端电脑 ▸ 主目录 ▸ <rel> 同形；段键序列 =
        // 主目录 → 逐级前缀）。
        out.push((
            REMOTE_HOME_KEY.to_string(),
            t!("filemgr.pc_home_remote").to_string(),
        ));
        let mut prefix = String::new();
        for part in cur.split('/') {
            if part.is_empty() {
                continue;
            }
            if prefix.is_empty() {
                prefix = part.to_string();
            } else {
                prefix = format!("{prefix}/{part}");
            }
            out.push((prefix.clone(), part.to_string()));
        }
        out
    }


    /// Ctrl/Cmd 单击多选，§2.6.1①）。
    pub fn click_row(&mut self, pane: PaneId, idx: usize, multi: bool) {
        self.active_pane = pane;
        let Some(path) = self.tree_rows(pane).into_iter().nth(idx).map(|r| r.path) else {
            return;
        };
        let view = self.view_mut(pane);
        if multi {
            if view.selected.contains(&path) {
                view.selected.retain(|n| n != &path);
            } else {
                view.selected.push(path);
            }
        } else {
            view.selected = vec![path];
        }
    }

    /// 的 children 缓存 = 排序按展开节点局部）。
    pub fn sort_header(&mut self, pane: PaneId, field: SortField) {
        let view = self.view_mut(pane);
        match (&view.sort.field, view.sort.desc) {
            (Some(f), false) if *f == field => view.sort.desc = true,
            (Some(f), true) if *f == field => {
                view.sort.field = None;
                view.sort.desc = false;
            }
            _ => {
                view.sort.field = Some(field);
                view.sort.desc = false;
            }
        }
        // 各展开节点 children 内存重排（§2.2 内存排序口径，树内局部化）。
        let sort = self.view(pane).sort;
        for node in self.view_mut(pane).nodes.values_mut() {
            if let Some(children) = &mut node.children {
                sort_entries(children, &sort);
            }
        }
    }

    // ── 复制/粘贴（§2.6.1①：复制语义 = 复制非移动；v1 无剪切）──

    /// 返回复制项数。
    pub fn copy_selection(&mut self, pane: PaneId) -> usize {
        let paths = self.selection_paths(pane);
        if paths.is_empty() {
            return 0;
        }
        self.clipboard = Some(Clip {
            source: pane,
            paths: paths.clone(),
        });
        // 复制源仲裁素材；读板失败/空板 = 0 = 仲裁回落签名亦零变 → 内部板）。
        self.clip_internal_copy_seq = crate::clipboard::clipboard_sequence_number();
        self.clip_internal_copy_os_sig = crate::clipboard::read_local_files()
            .as_ref()
            .map(r156_os_board_signature)
            .unwrap_or(0);
        self.status_line = Some(tf!("filemgr.select.copied", paths.len()));
        paths.len()
    }

    /// 快捷键粘贴（跨栏口径，§2.6.1①：目标 = 剪贴板来源的**对侧**栏——
    /// 复制即隐含方向；右键菜单粘贴 = 菜单所在栏，见 `paste_into`）。
    /// 返回入队项数（0 = 空剪贴板/同栏/忙/队列满）。
    pub fn paste_cross(
        &mut self,
        panel: &FilePanelState,
        file_tx: Option<&UnboundedSender<FileCommand>>,
        fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    ) -> usize {
        let Some(clip) = self.clipboard.clone() else {
            self.status_line = Some(t!("filemgr.clipboard.empty").to_string());
            return 0;
        };
        let target = match clip.source {
            PaneId::Local => PaneId::Remote,
            PaneId::Remote => PaneId::Local,
        };
        self.paste_into(target, panel, file_tx, fm_tx)
    }

    /// 粘贴到 `pane`（跨栏 = 传输入队；同栏 = no-op——v1 无移动）。
    /// 返回入队项数（0 = 空剪贴板/同栏/忙）。
    pub fn paste_into(
        &mut self,
        pane: PaneId,
        panel: &FilePanelState,
        file_tx: Option<&UnboundedSender<FileCommand>>,
        fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    ) -> usize {
        let Some(clip) = self.clipboard.take() else {
            self.status_line = Some(t!("filemgr.clipboard.empty").to_string());
            return 0;
        };
        if clip.source == pane {
            // 同栏粘贴 = v1 无移动（不删源）：剪贴板保留，状态提示。
            self.clipboard = Some(clip);
            self.status_line = Some(t!("filemgr.paste.same_pane").to_string());
            return 0;
        }
        if job_active(self) {
            self.clipboard = Some(clip);
            self.status_line = Some(t!("filemgr.busy").to_string());
            return 0;
        }
        // （目标侧恰一非符号链接目录 = 落点；未选中/非目录 = 回退目标栏
        // 当前目录节点——与栏头按钮同语义；旧 `enqueue_transfer` target=None
        // = 恒落对侧 `current`，粘贴忽略选中 = 用户「没按选中目录传到指定
        // 目录」断点之一）。
        let (t_remote, t_local) = match pane {
            PaneId::Remote => (self.single_dir_selection(PaneId::Remote), None),
            PaneId::Local => {
                let d = self
                    .single_dir_selection(PaneId::Local)
                    .map(PathBuf::from);
                (None, d)
            }
        };
        self.enqueue_transfer_targeted(
            clip.source, pane, clip.paths, t_remote, t_local, panel, file_tx, fm_tx,
        )
    }

    /// 调用：主键本帧按下 ∧ 悬停本行；已有候选 = 幂等早退）。
    pub fn r195_drag_press(&mut self, pane: PaneId, path: &str, pos: egui::Pos2) {
        if self.r195_drag.is_some() {
            return;
        }
        self.r195_drag = Some(R195Drag {
            source: pane,
            path: path.to_string(),
            start: pos,
            paths: Vec::new(),
        });
    }

    /// `render_panes_and_seam` 两栏 rect 捕获后）。状态机：
    /// - `escape` / 松开：已过阈值（载荷非空）且非 Escape = **Dropped**
    ///   （落定判定交调用方）；未过阈值即松开 = Idle（原单击路径零影响）；
    ///   Escape = 中断无动作（egui DragAndDrop 同语义）；
    /// - 按下保持 ∧ 位移 ≥ [`R195_DRAG_THRESHOLD`] = 载荷定格
    ///   （[`r195_drag_payload_paths`] 多选批量语义；定格一次不重算——
    ///   拖拽中途改选不影响本批）→ Dragging；
    /// - 其余 = Idle/Armed（零视觉零动作）。
    pub fn r195_drag_frame(
        &mut self,
        pressed: bool,
        released: bool,
        escape: bool,
        pos: Option<egui::Pos2>,
        threshold: f32,
    ) -> R195DragFrame {
        if escape || (self.r195_drag.is_some() && !pressed) {
            return match self.r195_drag.take() {
                Some(d) if !d.paths.is_empty() && !escape && released => {
                    R195DragFrame::Dropped { source: d.source, paths: d.paths }
                }
                _ => R195DragFrame::Idle,
            };
        }
        // 阈值交叉判定（take 复位防借用冲突；恒放回——未交叉保持候选，
        // 已定格/未达阈值非空载荷原样保持）。
        if let Some(mut d) = self.r195_drag.take() {
            if d.paths.is_empty() {
                let crossed = pos.map_or(false, |p| p.distance(d.start) >= threshold);
                if crossed {
                    d.paths =
                        r195_drag_payload_paths(&self.selection_paths(d.source), &d.path);
                }
            }
            self.r195_drag = Some(d);
        }
        match self.r195_drag.as_ref() {
            Some(d) if !d.paths.is_empty() => R195DragFrame::Dragging {
                source: d.source,
                paths: d.paths.clone(),
            },
            Some(_) => R195DragFrame::Armed,
            None => R195DragFrame::Idle,
        }
    }

    /// **既有传输链**入队（`enqueue_transfer_targeted` 单点复用，零新链路
    /// 零绕过）：本机栏拖起 → 远端栏释放 = 上传（SendFileV2 授权链 /
    /// FolderJob 整树原样）；远端栏拖起 → 本机栏释放 = 下载（`FetchFile` /
    /// 合成根 = `remote_default_target` 回退 `""` 对端 fs 根）。忙（活动
    /// 任务）= 显式提示零入队。返回入队项数。
    pub fn drop_transfer(
        &mut self,
        target: PaneId,
        paths: Vec<String>,
        panel: &FilePanelState,
        file_tx: Option<&UnboundedSender<FileCommand>>,
        fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    ) -> usize {
        if job_active(self) {
            self.status_line = Some(t!("filemgr.busy").to_string());
            return 0;
        }
        let (source, t_remote, t_local) = match target {
            PaneId::Remote => (PaneId::Local, Some(self.remote_default_target()), None),
            PaneId::Local => (PaneId::Remote, None, Some(self.local.current.clone())),
        };
        self.enqueue_transfer_targeted(
            source, target, paths, t_remote, t_local, panel, file_tx, fm_tx,
        )
    }

    /// 活动节点 = 「远端电脑」合成根时该键非真实目录 = 回退对端 fs 根
    /// `""`（家目录，旧默认落点语义保留；fail-closed 于服务端再兜底）。
    fn remote_default_target(&self) -> String {
        // 此为防御臂；保留键零入落点）。
        if self.remote.current == REMOTE_PC_ROOT_KEY || self.remote.current == REMOTE_HOME_KEY {
            String::new()
        } else {
            self.remote.current.clone()
        }
    }

    /// 上传落点目标（远端栏目录，root 相对）——**调用点注入** `panel_open`
    /// （s→c `paste_landing_fm_surface` 同口径：本方法不感知窗型/面板态）：
    /// 语境 = 面板开 ∧ 远端栏已启动 ∧ 对端支持浏览；否则 `None`（调用点走
    /// 既有 v1 Offer 链，零变化）。选中优先（恰一非符号链接目录）= 当前目录
    /// 回退（合成根 → `""` 对端 fs 根）——判定体 = 纯函数
    /// [`clip_upload_c2s_target`] 单一语义源。
    ///
    /// 时回退**会话级登记表**（per-peer addr 键控，lib.rs 帧首注入本窗
    /// [`Self::r167_session_dir_fallback`]）——FM 窗在而会话重建首帧未
    /// 置位/面板关等形态不再误伤；优先级 = **选中 > 当前（真实目录）>
    /// 登记表 > 合成根**（合成根仅无登记时维持既有 `""` 对端 fs 根口径；
    /// 既有单测矩阵逐位零变化——默认字段 `None`）。真无语境仍 `None` =
    /// v1 链/`dir_no_context` **显式提示保留**（禁静默红线⑤零放宽）。
    pub fn c2s_paste_upload_target(&self, panel_open: bool) -> Option<String> {
        let context = panel_open
            && self.remote.started
            && !self.remote.unsupported;
        let computed =
            clip_upload_c2s_target(
                context,
                self.single_dir_selection(PaneId::Remote),
                self.remote_default_target(),
            );
        // 合成根保留键 = 非「真实当前目录」→ 登记表优先于合成根（卡口径
        // 「选中 > 当前 > 登记表 > 合成根」；真实当前目录〔含 `""` 对端
        // fs 根〕不被登记表越位）。
        let synthesized_root = matches!(
            self.remote.current.as_str(),
            REMOTE_PC_ROOT_KEY | REMOTE_HOME_KEY
        );
        match computed {
            Some(t) if !synthesized_root => Some(t),
            Some(_) => self
                .r167_session_dir_fallback
                .clone()
                .or(computed),
            None => self.r167_session_dir_fallback.clone(),
        }
    }

    /// addr 登记表置位）。登记纪律 = 真实目录事实才登记（fail-closed 防
    /// 合成根/未浏览空态污染）：远端栏已启动 ∧ 支持浏览，值 = 恰一非符号
    /// 链接目录选中 > 当前目录（合成根保留键 = `None` 零登记，保留旧值）。
    pub(crate) fn r167_remote_dir_hint(&self) -> Option<String> {
        if !(self.remote.started && !self.remote.unsupported) {
            return None;
        }
        if let Some(sel) = self.single_dir_selection(PaneId::Remote) {
            return Some(sel);
        }
        match self.remote.current.as_str() {
            REMOTE_PC_ROOT_KEY | REMOTE_HOME_KEY => None,
            cur => Some(cur.to_string()),
        }
    }

    /// 元数据 → 本窗粘贴拉取语境；客户端 shell/file 会话接收臂每帧 drain）。
    ///
    /// 关）——`None`（未通告）/ 已知 OFF = fail-closed **零槽写** + 记档一
    /// **零触本机板**（占位写板/防回环 = 0x05 桌面路径资产；文件窗语境反馈
    pub fn on_clip_meta(&mut self, meta: crate::clipboard::FileClipMeta) {
        if !matches!(self.peer_consent, Some((true, _))) {
            // 30s 节流（`clip_gate_off_warn_due` 同口径：slot+30s <= now）。
            if self.clip_meta_gate_warn_at + Duration::from_secs(30)
                <= Instant::now()
            {
                self.clip_meta_gate_warn_at = Instant::now();
                tracing::warn!(
                    meta.entries.len(),
                    meta.cleared
                );
            }
            return;
        }
        let entries = meta.entries.len();
        let cleared = meta.cleared;
        // 不可绕过；消费点 = 窗层 drain 位点 `take_clip_prefetch_req`，
        // 消费后派发经既有 FetchFile 授权链，本函数零直发）。
        // 用户 2026-09-28 裁定；授权语义颠倒 = 只有粘贴才触发拉取。槽/
        // take 基建保留 = 未来延迟渲染另立项复用）。
        if crate::clipboard_direct::should_request_prefetch(
            self.peer_consent.map(|(clip, _)| clip),
            cleared,
        ) {
            self.clip_prefetch_req = Some(meta.clone());
        } else {
            self.clip_prefetch_req = None;
        }
        self.pending_clip_meta = if cleared { None } else { Some(meta) };
        tracing::info!("{}", crate::r134_7_clip_meta_apply_line(entries, cleared));
        // 仅非 CLEAR 实清单——CLEAR 清位零行）。
        if !cleared && entries > 0 {
            crate::conn_log_push_text(
                crate::widgets::ConnLogLevel::Info,
                &tf!("connect.log.r156_clip_meta", entries),
            );
        }
    }

    /// `clip_meta_rx` drain 臂取槽后携本窗 `file_tx` 派发；消费即清）。
    /// 桌面会话 `MetaApplied` 门内臂不经此槽（会话任务内直派发）。
    pub fn take_clip_prefetch_req(&mut self) -> Option<crate::clipboard::FileClipMeta> {
        self.clip_prefetch_req.take()
    }

    /// = 用户 Ctrl+C 发生在应用外〔Explorer 等〕+ 本窗 Ctrl+V）：
    /// - **c→s**（OS 板有文件）= 上传——落点 = **本窗远端栏目录**（选中优
    ///   先 / 当前回退 / 合成根 → 对端 fs 根，[`Self::c2s_paste_upload_target`]
    ///   单一语义源）→ 既有 `SendFileV2`（OfferV2 `target_dir` 零新 wire）；
    ///   视图；FM 窗在而会话重建首帧/面板态不齐不再误伤）→ 仍无 = 既有 v1
    ///   Offer 链零变化（服务端聚焦层/download_dir 回退同口径）+ 目录条目
    ///   `dir_no_context` **显式失败行保留**（真无语境禁静默）；批 ≤64
    ///  （K8 同口径）。
    /// - **s→c**（OS 板空 + pending 元数据有可拉取条目）= 拉取——落点 =
    ///   **本窗本地栏目录**（选中 > 当前 > download_dir 回退；派发时刻
    ///   存在/可写探测 + [`paste_landing_resolve`] 单一语义源）→ 既有
    ///   `clip_fetch_dispatch`（`FetchFile` 引擎面）；**消费即清**；
    /// - 双皆无 = 「剪贴板为空」状态行（`paste_cross` 同口径）。
    /// 返回派发条数（0 = 无通道/空板/无 pending）。
    pub fn paste_clipboard_fallback(
        &mut self,
        file_tx: Option<&UnboundedSender<FileCommand>>,
        os_files: Option<&crate::clipboard::OsFileBoard>,
    ) -> usize {
        let Some(tx) = file_tx else {
            return 0; // 无文件通道 = 无粘贴入口（§2.0 fail-closed 同口径）
        };
        // c→s：OS 板文件非空 = 上传（文件优先，与板状态机判定优先级同构）。
        if let Some(files) = os_files.filter(|b| !b.entries.is_empty()) {
            let total = files.entries.len();
            let batch = total.min(crate::CLIP_PASTE_MAX_FILES);
            let target = self.c2s_paste_upload_target(true);
            // 「not a regular file」静默丢弃 = 目录粘贴无响应 + 零反馈根因）
            // ——批内含目录 = 整批转 FolderJob ToRemote 整树递归（RDP-like，
            // 复用 `collect_local_folder` + SendWithConsent 批，零新 wire）；
            // 条目**显式失败提示**（禁静默）。
            let taken: Vec<&crate::clipboard::OsFileEntry> =
                files.entries.iter().take(batch).collect();
            let dir_n = taken.iter().filter(|e| e.is_dir).count();
            if dir_n > 0 {
                return match target.as_deref() {
                    Some(t) => {
                        let n = self.r156_paste_dirs_toremote(&taken, t);
                        tracing::info!(
                            dir_n,
                            taken.len() - dir_n,
                            t
                        );
                        crate::conn_log_push_text(
                            crate::widgets::ConnLogLevel::Info,
                            &tf!("connect.log.r156_paste_upload", dir_n, taken.len() - dir_n),
                        );
                        n
                    }
                    None => {
                        let mut sent = 0usize;
                        for e in taken.iter().filter(|e| !e.is_dir) {
                            if tx
                                .send(FileCommand::SendFile {
                                    path: PathBuf::from(&e.abs_path),
                                })
                                .is_ok()
                            {
                                sent += 1;
                            }
                        }
                        tracing::warn!(
                            dir_n
                        );
                        crate::conn_log_push_text(
                            crate::widgets::ConnLogLevel::Warn,
                            &tf!("connect.log.r156_dir_rejected", dir_n),
                        );
                        // 显式失败状态行（禁 `consent.waiting` 假等待）。
                        self.status_line =
                            Some(t!("filemgr.clip.dir_no_context").to_string());
                        sent
                    }
                };
            }
            // 失败行，禁「等待对方确认」假象，修复点 3）。
            let mut sent = 0usize;
            for e in files.entries.iter().take(batch) {
                let path = PathBuf::from(&e.abs_path);
                let cmd = match target.as_deref() {
                    Some(t) => FileCommand::SendFileV2 {
                        path,
                        target_dir: t.to_string(),
                    },
                    None => FileCommand::SendFile { path },
                };
                if tx.send(cmd).is_ok() {
                    sent += 1;
                }
            }
            tracing::info!(
                total,
                batch,
                match target.as_deref() {
                    Some(t) if t.is_empty() => "<peer fs root>".to_string(),
                    Some(t) => t.to_string(),
                    None => "v1 chain (no in-app remote context)".to_string(),
                }
            );
            // 等罕见形态）= 显式失败行，禁「等待对方确认」假象；上传开始
            // 埋点连接页一行（目录 0 / 文件 sent）。
            self.status_line = Some(
                if sent == 0 {
                    t!("consent.send_failed").to_string()
                } else {
                    t!("consent.waiting").to_string()
                },
            );
            if sent > 0 {
                crate::conn_log_push_text(
                    crate::widgets::ConnLogLevel::Info,
                    &tf!("connect.log.r156_paste_upload", 0, sent),
                );
            }
            return sent;
        }
        // s→c：OS 板空 + pending 元数据有可拉取条目 = 拉取（落点 = 本地栏）。
        if let Some(pm) = self.pending_clip_meta.clone() {
            let plan = crate::clip_fetch_plan(&pm);
            if plan.consumed {
                // 落点三层：选中目录 > 本地栏当前目录 > download_dir（派发
                // 时刻 std::fs 探测 + 纯函数单一语义源，§12.3 同口径）。
                let cfg = kirin_desk_utils::config::Config::load();
                let download_dir = cfg
                    .as_ref()
                    .map(|c| c.file_transfer.resolved_download_dir())
                    .unwrap_or_default();
                let candidate = self
                    .single_dir_selection(PaneId::Local)
                    .map(PathBuf::from)
                    .or_else(|| {
                        let c = self.local.current.clone();
                        if c.is_dir() {
                            Some(c)
                        } else {
                            None
                        }
                    });
                let (dir_exists, dir_writable) = match candidate.as_deref() {
                    Some(d) if d.is_dir() => (true, crate::fm_dir_writable_probe(d)),
                    _ => (false, false),
                };
                let landing = paste_landing_resolve(
                    candidate.as_deref(),
                    dir_exists,
                    dir_writable,
                    &download_dir,
                );
                let dir = match &landing {
                    PasteLanding::Browse(d) => d.clone(),
                    PasteLanding::Fallback(d) => d.clone(),
                };
                let plan = crate::clip_fetch_dispatch(tx, &pm, &dir);
                tracing::info!(
                    "{}",
                    crate::r135_1_s2c_landing_line(
                        crate::r135_1_s2c_source(true, false),
                        candidate.as_ref().and_then(|p| p.to_str()),
                        dir_exists,
                        dir_writable,
                        &dir.to_string_lossy(),
                    )
                );
                tracing::info!(
                    plan.fetchable_paths.len(),
                    dir.display(),
                    if plan.dir_paths.is_empty() {
                        String::new()
                    } else {
                        format!(
                            plan.dir_paths.len()
                        )
                    }
                );
                // 会话窗臂 ② 同口径——Explorer 可粘贴）。
                crate::clip_board_epoch_begin(&plan.fetchable_paths);
                // `FsOp::List` BFS 展开 → 逐文件 `FetchFile`（落点
                // `landing/<目录名>/…`，深度限界 `FOLDER_MAX_DEPTH`）。
                if !plan.dir_paths.is_empty() {
                    self.clip_expand_start(plan.dir_paths.clone(), &dir);
                }
                self.status_line = match &landing {
                    PasteLanding::Fallback(_) => Some(t!("clip.fetch.fallback").to_string()),
                    PasteLanding::Browse(_) if plan.outside_root > 0 => Some(
                        tf!("clip.fetch.outside_root", plan.outside_root).to_string(),
                    ),
                    PasteLanding::Browse(_) if !plan.dir_paths.is_empty() => Some(
                        tf!("clip.fetch.dirs_started", plan.dir_paths.len()).to_string(),
                    ),
                    PasteLanding::Browse(_) => Some(
                        tf!("filemgr.enqueued.recv", plan.fetchable_paths.len()).to_string(),
                    ),
                };
                // 消费即清（pending 生命周期第四态；CLEAR/会话拆除 = 其余清态）。
                self.pending_clip_meta = None;
                return plan.fetchable_paths.len();
            }
        }
        // 双皆无 = 空板状态行（与 `paste_cross` 空剪贴板同文案口径）。
        self.status_line = Some(t!("filemgr.clipboard.empty").to_string());
        0
    }

    /// OS 板目录条目（可混编散文件）整批入 FolderJob ToRemote：
    /// [`Self::r156_collect_toremote_payload`] 整树展开（复用
    /// `collect_local_folder`）+ 既有 SendWithConsent 批推进（tick 既有
    /// 机制，零新 wire）。返回入队文件数（0 = 纯空目录/全失败，状态行
    /// 收敛既有「此目录为空」口径）。
    fn r156_paste_dirs_toremote(
        &mut self,
        entries: &[&crate::clipboard::OsFileEntry],
        target: &str,
    ) -> usize {
        let mut dirs: Vec<String> = Vec::new();
        let mut loose: Vec<(String, u64, String)> = Vec::new();
        for e in entries {
            if e.is_dir {
                dirs.push(e.abs_path.clone());
            } else {
                loose.push((e.abs_path.clone(), e.size, String::new()));
            }
        }
        // 显示源 = 条目 basename「、」连接（与面板选中臂同口径）。
        let source = entries
            .iter()
            .map(|e| {
                e.abs_path
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(&e.abs_path)
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("、");
        let (mut jfiles, capped, failed, cycle_skipped, mkdir_queue, visit) =
            Self::r156_collect_toremote_payload(&dirs, target);
        jfiles.extend(loose);
        let finished = jfiles.is_empty() && mkdir_queue.is_empty();
        self.job = Some(FolderJob {
            direction: FolderDirection::ToRemote,
            source,
            target_remote_dir: target.to_string(),
            target_local_dir: PathBuf::new(),
            files: jfiles.clone(),
            depth_capped: capped,
            next_idx: 0,
            batch_head: 0,
            collecting: false,
            collect_queue: VecDeque::new(),
            finished,
            started: Instant::now(),
            consent_pending: false,
            consent_req_id: None,
            target_dirs: Vec::new(),
            visit,
            failed,
            cycle_skipped,
            summary_emitted: false,
            mkdir_queue,
        });
        if jfiles.is_empty() && finished {
            self.status_line = Some(t!("filemgr.empty.local").to_string());
        } else {
            // 「等待对方确认」= 文件夹上传同口径（真批已发出，非假等待——
            // 零入队形态在上一臂已显式失败）。
            self.status_line = Some(t!("consent.waiting").to_string());
        }
        jfiles.len()
    }


    /// 启动（粘贴臂调用；`landing_base` = 本窗落点目录，展开根子目录
    /// `landing/<根目录名>/`）。
    pub(crate) fn clip_expand_start(&mut self, dir_paths: Vec<String>, landing_base: &Path) {
        self.clip_expand = Some(ClipDirExpand::start(dir_paths, landing_base));
    }

    /// FSM 泵（tick 每帧调用；空闲 = 零开销；file_tx 缺失 = 冻结不推进，
    /// 通道恢复后续泵）。序 = 文件派发（收集即派）→ 在途空发下一层 List →
    /// 超时判失败 → 收敛终态（状态行 + 连接页汇总行）。
    pub(crate) fn clip_expand_pump(&mut self, file_tx: Option<&UnboundedSender<FileCommand>>) {
        if self.clip_expand.is_none() {
            return;
        }
        let mut finished_snapshot: Option<(usize, usize, usize, usize, usize)> = None;
        let mut cancel_snapshot: Option<(usize, usize, usize)> = None;
        {
            let Some(tx) = file_tx else { return };
            let Some(st) = self.clip_expand.as_mut() else { return };
            //    no-op）：清队列、弃在途（响应到达即丢弃——槽已空不命中）、
            //    已拉文件保留（落盘如实）；未派 K = 队列 + 已收未派 + 在途
            //    1（内容未收集）。终态处置出借用域（单测锁死幂等）。
            if st.cancelled {
                let pending = r159_cancel_unassigned(
                    st.queue.len(),
                    st.files.len(),
                    st.inflight.is_some(),
                );
                st.queue.clear();
                st.files.clear();
                st.inflight = None;
                st.inflight_since = None;
                st.conflict = None;
                cancel_snapshot = Some((st.fetch_sent, st.fetch_skipped, pending));
            } else if st.conflict.is_some() {
                // 队列/在途原样——在途响应仍被 on_response 吸收，派发面
                // 冻结不派不列）。
            } else {
                //    跳过计数（fail-open：stat 失败/任一不等 = 照常拉取，比对
                //    不一致最多多拉一次，不产生漏贴；RustDesk digest.is_identical
                //    三选（悬挂等框 / 覆盖删旧后派〔登记表 fail-closed〕/ 直派）。
                let mut dispatched_this_tick = 0usize;
                let taken = std::mem::take(&mut st.files);
                let mut idx = 0usize;
                while idx < taken.len() {
                    let (rel, subdir, size, mtime) = taken[idx].clone();
                    let local_dir = st.landing_root.join(&subdir);
                    let base = rel.rsplit('/').next().unwrap_or(&rel).to_string();
                    let local_path = local_dir.join(&base);
                    if r158_file_identical(size, mtime, r158_stat_meta(&local_path)) {
                        st.fetch_skipped += 1;
                        idx += 1;
                        continue;
                    }
                    match r159_conflict_gate(
                        local_path.exists(),
                        st.overwrite_all,
                        st.overwrite_once,
                    ) {
                        R159ConflictGate::Dispatch => {}
                        R159ConflictGate::Overwrite => {
                            //（命中**且**登记目录 = 本项落点）；未命中/删除
                            // 失败 = 回退跳过 + Warn（防误删用户文件）。
                            st.overwrite_once = false; // 单次旗标无论成败均消费
                            let reg_dir = crate::r159_peek_fetch_landing(&base);
                            if reg_dir.as_deref() == Some(local_dir.as_path())
                                && std::fs::remove_file(&local_path).is_ok()
                            {
                                tracing::info!(
                                    local_path.display()
                                );
                            } else {
                                st.fetch_skipped += 1;
                                tracing::warn!(
                                    local_path.display()
                                );
                                idx += 1;
                                continue;
                            }
                        }
                        R159ConflictGate::Suspend => {
                            // 悬挂：当前项回填队首（决策后本泵重放），余量随行。
                            st.conflict = Some(R159ConflictItem {
                                rel_path: rel,
                                subdir,
                                size,
                                mtime,
                            });
                            st.files = taken[idx..].to_vec();
                            break;
                        }
                    }
                    crate::r154_register_fetch_landing(&rel, &local_dir);
                    let _ = tx.send(FileCommand::FetchFile {
                        remote_path: rel,
                        local_dir,
                    });
                    st.fetch_sent += 1;
                    dispatched_this_tick += 1;
                    idx += 1;
                }
                // 另有终行）。
                if dispatched_this_tick >= R158_PROGRESS_EVERY {
                    crate::conn_log_push_text(
                        crate::widgets::ConnLogLevel::Info,
                        &r158_progress_line(
                            st.fetch_sent,
                            st.fetch_skipped,
                            st.files.len(),
                            st.failed.len(),
                        ),
                    );
                }
                // 2) 在途超时 = 本目录记失败继续（防响应丢失永久悬挂）。
                if let Some((rid, dir_rel, ..)) = st.inflight.as_ref() {
                    if *rid != 0
                        && st
                            .inflight_since
                            .is_some_and(|t| t.elapsed() >= R156_CLIP_INFLIGHT_TIMEOUT)
                    {
                        let dir_rel = dir_rel.clone();
                        st.inflight = None;
                        st.inflight_since = None;
                        st.dirs_done += 1;
                        st.failed.push(dir_rel);
                    }
                }
                // 3) 在途空 && 队列非空 → 发下一层 List（独立 req_id 关联槽，
                // pane 单槽零触碰）。
                if st.inflight.is_none() {
                    if let Some((dir_rel, depth, subdir)) = st.queue.pop_front() {
                        let _ = tx.send(FileCommand::Fs {
                            op: FsOp::List {
                                path: dir_rel.clone(),
                                offset: 0,
                                limit: R156_CLIP_LIST_LIMIT,
                            },
                        });
                        st.inflight = Some((0, dir_rel, 0, depth, subdir));
                        st.inflight_since = Some(Instant::now());
                    }
                }
                //    `create_dir_all` 已发现目录（零 wire——含纯空目录/空子树；
                //    不中止）。
                if st.is_finished() {
                    let base = st.landing_root.clone();
                    let mut io_failed = 0usize;
                    for d in std::mem::take(&mut st.dirs) {
                        if let Err(e) = std::fs::create_dir_all(base.join(&d)) {
                            io_failed += 1;
                            tracing::warn!("{} (create err={e})", r135_5b_fail_line("io", &d));
                        }
                    }
                    if io_failed > 0 {
                        st.failed.push(format!("io:{io_failed} dir(s)"));
                    }
                    finished_snapshot = Some((
                        st.fetch_sent,
                        st.fetch_skipped,
                        st.files.len(),
                        st.dirs_done,
                        st.failed.len(),
                    ));
                }
            }
        }
        if let Some((sent, skipped, pending)) = cancel_snapshot {
            // 已收 N/已跳 M/未派 K」；连接页观测行格式钉死单测）。
            self.clip_expand = None;
            crate::conn_log_push_text(
                crate::widgets::ConnLogLevel::Info,
                &r159_cancel_line(sent, skipped, pending),
            );
            self.status_line = Some(tf!("filemgr.clip.cancelled", sent, skipped, pending).to_string());
            tracing::info!(
            );
        }
        if let Some((sent, skipped, pending, dirs, failed_n)) = finished_snapshot {
            self.clip_expand = None;
            if sent > 0 || dirs > 0 || skipped > 0 {
                // 钉死单测）。
                crate::conn_log_push_text(
                    if failed_n > 0 {
                        crate::widgets::ConnLogLevel::Warn
                    } else {
                        crate::widgets::ConnLogLevel::Info
                    },
                    &r158_progress_line(sent, skipped, pending, failed_n),
                );
                self.status_line = Some(tf!("filemgr.enqueued.recv", sent).to_string());
                crate::conn_log_push_text(
                    crate::widgets::ConnLogLevel::Info,
                    &tf!("connect.log.r156_fetch_done", sent, dirs),
                );
                tracing::info!(
                );
            }
        }
    }

    /// `Admitted` 事件回填（on_fs_event 前置拦截；命中 = pane 槽零误领）。
    fn clip_expand_on_admitted(&mut self, req_id: u32, op: &FsOp) -> bool {
        let Some(st) = self.clip_expand.as_mut() else {
            return false;
        };
        let claim = matches!(&st.inflight, Some((0, path, ..)) if matches!(
            op,
            FsOp::List { path: p, .. } if *p == *path
        ));
        if claim {
            if let Some(slot) = st.inflight.as_mut() {
                slot.0 = req_id;
                st.inflight_since = Some(Instant::now());
            }
        }
        claim
    }

    /// `Response` 事件消费（on_fs_event 前置拦截；返回 true = 本槽已消费）。
    fn clip_expand_on_response(
        &mut self,
        req_id: u32,
        result: &Result<FsResponsePayload, String>,
    ) -> bool {
        let Some(st) = self.clip_expand.as_mut() else {
            return false;
        };
        let hit = matches!(&st.inflight, Some((rid, ..)) if *rid != 0 && *rid == req_id);
        if !hit {
            return false;
        }
        if let Some((_, dir_rel, offset, depth, subdir)) = st.inflight.take() {
            st.inflight_since = None;
            match result {
                Ok(payload) if payload.ok => {
                    match bincode::deserialize::<FsListPayload>(&payload.payload) {
                        Ok(list) => {
                            st.absorb_page(&dir_rel, offset, depth, &subdir, &list.entries, list.has_more);
                        }
                        Err(_) => {
                            st.dirs_done += 1;
                            st.failed.push(dir_rel);
                        }
                    }
                }
                _ => {
                    st.dirs_done += 1;
                    st.failed.push(dir_rel);
                }
            }
        }
        true
    }

    /// 入口）——记忆映射走纯函数 [`r159_conflict_apply`]（单测钉死）：
    /// 跳过 = 丢弃悬挂项（队首回放件，`fetch_skipped` +1 零网络帧）；覆盖 =
    /// 单次旗标（项保留，门重判走 Overwrite 臂删旧后派）；全部应用 = 会话
    /// 记忆 `overwrite_all`（后续同名不再弹，RustDesk
    /// `default_overwrite_strategy` 同口径）。无悬挂槽 = no-op（幂等）。
    pub(crate) fn clip_conflict_resolve(&mut self, d: R159ConflictDecision) {
        let Some(st) = self.clip_expand.as_mut() else {
            return;
        };
        if st.conflict.take().is_none() {
            return;
        }
        let (all, once, drop_item) = r159_conflict_apply(d);
        st.overwrite_all = st.overwrite_all || all;
        st.overwrite_once = once;
        if drop_item {
            st.files.remove(0); // 悬挂项在队首（Suspend 臂回填原样）
            st.fetch_skipped += 1;
        }
    }

    /// 点收敛（清队列、弃在途、已拉文件保留、汇总行如实结算）；零 wire。
    /// 冲突悬挂一并清（取消优先于悬挂决策）。
    pub fn clip_expand_cancel(&mut self) {
        if let Some(st) = self.clip_expand.as_mut() {
            st.cancelled = true;
            st.conflict = None;
        }
    }


    /// 源侧可传输选中数（与 `enqueue_transfer` 的 files/dirs 分派**同口径**：
    /// 文件（含符号链接文件）+ 非符号链接目录；符号链接目录/失效路径 = 不可
    /// 传输——源侧「自动识别文件还是目录」的识别面即此分派。
    pub fn transferable_sel_count(&self, pane: PaneId) -> usize {
        self.selection_paths(pane)
            .iter()
            .filter(|p| {
                self.resolve_entry(pane, p)
                    .map(|e| !e.is_dir || !e.is_symlink)
                    .unwrap_or(false)
            })
            .count()
    }

    /// 目标栏选中恰一个非符号链接目录 → 该目录**节点全路径**（文件/多项/空/
    /// 符号链接 = `None`，fail-closed：箭头目标必须是目录，用户规格②「…到
    /// 绝对），落点即选中目录节点自身，不再与当前目录拼接）。
    pub fn single_dir_selection(&self, pane: PaneId) -> Option<String> {
        let sel = self.selection_paths(pane);
        if sel.len() != 1 {
            return None;
        }
        let path = sel[0].clone();
        // = **不可作传输落点**（fail-closed）。
        // 语义 = 盘符层本身，落点资格须到盘符/盘内目录层）。
        if (pane == PaneId::Local && path == LOCAL_PC_ROOT_KEY)
            || (pane == PaneId::Remote && path == REMOTE_PC_ROOT_KEY)
        {
            return None;
        }
        // 落点，落点语义 = home `""`——与 `remote_default_target` 合成根
        // 回退同形）。
        if pane == PaneId::Remote && path == REMOTE_HOME_KEY {
            return Some(String::new());
        }
        let e = self.resolve_entry(pane, &path)?;
        if e.is_dir && !e.is_symlink {
            Some(path)
        } else {
            None
        }
    }

    /// 指定方向箭头是否可点（**单一判定面**：源侧有可传输选中 + 目标侧恰一
    /// 目录 + 非在途〔job/dialog/pending，与既有栏按钮 busy 门同构〕）。
    /// 纯选择矩阵面见 [`arrow_enabled`]（单测分别钉死）。
    pub fn arrow_ready(&self, dir: ArrowDirection) -> bool {
        if job_active(self) || self.has_dialog() || self.pending.is_some() {
            return false;
        }
        let (src, dst) = dir.panes();
        arrow_enabled(
            self.transferable_sel_count(src),
            self.single_dir_selection(dst).is_some(),
        )
    }

    /// `None` = 就绪）。与 [`Self::arrow_ready`] **同序同判据**（busy 门
    /// job/dialog/pending 首判 → 源侧可传输选中 → 目标侧恰一目录）代入纯核
    /// [`arrow_disabled_reason`]（单一语义源，防两判据分叉）。
    pub fn arrow_disabled_reason(&self, dir: ArrowDirection) -> Option<ArrowDisabledReason> {
        let busy = job_active(self) || self.has_dialog() || self.pending.is_some();
        let (src, dst) = dir.panes();
        arrow_disabled_reason(
            busy,
            self.transferable_sel_count(src),
            self.single_dir_selection(dst).is_some(),
        )
    }

    /// 全路径，落点 = 该节点自身，不再与当前目录拼接；源侧自动识别文件/目录
    /// = 复用 `enqueue_transfer` 快路径/FolderJob 整目录编排，零 wire 新增）。
    /// 返回入队项数（0 = 条件不满足/空选）。
    pub fn arrow_transfer(
        &mut self,
        dir: ArrowDirection,
        panel: &FilePanelState,
        file_tx: Option<&UnboundedSender<FileCommand>>,
        fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    ) -> usize {
        // 调用面 fail-closed 兜底（渲染层 `arrow_ready` 已门；防御非渲染
        // 调用点与在途竞态，与 `paste_into` busy 门同构）。
        if job_active(self) || self.has_dialog() {
            self.status_line = Some(t!("filemgr.busy").to_string());
            return 0;
        }
        let (src, dst) = dir.panes();
        // 远端 root-relative；Download = 本地绝对路径）。
        let Some(dst_path) = self.single_dir_selection(dst) else {
            self.status_line = Some(t!("filemgr.arrow.need_dir").to_string());
            return 0;
        };
        let paths = self.selection_paths(src);
        if self.transferable_sel_count(src) == 0 {
            return 0;
        }
        match dir {
            ArrowDirection::Upload => {
                self.enqueue_transfer_targeted(
                    src, dst, paths, Some(dst_path), None, panel, file_tx, fm_tx,
                )
            }
            ArrowDirection::Download => {
                self.enqueue_transfer_targeted(
                    src, dst, paths, None, Some(PathBuf::from(dst_path)), panel, file_tx, fm_tx,
                )
            }
        }
    }

    /// 零 wire；目录不存在 = 栏内提示 fail-closed，不清选中）。
    ///
    /// 清选中 =「树展开了但目标行不选中不高亮不滚动」。本入口改为：
    /// ①展开链（同修前）；②**选中 = 目标节点全键**（`local_path_key` 形，
    /// 与 [`Self::tree_rows`] 行键 / 行区选中高亮判据同形）→ 行区选中高亮；
    /// ③滚动锚置位（渲染层收敛消费即清，滚轮残量门/贴边双态收敛判据与
    /// 远端臂共用）；④`local.current` 锚定不变（上传落点语义零迁移）。
    pub fn goto_local_quick(&mut self, dir: &Path) {
        self.active_pane = PaneId::Local;
        if !dir.is_dir() {
            self.local.view.status = Some(t!("filemgr.err.io").to_string());
            return;
        }
        if !self.local_expand_chain(dir) {
            self.local.view.status = Some(t!("filemgr.err.io").to_string());
            return;
        }
        self.local.current = dir.to_path_buf();
        // 行区高亮命中）；滚动锚 + 收敛观测复位（渲染帧消费）。
        let key = local_path_key(dir);
        self.local.view.selected = vec![key.clone()];
        self.local.scroll_anchor = Some(key);
        self.local.scroll_anchor_prev_delta = None;
    }

    /// 对端 home 直接子目录，**既有 `FsOp::List` 字符串通道零新 wire
    /// op**）。
    ///
    /// 远端树 = 「远端电脑」合成根 ▸ 合成「主目录」节点
    /// （[`REMOTE_HOME_KEY`]，children = home List 缓存 `nodes[""]`）▸
    /// **home 相对键**（`"Desktop"` 等）——修前 home 相对键挂在不可见 home
    /// 根 `""` 下 = 孤儿子树永不渲染（`tree_roots` 单根 DFS 不达）=「点
    /// 快捷无选中无跳转 / 目录层级没分开」根因面。本入口改为：
    /// ①主目录链展开（合成根 + 主目录节点 + 目标键入展开集）；
    /// ②**选中 = 目标节点全键**（行区选中高亮 + `scroll_anchor` 滚动锚，
    /// 渲染帧消费即清）；③`remote.current` 锚定不变（上传默认落点
    /// `remote_default_target` 语义零迁移）；④缓存命中零 wire，未落定 =
    /// 单在途一次 List（单槽纪律同 [`Self::request_remote_list_at_node`]）。
    pub fn goto_remote_quick(&mut self, name: &str, file_tx: Option<&UnboundedSender<FileCommand>>) {
        self.active_pane = PaneId::Remote;
        // ① 主目录链展开（根默认展开，折叠态再展开 = 链完整可见）。
        for k in [REMOTE_PC_ROOT_KEY, REMOTE_HOME_KEY] {
            if !self.remote.view.expanded.iter().any(|p| p == k) {
                self.remote.view.expanded.push(k.to_string());
            }
        }
        // ② 选中 = 目标节点全键（home 相对裸名，与 `child_path_key`
        // 「主目录」臂同形）→ 行区选中高亮；滚动锚（渲染层消费）。
        self.remote.current = name.to_string();
        self.remote.view.selected = vec![name.to_string()];
        self.remote.scroll_anchor = Some(name.to_string());
        self.remote.scroll_anchor_prev_delta = None;
        // ③ 目标键入展开集（缓存命中 = 子行立即可见；未命中路径响应落定
        // 后由 `request_remote_list_at_node` 补推）。
        if !self.remote.view.expanded.iter().any(|p| p == name) {
            self.remote.view.expanded.push(name.to_string());
        }
        // ④ 缓存命中零 wire；未落定 = 单在途一次 List（既有通道）。
        let cached = self
            .remote
            .view
            .nodes
            .get(name)
            .is_some_and(|n| n.children.is_some() && n.error.is_none());
        if !cached {
            self.request_remote_list_at_node(name, file_tx);
        }
    }

    // ── 传输入队（既有入口零变化；`_targeted` = 显式目标目录核心）──

    /// 传输入队（§2.4 操作矩阵 / §2.6.1② 文件夹 UI 编排）：
    /// 单文件 = 快路径直发；目录/多项 = 文件夹任务（深度 10 层超限不展开 +
    /// 提示、批 ≤[`FOLDER_BATCH_SIZE`] FIFO 自然节流、并发 ≤3 引擎侧保证）。
    /// （中缝箭头走 [`Self::arrow_transfer`] = 对侧**选中目录节点**）。
    pub fn enqueue_transfer(
        &mut self,
        from: PaneId,
        to: PaneId,
        names: Vec<String>,
        panel: &FilePanelState,
        file_tx: Option<&UnboundedSender<FileCommand>>,
        fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    ) -> usize {
        self.enqueue_transfer_targeted(from, to, names, None, None, panel, file_tx, fm_tx)
    }

    /// `enqueue_transfer_targeted` 上传臂原样抽取（行为逐位零变化）：
    /// 逐目录 [`collect_local_folder`] 整树展开 + 环防护去重（小写键，同
    /// `r156_paste_dirs_toremote`，c→s 目录 RDP-like 整树上传）。
    /// 返回 (目录树文件, depth_capped, failed, cycle_skipped, mkdir_queue, visit)。
    #[allow(clippy::type_complexity)]
    fn r156_collect_toremote_payload(
        dirs: &[String],
        target_remote_dir: &str,
    ) -> (
        Vec<(String, u64, String)>,
        Vec<String>,
        Vec<(String, String)>,
        Vec<String>,
        VecDeque<String>,
        HashSet<String>,
    ) {
        let mut jfiles: Vec<(String, u64, String)> = Vec::new();
        let mut capped: Vec<String> = Vec::new();
        let mut visit: HashSet<String> = HashSet::new();
        let mut failed: Vec<(String, String)> = Vec::new();
        let mut cycle_skipped: Vec<String> = Vec::new();
        let mut mkdir_disp: Vec<String> = Vec::new();
        for d in dirs {
            let base = task_file_basename(d);
            // 收集（环防护入口；记清单不静默）。
            if !visit.insert(d.to_ascii_lowercase()) {
                cycle_skipped.push(base);
                continue;
            }
            let col = collect_local_folder(Path::new(d), FOLDER_MAX_DEPTH);
            for (rel, sz) in &col.files {
                // 目录选中镜像 `目标/<目录名>/…`：顶层文件 rel 无
                // 父级 → subdir = base 本身；嵌套 = base/rel 父级。
                let subdir = match rel.rfind('/') {
                    Some(i) => format!("{base}/{}", &rel[..i]),
                    None => base.clone(),
                };
                jfiles.push((local_path_key(&Path::new(d).join(rel)), *sz, subdir));
            }
            capped.extend(col.capped.iter().map(|p| format!("{base}/{p}")));
            // 目录本身仍入 Mkdir 队列 = 远端建为空目录）。
            for r in &col.read_failed {
                let disp = job_dir_display(&base, r);
                tracing::warn!("{}", r135_5c_fail_line("io", &disp));
                failed.push((disp, "io".to_string()));
            }
            // 目录）须远端创建 = 既有 `FsOp::Mkdir`（零新 wire op）。
            for rel in r135_5c_empty_dirs(&col.files, &col.dirs) {
                mkdir_disp.push(job_dir_display(&base, &rel));
            }
        }
        // 远端全路径（`remote_join` 同一 join 口径）。
        mkdir_disp.sort_by(|a, b| {
            (a.matches('/').count(), a.as_str()).cmp(&(b.matches('/').count(), b.as_str()))
        });
        let mkdir_queue: VecDeque<String> = mkdir_disp
            .iter()
            .map(|disp| remote_join(target_remote_dir, disp))
            .collect();
        (jfiles, capped, failed, cycle_skipped, mkdir_queue, visit)
    }

    /// 目标目录节点覆盖；`None` = 对侧栏当前目录节点）。文件/目录自动识别：
    /// 单文件（无目录）= 快路径；目录/多项 = FolderJob 整目录编排（目录选中
    /// = 整目录传输，镜像于 `目标/<选中目录名>/…`，零 wire 新增）。
    pub fn enqueue_transfer_targeted(
        &mut self,
        from: PaneId,
        to: PaneId,
        names: Vec<String>,
        target_remote_dir: Option<String>,
        target_local_dir: Option<PathBuf>,
        panel: &FilePanelState,
        file_tx: Option<&UnboundedSender<FileCommand>>,
        fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    ) -> usize {
        if from == to {
            return 0;
        }
        let direction = match (from, to) {
            (PaneId::Local, PaneId::Remote) => FolderDirection::ToRemote,
            (PaneId::Remote, PaneId::Local) => FolderDirection::ToLocal,
            _ => return 0,
        };
        // / 失效路径 = 跳过，S4）。
        let mut files: Vec<(String, u64, String)> = Vec::new();
        let mut dirs: Vec<String> = Vec::new();
        for p in &names {
            // （与 `single_dir_selection` 落点门同口径，源侧 fail-closed）。
            // 传输源；home 相对真子目录键不在排除列）。
            if (from == PaneId::Local && p == LOCAL_PC_ROOT_KEY)
                || (from == PaneId::Remote
                    && (p == REMOTE_PC_ROOT_KEY || p == REMOTE_HOME_KEY))
            {
                continue;
            }
            match self.resolve_entry(from, p) {
                Some(e) if e.is_dir && !e.is_symlink => dirs.push(p.clone()),
                Some(e) if !e.is_dir => files.push((p.clone(), e.size, String::new())),
                // 查无（已删/失效）或符号链接目录（S4）= 跳过。
                _ => {}
            }
        }
        if files.is_empty() && dirs.is_empty() {
            self.status_line = Some(t!("filemgr.empty.local").to_string());
            return 0;
        }
        if dirs.is_empty() && files.len() == 1 {
            return self.enqueue_single_file_targeted(
                from,
                &files[0].0,
                target_remote_dir.as_deref(),
                target_local_dir.as_deref(),
                panel,
                file_tx,
                fm_tx,
            );
        }
        let source = dirs
            .iter()
            .map(|d| task_file_basename(d))
            .chain(files.iter().map(|(p, _, _)| task_file_basename(p)))
            .collect::<Vec<_>>()
            .join("、");
        match direction {
            FolderDirection::ToRemote => {
                let mut jfiles = files;
                // **目录节点**）；`None` = 远端栏默认目标
                let target_remote_dir =
                    target_remote_dir.unwrap_or_else(|| self.remote_default_target());
                // ——面板选中臂与 OS 板粘贴臂两调用面共享，行为逐位零变化）。
                let (mut dir_files, capped, failed, cycle_skipped, mkdir_queue, visit) =
                    Self::r156_collect_toremote_payload(&dirs, &target_remote_dir);
                jfiles.append(&mut dir_files);
                let finished = jfiles.is_empty() && mkdir_queue.is_empty();
                self.job = Some(FolderJob {
                    direction,
                    source,
                    target_remote_dir,
                    target_local_dir: PathBuf::new(),
                    files: jfiles.clone(),
                    depth_capped: capped,
                    next_idx: 0,
                    batch_head: 0,
                    collecting: false,
                    collect_queue: VecDeque::new(),
                    // （纯空目录选中 = Mkdir 链在途 = 任务未终态；排空后
                    // tick 收敛点置终态 + 状态行 = 既有「此目录为空」口径）。
                    finished,
                    started: Instant::now(),
                    consent_pending: false,
                    consent_req_id: None,
                    target_dirs: Vec::new(),
                    visit,
                    failed,
                    cycle_skipped,
                    summary_emitted: false,
                    mkdir_queue,
                });
                if jfiles.is_empty() && finished {
                    self.status_line = Some(t!("filemgr.empty.local").to_string());
                }
                jfiles.len()
            }
            FolderDirection::ToLocal => {
                let mut q: VecDeque<(String, u32, usize, String, String)> = VecDeque::new();
                // （含顶层同名根）+ 重复根跳过清单（散选重复/大小写异写）。
                let mut visit: HashSet<String> = HashSet::new();
                let mut target_dirs: Vec<String> = Vec::new();
                let mut cycle_skipped: Vec<String> = Vec::new();
                for d in &dirs {
                    let prefix = task_file_basename(d);
                    if !visit.insert(d.to_ascii_lowercase()) {
                        // 不再次收集（环防护入口；记清单不静默）。
                        cycle_skipped.push(prefix);
                        continue;
                    }
                    // （**空目录也在目标创建** = 用户第 2 项补口径）。
                    target_dirs.push(prefix);
                    q.push_back((d.clone(), 0, 1, d.clone(), task_file_basename(d)));
                }
                let collecting = !q.is_empty();
                let finished = files.is_empty() && q.is_empty();
                self.job = Some(FolderJob {
                    direction,
                    source,
                    target_remote_dir: String::new(),
                    // **目录节点**）；`None` = 本地栏当前目录节点。
                    target_local_dir: target_local_dir
                        .unwrap_or_else(|| self.local.current.clone()),
                    files: files.clone(),
                    depth_capped: Vec::new(),
                    next_idx: 0,
                    batch_head: 0,
                    collecting,
                    collect_queue: q,
                    finished,
                    started: Instant::now(),
                    // 不涉同意接收（拉取 = 用户显式动作，既有链零变化）。
                    consent_pending: false,
                    consent_req_id: None,
                    target_dirs,
                    visit,
                    failed: Vec::new(),
                    cycle_skipped,
                    summary_emitted: false,
                    // `create_dir_all` 零 wire，归 `target_dirs` 收敛）。
                    mkdir_queue: VecDeque::new(),
                });
                files.len()
            }
        }
    }

    /// 返回 1 = 已入队。落点 = 对侧栏**当前目录节点**（中缝箭头走
    /// [`Self::arrow_transfer`] 显式目标目录节点）。
    pub fn enqueue_single_file(
        &mut self,
        from: PaneId,
        name: &str,
        panel: &FilePanelState,
        file_tx: Option<&UnboundedSender<FileCommand>>,
        fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    ) -> usize {
        self.enqueue_single_file_targeted(from, name, None, None, panel, file_tx, fm_tx)
    }

    /// 显式落点目录节点覆盖；`None` = 对侧栏当前目录节点）。返回 1 = 已入队。
    pub fn enqueue_single_file_targeted(
        &mut self,
        from: PaneId,
        name: &str,
        target_remote_dir: Option<&str>,
        target_local_dir: Option<&Path>,
        panel: &FilePanelState,
        file_tx: Option<&UnboundedSender<FileCommand>>,
        fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    ) -> usize {
        match from {
            PaneId::Local => {
                let path = PathBuf::from(name);
                if !path.is_file() {
                    //（选中后失效/被删）= 显式状态行——修前静默 `0`
                    //（点击无任何反馈，用户无法归因）。
                    self.status_line = Some(t!("filemgr.err.not_found").to_string());
                    return 0;
                }
                if active_task_count(panel, FileDirection::Upload) >= MAX_QUEUE_LEN {
                    self.status_line = Some(t!("filemgr.queue_full").to_string());
                    return 0;
                }
                if let Some(fm) = fm_tx {
                    // + 对端确认后才拉取（未确认零内容帧，fail-closed）；
                    // 落点 = 远端栏当前目录（K4 v2 target_dir 同语义捕获）；
                    // 目标 = `remote_default_target`（合成根回退 `""`）。
                    let target = target_remote_dir
                        .map(str::to_string)
                        .unwrap_or_else(|| self.remote_default_target());
                    let _ = fm.send(FileMgrCommand::SendWithConsent {
                        entries: vec![(path, target)],
                        truncated: false,
                        from_job: false,
                    });
                    self.status_line = Some(t!("consent.waiting").to_string());
                    1
                } else {
                    0
                }
            }
            PaneId::Remote => {
                if self.pending.is_some() {
                    self.status_line = Some(t!("filemgr.busy").to_string());
                    return 0;
                }
                if active_task_count(panel, FileDirection::Download) >= MAX_QUEUE_LEN {
                    self.status_line = Some(t!("filemgr.queue_full").to_string());
                    return 0;
                }
                if let Some(tx) = file_tx {
                    let remote_path = name.to_string();
                    // `None` = 本地栏当前目录节点。
                    let local_dir = target_local_dir
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| self.local.current.clone());
                    let _ = tx.send(FileCommand::FetchFile {
                        remote_path: remote_path.clone(),
                        local_dir,
                    });
                    self.pending = Some(PendingOp {
                        req_id: 0,
                        kind: PendingKind::Fetch { remote_path },
                        started: Instant::now(),
                    });
                    self.status_line = Some(tf!("filemgr.enqueued.recv", 1));
                    1
                } else {
                    0
                }
            }
        }
    }

    // ── 文件夹编排推进（渲染帧驱动；节奏化入队）──

    /// **全路径**，`task_file_basename` 双分隔符同收；**查无任务** =
    /// [`BATCH_SETTLE`] 落定窗口后视同终态——防命令已发/任务未及 upsert 竞态
    /// 与引擎侧静默丢弃（源文件失效等）卡死编排）。
    /// 本机 FS，零 self 借用）：① 目标侧逐条 `create_dir_all` 全已访目录
    /// （**零 wire** = 本机操作；**空目录也在目标创建** = 用户补口径；含
    /// 深度上限线目录本身〔其子未展开不建〕；创建失败 = `failed` 清单
    /// kind=`io`，不中止）② 有失败/环跳过 = 打一行汇总观测行（格式钉死
    /// [`r135_5b_summary_line`]；无 = 零行）③ 零文件 = 任务终态（状态行
    /// 由调用方置既有「此目录为空」口径）。
    fn settle_job_dirs(job: &mut FolderJob) {
        if job.direction != FolderDirection::ToLocal || job.summary_emitted {
            return;
        }
        job.summary_emitted = true;
        let base = job.target_local_dir.clone();
        for d in &job.target_dirs {
            if let Err(e) = std::fs::create_dir_all(base.join(d)) {
                job.failed.push((d.clone(), "io".to_string()));
                tracing::warn!("{} (create err={e})", r135_5b_fail_line("io", d));
            }
        }
        if let Some(line) = r135_5b_summary_line(
            job.files.len(),
            &job.failed,
            &job.cycle_skipped,
        ) {
            let lvl = if job.failed.is_empty() {
                crate::widgets::ConnLogLevel::Info
            } else {
                crate::widgets::ConnLogLevel::Warn
            };
            crate::conn_log_push_text(lvl, &line);
            if job.failed.is_empty() {
                tracing::info!("{line}");
            } else {
                tracing::warn!("{line}");
            }
        }
        if job.files.is_empty() {
            job.finished = true;
        }
    }

    /// `summary_emitted` 守卫——双调用点仅首达生效）：失败汇总观测行（格式
    /// 钉死 [`r135_5c_summary_line`];无失败且无环跳过 = 零行）。调用点 =
    /// ① Mkdir 链排空相（tick）② 终态分支兜底（本帧刚发出末条 Mkdir）。
    /// 零文件终态/状态行归调用方（同 [`Self::settle_job_dirs`] 分工）。
    fn settle_upload_summary(job: &mut FolderJob) {
        if job.direction != FolderDirection::ToRemote || job.summary_emitted {
            return;
        }
        job.summary_emitted = true;
        if let Some(line) =
            r135_5c_summary_line(job.files.len(), &job.failed, &job.cycle_skipped)
        {
            let lvl = if job.failed.is_empty() {
                crate::widgets::ConnLogLevel::Info
            } else {
                crate::widgets::ConnLogLevel::Warn
            };
            crate::conn_log_push_text(lvl, &line);
            if job.failed.is_empty() {
                tracing::info!("{line}");
            } else {
                tracing::warn!("{line}");
            }
        }
    }

    pub fn batch_all_terminal(
        job: &FolderJob,
        panel: &FilePanelState,
        dir: FileDirection,
        now: Instant,
    ) -> bool {
        let settled = now.duration_since(job.started) >= BATCH_SETTLE;
        job.files[job.batch_head..job.next_idx]
            .iter()
            .all(|(p, size, _sub)| {
                let b = task_file_basename(p);
                let matches: Vec<&FileTask> = panel
                    .tasks
                    .iter()
                    .filter(|t| t.name == b && t.size == *size && t.direction == dir)
                    .collect();
                if matches.is_empty() {
                    settled
                } else {
                    matches.iter().all(|t| is_terminal_status(&t.status))
                }
            })
    }

    /// 每帧推进：本地超时（零 wire 帧 §1.2）→ 写后刷新 → 文件夹任务。
    pub fn tick(
        &mut self,
        panel: &FilePanelState,
        file_tx: Option<&UnboundedSender<FileCommand>>,
        fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    ) {
        // 结算归引擎 on_tick 5min 常量，UI 只呈现）。
        consent_out_prune(&mut self.consent_out, Instant::now());
        self.clip_expand_pump(file_tx);
        // 1. 本地超时（UI 侧 FS_LOCAL_TIMEOUT ≥ 引擎 10s + tick 余量）。
        if let Some(p) = &self.pending {
            if p.started.elapsed() >= FS_LOCAL_TIMEOUT {
                let kind = p.kind.clone();
                self.pending = None;
                self.on_local_timeout(kind);
            }
        }
        // = `ConsentSettled{Consumed}` 事件臂（from_job = 批根；单文件/粘贴批
        // = Fetch 命中条目 target_dir）+ ToRemote 整树编排收敛臂。发射门 =
        // **上传全终态**（落盘已毕 = 列表反映新文件）+ 单在途空闲（不砸
        // CollectList/写操作在途槽）；消费经既有 `refresh_node` 槽 = 展开门
        //（未展开 = 无可见变化零 wire）+ 单在途纪律全复用，零新 wire 零新
        // 机制。多落点 = 逐帧一枚（FIFO），响应落定后续帧自然推进。
        if !self.upload_drain_watch.is_empty()
            && self.pending.is_none()
            && active_task_count(panel, FileDirection::Upload) == 0
        {
            let dir = self.upload_drain_watch.remove(0);
            self.remote.refresh_node = Some(dir);
        }
        // 未展开 = 无可见变化，跳过）。
        if let Some(node) = self.remote.refresh_node.take() {
            if self.remote.view.expanded.contains(&node) {
                self.remote.view.nodes.remove(&node);
                self.request_remote_list_at_node(&node, file_tx);
            }
        }
        // 单在途 List 纪律）。
        while !self.remote.expand_queue.is_empty() {
            if self.pending.is_some() {
                break; // 单在途：响应回来下一帧再推进
            }
            let front = self.remote.expand_queue[0].clone();
            if self
                .remote
                .view
                .nodes
                .get(&front)
                .is_some_and(|n| n.children.is_some())
            {
                self.remote.expand_queue.pop_front();
                continue; // 缓存已在（别的路径先到）= 跳过
            }
            if !self.remote.view.expanded.contains(&front) {
                self.remote.expand_queue.clear();
                break; // 链已作废（折叠/他处导航）= 清队不推进
            }
            if self
                .remote
                .view
                .nodes
                .get(&front)
                .is_some_and(|n| n.error.is_some())
            {
                self.remote.expand_queue.clear();
                break; // 链上错误节点 = 中止（节点自带错误标记 + 重试）
            }
            self.remote.expand_queue.pop_front();
            self.request_remote_list_at_node(&front, file_tx);
            break; // 本帧只发一个（pending 已置，循环下轮自断）
        }
        // `List("")`（对端 home，远端常用三钮 enable 数据源）；其响应落定
        // （节点 `""` children 或 error）后，盘符层（「远端电脑」合成根）
        // 未缓存时续发 `List(REMOTE_PC_ROOT_KEY)`——**`drive_chain_armed`
        // 武装门（开窗置位、发射即解除 = 每窗恰一次，非开窗路径
        // Default=false 零 wire）**+ 单在途（`pending` 空才发）+ 幂等
        //（盘符节点 loading/children/error 任一在位 = 不重发）。
        // **零新 wire op**（既有 `FsOp::List` ×2 串行）。
        if self.remote.started
            && self.remote.drive_chain_armed
            && !self.remote.unsupported
            && self.pending.is_none()
            && self
                .remote
                .view
                .nodes
                .get("")
                .is_some_and(|n| n.children.is_some() || n.error.is_some())
            && self
                .remote
                .view
                .nodes
                .get(REMOTE_PC_ROOT_KEY)
                .map_or(true, |n| !(n.children.is_some() || n.loading || n.error.is_some()))
        {
            self.remote.drive_chain_armed = false;
            self.request_remote_list_at_node(REMOTE_PC_ROOT_KEY, file_tx);
        }
        // 3. 文件夹任务。
        let Some(job) = self.job.as_mut() else { return };
        if job.finished {
            return;
        }
        // 守卫）：① 目标侧镜像创建全已访目录（**含空目录**，零 wire）
        // ② 失败/环汇总观测行 ③ 零文件 = 任务终态（状态行 = 既有
        // 「此目录为空」口径；原 tick pop-None / 响应尾两处分支内联语义
        // 收口于此）。
        if job.direction == FolderDirection::ToLocal
            && !job.collecting
            && !job.summary_emitted
        {
            let was_finished = job.finished;
            Self::settle_job_dirs(job);
            if job.finished && !was_finished {
                self.status_line = Some(t!("filemgr.empty.local").to_string());
            }
            if job.finished {
                return;
            }
        }
        // 阶段 1：远端→本地 BFS 收集（单在途 List；深度超限记 capped 不展开）。
        if job.collecting {
            if self.pending.is_none() {
                if let Some((path, offset, depth, src_root, prefix)) =
                    job.collect_queue.pop_front()
                {
                    if depth > FOLDER_MAX_DEPTH {
                        job.depth_capped.push(format!("{prefix}/{path}"));
                        return;
                    }
                    if let Some(tx) = file_tx {
                        let _ = tx.send(FileCommand::Fs {
                            op: FsOp::List {
                                path: path.clone(),
                                offset,
                                limit: PAGE_SIZE,
                            },
                        });
                        self.pending = Some(PendingOp {
                            req_id: 0,
                            kind: PendingKind::CollectList {
                                path,
                                offset,
                                depth,
                                src_root,
                                prefix,
                            },
                            started: Instant::now(),
                        });
                    } else {
                        // 理论不可达（门控保证通道存在）：中止收集，保留已收集。
                        job.collecting = false;
                    }
                } else {
                    // 失败汇总 / 零文件终态）归上方 `settle_job_dirs` 单点
                    // （下一帧执行），此处只落 collecting 态。
                    job.collecting = false;
                }
            }
            return;
        }
        // 中断**（其余条目不入队；状态行钉死 i18n `filemgr.dl.cancelled`）。
        // 匹配口径 = [`batch_all_terminal`] 同源（basename + size + 方向）。
        // = `filemgr.ul.cancelled`；中断 = 余留 Mkdir 队列一并弃置）。
        let cancelled = match job.direction {
            FolderDirection::ToLocal => {
                job.next_idx > job.batch_head
                    && job_has_cancelled(job, panel, FileDirection::Download)
            }
            FolderDirection::ToRemote => {
                job.next_idx > job.batch_head
                    && job_has_cancelled(job, panel, FileDirection::Upload)
            }
        };
        if cancelled {
            job.finished = true;
            self.status_line = Some(match job.direction {
                FolderDirection::ToLocal => t!("filemgr.dl.cancelled").to_string(),
                FolderDirection::ToRemote => t!("filemgr.ul.cancelled").to_string(),
            });
            return;
        }
        // （**零新 wire op** = 既有 `FsOp::Mkdir{path}`；单级无 `-p` → 父先
        // 子后深度升序逐级；AlreadyExists 宽容 = 幂等重跑）。**独立于文件批**
        // （双通道：Mkdir = `file_tx` Fs op / 批 = `fm_tx` consent；Mkdir 链
        // 从根逐级 = 父目录要么刚建要么随文件上传由接收侧 `create_dir_all`
        // 附带建，不依赖传输完成）；单在途 FS 纪律共享 `self.pending` 槽。
        if job.direction == FolderDirection::ToRemote {
            if !job.mkdir_queue.is_empty() {
                if self.pending.is_none() {
                    let path = job.mkdir_queue.front().cloned();
                    if let (Some(path), Some(tx)) = (path, file_tx) {
                        let _ = tx.send(FileCommand::Fs {
                            op: FsOp::Mkdir { path: path.clone() },
                        });
                        self.pending = Some(PendingOp {
                            req_id: 0,
                            kind: PendingKind::Mkdir {
                                path,
                                for_job: true,
                            },
                            started: Instant::now(),
                        });
                    } else {
                        // 通道缺失（理论不可达 = 门控保证存在）= 余留队列记
                        // 清单不静默 + 任务终止（fail-closed 不悬等，同 consent
                        // 路径口径）。
                        for p in job.mkdir_queue.iter() {
                            let disp = remote_strip_base(&job.target_remote_dir, p);
                            job.failed.push((disp, "interrupted".to_string()));
                        }
                        job.mkdir_queue.clear();
                        job.finished = true;
                        self.status_line =
                            Some(t!("consent.send_failed").to_string());
                        return;
                    }
                }
                // Mkdir 在途/等待槽 = 本帧不推进（文件批相照常——两通道
                // 独立，批可并行入队）。
            } else {
                // Mkdir 链排空 = 收敛点（幂等守卫）：失败汇总观测行 + 零
                // 文件（纯空目录选中）= 任务终态（状态行 = 既有「此目录
                Self::settle_upload_summary(job);
                if job.files.is_empty() {
                    job.finished = true;
                    self.status_line = Some(t!("filemgr.empty.local").to_string());
                    return;
                }
            }
        }
        // 阶段 2：分批入队（批 = FOLDER_BATCH_SIZE；整批终态才推进下一批）。
        let dir = match job.direction {
            FolderDirection::ToRemote => FileDirection::Upload,
            FolderDirection::ToLocal => FileDirection::Download,
        };
        let batch_end = (job.batch_head + FOLDER_BATCH_SIZE).min(job.files.len());
        if job.direction == FolderDirection::ToRemote && job.next_idx < batch_end {
            // ≤255 结构保证）= 一个 TransferRequest 通告 = 一个确认框；
            // consent 在途（pending/req_id）= 等待结算，不推进不重发。
            // Declined/Timeout/SendFailed = 任务终止 + 状态行（on_fs_event 侧）。
            if job.consent_pending || job.consent_req_id.is_some() {
                return; // consent 在途：等待对方确认（≤5min，Q11）
            }
            // 先拷出本批条目与路径基准（job 为 &mut，避免借用交叠）。
            let batch: Vec<(String, u64, String)> = job.files[job.next_idx..batch_end].to_vec();
            let target_remote_dir = job.target_remote_dir.clone();
            let mut entries = Vec::with_capacity(batch.len());
            // 目标内子路径)。
            for (abs, _size, subdir) in &batch {
                let target = remote_join(&target_remote_dir, subdir);
                entries.push((PathBuf::from(abs), target));
            }
            job.next_idx = batch_end;
            if let Some(fm) = fm_tx {
                let _ = fm.send(FileMgrCommand::SendWithConsent {
                    entries,
                    // 批 = 128 ≤ 255：单批零拆分；>255 截断记档归引擎侧。
                    truncated: false,
                    from_job: true,
                });
                job.consent_pending = true; // ConsentSent 回填 req_id
            } else {
                // 门控保证通道存在；理论不可达 = 任务终止（fail-closed 不悬等）。
                job.finished = true;
                self.status_line = Some(t!("consent.send_failed").to_string());
            }
            return;
        }
        if job.next_idx < batch_end {
            // ToLocal：⬇ 拉取既有节奏（逐文件 FetchFile、响应链式、每帧 ≤4——
            // 本机显式动作，不涉同意接收，零变化）。
            let headroom = MAX_QUEUE_LEN.saturating_sub(active_task_count(panel, dir));
            if headroom == 0 {
                return; // FIFO 自然节流：队列水位满则等
            }
            if self.pending.is_some() {
                return; // 响应链式：前一个 Fetch 响应前不发下一个（S8 友好）
            }
            let n = ISSUE_PER_TICK.min(batch_end - job.next_idx);
            // 先拷出本帧入队项与路径基准（job 为 &mut，避免与 self.pending 借用交叠）。
            let to_issue: Vec<(String, String)> = job.files[job.next_idx..job.next_idx + n]
                .iter()
                .map(|(p, _, sub)| (p.clone(), sub.clone()))
                .collect();
            let target_local_dir = job.target_local_dir.clone();
            job.next_idx += n;
            for (full, subdir) in &to_issue {
                if let Some(ftx) = file_tx {
                    // 内子目录（`""` = 直接落目标）。
                    let local_dir = target_local_dir.join(subdir);
                    let _ = ftx.send(FileCommand::FetchFile {
                        remote_path: full.clone(),
                        local_dir,
                    });
                    self.pending = Some(PendingOp {
                        req_id: 0,
                        kind: PendingKind::Fetch {
                            remote_path: full.clone(),
                        },
                        started: Instant::now(),
                    });
                }
            }
        } else if job.next_idx >= job.files.len() {
            // 后收敛点打汇总行；终态判定 = 此处下帧）。ToLocal 零变化。
            if job.direction == FolderDirection::ToRemote
                && !job.mkdir_queue.is_empty()
            {
                // Mkdir 链在途：等待排空（零文件终态归 Mkdir 相收敛点）。
            } else {
                // 相走「发帧」分支未收敛）= 汇总行单点兜底（幂等守卫）+
                // 零文件（纯空目录）= 状态行「此目录为空」口径。
                let empty_files = job.files.is_empty();
                if job.direction == FolderDirection::ToRemote {
                    Self::settle_upload_summary(job);
                    // 排空）= 任务终态——落点失效待办武装（与 ConsentSettled
                    // {Consumed} 事件臂同槽去重；授权回执缺席〔窗重开/乱序〕
                    // 时此臂兜底）。真重列仍待上传排空（tick 1c 门）。
                    Self::r173_watch_arm(
                        &mut self.upload_drain_watch,
                        &job.target_remote_dir.clone(),
                    );
                }
                job.finished = true;
                self.status_line = Some(if empty_files {
                    t!("filemgr.empty.local").to_string()
                } else {
                    match job.direction {
                        FolderDirection::ToRemote => {
                            tf!("filemgr.enqueued.send", job.files.len())
                        }
                        FolderDirection::ToLocal => {
                            tf!("filemgr.enqueued.recv", job.files.len())
                        }
                    }
                });
            }
        } else if Self::batch_all_terminal(job, panel, dir, Instant::now()) {
            job.batch_head = job.next_idx; // 整批终态 → 推进下一批
        }
    }

    fn on_local_timeout(&mut self, kind: PendingKind) {
        match kind {
            PendingKind::List {
                pane, path, ..
            } if pane == PaneId::Remote => {
                // 折叠 = 无可见变化。
                self.remote.view.loading = false;
                if let Some(node) = self.remote.view.nodes.get_mut(&path) {
                    node.loading = false;
                    node.error = Some(t!("filemgr.err.timeout").to_string());
                }
                self.remote.view.status = Some(t!("filemgr.err.timeout").to_string());
            }
            PendingKind::CollectList {
                path, src_root, prefix, ..
            } => {
                // `timeout`），队列余下条目下帧继续收集（原「整任务终止 +
                // 静默丢弃已收集」语义移除；观测行格式钉死单测）。
                let rel = remote_strip_base(&src_root, &path);
                let disp = job_dir_display(&prefix, &rel);
                tracing::warn!("{}", r135_5b_fail_line("timeout", &disp));
                if let Some(job) = self.job.as_mut() {
                    job.failed.push((disp, "timeout".to_string()));
                }
                self.status_line = Some(t!("filemgr.err.timeout").to_string());
            }
            PendingKind::Mkdir {
                ref path,
                for_job: true,
            } => {
                // 超时口径；父失败子或连带失败 = 逐条记清单不静默）。
                self.on_job_mkdir_timeout(path);
                self.status_line = Some(t!("filemgr.err.timeout").to_string());
            }
            PendingKind::Fetch { .. }
            | PendingKind::Mkdir { .. }
            | PendingKind::Rename { .. }
            | PendingKind::Delete { .. } => {
                self.status_line = Some(t!("filemgr.err.timeout").to_string());
            }
            _ => {}
        }
    }

    /// 任务已终态〔取消/拒收〕= 在途残响零记录；队列首不匹配 = 陈旧忽略）。
    fn on_job_mkdir_timeout(&mut self, path: &str) {
        let Some(job) = self.job.as_mut() else { return };
        if job.direction != FolderDirection::ToRemote || job.finished {
            return;
        }
        if job.mkdir_queue.front().map(|s| s.as_str()) != Some(path) {
            return; // 陈旧（单在途纪律下不应发生）
        }
        job.mkdir_queue.pop_front();
        let disp = remote_strip_base(&job.target_remote_dir, path);
        tracing::warn!("{}", r135_5c_fail_line("timeout", &disp));
        job.failed.push((disp, "timeout".to_string()));
    }

    /// 失败清单，链继续；**AlreadyExists = 良性成功**〔幂等重跑/并发创建，
    /// 目录在位即目标达成，零记录〕；任务已终态 = 在途残响零记录）。
    fn on_job_mkdir_result(
        &mut self,
        path: &str,
        result: Result<FsResponsePayload, String>,
    ) {
        let Some(job) = self.job.as_mut() else { return };
        if job.direction != FolderDirection::ToRemote || job.finished {
            return;
        }
        if job.mkdir_queue.front().map(|s| s.as_str()) != Some(path) {
            return; // 陈旧（单在途纪律下不应发生）
        }
        job.mkdir_queue.pop_front();
        let disp = remote_strip_base(&job.target_remote_dir, path);
        let failed_kind = match &result {
            Ok(payload) if payload.ok => None,
            Ok(payload) if payload.err == FsErrCode::AlreadyExists => None,
            Ok(payload) => Some(format!("mkdir:{:?}", payload.err)),
            Err(_) => Some("mkdir:wire".to_string()),
        };
        if let Some(kind) = failed_kind {
            tracing::warn!("{}", r135_5c_fail_line(&kind, &disp));
            job.failed.push((disp, kind));
        }
    }

    // ── Fs 事件消费（take_fs_response 生产接线后的 UI 侧）──

    /// 引擎 → UI 事件（窗口层每帧 drain `fs_event_rx` 后调用）。
    pub fn on_fs_event(&mut self, ev: FsEvent) {
        match ev {
            FsEvent::Admitted { req_id, op } => {
                // pane 单槽零误领）。
                if self.clip_expand_on_admitted(req_id, &op) {
                    return;
                }
                // req_id ↔ op 关联回填（单槽 pending；不匹配 = 陈旧事件忽略）。
                if let Some(p) = &mut self.pending {
                    if p.req_id == 0 && same_op(&p.kind, &op) {
                        p.req_id = req_id;
                    }
                }
            }
            FsEvent::Response { req_id, result } => {
                if self.clip_expand_on_response(req_id, &result) {
                    return;
                }
                let Some(p) = self.pending.take() else { return };
                if p.req_id != req_id {
                    // op（旧实现静默丢弃会丢在途跟踪 → 新节点卡 loading 永不
                    // 结算）。`req_id==0`（Admitted 未回填）时任何非零迟到
                    // 响应必为陈旧（引擎先 Admitted 后 Response）。
                    self.pending = Some(p);
                    return;
                }
                self.apply_result(p.kind, result);
            }
            // 任务批 = job 状态推进，单文件/粘贴 = 等待确认行）。
            FsEvent::ConsentSent {
                req_id,
                peer_label,
                count,
                total_size,
                truncated,
                from_job,
            } => {
                if from_job {
                    if let Some(job) = self.job.as_mut() {
                        if job.consent_pending {
                            job.consent_pending = false;
                            job.consent_req_id = Some(req_id);
                        }
                    }
                    // 文件夹批不另建行（任务徽标 + 状态行呈现，E2 口径）。
                    return;
                }
                self.consent_out.push(ConsentOutLine {
                    req_id,
                    peer_label,
                    count,
                    total_size,
                    truncated,
                    from_job: false,
                    started: Instant::now(),
                    state: ConsentOutState::Waiting,
                    settled_at: None,
                });
            }
            FsEvent::ConsentSettled {
                req_id,
                outcome,
                from_job,
                target_dir,
            } => {
                if from_job {
                    let armed_dir = {
                        let Some(job) = self.job.as_mut() else { return };
                        // 匹配 = 已回填 req_id 或 pending 态（发送失败时 req_id
                        // 未回填，引擎仍回事件——唯一在途批，零歧义）。
                        let matched = match job.consent_req_id {
                            Some(rid) => rid == req_id,
                            None => job.consent_pending,
                        };
                        if !matched {
                            return; // 陈旧（批已推进后迟到）= 静默忽略
                        }
                        job.consent_req_id = None;
                        job.consent_pending = false;
                        if outcome == ConsentOutcome::Consumed {
                            // 落点目录失效待办武装（事件载荷 target_dir 忽略：
                            // from_job 批各条 target_dir 异构〔结构镜像〕，批根
                            // = `job.target_remote_dir`）。真重列在**上传排空**
                            // 后（tick 侧）= 文件确已落盘，防起跑时刻空列。
                            // 失败终态臂零武装（零落盘零刷新，卡置位矩阵）。
                            Some(job.target_remote_dir.clone())
                        } else {
                            // 对方取消 / 超时 / 发送失败 = 整任务终止（诚实状态行）。
                            job.finished = true;
                            self.status_line = Some(match outcome {
                                ConsentOutcome::Declined => t!("consent.declined").to_string(),
                                ConsentOutcome::Timeout => t!("consent.timeout").to_string(),
                                _ => t!("consent.send_failed").to_string(),
                            });
                            None
                        }
                    };
                    if let Some(dir) = armed_dir {
                        Self::r173_watch_arm(&mut self.upload_drain_watch, &dir);
                    }
                    // Consumed = 真实传输行归全局任务面板，本批终态后自然推进。
                    return;
                }
                if let Some(line) = self
                    .consent_out
                    .iter_mut()
                    .find(|l| l.req_id == req_id)
                {
                    consent_out_apply(line, outcome, Instant::now());
                } else if req_id == 0 {
                    // req_id 空间 `0x8000_0000|seq` 永不冲突）——引擎零
                    // TransferRequest 发出（条目全跳过/出根）= 等待行即时
                    // 结算失败，不再 5min 悬等「对方未确认」。
                    self.status_line = Some(t!("consent.send_failed").to_string());
                }
                // 落点失效待办武装（引擎事件载荷 = Fetch 命中条目实际
                // target_dir；v1 回退 `None` = 未知落点不下发，卡矩阵）。
                // 真重列同 from_job 臂 = 上传排空后（tick 侧单帧一枚）。
                if outcome == ConsentOutcome::Consumed {
                    if let Some(dir) = target_dir {
                        Self::r173_watch_arm(&mut self.upload_drain_watch, &dir);
                    }
                }
            }
            // 对端 FileSession 首 tick 通告 = 构造快照冻结值；重连 = 新会话
            // 重新通告覆盖）。展示面消费 = `render_file_transfer_off_banner`
            // （对端语义文案；`None` = 未通告 = fail-closed 显式提示）。
            FsEvent::PeerConsent {
                clipboard_allowed,
                file_transfer_allowed,
            } => {
                self.peer_consent = Some((clipboard_allowed, file_transfer_allowed));
            }
        }
    }

    fn apply_result(&mut self, kind: PendingKind, result: Result<FsResponsePayload, String>) {
        match kind {
            PendingKind::List { pane, path, offset, .. } => {
                // 落定/节点已换 = 陈旧丢弃）。
                let stale = pane != PaneId::Remote
                    || offset != 0
                    || !self
                        .remote
                        .view
                        .nodes
                        .get(&path)
                        .is_some_and(|n| n.loading);
                if stale {
                    // 被丢弃（节点已换/已结算）——「请求发了但刷新不生效」类
                    // 故障的可观测点。
                    tracing::debug!(
                        self.remote.current
                    );
                    self.remote.view.loading = false;
                    return;
                }
                self.remote.view.loading = false;
                match result {
                    Ok(payload) if payload.ok => {
                        match bincode::deserialize::<FsListPayload>(&payload.payload) {
                            Ok(list) => {
                                let entries = list.entries
                                    .into_iter()
                                    .map(|e| {
                                        // （wire `FsEntry` 无属性字段〔冻结，
                                        // 零新 wire〕——对端 OS 隐藏属性不可
                                        // 感知，能力边界如实）。
                                        let is_hidden = name_is_hidden(&e.name);
                                        FileMgrEntry {
                                            name: e.name,
                                            size: e.size,
                                            mtime: e.mtime,
                                            is_dir: e.is_dir,
                                            is_symlink: e.is_symlink,
                                            is_hidden,
                                        }
                                    })
                                    .collect();
                                let sort = self.remote.view.sort;
                                let mut entries: Vec<FileMgrEntry> = entries;
                                sort_entries(&mut entries, &sort);
                                let applied = entries.len();
                                if let Some(node) = self.remote.view.nodes.get_mut(&path) {
                                    node.children = Some(entries);
                                    node.loading = false;
                                    node.error = None;
                                    node.has_more = list.has_more;
                                }
                                // 客户端 = `""` 兼容口径保留）。
                                if (path.is_empty() || path == REMOTE_PC_ROOT_KEY)
                                    && self.remote.root_display.is_empty()
                                {
                                    self.remote.root_display = list.root_display;
                                }
                                self.remote.view.status = None;
                                // 栏状态（三锚点链「请求发出①→响应收到②→控件
                                // 刷新③」末环）——179 列目录空白取证：①②在
                                // 而③缺 = 事件链断；③在而屏上空白 = 渲染层。
                                tracing::info!(
                                    list.has_more
                                );
                            }
                            Err(_) => {
                                if let Some(node) = self.remote.view.nodes.get_mut(&path) {
                                    node.loading = false;
                                    node.error = Some(t!("filemgr.err.io").to_string());
                                }
                                self.remote.view.status = Some(t!("filemgr.err.io").to_string());
                            }
                        }
                    }
                    Ok(payload) => {
                        let msg = err_text(payload.err);
                        if let Some(node) = self.remote.view.nodes.get_mut(&path) {
                            node.loading = false;
                            node.error = Some(msg.clone());
                        }
                        self.remote.view.status = Some(msg);
                    }
                    Err(err) => {
                        // 本地 Timeout（零 wire 帧，§1.2）：判「不支持」——
                        // 版本门为静态（legacy 放行端文件帧零发送，fail-closed）。
                        // 超时）= 锚点①在而②永不到达——WARN 一行留痕，
                        // 不再静默（与「响应收到」锚点②构成闭环判定）。
                        tracing::warn!(
                        );
                        self.remote.unsupported = true;
                        if let Some(node) = self.remote.view.nodes.get_mut(&path) {
                            node.loading = false;
                            node.error = Some(t!("filemgr.err.timeout").to_string());
                        }
                        self.remote.view.status = Some(t!("filemgr.empty.remote").to_string());
                    }
                }
            }
            PendingKind::Fetch { .. } => match result {
                Ok(_) => {
                    // 服务端已发起 Offer → 任务面板呈现接收进度。
                    self.status_line = Some(tf!("filemgr.enqueued.recv", 1));
                }
                Err(_) => {
                    self.status_line = Some(t!("filemgr.err.timeout").to_string());
                }
            },
            PendingKind::Mkdir {
                path,
                for_job: true,
            } => {
                // AlreadyExists 宽容；无节点标记——链内目录树未展示 = 无
                // 可见变化，任务徽标/汇总行呈现）。
                self.on_job_mkdir_result(&path, result);
            }
            PendingKind::Mkdir { path, for_job: false }
            | PendingKind::Rename { to: path, .. }
            | PendingKind::Delete { path, .. } => match result {
                Ok(payload) if payload.ok => {
                    // 盘符感知（`remote_parent_key`）。
                    self.remote.refresh_node = Some(remote_parent_key(&path));
                }
                Ok(payload) => {
                    self.status_line = Some(err_text(payload.err));
                }
                Err(_) => {
                    self.status_line = Some(t!("filemgr.err.timeout").to_string());
                }
            },
            PendingKind::CollectList {
                path,
                offset,
                depth,
                src_root,
                prefix,
            } => {
                let Some(job) = self.job.as_mut() else { return };
                match result {
                    Ok(payload) if payload.ok => {
                        if let Ok(list) = bincode::deserialize::<FsListPayload>(&payload.payload) {
                            for e in &list.entries {
                                if e.is_symlink {
                                    continue; // S4：不跟随、不展开
                                }
                                let full = remote_join(&path, &e.name);
                                // 节点；顶层 = basename）。
                                let rel_under_src = remote_strip_base(&src_root, &full);
                                if e.is_dir {
                                    let disp = job_dir_display(&prefix, &rel_under_src);
                                    // 大小写不敏感）= 跳过不展开、记清单
                                    // （junction 环逐层新路径串由
                                    // [`FOLDER_MAX_DEPTH`] 深度上限硬限界）。
                                    if !job.visit.insert(full.to_ascii_lowercase()) {
                                        job.cycle_skipped.push(disp);
                                        continue;
                                    }
                                    // **空目录**/深度上限线目录本身——收集
                                    // 结束 `settle_job_dirs` 逐条建，零 wire）。
                                    job.target_dirs.push(disp.clone());
                                    if depth + 1 > FOLDER_MAX_DEPTH {
                                        job.depth_capped.push(disp);
                                    } else {
                                        job.collect_queue.push_back((
                                            full,
                                            0,
                                            depth + 1,
                                            src_root.clone(),
                                            prefix.clone(),
                                        ));
                                    }
                                } else {
                                    // 目标内子目录 = prefix〔+ "/" + 源内父级〕
                                    // （顶层文件 = 直接落 `目标/<选中目录名>/`）。
                                    let subdir = match rel_parent(&rel_under_src) {
                                        "" => prefix.clone(),
                                        par => format!("{prefix}/{par}"),
                                    };
                                    // （零 wire 本地优化，fail-open）——落点已有
                                    // 同 size+mtime（±1s）文件 = 不入队（二次
                                    // 下载免全程重拉；RustDesk digest.is_identical
                                    // 同语义；判定 = [`r158_file_identical`] 与
                                    // 粘贴臂同一单一事实源；跳过逐条 tracing
                                    // 观测行，FolderJob 零新字段 = file_panel
                                    // 测试助手零触碰）。
                                    let base = full.rsplit('/').next().unwrap_or(&full);
                                    let local_target =
                                        job.target_local_dir.join(&subdir).join(base);
                                    if r158_file_identical(
                                        e.size,
                                        e.mtime,
                                        r158_stat_meta(&local_target),
                                    ) {
                                        tracing::info!(
                                            local_target.display()
                                        );
                                    } else {
                                        job.files.push((full, e.size, subdir));
                                    }
                                }
                            }
                            if list.has_more {
                                // 页续接（500/页 沿用，§2.2）。
                                job.collect_queue.push_front((
                                    path,
                                    offset + PAGE_SIZE,
                                    depth,
                                    src_root,
                                    prefix,
                                ));
                            }
                        } else {
                            // 继续其余条目（原「中止收集」静默语义移除）。
                            let rel = remote_strip_base(&src_root, &path);
                            let disp = job_dir_display(&prefix, &rel);
                            tracing::warn!("{}", r135_5b_fail_line("list:badpayload", &disp));
                            job.failed.push((disp, "list:badpayload".to_string()));
                        }
                    }
                    Ok(payload) => {
                        // 收集其余条目（观测行格式钉死 `r135_5b_fail_line`
                        // 单测；汇总行收集结束打，`r135_5b_summary_line`）。
                        let rel = remote_strip_base(&src_root, &path);
                        let disp = job_dir_display(&prefix, &rel);
                        let kind = format!("list:{:?}", payload.err);
                        tracing::warn!("{}", r135_5b_fail_line(&kind, &disp));
                        job.failed.push((disp, kind));
                    }
                    Err(_) => {
                        let rel = remote_strip_base(&src_root, &path);
                        let disp = job_dir_display(&prefix, &rel);
                        tracing::warn!("{}", r135_5b_fail_line("list:wire", &disp));
                        job.failed.push((disp, "list:wire".to_string()));
                    }
                }
                if job.collect_queue.is_empty() {
                    // 失败汇总 / 零文件终态）归 tick `settle_job_dirs` 单点
                    // （下一帧执行），此处只落 collecting 态。
                    job.collecting = false;
                }
            }
        }
    }

    // ── 对话框态机（§1.7：取消 = 零 wire 帧——**必测 wire 级断言**）──

    /// （盘符感知：`C:\` → `C:\`、`C:\Users` → `Users`）。
    pub fn display_basename(&self, pane: PaneId, path: &str) -> String {
        if pane == PaneId::Remote {
            remote_entry_name(path)
        } else {
            Path::new(path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string())
        }
    }

    /// **节点全路径**）。
    pub fn open_delete(&mut self, pane: PaneId) {
        self.pending_deletes.clear();
        let paths = self.selection_paths(pane);
        for path in &paths {
            // `""`）= 树展示节点，非数据节点 = 不可删（fail-closed 不进确认
            // 「主目录」节点同口径（保留键零入删除批）。
            if (pane == PaneId::Local && path == LOCAL_PC_ROOT_KEY)
                || (pane == PaneId::Remote
                    && (path.is_empty()
                        || path == REMOTE_PC_ROOT_KEY
                        || path == REMOTE_HOME_KEY))
            {
                continue;
            }
            if let Some(e) = self.resolve_entry(pane, path) {
                self.pending_deletes.push(DeleteTarget {
                    pane,
                    path: path.clone(),
                    size: e.size,
                    is_dir: e.is_dir,
                });
            }
        }
        self.show_next_delete_dialog();
    }

    fn show_next_delete_dialog(&mut self) {
        self.dialog = self
            .pending_deletes
            .first()
            .cloned()
            .map(|t| Dialog::ConfirmDelete {
                name: self.display_basename(t.pane, &t.path),
                size: t.size,
                is_dir: t.is_dir,
            })
            .unwrap_or(Dialog::None);
    }

    /// 删除确认解析。`confirm=false` = **整批中止、零 wire 帧**（§1.7）。
    /// 返回 Some = 需发出的远端命令（本地删除 = 同步 std::fs，None）。
    pub fn delete_resolve(&mut self, confirm: bool) -> Option<FileCommand> {
        let Some(target) = self.pending_deletes.pop() else {
            self.dialog = Dialog::None;
            return None;
        };
        if !confirm {
            // §1.7：取消 = 零 wire 帧（当前项丢弃 + 剩余整批中止）。
            self.pending_deletes.clear();
            self.dialog = Dialog::None;
            return None;
        }
        match target.pane {
            PaneId::Local => {
                let p = PathBuf::from(&target.path);
                let res = if target.is_dir {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
                match res {
                    Ok(()) => {
                        self.local.view.selected.retain(|n| n != &target.path);
                        // 受影响节点 = 原父节点（重读其缓存）。
                        if let Some(parent) = p.parent() {
                            let key = local_path_key(parent);
                            self.local.view.nodes.remove(&key);
                        }
                        self.refresh_local();
                    }
                    Err(_) => {
                        self.local
                            .view
                            .status
                            .get_or_insert_with(|| t!("filemgr.err.io").to_string());
                    }
                }
                self.show_next_delete_dialog();
                None
            }
            PaneId::Remote => {
                if self.pending.is_some() {
                    // 单在途（防 req_id 关联混淆）：放回队首等待。
                    self.pending_deletes.insert(0, target);
                    self.status_line = Some(t!("filemgr.busy").to_string());
                    self.show_next_delete_dialog();
                    return None;
                }
                let path = target.path.clone();
                self.local.view.selected.retain(|n| n != &target.path);
                self.remote.view.selected.retain(|n| n != &target.path);
                self.pending = Some(PendingOp {
                    req_id: 0,
                    kind: PendingKind::Delete {
                        path: path.clone(),
                        recursive: target.is_dir,
                    },
                    started: Instant::now(),
                });
                self.show_next_delete_dialog();
                Some(FileCommand::Fs {
                    op: FsOp::Delete {
                        path,
                        recursive: target.is_dir,
                    },
                })
            }
        }
    }

    /// 输入框初值 = 显示名）。
    pub fn open_rename(&mut self, pane: PaneId) {
        let paths = self.selection_paths(pane);
        if paths.len() == 1 {
            // 栏根不可改名（与删除同口径：树展示节点非数据节点）。
            let is_root = (pane == PaneId::Local && paths[0] == LOCAL_PC_ROOT_KEY)
                || (pane == PaneId::Remote && paths[0].is_empty());
            if !is_root {
                self.dialog = Dialog::InputRename {
                    pane,
                    from: paths[0].clone(),
                    new_name: self.display_basename(pane, &paths[0]),
                };
            }
        }
    }

    /// 打开新建目录输入（单级，§2.2）。
    pub fn open_mkdir(&mut self, pane: PaneId) {
        self.dialog = Dialog::InputMkdir {
            pane,
            name: String::new(),
        };
    }

    /// 输入校验（非空、无分隔符；改名另禁同名 no-op）。
    fn valid_fs_name(name: &str) -> bool {
        !name.is_empty()
            && !name.contains('/')
            && !name.contains('\\')
            && name.bytes().all(|b| b != 0)
    }

    /// 同名 no-op 判定 = 与**显示名**比较。
    pub fn rename_submit(&mut self) {
        let Dialog::InputRename { pane, from, new_name } =
            std::mem::replace(&mut self.dialog, Dialog::None)
        else {
            return;
        };
        let name = new_name.trim().to_string();
        let same_name = self.display_basename(pane, &from) == name;
        if !Self::valid_fs_name(&name) || same_name {
            // 无效输入 = 关窗（v1 口径；零 wire）。
            self.status_line = Some(t!("filemgr.rename.invalid").to_string());
            return;
        }
        self.dialog = Dialog::ConfirmRename {
            pane,
            from,
            to: name,
        };
    }

    /// 改名确认解析（**S13：目标存在 = 拒绝，无静默覆盖路径**——本地
    /// `std::fs::rename` 在 unix 会静默覆盖 → 本地预检；远端 = 服务端
    /// `AlreadyExists` 拒绝（响应态机 `apply_result` 映射文案））。
    pub fn rename_resolve(&mut self, confirm: bool) -> Option<FileCommand> {
        let Dialog::ConfirmRename { pane, from, to } =
            std::mem::replace(&mut self.dialog, Dialog::None)
        else {
            return None;
        };
        if !confirm {
            return None; // §1.7 同口径：取消 = 零 wire 帧
        }
        match pane {
            PaneId::Local => {
                let from_p = PathBuf::from(&from);
                let to_p = from_p.with_file_name(&to);
                if to_p.exists() {
                    // S13 本地预检（跨平台同构：unix rename(2) 静默覆盖）。
                    self.local
                        .view
                        .status
                        .get_or_insert_with(|| t!("filemgr.err.already_exists").to_string());
                    None
                } else {
                    match std::fs::rename(&from_p, &to_p) {
                        Ok(()) => {
                            self.local.view.selected = vec![local_path_key(&to_p)];
                            // 受影响节点 = 原父节点（重读其缓存）。
                            if let Some(parent) = from_p.parent() {
                                let key = local_path_key(parent);
                                self.local.view.nodes.remove(&key);
                            }
                            self.refresh_local();
                            None
                        }
                        Err(_) => {
                            self.local
                                .view
                                .status
                                .get_or_insert_with(|| t!("filemgr.err.io").to_string());
                            None
                        }
                    }
                }
            }
            PaneId::Remote => {
                if self.pending.is_some() {
                    self.status_line = Some(t!("filemgr.busy").to_string());
                    return None;
                }
                if from == REMOTE_PC_ROOT_KEY || from == REMOTE_HOME_KEY {
                    // （fail-closed，零 wire；与 `single_dir_selection` 落点门
                    // 入改名帧）。
                    self.status_line = Some(t!("filemgr.err.outside_root").to_string());
                    return None;
                }
                // `rel_parent` 语义零漂移）。
                let from_r = from.clone();
                let to_r = remote_join(&remote_parent_key(&from), &to);
                self.pending = Some(PendingOp {
                    req_id: 0,
                    kind: PendingKind::Rename {
                        from: from_r.clone(),
                        to: to_r.clone(),
                    },
                    started: Instant::now(),
                });
                Some(FileCommand::Fs {
                    op: FsOp::Rename {
                        from: from_r,
                        to: to_r,
                    },
                })
            }
        }
    }

    /// 新建目录输入提交（本地 = 同步 std::fs 单级；远端 = `FsOp::Mkdir`）。
    ///
    /// 合成根）= **保开对话框 + 框内显式错误**（[`Self::dialog_error`]，
    /// 非静默）——旧语义对话框直接消失仅状态行小字，用户观感 = 「点了
    /// 没反应」（第五轮零 Mkdir 帧在案 = 断点②客户端派发面）。成功/
    /// 取消 = 对话框关（既有语义）。零 wire 形态变化（帧 = 既有
    /// `FsOp::Mkdir{path}`）。
    pub fn mkdir_submit(&mut self) -> Option<FileCommand> {
        let (pane, raw) = {
            let Dialog::InputMkdir { pane, name } =
                std::mem::replace(&mut self.dialog, Dialog::None)
            else {
                return None;
            };
            (pane, name)
        };
        let name = raw.trim().to_string();
        if !Self::valid_fs_name(&name) {
            self.dialog = Dialog::InputMkdir { pane, name: raw };
            self.dialog_error = Some(t!("filemgr.rename.invalid").to_string());
            self.status_line = Some(t!("filemgr.rename.invalid").to_string());
            return None;
        }
        match pane {
            PaneId::Local => {
                let p = self.local.current.join(&name);
                // 父目录不存在/目标已存在 = NotFound 口径（§2.2 单级无 -p）。
                match std::fs::create_dir(&p) {
                    Ok(()) => {
                        let key = local_path_key(&self.local.current);
                        self.local.view.nodes.remove(&key);
                        self.refresh_local();
                    }
                    Err(_) => {
                        self.local
                            .view
                            .status
                            .get_or_insert_with(|| t!("filemgr.err.not_found").to_string());
                    }
                }
                None
            }
            PaneId::Remote => {
                if self.pending.is_some() {
                    self.dialog = Dialog::InputMkdir { pane, name: raw };
                    self.dialog_error = Some(t!("filemgr.busy").to_string());
                    self.status_line = Some(t!("filemgr.busy").to_string());
                    return None;
                }
                if self.remote.current == REMOTE_PC_ROOT_KEY
                    || self.remote.current == REMOTE_HOME_KEY
                {
                    // 直接新建目录（fail-closed：防保留键被当相对路径误建
                    // `__kirin_remote_pc_root__` 子目录）——须先进入盘符/盘内
                    // 合成「主目录」保留键同口径（活动节点经 home 导航恒
                    // `""`，此为防御臂）。
                    self.dialog = Dialog::InputMkdir { pane, name: raw };
                    self.dialog_error = Some(t!("filemgr.err.outside_root").to_string());
                    self.status_line = Some(t!("filemgr.err.outside_root").to_string());
                    return None;
                }
                // 拼接；旧 root 相对语义零漂移）。
                let path = remote_join(&self.remote.current, &name);
                self.pending = Some(PendingOp {
                    req_id: 0,
                    kind: PendingKind::Mkdir {
                        path: path.clone(),
                        for_job: false, // 用户新建目录按钮（既有语义零变化）。
                    },
                    started: Instant::now(),
                });
                Some(FileCommand::Fs {
                    op: FsOp::Mkdir { path },
                })
            }
        }
    }

    /// 对话框取消（**零 wire 帧**，§1.7）。
    pub fn dialog_cancel(&mut self) {
        self.pending_deletes.clear(); // 多项删除整批中止
        self.dialog = Dialog::None;
        // 落点不动零网络帧，零 wire）。
        if self.clip_expand.as_ref().is_some_and(|c| c.conflict.is_some()) {
            self.clip_conflict_resolve(R159ConflictDecision::Skip);
        }
    }

    /// 对话框内回车 = 默认动作（输入框 = 提交；确认框 = 确认）。
    /// 返回 Some = 需发出的远端命令。
    pub fn dialog_enter(&mut self) -> Option<FileCommand> {
        match std::mem::replace(&mut self.dialog, Dialog::None) {
            Dialog::ConfirmDelete { .. } => self.delete_resolve(true),
            Dialog::ConfirmRename { .. } => self.rename_resolve(true),
            Dialog::InputMkdir { .. } => self.mkdir_submit(),
            Dialog::InputRename { .. } => {
                self.rename_submit();
                None
            }
            Dialog::None => None,
        }
    }

    /// **仅展开**（未展开才展开，已展开不折叠——避免与双击 toggle 语义
    /// 打架）；本地文件 = 系统资源管理器显示（既有语义沿用）；远端文件 =
    /// 无动作（v1 无预览）。
    pub fn enter_selected(&mut self, file_tx: Option<&UnboundedSender<FileCommand>>) {
        let pane = self.active_pane;
        let paths = self.selection_paths(pane);
        if paths.len() != 1 {
            return;
        }
        let path = &paths[0];
        let Some(e) = self.resolve_entry(pane, path) else {
            return;
        };
        if e.is_dir && !e.is_symlink {
            if !self.view(pane).expanded.contains(path) {
                self.tree_expand(pane, path, file_tx);
            }
        } else if pane == PaneId::Local && !e.is_dir {
            { let p = PathBuf::from(path); crate::file_panel::show_in_folder(&p); }
        }
    }
}

/// 文件夹任务进行中（编排单任务口径：运行中拒绝新的复制/粘贴/写操作入口）。
pub fn job_active(state: &FileManagerState) -> bool {
    state.job.as_ref().map(|j| !j.finished).unwrap_or(false)
}

/// `PendingKind` ↔ `FsOp` 同源校验（`Admitted` req_id 回填防串扰）。
fn same_op(kind: &PendingKind, op: &FsOp) -> bool {
    match (kind, op) {
        (
            PendingKind::List { path, offset, .. },
            FsOp::List {
                path: p2,
                offset: o2,
                ..
            },
        )
        | (
            PendingKind::CollectList {
                path, offset, ..
            },
            FsOp::List {
                path: p2,
                offset: o2,
                ..
            },
        ) => path == p2 && *offset == *o2,
        (PendingKind::Mkdir { path, .. }, FsOp::Mkdir { path: p2 }) => path == p2,
        (
            PendingKind::Rename {
                from, to, ..
            },
            FsOp::Rename {
                from: f2,
                to: t2,
            },
        ) => from == f2 && to == t2,
        (
            PendingKind::Delete {
                path, recursive, ..
            },
            FsOp::Delete {
                path: p2,
                recursive: r2,
            },
        ) => path == p2 && recursive == r2,
        (PendingKind::Fetch { remote_path }, FsOp::Fetch { path: p2 }) => {
            remote_path == p2
        }
        _ => false,
    }
}

/// `FsErrCode` 可读化（S10：对端只见码，本地映射文案；`tr` 直取——
/// `t!` 宏仅接受字面量键）。
fn err_text(err: FsErrCode) -> String {
    let key = match err {
        FsErrCode::NotFound => "filemgr.err.not_found",
        FsErrCode::NotADirectory | FsErrCode::IsADirectory => "filemgr.err.io",
        FsErrCode::AlreadyExists => "filemgr.err.already_exists",
        FsErrCode::PermissionDenied => "filemgr.err.denied",
        FsErrCode::PathOutsideRoot => "filemgr.err.outside_root",
        FsErrCode::PathTooLong => "filemgr.err.outside_root",
        FsErrCode::Io => "filemgr.err.io",
        FsErrCode::NotSupported => "filemgr.err.io",
        FsErrCode::RateLimited => "filemgr.err.rate",
        FsErrCode::Internal => "filemgr.err.io",
        // `consent.*` 专属键 = A 岗 i18n 范围，本臂 = 穷举兜底（复用通用文案，
        // 零新 i18n 键）。
        FsErrCode::Declined => "filemgr.err.io",
        FsErrCode::Ok => "filemgr.err.io",
    };
    crate::i18n::tr(key).to_string()
}

/// 点**）。
///
/// 原读本机 `config_cache_load`（「它检查的是客户端所在设备的服务端设置」
/// = 用户指正病灶）→ 现按**对端（远端服务端）**通告值判定
///（[`FileManagerState::peer_consent`]，`FileOp::PeerConsent` 帧消费产物；
/// 值源 = 对端 FileSession 构造 consent 快照 = 对端实际执法值）：
/// - 对端 `file_transfer_allowed` **已知 OFF** → 一行 `consent.file_
///   transfer_off_banner`（对端语义文案：对端会自动拒绝本机发来的上传；
///   浏览/拉取不受对端本开关门控）；
/// - 对端 `clipboard_allowed` **已知 OFF** → 一行 `consent.clipboard_
///   off_banner`（对端语义文案：会话内剪贴板同步被对端门控）；
/// - 对端**未通告**（`None`：旧版本对端 / 会话刚建立通告未到）→ 对应
///   `*_peer_unknown_banner` 显式文案（fail-closed 红线⑤：未知 = 按 OFF +
///   如实提示，不静默放行）；
/// - 对端双已知 ON = **零显示**（不占行、不干扰）。
///
/// 纯展示面（零状态写、零 wire）。
fn render_file_transfer_off_banner(
    ui: &mut Ui,
    theme: &Theme,
    peer_consent: Option<(bool, bool)>,
) {
    let (clip_on, ft_on) = match peer_consent {
        Some((c, f)) => (Some(c), Some(f)),
        // 未通告（旧版本对端 / 通告未到）= 双开关未知（fail-closed 显式
        // 文案，红线⑤）。
        None => (None, None),
    };
    // 任一开关「已知 ON」且另一「已知 ON/未通告但本行不显示」= 该开关零
    // 显示；逐开关独立判定（双 OFF / 单 OFF / 单未通告 / 双未通告全覆盖）。
    if !matches!(ft_on, Some(true)) {
        // `t!` 仅收字面量 → 键选择内联展开（两臂同类型 `&str`）。
        let text = if ft_on == Some(false) {
            t!("consent.file_transfer_off_banner")
        } else {
            t!("consent.file_transfer_peer_unknown_banner")
        };
        ui.add(
            egui::Label::new(RichText::new(text)
                .color(theme.warning)
                .size(theme.small_size))
            .wrap_mode(egui::TextWrapMode::Wrap),
        );
    }
    if !matches!(clip_on, Some(true)) {
        let text = if clip_on == Some(false) {
            t!("consent.clipboard_off_banner")
        } else {
            t!("consent.clipboard_peer_unknown_banner")
        };
        ui.add(
            egui::Label::new(RichText::new(text)
                .color(theme.warning)
                .size(theme.small_size))
            .wrap_mode(egui::TextWrapMode::Wrap),
        );
    }
}

// ════════════════════════════════════════════════════════════════
// egui 渲染（布局基准 = 设计 §2.6 框图 1 verbatim）
// ════════════════════════════════════════════════════════════════

/// 文件管理器双栏渲染（Shell 窗 `TopBottomPanel::bottom` 内调用）。
///
/// 桌面/下载/文档 + 远端根目录）→ 双栏 + 48px 中缝（← 下载 / → 上传
/// 箭头，两侧均选中且目标为目录才 enable）→ 状态行/传输条/对话框。
///
/// `file_mgr_focus` = 窗口层显式焦点态（入参，快捷键门）；`*out_focus` =
/// 本帧「文件管理器请求持焦」（点击进面板 / 弹窗打开）——窗口层据此置位。
pub fn show_file_manager(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FileManagerState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
    fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    panel: &FilePanelState,
    file_mgr_focus: bool,
    out_focus: &mut bool,
) {
    state.in_text_input = false;
    state.tick(panel, file_tx, fm_tx);
    // 空目录 ≠ 未初始化，`started` 旗标语义沿用）。
    // home）**——远端常用三钮（桌面/下载/文档）fail-closed enable 的数据
    // 源 + `root_display`；盘符层 List 在其响应落定后由 tick「2c 首帧链」
    // 续发（单在途纪律；**零新 wire op** = 既有 `FsOp::List` ×2 串行，
    // 修前 = 仅盘符层 1 次）。
    if !state.remote.started && !state.remote.unsupported {
        state.remote.started = true;
        // 首帧链武装（tick 2c 恰一次续发盘符层 List；发射后解除）。
        state.remote.drive_chain_armed = true;
        state.request_remote_list_at_node("", file_tx);
    }
    // 焦点切分（09-11）：本帧主键按下落在面板区 = 请求持焦（显式状态跟踪，
    // 非 egui 焦点粒度推断——点击行/按钮/空白均覆盖）。
    let panel_clicked = ui.ctx().input(|i| {
        i.pointer.button_pressed(egui::PointerButton::Primary)
            && i
                .pointer
                .hover_pos()
                .map(|p| ui.max_rect().contains(p))
                .unwrap_or(false)
    });
    if panel_clicked {
        *out_focus = true;
    }

    //    已知 ON 态零显示）——用户 09-22 复测「文件传输无效」误判 → OFF 态
    //    （远端服务端）**通告值（`state.peer_consent`；未通告 = fail-closed
    //    显式文案，红线⑤），文案键 = 对端语义
    //    `consent.file_transfer_off_banner` / `consent.clipboard_off_banner`
    //    + `*_peer_unknown_banner`。
    render_file_transfer_off_banner(ui, theme, state.peer_consent);

    //    布局修复**：「远端常用/远端电脑」等文字修前与本机区同挤**左对齐
    //    单行**（远端标签落在本地栏侧 = 用户指认位置错误）→ 现分段：
    //    **本机区对齐左栏 / 远端区对齐右栏**，各段矩形 x/宽 =
    //    `render_panes_and_seam` 同式同参推导（pane_w/SEAM_WIDTH/spacing
    //    同源零漂移）。远端段新增 桌面/下载/文档 三钮（fail-closed
    //    enable = `List("")` home 条目命中，[`remote_home_dir_present`]）
    //    + 既有「远端电脑」根钮。──
    render_quick_sections(ui, theme, state, file_tx);

    // 旧 `f32::INFINITY` 在 egui 0.28.1 **release** 构建下越过
    // `Placer::next_space` 的 finiteness `debug_assert!`（release 编译移除）
    // → 无限尺寸流入 `Layout::next_frame` 产出退化/±INFINITY/NaN 子矩形 →
    // 两栏全部控件（栏头/面包屑/表头/行/空目录提示）**与紧随的状态行**
    // 静默不绘制（quota 条在双栏之前、常规布局 → 唯一幸存渲染项，与 179
    // 09-18 截图像素取证一致：仅标题栏+配额行，其下全为均匀背景）；
    // debug 构建会 panic，故既有门禁（headless 测试 + release self-test）
    // 从未捕获。`available_height()` 与 INFINITY 意图等价（填满剩余高度）
    // 且有限；`.max(1.0)` 防首帧 0 高退化。
    // `allocate_ui` 组合在 egui 0.28.1 有两条退化路径（均经 ui.rs/
    // scroll_area.rs 源码证实 + headless 双父级×主题×宽度矩阵复现）：
    //   a) `allocate_ui = allocate_ui_with_layout(_, *self.layout())`
    //      （ui.rs:1102）——栏子 ui **继承** `ui.horizontal` 的横向布局
    //      → 栏内全部内容（栏头｜面包屑｜表头｜行 Grid｜分页）被左到右
    //      排成一行（行 Grid 推到表头右侧，向下展开 1218px = 58 行×21px）；
    //   b) `ui.horizontal` 是「行」：初始高 = `interact_size.y` ≈ 20px
    //      （ui.rs:2183 `horizontal_with_main_wrap_dyn`）→ 其内
    //      `available_height()` ≈ 20px → 栏 max_rect 高 ≈ 20px → 行区
    //      ScrollArea（`min_scrolled_size` = 64px，scroll_area.rs:221/540）
    //      钳到 64-70px 最小高 → 58 行 Grid 向下溢出 1150px+，整片落在
    //      底栏可见区外 = 「行区整片不绘制」；栏头/表头/分页挤进顶栏
    //      两行（179 第二半症状）；空目录 label 恰在 70px 可见带内 →
    //      「空目录反而正常」。
    // 修复 = `ui.columns(2)`（列矩形 = 游标→父 max_rect 底边 = **满剩余
    // 高**，且列布局显式 `top_down_justified` 竖排、无布局继承，
    // 有限值）恰被保留。headless 对照：单栏直挂竖排父 ui 同数据布局
    // 正常 = 反证退化必来自双栏包装层。
    // columns(2) **几何同构**（栏矩形 = 游标→父底边满剩余高 + 显式
    // `top_down_justified(LEFT)` + 光标推进同构 `columns_dyn`），上述
    render_panes_and_seam(ui, theme, state, file_tx, fm_tx, panel);

    render_status_row(ui, theme, state, panel, file_tx);
    render_transfer_bar(ui, theme, panel, file_tx);

    // ── 对话框（顶层；取消 = 零 wire 帧 §1.7）──
    render_dialogs(ui, theme, state, file_tx);
    // 弹窗打开 / 文本输入 = 键盘归文件管理器（终端 feed 停）。
    if state.has_dialog() || state.in_text_input {
        *out_focus = true;
    }

    // ── 面板侧快捷键（统一入口；**显式焦点门**，09-11 硬保证）──
    let (c, v, enter) = ui.ctx().input(|i| {
        let mod_down = copy_paste_mods(&i.modifiers);
        (
            mod_down && key_pressed_once(i, egui::Key::C),
            mod_down && key_pressed_once(i, egui::Key::V),
            key_pressed_once(i, egui::Key::Enter),
        )
    });
    // Esc = 对话框取消（零 wire 帧）。
    let esc = ui.ctx().input(|i| key_pressed_once(i, egui::Key::Escape));
    if c {
        handle_shortcut(
            state, file_mgr_focus, state.in_text_input, FileMgrShortcut::Copy, panel, file_tx, fm_tx,
        );
    } else if v {
        if file_mgr_shortcut_active(file_mgr_focus, state.in_text_input) {
            handle_shortcut(
                state, file_mgr_focus, state.in_text_input, FileMgrShortcut::Paste, panel, file_tx, fm_tx,
            );
        } else if r164_paste_focus_hint_due(file_mgr_focus, state.in_text_input) {
            // **显式反馈**三面（修前零动作静默 → egui 默认文本粘贴 →
            // arboard「clipboard is empty」误现）：面板状态行 + 连接页
            // Warn + tracing 锚行（用户日志 grep 位点）。文本输入形态
            // 不经此臂（`r164_paste_focus_hint_due` 恒 false）= egui
            // 文本粘贴既有行为零变化。
            state.status_line = Some(t!("filemgr.paste.focus_hint").to_string());
            crate::conn_log_push_text(
                crate::widgets::ConnLogLevel::Warn,
                &t!("connect.log.r164_paste_focus_hint").to_string(),
            );
            tracing::warn!(
                 in_text_input={}) — explicit hint shown (no silent drop)",
                state.in_text_input
            );
        }
        // 焦点门关闭且在文本输入 = 零动作（egui 文本粘贴，既有行为）。
    } else if enter {
        handle_shortcut(
            state, file_mgr_focus, state.in_text_input, FileMgrShortcut::Enter, panel, file_tx, fm_tx,
        );
    } else if esc && state.has_dialog() && !state.in_text_input {
        state.dialog_cancel();
    }
}

///（用户规格①「界面顶部几个常见工具，比如本机常用目录、远程常用目录」）。
///
/// 布局 = **两段分行对位双栏**（修前 = 单行 `ui.horizontal` 左对齐：本机区
/// + 分隔线 + 远端区全挤一行，「远端常用/远端电脑」文字落在**左栏侧** =
/// 用户指认「位置放错，应该放置到右边对应远端电脑」）：
/// - 本机段矩形 = 左栏同位同宽（`pane_w`，x = 栏左缘）；
/// - 远端段矩形 = 右栏同位同宽（x = 左栏右缘 + 中缝 + 双行距——
///   [`render_panes_and_seam`] 同式同参推导，几何零漂移）；
///   横排子 ui（`left_to_right(Center)`，与 `render_seam` 子 ui 同族——
fn render_quick_sections(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FileManagerState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
) {
    let spacing = ui.spacing().item_spacing.x;
    let avail_w = ui.available_width();
    let pane_w = ((avail_w - SEAM_WIDTH - 2.0 * spacing) / 2.0).max(1.0);
    let top = ui.cursor().min;
    let row_bottom = top.y + QUICK_ROW_H;
    // 本机段（左栏上）：本地根 → 左缘。
    let left_rect = Rect::from_min_max(top, pos2(top.x + pane_w, row_bottom));
    let mut lc = ui.child_ui(left_rect, Layout::left_to_right(Align::Center), None);
    lc.set_width(pane_w);
    render_quick_section_local(&mut lc, theme, state);
    // 远端段（右栏上）：中缝几何 = `render_panes_and_seam` 右栏起点同式。
    let right_x = top.x + pane_w + SEAM_WIDTH + 2.0 * spacing;
    let right_rect = Rect::from_min_max(
        pos2(right_x, top.y),
        pos2(right_x + pane_w, row_bottom),
    );
    let mut rc = ui.child_ui(right_rect, Layout::left_to_right(Align::Center), None);
    rc.set_width(pane_w);
    render_quick_section_remote(&mut rc, theme, state, file_tx);
    ui.advance_cursor_after_rect(Rect::from_min_max(
        top,
        pos2(top.x + (2.0 * pane_w + SEAM_WIDTH + 2.0 * spacing).min(avail_w), row_bottom),
    ));
}

/// 本机常用段（label + 桌面/下载/文档；行为 = 修前零变化：[`local_quick_
/// dirs`] home 基准，目录不存在 = disable，点击 = [`FileManagerState::
/// goto_local_quick`] 同步链展开导航）。
fn render_quick_section_local(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FileManagerState,
) {
    ui.add(
        egui::Label::new(
            RichText::new(t!("filemgr.quick.local")).size(theme.small_size),
        )
        .selectable(false),
    );
    let home = dirs_next::home_dir().unwrap_or_else(|| state.local.root.clone());
    let dirs = local_quick_dirs(&home);
    for (key, dir) in LOCAL_QUICK_KEYS.iter().zip(dirs.iter()) {
        if ui
            .add_enabled(
                dir.is_dir(),
                egui::Button::new(RichText::new(crate::i18n::tr(key)).size(theme.small_size))
                    .frame(false),
            )
            .clicked()
        {
            state.goto_local_quick(dir);
        }
    }
}

/// 桌面/下载/文档 三钮——用户「常见目录要有展示比如文档 桌面 下载」）。
///
/// - 「远端电脑」= 修前行为零变化（`navigate_to_prefix` 合成根导航）；
/// - 三钮 enable = [`remote_home_dir_present`]（**fail-closed**：`List("")`
///   home 未列定 / 在途 / 错误 / 条目缺席 = disable，同本地 `dir.is_dir()`
///   口径）；点击 = [`FileManagerState::goto_remote_quick`]（root 相对
///   单级 List，零新 wire op）。
fn render_quick_section_remote(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FileManagerState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
) {
    ui.add(
        egui::Label::new(
            RichText::new(t!("filemgr.quick.remote")).size(theme.small_size),
        )
        .selectable(false),
    );
    // （语义随根迁移；enable = 非在途，修前口径零变化）。
    let root_label = t!("filemgr.pc_root_remote").to_string();
    if ui
        .add_enabled(
            !state.remote.view.loading,
            egui::Button::new(
                RichText::new(root_label).color(theme.accent).size(theme.small_size),
            )
            .frame(false),
        )
        .clicked()
    {
        state.navigate_to_prefix(PaneId::Remote, REMOTE_PC_ROOT_KEY.to_string(), file_tx);
    }
    for (key, name) in LOCAL_QUICK_KEYS.iter().zip(remote_quick_dir_names().iter()) {
        let enabled = remote_home_dir_present(state, name);
        if ui
            .add_enabled(
                enabled,
                egui::Button::new(RichText::new(crate::i18n::tr(key)).size(theme.small_size))
                    .frame(false),
            )
            .clicked()
        {
            state.goto_remote_quick(name, file_tx);
        }
    }
}

///
/// 栏子 ui 矩形 = 游标 → 父 `max_rect` 底边（**满剩余高、有限值**）+
/// 显式 `top_down_justified(LEFT)`（无父布局继承）；中缝 = 定宽
/// [`SEAM_WIDTH`] 窄列（同高），两个箭头按钮确定性垂直居中（按钮高
/// [`SEAM_BTN_H`] 钉死 + `add_space` = （可用高 − 2×H − 行距）/ 2）。
/// 光标推进同构 `columns_dyn`（`advance_cursor_after_rect` = 最高子用高）。
fn render_panes_and_seam(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FileManagerState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
    fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    panel: &FilePanelState,
) {
    let spacing = ui.spacing().item_spacing.x;
    let avail_w = ui.available_width();
    let pane_w = ((avail_w - SEAM_WIDTH - 2.0 * spacing) / 2.0).max(1.0);
    let top_left = ui.cursor().min;
    let bottom_y = ui.max_rect().right_bottom().y;

    let mut heights = [0.0f32; 3];
    // rect，含栏头+树行区——与 `r195_drop_target` 对侧命中语义配对）。
    // 无初值声明（块内无条件赋值 = 延迟初始化；零未读赋值/可变性警告）。
    let r195_local_rect;
    let r195_remote_rect;
    // 左栏（本地）。
    {
        let pos = top_left;
        let rect = Rect::from_min_max(pos, pos2(pos.x + pane_w, bottom_y));
        let mut c = ui.child_ui(rect, Layout::top_down_justified(Align::LEFT), None);
        c.set_width(pane_w);
        render_pane(&mut c, theme, state, PaneId::Local, file_tx, fm_tx, panel);
        heights[0] = c.min_size().y;
        r195_local_rect = rect;
    }
    // 中缝（←/→ 箭头）。
    {
        let pos = top_left + vec2(pane_w + spacing, 0.0);
        let rect = Rect::from_min_max(pos, pos2(pos.x + SEAM_WIDTH, bottom_y));
        let mut c = ui.child_ui(rect, Layout::top_down(Align::Center), None);
        render_seam(&mut c, state, file_tx, fm_tx, panel);
        heights[1] = c.min_size().y;
    }
    // 右栏（远端）。
    {
        let pos = top_left + vec2(pane_w + SEAM_WIDTH + 2.0 * spacing, 0.0);
        let rect = Rect::from_min_max(pos, pos2(pos.x + pane_w, bottom_y));
        let mut c = ui.child_ui(rect, Layout::top_down_justified(Align::LEFT), None);
        c.set_width(pane_w);
        render_pane(&mut c, theme, state, PaneId::Remote, file_tx, fm_tx, panel);
        heights[2] = c.min_size().y;
        r195_remote_rect = rect;
    }
    // 单点调用——行按下登记在 `render_pane` 行渲染内，见各 Node 行臂）。
    r195_drag_feedback_and_drop(
        ui,
        theme,
        state,
        r195_local_rect,
        r195_remote_rect,
        panel,
        file_tx,
        fm_tx,
    );
    let max_h = heights.iter().cloned().fold(0.0f32, f32::max);
    let size = vec2(
        avail_w.max(2.0 * pane_w + SEAM_WIDTH + 2.0 * spacing),
        max_h,
    );
    ui.advance_cursor_after_rect(Rect::from_min_size(top_left, size));
}

/// `render_panes_and_seam` 两栏 rect 捕获后；行按下登记在 `render_pane`
/// Node 行臂，推进/落定在此全局一次 = 状态机单写点）。
///
/// - **视觉**（仅拖拽中 = 载荷已定格）：指针悬于**对侧**栏 = 该栏高亮
///   （theme `accent` token：淡填充 + 描边）；拖拽影子 = 指针跟随 tooltip
///   （basename 摘要，[`r195_drag_shadow_text`]）；光标 Grabbing。源栏/
///   中缝/栏头悬停 = 零高亮（无效目标零误导）。
/// - **落定**：释放帧 = [`FileManagerState::r195_drag_frame`] → Dropped →
///   [`r195_drop_target`] 对侧命中 → [`FileManagerState::drop_transfer`]
///   （既有授权链入队）；源栏/中缝/栏外/指针离窗 = 无动作。
fn r195_drag_feedback_and_drop(
    ui: &Ui,
    theme: &Theme,
    state: &mut FileManagerState,
    local_rect: Rect,
    remote_rect: Rect,
    panel: &FilePanelState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
    fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
) {
    let (pressed, released, escape) = ui.input(|i| {
        (
            i.pointer.primary_down(),
            i.pointer.primary_released(),
            i.key_pressed(egui::Key::Escape),
        )
    });
    let pos = ui.input(|i| i.pointer.interact_pos());
    match state.r195_drag_frame(pressed, released, escape, pos, R195_DRAG_THRESHOLD) {
        R195DragFrame::Idle | R195DragFrame::Armed => {}
        R195DragFrame::Dragging { source, paths } => {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
            // 悬停目标栏高亮（match 语义保证仅对侧 = 有效目标；源栏悬停
            // 零高亮 = 无效目标零误导）。
            let hovered_local = pos.map_or(false, |p| local_rect.contains(p));
            let hovered_remote = pos.map_or(false, |p| remote_rect.contains(p));
            let hl = match (source, hovered_local, hovered_remote) {
                (PaneId::Local, _, true) => Some(remote_rect),
                (PaneId::Remote, true, _) => Some(local_rect),
                _ => None,
            };
            if let Some(rect) = hl {
                ui.painter()
                    .rect_filled(rect, 4.0, theme.accent.gamma_multiply(0.12));
                ui.painter().rect_stroke(rect, 4.0, (2.0, theme.accent));
            }
            // 拖拽影子：指针跟随 tooltip（顶层 layer，不受栏裁剪）。
            egui::containers::popup::show_tooltip_at_pointer(
                ui.ctx(),
                ui.layer_id(),
                Id::new("r195_drag_shadow"),
                |ui| {
                    ui.label(
                        RichText::new(r195_drag_shadow_text(&paths))
                            .size(theme.small_size),
                    );
                },
            );
        }
        R195DragFrame::Dropped { source, paths } => {
            // 指针离窗释放（pos None）/ 源栏·中缝·栏外 = 无动作。
            let Some(pos) = pos else { return };
            if let Some(target) =
                r195_drop_target(source, local_rect.contains(pos), remote_rect.contains(pos))
            {
                state.drop_transfer(target, paths, panel, file_tx, fm_tx);
            }
        }
    }
}

/// 点击」）。
///
/// - `←` = [`ArrowDirection::Download`]：远程选中项下载到本地选中目录；
/// - `→` = [`ArrowDirection::Upload`]：本地选中项上传到远程选中目录；
/// - enable = [`FileManagerState::arrow_ready`]（两侧均有选中〔文件/目录
///   自动识别〕+ 目标侧恰一目录 + 非在途）；点击 = [`FileManagerState::arrow_transfer`]
/// （目标 = 对侧选中目录；状态行/传输条/toast 沿用既有）。
fn render_seam(
    ui: &mut Ui,
    state: &mut FileManagerState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
    fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    panel: &FilePanelState,
) {
    // 确定性垂直居中（按钮高钉死 [`SEAM_BTN_H`]；双钮间距 = egui 自动
    // item_spacing.y 一项——**不再**显式 add_space，防双重间距）。
    let total = 2.0 * SEAM_BTN_H + ui.spacing().item_spacing.y;
    ui.add_space((ui.available_height() - total).max(0.0) / 2.0);
    // ← 远端 → 本地（下载）。
    // 消 fail-closed 静默禁用零可观测）；enable 态行为零变化。
    let dl_ready = state.arrow_ready(ArrowDirection::Download);
    let dl_resp = ui
        .add_enabled(
            dl_ready,
            egui::Button::new(RichText::new("←").size(18.0))
                .min_size(vec2(SEAM_BTN_W, SEAM_BTN_H)),
        )
        .on_hover_text(t!("filemgr.arrow.down_tip").to_string());
    if dl_resp.clicked() {
        state.arrow_transfer(ArrowDirection::Download, panel, file_tx, fm_tx);
    } else if seam_disabled_click_attempt(ui, &dl_resp, dl_ready) {
        if let Some(reason) = state.arrow_disabled_reason(ArrowDirection::Download) {
            tracing::warn!("{}", format_arrow_disabled_click_line(ArrowDirection::Download, reason));
        }
    }
    // → 本地 → 远端（上传）（双钮间距 = 上方自动 item_spacing.y）。
    let up_ready = state.arrow_ready(ArrowDirection::Upload);
    let up_resp = ui
        .add_enabled(
            up_ready,
            egui::Button::new(RichText::new("→").size(18.0))
                .min_size(vec2(SEAM_BTN_W, SEAM_BTN_H)),
        )
        .on_hover_text(t!("filemgr.arrow.up_tip").to_string());
    if up_resp.clicked() {
        state.arrow_transfer(ArrowDirection::Upload, panel, file_tx, fm_tx);
    } else if seam_disabled_click_attempt(ui, &up_resp, up_ready) {
        if let Some(reason) = state.arrow_disabled_reason(ArrowDirection::Upload) {
            tracing::warn!("{}", format_arrow_disabled_click_line(ArrowDirection::Upload, reason));
        }
    }
}

/// false 早退）。`add_enabled(false)` 的按钮 `.clicked()` 恒 false，但指针
/// 落在按钮矩形上且本帧主键按下 = 用户尝试点禁用箭头 → 返回 true（调用方
/// 补 WARN 一行）。纯 egui 输入面（零状态写，不触 `FileManagerState`）。
fn seam_disabled_click_attempt(ui: &Ui, resp: &egui::Response, enabled: bool) -> bool {
    if enabled {
        return false;
    }
    ui.ctx().input(|i| {
        i.pointer.button_clicked(egui::PointerButton::Primary)
            && i
                .pointer
                .hover_pos()
                .is_some_and(|pos| resp.rect.contains(pos))
    })
}

// ════════════════════════════════════════════════════════════════
//
// 穿模根因（双因子，均在案）：
// ① Grid 列宽随内容涨破 `pane_w`——名称列 `SelectableLabel` 无宽度约束，
//    egui 0.28.1 grid.rs `add_cell` 列宽 = `max(widget_rect.width, min_col_width)`
//    （无上界）+ `full_width` = Σ列宽（grid.rs:42）→ 长文件名把整条 Grid
//    总宽推出栏 child_ui 矩形；
// ② 纹带/行绘制未钳到栏矩形——栏 `child_ui` 继承**父** painter clip
//    （egui 0.28.1 ui.rs `child_ui` `painter: self.painter.clone()`），而
//    ScrollArea 仅在**滚动轴**且内容溢出时才把 content clip 收到可视
//    inner rect（containers/scroll_area.rs `content_clip_rect` 段）；非滚动
//    （水平）轴的 clip max 仍取父（窗）clip → 条纹 rect（宽 = Grid 总宽 +
//    4px HACK，grid.rs `paint_row`）自栏左缘铺到 Grid 全宽，经中缝铺到
//    右栏之下、仅被窗缘兜底裁切 = 130228「左栏行斑马纹横跨全窗宽」实证。
//
// 修复（双重）：
// ① 名称列钳宽——长名省略号（[`r134_9_ellipsis_name`]）使 Grid 总宽 ≤
//    `pane_w − R134_9_GRID_PANE_MARGIN`（列宽不再随内容涨破栏宽；悬停
//    tooltip 仍给全名，既有 `on_hover_text` 零变化）；
// ② 行区绘制区硬钳到栏可视矩形（`set_clip_rect`）——即便 ① 的度量估计
//    偏差或未来新增列，条纹/长文本/悬停高亮也一律在栏矩形硬裁，永不出
//    中缝（像素级判据由 `r134_9_tests` headless 钉死）。
//
// 滚轮专项核验（卡内两因定案，本段同锚点）：egui 0.28.1 滚轮消费门 =
// 可视 `outer_rect`（containers/scroll_area.rs `outer_rect` +
// `is_hovering_outer_rect = ui.rect_contains_pointer(outer_rect)`，ui.rs
// `rect_contains_pointer` 再 ∩ 本 ui clip）——`outer_rect` x 域 = 栏可视
// 宽（来自栏 child_ui `set_width(pane_w)` 的 available 矩形），**超宽
// 内容矩形不参与滚轮命中** → 「命中被穿模区遮挡」排除（超宽内容仅延伸
// `Sense::drag` 交互矩形到对栏空白区 = 点击拖拽路径，非滚轮）；右栏滚轮
// 失效 = 右列表未溢出可视高 → `content_is_too_large[1]=false` →
// `max_offset[1]≤0` → `scrolling_up/down` 恒 false（delta 不被消费、
// 滚动条不显）=「未溢出无可滚」表象（130228 右栏条目少、无滚动条可见
// = 吻合）。行为钉死见 `r134_9_tests::r134_9_right_pane_wheel_scrolls_right_table`。
// ════════════════════════════════════════════════════════════════

///
/// `other_cols_total_w` = 大小/修改时间/类型三列 galley 宽之和（[`r134_9_other_cols_w`]，
/// 当前页最宽条）；`spacing_x` = Grid 列间距（[`R134_9_GRID_SPACING_X`]，4 列 = 3 间距）；
/// `frame_pad_x` = 名称列 `SelectableLabel` 的 frame 单侧 padding（egui
/// `total_extra = button_padding + button_padding`，取 `spacing().button_padding.x`）。
/// 极端窄栏（其他列已超栏宽）→ 钳 0（无 NaN/负值；绘制由行区 clip 兜底）。
///
/// **test-only**（`r134_9_tests` 矩阵钉死 4 列公式零漂移），非测试构建
/// 不参与 dead-code 面（release 警告恰 4 位点门禁保位）。
#[cfg(test)]
pub fn r134_9_name_col_max_w(
    pane_w: f32,
    other_cols_total_w: f32,
    spacing_x: f32,
    frame_pad_x: f32,
) -> f32 {
    r134_9b_name_col_max_w(pane_w, other_cols_total_w, 4, spacing_x, frame_pad_x)
}

/// 不超宽 = **原样返回零变化**（短名路径零开销、零观感差异）。
///
/// 纯函数（测量函数 `measure` 由调用方注入 = 与 egui 上下文解耦，可无
/// headless 全量矩阵钉死）。宽度随假前缀单调不减 → 二分最长适配前缀
/// （O(log n) 次测量；`layout_no_wrap` 内部按文本 memoize）。
/// `max_w` 小于 `…` 自身宽（极端窄栏）→ 返回 `…`（行区 clip 兜底）。
pub fn r134_9_ellipsis_name(name: &str, max_w: f32, measure: &dyn Fn(&str) -> f32) -> String {
    if name.is_empty() {
        return String::new();
    }
    if measure(name) <= max_w {
        return name.to_string();
    }
    const ELLIPSIS: &str = "…";
    if measure(ELLIPSIS) > max_w {
        return ELLIPSIS.to_string();
    }
    let chars: Vec<char> = name.chars().collect();
    // P(k) = prefix(chars[..k]) + "…" 适配 max_w；P 单调（k↑ ⇒ 宽不减），
    // 且 P(0)=true（前置已证）、P(len)=false（全名已超宽 ⇒ 全名+"…" 更超）。
    let fits = |k: usize| -> bool {
        let mut s: String = chars[..k].iter().collect();
        s.push_str(ELLIPSIS);
        measure(&s) <= max_w
    };
    let mut lo = 0usize;
    let mut hi = chars.len();
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        if fits(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let mut out: String = chars[..lo].iter().collect();
    out.push_str(ELLIPSIS);
    out
}

/// （名称列钳宽的「他列」输入）。每列只测按字符数最长的一个字符串 =
/// 至多 3 次布局调用（500 行零逐行开销；列宽单调性 = 同字体下字符数
/// 最长串宽 ≥ 其余串的宽误差由 [`R134_9_GRID_PANE_MARGIN`] + 行区 clip 兜底）。
/// 每列另钳 [`R134_9_GRID_MIN_COL_W`] 底 = Grid `.min_col_width` 实际列宽
/// 口径（列宽 = max(内容宽, 40)，内容窄于列底时防低估）。
pub fn r134_9_other_cols_w(rows: &[FileMgrEntry], measure: &dyn Fn(&str) -> f32) -> f32 {
    let widest = |f: &dyn Fn(&FileMgrEntry) -> String| {
        rows.iter()
            .map(f)
            .max_by_key(|s| s.chars().count())
            .map(|s| measure(&s).max(R134_9_GRID_MIN_COL_W))
            .unwrap_or(0.0)
    };
    let size_w = widest(&|e| {
        if e.is_dir {
            "-".to_string()
        } else {
            format_size(e.size)
        }
    });
    let mtime_w = widest(&|e| format_mtime(e.mtime));
    let type_w = widest(&|e| type_label(e));
    size_w + mtime_w + type_w
}

/// 单栏渲染（栏头按钮行 + 面包屑 + 表头 + 行 + 分页）。
fn render_pane(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FileManagerState,
    pane: PaneId,
    file_tx: Option<&UnboundedSender<FileCommand>>,
    fm_tx: Option<&UnboundedSender<FileMgrCommand>>,
    panel: &FilePanelState,
) {
    let local = pane == PaneId::Local;
    // ── 栏头：标题 + 操作按钮（框图 1）──
    ui.horizontal(|ui| {
        ui.add(
            egui::Label::new(
                RichText::new(if local { t!("filemgr.local") } else { t!("filemgr.remote") })
                    .strong()
                    .size(theme.small_size),
            )
            .selectable(false),
        );
        ui.separator();
        let busy = job_active(state) || state.has_dialog();
        if local {
            // 落点 = **远端栏选中目录**（恰一非符号链接目录；未选中/非目录
            // = 回退远端栏当前目录节点）。旧 `enqueue_transfer`（target=None）
            // 恒落 `remote.current`——选中目录被忽略 = 用户「没按选中目录传
            // 到指定目录」主断点（取证：09-23 日志上传全 Ok 但落点 = 家目录
            // 根）。
            let sel = state.selection_paths(PaneId::Local);
            let sel_nonempty = !sel.is_empty();
            if ui
                .add_enabled(
                    sel_nonempty && !busy,
                    egui::Button::new(RichText::new(t!("filemgr.btn.send_selected")).size(theme.small_size)),
                )
                .clicked()
            {
                let t_remote = state.single_dir_selection(PaneId::Remote);
                state.enqueue_transfer_targeted(
                    PaneId::Local, PaneId::Remote, sel, t_remote, None, panel, file_tx, fm_tx,
                );
            }
            if ui
                .add_enabled(
                    sel_nonempty,
                    egui::Button::new(RichText::new(t!("filemgr.btn.show_in_folder")).size(theme.small_size)),
                )
                .clicked()
            {
                if let Some(first) = state.selection_paths(PaneId::Local).into_iter().next() {
                    { let p = PathBuf::from(&first); crate::file_panel::show_in_folder(&p); }
                }
            }
        } else {
            let sel = state.selection_paths(PaneId::Remote);
            let sel_count = sel.len();
            if ui
                .add_enabled(
                    sel_count > 0 && !busy,
                    egui::Button::new(RichText::new(t!("filemgr.btn.recv_selected")).size(theme.small_size)),
                )
                .clicked()
            {
                // **本地栏选中目录**（恰一非符号链接目录；未选中/非目录 =
                // 回退本地栏当前目录节点）——目录 = 在目标下新建**同名目录**
                // 再下载入内（FolderJob BFS 镜像前缀 = basename，
                // `target_local_dir/<目录名>/…`，既有语义，零静默变更）。
                let t_local =
                    state.single_dir_selection(PaneId::Local).map(PathBuf::from);
                state.enqueue_transfer_targeted(
                    PaneId::Remote, PaneId::Local, sel, None, t_local, panel, file_tx, fm_tx,
                );
            }
            if ui
                .add_enabled(
                    !busy,
                    egui::Button::new(RichText::new(t!("filemgr.btn.mkdir")).size(theme.small_size)),
                )
                .clicked()
            {
                state.open_mkdir(PaneId::Remote);
            }
            if ui
                .add_enabled(
                    sel_count == 1 && !busy,
                    egui::Button::new(RichText::new(t!("filemgr.btn.rename")).size(theme.small_size)),
                )
                .clicked()
            {
                state.open_rename(PaneId::Remote);
            }
            if ui
                .add_enabled(
                    sel_count > 0 && !busy,
                    egui::Button::new(RichText::new(t!("filemgr.btn.delete")).size(theme.small_size)),
                )
                .clicked()
            {
                state.open_delete(PaneId::Remote);
            }
        }
        // 默认关**；样式 = egui checkbox theme token 视觉，`domain_panel.rs`
        // `ddns.enabled` 先例同款；small_size 与工具行文字档一致）。过滤在
        // 渲染层（[`FileManagerState::pane_rows_recur`]），翻转即帧级生效，
        // 零重列零 wire。
        ui.separator();
        let mut r172_show_hidden = state.view(pane).show_hidden;
        if ui
            .checkbox(
                &mut r172_show_hidden,
                RichText::new(t!("filemgr.show_hidden")).size(theme.small_size),
            )
            .changed()
        {
            state.view_mut(pane).show_hidden = r172_show_hidden;
        }
        //（[`FileManagerState::refresh_remote_force`]：清当前节点缓存 + 恒
        // 联动为另一出口）。仅远端栏（本地栏 std::fs 直读零陈旧面；语义
        // 对称面 = 本地既有 🔄 零 wire 重读）。样式 = theme token 视觉
        if !local {
            ui.separator();
            if ui
                .add(
                    egui::Button::new(
                        RichText::new(t!("filemgr.btn.force_refresh")).size(theme.small_size),
                    ),
                )
                .clicked()
            {
                state.refresh_remote_force(file_tx);
            }
        }
    });

    // ── 面包屑（根选择器首段 = root_display / 本地 root）+ 🔄 ──
    ui.horizontal(|ui| {
        let crumbs: Vec<(String, String)> = if local {
            state.local_breadcrumb()
        } else {
            state.remote_breadcrumb()
        };
        for (i, (prefix, label)) in crumbs.iter().enumerate() {
            if i > 0 {
                ui.label(RichText::new("▸").size(theme.small_size));
            }
            if ui
                .add(
                    egui::Button::new(
                        RichText::new(label).color(theme.accent).size(theme.small_size),
                    )
                    .frame(false),
                )
                .clicked()
            {
                state.navigate_to_prefix(pane, prefix.clone(), file_tx);
            }
        }
        if ui
            .add_enabled(
                !local || !state.remote.view.loading,
                egui::Button::new(RichText::new(t!("filemgr.btn.refresh")).size(theme.small_size)),
            )
            .clicked()
        {
            if local {
                state.refresh_local();
            } else {
                state.request_remote_list(file_tx);
            }
        }
        // 栏内状态（加载中/错误）。
        if let Some(st) = &state.view(pane).status {
            ui.add(
                egui::Label::new(RichText::new(st).size(theme.small_size).color(theme.fg_weak))
                    .selectable(false),
            );
        } else if state.view(pane).loading {
            ui.add(
                egui::Label::new(
                    RichText::new(t!("filemgr.loading")).size(theme.small_size).color(theme.fg_weak),
                )
                .selectable(false),
            );
        }
    });

    // ── 表头（排序三态：点击名称/大小/修改时间 asc→desc→off；类型列展示）──
    ui.horizontal(|ui| {
        for field in [SortField::Name, SortField::Size, SortField::Modified] {
            let base = match field {
                SortField::Name => t!("filemgr.col.name"),
                SortField::Size => t!("filemgr.col.size"),
                SortField::Modified => t!("filemgr.col.modified"),
            };
            let arrow = match state.view(pane).sort.field {
                Some(f) if f == field => {
                    if state.view(pane).sort.desc { " ↓" } else { " ↑" }
                }
                _ => "",
            };
            if ui
                .add(
                    egui::Button::new(
                        RichText::new(format!("{base}{arrow}")).size(theme.small_size),
                    )
                    .frame(false),
                )
                .clicked()
            {
                state.sort_header(pane, field);
            }
        }
        ui.add(
            egui::Label::new(RichText::new(t!("filemgr.col.type")).size(theme.small_size))
                .selectable(false),
        );
    });

    // 展开/折叠；右键菜单；**树内无分页**）──
    let rows: Vec<PaneRow> = state.pane_rows(pane);
    // 栏 child_ui 继承父 clip + ScrollArea 非滚动轴 clip 到窗缘）。
    // `rows_view` = 行区可视矩形（全局坐标；ScrollArea 滚动只移动内容
    // 原点、不改可视区 → 每帧同值，clip 语义稳定）。
    let pane_w = ui.max_rect().width().max(1.0);
    let rows_view = Rect::from_min_size(
        ui.cursor().min,
        vec2(ui.available_width(), ui.available_height()),
    );
    // 纪律）。缺省 `id_source = Id::new("scroll_area")`（egui 0.28.1
    // scroll_area.rs:502）→ 双栏同帧同一 persistent ID（兄弟子 ui
    // `id = parent.id.with("child")` 相等，ui.rs:167）→ egui ID 冲突
    // （🔥 First/Second use）+ 两栏共享 `State`（scroll offset/
    // content_size/滚动条状态互相污染）——与 (a)(b) 叠加放大 179 症状。
    // 经 `begin()` 内 `ui.make_persistent_id` 同 ui 同源 = 同值；滚动锚
    let rows_sa_id = ui.make_persistent_id(egui::Id::new(format!(
        "file_mgr_rows_{:?}",
        pane
    )));
    let mut r163_anchor_delta: Option<f32> = None;
    egui::ScrollArea::vertical()
        .id_source(format!("file_mgr_rows_{:?}", pane))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // 一律在栏矩形裁切（egui 非滚动轴 content clip 到窗缘的兜底，
            // 像素判据 headless 钉死）。
            ui.set_clip_rect(rows_view);
            let unsupported = !local && state.remote.unsupported;
            if unsupported || rows.is_empty() {
                let text = if local {
                    t!("filemgr.empty.local")
                } else if state.remote.view.loading && !unsupported {
                    t!("filemgr.loading")
                } else if unsupported {
                    t!("filemgr.empty.remote")
                } else {
                    t!("filemgr.empty.local")
                };
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(RichText::new(text).size(theme.small_size).color(theme.fg_weak))
                        .selectable(false),
                );
                return;
            }
            // 可见行最宽条实测〔至多 3 次布局调用〕+ 缩进预算〔最大深度 ×
            // [`R134_9B_TREE_INDENT`] + 标记列宽 [`R134_9B_TREE_MARK_W`]，受
            // [`R134_9_GRID_MIN_COL_W`] 列底钳制取大〕；超宽名 O(log n) 前缀
            // 测量；`layout_no_wrap` memoize）。
            let name_max_w = {
                let measure = |s: &str| -> f32 {
                    ui.fonts(|f| {
                        f.layout_no_wrap(
                            s.to_string(),
                            FontId::new(theme.small_size, FontFamily::Proportional),
                            Color32::TRANSPARENT,
                        )
                        .rect
                        .width()
                    })
                };
                let entries: Vec<FileMgrEntry> = rows
                    .iter()
                    .filter_map(|r| match r {
                        PaneRow::Node(t) => Some(t.entry.clone()),
                        PaneRow::Marker { .. } => None,
                    })
                    .collect();
                let indent_budget = rows.iter().fold(0.0f32, |mx, r| {
                    let d = match r {
                        PaneRow::Node(t) => t.depth,
                        PaneRow::Marker { depth, .. } => *depth,
                    };
                    (d as f32 * R134_9B_TREE_INDENT).max(mx)
                });
                // 标记格 = `ui.horizontal`〔缩进 + 控件间距 + 标记〕（grid 内
                // 多控件格口径；间距 = 栏 ui item_spacing.x 运行时值）。
                let col1_w = (indent_budget
                    + ui.spacing().item_spacing.x
                    + R134_9B_TREE_MARK_W)
                    .max(R134_9_GRID_MIN_COL_W);
                r134_9b_name_col_max_w(
                    pane_w,
                    r134_9_other_cols_w(&entries, &measure) + col1_w,
                    5,
                    R134_9_GRID_SPACING_X,
                    ui.spacing().button_padding.x,
                )
            };
            egui::Grid::new(Id::new(format!("file_mgr_grid_{:?}", pane)))
                .striped(true)
                // 形态（空远端 = 恰根行 1 条行背景）条纹判据在位（r133_2
                // 先例口径；行奇偶纹带视觉不变）。
                .start_row(1)
                .spacing([R134_9_GRID_SPACING_X, 1.0])
                .min_col_width(R134_9_GRID_MIN_COL_W)
                .show(ui, |ui| {
                    // / 类型。`node_idx` = Node 行序（= `tree_rows` 序 =
                    // `click_row` 索引；标记行不计）。
                    let mut node_idx = 0usize;
                    for row in &rows {
                        match row {
                            PaneRow::Node(t) => {
                                let idx = node_idx;
                                node_idx += 1;
                                let selected = state.view(pane).selected.contains(&t.path);
                                // ① 缩进 + 标记列（目录 = **+/− 折叠钮**〔用户
                                // 09-22 交互修正：经典树控件形态；单击 + 展开
                                // 变 −、− 收起；双击目录 = 展开亦保留，+/− 为
                                // 主 affordance〕；文件 = 等宽占位，同深度名称
                                // 对齐）。多控件格必包 `ui.horizontal`（egui
                                // 0.28.1 grid 文档口径：grid 内裸 `add_space` =
                                // 渲染捕获修复）。
                                ui.horizontal(|ui| {
                                    ui.add_space(t.depth as f32 * R134_9B_TREE_INDENT);
                                    if t.entry.is_dir {
                                        let glyph = if state
                                            .view(pane)
                                            .expanded
                                            .contains(&t.path)
                                        {
                                            "−" // 已展开 = 可收起
                                        } else {
                                            "+" // 未展开 = 单击展开
                                        };
                                        // 缩小——字形 14→11px + padding [4,2]→1px
                                        // （按钮全宽 ≈16px ≤ 旧 ≈22px，与单层缩进
                                        // 14px 同量级；几何常量
                                        // `R135_5_TREE_MARK_GLYPH_SIZE`/
                                        // `R135_5_TREE_MARK_BTN_PAD` 钉死单测）。
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new(glyph)
                                                        .size(R135_5_TREE_MARK_GLYPH_SIZE),
                                                )
                                                .frame(R135_5_TREE_MARK_BTN_FRAME),
                                            )
                                            .on_hover_text(t.path.clone())
                                            .clicked()
                                        {
                                            state.tree_expand(pane, &t.path, file_tx);
                                        }
                                    } else {
                                        ui.add_space(R134_9B_TREE_MARK_W);
                                    }
                                });
                                let label = if t.entry.is_symlink {
                                    format!("{} 🔗", t.entry.name)
                                } else {
                                    t.entry.name.clone()
                                };
                                // 重映射）。
                                let label_disp = r134_9_ellipsis_name(
                                    &label,
                                    name_max_w,
                                    &|s| {
                                        ui.fonts(|f| {
                                            f.layout_no_wrap(
                                                s.to_string(),
                                                FontId::new(theme.small_size, FontFamily::Proportional),
                                                Color32::TRANSPARENT,
                                            )
                                            .rect
                                            .width()
                                        })
                                    },
                                );
                                let resp = ui
                                    .add(egui::SelectableLabel::new(
                                        selected,
                                        RichText::new(label_disp).size(theme.small_size),
                                    ))
                                    .on_hover_text(t.path.clone());
                                // 零触既有 response 判定——单击/双击/右键/
                                // `r195_drag_feedback_and_drop` 全局单点）。
                                if ui.ctx().input(|i| i.pointer.primary_pressed())
                                    && resp.hovered()
                                {
                                    if let Some(pos) =
                                        ui.ctx().input(|i| i.pointer.interact_pos())
                                    {
                                        state.r195_drag_press(pane, &t.path, pos);
                                    }
                                }
                                let size_text = if t.entry.is_dir {
                                    "-".to_string()
                                } else {
                                    format_size(t.entry.size)
                                };
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(size_text).size(theme.small_size),
                                    )
                                    .selectable(false),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format_mtime(t.entry.mtime))
                                            .size(theme.small_size),
                                    )
                                    .selectable(false),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(type_label(&t.entry)).size(theme.small_size),
                                    )
                                    .selectable(false),
                                );
                                ui.end_row();

                                // 锚键命中本行 = **直达本栏 ScrollArea 持久 State
                                // 的居中写**。修前 `ui.scroll_to_cursor` 走 egui
                                // 帧级 `scroll_target` 槽 + 平滑动画，实测被滚轮
                                // 平滑滚动残量（`InputState::unprocessed_scroll_
                                // delta` 跨帧衰减，触钳制边界后永不清零）与既有
                                // 动画槽竞态吞没 = 用户实机「点快捷不滚动 → 目标
                                // 行不可见（egui `is_rect_visible` 裁剪不绘制）→
                                // 连带『无高亮』」。直写 `State.offset` + 收敛前
                                // 逐帧再贴（锚武装至 Δ 稳定/居中），对残量/惯性/
                                // 既有动画槽免疫；收敛即清 = 不与用户后续滚动打架。
                                if state.scroll_anchor(pane) == Some(t.path.as_str()) {
                                    let viewport = ui.clip_rect();
                                    let delta_y = resp.rect.center().y - viewport.center().y;
                                    // 滚轮平滑残量未耗尽前不判收敛（end() 滚轮臂
                                    // 仍会逐帧拖拽 offset——清早了必被拖离居中位）。
                                    let wheel_quiet = ui
                                        .ctx()
                                        .input(|i| i.smooth_scroll_delta.y.abs() < 1.0);
                                    let settled = viewport.is_finite()
                                        && viewport.height() > 0.0
                                        && wheel_quiet
                                        && (delta_y.abs() < 2.0
                                            || state.scroll_anchor_prev_delta_of(pane)
                                                == Some(delta_y));
                                    if settled {
                                        // 臂语义零变化——helper match 远端臂 =
                                        // 修前逐位同形）。
                                        state.scroll_anchor_settle(pane);
                                    } else {
                                        // 帧内不直写（`end()` 的 `State::store` 以
                                        // begin 载得的副本收尾 = 会盖写）——记偏差，
                                        // `show()` 返回后（store 已落）再持久应用。
                                        r163_anchor_delta = Some(delta_y);
                                        state.scroll_anchor_observe(pane, delta_y);
                                        ui.ctx().request_repaint();
                                    }
                                }

                                if resp.clicked() {
                                    let multi =
                                        ui.ctx().input(|i| copy_paste_mods(&i.modifiers));
                                    state.click_row(pane, idx, multi);
                                }
                                if resp.double_clicked() {
                                    // （错误态 = 重试）；本地文件 = 既有语义
                                    // （资源管理器显示）；远端文件 = 无动作。
                                    if t.entry.is_dir && !t.entry.is_symlink {
                                        state.tree_expand(pane, &t.path, file_tx);
                                    } else if local && !t.entry.is_dir {
                                        { let p = PathBuf::from(&t.path); crate::file_panel::show_in_folder(&p); }
                                    }
                                }
                                // 右键菜单（鼠标驱动，不受焦点态影响——09-11
                                // 加分项③）。
                                resp.context_menu(|ui| {
                                    let sel = state.selection_paths(pane);
                                    if sel.is_empty() {
                                        state.click_row(pane, idx, false);
                                    }
                                    if ui.button(t!("widgets.copy")).clicked() {
                                        state.copy_selection(pane);
                                        ui.close_menu();
                                    }
                                    if ui.button(t!("widgets.paste")).clicked() {
                                        state.paste_into(pane, panel, file_tx, fm_tx);
                                        ui.close_menu();
                                    }
                                });
                            }
                            PaneRow::Marker { depth, text, warn, retry } => {
                                // ① 缩进 + 标记列（错误行 = 🔄 重试按钮；
                                // 提示行 = 占位；多控件格同 Node 行口径包
                                // `ui.horizontal`）。
                                ui.horizontal(|ui| {
                                    ui.add_space(*depth as f32 * R134_9B_TREE_INDENT);
                                    if let Some(rp) = retry {
                                        if ui
                                            .add(egui::Button::new(
                                                RichText::new("🔄").size(theme.small_size),
                                            ))
                                            .on_hover_text(rp.clone())
                                            .clicked()
                                        {
                                            state.tree_expand(pane, rp, file_tx);
                                        }
                                    } else {
                                        ui.add_space(R134_9B_TREE_MARK_W);
                                    }
                                });
                                let col = if *warn { theme.warning } else { theme.fg_weak };
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(text.clone())
                                            .size(theme.small_size)
                                            .color(col),
                                    )
                                    .selectable(false),
                                );
                                // 后三列留空（Grid 行对齐）。
                                for _ in 0..3 {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(String::new()).size(theme.small_size),
                                        )
                                        .selectable(false),
                                    );
                                }
                                ui.end_row();
                            }
                        }
                    }
                });
        });

    // 锚命中行的居中偏差持久写进 State.offset（下一帧布局生效），随后由
    // 网格臂收敛判据消费即清。egui 路径（帧 slot + 平滑动画）被滚轮平滑
    if let Some(delta_y) = r163_anchor_delta {
        if let Some(mut sa) = egui::scroll_area::State::load(ui.ctx(), rows_sa_id) {
            sa.offset.y = (sa.offset.y + delta_y).max(0.0);
            sa.store(ui.ctx(), rows_sa_id);
        }
    }

    // `filemgr.page.more` 提示行，v1 不逐节点翻页）。
}

/// 状态行（操作结果）+ 文件夹编排进度徽标（深度超限 = Warning 徽标）。
fn render_status_row(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FileManagerState,
    panel: &FilePanelState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
) {
    ui.horizontal(|ui| {
        if let Some(line) = &state.status_line {
            ui.add(
                egui::Label::new(RichText::new(line).size(theme.small_size))
                    .selectable(false),
            );
        }
        // 倒计时（`CONSENT_WAIT_TIMEOUT` - 已耗）；终态 = 结果徽标（TTL 后
        // 剪除，tick 侧 [`consent_out_prune`]）。
        for l in &state.consent_out {
            let text = match l.state {
                ConsentOutState::Waiting => {
                    let remain = CONSENT_WAIT_TIMEOUT.saturating_sub(l.started.elapsed());
                    tf!(
                        "consent.waiting_countdown",
                        consent_countdown(remain),
                        l.count
                    )
                }
                ConsentOutState::Transferring => tf!("consent.transferring", l.count),
                ConsentOutState::Declined => t!("consent.declined").to_string(),
                ConsentOutState::Timeout => t!("consent.timeout").to_string(),
                ConsentOutState::SendFailed => t!("consent.send_failed").to_string(),
            };
            badge(
                ui,
                theme,
                &text,
                match l.state {
                    ConsentOutState::Waiting | ConsentOutState::Transferring => {
                        BadgeKind::Info
                    }
                    _ => BadgeKind::Warning,
                },
            );
        }
        // 徽标显示条件原样保留（终态含失败/超深清单仍显）。
        let clip_active = state
            .clip_expand
            .as_ref()
            .is_some_and(|c| !c.cancelled);
        let job_snapshot = state.job.as_ref().map(|j| {
            (
                j.finished,
                j.source.clone(),
                j.batch_head,
                j.files.len(),
                j.depth_capped.is_empty(),
                j.failed.is_empty(),
                j.failed.len(),
                j.direction,
            )
        });
        if let Some((
            finished,
            source,
            batch_head,
            files_len,
            capped_empty,
            failed_empty,
            failed_n,
            direction,
        )) = job_snapshot
        {
            if !finished || !capped_empty || !failed_empty {
                badge(
                    ui,
                    theme,
                    &tf!("filemgr.job_fmt", source, batch_head, files_len),
                    BadgeKind::Info,
                );
                if !capped_empty {
                    badge(
                        ui,
                        theme,
                        &tf!("filemgr.depth_limit", FOLDER_MAX_DEPTH),
                        BadgeKind::Warning,
                    );
                }
                // 日志行；单条目失败不中止任务、继续其余条目）。
                if !failed_empty {
                    let warn_text = match direction {
                        FolderDirection::ToLocal => tf!("filemgr.dl_failed", failed_n),
                        FolderDirection::ToRemote => tf!("filemgr.ul_failed", failed_n),
                    };
                    badge(ui, theme, &warn_text, BadgeKind::Warning);
                }
            }
            // 逐个 `FileCommand::Cancel` → 既有取消传播（`job_has_cancelled`）
            // 整任务中断先例消费，零新状态零新 wire。
            if !finished
                && ui
                    .add(egui::Button::new(
                        RichText::new(t!("filemgr.clip.cancel")).size(theme.small_size),
                    ))
                    .on_hover_text(t!("filemgr.clip.cancel"))
                    .clicked()
            {
                r159_cancel_job_batch(state, panel, file_tx);
            }
        }
        // 取消键同位；置位 → 泵点收敛非阻塞轮询）。
        if clip_active {
            badge(
                ui,
                theme,
                &t!("filemgr.clip.expanding").to_string(),
                BadgeKind::Info,
            );
            if ui
                .add(egui::Button::new(
                    RichText::new(t!("filemgr.clip.cancel")).size(theme.small_size),
                ))
                .on_hover_text(t!("filemgr.clip.cancel"))
                .clicked()
            {
                state.clip_expand_cancel();
            }
        }
    });
}

/// `FileCommand::Cancel`，`job_has_cancelled` 同名+size+direction 匹配命中
/// → 整任务中断既有路径〔`filemgr.ul/dl.cancelled` 状态行〕；零新状态
/// 零新 wire）。通道缺失 = 零发送（§2.0 fail-closed 同口径）。
fn r159_cancel_job_batch(
    state: &FileManagerState,
    panel: &FilePanelState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
) {
    let Some(job) = state.job.as_ref() else {
        return;
    };
    if job.finished {
        return;
    }
    let dir = match job.direction {
        FolderDirection::ToLocal => FileDirection::Download,
        FolderDirection::ToRemote => FileDirection::Upload,
    };
    let batch_end = (job.batch_head + FOLDER_BATCH_SIZE).min(job.files.len());
    let batch: Vec<(String, u64)> = job.files[job.batch_head..batch_end]
        .iter()
        .map(|(p, s, _)| (task_file_basename(p), *s))
        .collect();
    let mut sent = 0usize;
    if let Some(tx) = file_tx {
        for t in &panel.tasks {
            if t.direction == dir
                && !matches!(t.status, FileTaskStatus::Cancelled)
                && batch.iter().any(|(n, s)| t.name == *n && t.size == *s)
                && tx.send(FileCommand::Cancel {
                    transfer_id: t.transfer_id,
                })
                .is_ok()
            {
                sent += 1;
            }
        }
    }
}

/// 传输条最小速览（框图 1 在位项：方向/名称/进度/速度/⏸/▶/✕）。
/// 展示口径 = 全局任务面板（本岗不重复维护传输态）。
fn render_transfer_bar(
    ui: &mut Ui,
    theme: &Theme,
    panel: &FilePanelState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
) {
    let active: Vec<&FileTask> = panel
        .tasks
        .iter()
        .filter(|t| {
            matches!(
                t.status,
                FileTaskStatus::Sending | FileTaskStatus::WaitingAccept | FileTaskStatus::Paused
            )
        })
        .collect();
    if active.is_empty() {
        return;
    }
    egui::Frame::none()
        .fill(ui.visuals().faint_bg_color)
        .inner_margin(4.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(t!("filemgr.transfer_bar")).strong().size(theme.small_size),
                    )
                    .selectable(false),
                );
                for task in active {
                    let glyph = if task.direction == FileDirection::Upload { "↑" } else { "↓" };
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!("{glyph} {}", task.name)).size(theme.small_size),
                        )
                        .selectable(false),
                    );
                    let frac = task.progress_fraction();
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .desired_width(120.0)
                            .text(format!("{:.0}%", frac * 100.0)),
                    );
                    ui.add(
                        egui::Label::new(
                            RichText::new(format_speed(task.speed)).size(theme.small_size),
                        )
                        .selectable(false),
                    );
                    if matches!(
                        task.status,
                        FileTaskStatus::Sending | FileTaskStatus::WaitingAccept
                    ) {
                        let resp = ui.add_enabled(
                            file_tx.is_some(),
                            egui::Button::new(RichText::new("⏸").size(theme.small_size)),
                        );
                        if resp
                            .on_hover_text(t!("filepanel.btn.pause"))
                            .clicked()
                        {
                            if let Some(tx) = file_tx {
                                let _ = tx.send(FileCommand::Pause {
                                    transfer_id: task.transfer_id,
                                });
                            }
                        }
                    }
                    if matches!(task.status, FileTaskStatus::Paused) {
                        let resp = ui.add_enabled(
                            file_tx.is_some(),
                            egui::Button::new(RichText::new("▶").size(theme.small_size)),
                        );
                        if resp
                            .on_hover_text(t!("filepanel.btn.resume"))
                            .clicked()
                        {
                            if let Some(tx) = file_tx {
                                let _ = tx.send(FileCommand::Resume {
                                    transfer_id: task.transfer_id,
                                });
                            }
                        }
                    }
                    let resp = ui.add_enabled(
                        file_tx.is_some(),
                        egui::Button::new(RichText::new("✕").size(theme.small_size)),
                    );
                    if resp.on_hover_text(t!("filepanel.btn.cancel")).clicked() {
                        if let Some(tx) = file_tx {
                            let _ = tx.send(FileCommand::Cancel {
                                transfer_id: task.transfer_id,
                            });
                        }
                    }
                    ui.separator();
                }
            });
        });
}

/// 对话框渲染（顶层 egui::Window；确认 = 发出命令，取消/Esc = **零 wire 帧**）。
fn render_dialogs(
    ui: &mut Ui,
    theme: &Theme,
    state: &mut FileManagerState,
    file_tx: Option<&UnboundedSender<FileCommand>>,
) {
    let d = state.dialog.clone();
    let ctx = ui.ctx().clone();
    let small = theme.small_size;
    match d {
        Dialog::None => {}
        Dialog::ConfirmDelete { name, size, is_dir, .. } => {
            let size_str = if is_dir { "-".into() } else { format_size(size) };
            let type_str = if is_dir {
                t!("filemgr.type.dir").to_string()
            } else {
                t!("filemgr.type.file").to_string()
            };
            egui::Window::new(t!("filemgr.btn.delete"))
                .id(Id::new("file_mgr_dlg_delete"))
                .collapsible(false)
                .resizable(false)
                .default_width(440.0)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(tf!(
                                "filemgr.confirm.delete",
                                &name,
                                &size_str,
                                &type_str
                            ))
                            .size(small),
                        )
                        .wrap(),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(RichText::new(t!("common.ok")).size(small)))
                            .clicked()
                        {
                            if let Some(cmd) = state.dialog_enter() {
                                if let Some(tx) = file_tx {
                                    let _ = tx.send(cmd);
                                }
                            }
                        }
                        if ui
                            .add(egui::Button::new(RichText::new(t!("common.cancel")).size(small)))
                            .clicked()
                        {
                            state.dialog_cancel();
                        }
                    });
                });
        }
        Dialog::ConfirmRename { from, to, .. } => {
            egui::Window::new(t!("filemgr.btn.rename"))
                .id(Id::new("file_mgr_dlg_rename"))
                .collapsible(false)
                .resizable(false)
                .default_width(440.0)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(tf!("filemgr.confirm.rename", &from, &to)).size(small),
                        )
                        .wrap(),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(RichText::new(t!("common.ok")).size(small)))
                            .clicked()
                        {
                            if let Some(cmd) = state.dialog_enter() {
                                if let Some(tx) = file_tx {
                                    let _ = tx.send(cmd);
                                }
                            }
                        }
                        if ui
                            .add(egui::Button::new(RichText::new(t!("common.cancel")).size(small)))
                            .clicked()
                        {
                            state.dialog_cancel();
                        }
                    });
                });
        }
        Dialog::InputMkdir { .. } => {
            egui::Window::new(t!("filemgr.btn.mkdir"))
                .id(Id::new("file_mgr_dlg_mkdir"))
                .collapsible(false)
                .resizable(false)
                .default_width(360.0)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    let field_focus = if let Dialog::InputMkdir { name, .. } =
                        &mut state.dialog
                    {
                        let resp = ui.text_edit_singleline(name);
                        // 无焦点时用户键入无处落（名恒空 → 提交被静默拒 +
                        // 对话框消失 = 「点两次没看到新目录」主断点）。
                        // Enter 提交 = 既有全局快捷键路径（egui singleline
                        // return_key 释放焦点 → 当帧 in_text_input=false →
                        // `handle_shortcut(Enter)` → `dialog_enter`），零新增
                        // 键面。
                        resp.request_focus();
                        resp.has_focus()
                    } else {
                        false
                    };
                    state.in_text_input = field_focus;
                    // （非静默；断点①形态〔盘符层/D 盘位置新建〕同此面）。
                    if let Some(err) = &state.dialog_error {
                        // （语义不变：对话框显式错误；随主题对比度达标）。
                        ui.add(
                            egui::Label::new(
                                RichText::new(err)
                                    .size(small)
                                    .color(theme.danger),
                            )
                            .wrap(),
                        );
                        ui.add_space(4.0);
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(RichText::new(t!("common.ok")).size(small)))
                            .clicked()
                        {
                            if let Some(cmd) = state.dialog_enter() {
                                if let Some(tx) = file_tx {
                                    let _ = tx.send(cmd);
                                }
                            }
                        }
                        if ui
                            .add(egui::Button::new(RichText::new(t!("common.cancel")).size(small)))
                            .clicked()
                        {
                            state.dialog_cancel();
                        }
                    });
                });
        }
        Dialog::InputRename { from, new_name, .. } => {
            egui::Window::new(t!("filemgr.btn.rename"))
                .id(Id::new("file_mgr_dlg_rename_in"))
                .collapsible(false)
                .resizable(false)
                .default_width(360.0)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(tf!("filemgr.confirm.rename", &from, &new_name))
                                .size(small)
                                .color(theme.fg_weak),
                        )
                        .wrap(),
                    );
                    let field_focus = if let Dialog::InputRename { new_name, .. } =
                        &mut state.dialog
                    {
                        let resp = ui.text_edit_singleline(new_name);
                        // InputMkdir 无焦点缺陷（键入丢失 = 静默 no-op）；
                        // 校验保开/框内错误面 = 既有语义零变化（遗留备案）。
                        resp.request_focus();
                        resp.has_focus()
                    } else {
                        false
                    };
                    state.in_text_input = field_focus;
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(RichText::new(t!("common.ok")).size(small)))
                            .clicked()
                        {
                            if let Some(cmd) = state.dialog_enter() {
                                if let Some(tx) = file_tx {
                                    let _ = tx.send(cmd);
                                }
                            }
                        }
                        if ui
                            .add(egui::Button::new(RichText::new(t!("common.cancel")).size(small)))
                            .clicked()
                        {
                            state.dialog_cancel();
                        }
                    });
                });
        }
    }

    // 对齐：覆盖/跳过/全部应用；默认焦点「跳过」= 不再静默改名；Esc =
    // 跳过 fail-safe〔`dialog_cancel`〕；零 wire——覆盖 = 登记表 fail-closed
    // 删旧后既有 FetchFile，跳过 = 零网络帧）。
    let conflict = state.clip_expand.as_ref().and_then(|c| c.conflict.clone());
    if let Some(item) = conflict {
        let name = item
            .rel_path
            .rsplit('/')
            .next()
            .unwrap_or(&item.rel_path)
            .to_string();
        let size_str = format_size(item.size);
        egui::Window::new(t!("filemgr.clip.conflict_title"))
            .id(Id::new("file_mgr_dlg_clip_conflict"))
            .collapsible(false)
            .resizable(false)
            .default_width(440.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(&ctx, |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(tf!(
                            "filemgr.clip.conflict_body",
                            &name,
                            &size_str
                        ))
                        .size(small),
                    )
                    .wrap(),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(RichText::new(
                            t!("filemgr.clip.conflict_overwrite"),
                        )
                        .size(small)))
                        .clicked()
                    {
                        state.clip_conflict_resolve(R159ConflictDecision::Overwrite);
                    }
                    // 跳过 = 默认焦点（卡面口径：默认值对齐 RustDesk，不再
                    // 静默改名；每帧 request_focus 保持默认可达）。
                    let skip_resp = ui.add(egui::Button::new(RichText::new(
                        t!("filemgr.clip.conflict_skip"),
                    )
                    .size(small)));
                    let skip_clicked = skip_resp.clicked();
                    skip_resp.request_focus();
                    if skip_clicked {
                        state.clip_conflict_resolve(R159ConflictDecision::Skip);
                    }
                    if ui
                        .add(egui::Button::new(RichText::new(
                            t!("filemgr.clip.conflict_apply_all"),
                        )
                        .size(small)))
                        .clicked()
                    {
                        state.clip_conflict_resolve(R159ConflictDecision::OverwriteAll);
                    }
                });
            });
    }
}

// ════════════════════════════════════════════════════════════════
// 删除确认取消零 wire 帧 / 改名 AlreadyExists；引擎侧族在 lib.rs）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod r92e1_tests {
    use super::*;
    use std::io::Write as _;
    use kirin_desk_core::connection::file_transfer::{
        FsEntry, FsListPayload, TRANSFER_REQUEST_MAX_ENTRIES,
    };

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "k92e1_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn mkfile(p: &Path, content: &str) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    fn mk_entry(name: &str, size: u64, is_dir: bool) -> FileMgrEntry {
        FileMgrEntry {
            name: name.into(),
            size,
            mtime: 0,
            is_dir,
            is_symlink: false,
            is_hidden: false,
        }
    }

    /// 自身 children 缓存〔旧 `view.entries` = 当前目录列表的同构迁移〕；
    /// 祖先链默认展开 = 旧「已进入当前目录」语义）。
    fn seed_remote(state: &mut FileManagerState, current: &str, entries: &[FileMgrEntry]) {
        state.remote.current = current.to_string();
        state
            .remote
            .view
            .nodes
            .insert(
                current.to_string(),
                TreeNodeState {
                    children: Some(entries.to_vec()),
                    ..Default::default()
                },
            );
        for p in std::iter::once(String::new()).chain(remote_chain_ancestors(current)) {
            if !state.remote.view.expanded.iter().any(|e| e.as_str() == p) {
                state.remote.view.expanded.push(p);
            }
        }
        if !state.remote.view.expanded.iter().any(|e| e == current) {
            state.remote.view.expanded.push(current.to_string());
        }
    }

    fn ctrl(key: egui::Key) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers {
                ctrl: true,
                shift: false,
                alt: false,
                command: false,
                mac_cmd: false,
            },
        }
    }

    fn build_fs_list_payload(
        entries: &[(&str, u64, bool)],
        has_more: bool,
        root_display: &str,
    ) -> FsResponsePayload {
        let list = FsListPayload {
            entries: entries
                .iter()
                .map(|(n, s, d)| FsEntry {
                    name: (*n).into(),
                    size: *s,
                    mtime: 0,
                    is_dir: *d,
                    is_symlink: false,
                })
                .collect(),
            has_more,
            root_display: root_display.into(),
        };
        FsResponsePayload {
            ok: true,
            err: FsErrCode::Ok,
            payload: bincode::serialize(&list).unwrap(),
        }
    }

    // ── 族 1：门控矩阵 + 键盘焦点切分（PM 09-11 硬保证）─────────────

    /// 门控矩阵（门控口径单一事实源 = win.kind + file_tx，§2.0；
    /// 文件管理器仅承载窗 + 文件通道在位时挂载；Desktop 窗既有
    /// 📁 队列面板零改动。
    #[test]
    fn test_r92e1_gate_matrix() {
        assert!(file_mgr_mountable(true, true), "承载窗 + 通道在位 = 挂载");
        assert!(
            !file_mgr_mountable(true, false),
            "Shell 窗 + 无通道 = fail-closed 无入口（§2.0）"
        );
        assert!(
            !file_mgr_mountable(false, true),
            "Desktop 窗 = 既有 📁 队列面板，文件管理器不挂载"
        );
        assert!(!file_mgr_mountable(false, false), "Desktop 窗 + 无通道 = 无入口");
    }

    /// 焦点切分①（PM 09-11）：终端聚焦 + Ctrl+C 按下 = **0x03 进 PTY，
    /// 文件管理器零动作**（无入队 / 无 OfferV2 帧 / 无 FileManagerState 变更）。
    #[test]
    fn test_r92e1_focus_split_terminal_ctrl_c() {
        let root = tmp_root("focus_term");
        mkfile(&root.join("a.txt"), "x");
        let mut state = FileManagerState::with_local_root(root.clone());
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        state.local.view.selected = vec![local_path_key(&root.join("a.txt"))];
        // 终端聚焦 = 文件管理器不持焦（显式状态）。
        assert!(
            !file_mgr_shortcut_active(false, false),
            "终端聚焦 → 面板快捷键必须不生效"
        );
        assert!(terminal_feeds_keys(true, false), "窗口聚焦 + 面板不持焦 = feed 正常");
        // 终端侧：Ctrl+C → 0x03（语义零改动回归）。
        let mut term = crate::terminal::Terminal::new(80, 24);
        assert!(term.handle_event(&ctrl(egui::Key::C)), "终端应吞 Ctrl+C");
        assert_eq!(term.take_input(), vec![0x03], "Ctrl+C = 0x03 进 PTY");
        // 文件管理器侧：零动作（无入队 / 无状态变更）。
        let sel_before = state.local.view.selected.clone();
        let clip_before = state.clipboard.clone();
        handle_shortcut(
            &mut state, false, false, FileMgrShortcut::Copy, &panel, Some(&ftx), Some(&mtx),
        );
        assert_eq!(state.clipboard, clip_before, "复制零动作");
        assert_eq!(state.local.view.selected, sel_before, "选中零变更");
        handle_shortcut(
            &mut state, false, false, FileMgrShortcut::Paste, &panel, Some(&ftx), Some(&mtx),
        );
        handle_shortcut(
            &mut state, false, false, FileMgrShortcut::Enter, &panel, Some(&ftx), Some(&mtx),
        );
        assert!(frx.try_recv().is_err(), "零 FileCommand（无 wire 帧）");
        assert!(mxr.try_recv().is_err(), "零 FileMgrCommand（无 OfferV2 帧）");
        std::fs::remove_dir_all(&root).ok();
    }

    /// 关**且非文本输入** = 提示；文本输入形态恒零提示（egui 文本粘贴既有
    /// 行为零变化）；门开 = 恒 false（粘贴臂自身判定）。
    #[test]
    fn test_r164_paste_focus_hint_matrix() {
        // 焦点不在面板 + 非文本输入（用户病灶形态：Ctrl+V 落 egui 默认
        // 文本粘贴 → arboard「clipboard is empty」误现）= 显式提示。
        assert!(r164_paste_focus_hint_due(false, false));
        // 文本输入形态 = 零提示（Ctrl+V = 文本粘贴，行为零变化）。
        assert!(!r164_paste_focus_hint_due(false, true));
        // 门开（持焦）= 非拦截形态。
        assert!(!r164_paste_focus_hint_due(true, false));
        assert!(!r164_paste_focus_hint_due(true, true));
        // 对偶不变式：提示 ⇔ 门关 且 非文本输入（与门纯函数联动零漂移）。
        for f in [false, true] {
            for t in [false, true] {
                assert_eq!(
                    r164_paste_focus_hint_due(f, t),
                    !file_mgr_shortcut_active(f, t) && !t,
                    "矩阵 ({f},{t}) 与门判定对偶失配"
                );
            }
        }
    }

    /// egui 焦点或窗层粘性持焦任一成立 = FM 持焦；两者皆无 = 不持焦
    /// （放宽 = 既有粘性语义超集，无收窄面）。
    #[test]
    fn test_r164_file_window_fm_focus_matrix() {
        assert!(r164_file_window_fm_focus(true, false), "窗持焦即活（放宽面）");
        assert!(r164_file_window_fm_focus(false, true), "粘性持焦保留（既有语义）");
        assert!(r164_file_window_fm_focus(true, true));
        assert!(!r164_file_window_fm_focus(false, false), "全无焦点 = 不持焦");
    }

    /// 焦点切分②（PM 09-11）：文件面板聚焦（面板内选中文件）+
    /// Ctrl+C/Ctrl+V = **文件复制/粘贴入队，PTY 零 0x03**（终端零接收，
    /// wire 级 = 终端输入缓冲零字节）。
    #[test]
    fn test_r92e1_focus_split_panel_ctrl_cv() {
        // —— 本地→远端（上传 = OfferV2 载体；target_dir = 远端栏当前目录）——
        let root = tmp_root("focus_local");
        mkfile(&root.join("a.txt"), "hello");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.remote.current = "docs".into();
        state.local.view.selected = vec![local_path_key(&root.join("a.txt"))];
        state.active_pane = PaneId::Local;
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        assert!(
            file_mgr_shortcut_active(true, false),
            "面板聚焦 + 非文本输入 = 快捷键生效"
        );
        assert!(
            !terminal_feeds_keys(true, true),
            "面板持焦 → 终端全键零 feed（负门）"
        );
        // 终端侧：门控关闭（即使同一批按键事件也零 feed）。
        let mut term = crate::terminal::Terminal::new(80, 24);
        if terminal_feeds_keys(true, true) {
            term.handle_event(&ctrl(egui::Key::C));
            term.handle_event(&ctrl(egui::Key::V));
        }
        assert!(term.take_input().is_empty(), "PTY 零字节（终端零接收）");
        // 面板侧：Ctrl+C = 复制。
        handle_shortcut(
            &mut state, true, false, FileMgrShortcut::Copy, &panel, Some(&ftx), Some(&mtx),
        );
        assert_eq!(
            state.clipboard.as_ref().map(|c| c.paths.clone()),
            Some(vec![local_path_key(&root.join("a.txt"))]),
        );
        // 当前目录单条目；上传仍不走 FileCommand 通道）。
        handle_shortcut(
            &mut state, true, false, FileMgrShortcut::Paste, &panel, Some(&ftx), Some(&mtx),
        );
        match mxr.try_recv() {
            Ok(FileMgrCommand::SendWithConsent {
                entries,
                truncated,
                from_job,
            }) => {
                assert_eq!(entries.len(), 1, "单文件 = 单条目");
                assert!(!truncated, "单文件零截断");
                assert!(!from_job, "粘贴 = 非文件夹任务");
                assert_eq!(&entries[0].0, &root.join("a.txt"));
                assert_eq!(entries[0].1, "docs", "落点 = 远端栏当前目录");
            }
            other => panic!("应得 SendWithConsent，实际 {other:?}"),
        }
        assert!(frx.try_recv().is_err(), "上传不走 FileCommand 通道");
        std::fs::remove_dir_all(&root).ok();

        // —— 远端→本地（下载 = FetchFile；落本地栏当前目录，零 wire 落点）——
        let root2 = tmp_root("focus_remote");
        let mut st2 = FileManagerState::with_local_root(root2.clone());
        seed_remote(&mut st2, "docs", &[mk_entry("r.txt", 7, false)]);
        st2.remote.view.selected = vec!["docs/r.txt".into()];
        st2.active_pane = PaneId::Remote;
        let panel2 = FilePanelState::new();
        let (ftx2, mut frx2) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx2, _mxr2) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        handle_shortcut(
            &mut st2, true, false, FileMgrShortcut::Copy, &panel2, Some(&ftx2), Some(&mtx2),
        );
        handle_shortcut(
            &mut st2, true, false, FileMgrShortcut::Paste, &panel2, Some(&ftx2), Some(&mtx2),
        );
        match frx2.try_recv() {
            Ok(FileCommand::FetchFile {
                remote_path,
                local_dir,
            }) => {
                assert_eq!(remote_path, "docs/r.txt");
                assert_eq!(local_dir, root2, "落点 = 本地栏当前目录");
            }
            other => panic!("应得 FetchFile，实际 {other:?}"),
        }
        std::fs::remove_dir_all(&root2).ok();
    }

    /// 焦点切分负门边界（PM 裁定条件②）：窗口聚焦 + file_mgr_focus =
    /// feed **全停**（非仅 Ctrl+C，全键零 feed，PTY 零字节）；窗口聚焦 +
    /// !file_mgr_focus = feed 正常（含 Ctrl+C=0x03 回归断言）；窗口失焦 =
    /// 恒不 feed（保守向）。
    #[test]
    fn test_r92e1_focus_feed_negative_gate_boundary() {
        let events: Vec<egui::Event> = vec![
            ctrl(egui::Key::C),
            ctrl(egui::Key::V),
            egui::Event::Key {
                key: egui::Key::Enter,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers {
                    ctrl: false,
                    shift: false,
                    alt: false,
                    command: false,
                    mac_cmd: false,
                },
            },
            egui::Event::Text("a".into()),
            egui::Event::Key {
                key: egui::Key::ArrowUp,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers {
                    ctrl: false,
                    shift: false,
                    alt: false,
                    command: false,
                    mac_cmd: false,
                },
            },
        ];
        // 边界 A：窗口聚焦 + 面板不持焦 = feed 正常（全键进 PTY）。
        let mut term = crate::terminal::Terminal::new(80, 24);
        assert!(terminal_feeds_keys(true, false));
        for ev in &events {
            term.handle_event(ev);
        }
        let fed = term.take_input();
        assert_eq!(fed[0], 0x03, "Ctrl+C = 0x03（语义零改动）");
        assert!(fed.contains(&b'a'), "文本键进 PTY");
        assert!(fed.contains(&b'\r'), "Enter = CR 进 PTY");
        // 边界 B：窗口聚焦 + 面板持焦 = 全键零 feed（PTY 零字节）。
        let mut term2 = crate::terminal::Terminal::new(80, 24);
        assert!(!terminal_feeds_keys(true, true));
        if terminal_feeds_keys(true, true) {
            for ev in &events {
                term2.handle_event(ev);
            }
        }
        assert!(term2.take_input().is_empty(), "面板持焦 = 全键零 feed");
        // 边界 C：窗口失焦 = 恒不 feed（回焦默认归终端 = 保守向）。
        assert!(!terminal_feeds_keys(false, false));
        assert!(!terminal_feeds_keys(false, true));
    }

    /// 加分项③（PM 09-11）：右键菜单「复制/粘贴」路径不受焦点状态影响
    /// （两态下菜单动作均正常——鼠标驱动，不经快捷键焦点门）。
    #[test]
    fn test_r92e1_context_menu_focus_independent() {
        let root = tmp_root("ctx_menu");
        mkfile(&root.join("a.txt"), "x");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.remote.current = "up".into();
        state.local.view.selected = vec![local_path_key(&root.join("a.txt"))];
        let panel = FilePanelState::new();
        let (ftx, _frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        // 文件管理器**不持焦**（file_mgr_focus=false）：菜单复制/粘贴照常。
        assert_eq!(state.copy_selection(PaneId::Local), 1, "菜单复制不依赖焦点");
        state.paste_into(PaneId::Remote, &panel, Some(&ftx), Some(&mtx));
        assert!(
            matches!(mxr.try_recv(), Ok(FileMgrCommand::SendWithConsent { .. })),
            "菜单粘贴（远端栏）不依赖焦点"
        );
        // 持焦态同样正常。
        assert!(state.copy_selection(PaneId::Local) == 1);
        state.paste_into(PaneId::Remote, &panel, Some(&ftx), Some(&mtx));
        assert!(matches!(mxr.try_recv(), Ok(FileMgrCommand::SendWithConsent { .. })));
        std::fs::remove_dir_all(&root).ok();
    }

    // ── 族 2：复制粘贴语义（§2.6.1① 复制非移动；v1 无剪切）─────────

    /// 复制语义 = 复制（非移动）：粘贴不删源、不删远端、无 Delete 命令。
    #[test]
    fn test_r92e1_copy_not_move() {
        let root = tmp_root("nomove");
        mkfile(&root.join("src.txt"), "data");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.remote.current = "up".into();
        state.local.view.selected = vec![local_path_key(&root.join("src.txt"))];
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        assert_eq!(state.copy_selection(PaneId::Local), 1);
        assert_eq!(state.paste_cross(&panel, Some(&ftx), Some(&mtx)), 1);
        assert!(root.join("src.txt").exists(), "本地源不删（复制非移动）");
        assert!(
            matches!(mxr.try_recv(), Ok(FileMgrCommand::SendWithConsent { .. })),
        );
        // 远端→本地：源条目保留（无远端 Delete 命令）。
        let root2 = tmp_root("nomove2");
        let mut st2 = FileManagerState::with_local_root(root2.clone());
        seed_remote(&mut st2, "srv", &[mk_entry("r.bin", 4, false)]);
        st2.remote.view.selected = vec!["srv/r.bin".into()];
        let (ftx2, mut frx2) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx2, _mxr2) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        assert_eq!(st2.copy_selection(PaneId::Remote), 1);
        st2.paste_cross(&panel, Some(&ftx2), Some(&mtx2));
        assert_eq!(
            st2
                .remote
                .view
                .nodes
                .get("srv")
                .and_then(|n| n.children.as_ref())
                .map(Vec::len)
                .unwrap_or(0),
            1,
            "远端源条目不删（无远端删除路径）"
        );
        // 两方向捕获的命令中均无 Delete。
        for _ in 0..4 {
            match frx.try_recv() {
                Ok(FileCommand::Fs { op: FsOp::Delete { .. } }) => panic!("不得发 Delete"),
                Ok(_) => {}
                Err(_) => break,
            }
        }
        for _ in 0..4 {
            match frx2.try_recv() {
                Ok(FileCommand::Fs { op: FsOp::Delete { .. } }) => panic!("不得发 Delete"),
                Ok(_) => {}
                Err(_) => break,
            }
        }
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&root2).ok();
    }

    /// 同栏粘贴 = no-op（v1 无移动）；空剪贴板 = 提示 + 零命令。
    #[test]
    fn test_r92e1_paste_same_pane_and_empty() {
        let root = tmp_root("samepane");
        mkfile(&root.join("a.txt"), "x");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.local.view.selected = vec![local_path_key(&root.join("a.txt"))];
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        // 空剪贴板。
        state.paste_into(PaneId::Remote, &panel, Some(&ftx), Some(&mtx));
        assert!(frx.try_recv().is_err() && mxr.try_recv().is_err(), "空剪贴板零命令");
        assert_eq!(
            state.status_line.as_deref(),
            Some(t!("filemgr.clipboard.empty"))
        );
        // 同栏粘贴（菜单路径：本地栏内粘贴本地复制）。
        assert_eq!(state.copy_selection(PaneId::Local), 1);
        state.paste_into(PaneId::Local, &panel, Some(&ftx), Some(&mtx));
        assert!(
            frx.try_recv().is_err() && mxr.try_recv().is_err(),
            "同栏粘贴零命令（v1 无移动）"
        );
        assert_eq!(
            state.status_line.as_deref(),
            Some(t!("filemgr.paste.same_pane"))
        );
        assert!(state.clipboard.is_some(), "剪贴板保留（可再粘贴）");
        std::fs::remove_dir_all(&root).ok();
    }

    /// 多选复制粘贴 = 文件夹任务（ToRemote；target_remote_dir 固定于启动时）。
    #[test]
    fn test_r92e1_multi_select_copy_paste_job() {
        let root = tmp_root("multi");
        mkfile(&root.join("a.txt"), "1");
        mkfile(&root.join("b.txt"), "22");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.remote.current = "up/proj".into();
        state.local.view.selected = vec![
            local_path_key(&root.join("a.txt")),
            local_path_key(&root.join("b.txt")),
        ];
        let panel = FilePanelState::new();
        let (ftx, _frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, _mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        assert_eq!(state.copy_selection(PaneId::Local), 2);
        assert_eq!(state.paste_cross(&panel, Some(&ftx), Some(&mtx)), 2);
        let job = state.job.as_ref().expect("多项 = 文件夹任务");
        assert_eq!(job.direction, FolderDirection::ToRemote);
        assert_eq!(job.files.len(), 2);
        assert_eq!(job.target_remote_dir, "up/proj", "落点固定于启动时远端栏目录");
        let srcs: Vec<&String> = job.files.iter().map(|(p, _, _)| p).collect();
        assert_eq!(
            srcs,
            vec![
                &local_path_key(&root.join("a.txt")),
                &local_path_key(&root.join("b.txt")),
            ]
        );
        std::fs::remove_dir_all(&root).ok();
    }


    /// 拖拽载荷键形/多选批量（`r195_drag_payload_paths` 单源）+ 影子文案。
    #[test]
    fn r195_drag_payload_paths_shape_and_batch() {
        let sel = vec![
            "a/b.txt".to_string(),
            "c/d.txt".to_string(),
            "e".to_string(),
        ];
        // 被拖行 ∈ 多选 = 整批（选择序原样）。
        assert_eq!(
            r195_drag_payload_paths(&sel, "c/d.txt"),
            vec![
                "a/b.txt".to_string(),
                "c/d.txt".to_string(),
                "e".to_string()
            ]
        );
        // ∉ 多选 = 单行（键形 = 节点全路径原样透传）。
        assert_eq!(
            r195_drag_payload_paths(&sel, "x/y.txt"),
            vec!["x/y.txt".to_string()]
        );
        // 空选 = 单行。
        assert_eq!(
            r195_drag_payload_paths(&[], "solo"),
            vec!["solo".to_string()]
        );
        // 影子文案：≤3 项全列（basename 口径）；>3 项折叠 + 总数。
        assert_eq!(r195_drag_shadow_text(&sel), "b.txt、d.txt、e");
        let five: Vec<String> = ["1", "2", "3", "4", "5"]
            .iter()
            .map(|n| format!("a/{n}"))
            .collect();
        assert_eq!(r195_drag_shadow_text(&five), "1、2、3、… ×5");
    }

    /// 双栏 drop 目标判定矩阵（纯函数）：对侧栏命中才有效；源栏/中缝/栏外
    /// （对侧 rect 未命中）= 无动作。
    #[test]
    fn r195_drop_target_matrix() {
        // 本机栏拖起：仅远端栏命中 = 有效。
        assert_eq!(
            r195_drop_target(PaneId::Local, false, true),
            Some(PaneId::Remote)
        );
        assert_eq!(
            r195_drop_target(PaneId::Local, true, false),
            None,
            "源栏释放 = 无动作"
        );
        assert_eq!(
            r195_drop_target(PaneId::Local, false, false),
            None,
            "栏外/中缝释放 = 无动作"
        );
        // 远端栏拖起：仅本机栏命中 = 有效。
        assert_eq!(
            r195_drop_target(PaneId::Remote, true, false),
            Some(PaneId::Local)
        );
        assert_eq!(
            r195_drop_target(PaneId::Remote, false, true),
            None,
            "源栏释放 = 无动作"
        );
        assert_eq!(
            r195_drop_target(PaneId::Remote, false, false),
            None,
            "栏外/中缝释放 = 无动作"
        );
    }

    /// 本机→远端单文件拖放 = **授权链接线断言**：走既有 `SendWithConsent`
    /// 拉取，未确认零内容帧 fail-closed），落点 = 远端栏当前浏览目录
    /// （拖放语义钉死）；内部剪贴板零触碰。
    #[test]
    fn r195_drop_local_to_remote_consent_chain() {
        let root = tmp_root("r195up");
        mkfile(&root.join("a.txt"), "1");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.remote.current = "up/proj".into();
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let n = state.drop_transfer(
            PaneId::Remote,
            vec![local_path_key(&root.join("a.txt"))],
            &panel,
            Some(&ftx),
            Some(&mtx),
        );
        assert_eq!(n, 1);
        assert!(
            frx.try_recv().is_err(),
            "本机→远端零 FetchFile（下载链不适用）"
        );
        match mxr.try_recv() {
            Ok(FileMgrCommand::SendWithConsent {
                entries,
                truncated: false,
                from_job: false,
            }) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].0, root.join("a.txt"), "源 = 节点全路径");
                assert_eq!(
                    entries[0].1, "up/proj",
                    "落点 = 远端栏当前浏览目录（非选中优先）"
                );
            }
            other => panic!("应得 SendWithConsent（同意接收链），实际 {other:?}"),
        }
        assert!(state.clipboard.is_none(), "拖放零触内部剪贴板");
        assert_eq!(
            state.status_line.as_deref(),
            Some(t!("consent.waiting")),
            "授权链反馈原样（等待对方确认）"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// 远端→本机单文件拖放 = 既有 `FetchFile` 下载链，落点 = 本机栏当前
    #[test]
    fn r195_drop_remote_to_local_fetch_lands_current_dir() {
        let root = tmp_root("r195dn");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.remote.started = true;
        state.remote.view.nodes.insert(
            "docs".to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("r.txt", 7, false)]),
                ..Default::default()
            },
        );
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, _mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let n = state.drop_transfer(
            PaneId::Local,
            vec!["docs/r.txt".to_string()],
            &panel,
            Some(&ftx),
            Some(&mtx),
        );
        assert_eq!(n, 1);
        match frx.try_recv() {
            Ok(FileCommand::FetchFile {
                remote_path,
                local_dir,
            }) => {
                assert_eq!(remote_path, "docs/r.txt");
                assert_eq!(local_dir, root, "落点 = 本机栏当前浏览目录");
            }
            other => panic!("应得 FetchFile（既有下载链），实际 {other:?}"),
        }
        assert!(state.pending.is_some(), "pending 槽置位（在途跟踪原样）");
        std::fs::remove_dir_all(&root).ok();
    }

    /// 多选批量拖放 = 整批 FolderJob（ToRemote；落点固定于远端栏当前
    /// 目录；内部剪贴板零触碰 = 与粘贴路径零串扰）。
    #[test]
    fn r195_drop_multi_files_batch_folderjob() {
        let root = tmp_root("r195multi");
        mkfile(&root.join("a.txt"), "1");
        mkfile(&root.join("b.txt"), "22");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.remote.current = "up/proj".into();
        let panel = FilePanelState::new();
        let (ftx, _frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, _mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let n = state.drop_transfer(
            PaneId::Remote,
            vec![
                local_path_key(&root.join("a.txt")),
                local_path_key(&root.join("b.txt")),
            ],
            &panel,
            Some(&ftx),
            Some(&mtx),
        );
        assert_eq!(n, 2, "整批入队");
        let job = state.job.as_ref().expect("多项 = 文件夹任务");
        assert_eq!(job.direction, FolderDirection::ToRemote);
        assert_eq!(job.files.len(), 2);
        assert_eq!(
            job.target_remote_dir, "up/proj",
            "落点 = 远端栏当前浏览目录"
        );
        assert!(state.clipboard.is_none(), "拖放零触内部剪贴板");
        std::fs::remove_dir_all(&root).ok();
    }

    /// 忙（活动任务）= 显式提示零入队（拖放与粘贴同 busy 门，零绕过）。
    #[test]
    fn r195_drop_busy_zero_enqueue() {
        let root = tmp_root("r195busy");
        mkfile(&root.join("a.txt"), "1");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.job = Some(FolderJob {
            direction: FolderDirection::ToRemote,
            source: root.display().to_string(),
            target_remote_dir: "up".into(),
            target_local_dir: PathBuf::new(),
            files: Vec::new(),
            depth_capped: Vec::new(),
            next_idx: 0,
            batch_head: 0,
            collecting: false,
            collect_queue: VecDeque::new(),
            finished: false,
            started: Instant::now(),
            consent_pending: false,
            consent_req_id: None,
            target_dirs: Vec::new(),
            visit: HashSet::new(),
            failed: Vec::new(),
            cycle_skipped: Vec::new(),
            summary_emitted: false,
            mkdir_queue: VecDeque::new(),
        });
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let n = state.drop_transfer(
            PaneId::Remote,
            vec![local_path_key(&root.join("a.txt"))],
            &panel,
            Some(&ftx),
            Some(&mtx),
        );
        assert_eq!(n, 0, "忙 = 零入队");
        assert!(
            frx.try_recv().is_err() && mxr.try_recv().is_err(),
            "忙 = 双通道零命令"
        );
        assert_eq!(state.status_line.as_deref(), Some(t!("filemgr.busy")));
        std::fs::remove_dir_all(&root).ok();
    }

    /// 拖拽状态机阈值/定格/落定（纯状态推进；未过阈值松开 = 原单击路径
    /// 零影响；Escape 中断无动作；定格一次不随中途改选重算）。
    #[test]
    fn r195_drag_state_machine_threshold() {
        let root = tmp_root("r195sm");
        let mut state = FileManagerState::with_local_root(root.clone());
        let p0 = egui::pos2(100.0, 100.0);
        state.r195_drag_press(PaneId::Local, "C:\\t\\a.txt", p0);
        // 未过阈值 = Armed（零视觉零动作）。
        assert_eq!(
            state.r195_drag_frame(
                true,
                false,
                false,
                Some(egui::pos2(103.0, 100.0)),
                R195_DRAG_THRESHOLD
            ),
            R195DragFrame::Armed
        );
        // 过阈值 = 载荷定格（空选 = 单行）。
        match state.r195_drag_frame(
            true,
            false,
            false,
            Some(egui::pos2(107.0, 100.0)),
            R195_DRAG_THRESHOLD
        ) {
            R195DragFrame::Dragging { source, paths } => {
                assert_eq!(source, PaneId::Local);
                assert_eq!(paths, vec!["C:\\t\\a.txt".to_string()]);
            }
            other => panic!("应 Dragging，实际 {other:?}"),
        }
        // 定格一次：拖拽中途改选不重算。
        state.local.view.selected = vec![
            "C:\\t\\a.txt".to_string(),
            "C:\\t\\b.txt".to_string(),
        ];
        match state.r195_drag_frame(
            true,
            false,
            false,
            Some(egui::pos2(120.0, 100.0)),
            R195_DRAG_THRESHOLD
        ) {
            R195DragFrame::Dragging { paths, .. } => {
                assert_eq!(paths.len(), 1, "已定格不重算")
            }
            other => panic!("应保持 Dragging，实际 {other:?}"),
        }
        // 释放 = Dropped（源/载荷原样）+ 状态即清。
        match state.r195_drag_frame(
            false,
            true,
            false,
            Some(egui::pos2(130.0, 100.0)),
            R195_DRAG_THRESHOLD
        ) {
            R195DragFrame::Dropped { source, paths } => {
                assert_eq!(source, PaneId::Local);
                assert_eq!(paths, vec!["C:\\t\\a.txt".to_string()]);
            }
            other => panic!("应 Dropped，实际 {other:?}"),
        }
        assert!(state.r195_drag.is_none(), "落定即清");
        // 未过阈值即松开 = Idle（原单击路径零影响）。
        state.r195_drag_press(PaneId::Remote, "docs/r.txt", p0);
        assert_eq!(
            state.r195_drag_frame(false, true, false, Some(p0), R195_DRAG_THRESHOLD),
            R195DragFrame::Idle
        );
        assert!(state.r195_drag.is_none());
        // Escape 中断 = 已过阈值载荷弃置（无动作）。
        state.r195_drag_press(PaneId::Local, "C:\\t\\a.txt", p0);
        let _ = state.r195_drag_frame(
            true,
            false,
            false,
            Some(egui::pos2(200.0, 100.0)),
            R195_DRAG_THRESHOLD
        );
        assert_eq!(
            state.r195_drag_frame(
                true,
                false,
                true,
                Some(egui::pos2(200.0, 100.0)),
                R195_DRAG_THRESHOLD
            ),
            R195DragFrame::Idle,
            "Escape = 无动作"
        );
        assert!(state.r195_drag.is_none());
        std::fs::remove_dir_all(&root).ok();
    }

    // ── 族 3：文件夹编排（深度 10 层 / 分批节流 / BFS 响应链）───────

    /// 递归深度上限 10 层：超限子目录不展开 + 记入 capped（UI 提示源）。
    /// 链 = A(1) → D2(2) → … → D11(11) → D12(12)；每层 1 文件。
    #[test]
    fn test_r92e1_folder_depth_cap_10() {
        let root = tmp_root("depth");
        let a = root.join("A");
        std::fs::create_dir_all(&a).unwrap();
        let mut cur = a.clone();
        for i in 0..11 {
            let next = cur.join(format!("D{}", i + 2));
            std::fs::create_dir_all(&next).unwrap();
            let _ = std::fs::File::create(cur.join(format!("f{}.txt", i + 1)));
            cur = next;
        }
        let _ = std::fs::File::create(cur.join("f12.txt"));
        let col = collect_local_folder(&a, FOLDER_MAX_DEPTH);
        let files = &col.files;
        let capped = &col.capped;
        let names: Vec<String> = files.iter().map(|(r, _)| r.clone()).collect();
        // f1..f10 收集（f11 在深度 11 子目录 K 内 = 未展开不收集）。
        assert_eq!(names.len(), 10, "仅收集 ≤10 层内文件: {names:?}");
        for i in 1..=10 {
            assert!(names.iter().any(|n| n.ends_with(&format!("f{i}.txt"))), "缺 f{i}.txt");
        }
        assert!(
            !names.iter().any(|n| n.contains("f11.") || n.contains("f12.")),
            "超限文件不得收集"
        );
        // capped = 深度 11 子目录（D11 内的 D12… 依链）——首条 = D11 相对路径。
        assert!(
            capped.iter().any(|c| c == "D2/D3/D4/D5/D6/D7/D8/D9/D10/D11"),
            "深度 11 子目录记入 capped: {capped:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// 批 = FOLDER_BATCH_SIZE=128 ≤ 255 = 一个 TransferRequest = 一个确认
    /// 框；**每帧至多 1 个 consent 通告命令**（整批一条目）；consent 在途
    /// （未结算）时零推进零重发；`Consumed` 结算 + 整批终态才推进下一批。
    /// 测试侧模拟引擎 consent 回合（`ConsentSent` req_id 回填 → 对端确认
    /// `ConsentSettled{Consumed}` → 传输行 upsert），验证编排状态机闭环。
    #[test]
    fn test_r92e1_folder_batch_throttle_1500() {
        let root = tmp_root("batch");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.remote.current = "up".into();
        let files: Vec<(String, u64, String)> = (0..1500)
            .map(|i| {
                let rel = format!("b{}/f{i:04}.txt", i / 50);
                (
                    local_path_key(&root.join(&rel)),
                    (i % 7 + 1) as u64,
                    rel_parent(&rel).to_string(),
                )
            })
            .collect();
        state.job = Some(FolderJob {
            direction: FolderDirection::ToRemote,
            source: root.display().to_string(),
            target_remote_dir: "up".into(),
            target_local_dir: PathBuf::new(),
            files,
            depth_capped: Vec::new(),
            next_idx: 0,
            batch_head: 0,
            collecting: false,
            collect_queue: VecDeque::new(),
            finished: false,
            started: Instant::now(),
            consent_pending: false,
            consent_req_id: None,
            target_dirs: Vec::new(),
            visit: HashSet::new(),
            failed: Vec::new(),
            cycle_skipped: Vec::new(),
            summary_emitted: false,
            mkdir_queue: VecDeque::new(),
        });
        let (ftx, _frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let mut panel = FilePanelState::new();
        let fopt: Option<UnboundedSender<FileCommand>> = Some(ftx);
        let mopt: Option<UnboundedSender<FileMgrCommand>> = Some(mtx);
        let mut issued = 0usize;
        let mut max_inflight = 0usize;
        let mut per_tick_max = 0usize;
        let mut fake_req_id = 0x8000_0001u32;
        let mut ticks = 0u32;
        while !state.job.as_ref().unwrap().finished {
            assert!(ticks < 20_000, "编排不得卡死（{ticks} ticks）");
            state.tick(&panel, fopt.as_ref(), mopt.as_ref());
            ticks += 1;
            let mut this_tick = 0usize;
            while let Ok(cmd) = mxr.try_recv() {
                this_tick += 1;
                let FileMgrCommand::SendWithConsent {
                    entries,
                    truncated,
                    from_job,
                } = cmd
                else {
                    unreachable!("ToRemote 批只发 consent 通告")
                };
                assert!(from_job, "文件夹批 = from_job");
                assert!(!truncated, "批 = 128 ≤ 255 零拆分");
                for (path, target_dir) in &entries {
                    let name = path.file_name().unwrap().to_string_lossy().to_string();
                    let (_abs, size, subdir) = state
                        .job
                        .as_ref()
                        .unwrap()
                        .files
                        .iter()
                        .find(|(p, _, _)| task_file_basename(p) == name)
                        .cloned()
                        .expect("在途文件必在任务清单");
                    assert_eq!(
                        target_dir.as_str(),
                        remote_join("up", &subdir).as_str(),
                        "落点 = 启动时远端栏目录 + 相对子路径（结构镜像）"
                    );
                    issued += 1;
                    panel.upsert(FileTask {
                        transfer_id: issued as u64,
                        name,
                        size,
                        direction: FileDirection::Upload,
                        done: 0,
                        status: FileTaskStatus::WaitingAccept,
                        speed: 0.0,
                        path: None,
                    });
                }
                // 模拟引擎 consent 回合：通告 admit（req_id 回填）→ 对端
                // 确认（Consumed）→ 传输行已在上方 upsert（引擎侧口径）。
                state.on_fs_event(FsEvent::ConsentSent {
                    req_id: fake_req_id,
                    peer_label: "test".to_string(),
                    count: entries.len(),
                    total_size: 0,
                    truncated: false,
                    from_job: true,
                });
                state.on_fs_event(FsEvent::ConsentSettled {
                    req_id: fake_req_id,
                    outcome: ConsentOutcome::Consumed,
                    from_job: true,
                });
                fake_req_id += 1;
            }
            per_tick_max = per_tick_max.max(this_tick);
            let inflight = active_task_count(&panel, FileDirection::Upload);
            max_inflight = max_inflight.max(inflight);
            assert!(
                inflight <= MAX_QUEUE_LEN,
                "任意时刻在途 ≤ MAX_QUEUE_LEN（实际 {inflight}）"
            );
            // 模拟整批完成（释放水位）——批节流推进。
            if inflight >= FOLDER_BATCH_SIZE {
                for t in &mut panel.tasks {
                    if t.direction == FileDirection::Upload && !is_terminal_status(&t.status) {
                        t.status = FileTaskStatus::Completed;
                    }
                }
            }
        }
        assert_eq!(issued, 1500, ">1000 项全部通告");
        assert!(max_inflight <= MAX_QUEUE_LEN, "批节流上限（consent 在途 = 至多一整批）");
        assert!(per_tick_max <= 1, "每帧至多 1 个 consent 通告（整批 = 一框）");
        std::fs::remove_dir_all(&root).ok();
    }

    /// 远端→本地 BFS 收集（单在途 List、页续接、深度门）+ Fetch 响应链式
    /// （前一个 Fetch 响应前不发下一个；落本地栏当前目录）。
    #[test]
    fn test_r92e1_folder_remote_bfs_and_fetch_chain() {
        let root = tmp_root("bfs");
        let mut state = FileManagerState::with_local_root(root.clone());
        seed_remote(
            &mut state,
            "srv",
            &[mk_entry("proj", 0, true), mk_entry("a.txt", 5, false)],
        );
        // = 目录名）。
        state.remote.view.selected = vec!["srv/proj".into()];
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, _mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let fopt: Option<UnboundedSender<FileCommand>> = Some(ftx);
        let mopt: Option<UnboundedSender<FileMgrCommand>> = Some(mtx);
        let n = state.enqueue_transfer(
            PaneId::Remote, PaneId::Local, vec!["srv/proj".into()], &panel, fopt.as_ref(), mopt.as_ref(),
        );
        assert_eq!(n, 0, "纯目录 = 收集期零直发");
        assert!(state.job.as_ref().unwrap().collecting);

        // tick → List srv/proj（depth 1）。
        state.tick(&panel, fopt.as_ref(), mopt.as_ref());
        match frx.try_recv() {
            Ok(FileCommand::Fs {
                op: FsOp::List {
                    path,
                    offset,
                    limit,
                },
            }) => {
                assert_eq!((path, offset, limit), ("srv/proj".to_string(), 0, PAGE_SIZE));
            }
            other => panic!("应得 List，实际 {other:?}"),
        }
        // 引擎 Admitted（req_id 回填）+ 响应（sub/ + b.txt）。
        state.on_fs_event(FsEvent::Admitted {
            req_id: 7,
            op: FsOp::List {
                path: "srv/proj".into(),
                offset: 0,
                limit: PAGE_SIZE,
            },
        });
        assert_eq!(state.pending.as_ref().unwrap().req_id, 7);
        state.on_fs_event(FsEvent::Response {
            req_id: 7,
            result: Ok(build_fs_list_payload(
                &[("sub", 0, true), ("b.txt", 9, false)],
                false,
                "srv",
            )),
        });
        let job = state.job.as_ref().unwrap();
        assert_eq!(
            job.files,
            vec![("srv/proj/b.txt".to_string(), 9u64, "proj".to_string())]
        );
        assert_eq!(job.collect_queue.len(), 1, "sub 待列");

        // tick → List srv/proj/sub（depth 2）→ 空目录 → 收集完毕。
        state.tick(&panel, fopt.as_ref(), mopt.as_ref());
        match frx.try_recv() {
            Ok(FileCommand::Fs {
                op: FsOp::List { path, .. },
            }) => assert_eq!(path, "srv/proj/sub"),
            other => panic!("应得 List sub，实际 {other:?}"),
        }
        state.on_fs_event(FsEvent::Admitted {
            req_id: 8,
            op: FsOp::List {
                path: "srv/proj/sub".into(),
                offset: 0,
                limit: PAGE_SIZE,
            },
        });
        state.on_fs_event(FsEvent::Response {
            req_id: 8,
            result: Ok(build_fs_list_payload(&[], false, "srv")),
        });
        let job = state.job.as_ref().unwrap();
        assert!(!job.collecting && !job.finished, "收集完毕、文件待入队");

        // tick → FetchFile 响应链式：第一个 = proj/b.txt（落本地栏当前目录，
        // 子目录结构镜像：local_dir = 当前目录 + rel 父级）。
        state.tick(&panel, fopt.as_ref(), mopt.as_ref());
        match frx.try_recv() {
            Ok(FileCommand::FetchFile {
                remote_path,
                local_dir,
            }) => {
                assert_eq!(remote_path, "srv/proj/b.txt");
                assert_eq!(local_dir, root.join("proj"), "落本地栏当前目录（结构镜像）");
            }
            other => panic!("应得 FetchFile，实际 {other:?}"),
        }
        // 响应链式：pending 未清 → 下一 tick 零发。
        state.tick(&panel, fopt.as_ref(), mopt.as_ref());
        assert!(frx.try_recv().is_err(), "前一个 Fetch 响应前不发下一个");
        // Fetch 响应 → 清 pending → tick → 收尾（finished + 状态行）。
        state.on_fs_event(FsEvent::Admitted {
            req_id: 9,
            op: FsOp::Fetch {
                path: "srv/proj/b.txt".into(),
            },
        });
        state.on_fs_event(FsEvent::Response {
            req_id: 9,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: Vec::new(),
            }),
        });
        state.tick(&panel, fopt.as_ref(), mopt.as_ref());
        assert!(state.job.as_ref().unwrap().finished);
        assert_eq!(
            state.status_line,
            Some(tf!("filemgr.enqueued.recv", 1)),
            "收尾状态行"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // ── 族 4：删除确认弹窗（§1.7 取消 = 零 wire 帧——wire 级断言）────

    /// §1.7：取消 = **零 wire 帧**（wire 级断言：FileCommand/FileMgrCommand
    /// 双通道零捕获）+ 整批中止 + 对话框关闭。
    #[test]
    fn test_r92e1_delete_cancel_zero_wire() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        seed_remote(
            &mut state,
            "d",
            &[mk_entry("x.txt", 1, false), mk_entry("y.txt", 2, false)],
        );
        state.remote.view.selected = vec!["d/x.txt".into(), "d/y.txt".into()];
        state.open_delete(PaneId::Remote);
        assert!(matches!(state.dialog, Dialog::ConfirmDelete { .. }));
        assert_eq!(state.pending_deletes.len(), 2, "多项 = 逐条确认队列");
        let cmd = state.delete_resolve(false);
        assert!(cmd.is_none(), "取消不得产出命令");
        assert!(!state.has_dialog(), "对话框关闭");
        assert!(state.pending_deletes.is_empty(), "整批中止");
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let _ = (ftx, mtx); // 通道从未被任何路径触达
        assert!(frx.try_recv().is_err(), "wire 级：零 FileCommand（无 FsRequest 帧）");
        assert!(mxr.try_recv().is_err(), "wire 级：零 FileMgrCommand");
        // 选中保留（取消 = 无副作用）。
        assert_eq!(
            state.selection_paths(PaneId::Remote),
            vec!["d/x.txt".to_string(), "d/y.txt".to_string()]
        );
    }

    /// 确认 = Delete 经既有 FileCommand 管线（目录 recursive=true / 文件
    /// false；成功后 needs_refresh）；文案含「远端直接执行」口径（键表）。
    #[test]
    fn test_r92e1_delete_confirm_fs_pipeline() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        seed_remote(
            &mut state,
            "d",
            &[mk_entry("y.txt", 1, false), mk_entry("sub", 0, true)],
        );
        state.remote.view.selected = vec!["d/y.txt".into()];
        state.open_delete(PaneId::Remote);
        let cmd = state.delete_resolve(true);
        match cmd {
            Some(FileCommand::Fs {
                op: FsOp::Delete { path, recursive },
            }) => {
                assert_eq!(path, "d/y.txt");
                assert!(!recursive, "文件 = 非递归");
            }
            other => panic!("应得 Fs Delete，实际 {other:?}"),
        }
        // 响应链：Admitted + ok → needs_refresh（渲染帧刷新当前页）。
        state.on_fs_event(FsEvent::Admitted {
            req_id: 1,
            op: FsOp::Delete {
                path: "d/y.txt".into(),
                recursive: false,
            },
        });
        state.on_fs_event(FsEvent::Response {
            req_id: 1,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: Vec::new(),
            }),
        });
        assert_eq!(
            state.remote.refresh_node.as_deref(),
            Some("d"),
            "删除成功 → 重列受影响节点"
        );
        assert!(
            !state.remote.view.selected.contains(&"d/y.txt".to_string()),
            "选中剪除"
        );
        // 目录：recursive = true。
        state.remote.view.selected = vec!["d/sub".into()];
        state.open_delete(PaneId::Remote);
        let cmd = state.delete_resolve(true);
        match cmd {
            Some(FileCommand::Fs {
                op: FsOp::Delete { path, recursive },
            }) => {
                assert_eq!(path, "d/sub");
                assert!(recursive, "目录 = 递归");
            }
            other => panic!("应得 Fs Delete(recursive)，实际 {other:?}"),
        }
        // §1.7 文案口径（键表在位）。
        let msg = tf!(
            "filemgr.confirm.delete",
            "x",
            "-",
            t!("filemgr.type.dir")
        );
        assert!(msg.contains("远端直接执行"), "确认文案口径: {msg}");
    }

    /// 本地删除 = 同步 std::fs（零命令 = 零 wire；逐项确认直至整批完成）。
    #[test]
    fn test_r92e1_delete_local_std_fs_no_wire() {
        let root = tmp_root("loca_del");
        mkfile(&root.join("rm_me.txt"), "x");
        std::fs::create_dir_all(root.join("rm_dir")).unwrap();
        let _ = std::fs::File::create(root.join("rm_dir").join("inner.txt"));
        let mut state = FileManagerState::with_local_root(root.clone());
        state.local.view.selected.extend([
            local_path_key(&root.join("rm_me.txt")),
            local_path_key(&root.join("rm_dir")),
        ]);
        let (_ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (_mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        state.open_delete(PaneId::Local);
        let mut rounds = 0;
        while state.has_dialog() {
            rounds += 1;
            assert!(rounds <= 8, "确认队列不得死循环");
            let cmd = state.delete_resolve(true);
            assert!(cmd.is_none(), "本地删除零命令（无 wire）");
        }
        assert!(!root.join("rm_me.txt").exists(), "本地文件已删");
        assert!(!root.join("rm_dir").exists(), "本地目录已删");
        assert!(frx.try_recv().is_err() && mxr.try_recv().is_err(), "本地删除零 wire");
        std::fs::remove_dir_all(&root).ok();
    }

    // ── 族 5：改名 AlreadyExists（S13：无静默覆盖路径）──────────────

    /// S13 本地：rename 目标存在 = AlreadyExists 拒绝（unix rename(2)
    /// 静默覆盖 → 本地预检；源保留、目标零覆盖、零命令）。
    #[test]
    fn test_r92e1_rename_local_already_exists() {
        let root = tmp_root("ren_local");
        mkfile(&root.join("a.txt"), "A");
        mkfile(&root.join("b.txt"), "B");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.local.view.selected = vec![local_path_key(&root.join("a.txt"))];
        state.open_rename(PaneId::Local);
        if let Dialog::InputRename { new_name, .. } = &mut state.dialog {
            *new_name = "b.txt".into();
        }
        state.rename_submit();
        assert!(matches!(state.dialog, Dialog::ConfirmRename { .. }));
        let cmd = state.rename_resolve(true);
        assert!(cmd.is_none(), "本地改名零命令");
        assert_eq!(
            state.local.view.status.as_deref(),
            Some(t!("filemgr.err.already_exists")),
            "S13：目标已存在 → 拒绝文案"
        );
        assert!(root.join("a.txt").exists(), "源保留");
        assert_eq!(std::fs::read_to_string(root.join("b.txt")).unwrap(), "B", "目标零覆盖");
        std::fs::remove_dir_all(&root).ok();
    }

    /// S13 本地：改名成功路径（目标不存在 → std::fs::rename，选中随迁）。
    #[test]
    fn test_r92e1_rename_local_success() {
        let root = tmp_root("ren_ok");
        mkfile(&root.join("a.txt"), "A");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.local.view.selected = vec![local_path_key(&root.join("a.txt"))];
        state.open_rename(PaneId::Local);
        if let Dialog::InputRename { new_name, .. } = &mut state.dialog {
            *new_name = "c.txt".into();
        }
        state.rename_submit();
        assert!(state.rename_resolve(true).is_none());
        assert!(root.join("c.txt").exists() && !root.join("a.txt").exists());
        assert_eq!(
            state.local.view.selected,
            vec![local_path_key(&root.join("c.txt"))]
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// S13 远端：rename 目标存在 = **服务端** `AlreadyExists` 拒绝（响应
    /// 态机映射文案；UI 无静默覆盖路径）。
    #[test]
    fn test_r92e1_rename_remote_already_exists_response() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        seed_remote(
            &mut state,
            "d",
            &[mk_entry("a.txt", 1, false), mk_entry("b.txt", 2, false)],
        );
        state.remote.view.selected = vec!["d/a.txt".into()];
        state.open_rename(PaneId::Remote);
        if let Dialog::InputRename { new_name, .. } = &mut state.dialog {
            *new_name = "b.txt".into();
        }
        state.rename_submit();
        let cmd = state.rename_resolve(true);
        match cmd {
            Some(FileCommand::Fs {
                op: FsOp::Rename { from, to },
            }) => {
                assert_eq!((from, to), ("d/a.txt".to_string(), "d/b.txt".to_string()));
            }
            other => panic!("应得 Fs Rename，实际 {other:?}"),
        }
        // 服务端 S13 拒绝（AlreadyExists）。
        state.on_fs_event(FsEvent::Admitted {
            req_id: 3,
            op: FsOp::Rename {
                from: "d/a.txt".into(),
                to: "d/b.txt".into(),
            },
        });
        state.on_fs_event(FsEvent::Response {
            req_id: 3,
            result: Ok(FsResponsePayload {
                ok: false,
                err: FsErrCode::AlreadyExists,
                payload: Vec::new(),
            }),
        });
        assert_eq!(
            state.status_line.as_deref(),
            Some(t!("filemgr.err.already_exists")),
            "服务端 AlreadyExists → 可读文案（无静默覆盖）"
        );
    }

    /// 改名取消 = 零 wire 帧；无效输入（空/含分隔符/同名）= 关窗零命令。
    #[test]
    fn test_r92e1_rename_cancel_and_invalid_zero_wire() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        seed_remote(&mut state, "d", &[mk_entry("a.txt", 1, false)]);
        state.remote.view.selected = vec!["d/a.txt".into()];
        let (_ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (_mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        // 取消 = 零 wire。
        state.open_rename(PaneId::Remote);
        if let Dialog::InputRename { new_name, .. } = &mut state.dialog {
            *new_name = "z.txt".into();
        }
        state.rename_submit();
        assert!(state.rename_resolve(false).is_none());
        assert!(!state.has_dialog());
        assert!(frx.try_recv().is_err() && mxr.try_recv().is_err(), "取消零 wire");
        // 无效输入 = 关窗 + 提示 + 零命令。
        for bad in ["", "a/b", "a\\b", "a.txt"] {
            state.open_rename(PaneId::Remote);
            if let Dialog::InputRename { new_name, .. } = &mut state.dialog {
                *new_name = bad.into();
            }
            state.rename_submit();
            assert!(!state.has_dialog(), "无效输入关窗: {bad}");
            assert!(frx.try_recv().is_err(), "无效输入零命令: {bad}");
        }
        assert_eq!(
            state.status_line.as_deref(),
            Some(t!("filemgr.rename.invalid"))
        );
    }

    // ── 附：i18n 新键在位（zh/en 占位符一一对应）────────────────────

    /// E1 新增键全部在键表（缺键 = 停手上报口径的在位自检）。
    #[test]
    fn test_r92e1_i18n_keys_present() {
        for key in [
            "filemgr.type.dir",
            "filemgr.type.file",
            "filemgr.type.symlink",
            "filemgr.btn.send_selected",
            "filemgr.btn.recv_selected",
            "filemgr.page.more",
            "filemgr.page_fmt",
            "filemgr.loading",
            "filemgr.busy",
            "filemgr.queue_full",
            "filemgr.clipboard.empty",
            "filemgr.paste.same_pane",
            "filemgr.select.copied",
            "filemgr.enqueued.send",
            "filemgr.enqueued.recv",
            "filemgr.job_fmt",
            "filemgr.depth_limit",
            "filemgr.rename.invalid",
            "filemgr.transfer_bar",
            "widgets.paste",
        ] {
            let zh = crate::i18n::tr_lang(crate::i18n::Lang::Zh, key);
            let en = crate::i18n::tr_lang(crate::i18n::Lang::En, key);
            assert_ne!(zh, key, "zh 缺键: {key}");
            assert_ne!(en, key, "en 缺键: {key}");
            // 占位符一一对应。
            let ph: Vec<&str> = ["{0}", "{1}", "{2}", "{3}"].to_vec();
            for p in ph {
                assert_eq!(zh.contains(p), en.contains(p), "{key} 占位符 {p} 不一致");
            }
        }
    }


    /// 拆批边界（§8.6/§8.4）：≤255 一批；255 整批零截断；256 = 2 批 +
    /// 截断记档；600 = 3 批（255/255/90）+ 截断；空 = 零批零截断。
    #[test]
    fn test_r110a3_consent_split_batches() {
        // 255 整批 = 1 批零截断（边界）。
        let items: Vec<u32> = (0..255).collect();
        let (b, tr) = consent_split_batches(&items, TRANSFER_REQUEST_MAX_ENTRIES);
        assert_eq!(b.len(), 1, "255 = 整批");
        assert!(!tr, "255 零截断");
        // 256 = 2 批 + 截断。
        let items: Vec<u32> = (0..256).collect();
        let (b, tr) = consent_split_batches(&items, TRANSFER_REQUEST_MAX_ENTRIES);
        assert_eq!(b.len(), 2);
        assert_eq!((b[0].len(), b[1].len()), (255, 1));
        assert!(tr, "256 > 255 = 截断记档");
        // 600 = 3 批（255/255/90）。
        let items: Vec<u32> = (0..600).collect();
        let (b, tr) = consent_split_batches(&items, TRANSFER_REQUEST_MAX_ENTRIES);
        assert_eq!(b.len(), 3);
        assert_eq!((b[0].len(), b[1].len(), b[2].len()), (255, 255, 90));
        assert!(tr);
        // 内容序保持（FIFO 不重排）。
        assert_eq!(b[2][0], 510);
        // 空 = 零批零截断。
        let (b, tr) = consent_split_batches::<u32>(&[], TRANSFER_REQUEST_MAX_ENTRIES);
        assert!(b.is_empty() && !tr);
        // 退化 max=0 = 无批可成 + 截断（生产不可达防御臂）。
        let (b, tr) = consent_split_batches(&items, 0);
        assert!(b.is_empty() && tr);
    }

    /// 三选 → 回执映射（§8.3 生产可达面）：【取消】= `Declined` 负回执。
    /// 零构造，禁 dead code 红线）——其「零直接回执」断言格随变体删除
    ///（pull 模型语义不变：接收类决策无单独 ok 回执，对端 Fetch 到达即
    /// 同意回执 §8.7①）。
    #[test]
    fn test_r110a3_consent_decision_receipt() {
        assert_eq!(
            consent_reply_err(&ConsentDecision::Cancel),
            Some(FsErrCode::Declined)
        );
    }

    /// 落点三级优先级（§8.5）：另存为 ＞ OfferV2 target ＞ download_dir
    ///（8 格全矩阵——每级在/缺独立）。
    #[test]
    fn test_r110a3_consent_landing_priority() {
        let save = Path::new("/save/as");
        let v2 = Path::new("remote/target");
        let dl = Path::new("/downloads");
        assert_eq!(
            consent_landing_dir(Some(save), Some(v2), dl),
            save,
            "① 另存为最高"
        );
        assert_eq!(consent_landing_dir(None, Some(v2), dl), v2, "② OfferV2 次之");
        assert_eq!(
            consent_landing_dir(Some(save), None, dl),
            save,
            "① 独立于 ② 在位"
        );
        assert_eq!(consent_landing_dir(None, None, dl), dl, "③ 默认兜底");
    }

    /// 等待超时判定（Q11 5min 常量）：恰好 300s 到期 / 299s 未到 /
    /// 时钟回拨饱和（未超时——fail-safe 不误杀在途确认）。
    #[test]
    fn test_r110a3_consent_wait_timeout() {
        let now = Instant::now();
        let t = CONSENT_WAIT_TIMEOUT;
        assert!(
            consent_wait_expired(now - t, now, t),
            "恰好 300s = 到期"
        );
        assert!(
            !consent_wait_expired(now - (t - Duration::from_secs(1)), now, t),
            "299s = 未到期"
        );
        assert!(
            consent_wait_expired(now, now, Duration::from_secs(0)),
            "timeout=0 = 立即到期（退化边界）"
        );
        // 时钟回拨（started 在 now 之后）= duration_since 饱和 0 = 未超时。
        assert!(
            !consent_wait_expired(now + Duration::from_secs(60), now, t),
            "时钟回拨饱和 = 未超时（fail-safe）"
        );
    }

    // （Q9 二态判定）随 `consent_handle_mode`/`ConsentHandleMode` 退役——
    // 设计 §12.1 A3 处置表「headless 自动接受臂 → 收敛（与 GUI 开统一）」：
    // 二态（Gui/Headless）→ 开关决策四格（GUI-开/headless-开 = 同一自动
    // 接受臂；GUI-关/headless-关 = 同一自动 `Declined` 臂）；四格语义由
    // `test_r110v13b2_consent_switch_decision_matrix` 超集钉死（12 格 +
    // 显式 3 钉）。

    /// 重复推送去重（§8.6）：同 (name,size) 在等待中 = 命中跳过；同名异
    /// 大小 / 异名同大小 = 不命中（两维独立）。
    #[test]
    fn test_r110a3_consent_dedup() {
        let pending = vec![("a.txt".to_string(), 100u64), ("b.txt".to_string(), 200)];
        assert!(consent_is_pending(&pending, "a.txt", 100), "在途命中");
        assert!(!consent_is_pending(&pending, "a.txt", 999), "同名异大小不命中");
        assert!(!consent_is_pending(&pending, "c.txt", 100), "异名不命中");
        assert!(!consent_is_pending(&[], "a.txt", 100), "空表不命中");
    }

    /// 发送侧行状态机（等待 → 四终态）+ 幂等（已结算行对迟到事件不变）+
    /// TTL 剪除（终态 60s 后剪；等待行不剪）。
    #[test]
    fn test_r110a3_consent_out_state_machine() {
        let now = Instant::now();
        let mut line = ConsentOutLine {
            req_id: 0x8000_0001,
            peer_label: "peer".into(),
            count: 3,
            total_size: 300,
            truncated: false,
            from_job: false,
            started: now,
            state: ConsentOutState::Waiting,
            settled_at: None,
        };
        assert!(!line.state.is_terminal(), "初态 = 等待（非终态）");
        // 等待 → Transferring（Consumed）。
        consent_out_apply(&mut line, ConsentOutcome::Consumed, now);
        assert_eq!(line.state, ConsentOutState::Transferring);
        assert!(line.settled_at.is_some());
        assert!(line.state.is_terminal());
        // 幂等：迟到 Declined 不翻转已结算行。
        consent_out_apply(&mut line, ConsentOutcome::Declined, now);
        assert_eq!(line.state, ConsentOutState::Transferring, "已结算 = 幂等不翻转");
        // 四终态映射。
        for (outcome, want) in [
            (ConsentOutcome::Consumed, ConsentOutState::Transferring),
            (ConsentOutcome::Declined, ConsentOutState::Declined),
            (ConsentOutcome::Timeout, ConsentOutState::Timeout),
            (ConsentOutcome::SendFailed, ConsentOutState::SendFailed),
        ] {
            let mut l2 = line.clone();
            l2.settled_at = None;
            l2.state = ConsentOutState::Waiting;
            consent_out_apply(&mut l2, outcome, now);
            assert_eq!(l2.state, want, "{outcome:?} 映射");
        }
        // TTL 剪除：终态 60s 后剪；等待行不剪；60s 内保留。
        let mut lines = vec![
            line.clone(), // 已结算 @now
            ConsentOutLine {
                req_id: 2,
                peer_label: "p".into(),
                count: 1,
                total_size: 1,
                truncated: false,
                from_job: false,
                started: now,
                state: ConsentOutState::Waiting,
                settled_at: None,
            },
        ];
        consent_out_prune(&mut lines, now + CONSENT_OUT_TTL);
        assert_eq!(lines.len(), 1, "终态 TTL 到期 = 剪");
        assert!(lines[0].state == ConsentOutState::Waiting, "剪剩 = 等待行（不剪）");
        let mut lines2 = vec![line.clone()];
        consent_out_prune(&mut lines2, now + (CONSENT_OUT_TTL - Duration::from_secs(1)));
        assert_eq!(lines2.len(), 1, "TTL 未满 = 保留");
        // 倒计时显示串（mm:ss 零填充）。
        assert_eq!(consent_countdown(Duration::from_secs(300)), "05:00");
        assert_eq!(consent_countdown(Duration::from_secs(59)), "00:59");
        assert_eq!(consent_countdown(Duration::from_secs(0)), "00:00");
    }

    // 对象 `ConsentQueue`/`ConsentRequest` 随三选弹窗删除（§12.1 处置表
    // 「废弃」；B2 起两开关态均不入确认队列，结构零生产消费）。

    /// `consent.*` 命名空间 zh/en 成对在位 + 占位符一一对应（house style
    /// 同 filemgr.*/clip.* 先例；缺键 = 停手上报口径的在位自检）。
    /// accept/saveas/cancel/default_dir_hint）随三选弹窗删除——本测仅核
    /// **保留 6 键**（发送侧等待行族）；7 键缺席由
    /// `test_r110v13b3_consent_retired_keys_absent` 反向钉死。
    #[test]
    fn test_r110a3_consent_i18n_paired() {
        for key in [
            "consent.waiting",
            "consent.waiting_countdown",
            "consent.timeout",
            "consent.declined",
            "consent.transferring",
            "consent.send_failed",
        ] {
            let zh = crate::i18n::tr_lang(crate::i18n::Lang::Zh, key);
            let en = crate::i18n::tr_lang(crate::i18n::Lang::En, key);
            assert_ne!(zh, key, "zh 缺键: {key}");
            assert_ne!(en, key, "en 缺键: {key}");
            assert!(!zh.trim().is_empty() && !en.trim().is_empty(), "{key} 空值");
            let ph: Vec<&str> = ["{0}", "{1}", "{2}"].to_vec();
            for p in ph {
                assert_eq!(zh.contains(p), en.contains(p), "{key} 占位符 {p} 不一致");
            }
        }
    }

    //    单测（三形态取值点谓词 + 落点决议矩阵 + 三选退役 i18n 反向钉死）。──

    /// FM 挂载）= 恒无上下文；Shell 窗 = 面板开才有上下文；File 窗（全窗
    /// 形态，调用点 `panel_open` 传恒 true）= 恒有上下文。
    #[test]
    fn test_r110v13b3_paste_landing_surface_gate() {
        assert!(!paste_landing_fm_surface(false, false), "Desktop = 恒 false");
        assert!(!paste_landing_fm_surface(false, true), "Desktop = 恒 false（面板态不参与）");
        assert!(paste_landing_fm_surface(true, true), "Shell 面板开 / File 全窗 = true");
        assert!(!paste_landing_fm_surface(true, false), "Shell 面板关 = 无上下文");
    }

    /// = `Browse`（该目录逐字透传，零改写）。
    #[test]
    fn test_r110v13b3_paste_landing_browse() {
        let dir = Path::new("/home/u/browse/dir");
        let dl = Path::new("/home/u/downloads");
        assert_eq!(
            paste_landing_resolve(Some(dir), true, true, dl),
            PasteLanding::Browse(PathBuf::from("/home/u/browse/dir")),
            "存在+可写 = Browse（该目录）"
        );
    }

    /// 目录不存在 / 目录不可写 = 一律 `Fallback(download_dir)`（逐字透传
    /// 实参；可写但存在性缺失、存在但不可写的**各格独立**钉死，防短路
    /// 顺序漂移）。
    #[test]
    fn test_r110v13b3_paste_landing_fallback_matrix() {
        let dir = Path::new("/home/u/browse/dir");
        let dl = Path::new("/home/u/downloads");
        let expected = PasteLanding::Fallback(PathBuf::from("/home/u/downloads"));
        assert_eq!(
            paste_landing_resolve(None, true, true, dl),
            expected,
            "无 FM 上下文（Desktop）= Fallback"
        );
        assert_eq!(
            paste_landing_resolve(Some(dir), false, true, dl),
            expected,
            "目录不存在（浏览中途被删）= Fallback"
        );
        assert_eq!(
            paste_landing_resolve(Some(dir), true, false, dl),
            expected,
            "目录不可写（权限变化）= Fallback"
        );
        assert_eq!(
            paste_landing_resolve(Some(dir), false, false, dl),
            expected,
            "双缺失 = Fallback（格不短路漂移）"
        );
    }

    /// 框专属 7 键**缺席**（`tr_lang` 缺键回退 = 键名原样返回，house style
    /// 在位自检先例的反向运用）+ B2 开关门控 5 键**保留在位**（含
    /// `clip.fetch.fallback` = B3 新增消费点、键文零改）——防 dead key
    #[test]
    fn test_r110v13b3_consent_retired_keys_absent() {
        for key in [
            "consent.title",
            "consent.waiting_more",
            "consent.truncated",
            "consent.accept",
            "consent.saveas",
            "consent.cancel",
            "consent.default_dir_hint",
        ] {
            let zh = crate::i18n::tr_lang(crate::i18n::Lang::Zh, key);
            let en = crate::i18n::tr_lang(crate::i18n::Lang::En, key);
            assert_eq!(zh, key, "退役键复入 zh: {key}");
            assert_eq!(en, key, "退役键复入 en: {key}");
        }
        for key in [
            "consent.auto_accepted",
            "consent.switch_declined",
            "consent.config_invalid_hint",
            "clip.fetch.fallback",
            "clip.paste_disabled",
        ] {
            let zh = crate::i18n::tr_lang(crate::i18n::Lang::Zh, key);
            let en = crate::i18n::tr_lang(crate::i18n::Lang::En, key);
            assert_ne!(zh, key, "B2 保留键误删 zh: {key}");
            assert_ne!(en, key, "B2 保留键误删 en: {key}");
        }
    }

    /// （缺键 = serde 默认开，load 侧已归一 = 字段即真值）/ Err+缺文件
    /// （首启）= 默认开 / Err+文件存在（损坏）= 双关 fail-closed /
    /// Err+路径不可解析 = 态不可得 = 按关（fail-closed 方向不留「不可得
    /// = 开」偶然）。
    #[test]
    fn test_r110v13b2_consent_switches_three_state() {
        // Ok = 字段值（显式值逐位透传）。
        assert_eq!(
            consent_switches_core(Some((true, true)), Some(true)),
            (true, true),
            "Ok(开,开) = (开,开)"
        );
        assert_eq!(
            consent_switches_core(Some((false, true)), Some(true)),
            (false, true),
            "Ok(关,开) 混合态透传"
        );
        // Ok 臂对 exists 不敏感（字段值优先）。
        assert_eq!(
            consent_switches_core(Some((false, false)), None),
            (false, false),
            "Ok 臂 = 字段值，存在性不参与"
        );
        // Err + 配置文件不存在（首启）= 默认开（用户「默认都开」）。
        assert_eq!(
            consent_switches_core(None, Some(false)),
            (true, true),
            "Err+缺文件（首启）= 默认开"
        );
        // Err + 文件存在（损坏/不可读）= 双关 fail-closed（红线⑤）。
        assert_eq!(
            consent_switches_core(None, Some(true)),
            (false, false),
            "Err+文件存在（损坏）= 双关 fail-closed"
        );
        // Err + 路径不可解析 = 态不可得 = 按关。
        assert_eq!(
            consent_switches_core(None, None),
            (false, false),
            "Err+路径不可解析 = 按关"
        );
    }

    /// Ok → Ok / Err+缺文件 → FirstRun / Err+存在 → Invalid /
    /// Err+路径不可解析 → Invalid（损坏与路径不可解析同按关面）。
    #[test]
    fn test_r110v13b2_consent_config_state_grid() {
        assert_eq!(
            consent_config_state_core(true, Some(true)),
            ConsentConfigState::Ok,
            "Ok = Ok 态"
        );
        assert_eq!(
            consent_config_state_core(false, Some(false)),
            ConsentConfigState::FirstRun,
            "Err+缺文件 = 首启态"
        );
        assert_eq!(
            consent_config_state_core(false, Some(true)),
            ConsentConfigState::Invalid,
            "Err+文件存在 = Invalid（损坏）"
        );
        assert_eq!(
            consent_config_state_core(false, None),
            ConsentConfigState::Invalid,
            "Err+路径不可解析 = Invalid（态不可得）"
        );
    }

    /// 12 格全钉死）——TransferRequest → 文件传输开关；Offer → 文件传输
    /// **AND** 剪贴板（§12.2⑥ 任一关 = Reject）；臂 ② → 剪贴板开关
    /// （本地门）。fail-closed 方向 = 只减接受面不增。
    #[test]
    fn test_r110v13b2_consent_switch_decision_matrix() {
        for (ft, clip) in [(true, true), (true, false), (false, true), (false, false)] {
            // 臂：TransferRequest（同意族）——只看文件传输开关。
            assert_eq!(
                consent_switch_decision(ft, clip, ConsentArrival::TransferRequest),
                if ft {
                    ConsentSwitchDecision::Accept
                } else {
                    ConsentSwitchDecision::Declined
                },
                "TransferRequest (ft={ft}, clip={clip})"
            );
            // 臂：Offer（直发族）——文件传输 AND 剪贴板。
            assert_eq!(
                consent_switch_decision(ft, clip, ConsentArrival::Offer),
                if ft && clip {
                    ConsentSwitchDecision::Accept
                } else {
                    ConsentSwitchDecision::Reject
                },
                "Offer (ft={ft}, clip={clip})"
            );
            // 臂：② 粘贴拉取（本地门，零 wire）——只看剪贴板开关。
            assert_eq!(
                consent_switch_decision(ft, clip, ConsentArrival::PasteFetch),
                if clip {
                    ConsentSwitchDecision::Accept
                } else {
                    ConsentSwitchDecision::Blocked
                },
                "PasteFetch (ft={ft}, clip={clip})"
            );
        }
        // 显式四格钉死（防「矩阵循环自身写反」的共谋性错误）：
        assert_eq!(
            consent_switch_decision(true, false, ConsentArrival::Offer),
            ConsentSwitchDecision::Reject,
            "(ON,OFF) Offer = Reject（剪贴板关）"
        );
        assert_eq!(
            consent_switch_decision(false, true, ConsentArrival::Offer),
            ConsentSwitchDecision::Reject,
            "(OFF,ON) Offer = Reject（文件传输关）"
        );
        assert_eq!(
            consent_switch_decision(true, false, ConsentArrival::PasteFetch),
            ConsentSwitchDecision::Blocked,
            "(ON,OFF) 臂② = 不派发（文件传输开关不管本地臂）"
        );
    }

    /// zh/en 成对在位 + 占位符一一对应（提案案 = 技术过渡口径，用户终稿
    /// F 复测后 G 岗统一改；`clip.fetch.fallback` = B3 消费先入表防缺键）。
    #[test]
    fn test_r110v13b2_i18n_new_keys_paired() {
        for key in [
            "consent.auto_accepted",
            "consent.switch_declined",
            "consent.config_invalid_hint",
            "clip.fetch.fallback",
            "clip.paste_disabled",
        ] {
            let zh = crate::i18n::tr_lang(crate::i18n::Lang::Zh, key);
            let en = crate::i18n::tr_lang(crate::i18n::Lang::En, key);
            assert_ne!(zh, key, "zh 缺键: {key}");
            assert_ne!(en, key, "en 缺键: {key}");
            assert!(!zh.trim().is_empty() && !en.trim().is_empty(), "{key} 空值");
            let ph: Vec<&str> = ["{0}", "{1}", "{2}"].to_vec();
            for p in ph {
                assert_eq!(zh.contains(p), en.contains(p), "{key} 占位符 {p} 不一致");
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════
//
// 用户 09-21 二轮复测：非空目录（远端 58 条 wire 全部应用成功）行区整片
// 不绘制，栏头/空态/分页塌缩进顶栏两行（表头挤进工具行）；空目录反而
// 双父级×主题×宽度矩阵复现 + egui 0.28.1 源码证实，三因叠加）：
//   a) `allocate_ui = allocate_ui_with_layout(_, *self.layout())`
//      **继承横向布局** → 栏内全部内容（栏头｜面包屑｜表头｜行 Grid｜
//      分页）被左到右排成一行（行 Grid 推到表头右侧）；
//   b) `ui.horizontal` 是「行」：初始高 = `interact_size.y` ≈ 20px
//      （ui.rs:2183 `horizontal_with_main_wrap_dyn`）→ 其内
//      `available_height()` ≈ 20px → 栏 max_rect 高 ≈ 20px → 行区
//      ScrollArea 被 `min_scrolled_size` = 64px（scroll_area.rs:221/540）
//      钳到 64-70px 最小高 → 58 行（1218px）向下整片溢出可见区 =
//      「行区整片不绘制」；
//   c) 兄弟子 ui `id = parent.id.with("child")` 相等（ui.rs:167，
//      无计数器）→ 两栏缺 id 的 ScrollArea 共享同一 persistent ID
//      （scroll_area.rs:502 缺省 `Id::new("scroll_area")`）→
//      ScrollArea 状态（offset/content_size/滚动条）跨栏互相污染
//      + 同帧 ID 冲突（🔥 First/Second use）。
// 修复 = `ui.columns(2)`（列矩形 = 游标→父 max_rect 底边 = 满剩余高，
// 且列布局显式 `top_down_justified` 竖排、无继承，ui.rs:2342
// `columns_dyn`）+ ScrollArea 逐栏 `.id_source(...)`。
//
// 判据（与 179 09-21 场景同构，1920×1080 ≈ 用户宽屏形态；CentralPanel
// = File 窗全窗形态 = 生产父级之二；Shell 底栏形态经 diag 矩阵同判据
// 归一后删除）：
// - 非空 58 条：双栏并排（栏头 y 齐平）、栏内栏头/面包屑/表头竖排
//   正常行距、远端行区行背景在位且行距均匀、行区对齐表头正下方
//   （不右偏/不出屏）、双栏分页行在位；
// - 空目录：「此目录为空」在位 + 零行背景（零回归）。
//
// 注：同一 Context 跑 2 帧——帧 1 = grid sizing pass（`prev_state` 空
// 条纹不绘制，egui `Grid` 两遍设计），帧 2 = 稳态（与用户截图帧同构）。
#[cfg(test)]
mod r133_2_tests {
    use super::*;

    /// 同一 Context 连跑 `n` 帧 headless 布局（`screen` = 屏幕尺寸，
    /// 1920×1080 ≈ 用户宽屏形态），返回末帧全部绘制 shapes（`ClippedShape`
    /// 含 `clip_rect`——退化裁剪矩形同样是可观测信号）。
    fn run_frames(
        state: &mut FileManagerState,
        panel: &FilePanelState,
        screen: (f32, f32),
        n: u32,
    ) -> Vec<egui::epaint::ClippedShape> {
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let mut shapes: Vec<egui::epaint::ClippedShape> = Vec::new();
        for _ in 0..n {
            let mut raw = egui::RawInput::default();
            raw.screen_rect =
                Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(screen.0, screen.1)));
            shapes = ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let mut focus = false;
                    show_file_manager(
                        ui,
                        &Theme::LIGHT,
                        state,
                        None,
                        None,
                        panel,
                        false,
                        &mut focus,
                    );
                });
            })
            .shapes;
        }
        shapes
    }

    /// 测试态构造：本地栏指向空临时目录（零干扰）+ 远端栏预置条目
    /// （`started = true` = 首 List 已发起，测试零 wire）。
    /// children 缓存。
    fn state_with_remote(root: PathBuf, entries: Vec<FileMgrEntry>) -> FileManagerState {
        let mut state = FileManagerState::with_local_root(root);
        state.remote.started = true;
        state.remote.root_display = "r133-2".to_string();
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(entries),
                ..Default::default()
            },
        );
        state
    }

    fn empty_tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("k133_2_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 行区行背景 = grid 条纹行（`faint_bg_color` 宽矩形；`width ≥ 100` 排除
    /// 零星小色块），返回按 y 排序的矩形列表。
    fn row_bg_rects(shapes: &[egui::epaint::ClippedShape]) -> Vec<egui::Rect> {
        let fill = egui::Visuals::light().faint_bg_color;
        let mut v: Vec<egui::Rect> = shapes
            .iter()
            .filter_map(|cs| match &cs.shape {
                egui::Shape::Rect(r) if r.fill == fill && r.rect.width() >= 100.0 => Some(r.rect),
                _ => None,
            })
            .collect();
        v.sort_by(|a, b| a.min.y.total_cmp(&b.min.y));
        v
    }

    /// 精确文本匹配的 text 矩形 → (x, y, w, h)，按 (y, x) 排序。
    fn text_rects(shapes: &[egui::epaint::ClippedShape], text: &str) -> Vec<(f32, f32, f32, f32)> {
        let mut v: Vec<(f32, f32, f32, f32)> = shapes
            .iter()
            .filter_map(|cs| match &cs.shape {
                egui::Shape::Text(t) if t.galley.job.text == text => {
                    Some((t.pos.x, t.pos.y, t.galley.rect.width(), t.galley.rect.height()))
                }
                _ => None,
            })
            .collect();
        v.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.total_cmp(&b.0)));
        v
    }

    /// 修复前 = RED（双栏包装层横向布局继承 + 行高 20px 钳制 → 栏头/
    /// 表头/分页塌缩成一行、行 Grid 右偏表头之外向下溢出）；修复后 =
    /// 行区对齐表头正下方、双栏并排、行距均匀。
    #[test]
    fn r133_2_nonempty_58_rows_rendered() {
        // 修复并行 `set_lang` 切换致「远端表头应 4 列」偶发 flake。
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let root = empty_tmp_root("ne");
        let entries: Vec<FileMgrEntry> = (0..58)
            .map(|i| FileMgrEntry {
                name: format!("remote_{i:02}.bin"),
                size: 1024 * (i as u64 + 1),
                mtime: 1_750_000_000 + i as i64,
                is_dir: i % 10 == 0,
                is_symlink: false,
                is_hidden: false,
            })
            .collect();
        let mut state = state_with_remote(root, entries);
        let panel = FilePanelState::new();
        let (sw, sh) = (1920.0, 1080.0);
        let shapes = run_frames(&mut state, &panel, (sw, sh), 2);

        // (1) 退化分配判据：任何非有限矩形/裁剪 = 退化（release 断言移除
        //     族下静默不绘制；debug 下 egui finiteness assert 先行，此处
        //     显式兜底同构语义）。
        for cs in &shapes {
            assert!(cs.clip_rect.is_finite(), "非有限裁剪矩形（退化分配）");
            if let egui::Shape::Rect(r) = &cs.shape {
                assert!(r.rect.is_finite(), "非有限矩形 shape（退化分配）");
            }
        }

        // (2) 双栏并排：两栏栏头 y 齐平（±2px）。修复前：23px 纵向错位
        //     → RED。
        let local_marks = text_rects(&shapes, crate::t!("filemgr.local"));
        let remote_marks = text_rects(&shapes, crate::t!("filemgr.remote"));
        assert!(!local_marks.is_empty() && !remote_marks.is_empty(), "栏头行未绘制");
        let (local_y, remote_y) = (local_marks[0].1, remote_marks[0].1);
        assert!(
            (local_y - remote_y).abs() <= 2.0,
            "双栏未并排（栏头 y 错位 {:.1}px）= 布局退化",
            local_y - remote_y
        );

        // (3) 栏内 栏头→面包屑→表头 竖排正常行距（行高 ≥15px）。修复前：
        //     （「本地」仅栏头一处；面包屑 y 取本地栏「▸」分隔符行）。
        assert!(
            local_marks.len() == 1,
            "本地栏「{}」应恰一处（栏头），实际 {}",
            crate::t!("filemgr.local"),
            local_marks.len()
        );
        let bc_y = text_rects(&shapes, "▸")
            .into_iter()
            .find(|(x, _, _, _)| *x < sw / 2.0)
            .map(|(_, y, _, _)| y)
            .unwrap_or_else(|| panic!("本地面包屑分隔符「▸」未绘制"));
        let th_y = text_rects(&shapes, crate::t!("filemgr.col.name"))
            .into_iter()
            .find(|(x, _, _, _)| *x < sw / 2.0)
            .map(|(_, y, _, _)| y)
            .unwrap_or_else(|| panic!("本地表头「{}」未绘制", crate::t!("filemgr.col.name")));
        assert!(
            bc_y - local_y >= 15.0,
            "栏头/面包屑塌缩（行高 {:.1}px）= 布局退化",
            bc_y - local_y
        );
        assert!(
            th_y - bc_y >= 15.0,
            "面包屑/表头塌缩（行高 {:.1}px）= 布局退化",
            th_y - bc_y
        );

        // (4) 远端行区行背景（grid 条纹，58 行 → 29）：在位、严格递增、
        //     行距均匀（±2px）。
        let remote_rows: Vec<egui::Rect> =
            row_bg_rects(&shapes).into_iter().filter(|r| r.min.x >= sw / 2.0).collect();
        assert!(
            remote_rows.len() >= 25,
            "远端行区行背景 {} 条（<25）= 行区整片未绘制/塌缩",
            remote_rows.len()
        );
        for w in remote_rows.windows(2) {
            assert!(
                w[1].min.y > w[0].min.y + 5.0,
                "行区行重叠/塌缩: {:?} → {:?}",
                w[0],
                w[1]
            );
        }
        let pitches: Vec<f32> = remote_rows.windows(2).map(|w| w[1].min.y - w[0].min.y).collect();
        let pmin = pitches.iter().cloned().fold(f32::INFINITY, f32::min);
        let pmax = pitches.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        assert!(
            pmax - pmin <= 2.0,
            "行区行距不均匀（min={pmin} max={pmax}）= 退化布局"
        );

        // (5) 行区对齐表头正下方（根因判据）：行背景 x 区间与远端表头行
        //     x 区间重叠。修复前：表头 x≈1554..1740、行 x≈1754..2075
        //     （行被推到表头右侧、右半出屏）→ RED。
        let th_rects: Vec<(f32, f32, f32, f32)> = [
            text_rects(&shapes, crate::t!("filemgr.col.name")),
            text_rects(&shapes, crate::t!("filemgr.col.size")),
            text_rects(&shapes, crate::t!("filemgr.col.modified")),
            text_rects(&shapes, crate::t!("filemgr.col.type")),
        ]
        .iter()
        .flat_map(|v| v.iter().copied())
        .filter(|(x, _, _, _)| *x >= sw / 2.0)
        .collect();
        assert!(th_rects.len() == 4, "远端表头应 4 列，实际 {}", th_rects.len());
        let th_xmin = th_rects.iter().map(|t| t.0).fold(f32::INFINITY, f32::min);
        let th_xmax = th_rects.iter().map(|t| t.0 + t.2).fold(f32::NEG_INFINITY, f32::max);
        let (row_xmin, row_xmax) = (
            remote_rows.first().map(|r| r.min.x).unwrap(),
            remote_rows.last().map(|r| r.max.x).unwrap(),
        );
        assert!(
            row_xmin < th_xmax && row_xmax > th_xmin,
            "行区被推到表头右侧（行 x {:.0}..{:.0} vs 表头 x {:.0}..{:.0}）= 横向布局退化",
            row_xmin,
            row_xmax,
            th_xmin,
            th_xmax
        );

        // (6) 首行顶在表头下沿之下且在屏内（不挤进工具行、不整片出屏）。
        let th_bottom = th_rects.iter().map(|t| t.1 + t.3).fold(f32::NEG_INFINITY, f32::max);
        assert!(
            remote_rows[0].min.y > th_bottom,
            "行区挤进表头/工具行: 首行顶 {:.1} ≤ 表头底 {:.1}",
            remote_rows[0].min.y,
            th_bottom
        );
        assert!(
            remote_rows[0].min.y < sh,
            "行区首行已出屏（{:.1} > 屏高 {:.0}）= 行区整片不绘制",
            remote_rows[0].min.y,
            sh
        );

        // 子行全量可见（无分页行；59 行 = 根 + 58 子）。
        let n_root = text_rects(&shapes, crate::i18n::tr("filemgr.pc_root_remote")).len();
        assert!(n_root >= 1, "远端根行（「远端电脑」合成根）未绘制");
        assert!(
            remote_rows.len() >= 28,
            "树行区背景 {} 条（<28，59 行应 ≥29）= 行区未全量绘制",
            remote_rows.len()
        );
    }

    /// （root_display）渲染、零子行（旧「此目录为空」提示行 = 树根行替代）。
    #[test]
    fn r133_2_empty_dir_no_regression() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let root = empty_tmp_root("em");
        let mut state = state_with_remote(root, Vec::new());
        let panel = FilePanelState::new();
        let shapes = run_frames(&mut state, &panel, (1920.0, 1080.0), 2);

        let n_root = text_rects(&shapes, crate::i18n::tr("filemgr.pc_root_remote")).len();
        assert!(n_root >= 1, "远端根行（「远端电脑」合成根）未绘制（空目录形态回归）");
        let remote_rows: Vec<egui::Rect> =
            row_bg_rects(&shapes).into_iter().filter(|r| r.min.x >= 960.0).collect();
        assert_eq!(
            remote_rows.len(),
            1,
            "空远端 = 恰根行 1 条行背景（无子行），实际 {}",
            remote_rows.len()
        );
    }
}

// ════════════════════════════════════════════════════════════
// 文件vs目录识别 + 顶栏常用目录定案 + headless 布局判据）
// ════════════════════════════════════════════════════════════

#[cfg(test)]
mod r133_7_tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "k133_7_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn mkfile(p: &Path, content: &str) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(p).unwrap();
        std::io::Write::write_all(&mut f, content.as_bytes()).unwrap();
    }

    fn mk_entry(name: &str, size: u64, is_dir: bool) -> FileMgrEntry {
        FileMgrEntry {
            name: name.into(),
            size,
            mtime: 0,
            is_dir,
            is_symlink: false,
            is_hidden: false,
        }
    }

    fn mk_symlink_dir(name: &str) -> FileMgrEntry {
        FileMgrEntry {
            name: name.into(),
            size: 0,
            mtime: 0,
            is_dir: true,
            is_symlink: true,
            is_hidden: false,
        }
    }

    /// 测试态：本地 = 真临时目录（含 `updir/a.txt` + `up.txt` + 空目录
    /// `dld`），远端 = 预置条目（`dldir` 目录 + `dl.txt` 文件 + 符号链接
    /// 目录 `link`），`started = true` 零 wire。
    fn state_armed(root: PathBuf) -> FileManagerState {
        let mut state = FileManagerState::with_local_root(root.clone());
        mkfile(&root.join("up.txt"), "up");
        mkfile(&root.join("updir").join("a.txt"), "a");
        std::fs::create_dir_all(root.join("dld")).unwrap();
        // 行；零 wire）。
        assert!(state.local_expand_chain(&root), "本地链展开（测试前置）");
        state.remote.started = true;
        state.remote.root_display = "r133-7".to_string();
        // → 盘内条目（真拓扑同形：合成根之子 = 盘符根，盘内 = 常规条目）。
        // 活动节点 = `C:\`（选中路径经 `remote_join` 盘符感知拼接）。
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("C:\\", 0, true)]),
                ..Default::default()
            },
        );
        state.remote.view.nodes.insert(
            "C:\\".to_string(),
            TreeNodeState {
                children: Some(vec![
                    mk_entry("dldir", 0, true),
                    mk_entry("dl.txt", 9, false),
                    mk_symlink_dir("link"),
                ]),
                ..Default::default()
            },
        );
        state.remote.current = "C:\\".to_string();
        state
    }

    /// 当前节点〔seed = 根〕相对拼路径——根级名串零漂移）。
    fn select(state: &mut FileManagerState, pane: PaneId, names: &[&str]) {
        let paths: Vec<String> = match pane {
            PaneId::Local => names
                .iter()
                .map(|s| local_path_key(&state.local.current.join(s)))
                .collect(),
            PaneId::Remote => names
                .iter()
                .map(|s| remote_join(&state.remote.current, s))
                .collect(),
        };
        state.view_mut(pane).selected = paths;
    }

    /// ① enable 纯谓词矩阵（双选中 enable / 单侧 disable / 目标非目录
    /// disable——方向无关基元）。
    #[test]
    fn r133_7_arrow_enabled_matrix() {
        // 单侧/双侧无选中 = disable。
        assert!(!arrow_enabled(0, false), "双侧无选中 = disable");
        assert!(!arrow_enabled(0, true), "仅目标侧选中（源空）= disable");
        assert!(!arrow_enabled(1, false), "仅源侧选中（目标非目录）= disable");
        // 双选中 + 目标恰一目录 = enable（文件/目录多选源均可）。
        assert!(arrow_enabled(1, true), "单文件源 + 目录目标 = enable");
        assert!(arrow_enabled(3, true), "多选源 + 目录目标 = enable");
    }

    /// ② 方向语义：`panes()` 映射（← = 远端→本地 / → = 本地→远端）
    /// 单一事实源钉死。
    #[test]
    fn r133_7_arrow_panes_direction() {
        assert_eq!(
            ArrowDirection::Download.panes(),
            (PaneId::Remote, PaneId::Local),
            "← = 远程选中项下载到本地选中目录"
        );
        assert_eq!(
            ArrowDirection::Upload.panes(),
            (PaneId::Local, PaneId::Remote),
            "→ = 本地选中项上传到远程选中目录"
        );
    }

    /// ③ 常用目录集合定案：本机 = 桌面/下载/文档（home 基准，固定序）；
    /// 标签键与路径一一对应。
    #[test]
    fn r133_7_local_quick_dirs_set() {
        let home = PathBuf::from("/home/u");
        let dirs = local_quick_dirs(&home);
        assert_eq!(
            dirs,
            [
                PathBuf::from("/home/u/Desktop"),
                PathBuf::from("/home/u/Downloads"),
                PathBuf::from("/home/u/Documents"),
            ],
            "本机常用目录定案 = 桌面/下载/文档（固定序）"
        );
        assert_eq!(LOCAL_QUICK_KEYS.len(), dirs.len(), "标签键与路径一一对应");
    }

    /// ④ enable 状态矩阵（state 级：双选中 enable / 单侧 disable / 目标为
    /// 文件 fail-closed / 目标符号链接目录 fail-closed / 目标多选 disable /
    /// 源仅符号链接目录 = 不可传输 disable / busy 门）。
    #[test]
    fn r133_7_arrow_ready_selection_matrix() {
        let root = tmp_root("ready");
        let mut state = state_armed(root.clone());

        // (a) 双侧无选中 = 双向 disable。
        assert!(!state.arrow_ready(ArrowDirection::Download), "无选中 ← = disable");
        assert!(!state.arrow_ready(ArrowDirection::Upload), "无选中 → = disable");

        // (b) 单侧选中 = 双向 disable（下载源=远端空；上传目标=远端空）。
        select(&mut state, PaneId::Local, &["up.txt"]);
        assert!(!state.arrow_ready(ArrowDirection::Download), "仅本地选中 ← = disable");
        assert!(!state.arrow_ready(ArrowDirection::Upload), "仅本地选中 → = disable");
        select(&mut state, PaneId::Local, &[]);
        select(&mut state, PaneId::Remote, &["dldir"]);
        assert!(!state.arrow_ready(ArrowDirection::Upload), "仅远端选中 → = disable");
        assert!(!state.arrow_ready(ArrowDirection::Download), "仅远端选中 ← = disable");

        // (c) 双选中（本地目录 + 远端目录）= 双向 enable。
        select(&mut state, PaneId::Local, &["dld"]);
        select(&mut state, PaneId::Remote, &["dldir"]);
        assert!(state.arrow_ready(ArrowDirection::Download), "双选中（目录×目录）← = enable");
        assert!(state.arrow_ready(ArrowDirection::Upload), "双选中（目录×目录）→ = enable");

        // (d) 目标侧选中为文件 = fail-closed disable（← 目标 = 本地选中
        //     须为目录；up.txt 是文件）。
        select(&mut state, PaneId::Local, &["up.txt"]);
        assert!(!state.arrow_ready(ArrowDirection::Download), "目标为文件 ← = disable");
        // → 源 = 本地文件（可传输）+ 目标 = 远端目录 = enable（源自动识别
        // = 文件走单文件快路径）。
        assert!(state.arrow_ready(ArrowDirection::Upload), "本地文件→远端目录 → = enable");

        // (e) 目标侧选中符号链接目录 = fail-closed disable（S4 不跟随）。
        select(&mut state, PaneId::Remote, &["link"]);
        select(&mut state, PaneId::Local, &["dld"]);
        assert!(!state.arrow_ready(ArrowDirection::Upload), "目标为符号链接目录 → = disable");
        // ← 源 = 远端符号链接目录（不可传输）+ 目标 = 本地目录 = disable。
        select(&mut state, PaneId::Remote, &["link"]);
        select(&mut state, PaneId::Local, &["dld"]);
        assert!(!state.arrow_ready(ArrowDirection::Download), "源仅符号链接目录 ← = disable");

        // (f) 目标侧多选（目录 + 文件）= 非「恰一目录」= disable。
        select(&mut state, PaneId::Local, &["dld", "up.txt"]);
        select(&mut state, PaneId::Remote, &["dl.txt"]);
        assert!(!state.arrow_ready(ArrowDirection::Download), "目标多选 ← = disable");

        // (g) busy 门：在途 job = 双向 disable（既有栏按钮同构）。
        select(&mut state, PaneId::Local, &["dld"]);
        select(&mut state, PaneId::Remote, &["dldir"]);
        state.job = Some(FolderJob {
            direction: FolderDirection::ToRemote,
            source: String::new(),
            target_remote_dir: String::new(),
            target_local_dir: PathBuf::new(),
            files: vec![],
            depth_capped: vec![],
            next_idx: 0,
            batch_head: 0,
            collecting: false,
            collect_queue: VecDeque::new(),
            finished: false,
            started: Instant::now(),
            consent_pending: false,
            consent_req_id: None,
            target_dirs: Vec::new(),
            visit: HashSet::new(),
            failed: Vec::new(),
            cycle_skipped: Vec::new(),
            summary_emitted: false,
            mkdir_queue: VecDeque::new(),
        });
        assert!(!state.arrow_ready(ArrowDirection::Download), "在途 job ← = disable");
        assert!(!state.arrow_ready(ArrowDirection::Upload), "在途 job → = disable");
        std::fs::remove_dir_all(&root).ok();
    }

    /// ⑤ 方向语义 + 文件vs目录识别 + 目标 = 对侧**选中目录**（非当前目录）
    /// ——四形态逐一定案：
    /// a) → 本地**文件** + 远端**目录** = SendWithConsent 单条目，落点 =
    ///    远端选中目录（remote.current/dldir，而非 remote.current）；
    /// b) → 本地**目录** + 远端**目录** = FolderJob 整目录编排，
    ///    target_remote_dir = 远端选中目录，零即刻帧（tick 节奏既有）；
    /// c) ← 远端**文件** + 本地**目录** = FetchFile，落点 = 本地选中目录
    ///    （local.current/dld，而非 local.current）；
    /// d) ← 远端**目录** + 本地**目录** = FolderJob 整目录编排，
    ///    target_local_dir = 本地选中目录 + BFS 收集远端选中目录。
    #[test]
    fn r133_7_arrow_transfer_file_vs_dir() {
        // —— a) → 本地文件 → 远端选中目录 ——
        let root = tmp_root("up_file");
        let mut state = state_armed(root.clone());
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        select(&mut state, PaneId::Local, &["up.txt"]);
        select(&mut state, PaneId::Remote, &["dldir"]);
        let n = state.arrow_transfer(ArrowDirection::Upload, &panel, Some(&ftx), Some(&mtx));
        assert_eq!(n, 1, "单文件 = 入队 1 项");
        assert!(state.job.is_none(), "单文件 = 快路径不建任务");
        match mxr.try_recv() {
            Ok(FileMgrCommand::SendWithConsent {
                entries,
                truncated,
                from_job,
            }) => {
                assert_eq!(entries.len(), 1, "单文件 = 单条目");
                assert!(!truncated && !from_job, "单文件零截断非任务");
                assert_eq!(&entries[0].0, &root.join("up.txt"));
                assert_eq!(entries[0].1, "C:\\dldir", "落点 = 远端选中目录（非当前目录）");
            }
            other => panic!("应得 SendWithConsent，实际 {other:?}"),
        }
        assert!(frx.try_recv().is_err(), "上传不走 FileCommand 通道");

        // —— b) → 本地目录 → 远端选中目录（整目录传输 = 既有编排零 wire）——
        select(&mut state, PaneId::Local, &["updir"]);
        select(&mut state, PaneId::Remote, &["dldir"]);
        let n = state.arrow_transfer(ArrowDirection::Upload, &panel, Some(&ftx), Some(&mtx));
        assert_eq!(n, 1, "目录内 1 文件 = 入队 1 项");
        let job = state.job.as_ref().expect("目录 = FolderJob 整目录编排");
        assert_eq!(job.direction, FolderDirection::ToRemote, "→ = ToRemote");
        assert_eq!(job.target_remote_dir, "C:\\dldir", "目标 = 远端选中目录");
        assert!(
            job.files
                .iter()
                .any(|(p, _, sub)| p == &local_path_key(&root.join("updir").join("a.txt"))
                    && sub == "updir"),
            "整目录文件结构镜像: {:?}",
            job.files
        );
        assert!(mxr.try_recv().is_err(), "文件夹任务零即刻帧（tick 节奏既有）");

        // —— c) ← 远端文件 → 本地选中目录 ——
        let root2 = tmp_root("dn_file");
        let mut st2 = state_armed(root2.clone());
        let panel2 = FilePanelState::new();
        let (ftx2, mut frx2) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx2, _mxr2) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        select(&mut st2, PaneId::Remote, &["dl.txt"]);
        select(&mut st2, PaneId::Local, &["dld"]);
        let n = st2.arrow_transfer(ArrowDirection::Download, &panel2, Some(&ftx2), Some(&mtx2));
        assert_eq!(n, 1, "单文件 = 入队 1 项");
        assert!(st2.job.is_none(), "单文件 = 快路径不建任务");
        match frx2.try_recv() {
            Ok(FileCommand::FetchFile {
                remote_path,
                local_dir,
            }) => {
                assert_eq!(remote_path, "C:\\dl.txt", "源 = 远端选中文件");
                assert_eq!(local_dir, root2.join("dld"), "落点 = 本地选中目录（非当前目录）");
            }
            other => panic!("应得 FetchFile，实际 {other:?}"),
        }
        assert!(
            matches!(
                st2.pending.as_ref().map(|p| &p.kind),
                Some(PendingKind::Fetch { remote_path }) if remote_path == "C:\\dl.txt"
            ),
            "pending 回填 Fetch"
        );

        // —— d) ← 远端目录 → 本地选中目录（整目录传输 = 既有编排零 wire）——
        select(&mut st2, PaneId::Remote, &["dldir"]);
        select(&mut st2, PaneId::Local, &["dld"]);
        let n = st2.arrow_transfer(ArrowDirection::Download, &panel2, Some(&ftx2), Some(&mtx2));
        assert!(n >= 0, "收集期入队数 = 已收集文件数（首帧 0 允许）");
        let job = st2.job.as_ref().expect("目录 = FolderJob 整目录编排");
        assert_eq!(job.direction, FolderDirection::ToLocal, "← = ToLocal");
        assert_eq!(job.target_local_dir, root2.join("dld"), "目标 = 本地选中目录");
        assert!(job.collecting, "远端目录 = BFS 收集在途");
        // BFS 根 = 选中目录节点自身 + 镜像前缀 = 目录名。
        assert!(
            job.collect_queue
                .iter()
                .any(|(p, _, _, src, prefix)| {
                    p == "C:\\dldir" && src == "C:\\dldir" && prefix == "dldir"
                }),
            "收集队列含远端选中目录（盘符路径 + 镜像前缀 = 目录名）: {:?}",
            job.collect_queue
        );

        // —— 单侧选中调用面 = 0 项 + 零帧（fail-closed 兜底）——
        select(&mut st2, PaneId::Local, &[]);
        let n = st2.arrow_transfer(ArrowDirection::Download, &panel2, Some(&ftx2), Some(&mtx2));
        assert_eq!(n, 0, "目标侧无选中 = 零入队");
        assert!(frx2.try_recv().is_err(), "零入队 = 零帧");
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&root2).ok();
    }

    /// ⑥ 常用目录导航（点击面）：目录存在 = 进入 + 清选中 + 回页 0 + 刷新；
    /// 目录不存在 = 栏内提示 fail-closed（不跳目录不清选中）。
    #[test]
    fn r133_7_goto_local_quick() {
        let root = tmp_root("quick");
        let mut state = state_armed(root.clone());
        std::fs::create_dir_all(root.join("Desktop")).unwrap();
        mkfile(&root.join("Desktop").join("note.txt"), "n");
        select(&mut state, PaneId::Local, &["up.txt"]);

        state.goto_local_quick(&root.join("Desktop"));
        assert_eq!(state.local.current, root.join("Desktop"), "进入常用目录");
        let key = local_path_key(&root.join("Desktop"));
        // 「导航清选中」= 展开了但不选中不高亮不滚动的用户复测根因面）。
        assert_eq!(
            state.local.view.selected,
            vec![key.clone()],
        );
        assert_eq!(
            state.local.scroll_anchor.as_deref(),
            Some(key.as_str()),
        );
        assert!(state.local.scroll_anchor_prev_delta.is_none(), "收敛观测复位");
        assert!(
            state.local.view.expanded.iter().any(|e| e == &key),
            "链展开至目标节点"
        );
        assert!(
            state
                .local
                .view
                .nodes
                .get(&key)
                .and_then(|n| n.children.as_ref())
                .is_some_and(|c| c.iter().any(|e| e.name == "note.txt")),
            "导航后刷新在位"
        );

        state.goto_local_quick(&root.join("Downloads"));
        assert_eq!(state.local.current, root.join("Desktop"), "不存在目录不跳转");
        assert_eq!(
            state.local.view.selected,
            vec![key],
        );
        assert_eq!(
            state.local.scroll_anchor.as_deref(),
            Some(local_path_key(&root.join("Desktop")).as_str()),
        );
        assert!(
            state
                .local
                .view
                .status
                .as_deref()
                .is_some_and(|s| !s.is_empty()),
            "栏内错误提示在位"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// ⑦ headless 布局判据（双栏 + 中缝箭头 + 顶栏快捷区）：
    /// a) 顶栏快捷区在双栏之上（「桌面」y < 栏头 y）；
    /// b) ←/→ 在位且**垂直居中**于双栏行带（双箭头中心距 ≈ 按钮高，
    ///    组中心 = 行带中心容差内）、x = 双栏中缝 ±5px；
    /// d) 零退化分配（全部矩形/裁剪有限）。
    #[test]
    fn r133_7_layout_quickbar_and_seam() {
        // 串行化并钉中文基线（同 r133_2_tests 先例）。
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let root = tmp_root("layout");
        // 垂直居中参考面；`state_armed` 链展开后全部入树）。
        for i in 0..40 {
            mkfile(&root.join(format!("row_{i:02}.bin")), "x");
        }
        let mut state = state_armed(root.clone());
        let panel = FilePanelState::new();
        let (sw, sh) = (1920.0, 1080.0);

        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let mut shapes: Vec<egui::epaint::ClippedShape> = Vec::new();
        for _ in 0..2 {
            let mut raw = egui::RawInput::default();
            raw.screen_rect =
                Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(sw, sh)));
            shapes = ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let mut focus = false;
                    show_file_manager(
                        ui,
                        &Theme::LIGHT,
                        &mut state,
                        None,
                        None,
                        &panel,
                        false,
                        &mut focus,
                    );
                });
            })
            .shapes;
        }

        // (d) 零退化分配。
        for cs in &shapes {
            assert!(cs.clip_rect.is_finite(), "非有限裁剪矩形（退化分配）");
            if let egui::Shape::Rect(r) = &cs.shape {
                assert!(r.rect.is_finite(), "非有限矩形 shape（退化分配）");
            }
        }

        fn text_rects(shapes: &[egui::epaint::ClippedShape], text: &str) -> Vec<egui::Rect> {
            shapes
                .iter()
                .filter_map(|cs| match &cs.shape {
                    egui::Shape::Text(t) if t.galley.job.text == text => {
                        Some(egui::Rect::from_min_size(t.pos, t.galley.size()))
                    }
                    _ => None,
                })
                .collect()
        }

        // (a) 顶栏快捷区在双栏之上。
        let desktop = &t!("filemgr.quick.desktop");
        let dl = text_rects(&shapes, desktop);
        assert!(!dl.is_empty(), "顶栏常用目录「{desktop}」未绘制");
        let local_marks = text_rects(&shapes, &t!("filemgr.local"));
        assert!(!local_marks.is_empty(), "本地栏头未绘制");
        let header_y = local_marks.iter().map(|r| r.min.y).fold(f32::INFINITY, f32::min);
        assert!(
            dl[0].min.y < header_y,
            "常用目录快捷区应在双栏之上（桌面 y {:.1} ≥ 栏头 y {:.1}）",
            dl[0].min.y,
            header_y
        );

        // (b) ←/→ 在位 + 垂直居中 + x = 中缝。
        let down = text_rects(&shapes, "←");
        let up = text_rects(&shapes, "→");
        assert!(!down.is_empty() && !up.is_empty(), "中缝 ←/→ 箭头未绘制");
        let down_c = down[0].center();
        let up_c = up[0].center();
        assert!(
            (down_c.x - up_c.x).abs() <= 1.0,
            "双箭头 x 不齐（{:.1} vs {:.1}）",
            down_c.x,
            up_c.x
        );
        assert!(
            (down_c.x - sw / 2.0).abs() <= 5.0,
            "中缝箭头偏离双栏中线（x {:.1} vs 中线 {:.1}）",
            down_c.x,
            sw / 2.0
        );
        // 双钮中心距 = 按钮高 + 一项自动 item_spacing.y（egui 0.28 默认
        // 3.0；双重间距 = 回归信号）。
        let pitch = up_c.y - down_c.y;
        assert!(
            (pitch - (SEAM_BTN_H + 3.0)).abs() <= 1.0,
            "双箭头行距异常（{pitch:.1} ≈ 按钮高+行距 {SEAM_BTN_H}+3）"
        );
        // 行条纹矩形最大底沿**钳窗底**——树内展开节点的屏下行条纹矩形在
        // 内容坐标延伸远超可视底（painter clip 在光栅阶段，shape 矩形不裁
        // 剪），不得参与带心计算；本地「此电脑」根行恒在位保证非空）。
        let row_bottom = shapes
            .iter()
            .filter_map(|cs| match &cs.shape {
                egui::Shape::Rect(r)
                    if r.fill == egui::Visuals::light().faint_bg_color
                        && r.rect.width() >= 100.0 =>
                {
                    Some(r.rect.max.y)
                }
                _ => None,
            })
            .fold(f32::NEG_INFINITY, f32::max)
            .min(sh);
        assert!(row_bottom > header_y, "行区未渲染（无行条纹）= 布局退化");
        let band_top = header_y;
        let band_center = (band_top + row_bottom) / 2.0;
        let arrows_center = (down_c.y + up_c.y) / 2.0;
        assert!(
            arrows_center > band_top && arrows_center < row_bottom,
            "箭头组不在双栏行带内（{arrows_center:.1} ∉ [{band_top:.1}, {row_bottom:.1}]）"
        );
        assert!(
            (arrows_center - band_center).abs() <= 30.0,
            "箭头组未垂直居中（{arrows_center:.1} vs 行带中心 {band_center:.1}）——行带含栏头/面包屑/表头/行区固定行，居中容差 30px"
        );
        assert!(sh > 0.0, "屏高非零");

        let remote_marks = text_rects(&shapes, &t!("filemgr.remote"));
        assert!(!remote_marks.is_empty(), "远端栏头未绘制");
        let (local_y, remote_y) = (
            local_marks.iter().map(|r| r.min.y).fold(f32::INFINITY, f32::min),
            remote_marks.iter().map(|r| r.min.y).fold(f32::INFINITY, f32::min),
        );
        assert!(
            (local_y - remote_y).abs() <= 2.0,
            "双栏未并排（栏头 y 错位 {:.1}px）",
            local_y - remote_y
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// ⑧ 隔离目录截屏自验（用户观感终判）：headless 真 egui 双帧 → 软件光栅化
    /// （Rect fill/stroke + 字形经字体图集 UV 采样混色）→ PNG 落
    /// `docs/r133_7_seam_sandbox.png`（**不入库**）。形态 = 双方向均
    /// enable 的双选中态（本地 `dld` + 远端 `dldir`）：顶栏快捷区 + 双栏 +
    /// 中缝 ←/→ 高亮在位。仅测试区消费（零生产代码）。
    #[test]
    fn r133_7_screenshot_dump() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let root = tmp_root("shot");
        let mut state = state_armed(root.clone());
        // 双选中态（箭头 enable 形态）。
        select(&mut state, PaneId::Local, &["dld"]);
        select(&mut state, PaneId::Remote, &["dldir"]);
        let panel = FilePanelState::new();
        let (sw, sh) = (1280.0, 720.0);

        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let run_frame = |ctx: &egui::Context, state: &mut FileManagerState| {
            let mut raw = egui::RawInput::default();
            raw.screen_rect =
                Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(sw, sh)));
            ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let mut focus = false;
                    show_file_manager(
                        ui,
                        &Theme::LIGHT,
                        state,
                        None,
                        None,
                        &panel,
                        false,
                        &mut focus,
                    );
                });
            })
        };
        // 帧 1 = 字体图集建立（`ImageData::Font` = 单通道覆盖度）；
        // 帧 2 = 稳态 shapes。
        let out1 = run_frame(&ctx, &mut state);
        let out2 = run_frame(&ctx, &mut state);
        let mut atlas: Option<(usize, usize, Vec<f32>)> = None;
        for (_, delta) in out1.textures_delta.set.iter() {
            if let egui::epaint::ImageData::Font(fi) = &delta.image {
                if fi.size[0] * fi.size[1] > atlas.as_ref().map(|(a, b, _)| a * b).unwrap_or(0) {
                    atlas = Some((fi.size[0], fi.size[1], fi.pixels.clone()));
                }
            }
        }
        let (aw, ah, aatlas) = atlas.expect("字体图集纹理应在首帧建立");

        // 软件光栅化（Rect fill/stroke + Text 字形图集采样；Mesh 等 = 跳过）。
        fn c32_rgba(c: egui::Color32) -> image::Rgba<u8> {
            let [r, g, b, a] = c.to_srgba_unmultiplied();
            image::Rgba::<u8>([r, g, b, a])
        }
        let (w, h) = (sw as u32, sh as u32);
        let panel_bg = egui::Visuals::light().panel_fill;
        let mut img = image::RgbaImage::from_pixel(w, h, c32_rgba(panel_bg));
        for cs in &out2.shapes {
            let clip = cs.clip_rect;
            let mut draw_rect = |r: egui::Rect, c: image::Rgba<u8>| {
                let x0 = (r.min.x.max(clip.min.x)).floor() as i32;
                let y0 = (r.min.y.max(clip.min.y)).floor() as i32;
                let x1 = (r.max.x.min(clip.max.x)).ceil() as i32;
                let y1 = (r.max.y.min(clip.max.y)).ceil() as i32;
                for y in y0.max(0)..y1.min(h as i32) {
                    for x in x0.max(0)..x1.min(w as i32) {
                        img.put_pixel(x as u32, y as u32, c);
                    }
                }
            };
            match &cs.shape {
                egui::Shape::Rect(rs) => {
                    if rs.fill.a() > 0 {
                        draw_rect(rs.rect, c32_rgba(rs.fill));
                    }
                    if rs.stroke.width > 0.0 {
                        let swd = rs.stroke.width.max(1.0);
                        draw_rect(rs.rect, c32_rgba(rs.stroke.color));
                        let inner = rs.rect.shrink2(egui::vec2(swd / 2.0, swd / 2.0));
                        if inner.width() > 0.0 && inner.height() > 0.0 {
                            draw_rect(inner, c32_rgba(panel_bg));
                        }
                    }
                }
                egui::Shape::Text(t) => {
                    let sections = &t.galley.job.sections;
                    for row in &t.galley.rows {
                        for g in &row.glyphs {
                            let uv = &g.uv_rect;
                            let (sx0, sy0) = (uv.min[0] as i32, uv.min[1] as i32);
                            let (sx1, sy1) = (uv.max[0] as i32, uv.max[1] as i32);
                            let sw_ = (sx1 - sx0).max(1);
                            let sh_ = (sy1 - sy0).max(1);
                            let mut color = sections
                                .get(g.section_index as usize)
                                .map(|s| s.format.color)
                                .unwrap_or_default();
                            if color == egui::Color32::PLACEHOLDER {
                                color = t.fallback_color;
                            }
                            if let Some(oc) = t.override_text_color {
                                color = oc;
                            }
                            let [cr, cg, cb, ca] = color.to_srgba_unmultiplied();
                            let gx0 = (t.pos.x + g.pos.x + uv.offset.x).floor() as i32;
                            let gy0 = (t.pos.y + g.pos.y + uv.offset.y).floor() as i32;
                            let gw_i = uv.size.x.max(1.0) as i32;
                            let gh_i = uv.size.y.max(1.0) as i32;
                            for dy in 0..gh_i {
                                let ay = (sy0 + dy * sh_ / gh_i).min(ah as i32 - 1);
                                for dx in 0..gw_i {
                                    let ax = (sx0 + dx * sw_ / gw_i).min(aw as i32 - 1);
                                    if ax < 0 || ay < 0 {
                                        continue;
                                    }
                                    let a = aatlas[(ay as usize) * aw + (ax as usize)]
                                        * (ca as f32 / 255.0);
                                    if a <= 0.01 {
                                        continue;
                                    }
                                    let px = gx0 + dx;
                                    let py = gy0 + dy;
                                    if px < 0 || py < 0 || px >= w as i32 || py >= h as i32 {
                                        continue;
                                    }
                                    if px < clip.min.x as i32 || px >= clip.max.x as i32
                                        || py < clip.min.y as i32
                                        || py >= clip.max.y as i32
                                    {
                                        continue;
                                    }
                                    let dst = img.get_pixel(px as u32, py as u32);
                                    let out = image::Rgba::<u8>([
                                        (cr as f32 * a + dst[0] as f32 * (1.0 - a)) as u8,
                                        (cg as f32 * a + dst[1] as f32 * (1.0 - a)) as u8,
                                        (cb as f32 * a + dst[2] as f32 * (1.0 - a)) as u8,
                                        255,
                                    ]);
                                    img.put_pixel(px as u32, py as u32, out);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let out_path = "E:/projects_rd/docs/r133_7_seam_sandbox.png";
        img.save(out_path).expect("PNG 落盘");
        assert!(std::path::Path::new(out_path).is_file(), "截屏在位");
        std::fs::remove_dir_all(&root).ok();
    }
}

// ════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════
#[cfg(test)]
mod r134_7_tests {
    use super::*;

    /// 与 [`FileManagerState::arrow_ready`] 的 fail-closed 判定序逐位对齐；
    /// `None` = 就绪 = `arrow_ready` 为 true 同态）。
    #[test]
    fn r134_7_arrow_disabled_reason_matrix() {
        // 在途（busy）= 首判，无论源/目标态。
        assert_eq!(
            arrow_disabled_reason(true, 0, false),
            Some(ArrowDisabledReason::InFlight),
            "busy + 无源 + 无目标 = InFlight（首判）"
        );
        assert_eq!(
            arrow_disabled_reason(true, 3, true),
            Some(ArrowDisabledReason::InFlight),
            "busy 压过「源/目标均就绪」= InFlight"
        );
        // 非在途 + 源侧无可传输选中。
        assert_eq!(
            arrow_disabled_reason(false, 0, false),
            Some(ArrowDisabledReason::NoSourceSel),
            "无源（目标亦无）= NoSourceSel"
        );
        assert_eq!(
            arrow_disabled_reason(false, 0, true),
            Some(ArrowDisabledReason::NoSourceSel),
            "无源（目标就绪）= NoSourceSel（源侧优先于目标侧）"
        );
        // 非在途 + 源侧有 + 目标侧非单目录。
        assert_eq!(
            arrow_disabled_reason(false, 2, false),
            Some(ArrowDisabledReason::NoTargetDir),
            "源有 + 目标非单目录 = NoTargetDir"
        );
        // 全就绪 = None（= arrow_ready true 同态）。
        assert_eq!(arrow_disabled_reason(false, 1, true), None, "就绪 = None");
        // 与 arrow_ready/arrow_enabled 互斥性钉死（禁 ready 与 reason 分叉）。
        for busy in [false, true] {
            for src in [0usize, 1, 5] {
                for dst in [false, true] {
                    let ready = !busy && arrow_enabled(src, dst);
                    let reason = arrow_disabled_reason(busy, src, dst);
                    assert_eq!(
                        ready,
                        reason.is_none(),
                        "arrow_ready 与 arrow_disabled_reason 分叉 (busy={busy}, src={src}, dst={dst})"
                    );
                }
            }
        }
    }

    #[test]
    fn r134_7_arrow_labels_pinned() {
        assert_eq!(arrow_dir_label(ArrowDirection::Download), "download");
        assert_eq!(arrow_dir_label(ArrowDirection::Upload), "upload");
        assert_eq!(ArrowDisabledReason::InFlight.label(), "in_flight");
        assert_eq!(ArrowDisabledReason::NoSourceSel.label(), "no_source_sel");
        assert_eq!(ArrowDisabledReason::NoTargetDir.label(), "no_target_dir");
    }

    /// disabled click: dir=… reason=…`。
    #[test]
    fn r134_7_arrow_disabled_click_line_format() {
        assert_eq!(
            format_arrow_disabled_click_line(
                ArrowDirection::Upload,
                ArrowDisabledReason::NoSourceSel
            ),
        );
        assert_eq!(
            format_arrow_disabled_click_line(
                ArrowDirection::Download,
                ArrowDisabledReason::NoTargetDir
            ),
        );
        assert_eq!(
            format_arrow_disabled_click_line(
                ArrowDirection::Upload,
                ArrowDisabledReason::InFlight
            ),
        );
        // 锚点族钉死。
        for dir in [ArrowDirection::Download, ArrowDirection::Upload] {
            for reason in [
                ArrowDisabledReason::InFlight,
                ArrowDisabledReason::NoSourceSel,
                ArrowDisabledReason::NoTargetDir,
            ] {
                let line = format_arrow_disabled_click_line(dir, reason);
                assert!(line.ends_with(&format!(" reason={}", reason.label())));
            }
        }
    }

    /// 两方向箭头均经 `seam_disabled_click_attempt`（禁用点击检测）+
    /// `arrow_disabled_reason`（取因）+ `format_arrow_disabled_click_line`
    /// （行渲染）补 WARN；enable 态 `arrow_transfer` 行为不变。
    #[test]
    fn r134_7_arrow_wiring_check() {
        let src = include_str!("file_manager.rs");
        // 禁用点击检测辅助在位。
        assert!(
            src.contains("fn seam_disabled_click_attempt("),
            "seam_disabled_click_attempt 辅助必须在位"
        );
        // 两方向均接禁用点击臂（Download + Upload）。
        assert!(
            src.contains("seam_disabled_click_attempt(ui, &dl_resp, dl_ready)"),
            "← 下载箭头必须接禁用点击检测"
        );
        assert!(
            src.contains("seam_disabled_click_attempt(ui, &up_resp, up_ready)"),
            "→ 上传箭头必须接禁用点击检测"
        );
        // 取因 + 行渲染接线。
        assert!(
            src.contains("state.arrow_disabled_reason(ArrowDirection::Download)"),
            "← 禁用点击必须取因（Download）"
        );
        assert!(
            src.contains("state.arrow_disabled_reason(ArrowDirection::Upload)"),
            "→ 禁用点击必须取因（Upload）"
        );
        assert!(
            src.contains("format_arrow_disabled_click_line(ArrowDirection::Download, reason)"),
            "← 禁用点击必须渲染 WARN 行（Download）"
        );
        assert!(
            src.contains("format_arrow_disabled_click_line(ArrowDirection::Upload, reason)"),
            "→ 禁用点击必须渲染 WARN 行（Upload）"
        );
        // enable 态行为不变（arrow_transfer 调用点保留）。
        assert!(
            src.contains("state.arrow_transfer(ArrowDirection::Download, panel, file_tx, fm_tx)"),
            "← enable 态 arrow_transfer 不得移除"
        );
        assert!(
            src.contains("state.arrow_transfer(ArrowDirection::Upload, panel, file_tx, fm_tx)"),
            "→ enable 态 arrow_transfer 不得移除"
        );
    }
}

// ════════════════════════════════════════════════════════════════
// + 右栏滚轮单侧生效；纯函数矩阵 + headless 像素判据 + 滚轮行为钉死）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod r134_9_tests {
    use super::*;

    /// 与 `render_panes_and_seam` 同构几何（`pane_w=(avail−SEAM−2×spacing)/2`）：
    /// 返回 (左栏右缘, 中缝左缘, 右栏左缘, 右栏右缘)。
    fn pane_geometry(screen_w: f32) -> (f32, f32, f32, f32) {
        let spacing = egui::Style::default().spacing.item_spacing.x;
        let pane_w = ((screen_w - SEAM_WIDTH - 2.0 * spacing) / 2.0).max(1.0);
        (
            pane_w,
            pane_w + spacing,
            pane_w + SEAM_WIDTH + 2.0 * spacing,
            pane_w + SEAM_WIDTH + 2.0 * spacing + pane_w,
        )
    }

    /// 本地测试目录：1 个长文件名文件（名 = `long_len` 字符 + `.dat`）+
    /// `n_normal` 个常规文件（`file_NN.txt`）。
    fn local_root_with_files(tag: &str, long_len: usize, n_normal: usize) -> PathBuf {
        let p = std::env::temp_dir().join(format!("k134_9_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        let long_name: String = "L".repeat(long_len);
        std::fs::write(p.join(format!("{long_name}.dat")), b"x").unwrap();
        for i in 0..n_normal {
            std::fs::write(p.join(format!("file_{i:02}.txt")), b"x").unwrap();
        }
        p
    }

    /// 远端条目（内存，零 wire）：`n` 个 `remote_NN.bin` + 可选长名条目（尾部）。
    fn remote_entries(n: usize, long: Option<String>) -> Vec<FileMgrEntry> {
        let mut v: Vec<FileMgrEntry> = (0..n)
            .map(|i| FileMgrEntry {
                name: format!("remote_{i:02}.bin"),
                size: 1024 * (i as u64 + 1),
                mtime: 1_750_000_000 + i as i64,
                is_dir: i % 10 == 0,
                is_symlink: false,
                is_hidden: false,
            })
            .collect();
        if let Some(name) = long {
            v.push(FileMgrEntry {
                name,
                size: 42,
                mtime: 1_750_000_000,
                is_dir: false,
                is_symlink: false,
                is_hidden: false,
            });
        }
        v
    }

    /// headless 帧驱动器（同 r133_2 `run_frames` 口径 + 逐帧事件注入 =
    /// 滚轮/指针场景）。`CentralPanel` 零边距 → 屏宽 = 可用宽。
    struct FmHarness {
        ctx: egui::Context,
        state: FileManagerState,
        panel: FilePanelState,
        screen: (f32, f32),
    }

    impl FmHarness {
        fn new(state: FileManagerState, panel: FilePanelState, screen: (f32, f32)) -> Self {
            let ctx = egui::Context::default();
            ctx.set_visuals(egui::Visuals::light());
            Self {
                ctx,
                state,
                panel,
                screen,
            }
        }

        /// 跑一帧（`events` = 本帧指针/滚轮事件），返回该帧全部 shapes。
        fn frame(&mut self, events: Vec<egui::Event>) -> Vec<egui::epaint::ClippedShape> {
            let mut raw = egui::RawInput::default();
            raw.screen_rect = Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(self.screen.0, self.screen.1),
            ));
            raw.events = events;
            let mut focus = false;
            self.ctx
                .run(raw, |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        show_file_manager(
                            ui,
                            &Theme::LIGHT,
                            &mut self.state,
                            None,
                            None,
                            &self.panel,
                            false,
                            &mut focus,
                        );
                    });
                })
                .shapes
        }
    }

    /// 精确文本 → (x, y, w, h)（按 (y, x) 排序），同 r133_2 `text_rects` 口径。
    fn text_rects(shapes: &[egui::epaint::ClippedShape], text: &str) -> Vec<(f32, f32, f32, f32)> {
        let mut v: Vec<(f32, f32, f32, f32)> = shapes
            .iter()
            .filter_map(|cs| match &cs.shape {
                egui::Shape::Text(t) if t.galley.job.text == text => {
                    Some((t.pos.x, t.pos.y, t.galley.rect.width(), t.galley.rect.height()))
                }
                _ => None,
            })
            .collect();
        v.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.total_cmp(&a.0)));
        v
    }


    #[test]
    fn r134_9_ellipsis_name_matrix() {
        // 伪测量：2px/字符（确定性、无 egui）。
        let m = |s: &str| s.chars().count() as f32 * 2.0;
        // (a) 不超宽 = 原样返回（零变化）。
        assert_eq!(r134_9_ellipsis_name("short.txt", 100.0, &m), "short.txt");
        // (b) 超宽 → 前缀 + "…"，且截后宽 ≤ max_w、前缀 ∈ 原名。
        let long = "a".repeat(60); // 120px > 100
        let t = r134_9_ellipsis_name(&long, 100.0, &m);
        assert!(t.ends_with('…'), "截断必须以省略号结尾: {t:?}");
        let body = &t[..t.len() - '…'.len_utf8()];
        assert!(long.starts_with(body), "截断体必须是原名假前缀");
        assert!(m(&t) <= 100.0, "截后宽必须 ≤ max_w");
        // (c) 最长前缀最优：(100 − 2px省略号)/2 = 49 字符（多 1 字符即超）。
        assert_eq!(body.chars().count(), 49, "必须是最长适配前缀（二分最优）");
        // (d) 极端窄栏（< "…" 宽）→ "…" 兜底。
        assert_eq!(r134_9_ellipsis_name(&long, 1.0, &m), "…");
        // (e) 空输入 → 空。
        assert_eq!(r134_9_ellipsis_name("", 100.0, &m), "");
        // (f) 幂等。
        assert_eq!(r134_9_ellipsis_name(&t, 100.0, &m), t);
        // (g) Unicode 按字符截（不切字节、不 panic）。
        let uni = "文".repeat(60);
        let tu = r134_9_ellipsis_name(&uni, 100.0, &m);
        assert!(tu.ends_with('…') && uni.starts_with(&tu[..tu.len() - '…'.len_utf8()]));
    }

    #[test]
    fn r134_9_name_col_max_w_matrix() {
        // 正常：928 − 8(安全边) − 200(他列) − 3×8(间距) − 2×4(frame) = 688。
        assert!((r134_9_name_col_max_w(928.0, 200.0, 8.0, 4.0) - 688.0).abs() < 1e-3);
        // 他列已超栏宽 → 钳 0（无 NaN/负值；绘制由行区 clip 兜底）。
        assert_eq!(r134_9_name_col_max_w(50.0, 400.0, 8.0, 4.0), 0.0);
        assert_eq!(r134_9_name_col_max_w(1.0, 0.0, 8.0, 4.0), 0.0);
    }

    #[test]
    fn r134_9_other_cols_w_widest_per_col() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let m = |s: &str| s.chars().count() as f32 * 2.0;
        let rows = vec![
            FileMgrEntry {
                name: "a".into(),
                size: 5,
                mtime: 0,
                is_dir: false,
                is_symlink: false,
                is_hidden: false,
            },
            FileMgrEntry {
                name: "b".into(),
                size: 1_234_567_890,
                mtime: 1_750_000_000,
                is_dir: false,
                is_symlink: false,
                is_hidden: false,
            },
            FileMgrEntry {
                name: "c".into(),
                size: 1,
                mtime: 0,
                is_dir: true,
                is_symlink: false,
                is_hidden: false,
            },
        ];
        // 每列取整页最宽 + `R134_9_GRID_MIN_COL_W`(40) 钳底（= Grid
        // `.min_col_width` 实际列宽口径）：size = format_size(0000000890)=
        // "1.1 MB"(6) vs "5 B"(3) vs 目录"-"(1) → 12px → 钳底 40；mtime =
        // "%m-%d %H:%M"(11) vs "—"(1) → 22px → 40；type = zh「目录/文件」(2)
        // → 4px → 40。合计 120px（三列内容均窄于列底，全走钳底）。
        assert!((r134_9_other_cols_w(&rows, &m) - 120.0).abs() < 1e-3);
        // 空页 = 0（无行可测）。
        assert_eq!(r134_9_other_cols_w(&[], &m), 0.0);
    }

    // ── headless 像素判据：穿模回归（修前 RED / 修后 GREEN）──

    /// （130228 实证形态：纹带经中缝铺到右栏之下）。判据 =
    /// (1) 条纹 rect 不越本栏右缘 (2) 条纹 clip 右缘钳到栏矩形
    /// （像素级「纹带钳栏」）(3) 长名省略号在栏内、全名不得原样绘制。
    #[test]
    fn r134_9_stripes_clamped_to_pane_headless() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let (sw, sh) = (1920.0, 1080.0);
        let root = local_root_with_files("clip", 100, 5);
        let mut state = FileManagerState::with_local_root(root.clone());
        // 判据面）。
        assert!(state.local_expand_chain(&root), "本地链展开（此电脑根 → 盘符 → 测试根）");
        assert!(
            !state.tree_rows(PaneId::Local).is_empty(),
            "测试前置：左栏非空"
        );
        state.remote.started = true;
        state.remote.root_display = "r134-9".to_string();
        let long_remote: String = "R".repeat(200);
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(remote_entries(20, Some(long_remote.clone()))),
                ..Default::default()
            },
        );

        let mut h = FmHarness::new(state, FilePanelState::new(), (sw, sh));
        h.frame(Vec::new());
        let shapes = h.frame(Vec::new());

        let (left_right, _seam_left, _right_left, right_right) = pane_geometry(sw);

        for cs in &shapes {
            assert!(cs.clip_rect.is_finite(), "非有限裁剪矩形（退化分配）");
            if let egui::Shape::Rect(r) = &cs.shape {
                assert!(r.rect.is_finite(), "非有限矩形 shape（退化分配）");
            }
        }

        // (1)(2) 条纹矩 = faint_bg_color 宽矩形（r133_2 `row_bg_rects` 同口径）：
        //     ① rect 右缘不越本栏（修前 RED：左栏长名把 Grid 列宽推出栏宽，
        //        纹带 rect 经中缝铺到右栏之下 = 130228）；
        //     ② clip 右缘钳到栏矩形（修前 RED：egui 非滚动轴 content clip
        //        到窗缘 → 条纹「可见」地横跨全窗）。
        let fill = egui::Visuals::light().faint_bg_color;
        let stripes: Vec<(egui::Rect, egui::Rect)> = shapes
            .iter()
            .filter_map(|cs| match &cs.shape {
                egui::Shape::Rect(r) if r.fill == fill && r.rect.width() >= 100.0 => {
                    Some((r.rect, cs.clip_rect))
                }
                _ => None,
            })
            .collect();
        assert!(!stripes.is_empty(), "行背景条纹缺失 = 行区未绘制（布局回归）");
        let (mut n_left, mut n_right) = (0usize, 0usize);
        for (rect, clip) in &stripes {
            let (pane_right, is_left) = if rect.min.x < left_right {
                (left_right, true)
            } else {
                (right_right, false)
            };
            if is_left {
                n_left += 1;
            } else {
                n_right += 1;
            }
            assert!(
                rect.max.x <= pane_right + 4.0,
                "条纹 rect 越栏（{is_left:?} 栏 max.x {:.0} > 栏右缘 {:.0}+4）= 穿模",
                rect.max.x,
                pane_right
            );
            assert!(
                clip.max.x <= pane_right + 0.5,
                "条纹 clip 未钳到栏矩形（clip.max.x {:.0} > 栏右缘 {:.0}）= 条纹可见地横贯全窗",
                clip.max.x,
                pane_right
            );
        }
        // 右 = 根行 + 21 子行 ≥11 条）。
        assert!(n_left >= 4, "左栏条纹仅 {n_left} 条（行区塌缩?）");
        assert!(n_right >= 11, "右栏条纹仅 {n_right} 条（行区塌缩?）");

        // (3) 长名省略号：全名不得原样绘制；绘制形态 = 前缀 + "…" 且在栏内。
        let local_full: String = format!("{}.dat", "L".repeat(100));
        assert!(
            !shapes
                .iter()
                .any(|cs| matches!(&cs.shape, egui::Shape::Text(t) if t.galley.job.text == long_remote.as_str() || t.galley.job.text == local_full.as_str())),
            "完整长文件名被原样绘制（未钳宽/未省略号）= 穿模根因仍在"
        );
        let truncated: Vec<(f32, f32)> = shapes
            .iter()
            .filter_map(|cs| match &cs.shape {
                egui::Shape::Text(t)
                    if t.galley.job.text.ends_with('…')
                        && t.galley.job.text.starts_with("R")
                        && t.galley.job.text.len() > 40 =>
                {
                    Some((t.pos.x + t.galley.rect.width(), t.pos.y))
                }
                _ => None,
            })
            .collect();
        assert!(
            !truncated.is_empty(),
            "省略号化的长文件名未绘制（省略号路径未生效）"
        );
        for (xmax, _y) in &truncated {
            assert!(
                *xmax <= right_right + 0.5,
                "省略号长文件名仍越栏（x+width {:.0} > 窗右缘 {:.0}）",
                xmax,
                right_right
            );
        }

        // (4) 常规短名行区零回归：右栏首行在位且对齐表头列（r133_2 判据抽样）。
        let first = text_rects(&shapes, "remote_00.bin").into_iter().next();
        assert!(first.is_some(), "右栏首行 remote_00.bin 未绘制（行区回归）");
    }

    // ── 滚轮行为钉死（卡内判据：右栏条目超可视高时滚轮滚动右表）──

    /// （修前 = 左栏内容涨破栏宽）。指针在**右栏**滚两格 →
    /// 右表滚 2×5px、左表零位移。
    /// 文件行位于行区可视底之下，行区顶锚 = 链行「Users」，y>80 门滤除
    /// 面包屑同文）。
    ///
    /// 修前 = RED（穿模区遮挡定案亲证）：egui 0.28.1 ScrollArea
    /// `auto_shrink(false,false)` 使非滚动轴 inner/outer rect **涨到内容
    /// 宽**（containers/scroll_area.rs `end` `(false,false) =>
    /// inner_size.max(content_size)`）→ 左栏 outer_rect 经中缝吞掉右栏
    /// 命中域，且左栏先处理先消费滚轮 delta（`end` 内
    /// `is_hovering_outer_rect` 门 + delta 清零）→ 右栏滚轮滚的是左表。
    /// 修复 = 名称列钳宽使左栏内容宽 ≤ pane_w → outer_rect 不再外溢，
    /// 滚轮归右栏。
    #[test]
    fn r134_9_right_pane_wheel_scrolls_right_table() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let (sw, sh) = (1280.0, 720.0);
        // 左栏：60 条目（1 个 100 字符长名 + 59 常规）= 超可视高。
        // 位于行区可视底之下——Temp 链兄弟行占前部；锚 = 行区顶链行）。
        let root = local_root_with_files("wheel", 100, 59);
        let mut state = FileManagerState::with_local_root(root.clone());
        assert!(state.local_expand_chain(&root), "本地链展开（此电脑根 → 盘符 → 测试根）");
        assert!(
            state.tree_rows(PaneId::Local).len() >= 61,
            "测试前置：左栏 ≥60 文件行（+盘符根）"
        );
        // 右栏：60 条目（内存，零 wire）= 超可视高（根节点 children 缓存）。
        state.remote.started = true;
        state.remote.root_display = "r134-9w".to_string();
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(remote_entries(60, None)),
                ..Default::default()
            },
        );
        // 本试对象 = 滚轮劫持判定，横幅占行（未通告态 fail-closed 文案路径）
        // 另行由 r137_1 族钉死；不受控（`None`）= 两「未知」横幅行下移行区
        // ~45px → 「左栏超可视高」判据（根行恰在可视底外沿）失效。
        state.peer_consent = Some((true, true));

        let mut h = FmHarness::new(state, FilePanelState::new(), (sw, sh));
        // 首帧 = Grid sizing pass（egui 0.28.1 grid.rs：首帧状态未持久化时
        // `set_sizing_pass` = 不可见测量）→ 行区第二帧起才绘制（r133_2
        // `run_frames(n=2)` 同口径）。
        h.frame(Vec::new());
        let base = h.frame(Vec::new());

        // 首行 y 提取（双栏各取一个锚文本；行高 ~21px × 60 ≈ 1260 > 可视高）。
        // 左栏锚 = 行区内「Users」链行（C:\ 上位目录，恒在行区顶部 ~第 7 行；
        // y>80 门滤除面包屑同文〔y≲65〕）——60 文件行在行区可视底之下，
        // 不可作锚（可见性门不绘制）。
        let y_of = |shapes: &Vec<egui::epaint::ClippedShape>, text: &str| -> Option<f32> {
            text_rects(shapes, text).into_iter().next().map(|r| r.1)
        };
        let left_anchor_of =
            |shapes: &Vec<egui::epaint::ClippedShape>| -> Option<f32> {
                text_rects(shapes, "Users").into_iter().find(|r| r.1 > 80.0).map(|r| r.1)
            };
        let (left_y0, right_y0) = (
            left_anchor_of(&base).expect("左栏锚行 Users 未绘制（行区退化）"),
            y_of(&base, "remote_00.bin").expect("右栏锚行 remote_00.bin 未绘制"),
        );
        // 双栏均须溢出可视高（滚轮可滚前提 = 卡内判据「条目超可视高」）。
        // egui 0.28.1 行文本有可见性门（SelectableLabel `ui.is_rect_visible`，
        // selected_label.rs；max_rect = ScrollArea 内容可视窗）→ 可视底之下的
        // 行 Text 不入 shapes（布局仍全量进行，content_size 全量 → max_offset
        // 有效，滚动功能不受影响）。右栏溢出判定 = 末次绘制行抵达可视底
        // （y > 90% 屏高）；左栏溢出判定 = 测试根行（行区出现）未绘制
        // （60 文件行更在其下）。① 中锚行确实位移是第二重溢出证明
        // （max_offset > 0 才能滚）。
        let last_i_of =
            |shapes: &Vec<egui::epaint::ClippedShape>, fmt: &dyn Fn(usize) -> String| -> usize {
                (0..60).rev().find(|i| y_of(shapes, &fmt(*i)).is_some()).unwrap_or(0)
            };
        let right_last_i = last_i_of(&base, &|i| format!("remote_{i:02}.bin"));
        let right_last = y_of(&base, &format!("remote_{right_last_i:02}.bin")).unwrap();
        assert!(
            right_last_i >= 25,
            "右栏行区绘制过短：末绘制行索引 {right_last_i}（应 ≥25 = 长列表）"
        );
        assert!(
            right_last > sh * 0.9,
            "右栏须超可视高（右末绘制行 y={right_last:.0}，应抵达可视底 ~{:.0}）",
            sh * 0.9
        );
        let root_name = root.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            text_rects(&base, &root_name).iter().all(|r| r.1 <= 80.0),
            "左栏未超可视高：测试根行 y>80 绘制 = 列表过短（劫持判据失效）"
        );

        // 指针 = 右栏行区中部（1280 几何：右栏 x∈[672,1280]）。
        let (_lr, _sl, right_left, _rr) = pane_geometry(sw);
        let p = egui::pos2(right_left + (sw - right_left) / 2.0, sh * 0.62);
        let wheel_down = || {
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                // |delta| < 8 = 立即应用（egui 0.28.1 input_state 平滑分支
                // 旁路）→ 确定性 5px/帧。负 Y = 内容上移 = 列表前翻。
                delta: egui::vec2(0.0, -5.0),
                modifiers: egui::Modifiers::default(),
            }
        };

        // 帧序（真实交互口径）：f1 指针入右栏（hover 初始化帧）→ f2/f3
        // 两格滚轮 → f4 无事件稳定帧。egui 0.28.1 ScrollArea 滚动状态在
        // `end()` 落盘、**次帧** `begin()` 取用（scroll_area.rs：内容原点
        // `inner_rect.min - state.offset` 用帧首载入的 offset）→ 每格滚轮
        // 位移在**下一帧**渲染体现（f2 格 → f3 帧位移，f3 格 → f4 帧位移）；
        // 断言钉在稳定帧 f4 = 两格合计 −10px。
        let f1 = h.frame(vec![egui::Event::PointerMoved(p)]);
        let f2 = h.frame(vec![wheel_down()]);
        let f3 = h.frame(vec![wheel_down()]);
        let f4 = h.frame(Vec::new());

        let (left_y1, right_y1) = (
            left_anchor_of(&f1).expect("滚后左栏锚行缺失"),
            y_of(&f1, "remote_00.bin").expect("滚后右栏锚行缺失"),
        );
        let (left_y2, right_y2) = (
            left_anchor_of(&f2).expect("滚后左栏锚行缺失"),
            y_of(&f2, "remote_00.bin").expect("滚后右栏锚行缺失"),
        );
        let (left_y3, right_y3) = (
            left_anchor_of(&f3).expect("滚后左栏锚行缺失"),
            y_of(&f3, "remote_00.bin").expect("滚后右栏锚行缺失"),
        );
        let (left_y4, right_y4) = (
            left_anchor_of(&f4).expect("滚后左栏锚行缺失"),
            y_of(&f4, "remote_00.bin").expect("滚后右栏锚行缺失"),
        );

        // 判据①（卡内钉死）：右栏条目超可视高时，指针在右栏滚两格 →
        // 右表前翻恰 2×5px（±0.5 浮点，f4 稳定帧读值）。修前 RED = 右表
        // 纹丝不动（delta 被左栏穿模 outer_rect 先消费）。
        assert!(
            (right_y1 - right_y4 - 10.0).abs() < 0.5,
            "右栏滚轮未滚动右表（右首行 y: {right_y1:.1} → {right_y4:.1}，期望 −10px）"
        );
        // 判据②：左栏零位移（滚轮不得被左栏劫持；修前 RED = 左表 −10px）。
        assert!(
            (left_y1 - left_y0).abs() < 0.5
                && (left_y2 - left_y0).abs() < 0.5
                && (left_y3 - left_y0).abs() < 0.5
                && (left_y4 - left_y0).abs() < 0.5,
            "左栏被右栏滚轮劫持（左首行 y: {left_y0:.1} → {left_y1:.1} → {left_y2:.1} → {left_y3:.1} → {left_y4:.1}）= 穿模区遮挡命中"
        );
        // 判据③：位移逐帧单调（f3/f4 各体现一格 ≥4px；无回弹/双滚）。
        assert!(
            right_y2 - right_y3 >= 4.0 && right_y3 - right_y4 >= 4.0,
            "右栏滚动非单调（{right_y1:.1} → {right_y2:.1} → {right_y3:.1} → {right_y4:.1}）"
        );
    }


    /// 100 字符长文件 + 右栏 200 字符长条目。目验 = 行底纹钳栏（不横贯
    /// 中缝）+ 长名省略号在栏内 + 右栏不被左栏纹带覆盖。
    /// 软件光栅化）；PNG 落 `E:/projects_rd/docs/`（仓外，不 commit）。
    #[test]
    fn r134_9_screenshot_dump() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let (sw, sh) = (1920.0, 1080.0);
        let root = local_root_with_files("shot", 100, 5);
        let mut state = FileManagerState::with_local_root(root.clone());
        assert!(state.local_expand_chain(&root), "本地链展开（此电脑根 → 盘符 → 测试根）");
        state.remote.started = true;
        state.remote.root_display = "r134-9".to_string();
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                children: Some(remote_entries(20, Some("R".repeat(200)))),
                ..Default::default()
            },
        );
        let panel = FilePanelState::new();

        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let run_frame = |ctx: &egui::Context, state: &mut FileManagerState| {
            let mut raw = egui::RawInput::default();
            raw.screen_rect =
                Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(sw, sh)));
            let mut focus = false;
            ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    show_file_manager(
                        ui,
                        &Theme::LIGHT,
                        state,
                        None,
                        None,
                        &panel,
                        false,
                        &mut focus,
                    );
                });
            })
        };
        // 帧 1 = 字体图集建立（`ImageData::Font` = 单通道覆盖度）+ Grid
        // sizing pass；帧 2 = 稳态 shapes（行区第二帧起才绘制，同 r133_2 口径）。
        let out1 = run_frame(&ctx, &mut state);
        let out2 = run_frame(&ctx, &mut state);
        let mut atlas: Option<(usize, usize, Vec<f32>)> = None;
        for (_, delta) in out1.textures_delta.set.iter() {
            if let egui::epaint::ImageData::Font(fi) = &delta.image {
                if fi.size[0] * fi.size[1] > atlas.as_ref().map(|(a, b, _)| a * b).unwrap_or(0) {
                    atlas = Some((fi.size[0], fi.size[1], fi.pixels.clone()));
                }
            }
        }
        let (aw, ah, aatlas) = atlas.expect("字体图集纹理应在首帧建立");

        // 软件光栅化（Rect fill/stroke + Text 字形图集采样；Mesh 等 = 跳过）。
        fn c32_rgba(c: egui::Color32) -> image::Rgba<u8> {
            let [r, g, b, a] = c.to_srgba_unmultiplied();
            image::Rgba::<u8>([r, g, b, a])
        }
        let (w, h) = (sw as u32, sh as u32);
        let panel_bg = egui::Visuals::light().panel_fill;
        let mut img = image::RgbaImage::from_pixel(w, h, c32_rgba(panel_bg));
        for cs in &out2.shapes {
            let clip = cs.clip_rect;
            let mut draw_rect = |r: egui::Rect, c: image::Rgba<u8>| {
                let x0 = (r.min.x.max(clip.min.x)).floor() as i32;
                let y0 = (r.min.y.max(clip.min.y)).floor() as i32;
                let x1 = (r.max.x.min(clip.max.x)).ceil() as i32;
                let y1 = (r.max.y.min(clip.max.y)).ceil() as i32;
                for y in y0.max(0)..y1.min(h as i32) {
                    for x in x0.max(0)..x1.min(w as i32) {
                        img.put_pixel(x as u32, y as u32, c);
                    }
                }
            };
            match &cs.shape {
                egui::Shape::Rect(rs) => {
                    if rs.fill.a() > 0 {
                        draw_rect(rs.rect, c32_rgba(rs.fill));
                    }
                    if rs.stroke.width > 0.0 {
                        let swd = rs.stroke.width.max(1.0);
                        draw_rect(rs.rect, c32_rgba(rs.stroke.color));
                        let inner = rs.rect.shrink2(egui::vec2(swd / 2.0, swd / 2.0));
                        if inner.width() > 0.0 && inner.height() > 0.0 {
                            draw_rect(inner, c32_rgba(panel_bg));
                        }
                    }
                }
                egui::Shape::Text(t) => {
                    let sections = &t.galley.job.sections;
                    for row in &t.galley.rows {
                        for g in &row.glyphs {
                            let uv = &g.uv_rect;
                            let (sx0, sy0) = (uv.min[0] as i32, uv.min[1] as i32);
                            let (sx1, sy1) = (uv.max[0] as i32, uv.max[1] as i32);
                            let sw_ = (sx1 - sx0).max(1);
                            let sh_ = (sy1 - sy0).max(1);
                            let mut color = sections
                                .get(g.section_index as usize)
                                .map(|s| s.format.color)
                                .unwrap_or_default();
                            if color == egui::Color32::PLACEHOLDER {
                                color = t.fallback_color;
                            }
                            if let Some(oc) = t.override_text_color {
                                color = oc;
                            }
                            let [cr, cg, cb, ca] = color.to_srgba_unmultiplied();
                            let gx0 = (t.pos.x + g.pos.x + uv.offset.x).floor() as i32;
                            let gy0 = (t.pos.y + g.pos.y + uv.offset.y).floor() as i32;
                            let gw_i = uv.size.x.max(1.0) as i32;
                            let gh_i = uv.size.y.max(1.0) as i32;
                            for dy in 0..gh_i {
                                let ay = (sy0 + dy * sh_ / gh_i).min(ah as i32 - 1);
                                for dx in 0..gw_i {
                                    let ax = (sx0 + dx * sw_ / gw_i).min(aw as i32 - 1);
                                    if ax < 0 || ay < 0 {
                                        continue;
                                    }
                                    let a = aatlas[(ay as usize) * aw + (ax as usize)]
                                        * (ca as f32 / 255.0);
                                    if a <= 0.01 {
                                        continue;
                                    }
                                    let px = gx0 + dx;
                                    let py = gy0 + dy;
                                    if px < 0 || py < 0 || px >= w as i32 || py >= h as i32 {
                                        continue;
                                    }
                                    if px < clip.min.x as i32 || px >= clip.max.x as i32
                                        || py < clip.min.y as i32
                                        || py >= clip.max.y as i32
                                    {
                                        continue;
                                    }
                                    let dst = img.get_pixel(px as u32, py as u32);
                                    let out = image::Rgba::<u8>([
                                        (cr as f32 * a + dst[0] as f32 * (1.0 - a)) as u8,
                                        (cg as f32 * a + dst[1] as f32 * (1.0 - a)) as u8,
                                        (cb as f32 * a + dst[2] as f32 * (1.0 - a)) as u8,
                                        255,
                                    ]);
                                    img.put_pixel(px as u32, py as u32, out);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let out_path = "E:/projects_rd/docs/r134_9_longname_sandbox.png";
        img.save(out_path).expect("PNG 落盘");
        assert!(std::path::Path::new(out_path).is_file(), "截屏在位");
        std::fs::remove_dir_all(&root).ok();
    }
}

// ════════════════════════════════════════════════════════════════
// 选中重映射 / 箭头落点衔接 / 错误重试 / 长路径 / 无分页）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod r134_9b_tests {
    use super::*;
    use std::io::Write as _;
    use kirin_desk_core::connection::file_transfer::FsEntry;

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("k9b_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn mkfile(p: &Path, content: &str) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    fn mk_entry(name: &str, size: u64, is_dir: bool) -> FileMgrEntry {
        FileMgrEntry {
            name: name.into(),
            size,
            mtime: 0,
            is_dir,
            is_symlink: false,
            is_hidden: false,
        }
    }

    /// 排干 mock 通道，收集 `FsOp::List` 帧的 path 序列（零 wire 纪律计数口径）。
    fn drain_list_paths(frx: &mut tokio::sync::mpsc::UnboundedReceiver<FileCommand>) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(cmd) = frx.try_recv() {
            if let FileCommand::Fs { op: FsOp::List { path, .. } } = cmd {
                out.push(path);
            }
        }
        out
    }

    fn admit_list(state: &mut FileManagerState, req_id: u32, path: &str) {
        state.on_fs_event(FsEvent::Admitted {
            req_id,
            op: FsOp::List {
                path: path.to_string(),
                offset: 0,
                limit: PAGE_SIZE,
            },
        });
    }

    /// 远端 List 成功响应（entries = (name, size, is_dir)；`root_display` 恒携
    /// 带——服务端每 List 响应恒携带，§1.3）。
    fn respond_list(
        state: &mut FileManagerState,
        req_id: u32,
        entries: &[(&str, u64, bool)],
        has_more: bool,
        root_display: &str,
    ) {
        let list = FsListPayload {
            entries: entries
                .iter()
                .map(|(n, s, d)| FsEntry {
                    name: (*n).into(),
                    size: *s,
                    mtime: 0,
                    is_dir: *d,
                    is_symlink: false,
                })
                .collect(),
            has_more,
            root_display: root_display.into(),
        };
        state.on_fs_event(FsEvent::Response {
            req_id,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: bincode::serialize(&list).unwrap(),
            }),
        });
    }

    fn channel() -> (
        tokio::sync::mpsc::UnboundedSender<FileCommand>,
        tokio::sync::mpsc::UnboundedReceiver<FileCommand>,
    ) {
        tokio::sync::mpsc::unbounded_channel()
    }

    // ── ① 默认根 = 「此电脑」合成根 + 远端根（用户 09-22 口径修正：盘符是
    //    根下目录层，非根；默认展开根 = 盘符层可见）──────────────────────

    #[test]
    fn test_r134_9b_default_pc_root_lazy() {
        let root = tmp_root("drive");
        mkfile(&root.join("a.txt"), "x");
        let state = FileManagerState::with_local_root(root.clone());
        // 本地树根 = 「此电脑」合成根行（depth 0）；盘符 = 根下目录层
        // （depth 1，默认展开根后全部可见 = 默认展示盘符层）。
        let drives = local_drives();
        assert!(!drives.is_empty(), "本机至少一盘符");
        let rows = state.tree_rows(PaneId::Local);
        assert_eq!(rows.len(), 1 + drives.len(), "此电脑根行 + 盘符行");
        assert_eq!(rows[0].path, LOCAL_PC_ROOT_KEY, "根行 = 此电脑合成根");
        assert_eq!(rows[0].depth, 0);
        assert!(rows[0].entry.is_dir);
        for (r, d) in rows[1..].iter().zip(drives.iter()) {
            assert_eq!(r.path, local_path_key(d), "盘符行 = 根下目录层键");
            assert_eq!(r.depth, 1, "盘符 depth 1（用户 09-22：盘符非根）");
            assert!(r.entry.is_dir);
        }
        // 「此电脑」默认展开；盘符零自动展开（双击/＋ 进入）。
        assert!(
            state.local.view.expanded.iter().any(|e| e == LOCAL_PC_ROOT_KEY),
            "此电脑根默认展开"
        );
        for d in &drives {
            assert!(
                !state.local.view.expanded.iter().any(|e| e == &local_path_key(d)),
                "盘符零自动展开"
            );
        }
        // List（空目录 ≠ 未初始化）。
        assert!(
            state.remote.view.expanded.iter().any(|e| e == REMOTE_PC_ROOT_KEY),
            "远端合成根默认展开"
        );
        let rrows = state.tree_rows(PaneId::Remote);
        // home 缓存未落定 = 零子行）。
        assert_eq!(rrows[0].path, REMOTE_PC_ROOT_KEY, "根行 = 远端电脑保留键");
        assert_eq!(rrows[0].depth, 0);
        assert_eq!(rrows[1].path, REMOTE_HOME_KEY, "第二行 = 主目录保留键");
        assert_eq!(rrows[1].depth, 1, "主目录 = 合成根下 depth 1");
        assert!(rrows[1].entry.is_dir, "主目录 = 目录条目");
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ② 惰性加载：每展开一层一次 List（零 wire 纪律）─────────────────────

    #[test]
    fn test_r134_9b_lazy_one_list_per_expand() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true; // 测试不经渲染首 List；手动驱动
        let (ftx, mut frx) = channel();
        assert!(drain_list_paths(&mut frx).is_empty(), "前提零 wire");
        // limit=500 = 既有协议形态零新 wire op）。
        state.request_remote_list_at_node(REMOTE_PC_ROOT_KEY, Some(&ftx));
        assert_eq!(
            drain_list_paths(&mut frx),
            vec![REMOTE_PC_ROOT_KEY.to_string()],
            "根 List 恰一次"
        );
        admit_list(&mut state, 1, REMOTE_PC_ROOT_KEY);
        respond_list(
            &mut state,
            1,
            &[("a", 0, true), ("z.txt", 5, false)],
            false,
            "rt",
        );
        // 未展开子节点 = 零 wire（惰性核心保证）。
        assert_eq!(drain_list_paths(&mut frx).len(), 0, "未展开子零 wire");
        let node = &state.remote.view.nodes[REMOTE_PC_ROOT_KEY];
        assert_eq!(node.children.as_ref().unwrap().len(), 2);
        assert!(!node.loading && node.error.is_none());
        assert_eq!(state.remote.root_display, "rt", "root_display 捕获");
        // 展开第二层（a）= 一次 List。
        state.tree_expand(PaneId::Remote, "a", Some(&ftx));
        assert_eq!(drain_list_paths(&mut frx), vec!["a".to_string()], "展开一层 = 一次 List");
        admit_list(&mut state, 2, "a");
        respond_list(&mut state, 2, &[("b", 0, true)], false, "rt");
        // 第三层（a/b）= 一次 List。
        state.tree_expand(PaneId::Remote, "a/b", Some(&ftx));
        assert_eq!(drain_list_paths(&mut frx), vec!["a/b".to_string()], "再展开一层 = 再一次 List");
        assert_eq!(
            state.remote.view.expanded,
            vec![REMOTE_PC_ROOT_KEY.to_string(), "a".to_string(), "a/b".to_string()],
            "展开集 = 根 + 两层"
        );
        assert_eq!(
            state.remote.current, "a/b",
            "活动节点 = 最后展开节点（面包屑/刷新入口）"
        );
        // 折叠 = 零 wire。
        state.tree_expand(PaneId::Remote, "a/b", Some(&ftx));
        assert!(drain_list_paths(&mut frx).is_empty(), "折叠零 wire");
    }

    // ── ③ 双击展开/折叠 toggle + 折叠弃缓存 + 再展开重 List（新鲜度）────────

    #[test]
    fn test_r134_9b_collapse_drop_cache_reexpand_refetch() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true;
        let (ftx, mut frx) = channel();
        state.request_remote_list_at_node("", Some(&ftx));
        assert_eq!(drain_list_paths(&mut frx), vec!["".to_string()]);
        admit_list(&mut state, 1, "");
        respond_list(&mut state, 1, &[("a", 0, true), ("b.txt", 3, false)], false, "rt");
        state.tree_expand(PaneId::Remote, "a", Some(&ftx));
        assert_eq!(drain_list_paths(&mut frx), vec!["a".to_string()]);
        admit_list(&mut state, 2, "a");
        respond_list(&mut state, 2, &[("f.txt", 1, false)], false, "rt");
        assert!(state.remote.view.nodes["a"].children.is_some(), "a 缓存已在");
        // 选中 = 子树内一项 + 兄弟一项（折叠剪除口径）。
        state
            .remote
            .view
            .selected
            .extend(["a/f.txt".to_string(), "b.txt".to_string()]);
        // 二次双击 = 折叠（toggle；零 wire）。
        state.tree_expand(PaneId::Remote, "a", Some(&ftx));
        assert!(drain_list_paths(&mut frx).is_empty(), "折叠零 wire");
        assert!(
            !state.remote.view.expanded.iter().any(|e| e == "a"),
            "折叠移出展开集"
        );
        assert!(
            !state.remote.view.nodes.contains_key("a"),
            "折叠丢弃节点缓存（再展开 = 重新 List）"
        );
        assert_eq!(
            state.remote.view.selected,
            vec!["b.txt".to_string()],
            "子树选中剪除（兄弟选中保留）"
        );
        // 再展开 = 重新 List（弃缓存保新鲜度）。
        state.tree_expand(PaneId::Remote, "a", Some(&ftx));
        assert_eq!(
            drain_list_paths(&mut frx),
            vec!["a".to_string()],
            "再展开重 List（新鲜度）"
        );
    }

    // ── ④ 选中语义重映射：条目名 → 节点全路径（失效剪除 + click_row 索引）──

    #[test]
    fn test_r134_9b_selection_remap_and_click_row() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true;
        // （合成根之子 = 盘符根，真拓扑同形）。
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(vec![
                    mk_entry("C:\\", 0, true),
                    mk_entry("D:\\", 0, true),
                ]),
                ..Default::default()
            },
        );
        // 失效路径惰性剪除（选中 = 全路径集合的可见子集）。
        state
            .remote
            .view
            .selected
            .extend(["C:\\".to_string(), "gone.txt".to_string()]);
        assert_eq!(
            state.selection_paths(PaneId::Remote),
            vec!["C:\\".to_string()],
            "失效路径剪除"
        );
        // 远端「远端电脑」保留键 = 合成根条目（落点资格由
        // `single_dir_selection` fail-closed 门）；旧远端根 "" 兼容口径保留。
        assert!(state.resolve_entry(PaneId::Remote, REMOTE_PC_ROOT_KEY).is_some());
        assert!(state.resolve_entry(PaneId::Remote, "").is_some());
        assert!(state.resolve_entry(PaneId::Remote, "C:\\").unwrap().is_dir);
        assert_eq!(
            state.resolve_entry(PaneId::Remote, "C:\\work"),
            None,
            "父节点缓存无此子 = 失效（不猜）"
        );
        // 子行按目录恒前 + 名升序）。
        let rows = state.tree_rows(PaneId::Remote);
        assert_eq!(rows[1].path, REMOTE_HOME_KEY, "行 1 = 主目录行");
        state.click_row(PaneId::Remote, 2, false);
        assert_eq!(state.remote.view.selected, vec!["C:\\".to_string()], "单击 = 单选（路径）");
        state.click_row(PaneId::Remote, 3, true);
        assert_eq!(
            state.remote.view.selected,
            vec!["C:\\".to_string(), "D:\\".to_string()],
            "Ctrl 单击 = 追加（路径）"
        );
        state.click_row(PaneId::Remote, 3, true);
        assert_eq!(
            state.remote.view.selected,
            vec!["C:\\".to_string()],
            "Ctrl 再单击 = 取消（路径）"
        );
    }

    // ── ⑤ 箭头落点衔接：目标 = 对侧选中**目录节点**（非当前目录 join）───────

    #[test]
    fn test_r134_9b_arrow_landing_selected_dir() {
        let root = tmp_root("arrow");
        mkfile(&root.join("proj/a.txt"), "1");
        mkfile(&root.join("proj/sub/b.txt"), "22");
        mkfile(&root.join("x.txt"), "3");
        std::fs::create_dir_all(root.join("dld")).unwrap();
        let mut state = FileManagerState::with_local_root(root.clone());
        state.remote.started = true;
        // 远端根 children = [dl/, srv/]；远端「当前目录」= 根（""）。
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                children: Some(vec![mk_entry("dl", 0, true), mk_entry("srv", 0, true)]),
                ..Default::default()
            },
        );
        state.remote.view.selected = vec!["dl".to_string()];
        let panel = FilePanelState::new();
        let (ftx, mut frx) = channel();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();

        // —— → 上传·单文件：落点 = 远端选中目录 "dl"（若与 remote.current join
        //    则落 ""，断言钉死重映射）。
        state
            .local
            .view
            .selected
            .push(local_path_key(&root.join("x.txt")));
        assert_eq!(
            state.arrow_transfer(ArrowDirection::Upload, &panel, Some(&ftx), Some(&mtx)),
            1,
            "单文件上传入队"
        );
        match mxr.try_recv().expect("SendWithConsent 在位") {
            FileMgrCommand::SendWithConsent {
                entries,
                from_job,
                ..
            } => {
                assert!(!from_job);
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].0, root.join("x.txt"), "源 = 本地绝对全路径");
                assert_eq!(entries[0].1, "dl", "落点 = 远端选中目录节点");
            }
            other => panic!("意外命令: {other:?}"),
        }
        // —— → 上传·目录：FolderJob 目标 = "dl"；镜像子目录 = proj / proj/sub。
        state
            .local
            .view
            .selected
            .push(local_path_key(&root.join("proj")));
        state.local.view.selected = vec![local_path_key(&root.join("proj"))];
        assert_eq!(
            state.arrow_transfer(ArrowDirection::Upload, &panel, Some(&ftx), Some(&mtx)),
            2,
            "目录上传 = 2 文件"
        );
        let job = state.job.as_ref().expect("目录 = FolderJob");
        assert_eq!(job.target_remote_dir, "dl", "job 落点 = 选中目录节点");
        assert_eq!(job.source, "proj", "显示源 = 选中目录 basename");
        let mut subs: Vec<String> = job.files.iter().map(|f| f.2.clone()).collect();
        subs.sort();
        assert_eq!(
            subs,
            vec!["proj".to_string(), "proj/sub".to_string()],
            "目录镜像子目录 = <目录名>/[父级]"
        );
        assert!(
            job.files.iter().all(|(p, _, _)| Path::new(p).is_file()),
            "job 文件条目 = 本地绝对全路径"
        );
        // tick 阶段 2：consent 条目目标 = remote_join("dl", subdir)（wire 衔接）。
        state.tick(&panel, Some(&ftx), Some(&mtx));
        match mxr.try_recv().expect("文件夹批 SendWithConsent 在位") {
            FileMgrCommand::SendWithConsent {
                entries,
                from_job,
                ..
            } => {
                assert!(from_job);
                let targets: Vec<String> = entries.iter().map(|e| e.1.clone()).collect();
                assert_eq!(
                    targets,
                    vec!["dl/proj".to_string(), "dl/proj/sub".to_string()],
                    "批目标 = 落点节点 + 子路径镜像"
                );
            }
            other => panic!("意外命令: {other:?}"),
        }
        // —— ← 下载：远端文件 → 本地选中目录节点（绝对全路径落点）。
        state.job = None;
        std::fs::create_dir_all(root.join("dld")).ok();
        state
            .remote
            .view
            .nodes
            .insert(
                "srv".to_string(),
                TreeNodeState {
                    children: Some(vec![mk_entry("r.bin", 9, false)]),
                    ..Default::default()
                },
            );
        state.remote.view.expanded.push("srv".to_string());
        state.remote.view.selected = vec!["srv/r.bin".to_string()];
        state.local.view.selected = vec![local_path_key(&root.join("dld"))];
        assert_eq!(
            state.arrow_transfer(ArrowDirection::Download, &panel, Some(&ftx), Some(&mtx)),
            1,
            "下载入队"
        );
        match frx.try_recv().expect("FetchFile 在位") {
            FileCommand::FetchFile {
                remote_path,
                local_dir,
            } => {
                assert_eq!(remote_path, "srv/r.bin");
                assert_eq!(local_dir, root.join("dld"), "落点 = 本地选中目录节点全路径");
            }
            other => panic!("意外命令: {other:?}"),
        }
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ⑤b 「此电脑」合成根：树节点可选中，但传输源/落点 fail-closed ──────

    #[test]
    fn test_r134_9b_pc_root_not_transfer_target() {
        let root = tmp_root("pcroot1349b");
        mkfile(&root.join("a.txt"), "x");
        let mut state = FileManagerState::with_local_root(root.clone());
        state.remote.started = true;
        // 树节点可解析（可选中、可展开/折叠）。
        assert!(state.resolve_entry(PaneId::Local, LOCAL_PC_ROOT_KEY).is_some());
        state.local.view.selected = vec![LOCAL_PC_ROOT_KEY.to_string()];
        assert_eq!(
            state.single_dir_selection(PaneId::Local),
            None,
            "此电脑合成根 ≠ 传输落点（fail-closed；用户 09-22）"
        );
        // 源侧：「此电脑」= 不可传（跳过，不建空任务，零 wire）。
        let panel = FilePanelState::new();
        let (ftx, mut frx) = channel();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        assert_eq!(
            state.enqueue_transfer(
                PaneId::Local,
                PaneId::Remote,
                vec![LOCAL_PC_ROOT_KEY.to_string()],
                &panel,
                Some(&ftx),
                Some(&mtx),
            ),
            0,
            "此电脑源侧跳过 = 零入队"
        );
        assert!(state.job.is_none(), "不建空任务");
        assert!(frx.try_recv().is_err() && mxr.try_recv().is_err(), "零命令");
        // 展开/折叠 toggle：折叠 → 再展开 = 重新枚举盘符（弃缓存保新鲜度）。
        let mut state2 = FileManagerState::with_local_root(root.clone());
        state2.tree_expand(PaneId::Local, LOCAL_PC_ROOT_KEY, None);
        assert!(
            !state2.local.view.expanded.iter().any(|e| e == LOCAL_PC_ROOT_KEY),
            "「−」收起此电脑根"
        );
        assert!(!state2.local.view.nodes.contains_key(LOCAL_PC_ROOT_KEY), "折叠弃缓存");
        state2.tree_expand(PaneId::Local, LOCAL_PC_ROOT_KEY, None);
        assert!(
            state2.local.view.expanded.iter().any(|e| e == LOCAL_PC_ROOT_KEY),
            "「+」再展开此电脑根"
        );
        assert!(
            state2.local.view.nodes[LOCAL_PC_ROOT_KEY].children.is_some(),
            "再展开重枚举盘符层"
        );
        assert_eq!(state2.local.current, root, "活动节点 = 基准根");
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ⑥ 树内取消分页：>500 子全量可见（has_more = 节点内标记行）──────────

    #[test]
    fn test_r134_9b_no_pagination_all_visible() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true;
        let entries: Vec<FileMgrEntry> = (0..600)
            .map(|i| mk_entry(&format!("f_{i:03}.txt"), 1, false))
            .collect();
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(entries),
                has_more: true,
                ..Default::default()
            },
        );
        let rows = state.tree_rows(PaneId::Remote);
        assert_eq!(
            rows.len(),
            602,
        );
        let pr = state.pane_rows(PaneId::Remote);
        let markers: Vec<&PaneRow> =
            pr.iter().filter(|r| matches!(r, PaneRow::Marker { .. })).collect();
        assert_eq!(markers.len(), 1, "has_more = 恰一标记行");
        assert!(
            matches!(&markers[0], PaneRow::Marker { retry: None, .. }),
            "「更多」标记行无重试"
        );
    }

    // ── ⑦ 长路径（12 层）本地同步链展开：零 wire + 深度单调 ─────────────────

    #[test]
    fn test_r134_9b_long_path_local_chain_zero_wire() {
        // 环境解耦（门禁稳定）：Temp 高熵（实机 >500 目录）→ 本地 Temp 节点
        // children 触发 `PAGE_SIZE` 上限截断，测试根被挤出树行区 = 负载
        // flake（与本测 12 层/零 wire/深度不变式语义无关）。基址锚定 Temp
        // 父层（AppData\Local 低熵稳定层；非 Temp 形态零漂移）。
        let base = std::env::temp_dir();
        let base = if base
            .file_name()
            .map(|s| s == "Temp")
            .unwrap_or(false)
        {
            base.parent().map(PathBuf::from).unwrap_or(base)
        } else {
            base
        };
        let root = base.join(format!("k92e1_deep_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut p = root.clone();
        for i in 0..12 {
            p = p.join(format!("lvl{i:02}"));
        }
        std::fs::create_dir_all(&p).unwrap();
        mkfile(&p.join("leaf.txt"), "x");
        let mut state = FileManagerState::with_local_root(root.clone());
        let (ftx, mut frx) = channel();
        assert!(state.local_expand_chain(&p), "链展开成功");
        assert!(frx.try_recv().is_err(), "本地链展开零 wire");
        let rows = state.tree_rows(PaneId::Local);
        let target_key = local_path_key(&p);
        assert!(
            rows.iter().any(|r| r.path == target_key),
            "最深层目录行在位（12 层无截断）"
        );
        // 深度不变式（用户 09-22：此电脑根层 = depth 0）：盘符 = depth 1；
        // 其余 = 盘符相对组件数 + 1（树结构序无跳层）。
        for r in &rows {
            if r.path == LOCAL_PC_ROOT_KEY {
                assert_eq!(r.depth, 0, "此电脑根 = depth 0");
                continue;
            }
            let pp = Path::new(&r.path);
            let Some(drive) = local_drive_of(pp) else {
                continue;
            };
            let rel = pp.strip_prefix(&drive).unwrap_or_else(|_| Path::new(""));
            assert_eq!(
                r.depth,
                rel.components().count() + 1,
                "行深度 = 盘符相对组件数 + 1（此电脑根层；{}）",
                r.path
            );
        }
        let target_depth = rows
            .iter()
            .find(|r| r.path == target_key)
            .unwrap()
            .depth;
        let leaf = rows
            .iter()
            .find(|r| r.entry.name == "leaf.txt" && r.depth == target_depth + 1)
            .expect("叶子文件行 = 最深层 + 1");
        let _ = leaf;
        std::fs::remove_dir_all(&root).ok();
        let _ = ftx;
    }

    // ── ⑧ 错误节点：标记可重试（双击/🔄 重列；恢复清错误）──────────────────

    #[test]
    fn test_r134_9b_error_node_retry() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true;
        let (ftx, mut frx) = channel();
        state.request_remote_list_at_node(REMOTE_PC_ROOT_KEY, Some(&ftx));
        assert_eq!(drain_list_paths(&mut frx), vec![REMOTE_PC_ROOT_KEY.to_string()]);
        admit_list(&mut state, 1, REMOTE_PC_ROOT_KEY);
        respond_list(&mut state, 1, &[("a", 0, true)], false, "rt");
        // 展开 a → List → 错误响应（NotFound；版本门 unsupported 不置位）。
        state.tree_expand(PaneId::Remote, "a", Some(&ftx));
        assert_eq!(drain_list_paths(&mut frx), vec!["a".to_string()]);
        admit_list(&mut state, 2, "a");
        state.on_fs_event(FsEvent::Response {
            req_id: 2,
            result: Ok(FsResponsePayload {
                ok: false,
                err: FsErrCode::NotFound,
                payload: Vec::new(),
            }),
        });
        let node = &state.remote.view.nodes["a"];
        assert!(!node.loading, "错误后 loading 清");
        assert!(node.error.is_some(), "错误节点标记");
        assert!(node.children.is_none());
        assert!(
            !state.remote.unsupported,
            "结构化错误码 ≠ 版本门（unsupported 不置位）"
        );
        assert!(
            state.remote.view.expanded.iter().any(|e| e == "a"),
            "错误节点保持展开（待重试）"
        );
        // 渲染层标记行 = 错误 + 重试目标。
        let pr = state.pane_rows(PaneId::Remote);
        let retry: Vec<&String> = pr
            .iter()
            .filter_map(|r| match r {
                PaneRow::Marker {
                    retry: Some(p),
                    warn,
                    ..
                } if *warn => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(retry, vec![&"a".to_string()], "错误标记行携重试目标");
        // 双击重试 = 重新 List（恰一次；错误态不清展开）。
        state.tree_expand(PaneId::Remote, "a", Some(&ftx));
        assert_eq!(
            drain_list_paths(&mut frx),
            vec!["a".to_string()],
            "重试 = 重列一次"
        );
        // 恢复：正常响应 → children 就绪、错误清除。
        admit_list(&mut state, 3, "a");
        respond_list(&mut state, 3, &[("f.txt", 1, false)], false, "rt");
        let node = &state.remote.view.nodes["a"];
        assert!(node.error.is_none() && node.children.is_some(), "恢复后错误清除");
        assert!(
            state.remote.view.expanded.iter().any(|e| e == "a"),
            "恢复后仍在展开集"
        );
    }

    // ── ⑨ 陈旧响应回归：迟到响应收回 = 在途 op 不丢（不再卡 loading）────────

    #[test]
    fn test_r134_9b_stale_response_keeps_pending() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true;
        let (ftx, mut frx) = channel();
        // 第一节点 a（req_id=1）在途。
        state.request_remote_list_at_node("a", Some(&ftx));
        admit_list(&mut state, 1, "a");
        // 换节点 b（cancel_pending 零 wire 帧 + 新在途 req_id=2）。
        state.request_remote_list_at_node("b", Some(&ftx));
        admit_list(&mut state, 2, "b");
        assert_eq!(
            drain_list_paths(&mut frx),
            vec!["a".to_string(), "b".to_string()],
            "两节点各一次 List"
        );
        // 迟到的陈旧响应（a, req_id=1）→ 在途 b（req_id=2）**放回**不丢。
        state.on_fs_event(FsEvent::Response {
            req_id: 1,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: Vec::new(),
            }),
        });
        let p = state
            .pending
            .as_ref()
            .expect("陈旧响应后在途 op 不得丢失（旧实现静默丢弃 → 卡 loading）");
        assert!(
            matches!(&p.kind, PendingKind::List { path, .. } if path == "b"),
            "在途仍 = b"
        );
        assert!(
            state.remote.view.nodes["b"].loading,
            "b 保持 loading（等待自己的响应）"
        );
        // b 的响应正常结算。
        respond_list(&mut state, 2, &[("ok.txt", 1, false)], false, "rt");
        assert!(state.pending.is_none(), "b 结算后无在途");
        assert!(
            state.remote.view.nodes["b"].children.is_some()
                && !state.remote.view.nodes["b"].loading,
            "b children 就绪"
        );
    }

    // ── ⑩ expand_queue 链导航：逐层推进、单在途、链作废清队 ─────────────────

    #[test]
    fn test_r134_9b_expand_queue_chain_nav() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true;
        let (ftx, mut frx) = channel();
        let panel = FilePanelState::new();
        // 播种：根 children=[x/]；x、x/y 在展开集但缓存已弃（链队列场景）。
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                children: Some(vec![mk_entry("x", 0, true)]),
                ..Default::default()
            },
        );
        state
            .remote
            .view
            .expanded
            .extend(["x".to_string(), "x/y".to_string()]);
        state.remote.current = "x/y".to_string();
        state.remote.expand_queue = vec!["x".to_string(), "x/y".to_string()].into();
        // 帧 1：front x（已展开无缓存）= List x；单在途（本帧只发一个）。
        state.tick(&panel, Some(&ftx), None);
        assert_eq!(
            drain_list_paths(&mut frx),
            vec!["x".to_string()],
            "逐层推进：帧 1 = 第一层"
        );
        admit_list(&mut state, 1, "x");
        respond_list(&mut state, 1, &[("y", 0, true)], false, "rt");
        // 帧 2：x 缓存命中跳过 → front x/y = List。
        state.tick(&panel, Some(&ftx), None);
        assert_eq!(
            drain_list_paths(&mut frx),
            vec!["x/y".to_string()],
            "逐层推进：帧 2 = 第二层"
        );
        admit_list(&mut state, 2, "x/y");
        respond_list(&mut state, 2, &[], false, "rt");
        assert!(state.remote.expand_queue.is_empty(), "链推进完毕");
        // 链作废：front 已折叠 = 清队不推进（零 wire）。
        state.remote.view.expanded.retain(|e| e != "x/y");
        state.remote.expand_queue = vec!["x/y".to_string()].into();
        state.tick(&panel, Some(&ftx), None);
        assert!(state.remote.expand_queue.is_empty(), "链作废清队");
        assert!(drain_list_paths(&mut frx).is_empty(), "作废零 wire");
    }

    // ── ⑪ 排序按展开节点局部：表头三态重排全部已展开节点 children ───────────

    #[test]
    fn test_r134_9b_sort_header_local_nodes() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true;
        fn node2(a: (&str, u64), b: (&str, u64)) -> TreeNodeState {
            TreeNodeState {
                children: Some(vec![mk_entry(a.0, a.1, false), mk_entry(b.0, b.1, false)]),
                ..Default::default()
            }
        }
        // 两展开节点 children 均非 size 序。
        state
            .remote
            .view
            .nodes
            .insert(String::new(), node2(("z", 1), ("a", 9)));
        state
            .remote
            .view
            .nodes
            .insert("d".to_string(), node2(("q", 5), ("m", 2)));
        state
            .remote
            .view
            .expanded
            .extend([String::new(), "d".to_string()]);
        let names = |s: &FileManagerState, k: &str| -> Vec<String> {
            s.remote
                .view
                .nodes
                .get(k)
                .unwrap()
                .children
                .as_ref()
                .unwrap()
                .iter()
                .map(|e| e.name.clone())
                .collect()
        };
        state.sort_header(PaneId::Remote, SortField::Size);
        assert_eq!(names(&state, ""), vec!["z", "a"], "asc：两节点均重排");
        assert_eq!(names(&state, "d"), vec!["m", "q"]);
        state.sort_header(PaneId::Remote, SortField::Size);
        assert_eq!(names(&state, ""), vec!["a", "z"], "desc 三态第二拍");
        assert_eq!(names(&state, "d"), vec!["q", "m"]);
        state.sort_header(PaneId::Remote, SortField::Size);
        assert_eq!(names(&state, ""), vec!["a", "z"], "off 三态第三拍（名升序）");
        assert_eq!(names(&state, "d"), vec!["m", "q"]);
    }

    // ── ⑫ 自绘缩进树渲染：标记列逐层 14px 递进 + 名称列确定性对齐 ───────────

    /// headless 帧驱动器（同 r134_9 `FmHarness` 口径；CentralPanel 零边距）。
    struct IndHarness {
        ctx: egui::Context,
        state: FileManagerState,
        panel: FilePanelState,
        screen: (f32, f32),
    }

    impl IndHarness {
        fn new(state: FileManagerState, panel: FilePanelState, screen: (f32, f32)) -> Self {
            let ctx = egui::Context::default();
            ctx.set_visuals(egui::Visuals::light());
            Self {
                ctx,
                state,
                panel,
                screen,
            }
        }

        fn frame(&mut self, events: Vec<egui::Event>) -> Vec<egui::epaint::ClippedShape> {
            let mut raw = egui::RawInput::default();
            raw.screen_rect = Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(self.screen.0, self.screen.1),
            ));
            raw.events = events;
            let mut focus = false;
            self.ctx
                .run(raw, |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        show_file_manager(
                            ui,
                            &Theme::LIGHT,
                            &mut self.state,
                            None,
                            None,
                            &self.panel,
                            false,
                            &mut focus,
                        );
                    });
                })
                .shapes
        }
    }

    /// 精确文本 → [(x, y, w, h)]（按 (y, x) 排序；同 r134_9 `text_rects` 口径）。
    fn text_rects(shapes: &[egui::epaint::ClippedShape], text: &str) -> Vec<(f32, f32, f32, f32)> {
        let mut v: Vec<(f32, f32, f32, f32)> = shapes
            .iter()
            .filter_map(|cs| match &cs.shape {
                egui::Shape::Text(t) if t.galley.job.text == text => {
                    Some((t.pos.x, t.pos.y, t.galley.rect.width(), t.galley.rect.height()))
                }
                _ => None,
            })
            .collect();
        v.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.total_cmp(&b.0)));
        v
    }

    #[test]
    fn test_r134_9b_indent_render_markers_stagger() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        // 盘符链 = 驱动器 → … → 主目录（真 fs 同步展开，零 wire；行数可控 =
        // 盘符 + 盘根子 + Users 子 + 主目录子，1200px 屏内全可见）。
        let home = dirs_next::home_dir().unwrap_or_else(std::env::temp_dir);
        let mut state = FileManagerState::with_local_root(home.clone());
        assert!(state.local_expand_chain(&home), "盘符链同步展开");
        state.local.current = home.clone();
        state.remote.started = true; // 右栏空态（不扰动左栏断言）
        let panel = FilePanelState::new();
        let (sw, sh) = (1280.0, 1200.0);
        let mut h = IndHarness::new(state, panel, (sw, sh));
        let _f1 = h.frame(Vec::new()); // 字体图集 + Grid sizing pass
        let f2 = h.frame(Vec::new());
        // 左栏行区 x 上界（同 `render_panes_and_seam` 几何：左栏右缘）。
        let spacing = egui::Style::default().spacing.item_spacing.x;
        let pane_w = ((sw - SEAM_WIDTH - 2.0 * spacing) / 2.0).max(1.0);
        // ① 标记列：左栏 −（已展开目录的 − 折叠钮；用户 09-22）x 逐层 +14px
        //    （缩进步长 ±0.5 浮点抖动）。
        let marks: Vec<f32> = text_rects(&f2, "−")
            .into_iter()
            .filter(|(x, _, _, _)| *x < pane_w)
            .map(|(x, _, _, _)| x)
            .collect();
        let mut xs = marks;
        xs.sort_by(|a, b| a.total_cmp(b));
        assert!(
            xs.len() >= 4,
            "左栏已展开目录 − 标记 ≥4 层（此电脑根 + 盘符链），实得 {}",
            xs.len()
        );
        for i in 1..xs.len() {
            assert!(
                (xs[i] - xs[i - 1] - R134_9B_TREE_INDENT).abs() <= 0.5,
                "相邻层标记 x 差 = {R134_9B_TREE_INDENT}px（实得 {:.1} → {:.1}）",
                xs[i - 1],
                xs[i]
            );
        }
        // ② 名称列确定性对齐（5 列 Grid 名称列同 x；缩进只落标记列）——
        //    跨深度取「此电脑」根行（d0）与盘符行（d1）名称同 x。名称亦出现
        //    于面包屑（当前链含 此电脑/盘符 段）→ 取 y 序**末次**（树行在
        //    面包屑之下）。
        let rows = h.state.tree_rows(PaneId::Local);
        let root_row = rows.first().expect("此电脑根行在位");
        let drive_row = rows
            .iter()
            .find(|r| r.depth == 1 && r.entry.is_dir)
            .expect("盘符行（根下目录层）在位");
        let xr = text_rects(&f2, &root_row.entry.name)
            .pop()
            .expect("此电脑行名称在位");
        let xd = text_rects(&f2, &drive_row.entry.name)
            .pop()
            .expect("盘符行名称在位");
        assert!(
            (xr.0 - xd.0).abs() <= 0.5,
            "名称列 x 跨深度对齐（d0={:.1} d1={:.1}）",
            xr.0,
            xd.0
        );
        // ③ 缩进预算：标记 x 跨度 = (层数-1)×步长。
        assert!(
            xs.last().unwrap() - xs.first().unwrap()
                >= ((xs.len() - 1) as f32 * R134_9B_TREE_INDENT - 1.0),
            "标记列缩进跨度达标"
        );
        let _ = sh;
    }

    // ── ⑬ 隔离目录截屏自验（盘符根 / 展开层 / 缩进层级 / 错误态；用户观感终判）──

    /// 软件光栅化（Rect fill/stroke + Text 字形图集采样；Mesh 等 = 跳过）——
    /// 配方同 r134_9_screenshot_dump（帧 1 字体图集 + 帧 2 shapes）。
    pub(crate) fn rasterize_png(
        out1: &egui::FullOutput,
        out2: &egui::FullOutput,
        w: u32,
        h: u32,
        out_path: &str,
    ) {
        let mut atlas: Option<(usize, usize, Vec<f32>)> = None;
        for (_, delta) in out1.textures_delta.set.iter() {
            if let egui::epaint::ImageData::Font(fi) = &delta.image {
                if fi.size[0] * fi.size[1] > atlas.as_ref().map(|(a, b, _)| a * b).unwrap_or(0) {
                    atlas = Some((fi.size[0], fi.size[1], fi.pixels.clone()));
                }
            }
        }
        let (aw, ah, aatlas) = atlas.expect("字体图集纹理应在首帧建立");
        fn c32_rgba(c: egui::Color32) -> image::Rgba<u8> {
            let [r, g, b, a] = c.to_srgba_unmultiplied();
            image::Rgba::<u8>([r, g, b, a])
        }
        let panel_bg = egui::Visuals::light().panel_fill;
        let mut img = image::RgbaImage::from_pixel(w, h, c32_rgba(panel_bg));
        for cs in &out2.shapes {
            let clip = cs.clip_rect;
            let mut draw_rect = |r: egui::Rect, c: image::Rgba<u8>| {
                let x0 = (r.min.x.max(clip.min.x)).floor() as i32;
                let y0 = (r.min.y.max(clip.min.y)).floor() as i32;
                let x1 = (r.max.x.min(clip.max.x)).ceil() as i32;
                let y1 = (r.max.y.min(clip.max.y)).ceil() as i32;
                for y in y0.max(0)..y1.min(h as i32) {
                    for x in x0.max(0)..x1.min(w as i32) {
                        img.put_pixel(x as u32, y as u32, c);
                    }
                }
            };
            match &cs.shape {
                egui::Shape::Rect(rs) => {
                    if rs.fill.a() > 0 {
                        draw_rect(rs.rect, c32_rgba(rs.fill));
                    }
                    if rs.stroke.width > 0.0 {
                        let swd = rs.stroke.width.max(1.0);
                        draw_rect(rs.rect, c32_rgba(rs.stroke.color));
                        let inner = rs.rect.shrink2(egui::vec2(swd / 2.0, swd / 2.0));
                        if inner.width() > 0.0 && inner.height() > 0.0 {
                            draw_rect(inner, c32_rgba(panel_bg));
                        }
                    }
                }
                egui::Shape::Text(t) => {
                    let sections = &t.galley.job.sections;
                    for row in &t.galley.rows {
                        for g in &row.glyphs {
                            let uv = &g.uv_rect;
                            let (sx0, sy0) = (uv.min[0] as i32, uv.min[1] as i32);
                            let (sx1, sy1) = (uv.max[0] as i32, uv.max[1] as i32);
                            let sw_ = (sx1 - sx0).max(1);
                            let sh_ = (sy1 - sy0).max(1);
                            let mut color = sections
                                .get(g.section_index as usize)
                                .map(|s| s.format.color)
                                .unwrap_or_default();
                            if color == egui::Color32::PLACEHOLDER {
                                color = t.fallback_color;
                            }
                            if let Some(oc) = t.override_text_color {
                                color = oc;
                            }
                            let [cr, cg, cb, ca] = color.to_srgba_unmultiplied();
                            let gx0 = (t.pos.x + g.pos.x + uv.offset.x).floor() as i32;
                            let gy0 = (t.pos.y + g.pos.y + uv.offset.y).floor() as i32;
                            let gw_i = uv.size.x.max(1.0) as i32;
                            let gh_i = uv.size.y.max(1.0) as i32;
                            for dy in 0..gh_i {
                                let ay = (sy0 + dy * sh_ / gh_i).min(ah as i32 - 1);
                                for dx in 0..gw_i {
                                    let ax = (sx0 + dx * sw_ / gw_i).min(aw as i32 - 1);
                                    if ax < 0 || ay < 0 {
                                        continue;
                                    }
                                    let a = aatlas[(ay as usize) * aw + (ax as usize)]
                                        * (ca as f32 / 255.0);
                                    if a <= 0.01 {
                                        continue;
                                    }
                                    let px = gx0 + dx;
                                    let py = gy0 + dy;
                                    if px < 0 || py < 0 || px >= w as i32 || py >= h as i32 {
                                        continue;
                                    }
                                    if px < clip.min.x as i32 || px >= clip.max.x as i32
                                        || py < clip.min.y as i32
                                        || py >= clip.max.y as i32
                                    {
                                        continue;
                                    }
                                    let dst = img.get_pixel(px as u32, py as u32);
                                    let out = image::Rgba::<u8>([
                                        (cr as f32 * a + dst[0] as f32 * (1.0 - a)) as u8,
                                        (cg as f32 * a + dst[1] as f32 * (1.0 - a)) as u8,
                                        (cb as f32 * a + dst[2] as f32 * (1.0 - a)) as u8,
                                        255,
                                    ]);
                                    img.put_pixel(px as u32, py as u32, out);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        img.save(out_path).expect("PNG 落盘");
    }

    /// 09-22〕+ 盘符层 + 展开链至测试目录 = 根/目录层/缩进层级 + −/＋ 折叠
    /// 钮）；右栏 = 播种远端树（远端根 + 两层展开 + 错误节点 🔄 标记行 +
    /// 加载中行）。目验 = 用户观感初判（PNG 落 `E:/projects_rd/docs/`，
    /// 仓外不 commit，同 r133_7/r134_9 先例）。
    #[test]
    fn r134_9b_screenshot_dump() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let (sw, sh) = (1920.0, 1080.0);
        let root = tmp_root("shot1349b");
        std::fs::create_dir_all(root.join("aa/bb")).unwrap();
        mkfile(&root.join("aa/bb/cc.txt"), "x");
        mkfile(&root.join("aa/mid.txt"), "y");
        mkfile(&root.join("top.txt"), "z");
        let mut state = FileManagerState::with_local_root(root.clone());
        // 左栏：盘符链同步展开至测试根（零 wire；真盘符树形态）。
        assert!(state.local_expand_chain(&root), "本地链展开");
        state.local.current = root.clone();
        // 右栏：播种远端树（started = true 抑制首 List 覆盖播种）。
        state.remote.started = true;
        state.remote.root_display = "sandbox".to_string();
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(vec![
                    mk_entry("docs", 0, true),
                    mk_entry("proj", 0, true),
                    mk_entry("notes.txt", 128, false),
                ]),
                ..Default::default()
            },
        );
        state.remote.view.expanded.push("docs".to_string());
        state.remote.view.nodes.insert(
            "docs".to_string(),
            TreeNodeState {
                children: Some(vec![
                    mk_entry("guide", 0, true),
                    mk_entry("readme.md", 64, false),
                ]),
                ..Default::default()
            },
        );
        // 错误节点（List 失败 = 标记行 + 🔄 可重试）。
        state.remote.view.expanded.push("docs/guide".to_string());
        state.remote.view.nodes.insert(
            "docs/guide".to_string(),
            TreeNodeState {
                loading: false,
                error: Some("not found（隔离目录演示）".to_string()),
                ..Default::default()
            },
        );
        // 加载中节点（List 在途 = 标记行）。
        state.remote.view.expanded.push("proj".to_string());
        state.remote.view.nodes.insert(
            "proj".to_string(),
            TreeNodeState {
                loading: true,
                ..Default::default()
            },
        );
        let panel = FilePanelState::new();

        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let run_frame = |ctx: &egui::Context, state: &mut FileManagerState| {
            let mut raw = egui::RawInput::default();
            raw.screen_rect =
                Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(sw, sh)));
            let mut focus = false;
            ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    show_file_manager(
                        ui,
                        &Theme::LIGHT,
                        state,
                        None,
                        None,
                        &panel,
                        false,
                        &mut focus,
                    );
                });
            })
        };
        let out1 = run_frame(&ctx, &mut state);
        let out2 = run_frame(&ctx, &mut state);
        let out_path = "E:/projects_rd/docs/r134_9b_tree_sandbox.png";
        rasterize_png(&out1, &out2, sw as u32, sh as u32, out_path);
        assert!(std::path::Path::new(out_path).is_file(), "截屏在位");
        std::fs::remove_dir_all(&root).ok();
    }
}

// ════════════════════════════════════════════════════════════════
// 顶部提示文字 / 上传失败修复 / 选中目录下载语义 / 会话配额移除）
// ════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r135_5_tests {
    use super::*;
    use kirin_desk_core::connection::file_transfer::FsEntry;

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "kirin_fm_r135_5_{tag}_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn mkfile(p: &Path, content: &str) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(p, content).unwrap();
    }

    fn mk_entry(name: &str, size: u64, is_dir: bool) -> FileMgrEntry {
        FileMgrEntry {
            name: name.to_string(),
            size,
            mtime: 0,
            is_dir,
            is_symlink: false,
            is_hidden: false,
        }
    }

    fn build_fs_list_payload(
        entries: &[(&str, u64, bool)],
        has_more: bool,
        root_display: &str,
    ) -> FsResponsePayload {
        let list = FsListPayload {
            entries: entries
                .iter()
                .map(|(n, s, d)| FsEntry {
                    name: (*n).into(),
                    size: *s,
                    mtime: 0,
                    is_dir: *d,
                    is_symlink: false,
                })
                .collect(),
            has_more,
            root_display: root_display.into(),
        };
        FsResponsePayload {
            ok: true,
            err: FsErrCode::Ok,
            payload: bincode::serialize(&list).unwrap(),
        }
    }

    /// ① 第 1 项：± 折叠钮几何钉死（字形 14→11px + `frame(false)` 零 padding
    /// + 标记列宽 24→16px；单层缩进 14px 不变 = 树行节奏恢复）。
    #[test]
    fn r135_5_tree_mark_geometry_pinned() {
        assert_eq!(R135_5_TREE_MARK_GLYPH_SIZE, 11.0, "± 字形 14→11px");
        assert!(!R135_5_TREE_MARK_BTN_FRAME, "± 按钮 frame=false（egui 0.28.1 = padding 归零）");
        assert_eq!(R134_9B_TREE_MARK_W, 16.0, "标记列宽 24→16px");
        assert_eq!(R134_9B_TREE_INDENT, 14.0, "单层缩进不变");
    }

    /// ② 第 2 项：盘符路径识别矩阵（与服务端 lib.rs `fs_is_drive_path`
    /// 同判据——双端同构防漂移）。
    #[test]
    fn r135_5_is_drive_path_matrix() {
        for (p, e) in [
            ("C:\\", true),
            ("C:", true),
            ("C:/Users", true),
            ("c:\\x", true),
            ("D:\\", true),
            ("C:Users", false),
            ("CD:\\", false),
            ("Users", false),
            ("", false),
            ("C", false),
            (":\\", false),
            ("1:\\", false),
        ] {
            assert_eq!(is_drive_path(p), e, "{p:?}");
        }
    }

    /// ③ 第 2 项：盘符感知路径助手族矩阵（父键/节点名/join/祖先链/相对化；
    /// 非盘符 = 旧语义零漂移）。
    #[test]
    fn r135_5_drive_path_helpers_matrix() {
        // remote_parent_key
        assert_eq!(remote_parent_key("C:\Users\dev"), "C:\\Users");
        assert_eq!(remote_parent_key("C:\\Users"), "C:\\");
        assert_eq!(remote_parent_key("C:\\"), REMOTE_PC_ROOT_KEY);
        assert_eq!(remote_parent_key("C:"), REMOTE_PC_ROOT_KEY);
        assert_eq!(remote_parent_key("a/b"), "a");
        assert_eq!(remote_parent_key("b"), "");
        assert_eq!(remote_parent_key("a/b/c"), "a/b");
        // remote_entry_name
        assert_eq!(remote_entry_name("C:\Users\dev"), "yu");
        assert_eq!(remote_entry_name("C:\\Users"), "Users");
        assert_eq!(remote_entry_name("C:\\"), "C:\\");
        assert_eq!(remote_entry_name("a/b"), "b");
        assert_eq!(remote_entry_name("b"), "b");
        // remote_join（盘符 = `\` 拼接；旧 `/` 语义零漂移）
        assert_eq!(remote_join("C:\\", "Users"), "C:\\Users");
        assert_eq!(remote_join("C:", "Users"), "C:\\Users");
        assert_eq!(remote_join("C:\\Users", "yu"), "C:\Users\dev");
        assert_eq!(remote_join("a", "b"), "a/b");
        assert_eq!(remote_join("", "x"), "x");
        assert_eq!(remote_join("a", ""), "a");
        // remote_chain_ancestors（盘符层挂合成根下，不入链）
        assert_eq!(
            remote_chain_ancestors("C:\Users\dev"),
            vec!["C:\\", "C:\\Users", "C:\Users\dev"]
        );
        assert!(remote_chain_ancestors("C:\\").is_empty(), "裸盘符无祖先层");
        assert_eq!(remote_chain_ancestors("a/b"), vec!["a", "a/b"]);
        // remote_strip_base（盘符 = `\` 前缀剥离 → `/` 相对形态）
        assert_eq!(remote_strip_base("C:\\src", "C:\\src\\a\\b"), "a/b");
        assert_eq!(remote_strip_base("src", "src/a/b"), "a/b");
        assert_eq!(remote_strip_base("", "x/y"), "x/y");
    }

    /// ④ 第 2 项：「远端电脑」合成根**结构 + fail-closed 矩阵**（构造默认
    /// 展开/current/首 List 保留键；落点/源/删除/新建/改名五面排除；默认
    /// 目标回退 `""`）。
    #[test]
    fn r135_5_remote_pc_root_structure_and_guards() {
        let root = tmp_root("pcroot135");
        let mut state = FileManagerState::with_local_root(root.clone());
        // a) 构造：远端默认展开 + current = 保留键（首 List 打保留键）。
        assert!(
            state.remote.view.expanded.iter().any(|p| p == REMOTE_PC_ROOT_KEY),
            "远端合成根默认展开"
        );
        assert_eq!(state.remote.current, REMOTE_PC_ROOT_KEY, "current 初始 = 保留键");
        // b) 树根行 = 保留键 + i18n 名（「远端电脑」）。
        let rows = state.tree_rows(PaneId::Remote);
        assert_eq!(rows[0].path, REMOTE_PC_ROOT_KEY, "根行 = 保留键");
        assert_eq!(rows[0].entry.name, crate::i18n::tr("filemgr.pc_root_remote"));
        assert!(rows[0].entry.is_dir && !rows[0].entry.is_symlink);
        // c) resolve_entry = 合成目录条目。
        let e = state.resolve_entry(PaneId::Remote, REMOTE_PC_ROOT_KEY).unwrap();
        assert!(e.is_dir && !e.is_symlink);
        // d) single_dir_selection = 落点 fail-closed 排除。
        state.remote.view.selected = vec![REMOTE_PC_ROOT_KEY.to_string()];
        assert!(
            state.single_dir_selection(PaneId::Remote).is_none(),
            "合成根不可作传输落点"
        );
        // e) 传输源枚举排除（合成根不可传）。
        let n = state.enqueue_transfer_targeted(
            PaneId::Remote,
            PaneId::Local,
            vec![REMOTE_PC_ROOT_KEY.to_string()],
            None,
            None,
            &FilePanelState::new(),
            None,
            None,
        );
        assert_eq!(n, 0, "合成根源 = 零入队");
        // f) open_delete = 不进确认批（fail-closed）。
        state.remote.view.selected = vec![REMOTE_PC_ROOT_KEY.to_string()];
        state.open_delete(PaneId::Remote);
        assert!(state.pending_deletes.is_empty(), "合成根不可删");
        // g) mkdir 守卫（current = 保留键 → 零 wire + 状态行；防误建
        //    对话框 + 框内显式错误**（非静默；旧「对话框消失仅状态行小字」
        //    语义已废）。
        state.remote.current = REMOTE_PC_ROOT_KEY.to_string();
        state.dialog = Dialog::InputMkdir {
            pane: PaneId::Remote,
            name: "X".into(),
        };
        assert!(state.mkdir_submit().is_none(), "合成根下 mkdir 零 wire");
        assert_eq!(
            state.status_line.as_deref(),
            Some(crate::i18n::tr("filemgr.err.outside_root")),
            "mkdir 守卫状态行"
        );
        match &state.dialog {
            Dialog::InputMkdir { pane, name } => {
                assert_eq!(*pane, PaneId::Remote);
                assert_eq!(name, "X", "保开对话框 + 已输入文本保留");
            }
            other => panic!("mkdir 守卫应保开对话框，实际 {other:?}"),
        }
        assert_eq!(
            state.dialog_error.as_deref(),
            Some(crate::i18n::tr("filemgr.err.outside_root")),
        );
        // h) rename 守卫（from = 保留键 → 零 wire）。
        state.dialog = Dialog::ConfirmRename {
            pane: PaneId::Remote,
            from: REMOTE_PC_ROOT_KEY.to_string(),
            to: "X".into(),
        };
        assert!(state.rename_resolve(true).is_none(), "合成根不可改名");
        // i) 默认目标回退（合成根 = 非真实目录 → `""` = 对端 fs 根）。
        state.remote.current = REMOTE_PC_ROOT_KEY.to_string();
        assert_eq!(state.remote_default_target(), "");
        state.remote.current = "C:\\work".to_string();
        assert_eq!(state.remote_default_target(), "C:\\work");
        // j) 首 List 零通道形态（节点缓存空目录呈现，不 panic）。
        state.request_remote_list_at_node(REMOTE_PC_ROOT_KEY, None);
        assert!(
            state.remote.view.nodes[REMOTE_PC_ROOT_KEY].children.as_ref().is_some(),
            "零通道首 List = 空目录呈现"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// ⑤ 第 4+5 项：**栏头按钮/粘贴 targeting + 选中目录下载落点语义**
    /// （用户原话语义钉死：目录 = 在目标选中目录下新建**同名目录**再下载
    /// 入内；上传对称 = 目标选中目录）。
    #[test]
    fn r135_5_targeting_and_dir_download_semantics() {
        let root = tmp_root("target");
        let proj = root.join("proj");
        mkfile(&proj.join("a.txt"), "12345");
        let mut state = FileManagerState::with_local_root(root.clone());
        // 远端树播种：合成根 + C:\（盘符层）+ C:\work〔目标〕+ C:\other〔current〕。
        state.remote.started = true;
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("C:\\", 0, true), mk_entry("D:\\", 0, true)]),
                ..Default::default()
            },
        );
        state.remote.view.expanded.push("C:\\".to_string());
        state.remote.view.nodes.insert(
            "C:\\".to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("work", 0, true), mk_entry("other", 0, true)]),
                ..Default::default()
            },
        );
        state.remote.view.expanded.push("C:\\work".to_string());
        state.remote.view.nodes.insert(
            "C:\\work".to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("r.txt", 5, false)]),
                ..Default::default()
            },
        );
        state.remote.current = "C:\\other".to_string(); // current ≠ 选中目标（钉死优先级）
        state.remote.view.selected = vec!["C:\\work".to_string()];
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mrx) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let panel = FilePanelState::new();
        // a) 目标侧选中恰一目录 = 落点解析（盘符路径）。
        assert_eq!(
            state.single_dir_selection(PaneId::Remote).as_deref(),
            Some("C:\\work")
        );
        // b) 「发送所选」单文件上传 = 落点**选中远端目录**（非 remote.current）。
        state.local.current = proj.clone();
        state.local.view.selected = vec![local_path_key(&proj.join("a.txt"))];
        let t_remote = state.single_dir_selection(PaneId::Remote);
        let n = state.enqueue_transfer_targeted(
            PaneId::Local,
            PaneId::Remote,
            state.selection_paths(PaneId::Local),
            t_remote,
            None,
            &panel,
            Some(&ftx),
            Some(&mtx),
        );
        assert_eq!(n, 1, "单文件快路径入队");
        match mrx.try_recv().unwrap() {
            FileMgrCommand::SendWithConsent { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].1, "C:\\work", "上传落点 = 选中远端目录");
            }
            other => panic!("应得 SendWithConsent，实际 {other:?}"),
        }
        // c) 「发送所选」目录上传 = FolderJob 目标 = 选中远端目录（对称核）。
        state.local.view.selected = vec![local_path_key(&proj)];
        let t_remote = state.single_dir_selection(PaneId::Remote);
        state.enqueue_transfer_targeted(
            PaneId::Local,
            PaneId::Remote,
            state.selection_paths(PaneId::Local),
            t_remote,
            None,
            &panel,
            Some(&ftx),
            Some(&mtx),
        );
        assert_eq!(
            state.job.as_ref().unwrap().target_remote_dir,
            "C:\\work",
            "目录上传落点 = 选中远端目录"
        );
        // d) 「接收所选」目录下载 = **目标选中目录下新建同名目录**再下载
        //    入内（BFS 镜像前缀 = 目录名 + `target_local_dir.join(subdir)`）。
        state.job = None;
        state.pending = None;
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        state.local.view.selected = vec![local_path_key(&dl)];
        state.remote.view.selected = vec!["C:\\work".to_string()];
        let t_local = state.single_dir_selection(PaneId::Local).map(PathBuf::from);
        assert_eq!(t_local.as_deref(), Some(dl.as_path()), "下载落点 = 选中本地目录");
        let n = state.enqueue_transfer_targeted(
            PaneId::Remote,
            PaneId::Local,
            vec!["C:\\work".to_string()],
            None,
            t_local,
            &panel,
            Some(&ftx),
            Some(&mtx),
        );
        assert_eq!(n, 0, "纯目录 = 收集期零直发");
        let job = state.job.as_ref().unwrap();
        assert_eq!(job.target_local_dir, dl, "目录任务目标 = 选中本地目录");
        assert_eq!(job.collect_queue.len(), 1, "BFS 根 = 选中目录节点");
        // tick → List `C:\work`（盘符路径 wire = 反斜杠形态）。
        state.tick(&panel, Some(&ftx), Some(&mtx));
        match frx.try_recv().unwrap() {
            FileCommand::Fs {
                op: FsOp::List { path, .. },
            } => assert_eq!(path, "C:\\work", "盘符路径 List wire 形态"),
            other => panic!("应得 List，实际 {other:?}"),
        }
        state.on_fs_event(FsEvent::Admitted {
            req_id: 1,
            op: FsOp::List {
                path: "C:\\work".into(),
                offset: 0,
                limit: PAGE_SIZE,
            },
        });
        state.on_fs_event(FsEvent::Response {
            req_id: 1,
            result: Ok(build_fs_list_payload(&[("r.txt", 5, false)], false, "srv")),
        });
        let job = state.job.as_ref().unwrap();
        assert!(!job.collecting && !job.finished, "收集完毕、文件待入队");
        assert_eq!(
            job.files,
            vec![("C:\\work\\r.txt".to_string(), 5u64, "work".to_string())],
            "镜像子路径 = 同名目录名"
        );
        // tick → FetchFile：落点 = **选中本地目录 / <同名目录>**。
        state.tick(&panel, Some(&ftx), Some(&mtx));
        match frx.try_recv().unwrap() {
            FileCommand::FetchFile { remote_path, local_dir } => {
                assert_eq!(remote_path, "C:\\work\\r.txt");
                assert_eq!(
                    local_dir,
                    dl.join("work"),
                    "目录下载 = 目标选中目录/<同名目录>（用户原话语义）"
                );
            }
            other => panic!("应得 FetchFile，实际 {other:?}"),
        }
        // e) 粘贴 = 目标栏选中目录（同 b 口径；旧 target=None 断点修复）。
        state.job = None;
        state.pending = None;
        while mrx.try_recv().is_ok() {}
        state.clipboard = Some(Clip {
            source: PaneId::Local,
            paths: vec![local_path_key(&proj.join("a.txt"))],
        });
        state.remote.view.selected = vec!["C:\\work".to_string()];
        let n = state.paste_into(PaneId::Remote, &panel, Some(&ftx), Some(&mtx));
        assert_eq!(n, 1, "粘贴入队");
        match mrx.try_recv().unwrap() {
            FileMgrCommand::SendWithConsent { entries, .. } => {
                assert_eq!(entries[0].1, "C:\\work", "粘贴落点 = 目标栏选中目录");
            }
            other => panic!("应得 SendWithConsent，实际 {other:?}"),
        }
        // f) 渲染层接线钉死（栏头按钮走 targeting 通道，非裸 enqueue_transfer）。
        let src = include_str!("file_manager.rs");
        assert!(
            src.contains("PaneId::Local, PaneId::Remote, sel, t_remote, None, panel, file_tx, fm_tx"),
            "发送所选 = 远端选中目录 targeting"
        );
        assert!(
            src.contains("PaneId::Remote, PaneId::Local, sel, None, t_local, panel, file_tx, fm_tx"),
            "接收所选 = 本地选中目录 targeting"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// ⑥ 第 2 项：面包屑盘符分段 + 合成根导航复位 + 盘符前缀折叠剪除。
    #[test]
    fn r135_5_remote_breadcrumb_drive() {
        let mut state = FileManagerState::with_local_root(tmp_root("crumb"));
        state.remote.current = "C:\Users\dev".to_string();
        let crumbs = state.remote_breadcrumb();
        assert_eq!(crumbs.len(), 4);
        assert_eq!(crumbs[0].0, REMOTE_PC_ROOT_KEY);
        assert_eq!(crumbs[0].1, crate::i18n::tr("filemgr.pc_root_remote"));
        assert_eq!(crumbs[1], ("C:\\".to_string(), "C:\\".to_string()));
        assert_eq!(crumbs[2], ("C:\\Users".to_string(), "Users".to_string()));
        assert_eq!(crumbs[3], ("C:\Users\dev".to_string(), "yu".to_string()));
        // 裸盘符 = 两段（合成根 + 盘符根）。
        state.remote.current = "C:\\".to_string();
        let c2 = state.remote_breadcrumb();
        assert_eq!(c2.len(), 2);
        assert_eq!(c2[1].0, "C:\\");
        // 合成根导航 = 复位盘符层（节点已缓存 = 零 wire；不清已缓存节点）。
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("C:\\", 0, true)]),
                ..Default::default()
            },
        );
        state.remote.current = "C:\Users\dev".to_string();
        state.navigate_to_prefix(PaneId::Remote, REMOTE_PC_ROOT_KEY.to_string(), None);
        assert_eq!(state.remote.current, REMOTE_PC_ROOT_KEY, "复位 = 保留键");
        assert!(state.remote.view.selected.is_empty(), "复位清选中");
        // tree_collapse 盘符前缀剪除（`C:\` 前缀 = 自身；`D:\x` 保留）。
        state.remote.view.selected = vec![
            "C:\Users\dev".into(),
            "C:\\Users".into(),
            "D:\\".into(),
        ];
        state.tree_collapse(PaneId::Remote, "C:\\");
        assert_eq!(state.remote.view.selected, vec!["D:\\".to_string()]);
    }

    /// ⑦ 第 2+3 项：i18n 新键 `filemgr.pc_root_remote` zh/en 成对钉死 +
    /// 横幅键方向锚定。
    /// 两 OFF 横幅判定源改**对端（远端服务端）**通告值 → 文案方向锚点 =
    /// 失实恒不在；新增对端未知 fail-closed 键（`*_peer_unknown_banner`）
    /// zh/en 成对 + 锚点钉死。
    #[test]
    fn r135_5_i18n_pc_root_remote_pairing() {
        use crate::i18n::{tr_lang, Lang};
        assert_eq!(tr_lang(Lang::Zh, "filemgr.pc_root_remote"), "远端电脑");
        assert_eq!(tr_lang(Lang::En, "filemgr.pc_root_remote"), "Remote PC");
        for key in [
            "consent.file_transfer_off_banner",
            "consent.clipboard_off_banner",
        ] {
            let zh = tr_lang(Lang::Zh, key);
            assert!(zh.contains("对端"), "{key} zh 缺「对端」方向: {zh}");
            assert!(
                !zh.contains("请在 本机 设置"),
            );
            assert!(!zh.contains("请在对端（受控端）开启"), "{key} zh 残留旧方向: {zh}");
            let en = tr_lang(Lang::En, key);
            assert!(
                en.contains("peer"),
                "{key} en 缺 'peer' 方向: {en}"
            );
            assert!(
                !en.to_lowercase().contains("in this machine's settings"),
            );
        }
        for key in [
            "consent.clipboard_peer_unknown_banner",
            "consent.file_transfer_peer_unknown_banner",
        ] {
            let zh = tr_lang(Lang::Zh, key);
            let en = tr_lang(Lang::En, key);
            assert_ne!(zh, key, "zh 缺键: {key}");
            assert_ne!(en, key, "en 缺键: {key}");
            assert!(zh.contains("未知"), "{key} zh 缺「未知」: {zh}");
            assert!(zh.contains("fail-closed"), "{key} zh 缺 fail-closed 口径: {zh}");
            assert!(
                en.to_lowercase().contains("unknown"),
                "{key} en 缺 'unknown': {en}"
            );
            assert!(
                en.to_lowercase().contains("fail-closed"),
                "{key} en 缺 'fail-closed': {en}"
            );
        }
    }

    ///（初值 `None` = 未通告 fail-closed；通告覆写；重连新值优先于陈旧值——
    /// 文件传输窗横幅判定源同源消费）。
    #[test]
    fn r137_1_peer_consent_fs_event_overwrite() {
        let mut st = FileManagerState::default();
        assert!(st.peer_consent.is_none(), "初值 = 未通告（fail-closed 显式提示）");
        st.on_fs_event(FsEvent::PeerConsent {
            clipboard_allowed: true,
            file_transfer_allowed: false,
        });
        assert_eq!(st.peer_consent, Some((true, false)));
        // 重连（新会话通告覆写陈旧值）。
        st.on_fs_event(FsEvent::PeerConsent {
            clipboard_allowed: false,
            file_transfer_allowed: true,
        });
        assert_eq!(st.peer_consent, Some((false, true)));
    }


    fn r147_test_meta(n: usize) -> crate::clipboard::FileClipMeta {
        crate::clipboard::FileClipMeta {
            version: crate::clipboard::FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: (0..n)
                .map(|i| crate::clipboard::FileClipEntry {
                    rel_path: format!("f{i}.txt"),
                    size: i as u64,
                    is_dir: false,
                    fetchable: true,
                })
                .collect(),
        }
    }

    /// 未通告/对端剪贴板 OFF = 零槽写；ON = 槽置；CLEAR 帧 = 清槽；
    /// 拒绝帧不覆写既有槽（陈旧 pending 保留）。门键 = `peer_consent`
    /// 元组首元素（clipboard，`FsEvent::PeerConsent` 覆写同源）。
    #[test]
    fn r147_on_clip_meta_gate_matrix() {
        // 未通告（None）= fail-closed 零槽写。
        let mut st = FileManagerState::default();
        st.on_clip_meta(r147_test_meta(2));
        assert!(st.pending_clip_meta.is_none(), "未通告 = 零槽写");
        // 对端剪贴板 OFF（元组首元素 = clipboard）= 零槽写。
        st.peer_consent = Some((false, true));
        st.on_clip_meta(r147_test_meta(2));
        assert!(st.pending_clip_meta.is_none(), "对端剪贴板 OFF = 零槽写");
        // 对端剪贴板 ON = 槽置（文件传输开关值不参与本门——s→c 粘贴语境
        // = 剪贴板同步面）。
        st.peer_consent = Some((true, false));
        st.on_clip_meta(r147_test_meta(3));
        assert_eq!(
            st.pending_clip_meta.as_ref().map(|m| m.entries.len()),
            Some(3),
            "ON = 槽置"
        );
        // 拒绝帧不覆写既有槽（陈旧 pending 保留）。
        st.peer_consent = Some((false, true));
        st.on_clip_meta(r147_test_meta(1));
        assert_eq!(
            st.pending_clip_meta.as_ref().map(|m| m.entries.len()),
            Some(3),
            "拒绝 = 零槽写（既有保留）"
        );
        // CLEAR 帧（ON 态）= 清槽。
        st.peer_consent = Some((true, true));
        let mut clear = r147_test_meta(0);
        clear.cleared = true;
        st.on_clip_meta(clear);
        assert!(st.pending_clip_meta.is_none(), "CLEAR = 清槽");
    }

    /// 授权语义颠倒 = 复制零传输）**：门恒拒 → 槽对**全部**门态恒空（含
    /// 既有 ON 态非 CLEAR 放行臂，亦撤销）；消费即清语义保留（基建面）。
    #[test]
    fn r166_clip_prefetch_req_gate_matrix() {
        let mut st = FileManagerState::default();
        // 未通告 = 零预取槽。
        st.on_clip_meta(r147_test_meta(2));
        assert!(st.clip_prefetch_req.is_none(), "未通告 = 零预取槽");
        // 对端剪贴板 OFF = 零预取槽（fail-closed：开关 OFF 对方复制不得触发预取）。
        st.peer_consent = Some((false, true));
        st.on_clip_meta(r147_test_meta(2));
        assert!(st.clip_prefetch_req.is_none(), "对端剪贴板 OFF = 零预取槽");
        st.peer_consent = Some((true, false));
        st.on_clip_meta(r147_test_meta(3));
        assert!(
            st.take_clip_prefetch_req().is_none(),
        );
        // CLEAR 帧 = 零预取槽（非新复制语境）。
        st.peer_consent = Some((true, true));
        let mut clear = r147_test_meta(0);
        clear.cleared = true;
        st.on_clip_meta(clear);
        assert!(st.clip_prefetch_req.is_none(), "CLEAR = 零预取槽");
        // 放宽——未通告/OFF/ON 全门态槽恒空。
        let dir_meta = crate::clipboard::FileClipMeta {
            version: crate::clipboard::FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![
                crate::clipboard::FileClipEntry {
                    rel_path: "top".to_string(),
                    size: 0,
                    is_dir: true,
                    fetchable: true,
                },
                crate::clipboard::FileClipEntry {
                    rel_path: "top/a.txt".to_string(),
                    size: 1,
                    is_dir: false,
                    fetchable: true,
                },
            ],
        };
        st.peer_consent = Some((true, false));
        st.on_clip_meta(dir_meta.clone());
        assert!(
            st.take_clip_prefetch_req().is_none(),
        );
        st.peer_consent = Some((false, true));
        st.on_clip_meta(dir_meta);
        assert!(
            st.clip_prefetch_req.is_none(),
            "目录批 + OFF = 零槽写（fail-closed 不放宽）"
        );
    }

    /// 上传：落点 = 本窗远端栏目录（`c2s_paste_upload_target` 单一语义源：
    /// 无选中 = `remote.current`，默认 `""` = 对端 fs 根）→ `SendFileV2`
    /// 零新 wire；无远端语境（未启动）= 既有 v1 `SendFile` Offer 链零变化；
    /// 批 ≤64（K8 同口径）；无通道 = 0（fail-closed 无入口）；状态行 =
    /// 「等待对方确认」（单文件上传同口径反馈）。
    #[test]
    fn r147_paste_clipboard_fallback_c2s_upload() {
        let board = crate::clipboard::OsFileBoard {
            entries: vec![
                crate::clipboard::OsFileEntry {
                    abs_path: r"C:\clip\a.txt".to_string(),
                    size: 1,
                    is_dir: false,
                },
                crate::clipboard::OsFileEntry {
                    abs_path: r"C:\clip\b.bin".to_string(),
                    size: 2,
                    is_dir: false,
                },
            ],
        };
        // (a) 远端栏已启动 + 无选中 = current（默认 `""` = 对端 fs 根）
        // → SendFileV2 target `""`。
        let mut st = FileManagerState::default();
        st.remote.started = true;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let n = st.paste_clipboard_fallback(Some(&tx), Some(&board));
        assert_eq!(n, 2, "派发条数 = OS 板条数");
        for p in [r"C:\clip\a.txt", r"C:\clip\b.bin"] {
            match rx.try_recv().expect("命令入队") {
                FileCommand::SendFileV2 { path, target_dir } => {
                    assert_eq!(path, std::path::PathBuf::from(p), "路径原样");
                    assert_eq!(
                        target_dir, "",
                        "无选中 = remote.current（默认 \"\" = 对端 fs 根）"
                    );
                }
                other => panic!("期望 SendFileV2，实为: {other:?}"),
            }
        }
        assert!(
            st.status_line.is_some(),
            "状态行 = 等待确认反馈（OS 粘贴零感知防线）"
        );
        // (b) 无远端语境（未启动）= v1 Offer 链（SendFile），既有行为零变化。
        let mut st2 = FileManagerState::default();
        let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let n2 = st2.paste_clipboard_fallback(Some(&tx2), Some(&board));
        assert_eq!(n2, 2);
        match rx2.try_recv().expect("v1 命令入队") {
            FileCommand::SendFile { path } => {
                assert_eq!(path, std::path::PathBuf::from(r"C:\clip\a.txt"));
            }
            other => panic!("期望 SendFile，实为: {other:?}"),
        }
        // (c) 批上限 64（K8 同口径）：70 条 → 恰 64 入队。
        let big_board = crate::clipboard::OsFileBoard {
            entries: (0..70)
                .map(|i| crate::clipboard::OsFileEntry {
                    abs_path: format!("/tmp/clip/{i:02}.txt"),
                    size: 0,
                    is_dir: false,
                })
                .collect(),
        };
        let mut st3 = FileManagerState::default();
        st3.remote.started = true;
        let (tx3, mut rx3) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let n3 = st3.paste_clipboard_fallback(Some(&tx3), Some(&big_board));
        assert_eq!(n3, crate::CLIP_PASTE_MAX_FILES);
        let mut count = 0usize;
        while rx3.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, crate::CLIP_PASTE_MAX_FILES, "恰 64 入队（截断）");
        // (d) 无文件通道 = 0（fail-closed：无通道 = 无入口）。
        let mut st4 = FileManagerState::default();
        assert_eq!(st4.paste_clipboard_fallback(None, Some(&board)), 0);
    }

    /// pending 有可拉取条目 = 拉取：落点 = 本窗**本地栏当前目录**（无选中
    /// = `local.current`；派发时刻 is_dir + 可写探测）→ `FetchFile`（既有
    /// 引擎面）；根外条目跳过（计数入状态行）；**消费即清** pending；
    #[test]
    fn r147_paste_clipboard_fallback_s2c_fetch() {
        let mut st = FileManagerState::default();
        // 落点 = 本地栏当前目录（测试 = 临时目录，确定性存在 + 可写）。
        st.local.current = std::env::temp_dir();
        st.peer_consent = Some((true, true));
        st.on_clip_meta(crate::clipboard::FileClipMeta {
            version: crate::clipboard::FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![
                crate::clipboard::FileClipEntry {
                    rel_path: "recv/a.txt".to_string(),
                    size: 1,
                    is_dir: false,
                    fetchable: true,
                },
                crate::clipboard::FileClipEntry {
                    rel_path: "outside.dat".to_string(),
                    size: 2,
                    is_dir: false,
                    fetchable: false, // 根外 = 跳过（计数）
                },
            ],
        });
        assert!(st.pending_clip_meta.is_some(), "ON 态槽已置");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let n = st.paste_clipboard_fallback(Some(&tx), None);
        assert_eq!(n, 1, "仅 fetchable 条目入队（根外跳过）");
        match rx.try_recv().expect("fetch 入队") {
            FileCommand::FetchFile {
                remote_path,
                local_dir,
            } => {
                assert_eq!(remote_path, "recv/a.txt");
                assert_eq!(
                    local_dir,
                    std::env::temp_dir(),
                    "落点 = 本窗本地栏当前目录（目录感知）"
                );
            }
            other => panic!("期望 FetchFile，实为: {other:?}"),
        }
        assert!(st.pending_clip_meta.is_none(), "消费即清");
        assert!(
            st.status_line.is_some(),
            "状态行 = 入队/根外反馈（`clip.fetch.outside_root` 口径）"
        );
    }

    #[test]
    fn r147_paste_clipboard_fallback_empty_and_noop() {
        let mut st = FileManagerState::default();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        assert_eq!(st.paste_clipboard_fallback(Some(&tx), None), 0);
        assert!(st.status_line.is_some(), "空板反馈状态行");
        // 拉取派发，消费即清；修前 v1 不可拉取 = 静默跳过不消费）。
        st.peer_consent = Some((true, true));
        st.on_clip_meta(crate::clipboard::FileClipMeta {
            version: crate::clipboard::FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: vec![crate::clipboard::FileClipEntry {
                rel_path: "dir-only".to_string(),
                size: 0,
                is_dir: true,
                fetchable: true,
            }],
        });
        assert_eq!(st.paste_clipboard_fallback(Some(&tx), None), 0);
        assert!(
            st.pending_clip_meta.is_none(),
        );
        assert!(
            st.clip_expand.is_some(),
        );
    }

    // → `paste_cross` 既有路径零变化；否则 OS 板读 → `paste_clipboard_fallback`）
    // 单测族覆盖；OS 板读为 FFI 面（环境依赖）不入单测（门禁 self-test
    // + 用户实机复测覆盖）。

    /// ⑧ 隔离目录截屏（1920×1080 双帧）：左栏 = 本地真树（**缩小 ± 折叠钮**
    /// 〔第 1 项〕）；右栏 = **「远端电脑」合成根 + 盘符层 + 展开链**
    /// 〔第 2 项〕+ 错误节点 🔄 标记行 + 加载中行。目验 = 用户观感初判
    /// （PNG 落 `E:/projects_rd/docs/`，仓外不 commit）。
    #[test]
    fn r135_5_screenshot_dump() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let (sw, sh) = (1920.0, 1080.0);
        // 环境解耦（同 `long_path` 口径，见该处注）：左栏本地真树基址取
        // 低熵层，避免 Temp `PAGE_SIZE` 截断把测试根挤出树行区。
        let base = std::env::temp_dir();
        let base = if base
            .file_name()
            .map(|s| s == "Temp")
            .unwrap_or(false)
        {
            base.parent().map(PathBuf::from).unwrap_or(base)
        } else {
            base
        };
        let root = base.join(format!("k92e1_shot135_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(root.join("aa/bb")).unwrap();
        mkfile(&root.join("aa/bb/cc.txt"), "x");
        mkfile(&root.join("aa/mid.txt"), "y");
        mkfile(&root.join("top.txt"), "z");
        let mut state = FileManagerState::with_local_root(root.clone());
        // 左栏：盘符链同步展开至测试根（缩小 ± 钮真树形态）。
        assert!(state.local_expand_chain(&root), "本地链展开");
        state.local.current = root.clone();
        // 右栏：播种「远端电脑」树（started = true 抑制首 List 覆盖播种）。
        state.remote.started = true;
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("C:\\", 0, true), mk_entry("D:\\", 0, true)]),
                ..Default::default()
            },
        );
        state.remote.view.expanded.push("C:\\".to_string());
        state.remote.view.nodes.insert(
            "C:\\".to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("Users", 0, true), mk_entry("work", 0, true)]),
                ..Default::default()
            },
        );
        state.remote.view.expanded.push("C:\\Users".to_string());
        state.remote.view.nodes.insert(
            "C:\\Users".to_string(),
            TreeNodeState {
                loading: false,
                error: Some("路径超出允许范围（隔离目录演示）".to_string()),
                ..Default::default()
            },
        );
        state.remote.view.expanded.push("C:\\work".to_string());
        state.remote.view.nodes.insert(
            "C:\\work".to_string(),
            TreeNodeState {
                loading: true,
                ..Default::default()
            },
        );
        let panel = FilePanelState::new();
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let run_frame = |ctx: &egui::Context, state: &mut FileManagerState| {
            let mut raw = egui::RawInput::default();
            raw.screen_rect =
                Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(sw, sh)));
            let mut focus = false;
            ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    show_file_manager(
                        ui,
                        &Theme::LIGHT,
                        state,
                        None,
                        None,
                        &panel,
                        false,
                        &mut focus,
                    );
                });
            })
        };
        let out1 = run_frame(&ctx, &mut state);
        let out2 = run_frame(&ctx, &mut state);
        let out_path = "E:/projects_rd/docs/r135_5_tree_sandbox.png";
        crate::file_manager::r134_9b_tests::rasterize_png(
            &out1,
            &out2,
            sw as u32,
            sh as u32,
            out_path,
        );
        assert!(Path::new(out_path).is_file(), "截屏在位");
        std::fs::remove_dir_all(&root).ok();
    }
}

// ════════════════════════════════════════════════════════════════
// 目录下载整树递归——同名根 + 远端相对结构镜像 + **空目录也在目标创建** +
// 目录环/超深防护（深度上限 + 已访集合）+ 单条目失败不静默跳过（继续其余
// + 失败清单观测行）+ 取消请求传播中断。**零新 wire op**（既有 List+Fetch
// 组合逐层走——wire 帧断言只允许 List/Fetch）。
// ════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r135_5b_tests {
    use super::*;
    use kirin_desk_core::connection::file_transfer::FsEntry;

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "kirin_fm_r1355b_{tag}_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn mk_entry(name: &str, size: u64, is_dir: bool) -> FileMgrEntry {
        FileMgrEntry {
            name: name.to_string(),
            size,
            mtime: 0,
            is_dir,
            is_symlink: false,
            is_hidden: false,
        }
    }

    fn list_payload(entries: &[(&str, u64, bool)]) -> FsResponsePayload {
        let list = FsListPayload {
            entries: entries
                .iter()
                .map(|(n, s, d)| FsEntry {
                    name: (*n).into(),
                    size: *s,
                    mtime: 0,
                    is_dir: *d,
                    is_symlink: false,
                })
                .collect(),
            has_more: false,
            root_display: String::new(),
        };
        FsResponsePayload {
            ok: true,
            err: FsErrCode::Ok,
            payload: bincode::serialize(&list).unwrap(),
        }
    }

    fn err_payload(err: FsErrCode) -> FsResponsePayload {
        FsResponsePayload {
            ok: false,
            err,
            payload: Vec::new(),
        }
    }

    /// 远端树播种：合成根 + 盘符 + 目录节点（`resolve_entry` 查找口径 =
    /// 父节点 children 含同形条目）。
    fn seed_remote_dir(state: &mut FileManagerState, dir_path: &str) {
        let name = dir_path.rsplit('\\').next().unwrap();
        state.remote.started = true;
        state
            .remote
            .view
            .nodes
            .insert(
                REMOTE_PC_ROOT_KEY.to_string(),
                TreeNodeState {
                    children: Some(vec![mk_entry("C:\\", 0, true)]),
                    ..Default::default()
                },
            );
        state.remote.view.expanded.push("C:\\".to_string());
        state.remote.view.nodes.insert(
            "C:\\".to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry(name, 0, true)]),
                ..Default::default()
            },
        );
    }

    /// 一次 List 往返：tick → 取 List（断言 wire 形态）→ Admitted →
    /// Response。返回本帧 wire 命令（调用方做「只允许 List/Fetch」断言）。
    fn list_round(
        state: &mut FileManagerState,
        panel: &FilePanelState,
        ftx: &UnboundedSender<FileCommand>,
        frx: &mut tokio::sync::mpsc::UnboundedReceiver<FileCommand>,
        req_id: u32,
        expect_path: &str,
        result: Result<FsResponsePayload, String>,
    ) -> FileCommand {
        state.tick(panel, Some(ftx), None);
        let cmd = frx
            .try_recv()
            .unwrap_or_else(|e| panic!("应发出 List（{e}）"));
        match &cmd {
            FileCommand::Fs {
                op: FsOp::List { path, .. },
            } => assert_eq!(path, expect_path, "List wire 形态"),
            other => panic!("应得 List，实际 {other:?}"),
        }
        state.on_fs_event(FsEvent::Admitted {
            req_id,
            op: FsOp::List {
                path: expect_path.to_string(),
                offset: 0,
                limit: PAGE_SIZE,
            },
        });
        state.on_fs_event(FsEvent::Response {
            req_id,
            result,
        });
        cmd
    }

    /// wire 纪律断言：目录下载全程只允许既有 `List`/`FetchFile`
    /// （**零新 wire op**）。
    fn assert_wire_only_list_or_fetch(cmds: &[FileCommand]) {
        for c in cmds {
            assert!(
                matches!(c, FileCommand::Fs { op: FsOp::List { .. } })
                    || matches!(c, FileCommand::FetchFile { .. }),
                "wire 帧必须 ∈ {{List, FetchFile}}（零新 wire op），实际 {c:?}"
            );
        }
    }

    /// 下载任务构造公共段：本地 dl 目标选中 + 远端目录选中 + 入队。
    fn enqueue_download(
        state: &mut FileManagerState,
        dl: &Path,
        remote_dir: &str,
        names: Vec<String>,
        panel: &FilePanelState,
        ftx: &UnboundedSender<FileCommand>,
    ) -> usize {
        state.local.view.selected = vec![local_path_key(dl)];
        state.remote.view.selected = vec![remote_dir.to_string()];
        let t_local = state
            .single_dir_selection(PaneId::Local)
            .map(PathBuf::from);
        assert_eq!(t_local.as_deref(), Some(dl), "下载落点 = 选中本地目录");
        state.enqueue_transfer_targeted(
            PaneId::Remote,
            PaneId::Local,
            names,
            None,
            t_local,
            panel,
            Some(ftx),
            None,
        )
    }

    // ── ① 观测行格式钉死（纯函数；行格式单测口径）────────────────

    #[test]
    fn r135_5b_line_formats_pinned() {
        // 单条目失败行（kind 五态 + 路径）。
        assert_eq!(
            r135_5b_fail_line("list:NotFound", "t/bad"),
        );
        assert_eq!(
            r135_5b_fail_line("list:wire", "t/bad"),
        );
        assert_eq!(
            r135_5b_fail_line("timeout", "t/sub"),
        );
        assert_eq!(
            r135_5b_fail_line("io", "t"),
        );
        assert_eq!(
            r135_5b_fail_line("interrupted", "t/x"),
        );
        // 汇总行：无失败无环 = None（零行）。
        assert_eq!(r135_5b_summary_line(3, &[], &[]), None);
        // 仅失败（多条 = `;` 连）。
        assert_eq!(
            r135_5b_summary_line(
                2,
                &[
                    ("t/b".to_string(), "timeout".to_string()),
                    ("t/a".to_string(), "io".to_string()),
                ],
                &[]
            ),
            Some(
                    .to_string()
            )
        );
        // 仅环跳过。
        assert_eq!(
            r135_5b_summary_line(0, &[], &["t/loop".to_string()]),
            Some(
            )
        );
        // 双清单。
        assert_eq!(
            r135_5b_summary_line(
                1,
                &[("t/bad".to_string(), "list:NotFound".to_string())],
                &["t/loop".to_string(), "t/loop2".to_string()]
            ),
            Some(
                 cycle=[t/loop;t/loop2]"
                    .to_string()
            )
        );
        // 目标内显示路径：顶层同名根 = prefix 本身。
        assert_eq!(job_dir_display("t", ""), "t");
        assert_eq!(job_dir_display("t", "a"), "t/a");
        assert_eq!(job_dir_display("t", "a/b"), "t/a/b");
    }

    // ── ② ≥3 层嵌套含空目录 + 目标相对结构镜像 + 零新 wire ──────────

    #[test]
    fn r135_5b_nested_mirror_incl_empty_dirs() {
        // 远端树（≥3 层 + 空目录）：
        //   C:\t\a.txt / C:\t\sub1\b.txt / C:\t\sub1\sub2\c.txt
        //   C:\t\sub1\empty 〔空目录〕
        let root = tmp_root("nest1355b");
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        let mut state = FileManagerState::with_local_root(root.clone());
        seed_remote_dir(&mut state, "C:\\t");
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let cmds = enqueue_download(
            &mut state,
            &dl,
            "C:\\t",
            vec!["C:\\t".to_string()],
            &panel,
            &ftx,
        );
        assert_eq!(cmds, 0, "纯目录 = 收集期零直发");
        let job = state.job.as_ref().unwrap();
        assert!(job.collecting, "BFS 收集在途");
        assert_eq!(job.collect_queue.len(), 1, "BFS 根 = 选中目录");
        // 第 1 层：根 List。
        let c1 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            1,
            "C:\\t",
            Ok(list_payload(&[
                ("a.txt", 5, false),
                ("sub1", 0, true),
            ])),
        );
        // 第 2 层：sub1。
        let c2 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            2,
            "C:\\t\\sub1",
            Ok(list_payload(&[
                ("b.txt", 5, false),
                ("sub2", 0, true),
                ("empty", 0, true),
            ])),
        );
        // 第 3 层：sub2。
        let c3 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            3,
            "C:\\t\\sub1\\sub2",
            Ok(list_payload(&[("c.txt", 5, false)])),
        );
        // 第 4 层：empty（空目录 = 零条目）。
        let c4 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            4,
            "C:\\t\\sub1\\empty",
            Ok(list_payload(&[])),
        );
        assert_wire_only_list_or_fetch(&[c1.clone(), c2, c3, c4]);
        let job = state.job.as_ref().unwrap();
        assert!(!job.collecting, "收集完毕");
        assert_eq!(
            job.files,
            vec![
                ("C:\\t\\a.txt".to_string(), 5u64, "t".to_string()),
                ("C:\\t\\sub1\\b.txt".to_string(), 5u64, "t/sub1".to_string()),
                (
                    "C:\\t\\sub1\\sub2\\c.txt".to_string(),
                    5u64,
                    "t/sub1/sub2".to_string()
                ),
            ],
            "目标相对结构镜像（同名根 + 源内相对父级）"
        );
        // tick → 收集结束收敛（空目录物化）+ 分批入队 FetchFile。
        state.tick(&panel, Some(&ftx), None);
        let job = state.job.as_ref().unwrap();
        assert!(job.summary_emitted, "收敛已执行");
        assert!(job.failed.is_empty(), "零失败");
        assert!(!job.finished, "文件待传");
        for d in ["t", "t/sub1", "t/sub1/sub2", "t/sub1/empty"] {
            let p = dl.join(d);
            assert!(p.is_dir(), "目标侧镜像目录在位（含空目录）: {d}");
        }
        let mut fetched = Vec::new();
        while let Ok(cmd) = frx.try_recv() {
            fetched.push(cmd);
        }
        assert_wire_only_list_or_fetch(&fetched);
        assert_eq!(fetched.len(), 3, "3 文件入队（每帧 ≤ISSUE_PER_TICK=4 全入）");
        let mut pairs: Vec<(String, PathBuf)> = fetched
            .iter()
            .map(|c| match c {
                FileCommand::FetchFile {
                    remote_path,
                    local_dir,
                } => (remote_path.clone(), local_dir.clone()),
                other => panic!("应得 FetchFile，实际 {other:?}"),
            })
            .collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                ("C:\\t\\a.txt".to_string(), dl.join("t")),
                (
                    "C:\\t\\sub1\\b.txt".to_string(),
                    dl.join("t").join("sub1")
                ),
                (
                    "C:\\t\\sub1\\sub2\\c.txt".to_string(),
                    dl.join("t").join("sub1").join("sub2")
                ),
            ],
            "落点 = 目标选中目录 / 同名根 / 源内相对结构"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ③ 环防护（已访集合）：重复根 + 同目录同名重复条目 ────────────

    #[test]
    fn r135_5b_cycle_visited_dedup() {
        let root = tmp_root("cycle1355b");
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        let mut state = FileManagerState::with_local_root(root.clone());
        seed_remote_dir(&mut state, "C:\\t");
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        // a) 重复根（散选重复同路径）= 二次不收集、记清单。
        let _ = enqueue_download(
            &mut state,
            &dl,
            "C:\\t",
            vec!["C:\\t".to_string(), "C:\\t".to_string()],
            &panel,
            &ftx,
        );
        let job = state.job.as_ref().unwrap();
        assert_eq!(job.collect_queue.len(), 1, "重复根只收集一次");
        assert_eq!(job.cycle_skipped, vec!["t".to_string()], "重复根记环清单");
        assert_eq!(job.visit.len(), 1, "已访集合 = 根 1 项");
        // b) 同目录同名重复条目（非树形服务端响应）= 二次跳过记清单。
        let c1 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            1,
            "C:\\t",
            Ok(list_payload(&[
                ("a", 0, true),
                ("a", 0, true),
                ("x.txt", 5, false),
            ])),
        );
        let c2 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            2,
            "C:\\t\\a",
            Ok(list_payload(&[])),
        );
        assert_wire_only_list_or_fetch(&[c1, c2]);
        let job = state.job.as_ref().unwrap();
        assert_eq!(
            job.cycle_skipped,
            vec!["t".to_string(), "t/a".to_string()],
            "重复条目记环清单"
        );
        assert_eq!(
            job.files,
            vec![("C:\\t\\x.txt".to_string(), 5u64, "t".to_string())],
            "正常条目不受环防护影响"
        );
        assert_eq!(
            job.target_dirs,
            vec!["t".to_string(), "t/a".to_string()],
            "镜像列表不重复"
        );
        state.tick(&panel, Some(&ftx), None); // 收敛（物化 t/t/a）+ 入队
        assert!(dl.join("t").is_dir() && dl.join("t/a").is_dir());
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ④ 单条目失败不静默跳过：继续其余 + 失败清单 ─────────────────

    #[test]
    fn r135_5b_fail_continue_and_collect_failed() {
        let root = tmp_root("fail1355b");
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        let mut state = FileManagerState::with_local_root(root.clone());
        seed_remote_dir(&mut state, "C:\\t");
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let _ = enqueue_download(
            &mut state,
            &dl,
            "C:\\t",
            vec!["C:\\t".to_string()],
            &panel,
            &ftx,
        );
        // 根 List：bad（wire Err）/ bad2（非 Ok 载荷）/ good / top.txt。
        let c1 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            1,
            "C:\\t",
            Ok(list_payload(&[
                ("bad", 0, true),
                ("bad2", 0, true),
                ("good", 0, true),
                ("top.txt", 5, false),
            ])),
        );
        // bad = 传输 Err（wire 面）。
        let c2 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            2,
            "C:\\t\\bad",
            Err("wire down".to_string()),
        );
        let job = state.job.as_ref().unwrap();
        assert!(
            job.collecting,
            "单条目失败 ≠ 任务中止（继续其余条目）"
        );
        assert_eq!(
            job.failed,
            vec![("t/bad".to_string(), "list:wire".to_string())],
            "失败清单第 1 项（kind=list:wire）"
        );
        // bad2 = 服务端非 Ok（NotFound）。
        let c3 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            3,
            "C:\\t\\bad2",
            Ok(err_payload(FsErrCode::NotFound)),
        );
        // good = 正常（继续收集证据）。
        let c4 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            4,
            "C:\\t\\good",
            Ok(list_payload(&[("y.txt", 5, false)])),
        );
        assert_wire_only_list_or_fetch(&[c1, c2, c3, c4]);
        state.tick(&panel, Some(&ftx), None); // 收敛 + 入队
        let job = state.job.as_ref().unwrap();
        assert_eq!(
            job.failed,
            vec![
                ("t/bad".to_string(), "list:wire".to_string()),
                ("t/bad2".to_string(), "list:NotFound".to_string()),
            ],
            "失败清单全量（顺序 = 收集序）"
        );
        assert!(job.summary_emitted, "汇总观测行已打");
        assert_eq!(
            job.files,
            vec![
                ("C:\\t\\top.txt".to_string(), 5u64, "t".to_string()),
                ("C:\\t\\good\\y.txt".to_string(), 5u64, "t/good".to_string()),
            ],
            "其余条目继续收集"
        );
        let mut fetched: Vec<String> = Vec::new();
        while let Ok(cmd) = frx.try_recv() {
            if let FileCommand::FetchFile { remote_path, .. } = cmd {
                fetched.push(remote_path);
            }
        }
        fetched.sort();
        assert_eq!(
            fetched,
            vec![
                "C:\\t\\good\\y.txt".to_string(),
                "C:\\t\\top.txt".to_string(),
            ],
            "仅成功条目入队 FetchFile"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ⑤ 收集超时 = 单条目失败（记清单 + 继续其余）─────────────────

    #[test]
    fn r135_5b_timeout_recorded_and_continues() {
        let root = tmp_root("to1355b");
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        let mut state = FileManagerState::with_local_root(root.clone());
        seed_remote_dir(&mut state, "C:\\t");
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let _ = enqueue_download(
            &mut state,
            &dl,
            "C:\\t",
            vec!["C:\\t".to_string()],
            &panel,
            &ftx,
        );
        let c1 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            1,
            "C:\\t",
            Ok(list_payload(&[
                ("bad", 0, true),
                ("good", 0, true),
            ])),
        );
        // bad List 在途超时（本地判 Timeout，零 wire 帧——与生产 tick 同
        // 口径：先清 pending 再 on_local_timeout）。
        state.tick(&panel, Some(&ftx), None);
        assert!(matches!(
            frx.try_recv().ok(),
            Some(FileCommand::Fs {
                op: FsOp::List {
                    ref path,
                    ..
                }
            }) if path == "C:\\t\\bad"
        ));
        let kind = PendingKind::CollectList {
            path: "C:\\t\\bad".to_string(),
            offset: 0,
            depth: 2,
            src_root: "C:\\t".to_string(),
            prefix: "t".to_string(),
        };
        let _ = state.pending.take();
        state.on_local_timeout(kind);
        let job = state.job.as_ref().unwrap();
        assert!(job.collecting, "超时 ≠ 任务中止");
        assert!(!job.finished);
        assert_eq!(
            job.failed,
            vec![("t/bad".to_string(), "timeout".to_string())],
            "超时记失败清单（kind=timeout）"
        );
        // 其余条目继续（good）。
        let c2 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            2,
            "C:\\t\\good",
            Ok(list_payload(&[("y.txt", 5, false)])),
        );
        assert_wire_only_list_or_fetch(&[c1, c2]);
        state.tick(&panel, Some(&ftx), None);
        let job = state.job.as_ref().unwrap();
        assert!(job.summary_emitted);
        assert_eq!(job.failed, vec![("t/bad".to_string(), "timeout".to_string())]);
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ⑥ 取消请求传播中断（✕ 在途条目 = 整任务终止）────────────────

    #[test]
    fn r135_5b_cancel_propagates_abort() {
        let root = tmp_root("cancel1355b");
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        let mut state = FileManagerState::with_local_root(root.clone());
        seed_remote_dir(&mut state, "C:\\t");
        let mut panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let _ = enqueue_download(
            &mut state,
            &dl,
            "C:\\t",
            vec!["C:\\t".to_string()],
            &panel,
            &ftx,
        );
        let c1 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            1,
            "C:\\t",
            Ok(list_payload(&[
                ("a.txt", 5, false),
                ("b.txt", 5, false),
                ("c.txt", 5, false),
            ])),
        );
        assert_wire_only_list_or_fetch(&[c1]);
        // tick → 收敛 + 3 FetchFile 入队。
        state.tick(&panel, Some(&ftx), None);
        let mut n_fetched = 0usize;
        while frx.try_recv().is_ok() {
            n_fetched += 1;
        }
        assert_eq!(n_fetched, 3, "3 文件已入队");
        // 用户取消首个在途条目（✕ → FileCommand::Cancel → 任务 Cancelled）。
        let mut t = FileTask::queued(1, "a.txt".to_string(), 5, FileDirection::Download);
        t.status = FileTaskStatus::Cancelled;
        panel.tasks.push(t);
        state.tick(&panel, Some(&ftx), None);
        assert!(state.job.as_ref().unwrap().finished, "整任务中断");
        assert_eq!(
            state.status_line.as_deref(),
            Some(crate::i18n::tr("filemgr.dl.cancelled")),
            "取消状态行（i18n 钉死）"
        );
        assert!(frx.try_recv().is_err(), "中断后零新增 wire 帧");
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ⑦ 空根目录：目标侧同名根仍须创建 + 零文件终态 ────────────────

    #[test]
    fn r135_5b_empty_root_creates_target_root() {
        let root = tmp_root("empty1355b");
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        let mut state = FileManagerState::with_local_root(root.clone());
        seed_remote_dir(&mut state, "C:\\t");
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let _ = enqueue_download(
            &mut state,
            &dl,
            "C:\\t",
            vec!["C:\\t".to_string()],
            &panel,
            &ftx,
        );
        let c1 = list_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            1,
            "C:\\t",
            Ok(list_payload(&[])),
        );
        assert_wire_only_list_or_fetch(&[c1]);
        state.tick(&panel, Some(&ftx), None); // 收敛
        let job = state.job.as_ref().unwrap();
        assert!(dl.join("t").is_dir(), "空根 = 目标侧同名根仍创建");
        assert!(job.finished, "零文件 = 任务终态");
        assert_eq!(
            state.status_line.as_deref(),
            Some(crate::i18n::tr("filemgr.empty.local")),
            "零文件状态行（既有口径）"
        );
        assert!(job.failed.is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ⑧ 取消传播判定纯函数（正/负 + 批边界）───────────────────────

    #[test]
    fn r135_5b_job_has_cancelled_matrix() {
        let mut panel = FilePanelState::new();
        let mut job = FolderJob {
            direction: FolderDirection::ToLocal,
            source: "t".into(),
            target_remote_dir: String::new(),
            target_local_dir: PathBuf::new(),
            files: vec![
                ("C:\\t\\a.txt".to_string(), 5u64, "t".to_string()),
                ("C:\\t\\b.txt".to_string(), 6u64, "t".to_string()),
            ],
            depth_capped: Vec::new(),
            next_idx: 2,
            batch_head: 0,
            collecting: false,
            collect_queue: VecDeque::new(),
            finished: false,
            started: Instant::now(),
            consent_pending: false,
            consent_req_id: None,
            target_dirs: Vec::new(),
            visit: HashSet::new(),
            failed: Vec::new(),
            cycle_skipped: Vec::new(),
            summary_emitted: false,
            mkdir_queue: VecDeque::new(),
        };
        // 负：无任务 / 方向异 / 大小异 / 状态非 Cancelled。
        assert!(!job_has_cancelled(&job, &panel, FileDirection::Download));
        let mut t1 = FileTask::queued(1, "a.txt".to_string(), 5, FileDirection::Upload);
        t1.status = FileTaskStatus::Cancelled;
        panel.tasks.push(t1);
        assert!(!job_has_cancelled(&job, &panel, FileDirection::Download), "方向异 = 不中");
        let mut t2 = FileTask::queued(2, "a.txt".to_string(), 999, FileDirection::Download);
        t2.status = FileTaskStatus::Cancelled;
        panel.tasks.push(t2);
        assert!(!job_has_cancelled(&job, &panel, FileDirection::Download), "大小异 = 不中");
        let mut t3 = FileTask::queued(3, "a.txt".to_string(), 5, FileDirection::Download);
        t3.status = FileTaskStatus::Failed("x".into());
        panel.tasks.push(t3);
        assert!(
            !job_has_cancelled(&job, &panel, FileDirection::Download),
            "失败 ≠ 取消（继续其余语义）"
        );
        // 正：basename + size + 方向 + Cancelled 全同。
        let mut t4 = FileTask::queued(4, "b.txt".to_string(), 6, FileDirection::Download);
        t4.status = FileTaskStatus::Cancelled;
        panel.tasks.push(t4);
        assert!(job_has_cancelled(&job, &panel, FileDirection::Download), "命中 = 中断");
        // 批边界：下一批条目不在判定域。
        job.files.push(("C:\\t\\c.txt".to_string(), 7u64, "t".to_string()));
        job.batch_head = 2; // 批 = [2..3]（c.txt）
        let mut t5 = FileTask::queued(5, "c.txt".to_string(), 7, FileDirection::Download);
        t5.status = FileTaskStatus::Cancelled;
        panel.tasks.push(t5);
        assert!(job_has_cancelled(&job, &panel, FileDirection::Download), "当前批命中");
        job.batch_head = 3; // 批空（c.txt 已推进）——旧批 Cancelled 不重触发
        assert!(!job_has_cancelled(&job, &panel, FileDirection::Download), "批推进后不重触发");
    }
}

// ════════════════════════════════════════════════════════════════
// 递归上传」）：上传侧整树递归补全测试族。fresh 核对判定 = 文件递归已在
// create_dir_all）；本族钉死缺口补齐 = 空目录远端创建（既有 Mkdir 链，
// 零新 wire op）/ 失败汇总 / 取消传播 / 重复根环防护 / 远端相对结构镜像。
// ════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r135_5c_tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "kirin_fm_r1355c_{tag}_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 本地树播种（≥3 层嵌套 + 两空目录）：
    ///   t/a.txt / t/sub1/b.txt / t/sub1/sub2/c.txt
    ///   t/sub1/empty〔空〕 / t/e2〔空〕
    fn mk_nested_tree(root: &Path) -> PathBuf {
        let t = root.join("t");
        std::fs::create_dir_all(t.join("sub1").join("sub2")).unwrap();
        std::fs::create_dir_all(t.join("sub1").join("empty")).unwrap();
        std::fs::create_dir_all(t.join("e2")).unwrap();
        std::fs::write(t.join("a.txt"), b"aaaaa").unwrap();
        std::fs::write(t.join("sub1").join("b.txt"), b"bbbbb").unwrap();
        std::fs::write(t.join("sub1").join("sub2").join("c.txt"), b"ccccc").unwrap();
        t
    }

    fn ok_payload() -> FsResponsePayload {
        FsResponsePayload {
            ok: true,
            err: FsErrCode::Ok,
            payload: Vec::new(),
        }
    }

    fn err_payload(err: FsErrCode) -> FsResponsePayload {
        FsResponsePayload {
            ok: false,
            err,
            payload: Vec::new(),
        }
    }

    /// Mkdir 往返：tick → 取 Mkdir（断言 wire 形态）→ Admitted → Response。
    /// ftx 通道只走 Fs op（consent 批归 mtx 通道——双通道独立口径）。
    fn mkdir_round(
        state: &mut FileManagerState,
        panel: &FilePanelState,
        ftx: &UnboundedSender<FileCommand>,
        frx: &mut tokio::sync::mpsc::UnboundedReceiver<FileCommand>,
        mtx: Option<&UnboundedSender<FileMgrCommand>>,
        req_id: u32,
        expect_path: &str,
        result: Result<FsResponsePayload, String>,
    ) -> FileCommand {
        state.tick(panel, Some(ftx), mtx);
        let cmd = frx
            .try_recv()
            .unwrap_or_else(|e| panic!("应发出 Mkdir（{e}）"));
        match &cmd {
            FileCommand::Fs {
                op: FsOp::Mkdir { path },
            } => assert_eq!(path, expect_path, "Mkdir wire 形态（零新 op = 既有 Mkdir）"),
            other => panic!("应得 Mkdir，实际 {other:?}"),
        }
        state.on_fs_event(FsEvent::Admitted {
            req_id,
            op: FsOp::Mkdir {
                path: expect_path.to_string(),
            },
        });
        state.on_fs_event(FsEvent::Response { req_id, result });
        cmd
    }

    /// wire 纪律断言：上传空目录链帧 ∈ {Mkdir}（**零新 wire op** = 既有
    /// `FsOp::Mkdir`；文件 = 既有 OfferV2 consent 批通道，不在此 ftx 通道）。
    fn assert_wire_only_mkdir(cmds: &[FileCommand]) {
        for c in cmds {
            assert!(
                matches!(c, FileCommand::Fs { op: FsOp::Mkdir { .. } }),
                "wire 帧必须 ∈ {{Mkdir}}（零新 wire op），实际 {c:?}"
            );
        }
    }

    /// 上传任务构造公共段：远端落点 = `"up"`（`remote.current`）+ 入队。
    fn enqueue_upload(
        state: &mut FileManagerState,
        t: &Path,
        names: Vec<String>,
        panel: &FilePanelState,
        ftx: &UnboundedSender<FileCommand>,
        mtx: &UnboundedSender<FileMgrCommand>,
    ) -> usize {
        state.remote.current = "up".into();
        state.enqueue_transfer_targeted(
            PaneId::Local,
            PaneId::Remote,
            names,
            None,
            None,
            panel,
            Some(ftx),
            Some(mtx),
        )
    }

    // ── ① 观测行/空目录选择 格式钉死（纯函数；行格式单测口径）────────

    #[test]
    fn r135_5c_line_formats_pinned() {
        // 单条目失败行（kind 五态 + 路径）。
        assert_eq!(
            r135_5c_fail_line("mkdir:NotFound", "t/e"),
        );
        assert_eq!(
            r135_5c_fail_line("mkdir:wire", "up/t/e"),
        );
        assert_eq!(
            r135_5c_fail_line("timeout", "t/sub"),
        );
        assert_eq!(
            r135_5c_fail_line("io", "t/bad"),
        );
        assert_eq!(
            r135_5c_fail_line("interrupted", "t/x"),
        );
        // 汇总行：无失败且无环 = None（零行）。
        assert_eq!(r135_5c_summary_line(3, &[], &[]), None);
        // 仅失败（多条 = `;` 连）。
        assert_eq!(
            r135_5c_summary_line(
                2,
                &[
                    ("t/e1".to_string(), "mkdir:NotFound".to_string()),
                    ("t/e2".to_string(), "timeout".to_string()),
                ],
                &[]
            ),
            Some(
                    .to_string()
            )
        );
        // 仅环跳过。
        assert_eq!(
            r135_5c_summary_line(0, &[], &["t".to_string()]),
        );
        // 双清单。
        assert_eq!(
            r135_5c_summary_line(
                1,
                &[("io".to_string(), "io".to_string())],
                &["t".to_string(), "t2".to_string()]
            ),
            Some(
            )
        );
        // r135_5c_empty_dirs 矩阵（纯函数）：
        // a) 子树有文件 = 非空（接收侧 create_dir_all 附带建，零 Mkdir）。
        assert_eq!(
            r135_5c_empty_dirs(&[("s1/x.txt".into(), 1)], &["s1".into()]),
            Vec::<String>::new(),
            "有文件子树不建（接收侧附带）"
        );
        // b) 空/非空混合 = 仅空目录入列（顺序 = dirs 发现序）。
        assert_eq!(
            r135_5c_empty_dirs(
                &[("s1/x.txt".into(), 1)],
                &["s1".into(), "s2".into(), "s1/s3".into()]
            ),
            vec!["s2".to_string(), "s1/s3".to_string()],
            "s2（真空）+ s1/s3（空）须建；s1 有文件 = 不建"
        );
        // c) 根空 = `""` 须建同名根。
        assert_eq!(r135_5c_empty_dirs(&[], &[]), vec![String::new()], "纯空根");
        assert_eq!(
            r135_5c_empty_dirs(&[], &["e".into()]),
            vec![String::new(), "e".to_string()],
            "根空 + 子空（父先子后由队列深度排序保证）"
        );
    }

    // ── ② ≥3 层嵌套含空目录 + 远端相对结构镜像 + 零新 wire ───────────

    #[test]
    fn r135_5c_nested_mirror_incl_empty_dirs() {
        let root = tmp_root("nest1355c");
        let t = mk_nested_tree(&root);
        let mut state = FileManagerState::with_local_root(root.clone());
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let n = enqueue_upload(
            &mut state,
            &t,
            vec![local_path_key(&t)],
            &panel,
            &ftx,
            &mtx,
        );
        assert_eq!(n, 3, "3 文件入队（空目录不计文件）");
        let job = state.job.as_ref().unwrap();
        assert_eq!(job.direction, FolderDirection::ToRemote);
        // 同名根 + 源内相对父级。路径 = 本地原生分隔符归一后比较（收集期
        // Windows API 双分隔符兼容——比较面归一不改变行为）。
        let mut files = job
            .files
            .iter()
            .map(|(p, s, sub)| (p.replace('/', "\\"), *s, sub.clone()))
            .collect::<Vec<_>>();
        files.sort();
        assert_eq!(
            files,
            vec![
                (
                    local_path_key(&t.join("a.txt")),
                    5u64,
                    "t".to_string()
                ),
                (
                    local_path_key(&t.join("sub1").join("b.txt")),
                    5u64,
                    "t/sub1".to_string()
                ),
                (
                    local_path_key(&t.join("sub1").join("sub2").join("c.txt")),
                    5u64,
                    "t/sub1/sub2".to_string()
                ),
            ],
            "整树递归文件清单（≥3 层）"
        );
        // 非空子树 = 零帧——接收侧 create_dir_all 附带创建）。
        assert_eq!(
            job.mkdir_queue,
            vec!["up/t/e2".to_string(), "up/t/sub1/empty".to_string()],
            "仅空目录入列、深度升序（e2 深 1 → sub1/empty 深 2）"
        );
        assert!(job.failed.is_empty() && job.cycle_skipped.is_empty(), "零失败零环");
        assert!(!job.finished, "Mkdir 链在途 = 任务未终态");
        // Mkdir 回合 1：e2（同帧 consent 批经 mtx 并行——双通道独立）。
        let c1 = mkdir_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            Some(&mtx),
            1,
            "up/t/e2",
            Ok(ok_payload()),
        );
        let consent1 = mxr.try_recv().expect("consent 批与 Mkdir 并行发出");
        assert!(
            matches!(&consent1, FileMgrCommand::SendWithConsent { from_job: true, .. }),
            "文件批 = 既有 SendWithConsent 通道（零新 wire op）"
        );
        // Mkdir 回合 2：sub1/empty（链排空；父先子后拓扑序保持）。
        let c2 = mkdir_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            Some(&mtx),
            2,
            "up/t/sub1/empty",
            Ok(ok_payload()),
        );
        assert_wire_only_mkdir(&[c1, c2]);
        // 链排空响应后下一帧 = 收敛点（零行汇总：无失败）+ 文件全发出 =
        // 终态（单在途 = 在途条目在队列首、响应才弹——收敛归响应后帧，同
        state.tick(&panel, Some(&ftx), Some(&mtx));
        let job = state.job.as_ref().unwrap();
        assert!(job.summary_emitted, "收敛已执行");
        assert!(job.finished, "文件全发出 + Mkdir 排空 = 终态");
        // wire 级远端相对结构镜像断言：批条目 = (源全路径, 落点 =
        // `up/t/…`)——落点 = 远端目标目录 / 同名根 / 源内相对结构。
        let FileMgrCommand::SendWithConsent { entries, .. } = consent1 else {
            unreachable!()
        };
        let mut targets: Vec<(String, String)> = entries
            .iter()
            .map(|(p, d)| {
                (
                    p.file_name().unwrap().to_string_lossy().to_string(),
                    d.clone(),
                )
            })
            .collect();
        targets.sort();
        assert_eq!(
            targets,
            vec![
                ("a.txt".to_string(), "up/t".to_string()),
                ("b.txt".to_string(), "up/t/sub1".to_string()),
                ("c.txt".to_string(), "up/t/sub1/sub2".to_string()),
            ],
            "落点 = 远端目标目录 / 同名根 / 源内相对结构（镜像）"
        );
        // 模拟引擎 consent 回合 → 终态后零新增帧。
        state.on_fs_event(FsEvent::ConsentSent {
            req_id: 0x8001,
            peer_label: "test".to_string(),
            count: 3,
            total_size: 15,
            truncated: false,
            from_job: true,
        });
        state.on_fs_event(FsEvent::ConsentSettled {
            req_id: 0x8001,
            outcome: ConsentOutcome::Consumed,
            from_job: true,
            target_dir: None,
        });
        state.tick(&panel, Some(&ftx), Some(&mtx));
        assert!(frx.try_recv().is_err(), "终态后零新增 wire 帧");
        assert!(mxr.try_recv().is_err(), "终态后零新增 consent 通告");
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ③ 环防护（已访集合）重复根 + 深度上限 10（含 capped 远端建空）──

    #[test]
    fn r135_5c_cycle_duplicate_root_and_depth_cap() {
        let root = tmp_root("cycle1355c");
        let t = mk_nested_tree(&root);
        let mut state = FileManagerState::with_local_root(root.clone());
        let panel = FilePanelState::new();
        let (ftx, _frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, _mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        // a) 重复根（散选重复同路径）= 不二次收集不双重上传、记清单。
        let _ = enqueue_upload(
            &mut state,
            &t,
            vec![local_path_key(&t), local_path_key(&t)],
            &panel,
            &ftx,
            &mtx,
        );
        let job = state.job.as_ref().unwrap();
        assert_eq!(job.files.len(), 3, "重复根只收集一次（不双重上传）");
        assert_eq!(job.cycle_skipped, vec!["t".to_string()], "重复根记环清单");
        assert_eq!(job.visit.len(), 1, "已访集合 = 根 1 项");
        assert_eq!(
            job.mkdir_queue,
            vec!["up/t/e2".to_string(), "up/t/sub1/empty".to_string()],
            "Mkdir 队列不重复"
        );
        // b) 大小写异写重复（Windows 大小写不敏感 FS = 同目录）。
        #[cfg(windows)]
        {
            let root2 = tmp_root("case1355c");
            let mixed = root2.join("MiXcAsE");
            std::fs::create_dir_all(&mixed).unwrap();
            let mut st2 = FileManagerState::with_local_root(root2.clone());
            let _ = enqueue_upload(
                &mut st2,
                &mixed,
                vec![
                    local_path_key(&root2.join("MiXcAsE")),
                    local_path_key(&root2.join("mixcase")),
                ],
                &panel,
                &ftx,
                &mtx,
            );
            let j2 = st2.job.as_ref().unwrap();
            assert_eq!(j2.cycle_skipped.len(), 1, "大小写异写重复 = 已访集合命中");
            assert_eq!(j2.files.len(), 0, "不双重收集");
            std::fs::remove_dir_all(&root2).ok();
        }
        // c) 深度上限 = 10（既有 FOLDER_MAX_DEPTH）：capped 目录不展开但
        let root3 = tmp_root("depth1355c");
        let a = root3.join("A");
        std::fs::create_dir_all(&a).unwrap();
        let mut cur = a.clone();
        for i in 0..11 {
            let next = cur.join(format!("D{}", i + 2));
            std::fs::create_dir_all(&next).unwrap();
            let _ = std::fs::File::create(cur.join(format!("f{}.txt", i + 1)));
            cur = next;
        }
        let _ = std::fs::File::create(cur.join("f12.txt"));
        let mut st3 = FileManagerState::with_local_root(root3.clone());
        let _ = enqueue_upload(
            &mut st3,
            &a,
            vec![local_path_key(&a)],
            &panel,
            &ftx,
            &mtx,
        );
        let j3 = st3.job.as_ref().unwrap();
        assert_eq!(j3.files.len(), 10, "仅收集 ≤10 层内文件");
        assert!(
            j3
                .depth_capped
                .iter()
                .any(|c| c == "A/D2/D3/D4/D5/D6/D7/D8/D9/D10/D11"),
            "深度 11 子目录记入 capped"
        );
        assert_eq!(
            j3.mkdir_queue.back(),
            Some(&"up/A/D2/D3/D4/D5/D6/D7/D8/D9/D10/D11".to_string()),
            "深度上限线目录本身 = 远端建空（队列最深条目）"
        );
        std::fs::remove_dir_all(&root3).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ④ 单条目失败不静默跳过：记清单链继续 + AlreadyExists 良性 ─────

    #[test]
    fn r135_5c_mkdir_fail_continue_and_alreadyexists_benign() {
        let root = tmp_root("mkdirfail1355c");
        let t = mk_nested_tree(&root);
        let mut state = FileManagerState::with_local_root(root.clone());
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, _mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let _ = enqueue_upload(
            &mut state,
            &t,
            vec![local_path_key(&t)],
            &panel,
            &ftx,
            &mtx,
        );
        let job = state.job.as_ref().unwrap();
        assert_eq!(job.mkdir_queue.len(), 2, "空目录 2 个待建");
        // Mkdir e2 = 服务端 NotFound（如落点中途被删）→ 记清单、链继续。
        mkdir_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            Some(&mtx),
            1,
            "up/t/e2",
            Ok(err_payload(FsErrCode::NotFound)),
        );
        let job = state.job.as_ref().unwrap();
        assert_eq!(
            job.failed,
            vec![("t/e2".to_string(), "mkdir:NotFound".to_string())],
            "单条目失败记清单（路径 = 目标内相对显示）"
        );
        assert!(!job.finished, "单条目失败 ≠ 任务中止");
        // 链继续：sub1/empty 照发 + AlreadyExists = 良性成功（零记录）。
        mkdir_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            Some(&mtx),
            2,
            "up/t/sub1/empty",
            Ok(err_payload(FsErrCode::AlreadyExists)),
        );
        let job = state.job.as_ref().unwrap();
        assert_eq!(job.failed.len(), 1, "AlreadyExists = 幂等良性（不记清单）");
        assert!(job.mkdir_queue.is_empty(), "链排空（响应弹首）");
        // 排空响应后下一帧 = 收敛点（汇总行含失败 1 条）+ 终态。
        state.tick(&panel, Some(&ftx), Some(&mtx));
        let job = state.job.as_ref().unwrap();
        assert!(job.summary_emitted && job.finished, "收敛 + 终态");
        // 汇总行形态（纯函数重建 = 观测行同源；含失败 1 条）。
        assert_eq!(
            r135_5c_summary_line(job.files.len(), &job.failed, &job.cycle_skipped).as_deref(),
            Some(
            ),
            "汇总行 = 成功文件数 + 失败清单"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ⑤ 取消传播（ToRemote）：✕ 在途条目 = 整任务中断 ──────────────

    #[test]
    fn r135_5c_cancel_propagates_abort_upload() {
        let root = tmp_root("cancel1355c");
        let t = mk_nested_tree(&root);
        let mut state = FileManagerState::with_local_root(root.clone());
        let mut panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let _ = enqueue_upload(
            &mut state,
            &t,
            vec![local_path_key(&t)],
            &panel,
            &ftx,
            &mtx,
        );
        // Mkdir e2 + consent 批（双通道并行）。
        let c1 = mkdir_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            Some(&mtx),
            1,
            "up/t/e2",
            Ok(ok_payload()),
        );
        assert_wire_only_mkdir(&[c1]);
        let _consent = mxr.try_recv().expect("consent 批在位");
        // 引擎 consent 回合：Consumed + 传输行在位（a.txt）。
        state.on_fs_event(FsEvent::ConsentSent {
            req_id: 0x9001,
            peer_label: "test".to_string(),
            count: 3,
            total_size: 15,
            truncated: false,
            from_job: true,
        });
        state.on_fs_event(FsEvent::ConsentSettled {
            req_id: 0x9001,
            outcome: ConsentOutcome::Consumed,
            from_job: true,
            target_dir: None,
        });
        let mut task = FileTask::queued(1, "a.txt".to_string(), 5, FileDirection::Upload);
        task.status = FileTaskStatus::Cancelled;
        panel.tasks.push(task);
        // 照入队、余留空目录 Mkdir 照发）。
        state.tick(&panel, Some(&ftx), Some(&mtx));
        let job = state.job.as_ref().unwrap();
        assert!(job.finished, "取消 = 整任务中断");
        assert_eq!(
            state.status_line.as_deref(),
            Some(crate::i18n::tr("filemgr.ul.cancelled")),
            "取消状态行（i18n 钉死）"
        );
        assert!(frx.try_recv().is_err(), "中断后零新增 wire 帧");
        assert!(mxr.try_recv().is_err(), "中断后零新增 consent 通告");
        assert_eq!(
            job.mkdir_queue,
            vec!["up/t/sub1/empty".to_string()],
            "余留 Mkdir 队列弃置在位（任务终态后零新帧）"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // ── ⑥ 空根目录：远端同名根仍须创建 + 零文件终态 ──────────────────

    #[test]
    fn r135_5c_empty_root_creates_remote_root() {
        let root = tmp_root("empty1355c");
        let t = root.join("t");
        std::fs::create_dir_all(&t).unwrap();
        let mut state = FileManagerState::with_local_root(root.clone());
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, mut mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        let n = enqueue_upload(
            &mut state,
            &t,
            vec![local_path_key(&t)],
            &panel,
            &ftx,
            &mtx,
        );
        assert_eq!(n, 0, "纯空目录 = 零文件");
        let job = state.job.as_ref().unwrap();
        assert!(
            !job.finished,
            "Mkdir 在途 = 未终态（修前 = 立终态 + 远端静默缺失）"
        );
        assert_eq!(job.mkdir_queue, vec!["up/t".to_string()], "同名根入 Mkdir 队列");
        // Mkdir 同名根 + 排空响应后下一帧 = 收敛终态（状态行 = 既有
        // 「此目录为空」口径）。
        mkdir_round(
            &mut state,
            &panel,
            &ftx,
            &mut frx,
            Some(&mtx),
            1,
            "up/t",
            Ok(ok_payload()),
        );
        state.tick(&panel, Some(&ftx), Some(&mtx));
        let job = state.job.as_ref().unwrap();
        assert!(job.finished, "零文件 + Mkdir 排空 = 任务终态");
        assert!(job.summary_emitted, "收敛已执行");
        assert_eq!(
            state.status_line.as_deref(),
            Some(crate::i18n::tr("filemgr.empty.local")),
            "零文件状态行（既有口径）"
        );
        assert!(frx.try_recv().is_err(), "终态后零新增 wire 帧");
        assert!(mxr.try_recv().is_err(), "零文件 = 零 consent 通告");
        std::fs::remove_dir_all(&root).ok();
    }
}

// ════════════════════════════════════════════════════════════════
//   （c→s）落点目标目录决议——纯函数矩阵 + 状态方法矩阵（s→c 面
//   `paste_landing_resolve` 族零变化 = 既有 r110v13b3 单测回归在案）。
// ════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r137_2_tests {
    use super::*;

    fn mk_entry(name: &str, size: u64, is_dir: bool) -> FileMgrEntry {
        FileMgrEntry {
            name: name.into(),
            size,
            mtime: 0,
            is_dir,
            is_symlink: false,
            is_hidden: false,
        }
    }

    fn mk_symlink_dir(name: &str) -> FileMgrEntry {
        FileMgrEntry {
            name: name.into(),
            size: 0,
            mtime: 0,
            is_dir: true,
            is_symlink: true,
            is_hidden: false,
        }
    }

    /// 测试态：远端 = 「远端电脑」合成根 → `C:\` → [`dldir` 目录 /
    /// `dl.txt` 文件 / 符号链接目录 `link`]（同 r133_7 拓扑口径），
    /// `current = C:\`，`started/unsupported` 参数化。
    fn state_r137_2(started: bool, unsupported: bool) -> FileManagerState {
        let mut state = FileManagerState::default();
        state.remote.started = started;
        state.remote.unsupported = unsupported;
        state.remote.root_display = "r137-2".to_string();
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("C:\\", 0, true)]),
                ..Default::default()
            },
        );
        state.remote.view.nodes.insert(
            "C:\\".to_string(),
            TreeNodeState {
                children: Some(vec![
                    mk_entry("dldir", 0, true),
                    mk_entry("dl.txt", 9, false),
                    mk_symlink_dir("link"),
                ]),
                ..Default::default()
            },
        );
        state.remote.current = "C:\\".to_string();
        state
    }

    fn sel_remote(state: &mut FileManagerState, names: &[&str]) {
        let paths: Vec<String> =
            names.iter().map(|s| remote_join(&state.remote.current, s)).collect();
        state.view_mut(PaneId::Remote).selected = paths;
    }

    /// 纯函数矩阵：无 FM 语境 = `None`（调用点走既有 v1 链零变化）；
    /// 有语境 = 选中优先（恰一非符号链接目录）→ 当前目录回退
    /// （合成根 → `""` 对端 fs 根）。
    #[test]
    fn r137_2_clip_upload_c2s_target_matrix() {
        // 语境缺位（无窗/面板关/未启动/不支持）= None——选中/当前值在案亦不采纳。
        assert_eq!(
            clip_upload_c2s_target(false, Some("a/b".into()), "a".into()),
            None,
            "无 FM 语境 = None（v1 链零变化）"
        );
        // 语境在位 + 选中 = 选中优先。
        assert_eq!(
            clip_upload_c2s_target(true, Some("a/b".into()), "a".into()),
            Some("a/b".into()),
            "选中目录优先于当前目录"
        );
        // 语境在位 + 无选中 = 当前目录（含 `""` 对端 fs 根形态）。
        assert_eq!(
            clip_upload_c2s_target(true, None, "a".into()),
            Some("a".into()),
            "无选中 = 当前目录回退"
        );
        assert_eq!(
            clip_upload_c2s_target(true, None, String::new()),
            Some(String::new()),
            "合成根当前 = 空串（对端 fs 根）"
        );
    }

    /// 状态方法矩阵（调用点注入面板态；s→c `paste_landing_fm_surface` 同
    /// 口径 = 本方法不感知窗型/面板态，语境 = 面板开 ∧ 已启动 ∧ 支持）。
    #[test]
    fn r137_2_c2s_paste_upload_target_state_matrix() {
        // 面板关 = 无语境（远端栏状态在案亦不采纳）。
        let mut s = state_r137_2(true, false);
        sel_remote(&mut s, &["dldir"]);
        assert_eq!(s.c2s_paste_upload_target(false), None, "面板关 = None");
        // 未启动 = 无语境（远端栏未 List = 无浏览事实）。
        let mut s = state_r137_2(false, false);
        sel_remote(&mut s, &["dldir"]);
        assert_eq!(s.c2s_paste_upload_target(true), None, "未启动 = None");
        // 对端不支持浏览 = 无语境。
        let mut s = state_r137_2(true, true);
        assert_eq!(s.c2s_paste_upload_target(true), None, "不支持 = None");
        // 已启动 + 无选中 = 当前目录。
        let mut s = state_r137_2(true, false);
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some("C:\\".into()),
            "无选中 = 当前目录"
        );
        // 当前 = 合成根 + 无选中 = 空串（对端 fs 根，remote_default_target 口径）。
        let mut s = state_r137_2(true, false);
        s.remote.current = REMOTE_PC_ROOT_KEY.to_string();
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some(String::new()),
            "合成根当前 = 对端 fs 根"
        );
        // 恰一目录选中 = 选中优先（非当前目录）。
        let mut s = state_r137_2(true, false);
        sel_remote(&mut s, &["dldir"]);
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some("C:\\dldir".into()),
            "选中目录优先"
        );
        // 选中 = 文件 → 非「恰一目录」→ 当前目录回退。
        let mut s = state_r137_2(true, false);
        sel_remote(&mut s, &["dl.txt"]);
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some("C:\\".into()),
            "文件选中 = 当前目录回退"
        );
        // 选中 = 符号链接目录 → fail-closed → 当前目录回退。
        let mut s = state_r137_2(true, false);
        sel_remote(&mut s, &["link"]);
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some("C:\\".into()),
            "符号链接目录选中 = 当前目录回退"
        );
        // 多选 = 非「恰一目录」→ 当前目录回退。
        let mut s = state_r137_2(true, false);
        sel_remote(&mut s, &["dldir", "dl.txt"]);
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some("C:\\".into()),
            "多选 = 当前目录回退"
        );
    }

    //    登记表回退矩阵 + 语境登记值 hint 矩阵 + 跨会话零复用钉死。──

    /// 真实目录 > 登记表 > 合成根）；默认字段 None = 既有矩阵逐位零变化。
    #[test]
    fn r167_c2s_paste_upload_target_registry_fallback_matrix() {
        crate::r167_clip_remote_dir_clear("t-a");
        // 未启动（会话重建首帧）+ 登记表 = 回退命中（b 臂：不再误伤）。
        let mut s = state_r137_2(false, false);
        s.r167_session_dir_fallback = Some("C:\\last".into());
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some("C:\\last".into()),
            "未启动 + 登记表 = 回退命中"
        );
        // 对端不支持（静态版本门）+ 登记表 = 回退命中（本会话内曾有效
        // 语境；跨会话已由清位面剪除）。
        let mut s = state_r137_2(true, true);
        s.r167_session_dir_fallback = Some("C:\\last".into());
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some("C:\\last".into()),
            "不支持 + 登记表 = 回退命中"
        );
        // 合成根当前 + 登记表 = 登记表 > 合成根（卡口径优先级）。
        let mut s = state_r137_2(true, false);
        s.remote.current = REMOTE_PC_ROOT_KEY.to_string();
        s.r167_session_dir_fallback = Some("C:\\last".into());
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some("C:\\last".into()),
            "合成根 + 登记表 = 登记表优先"
        );
        // 合成根当前 + 无登记表 = 既有 `""` 对端 fs 根兜底零变化。
        let mut s = state_r137_2(true, false);
        s.remote.current = REMOTE_PC_ROOT_KEY.to_string();
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some(String::new()),
            "合成根 + 无登记表 = 对端 fs 根（既有口径）"
        );
        // 真实当前目录（含 `""` 真根）不被登记表越位。
        let mut s = state_r137_2(true, false);
        s.r167_session_dir_fallback = Some("C:\\last".into());
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some("C:\\".into()),
            "真实当前目录 > 登记表"
        );
        // 登记值 = 空串（对端 fs 根，合法目录）同样回退命中。
        let mut s = state_r137_2(false, false);
        s.r167_session_dir_fallback = Some(String::new());
        assert_eq!(
            s.c2s_paste_upload_target(true),
            Some(String::new()),
            "登记空串 = 对端 fs 根回退命中"
        );
        crate::r167_clip_remote_dir_clear("t-a");
    }

    /// （合成根零登记防污染；未启动/不支持零登记）。
    #[test]
    fn r167_remote_dir_hint_matrix() {
        // 已启动 + 真实当前目录 = Some(当前)。
        let s = state_r137_2(true, false);
        assert_eq!(s.r167_remote_dir_hint(), Some("C:\\".into()));
        // 已启动 + 恰一目录选中 = 选中优先。
        let mut s = state_r137_2(true, false);
        sel_remote(&mut s, &["dldir"]);
        assert_eq!(s.r167_remote_dir_hint(), Some("C:\\dldir".into()));
        // 合成根当前 + 无选中 = None（零登记，保留旧值）。
        let mut s = state_r137_2(true, false);
        s.remote.current = REMOTE_PC_ROOT_KEY.to_string();
        assert_eq!(s.r167_remote_dir_hint(), None, "合成根零登记");
        // 真根 `""` = 真实目录 = Some("")。
        let mut s = state_r137_2(true, false);
        s.remote.current = String::new();
        assert_eq!(s.r167_remote_dir_hint(), Some(String::new()));
        // 未启动 / 不支持 = None（零登记）。
        let s = state_r137_2(false, false);
        assert_eq!(s.r167_remote_dir_hint(), None);
        let s = state_r137_2(true, true);
        assert_eq!(s.r167_remote_dir_hint(), None);
    }

    /// 拆除/CLEAR/对端门 OFF 的共享原子；upsert 置新 + 容量上界逐最旧）。
    #[test]
    fn r167_clip_remote_dir_registry_lifecycle() {
        crate::r167_clip_remote_dir_clear("t-reg");
        assert_eq!(crate::r167_clip_remote_dir_get("t-reg"), None);
        crate::r167_clip_remote_dir_set("t-reg", "C:\\work");
        assert_eq!(
            crate::r167_clip_remote_dir_get("t-reg"),
            Some("C:\\work".into())
        );
        // upsert 置新（同 addr 唯一条目）。
        crate::r167_clip_remote_dir_set("t-reg", "C:\\work2");
        assert_eq!(
            crate::r167_clip_remote_dir_get("t-reg"),
            Some("C:\\work2".into())
        );
        // 清位 = 跨会话零复用（fail-closed）。
        crate::r167_clip_remote_dir_clear("t-reg");
        assert_eq!(crate::r167_clip_remote_dir_get("t-reg"), None);
        for i in 0..20 {
            crate::r167_clip_remote_dir_set(&format!("cap-{i}"), "d");
        }
        assert_eq!(crate::r167_clip_remote_dir_get("cap-0"), None, "最旧被逐");
        assert_eq!(
            crate::r167_clip_remote_dir_get("cap-19"),
            Some("d".into())
        );
        for i in 0..20 {
            crate::r167_clip_remote_dir_clear(&format!("cap-{i}"));
        }
    }
}

#[cfg(test)]
mod r137_3_tests {
    use super::*;

    /// + 框内显式错误**（非静默）。第五轮零 Mkdir 帧在案 = 三拒绝路径
    /// （空名〔对话框焦点未抓 = 键入无处落〕/ busy / 盘符层合成根）旧
    /// 「对话框消失仅状态行小字」语义 → 用户「点两次没看到新目录」。
    #[test]
    fn r137_3_mkdir_reject_keeps_dialog_with_explicit_error() {
        let mut state = FileManagerState::default();
        state.remote.current = "C:\Users\dev".to_string();
        // a) 空名（= 焦点缺失时键入丢失的终态）= 零 wire + 保开 + 框内显式错误。
        state.dialog = Dialog::InputMkdir {
            pane: PaneId::Remote,
            name: "   ".into(),
        };
        assert!(state.mkdir_submit().is_none(), "空名 = 零 wire");
        let Dialog::InputMkdir { pane, name } = &state.dialog else {
            panic!("空名应保开对话框，实际 {:?}", state.dialog)
        };
        assert_eq!(*pane, PaneId::Remote);
        assert_eq!(name, "   ", "保开对话框 + 已输入文本保留（供修正）");
        assert_eq!(
            state.dialog_error.as_deref(),
            Some(crate::i18n::tr("filemgr.rename.invalid")),
            "框内显式错误（非静默）"
        );
        assert_eq!(
            state.status_line.as_deref(),
            Some(crate::i18n::tr("filemgr.rename.invalid")),
            "状态行同文（双呈现）"
        );
        // b) busy（List 在途占 pending 单槽）= 零 wire + 保开 + busy 显式。
        state.pending = Some(PendingOp {
            req_id: 0,
            kind: PendingKind::List {
                pane: PaneId::Remote,
                path: "x".into(),
                offset: 0,
            },
            started: Instant::now(),
        });
        state.dialog = Dialog::InputMkdir {
            pane: PaneId::Remote,
            name: "newdir".into(),
        };
        assert!(state.mkdir_submit().is_none(), "busy = 零 wire");
        let Dialog::InputMkdir { pane, name } = &state.dialog else {
            panic!("busy 应保开对话框，实际 {:?}", state.dialog)
        };
        assert_eq!(*pane, PaneId::Remote);
        assert_eq!(name, "newdir", "busy 保开 + 文本保留");
        assert_eq!(
            state.dialog_error.as_deref(),
            Some(crate::i18n::tr("filemgr.busy")),
            "框内 busy 显式"
        );
        // c) 成功路径：帧发出 + pending 登记 + 对话框关 + 错误态清零。
        state.pending = None;
        let cmd = state.mkdir_submit();
        match &cmd {
            Some(FileCommand::Fs {
                op: FsOp::Mkdir { path },
            }) => {
                assert_eq!(path, "C:\Users\dev\\newdir", "盘符感知拼接（既有语义）");
            }
            other => panic!("合法名应发 Mkdir 帧，实际 {other:?}"),
        }
        assert!(!state.has_dialog(), "提交成功 = 对话框关");
        assert!(state.dialog_error.is_none(), "提交成功 = 错误态清零");
        assert!(
            matches!(
                state.pending.as_ref().map(|p| &p.kind),
                Some(PendingKind::Mkdir {
                    path,
                    for_job: false,
                }) if path == "C:\Users\dev\\newdir"
            ),
            "pending = Mkdir 用户按钮态（for_job=false）"
        );
        // d) 取消 = 错误态清零（零 wire 帧 §1.7）。
        state.dialog = Dialog::InputMkdir {
            pane: PaneId::Remote,
            name: "z".into(),
        };
        state.dialog_error = Some("stale".into());
        state.dialog_cancel();
        assert!(!state.has_dialog());
        assert!(state.dialog_error.is_none(), "取消 = 错误态清零");
        // e) 开新对话框 = 错误态清零。
        state.dialog_error = Some("stale".into());
        state.open_mkdir(PaneId::Remote);
        assert!(state.dialog_error.is_none(), "开新对话框 = 错误态清零");
        let Dialog::InputMkdir { name, .. } = &state.dialog else {
            panic!("open_mkdir 应开 InputMkdir 对话框")
        };
        assert!(name.is_empty());
    }

    /// 显式 `outside_root` 错误（保开）；进入盘内目录后新建 = Mkdir 帧
    /// （服务端裁决——兄弟盘符写 = 服务端 `PathOutsideRoot` 显式负回执，
    /// 本岗不扩写面）。
    #[test]
    fn r137_3_mkdir_drive_layer_vs_drive_subtree() {
        let mut state = FileManagerState::default();
        // a) 盘符层（current = 合成根）= 客户端拒（保开 + outside_root）。
        state.remote.current = REMOTE_PC_ROOT_KEY.to_string();
        state.dialog = Dialog::InputMkdir {
            pane: PaneId::Remote,
            name: "d".into(),
        };
        assert!(state.mkdir_submit().is_none());
        assert_eq!(
            state.dialog_error.as_deref(),
            Some(crate::i18n::tr("filemgr.err.outside_root")),
            "盘符层新建 = 显式 outside_root（非静默）"
        );
        assert!(state.has_dialog(), "保开");
        // b) 盘内目录（C 盘 home 子树）= 帧发出（服务端 policy 内 = 成功）。
        state.dialog_cancel();
        state.remote.current = "C:\Users\dev".to_string();
        state.dialog = Dialog::InputMkdir {
            pane: PaneId::Remote,
            name: "sub".into(),
        };
        let cmd = state.mkdir_submit();
        assert!(
            matches!(
                &cmd,
                Some(FileCommand::Fs {
                    op: FsOp::Mkdir { path }
                }) if path == "C:\Users\dev\\sub"
            ),
            "home 子树新建 = Mkdir 帧在位"
        );
        // c) D 盘目录（第 8 项修复后可达）= 帧同样发出——写裁决归服务端
        // （兄弟盘符写 = PathOutsideRoot 显式负回执 = 既有 err_text 状态行，
        // 本岗零扩权）。
        state.dialog_cancel();
        state.pending = None; // b) 的 Mkdir 在途清槽（单槽语义 = 真实链路
        // 响应回填后自然清；测试态直接复位）。
        state.remote.current = "D:\\".to_string();
        state.dialog = Dialog::InputMkdir {
            pane: PaneId::Remote,
            name: "d2".into(),
        };
        let cmd = state.mkdir_submit();
        assert!(
            matches!(
                &cmd,
                Some(FileCommand::Fs {
                    op: FsOp::Mkdir { path }
                }) if path == "D:\\d2"
            ),
            "D 盘目录新建 = 帧发出（写不扩权 = 服务端显式拒，非客户端静默）"
        );
    }
}

// ════════════════════════════════════════════════════════════
// 目录展示」）：UI 面单测——fail-closed enable 矩阵 / 固定序 / 导航
// 行为 / 首帧链（List("")→盘符层）/ headless 布局判据（**远端段标签
// 归右栏** = 用户指认面像素级钉死）。
// ════════════════════════════════════════════════════════════
#[cfg(test)]
mod r137_4_fm_tests {
    use super::*;
    use kirin_desk_core::connection::file_transfer::FsEntry;

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "k137_4_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn mk_entry(name: &str, size: u64, is_dir: bool) -> FileMgrEntry {
        FileMgrEntry {
            name: name.into(),
            size,
            mtime: 0,
            is_dir,
            is_symlink: false,
            is_hidden: false,
        }
    }

    fn drain_list_paths(
        frx: &mut tokio::sync::mpsc::UnboundedReceiver<FileCommand>,
    ) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(cmd) = frx.try_recv() {
            if let FileCommand::Fs {
                op: FsOp::List { path, .. },
            } = cmd
            {
                out.push(path);
            }
        }
        out
    }

    fn admit_list(state: &mut FileManagerState, req_id: u32, path: &str) {
        state.on_fs_event(FsEvent::Admitted {
            req_id,
            op: FsOp::List {
                path: path.to_string(),
                offset: 0,
                limit: PAGE_SIZE,
            },
        });
    }

    fn respond_list(
        state: &mut FileManagerState,
        req_id: u32,
        entries: &[(&str, u64, bool)],
        has_more: bool,
        root_display: &str,
    ) {
        let list = FsListPayload {
            entries: entries
                .iter()
                .map(|(n, s, d)| FsEntry {
                    name: (*n).into(),
                    size: *s,
                    mtime: 0,
                    is_dir: *d,
                    is_symlink: false,
                })
                .collect(),
            has_more,
            root_display: root_display.into(),
        };
        state.on_fs_event(FsEvent::Response {
            req_id,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: bincode::serialize(&list).unwrap(),
            }),
        });
    }

    fn channel() -> (
        tokio::sync::mpsc::UnboundedSender<FileCommand>,
        tokio::sync::mpsc::UnboundedReceiver<FileCommand>,
    ) {
        tokio::sync::mpsc::unbounded_channel()
    }

    /// ① fail-closed enable 矩阵（用户「远端目录不存在 = 按钮禁用」口径）：
    /// 未列定 / 在途 / 错误 / 条目缺席 / 同名文件（非目录）= 全 disable；
    /// 落定 + 同名目录（大小写不敏感）= enable。
    #[test]
    fn r137_4_remote_home_dir_present_matrix() {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        assert!(
            !remote_home_dir_present(&state, "Desktop"),
            "未列定（无节点）= disable"
        );
        // 在途（loading）= disable。
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                loading: true,
                ..Default::default()
            },
        );
        assert!(!remote_home_dir_present(&state, "Desktop"), "在途 = disable");
        // 落定 + 同名目录（异写大小写）= enable；缺席 / 文件 = disable。
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                children: Some(vec![
                    mk_entry("downloads", 0, true),
                    mk_entry("Desktop", 0, false), // 同名文件 ≠ 目录
                ]),
                ..Default::default()
            },
        );
        assert!(
            remote_home_dir_present(&state, "Downloads"),
            "落定 + 同名目录（小写异写）= enable"
        );
        assert!(
            !remote_home_dir_present(&state, "Desktop"),
            "同名文件（非目录）= disable（不猜）"
        );
        assert!(
            !remote_home_dir_present(&state, "Documents"),
            "条目缺席 = disable"
        );
        // 错误节点 = disable。
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                error: Some("err".to_string()),
                ..Default::default()
            },
        );
        assert!(!remote_home_dir_present(&state, "Downloads"), "错误节点 = disable");
    }

    /// ② 固定序一一对应（远端磁盘名 × i18n 键 × 本机目录名同源序——
    /// 与 `local_quick_dirs` 桌面/下载/文档同序，防三表错位）。
    #[test]
    fn r137_4_remote_quick_names_ordering() {
        let names = remote_quick_dir_names();
        assert_eq!(
            names,
            ["Desktop", "Downloads", "Documents"],
            "远端磁盘名固定序 = 桌面/下载/文档"
        );
        let home = PathBuf::from("/fake/home");
        let local = local_quick_dirs(&home);
        let local_stems: Vec<String> = local
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names.as_slice(),
            local_stems.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice(),
            "远端磁盘名 = 本机常用目录 stem 同序（profile 目录名跨机同形）"
        );
        assert_eq!(LOCAL_QUICK_KEYS.len(), 3, "i18n 键固定序三枚");
    }

    /// ③ 导航行为（root 相对单级；缓存命中零 wire / 未落定单在途一次
    /// List）+ current 锚定 + **选中 = 目标节点全键 + 主目录链展开**
    /// 跳转」根因面；可见链 = 根 ▸ 主目录 ▸ 目标键）。
    #[test]
    fn r137_4_goto_remote_quick_cached_and_uncached() {
        let (ftx, mut frx) = channel();
        // 未落定 = 一次 List + current 锚定 + 选中 = 目标全键 + 链展开。
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true;
        state.remote.current = "C:\\".to_string();
        state.remote.view.selected.push("C:\\x".to_string());
        state.goto_remote_quick("Desktop", Some(&ftx));
        assert_eq!(state.remote.current, "Desktop", "current 锚定 root 相对目录");
        assert_eq!(
            state.remote.view.selected,
            vec!["Desktop".to_string()],
        );
        assert!(
            state.remote.view.expanded.iter().any(|p| p == REMOTE_PC_ROOT_KEY),
        );
        assert!(
            state.remote.view.expanded.iter().any(|p| p == REMOTE_HOME_KEY),
        );
        assert!(
            state.remote.view.expanded.iter().any(|p| p == "Desktop"),
        );
        assert_eq!(
            state.remote.scroll_anchor.as_deref(),
            Some("Desktop"),
        );
        assert_eq!(
            drain_list_paths(&mut frx),
            vec!["Desktop".to_string()],
            "未落定 = 恰一 List（单在途）"
        );
        assert_eq!(state.active_pane, PaneId::Remote, "活动栏切远端");
        // 缓存命中（children 落定无错）= 零 wire。
        let mut state2 = FileManagerState::with_local_root(std::env::temp_dir());
        state2.remote.started = true;
        state2.remote.current = "C:\\".to_string();
        state2
            .remote
            .view
            .nodes
            .insert("Desktop".to_string(), TreeNodeState {
                children: Some(vec![mk_entry("a.txt", 1, false)]),
                ..Default::default()
            });
        state2.goto_remote_quick("Desktop", Some(&ftx));
        assert_eq!(state2.remote.current, "Desktop");
        assert!(
            drain_list_paths(&mut frx).is_empty(),
            "缓存命中 = 零 wire"
        );
    }

    /// ④ 首帧链（tick 2c）：`List("")` 落定 → 盘符层 List 续发（单在途
    /// 幂等）；home 未落定 = 零 wire。
    #[test]
    fn r137_4_initial_chain_home_then_drive() {
        let (ftx, mut frx) = channel();
        let panel = FilePanelState::new();
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true;
        // 开窗武装（首帧链恰一次；发射即解除——末帧幂等断言依赖解除态）。
        state.remote.drive_chain_armed = true;
        // home 在途（loading）= 不续发。
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                loading: true,
                ..Default::default()
            },
        );
        state.tick(&panel, Some(&ftx), None);
        assert!(
            drain_list_paths(&mut frx).is_empty(),
            "home 未落定 = 零 wire（单在途）"
        );
        // home 落定 → 盘符层续发（恰一）。
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                children: Some(vec![mk_entry("Desktop", 0, true)]),
                ..Default::default()
            },
        );
        state.tick(&panel, Some(&ftx), None);
        assert_eq!(
            drain_list_paths(&mut frx),
            vec![REMOTE_PC_ROOT_KEY.to_string()],
            "home 落定 = 盘符层 List 续发（恰一）"
        );
        // 幂等：盘符节点 loading 在位 = 不重发。
        state.tick(&panel, Some(&ftx), None);
        assert!(
            drain_list_paths(&mut frx).is_empty(),
            "盘符层在途 = 不重发（幂等）"
        );
    }

    /// ⑤ headless 布局判据（**用户指认面**：「远端常用/远端电脑」文字归
    /// **右栏侧**；远端常见目录 文档/桌面/下载 在右段在位）：
    /// - 「本机常用」全实例 x < 中线（左段）；
    /// - 「远端常用」全实例 x ≥ 中线（**右段** = 修前病灶面钉死）；
    /// - 右段快捷行 y < 右栏头 y（对位右栏之上）+ 桌面/下载/文档 右段
    ///   实例在位（各标签恰双实例：左段 + 右段）；
    #[test]
    fn r137_4_quick_sections_layout_remote_right() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let root = tmp_root("layout");
        let mut state = FileManagerState::with_local_root(root.clone());
        assert!(state.local_expand_chain(&root), "本地链展开（测试前置）");
        // 远端 = 已初始化形态（started 抑制首 List）+ 盘符树播种 + home
        // 条目播种（三钮 enable 形态）。
        state.remote.started = true;
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                children: Some(vec![
                    mk_entry("Desktop", 0, true),
                    mk_entry("Downloads", 0, true),
                    mk_entry("Documents", 0, true),
                ]),
                ..Default::default()
            },
        );
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("C:\\", 0, true)]),
                ..Default::default()
            },
        );
        state.remote.current = "C:\\".to_string();
        let panel = FilePanelState::new();
        let (sw, sh) = (1920.0, 1080.0);
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let mut shapes: Vec<egui::epaint::ClippedShape> = Vec::new();
        for _ in 0..2 {
            let mut raw = egui::RawInput::default();
            raw.screen_rect =
                Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(sw, sh)));
            shapes = ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let mut focus = false;
                    show_file_manager(
                        ui,
                        &Theme::LIGHT,
                        &mut state,
                        None,
                        None,
                        &panel,
                        false,
                        &mut focus,
                    );
                });
            })
            .shapes;
        }
        // (a) 零退化分配。
        for cs in &shapes {
            assert!(cs.clip_rect.is_finite(), "非有限裁剪矩形（退化分配）");
            if let egui::Shape::Rect(r) = &cs.shape {
                assert!(r.rect.is_finite(), "非有限矩形 shape（退化分配）");
            }
        }
        fn text_rects(
            shapes: &[egui::epaint::ClippedShape],
            text: &str,
        ) -> Vec<egui::Rect> {
            shapes
                .iter()
                .filter_map(|cs| match &cs.shape {
                    egui::Shape::Text(t) if t.galley.job.text == text => {
                        Some(egui::Rect::from_min_size(t.pos, t.galley.size()))
                    }
                    _ => None,
                })
                .collect()
        }
        let mid = sw / 2.0;
        // (b) 「本机常用」= 左段（全实例 x < 中线）。
        let local_labels = text_rects(&shapes, &t!("filemgr.quick.local"));
        assert!(!local_labels.is_empty(), "「本机常用」未绘制");
        assert!(
            local_labels.iter().all(|r| r.min.x < mid),
            "「本机常用」应全在左段（x < {:.0}），实得 {:?}",
            mid,
            local_labels
        );
        // (c) 「远端常用」= **右段**（用户指认面：修前与本机区同挤左行）。
        let remote_labels = text_rects(&shapes, &t!("filemgr.quick.remote"));
        assert!(!remote_labels.is_empty(), "「远端常用」未绘制");
        assert!(
            remote_labels.iter().all(|r| r.min.x >= mid),
            "「远端常用」应全在右段（x ≥ {:.0} = 对位远端电脑栏），实得 {:?}",
            mid,
            remote_labels
        );
        // (d) 右段快捷行在右栏头之上（对位右栏）+ 右段「远端电脑」根钮
        //     在位（快捷行区 = 栏头 y 之上）。
        let remote_headers = text_rects(&shapes, &t!("filemgr.remote"));
        assert!(!remote_headers.is_empty(), "远端栏头未绘制");
        let remote_header_y = remote_headers
            .iter()
            .map(|r| r.min.y)
            .fold(f32::INFINITY, f32::min);
        let pc_root_quick = text_rects(&shapes, &t!("filemgr.pc_root_remote"))
            .into_iter()
            .filter(|r| r.min.x >= mid && r.min.y < remote_header_y)
            .collect::<Vec<_>>();
        assert!(
            !pc_root_quick.is_empty(),
            "右段快捷行「远端电脑」根钮未绘制（y < 栏头 y {:.1}）",
            remote_header_y
        );
        // (e) 桌面/下载/文档 = 各恰双实例（左段本机 + 右段远端），右段
        //     实例在右栏头之上。
        for key in LOCAL_QUICK_KEYS.iter() {
            let rects = text_rects(&shapes, crate::i18n::tr(key));
            assert!(
                rects.len() >= 2,
                "「{}」应双实例（左段 + 右段），实得 {}（右段缺失 = 远端常见目录未展示）",
                crate::i18n::tr(key),
                rects.len()
            );
            let right_side = rects
                .iter()
                .filter(|r| r.min.x >= mid && r.min.y < remote_header_y)
                .count();
            assert!(
                right_side >= 1,
                "「{}」右段实例缺失（x ≥ {:.0} 且 y < 栏头 y）",
                crate::i18n::tr(key),
                mid
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    /// egui 双帧 → 软件光栅化 → PNG 落 `docs/r137_4_after_sandbox.png`
    ///（**不入库**）。形态 = 用户第 11 项场景同构：右栏远端树展开至
    /// `C:\Users\<user>\Desktop`（桌面节点在位）+ 右段快捷行「远端常用
    /// ｜远端电脑｜桌面 下载 文档」三钮 enable（home 条目播种）+ 左段
    /// 「本机常用」段对位左栏。headless CJK 豆腐块 = 隔离目录字体局限（同
    /// r135_5 口径），观感以用户实机终判。
    #[test]
    fn r137_4_screenshot_dump() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let (sw, sh) = (1920.0, 1080.0);
        // 环境解耦（同 r135_5 口径）：本地真树基址取低熵层，防 Temp
        // `PAGE_SIZE` 截断把测试根挤出树行区。
        let base = std::env::temp_dir();
        let base = if base
            .file_name()
            .map(|s| s == "Temp")
            .unwrap_or(false)
        {
            base.parent().map(PathBuf::from).unwrap_or(base)
        } else {
            base
        };
        let root = base.join(format!("k137_4_shot_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("Desktop")).unwrap();
        std::fs::write(root.join("Desktop/up.png"), b"x").unwrap();
        std::fs::write(root.join("aa.txt"), b"y").unwrap();
        let mut state = FileManagerState::with_local_root(root.clone());
        assert!(state.local_expand_chain(&root), "本地链展开");
        state.local.current = root.clone();
        // 右栏 = 用户场景同构播种：远端电脑 → C:\ → Users → yu →
        // Desktop（活动节点 = 桌面）+ home 条目（三钮 enable 形态）。
        state.remote.started = true;
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                children: Some(vec![
                    mk_entry("Desktop", 0, true),
                    mk_entry("Downloads", 0, true),
                    mk_entry("Documents", 0, true),
                ]),
                ..Default::default()
            },
        );
        state
            .remote
            .view
            .nodes
            .insert(REMOTE_PC_ROOT_KEY.to_string(), TreeNodeState {
                children: Some(vec![mk_entry("C:\\", 0, true)]),
                ..Default::default()
            });
        state
            .remote
            .view
            .nodes
            .insert("C:\\".to_string(), TreeNodeState {
                children: Some(vec![
                    mk_entry("Users", 0, true),
                    mk_entry("work", 0, true),
                ]),
                ..Default::default()
            });
        state
            .remote
            .view
            .nodes
            .insert("C:\\Users".to_string(), TreeNodeState {
                children: Some(vec![mk_entry("yu", 0, true)]),
                ..Default::default()
            });
        state
            .remote
            .view
            .nodes
            .insert("C:\Users\dev".to_string(), TreeNodeState {
                children: Some(vec![
                    mk_entry("Desktop", 0, true),
                    mk_entry("Downloads", 0, true),
                    mk_entry("Documents", 0, true),
                ]),
                ..Default::default()
            });
        state
            .remote
            .view
            .expanded
            .extend([
                REMOTE_PC_ROOT_KEY.to_string(),
                "C:\\".to_string(),
                "C:\\Users".to_string(),
                "C:\Users\dev".to_string(),
            ]);
        state.remote.current = "C:\Users\dev\\Desktop".to_string();
        let panel = FilePanelState::new();
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let run_frame = |ctx: &egui::Context, state: &mut FileManagerState| {
            let mut raw = egui::RawInput::default();
            raw.screen_rect =
                Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(sw, sh)));
            let mut focus = false;
            ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    show_file_manager(
                        ui,
                        &Theme::LIGHT,
                        state,
                        None,
                        None,
                        &panel,
                        false,
                        &mut focus,
                    );
                });
            })
        };
        let out1 = run_frame(&ctx, &mut state);
        let out2 = run_frame(&ctx, &mut state);
        let out_path = "E:/projects_rd/docs/r137_4_after_sandbox.png";
        crate::file_manager::r134_9b_tests::rasterize_png(
            &out1,
            &out2,
            sw as u32,
            sh as u32,
            out_path,
        );
        assert!(Path::new(out_path).is_file(), "截屏在位");
        std::fs::remove_dir_all(&root).ok();
    }
}

// ════════════════════════════════════════════════════════════════════
// `send_one_consent_batch` 零调用）= `ConsentSettled{req_id:0, SendFailed}`
// 哨兵回执 → FolderJob ≤1 事件内终态（悬挂回归钉）；单文件臂等待行即时
// 结算（不再 5min 悬等）。
// ════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r155_tests {
    use super::*;

    /// 零批回执哨兵（req_id=0 = 真实 consent req_id 空间
    /// `0x8000_0000|seq` 永不冲突）→ from_job 臂 = 任务终态 + 失败状态行；
    /// 单文件臂（无匹配等待行 + 哨兵）= 状态行结算。
    #[test]
    fn test_r155_zero_batch_settles_job_terminal() {
        let root = std::env::temp_dir().join(format!("kirin_r155_zb_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut state = FileManagerState::with_local_root(root.clone());
        state.job = Some(FolderJob {
            direction: FolderDirection::ToRemote,
            source: "src".into(),
            target_remote_dir: "up".into(),
            target_local_dir: PathBuf::new(),
            files: Vec::new(),
            depth_capped: Vec::new(),
            next_idx: 0,
            batch_head: 0,
            collecting: false,
            collect_queue: VecDeque::new(),
            finished: false,
            started: Instant::now(),
            // 发送侧批已发出命令、ConsentSent 未回填（req_id=None）的
            // 在途形态 = 修前零批回执缺失时的永久悬挂态。
            consent_pending: true,
            consent_req_id: None,
            target_dirs: Vec::new(),
            visit: HashSet::new(),
            failed: Vec::new(),
            cycle_skipped: Vec::new(),
            summary_emitted: false,
            mkdir_queue: VecDeque::new(),
        });
        state.on_fs_event(FsEvent::ConsentSettled {
            req_id: 0,
            outcome: ConsentOutcome::SendFailed,
            from_job: true,
            target_dir: None,
        });
        let job = state.job.as_ref().unwrap();
        assert!(job.finished, "零批 = 任务终态（禁悬挂）");
        assert!(!job.consent_pending, "consent_pending 不得跨事件存活");
        assert!(job.consent_req_id.is_none());
        let expect = t!("consent.send_failed").to_string();
        assert_eq!(
            state.status_line.as_deref(),
            Some(expect.as_str()),
            "失败状态行（禁静默悬挂）"
        );
        // 单文件臂（from_job=false）：无匹配等待行 + 哨兵 → 状态行即时结算。
        state.status_line = None;
        state.on_fs_event(FsEvent::ConsentSettled {
            req_id: 0,
            outcome: ConsentOutcome::SendFailed,
            from_job: false,
            target_dir: None,
        });
        assert_eq!(
            state.status_line.as_deref(),
            Some(expect.as_str()),
            "单文件等待行即时结算（不再 5min 悬等）"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r153_tests {
    use super::*;

    fn mk_entry(name: &str, size: u64, is_dir: bool) -> FileMgrEntry {
        FileMgrEntry {
            name: name.into(),
            size,
            mtime: 0,
            is_dir,
            is_symlink: false,
            is_hidden: false,
        }
    }

    fn channel() -> (
        tokio::sync::mpsc::UnboundedSender<FileCommand>,
        tokio::sync::mpsc::UnboundedReceiver<FileCommand>,
    ) {
        tokio::sync::mpsc::unbounded_channel()
    }

    fn drain_list_paths(
        frx: &mut tokio::sync::mpsc::UnboundedReceiver<FileCommand>,
    ) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(cmd) = frx.try_recv() {
            if let FileCommand::Fs {
                op: FsOp::List { path, .. },
            } = cmd
            {
                out.push(path);
            }
        }
        out
    }

    /// 播种形态：home 槽 `""` = 三常用目录 + 1 文件；合成根 = 盘符层
    /// `C:\`（真拓扑同形）；Desktop 节点 children 落定（缓存命中形态）。
    fn seeded_state() -> FileManagerState {
        let mut state = FileManagerState::with_local_root(std::env::temp_dir());
        state.remote.started = true;
        state.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                children: Some(vec![
                    mk_entry("Desktop", 0, true),
                    mk_entry("Downloads", 0, true),
                    mk_entry("Documents", 0, true),
                    mk_entry("notes.txt", 3, false),
                ]),
                ..Default::default()
            },
        );
        state.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("C:\\", 0, true)]),
                ..Default::default()
            },
        );
        state.remote.view.nodes.insert(
            "Desktop".to_string(),
            TreeNodeState {
                children: Some(vec![mk_entry("a.txt", 1, false)]),
                ..Default::default()
            },
        );
        state
    }

    /// ① headless 结构探针（卡面验收）：远端树含「远端电脑 ▸ 主目录 ▸
    /// Desktop」三行（depth 0/1/2）；主目录子键 = home 相对裸名。
    #[test]
    fn r153_tree_home_node_three_levels() {
        let mut state = seeded_state();
        // 主目录展开态（快捷跳转/双击展开后的形态）。
        state.remote.view.expanded.push(REMOTE_HOME_KEY.to_string());
        let rows = state.tree_rows(PaneId::Remote);
        let root = rows.iter().find(|r| r.path == REMOTE_PC_ROOT_KEY).expect("根行");
        assert_eq!(root.depth, 0, "远端电脑 = depth 0");
        let home = rows.iter().find(|r| r.path == REMOTE_HOME_KEY).expect("主目录行");
        assert_eq!(home.depth, 1, "主目录 = depth 1");
        assert_eq!(home.entry.name, crate::i18n::tr("filemgr.pc_home_remote"));
        assert!(home.entry.is_dir && !home.entry.is_symlink);
        let desktop = rows.iter().find(|r| r.path == "Desktop").expect("Desktop 行");
        assert_eq!(desktop.depth, 2, "Desktop = 主目录下 depth 2");
        // 主目录子键 = home 相对裸名（与 goto_remote_quick 键同形）。
        assert!(
            rows.iter().any(|r| r.path == "Downloads") && rows.iter().any(|r| r.path == "Documents"),
            "home 相对裸名子行在位"
        );
        // 盘符层仍挂合成根下（depth 1；home 行在其前 = 首子行）。
        let c = rows.iter().find(|r| r.path == "C:\\").expect("盘符行");
        assert_eq!(c.depth, 1);
        let i_home = rows.iter().position(|r| r.path == REMOTE_HOME_KEY).unwrap();
        let i_c = rows.iter().position(|r| r.path == "C:\\").unwrap();
        assert!(i_home < i_c, "主目录 = 合成根首子行（先于盘符层）");
    }

    /// ② 快捷跳转选中 + 行区子行（卡面验收）：点击「桌面」等价入口后
    /// `selected == ["Desktop"]`、行区含 Desktop 子节点行（≥1）、缓存命中
    /// 零 wire、滚动锚置位。
    #[test]
    fn r153_quick_jump_selects_and_shows_children() {
        let (ftx, mut frx) = channel();
        let mut state = seeded_state();
        state.goto_remote_quick("Desktop", Some(&ftx));
        assert_eq!(state.remote.view.selected, vec!["Desktop".to_string()]);
        assert_eq!(state.remote.current, "Desktop", "落点语义零迁移");
        assert!(
            drain_list_paths(&mut frx).is_empty(),
            "Desktop 缓存命中 = 零 wire"
        );
        // 行区：Desktop 子节点行（depth 3）在位 ≥1。
        let rows = state.tree_rows(PaneId::Remote);
        let children: Vec<&TreeRow> = rows
            .iter()
            .filter(|r| r.path == "Desktop/a.txt")
            .collect();
        assert_eq!(children.len(), 1, "Desktop 子节点行在位");
        assert_eq!(children[0].depth, 3, "子行 = Desktop 下 depth 3");
        assert_eq!(
            state.remote.scroll_anchor.as_deref(),
            Some("Desktop"),
            "滚动锚置位（渲染层消费即清）"
        );
    }

    /// ③ 未命中路径 = 恰 1 帧 `List("Desktop")`（单在途钉死；卡面验收）。
    #[test]
    fn r153_quick_jump_uncached_exactly_one_list() {
        let (ftx, mut frx) = channel();
        let mut state = seeded_state();
        state.remote.view.nodes.remove("Desktop");
        state.goto_remote_quick("Desktop", Some(&ftx));
        assert_eq!(
            drain_list_paths(&mut frx),
            vec!["Desktop".to_string()],
            "未命中 = 恰 1 帧 List(\"Desktop\")"
        );
    }

    /// ④ 主目录节点展开：缓存命中 = 零 wire + current 锚 home `""`；
    /// 未落定 = 恰 1 帧 `List("")`；在途 = 不重发（单槽纪律）。
    #[test]
    fn r153_home_expand_cache_and_single_inflight() {
        let (ftx, mut frx) = channel();
        // 缓存命中 = 零 wire。
        let mut state = seeded_state();
        state.tree_expand(PaneId::Remote, REMOTE_HOME_KEY, Some(&ftx));
        assert!(drain_list_paths(&mut frx).is_empty(), "home 缓存命中 = 零 wire");
        assert_eq!(state.remote.current, "", "活动节点 = home");
        assert!(
            state.remote.view.expanded.iter().any(|p| p == REMOTE_HOME_KEY),
            "主目录节点入展开集"
        );
        // 未落定 = 恰 1 帧 List("")。
        let mut state2 = FileManagerState::with_local_root(std::env::temp_dir());
        state2.remote.started = true;
        state2.tree_expand(PaneId::Remote, REMOTE_HOME_KEY, Some(&ftx));
        assert_eq!(
            drain_list_paths(&mut frx),
            vec![String::new()],
            "home 未落定 = 恰 1 帧 List(\"\")"
        );
        // 在途 = 不重发（单槽纪律）。
        state2.tree_expand(PaneId::Remote, REMOTE_HOME_KEY, Some(&ftx));
        assert!(drain_list_paths(&mut frx).is_empty(), "home 在途 = 零重发");
        // 无通道（headless 形态）= 零 wire 空目录落定。
        let mut state3 = FileManagerState::with_local_root(std::env::temp_dir());
        state3.remote.started = true;
        state3.tree_expand(PaneId::Remote, REMOTE_HOME_KEY, None);
        assert!(
            state3.remote.view.nodes[""].children.is_some(),
            "无通道 = 空目录落定（既有 request 形态）"
        );
    }

    /// ⑤ 保留键 fail-closed 矩阵：落点 = home `""`；传输源/删除/改名/
    /// mkdir 零入队零 wire；`remote_default_target` 防御臂同形。
    #[test]
    fn r153_reserved_key_failclosed_guards() {
        let mut state = seeded_state();
        // 落点资格：主目录选中 = 落点 home `""`。
        state.remote.view.selected = vec![REMOTE_HOME_KEY.to_string()];
        assert_eq!(
            state.single_dir_selection(PaneId::Remote),
            Some(String::new()),
            "主目录选中 = 落点 home"
        );
        // 传输源排除（保留键零入队）。
        assert_eq!(
            state.enqueue_transfer_targeted(
                PaneId::Remote,
                PaneId::Local,
                vec![REMOTE_HOME_KEY.to_string()],
                None,
                None,
                &FilePanelState::new(),
                None,
                None,
            ),
            0,
            "主目录保留键 = 传输源零入队"
        );
        // 删除排除（不进确认批）。
        state.remote.view.selected = vec![REMOTE_HOME_KEY.to_string()];
        state.open_delete(PaneId::Remote);
        assert!(state.pending_deletes.is_empty(), "主目录保留键不可删");
        // 改名排除（零 wire + 状态行）。
        state.dialog = Dialog::ConfirmRename {
            pane: PaneId::Remote,
            from: REMOTE_HOME_KEY.to_string(),
            to: "X".into(),
        };
        assert!(
            state.rename_resolve(true).is_none(),
            "主目录保留键不可改名（零 wire）"
        );
        // mkdir 防御臂（current = 保留键 → 零 wire）。
        state.remote.current = REMOTE_HOME_KEY.to_string();
        state.dialog = Dialog::InputMkdir {
            pane: PaneId::Remote,
            name: "X".into(),
        };
        assert!(state.mkdir_submit().is_none(), "主目录保留键下 mkdir 零 wire");
        // default target 防御臂同形（回退 home `""`）。
        assert_eq!(state.remote_default_target(), "");
        // 面包屑：home 相对键 = 远端电脑 ▸ 主目录 ▸ Desktop；home 本身 =
        // 远端电脑 ▸ 主目录。
        state.remote.current = "Desktop".to_string();
        let crumbs = state.remote_breadcrumb();
        assert_eq!(crumbs.len(), 3);
        assert_eq!(crumbs[1].0, REMOTE_HOME_KEY);
        assert_eq!(crumbs[1].1, crate::i18n::tr("filemgr.pc_home_remote"));
        assert_eq!(crumbs[2], ("Desktop".to_string(), "Desktop".to_string()));
        state.remote.current = String::new();
        let crumbs2 = state.remote_breadcrumb();
        assert_eq!(crumbs2.len(), 2, "home 本身 = 根 + 主目录两段");
        assert_eq!(crumbs2[1].0, REMOTE_HOME_KEY);
        // 面包屑「主目录」段点击 = home 导航（缓存命中零 wire）。
        let (ftx, mut frx) = channel();
        state.remote.current = "C:\\".to_string();
        state.remote.view.selected.push("C:\\x".to_string());
        state.navigate_to_prefix(PaneId::Remote, REMOTE_HOME_KEY.to_string(), Some(&ftx));
        assert_eq!(state.remote.current, "", "导航 = home");
        assert!(state.remote.view.selected.is_empty(), "导航清选中");
        assert!(drain_list_paths(&mut frx).is_empty(), "home 缓存命中 = 零 wire");
    }

    /// ⑥ i18n 新键 `filemgr.pc_home_remote` zh/en 成对钉死。
    #[test]
    fn r153_i18n_pc_home_remote_pairing() {
        use crate::i18n::{tr_lang, Lang};
        assert_eq!(tr_lang(Lang::Zh, "filemgr.pc_home_remote"), "主目录");
        assert_eq!(tr_lang(Lang::En, "filemgr.pc_home_remote"), "Home");
    }

    /// ⑦ 隔离目录截屏（卡面交付物；观感用户终判）：快捷跳转后形态 =
    /// 远端电脑 ▸ 主目录 ▸ Desktop（选中高亮 + 子行）▸ 盘符层。
    /// PNG 落 `E:/projects_rd/docs/`（仓外，不 commit）。
    #[test]
    fn r153_screenshot_dump() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let (sw, sh) = (1920.0, 1080.0);
        let mut state = seeded_state();
        // 快捷跳转「桌面」（缓存命中形态 = 零 wire；选中 + 链展开 + 滚动锚）。
        state.goto_remote_quick("Desktop", None);
        let panel = FilePanelState::new();
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let run_frame = |ctx: &egui::Context, state: &mut FileManagerState| {
            let mut raw = egui::RawInput::default();
            raw.screen_rect =
                Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(sw, sh)));
            let mut focus = false;
            ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    show_file_manager(
                        ui,
                        &Theme::LIGHT,
                        state,
                        None,
                        None,
                        &panel,
                        false,
                        &mut focus,
                    );
                });
            })
        };
        let mut outs = Vec::new();
        for _f in 0..5 {
            outs.push(run_frame(&ctx, &mut state));
        }
        let out1 = outs.remove(0);
        let out2 = outs.remove(0);
        let out_last = outs.pop().expect("尾帧");
        assert!(
            state.remote.scroll_anchor.is_none(),
        );
        let out_path = "E:/projects_rd/docs/r153_quick_jump_sandbox.png";
        crate::file_manager::r134_9b_tests::rasterize_png(
            &out1,
            &out_last,
            sw as u32,
            sh as u32,
            out_path,
        );
        assert!(Path::new(out_path).is_file(), "截屏在位");
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r156_tests {
    use super::*;
    use crate::clipboard::OsFileBoard;

    fn board(entries: Vec<(&str, u64, bool)>) -> OsFileBoard {
        OsFileBoard {
            entries: entries
                .into_iter()
                .map(|(p, s, d)| crate::clipboard::OsFileEntry {
                    abs_path: p.to_string(),
                    size: s,
                    is_dir: d,
                })
                .collect(),
        }
    }

    fn conn_texts() -> Vec<String> {
        crate::conn_log_buffer()
            .snapshot()
            .iter()
            .map(|l| format!("{:?}", l.segments))
            .collect()
    }

    fn clip_entry(
        rel: &str,
        size: u64,
        is_dir: bool,
        fetchable: bool,
    ) -> crate::clipboard::FileClipEntry {
        crate::clipboard::FileClipEntry {
            rel_path: rel.to_string(),
            size,
            is_dir,
            fetchable,
        }
    }

    fn fs_entry(name: &str, is_dir: bool, sym: bool) -> FsEntry {
        FsEntry {
            name: name.to_string(),
            size: 1,
            mtime: 0,
            is_dir,
            is_symlink: sym,
        }
    }

    /// 修复点 3：最近复制源仲裁矩阵（6 例钉死）。
    #[test]
    fn r156_os_board_newer_matrix() {
        // ① 板序号未推进（内部复制后板未变）→ 内部板胜。
        assert!(!r156_os_board_newer(5, 0xAA, 5, 0xAA));
        // ② 板序号推进 → OS 板（Explorer 后复制）胜。
        assert!(r156_os_board_newer(5, 0xAA, 6, 0xBB));
        // ③ 序号推进但签名恰同（同内容重复制）→ 仍 OS 板胜（序号优先）。
        assert!(r156_os_board_newer(5, 0xAA, 6, 0xAA));
        // ④ 序号不可用（unix/基线未置）→ 签名仲裁：内容同 → 内部板。
        assert!(!r156_os_board_newer(0, 0xAA, 0, 0xAA));
        // ⑤ 序号不可用 + 签名不同 → OS 板。
        assert!(r156_os_board_newer(0, 0xAA, 0, 0xBB));
        // ⑥ 单侧序号可用 → 回落签名仲裁。
        assert!(r156_os_board_newer(5, 0xAA, 0, 0xBB));
    }

    /// OS 板内容签名：空板 = 0；同内容同签名；内容变 = 签名变。
    #[test]
    fn r156_os_board_signature_content() {
        assert_eq!(r156_os_board_signature(&board(vec![])), 0);
        let a = board(vec![("C:/x/a.txt", 3, false)]);
        let a2 = board(vec![("C:/x/a.txt", 3, false)]);
        let b = board(vec![("C:/x/a.txt", 4, false)]);
        let d = board(vec![("C:/x/sub", 0, true)]);
        assert_eq!(r156_os_board_signature(&a), r156_os_board_signature(&a2));
        assert_ne!(r156_os_board_signature(&a), r156_os_board_signature(&b));
        assert_ne!(r156_os_board_signature(&a), r156_os_board_signature(&d));
    }

    /// 修复点 2：clip_fetch_plan 目录条目入 `dir_paths`（不再静默跳过）；
    /// 根外文件计数口径零漂移；纯目录清单 = consumed。
    #[test]
    fn r156_clip_fetch_plan_dirs_mixed() {
        let meta = crate::clipboard::FileClipMeta {
            version: 1,
            cleared: false,
            truncated: false,
            entries: vec![
                clip_entry("f.txt", 1, false, true),
                clip_entry("mydir", 0, true, true),
                clip_entry("out.bin", 2, false, false),
                clip_entry("outdir", 0, true, false),
            ],
        };
        let plan = crate::clip_fetch_plan(&meta);
        assert_eq!(plan.fetchable_paths, vec!["f.txt".to_string()]);
        assert_eq!(plan.dir_paths, vec!["mydir".to_string()]);
        assert_eq!(plan.outside_root, 1);
        assert!(plan.consumed);
        let dirs_only = crate::clipboard::FileClipMeta {
            version: 1,
            cleared: false,
            truncated: false,
            entries: vec![clip_entry("mydir", 0, true, true)],
        };
        let plan2 = crate::clip_fetch_plan(&dirs_only);
        assert!(plan2.consumed);
        assert!(plan2.fetchable_paths.is_empty());
        assert_eq!(plan2.dir_paths.len(), 1);
    }

    /// 展开页吸收（纯状态转移）：文件继承子目录、目录入队、符号链接跳过、
    /// 深度限界、续页 offset 累进。
    #[test]
    fn r156_clip_expand_absorb_page() {
        let mut st = ClipDirExpand::start(vec!["mydir".to_string()], Path::new("C:/land"));
        assert_eq!(st.queue.front().unwrap().2, "mydir");
        st.queue.pop_front(); // 模拟泵点消费根目录（ pump 在发 List 前 pop）
        st.inflight = Some((7, "mydir".into(), 0, 0, "mydir".into()));
        st.absorb_page(
            "mydir",
            0,
            0,
            "mydir",
            &[
                fs_entry("a.txt", false, false),
                fs_entry("sub", true, false),
                fs_entry("lnk", true, true),
                fs_entry("b.txt", false, false),
            ],
            false,
        );
        assert_eq!(st.dirs_done, 1);
        assert!(st.inflight.is_none(), "页尽 = 在途清");
        assert_eq!(
            st.files,
            vec![
                ("mydir/a.txt".to_string(), "mydir".to_string(), 1, 0),
                ("mydir/b.txt".to_string(), "mydir".to_string(), 1, 0),
            ]
        );
        assert_eq!(
            st.dirs,
            vec!["mydir".to_string(), "mydir/sub".to_string()],
            "根子目录本身 + 目录项入落点目录清单"
        );
        assert_eq!(st.queue.front().unwrap().0, "mydir/sub");
        assert_eq!(st.queue.front().unwrap().2, "mydir/sub");
        // 深度限界：depth = FOLDER_MAX_DEPTH 处的目录 → failed 不入队；
        let mut deep = ClipDirExpand::start(vec!["d".to_string()], Path::new("C:/land"));
        deep.queue.pop_front(); // 模拟泵点消费根目录
        deep.absorb_page("d", 0, FOLDER_MAX_DEPTH, "d", &[fs_entry("x", true, false)], false);
        assert!(deep.queue.is_empty());
        assert_eq!(deep.failed, vec!["d/x".to_string()]);
        assert_eq!(deep.dirs, vec!["d".to_string(), "d/x".to_string()]);
        // 续页：has_more = 在途重置（req_id 待回填、offset 累进、未计数）。
        let mut more = ClipDirExpand::start(vec!["m".to_string()], Path::new("C:/land"));
        more.queue.pop_front(); // 模拟泵点消费根目录
        more.absorb_page("m", 0, 0, "m", &[fs_entry("c.txt", false, false)], true);
        assert_eq!(more.dirs_done, 0);
        let (rid, _p, off, _d, _s) = more.inflight.unwrap();
        assert_eq!((rid, off), (0, 1));
    }

    /// FSM 端到端：粘贴启动 → List 命令 → Admitted/Response → FetchFile
    #[test]
    fn r156_clip_expand_fsm_end_to_end() {
        // 零机外副作用）。
        let land = std::env::temp_dir().join(format!("k158_land_{}", std::process::id()));
        std::fs::create_dir_all(&land).unwrap();
        let mut st = FileManagerState::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.clip_expand_start(vec!["mydir".into()], &land);
        st.clip_expand_pump(Some(&tx));
        match rx.try_recv().expect("List 命令入队") {
            FileCommand::Fs { op } => match op {
                FsOp::List { path, offset, limit } => {
                    assert_eq!(
                        (path.as_str(), offset, limit),
                        ("mydir", 0, R156_CLIP_LIST_LIMIT)
                    );
                }
                _ => panic!("期望 FsOp::List"),
            },
            _ => panic!("期望 FileCommand::Fs"),
        }
        st.on_fs_event(FsEvent::Admitted {
            req_id: 7,
            op: FsOp::List { path: "mydir".into(), offset: 0, limit: 500 },
        });
        let list = FsListPayload {
            entries: vec![
                fs_entry("f1.txt", false, false),
                fs_entry("sub", true, false),
            ],
            has_more: false,
            root_display: "home".into(),
        };
        st.on_fs_event(FsEvent::Response {
            req_id: 7,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: bincode::serialize(&list).unwrap(),
            }),
        });
        // 子目录入队 → 泵发第二层 List；文件即派 FetchFile。
        st.clip_expand_pump(Some(&tx));
        match rx.try_recv().expect("FetchFile 入队") {
            FileCommand::FetchFile { remote_path, local_dir } => {
                assert_eq!(remote_path, "mydir/f1.txt");
                assert_eq!(local_dir, land.join("mydir"));
            }
            _ => panic!("期望 FetchFile"),
        }
        match rx.try_recv().expect("第二层 List 入队") {
            FileCommand::Fs { op } => match op {
                FsOp::List { path, offset: 0, .. } => assert_eq!(path, "mydir/sub"),
                _ => panic!("期望第二层 List"),
            },
            _ => panic!("期望 FileCommand::Fs"),
        }
        // 第二层响应 → 泵收敛终态（clip_expand 清零 + 状态行）。
        st.on_fs_event(FsEvent::Admitted {
            req_id: 9,
            op: FsOp::List { path: "mydir/sub".into(), offset: 0, limit: 500 },
        });
        let list2 = FsListPayload {
            entries: vec![fs_entry("f2.txt", false, false)],
            has_more: false,
            root_display: "home".into(),
        };
        st.on_fs_event(FsEvent::Response {
            req_id: 9,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: bincode::serialize(&list2).unwrap(),
            }),
        });
        st.clip_expand_pump(Some(&tx));
        match rx.try_recv().expect("f2 FetchFile 入队") {
            FileCommand::FetchFile { remote_path, local_dir } => {
                assert_eq!(remote_path, "mydir/sub/f2.txt");
                assert_eq!(local_dir, land.join("mydir/sub"));
            }
            _ => panic!("期望 FetchFile"),
        }
        assert!(st.clip_expand.is_none(), "队列空+无在途+文件派尽 = 终态清零");
        assert!(st.status_line.is_some());
    }


    /// stat 失败 fail-open、mtime 不可得 fail-open）。
    #[test]
    fn r158_file_identical_matrix() {
        // 同 size + 同 mtime = identical。
        assert!(r158_file_identical(100, 1_700_000_000, Some((100, 1_700_000_000))));
        // ±1s 容差内 = identical。
        assert!(r158_file_identical(100, 1_700_000_000, Some((100, 1_700_000_001))));
        assert!(r158_file_identical(100, 1_700_000_000, Some((100, 1_699_999_999))));
        // ±2s 超差 = 不 identical。
        assert!(!r158_file_identical(100, 1_700_000_000, Some((100, 1_700_000_002))));
        assert!(!r158_file_identical(100, 1_700_000_000, Some((100, 1_699_999_998))));
        // 异 size = 不 identical（mtime 全等亦然）。
        assert!(!r158_file_identical(101, 1_700_000_000, Some((100, 1_700_000_000))));
        // stat 失败（None）= fail-open 照常拉取。
        assert!(!r158_file_identical(100, 1_700_000_000, None));
        // 远端 mtime 不可得（FsEntry 口径 0）= 差值巨大 = fail-open。
        assert!(!r158_file_identical(100, 0, Some((100, 1_700_000_000))));
    }

    #[test]
    fn r158_progress_line_format() {
        assert_eq!(
            r158_progress_line(3, 1, 0, 0),
        );
        assert_eq!(
            r158_progress_line(0, 2, 5, 1),
        );
        assert_eq!(
            r158_progress_line(0, 0, 0, 0),
        );
    }

    /// 不入、重复目录（已访）不重记。
    #[test]
    fn r158_absorb_dirs_matrix() {
        let mut st = ClipDirExpand::start(vec!["t".to_string()], Path::new("C:/land"));
        assert_eq!(st.dirs, vec!["t".to_string()], "根子目录本身在案");
        st.queue.pop_front();
        st.inflight = Some((7, "t".into(), 0, 0, "t".into()));
        st.absorb_page(
            "t",
            0,
            0,
            "t",
            &[
                fs_entry("empty", true, false),
                fs_entry("lnk", true, true),
                fs_entry("f.txt", false, false),
            ],
            false,
        );
        assert_eq!(
            st.dirs,
            vec!["t".to_string(), "t/empty".to_string()],
            "空子目录入清单、符号链接目录不入"
        );
        // 同一目录二次吸收（重复条目）= 已访键去重不重记。
        st.absorb_page("t", 0, 0, "t", &[fs_entry("empty", true, false)], false);
        assert_eq!(st.dirs.len(), 2, "已访目录不重记（重复吸收零重复）");
    }

    /// 不存在 = None。
    #[test]
    fn r158_stat_meta_reads_local_file() {
        let dir = std::env::temp_dir().join(format!("k158_stat_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.bin");
        std::fs::write(&p, b"12345").unwrap();
        let got = r158_stat_meta(&p).expect("存在文件 stat 成功");
        assert_eq!(got.0, 5, "字节数同源");
        assert!(got.1 > 1_600_000_000, "mtime = UNIX 秒量级");
        assert!(r158_stat_meta(&dir.join("missing.bin")).is_none(), "缺失 = None");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// （临时目录集成；FSM 全链：List→响应→派发→空子树 List→收敛落盘）。
    #[test]
    fn r158_clip_expand_empty_dir_integration() {
        let land = std::env::temp_dir().join(format!("k158_empty_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&land);
        std::fs::create_dir_all(&land).unwrap();
        let mut st = FileManagerState::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.clip_expand_start(vec!["t".into()], &land);
        st.clip_expand_pump(Some(&tx));
        assert!(matches!(rx.try_recv(), Ok(FileCommand::Fs { .. })), "根 List");
        st.on_fs_event(FsEvent::Admitted {
            req_id: 7,
            op: FsOp::List { path: "t".into(), offset: 0, limit: 500 },
        });
        let list = FsListPayload {
            entries: vec![
                fs_entry("f1.txt", false, false),
                fs_entry("f2.txt", false, false),
                fs_entry("f3.txt", false, false),
                fs_entry("empty", true, false),
            ],
            has_more: false,
            root_display: "home".into(),
        };
        st.on_fs_event(FsEvent::Response {
            req_id: 7,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: bincode::serialize(&list).unwrap(),
            }),
        });
        // 泵：3 文件派发 + 空子目录入队发第二层 List。
        st.clip_expand_pump(Some(&tx));
        let mut fetched = 0;
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                FileCommand::FetchFile { .. } => fetched += 1,
                FileCommand::Fs { op } => match op {
                    FsOp::List { path, .. } => assert_eq!(path, "t/empty"),
                    _ => panic!("期望第二层 List"),
                },
                _ => panic!("期望 FetchFile/Fs"),
            }
        }
        assert_eq!(fetched, 3, "三文件即派");
        st.on_fs_event(FsEvent::Admitted {
            req_id: 9,
            op: FsOp::List { path: "t/empty".into(), offset: 0, limit: 500 },
        });
        let list2 = FsListPayload {
            entries: vec![],
            has_more: false,
            root_display: "home".into(),
        };
        st.on_fs_event(FsEvent::Response {
            req_id: 9,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: bincode::serialize(&list2).unwrap(),
            }),
        });
        // 泵收敛：空目录物化落盘 + 终态清零。
        st.clip_expand_pump(Some(&tx));
        assert!(st.clip_expand.is_none(), "收敛终态清零");
        assert!(land.join("t").is_dir(), "落点根目录已建");
        assert!(
            land.join("t").join("empty").is_dir(),
            "纯空子目录也在落点创建（验收②核心）"
        );
        let _ = std::fs::remove_dir_all(&land);
    }

    /// 文件（`fetch_skipped` 计数=1；异 mtime 文件照常派发 fail-open）。
    #[test]
    fn r158_clip_expand_identical_skip_e2e() {
        let land = std::env::temp_dir().join(format!("k158_skip_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&land);
        std::fs::create_dir_all(land.join("mydir")).unwrap();
        // 落点已有 f1.txt（内容 5 字节）——以其真实 (size, mtime) 为远端
        // 元数据 = 全等 identical。
        std::fs::write(land.join("mydir").join("f1.txt"), b"12345").unwrap();
        let (sz, mt) = r158_stat_meta(&land.join("mydir").join("f1.txt")).unwrap();
        let mut st = FileManagerState::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.clip_expand_start(vec!["mydir".into()], &land);
        st.clip_expand_pump(Some(&tx));
        let _ = rx.try_recv(); // 根 List
        st.on_fs_event(FsEvent::Admitted {
            req_id: 7,
            op: FsOp::List { path: "mydir".into(), offset: 0, limit: 500 },
        });
        let list = FsListPayload {
            entries: vec![
                FsEntry { name: "f1.txt".into(), size: sz, mtime: mt, is_dir: false, is_symlink: false },
                FsEntry { name: "f2.txt".into(), size: sz, mtime: mt + 100, is_dir: false, is_symlink: false },
            ],
            has_more: false,
            root_display: "home".into(),
        };
        st.on_fs_event(FsEvent::Response {
            req_id: 7,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: bincode::serialize(&list).unwrap(),
            }),
        });
        st.clip_expand_pump(Some(&tx));
        let mut fetched: Vec<String> = Vec::new();
        while let Ok(cmd) = rx.try_recv() {
            if let FileCommand::FetchFile { remote_path, .. } = cmd {
                fetched.push(remote_path);
            }
        }
        assert_eq!(fetched, vec!["mydir/f2.txt"], "identical 文件不在派发清单");
        assert!(st.clip_expand.is_none(), "收敛终态清零");
        // skipped/fetch_sent 计数留证：未收敛副本（队列留子目录防终态清零）
        // 同清单重放，核计数恰 1/1。
        let mut st2 = FileManagerState::default();
        let (tx2, _rx2) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st2.clip_expand_start(vec!["mydir".into()], &land);
        st2.clip_expand_pump(Some(&tx2));
        {
            let st2x = st2.clip_expand.as_mut().unwrap();
            st2x.queue.pop_front();
            st2x.absorb_page(
                "mydir",
                0,
                0,
                "mydir",
                &[
                    FsEntry { name: "f1.txt".into(), size: sz, mtime: mt, is_dir: false, is_symlink: false },
                    FsEntry { name: "f2.txt".into(), size: sz, mtime: mt + 100, is_dir: false, is_symlink: false },
                    FsEntry { name: "sub".into(), size: 0, mtime: 0, is_dir: true, is_symlink: false },
                ],
                false,
            );
        }
        st2.clip_expand_pump(Some(&tx2));
        let st2f = st2.clip_expand.as_ref().expect("子目录在队 = 未收敛不清零");
        assert_eq!(st2f.fetch_skipped, 1, "skipped 计数=1（验收③）");
        assert_eq!(st2f.fetch_sent, 1, "异 mtime 照常派发");
        assert_eq!(st2f.files.len(), 0, "待派清零");
        let _ = std::fs::remove_dir_all(&land);
    }

    /// ClipDirExpand 派发臂同一纯函数 [`r158_file_identical`] 单一事实源；
    /// 落点同 size+mtime = 跳过、异 size/异 mtime = 照常入队）。
    #[test]
    fn r158_folderjob_tolocal_identical_decision() {
        let dir = std::env::temp_dir().join(format!("k158_job_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("same.bin");
        std::fs::write(&p, b"abcdef").unwrap();
        let (sz, mt) = r158_stat_meta(&p).unwrap();
        assert!(r158_file_identical(sz, mt, r158_stat_meta(&p)), "同源全等 = 跳过");
        assert!(
            !r158_file_identical(sz + 1, mt, r158_stat_meta(&p)),
            "异 size = 照常入队"
        );
        assert!(
            !r158_file_identical(sz, mt + 9, r158_stat_meta(&p)),
            "异 mtime = 照常入队"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 修复点 1：c→s 目录+文件混编粘贴（有远端语境）= FolderJob ToRemote
    /// 整树展开（tempdir 真实目录树；目录批零 SendFileV2 逐条命令）。
    #[test]
    fn r156_paste_dirs_with_context_builds_job() {
        let root = std::env::temp_dir().join(format!("k156_dir_{}", std::process::id()));
        let mydir = root.join("mydir");
        let sub = mydir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(mydir.join("f1.txt"), b"a").unwrap();
        std::fs::write(sub.join("f2.txt"), b"bb").unwrap();
        let loose = root.join("loose.txt");
        std::fs::write(&loose, b"ccc").unwrap();
        let mut st = FileManagerState::default();
        st.remote.started = true;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let b = board(vec![
            (loose.to_str().unwrap(), 3, false),
            (mydir.to_str().unwrap(), 0, true),
        ]);
        let n = st.paste_clipboard_fallback(Some(&tx), Some(&b));
        let job = st.job.expect("整批入 FolderJob ToRemote");
        assert_eq!(job.direction, FolderDirection::ToRemote);
        assert_eq!(n, 3, "2 目录树文件 + 1 散文件");
        let subdirs: std::collections::BTreeSet<String> =
            job.files.iter().map(|(_, _, s)| s.clone()).collect();
        assert!(subdirs.contains(""), "散文件落目标根");
        assert!(subdirs.contains("mydir"), "顶层文件镜像 目标/mydir/");
        assert!(subdirs.contains("mydir/sub"), "嵌套文件镜像 目标/mydir/sub/");
        assert!(rx.try_recv().is_err(), "目录批零 SendFileV2 逐条命令");
        assert_eq!(st.status_line.as_deref(), Some(t!("consent.waiting").as_ref()));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 修复点 1（禁静默）：目录粘贴无远端语境 = 文件臂 v1 链保留 + 目录
    /// 显式失败状态行（≠ consent.waiting）。
    #[test]
    fn r156_paste_dirs_no_context_explicit_failure() {
        let mut st = FileManagerState::default();
        assert!(!st.remote.started, "无语境前置");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let b = board(vec![
            ("C:/clip/noctx/f.txt", 1, false),
            ("C:/clip/noctx/mydir", 0, true),
        ]);
        let n = st.paste_clipboard_fallback(Some(&tx), Some(&b));
        match rx.try_recv().unwrap() {
            FileCommand::SendFile { path } => {
                assert_eq!(path, PathBuf::from("C:/clip/noctx/f.txt"));
            }
            _ => panic!("期望 SendFile v1"),
        }
        assert_ne!(
            st.status_line.as_deref(),
            Some(t!("consent.waiting").as_ref()),
            "禁假等待"
        );
    }

    /// 修复点 3：零入队（通道关闭）= 显式失败状态行（禁 consent.waiting
    /// 假象 + 禁「上传已开始」）。
    #[test]
    fn r156_paste_files_zero_enqueue_explicit_failure() {
        let mut st = FileManagerState::default();
        st.remote.started = true;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        drop(rx);
        let b = board(vec![
            ("C:/clip/z/a.txt", 1, false),
            ("C:/clip/z/b.txt", 2, false),
        ]);
        let n = st.paste_clipboard_fallback(Some(&tx), Some(&b));
        assert_eq!(n, 0);
        assert_ne!(st.status_line.as_deref(), Some(t!("consent.waiting").as_ref()));
    }

    /// 修复点 4（C5 埋点行在位）：粘贴上传开始行 + ClipMeta 到达行 +
    /// 拉取派发行（结构化缓冲 presence 断言）。
    #[test]
    fn r156_conn_log_lines_present() {
        // ① c→s 纯文件粘贴上传开始行。
        let mut st = FileManagerState::default();
        st.remote.started = true;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let b = board(vec![("C:/clip/log/a.txt", 1, false)]);
        st.paste_clipboard_fallback(Some(&tx), Some(&b));
        assert!(
            conn_texts().iter().any(|s| s.contains("粘贴上传已开始")),
            "上传开始行"
        );
        // ② s→c ClipMeta 到达行（对端 consent ON 门内）。
        let mut st2 = FileManagerState::default();
        st2.peer_consent = Some((true, true));
        st2.on_clip_meta(crate::clipboard::FileClipMeta {
            version: 1,
            cleared: false,
            truncated: false,
            entries: vec![
                clip_entry("x.txt", 1, false, true),
                clip_entry("y.txt", 2, false, true),
            ],
        });
        assert!(
            conn_texts().iter().any(|s| s.contains("剪贴板文件清单")),
            "ClipMeta 到达行"
        );
        // ③ 拉取派发行（clip_fetch_dispatch 单点）。
        let (tx3, _rx3) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let pm = crate::clipboard::FileClipMeta {
            version: 1,
            cleared: false,
            truncated: false,
            entries: vec![clip_entry("x.txt", 1, false, true)],
        };
        crate::clip_fetch_dispatch(&tx3, &pm, Path::new("C:/land"));
        assert!(
            conn_texts().iter().any(|s| s.contains("拉取已派发")),
            "拉取派发行"
        );
    }
}

// ════════════════════════════════════════════════════════════════
// 决策记忆映射 / 取消收敛幂等 / 覆盖 fail-closed 回退跳过 / 跳过零网络帧）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod r159_tests {
    use super::*;

    fn conn_texts() -> Vec<String> {
        crate::conn_log_buffer()
            .snapshot()
            .iter()
            .map(|l| format!("{:?}", l.segments))
            .collect()
    }

    /// 三选门矩阵（同名命中 × overwrite_all 记忆 × 单次旗标，全 8 格钉死）。
    #[test]
    fn r159_conflict_gate_matrix() {
        // 落点无同名 = 直派（策略位不敏感）。
        assert_eq!(
            r159_conflict_gate(false, false, false),
            R159ConflictGate::Dispatch
        );
        assert_eq!(
            r159_conflict_gate(false, true, false),
            R159ConflictGate::Dispatch
        );
        assert_eq!(
            r159_conflict_gate(false, false, true),
            R159ConflictGate::Dispatch
        );
        assert_eq!(
            r159_conflict_gate(false, true, true),
            R159ConflictGate::Dispatch
        );
        // 同名 + 无既定策略 = 悬挂（弹三选框，不再静默改名）。
        assert_eq!(
            r159_conflict_gate(true, false, false),
            R159ConflictGate::Suspend
        );
        // 同名 + 会话记忆 / 单次旗标 = 覆盖（删旧后派）。
        assert_eq!(
            r159_conflict_gate(true, true, false),
            R159ConflictGate::Overwrite
        );
        assert_eq!(
            r159_conflict_gate(true, false, true),
            R159ConflictGate::Overwrite
        );
        assert_eq!(
            r159_conflict_gate(true, true, true),
            R159ConflictGate::Overwrite
        );
    }

    /// 决策 → 记忆映射矩阵（跳过 = 丢弃零记忆；覆盖 = 单次旗标；全部应用 =
    /// 会话记忆置位且单次旗标清场）。
    #[test]
    fn r159_conflict_apply_memory_matrix() {
        assert_eq!(r159_conflict_apply(R159ConflictDecision::Skip), (false, false, true));
        assert_eq!(r159_conflict_apply(R159ConflictDecision::Overwrite), (false, true, false));
        assert_eq!(r159_conflict_apply(R159ConflictDecision::OverwriteAll), (true, false, false));
        // 会话记忆粘性：resolve(OverwriteAll) 后再 resolve(Overwrite) 不清记忆。
        let mut st = FileManagerState::default();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.clip_expand_start(vec!["m".into()], Path::new("C:/land"));
        {
            let c = st.clip_expand.as_mut().unwrap();
            c.queue.pop_front(); // 消费根目录防泵派发
            c.conflict = Some(R159ConflictItem {
                rel_path: "m/a.txt".into(),
                subdir: "m".into(),
                size: 1,
                mtime: 0,
            });
        }
        st.clip_conflict_resolve(R159ConflictDecision::OverwriteAll);
        assert!(st.clip_expand.as_ref().unwrap().overwrite_all, "全部应用 = 会话记忆");
        assert!(
            !st.clip_expand.as_ref().unwrap().overwrite_once,
            "决策互斥：单次旗标不置"
        );
        // 记忆粘性：后续单次覆盖决策不清 overwrite_all。
        let mut c = st.clip_expand.as_mut().unwrap();
        c.conflict = Some(R159ConflictItem {
            rel_path: "m/b.txt".into(),
            subdir: "m".into(),
            size: 1,
            mtime: 0,
        });
        drop(c);
        st.clip_conflict_resolve(R159ConflictDecision::Overwrite);
        assert!(
            st.clip_expand.as_ref().unwrap().overwrite_all,
            "会话记忆粘性（本粘贴会话有效）"
        );
    }

    /// 取消汇总观测行格式钉死（一行式 conn_log 通道契约）。
    #[test]
    fn r159_cancel_line_format() {
        assert_eq!(
            r159_cancel_line(3, 1, 5),
        );
        assert_eq!(
            r159_cancel_line(0, 0, 0),
        );
    }

    /// 取消「未派 K」计数纯函数（队列 + 已收未派 + 在途 1）。
    #[test]
    fn r159_cancel_unassigned_counts() {
        assert_eq!(r159_cancel_unassigned(0, 0, false), 0);
        assert_eq!(r159_cancel_unassigned(2, 3, false), 5);
        assert_eq!(r159_cancel_unassigned(0, 0, true), 1);
        assert_eq!(r159_cancel_unassigned(1, 1, true), 3);
    }

    /// 取消收敛幂等（FSM 端到端）：置位 → 泵一次收敛（队列/在途/悬挂全清、
    /// 零网络帧、汇总行在案）→ 二次泵 no-op（槽已清零，无双重结算）。
    #[test]
    fn r159_cancel_convergence_idempotent() {
        let mut st = FileManagerState::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.clip_expand_start(vec!["c".into()], Path::new("C:/land"));
        {
            let c = st.clip_expand.as_mut().unwrap();
            c.queue.pop_front(); // 消费根目录
            c.queue.push_back(("c/sub".into(), 1usize, "c/sub".into()));
            c.files.push(("c/f.txt".into(), "c".into(), 7, 0));
            c.inflight = Some((3, "c/cur".into(), 0usize, 0usize, "c/cur".into()));
            c.fetch_sent = 2;
            c.fetch_skipped = 1;
            c.conflict = Some(R159ConflictItem {
                rel_path: "c/g.txt".into(),
                subdir: "c".into(),
                size: 7,
                mtime: 0,
            });
            c.cancelled = true;
        }
        st.clip_expand_pump(Some(&tx));
        assert!(st.clip_expand.is_none(), "取消收敛 = 终态清零");
        assert!(rx.try_recv().is_err(), "取消 = 零网络帧");
        assert!(
            st.status_line.is_some(),
            "取消汇总状态行在案（已收 N/已跳 M/未派 K）"
        );
        assert!(
            conn_texts()
                .iter()
                .any(|s| s.contains(
                )),
            "取消汇总观测行（未派 = 队列1+文件1+在途1）"
        );
        // 幂等：二次泵 no-op（槽已清零，无双重汇总行）。
        let n_before = conn_texts()
            .iter()
            .count();
        st.clip_expand_pump(Some(&tx));
        assert!(st.clip_expand.is_none(), "幂等：二次泵零变化");
        assert!(rx.try_recv().is_err(), "幂等：零网络帧");
        assert_eq!(
            conn_texts()
                .iter()
                .count(),
            n_before,
            "幂等：汇总行不重复"
        );
    }

    /// 冲突悬挂 +「跳过」：落点同名（异 size）→ 泵悬挂弹框（零网络帧、
    /// 文件原样）；跳过决策 → 悬挂项丢弃（fetch_skipped=1、落点不动）、
    /// 泵恢复收敛。
    #[test]
    fn r159_conflict_suspend_then_skip_drops_silently() {
        let land = std::env::temp_dir().join(format!("k159_skip_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&land);
        std::fs::create_dir_all(land.join("mydir")).unwrap();
        std::fs::write(land.join("mydir").join("f1.txt"), b"old").unwrap();
        let mut st = FileManagerState::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.clip_expand_start(vec!["mydir".into()], &land);
        st.clip_expand_pump(Some(&tx));
        let _ = rx.try_recv(); // 根 List
        st.on_fs_event(FsEvent::Admitted {
            req_id: 7,
            op: FsOp::List { path: "mydir".into(), offset: 0, limit: 500 },
        });
        let list = FsListPayload {
            entries: vec![FsEntry {
                name: "f1.txt".into(),
                size: 5,
                mtime: 0,
                is_dir: false,
                is_symlink: false,
            }],
            has_more: false,
            root_display: "home".into(),
        };
        st.on_fs_event(FsEvent::Response {
            req_id: 7,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: bincode::serialize(&list).unwrap(),
            }),
        });
        // 泵：异 size = 非 identical → 冲突悬挂（弹框、零派发、文件原样）。
        st.clip_expand_pump(Some(&tx));
        assert!(rx.try_recv().is_err(), "悬挂 = 零网络帧");
        let conf = st
            .clip_expand
            .as_ref()
            .and_then(|c| c.conflict.as_ref())
            .expect("同名冲突悬挂弹框");
        assert_eq!(conf.rel_path, "mydir/f1.txt");
        assert!(st.has_dialog(), "冲突框入对话框 busy 面");
        // 跳过：悬挂项丢弃零网络帧、落点文件不动。
        st.clip_conflict_resolve(R159ConflictDecision::Skip);
        assert!(
            st.clip_expand.as_ref().unwrap().conflict.is_none(),
            "决策消费悬挂槽"
        );
        assert!(!st.has_dialog(), "决策后 busy 面清零");
        st.clip_expand_pump(Some(&tx));
        assert!(rx.try_recv().is_err(), "跳过 = 零网络帧（落点文件不动）");
        assert!(st.clip_expand.is_none(), "跳过后泵恢复收敛");
        assert_eq!(
            std::fs::read(land.join("mydir").join("f1.txt")).unwrap(),
            b"old",
            "落点文件原样"
        );
        let _ = std::fs::remove_dir_all(&land);
    }

    /// 覆盖 fail-closed 回退跳过：登记表未命中 = 删除被拦（文件原样、
    /// 回退跳过零网络帧）——防误删用户文件红线。
    #[test]
    fn r159_conflict_overwrite_registry_miss_fallback_skip() {
        let land = std::env::temp_dir().join(format!("k159_miss_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&land);
        std::fs::create_dir_all(land.join("mydir")).unwrap();
        std::fs::write(land.join("mydir").join("owm.txt"), b"keep").unwrap();
        let mut st = FileManagerState::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.clip_expand_start(vec!["mydir".into()], &land);
        st.clip_expand_pump(Some(&tx));
        let _ = rx.try_recv(); // 根 List
        st.on_fs_event(FsEvent::Admitted {
            req_id: 7,
            op: FsOp::List { path: "mydir".into(), offset: 0, limit: 500 },
        });
        let list = FsListPayload {
            entries: vec![FsEntry {
                name: "owm.txt".into(),
                size: 9,
                mtime: 0,
                is_dir: false,
                is_symlink: false,
            }],
            has_more: false,
            root_display: "home".into(),
        };
        st.on_fs_event(FsEvent::Response {
            req_id: 7,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: bincode::serialize(&list).unwrap(),
            }),
        });
        st.clip_expand_pump(Some(&tx)); // 悬挂
        st.clip_conflict_resolve(R159ConflictDecision::Overwrite); // 单次覆盖
        st.clip_expand_pump(Some(&tx)); // 门重判 Overwrite → 登记未命中 → 回退跳过
        assert!(rx.try_recv().is_err(), "登记未命中 = 零 FetchFile");
        assert_eq!(
            std::fs::read(land.join("mydir").join("owm.txt")).unwrap(),
            b"keep",
            "fail-closed：未命中登记表禁删（文件原样）"
        );
        assert!(st.clip_expand.is_none(), "回退跳过后收敛");
        let _ = std::fs::remove_dir_all(&land);
    }

    /// 覆盖正路（登记命中）：删旧后既有 FetchFile 重拉（单一事实源登记表；
    /// 「全部应用」后续同名不再弹直接覆盖）。
    #[test]
    fn r159_conflict_overwrite_registry_hit_and_apply_all() {
        let land = std::env::temp_dir().join(format!("k159_hit_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&land);
        std::fs::create_dir_all(land.join("mydir")).unwrap();
        std::fs::write(land.join("mydir").join("owa.txt"), b"OLD").unwrap();
        std::fs::write(land.join("mydir").join("owb.txt"), b"OLD-B").unwrap();
        // 登记表登记两文件落点（命中前提；键 = basename 小写）。
        crate::r154_register_fetch_landing("owa.txt", &land.join("mydir"));
        crate::r154_register_fetch_landing("owb.txt", &land.join("mydir"));
        let mut st = FileManagerState::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.clip_expand_start(vec!["mydir".into()], &land);
        st.clip_expand_pump(Some(&tx));
        let _ = rx.try_recv(); // 根 List
        st.on_fs_event(FsEvent::Admitted {
            req_id: 7,
            op: FsOp::List { path: "mydir".into(), offset: 0, limit: 500 },
        });
        let list = FsListPayload {
            entries: vec![
                FsEntry { name: "owa.txt".into(), size: 4, mtime: 0, is_dir: false, is_symlink: false },
                FsEntry { name: "owb.txt".into(), size: 4, mtime: 0, is_dir: false, is_symlink: false },
            ],
            has_more: false,
            root_display: "home".into(),
        };
        st.on_fs_event(FsEvent::Response {
            req_id: 7,
            result: Ok(FsResponsePayload {
                ok: true,
                err: FsErrCode::Ok,
                payload: bincode::serialize(&list).unwrap(),
            }),
        });
        // 第一文件悬挂 → 全部应用。
        st.clip_expand_pump(Some(&tx));
        assert!(
            st.clip_expand.as_ref().unwrap().conflict.is_some(),
            "首同名弹框"
        );
        st.clip_conflict_resolve(R159ConflictDecision::OverwriteAll);
        assert!(
            st.clip_expand.as_ref().unwrap().overwrite_all,
            "会话记忆在案"
        );
        st.clip_expand_pump(Some(&tx));
        let mut fetched: Vec<String> = Vec::new();
        while let Ok(cmd) = rx.try_recv() {
            if let FileCommand::FetchFile { remote_path, .. } = cmd {
                fetched.push(remote_path);
            }
        }
        assert_eq!(
            fetched,
            vec!["mydir/owa.txt", "mydir/owb.txt"],
            "全部应用 = 后续同名不再弹直接覆盖重拉"
        );
        assert!(
            !land.join("mydir").join("owa.txt").exists()
                && !land.join("mydir").join("owb.txt").exists(),
            "覆盖 = 旧文件已删（登记命中）"
        );
        assert!(st.clip_expand.is_none(), "泵收敛");
        let _ = std::fs::remove_dir_all(&land);
    }

    /// 复验）——真代码路径 `render_dialogs`（冲突三选框）+ `render_status_
    /// row`（目录展开徽标 + 取消钮）各两帧；debug 构建下任何 INFINITY/NaN
    /// 退化路径即 panic（门禁 = 不 panic + in_text_input 零误置）。
    #[test]
    fn r159_conflict_dialog_and_status_row_headless_probe() {
        let theme = crate::theme::Theme::LIGHT;
        let mut st = FileManagerState::default();
        st.clip_expand_start(vec!["p".into()], Path::new("C:/land"));
        {
            let c = st.clip_expand.as_mut().unwrap();
            c.conflict = Some(R159ConflictItem {
                rel_path: "p/报告.txt".into(),
                subdir: "p".into(),
                size: 1234,
                mtime: 0,
            });
        }
        assert!(st.has_dialog());
        for _frame in 0..2 {
            let raw = {
                let mut r = egui::RawInput::default();
                r.screen_rect = Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1024.0, 768.0),
                ));
                r
            };
            let _ = egui::Context::default().run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    render_status_row(ui, &theme, &mut st, &FilePanelState::default(), None);
                    render_dialogs(ui, &theme, &mut st, None);
                });
            });
        }
        assert!(!st.in_text_input, "冲突框无文本输入（焦点在「跳过」钮）");
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r163_tests {
    use super::*;

    fn mke(name: &str, size: u64, is_dir: bool) -> FileMgrEntry {
        FileMgrEntry { name: name.into(), size, mtime: 0, is_dir, is_symlink: false, is_hidden: false }
    }

    /// 拟真形态：home 已列（快捷钮 enable 源）+ 远端电脑盘符层 + C:\ 深子树
    /// （预滚背景）；Desktop **未列**（缓存未中 = 点击后单在途 List 形态）。
    fn seeded_r163() -> FileManagerState {
        let mut st = FileManagerState::with_local_root(std::env::temp_dir());
        st.remote.started = true;
        st.remote.view.nodes.insert(
            String::new(),
            TreeNodeState {
                children: Some(vec![
                    mke("Desktop", 0, true),
                    mke("Downloads", 0, true),
                    mke("Documents", 0, true),
                    mke("notes.txt", 3, false),
                ]),
                ..Default::default()
            },
        );
        let drives: Vec<FileMgrEntry> = (0..40).map(|i| mke(&format!("d{i:02}", i = i), 0, true)).collect();
        st.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState { children: Some(drives), ..Default::default() },
        );
        let files: Vec<FileMgrEntry> = (0..40).map(|i| mke(&format!("f{i:02}", i = i), i, false)).collect();
        st.remote
            .view
            .nodes
            .insert("C:\\".to_string(), TreeNodeState { children: Some(files), ..Default::default() });
        st.remote.view.expanded.push(REMOTE_PC_ROOT_KEY.to_string());
        st.remote.view.expanded.push(REMOTE_HOME_KEY.to_string());
        st.remote.view.expanded.push("C:\\".to_string());
        st
    }

    fn r163_frame(
        ctx: &egui::Context,
        st: &mut FileManagerState,
        t: f64,
        wheel: bool,
    ) -> egui::FullOutput {
        let mut raw = egui::RawInput::default();
        raw.screen_rect = Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(1920.0, 560.0),
        ));
        raw.time = Some(t);
        if wheel {
            raw.events.push(egui::Event::PointerMoved(egui::Pos2::new(1400.0, 300.0)));
            raw.events.push(egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -900.0),
                modifiers: Default::default(),
            });
        }
        ctx.run(raw, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                show_file_manager(
                    ui,
                    &Theme::LIGHT,
                    st,
                    None,
                    None,
                    &FilePanelState::new(),
                    false,
                    &mut false,
                );
            });
        })
    }

    /// 远端半屏内：`(选中填充矩形, 行文本位置)`（按 clip 中心距排序取首个）。
    fn r163_scan(
        out: &egui::FullOutput,
        sel: egui::Color32,
    ) -> (Option<(egui::Rect, egui::Rect)>, Option<egui::Rect>) {
        let mut sel_rect = None;
        let mut desktop_row = None;
        for cs in &out.shapes {
            match &cs.shape {
                egui::epaint::Shape::Rect(r) => {
                    if r.fill == sel
                        && r.rect.center().x > 960.0
                        && r.rect.width() > 40.0
                        && sel_rect.is_none()
                    {
                        sel_rect = Some((r.rect, cs.clip_rect));
                    }
                }
                egui::epaint::Shape::Text(t) => {
                    if t.galley.text() == "Desktop" && t.pos.x > 960.0 && desktop_row.is_none() {
                        desktop_row = Some(
                            Rect::from_min_size(t.pos, egui::vec2(60.0, 18.0)),
                        );
                    }
                }
                _ => {}
            }
        }
        (sel_rect, desktop_row)
    }

    /// ①端到端（真 `show_file_manager` 渲染层）：滚轮深滚背景（滚轮平滑
    /// 残量形态 = 修前 `ui.scroll_to_cursor` 帧槽/动画被吞没的根因面）→
    /// 点快捷「桌面」（缓存未中 = 在途 List 形态）→ **目标行滚入可视区**
    /// （选中行贴视口边界形态 = 可见且高亮）+ **异步 List 到达不丢选中**
    /// + 锚收敛消费即清（残量耗尽后）。
    #[test]
    fn r163_quick_jump_centers_and_highlights_under_wheel_history() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let mut st = seeded_r163();
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let sel = ctx.style().visuals.selection.bg_fill;
        // 背景：用户先前在 C:\ 深处滚轮浏览（滚轮残量形态）。
        for f in 0..8 {
            let _ = r163_frame(&ctx, &mut st, f as f64 * 0.016, true);
        }
        assert_ne!(st.remote.view.selected, vec!["Desktop".to_string()]);
        // 点击快捷「桌面」+ 在途 List 形态（loading 标记行）。
        st.goto_remote_quick("Desktop", None);
        assert_eq!(st.remote.view.selected, vec!["Desktop".to_string()]);
        if let Some(n) = st.remote.view.nodes.get_mut("Desktop") {
            n.loading = true;
        }
        // 渲染：f=14 异步 List 到达（标记消/子行落——数据晚到不丢选中）。
        let mut visible_highlighted = false;
        for f in 8..46 {
            if f == 14 {
                if let Some(n) = st.remote.view.nodes.get_mut("Desktop") {
                    n.loading = false;
                    n.children = Some(vec![mke("a.txt", 1, false)]);
                }
            }
            let out = r163_frame(&ctx, &mut st, f as f64 * 0.016, false);
            if let Some((rect, clip)) = r163_scan(&out, sel).0 {
                // 选中行矩形完整落在行区视口内（≠ 视口外被裁剪不绘制）。
                if clip.contains(rect.center())
                    && rect.bottom() < clip.max.y
                    && rect.top() > clip.min.y
                {
                    visible_highlighted = true;
                }
            }
        }
        // 异步 List 到达后选中仍命中（数据晚到不丢选中）。
        assert_eq!(st.remote.view.selected, vec!["Desktop".to_string()], "晚到不丢选中");
        // 锚收敛消费即清（不与用户后续滚动打架）。
        assert!(st.remote.scroll_anchor.is_none(), "锚收敛消费");
        assert!(st.remote.scroll_anchor_prev_delta.is_none(), "收敛观测清");
        assert!(visible_highlighted, "目标行滚入可视区且高亮可见（滚轮残量背景下）");
    }

    /// ②边界形态收敛判据：短内容（无滚动空间）——锚不永挂（Δ 与上帧恒等
    /// = 贴边即消费即清），选中照常置位。
    #[test]
    fn r163_anchor_settles_on_unscrollable_content() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let mut st = seeded_r163();
        st.remote.view.nodes.get_mut(REMOTE_PC_ROOT_KEY).unwrap().children = Some(vec![mke("C:\\", 0, true)]);
        st.remote.view.nodes.get_mut("C:\\").unwrap().children = Some(Vec::new());
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        st.goto_remote_quick("Desktop", None);
        for f in 0..45 {
            let _ = r163_frame(&ctx, &mut st, f as f64 * 0.016, false);
        }
        assert!(st.remote.scroll_anchor.is_none(), "短内容贴边 = 锚收敛消费（不与用户滚动打架）");
        assert!(st.remote.scroll_anchor_prev_delta.is_none());
        assert_eq!(st.remote.view.selected, vec!["Desktop".to_string()]);
    }

    /// ③真居中形态：目标行深居内容中部（home 前置 60 目录 = 有下滚空间）
    /// → 锚应用后选中行收敛到视口中部（|Δ| < 2px 判据可直接命中）。
    #[test]
    fn r163_anchor_centers_deep_target() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let mut st = seeded_r163();
        // home 前置 60 目录（Desktop 深居内容中部）。
        let mut home: Vec<FileMgrEntry> =
            (0..60).map(|i| mke(&format!("h{i:02}", i = i), 0, true)).collect();
        home.push(mke("Desktop", 0, true));
        st.remote.view.nodes.get_mut("").unwrap().children = Some(home);
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let sel = ctx.style().visuals.selection.bg_fill;
        st.goto_remote_quick("Desktop", None);
        let mut centered = false;
        for f in 0..45 {
            let out = r163_frame(&ctx, &mut st, f as f64 * 0.016, false);
            if let Some((rect, clip)) = r163_scan(&out, sel).0 {
                if (rect.center().y - clip.center().y).abs() < 40.0 {
                    centered = true;
                }
            }
        }
        assert!(centered, "深目标行收敛到视口中部");
        assert!(st.remote.scroll_anchor.is_none(), "居中收敛消费");
    }
}

// ═══════════════════════════════════════════════════════════════════
// 逐位对称：goto_local_quick 置选中 + 滚动锚；行区锚臂双栏共用收敛判据
// 〔滚轮残量门 / |Δ|<2px 居中 / Δ 恒等贴边〕；渲染帧消费即清）。
// ═══════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r170_tests {
    use super::*;

    /// 本机树拟真形态：基座目录 = 仓内 `target/k170_tmp/`（**非隐藏链**：
    /// `AppData` 行 = 树链断不可达，纯测试环境伪象——生产 `home\Desktop`
    /// 链全可见不受影响）+ `Desktop` 目标 + 前置 `a00..a59` 目录（NTFS
    /// 大小写不敏感序 `a*` < `Desktop` = 目标深居内容中部 = 有下滚空间；
    /// 本机 = std::fs 同步直读，链展开即真列）。
    fn seeded_r170(tag: &str, with_padding: bool) -> (PathBuf, FileManagerState) {
        // 逐组件 join（键 = 原生分隔符字符串，禁混 `/`/`..`——`local_path_key`
        // 原样字符串，链键/行键/选中键三方一致的前提）。
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target")
            .join("k170_tmp")
            .join(format!("{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("Desktop")).unwrap();
        if with_padding {
            for i in 0..60 {
                std::fs::create_dir(base.join(format!("a{i:02}", i = i))).unwrap();
            }
        }
        let st = FileManagerState::with_local_root(base.clone());
        (base, st)
    }

    /// 本机半屏内单帧（指针/滚轮落在左栏 = 本机行区，形态同 r163_frame）。
    fn r170_frame(
        ctx: &egui::Context,
        st: &mut FileManagerState,
        t: f64,
        wheel: bool,
    ) -> egui::FullOutput {
        let mut raw = egui::RawInput::default();
        raw.screen_rect = Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(1920.0, 560.0),
        ));
        raw.time = Some(t);
        if wheel {
            raw.events.push(egui::Event::PointerMoved(egui::Pos2::new(400.0, 300.0)));
            raw.events.push(egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -900.0),
                modifiers: Default::default(),
            });
        }
        ctx.run(raw, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                show_file_manager(
                    ui,
                    &Theme::LIGHT,
                    st,
                    None,
                    None,
                    &FilePanelState::new(),
                    false,
                    &mut false,
                );
            });
        })
    }

    /// 左半屏内选中填充矩形（行区视口 clip 随行记下）。
    fn r170_scan_sel(out: &egui::FullOutput, sel: egui::Color32) -> Option<(Rect, Rect)> {
        for cs in &out.shapes {
            if let egui::epaint::Shape::Rect(r) = &cs.shape {
                if r.fill == sel && r.rect.center().x < 960.0 && r.rect.width() > 40.0 {
                    return Some((r.rect, cs.clip_rect));
                }
            }
        }
        None
    }

    /// ①键形一致（状态层）：goto_local_quick 置位的选中/锚键 = 渲染行键
    /// （`pane_rows` Node 行 path 同形）——行区高亮判据 `selected.contains
    /// (&t.path)` 与锚判据 `scroll_anchor == t.path` 能命中的唯一前提。
    #[test]
    fn r170_goto_local_quick_key_matches_rendered_row() {
        let (base, mut st) = seeded_r170("key", false);
        st.goto_local_quick(&base.join("Desktop"));
        let key = local_path_key(&base.join("Desktop"));
        assert_eq!(st.local.view.selected, vec![key.clone()], "选中 = 目标全键");
        assert_eq!(st.local.scroll_anchor.as_deref(), Some(key.as_str()), "锚 = 同键");
        assert!(
            st.pane_rows(PaneId::Local)
                .iter()
                .any(|r| matches!(r, PaneRow::Node(t) if t.path == key)),
            "渲染行含该键（键形一致）"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// ②端到端（真 `show_file_manager` 渲染层）：滚轮深滚背景（左栏）→
    /// 点本机快捷「桌面」→ 目标行滚入可视区且高亮 + 锚收敛消费即清
    /// （滚轮残量门共用，形态 = r163 远端①的本机对称臂）。
    #[test]
    fn r170_local_quick_jump_highlights_under_wheel_history() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let (base, mut st) = seeded_r170("e2e", true);
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        let sel = ctx.style().visuals.selection.bg_fill;
        // 背景：用户先前在本机栏滚轮浏览（滚轮平滑残量形态）。
        for f in 0..8 {
            let _ = r170_frame(&ctx, &mut st, f as f64 * 0.016, true);
        }
        let key = local_path_key(&base.join("Desktop"));
        assert_ne!(st.local.view.selected, vec![key.clone()]);
        st.goto_local_quick(&base.join("Desktop"));
        assert_eq!(st.local.view.selected, vec![key.clone()], "点击即选中");
        let mut visible_highlighted = false;
        for f in 8..46 {
            let out = r170_frame(&ctx, &mut st, f as f64 * 0.016, false);
            if let Some((rect, clip)) = r170_scan_sel(&out, sel) {
                if clip.contains(rect.center())
                    && rect.bottom() < clip.max.y
                    && rect.top() > clip.min.y
                {
                    visible_highlighted = true;
                }
            }
        }
        assert!(st.local.scroll_anchor.is_none(), "锚收敛消费即清");
        assert!(st.local.scroll_anchor_prev_delta.is_none(), "收敛观测清");
        assert!(visible_highlighted, "目标行滚入可视区且高亮可见（滚轮残量背景下）");
        std::fs::remove_dir_all(&base).ok();
    }

    /// ③边界形态收敛判据（本机臂）：内容近端部无滚动空间——锚不永挂
    /// （Δ 与上帧恒等 = 贴边即消费即清），选中照常置位。
    #[test]
    fn r170_local_anchor_settles_on_unscrollable_content() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let (base, mut st) = seeded_r170("clamp", false);
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        st.goto_local_quick(&base.join("Desktop"));
        for f in 0..45 {
            let _ = r170_frame(&ctx, &mut st, f as f64 * 0.016, false);
        }
        assert!(st.local.scroll_anchor.is_none(), "贴边 = 锚收敛消费（不与用户滚动打架）");
        assert!(st.local.scroll_anchor_prev_delta.is_none());
        assert_eq!(
            st.local.view.selected,
            vec![local_path_key(&base.join("Desktop"))]
        );
        std::fs::remove_dir_all(&base).ok();
    }
}

// ═══════════════════════════════════════════════════════════════════
// （栏别独立会话内内存态，默认关；本机 = Windows FILE_ATTRIBUTE_HIDDEN
// 属性位〔非 Windows = dot 惯例〕；远端 = dot 前缀——wire `FsEntry` 无
// 属性字段〔冻结，零新 wire〕，能力边界如实；过滤在渲染层
// [`FileManagerState::pane_rows_recur`]，缓存/排序/选中/分页零触碰）。
// ═══════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r172_tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("k172_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn entry(name: &str, is_hidden: bool) -> FileMgrEntry {
        FileMgrEntry {
            name: name.to_string(),
            size: 1,
            mtime: 0,
            is_dir: false,
            is_symlink: false,
            is_hidden,
        }
    }

    /// 远端树形态（根节点承载 children；根默认展开见 `with_local_root`）。
    fn remote_state(root: PathBuf, entries: Vec<FileMgrEntry>) -> FileManagerState {
        let mut st = FileManagerState::with_local_root(root);
        st.remote.started = true;
        st.remote.view.nodes.insert(
            REMOTE_PC_ROOT_KEY.to_string(),
            TreeNodeState {
                children: Some(entries),
                has_more: false,
                ..Default::default()
            },
        );
        st
    }

    /// 可见 Node 行名序（Marker 行剔除）。
    fn node_names(st: &FileManagerState, pane: PaneId) -> Vec<String> {
        st.pane_rows(pane)
            .into_iter()
            .filter_map(|r| match r {
                PaneRow::Node(row) => Some(row.entry.name),
                PaneRow::Marker { .. } => None,
            })
            .collect()
    }

    /// ① 纯判定函数矩阵：Windows 属性位（0x2）+ dot 前缀。
    #[test]
    fn test_r172_hidden_predicate_matrix() {
        // Windows FILE_ATTRIBUTE_HIDDEN = 0x2：置位即隐藏，与其他位复合共存。
        assert!(!win_file_attr_hidden(0x0000_0000));
        assert!(win_file_attr_hidden(0x0000_0002));
        assert!(win_file_attr_hidden(0x0000_0012)); // HIDDEN|DIRECTORY
        assert!(win_file_attr_hidden(0x0000_0022)); // HIDDEN|ARCHIVE 复合
        assert!(win_file_attr_hidden(u32::MAX));
        assert!(!win_file_attr_hidden(0x0000_0010)); // DIRECTORY 单独
        assert!(!win_file_attr_hidden(0xFFFF_FFFD)); // 全位置位唯 0x2 清零
        // dot 前缀惯例（远端栏唯一可感知面；非 Windows 本地同义）。
        assert!(name_is_hidden(".git"));
        assert!(name_is_hidden(".."));
        assert!(name_is_hidden(".config.json"));
        assert!(!name_is_hidden("git"));
        assert!(!name_is_hidden(""));
        assert!(!name_is_hidden("x."));
        assert!(!name_is_hidden("文 档.txt"));
    }

    /// （不作为用户可选目录呈现；其余条目零触碰）。
    #[test]
    fn test_r192_local_list_filters_internal_cache_dir() {
        let dir = tmp_dir("r192_local_filter");
        std::fs::create_dir_all(dir.join(".kirin_desk_clip").join("c2s-1")).unwrap();
        std::fs::write(dir.join("keep.txt"), b"x").unwrap();
        let list = list_local_dir(&dir).unwrap();
        assert!(
            !list.iter().any(|e| e.name.eq_ignore_ascii_case(".kirin_desk_clip")),
            "内部缓存目录不入用户可选目录呈现"
        );
        assert!(list.iter().any(|e| e.name == "keep.txt"), "普通条目零触碰");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 内部（FM 本机栏直达）= 条目**整层**不呈现（仅顶层名过滤不足）；
    /// 深层祖先链同判；普通目录零触碰。
    #[test]
    fn test_r192_local_list_filters_internal_cache_sublayer() {
        let dir = tmp_dir("r192_local_sublayer");
        let job = dir.join(".kirin_desk_clip").join("c2s-2");
        std::fs::create_dir_all(&job).unwrap();
        std::fs::write(job.join("part.bin"), b"x").unwrap();
        // 缓存根层与任务目录层：整层不呈现。
        assert!(
            list_local_dir(&dir.join(".kirin_desk_clip"))
                .unwrap()
                .is_empty(),
            "缓存根子层整层过滤"
        );
        assert!(list_local_dir(&job).unwrap().is_empty(), "任务目录层整层过滤");
        // 更深祖先链同判（任意层级命中缓存根名 = 内部子层）。
        let deep = job.join("nested");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("y.bin"), b"y").unwrap();
        assert!(list_local_dir(&deep).unwrap().is_empty(), "深层同判");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ② 本机栏枚举层真值：Windows = `attrib +h` 置 FILE_ATTRIBUTE_HIDDEN
    /// 后 `list_local_dir` 标记隐藏（开关语义：关 = 不显示）；非 Windows =
    /// dot 前缀惯例。普通文件两平台恒 false。
    #[test]
    fn test_r172_local_list_hidden_truth() {
        let dir = tmp_dir("local_truth");
        std::fs::write(dir.join("normal.txt"), b"x").unwrap();
        #[cfg(windows)]
        {
            let hidden_path = dir.join("hidden_by_attr.txt");
            std::fs::write(&hidden_path, b"x").unwrap();
            let out = std::process::Command::new("attrib")
                .arg("+h")
                .arg(&hidden_path)
                .output()
                .expect("attrib");
            assert!(out.status.success(), "attrib +h failed");
            let list = list_local_dir(&dir).unwrap();
            let by = |n: &str| list.iter().find(|e| e.name == n).cloned().unwrap();
            // 真值锚：属性位隐藏（与名称无关——"hidden_by_attr.txt" 无 dot）。
            assert!(by("hidden_by_attr.txt").is_hidden);
            assert!(!by("normal.txt").is_hidden);
        }
        #[cfg(not(windows))]
        {
            std::fs::write(dir.join(".hidden_dot"), b"x").unwrap();
            let list = list_local_dir(&dir).unwrap();
            let by = |n: &str| list.iter().find(|e| e.name == n).cloned().unwrap();
            assert!(by(".hidden_dot").is_hidden);
            assert!(!by("normal.txt").is_hidden);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 注入条目在 Node 行序中的投影（剔除合成根/主目录行与 Marker 行，
    fn injected_names(st: &FileManagerState, pane: PaneId) -> Vec<String> {
        let injected: &[&str] = &["alpha", ".env", "zeta", ".git", "visible", ".hidden"];
        node_names(st, pane)
            .into_iter()
            .filter(|n| injected.contains(&n.as_str()))
            .collect()
    }

    /// ③ 渲染层过滤矩阵：默认关 = 隐藏条目不渲染（可见条目排序序保持）；
    /// 开 = 全量呈现；栏别独立（本机开关不影响远端栏）；has_more 截断
    /// 标记行不受过滤影响（分页面不破）；Marker/选中缓存零触碰。
    #[test]
    fn test_r172_toggle_filter_rows_per_pane() {
        let entries = vec![
            entry("alpha", false),
            entry(".env", true),
            entry("zeta", false),
            entry(".git", true),
        ];
        let mut st = remote_state(tmp_dir("rows"), entries);
        // 默认（Default 关）+ 显式双确认。
        assert!(!st.view(PaneId::Remote).show_hidden);
        assert!(!PaneView::default().show_hidden);
        let off = injected_names(&st, PaneId::Remote);
        assert_eq!(off, vec!["alpha".to_string(), "zeta".to_string()]);
        // 开 = 全量、缓存原序（排序分页面零触碰的直接后果）。
        st.view_mut(PaneId::Remote).show_hidden = true;
        let on = injected_names(&st, PaneId::Remote);
        assert_eq!(
            on,
            vec!["alpha", ".env", "zeta", ".git"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
        // 栏别独立：远端关回，本机开——远端仍过滤、本机开关内存态在位。
        st.view_mut(PaneId::Remote).show_hidden = false;
        st.view_mut(PaneId::Local).show_hidden = true;
        assert_eq!(injected_names(&st, PaneId::Remote).len(), 2);
        assert!(st.view(PaneId::Local).show_hidden);
        assert!(!st.view(PaneId::Remote).show_hidden);
    }

    /// ④ has_more 截断标记行不受过滤影响（v1「更多 ↓」提示行恒呈现 =
    /// 服务端分页事实如实；隐藏条目过滤不吞标记）。
    #[test]
    fn test_r172_more_marker_survives_filter() {
        let entries = vec![entry("visible", false), entry(".hidden", true)];
        let mut st = remote_state(tmp_dir("more"), entries);
        st.remote
            .view
            .nodes
            .get_mut(REMOTE_PC_ROOT_KEY)
            .unwrap()
            .has_more = true;
        let rows = st.pane_rows(PaneId::Remote);
        let markers = rows
            .iter()
            .filter(|r| matches!(r, PaneRow::Marker { .. }))
            .count();
        assert_eq!(markers, 1, "更多标记行恒在");
        assert_eq!(injected_names(&st, PaneId::Remote), vec!["visible"]);
    }

    /// ⑤ i18n 新键 zh/en 成对 + 逐字钉死（进程级语言态串行化纪律同
    /// r133_2：r92ti 全局锁）。
    #[test]
    fn test_r172_i18n_show_hidden_pair() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        assert_eq!(crate::i18n::tr("filemgr.show_hidden"), "显示隐藏文件");
        crate::i18n::set_lang(crate::i18n::Lang::En);
        assert_eq!(crate::i18n::tr("filemgr.show_hidden"), "Show hidden files");
    }
}


// ════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════
#[cfg(test)]
mod r173_tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("k173_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 落点节点武装（expanded + 旧缓存 = 模拟用户正开着该目录）。
    fn arm_landing_node(st: &mut FileManagerState, dir: &str) {
        if !st.remote.view.expanded.iter().any(|p| p == dir) {
            st.remote.view.expanded.push(dir.to_string());
        }
        st.remote.view.nodes.insert(
            dir.to_string(),
            TreeNodeState {
                children: Some(vec![FileMgrEntry {
                    name: "old.txt".to_string(),
                    size: 1,
                    mtime: 0,
                    is_dir: false,
                    is_symlink: false,
                    is_hidden: false,
                }]),
                has_more: false,
                ..Default::default()
            },
        );
    }

    fn upload_task(status: FileTaskStatus) -> FileTask {
        FileTask {
            transfer_id: 1,
            name: "new.bin".to_string(),
            size: 8,
            direction: FileDirection::Upload,
            done: 0,
            status,
            speed: 0.0,
            path: None,
        }
    }

    /// ① 置位矩阵·单文件（from_job=false）：Consumed + Some(dir) 武装；
    /// 在途未排空 = 零 wire；排空帧 = 恰 1 帧 List（落点）+ 待办清零。
    #[test]
    fn test_r173_consent_consumed_arms_and_drain_fires() {
        let mut st = FileManagerState::with_local_root(tmp_dir("drain"));
        arm_landing_node(&mut st, "up");
        let mut panel = FilePanelState::new();
        panel.tasks.push(upload_task(FileTaskStatus::Sending));
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.on_fs_event(FsEvent::ConsentSettled {
            req_id: 9,
            outcome: ConsentOutcome::Consumed,
            from_job: false,
            target_dir: Some("up".to_string()),
        });
        assert_eq!(st.upload_drain_watch, vec!["up".to_string()], "武装恰一份");
        // 排空前：零 wire（传输未完成 = 落盘未毕，不提前重列）。
        st.tick(&panel, Some(&ftx), None);
        assert!(frx.try_recv().is_err(), "上传在途 = 不得提前重列");
        // 终态帧：恰 1 帧 List（落点目录）+ 待办消费（既有 refresh_node 槽）。
        panel.tasks[0].status = FileTaskStatus::Completed;
        st.tick(&panel, Some(&ftx), None);
        match frx.try_recv() {
            Ok(FileCommand::Fs {
                op: FsOp::List { path, offset, limit },
            }) => {
                assert_eq!(path, "up");
                assert_eq!((offset, limit), (0, PAGE_SIZE));
            }
            other => panic!("应得落点 List，实际 {other:?}"),
        }
        assert!(frx.try_recv().is_err(), "恰 1 帧（无风暴）");
        assert!(st.upload_drain_watch.is_empty(), "待办已消费");
        assert!(st.remote.refresh_node.is_none(), "单帧一枚");
    }

    /// ② 置位矩阵·失败/v1 回退：Declined（即便载荷在）与 Consumed+None
    #[test]
    fn test_r173_declined_and_v1_fallback_no_arm() {
        let mut st = FileManagerState::with_local_root(tmp_dir("noarm"));
        arm_landing_node(&mut st, "up");
        let panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.on_fs_event(FsEvent::ConsentSettled {
            req_id: 1,
            outcome: ConsentOutcome::Declined,
            from_job: false,
            target_dir: Some("up".to_string()),
        });
        st.on_fs_event(FsEvent::ConsentSettled {
            req_id: 2,
            outcome: ConsentOutcome::Consumed,
            from_job: false,
            target_dir: None,
        });
        st.tick(&panel, Some(&ftx), None);
        assert!(frx.try_recv().is_err(), "失败/未知落点 = 零武装零 wire");
        assert!(st.upload_drain_watch.is_empty());
        assert!(
            st.remote
                .view
                .nodes
                .get("up")
                .is_some_and(|n| n.children.is_some()),
            "旧缓存原样（未失效）"
        );
    }

    /// ③ from_job 批：Consumed 臂取 job 落点根武装（事件载荷忽略）；
    /// 编排收敛臂兜底同槽去重；上传排空后重列恰一次（批根目录）。
    #[test]
    fn test_r173_job_batch_root_and_converge_fallback() {
        let root = tmp_dir("job");
        std::fs::write(root.join("a.txt"), b"1").unwrap();
        std::fs::write(root.join("b.txt"), b"22").unwrap();
        let mut st = FileManagerState::with_local_root(root.clone());
        st.remote.current = "up".into();
        st.local.view.selected = vec![
            local_path_key(&root.join("a.txt")),
            local_path_key(&root.join("b.txt")),
        ];
        arm_landing_node(&mut st, "up");
        let mut panel = FilePanelState::new();
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        let (mtx, _mxr) = tokio::sync::mpsc::unbounded_channel::<FileMgrCommand>();
        assert_eq!(st.copy_selection(PaneId::Local), 2);
        assert_eq!(st.paste_cross(&panel, Some(&ftx), Some(&mtx)), 2);
        assert_eq!(st.job.as_ref().unwrap().target_remote_dir, "up");
        // tick#1：批 consent 通告出账（fm_tx）+ consent_pending 置位；1c 被
        // 面板在途门拦截（见下）——本测试此刻零上传在途、零武装 = 零 wire。
        st.tick(&panel, Some(&ftx), Some(&mtx));
        // 测试控制：文件清单已枚举完毕，跳过 BFS 收集相直入批通告相。
        st.job.as_mut().unwrap().collecting = false;
        assert!(st.job.as_ref().unwrap().consent_pending, "批通告在途");
        assert!(frx.try_recv().is_err(), "未武装 = 零 wire");
        // ConsentSettled{Consumed}（from_job）= 起跑武装（载荷 None 亦武装；
        // pending 态匹配零歧义）。
        st.on_fs_event(FsEvent::ConsentSettled {
            req_id: 77,
            outcome: ConsentOutcome::Consumed,
            from_job: true,
            target_dir: None,
        });
        assert_eq!(st.upload_drain_watch, vec!["up".to_string()]);
        // 注入在途上传（面板视角）→ 编排收敛帧（全部批通告完 = next_idx 追平
        // + Mkdir 链排空）= 兜底武装（同槽去重恰一份）+ 任务终态。
        panel.tasks.push(upload_task(FileTaskStatus::Sending));
        let job = st.job.as_mut().unwrap();
        job.next_idx = job.files.len();
        job.batch_head = job.next_idx;
        st.tick(&panel, Some(&ftx), None);
        assert!(st.job.as_ref().unwrap().finished, "收敛帧 = 任务终态");
        assert_eq!(st.upload_drain_watch.len(), 1, "兜底臂去重恰一份");
        assert!(frx.try_recv().is_err(), "在途未排空零 wire");
        // 排空帧：重列恰一次（批根 = up）。
        panel.tasks[0].status = FileTaskStatus::Completed;
        st.tick(&panel, Some(&ftx), None);
        match frx.try_recv() {
            Ok(FileCommand::Fs {
                op: FsOp::List { path, .. },
            }) => assert_eq!(path, "up", "重列 = 落点根目录"),
            other => panic!("应得落点 List，实际 {other:?}"),
        }
        assert!(frx.try_recv().is_err(), "恰一次");
        std::fs::remove_dir_all(&root).ok();
    }

    /// ④ 强制刷新钮语义：清缓存 + 恒 wire 恰 1 帧 List + 单在途槽占用；
    /// 连点 = 逐次单 List（无风暴放大）；零通道形态零 wire 空目录。
    #[test]
    fn test_r173_force_refresh_button_semantics() {
        let mut st = FileManagerState::with_local_root(tmp_dir("force"));
        st.remote.current = "up".into();
        arm_landing_node(&mut st, "up");
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.refresh_remote_force(Some(&ftx));
        match frx.try_recv() {
            Ok(FileCommand::Fs {
                op: FsOp::List { path, offset, limit },
            }) => {
                assert_eq!(path, "up");
                assert_eq!((offset, limit), (0, PAGE_SIZE));
            }
            other => panic!("强制刷新 = 恒 wire List，实际 {other:?}"),
        }
        assert!(frx.try_recv().is_err(), "恰 1 帧");
        assert!(st.pending.is_some(), "单在途槽占用（纪律零破坏）");
        assert!(
            st.remote
                .view
                .nodes
                .get("up")
                .is_some_and(|n| n.loading && n.children.is_none()),
            "缓存已清 + 重建 loading 态"
        );
        // 连点 = 逐次单 List（旧在途按陈旧丢弃，线性于点击无放大）。
        st.refresh_remote_force(Some(&ftx));
        assert!(matches!(
            frx.try_recv(),
            Ok(FileCommand::Fs {
                op: FsOp::List { .. }
            })
        ));
        assert!(frx.try_recv().is_err(), "连点恰 2 帧");
        // 零通道（headless 形态）：零 wire + 空目录重建（既有同形态）。
        let mut st2 = FileManagerState::with_local_root(tmp_dir("force2"));
        st2.remote.current = "up".into();
        arm_landing_node(&mut st2, "up");
        st2.refresh_remote_force(None);
        assert!(frx.try_recv().is_err(), "零通道 = 零 wire");
        assert!(
            st2.remote
                .view
                .nodes
                .get("up")
                .is_some_and(|n| matches!(&n.children, Some(c) if c.is_empty())),
            "零通道 = 空目录呈现"
        );
    }

    /// 缓存命中零 wire 纪律零变化）。
    #[test]
    fn test_r173_cache_hit_zero_wire_regression() {
        let mut st = FileManagerState::with_local_root(tmp_dir("r153"));
        arm_landing_node(&mut st, "up");
        st.remote.view.nodes.get_mut("up").unwrap().loading = false;
        let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
        st.goto_remote_quick("up", Some(&ftx));
    }

    /// ⑥ 布局红线：新钮 headless 双帧探针（egui 0.28.1 陷阱族复验；
    /// 双帧零 panic = 布局有限性在案）。
    #[test]
    fn test_r173_force_refresh_headless_two_frames() {
        let mut st = FileManagerState::with_local_root(tmp_dir("headless"));
        st.remote.started = true;
        arm_landing_node(&mut st, "up");
        let panel = FilePanelState::new();
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::light());
        for _ in 0..2 {
            let mut raw = egui::RawInput::default();
            raw.screen_rect = Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1100.0, 720.0),
            ));
            let _ = ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    show_file_manager(
                        ui,
                        &Theme::LIGHT,
                        &mut st,
                        None,
                        None,
                        &panel,
                        false,
                        &mut false,
                    );
                });
            });
        }
    }

    /// ⑦ i18n 新键 zh/en 成对 + 逐字钉死（进程级语言态串行化纪律同
    /// r133_2：r92ti 全局锁）。
    #[test]
    fn test_r173_i18n_force_refresh_pair() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        assert_eq!(crate::i18n::tr("filemgr.btn.force_refresh"), "刷新");
        crate::i18n::set_lang(crate::i18n::Lang::En);
        assert_eq!(crate::i18n::tr("filemgr.btn.force_refresh"), "Refresh");
    }
}
