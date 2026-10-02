//!
//! 用户定性「复制动作自动触发数据传输 = **未经授权的获取文件**，不允许」。
//! 授权语义颠倒：**复制动作不得触发任何数据传输；只有粘贴（或文件窗显式
//! 操作）才触发**。本模块的 s→c 自动预取与 c→s 桌面轮询自动直传触发臂
//! **全部恒闭**（[`AUTO_TRANSFER_REVOKED`] 锚：`should_request_prefetch`
//! 恒拒 / `direct_paste_enabled` 恒 false / `prefetch_dispatch` 恒 no-op）；
//! 对端复制 → 仍走既有两段式（元数据通告 + 对端文件窗 Ctrl+V 拉取，
//! OLE 延迟渲染另立项复用）但不再被自动路径调用；`.kirin_desk_clip` 直贴
//! 上传臂随之撤销（受控端不再出现新增缓存目录，存量 = 启动一次性清扫
//! [`startup_cache_sweep`]）。
//!
//! 用户验收判据 = 受控端复制文件后，主控端系统 Explorer/桌面 Ctrl+V 可直接
//! 粘贴。现两段式（应用内粘贴拉取）结构性不写主控 OS 板；本模块 = 阶段一
//! 裁定形态（PM 2026-09-27 唯一口径）：
//!
//! - **s→c（受控复制 → 主控直贴）**：受控端复制 → 既有 `FileClipMeta` 元
//!   + 本机 `clip_direct_paste` 开）**后台自动预取**——复用既有
//!   `FetchFile` 引擎面与授权链（Fetch 授权/sanitize/配额/断点全既有）——
//!   至本地缓存目录 `%LOCALAPPDATA%\kirin_desk\clip_cache\<job>\`；预期集
//!   全部落定 → [`crate::clipboard::write_cf_hdrop`] 把缓存内**真实路径**
//!   写进本机 OS 剪贴板（CF_HDROP）→ Explorer/桌面 Ctrl+V 即得，零阻塞。
//! - **c→s（主控复制 → 受控直贴）**：主控端本机复制文件（桌面会话剪贴板
//!   轮询 tick 检测新文件板签名）→ 按既有上传链（`SendFileV2` 既有帧）
//!   自动送至受控端缓存目录（根相对 `.kirin_desk_clip\<job>\`——wire 面
//!   S1 禁绝对路径，落点 = 对端首浏览根之下缓存目录）；受控端落盘写板 =
//! - **两方向共用缓存管理**：LRU 上限（512 MB / 50 目录，超限清最旧；
//!   至少保留最新一个）+ 预取 TTL 懒清扫（半成品目录删除 + 连接页 Warn
//!   一行不刷屏）。
//! - **失败降级**：预取失败（超时/对端离线中途/缓存目录建失败）= 静默
//!   回退现状两段式（应用内文件窗粘贴仍可用），连接页 Warn 一行。
//! - **安全面不绕过**：预取/直传全部走既有授权链——s→c 预取唯一入口 =
//!   FM `on_clip_meta` 门内置槽（对端开关 OFF/未通告 = fail-closed 零槽
//!   直传接受面 = 受控端既有 consent/写根/配额门（零新旁路）。写 OS 板
//!   覆盖本机现有剪贴板内容 = 业界常态（README/CHANGELOG 告知）。
//!
//! - **目录条目整树预取（阶段二核心）**：受控端复制目录 → 元数据通告
//!   **含目录树**（`filemeta_from_board` 受控端本地枚举追加树行，零 wire
//!   schema 变更 = `FileClipEntry` 行复用；上限触顶 = `truncated=true`）→
//!   主控端把整树预取到缓存（`local_dir` = 任务目录 + rel 父链，**子目录
//!   结构保持**；纯空目录 = 落盘目录行）→ 写板路径 = **缓存目录路径**
//!   （CF_HDROP 原生支持目录，Explorer 粘贴目录 = 递归复制）→ 粘贴即得
//!   整树。树不完整（`truncated`）= 整批回退两段式（禁半树写板）。
//! - **basename 同名多文件（阶段二修复）**：预期/落定键 = 缓存内**相对
//!   路径**（非 basename）——同名不同子目录各自落位（结构保持），阶段一
//!   「同名集去重 = TTL 回退」触发面**消除**（仅剩引擎层 unique_target_path
//!   改名等异常残臂，TTL 为兜底）。
//! - **c→s 方向目录臂（阶段二仍边界）**：主控复制目录 → c→s 直传仍跳过
//!   （一行 Info；应用内 FolderJob 整树上传照旧）——真延迟渲染（OLE
//!   CFSTR_FILEDESCRIPTORW/FILECONTENTS）与 c→s 目录直传另卡。
//!   后，c→s 检测以签名比对跳过自写板（[`note_self_board_write`] /
//!   [`is_self_board_write`]），防止「预取落定板 → 误判用户新复制 → 回传
//!   对端」死循环；签名按写板点/检测点同源 stat（目录项同样覆盖）。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ───────────────────────── 常量（PM 裁定：容量与数量上界） ─────────────────────────

/// 动作自动触发数据传输 = 未经授权的获取文件，不允许」。授权语义颠倒——
/// **复制动作不得触发任何数据传输；只有粘贴（或文件窗显式操作）才触发**。
/// （门改恒拒）；写板/缓存/LRU/防回环基建**保留**（未来延迟渲染另立项
/// 复用）但不再被自动路径调用。回退形态 = 既有两段式（元数据通告 + 对端
pub(crate) const AUTO_TRANSFER_REVOKED: bool = true;

/// 主控端预取缓存根目录名（`%LOCALAPPDATA%\kirin_desk\clip_cache\`）。
pub(crate) const MASTER_CACHE_DIRNAME: &str = "clip_cache";

/// 受控端直贴缓存根目录名（对端首浏览根之下根相对 `.kirin_desk_clip\`；
/// wire 面 S1 禁绝对路径 = 缓存目录必须落在浏览根语义内）。
pub(crate) const C2S_CACHE_ROOTNAME: &str = ".kirin_desk_clip";

/// 预取任务 TTL（懒清扫判据；同 [`crate::CLIP_BOARD_EPOCH_TTL`] 10min 口径）。
const PREFETCH_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// LRU 总量上界（字节；PM 裁定 512 MB）。
pub(crate) const SWEEP_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

/// LRU 目录数上界（PM 裁定 50 目录）。
pub(crate) const SWEEP_MAX_DIRS: usize = 50;

/// 目录体积统计递归文件数上限（防异常巨树拖垮 UI 帧；超限 = 按上限计体积
/// 优先清扫，fail-closed 不猜全量）。
const SWEEP_WALK_FILE_CAP: usize = 20_000;

// ───────────────────────── 决策纯核（可单测） ─────────────────────────

///（`None` = 未通告 / `Some(false)` = 通告 OFF → **fail-closed 零槽
/// 写**）；`cleared` = CLEAR 帧（清 pending 语境，非新复制 → 不预取）。
/// 该函数 = FM `on_clip_meta` 置预取请求槽的**唯一**判定源；槽外无任何
/// 预取入口（结构性防绕过）。
///
/// 裁定），授权语义颠倒后本门对全部输入恒 `false`（槽永不置位 = 下游
/// drain 派发臂结构性饿死）；签名保留 = 基建/单测锚面，未来延迟渲染
/// 另立项复用。
pub(crate) fn should_request_prefetch(
    peer_clip_allowed: Option<bool>,
    cleared: bool,
) -> bool {
    if AUTO_TRANSFER_REVOKED {
        return false;
    }
    let _ = (peer_clip_allowed, cleared);
    false
}

/// 企划纯函数产出）+ 元数据 `truncated`（树完整性旗标）。阶段二 = 目录
/// 条目纳入预取（不再整批回退）；`FallbackDirs` 语义收缩为**树不完整臂**
/// （`truncated=true` 且含目录条目 = 半树禁写板，整批回退两段式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectDecision {
    /// 预取（散文件和/或目录树，结构落位；纯散文件截断批 = 阶段一局部
    /// 预取口径零变化）。
    Start,
    /// 树不完整（元数据 `truncated` 且含目录条目）= 整批回退两段式（连接
    /// 页 Info 一行；不完整树绝不佯装完整写板）。
    FallbackDirs,
    /// 无可预取条目（全根外）= 静默零动作。
    FallbackNoFetchable,
}

pub(crate) fn prefetch_decision(plan: &crate::ClipFetchPlan, tree_truncated: bool) -> DirectDecision {
    if plan.fetchable_paths.is_empty() && plan.dir_paths.is_empty() {
        DirectDecision::FallbackNoFetchable
    } else if tree_truncated && !plan.dir_paths.is_empty() {
        // 粘贴与元数据无关，整树照旧可用——fail-closed 不降级为半树）。
        DirectDecision::FallbackDirs
    } else {
        DirectDecision::Start
    }
}

/// 自守防调用面绕过）。`truncated` 且含目录条目 = 半树禁预取禁写板。
fn tree_incomplete(meta: &crate::clipboard::FileClipMeta) -> bool {
    meta.truncated && meta.entries.iter().any(|e| e.fetchable && e.is_dir)
}

/// 配置读取失败 = 落默认开——开关语义 = 用户显式关闭才停用）。
///
/// 2026-09-28 裁定）；c→s 桌面轮询检测臂与本派发入口同门封死（零读板
/// 零直传，完全回退两段式）。
pub(crate) fn direct_paste_enabled() -> bool {
    if AUTO_TRANSFER_REVOKED {
        return false;
    }
    kirin_desk_utils::config::Config::load()
        .ok()
        .map(|c| c.file_transfer.clip_direct_paste)
        .unwrap_or(true)
}

// ───────────────────────── 主控端预取任务注册表（状态机） ─────────────────────────

/// 一个预取任务 = 一次元数据通告的后台预取周期（状态机：
/// `Registered → 逐文件落定累积 → Complete（整集写板并移除）/
/// Expired（TTL 懒清扫：删半成品 + Warn 一行）/ Cancelled（CLEAR/新任务
/// 取代：删半成品）`）。
pub(crate) struct PrefetchJob {
    /// 会话标签（addr/session_id——同会话新元数据 = 取代旧任务）。
    pub tag: String,
    /// 缓存目录（注册表**键**：落盘路径前缀归属〔`starts_with`，阶段二 =
    /// 子目录结构落位后的嵌套路径命中〕，会话零 plumbing）。
    pub dir: PathBuf,
    /// 预期落盘条目 = 缓存内**相对路径**集（`/` 分隔；阶段二键改型——
    /// basename → rel：同名不同子目录各自落位，TTL 回退触发面消除）。
    pub expected: HashSet<String>,
    /// 已落定（rel 相对路径, 绝对路径）——落定序。
    pub landed: Vec<(String, PathBuf)>,
    /// 文件路径；目录条目 = 缓存内**目录路径**〔CF_HDROP 目录项，Explorer
    /// 粘贴 = 递归复制〕）。完成臂返回本清单（空 = 回退 landed 路径）。
    pub board: Vec<PathBuf>,
    /// 登记时刻（TTL 锚点）。
    pub started: std::time::Instant,
}

fn registry() -> &'static std::sync::Mutex<Vec<PrefetchJob>> {
    static REG: OnceLock<std::sync::Mutex<Vec<PrefetchJob>>> = OnceLock::new();
    REG.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// 主控端预取缓存根（`%LOCALAPPDATA%\kirin_desk\clip_cache`；不可得 =
/// `None` → 预取回退两段式）。
pub(crate) fn master_cache_root() -> Option<PathBuf> {
    dirs_next::data_local_dir().map(|d| d.join("kirin_desk").join(MASTER_CACHE_DIRNAME))
}


/// `symlink_metadata`（不穿透链接）断言**非符号链接/junction 且为目录**；
/// 不存在 = 常规 `create_dir_all` 后**复检**（防创建间隙置换/竞态兜底）。
/// 返回 `false` = 该路径**拒绝使用**（调用方整体回退，**禁删除用户预置
/// 对象**——不越权清理，仅绕开）。
pub(crate) fn ensure_real_dir(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(md) => is_plain_real_dir(&md),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).is_ok()
                && std::fs::symlink_metadata(path).is_ok_and(|md| is_plain_real_dir(&md))
        }
        Err(_) => false,
    }
}

/// Windows 上符号链接与目录联接（junction）均为 reparse point，按属性位
/// `FILE_ATTRIBUTE_REPARSE_POINT` 判定（不依赖 std 版本对 junction 的
/// `is_symlink` 口径差异，敌性重定向一律拒绝）；非 Windows 按
/// `file_type().is_symlink()`。
fn is_plain_real_dir(md: &std::fs::Metadata) -> bool {
    if !md.is_dir() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
    }
    #[cfg(not(windows))]
    {
        !md.file_type().is_symlink()
    }
}

/// 任务目录名：会话标签消毒（仅留字母数字，其余剥除——addr 形态
/// `ip:port` / 设备 ID 等，防路径注入）+ 纳秒时戳（同会话新任务不撞名）。
pub(crate) fn job_dir_name(tag: &str, unix_ns: u128) -> String {
    let safe: String = tag
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(24)
        .collect();
    let safe = if safe.is_empty() { "sess".to_string() } else { safe };
    format!("{safe}-{unix_ns}")
}

/// TTL 懒清扫（注册表持锁内调用）：过期任务 = 删半成品目录 + 连接页
/// Warn 一行（每任务恰一行，不刷屏）；过期已完成任务 = 静默移除（正常
/// 完成路径已在写板点移除，此处 = 防御性兜底）。
fn sweep_stale_locked(now: std::time::Instant) {
    let mut reg = registry().lock().unwrap();
    let expired: Vec<usize> = reg
        .iter()
        .enumerate()
        .filter(|(_, j)| now.duration_since(j.started) > PREFETCH_TTL)
        .map(|(i, _)| i)
        .collect();
    for i in expired.into_iter().rev() {
        let job = reg.remove(i);
        tracing::info!(
            job.dir.display(),
            job.landed.len(),
            job.expected.len()
        );
        let _ = std::fs::remove_dir_all(&job.dir);
        if !job.landed.is_empty() || !job.expected.is_empty() {
            crate::conn_log_push_text(
                crate::widgets::ConnLogLevel::Warn,
                &crate::t!("connect.log.r166_prefetch_failed").to_string(),
            );
        }
    }
}

/// 门内臂 + Shell/File 窗 drain 位点取槽后）。开关 OFF / 树不完整 / 缓存
/// 目录建失败 → 静默或一行降级（两段式 pending 槽不受影响 = 照旧可用）；
/// `Start` = 取代同会话旧任务 + LRU 清扫 + 建 `clip_cache\<job>` 目录树
/// （子目录结构保持）+ 逐文件 `FileCommand::FetchFile`（嵌套 `local_dir`
/// ——既有引擎面与授权链，Offer 名 = basename 落于结构位）。
///
/// 2026-09-28 裁定）；本入口对全部输入恒零动作（调用点保留 = 基建编译
/// 面，未来延迟渲染另立项复用；门三层钉死 = 本函数 + 总开关 +
/// `should_request_prefetch` 槽位恒拒）。
pub(crate) fn prefetch_dispatch(
    file_tx: Option<&tokio::sync::mpsc::UnboundedSender<crate::file_panel::FileCommand>>,
    meta: &crate::clipboard::FileClipMeta,
    tag: &str,
) {
    if AUTO_TRANSFER_REVOKED {
    }
    if !direct_paste_enabled() {
        return; // 开关 OFF = 完全回退两段式（零预取）。
    }
    let plan = crate::clip_fetch_plan(meta);
    match prefetch_decision(&plan, tree_incomplete(meta)) {
        DirectDecision::FallbackNoFetchable => return,
        DirectDecision::FallbackDirs => {
            tracing::info!(
                plan.dir_paths.len()
            );
            crate::conn_log_push_text(
                crate::widgets::ConnLogLevel::Info,
                &crate::t!("connect.log.r166_dirs_fallback").to_string(),
            );
            return;
        }
        DirectDecision::Start => {}
    }
    let Some(tx) = file_tx else {
        return;
    };
    let Some(root) = master_cache_root() else {
        return;
    };
    prefetch_dispatch_at(&root, tx, meta, tag);
}

/// rel 路径 → 缓存内相对路径（`/` 分段显式 join——零绝对化零盘符）。
fn rel_to_path(rel: &str) -> PathBuf {
    rel.split('/').filter(|s| !s.is_empty()).collect::<PathBuf>()
}

/// rel 路径父链（`/` 分隔；无父 = 空串 = 任务目录本身）。
fn rel_parent(rel: &str) -> &str {
    match rel.rfind('/') {
        Some(i) => &rel[..i],
        None => "",
    }
}

/// 与任务目录两处统一走 [`ensure_real_dir`] 预检：预检不过 = 拒用该路径
/// → 预取整体回退既有两段式（tracing::warn! + 连接页 Warn 一行）；
/// **容器根预检先于一切清扫/建目录** = 敌性容器（junction 重定向）零
/// 触碰（禁删除用户预置对象——LRU/TTL 清扫不落于链接之上）。
///
/// （子目录/纯空目录，零 wire）；②逐文件 `FetchFile`（`local_dir` =
/// 任务目录 + rel 父链——结构落位，同名不同子目录各自就位）；③预期集 =
/// 缓存内 rel 路径集（basename → rel 键改型，去 TTL 回退）；④写板素材 =
/// 复制序**顶层**条目（散文件 + **目录路径**〔CF_HDROP 目录项〕）。结构
/// 建失败 = 整批放弃回退两段式（零半树登记）。
fn prefetch_dispatch_at(
    root: &Path,
    tx: &tokio::sync::mpsc::UnboundedSender<crate::file_panel::FileCommand>,
    meta: &crate::clipboard::FileClipMeta,
    tag: &str,
) {
    // ——执行核自身亦守，防调用面绕过；零派发零登记零结构）。
    if tree_incomplete(meta) {
        return;
    }
    if !ensure_real_dir(root) {
        tracing::warn!(
            root.display()
        );
        crate::conn_log_push_text(
            crate::widgets::ConnLogLevel::Warn,
            &crate::t!("connect.log.r186_cache_dir_refused").to_string(),
        );
        return;
    }
    // 派发前清扫：TTL 过期任务（半成品清理 + Warn 一行）+ LRU 超限清最旧。
    sweep_stale_locked(std::time::Instant::now());
    sweep_cache_root(root);
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = root.join(job_dir_name(tag, now_ns));
    // 取代同会话旧任务（新复制 = 新预取周期）。
    cancel_tag_locked(tag);
    // 回退——取代旧任务的清扫已先行，本臂仅放弃本批预取）。
    if !ensure_real_dir(&dir) {
        tracing::warn!(
            dir.display()
        );
        crate::conn_log_push_text(
            crate::widgets::ConnLogLevel::Warn,
            &crate::t!("connect.log.r186_cache_dir_refused").to_string(),
        );
        return;
    }
    // 树行分诊（单遍；顺序 = 元数据条目序 = 用户复制序）：
    // dir_rels = 目录行全集（顶层 + 树行嵌套）作覆盖判定源。
    let dir_rels: Vec<String> = meta
        .entries
        .iter()
        .filter(|e| e.fetchable && e.is_dir)
        .map(|e| e.rel_path.clone())
        .collect();
    let mut expected: HashSet<String> = HashSet::new();
    let mut board: Vec<PathBuf> = Vec::new();
    let mut subdirs: Vec<String> = Vec::new();
    let mut fetches: Vec<String> = Vec::new();
    for e in &meta.entries {
        if !e.fetchable {
            continue; // 根外 = 占位行（既有口径零预取零计数）
        }
        let covered = crate::clip_entry_dir_covered(&e.rel_path, &dir_rels);
        if e.is_dir {
            subdirs.push(e.rel_path.clone());
            if !covered {
                // 顶层目录 = 写板目录项（缓存内目录路径，CF_HDROP 原生）。
                board.push(dir.join(rel_to_path(&e.rel_path)));
            }
        } else {
            // 树内文件 + 散文件全量预取（rel 键 = 结构落位）；写板素材仅
            // 顶层散文件（树内文件由顶层目录项递归承载）。
            expected.insert(e.rel_path.clone());
            fetches.push(e.rel_path.clone());
            if !covered {
                board.push(dir.join(rel_to_path(&e.rel_path)));
            }
        }
    }
    // 结构落位（本机 create_dir_all，零 wire——子目录 + 纯空目录保留，
    // 登记，两段式照旧）。
    for sub in &subdirs {
        if let Err(e) = std::fs::create_dir_all(dir.join(rel_to_path(sub))) {
            tracing::warn!(
                dir.join(rel_to_path(sub)).display()
            );
            return;
        }
    }
    if expected.is_empty() {
        // 纯空目录树：零 FetchFile，写板即完成（目录项上板，粘贴得空树）。
        if crate::clipboard::write_cf_hdrop(&board) {
            tracing::info!(
                board.len(),
                dir.display()
            );
            note_self_board_write(&board);
            crate::conn_log_push_text(
                crate::widgets::ConnLogLevel::Info,
                &crate::tf!("connect.log.r166_prefetch_ready", board.len()).to_string(),
            );
        }
        return;
    }
    let job = PrefetchJob {
        tag: tag.to_string(),
        expected,
        dir: dir.clone(),
        landed: Vec::new(),
        board,
        started: std::time::Instant::now(),
    };
    let n = job.expected.len();
    registry().lock().unwrap().push(job);
    for rel in &fetches {
        let local_dir = match rel_parent(rel) {
            "" => dir.clone(),
            parent => dir.join(rel_to_path(parent)),
        };
        tracing::info!(
            rel,
            local_dir.display()
        );
        let _ = tx.send(crate::file_panel::FileCommand::FetchFile {
            remote_path: rel.clone(),
            local_dir,
        });
    }
    tracing::info!(
        dir.display()
    );
    crate::conn_log_push_text(
        crate::widgets::ConnLogLevel::Info,
        &crate::tf!("connect.log.r166_prefetch_started", n).to_string(),
    );
}

/// 所有会话/角色共用——注册表以落盘路径前缀归属〔`starts_with`，阶段二 =
/// 结构落位嵌套路径命中〕，非本岗任务 = `None` 零动作）。预期集全落定 =
/// 移除任务并返回**写板素材**（阶段二 = 复制序顶层条目〔含目录项〕；空 =
/// 回退 landed 路径，调用方 `write_cf_hdrop` 写本机板 + 连接页就绪行）；
/// 未齐 = `None` 继续等。键 = 缓存内 rel 路径（`name` 形参仅为签名兼容
/// 保留——basename 键已废，同名不同子目录各自落位）。
pub(crate) fn prefetch_landed(_name: &str, path: &Path) -> Option<Vec<PathBuf>> {
    sweep_stale_locked(std::time::Instant::now());
    let mut reg = registry().lock().unwrap();
    let pos = reg.iter().position(|j| path.starts_with(&j.dir))?;
    // rel 键：任务目录前缀剥离（组件级 strip，零字符串误配）+ 反斜杠
    // 规范化（Windows 落盘形态 → wire `/` 分隔键域）。
    let rel = path
        .strip_prefix(&reg[pos].dir)
        .ok()?
        .to_string_lossy()
        .replace('\\', "/");
    let job = &mut reg[pos];
    if !job.expected.contains(&rel) || job.landed.iter().any(|(n, _)| *n == rel) {
        return None;
    }
    job.landed.push((rel, path.to_path_buf()));
    if job.landed.len() < job.expected.len() {
        return None;
    }
    let job = reg.remove(pos);
    Some(if job.board.is_empty() {
        job.landed.into_iter().map(|(_, p)| p).collect()
    } else {
        job.board
    })
}

/// 同会话任务取消（CLEAR 臂 / 新任务取代前；注册表持锁内）。
fn cancel_tag_locked(tag: &str) {
    let mut reg = registry().lock().unwrap();
    let stale: Vec<PathBuf> = reg
        .iter()
        .filter(|j| j.tag == tag)
        .map(|j| j.dir.clone())
        .collect();
    reg.retain(|j| j.tag != tag);
    for d in stale {
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// 已写板不回滚 = 剪贴板覆盖告知口径）。
pub(crate) fn cancel_tag(tag: &str) {
    cancel_tag_locked(tag);
}

// ───────────────────────── 缓存 LRU（两方向共用） ─────────────────────────

/// 缓存目录统计项（LRU 输入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CacheDirStat {
    /// 目录名（任务目录）。
    pub name: String,
    /// 递归体积（字节）。
    pub bytes: u64,
    /// mtime（epoch 秒；不可得 = 0 = 最旧优先清）。
    pub modified: i64,
}

/// LRU 受害者决议（**纯函数，可单测**）：mtime 升序（最旧优先）累计，
/// 超总量上界或目录数上界即入受害集；**至少保留最新一个**（最新目录 =
/// 常为在用预取目标，清了必复发）。
pub(crate) fn lru_victims(dirs: &mut Vec<CacheDirStat>, max_bytes: u64, max_dirs: usize) -> Vec<String> {
    dirs.sort_by_key(|d| (d.modified, d.name.clone()));
    let mut victims = Vec::new();
    let mut total: u64 = dirs.iter().map(|d| d.bytes).sum();
    let keep = dirs.len().saturating_sub(1); // 恒保留最新一个
    for i in 0..keep {
        let over_bytes = total > max_bytes;
        let over_dirs = dirs.len() - victims.len() > max_dirs;
        if !over_bytes && !over_dirs {
            break;
        }
        total = total.saturating_sub(dirs[i].bytes);
        victims.push(dirs[i].name.clone());
    }
    victims
}

/// 递归统计目录体积（文件数封顶 [`SWEEP_WALK_FILE_CAP`]）。
fn dir_size_walk(dir: &Path, budget: &mut usize) -> u64 {
    let mut total = 0u64;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    for e in rd.flatten() {
        if *budget == 0 {
            return total;
        }
        *budget -= 1;
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            total += dir_size_walk(&e.path(), budget);
        } else {
            total += e.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

/// 缓存根 LRU 清扫（fs 执行面；[`lru_victims`] 纯核决议 + `remove_dir_all`）。
pub(crate) fn sweep_cache_root(root: &Path) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    let mut stats: Vec<CacheDirStat> = Vec::new();
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let mut budget = SWEEP_WALK_FILE_CAP;
        stats.push(CacheDirStat {
            name: e.file_name().to_string_lossy().into_owned(),
            bytes: dir_size_walk(&e.path(), &mut budget),
            modified: e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        });
    }
    let victims = lru_victims(&mut stats, SWEEP_MAX_TOTAL_BYTES, SWEEP_MAX_DIRS);
    for v in victims {
        let p = root.join(&v);
        let _ = std::fs::remove_dir_all(&p);
    }
}

/// 落盘路径祖先含 [`C2S_CACHE_ROOTNAME`] = 直贴缓存目录 → 对该缓存根
/// LRU 清扫（用户目录零触碰）。
pub(crate) fn sweep_if_cache_path(p: &Path) {
    let mut anc = p.ancestors();
    anc.next(); // 自身跳过
    for a in anc {
        if a.file_name().and_then(|n| n.to_str()) == Some(C2S_CACHE_ROOTNAME) {
            sweep_cache_root(a);
            return;
        }
    }
}

/// 受控端直贴上传目标目录（**根相对** wire 形态；`SendFileV2.target_dir`
/// 消费 = 对端 `on_offer_v2` 既有 sanitize + 写根门 + 配额门）。
pub(crate) fn c2s_target_dir(unix_ns: u128) -> String {
    format!("{}/{}", C2S_CACHE_ROOTNAME, job_dir_name("c2s", unix_ns))
}


/// 缓存任务目录名判定（**纯函数，可单测**）：`<消毒标签>-<纯数字时戳>`
/// 形态（[`job_dir_name`] 产出域——标签仅字母数字 ≤24 + `-` + 纳秒十进
/// 制数字）。启动清扫**只删命中形态的条目**（非任务形态 = 用户数据嫌疑
/// = 零触碰；保守不猜）。
pub(crate) fn is_cache_task_dir_name(name: &str) -> bool {
    let Some(dash) = name.rfind('-') else {
        return false;
    };
    let (tag, ts) = (&name[..dash], &name[dash + 1..]);
    !tag.is_empty()
        && tag.len() <= 24
        && tag.chars().all(|c| c.is_ascii_alphanumeric())
        && !ts.is_empty()
        && ts.bytes().all(|b| b.is_ascii_digit())
}

/// 单缓存根一次性过期清扫（**启动臂执行面**；判据 = TTL 过期〔mtime 为
/// 准〕，生产 = [`PREFETCH_TTL`] 同懒清扫口径）：只删
/// [`is_cache_task_dir_name`] 命中且 mtime 早于 TTL 的目录（半成品/已消费
/// 任务缓存）；其余条目零触碰。返回删除目录数（观测面）。TTL 注入形 =
/// 单测可钉（巨 TTL = 零删 / 零 TTL = 全删矩阵）。
pub(crate) fn sweep_expired_task_dirs(root: &Path, ttl: std::time::Duration) -> usize {
    let Ok(rd) = std::fs::read_dir(root) else {
        return 0;
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0usize;
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if !is_cache_task_dir_name(&name) {
            continue;
        }
        let stale = e
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| now.duration_since(t).ok())
            .map(|d| d > ttl)
            .unwrap_or(false);
        if stale {
            let p = root.join(&name);
            if std::fs::remove_dir_all(&p).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// 受控端 `.kirin_desk_clip` 缓存根定位（**纯函数**）：浏览根列表逐根
/// 本函数同域逆向定位）。
pub(crate) fn c2s_cache_roots(browse_roots: &[PathBuf]) -> Vec<PathBuf> {
    browse_roots
        .iter()
        .map(|r| r.join(C2S_CACHE_ROOTNAME))
        .collect()
}

/// 同钩子）：①主控端 `clip_cache` 根 = 过期任务目录清扫 + LRU 上界清扫
/// （沿用 [`sweep_cache_root`]）；②受控端浏览根下 `.kirin_desk_clip` 根
/// = 过期任务目录清扫（`c2s-*` 形态钉死，其余零触碰）。自动传输已恒闭
pub(crate) fn startup_cache_sweep() {
    // ① 主控端预取缓存根。
    if let Some(root) = master_cache_root() {
        let n = sweep_expired_task_dirs(&root, PREFETCH_TTL);
        sweep_cache_root(&root);
        if n > 0 {
        }
    }
    // ② 受控端浏览根下直贴缓存根（浏览根解析 = 服务端元数据 rel 解析同
    // 口径；空配置 = [home] 兜底同源）。
    let cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
    let roots = crate::resolve_fs_browse_roots(&cfg.file_transfer.fs_roots).roots;
    for root in c2s_cache_roots(&roots) {
        let n = sweep_expired_task_dirs(&root, PREFETCH_TTL);
        if n > 0 {
            tracing::info!(
                root.display()
            );
        }
    }
}

// ───────────────────────── 自写板防回环（c→s 检测门） ─────────────────────────

/// 登记；c→s 检测比对命中 = 非用户新复制 = 跳过直传，防回环）。
fn self_write_sig() -> &'static std::sync::Mutex<u64> {
    static SIG: OnceLock<std::sync::Mutex<u64>> = OnceLock::new();
    SIG.get_or_init(|| std::sync::Mutex::new(0))
}

/// 板签名（**纯函数**：`path\0size` 顺序敏感 FNV-1a——写板点与检测点
/// 同源同序 = 精确比对；跨实现零兼容诉求）。
pub(crate) fn board_signature(entries: &[(String, u64)]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for (p, s) in entries {
        for b in p.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= 0;
        h = h.wrapping_mul(0x100000001b3);
        for b in s.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

/// 直贴链写板点登记（写板成功后调用）。
pub(crate) fn note_self_board_write(paths: &[PathBuf]) {
    let entries: Vec<(String, u64)> = paths
        .iter()
        .map(|p| {
            (
                p.to_string_lossy().into_owned(),
                std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
            )
        })
        .collect();
    *self_write_sig().lock().unwrap() = board_signature(&entries);
}

/// c→s 检测点比对：当前板签名命中最近自写板 = `true`（跳过直传）。
pub(crate) fn is_self_board_write(entries: &[(String, u64)]) -> bool {
    *self_write_sig().lock().unwrap() != 0
        && *self_write_sig().lock().unwrap() == board_signature(entries)
}

// ───────────────────────── 单测（阶段一矩阵） ─────────────────────────

#[cfg(test)]
mod r166_tests {
    use super::*;

    /// (rel_path, is_dir) 行 → 元数据（fetchable=true；树行形态 = rel 带
    /// `/`，与受控端 `filemeta_from_board` 产出同域）。
    fn meta_of(entries: &[(&str, bool)]) -> crate::clipboard::FileClipMeta {
        crate::clipboard::FileClipMeta {
            version: crate::clipboard::FILEMETA_VERSION,
            cleared: false,
            truncated: false,
            entries: entries
                .iter()
                .map(|(rel, is_dir)| crate::clipboard::FileClipEntry {
                    rel_path: (*rel).to_string(),
                    size: 1,
                    is_dir: *is_dir,
                    fetchable: true,
                })
                .collect(),
        }
    }

    fn plan_of(entries: &[(bool, bool)]) -> crate::ClipFetchPlan {
        // (fetchable, is_dir) → 企划（复用既有 clip_fetch_plan 纯函数语义
        // 的直构形态：root 相对路径零 side effect）。
        let mut fetchable_paths = Vec::new();
        let mut dir_paths = Vec::new();
        for (i, (fetchable, is_dir)) in entries.iter().enumerate() {
            let rel = format!("item{i}.bin");
            if *is_dir {
                if *fetchable {
                    dir_paths.push(rel);
                }
            } else if *fetchable {
                fetchable_paths.push(rel);
            }
        }
        crate::ClipFetchPlan {
            consumed: !fetchable_paths.is_empty() || !dir_paths.is_empty(),
            fetchable_paths,
            dir_paths,
            outside_root: 0,
        }
    }

    /// ① 决策矩阵（阶段二）：纯文件 = Start；**目录批/混编 = Start（目录
    /// 整批直贴核心——不再回退）**；全根外 = 静默；含目录 + truncated =
    /// 树不完整臂整批回退（半树禁写板）；纯文件 + truncated = 阶段一局部
    /// 预取口径零变化。
    #[test]
    fn r166_prefetch_decision_matrix() {
        // 目录批（顶层目录行，企划 = dir_paths 非空 / fetchable 空）。
        let plan_dirs = plan_of(&[(true, true)]);
        assert_eq!(
            prefetch_decision(&plan_dirs, false),
            DirectDecision::Start,
            "阶段二：目录批 = 整批预取（不再回退）"
        );
        // 混编（文件 + 目录）。
        let plan_mixed = plan_of(&[(true, false), (true, true)]);
        assert_eq!(prefetch_decision(&plan_mixed, false), DirectDecision::Start);
        // 纯文件（阶段一口径零漂移）。
        let plan_files = plan_of(&[(true, false), (true, false)]);
        assert_eq!(prefetch_decision(&plan_files, false), DirectDecision::Start);
        // 树不完整臂：truncated + 含目录 = 回退；truncated + 纯文件 = 阶段一局部预取。
        assert_eq!(
            prefetch_decision(&plan_dirs, true),
            DirectDecision::FallbackDirs,
            "truncated + 目录 = 树不完整整批回退"
        );
        assert_eq!(
            prefetch_decision(&plan_files, true),
            DirectDecision::Start,
            "truncated + 纯文件 = 阶段一局部预取口径保留"
        );
        // 全根外 = 静默零动作。
        assert_eq!(
            prefetch_decision(&plan_of(&[]), false),
            DirectDecision::FallbackNoFetchable
        );
    }

    /// 颠倒）**：复制动作不得触发任何数据传输 → 本门对全部输入**恒拒**
    ///（未通告/OFF/CLEAR 既有 fail-closed 面之上，唯「通告 ON + 非 CLEAR」
    /// 放行臂亦撤销）——槽永不置位 = 下游 drain 派发臂结构性饿死。
    #[test]
    fn r166_gate_not_bypassed() {
        assert!(!should_request_prefetch(None, false), "未通告 = fail-closed 拒");
        assert!(!should_request_prefetch(Some(false), false), "通告 OFF = 拒");
        assert!(!should_request_prefetch(Some(true), true), "CLEAR = 非新复制拒");
        assert!(
            !should_request_prefetch(Some(true), false),
        );
    }

    /// 三层全恒闭——复制动作零传输；两段式基建零触碰。
    #[test]
    fn r192_auto_arms_closed_matrix() {
        // 决策门全输入恒拒（× {None,Some(false),Some(true)} × {false,true}）。
        for peer in [None, Some(false), Some(true)] {
            for cleared in [false, true] {
                assert!(
                    !should_request_prefetch(peer, cleared),
                );
            }
        }
        // 总开关恒 false（c→s 桌面轮询检测臂同门封死 = 零读板零直传）。
        // 派发入口恒 no-op：注册表零登记（携带 ON 语境元数据照旧零动作）。
        registry().lock().unwrap().clear();
        let tx = tokio::sync::mpsc::unbounded_channel().0;
        prefetch_dispatch(Some(&tx), &meta_of(&[("a.txt", false)]), "r192");
        assert!(
            registry().lock().unwrap().is_empty(),
        );
    }

    #[test]
    fn r192_cache_task_dir_name_matrix() {
        assert!(is_cache_task_dir_name("sess-123"), "标签-数字时戳 = 任务形态");
        assert!(is_cache_task_dir_name("c2s-999"), "c2s 任务形态");
        assert!(is_cache_task_dir_name("ABC123-0"), "字母数字标签上界内");
        assert!(!is_cache_task_dir_name("my-backup"), "非数字时戳 = 用户数据嫌疑零触碰");
        assert!(!is_cache_task_dir_name("docs"), "无 `-` = 零触碰");
        assert!(!is_cache_task_dir_name("-123"), "空标签 = 零触碰");
        assert!(!is_cache_task_dir_name("sess-"), "空时戳 = 零触碰");
        assert!(!is_cache_task_dir_name("sess-12a"), "时戳混非数字 = 零触碰");
        assert!(
            !is_cache_task_dir_name("abcdefghijklmnopqrstuvwxyz-123"),
            "标签 >24 = 零触碰"
        );
    }

    /// 非任务形态条目零触碰；主控/受控缓存根定位纯函数。
    #[test]
    fn r192_startup_sweep_matrix() {
        let base = std::env::temp_dir().join(format!(
            "kirin_r192_sweep_{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let root = base.join("clip_cache");
        std::fs::create_dir_all(root.join("sess-1")).unwrap();
        std::fs::create_dir_all(root.join("sess-2")).unwrap();
        std::fs::create_dir_all(root.join("keep-me")).unwrap();
        std::fs::write(root.join("sess-1").join("f.txt"), b"x").unwrap();
        // fs 时间戳精度兜底（确保 mtime 已推进过零 TTL）。
        std::thread::sleep(std::time::Duration::from_millis(30));
        // TTL = 0：任务形态全过期 → 删；非任务形态零触碰。
        let removed = sweep_expired_task_dirs(&root, std::time::Duration::from_secs(0));
        assert_eq!(removed, 2, "两个任务目录全删");
        assert!(!root.join("sess-1").exists() && !root.join("sess-2").exists());
        assert!(root.join("keep-me").exists(), "非任务形态零触碰");
        // TTL 巨值：新任务目录保留（零删）。
        let removed2 = sweep_expired_task_dirs(&root, PREFETCH_TTL);
        assert_eq!(removed2, 0, "巨 TTL = 零删");
        // 缓存根定位纯函数（受控端浏览根 → .kirin_desk_clip 根）。
        let roots = c2s_cache_roots(&[PathBuf::from(r"C:\u"), PathBuf::from(r"D:\dl")]);
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0], PathBuf::from(r"C:\u").join(C2S_CACHE_ROOTNAME));
        assert_eq!(roots[1], PathBuf::from(r"D:\dl").join(C2S_CACHE_ROOTNAME));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// ③ LRU 纯核：超总量/超数量清最旧 + 恒保留最新一个。
    #[test]
    fn r166_lru_victims_matrix() {
        let mk = |name: &str, bytes: u64, modified: i64| CacheDirStat {
            name: name.to_string(),
            bytes,
            modified,
        };
        // 超数量：5 目录 / 上限 2 → 清最旧 3 个（留最新 2）。
        let mut dirs = vec![
            mk("a", 10, 5),
            mk("b", 10, 4),
            mk("c", 10, 3),
            mk("d", 10, 2),
            mk("e", 10, 1),
        ];
        let v = lru_victims(&mut dirs, u64::MAX, 2);
        assert_eq!(v, vec!["e", "d", "c"], "mtime 升序清最旧，保最新 2");
        // 超总量：3 目录 100B / 上限 50B → 清最旧 2（保最新，即使仍超也不清 newest）。
        let mut dirs = vec![mk("x", 40, 3), mk("y", 30, 2), mk("z", 30, 1)];
        let v = lru_victims(&mut dirs, 50, usize::MAX);
        assert_eq!(v, vec!["z", "y"], "超量清最旧；最新 x 恒保留");
        // 单目录 = 永不清（keep = 0）。
        let mut dirs = vec![mk("only", u64::MAX, 1)];
        assert!(lru_victims(&mut dirs, 1, 1).is_empty(), "单目录恒保留");
    }

    /// ④ 状态机矩阵（阶段二键域 = 缓存内 rel 路径）：登记 → 部分落定
    /// （None）→ 全落定（Some = 写板素材〔顶层条目〕且任务移除）；非预期
    /// rel / 重复落定 = None；外域路径（非缓存前缀）= None。
    #[test]
    fn r166_job_state_machine() {
        let root = std::env::temp_dir().join(format!("kirin_r166_sm_{}", std::process::id()));
        let dir = root.join("sess-1");
        std::fs::create_dir_all(&dir).unwrap();
        let job = PrefetchJob {
            tag: "sess1".into(),
            expected: ["a.txt".to_string(), "b.txt".to_string()].into_iter().collect(),
            dir: dir.clone(),
            landed: Vec::new(),
            board: vec![dir.join("a.txt"), dir.join("b.txt")],
            started: std::time::Instant::now(),
        };
        registry().lock().unwrap().push(job);
        let p_a = dir.join("a.txt");
        let p_b = dir.join("b.txt");
        // 非预期名 = None（零动作）。
        assert!(prefetch_landed("other.txt", &p_a).is_none());
        // 部分落定 = None。
        assert!(prefetch_landed("a.txt", &p_a).is_none());
        // 重复落定 = None（防同名单元重复计数）。
        assert!(prefetch_landed("a.txt", &p_a).is_none());
        // 全落定 = Some 写板素材（复制序顶层清单）且任务移除。
        let done = prefetch_landed("b.txt", &p_b).expect("complete");
        assert_eq!(done, vec![dir.join("a.txt"), dir.join("b.txt")]);
        // 任务已移除 = 后续落定零动作。
        assert!(prefetch_landed("b.txt", &p_b).is_none());
        // 外域路径 = None（注册表按目录前缀归属 = 跨会话零串扰）。
        let outside = root.join("outside.txt");
        std::fs::write(&outside, b"x").unwrap();
        assert!(prefetch_landed("outside.txt", &outside).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ④' 阶段二目录树状态机：预期键 = 缓存内 rel（`sub/a.txt` 形态）——
    /// **同名不同子目录各自落位**（basename 去重 TTL 回退消除）；嵌套落盘
    /// 路径经 `starts_with` 前缀归属 + 反斜杠规范化命中；完成返回写板素材
    /// （顶层目录项 + 顶层散文件，树内文件不重复上板）。
    #[test]
    fn r166_tree_job_dedup_and_board() {
        let root = std::env::temp_dir().join(format!("kirin_r166_tj_{}", std::process::id()));
        let dir = root.join("sess-2");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::create_dir_all(dir.join("sub2")).unwrap();
        let job = PrefetchJob {
            tag: "sess2".into(),
            // 同名 a.txt 两份（根 + sub/）+ sub2/b.txt——basename 域仅 2 键，
            // rel 域 3 键（阶段一形态 = 集合去重后永不齐 → TTL 回退）。
            expected: [
                "a.txt".to_string(),
                "sub/a.txt".to_string(),
                "sub2/b.txt".to_string(),
            ]
            .into_iter()
            .collect(),
            dir: dir.clone(),
            landed: Vec::new(),
            board: vec![dir.join("a.txt"), dir.join("sub")],
            started: std::time::Instant::now(),
        };
        registry().lock().unwrap().push(job);
        // 同名双落位（根 a.txt + sub/a.txt）双双入账（None = 未齐）。
        assert!(prefetch_landed("a.txt", &dir.join("a.txt")).is_none());
        assert!(prefetch_landed("a.txt", &dir.join("sub").join("a.txt")).is_none());
        // 末件落定 = 完成，返回写板素材（顶层文件 + 顶层目录项）。
        let done = prefetch_landed("b.txt", &dir.join("sub2").join("b.txt")).expect("complete");
        assert_eq!(done, vec![dir.join("a.txt"), dir.join("sub")]);
        assert!(!done.iter().any(|p| p.ends_with("b.txt")), "树内文件不上板（目录项承载）");
        assert!(registry().lock().unwrap().iter().all(|j| j.tag != "sess2"), "完成即移除");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ④'' 派发→落定全链（真实 fs）：目录批元数据 → 结构落位（子目录树
    /// create_dir_all）+ 嵌套 local_dir FetchFile 派发 + rel 键登记 + 逐件
    /// 落定 → 完成。树内文件零重复上板。
    #[test]
    fn r166_dispatch_tree_end_to_end() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        let root = std::env::temp_dir().join(format!("kirin_r166_e2e_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        crate::conn_log_buffer().clear();
        let meta = meta_of(&[
            ("top", true),
            ("top/sub", true),
            ("top/a.txt", false),
            ("top/sub/b.txt", false),
            ("loose.bin", false),
        ]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        prefetch_dispatch_at(&root, &tx, &meta, "r166e2e");
        // 派发 = 全部 fetchable 文件（树内 + 散）；local_dir = rel 父链。
        let mut fetches: Vec<(String, PathBuf)> = Vec::new();
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                crate::file_panel::FileCommand::FetchFile {
                    remote_path,
                    local_dir,
                } => fetches.push((remote_path, local_dir)),
                other => panic!("期望 FetchFile，实为 {other:?}"),
            }
        }
        assert_eq!(fetches.len(), 3, "树内 2 + 散 1");
        let jobs = registry().lock().unwrap();
        let job = jobs.iter().find(|j| j.tag == "r166e2e").expect("任务登记");
        let dir = job.dir.clone();
        // 预期集 = rel 键 3 件；写板素材 = 顶层 top 目录 + loose.bin（复制序）。
        assert_eq!(job.expected.len(), 3);
        assert!(job.expected.contains("top/a.txt") && job.expected.contains("top/sub/b.txt"));
        assert_eq!(
            job.board,
            vec![dir.join("top"), dir.join("loose.bin")],
            "写板素材 = 顶层目录项 + 顶层散文件（复制序）"
        );
        // 结构落位实测：任务目录下 top/sub 目录树已建。
        assert!(dir.join("top").is_dir() && dir.join("top/sub").is_dir());
        // 派发 local_dir = 结构位（top/a.txt → <job>/top；top/sub/b.txt → <job>/top/sub）。
        for (rel, local_dir) in &fetches {
            let want = match rel.as_str() {
                "top/a.txt" => dir.join("top"),
                "top/sub/b.txt" => dir.join("top").join("sub"),
                "loose.bin" => dir.clone(),
                other => panic!("意外派发项 {other}"),
            };
            assert_eq!(local_dir, &want, "rel={rel}");
        }
        drop(jobs);
        // 逐件落定 → 完成 = 写板素材（顶层目录项）。
        assert!(prefetch_landed("x", &dir.join("top").join("a.txt")).is_none());
        assert!(prefetch_landed("x", &dir.join("top").join("sub").join("b.txt")).is_none());
        let done = prefetch_landed("x", &dir.join("loose.bin")).expect("complete");
        assert_eq!(done, vec![dir.join("top"), dir.join("loose.bin")]);
        cancel_tag("r166e2e");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ④''' 降级臂（阶段二收缩面）：truncated 目录批 = 零派发零登记（回退
    /// 两段式）；纯空目录树 = 零 FetchFile + 目录项直接写板（write_cf_hdrop
    /// 假板上板断言经 CF_HDROP 负载构造器等价形态——此处锚「零派发」与
    /// 「结构已落位」两事实）。
    #[test]
    #[cfg(windows)]
    fn r166_dispatch_truncated_and_empty_tree() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        let root = std::env::temp_dir().join(format!("kirin_r166_fb2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // 臂 A：truncated 目录批 → 回退（零派发零登记零结构）。
        crate::conn_log_buffer().clear();
        let mut meta = meta_of(&[("top", true), ("top/a.txt", false)]);
        meta.truncated = true;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        prefetch_dispatch_at(&root, &tx, &meta, "r166trunc");
        assert!(rx.try_recv().is_err(), "truncated = 零派发");
        assert!(
            !registry().lock().unwrap().iter().any(|j| j.tag == "r166trunc"),
            "truncated = 零登记"
        );
        // （回退提示行 = `prefetch_dispatch` 决策臂职责；执行核自守臂静默，
        // FallbackDirs 决策矩阵于 ① 钉死。）
        // 臂 B：纯空目录树 → 零 FetchFile + 结构落位 + 目录项写板。
        let meta2 = meta_of(&[("emptytop", true), ("emptytop/inner", true)]);
        let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel();
        prefetch_dispatch_at(&root, &tx2, &meta2, "r166empty");
        assert!(rx2.try_recv().is_err(), "空树 = 零 FetchFile");
        assert!(
            !registry().lock().unwrap().iter().any(|j| j.tag == "r166empty"),
            "空树 = 零登记（同步完成）"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ⑤ 降级臂 + 边界：目录名消毒（addr 形态 `ip:port` → 仅字母数字）；
    /// c2s 目标目录 = 根相对缓存形态（S1 兼容：零绝对路径零盘符）。
    #[test]
    fn r166_naming_and_fallback_edges() {
        let name = job_dir_name("192.168.77.16:3737", 42);
        assert!(name.starts_with("1099163737"), "消毒只留字母数字：{name}");
        assert!(name.ends_with("-42"));
        assert!(!name.contains(':') && !name.contains('.'), "路径注入字符剥除");
        assert_eq!(job_dir_name(":::", 7), "sess-7", "全剥除 = 兜底 sess");
        let tgt = c2s_target_dir(9);
        assert!(tgt.starts_with(C2S_CACHE_ROOTNAME), "根相对缓存目录");
        assert!(!tgt.starts_with('/') && !tgt.contains(':'), "零绝对路径零盘符（S1）");
    }

    /// ⑥ 自写板签名：写板登记 → 同内容命中（跳过直传）；内容/顺序变化
    /// 不命中；未登记态（sig=0）恒不命中。条目 size=0 形态 = 写板点与
    /// 检测点同源（metadata 不可得双侧一致归零）。
    #[test]
    fn r166_self_write_loop_guard() {
        let entries = vec![("C:\\a.txt".to_string(), 0u64), ("C:\\b.txt".to_string(), 0u64)];
        // 未登记 = 恒不命中（避免初态误吞用户真实复制）。
        assert!(!is_self_board_write(&entries));
        let paths: Vec<PathBuf> = entries.iter().map(|(p, _)| PathBuf::from(p)).collect();
        note_self_board_write(&paths);
        assert!(is_self_board_write(&entries), "同内容同序 = 自写板命中");
        let mut reordered = entries.clone();
        reordered.reverse();
        assert!(!is_self_board_write(&reordered), "顺序变化 = 用户新复制（不吞）");
        let mut changed = entries.clone();
        changed[0].1 = 99;
        assert!(!is_self_board_write(&changed), "内容变化 = 不命中");
        // 点/检测点同源 stat）——同内容同序 = 命中（签名覆盖目录项）。
        let base = std::env::temp_dir().join(format!("kirin_r166_loop_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let tree = base.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        let dir_paths = vec![tree.clone(), base.join("loose.txt")];
        note_self_board_write(&dir_paths);
        let dir_entries: Vec<(String, u64)> = dir_paths
            .iter()
            .map(|p| {
                (
                    p.to_string_lossy().into_owned(),
                    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
                )
            })
            .collect();
        assert!(is_self_board_write(&dir_entries), "目录项签名命中（防回环覆盖目录）");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `build_hdrop_payload`——写与回滚共用；本测 = 直贴链写板素材的
    /// 布局锚：20B 头 + 双空终止宽字符路径列表）。
    #[test]
    #[cfg(windows)]
    fn r166_dropfiles_payload_layout_nail() {
        let payload = crate::clipboard::build_hdrop_payload(&[
            "C:\\cache\\a.txt".to_string(),
            "C:\\cache\\b.txt".to_string(),
        ]);
        // 头 20B（POINT 8 + fNC 4 + fWide 4 + dwReserved 4）；路径
        // `C:\cache\a.txt` = 14 字符 ×2B + NUL ×2B = 30B/条。
        assert_eq!(payload.len(), 20 + (14 + 1) * 2 + (14 + 1) * 2 + 2);
        // fWide = 1（宽字符）。
        assert_eq!(&payload[12..16], &1i32.to_ne_bytes());
        // 主体 = UTF-16LE 路径 + 单 NUL 终止 ×2 + 末尾双 NUL。
        let body = &payload[20..];
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_ne_bytes([c[0], c[1]]))
            .collect();
        let s: String = units.iter().filter(|&&u| u != 0).map(|&u| char::from_u32(u as u32).unwrap()).collect();
        assert_eq!(s, "C:\\cache\\a.txtC:\\cache\\b.txt");
        assert_eq!(units[units.len() - 1], 0);
        assert_eq!(units[units.len() - 2], 0, "末尾双 NUL 终止");
        // 序列化单点（CF_HDROP 原生支持目录，Explorer 粘贴 = 递归复制；
        // 零 is_dir 字段 = 负载形态逐位同构，仅路径语义不同）。
        let dir_payload = crate::clipboard::build_hdrop_payload(&[
            "C:\\cache\\top".to_string(),
            "C:\\cache\\loose.bin".to_string(),
        ]);
        let dunits: Vec<u16> = dir_payload[20..]
            .chunks_exact(2)
            .map(|c| u16::from_ne_bytes([c[0], c[1]]))
            .collect();
        let ds: String = dunits
            .iter()
            .filter(|&&u| u != 0)
            .map(|&u| char::from_u32(u as u32).unwrap())
            .collect();
        assert_eq!(ds, "C:\\cache\\topC:\\cache\\loose.bin", "目录项 = 路径原样入板");
        assert_eq!(dir_payload.len(), 20 + (12 + 1) * 2 + (18 + 1) * 2 + 2);
    }


    /// Windows 目录联接构造（mklink /J 无需特权；junction = reparse point
    /// 代表形态，符号链接同属性位同类拦截）。
    #[cfg(windows)]
    fn make_junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn r186_warn_lines() -> usize {
        crate::conn_log_buffer()
            .snapshot()
            .iter()
            .filter(|l| {
                l.level == crate::widgets::ConnLogLevel::Warn
                    && l.segments.iter().any(|s| {
                        matches!(s, crate::widgets::ConnLogSeg::Text(t) if t.contains("直贴缓存目录异常"))
                    })
            })
            .count()
    }

    /// 常规创建 + 复检 = true；普通文件 = false；目录联接（junction）=
    /// false（敌性容器拒用，零删除——预置对象原样保留）。
    #[test]
    fn r186_ensure_real_dir_matrix() {
        let base = std::env::temp_dir().join(format!("kirin_r186_er_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // 正常目录 = true。
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        assert!(ensure_real_dir(&real), "正常目录可用");
        // 不存在 = 常规创建 + 复检 = true（且目录真实落盘）。
        let fresh = base.join("fresh").join("nested");
        assert!(ensure_real_dir(&fresh), "缺径 = create_dir_all 后复检");
        assert!(fresh.is_dir(), "目录已创建");
        // 普通文件 = false（非目录拒用）。
        let file = base.join("afile");
        std::fs::write(&file, b"x").unwrap();
        assert!(!ensure_real_dir(&file), "文件 = 拒用");
        // 目录联接 = false（重定向容器拒用；目标对象零触碰）。
        #[cfg(windows)]
        {
            let target = base.join("jtarget");
            std::fs::create_dir_all(&target).unwrap();
            std::fs::write(target.join("keep.txt"), b"k").unwrap();
            let link = base.join("jlink");
            assert!(make_junction(&link, &target), "junction 构造（NTFS 前置）");
            assert!(!ensure_real_dir(&link), "junction = 敌性容器拒用");
            assert!(
                target.join("keep.txt").exists(),
                "禁删除用户预置对象：链接目标原样保留"
            );
            let _ = std::fs::remove_dir(&link); // 仅删链接本身，不递归目标。
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 下 `prefetch_dispatch_at` 零 FetchFile 派发（零跨链接写入）、链接
    /// 目标零落盘、注册表零登记、连接页 Warn 恰一行。
    #[test]
    #[cfg(windows)]
    fn r186_prefetch_falls_back_on_hostile_root() {
        // 共享连接日志缓冲读清 → r92ti 锁域串行化（file_panel/lib 测试同
        // 纪律：防并发写用例污染断言）。
        let _g = crate::cli::r92ti_global_lock::lock_global();
        let base = std::env::temp_dir().join(format!("kirin_r186_fb_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("attacker_target");
        std::fs::create_dir_all(&target).unwrap();
        let root = base.join("clip_cache");
        assert!(make_junction(&root, &target), "junction 构造（NTFS 前置）");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        crate::conn_log_buffer().clear();
        let tag = "r186hostile";
        prefetch_dispatch_at(&root, &tx, &meta_of(&[("a.txt", false), ("b.txt", false)]), tag);
        // 零 FetchFile = 零跨链接写入。
        assert!(rx.try_recv().is_err(), "敌性容器 = 零预取派发（回退两段式）");
        // 链接目标零落盘（禁删除 + 禁写入）。
        let landed: Vec<_> = std::fs::read_dir(&target).unwrap().collect();
        assert_eq!(landed.len(), 0, "链接目标零触碰零写入");
        // 注册表零登记。
        assert!(
            !registry().lock().unwrap().iter().any(|j| j.tag == tag),
            "敌性容器 = 零任务登记"
        );
        // 连接页 Warn 恰一行。
        assert_eq!(r186_warn_lines(), 1, "Warn 恰一行（不刷屏）");
        let _ = std::fs::remove_dir(&root);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 恰如计划数、任务登记于根下任务目录（容器预检零误伤）。
    #[test]
    fn r186_prefetch_normal_root_unchanged() {
        // 派发臂会推连接日志行（prefetch started）→ 同锁域串行化，防污染
        // 并行断言用例（r92ti 纪律）。
        let _g = crate::cli::r92ti_global_lock::lock_global();
        let root = std::env::temp_dir().join(format!("kirin_r186_ok_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let tag = "r186normal";
        prefetch_dispatch_at(&root, &tx, &meta_of(&[("a.txt", false), ("b.txt", false)]), tag);
        let mut got = 0;
        while let Ok(cmd) = rx.try_recv() {
            assert!(matches!(cmd, crate::file_panel::FileCommand::FetchFile { .. }));
            got += 1;
        }
        assert_eq!(got, 2, "正常容器 = 逐文件 FetchFile 派发（现状不变）");
        let jobs = registry().lock().unwrap();
        let job = jobs.iter().find(|j| j.tag == tag).expect("任务已登记");
        assert_eq!(job.dir.parent(), Some(root.as_path()), "任务目录在根下");
        drop(jobs);
        cancel_tag(tag); // 清理（半成品删除既有臂）。
        assert!(!registry().lock().unwrap().iter().any(|j| j.tag == tag));
        let _ = std::fs::remove_dir_all(&root);
    }
}
