mod cli;
mod policy;
mod privacy;
mod theme;
mod widgets;
pub mod terminal;
pub mod clipboard;
pub mod file_panel;

use file_panel::{FileCommand, FileDirection, FilePanelState, FileTask, FileTaskStatus};

use kirin_desk_core::connection::file_transfer::{
    block_len, block_offset, derive_transfer_id, sanitize_filename, sha256_file,
    validate_block_count, ChunkReceiver, FileOfferMeta, FileOp, FileTransferError,
    FileTransferFrame, SlideWindowSender, StoredTransfer, TransferScheduler, TransferStore,
    BLOCK_SIZE, DEFAULT_MAX_FILE_SIZE,
};
use kirin_desk_core::connection::ShellMessage;
// M8-T019: 隐私模式（黑屏 / 锁屏）状态机。
use kirin_desk_core::connection::privacy::{PrivacyController, PrivacyLevel, PrivacyOutcome};
use kirin_desk_core::connection::temp_mode::TempModeManager;
use kirin_desk_core::crypto::ed25519::IdentityManager;
// M15 (SRV-SEC-KH-001): 服务端两阶段握手（预读 init → pin → 应答）。
use kirin_desk_core::crypto::handshake::{
    domain_matches_whitelist, server_handshake_respond_generic, server_read_init,
    verify_server_init_with_temp, SecureChannel,
};
use kirin_desk_media::capture::CaptureError;
// M15 (SRV-SEC-RL-001/002): 服务端连接速率限制。
use kirin_desk_core::network::rate_limit::{RateLimitDecision, RateLimiter};
use kirin_desk_utils::logging::LogBuffer;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use terminal::Terminal;

// M15-T008: 设计令牌 + 通用组件（本文件全部取色/字号经 theme 令牌，零裸 Color32）。
use theme::{Theme, ThemeMode};
use widgets::{
    action_button, badge, card, copy_button, labeled_input, log_view, selectable_pill,
    segmented_control, stat_card, StatRow, status_dot, status_dot_char, stepper, toolbar_button,
    BadgeKind, ButtonKind, ButtonState, LogViewOptions, Validity,
};

// M10: 设备列表持久化 + DNS 发现连接。
use kirin_desk_dns::discovery::DiscoveryService;
use kirin_desk_dns::godaddy::GoDaddyClient;
use kirin_desk_utils::devices::{DeviceStore, SavedDevice};
// M15 (CLI-KH): 已知主机指纹验证。
use kirin_desk_utils::known_hosts::{fingerprint as kh_fingerprint, FingerprintStatus, KnownHostsStore};

// M9: 远程输入注入（客户端捕获 → 加密通道 → 服务端注入）。
// M8-T020: SpecialCombo 特殊键（Win/Alt+Tab/任务管理器/锁屏）。
use kirin_desk_input::injector::{
    button as hid_button, modifier as hid_modifier, InputEvent as WireInputEvent, InputInjector,
    InputKind, Key as HidKey, SpecialCombo,
};
use kirin_desk_media::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use kirin_desk_media::proto::DisplayInfo;
use kirin_desk_media::transport::{
    ChannelTag, ControlMessage, SecureChannelReceiver, SecureChannelSender,
};
// M14-T005: 自动更新（Settings Update 面板 + 每周后台检查）。
use kirin_desk_updater::{ReleaseInfo, UpdateChannel, UpdateStatus, Updater};
use std::path::{Path, PathBuf};

/// Global log buffer shared between tracing and GUI display.
fn gui_log_buffer() -> Arc<LogBuffer> {
    static BUF: std::sync::OnceLock<Arc<LogBuffer>> = std::sync::OnceLock::new();
    BUF.get_or_init(|| LogBuffer::new(500)).clone()
}

/// M15-T008: LogView「Clear」按钮回调——清空共享日志缓冲（`fn()` 无借用冲突）。
pub(crate) fn clear_gui_log() {
    gui_log_buffer().clear();
}

/// Global persistent device identity (loaded once at startup).
fn global_identity() -> &'static OnceLock<IdentityManager> {
    static ID: OnceLock<IdentityManager> = OnceLock::new();
    &ID
}

/// Signal to stop the server thread.
fn server_stop_signal() -> &'static AtomicBool {
    static STOP: AtomicBool = AtomicBool::new(false);
    &STOP
}

/// Shared connection status (server/connect threads → GUI).
fn connection_status() -> &'static Mutex<String> {
    static S: OnceLock<Mutex<String>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(String::new()))
}

/// Global server-side channel halves: (输入接收读半, 视频发送写半)。
/// M9 起由 [`SecureChannelReceiver`]/[`SecureChannelSender`] 表示，
/// 各方向单任务独占，无锁并发。
fn server_channel() -> &'static Mutex<Option<(SecureChannelReceiver, SecureChannelSender)>> {
    static C: OnceLock<Mutex<Option<(SecureChannelReceiver, SecureChannelSender)>>> =
        OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// 客户端已知的远端捕获分辨率（接收循环按 session_id 写入；视口输入捕获读取）。
/// M8-T021 P1 (T021-02): 键控 map——多连接各窗口读取自身会话的分辨率，
/// 不再后写覆盖。
fn client_resolution() -> &'static Mutex<HashMap<u64, (u32, u32)>> {
    static R: OnceLock<Mutex<HashMap<u64, (u32, u32)>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Connection stats for the status bar (FPS, bandwidth, resolution).
#[derive(Clone, Default)]
struct ConnectionStats {
    fps: f32,
    bandwidth_kbps: f32,
    resolution: String,
}

/// 共享连接统计（M8-T021 P1: 按 session_id 键控，多窗口各自读取自身会话）。
fn connection_stats() -> &'static Mutex<HashMap<u64, ConnectionStats>> {
    static S: OnceLock<Mutex<HashMap<u64, ConnectionStats>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// M8-T018: 显示器查看状态（接收循环写，连接窗口读）。
///
/// - `list`：`DisplayListResp` 填充的显示器列表（CLI-MON-001）；
/// - `nack`：`DisplaySelectNack` 拒绝原因（切换失败提示，MON-NF-001）。
#[derive(Clone, Default)]
struct DisplayViewState {
    /// 服务端显示器列表（空 = 尚未请求/响应）。
    list: Vec<DisplayInfo>,
    /// 最近一次切换拒绝原因（窗口提示后清除）。
    nack: Option<String>,
}

/// 共享显示器查看状态（M8-T021 P1: 按 session_id 键控，多窗口互不串扰）。
fn display_view_state() -> &'static Mutex<HashMap<u64, DisplayViewState>> {
    static S: OnceLock<Mutex<HashMap<u64, DisplayViewState>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

// ════════════════════════════════════════════════════════════════
// M8-T019: 隐私模式 — 跨线程共享状态
// ════════════════════════════════════════════════════════════════

/// 客户端隐私状态（接收循环写 ack，连接窗口读徽标/输入禁用/toast）。
#[derive(Clone, Default)]
struct PrivacyClientState {
    /// 客户端最近一次请求（窗口发送前设置；接收循环据此生成降级提示）。
    requested: Option<PrivacyLevel>,
    /// 服务端最近一次响应（`PrivacyModeAck`）。
    ack: Option<privacy::PrivacyAckState>,
}

/// 客户端隐私共享状态（UI-PRIV-002/004；M8-T021 P1: 按 session_id 键控）。
fn client_privacy_state() -> &'static Mutex<HashMap<u64, PrivacyClientState>> {
    static S: OnceLock<Mutex<HashMap<u64, PrivacyClientState>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// M8-T021 P1 (T021-02) / P2 (T021-02): 会话退出时清理自身的键控状态条目
///（P2 在两个会话启动器退出路径调用；无论窗口关闭与会话退出谁先发生，最终无残留）。
fn cleanup_session_state(session_id: u64) {
    if let Ok(mut m) = client_resolution().lock() {
        m.remove(&session_id);
    }
    if let Ok(mut m) = connection_stats().lock() {
        m.remove(&session_id);
    }
    if let Ok(mut m) = display_view_state().lock() {
        m.remove(&session_id);
    }
    if let Ok(mut m) = client_privacy_state().lock() {
        m.remove(&session_id);
    }
}

/// 服务端隐私控制器（GUI 模式黑屏覆盖 / 锁屏执行；每会话一个，接收任务
/// 与 UI 线程共享——UI 每帧轮询 `active_level` 驱动覆盖窗口显示/关闭，
/// 断连恢复由此**无网络依赖**，SRV-PRIV-014）。
fn server_privacy_controller() -> &'static Mutex<Option<Arc<Mutex<PrivacyController>>>> {
    static C: OnceLock<Mutex<Option<Arc<Mutex<PrivacyController>>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

// ════════════════════════════════════════════════════════════════
// M13-T006: 文件传输 — 跨线程共享状态
// ════════════════════════════════════════════════════════════════

/// 客户端文件面板状态（客户端会话任务写，连接窗口读）。
fn file_panel_state() -> &'static Mutex<FilePanelState> {
    static S: OnceLock<Mutex<FilePanelState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(FilePanelState::new()))
}

/// 服务端文件面板状态（服务端会话任务写，主窗口读）。
fn server_file_panel_state() -> &'static Mutex<FilePanelState> {
    static S: OnceLock<Mutex<FilePanelState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(FilePanelState::new()))
}

/// 服务端文件命令通道（主窗口 → 服务端会话；连接建立时注册）。
fn server_file_tx(
) -> &'static Mutex<Option<tokio::sync::mpsc::UnboundedSender<FileCommand>>> {
    static T: OnceLock<Mutex<Option<tokio::sync::mpsc::UnboundedSender<FileCommand>>>> =
        OnceLock::new();
    T.get_or_init(|| Mutex::new(None))
}

/// 服务端文件接收完成通知（会话写，主窗口每帧 drain 弹窗，UI-FT-005）。
fn server_file_notices() -> &'static Mutex<std::collections::VecDeque<String>> {
    static N: OnceLock<Mutex<std::collections::VecDeque<String>>> = OnceLock::new();
    N.get_or_init(|| Mutex::new(std::collections::VecDeque::new()))
}

/// M13-T006: 文件传输会话盐——握手双方一致（本端 ID 与对端 ID 排序拼接）。
/// transfer_id = hash(文件名|大小|盐)，双方必须派生相同值。
fn file_transfer_salt(my_id: &str, peer_id: &str) -> String {
    let mut parts = [my_id.to_string(), peer_id.to_string()];
    parts.sort();
    parts.concat()
}

/// M13-T006: 会话断点存储路径（客户端/服务端分离，避免双会话并发写冲突）。
fn transfers_store_path(role: &str) -> PathBuf {
    kirin_desk_utils::config::Config::config_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(format!("transfers_{role}.json"))
}

// ════════════════════════════════════════════════════════════════
// M14-T005: 自动更新 — 全局更新器 + 跨线程共享状态
// 模式同连接/服务端：工作线程（自建 tokio runtime）写共享状态，
// GUI 每帧读；`request_repaint` 通知 UI 刷新。
// ════════════════════════════════════════════════════════════════

/// 全局更新器（懒初始化；下载目录 = 配置目录/updates）。
fn global_updater() -> &'static OnceLock<Updater> {
    static U: OnceLock<Updater> = OnceLock::new();
    &U
}

fn updater() -> Updater {
    global_updater()
        .get_or_init(|| {
            let data_dir = kirin_desk_utils::config::Config::config_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("updates");
            Updater::new(data_dir, UpdateChannel::Stable)
        })
        .clone()
}

/// 更新线程 → GUI 的共享状态（工作线程写，Settings 面板每帧读）。
#[derive(Default)]
struct UpdateUiState {
    /// 正在检查更新。
    checking: bool,
    /// 正在下载更新。
    downloading: bool,
    /// 最近一次检查结果（Error 变体走 `error` 字段）。
    result: Option<UpdateStatus>,
    /// 下载进度：(已接收字节, 总字节或 None)。
    progress: (u64, Option<u64>),
    /// 已下载到本地的更新文件。
    downloaded: Option<PathBuf>,
    /// 最近错误信息。
    error: Option<String>,
}

fn update_state() -> &'static Mutex<UpdateUiState> {
    static S: OnceLock<Mutex<UpdateUiState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(UpdateUiState::default()))
}

/// 后台检查更新（std::thread + 自建 tokio runtime，与 Connect 按钮同模式）。
fn spawn_update_check(ctx: egui::Context) {
    std::thread::spawn(move || {
        let updater = updater();
        {
            let mut s = update_state().lock().unwrap();
            s.checking = true;
            s.error = None;
        }
        ctx.request_repaint();
        let rt = tokio::runtime::Runtime::new().expect("update check rt");
        let status = rt.block_on(updater.check_for_updates());
        let mut s = update_state().lock().unwrap();
        s.checking = false;
        match status {
            UpdateStatus::Error(e) => s.error = Some(e),
            other => s.result = Some(other),
        }
        ctx.request_repaint();
    });
}

/// 后台下载更新（进度写入共享状态，每块下载后 repaint）。
fn spawn_update_download(ctx: egui::Context, release: ReleaseInfo) {
    std::thread::spawn(move || {
        let updater = updater();
        {
            let mut s = update_state().lock().unwrap();
            s.downloading = true;
            s.progress = (0, None);
            s.error = None;
        }
        ctx.request_repaint();
        let rt = tokio::runtime::Runtime::new().expect("update download rt");
        let ctx_progress = ctx.clone();
        let result = rt.block_on(updater.download_update_with_progress(
            &release,
            move |received, total| {
                let mut s = update_state().lock().unwrap();
                s.progress = (received, total);
                ctx_progress.request_repaint();
            },
        ));
        let mut s = update_state().lock().unwrap();
        s.downloading = false;
        match result {
            Ok(path) => s.downloaded = Some(path),
            Err(e) => s.error = Some(e.to_string()),
        }
        ctx.request_repaint();
    });
}

/// 安装已下载更新（Windows：替换脚本 → 旧进程退出 → 覆盖 exe → 重启）。
#[cfg(target_os = "windows")]
fn install_update(downloaded: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let script_dir = std::env::temp_dir().join("kirin_desk_update");
    std::fs::create_dir_all(&script_dir).map_err(|e| e.to_string())?;
    let script = script_dir.join("apply_update.bat");
    let content = format!(
        "@echo off\r\n\
         timeout /t 2 /nobreak >nul\r\n\
         copy /Y \"{}\" \"{}\" >nul\r\n\
         if exist \"{}\" start \"\" \"{}\"\r\n\
         del \"%~f0\"\r\n",
        downloaded.display(),
        exe.display(),
        exe.display(),
        exe.display()
    );
    std::fs::write(&script, content).map_err(|e| e.to_string())?;
    // CREATE_NO_WINDOW：替换脚本后台静默运行。
    std::process::Command::new("cmd")
        .args(["/c", script.to_str().unwrap_or("")])
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// 非 Windows 平台：自动安装暂未支持，提示手动替换。
#[cfg(not(target_os = "windows"))]
fn install_update(_downloaded: &Path) -> Result<(), String> {
    Err("自动安装暂仅支持 Windows，请手动替换应用。".to_string())
}

// M15 (SRV-SEC-WL / 连接审批): 服务端线程 ↔ GUI 审批弹窗的跨线程桥。
// 服务端 accept 线程：未知公钥 + 非白名单 → 推送 `PendingConnection` 到
// `pending_conn_rx`（GUI 弹窗）→ 注册 oneshot 到 `pending_decisions` →
// 等待用户决策（60s 超时）→ 接受则应答握手、拒绝则关闭。
// GUI 线程：`update()` 每帧 drain rx 到 `self.pending_connections`；
// `approve_connection` 向 `pending_decisions` 回传决策。

/// 服务端 → GUI 的待审批连接通知（发送端，服务端线程持有）。
fn pending_conn_tx() -> &'static OnceLock<tokio::sync::mpsc::UnboundedSender<PendingConnection>> {
    static TX: OnceLock<tokio::sync::mpsc::UnboundedSender<PendingConnection>> = OnceLock::new();
    &TX
}

/// GUI 侧待审批连接接收端（egui update 每帧 try_recv）。
fn pending_conn_rx() -> &'static Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<PendingConnection>>>
{
    static RX: OnceLock<Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<PendingConnection>>>> =
        OnceLock::new();
    RX.get_or_init(|| Mutex::new(None))
}

/// 审批决策回传：pending id → oneshot（GUI approve → 服务端线程握手续答）。
fn pending_decisions() -> &'static Mutex<HashMap<u64, tokio::sync::oneshot::Sender<bool>>> {
    static D: OnceLock<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<bool>>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 待审批连接 id 分配（服务端线程内跨连接唯一）。
fn pending_next_id() -> u64 {
    static ID: AtomicU64 = AtomicU64::new(1);
    ID.fetch_add(1, Ordering::Relaxed)
}

/// 审计写入助手（审计器不可用时静默跳过）。
fn audit_record(
    audit: &mut Option<kirin_desk_utils::audit::AuditLogger>,
    event: kirin_desk_utils::audit::AuditEvent,
    detail: &str,
) {
    if let Some(a) = audit {
        let _ = a.record(event, detail);
    }
}

/// M8-T019 (SRV-PRIV-002): 发送 `PrivacyModeAck`（复用 M8-T018 控制通道，
/// `ChannelTag::Control`，bincode `ControlMessage`）。
/// `sender` 为 tokio Mutex 共享写半（与输入/文件发送任务共用，帧边界安全）。
async fn send_privacy_ack(
    sender: &Arc<tokio::sync::Mutex<SecureChannelSender>>,
    ok: bool,
    active_level: Option<PrivacyLevel>,
) {
    let msg = ControlMessage::PrivacyModeAck { ok, active_level };
    let data = match bincode::serialize(&msg) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("privacy ack serialize failed: {e}");
            return;
        }
    };
    let pkt = EncodedPacket {
        ts: Timestamp::now(),
        kind: PacketKind::Control,
        data,
        is_key: false,
    };
    if let Err(e) = sender.lock().await.send_packets(&[pkt]).await {
        tracing::warn!("privacy ack send failed: {e}");
    }
}

/// M8-T019 (SRV-PRIV-001/002/013 + PRIV-SEC-001): 处理客户端隐私模式请求
/// （`ControlMessage::PrivacyMode`）→ 执行黑屏/锁屏 → Ack + 审计。
///
/// - Black 且无 GUI（headless）→ 自动降级 Lock（由 [`PrivacyController::request`] 返回）；
/// - Lock 平台调用失败 → `Rejected` → Ack `ok=false`；
/// - 所有开启/关闭/降级/失败均写审计（事件含 level 与发起方）。
async fn handle_server_privacy_message(
    payload: &[u8],
    controller: &Arc<Mutex<PrivacyController>>,
    sender: &Arc<tokio::sync::Mutex<SecureChannelSender>>,
    audit: &mut Option<kirin_desk_utils::audit::AuditLogger>,
    audit_peer: &str,
) {
    let msg: ControlMessage = match bincode::deserialize(payload) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("privacy message deserialize failed: {e}");
            return;
        }
    };
    let ControlMessage::PrivacyMode { level, on } = msg else {
        tracing::debug!("control message on privacy channel (unhandled): {msg:?}");
        return;
    };
    let outcome = controller.lock().unwrap().request(level, on);
    let (ok, active_level, event, detail) = match outcome {
        PrivacyOutcome::Activated(active) => {
            let degraded = active != level;
            if degraded {
                // Black 请求 → 实际 Lock（无 GUI 降级，SRV-PRIV-013）。
                (
                    true,
                    Some(active),
                    kirin_desk_utils::audit::AuditEvent::PrivacyDegraded,
                    format!(
                        "level={}->{} {audit_peer}",
                        level.as_str(),
                        active.as_str()
                    ),
                )
            } else {
                (
                    true,
                    Some(active),
                    kirin_desk_utils::audit::AuditEvent::PrivacyEnabled,
                    format!("level={} {audit_peer}", active.as_str()),
                )
            }
        }
        PrivacyOutcome::Off => (
            true,
            None,
            kirin_desk_utils::audit::AuditEvent::PrivacyDisabled,
            format!("level={} {audit_peer}", level.as_str()),
        ),
        PrivacyOutcome::Rejected(reason) => (
            false,
            controller.lock().unwrap().active_level(),
            kirin_desk_utils::audit::AuditEvent::PrivacyDegraded,
            format!("level={} reason={} {audit_peer}", level.as_str(), reason),
        ),
    };
    audit_record(audit, event, &detail);
    tracing::info!(
        "[Privacy] request level={} on={} → ok={} active={:?} ({detail})",
        level.as_str(),
        on,
        ok,
        active_level
    );
    send_privacy_ack(sender, ok, active_level).await;
}

/// Initialize tracing/logging from the config file (falling back to defaults).
fn init_logging_from_config() {
    let buf = gui_log_buffer();
    match kirin_desk_utils::config::Config::load() {
        Ok(cfg) => {
            let level = cfg.logging.level.clone();
            let format = cfg.logging.format.clone();
            let keep_days = cfg.logging.log_keep_days;
            let log_dir = cfg
                .logging
                .log_dir
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(kirin_desk_utils::logging::default_log_dir);
            kirin_desk_utils::logging::init_logging_with(
                &level,
                &format,
                &log_dir,
                keep_days,
                Some(buf),
            );
        }
        Err(_) => {
            kirin_desk_utils::logging::init_logging_with(
                "info",
                "text",
                &kirin_desk_utils::logging::default_log_dir(),
                kirin_desk_utils::logging::DEFAULT_KEEP_DAYS,
                Some(buf),
            );
        }
    }
}

pub fn run() {
    // Initialize logging from config
    init_logging_from_config();

    // Probe FFmpeg availability at startup
    if kirin_desk_media::ffmpeg::ensure_loaded().is_ok() {
        tracing::info!("FFmpeg DLLs loaded OK");
    } else {
        tracing::warn!("FFmpeg DLLs not available — H.264 encode/decode disabled");
    }

    let has_cli_flag = std::env::args().any(|a| a == "--cli");
    // M13-T005 (UA-BOOT-004): `--autostart` 由系统开机自启拉起——与 `--cli` 互斥
    // （CLI 场景忽略自启参数），驱动窗口最小化启动（UA-UI-003）。
    let autostart_launched = std::env::args().any(|a| a == "--autostart") && !has_cli_flag;
    if autostart_launched {
        tracing::info!("Launched by OS autostart (--autostart)");
    }

    #[cfg(target_os = "windows")]
    if has_cli_flag {
        extern "system" {
            fn AllocConsole() -> i32;
        }
        unsafe {
            AllocConsole();
        }
    }

    if has_cli_flag {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        rt.block_on(async { cli::run_cli().await });
        return;
    }
    if start_gui(autostart_launched).is_err() {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        rt.block_on(async { cli::run_cli().await });
    }
}

fn start_gui(autostart_launched: bool) -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("KirinDesk - P2P Remote Desktop"),
        // M15-T008: ThemeMode::System 需要系统主题信息（eframe 0.28 经
        // `frame.info().system_theme` 暴露；0.28 无 `ctx.system_theme()`）。
        follow_system_theme: true,
        ..Default::default()
    };
    eframe::run_native(
        "KirinDesk",
        options,
        Box::new(move |cc| {
            // M15-T008: 令牌 + 字体回退链 + 主题安装；初始模式取自 Config `[ui] theme`。
            let initial_mode = kirin_desk_utils::config::Config::load()
                .map(|cfg| ThemeMode::from_str(&cfg.ui.theme))
                .unwrap_or_default();
            theme::install(&cc.egui_ctx, initial_mode);
            Ok(Box::new(KirinDeskApp {
                theme_mode: initial_mode,
                // M13-T005: --autostart 标记（驱动最小化启动）
                autostart_launched,
                ..Default::default()
            }))
        }),
    )
    .map_err(|e| e.to_string())
}

/// A pending incoming connection waiting for user approval.
#[derive(Clone)]
struct PendingConnection {
    id: u64,
    client_id: String,
    client_domain: String,
    device_type: String,
    status: PendingStatus,
}

#[derive(Clone, PartialEq)]
enum PendingStatus {
    Waiting,
    Accepted,
    Rejected,
}

/// Shared state between the GUI and the server listener thread.
struct ServerState {
    pending_connections: Vec<PendingConnection>,
    next_id: u64,
}

/// 连接窗口类型（M11：桌面远程控制 / 远程 Shell PTY）。
#[derive(Clone, Copy, PartialEq)]
enum WindowKind {
    Desktop,
    Shell,
}

/// M8-T020 UI-SKEY-004: 被控端（服务端）平台——特殊键面板据此禁用
/// 不支持项（macOS 不支持 Alt+Tab 注入，SRV-SKEY-014）。
///
/// 平台传播通道预留：当前默认 `Unknown`（不限制）；待控制消息
/// 基础设施（M8-T019 控制通道）就绪后由连接建立路径填充
/// （`Windows`/`Linux` 变体为传播机制预留，见 UI-SKEY-004）。
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // 变体为平台传播机制预留（UI-SKEY-004 P2）
enum RemotePlatform {
    Unknown,
    Windows,
    Linux,
    MacOS,
}

/// A remote connection window (desktop or terminal).
struct ConnectionWindow {
    id: u64,
    /// M8-T021 P1: 会话标识——键控状态（分辨率/统计/显示/隐私）的 key；
    /// 与窗口 id（`ViewportId`）解耦。
    session_id: u64,
    addr: String,
    device_type: String,
    kind: WindowKind,
    /// M9: 输入事件批次发送通道（UI 线程 → tokio 发送任务）。
    /// 窗口关闭时随窗口结构 drop，发送任务收到 None 后自行退出。
    input_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<WireInputEvent>>>,
    /// M9: 输入捕获队列（鼠标移动 60fps 节流合并）。
    input_queue: InputCaptureQueue,
    /// M8-T015 P2D: 远端帧纹理缓存（TextureHandle::set 复用上传，
    /// 避免每帧 `ctx.load_texture` 重建；分辨率变化时 set 自动重建）。
    texture: Option<egui::TextureHandle>,
    /// M8-T021 P1: 本会话的渲染桥（随信号而来；每窗口每帧 pop 自己的帧，
    /// 替代原全局 `render_bridge()` / `client_frame()` 互抢）。
    bridge: Option<kirin_desk_media::decoder::RenderBridge>,
    /// M8-T021 P1: 会话退出通知通道（窗口持有；关闭 / 被去重丢弃时 drop）。
    /// P1 只引入不消费（P2 用 close_rx 侧实现会话退出）。
    #[allow(dead_code)] // P2（会话线程生命周期）读取；P1 仅持有 drop 语义
    close_tx: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    /// M11: 远程 Shell — 终端模拟器（接收任务 feed / UI 渲染共用）。
    terminal: Option<Arc<Mutex<Terminal>>>,
    /// M11: 远程 Shell — 输入/尺寸消息发送通道（UI 线程 → tokio 发送任务）。
    shell_tx: Option<tokio::sync::mpsc::UnboundedSender<ShellMessage>>,
    /// M13-T006: 文件传输命令通道（UI → 会话文件任务；窗口关闭时 drop）。
    file_tx: Option<tokio::sync::mpsc::UnboundedSender<FileCommand>>,
    /// M8-T018: 显示器控制消息发送通道（下拉 → `DisplaySelect` / ⟳ → `DisplayListReq`）。
    /// 窗口关闭时 drop，控制发送任务收到 None 后自行退出。
    control_tx: Option<tokio::sync::mpsc::UnboundedSender<ControlMessage>>,
    /// M8-T018: 显示器列表缓存（`DisplayListResp` 填充，下拉渲染用）。
    display_list: Vec<DisplayInfo>,
    /// M8-T018: 当前所选显示器索引（None = 未选择/服务端默认屏）。
    display_selected: Option<u32>,
    /// M8-T018: 最近一次切换拒绝原因（`DisplaySelectNack`；新选择/新列表后清除）。
    display_nack: Option<String>,
    /// M13-T006: 是否显示文件面板（工具栏 📁 切换）。
    show_file_panel: bool,
    /// M15-T008: 全屏状态（工具栏 ▣ / F11 切换，跟随视口即时生效）。
    fullscreen: bool,
    /// M8-T020 UI-SKEY-001: 特殊键面板开关（工具栏 🔑 切换）。
    show_special_key_panel: bool,
    /// M8-T020 UI-SKEY-004: 被控端平台（macOS → 禁用 Alt+Tab）。
    remote_platform: RemotePlatform,
    /// M8-T020 UI-SKEY-003: 上次特殊键点击时刻（1s 内禁止重复点击，防连点）。
    last_special_key: std::time::Instant,
    /// M8-T019 (UI-PRIV-002/004): 当前隐私状态（来自 `PrivacyModeAck`；
    /// 驱动徽标、锁屏输入禁用与菜单状态）。
    privacy_level: Option<PrivacyLevel>,
    /// M8-T019: 已消费的 ack 序号（toast 只弹一次）。
    privacy_ack_seq: u64,
    /// M8-T019: 待显示 toast（(文案, 起始时刻)，5s 自动消失）。
    privacy_toast: Option<(String, std::time::Instant)>,
}

impl ConnectionWindow {
    /// M8-T018（CLI-MON-003）：当前所选显示器的信息（列表 + 选中索引；
    /// 未选择 = 服务端默认屏，即列表首项）。
    fn current_display(&self) -> Option<&DisplayInfo> {
        let idx = self.display_selected.unwrap_or(0) as usize;
        self.display_list.get(idx)
    }

    /// M8-T018（MON-NF-001）：同步共享显示器状态（接收循环 → 本窗口缓存）。
    /// M8-T021 P1: 按 `session_id` 读取自身会话的键控状态。
    ///
    /// - 新列表（`DisplayListResp`）→ 更新缓存 + 校验选中索引 + 清 Nack；
    /// - Nack 一次性取走（窗口内持续显示，直到用户重新选择或新列表到达）。
    fn sync_display_state(&mut self) {
        let mut st = display_view_state().lock().unwrap();
        let Some(st) = st.get_mut(&self.session_id) else {
            return; // 会话尚未写入 / 已清理（P2）→ 保持现状
        };
        if !st.list.is_empty() && st.list != self.display_list {
            self.display_list = st.list.clone();
            // 列表刷新（热插拔）后选中索引越界 → 回退默认屏。
            if let Some(sel) = self.display_selected {
                if sel as usize >= self.display_list.len() {
                    self.display_selected = None;
                }
            }
            self.display_nack = None;
        }
        if let Some(nack) = st.nack.take() {
            self.display_nack = Some(nack);
        }
    }

    /// M8-T018（CLI-MON-002）：发送显示器控制消息（切换 / 刷新请求）。
    /// 发送失败 = 会话已关闭（发送任务退出），忽略即可。
    fn send_display_control(&self, msg: ControlMessage) {
        if let Some(tx) = &self.control_tx {
            let _ = tx.send(msg);
        }
    }

    /// M8-T019（UI-PRIV-001/003）：发送隐私模式控制消息（黑屏/锁屏/恢复），
    /// 复用 M8-T018 控制通道（`ChannelTag::Control`，bincode `ControlMessage`）。
    /// 发送失败 = 会话已关闭（发送任务退出），忽略即可。
    fn send_privacy(&self, msg: ControlMessage) {
        self.send_display_control(msg);
    }

    /// M8-T019（UI-PRIV-002）：把共享 ack 状态同步到本窗口（徽标 + 一次性 toast）。
    /// M8-T021 P1: 按 `session_id` 读取自身会话的键控状态。
    fn sync_privacy_state(&mut self) {
        let st = client_privacy_state().lock().unwrap();
        let Some(st) = st.get(&self.session_id) else {
            return; // 会话尚未写入 / 已清理（P2）→ 保持现状
        };
        if let Some(ack) = &st.ack {
            if ack.seq != self.privacy_ack_seq {
                self.privacy_ack_seq = ack.seq;
                self.privacy_level = ack.level;
                if !ack.toast.is_empty() {
                    self.privacy_toast = Some((ack.toast.clone(), std::time::Instant::now()));
                }
            }
        }
    }
}

/// M9-T002: 客户端输入捕获队列（每连接窗口一个）。
///
/// - 鼠标移动：只保留最新位置（合并），按 60fps（[`INPUT_MOVE_INTERVAL`]）节流发送。
/// - 按键/点击/滚轮/文本：即时入队，随下一次 flush 一起发送（移动事件在前，保证顺序）。
struct InputCaptureQueue {
    pending: Vec<WireInputEvent>,
    pending_move: Option<(u32, u32)>,
    last_flush: std::time::Instant,
}

/// 鼠标移动节流间隔（60fps）。
const INPUT_MOVE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(16);

impl InputCaptureQueue {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            pending_move: None,
            // 初始化为"早已发送过"：首个移动事件立即发送，不被节流吞掉。
            last_flush: std::time::Instant::now() - INPUT_MOVE_INTERVAL,
        }
    }

    /// 记录最新鼠标位置（合并，覆盖上一帧位置）。
    fn push_move(&mut self, x: u32, y: u32) {
        self.pending_move = Some((x, y));
    }

    /// 入队非移动事件。
    fn push(&mut self, ev: WireInputEvent) {
        self.pending.push(ev);
    }

    /// 是否还有未发送事件（节流中判断是否需重绘）。
    fn has_pending(&self) -> bool {
        !self.pending.is_empty() || self.pending_move.is_some()
    }

    /// 节流 flush：
    /// - 含非移动事件 → 立即发送（键鼠指令不可等）；
    /// - 纯移动 → 距上次发送 ≥16ms 才发送（60fps 上限）。
    /// 移动合并为单条、排在批次最前（点击前的位置必须已生效）。
    /// 返回是否实际发送；未发送（节流中）返回 false。
    fn flush_if_due(
        &mut self,
        tx: &tokio::sync::mpsc::UnboundedSender<Vec<WireInputEvent>>,
    ) -> bool {
        if !self.has_pending() {
            return false;
        }
        let has_immediate = !self.pending.is_empty();
        if !has_immediate && self.last_flush.elapsed() < INPUT_MOVE_INTERVAL {
            return false;
        }
        let mut batch = Vec::with_capacity(self.pending.len() + 1);
        if let Some((x, y)) = self.pending_move.take() {
            batch.push(WireInputEvent::mouse_move(x, y));
        }
        batch.append(&mut self.pending);
        self.last_flush = std::time::Instant::now();
        // 发送失败 = 窗口已关闭（发送任务已退出），丢弃即可。
        let _ = tx.send(batch);
        true
    }
}

/// egui 逻辑键 → 管线 HID 键码（[`HidKey`] 判别式，布局无关）。
/// 未覆盖的键（标点/系统键等）返回 None，上层丢弃。
fn egui_key_to_hid(key: egui::Key) -> Option<HidKey> {
    Some(match key {
        egui::Key::A => HidKey::A,
        egui::Key::B => HidKey::B,
        egui::Key::C => HidKey::C,
        egui::Key::D => HidKey::D,
        egui::Key::E => HidKey::E,
        egui::Key::F => HidKey::F,
        egui::Key::G => HidKey::G,
        egui::Key::H => HidKey::H,
        egui::Key::I => HidKey::I,
        egui::Key::J => HidKey::J,
        egui::Key::K => HidKey::K,
        egui::Key::L => HidKey::L,
        egui::Key::M => HidKey::M,
        egui::Key::N => HidKey::N,
        egui::Key::O => HidKey::O,
        egui::Key::P => HidKey::P,
        egui::Key::Q => HidKey::Q,
        egui::Key::R => HidKey::R,
        egui::Key::S => HidKey::S,
        egui::Key::T => HidKey::T,
        egui::Key::U => HidKey::U,
        egui::Key::V => HidKey::V,
        egui::Key::W => HidKey::W,
        egui::Key::X => HidKey::X,
        egui::Key::Y => HidKey::Y,
        egui::Key::Z => HidKey::Z,
        egui::Key::Num0 => HidKey::Num0,
        egui::Key::Num1 => HidKey::Num1,
        egui::Key::Num2 => HidKey::Num2,
        egui::Key::Num3 => HidKey::Num3,
        egui::Key::Num4 => HidKey::Num4,
        egui::Key::Num5 => HidKey::Num5,
        egui::Key::Num6 => HidKey::Num6,
        egui::Key::Num7 => HidKey::Num7,
        egui::Key::Num8 => HidKey::Num8,
        egui::Key::Num9 => HidKey::Num9,
        egui::Key::Enter => HidKey::Enter,
        egui::Key::Escape => HidKey::Esc,
        egui::Key::Backspace => HidKey::Backspace,
        egui::Key::Tab => HidKey::Tab,
        egui::Key::Space => HidKey::Space,
        egui::Key::F1 => HidKey::F1,
        egui::Key::F2 => HidKey::F2,
        egui::Key::F3 => HidKey::F3,
        egui::Key::F4 => HidKey::F4,
        egui::Key::F5 => HidKey::F5,
        egui::Key::F6 => HidKey::F6,
        egui::Key::F7 => HidKey::F7,
        egui::Key::F8 => HidKey::F8,
        egui::Key::F9 => HidKey::F9,
        egui::Key::F10 => HidKey::F10,
        egui::Key::F11 => HidKey::F11,
        egui::Key::F12 => HidKey::F12,
        egui::Key::ArrowUp => HidKey::Up,
        egui::Key::ArrowDown => HidKey::Down,
        egui::Key::ArrowLeft => HidKey::Left,
        egui::Key::ArrowRight => HidKey::Right,
        egui::Key::Insert => HidKey::Insert,
        egui::Key::Home => HidKey::Home,
        egui::Key::PageUp => HidKey::PageUp,
        egui::Key::Delete => HidKey::Delete,
        egui::Key::End => HidKey::End,
        egui::Key::PageDown => HidKey::PageDown,
        _ => return None,
    })
}

/// M8-T021 P1: 全局会话 id（跨 UI/会话线程原子递增）。随窗口信号传递给窗口，
/// 作为一切键控状态（分辨率/统计/显示/隐私）的 key。窗口 id（`ViewportId`）
/// 与之解耦，两者各自单调。
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
fn next_session_id() -> u64 {
    NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)
}

/// M8-T021 P1: 桌面窗口信号（替换 `add_window_signal` 的元组载荷）。
/// 会话握手成功后 push；UI 帧 drain 创建窗口。
struct DesktopWindowSignal {
    session_id: u64,
    addr: String,
    /// 会话创建的渲染桥克隆；窗口每帧 `pop_render` 直上自身纹理。
    bridge: kirin_desk_media::decoder::RenderBridge,
    input_tx: tokio::sync::mpsc::UnboundedSender<Vec<WireInputEvent>>,
    file_tx: tokio::sync::mpsc::UnboundedSender<FileCommand>,
    control_tx: tokio::sync::mpsc::UnboundedSender<ControlMessage>,
    /// 窗口持有；关闭 / 去重丢弃信号 → sender drop → 会话退出（P2 消费）。
    close_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

/// Signal to add a new connection window (addr + 输入发送通道 + 文件命令通道
/// + M8-T018 显示器控制通道 + M8-T021 P1 会话标识/渲染桥/关闭通道)。
fn add_window_signal() -> &'static Mutex<Vec<DesktopWindowSignal>> {
    static W: OnceLock<Mutex<Vec<DesktopWindowSignal>>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(Vec::new()))
}

/// M10-T003: 连接线程成功保存设备后置位，UI 每帧检查并刷新 Devices 列表。
fn devices_dirty() -> &'static AtomicBool {
    static D: AtomicBool = AtomicBool::new(false);
    &D
}

/// M8-T021 P1: Shell 窗口信号（替换 `add_shell_window_signal` 的元组载荷）。
struct ShellWindowSignal {
    session_id: u64,
    addr: String,
    /// 会话已 feed 的终端实例（P1-5 修复断链：窗口直接渲染会话侧终端）。
    terminal: Arc<Mutex<Terminal>>,
    shell_tx: tokio::sync::mpsc::UnboundedSender<ShellMessage>,
    close_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

/// M11-T005: 信号——添加远程 Shell 连接窗口（addr + 终端消息发送通道）。
/// 每设备+每端口 = 独立 PTY 会话，断开单个不影响其他。
fn add_shell_window_signal() -> &'static Mutex<Vec<ShellWindowSignal>> {
    static W: OnceLock<Mutex<Vec<ShellWindowSignal>>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(Vec::new()))
}

/// M8-T021 P1 (T021-01-D): 信号队列是否有同目标 pending（会话已握手成功、
/// 信号已 push、UI 帧尚未 drain）。Domain 模式会话线程无法访问窗口列表，
/// 仅能以此查 pending；已有窗口场景由 UI 帧 drain 去重兜底。
fn pending_signal_has(addr: &str, kind: WindowKind) -> bool {
    match kind {
        WindowKind::Desktop => add_window_signal()
            .lock()
            .map(|q| q.iter().any(|s| s.addr == addr))
            .unwrap_or(false),
        WindowKind::Shell => add_shell_window_signal()
            .lock()
            .map(|q| q.iter().any(|s| s.addr == addr))
            .unwrap_or(false),
    }
}

/// M15 (CLI-HSK-SEC-001/003): 客户端对服务端公钥的信任策略。
#[derive(Clone)]
enum ClientTrust {
    /// 带外可信公钥（known_hosts 指纹 / DNS TXT，用户已确认）→ 握手严格比对，
    /// 不等即拒绝（CLI-HSK-SEC-001）。
    Verified(String),
    /// 无带外公钥 → 握手响应时经确认回调判定（known_hosts 命中自动放行；
    /// 未命中弹首次指纹确认框，CLI-KH-001）。用户确认的公钥在握手成功后
    /// 写入 known_hosts（CLI-KH-002）。
    Confirm,
}

/// M15 (CLI-KH-001): 首次连接指纹确认请求——连接线程设置后阻塞等待，
/// UI 线程渲染模态框，用户接受/拒绝后经 mpsc 应答。
struct PendingFingerprint {
    device_id: String,
    pubkey_base64: String,
    fingerprint: String,
    answer_tx: std::sync::mpsc::Sender<bool>,
}

fn pending_fingerprint() -> &'static Mutex<Option<PendingFingerprint>> {
    static P: OnceLock<Mutex<Option<PendingFingerprint>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(None))
}

/// 设置指纹确认请求并阻塞等待用户应答（连接线程调用；UI 线程渲染模态框）。
/// 返回 `true` = 用户接受。UI 关闭窗口（Sender drop）视为拒绝。
fn confirm_fingerprint_blocking(device_id: &str, pubkey_base64: &str) -> bool {
    let fp = kh_fingerprint(pubkey_base64);
    tracing::info!(
        "[known_hosts] first-connect fingerprint prompt for '{}': {}",
        device_id,
        fp
    );
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    {
        let mut guard = match pending_fingerprint().lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        // 同一时刻只保留一个待确认请求（多连接并发时后者覆盖前者）。
        *guard = Some(PendingFingerprint {
            device_id: device_id.to_string(),
            pubkey_base64: pubkey_base64.to_string(),
            fingerprint: fp,
            answer_tx: tx,
        });
    }
    // 阻塞等待 UI 应答（模态框出现依赖 UI 每帧轮询；窗口被关 → recv Err → 拒绝）。
    match rx.recv() {
        Ok(true) => true,
        _ => {
            if let Ok(mut s) = connection_status().lock() {
                *s = format!(
                    "Fingerprint confirmation declined for '{}' — connection aborted",
                    device_id
                );
            }
            false
        }
    }
}

/// M15 (CLI-KH-003/004): known_hosts 指纹判定 + 首次确认。
/// - 命中且一致 → 自动放行（最高优先级可信公钥来源，优先于 DNS TXT）；
/// - 命中但不一致 → **拒绝连接**（防 MITM，不是仅警告）；
/// - 未命中 → 首次指纹确认框，用户确认后才继续。
/// 拒绝时向 `connection_status` 写入原因。
fn known_hosts_or_confirm(device_id: &str, pubkey_base64: &str) -> bool {
    match KnownHostsStore::load()
        .map(|store| store.check(device_id, pubkey_base64))
    {
        Ok(FingerprintStatus::Match) => {
            tracing::info!("[known_hosts] fingerprint MATCH for '{}'", device_id);
            true
        }
        Ok(FingerprintStatus::Mismatch) => {
            tracing::error!(
                "[known_hosts] fingerprint MISMATCH for '{}' — refusing connection (MITM guard)",
                device_id
            );
            if let Ok(mut s) = connection_status().lock() {
                *s = format!(
                    "SECURITY: known_hosts fingerprint MISMATCH for '{}' — connection refused",
                    device_id
                );
            }
            false
        }
        Ok(FingerprintStatus::Unknown) | Err(_) => {
            confirm_fingerprint_blocking(device_id, pubkey_base64)
        }
    }
}

/// 握手成功后记录 known_hosts（CLI-KH-002）；失败仅告警，不影响主流程。
fn record_known_host(device_id: &str, pubkey_base64: &str) {
    match KnownHostsStore::load().and_then(|mut s| s.confirm(device_id, pubkey_base64)) {
        Ok(fp) => tracing::info!(
            "[known_hosts] recorded '{}' fingerprint {}",
            device_id,
            fp
        ),
        Err(e) => tracing::warn!("[known_hosts] failed to record '{}': {}", device_id, e),
    }
}

/// M11-T002/T005: 客户端远程 Shell 会话启动器（GUI IP 模式）。
///
/// TCP → 完整握手（与 `run_client_session` 相同安全级别：`ClientTrust` 信任策略
/// ——known_hosts / DNS TXT 公钥绑定或首次指纹确认）→ 拆分读写半通道 →
/// 发送任务（终端输入/尺寸 → 加密通道）+ 接收任务（ShellStdout → 终端 feed）→
/// 通知 UI 打开独立 Shell 窗口。多会话：每窗口独立通道/终端/任务。
async fn run_client_shell_session(
    addr: String,
    server_id: String,
    trust: ClientTrust,
    challenge: String,
    domain: String,
    device_type: &str,
    ctx: egui::Context,
) {
    use kirin_desk_core::crypto::handshake::client_handshake_with_confirm;
    // M8-T021 P1: 会话标识（窗口键控状态 key；窗口 id 与之解耦）。
    let session_id = next_session_id();
    tracing::info!("[shell] TCP connecting to {} ...", addr);
    if let Ok(mut s) = connection_status().lock() {
        *s = format!("[shell] Connecting: {} ...", addr);
    }
    let Ok(stream) = tokio::net::TcpStream::connect(&addr).await else {
        tracing::error!("[shell] TCP connect to {} FAILED", addr);
        if let Ok(mut s) = connection_status().lock() {
            *s = format!("[shell] TCP connect FAILED: {}", addr);
        }
        return;
    };
    tracing::info!("[shell] TCP connected to {}", addr);

    let Some(client_id) = global_identity().get() else {
        tracing::error!("[shell] No device identity loaded, can't handshake");
        return;
    };
    let server_name = if server_id.is_empty() {
        "shell-server"
    } else {
        &server_id
    };
    let confirmed_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let ch = match trust.clone() {
        ClientTrust::Verified(expected) => {
            client_handshake_with_confirm(
                stream,
                client_id,
                &server_id,
                "gui-client.local",
                "shell",
                server_name,
                Some(expected),
                None,
                &challenge,
            )
            .await
        }
        ClientTrust::Confirm => {
            let device_id_cb = server_id.clone();
            let confirmed_key_cb = confirmed_key.clone();
            let key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>> =
                Some(Box::new(move |key: &str| {
                    let ok = known_hosts_or_confirm(&device_id_cb, key);
                    if ok {
                        if let Ok(mut ck) = confirmed_key_cb.lock() {
                            *ck = Some(key.to_string());
                        }
                    }
                    ok
                }));
            client_handshake_with_confirm(
                stream,
                client_id,
                &server_id,
                "gui-client.local",
                "shell",
                server_name,
                None,
                key_confirm,
                &challenge,
            )
            .await
        }
    };
    let ch = match ch {
        Ok(ch) => ch,
        Err(e) => {
            tracing::error!("[shell] Handshake FAILED: {}", e);
            if let Ok(mut s) = connection_status().lock() {
                *s = format!("[shell] Handshake FAILED: {}", e);
                // M8-T017-P2 (CLI-TMP-003): 携带挑战码时追加引导提示（防枚举，纯客户端文案）。
                if let Some(h) = crate::policy::connect_failure_challenge_hint(&challenge) {
                    s.push('\n');
                    s.push_str(&h);
                }
            }
            return;
        }
    };
    tracing::info!("[shell] Handshake SUCCESS! Channel to '{}'", server_id);
    if let Ok(mut s) = connection_status().lock() {
        *s = format!("[shell] Connected to {}@{} (transport: TCP)", server_id, addr);
    }

    // M15 (CLI-KH-002): 连接成功 → 记录 known_hosts + 自动保存设备。
    let trusted_key = match &trust {
        ClientTrust::Verified(k) => Some(k.clone()),
        ClientTrust::Confirm => confirmed_key.lock().ok().and_then(|k| k.clone()),
    };
    if let Some(key) = &trusted_key {
        record_known_host(&server_id, key);
        save_device_to_store(&addr, &server_id, key, device_type, &domain);
    }

    let (mut shell_reader, mut shell_writer) = ch.into_split();

    // 终端模拟器（接收任务 feed / UI 渲染共用；跨线程 Arc<Mutex>）。
    let terminal: Arc<Mutex<Terminal>> = Arc::new(Mutex::new(Terminal::new(120, 30)));

    // 发送任务：终端输入/尺寸消息 → 加密通道。
    // 窗口关闭 → UI 侧 Sender drop → recv None → 任务退出。
    let (shell_tx, mut shell_rx) = tokio::sync::mpsc::unbounded_channel::<ShellMessage>();
    tokio::spawn(async move {
        while let Some(msg) = shell_rx.recv().await {
            match msg.encode() {
                Ok(payload) => {
                    if let Err(e) = shell_writer.send(&payload).await {
                        tracing::error!("[shell] send error: {} — stopping", e);
                        break;
                    }
                }
                Err(e) => tracing::warn!("[shell] encode error: {}", e),
            }
        }
        tracing::info!("[shell] send task exited (window closed or channel lost)");
    });

    // 接收任务：ShellStdout → 终端 feed（egui Context 跨线程安全）。
    // M8-T021 P2: 保存 JoinHandle 供会话尾部 select（连接断开 → 循环 break →
    // 任务结束 → 会话退出）。
    let term_recv = terminal.clone();
    let ctx_recv = ctx.clone();
    let recv_handle = tokio::spawn(async move {
        loop {
            match shell_reader.receive().await {
                Ok(bytes) => match ShellMessage::decode(&bytes) {
                    Ok(ShellMessage::ShellStdout(data)) => {
                        term_recv.lock().unwrap().feed(&data);
                        ctx_recv.request_repaint();
                    }
                    _ => {}
                },
                Err(e) => {
                    tracing::info!("[shell] receive loop ended: {}", e);
                    ctx_recv.request_repaint();
                    break;
                }
            }
        }
    });

    // 通知 UI 打开独立 Shell 窗口（多会话：每窗口独立）。
    // M8-T021 P1: 携带 session_id + 会话侧已 feed 的终端实例（P1-5 修复断链——
    // 窗口直接渲染此实例，不再另建空终端）+ close_tx（去重丢弃/关窗 → drop →
    // 会话退出，P2 消费）。
    let (close_tx, mut close_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    if let Ok(mut w) = add_shell_window_signal().lock() {
        w.push(ShellWindowSignal {
            session_id,
            addr: addr.clone(),
            terminal: terminal.clone(),
            shell_tx,
            close_tx,
        });
    }

    // M8-T021 P2 (T021-03-A): 会话退出通道——窗口关闭（close_tx sender drop →
    // close_rx 返回 None）或连接断开（接收任务结束）任一触发即返回，不再
    // pending 挂起；返回后 runtime drop → 任务 abort → 线程回收，杜绝泄漏。
    tokio::select! {
        _ = close_rx.recv() => {
            tracing::info!("[shell] session ended: window closed");
        }
        _ = recv_handle => {
            tracing::info!("[shell] session ended: connection closed");
        }
    }
    // M8-T021 P2 (T021-02): 清理本会话的键控状态条目（窗口关闭先于会话退出
    // 亦无残留——无论退出顺序如何，最终清空）。
    cleanup_session_state(session_id);
}

// ════════════════════════════════════════════════════════════════
// M13-T006: 文件会话引擎（客户端/服务端共用）
// ════════════════════════════════════════════════════════════════

/// 把 core 侧 [`TransferStatus`] 映射为 UI 任务状态。
fn map_file_status(st: kirin_desk_core::connection::file_transfer::TransferStatus) -> FileTaskStatus {
    use kirin_desk_core::connection::file_transfer::TransferStatus as S;
    match st {
        S::Queued => FileTaskStatus::Queued,
        S::Sending => FileTaskStatus::Sending,
        S::Paused => FileTaskStatus::Paused,
        S::Completed => FileTaskStatus::Completed,
        S::Failed(e) => FileTaskStatus::Failed(e),
        S::Cancelled => FileTaskStatus::Cancelled,
    }
}

/// 构造 FileTransfer 帧 EncodedPacket（64 KiB 大帧，走 `send_big_packet`）。
fn file_packet(frame: &FileTransferFrame) -> EncodedPacket {
    EncodedPacket {
        ts: Timestamp::now(),
        kind: PacketKind::FileTransfer,
        data: frame.encode().unwrap_or_default(),
        is_key: false,
    }
}

/// M13-T006: 会话内文件任务引擎。
///
/// 职责：
/// - 发送：FIFO 调度（并发 ≤3）→ Offer → 滑窗 64 块 → Ack/Nack → Finish →
///   FinishAck；块超时重传；空闲死链判定；断点续传（双方进度协商）。
/// - 接收：Offer 校验（路径消毒/大小限制）→ 排队 → Accept → 分片落 `.part` →
///   整体 SHA-256 校验 → 原子 rename；取消回滚删 `.part`。
/// - 状态：UI 面板同步（共享 [`FilePanelState`]）+ 断点持久化
///   （`transfers_{role}.json`，仅元数据）。
///
/// 帧收发全部经共享 `Arc<Mutex<SecureChannelSender>>`（单 writer 语义，
/// 与 input/clipboard/视频发送任务互斥，保证帧边界）。
struct FileSession {
    sender: Arc<tokio::sync::Mutex<SecureChannelSender>>,
    panel: &'static Mutex<FilePanelState>,
    salt: String,
    store_path: PathBuf,
    download_dir: PathBuf,
    max_file_size: u64,
    /// 接收完成通知（服务端 → 主窗口弹窗队列；客户端为 None）。
    notices: Option<&'static Mutex<std::collections::VecDeque<String>>>,
    /// 发送调度（FIFO ≤3）。
    send_sched: TransferScheduler<u64>,
    /// 活跃发送器。
    senders: HashMap<u64, SlideWindowSender>,
    /// 发送源文件句柄（transfer_id → File）。
    src_files: HashMap<u64, std::fs::File>,
    /// 接收调度（FIFO ≤3，Offer 排队延迟 Accept）。
    recv_sched: TransferScheduler<u64>,
    /// 等待 Accept 的 Offer（transfer_id → (meta, sha256)）。
    pending_offers: HashMap<u64, (FileOfferMeta, [u8; 32])>,
    /// 活跃接收器。
    receivers: HashMap<u64, ChunkReceiver>,
}

impl FileSession {
    fn new(
        sender: Arc<tokio::sync::Mutex<SecureChannelSender>>,
        panel: &'static Mutex<FilePanelState>,
        salt: String,
        store_path: PathBuf,
        download_dir: PathBuf,
        max_file_size: u64,
        notices: Option<&'static Mutex<std::collections::VecDeque<String>>>,
    ) -> Self {
        Self {
            sender,
            panel,
            salt,
            store_path,
            download_dir,
            max_file_size,
            notices,
            send_sched: TransferScheduler::new(),
            senders: HashMap::new(),
            src_files: HashMap::new(),
            recv_sched: TransferScheduler::new(),
            pending_offers: HashMap::new(),
            receivers: HashMap::new(),
        }
    }

    /// 断点存储读改写（store 很小，每次变更全量读-改-写）。
    fn save_store(&self, f: impl FnOnce(&mut TransferStore)) {
        let mut store = TransferStore::load_from(&self.store_path).unwrap_or_default();
        f(&mut store);
        if let Err(e) = store.save_to(&self.store_path) {
            tracing::warn!("transfers.json save failed: {e}");
        }
    }

    /// 发送一帧（共享 sender，锁内一次 write；64 KiB 大帧走 `send_big_packet`）。
    async fn send_frame(&self, frame: FileTransferFrame) -> bool {
        let pkt = file_packet(&frame);
        match self.sender.lock().await.send_big_packet(&pkt).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("File frame send failed: {}", e);
                false
            }
        }
    }

    /// M8-T019 (SRV-PRIV-002): 发送隐私模式响应（无头 Server 模式 ack；
    /// 复用控制通道 `ChannelTag::Control`，与 GUI 服务端一致）。
    pub(crate) async fn send_privacy_ack(
        &self,
        ok: bool,
        active_level: Option<PrivacyLevel>,
    ) -> bool {
        let msg = ControlMessage::PrivacyModeAck { ok, active_level };
        let data = match bincode::serialize(&msg) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("privacy ack serialize failed: {e}");
                return false;
            }
        };
        let pkt = EncodedPacket {
            ts: Timestamp::now(),
            kind: PacketKind::Control,
            data,
            is_key: false,
        };
        match self.sender.lock().await.send_packets(&[pkt]).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("privacy ack send failed: {e}");
                false
            }
        }
    }

    /// 同步发送侧任务到面板。
    fn panel_sync_send(&self, tid: u64) {
        let Some(s) = self.senders.get(&tid) else { return };
        let (done, total) = s.progress();
        let mut task = FileTask::queued(tid, s.name.clone(), total, FileDirection::Upload);
        task.done = done;
        task.status = map_file_status(s.status());
        task.speed = s.speed();
        if let Ok(mut p) = self.panel.lock() {
            p.upsert(task);
        }
    }

    /// 同步接收侧任务到面板。
    fn panel_sync_recv(&self, tid: u64) {
        let Some(r) = self.receivers.get(&tid) else { return };
        let (done, total) = r.progress();
        let mut task = FileTask::queued(tid, r.name.clone(), total, FileDirection::Download);
        task.done = done;
        task.status = FileTaskStatus::Sending;
        if let Some(p) = r.final_path() {
            task.path = Some(p.to_path_buf());
        }
        if let Ok(mut p) = self.panel.lock() {
            p.upsert(task);
        }
    }

    /// 移除任务并释放资源（回收调度槽位）。
    fn cleanup_task(&mut self, tid: u64) {
        self.senders.remove(&tid);
        self.src_files.remove(&tid);
        self.pending_offers.remove(&tid);
        self.receivers.remove(&tid);
    }

    /// UI 命令处理。
    async fn handle_command(&mut self, cmd: FileCommand) {
        match cmd {
            FileCommand::SendFile { path } => self.cmd_send_file(path).await,
            FileCommand::Cancel { transfer_id } => self.cmd_cancel(transfer_id).await,
            FileCommand::Pause { transfer_id } => {
                if let Some(s) = self.senders.get_mut(&transfer_id) {
                    s.pause();
                    self.panel_sync_send(transfer_id);
                }
            }
            FileCommand::Resume { transfer_id } => {
                if let Some(s) = self.senders.get_mut(&transfer_id) {
                    s.resume();
                    self.panel_sync_send(transfer_id);
                }
            }
        }
    }

    /// 发送本地文件（拖拽/选择器入口）：校验 → 哈希 → 断点检查 → 入队。
    async fn cmd_send_file(&mut self, path: PathBuf) {
        let name = match path.file_name().map(|s| s.to_string_lossy().to_string()) {
            Some(n) => n,
            None => {
                tracing::warn!("send file: no filename for {}", path.display());
                return;
            }
        };
        let name = match sanitize_filename(&name) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("send file: {e}");
                if let Ok(mut p) = self.panel.lock() {
                    p.upsert(FileTask {
                        transfer_id: 0,
                        name: name.clone(),
                        size: 0,
                        direction: FileDirection::Upload,
                        done: 0,
                        status: FileTaskStatus::Failed(format!("本地文件名不安全: {e}")),
                        speed: 0.0,
                        path: None,
                    });
                }
                return;
            }
        };
        let meta = match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => m,
            Ok(_) => {
                tracing::warn!("send file: {} is not a regular file", path.display());
                return;
            }
            Err(e) => {
                tracing::warn!("send file: metadata {}: {e}", path.display());
                return;
            }
        };
        let size = meta.len();
        if size > self.max_file_size {
            if let Ok(mut p) = self.panel.lock() {
                p.upsert(FileTask {
                    transfer_id: 0,
                    name,
                    size,
                    direction: FileDirection::Upload,
                    done: 0,
                    status: FileTaskStatus::Failed(format!("超过大小限制 ({size} 字节)")),
                    speed: 0.0,
                    path: None,
                });
            }
            return;
        }
        // 整文件 SHA-256（同步计算；1 GB 约 1~2 s，可接受）。
        let sha256 = match sha256_file(&path) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("send file: sha256 {}: {e}", path.display());
                return;
            }
        };
        let tid = derive_transfer_id(&name, size, &self.salt);
        // 断点：本端上次发送进度（transfers_client/server.json）。
        let resume = match TransferStore::load_from(&self.store_path) {
            Ok(st) => st
                .find(tid)
                .filter(|t| t.direction == "send")
                .map(|t| t.next_seq)
                .unwrap_or(0),
            Err(_) => 0,
        };
        let mut s = match SlideWindowSender::new(tid, name.clone(), size, sha256) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("send file: {e}");
                return;
            }
        };
        s.local_resume_seq = resume;
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("send file: open {}: {e}", path.display());
                return;
            }
        };
        self.save_store(|st| {
            st.upsert(StoredTransfer {
                transfer_id: tid,
                name,
                size,
                direction: "send".into(),
                next_seq: resume,
                sha256: Some(sha256),
                part_path: None,
            });
        });
        self.senders.insert(tid, s);
        self.src_files.insert(tid, file);
        self.send_sched.push(tid);
        self.schedule_next_send().await;
    }

    /// 发送调度：活跃 <3 时出队并发 Offer。
    async fn schedule_next_send(&mut self) {
        while let Some(tid) = self.send_sched.pop_ready() {
            if !self.senders.contains_key(&tid) {
                self.send_sched.finish_one();
                continue;
            }
            if !self.send_offer(tid).await {
                self.send_sched.finish_one();
            }
        }
    }

    /// 发 Offer（声明白名、大小、总块数、整文件哈希）。
    async fn send_offer(&mut self, tid: u64) -> bool {
        let Some(s) = self.senders.get(&tid) else { return false };
        let meta = FileOfferMeta { name: s.name.clone(), size: s.size };
        let frame = FileTransferFrame::offer(tid, &meta, s.total_blocks(), s.sha256);
        if !self.send_frame(frame).await {
            return false;
        }
        if let Ok(mut p) = self.panel.lock() {
            p.upsert(FileTask {
                transfer_id: tid,
                name: meta.name,
                size: meta.size,
                direction: FileDirection::Upload,
                done: 0,
                status: FileTaskStatus::WaitingAccept,
                speed: 0.0,
                path: None,
            });
        }
        true
    }

    /// 填满发送窗口（读源文件 → Data 帧 → mark_sent）。
    async fn fill_window(&mut self, tid: u64) {
        loop {
            let Some(seq) = self.senders.get(&tid).and_then(|s| s.next_unsent_seq()) else {
                break;
            };
            let size = self.senders.get(&tid).map(|s| s.size).unwrap_or(0);
            let total_blocks = self.senders.get(&tid).map(|s| s.total_blocks()).unwrap_or(0);
            let read = {
                let Some(file) = self.src_files.get_mut(&tid) else { break };
                use std::io::{Read, Seek, SeekFrom};
                let len = block_len(seq, size);
                if let Err(e) = file.seek(SeekFrom::Start(block_offset(seq))) {
                    tracing::error!("file seek: {e}");
                    break;
                }
                let mut buf = vec![0u8; len];
                if let Err(e) = file.read_exact(&mut buf) {
                    tracing::error!("file read: {e}");
                    break;
                }
                buf
            };
            let frame = FileTransferFrame {
                transfer_id: tid,
                op: FileOp::Data,
                seq,
                total_blocks,
                data: read,
                sha256: [0u8; 32],
            };
            if !self.send_frame(frame).await {
                break;
            }
            if let Some(s) = self.senders.get_mut(&tid) {
                s.mark_sent(seq);
            }
        }
        self.panel_sync_send(tid);
    }

    /// 远端 Accept：续传协商（双方进度取最大）→ 开始发块。
    async fn on_accept(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let (all_acked, sha, total_blocks) = {
            let Some(sender) = self.senders.get_mut(&tid) else { return };
            let remote_next = bincode::deserialize::<u32>(&frame.data).unwrap_or(0);
            sender.on_accept(remote_next);
            (sender.all_acked(), sender.sha256, sender.total_blocks())
        };
        self.panel_sync_send(tid);
        if all_acked {
            // 空文件 / 断点已全收：无需发块，直接 Finish。
            let fin = FileTransferFrame {
                transfer_id: tid,
                op: FileOp::Finish,
                seq: 0,
                total_blocks,
                data: Vec::new(),
                sha256: sha,
            };
            let _ = self.send_frame(fin).await;
            return;
        }
        self.fill_window(tid).await;
    }

    /// 远端 Ack（累积确认）→ 全部确认后发 Finish。
    async fn on_ack(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let (finish_ready, sha, total_blocks) = {
            let Some(sender) = self.senders.get_mut(&tid) else { return };
            let was_complete = sender.is_complete();
            sender.on_ack(frame.seq);
            (sender.all_acked() && !was_complete, sender.sha256, sender.total_blocks())
        };
        self.panel_sync_send(tid);
        if finish_ready {
            // 全部块确认 → Finish（整文件哈希回执）。
            let fin = FileTransferFrame {
                transfer_id: tid,
                op: FileOp::Finish,
                seq: 0,
                total_blocks,
                data: Vec::new(),
                sha256: sha,
            };
            let _ = self.send_frame(fin).await;
        }
        // 窗口腾位 → 继续发。
        self.fill_window(tid).await;
    }

    /// 远端 Nack → 立即重发该块。
    async fn on_nack(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        if let Some(s) = self.senders.get_mut(&tid) {
            s.on_nack(frame.seq);
        }
        self.fill_window(tid).await;
    }

    /// 远端 FinishAck：传输完成。
    async fn on_finish_ack(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        if let Some(s) = self.senders.get(&tid) {
            if let Ok(mut p) = self.panel.lock() {
                p.upsert(FileTask {
                    transfer_id: tid,
                    name: s.name.clone(),
                    size: s.size,
                    direction: FileDirection::Upload,
                    done: s.size,
                    status: FileTaskStatus::Completed,
                    speed: s.speed(),
                    path: None,
                });
            }
        }
        self.save_store(|st| st.remove(tid));
        self.send_sched.finish_one();
        self.cleanup_task(tid);
        self.schedule_next_send().await;
    }

    /// 远端 Reject：发送失败。
    async fn on_reject(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let reason = String::from_utf8_lossy(&frame.data).to_string();
        if let Some(s) = self.senders.get(&tid) {
            if let Ok(mut p) = self.panel.lock() {
                p.upsert(FileTask {
                    transfer_id: tid,
                    name: s.name.clone(),
                    size: s.size,
                    direction: FileDirection::Upload,
                    done: 0,
                    status: FileTaskStatus::Failed(reason.clone()),
                    speed: 0.0,
                    path: None,
                });
            }
        }
        self.save_store(|st| st.remove(tid));
        self.send_sched.finish_one();
        self.cleanup_task(tid);
        self.schedule_next_send().await;
    }

    /// 远端 Offer：校验 → 入队 → 活跃 <3 时 Accept（携带续传进度）。
    async fn on_offer(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let meta = match bincode::deserialize::<FileOfferMeta>(&frame.data) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("file offer deserialize failed: {e}");
                let _ = self.send_frame(FileTransferFrame::simple(tid, FileOp::Reject, 0)).await;
                return;
            }
        };
        // FT-SEC-001/002：路径消毒 + 大小限制 + 块数一致性。
        let checked = match ChunkReceiver::validate_offer(&meta, self.max_file_size) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("file offer rejected: {e}");
                let mut rej = FileTransferFrame::simple(tid, FileOp::Reject, 0);
                rej.data = e.to_string().into_bytes();
                let _ = self.send_frame(rej).await;
                return;
            }
        };
        if let Err(e) = validate_block_count(checked.size, frame.total_blocks) {
            tracing::warn!("file offer rejected: {e}");
            let mut rej = FileTransferFrame::simple(tid, FileOp::Reject, 0);
            rej.data = e.to_string().into_bytes();
            let _ = self.send_frame(rej).await;
            return;
        }
        // FT-SEC-004：transfer_id 去重（正在传输的拒绝）。
        if self.receivers.contains_key(&tid) || self.pending_offers.contains_key(&tid) {
            let mut rej = FileTransferFrame::simple(tid, FileOp::Reject, 0);
            rej.data = b"duplicate transfer_id".to_vec();
            let _ = self.send_frame(rej).await;
            return;
        }
        self.pending_offers.insert(tid, (checked, frame.sha256));
        self.recv_sched.push(tid);
        self.maybe_start_recv().await;
    }

    /// 接收调度：活跃 <3 → Accept（data = 续传进度）→ 开始收。
    async fn maybe_start_recv(&mut self) {
        while let Some(tid) = self.recv_sched.pop_ready() {
            let Some((meta, sha256)) = self.pending_offers.remove(&tid) else {
                self.recv_sched.finish_one();
                continue;
            };
            // 断点：上次接收进度（.part 保留；孤儿记录清理）。
            let mut resume_from = 0u32;
            {
                let mut store = TransferStore::load_from(&self.store_path).unwrap_or_default();
                store.prune_missing();
                if let Some(t) = store.find(tid).cloned() {
                    if t.direction == "recv" {
                        resume_from = t.next_seq;
                    }
                }
                if let Err(e) = store.save_to(&self.store_path) {
                    tracing::warn!("transfers.json save failed: {e}");
                }
            }
            let mut recv = ChunkReceiver::new(tid);
            if let Err(e) = recv.begin(&meta, &self.download_dir, sha256, resume_from) {
                tracing::warn!("file receive begin failed: {e}");
                let mut rej = FileTransferFrame::simple(tid, FileOp::Reject, 0);
                rej.data = e.to_string().into_bytes();
                let _ = self.send_frame(rej).await;
                self.recv_sched.finish_one();
                continue;
            }
            self.save_store(|st| {
                st.upsert(StoredTransfer {
                    transfer_id: tid,
                    name: recv.name.clone(),
                    size: recv.size,
                    direction: "recv".into(),
                    next_seq: recv.next_seq(),
                    sha256: Some(recv.sha256),
                    part_path: Some(recv.part_path().to_string_lossy().to_string()),
                });
            });
            self.receivers.insert(tid, recv);
            // Accept 携带本端续传进度（u32）。
            let mut acc = FileTransferFrame::simple(tid, FileOp::Accept, 0);
            acc.data = bincode::serialize(&resume_from).unwrap_or_default();
            acc.total_blocks = self.receivers.get(&tid).map(|r| r.total_blocks).unwrap_or(0);
            if !self.send_frame(acc).await {
                tracing::error!("file accept send failed");
                self.recv_sched.finish_one();
                self.cleanup_task(tid);
                continue;
            }
            self.panel_sync_recv(tid);
        }
    }

    /// 远端 Data：落 `.part`（按序，重复块忽略）→ Ack 累积。
    async fn on_data(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let outcome = {
            let Some(recv) = self.receivers.get_mut(&tid) else {
                return; // 未知/已清理任务：忽略。
            };
            match recv.on_data(frame.seq, &frame.data) {
                Ok(_dup) => Ok(recv.next_seq()),
                Err(e) => Err(e),
            }
        };
        match outcome {
            Ok(next_seq) => {
                // 累积确认：回 Ack(已连续收至 last)。
                let ack = FileTransferFrame::simple(tid, FileOp::Ack, next_seq.saturating_sub(1));
                let _ = self.send_frame(ack).await;
                self.panel_sync_recv(tid);
            }
            Err(e) => {
                // 顺序破坏/块长异常 → 终止该传输（防御）。
                tracing::warn!("file receive error: {e}");
                let _ = self.send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0)).await;
                if let Some(r) = self.receivers.get_mut(&tid) {
                    r.cancel();
                }
                self.cleanup_task(tid);
                self.recv_sched.finish_one();
                self.maybe_start_recv().await;
            }
        }
    }

    /// 远端 Finish：整体 SHA-256 校验 → 原子 rename → FinishAck。
    async fn on_finish(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        let outcome = {
            let Some(recv) = self.receivers.get_mut(&tid) else {
                let _ = self.send_frame(FileTransferFrame::simple(tid, FileOp::FinishAck, 0)).await;
                return;
            };
            let result = recv.verify().map(|()| recv.commit());
            let (done, total) = recv.progress();
            let name = recv.name.clone();
            (result, done, total, name)
        };
        match outcome {
            (Ok(Ok(final_path)), done, total, name) => {
                tracing::info!("file received OK: {}", final_path.display());
                let mut fa = FileTransferFrame::simple(tid, FileOp::FinishAck, 0);
                fa.data = final_path.to_string_lossy().to_string().into_bytes();
                let _ = self.send_frame(fa).await;
                let path = final_path.clone();
                if let Ok(mut p) = self.panel.lock() {
                    p.upsert(FileTask {
                        transfer_id: tid,
                        name,
                        size: total,
                        direction: FileDirection::Download,
                        done,
                        status: FileTaskStatus::Completed,
                        speed: 0.0,
                        path: Some(path.clone()),
                    });
                }
                if let Some(ntx) = &self.notices {
                    if let Ok(mut q) = ntx.lock() {
                        q.push_back(format!("已接收文件：{}", path.display()));
                    }
                }
                self.save_store(|st| st.remove(tid));
                self.cleanup_task(tid);
                self.recv_sched.finish_one();
                self.maybe_start_recv().await;
            }
            (_, _, total, name) => {
                // 校验失败（FT-SEC-003）：Cancel + 删除 .part。
                tracing::warn!("file checksum FAILED for {tid}");
                let _ = self.send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0)).await;
                if let Some(r) = self.receivers.get_mut(&tid) {
                    r.cancel();
                }
                if let Ok(mut p) = self.panel.lock() {
                    p.upsert(FileTask {
                        transfer_id: tid,
                        name,
                        size: total,
                        direction: FileDirection::Download,
                        done: 0,
                        status: FileTaskStatus::Failed("SHA-256 校验失败".into()),
                        speed: 0.0,
                        path: None,
                    });
                }
                self.save_store(|st| st.remove(tid));
                self.cleanup_task(tid);
                self.recv_sched.finish_one();
                self.maybe_start_recv().await;
            }
        }
    }

    /// 远端 Cancel：取消对应任务（发送 → 失败；接收 → 回滚删 .part）。
    async fn on_cancel(&mut self, frame: FileTransferFrame) {
        let tid = frame.transfer_id;
        if self.senders.contains_key(&tid) {
            if let Some(s) = self.senders.get(&tid) {
                if let Ok(mut p) = self.panel.lock() {
                    p.upsert(FileTask {
                        transfer_id: tid,
                        name: s.name.clone(),
                        size: s.size,
                        direction: FileDirection::Upload,
                        done: 0,
                        status: FileTaskStatus::Cancelled,
                        speed: 0.0,
                        path: None,
                    });
                }
            }
            self.save_store(|st| st.remove(tid));
            self.send_sched.finish_one();
            self.cleanup_task(tid);
            self.schedule_next_send().await;
        } else if self.receivers.contains_key(&tid) || self.pending_offers.contains_key(&tid) {
            if let Some(r) = self.receivers.get_mut(&tid) {
                r.cancel();
            }
            if let Ok(mut p) = self.panel.lock() {
                p.upsert(FileTask {
                    transfer_id: tid,
                    name: self.pending_offers.get(&tid).map(|(m, _)| m.name.clone()).unwrap_or_default(),
                    size: 0,
                    direction: FileDirection::Download,
                    done: 0,
                    status: FileTaskStatus::Cancelled,
                    speed: 0.0,
                    path: None,
                });
            }
            self.save_store(|st| st.remove(tid));
            self.cleanup_task(tid);
            self.recv_sched.finish_one();
            self.maybe_start_recv().await;
        }
    }

    /// 远端帧入口。
    async fn handle_frame(&mut self, frame: FileTransferFrame) {
        match frame.op {
            FileOp::Offer => self.on_offer(frame).await,
            FileOp::Accept => self.on_accept(frame).await,
            FileOp::Reject => self.on_reject(frame).await,
            FileOp::Data => self.on_data(frame).await,
            FileOp::Ack => self.on_ack(frame).await,
            FileOp::Nack => self.on_nack(frame).await,
            FileOp::Finish => self.on_finish(frame).await,
            FileOp::FinishAck => self.on_finish_ack(frame).await,
            FileOp::Cancel => self.on_cancel(frame).await,
            // Pause/Resume 仅本端生效（暂停发送），对端无需处理。
            FileOp::Pause | FileOp::Resume => {}
        }
    }

    /// 周期 tick：块超时重传 + 空闲死链判定 + 补窗口。
    async fn on_tick(&mut self) {
        use kirin_desk_core::connection::file_transfer::TransferStatus as CoreStatus;
        let now = std::time::Instant::now();
        let mut retransmit = Vec::new();
        let mut dead = Vec::new();
        for (tid, s) in self.senders.iter_mut() {
            if s.is_cancelled() || s.status() != CoreStatus::Sending {
                continue;
            }
            retransmit.extend(s.retransmit_due(now).into_iter().map(|seq| (*tid, seq)));
            if s.idle_timeout(now) {
                dead.push(*tid);
            }
        }
        for (tid, _seq) in retransmit {
            self.fill_window(tid).await;
        }
        for tid in dead {
            tracing::warn!("file transfer {tid} idle timeout — cancelling");
            let _ = self.send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0)).await;
            if let Some(s) = self.senders.get(&tid) {
                if let Ok(mut p) = self.panel.lock() {
                    p.upsert(FileTask {
                        transfer_id: tid,
                        name: s.name.clone(),
                        size: s.size,
                        direction: FileDirection::Upload,
                        done: s.acked_bytes(),
                        status: FileTaskStatus::Failed("连接空闲超时".into()),
                        speed: 0.0,
                        path: None,
                    });
                }
            }
            self.save_store(|st| st.remove(tid));
            self.send_sched.finish_one();
            self.cleanup_task(tid);
        }
        // 补窗口（Ack 推进后空出的槽位）。
        let tids: Vec<u64> = self.senders.keys().copied().collect();
        for tid in tids {
            self.fill_window(tid).await;
        }
        // 进度断点持久化（1s 粒度，避免每块全量写 json）。
        let recv_ids: Vec<u64> = self.receivers.keys().copied().collect();
        let send_ids: Vec<u64> = self.senders.keys().copied().collect();
        if !recv_ids.is_empty() || !send_ids.is_empty() {
            self.save_store(|st| {
                for tid in recv_ids {
                    if let Some(r) = self.receivers.get(&tid) {
                        if let Some(t) = st.find_mut(tid) {
                            t.next_seq = r.next_seq();
                        }
                    }
                }
                for tid in send_ids {
                    if let Some(s) = self.senders.get(&tid) {
                        if let Some(t) = st.find_mut(tid) {
                            t.next_seq = s.resume_seq();
                        }
                    }
                }
            });
        }
    }

    /// 本地取消命令：发 Cancel 帧 + 回滚。
    async fn cmd_cancel(&mut self, tid: u64) {
        if self.senders.contains_key(&tid) {
            let _ = self.send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0)).await;
            if let Ok(mut p) = self.panel.lock() {
                if let Some(s) = self.senders.get(&tid) {
                    p.upsert(FileTask {
                        transfer_id: tid,
                        name: s.name.clone(),
                        size: s.size,
                        direction: FileDirection::Upload,
                        done: s.acked_bytes(),
                        status: FileTaskStatus::Cancelled,
                        speed: 0.0,
                        path: None,
                    });
                }
            }
            self.save_store(|st| st.remove(tid));
            self.send_sched.finish_one();
            self.cleanup_task(tid);
            self.schedule_next_send().await;
        } else if self.receivers.contains_key(&tid) || self.pending_offers.contains_key(&tid) {
            let _ = self.send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0)).await;
            if let Some(r) = self.receivers.get_mut(&tid) {
                r.cancel();
            }
            if let Ok(mut p) = self.panel.lock() {
                p.upsert(FileTask {
                    transfer_id: tid,
                    name: self.pending_offers.get(&tid).map(|(m, _)| m.name.clone()).unwrap_or_default(),
                    size: 0,
                    direction: FileDirection::Download,
                    done: 0,
                    status: FileTaskStatus::Cancelled,
                    speed: 0.0,
                    path: None,
                });
            }
            self.save_store(|st| st.remove(tid));
            self.cleanup_task(tid);
            self.recv_sched.finish_one();
            self.maybe_start_recv().await;
        }
    }
}

/// M10-T001/T003: 共享客户端会话启动器（IP 模式 + Domain 模式共用）。
///
/// 流程: TCP 连接 → 完整握手（`ClientTrust` 信任策略：known_hosts 指纹 / DNS TXT
/// 公钥绑定（CLI-HSK-SEC-001）或首次指纹确认（CLI-KH-001））→ 拆分读写半通道 →
/// 输入发送/视频接收任务 → 通知 UI 开窗口。握手成功后自动保存设备到
/// `devices.json`（M10-T003）并记录 known_hosts（CLI-KH-002），置位
/// `devices_dirty` 让 Devices 页即时刷新。
async fn run_client_session(
    addr: String,
    server_id: String,
    trust: ClientTrust,
    challenge: String,
    domain: String,
    device_type: &str,
) {
    tracing::info!("TCP connecting to {} ...", addr);
    if let Ok(mut s) = connection_status().lock() {
        *s = format!("Connecting: {} ...", addr);
    }
    let Ok(stream) = tokio::net::TcpStream::connect(&addr).await else {
        tracing::error!("TCP connect to {} FAILED", addr);
        if let Ok(mut s) = connection_status().lock() {
            *s = format!("TCP connect FAILED: {}", addr);
        }
        return;
    };
    tracing::info!("TCP connected to {}", addr);
    run_client_session_with_stream(stream, addr, server_id, trust, challenge, domain, device_type)
        .await;
}

/// M8-T026-P2 (ID-021)：会话入口的**已连接流**变体 —— 供设备 ID 模式
/// （`connect_stream` 已建立直连/中继流）与既有 connect 路径共用同一套
/// 握手 + 媒体会话逻辑（ID-013 访问控制零降级）。
async fn run_client_session_with_stream(
    stream: tokio::net::TcpStream,
    addr_label: String,
    server_id: String,
    trust: ClientTrust,
    challenge: String,
    domain: String,
    device_type: &str,
) {
    use kirin_desk_core::crypto::handshake::client_handshake_with_confirm;
    // M8-T021 P1: 会话标识（窗口键控状态 key；窗口 id 与之解耦）。
    let session_id = next_session_id();

    let Some(client_id) = global_identity().get() else {
        tracing::error!("No device identity loaded, can't handshake");
        return;
    };
    let my_pub = client_id.public_key_base64();
    tracing::info!("Client identity: pubkey={}...", &my_pub[..16]);

    // 握手阶段状态（Domain 模式将用 TXT 公钥强制验证服务端身份）。
    if let Ok(mut s) = connection_status().lock() {
        *s = format!("Handshaking: {}@{} ...", server_id, addr_label);
    }
    let server_name = if server_id.is_empty() {
        "gui-server"
    } else {
        &server_id
    };
    let confirmed_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let ch = match trust.clone() {
        // M15 (CLI-HSK-SEC-001): 带外可信公钥 → 强制比对，不等即拒绝。
        ClientTrust::Verified(expected) => {
            tracing::info!(
                "Attempting full handshake with server '{}' (pubkey verify: {}, challenge: {})...",
                server_name,
                "strict",
                if challenge.is_empty() { "none" } else { "set" }
            );
            client_handshake_with_confirm(
                stream,
                client_id,
                &server_id,
                "gui-client.local",
                "desktop",
                server_name,
                Some(expected),
                None,
                &challenge,
            )
            .await
        }
        // M15 (CLI-KH-001/003): 无带外公钥 → 确认回调（known_hosts 自动放行 /
        // 首次指纹确认框）。
        ClientTrust::Confirm => {
            tracing::info!(
                "Attempting full handshake with server '{}' (pubkey verify: known_hosts/confirm, challenge: {})...",
                server_name,
                if challenge.is_empty() { "none" } else { "set" }
            );
            let device_id_cb = server_id.clone();
            let confirmed_key_cb = confirmed_key.clone();
            let key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>> =
                Some(Box::new(move |key: &str| {
                    let ok = known_hosts_or_confirm(&device_id_cb, key);
                    if ok {
                        if let Ok(mut ck) = confirmed_key_cb.lock() {
                            *ck = Some(key.to_string());
                        }
                    }
                    ok
                }));
            client_handshake_with_confirm(
                stream,
                client_id,
                &server_id,
                "gui-client.local",
                "desktop",
                server_name,
                None,
                key_confirm,
                &challenge,
            )
            .await
        }
    };
    let ch = match ch {
        Ok(ch) => ch,
        Err(e) => {
            tracing::error!("Handshake FAILED: {}", e);
            if let Ok(mut s) = connection_status().lock() {
                *s = format!("Handshake FAILED: {}", e);
                // M8-T017-P2 (CLI-TMP-003): 携带挑战码时追加引导提示（防枚举，纯客户端文案）。
                if let Some(h) = crate::policy::connect_failure_challenge_hint(&challenge) {
                    s.push('\n');
                    s.push_str(&h);
                }
            }
            return;
        }
    };
    tracing::info!(
        "Handshake SUCCESS! Secured channel established to '{}'",
        server_id
    );
    if let Ok(mut s) = connection_status().lock() {
        // M8-T025 P5-4 (B5)：连接状态显示传输模式（GUI 会话走 TCP/SecureChannel 路径；
        // QUIC 主路径经 media 会话接入后由 stats.transport_mode 驱动同一状态位）。
        *s = format!("Connected to {}@{} (transport: TCP)", server_id, addr_label);
    }

    // M15 (CLI-KH-002): 连接成功 → 记录 known_hosts。
    let trusted_key = match &trust {
        ClientTrust::Verified(k) => Some(k.clone()),
        ClientTrust::Confirm => confirmed_key.lock().ok().and_then(|k| k.clone()),
    };
    // M10-T003: 连接成功后自动保存设备（按 id 去重 + last_seen 刷新由 DeviceStore 维护）。
    if let Some(key) = &trusted_key {
        record_known_host(&server_id, key);
        save_device_to_store(&addr_label, &server_id, key, device_type, &domain);
    }

    // M9: 拆分通道为读写半通道——视频接收（读半）与输入发送（写半）
    // 各自单任务独占、无锁并发（TCP 双工 + 每消息随机 nonce）。
    // M13-T006: 写半进一步由多个任务共享（input/clipboard/文件），
    // 用 Arc<tokio::sync::Mutex<SecureChannelSender>> 保证帧边界。
    let peer_id = ch.peer_id.clone();
    let (reader, writer) = ch.into_split();
    let sender_shared: Arc<tokio::sync::Mutex<SecureChannelSender>> =
        Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(writer)));
    let mut video_receiver = SecureChannelReceiver::new(reader);

    // M9: 输入发送任务（UI 线程事件批次 → 加密可靠流 InputEcho）。
    // 窗口关闭 → UI 侧 Sender drop → recv 返回 None → 任务退出。
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<WireInputEvent>>();
    // M13-T003: 剪贴板推送通道（轮询任务产出的 EncodedPacket 批）。
    let (clip_tx, mut clip_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<EncodedPacket>>();
    // M8-T018: 显示器控制消息通道（下拉切换 / 列表刷新 → `ChannelTag::Control`）。
    let (control_tx, mut control_rx) =
        tokio::sync::mpsc::unbounded_channel::<ControlMessage>();
    // M13-T006: 文件命令（UI → 文件会话）与帧转发（接收循环 → 文件会话）。
    let (file_cmd_tx, mut file_cmd_rx) =
        tokio::sync::mpsc::unbounded_channel::<FileCommand>();
    let (file_frame_tx, mut file_frame_rx) =
        tokio::sync::mpsc::unbounded_channel::<FileTransferFrame>();
    let sender_input = sender_shared.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                batch = input_rx.recv() => {
                    let Some(batch) = batch else {
                        tracing::info!("Input send task exited (window closed or channel lost)");
                        break;
                    };
                    let pkts: Vec<EncodedPacket> = batch
                        .into_iter()
                        .map(|ev| {
                            let data = match bincode::serialize(&ev) {
                                Ok(d) => d,
                                Err(e) => {
                                    tracing::warn!("input serialize failed: {e}");
                                    Vec::new()
                                }
                            };
                            EncodedPacket {
                                ts: Timestamp::now(),
                                kind: PacketKind::InputEcho,
                                data,
                                is_key: false,
                            }
                        })
                        .collect();
                    if let Err(e) = sender_input.lock().await.send_packets(&pkts).await {
                        tracing::error!("Input send error: {} — stopping", e);
                        break;
                    }
                }
                // M8-T018: 显示器控制消息（DisplaySelect / DisplayListReq）→
                // `ChannelTag::Control` 可靠流（与键鼠同优先，不丢）。
                msg = control_rx.recv() => {
                    let Some(msg) = msg else {
                        tracing::info!("Control send task exited (window closed)");
                        break;
                    };
                    let data = match bincode::serialize(&msg) {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::warn!("control serialize failed: {e}");
                            continue;
                        }
                    };
                    let pkt = EncodedPacket {
                        ts: Timestamp::now(),
                        kind: PacketKind::Control,
                        data,
                        is_key: false,
                    };
                    if let Err(e) = sender_input.lock().await.send_packets(&[pkt]).await {
                        tracing::error!("Control send error: {} — stopping", e);
                        break;
                    }
                }
                pkts = clip_rx.recv() => {
                    if let Some(pkts) = pkts {
                        if let Err(e) = sender_input.lock().await.send_packets(&pkts).await {
                            tracing::error!("Clipboard send error: {} — stopping", e);
                            break;
                        }
                    }
                }
            }
        }
    });
    // M8-T021 P1: 渲染桥在 push 信号**之前**创建（原 2398 位于 push 之后需调整
    // 顺序）——桥克隆进信号随窗口走，会话保留一份给解码线程 push_decoded。
    let bridge = kirin_desk_media::decoder::RenderBridge::new(2, 16); // jitter 2 帧 @60fps
    // M8-T021 P1: close_tx——窗口持有；去重丢弃信号 / 窗口关闭 → sender drop →
    // 会话退出（P2 消费 close_rx）。
    let (close_tx, mut close_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    // Signal main thread to open connection window (addr + 输入通道 + 文件命令通道
    // + M8-T018 显示器控制通道 + M8-T021 P1 会话标识/渲染桥/关闭通道)
    if let Ok(mut w) = add_window_signal().lock() {
        w.push(DesktopWindowSignal {
            session_id,
            addr: addr_label.clone(),
            bridge: bridge.clone(),
            input_tx,
            file_tx: file_cmd_tx.clone(),
            control_tx: control_tx.clone(),
            close_tx,
        });
    }
    // M8-T018（CLI-MON-001）：连接建立后自动请求显示器列表（与既有控制
    // 消息流程一致，无握手协议改动）。热插拔后可经工具栏 ⟳ 手动刷新（MON-NF-001）。
    // M8-T021 P1: 键控清空本会话的显示状态。
    if let Ok(mut m) = display_view_state().lock() {
        let st = m.entry(session_id).or_default();
        st.list.clear();
        st.nack = None;
    }
    let _ = control_tx.send(ControlMessage::DisplayListReq);

    // M13-T003: 剪贴板同步——本地轮询（500ms）→ 变更推送；远端推送在接收
    // 循环按 `ChannelTag::Clipboard` 分发（见下）。共享状态机防回环。
    let clip_state: Arc<Mutex<clipboard::ClipboardSyncState>> =
        Arc::new(Mutex::new(clipboard::ClipboardSyncState::new()));
    let clip_io: Option<Arc<Mutex<clipboard::OsClipboard>>> =
        clipboard::OsClipboard::new().map(|c| Arc::new(Mutex::new(c)));
    if let Some(clip_io_poll) = clip_io.clone() {
        let clip_state_poll = clip_state.clone();
        let clip_tx_poll = clip_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(clipboard::POLL_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let now_ms = now_epoch_ms();
                let pushed = {
                    let mut st = clip_state_poll.lock().unwrap();
                    let mut io = clip_io_poll.lock().unwrap();
                    st.poll_local(now_ms, &mut *io)
                };
                if let Some(text) = pushed {
                    let pkts = clipboard::clipboard_packets(&text);
                    if clip_tx_poll.send(pkts).is_err() {
                        break; // 窗口关闭
                    }
                }
            }
        });
    }

    // M13-T006: 文件会话任务——命令（UI）/ 帧事件（接收循环）/ 1s tick 三路驱动。
    // 发送：FIFO ≤3 调度 + 滑窗 + 重传 + 断点续传；接收：分片重组 + 校验落盘。
    {
        let sender_ft = sender_shared.clone();
        let panel_ft = file_panel_state();
        let my_id = client_id.public_key_base64();
        let salt = file_transfer_salt(&my_id, &peer_id);
        let cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
        let store_path = transfers_store_path("client");
        let download_dir = cfg.file_transfer.resolved_download_dir();
        let max_file_size = if cfg.file_transfer.max_file_size > 0 {
            cfg.file_transfer.max_file_size
        } else {
            DEFAULT_MAX_FILE_SIZE
        };
        tokio::spawn(async move {
            let mut ft = FileSession::new(
                sender_ft,
                panel_ft,
                salt,
                store_path,
                download_dir,
                max_file_size,
                None,
            );
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    cmd = file_cmd_rx.recv() => {
                        let Some(cmd) = cmd else {
                            tracing::info!("File session exited (window closed)");
                            break;
                        };
                        ft.handle_command(cmd).await;
                    }
                    frame = file_frame_rx.recv() => {
                        let Some(frame) = frame else {
                            tracing::info!("File session exited (receive loop closed)");
                            break;
                        };
                        ft.handle_frame(frame).await;
                    }
                    _ = tick.tick() => {
                        ft.on_tick().await;
                    }
                }
            }
            // 会话结束：清理未完成任务（保留 .part 与断点记录，供重连续传）。
            let _ = file_frame_tx;
        });
    }

    // M8-T015 P2D：解码与 UI 线程分离（重写旧实现——原 tokio
    // 接收循环内直接 decode 且只解窗口首帧 IDR、无 PTS/抖动缓冲）。
    // 拓扑：tokio 接收循环（重组 + 投递）→ DecoderPacket channel
    // → 解码线程（专用 std::thread）→ RenderBridge（抖动缓冲）
    // → 各连接窗口 pop 自己的桥 → 窗口纹理上传（M8-T021 P1）。
    // 桥已在 push 信号前创建（见上）：信号里放克隆给窗口，会话保留本份给解码线程。
    let (pkt_tx, pkt_rx) =
        std::sync::mpsc::channel::<kirin_desk_media::decoder::DecoderPacket>();

    // 1. 解码线程：FFmpeg 解码为阻塞同步调用，用专用 std::thread
    //    （避免污染 tokio runtime；解码器 Send 非 Sync，线程独占）。
    let decode_bridge = bridge.clone();
    let decode_handle = std::thread::Builder::new()
        .name("kirin-video-decode".into())
        .spawn(move || {
            // P2B：VideoDecoderPipeline（回退链 qsv→cuvid→…→软解）。
            let mut decoder = match kirin_desk_media::decoder::factory::create_video_decoder(
                kirin_desk_media::encoder::Codec::H264,
            ) {
                Ok(d) => {
                    tracing::info!("Client decoder: {} (HW={})", d.name(), d.is_hardware());
                    Some(d)
                }
                Err(e) => {
                    tracing::error!("Failed to create H.264 decoder: {}", e);
                    None
                }
            };
            while let Ok(pkt) = pkt_rx.recv() {
                let Some(dec) = decoder.as_mut() else { continue; };
                match dec.decode(&pkt) {
                    Ok(frames) => {
                        for f in frames {
                            decode_bridge.push_decoded(f);
                        }
                        // 解码统计上报（P2B 接入 ReportGenerator）。
                        // report_gen.record_decoded_frame(start.elapsed_ms())
                    }
                    Err(e) => {
                        tracing::warn!("decode error: {}", e);
                        // P2B：连续错误触发 request_keyframe（会话层实现）。
                    }
                }
            }
            // pkt_tx drop（连接关闭）→ recv Err → 线程退出 → Drop 释放解码器。
            tracing::info!("Video decode thread exited");
        })
        .expect("spawn video decode thread");

    // 2. 接收循环（tokio，瘦身：仅重组 + 投递 DecoderPacket，不再解码）。
    // NOTE: runs in the SAME tokio runtime as the handshake to avoid
    // "Tokio 1.x context was found, but it is being shutdown" errors.
    // M8-T021 P2: 保存 JoinHandle 供会话尾部 select（连接断开 → 循环 break →
    // join 解码线程 → 任务结束）。
    let recv_handle = tokio::spawn(async move {
        let mut total_bytes: u64 = 0;
        let mut last_fps_check = std::time::Instant::now();
        let mut frame_count: u32 = 0;
        let mut current_fps: f32 = 0.0;
        let mut current_bandwidth: f32 = 0.0;
        let mut current_resolution = String::new();
        loop {
            // M9/P1F: tag 分帧接收——按 tag 分发（Video → 解码；Clipboard → 剪贴板）。
            let (tag, _header, payload) = match video_receiver.recv_tagged().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("Recv error: {}", e);
                    break;
                }
            };
            // M13-T003: 远端剪贴板推送 → 写入本地（分片重组 + 防回环）。
            if tag == ChannelTag::Clipboard {
                if let Some(clip_io_recv) = &clip_io {
                    let mut st = clip_state.lock().unwrap();
                    let mut io = clip_io_recv.lock().unwrap();
                    st.apply_remote_frame(now_epoch_ms(), &payload, &mut *io);
                }
                continue;
            }
            // M8-T018: 显示器控制响应（DisplayListResp / DisplaySelectNack）
            // → 更新共享查看状态（窗口下拉/状态栏每帧读取）。
            // M8-T019: 隐私模式响应（PrivacyModeAck）→ 共享隐私状态
            // （连接窗口徽标 / 锁屏输入禁用 / toast，UI-PRIV-002）。
            if tag == ChannelTag::Control {
                match bincode::deserialize::<ControlMessage>(&payload) {
                    Ok(ControlMessage::DisplayListResp { displays }) => {
                        tracing::info!(
                            "DisplayListResp: {} display(s) available",
                            displays.len()
                        );
                        // M8-T021 P1: 键控写入本会话的显示列表（多窗口互不覆盖）。
                        if let Ok(mut m) = display_view_state().lock() {
                            let st = m.entry(session_id).or_default();
                            st.list = displays;
                            st.nack = None;
                        }
                    }
                    Ok(ControlMessage::DisplaySelectNack { reason }) => {
                        tracing::warn!("DisplaySelectNack: {}", reason);
                        if let Ok(mut m) = display_view_state().lock() {
                            m.entry(session_id).or_default().nack = Some(reason);
                        }
                    }
                    Ok(ControlMessage::PrivacyModeAck { ok, active_level }) => {
                        tracing::info!(
                            "PrivacyModeAck: ok={} active={:?}",
                            ok,
                            active_level
                        );
                        // M8-T021 P1: 键控写入本会话的隐私状态。
                        let mut st = client_privacy_state().lock().unwrap();
                        let st = st.entry(session_id).or_default();
                        // 降级判断：请求 Black 但生效 Lock（SRV-PRIV-013）→ toast。
                        let toast =
                            privacy::ack_toast(ok, active_level, st.requested);
                        st.ack = Some(privacy::PrivacyAckState {
                            level: active_level,
                            seq: st
                                .ack
                                .as_ref()
                                .map_or(0, |a| a.seq)
                                .saturating_add(1),
                            toast,
                        });
                    }
                    Ok(other) => tracing::debug!("Control message (unhandled): {:?}", other),
                    Err(e) => tracing::warn!("display control deserialize failed: {e}"),
                }
                continue;
            }
            // M13-T006: 远端文件帧 → 文件会话任务（帧处理 + 回复由它统一发送）。
            if tag == ChannelTag::FileTransfer {
                match FileTransferFrame::decode(&payload) {
                    Ok(frame) => {
                        if file_frame_tx.send(frame).is_err() {
                            break; // 文件会话已退出
                        }
                    }
                    Err(e) => tracing::warn!("file frame decode failed: {e}"),
                }
                continue;
            }
            if tag != ChannelTag::Video {
                continue;
            }
            let data_len = payload.len();
            match bincode::deserialize::<kirin_desk_media::proto::EncodedWindow>(&payload) {
                Ok(window) => {
                    total_bytes += data_len as u64;
                    frame_count += window.frame_count;
                    let now = std::time::Instant::now();
                    let elapsed = now.duration_since(last_fps_check).as_secs_f32();
                    if elapsed >= 1.0 {
                        current_fps = frame_count as f32 / elapsed;
                        current_bandwidth = total_bytes as f32 / (elapsed * 1024.0);
                        frame_count = 0;
                        total_bytes = 0;
                        last_fps_check = now;
                    }
                    if window.base_w > 0 && window.base_h > 0 {
                        current_resolution = format!("{}×{}", window.base_w, window.base_h);
                        // M9: 发布远端分辨率（视口输入捕获按此换算像素坐标）。
                        // M8-T021 P1: 键控写入本会话。
                        if let Ok(mut m) = client_resolution().lock() {
                            *m.entry(session_id).or_default() = (window.base_w, window.base_h);
                        }
                    }
                    // 状态栏统计（解码结果不影响网络统计更新）。
                    // M8-T021 P1: 键控写入本会话（多窗口各自独立）。
                    if let Ok(mut m) = connection_stats().lock() {
                        m.insert(
                            session_id,
                            ConnectionStats {
                                fps: current_fps,
                                bandwidth_kbps: current_bandwidth,
                                resolution: current_resolution.clone(),
                            },
                        );
                    }

                    // P2D：窗口 → 逐帧 DecoderPacket → 解码线程。
                    // PTS 方案 A：frame_id 线性近似（每窗口 2~4 帧，
                    // wid×10+idx 保证跨窗口单调；详见 frame_id_to_pts）。
                    for (idx, frame_nalus) in
                        KirinDeskApp::window_frame_nalus(&window).into_iter().enumerate()
                    {
                        if frame_nalus.is_empty() {
                            continue;
                        }
                        let mut frame_data = Vec::new();
                        for nal in frame_nalus {
                            frame_data.extend_from_slice(nal);
                        }
                        let pkt = kirin_desk_media::decoder::DecoderPacket {
                            pts: kirin_desk_media::decoder::frame_id_to_pts(
                                window.window_id * 10 + idx as u64,
                                60,
                            ),
                            data: frame_data,
                            is_key: idx == 0, // 窗口首帧为 IDR
                            extradata: None,
                        };
                        if pkt_tx.send(pkt).is_err() {
                            break; // 解码线程已退出
                        }
                    }
                }
                Err(e) => tracing::error!("Deserialize EncodedWindow failed: {}", e),
            }
        }
        // 连接关闭：pkt_tx drop → 解码线程 recv Err → 退出；
        // join 回收线程（panic 检测，无残留线程/解码器泄漏）。
        tracing::info!("Receive loop exited, joining video decode thread");
        if decode_handle.join().is_err() {
            tracing::error!("Video decode thread panicked");
        }
    });
    // M8-T021 P2 (T021-03-A): 会话退出通道——窗口关闭或连接断开任一触发即返回，
    // 不再 pending 挂起；返回后 runtime drop → 任务 abort → 线程回收，杜绝泄漏。
    tokio::select! {
        _ = close_rx.recv() => {
            tracing::info!("[session] ended: window closed");
            // 窗口关闭路径：接收任务仍存活，runtime drop 时 abort → pkt_tx drop →
            // 解码线程 recv Err 自行退出（1 帧内），无残留。
        }
        _ = recv_handle => {
            tracing::info!("[session] ended: connection closed");
            // 连接断开路径：接收任务内部已 join 解码线程，零残留。
        }
    }
    // M8-T021 P2 (T021-02): 清理本会话的键控状态条目（窗口关闭先于会话退出
    // 亦无残留——无论退出顺序如何，最终清空）。
    cleanup_session_state(session_id);
}

/// M8-T026-P2 (ID-021): GUI 设备 ID 模式连接线程 —— 解析（ID-010）→ 服务器
/// 签名验签（ID-SEC-001）→ 公钥 pin（known_hosts 命中强制比对 / 未命中首次
/// 指纹确认，ID-012）→ 三级路径编排（ID-011：直连 → 打洞 hook → 中继兜底）
/// → 复用 `run_client_session_with_stream` 握手 + 媒体会话（ID-013）。
async fn run_client_session_by_id(device_id: String, ctx: egui::Context) {
    use kirin_desk_core::connection::id_mode::{IdConnectError, IdConnector, IdModeConfig};
    use kirin_desk_utils::audit::{AuditEvent, AuditLogger};
    use kirin_desk_utils::known_hosts::{FingerprintStatus, KnownHostsStore};

    let cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
    let tunnel = cfg.tunnel.clone();
    let Some(client_id) = global_identity().get() else {
        if let Ok(mut s) = connection_status().lock() {
            *s = "设备 ID 模式：未加载本机身份".to_string();
        }
        return;
    };
    // ID-014：ID 模式需服务器配置。
    let server_pubkey = match tunnel.server_pubkey.as_deref() {
        Some(k) if !k.trim().is_empty() => k.to_string(),
        _ => {
            if let Ok(mut s) = connection_status().lock() {
                *s = "ID 模式未配置 server_pubkey（tunnel serve 启动时输出）".to_string();
            }
            return;
        }
    };
    let connector = match IdModeConfig::try_new(&tunnel.server_addr, &tunnel.token, &server_pubkey)
    {
        Ok(c) => IdConnector::new(c),
        Err(e) => {
            if let Ok(mut s) = connection_status().lock() {
                *s = format!("ID 模式配置错误: {}", e);
            }
            return;
        }
    };
    // ID-010 + ID-SEC-001：解析 + 验签。
    let info = match connector.resolve(&device_id).await {
        Ok(i) => i,
        Err(IdConnectError::SignatureVerification) => {
            if let Ok(mut s) = connection_status().lock() {
                *s = "解析响应签名校验失败（ID-SEC-001）— 可能 server_pubkey 错误或中间人".to_string();
            }
            return;
        }
        Err(e) => {
            if let Ok(mut s) = connection_status().lock() {
                *s = format!("解析失败: {}", e);
            }
            return;
        }
    };
    // ID-010：离线/未知统一文案（ID-SEC-002）。
    if !IdConnector::is_connectable(&info) {
        if let Ok(mut s) = connection_status().lock() {
            *s = format!("设备 '{}' 离线或未注册", device_id);
        }
        return;
    }
    // ID-012：公钥 pin（known_hosts 三态：命中一致 → Verified；命中不一致 →
    // 拒绝；未命中 → Confirm 首次指纹确认）。
    let trust = match KnownHostsStore::load() {
        Ok(store) => match store.check(&device_id, &info.payload.ed25519_pub) {
            FingerprintStatus::Match => ClientTrust::Verified(info.payload.ed25519_pub.clone()),
            FingerprintStatus::Mismatch => {
                if let Ok(mut s) = connection_status().lock() {
                    *s = format!(
                        "known_hosts 指纹不匹配 '{}' — 拒绝连接（MITM 防护）",
                        device_id
                    );
                }
                return;
            }
            FingerprintStatus::Unknown => ClientTrust::Confirm,
        },
        Err(_) => ClientTrust::Confirm,
    };
    // ID-011：三级路径编排（直连 → 打洞 hook → 中继兜底）。
    let from_peer = tunnel
        .device_id
        .clone()
        .unwrap_or_else(|| kirin_desk_utils::known_hosts::fingerprint(&client_id.public_key_base64()));
    if let Ok(mut s) = connection_status().lock() {
        *s = format!("Connecting: {} (relay {}) ...", device_id, tunnel.server_addr);
    }
    let (path, stream) = match connector.connect_stream(&info, &from_peer).await {
        Ok(x) => x,
        Err(e) => {
            if let Ok(mut s) = connection_status().lock() {
                *s = format!("连接失败（全部路径）: {}", e);
            }
            return;
        }
    };
    tracing::info!("ID mode: path selected = {} for '{}'", path, device_id);
    if let Ok(mut logger) = AuditLogger::open_default() {
        let _ = logger.record(
            AuditEvent::TunnelPathSelected,
            &format!("device={} path={}", device_id, path),
        );
    }
    let challenge = cfg.device.challenge_code.clone();
    let ctx2 = ctx.clone();
    let device_id2 = device_id.clone();
    // 复用会话入口（握手 + 媒体会话）；首次连接指纹确认由内部 key_confirm 弹窗。
    run_client_session_with_stream(
        stream,
        format!("{} (via relay, {})", device_id, path),
        device_id2,
        trust,
        challenge,
        String::new(),
        "desktop",
    )
    .await;
    let _ = ctx2;
}

#[derive(Default)]
struct KirinDeskApp {
    current_tab: Tab,
    /// M10: 已保存设备列表（Devices 页展示，按 last_seen 降序）。
    devices: Vec<SavedDevice>,
    // Connect panel fields
    connect_domain: String,
    connect_ipv6: String,
    connect_port: String,
    connect_nickname: String,
    connect_challenge: String,
    connect_status: String,
    /// M8-T026-P2 (ID-021): 设备 ID 模式输入框。
    connect_device_id: String,
    /// M8-T026-P2 (ID-021): 设备 ID 模式选中态（三态：IP / Domain / ID）。
    connect_id_mode: bool,
    // Settings fields
    api_key: String,
    api_secret: String,
    /// GoDaddy API base URL（Settings 未保存时回退生产环境）。
    api_url: String,
    domain: String,
    device_id: String,
    nickname: String,
    challenge_code: String,
    allowed_domains: String,
    listen_port: String,
    ip_mode_allowed: bool,
    temp_mode: bool,
    settings_status: String,
    // Server mode
    server_running: bool,
    server_status: String,
    pending_connections: Vec<PendingConnection>,
    next_pending_id: u64,
    // Status bar
    local_ipv6: String,
    config_loaded: bool,
    // Real-time log display
    gui_log: String,
    log_poll_counter: u8,
    // Connection windows (auto-opened per connection)
    windows: Vec<ConnectionWindow>,
    next_window_id: u64,
    /// M13-T006 (UI-FT-005): 服务端接收完成提示弹窗（可关闭）。
    file_notices: Vec<String>,
    // M10-T005: 设备编辑弹窗状态
    editing_device: Option<String>,
    edit_nickname: String,
    edit_domain: String,
    edit_port: String,
    // M15-T008: 主题模式（Config `[ui] theme`，默认 Light）+ 密文输入可见开关
    theme_mode: ThemeMode,
    show_secret_connect: bool,
    show_secret_api: bool,
    show_secret_challenge: bool,
    // M13-T005: 无人值守模式（Settings 页状态 + 启动时序）
    unattended_enabled: bool,
    unattended_autostart: bool,
    unattended_auto_server: bool,
    // M8-T026: 内网穿透设置（Settings 页 Tunnel (内网穿透) 分组）
    tunnel_enabled: bool,
    tunnel_mode: String,
    tunnel_server_addr: String,
    tunnel_token: String,
    tunnel_proxies: String,
    show_secret_tunnel_token: bool,
    /// 本次启动是否由系统开机自启拉起（`--autostart`）——用于窗口最小化启动。
    autostart_launched: bool,
    /// 无人值守自动开启服务端是否已执行（一次性标记）。
    server_auto_started: bool,
    // M8-T017: 临时连接（Dashboard 卡片）状态——明文码仅本次进程持有
    // （TMP-SEC-001，状态文件只存哈希）；窗口过期/关闭后复位。
    temp_code: Option<String>,
    /// 上一帧临时窗口是否激活（用于归零瞬间的过期检测 + 审计，UI-TMP-004）。
    temp_window_was_active: bool,
    /// 卡片内操作结果提示（enable 失败等）。
    temp_status: String,
    /// M8-T028 (UI-BTY-028): 复制成功浮出提示（(预览文案, 点击时刻)，2s 自动消失）。
    copied_feedback: Option<(String, std::time::Instant)>,
}

/// M8-T028 (UI-BTY-028): 状态栏「Copied: …」浮出提示持续时间。
const COPY_TOAST_DURATION: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(PartialEq)]
enum Tab {
    Dashboard,
    Devices,
    Connect,
    Settings,
}
impl Default for Tab {
    fn default() -> Self {
        Tab::Dashboard
    }
}

/// M10-T004: 上次在线时间的本地时区展示——今天显示"今天 HH:MM"，否则"MM-DD HH:MM"。
fn format_last_seen(dt: chrono::DateTime<chrono::Utc>) -> String {
    use chrono::Local;
    let local = dt.with_timezone(&Local);
    if local.date_naive() == Local::now().date_naive() {
        format!("今天 {}", local.format("%H:%M"))
    } else {
        local.format("%m-%d %H:%M").to_string()
    }
}

/// 从 "[ipv6]:port" 连接地址中提取 IPv6 部分（设备自动保存用）。
fn addr_ipv6(addr: &str) -> String {
    addr.trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or("")
        .to_string()
}

/// 当前 epoch 毫秒（剪贴板冷却窗口计时）。
fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// M10-T003: 连接成功后自动保存设备到 `devices.json`（桌面会话与 Shell 会话共用）。
/// 按 id 去重 + last_seen 刷新由 `DeviceStore` 维护；保存成功置位 `devices_dirty`
/// 让 Devices 页即时刷新。
fn save_device_to_store(addr: &str, server_id: &str, pubkey: &str, device_type: &str, domain: &str) {
    let port = addr
        .rsplit(':')
        .next()
        .and_then(|p| p.trim_end_matches(']').parse().ok())
        .unwrap_or(0);
    let device = SavedDevice {
        id: server_id.to_string(),
        nickname: server_id.to_string(),
        ipv6: addr_ipv6(addr),
        port,
        pubkey: pubkey.to_string(),
        device_type: device_type.to_string(),
        last_seen: chrono::Utc::now(),
        domain: domain.to_string(),
    };
    match DeviceStore::load() {
        Ok(mut store) => {
            store.upsert(device);
            match store.save() {
                Ok(()) => devices_dirty().store(true, Ordering::Relaxed),
                Err(e) => tracing::warn!("Save device failed: {}", e),
            }
        }
        Err(e) => tracing::warn!("Device store load failed: {}", e),
    }
}

impl eframe::App for KirinDeskApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if !self.config_loaded {
            self.load_config();
            self.config_loaded = true;
            // M13-T005 (UA-SRV-001): 无人值守自动开启服务端——启动即监听，
            // 无需人工点击 Dashboard 启动按钮；失败处理见 start_server 内审计。
            if self.unattended_enabled && self.unattended_auto_server {
                self.start_server();
            }
            // UA-UI-003 (D4): --autostart 或无人值守启动 → 窗口最小化启动，
            // 不打断用户前台工作（托盘常驻列为后续增强）。
            if self.unattended_enabled || self.autostart_launched {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }
        }

        // M14-T005: 每周后台自动检查更新（启动时一次，静默；结果写入 Update 面板）。
        // 网络失败不记录时间戳，下次启动重试；成功后进入 7 天检查周期。
        static AUTO_CHECK_DONE: AtomicBool = AtomicBool::new(false);
        if !AUTO_CHECK_DONE.swap(true, Ordering::Relaxed) {
            let updater = updater();
            if updater.should_auto_check(7) {
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().expect("auto update check rt");
                    let status = rt.block_on(updater.check_for_updates());
                    match status {
                        UpdateStatus::Error(_) => {} // 静默失败，下次启动重试
                        other => {
                            let _ = updater.record_auto_check();
                            let mut s = update_state().lock().unwrap();
                            s.result = Some(other);
                        }
                    }
                });
            }
        }

        // M15-T008: 主题解析 + 应用——System 模式跟随系统，明暗变化即时重设
        // （set_visuals + set_style 全量重设，无需重启；各视口独立 ctx 同样处理）。
        let system_dark = frame.info().system_theme == Some(eframe::Theme::Dark);
        let theme = self.theme_mode.resolve(system_dark);
        theme::apply_theme(ctx, &theme);

        // M8-T028 (UI-BTY-028): 复制成功浮出提示 2s 自动消失；
        // 提示存活期间持续请求重绘，避免窗口无输入时提示残留。
        if let Some((_, t)) = &self.copied_feedback {
            if t.elapsed() >= COPY_TOAST_DURATION {
                self.copied_feedback = None;
            } else {
                ctx.request_repaint();
            }
        }

        // M10-T003: 连接线程自动保存设备后刷新列表（跨线程信号，非每帧读盘）。
        if devices_dirty().swap(false, Ordering::Relaxed) {
            self.reload_devices();
        }

        // Poll log buffer every 6 frames (~100ms at 60fps)
        self.log_poll_counter = self.log_poll_counter.wrapping_add(1);
        if self.log_poll_counter % 6 == 0 {
            let buf = gui_log_buffer();
            self.gui_log = buf.all();
            // Keep max ~100 lines for display
            if self.gui_log.len() > 8000 {
                if let Some(pos) = self.gui_log.as_bytes().iter().rposition(|&b| b == b'\n') {
                    let cut = self.gui_log.len().saturating_sub(6000);
                    let start = self
                        .gui_log
                        .as_bytes()
                        .iter()
                        .skip(cut)
                        .position(|&b| b == b'\n')
                        .unwrap_or(0);
                    self.gui_log = self.gui_log[cut + start..].to_string();
                }
            }
            ctx.request_repaint();
        }

        // M8-T017 (UI-TMP-004/005): 临时连接窗口逐帧检测——窗口激活期间每秒
        // 重绘驱动倒计时（mm:ss）；归零瞬间（上一帧激活 → 本帧失效）复位卡片
        // 并审计 TempModeExpired。手动关闭在卡片按钮内处理（审计 Disabled）。
        let temp_active = crate::policy::temp_mode_window_active();
        if self.temp_window_was_active && !temp_active {
            let mut logger = kirin_desk_utils::audit::AuditLogger::open_default().ok();
            audit_record(
                &mut logger,
                kirin_desk_utils::audit::AuditEvent::TempModeExpired,
                "reason=expired",
            );
            self.temp_code = None;
            self.temp_status = "临时连接窗口已过期".to_string();
        }
        self.temp_window_was_active = temp_active;
        if temp_active {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }

        // --- Approval dialog (top-level modal for pending connections) ---
        // M15: 每帧 drain 服务端线程推送的待审批连接；已处理的记录顺手清理。
        if let Some(rx) = pending_conn_rx().lock().unwrap().as_mut() {
            while let Ok(pc) = rx.try_recv() {
                self.pending_connections.push(pc);
            }
        }
        self.pending_connections
            .retain(|p| p.status == PendingStatus::Waiting);
        let pending = self.pending_connections.clone();
        let waiting: Vec<_> = pending
            .iter()
            .filter(|p| p.status == PendingStatus::Waiting)
            .collect();
        if let Some(pc) = waiting.first() {
            egui::Window::new("Incoming Connection")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    // M15-T008: 卡片化——设备名加粗 + 类型徽标 + 指纹 Mono + 语义按钮。
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(
                                "A device outside your whitelist is trying to connect:",
                            )
                            .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                    ui.add_space(4.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(egui::RichText::new(&pc.client_id).strong())
                                .selectable(true),
                        );
                        // M8-T028 (UI-BTY-026): 设备名（client_id）一键复制。
                        self.copied_button(ui, &theme, &pc.client_id);
                        badge(ui, &theme, &pc.device_type, BadgeKind::Info);
                    });
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("Domain: {}", pc.client_domain))
                                    .monospace()
                                    .color(theme.fg_weak),
                            )
                            .selectable(true),
                        );
                        // M8-T028 (UI-BTY-026): Domain 一键复制（空值按钮自动禁用）。
                        self.copied_button(ui, &theme, &pc.client_domain);
                    });
                    // 指纹等宽显示（远端设备标识即指纹，无独立 pubkey 字段）
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("Fingerprint: {}", pc.client_id))
                                    .monospace()
                                    .size(theme.mono_size)
                                    .color(theme.fg),
                            )
                            .selectable(true),
                        );
                        // M8-T028 (UI-BTY-026): 指纹一键复制（与设备 ID 同源显示）。
                        self.copied_button(ui, &theme, &pc.client_id);
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        if action_button(
                            ui,
                            &theme,
                            ButtonKind::Success,
                            "✓ Accept",
                            ButtonState::Enabled,
                        )
                        .clicked()
                        {
                            self.approve_connection(pc.id, true);
                        }
                        if action_button(
                            ui,
                            &theme,
                            ButtonKind::Danger,
                            "✗ Reject",
                            ButtonState::Enabled,
                        )
                        .clicked()
                        {
                            self.approve_connection(pc.id, false);
                        }
                    });
                });
        }

        // --- M15 (CLI-KH-001): 首次连接指纹确认模态框 ---
        // 连接线程设置 `pending_fingerprint` 后阻塞等待；本模态框应答后放行。
        // 窗口被关闭（X）→ Sender drop → 连接线程 recv Err → 视为拒绝。
        let pending_fp = pending_fingerprint().lock().ok().and_then(|mut g| g.take());
        if let Some(pfp) = pending_fp {
            let mut accepted = false;
            let mut rejected = false;
            egui::Window::new("首次连接指纹确认")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(
                                "这是第一次连接该设备。请核对远端 Ed25519 公钥指纹，\n\
                                 与设备持有者提供的指纹一致才可继续（防中间人攻击）。",
                            )
                            .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                    ui.add_space(4.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(egui::RichText::new("Device:").color(theme.fg_weak))
                                .selectable(false),
                        );
                        ui.add(
                            egui::Label::new(egui::RichText::new(&pfp.device_id).strong())
                                .selectable(true),
                        );
                    });
                    ui.add_space(4.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(&pfp.fingerprint)
                                .monospace()
                                .size(theme.mono_size)
                                .color(theme.fg),
                        )
                        .selectable(true),
                    );
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new("SHA-256 of the server's Ed25519 public key")
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(format!(
                                "Pubkey: {}…",
                                &pfp.pubkey_base64[..pfp.pubkey_base64.len().min(24)]
                            ))
                            .monospace()
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                        )
                        .selectable(true),
                    );
                    ui.separator();
                    ui.horizontal(|ui| {
                        if action_button(
                            ui,
                            &theme,
                            ButtonKind::Success,
                            "✓ 接受并连接",
                            ButtonState::Enabled,
                        )
                        .clicked()
                        {
                            accepted = true;
                        }
                        if action_button(
                            ui,
                            &theme,
                            ButtonKind::Danger,
                            "✗ 拒绝",
                            ButtonState::Enabled,
                        )
                        .clicked()
                        {
                            rejected = true;
                        }
                    });
                });
            if accepted {
                let _ = pfp.answer_tx.send(true);
            } else if rejected {
                let _ = pfp.answer_tx.send(false);
            }
            // 未应答（窗口仍开着）→ 下一帧继续显示。
            if !accepted && !rejected {
                pending_fingerprint().lock().ok().map(|mut g| *g = Some(pfp));
                ctx.request_repaint();
            }
        }

        egui::TopBottomPanel::top("nav_bar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                // M15-T008: 品牌区——品牌 emoji + 名称 + 版本徽标
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("🐉 KirinDesk")
                            .size(theme.heading_size)
                            .strong()
                            .color(theme.fg),
                    )
                    .selectable(false),
                );
                badge(ui, &theme, kirin_desk_updater::APP_VERSION, BadgeKind::Neutral);
                ui.separator();
                // 图标化标签页（选中态品牌色胶囊）
                for (tab, icon, name) in [
                    (Tab::Dashboard, "🏠", "Dashboard"),
                    (Tab::Devices, "🖥", "Devices"),
                    (Tab::Connect, "🔗", "Connect"),
                    (Tab::Settings, "⚙", "Settings"),
                ] {
                    if selectable_pill(
                        ui,
                        &theme,
                        &format!("{icon} {name}"),
                        self.current_tab == tab,
                    )
                    .clicked()
                    {
                        self.current_tab = tab;
                    }
                }
                // M15-T008: pending 计数改红色 Badge
                let wc = waiting.len();
                if wc > 0 {
                    badge(ui, &theme, &format!("⚡ {} pending!", wc), BadgeKind::Danger);
                }
            });
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!("IPv6: {}", self.local_ipv6))
                            .monospace()
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(true),
                );
                ui.separator();
                // M15-T008: API 状态改语义 Badge
                if self.api_key.is_empty() {
                    badge(ui, &theme, "API: Not configured", BadgeKind::Warning);
                } else {
                    badge(ui, &theme, "API: Ready", BadgeKind::Success);
                }
                ui.separator();
                // M15-T008: StatusDot——监听=绿 / 停止=灰
                if self.server_running {
                    status_dot(ui, theme.success, "Server: Listening");
                } else {
                    status_dot_char(ui, theme.fg_weak, "○", "Server: Stopped");
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // M8-T028 (UI-BTY-028): 复制成功浮出提示（右侧弱色，2s 自动消失）。
                    if let Some((value, _)) = &self.copied_feedback {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("Copied: {value}"))
                                    .monospace()
                                    .size(theme.small_size)
                                    .color(theme.fg_weak),
                            )
                            .selectable(false),
                        );
                    }
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new("81/81 tests")
                                .monospace()
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.current_tab {
            Tab::Dashboard => self.show_dashboard(ui, &theme),
            Tab::Devices => self.show_devices(ui, &theme),
            Tab::Connect => self.show_connect(ui, &theme),
            Tab::Settings => self.show_settings(ui, &theme),
        });

        // M13-T006 (UI-FT-005): 服务端接收完成提示弹窗（会话写队列 → 本帧 drain）。
        if let Ok(mut q) = server_file_notices().lock() {
            self.file_notices.extend(q.drain(..));
        }
        let mut dismiss = Vec::new();
        for (i, notice) in self.file_notices.iter().enumerate() {
            let mut closed = false;
            egui::Window::new("📁 文件接收完成")
                .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-16.0, 16.0))
                .show(ctx, |ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(notice).size(theme.small_size),
                        )
                        .selectable(true),
                    );
                    ui.add_space(8.0);
                    if action_button(
                        ui,
                        &theme,
                        ButtonKind::Secondary,
                        "关闭",
                        ButtonState::Enabled,
                    )
                    .clicked()
                    {
                        closed = true;
                    }
                });
            if closed {
                dismiss.push(i);
            }
        }
        for i in dismiss.into_iter().rev() {
            self.file_notices.remove(i);
        }

        // Connection windows (auto-opened per connection)
        // M8-T021 P1 (T021-01-A/B): drain 窗口信号 + 去重——同 addr+kind 已有窗口
        // → 丢弃新信号（不建窗口、不建重复连接）+ 聚焦已有窗口（egui 0.28.1 无
        // BringToFront，仅 Focus）。信号 drop → close_tx drop → 重复会话退出（P2）。
        {
            if let Ok(mut signals) = add_window_signal().lock() {
                for sig in signals.drain(..) {
                    if let Some(existing) = self.windows.iter().find(|w| {
                        w.addr == sig.addr && w.kind == WindowKind::Desktop
                    }) {
                        Self::focus_window(ctx, existing.id);
                        tracing::info!(
                            "[dedup] desktop window {} exists for {}, signal dropped",
                            existing.id,
                            sig.addr
                        );
                        continue;
                    }
                    let wid = self.next_window_id;
                    self.next_window_id += 1;
                    self.windows.push(ConnectionWindow {
                        id: wid,
                        session_id: sig.session_id,
                        addr: sig.addr,
                        device_type: "desktop".to_string(),
                        kind: WindowKind::Desktop,
                        input_tx: Some(sig.input_tx),
                        bridge: Some(sig.bridge),
                        close_tx: Some(sig.close_tx),
                        input_queue: InputCaptureQueue::new(),
                        texture: None,
                        terminal: None,
                        shell_tx: None,
                        file_tx: Some(sig.file_tx),
                        control_tx: Some(sig.control_tx),
                        display_list: Vec::new(),
                        display_selected: None,
                        display_nack: None,
                        show_file_panel: false,
                        fullscreen: false,
                        show_special_key_panel: false,
                        remote_platform: RemotePlatform::Unknown,
                        last_special_key: std::time::Instant::now(),
                        privacy_level: None,
                        privacy_ack_seq: 0,
                        privacy_toast: None,
                    });
                    tracing::info!("Connection window opened: id={}", wid);
                }
            }
            // M11-T005: 远程 Shell 会话窗口（每设备+每端口独立 PTY 会话）。
            // M8-T021 P1: 同 addr 去重 + 聚焦；terminal 用会话侧实例（断链修复）。
            if let Ok(mut signals) = add_shell_window_signal().lock() {
                for sig in signals.drain(..) {
                    if let Some(existing) = self.windows.iter().find(|w| {
                        w.addr == sig.addr && w.kind == WindowKind::Shell
                    }) {
                        Self::focus_window(ctx, existing.id);
                        tracing::info!(
                            "[dedup] shell window {} exists for {}, signal dropped",
                            existing.id,
                            sig.addr
                        );
                        continue;
                    }
                    let wid = self.next_window_id;
                    self.next_window_id += 1;
                    self.windows.push(ConnectionWindow {
                        id: wid,
                        session_id: sig.session_id,
                        addr: sig.addr,
                        device_type: "shell".to_string(),
                        kind: WindowKind::Shell,
                        input_tx: None,
                        bridge: None,
                        close_tx: Some(sig.close_tx),
                        input_queue: InputCaptureQueue::new(),
                        texture: None,
                        // P1-5: 会话侧已 feed 的终端实例（不再另建空终端）。
                        terminal: Some(sig.terminal),
                        shell_tx: Some(sig.shell_tx),
                        file_tx: None,
                        control_tx: None,
                        display_list: Vec::new(),
                        display_selected: None,
                        display_nack: None,
                        show_file_panel: false,
                        fullscreen: false,
                        show_special_key_panel: false,
                        remote_platform: RemotePlatform::Unknown,
                        last_special_key: std::time::Instant::now(),
                        privacy_level: None,
                        privacy_ack_seq: 0,
                        privacy_toast: None,
                    });
                    tracing::info!("Shell window opened: id={}", wid);
                }
            }
        }

        let mut closed = Vec::new();
        for (_i, win) in self.windows.iter_mut().enumerate() {
            let viewport_id = egui::ViewportId::from_hash_of(&win.id);
            let title = format!("KirinDesk - {} ({})", win.addr, win.device_type);
            let wid = win.id;
            ctx.show_viewport_immediate(
                viewport_id,
                egui::ViewportBuilder::default()
                    .with_title(&title)
                    .with_inner_size([960.0, 600.0])
                    .with_close_button(true),
                |ctx, _class| {
                    // M15-T008: 子视口独立 egui Context——共享字体回退链与主题令牌。
                    theme::ensure_fonts(ctx);
                    theme::apply_theme(ctx, &theme);

                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed.push(wid);
                        return;
                    }

                    // M8-T007: Status bar at top (replaces right-click context menu)
                    // M8-T021 P1: 键控读取本会话统计（多窗口各自独立）。
                    let stats = connection_stats()
                        .lock()
                        .unwrap()
                        .get(&win.session_id)
                        .cloned()
                        .unwrap_or_default();
                    // M8-T018: 同步显示器列表 / Nack（接收循环 → 本窗口缓存）。
                    if win.kind == WindowKind::Desktop {
                        win.sync_display_state();
                    }
                    // M8-T019 (UI-PRIV-002): 同步隐私 ack（徽标 / 输入禁用 / toast）。
                    win.sync_privacy_state();
                    egui::TopBottomPanel::top(format!("conn_status_{}", wid)).show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            if win.kind == WindowKind::Shell {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(
                                            "Remote Shell — PTY session (ANSI + scrollback)",
                                        )
                                        .color(theme.fg_weak),
                                    )
                                    .selectable(false),
                                );
                            } else if stats.fps > 0.0 {
                                // M15-T008: FPS/BW/Res 改 Mono 徽标
                                // M8-T021 P1: 键控 map 默认值为空 → 显示占位。
                                badge(
                                    ui,
                                    &theme,
                                    &format!("FPS: {:.0}", stats.fps),
                                    BadgeKind::Neutral,
                                );
                                badge(
                                    ui,
                                    &theme,
                                    &format!("BW: {:.1} KB/s", stats.bandwidth_kbps),
                                    BadgeKind::Neutral,
                                );
                                badge(ui, &theme, &stats.resolution, BadgeKind::Neutral);
                            } else {
                                badge(ui, &theme, "FPS: --  BW: --  Res: --", BadgeKind::Neutral);
                            }
                            // M8-T018（CLI-MON-003）：状态栏显示当前屏名称与分辨率。
                            if win.kind == WindowKind::Desktop {
                                if let Some(d) = win.current_display() {
                                    badge(
                                        ui,
                                        &theme,
                                        &format!(
                                            "🖥 {} {}×{}{}",
                                            d.name,
                                            d.width,
                                            d.height,
                                            if d.is_primary { " [主屏]" } else { "" }
                                        ),
                                        BadgeKind::Info,
                                    );
                                }
                                // M8-T018（MON-NF-001）：切换被拒 → 错误提示（保持当前屏）。
                                if let Some(reason) = &win.display_nack {
                                    badge(ui, &theme, &format!("⛔ {reason}"), BadgeKind::Danger);
                                }
                                // M8-T019 (UI-PRIV-002): 隐私徽标（黑屏 / 锁屏）。
                                match win.privacy_level {
                                    Some(PrivacyLevel::Black) => {
                                        badge(ui, &theme, "🛡 黑屏", BadgeKind::Info);
                                    }
                                    Some(PrivacyLevel::Lock) => {
                                        badge(ui, &theme, "🔒 锁屏", BadgeKind::Danger);
                                    }
                                    None => {}
                                }
                            }
                            // M15-T008: 工具栏（显示器 🖥 / 文件 📁 / 特殊键 🔑 / 全屏 ▣ / 断开 ✖）
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if win.kind == WindowKind::Desktop {
                                        // M8-T018（CLI-MON-002 / UI-BTY-016）：显示器下拉。
                                        // 列表显示 `名称 分辨率 [主屏]`；切换即发 DisplaySelect。
                                        if !win.display_list.is_empty() {
                                            let cur = win.display_selected.unwrap_or(0);
                                            let mut selected = cur as usize;
                                            let sel_text = format!(
                                                "🖥 {}",
                                                win.current_display()
                                                    .map(|d| d.name.as_str())
                                                    .unwrap_or("显示器")
                                            );
                                            egui::ComboBox::from_id_source(format!(
                                                "display_sel_{wid}"
                                            ))
                                            .selected_text(sel_text)
                                            .width(170.0)
                                            .show_ui(ui, |ui| {
                                                for d in &win.display_list {
                                                    let label = format!(
                                                        "{} {}×{}{}",
                                                        d.name,
                                                        d.width,
                                                        d.height,
                                                        if d.is_primary { " [主屏]" } else { "" }
                                                    );
                                                    ui.selectable_value(
                                                        &mut selected,
                                                        d.index as usize,
                                                        label,
                                                    );
                                                }
                                            });
                                            // 用户已选择过（display_selected.is_some()）才发切换；
                                            // 初始默认显示屏 0 不产生多余信令。
                                            let new_sel = selected as u32;
                                            if win.display_selected.is_some()
                                                && win.display_selected != Some(new_sel)
                                            {
                                                win.display_selected = Some(new_sel);
                                                win.display_nack = None;
                                                win.send_display_control(
                                                    ControlMessage::DisplaySelect {
                                                        index: new_sel,
                                                    },
                                                );
                                            }
                                            // MON-NF-001: 手动刷新列表（显示器热插拔后）。
                                            if toolbar_button(
                                                ui,
                                                &theme,
                                                "⟳",
                                                "刷新显示器列表",
                                            )
                                            .clicked()
                                            {
                                                win.send_display_control(
                                                    ControlMessage::DisplayListReq,
                                                );
                                            }
                                        }
                                        // M8-T020 UI-SKEY-001: 特殊键面板（Win/Alt+Tab/任务管理器/锁屏）。
                                        if toolbar_button(ui, &theme, "🔑", "特殊键 (Win / Alt+Tab / 锁屏)")
                                            .clicked()
                                        {
                                            win.show_special_key_panel = !win.show_special_key_panel;
                                        }
                                        if toolbar_button(ui, &theme, "📁", "文件传输面板 (拖拽发送)")
                                            .clicked()
                                        {
                                            win.show_file_panel = !win.show_file_panel;
                                        }
                                        // M8-T019 (UI-PRIV-001/002): 隐私模式菜单——
                                        // 黑屏（Level 1）/ 锁屏（Level 2）/ 恢复屏幕。
                                        // 激活时按钮文案显示当前状态（高亮由状态栏徽标承担）。
                                        let privacy_label = match win.privacy_level {
                                            Some(PrivacyLevel::Black) => "🛡 黑屏",
                                            Some(PrivacyLevel::Lock) => "🛡 锁屏",
                                            None => "🛡 隐私",
                                        };
                                        ui.menu_button(privacy_label, |ui| {
                                            let black_active = win.privacy_level
                                                == Some(PrivacyLevel::Black);
                                            let lock_active = win.privacy_level
                                                == Some(PrivacyLevel::Lock);
                                            if ui
                                                .add_enabled(
                                                        !black_active,
                                                        egui::Button::new(
                                                            "隐藏被控端屏幕（黑屏）",
                                                        ),
                                                    )
                                                    .on_hover_text(
                                                        "被控端屏幕被纯黑覆盖；远程操作与输入注入照常",
                                                    )
                                                    .clicked()
                                                {
                                                    // M8-T021 P1: 键控写入本会话
                                                    // （多窗口各自的 requested 互不串扰）。
                                                    client_privacy_state()
                                                        .lock()
                                                        .unwrap()
                                                        .entry(win.session_id)
                                                        .or_default()
                                                        .requested =
                                                        Some(PrivacyLevel::Black);
                                                    win.send_privacy(ControlMessage::PrivacyMode {
                                                        level: PrivacyLevel::Black,
                                                        on: true,
                                                    });
                                                    ui.close_menu();
                                                }
                                                if ui
                                                    .add_enabled(
                                                        !lock_active,
                                                        egui::Button::new("锁定被控端"),
                                                    )
                                                    .on_hover_text(
                                                        "系统锁屏；锁屏后输入注入暂停，解锁自动恢复",
                                                    )
                                                    .clicked()
                                                {
                                                    // M8-T021 P1: 键控写入本会话。
                                                    client_privacy_state()
                                                        .lock()
                                                        .unwrap()
                                                        .entry(win.session_id)
                                                        .or_default()
                                                        .requested =
                                                        Some(PrivacyLevel::Lock);
                                                    win.send_privacy(ControlMessage::PrivacyMode {
                                                        level: PrivacyLevel::Lock,
                                                        on: true,
                                                    });
                                                    ui.close_menu();
                                                }
                                                ui.separator();
                                                if ui
                                                    .add_enabled(
                                                        win.privacy_level.is_some(),
                                                        egui::Button::new("恢复屏幕"),
                                                    )
                                                    .clicked()
                                                {
                                                    // M8-T021 P1: 键控写入本会话。
                                                    client_privacy_state()
                                                        .lock()
                                                        .unwrap()
                                                        .entry(win.session_id)
                                                        .or_default()
                                                        .requested = None;
                                                    win.send_privacy(ControlMessage::PrivacyMode {
                                                        level: PrivacyLevel::Black,
                                                        on: false,
                                                    });
                                                    ui.close_menu();
                                                }
                                                // UI-PRIV-004: 锁屏期间提示输入暂停。
                                                if lock_active {
                                                    ui.separator();
                                                    ui.add(
                                                        egui::Label::new(
                                                            egui::RichText::new(
                                                                "被控端已锁定，输入暂停",
                                                            )
                                                            .color(theme.fg_weak),
                                                        )
                                                        .selectable(false),
                                                    );
                                                }
                                            });
                                    }
                                    if toolbar_button(ui, &theme, "▣", "Fullscreen (F11)").clicked()
                                    {
                                        win.fullscreen = !win.fullscreen;
                                        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(
                                            win.fullscreen,
                                        ));
                                    }
                                    if toolbar_button(ui, &theme, "✖", "Disconnect").clicked() {
                                        closed.push(wid);
                                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                    }
                                },
                            );
                        });
                    });
                    // M15-T008: F11 全屏快捷键（窗口聚焦时）
                    if ctx.input(|i| i.key_pressed(egui::Key::F11)) {
                        win.fullscreen = !win.fullscreen;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(win.fullscreen));
                    }

                    // M13-T006 (UI-FT-003): 拖拽文件到连接窗口 → 立即发送。
                    if win.kind == WindowKind::Desktop {
                        let dropped = file_panel::dropped_file_paths(ctx);
                        if !dropped.is_empty() {
                            ctx.input_mut(|i| i.raw.dropped_files.clear());
                            if let Some(tx) = &win.file_tx {
                                for path in dropped {
                                    tracing::info!("Dropped file → send: {}", path.display());
                                    let _ = tx.send(FileCommand::SendFile { path });
                                }
                            }
                        }
                    }

                    // M13-T006 (UI-FT-001/002): 文件传输面板（📁 切换；进度/速度/状态/控制）。
                    if win.kind == WindowKind::Desktop && win.show_file_panel {
                        egui::TopBottomPanel::bottom(format!("file_panel_{wid}"))
                            .resizable(true)
                            .default_height(240.0)
                            .show(ctx, |ui| {
                                let mut state = file_panel_state().lock().unwrap();
                                file_panel::show_file_panel(ui, &theme, &mut state, win.file_tx.as_ref());
                            });
                    }

                    // M8-T020 UI-SKEY-001/002/003/004: 特殊键面板（🔑 切换）。
                    // Win+E/D/L/R、Alt+Tab、任务管理器、Alt+F4、锁屏（CAC 替代）；
                    // 1s 防连点；macOS 被控端禁用 Alt+Tab。
                    if win.kind == WindowKind::Desktop && win.show_special_key_panel {
                        let on_cooldown =
                            win.last_special_key.elapsed() < std::time::Duration::from_secs(1);
                        let alt_tab_unsupported = win.remote_platform == RemotePlatform::MacOS;
                        let mut clicked: Option<SpecialCombo> = None;
                        egui::Window::new("特殊键")
                            .collapsible(false)
                            .resizable(false)
                            .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-16.0, 44.0))
                            .show(ctx, |ui| {
                                egui::Grid::new(egui::Id::new(("special_key_grid", wid)))
                                    .num_columns(4)
                                    .spacing([8.0, 8.0])
                                    .show(ui, |ui| {
                                        for combo in [
                                            SpecialCombo::WinE,
                                            SpecialCombo::WinD,
                                            SpecialCombo::WinL,
                                            SpecialCombo::WinR,
                                            SpecialCombo::AltTab,
                                            SpecialCombo::CtrlShiftEsc,
                                            SpecialCombo::AltF4,
                                            SpecialCombo::LockScreen,
                                        ] {
                                            // UI-SKEY-004: macOS 被控端 Alt+Tab 禁用并提示。
                                            let state = if on_cooldown
                                                || (alt_tab_unsupported && combo == SpecialCombo::AltTab)
                                            {
                                                ButtonState::Disabled
                                            } else {
                                                ButtonState::Enabled
                                            };
                                            let resp = action_button(
                                                ui,
                                                &theme,
                                                ButtonKind::Secondary,
                                                combo.label(),
                                                state,
                                            );
                                            // UI-SKEY-003: tooltip 提示（Alt+Tab 另附被控端前台要求）。
                                            let hint = if combo == SpecialCombo::AltTab
                                                && alt_tab_unsupported
                                            {
                                                "被控端为 macOS：不支持 Alt+Tab（Cmd+Tab 为系统 UI）"
                                            } else {
                                                combo.hint()
                                            };
                                            let resp = resp.on_hover_text(hint);
                                            if state == ButtonState::Enabled && resp.clicked() {
                                                clicked = Some(combo);
                                            }
                                            ui.end_row();
                                        }
                                    });
                                // UI-SKEY-002: CAC 限制说明（锁屏替代文案）。
                                ui.add_space(4.0);
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(
                                            "Ctrl+Alt+Del 为系统安全序列，普通进程不可注入 — 以「锁屏」代替",
                                        )
                                        .size(theme.small_size)
                                        .color(theme.fg_weak),
                                    )
                                    .selectable(false),
                                );
                            });
                        if let Some(combo) = clicked {
                            // UI-SKEY-003: 点击后 1s 防连点。
                            win.last_special_key = std::time::Instant::now();
                            // 顺序保证：先 flush 待发队列（移动/按键在前），再发特殊键。
                            if let Some(tx) = win.input_tx.as_ref() {
                                win.input_queue.flush_if_due(tx);
                                let _ = tx.send(vec![WireInputEvent::special_key(combo)]);
                            }
                            tracing::info!(
                                "Special key requested: {} (window {})",
                                combo.label(),
                                wid
                            );
                        }
                    }

                    // M8-T019 (UI-PRIV-002): 隐私 toast（5s 自动消失；关闭按钮即时消失）。
                    if let Some((text, at)) = &win.privacy_toast {
                        let elapsed = at.elapsed();
                        if elapsed < std::time::Duration::from_secs(5) {
                            let mut dismiss = false;
                            egui::Window::new("🛡 隐私模式")
                                .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-16.0, 44.0))
                                .collapsible(false)
                                .resizable(false)
                                .show(ctx, |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(text).size(theme.small_size),
                                        )
                                        .selectable(false),
                                    );
                                    ui.add_space(6.0);
                                    if action_button(
                                        ui,
                                        &theme,
                                        ButtonKind::Secondary,
                                        "关闭",
                                        ButtonState::Enabled,
                                    )
                                    .clicked()
                                    {
                                        dismiss = true;
                                    }
                                });
                            if dismiss {
                                win.privacy_toast = None;
                            }
                        } else {
                            win.privacy_toast = None;
                        }
                    }

                    egui::CentralPanel::default()
                        // M15-T008: letterbox 黑底（视频画布底色令牌）
                        .frame(egui::Frame::none().fill(theme.video_bg))
                        .show(ctx, |ui| {
                        // M11-T002/T005: 远程 Shell 终端渲染（独立会话，互不影响）。
                        if win.kind == WindowKind::Shell {
                            let (focused, events) = ctx.input(|i| (i.focused, i.events.clone()));
                            let Some(term) = win.terminal.as_ref() else {
                                ui.label("Shell terminal not initialized.");
                                return;
                            };
                            // 1. 键盘事件 → 终端字节流（仅窗口聚焦时捕获）。
                            if focused {
                                let mut t = term.lock().unwrap();
                                for ev in &events {
                                    t.handle_event(ev);
                                }
                            }
                            // 2. 渲染 + 尺寸变化 → ShellResize（终端尺寸变更通知）。
                            let (cols, rows, resized) = term.lock().unwrap().ui(ui);
                            if resized {
                                if let Some(tx) = win.shell_tx.as_ref() {
                                    let _ = tx.send(ShellMessage::ShellResize { cols, rows });
                                }
                            }
                            // 3. 累积输入 → ShellStdin（含 DSR 应答字节）。
                            let input = term.lock().unwrap().take_input();
                            if !input.is_empty() {
                                if let Some(tx) = win.shell_tx.as_ref() {
                                    let _ = tx.send(ShellMessage::ShellStdin(input));
                                }
                            }
                            return;
                        }

                        // Desktop: show received frame
                        // M8-T015 P2D + M8-T021 P1: 每窗口 pop **自己的**渲染桥 →
                        // 直接上本窗口纹理（原全局 pop → client_frame() 只有第一个
                        // 窗口能取到帧；键控后各窗口互不抢帧）。
                        // TextureHandle::set 复用，避免每帧 ctx.load_texture 重建；
                        // 分辨率变化时 set 自动按新尺寸重建纹理。
                        if let Some(bridge) = win.bridge.as_ref() {
                            if let Some(frame) = bridge.pop_render() {
                                let img = egui::ColorImage::from_rgba_unmultiplied(
                                    [frame.width as usize, frame.height as usize],
                                    &frame.rgba,
                                );
                                match &mut win.texture {
                                    Some(t) => t.set(img, egui::TextureOptions::LINEAR),
                                    None => {
                                        win.texture = Some(ctx.load_texture(
                                            "remote_frame",
                                            img,
                                            egui::TextureOptions::LINEAR,
                                        ))
                                    }
                                }
                                ctx.request_repaint_after(std::time::Duration::from_millis(16));
                            }
                        }
                        // M15-T008: 断开检测（输入发送通道已关闭 = 远端会话结束）→
                        // 错误覆盖层 + 重连按钮（重连逻辑预留，后续 M9 联调期接入）。
                        let disconnected = win
                            .input_tx
                            .as_ref()
                            .map(|tx| tx.is_closed())
                            .unwrap_or(false);
                        if disconnected {
                            // M8-T019: 断连后隐私徽标清空（服务端已本地恢复，SRV-PRIV-014）。
                            win.privacy_level = None;
                            ui.centered_and_justified(|ui| {
                                ui.vertical(|ui| {
                                    status_dot(ui, theme.danger, "Connection lost");
                                    ui.add_space(8.0);
                                    if action_button(
                                        ui,
                                        &theme,
                                        ButtonKind::Primary,
                                        "Reconnect",
                                        ButtonState::Enabled,
                                    )
                                    .clicked()
                                    {
                                        tracing::info!(
                                            "Reconnect requested — reserved for M9 integration"
                                        );
                                    }
                                });
                            });
                            return;
                        }
                        let Some(texture) = win.texture.as_ref() else {
                            // 缓冲长期为空（网络/解码停顿）→ 显示上一帧而非黑屏；
                            // 首帧未到 → 占位提示（原文案保持）。
                            ui.centered_and_justified(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(
                                            "Connected — waiting for video stream...",
                                        )
                                        .color(theme.fg_weak),
                                    )
                                    .selectable(false),
                                );
                            });
                            ctx.request_repaint();
                            return;
                        };
                        // M15-T008: letterbox——等比缩放（仅缩小）+ 居中；
                        // 黑底由面板 `theme.video_bg` 提供（Frame::dark 的令牌化实现）。
                        let img_size = texture.size_vec2();
                        let available = ui.available_size();
                        let fit_scale = (available.x / img_size.x)
                            .min(available.y / img_size.y)
                            .min(1.0);
                        let new_size =
                            egui::vec2(img_size.x * fit_scale, img_size.y * fit_scale);
                        let img_rect =
                            egui::Rect::from_center_size(ui.max_rect().center(), new_size);
                        let img_resp = ui.put(
                            img_rect,
                            egui::Image::new(texture).fit_to_exact_size(new_size),
                        );

                        // M9-T002/T004: 远程输入捕获（仅窗口聚焦 + 指针在图像内）。
                        // M8-T019 (UI-PRIV-004): 锁屏期间本地输入禁用
                        // （服务端也不接收注入，双保险；黑屏期间输入照常）。
                        // M8-T021 P1: 键控读取本会话分辨率（多窗口各自独立）。
                        let (base_w, base_h) = client_resolution()
                            .lock()
                            .unwrap()
                            .get(&win.session_id)
                            .copied()
                            .unwrap_or((0, 0));
                        if base_w > 0 && base_h > 0 {
                            let (focused, pointer_pos, events, mods) = ctx.input(|i| {
                                (
                                    i.focused,
                                    i.pointer.latest_pos(),
                                    i.events.clone(),
                                    i.modifiers,
                                )
                            });
                            if focused && win.privacy_level != Some(PrivacyLevel::Lock) {
                                let mut mod_flags = 0u8;
                                if mods.ctrl {
                                    mod_flags |= hid_modifier::CTRL;
                                }
                                if mods.shift {
                                    mod_flags |= hid_modifier::SHIFT;
                                }
                                if mods.alt {
                                    mod_flags |= hid_modifier::ALT;
                                }
                                if mods.command {
                                    mod_flags |= hid_modifier::SUPER;
                                }

                                // 鼠标：指针在图像内 → 归一化 → 远端像素（T004 比例映射）
                                let px =
                                    pointer_pos.filter(|p| img_resp.rect.contains(*p)).map(|p| {
                                        let nx = ((p.x - img_resp.rect.min.x)
                                            / img_resp.rect.width())
                                        .clamp(0.0, 1.0);
                                        let ny = ((p.y - img_resp.rect.min.y)
                                            / img_resp.rect.height())
                                        .clamp(0.0, 1.0);
                                        ((nx * base_w as f32) as u32, (ny * base_h as f32) as u32)
                                    });
                                if let Some((px, py)) = px {
                                    win.input_queue.push_move(px, py);
                                    for (btn, bits) in [
                                        (egui::PointerButton::Primary, hid_button::LEFT),
                                        (egui::PointerButton::Secondary, hid_button::RIGHT),
                                        (egui::PointerButton::Middle, hid_button::MIDDLE),
                                    ] {
                                        let (pressed, released) = ctx.input(|i| {
                                            (
                                                i.pointer.button_pressed(btn),
                                                i.pointer.button_released(btn),
                                            )
                                        });
                                        if pressed {
                                            win.input_queue
                                                .push(WireInputEvent::mouse_button(bits, px, py));
                                        } else if released {
                                            win.input_queue.push(WireInputEvent::mouse_button(
                                                bits | hid_button::RELEASE,
                                                px,
                                                py,
                                            ));
                                        }
                                    }
                                    // 滚轮：Line ≈ 3 行/格 → 120 (WHEEL_DELTA)；
                                    // Point ≈ 60pt/格 → 120。
                                    for ev in &events {
                                        if let egui::Event::MouseWheel { unit, delta, .. } = ev {
                                            let wheel = match unit {
                                                egui::MouseWheelUnit::Line => {
                                                    (delta.y * 40.0) as i32
                                                }
                                                egui::MouseWheelUnit::Point => {
                                                    (delta.y * 2.0) as i32
                                                }
                                                egui::MouseWheelUnit::Page => {
                                                    (delta.y * 120.0) as i32
                                                }
                                            };
                                            if wheel != 0 {
                                                win.input_queue.push(WireInputEvent::mouse_wheel(
                                                    wheel, px, py,
                                                ));
                                            }
                                        }
                                    }
                                }

                                // 键盘：仅需窗口聚焦（IME/快捷键不依赖指针位置）
                                for ev in &events {
                                    match ev {
                                        egui::Event::Key {
                                            key,
                                            pressed,
                                            repeat,
                                            ..
                                        } => {
                                            if let Some(hid) = egui_key_to_hid(*key) {
                                                let kind = if !*pressed {
                                                    InputKind::KeyUp
                                                } else if *repeat {
                                                    InputKind::KeyRepeat
                                                } else {
                                                    InputKind::KeyDown
                                                };
                                                win.input_queue.push(WireInputEvent::key(
                                                    kind, hid, mod_flags,
                                                ));
                                            }
                                        }
                                        egui::Event::Text(text) => {
                                            if !text.is_empty() {
                                                win.input_queue
                                                    .push(WireInputEvent::text(text.clone()));
                                            }
                                        }
                                        _ => {}
                                    }
                                }

                                // 按节流规则 flush；纯移动节流中安排重绘补发（60fps）
                                if let Some(tx) = win.input_tx.as_ref() {
                                    if !win.input_queue.flush_if_due(tx)
                                        && win.input_queue.has_pending()
                                    {
                                        ctx.request_repaint_after(INPUT_MOVE_INTERVAL);
                                    }
                                }
                            }
                            // M8-T019 (UI-PRIV-004): 锁屏期间输入暂停提示
                            // （视频照常显示，输入捕获已禁用）。
                            if win.privacy_level == Some(PrivacyLevel::Lock) {
                                let painter = ui.painter();
                                painter.text(
                                    ui.max_rect().center_top() + egui::vec2(0.0, 14.0),
                                    egui::Align2::CENTER_TOP,
                                    "🔒 被控端已锁定，输入暂停（解锁后自动恢复）",
                                    egui::FontId::proportional(16.0),
                                    theme.fg_weak,
                                );
                            }
                        }
                    });
                },
            );
        }
        for wid in closed {
            // M8-T019 (UI-PRIV-003): 窗口关闭 → 通知服务端恢复屏幕。
            // 与服务端断连自动恢复（SRV-PRIV-014）构成双保险。
            if let Some(win) = self.windows.iter().find(|w| w.id == wid) {
                if win.privacy_level.is_some() {
                    tracing::info!(
                        "Connection window closing — sending PrivacyMode off (window {})",
                        wid
                    );
                    win.send_privacy(ControlMessage::PrivacyMode {
                        level: PrivacyLevel::Black,
                        on: false,
                    });
                }
            }
            self.windows.retain(|w| w.id != wid);
            tracing::info!("Connection window closed: id={}", wid);
        }

        // M8-T019 (SRV-PRIV-011/016): 被控端黑屏覆盖窗口（全屏纯黑 + 提示条 +
        // 本地逃生舱）。控制器无活跃黑屏时本调用立即返回（覆盖窗口自动关闭，
        // 断连恢复无网络依赖，SRV-PRIV-014）。
        match privacy::show_black_overlay(ctx) {
            privacy::OverlayOutcome::Escaped => {
                // 本地逃生舱触发（Esc 3s / Ctrl+Alt+F9）：复位控制器 + 审计
                // （PRIV-SEC-001）。不通知远端——紧急操作，SRV-PRIV-016。
                let was = server_privacy_controller()
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|c| c.lock().unwrap().local_escape())
                    .unwrap_or(false);
                if was {
                    if let Ok(mut l) = kirin_desk_utils::audit::AuditLogger::open_default() {
                        let _ = l.record(
                            kirin_desk_utils::audit::AuditEvent::PrivacyDisabled,
                            "level=black initiator=local escape_hatch",
                        );
                    }
                    tracing::warn!("[Privacy] black overlay escaped locally by user");
                }
            }
            _ => {}
        }
    }
}

impl KirinDeskApp {
    /// M8-T021 P1 (T021-01-B): 聚焦已有窗口——egui 0.28.1 无 `BringToFront`，
    /// 仅 `ViewportCommand::Focus`（窗口 id → ViewportId::from_hash_of）。
    fn focus_window(ctx: &egui::Context, wid: u64) {
        ctx.send_viewport_cmd_to(
            egui::ViewportId::from_hash_of(&wid),
            egui::ViewportCommand::Focus,
        );
    }

    /// M8-T021 P1 (T021-01-D): 连接前置查重——已存在同目标窗口 → 聚焦并拒绝
    /// 新连接；信号队列有同目标 pending（本帧未 drain）→ 拒绝新连接。
    /// 返回 true = 已去重，调用方不再启动会话。
    ///
    /// 与 drain 去重（P1-2）构成双保险：前置处理「点击时刻已知有窗口」；
    /// drain 兜底「点击与握手期间窗口才建立」的竞态。
    fn try_dedup_connect(&self, ctx: &egui::Context, addr: &str, kind: WindowKind) -> bool {
        // 1. 已有窗口：聚焦（T021-01-B）。
        if let Some(win) = self.windows.iter().find(|w| w.addr == addr && w.kind == kind) {
            Self::focus_window(ctx, win.id);
            return true;
        }
        // 2. 信号队列 pending（同目标会话已建立连接，drain 未执行）。
        pending_signal_has(addr, kind)
    }

    fn load_config(&mut self) {
        self.connect_port = "3389".to_string();
        self.listen_port = "3389".to_string();
        self.ip_mode_allowed = true;
        if let Ok(cfg) = kirin_desk_utils::config::Config::load() {
            self.api_key = cfg.godaddy.api_key;
            self.api_secret = cfg.godaddy.api_secret;
            self.api_url = cfg.godaddy.api_url.clone();
            self.domain = cfg.godaddy.domain;
            self.device_id = cfg.device.id;
            self.nickname = cfg.device.nickname;
            self.challenge_code = cfg.device.challenge_code;
            self.allowed_domains = cfg.network.allowed_domains.join(", ");
            self.ip_mode_allowed = cfg.network.ip_mode_allowed;
            self.temp_mode = cfg.network.temp_mode;
            self.listen_port = cfg.network.port.to_string();
            // M15-T008: 主题模式（启动时 install 已用同源值，此处保持一致防漂移）。
            self.theme_mode = ThemeMode::from_str(&cfg.ui.theme);
            // M13-T005: 无人值守模式状态（Settings 页 + 启动时序共用）。
            self.unattended_enabled = cfg.unattended.enabled;
            self.unattended_autostart = cfg.unattended.auto_start_on_boot;
            self.unattended_auto_server = cfg.unattended.auto_start_server;
            // M8-T026: 内网穿透设置（Settings 页 Tunnel 分组回填；proxies 转多行文本）。
            self.tunnel_enabled = cfg.tunnel.enabled;
            self.tunnel_mode = cfg.tunnel.mode.clone();
            self.tunnel_server_addr = cfg.tunnel.server_addr.clone();
            self.tunnel_token = cfg.tunnel.token.clone();
            self.tunnel_proxies =
                kirin_desk_utils::config::TunnelConfig::format_proxy_lines(&cfg.tunnel.proxies);
        }
        // M10-T003: 启动时加载已保存设备列表（文件不存在 → 空列表）。
        self.reload_devices();
        if let Ok(ip) = kirin_desk_core::network::ipv6::get_global_ipv6() {
            self.local_ipv6 = ip.to_string();
        } else {
            self.local_ipv6 = "N/A".to_string();
        }
        // Load or generate persistent device identity
        let device_id = if self.device_id.is_empty() {
            "default"
        } else {
            &self.device_id
        };
        match IdentityManager::load_or_generate(
            std::path::PathBuf::from(
                dirs_next::home_dir()
                    .unwrap_or_default()
                    .join(".kirin_desk")
                    .join("identity")
                    .join("ed25519.json"),
            ),
            device_id,
        ) {
            Ok(id) => {
                let pubkey = id.public_key_base64();
                tracing::info!("Device identity loaded: pubkey={}...", &pubkey[..16]);
                let _ = global_identity().set(id);
            }
            Err(e) => tracing::error!("Failed to load device identity: {}", e),
        }
    }

    fn approve_connection(&mut self, id: u64, accept: bool) {
        if let Some(pc) = self.pending_connections.iter_mut().find(|p| p.id == id) {
            pc.status = if accept {
                PendingStatus::Accepted
            } else {
                PendingStatus::Rejected
            };
            self.server_status = format!(
                "Connection from {}: {}",
                pc.client_domain,
                if accept { "Accepted" } else { "Rejected" }
            );
            // M15: 审批决策回传服务端线程（握手续答或拒绝），并写审计日志。
            if let Some(tx) = pending_decisions().lock().unwrap().remove(&id) {
                let _ = tx.send(accept);
            }
            if let Ok(mut audit) = kirin_desk_utils::audit::AuditLogger::open_default() {
                let event = if accept {
                    kirin_desk_utils::audit::AuditEvent::ApprovalAccepted
                } else {
                    kirin_desk_utils::audit::AuditEvent::ApprovalRejected
                };
                let _ = audit.record(
                    event,
                    &format!("client={} domain={}", pc.client_id, pc.client_domain),
                );
            }
        }
    }

    /// M8-T028 (UI-BTY-028): 复制成功反馈——记录状态栏浮出提示
    /// （`Copied: <值前 24 字符>…`，2s 自动消失；空值不提示）。
    fn notify_copied(&mut self, value: &str) {
        if value.is_empty() {
            return;
        }
        let preview: String = value.chars().take(24).collect();
        let shown = if preview.chars().count() < value.chars().count() {
            format!("{preview}…")
        } else {
            preview
        };
        self.copied_feedback = Some((shown, std::time::Instant::now()));
    }

    /// M8-T028: 📋 复制按钮 + 成功反馈（空值禁用由 `copy_button` 内部处理）。
    fn copied_button(&mut self, ui: &mut egui::Ui, theme: &Theme, text: &str) {
        let (_, copied) = copy_button(ui, theme, text);
        if copied {
            self.notify_copied(text);
        }
    }

    fn show_dashboard(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        ui.heading("Dashboard");
        ui.separator();

        // M15-T008: ① 身份信息卡（值 Mono + 📋 复制按钮）
        let wl = if self.allowed_domains.is_empty() {
            "Any (insecure)".to_string()
        } else {
            self.allowed_domains.clone()
        };
        let api = if self.api_key.is_empty() {
            "Not set"
        } else {
            "Ready"
        };
        // M8-T028 (UI-BTY-024): 身份卡三行（Device ID / IPv6 / Domain）均带 📋；
        // stat_card 返回本帧复制的内容 → 状态栏浮出提示（UI-BTY-028）。
        if let Some(copied) = stat_card(
            ui,
            theme,
            "Identity",
            &[
                StatRow {
                    key: "Device ID:",
                    value: self.device_id.clone(),
                    mono: true,
                    copy: true,
                },
                StatRow {
                    key: "Nickname:",
                    value: self.nickname.clone(),
                    mono: false,
                    copy: false,
                },
                StatRow {
                    key: "IPv6:",
                    value: self.local_ipv6.clone(),
                    mono: true,
                    copy: true,
                },
                StatRow {
                    key: "Domain:",
                    value: self.domain.clone(),
                    mono: true,
                    copy: true,
                },
                StatRow {
                    key: "Listen Port:",
                    value: self.listen_port.clone(),
                    mono: true,
                    copy: false,
                },
                StatRow {
                    key: "API:",
                    value: api.to_string(),
                    mono: false,
                    copy: false,
                },
                StatRow {
                    key: "Allowed:",
                    value: wl,
                    mono: false,
                    copy: false,
                },
            ],
        ) {
            self.notify_copied(&copied);
        }
        ui.add_space(theme.spacing);

        // M15-T008: ② 服务器控制卡（大号主/次按钮 + StatusDot + Temp Mode Badge）
        card(ui, theme, "Server", |ui| {
            ui.horizontal(|ui| {
                if self.server_running {
                    status_dot(ui, theme.success, "Listening");
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(format!("Port: {}", self.listen_port))
                                .monospace()
                                .size(theme.mono_size),
                        )
                        .selectable(true),
                    );
                    if self.temp_mode {
                        badge(
                            ui,
                            theme,
                            "Temp Mode: ON (whitelist bypassed)",
                            BadgeKind::Warning,
                        );
                    }
                    // M8-T017 (UI-TMP-004): 临时连接窗口激活徽标（状态栏）。
                    if crate::policy::temp_mode_window_active() {
                        badge(ui, theme, "Temp Window: ON", BadgeKind::Warning);
                    }
                    // M13-T005 (UA-UI-002): 无人值守模式徽标。
                    if self.unattended_enabled {
                        badge(ui, theme, "Unattended", BadgeKind::Info);
                    }
                } else {
                    // 原文案 `○ Stopped` 保留
                    status_dot_char(ui, theme.fg_weak, "○", "Stopped");
                }
            });
            if !self.server_status.is_empty() {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&self.server_status)
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(true),
                );
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if self.server_running {
                    // Stop Listening → 危险语义
                    if action_button(
                        ui,
                        theme,
                        ButtonKind::Danger,
                        "■ Stop Listening",
                        ButtonState::Enabled,
                    )
                    .clicked()
                    {
                        server_stop_signal().store(true, Ordering::Relaxed);
                        self.server_running = false;
                        self.server_status = "Stopped".to_string();
                        tracing::info!("Server stop signal sent");
                    }
                    // 待审批计数 → 红色 Badge
                    let waiting_count = self
                        .pending_connections
                        .iter()
                        .filter(|p| p.status == PendingStatus::Waiting)
                        .count();
                    if waiting_count > 0 {
                        badge(
                            ui,
                            theme,
                            &format!("{} pending connection(s)", waiting_count),
                            BadgeKind::Danger,
                        );
                    }
                } else {
                    if action_button(
                        ui,
                        theme,
                        ButtonKind::Primary,
                        "Start Listening",
                        ButtonState::Enabled,
                    )
                    .clicked()
                    {
                        self.start_server();
                    }
                }
            });
        });
        ui.add_space(theme.spacing);

        // M8-T017 (UI-TMP-001~006): ③ 临时连接卡片——开启生成 8 位临时挑战码，
        // 窗口期内跳过域名白名单；开启态展示码 + 倒计时 + 关闭按钮。
        card(ui, theme, "临时连接", |ui| {
            if self.unattended_enabled {
                // UI-TMP-006: 无人值守下禁用（UA-ACCEPT-004）。
                badge(ui, theme, "Temp Mode", BadgeKind::Info);
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "无人值守模式下不可用（不提供任何临时放行未知设备的旁路）。",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                return;
            }
            let temp_active = crate::policy::temp_mode_window_active();
            if temp_active {
                // 开启态（UI-TMP-003）：徽标 + mm:ss 倒计时（每秒刷新）。
                ui.horizontal(|ui| {
                    badge(ui, theme, "Temp Mode", BadgeKind::Warning);
                    let remaining = TempModeManager::new()
                        .map(|m| m.remaining_secs())
                        .unwrap_or(0);
                    let mm = remaining / 60;
                    let ss = remaining % 60;
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(format!("{:02}:{:02}", mm, ss))
                                .monospace()
                                .size(theme.mono_size)
                                .color(theme.fg),
                        )
                        .selectable(true),
                    );
                });
                ui.add_space(4.0);
                match self.temp_code.clone() {
                    Some(code) => {
                        // 大号等宽码（UI-BTY-004）+ 一键复制（M8-T028 成功反馈）。
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&code)
                                        .monospace()
                                        .size(theme.mono_size + 6.0)
                                        .strong()
                                        .color(theme.fg),
                                )
                                .selectable(true),
                            );
                            self.copied_button(ui, theme, &code);
                        });
                    }
                    None => {
                        // 窗口由 CLI/其他进程开启：码仅在开启时展示一次（TMP-SEC-001）。
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(
                                    "临时码已在开启时展示一次，未落盘保存（TMP-SEC-001）。",
                                )
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                            )
                            .selectable(false),
                        );
                    }
                }
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "窗口期内跳过域名白名单，任何持有此码的客户端均可连接。",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                if !self.temp_status.is_empty() {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(&self.temp_status)
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(true),
                    );
                }
                ui.add_space(4.0);
                if action_button(
                    ui,
                    theme,
                    ButtonKind::Danger,
                    "关闭临时连接",
                    ButtonState::Enabled,
                )
                .clicked()
                {
                    let closed = TempModeManager::new()
                        .and_then(|m| m.disable())
                        .unwrap_or(false);
                    self.temp_code = None;
                    // 手动关闭 → 审计 Disabled；清标记避免归零误报 Expired。
                    self.temp_window_was_active = false;
                    let mut logger =
                        kirin_desk_utils::audit::AuditLogger::open_default().ok();
                    if closed {
                        audit_record(
                            &mut logger,
                            kirin_desk_utils::audit::AuditEvent::TempModeDisabled,
                            "reason=manual_gui",
                        );
                        self.temp_status = "临时连接已关闭".to_string();
                    } else {
                        self.temp_status = "临时连接已失效".to_string();
                    }
                }
            } else {
                // 关闭态（UI-TMP-002）：说明文案 + 主按钮。
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "临时授权访问：开启后生成 8 位临时挑战码，窗口期内跳过域名白名单，任何持有此码的客户端均可连接（默认 5 分钟，过期自动失效）。",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                if !self.temp_status.is_empty() {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(&self.temp_status)
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(true),
                    );
                }
                ui.add_space(4.0);
                if action_button(
                    ui,
                    theme,
                    ButtonKind::Primary,
                    "开启临时连接（5 分钟）",
                    ButtonState::Enabled,
                )
                .clicked()
                {
                    let cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
                    let ttl = cfg.network.effective_temp_mode_ttl();
                    match TempModeManager::new() {
                        Ok(mgr) => match mgr.enable(ttl) {
                            Ok(code) => {
                                self.temp_code = Some(code);
                                self.temp_status = format!("临时连接已开启（{} 分钟）", ttl / 60);
                                let mut logger =
                                    kirin_desk_utils::audit::AuditLogger::open_default().ok();
                                audit_record(
                                    &mut logger,
                                    kirin_desk_utils::audit::AuditEvent::TempModeEnabled,
                                    &format!(
                                        "ttl={}s state={}",
                                        ttl,
                                        mgr.state_file_path().display()
                                    ),
                                );
                            }
                            Err(e) => self.temp_status = format!("开启失败：{}", e),
                        },
                        Err(e) => self.temp_status = format!("开启失败：{}", e),
                    }
                }
            }
        });
        ui.add_space(theme.spacing);

        // M13-T006 (UI-FT-005): 服务端文件传输面板（连接建立后可用；
        // 拖拽文件到主窗口 = 推送（下载方向，服务端主动）。无 GUI 时静默接收）。
        card(ui, theme, "文件传输（服务端）", |ui| {
            let connected = server_file_tx().lock().unwrap().is_some();
            if !connected {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "无已连接客户端 — 客户端连接后，可拖拽文件到本窗口推送（服务端 → 客户端）。\n客户端推送的文件将静默接收至下载目录。",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                return;
            }
            // 拖拽 → 推送。
            let dropped = file_panel::dropped_file_paths(ui.ctx());
            if !dropped.is_empty() {
                ui.ctx().input_mut(|i| i.raw.dropped_files.clear());
                let tx = server_file_tx().lock().unwrap().clone();
                if let Some(tx) = tx {
                    for path in dropped {
                        tracing::info!("Server file drop → push: {}", path.display());
                        let _ = tx.send(FileCommand::SendFile { path });
                    }
                }
            }
            let tx = server_file_tx().lock().unwrap().clone();
            let mut state = server_file_panel_state().lock().unwrap();
            file_panel::show_file_panel(ui, theme, &mut state, tx.as_ref());
        });
        ui.add_space(theme.spacing);

        // M15-T008: ③ Live Log → LogView（级别着色 + 清空/复制）
        log_view(
            ui,
            theme,
            &self.gui_log,
            &LogViewOptions {
                title: "Live Log",
                empty: "(no log output yet)",
                max_height: 280.0,
                clearable: true,
                clear: Some(clear_gui_log),
            },
        );
    }

    /// M8-T015 P2D: 提取 EncodedWindow 内逐帧 NALU 列表。
    ///
    /// 兼容两种存储格式：扁平 `nalus + frame_nalu_counts`（新格式）与
    /// 嵌套 `frames`（旧格式，当前服务端 window_pipeline 使用）。
    /// 每帧 NALU 拼接后即 Annex B 码流（首帧含 SPS/PPS + IDR）。
    fn window_frame_nalus(window: &kirin_desk_media::proto::EncodedWindow) -> Vec<Vec<&[u8]>> {
        if !window.frame_nalu_counts.is_empty() {
            let mut out = Vec::with_capacity(window.frame_nalu_counts.len());
            let mut start = 0usize;
            for &count in &window.frame_nalu_counts {
                let end = start + count;
                out.push(
                    window
                        .nalus
                        .get(start..end)
                        .map(|nalus| nalus.iter().map(|n| n.as_ref()).collect())
                        .unwrap_or_default(),
                );
                start = end;
            }
            out
        } else {
            // 旧格式：frames = Vec<每帧的 NAL 包列表>。
            window
                .frames
                .iter()
                .map(|frame| frame.iter().map(|nal| nal.as_slice()).collect())
                .collect()
        }
    }

    fn start_server(&mut self) {
        use tracing::{error, info, warn};
        let port: u16 = self.listen_port.parse().unwrap_or(3389);
        let allowed: Vec<String> = self
            .allowed_domains
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let temp_mode = self.temp_mode;
        let ip_mode = self.ip_mode_allowed;
        let expected_nick = if self.nickname.is_empty() {
            None
        } else {
            Some(self.nickname.clone())
        };
        let use_temp_key = self.device_id.is_empty();

        self.server_running = true;
        self.server_status = format!("Starting on port {}...", port);
        // Log device identity
        if let Some(id) = global_identity().get() {
            info!(
                "Server identity: pubkey={}...",
                &id.public_key_base64()[..16]
            );
        }

        // IP mode bypasses whitelist check（无人值守下在 cfg 加载后强制关闭，
        // 见下方 `unattended` 判定 —— UA-ACCEPT-004）。
        let mut skip_whitelist = temp_mode || ip_mode;
        let mut unattended = false;

        // M15 (SRV-SEC-KH/RL/AUDIT): 服务端策略组件 — known_hosts / 审计 /
        // 速率限制 / DNS 配置（供 TXT 公钥兜底）。
        let mut known = match kirin_desk_utils::known_hosts::KnownClientsStore::load() {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!("known_clients load error (in-memory fallback): {}", e);
                kirin_desk_utils::known_hosts::KnownClientsStore::empty()
            }
        };
        let cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
        // M13-T005 (UA-ACCEPT-004): 无人值守下强制关闭 temp-mode/ip-mode 旁路——
        // 不提供任何临时放行未知设备的路径。
        unattended = cfg.unattended.enabled;
        if unattended {
            skip_whitelist = false;
        }
        info!(
            "Server: temp_mode={}, ip_mode={}, skip_whitelist={}, unattended={}",
            temp_mode, ip_mode, skip_whitelist, unattended
        );
        let mut audit = match kirin_desk_utils::audit::AuditLogger::open_default() {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!("audit log open error (audit disabled): {}", e);
                None
            }
        };
        let mut rate_limiter = kirin_desk_core::network::rate_limit::RateLimiter::new();
        // 审批桥：服务端线程 → GUI 弹窗（连接审批，SRV-SEC-WL）。
        let (pend_tx, pend_rx) = tokio::sync::mpsc::unbounded_channel::<PendingConnection>();
        let _ = pending_conn_tx().set(pend_tx);
        *pending_conn_rx().lock().unwrap() = Some(pend_rx);

        // Spawn server listener in a background thread
        let stop = server_stop_signal();
        stop.store(false, Ordering::Relaxed);
        let server_nickname = self.nickname.clone();
        let server_challenge = self.challenge_code.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create server runtime");
            rt.block_on(async {
                match kirin_desk_core::network::tcp::TcpServer::bind(port).await {
                    Ok(server) => {
                        info!("Server listening on port {}", server.port());
                        loop {
                            if stop.load(Ordering::Relaxed) {
                                info!("Server stopping by user request");
                                break;
                            }
                            match server.accept().await {
                                Ok((stream, addr)) => {
                                    info!("Incoming connection from {}", addr);
                                    // M15 (SRV-SEC-RL/AUDIT/KH/WL): 速率限制 → 审计 →
                                    // 两阶段握手（known_hosts/DNS pin + 白名单 + 审批）。
                                    let ip = addr.ip().to_canonical();
                                    audit_record(
                                        &mut audit,
                                        kirin_desk_utils::audit::AuditEvent::ConnectionRequest,
                                        &format!("ip={} port={}", ip, addr.port()),
                                    );
                                    if !matches!(
                                        rate_limiter.check_connect(&ip),
                                        RateLimitDecision::Allowed
                                    ) {
                                        audit_record(
                                            &mut audit,
                                            kirin_desk_utils::audit::AuditEvent::RateLimited,
                                            &format!("ip={}", ip),
                                        );
                                        warn!("Rate limited: {} — rejected", ip);
                                        continue;
                                    }
                                    // Use global identity as server identity
                                    if let Some(server_id) = global_identity().get() {
                                        let server_name = if server_nickname.is_empty() { "gui-server".to_string() } else { server_nickname.clone() };
                                        let expected_challenge = if server_challenge.is_empty() { None } else { Some(&*server_challenge) };
                                        // 1) 预读握手初始化消息（不应答）。
                                        let mut stream = stream;
                                        let init = match server_read_init(&mut stream).await {
                                            Ok(i) => i,
                                            Err(e) => {
                                                audit_record(
                                                    &mut audit,
                                                    kirin_desk_utils::audit::AuditEvent::HandshakeFailure,
                                                    &format!("ip={} error={}", ip, e),
                                                );
                                                rate_limiter.record_handshake_failure(&ip);
                                                continue;
                                            }
                                        };
                                        // 2) 客户端公钥解析（known_hosts → DNS TXT，SRV-SEC-KH-001）。
                                        let (expected_key, _resolution) = crate::policy::resolve_expected_client_key(&known, &cfg, &init.client_id).await;
                                        // 3) 白名单检查；未知公钥且非白名单 → 审批弹窗（temp/ip 模式跳过）。
                                        // M8-T017 (SRV-TMP-006): 临时连接窗口**逐连接**判定
                                        // （窗口中途开启/过期即时生效），与配置旁路取或；
                                        // 无人值守下窗口维度一并关闭（UA-ACCEPT-004）。
                                        let temp_window: Option<TempModeManager> = if unattended {
                                            None
                                        } else {
                                            crate::policy::temp_mode_window_manager()
                                        };
                                        let skip = skip_whitelist || temp_window.is_some();
                                        let is_whitelisted = allowed.iter().any(|a| domain_matches_whitelist(&init.client_domain, a));
                                        if !skip && !is_whitelisted && expected_key.is_none() {
                                            // M13-T005 (UA-ACCEPT-002): 无人值守下
                                            // 未知设备自动拒绝——无人工审批弹窗，
                                            // 立即审计 + 记握手失败后断开。
                                            if unattended {
                                                audit_record(
                                                    &mut audit,
                                                    kirin_desk_utils::audit::AuditEvent::AuthFailure,
                                                    &format!("ip={} client={} reason=unattended_unknown", ip, init.client_id),
                                                );
                                                rate_limiter.record_handshake_failure(&ip);
                                                warn!(
                                                    "Unattended: unknown client {} ({}) rejected — no approval in unattended mode",
                                                    init.client_id, ip
                                                );
                                                continue;
                                            }
                                            let id = pending_next_id();
                                            let (dec_tx, dec_rx) = tokio::sync::oneshot::channel::<bool>();
                                            pending_decisions().lock().unwrap().insert(id, dec_tx);
                                            let pc = PendingConnection {
                                                id,
                                                client_id: init.client_id.clone(),
                                                client_domain: init.client_domain.clone(),
                                                device_type: init.client_device_type.clone(),
                                                status: PendingStatus::Waiting,
                                            };
                                            if let Some(tx) = pending_conn_tx().get() {
                                                let _ = tx.send(pc);
                                            }
                                            // 等待用户决策（60s 超时）。
                                            match tokio::time::timeout(
                                                std::time::Duration::from_secs(60),
                                                dec_rx,
                                            )
                                            .await
                                            {
                                                Ok(Ok(true)) => {} // 用户接受 → 继续握手
                                                _ => {
                                                    audit_record(
                                                        &mut audit,
                                                        kirin_desk_utils::audit::AuditEvent::AuthFailure,
                                                        &format!("ip={} client={} approval declined/timeout", ip, init.client_id),
                                                    );
                                                    rate_limiter.record_handshake_failure(&ip);
                                                    continue;
                                                }
                                            }
                                        }
                                        // 4) pin/nickname/challenge/签名校验 + 应答。
                                        // M8-T017 (SRV-TMP-HK-001/003): 挑战码二态——固定
                                        // 挑战码 **或** 窗口内临时挑战码任一正确即通过。
                                        if let Err(e) = verify_server_init_with_temp(
                                            &init,
                                            expected_key.as_deref().unwrap_or(""),
                                            expected_nick.as_deref(),
                                            expected_challenge,
                                            temp_window.as_ref(),
                                        ) {
                                            audit_record(
                                                &mut audit,
                                                kirin_desk_utils::audit::AuditEvent::HandshakeFailure,
                                                &format!("ip={} error={}", ip, e),
                                            );
                                            rate_limiter.record_handshake_failure(&ip);
                                            continue;
                                        }
                                        let g = match server_handshake_respond_generic(
                                            stream, server_id, &server_name, &init, "",
                                        )
                                        .await
                                        {
                                            Ok(g) => g,
                                            Err(e) => {
                                                audit_record(
                                                    &mut audit,
                                                    kirin_desk_utils::audit::AuditEvent::HandshakeFailure,
                                                    &format!("ip={} error={}", ip, e),
                                                );
                                                rate_limiter.record_handshake_failure(&ip);
                                                continue;
                                            }
                                        };
                                        let ch = SecureChannel {
                                            stream: g.stream,
                                            cipher: g.cipher,
                                            peer_id: g.peer_id,
                                            peer_domain: g.peer_domain,
                                            peer_device_type: g.peer_device_type,
                                            selected_codec: g.selected_codec,
                                        };
                                        audit_record(
                                            &mut audit,
                                            kirin_desk_utils::audit::AuditEvent::HandshakeSuccess,
                                            &format!("ip={} client={} <{}>", ip, ch.peer_id, ch.peer_domain),
                                        );
                                        rate_limiter.reset(&ip);
                                        crate::policy::record_successful_handshake(&mut known, &ch.peer_id);
                                        info!("Handshake SUCCESS with {}", addr);
                                        // M13-T005 (UA-ACCEPT-003): 会话类型分发——
                                        // 客户端声明 "shell" → PTY 桥接（无头/远程终端）；
                                        // 其余（desktop）→ 远程桌面（捕获+编码+输入注入）。
                                        // 单端口统一监听，远控与 shell 会话互不冲突
                                        // （shell 仅服务端处于无头服务器模式时使用）。
                                        if ch.peer_device_type == "shell" {
                                            use kirin_desk_core::connection::{
                                                run_shell_bridge, DEFAULT_PTY_COLS, DEFAULT_PTY_ROWS,
                                            };
                                            let peer_id = ch.peer_id.clone();
                                            info!("Session type: shell — bridging PTY for {}", peer_id);
                                            let result = run_shell_bridge(
                                                ch,
                                                DEFAULT_PTY_COLS,
                                                DEFAULT_PTY_ROWS,
                                                None,
                                            )
                                            .await;
                                            audit_record(
                                                &mut audit,
                                                kirin_desk_utils::audit::AuditEvent::Disconnect,
                                                &format!("ip={} client={} shell", ip, peer_id),
                                            );
                                            match result {
                                                Ok(()) => info!("Shell session closed: {}", addr),
                                                Err(e) => warn!("Shell session ended with error: {}", e),
                                            }
                                            continue;
                                        }
                                        // M9: 拆分读写半通道——视频发送（写）+ 输入接收（读），
                                        // 各方向单任务独占、无锁并发。
                                        // M13-T006: 写半由多任务共享（视频捕获 + 文件传输），
                                        // 用 Arc<Mutex<SecureChannelSender>> 保证帧边界。
                                        let peer_id_ft = ch.peer_id.clone();
                                        let (reader, writer) = ch.into_split();
                                        // Store channel halves for capture streaming + input injection
                                        if let Ok(mut c) = server_channel().lock() {
                                            *c = Some((
                                                SecureChannelReceiver::new(reader),
                                                SecureChannelSender::new(writer),
                                            ));
                                        }

                                                // M8: 窗口式媒体传输捕获循环 (DXGI + WindowPipeline + EncodedWindow)
                                                let stop_capture = server_stop_signal();
                                                tokio::spawn(async move {
                                                    use kirin_desk_media::capture::create_capture_source;
                                                    use kirin_desk_media::encoder::types::Codec;
                                                    use kirin_desk_media::VideoEncoderPipeline;
                                                    use kirin_desk_media::window_pipeline::WindowPipeline;
                                                    use kirin_desk_media::proto::{EncodeConfig, RawFrame, WindowConfig};
                                                    use std::time::Duration;

                                                    // Wait briefly for the channel to settle
                                                    tokio::time::sleep(Duration::from_millis(200)).await;

                                                    // 1. Create DXGI capture source on monitor 0
                                                    let mut capture = match create_capture_source(0) {
                                                        Ok(c) => c,
                                                        Err(e) => {
                                                            error!("Failed to create capture source: {}", e);
                                                            return;
                                                        }
                                                    };
                                                    let (width, height) = capture.resolution();
                                                    info!("Capture: DXGI source created, {}x{}", width, height);

                                                    // 2. Create video encoder pipeline (P1C: VideoEncoderPipeline,
                                                    //    HW 优先 + libx264 软编回退)
                                                    let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
                                                        Ok(e) => e,
                                                        Err(e) => {
                                                            error!("Failed to create video encoder pipeline: {}", e);
                                                            return;
                                                        }
                                                    };
                                                    info!("Capture: video encoder '{}' created (hw={})", encoder.name(), encoder.is_hardware());

                                                    // 3. Create window pipeline
                                                    let mut pipeline = WindowPipeline::new(
                                                        WindowConfig::default(),
                                                        encoder,
                                                    );
                                                    pipeline.update_encode_config(EncodeConfig {
                                                        qp: 26,
                                                        force_idr: false,
                                                        frame_ratio: 1.0,
                                                        preset: "ultrafast".into(),
                                                    });

                                                    // Take channel halves once（输入接收读半 → 分发任务；视频发送写半 → 本任务）
                                                    let (mut receiver, sender) = match server_channel().lock().unwrap().take() {
                                                        Some(parts) => parts,
                                                        None => {
                                                            error!("Server channel lost before capture start");
                                                            return;
                                                        }
                                                    };
                                                    let sender_shared: Arc<tokio::sync::Mutex<SecureChannelSender>> =
                                                        Arc::new(tokio::sync::Mutex::new(sender));

                                                    // M13-T006: 服务端文件命令/帧事件通道。
                                                    let (server_file_cmd_tx, mut server_file_cmd_rx) =
                                                        tokio::sync::mpsc::unbounded_channel::<FileCommand>();
                                                    let (server_file_frame_tx, mut server_file_frame_rx) =
                                                        tokio::sync::mpsc::unbounded_channel::<FileTransferFrame>();
                                                    *server_file_tx().lock().unwrap() = Some(server_file_cmd_tx);

                                                    // M13-T006: 服务端文件会话任务（接收落盘 + 推送下载）。
                                                    {
                                                        let sender_ft = sender_shared.clone();
                                                        let my_id = global_identity().get().map(|i| i.public_key_base64()).unwrap_or_default();
                                                        let salt = file_transfer_salt(&my_id, &peer_id_ft);
                                                        let cfg_ft = kirin_desk_utils::config::Config::load().unwrap_or_default();
                                                        let store_path = transfers_store_path("server");
                                                        let download_dir = cfg_ft.file_transfer.resolved_download_dir();
                                                        let max_file_size = if cfg_ft.file_transfer.max_file_size > 0 {
                                                            cfg_ft.file_transfer.max_file_size
                                                        } else {
                                                            DEFAULT_MAX_FILE_SIZE
                                                        };
                                                        tokio::spawn(async move {
                                                            let mut ft = FileSession::new(
                                                                sender_ft,
                                                                server_file_panel_state(),
                                                                salt,
                                                                store_path,
                                                                download_dir,
                                                                max_file_size,
                                                                Some(server_file_notices()),
                                                            );
                                                            let mut tick = tokio::time::interval(Duration::from_secs(1));
                                                            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                                                            loop {
                                                                tokio::select! {
                                                                    cmd = server_file_cmd_rx.recv() => {
                                                                        let Some(cmd) = cmd else {
                                                                            tracing::info!("Server file session exited");
                                                                            break;
                                                                        };
                                                                        ft.handle_command(cmd).await;
                                                                    }
                                                                    frame = server_file_frame_rx.recv() => {
                                                                        let Some(frame) = frame else {
                                                                            tracing::info!("Server file session exited (recv loop closed)");
                                                                            break;
                                                                        };
                                                                        ft.handle_frame(frame).await;
                                                                    }
                                                                    _ = tick.tick() => {
                                                                        ft.on_tick().await;
                                                                    }
                                                                }
                                                            }
                                                            *server_file_tx().lock().unwrap() = None;
                                                        });
                                                    }

                                                    // M9/M13-T006: 服务端接收分发任务——Input → 注入；
                                                    // FileTransfer → 文件会话；其他 tag 忽略。
                                                    let stop_input = stop_capture;
                                                    let file_frame_tx_dispatch = server_file_frame_tx.clone();
                                                    // M8-T020 SKEY-SEC-002: 锁屏请求审计 detail（对端身份）。
                                                    let audit_peer = format!("ip={} client={}", ip, peer_id_ft);
                                                    // M8-T019 (SRV-PRIV-010/014): 服务端隐私控制器——
                                                    // GUI 模式（headless=false）可绘制黑屏覆盖窗口；
                                                    // 接收任务与 UI 线程共享（UI 每帧轮询 active_level）。
                                                    let privacy_controller =
                                                        Arc::new(Mutex::new(PrivacyController::new(false)));
                                                    *server_privacy_controller().lock().unwrap() =
                                                        Some(privacy_controller.clone());
                                                    // M8-T019 (PRIV-SEC-001): 隐私审计独立句柄
                                                    // （append 模式多句柄并发安全；与主审计流互不干扰）。
                                                    let mut privacy_audit =
                                                        kirin_desk_utils::audit::AuditLogger::open_default().ok();
                                                    let sender_privacy = sender_shared.clone();
                                                    // M8-T018: 显示器切换命令通道（分发任务 → 捕获循环；
                                                    // 热切换重建捕获源，无需重连）。
                                                    let (switch_monitor_tx, mut switch_monitor_rx) =
                                                        tokio::sync::mpsc::unbounded_channel::<u32>();
                                                    // M8-T018（SRV-MON-010）：注入器在分发任务与捕获循环
                                                    // 间共享——显示器切换后同步更新换算基准（src/dst = 新屏
                                                    // 分辨率）。键鼠事件 ~60fps，切换低频，锁竞争可忽略。
                                                    let injector = Arc::new(tokio::sync::Mutex::new(
                                                        InputInjector::new(width, height, width, height),
                                                    ));
                                                    // 捕获循环持有的另一句柄（切换成功后更新基准）。
                                                    let injector_capture = injector.clone();
                                                    tokio::spawn(async move {
                                                        // src = 客户端坐标空间：客户端按服务端捕获分辨率
                                                        // (base_w/base_h) 发像素坐标 → src == dst。
                                                        let injector_dispatch = injector;
                                                        let switch_monitor_tx_dispatch = switch_monitor_tx.clone();
                                                        let mut dropped_input: u64 = 0;
                                                        // M8-T019 (SRV-PRIV-015): 锁屏解锁轮询节流（1s）。
                                                        let mut last_unlock_poll =
                                                            std::time::Instant::now() - Duration::from_secs(1);
                                                        loop {
                                                            if stop_input.load(Ordering::Relaxed) {
                                                                info!("Input receive loop stopping by user request");
                                                                break;
                                                            }
                                                            // M8-T019 (SRV-PRIV-015): 锁屏被本地解锁 →
                                                            // 自动恢复注入 + 通知客户端（无需重连）。
                                                            if last_unlock_poll.elapsed()
                                                                >= Duration::from_secs(1)
                                                            {
                                                                last_unlock_poll = std::time::Instant::now();
                                                                let resumed = privacy_controller
                                                                    .lock()
                                                                    .unwrap()
                                                                    .poll_unlock();
                                                                if resumed {
                                                                    audit_record(
                                                                        &mut privacy_audit,
                                                                        kirin_desk_utils::audit::AuditEvent::PrivacyRecovered,
                                                                        "event=unlock level=lock initiator=local",
                                                                    );
                                                                    info!("[Privacy] workstation unlocked — injection resumed");
                                                                    send_privacy_ack(
                                                                        &sender_privacy,
                                                                        true,
                                                                        None,
                                                                    )
                                                                    .await;
                                                                }
                                                            }
                                                            let (tag, _header, payload) = match receiver.recv_tagged().await {
                                                                Ok(v) => v,
                                                                Err(e) => {
                                                                    error!("Receive channel error: {} — stopping", e);
                                                                    break;
                                                                }
                                                            };
                                                            match tag {
                                                                ChannelTag::Input => {
                                                                    // M8-T019 (SRV-PRIV-015): 锁屏期间注入暂停
                                                                    // （SendInput 对安全桌面无效），解锁自动恢复。
                                                                    if privacy_controller
                                                                        .lock()
                                                                        .unwrap()
                                                                        .injection_paused()
                                                                    {
                                                                        dropped_input += 1;
                                                                        if dropped_input % 200 == 1 {
                                                                            warn!(
                                                                                "[Privacy] input dropped during lock ({} events)",
                                                                                dropped_input
                                                                            );
                                                                        }
                                                                        continue;
                                                                    }
                                                                    match bincode::deserialize::<WireInputEvent>(&payload) {
                                                                        Ok(ev) => {
                                                                            // M8-T020 SKEY-SEC-002: 锁屏请求写审计日志
                                                                            // （锁屏调用本身由注入管线执行，单一实现 =
                                                                            // M8-T019 privacy::platform_lock_screen）。
                                                                            if ev.kind == InputKind::SpecialKey
                                                                                && ev.combo == Some(SpecialCombo::LockScreen)
                                                                            {
                                                                                if let Ok(mut audit) =
                                                                                    kirin_desk_utils::audit::AuditLogger::open_default()
                                                                                {
                                                                                    let _ = audit.record(
                                                                                        kirin_desk_utils::audit::AuditEvent::LockScreen,
                                                                                        &format!("{audit_peer} combo=LockScreen"),
                                                                                    );
                                                                                }
                                                                            }
                                                                            // 注入失败不重试（可靠流不重发用户操作），仅记日志。
                                                                            let mut inj = injector_dispatch
                                                                                .lock()
                                                                                .await;
                                                                            if let Err(e) = inj.handle(ev) {
                                                                                warn!("Input inject failed (dropping, no retry): {}", e);
                                                                            }
                                                                        }
                                                                        Err(e) => warn!("Input event deserialize failed: {}", e),
                                                                    }
                                                                }
                                                                // M8-T019 (SRV-PRIV-001/002/013 + PRIV-SEC-001):
                                                                // 隐私模式控制（复用 M8-T018 控制通道）。
                                                                // M8-T018: 显示器枚举/切换控制（同通道分发）。
                                                                ChannelTag::Control => {
                                                                    match bincode::deserialize::<ControlMessage>(
                                                                        &payload,
                                                                    ) {
                                                                        Ok(ControlMessage::DisplayListReq) => {
                                                                            // M8-T018（SRV-CAP-MON-001）：枚举显示器
                                                                            // → DisplayListResp（空时兜底默认屏）。
                                                                            let displays = kirin_desk_media::capture::factory::enumerate_monitors();
                                                                            if let Ok(data) = bincode::serialize(
                                                                                &ControlMessage::DisplayListResp { displays },
                                                                            ) {
                                                                                let pkt = EncodedPacket {
                                                                                    ts: Timestamp::now(),
                                                                                    kind: PacketKind::Control,
                                                                                    data,
                                                                                    is_key: false,
                                                                                };
                                                                                if let Err(e) = sender_privacy
                                                                                    .lock()
                                                                                    .await
                                                                                    .send_packets(&[pkt])
                                                                                    .await
                                                                                {
                                                                                    warn!("DisplayListResp send failed: {}", e);
                                                                                }
                                                                            }
                                                                        }
                                                                        Ok(ControlMessage::DisplaySelect { index }) => {
                                                                            // M8-T018（SRV-MON-003）：捕获循环热切换；
                                                                            // 越界/重建失败 → Nack（捕获循环回复）。
                                                                            if switch_monitor_tx_dispatch.send(index).is_err() {
                                                                                warn!("DisplaySelect: switch channel closed");
                                                                            }
                                                                        }
                                                                        // 其余控制消息（PrivacyMode 等）→ 既有隐私处理
                                                                        // （其内部忽略非 PrivacyMode 消息）。
                                                                        Ok(_) => {
                                                                            handle_server_privacy_message(
                                                                                &payload,
                                                                                &privacy_controller,
                                                                                &sender_privacy,
                                                                                &mut privacy_audit,
                                                                                &audit_peer,
                                                                            )
                                                                            .await;
                                                                        }
                                                                        Err(e) => {
                                                                            warn!("Control message deserialize failed: {}", e);
                                                                        }
                                                                    }
                                                                }
                                                                ChannelTag::FileTransfer => {
                                                                    match FileTransferFrame::decode(&payload) {
                                                                        Ok(frame) => {
                                                                            if file_frame_tx_dispatch.send(frame).is_err() {
                                                                                break;
                                                                            }
                                                                        }
                                                                        Err(e) => warn!("File frame decode failed: {}", e),
                                                                    }
                                                                }
                                                                // 其余 tag（Video/Audio/Clipboard 等）无服务端消费方，静默忽略。
                                                                _ => {}
                                                            }
                                                        }
                                                        // M8-T019 (SRV-PRIV-014 安全红线): 断连/停止 →
                                                        // 本地状态复位（黑屏覆盖随之关闭，无网络依赖）。
                                                        if let Some(was) = privacy_controller
                                                            .lock()
                                                            .unwrap()
                                                            .on_connection_lost()
                                                        {
                                                            audit_record(
                                                                &mut privacy_audit,
                                                                kirin_desk_utils::audit::AuditEvent::PrivacyRecovered,
                                                                &format!(
                                                                    "event=disconnect level={} initiator=system",
                                                                    was.as_str()
                                                                ),
                                                            );
                                                            info!(
                                                                "[Privacy] connection lost — privacy state restored ({})",
                                                                was.as_str()
                                                            );
                                                        }
                                                        *server_privacy_controller().lock().unwrap() = None;
                                                    });
                                                    info!("Capture loop started (DXGI event-driven + 70ms windows)");

                                                    let mut window_count: u64 = 0;
                                                    // M8-T018（SRV-CAP-MON-003）：显示器切换成功后，
                                                    // 下一窗口强制 IDR（客户端切换后立即可解码）。
                                                    let mut force_idr_next = false;

                                                        loop {
                                                            if stop_capture.load(Ordering::Relaxed) {
                                                                info!("Capture loop stopping by user request");
                                                                break;
                                                            }

                                                            // M8-T018（SRV-CAP-MON-002）：显示器切换命令——
                                                            // 会话内热切换（重建捕获源，无需重连）。失败回退
                                                            // 当前屏 + Nack（MON-NF-001）。
                                                            if let Ok(idx) = switch_monitor_rx.try_recv() {
                                                                match capture.switch_monitor(idx as usize) {
                                                                    Ok(()) => {
                                                                        let (sw, sh) = capture.resolution();
                                                                        info!(
                                                                            "Capture: switched to monitor {} ({}x{})",
                                                                            idx, sw, sh
                                                                        );
                                                                        force_idr_next = true;
                                                                        // M8-T018（SRV-MON-010）：注入换算基准
                                                                        // 跟随新屏分辨率（客户端基数同步切换）。
                                                                        let mut inj = injector_capture.lock().await;
                                                                        inj.set_resolution(sw, sh);
                                                                    }
                                                                    Err(e) => {
                                                                        error!(
                                                                            "Capture: switch monitor {} failed: {} — keeping current",
                                                                            idx, e
                                                                        );
                                                                        let reason = format!(
                                                                            "switch monitor {idx} failed: {e}"
                                                                        );
                                                                        if let Ok(data) = bincode::serialize(
                                                                            &ControlMessage::DisplaySelectNack { reason },
                                                                        ) {
                                                                            let pkt = EncodedPacket {
                                                                                ts: Timestamp::now(),
                                                                                kind: PacketKind::Control,
                                                                                data,
                                                                                is_key: false,
                                                                            };
                                                                            if let Err(e2) = sender_shared
                                                                                .lock()
                                                                                .await
                                                                                .send_packets(&[pkt])
                                                                                .await
                                                                            {
                                                                                warn!("DisplaySelectNack send failed: {}", e2);
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }

                                                            // Wait for a fresh screen frame (blocks until change)
                                                            // M8-T018（MON-NF-002）：带超时等待——静默屏幕
                                                            // （长时间无画面变化）也定期醒来处理切换命令，
                                                            // 切换延迟与屏幕活动度解耦（目标 <500ms）。
                                                            match capture.wait_for_frame_timeout(Duration::from_millis(200)) {
                                                                Ok(frame) => {
                                                                    let raw = RawFrame {
                                                                        data: Arc::new(frame.data().to_vec()),
                                                                        width: frame.width(),
                                                                        height: frame.height(),
                                                                        timestamp: std::time::SystemTime::now(),
                                                                        dirty_rects: frame.dirty_rects().to_vec(),
                                                                        force_key: window_count == 0 || force_idr_next,
                                                                    };
                                                                    force_idr_next = false;
                                                                    // push_frame already returns the EncodedWindow if window closes
                                                                    match pipeline.push_frame(raw) {
                                                                        Ok(Some(encoded_window)) => {
                                                                            window_count = encoded_window.window_id;
                                                                            let n_frames = encoded_window.frame_count;
                                                                            info!("Capture: window {} encoded ({} frames, {}x{})",
                                                                                encoded_window.window_id, n_frames,
                                                                                encoded_window.base_w, encoded_window.base_h);

                                                                            // Serialize and send over SecureChannel (tag 分帧 Video)
                                                                            match bincode::serialize(&encoded_window) {
                                                                                Ok(bytes) => {
                                                                                    let pkt = EncodedPacket {
                                                                                        ts: Timestamp::now(),
                                                                                        kind: PacketKind::Video,
                                                                                        data: bytes,
                                                                                        is_key: window_count == 0,
                                                                                    };
                                                                                    if let Err(e) = sender_shared.lock().await.send_packets(&[pkt]).await {
                                                                                        error!("Capture send error window {}: {} — closing", encoded_window.window_id, e);
                                                                                        break;
                                                                                    }
                                                                                }
                                                                                Err(e) => {
                                                                                    error!("Serialize window {} failed: {}", encoded_window.window_id, e);
                                                                                }
                                                                            }
                                                                        }
                                                                        Ok(None) => {
                                                                            // still collecting frames for this window
                                                                        }
                                                                        Err(e) => {
                                                                            error!("Window pipeline error: {} — retrying", e);
                                                                            tokio::time::sleep(Duration::from_millis(50)).await;
                                                                        }
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    // Fatal errors: break the capture loop (connection lost, no monitor)
                                                                    // Transient errors: retry with backoff
                                                                    match &e {
                                                                        // M8-T018（MON-NF-002）：静默屏幕超时——
                                                                        // 定期醒来轮询显示器切换命令，无需日志。
                                                                        CaptureError::Timeout => continue,
                                                                        CaptureError::AccessLost => {
                                                                            error!("Capture access lost — closing connection, will recreate");
                                                                            break;
                                                                        }
                                                                        CaptureError::NoMonitor | CaptureError::InvalidMonitor => {
                                                                            error!("Capture: {} — stopping capture", e);
                                                                            break;
                                                                        }
                                                                        _ => {
                                                                            error!("Capture error: {} — sleeping and retrying", e);
                                                                            tokio::time::sleep(Duration::from_millis(100)).await;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        info!("Capture loop exited after {} windows", window_count);

                                                        // 连接退出：清空（输入任务因 recv 失败自行退出）
                                                        *server_channel().lock().unwrap() = None;
                                                });
                                    } else {
                                        error!("No server identity available, rejecting {}", addr);
                                    }
                                }
                                Err(e) => {
                                    error!("Accept error: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Server bind error on port {}: {}", port, e);
                    }
                }
            });
        });
    }

    fn show_devices(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        ui.heading("Devices");
        ui.separator();
        if self.devices.is_empty() {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(
                        "No saved devices yet. Connect to a device first — it is saved automatically.",
                    )
                    .size(theme.small_size)
                    .color(theme.fg_weak),
                )
                .selectable(false),
            );
        } else {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(format!(
                        "{} saved device(s) — 单击自动填入 Connect 页，右键打开菜单",
                        self.devices.len()
                    ))
                    .size(theme.small_size)
                    .color(theme.fg_weak),
                )
                .selectable(false),
            );
            egui::ScrollArea::vertical().show(ui, |ui| {
                for i in 0..self.devices.len() {
                    let d = self.devices[i].clone();
                    // M15-T008: 设备卡片——StatusDot + 设备名@IP + 类型徽标 + 上次在线。
                    // 状态点：SavedDevice 无实时 status 字段 → 中性停止态（fg_weak "saved"，
                    // 方案 §3.1 停止态映射；实时在线状态待 M9 联调期补充）。
                    // M8-T028 (UI-BTY-025): 主标题整串（昵称@域名 / 昵称@[IPv6]:端口）与
                    // 地址行纯连接地址（[IPv6]:端口）各带 📋；行内预留 32px（26 按钮 + 6 间距），
                    // 按钮在卡片点击层之后注册（同层后注册者优先命中）→ 不改变单击填入/右键菜单。
                    let name = if d.domain.is_empty() {
                        format!("{}@[{}]:{}", d.nickname, d.ipv6, d.port)
                    } else {
                        format!("{}@{}", d.nickname, d.domain)
                    };
                    let addr = if d.domain.is_empty() {
                        None
                    } else {
                        Some(format!("[{}]:{}", d.ipv6, d.port))
                    };
                    let mut title_rect: Option<egui::Rect> = None;
                    let mut addr_rect: Option<egui::Rect> = None;
                    let card = egui::Frame::none()
                        .fill(theme.bg_panel)
                        .stroke(egui::Stroke::new(theme.border_width, theme.border))
                        .rounding(theme.rounding_card)
                        .inner_margin(egui::Margin::same(theme.card_padding))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                status_dot(ui, theme.fg_weak, "saved");
                                let tr = ui.add(
                                    egui::Label::new(egui::RichText::new(&name).strong())
                                        .selectable(true),
                                );
                                title_rect = Some(tr.rect);
                                ui.add_space(32.0); // 📋 预留
                                // 类型徽标（server=info / desktop=neutral）
                                let (kind, label) = if d.device_type == "server" {
                                    (BadgeKind::Info, "server")
                                } else {
                                    (BadgeKind::Neutral, "desktop")
                                };
                                badge(ui, theme, label, kind);
                                if let Some(addr) = &addr {
                                    let ar = ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(addr)
                                                .monospace()
                                                .size(theme.small_size)
                                                .color(theme.fg_weak),
                                        )
                                        .selectable(true),
                                    );
                                    addr_rect = Some(ar.rect);
                                    ui.add_space(32.0); // 📋 预留
                                }
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(format_last_seen(d.last_seen))
                                                    .size(theme.small_size)
                                                    .color(theme.fg_weak),
                                            )
                                            .selectable(false),
                                        );
                                    },
                                );
                            });
                        });
                    // M15-T008: Frame 只给 hover 感知 → 叠加点击交互层（单击填入 / 右键菜单）。
                    let rect = card.response.rect;
                    let click = ui.interact(
                        rect,
                        ui.id().with(("dev_card", i)),
                        egui::Sense::click(),
                    );
                    // M8-T028: 📋 按钮注册于卡片点击层之后（同层后注册者优先命中）——
                    // 按钮可点，卡片单击填入/右键菜单行为不变。
                    let mut copied: Option<String> = None;
                    let mut place_btn = |ui: &mut egui::Ui, r: egui::Rect, text: &str| {
                        let (_, was_copied) = ui
                            .allocate_ui_at_rect(
                                egui::Rect::from_min_size(
                                    egui::pos2(r.max.x + 6.0, r.center().y - 10.0),
                                    egui::vec2(26.0, 20.0),
                                ),
                                |ui| copy_button(ui, theme, text),
                            )
                            .inner;
                        if was_copied {
                            copied = Some(text.to_owned());
                        }
                    };
                    if let Some(r) = title_rect {
                        place_btn(ui, r, &name);
                    }
                    if let (Some(r), Some(addr)) = (addr_rect, &addr) {
                        place_btn(ui, r, addr);
                    }
                    if let Some(v) = copied {
                        self.notify_copied(&v);
                    }
                    if click.hovered() {
                        ui.painter().rect_stroke(
                            rect,
                            egui::Rounding::same(theme.rounding_card),
                            egui::Stroke::new(1.5, theme.primary),
                        );
                    }
                    // M10-T004: 单击 → 自动填入 Connect 页并切换标签页。
                    if click.clicked() {
                        self.fill_connect_from_device(&d);
                    }
                    // M10-T004/T005: 右键菜单 — 连接 / 编辑 / 删除。
                    click.context_menu(|ui| {
                        if ui.button("连接").clicked() {
                            self.fill_connect_from_device(&d);
                            ui.close_menu();
                        }
                        if ui.button("编辑").clicked() {
                            self.start_edit_device(&d);
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("删除").clicked() {
                            self.delete_device(&d.id);
                            ui.close_menu();
                        }
                    });
                }
            });
        }

        // M10-T005: 设备编辑弹窗（昵称 / 域名 / 端口）。
        if let Some(id) = self.editing_device.clone() {
            let mut open = true;
            egui::Window::new("编辑设备")
                .collapsible(false)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("设备 ID: {}", id))
                                    .monospace()
                                    .size(theme.mono_size)
                                    .color(theme.fg_weak),
                            )
                            .selectable(true),
                        );
                        // M8-T028 (UI-BTY-027): 设备 ID 只读行一键复制。
                        self.copied_button(ui, theme, &id);
                    });
                    ui.separator();
                    labeled_input(
                        ui,
                        theme,
                        "昵称:",
                        &mut self.edit_nickname,
                        "",
                        Validity::None,
                        None,
                        false,
                    );
                    labeled_input(
                        ui,
                        theme,
                        "域名:",
                        &mut self.edit_domain,
                        "",
                        Validity::None,
                        None,
                        true,
                    );
                    labeled_input(
                        ui,
                        theme,
                        "端口:",
                        &mut self.edit_port,
                        "",
                        Validity::None,
                        None,
                        true,
                    );
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("保存").clicked() {
                            let fallback = self
                                .devices
                                .iter()
                                .find(|d| d.id == id)
                                .map(|d| d.port)
                                .unwrap_or(3389);
                            let port = self.edit_port.trim().parse().unwrap_or(fallback);
                            self.commit_device_edit(&id, port);
                            open = false;
                        }
                        if ui.button("取消").clicked() {
                            open = false;
                        }
                    });
                });
            if !open {
                self.editing_device = None;
            }
        }
    }

    /// M10-T004: 设备 → 自动填入 Connect 页并切换标签页。
    /// 有域名且 API 已配置 → Domain 模式（DNS 发现）；否则 IP 模式直连。
    fn fill_connect_from_device(&mut self, d: &SavedDevice) {
        self.connect_nickname = d.nickname.clone();
        if !d.domain.is_empty() && !self.api_key.trim().is_empty() && !self.api_secret.trim().is_empty()
        {
            self.connect_domain = d.domain.clone();
            self.ip_mode_allowed = false; // 切换 Domain 模式界面（仅内存，不写回配置）
            self.connect_status = format!("Ready: {}@{}（Domain 模式自动发现）", d.nickname, d.domain);
        } else {
            self.connect_ipv6 = d.ipv6.clone();
            self.connect_port = d.port.to_string();
            self.ip_mode_allowed = true;
            self.connect_status = format!("Ready: {}@[{}]:{}", d.nickname, d.ipv6, d.port);
        }
        self.current_tab = Tab::Connect;
    }

    /// M10-T005: 打开设备编辑弹窗（预填当前值）。
    fn start_edit_device(&mut self, d: &SavedDevice) {
        self.editing_device = Some(d.id.clone());
        self.edit_nickname = d.nickname.clone();
        self.edit_domain = d.domain.clone();
        self.edit_port = d.port.to_string();
    }

    /// M10-T005: 提交编辑 → 持久化到 devices.json → 刷新列表。
    fn commit_device_edit(&mut self, id: &str, port: u16) {
        let nickname = self.edit_nickname.trim().to_string();
        let domain = self.edit_domain.trim().to_string();
        if nickname.is_empty() {
            self.editing_device = None;
            return;
        }
        match DeviceStore::load() {
            Ok(mut store) => {
                if store.update(id, &nickname, &domain, port) {
                    if let Err(e) = store.save() {
                        tracing::error!("Edit device save failed: {}", e);
                    }
                }
                self.devices = store.devices().to_vec();
            }
            Err(e) => tracing::error!("Edit device: store load failed: {}", e),
        }
        self.editing_device = None;
    }

    /// M10-T005: 删除设备记录 → 持久化 → 刷新列表。
    fn delete_device(&mut self, id: &str) {
        match DeviceStore::load() {
            Ok(mut store) => {
                store.remove(id);
                if let Err(e) = store.save() {
                    tracing::error!("Delete device save failed: {}", e);
                }
                self.devices = store.devices().to_vec();
                tracing::info!("Device '{}' removed from saved devices", id);
            }
            Err(e) => tracing::error!("Delete device: store load failed: {}", e),
        }
    }

    /// 从 devices.json 重新加载设备列表（文件不存在 → 空列表）。
    fn reload_devices(&mut self) {
        match DeviceStore::load() {
            Ok(store) => self.devices = store.devices().to_vec(),
            Err(e) => tracing::warn!("Devices: reload failed: {}", e),
        }
    }

    fn show_connect(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        ui.heading("Connect to Device");
        ui.separator();

        // Show connection status from background threads
        // M10-T001: 状态机着色——已连接绿 / 进行中（发现中→连接中→握手）蓝 / 失败红。
        // M15-T008: StatusDot 化（● + 语义色）。
        let status = connection_status().lock().unwrap().clone();
        if !status.is_empty() {
            let color = if status.starts_with("Connected") {
                theme.success
            } else if status.starts_with("Discovering")
                || status.starts_with("Connecting")
                || status.starts_with("Handshaking")
            {
                theme.info
            } else {
                theme.danger
            };
            status_dot(ui, color, &status);
            ui.separator();
        }

        // M15-T008: 模式行改 SegmentedControl（IP/Domain，选中项品牌色底）
        // M8-T026-P2 (ID-021): 新增第三段「ID Mode」（relay 设备 ID）。
        let mut mode = if self.connect_id_mode {
            2
        } else if self.ip_mode_allowed {
            0
        } else {
            1
        };
        if segmented_control(
            ui,
            theme,
            &[
                "IP Mode (direct IPv6 connection)",
                "Domain Mode (DNS-based discovery)",
                "ID Mode (relay device ID)",
            ],
            &mut mode,
        ) {
            self.ip_mode_allowed = mode == 0;
            self.connect_id_mode = mode == 2;
        }
        ui.separator();

        if self.ip_mode_allowed {
            // M15-T008: 表单校验——IPv6 合法 / 端口 1-65535 / 昵称与挑战码必填（UI-CON-010/022）
            let ip_empty = self.connect_ipv6.trim().is_empty();
            let ip_ok = self.connect_ipv6.trim().parse::<std::net::Ipv6Addr>().is_ok();
            let port_empty = self.connect_port.trim().is_empty();
            let port_ok = self
                .connect_port
                .trim()
                .parse::<u16>()
                .map(|p| p > 0)
                .unwrap_or(false);
            let nick_ok = !self.connect_nickname.trim().is_empty();
            let chal_ok = !self.connect_challenge.trim().is_empty();

            labeled_input(
                ui,
                theme,
                "IPv6 Address:",
                &mut self.connect_ipv6,
                "2001:db8::1",
                if ip_empty {
                    Validity::None
                } else if ip_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid("Not a valid IPv6 address")
                },
                None,
                true,
            );
            labeled_input(
                ui,
                theme,
                "Port:",
                &mut self.connect_port,
                "3389",
                if port_empty {
                    Validity::None
                } else if port_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid("Port must be 1-65535")
                },
                None,
                true,
            );
            labeled_input(
                ui,
                theme,
                "Nickname (sent to server):",
                &mut self.connect_nickname,
                "required",
                if nick_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid("Nickname is required")
                },
                None,
                false,
            );
            labeled_input(
                ui,
                theme,
                "Challenge (sent to server):",
                &mut self.connect_challenge,
                "required",
                if chal_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid("Challenge is required")
                },
                Some(&mut self.show_secret_connect),
                false,
            );
            ui.add_space(6.0);

            // M15-T008: 连接中显示 Stepper（先按状态字符串映射：发现→连接→握手→已连接）
            let step = if status.starts_with("Discovering") {
                Some(0)
            } else if status.starts_with("Connecting") {
                Some(1)
            } else if status.starts_with("Handshaking") {
                Some(2)
            } else if status.starts_with("Connected") {
                Some(3)
            } else {
                None
            };
            if let Some(cur) = step {
                stepper(
                    ui,
                    theme,
                    &["Discovering", "Connecting", "Handshaking", "Connected"],
                    cur,
                );
                ui.add_space(6.0);
            }
            // 进行中 → ⏳ 前缀禁用；必填/非法 → 灰化禁用（UI-CON-010 联动按钮）
            let busy = matches!(step, Some(0) | Some(1) | Some(2));
            let can_connect = ip_ok && port_ok && nick_ok && chal_ok;
            let state = if busy {
                ButtonState::Busy
            } else if can_connect {
                ButtonState::Enabled
            } else {
                ButtonState::Disabled
            };

            // M11-T002: Connect（桌面）与 Connect Shell（远程终端）并排。
            let mut do_connect = false;
            let mut do_shell = false;
            ui.horizontal(|ui| {
                if action_button(ui, theme, ButtonKind::Primary, "Connect", state).clicked() {
                    do_connect = true;
                }
                if action_button(ui, theme, ButtonKind::Secondary, "Connect Shell", state)
                    .clicked()
                {
                    do_shell = true;
                }
            });
            if do_connect || do_shell {
                let ip = self.connect_ipv6.trim().to_string();
                let port: u16 = self.connect_port.parse().unwrap_or(0);
                let nick = self.connect_nickname.trim().to_string();
                let chal = self.connect_challenge.trim().to_string();
                if ip.is_empty() {
                    self.connect_status = "Enter an IPv6 address".to_string();
                } else if port == 0 {
                    self.connect_status = "Enter a valid port".to_string();
                } else if nick.is_empty() {
                    self.connect_status = "Enter the device nickname".to_string();
                } else {
                    let addr = format!("[{}]:{}", ip, port);
                    let kind = if do_shell {
                        WindowKind::Shell
                    } else {
                        WindowKind::Desktop
                    };
                    // M8-T021 P1 (T021-01-D): 前置查重——同目标已有窗口 → 聚焦 +
                    // 提示，不 spawn（session_id 不分配、TCP/握手零浪费；握手期间
                    // 竞态由 drain 去重兜底）。
                    if self.try_dedup_connect(ui.ctx(), &addr, kind) {
                        self.connect_status = "已有该设备的连接窗口，已聚焦".to_string();
                        tracing::info!("[dedup] connect pre-check hit for {}, not spawning", addr);
                    } else {
                        self.connect_status =
                            format!("Connecting [{}]:{} as '{}'...", ip, port, nick);
                        tracing::info!(
                            "Connect button: target=[{}]:{} nickname={} shell={}",
                            ip,
                            port,
                            nick,
                            do_shell
                        );
                        // M15: 共享会话启动器——TCP 连接 → 完整握手（IP 模式无带外
                        // 公钥 → known_hosts 命中自动放行 / 首次指纹确认，CLI-HSK-SEC-003）
                        // → 会话任务 → 自动保存设备 + 记录 known_hosts。
                        let ctx = ui.ctx().clone();
                        std::thread::spawn(move || {
                            let rt = tokio::runtime::Runtime::new().expect("connect rt");
                            rt.block_on(async {
                                if do_shell {
                                    // M11: 远程 Shell 会话（独立终端窗口）。
                                    run_client_shell_session(
                                        addr,
                                        nick,
                                        ClientTrust::Confirm,
                                        chal,
                                        String::new(),
                                        "server",
                                        ctx,
                                    )
                                    .await;
                                } else {
                                    run_client_session(
                                        addr,
                                        nick,
                                        ClientTrust::Confirm,
                                        chal,
                                        String::new(),
                                        "desktop",
                                    )
                                    .await;
                                }
                            });
                        });
                    }
                }
            }
            ui.separator();
            ui.add(
                egui::Label::new(
                    egui::RichText::new("IP mode: direct TCP, no DNS resolution.")
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            ui.add(
                egui::Label::new(
                    egui::RichText::new("Domain whitelist does not apply.")
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
        } else if self.connect_id_mode {
            // M8-T026-P2 (ID-021): 设备 ID 模式 —— 经 relay 服务器按 ID 解析 +
            // 三级路径（直连/打洞/中继）连接（ID-010~013）。
            let id_ok = !self.connect_device_id.trim().is_empty();
            let tunnel_cfg = kirin_desk_utils::config::Config::load()
                .map(|c| c.tunnel)
                .unwrap_or_default();
            let tunnel_ok = !tunnel_cfg.server_addr.trim().is_empty()
                && !tunnel_cfg.token.is_empty()
                && tunnel_cfg
                    .server_pubkey
                    .as_deref()
                    .map(|k| !k.trim().is_empty())
                    .unwrap_or(false);
            labeled_input(
                ui,
                theme,
                "Device ID:",
                &mut self.connect_device_id,
                "pc-abc123",
                if id_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid("Device ID is required")
                },
                None,
                true,
            );
            if !tunnel_ok {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "ID 模式需配置 [tunnel] server_addr / token / server_pubkey",
                        )
                        .color(theme.danger)
                        .size(theme.small_size),
                    )
                    .selectable(false),
                );
            } else {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!(
                            "via relay {}",
                            tunnel_cfg.server_addr
                        ))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            }
            ui.add_space(6.0);
            // 连接中 → Stepper（解析→直连/中继→握手→已连接）
            let step = if status.starts_with("Resolving") {
                Some(0)
            } else if status.starts_with("Connecting") {
                Some(1)
            } else if status.starts_with("Handshaking") {
                Some(2)
            } else if status.starts_with("Connected") {
                Some(3)
            } else {
                None
            };
            if let Some(cur) = step {
                stepper(
                    ui,
                    theme,
                    &["Resolving", "Connecting", "Handshaking", "Connected"],
                    cur,
                );
                ui.add_space(6.0);
            }
            let busy = matches!(step, Some(0) | Some(1) | Some(2));
            let can_connect = id_ok && tunnel_ok;
            let state = if busy {
                ButtonState::Busy
            } else if can_connect {
                ButtonState::Enabled
            } else {
                ButtonState::Disabled
            };
            if action_button(ui, theme, ButtonKind::Primary, "Connect", state).clicked() {
                let device_id = self.connect_device_id.trim().to_string();
                if device_id.is_empty() {
                    self.connect_status = "Enter the device ID".to_string();
                } else if !tunnel_ok {
                    self.connect_status =
                        "ID 模式未配置：请在 config 中设置 [tunnel] server_addr/token/server_pubkey".to_string();
                } else {
                    // M8-T026-P2: ID 模式连接线程：解析 → 验签 → pin → 三级路径 →
                    // 握手 → 会话（复用 run_client_session_with_stream）。
                    self.connect_status = format!("Resolving: {} ...", device_id);
                    tracing::info!("Connect button (ID mode): device={}", device_id);
                    let ctx = ui.ctx().clone();
                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().expect("connect rt");
                        rt.block_on(run_client_session_by_id(device_id, ctx));
                    });
                }
            }
            ui.separator();
            ui.add(
                egui::Label::new(
                    egui::RichText::new(
                        "ID mode: relay server resolves the device; direct → punch → relay paths.",
                    )
                    .size(theme.small_size)
                    .color(theme.fg_weak),
                )
                .selectable(false),
            );
        } else {
            // M10-T002: 无 GoDaddy API 配置 → 友好提示 + 直接跳转 Settings。
            if self.api_key.trim().is_empty() || self.api_secret.trim().is_empty() {
                ui.add(
                    egui::Label::new(egui::RichText::new("GoDaddy API 未配置").color(theme.danger))
                        .selectable(false),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "请先在 Settings 配置 GoDaddy API，才能使用 DNS 域名发现。",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                if ui.button("跳转到 Settings").clicked() {
                    self.current_tab = Tab::Settings;
                }
                ui.separator();
            }
            // M15-T008: Domain 模式表单（校验 + secret 挑战码）
            let domain_ok = !self.connect_domain.trim().is_empty();
            let nick_ok = !self.connect_nickname.trim().is_empty();
            let chal_ok = !self.connect_challenge.trim().is_empty();
            labeled_input(
                ui,
                theme,
                "Domain:",
                &mut self.connect_domain,
                "example.com",
                if domain_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid("Domain is required")
                },
                None,
                true,
            );
            labeled_input(
                ui,
                theme,
                "Nickname (sent to server):",
                &mut self.connect_nickname,
                "required",
                if nick_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid("Nickname is required")
                },
                None,
                false,
            );
            labeled_input(
                ui,
                theme,
                "Challenge (sent to server):",
                &mut self.connect_challenge,
                "required",
                if chal_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid("Challenge is required")
                },
                Some(&mut self.show_secret_connect),
                false,
            );
            ui.add_space(6.0);
            // 连接中 → Stepper（Domain 模式含 Discovering 步骤）
            let step = if status.starts_with("Discovering") {
                Some(0)
            } else if status.starts_with("Connecting") {
                Some(1)
            } else if status.starts_with("Handshaking") {
                Some(2)
            } else if status.starts_with("Connected") {
                Some(3)
            } else {
                None
            };
            if let Some(cur) = step {
                stepper(
                    ui,
                    theme,
                    &["Discovering", "Connecting", "Handshaking", "Connected"],
                    cur,
                );
                ui.add_space(6.0);
            }
            let busy = matches!(step, Some(0) | Some(1) | Some(2));
            let api_ok = !self.api_key.trim().is_empty() && !self.api_secret.trim().is_empty();
            let can_connect = domain_ok && nick_ok && chal_ok && api_ok;
            let state = if busy {
                ButtonState::Busy
            } else if can_connect {
                ButtonState::Enabled
            } else {
                ButtonState::Disabled
            };
            if action_button(ui, theme, ButtonKind::Primary, "Connect", state).clicked() {
                let domain = self.connect_domain.trim().to_string();
                let nick = self.connect_nickname.trim().to_string();
                let chal = self.connect_challenge.trim().to_string();
                if domain.is_empty() {
                    self.connect_status = "Enter the remote domain".to_string();
                } else if nick.is_empty() {
                    self.connect_status = "Enter the device nickname".to_string();
                } else if self.api_key.trim().is_empty() || self.api_secret.trim().is_empty() {
                    // M10-T002: 无 GoDaddy API → 拒绝执行（页面上方已有引导提示）。
                    self.connect_status =
                        "GoDaddy API not configured — configure it in Settings first".to_string();
                } else {
                    // M10-T001 + M15: Domain 模式 — DNS 发现（SRV 端口 + TXT 公钥 +
                    // AAAA IPv6）→ 信任解析（known_hosts 优先于 TXT；未命中首次指纹
                    // 确认）→ TCP 连接 → 完整握手（TXT 公钥强制验证）→ 自动保存设备。
                    self.connect_status = format!("Discovering: {}@{} ...", nick, domain);
                    tracing::info!("Connect button: domain={} device={}", domain, nick);
                    let api_key = self.api_key.trim().to_string();
                    let api_secret = self.api_secret.trim().to_string();
                    let api_url = if self.api_url.is_empty() {
                        "https://api.godaddy.com".to_string()
                    } else {
                        self.api_url.clone()
                    };
                    let ctx = ui.ctx().clone();
                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().expect("connect rt");
                        rt.block_on(async {
                            // 1. 发现中：GoDaddy API 并行查询 SRV/TXT/AAAA。
                            let device_id = nick.clone();
                            let discovery_res = {
                                let client = GoDaddyClient::new(&api_key, &api_secret, &api_url);
                                let discovery = DiscoveryService::new(&client, &domain);
                                discovery.discover(&device_id).await
                            };
                            match discovery_res {
                                Ok(info) => {
                                    // M8-T025 P5-4：地址族按配置 `[transport].ip_family`
                                    // 选择（P1 `select_connect_addr` 契约；哨兵 IPv6 在
                                    // 此消化）；无可用地址 → 明确报错。
                                    let cfg = kirin_desk_utils::config::Config::load()
                                        .unwrap_or_default();
                                    let family = match cfg.transport.ip_family.as_str() {
                                        "auto" => Some(kirin_desk_dns::IpFamily::Auto),
                                        "ipv4" => Some(kirin_desk_dns::IpFamily::Ipv4),
                                        "ipv6" => Some(kirin_desk_dns::IpFamily::Ipv6),
                                        _ => None,
                                    };
                                    let family = match family {
                                        Some(f) => f,
                                        None => {
                                            if let Ok(mut s) = connection_status().lock() {
                                                *s = format!(
                                                    "配置错误: [transport].ip_family='{}'（应为 auto|ipv4|ipv6）",
                                                    cfg.transport.ip_family
                                                );
                                            }
                                            return;
                                        }
                                    };
                                    let selected = match info.select_connect_addr(family) {
                                        Some(a) => a,
                                        None => {
                                            tracing::error!(
                                                "Discovered '{}' has no usable IPv4/IPv6 address \
                                                 (ip_family={})",
                                                info.device_id,
                                                cfg.transport.ip_family
                                            );
                                            if let Ok(mut s) = connection_status().lock() {
                                                *s = format!(
                                                    "设备 '{}' 无可用 IPv4/IPv6 地址",
                                                    info.device_id
                                                );
                                            }
                                            return;
                                        }
                                    };
                                    let addr = selected.to_string();
                                    tracing::info!(
                                        "Discovered '{}': IPv6={}, IPv4={}, port={}, type={}, family={}",
                                        info.device_id,
                                        if info.ipv6_addr
                                            == std::net::Ipv6Addr::UNSPECIFIED
                                        {
                                            "none".to_string()
                                        } else {
                                            info.ipv6_addr.to_string()
                                        },
                                        info.ipv4_addr
                                            .map(|a| a.to_string())
                                            .unwrap_or_else(|| "none".to_string()),
                                        info.port,
                                        info.device_type,
                                        cfg.transport.ip_family
                                    );
                                    let kind = if info.device_type == "server" {
                                        WindowKind::Shell
                                    } else {
                                        WindowKind::Desktop
                                    };
                                    // M8-T021 P1 (T021-01-D): 前置查重——会话线程
                                    // 无法访问 UI 窗口列表，此处仅查 pending 信号队列；
                                    // 已有窗口场景由 UI 帧 drain 去重兜底。
                                    if pending_signal_has(&addr, kind) {
                                        if let Ok(mut s) = connection_status().lock() {
                                            *s = "已有该设备的连接窗口，已聚焦".to_string();
                                        }
                                        tracing::info!(
                                            "[dedup] domain discovery pending hit for {}, not spawning",
                                            addr
                                        );
                                        return;
                                    }
                                    // 2. 信任解析：known_hosts 命中优先（CLI-KH-004）；
                                    //    未命中 → 首次指纹确认（CLI-KH-001）；不一致 → 拒绝。
                                    if !known_hosts_or_confirm(&device_id, &info.public_key_base64)
                                    {
                                        return;
                                    }
                                    let trust = ClientTrust::Verified(info.public_key_base64);
                                    // 3. 连接中 → 握手（TXT 公钥强制验证）→ 已连接 → 自动保存。
                                    //    server 型设备自动切换远程终端窗口（§8.4）。
                                    if info.device_type == "server" {
                                        run_client_shell_session(
                                            addr,
                                            device_id,
                                            trust,
                                            chal,
                                            domain,
                                            "server",
                                            ctx,
                                        )
                                        .await;
                                    } else {
                                        run_client_session(
                                            addr,
                                            device_id,
                                            trust,
                                            chal,
                                            domain,
                                            "desktop",
                                        )
                                        .await;
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Discovery FAILED for '{}@{}': {}",
                                        device_id,
                                        domain,
                                        e
                                    );
                                    if let Ok(mut s) = connection_status().lock() {
                                        *s = format!("Discovery FAILED: {}", e);
                                    }
                                }
                            }
                        });
                    });
                }
            }
            ui.separator();
            ui.add(
                egui::Label::new(
                    egui::RichText::new("Domain whitelist is enforced.")
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            ui.add(
                egui::Label::new(
                    egui::RichText::new("Only whitelisted domains in Settings are accepted.")
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(
                        "Tip: auto-discovers via SRV (port) + TXT (key) + AAAA (IPv6).",
                    )
                    .size(theme.small_size)
                    .color(theme.fg_weak),
                )
                .selectable(false),
            );
        }

        ui.separator();
        // 就绪/错误状态行（Mono 弱色）
        if !self.connect_status.is_empty() {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&self.connect_status)
                        .monospace()
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(true),
            );
            ui.add_space(4.0);
        }
        // M15-T008: 底部连接日志改 LogView（级别着色 + 清空/复制）
        log_view(
            ui,
            theme,
            &self.gui_log,
            &LogViewOptions {
                title: "Connection Log:",
                empty: "(no connection log yet)",
                max_height: 150.0,
                clearable: true,
                clear: Some(clear_gui_log),
            },
        );
    }

    fn show_settings(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        ui.heading("Settings");
        ui.separator();
        egui::ScrollArea::vertical().show(ui, |ui| {
            // M15-T008: 6 个可折叠分组（GoDaddy API / 服务端 / 日志 / 身份 / 白名单 / 关于）
            // + 外观组（主题切换）。

            egui::CollapsingHeader::new("GoDaddy API")
                .default_open(true)
                .show(ui, |ui| {
                    labeled_input(
                        ui,
                        theme,
                        "Domain:",
                        &mut self.domain,
                        "example.com",
                        Validity::None,
                        None,
                        true,
                    );
                    labeled_input(
                        ui,
                        theme,
                        "API Key:",
                        &mut self.api_key,
                        "required",
                        Validity::None,
                        None,
                        false,
                    );
                    // M15-T008: API Secret 密文输入（圆点遮蔽 + 👁 切换）
                    labeled_input(
                        ui,
                        theme,
                        "API Secret:",
                        &mut self.api_secret,
                        "required",
                        Validity::None,
                        Some(&mut self.show_secret_api),
                        false,
                    );
                });

            egui::CollapsingHeader::new("Server").show(ui, |ui| {
                labeled_input(
                    ui,
                    theme,
                    "Listen Port:",
                    &mut self.listen_port,
                    "3389",
                    Validity::None,
                    None,
                    true,
                );
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Connection Mode:")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                let mut mode = if self.ip_mode_allowed { 1 } else { 0 };
                if segmented_control(
                    ui,
                    theme,
                    &["Domain Mode (strict)", "IP Mode (flexible)"],
                    &mut mode,
                ) {
                    self.ip_mode_allowed = mode == 1;
                }
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Temp Mode (headless):")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                let mut tm = if self.temp_mode { 1 } else { 0 };
                if segmented_control(
                    ui,
                    theme,
                    &["Off (whitelist enforced)", "On (bypass whitelist)"],
                    &mut tm,
                ) {
                    self.temp_mode = tm == 1;
                }
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "Temp mode skips whitelist check. Use for Linux headless servers.",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            });

            // M8-T026 (TNL-CFG-004): 内网穿透设置——客户端填写 relay 服务器
            // 地址 / token / 代理列表；服务端参数（bind_port/port_range/heartbeat）
            // 不占 GUI，在 config/default.toml 配置，穿透服务端走 CLI `tunnel serve`。
            egui::CollapsingHeader::new("Tunnel (内网穿透)").show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "内网穿透：被控端主动出站连接公网 relay 服务器，把内网 TCP 服务\
                             （SSH/RDP/HTTP）映射到公网端口——P2P 直连不可达时的兜底。\
                             默认关闭，仅在有公网服务器（自建 relay）时启用。",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Enabled:")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                let mut te = if self.tunnel_enabled { 1 } else { 0 };
                if segmented_control(ui, theme, &["Off", "On"], &mut te) {
                    self.tunnel_enabled = te == 1;
                }
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Mode:")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                let mut tm = if self.tunnel_mode == "server" { 1 } else { 0 };
                if segmented_control(ui, theme, &["Client", "Server"], &mut tm) {
                    self.tunnel_mode = if tm == 1 { "server" } else { "client" }.to_string();
                }
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "Client = 被控端主动出站（推荐）；Server = 公网 relay 服务端\
                             （也可用 CLI `tunnel serve`，服务端参数在 default.toml）。",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add_space(4.0);
                labeled_input(
                    ui,
                    theme,
                    "Server Address:",
                    &mut self.tunnel_server_addr,
                    "relay.example.com:7000",
                    Validity::None,
                    None,
                    true,
                );
                labeled_input(
                    ui,
                    theme,
                    "Token:",
                    &mut self.tunnel_token,
                    "required",
                    Validity::None,
                    Some(&mut self.show_secret_tunnel_token),
                    false,
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Proxies (one per line):")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                egui::TextEdit::multiline(&mut self.tunnel_proxies)
                    .desired_rows(3)
                    .desired_width(ui.available_width())
                    .show(ui);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "Format: name|local_addr:port|remote_port  (remote_port 留空 = 服务端自动分配)\
                             \ne.g. ssh|127.0.0.1:22|6022",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            });

            // M13-T005 (UA-UI-001): 无人值守模式卡片——总开关 + 子选项 +
            // 自启注册状态 + 安全提示。保存按钮统一落盘（见下方 Save 分支）。
            egui::CollapsingHeader::new("Unattended Mode").show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "无人值守：开机自启 + 自动开启服务端 + 受信任设备自动接受连接（远程桌面远控 / 远程 Shell PTY 均可）。",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add_space(4.0);
                // 总开关
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Unattended mode:")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                let mut ua = if self.unattended_enabled { 1 } else { 0 };
                if segmented_control(
                    ui,
                    theme,
                    &["Off", "On"],
                    &mut ua,
                ) {
                    self.unattended_enabled = ua == 1;
                }
                ui.add_space(4.0);
                // 开机自动启动（独立于总开关，D6）
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Start at OS logon (autostart):")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                let mut asb = if self.unattended_autostart { 1 } else { 0 };
                if segmented_control(ui, theme, &["Off", "On"], &mut asb) {
                    self.unattended_autostart = asb == 1;
                }
                // 自启注册状态（以系统实际状态为准，UA-BOOT-002）
                let installed = kirin_desk_utils::autostart::is_installed();
                badge(
                    ui,
                    theme,
                    if installed {
                        "registered at OS logon"
                    } else {
                        "not registered"
                    },
                    if installed {
                        BadgeKind::Success
                    } else {
                        BadgeKind::Neutral
                    },
                );
                ui.add_space(4.0);
                // 启动时自动开启服务端
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Auto-start server on launch:")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                let mut ass = if self.unattended_auto_server { 1 } else { 0 };
                if segmented_control(ui, theme, &["Off", "On"], &mut ass) {
                    self.unattended_auto_server = ass == 1;
                }
                ui.add_space(4.0);
                // 安全提示（UA-SEC-003 / UA-ACCEPT-002）
                if self.unattended_enabled {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(
                                "⚠ 无人值守下：known_clients/白名单命中的连接自动放行（远控或 PTY）；\
                                 未知设备一律拒绝（无审批弹窗）；temp-mode 旁路禁用。\
                                 建议先在 Whitelist / known-hosts 中配置受信任设备。",
                            )
                            .size(theme.small_size)
                            .color(theme.danger),
                        )
                        .selectable(false),
                    );
                }
            });

            egui::CollapsingHeader::new("Identity").show(ui, |ui| {
                labeled_input(
                    ui,
                    theme,
                    "Device ID:",
                    &mut self.device_id,
                    "my-pc",
                    Validity::None,
                    None,
                    true,
                );
                labeled_input(
                    ui,
                    theme,
                    "Nickname (server expects this):",
                    &mut self.nickname,
                    "required",
                    Validity::None,
                    None,
                    false,
                );
                // M15-T008: 验证码密文输入（圆点遮蔽 + 👁 切换）
                labeled_input(
                    ui,
                    theme,
                    "Challenge Code (server expects this):",
                    &mut self.challenge_code,
                    "optional",
                    Validity::None,
                    Some(&mut self.show_secret_challenge),
                    false,
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("(Incoming clients must send this nickname)")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            });

            egui::CollapsingHeader::new("Whitelist").show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Allowed Domains:")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                egui::TextEdit::multiline(&mut self.allowed_domains)
                    .desired_rows(3)
                    .desired_width(ui.available_width())
                    .show(ui);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("(comma-separated, one or more domains)")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Domain whitelist is more secure.")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Non-whitelisted clients trigger an approval dialog.")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "On headless servers, enable Temp Mode or clients are rejected.",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            });

            egui::CollapsingHeader::new("Logging").show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "Log level / format / keep days are configured in config/default.toml.",
                        )
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            });

            // M15-T008: 外观组——明亮/深色/跟随系统，选择即时生效（无需重启）。
            egui::CollapsingHeader::new("Appearance")
                .default_open(true)
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new("Theme:")
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                    let mut mode = match self.theme_mode {
                        ThemeMode::Light => 0,
                        ThemeMode::Dark => 1,
                        ThemeMode::System => 2,
                    };
                    if segmented_control(
                        ui,
                        theme,
                        &["Light", "Dark", "System"],
                        &mut mode,
                    ) {
                        self.theme_mode = match mode {
                            0 => ThemeMode::Light,
                            1 => ThemeMode::Dark,
                            _ => ThemeMode::System,
                        };
                        // 即时生效：update() 帧首 apply_theme 检测明暗变化即全量重设。
                    }
                });

            // M14-T005: 自动更新分组——检查 / 下载进度 / 安装重启。
            // 状态由后台线程写入 `update_state()`，本面板每帧读取。
            egui::CollapsingHeader::new("Update")
                .default_open(true)
                .show(ui, |ui| {
                    let s = update_state();
                    let guard = s.lock().unwrap();

                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new("Current version:")
                                    .size(theme.small_size)
                                    .color(theme.fg_weak),
                            )
                            .selectable(false),
                        );
                        badge(ui, theme, kirin_desk_updater::APP_VERSION, BadgeKind::Neutral);
                    });

                    if guard.checking {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Checking for updates...");
                        });
                    } else {
                        ui.add_space(4.0);
                        if action_button(
                            ui,
                            theme,
                            ButtonKind::Secondary,
                            "Check for updates",
                            ButtonState::Enabled,
                        )
                        .clicked()
                        {
                            let ctx = ui.ctx().clone();
                            drop(guard);
                            spawn_update_check(ctx);
                            return;
                        }
                    }

                    match &guard.result {
                        Some(UpdateStatus::Available(info)) => {
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new("New version").strong(),
                                    )
                                    .selectable(false),
                                );
                                badge(ui, theme, &format!("v{}", info.version), BadgeKind::Success);
                            });
                            if !info.release_notes.is_empty() {
                                egui::ScrollArea::vertical()
                                    .max_height(120.0)
                                    .show(ui, |ui| {
                                        ui.label(&info.release_notes);
                                    });
                            }
                            if guard.downloading {
                                let (received, total) = guard.progress;
                                let frac = total
                                    .filter(|t| *t > 0)
                                    .map(|t| received as f32 / t as f32)
                                    .unwrap_or(0.0);
                                let text = match total {
                                    Some(t) => format!(
                                        "{:.1} / {:.1} MB",
                                        received as f32 / 1e6,
                                        t as f32 / 1e6
                                    ),
                                    None => format!("{:.1} MB", received as f32 / 1e6),
                                };
                                ui.add(egui::ProgressBar::new(frac).text(text));
                            } else if guard.downloaded.is_none() {
                                ui.add_space(4.0);
                                if action_button(
                                    ui,
                                    theme,
                                    ButtonKind::Primary,
                                    "Download update",
                                    ButtonState::Enabled,
                                )
                                .clicked()
                                {
                                    let ctx = ui.ctx().clone();
                                    let info = info.clone();
                                    drop(guard);
                                    spawn_update_download(ctx, info);
                                    return;
                                }
                            } else {
                                ui.add_space(4.0);
                                if action_button(
                                    ui,
                                    theme,
                                    ButtonKind::Primary,
                                    "Install & Restart",
                                    ButtonState::Enabled,
                                )
                                .clicked()
                                {
                                    let path = guard.downloaded.clone().unwrap();
                                    drop(guard);
                                    match install_update(&path) {
                                        // 替换脚本已在后台启动：立即退出让出 exe 文件锁。
                                        Ok(()) => std::process::exit(0),
                                        Err(e) => {
                                            let mut s2 = s.lock().unwrap();
                                            s2.error = Some(e);
                                        }
                                    }
                                    return;
                                }
                            }
                        }
                        Some(UpdateStatus::UpToDate) => {
                            ui.add_space(4.0);
                            ui.label("You are up to date.");
                        }
                        Some(UpdateStatus::Error(_)) | None => {}
                    }

                    if let Some(e) = &guard.error {
                        ui.add_space(4.0);
                        badge(ui, theme, &format!("Update error: {}", e), BadgeKind::Danger);
                    }
                });

            egui::CollapsingHeader::new("About").show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(egui::RichText::new("🐉 KirinDesk").strong())
                            .selectable(false),
                    );
                    badge(ui, theme, kirin_desk_updater::APP_VERSION, BadgeKind::Neutral);
                });
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("P2P Remote Desktop — secure direct connections.")
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            });

            ui.separator();
            ui.horizontal(|ui| {
                if action_button(ui, theme, ButtonKind::Primary, "Save", ButtonState::Enabled)
                    .clicked()
                {
                    let mut cfg = kirin_desk_utils::config::Config::default();
                    cfg.device.id = self.device_id.clone();
                    cfg.device.nickname = self.nickname.clone();
                    cfg.device.challenge_code = self.challenge_code.clone();
                    cfg.godaddy.api_key = self.api_key.clone();
                    cfg.godaddy.api_secret = self.api_secret.clone();
                    cfg.godaddy.domain = self.domain.clone();
                    if let Ok(p) = self.listen_port.parse::<u16>() {
                        cfg.network.port = p;
                    }
                    cfg.network.allowed_domains = self
                        .allowed_domains
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    cfg.network.ip_mode_allowed = self.ip_mode_allowed;
                    cfg.network.temp_mode = self.temp_mode;
                    // M15-T008: 主题模式持久化（`[ui] theme`，默认 light）
                    cfg.ui.theme = self.theme_mode.as_str().to_string();
                    // M13-T005 (UA-CFG-002): 无人值守配置持久化
                    cfg.unattended.enabled = self.unattended_enabled;
                    cfg.unattended.auto_start_server = self.unattended_auto_server;
                    cfg.unattended.auto_start_on_boot = self.unattended_autostart;
                    // M8-T026 (TNL-CFG-004): 内网穿透设置持久化（proxies 多行文本
                    // 解析回 Vec<TunnelProxy>；服务端参数保留配置默认值）。
                    cfg.tunnel.enabled = self.tunnel_enabled;
                    cfg.tunnel.mode = self.tunnel_mode.clone();
                    cfg.tunnel.server_addr = self.tunnel_server_addr.clone();
                    cfg.tunnel.token = self.tunnel_token.clone();
                    cfg.tunnel.proxies =
                        kirin_desk_utils::config::TunnelConfig::parse_proxy_lines(
                            &self.tunnel_proxies,
                        );
                    match cfg.save() {
                        Ok(()) => {
                            self.settings_status = "Saved".to_string();
                            if let Ok(p) = self.listen_port.parse::<u16>() {
                                self.connect_port = p.to_string();
                            }
                            // M13-T005 (UA-BOOT-001/002): 自启开关与系统状态同步——
                            // 开启则注册用户级自启，关闭则移除（幂等）。
                            if self.unattended_autostart {
                                if let Err(e) = kirin_desk_utils::autostart::install() {
                                    self.settings_status =
                                        format!("Saved, but autostart registration failed: {}", e);
                                }
                            } else {
                                let _ = kirin_desk_utils::autostart::uninstall();
                            }
                        }
                        Err(e) => self.settings_status = format!("Save failed: {}", e),
                    }
                }
                // M15-T008: 保存反馈改横幅 Badge（success/danger）
                if !self.settings_status.is_empty() {
                    let kind = if self.settings_status.starts_with("Saved") {
                        BadgeKind::Success
                    } else {
                        BadgeKind::Danger
                    };
                    badge(ui, theme, &self.settings_status, kind);
                }
            });
        });
    }
}

// ════════════════════════════════════════════════════════════════
// M9-T007: 客户端输入捕获单测（键映射表 / 节流合并队列）
// ════════════════════════════════════════════════════════════════
#[cfg(test)]
mod m9_input_tests {
    use super::*;

    #[test]
    fn test_egui_key_to_hid_letters() {
        assert_eq!(egui_key_to_hid(egui::Key::A), Some(HidKey::A));
        assert_eq!(egui_key_to_hid(egui::Key::M), Some(HidKey::M));
        assert_eq!(egui_key_to_hid(egui::Key::Z), Some(HidKey::Z));
    }

    #[test]
    fn test_egui_key_to_hid_digits_and_functions() {
        assert_eq!(egui_key_to_hid(egui::Key::Num0), Some(HidKey::Num0));
        assert_eq!(egui_key_to_hid(egui::Key::Num9), Some(HidKey::Num9));
        assert_eq!(egui_key_to_hid(egui::Key::F1), Some(HidKey::F1));
        assert_eq!(egui_key_to_hid(egui::Key::F12), Some(HidKey::F12));
        assert_eq!(egui_key_to_hid(egui::Key::Escape), Some(HidKey::Esc));
        assert_eq!(egui_key_to_hid(egui::Key::Enter), Some(HidKey::Enter));
        assert_eq!(egui_key_to_hid(egui::Key::Tab), Some(HidKey::Tab));
        assert_eq!(egui_key_to_hid(egui::Key::Space), Some(HidKey::Space));
        assert_eq!(
            egui_key_to_hid(egui::Key::Backspace),
            Some(HidKey::Backspace)
        );
    }

    #[test]
    fn test_egui_key_to_hid_navigation() {
        assert_eq!(egui_key_to_hid(egui::Key::ArrowUp), Some(HidKey::Up));
        assert_eq!(egui_key_to_hid(egui::Key::ArrowDown), Some(HidKey::Down));
        assert_eq!(egui_key_to_hid(egui::Key::ArrowLeft), Some(HidKey::Left));
        assert_eq!(egui_key_to_hid(egui::Key::ArrowRight), Some(HidKey::Right));
        assert_eq!(egui_key_to_hid(egui::Key::Home), Some(HidKey::Home));
        assert_eq!(egui_key_to_hid(egui::Key::End), Some(HidKey::End));
        assert_eq!(egui_key_to_hid(egui::Key::PageUp), Some(HidKey::PageUp));
        assert_eq!(egui_key_to_hid(egui::Key::PageDown), Some(HidKey::PageDown));
        assert_eq!(egui_key_to_hid(egui::Key::Insert), Some(HidKey::Insert));
        assert_eq!(egui_key_to_hid(egui::Key::Delete), Some(HidKey::Delete));
    }

    #[test]
    fn test_egui_key_to_hid_unmapped_dropped() {
        // 标点/系统键（Copy/Colon/F13+）未覆盖 → None，上层丢弃不崩溃。
        assert_eq!(egui_key_to_hid(egui::Key::Copy), None);
        assert_eq!(egui_key_to_hid(egui::Key::Colon), None);
        assert_eq!(egui_key_to_hid(egui::Key::F13), None);
    }

    #[test]
    fn test_capture_queue_move_coalescing() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut q = InputCaptureQueue::new();
        q.push_move(100, 200);
        q.push_move(300, 400); // 同帧多次移动 → 只保留最新
        assert!(q.flush_if_due(&tx));
        let batch = rx.try_recv().unwrap();
        assert_eq!(batch.len(), 1);
        assert!(matches!(
            batch[0],
            WireInputEvent {
                kind: InputKind::MouseMove,
                x: 300,
                y: 400,
                ..
            }
        ));
        // 已清空 → 不再发送
        assert!(!q.flush_if_due(&tx));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_capture_queue_move_throttle_60fps() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut q = InputCaptureQueue::new();
        q.push_move(1, 1);
        assert!(q.flush_if_due(&tx)); // 首个移动立即发送
        rx.try_recv().unwrap(); // 消费第一批
        q.push_move(2, 2);
        // 距上次发送 <16ms → 节流，等待下一帧
        assert!(!q.flush_if_due(&tx));
        assert!(q.has_pending());
        // 非移动事件（点击）→ 强制立即 flush，且移动排在点击之前（顺序正确）
        q.push(WireInputEvent::mouse_button(hid_button::LEFT, 2, 2));
        assert!(q.flush_if_due(&tx));
        let batch = rx.try_recv().unwrap();
        assert_eq!(batch.len(), 2);
        assert!(matches!(
            batch[0],
            WireInputEvent {
                kind: InputKind::MouseMove,
                ..
            }
        ));
        assert!(matches!(
            batch[1],
            WireInputEvent {
                kind: InputKind::MouseButton,
                ..
            }
        ));
        // flush 后无积压
        assert!(!q.has_pending());
    }

    #[test]
    fn test_capture_queue_empty_no_send() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut q = InputCaptureQueue::new();
        assert!(!q.flush_if_due(&tx));
        assert!(rx.try_recv().is_err());
    }
}
