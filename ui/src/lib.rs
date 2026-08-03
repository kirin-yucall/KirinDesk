mod cli;
pub mod clipboard;
pub mod domain_panel;
pub mod file_panel;
mod policy;
mod privacy;
pub mod terminal;
mod theme;
mod widgets;
// R-12 (M15-T007): 国际化基础设施（先行；文案抽取随 M8-T038 波次 2，
// 见 task_docs/修复任务/E_安全打磨R-12至R-13.md）。消费方 `use crate::t;`。
// 注：lib.rs 为 crate 根，`#[macro_export]` 的 t!/tf! 已在本模块宏命名空间直接可用。
mod i18n;

use file_panel::{FileCommand, FileDirection, FilePanelState, FileTask, FileTaskStatus};

use kirin_desk_core::connection::file_transfer::{
    block_len, block_offset, derive_transfer_id, sanitize_filename, sha256_file,
    validate_block_count, ChunkReceiver, FileOfferMeta, FileOp, FileTransferError,
    FileTransferFrame, SlideWindowSender, StoredTransfer, TransferScheduler, TransferStore,
    BLOCK_SIZE, DEFAULT_MAX_FILE_SIZE,
};
// R-03 (R03-S1): 可复用建连链路（CLI/GUI/断线重连共用）。
use kirin_desk_core::connection::client::{
    connect_peer, resolve_peer, ConnectError, ConnectionOptions, DnsConfig, TrustPolicy,
};
// R-03 (R03-S2/S4): 重连状态机与上下文。
use kirin_desk_core::connection::manager::{ManagedConnection, ReconnectContext};
use kirin_desk_core::connection::reconnection::attempt_reconnect;
use kirin_desk_core::connection::ShellMessage;
// M8-T019: 隐私模式（黑屏 / 锁屏）状态机。
use kirin_desk_core::connection::privacy::{PrivacyController, PrivacyLevel, PrivacyOutcome};
use kirin_desk_core::connection::temp_mode::TempModeManager;
use kirin_desk_core::crypto::ed25519::IdentityManager;
// M15 (SRV-SEC-KH-001): 服务端两阶段握手（预读 init → pin → 应答）。
use kirin_desk_core::crypto::handshake::{
    domain_matches_whitelist, id_matches_whitelist, server_handshake_respond_generic,
    server_read_init, verify_server_init_with_temp, SecureChannel,
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
    action_button, badge, card, copy_button, labeled_input, log_view, segmented_control,
    selectable_pill, stat_card, stat_card_with_footer, state_button, status_dot, status_dot_char,
    stepper, toggle_switch, toolbar_button, BadgeKind, ButtonKind, ButtonState, LogViewOptions,
    StatRow, Validity,
};

// M10: 设备列表持久化 + DNS 发现连接。
use kirin_desk_dns::discovery::DiscoveryService;
use kirin_desk_utils::devices::{DeviceStore, SavedDevice};
// M15 (CLI-KH): 已知主机指纹验证。
use kirin_desk_utils::known_hosts::{
    fingerprint as kh_fingerprint, FingerprintStatus, KnownHostsStore,
};

// M9: 远程输入注入（客户端捕获 → 加密通道 → 服务端注入）。
// M8-T020: SpecialCombo 特殊键（Win/Alt+Tab/任务管理器/锁屏）。
use kirin_desk_input::injector::{
    button as hid_button, modifier as hid_modifier, InputEvent as WireInputEvent, InputInjector,
    InputKind, Key as HidKey, SpecialCombo,
};
use kirin_desk_media::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use kirin_desk_media::proto::DisplayInfo;
use kirin_desk_media::transport::{
    ChannelTag, ControlMessage, MAX_PACKET_PAYLOAD, SecureChannelReceiver, SecureChannelSender,
};
// M14-T005: 自动更新（Settings Update 面板 + 每周后台检查）。
use kirin_desk_updater::{InstallOutcome, ReleaseInfo, UpdateChannel, UpdateStatus, Updater};
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

/// 当前激活 DNS 服务商是否已配置可用凭据（注册表已注册 + `[dns.providers.*]`
/// 对应条目非空）。M9-DNS022 (UI-DNS-004) 泛化：不再限定 GoDaddy——Connect 页
/// 域名模式前置校验 / 状态栏 DNS 徽标统一走本判定（配合 App 内存
/// `dns_configured`，避免每帧读配置）。
fn dns_provider_configured(cfg: &kirin_desk_utils::config::Config) -> bool {
    !cfg.dns.provider.is_empty()
        && kirin_desk_dns::provider_registry().has(&cfg.dns.provider)
        && cfg
            .dns_provider_credentials(&cfg.dns.provider)
            .map_or(false, |m| !m.is_empty())
}

/// S-02 (F-5): 服务端并发连接处理上限（含 60s 审批等待）——accept 循环每连接
/// `tokio::spawn`，同时处理的连接数不超过本值，超出者在任务内排队（信号量）；
/// GUI 与 CLI（`super::`）共用。
pub(crate) const SERVER_MAX_CONCURRENT_CONNECTIONS: usize = 64;

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

/// M8-T034: 服务端真实运行态（监听线程写 → GUI 每帧读）。
/// 修复旧实现「bind 失败只打日志、`server_running` 保持 true」的假死：
/// 失败时写 `error` 并置 `listening=false`，开关即时回 OFF 并展示原因。
#[derive(Debug, Clone, Default)]
struct ServerRuntimeState {
    /// bind 进行中（GUI 点击后置位，监听线程 bind 完成后复位）。
    starting: bool,
    /// 是否在监听（bind 成功且未 stop）。
    listening: bool,
    /// 实际监听端口（bind 成功后写回；0 = 未知）。
    port: u16,
    /// bind/运行错误（None = 无错误；Some → 开关回 OFF 并展示原因）。
    error: Option<String>,
}

/// 服务端运行态共享槽（GUI 每帧读，监听线程写）。
fn server_runtime_state() -> &'static Mutex<ServerRuntimeState> {
    static S: OnceLock<Mutex<ServerRuntimeState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(ServerRuntimeState::default()))
}

/// M8-T039 §3.4.3: 隧道真实运行态（后台线程写 → GUI 每帧读；仿 ServerRuntimeState）。
#[derive(Debug, Clone, Default)]
struct TunnelRuntimeState {
    /// 启动进行中（GUI 点击后置位，后台线程确认后复位）。
    starting: bool,
    /// 隧道运行中（client 控制连接在 / server 在监听）。
    running: bool,
    /// 实际监听端口（server 模式 bind 成功后写回；0 = 未知）。
    port: u16,
    /// 实际监听地址列表（server 模式；空 = 默认双栈回退）。
    addrs: String,
    /// 启动/运行错误（None = 无错误；Some → 状态行展示原因）。
    error: Option<String>,
}

/// 隧道运行态共享槽（GUI 每帧读，后台线程写）。
fn tunnel_runtime_state() -> &'static Mutex<TunnelRuntimeState> {
    static S: OnceLock<Mutex<TunnelRuntimeState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(TunnelRuntimeState::default()))
}

/// 隧道运行句柄槽（停止时优雅关闭；client 持 `Arc<TunnelClient>`，
/// server 持 `TunnelServerHandle`；运行结束由后台线程清空）。
fn tunnel_run_handles() -> &'static Mutex<Option<TunnelRunHandles>> {
    static S: OnceLock<Mutex<Option<TunnelRunHandles>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(None))
}

/// 隧道运行句柄（停止路径用；优雅关闭优于 runtime drop abort，TNL-SERVER-006）。
#[derive(Default)]
struct TunnelRunHandles {
    client: Option<std::sync::Arc<kirin_desk_relay::client::TunnelClient>>,
    server: Option<kirin_desk_relay::server::TunnelServerHandle>,
}

/// M8-T039: 隧道状态行文案（运行中 ● / 已停止 ○ / 启动失败: 原因（配置保持启用…））。
fn tunnel_status_text(st: &TunnelRuntimeState, mode: &str) -> String {
    if let Some(e) = &st.error {
        return tf!("tunnel.run.failed", e); // 「启动失败: {0}（配置保持启用，下次启动将自动重试）」
    }
    if st.running {
        if mode == "server" {
            if !st.addrs.is_empty() {
                return tf!("tunnel.run.running", st.port, &st.addrs); // 「● 运行中 :{0} ({1})」
            }
            return tf!("tunnel.run.running", st.port, t!("tunnel.run.default_addrs"));
        }
        return t!("tunnel.run.running_client").to_string(); // 「● 运行中（client）」
    }
    t!("tunnel.run.stopped").to_string() // 「○ 已停止」
}

/// M8-T036: 公网出口探测状态（Dashboard「公网检测」混合判定的一部分）。
/// 仅当本地地址全部非公网时触发一次：后台线程向 `api.ipify.org` 查询公网出口
/// IP（4s 超时）；探测结果与本地任一地址相同 → 本机直持公网地址。
#[derive(Clone, Copy, PartialEq, Debug)]
enum PublicProbeState {
    /// 未触发（本地已有公网地址时保持）。
    Idle,
    /// 探测线程运行中。
    Probing,
    /// 已完成（None = 探测失败/无网络）。
    Done(Option<std::net::IpAddr>),
}

fn public_probe_state() -> &'static Mutex<PublicProbeState> {
    static S: OnceLock<Mutex<PublicProbeState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(PublicProbeState::Idle))
}

/// 惰性触发一次公网出口探测（仅 Idle → Probing 时启动线程；线程结束后写回）。
fn ensure_public_probe() {
    let mut state = public_probe_state().lock().unwrap();
    if *state != PublicProbeState::Idle {
        return;
    }
    *state = PublicProbeState::Probing;
    drop(state);
    std::thread::spawn(|| {
        let ip = probe_public_ip();
        *public_probe_state().lock().unwrap() = PublicProbeState::Done(ip);
        tracing::info!(
            "[public-ip] external probe finished: {}",
            ip.map(|i| i.to_string()).unwrap_or_else(|| "failed".to_string())
        );
    });
}

/// 公网出口 IP 探测：纯 TCP HTTP GET `api.ipify.org`（无 TLS 依赖，4s 超时）。
fn probe_public_ip() -> Option<std::net::IpAddr> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    let addr: std::net::SocketAddr = "api.ipify.org:80".parse().ok()?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(4)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(4))).ok()?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    let body = buf.rsplit("\r\n\r\n").next().unwrap_or("").trim();
    body.parse::<std::net::IpAddr>().ok()
}

/// Shared connection status (server/connect threads → GUI).
fn connection_status() -> &'static Mutex<String> {
    static S: OnceLock<Mutex<String>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(String::new()))
}

/// M8-T038 (P1): 连接状态 → 语义色（Shell 前缀剥离后判定；与既有 Connect 页
/// 7868-7877 映射一致：已连接绿 / 发现·解析·连接·握手蓝 / 其余红）。
fn conn_status_color(theme: &Theme, status: &str) -> egui::Color32 {
    let s = status.strip_prefix("[shell] ").unwrap_or(status);
    if s.starts_with("Connected") {
        theme.success
    } else if s.starts_with("Discovering")
        || s.starts_with("Resolving")
        || s.starts_with("Connecting")
        || s.starts_with("Handshaking")
    {
        theme.info
    } else {
        theme.danger
    }
}

/// M8-T038 (P1): 连接状态 → Stepper 步数（0=发现/解析 1=连接 2=握手 3=已连接；
/// 其余 None）。与 Connect 页 step 推导同逻辑，另剥离 `[shell] ` 前缀
/// （"[shell] Connected to …" → 第 3 步）。
fn conn_step(status: &str) -> Option<usize> {
    let s = status.strip_prefix("[shell] ").unwrap_or(status);
    if s.starts_with("Discovering") || s.starts_with("Resolving") {
        Some(0)
    } else if s.starts_with("Connecting") {
        Some(1)
    } else if s.starts_with("Handshaking") {
        Some(2)
    } else if s.starts_with("Connected") {
        Some(3)
    } else {
        None
    }
}

/// M8-T038 (P6): 特殊键按钮文案（input crate 的 `SpecialCombo::label` 为硬编码
/// 中文——UI 层以 t!() 覆盖，input 层保持平台通用不依赖 ui/i18n；键名同义）。
fn special_combo_label(c: SpecialCombo) -> &'static str {
    match c {
        SpecialCombo::WinE => t!("session.special_key.win_e"),
        SpecialCombo::WinD => t!("session.special_key.win_d"),
        SpecialCombo::WinL => t!("session.special_key.win_l"),
        SpecialCombo::WinR => t!("session.special_key.win_r"),
        SpecialCombo::AltTab => t!("session.special_key.alt_tab"),
        SpecialCombo::CtrlShiftEsc => t!("session.special_key.ctrl_shift_esc"),
        SpecialCombo::AltF4 => t!("session.special_key.alt_f4"),
        SpecialCombo::CtrlEsc => t!("session.special_key.ctrl_esc"),
        SpecialCombo::LockScreen => t!("session.special_key.lock_screen"),
    }
}

/// M8-T038 (P6): 特殊键按钮 tooltip（同上，覆盖 input crate 的 `hint()`）。
fn special_combo_hint(c: SpecialCombo) -> &'static str {
    match c {
        SpecialCombo::WinE => t!("session.special_key.win_e_hint"),
        SpecialCombo::WinD => t!("session.special_key.win_d_hint"),
        SpecialCombo::WinL => t!("session.special_key.win_l_hint"),
        SpecialCombo::WinR => t!("session.special_key.win_r_hint"),
        SpecialCombo::AltTab => t!("session.special_key.alt_tab_hint"),
        SpecialCombo::CtrlShiftEsc => t!("session.special_key.ctrl_shift_esc_hint"),
        SpecialCombo::AltF4 => t!("session.special_key.alt_f4_hint"),
        SpecialCombo::CtrlEsc => t!("session.special_key.ctrl_esc_hint"),
        SpecialCombo::LockScreen => t!("session.special_key.lock_screen_hint"),
    }
}

/// R-04：会话级音频开关（Settings 页 / CLI `--no-audio` 共用，进程级生效）。
///
/// 会话启动时读取：GUI 客户端会话据此创建音频解码/播放线程，GUI 服务端
/// 会话据此创建捕获/编码线程；`false` → 会话无声但视频/键鼠不受影响。
fn audio_enabled_global() -> &'static AtomicBool {
    static AUDIO: AtomicBool = AtomicBool::new(true); // 默认开（P1D 默认参数）
    &AUDIO
}

/// R-04：音频开关读取（CLI 解析测试 / 会话启动共用；`pub(crate)`）。
pub(crate) fn audio_enabled() -> bool {
    audio_enabled_global().load(Ordering::Relaxed)
}

/// R-04：音频开关写入（Settings 勾选 / CLI `--no-audio` 解析）。
///
/// M8-T032：本开关为**总开关**——`false` 同时关三个子开关
/// （① 服务端发送 / ② 客户端播放 / ③ 客户端麦克风回传），兼容
/// CLI `--no-audio` 全关语义；重新开启 → 三个子开关恢复默认
/// （开 / 开 / 关，M8-T032 §3.1）。
pub(crate) fn set_audio_enabled(enabled: bool) {
    audio_enabled_global().store(enabled, Ordering::Relaxed);
    if !enabled {
        set_server_audio_allowed(false);
        set_client_audio_play(false);
        set_client_mic_enabled(false);
    }
    tracing::info!(
        "[audio] session audio {}",
        if enabled { "enabled" } else { "disabled" }
    );
}

// ════════════════════════════════════════════════════════════════
// M8-T032：音频三开关（进程级原子量，会话任务循环内逐轮读取——
// 运行时切换立即生效，无需重连）
// ════════════════════════════════════════════════════════════════

/// ① 服务端「允许麦克风」：服务端是否把本机声音（WASAPI 环回）传给客户端。
/// Dashboard Server 卡开关读写；关 → 服务端不启动/停止音频发送。
/// M8-T035：**默认关**（需求 8；总开关开启不回写子开关默认值，故
/// 「总开关 开→关→开」循环后本开关仍保持关）。
fn server_audio_allowed_global() -> &'static AtomicBool {
    static ALLOWED: AtomicBool = AtomicBool::new(false);
    &ALLOWED
}

/// ① 读取。
pub(crate) fn server_audio_allowed() -> bool {
    server_audio_allowed_global().load(Ordering::Relaxed)
}

/// ① 写入（Dashboard 开关）。
pub(crate) fn set_server_audio_allowed(enabled: bool) {
    server_audio_allowed_global().store(enabled, Ordering::Relaxed);
    tracing::info!(
        "[audio] server audio (loopback → client) {}",
        if enabled { "enabled" } else { "disabled" }
    );
}

/// ② 客户端「播放音频」：是否播放服务端传来的音频。连接窗口开关读写；
/// 关 → 丢弃到达的音频包（动态静音）。默认开。
fn client_audio_play_global() -> &'static AtomicBool {
    static PLAY: AtomicBool = AtomicBool::new(true);
    &PLAY
}

/// ② 读取。
pub(crate) fn client_audio_play() -> bool {
    client_audio_play_global().load(Ordering::Relaxed)
}

/// ② 写入（连接窗口开关）。
pub(crate) fn set_client_audio_play(enabled: bool) {
    client_audio_play_global().store(enabled, Ordering::Relaxed);
    tracing::info!(
        "[audio] client playback {}",
        if enabled { "enabled" } else { "muted" }
    );
}

/// ③ 客户端「麦克风」：是否捕获本机麦克风并回传服务端播放（talkback）。
/// 连接窗口开关读写；关 → 停发（动态）。**默认关**（新功能，旧行为零变化）。
fn client_mic_enabled_global() -> &'static AtomicBool {
    static MIC: AtomicBool = AtomicBool::new(false);
    &MIC
}

/// ③ 读取。
pub(crate) fn client_mic_enabled() -> bool {
    client_mic_enabled_global().load(Ordering::Relaxed)
}

/// ③ 写入（连接窗口开关）。
pub(crate) fn set_client_mic_enabled(enabled: bool) {
    client_mic_enabled_global().store(enabled, Ordering::Relaxed);
    tracing::info!(
        "[audio] client microphone (talkback) {}",
        if enabled { "enabled" } else { "disabled" }
    );
}

/// R-04：会话窗口状态栏音频状态（静音 / 播放中 / 已禁用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AudioUiState {
    /// 会话级开关关闭（`--no-audio` / Settings 取消勾选）。
    Disabled,
    /// 音频线程存活但无声（无设备降级 / 尚未收到包）。
    Muted,
    /// 播放中（解码管线已启动并投递 PCM）。
    Playing,
}

/// R-04：共享音频 UI 状态（M8-T021 P1 键控惯例：按 session_id 键控，
/// 音频线程写，各连接窗口状态栏每帧读自身会话）。
fn audio_window_state() -> &'static Mutex<HashMap<u64, AudioUiState>> {
    static S: OnceLock<Mutex<HashMap<u64, AudioUiState>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
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
    // R-04：音频 UI 状态（会话退出清理，窗口关闭后无残留）。
    if let Ok(mut m) = audio_window_state().lock() {
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
fn server_file_tx() -> &'static Mutex<Option<tokio::sync::mpsc::UnboundedSender<FileCommand>>> {
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
            // R-07-S4: 更新通道取 `[update].channel`（默认 release；配置缺失/非法回退 Stable）。
            let channel = kirin_desk_utils::config::Config::load()
                .ok()
                .and_then(|c| c.update.channel.parse().ok())
                .unwrap_or(UpdateChannel::Stable);
            Updater::new(data_dir, channel)
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
    /// R-07-S3: 最近提示信息（如 macOS/Linux 手动安装指引）。
    info: Option<String>,
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

/// 安装已下载更新（R-07-S3：安装职责收归 updater crate——
/// Windows 替换脚本由 `Updater::install` 生成并后台启动；macOS/Linux 返回
/// 手动安装提示）。
fn install_update(downloaded: &Path) -> Result<InstallOutcome, String> {
    updater().install(downloaded).map_err(|e| e.to_string())
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
fn pending_conn_rx(
) -> &'static Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<PendingConnection>>> {
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
                    format!("level={}->{} {audit_peer}", level.as_str(), active.as_str()),
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

/// M8-T030（R-06）：从 config `[media.gpu]` 注入单 GPU 偏好。
///
/// 读取失败 / 未配置 → 默认偏好（auto + 过滤虚拟），不阻断启动；
/// `KIRIN_GPU_PREFER` env 覆盖在 `gpu::apply_preferences` 内部完成
/// （env > config > auto，GPU-NF-005）。
fn apply_gpu_preferences_from_config() {
    use kirin_desk_media::gpu::{apply_preferences, GpuPreference, GpuPreferences};

    let cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
    let prefs = GpuPreferences {
        prefer: GpuPreference::parse_str(&cfg.media.gpu.prefer),
        filter_virtual: cfg.media.gpu.filter_virtual,
        virtual_keywords: cfg.media.gpu.virtual_keywords.clone(),
    };
    // 触发枚举 + 选择（首用缓存；选定结果仅日志，供编码/解码绑定读取）。
    let _ = apply_preferences(prefs);
}

pub fn run() {
    // Initialize logging from config
    init_logging_from_config();

    // R-10 (M15-T006): 全局 panic hook——panic 写入日志文件/控制台，
    // GUI 模式下由 show_panic_dialog 弹错误框（附日志路径）。
    kirin_desk_utils::logging::install_panic_hook();

    // M8-T030（R-06，GPU-FR-009）：启动时注入单 GPU 偏好（config `[media.gpu]`，
    // KIRIN_GPU_PREFER env 覆盖）。后续编码/解码/GPU 内核经 gpu 模块首用缓存
    // 绑定选定适配器；无真实 GPU → None 回退 FFmpeg 默认设备（GPU-NF-002）。
    apply_gpu_preferences_from_config();

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
            // M8-T038: 语言初始化（Config `[ui] language`，首个 UI 帧前生效；
            // 缺省 "system" → 跟随系统）。
            let initial_lang = kirin_desk_utils::config::Config::load()
                .map(|cfg| cfg.ui.language.clone())
                .unwrap_or_else(|_| "system".to_string());
            i18n::set_lang_code(&initial_lang);
            Ok(Box::new(KirinDeskApp {
                theme_mode: initial_mode,
                ui_language: initial_lang,
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
    /// S-21 (F-26)：客户端自报 Ed25519 公钥（base64）——审批弹窗展示其
    /// 真实指纹（而非自报 id）；审批前已解析校验，解析失败不弹窗直接拒绝。
    client_pubkey_base64: String,
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
    /// R-03 (R03-S4)：断线重连上下文（会话建立时登记；断开后自动/手动重连）。
    reconnect_ctx: Option<Arc<ReconnectCtx>>,
    /// R-03：重连任务停止标志（窗口关闭时置位，中止退避循环）。
    reconnect_stop: Option<Arc<AtomicBool>>,
    /// R-04：本会话音频状态（音频线程经键控 map 写入；状态栏徽标读取）。
    audio_state: AudioUiState,
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

    /// R-04：同步本会话音频状态（音频线程 → 键控 map → 状态栏徽标）。
    fn sync_audio_state(&mut self) {
        if let Ok(m) = audio_window_state().lock() {
            if let Some(st) = m.get(&self.session_id) {
                self.audio_state = *st;
            }
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
    /// R-03 (R03-S4)：断线重连上下文（窗口持有；None = 该连接不支持自动重连）。
    reconnect_ctx: Option<Arc<ReconnectCtx>>,
}

/// Signal to add a new connection window (addr + 输入发送通道 + 文件命令通道
/// + M8-T018 显示器控制通道 + M8-T021 P1 会话标识/渲染桥/关闭通道)。
fn add_window_signal() -> &'static Mutex<Vec<DesktopWindowSignal>> {
    static W: OnceLock<Mutex<Vec<DesktopWindowSignal>>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(Vec::new()))
}

/// R-03 (R03-S3/S4)：重连续接信号——断线重连成功后按 `session_id` 更新
/// **既有窗口**的通道（不新建窗口；UI 帧 drain 消费）。
struct ResumeSignal {
    session_id: u64,
    addr: String,
    bridge: kirin_desk_media::decoder::RenderBridge,
    input_tx: tokio::sync::mpsc::UnboundedSender<Vec<WireInputEvent>>,
    file_tx: tokio::sync::mpsc::UnboundedSender<FileCommand>,
    control_tx: tokio::sync::mpsc::UnboundedSender<ControlMessage>,
    close_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

/// R-03：重连续接信号队列（会话线程 push；UI 帧按 session_id 换通道）。
fn add_resume_signal() -> &'static Mutex<Vec<ResumeSignal>> {
    static R: OnceLock<Mutex<Vec<ResumeSignal>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Vec::new()))
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

// ════════════════════════════════════════════════════════════════
// R-03 (R03-S2/S4/S5)：断线重连 UI 状态
// ════════════════════════════════════════════════════════════════

/// R-03 (R03-S4)：桌面会话重连上下文（首次建连时登记；断线后自动/手动重连）。
#[derive(Clone)]
struct ReconnectCtx {
    /// 建连规格（含信任策略与凭据；core `ReconnectContext` 以此为凭）。
    options: ConnectionOptions,
    server_id: String,
    /// 展示用地址（窗口标题/日志）。
    addr_label: String,
    domain: String,
    device_type: String,
}

impl ReconnectCtx {
    /// 转为 core 层重连上下文（`attempt_reconnect` 消费）。
    fn to_core(&self) -> ReconnectContext {
        ReconnectContext {
            options: self.options.clone(),
            server_id: self.server_id.clone(),
        }
    }
}

/// R-03 (R03-S4)：重连状态（重连线程写入 → UI 帧读取覆盖层）。
#[derive(Debug, Clone, PartialEq)]
enum ReconnectUiState {
    /// 自动重连进行中（第 N 次 / 共 M 次；N=0 表示刚触发未到首次）。
    Retrying { attempt: u32, max: u32 },
    /// 不可重连（R03-S5：明确原因文案，不静默失败）。
    Failed { reason: String },
}

/// R-03：按 `session_id` 键控的重连状态（多窗口各自独立）。
fn reconnect_state_map() -> &'static Mutex<HashMap<u64, ReconnectUiState>> {
    static M: OnceLock<Mutex<HashMap<u64, ReconnectUiState>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// R-03：自动重连最大尝试次数（退避 1s/2s/4s/8s/16s，与 `ManagedConnection` 默认一致）。
const MAX_RECONNECT_ATTEMPTS: u32 = 5;

/// R-03 (R03-S1)：GUI `ClientTrust` → 抽取链路 `TrustPolicy`（确认策略回调注入；
/// 确认放行的公钥写入共享槽，供握手成功后记录 known_hosts，CLI-KH-002）。
fn core_trust_policy(
    trust: &ClientTrust,
    server_id: &str,
    confirmed_key: Arc<Mutex<Option<String>>>,
) -> TrustPolicy {
    match trust {
        ClientTrust::Verified(k) => TrustPolicy::Verified(k.clone()),
        ClientTrust::Confirm => {
            let id = server_id.to_string();
            let confirmed_key_cb = confirmed_key;
            TrustPolicy::Confirm(Some(Arc::new(move |key: &str| {
                let ok = known_hosts_or_confirm(&id, key);
                if ok {
                    if let Ok(mut ck) = confirmed_key_cb.lock() {
                        *ck = Some(key.to_string());
                    }
                }
                ok
            })))
        }
    }
}

/// R-03 (R03-S2)：把 "[v6]:port" / "v4:port" 拆为 (ip, port)（建连规格组装用）。
fn split_connect_addr(addr: &str) -> (String, u16) {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((ip, tail)) = rest.split_once(']') {
            let port = tail.trim_start_matches(':').parse().unwrap_or(3389);
            return (ip.to_string(), port);
        }
    }
    if let Some((ip, port)) = addr.rsplit_once(':') {
        return (ip.to_string(), port.parse().unwrap_or(3389));
    }
    (addr.to_string(), 3389)
}

/// R-03 (R03-S2/S4)：构造桌面会话的重连上下文（断线后自动重连用）。
/// 返回 `None` = 无设备身份（理论不可达，启动时已加载）。
fn build_reconnect_ctx(
    target: String,
    port: u16,
    server_id: String,
    challenge: String,
    device_type: &str,
    trust: ClientTrust,
    dns: Option<DnsConfig>,
    domain: String,
) -> Option<Arc<ReconnectCtx>> {
    let identity = global_identity().get()?;
    let addr_label = if dns.is_some() {
        // 域名模式：重连时重新发现（IP 可能变化），展示用原域名。
        server_id.clone()
    } else {
        // IP 模式：目标即地址。
        if target.contains(':') {
            format!("[{}]:{}", target, port)
        } else {
            format!("{}:{}", target, port)
        }
    };
    let confirmed_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    Some(Arc::new(ReconnectCtx {
        options: ConnectionOptions {
            target,
            port,
            server_id: server_id.clone(),
            challenge,
            device_type: device_type.to_string(),
            client_identity: Arc::new(identity.clone()),
            // 保持 GUI 既有行为（client_id = server_id；client_domain 固定）。
            client_id: server_id.clone(),
            client_domain: "gui-client.local".to_string(),
            dns,
            trust: core_trust_policy(&trust, &server_id, confirmed_key),
        },
        server_id,
        addr_label,
        domain,
        device_type: device_type.to_string(),
    }))
}

/// R-03 (R03-S4)：启动断线重连任务（自动/手动按钮共用）——`attempt_reconnect`
/// 按 1s/2s/4s…退避驱动（上限 30s），成功后以**同一 session_id** 续接会话
/// （R03-S3：`run_client_session_with_channel` push 续接信号，UI 帧换通道）。
/// 失败 → 覆盖层显示明确原因（R03-S5）。窗口关闭时置位停止标志中止退避。
fn spawn_reconnect(win: &mut ConnectionWindow) {
    let Some(ctx) = win.reconnect_ctx.clone() else {
        return;
    };
    let session_id = win.session_id;
    let stop = Arc::new(AtomicBool::new(false));
    win.reconnect_stop = Some(stop.clone());
    {
        let mut m = reconnect_state_map().lock().unwrap();
        m.insert(
            session_id,
            ReconnectUiState::Retrying {
                attempt: 0,
                max: MAX_RECONNECT_ATTEMPTS,
            },
        );
    }
    let state_map = reconnect_state_map();
    let addr_label = ctx.addr_label.clone();
    let core_ctx = ctx.to_core();
    tracing::info!(
        "[reconnect] session {}: spawning backoff reconnect",
        session_id
    );
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("reconnect rt");
        rt.block_on(async move {
            let mut conn = ManagedConnection::new(&core_ctx.server_id);
            conn.max_reconnect_attempts = MAX_RECONNECT_ATTEMPTS;
            conn.set_reconnect_context(core_ctx);
            // 每次尝试前更新覆盖层"第 N 次"。
            let on_attempt: Option<Arc<dyn Fn(u32) + Send + Sync>> =
                Some(Arc::new(move |attempt: u32| {
                    if let Ok(mut m) = state_map.lock() {
                        if let Some(ReconnectUiState::Retrying { attempt: cur, .. }) =
                            m.get_mut(&session_id)
                        {
                            *cur = attempt;
                        }
                    }
                }));
            match attempt_reconnect(&mut conn, on_attempt, Some(stop)).await {
                Ok(channel) => {
                    tracing::info!(
                        "[reconnect] session {} reconnected — resuming session",
                        session_id
                    );
                    // R03-S3：会话层续接（同一 session_id；UI 帧按续接信号换通道，
                    // 不再新建窗口）。
                    run_client_session_with_channel(
                        channel,
                        addr_label,
                        Some(ctx),
                        Some(session_id),
                    )
                    .await;
                }
                Err(f) => {
                    tracing::warn!("[reconnect] session {} failed: {}", session_id, f.reason);
                    // R03-S5：明确不可重连原因（不静默失败）。
                    if let Ok(mut m) = state_map.lock() {
                        m.insert(
                            session_id,
                            ReconnectUiState::Failed {
                                reason: f.message(),
                            },
                        );
                    }
                    if let Ok(mut s) = connection_status().lock() {
                        *s = f.message();
                    }
                }
            }
        });
    });
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
    match KnownHostsStore::load().map(|store| store.check(device_id, pubkey_base64)) {
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
        Ok(fp) => tracing::info!("[known_hosts] recorded '{}' fingerprint {}", device_id, fp),
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
    use kirin_desk_core::crypto::handshake::{
        client_handshake_with_confirm, CoreReason, PinExpectation,
    };
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
            // R-02：pin 强类型——known_hosts/DNS TXT 已确认公钥 → `Exact` 强制比对。
            let pin = match PinExpectation::exact_from_base64(&expected) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("[shell] invalid trusted key: {}", e);
                    return;
                }
            };
            client_handshake_with_confirm(
                stream,
                client_id,
                &server_id,
                "gui-client.local",
                "shell",
                server_name,
                pin,
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
                // R-02：无带外公钥 → 确认回调必填（`UserConfirmRequired`，无跳过路径）。
                PinExpectation::None(CoreReason::UserConfirmRequired),
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
        *s = format!(
            "[shell] Connected to {}@{} (transport: TCP)",
            server_id, addr
        );
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
fn map_file_status(
    st: kirin_desk_core::connection::file_transfer::TransferStatus,
) -> FileTaskStatus {
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
        let Some(s) = self.senders.get(&tid) else {
            return;
        };
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
        let Some(r) = self.receivers.get(&tid) else {
            return;
        };
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
        let Some(s) = self.senders.get(&tid) else {
            return false;
        };
        let meta = FileOfferMeta {
            name: s.name.clone(),
            size: s.size,
        };
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
            let total_blocks = self
                .senders
                .get(&tid)
                .map(|s| s.total_blocks())
                .unwrap_or(0);
            let read = {
                let Some(file) = self.src_files.get_mut(&tid) else {
                    break;
                };
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
            let Some(sender) = self.senders.get_mut(&tid) else {
                return;
            };
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
            let Some(sender) = self.senders.get_mut(&tid) else {
                return;
            };
            let was_complete = sender.is_complete();
            sender.on_ack(frame.seq);
            (
                sender.all_acked() && !was_complete,
                sender.sha256,
                sender.total_blocks(),
            )
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
                let _ = self
                    .send_frame(FileTransferFrame::simple(tid, FileOp::Reject, 0))
                    .await;
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
            acc.total_blocks = self
                .receivers
                .get(&tid)
                .map(|r| r.total_blocks)
                .unwrap_or(0);
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
                let _ = self
                    .send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0))
                    .await;
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
                let _ = self
                    .send_frame(FileTransferFrame::simple(tid, FileOp::FinishAck, 0))
                    .await;
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
                let _ = self
                    .send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0))
                    .await;
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
                    name: self
                        .pending_offers
                        .get(&tid)
                        .map(|(m, _)| m.name.clone())
                        .unwrap_or_default(),
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
            let _ = self
                .send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0))
                .await;
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
            let _ = self
                .send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0))
                .await;
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
            let _ = self
                .send_frame(FileTransferFrame::simple(tid, FileOp::Cancel, 0))
                .await;
            if let Some(r) = self.receivers.get_mut(&tid) {
                r.cancel();
            }
            if let Ok(mut p) = self.panel.lock() {
                p.upsert(FileTask {
                    transfer_id: tid,
                    name: self
                        .pending_offers
                        .get(&tid)
                        .map(|(m, _)| m.name.clone())
                        .unwrap_or_default(),
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

/// P2（修复计划 2026-08-03）：音频包发送——大小分流 + 失败不中断。
///
/// - 单包 ≤ [`MAX_PACKET_PAYLOAD`]（≈1151B）走 `send_packets` 小分片路径
///   （与未来 QUIC datagram 迁移语义一致，保持"音频不排视频大帧后面"的
///   设计意图）；
/// - 超限（高码率 opus 单帧可至 1275B > 1151B）改走 `send_big_packet`
///   大帧路径（16 MiB 上限，与视频/文件传输共用）；
/// - 任一路径失败仅记 warn 丢弃该批（音频可丢，播放端静音补位），**不中断
///   发送循环**——与视频"失败即断"语义区分，杜绝一帧超限静音整条音频。
async fn send_audio_packets(
    sender: &Arc<tokio::sync::Mutex<SecureChannelSender>>,
    pkts: &[EncodedPacket],
) {
    let mut s = sender.lock().await;
    let mut small: Vec<EncodedPacket> = Vec::new();
    let mut big: Vec<EncodedPacket> = Vec::new();
    for pkt in pkts {
        if pkt.data.len() > MAX_PACKET_PAYLOAD {
            big.push(pkt.clone());
        } else {
            small.push(pkt.clone());
        }
    }
    if !small.is_empty() {
        if let Err(e) = s.send_packets(&small).await {
            tracing::warn!("Audio send failed (small path): {e} — dropping batch");
        }
    }
    for pkt in big {
        if let Err(e) = s.send_big_packet(&pkt).await {
            tracing::warn!("Audio send failed (big path): {e} — dropping packet");
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
    reconnect: Option<Arc<ReconnectCtx>>,
) {
    // R-03 (R03-S1)：初始建连共用抽取链路（resolve_peer + connect_peer），
    // 会话机制复用 run_client_session_with_channel（重连续接同入口）。
    tracing::info!("TCP connecting to {} ...", addr);
    if let Ok(mut s) = connection_status().lock() {
        *s = format!("Connecting: {} ...", addr);
    }
    let Some(client_id) = global_identity().get() else {
        tracing::error!("No device identity loaded, can't handshake");
        return;
    };
    let (ip, port) = split_connect_addr(&addr);
    // 确认回调共享槽（Confirm 路径：确认放行的公钥供成功后记录 known_hosts，CLI-KH-002）。
    let confirmed_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let opts = ConnectionOptions {
        target: ip,
        port,
        server_id: server_id.clone(),
        challenge: challenge.clone(),
        device_type: device_type.to_string(),
        client_identity: Arc::new(client_id.clone()),
        client_id: server_id.clone(), // 保持 GUI 既有行为
        client_domain: "gui-client.local".to_string(), // 保持 GUI 既有行为
        dns: None,                    // GUI 发现在调用方完成，此处直连
        trust: core_trust_policy(&trust, &server_id, confirmed_key.clone()),
    };
    let peer = match resolve_peer(&opts).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("resolve peer failed: {}", e);
            if let Ok(mut s) = connection_status().lock() {
                *s = format!("{}", e);
            }
            return;
        }
    };
    // 握手阶段状态（与旧流程同文案）。
    if let Ok(mut s) = connection_status().lock() {
        *s = format!("Handshaking: {}@{} ...", server_id, addr);
    }
    let outcome = match connect_peer(&opts, &peer).await {
        Ok(o) => o,
        Err(ConnectError::Tcp(e)) => {
            tracing::error!("TCP connect to {} FAILED: {}", addr, e);
            if let Ok(mut s) = connection_status().lock() {
                *s = format!("TCP connect FAILED: {}", addr);
            }
            return;
        }
        Err(e) => {
            tracing::error!("Handshake FAILED: {}", e);
            if let Ok(mut s) = connection_status().lock() {
                *s = format!("Handshake FAILED: {}", e);
                // M8-T017-P2 (CLI-TMP-003): 携带挑战码时追加引导提示（防枚举，纯客户端文案）。
                if let ConnectError::Handshake(_) = &e {
                    if let Some(h) = crate::policy::connect_failure_challenge_hint(&challenge) {
                        s.push('\n');
                        s.push_str(&h);
                    }
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
        *s = format!("Connected to {}@{} (transport: TCP)", server_id, addr);
    }
    // M15 (CLI-KH-002): 连接成功 → 记录 known_hosts；M10-T003: 自动保存设备。
    let trusted_key = match &trust {
        ClientTrust::Verified(k) => Some(k.clone()),
        ClientTrust::Confirm => confirmed_key.lock().ok().and_then(|k| k.clone()),
    };
    if let Some(key) = &trusted_key {
        record_known_host(&server_id, key);
        save_device_to_store(&addr, &server_id, key, device_type, &domain);
    }
    run_client_session_with_channel(outcome.channel, addr, reconnect, None).await;
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
    // R-03 (R03-S3/S4)：重连续接上下文 / 续接会话标识（重连成功后复用同一
    // session_id 更新既有窗口，不新建）。
    reconnect: Option<Arc<ReconnectCtx>>,
    resume_session_id: Option<u64>,
) {
    use kirin_desk_core::crypto::handshake::{
        client_handshake_with_confirm, CoreReason, PinExpectation,
    };
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
            // R-02：pin 强类型——DNS TXT 已确认公钥 → `Exact` 强制比对。
            let pin = match PinExpectation::exact_from_base64(&expected) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("invalid trusted key: {}", e);
                    return;
                }
            };
            client_handshake_with_confirm(
                stream,
                client_id,
                &server_id,
                "gui-client.local",
                "desktop",
                server_name,
                pin,
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
                // R-02：无带外公钥 → 确认回调必填（`UserConfirmRequired`，无跳过路径）。
                PinExpectation::None(CoreReason::UserConfirmRequired),
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

    // R-03 (R03-S3)：握手完成 → 会话机制（通道拆分/任务/窗口信号）统一入口。
    run_client_session_with_channel(ch, addr_label, reconnect, resume_session_id).await;
}
/// R-03 (R03-S3/S4)：会话机制统一入口——通道拆分 → 输入/控制/文件任务 →
/// 视频接收解码 → 窗口信号。首连（`resume_session_id = None`）push 新建窗口
/// 信号；断线重连续接（`Some(session_id)`）push 续接信号（UI 帧按 session_id
/// 更新既有窗口通道，不新建窗口）。与 R-04（音频接线）按函数级分块。
#[allow(clippy::too_many_arguments)]
async fn run_client_session_with_channel(
    channel: SecureChannel,
    addr_label: String,
    reconnect: Option<Arc<ReconnectCtx>>,
    resume_session_id: Option<u64>,
) {
    // M8-T021 P1: 会话标识（窗口键控状态 key；窗口 id 与之解耦）。
    // R-03：重连续接复用同一 session_id（窗口已存在，键控状态继续有效）。
    let session_id = resume_session_id.unwrap_or_else(next_session_id);
    // R-32（M13-T002 阶段 B）：握手协商的编码标准——`channel` 随后
    // `into_split()` 字段不可用，先取出（Copy 枚举，可自由捕获进解码线程）。
    // 空/未知 → H.264 兜底（未协商/旧服务端场景与既有行为一致）。
    let negotiated_codec = kirin_desk_media::encoder::Codec::from_str(&channel.selected_codec)
        .unwrap_or(kirin_desk_media::encoder::Codec::H264);
    // 本机身份（文件会话盐需要公钥；启动时已加载）。
    let Some(client_id) = global_identity().get() else {
        tracing::error!("No device identity loaded, can't start session");
        return;
    };
    // M9: 拆分通道为读写半通道——视频接收（读半）与输入发送（写半）
    // 各自单任务独占、无锁并发（TCP 双工 + 每消息随机 nonce）。
    // M13-T006: 写半进一步由多个任务共享（input/clipboard/文件），
    // 用 Arc<tokio::sync::Mutex<SecureChannelSender>> 保证帧边界。
    let peer_id = channel.peer_id.clone();
    let (reader, writer) = channel.into_split();
    let sender_shared: Arc<tokio::sync::Mutex<SecureChannelSender>> =
        Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(writer)));
    let mut video_receiver = SecureChannelReceiver::new(reader);

    // M9: 输入发送任务（UI 线程事件批次 → 加密可靠流 InputEcho）。
    // 窗口关闭 → UI 侧 Sender drop → recv 返回 None → 任务退出。
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<WireInputEvent>>();
    // M13-T003: 剪贴板推送通道（轮询任务产出的 EncodedPacket 批）。
    let (clip_tx, mut clip_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<EncodedPacket>>();
    // M8-T018: 显示器控制消息通道（下拉切换 / 列表刷新 → `ChannelTag::Control`）。
    let (control_tx, mut control_rx) = tokio::sync::mpsc::unbounded_channel::<ControlMessage>();
    // M13-T006: 文件命令（UI → 文件会话）与帧转发（接收循环 → 文件会话）。
    let (file_cmd_tx, mut file_cmd_rx) = tokio::sync::mpsc::unbounded_channel::<FileCommand>();
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
    // R-03 (R03-S3/S4)：首连 → 新建窗口信号；重连续接 → 续接信号（UI 帧按
    // session_id 更新既有窗口的通道，不新建窗口）。
    if resume_session_id.is_some() {
        if let Ok(mut w) = add_resume_signal().lock() {
            w.push(ResumeSignal {
                session_id,
                addr: addr_label.clone(),
                bridge: bridge.clone(),
                input_tx,
                file_tx: file_cmd_tx.clone(),
                control_tx: control_tx.clone(),
                close_tx,
            });
        }
    } else if let Ok(mut w) = add_window_signal().lock() {
        w.push(DesktopWindowSignal {
            session_id,
            addr: addr_label.clone(),
            bridge: bridge.clone(),
            input_tx,
            file_tx: file_cmd_tx.clone(),
            control_tx: control_tx.clone(),
            close_tx,
            reconnect_ctx: reconnect,
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
    let (pkt_tx, pkt_rx) = std::sync::mpsc::channel::<kirin_desk_media::decoder::DecoderPacket>();

    // 1. 解码线程：FFmpeg 解码为阻塞同步调用，用专用 std::thread
    //    （避免污染 tokio runtime；解码器 Send 非 Sync，线程独占）。
    let decode_bridge = bridge.clone();
    let decode_handle = std::thread::Builder::new()
        .name("kirin-video-decode".into())
        .spawn(move || {
            // P2B：VideoDecoderPipeline（回退链 qsv→cuvid→…→软解）。
            // R-32（M13-T002 阶段 B）：解码标准取握手协商结果
            // （`negotiated_codec`；空/未知 → H.264 兜底）。
            let mut decoder = match kirin_desk_media::decoder::factory::create_video_decoder(
                negotiated_codec,
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
                let Some(dec) = decoder.as_mut() else {
                    continue;
                };
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

    // R-04：音频解码 + 播放线程（会话级开关；libopus/播放设备缺失 → 静音
    // 降级，视频/键鼠不受影响）。接收循环按 `ChannelTag::Audio` 分流投递。
    // 线程退出条件：会话结束（sender drop → `run()` 返回）或开关关闭（不建线程）。
    let audio_pkt_tx = if audio_enabled_global().load(Ordering::Relaxed) {
        let (audio_tx, audio_rx) =
            std::sync::mpsc::channel::<kirin_desk_media::decoder::AudioPacket>();
        let audio_sid = session_id;
        let audio_handle = std::thread::Builder::new()
            .name("kirin-audio-decode".into())
            .spawn(move || {
                let mut pipe =
                    match kirin_desk_media::decoder::audio::AudioDecodePipeline::new(audio_rx) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::info!("Audio decode disabled (init failed): {e}");
                            if let Ok(mut m) = audio_window_state().lock() {
                                m.insert(audio_sid, AudioUiState::Muted);
                            }
                            return;
                        }
                    };
                match pipe.start_playback() {
                    Ok(()) => {
                        tracing::info!("Audio playback started (WASAPI shared render)");
                        if let Ok(mut m) = audio_window_state().lock() {
                            m.insert(audio_sid, AudioUiState::Playing);
                        }
                    }
                    Err(e) => {
                        tracing::info!("Audio playback unavailable ({e}) — decode-only (silent)");
                        if let Ok(mut m) = audio_window_state().lock() {
                            m.insert(audio_sid, AudioUiState::Muted);
                        }
                    }
                }
                // run()：音频通道关闭（会话结束）→ Ok 返回，线程干净退出。
                let _ = pipe.run();
                if let Ok(mut m) = audio_window_state().lock() {
                    m.insert(audio_sid, AudioUiState::Muted);
                }
                tracing::info!("Audio pipeline exited");
            })
            .expect("spawn audio decode thread");
        // 线程句柄持有即保活（std::thread 句柄 drop 不 join）；退出由通道关闭驱动。
        let _ = audio_handle;
        Some(audio_tx)
    } else {
        // 开关关闭：状态栏显示「音频已禁用」，不建线程、不缓冲。
        if let Ok(mut m) = audio_window_state().lock() {
            m.insert(session_id, AudioUiState::Disabled);
        }
        None
    };
    // M8-T032：② 播放开关进程级持久——上次会话关闭的播放开关跨会话保持，
    // 新会话初始徽标对齐（关 → 静音；总开关关时不覆盖 Disabled）。
    if audio_pkt_tx.is_some() && !client_audio_play() {
        if let Ok(mut m) = audio_window_state().lock() {
            m.insert(session_id, AudioUiState::Muted);
        }
    }

    // M8-T032：③ 客户端麦克风回传（talkback）——本机麦克风 → 服务端播放。
    // 捕获+编码为阻塞调用 → blocking 线程池；`client_mic_enabled()` 逐轮读取
    // （关 → 停发，动态生效）；批次经 tokio 通道交发送循环（与输入/控制/文件
    // 写半互斥，tag=Audio，wire 映射与 ChannelTag 对齐——无需协议改动）。
    // 会话结束（窗口关闭 / 断链）→ 发送循环退出 → 通道关闭 → 捕获线程退出。
    if audio_enabled_global().load(Ordering::Relaxed) {
        let sender_mic = sender_shared.clone();
        let (mic_pkt_tx, mut mic_pkt_rx) =
            tokio::sync::mpsc::channel::<Vec<EncodedPacket>>(32);
        tokio::task::spawn_blocking(move || {
            let mut pipeline = match kirin_desk_media::AudioPipeline::new_mic() {
                Ok(p) => p,
                Err(e) => {
                    // 非 Windows / 无麦克风设备：优雅降级（info 日志，视频/键鼠不受影响）。
                    tracing::info!("Microphone disabled (pipeline init failed): {e}");
                    return;
                }
            };
            if let Err(e) = pipeline.start() {
                tracing::info!("Microphone disabled (capture start failed): {e}");
                return;
            }
            tracing::info!(
                "Microphone capture started ({}Hz/{}ch)",
                pipeline.sample_rate(),
                pipeline.channels()
            );
            loop {
                // M8-T032：③ 动态门控——关 → 停发（消费丢弃防通道堆积）；
                // 再开 → 恢复（无需重连）。
                if !client_mic_enabled() {
                    let _ = pipeline.next_packets();
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                match pipeline.next_packets() {
                    Ok(pkts) if !pkts.is_empty() => {
                        // 发送循环忙（通道满）→ 丢批次（音频可丢，播放端静音补位）。
                        if mic_pkt_tx.try_send(pkts).is_err() {
                            tracing::debug!("Mic batch dropped (send loop busy)");
                        }
                    }
                    Ok(_) => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(e) => {
                        tracing::warn!("Microphone pipeline error: {e} — stopping mic");
                        break;
                    }
                }
            }
            tracing::info!("Microphone capture stopped");
        });
        // 发送循环：会话结束（stop / 断链）→ 通道关闭 → 退出。
        tokio::spawn(async move {
            while let Some(pkts) = mic_pkt_rx.recv().await {
                // P2（修复计划 2026-08-03）：大小分流 + 失败不中断（音频可丢）。
                send_audio_packets(&sender_mic, &pkts).await;
            }
        });
    }

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
        // M8-T032：② 播放开关上次值（状态变化检测 → 徽标同步）。
        let mut audio_play_last = client_audio_play();
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
                        tracing::info!("DisplayListResp: {} display(s) available", displays.len());
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
                        tracing::info!("PrivacyModeAck: ok={} active={:?}", ok, active_level);
                        // M8-T021 P1: 键控写入本会话的隐私状态。
                        let mut st = client_privacy_state().lock().unwrap();
                        let st = st.entry(session_id).or_default();
                        // 降级判断：请求 Black 但生效 Lock（SRV-PRIV-013）→ toast。
                        let toast = privacy::ack_toast(ok, active_level, st.requested);
                        st.ack = Some(privacy::PrivacyAckState {
                            level: active_level,
                            seq: st.ack.as_ref().map_or(0, |a| a.seq).saturating_add(1),
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
            // R-04：音频包（Opus 帧）→ 音频解码/播放线程（PTS 来自帧头，
            // jitter 排序 + WASAPI 播放；会话开关关闭时服务端不发音频包）。
            // M8-T032：② 播放开关——关 → 丢弃到达的包（动态静音），
            // 状态切换时同步徽标（静音/播放中）。
            if tag == ChannelTag::Audio {
                let play = client_audio_play();
                if play != audio_play_last && audio_pkt_tx.is_some() {
                    if let Ok(mut m) = audio_window_state().lock() {
                        m.insert(
                            session_id,
                            if play {
                                AudioUiState::Playing
                            } else {
                                AudioUiState::Muted
                            },
                        );
                    }
                }
                audio_play_last = play;
                if play {
                    if let Some(tx) = &audio_pkt_tx {
                        let pkt = kirin_desk_media::decoder::AudioPacket {
                            pts: _header.pts,
                            data: payload,
                        };
                        if tx.send(pkt).is_err() {
                            break; // 音频线程已退出（会话结束）
                        }
                    }
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
                    for (idx, frame_nalus) in KirinDeskApp::window_frame_nalus(&window)
                        .into_iter()
                        .enumerate()
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
                *s = "解析响应签名校验失败（ID-SEC-001）— 可能 server_pubkey 错误或中间人"
                    .to_string();
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
    let from_peer = tunnel.device_id.clone().unwrap_or_else(|| {
        kirin_desk_utils::known_hosts::fingerprint(&client_id.public_key_base64())
    });
    if let Ok(mut s) = connection_status().lock() {
        *s = format!(
            "Connecting: {} (relay {}) ...",
            device_id, tunnel.server_addr
        );
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
    // R-03：ID 模式暂不支持自动重连（重连需 re-resolve 中继路径，None 上下文）。
    run_client_session_with_stream(
        stream,
        format!("{} (via relay, {})", device_id, path),
        device_id2,
        trust,
        challenge,
        String::new(),
        "desktop",
        None,
        None,
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
    /// GoDaddy API base URL（未保存时回退生产环境）。
    api_url: String,
    domain: String,
    /// M9-DNS022 (UI-DNS-004): DNS 服务商是否已配置凭据（Connect 页域名模式 /
    /// 状态栏徽标判定；`load_config` 与 Domain 页保存后刷新——`api_key` 等
    /// 字段仅 godaddy 兼容填充，非 godaddy 服务商不能以它们判定）。
    dns_configured: bool,
    device_id: String,
    nickname: String,
    challenge_code: String,
    allowed_domains: String,
    /// M8-T027 (UI-IDWL-001): Settings ID 白名单文本框（逗号/换行分隔 device-id，
    /// 保存写 `[network].allowed_ids`，永久条目，即时生效）。
    allowed_ids: String,
    /// M8-T027 (UI-IDWL-002): ID 白名单条目列表缓存（含过期条目与永久条目，
    /// 供 Settings 展示过期/永久标记与逐条删除；随保存/删除刷新）。
    id_whitelist_entries: Vec<kirin_desk_utils::config::IdWhitelistEntry>,
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
    // M8-T033: 本机全局 IPv4（身份卡展示；无则 "N/A"）。
    local_ipv4: String,
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
    /// M8-T037: 编辑弹窗「地址 (IP/域名)」输入（预填：有域名 → 域名，否则 IPv6）。
    edit_host: String,
    edit_port: String,
    /// M8-T037: 编辑弹窗「备注名」「挑战码」（挑战码密文 + 👁）。
    edit_remark: String,
    edit_challenge: String,
    show_secret_edit_challenge: bool,
    // M15-T008: 主题模式（Config `[ui] theme`，默认 Light）+ 密文输入可见开关
    theme_mode: ThemeMode,
    /// M8-T038: 语言选择（"system" 跟随系统 | "zh" | "en"；Config `[ui] language`）。
    ui_language: String,
    show_secret_connect: bool,
    // M9-DNS022: show_secret_api 随 DNS 组迁至 Domain 页（domain_panel 内部持有）。
    show_secret_challenge: bool,
    // M13-T005: 无人值守模式（Settings 页状态 + 启动时序；M8-T037 三开关联动）
    unattended_enabled: bool,
    unattended_autostart: bool,
    /// M8-T037: 显示名「默认受控」——应用启动自动开启服务端（自动监听）。
    unattended_auto_server: bool,
    // M8-T026: 内网穿透设置（Tunnel 独立页，M8-T039；proxies 多行文本）。
    tunnel_enabled: bool,
    tunnel_mode: String,
    tunnel_server_addr: String,
    tunnel_token: String,
    tunnel_proxies: String,
    show_secret_tunnel_token: bool,
    // M8-T039 新增（表单值，P3；运行态字段 tunnel_runtime_state 归 P5 追加）：
    tunnel_bind_addrs: String, // 监听地址列表（逗号分隔，默认 "0.0.0.0,::"）
    tunnel_bind_port: String,  // 端口（默认 "7000"）
    tunnel_port_range: String, // 端口范围（默认 "60000-61000"）
    tunnel_auto_start: bool,   // GUI 最后运行状态（§3.4.3，启动/停止写入，P5 消费）
    tunnel_notice: String,     // 页面瞬态提示（「已保存」等）
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
    /// M8-T034: Dashboard 服务端设置保存反馈（小保存按钮旁展示）。
    dashboard_status: String,
    /// M8-T028 (UI-BTY-028): 复制成功浮出提示（(预览文案, 点击时刻)，2s 自动消失）。
    copied_feedback: Option<(String, std::time::Instant)>,
    /// M9-DNS000: 域名维护页面状态（Domain 标签页，Dashboard 右侧按钮进入）。
    domain_panel: domain_panel::DomainPanelState,
    /// M8-T040: DDNS 维护卡控制器（状态共享槽 + worker 句柄；WBS 6.2）。
    ddns_ui: domain_panel::DdnsUi,
}

/// M8-T028 (UI-BTY-028): 状态栏「Copied: …」浮出提示持续时间。
const COPY_TOAST_DURATION: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(PartialEq)]
enum Tab {
    Dashboard,
    /// M9-DNS000 (UI-DNS-001~009): 域名维护客户端页面（导航按钮位于
    /// Dashboard 右 / Devices 左）。
    Domain,
    Devices,
    Connect,
    /// M8-T039：内网穿透独立页（通用 TCP 反向代理）。
    Tunnel,
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
        tf!("devices.last_seen_today", local.format("%H:%M"))
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
fn save_device_to_store(
    addr: &str,
    server_id: &str,
    pubkey: &str,
    device_type: &str,
    domain: &str,
) {
    let port = addr
        .rsplit(':')
        .next()
        .and_then(|p| p.trim_end_matches(']').parse().ok())
        .unwrap_or(0);
    let device = SavedDevice {
        id: server_id.to_string(),
        nickname: server_id.to_string(),
        // M8-T037: 新字段默认值（GUI 自动保存路径不设备注/挑战码/排序）。
        remark: String::new(),
        challenge: String::new(),
        sort_order: 0,
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

/// R-10 (M15-T006): 待显示 panic 摘要（`show_panic_dialog` 每帧轮询
/// `take_panic_message` 填充；点「关闭」清除）。
fn panic_dialog_msg() -> &'static Mutex<Option<String>> {
    static M: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(None))
}

/// R-10 (M15-T006): panic 错误框——有 panic 摘要时弹居中模态窗
/// （消息摘要 + 日志文件路径可复制），点「关闭」后不再显示。
fn show_panic_dialog(ctx: &egui::Context, theme: &Theme) {
    if let Some(msg) = kirin_desk_utils::logging::take_panic_message() {
        *panic_dialog_msg().lock().unwrap() = Some(msg);
    }
    let msg = panic_dialog_msg().lock().unwrap().clone();
    if let Some(msg) = msg {
        let log_path = kirin_desk_utils::logging::current_log_path(
            &kirin_desk_utils::logging::default_log_dir(),
        );
        egui::Window::new(t!("dialog.panic.title"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("dialog.panic.body")).color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add_space(4.0);
                ui.separator();
                ui.add(
                    egui::Label::new(egui::RichText::new(&msg).monospace().size(theme.mono_size))
                        .selectable(true),
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("dialog.panic.log_label")).color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                    ui.add(
                        egui::Label::new(egui::RichText::new(log_path.display().to_string()))
                            .selectable(true),
                    );
                    copy_button(ui, theme, &log_path.display().to_string());
                });
                ui.add_space(4.0);
                if action_button(ui, theme, ButtonKind::Primary, t!("dialog.close"), ButtonState::Enabled)
                    .clicked()
                {
                    *panic_dialog_msg().lock().unwrap() = None;
                }
            });
    }
}

impl eframe::App for KirinDeskApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if !self.config_loaded {
            self.load_config();
            self.config_loaded = true;
            // M13-T005 (UA-SRV-001): 无人值守自动开启服务端——启动即监听，
            // 无需人工点击 Dashboard 启动按钮；失败处理见 start_server 内审计。
            // M8-T037: 条件放宽为仅「默认受控」——默认受控独立于无人值守
            // 总开关生效（无人值守关、默认受控开时同样自动监听）。
            if self.unattended_auto_server {
                self.start_server();
            }
            // M8-T039 §3.4.3: 隧道最后运行状态恢复——auto_start=true →
            // 按上次模式自动启动；失败 → 状态行显示原因且 auto_start 保持
            // true（下次启动继续尝试，与启动失败同语义）。
            if self.tunnel_auto_start {
                self.tunnel_start();
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

        // M8-T034: 每帧从共享运行态同步服务端状态——bind 失败 / 监听线程
        // 退出即时反映到「允许受控」开关（修复旧实现 bind 失败只打日志、
        // `server_running` 假死）。`server_status` 保留连接审批等消息文案
        // （仅「Starting…」阶段由运行态接管为「监听中 :port」）。
        {
            let stop_requested = server_stop_signal().load(Ordering::Relaxed);
            let st = server_runtime_state().lock().unwrap();
            if st.starting {
                // bind 进行中（乐观态：点击后 → 线程写回结果前保持 ON）。
                self.server_running = true;
            } else if st.listening && !stop_requested {
                self.server_running = true;
                if self.server_status.is_empty() || self.server_status.starts_with("Starting") {
                    self.server_status = format!("监听中 :{}", st.port);
                }
            } else if self.server_running {
                // 已请求停止（线程退出中）或从未成功（bind 失败）→ 回 OFF。
                self.server_running = false;
                self.server_status = st
                    .error
                    .clone()
                    .map(|e| format!("启动失败: {}", e))
                    .unwrap_or_else(|| "已停止".to_string());
            }
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
            egui::Window::new(t!("dialog.approve.title"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    // M15-T008: 卡片化——设备名加粗 + 类型徽标 + 指纹 Mono + 语义按钮。
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("dialog.approve.desc"))
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
                                egui::RichText::new(tf!(
                                    "dialog.approve.domain",
                                    pc.client_domain
                                ))
                                .monospace()
                                .color(theme.fg_weak),
                            )
                            .selectable(true),
                        );
                        // M8-T028 (UI-BTY-026): Domain 一键复制（空值按钮自动禁用）。
                        self.copied_button(ui, &theme, &pc.client_domain);
                    });
                    // S-21 (F-26)：指纹 = 客户端**公钥**的真实 SHA-256 指纹
                    // （对齐 known_hosts 指纹格式），不再把自报 client_id 当
                    // 指纹展示——审批人据此核实"批准的是谁"。
                    let client_fp = kirin_desk_utils::known_hosts::fingerprint(
                        &pc.client_pubkey_base64,
                    );
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(tf!("dialog.approve.fingerprint", client_fp))
                                .monospace()
                                .size(theme.mono_size)
                                .color(theme.fg),
                        )
                        .selectable(true),
                    );
                    // M8-T028 (UI-BTY-026): 指纹一键复制（真实公钥指纹）。
                    self.copied_button(ui, &theme, &client_fp);
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("dialog.approve.known_hint"))
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(tf!(
                                "dialog.pubkey_fmt",
                                &pc.client_pubkey_base64
                                    [..pc.client_pubkey_base64.len().min(24)]
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
                            t!("dialog.approve.accept"),
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
                            t!("dialog.approve.reject"),
                            ButtonState::Enabled,
                        )
                        .clicked()
                        {
                            self.approve_connection(pc.id, false);
                        }
                    });
                });
        }

        // R-10 (M15-T006): panic 错误框（每帧轮询；关闭后不再显示）。
        show_panic_dialog(ctx, &theme);

        // --- M15 (CLI-KH-001): 首次连接指纹确认模态框 ---
        // 连接线程设置 `pending_fingerprint` 后阻塞等待；本模态框应答后放行。
        // 窗口被关闭（X）→ Sender drop → 连接线程 recv Err → 视为拒绝。
        let pending_fp = pending_fingerprint().lock().ok().and_then(|mut g| g.take());
        if let Some(pfp) = pending_fp {
            let mut accepted = false;
            let mut rejected = false;
            egui::Window::new(t!("dialog.fingerprint.title"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("dialog.fingerprint.body"))
                                .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                    ui.add_space(4.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(t!("dialog.fingerprint.device_label"))
                                    .color(theme.fg_weak),
                            )
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
                            egui::RichText::new(t!("dialog.fingerprint.sha_hint"))
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(tf!(
                                "dialog.pubkey_fmt",
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
                            t!("dialog.fingerprint.confirm"),
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
                            t!("dialog.fingerprint.reject"),
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
                pending_fingerprint()
                    .lock()
                    .ok()
                    .map(|mut g| *g = Some(pfp));
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
                badge(
                    ui,
                    &theme,
                    kirin_desk_updater::APP_VERSION,
                    BadgeKind::Neutral,
                );
                ui.separator();
                // 图标化标签页（选中态品牌色胶囊）
                // M9-DNS000: Domain 按钮位于 Dashboard 右侧 / Devices 左侧——
                // 域名维护客户端页面入口。
                for (tab, icon, name) in [
                    (Tab::Dashboard, "🏠", t!("session.tab.dashboard")),
                    (Tab::Domain, "🌐", t!("session.tab.domain")),
                    (Tab::Devices, "🖥", t!("session.tab.devices")),
                    (Tab::Connect, "🔗", t!("session.tab.connect")),
                    (Tab::Tunnel, "🚇", t!("tunnel.tab")),
                    (Tab::Settings, "⚙", t!("session.tab.settings")),
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
                    badge(
                        ui,
                        &theme,
                        &tf!("session.pending_fmt", wc),
                        BadgeKind::Danger,
                    );
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
                // M9-DNS000 (UI-DNS-004): 文案泛化——不再出现 GoDaddy 字样，
                // 判定走 `dns_configured`（任意已注册服务商，非 godaddy 专属）。
                if self.dns_configured {
                    badge(ui, &theme, t!("session.statusbar.dns_ready"), BadgeKind::Success);
                } else {
                    badge(ui, &theme, t!("session.statusbar.dns_na"), BadgeKind::Warning);
                }
                ui.separator();
                // M15-T008: StatusDot——监听=绿 / 停止=灰
                if self.server_running {
                    status_dot(ui, theme.success, t!("session.statusbar.server_listening"));
                } else {
                    status_dot_char(ui, theme.fg_weak, "○", t!("session.statusbar.server_stopped"));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // M8-T028 (UI-BTY-028): 复制成功浮出提示（右侧弱色，2s 自动消失）。
                    if let Some((value, _)) = &self.copied_feedback {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(tf!("session.statusbar.copied", value))
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
            Tab::Domain => self.show_domain(ui, &theme),
            Tab::Devices => self.show_devices(ui, &theme),
            Tab::Connect => self.show_connect(ui, &theme),
            Tab::Tunnel => self.show_tunnel(ui, &theme),
            Tab::Settings => self.show_settings(ui, &theme),
        });

        // M13-T006 (UI-FT-005): 服务端接收完成提示弹窗（会话写队列 → 本帧 drain）。
        if let Ok(mut q) = server_file_notices().lock() {
            self.file_notices.extend(q.drain(..));
        }
        let mut dismiss = Vec::new();
        for (i, notice) in self.file_notices.iter().enumerate() {
            let mut closed = false;
            egui::Window::new(t!("dialog.file_received.title"))
                .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-16.0, 16.0))
                .show(ctx, |ui| {
                    ui.add(
                        egui::Label::new(egui::RichText::new(notice).size(theme.small_size))
                            .selectable(true),
                    );
                    ui.add_space(8.0);
                    if action_button(
                        ui,
                        &theme,
                        ButtonKind::Secondary,
                        t!("dialog.close"),
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
                    if let Some(existing) = self
                        .windows
                        .iter()
                        .find(|w| w.addr == sig.addr && w.kind == WindowKind::Desktop)
                    {
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
                        reconnect_ctx: sig.reconnect_ctx,
                        reconnect_stop: None,
                        audio_state: AudioUiState::Muted,
                    });
                    tracing::info!("Connection window opened: id={}", wid);
                }
            }
            // M11-T005: 远程 Shell 会话窗口（每设备+每端口独立 PTY 会话）。
            // M8-T021 P1: 同 addr 去重 + 聚焦；terminal 用会话侧实例（断链修复）。
            if let Ok(mut signals) = add_shell_window_signal().lock() {
                for sig in signals.drain(..) {
                    if let Some(existing) = self
                        .windows
                        .iter()
                        .find(|w| w.addr == sig.addr && w.kind == WindowKind::Shell)
                    {
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
                        // R-03：Shell 会话无桌面断线重连（窗口持有 None）。
                        reconnect_ctx: None,
                        reconnect_stop: None,
                        audio_state: AudioUiState::Muted,
                    });
                    tracing::info!("Shell window opened: id={}", wid);
                }
            }
            // R-03 (R03-S3/S4)：重连续接信号——按 session_id 更新**既有**窗口的
            // 通道（不新建窗口）；窗口已关闭 → 信号 drop → close_tx drop → 会话退出。
            if let Ok(mut signals) = add_resume_signal().lock() {
                for sig in signals.drain(..) {
                    if let Some(win) = self
                        .windows
                        .iter_mut()
                        .find(|w| w.session_id == sig.session_id)
                    {
                        win.addr = sig.addr;
                        win.input_tx = Some(sig.input_tx);
                        win.bridge = Some(sig.bridge);
                        win.file_tx = Some(sig.file_tx);
                        win.control_tx = Some(sig.control_tx);
                        win.close_tx = Some(sig.close_tx);
                        // 会话已恢复 → 清除重连状态（覆盖层随 input_tx 复活消失）。
                        if let Ok(mut m) = reconnect_state_map().lock() {
                            m.remove(&sig.session_id);
                        }
                        tracing::info!(
                            "[reconnect] session {} resumed (channels swapped)",
                            sig.session_id
                        );
                    } else {
                        tracing::warn!(
                            "[reconnect] resume signal for missing window session {} — dropped",
                            sig.session_id
                        );
                    }
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
                    // R-04：同步音频状态（音频线程 → 键控 map → 状态栏徽标）。
                    win.sync_audio_state();
                    egui::TopBottomPanel::top(format!("conn_status_{}", wid)).show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            if win.kind == WindowKind::Shell {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(t!("session.statusbar.shell_hint"))
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
                                badge(
                                    ui,
                                    &theme,
                                    t!("session.statusbar.fps_placeholder"),
                                    BadgeKind::Neutral,
                                );
                            }
                            // M8-T018（CLI-MON-003）：状态栏显示当前屏名称与分辨率。
                            if win.kind == WindowKind::Desktop {
                                if let Some(d) = win.current_display() {
                                    badge(
                                        ui,
                                        &theme,
                                        &tf!(
                                            "session.statusbar.display",
                                            d.name,
                                            d.width,
                                            d.height,
                                            if d.is_primary {
                                                t!("session.statusbar.primary_suffix")
                                            } else {
                                                ""
                                            }
                                        ),
                                        BadgeKind::Info,
                                    );
                                }
                                // M8-T018（MON-NF-001）：切换被拒 → 错误提示（保持当前屏）。
                                if let Some(reason) = &win.display_nack {
                                    badge(
                                        ui,
                                        &theme,
                                        &tf!("session.statusbar.nack", reason),
                                        BadgeKind::Danger,
                                    );
                                }
                                // M8-T019 (UI-PRIV-002): 隐私徽标（黑屏 / 锁屏）。
                                match win.privacy_level {
                                    Some(PrivacyLevel::Black) => {
                                        badge(
                                            ui,
                                            &theme,
                                            t!("session.statusbar.privacy_black"),
                                            BadgeKind::Info,
                                        );
                                    }
                                    Some(PrivacyLevel::Lock) => {
                                        badge(
                                            ui,
                                            &theme,
                                            t!("session.statusbar.privacy_lock"),
                                            BadgeKind::Danger,
                                        );
                                    }
                                    None => {}
                                }
                                // R-04：音频状态徽标（静音 / 播放中 / 已禁用）。
                                match win.audio_state {
                                    AudioUiState::Playing => {
                                        badge(
                                            ui,
                                            &theme,
                                            t!("session.statusbar.audio_playing"),
                                            BadgeKind::Info,
                                        );
                                    }
                                    AudioUiState::Muted => {
                                        badge(
                                            ui,
                                            &theme,
                                            t!("session.statusbar.audio_muted"),
                                            BadgeKind::Neutral,
                                        );
                                    }
                                    AudioUiState::Disabled => {
                                        badge(
                                            ui,
                                            &theme,
                                            t!("session.statusbar.audio_disabled"),
                                            BadgeKind::Neutral,
                                        );
                                    }
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
                                                    .unwrap_or_else(|| t!("session.toolbar.display_placeholder"))
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
                                                        if d.is_primary {
                                                            t!("session.statusbar.primary_suffix")
                                                        } else {
                                                            ""
                                                        }
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
                                                t!("session.toolbar.display_refresh"),
                                            )
                                            .clicked()
                                            {
                                                win.send_display_control(
                                                    ControlMessage::DisplayListReq,
                                                );
                                            }
                                        }
                                        // M8-T020 UI-SKEY-001: 特殊键面板（Win/Alt+Tab/任务管理器/锁屏）。
                                        if toolbar_button(
                                            ui,
                                            &theme,
                                            "🔑",
                                            t!("session.toolbar.special_keys"),
                                        )
                                        .clicked()
                                        {
                                            win.show_special_key_panel = !win.show_special_key_panel;
                                        }
                                        // M8-T032：② 播放音频开关（进程级原子量，
                                        // 会话内动态生效，无需重连）。关 → 丢弃
                                        // 到达的音频包（动态静音）+ 徽标立即同步。
                                        if audio_enabled_global().load(Ordering::Relaxed) {
                                            let mut play = client_audio_play();
                                            if toolbar_button(
                                                ui,
                                                &theme,
                                                if play { "🔊" } else { "🔇" },
                                                t!("session.toolbar.audio_play"),
                                            )
                                            .clicked()
                                            {
                                                play = !play;
                                                set_client_audio_play(play);
                                                win.audio_state = if play {
                                                    AudioUiState::Playing
                                                } else {
                                                    AudioUiState::Muted
                                                };
                                                if let Ok(mut m) = audio_window_state().lock() {
                                                    m.insert(win.session_id, win.audio_state);
                                                }
                                            }
                                            // M8-T032：③ 麦克风开关（talkback）——
                                            // 本机麦克风 → 服务端播放（默认关）。
                                            let mut mic = client_mic_enabled();
                                            if toolbar_button(
                                                ui,
                                                &theme,
                                                if mic { "🎙️" } else { "🎤" },
                                                t!("session.toolbar.mic"),
                                            )
                                            .clicked()
                                            {
                                                mic = !mic;
                                                set_client_mic_enabled(mic);
                                            }
                                        }
                                        if toolbar_button(ui, &theme, "📁", t!("session.toolbar.file"))
                                            .clicked()
                                        {
                                            win.show_file_panel = !win.show_file_panel;
                                        }
                                        // M8-T019 (UI-PRIV-001/002): 隐私模式菜单——
                                        // 黑屏（Level 1）/ 锁屏（Level 2）/ 恢复屏幕。
                                        // 激活时按钮文案显示当前状态（高亮由状态栏徽标承担）。
                                        let privacy_label = match win.privacy_level {
                                            Some(PrivacyLevel::Black) => t!("session.privacy.menu_black"),
                                            Some(PrivacyLevel::Lock) => t!("session.privacy.menu_lock"),
                                            None => t!("session.privacy.menu_idle"),
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
                                                            t!("session.privacy.black_action"),
                                                        ),
                                                    )
                                                    .on_hover_text(
                                                        t!("session.privacy.black_hint"),
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
                                                        egui::Button::new(
                                                            t!("session.privacy.lock_action"),
                                                        ),
                                                    )
                                                    .on_hover_text(
                                                        t!("session.privacy.lock_hint"),
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
                                                        egui::Button::new(
                                                            t!("session.privacy.restore"),
                                                        ),
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
                                                                t!("session.privacy.locked_note"),
                                                            )
                                                            .color(theme.fg_weak),
                                                        )
                                                        .selectable(false),
                                                    );
                                                }
                                            });
                                    }
                                    if toolbar_button(ui, &theme, "▣", t!("session.toolbar.fullscreen"))
                                        .clicked()
                                    {
                                        win.fullscreen = !win.fullscreen;
                                        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(
                                            win.fullscreen,
                                        ));
                                    }
                                    if toolbar_button(ui, &theme, "✖", t!("session.toolbar.disconnect"))
                                        .clicked()
                                    {
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
                        egui::Window::new(t!("session.special_key.title"))
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
                                                special_combo_label(combo),
                                                state,
                                            );
                                            // UI-SKEY-003: tooltip 提示（Alt+Tab 另附被控端前台要求）。
                                            let hint = if combo == SpecialCombo::AltTab
                                                && alt_tab_unsupported
                                            {
                                                t!("session.special_key.macos_alt_tab")
                                            } else {
                                                special_combo_hint(combo)
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
                                        egui::RichText::new(t!("session.special_key.cac_hint"))
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
                            egui::Window::new(t!("session.privacy.toast_title"))
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
                                        t!("dialog.close"),
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

                    // M8-T038 (P1): 连接状态条——工具栏面板（conn_status_{wid}）之下、
                    // 显示画面（CentralPanel）之前；状态非空才渲染，随弹出页出现/消失
                    // （零残留）。状态为进程级全局单例，多窗口并存时各窗口显示最近一次
                    // 写入（主设计 §7-4 已知限制）。本面板由 P1 独占，P6 不得改动。
                    let status = connection_status().lock().unwrap().clone();
                    if !status.is_empty() {
                        egui::TopBottomPanel::top(format!("conn_state_{wid}")).show(ctx, |ui| {
                            ui.add_space(2.0);
                            ui.horizontal(|ui| {
                                let color = conn_status_color(&theme, &status);
                                status_dot(ui, color, &status);
                                if let Some(cur) = conn_step(&status) {
                                    let s = status.strip_prefix("[shell] ").unwrap_or(&status);
                                    let steps = if s.starts_with("Resolving") {
                                        &["Resolving", "Connecting", "Handshaking", "Connected"]
                                    } else {
                                        &["Discovering", "Connecting", "Handshaking", "Connected"]
                                    };
                                    ui.add_space(8.0);
                                    stepper(ui, &theme, steps, cur);
                                }
                            });
                            ui.add_space(2.0);
                        });
                    }

                    egui::CentralPanel::default()
                        // M15-T008: letterbox 黑底（视频画布底色令牌）
                        .frame(egui::Frame::none().fill(theme.video_bg))
                        .show(ctx, |ui| {
                        // M11-T002/T005: 远程 Shell 终端渲染（独立会话，互不影响）。
                        if win.kind == WindowKind::Shell {
                            let (focused, events) = ctx.input(|i| (i.focused, i.events.clone()));
                            let Some(term) = win.terminal.as_ref() else {
                                ui.label(t!("session.shell_not_initialized"));
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
                            // R-27：终端画布固定经典深色——明亮主题下视频底已浅色化
                            // （theme.video_bg），终端保持 M11-T002 经典深色 ANSI
                            // 调色板可读性（深色主题下与 video_bg=纯黑 视觉一致）。
                            ui.painter().rect_filled(ui.max_rect(), 0.0, egui::Color32::BLACK);
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
                        // 错误覆盖层 + 重连按钮。
                        // R-03 (R03-S4)：断线后自动重连（一次性触发；重连中/已失败
                        // 不重复），覆盖层显示"自动重连中（第 N 次/共 M 次）"，按钮
                        // 禁用态随状态机；不可重连路径给出明确原因（R03-S5）。
                        let disconnected = win
                            .input_tx
                            .as_ref()
                            .map(|tx| tx.is_closed())
                            .unwrap_or(false);
                        if disconnected {
                            // M8-T019: 断连后隐私徽标清空（服务端已本地恢复，SRV-PRIV-014）。
                            win.privacy_level = None;
                            // 自动重连：仅首次触发（Retrying/Failed 状态下不重复）。
                            let auto_start = reconnect_state_map()
                                .lock()
                                .unwrap()
                                .get(&win.session_id)
                                .is_none()
                                && win.reconnect_ctx.is_some();
                            if auto_start {
                                spawn_reconnect(win);
                            }
                            let reconnect_state = reconnect_state_map()
                                .lock()
                                .unwrap()
                                .get(&win.session_id)
                                .cloned();
                            ui.centered_and_justified(|ui| {
                                ui.vertical(|ui| {
                                    status_dot(ui, theme.danger, t!("session.reconnect.lost"));
                                    ui.add_space(8.0);
                                    match &reconnect_state {
                                        Some(ReconnectUiState::Retrying { attempt, max }) => {
                                            ui.label(tf!(
                                                "session.reconnect.retrying",
                                                (*attempt).max(1),
                                                max
                                            ));
                                            ui.add_space(8.0);
                                            // 重连中：按钮禁用（随状态机）。
                                            action_button(
                                                ui,
                                                &theme,
                                                ButtonKind::Primary,
                                                t!("session.reconnect.button"),
                                                ButtonState::Busy,
                                            );
                                        }
                                        Some(ReconnectUiState::Failed { reason }) => {
                                            // R03-S5：明确不可重连原因，不静默。
                                            ui.label(reason.clone());
                                            ui.add_space(8.0);
                                            if action_button(
                                                ui,
                                                &theme,
                                                ButtonKind::Primary,
                                                t!("session.reconnect.button"),
                                                ButtonState::Enabled,
                                            )
                                            .clicked()
                                            {
                                                spawn_reconnect(win);
                                            }
                                        }
                                        None => {
                                            if win.reconnect_ctx.is_none() {
                                                // R03-S5：无重连上下文的连接（ID 模式等）
                                                // → 显式原因，不静默失败。
                                                ui.label(t!("session.reconnect.unsupported"));
                                            } else {
                                                ui.label(t!("session.reconnect.lost"));
                                                ui.add_space(8.0);
                                                if action_button(
                                                    ui,
                                                    &theme,
                                                    ButtonKind::Primary,
                                                    t!("session.reconnect.button"),
                                                    ButtonState::Enabled,
                                                )
                                                .clicked()
                                                {
                                                    spawn_reconnect(win);
                                                }
                                            }
                                        }
                                    }
                                });
                            });
                            // 重连进度/结果刷新（~5fps；恢复后信号消费即消失）。
                            ctx.request_repaint_after(std::time::Duration::from_millis(200));
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
                                    t!("session.privacy.input_paused"),
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
                // R-03 (R03-S4)：窗口关闭 → 中止重连退避 + 清重连状态。
                if let Some(stop) = &win.reconnect_stop {
                    stop.store(true, Ordering::Relaxed);
                }
                if let Ok(mut m) = reconnect_state_map().lock() {
                    m.remove(&win.session_id);
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
        if let Some(win) = self
            .windows
            .iter()
            .find(|w| w.addr == addr && w.kind == kind)
        {
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
            // M9-DNS022 (UI-DNS-004): App 内存 godaddy 凭据字段仅作 godaddy
            // 兼容——激活服务商非 godaddy 时清空（Connect 页/状态栏判定走
            // `dns_configured`，不依赖这些字段）。
            if cfg.dns.provider == "godaddy" {
                self.api_key = cfg.godaddy.api_key.clone();
                self.api_secret = cfg.godaddy.api_secret.clone();
                self.api_url = cfg.godaddy.api_url.clone();
                self.domain = cfg.godaddy.domain.clone();
            } else {
                self.api_key.clear();
                self.api_secret.clear();
                self.api_url.clear();
                self.domain.clear();
            }
            self.dns_configured = dns_provider_configured(&cfg);
            // M9-DNS022: DNS 服务商选择迁至 Domain 页（domain_panel 内部
            // 自配置读取并回填表单），App 不再持有该字段。
            // M8-T031: 配置留空 / 旧占位 `default-device` → 自动派生
            // （系统盘硬盘 UUID 等）；显式值原样保留。
            self.device_id = kirin_desk_utils::device::effective_device_id(&cfg.device.id);
            self.nickname = cfg.device.nickname;
            self.challenge_code = cfg.device.challenge_code;
            self.allowed_domains = cfg.network.allowed_domains.join(", ");
            // M8-T027 (UI-IDWL-001/002): ID 白名单文本框 + 条目列表缓存加载。
            self.allowed_ids = cfg.network.allowed_ids.join(", ");
            self.id_whitelist_entries = cfg.network.id_whitelist.clone();
            self.ip_mode_allowed = cfg.network.ip_mode_allowed;
            self.temp_mode = cfg.network.temp_mode;
            self.listen_port = cfg.network.port.to_string();
            // M15-T008: 主题模式（启动时 install 已用同源值，此处保持一致防漂移）。
            self.theme_mode = ThemeMode::from_str(&cfg.ui.theme);
            // M8-T038: 语言（启动时已 set_lang_code；此处同源防漂移）。
            self.ui_language = cfg.ui.language.clone();
            i18n::set_lang_code(&cfg.ui.language);
            // M13-T005: 无人值守模式状态（Settings 页 + 启动时序共用）。
            self.unattended_enabled = cfg.unattended.enabled;
            self.unattended_autostart = cfg.unattended.auto_start_on_boot;
            self.unattended_auto_server = cfg.unattended.auto_start_server;
            // M8-T026: 内网穿透设置（Tunnel 独立页回填；proxies 转多行文本）。
            self.tunnel_enabled = cfg.tunnel.enabled;
            self.tunnel_mode = cfg.tunnel.mode.clone();
            self.tunnel_server_addr = cfg.tunnel.server_addr.clone();
            self.tunnel_token = cfg.tunnel.token.clone();
            self.tunnel_proxies =
                kirin_desk_utils::config::TunnelConfig::format_proxy_lines(&cfg.tunnel.proxies);
            // M8-T039: Tunnel 页表单字段回填（Server 模式参数 + 最后运行状态；
            // 运行态 auto_start 供 P5 首帧自动恢复，见 update() config_loaded 块）。
            self.tunnel_bind_addrs = cfg.tunnel.bind_addrs.clone();
            self.tunnel_bind_port = cfg.tunnel.bind_port.to_string();
            self.tunnel_port_range = cfg.tunnel.port_range.clone();
            self.tunnel_auto_start = cfg.tunnel.auto_start;
        }
        // M10-T003: 启动时加载已保存设备列表（文件不存在 → 空列表）。
        self.reload_devices();
        if let Ok(ip) = kirin_desk_core::network::ipv6::get_global_ipv6() {
            self.local_ipv6 = ip.to_string();
        } else {
            self.local_ipv6 = "N/A".to_string();
        }
        // M8-T033: 本机全局 IPv4（失败显示 N/A）。
        if let Ok(ip) = kirin_desk_core::network::ipv4::get_global_ipv4() {
            self.local_ipv4 = ip.to_string();
        } else {
            self.local_ipv4 = "N/A".to_string();
        }
        // Load or generate persistent device identity
        // M8-T031: device_id 已解析（空/占位 → 自动硬盘 UUID），不再回落 "default"。
        let device_id = &self.device_id;
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
        ui.heading(t!("dashboard.title"));
        ui.separator();
        // M8-T035 (需求 9): Dashboard 整体滚动区（对齐 Settings 页做法；
        // Live Log 内部滚动条保留，双滚动不冲突）。
        egui::ScrollArea::vertical().show(ui, |ui| {
            // M15-T008: ① 身份信息卡（值 Mono + 📋 复制按钮）
            // M8-T035 (需求 13): 移除 Nickname/API/Allowed 三行——Nickname 在
            // 服务端设置卡可编辑、白名单配置仍在 Settings → Whitelist；本卡仅保留
            // 设备身份五行（Device ID / IPv6 / IPv4 / Domain / Listen Port）。
            // M8-T028 (UI-BTY-024): 身份卡三行（Device ID / IPv6 / Domain）均带 📋；
            // stat_card 返回本帧复制的内容 → 状态栏浮出提示（UI-BTY-028）。
            // M8-T033: 增加 IPv4 行（与 IPv6 并列；无本机 IPv4 时显示 N/A）。
            // M8-T034: 各行 `small: true`——身份卡字号整体调小。
            // M8-T037: 公网检测红/绿点——逐 IP 判定，状态点随行显示在
            // IPv6/IPv4 值之后（IPv4/IPv6 可能其一通畅）：本地地址为公网段
            // （is_public_*，含 ULA/CGNAT 剔除）或外部出口探测命中 → 绿点；
            // 否则红点（无地址 N/A 同样红）。仅两行均非公网时惰性触发一次
            // 外部出口探测（api.ipify.org，4s 超时）；探测期间卡底提示
            // 「公网检测中…」，双行均无公网（探测未命中/失败）→ 卡底提示
            // 「无公网地址建议开启内网穿透或端口转发」。
            let local_v4 = self.local_ipv4.parse::<std::net::Ipv4Addr>().ok();
            let local_v6 = self.local_ipv6.parse::<std::net::Ipv6Addr>().ok();
            let v4_local_public = local_v4
                .as_ref()
                .map(|a| kirin_desk_core::network::ipv4::is_public_ipv4(a))
                .unwrap_or(false);
            let v6_local_public = local_v6
                .as_ref()
                .map(|a| kirin_desk_core::network::ipv6::is_public_ipv6(a))
                .unwrap_or(false);
            let mut probing = false;
            let mut probe_ext: Option<std::net::IpAddr> = None;
            if !v4_local_public && !v6_local_public {
                // 本地无公网 → 外部探测兜底（Idle → 触发一次后台探测）。
                ensure_public_probe();
                match *public_probe_state().lock().unwrap() {
                    PublicProbeState::Probing => probing = true,
                    PublicProbeState::Done(ext) => probe_ext = ext,
                    PublicProbeState::Idle => {}
                }
            }
            let v4_public = v4_local_public || probe_ext == local_v4.map(std::net::IpAddr::V4);
            let v6_public = v6_local_public || probe_ext == local_v6.map(std::net::IpAddr::V6);
            let dot_public = (theme.success, t!("dashboard.identity.dot_public"));
            let dot_private = (theme.danger, t!("dashboard.identity.dot_private"));
            let v4_dot = if v4_public { dot_public } else { dot_private };
            let v6_dot = if v6_public { dot_public } else { dot_private };
            let footer = if !v4_public && !v6_public {
                if probing {
                    Some((theme.fg_weak, t!("dashboard.identity.probing").to_string()))
                } else {
                    Some((
                        theme.danger,
                        t!("dashboard.identity.no_public").to_string(),
                    ))
                }
            } else {
                None
            };
            if let Some(copied) = stat_card_with_footer(
                ui,
                theme,
                t!("dashboard.identity.title"),
                &[
                    StatRow {
                        key: t!("dashboard.identity.device_id"),
                        value: self.device_id.clone(),
                        mono: true,
                        copy: true,
                        small: true,
                        dot: None,
                    },
                    StatRow {
                        key: t!("dashboard.identity.ipv6"),
                        value: self.local_ipv6.clone(),
                        mono: true,
                        copy: true,
                        small: true,
                        dot: Some(v6_dot),
                    },
                    StatRow {
                        key: t!("dashboard.identity.ipv4"),
                        value: self.local_ipv4.clone(),
                        mono: true,
                        copy: true,
                        small: true,
                        dot: Some(v4_dot),
                    },
                    StatRow {
                        key: t!("dashboard.identity.domain"),
                        value: self.domain.clone(),
                        mono: true,
                        copy: true,
                        small: true,
                        dot: None,
                    },
                    StatRow {
                        key: t!("dashboard.identity.listen_port"),
                        value: self.listen_port.clone(),
                        mono: true,
                        copy: false,
                        small: true,
                        dot: None,
                    },
                ],
                footer,
            ) {
                self.notify_copied(&copied);
            }
            ui.add_space(theme.spacing);

            // M15-T008: ② 服务器控制卡（M8-T034 重构——滑动开关替代 Start/Stop
            // 按钮，连接状态实时呈现在开关旁；含麦克风/模式/临时连接开关）
            // M8-T035 (需求 6/7): 「允许受控」+「允许麦克风」同一行；停止态不再
            // 显示「已停止 / ○ Stopped」文字（开关位置即状态）；「允许音频」会话级
            // 总开关迁自 Settings Server 组（需求 4）；高危警告同步迁入（需求 4）。
            card(ui, theme, t!("dashboard.server.title"), |ui| {
                // ── ① 允许受控 + 允许麦克风（同一行，需求 7）──
                // 允许受控：开关 = 服务端启停；状态文字 = 真实运行态。
                let runtime_status = {
                    let st = server_runtime_state().lock().unwrap();
                    if st.listening {
                        Some(tf!("dashboard.server.listening", st.port))
                    } else if let Some(e) = &st.error {
                        // 截断避免撑破卡片（完整原因在下方 server_status 行 + Live Log）。
                        let mut s = tf!("dashboard.server.start_failed", e);
                        const MAX: usize = 56;
                        if s.chars().count() > MAX {
                            let t: String = s.chars().take(MAX - 1).collect();
                            s = format!("{t}…");
                        }
                        Some(s)
                    } else {
                        // M8-T035 (需求 6): 停止态不显示「已停止」——开关位置已直观表达。
                        None
                    }
                };
                ui.horizontal(|ui| {
                    let was_running = self.server_running;
                    let resp = toggle_switch(
                        ui,
                        theme,
                        t!("dashboard.server.allow_controlled"),
                        self.server_running,
                        runtime_status.as_deref(),
                    )
                    .on_hover_text(t!("dashboard.server.allow_controlled_hint"));
                    if resp.clicked() {
                        if was_running {
                            // OFF → 停止：stop 信号 + 运行态立即复位（监听线程随后退出）。
                            server_stop_signal().store(true, Ordering::Relaxed);
                            self.server_running = false;
                            self.server_status = t!("dashboard.server.stopped").to_string();
                            {
                                let mut st = server_runtime_state().lock().unwrap();
                                st.starting = false;
                                st.listening = false;
                                st.error = None;
                            }
                            tracing::info!("Server stop signal sent");
                        } else {
                            self.start_server();
                        }
                    }
                    // ── ② 允许麦克风（M8-T032 ①：服务端声音 → 客户端，动态生效）──
                    let mic_on = server_audio_allowed();
                    let mic_resp = toggle_switch(
                        ui,
                        theme,
                        t!("dashboard.server.allow_mic"),
                        mic_on,
                        Some(t!("dashboard.server.audio_direction")),
                    )
                    .on_hover_text(t!("dashboard.server.allow_mic_hint"));
                    if mic_resp.clicked() {
                        set_server_audio_allowed(!mic_on);
                    }
                });
                // M8-T037: 「允许音频（会话级）」开关已移除——音频总开关不再
                // 提供 GUI 写入入口（保持默认开；CLI `--no-audio` 语义不变，
                // 三个子开关仍可独立控制：服务端「允许麦克风」在本卡、
                // 「播放音频」/「麦克风」在连接窗口工具栏）。
                ui.add_space(4.0);
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
                // ── ④ 工作模式：IP ⟷ Domain 单按钮互换（Settings/Connect 页同字段）──
                ui.horizontal(|ui| {
                    let mode_label = if self.ip_mode_allowed {
                        tf!("dashboard.server.mode_label", t!("dashboard.server.mode_ip"))
                    } else {
                        tf!("dashboard.server.mode_label", t!("dashboard.server.mode_domain"))
                    };
                    if action_button(
                        ui,
                        theme,
                        ButtonKind::Secondary,
                        &mode_label,
                        ButtonState::Enabled,
                    )
                    .clicked()
                    {
                        self.ip_mode_allowed = !self.ip_mode_allowed;
                        tracing::info!(
                            "Server mode switched to {}",
                            if self.ip_mode_allowed { "IP" } else { "Domain" }
                        );
                    }
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("dashboard.server.mode_hint"))
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                });
                ui.add_space(4.0);
                // ── ⑤ 临时连接开关（替代原开启/关闭按钮；窗口过期自动回位）──
                if self.unattended_enabled {
                    // UI-TMP-006: 无人值守下禁用（UA-ACCEPT-004）。
                    toggle_switch(
                        ui,
                        theme,
                        t!("dashboard.temp.title"),
                        false,
                        Some(t!("dashboard.temp.unavailable")),
                    );
                } else {
                    let temp_active = crate::policy::temp_mode_window_active();
                    let temp_status = if temp_active {
                        let remaining = TempModeManager::new()
                            .map(|m| m.remaining_secs())
                            .unwrap_or(0);
                        tf!(
                            "dashboard.temp.remaining",
                            remaining / 60,
                            remaining % 60
                        )
                    } else {
                        t!("dashboard.temp.hint").to_string()
                    };
                    let resp = toggle_switch(
                        ui,
                        theme,
                        t!("dashboard.temp.title"),
                        temp_active,
                        Some(&temp_status),
                    )
                    .on_hover_text(t!("dashboard.temp.toggle_hint"));
                    if resp.clicked() {
                        if temp_active {
                            // OFF（手动）→ 审计 Disabled；清标记避免归零误报 Expired。
                            let closed = TempModeManager::new()
                                .and_then(|m| m.disable())
                                .unwrap_or(false);
                            self.temp_code = None;
                            self.temp_window_was_active = false;
                            let mut logger = kirin_desk_utils::audit::AuditLogger::open_default().ok();
                            if closed {
                                audit_record(
                                    &mut logger,
                                    kirin_desk_utils::audit::AuditEvent::TempModeDisabled,
                                    "reason=manual_gui",
                                );
                                self.temp_status = t!("dashboard.temp.closed").to_string();
                            } else {
                                self.temp_status = t!("dashboard.temp.expired").to_string();
                            }
                        } else {
                            // ON → 生成 10 位临时挑战码 + 审计 TempModeEnabled。
                            let cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
                            let ttl = cfg.network.effective_temp_mode_ttl();
                            match TempModeManager::new() {
                                Ok(mgr) => match mgr.enable(ttl) {
                                    Ok(code) => {
                                        self.temp_code = Some(code);
                                        self.temp_status =
                                            tf!("dashboard.temp.enabled", ttl / 60);
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
                                    Err(e) => self.temp_status = tf!("dashboard.temp.enable_failed", e),
                                },
                                Err(e) => self.temp_status = tf!("dashboard.temp.enable_failed", e),
                            }
                        }
                    }
                    if temp_active {
                        // 开启态：码 + 复制 + 隐藏（S-22：仅展示一次）+ 说明。
                        ui.add_space(4.0);
                        match self.temp_code.clone() {
                            Some(code) => {
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
                                    if action_button(
                                        ui,
                                        theme,
                                        ButtonKind::Secondary,
                                        t!("dashboard.temp.hide_code"),
                                        ButtonState::Enabled,
                                    )
                                    .clicked()
                                    {
                                        self.temp_code = None;
                                        self.temp_status = t!("dashboard.temp.hidden").to_string();
                                    }
                                });
                            }
                            None => {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(t!("dashboard.temp.not_stored"))
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
                                egui::RichText::new(t!("dashboard.temp.window_note"))
                                    .size(theme.small_size)
                                    .color(theme.fg_weak),
                            )
                            .selectable(false),
                        );
                    }
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
                }
                // 状态行：运行态 StatusDot + 临时模式/无人值守/待审批徽标。
                // M8-T035 (需求 6): 仅运行时渲染——停止时无「○ Stopped」。
                if self.server_running {
                    ui.horizontal(|ui| {
                        status_dot(ui, theme.success, t!("dashboard.server.status_listening"));
                        if self.temp_mode {
                            badge(
                                ui,
                                theme,
                                t!("dashboard.temp.badge_on"),
                                BadgeKind::Warning,
                            );
                        }
                        // M8-T017 (UI-TMP-004): 临时连接窗口激活徽标（状态行）。
                        if crate::policy::temp_mode_window_active() {
                            badge(ui, theme, t!("dashboard.temp.window_badge"), BadgeKind::Warning);
                        }
                        // M13-T005 (UA-UI-002): 无人值守模式徽标。
                        if self.unattended_enabled {
                            badge(ui, theme, t!("dashboard.unattended_badge"), BadgeKind::Info);
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
                                &tf!("dashboard.pending_fmt", waiting_count),
                                BadgeKind::Danger,
                            );
                        }
                    });
                }
                // S-01c (F-1/F-2): 高危配置警告——旁路（IP/Temp mode）开启但挑战码
                // 为空 → 旁路零凭据连接全部被拒（fail-closed），提示用户在下方
                // 「服务端设置」配置挑战码（凭据是旁路放行的前提）。迁自 Settings。
                if (self.ip_mode_allowed || self.temp_mode)
                    && self.challenge_code.trim().is_empty()
                {
                    ui.add_space(4.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("dashboard.risk.high_risk"))
                                .size(theme.small_size)
                                .color(theme.danger),
                        )
                        .selectable(false),
                    );
                }
            });
            ui.add_space(theme.spacing);

            // M8-T034: ③ 服务端设置（小字号；端口/昵称/挑战码迁自 Settings，
            // 下次启动服务端生效；页面内小保存按钮即时落盘）
            // M8-T035 (需求 1/2): 端口输入迁入（原 Settings Server 组 Listen Port），
            // 三项横向一排——端口定窄宽、昵称/挑战码弹性宽度。
            card(ui, theme, t!("dashboard.server_settings.title"), |ui| {
                // 整体字号压到 small_size（仅本卡内生效，渲染后还原）。
                let saved_style: egui::Style = ui.style().as_ref().clone();
                {
                    let s = ui.style_mut();
                    s.text_styles.insert(
                        egui::TextStyle::Body,
                        egui::FontId::new(theme.small_size, egui::FontFamily::Proportional),
                    );
                }
                // M8-T035: 端口校验（1–65535）——非法红边 + 提示 + 禁用保存。
                let port_validity = match self.listen_port.parse::<u16>() {
                    Ok(p) if p >= 1 => Validity::None,
                    _ => Validity::Invalid(t!("dashboard.server_settings.port_invalid")),
                };
                ui.horizontal(|ui| {
                    let row_w = ui.available_width();
                    let port_w = 130.0;
                    let field_w = ((row_w - port_w - 24.0) / 2.0).max(160.0);
                    ui.vertical(|ui| {
                        ui.set_width(port_w);
                        labeled_input(
                            ui,
                            theme,
                            t!("dashboard.server_settings.port"),
                            &mut self.listen_port,
                            "3389",
                            port_validity,
                            None,
                            true,
                        );
                    });
                    ui.vertical(|ui| {
                        ui.set_width(field_w);
                        labeled_input(
                            ui,
                            theme,
                            t!("dashboard.server_settings.nickname"),
                            &mut self.nickname,
                            t!("dashboard.server_settings.required"),
                            Validity::None,
                            None,
                            false,
                        );
                    });
                    ui.vertical(|ui| {
                        ui.set_width(field_w);
                        // M15-T008: 挑战码密文输入（圆点遮蔽 + 👁 切换）。
                        labeled_input(
                            ui,
                            theme,
                            t!("dashboard.server_settings.challenge"),
                            &mut self.challenge_code,
                            t!("dashboard.server_settings.optional"),
                            Validity::None,
                            Some(&mut self.show_secret_challenge),
                            false,
                        );
                    });
                });
                *ui.style_mut() = saved_style;
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("dashboard.server_settings.desc"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let port_ok = self
                        .listen_port
                        .parse::<u16>()
                        .map(|p| p >= 1)
                        .unwrap_or(false);
                    if ui
                        .add_enabled(port_ok, egui::Button::new(t!("dashboard.server_settings.save")).small())
                        .clicked()
                    {
                        self.save_dashboard_settings();
                    }
                    if !self.dashboard_status.is_empty() {
                        // M8-T038: 成功判定与同键文案比较（语言无关）。
                        let ok = self.dashboard_status == t!("dashboard.status.saved");
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&self.dashboard_status)
                                    .size(theme.small_size)
                                    .color(if ok { theme.success } else { theme.danger }),
                            )
                            .selectable(true),
                        );
                    }
                });
            });
            ui.add_space(theme.spacing);

            // M13-T006 (UI-FT-005): 服务端文件传输面板（连接建立后可用；
            // 拖拽文件到主窗口 = 推送（下载方向，服务端主动）。无 GUI 时静默接收）。
            card(ui, theme, t!("dashboard.file_transfer.title"), |ui| {
                let connected = server_file_tx().lock().unwrap().is_some();
                if !connected {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("dashboard.file_transfer.empty"))
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
                    title: t!("dashboard.log.title"),
                    empty: t!("dashboard.log.empty"),
                    max_height: 280.0,
                    clearable: true,
                    clear: Some(clear_gui_log),
                },
            );
        });
    }

    /// M9-DNS000 (UI-DNS-001~009): 域名维护客户端页面（Domain 标签页）。
    /// 全部逻辑在 `domain_panel` 模块：服务商选择/凭据表单（UI-DNS-001/002，
    /// 迁自 Settings → DNS）/ 测试连接 / 域名列表+添加 / 记录查询与增删改
    /// （SRV 动态字段），后台线程执行 API 调用。
    fn show_domain(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        let saved = domain_panel::show_domain_page(ui, theme, &mut self.domain_panel, &mut self.ddns_ui);
        if saved {
            // Domain 页保存凭据 → 同步 App 内存值（Connect 页 DNS 发现与
            // 状态栏徽标即时生效，无需重启）。godaddy 兼容字段仅激活服务商为
            // godaddy 时填充，否则清空（UI-DNS-004 泛化）。
            if let Ok(cfg) = kirin_desk_utils::config::Config::load() {
                if cfg.dns.provider == "godaddy" {
                    self.api_key = cfg.godaddy.api_key.clone();
                    self.api_secret = cfg.godaddy.api_secret.clone();
                    self.api_url = cfg.godaddy.api_url.clone();
                    self.domain = cfg.godaddy.domain.clone();
                } else {
                    self.api_key.clear();
                    self.api_secret.clear();
                    self.api_url.clear();
                    self.domain.clear();
                }
                self.dns_configured = dns_provider_configured(&cfg);
            }
        }
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

    /// M8-T027 (UI-IDWL-002): 逐条删除 ID 白名单条目（同时清理 `allowed_ids`
    /// 与 `id_whitelist` 两维），刷新列表缓存并写审计 `WhitelistIdRemoved`。
    fn remove_id_whitelist_entry(&mut self, device_id: &str) {
        match kirin_desk_utils::config::Config::load() {
            Ok(mut cfg) => match cfg.id_whitelist_remove(device_id) {
                Ok(true) => {
                    self.id_whitelist_entries
                        .retain(|e| e.device_id != device_id);
                    // 永久条目同时从文本框移除（逗号/换行分隔）。
                    self.allowed_ids = self
                        .allowed_ids
                        .split(|c| c == ',' || c == '\n' || c == '\r')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty() && s != device_id)
                        .collect::<Vec<_>>()
                        .join(", ");
                    if let Ok(mut a) = kirin_desk_utils::audit::AuditLogger::open_default() {
                        let _ = a.record(
                            kirin_desk_utils::audit::AuditEvent::WhitelistIdRemoved,
                            &format!("device={}", device_id),
                        );
                    }
                    self.settings_status = format!("Removed ID whitelist entry: {}", device_id);
                }
                Ok(false) => {
                    self.settings_status = format!("ID not found in whitelist: {}", device_id)
                }
                Err(e) => self.settings_status = format!("Remove failed: {}", e),
            },
            Err(_) => self.settings_status = "Config load failed".to_string(),
        }
    }

    fn start_server(&mut self) {
        use tracing::{error, info};
        let port: u16 = self.listen_port.parse().unwrap_or(3389);
        // M8-T035 (需求 5): 白名单快照不再在启动时冻结——握手层逐连接
        // 读取 `whitelist_active_patterns()`（含 CLI 条目，与 headless 一致）。
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
        // M8-T034: 运行态置「启动中」——bind 结果由监听线程回写
        // （成功 → listening/port；失败 → error）。
        {
            let mut st = server_runtime_state().lock().unwrap();
            st.starting = true;
            st.listening = false;
            st.port = 0;
            st.error = None;
        }
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
        // S-02 (F-5): 每连接并发处理——known_hosts 与限速器经 `Arc<Mutex>`
        // 跨连接共享（限速语义不因并发而丢失）；审计日志改由每连接独立打开
        // （append 模式多句柄并发安全，同隐私审计路径）。
        let known = Arc::new(Mutex::new(
            match kirin_desk_utils::known_hosts::KnownClientsStore::load() {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!("known_clients load error (in-memory fallback): {}", e);
                    kirin_desk_utils::known_hosts::KnownClientsStore::empty()
                }
            },
        ));
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
        let rate_limiter = Arc::new(Mutex::new(
            kirin_desk_core::network::rate_limit::RateLimiter::new(),
        ));
        // S-02 (F-5): 并发连接处理上限（含审批等待）——accept 循环 spawn 每连接，
        // 超出上限的连接在任务内排队（信号量），服务端持续接受新连接。
        let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(
            SERVER_MAX_CONCURRENT_CONNECTIONS,
        ));
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
                        // M8-T034: 运行态回写——GUI 每帧读取（开关状态/端口真实化）。
                        {
                            let mut st = server_runtime_state().lock().unwrap();
                            st.starting = false;
                            st.listening = true;
                            st.port = server.port();
                            st.error = None;
                        }
                        loop {
                            if stop.load(Ordering::Relaxed) {
                                info!("Server stopping by user request");
                                break;
                            }
                            match server.accept().await {
                                Ok((stream, addr)) => {
                                    // S-02 (F-5): 每连接 spawn 并发处理——单连接
                                    // "只连不发" / 60s 审批等待不再冻结 accept 循环；
                                    // 64 并发上限，超出者在任务内排队（信号量）。
                                    let sem = conn_semaphore.clone();
                                    let cfg = cfg.clone();
                                    let server_nickname = server_nickname.clone();
                                    let server_challenge = server_challenge.clone();
                                    let expected_nick = expected_nick.clone();
                                    let known = known.clone();
                                    let rate_limiter = rate_limiter.clone();
                                    tokio::spawn(async move {
                                        let Ok(_permit) = sem.acquire_owned().await else {
                                            return;
                                        };
                                        Self::handle_incoming_connection(
                                            stream,
                                            addr,
                                            cfg,
                                            skip_whitelist,
                                            unattended,
                                            server_nickname,
                                            server_challenge,
                                            expected_nick,
                                            known,
                                            rate_limiter,
                                        )
                                        .await;
                                    });
                                }
                                Err(e) => {
                                    error!("Accept error: {}", e);
                                }
                            }
                        }
                        // M8-T034: 监听线程退出（用户停止）→ 运行态回写。
                        {
                            let mut st = server_runtime_state().lock().unwrap();
                            st.listening = false;
                        }
                    }
                    Err(e) => {
                        error!("Server bind error on port {}: {}", port, e);
                        // M8-T034: bind 失败 → 回写运行态（GUI 开关回 OFF +
                        // 展示失败原因，修复旧实现「只打日志、开关假死」）。
                        {
                            let mut st = server_runtime_state().lock().unwrap();
                            st.starting = false;
                            st.listening = false;
                            st.port = 0;
                            st.error = Some(format!("bind port {} failed: {}", port, e));
                        }
                    }
                }
            });
        });
    }

    /// M8-T034: Dashboard「服务端设置」保存——ip_mode + 端口 + 昵称 + 挑战码
    /// 即时落盘（Settings 统一 Save 仍保留完整落盘；本按钮提供 Dashboard 页面
    /// 内保存入口）。已运行会话不受影响（下次启动服务端生效）。
    fn save_dashboard_settings(&mut self) {
        let mut cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
        cfg.network.ip_mode_allowed = self.ip_mode_allowed;
        cfg.device.nickname = self.nickname.clone();
        cfg.device.challenge_code = self.challenge_code.clone();
        // M8-T035 (需求 1): 端口迁入服务端设置——随本按钮一并落盘（非法值
        // 已被 UI 校验禁用保存，此处仍防御性跳过）。
        if let Ok(p) = self.listen_port.parse::<u16>() {
            cfg.network.port = p;
        }
        match cfg.save() {
            Ok(()) => {
                self.dashboard_status = t!("dashboard.status.saved").to_string();
            }
            Err(e) => self.dashboard_status = tf!("dashboard.status.save_failed", e),
        }
    }

    /// S-02 (F-5): 处理一条入站连接（accept 循环每连接 `tokio::spawn` 并发调用）。
    ///
    /// 流程与原内联实现完全一致（行为不变）：审计 → 速率限制 → 两阶段握手
    /// （known_hosts/DNS pin + 白名单 + 审批 + 二态挑战码）→ 会话分发
    /// （shell PTY / 远程桌面）。`rate_limiter`/`known` 为跨连接共享状态
    /// （`Arc<Mutex>`），仅在需要处短暂持锁、不跨 await；审计日志按连接独立
    /// 打开（append 模式多句柄并发安全，同隐私审计路径）。
    ///
    /// 本函数即 S-01c 追加每连接校验的落点（合并顺序 S-02 → S-01c）。
    /// M8-T035 (需求 5): 域名白名单判定改用 `whitelist_active_patterns()`——
    /// 含旧 `allowed_domains` + CLI `whitelist add` 写入的 `network.whitelist`
    /// 带过期/通配条目（去重），与 headless/CLI 语义完全一致（原 `allowed`
    /// 快照仅含 GUI 文本域条目，CLI 条目在 GUI 模式下不生效）。
    #[allow(clippy::too_many_arguments)]
    async fn handle_incoming_connection(
        stream: tokio::net::TcpStream,
        addr: std::net::SocketAddrV6,
        cfg: kirin_desk_utils::config::Config,
        skip_whitelist: bool,
        unattended: bool,
        server_nickname: String,
        server_challenge: String,
        expected_nick: Option<String>,
        known: Arc<Mutex<kirin_desk_utils::known_hosts::KnownClientsStore>>,
        rate_limiter: Arc<Mutex<RateLimiter>>,
    ) {
        use tracing::{error, info, warn};
        info!("Incoming connection from {}", addr);
        // M15 (SRV-SEC-RL/AUDIT/KH/WL): 速率限制 → 审计 →
        // 两阶段握手（known_hosts/DNS pin + 白名单 + 审批）。
        let ip = addr.ip().to_canonical();
        // S-02: 审计日志按连接独立打开（append 模式多句柄并发安全）。
        let mut audit = match kirin_desk_utils::audit::AuditLogger::open_default() {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!("audit log open error (audit disabled): {}", e);
                None
            }
        };
        audit_record(
            &mut audit,
            kirin_desk_utils::audit::AuditEvent::ConnectionRequest,
            &format!("ip={} port={}", ip, addr.port()),
        );
        if !matches!(
            rate_limiter.lock().unwrap().check_connect(&ip),
            RateLimitDecision::Allowed
        ) {
            audit_record(
                &mut audit,
                kirin_desk_utils::audit::AuditEvent::RateLimited,
                &format!("ip={}", ip),
            );
            warn!("Rate limited: {} — rejected", ip);
            return;
        }
        // Use global identity as server identity
        if let Some(server_id) = global_identity().get() {
            let server_name = if server_nickname.is_empty() {
                "gui-server".to_string()
            } else {
                server_nickname.clone()
            };
            let expected_challenge = if server_challenge.is_empty() {
                None
            } else {
                Some(&*server_challenge)
            };
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
                    rate_limiter.lock().unwrap().record_handshake_failure(&ip);
                    return;
                }
            };
            // 2) 客户端公钥解析（known_hosts → DNS TXT，SRV-SEC-KH-001）。
            // S-02: known 快照（resolve 为异步，避免跨 await 持锁）。
            let known_snapshot = known.lock().unwrap().clone();
            let (expected_key, _resolution) =
                crate::policy::resolve_expected_client_key(&known_snapshot, &cfg, &init.client_id)
                    .await;
            // 3) 白名单检查；未知公钥且非白名单 → 审批弹窗（temp/ip 模式跳过）。
            // M8-T017 (SRV-TMP-006): 临时连接窗口**逐连接**判定
            // （窗口中途开启/过期即时生效），与配置旁路取或；
            // 无人值守下窗口维度一并关闭（UA-ACCEPT-004）。
            let temp_window: Option<TempModeManager> = if unattended {
                None
            } else {
                crate::policy::temp_mode_window_manager()
            };
            // S-01c (F-2): 静态旁路（temp_mode/ip_mode
            // 配置开启 → skip_whitelist）开启但零凭据
            // （无固定挑战码 + 无激活临时窗口）→ 该连接
            // fail-closed 拒绝 + 审计。杜绝「配置即失守」
            // 后门：旁路只允许跳过白名单/审批，不允许
            // 跳过凭据本身。
            if skip_whitelist && expected_challenge.is_none() && temp_window.is_none() {
                audit_record(
                    &mut audit,
                    kirin_desk_utils::audit::AuditEvent::AuthFailure,
                    &format!(
                        "ip={} reason=bypass_without_credentials \
                                                     (temp_mode/ip_mode bypass enabled but no \
                                                     challenge code and no temp window)",
                        ip
                    ),
                );
                warn!(
                    "Rejected {}: whitelist bypass enabled without \
                                                 any credential (no challenge code, no temp \
                                                 window) — set a challenge code in Settings \
                                                 or enable a temp window (S-01c/F-2)",
                    addr
                );
                return;
            }
            let skip = skip_whitelist || temp_window.is_some();
            // M8-T027 (SRV-IDWL-021): 双白名单 OR——
            // 域名命中 **或** ID 命中即视为白名单命中（域名
            // 行为不变）；ID 列表**逐连接**从配置快照读取，
            // Settings 保存后即时生效（UI-IDWL-001）。
            // M8-T035 (需求 5): 域名维度改用 `whitelist_active_patterns`——
            // 旧 `allowed_domains` + CLI `whitelist add` 写入的
            // `network.whitelist`（带过期/通配条目，去重）共同生效，
            // 与 headless/CLI 语义一致：白名单命中 → 免人工审批，
            // 直接进入凭据校验（known_clients pin / 挑战码 / 临时窗口）。
            let now = chrono::Utc::now();
            let active_patterns = cfg.whitelist_active_patterns(now);
            let allowed_ids = kirin_desk_utils::config::Config::load()
                .map(|c| c.id_whitelist_active_ids(now))
                .unwrap_or_default();
            let is_whitelisted = active_patterns
                .iter()
                .any(|a| domain_matches_whitelist(&init.client_domain, a))
                || allowed_ids
                    .iter()
                    .any(|id| id_matches_whitelist(&init.client_id, id));
            // S-21 (F-26)：本连接是否经人工审批（通过后才把公钥写入
            // known_clients——仅审批放行的连接落 pin，白名单/旁路路径不落）。
            let mut was_approved = false;
            if !skip && !is_whitelisted && expected_key.is_none() {
                // M13-T005 (UA-ACCEPT-002): 无人值守下
                // 未知设备自动拒绝——无人工审批弹窗，
                // 立即审计 + 记握手失败后断开。
                if unattended {
                    audit_record(
                        &mut audit,
                        kirin_desk_utils::audit::AuditEvent::AuthFailure,
                        &format!(
                            "ip={} client={} reason=unattended_unknown",
                            ip, init.client_id
                        ),
                    );
                    rate_limiter.lock().unwrap().record_handshake_failure(&ip);
                    warn!(
                                                    "Unattended: unknown client {} ({}) rejected — no approval in unattended mode",
                                                    init.client_id, ip
                                                );
                    return;
                }
                let id = pending_next_id();
                let (dec_tx, dec_rx) = tokio::sync::oneshot::channel::<bool>();
                pending_decisions().lock().unwrap().insert(id, dec_tx);
                // S-21 (F-26)：审批**前**解析客户端公钥——伪造/损坏公钥直接
                // 拒绝（不弹窗，杜绝"审批先于签名校验"被刷弹窗骚扰/投毒）。
                let client_pubkey_b64 = init.client_ed25519_pub_base64.clone();
                if kirin_desk_core::crypto::ed25519::IdentityManager::parse_public_key(
                    &client_pubkey_b64,
                )
                .is_err()
                {
                    audit_record(
                        &mut audit,
                        kirin_desk_utils::audit::AuditEvent::AuthFailure,
                        &format!(
                            "ip={} client={} reason=unparsable_client_pubkey",
                            ip, init.client_id
                        ),
                    );
                    rate_limiter.lock().unwrap().record_handshake_failure(&ip);
                    warn!(
                        "Rejected {}: unparsable client public key '{}' — refused before approval (S-21/F-26)",
                        addr, init.client_id
                    );
                    return;
                }
                let pc = PendingConnection {
                    id,
                    client_id: init.client_id.clone(),
                    client_domain: init.client_domain.clone(),
                    device_type: init.client_device_type.clone(),
                    client_pubkey_base64: client_pubkey_b64,
                    status: PendingStatus::Waiting,
                };
                if let Some(tx) = pending_conn_tx().get() {
                    let _ = tx.send(pc);
                }
                // 等待用户决策（60s 超时）。
                match tokio::time::timeout(std::time::Duration::from_secs(60), dec_rx).await {
                    Ok(Ok(true)) => {} // 用户接受 → 继续握手（签名校验通过后落 known_clients）
                    _ => {
                        audit_record(
                            &mut audit,
                            kirin_desk_utils::audit::AuditEvent::AuthFailure,
                            &format!(
                                "ip={} client={} approval declined/timeout",
                                ip, init.client_id
                            ),
                        );
                        rate_limiter.lock().unwrap().record_handshake_failure(&ip);
                        return;
                    }
                }
                // S-21 (F-26)：审批通过 → 标记，待 Ed25519 签名校验通过后把
                // 客户端公钥写入 known_clients（下次同 id 凭 pin 自动放行）。
                was_approved = true;
            }
            // 4) pin/nickname/challenge/签名校验 + 应答。
            // M8-T017 (SRV-TMP-HK-001/003): 挑战码二态——固定
            // 挑战码 **或** 窗口内临时挑战码任一正确即通过。
            // S-01a (F-1)：生产路径零凭据 → 拒绝
            // （`allow_no_credentials = false`，R-02）。
            if let Err(e) = verify_server_init_with_temp(
                &init,
                expected_key.as_deref().unwrap_or(""),
                expected_nick.as_deref(),
                expected_challenge,
                temp_window.as_ref(),
                false,
            ) {
                audit_record(
                    &mut audit,
                    kirin_desk_utils::audit::AuditEvent::HandshakeFailure,
                    &format!("ip={} error={}", ip, e),
                );
                rate_limiter.lock().unwrap().record_handshake_failure(&ip);
                return;
            }
            // S-21 (F-26)：审批通过 + Ed25519 签名校验通过（公钥真实性已
            // 验证）→ 客户端公钥写入 known_clients——弹窗承诺"批准后此公钥
            // 写入 known_clients"在此兑现；下次同 id 连接凭 pin 自动放行。
            if was_approved {
                if let Ok(mut k) = known.lock() {
                    k.upsert(&init.client_id, &init.client_ed25519_pub_base64);
                    if let Err(e) = k.save() {
                        warn!(
                            "known_clients save failed after approval for '{}': {}",
                            init.client_id, e
                        );
                    }
                    info!(
                        "Approved client '{}' pinned in known_clients (S-21/F-26)",
                        init.client_id
                    );
                }
            }
            // R-32（M13-T002 阶段 B）：编码能力协商——服务端按自身编码优先级
            // （AV1 → H.265 → H.264，media 探测缓存）从客户端可解码列表挑选；
            // 交集为空（旧客户端未广告）→ 空串 → 客户端按 H.264 兜底。
            let server_caps: Vec<String> =
                kirin_desk_media::encoder::detect_supported_codecs_cached()
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect();
            let selected_codec =
                negotiate_codec_by_server_priority(&server_caps, &init.supported_codecs);
            let g =
                match server_handshake_respond_generic(stream, server_id, &server_name, &init, &selected_codec)
                    .await
                {
                    Ok(g) => g,
                    Err(e) => {
                        audit_record(
                            &mut audit,
                            kirin_desk_utils::audit::AuditEvent::HandshakeFailure,
                            &format!("ip={} error={}", ip, e),
                        );
                        rate_limiter.lock().unwrap().record_handshake_failure(&ip);
                        return;
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
            // R-32（M13-T002 阶段 B）：协商编码标准在 `ch.into_split()` 前取出
            // （拆分后字段不可用；Copy 枚举，编码任务闭包自由捕获）。
            let negotiated_codec =
                kirin_desk_media::encoder::Codec::from_str(&ch.selected_codec)
                    .unwrap_or(kirin_desk_media::encoder::Codec::H264);
            audit_record(
                &mut audit,
                kirin_desk_utils::audit::AuditEvent::HandshakeSuccess,
                &format!("ip={} client={} <{}>", ip, ch.peer_id, ch.peer_domain),
            );
            rate_limiter.lock().unwrap().reset(&ip);
            crate::policy::record_successful_handshake(&mut known.lock().unwrap(), &ch.peer_id);
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
                let result = run_shell_bridge(ch, DEFAULT_PTY_COLS, DEFAULT_PTY_ROWS, None).await;
                audit_record(
                    &mut audit,
                    kirin_desk_utils::audit::AuditEvent::Disconnect,
                    &format!("ip={} client={} shell", ip, peer_id),
                );
                match result {
                    Ok(()) => info!("Shell session closed: {}", addr),
                    Err(e) => warn!("Shell session ended with error: {}", e),
                }
                return;
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
                use kirin_desk_media::proto::{EncodeConfig, RawFrame, WindowConfig};
                use kirin_desk_media::window_pipeline::WindowPipeline;
                use kirin_desk_media::VideoEncoderPipeline;
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
                // M8-T030（R-06，GPU-FR-006）：GPU 内核复用选定适配器上的
                // D3D11 设备（与 FFmpeg HW 编解码同 GPU）；无真实 GPU /
                // 未链接 libkirin_gpu → init 失败 → kernel=None（CPU 路径，
                // tile-hash 由 classify_cpu 真实兜底）。
                // （R-03 编译解锁修复：未链接时与 media 同 cfg 门控回退 None。）
                let kernel: Option<
                    Box<dyn kirin_desk_media::encoder::video::tile_diff::GpuKernel>,
                > = {
                    #[cfg(kirin_gpu_linked)]
                    {
                        use kirin_desk_media::encoder::gpu_ffi::kernel::KgpuKernel;
                        KgpuKernel::init(kirin_desk_media::gpu::d3d11_device_handle())
                            .ok()
                            .map(|k| {
                                Box::new(k)
                                    as Box<
                                        dyn kirin_desk_media::encoder::video::tile_diff::GpuKernel,
                                    >
                            })
                    }
                    #[cfg(not(kirin_gpu_linked))]
                    {
                        None
                    }
                };
                let encoder = match VideoEncoderPipeline::new(
                    // R-32（M13-T002 阶段 B）：编码标准取握手协商结果
                    // （`negotiated_codec`；空/未知 → H.264 兜底）。AV1 会话 →
                    // SVT-AV1 软编（factory 内建「AV1 不可用 → 自动回退 H.264」
                    // 兜底——协商存在但运行时缺编码器也不会报错）。
                    negotiated_codec,
                    kernel,
                ) {
                    Ok(e) => e,
                    Err(e) => {
                        error!("Failed to create video encoder pipeline: {}", e);
                        return;
                    }
                };
                info!(
                    "Capture: video encoder '{}' created (hw={})",
                    encoder.name(),
                    encoder.is_hardware()
                );

                // 3. Create window pipeline
                let mut pipeline = WindowPipeline::new(WindowConfig::default(), encoder);
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

                // R-04 + M8-T032：音频捕获 + 编码线程（总开关 × ① 服务端允许
                // 麦克风；无环回设备/libopus → info 降级，视频/键鼠不断）。
                // 捕获+编码为阻塞调用 → blocking 线程池；批次经 tokio 通道交
                // 发送循环（与视频写半互斥，tag=Audio）。
                if audio_enabled_global().load(Ordering::Relaxed) && server_audio_allowed() {
                    let sender_audio = sender_shared.clone();
                    let stop_audio = stop_capture.clone();
                    tokio::spawn(async move {
                        let (audio_pkt_tx, mut audio_pkt_rx) =
                            tokio::sync::mpsc::channel::<Vec<EncodedPacket>>(32);
                        let audio_tx_task = audio_pkt_tx.clone();
                        let stop_pipe = stop_audio.clone();
                        tokio::task::spawn_blocking(move || {
                            let mut pipeline = match kirin_desk_media::AudioPipeline::new() {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::info!("Audio disabled (pipeline init failed): {e}");
                                    return;
                                }
                            };
                            if let Err(e) = pipeline.start() {
                                tracing::info!("Audio disabled (capture start failed): {e}");
                                return;
                            }
                            tracing::info!(
                                "Audio capture started ({}Hz/{}ch)",
                                pipeline.sample_rate(),
                                pipeline.channels()
                            );
                            loop {
                                if stop_pipe.load(Ordering::Relaxed) {
                                    break;
                                }
                                // M8-T032：① 动态门控——关 → 停发（消费丢弃
                                // 防通道堆积，捕获线程保活）；再开 → 恢复
                                // （无需重连，PTS 由编码器单调计数接续）。
                                if !server_audio_allowed() {
                                    let _ = pipeline.next_packets();
                                    std::thread::sleep(std::time::Duration::from_millis(50));
                                    continue;
                                }
                                match pipeline.next_packets() {
                                    Ok(pkts) if !pkts.is_empty() => {
                                        // 主循环忙（通道满）→ 丢批次（音频可丢，播放端静音补位）。
                                        if audio_tx_task.try_send(pkts).is_err() {
                                            tracing::debug!("Audio batch dropped (send loop busy)");
                                        }
                                    }
                                    Ok(_) => {
                                        std::thread::sleep(std::time::Duration::from_millis(5))
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Audio pipeline error: {e} — stopping audio"
                                        );
                                        break;
                                    }
                                }
                            }
                            tracing::info!("Audio capture stopped");
                        });
                        // 发送循环：会话结束（stop / 断链）→ 通道关闭 → 退出。
                        while let Some(pkts) = audio_pkt_rx.recv().await {
                            // P2（修复计划 2026-08-03）：大小分流 + 失败不中断
                            // （音频可丢，播放端静音补位）。
                            send_audio_packets(&sender_audio, &pkts).await;
                        }
                    });
                }

                // M13-T006: 服务端文件命令/帧事件通道。
                let (server_file_cmd_tx, mut server_file_cmd_rx) =
                    tokio::sync::mpsc::unbounded_channel::<FileCommand>();
                let (server_file_frame_tx, mut server_file_frame_rx) =
                    tokio::sync::mpsc::unbounded_channel::<FileTransferFrame>();
                *server_file_tx().lock().unwrap() = Some(server_file_cmd_tx);

                // M13-T006: 服务端文件会话任务（接收落盘 + 推送下载）。
                {
                    let sender_ft = sender_shared.clone();
                    let my_id = global_identity()
                        .get()
                        .map(|i| i.public_key_base64())
                        .unwrap_or_default();
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
                let privacy_controller = Arc::new(Mutex::new(PrivacyController::new(false)));
                *server_privacy_controller().lock().unwrap() = Some(privacy_controller.clone());
                // M8-T019 (PRIV-SEC-001): 隐私审计独立句柄
                // （append 模式多句柄并发安全；与主审计流互不干扰）。
                let mut privacy_audit = kirin_desk_utils::audit::AuditLogger::open_default().ok();
                let sender_privacy = sender_shared.clone();
                // M8-T018: 显示器切换命令通道（分发任务 → 捕获循环；
                // 热切换重建捕获源，无需重连）。
                let (switch_monitor_tx, mut switch_monitor_rx) =
                    tokio::sync::mpsc::unbounded_channel::<u32>();
                // M8-T018（SRV-MON-010）：注入器在分发任务与捕获循环
                // 间共享——显示器切换后同步更新换算基准（src/dst = 新屏
                // 分辨率）。键鼠事件 ~60fps，切换低频，锁竞争可忽略。
                let injector = Arc::new(tokio::sync::Mutex::new(InputInjector::new(
                    width, height, width, height,
                )));
                // 捕获循环持有的另一句柄（切换成功后更新基准）。
                let injector_capture = injector.clone();
                // M8-T032：服务端 talkback 播放线程——客户端麦克风回传（③）
                // → 本机扬声器（WASAPI 共享渲染）。与客户端播放线程同模式：
                // `AudioDecodePipeline::new(rx)` + `start_playback()` + `run()`；
                // 线程退出条件 = 会话结束（talkback_tx drop → run 返回），
                // 无新增泄漏。总开关关 → 不建线程（客户端也不会发）。
                let talkback_tx = if audio_enabled_global().load(Ordering::Relaxed) {
                    let (talkback_tx, talkback_rx) = std::sync::mpsc::channel::<
                        kirin_desk_media::decoder::AudioPacket,
                    >();
                    let _talkback_handle = std::thread::Builder::new()
                        .name("kirin-audio-talkback".into())
                        .spawn(move || {
                            let mut pipe = match kirin_desk_media::decoder::audio::
                                AudioDecodePipeline::new(talkback_rx)
                            {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::info!(
                                        "Talkback playback disabled (init failed): {e}"
                                    );
                                    return;
                                }
                            };
                            match pipe.start_playback() {
                                Ok(()) => {
                                    tracing::info!(
                                        "Talkback playback started (WASAPI shared render)"
                                    );
                                }
                                Err(e) => {
                                    tracing::info!(
                                        "Talkback playback unavailable ({e}) — decode-only (silent)"
                                    );
                                }
                            }
                            // run()：音频通道关闭（会话结束）→ Ok 返回，线程干净退出。
                            let _ = pipe.run();
                            tracing::info!("Talkback pipeline exited");
                        })
                        .expect("spawn talkback playback thread");
                    // 线程句柄持有即保活（std::thread 句柄 drop 不 join）；
                    // 退出由通道关闭驱动（talkback_tx 随分发任务 drop）。
                    let _ = _talkback_handle;
                    Some(talkback_tx)
                } else {
                    None
                };
                tokio::spawn(async move {
                    // src = 客户端坐标空间：客户端按服务端捕获分辨率
                    // (base_w/base_h) 发像素坐标 → src == dst。
                    let injector_dispatch = injector;
                    let switch_monitor_tx_dispatch = switch_monitor_tx.clone();
                    let mut dropped_input: u64 = 0;
                    // M8-T019 (SRV-PRIV-015): 锁屏解锁轮询节流（1s）。
                    let mut last_unlock_poll = std::time::Instant::now() - Duration::from_secs(1);
                    loop {
                        if stop_input.load(Ordering::Relaxed) {
                            info!("Input receive loop stopping by user request");
                            break;
                        }
                        // M8-T019 (SRV-PRIV-015): 锁屏被本地解锁 →
                        // 自动恢复注入 + 通知客户端（无需重连）。
                        if last_unlock_poll.elapsed() >= Duration::from_secs(1) {
                            last_unlock_poll = std::time::Instant::now();
                            let resumed = privacy_controller.lock().unwrap().poll_unlock();
                            if resumed {
                                audit_record(
                                    &mut privacy_audit,
                                    kirin_desk_utils::audit::AuditEvent::PrivacyRecovered,
                                    "event=unlock level=lock initiator=local",
                                );
                                info!("[Privacy] workstation unlocked — injection resumed");
                                send_privacy_ack(&sender_privacy, true, None).await;
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
                                if privacy_controller.lock().unwrap().injection_paused() {
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
                                        let mut inj = injector_dispatch.lock().await;
                                        if let Err(e) = inj.handle(ev) {
                                            warn!(
                                                "Input inject failed (dropping, no retry): {}",
                                                e
                                            );
                                        }
                                    }
                                    Err(e) => warn!("Input event deserialize failed: {}", e),
                                }
                            }
                            // M8-T019 (SRV-PRIV-001/002/013 + PRIV-SEC-001):
                            // 隐私模式控制（复用 M8-T018 控制通道）。
                            // M8-T018: 显示器枚举/切换控制（同通道分发）。
                            ChannelTag::Control => {
                                match bincode::deserialize::<ControlMessage>(&payload) {
                                    Ok(ControlMessage::DisplayListReq) => {
                                        // M8-T018（SRV-CAP-MON-001）：枚举显示器
                                        // → DisplayListResp（空时兜底默认屏）。
                                        let displays =
                                            kirin_desk_media::capture::factory::enumerate_monitors(
                                            );
                                        if let Ok(data) =
                                            bincode::serialize(&ControlMessage::DisplayListResp {
                                                displays,
                                            })
                                        {
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
                            ChannelTag::FileTransfer => match FileTransferFrame::decode(&payload) {
                                Ok(frame) => {
                                    if file_frame_tx_dispatch.send(frame).is_err() {
                                        break;
                                    }
                                }
                                Err(e) => warn!("File frame decode failed: {}", e),
                            },
                            // M8-T032：客户端麦克风回传（③）→ 解码 + WASAPI
                            // 播放（talkback）。投递失败 = 播放线程已退出
                            // （会话结束）→ 随接收循环退出。
                            ChannelTag::Audio => {
                                if let Some(tx) = &talkback_tx {
                                    let pkt = kirin_desk_media::decoder::AudioPacket {
                                        pts: _header.pts,
                                        data: payload,
                                    };
                                    if tx.send(pkt).is_err() {
                                        break;
                                    }
                                }
                            }
                            // 其余 tag（Video/Clipboard 等）无服务端消费方，静默忽略。
                            _ => {}
                        }
                    }
                    // M8-T019 (SRV-PRIV-014 安全红线): 断连/停止 →
                    // 本地状态复位（黑屏覆盖随之关闭，无网络依赖）。
                    if let Some(was) = privacy_controller.lock().unwrap().on_connection_lost() {
                        audit_record(
                            &mut privacy_audit,
                            kirin_desk_utils::audit::AuditEvent::PrivacyRecovered,
                            &format!("event=disconnect level={} initiator=system", was.as_str()),
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
                                info!("Capture: switched to monitor {} ({}x{})", idx, sw, sh);
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
                                let reason = format!("switch monitor {idx} failed: {e}");
                                if let Ok(data) =
                                    bincode::serialize(&ControlMessage::DisplaySelectNack {
                                        reason,
                                    })
                                {
                                    let pkt = EncodedPacket {
                                        ts: Timestamp::now(),
                                        kind: PacketKind::Control,
                                        data,
                                        is_key: false,
                                    };
                                    if let Err(e2) =
                                        sender_shared.lock().await.send_packets(&[pkt]).await
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
                                    info!(
                                        "Capture: window {} encoded ({} frames, {}x{})",
                                        encoded_window.window_id,
                                        n_frames,
                                        encoded_window.base_w,
                                        encoded_window.base_h
                                    );

                                    // Serialize and send over SecureChannel (tag 分帧 Video)。
                                    // 视频帧（编码窗口，4K 下可达 ~125KB）远超
                                    // `stream::MAX_PACKET_PAYLOAD`（≈1151B）小分片上限，
                                    // 走 `send_big_packet` 大帧路径（16MiB 上限，
                                    // 与 M13-T006 文件传输同路径，线格式一致：
                                    // `PacketHeader + payload`，客户端 parse_frame 无改动）。
                                    match bincode::serialize(&encoded_window) {
                                        Ok(bytes) => {
                                            let pkt = EncodedPacket {
                                                ts: Timestamp::now(),
                                                kind: PacketKind::Video,
                                                data: bytes,
                                                is_key: window_count == 0,
                                            };
                                            if let Err(e) = sender_shared
                                                .lock()
                                                .await
                                                .send_big_packet(&pkt)
                                                .await
                                            {
                                                error!(
                                                    "Capture send error window {}: {} — closing",
                                                    encoded_window.window_id, e
                                                );
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "Serialize window {} failed: {}",
                                                encoded_window.window_id, e
                                            );
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
                                    error!(
                                        "Capture access lost — closing connection, will recreate"
                                    );
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

    fn show_devices(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        ui.heading(t!("devices.title"));
        ui.separator();
        if self.devices.is_empty() {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("devices.empty"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
        } else {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(tf!("devices.count", self.devices.len()))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            egui::ScrollArea::vertical().show(ui, |ui| {
                for i in 0..self.devices.len() {
                    let d = self.devices[i].clone();
                    // M8-T037: 设备卡片——① 昵称（strong）+ 类型徽标 + 上次在线；
                    // ② 备注名（空 → "—" 弱色）；③ 地址行（[IPv6]:port 或域名，
                    // mono + 📋）；④ 显式按钮行（连接/编辑/删除/↑上移/↓下移）。
                    // 状态点：SavedDevice 无实时 status 字段 → 中性停止态
                    // （fg_weak "saved"）。保留单击卡片填 Connect 页 + 右键菜单；
                    // 点击交互层仅覆盖 ①~③（按钮行在层外，按钮可正常点击）。
                    let name = if d.nickname.is_empty() {
                        d.id.clone()
                    } else {
                        d.nickname.clone()
                    };
                    let addr = if d.domain.is_empty() {
                        format!("[{}]:{}", d.ipv6, d.port)
                    } else {
                        d.domain.clone()
                    };
                    let title_copy = if d.domain.is_empty() {
                        format!("{}@[{}]:{}", name, d.ipv6, d.port)
                    } else {
                        format!("{}@{}", name, d.domain)
                    };
                    let mut title_rect: Option<egui::Rect> = None;
                    let mut addr_rect: Option<egui::Rect> = None;
                    let mut click_bottom: f32 = f32::MAX;
                    let card = egui::Frame::none()
                        .fill(theme.bg_panel)
                        .stroke(egui::Stroke::new(theme.border_width, theme.border))
                        .rounding(theme.rounding_card)
                        .inner_margin(egui::Margin::same(theme.card_padding))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                status_dot(ui, theme.fg_weak, t!("devices.saved_badge"));
                                let tr = ui.add(
                                    egui::Label::new(egui::RichText::new(&name).strong())
                                        .selectable(true),
                                );
                                title_rect = Some(tr.rect);
                                ui.add_space(32.0); // 📋 预留
                                let (kind, label) = if d.device_type == "server" {
                                    (BadgeKind::Info, "server")
                                } else {
                                    (BadgeKind::Neutral, "desktop")
                                };
                                badge(ui, theme, label, kind);
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
                            // ② 备注名行（空 → "—" 弱色占位）。
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(if d.remark.is_empty() {
                                        t!("devices.remark_empty")
                                    } else {
                                        &d.remark
                                    })
                                    .size(theme.small_size)
                                    .color(theme.fg_weak),
                                )
                                .selectable(true),
                            );
                            // ③ 地址行。
                            ui.horizontal(|ui| {
                                let ar = ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&addr)
                                            .monospace()
                                            .size(theme.mono_size)
                                            .color(theme.fg),
                                    )
                                    .selectable(true),
                                );
                                addr_rect = Some(ar.rect);
                                ui.add_space(32.0); // 📋 预留
                            });
                            // ④ 按钮行起点 = 点击交互层下界（按钮在层外可点）。
                            click_bottom = ui.cursor().min.y;
                            ui.horizontal(|ui| {
                                if ui.small_button(t!("devices.btn.connect")).clicked() {
                                    self.fill_connect_from_device(&d);
                                }
                                if ui.small_button(t!("devices.btn.edit")).clicked() {
                                    self.start_edit_device(&d);
                                }
                                if ui.small_button(t!("devices.btn.delete")).clicked() {
                                    self.delete_device(&d.id);
                                }
                                ui.separator();
                                if ui
                                    .add_enabled(
                                        i > 0,
                                        egui::Button::new(t!("devices.btn.up")).small(),
                                    )
                                    .clicked()
                                {
                                    self.move_device(&d.id, true);
                                }
                                if ui
                                    .add_enabled(
                                        i + 1 < self.devices.len(),
                                        egui::Button::new(t!("devices.btn.down")).small(),
                                    )
                                    .clicked()
                                {
                                    self.move_device(&d.id, false);
                                }
                            });
                        });
                    // 点击交互层仅覆盖卡片内容区（不含按钮行）——单击填入/右键菜单
                    // 行为不变；按钮行在层外可正常点击。
                    let mut click_rect = card.response.rect;
                    if click_bottom != f32::MAX {
                        click_rect.max.y = click_bottom;
                    }
                    let click =
                        ui.interact(click_rect, ui.id().with(("dev_card", i)), egui::Sense::click());
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
                        place_btn(ui, r, &title_copy);
                    }
                    if let Some(r) = addr_rect {
                        place_btn(ui, r, &addr);
                    }
                    if let Some(v) = copied {
                        self.notify_copied(&v);
                    }
                    if click.hovered() {
                        ui.painter().rect_stroke(
                            card.response.rect,
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
                        if ui.button(t!("devices.menu.connect")).clicked() {
                            self.fill_connect_from_device(&d);
                            ui.close_menu();
                        }
                        if ui.button(t!("devices.menu.edit")).clicked() {
                            self.start_edit_device(&d);
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button(t!("devices.menu.delete")).clicked() {
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
            egui::Window::new(t!("devices.edit.title"))
                .collapsible(false)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(tf!("devices.edit.id_label", id))
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
                        t!("devices.edit.nickname"),
                        &mut self.edit_nickname,
                        "",
                        Validity::None,
                        None,
                        false,
                    );
                    // M8-T037: 地址（IP/域名）——update 选择性保存：可解析为 IP →
                    // 更新 IPv6 清空域名；否则视为域名；空 → 地址保持不变。
                    labeled_input(
                        ui,
                        theme,
                        t!("devices.edit.host"),
                        &mut self.edit_host,
                        "",
                        Validity::None,
                        None,
                        true,
                    );
                    labeled_input(
                        ui,
                        theme,
                        t!("devices.edit.remark"),
                        &mut self.edit_remark,
                        t!("devices.edit.optional"),
                        Validity::None,
                        None,
                        false,
                    );
                    labeled_input(
                        ui,
                        theme,
                        t!("devices.edit.challenge"),
                        &mut self.edit_challenge,
                        t!("devices.edit.optional"),
                        Validity::None,
                        Some(&mut self.show_secret_edit_challenge),
                        false,
                    );
                    labeled_input(
                        ui,
                        theme,
                        t!("devices.edit.port"),
                        &mut self.edit_port,
                        "",
                        Validity::None,
                        None,
                        true,
                    );
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(t!("common.ok")).clicked() {
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
                        if ui.button(t!("common.cancel")).clicked() {
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
    /// 有域名且 DNS 服务商已配置 → Domain 模式（DNS 发现）；否则 IP 模式直连。
    /// M8-T037: 设备保存的挑战码非空时预填连接表单（表单必填校验不变；
    /// 设备无挑战码 → 不预填，由用户输入）。
    fn fill_connect_from_device(&mut self, d: &SavedDevice) {
        self.connect_nickname = d.nickname.clone();
        self.connect_challenge = d.challenge.clone();
        // M9-DNS022 (UI-DNS-004): 判定泛化——任意已注册服务商凭据即可
        // （不再限定 GoDaddy api_key/api_secret）。
        if !d.domain.is_empty() && self.dns_configured {
            self.connect_domain = d.domain.clone();
            self.ip_mode_allowed = false; // 切换 Domain 模式界面（仅内存，不写回配置）
            self.connect_status =
                tf!("connect.ready_domain", d.nickname, d.domain);
        } else {
            self.connect_ipv6 = d.ipv6.clone();
            self.connect_port = d.port.to_string();
            self.ip_mode_allowed = true;
            self.connect_status = tf!("connect.ready", d.nickname, d.ipv6, d.port);
        }
        self.current_tab = Tab::Connect;
    }

    /// M10-T005: 打开设备编辑弹窗（预填当前值）。
    fn start_edit_device(&mut self, d: &SavedDevice) {
        self.editing_device = Some(d.id.clone());
        self.edit_nickname = d.nickname.clone();
        // M8-T037: 地址预填——有域名 → 域名，否则 IPv6（直连回退值）。
        self.edit_host = if d.domain.is_empty() {
            d.ipv6.clone()
        } else {
            d.domain.clone()
        };
        self.edit_port = d.port.to_string();
        self.edit_remark = d.remark.clone();
        self.edit_challenge = d.challenge.clone();
    }

    /// M10-T005: 提交编辑 → 持久化到 devices.json → 刷新列表。
    fn commit_device_edit(&mut self, id: &str, port: u16) {
        let nickname = self.edit_nickname.trim().to_string();
        let remark = self.edit_remark.trim().to_string();
        let challenge = self.edit_challenge.trim().to_string();
        let host = self.edit_host.trim().to_string();
        // M8-T037: 取消「昵称必填」限制——空昵称允许保存（卡片展示回退设备 ID）。
        match DeviceStore::load() {
            Ok(mut store) => {
                // M8-T037: 备注名/挑战码允许为空（空挑战码 = 无挑战码）；
                // 地址选择性保存：空 → 原地址不变（update 语义）。
                if store.update(id, &remark, &host, port, &nickname, &challenge) {
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

    /// M8-T037: 上移/下移设备（交换相邻 sort_order）→ 持久化 → 刷新列表。
    /// 首项上移 / 末项下移 / 未知 id 无效果（按钮已按边界禁用，防御性兜底）。
    fn move_device(&mut self, id: &str, up: bool) {
        match DeviceStore::load() {
            Ok(mut store) => {
                let moved = if up {
                    store.move_up(id)
                } else {
                    store.move_down(id)
                };
                if moved {
                    if let Err(e) = store.save() {
                        tracing::error!("Move device save failed: {}", e);
                    }
                    self.devices = store.devices().to_vec();
                    tracing::info!("Device '{}' moved {}", id, if up { "up" } else { "down" });
                }
            }
            Err(e) => tracing::error!("Move device: store load failed: {}", e),
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
        ui.heading(t!("connect.title"));
        ui.separator();

        // M8-T038 (P1): 连接状态已迁移至弹出页状态条（conn_state_{wid}）——
        // 本页不再显示顶部状态点行（原「IP Address 上方」位置，M10-T001/M15-T008 块已删）。

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
                t!("connect.mode.ip"),
                t!("connect.mode.domain"),
                t!("connect.mode.id"),
            ],
            &mut mode,
        ) {
            self.ip_mode_allowed = mode == 0;
            self.connect_id_mode = mode == 2;
        }
        ui.separator();

        // M8-T036 (需求 2): 双栏布局——左 = 表单（输入框 + Connect 按钮），
        // 右 = 连接日志（原页面底部 LogView 移至右侧，与表单并排）。
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(480.0);
                self.show_connect_form(ui, theme);
            });
            ui.vertical(|ui| {
                // 右侧：连接日志（级别着色 + 清空/复制；列内高度自适应）。
                log_view(
                    ui,
                    theme,
                    &self.gui_log,
                    &LogViewOptions {
                        title: t!("connect.log.title"),
                        empty: t!("connect.log.empty"),
                        max_height: 480.0,
                        clearable: true,
                        clear: Some(clear_gui_log),
                    },
                );
            });
        });
        ui.separator();

        // M8-T036 (需求 2): Connect 页下方展示「连接过的设备」（Devices 页同源
        // 数据 self.devices）——单击自动填入表单，右键菜单：连接/编辑/删除。
        self.show_connect_devices(ui, theme);
    }

    /// M8-T036: Connect 页左侧连接表单（IP / Domain / ID 三模式共用入口；
    /// 原 show_connect 主体，双栏化后独立成方法）。
    fn show_connect_form(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        let status = connection_status().lock().unwrap().clone();

        if self.ip_mode_allowed {
            // M15-T008: 表单校验——IP（v4/v6 均可，M8-T033）/ 端口 1-65535 /
            // 昵称与挑战码必填（UI-CON-010/022）
            let ip_empty = self.connect_ipv6.trim().is_empty();
            let ip_ok = self
                .connect_ipv6
                .trim()
                .parse::<std::net::IpAddr>()
                .is_ok();
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
                t!("connect.label.ip"),
                &mut self.connect_ipv6,
                "192.168.1.5 or 2001:db8::1",
                if ip_empty {
                    Validity::None
                } else if ip_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid(t!("connect.error.ip_invalid"))
                },
                None,
                true,
            );
            labeled_input(
                ui,
                theme,
                t!("connect.label.port"),
                &mut self.connect_port,
                "3389",
                if port_empty {
                    Validity::None
                } else if port_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid(t!("connect.error.port_invalid"))
                },
                None,
                true,
            );
            labeled_input(
                ui,
                theme,
                t!("connect.label.nickname"),
                &mut self.connect_nickname,
                t!("connect.placeholder.required"),
                if nick_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid(t!("connect.error.nickname_required"))
                },
                None,
                false,
            );
            labeled_input(
                ui,
                theme,
                t!("connect.label.challenge"),
                &mut self.connect_challenge,
                t!("connect.placeholder.required"),
                if chal_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid(t!("connect.error.challenge_required"))
                },
                Some(&mut self.show_secret_connect),
                false,
            );
            ui.add_space(6.0);

            // M15-T008: 连接状态 Stepper 已迁移至弹出页状态条（M8-T038 P1），
            // 本页保留 step 推导（busy 驱动按钮禁用/⏳），仅删渲染。
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
                if action_button(ui, theme, ButtonKind::Primary, t!("connect.button.connect"), state)
                    .clicked()
                {
                    do_connect = true;
                }
                if action_button(
                    ui,
                    theme,
                    ButtonKind::Secondary,
                    t!("connect.button.shell"),
                    state,
                )
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
                    self.connect_status = t!("connect.error.ip_empty").to_string();
                } else if port == 0 {
                    self.connect_status = t!("connect.error.port_empty").to_string();
                } else if nick.is_empty() {
                    self.connect_status = t!("connect.error.nickname_empty").to_string();
                } else {
                    // M8-T033: v4 不加方括号（`[192.168.1.5]:port` 非法）；
                    // v6 保持 `[ip]:port` 规范形式。
                    let addr = if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                        format!("{}:{}", ip, port)
                    } else {
                        format!("[{}]:{}", ip, port)
                    };
                    let kind = if do_shell {
                        WindowKind::Shell
                    } else {
                        WindowKind::Desktop
                    };
                    // M8-T021 P1 (T021-01-D): 前置查重——同目标已有窗口 → 聚焦 +
                    // 提示，不 spawn（session_id 不分配、TCP/握手零浪费；握手期间
                    // 竞态由 drain 去重兜底）。
                    if self.try_dedup_connect(ui.ctx(), &addr, kind) {
                        self.connect_status = t!("connect.dedup_hit").to_string();
                        tracing::info!("[dedup] connect pre-check hit for {}, not spawning", addr);
                    } else {
                        // M8-T038 (P1): 进度快照类 connect_status 写入已删除
                        // （进度改由弹出页状态条承载；本行保留 tracing 日志）。
                        tracing::info!(
                            "Connect button: target={} nickname={} shell={}",
                            addr,
                            nick,
                            do_shell
                        );
                        // M15: 共享会话启动器——TCP 连接 → 完整握手（IP 模式无带外
                        // 公钥 → known_hosts 命中自动放行 / 首次指纹确认，CLI-HSK-SEC-003）
                        // → 会话任务 → 自动保存设备 + 记录 known_hosts。
                        // R-03 (R03-S2/S4)：登记重连上下文（断线后自动重连）。
                        let reconnect_ctx = if do_shell {
                            None // Shell 会话无桌面断线重连
                        } else {
                            build_reconnect_ctx(
                                ip.clone(),
                                port,
                                nick.clone(),
                                chal.clone(),
                                "desktop",
                                ClientTrust::Confirm,
                                None,
                                String::new(),
                            )
                        };
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
                                        reconnect_ctx,
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
                    egui::RichText::new(t!("connect.hint.ip_mode"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("connect.hint.ip_whitelist_na"))
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
                t!("connect.label.device_id"),
                &mut self.connect_device_id,
                "pc-abc123",
                if id_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid(t!("connect.error.device_id_required"))
                },
                None,
                true,
            );
            if !tunnel_ok {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("connect.id.tunnel_missing"))
                            .color(theme.danger)
                            .size(theme.small_size),
                    )
                    .selectable(false),
                );
            } else {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(tf!("connect.id.via_relay", tunnel_cfg.server_addr))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            }
            ui.add_space(6.0);
            // M8-T038 (P1): Stepper 渲染已迁移至弹出页状态条；保留 step/busy 推导。
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
            let busy = matches!(step, Some(0) | Some(1) | Some(2));
            let can_connect = id_ok && tunnel_ok;
            let state = if busy {
                ButtonState::Busy
            } else if can_connect {
                ButtonState::Enabled
            } else {
                ButtonState::Disabled
            };
            if action_button(ui, theme, ButtonKind::Primary, t!("connect.button.connect"), state)
                .clicked()
            {
                let device_id = self.connect_device_id.trim().to_string();
                if device_id.is_empty() {
                    self.connect_status = t!("connect.error.device_id_empty").to_string();
                } else if !tunnel_ok {
                    self.connect_status = t!("connect.id.error_configure").to_string();
                } else {
                    // M8-T026-P2: ID 模式连接线程：解析 → 验签 → pin → 三级路径 →
                    // 握手 → 会话（复用 run_client_session_with_stream）。
                    // M8-T038 (P1): 进度快照类 connect_status 写入已删除（弹出页状态条承载）。
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
                    egui::RichText::new(t!("connect.hint.id_mode"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
        } else {
            // M10-T002: 无 DNS 服务商配置 → 友好提示 + 直接跳转 Domain 页。
            // M9-DNS022 (UI-DNS-004): 泛化——任意服务商，不再出现 GoDaddy 字样。
            if !self.dns_configured {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("domain.error.not_configured"))
                            .color(theme.danger),
                    )
                    .selectable(false),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("domain.provider.connect_guide"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                if ui.button(t!("domain.provider.goto_domain")).clicked() {
                    self.current_tab = Tab::Domain;
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
                t!("connect.label.domain"),
                &mut self.connect_domain,
                "example.com",
                if domain_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid(t!("connect.error.domain_required"))
                },
                None,
                true,
            );
            labeled_input(
                ui,
                theme,
                t!("connect.label.nickname"),
                &mut self.connect_nickname,
                t!("connect.placeholder.required"),
                if nick_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid(t!("connect.error.nickname_required"))
                },
                None,
                false,
            );
            labeled_input(
                ui,
                theme,
                t!("connect.label.challenge"),
                &mut self.connect_challenge,
                t!("connect.placeholder.required"),
                if chal_ok {
                    Validity::Valid
                } else {
                    Validity::Invalid(t!("connect.error.challenge_required"))
                },
                Some(&mut self.show_secret_connect),
                false,
            );
            ui.add_space(6.0);
            // M8-T038 (P1): Stepper 渲染已迁移至弹出页状态条；保留 step/busy 推导。
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
            let busy = matches!(step, Some(0) | Some(1) | Some(2));
            // M9-DNS022 (UI-DNS-004): 域名模式前置校验泛化——任意已注册服务商
            // 凭据即可（不再限定 GoDaddy）。
            let api_ok = self.dns_configured;
            let can_connect = domain_ok && nick_ok && chal_ok && api_ok;
            let state = if busy {
                ButtonState::Busy
            } else if can_connect {
                ButtonState::Enabled
            } else {
                ButtonState::Disabled
            };
            if action_button(ui, theme, ButtonKind::Primary, t!("connect.button.connect"), state)
                .clicked()
            {
                let domain = self.connect_domain.trim().to_string();
                let nick = self.connect_nickname.trim().to_string();
                let chal = self.connect_challenge.trim().to_string();
                if domain.is_empty() {
                    self.connect_status = t!("connect.error.domain_empty").to_string();
                } else if nick.is_empty() {
                    self.connect_status = t!("connect.error.nickname_empty").to_string();
                } else if !self.dns_configured {
                    // M10-T002: 无 DNS 服务商配置 → 拒绝执行（页面上方已有引导提示）。
                    self.connect_status = t!("domain.error.not_configured").to_string();
                } else {
                    // M10-T001 + M15: Domain 模式 — DNS 发现（SRV 端口 + TXT 公钥 +
                    // AAAA IPv6）→ 信任解析（known_hosts 优先于 TXT；未命中首次指纹
                    // 确认）→ TCP 连接 → 完整握手（TXT 公钥强制验证）→ 自动保存设备。
                    // M8-T038 (P1): 进度快照类 connect_status 写入已删除（弹出页状态条承载）。
                    tracing::info!("Connect button: domain={} device={}", domain, nick);
                    let ctx = ui.ctx().clone();
                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().expect("connect rt");
                        rt.block_on(async {
                            // 1. 发现中：当前激活服务商（配置层凭据）并行查询
                            //    SRV/TXT/AAAA（M9-DNS022 provider 化）。
                            let cfg = kirin_desk_utils::config::Config::load()
                                .unwrap_or_default();
                            // 目标域名：godaddy 兼容读 `[godaddy] domain`
                            // （设备注册域）；其余服务商取表单输入。
                            let target_domain = if cfg.dns.provider == "godaddy"
                                && !cfg.godaddy.domain.trim().is_empty()
                            {
                                cfg.godaddy.domain.trim().to_string()
                            } else {
                                domain.clone()
                            };
                            let device_id = nick.clone();
                            let discovery_res = {
                                let provider = match kirin_desk_dns::default_provider(
                                    &cfg.dns.provider,
                                    &cfg.dns.providers,
                                ) {
                                    Ok(p) => p,
                                    Err(e) => {
                                        tracing::error!(
                                            "DNS provider init failed: {}",
                                            e
                                        );
                                        if let Ok(mut s) = connection_status().lock() {
                                            *s = format!("DNS 服务商初始化失败: {}", e);
                                        }
                                        return;
                                    }
                                };
                                let discovery =
                                    DiscoveryService::new(&*provider, &target_domain);
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
                                    // ── M8-T040：域名模式强制加密 DNS（DDNS-DOH-001/003）──
                                    // GUI 连接路径同样收敛 `resolve_for_connect` 加密解析入口；
                                    // 未配置解析器（mode=off）/ 全端点不可用 → fail-closed 拒连，
                                    // 绝不回退明文（DDNS-UI-007 状态行指示）。
                                    let mut resolved_addr = selected;
                                    let host = format!("{}.{}", device_id, target_domain);
                                    match kirin_desk_core::dns::secure_resolver_from_config(&cfg) {
                                        Some(resolver) => {
                                            if let Ok(mut s) = connection_status().lock() {
                                                *s = t!("connect.dnssec.resolving").to_string();
                                            }
                                            match kirin_desk_core::dns::resolve_for_connect(
                                                &host,
                                                selected.port(),
                                                family,
                                                resolver.as_ref(),
                                            )
                                            .await
                                            {
                                                Ok(addrs) => {
                                                    if let Some(a) = addrs.first() {
                                                        resolved_addr = *a;
                                                    }
                                                    if let Ok(mut s) = connection_status().lock() {
                                                        if addrs.is_empty() {
                                                            // R-30（审计 §8-2）：合法空列表 → 状态行
                                                            // 如实显示「无记录」，连接沿用 discovery
                                                            // 地址继续（行为不变，非 fail-closed）。
                                                            *s = t!("connect.dnssec.no_records")
                                                                .to_string();
                                                        } else {
                                                            *s = tf!(
                                                                "connect.dnssec.resolved",
                                                                "DoH/DoT"
                                                            );
                                                        }
                                                    }
                                                    tracing::info!(
                                                        "[M8-T040] domain-mode encrypted resolve '{}' -> {} (records={})",
                                                        host, resolved_addr, addrs.len()
                                                    );
                                                }
                                                Err(e) => {
                                                    tracing::error!(
                                                        "[M8-T040] encrypted DNS unavailable for '{}': {}",
                                                        host, e
                                                    );
                                                    if let Ok(mut s) = connection_status().lock() {
                                                        *s =
                                                            t!("connect.dnssec.refused").to_string();
                                                    }
                                                    return; // fail-closed（DDNS-DOH-003）
                                                }
                                            }
                                        }
                                        None => {
                                            tracing::error!(
                                                "[M8-T040] domain-mode connect refused: \
                                                 no encrypted resolver (mode=off / not configured)"
                                            );
                                            if let Ok(mut s) = connection_status().lock() {
                                                *s = t!("connect.dnssec.refused").to_string();
                                            }
                                            return; // fail-closed（DDNS-DOH-007）
                                        }
                                    }
                                    let addr = resolved_addr.to_string();
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
                                    let trust = ClientTrust::Verified(info.public_key_base64.clone());
                                    // R-03 (R03-S2/S4)：登记重连上下文——断线后按原
                                    // 规格自动重连（重新发现域名，IP 可能已变化）；
                                    // server 型（Shell）会话无桌面断线重连。
                                    let reconnect_ctx = if info.device_type == "server" {
                                        None
                                    } else {
                                        build_reconnect_ctx(
                                            device_id.clone(),
                                            0, // 域名模式端口来自发现
                                            device_id.clone(),
                                            chal.clone(),
                                            "desktop",
                                            ClientTrust::Verified(
                                                info.public_key_base64.clone(),
                                            ),
                                            Some(DnsConfig {
                                                api_key: cfg.godaddy.api_key.clone(),
                                                api_secret: cfg.godaddy.api_secret.clone(),
                                                api_url: cfg.godaddy.api_url.clone(),
                                                domain: target_domain.clone(),
                                                ip_family: family,
                                                // M9-DNS023: provider 化——重连
                                                // 发现经 default_provider（配置层
                                                // 凭据表为事实源）。
                                                provider: cfg.dns.provider.clone(),
                                                credentials: cfg.dns.providers.clone(),
                                                // M8-T040: 域名模式强制加密 DNS
                                                // （DoH/DoT；mode=off/未配置 → None
                                                // → fail-closed 拒连并提示）。
                                                resolver:
                                                    kirin_desk_core::dns::secure_resolver_from_config(
                                                        &cfg,
                                                    ),
                                            }),
                                            domain.clone(),
                                        )
                                    };
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
                                            reconnect_ctx,
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
                    egui::RichText::new(t!("connect.hint.domain_whitelist"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("connect.hint.domain_whitelist_only"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("connect.hint.domain_tip"))
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
        // M8-T036: 连接日志已移至表单右侧（show_connect 双栏右列）。
    }

    /// M8-T036 (需求 2): Connect 页下方「连接过的设备」列表（与 Devices 页同源
    /// `self.devices`）——单击自动填入表单并切换 Connect 页，右键菜单
    /// 连接 / 编辑 / 删除（M10-T004/T005 语义复用，轻量行渲染）。
    fn show_connect_devices(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        ui.add(
            egui::Label::new(
                egui::RichText::new(t!("connect.devices.title"))
                    .size(theme.small_size)
                    .color(theme.fg_weak),
            )
            .selectable(false),
        );
        if self.devices.is_empty() {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("connect.devices.empty"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            return;
        }
        egui::ScrollArea::vertical()
            .max_height(220.0)
            .show(ui, |ui| {
                for i in 0..self.devices.len() {
                    let d = self.devices[i].clone();
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
                    let row = ui.horizontal(|ui| {
                        status_dot(ui, theme.fg_weak, t!("devices.saved_badge"));
                        ui.add(
                            egui::Label::new(egui::RichText::new(&name).strong())
                                .selectable(true),
                        );
                        let (kind, label) = if d.device_type == "server" {
                            (BadgeKind::Info, "server")
                        } else {
                            (BadgeKind::Neutral, "desktop")
                        };
                        badge(ui, theme, label, kind);
                        if let Some(addr) = &addr {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(addr)
                                        .monospace()
                                        .size(theme.small_size)
                                        .color(theme.fg_weak),
                                )
                                .selectable(true),
                            );
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
                    })
                    .response;
                    if row.clicked() {
                        self.fill_connect_from_device(&d);
                    }
                    row.context_menu(|ui| {
                        if ui.button(t!("devices.menu.connect")).clicked() {
                            self.fill_connect_from_device(&d);
                            ui.close_menu();
                        }
                        if ui.button(t!("devices.menu.edit")).clicked() {
                            self.start_edit_device(&d);
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button(t!("devices.menu.delete")).clicked() {
                            self.delete_device(&d.id);
                            ui.close_menu();
                        }
                    });
                }
            });
    }

    /// M8-T037: 「默认受控」联动 Dashboard「允许受控」——默认受控开启
    /// （或经无人值守跟随开启）时立即启动服务端监听；已运行则保持。
    /// bind 失败由每帧运行态同步自动回位开关并显示原因（见 update 帧同步），
    /// 无需额外处理；「允许受控」手动关闭不回写默认受控（单向联动）。
    fn apply_default_controlled(&mut self) {
        if !self.unattended_auto_server {
            return;
        }
        if !self.server_running {
            self.start_server();
        }
    }

    fn show_settings(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        ui.heading(t!("settings.title"));
        ui.separator();
        egui::ScrollArea::vertical().show(ui, |ui| {
            // M15-T008: 可折叠分组（Tunnel / Unattended / Identity / Whitelist /
            // Logging / Appearance / Update / About）+ 底部统一 Save。
            // M8-T035 (需求 4): 「Server」组已移除（Listen Port → Dashboard 服务端
            // 设置；音频总开关/高危警告 → Dashboard Server 卡；模式按钮 Dashboard 已有）。
            // M9-DNS022: 「DNS」组移除——服务商选择/凭据表单/测试连接全部迁至
            // Domain 页「服务商」卡（见 `domain_panel.rs`）；`[dns]`/`[godaddy]`
            // 配置段不变，CLI 行为零影响。

            // M9-DNS022: 「DNS」分组已移除——服务商选择/凭据表单/测试连接
            // 迁至 Domain 页「服务商」卡；此处不再渲染（见 `domain_panel.rs`）。

            // M8-T035 (需求 4/5): Settings「Server」组整体移除——Listen Port 迁
            // Dashboard「服务端设置」、连接模式迁 Dashboard 工作模式按钮（M8-T034）、
            // 音频总开关与高危警告迁 Dashboard Server 卡（会话级 toggle / 挑战码
            // 所在页提示闭环）；静态 temp_mode 仅由 CLI/config 管理（GUI 无入口）。
            // M8-T039: 「Tunnel (内网穿透)」分组整体移除——迁至顶部导航独立页
            // （show_tunnel，Tab::Tunnel）；本页不再渲染（见 show_tunnel）。

            // M13-T005 (UA-UI-001): 无人值守模式卡片——总开关 + 子选项 +
            // 自启注册状态 + 安全提示。保存按钮统一落盘（见下方 Save 分支）。
            egui::CollapsingHeader::new(t!("settings.unattended.title")).show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.unattended.desc"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add_space(4.0);
                // M8-T035 (需求 3) + M8-T037: 三个开关滑块横向一排——无人值守
                // （master）/ 开机自启 / 默认受控。M8-T037 联动：无人值守
                // 开 → 开机自启、默认受控跟随打开；关 → 跟随关闭（仅改配置，
                // 不停止运行中监听）；两个子开关均可独立翻转（只改自身）。
                // 默认受控开启 → 立即联动 Dashboard「允许受控」（启动监听）。
                ui.horizontal(|ui| {
                    // 总开关：开 → 子开关跟随开；关 → 子开关跟随关。
                    let ua = self.unattended_enabled;
                    let ua_resp = toggle_switch(
                        ui,
                        theme,
                        t!("settings.unattended.master"),
                        ua,
                        None,
                    )
                    .on_hover_text(t!("settings.unattended.master_hint"));
                    if ua_resp.clicked() {
                        self.unattended_enabled = !ua;
                        // M8-T037: 跟随打开/关闭（内存即时；保存时统一落盘）。
                        self.unattended_autostart = !ua;
                        self.unattended_auto_server = !ua;
                        // 子开关跟随开启 → 默认受控立即生效（启动服务端监听）。
                        if !ua {
                            self.apply_default_controlled();
                        }
                    }
                    // 开机自启（可独立翻转，D6；无人值守开/关时不跟随锁定）
                    let asb = self.unattended_autostart;
                    let asb_resp =
                        toggle_switch(ui, theme, t!("settings.unattended.autostart"), asb, None)
                            .on_hover_text(t!("settings.unattended.autostart_hint"));
                    if asb_resp.clicked() {
                        self.unattended_autostart = !asb;
                    }
                    // 默认受控（原「启动时自动开启服务端」，M8-T037 改名）——
                    // 开启立即联动 Dashboard「允许受控」；关闭仅下次启动不自动监听。
                    let ass = self.unattended_auto_server;
                    let ass_resp = toggle_switch(
                        ui,
                        theme,
                        t!("settings.unattended.default_controlled"),
                        ass,
                        None,
                    )
                    .on_hover_text(t!("settings.unattended.default_controlled_hint"));
                    if ass_resp.clicked() {
                        self.unattended_auto_server = !ass;
                        // 开启 → 立即联动 Dashboard「允许受控」启动监听。
                        if !ass {
                            self.apply_default_controlled();
                        }
                    }
                });
                // 自启注册状态（以系统实际状态为准，UA-BOOT-002）
                let installed = kirin_desk_utils::autostart::is_installed();
                badge(
                    ui,
                    theme,
                    if installed {
                        t!("settings.unattended.registered")
                    } else {
                        t!("settings.unattended.not_registered")
                    },
                    if installed {
                        BadgeKind::Success
                    } else {
                        BadgeKind::Neutral
                    },
                );
                ui.add_space(4.0);
                // 安全提示（UA-SEC-003 / UA-ACCEPT-002）
                if self.unattended_enabled {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("settings.unattended.security_hint"))
                                .size(theme.small_size)
                                .color(theme.danger),
                        )
                        .selectable(false),
                    );
                }
            });

            egui::CollapsingHeader::new(t!("settings.identity.title")).show(ui, |ui| {
                labeled_input(
                    ui,
                    theme,
                    t!("settings.identity.device_id"),
                    &mut self.device_id,
                    // M8-T031: 留空保存 = 自动（系统盘硬盘 UUID）。
                    t!("settings.identity.auto_hint"),
                    Validity::None,
                    None,
                    true,
                );
                // M8-T035: 昵称/挑战码/端口已迁至 Dashboard「服务端设置」
                // （下次启动服务端生效；页面内小保存按钮即时落盘）。
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.identity.moved_hint"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            });

            egui::CollapsingHeader::new(t!("settings.whitelist.title")).show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.whitelist.allowed_domains"))
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
                        egui::RichText::new(t!("settings.whitelist.domains_hint"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.whitelist.domain_secure"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.whitelist.non_whitelisted_dialog"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.whitelist.headless_hint"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );

                // M8-T027 (UI-IDWL-001): 设备 ID 白名单文本框（逗号/换行分隔，
                // 保存写 `[network].allowed_ids` 永久条目，重启持久化）。
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.whitelist.allowed_ids"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                egui::TextEdit::multiline(&mut self.allowed_ids)
                    .desired_rows(2)
                    .desired_width(ui.available_width())
                    .show(ui);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.whitelist.ids_hint"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                // M8-T027 (UI-IDWL-002): ID 白名单条目列表（永久/过期标记 +
                // 逐条删除；过期条目自动失效但仍展示直至被删/清理）。
                ui.add_space(6.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.whitelist.entries_label"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                let mut pending_remove: Option<String> = None;
                let idwl_now = chrono::Utc::now();
                for entry in &self.id_whitelist_entries {
                    let expired = !entry.is_active(idwl_now);
                    let expiry_label = match &entry.expiry {
                        Some(t) if expired => tf!(
                            "settings.whitelist.expired_fmt",
                            t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                        ),
                        Some(t) => tf!(
                            "settings.whitelist.expires_fmt",
                            t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                        ),
                        None => t!("settings.whitelist.permanent").to_string(),
                    };
                    ui.horizontal(|ui| {
                        ui.label(format!("  {}", entry.device_id));
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(expiry_label)
                                    .size(theme.small_size)
                                    .color(if expired { theme.danger } else { theme.fg_weak }),
                            )
                            .selectable(false),
                        );
                        if ui.small_button(t!("settings.whitelist.remove")).clicked() {
                            pending_remove = Some(entry.device_id.clone());
                        }
                    });
                }
                if let Some(device_id) = pending_remove {
                    self.remove_id_whitelist_entry(&device_id);
                }
            });

            egui::CollapsingHeader::new(t!("settings.logging.title")).show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.logging.config_hint"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            });

            // M15-T008: 外观组——明亮/深色/跟随系统，选择即时生效（无需重启）。
            egui::CollapsingHeader::new(t!("settings.appearance.title"))
                .default_open(true)
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("settings.appearance.theme"))
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
                        &[
                            t!("settings.appearance.light"),
                            t!("settings.appearance.dark"),
                            t!("settings.appearance.system"),
                        ],
                        &mut mode,
                    ) {
                        self.theme_mode = match mode {
                            0 => ThemeMode::Light,
                            1 => ThemeMode::Dark,
                            _ => ThemeMode::System,
                        };
                        // 即时生效：update() 帧首 apply_theme 检测明暗变化即全量重设。
                    }
                    // M8-T038: 语言三段（System / 中文 / English）——选项以自身语言
                    // 显示（语言选择器惯例）；选中即即时切换（与 Theme 同款交互）。
                    ui.add_space(6.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("settings.language"))
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                    let mut lang_mode = match self.ui_language.as_str() {
                        "zh" => 1,
                        "en" => 2,
                        _ => 0, // "system" 及未知 → 0
                    };
                    if segmented_control(
                        ui,
                        theme,
                        &["System", "中文", "English"],
                        &mut lang_mode,
                    ) {
                        self.ui_language = match lang_mode {
                            1 => "zh".into(),
                            2 => "en".into(),
                            _ => "system".into(),
                        };
                        i18n::set_lang_code(&self.ui_language); // 即时生效，无需重启
                    }
                });

            // M14-T005: 自动更新分组——检查 / 下载进度 / 安装重启。
            // 状态由后台线程写入 `update_state()`，本面板每帧读取。
            egui::CollapsingHeader::new(t!("settings.update.title"))
                .default_open(true)
                .show(ui, |ui| {
                    let s = update_state();
                    let guard = s.lock().unwrap();

                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(t!("settings.update.current_version"))
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
                            ui.label(t!("settings.update.checking"));
                        });
                    } else {
                        ui.add_space(4.0);
                        if action_button(
                            ui,
                            theme,
                            ButtonKind::Secondary,
                            t!("settings.update.check_button"),
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
                                        egui::RichText::new(t!("settings.update.new_version"))
                                            .strong(),
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
                                    t!("settings.update.download_button"),
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
                                    t!("settings.update.install_restart"),
                                    ButtonState::Enabled,
                                )
                                .clicked()
                                {
                                    let path = guard.downloaded.clone().unwrap();
                                    drop(guard);
                                    match install_update(&path) {
                                        // 替换脚本已在后台启动：立即退出让出 exe 文件锁。
                                        Ok(InstallOutcome::Restarting) => std::process::exit(0),
                                        // macOS/Linux：安装包已落地，提示手动打开方式。
                                        Ok(InstallOutcome::ManualInstall { artifact, hint }) => {
                                            let mut s2 = s.lock().unwrap();
                                            s2.downloaded = None;
                                            s2.info = Some(tf!(
                                                "settings.update.downloaded_fmt",
                                                artifact.display(),
                                                hint
                                            ));
                                        }
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
                            ui.label(t!("settings.update.up_to_date"));
                        }
                        Some(UpdateStatus::Error(_)) | None => {}
                    }

                    if let Some(e) = &guard.error {
                        ui.add_space(4.0);
                        badge(
                            ui,
                            theme,
                            &tf!("settings.update.error_fmt", e),
                            BadgeKind::Danger,
                        );
                    }
                    if let Some(m) = &guard.info {
                        ui.add_space(4.0);
                        badge(ui, theme, m, BadgeKind::Success);
                    }
                });

            egui::CollapsingHeader::new(t!("settings.about.title")).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(egui::RichText::new("🐉 KirinDesk").strong())
                            .selectable(false),
                    );
                    badge(ui, theme, kirin_desk_updater::APP_VERSION, BadgeKind::Neutral);
                });
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("settings.about.tagline"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            });

            ui.separator();
            ui.horizontal(|ui| {
                if action_button(ui, theme, ButtonKind::Primary, t!("settings.save"), ButtonState::Enabled)
                    .clicked()
                {
                    // M8-T027 (UI-IDWL-001): 改为基于**现有配置**修改而非重建——
                    // 否则 GUI 保存会清空 CLI 添加的域名/ID 过期条目（`whitelist`/
                    // `id_whitelist`）与 tunnel 服务端参数（M8-T026）。
                    let mut cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
                    // UI-IDWL-004: 保存时对**新增**的永久 ID 条目写审计
                    // `WhitelistIdAdded`（旧缓存含保存前条目）。
                    let prev_ids: std::collections::HashSet<String> = self
                        .id_whitelist_entries
                        .iter()
                        .map(|e| e.device_id.clone())
                        .collect();
                    cfg.device.id = self.device_id.clone();
                    cfg.device.nickname = self.nickname.clone();
                    cfg.device.challenge_code = self.challenge_code.clone();
                    // M9-DNS022: `[godaddy]` 凭据与 `[dns] provider` 不再由
                    // Settings 保存——统一在 Domain 页「服务商」卡维护（即时落盘）；
                    // 此处不写，避免旧值覆盖 Domain 页已保存的新值。
                    if let Ok(p) = self.listen_port.parse::<u16>() {
                        cfg.network.port = p;
                    }
                    cfg.network.allowed_domains = self
                        .allowed_domains
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    // M8-T027 (UI-IDWL-001): ID 白名单文本框（逗号/换行分隔）→
                    // `[network].allowed_ids` 永久条目（即时生效：accept 循环
                    // 逐连接读取配置快照）。
                    let new_ids: Vec<String> = self
                        .allowed_ids
                        .split(|c| c == ',' || c == '\n' || c == '\r')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    cfg.network.allowed_ids = new_ids.clone();
                    cfg.network.ip_mode_allowed = self.ip_mode_allowed;
                    cfg.network.temp_mode = self.temp_mode;
                    // M15-T008: 主题模式持久化（`[ui] theme`，默认 light）
                    cfg.ui.theme = self.theme_mode.as_str().to_string();
                    // M8-T038: 语言选择持久化（`[ui] language`，默认 system）
                    cfg.ui.language = self.ui_language.clone();
                    // M13-T005 (UA-CFG-002): 无人值守配置持久化
                    cfg.unattended.enabled = self.unattended_enabled;
                    cfg.unattended.auto_start_server = self.unattended_auto_server;
                    cfg.unattended.auto_start_on_boot = self.unattended_autostart;
                    // M8-T039: Tunnel 字段不再归 Settings 保存——迁移至 Tunnel 页
                    // 独立「保存」（tunnel_save，不写 enabled / auto_start）。
                    match cfg.save() {
                        Ok(()) => {
                            // UI-IDWL-004: 审计新增永久 ID 条目（附 device_id）。
                            if let Ok(mut a) = kirin_desk_utils::audit::AuditLogger::open_default()
                            {
                                for id in new_ids.iter().filter(|id| !prev_ids.contains(*id)) {
                                    let _ = a.record(
                                        kirin_desk_utils::audit::AuditEvent::WhitelistIdAdded,
                                        &format!("device={} expiry=permanent", id),
                                    );
                                }
                            }
                            // 刷新条目列表缓存（永久 + 带过期条目）。
                            let mut entries: Vec<kirin_desk_utils::config::IdWhitelistEntry> =
                                new_ids
                                    .iter()
                                    .map(|id| {
                                        kirin_desk_utils::config::IdWhitelistEntry::new(id, None)
                                    })
                                    .collect();
                            for e in &cfg.network.id_whitelist {
                                if !entries.iter().any(|x| x.device_id == e.device_id) {
                                    entries.push(e.clone());
                                }
                            }
                            self.id_whitelist_entries = entries;
                            self.settings_status = t!("settings.status.saved").to_string();
                            if let Ok(p) = self.listen_port.parse::<u16>() {
                                self.connect_port = p.to_string();
                            }
                            // M13-T005 (UA-BOOT-001/002): 自启开关与系统状态同步——
                            // 开启则注册用户级自启，关闭则移除（幂等）。
                            if self.unattended_autostart {
                                if let Err(e) = kirin_desk_utils::autostart::install() {
                                    self.settings_status =
                                        tf!("settings.status.autostart_failed", e);
                                }
                            } else {
                                let _ = kirin_desk_utils::autostart::uninstall();
                            }
                        }
                        Err(e) => {
                            self.settings_status = tf!("settings.status.save_failed", e)
                        }
                    }
                }
                // M15-T008: 保存反馈改横幅 Badge（success/danger）
                if !self.settings_status.is_empty() {
                    // M8-T038: 成功文案走 t!()，此处与同键结果比较判定语义色。
                    let kind = if self.settings_status == t!("settings.status.saved") {
                        BadgeKind::Success
                    } else {
                        BadgeKind::Danger
                    };
                    badge(ui, theme, &self.settings_status, kind);
                }
            });
        });
    }

    /// M8-T039 §3.1/§3.4：内网穿透独立页（通用 TCP 反向代理）。
    fn show_tunnel(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        ui.heading(t!("tunnel.title"));
        ui.separator();
        egui::ScrollArea::vertical().show(ui, |ui| {
            // ── 定位说明（§3.4.1 文案，tunnel.desc）──
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("tunnel.desc"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            ui.add_space(4.0);
            // ── [开启] [Client] [Server]（迁移 Settings 组 8867-8890 逻辑）──
            // 开启按钮仅改内存 tunnel_enabled；模式按钮写 tunnel_mode。
            ui.horizontal(|ui| {
                let on = self.tunnel_enabled;
                let resp = state_button(ui, theme, t!("tunnel.enable"), on).on_hover_text(if on {
                    t!("tunnel.enable_hint_on")
                } else {
                    t!("tunnel.enable_hint_off")
                });
                if resp.clicked() {
                    self.tunnel_enabled = !on;
                }
                let mut set_mode: Option<String> = None;
                for (label, is_sel, mode) in [
                    ("Client", self.tunnel_mode != "server", "client"),
                    ("Server", self.tunnel_mode == "server", "server"),
                ] {
                    let r = state_button(ui, theme, label, is_sel);
                    if r.clicked() {
                        set_mode = Some(mode.to_string());
                    }
                }
                if let Some(m) = set_mode {
                    self.tunnel_mode = m;
                }
            });
            ui.add_space(4.0);
            // ── 模式条件区块 ──
            if self.tunnel_mode == "client" {
                // Client 区块（全量，本任务实现）：Server Address / Token(👁) /
                // Proxies 多行 + 格式提示（迁移 8904-8934 区域逻辑，键迁移改名）。
                // Token 行保持现状（密文 + 👁），无 ✏️📋（P4 不得加）。
                ui.heading(t!("tunnel.client.title"));
                labeled_input(
                    ui,
                    theme,
                    t!("tunnel.server_address"),
                    &mut self.tunnel_server_addr,
                    "relay.example.com:7000",
                    Validity::None,
                    None,
                    true,
                );
                labeled_input(
                    ui,
                    theme,
                    t!("tunnel.token"),
                    &mut self.tunnel_token,
                    "required",
                    Validity::None,
                    Some(&mut self.show_secret_tunnel_token),
                    false,
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("tunnel.proxies_label"))
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
                        egui::RichText::new(t!("tunnel.proxies_format"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            } else {
                // Server 区块（M8-T039 P4：配置输入 + 校验；Token 行含 ✏️📋）。
                ui.heading(t!("tunnel.server.title"));
                let addrs_ok = self.tunnel_addrs_valid();
                let port_ok = self.tunnel_port_valid();
                let range_ok = self.tunnel_range_valid();
                labeled_input(
                    ui,
                    theme,
                    t!("tunnel.server.bind_addrs"),
                    &mut self.tunnel_bind_addrs,
                    "0.0.0.0,::",
                    if addrs_ok {
                        Validity::None
                    } else {
                        Validity::Invalid(t!("tunnel.server.bind_addrs_invalid"))
                    },
                    None,
                    true,
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("tunnel.server.bind_addrs_hint"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                // §3.2.2：只配 `::` 单地址 → 仅收 IPv6，弱色提示补 0.0.0.0。
                if self.tunnel_bind_addrs.contains("::")
                    && !self.tunnel_bind_addrs.contains("0.0.0.0")
                {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(t!("tunnel.server.v6_only_hint"))
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                        )
                        .selectable(false),
                    );
                }
                labeled_input(
                    ui,
                    theme,
                    t!("tunnel.server.bind_port"),
                    &mut self.tunnel_bind_port,
                    "7000",
                    if port_ok {
                        Validity::None
                    } else {
                        Validity::Invalid(t!("tunnel.server.port_invalid"))
                    },
                    None,
                    true,
                );
                labeled_input(
                    ui,
                    theme,
                    t!("tunnel.server.port_range"),
                    &mut self.tunnel_port_range,
                    "60000-61000",
                    if range_ok {
                        Validity::None
                    } else {
                        Validity::Invalid(t!("tunnel.server.port_range_invalid"))
                    },
                    None,
                    true,
                );
                // ── Token 行（Server 专属：👁 + ✏️ + 📋）──
                // labeled_input 为 vertical 布局（标签上置 + 👁 同行），✏️📋
                // 与输入行同行排布（horizontal 包裹，尺寸对齐 copy_button）。
                ui.horizontal(|ui| {
                    labeled_input(
                        ui,
                        theme,
                        t!("tunnel.token"),
                        &mut self.tunnel_token,
                        "required",
                        Validity::None,
                        Some(&mut self.show_secret_tunnel_token),
                        false,
                    );
                    ui.vertical(|ui| {
                        if ui
                            .add(
                                egui::Button::new("✏️")
                                    .min_size(egui::vec2(26.0, 20.0)),
                            )
                            .on_hover_text(t!("tunnel.server.gen_token_hint"))
                            .clicked()
                        {
                            self.tunnel_gen_token();
                        }
                        // 📋 复用 copy_button（空 token 内建禁用；✓ 瞬态反馈）。
                        let _ = copy_button(ui, theme, &self.tunnel_token);
                    });
                });
            }
            ui.separator();
            // ── 保存（独立于 Settings 全局 Save）──
            // 启用条件挂 tunnel_save_allowed()（P3 占位恒 true；P4 挂校验结果）。
            if self.tunnel_save_allowed()
                && action_button(
                    ui,
                    theme,
                    ButtonKind::Primary,
                    t!("tunnel.save"),
                    ButtonState::Enabled,
                )
                .clicked()
            {
                self.tunnel_save();
            }
            if !self.tunnel_notice.is_empty() {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&self.tunnel_notice)
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
            }
            // ── 运行控制区（M8-T039 P5：▶ 启动 / ■ 停止 + 状态行）──
            // 按钮文案随实际运行态切换（starting 期间也显示「■ 停止」——可点即停止）。
            ui.horizontal(|ui| {
                // 先取运行态快照（守卫立即释放——stop/start 内部再锁同一互斥量，
                // std Mutex 不可重入，跨调用持锁即死锁）。
                let (running, status, has_error) = {
                    let st = tunnel_runtime_state().lock().unwrap();
                    let status = tunnel_status_text(&st, &self.tunnel_mode);
                    // 状态行跨帧常驻（TunnelRuntimeState 静态槽，非一次性 toast）；
                    // 失败原因截断对齐 Dashboard start_failed 先例（lib.rs:5933-5938）。
                    let status = if status.chars().count() > 56 {
                        let t: String = status.chars().take(55).collect();
                        format!("{t}…")
                    } else {
                        status
                    };
                    (st.running || st.starting, status, st.error.is_some())
                };
                let label = if running {
                    t!("tunnel.run.stop")
                } else {
                    t!("tunnel.run.start")
                };
                let kind = if running {
                    ButtonKind::Danger
                } else {
                    ButtonKind::Primary
                };
                if action_button(ui, theme, kind, label, ButtonState::Enabled).clicked() {
                    if running {
                        self.tunnel_stop();
                    } else {
                        self.tunnel_start();
                    }
                }
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(status)
                            .size(theme.small_size)
                            .color(if has_error { theme.danger } else { theme.fg_weak }),
                    )
                    .selectable(false),
                );
            });
        });
    }

    /// M8-T039：Tunnel 页保存（§3.4.3）——只落盘配置字段，不写 enabled / auto_start。
    fn tunnel_save(&mut self) {
        if let Ok(mut cfg) = kirin_desk_utils::config::Config::load() {
            cfg.tunnel.mode = self.tunnel_mode.clone();
            cfg.tunnel.server_addr = self.tunnel_server_addr.clone();
            cfg.tunnel.token = self.tunnel_token.clone();
            cfg.tunnel.bind_addrs = self.tunnel_bind_addrs.trim().to_string();
            cfg.tunnel.bind_port = self.tunnel_bind_port.trim().parse().unwrap_or(7000);
            cfg.tunnel.port_range = self.tunnel_port_range.trim().to_string();
            cfg.tunnel.proxies =
                kirin_desk_utils::config::TunnelConfig::parse_proxy_lines(&self.tunnel_proxies);
            match cfg.save() {
                Ok(()) => self.tunnel_notice = t!("tunnel.saved").to_string(),
                Err(e) => self.tunnel_notice = tf!("tunnel.save_failed", e),
            }
        }
    }

    /// M8-T039 P4：保存允许判定——Server 模式且 Server 区块输入非法 → 禁用保存。
    /// 校验不阻断保存路径之外的行为（模式切换 / 表单编辑 / ✏️ / 📋 始终可用）。
    fn tunnel_save_allowed(&self) -> bool {
        self.tunnel_server_form_valid()
    }

    /// M8-T039 P4：Server 区块表单整体合法（渲染红边与保存允许判定同源，
    /// 防双写漂移；Client 模式无 Server 区块校验）。
    fn tunnel_server_form_valid(&self) -> bool {
        if self.tunnel_mode != "server" {
            return true;
        }
        self.tunnel_addrs_valid() && self.tunnel_port_valid() && self.tunnel_range_valid()
    }

    /// M8-T039 P4：监听地址合法——空（含纯空白）= 合法（落盘空串 → relay
    /// 回退默认双栈，P7）；非空 → `parse_bind_addr_list` 各分支失败（非 IP /
    /// 空段 / 域名）→ 非法。端口不参与地址段校验（由 `tunnel_port_valid` 独立提示）。
    fn tunnel_addrs_valid(&self) -> bool {
        let s = self.tunnel_bind_addrs.trim();
        if s.is_empty() {
            return true;
        }
        kirin_desk_utils::config::parse_bind_addr_list(s, 7000).is_ok()
    }

    /// M8-T039 P4：端口合法（1-65535，对齐 Dashboard 端口校验先例）。
    fn tunnel_port_valid(&self) -> bool {
        self.tunnel_bind_port
            .trim()
            .parse::<u16>()
            .map(|p| (1..=65535).contains(&p))
            .unwrap_or(false)
    }

    /// M8-T039 P4：端口范围合法（"start-end"，复用 cli.rs
    /// `parse_tunnel_port_range`；空串合法 = remote_port 显式必填语义）。
    fn tunnel_range_valid(&self) -> bool {
        let s = self.tunnel_port_range.trim();
        s.is_empty() || crate::cli::parse_tunnel_port_range(s).is_some()
    }

    /// M8-T039 §3.3：✏️ 生成随机高熵 Token（32 字节 → 64 hex）并**立即落盘**
    /// （覆盖旧 token，生成即生效；落盘失败仅提示，输入框值不回滚）。
    fn tunnel_gen_token(&mut self) {
        let token = kirin_desk_utils::config::generate_random_token();
        self.tunnel_token = token.clone();
        if let Ok(mut cfg) = kirin_desk_utils::config::Config::load() {
            cfg.tunnel.token = token;
            match cfg.save() {
                Ok(()) => self.tunnel_notice = t!("tunnel.server.token_saved").to_string(),
                Err(e) => self.tunnel_notice = tf!("tunnel.save_failed", e),
            }
        } else {
            self.tunnel_notice = t!("tunnel.server.token_save_failed").to_string();
        }
    }

    /// M8-T039 §3.4.3: 启动隧道（GUI 唯一运行控制入口）。
    /// 校验（fail-closed）→ 自动落盘当前表单 → auto_start=true 落盘 → 后台运行。
    fn tunnel_start(&mut self) {
        // ── 1. 校验（对齐 cli.rs cmd_tunnel_serve 4860-4871 / cmd_tunnel_start）──
        let server_mode = self.tunnel_mode == "server";
        if server_mode {
            if self.tunnel_token.trim().is_empty() {
                // TNL-SEC-008 fail-closed：空 token 拒绝启动。
                self.tunnel_set_error(t!("tunnel.run.err_token_empty"));
                return;
            }
            if self.tunnel_token.trim().len() < 16 {
                // TNL-SEC-009：短 token 警告（不阻断，提示后继续）。
                tracing::warn!(
                    "tunnel: short token ({}) — use >=32 bytes high-entropy",
                    self.tunnel_token.trim().len()
                );
            }
        } else if self.tunnel_server_addr.trim().is_empty() {
            self.tunnel_set_error(t!("tunnel.run.err_server_addr_empty"));
            return;
        }
        // ── 2. 自动落盘当前表单（校验失败已拦截——避免启动用旧配置）──
        self.tunnel_save(); // P3 方法（不写 enabled / auto_start）
        // ── 3. auto_start = true 落盘（启动失败不回位，§3.4.3；失败仅影响
        //    持久化，运行照常）──
        if let Ok(mut cfg) = kirin_desk_utils::config::Config::load() {
            cfg.tunnel.auto_start = true;
            let _ = cfg.save();
        }
        self.tunnel_auto_start = true;
        // ── 4. 状态置 starting ──
        {
            let mut st = tunnel_runtime_state().lock().unwrap();
            st.starting = true;
            st.running = false;
            st.error = None;
        }
        // ── 5. 组装 + 后台运行（std::thread + 自建 tokio runtime，对齐
        //    start_server 先例 lib.rs:6546-6548）──
        let mode = self.tunnel_mode.clone();
        let token = self.tunnel_token.clone();
        let server_addr = self.tunnel_server_addr.clone();
        let proxies = self.tunnel_proxies.clone();
        let bind_addrs = self.tunnel_bind_addrs.clone();
        let bind_port = self.tunnel_bind_port.trim().parse().unwrap_or(7000);
        let port_range = self.tunnel_port_range.clone();
        let hostname = kirin_desk_utils::config::Config::load()
            .map(|c| c.device.id.clone())
            .unwrap_or_else(|_| "kirindesk".to_string());
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("tunnel runtime");
            let result: Result<(), String> = rt.block_on(async {
                if mode == "server" {
                    let mut srv_cfg = kirin_desk_relay::server::TunnelServerConfig {
                        bind_port,
                        token: token.clone(),
                        port_range: crate::cli::parse_tunnel_port_range(&port_range),
                        // 心跳/连接池等走 relay 默认值（对齐 cmd_tunnel_serve）。
                        ..Default::default()
                    };
                    if !bind_addrs.trim().is_empty() {
                        // P4 表单已校验，此处仍 fail-closed：解析失败即启动失败。
                        srv_cfg.bind_addrs = kirin_desk_utils::config::parse_bind_addr_list(
                            &bind_addrs,
                            bind_port,
                        )?;
                    }
                    let server = kirin_desk_relay::server::TunnelServer::bind(srv_cfg)
                        .await
                        .map_err(|e| e.to_string())?;
                    let port = server.port();
                    let addrs = bind_addrs.trim().to_string();
                    {
                        let mut st = tunnel_runtime_state().lock().unwrap();
                        st.running = true;
                        st.starting = false;
                        st.port = port;
                        st.addrs = addrs;
                    }
                    let handle = server.shutdown_handle();
                    *tunnel_run_handles().lock().unwrap() = Some(TunnelRunHandles {
                        client: None,
                        server: Some(handle),
                    });
                    server.run().await.map_err(|e| e.to_string())
                } else {
                    // client 组装对齐 cli.rs cmd_tunnel_start（4805-4832）：
                    // TunnelClientConfig + parse_proxy_lines + server_addr/token。
                    let proxies: Vec<kirin_desk_relay::client::ProxySpec> =
                        kirin_desk_utils::config::TunnelConfig::parse_proxy_lines(&proxies)
                            .into_iter()
                            .map(|p| kirin_desk_relay::client::ProxySpec {
                                name: p.name,
                                local_addr: p.local_addr,
                                local_port: p.local_port,
                                remote_port: p.remote_port,
                            })
                            .collect();
                    let client_cfg = kirin_desk_relay::client::TunnelClientConfig {
                        server_addr,
                        token,
                        hostname,
                        heartbeat_interval: std::time::Duration::from_secs(10),
                        heartbeat_timeout: std::time::Duration::from_secs(30),
                        connect_timeout: std::time::Duration::from_secs(5),
                        local_dial_timeout: std::time::Duration::from_secs(2),
                        backoff_base: std::time::Duration::from_secs(1),
                        backoff_max: std::time::Duration::from_secs(60),
                        proxies,
                    };
                    let client = kirin_desk_relay::client::TunnelClient::new(client_cfg);
                    let arc = std::sync::Arc::new(client);
                    *tunnel_run_handles().lock().unwrap() = Some(TunnelRunHandles {
                        client: Some(arc.clone()),
                        server: None,
                    });
                    {
                        let mut st = tunnel_runtime_state().lock().unwrap();
                        st.running = true;
                        st.starting = false;
                    }
                    arc.run().await.map_err(|e| e.to_string())
                }
            });
            match result {
                Ok(()) => {} // 优雅退出（stop）——状态已由 stop 路径复位
                Err(e) => {
                    // 启动失败 / 运行判死退出：intent 保留（auto_start 不回位，
                    // §3.4.3 —— 状态行显示原因，下次启动自动重试）。
                    let mut st = tunnel_runtime_state().lock().unwrap();
                    st.starting = false;
                    st.running = false;
                    st.error = Some(e);
                }
            }
            *tunnel_run_handles().lock().unwrap() = None;
        });
    }

    /// M8-T039 §3.4.3: 停止隧道（auto_start=false 落盘 → 优雅关闭 → 线程回收）。
    /// 幂等：未运行点「停止」→ 仅落盘 false + 复位状态（无句柄即跳过关闭调用）。
    fn tunnel_stop(&mut self) {
        self.tunnel_auto_start = false;
        if let Ok(mut cfg) = kirin_desk_utils::config::Config::load() {
            cfg.tunnel.auto_start = false;
            let _ = cfg.save();
        }
        if let Some(h) = tunnel_run_handles().lock().unwrap().take() {
            if let Some(c) = &h.client {
                c.stop(); // 优雅 Logout（client.rs:169）
            }
            if let Some(s) = &h.server {
                s.shutdown(); // 广播关闭（server.rs:225 起）
            }
        }
        {
            let mut st = tunnel_runtime_state().lock().unwrap();
            st.starting = false;
            st.running = false;
            st.error = None;
        }
    }

    /// M8-T039 P5：隧道运行态错误写入（状态行跨帧展示；auto_start 不回位
    /// 的「保留 intent」语义由调用路径保证——校验失败先于落盘，不写 true）。
    fn tunnel_set_error(&self, msg: &str) {
        let mut st = tunnel_runtime_state().lock().unwrap();
        st.starting = false;
        st.running = false;
        st.error = Some(msg.to_string());
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
