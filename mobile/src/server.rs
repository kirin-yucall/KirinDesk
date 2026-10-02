//!
//! # 定位
//!
//! mobile crate 既有路径是安卓**控制端**（[`orchestration`]：连接/TOFU/历史/
//! 输入）。本模块是其镜像的另一半：手机作为**被控端**——MediaProjection
//! 屏幕共享（Kotlin 波 2）把 RGBA 帧经 [`feed_frame`] 喂入，本模块完成
//! 「软编（libx264 经 FFmpeg，红线①）→ 编码窗口 → 每观众分发（SecureChannel
//! `ChannelTag::Input` 分支按红线⑥反序列化 `injector::InputEvent`（与桌面被控端
//! 分发任务同型），纯转换为「归一化坐标 + 编码分辨率基数」上抛参数后经 JNI 上抛
//!
//! **不复制任何逻辑**——握手走 core 库层入口（`server_read_init` /
//! `verify_server_init` / `server_handshake_respond_generic` /
//! `send_handshake_reject`，与桌面 GUI 被控端同一校验链，红线②④）；ID 模式
//! 注册走 `relay::id_client::IdClient`（注册/心跳/中继牵线全在 relay 库层，
//! 本模块只做配置装配 + 隧道流回调接线）；编码走 `media::WindowPipeline`
//! `rate_ladder` 按输出分辨率取档在 SW 编码器 open 时自动应用）。
//!
//! # 握手语义口径（已定案）
//!
//!   `port = 0` = 系统临时端口（宿主 e2e 测试口径）。
//! - **昵称门**：握手 `init.client_id` 必须 = 本机昵称（字面比对、大小写
//!   （`client_domain` 非空）必查；ID 模式客户端（`client_domain` 空）跳过
//!   昵称，对齐桌面 GUI `expected_nick_for_verify`）。
//! - **挑战码**：配置值校验（core 常量时间比较）。**缺失配置 fail-closed**：
//!   未配挑战码的监听不静默放行任何连接（`CREDENTIALS_REQUIRED` 结构化
//!   拒绝，S-01a 零凭据口径）。
//!   （`send_handshake_reject`，控制端可读文案）；错昵称 → **裸 close
//!   （early eof 形态）**——昵称是字面凭据，按防枚举口径不下发细粒度失配
//!   损坏等异常流量 → 各自形态（结构化 `version_mismatch` / 静默 close）。
//!
//!
//! 单编码 + 每观众分发（ui `server_media.rs` 多观众广播的移动版）：
//!
//! - **帧泵**（专用 std 线程）：帧喂入槽（最新帧替换，积压丢旧保新）→
//!   `WindowPipeline`（low_latency：逐帧关窗即编，长 GOP 不每窗 IDR）→
//!   `EncodedWindow` 广播。首观众拉起 / 全退 5s 宽限停（[`CAPTURE_GRACE`]）；
//!   新观众接入使宽限失效并重启泵（新编码器首窗天然 IDR，后到观众可解码）。
//! - **每观众** 8 深有界广播缓冲（[`VIEWER_BUFFER`]）：满 → 非关键帧丢弃并
//!   置慢标记（保新，跳过至下一可解码帧）；关键帧限时（200ms）补投，超时
//! - **线上格式** = 既有 `EncodedWindow` bincode 大帧经 `send_big_packet`
//!   （与桌面被控端同口径，红线⑥禁自创）。
//!
//! # ID 模式（relay 注册）
//!
//! `relay_server_addr` + `relay_token` 双非空 ⇒ 启用：装配
//! 端口）+ `IdClient::run()` 注册接线（token 挑战-响应认证
//! TNL-SEC-006~008 在 relay 库层）；中继牵线到达的隧道流经与本地监听
//! **同一** [`handshake_incoming`] 入口（ID-013 访问控制零降级：昵称/挑战码
//! 门同样生效）。**`relay_server_pubkey` 缺失 fail-closed 拒注册**
//! （ID-SEC-001 口径：控制端凭该公钥验 DeviceInfo 签名，缺则 ID 模式
//! 部署不完整——注册前置拒绝）。
//!
//! # 线程模型
//!
//! 所有 tokio 任务挂**全局 runtime**（[`crate::runtime`]，`Runtime::spawn`
//! 显式句柄——JNI 线程无 async 上下文）；帧泵是 std 线程（FFmpeg 阻塞
//! 同步编码，同桌面「编码/解码专用线程」拓扑）。
//!
//! # 音频
//!
//! 本波不做（遗留列清，回报 PM）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use kirin_desk_core::connection::file_transfer::{
    FileTransferFrame, DEFAULT_MAX_FILE_SIZE,
};
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    handshake_error_reject_code, negotiate_codec_by_server_priority,
    reject_if_client_too_new, server_handshake_respond_generic, server_read_init,
    send_handshake_reject, verify_server_init_with_answer, REJECT_CODE_CHALLENGE_MISMATCH,
    REJECT_CODE_CREDENTIALS_REQUIRED, SecureChannel,
};
// 与桌面被控端分发任务 ui/src/lib.rs 消费同型；控制端 mobile
// orchestration::build_input_event 序列化同型——双向对称）。
use kirin_desk_input::injector::{InputEvent as WireInputEvent, InputKind};
use kirin_desk_media::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use kirin_desk_media::encoder::{Codec, VideoEncoderPipeline};
use kirin_desk_media::transport::{
    bind_dual_stack_tcp_listener, ChannelTag, SecureChannelReceiver, SecureChannelSender,
};
use kirin_desk_media::{EncodedWindow, RawFrame, WindowConfig, WindowPipeline};
use kirin_desk_relay::id_client::{
    IdClient, IdClientConfig, DEFAULT_BACKOFF_BASE, DEFAULT_BACKOFF_MAX, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT,
};
use kirin_desk_utils::config::DEFAULT_NETWORK_PORT;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

pub const DEFAULT_LISTEN_PORT: u16 = DEFAULT_NETWORK_PORT;

pub const VIEWER_BUFFER: usize = 8;

/// 观众全退后的帧泵宽限：宽限期内新观众接入则取消停止，仍为 0 则停泵
pub const CAPTURE_GRACE: Duration = Duration::from_secs(5);

const KEY_DELIVER_TIMEOUT: Duration = Duration::from_millis(200);

/// 帧泵喂入槽轮询上限（stop/宽限标志的检查节拍）。
const PUMP_POLL_INTERVAL: Duration = Duration::from_millis(50);

// ════════════════════════════════════════════════════════════════
// 配置
// ════════════════════════════════════════════════════════════════

/// 被控端服务端配置（JNI `nativeServerStart` 参数规整后的纯数据）。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// 端口，宿主 e2e 测试口径）。
    pub port: u16,
    /// 非空；trim 后使用，字面比对大小写敏感）。
    pub nickname: String,
    /// 挑战码（配置值；**空 = 未配置 → fail-closed**：监听仍起，但每个
    /// 连接收 `CREDENTIALS_REQUIRED` 结构化拒绝，不静默放行）。
    pub challenge: String,
    /// relay 服务器地址 `host:port`（与 token 双非空 ⇒ 启用 ID 模式）。
    pub relay_server_addr: String,
    /// relay token（TNL-SEC-001 认证）。
    pub relay_token: String,
    /// relay 服务器 Ed25519 公钥（base64；**ID 模式下缺失 → fail-closed
    /// 拒注册**，ID-SEC-001 口径）。
    pub relay_server_pubkey: String,
    /// 桌面 `[tunnel] device_id`/`[device] id` 单一来源同口径）。
    pub device_id: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_LISTEN_PORT,
            nickname: String::new(),
            challenge: String::new(),
            relay_server_addr: String::new(),
            relay_token: String::new(),
            relay_server_pubkey: String::new(),
            device_id: String::new(),
        }
    }
}

impl ServerConfig {
    /// 配置校验（纯函数，`start` 前置；fail-fast，不静默回退）。
    ///
    /// - ID 模式齐备性：`relay_server_addr`/`relay_token` 双非空才启用，
    ///   单侧非空 → 错误（不静默降级为直连）；
    /// - **ID 模式启用时 `relay_server_pubkey` 缺失 → fail-closed**
    ///   （ID-SEC-001：控制端凭该公钥验 DeviceInfo 签名；缺则 ID 模式
    ///   不可用，注册前置拒绝）。
    pub fn validate(&self) -> Result<(), String> {
        if self.nickname.trim().is_empty() {
            return Err(
                "nickname is empty — the controlled device's nickname is a handshake \
                    .into(),
            );
        }
        let has_addr = !self.relay_server_addr.trim().is_empty();
        let has_token = !self.relay_token.trim().is_empty();
        if has_addr != has_token {
            return Err(
                "ID mode config incomplete: relay server_addr and token must both be set \
                 (or both empty to disable ID mode)"
                    .into(),
            );
        }
        if self.id_mode_enabled() && self.relay_server_pubkey.trim().is_empty() {
            return Err(
                "ID mode: relay server_pubkey missing — registration refused (fail-closed, ID-SEC-001)"
                    .into(),
            );
        }
        Ok(())
    }

    /// ID 模式是否启用（relay 地址 + token 双非空）。
    pub fn id_mode_enabled(&self) -> bool {
        !self.relay_server_addr.trim().is_empty() && !self.relay_token.trim().is_empty()
    }
}

/// `utils::device::registration_device_id`——显式配置（空白视为未填写）优先，
/// 否则回落 `effective_device_id`（`[device] id` 自动派生短码，与身份生成
/// `orchestration::load_identity` 同一口径）。旧公钥指纹 fallback 是第二套
pub fn registration_device_id(config: &ServerConfig) -> String {
    let base = kirin_desk_utils::config::Config::load()
        .map(|c| c.device.id)
        .unwrap_or_default();
    kirin_desk_utils::device::registration_device_id(Some(&config.device_id), &base)
}

// ════════════════════════════════════════════════════════════════
// 帧喂入（Rust 侧入口；JNI 签名本波只定义，Kotlin 实现归波 2）
// ════════════════════════════════════════════════════════════════

/// 一帧喂入数据（RGBA + 宽高 + 时间戳）。
#[derive(Debug)]
pub struct ServerFrame {
    /// RGBA 像素（`width * height * 4` 字节）。
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// 帧时间戳（epoch；`feed_frame` 的 `timestamp_ms = 0` → now）。
    pub timestamp: SystemTime,
}

///
/// JNI 喂帧线程（MediaProjection 回调）与帧泵线程共享；内存有界（恒 ≤1 帧）。
pub struct FrameFeed {
    slot: Mutex<Option<ServerFrame>>,
    cv: Condvar,
}

impl FrameFeed {
    fn new() -> Self {
        Self {
            slot: Mutex::new(None),
            cv: Condvar::new(),
        }
    }

    /// 喂入一帧（替换槽内旧帧）。
    pub fn push(&self, frame: ServerFrame) {
        let mut guard = self.slot.lock().unwrap();
        *guard = Some(frame);
        self.cv.notify_one();
    }

    /// 取最新帧（阻塞至多 `timeout`；超时返回 None——泵循环据此检查
    /// stop/宽限标志）。
    pub fn take_latest(&self, timeout: Duration) -> Option<ServerFrame> {
        let mut guard = self.slot.lock().unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(frame) = guard.take() {
                return Some(frame);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (g, _res) = self.cv.wait_timeout(guard, remaining).expect("condvar poisoned");
            guard = g;
        }
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// 观众条目（注册表值）：每观众独立有界广播缓冲写半 + 慢观众标记。
struct ViewerEntry {
    /// 审计/定向控制消费点保留）。
    #[allow(dead_code)]
    pub peer_id: String,
    /// 广播缓冲写半（帧泵 try_send；观众发送任务 recv 后写加密通道）。
    pkt_tx: tokio::sync::mpsc::Sender<EncodedPacket>,
    /// 慢观众标记：缓冲满后置位，期间非关键帧全部跳过，直到关键帧成功
    lagging: bool,
}

const VIEWER_ID_BASE: u64 = 1u64 << 48;

/// 被控端服务端全局状态（进程唯一；`start`/`stop` 生命周期）。
pub struct Server {
    /// 当前配置（`start` 写入；逐连接读取——与桌面「配置逐连接读盘」同向）。
    config: Mutex<Option<ServerConfig>>,
    /// 本机身份（`start` 加载；握手签名用）。
    identity: Mutex<Option<Arc<IdentityManager>>>,
    /// 服务运行标志（`start` 置位 / `stop` 清位）。
    running: AtomicBool,
    /// 实际绑定端口（`port = 0` 时 = 临时端口，status 回显）。
    actual_port: AtomicU16,
    /// 服务级停止标志（帧泵/接收任务轮询）。
    stop: AtomicBool,
    /// 服务级停止通知（accept 循环/观众接收任务/注册 runner 响应）。
    stop_notify: tokio::sync::Notify,
    // ── 观众注册表 ──
    viewers: Mutex<HashMap<u64, ViewerEntry>>,
    /// 断连即随观众移除清理；B2 岗 JNI 经 [`Self::viewer_file_handle`] 寻址）。
    viewer_files: Mutex<HashMap<u64, crate::file_transfer::FileTransferHandle>>,
    /// 观众计数镜像（原子读，供宽限判定等同步上下文无锁读取）。
    viewer_count: AtomicUsize,
    /// 观众 id 分配器（注册表键，进程内单调）。
    viewer_next: AtomicU64,
    // ── 帧泵生命周期 ──
    /// 帧泵线程运行中（首观众拉起 / 宽限到期停 / stop 停）。
    pump_running: AtomicBool,
    /// 宽限停止标志：宽限到期且观众仍为 0 → 置位，帧泵轮询后退出。
    pump_grace_stop: AtomicBool,
    /// 宽限代数：新观众接入即递增，使旧的宽限计时器失效（取消停止）。
    grace_generation: AtomicU64,
    /// 泵代数（`start` 递增——旧泵线程据此自杀，防 stop/start 竞态双泵）。
    pump_generation: AtomicU64,
    /// 强制 IDR 请求：后到观众（泵运行中）置位，下一帧 force_key——
    force_key_requested: AtomicBool,
    /// 最近喂入帧尺寸 = **编码分辨率基数**（控制端输入 wire 坐标的换算
    /// 基数，与 `EncodedWindow.base_w/base_h` 同口径——`frames[0].width`
    /// 直传无缩放；打包 `width << 32 | height`，0×0 = 尚无帧喂入）。
    frame_base: AtomicU64,
    /// 输入 wire 非法字节流「仅告警一次」标记（fail-soft：坏包丢弃 + 首次
    /// warn，防恶意/故障流量日志洪泛；`start` 复位）。
    input_parse_warned: AtomicBool,
    /// 帧喂入槽（JNI 线程 → 帧泵线程）。
    feed: Arc<FrameFeed>,
    // ── ID 模式（relay 注册）──
    id_client: Mutex<Option<IdClient>>,
}

impl Server {
    fn new() -> Self {
        Self {
            config: Mutex::new(None),
            identity: Mutex::new(None),
            running: AtomicBool::new(false),
            actual_port: AtomicU16::new(0),
            stop: AtomicBool::new(false),
            stop_notify: tokio::sync::Notify::new(),
            viewers: Mutex::new(HashMap::new()),
            viewer_files: Mutex::new(HashMap::new()),
        viewer_count: AtomicUsize::new(0),
        // ——B2 JNI 四语义用同一 jlong 双角色寻址，空间相交则双角色同设备并发时
        // 歧义；观众 id 仅注册表键+日志，2^48 远超进程观众数量级）。
        viewer_next: AtomicU64::new(VIEWER_ID_BASE),
            pump_running: AtomicBool::new(false),
            pump_grace_stop: AtomicBool::new(false),
            grace_generation: AtomicU64::new(0),
            pump_generation: AtomicU64::new(0),
            force_key_requested: AtomicBool::new(false),
            frame_base: AtomicU64::new(0),
            input_parse_warned: AtomicBool::new(false),
            feed: Arc::new(FrameFeed::new()),
            id_client: Mutex::new(None),
        }
    }

    /// 全局单例（进程唯一被控端服务端）。
    pub fn global() -> &'static Arc<Server> {
        static G: OnceLock<Arc<Server>> = OnceLock::new();
        G.get_or_init(|| Arc::new(Server::new()))
    }

    /// 本机身份（`start` 加载后；未启动 = None）。
    fn identity(&self) -> Option<Arc<IdentityManager>> {
        self.identity.lock().unwrap().clone()
    }

    /// 分配观众 id（注册表键）。
    fn next_viewer_id(&self) -> u64 {
        self.viewer_next.fetch_add(1, Ordering::Relaxed)
    }

    /// 编码分辨率基数（输入坐标换算用；(0,0) = 尚无帧喂入）。
    pub fn frame_base(&self) -> (u32, u32) {
        let v = self.frame_base.load(Ordering::Relaxed);
        ((v >> 32) as u32, v as u32)
    }

    /// 观众断连/移除后返回 None）。
    pub fn viewer_file_handle(&self, viewer_id: u64) -> Option<crate::file_transfer::FileTransferHandle> {
        self.viewer_files.lock().unwrap().get(&viewer_id).cloned()
    }

    pub fn viewer_ids(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.viewer_files.lock().unwrap().keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// 一次取全：句柄 = 四语义 API 输入，peer_id = 按 B1 salt 口径
    /// （本端公钥 b64 + peer_id 排序拼接）预派生 `transfer_id` 用；观众
    /// 断连/移除后返回 None）。
    pub fn viewer_file_session(
        &self,
        viewer_id: u64,
    ) -> Option<(crate::file_transfer::FileTransferHandle, String)> {
        let peer_id = self.viewers.lock().unwrap().get(&viewer_id)?.peer_id.clone();
        Some((self.viewer_file_handle(viewer_id)?, peer_id))
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// 注册观众（握手成功后由连接任务调用）：入注册表 + 取消既有宽限 +
/// 拉起/标记帧泵。
fn register_viewer(state: &Arc<Server>, viewer_id: u64, pkt_tx: tokio::sync::mpsc::Sender<EncodedPacket>, peer_id: String) {
    // 新观众接入 → 递增宽限代数（使旧宽限计时器失效）+ 清宽限停标志。
    state.grace_generation.fetch_add(1, Ordering::Relaxed);
    state.pump_grace_stop.store(false, Ordering::Relaxed);
    let pump_was_running = state.pump_running.load(Ordering::Relaxed);
    {
        let mut m = state.viewers.lock().unwrap();
        m.insert(
            viewer_id,
            ViewerEntry {
                peer_id,
                pkt_tx,
                lagging: false,
            },
        );
        state.viewer_count.store(m.len(), Ordering::Relaxed);
    }
    if pump_was_running {
        // 泵运行中（后到观众）→ 下一帧强制 IDR（新观众解码锚点）。
        state.force_key_requested.store(true, Ordering::Relaxed);
    } else if !state.stop.load(Ordering::Relaxed) {
        spawn_pump(Arc::clone(state));
    }
}

/// 移除观众（发送失败/接收 EOF/stop/踢出统一入口）；注册表清零且泵运行中
fn remove_viewer(state: &Arc<Server>, viewer_id: u64) {
    let mut m = state.viewers.lock().unwrap();
    let removed = m.remove(&viewer_id).is_some();
    let n = m.len();
    state.viewer_count.store(n, Ordering::Relaxed);
    drop(m);
    // 文件会话任务退出；断点记录按口径保留于 transfers_server.json）。
    state.viewer_files.lock().unwrap().remove(&viewer_id);
    if removed {
        info!("mobile server: viewer #{viewer_id} removed (viewers now: {n})");
    }
    if n == 0 && state.pump_running.load(Ordering::Relaxed) && !state.stop.load(Ordering::Relaxed)
    {
        schedule_grace_stop(Arc::clone(state));
    }
}

/// 排定宽限停止：`CAPTURE_GRACE` 后若宽限代数未变（无新观众）且观众仍为 0
/// → 置 `pump_grace_stop`（帧泵轮询后退出并释放编码器）。
fn schedule_grace_stop(state: Arc<Server>) {
    let gen = state.grace_generation.load(Ordering::Relaxed);
    crate::runtime().spawn(async move {
        tokio::time::sleep(CAPTURE_GRACE).await;
        let state = Arc::clone(&state);
        if state.grace_generation.load(Ordering::Relaxed) == gen
            && state.viewer_count.load(Ordering::Relaxed) == 0
            && !state.stop.load(Ordering::Relaxed)
        {
            info!(
                "mobile server: all viewers left and {}s grace expired — frame pump stopping (restarts on next viewer)",
                CAPTURE_GRACE.as_secs()
            );
            state.pump_grace_stop.store(true, Ordering::Relaxed);
        }
    });
}

// ════════════════════════════════════════════════════════════════
// 帧泵（专用 std 线程：FFmpeg 阻塞同步编码，同桌面拓扑）
// ════════════════════════════════════════════════════════════════

/// 编码管线构建：H.264 软编（libx264 经 FFmpeg，红线①；`kernel = None`
/// ⇒ 工厂 SW 优先——HW 编码器为桌面 D3D11/GPU 内核路径，移动端不启用）。
///
/// ≤720p 4M / ≤1080p 10M / ≤1440p 16M / 4K+ 32M + bufsize 1s VBV），
/// preset 同源阶梯——分辨率由首帧/尺寸变化驱动，本层不额外干预。
fn build_pipeline() -> Result<WindowPipeline, String> {
    let encoder = VideoEncoderPipeline::new(Codec::H264, None)
        .map_err(|e| format!("video encoder init failed: {e}"))?;
    let mut pipe = WindowPipeline::new(WindowConfig::default(), encoder);
    // + 长 GOP 不每窗 IDR（流畅优先，用户裁定）。
    pipe.set_low_latency(true);
    Ok(pipe)
}

/// 拉起帧泵线程（泵代数递增——旧线程自杀，防 stop/start 竞态双泵）。
fn spawn_pump(state: Arc<Server>) {
    if state.pump_running.swap(true, Ordering::Relaxed) {
        return; // 已在运行（register_viewer 并发双调防护）
    }
    let gen = state.pump_generation.fetch_add(1, Ordering::Relaxed) + 1;
    state.pump_grace_stop.store(false, Ordering::Relaxed);
    let feed = Arc::clone(&state.feed);
    let state_for_thread = Arc::clone(&state);
    if std::thread::Builder::new()
        .name("kirin-mobile-server-pump".into())
        .spawn(move || pump_loop(Arc::clone(&state_for_thread), gen, feed))
        .is_err()
    {
        state.pump_running.store(false, Ordering::Relaxed);
    }
}

/// 帧泵主循环：喂入槽取最新帧 → WindowPipeline 低延迟编码 → 广播。
///
/// 退出条件：服务 stop / 宽限停（`pump_grace_stop`）/ 泵代数被新 start 取代。
fn pump_loop(state: Arc<Server>, my_gen: u64, feed: Arc<FrameFeed>) {
    let mut pipeline = match build_pipeline() {
        Ok(p) => p,
        Err(e) => {
            // 编码器不可用（FFmpeg 未载等）→ 泵退出；新观众注册会重新拉起
            // （重试），不 backpressure 注册路径。
            warn!("mobile server: frame pump start failed: {e}");
            state.pump_running.store(false, Ordering::Relaxed);
            return;
        }
    };
    let mut first_window = true; // 泵（重）启动后首窗 = 新编码器首帧，天然 IDR
    info!(
        "mobile server: frame pump started (libx264 via FFmpeg, low-latency, ladder by resolution)"
    );
    loop {
        if state.stop.load(Ordering::Relaxed)
            || state.pump_grace_stop.load(Ordering::Relaxed)
            || state.pump_generation.load(Ordering::Relaxed) != my_gen
        {
            break;
        }
        let Some(frame) = feed.take_latest(PUMP_POLL_INTERVAL) else {
            continue; // 无帧：重新检查生命周期标志
        };
        if state.stop.load(Ordering::Relaxed)
            || state.pump_grace_stop.load(Ordering::Relaxed)
            || state.pump_generation.load(Ordering::Relaxed) != my_gen
        {
            break;
        }
        // 后到观众强制 IDR 请求（消费即清；长 GOP 下新观众解码锚点）。
        let force_key = state.force_key_requested.swap(false, Ordering::Relaxed);
        let raw = RawFrame {
            data: Arc::new(frame.data),
            width: frame.width,
            height: frame.height,
            timestamp: frame.timestamp,
            dirty_rects: Vec::new(),
            force_key,
        };
        match pipeline.push_frame(raw) {
            Ok(Some(window)) if !window.is_empty() => {
                let is_idr = first_window || force_key;
                first_window = false;
                broadcast_window(&state, &window, is_idr);
            }
            Ok(Some(_)) => {
                // 空窗口（帧被门控全吞的边角）：窗口号已前进，首窗标志清。
                first_window = false;
            }
            Ok(None) => {} // 频率门控未放行（丢旧保新，最新帧留窗）
            Err(e) => {
                // 降级路径在桌面侧体现，本波移动端不做编码重启策略）。
                warn!("mobile server: encode error: {e}");
            }
        }
    }
    state.pump_running.store(false, Ordering::Relaxed);
    info!("mobile server: frame pump stopped");
}

/// 关键帧限时补投（缓冲满时）：10ms 节拍 try_send 至 `KEY_DELIVER_TIMEOUT`，
/// 超时 = 观众发送任务说明死/链路僵死 → 返回 false（调用方踢出）。同步实现
/// （帧泵 std 线程上下文，不依赖 runtime）。
fn deliver_key_with_timeout(
    tx: &tokio::sync::mpsc::Sender<EncodedPacket>,
    pkt: &EncodedPacket,
) -> bool {
    let deadline = Instant::now() + KEY_DELIVER_TIMEOUT;
    loop {
        match tx.try_send(pkt.clone()) {
            Ok(()) => return true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
        }
    }
}

/// bincode(EncodedWindow) 大帧包，`is_key` = 本窗首帧是否 IDR）。
fn broadcast_window(state: &Arc<Server>, window: &EncodedWindow, is_idr: bool) {
    let Ok(bytes) = bincode::serialize(window) else {
        warn!(
            "mobile server: serialize window {} failed — dropped",
            window.window_id
        );
        return;
    };
    let pkt = EncodedPacket {
        ts: Timestamp::now(),
        kind: PacketKind::Video,
        data: bytes,
        is_key: is_idr,
    };
    let mut kick: Vec<u64> = Vec::new();
    {
        let mut m = state.viewers.lock().unwrap();
        for (id, v) in m.iter_mut() {
            // 慢观众 + 非关键帧 → 丢弃（保新；跳过至下一可解码帧）。
            if v.lagging && !pkt.is_key {
                continue;
            }
            match v.pkt_tx.try_send(pkt.clone()) {
                Ok(()) => v.lagging = false,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    if pkt.is_key {
                        // 关键帧限时补投；超时 → 踢出（不 backpressure 帧泵）。
                        if deliver_key_with_timeout(&v.pkt_tx, &pkt) {
                            v.lagging = false;
                        } else {
                            warn!(
                                "mobile server: viewer #{id} key-frame deliver timed out — kicking"
                            );
                            kick.push(*id);
                        }
                    } else {
                        debug!("mobile server: viewer #{id} buffer full — dropping frame");
                        v.lagging = true;
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => kick.push(*id),
            }
        }
        for id in &kick {
            m.remove(id);
        }
        let n = m.len();
        state.viewer_count.store(n, Ordering::Relaxed);
    }
    // 踢出也可能使注册表清零（唯一观众链路僵死）——与 remove_viewer 同一
    if !kick.is_empty()
        && state.viewer_count.load(Ordering::Relaxed) == 0
        && state.pump_running.load(Ordering::Relaxed)
        && !state.stop.load(Ordering::Relaxed)
    {
        schedule_grace_stop(Arc::clone(state));
    }
}

// ════════════════════════════════════════════════════════════════
// 握手 + 观众会话
// ════════════════════════════════════════════════════════════════

/// 单连接握手（**本地监听与 relay 隧道流共用入口**——ID-013 访问控制零
/// 降级：ID 模式中继牵线到达的流同样过昵称/挑战码门）。
///
/// 流程（桌面 GUI `handle_incoming_connection` 的被控端最小子集）：
/// 1. `server_read_init` 预读 init（core S-02 内建 10s deadline，只读不答）；
/// 3. `verify_server_init` 凭据校验（单态挑战码，生产路径
///    `allow_no_credentials = false`——零凭据 fail-closed）：
///    - 昵称门：IP/域名模式（`client_domain` 非空）字面比对本机昵称
///      跳过昵称（桌面 `expected_nick_for_verify` 同款）；
///    - 挑战码：配置值（空 = 未配置 → 零凭据拒绝路径）；
///    - 错挑战码 / 零凭据（未配置）→ `send_handshake_reject` 结构化码
///    - 昵称不匹配 → **裸 close（early eof 形态）**——防枚举，不下发
///    - 其余（签名失败/消息损坏）→ 静默裸 close（异常流量，无用户文案语义）；
/// 5. codec 协商（本端仅 H.264 软编；空交集 → 空串 → 控制端 H.264 兜底，
///    既有握手语义）；
/// 6. `server_handshake_respond_generic` 应答建安全通道（签名 id = 本机
///    昵称——控制端以同一昵称验签，GUI 8999 端口径）。
async fn handshake_incoming(
    stream: TcpStream,
    ip: &str,
    state: &Arc<Server>,
) -> Option<SecureChannel> {
    let (cfg, identity) = {
        let cfg = state.config.lock().unwrap().clone()?;
        let identity = state.identity()?;
        (cfg, identity)
    };
    let mut stream = stream;
    // 1) 预读 init（只读不答；超时/损坏 → 静默断开）。
    let init = match server_read_init(&mut stream).await {
        Ok(i) => i,
        Err(e) => {
            debug!("mobile server: init read from {ip} failed: {e}");
            return None;
        }
    };
    if reject_if_client_too_new(&mut stream, &init).await {
        warn!(
            "mobile server: rejecting {} ({ip}) — client proto_ver {} too new",
            init.client_id, init.proto_ver
        );
        return None;
    }
    // 3) 凭据校验（core 校验链：昵称 → 挑战码（常量时间）→ Ed25519 签名）。
    let nickname = cfg.nickname.trim();
    let challenge = cfg.challenge.trim();
    let expected_nick = if init.client_domain.is_empty() {
        None // ID 模式（relay 隧道/打洞流）：昵称非凭据，跳过（桌面同款）
    } else {
        Some(nickname)
    };
    let expected_challenge = if challenge.is_empty() {
        // 未配置挑战码 → 零凭据 fail-closed（`allow_no_credentials = false`
        // + 无 pin → core 拒绝；此处显式 None 表达「无固定码」语义）。
        None
    } else {
        Some(challenge)
    };
    //     挑战-响应轮（下发 nonce、限时收应答；失败/超时 = 结构化拒绝，
    //     与 verify 失败同处置面）。
    let challenge_answer =
        if kirin_desk_core::crypto::handshake::challenge_round_required(
            "",
            &init.client_ed25519_pub_base64,
            expected_challenge,
            None,
        ) {
            match kirin_desk_core::crypto::handshake::server_challenge_round(&mut stream).await {
                Ok(a) => Some(a),
                Err(e) => {
                    debug!("mobile server: challenge round from {ip} failed: {e}");
                    let _ = send_handshake_reject(
                        &mut stream,
                        REJECT_CODE_CHALLENGE_MISMATCH,
                        &init.client_id,
                    )
                    .await;
                    return None;
                }
            }
        } else {
            None
        };
    if let Err(e) = verify_server_init_with_answer(&init, "", expected_nick, expected_challenge, false, challenge_answer.as_ref()) {
        // 4) 错误分类下发（拒绝码取 core 映射，不自造码表）。
        match handshake_error_reject_code(&e) {
            Some(REJECT_CODE_CHALLENGE_MISMATCH) => {
                let _ =
                    send_handshake_reject(&mut stream, REJECT_CODE_CHALLENGE_MISMATCH, &init.client_id)
                        .await;
            }
            Some(REJECT_CODE_CREDENTIALS_REQUIRED) => {
                let _ = send_handshake_reject(
                    &mut stream,
                    REJECT_CODE_CREDENTIALS_REQUIRED,
                    &init.client_id,
                )
                .await;
            }
            // 昵称不匹配（REJECT_CODE_NICKNAME_MISMATCH）与其余 → 裸 close
            // （early eof 形态 / 静默，防枚举口径）。
            _ => {}
        }
        warn!("mobile server: rejecting {} ({ip}): {e}", init.client_id);
        return None;
    }
    // 5) codec 协商：本端软编 H.264（libx264 经 FFmpeg，红线①）。
    let selected_codec =
        negotiate_codec_by_server_priority(&["h264".to_string()], &init.supported_codecs);
    // 6) 应答（签名 id = 本机昵称——客户端以同一昵称验签；不泄露额外公钥
    //    语义由 core 既有流程保证）。
    let g = match server_handshake_respond_generic(stream, &identity, nickname, &init, &selected_codec)
        .await
    {
        Ok(g) => g,
        Err(e) => {
            warn!("mobile server: handshake respond failed ({ip}): {e}");
            return None;
        }
    };
    // SecureChannelGeneric<TcpStream> → SecureChannel（字段一一对应；
    // media 的同名助手为 crate 私有，此处直接收敛）。
    Some(SecureChannel {
        stream: g.stream,
        cipher: g.cipher,
        peer_id: g.peer_id,
        peer_domain: g.peer_domain,
        peer_device_type: g.peer_device_type,
        selected_codec: g.selected_codec,
        peer_os: g.peer_os,
    })
}

/// 观众会话：注册广播注册表 + 发送任务（广播缓冲 → `send_big_packet` 大帧
/// wire 输入消费点——`injector::InputEvent` 反序列化后 JNI 上抛 Kotlin 无障碍
async fn run_viewer_session(viewer_id: u64, channel: SecureChannel, state: Arc<Server>) {
    let peer_id = channel.peer_id.clone();
    let (reader, writer) = channel.into_split();
    let sender = Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(writer)));
    let mut receiver = SecureChannelReceiver::new(reader);

    // sender——与视频广播发送任务互斥保证帧边界；salt = 本端公钥 b64 +
    // 观众 peer_id 排序拼接，桌面 ui 同口径；断点 transfers_server.json
    // 落 KIRIN_DATA_DIR）。收帧馈送端由下方接收任务 0x06 分支持有——
    // 断连（接收任务退出）即 drop → 会话任务退出。
    let (files, file_frame_tx) = crate::file_transfer::spawn_session(
        crate::runtime(),
        Arc::clone(&sender),
        crate::file_transfer::session_salt(
            &state
                .identity()
                .map(|i| i.public_key_base64())
                .unwrap_or_default(),
            &peer_id,
        ),
        "server",
        DEFAULT_MAX_FILE_SIZE,
    );
    state.viewer_files.lock().unwrap().insert(viewer_id, files);

    // 注册（每观众 8 深缓冲 + 帧泵拉起/IDR 标记）。
    let (pkt_tx, mut pkt_rx) = tokio::sync::mpsc::channel::<EncodedPacket>(VIEWER_BUFFER);
    register_viewer(
        &state,
        viewer_id,
        pkt_tx,
        peer_id,
    );

    // 发送任务：缓冲 → 自己的加密写半（视频窗走 send_big_packet——与桌面
    let send_task = {
        let sender = Arc::clone(&sender);
        let state = Arc::clone(&state);
        crate::runtime().spawn(async move {
            while let Some(pkt) = pkt_rx.recv().await {
                if sender.lock().await.send_big_packet(&pkt).await.is_err() {
                    warn!("mobile server: viewer #{viewer_id} send failed — removing");
                    break;
                }
            }
            remove_viewer(&state, viewer_id);
        })
    };
    // 接收任务：排空入站（EOF/stop → 移除观众；移除 → 发送任务随 tx drop 退出）。
    {
        let state = Arc::clone(&state);
        let _recv_task = crate::runtime().spawn(async move {
            loop {
                tokio::select! {
                    _ = state.stop_notify.notified() => break,
                    r = receiver.recv_tagged() => match r {
                        Ok((ChannelTag::Input, _header, payload)) => {
                            // 输入事件——红线⑥ `injector::InputEvent`（与桌面被控端
                            // 分发任务 ui/src/lib.rs 消费同型；与移动端控制端
                            // build_input_event 序列化双向对称）→ 纯转换上抛参数
                            // （归一化坐标 + 编码分辨率基数）→ JNI 上抛 Kotlin
                            //
                            // fail-soft（红线⑤）：无障碍服务未启用（Kotlin 未置
                            // nativeSetInputCallbackEnabled(true)）/ JNI 未初始化 /
                            // 回调失败 → 本事件静默丢弃（jni 层仅首次失败 warn），
                            // 会话照常继续，绝不断连。
                            match input_event_to_jni_args(&payload, state.frame_base()) {
                                Some(args) => deliver_input_event(&args),
                                None => {
                                    // 非法字节流（非 injector::InputEvent 线格式）
                                    // → 丢弃 + 仅首次 warn（防日志洪泛）。
                                    if state.input_parse_warned.swap(true, Ordering::Relaxed) {
                                        warn!(
                                            "mobile server: viewer #{viewer_id} input payload is not a valid injector::InputEvent — dropped (warn once)"
                                        );
                                    }
                                }
                            }
                        }
                        Ok((ChannelTag::FileTransfer, _header, payload)) => {
                            // 任务（桌面 ui 收侧 tag 路由同口径；坏帧 warn 丢弃，
                            // 不断连、不影响视频/输入）。
                            match FileTransferFrame::decode(&payload) {
                                Ok(frame) => {
                                    let _ = file_frame_tx.send(frame);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "mobile server: viewer #{viewer_id} file frame decode failed: {e}"
                                    );
                                }
                            }
                        }
                        Ok((tag, _header, _payload)) => {
                            // 音频（本波不做，遗留列清）/控制等：忽略记调试日志。
                            debug!("mobile server: viewer #{viewer_id} tag {tag:?} ignored (no audio/control in wave 1)");
                        }
                        Err(e) => {
                            info!("mobile server: viewer #{viewer_id} receive ended: {e}");
                            break;
                        }
                    },
                }
            }
            remove_viewer(&state, viewer_id);
        });
    }
    // 等发送任务收尾（缓冲排空或通道断开）；两半通道随任务 drop → TCP FIN。
    let _ = send_task.await;
    info!("mobile server: viewer #{viewer_id} session ended");
}

/// 监听接受循环（全局 runtime 任务）。
async fn accept_loop(listener: TcpListener, state: Arc<Server>) {
    loop {
        tokio::select! {
            _ = state.stop_notify.notified() => {
                info!("mobile server: accept loop stopped");
                return;
            }
            res = listener.accept() => {
                let (stream, addr) = match res {
                    Ok(x) => x,
                    Err(e) => {
                        if state.stop.load(Ordering::Relaxed) {
                            return;
                        }
                        warn!("mobile server: accept error: {e}");
                        continue;
                    }
                };
                let ip = addr.ip().to_string();
                let state = Arc::clone(&state);
                crate::runtime().spawn(async move {
                    match handshake_incoming(stream, &ip, &state).await {
                        Some(channel) => {
                            let id = state.next_viewer_id();
                            info!(
                                "mobile server: viewer #{id} connected from {ip} (peer '{}', codec '{}')",
                                channel.peer_id, channel.selected_codec
                            );
                            run_viewer_session(id, channel, state).await;
                        }
                        None => {} // 拒绝路径（已分类下发/静默）
                    }
                });
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════
// ID 模式（relay 注册接线）
// ════════════════════════════════════════════════════════════════

/// 装配并启动 [`IdClient`] 注册（配置齐备性已由 `validate` 前置：
/// server_addr/token/server_pubkey 齐备，server_pubkey 缺失 fail-closed
/// 已在 `validate` 拒绝）。
///
/// 中继牵线（`on_tunnel_stream`）到达的流走与本地监听**同一**
/// [`handshake_incoming`] 入口（ID-013 零降级）。
fn start_id_registration(state: &Arc<Server>, config: &ServerConfig, identity: &IdentityManager) {
    let device_id = registration_device_id(config);
    let listen_port = state.actual_port.load(Ordering::Relaxed);
    let cfg = IdClientConfig {
        server_addr: config.relay_server_addr.trim().to_string(),
        token: config.relay_token.trim().to_string(),
        device_id: device_id.clone(),
        ed25519_pub: identity.public_key_base64(),
        hostname: if config.nickname.trim().is_empty() {
            "kirin-android".into()
        } else {
            config.nickname.trim().to_string()
        },
        heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
        heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
        connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        backoff_base: DEFAULT_BACKOFF_BASE,
        backoff_max: DEFAULT_BACKOFF_MAX,
        extra_candidates: Vec::new(),
        local_port: listen_port,
        report_lan_candidates: true,
    };
    let relay_addr = cfg.server_addr.clone();
    let state_for_tunnel = Arc::clone(state);
    let id_client = IdClient::new(cfg, move |stream: TcpStream| {
        // §8.1 设备级中继：回调收到设备侧数据流（relay 已与控制器配对泵流）
        // → 执行 KirinDesk 服务端握手（与本地监听同入口）+ 会话。回调为同步
        // `Fn`（可多次调用）：每次克隆一份状态 Arc 进异步任务，spawn 后
        // 立即返回（不阻塞 relay 控制循环；`Runtime::spawn` 不失败）。
        let st = Arc::clone(&state_for_tunnel);
        crate::runtime().spawn(async move {
            match handshake_incoming(stream, "relay", &st).await {
                Some(channel) => {
                    let id = st.next_viewer_id();
                    info!(
                        "mobile server: relay tunnel viewer #{id} (peer '{}')",
                        channel.peer_id
                    );
                    run_viewer_session(id, channel, st).await;
                }
                None => {}
            }
        });
    });
    *state.id_client.lock().unwrap() = Some(id_client.clone());
    info!(
        "mobile server: ID mode registration started (device '{}' on relay {relay_addr})",
        device_id
    );
    // runner：`IdClient::run` 内部已有会话级退避重连（TNL-STAB-003）；外层
    // 封顶 60s，stop 打断后**不**重启——注册生命周期由 stop 与 relay 心跳
    // TTL 决定）。
    let runner = id_client;
    let state = Arc::clone(state);
    crate::runtime().spawn(async move {
        let mut attempt: u32 = 0;
        loop {
            match runner.run().await {
                Ok(()) => return, // stop()/Shutdown：优雅退出
                Err(e) => {
                    if state.stop.load(Ordering::Relaxed) {
                        return;
                    }
                    attempt += 1;
                    let backoff_secs = (1u64 << attempt.min(6)).min(60);
                    warn!(
                        "mobile server: ID registration runner exited (#{attempt}): {e} — retrying in {backoff_secs}s"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => {}
                        _ = state.stop_notify.notified() => return,
                    }
                }
            }
        }
    });
}

// ════════════════════════════════════════════════════════════════
// 公共入口（JNI / 宿主测试）
// ════════════════════════════════════════════════════════════════

/// 启动被控端服务端（JNI `nativeServerStart`；幂等性 = 运行中再启报错）。
///
/// 顺序：配置校验（fail-fast）→ 身份加载 → 双栈监听绑定 → accept 循环 →
/// ID 模式注册（启用时；server_pubkey 缺失已在 `validate` fail-closed）。
/// 返回状态快照（含实际端口/本机公钥——控制端配对与测试断言用）。
pub fn start(config: ServerConfig) -> Result<ServerStatus, String> {
    let state = Server::global();
    config.validate().map_err(|e| format!("invalid server config: {e}"))?;
    if state.running.load(Ordering::Relaxed) {
        return Err("server already running (stop it first)".into());
    }
    // 本机身份（首启生成并落 config_dir；与 nativeIdentity 同口径）。
    let identity = Arc::new(
        crate::orchestration::load_identity()
            .map_err(|e| format!("identity: {e}"))?,
    );
    *state.identity.lock().unwrap() = Some(Arc::clone(&identity));
    *state.config.lock().unwrap() = Some(config.clone());
    // （ScreenShareService.startServer），线程上**无 tokio runtime 上下文**
    // ——`bind_dual_stack_tcp_listener` → `TcpListener::from_std` 注册
    // `#[tokio::test]` 上下文内，掩盖至今）。进入全局 runtime 上下文后再
    // 做同步建监听；后续 spawn 仍走 `Runtime::spawn` 显式句柄（不受
    // thread-local Enter 影响），guard 存活至本函数尾=覆盖整段同步装配。
    let _rt_enter = crate::runtime().enter();
    let listener = bind_dual_stack_tcp_listener(config.port)
        .map_err(|e| format!("bind port {} failed: {e}", config.port))?;
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(config.port);
    state.actual_port.store(port, Ordering::Relaxed);
    // 生命周期复位（stop/start 竞态防护：泵代数递增 → 旧泵线程自杀）。
    state.stop.store(false, Ordering::Relaxed);
    state.pump_grace_stop.store(false, Ordering::Relaxed);
    state.pump_running.store(false, Ordering::Relaxed);
    state.pump_generation.fetch_add(1, Ordering::Relaxed);
    state.viewers.lock().unwrap().clear();
    state.viewer_count.store(0, Ordering::Relaxed);
    // 不得污染新会话）。
    state.frame_base.store(0, Ordering::Relaxed);
    state.input_parse_warned.store(false, Ordering::Relaxed);
    state.running.store(true, Ordering::Relaxed);
    crate::runtime().spawn(accept_loop(listener, Arc::clone(state)));
    // ID 模式（relay 注册）。
    if config.id_mode_enabled() {
        start_id_registration(state, &config, &identity);
    }
    let snap = status_snapshot(state);
    info!(
        "mobile server: listening on port {port} (nickname '{}', ID mode {})",
        config.nickname.trim(),
        if config.id_mode_enabled() { "on" } else { "off" }
    );
    Ok(snap)
}

/// 停止被控端服务端（JNI `nativeServerStop`）。
///
/// 停监听/停止帧泵（宽限标志 + 泵轮询自退）/优雅停 ID 注册（Logout）/
/// 清观众注册表（各观众发送任务随通道 drop 自行退出）/清配置。
pub fn stop() -> bool {
    let state = Server::global();
    if !state.running.swap(false, Ordering::Relaxed) {
        return false;
    }
    state.stop.store(true, Ordering::Relaxed);
    state.pump_grace_stop.store(true, Ordering::Relaxed);
    state.pump_generation.fetch_add(1, Ordering::Relaxed);
    {
        let mut guard = state.id_client.lock().unwrap();
        if let Some(c) = guard.as_ref() {
            c.stop();
        }
        *guard = None;
    }
    state.viewers.lock().unwrap().clear();
    state.viewer_count.store(0, Ordering::Relaxed);
    state.config.lock().unwrap().take();
    state.stop_notify.notify_waiters();
    info!("mobile server: stopped");
    true
}

/// 帧喂入入口（JNI `nativeServerFeedFrame`；波 2 MediaProjection 回调）。
///
/// `rgba` = `width * height * 4` 字节 RGBA；`timestamp_ms` = epoch 毫秒
/// （0 = now）。服务端未运行或尺寸/数据不合法 → false（不 panic、不落日志
/// 洪泛——喂帧高频路径）。
pub fn feed_frame(rgba: &[u8], width: u32, height: u32, timestamp_ms: u64) -> bool {
    let state = Server::global();
    if !state.running.load(Ordering::Relaxed) {
        return false;
    }
    if width == 0 || height == 0 || rgba.len() != (width as usize).saturating_mul(height as usize).saturating_mul(4)
    {
        return false;
    }
    // `EncodedWindow.base_w/base_h` = 首帧原始尺寸无缩放——控制端正是按此
    state
        .frame_base
        .store(((width as u64) << 32) | (height as u64), Ordering::Relaxed);
    let timestamp = if timestamp_ms == 0 {
        SystemTime::now()
    } else {
        SystemTime::UNIX_EPOCH + Duration::from_millis(timestamp_ms)
    };
    state
        .feed
        .push(ServerFrame {
            data: rgba.to_vec(),
            width,
            height,
            timestamp,
        });
    true
}

/// 服务端状态快照（JNI `nativeServerStatus` JSON 返回体；含本机公钥/指纹
/// ——控制端 TOFU 配对核对与设置页展示用）。
#[derive(Debug, Clone)]
pub struct ServerStatus {
    /// 服务运行中。
    pub running: bool,
    /// 实际监听端口（`port = 0` 时 = 临时端口）。
    pub port: u16,
    /// 本机昵称。
    pub nickname: String,
    /// 注册设备 ID（显式配置或指纹派生；未启动 = 空）。
    pub device_id: String,
    /// 公钥指纹（79 字符；与桌面 Dashboard 核对口径一致；未启动 = 空）。
    pub fingerprint: String,
    /// 本机 Ed25519 公钥（base64；控制端带外 pin 用；未启动 = 空）。
    pub public_key: String,
    /// 当前观众数。
    pub viewers: usize,
    /// 纯增量字段，旧消费方忽略即兼容）。
    pub viewer_ids: Vec<u64>,
    /// 帧泵运行中（首观众拉起 / 全退宽限停）。
    pub pump_active: bool,
    /// ID 模式是否启用。
    pub id_mode_enabled: bool,
    /// ID 注册状态（relay 登录在册）。
    pub id_registered: bool,
}

fn status_snapshot(state: &Arc<Server>) -> ServerStatus {
    let cfg = state.config.lock().unwrap().clone();
    // "—"——按 `registration_device_id` 同链现读落盘配置（显式 id 优先，
    // 否则 `effective_device_id` 派生；与连接页 `nativeIdentity` 同口径，
    // Kotlin ServerScreen 文档口径「未运行时 identity 字段亦可得」）。
    let base_device = kirin_desk_utils::config::Config::load()
        .map(|c| c.device.id)
        .unwrap_or_default();
    let (nickname, device_id, id_mode_enabled) = match &cfg {
        Some(c) => {
            let dev = registration_device_id(c);
            (c.nickname.trim().to_string(), dev, c.id_mode_enabled())
        }
        None => (
            String::new(),
            kirin_desk_utils::device::effective_device_id(&base_device),
            false,
        ),
    };
    // 同上：identity 缓存未建立（未运行过）→ 现读落盘身份（无则生成），
    // 指纹/公钥随之可得；读取失败保持空串（UI 占位，原行为）。
    let id = state.identity().or_else(|| {
        crate::orchestration::load_identity().ok().map(Arc::new)
    });
    let (fingerprint, public_key) = match id.as_ref() {
        Some(i) => {
            let pk = i.public_key_base64();
            (
                kirin_desk_utils::known_hosts::fingerprint(&pk),
                pk,
            )
        }
        None => (String::new(), String::new()),
    };
    let id_registered = state
        .id_client
        .lock()
        .unwrap()
        .as_ref()
        .map(|c| c.status().registered)
        .unwrap_or(false);
    ServerStatus {
        running: state.running.load(Ordering::Relaxed),
        port: state.actual_port.load(Ordering::Relaxed),
        nickname,
        device_id,
        fingerprint,
        public_key,
        viewers: state.viewer_count.load(Ordering::Relaxed),
        viewer_ids: state.viewer_ids(),
        pump_active: state.pump_running.load(Ordering::Relaxed),
        id_mode_enabled,
        id_registered,
    }
}

/// 当前状态快照（同步读取）。
pub fn status() -> ServerStatus {
    status_snapshot(Server::global())
}

/// 状态 JSON（JNI `nativeServerStatus` 返回串）。
pub fn status_json() -> String {
    let s = status();
    serde_json::json!({
        "running": s.running,
        "port": s.port,
        "nickname": s.nickname,
        "device_id": s.device_id,
        "fingerprint": s.fingerprint,
        "public_key": s.public_key,
        "viewers": s.viewers,
        "viewer_ids": s.viewer_ids,
        "pump_active": s.pump_active,
        "id_mode_enabled": s.id_mode_enabled,
        "id_registered": s.id_registered,
    })
    .to_string()
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// Kotlin 上抛参数 `kind` 判别常量——与 `injector::InputKind` **变体声明序**
/// 一一对应（即 wire bincode 枚举判别式空间；wire 枚举序变更须同步改此处
/// 与 jni.rs 契约注释，两端契约锚）。
pub mod input_kind {
    /// 鼠标移动（`nx`/`ny` 有效）。
    pub const MOUSE_MOVE: i32 = 0;
    /// 鼠标按键（`key` = wire 按钮位标志 1/2/4，|0x80 = 抬起；`nx`/`ny` 有效）。
    pub const MOUSE_BUTTON: i32 = 1;
    /// 滚轮（`key` = `wheel_delta`，正上负下；无坐标语义）。
    pub const MOUSE_WHEEL: i32 = 2;
    /// 键按下（`key` = wire 键码，`modifiers` 位标志有效）。
    pub const KEY_DOWN: i32 = 3;
    /// 键抬起（同上）。
    pub const KEY_UP: i32 = 4;
    /// 键重复（同上）。
    pub const KEY_REPEAT: i32 = 5;
    /// Unicode 文本（`text` 有效，其余默认）。
    pub const TEXT: i32 = 6;
    /// 系统组合键（`key` = `SpecialCombo` 判别式，见下）。
    pub const SPECIAL_KEY: i32 = 7;
}

/// `SpecialCombo` → Kotlin 判别常量（= `injector::SpecialCombo` 变体声明序）。
pub mod special_combo {
    pub const WIN_E: i32 = 0;
    pub const WIN_D: i32 = 1;
    pub const WIN_L: i32 = 2;
    pub const WIN_R: i32 = 3;
    pub const ALT_TAB: i32 = 4;
    pub const CTRL_SHIFT_ESC: i32 = 5;
    pub const ALT_F4: i32 = 6;
    pub const CTRL_ESC: i32 = 7;
    pub const LOCK_SCREEN: i32 = 8;
}

/// 上抛参数（wire [`WireInputEvent`] → Kotlin `onServerInputEvent` 的纯转换
/// 输出；字段序 = JNI 签名 `(IIFFLjava/lang/String;II)V` 参数序）。
///
///
/// 控制端（mobile `orchestration::build_input_event`）上线前已把归一化
/// `nx/ny` 按会话跟踪的编码分辨率换算成**像素** `x/y`（对齐桌面
/// `nx * base_w` 口径）——线上 `x/y` 的基数 = 编码分辨率 = 本服务端喂帧
/// 尺寸（`frame_base`）。上抛时**反向归一化**（`nx = x / base_w`，clamp
/// `[0,1]`）并同时给出 `base_w/base_h`，Kotlin 下棒按**屏幕真实尺寸**自
/// 行换算（`screen_px = nx * screen_w`；base 仅供核对/像素口径备用）。
/// 基数未知（尚无一帧喂入）→ `nx = ny = 0.0`（fail-soft：按钮事件 Kotlin
/// 侧可回退当前指针位，移动事件自然无效）。
#[derive(Debug, Clone, PartialEq)]
pub struct InputEventArgs {
    /// 事件种类（[`input_kind`] 常量）。
    pub kind: i32,
    /// 语义槽（按 `kind`）：键码（KeyDown/Up/Repeat）/ 按钮位标志
    /// （MouseButton）/ 滚轮增量（MouseWheel）/ `SpecialCombo` 判别式
    /// （SpecialKey）/ 0（MouseMove/Text）。
    pub key: i32,
    /// 归一化 x（0.0–1.0；仅 MouseMove/MouseButton 有效，其余 0.0）。
    pub nx: f32,
    /// 归一化 y（同 `nx`）。
    pub ny: f32,
    /// 修饰键位标志（wire 口径：1=Ctrl 2=Shift 4=Alt 8=Super；键事件有效）。
    pub modifiers: i32,
    /// Unicode 文本（仅 [`input_kind::TEXT`] 非空，其余恒空串——JNI 侧永不
    /// 传 null）。
    pub text: String,
    /// 编码分辨率基数宽（= 喂帧宽；0 = 尚无帧）。
    pub base_w: u32,
    /// 编码分辨率基数高（同 `base_w`）。
    pub base_h: u32,
}

/// 纯转换：wire [`WireInputEvent`] + 编码分辨率基数 → 上抛参数（无 I/O，
/// 宿主单测矩阵对象；JNI 上抛动作归 `crate::jni::deliver_input_event`）。
pub fn input_event_args(ev: &WireInputEvent, base: (u32, u32)) -> InputEventArgs {
    let kind = match ev.kind {
        InputKind::MouseMove => input_kind::MOUSE_MOVE,
        InputKind::MouseButton => input_kind::MOUSE_BUTTON,
        InputKind::MouseWheel => input_kind::MOUSE_WHEEL,
        InputKind::KeyDown => input_kind::KEY_DOWN,
        InputKind::KeyUp => input_kind::KEY_UP,
        InputKind::KeyRepeat => input_kind::KEY_REPEAT,
        InputKind::Text => input_kind::TEXT,
        InputKind::SpecialKey => input_kind::SPECIAL_KEY,
    };
    // `key` 语义槽（按 kind）。
    let key = match ev.kind {
        InputKind::KeyDown | InputKind::KeyUp | InputKind::KeyRepeat => ev.key as i32,
        InputKind::MouseButton => ev.button as i32,
        InputKind::MouseWheel => ev.wheel_delta,
        InputKind::SpecialKey => ev.combo.map(|c| c as i32).unwrap_or(0),
        InputKind::MouseMove | InputKind::Text => 0,
    };
    // 归一化坐标：仅鼠标位事件取值；基数未知 → (0.0, 0.0)（fail-soft，
    // 不 NaN/不 panic）；越界（恶意客户端 x > base）→ clamp [0,1]。
    let (nx, ny) = match ev.kind {
        InputKind::MouseMove | InputKind::MouseButton => {
            if base.0 > 0 && base.1 > 0 {
                (
                    (ev.x as f32 / base.0 as f32).clamp(0.0, 1.0),
                    (ev.y as f32 / base.1 as f32).clamp(0.0, 1.0),
                )
            } else {
                (0.0, 0.0)
            }
        }
        _ => (0.0, 0.0),
    };
    let text = if ev.kind == InputKind::Text {
        ev.text.clone()
    } else {
        String::new()
    };
    InputEventArgs {
        kind,
        key,
        nx,
        ny,
        modifiers: ev.modifiers as i32,
        text,
        base_w: base.0,
        base_h: base.1,
    }
}

/// 纯转换（含反序列化）：wire bytes + 编码分辨率基数 → 上抛参数。
///
/// `None` = 字节流不是合法 `injector::InputEvent`（红线⑥ 线格式违例）——
/// 调用方 fail-soft 丢弃（仅首次 warn），**绝不 panic**。
pub fn input_event_to_jni_args(payload: &[u8], base: (u32, u32)) -> Option<InputEventArgs> {
    let ev: WireInputEvent = bincode::deserialize(payload).ok()?;
    Some(input_event_args(&ev, base))
}

/// `NativeBridge.onServerInputEvent`（`crate::jni::deliver_input_event`，
/// 契约见 jni.rs 模块注释）；宿主机 = no-op——本 crate 约定宿主零 JNI
/// 依赖（`jni` 模块 `target_os = "android"` 门控），宿主 e2e 只验证消费
/// 路径（事件被真实解析转换、会话不被断），JNI 层归 Kotlin 下棒联调。
#[cfg(target_os = "android")]
fn deliver_input_event(args: &InputEventArgs) {
    crate::jni::deliver_input_event(args)
}
#[cfg(not(target_os = "android"))]
fn deliver_input_event(_args: &InputEventArgs) {}

// ════════════════════════════════════════════════════════════════
// Tests（宿主机纯函数单测；e2e 见 tests/server_loopback.rs）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cfg() -> ServerConfig {
        ServerConfig {
            nickname: "bob-phone".into(),
            challenge: "ch-123".into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_validate_ok_default() {
        assert!(base_cfg().validate().is_ok());
        assert_eq!(base_cfg().port, DEFAULT_LISTEN_PORT);
        assert!(!base_cfg().id_mode_enabled());
    }

    #[test]
    fn test_validate_requires_nickname() {
        let mut c = base_cfg();
        c.nickname = String::new();
        c.nickname = "   ".into();
        assert!(c.validate().is_err(), "trim 后空昵称必拒");
    }

    #[test]
    fn test_validate_id_mode_completeness() {
        // 单侧非空 → 错误（不静默降级）。
        let mut c = base_cfg();
        c.relay_server_addr = "relay.example.com:7000".into();
        assert!(c.validate().is_err(), "仅地址未配 token 必拒");
        c.relay_token = "tok".into();
        // 双非空但 server_pubkey 缺失 → fail-closed（ID-SEC-001）。
        assert!(
            c.validate()
                .unwrap_err()
                .contains("server_pubkey"),
            "ID 模式缺 server_pubkey 必 fail-closed"
        );
        c.relay_server_pubkey = "pubkey-base64".into();
        assert!(c.validate().is_ok());
        assert!(c.id_mode_enabled());
        // 全空 = 关闭 ID 模式（合法）。
        let c2 = base_cfg();
        assert!(!c2.id_mode_enabled());
        assert!(c2.validate().is_ok());
    }

    #[test]
    fn test_frame_feed_latest_wins() {
        let feed = FrameFeed::new();
        assert!(feed.take_latest(Duration::from_millis(10)).is_none());
        feed.push(ServerFrame {
            data: vec![1, 2, 3, 4],
            width: 1,
            height: 1,
            timestamp: SystemTime::now(),
        });
        // 未取走前再推一帧 → 槽内只留最新（丢旧保新，内存有界）。
        feed.push(ServerFrame {
            data: vec![9, 9, 9, 9],
            width: 1,
            height: 1,
            timestamp: SystemTime::now(),
        });
        let latest = feed.take_latest(Duration::from_millis(50)).expect("frame");
        assert_eq!(latest.data, vec![9, 9, 9, 9]);
        assert!(feed.take_latest(Duration::from_millis(10)).is_none());
    }

    #[test]
    fn test_frame_feed_wait_unblocks_on_push() {
        let feed = Arc::new(FrameFeed::new());
        let feed2 = Arc::clone(&feed);
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            feed2.push(ServerFrame {
                data: vec![7, 7, 7, 7],
                width: 1,
                height: 1,
                timestamp: SystemTime::now(),
            });
        });
        let t0 = Instant::now();
        let got = feed
            .take_latest(Duration::from_secs(2))
            .expect("push must unblock wait");
        h.join().unwrap();
        assert_eq!(got.data, vec![7, 7, 7, 7]);
        assert!(t0.elapsed() < Duration::from_millis(1500), "wait must return promptly on push");
    }


    const BASE: (u32, u32) = (1920, 1080);

    #[test]
    fn test_input_args_keydown_key_and_modifiers() {
        // KeyDown：key = wire 键码（A = 0x04），modifiers 位标志（Ctrl|Shift = 3），
        // 坐标/text 默认。
        let ev = WireInputEvent::key(InputKind::KeyDown, kirin_desk_input::injector::Key::A, 3);
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.kind, input_kind::KEY_DOWN);
        assert_eq!(a.key, 0x04, "wire 键码 = Key 判别式（HID 空间）");
        assert_eq!(a.modifiers, 3, "modifiers 位标志原样上抛");
        assert_eq!((a.nx, a.ny), (0.0, 0.0), "键事件无坐标语义");
        assert!(a.text.is_empty());
        assert_eq!((a.base_w, a.base_h), BASE, "编码分辨率基数原样上抛");
    }

    #[test]
    fn test_input_args_keyup() {
        let ev = WireInputEvent::key(InputKind::KeyUp, kirin_desk_input::injector::Key::Enter, 1);
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.kind, input_kind::KEY_UP);
        assert_eq!(a.key, 0x28, "Enter = HID 0x28");
        assert_eq!(a.modifiers, 1);
    }

    #[test]
    fn test_input_args_keyrepeat() {
        let ev = WireInputEvent::key(InputKind::KeyRepeat, kirin_desk_input::injector::Key::D, 0);
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.kind, input_kind::KEY_REPEAT);
        assert_eq!(a.key, 0x07, "D = A(0x04) + 3");
    }

    #[test]
    fn test_input_args_mousemove_normalized() {
        // 像素 (960, 540) @ 基数 (1920, 1080) → 归一化 (0.5, 0.5)。
        let ev = WireInputEvent::mouse_move(960, 540);
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.kind, input_kind::MOUSE_MOVE);
        assert!((a.nx - 0.5).abs() < f32::EPSILON, "nx = x / base_w");
        assert!((a.ny - 0.5).abs() < f32::EPSILON, "ny = y / base_h");
        assert_eq!(a.key, 0);
        assert_eq!((a.base_w, a.base_h), BASE);
    }

    #[test]
    fn test_input_args_mousemove_base_unknown() {
        // 基数未知（尚无一帧喂入）→ (0.0, 0.0)，不 NaN/不 panic（fail-soft）。
        let ev = WireInputEvent::mouse_move(960, 540);
        let a = input_event_args(&ev, (0, 0));
        assert_eq!((a.nx, a.ny), (0.0, 0.0));
        assert!(!a.nx.is_nan() && !a.ny.is_nan());
        assert_eq!((a.base_w, a.base_h), (0, 0));
    }

    #[test]
    fn test_input_args_mousemove_out_of_range_clamped() {
        // 恶意/故障客户端 x > base → clamp [0,1]（不越界上抛）。
        let ev = WireInputEvent::mouse_move(5000, 0);
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.nx, 1.0, "x > base_w → 1.0");
        assert_eq!(a.ny, 0.0);
    }

    #[test]
    fn test_input_args_button_down_left() {
        // 左键按下：button 位 1，坐标 (480, 270) → (0.25, 0.25)。
        let ev = WireInputEvent::mouse_button(kirin_desk_input::injector::button::LEFT, 480, 270);
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.kind, input_kind::MOUSE_BUTTON);
        assert_eq!(a.key, 1, "key 槽 = wire 按钮位标志（1=左）");
        assert!((a.nx - 0.25).abs() < f32::EPSILON);
        assert!((a.ny - 0.25).abs() < f32::EPSILON);
    }

    #[test]
    fn test_input_args_button_up_right() {
        // 右键抬起：位标志 2 | 0x80 = 0x82。
        let bits = kirin_desk_input::injector::button::RIGHT | kirin_desk_input::injector::button::RELEASE;
        let ev = WireInputEvent::mouse_button(bits, 0, 0);
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.kind, input_kind::MOUSE_BUTTON);
        assert_eq!(a.key, 0x82, "RELEASE 位（0x80）随按钮位上抛");
    }

    #[test]
    fn test_input_args_wheel() {
        // 滚轮：wheel_delta 进 key 槽，无坐标语义。
        let ev = WireInputEvent::mouse_wheel(120, 0, 0);
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.kind, input_kind::MOUSE_WHEEL);
        assert_eq!(a.key, 120, "WHEEL_DELTA 120/格 原样上抛");
        assert_eq!((a.nx, a.ny), (0.0, 0.0));
    }

    #[test]
    fn test_input_args_text_variant() {
        // Text：text 有效，其余默认；坐标/键默认。
        let ev = WireInputEvent::text("你好");
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.kind, input_kind::TEXT);
        assert_eq!(a.text, "你好", "Unicode 文本原样上抛");
        assert_eq!(a.key, 0);
        assert_eq!((a.nx, a.ny), (0.0, 0.0));
        assert_eq!(a.modifiers, 0);
    }

    #[test]
    fn test_input_args_text_only_carries_text() {
        // Text 事件即使夹带坐标/键字段也不上抛（口径：仅 text 有效）。
        let mut ev = WireInputEvent::text("x");
        ev.x = 100;
        ev.y = 200;
        ev.key = 0x41;
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.text, "x");
        assert_eq!(a.key, 0, "Text 的 key 槽恒 0");
        assert_eq!((a.nx, a.ny), (0.0, 0.0), "Text 不取坐标");
    }

    #[test]
    fn test_input_args_special_key_lock_screen() {
        // SpecialKey：key 槽 = SpecialCombo 判别式（LockScreen = 8）。
        let ev = WireInputEvent::special_key(kirin_desk_input::injector::SpecialCombo::LockScreen);
        let a = input_event_args(&ev, BASE);
        assert_eq!(a.kind, input_kind::SPECIAL_KEY);
        assert_eq!(a.key, special_combo::LOCK_SCREEN);
    }

    #[test]
    fn test_input_args_roundtrip_serialized_event() {
        // 端到端口径：bincode(wire 事件) → 上抛参数（与桌面服务端反序列化
        // 同型——控制端 build_input_event 产物必须被本函数接受）。
        let evs = vec![
            WireInputEvent::mouse_move(960, 540),
            WireInputEvent::mouse_button(kirin_desk_input::injector::button::LEFT, 10, 20),
            WireInputEvent::mouse_wheel(-120, 0, 0),
            WireInputEvent::key(InputKind::KeyDown, kirin_desk_input::injector::Key::A, 2),
            WireInputEvent::text("测试"),
        ];
        for ev in evs {
            let bytes = bincode::serialize(&ev).unwrap();
            let a = input_event_to_jni_args(&bytes, BASE).expect("合法 wire 必接受");
            assert_eq!(a, input_event_args(&ev, BASE), "两条路径同参");
        }
    }

    #[test]
    fn test_input_args_garbage_bytes_fail_soft() {
        // 非法字节流 → None（fail-soft 不 panic）：随机字节 / 空 / 异型数据。
        assert!(input_event_to_jni_args(&[0xFF; 3], BASE).is_none());
        assert!(input_event_to_jni_args(&[], BASE).is_none());
        // 合法 bincode 但非 InputEvent 类型（i32 线型）→ 必拒。
        let other = bincode::serialize(&42i32).unwrap();
        assert!(input_event_to_jni_args(&other, BASE).is_none());
        // 合法 InputEvent 尾截断 → 必拒（不半解析）。
        let ev = WireInputEvent::text("abcd");
        let mut bytes = bincode::serialize(&ev).unwrap();
        bytes.truncate(bytes.len() / 2);
        assert!(input_event_to_jni_args(&bytes, BASE).is_none());
    }
}
