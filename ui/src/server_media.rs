//!
//! 目标口径（用户裁定）：**捕获一次、编码一份、广播 N 个已认证连接**。
//!
//! - 旧实现（M9 单会话独占）：`server_channel()` 全局单槽，第二个控制端
//!   连入直接覆盖槽位，先连者断流。
//! - 本模块改为**会话注册表**（session_id → 观众条目）+ **帧广播总线**
//!   （每观众独立有界 mpsc 缓冲）：
//!   - 捕获+编码任务生命周期与单个会话解耦：首位观众接入启动，观众全退
//!     后经宽限（[`CAPTURE_GRACE`]，默认 5s）停止；服务端停止信号
//!   - 慢观众不拖快观众：每观众独立 [`VIEWER_BUFFER`] 深有界缓冲，满时
//!     丢非关键帧保新（跳到下一可解码帧），关键帧限时补投，超时踢出；
//!     观众发送失败/断开 → 从注册表移除，不影响其他观众。
//!   - 编码参数 MVP = 全场统一：捕获运行期间的编码标准记录在
//!     [`capture_codec_slot`]，后续观众握手协商经 [`converge_codec`]
//!     收敛为当前实际编码（口径见函数文档）。
//!
//! 输入多路共存（子项 5）：每观众读半通道仍由各连接的接收分发任务独占
//! （见 `lib.rs::handle_incoming_connection`），多观众输入事件全部注入。
//!
//! → 分发任务读错退出 → `remove_viewer`；②发送失败（视频帧写死连接出错）
//! → 观众发送任务退出 → `remove_viewer`；③异常断开（进程被杀/断网，无
//! FIN）→ `TcpServer::accept` 启用的 TCP keepalive（core `set_keepalive`，
//! ≈30s 检测窗口）把半开连接变成读错 → 回到 ①。踢出路径（broadcast 缓冲
//! 关闭/关键帧补投超时）同样收敛生命周期（清零即排宽限停捕获）。
//!
//! 架构红线保持：编码统一 FFmpeg libavcodec（本模块只编排，不动编码器
//! 内部）；每会话 SecureChannel 各自加密（广播发生在**明文 EncodedPacket
//! 层**，各观众发送任务独立走自己的加密写半通道）；传输主路径
//! QUIC/TCP 现状；fail-closed。

use std::collections::{HashMap, VecDeque};
use std::ptr;
use std::sync::atomic::{
    AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering,
};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use kirin_desk_input::injector::InputInjector;
use kirin_desk_media::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use kirin_desk_media::encoder::Codec;
use kirin_desk_media::transport::{ControlMessage, SecureChannelSender};
use tracing::{debug, info, warn};

///
/// 服务端三段：`enc`（capture 提交→编码完成）/ `bus`（编码完成→广播总线）/
/// `sendq`（观众发送任务出队→写完成）。capture 时刻经 wire `PacketHeader.pts`
/// 旁路带给客户端（仅开启时；未开启 `pts=0` 与现状逐字节一致）。
pub(crate) use crate::latency_trace;

/// 每观众共享写半通道（与文件传输/控制回复共用，保证帧边界）。
pub(crate) type SharedSender = Arc<tokio::sync::Mutex<SecureChannelSender>>;

/// 每观众独立有界缓冲深度（编码窗口/音频批次排队上限；满 → 丢帧保新）。
pub(crate) const VIEWER_BUFFER: usize = 8;

/// 观众全退后的捕获宽限：宽限期内新观众接入则取消停止，仍为 0 则停捕获。
pub(crate) const CAPTURE_GRACE: Duration = Duration::from_secs(5);

/// 后 + 本时长内**该观众零新帧**（最近一帧早于加入时刻 / 从未有帧）→ 判
/// 捕获僵死（进程内 stop 后状态未清的僵尸态，或静屏下新观众拿不到任何
/// 可解码内容）→ 强制清态重启。3s ≫ 健康加入延迟（首帧 ~0.3-1.5s：编码
/// 器初始化 + 首窗 + 广播），静屏健康捕获由重启后 DXGI 初始全帧 IDR 兜底
/// （新捕获源首帧恒 = 当前桌面全图），不会误杀动态画面。
pub(crate) const NO_FRAME_RESTART_SECS: u64 = 3;

/// [`r134_1_cap_live_line`]：行的存在 = 本世代广播循环存活；行内
/// `last_frame_age_ms` 持续增长 = 无帧在产（与无帧看门狗互为印证）。
pub(crate) const CAPTURE_LIVE_TICK_SECS: u64 = 5;

/// 慢观众关键帧补投超时——超时即判定该观众发送任务说明死/链路僵死，
/// 从注册表踢出（不 backpressure 编码循环、不拖其他观众）。
const KEY_DELIVER_TIMEOUT: Duration = Duration::from_millis(200);

/// 观众条目：注册表值。
pub(crate) struct ViewerEntry {
    /// 对端身份（注册表元数据；后续任务如按观众审计/定向控制消费）。
    #[allow(dead_code)]
    pub peer_id: String,
    /// 该观众握手协商出的编码标准（首位观众的值决定捕获任务编码）。
    pub negotiated_codec: Codec,
    /// 广播缓冲写半（编码任务 try_send；观众发送任务 recv 后写加密通道）。
    pkt_tx: tokio::sync::mpsc::Sender<EncodedPacket>,
    /// 慢观众标记：缓冲满后置位，期间非关键帧全部跳过，直到关键帧成功
    /// 入队后复位（「跳过至下一可解码帧」的简化实现）。
    lagging: bool,
    ///
    /// 关键帧补投超时/通道关闭踢出前注入 `ControlMessage::Disconnect`
    /// **biased 最高优先**消费本通道（先于帧队列/心跳）。独立于帧队列的
    /// Full 丢失；本通道不占帧缓冲。条目 drop → 本发送端随之 drop →
    /// 发送任务分支降级（None-ready 防饿死，见 [`viewer_send_task`]）。
    end_tx: tokio::sync::mpsc::Sender<EncodedPacket>,
}

/// （`pkt_tx`/`lagging`/`end_tx` 不对外暴露构造面），本构造器与
/// `register_reserved_viewer` 内部构造逐位同构（`lagging: false` 初值），
/// 并返回 [`viewer_send_task`] 所需的两个读半句柄。仅 `#[cfg(test)]` 编译
#[cfg(test)]
pub(crate) fn viewer_entry_for_test(
    peer_id: String,
    codec: Codec,
) -> (
    ViewerEntry,
    tokio::sync::mpsc::Receiver<EncodedPacket>,
    tokio::sync::mpsc::Receiver<EncodedPacket>,
) {
    let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel(VIEWER_BUFFER);
    let (end_tx, end_rx) = tokio::sync::mpsc::channel(1);
    (
        ViewerEntry {
            peer_id,
            negotiated_codec: codec,
            pkt_tx,
            lagging: false,
            end_tx,
        },
        pkt_rx,
        end_rx,
    )
}

/// 会话注册表：session_id → 观众条目。
fn server_sessions() -> &'static tokio::sync::Mutex<HashMap<u64, ViewerEntry>> {
    static S: OnceLock<tokio::sync::Mutex<HashMap<u64, ViewerEntry>>> = OnceLock::new();
    S.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

/// 观众计数镜像（原子读，供 UI 每帧/宽限判定等同步上下文无锁读取）。
fn viewer_count_atomic() -> &'static AtomicUsize {
    static C: OnceLock<AtomicUsize> = OnceLock::new();
    C.get_or_init(|| AtomicUsize::new(0))
}

/// `egui::Context` 为 `Clone + Send + Sync`）。
///
/// 病机：服务端「连接中 {N}」徽标（`lib.rs` 每帧读 [`viewer_count`]）依赖 egui
/// 重绘，而观众注册/注销/踢出状态迁移全部发生在 tokio 自由任务（分发任务
/// 清理段 / 观众发送任务 / 补投看门狗——均无 egui Context）且**零
/// request_repaint** → 客户端托盘退出（FIN）后断连清退全部完成，空闲主窗
/// 却停留最后一帧「连接中 1」直到下次鼠标/键盘输入。
///
/// 修复：在计数变更汇聚点（[`insert_viewer`] / [`remove_viewer_inner`] /
/// 踢出循环）经本槽对主窗请求重绘 → 徽标 ≤1s 自行消失。未存入（首帧前）
/// → no-op（此时徽标未呈现，无陈旧帧可言）。
fn main_window_ctx() -> &'static OnceLock<egui::Context> {
    static C: OnceLock<egui::Context> = OnceLock::new();
    &C
}

/// 存入主窗 Context——**首次胜出**（OnceLock 语义，幂等）。
/// 快路径 `get()` 先行：已装入则零成本返回，避免逐帧 `Context::clone`。
fn install_ctx_in(slot: &OnceLock<egui::Context>, ctx: &egui::Context) -> bool {
    if slot.get().is_some() {
        return false;
    }
    slot.set(ctx.clone()).is_ok()
}

///
/// `hidden` = 主窗隐藏态门控（与 `lib.rs::main_repaint` 同口径：隐藏窗不收
/// WM_PAINT，重绘请求无效且致 eframe 陈旧 deadline busy 泵；窗口恢复时
/// ShowMain 路径自身 `request_repaint` 的新帧会读到最新 `viewer_count`，
/// 徽标状态在可见时必正确）。
fn request_main_repaint_in(slot: &OnceLock<egui::Context>, hidden: bool) {
    if hidden {
        return;
    }
    if let Some(ctx) = slot.get() {
        ctx.request_repaint();
    }
}

/// 快路径返回）。返回本次是否实际装入。
pub(crate) fn install_main_window_ctx(ctx: &egui::Context) -> bool {
    install_ctx_in(main_window_ctx(), ctx)
}

/// ctx 未存入时 no-op——tokio 自由任务安全，`request_repaint` 为 `&self`）。
pub(crate) fn request_main_repaint() {
    request_main_repaint_in(main_window_ctx(), crate::tray::is_main_window_hidden())
}

/// 观众 id 分配器（会话注册表键，进程内单调）。
fn viewer_next_id() -> &'static AtomicU64 {
    static I: OnceLock<AtomicU64> = OnceLock::new();
    I.get_or_init(|| AtomicU64::new(0))
}

/// 捕获任务运行标志（注册/宽限生命周期判定用）。
fn capture_running() -> &'static AtomicBool {
    static R: OnceLock<AtomicBool> = OnceLock::new();
    R.get_or_init(|| AtomicBool::new(false))
}

/// 宽限停止标志：宽限到期且观众仍为 0 → 置位，捕获循环轮询后退出。
fn capture_grace_stop() -> &'static AtomicBool {
    static G: OnceLock<AtomicBool> = OnceLock::new();
    G.get_or_init(|| AtomicBool::new(false))
}

/// 宽限代数：新观众接入即递增，使旧的宽限计时器失效（取消停止）。
fn grace_generation() -> &'static AtomicU64 {
    static G: OnceLock<AtomicU64> = OnceLock::new();
    G.get_or_init(|| AtomicU64::new(0))
}

/// 当前捕获任务实际使用的编码标准（编码参数全场统一口径的事实源；
/// 捕获启动写入、退出清空；握手协商收敛 [`converge_codec`] 读取）。
fn capture_codec_slot() -> &'static Mutex<Option<Codec>> {
    static C: OnceLock<Mutex<Option<Codec>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

///（移动端 1280 等；0 = 原生）。捕获启动写入、退出清空；后连观众口径同
/// [`converge_codec`]（跟随在场流，不重建）。
fn capture_max_width_slot() -> &'static AtomicU32 {
    static W: OnceLock<AtomicU32> = OnceLock::new();
    W.get_or_init(|| AtomicU32::new(0))
}

///（降采样激活时 out ≠ native；连接分发任务注入前据此把客户端坐标从
/// 编码分辨率换算到原生屏幕分辨率）。None = 捕获未运行 / 无降采样。
fn capture_coord_dims() -> &'static Mutex<Option<(u32, u32, u32, u32)>> {
    static D: OnceLock<Mutex<Option<(u32, u32, u32, u32)>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(None))
}

/// [`reset_capture_state_on_stop`] / 无帧强制重启各递增一次）。
///
/// 用途 = **垂死任务安全退出**的世代守卫：捕获任务 spawn 时捕获本世代，
/// 单轮 `run_capture_once` 返回后比对——失配 = 已有更新世代（stop 确定性
/// 重置 / 强制重启）接管状态所有权 → 本任务**不碰任何状态、不释放输入**
/// 直接退出（旧实现无此守卫：垂死任务晚到的 `capture_running=false` /
/// codec 清槽会踩掉新捕获的状态 = 09-22 复现链的状态污染放大因子；其
/// 自清理又依赖自身不被卡住 = 「垂死任务自清理不可靠」根因）。
fn capture_generation() -> &'static AtomicU64 {
    static G: OnceLock<AtomicU64> = OnceLock::new();
    G.get_or_init(|| AtomicU64::new(0))
}

/// 逐窗打戳；0 = 进程内从未广播过）。消费：① 无帧强制重启看门狗的
/// 「该观众加入后零新帧」判据（[`r134_1_no_frame_decision`]）② 活性 tick
/// 行 [`r134_1_cap_live_line`] 的 `last_frame_age_ms` 字段。
///
/// 口径说明：广播 = 捕获环产出窗口并进入总线（与有无观众无关）；静屏下
/// 无新帧 = 本时戳停止推进 = 看门狗判据的触发素材（重启后 DXGI 初始全帧
/// IDR 兜底交付，见 [`NO_FRAME_RESTART_SECS`] 文档）。
fn last_video_frame_ms() -> &'static AtomicU64 {
    static L: OnceLock<AtomicU64> = OnceLock::new();
    L.get_or_init(|| AtomicU64::new(0))
}

pub(crate) fn capture_coord_scale() -> Option<(u32, u32, u32, u32)> {
    *capture_coord_dims().lock().unwrap()
}

pub(crate) fn output_dims_for(native_w: u32, native_h: u32, max_width: u32) -> (u32, u32) {
    if max_width > 0 && native_w > 0 && native_w > max_width {
        let h = ((native_h as u64 * max_width as u64) / native_w as u64).max(1) as u32;
        (max_width, h)
    } else {
        (native_w, native_h)
    }
}

/// 共享输入注入器（捕获任务创建并随显示器切换更新分辨率基准；
/// 各连接分发任务读取使用——多观众输入全部注入同一桌面会话）。
pub(crate) fn server_input_injector(
) -> &'static OnceLock<Arc<tokio::sync::Mutex<InputInjector>>> {
    static I: OnceLock<Arc<tokio::sync::Mutex<InputInjector>>> = OnceLock::new();
    &I
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// 交互地板宽限窗（ms）：最近输入距今 ≤ 此值 → 地板生效（目标帧率至少
/// 慢速鼠标移动（两次移动间隔 >200ms）与操作停顿期间地板失效，tile 采样
/// 活动度为 0 → 连续 3 窗钉死 1fps（用户「鼠标移动后画面才跟上」的另一
/// 根因）；2000ms 覆盖操作停顿与 WAN 输入回包（客户端输入包 → 服务端
/// 打戳，RTT 100-300ms 量级），人在操作期间（含停顿）持续中间档。
/// 地板值保持 `low_fps`（30fps，生产档位配置）。
pub(crate) const CLIENT_INPUT_FLOOR_MS: u64 = 2000;

fn last_client_input_ms() -> &'static AtomicU64 {
    static L: OnceLock<AtomicU64> = OnceLock::new();
    L.get_or_init(|| AtomicU64::new(0))
}

/// 零分配（一次原子 store）；trace 门控无关（SystemTime 直读）。
pub(crate) fn mark_client_input() {
    last_client_input_ms().store(latency_trace::epoch_ms(), Ordering::Relaxed);
}

/// `last_ms = 0`（从未有输入）→ false；时钟回拨（`now < last`）→
/// saturating 得 0 → true（安全侧：保持地板，流畅优先）。
pub(crate) fn client_input_recent(last_ms: u64, now_ms: u64) -> bool {
    last_ms != 0 && now_ms.saturating_sub(last_ms) <= CLIENT_INPUT_FLOOR_MS
}

///
/// - `static_ratio` 默认 0.001 是 **1080p 单 tile 量级**（1/510）。4K 屏
///   单 tile = 1/2040 ≈ 0.00049 < 0.001 → 光标级小变化（悬停/菜单/光标
///   拖动引起的局部重绘）被误判「静态」钉死 1fps——用户「鼠标移动后画面
///   才跟上」的高分辨率根因之一。精化到 0.0002：4K/5K 单 tile 活动度
///   （≥0.00031）留在中间档，真正静止屏（0 活动度）仍降静态档；
pub(crate) fn r68a_fps_governor_config() -> kirin_desk_media::adaptive::FpsGovernorConfig {
    kirin_desk_media::adaptive::FpsGovernorConfig {
        static_fps: 1.0,
        low_fps: 30.0,
        motion_fps: 60.0,
        static_ratio: 0.0002,
        ..kirin_desk_media::adaptive::FpsGovernorConfig::default()
    }
}

///
/// `InputInjector::release_all` 只释放真正按下的按钮（对未按下键发 up 为
/// 无害 no-op）并复位修饰键 / Move 守卫状态——二次调用为零事件 no-op，
/// 故各会话结束路径（观众断开 / 捕获宿主停止 / 媒体会话收尾钩子）可各自
/// 调用、无需协调（双接线依赖此幂等性）。
async fn release_shared_input_state() {
    if let Some(inj) = server_input_injector().get() {
        inj.lock().await.release_all();
    }
}

///（`GetAsyncKeyState`，含左右 Win）→ 非空则一次 SendInput 批**全释放**
///（含 Win），INFO 对账行；全空也打一行（复测对账锚点）。
///
/// 背景（用户两轮复测）：第一轮 Ctrl+O 弹 OSK（=系统热键 Ctrl+Win+O）、
/// 第二轮 Ctrl+C/Ctrl+V 失效——并存现象与「被控端 Win 键残留按下态」假设
/// **启动侧对称补齐**：退出侧只释放「本注入器按下的状态」，不管会话开始
/// 时被控端本地已残留的物理按下态。
///
/// 口径：
/// - **接入时机** = `run_capture_once` 注入器创建后、槽 set 前——连接分发
///   任务读到槽才开始注入，故卫生释放严格先于任何输入注入；捕获致命错误
///   重启（退避循环）每轮再跑一次，同时兜住重启前旧实例漏放的残留
///   （退避路径不走退出侧 release，幂等、无副作用）；
/// - **幂等**：重复调用只多一行日志，up 未按下键为无害 no-op；
/// - **失败不阻断会话**：SendInput 失败 → WARN 继续（残留可能仍在，日志
///   位图 = 复测取证）。
fn input_hygiene_release() {
    let (plan, ok) = kirin_desk_input::windows::hygiene_release_residual_modifiers();
    if plan == 0 {
    } else if ok {
        info!(
            if plan & kirin_desk_input::injector::modifier::SUPER != 0 {
                " (incl. super)"
            } else {
                ""
            }
        );
    } else {
        warn!(
             session continues (residual may persist)"
        );
    }
}

/// 显示器切换请求（连接分发任务 → 捕获循环；携带请求方 session_id
/// 供 Nack 定向回复）。
pub(crate) struct SwitchRequest {
    pub session_id: u64,
    pub index: u32,
}

/// 显示器切换请求通道（捕获任务置入，退出时清空）。
fn switch_request_tx(
) -> &'static Mutex<Option<tokio::sync::mpsc::UnboundedSender<SwitchRequest>>> {
    static T: OnceLock<Mutex<Option<tokio::sync::mpsc::UnboundedSender<SwitchRequest>>>> =
        OnceLock::new();
    T.get_or_init(|| Mutex::new(None))
}

/// 连接分发任务调用：请求热切换显示器（失败由捕获循环回 Nack）。
pub(crate) fn request_switch_monitor(session_id: u64, index: u32) {
    let guard = switch_request_tx().lock().unwrap();
    if let Some(tx) = guard.as_ref() {
        if tx.send(SwitchRequest { session_id, index }).is_err() {
            warn!("DisplaySelect: switch channel closed");
        }
    } else {
        warn!("DisplaySelect: capture task not running");
    }
}

/// 当前观众数（原子镜像读，同步上下文安全）。
pub(crate) fn viewer_count() -> usize {
    viewer_count_atomic().load(Ordering::Relaxed)
}

/// 共享静态注册表〔观众表/受控判定槽〕被**跨模块**测试共享：`r62_tests`
/// `register_viewer` 真实注册观众）必须共用同一把锁串行化，否则并行时
/// `viewer_count()` 断言互相污染（r673 实测 2≠1 回归）。std Mutex 守卫跨
/// await 是故意避免的：这里用 tokio Mutex 的测试专用串行锁。
#[cfg(test)]
pub(crate) fn test_serial() -> &'static tokio::sync::Mutex<()> {
    static L: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    L.get_or_init(|| tokio::sync::Mutex::new(()))
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy)]
pub(crate) struct WindowPacingSample {
    /// 窗口号（window_id）。
    pub window_id: u64,
    /// 广播时刻（进入 broadcast 的 Instant）。
    pub broadcast: Instant,
    /// 窗口内编码帧数。
    pub frames: u32,
    /// 窗口 bincode 序列化字节数（网络发送量）。
    pub bytes: usize,
    /// 窗口编码耗时（毫秒）。
    pub encode_ms: f64,
}

/// 节奏样本环形缓冲上限（保留最近若干秒的窗口记录，供测试/诊断读取）。
const WINDOW_PACING_CAP: usize = 8192;

fn window_pacing_log() -> &'static Mutex<VecDeque<WindowPacingSample>> {
    static L: OnceLock<Mutex<VecDeque<WindowPacingSample>>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(VecDeque::with_capacity(WINDOW_PACING_CAP)))
}

/// 记录一个窗口样本（broadcast_encoded_window 内调用；容量上限时丢弃最旧）。
pub(crate) fn record_window_pacing(sample: WindowPacingSample) {
    let mut q = window_pacing_log().lock().unwrap();
    if q.len() >= WINDOW_PACING_CAP {
        q.pop_front();
    }
    q.push_back(sample);
}

/// 读取节奏样本快照（测试/诊断用）。
#[allow(dead_code)]
pub(crate) fn window_pacing_snapshot() -> Vec<WindowPacingSample> {
    window_pacing_log().lock().unwrap().iter().copied().collect()
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// 编码线程逐帧消费（`swap` 取走）。
fn capture_force_idr() -> &'static AtomicBool {
    static F: OnceLock<AtomicBool> = OnceLock::new();
    F.get_or_init(|| AtomicBool::new(false))
}

/// 请求下一帧强制 IDR（幂等；多方共用了无妨——多一次 IDR 只是码率尖峰）。
pub(crate) fn request_capture_idr() {
    capture_force_idr().store(true, Ordering::Relaxed);
}

fn bitrate_tier() -> &'static AtomicU32 {
    static T: OnceLock<AtomicU32> = OnceLock::new();
    T.get_or_init(|| AtomicU32::new(0))
}

/// 迟滞基准。
fn last_lag_ms() -> &'static AtomicU64 {
    static L: OnceLock<AtomicU64> = OnceLock::new();
    L.get_or_init(|| AtomicU64::new(0))
}

fn last_idr_request_ms() -> &'static AtomicU64 {
    static L: OnceLock<AtomicU64> = OnceLock::new();
    L.get_or_init(|| AtomicU64::new(0))
}

fn last_tier_change_ms() -> &'static AtomicU64 {
    static L: OnceLock<AtomicU64> = OnceLock::new();
    L.get_or_init(|| AtomicU64::new(0))
}

/// 最高降档档位（1/2 → 1/4 → 1/8 → 1/16 基准码率）。
pub(crate) const MAX_BITRATE_TIER: u32 = 3;

/// 慢观众积压后多久允许再降一档（毫秒）——给当前档位留收敛窗口。
const TIER_STEP_DOWN_INTERVAL_MS: u64 = 2_000;

/// 持续无积压多久后升回一档（毫秒）——迟滞防振荡。
const TIER_STEP_UP_QUIET_MS: u64 = 30_000;

/// 慢观众恢复 IDR 请求限速（毫秒）。
const IDR_REQUEST_INTERVAL_MS: u64 = 1_000;

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn tier_bitrate_for(base_bps: u64, tier: u32) -> u64 {
    (base_bps >> tier.min(MAX_BITRATE_TIER)).max(1_000_000)
}

///
/// 捕获启动恒置 0（fail = 常态阶梯）；观众会话建立/点选时客户端推送当前
/// 显示模式档（app 级静态记忆，`ui::display_mode()`）。多观众共享编码器
/// = **最后推送者生效**（与 DisplaySelect 共享捕获热切换同语义
fn r126b_quality_high() -> &'static AtomicU8 {
    static M: OnceLock<AtomicU8> = OnceLock::new();
    M.get_or_init(|| AtomicU8::new(0))
}

///
/// - **非高画质**：`tier==0` → `None`（阶梯全档，零覆盖）；`tier>0` →
///   [`tier_bitrate_for`] 现状口径（**零行为变化**）。
/// - **高画质**：`tier_bitrate_for(base*2, tier)` = 阶梯基准 2× 再按降档档
///   减半（tier 0 = 2× 基准〔1080p 10M→20M ≈ 0.32bpp@30fps，rate_ladder
///   模块口径 ≥0.10=良好之上〕；tier n = 2× 基准经 n 次减半）。
///   **慢网络积压降档保护不变**（流畅优先红线不破坏：高画质只抬基准、
///   不封死降档，`on_viewer_lag` 降档照常生效）。
pub(crate) fn r126b_quality_bitrate_for(
    base_bps: u64,
    tier: u32,
    high_quality: bool,
) -> Option<u64> {
    let t = tier.min(MAX_BITRATE_TIER);
    if high_quality {
        Some(tier_bitrate_for(base_bps.saturating_mul(2), t))
    } else if t == 0 {
        None
    } else {
        Some(tier_bitrate_for(base_bps, t))
    }
}

///
/// `mode` = 客户端 `DisplayMode as u8`（0 流畅 / 1 低延迟 / 2 高画质，ui 侧
/// 唯一定义点）；**只消费高画质位**（2 → 1，其余含未知值 → 0 = fail-safe
/// 向常态——旧客户端不发本消息 = 恒 0 = 现状零变化）。幂等：同值不刷日志；
/// 编码循环按 (tier, 高画质) 组合变化点统一重算 override 并强制 IDR 重开。
pub(crate) fn apply_display_mode_request(mode: u8) {
    let hq = u8::from(mode == 2);
    let prev = r126b_quality_high().load(Ordering::Relaxed);
    if prev != hq {
        r126b_quality_high().store(hq, Ordering::Relaxed);
        info!(
            mode,
            if hq == 1 { "high quality (2x ladder base)" } else { "normal" }
        );
    }
}

pub(crate) fn tier_should_step_down(tier: u32, now_ms: u64, last_change_ms: u64) -> bool {
    tier < MAX_BITRATE_TIER && now_ms.saturating_sub(last_change_ms) >= TIER_STEP_DOWN_INTERVAL_MS
}

pub(crate) fn tier_should_step_up(
    tier: u32,
    now_ms: u64,
    last_lag_at_ms: u64,
) -> bool {
    tier > 0 && now_ms.saturating_sub(last_lag_at_ms) >= TIER_STEP_UP_QUIET_MS
}

/// 时长 / 观众缓冲 `w` 帧期 = **误触发填充比**（阈值复核模型，单测钉死）。
///
/// 模型口径（推导与结论见交付报告；30fps 生产帧率档）：
/// - ABR 目标码率 `stream_bps`（rate_ladder 阶梯 × HQ 倍率；T4 GOP 变化
///   （保守上界 2）；
/// - ABR 每 GOP 比特预算 = `stream_bps × gop / 30` →
///   P = 预算 / (k + gop − 1)；
/// - 最坏 `w` 连续帧窗含 `n_idr = (w−1)/gop + 1` 个 IDR（窗首对齐 GOP
///   边界多拿一个；gop≥w 时恒 1）；
/// - 观众每帧恰一包、通道 [`VIEWER_BUFFER`] = 8 **槽位**（`broadcast_packet`
///   `try_send` 按包计数，**不按字节**——I 帧体积大不占额外槽）；
/// - 误触发（队列满 → 非关键帧丢弃 → `on_viewer_lag` → 降档）= 发送任务
///   对最坏 `w` 帧窗的发送时长 ≥ `w/30` s（发送速率持续低于 30fps 生产节奏）。
///
/// 返回 `<1` = I 帧开销单独**不能**填满缓冲（无误触发）；`>1` = 链路已
/// 30s 迟滞自愈合，非 T4 误触发）。
///
/// 仅单测消费（诊断纯函数，不进生产热路径）→ `dead_code` 豁免同
/// [`window_pacing_snapshot`] 先例（保持 release 警告恰 4 位点零漂移）。
#[allow(dead_code)]
pub(crate) fn r136_gop_burst_fill_ratio(
    gop: u32,
    ip_ratio: f64,
    stream_bps: u64,
    link_bps: u64,
    window_frames: u32,
) -> f64 {
    if gop == 0 || link_bps == 0 || window_frames == 0 {
        return f64::INFINITY;
    }
    let n_idr = (((window_frames - 1) / gop) + 1).min(window_frames);
    let fps = 30u64;
    let p_bits = stream_bps as f64 * gop as f64
        / fps as f64
        / (ip_ratio + gop as f64 - 1.0);
    let burst_bits = p_bits * (ip_ratio * n_idr as f64 + (window_frames - n_idr) as f64);
    burst_bits / link_bps as f64 / (window_frames as f64 / fps as f64)
}

/// 降画质保流畅：① 限速请求强制 IDR（慢观众跳到可解码点）；② 限速降一档
/// 码率（编码器按新码率重开）。
fn on_viewer_lag() {
    let now = now_epoch_ms();
    last_lag_ms().store(now, Ordering::Relaxed);
    if now.saturating_sub(last_idr_request_ms().load(Ordering::Relaxed))
        >= IDR_REQUEST_INTERVAL_MS
    {
        last_idr_request_ms().store(now, Ordering::Relaxed);
        request_capture_idr();
    }
    let tier = bitrate_tier().load(Ordering::Relaxed);
    if tier_should_step_down(
        tier,
        now,
        last_tier_change_ms().load(Ordering::Relaxed),
    ) {
        bitrate_tier().store(tier + 1, Ordering::Relaxed);
        last_tier_change_ms().store(now, Ordering::Relaxed);
        warn!(
            tier + 1
        );
    }
}

/// （回到阶梯全档为上限），升档点请求 IDR 给降码率重开一个干净起点。
fn maybe_tier_step_up() {
    let now = now_epoch_ms();
    let tier = bitrate_tier().load(Ordering::Relaxed);
    if tier_should_step_up(tier, now, last_lag_ms().load(Ordering::Relaxed)) {
        bitrate_tier().store(tier - 1, Ordering::Relaxed);
        last_tier_change_ms().store(now, Ordering::Relaxed);
        last_lag_ms().store(now, Ordering::Relaxed); // 重置迟滞窗口。
        request_capture_idr();
    }
}

// ════════════════════════════════════════════════════════════════
// 生命周期决策（纯函数，可测）
// ════════════════════════════════════════════════════════════════

/// 观众数变化后的捕获生命周期决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureAction {
    /// 无观众 → 有观众且捕获未运行 → 启动捕获。
    Start,
    /// 有观众 → 无观众且捕获运行中 → 排定宽限停止。
    ScheduleGraceStop,
    /// 无动作（观众增减但状态不变）。
    None,
}

/// 纯函数：观众数变化后的捕获动作。
pub(crate) fn capture_action_on_viewer_change(
    running: bool,
    viewers_after: usize,
) -> CaptureAction {
    if viewers_after > 0 {
        if running {
            CaptureAction::None
        } else {
            CaptureAction::Start
        }
    } else if running {
        CaptureAction::ScheduleGraceStop
    } else {
        CaptureAction::None
    }
}

/// 纯函数：宽限到期时是否停止捕获（观众仍为 0 → 停）。
pub(crate) fn grace_expired_should_stop(viewers_now: usize) -> bool {
    viewers_now == 0
}

/// 慢观众丢帧决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LagSkip {
    /// 正常投递。
    Send,
    /// 慢观众 + 非关键帧 → 跳过（丢弃至下一可解码帧）。
    Skip,
}

/// 纯函数：慢观众收到一包的投递决策（关键帧始终尝试送达以恢复解码）。
pub(crate) fn lag_skip_decision(lagging: bool, is_key: bool) -> LagSkip {
    if lagging && !is_key {
        LagSkip::Skip
    } else {
        LagSkip::Send
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

///
/// 根因（79 实机 17:11:07.419→17:11:10.655 3.2s 窗口零日志落点）：修复前
/// `server_audio_allowed`（默认关）兼作**任务 spawn 门控**——
/// `run_capture_once` 只在捕获任务启动时判一次（修复前本文件该 if 条件含
/// `&& crate::server_audio_allowed()`）。默认关 ⇒ 会话建立时开关为关的
/// 会话里音频任务从未被 spawn；会话中途开开关只写原子量 + setter 日志
/// （lib.rs `set_server_audio_allowed`），无任务消费 ⇒ 无启动尝试 / 成功 /
/// 失败任何落点。修复后音频任务只受总开关门控（常驻），子开关由本状态机
/// 逐轮驱动（空闲轮询 ≤50ms，中途开/关 ≤100ms 生效，远优于 ≤2s 目标）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AudioToggleAction {
    /// 关→开（或开但无流水线且无近期失败）→ 创建 + 启动捕获
    /// （日志三落点：尝试 INFO / 成功 INFO / 失败 WARN）。
    Start,
    /// 开且捕获运行中 → 保持消费发送。
    Running,
    /// 开→关（或关但流水线在跑）→ 停止捕获 + 释放线程（INFO 落点）。
    Stop,
    /// 开但上一次启动失败 → 等待（开关保持开时不重试——无声卡场景
    /// 避免 WARN 风暴；下一次 关→开 边沿重置并重新尝试）。
    WaitRetry,
    /// 关且无流水线 → 低频空闲轮询。
    Idle,
}

///
/// 不变式：`pipeline_ready` ⟺ 音频任务实际持有 `AudioPipeline`。任务按
/// [`AudioToggleAction`] 施动后经 [`mark_started`] / [`mark_start_failed`]
/// 回报；`Stop` 时机器自行复位（关→开边沿重置 `start_failed`——每次
/// 重新开启都是一次新的启动尝试，PM 口径 b「重开→重新启动捕获」）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct AudioToggleMachine {
    /// 捕获流水线存在且运行中。
    pipeline_ready: bool,
    /// 上一次启动尝试失败（等待 关→开 边沿重置）。
    start_failed: bool,
    /// 上一轮的开关值（识别 关→开 边沿用）。
    last_enabled: bool,
}

impl AudioToggleMachine {
    /// 初始态：开关默认关 + 无流水线。
    pub(crate) fn new() -> Self {
        Self {
            pipeline_ready: false,
            start_failed: false,
            last_enabled: false,
        }
    }

    /// 单轮决策：输入 = 当前开关值；返回本轮动作（仅内部簿记，不改真实
    /// 流水线——施动与回报由任务侧完成）。
    pub(crate) fn step(&mut self, enabled: bool) -> AudioToggleAction {
        let action = if enabled {
            if self.pipeline_ready {
                AudioToggleAction::Running
            } else if self.start_failed && self.last_enabled {
                // 开关保持开 + 已失败 → 不重试（失败 WARN 只打一次/次开启）。
                AudioToggleAction::WaitRetry
            } else {
                // 首次开 或 关→开 边沿 → 重置失败标记，重新尝试。
                self.start_failed = false;
                AudioToggleAction::Start
            }
        } else if self.pipeline_ready {
            self.pipeline_ready = false;
            self.start_failed = false;
            AudioToggleAction::Stop
        } else {
            AudioToggleAction::Idle
        };
        self.last_enabled = enabled;
        action
    }

    /// 启动成功 → 机器对齐「流水线在跑」。
    pub(crate) fn mark_started(&mut self) {
        self.pipeline_ready = true;
        self.start_failed = false;
    }

    /// 启动失败 / 流水线运行期错误 → 等待 关→开 边沿再尝试。
    pub(crate) fn mark_start_failed(&mut self) {
        self.pipeline_ready = false;
        self.start_failed = true;
    }
}

impl Default for AudioToggleMachine {
    fn default() -> Self {
        Self::new()
    }
}

///
/// 端点固定 = 默认渲染端点（eRender/eConsole）+ 环回标志（wasapi.rs
/// `run_capture_inner`）；目标格式 = 48000Hz/2ch float32 → Opus
/// 48kHz/stereo/64kbps/20ms（常量取 media crate，与编码参数同源）。
/// 实际系统 mix format 由 WASAPI 线程的成功行
/// `WASAPI loopback capture started: mix=...`（wasapi.rs:349-356）打印。
pub(crate) fn loopback_attempt_params() -> String {
    use kirin_desk_media::encoder::audio::{BIT_RATE, CHANNELS, FRAME_MS, SAMPLE_RATE};
    format!(
        "endpoint=GetDefaultAudioEndpoint(eRender, eConsole) + AUDCLNT_STREAMFLAGS_LOOPBACK, \
         target={SAMPLE_RATE}Hz/{CHANNELS}ch float32 -> Opus {SAMPLE_RATE}Hz/stereo/{BIT_RATE}bps/{FRAME_MS}ms"
    )
}

///
/// 拆出独立函数：任务侧状态机臂只做编排；错误经 WARN 落点输出
/// （`EncodeError` 文案含 HRESULT/原因，如 `GetDefaultAudioEndpoint: 0x8889000A`）。
fn start_loopback_pipeline()
-> Result<kirin_desk_media::AudioPipeline, kirin_desk_media::encoder::video::EncodeError> {
    let mut p = kirin_desk_media::AudioPipeline::new()?;
    p.start()?;
    Ok(p)
}

// ════════════════════════════════════════════════════════════════
// 注册表增删 + 生命周期编排
// ════════════════════════════════════════════════════════════════

///
/// 供 GUI accept 生产路径「延迟注册」使用（见 [`register_reserved_viewer`]
/// 文档）：ID 在握手响应发出时刻即稳定（文件/隐私会话键控槽、DisplaySelect
/// Nack 定向回复以该 ID 为键），但真实入表/起捕获/武装关键帧看门狗推迟到
/// 客户端首包到达（= 握手完全完成）。仅预占、未注册的 ID 对
/// [`viewer_count`]/生命周期决策零影响；客户端永不发首包（确认对话框取消
/// 等）→ ID 留空号，无害（进程内单调计数器）。
pub(crate) fn reserve_viewer_id() -> u64 {
    viewer_next_id().fetch_add(1, Ordering::Relaxed) + 1
}

/// 注册观众（握手成功后由连接处理调用）：
/// ① 入注册表（计数镜像同步）；② 起独立观众发送任务（recv 广播缓冲 →
/// 写自己的加密写半通道；失败即注销）；③ 按生命周期决策启动捕获 /
/// 取消宽限停止。返回 session_id（连接退出时 [`remove_viewer`] 注销用）。
///
/// **首位观众**的值决定捕获任务输出尺寸（多观众口径同 [`converge_codec`]：
/// 后连观众跟随在场流，不重建——不一致记 warn）。
///
///
/// 即时注册（bench/测试）= [`reserve_viewer_id`] + 本函数连调。
///
/// 注册时机 = 客户端**首包到达**（连接分发任务首次 `recv_tagged` 成功）：
/// wire 上握手 = 客户端 init → 服务端 response 两消息（`core/src/crypto/
/// handshake.rs` `client_handshake_with_confirm_and_codecs_generic`）——服务端
/// 发出响应后客户端还要本地验签 + TOFU 指纹确认（用户对话框；确认完成前
/// 客户端**零出站**），完成才发首包（生产客户端恒定 `DisplayListReq`，
/// `ui/src/lib.rs` connect 尾部无条件发送）。首包到达即「客户端握手完全
/// 完成、会话真正建立」的服务端可观测信号点。该时机前：不入 viewer 表、
/// 不起捕获/编码、不武装关键帧补投看门狗、零广播流量（TOFU 慢启动期间
/// 服务端资源占用 = 一个 parked 在 recv 的分发任务）。
///
/// 即时注册（ID 自分配）的其余语义与「[`reserve_viewer_id`] + 本函数」
/// 连调完全一致（入表/起发送任务/生命周期决策），
/// 返回 `id`（= 传入的预占 ID；连接退出时 [`remove_viewer`] 注销——从未
/// 注册的 ID 注销为 no-op）。
pub(crate) async fn register_reserved_viewer(
    id: u64,
    peer_id: String,
    codec: Codec,
    sender: SharedSender,
    max_width: u32,
) -> u64 {
    let (tx, rx) = tokio::sync::mpsc::channel(VIEWER_BUFFER);
    let (end_tx, end_rx) = tokio::sync::mpsc::channel(1);
    let first_codec = insert_viewer(
        id,
        ViewerEntry {
            peer_id: peer_id.clone(),
            negotiated_codec: codec,
            pkt_tx: tx,
            lagging: false,
            end_tx,
        },
    )
    .await;
    info!(
        id,
        peer_id,
        codec.as_str(),
        max_width,
        viewer_count()
    );
    // 观众发送任务：独立写自己的 SecureChannelSender；失败/断开 → 注销，
    // [`viewer_send_task`]）。
    tokio::spawn(viewer_send_task(
        id,
        rx,
        end_rx,
        sender,
        VIEWER_HEARTBEAT_INTERVAL,
    ));
    match capture_action_on_viewer_change(capture_running().load(Ordering::Relaxed), viewer_count())
    {
        CaptureAction::Start => {
            start_capture(first_codec.unwrap_or(codec), max_width);
        }
        // 新观众接入 → 宽限停止作废（代数递增使旧计时器失效）。
        _ => {
            grace_generation().fetch_add(1, Ordering::Relaxed);
            // IDR 给新观众一个可解码起点（旧观众多收一个 IDR 无害）。
            if capture_running().load(Ordering::Relaxed) {
                request_capture_idr();
                let cur = capture_max_width_slot().load(Ordering::Relaxed);
                if cur != max_width {
                    warn!(
                         with max_w={cur} — converging to running width (first-viewer basis)"
                    );
                }
                // +NO_FRAME_RESTART_SECS 仍零新帧（僵尸状态污染 / 静屏零交付）
                // → 确定性清态 + 以本观众口径重启捕获（判据/日志格式钉死
                // 单测；健康动态画面加入后 ~0.3-1.5s 必有帧，不误触发）。
                spawn_no_frame_watchdog(id, codec, max_width);
            }
        }
    }
    id
}

/// 关键帧补投超时踢出后分发任务据此退出，停止向被踢观众注入输入并收敛
/// 本连接各发送端 Arc）。async 上下文调用（锁仅内存操作，不跨其它 await）。
pub(crate) async fn is_viewer_registered(id: u64) -> bool {
    server_sessions().lock().await.contains_key(&id)
}

/// 抽纯函数供单测钉死时机口径——`ui/src/lib.rs` 分发任务首包点与
/// 500ms kick-watch tick 共用）：
///
/// - `packet_arrived && !session_registered` → **Register**：客户端包到达
///   且未注册——**首包是注册的唯一触发**（首包 = 握手完全完成：客户端已
///   验签 + TOFU 指纹确认完毕并启动发送；wire 上确认前客户端零出站）。
///   已注册 → 不重复注册（后续包照常分发）。
/// - `session_registered && !in_registry` → **EndDispatch**：已注册但
///   viewer 已被移出注册表（关键帧补投超时/通道死踢出）→ 分发任务退出。
/// - 其余 → **Continue**——关键不变式：**TOFU 等待期（未注册、首包未到）
///   恒 Continue，绝不判死**（viewer 本就不在表内，`in_registry=false`
///   不得被解读为「被踢」——旧口径的误杀形态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeferredViewerTick {
    /// 首包到达且未注册 → 真实注册（入表+起捕获+武装看门狗）。
    Register,
    /// 已注册且被踢出 → 分发任务退出（停注入+收敛发送端）。
    EndDispatch,
    /// 保持现状（TOFU 等待期 / 已注册正常 / 已注册后续包）。
    Continue,
}

pub(crate) fn deferred_viewer_tick(
    packet_arrived: bool,
    session_registered: bool,
    in_registry: bool,
) -> DeferredViewerTick {
    if packet_arrived && !session_registered {
        DeferredViewerTick::Register
    } else if session_registered && !in_registry {
        DeferredViewerTick::EndDispatch
    } else {
        DeferredViewerTick::Continue
    }
}

/// 内部：插入观众条目，返回「本条目是否使注册表从空变为非空」
/// （非空 → 本观众是首位，其协商编码决定捕获任务编码标准）。
///
/// 注册表条目（`register_reserved_viewer` 会连带触发捕获生命周期，本函数
/// 仅入表零副作用，e2e 专用）。零行为变化/零签名变化/零 wire。
pub(crate) async fn insert_viewer(id: u64, entry: ViewerEntry) -> Option<Codec> {
    let mut m = server_sessions().lock().await;
    let first = m.is_empty();
    let codec = if first { Some(entry.negotiated_codec) } else { None };
    m.insert(id, entry);
    viewer_count_atomic().store(m.len(), Ordering::Relaxed);
    // （注册发生在分发任务首包点——tokio 自由任务，无 egui Context）。
    request_main_repaint();
    codec
}

/// 内部：移除观众条目，返回是否确实移除。
async fn remove_viewer_inner(id: u64) -> bool {
    let mut m = server_sessions().lock().await;
    let removed = m.remove(&id).is_some();
    viewer_count_atomic().store(m.len(), Ordering::Relaxed);
    // ≤1s 自行清退。全部注销路径汇聚于此：①客户端断开（FIN→EOF）→ 分发
    // 任务清理段 `remove_viewer`；②观众发送失败 → 发送任务退出 →
    // `remove_viewer`；③`notify_viewers_session_end` 优雅停止。修复前此
    // 路径零 request_repaint → 空闲主窗停留最后一帧直到下次输入。
    if removed {
        request_main_repaint();
    }
    removed
}

/// 注销观众（连接退出 / 发送失败调用）：移除条目；观众清零且捕获运行中
/// → 排定宽限停止。
pub(crate) async fn remove_viewer(id: u64) {
    if remove_viewer_inner(id).await {
        // 全部按下的输入状态，防被控端本地鼠标按键被远端状态「钉死」
        // （幂等；与宿主停止 / 媒体会话收尾路径可能重叠，重复调用 no-op）。
        release_shared_input_state().await;
        if capture_action_on_viewer_change(
            capture_running().load(Ordering::Relaxed),
            viewer_count(),
        ) == CaptureAction::ScheduleGraceStop
        {
            schedule_grace_stop();
        }
    }
}

/// 轻量「会话结束」控制消息（复用既有 `ControlMessage::Disconnect` 变体，
/// **零协议变更**；旧客户端走 `Ok(other)` debug 静默忽略 = fail-safe），
/// 随后注销全部观众（注册表条目 drop → 广播通道关闭 → 各观众发送任务
/// 把队内残留（含本 Disconnect）按 FIFO 发完后退出）。
///
/// 「停止服务」场景进程存活——捕获任务虽停，但观众发送任务不受影响，
/// 继续每 3s 空档心跳**永久刷新客户端 10s 看门狗** → 客户端旧画面无限
/// 停留且自认连接健康（比 10s 更糟）。本函数把「服务端主动关闭」变成
/// 客户端 **<1s** 的即时断开判定（客户端收 `Disconnect` → lost 路径）。
///
/// 幂等：无观众 → 直接返回；重复调用无害（注销后注册表为空）。
pub(crate) async fn notify_viewers_session_end(reason: &str) {
    let sids: Vec<u64> = {
        let m = server_sessions().lock().await;
        m.keys().copied().collect()
    };
    if sids.is_empty() {
        return;
    }
    let pkt = EncodedPacket {
        ts: Timestamp::now(),
        kind: PacketKind::Control,
        data: bincode::serialize(&ControlMessage::Disconnect {
            reason: reason.to_string(),
        })
        .expect("Disconnect bincode serialize（固定变体，不可能失败）"),
        is_key: false,
    };
    // 注入各观众广播通道（FIFO 于队内残留视频帧之后）；发送失败 = 该观众
    // 通道已死（发送任务正在退出）→ 仅日志，不影响其余观众。
    let m = server_sessions().lock().await;
    for sid in &sids {
        if let Some(v) = m.get(sid) {
            if v.pkt_tx.try_send(pkt.clone()).is_err() {
                warn!(
                );
            }
        }
    }
    drop(m);
    let n = sids.len();
    for sid in sids {
        remove_viewer(sid).await;
    }
}

/// 排定宽限停止：5s 后仍无观众且服务端未停止 → 置宽限停止标志。
fn schedule_grace_stop() {
    let gen = grace_generation().load(Ordering::Relaxed);
    info!(
        CAPTURE_GRACE.as_secs()
    );
    tokio::spawn(async move {
        tokio::time::sleep(CAPTURE_GRACE).await;
        if grace_generation().load(Ordering::Relaxed) == gen
            && grace_expired_should_stop(viewer_count())
            && !crate::server_stop_signal().load(Ordering::Relaxed)
        {
            capture_grace_stop().store(true, Ordering::Relaxed);
        }
    });
}

// ════════════════════════════════════════════════════════════════
// 帧广播总线
// ════════════════════════════════════════════════════════════════

/// 编码任务产出的包广播给全部注册观众（明文 EncodedPacket 层分发；
/// 各观众发送任务独立加密发送）。
///
/// 慢观众策略（子项 3）：缓冲满 → 非关键帧直接丢弃并置慢标记；关键帧
/// 限时（[`KEY_DELIVER_TIMEOUT`]）阻塞补投，超时或通道关闭 → 踢出该
/// 观众。编码循环最多为单个关键帧补投阻塞 200ms，不持续 backpressure。
/// `ControlMessage::Disconnect` 尾变体，零新 wire 变体；旧客户端 fail-safe
/// 忽略口径不变）。注入该观众专用 end 通道（[`ViewerEntry::end_tx`]，容量 1，
/// 独立于满帧队列）→ 观众发送任务 biased 最高优先分支送达：客户端可读取
/// 看门狗）。try_send 失败仅为防御分支（kick 每观众至多一次且持表锁，
/// 容量 1 队列必空）→ 日志后照踢，不阻塞。
fn kick_notify_session_end(
    end_tx: &tokio::sync::mpsc::Sender<EncodedPacket>,
    sid: u64,
    reason: &str,
) {
    let pkt = EncodedPacket {
        ts: Timestamp::now(),
        kind: PacketKind::Control,
        data: bincode::serialize(&ControlMessage::Disconnect {
            reason: reason.to_string(),
        })
        .expect("Disconnect bincode serialize（固定变体，不可能失败）"),
        is_key: false,
    };
    if end_tx.try_send(pkt).is_err() {
        warn!(
        );
    }
}

pub(crate) async fn broadcast_packet(pkt: &EncodedPacket) {
    let mut m = server_sessions().lock().await;
    let mut kick: Vec<(u64, &'static str)> = Vec::new();
    for (sid, v) in m.iter_mut() {
        if lag_skip_decision(v.lagging, pkt.is_key) == LagSkip::Skip {
            continue;
        }
        match v.pkt_tx.try_send(pkt.clone()) {
            Ok(()) => v.lagging = false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                if pkt.is_key {
                    match tokio::time::timeout(
                        KEY_DELIVER_TIMEOUT,
                        v.pkt_tx.send(pkt.clone()),
                    )
                    .await
                    {
                        Ok(Ok(())) => v.lagging = false,
                        _ => {
                            warn!(
                                sid
                            );
                            kick_notify_session_end(
                                &v.end_tx,
                                *sid,
                                "key-frame deliver timed out (server-side kick)",
                            );
                            kick.push((*sid, "key-frame deliver timed out"));
                        }
                    }
                } else {
                    //（限速请求 IDR + 码率降一档——降画质保流畅）。
                    if !v.lagging {
                        on_viewer_lag();
                    }
                    v.lagging = true;
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // 帧队列读半已落（发送任务正在退出/已退出）→ 对端已离场，
                // end 通知大概率无接收者（best-effort，失败仅日志）。
                warn!(
                    sid
                );
                kick_notify_session_end(
                    &v.end_tx,
                    *sid,
                    "channel closed (server-side kick)",
                );
                kick.push((*sid, "channel closed"));
            }
        }
    }
    for (sid, reason) in &kick {
        m.remove(sid);
        viewer_count_atomic().store(m.len(), Ordering::Relaxed);
    }
    // 出）→ 同口径请求主窗重绘。
    if !kick.is_empty() {
        request_main_repaint();
    }
    // 踢出）——与 [`remove_viewer`] 同一生命周期决策：清零且捕获运行中 →
    // 排定宽限停止。旧实现只删条目不排宽限 → 全部观众被踢后捕获任务
    // 永不停止（viewer 泄漏的对称缺口：注册表清零但捕获/会话态不收敛）。
    if !kick.is_empty()
        && kick_lifecycle_should_schedule_grace(
            capture_running().load(Ordering::Relaxed),
            viewer_count(),
        )
    {
        schedule_grace_stop();
    }
}

/// `remove_viewer` 的 `capture_action_on_viewer_change(...) ==
/// CaptureAction::ScheduleGraceStop` 判定同源，独立成函数供单测钉死口径）。
fn kick_lifecycle_should_schedule_grace(running: bool, remaining: usize) -> bool {
    capture_action_on_viewer_change(running, remaining) == CaptureAction::ScheduleGraceStop
}

/// 定向单发（显示器切换 Nack 回请求方；尽力投递，失败仅记日志）。
async fn send_to_viewer(session_id: u64, pkt: EncodedPacket) {
    let m = server_sessions().lock().await;
    if let Some(v) = m.get(&session_id) {
        if v.pkt_tx.try_send(pkt).is_err() {
            warn!("DisplaySelectNack: viewer #{} buffer full — dropped", session_id);
        }
    }
}

///
/// `is_idr`：本窗口首帧是否 IDR（帧泵长 GOP 下 IDR 只由显式 force_key
/// 驱动——会话首帧/显示器切换/新观众/慢观众恢复/码率档位切换）。
/// 标记关键帧供慢观众丢帧后跳到下一可解码帧（真 IDR 才是恢复点；旧
/// 实现恒置 true 使「缓冲满丢非关键帧保关键帧」策略失效——每窗都是
/// "关键帧"等于没有关键帧）。
///
/// 关闭）→ ① `bus` 段采样（编码完成→广播总线，含 bincode 序列化 + 广播锁）；
/// ② **wire pts 旁路**：`ts.pts = capture_ms`（客户端跨段关联；关闭时
/// `Timestamp::now()` 即 pts=0，与现状逐字节一致——零协议变更）。
async fn broadcast_encoded_window(
    encoded_window: &kirin_desk_media::proto::EncodedWindow,
    is_idr: bool,
    task_start: std::time::Instant,
    window_count: &mut u64,
    marks: Option<(u64, u64)>,
) {
    *window_count = encoded_window.window_id;
    let n_frames = encoded_window.frame_count;
    // 「加入后零新帧」判据 + 活性行 last_frame_age_ms 字段的事实源。
    // 与打点门控无关（SystemTime 直读，零分配）。
    last_video_frame_ms().store(latency_trace::epoch_ms(), Ordering::Relaxed);
    // 一条，60fps 下 ~2-4 条/s），生产 info 级无对账价值；首窗 IDR 锚点
    debug!(
        "Capture: window {} encoded ({} frames, {}x{}, {}ms encode{})",
        encoded_window.window_id,
        n_frames,
        encoded_window.base_w,
        encoded_window.base_h,
        encoded_window.encode_duration_ms as u64,
        if is_idr { " [IDR]" } else { "" },
    );
    if encoded_window.window_id == 0 {
        info!(
            task_start.elapsed().as_millis()
        );
    }
    match bincode::serialize(encoded_window) {
        Ok(bytes) => {
            record_window_pacing(WindowPacingSample {
                window_id: encoded_window.window_id,
                broadcast: Instant::now(),
                frames: encoded_window.frame_count,
                bytes: bytes.len(),
                encode_ms: encoded_window.encode_duration_ms,
            });
            // 1 行/秒；门控 = latency_trace 同源）。字段口径（进程内 ms）：
            // win=窗口号（帧序号，帧关联键；wire pts 服务端单源）/ cap=
            // capture 提交→编码完成间隔（静态屏 flush 臂 marks=(now,now)
            // → 恒 0）/ enc=编码完成锚点（epoch ms）/ enc_dt=编码器内部
            // 耗时 / key=窗首帧是否 IDR。marks=None（门控关）→ 无行零开销。
            // 挂点=广播区单点：marks 由捕获/编码区（正常臂/静态 flush 臂）
            // 产出，两臂在此同形汇入。
            if let Some((cap_anchor, enc_done)) = marks {
                if latency_trace::r123_step(
                    0,
                    latency_trace::R123_STREAM_VID,
                    enc_done,
                ) {
                    tracing::info!(
                        encoded_window.window_id,
                        enc_done.saturating_sub(cap_anchor),
                        enc_done,
                        encoded_window.encode_duration_ms as u64,
                        u8::from(is_idr),
                    );
                }
            }
            let ts = match marks {
                Some((capture, enc_done)) => {
                    let now = latency_trace::epoch_ms();
                    latency_trace::record(
                        latency_trace::Stage::Bus,
                        (now.saturating_sub(enc_done)) as f64,
                    );
                    Timestamp::new(Instant::now(), capture)
                }
                None => Timestamp::now(),
            };
            let pkt = EncodedPacket {
                ts,
                kind: PacketKind::Video,
                data: bytes,
                is_key: is_idr,
            };
            broadcast_packet(&pkt).await;
        }
        Err(e) => {
            tracing::error!("Serialize window {} failed: {}", encoded_window.window_id, e);
        }
    }
}

/// 屏/无观众输入）→ 向该观众发一条轻量 `ControlMessage::Heartbeat`。
///
/// 对齐；客户端看门狗 10s = 3×3s（至少漏 3 个心跳才判死，防抖动误杀）。
///
/// 协议兼容性（核查 PASS）：`Heartbeat` 变体自 v0.2.0 已发布且变体序与
/// HEAD 逐位一致（bincode 位置编码）→ 旧客户端可正常反序列化并走
/// `Ok(other)` debug 静默忽略（fail-safe，不断连不刷屏）。
const VIEWER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

/// 观众发送任务：广播缓冲 → 自己的加密写半通道。
///
/// 路由与既有单会话路径一致：视频窗口走 `send_big_packet` 大帧路径；
/// 音频走 [`crate::send_audio_packets`] 大小分流（可丢，不中断）；
/// 其余（控制等）走小分片 `send_packets`。
///
/// 测试注入小值）。`select!` 分支：
/// - 有帧/包 → 照常发送并刷新 `last_outbound`（**帧流期间心跳永不到期，
///   零额外流量**——行为锚：正常会话零开销）；
/// - 空档到期（暂停/静态屏）→ 发 `ControlMessage::Heartbeat`；**发送失败 =
///   连接死**（死连接 + 静态屏场景下这是唯一出站——此前只能等 SO_KEEPALIVE
///
/// `biased;` 帧分支优先：帧就绪时不与心跳计时竞争丢帧。
///
/// 进程内通道，非 wire）。`biased;` **最高优先**分支（先于帧/心跳）：
///   尾变体，**零新 wire 变体**）→ break。踢出路径（关键帧补投超时）的
///   前提恰是帧队列满——通知独立于帧队列送达：发送任务从在途写完成/失败
///   分支 filter 关闭降级原双分支语义（None-ready 分支在 biased 下会饿死
///   照旧先排帧后退出，行为零回退。
///
/// 发送任务（生产同款任务体，心跳周期注入小值加速）。零行为变化/零签名
/// 变化/零 wire。
pub(crate) async fn viewer_send_task(
    session_id: u64,
    mut rx: tokio::sync::mpsc::Receiver<EncodedPacket>,
    mut end_rx: tokio::sync::mpsc::Receiver<EncodedPacket>,
    sender: SharedSender,
    heartbeat_interval: Duration,
) {
    let mut last_outbound = Instant::now();
    let mut end_open = true;
    loop {
        tokio::select! {
            biased;
            maybe_end = end_rx.recv(), if end_open => {
                match maybe_end {
                    Some(notif) => {
                        // 被踢观众的残留帧已不可解码消费，原因信号优先）。
                        // 发送失败 = 连接死（仅日志；条目已由踢出方移除）。
                        if let Err(e) = sender
                            .lock()
                            .await
                            .send_packets(std::slice::from_ref(&notif))
                            .await
                        {
                            warn!(
                                 — removing viewer",
                                session_id
                            );
                        }
                        break;
                    }
                    None => {
                        // 条目已 drop（注销/踢出/全局停止）且通知队空 →
                        end_open = false;
                    }
                }
            }
            maybe_pkt = rx.recv() => {
                let Some(pkt) = maybe_pkt else { break };
                let res = match pkt.kind {
                    // AEAD + TCP 写）；trace 关闭时零开销。
                    PacketKind::Video => {
                        let t0 = if latency_trace::enabled() {
                            Some(latency_trace::epoch_ms())
                        } else {
                            None
                        };
                        let r = sender.lock().await.send_big_packet(&pkt).await;
                        if let (Some(t0), Ok(())) = (t0, &r) {
                            latency_trace::record(
                                latency_trace::Stage::Sendq,
                                (latency_trace::epoch_ms().saturating_sub(t0)) as f64,
                            );
                        }
                        r
                    }
                    PacketKind::Audio => {
                        crate::send_audio_packets(&sender, &[pkt]).await;
                        last_outbound = Instant::now();
                        continue;
                    }
                    _ => sender.lock().await.send_packets(&[pkt]).await,
                };
                if let Err(e) = res {
                    warn!(
                        session_id, e
                    );
                    break;
                }
                last_outbound = Instant::now();
            }
            _ = tokio::time::sleep_until((last_outbound + heartbeat_interval).into()) => {
                let hb = EncodedPacket {
                    ts: Timestamp::now(),
                    kind: PacketKind::Control,
                    data: bincode::serialize(&ControlMessage::Heartbeat {
                        timestamp_ms: now_epoch_ms(),
                    })
                    .expect("Heartbeat bincode serialize（固定变体，不可能失败）"),
                    is_key: false,
                };
                if let Err(e) = sender
                    .lock()
                    .await
                    .send_packets(std::slice::from_ref(&hb))
                    .await
                {
                    warn!(
                        session_id, e
                    );
                    break;
                }
                last_outbound = Instant::now();
            }
        }
    }
    remove_viewer(session_id).await;
}

// ════════════════════════════════════════════════════════════════
// 编码参数收敛（子项 4：全场统一口径）
// ════════════════════════════════════════════════════════════════

/// 握手协商收敛：捕获任务运行期间，后续观众统一上报**当前实际编码**
/// （不改协议消息格式，仅在握手应答处收敛编码标准字符串）。
///
/// 口径：
/// - 捕获未运行（首位观众）→ 用协商结果（空/未知由调用方 H.264 兜底）。
/// - 捕获运行中 → 返回当前实际编码；若与本观众协商结果不一致记 warn，
///   仍按服务端当前编码发送（后加入观众跟随在场流；对齐客户端
///   「AV1 不可用回退 H.264」的兜底先例）。
/// - 异构观众的完整方案（按观众子流转码/多编码器实例）列为后续。
pub(crate) fn converge_codec(negotiated: &str) -> String {
    let running = capture_running().load(Ordering::Relaxed);
    let current = *capture_codec_slot().lock().unwrap();
    match (running, current) {
        (true, Some(cur)) => {
            if negotiated != cur.as_str() {
                warn!(
                     converging to running codec (multi-codec per-viewer is future work)",
                    negotiated,
                    cur.as_str()
                );
            }
            cur.as_str().to_string()
        }
        _ => negotiated.to_string(),
    }
}

// ════════════════════════════════════════════════════════════════
//
// 根因（09-22 三轮复测 P0「waiting for video stream 卡死」）：进程内
// stop→start 跨周期捕获状态未确定性清理——capture_running / codec 槽等
// 的清除**依赖垂死捕获任务自己的收尾**（`start_capture` 任务体
// run_capture_once 返回后的清态段），任务一旦卡住/迟到，状态残留：
// 后到 viewer 经 `capture_action_on_viewer_change(running=true, 1)` 判
// `None` 跳过 `start_capture` + `converge_codec` 收敛到陈旧 codec 槽 →
// 零帧 → 客户端恒显「Connected — waiting for video stream...」。
// 本段三件：(a) stop 置位处**单一确定点**同步清全状态（不等垂死任务）
// + 世代守卫使垂死任务醒来时零状态踩踏；(b) viewer 加入 running=true
// 但 N 秒零新帧 → 强制清态重启；(d) 广播环周期性活性 tick 行。
// 零 wire 改动。
// ════════════════════════════════════════════════════════════════

///
/// `was_codec` = 清理前 codec 槽（None → `none`）；`gen` = 清理后新世代
///（递增后的值——行内即「从此世代起旧任务全部失配」的判据锚点）。
pub(crate) fn r134_1_reset_line(
    reason: &str,
    gen: u64,
    was_running: bool,
    was_codec: Option<&str>,
    viewers: usize,
) -> String {
    let codec = was_codec.unwrap_or("none");
    format!(
    )
}

///
/// `last_frame_age_ms` = 触发时刻距最近一次视频窗口广播的毫秒
///（从未广播 = `none`）；`secs` = 看门狗窗（[`NO_FRAME_RESTART_SECS`]）。
pub(crate) fn r134_1_no_frame_trigger_line(
    viewer_id: u64,
    secs: u64,
    last_frame_age_ms: Option<u64>,
) -> String {
    let age = match last_frame_age_ms {
        Some(a) => format!("{a}ms"),
        None => "none".to_string(),
    };
    format!(
    )
}

/// `start_capture` 的「shared capture task starting」行之前各一行。
pub(crate) fn r134_1_force_restart_line(codec: &str, max_w: u32, gen: u64) -> String {
}

/// [`CAPTURE_LIVE_TICK_SECS`] 周期一行：行的存在 = 本世代广播环存活；
/// `last_frame_age_ms` 持续增长 = 无帧在产（静屏正常 / 捕获环僵死同形，
/// 区分靠本行是否继续出现）。
pub(crate) fn r134_1_cap_live_line(gen: u64, viewers: usize, last_frame_age_ms: Option<u64>) -> String {
    let age = match last_frame_age_ms {
        Some(a) => format!("last_frame_age_ms={a}"),
        None => "last_frame_age_ms=none".to_string(),
    };
}

/// 抽纯函数供单测钉死口径）：
///
/// - 本任务世代 == 当前世代 → [`CaptureRoundExit::Current`]：清态归本任务
///   （stop/宽限/重启分支按既有语义）。
/// - 失配（更新世代已接管）→ [`CaptureRoundExit::Superseded`]：**不碰
///   任何状态、不释放输入**直接退出——状态所有权归新世代；输入释放归新
///   世代宿主（本任务若释放会踩掉新会话的按下态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureRoundExit {
    /// 世代匹配：按既有语义清态 + 分因退出/退避重启。
    Current,
    /// 世代失配：更新世代已接管——零状态触碰、零输入释放，直接退出。
    Superseded,
}

pub(crate) fn capture_round_exit_decision(gen: u64, current_gen: u64) -> CaptureRoundExit {
    if gen == current_gen {
        CaptureRoundExit::Current
    } else {
        CaptureRoundExit::Superseded
    }
}

/// 单测钉死矩阵）——**真 = 强制重启**：
///
/// - `stopped`（服务端停止中）→ 不重启（停止语义优先，重启无意义）。
/// - `!running`（捕获已合法退出）→ 不重启（退出分支/后到观众自行处置）。
/// - `!viewer_registered`（触发观众已离场）→ 不为已离场观众重启。
/// - `last_frame_ms >= join_ms`（加入后有帧在产）→ 健康，不动。
/// - 其余（加入后**零新帧**：最近帧早于加入 / 从未有帧）→ 僵死态
///   （僵尸状态污染 / 静屏新观众零交付）→ 强制清态重启。
pub(crate) fn r134_1_no_frame_decision(
    stopped: bool,
    running: bool,
    viewer_registered: bool,
    last_frame_ms: u64,
    join_ms: u64,
) -> bool {
    !stopped && running && viewer_registered && last_frame_ms < join_ms
}

/// 全状态（不等垂死任务自清理），打清尾日志行（[`r134_1_reset_line`]）。
///
/// 清除集 = 「stop 后、进程内重启前」状态必须回到**全新启动等价态**的
/// 全量并集：
/// - `capture_running` → false（后到观众 `capture_action_on_viewer_change`
///   必判 `Start`——09-22 复现链的误判点）；
/// - `capture_codec_slot` → None（`converge_codec` 不再收敛到陈旧编码）；
/// - `capture_max_width_slot` → 0 / `capture_coord_dims` → None /
///   `switch_request_tx` → None（任务退出清态段同集——重置后即使垂死
///   任务晚醒也无陈旧槽可读，坐标换算侧 `capture_coord_scale()` = None
///   = 恒等跳过）；
/// - `capture_grace_stop` → false（宽限旗标归零，不残留到下一轮）；
/// - `grace_generation` 递增（挂起的宽限计时器任务醒来判代数失配 → 不置
///   宽限旗标——旧宽限作废）；
/// - `r126b_quality_high` → 0（与 `start_capture` 的「捕获世代起点 = 常态
///   阶梯」同口径）；
/// - `capture_generation` 递增（**关键**：任何在跑的垂死捕获任务醒来后
///   世代失配 → [`CaptureRoundExit::Superseded`] 零状态触碰退出）。
///
/// 幂等：无捕获在跑时调用 = 纯归零 + 日志行（各 store 同值）。调用点 =
/// lib.rs 服务端「允许受控」开关 OFF 分支（stop 信号 `store(true)` 紧后，
/// 生产唯一进程内 stop 置位点；进程退出路径无重启诉求不挂）。
pub(crate) fn reset_capture_state_on_stop(reason: &str) {
    let was_running = capture_running().load(Ordering::Relaxed);
    let was_codec = capture_codec_slot().lock().unwrap().as_ref().map(|c| c.as_str().to_string());
    let gen = capture_generation().fetch_add(1, Ordering::Relaxed) + 1;
    capture_running().store(false, Ordering::Relaxed);
    *capture_codec_slot().lock().unwrap() = None;
    capture_max_width_slot().store(0, Ordering::Relaxed);
    *capture_coord_dims().lock().unwrap() = None;
    *switch_request_tx().lock().unwrap() = None;
    capture_grace_stop().store(false, Ordering::Relaxed);
    grace_generation().fetch_add(1, Ordering::Relaxed);
    r126b_quality_high().store(0, Ordering::Relaxed);
    info!(
        "{}",
        r134_1_reset_line(reason, gen, was_running, was_codec.as_deref(), viewer_count())
    );
}

/// 武装本任务（[`register_reserved_viewer`] 的既有运行中分支调用）：
/// 加入 + [`NO_FRAME_RESTART_SECS`] 到期时按 [`r134_1_no_frame_decision`]
/// 判定，成立 → 打触发行 → 确定性清态（复用 stop 同集，reason=`no-frame
/// watchdog`）→ 以该观众的协商编码/宽度重启捕获（打重启行 +
/// `start_capture` 既有 starting 行）。
///
/// 误杀口径：健康动态画面加入后 ~0.3-1.5s 必有帧（首窗 IDR + 广播）≪
/// 3s 窗；静屏健康捕获 = 加入后零新帧 → 触发重启（**收益** = 新捕获源
/// 的 DXGI 初始全帧 IDR 立即交付给卡占位图的观众，重启代价 ~1s 可接受）。
/// 每次加入武装一个 oneshot；触发观众已离场 / 停止中 / 捕获已合法退出
/// → 判定不成立零动作（判定矩阵钉死单测）。
fn spawn_no_frame_watchdog(viewer_id: u64, codec: Codec, max_width: u32) {
    let join_ms = latency_trace::epoch_ms();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(NO_FRAME_RESTART_SECS)).await;
        let stopped = crate::server_stop_signal().load(Ordering::Relaxed);
        let running = capture_running().load(Ordering::Relaxed);
        let registered = is_viewer_registered(viewer_id).await;
        let last = last_video_frame_ms().load(Ordering::Relaxed);
        if !r134_1_no_frame_decision(stopped, running, registered, last, join_ms) {
            return;
        }
        let now = latency_trace::epoch_ms();
        let age = if last == 0 {
            None
        } else {
            Some(now.saturating_sub(last))
        };
        info!(
            "{}",
            r134_1_no_frame_trigger_line(viewer_id, NO_FRAME_RESTART_SECS, age)
        );
        reset_capture_state_on_stop("no-frame watchdog");
        info!(
            "{}",
            r134_1_force_restart_line(codec.as_str(), max_width, capture_generation().load(Ordering::Relaxed))
        );
        start_capture(codec, max_width);
    });
}

// ════════════════════════════════════════════════════════════════
// 共享捕获任务（捕获一次、编码一份）
// ════════════════════════════════════════════════════════════════

/// 重启时调用）。
///
/// 单轮结束/退避唤醒后的清态与再武装均以「世代仍为自己」为前提
///（[`capture_round_exit_decision`]）：stop 确定性重置 / 强制重启接管后，
/// 垂死旧任务醒来 = 零状态触碰零输入释放直接退出，不再可能把新捕获的
/// running/codec/坐标槽踩回陈旧值（09-22 复现链的状态污染放大因子）。
fn start_capture(codec: Codec, max_width: u32) {
    let gen = capture_generation().fetch_add(1, Ordering::Relaxed) + 1;
    capture_running().store(true, Ordering::Relaxed);
    capture_grace_stop().store(false, Ordering::Relaxed);
    *capture_codec_slot().lock().unwrap() = Some(codec);
    capture_max_width_slot().store(max_width, Ordering::Relaxed);
    // 在连观众会话建立即推当前档——客户端 DisplayListReq 同位点）。
    r126b_quality_high().store(0, Ordering::Relaxed);
    tokio::spawn(async move {
        loop {
            info!(
                codec.as_str(),
                max_width
            );
            run_capture_once(gen, codec, max_width).await;
            // 状态所有权 → 零状态触碰、零输入释放直接退出（决策钉死单测
            // `r134_1_capture_round_exit_decision_matrix`）。
            if capture_round_exit_decision(gen, capture_generation().load(Ordering::Relaxed))
                == CaptureRoundExit::Superseded
            {
                info!(
                    capture_generation().load(Ordering::Relaxed)
                );
                break;
            }
            capture_running().store(false, Ordering::Relaxed);
            *capture_codec_slot().lock().unwrap() = None;
            *capture_coord_dims().lock().unwrap() = None;
            *switch_request_tx().lock().unwrap() = None;
            // → 不再重启；否则（致命捕获错误）仍有观众 → 1s 退避重启。
            if crate::server_stop_signal().load(Ordering::Relaxed)
                || viewer_count() == 0
            {
                // 宽限到期）→ 释放全部按下的输入状态（幂等：remove_viewer
                // 路径可能已释放，二次调用 no-op）。
                release_shared_input_state().await;
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            if crate::server_stop_signal().load(Ordering::Relaxed) || viewer_count() == 0 {
                release_shared_input_state().await;
                break;
            }
            // 不再再武装 running/codec 槽（会与在跑新任务双捕获），直接退出。
            if capture_round_exit_decision(
                gen,
                capture_generation().load(Ordering::Relaxed),
            ) == CaptureRoundExit::Superseded
            {
                info!(
                );
                break;
            }
            capture_running().store(true, Ordering::Relaxed);
            capture_grace_stop().store(false, Ordering::Relaxed);
            *capture_codec_slot().lock().unwrap() = Some(codec);
        }
    });
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// swscale 上下文含裸指针非 `Send`——与 media 编码器（`unsafe impl Send`）
/// 同口径：编码线程单线程独占，本包装声明跨线程移动安全。
struct SendScaler(kirin_desk_media::ffmpeg::scale::SwsConverter);
unsafe impl Send for SendScaler {}

/// 单轮共享捕获循环（DXGI → VideoEncoderPipeline → WindowPipeline → 广播）。
///
/// 显示器热切换、音频捕获广播），差异仅：帧不再发往单槽通道，而是
/// [`broadcast_packet`] 广播给全部注册观众；停止条件为服务端停止信号
///
/// swscale 等比降采样到 `max_width` 再编码（移动端 4K 不可解码/上屏吃不动，
/// 协议层 b6b3c3e 已就绪，本处为服务端消费点）；码率阶梯按实际编码分辨率
/// 自动取档；注入侧坐标经 [`capture_coord_scale`] 换算回原生分辨率。
///
/// [`CAPTURE_LIVE_TICK_SECS`] 周期活性行 [`r134_1_cap_live_line`] 携带
///（行的存在 = 本世代广播环存活，判读口径见常量文档）。
async fn run_capture_once(gen: u64, codec: Codec, max_width: u32) {
    use kirin_desk_media::capture::create_capture_source;
    use kirin_desk_media::proto::{EncodeConfig, RawFrame, WindowConfig};
    use kirin_desk_media::window_pipeline::WindowPipeline;
    use kirin_desk_media::VideoEncoderPipeline;

    // 在首个窗口广播处打 info 日志（首帧全链路 = 客户端握手完成 ≈ register_
    // viewer → 本任务启动 → 首窗广播 → 客户端收窗解码渲染）。
    let task_start = std::time::Instant::now();

    // sleep——DXGI 桌面复制无"流稳定"概念（该等待疑似摄像头捕获时代残留），
    // 首帧链路白白 +200ms。捕获源创建本身即就绪语义。

    // 1. Create DXGI capture source on monitor 0
    let mut capture = match create_capture_source(0) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create capture source: {}", e);
            return;
        }
    };
    let (width, height) = capture.resolution();
    info!(
        "Capture: DXGI source created, {}x{} ({}ms after capture task start)",
        width,
        height,
        task_start.elapsed().as_millis()
    );

    // 2. Create video encoder pipeline（HW 优先 + 软编回退；红线：不动
    //    编码器内部，统一 FFmpeg libavcodec）。
    let kernel: Option<Box<dyn kirin_desk_media::encoder::video::tile_diff::GpuKernel>> = {
        #[cfg(kirin_gpu_linked)]
        {
            use kirin_desk_media::encoder::gpu_ffi::kernel::KgpuKernel;
            KgpuKernel::init(kirin_desk_media::gpu::d3d11_device_handle())
                .ok()
                .map(|k| {
                    Box::new(k)
                        as Box<dyn kirin_desk_media::encoder::video::tile_diff::GpuKernel>
                })
        }
        #[cfg(not(kirin_gpu_linked))]
        {
            None
        }
    };
    let encoder = match VideoEncoderPipeline::new(codec, kernel) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to create video encoder pipeline: {}", e);
            return;
        }
    };
    info!(
        "Capture: video encoder '{}' created (hw={})",
        encoder.name(),
        encoder.is_hardware()
    );

    // 只读，值在此固化）——HW 全失败落软编时捕获降采样上限压 ≤960 宽。
    let sw_fallback = !encoder.is_hardware();

    // 3. Create window pipeline
    let mut pipeline = WindowPipeline::new(WindowConfig::default(), encoder);
    // 逐帧关窗即编即发（实测旧节奏：70ms 积攒 + 82ms 串行编码 = 182ms 窗口
    // 节律 → 动态内容仅 ~22fps、端到端 +130ms；静态屏门控积攒陈旧帧成批
    // 补发 → 1.2 窗/s + 1.25s 节奏空洞 = 用户实测 180KB/s 卡顿）。长 GOP
    //（不每窗 IDR——实测 IDR 占 78% 带宽），IDR 只由显式 force_key 驱动。
    pipeline.set_low_latency(true);
    // 静态 1fps 省电——DXGI 静止屏本就无帧）。配置本体见
    pipeline.set_fps_governor_config(r68a_fps_governor_config());
    // 分辨率取码率/preset）取代——SW reconfigure 仅消费 force_idr，HW 对
    // force_idr 通道语义（首帧/切换 IDR 经 RawFrame.force_key 走 set_cpu_frame）。
    pipeline.update_encode_config(EncodeConfig {
        qp: 26,
        force_idr: false,
        frame_ratio: 1.0,
        preset: "ultrafast".into(),
    });

    // 共享输入注入器（多观众输入全部注入；显示器切换时更新分辨率基准）。
    // 客户端坐标 → 原生的换算在连接分发任务（lib.rs）经 [`capture_coord_scale`]
    // 完成（避免动 input crate 的 src/dst 基准 API）。
    let injector = Arc::new(tokio::sync::Mutex::new(InputInjector::new(
        width, height, width, height,
    )));
    // **前**执行：分发任务读到槽才开始注入，故严格先于任何输入注入；读修饰
    // 键物理按下态（含左右 Win）非空则全释放，INFO 对账行
    // `input hygiene: clean / released residual modifiers bits=0x..`；幂等、
    // 失败 WARN 不阻断会话。
    input_hygiene_release();
    let _prev = server_input_injector().set(injector.clone());

    // 降采样上限压到 ≤960 宽——1080p 软编均值 ~29ms 贴满 30fps 帧距
    // （33ms）→ 帧率预算失守（e2e 尾巴主因之一）；≤960 宽（像素 -56%）
    // 恢复预算。HW 路径（is_hardware=true）保持原 max_width，**零改动**。
    let effective_max_width = if sw_fallback {
        kirin_desk_media::encoder::factory::sw_fallback_output_width(max_width)
    } else {
        max_width
    };
    let (out_w, out_h) = output_dims_for(width, height, effective_max_width);
    if sw_fallback && out_w < width {
        info!(
             (hw encoders unavailable): {}x{} -> {}x{} (fps budget recovery)",
            kirin_desk_media::encoder::factory::SW_FALLBACK_MAX_WIDTH,
            width,
            height,
            out_w,
            out_h
        );
    }
    let mut scaler: Option<SendScaler> = if (out_w, out_h) != (width, height) {
        match kirin_desk_media::ffmpeg::scale::SwsConverter::new(
            width as i32,
            height as i32,
            kirin_desk_media::ffmpeg::AV_PIX_FMT_RGBA,
            out_w as i32,
            out_h as i32,
            kirin_desk_media::ffmpeg::AV_PIX_FMT_RGBA,
        ) {
            Ok(s) => {
                info!(
                    width, height, out_w, out_h, effective_max_width, sw_fallback
                );
                Some(SendScaler(s))
            }
            Err(e) => {
                None
            }
        }
    } else {
        None
    };
    // 坐标换算基准（分发任务读取；out == native 时为恒等，分发侧跳过）。
    *capture_coord_dims().lock().unwrap() = Some((out_w, out_h, width, height));

    // 显示器切换请求通道（各连接分发任务 → 编码线程）。
    let (switch_tx, mut switch_rx) =
        tokio::sync::mpsc::unbounded_channel::<SwitchRequest>();
    *switch_request_tx().lock().unwrap() = Some(switch_tx);

    // 广播给全部观众（每观众发送任务独立加密/分流）。
    //
    // 子开关 `server_audio_allowed`（默认关）是**运行时**开关——由
    // 任务内状态机（[`AudioToggleMachine`]，纯逻辑核心可单测）逐轮读取
    // （空闲轮询 50ms）驱动捕获启停：会话中途开/关 ≤100ms 生效（PM 口径 a：
    // 目标 ≤2s），且日志三落点必达（尝试 INFO〔端点+格式〕/ 成功 INFO /
    // 失败 WARN〔HRESULT/原因〕，见各臂注释）。
    //
    // 修复前根因（79 实机 3.2s 窗口零落点）：子开关兼作 spawn 门控（本条件
    // 修复前为 `&& crate::server_audio_allowed()`）——默认关 ⇒ 会话建立时
    // 开关为关则音频任务从未 spawn；中途开开关只写原子量 + setter 日志
    // （lib.rs `set_server_audio_allowed`），无消费者 ⇒ 启动既无成功落点
    // 也无失败落点。
    // 重试路径（start_capture 循环重跑本函数且**复位 grace**），该路径全局
    // stop/grace 均不变 ⇒ 本 run 的音频任务必须随 run 退出，否则残留旧任务
    // 未 spawn，尾部 store 为无害 no-op。
    let run_audio_stop = Arc::new(AtomicBool::new(false));
    if crate::audio_enabled_global().load(Ordering::Relaxed) {
        let stop_audio = crate::server_stop_signal();
        let grace_audio = capture_grace_stop();
        let run_audio_stop_task = run_audio_stop.clone();
        tokio::spawn(async move {
            let (audio_pkt_tx, mut audio_pkt_rx) =
                tokio::sync::mpsc::channel::<Vec<EncodedPacket>>(32);
            let audio_tx_task = audio_pkt_tx.clone();
            let stop_pipe = stop_audio;
            let grace_pipe = grace_audio;
            let run_stop_pipe = run_audio_stop_task;
            tokio::task::spawn_blocking(move || {
                // 端点（无声卡机器零开销、零 WARN 噪声）；关闭即 stop + 释放
                let mut machine = AudioToggleMachine::new();
                let mut pipeline: Option<kirin_desk_media::AudioPipeline> = None;
                loop {
                    // 消亡。测试/runtime 丢弃时异步任务先于 blocking 池
                    // 排空被 drop → 本线程 ≤50ms 内退出；缺此条件时三个
                    // 停止原子量在丢弃路径上**无人置位**（run 尾部 store
                    // 在 pump 循环被 drop 前不会执行），blocking 池 drop
                    // 无限等待本线程 → 进程退出挂死（r74e 全测卡死根因）。
                    // 生产语义不变：run 存活期间 recv 端存活 → 恒 false。
                    if stop_pipe.load(Ordering::Relaxed)
                        || grace_pipe.load(Ordering::Relaxed)
                        || run_stop_pipe.load(Ordering::Relaxed)
                        || audio_tx_task.is_closed()
                    {
                        break;
                    }
                    match machine.step(crate::server_audio_allowed()) {
                        AudioToggleAction::Start => {
                            // 防御：清残留旧流水线（不变式下应为 None；stop 幂等）。
                            if let Some(mut old) = pipeline.take() {
                                old.stop();
                            }
                            // 日志三落点①：启动尝试 INFO（关键参数：端点+格式）。
                            tracing::info!(
                                "[audio] loopback capture start attempt: {}",
                                loopback_attempt_params()
                            );
                            match start_loopback_pipeline() {
                                Ok(p) => {
                                    // 日志三落点②：成功 INFO（WASAPI 线程另打
                                    // 实际 mix 格式行 `WASAPI loopback capture
                                    // started: mix=...`，wasapi.rs:349-356）。
                                    tracing::info!(
                                        "[audio] loopback capture started ({}Hz/{}ch)",
                                        p.sample_rate(),
                                        p.channels()
                                    );
                                    machine.mark_started();
                                    pipeline = Some(p);
                                }
                                Err(e) => {
                                    // 日志三落点③：失败 WARN（EncodeError 含
                                    // HRESULT/原因）。开关保持开时不重试
                                    // （无声卡场景避免 WARN 风暴）；下一次
                                    // 关→开 边沿重新尝试（状态机边沿重置）。
                                    tracing::warn!(
                                        "[audio] loopback capture start failed: {e} — idle until next off→on toggle"
                                    );
                                    machine.mark_start_failed();
                                }
                            }
                            // 本轮已花在建/启上；下轮进入发送/空闲节奏。
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        AudioToggleAction::Stop => {
                            if let Some(mut p) = pipeline.take() {
                                // 排空在途 PCM 后停：stop_flag + join → 捕获
                                // 线程 ≤10ms 退出并释放 COM（无线程/设备泄漏）。
                                let _ = p.next_packets();
                                p.stop();
                                tracing::info!("[audio] loopback capture stopped (switch off)");
                            }
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                        AudioToggleAction::Running => match pipeline.as_mut() {
                            Some(p) => match p.next_packets() {
                                Ok(pkts) if !pkts.is_empty() => {
                                    if audio_tx_task.try_send(pkts).is_err() {
                                        tracing::debug!("[audio] batch dropped (send loop busy)");
                                    }
                                }
                                Ok(_) => {
                                    std::thread::sleep(std::time::Duration::from_millis(5));
                                }
                                Err(e) => {
                                    // 日志三落点③（运行期变体）：WARN → 停
                                    // 捕获 + 释放；用户关→开可恢复。
                                    tracing::warn!(
                                        "[audio] audio pipeline error: {e} — stopping capture (re-enable via off→on)"
                                    );
                                    // 取所有权停止：drop(&mut) 为 no-op 不放
                                    // 设备/线程——take 出 owned 值，stop 后随
                                    // 作用域结束 drop（WASAPI 线程 join + COM
                                    if let Some(mut owned) = pipeline.take() {
                                        owned.stop();
                                    }
                                    machine.mark_start_failed();
                                    std::thread::sleep(std::time::Duration::from_millis(50));
                                }
                            },
                            // 防御分支（不变式：Running ⟺ pipeline Some；
                            // 若被破坏 → 对齐为「无流水线 + 失败待边沿」）。
                            None => {
                                machine.mark_start_failed();
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                        },
                        AudioToggleAction::Idle | AudioToggleAction::WaitRetry => {
                            // 关 / 失败等 关→开 边沿：低频轮询（50ms ≪ 2s）。
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                    }
                }
                if let Some(mut p) = pipeline {
                    let _ = p.next_packets();
                    p.stop();
                    tracing::info!("[audio] loopback capture stopped (session end)");
                } else {
                    tracing::debug!("[audio] loopback capture task exited (never started or already stopped)");
                }
            });
            // 捕获线程退出后全部 Sender 尽失 → recv() 返回 None → 发送循环
            // 退出 → 本任务终结。缺此 drop 时本 async 块局部 audio_pkt_tx
            // 永久持有通道 → 任务永挂（修复前既有泄漏，本岗一并修复）。
            drop(audio_pkt_tx);
            // 发送循环：广播给全部观众（音频可丢）。
            while let Some(pkts) = audio_pkt_rx.recv().await {
                // ≥1000ms 1 行/秒；每批至多 1 行，代表=批首包；门控 =
                // latency_trace 同源）。字段口径（进程内 ms）：sid=0
                // （服务端全局流槽位，与 srv-vid 同口径）/ v=当前观众数
                // （广播扇出）/ snd0=捕获锚点（会话 ms pts=音频侧帧关联
                // 键，wire pts 服务端单源）/ snd1=广播环到达锚点（同一
                // 会话时钟基 = snd0 + snd_dt）/ snd_dt=捕获→广播环到达
                // 总间隔（Instant 基，含 WASAPI 捕获 + opus 编码 + 通道 +
                // 环调度；批首包为基）/ bytes=首包 Opus 帧字节 / key=首包
                // is_key（Opus 无关键帧语义，仅编码器初始化后首包=1）。
                if let Some(first) = pkts.first() {
                    let now_i = Instant::now();
                    let span_ms = now_i
                        .saturating_duration_since(first.ts.instant)
                        .as_millis() as u64;
                    if latency_trace::r123_step(
                        0,
                        latency_trace::R123_STREAM_SND,
                        latency_trace::epoch_ms(),
                    ) {
                        tracing::info!(
                            viewer_count(),
                            first.ts.pts,
                            first.ts.pts.saturating_add(span_ms),
                            span_ms,
                            first.data.len(),
                            u8::from(first.is_key),
                        );
                    }
                }
                for pkt in pkts {
                    broadcast_packet(&pkt).await;
                }
            }
        });
    }


    // 时携带；None = 关闭，逐字节行为与现状一致）。
    enum PumpOut {
        Window(kirin_desk_media::proto::EncodedWindow, bool, Option<(u64, u64)>),
        /// 显示器切换失败 → 定向 Nack 回请求方。
        Nack { session_id: u64, reason: String },
    }
    let (pump_tx, mut pump_rx) = tokio::sync::mpsc::unbounded_channel::<PumpOut>();
    let task_start_encode = task_start;

    // 原 async 任务内联做阻塞 std mpsc 接收 + FFmpeg 编码（70-90ms/窗），
    // 占用 tokio worker 且与广播/发送任务争抢调度——发送节奏抖动的帮凶。
    // 现整体搬到 blocking 线程（与 media 会话 run_server_session 同模式），
    // 编码窗口经无界通道送异步广播循环（广播 200ms 关键帧补投阻塞不再
    // 拖慢捕获/编码节奏）。
    let encode_handle = tokio::task::spawn_blocking(move || {
        let stop_capture = crate::server_stop_signal();
        let grace_stop = capture_grace_stop();
        let force_idr_flag = capture_force_idr();
        let mut window_count: u64 = 0;
        let mut force_idr_next = false;
        let mut idr_pending = false;
        // 任一变化即重算 override 并强制 IDR 干净重开。
        let mut applied_tier = u32::MAX;
        let mut applied_hq: Option<bool> = None;

        loop {
            if stop_capture.load(Ordering::Relaxed) {
                info!("Capture loop stopping by user request");
                break;
            }
            if grace_stop.load(Ordering::Relaxed) {
                info!("Capture loop stopping by viewer-count grace");
                break;
            }

            // applied_hq=None → 按常态首态应用，与 applied_tier=MAX 同节奏）。
            let tier = bitrate_tier().load(Ordering::Relaxed);
            let hq = r126b_quality_high().load(Ordering::Relaxed) == 1;
            if tier != applied_tier || applied_hq != Some(hq) {
                let prev_hq = applied_hq.unwrap_or(false);
                applied_tier = tier;
                applied_hq = Some(hq);
                let (cw, ch) = capture.resolution();
                let base = kirin_desk_media::encoder::video::rate_ladder::bitrate_for_resolution(cw, ch);
                let bps = r126b_quality_bitrate_for(base, tier, hq);
                pipeline.encoder().set_bitrate_override(bps);
                force_idr_next = true;
                if hq != prev_hq {
                    info!(
                        if hq { "high quality" } else { "normal" },
                        tier,
                        bps.map(|b| b.to_string())
                            .unwrap_or_else(|| "ladder".to_string())
                    );
                }
            }

            // 显示器切换命令——会话内热切换（重建捕获源，无需重连）。
            if let Ok(req) = switch_rx.try_recv() {
                match capture.switch_monitor(req.index as usize) {
                    Ok(()) => {
                        let (sw, sh) = capture.resolution();
                        info!("Capture: switched to monitor {} ({}x{})", req.index, sw, sh);
                        force_idr_next = true;
                        injector.blocking_lock().set_resolution(sw, sh);
                        let (nw, nh) = output_dims_for(sw, sh, max_width);
                        scaler = if (nw, nh) != (sw, sh) {
                            kirin_desk_media::ffmpeg::scale::SwsConverter::new(
                                sw as i32,
                                sh as i32,
                                kirin_desk_media::ffmpeg::AV_PIX_FMT_RGBA,
                                nw as i32,
                                nh as i32,
                                kirin_desk_media::ffmpeg::AV_PIX_FMT_RGBA,
                            )
                            .ok()
                            .map(SendScaler)
                        } else {
                            None
                        };
                        *capture_coord_dims().lock().unwrap() = Some((nw, nh, sw, sh));
                    }
                    Err(e) => {
                        tracing::error!(
                            "Capture: switch monitor {} failed: {} — keeping current",
                            req.index, e
                        );
                        let reason = format!("switch monitor {} failed: {e}", req.index);
                        if pump_tx
                            .send(PumpOut::Nack {
                                session_id: req.session_id,
                                reason,
                            })
                            .is_err()
                        {
                            break; // 广播循环已退出（会话结束）。
                        }
                    }
                }
            }

            // 阻塞等待新帧（静默屏幕定期醒来处理切换命令/档位变更）。
            match capture.wait_for_frame_timeout(Duration::from_millis(200)) {
                Ok(frame) => {
                    // 宁可丢帧不涨延迟（流畅优先）。软编高分辨率/低配机编码
                    // 慢于捕获率时延迟不再雪崩。
                    let frame = capture.drain_latest_frame().unwrap_or(frame);
                    let capture_ms = if latency_trace::enabled() {
                        latency_trace::epoch_ms()
                    } else {
                        0
                    };
                    let forced = window_count == 0
                        || force_idr_next
                        || force_idr_flag.swap(false, Ordering::Relaxed);
                    force_idr_next = false;
                    idr_pending |= forced;
                    //（码率阶梯按实际编码分辨率自动取档）。
                    let (frame_data, fw, fh) = if let Some(s) = scaler.as_ref().map(|w| &w.0) {
                        let mut out = vec![0u8; (out_w as usize) * (out_h as usize) * 4];
                        let src: [*const u8; 4] = [frame.data().as_ptr(), ptr::null(), ptr::null(), ptr::null()];
                        let src_stride: [i32; 4] =
                            [(frame.width() as usize * 4) as i32, 0, 0, 0];
                        let dst: [*mut u8; 4] = [out.as_mut_ptr(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut()];
                        let dst_stride: [i32; 4] = [(out_w as usize * 4) as i32, 0, 0, 0];
                        match s.scale(&src, &src_stride, &dst, &dst_stride) {
                            Ok(_) => (out, out_w, out_h),
                            Err(e) => {
                                (frame.data().to_vec(), frame.width(), frame.height())
                            }
                        }
                    } else {
                        (frame.data().to_vec(), frame.width(), frame.height())
                    };
                    let raw = RawFrame {
                        data: Arc::new(frame_data),
                        width: fw,
                        height: fh,
                        timestamp: std::time::SystemTime::now(),
                        dirty_rects: frame.dirty_rects().to_vec(),
                        force_key: forced,
                    };
                    // 最近 2000ms 有客户端输入 → 目标至少中间档（高分辨率
                    // 屏交互引起的小变化——悬停/菜单/回显/慢速移动——可能
                    // 被 tile 采样误判「静态」钉 1fps；人在操作期间〔含停
                    // 顿与 WAN 回包〕不依赖屏幕活动度启发式。零输入 → 地
                    // 板关，档位回启发式）。
                    {
                        let now_ms = latency_trace::epoch_ms();
                        let floor = if client_input_recent(
                            last_client_input_ms().load(Ordering::Relaxed),
                            now_ms,
                        ) {
                            pipeline.fps_governor_config().low_fps
                        } else {
                            0.0
                        };
                        pipeline.set_activity_floor(floor);
                    }
                    match pipeline.push_frame(raw) {
                        Ok(Some(encoded_window)) => {
                            window_count = encoded_window.window_id;
                            let is_idr = idr_pending;
                            idr_pending = false;
                            let marks = if latency_trace::enabled() {
                                let enc_done = latency_trace::epoch_ms();
                                latency_trace::record(
                                    latency_trace::Stage::Enc,
                                    (enc_done.saturating_sub(capture_ms)) as f64,
                                );
                                Some((capture_ms, enc_done))
                            } else {
                                None
                            };
                            if pump_tx
                                .send(PumpOut::Window(encoded_window, is_idr, marks))
                                .is_err()
                            {
                                break; // 广播循环已退出（会话结束）。
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::error!("Window pipeline error: {} — retrying", e);
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
                Err(e) => {
                    match &e {
                        kirin_desk_media::capture::CaptureError::Timeout => {
                            // "已到期但未关窗"的滞留帧。帧泵模式下滞留帧至多
                            // 一帧（门控丢旧保新），补发即最新内容。
                            match pipeline.flush_window_if_expired() {
                                Ok(Some(encoded_window)) => {
                                    window_count = encoded_window.window_id;
                                    let is_idr = idr_pending;
                                    idr_pending = false;
                                    // 时刻不可考，锚点取 flush 时刻（enc≈0；xfer
                                    // 段略低估，仅静态屏路径，不影响动态内容口径）。
                                    let marks = if latency_trace::enabled() {
                                        let now = latency_trace::epoch_ms();
                                        Some((now, now))
                                    } else {
                                        None
                                    };
                                    if pump_tx
                                        .send(PumpOut::Window(encoded_window, is_idr, marks))
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    tracing::error!(
                                        "Window pipeline flush-if-expired error: {err}"
                                    );
                                }
                            }
                            continue;
                        }
                        kirin_desk_media::capture::CaptureError::AccessLost => {
                            tracing::error!(
                                "Capture access lost — closing capture, will recreate"
                            );
                            break;
                        }
                        kirin_desk_media::capture::CaptureError::NoMonitor
                        | kirin_desk_media::capture::CaptureError::InvalidMonitor => {
                            tracing::error!("Capture: {} — stopping capture", e);
                            break;
                        }
                        _ => {
                            tracing::error!("Capture error: {} — sleeping and retrying", e);
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            }
        }
        window_count
    });

    let mut window_count: u64 = 0;
    let mut tier_tick = tokio::time::interval(Duration::from_secs(1));
    tier_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_trace_tick = latency_trace::first_tick();
    // CAPTURE_LIVE_TICK_SECS 次一行）。
    let mut live_tick_count: u64 = 0;
    loop {
        tokio::select! {
            out = pump_rx.recv() => {
                match out {
                    Some(PumpOut::Window(encoded_window, is_idr, marks)) => {
                        broadcast_encoded_window(
                            &encoded_window,
                            is_idr,
                            task_start_encode,
                            &mut window_count,
                            marks,
                        )
                        .await;
                    }
                    Some(PumpOut::Nack { session_id, reason }) => {
                        if let Ok(data) =
                            bincode::serialize(&ControlMessage::DisplaySelectNack { reason })
                        {
                            let pkt = EncodedPacket {
                                ts: Timestamp::now(),
                                kind: PacketKind::Control,
                                data,
                                is_key: false,
                            };
                            send_to_viewer(session_id, pkt).await;
                        }
                    }
                    None => break, // 编码线程退出（停止/宽限/致命错误）。
                }
            }
            _ = tier_tick.tick() => {
                maybe_tier_step_up();
                latency_trace::maybe_summary("srv", &mut last_trace_tick);
                // 5s 周期一行）——行的存在 = 本世代广播环存活；行内
                // last_frame_age_ms 持续增长 = 无帧在产（静屏正常 / 编码环
                // 僵死同形，区分靠本行是否继续出现；僵死叠加观众加入由
                // 无帧看门狗自动强制重启兜底）。
                live_tick_count += 1;
                if live_tick_count % CAPTURE_LIVE_TICK_SECS == 0 {
                    let now = latency_trace::epoch_ms();
                    let last = last_video_frame_ms().load(Ordering::Relaxed);
                    let age = if last == 0 {
                        None
                    } else {
                        Some(now.saturating_sub(last))
                    };
                    info!("{}", r134_1_cap_live_line(gen, viewer_count(), age));
                }
            }
        }
    }
    // 回收编码线程（取最终窗口计数）。
    let final_count = encode_handle.await.unwrap_or(window_count);
    info!("Capture loop exited after {} windows", final_count);
    // 重试路径不设全局 stop/grace（且循环会复位 grace），必须经本标志让
    // 本 run 的音频任务在 ≤50ms 内退出并释放捕获线程/WASAPI 设备。
    run_audio_stop.store(true, Ordering::Relaxed);
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod r62_tests {
    use super::*;

    // `use super::*` 共用同一把锁。

    fn make_pkt(key: bool, seq: u64) -> EncodedPacket {
        EncodedPacket {
            ts: Timestamp::now(),
            kind: PacketKind::Video,
            data: seq.to_be_bytes().to_vec(),
            is_key: key,
        }
    }

    /// 注册一个测试观众（不经 register_viewer，避免起发送任务/生命周期）。
    async fn add_test_viewer(id: u64) -> tokio::sync::mpsc::Receiver<EncodedPacket> {
        let (tx, rx) = tokio::sync::mpsc::channel(VIEWER_BUFFER);
        let (end_tx, _end_rx) = tokio::sync::mpsc::channel(1);
        insert_viewer(
            id,
            ViewerEntry {
                peer_id: format!("test-{id}"),
                negotiated_codec: Codec::H264,
                pkt_tx: tx,
                lagging: false,
                end_tx,
            },
        )
        .await;
        rx
    }

    /// ① 注册表增删 / 并发安全。
    #[tokio::test]
    async fn registry_add_remove_concurrent() {
        let _g = test_serial().lock().await;
        // 并发 8 任务 × 各 25 对插入/删除（互不重叠的 id 段）。
        let mut joins = Vec::new();
        for t in 0..8u64 {
            joins.push(tokio::spawn(async move {
                for i in 0..25u64 {
                    let id = t * 1000 + i;
                    let rx = add_test_viewer(id).await;
                    drop(rx);
                    assert!(remove_viewer_inner(id).await);
                }
            }));
        }
        for j in joins {
            j.await.unwrap();
        }
        assert_eq!(viewer_count(), 0);
        // 单插单删。
        let rx = add_test_viewer(999_999).await;
        assert_eq!(viewer_count(), 1);
        drop(rx);
        assert!(remove_viewer_inner(999_999).await);
        assert_eq!(viewer_count(), 0);
        // 重复删除无害。
        assert!(!remove_viewer_inner(999_999).await);
    }

    /// ② 广播分发：N 个观众各收到帧。
    #[tokio::test]
    async fn broadcast_delivers_to_all_viewers() {
        let _g = test_serial().lock().await;
        let mut rxs = Vec::new();
        for id in 1..=5u64 {
            rxs.push(add_test_viewer(id).await);
        }
        broadcast_packet(&make_pkt(true, 42)).await;
        for rx in rxs.iter_mut() {
            let pkt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .expect("timeout")
                .expect("channel closed");
            assert_eq!(pkt.data, 42u64.to_be_bytes());
            assert!(pkt.is_key);
        }
        for id in 1..=5u64 {
            remove_viewer_inner(id).await;
        }
    }

    /// ③ 慢观众丢帧：缓冲满丢非关键帧；慢期间非关键帧跳过；关键帧恢复。
    #[tokio::test]
    async fn slow_viewer_drops_to_keyframe() {
        let _g = test_serial().lock().await;
        let mut slow_rx = add_test_viewer(1).await;
        let mut fast_rx = add_test_viewer(2).await;
        // 填满慢观众缓冲（cap=8）：9 个非关键帧 → 前 8 入队、第 9 丢弃并置慢；
        // 快观众每轮排空（不积压 → 不慢）。
        let mut got_fast: u64 = 0;
        for seq in 0..9u64 {
            broadcast_packet(&make_pkt(false, seq)).await;
            while let Ok(_) = fast_rx.try_recv() {
                got_fast += 1;
            }
        }
        // 慢观众标记已置位：后续非关键帧全部跳过（快观众仍应收到）。
        broadcast_packet(&make_pkt(false, 100)).await;
        while let Ok(_) = fast_rx.try_recv() {
            got_fast += 1;
        }
        // 快观众 10 帧全部收到（未受慢观众影响）。
        assert_eq!(got_fast, 10);
        // 慢观众仅收到前 8 帧（第 9 与 100 均未入队）。
        let mut got_slow = 0;
        while let Ok(_) = slow_rx.try_recv() {
            got_slow += 1;
        }
        assert_eq!(got_slow, 8);
        // 关键帧到达：缓冲已排空 → try_send 成功，慢标记复位。
        broadcast_packet(&make_pkt(true, 200)).await;
        let pkt = tokio::time::timeout(Duration::from_secs(1), slow_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert!(pkt.is_key);
        // 复位后非关键帧恢复投递。
        broadcast_packet(&make_pkt(false, 201)).await;
        let pkt = tokio::time::timeout(Duration::from_secs(1), slow_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert!(!pkt.is_key);
        remove_viewer_inner(1).await;
        remove_viewer_inner(2).await;
    }

    /// ③b 关键帧补投：缓冲满时关键帧经限时阻塞路径送达（消费方腾出容量）。
    #[tokio::test]
    async fn keyframe_delivered_via_timeout_path() {
        let _g = test_serial().lock().await;
        let mut rx = add_test_viewer(7).await;
        for seq in 0..VIEWER_BUFFER as u64 {
            broadcast_packet(&make_pkt(false, seq)).await;
        }
        // 缓冲满：关键帧 try_send 失败 → 200ms 限时阻塞补投；并发排空一帧
        // 腾出容量 → 关键帧入队成功。
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = rx.recv().await;
        });
        broadcast_packet(&make_pkt(true, 77)).await;
        // 关键帧在注册表侧已入队（此处从注册表行为反证：非关键帧恢复投递）。
        broadcast_packet(&make_pkt(false, 78)).await;
        remove_viewer_inner(7).await;
    }

    /// ④ 观众退出/通道关闭不影响他人（模拟发送失败）。
    #[tokio::test]
    async fn closed_viewer_does_not_affect_others() {
        let _g = test_serial().lock().await;
        let gone_rx = add_test_viewer(1).await;
        let mut alive_rx = add_test_viewer(2).await;
        drop(gone_rx); // 模拟观众发送任务失败/断开（接收端 drop）。
        broadcast_packet(&make_pkt(true, 1)).await;
        // 关闭的观众被踢出注册表；存活观众正常收到。
        let pkt = tokio::time::timeout(Duration::from_secs(1), alive_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert_eq!(pkt.data, 1u64.to_be_bytes());
        assert_eq!(viewer_count(), 1);
        remove_viewer_inner(2).await;
        assert_eq!(viewer_count(), 0);
    }

    /// ⑤ 生命周期决策纯函数 + 慢观众决策纯函数。
    #[test]
    fn lifecycle_decision_table() {
        use CaptureAction::*;
        // 首位观众接入（未运行 → 启动）。
        assert_eq!(capture_action_on_viewer_change(false, 1), Start);
        // 已运行 + 观众增减（仍 >0）→ 无动作。
        assert_eq!(capture_action_on_viewer_change(true, 2), None);
        assert_eq!(capture_action_on_viewer_change(true, 1), None);
        // 观众清零 + 运行中 → 排定宽限停止。
        assert_eq!(capture_action_on_viewer_change(true, 0), ScheduleGraceStop);
        // 观众清零 + 未运行 → 无动作。
        assert_eq!(capture_action_on_viewer_change(false, 0), None);
        // 宽限到期：仍 0 → 停；有观众 → 不停。
        assert!(grace_expired_should_stop(0));
        assert!(!grace_expired_should_stop(1));
    }

    #[test]
    fn lag_skip_decision_table() {
        use LagSkip::*;
        assert_eq!(lag_skip_decision(false, false), Send);
        assert_eq!(lag_skip_decision(false, true), Send);
        assert_eq!(lag_skip_decision(true, true), Send); // 关键帧始终尝试送达
        assert_eq!(lag_skip_decision(true, false), Skip); // 慢 + 非关键 → 丢
    }

    // ══════════════════════════════════════════════════════════════
    // ══════════════════════════════════════════════════════════════

    /// 排定宽限停止（旧实现缺口：只删条目不排宽限，捕获任务永不停止）。
    #[test]
    fn r673_kick_lifecycle_decision() {
        // 踢出后仍有观众 → 不排（None 决策）。
        assert!(!kick_lifecycle_should_schedule_grace(true, 2));
        assert!(!kick_lifecycle_should_schedule_grace(false, 1));
        // 踢光 + 捕获运行中 → 排定宽限。
        assert!(kick_lifecycle_should_schedule_grace(true, 0));
        // 踢光 + 捕获未运行 → 无动作。
        assert!(!kick_lifecycle_should_schedule_grace(false, 0));
    }

    #[tokio::test]
    async fn r673_kick_last_viewer_clears_count() {
        let _g = test_serial().lock().await;
        let gone = add_test_viewer(1).await;
        drop(gone); // 观众通道关闭（发送任务退出 / 链路僵死）。
        // 广播触发踢出（Closed → kick）。
        broadcast_packet(&make_pkt(true, 9)).await;
        assert_eq!(viewer_count(), 0, "kicked viewer must leave the registry");
        assert!(!crate::server_controlled_active(), "受控判定必须归零");
    }

    /// 归零（黄框/受控中判定链：viewer 计数 + 隐私/文件槽全空）。
    #[tokio::test]
    async fn r673_controlled_active_resets_after_viewer_exit() {
        let _g = test_serial().lock().await;
        let rx = add_test_viewer(31337).await;
        assert_eq!(viewer_count(), 1);
        assert!(
            crate::server_controlled_active(),
            "有观众时会话应判定为活动（黄框显示）"
        );
        // 模拟连接级任务退出：通道关闭 + remove_viewer（keepalive 触发的读错
        // 退出 / 正常断开退出都汇聚到这里）。
        drop(rx);
        assert!(remove_viewer_inner(31337).await);
        assert_eq!(viewer_count(), 0, "计数徽标源必须复位");
        assert!(
            !crate::server_controlled_active(),
            "全部观众退出后受控判定必须归零（黄框消失）"
        );
    }

    /// （真实 TCP：客户端 drop 后服务端写失败，viewer_send_task 的
    /// 「发送失败踢出路径」——keepalive 之外的另一条观众移除路径回归）。
    #[tokio::test]
    async fn r673_dead_connection_send_failure_removes_viewer() {
        use kirin_desk_core::crypto::aead::AeadCipher;
        use kirin_desk_core::crypto::handshake::SecureChannel;
        let _g = test_serial().lock().await;

        // 本地 TCP 对：客户端侧随后 drop，模拟主控异常断开。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_sock, _) = listener.accept().await.unwrap();
        // 生产路径在 TcpServer::accept 统一启用；此处显式锻炼辅助函数。
        kirin_desk_core::network::tcp::set_keepalive(&server_sock).unwrap();

        // 组装真实 SecureChannelSender（dummy 密钥即可——只关心写路径错误）。
        let ch = SecureChannel {
            stream: server_sock,
            cipher: AeadCipher::new(&[0u8; 32]),
            peer_id: "dead-peer".to_string(),
            peer_domain: String::new(),
            peer_device_type: "desktop".to_string(),
            selected_codec: String::new(),
        };
        let (_reader, writer) = ch.into_split();
        let sender: SharedSender = Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(
            writer,
        )));

        // 注册观众 + 启动发送任务（register_viewer 同款任务体）。
        let id = 4242u64;
        let (tx, rx) = tokio::sync::mpsc::channel(VIEWER_BUFFER);
        let (end_tx, end_rx) = tokio::sync::mpsc::channel(1);
        insert_viewer(
            id,
            ViewerEntry {
                peer_id: "dead-peer".to_string(),
                negotiated_codec: Codec::H264,
                pkt_tx: tx,
                lagging: false,
                end_tx,
            },
        )
        .await;
        assert!(crate::server_controlled_active());
        tokio::spawn(viewer_send_task(
            id,
            rx,
            end_rx,
            sender,
            VIEWER_HEARTBEAT_INTERVAL,
        ));

        // 客户端断开 → 广播若干帧驱动发送 → 写失败 → 任务退出 → 注销。
        drop(client);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut seq = 0u64;
        while viewer_count() > 0 && std::time::Instant::now() < deadline {
            broadcast_packet(&make_pkt(false, seq)).await;
            seq += 1;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            viewer_count(),
            0,
            "死连接观众必须被发送失败路径注销（推送 {seq} 帧后）"
        );
        assert!(!crate::server_controlled_active(), "黄框判定归零");
    }

    // ════════════════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════════════════

    /// 发出 `ControlMessage::Heartbeat`（间隔不密集、不遗漏）；② 帧流恢复
    /// （15ms/帧）期间**零心跳**（行为锚：正常会话零额外开销）；③ 帧流停止
    /// 后心跳按周期恢复。
    #[tokio::test]
    async fn r74g_idle_heartbeat_interval_flow_gate() {
        use kirin_desk_core::crypto::aead::AeadCipher;
        use kirin_desk_core::crypto::handshake::SecureChannel;
        use kirin_desk_media::transport::{ChannelTag, SecureChannelReceiver};
        let _g = test_serial().lock().await;

        // 本地 TCP 对 + 双端 dummy 密钥通道（同密钥双向：每消息随机 nonce）。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_sock, _) = listener.accept().await.unwrap();
        let mk = |stream: tokio::net::TcpStream| SecureChannel {
            stream,
            cipher: AeadCipher::new(&[0u8; 32]),
            peer_id: "r74g-hb".to_string(),
            peer_domain: String::new(),
            peer_device_type: "desktop".to_string(),
            selected_codec: String::new(),
        };
        let (c_reader, c_writer) = mk(client_sock).into_split();
        let (_s_reader, s_writer) = mk(server_sock).into_split();
        let mut rx = SecureChannelReceiver::new(c_reader);
        let sender: SharedSender =
            Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(s_writer)));

        let id = 7401u64;
        let (tx, rxp) = tokio::sync::mpsc::channel(VIEWER_BUFFER);
        let (end_tx, end_rx) = tokio::sync::mpsc::channel(1);
        insert_viewer(
            id,
            ViewerEntry {
                peer_id: "r74g-hb".to_string(),
                negotiated_codec: Codec::H264,
                pkt_tx: tx.clone(),
                lagging: false,
                end_tx,
            },
        )
        .await;
        let hb_iv = Duration::from_millis(150); // 注入小周期（生产 3s）
        tokio::spawn(viewer_send_task(id, rxp, end_rx, sender, hb_iv));

        // ① 空档：3 个心跳按周期到达（间隔不密集 ≥ 100ms，允许 CI 抖动）。
        let t0 = Instant::now();
        let mut prev: Option<Instant> = None;
        for _ in 0..3 {
            let (tag, _h, payload) =
                tokio::time::timeout(Duration::from_secs(3), rx.recv_tagged())
                    .await
                    .expect("心跳超时")
                    .expect("通道断开");
            assert_eq!(tag, ChannelTag::Control, "空档包必须是 Control tag");
            match bincode::deserialize::<ControlMessage>(&payload) {
                Ok(ControlMessage::Heartbeat { .. }) => {}
                other => panic!("空档包必须是 Heartbeat，got {other:?}"),
            }
            let now = Instant::now();
            if let Some(p) = prev {
                let gap = now.duration_since(p);
                assert!(
                    gap >= Duration::from_millis(100),
                    "心跳过于密集（{gap:?} < 100ms）——应为周期发出"
                );
            }
            prev = Some(now);
        }
        assert!(
            t0.elapsed() <= Duration::from_millis(hb_iv.as_millis() as u64 * 3 + 1500),
            "心跳到达过慢（{:?}）——周期偏离注入值",
            t0.elapsed()
        );

        // ② 帧流：15ms/帧 × 25 帧（≈375ms ≥ 2.5 个心跳周期）→ 期间零心跳。
        let tx_pump = tx.clone();
        let pump = tokio::spawn(async move {
            for i in 0..25u64 {
                let _ = tx_pump.send(make_pkt(false, i)).await;
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        });
        let flow_deadline = Instant::now() + Duration::from_millis(375 + 400);
        let mut video_got = 0u32;
        while video_got < 25 && Instant::now() < flow_deadline {
            let (tag, _h, _p) =
                tokio::time::timeout(Duration::from_secs(2), rx.recv_tagged())
                    .await
                    .expect("帧流超时")
                    .expect("通道断开");
            assert_eq!(
                tag,
                ChannelTag::Video,
                "帧流期间不得出现心跳/控制包（零额外开销行为锚）"
            );
            video_got += 1;
        }
        assert_eq!(video_got, 25, "帧流 25 帧必须全部送达");
        pump.await.unwrap();

        // ③ 帧流停止 → 心跳按周期恢复（最后一个视频帧后 ≤ 2 个周期内到达）。
        let (tag, _h, payload) =
            tokio::time::timeout(hb_iv * 4, rx.recv_tagged())
                .await
                .expect("帧流停止后心跳未恢复")
                .expect("通道断开");
        assert_eq!(tag, ChannelTag::Control);
        match bincode::deserialize::<ControlMessage>(&payload) {
            Ok(ControlMessage::Heartbeat { .. }) => {}
            other => panic!("恢复包必须是 Heartbeat，got {other:?}"),
        }

        // 清理：走生产断链路径——客户端写半 drop（FIN/RST）→ 心跳发送失败
        // → 任务退出 → remove_viewer（注销同时释放条目内 pkt_tx 克隆）。
        // 注：不能靠 drop(tx) 关通道——ViewerEntry 持有 pkt_tx 克隆（广播
        // 总线用），通道永不关闭（与生产一致：退出由发送失败/显式注销驱动）。
        drop(c_writer);
        drop(rx);
        let deadline = Instant::now() + Duration::from_secs(5);
        while viewer_count() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(viewer_count(), 0, "观众必须注销");
    }

    /// 发送失败 → 观众移除。此前该场景只能等 SO_KEEPALIVE（数分钟）——
    /// 用户「被控端退出后主控端旧画面停留数分钟」的服务端侧镜像。
    #[tokio::test]
    async fn r74g_heartbeat_failure_removes_viewer_on_dead_conn() {
        use kirin_desk_core::crypto::aead::AeadCipher;
        use kirin_desk_core::crypto::handshake::SecureChannel;
        let _g = test_serial().lock().await;

        // 本地 TCP 对：客户端随后 drop（模拟主控异常断开，无 RST 的静默
        // 场景在 Windows 上由首次写失败/RST 送达兜住——周期心跳持续探测）。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_sock, _) = listener.accept().await.unwrap();
        let ch = SecureChannel {
            stream: server_sock,
            cipher: AeadCipher::new(&[0u8; 32]),
            peer_id: "r74g-dead".to_string(),
            peer_domain: String::new(),
            peer_device_type: "desktop".to_string(),
            selected_codec: String::new(),
        };
        let (_reader, writer) = ch.into_split();
        let sender: SharedSender = Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(
            writer,
        )));

        let id = 7402u64;
        let (tx, rxp) = tokio::sync::mpsc::channel(VIEWER_BUFFER);
        let (end_tx, end_rx) = tokio::sync::mpsc::channel(1);
        insert_viewer(
            id,
            ViewerEntry {
                peer_id: "r74g-dead".to_string(),
                negotiated_codec: Codec::H264,
                pkt_tx: tx,
                lagging: false,
                end_tx,
            },
        )
        .await;
        tokio::spawn(viewer_send_task(
            id,
            rxp,
            end_rx,
            sender,
            Duration::from_millis(200), // 注入小周期（生产 3s）
        ));

        // 客户端断开，**不推送任何帧**——仅心跳驱动发送失败。
        drop(client_sock);
        let deadline = Instant::now() + Duration::from_secs(10);
        while viewer_count() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            viewer_count(),
            0,
            "死连接零帧场景：心跳发送失败路径必须注销观众"
        );
        assert!(!crate::server_controlled_active(), "黄框判定归零");
    }

    // ════════════════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════════════════

    /// （register_viewer → run_capture_once 捕获/编码/广播 → viewer_send_task
    /// 加密发送）+ **生产同构客户端管线**（recv → EncodedWindow 反序列化 →
    /// DecoderPacket → 真解码线程（KIRIN_NOHW_HW_DECODE=1 软解）→
    /// RenderBridge → 60fps 泵 pop），端到端各段 p50/p95 表。
    ///
    /// 运行（**单独跑**——`KIRIN_LATENCY_TRACE` 进程级一次性读取；建议同时
    /// 开动态内容窗：`scripts/r77d_anim.ps1`，`-Mode rect`=大面积运动档 /
    /// `-Mode dot`=光标级小变化〔复现用户「鼠标移动画面才跟上」场景〕）：
    ///
    /// ```bash
    /// KIRIN_NOHW_HW_DECODE=1 cargo test -p kirin-desk-ui --lib \
    ///   -- --ignored r77d_latency_bench_loopback --nocapture
    /// ```
    ///
    /// 产出：enc/bus/sendq（服务端）+ xfer/decode/render/e2e（客户端）
    /// 各段 p50/p95/max（ms），与 5s 周期 INFO 汇总行互为印证。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "manual latency bench: needs real desktop + dynamic content; run with --nocapture, standalone"]
    async fn r77d_latency_bench_loopback() {
        use kirin_desk_core::crypto::ed25519::IdentityManager;
        use kirin_desk_core::crypto::handshake as hs;
        use kirin_desk_core::crypto::handshake::{PinExpectation, SecureChannel};
        use kirin_desk_media::decoder::{
            factory, frame_id_to_pts, DecoderPacket, RenderBridge,
        };
        let _g = test_serial().lock().await;
        crate::server_stop_signal().store(false, Ordering::Relaxed);
        // 打点门控（进程级一次性读取）——bench 须单独跑（与其它测试并行会
        // 被先跑的测试把门控固化为 off）。
        std::env::set_var("KIRIN_LATENCY_TRACE", "1");
        assert!(
            latency_trace::enabled(),
            "latency trace gate not enabled — run this bench standalone"
        );
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_target(false)
            .try_init();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tmp = std::env::temp_dir();
        let server_im =
            IdentityManager::generate(tmp.join("kirin_r77d_bench_s.key")).expect("server id");
        let client_im =
            IdentityManager::generate(tmp.join("kirin_r77d_bench_c.key")).expect("client id");
        let server_pub = server_im.public_key_base64();
        let client_pub = client_im.public_key_base64();

        // 服务端：accept → 完整握手 → 注册观众（真实捕获+编码+广播+发送）。
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = kirin_desk_core::network::tcp::set_nodelay(&stream);
            let ch = hs::server_handshake_verified_generic(
                stream,
                &server_im,
                "r77d-bench-server",
                &client_pub,
            )
            .await
            .expect("server handshake");
            let ch = SecureChannel {
                stream: ch.stream,
                cipher: ch.cipher,
                peer_id: ch.peer_id,
                peer_domain: ch.peer_domain,
                peer_device_type: ch.peer_device_type,
                selected_codec: ch.selected_codec,
            };
            let (_reader, writer) = ch.into_split();
            let sender: SharedSender = Arc::new(tokio::sync::Mutex::new(
                kirin_desk_media::transport::SecureChannelSender::new(writer),
            ));
            register_reserved_viewer(
                reserve_viewer_id(),
                "r77d-bench-client".into(),
                Codec::H264,
                sender,
                0,
            )
            .await
        });

        // 客户端：拨号 + 完整握手。
        let cstream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = kirin_desk_core::network::tcp::set_nodelay(&cstream);
        let ch = hs::client_handshake_generic(
            cstream,
            &client_im,
            "r77d-bench-client",
            "bench.local",
            "desktop",
            "r77d-bench-server",
            PinExpectation::exact_from_base64(&server_pub).unwrap(),
            "challenge",
        )
        .await
        .expect("client handshake");
        let ch = SecureChannel {
            stream: ch.stream,
            cipher: ch.cipher,
            peer_id: ch.peer_id,
            peer_domain: ch.peer_domain,
            peer_device_type: ch.peer_device_type,
            selected_codec: ch.selected_codec,
        };
        let (reader, _writer) = ch.into_split();
        let mut rx = kirin_desk_media::transport::SecureChannelReceiver::new(reader);
        let session_id = server_task.await.expect("server join");
        eprintln!("[bench] viewer #{session_id} registered — measuring up to 12s");

        // ── 生产同构客户端管线 ────────────────────────────────────
        let bridge = RenderBridge::new(2, 16);
        let (pkt_tx, pkt_rx) = std::sync::mpsc::channel::<DecoderPacket>();
        // 真解码线程（生产同款拓扑：专用 std::thread + 回退链解码器）。
        let decode_bridge = bridge.clone();
        let decode_handle = std::thread::Builder::new()
            .name("r77d-bench-decode".into())
            .spawn(move || {
                let mut decoder = match factory::create_video_decoder(
                    kirin_desk_media::encoder::Codec::H264,
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("[bench] decoder init failed: {e}");
                        return;
                    }
                };
                while let Ok(pkt) = pkt_rx.recv() {
                    match decoder.decode(&pkt) {
                        Ok(frames) => {
                            // 与生产解码线程同款 `decode` 段采样。
                            if pkt.recv_ms != 0 {
                                latency_trace::record(
                                    latency_trace::Stage::Decode,
                                    (latency_trace::epoch_ms()
                                        .saturating_sub(pkt.recv_ms)) as f64,
                                );
                            }
                            for f in frames {
                                decode_bridge.push_decoded(f);
                            }
                        }
                        Err(e) => {
                            eprintln!("[bench] decode error: {e}");
                        }
                    }
                }
            })
            .expect("spawn bench decode thread");
        // 60fps 泵（与生产连接窗口同款节奏 + `render`/`e2e` 段采样）。
        let pump_bridge = bridge.clone();
        let pump_stop = Arc::new(AtomicBool::new(false));
        let pump_stop_p = pump_stop.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(16));
            loop {
                iv.tick().await;
                if pump_stop_p.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(frame) = pump_bridge.pop_render() {
                    if frame.capture_ms != 0 && frame.decode_done_ms != 0 {
                        let now = latency_trace::epoch_ms();
                        latency_trace::record(
                            latency_trace::Stage::Render,
                            (now.saturating_sub(frame.decode_done_ms)) as f64,
                        );
                        latency_trace::record(
                            latency_trace::Stage::E2E,
                            (now.saturating_sub(frame.capture_ms)) as f64,
                        );
                    }
                }
            }
        });

        // 接收循环（生产同款阶段划分：recv → xfer 采样 → 反序列化 →
        // DecoderPacket → 解码线程通道）。
        let deadline_total = Instant::now() + Duration::from_secs(40);
        let mut started: Option<Instant> = None;
        'recv: loop {
            if let Some(t0) = started {
                if t0.elapsed() >= Duration::from_secs(12) {
                    break 'recv;
                }
            }
            if Instant::now() >= deadline_total {
                eprintln!("[bench] ABORT: total deadline hit before 12s window");
                break 'recv;
            }
            let (tag, header, payload) =
                match tokio::time::timeout(Duration::from_secs(5), rx.recv_tagged()).await {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        eprintln!("[bench] recv error: {e}");
                        break 'recv;
                    }
                    Err(_) => {
                        eprintln!("[bench] 5s no data");
                        break 'recv;
                    }
                };
            if tag != kirin_desk_media::transport::ChannelTag::Video {
                continue 'recv;
            }
            // 与生产接收循环同款 `xfer` 段采样（pts 旁路 = capture 锚点）。
            let capture_ms = if latency_trace::enabled() { header.pts } else { 0 };
            let recv_ms = if latency_trace::is_epoch_ts(capture_ms) {
                let now = latency_trace::epoch_ms();
                latency_trace::record(
                    latency_trace::Stage::Xfer,
                    (now.saturating_sub(capture_ms)) as f64,
                );
                now
            } else {
                0
            };
            let Ok(window) =
                bincode::deserialize::<kirin_desk_media::proto::EncodedWindow>(&payload)
            else {
                continue 'recv;
            };
            if started.is_none() {
                started = Some(Instant::now());
            }
            // 旧格式（frames 嵌套）——与生产 `window_frame_nalus` 同口径。
            for (idx, nals) in window.frames.iter().enumerate() {
                let mut data = Vec::new();
                for n in nals {
                    data.extend_from_slice(n);
                }
                if data.is_empty() {
                    continue;
                }
                let pkt = DecoderPacket {
                    pts: frame_id_to_pts(window.window_id * 10 + idx as u64, 60),
                    data,
                    is_key: idx == 0,
                    extradata: None,
                    capture_ms,
                    recv_ms,
                };
                if pkt_tx.send(pkt).is_err() {
                    break 'recv;
                }
            }
        }

        // 收尾：停捕获 + 注销观众 + 停泵 + join 解码线程。
        pump_stop.store(true, Ordering::Relaxed);
        crate::server_stop_signal().store(true, Ordering::Relaxed);
        remove_viewer(session_id).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(pkt_tx);
        let _ = decode_handle.join();
        crate::server_stop_signal().store(false, Ordering::Relaxed);

        // 报告：全段 p50/p95/max + 服务端节奏。
        let snap = latency_trace::snapshot();
        for s in &snap {
            let name = match s.stage {
                latency_trace::Stage::Enc => "enc (capture→encode)",
                latency_trace::Stage::Bus => "bus (encode→broadcast)",
                latency_trace::Stage::Sendq => "sendq (bus→send done)",
                latency_trace::Stage::Xfer => "xfer (capture→recv)",
                latency_trace::Stage::Decode => "decode (recv→decode done)",
                latency_trace::Stage::Render => "render (decode→UI pop)",
                latency_trace::Stage::E2E => "e2e (capture→render)",
            };
            eprintln!(
                "[bench]   {:<28} n={:>5} p50={:>7.1} p95={:>7.1} max={:>7.1}",
                name, s.n, s.p50, s.p95, s.max
            );
        }
        let pacing = window_pacing_snapshot();
        if !pacing.is_empty() {
            let enc_frames: u32 = pacing.iter().map(|s| s.frames).sum();
            let multi_frame: usize = pacing.iter().filter(|s| s.frames >= 2).count();
            eprintln!(
                "[bench]   server: {} windows / {} frames in {:.2}s (avg encode {:.1}ms); \
                 >=2-frame batch windows: {multi_frame}/{} = {:.1}%",
                pacing.len(),
                enc_frames,
                pacing
                    .last()
                    .unwrap()
                    .broadcast
                    .duration_since(pacing.first().unwrap().broadcast)
                    .as_secs_f64(),
                pacing.iter().map(|s| s.encode_ms).sum::<f64>() / pacing.len() as f64,
                pacing.len(),
                100.0 * multi_frame as f64 / pacing.len() as f64
            );
        }
        if snap.iter().all(|s| s.stage != latency_trace::Stage::E2E || s.n == 0) {
            eprintln!("[bench] WARN: no e2e samples — dynamic content on screen?");
        }
    }

    // ════════════════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════════════════

    /// 客户端**生产读侧**（`recv_tagged_with_watchdog` + Control 分发口径）
    /// 在 **<1s** 内收到 `ControlMessage::Disconnect`（走 lost 路径），
    /// 且观众全部注销（发送任务退出、注册表清零）。
    ///
    /// 对照场景（修复前）：观众发送任务继续 3s 空档心跳永久刷新客户端
    /// 10s 看门狗 → 客户端无限等待（比 10s 更糟）。
    #[tokio::test]
    async fn r77d_server_stop_notifies_client_immediately() {
        use kirin_desk_core::crypto::aead::AeadCipher;
        use kirin_desk_core::crypto::handshake::SecureChannel;
        use kirin_desk_media::transport::{ChannelTag, SecureChannelReceiver};
        let _g = test_serial().lock().await;

        // 本地 TCP 对 + 双端 dummy 密钥通道（同 r74g 测试口径）。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_sock, _) = listener.accept().await.unwrap();
        let mk = |stream: tokio::net::TcpStream| SecureChannel {
            stream,
            cipher: AeadCipher::new(&[0u8; 32]),
            peer_id: "r77d-stop".to_string(),
            peer_domain: String::new(),
            peer_device_type: "desktop".to_string(),
            selected_codec: String::new(),
        };
        let (c_reader, _c_writer) = mk(client_sock).into_split();
        let (_s_reader, s_writer) = mk(server_sock).into_split();
        let mut rx = SecureChannelReceiver::new(c_reader);
        let sender: SharedSender =
            Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(s_writer)));

        // 注册观众 + 启动发送任务（生产同款；心跳周期注入 200ms）。
        let id = 7701u64;
        let (tx, rxp) = tokio::sync::mpsc::channel(VIEWER_BUFFER);
        let (end_tx, end_rx) = tokio::sync::mpsc::channel(1);
        let tx_pump = tx.clone();
        insert_viewer(
            id,
            ViewerEntry {
                peer_id: "r77d-stop".to_string(),
                negotiated_codec: Codec::H264,
                pkt_tx: tx,
                lagging: false,
                end_tx,
            },
        )
        .await;
        tokio::spawn(viewer_send_task(
            id,
            rxp,
            end_rx,
            sender,
            Duration::from_millis(200),
        ));

        // 先投一帧视频（验证 FIFO：残留帧先于 Disconnect 送达）。
        tx_pump.send(make_pkt(true, 1)).await.expect("viewer buffer");

        // 服务端停止：即时会话结束通知 + 注销。
        let t0 = Instant::now();
        notify_viewers_session_end("server stopping (r77d test)").await;

        // 客户端生产口径读侧：recv_tagged_with_watchdog（看门狗阈值用生产
        // 10s——断言 <1s 到达即证明**不是**等看门狗）+ Control 分发口径。
        let mut got_video = 0u32;
        let mut got_disconnect: Option<String> = None;
        let deadline = Instant::now() + Duration::from_secs(5); // 硬兜底
        while got_disconnect.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!("5s 硬兜底到期仍未收到 Disconnect");
            }
            let (tag, _h, payload) =
                tokio::time::timeout(remaining, crate::recv_tagged_with_watchdog(
                    &mut rx,
                    std::time::Duration::from_secs(10),
                ))
                .await
                .expect("5s 硬兜底到期")
                .expect("client recv error");
            match tag {
                ChannelTag::Video => got_video += 1,
                ChannelTag::Control => {
                    if let Ok(ControlMessage::Disconnect { reason }) =
                        bincode::deserialize::<ControlMessage>(&payload)
                    {
                        got_disconnect = Some(reason);
                    }
                }
                _ => {}
            }
        }
        let elapsed = t0.elapsed();
        assert!(
            got_video >= 1,
            "残留视频帧必须先于 Disconnect 送达（FIFO），got {got_video}"
        );
        let Some(reason) = got_disconnect else {
            panic!("no Disconnect within 5s");
        };
        assert_eq!(reason, "server stopping (r77d test)");
        assert!(
            elapsed < Duration::from_secs(1),
            "客户端必须在 1s 内收到会话结束信号（实测 {elapsed:?}）——不等 10s 看门狗"
        );
        // 观众全部注销（发送任务退出 → 注册表清零 → 受控判定归零）。
        assert_eq!(viewer_count(), 0, "观众必须注销");
        assert!(!crate::server_controlled_active(), "黄框判定归零");
    }

    /// （1/2040 ≈ 0.00049），否则高分辨率屏光标级小变化被钉静态档 1fps；
    /// 档位语义（1/30/60）保持不变。
    #[test]
    fn r77d_r68a_config_static_ratio_4k_safe() {
        let cfg = r68a_fps_governor_config();
        assert!(
            cfg.static_ratio < 1.0 / 2040.0,
            "static_ratio {} 必须小于 4K 单 tile 活动度 1/2040",
            cfg.static_ratio
        );
        assert!(cfg.static_ratio > 0.0, "必须 >0（否则永不降静态档）");
        assert_eq!(cfg.static_fps, 1.0, "静态档 1fps");
        assert_eq!(cfg.low_fps, 30.0, "中间档 30fps");
        assert_eq!(cfg.motion_fps, 60.0, "运动档 60fps");
    }

    /// （覆盖操作停顿与 WAN 输入回包）/ 从未输入 / 时钟回拨安全侧
    /// + 打戳路径（mark 后判 recent）+ 宽限值钉死 2000（防回退 200）。
    #[test]
    fn r77d_client_input_recent() {
        assert!(!client_input_recent(0, 1_000), "从未有输入 → false");
        assert!(
            client_input_recent(1_000, 3_000),
            "恰好 2000ms 宽限边界 → true"
        );
        assert!(!client_input_recent(1_000, 3_001), "2001ms 出宽限窗 → false");
        assert!(
            client_input_recent(5_000, 3_000),
            "时钟回拨 → 安全侧 true（保持地板）"
        );
        mark_client_input();
        let last = last_client_input_ms().load(Ordering::Relaxed);
        assert!(last > 0, "打戳后非零");
        assert!(client_input_recent(last, last));
    }

    // ════════════════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════════════════

    /// bench 到达样本（客户端视角的一个窗口到达记录）。
    struct Arr {
        t: Instant,
        wid: u64,
        frames: u32,
        bytes: usize,
    }

    /// （register_viewer → run_capture_once → broadcast → viewer_send_task
    /// → SecureChannel 大帧发送）+ 真实握手 TCP 回环客户端，测量：
    /// 服务端编码窗口节奏（帧率/字节/编码耗时）vs 客户端到达节奏
    /// （窗口率/吞吐/到达间隔/端到端延迟）。
    ///
    /// 运行（建议同时播放动态内容，如 ffplay testsrc2）：
    /// `cargo test -p kirin-desk-ui --lib -- --ignored r68_lan_bench --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "manual throughput bench: needs real desktop; run with --nocapture"]
    async fn r68_lan_bench_real_capture_loopback() {
        use kirin_desk_core::crypto::ed25519::IdentityManager;
        use kirin_desk_core::crypto::handshake as hs;
        use kirin_desk_core::crypto::handshake::{PinExpectation, SecureChannel};
        let _g = test_serial().lock().await;
        crate::server_stop_signal().store(false, Ordering::Relaxed);
        // bench 日志可见性（RUST_LOG 可覆盖；默认 info）。
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_target(false)
            .try_init();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tmp = std::env::temp_dir();
        let server_im =
            IdentityManager::generate(tmp.join("kirin_r68_bench_s.key")).expect("server id");
        let client_im =
            IdentityManager::generate(tmp.join("kirin_r68_bench_c.key")).expect("client id");
        let server_pub = server_im.public_key_base64();
        let client_pub = client_im.public_key_base64();

        // 服务端：accept → 完整握手 → 注册观众（启动真实捕获+编码+广播）。
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = kirin_desk_core::network::tcp::set_nodelay(&stream);
            let ch = hs::server_handshake_verified_generic(
                stream,
                &server_im,
                "bench-server",
                &client_pub,
            )
            .await
            .expect("server handshake");
            // 泛型结果 → TCP 专用 SecureChannel（字段一一对应）。
            let ch = SecureChannel {
                stream: ch.stream,
                cipher: ch.cipher,
                peer_id: ch.peer_id,
                peer_domain: ch.peer_domain,
                peer_device_type: ch.peer_device_type,
                selected_codec: ch.selected_codec,
            };
            let (_reader, writer) = ch.into_split();
            let sender: SharedSender = Arc::new(tokio::sync::Mutex::new(
                kirin_desk_media::transport::SecureChannelSender::new(writer),
            ));
            register_reserved_viewer(
                reserve_viewer_id(),
                "bench-client".into(),
                Codec::H264,
                sender,
                0,
            )
            .await
        });

        // 客户端：拨号 + 完整握手 + 接收循环。
        let cstream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = kirin_desk_core::network::tcp::set_nodelay(&cstream);
        let ch = hs::client_handshake_generic(
            cstream,
            &client_im,
            "bench-client",
            "bench.local",
            "desktop",
            "bench-server",
            PinExpectation::exact_from_base64(&server_pub).unwrap(),
            "challenge",
        )
        .await
        .expect("client handshake");
        // 泛型结果 → TCP 专用 SecureChannel（与服务端侧对称）。
        let ch = SecureChannel {
            stream: ch.stream,
            cipher: ch.cipher,
            peer_id: ch.peer_id,
            peer_domain: ch.peer_domain,
            peer_device_type: ch.peer_device_type,
            selected_codec: ch.selected_codec,
        };
        let (reader, _writer) = ch.into_split();
        let mut rx = kirin_desk_media::transport::SecureChannelReceiver::new(reader);
        let session_id = server_task.await.expect("server join");
        eprintln!("[bench] viewer #{session_id} registered — measuring up to 12s");

        // 测量窗口：首个窗口到达后计时 12s（总兜底 40s）。
        let mut arrivals: Vec<Arr> = Vec::new();
        let deadline_total = Instant::now() + Duration::from_secs(40);
        let mut started: Option<Instant> = None;
        loop {
            if let Some(t0) = started {
                if t0.elapsed() >= Duration::from_secs(12) {
                    break;
                }
            }
            if Instant::now() >= deadline_total {
                eprintln!("[bench] ABORT: total deadline hit before 12s window");
                break;
            }
            let (tag, _hdr, payload) =
                match tokio::time::timeout(Duration::from_secs(5), rx.recv_tagged()).await {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        eprintln!("[bench] recv error: {e}");
                        break;
                    }
                    Err(_) => {
                        eprintln!("[bench] 5s no data");
                        break;
                    }
                };
            if tag != kirin_desk_media::transport::ChannelTag::Video {
                eprintln!("[bench] non-video tag arrived: {tag:?}");
                continue;
            }
            let Ok(w) =
                bincode::deserialize::<kirin_desk_media::proto::EncodedWindow>(&payload)
            else {
                continue;
            };
            if started.is_none() {
                started = Some(Instant::now());
            }
            arrivals.push(Arr {
                t: Instant::now(),
                wid: w.window_id,
                frames: w.frame_count,
                bytes: payload.len(),
            });
        }

        // 服务端视角样本（同进程 → Instant 可比）。
        let pacing = window_pacing_snapshot();
        bench_report(&arrivals, &pacing, started);
        // 逐窗口明细（前 30 条：broadcast/到达/延迟）。
        let by_wid: HashMap<u64, Instant> =
            pacing.iter().map(|s| (s.window_id, s.broadcast)).collect();
        for a in arrivals.iter().take(30) {
            if let Some(b) = by_wid.get(&a.wid) {
                eprintln!(
                    "[trace] wid={:>3} bcast=+{:>8.1}ms recv=+{:>8.1}ms lat={:>7.1}ms bytes={}",
                    a.wid,
                    b.duration_since(arrivals[0].t).as_secs_f64() * 1000.0,
                    a.t.duration_since(arrivals[0].t).as_secs_f64() * 1000.0,
                    a.t.duration_since(*b).as_secs_f64() * 1000.0,
                    a.bytes
                );
            }
        }

        // 收尾：停捕获 + 注销观众。
        crate::server_stop_signal().store(true, Ordering::Relaxed);
        remove_viewer(session_id).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        crate::server_stop_signal().store(false, Ordering::Relaxed);
    }

    /// bench 报告：客户端到达节奏 + 服务端编码节奏 + 端到端延迟。
    fn bench_report(arrivals: &[Arr], pacing: &[WindowPacingSample], started: Option<Instant>) {
        use std::fmt::Write as _;
        let mut out = String::new();
        if arrivals.is_empty() {
            eprintln!("[bench] NO windows received — server sent nothing");
            return;
        }
        let Some(t0) = started else { return };
        let dur = arrivals.last().unwrap().t.duration_since(t0).as_secs_f64();
        let total_bytes: usize = arrivals.iter().map(|a| a.bytes).sum();
        let total_frames: u32 = arrivals.iter().map(|a| a.frames).sum();
        let _ = writeln!(
            out,
            "[client] {} windows / {} frames / {:.1} KB in {:.2}s → {:.1} windows/s, {:.1} fps, {:.0} KB/s ({:.2} Mbps)",
            arrivals.len(),
            total_frames,
            total_bytes as f64 / 1024.0,
            dur,
            arrivals.len() as f64 / dur,
            total_frames as f64 / dur,
            total_bytes as f64 / 1024.0 / dur,
            total_bytes as f64 * 8.0 / dur / 1e6
        );
        // 到达间隔分布。
        let mut gaps: Vec<f64> = Vec::new();
        for pair in arrivals.windows(2) {
            gaps.push(pair[1].t.duration_since(pair[0].t).as_secs_f64() * 1000.0);
        }
        gaps.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pct = |g: &[f64], p: f64| -> f64 {
            if g.is_empty() {
                0.0
            } else {
                g[((g.len() as f64 - 1.0) * p).round() as usize]
            }
        };
        let _ = writeln!(
            out,
            "[client] inter-window gap ms: p50={:.0} p90={:.0} p99={:.0} max={:.0}",
            pct(&gaps, 0.5),
            pct(&gaps, 0.9),
            pct(&gaps, 0.99),
            gaps.last().copied().unwrap_or(0.0)
        );
        // 每窗口字节。
        let mut wb: Vec<usize> = arrivals.iter().map(|a| a.bytes).collect();
        wb.sort_unstable();
        let _ = writeln!(
            out,
            "[client] window bytes: min={} p50={} max={}",
            wb.first().copied().unwrap_or(0),
            wb.get(wb.len() / 2).copied().unwrap_or(0),
            wb.last().copied().unwrap_or(0)
        );
        // 服务端编码节奏 + 端到端（broadcast → 客户端到达，同进程 Instant 对齐）。
        if !pacing.is_empty() {
            let enc_frames: u32 = pacing.iter().map(|s| s.frames).sum();
            let enc_bytes: usize = pacing.iter().map(|s| s.bytes).sum();
            let span = pacing
                .last()
                .unwrap()
                .broadcast
                .duration_since(pacing.first().unwrap().broadcast)
                .as_secs_f64();
            let _ = writeln!(
                out,
                "[server] {} windows / {} frames / {:.1} KB in {:.2}s → {:.1} windows/s, {:.1} fps, {:.0} KB/s; avg encode {:.1}ms",
                pacing.len(),
                enc_frames,
                enc_bytes as f64 / 1024.0,
                span,
                pacing.len() as f64 / span.max(1e-9),
                enc_frames as f64 / span.max(1e-9),
                enc_bytes as f64 / 1024.0 / span.max(1e-9),
                pacing.iter().map(|s| s.encode_ms).sum::<f64>() / pacing.len() as f64
            );
            let by_wid: HashMap<u64, Instant> =
                pacing.iter().map(|s| (s.window_id, s.broadcast)).collect();
            let mut lat: Vec<f64> = arrivals
                .iter()
                .filter_map(|a| {
                    by_wid
                        .get(&a.wid)
                        .map(|b| a.t.duration_since(*b).as_secs_f64() * 1000.0)
                })
                .collect();
            if !lat.is_empty() {
                lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
                let _ = writeln!(
                    out,
                    "[e2e] broadcast→recv ms: p50={:.1} p90={:.1} p99={:.1} max={:.1} (n={})",
                    pct(&lat, 0.5),
                    pct(&lat, 0.9),
                    pct(&lat, 0.99),
                    lat.last().copied().unwrap_or(0.0),
                    lat.len()
                );
            }
        }
        eprintln!("{out}");
    }
}

// ════════════════════════════════════════════════════════════════
//
// WASAPI 实调用（端点获取/Initialize/GetBuffer）无单测面——真实行为以
// 用户 79/179 双机复测覆盖（开关开 ≥10s → 查 [audio] 三落点日志行 +
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod r79c_tests {
    use super::*;

    /// ① 决策表：(开关 × 流水线 × 近期失败) 全组合 → 动作。
    ///
    /// 钉死 PM 口径 a/b：默认关 = 任务常驻但空闲（修复前此态「任务不存在」
    /// = 3.2s 零落点根因）；关→开 = 启动尝试；开→关 = 停止 + 释放。
    #[test]
    fn r79c_toggle_decision_table() {
        let mut m = AudioToggleMachine::new();
        // 初始：关 + 无流水线 → 空闲轮询。
        assert_eq!(m.step(false), AudioToggleAction::Idle);
        // 关→开：启动尝试。
        assert_eq!(m.step(true), AudioToggleAction::Start);
        // 启动成功 → 保持发送。
        m.mark_started();
        assert_eq!(m.step(true), AudioToggleAction::Running);
        assert_eq!(m.step(true), AudioToggleAction::Running);
        // 开→关：停止 + 释放（机器自复位）。
        assert_eq!(m.step(false), AudioToggleAction::Stop);
        // 关 + 无流水线 → 空闲（无重复 Stop）。
        assert_eq!(m.step(false), AudioToggleAction::Idle);
    }

    /// ② 中途生效 + 失败重试边沿（79 复测口径的决策级等价）：
    /// 失败后开关保持开不重试（无 WARN 风暴）；关→开 边沿重置 → 再尝试；
    /// 停止后重新开启 → 再次 Start（重开 = 重启，无需重连）。
    #[test]
    fn r79c_mid_session_toggle_and_failure_retry_edge() {
        let mut m = AudioToggleMachine::new();
        assert_eq!(m.step(false), AudioToggleAction::Idle);

        // 首次开：尝试 → 模拟初始化失败（无声卡/端点不可达）。
        assert_eq!(m.step(true), AudioToggleAction::Start);
        m.mark_start_failed();
        // 开关保持开：只等待，不重复尝试。
        assert_eq!(m.step(true), AudioToggleAction::WaitRetry);
        assert_eq!(m.step(true), AudioToggleAction::WaitRetry);
        // 关→开 边沿：重置失败标记 → 重新尝试（用户再开 = 新尝试 + 新日志落点）。
        assert_eq!(m.step(false), AudioToggleAction::Idle);
        assert_eq!(m.step(true), AudioToggleAction::Start);
        // 此次成功 → 运行。
        m.mark_started();
        assert_eq!(m.step(true), AudioToggleAction::Running);
        // 关 → 停止（释放）；再开 → 再次 Start（口径 b：重开→重新启动捕获）。
        assert_eq!(m.step(false), AudioToggleAction::Stop);
        assert_eq!(m.step(true), AudioToggleAction::Start);
        m.mark_started();
        assert_eq!(m.step(true), AudioToggleAction::Running);
    }

    /// ③ 不变式：`pipeline_ready` ⟺ 任务实际持有流水线——Start 未成功/失败/
    /// Stop 之后绝不出现「Running 但无流水线」或「无流水线却 Stop」。
    #[test]
    fn r79c_machine_invariant_no_stale_ready() {
        let mut m = AudioToggleMachine::new();
        m.step(false); // 稳定初始态
        // 失败路径：Start → 失败 → 其间只能 WaitRetry（无 Running/Stop 假象）。
        assert_eq!(m.step(true), AudioToggleAction::Start);
        m.mark_start_failed();
        assert_eq!(m.step(true), AudioToggleAction::WaitRetry);
        assert_eq!(m.step(false), AudioToggleAction::Idle); // 无流水线 → 无 Stop
        // 成功路径：Stop 必须先经 mark_started，且 Stop 后不再二次 Stop。
        assert_eq!(m.step(true), AudioToggleAction::Start);
        m.mark_started();
        assert_eq!(m.step(true), AudioToggleAction::Running);
        assert_eq!(m.step(false), AudioToggleAction::Stop);
        assert_eq!(m.step(false), AudioToggleAction::Idle);
    }

    /// ④ 尝试日志参数组装：关键参数（端点 + 格式）必须齐全——
    /// 钉死三落点口径「启动尝试 INFO 含端点/格式」（防后续漂移）。
    #[test]
    fn r79c_attempt_params_carry_endpoint_and_format() {
        let s = loopback_attempt_params();
        for needle in [
            "eRender",
            "eConsole",
            "AUDCLNT_STREAMFLAGS_LOOPBACK",
            "48000Hz",
            "2ch",
            "float32",
            "Opus",
        ] {
            assert!(
                s.contains(needle),
                "attempt params missing {needle}: {s}"
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod r83c_tests {
    use super::*;

    fn make_pkt(key: bool, seq: u64) -> EncodedPacket {
        EncodedPacket {
            ts: Timestamp::now(),
            kind: PacketKind::Video,
            data: seq.to_be_bytes().to_vec(),
            is_key: key,
        }
    }

    /// 时机单测：延迟注册/踢出探测纯决策（`deferred_viewer_tick`，生产分发
    /// 任务首包点与 500ms kick-watch tick 的判定单一点）——决策表全枚举：
    ///
    /// | packet | registered | in_registry | 期望        | 语义 |
    /// |--------|------------|-------------|-------------|------|
    /// | T      | F          | F           | Register    | 首包 = 握手完全完成 → 注册（唯一触发） |
    /// | T      | T          | T           | Continue    | 已注册后续包（不重复注册） |
    /// | T      | T          | F           | EndDispatch | 首包同刻已被踢 → 按踢出收敛 |
    /// | F      | F          | T           | Continue    | 异常态（未注册却在表）→ 不激进行动 |
    /// | F      | T          | T           | Continue    | 已注册正常 |
    /// | F      | T          | F           | EndDispatch | 已注册且被踢（看门狗）→ 分发任务退出 |
    #[test]
    fn r83c_deferred_viewer_tick_decision_table() {
        use DeferredViewerTick::*;
        assert_eq!(
            deferred_viewer_tick(true, false, false),
            Register,
            "首包到达且未注册 → 注册（握手完全完成的唯一触发）"
        );
        assert_eq!(
            deferred_viewer_tick(true, true, true),
            Continue,
            "已注册后续包 → 不重复注册"
        );
        assert_eq!(
            deferred_viewer_tick(true, true, false),
            EndDispatch,
            "已注册且已被踢（极端同刻窗口）→ 收敛"
        );
        assert_eq!(
            deferred_viewer_tick(false, false, false),
            Continue,
            "TOFU 等待期（未注册、首包未到）恒 Continue——旧口径把 \
             「不在表内」误读为「被踢」= 22.25s 慢启动被误杀"
        );
        assert_eq!(
            deferred_viewer_tick(false, false, true),
            Continue,
            "异常态（未注册却在表）→ 不激进行动"
        );
        assert_eq!(
            deferred_viewer_tick(false, true, true),
            Continue,
            "已注册正常 → 保持"
        );
        assert_eq!(
            deferred_viewer_tick(false, true, false),
            EndDispatch,
            "已注册且被踢出（关键帧看门狗）→ 分发任务退出"
        );
    }

    /// 帧队列满〕→ 关键帧补投 200ms 超时踢出 → ① 注册表即时移除（真死链路
    /// 快速回收语义保持）② 客户端在卡点解除后 **<1s** 收到
    /// `ControlMessage::Disconnect`（end 通道 biased 最高优先送达，复用
    /// 重连决策，不等 10s 看门狗）。
    ///
    /// 卡死模拟：测试持发送半锁 = 生产「发送任务阻塞于停滞 TCP 写」的等价
    /// 形态（任务在 `sender.lock()` 等待，帧队列不可排空）→ 队列必满 →
    /// 关键帧补投超时必现（200ms 生产预算，无注入）。
    #[tokio::test]
    async fn r83c_kicked_viewer_notifies_client_within_1s() {
        use kirin_desk_core::crypto::aead::AeadCipher;
        use kirin_desk_core::crypto::handshake::SecureChannel;
        use kirin_desk_media::transport::{ChannelTag, SecureChannelReceiver};
        let _g = test_serial().lock().await;

        // 本地 TCP 对 + 双端 dummy 密钥通道（r77d 同口径）。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_sock, _) = listener.accept().await.unwrap();
        let mk = |stream: tokio::net::TcpStream| SecureChannel {
            stream,
            cipher: AeadCipher::new(&[0u8; 32]),
            peer_id: "r83c-kick".to_string(),
            peer_domain: String::new(),
            peer_device_type: "desktop".to_string(),
            selected_codec: String::new(),
        };
        let (c_reader, _c_writer) = mk(client_sock).into_split();
        let (_s_reader, s_writer) = mk(server_sock).into_split();
        let mut rx = SecureChannelReceiver::new(c_reader);
        let sender: SharedSender = Arc::new(tokio::sync::Mutex::new(
            SecureChannelSender::new(s_writer),
        ));

        // 注册观众 + 发送任务（生产同款任务体；心跳注入 300s 避免干扰）。
        let id = 8301u64;
        let (tx, rxp) = tokio::sync::mpsc::channel(VIEWER_BUFFER);
        let (end_tx, end_rx) = tokio::sync::mpsc::channel(1);
        let tx_pump = tx.clone();
        insert_viewer(
            id,
            ViewerEntry {
                peer_id: "r83c-kick".to_string(),
                negotiated_codec: Codec::H264,
                pkt_tx: tx,
                lagging: false,
                end_tx,
            },
        )
        .await;
        tokio::spawn(viewer_send_task(
            id,
            rxp,
            end_rx,
            sender.clone(),
            Duration::from_secs(300),
        ));

        // 链路活性锚：客户端收到一帧（发送任务正常运行中）。
        tx_pump.send(make_pkt(true, 1)).await.expect("viewer buffer");
        let (tag, _h, _p) = tokio::time::timeout(Duration::from_secs(3), rx.recv_tagged())
            .await
            .expect("3s 内必须收到首帧")
            .expect("client recv error");
        assert_eq!(tag, ChannelTag::Video);

        // 卡死模拟：持发送半锁（= 发送任务阻塞于停滞写）→ 帧队列不可排空。
        let guard = sender.lock().await;
        // **稳定化**（防竞态）：先投一帧让发送任务取走并阻塞在锁上——
        // 任务 dequeue 不持锁但发送必持锁，此帧后任务必然 parked 于
        // `sender.lock()`，无法再 dequeue（否则队列残留 pending 唤醒会在
        // 200ms 补投窗口内取出一个槽位使关键帧「假送达」——非生产形态）。
        tx_pump.send(make_pkt(false, 700)).await.expect("viewer buffer");
        tokio::time::sleep(Duration::from_millis(100)).await;
        // 任务已阻塞于锁 → try_send 循环填队（不可再被排空）→ 队列必满。
        for seq in 0..64u64 {
            if tx_pump.try_send(make_pkt(false, seq)).is_err() {
                break;
            }
        }
        assert!(
            tx_pump.try_send(make_pkt(false, 999)).is_err(),
            "帧队列必须已满（任务说明死不可排空）——否则关键帧补投超时不成立"
        );

        let t_kick = Instant::now();
        broadcast_packet(&make_pkt(true, 200)).await;
        assert_eq!(
            viewer_count(),
            0,
            "关键帧补投超时必须把观众移出注册表（真死链路快速回收语义不变）"
        );

        // 解除卡点 → 发送任务：在途帧 → end 通知（biased 最高优先）→ 退出。
        drop(guard);
        let mut got_disconnect: Option<String> = None;
        let deadline = Instant::now() + Duration::from_secs(1);
        while got_disconnect.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.recv_tagged()).await {
                Ok(Ok((tag, _h, payload))) => {
                    if tag == ChannelTag::Control {
                        if let Ok(ControlMessage::Disconnect { reason }) =
                            bincode::deserialize::<ControlMessage>(&payload)
                        {
                            got_disconnect = Some(reason);
                        }
                    }
                }
                _ => break,
            }
        }
        let Some(reason) = got_disconnect else {
        };
        assert_eq!(
            reason, "key-frame deliver timed out (server-side kick)",
            "会话结束原因必须携带踢出根因（取证/复现口径）"
        );
        assert!(
            t_kick.elapsed() < Duration::from_secs(2),
            "踢出（含 200ms 补投预算）+ 通知送达必须在 2s 内（实测 {}）—— \
             客户端侧判定 <1s 从通知送达起算",
            t_kick.elapsed().as_millis()
        );
    }
}

///
/// 锁 winit/Win32 的部分（`Visible(true)` 重同步内部标志、实际重绘）不
/// 钉死可纯测的逻辑：首次胜出幂等 / 未存入 no-op / 隐藏门控跳过。
#[cfg(test)]
mod r85c_tests {
    use super::*;

    /// set 语义：首次装入返回 true，二次装入返回 false（OnceLock 首次胜出，
    /// 槽内保留首值）；`get()` 可见已装入。
    #[test]
    fn r85c_install_ctx_in_first_wins_idempotent() {
        let slot: OnceLock<egui::Context> = OnceLock::new();
        assert!(slot.get().is_none());
        let a = egui::Context::default();
        let b = egui::Context::default();
        assert!(install_ctx_in(&slot, &a), "首次装入必须返回 true");
        assert!(slot.get().is_some(), "装入后 get() 必须可见");
        assert!(!install_ctx_in(&slot, &b), "二次装入必须 no-op 返回 false");
        // 快路径同样成立：已装入 → 零成本 false（不覆盖、不 clone）。
        assert!(!install_ctx_in(&slot, &egui::Context::default()));
    }

    /// get/repaint 语义：未存入 → no-op 不 panic（首帧前调用安全）；
    /// 隐藏门控 → 跳过（与 `lib.rs::main_repaint` 同口径，隐藏窗重绘请求
    /// 无效且致 busy 泵）；可见且已存入 → headless `request_repaint` 不
    /// panic（tokio 自由任务跨线程调用形态与生产一致）。
    #[test]
    fn r85c_request_repaint_in_gating() {
        let slot: OnceLock<egui::Context> = OnceLock::new();
        let ctx = egui::Context::default();
        request_main_repaint_in(&slot, false); // 未存入 → no-op
        request_main_repaint_in(&slot, true); // 未存入 + 隐藏 → no-op
        install_ctx_in(&slot, &ctx);
        request_main_repaint_in(&slot, true); // 已存入但隐藏 → 门控跳过
        request_main_repaint_in(&slot, false); // 已存入且可见 → 实际请求
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod r126b_tests {
    use super::*;

    /// 非高画质 = 既有 `tier_bitrate_for` 口径**零行为变化**（tier 0 = None
    /// 阶梯全档）。慢网络降档保护在高画质下不变（流畅优先红线）。
    #[test]
    fn r126b_quality_bitrate_matrix() {
        let base = 10_000_000u64; // 1080p 档阶梯基准
        // 非高画质 = 现状口径（零行为变化断言）。
        assert_eq!(r126b_quality_bitrate_for(base, 0, false), None);
        assert_eq!(r126b_quality_bitrate_for(base, 1, false), Some(5_000_000));
        assert_eq!(r126b_quality_bitrate_for(base, 2, false), Some(2_500_000));
        assert_eq!(r126b_quality_bitrate_for(base, 3, false), Some(1_250_000));
        assert_eq!(
            r126b_quality_bitrate_for(base, 9, false),
            Some(1_250_000),
            "超 MAX_BITRATE_TIER 钳制 = 与 tier 3 同"
        );
        // 高画质 = 2× 基准再减半。
        assert_eq!(
            r126b_quality_bitrate_for(base, 0, true),
            Some(20_000_000),
            "tier 0 高画质 = 2× 阶梯基准（1080p 10M→20M ≈ 0.32bpp@30fps）"
        );
        assert_eq!(r126b_quality_bitrate_for(base, 1, true), Some(10_000_000));
        assert_eq!(r126b_quality_bitrate_for(base, 2, true), Some(5_000_000));
        assert_eq!(r126b_quality_bitrate_for(base, 3, true), Some(2_500_000));
        // 1Mbps 下限（2× 小基准经 3 档减半后触底）。
        assert_eq!(r126b_quality_bitrate_for(2_000_000, 3, true), Some(1_000_000));
        // 饱和防御（u64 MAX 基准 2× 不溢出）。
        assert!(r126b_quality_bitrate_for(u64::MAX, 0, true).is_some());
    }

    /// fail-safe）+ 幂等（同值二次请求零状态变化）。本模块内唯一触全局位
    /// 的测试（码率矩阵 = 纯函数零全局），收工恢复默认 0。
    #[test]
    fn r126b_display_mode_request_mapping() {
        r126b_quality_high().store(0, Ordering::Relaxed);
        apply_display_mode_request(2);
        assert_eq!(r126b_quality_high().load(Ordering::Relaxed), 1);
        apply_display_mode_request(2); // 幂等：同值零状态变化
        assert_eq!(r126b_quality_high().load(Ordering::Relaxed), 1);
        apply_display_mode_request(0); // 流畅 → 常态
        assert_eq!(r126b_quality_high().load(Ordering::Relaxed), 0);
        apply_display_mode_request(1); // 低延迟 → 常态
        assert_eq!(r126b_quality_high().load(Ordering::Relaxed), 0);
        apply_display_mode_request(99); // 未知值 = 常态（fail-safe 向常态）
        assert_eq!(r126b_quality_high().load(Ordering::Relaxed), 0);
        r126b_quality_high().store(0, Ordering::Relaxed); // 收工恢复默认
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod r134_1_tests {
    use super::*;

    // 本模块测试写入，串行化防并行污染（与 r62/r126b 同锁）。

    /// 日志行格式钉死（四行；常量值同钉——N=3s 在卡内建议 3-5s 区间）。
    #[test]
    fn r134_1_line_formats_pinned() {
        assert_eq!(
            r134_1_reset_line("user stop", 7, true, Some("h264"), 1),
        );
        assert_eq!(
            r134_1_reset_line("no-frame watchdog", 8, false, None, 0),
        );
        assert_eq!(
            r134_1_no_frame_trigger_line(2, NO_FRAME_RESTART_SECS, Some(3215)),
        );
        assert_eq!(
            r134_1_no_frame_trigger_line(5, NO_FRAME_RESTART_SECS, None),
        );
        assert_eq!(
            r134_1_force_restart_line("h264", 1280, 9),
        );
        assert_eq!(
            r134_1_cap_live_line(9, 2, Some(812)),
        );
        assert_eq!(
            r134_1_cap_live_line(9, 0, None),
        );
        // 常量钉死：无帧窗 3s（3-5s 卡内区间下沿——验收「重连 5s 内出首帧」
        // 留 ~1s 给重启后首帧链路）；活性 tick 5s。
        assert_eq!(NO_FRAME_RESTART_SECS, 3);
        assert_eq!(CAPTURE_LIVE_TICK_SECS, 5);
    }

    /// 垂死任务世代守卫决策矩阵（纯函数）。
    #[test]
    fn r134_1_capture_round_exit_decision_matrix() {
        assert_eq!(
            capture_round_exit_decision(3, 3),
            CaptureRoundExit::Current,
            "世代匹配 = 清态归本任务"
        );
        assert_eq!(
            capture_round_exit_decision(3, 4),
            CaptureRoundExit::Superseded,
            "失配 = 更新世代接管，零状态触碰"
        );
        assert_eq!(
            capture_round_exit_decision(3, 10),
            CaptureRoundExit::Superseded,
            "多代跨越同样失配"
        );
    }

    /// 无帧看门狗触发判据矩阵（纯函数）——真 = 强制重启。
    #[test]
    fn r134_1_no_frame_decision_matrix() {
        // a) 停止中 → 不重启（停止语义优先）。
        assert!(!r134_1_no_frame_decision(true, true, true, 0, 1000));
        // b) 捕获已合法退出 → 不重启。
        assert!(!r134_1_no_frame_decision(false, false, true, 0, 1000));
        // c) 触发观众已离场 → 不为已离场观众重启。
        assert!(!r134_1_no_frame_decision(false, true, false, 0, 1000));
        // d) 加入后有帧在产（末帧 ≥ 加入时刻）→ 健康不动。
        assert!(!r134_1_no_frame_decision(false, true, true, 1500, 1000));
        assert!(!r134_1_no_frame_decision(false, true, true, 1000, 1000), "边界：同刻有帧 = 健康");
        // e) 加入后零新帧（末帧早于加入）→ 僵死态 → 重启。
        assert!(r134_1_no_frame_decision(false, true, true, 999, 1000));
        // f) 从未有帧（0 < 加入时刻）→ 重启。
        assert!(r134_1_no_frame_decision(false, true, true, 0, 1000));
    }

    /// (a) 状态清理**确定性**——污染态（09-22 事故形态：running=true +
    /// codec 槽陈旧 + 宽限旗标残留）经 stop 处单一确定点清理后，全量回到
    /// 全新启动等价态；**不等垂死任务**（本测试无捕获任务在跑，清理即完成
    /// = 确定性口径的钉死）。
    #[test]
    fn r134_1_stop_reset_clears_all_state() {
        // 污染态（事故 12:45:45→12:45:53 形态）。
        capture_running().store(true, Ordering::Relaxed);
        *capture_codec_slot().lock().unwrap() = Some(Codec::H264);
        capture_max_width_slot().store(1280, Ordering::Relaxed);
        *capture_coord_dims().lock().unwrap() = Some((1280, 720, 1920, 1080));
        *switch_request_tx().lock().unwrap() = Some({
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<SwitchRequest>();
            tx
        });
        capture_grace_stop().store(true, Ordering::Relaxed);
        r126b_quality_high().store(1, Ordering::Relaxed);
        let gen_before = capture_generation().load(Ordering::Relaxed);
        let grace_gen_before = grace_generation().load(Ordering::Relaxed);

        reset_capture_state_on_stop("user stop");

        // 全量断言：stop 后状态 = 全新启动等价态。
        assert!(!capture_running().load(Ordering::Relaxed), "running 必清");
        assert!(*capture_codec_slot().lock().unwrap() == None, "codec 槽必清");
        assert_eq!(capture_max_width_slot().load(Ordering::Relaxed), 0, "max_w 必清");
        assert!(capture_coord_dims().lock().unwrap().is_none(), "坐标槽必清");
        assert!(switch_request_tx().lock().unwrap().is_none(), "切换通道必清");
        assert!(!capture_grace_stop().load(Ordering::Relaxed), "宽限旗标必清");
        assert_eq!(r126b_quality_high().load(Ordering::Relaxed), 0, "高画质位必清零");
        assert_eq!(
            capture_generation().load(Ordering::Relaxed),
            gen_before + 1,
            "世代必递增（垂死任务自此失配）"
        );
        assert_eq!(
            grace_generation().load(Ordering::Relaxed),
            grace_gen_before + 1,
            "宽限代数必递增（挂起宽限计时器作废）"
        );
    }

    /// 事故复现链回归钉死：污染态下后到观众**误判跳过启动**（修前形态）→
    /// stop 处确定性清理后 → 同一观众必判 **Start** + `converge_codec`
    /// 不再收敛到陈旧编码（修后形态）。
    #[tokio::test]
    async fn r134_1_polluted_state_late_viewer_regression() {
        let _g = test_serial().lock().await;
        // 污染态 = 事故 12:45:53 现场（垂死任务未完成自清理）。
        capture_running().store(true, Ordering::Relaxed);
        *capture_codec_slot().lock().unwrap() = Some(Codec::H264);
        // 修前形态：后到观众 running=true → 判 None 跳过 start_capture。
        assert_eq!(
            capture_action_on_viewer_change(
                capture_running().load(Ordering::Relaxed),
                1
            ),
            CaptureAction::None,
            "污染态复现：后到观众误判「已在播」"
        );
        assert_eq!(
            converge_codec("av1"),
            "h264",
            "污染态复现：收敛到陈旧 codec 槽"
        );

        // 修后：stop 处单一确定点清理（不等垂死任务）。
        reset_capture_state_on_stop("user stop");

        assert_eq!(
            capture_action_on_viewer_change(
                capture_running().load(Ordering::Relaxed),
                1
            ),
            CaptureAction::Start,
            "清理后后到观众必启动捕获"
        );
        assert_eq!(converge_codec("av1"), "av1", "清理后收敛用协商结果");

        // 收工恢复默认（running 保持 false = 默认态；其余已归零）。
        capture_running().store(false, Ordering::Relaxed);
    }

    /// `register_reserved_viewer` 的捕获运行中分支必调用
    /// `spawn_no_frame_watchdog`（viewer 加入 running=true → 看门狗在位）。
    #[test]
    fn r134_1_watchdog_armed_in_register_running_arm() {
        let src = std::fs::read_to_string("src/server_media.rs").expect("read self");
        // 定位 register_reserved_viewer 函数体。
        let start = src
            .find("pub(crate) async fn register_reserved_viewer(")
            .expect("register_reserved_viewer 在位");
        // 从函数首 `{` 起括号配平截取函数体。
        let brace_start = src[start..]
            .find('{')
            .expect("函数体在位")
            + start;
        let mut depth = 0usize;
        let mut end = brace_start + 1;
        for (i, c) in src[brace_start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = brace_start + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let fn_body = &src[start..end];
        assert!(
            fn_body.contains("spawn_no_frame_watchdog(id, codec, max_width)"),
            "register_running 分支必武装无帧看门狗（事故修复接线点）"
        );
    }
}

#[cfg(test)]
mod r136_tests {
    use super::*;

    /// （阈值复核，算术钉死；推导全文见交付报告）。
    ///
    /// 结论：
    /// - 触发器按**槽数**不按字节（`VIEWER_BUFFER=8` mpsc 槽、`broadcast_packet`
    ///   每帧恰一包）——I 帧体积增大不改变槽消耗；
    /// - GOP=30 最坏 8 帧窗 = 1 IDR + 7 P（8 帧窗至多 1 个 IDR，gop≥8），
    ///   fill = 8(k+g−1)⁻¹·… 展开 = 1.0887×(B/R)（k=2, w=8）；
    /// - GOP=60 同式 = 1.1066×(B/R) → T4 把误触发阈值 B/R 从 **0.904 移到
    ///   0.919**（放宽 1.5pp，方向安全）——GOP 缩短不是误触发源；
    /// - 目标 LAN（Gbps 级）：HQ 4K 顶 64M/1G = 6.4% 负载 → fill ≈0.07
    ///   （≈14× 裕度）；1080p 档 10M/1G → ≈0.011；降级 100Mbps 链路：
    ///   10M → ≈0.109（9× 裕度）、32M → ≈0.348——均 ≪1 无误触发；
    ///   响应 + 2s 限速 / 30s 迟滞自愈合，非 T4 误触发）。
    #[test]
    fn test_r136_t4_gop30_iframe_no_false_downgrade() {
        // ① 触发口径钉死：观众缓冲 = 8 槽（按槽不按字节，I 帧大小不占额外槽）。
        assert_eq!(
            VIEWER_BUFFER,
            8,
        );

        let k = 2.0; // I/P 尺寸比保守上界。
        let w = VIEWER_BUFFER as u32;

        // ② 目标 LAN：HQ 4K 顶（32M 阶梯 × 2 = 64M）@1Gbps → fill ≈0.0697。
        let fill = r136_gop_burst_fill_ratio(30, k, 64_000_000, 1_000_000_000, w);
        assert!(
            (0.06..0.08).contains(&fill),
            "HQ 4K@1G fill 应 ≈0.07，实际 {fill}"
        );
        // 1080p 档 10M @1Gbps → ≈0.0109。
        let fill = r136_gop_burst_fill_ratio(30, k, 10_000_000, 1_000_000_000, w);
        assert!(fill < 0.02, "1080p@1G fill 应 <0.02，实际 {fill}");
        // ③ 降级 100Mbps 链路：1080p 档 10M → ≈0.1089（9× 裕度，无误触发）；
        //    4K 档 32M → ≈0.3484（仍 <1，无误触发）。
        let fill = r136_gop_burst_fill_ratio(30, k, 10_000_000, 100_000_000, w);
        assert!(
            (0.10..0.12).contains(&fill),
            "1080p@100M fill 应 ≈0.109，实际 {fill}"
        );
        let fill = r136_gop_burst_fill_ratio(30, k, 32_000_000, 100_000_000, w);
        assert!(
            (0.33..0.37).contains(&fill),
            "4K@100M fill 应 ≈0.348，实际 {fill}"
        );

        // ④ 阈值移动复核：误触发阈值 = fill=1 的 B/R 解（g≥w 时
        // B/R = 8(k+g−1)/((k+7)g)）——GOP 60→30 仅 0.904→0.919（放宽 <2pp）。
        let thresh = |g: u32| {
            let mut lo = 0.0f64;
            let mut hi = 2.0f64;
            for _ in 0..64 {
                let mid = (lo + hi) / 2.0;
                if r136_gop_burst_fill_ratio(g, k, (mid * 1_000_000_000.0) as u64, 1_000_000_000, w)
                    < 1.0
                {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            (lo + hi) / 2.0
        };
        let t60 = thresh(60);
        let t30 = thresh(30);
        assert!(
            (0.90..0.91).contains(&t60),
            "GOP=60 误触发阈值应 ≈0.904，实际 {t60}"
        );
        assert!(
            (0.91..0.93).contains(&t30),
            "GOP=30 误触发阈值应 ≈0.919，实际 {t30}"
        );
        assert!(
            t30 > t60 && t30 - t60 < 0.02,
            "T4 阈值移动应 <2pp 且为放宽方向：t60={t60} t30={t30}"
        );

        // （正确响应 + 2s 限速 / 30s 迟滞自愈合，方向锚防模型误读）。
        let fill = r136_gop_burst_fill_ratio(30, k, 64_000_000, 60_000_000, w);
        assert!(
            fill > 1.0,
            "64M@60M 链路 fill 应 >1（真实过载，降档 = 设计行为）"
        );

        // ⑥ 退化入参 → INFINITY（不 panic / 不除零；模型 fail 向保守侧）。
        assert_eq!(
            r136_gop_burst_fill_ratio(0, k, 10_000_000, 100_000_000, w),
            f64::INFINITY
        );
        assert_eq!(
            r136_gop_burst_fill_ratio(30, k, 10_000_000, 0, w),
            f64::INFINITY
        );
    }
}
