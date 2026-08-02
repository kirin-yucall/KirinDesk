//! Linux PipeWire screen-cast portal 捕获后端（M12-T001 / R-14-S1）。
//!
//! # 方案
//!
//! X11 与 Wayland 统一走 **xdg-desktop-portal 的 ScreenCast 会话**
//! （`org.freedesktop.portal.ScreenCast`，D-Bus）——桌面门户对两种会话类型
//! 一视同仁，且是 Wayland 下唯一合规的屏幕捕获途径：
//!
//! ```text
//! CreateSession ──► SelectSources(types=Monitor) ──► Start ──► (fd, node_id)
//!      │                                                    │
//!      └──── portal 返回 PipeWire 节点 fd ────────────────────┘
//!                                     ▼
//!      pw_thread_loop + pw_context.connect_fd(fd) + pw_stream(Input/Video)
//!                                     ▼
//!      process 回调 ── RGBA（RGBx/BGRx 统一转换）──► mpsc 通道 ──► wait_for_frame
//! ```
//!
//! # 格式
//!
//! EnumFormat 候选：RGBx / BGRx / BGRA（portal 实现（GNOME/KDE）通常给
//! BGRx）。`param_changed` 解析最终协商格式，process 回调按格式转换：
//! RGBx 直拷、BGRx/BGRA 交换 R/B → 统一 RGBA 输出（与 Windows/macOS 后端
//! 的 `RGBA` 管线契约一致）。
//!
//! # 线程模型
//!
//! `pw_thread_loop` 内部自带线程跑事件循环（`ThreadLoop::start`）；D-Bus
//! 会话与 PW 对象树在创建线程构造、Drop 时销毁。`wait_for_frame` 阻塞收
//! 通道——与 Windows 后端（后台捕获线程 + channel）同模式。
//!
//! # 依赖（target_os = "linux" 专用）
//!
//! - `pipewire =0.8.0`：编译期链接 libpipewire-0.3（Ubuntu 需
//!   `libpipewire-0.3-dev`，见 release/BUILD_UBUNTU.md）；
//! - `zbus =3.15.2`：纯 Rust D-Bus 客户端（无系统依赖）。
//!
//! # 已知限制（v1）
//!
//! - 单流会话（`multiple=false`）→ 只捕获当前活动/主显示器；多显示器
//!   切换（`switch_monitor`）通过重建会话实现；
//! - 显示器枚举无法从 portal 直接获得 → 上报 1 个默认屏（真实分辨率在
//!   首帧协商后更新），与 `factory.rs` 的兜底语义一致；
//! - 无 xdg-desktop-portal 服务 / 无桌面会话（无头）→ `new` 返回错误，
//!   调用方回退（无头场景走 CLI serve，不捕获屏幕）。

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;

use zbus::blocking::Connection;
use zbus::zvariant::{OwnedFd, OwnedObjectPath, OwnedValue, Value};

use pipewire as pw;
use pw::spa;

use crate::capture::{CaptureError, CaptureFrame, DirtyRect, MonitorInfo, ScreenCaptureSource};

// ════════════════════════════════════════════════════════════════
// Portal 常量（org.freedesktop.portal.ScreenCast D-Bus 接口）
// ════════════════════════════════════════════════════════════════

const PORTAL_DEST: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const PORTAL_IFACE: &str = "org.freedesktop.portal.ScreenCast";

/// SelectSources 的 `types` 位：1 = Monitor（整屏捕获；窗口捕获 = 2）。
const SCREENCAST_TYPE_MONITOR: u32 = 1;
/// cursor_mode：1 = 嵌入光标（桌面远控需要光标位置可见）。
const SCREENCAST_CURSOR_EMBEDDED: u32 = 1;

/// 默认显示器兜底尺寸（portal 协商前；协商后更新）。
const DEFAULT_W: u32 = 1920;
const DEFAULT_H: u32 = 1080;

// ════════════════════════════════════════════════════════════════
// 内部帧结构（通道投递，模式同 windows_capture.rs CapturedFrame）
// ════════════════════════════════════════════════════════════════

/// 从捕获线程传递到主线程的一帧（统一 RGBA）。
pub struct PipeWireCapturedFrame {
    /// RGBA 像素数据（stride = width * 4，无行填充）。
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// portal/PW 无脏区信息 → 恒空（与 zed-scap 后端同语义，上游 diff 层兜底）。
    pub dirty_rects: Vec<DirtyRect>,
    /// 捕获时间戳（帧到达时刻）。
    pub timestamp: Instant,
}

// ════════════════════════════════════════════════════════════════
// portal 会话（D-Bus）——一次性建立，返回 PipeWire 节点 fd
// ════════════════════════════════════════════════════════════════

/// 建立 ScreenCast 会话并启动捕获，返回 PipeWire 连接用的节点 fd。
///
/// 流程：CreateSession → SelectSources(Monitor, multiple=false) → Start。
/// 返回的 fd 为 dup 副本，所有权归调用方（`std::os::fd::OwnedFd`）。
fn create_portal_session(conn: &Connection) -> Result<std::os::fd::OwnedFd, CaptureError> {
    // 1. CreateSession(s parent_window, a{sv} options) → (o session_handle,)。
    let reply = conn
        .call_method(
            Some(PORTAL_DEST),
            Some(PORTAL_PATH),
            Some(PORTAL_IFACE),
            "CreateSession",
            &(("", HashMap::<&str, Value>::new()),),
        )
        .map_err(|e| CaptureError::Capture(format!("portal CreateSession: {e}")))?;
    let (session,): (OwnedObjectPath,) = reply
        .body()
        .deserialize()
        .map_err(|e| CaptureError::Capture(format!("portal CreateSession reply: {e}")))?;

    // 2. SelectSources(o session, s parent, a{sv} options)。
    let mut opts = HashMap::<&str, Value>::new();
    opts.insert("types", Value::U32(SCREENCAST_TYPE_MONITOR));
    // multiple=false：单流 = 当前活动显示器（v1；多屏切换经会话重建）。
    opts.insert("multiple", Value::Bool(false));
    // 不持久化会话（persist_mode=0）。
    opts.insert("persist_mode", Value::U32(0));
    let _ = conn
        .call_method(
            Some(PORTAL_DEST),
            Some(PORTAL_PATH),
            Some(PORTAL_IFACE),
            "SelectSources",
            &((&session, "", opts),),
        )
        .map_err(|e| CaptureError::Capture(format!("portal SelectSources: {e}")))?;

    // 3. Start(o session, s parent, a{sv} options) → (a(ha{sv}) streams,)。
    let mut opts = HashMap::<&str, Value>::new();
    opts.insert("cursor_mode", Value::U32(SCREENCAST_CURSOR_EMBEDDED));
    let reply = conn
        .call_method(
            Some(PORTAL_DEST),
            Some(PORTAL_PATH),
            Some(PORTAL_IFACE),
            "Start",
            &((&session, "", opts),),
        )
        .map_err(|e| CaptureError::Capture(format!("portal Start: {e}")))?;
    let (streams,): (Vec<(OwnedFd, HashMap<String, OwnedValue>)>,) = reply
        .body()
        .deserialize()
        .map_err(|e| CaptureError::Capture(format!("portal Start reply: {e}")))?;

    let (fd, props) = streams
        .into_iter()
        .next()
        .ok_or_else(|| CaptureError::Capture("portal Start returned no streams".into()))?;
    // OwnedFd（zvariant 反序列化时 dup 过）→ 原生 fd 移交。
    let raw = fd.into_raw_fd();
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    let node_id = props
        .get("id")
        .and_then(|v| v.downcast_ref::<u32>())
        .copied()
        .unwrap_or(0);
    tracing::info!(
        "Portal ScreenCast started: node_id={node_id}, stream props: {:?}",
        props.keys().collect::<Vec<_>>()
    );
    Ok(owned)
}

// ════════════════════════════════════════════════════════════════
// PipeWire 流用户数据（process/param_changed 回调共享）
// ════════════════════════════════════════════════════════════════

/// 捕获流回调用户数据：协商格式 + 帧通道。
struct CaptureUserData {
    /// 最终协商的视频格式（param_changed 填充，process 消费）。
    format: spa::param::video::VideoInfoRaw,
    /// 帧投递通道（发送端；backend 持接收端）。
    frame_tx: mpsc::Sender<PipeWireCapturedFrame>,
}

// ════════════════════════════════════════════════════════════════
// 后端
// ════════════════════════════════════════════════════════════════

/// Linux PipeWire screen-cast portal 捕获源（M12-T001 / R-14-S1）。
pub struct LinuxPipewireBackend {
    /// 从捕获线程（pw_thread_loop 内部线程）接收帧。
    frame_rx: mpsc::Receiver<PipeWireCapturedFrame>,
    /// 停止信号（保留字段：与 Windows 后端结构对齐；pw 侧由
    /// `thread_loop.stop()` 停止）。
    #[allow(dead_code)]
    stop_flag: Arc<AtomicBool>,
    // ── PipeWire 对象树（thread_loop 启动后必须存活到 Drop，顺序释放）──
    _listener: Option<pw::stream::StreamListener<CaptureUserData>>,
    _stream: Option<pw::stream::Stream>,
    _core: Option<pw::core::Core>,
    _context: Option<pw::context::Context>,
    thread_loop: Option<pw::thread_loop::ThreadLoop>,
    /// portal D-Bus 连接（保持存活：连接断开会使 portal 侧会话失效）。
    _session: Option<Connection>,
    // ── 显示器 / 分辨率状态 ──
    monitors: Vec<MonitorInfo>,
    monitor_index: usize,
    width: u32,
    height: u32,
}

// thread_loop / context 为 Rc 内部（非 Send）；本结构体仅在**单一线程**
// 内创建与销毁（与 WindowsCaptureBackend 的 unsafe impl Send 同款模式：
// 捕获线程单线程使用，ScreenCaptureSource: Send 契约由 unsafe 覆盖）。
unsafe impl Send for LinuxPipewireBackend {}

impl LinuxPipewireBackend {
    /// 创建捕获后端：portal 会话 + PipeWire 流 + 启动捕获线程。
    ///
    /// `monitor_index`：v1 仅支持 0（单流会话捕获活动显示器）；>0 返回
    /// [`CaptureError::InvalidMonitor`]。
    pub fn new(monitor_index: usize) -> Result<Self, CaptureError> {
        if monitor_index != 0 {
            return Err(CaptureError::InvalidMonitor);
        }
        let conn = Connection::session()
            .map_err(|e| CaptureError::Capture(format!("D-Bus session bus: {e}")))?;
        let fd = create_portal_session(&conn)?;
        let mut backend = Self {
            frame_rx: mpsc::channel::<PipeWireCapturedFrame>().1,
            stop_flag: Arc::new(AtomicBool::new(false)),
            _listener: None,
            _stream: None,
            _core: None,
            _context: None,
            thread_loop: None,
            _session: Some(conn),
            monitors: vec![default_monitor()],
            monitor_index: 0,
            width: DEFAULT_W,
            height: DEFAULT_H,
        };
        backend.start_pipewire(fd)?;
        Ok(backend)
    }

    /// 建立 PipeWire 连接与捕获流（fd 来自 portal Start）。
    fn start_pipewire(&mut self, fd: std::os::fd::OwnedFd) -> Result<(), CaptureError> {
        // 1. ThreadLoop（内部自带线程；new 为 unsafe：C 侧 pw_thread_loop_new
        //    假定调用方已 pw_init——pipewire crate 内部已 init）。
        let thread_loop = unsafe { pw::thread_loop::ThreadLoop::new(Some("kirin-capture"), None) }
            .map_err(|e| CaptureError::Capture(format!("pw_thread_loop_new: {e}")))?;
        let context = pw::context::Context::new(&thread_loop)
            .map_err(|e| CaptureError::Capture(format!("pw_context_new: {e}")))?;
        // portal 提供的 fd 直连（非默认 socket）。
        let core = context
            .connect_fd(fd, None)
            .map_err(|e| CaptureError::Capture(format!("pw_core_connect_fd: {e}")))?;

        // 2. 流属性（media.type/category/role 是自动连接的必需三件套）。
        let props = pw::properties::properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        };
        let stream = pw::stream::Stream::new(&core, "kirin-screen-cast", props)
            .map_err(|e| CaptureError::Capture(format!("pw_stream_new: {e}")))?;

        // 3. 事件监听：param_changed 解析最终格式；process 拷帧投递。
        let (frame_tx, frame_rx) = mpsc::channel::<PipeWireCapturedFrame>();
        let user_data = CaptureUserData {
            format: spa::param::video::VideoInfoRaw::new(),
            frame_tx,
        };
        let listener = stream
            .add_local_listener_with_user_data(user_data)
            .param_changed(|_, user_data, id, param| {
                on_param_changed(user_data, id, param);
            })
            .process(|stream, user_data| {
                on_process(stream, user_data);
            })
            .register()
            .map_err(|e| CaptureError::Capture(format!("pw_stream listener: {e}")))?;

        // 4. 连接（EnumFormat 候选：RGBx/BGRx/BGRA）。
        let mut params = build_enum_format_pods()?;
        stream
            .connect(
                spa::utils::Direction::Input,
                None,
                pw::stream::StreamFlags::AUTOCONNECT
                    | pw::stream::StreamFlags::MAP_BUFFERS
                    | pw::stream::StreamFlags::RT_PROCESS,
                &mut params,
            )
            .map_err(|e| CaptureError::Capture(format!("pw_stream_connect: {e}")))?;

        // 5. 启动内部线程跑事件循环。
        thread_loop.start();
        tracing::info!("LinuxPipewireBackend: capture stream connected via portal");

        self._listener = Some(listener);
        self._stream = Some(stream);
        self._core = Some(core);
        self._context = Some(context);
        self.thread_loop = Some(thread_loop);
        self.frame_rx = frame_rx;
        Ok(())
    }

    /// 停止捕获并释放全部 PipeWire / portal 资源（幂等；Drop 也调用）。
    fn stop_capture(&mut self) {
        // 先停内部线程，再逆序释放对象树（与构造顺序相反）。
        if let Some(tl) = self.thread_loop.take() {
            tl.stop();
        }
        self._listener = None;
        self._stream = None;
        self._core = None;
        self._context = None;
        self._session = None;
        // Drain 残留帧（防 wait_for_frame 读到旧会话数据）。
        while self.frame_rx.try_recv().is_ok() {}
    }

    /// 重建整个会话（switch_monitor / recreate 用）：停止旧流 → 新 portal
    /// 会话 → 新 PW 流。
    fn restart_session(&mut self, monitor_index: usize) -> Result<(), CaptureError> {
        self.stop_capture();
        let conn = Connection::session()
            .map_err(|e| CaptureError::Capture(format!("D-Bus session bus: {e}")))?;
        let fd = create_portal_session(&conn)?;
        self.monitor_index = monitor_index;
        self.start_pipewire(fd)?;
        self._session = Some(conn);
        Ok(())
    }
}

impl ScreenCaptureSource for LinuxPipewireBackend {
    fn wait_for_frame(&mut self) -> Result<CaptureFrame, CaptureError> {
        let frame = self
            .frame_rx
            .recv()
            .map_err(|_| CaptureError::Capture("pipewire capture channel closed".into()))?;
        // 首帧后更新实际分辨率（协商格式为准）。
        self.width = frame.width;
        self.height = frame.height;
        if let Some(m) = self.monitors.first_mut() {
            m.width = frame.width;
            m.height = frame.height;
        }
        Ok(CaptureFrame::PipeWire(PipeWireFrame {
            data: frame.data,
            width: frame.width,
            height: frame.height,
            dirty_rects: frame.dirty_rects,
            timestamp: frame.timestamp,
        }))
    }

    /// 静默屏幕（无帧）时按超时醒来（M8-T018 MON-NF-002，同 Windows 后端）。
    fn wait_for_frame_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<CaptureFrame, CaptureError> {
        let frame = self.frame_rx.recv_timeout(timeout).map_err(|e| match e {
            mpsc::RecvTimeoutError::Timeout => CaptureError::Timeout,
            _ => CaptureError::Capture("pipewire capture channel closed".into()),
        })?;
        self.width = frame.width;
        self.height = frame.height;
        if let Some(m) = self.monitors.first_mut() {
            m.width = frame.width;
            m.height = frame.height;
        }
        Ok(CaptureFrame::PipeWire(PipeWireFrame {
            data: frame.data,
            width: frame.width,
            height: frame.height,
            dirty_rects: frame.dirty_rects,
            timestamp: frame.timestamp,
        }))
    }

    fn resolution(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn monitor_info(&self) -> &[MonitorInfo] {
        &self.monitors
    }

    fn switch_monitor(&mut self, index: usize) -> Result<(), CaptureError> {
        if index >= self.monitors.len() {
            return Err(CaptureError::InvalidMonitor);
        }
        if index == self.monitor_index {
            return Ok(());
        }
        // v1 单流会话：切换 = 重建会话（portal 重新 SelectSources）。
        self.restart_session(index)
    }

    fn recreate(&mut self) -> Result<(), CaptureError> {
        self.restart_session(self.monitor_index)
    }
}

impl Drop for LinuxPipewireBackend {
    fn drop(&mut self) {
        self.stop_capture();
    }
}

// ════════════════════════════════════════════════════════════════
// 回调实现
// ════════════════════════════════════════════════════════════════

/// `param_changed`：协商 Format 参数时解析视频格式（尺寸/像素格式）。
fn on_param_changed(user_data: &mut CaptureUserData, id: u32, param: Option<&spa::pod::Pod>) {
    // None = 清空格式；非 Format 参数忽略。
    let Some(param) = param else {
        return;
    };
    if id != spa::param::ParamType::Format.as_raw() {
        return;
    }
    // 仅接受 Video/Raw（RGBx/BGRx/BGRA 家族）。
    let Ok((media_type, media_subtype)) = spa::param::format_utils::parse_format(param) else {
        return;
    };
    if media_type != spa::param::format::MediaType::Video
        || media_subtype != spa::param::format::MediaSubtype::Raw
    {
        tracing::warn!("Linux capture: unexpected media {media_type:?}/{media_subtype:?}");
        return;
    }
    if user_data.format.parse(param).is_err() {
        tracing::warn!("Linux capture: failed to parse VideoInfoRaw");
        return;
    }
    let rect = user_data.format.size();
    let rate = user_data.format.framerate();
    // VideoFormat 无 Debug derive —— 打印 raw 值（RGBx=27/BGRx=28/BGRA=29 附近，
    // 见 libspa SPA_VIDEO_FORMAT_*；判别走 frame_to_rgba 的常量比较）。
    tracing::info!(
        "Linux capture: negotiated format={} {}x{} @ {}/{} fps",
        user_data.format.format().as_raw(),
        rect.width,
        rect.height,
        rate.num,
        rate.den
    );
}

/// `process`（内部线程）：取缓冲 → 转 RGBA → 投递 → 归还（Buffer Drop 自动
/// queue）。
fn on_process(stream: &pw::stream::StreamRef, user_data: &mut CaptureUserData) {
    let Some(mut buffer) = stream.dequeue_buffer() else {
        return;
    };
    // buffer drop 时自动 pw_stream_queue_buffer 归还。
    let datas = buffer.datas_mut();
    if datas.is_empty() {
        return;
    }
    let data = &datas[0];
    let Some(bytes) = data.data() else {
        return;
    };
    let chunk_size = data.chunk().size() as usize;
    let stride = data.stride().max(0) as usize;

    let rect = user_data.format.size();
    let w = rect.width;
    let h = rect.height;
    let fmt = user_data.format.format();
    if w == 0 || h == 0 || stride == 0 || chunk_size == 0 {
        return; // 未协商完成 / 空帧。
    }
    let src = &bytes[..chunk_size.min(bytes.len())];
    let rgba = frame_to_rgba(src, stride, w, h, fmt);
    // 投递失败（backend 已销毁）→ 忽略。
    let _ = user_data.frame_tx.send(PipeWireCapturedFrame {
        data: rgba,
        width: w,
        height: h,
        dirty_rects: Vec::new(),
        timestamp: Instant::now(),
    });
}

// ════════════════════════════════════════════════════════════════
// 格式转换与 POD 构造
// ════════════════════════════════════════════════════════════════

/// 每像素 4 字节的 portal 输出 → 统一 RGBA。
///
/// - RGBx：直拷（第 4 字节占位忽略）；
/// - BGRx / BGRA：交换 R/B（保持 RGB 顺序）。
/// 其他格式（YUY2 等）返回空 → 该帧被丢弃（协商阶段已限定 Raw 格式族，
/// 防御路径）。
fn frame_to_rgba(
    src: &[u8],
    stride: usize,
    w: u32,
    h: u32,
    fmt: spa::param::video::VideoFormat,
) -> Vec<u8> {
    let raw = fmt.as_raw();
    let swap = raw == spa::param::video::VideoFormat::BGRx.as_raw()
        || raw == spa::param::video::VideoFormat::BGRA.as_raw();
    let row_bytes = (w as usize) * 4;
    let mut out = Vec::with_capacity(row_bytes * h as usize);
    for y in 0..h as usize {
        let start = y * stride;
        if start >= src.len() {
            break; // 防御：缓冲不足。
        }
        let row = &src[start..(start + row_bytes).min(src.len())];
        if swap {
            for px in row.chunks_exact(4) {
                if px.len() == 4 {
                    out.extend_from_slice(&[px[2], px[1], px[0], 0xFF]);
                }
            }
        } else {
            for px in row.chunks_exact(4) {
                if px.len() == 4 {
                    out.extend_from_slice(&[px[0], px[1], px[2], 0xFF]);
                }
            }
        }
    }
    out
}

/// 构造 EnumFormat 候选 POD 列表（RGBx → BGRx → BGRA 优先级）。
///
/// 每个候选一个 EnumFormat 对象（SpaTypes::ObjectParamFormat）；PipeWire
/// 图会选第一个它支持的格式。尺寸/帧率留空 → 接受图的实际输出
/// （param_changed 时读回）。
fn build_enum_format_pods() -> Result<Vec<spa::pod::Pod>, CaptureError> {
    use pw::spa::param::format::FormatProperties;
    use pw::spa::param::format::{MediaSubtype, MediaType};
    use pw::spa::param::video::VideoFormat;
    use pw::spa::pod::{object, property};

    let mut params = Vec::new();
    for fmt in [VideoFormat::RGBx, VideoFormat::BGRx, VideoFormat::BGRA] {
        let obj = object!(
            pw::spa::utils::SpaTypes::ObjectParamFormat,
            pw::spa::param::ParamType::EnumFormat,
            property!(FormatProperties::MediaType, Id, MediaType::Video),
            property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
            property!(FormatProperties::VideoFormat, Id, fmt),
        );
        let values: Vec<u8> = spa::pod::serialize::PodSerializer::serialize(
            std::io::Cursor::new(Vec::new()),
            &spa::pod::Value::Object(obj),
        )
        .map_err(|e| CaptureError::Capture(format!("serialize EnumFormat pod: {e}")))?
        .0
        .into_inner();
        params.push(
            spa::pod::Pod::from_bytes(&values)
                .map_err(|e| CaptureError::Capture(format!("Pod::from_bytes: {e}")))?,
        );
    }
    Ok(params)
}

// ════════════════════════════════════════════════════════════════
// 显示器枚举（portal 无法直接枚举 → 默认单屏，factory 兜底语义）
// ════════════════════════════════════════════════════════════════

/// 默认单屏（真实分辨率在首帧协商后由后端更新）。
fn default_monitor() -> MonitorInfo {
    MonitorInfo {
        id: 0,
        name: "Screen (PipeWire portal)".into(),
        width: DEFAULT_W,
        height: DEFAULT_H,
        is_primary: true,
        is_virtual: false,
    }
}

/// 枚举显示器：portal 无枚举接口 → 上报 1 个默认屏（客户端下拉恒可用，
/// 与 `factory.rs` 的兜底一致）。
pub fn enumerate_monitors() -> Result<Vec<MonitorInfo>, CaptureError> {
    Ok(vec![default_monitor()])
}

// ════════════════════════════════════════════════════════════════
// Tests（环境无关：格式转换 / 候选构造；portal 实机在集成/手工验证）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// RGBx → RGBA 直拷（第 4 字节占位忽略）。
    #[test]
    fn test_frame_to_rgba_rgbx() {
        let w = 2u32;
        let h = 1u32;
        // 两像素：R=1,G=2,B=3,x=0xFF；R=10,G=20,B=30,x=0x00。
        let src = [1u8, 2, 3, 0xFF, 10, 20, 30, 0x00];
        let out = frame_to_rgba(&src, w as usize * 4, w, h, VideoFormat::RGBx);
        assert_eq!(out, vec![1, 2, 3, 0xFF, 10, 20, 30, 0xFF]);
    }

    /// BGRx → RGBA 交换 R/B。
    #[test]
    fn test_frame_to_rgba_bgrx_swap() {
        let w = 1u32;
        let h = 1u32;
        let src = [30u8, 20, 10, 0x00];
        let out = frame_to_rgba(&src, w as usize * 4, w, h, VideoFormat::BGRx);
        assert_eq!(out, vec![10, 20, 30, 0xFF]);
    }

    /// BGRA → RGBA 交换 R/B（A 忽略）。
    #[test]
    fn test_frame_to_rgba_bgra_swap() {
        let w = 1u32;
        let h = 1u32;
        let src = [30u8, 20, 10, 0x80];
        let out = frame_to_rgba(&src, w as usize * 4, w, h, VideoFormat::BGRA);
        assert_eq!(out, vec![10, 20, 30, 0xFF]);
    }

    /// stride > w*4（行填充）→ 逐行拷贝不越界。
    #[test]
    fn test_frame_to_rgba_stride_padding() {
        let w = 2u32;
        let h = 2u32;
        // 每行 8 字节数据 + 4 字节填充。
        let mut src = Vec::new();
        for y in 0..2u8 {
            for x in 0..2u8 {
                src.extend_from_slice(&[x * 10 + y, 100, 200, 0xEE]);
            }
            src.extend_from_slice(&[0xAB; 4]); // 填充。
        }
        let out = frame_to_rgba(&src, 12, w, h, VideoFormat::RGBx);
        assert_eq!(out.len(), (w * h * 4) as usize);
        // 第 0 行像素 0 为 (0,100,200)。
        assert_eq!(&out[0..4], &[0, 100, 200, 0xFF]);
    }

    /// 缓冲不足（chunk 小于整帧）→ 截断不 panic。
    #[test]
    fn test_frame_to_rgba_truncated() {
        let w = 8u32;
        let h = 8u32;
        let src = vec![7u8; 16]; // 远小于整帧。
        let out = frame_to_rgba(&src, w as usize * 4, w, h, VideoFormat::RGBx);
        assert!(!out.is_empty());
        assert!(out.len() <= (w * h * 4) as usize);
    }

    /// 候选 POD：3 个 EnumFormat（RGBx/BGRx/BGRA），可序列化反解析。
    #[test]
    fn test_build_enum_format_pods() {
        let params = build_enum_format_pods().expect("pods");
        assert_eq!(params.len(), 3, "RGBx/BGRx/BGRA 三个候选");
        // 每个 POD 可被 format_utils 解析为 Video/Raw。
        for p in &params {
            let (mt, ms) =
                spa::param::format_utils::parse_format(p).expect("parse_format on our own pod");
            assert_eq!(mt, spa::param::format::MediaType::Video);
            assert_eq!(ms, spa::param::format::MediaSubtype::Raw);
        }
    }

    /// 默认显示器：主屏、无虚拟标记、非空尺寸。
    #[test]
    fn test_default_monitor_shape() {
        let m = default_monitor();
        assert_eq!(m.id, 0);
        assert!(m.is_primary);
        assert!(!m.is_virtual);
        assert!(m.width > 0 && m.height > 0);
    }
}
