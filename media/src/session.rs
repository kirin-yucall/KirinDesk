//! 端到端 QUIC 媒体会话（M8-T009 集成层）。
//!
//! 把已有组件串成完整闭环：
//!
//! ```text
//! 服务端: capture → WindowPipeline → QuicMediaTransport(DATAGRAM) → 客户端
//!         ↑                                    │ FeedbackReport
//!         └── AdaptiveEngine ←─ 控制流 ─────────┘ (可靠流)
//!
//! 客户端: QuicMediaTransport(DATAGRAM 重组) → VideoDecoderPipeline → on_frame 回调
//!         │ FeedbackReport (ReportGenerator + LossDetector, 每 100ms)
//!         └──→ 可靠流 → 服务端 AdaptiveEngine
//! ```
//!
//! - 媒体走 QUIC DATAGRAM（14B 头 + AEAD 加密，分片重组，允许丢包）
//! - 控制走 QUIC 可靠流（VideoFormat / FeedbackReport / Disconnect）
//! - 自适应：编码超时保护 + 网络状态机 + 恢复策略（T009 §6.6）全部内建
//!
//! UI 层只需：
//! - 服务端：`QuicEndpoint::bind` + `accept_quic_transport` + `run_server_session`
//! - 客户端：`connect_quic_transport` + `run_client_session`

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::adaptive::{AdaptiveEngine, FeedbackReport, ReportGenerator};
use crate::capture::{CaptureError, CaptureFrame, ScreenCaptureSource};
use crate::decoder::factory::create_video_decoder;
use crate::decoder::{frame_id_to_pts, DecoderPacket};
use crate::encoder::types::Codec;
use crate::encoder::VideoEncoderPipeline;
use crate::proto::{EncodeConfig, EncodedWindow, RawFrame, WindowConfig};
use crate::transport::{
    control, ControlMessage, MediaTransport, QuicMediaTransport, TransportError,
};
use crate::window_pipeline::WindowPipeline;

// ════════════════════════════════════════════════════════════════
// 会话配置与统计
// ════════════════════════════════════════════════════════════════

/// PTS 线性近似用的目标帧率（P2A §T1.1 方案 A；SessionConfig 暂无 fps 字段，
/// 客户端单帧率场景取 60 足够；P2G 基准若 lip-sync 不达标再升级方案 B）。
const TARGET_FPS: u32 = 60;

/// 媒体会话配置。
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// 窗口配置（70ms / 最大帧数 / 空闲超时）
    pub window: WindowConfig,
    /// 初始编码配置
    pub encode: EncodeConfig,
    /// 客户端反馈上报周期（毫秒，默认 100）
    pub feedback_interval_ms: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            window: WindowConfig::default(),
            encode: EncodeConfig::default(),
            feedback_interval_ms: 100,
        }
    }
}

/// 服务端会话统计（自适应闭环状态，UI 诊断用）。
#[derive(Debug, Clone, Default)]
pub struct ServerSessionStats {
    /// 已编码窗口数
    pub windows_encoded: u64,
    /// 静默窗口数（无变化）
    pub silent_windows: u64,
    /// 编码总帧数
    pub frames_encoded: u64,
    /// 上次编码耗时（毫秒）
    pub last_encode_ms: f64,
    /// 当前 QP
    pub active_qp: u32,
    /// 当前帧保留比例
    pub active_frame_ratio: f64,
    /// 最近 RTT（毫秒）
    pub last_rtt_ms: u64,
    /// 客户端反馈丢包率（0.0~1.0）
    pub last_loss_rate: f64,
    /// 客户端反馈接收带宽（bps）
    pub last_bandwidth_bps: u64,
    /// 当前网络状态
    pub network_state: String,
    /// 恢复阶段
    pub recovery_phase: String,
    /// 收到的反馈报告数
    pub feedback_reports: u64,
}

/// 客户端会话统计。
#[derive(Debug, Clone, Default)]
pub struct ClientSessionStats {
    /// 接收并解码的帧数
    pub frames_decoded: u64,
    /// 丢弃帧数（解码失败 / 窗口不完整）
    pub frames_dropped: u64,
    /// 当前丢包率（0.0~1.0）
    pub loss_rate: f64,
    /// 最近 RTT（毫秒）
    pub rtt_ms: u64,
    /// 接收带宽（bps）
    pub bandwidth_bps: u64,
    /// 平均解码耗时（毫秒）
    pub avg_decode_ms: f64,
    /// 最近解码的分辨率
    pub video_w: u32,
    pub video_h: u32,
    /// 发送的反馈报告数
    pub feedback_sent: u64,
}

// ════════════════════════════════════════════════════════════════
// 服务端会话
// ════════════════════════════════════════════════════════════════

/// 捕获+编码任务（阻塞线程）→ 异步发送循环 的输出。
enum ServerOut {
    /// 非空窗口（含编码耗时，供自适应引擎使用）
    Window(EncodedWindow),
    /// 静默窗口（无变化，不发送媒体）
    Silent {
        window_id: u64,
        encode_duration_ms: f64,
    },
    /// M8-T018：显示器切换结果（Ok=新分辨率，Err=失败原因 → Nack）。
    MonitorSwitched(Result<(u32, u32), String>),
    /// 致命错误（捕获不可用等 → 会话终止）
    Fatal(String),
}

/// M8-T018：控制任务 → 主循环 的显示器控制响应（经控制流发出）。
enum DisplayResp {
    /// 显示器列表（`DisplayListReq` 的响应负载）。
    List(Vec<crate::proto::DisplayInfo>),
    /// 切换拒绝原因（越界索引 → `DisplaySelectNack`）。
    Nack(String),
}

/// 运行服务端 QUIC 媒体会话：捕获 → 窗口编码 → DATAGRAM 发送 + 反馈自适应闭环。
///
/// 内部并发结构：
/// - 捕获+编码 task（`spawn_blocking`）：屏幕捕获与 FFmpeg 编码均为**阻塞调用**，
///   必须离开 tokio worker 线程——否则 worker 被占死后 quinn 连接驱动任务被
///   饿死，服务器停止 ACK/发送，整个 QUIC 连接静默冻结（端到端回归
///   `quic_loopback` 曾以「客户端解码 0 帧」暴露此问题）。编码窗口经 mpsc
///   通道送达异步主循环。
/// - 主循环（异步）：接收编码窗口 → `send_window`（DATAGRAM）+ 自适应统计。
/// - 控制 task：`recv_control`（FeedbackReport）→ `AdaptiveEngine::on_feedback`
///   → 更新共享编码配置（恢复策略 / 状态机 / 编码超时保护均在此闭环内生效）。
///
/// `stop` 置 true 后会话在下个窗口边界退出。
pub async fn run_server_session(
    mut transport: QuicMediaTransport,
    capture: Box<dyn ScreenCaptureSource>,
    encoder: VideoEncoderPipeline,
    config: SessionConfig,
    stop: Arc<AtomicBool>,
) -> Result<ServerSessionStats, String> {
    let (w, h) = capture.resolution();
    info!("server session: capture {}x{}", w, h);

    // 推送分辨率（客户端解码 DATAGRAM 重组帧需要；wire 帧头不携带宽高）
    transport
        .send_control(&ControlMessage::VideoFormat {
            width: w,
            height: h,
        })
        .await
        .map_err(|e| format!("send VideoFormat: {e}"))?;

    let engine = Arc::new(Mutex::new(AdaptiveEngine::new(w, h)));
    let shared_config = Arc::new(Mutex::new(config.encode.clone()));
    let stats = Arc::new(Mutex::new(ServerSessionStats::default()));

    // ── M8-T018: 显示器控制通道 ─────────────────────────────────
    // 控制任务 → 主循环：显示器列表 / 切换拒绝（主循环持有 transport 发送）。
    let (display_resp_tx, mut display_resp_rx) =
        tokio::sync::mpsc::unbounded_channel::<DisplayResp>();
    // 控制任务 → 捕获任务：待切换的显示器索引（热切换，无需重连）。
    let (switch_tx, mut switch_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();

    // ── 控制接收 task（客户端反馈 → 自适应引擎）──────────────────
    if let Some(recv_stream) = transport.take_control_receiver() {
        let cipher = transport.cipher_handle();
        let engine = Arc::clone(&engine);
        let shared_config = Arc::clone(&shared_config);
        let stats = Arc::clone(&stats);
        let stop = Arc::clone(&stop);
        let display_resp_tx = display_resp_tx.clone();
        let switch_tx = switch_tx.clone();
        tokio::spawn(async move {
            let mut stream = recv_stream;
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match control::recv_control_msg(&mut stream, &cipher).await {
                    Ok(ControlMessage::DisplayListReq) => {
                        // M8-T018（SRV-MON-002）：枚举显示器 → 响应。
                        // 每次请求返回最新列表（热插拔后客户端可手动刷新，MON-NF-001）。
                        let displays = crate::capture::factory::enumerate_monitors();
                        info!("[Session] DisplayListReq → {} display(s)", displays.len());
                        let _ = display_resp_tx.send(DisplayResp::List(displays));
                    }
                    Ok(ControlMessage::DisplaySelect { index }) => {
                        // M8-T018（SRV-MON-003）：越界 → Nack（保持当前屏）；
                        // 合法 → 捕获线程热切换（重建捕获源 + 下一窗口 IDR）。
                        let displays = crate::capture::factory::enumerate_monitors();
                        if index as usize >= displays.len() {
                            warn!(
                                "[Session] DisplaySelect({index}) out of range ({} available) — Nack",
                                displays.len()
                            );
                            let _ = display_resp_tx.send(DisplayResp::Nack(format!(
                                "invalid monitor index {index} ({} display(s) available)",
                                displays.len()
                            )));
                        } else {
                            info!("[Session] DisplaySelect({index}) → switching capture");
                            let _ = switch_tx.send(index);
                        }
                    }
                    Ok(ControlMessage::FeedbackReport {
                        loss_rate,
                        rtt_ms,
                        received_bitrate,
                        frame_id,
                        missing_frames,
                    }) => {
                        let report = FeedbackReport {
                            loss_rate,
                            rtt_ms: rtt_ms as f64,
                            jitter_us: 0.0,
                            bandwidth_bps: received_bitrate,
                            last_frame_id: frame_id,
                            missing_frames,
                            urgent_reduce: loss_rate > 0.1,
                            decode_stats: None,
                        };
                        // ⚠️ 锁顺序与主循环保持一致：engine → stats。
                        // 若此处先锁 stats 再锁 engine，首次反馈到达时与主循环
                        // （engine → stats）构成 ABBA 死锁，整个 QUIC 会话冻结。
                        let new_config = {
                            let mut eng = engine.lock().unwrap();
                            eng.on_feedback(&report)
                        };
                        if let Some(cfg) = new_config {
                            let mut shared = shared_config.lock().unwrap();
                            shared.qp = cfg.qp;
                            shared.frame_ratio = cfg.frame_ratio;
                            shared.preset = cfg.preset.clone();
                            info!(
                                "[Session] adaptive config: QP={}, ratio={:.3}, preset={}",
                                cfg.qp, cfg.frame_ratio, cfg.preset
                            );
                        }
                        {
                            let eng = engine.lock().unwrap();
                            let mut st = stats.lock().unwrap();
                            st.feedback_reports += 1;
                            st.last_loss_rate = loss_rate;
                            st.last_bandwidth_bps = received_bitrate;
                            st.network_state = format!("{:?}", eng.network_state());
                            st.recovery_phase = format!("{:?}", eng.recovery_phase());
                        }
                    }
                    Ok(ControlMessage::Disconnect { reason }) => {
                        info!("[Session] client disconnect: {}", reason);
                        break;
                    }
                    Ok(_) => { /* 忽略其它控制消息 */ }
                    Err(e) => {
                        debug!("[Session] control stream closed: {e}");
                        break;
                    }
                }
            }
        });
    } else {
        warn!("server session: no control receiver stream");
    }

    // ── 捕获 + 编码 task（阻塞线程）──────────────────────────────
    //
    // capture.wait_for_frame() 与 FFmpeg 编码是阻塞调用。若在异步主循环里
    // 直接调用，会长时间占用 tokio worker 线程（捕获节拍 33ms + 编码耗时
    // 几乎占满一个 worker 且不 yield）→ quinn 连接驱动任务被饿死，连接
    // 静默冻结。因此整体搬到 blocking 线程池，仅把编码结果经通道送回。
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<ServerOut>(4);
    let pipeline_stop = Arc::clone(&stop);
    let pipeline_config = Arc::clone(&shared_config);
    tokio::task::spawn_blocking(move || {
        let mut pipeline = WindowPipeline::new(config.window.clone(), encoder);
        pipeline.update_encode_config(config.encode.clone());
        let mut capture = capture;
        let mut windows_encoded: u64 = 0;
        // M8-T018（SRV-CAP-MON-003）：显示器切换成功后，下一窗口强制 IDR。
        let mut force_idr_next = false;

        loop {
            if pipeline_stop.load(Ordering::Relaxed) {
                info!("server session: stopping by user request");
                break;
            }

            // M8-T018（SRV-CAP-MON-002）：显示器切换命令 —— 会话内热切换
            // （重建捕获源，无需重连）。阻塞捕获源重建放本线程执行。
            if let Ok(idx) = switch_rx.try_recv() {
                match capture.switch_monitor(idx as usize) {
                    Ok(()) => {
                        let (sw, sh) = capture.resolution();
                        info!("[Session] capture switched to monitor {idx} ({}x{})", sw, sh);
                        force_idr_next = true; // 下一窗口 IDR，无需客户端等花屏
                        // 主循环：推送新 VideoFormat（分辨率变更 → 客户端重建解码上下文）
                        let _ = out_tx.blocking_send(ServerOut::MonitorSwitched(Ok((sw, sh))));
                    }
                    Err(e) => {
                        warn!("[Session] switch monitor {idx} failed: {e} — keeping current");
                        let _ = out_tx.blocking_send(ServerOut::MonitorSwitched(Err(format!(
                            "switch monitor {idx} failed: {e}"
                        ))));
                    }
                }
            }

            // 应用最新自适应配置（异步主循环可能已更新）
            {
                let shared = pipeline_config.lock().unwrap();
                let cur = pipeline.encode_config().clone();
                if shared.qp != cur.qp
                    || (shared.frame_ratio - cur.frame_ratio).abs() > 1e-9
                    || shared.preset != cur.preset
                {
                    pipeline.update_encode_config(shared.clone());
                    debug!(
                        "[Session] apply config: QP={}, ratio={:.3}",
                        shared.qp, shared.frame_ratio
                    );
                }
            }

            // M8-T018（MON-NF-002）：带超时等待——静默屏幕（无帧到达）时
            // 定期醒来轮询切换命令，切换延迟与屏幕活动度解耦（目标 <500ms）。
            let frame = match capture.wait_for_frame_timeout(Duration::from_millis(100)) {
                Ok(f) => f,
                Err(CaptureError::Timeout) => continue,
                Err(e) => {
                    // 捕获失败：AccessLost 重建，其它重试（与 UI 旧循环语义一致）
                    match &e {
                        CaptureError::AccessLost => {
                            warn!("[Session] capture access lost — recreating");
                            if capture.recreate().is_err() {
                                let _ = out_tx.blocking_send(ServerOut::Fatal(format!(
                                    "capture recreate failed"
                                )));
                                break;
                            }
                            continue;
                        }
                        CaptureError::NoMonitor | CaptureError::InvalidMonitor => {
                            let _ = out_tx.blocking_send(ServerOut::Fatal(format!(
                                "capture unavailable: {e}"
                            )));
                            break;
                        }
                        _ => {
                            warn!("[Session] capture error: {e} — retrying");
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                    }
                }
            };

            let raw = RawFrame {
                data: Arc::new(frame.data().to_vec()),
                width: frame.width(),
                height: frame.height(),
                timestamp: std::time::SystemTime::now(),
                dirty_rects: frame.dirty_rects().to_vec(),
                // 首帧或显示器切换后 → 强制 IDR（切换后下一帧可解码，无花屏等待）。
                force_key: windows_encoded == 0 || force_idr_next,
            };
            force_idr_next = false;

            match pipeline.push_frame(raw) {
                Ok(Some(window)) => {
                    windows_encoded = window.window_id;
                    let is_empty = window.is_empty();
                    let msg = if is_empty {
                        ServerOut::Silent {
                            window_id: window.window_id,
                            encode_duration_ms: window.encode_duration_ms,
                        }
                    } else {
                        ServerOut::Window(window)
                    };
                    if out_tx.blocking_send(msg).is_err() {
                        // 异步主循环已退出（连接关闭）→ 结束捕获
                        break;
                    }
                }
                Ok(None) => { /* 窗口仍在收集帧 */ }
                Err(e) => {
                    warn!("[Session] window pipeline error: {e} — retrying");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    });

    // ── 异步主循环：窗口接收 → 自适应统计 → DATAGRAM 发送 ────────
    //    M8-T018：与显示器控制响应（列表/切换拒绝）并行——控制任务发来的
    //    响应统一经本循环经 transport.send_control 发回客户端。
    let mut windows_encoded: u64 = 0;
    let mut frames_encoded: u64 = 0;
    let mut silent_windows: u64 = 0;
    let mut last_encode_ms: f64 = 0.0;

    loop {
        tokio::select! {
            out = out_rx.recv() => {
                let Some(out) = out else { break };
                if stop.load(Ordering::Relaxed) {
                    info!("server session: stopping by user request");
                    break;
                }

                let mut new_config: Option<EncodeConfig> = None;
                match out {
                    ServerOut::Window(window) => {
                windows_encoded = window.window_id;
                frames_encoded += window.frame_count as u64;
                last_encode_ms = window.encode_duration_ms;
                {
                    // 编码耗时 → 超时保护（锁内计算，不跨 await）
                    let mut engine_guard = engine.lock().unwrap();
                    engine_guard.on_active_window();
                    new_config = engine_guard.on_encode_complete(window.encode_duration_ms);
                }

                debug!("[Session] send_window enter id={}", window.window_id);
                transport
                    .send_window(&window)
                    .await
                    .map_err(|e| format!("send_window {}: {e}", window.window_id))?;
                debug!("[Session] send_window exit id={}", window.window_id);
            }
            ServerOut::Silent {
                window_id,
                encode_duration_ms,
            } => {
                windows_encoded = window_id;
                silent_windows += 1;
                last_encode_ms = encode_duration_ms;
                {
                    let mut engine_guard = engine.lock().unwrap();
                    engine_guard.on_silent_window();
                    new_config = engine_guard.on_encode_complete(encode_duration_ms);
                }
            }
            ServerOut::Fatal(reason) => {
                warn!("[Session] capture/pipeline fatal: {reason}");
                break;
            }
            ServerOut::MonitorSwitched(result) => {
                // M8-T018（SRV-CAP-MON-003）：切换成功 → 重推 VideoFormat
                // （分辨率变更 → 客户端解码上下文重建 + 坐标基数跟随）；
                // 失败 → DisplaySelectNack（客户端提示并保持当前屏）。
                match result {
                    Ok((sw, sh)) => {
                        info!("[Session] monitor switched → VideoFormat {}x{}", sw, sh);
                        if let Err(e) = transport
                            .send_control(&ControlMessage::VideoFormat {
                                width: sw,
                                height: sh,
                            })
                            .await
                        {
                            warn!("[Session] send VideoFormat after switch: {e}");
                        }
                    }
                    Err(reason) => {
                        warn!("[Session] monitor switch rejected: {reason}");
                        if let Err(e) = transport
                            .send_control(&ControlMessage::DisplaySelectNack { reason })
                            .await
                        {
                            warn!("[Session] send DisplaySelectNack: {e}");
                        }
                    }
                }
            }
        }

        // QUIC 统计（RTT / cwnd）→ 状态机 + 恢复条件 C
        let rtt = transport.rtt();
        let cwnd = transport.conn().congestion_window();
        {
            let mut eng = engine.lock().unwrap();
            if let Some(cfg) = eng.on_quic_stats(rtt as f64, cwnd) {
                new_config = Some(cfg);
            }
            {
                let mut st = stats.lock().unwrap();
                st.network_state = format!("{:?}", eng.network_state());
                st.recovery_phase = format!("{:?}", eng.recovery_phase());
                st.last_rtt_ms = rtt;
            }
        }
        // 诊断：每 10 个窗口打印一次 QUIC 收发统计
        if windows_encoded % 10 == 0 {
            let (tx_dg, tx_b, rx_dg, rx_b) = transport.conn().udp_stats();
            debug!(
                "[Session] diag window={} udp tx={} dg/{}B rx={} dg/{}B cwnd={}",
                windows_encoded, tx_dg, tx_b, rx_dg, rx_b, cwnd
            );
        }
        if let Some(cfg) = new_config {
            let mut shared = shared_config.lock().unwrap();
            shared.qp = cfg.qp;
            shared.frame_ratio = cfg.frame_ratio;
            shared.preset = cfg.preset.clone();
        }
            }
            resp = display_resp_rx.recv() => {
                // M8-T018：控制任务 → 主循环 的显示器响应（列表 / 切换拒绝）。
                let Some(resp) = resp else { continue };
                if stop.load(Ordering::Relaxed) {
                    info!("server session: stopping by user request");
                    break;
                }
                let msg = match resp {
                    DisplayResp::List(displays) => {
                        ControlMessage::DisplayListResp { displays }
                    }
                    DisplayResp::Nack(reason) => {
                        ControlMessage::DisplaySelectNack { reason }
                    }
                };
                if let Err(e) = transport.send_control(&msg).await {
                    warn!("[Session] send display control response: {e}");
                }
            }
        }
    }

    transport.conn().close("server session end");

    let udp = transport.conn().udp_stats();
    info!(
        "server session ended: udp tx={} dg/{} B, rx={} dg/{} B",
        udp.0, udp.1, udp.2, udp.3
    );

    // 合并统计
    let mut st = stats.lock().unwrap();
    st.windows_encoded = windows_encoded;
    st.silent_windows = silent_windows;
    st.frames_encoded = frames_encoded;
    st.last_encode_ms = last_encode_ms;
    st.active_qp = shared_config.lock().unwrap().qp;
    st.active_frame_ratio = shared_config.lock().unwrap().frame_ratio;
    Ok(st.clone())
}

// ════════════════════════════════════════════════════════════════
// 客户端会话
// ════════════════════════════════════════════════════════════════

/// 运行客户端 QUIC 媒体会话：DATAGRAM 重组 → 解码 → 渲染回调 + 反馈上报。
///
/// 内部并发结构：
/// - 主循环：`recv_frame`（含分片重组 + 丢包检测）→ `VideoDecoderPipeline` → `on_frame(w, h, rgba)`
/// - 反馈 task：每 `feedback_interval_ms` 上报 `FeedbackReport`（共享 LossDetector
///   + 带宽/RTT 统计）
///
/// `on_frame` 在 tokio task 内被调用，**必须尽快返回**（渲染上传由调用方处理）。
pub async fn run_client_session<F>(
    mut transport: QuicMediaTransport,
    mut on_frame: F,
    config: SessionConfig,
    stop: Arc<AtomicBool>,
) -> Result<ClientSessionStats, String>
where
    F: FnMut(u32, u32, &[u8]) + Send + 'static,
{
    // 1. 等待服务端推送分辨率（会话开始时，10s 超时）
    let (w, h) = match tokio::time::timeout(Duration::from_secs(10), transport.recv_control()).await
    {
        Ok(Ok(ControlMessage::VideoFormat { width, height })) => (width, height),
        Ok(Ok(other)) => {
            warn!("[Session] expected VideoFormat, got {:?}", other);
            (0, 0)
        }
        Ok(Err(e)) => return Err(format!("recv VideoFormat: {e}")),
        Err(_) => return Err("timeout waiting for VideoFormat from server".into()),
    };
    if w == 0 || h == 0 {
        return Err("invalid VideoFormat from server".into());
    }
    info!("client session: video {}x{}", w, h);

    // 2. 解码器（回退链：qsv→cuvid→d3d11va→vt→vaapi→软解；P2B 流式管线）。
    //    旧逻辑（hw 打开成功但首帧失败 → 整体回退软解）由新管线的连续错误
    //    → flush + IDR 请求机制取代（P2B §T2.3 IDR 恢复策略）。
    let mut decoder = match create_video_decoder(Codec::H264) {
        Ok(d) => {
            info!(
                "client session: decoder '{}' (hw={})",
                d.name(),
                d.is_hardware()
            );
            d
        }
        Err(e) => return Err(format!("create H.264 decoder: {e}")),
    };

    let stats = Arc::new(Mutex::new(ClientSessionStats::default()));

    // 3. 反馈上报 task（每 feedback_interval_ms）
    if let Some(send_stream) = transport.take_control_sender() {
        let cipher = transport.cipher_handle();
        let loss_detector = transport.loss_detector_shared();
        let stats = Arc::clone(&stats);
        let stop = Arc::clone(&stop);
        let interval = Duration::from_millis(config.feedback_interval_ms);
        tokio::spawn(async move {
            let mut stream = send_stream;
            let mut report_gen = ReportGenerator::new(interval);
            report_gen.set_loss_detector(loss_detector);
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(interval).await;
                {
                    let st = stats.lock().unwrap();
                    report_gen.update_rtt(st.rtt_ms.saturating_mul(1000));
                    report_gen.update_bandwidth(st.bandwidth_bps);
                }
                if let Some(msg) = report_gen.generate_control_msg() {
                    if control::send_control_msg(&mut stream, &cipher, &msg)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    stats.lock().unwrap().feedback_sent += 1;
                }
            }
        });
    } else {
        warn!("client session: no control sender stream");
    }

    // 4. 主循环：接收 → 解码 → 渲染回调
    let mut bandwidth_accum: u64 = 0;
    let mut bandwidth_window = Instant::now();
    let mut decode_accum: f64 = 0.0;
    let mut decode_count: u64 = 0;

    loop {
        if stop.load(Ordering::Relaxed) {
            info!("client session: stopping by user request");
            break;
        }

        // 带宽估算（字节累计 → bps）
        {
            let mut st = stats.lock().unwrap();
            let elapsed = bandwidth_window.elapsed().as_secs_f64();
            if elapsed >= 1.0 {
                st.bandwidth_bps = (bandwidth_accum as f64 * 8.0 / elapsed) as u64;
                bandwidth_accum = 0;
                bandwidth_window = Instant::now();
            }
            st.rtt_ms = transport.rtt();
        }

        debug!("[Session] recv_frame enter");
        match transport.recv_frame().await {
            Ok(frame) => {
                debug!("[Session] recv_frame exit got frame {}", frame.frame_id);
                bandwidth_accum += (frame.data.len() + 14) as u64;
                let is_key = frame.flags & 0x01 != 0;
                if is_key {
                    // IDR 到达：清旧参考帧（seek/丢包后安全重同步）。
                    decoder.flush();
                }
                // PTS 方案 A（P2A §T1.1）：frame_id 线性近似。
                let pkt = DecoderPacket {
                    pts: frame_id_to_pts(frame.frame_id, TARGET_FPS),
                    data: frame.data.clone(),
                    is_key,
                    extradata: None,
                };
                let start = Instant::now();
                match decoder.decode(&pkt) {
                    Ok(frames) => {
                        let ms = start.elapsed().as_secs_f64() * 1000.0;
                        decode_accum += ms;
                        decode_count += 1;
                        {
                            let mut st = stats.lock().unwrap();
                            st.frames_decoded += frames.len() as u64;
                            st.avg_decode_ms = if decode_count > 0 {
                                decode_accum / decode_count as f64
                            } else {
                                0.0
                            };
                            st.loss_rate = {
                                let ld = transport.loss_detector_shared();
                                let guard = ld.lock().unwrap();
                                guard.loss_rate()
                            };
                            st.video_w = w;
                            st.video_h = h;
                        }
                        // 流式：一包可能产出 0..N 帧（0 帧 = 参考帧缓冲中）。
                        for df in &frames {
                            on_frame(df.width, df.height, &df.rgba);
                        }
                    }
                    Err(e) => {
                        // 连续错误达阈值（≥3）→ 内部已 flush + idr_requests++，
                        // 上层（自适应反馈）据此让服务端强制下一帧 IDR。
                        if decoder.report_error() {
                            warn!(
                                "[Session] decode errors exceeded threshold — keyframe requested, awaiting IDR"
                            );
                        }
                        stats.lock().unwrap().frames_dropped += 1;
                        warn!("[Session] decode frame failed: {e}");
                    }
                }
            }
            Err(TransportError::Timeout) => {
                // 静默窗口期间无媒体数据 → 继续等待
                continue;
            }
            Err(e) => {
                debug!("[Session] recv ended: {e}");
                break;
            }
        }
    }

    transport.conn().close("client session end");

    let udp = transport.conn().udp_stats();
    info!(
        "client session ended: udp tx={} dg/{} B, rx={} dg/{} B",
        udp.0, udp.1, udp.2, udp.3
    );
    let st = stats.lock().unwrap();
    Ok(st.clone())
}
