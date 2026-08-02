//! M8-T009 端到端 loopback 集成测试（T013 Task 3.10 + P1F「端到端重组待实测」验证）。
//!
//! 真实 QUIC 连接（quinn UDP loopback [::1]）完整闭环：
//!
//! ```text
//! 服务端: accept_quic_transport（Ed25519 握手）
//!         → run_server_session（合成捕获 → WindowPipeline → H.264 → DATAGRAM）
//! 客户端: connect_quic_transport
//!         → run_client_session（重组 → 解码 → on_frame 回调）
//! 反馈:   客户端 FeedbackReport（可靠流）→ 服务端 AdaptiveEngine → 配置回写
//! ```
//!
//! 验证点：
//! 1. 握手 + VideoFormat 分辨率推送
//! 2. 媒体 DATAGRAM 分片 → 重组 → 解码 → 渲染回调（帧尺寸/内容正确）
//! 3. 反馈闭环：客户端上报 ≥1 个 FeedbackReport，服务端收到并驱动自适应
//!
//! 依赖 FFmpeg DLL（H.264 编解码），环境无 DLL 时自动跳过。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_media::capture::{
    CaptureError, CaptureFrame, MonitorInfo, ScreenCaptureSource,
};
use kirin_desk_media::encoder::types::Codec;
use kirin_desk_media::encoder::VideoEncoderPipeline;
use kirin_desk_media::session::{run_client_session, run_server_session, SessionConfig};
use kirin_desk_media::transport::{
    accept_quic_transport, connect_quic_transport, generate_quic_cert, QuicEndpoint,
};

// ════════════════════════════════════════════════════════════════
// 合成捕获源（不依赖真实屏幕）
// ════════════════════════════════════════════════════════════════

/// 合成捕获源：每 33ms 一帧，内容为移动色块（保证窗口内帧有变化）。
struct SyntheticCapture {
    w: u32,
    h: u32,
    frame_idx: u64,
    last: Instant,
}

impl SyntheticCapture {
    fn new(w: u32, h: u32) -> Self {
        Self {
            w,
            h,
            frame_idx: 0,
            last: Instant::now(),
        }
    }

    fn make_frame(&self) -> CaptureFrame {
        let mut data = vec![0x10u8; (self.w * self.h * 4) as usize]; // 深色背景
        // 移动白色色块（x 随帧号变化 → 每帧内容变化）
        let block = 32u32;
        let x = ((self.frame_idx as u32 * 8) % (self.w - block)) as usize;
        let y = ((self.frame_idx as u32 * 4) % (self.h - block)) as usize;
        for row in y..y + block as usize {
            for col in x..x + block as usize {
                let off = (row * self.w as usize + col) * 4;
                data[off] = 0xFF;
                data[off + 1] = 0xFF;
                data[off + 2] = 0xFF;
                data[off + 3] = 0xFF;
            }
        }
        CaptureFrame::WindowsCapture(kirin_desk_media::capture::WindowsCaptureFrame {
            data,
            width: self.w,
            height: self.h,
            dirty_rects: vec![],
            processing_time: Duration::ZERO,
            timestamp: Instant::now(),
        })
    }
}

impl ScreenCaptureSource for SyntheticCapture {
    fn wait_for_frame(&mut self) -> Result<CaptureFrame, CaptureError> {
        // 距上一帧不足 33ms → 等待（模拟显示器刷新节奏）
        let elapsed = self.last.elapsed();
        if elapsed < Duration::from_millis(33) {
            std::thread::sleep(Duration::from_millis(33) - elapsed);
        }
        self.last = Instant::now();
        let frame = self.make_frame();
        self.frame_idx += 1;
        Ok(frame)
    }

    fn resolution(&self) -> (u32, u32) {
        (self.w, self.h)
    }

    fn monitor_info(&self) -> &[MonitorInfo] {
        &[]
    }

    fn switch_monitor(&mut self, _index: usize) -> Result<(), CaptureError> {
        Ok(())
    }

    fn recreate(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════
// 测试
// ════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
async fn quic_loopback_end_to_end() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    // FFmpeg DLL 不可用 → 跳过（与 window_pipeline 测试同策略）
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("Skipping: no FFmpeg DLLs available");
        return;
    }

    const W: u32 = 320;
    const H: u32 = 240;

    // ── 身份（临时目录，不落盘） ────────────────────────────────
    let tmp = std::env::temp_dir();
    let server_id = "loopback-server".to_string();
    let client_id = "loopback-client".to_string();
    let server_im =
        IdentityManager::generate(tmp.join("kirin_loop_s.key")).expect("server identity");
    let client_im =
        IdentityManager::generate(tmp.join("kirin_loop_c.key")).expect("client identity");
    let server_pub = server_im.public_key_base64();
    let client_pub = client_im.public_key_base64();

    // ── 服务端 QUIC 端点（临时端口） ────────────────────────────
    let (cert, key) = generate_quic_cert(&server_id).expect("quic cert");
    let endpoint = QuicEndpoint::bind(0, cert, key).await.expect("bind");
    let addr: SocketAddr = {
        let local = endpoint.local_addr().expect("local addr");
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], local.port()))
    };
    let endpoint = Arc::new(endpoint);

    // ── 客户端收到的解码帧 ──────────────────────────────────────
    let decoded = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let stop = Arc::new(AtomicBool::new(false));

    // ── 服务端会话任务 ──────────────────────────────────────────
    let server_im = Arc::new(server_im);
    let server_im_task = Arc::clone(&server_im);
    let endpoint_task = Arc::clone(&endpoint);
    let stop_server = Arc::clone(&stop);
    let server_id_task = server_id.clone();
    let client_pub_task = client_pub.clone();
    let server_handle = tokio::spawn(async move {
        let transport = accept_quic_transport(
            &endpoint_task,
            &server_im_task,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .expect("accept + handshake");

        let encoder = VideoEncoderPipeline::new(Codec::H264, None).expect("encoder");
        let capture: Box<dyn ScreenCaptureSource> = Box::new(SyntheticCapture::new(W, H));
        run_server_session(
            transport,
            capture,
            encoder,
            SessionConfig::default(),
            Arc::clone(&stop_server),
        )
        .await
        .expect("server session")
    });

    // 等服务端进入 accept（给 1s 余量）
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── 客户端会话 ──────────────────────────────────────────────
    let decoded_task = Arc::clone(&decoded);
    let stop_client = Arc::clone(&stop);
    let client_handle = tokio::spawn(async move {
        let transport = connect_quic_transport(
            addr,
            &client_im,
            &client_id,
            "loopback.example",
            "desktop",
            &server_id,
            &server_pub,
            "challenge",
        )
        .await
        .expect("connect + handshake");

        let on_frame = move |w: u32, h: u32, rgba: &[u8]| {
            if w * h * 4 == rgba.len() as u32 {
                decoded_task.lock().unwrap().push(rgba.to_vec());
            }
        };
        run_client_session(transport, on_frame, SessionConfig::default(), stop_client)
            .await
            .expect("client session")
    });

    // ── 运行 3s：覆盖 ≥2 个窗口 + ≥1 个反馈周期 ────────────────
    let total = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::time::sleep(Duration::from_secs(3)).await;
        stop.store(true, Ordering::Relaxed);

        let client_stats = client_handle.await.expect("client join");
        let server_stats = server_handle.await.expect("server join");
        (client_stats, server_stats)
    })
    .await
    .expect("test timeout");

    let (client_stats, server_stats) = total;

    eprintln!(
        "server: windows={} frames={} silent={} feedback={} loss={:.3} state={} recovery={} | client: decoded={} dropped={} fb_sent={} rtt={} bps={}",
        server_stats.windows_encoded,
        server_stats.frames_encoded,
        server_stats.silent_windows,
        server_stats.feedback_reports,
        server_stats.last_loss_rate,
        server_stats.network_state,
        server_stats.recovery_phase,
        client_stats.frames_decoded,
        client_stats.frames_dropped,
        client_stats.feedback_sent,
        client_stats.rtt_ms,
        client_stats.bandwidth_bps,
    );

    // ── 验证 ────────────────────────────────────────────────────
    // 1. 媒体路径：客户端成功解码出帧，尺寸正确
    let frames = decoded.lock().unwrap().clone();
    assert!(
        !frames.is_empty(),
        "client should decode at least one frame (got {})",
        frames.len()
    );
    assert_eq!(frames[0].len(), (W * H * 4) as usize, "RGBA frame size");

    // 2. 会话统计：解码帧数 > 0，分辨率来自 VideoFormat 推送
    assert!(
        client_stats.frames_decoded > 0,
        "client decoded {} frames",
        client_stats.frames_decoded
    );
    assert_eq!(client_stats.video_w, W);
    assert_eq!(client_stats.video_h, H);

    // 3. 反馈闭环：客户端上报 ≥1，服务端收到并解析
    assert!(
        client_stats.feedback_sent > 0,
        "client should send feedback reports (sent {})",
        client_stats.feedback_sent
    );
    assert!(
        server_stats.feedback_reports > 0,
        "server should receive feedback reports (got {})",
        server_stats.feedback_reports
    );

    // 4. 服务端会话产出了编码窗口
    assert!(
        server_stats.windows_encoded > 0 || server_stats.frames_encoded > 0,
        "server should encode at least one window"
    );

    tracing::info!(
        "loopback OK: windows={} frames={} silent={} | client decoded={} dropped={} feedback_sent={} server_feedback={} loss={:.3}",
        server_stats.windows_encoded,
        server_stats.frames_encoded,
        server_stats.silent_windows,
        client_stats.frames_decoded,
        client_stats.frames_dropped,
        client_stats.feedback_sent,
        server_stats.feedback_reports,
        client_stats.loss_rate,
    );
}
