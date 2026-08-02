//! 二分定位 8：内联复制 run_server_session 主循环（捕获+窗口+编码+锁+on_encode_complete），
//! 但【不调用】transport.rtt()/congestion_window()/on_quic_stats。
//! 通过 → quinn stats() 连接锁是触发点。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_media::adaptive::AdaptiveEngine;
use kirin_desk_media::capture::{CaptureError, CaptureFrame, MonitorInfo, ScreenCaptureSource};
use kirin_desk_media::encoder::types::{Codec, EncodedPacket, EncodeDecision, GpuTexture, Timestamp};
use kirin_desk_media::encoder::video::EncodeError;
use kirin_desk_media::encoder::{VideoEncoder, VideoEncoderPipeline};
use kirin_desk_media::proto::{EncodeConfig, RawFrame, WindowConfig};
use kirin_desk_media::transport::{
    accept_quic_transport, connect_quic_transport, generate_quic_cert, ControlMessage,
    MediaTransport, QuicEndpoint,
};
use kirin_desk_media::window_pipeline::WindowPipeline;

struct DummyEncoder;
impl VideoEncoder for DummyEncoder {
    fn encode(&mut self, _tex: &GpuTexture, ts: Timestamp, _d: EncodeDecision) -> Result<Vec<EncodedPacket>, EncodeError> {
        let nal: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84];
        let mut data = Vec::new();
        for _ in 0..40 { data.extend_from_slice(&nal); }
        Ok(vec![EncodedPacket { ts, kind: kirin_desk_media::encoder::types::PacketKind::Video, data, is_key: true }])
    }
    fn codec(&self) -> Codec { Codec::H264 }
    fn is_hardware(&self) -> bool { false }
    fn name(&self) -> &'static str { "dummy" }
    fn reconfigure(&mut self, _cfg: &EncodeConfig) -> Result<(), EncodeError> { Ok(()) }
}

struct SyntheticCapture {
    w: u32, h: u32, frame_idx: u64, last: Instant,
}
impl SyntheticCapture {
    fn new(w: u32, h: u32) -> Self { Self { w, h, frame_idx: 0, last: Instant::now() } }
    fn make_frame(&self) -> CaptureFrame {
        let mut data = vec![0x10u8; (self.w * self.h * 4) as usize];
        let block = 32u32;
        let x = ((self.frame_idx as u32 * 8) % (self.w - block)) as usize;
        let y = ((self.frame_idx as u32 * 4) % (self.h - block)) as usize;
        for row in y..y + block as usize {
            for col in x..x + block as usize {
                let off = (row * self.w as usize + col) * 4;
                data[off] = 0xFF; data[off + 1] = 0xFF; data[off + 2] = 0xFF; data[off + 3] = 0xFF;
            }
        }
        CaptureFrame::WindowsCapture(kirin_desk_media::capture::WindowsCaptureFrame {
            data, width: self.w, height: self.h, dirty_rects: vec![],
            processing_time: Duration::ZERO, timestamp: Instant::now(),
        })
    }
}
impl ScreenCaptureSource for SyntheticCapture {
    fn wait_for_frame(&mut self) -> Result<CaptureFrame, CaptureError> {
        let _ = self.last.elapsed();
        self.last = Instant::now();
        let frame = self.make_frame();
        self.frame_idx += 1;
        Ok(frame)
    }
    fn resolution(&self) -> (u32, u32) { (self.w, self.h) }
    fn monitor_info(&self) -> &[MonitorInfo] { &[] }
    fn switch_monitor(&mut self, _i: usize) -> Result<(), CaptureError> { Ok(()) }
    fn recreate(&mut self) -> Result<(), CaptureError> { Ok(()) }
}

#[tokio::test(flavor = "multi_thread")]
async fn bisect9() {
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() { eprintln!("skip"); return; }
    const W: u32 = 320;
    const H: u32 = 240;
    let tmp = std::env::temp_dir();
    let server_id = "b8-server".to_string();
    let client_id = "b8-client".to_string();
    let server_im = IdentityManager::generate(tmp.join("kirin_b8_s.key")).unwrap();
    let client_im = IdentityManager::generate(tmp.join("kirin_b8_c.key")).unwrap();
    let server_pub = server_im.public_key_base64();
    let client_pub = client_im.public_key_base64();

    let (cert, key) = generate_quic_cert(&server_id).unwrap();
    let endpoint = Arc::new(QuicEndpoint::bind(0, cert, key).await.unwrap());
    let port = endpoint.local_addr().unwrap().port();
    let addr: SocketAddr = ([0, 0, 0, 0, 0, 0, 0, 1], port).into();
    let endpoint_task = Arc::clone(&endpoint);
    let server_im_task = Arc::new(server_im);
    let server_im2 = Arc::clone(&server_im_task);
    let server_id_task = server_id.clone();
    let client_pub_task = client_pub.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_server = Arc::clone(&stop);

    let server_handle = tokio::spawn(async move {
        let mut t = accept_quic_transport(
            &endpoint_task, &server_im2, &server_id_task, &client_pub_task, None, None,
        ).await.unwrap();
        t.send_control(&ControlMessage::VideoFormat { width: W, height: H }).await.unwrap();

        // 连接状态监控（clone 句柄）
        let watch = t.conn().clone_quic();
        let stop_w = Arc::clone(&stop_server);
        tokio::spawn(async move {
            let mut prev_alive = true;
            loop {
                if stop_w.load(Ordering::Relaxed) { break; }
                let alive = watch.is_alive();
                if !alive && prev_alive {
                    eprintln!("SERVER CONNECTION DIED: {:?}", watch.close_reason_str());
                    break;
                }
                prev_alive = alive;
                let d = watch.path_diag();
                eprintln!("PROBE alive={alive} {d}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        // 内联会话主循环（无 rtt/cwnd/stats 调用）
        let encoder = VideoEncoderPipeline::from_parts(None, Box::new(DummyEncoder)).unwrap();
        let mut capture = SyntheticCapture::new(W, H);
        let mut pipeline = WindowPipeline::new(WindowConfig::default(), encoder);
        let mut engine = AdaptiveEngine::new(W, H);
        let mut windows: u64 = 0;
        loop {
            if stop_server.load(Ordering::Relaxed) { break; }
            let frame = capture.wait_for_frame().unwrap();
            let raw = RawFrame {
                data: Arc::new(frame.data().to_vec()),
                width: frame.width(), height: frame.height(),
                timestamp: std::time::SystemTime::now(),
                dirty_rects: vec![],
                force_key: windows == 0,
            };
            match pipeline.push_frame(raw) {
                Ok(Some(window)) => {
                    windows = window.window_id;
                    if window.is_empty() {
                        engine.on_silent_window();
                    } else {
                        engine.on_active_window();
                        t.send_window(&window).await.unwrap();
                    }
                    let _ = engine.on_encode_complete(window.encode_duration_ms);
                }
                Ok(None) => {}
                Err(e) => { eprintln!("SERVER pipeline err: {e}"); }
            }
        }
        let udp = t.conn().udp_stats();
        eprintln!("SERVER udp tx={} dg rx={} dg windows={}", udp.0, udp.2, windows);
        t.conn().close("done");
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr, &client_im, &client_id, "b8.example", "desktop", &server_id, &server_pub, "challenge",
        ).await.unwrap();
        let _fmt = t.recv_control().await.unwrap();
        let mut got = 0u32;
        loop {
            match t.recv_frame().await {
                Ok(_) => { got += 1; }
                Err(e) => { eprintln!("CLIENT recv end: {e} (got {got})"); break; }
            }
        }
        eprintln!("CLIENT got={got}");
        t.conn().close("done");
    });

    tokio::time::timeout(Duration::from_secs(60), async {
        tokio::time::sleep(Duration::from_secs(4)).await;
        stop.store(true, Ordering::Relaxed);
        let _ = client_handle.await;
        let _ = server_handle.await;
    }).await.expect("timeout");
}
