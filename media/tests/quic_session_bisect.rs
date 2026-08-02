//! 二分定位：客户端用「内联循环」替代 run_client_session，
//! 其余完全复用 loopback 测试（真实会话 + 编码 + 解码 + 反馈）。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_media::capture::{CaptureError, CaptureFrame, MonitorInfo, ScreenCaptureSource};
use kirin_desk_media::decoder::factory::{create_software_decoder, create_video_decoder};
use kirin_desk_media::decoder::DecoderPacket;
use kirin_desk_media::encoder::types::Codec;
use kirin_desk_media::encoder::VideoEncoderPipeline;
use kirin_desk_media::session::{run_server_session, SessionConfig};
use kirin_desk_media::transport::{
    accept_quic_transport, connect_quic_transport, generate_quic_cert, ControlMessage,
    MediaTransport, QuicEndpoint,
};

struct SyntheticCapture {
    w: u32,
    h: u32,
    frame_idx: u64,
    last: Instant,
}
impl SyntheticCapture {
    fn new(w: u32, h: u32) -> Self {
        Self { w, h, frame_idx: 0, last: Instant::now() }
    }
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
        let elapsed = self.last.elapsed();
        if elapsed < Duration::from_millis(33) {
            std::thread::sleep(Duration::from_millis(33) - elapsed);
        }
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
async fn client_inline_loop() {
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("Skipping: no FFmpeg");
        return;
    }
    const W: u32 = 320;
    const H: u32 = 240;
    let tmp = std::env::temp_dir();
    let server_id = "bisect-server".to_string();
    let client_id = "bisect-client".to_string();
    let server_im = IdentityManager::generate(tmp.join("kirin_bisect_s.key")).unwrap();
    let client_im = IdentityManager::generate(tmp.join("kirin_bisect_c.key")).unwrap();
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
        let t = accept_quic_transport(
            &endpoint_task, &server_im2, &server_id_task, &client_pub_task, None, None,
        )
        .await
        .unwrap();
        let encoder = VideoEncoderPipeline::new(Codec::H264, None).unwrap();
        let capture: Box<dyn ScreenCaptureSource> = Box::new(SyntheticCapture::new(W, H));
        run_server_session(Box::new(t), capture, encoder, SessionConfig::default(), None, None, stop_server)
            .await
            .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let decoded = Arc::new(Mutex::new(0u32));
    let decoded_task = Arc::clone(&decoded);
    let stop_client = Arc::clone(&stop);
    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr, &client_im, &client_id, "bisect.example", "desktop", &server_id, kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&server_pub).expect("server pubkey"), "challenge",
        )
        .await
        .unwrap();
        // VideoFormat
        let fmt = t.recv_control().await.unwrap();
        eprintln!("CLIENT fmt: {fmt:?}");
        // 反馈 task（与 session 相同的报告结构——先不带 loss_detector）
        let sender = t.take_control_sender().unwrap();
        let cipher = t.cipher_handle();
        let stop_rpt = Arc::clone(&stop_client);
        tokio::spawn(async move {
            let mut stream = sender;
            let mut seq = 0u64;
            loop {
                if stop_rpt.load(Ordering::Relaxed) { break; }
                tokio::time::sleep(Duration::from_millis(100)).await;
                seq += 1;
                let msg = ControlMessage::FeedbackReport {
                    loss_rate: 0.0, rtt_ms: 1, received_bitrate: 1_000_000,
                    frame_id: seq, missing_frames: vec![],
                };
                if kirin_desk_media::transport::control::send_control_msg(&mut stream, &cipher, &msg).await.is_err() { break; }
            }
        });
        // 解码器
        let mut decoder = create_video_decoder(Codec::H264).unwrap();
        eprintln!("CLIENT decoder: {}", decoder.name());
        // 接收循环（与 run_client_session 主循环一致，但内联）
        let mut got = 0u32;
        let mut decoded_frames = 0u32;
        let mut sw = false;
        loop {
            if stop_client.load(Ordering::Relaxed) { break; }
            match t.recv_frame().await {
                Ok(frame) => {
                    got += 1;
                    let is_key = frame.flags & 0x01 != 0;
                    if is_key { decoder.flush(); }
                    match decoder.decode(&DecoderPacket {
                        pts: 0,
                        data: frame.data.clone(),
                        is_key,
                        extradata: None,
                    }) {
                        Ok(_rgba) => { decoded_frames += 1; *decoded_task.lock().unwrap() += 1; }
                        Err(e) => {
                            if !sw {
                                // P2-3 同源（quic_bisect）：fallback 必须显式软解
                                // ——create_video_decoder 重走回退链仍选回 h264_qsv
                                // （open2 成功但 MFX 会话失败），名不副实。
                                eprintln!(
                                    "CLIENT decode err on '{}': {e} — explicit sw fallback",
                                    decoder.name()
                                );
                                match create_software_decoder(Codec::H264) {
                                    Ok(d) => {
                                        decoder = d;
                                        sw = true;
                                    }
                                    Err(fe) => eprintln!("CLIENT sw fallback failed: {fe}"),
                                }
                            }
                        }
                    }
                }
                Err(e) => { eprintln!("CLIENT recv end: {e} (got {got} frames, decoded {decoded_frames})"); break; }
            }
        }
        let udp = t.conn().udp_stats();
        eprintln!("CLIENT udp tx={} dg/{}B rx={} dg/{}B cwnd={}", udp.0, udp.1, udp.2, udp.3, t.conn().congestion_window());
        eprintln!("CLIENT got={got} decoded={decoded_frames}");
        t.conn().close("done");
    });

    tokio::time::timeout(Duration::from_secs(60), async {
        tokio::time::sleep(Duration::from_secs(4)).await;
        stop.store(true, Ordering::Relaxed);
        let _ = client_handle.await;
        let _ = server_handle.await;
    })
    .await
    .expect("timeout");

    let n = *decoded.lock().unwrap();
    eprintln!("TOTAL DECODED: {n}");
    assert!(n > 0, "inline client should decode frames");
}
