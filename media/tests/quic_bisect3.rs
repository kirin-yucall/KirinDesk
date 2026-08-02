//! 二分定位 3：完整服务端会话（捕获+编码+锁） + 内联客户端（无反馈上报 task）。
//! 若成功 → 反馈路径（客户端报告 task / 服务端控制 task）触发冻结。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_media::capture::{CaptureError, CaptureFrame, MonitorInfo, ScreenCaptureSource};
use kirin_desk_media::decoder::factory::create_video_decoder;
use kirin_desk_media::decoder::DecoderPacket;
use kirin_desk_media::encoder::types::Codec;
use kirin_desk_media::encoder::VideoEncoderPipeline;
use kirin_desk_media::session::{run_server_session, SessionConfig};
use kirin_desk_media::transport::{
    accept_quic_transport, connect_quic_transport, generate_quic_cert, MediaTransport, QuicEndpoint,
};

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
        let elapsed = self.last.elapsed();
        if elapsed < Duration::from_millis(33) { std::thread::sleep(Duration::from_millis(33) - elapsed); }
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
async fn bisect3() {
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("Skipping: no FFmpeg");
        return;
    }
    const W: u32 = 320;
    const H: u32 = 240;
    let tmp = std::env::temp_dir();
    let server_id = "b3-server".to_string();
    let client_id = "b3-client".to_string();
    let server_im = IdentityManager::generate(tmp.join("kirin_b3_s.key")).unwrap();
    let client_im = IdentityManager::generate(tmp.join("kirin_b3_c.key")).unwrap();
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
        run_server_session(t, capture, encoder, SessionConfig::default(), stop_server)
            .await
            .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let decoded = Arc::new(Mutex::new(0u32));
    let decoded_task = Arc::clone(&decoded);
    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr, &client_im, &client_id, "b3.example", "desktop", &server_id, &server_pub, "challenge",
        )
        .await
        .unwrap();
        let _fmt = t.recv_control().await.unwrap();
        let mut decoder = create_video_decoder(Codec::H264).unwrap();
        eprintln!("CLIENT decoder: {}", decoder.name());
        let mut got = 0u32;
        let mut sw = false;
        loop {
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
                        Ok(_) => { *decoded_task.lock().unwrap() += 1; }
                        Err(e) => {
                            if !sw {
                                eprintln!("CLIENT hw decode err: {e} — sw fallback");
                                match create_video_decoder(Codec::H264) {
                                    Ok(d) => { decoder = d; sw = true; }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                }
                Err(e) => { eprintln!("CLIENT recv end: {e} (got {got})"); break; }
            }
        }
        let udp = t.conn().udp_stats();
        eprintln!("CLIENT udp tx={} dg/{}B rx={} dg/{}B cwnd={}", udp.0, udp.1, udp.2, udp.3, t.conn().congestion_window());
        eprintln!("CLIENT got={got}");
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
    assert!(n > 0, "should decode frames without client feedback task");
}
