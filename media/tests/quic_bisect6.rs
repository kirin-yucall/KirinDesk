//! 二分定位 6：完整服务端会话 + Dummy 编码器（瞬时返回假包，无 libx264）。
//! 通过 → libx264 编码是元凶；失败 → 会话结构（锁/控制 task/捕获）是元凶。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_media::capture::{CaptureError, CaptureFrame, MonitorInfo, ScreenCaptureSource};
use kirin_desk_media::encoder::types::{Codec, EncodedPacket, EncodeDecision, GpuTexture, Timestamp};
use kirin_desk_media::encoder::video::EncodeError;
use kirin_desk_media::encoder::{VideoEncoder, VideoEncoderPipeline};
use kirin_desk_media::proto::EncodeConfig;
use kirin_desk_media::session::{run_server_session, SessionConfig};
use kirin_desk_media::transport::{
    accept_quic_transport, connect_quic_transport, generate_quic_cert, MediaTransport, QuicEndpoint,
};

/// 瞬时假编码器：直接返回假 NAL 包。
struct DummyEncoder;
impl VideoEncoder for DummyEncoder {
    fn encode(&mut self, _tex: &GpuTexture, ts: Timestamp, _d: EncodeDecision) -> Result<Vec<EncodedPacket>, EncodeError> {
        Ok(vec![EncodedPacket {
            ts,
            kind: kirin_desk_media::encoder::types::PacketKind::Video,
            data: {
                let nal: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84];
                let mut d = Vec::new();
                for _ in 0..40 { d.extend_from_slice(&nal); }
                d
            },
            is_key: true,
        }])
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
async fn bisect6() {
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() { eprintln!("skip"); return; }
    const W: u32 = 320;
    const H: u32 = 240;
    let tmp = std::env::temp_dir();
    let server_id = "b6-server".to_string();
    let client_id = "b6-client".to_string();
    let server_im = IdentityManager::generate(tmp.join("kirin_b6_s.key")).unwrap();
    let client_im = IdentityManager::generate(tmp.join("kirin_b6_c.key")).unwrap();
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
        ).await.unwrap();
        let encoder = VideoEncoderPipeline::from_parts(None, Box::new(DummyEncoder)).unwrap();
        let capture: Box<dyn ScreenCaptureSource> = Box::new(SyntheticCapture::new(W, H));
        run_server_session(t, capture, encoder, SessionConfig::default(), stop_server).await.unwrap()
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr, &client_im, &client_id, "b6.example", "desktop", &server_id, &server_pub, "challenge",
        ).await.unwrap();
        let _fmt = t.recv_control().await.unwrap();
        let mut got = 0u32;
        loop {
            match t.recv_frame().await {
                Ok(_frame) => { got += 1; }
                Err(e) => { eprintln!("CLIENT recv end: {e} (got {got})"); break; }
            }
        }
        let udp = t.conn().udp_stats();
        eprintln!("CLIENT udp tx={} dg rx={} dg got={}", udp.0, udp.2, got);
        t.conn().close("done");
    });

    tokio::time::timeout(Duration::from_secs(60), async {
        tokio::time::sleep(Duration::from_secs(4)).await;
        stop.store(true, Ordering::Relaxed);
        let _ = client_handle.await;
        let _ = server_handle.await;
    }).await.expect("timeout");
}
