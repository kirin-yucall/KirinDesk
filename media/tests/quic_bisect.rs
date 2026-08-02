//! M8-T026-P1 历史二分定位测试（原 quic_bisect2~10，9 个独立文件）——
//! R-24 / R11-S4：参数化合并为单文件。共享脚手架（`setup_quic` /
//! `SyntheticCapture`（paced 变体）/ `DummyEncoder` / `fake_window`）抽到
//! 本文件顶部，9 个 `#[test]` 语义**逐字保留**（测试数不降，文件数 9→1）。
//!
//! 各变体定位（调试 QUIC 媒体链路冻结问题时的二分假设）：
//! - `bisect2`：flow 风格服务端（假窗口，无捕获/编码/锁）+ 内联客户端（含解码器）
//! - `bisect3`：完整服务端会话（捕获+编码+锁）+ 内联客户端（无反馈上报 task）
//! - `bisect4`：同 3，仅捕获无 33ms 节流（验证 thread::sleep 是否元凶）
//! - `bisect5`：同 3 + 客户端探针 task（每 200ms 采样连接统计）
//! - `bisect6`：完整服务端会话 + Dummy 编码器（无 libx264）
//! - `bisect7`：bisect2 + 服务端控制 task（客户端不发反馈）
//! - `bisect8`：内联复制 run_server_session 主循环（不调 rtt/cwnd/stats）
//! - `bisect9`：bisect8 + 连接存活监控 task
//! - `bisect10`：bisect7 紧循环 2000 窗口（无 sleep，验证发送速率触发点）

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_media::adaptive::AdaptiveEngine;
use kirin_desk_media::capture::{CaptureError, CaptureFrame, MonitorInfo, ScreenCaptureSource};
use kirin_desk_media::decoder::factory::create_video_decoder;
use kirin_desk_media::decoder::DecoderPacket;
use kirin_desk_media::encoder::types::{Codec, EncodedPacket, EncodeDecision, GpuTexture, Timestamp};
use kirin_desk_media::encoder::video::EncodeError;
use kirin_desk_media::encoder::{VideoEncoder, VideoEncoderPipeline};
use kirin_desk_media::proto::{EncodeConfig, EncodedWindow, RawFrame, WindowConfig};
use kirin_desk_media::session::{run_server_session, SessionConfig};
use kirin_desk_media::transport::{
    accept_quic_transport, connect_quic_transport, generate_quic_cert, ControlMessage,
    MediaTransport, QuicEndpoint,
};
use kirin_desk_media::window_pipeline::WindowPipeline;

/// 回环 QUIC 端点 + 双端身份的公共准备（原 9 文件逐份重复的样板）。
struct TestCtx {
    addr: SocketAddr,
    endpoint: Arc<QuicEndpoint>,
    server_im: Arc<IdentityManager>,
    client_im: IdentityManager,
    server_id: String,
    client_id: String,
    server_pub: String,
    client_pub: String,
}

async fn setup_quic(tag: &str) -> TestCtx {
    let tmp = std::env::temp_dir();
    let server_id = format!("{tag}-server");
    let client_id = format!("{tag}-client");
    let server_im =
        Arc::new(IdentityManager::generate(tmp.join(format!("kirin_{tag}_s.key"))).unwrap());
    let client_im = IdentityManager::generate(tmp.join(format!("kirin_{tag}_c.key"))).unwrap();
    let server_pub = server_im.public_key_base64();
    let client_pub = client_im.public_key_base64();

    let (cert, key) = generate_quic_cert(&server_id).unwrap();
    let endpoint = Arc::new(QuicEndpoint::bind(0, cert, key).await.unwrap());
    let port = endpoint.local_addr().unwrap().port();
    let addr: SocketAddr = ([0, 0, 0, 0, 0, 0, 0, 1], port).into();
    TestCtx {
        addr,
        endpoint,
        server_im,
        client_im,
        server_id,
        client_id,
        server_pub,
        client_pub,
    }
}

/// 客户端打洞/媒体连接共用的 pin 构造（PUNCH-SEC-001，R-02 `Exact` 强类型）。
fn exact_pin(pubkey_base64: &str) -> kirin_desk_core::crypto::handshake::PinExpectation {
    kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(pubkey_base64)
        .expect("server pubkey")
}

/// 假窗口（flow 风格服务端：无捕获/编码，直接发 EncodedWindow）。
fn fake_window(id: u64, frames: usize) -> EncodedWindow {
    let nal: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84];
    let mut f = Vec::new();
    for _ in 0..frames {
        let mut packet = Vec::new();
        for _ in 0..64 {
            packet.extend_from_slice(&nal);
        }
        f.push(vec![packet]);
    }
    EncodedWindow::new(id, 320, 240, f)
}

/// 合成捕获源：`paced = true` 时按 33ms 节流（原 bisect3/5/6/8 变体），
/// `false` 时立即出帧（原 bisect4/9 变体——验证 thread::sleep 是否元凶）。
struct SyntheticCapture {
    w: u32,
    h: u32,
    frame_idx: u64,
    last: Instant,
    paced: bool,
}
impl SyntheticCapture {
    fn new(w: u32, h: u32, paced: bool) -> Self {
        Self {
            w,
            h,
            frame_idx: 0,
            last: Instant::now(),
            paced,
        }
    }
    fn make_frame(&self) -> CaptureFrame {
        let mut data = vec![0x10u8; (self.w * self.h * 4) as usize];
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
        if self.paced {
            let elapsed = self.last.elapsed();
            if elapsed < Duration::from_millis(33) {
                std::thread::sleep(Duration::from_millis(33) - elapsed);
            }
        } else {
            let _ = self.last.elapsed();
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
    fn switch_monitor(&mut self, _i: usize) -> Result<(), CaptureError> {
        Ok(())
    }
    fn recreate(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
}

/// 瞬时假编码器：直接返回假 NAL 包（无 libx264）。
struct DummyEncoder;
impl VideoEncoder for DummyEncoder {
    fn encode(
        &mut self,
        _tex: &GpuTexture,
        ts: Timestamp,
        _d: EncodeDecision,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        let nal: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84];
        let mut data = Vec::new();
        for _ in 0..40 {
            data.extend_from_slice(&nal);
        }
        Ok(vec![EncodedPacket {
            ts,
            kind: kirin_desk_media::encoder::types::PacketKind::Video,
            data,
            is_key: true,
        }])
    }
    fn codec(&self) -> Codec {
        Codec::H264
    }
    fn is_hardware(&self) -> bool {
        false
    }
    fn name(&self) -> &'static str {
        "dummy"
    }
    fn reconfigure(&mut self, _cfg: &EncodeConfig) -> Result<(), EncodeError> {
        Ok(())
    }
}

/// 客户端连接 + 接收循环（仅计数帧数；连接关闭/错误即退出）。
async fn run_client_recv_count(ctx: &TestCtx, domain: &str) -> u32 {
    let mut t = connect_quic_transport(
        ctx.addr,
        &ctx.client_im,
        &ctx.client_id,
        domain,
        "desktop",
        &ctx.server_id,
        exact_pin(&ctx.server_pub),
        "challenge",
    )
    .await
    .unwrap();
    let _fmt = t.recv_control().await.unwrap();
    let mut got = 0u32;
    loop {
        match t.recv_frame().await {
            Ok(_) => {
                got += 1;
            }
            Err(e) => {
                eprintln!("CLIENT recv end: {e} (got {got})");
                break;
            }
        }
    }
    eprintln!("CLIENT got={got}");
    t.conn().close("done");
    got
}

#[tokio::test(flavor = "multi_thread")]
async fn bisect2() {
    // flow 风格服务端（假窗口） + 内联客户端（含解码器）。
    let ctx = setup_quic("b2").await;
    let endpoint_task = Arc::clone(&ctx.endpoint);
    let server_im2 = Arc::clone(&ctx.server_im);
    let server_id_task = ctx.server_id.clone();
    let client_pub_task = ctx.client_pub.clone();

    let server_handle = tokio::spawn(async move {
        let mut t = accept_quic_transport(
            &endpoint_task,
            &server_im2,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .unwrap();
        t.send_control(&ControlMessage::VideoFormat {
            width: 320,
            height: 240,
        })
        .await
        .unwrap();
        for i in 0..60u64 {
            t.send_window(&fake_window(i, 3)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        let udp = t.conn().udp_stats();
        eprintln!("SERVER udp tx={} dg/{}B rx={} dg/{}B", udp.0, udp.1, udp.2, udp.3);
        t.conn().close("done");
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let addr = ctx.addr;
    let client_im = ctx.client_im;
    let client_id = ctx.client_id;
    let server_id = ctx.server_id;
    let server_pub = ctx.server_pub;
    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr,
            &client_im,
            &client_id,
            "b2.example",
            "desktop",
            &server_id,
            exact_pin(&server_pub),
            "challenge",
        )
        .await
        .unwrap();
        let _fmt = t.recv_control().await.unwrap();
        // 解码器（怀疑点）
        let mut decoder = match create_video_decoder(Codec::H264) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("decoder failed: {e}");
                return;
            }
        };
        eprintln!("CLIENT decoder: {}", decoder.name());
        let mut got = 0u32;
        loop {
            match t.recv_frame().await {
                Ok(frame) => {
                    got += 1;
                    let is_key = frame.flags & 0x01 != 0;
                    if is_key {
                        decoder.flush();
                    }
                    let _ = decoder.decode(&DecoderPacket {
                        pts: 0,
                        data: frame.data.clone(),
                        is_key,
                        extradata: None,
                    });
                }
                Err(e) => {
                    eprintln!("CLIENT recv end: {e} (got {got})");
                    break;
                }
            }
        }
        eprintln!("CLIENT got={got}");
        t.conn().close("done");
    });

    tokio::time::timeout(Duration::from_secs(30), client_handle)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bisect3() {
    // 完整服务端会话（捕获+编码+锁） + 内联客户端（无反馈上报 task），捕获 33ms 节流。
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("Skipping: no FFmpeg");
        return;
    }
    const W: u32 = 320;
    const H: u32 = 240;
    let ctx = setup_quic("b3").await;
    let endpoint_task = Arc::clone(&ctx.endpoint);
    let server_im2 = Arc::clone(&ctx.server_im);
    let server_id_task = ctx.server_id.clone();
    let client_pub_task = ctx.client_pub.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_server = Arc::clone(&stop);

    let server_handle = tokio::spawn(async move {
        let t = accept_quic_transport(
            &endpoint_task,
            &server_im2,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .unwrap();
        let encoder = VideoEncoderPipeline::new(Codec::H264, None).unwrap();
        let capture: Box<dyn ScreenCaptureSource> = Box::new(SyntheticCapture::new(W, H, true));
        run_server_session(
            Box::new(t),
            capture,
            encoder,
            SessionConfig::default(),
            None,
            None,
            stop_server,
        )
        .await
        .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let decoded = Arc::new(Mutex::new(0u32));
    let decoded_task = Arc::clone(&decoded);
    let addr = ctx.addr;
    let client_im = ctx.client_im;
    let client_id = ctx.client_id;
    let server_id = ctx.server_id;
    let server_pub = ctx.server_pub;
    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr,
            &client_im,
            &client_id,
            "b3.example",
            "desktop",
            &server_id,
            exact_pin(&server_pub),
            "challenge",
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
                    if is_key {
                        decoder.flush();
                    }
                    match decoder.decode(&DecoderPacket {
                        pts: 0,
                        data: frame.data.clone(),
                        is_key,
                        extradata: None,
                    }) {
                        Ok(_) => {
                            *decoded_task.lock().unwrap() += 1;
                        }
                        Err(e) => {
                            if !sw {
                                eprintln!("CLIENT hw decode err: {e} — sw fallback");
                                match create_video_decoder(Codec::H264) {
                                    Ok(d) => {
                                        decoder = d;
                                        sw = true;
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("CLIENT recv end: {e} (got {got})");
                    break;
                }
            }
        }
        let udp = t.conn().udp_stats();
        eprintln!(
            "CLIENT udp tx={} dg/{}B rx={} dg/{}B cwnd={}",
            udp.0,
            udp.1,
            udp.2,
            udp.3,
            t.conn().congestion_window()
        );
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

#[tokio::test(flavor = "multi_thread")]
async fn bisect4() {
    // 同 bisect3，仅捕获**无 33ms 节流**（若 thread::sleep 是元凶，本测试会成功）。
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("Skipping: no FFmpeg");
        return;
    }
    const W: u32 = 320;
    const H: u32 = 240;
    let ctx = setup_quic("b4").await;
    let endpoint_task = Arc::clone(&ctx.endpoint);
    let server_im2 = Arc::clone(&ctx.server_im);
    let server_id_task = ctx.server_id.clone();
    let client_pub_task = ctx.client_pub.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_server = Arc::clone(&stop);

    let server_handle = tokio::spawn(async move {
        let t = accept_quic_transport(
            &endpoint_task,
            &server_im2,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .unwrap();
        let encoder = VideoEncoderPipeline::new(Codec::H264, None).unwrap();
        let capture: Box<dyn ScreenCaptureSource> = Box::new(SyntheticCapture::new(W, H, false));
        run_server_session(
            Box::new(t),
            capture,
            encoder,
            SessionConfig::default(),
            None,
            None,
            stop_server,
        )
        .await
        .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let decoded = Arc::new(Mutex::new(0u32));
    let decoded_task = Arc::clone(&decoded);
    let addr = ctx.addr;
    let client_im = ctx.client_im;
    let client_id = ctx.client_id;
    let server_id = ctx.server_id;
    let server_pub = ctx.server_pub;
    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr,
            &client_im,
            &client_id,
            "b4.example",
            "desktop",
            &server_id,
            exact_pin(&server_pub),
            "challenge",
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
                    if is_key {
                        decoder.flush();
                    }
                    match decoder.decode(&DecoderPacket {
                        pts: 0,
                        data: frame.data.clone(),
                        is_key,
                        extradata: None,
                    }) {
                        Ok(_) => {
                            *decoded_task.lock().unwrap() += 1;
                        }
                        Err(e) => {
                            if !sw {
                                eprintln!("CLIENT hw decode err: {e} — sw fallback");
                                match create_video_decoder(Codec::H264) {
                                    Ok(d) => {
                                        decoder = d;
                                        sw = true;
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("CLIENT recv end: {e} (got {got})");
                    break;
                }
            }
        }
        let udp = t.conn().udp_stats();
        eprintln!(
            "CLIENT udp tx={} dg/{}B rx={} dg/{}B cwnd={}",
            udp.0,
            udp.1,
            udp.2,
            udp.3,
            t.conn().congestion_window()
        );
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

#[tokio::test(flavor = "multi_thread")]
async fn bisect5() {
    // 同 bisect3 + 客户端探针 task（每 200ms 采样 udp 统计）。
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("skip");
        return;
    }
    const W: u32 = 320;
    const H: u32 = 240;
    let ctx = setup_quic("b5").await;
    let endpoint_task = Arc::clone(&ctx.endpoint);
    let server_im2 = Arc::clone(&ctx.server_im);
    let server_id_task = ctx.server_id.clone();
    let client_pub_task = ctx.client_pub.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_server = Arc::clone(&stop);

    let server_handle = tokio::spawn(async move {
        let t = accept_quic_transport(
            &endpoint_task,
            &server_im2,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .unwrap();
        let encoder = VideoEncoderPipeline::new(Codec::H264, None).unwrap();
        let capture: Box<dyn ScreenCaptureSource> = Box::new(SyntheticCapture::new(W, H, true));
        run_server_session(
            Box::new(t),
            capture,
            encoder,
            SessionConfig::default(),
            None,
            None,
            stop_server,
        )
        .await
        .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let probe_stats = Arc::new(Mutex::new(Vec::<(Instant, u64, u64, u64, u64)>::new()));
    let decoded = Arc::new(Mutex::new(0u32));
    let decoded_task = Arc::clone(&decoded);

    let stop_client = Arc::clone(&stop);
    let addr = ctx.addr;
    let client_im = ctx.client_im;
    let client_id = ctx.client_id;
    let server_id = ctx.server_id;
    let server_pub = ctx.server_pub;
    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr,
            &client_im,
            &client_id,
            "b5.example",
            "desktop",
            &server_id,
            exact_pin(&server_pub),
            "challenge",
        )
        .await
        .unwrap();
        let _fmt = t.recv_control().await.unwrap();
        // 探针：克隆连接句柄，每 200ms 采样
        let probe_conn = t.conn().clone_quic();
        let probe_stats = Arc::clone(&probe_stats);
        let stop_p = Arc::clone(&stop_client);
        tokio::spawn(async move {
            loop {
                if stop_p.load(Ordering::Relaxed) {
                    break;
                }
                let s = probe_conn.udp_stats();
                let cwnd = probe_conn.congestion_window();
                probe_stats
                    .lock()
                    .unwrap()
                    .push((Instant::now(), s.0, s.1, s.2, s.3));
                eprintln!(
                    "PROBE t+{}ms tx={} dg rx={} dg cwnd={}",
                    probe_stats
                        .lock()
                        .unwrap()
                        .last()
                        .unwrap()
                        .0
                        .duration_since(Instant::now() - Duration::from_millis(200))
                        .as_millis(),
                    s.0,
                    s.2,
                    cwnd
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
        // 客户端接收（内联，解码器 + 回退）
        let mut decoder = create_video_decoder(Codec::H264).unwrap();
        let mut got = 0u32;
        loop {
            match t.recv_frame().await {
                Ok(frame) => {
                    got += 1;
                    let is_key = frame.flags & 0x01 != 0;
                    if is_key {
                        decoder.flush();
                    }
                    if let Err(e) = decoder.decode(&DecoderPacket {
                        pts: 0,
                        data: frame.data.clone(),
                        is_key,
                        extradata: None,
                    }) {
                        eprintln!("CLIENT decode err: {e}");
                        if let Ok(sw) = create_video_decoder(Codec::H264) {
                            decoder = sw;
                        }
                    } else {
                        *decoded_task.lock().unwrap() += 1;
                    }
                }
                Err(e) => {
                    eprintln!("CLIENT recv end: {e} (got {got})");
                    break;
                }
            }
        }
        let udp = t.conn().udp_stats();
        eprintln!("CLIENT udp tx={} dg/{}B rx={} dg/{}B", udp.0, udp.1, udp.2, udp.3);
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
}

#[tokio::test(flavor = "multi_thread")]
async fn bisect6() {
    // 完整服务端会话 + Dummy 编码器（瞬时返回假包，无 libx264）。
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("skip");
        return;
    }
    const W: u32 = 320;
    const H: u32 = 240;
    let ctx = setup_quic("b6").await;
    let endpoint_task = Arc::clone(&ctx.endpoint);
    let server_im2 = Arc::clone(&ctx.server_im);
    let server_id_task = ctx.server_id.clone();
    let client_pub_task = ctx.client_pub.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_server = Arc::clone(&stop);

    let server_handle = tokio::spawn(async move {
        let t = accept_quic_transport(
            &endpoint_task,
            &server_im2,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .unwrap();
        let encoder = VideoEncoderPipeline::from_parts(None, Box::new(DummyEncoder)).unwrap();
        let capture: Box<dyn ScreenCaptureSource> = Box::new(SyntheticCapture::new(W, H, true));
        run_server_session(
            Box::new(t),
            capture,
            encoder,
            SessionConfig::default(),
            None,
            None,
            stop_server,
        )
        .await
        .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let addr = ctx.addr;
    let client_im = ctx.client_im;
    let client_id = ctx.client_id;
    let server_id = ctx.server_id;
    let server_pub = ctx.server_pub;
    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr,
            &client_im,
            &client_id,
            "b6.example",
            "desktop",
            &server_id,
            exact_pin(&server_pub),
            "challenge",
        )
        .await
        .unwrap();
        let _fmt = t.recv_control().await.unwrap();
        let mut got = 0u32;
        loop {
            match t.recv_frame().await {
                Ok(_frame) => {
                    got += 1;
                }
                Err(e) => {
                    eprintln!("CLIENT recv end: {e} (got {got})");
                    break;
                }
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
    })
    .await
    .expect("timeout");
}

#[tokio::test(flavor = "multi_thread")]
async fn bisect7() {
    // bisect2（flow 服务端）+ 服务端控制 task（客户端不发反馈）。
    let ctx = setup_quic("b7").await;
    let endpoint_task = Arc::clone(&ctx.endpoint);
    let server_im2 = Arc::clone(&ctx.server_im);
    let server_id_task = ctx.server_id.clone();
    let client_pub_task = ctx.client_pub.clone();

    let server_handle = tokio::spawn(async move {
        let mut t = accept_quic_transport(
            &endpoint_task,
            &server_im2,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .unwrap();
        t.send_control(&ControlMessage::VideoFormat {
            width: 320,
            height: 240,
        })
        .await
        .unwrap();
        // 服务端控制 task（阻塞读——客户端不发反馈）
        let cipher = t.cipher_handle();
        let recv = t.take_control_receiver().unwrap();
        tokio::spawn(async move {
            let mut stream = recv;
            loop {
                match kirin_desk_media::transport::control::recv_control_msg(&mut stream, &cipher)
                    .await
                {
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        for i in 0..60u64 {
            t.send_window(&fake_window(i, 3)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        let udp = t.conn().udp_stats();
        eprintln!("SERVER udp tx={} dg rx={} dg", udp.0, udp.2);
        t.conn().close("done");
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let got = run_client_recv_count(&ctx, "b7.example").await;
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
    eprintln!("bisect7 got={got}");
}

#[tokio::test(flavor = "multi_thread")]
async fn bisect8() {
    // 内联复制 run_server_session 主循环（捕获+窗口+编码+锁），不调 rtt/cwnd/stats。
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("skip");
        return;
    }
    const W: u32 = 320;
    const H: u32 = 240;
    let ctx = setup_quic("b8").await;
    let endpoint_task = Arc::clone(&ctx.endpoint);
    let server_im2 = Arc::clone(&ctx.server_im);
    let server_id_task = ctx.server_id.clone();
    let client_pub_task = ctx.client_pub.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_server = Arc::clone(&stop);

    let server_handle = tokio::spawn(async move {
        let mut t = accept_quic_transport(
            &endpoint_task,
            &server_im2,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .unwrap();
        t.send_control(&ControlMessage::VideoFormat {
            width: W,
            height: H,
        })
        .await
        .unwrap();

        // 内联会话主循环（无 rtt/cwnd/stats 调用）
        let encoder = VideoEncoderPipeline::from_parts(None, Box::new(DummyEncoder)).unwrap();
        let mut capture = SyntheticCapture::new(W, H, true);
        let mut pipeline = WindowPipeline::new(WindowConfig::default(), encoder);
        let mut engine = AdaptiveEngine::new(W, H);
        let mut windows: u64 = 0;
        loop {
            if stop_server.load(Ordering::Relaxed) {
                break;
            }
            let frame = capture.wait_for_frame().unwrap();
            let raw = RawFrame {
                data: Arc::new(frame.data().to_vec()),
                width: frame.width(),
                height: frame.height(),
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
                Err(e) => {
                    eprintln!("SERVER pipeline err: {e}");
                }
            }
        }
        let udp = t.conn().udp_stats();
        eprintln!("SERVER udp tx={} dg rx={} dg windows={}", udp.0, udp.2, windows);
        t.conn().close("done");
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // 客户端仅计数（原变体：spawn 后由 60s 块设 stop 收尾）。
    let addr = ctx.addr;
    let client_im = ctx.client_im;
    let client_id = ctx.client_id;
    let server_id = ctx.server_id;
    let server_pub = ctx.server_pub;
    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr,
            &client_im,
            &client_id,
            "b8.example",
            "desktop",
            &server_id,
            exact_pin(&server_pub),
            "challenge",
        )
        .await
        .unwrap();
        let _fmt = t.recv_control().await.unwrap();
        let mut got = 0u32;
        loop {
            match t.recv_frame().await {
                Ok(_) => {
                    got += 1;
                }
                Err(e) => {
                    eprintln!("CLIENT recv end: {e} (got {got})");
                    break;
                }
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
    })
    .await
    .expect("timeout");
}

#[tokio::test(flavor = "multi_thread")]
async fn bisect9() {
    // bisect8 + 连接存活监控 task（clone 句柄采样 is_alive/path_diag）。
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("skip");
        return;
    }
    const W: u32 = 320;
    const H: u32 = 240;
    let ctx = setup_quic("b9").await;
    let endpoint_task = Arc::clone(&ctx.endpoint);
    let server_im2 = Arc::clone(&ctx.server_im);
    let server_id_task = ctx.server_id.clone();
    let client_pub_task = ctx.client_pub.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_server = Arc::clone(&stop);

    let server_handle = tokio::spawn(async move {
        let mut t = accept_quic_transport(
            &endpoint_task,
            &server_im2,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .unwrap();
        t.send_control(&ControlMessage::VideoFormat {
            width: W,
            height: H,
        })
        .await
        .unwrap();

        // 连接状态监控（clone 句柄）
        let watch = t.conn().clone_quic();
        let stop_w = Arc::clone(&stop_server);
        tokio::spawn(async move {
            let mut prev_alive = true;
            loop {
                if stop_w.load(Ordering::Relaxed) {
                    break;
                }
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

        // 内联会话主循环（无 rtt/cwnd/stats 调用）；捕获无节流（原变体）
        let encoder = VideoEncoderPipeline::from_parts(None, Box::new(DummyEncoder)).unwrap();
        let mut capture = SyntheticCapture::new(W, H, false);
        let mut pipeline = WindowPipeline::new(WindowConfig::default(), encoder);
        let mut engine = AdaptiveEngine::new(W, H);
        let mut windows: u64 = 0;
        loop {
            if stop_server.load(Ordering::Relaxed) {
                break;
            }
            let frame = capture.wait_for_frame().unwrap();
            let raw = RawFrame {
                data: Arc::new(frame.data().to_vec()),
                width: frame.width(),
                height: frame.height(),
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
                Err(e) => {
                    eprintln!("SERVER pipeline err: {e}");
                }
            }
        }
        let udp = t.conn().udp_stats();
        eprintln!("SERVER udp tx={} dg rx={} dg windows={}", udp.0, udp.2, windows);
        t.conn().close("done");
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // 客户端仅计数（原变体：spawn 后由 60s 块设 stop 收尾）。
    let addr = ctx.addr;
    let client_im = ctx.client_im;
    let client_id = ctx.client_id;
    let server_id = ctx.server_id;
    let server_pub = ctx.server_pub;
    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr,
            &client_im,
            &client_id,
            "b9.example",
            "desktop",
            &server_id,
            exact_pin(&server_pub),
            "challenge",
        )
        .await
        .unwrap();
        let _fmt = t.recv_control().await.unwrap();
        let mut got = 0u32;
        loop {
            match t.recv_frame().await {
                Ok(_) => {
                    got += 1;
                }
                Err(e) => {
                    eprintln!("CLIENT recv end: {e} (got {got})");
                    break;
                }
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
    })
    .await
    .expect("timeout");
}

#[tokio::test(flavor = "multi_thread")]
async fn bisect10() {
    // bisect7 紧循环：2000 窗口无 sleep（若冻结 → 发送速率/模式是触发点）。
    let ctx = setup_quic("b10").await;
    let endpoint_task = Arc::clone(&ctx.endpoint);
    let server_im2 = Arc::clone(&ctx.server_im);
    let server_id_task = ctx.server_id.clone();
    let client_pub_task = ctx.client_pub.clone();

    let server_handle = tokio::spawn(async move {
        let mut t = accept_quic_transport(
            &endpoint_task,
            &server_im2,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .unwrap();
        t.send_control(&ControlMessage::VideoFormat {
            width: 320,
            height: 240,
        })
        .await
        .unwrap();
        // 服务端控制 task（阻塞读——客户端不发反馈）
        let cipher = t.cipher_handle();
        let recv = t.take_control_receiver().unwrap();
        tokio::spawn(async move {
            let mut stream = recv;
            loop {
                match kirin_desk_media::transport::control::recv_control_msg(&mut stream, &cipher)
                    .await
                {
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        // 紧循环：无 sleep（若冻结 → 发送速率/模式是触发点，与 pipeline 无关）
        for i in 0..2000u64 {
            t.send_window(&fake_window(i, 3)).await.unwrap();
            if i % 100 == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        let udp = t.conn().udp_stats();
        eprintln!("SERVER udp tx={} dg rx={} dg", udp.0, udp.2);
        t.conn().close("done");
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let got = run_client_recv_count(&ctx, "b10.example").await;
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
    eprintln!("bisect10 got={got}");
}
