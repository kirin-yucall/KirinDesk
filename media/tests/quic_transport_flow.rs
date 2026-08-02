//! 纯传输层流测试：accept/connect 传输 → VideoFormat → 连续 send_window（假数据）
//! → recv_frame 计数 + 控制流反馈。隔离「编码/解码」之外的传输路径冻结问题。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_media::proto::EncodedWindow;
use kirin_desk_media::transport::{
    accept_quic_transport, connect_quic_transport, generate_quic_cert, ControlMessage,
    MediaTransport, QuicEndpoint,
};

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

#[tokio::test(flavor = "multi_thread")]
async fn transport_window_flow() {
    let tmp = std::env::temp_dir();
    let server_id = "flow-server".to_string();
    let client_id = "flow-client".to_string();
    let server_im = IdentityManager::generate(tmp.join("kirin_flow_s.key")).unwrap();
    let client_im = IdentityManager::generate(tmp.join("kirin_flow_c.key")).unwrap();
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
    let server_handle = tokio::spawn(async move {
        let mut t = accept_quic_transport(
            &endpoint_task, &server_im2, &server_id_task, &client_pub, None, None,
        )
        .await
        .unwrap();
        // 分辨率推送
        t.send_control(&ControlMessage::VideoFormat { width: 320, height: 240 })
            .await
            .unwrap();
        // 服务端控制接收 task（模拟会话控制任务）
        let cipher = t.cipher_handle();
        let recv = t.take_control_receiver().unwrap();
        let fb = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let fb2 = Arc::clone(&fb);
        tokio::spawn(async move {
            let mut stream = recv;
            let mut count = 0u64;
            loop {
                match kirin_desk_media::transport::control::recv_control_msg(&mut stream, &cipher).await {
                    Ok(ControlMessage::FeedbackReport { .. }) => count += 1,
                    Ok(_) => {}
                    Err(_) => break,
                }
                fb2.store(count, Ordering::Relaxed);
            }
        });
        // 主循环：每 50ms 发一个窗口（3 帧）
        for i in 0..40u64 {
            t.send_window(&fake_window(i, 3)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let udp = t.conn().udp_stats();
        eprintln!("SERVER udp tx={} dg/{}B rx={} dg/{}B cwnd={} feedback={}",
            udp.0, udp.1, udp.2, udp.3, t.conn().congestion_window(), fb.load(Ordering::Relaxed));
        t.conn().close("done");
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr, &client_im, &client_id, "flow.example", "desktop", &server_id, &server_pub, "challenge",
        )
        .await
        .unwrap();
        // 收 VideoFormat
        let fmt = t.recv_control().await.unwrap();
        eprintln!("CLIENT got: {fmt:?}");
        // 客户端反馈 task（每 100ms 一次）
        let sender = t.take_control_sender().unwrap();
        let cipher = t.cipher_handle();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        tokio::spawn(async move {
            let mut stream = sender;
            let mut seq = 0u64;
            loop {
                if stop2.load(Ordering::Relaxed) { break; }
                tokio::time::sleep(Duration::from_millis(100)).await;
                seq += 1;
                let msg = ControlMessage::FeedbackReport {
                    loss_rate: 0.0, rtt_ms: 1, received_bitrate: 1_000_000,
                    frame_id: seq, missing_frames: vec![],
                };
                if kirin_desk_media::transport::control::send_control_msg(&mut stream, &cipher, &msg).await.is_err() {
                    break;
                }
            }
        });
        // 接收循环
        let mut got = 0u64;
        let mut got_frames = 0u64;
        loop {
            match t.recv_frame().await {
                Ok(f) => { got += 1; got_frames += 1; }
                Err(e) => { eprintln!("CLIENT recv end: {e} (got {got} frames)"); break; }
            }
        }
        stop.store(true, Ordering::Relaxed);
        let udp = t.conn().udp_stats();
        eprintln!("CLIENT udp tx={} dg/{}B rx={} dg/{}B cwnd={} frames={}",
            udp.0, udp.1, udp.2, udp.3, t.conn().congestion_window(), got);
        assert!(got_frames > 20, "client should receive most windows (got {got_frames})");
        t.conn().close("done");
    });

    let _ = tokio::time::timeout(Duration::from_secs(30), client_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
}
