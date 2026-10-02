//! IPv4 端到端集成测试（M8-T025_P3）：服务端双栈 `bind(0)` → 客户端按族拨号
//! `127.0.0.1` → 白名单握手 → EncodedWindow DATAGRAM 传输 + 控制流往返。
//!
//! 回归基线说明：现有 `quic_*` 测试全走 `[::1]`（v6 路径），本测试是第一条
//! v4 路径覆盖；`[::1]` 既有路径由 `quic_transport_flow.rs` 等继续回归。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
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
async fn ipv4_loopback_end_to_end() {
    let tmp = std::env::temp_dir();
    let server_id = "v4-server".to_string();
    let client_id = "v4-client".to_string();
    let server_im = IdentityManager::generate(tmp.join("kirin_v4_s.key")).unwrap();
    let client_im = IdentityManager::generate(tmp.join("kirin_v4_c.key")).unwrap();
    let server_pub = server_im.public_key_base64();
    let client_pub = client_im.public_key_base64();

    let (cert, key) = generate_quic_cert(&server_id).unwrap();
    let endpoint = Arc::new(QuicEndpoint::bind(0, cert, key).await.unwrap());
    let port = endpoint.local_addr().unwrap().port();
    // ★ v4 拨号目标（本任务核心路径）
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();

    let endpoint_task = Arc::clone(&endpoint);
    let server_im_task = Arc::new(server_im);
    let server_id_task = server_id.clone();
    let server_handle = tokio::spawn(async move {
        let mut t = accept_quic_transport(
            &endpoint_task, &server_im_task, &server_id_task, &client_pub, None, None,
        )
        .await
        .unwrap();
        // 控制流：分辨率推送
        t.send_control(&ControlMessage::VideoFormat { width: 320, height: 240 })
            .await
            .unwrap();
        // 控制流往返：收客户端反馈
        let fb = Arc::new(AtomicU64::new(0));
        let cipher = t.cipher_handle();
        let recv = t.take_control_receiver().unwrap();
        let fb2 = Arc::clone(&fb);
        tokio::spawn(async move {
            let mut stream = recv;
            let mut count = 0u64;
            loop {
                match kirin_desk_media::transport::control::recv_control_msg(
                    &mut stream,
                    &cipher,
                )
                .await
                {
                    Ok(ControlMessage::FeedbackReport { .. }) => count += 1,
                    Ok(_) => {}
                    Err(_) => break,
                }
                fb2.store(count, Ordering::Relaxed);
            }
        });
        // 媒体流：发 3 个 EncodedWindow（假数据）
        for i in 0..3u64 {
            t.send_window(&fake_window(i, 2)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await; // 等反馈
        let feedback = fb.load(Ordering::Relaxed);
        eprintln!("SERVER v4 feedback={feedback}");
        t.conn().close("done");
        assert!(feedback >= 1, "expected >=1 feedback over v4, got {feedback}");
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr, &client_im, &client_id, "v4.example", "desktop", &server_id, kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&server_pub).expect("server pubkey"),
            "challenge",
        )
        .await
        .unwrap();
        // 收 VideoFormat（控制流）
        let fmt = t.recv_control().await.unwrap();
        eprintln!("CLIENT v4 got format: {fmt:?}");
        // 发一条反馈
        let sender = t.take_control_sender().unwrap();
        let cipher = t.cipher_handle();
        tokio::spawn(async move {
            let mut stream = sender;
            let msg = ControlMessage::FeedbackReport {
                loss_rate: 0.0,
                rtt_ms: 1,
                received_bitrate: 1_000_000,
                frame_id: 1,
                missing_frames: vec![],
            };
            let _ =
                kirin_desk_media::transport::control::send_control_msg(&mut stream, &cipher, &msg)
                    .await;
        });
        // 媒体接收：recv_frame 计数
        let mut got = 0u64;
        loop {
            match t.recv_frame().await {
                Ok(_) => got += 1,
                Err(e) => {
                    eprintln!("CLIENT v4 recv end: {e} (got {got} frames)");
                    break;
                }
            }
        }
        assert!(got >= 1, "client should receive >=1 window over v4 (got {got})");
        t.conn().close("done");
    });

    let _ = tokio::time::timeout(Duration::from_secs(30), client_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(10), server_handle).await;
}
