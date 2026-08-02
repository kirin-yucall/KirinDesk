//! 二分定位 7：bisect2（flow 服务端，工作）+ 服务端控制 task（客户端不发反馈）。
//! 失败 → 控制 task 触发冻结。

use std::net::SocketAddr;
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
        for _ in 0..64 { packet.extend_from_slice(&nal); }
        f.push(vec![packet]);
    }
    EncodedWindow::new(id, 320, 240, f)
}

#[tokio::test(flavor = "multi_thread")]
async fn bisect7() {
    let tmp = std::env::temp_dir();
    let server_id = "b7-server".to_string();
    let client_id = "b7-client".to_string();
    let server_im = IdentityManager::generate(tmp.join("kirin_b7_s.key")).unwrap();
    let client_im = IdentityManager::generate(tmp.join("kirin_b7_c.key")).unwrap();
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
        ).await.unwrap();
        t.send_control(&ControlMessage::VideoFormat { width: 320, height: 240 }).await.unwrap();
        // 服务端控制 task（阻塞读——客户端不发反馈）
        let cipher = t.cipher_handle();
        let recv = t.take_control_receiver().unwrap();
        tokio::spawn(async move {
            let mut stream = recv;
            loop {
                match kirin_desk_media::transport::control::recv_control_msg(&mut stream, &cipher).await {
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

    let client_handle = tokio::spawn(async move {
        let mut t = connect_quic_transport(
            addr, &client_im, &client_id, "b7.example", "desktop", &server_id, &server_pub, "challenge",
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

    tokio::time::timeout(Duration::from_secs(30), client_handle).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
}
