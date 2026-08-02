//! M8-T025 P4 端到端 TCP 媒体闭环集成测试（tcp_fallback_loopback.rs）。
//!
//! 纯 TCP 端到端（无 QUIC）：服务端 accept → 握手 → `TcpMediaTransport`；
//! 客户端 connect → 握手 → 构造。服务端发 3 个窗口（含超 `MAX_PACKET_PAYLOAD`
//! 大帧走 send_big_packet 路径）→ 客户端 `recv_frame` 计数 = 预期帧数；
//! control 双向各 1 条；双侧 `mode() == Tcp`（P5 会话层消费契约）。
//!
//! 依赖仅 tokio TCP 回环，无 FFmpeg DLL / 无 quinn。

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake as core_handshake;
use kirin_desk_core::crypto::handshake::SecureChannel;
use kirin_desk_media::proto::EncodedWindow;
use kirin_desk_media::transport::{
    ControlMessage, MediaTransport, TcpMediaTransport, TransportMode, MAX_PACKET_PAYLOAD,
};
use tokio::net::TcpListener;

/// 构造一个窗口：每帧单个 NAL 包。
fn make_window(window_id: u64, frame_data: Vec<Vec<u8>>) -> EncodedWindow {
    EncodedWindow::new(
        window_id,
        320,
        240,
        frame_data.into_iter().map(|f| vec![f]).collect(),
    )
}

/// 服务端流程：accept → 握手 → 发 3 个窗口 + 1 条控制 → 收客户端控制。
async fn run_server(
    listener: TcpListener,
    server_im: &IdentityManager,
    server_id: &str,
    client_pub: &str,
) -> ControlMessage {
    let (stream, _) = listener.accept().await.expect("accept");
    let g = core_handshake::server_handshake_verified_generic(stream, server_im, server_id, client_pub)
        .await
        .expect("server handshake");
    let channel = SecureChannel {
        stream: g.stream,
        cipher: g.cipher,
        peer_id: g.peer_id,
        peer_domain: g.peer_domain,
        peer_device_type: g.peer_device_type,
        selected_codec: g.selected_codec,
    };
    let mut transport = TcpMediaTransport::new(channel);
    assert_eq!(transport.mode(), TransportMode::Tcp);

    // 3 个窗口（window2 首帧超 DATAGRAM 负载上限 → send_big_packet 路径）。
    transport
        .send_window(&make_window(0, vec![vec![0xA1; 64], vec![0xA2; 128]]))
        .await
        .expect("send window 0");
    transport
        .send_window(&make_window(1, vec![vec![0xB1; 96], vec![0xB2; 160], vec![0xB3; 200]]))
        .await
        .expect("send window 1");
    transport
        .send_window(&make_window(
            2,
            vec![vec![0xC1; MAX_PACKET_PAYLOAD + 500]],
        ))
        .await
        .expect("send window 2 (big frame)");

    // 控制：服务端 → 客户端 1 条（分辨率推送）。
    transport
        .send_control(&ControlMessage::VideoFormat {
            width: 320,
            height: 240,
        })
        .await
        .expect("send control");

    // 收客户端控制（Heartbeat）。
    transport.recv_control().await.expect("recv client control")
}

/// 客户端流程：connect → 握手 → 收 6 帧 + 1 条控制 → 回 1 条控制。
async fn run_client(
    addr: std::net::SocketAddr,
    client_im: &IdentityManager,
    client_id: &str,
    server_id: &str,
    server_pub: &str,
    expected_frames: &[Vec<u8>],
    expected_key_indices: &[usize],
) -> ControlMessage {
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let ch = core_handshake::client_handshake_generic(
        stream,
        client_im,
        client_id,
        "loopback.example",
        "tester",
        server_id,
        server_pub,
        "challenge",
    )
    .await
    .expect("client handshake");
    let channel = SecureChannel {
        stream: ch.stream,
        cipher: ch.cipher,
        peer_id: ch.peer_id,
        peer_domain: ch.peer_domain,
        peer_device_type: ch.peer_device_type,
        selected_codec: ch.selected_codec,
    };
    let mut transport = TcpMediaTransport::new(channel);
    assert_eq!(transport.mode(), TransportMode::Tcp);

    // 媒体：recv_frame 计数 = 预期帧数，数据逐帧一致，窗口首帧 is_key。
    for (idx, expected) in expected_frames.iter().enumerate() {
        let frame = transport.recv_frame().await.expect("recv frame");
        assert_eq!(&frame.data, expected, "frame {idx} payload mismatch");
        assert_eq!(
            frame.frame_id as usize, idx,
            "frame_id must be monotonic frame ordinal"
        );
        let is_key = frame.flags & 1 != 0;
        assert_eq!(
            is_key,
            expected_key_indices.contains(&idx),
            "frame {idx} key flag mismatch"
        );
    }

    // 控制：收服务端 VideoFormat。
    let got = transport.recv_control().await.expect("recv server control");
    assert_eq!(
        got,
        ControlMessage::VideoFormat {
            width: 320,
            height: 240
        }
    );

    // 控制：客户端 → 服务端 1 条（Heartbeat）。
    let heartbeat = ControlMessage::Heartbeat { timestamp_ms: 42 };
    transport
        .send_control(&heartbeat)
        .await
        .expect("send client control");
    heartbeat
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_fallback_loopback_end_to_end() {
    // ── 身份（临时目录，不落盘） ────────────────────────────────
    let tmp = std::env::temp_dir();
    let server_id = "tcp-loopback-server".to_string();
    let client_id = "tcp-loopback-client".to_string();
    let server_im =
        IdentityManager::generate(tmp.join("kirin_tcp_loop_s.key")).expect("server identity");
    let client_im =
        IdentityManager::generate(tmp.join("kirin_tcp_loop_c.key")).expect("client identity");
    let server_pub = server_im.public_key_base64();
    let client_pub = client_im.public_key_base64();

    // ── 服务端监听（临时端口） ──────────────────────────────────
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    // 预期媒体帧（与服务端窗口一一对应，共 6 帧）。
    let expected_frames: Vec<Vec<u8>> = vec![
        vec![0xA1; 64],
        vec![0xA2; 128],
        vec![0xB1; 96],
        vec![0xB2; 160],
        vec![0xB3; 200],
        vec![0xC1; MAX_PACKET_PAYLOAD + 500],
    ];
    // 每窗口首帧 is_key（帧序号 0 / 2 / 5）。
    let expected_key_indices = [0usize, 2, 5];

    let server_im_ref = server_im;
    let server_id_ref = server_id.clone();
    let client_pub_ref = client_pub;
    let server_handle = tokio::spawn(async move {
        run_server(
            listener,
            &server_im_ref,
            &server_id_ref,
            &client_pub_ref,
        )
        .await
    });

    // ── 客户端（主任务） ────────────────────────────────────────
    let server_msg = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        run_client(
            addr,
            &client_im,
            &client_id,
            &server_id,
            &server_pub,
            &expected_frames,
            &expected_key_indices,
        ),
    )
    .await
    .expect("client timeout");

    // ── 服务端收到客户端 Heartbeat ──────────────────────────────
    let got = tokio::time::timeout(std::time::Duration::from_secs(10), server_handle)
        .await
        .expect("server timeout")
        .expect("server task join");
    assert_eq!(got, server_msg, "control roundtrip mismatch");
    assert_eq!(got, ControlMessage::Heartbeat { timestamp_ms: 42 });
}
