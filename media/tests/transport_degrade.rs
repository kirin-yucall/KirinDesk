//! M8-T025 P5-5：会话降级全链路集成测试（transport_degrade.rs）。
//!
//! 覆盖（P5-5 测试表）：
//! - `degrade_connect_fallback`：QUIC 端口不可达 → `connect_media_transport(Quic, fallback)`
//!   自动回退 TCP，`mode() == Tcp`
//! - `degrade_mid_session`：真实 QUIC 会话 → 服务端关闭 QUIC 连接（模拟 UDP 封锁）
//!   → 客户端检测失效 → TCP 重建续传 → 帧数不归零、`transport_switches == 1`、模式 TCP
//! - `degrade_no_upgrade`：降级完成后继续运行，断言不自动升级回 QUIC（B3）
//! - `accept_dual_listen`：服务端双监听（UDP + TCP 先到者胜）：QUIC 先到 → QUIC 胜；
//!   TCP 先到 → TCP 胜
//! - `mode_forced_tcp`：`mode=tcp` 直接 TCP，不尝试 QUIC
//!
//! 依赖 FFmpeg DLL（H.264 编解码），环境无 DLL 时自动跳过。

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake as core_handshake;
use kirin_desk_core::network::tcp::TcpClient;
use kirin_desk_media::capture::{CaptureError, CaptureFrame, MonitorInfo, ScreenCaptureSource};
use kirin_desk_media::encoder::types::Codec;
use kirin_desk_media::encoder::VideoEncoderPipeline;
use kirin_desk_media::session::{
    run_client_session, run_server_session, ClientDegrade, ClientSessionStats, ServerDegrade,
    ServerSessionStats, SessionConfig,
};
use kirin_desk_media::transport::{
    accept_media_transport, accept_quic_transport, bind_dual_stack_tcp_listener,
    connect_media_transport, connect_quic_transport, generate_quic_cert, ControlMessage,
    QuicEndpoint, TcpMediaTransport, TransportMode,
};

// ════════════════════════════════════════════════════════════════
// 基建
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

/// 测试身份组（临时目录 key 路径，不落盘）。
#[derive(Clone)]
struct TestIds {
    server_id: String,
    client_id: String,
    server_im: Arc<IdentityManager>,
    client_im: Arc<IdentityManager>,
    server_pub: String,
    client_pub: String,
}

fn make_identities(tag: &str) -> TestIds {
    let tmp = std::env::temp_dir();
    let server_id = format!("dg-server-{tag}");
    let client_id = format!("dg-client-{tag}");
    let server_im = Arc::new(
        IdentityManager::generate(tmp.join(format!("kirin_dg_s_{tag}.key"))).expect("server id"),
    );
    let client_im = Arc::new(
        IdentityManager::generate(tmp.join(format!("kirin_dg_c_{tag}.key"))).expect("client id"),
    );
    let server_pub = server_im.public_key_base64();
    let client_pub = client_im.public_key_base64();
    TestIds {
        server_id,
        client_id,
        server_im,
        client_im,
        server_pub,
        client_pub,
    }
}

/// 带超时轮询等待条件成立（集成测试节奏控制）。
async fn wait_until(what: &str, timeout: Duration, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timeout ({timeout:?}) waiting for {what}");
}

/// 初始化 tracing（首个测试生效，其余 try_init 幂等忽略）。
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
}

// ════════════════════════════════════════════════════════════════
// 1) degrade_connect_fallback：QUIC 端口不可达 → 自动回退 TCP
// ════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
async fn degrade_connect_fallback() {
    init_tracing();
    let ids = make_identities("fallback");

    // UDP（QUIC）与 TCP 同端口：TCP 监听存活，QUIC 端点绑定后立即关闭
    // （模拟防火墙丢 UDP / QUIC 端口不可达）。
    let tcp_listener = Arc::new(bind_dual_stack_tcp_listener(0).expect("tcp bind"));
    let port = tcp_listener.local_addr().expect("tcp addr").port();
    let (cert, key) = generate_quic_cert(&ids.server_id).expect("quic cert");
    let quic_endpoint = QuicEndpoint::bind(port, cert, key).await.expect("quic bind");
    let addr: SocketAddr = (Ipv6Addr::LOCALHOST, port).into();
    drop(quic_endpoint); // UDP 端口关闭 → QUIC 拨号必然失败

    // 服务端：TCP 手动 accept + 完整握手，保持连接 3s（客户端完成回退断言与
    // 一次控制收发；期间连接存活）。
    let server_im = Arc::clone(&ids.server_im);
    let server_id = ids.server_id.clone();
    let client_pub = ids.client_pub.clone();
    let server_handle = tokio::spawn(async move {
        let (stream, _) = tcp_listener.accept().await.expect("accept");
        let ch = core_handshake::server_handshake_verified_with_nickname_generic(
            stream,
            &server_im,
            &server_id,
            &client_pub,
            None,
            None,
        )
        .await
        .expect("server handshake");
        let t = TcpMediaTransport::from_generic(ch);
        // 保持连接 3s：期间客户端完成「回退后控制收发」验证
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(t);
        Ok::<(), String>(())
    });

    // mode=Quic + fallback：QUIC 失败/超时 → 自动回退 TCP
    let transport = connect_media_transport(
        addr,
        TransportMode::Quic,
        true,
        &ids.client_im,
        &ids.client_id,
        "fallback.example",
        "desktop",
        &ids.server_id,
        kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&ids.server_pub).expect("server pubkey"),
        "challenge",
        Duration::from_secs(1),
    )
    .await
    .expect("fallback connect");

    assert_eq!(
        transport.mode(),
        TransportMode::Tcp,
        "QUIC 不可达时必须回退到 TCP"
    );

    // 回退后的传输可实际收发（TCP 媒体通路）
    let mut client = transport;
    client
        .send_control(&ControlMessage::Heartbeat { timestamp_ms: 1 })
        .await
        .expect("send control over TCP fallback");

    server_handle.await.expect("server join").expect("server ok");
}

// ════════════════════════════════════════════════════════════════
// 2) degrade_mid_session：QUIC 中途失效 → TCP 重建续传
// 3) degrade_no_upgrade：降级后不自动升级回 QUIC（B3）
// ════════════════════════════════════════════════════════════════

/// 完整降级场景（degrade_mid_session / degrade_no_upgrade 共用）：
/// QUIC 会话建立 → 帧流出 → 服务端关闭 QUIC 连接（模拟 UDP 封锁）→
/// 客户端检测失效 → TCP 重建续传 → 会话结束。
async fn run_degrade_scenario(tag: &str, hold_after_resume: Duration) {
    init_tracing();
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("Skipping: no FFmpeg DLLs available");
        return;
    }

    const W: u32 = 320;
    const H: u32 = 240;

    let ids = make_identities(tag);

    // 同一端口双监听：UDP（QUIC）+ TCP（降级回退）。
    let (cert, key) = generate_quic_cert(&ids.server_id).expect("cert");
    let endpoint = Arc::new(QuicEndpoint::bind(0, cert, key).await.expect("quic bind"));
    let port = endpoint.local_addr().expect("local addr").port();
    let tcp_listener = Arc::new(bind_dual_stack_tcp_listener(port).expect("tcp bind"));
    let addr: SocketAddr = (Ipv6Addr::LOCALHOST, port).into();

    // ── 初始 QUIC 连接（测试持有服务端连接句柄，用于模拟 UDP 封锁）──
    let accept_task = {
        let endpoint = Arc::clone(&endpoint);
        let ids = ids.clone();
        tokio::spawn(async move {
            accept_quic_transport(
                &endpoint,
                &ids.server_im,
                &ids.server_id,
                &ids.client_pub,
                None,
                None,
            )
            .await
            .expect("accept + handshake")
        })
    };
    let client_transport = connect_quic_transport(
        addr,
        &ids.client_im,
        &ids.client_id,
        "degrade.example",
        "desktop",
        &ids.server_id,
        kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&ids.server_pub).expect("server pubkey"),
        "challenge",
    )
    .await
    .expect("connect + handshake");
    let server_transport = accept_task.await.expect("accept join");
    // 杀连接句柄：关闭服务端 QUIC 连接 = 模拟 UDP 封锁（确定性快）。
    let quic_kill = server_transport.conn().clone_quic();

    // ── 会话任务 ──────────────────────────────────────────────────
    let decoded = Arc::new(Mutex::new(0u64));
    let stop = Arc::new(AtomicBool::new(false));

    let stop_server = Arc::clone(&stop);
    // 预克隆（async move 闭包会整体捕获 ids）
    let srv_tcp = Arc::clone(&tcp_listener);
    let srv_im = Arc::clone(&ids.server_im);
    let srv_id = ids.server_id.clone();
    let srv_client_pub = ids.client_pub.clone();
    let server_handle = tokio::spawn(async move {
        let encoder = VideoEncoderPipeline::new(Codec::H264, None).expect("encoder");
        let capture: Box<dyn ScreenCaptureSource> = Box::new(SyntheticCapture::new(W, H));
        run_server_session(
            Box::new(server_transport),
            capture,
            encoder,
            SessionConfig::default(),
            Some(ServerDegrade {
                tcp_listener: srv_tcp,
                server_identity: srv_im,
                server_id: srv_id,
                client_pubkey_base64: srv_client_pub,
                expected_nickname: None,
                expected_challenge: None,
            }),
            None, // M8-T026-P1：不启用打洞升舱
            stop_server,
        )
        .await
        .expect("server session")
    });

    let decoded_client = Arc::clone(&decoded);
    let stop_client = Arc::clone(&stop);
    let cli_im = Arc::clone(&ids.client_im);
    let cli_id = ids.client_id.clone();
    let cli_srv_id = ids.server_id.clone();
    let cli_srv_pub = ids.server_pub.clone();
    let client_handle = tokio::spawn(async move {
        let on_frame = move |w: u32, h: u32, rgba: &[u8]| {
            if w * h * 4 == rgba.len() as u32 {
                *decoded_client.lock().unwrap() += 1;
            }
        };
        run_client_session(
            Box::new(client_transport),
            on_frame,
            SessionConfig::default(),
            Some(ClientDegrade {
                addr,
                client_identity: cli_im,
                client_id: cli_id,
                client_domain: "degrade.example".to_string(),
                client_device_type: "desktop".to_string(),
                server_id: cli_srv_id,
                server_pin: kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&cli_srv_pub).expect("server pubkey"),
                challenge: "challenge".to_string(),
                connect_timeout: Duration::from_secs(3),
            }),
            None, // M8-T026-P1：不启用打洞升舱
            stop_client,
        )
        .await
        .expect("client session")
    });

    // ── 1) QUIC 主路径帧流出 ─────────────────────────────────────
    wait_until("QUIC 主路径帧流出", Duration::from_secs(20), || {
        *decoded.lock().unwrap() >= 5
    })
    .await;
    let frames_before = *decoded.lock().unwrap();

    // ── 2) 服务端关闭 QUIC 连接（模拟 UDP 封锁）──────────────────
    quic_kill.close("simulate UDP block");

    // ── 3) 客户端检测失效 → TCP 重建续传 → 帧恢复增长 ────────────
    wait_until("TCP 降级续传帧恢复", Duration::from_secs(20), || {
        *decoded.lock().unwrap() > frames_before + 5
    })
    .await;
    let frames_after = *decoded.lock().unwrap();

    // ── 4) B3：不自动升级回 QUIC（保持运行观察窗口）──────────────
    if !hold_after_resume.is_zero() {
        tokio::time::sleep(hold_after_resume).await;
    }

    // ── 5) 结束并校验 ────────────────────────────────────────────
    stop.store(true, Ordering::Relaxed);
    // R-28：join 带超时断言——会话任一侧异常卡死时明确失败而非挂起
    // （审计 §4-1：degrade_mid_session/degrade_no_upgrade 死等 >60s 复现；
    // 根因已修：`bind_dual_stack_tcp_listener` v6 路径漏 set_nonblocking，
    // 阻塞 accept 占住 tokio worker → runtime drop 无限等待）。
    let client_stats: ClientSessionStats =
        tokio::time::timeout(Duration::from_secs(15), client_handle)
            .await
            .expect("client session join timed out")
            .expect("client join");
    let server_stats: ServerSessionStats =
        tokio::time::timeout(Duration::from_secs(15), server_handle)
            .await
            .expect("server session join timed out")
            .expect("server join");

    assert!(
        frames_before >= 5,
        "QUIC 主路径应先流出帧（got {frames_before}）"
    );
    assert!(
        frames_after > frames_before + 5,
        "降级后帧数必须继续增长（before={frames_before}, after={frames_after}）"
    );
    // 会话不中断、帧计数不归零（B2 验收）
    assert_eq!(client_stats.transport_switches, 1, "客户端恰一次 QUIC→TCP 切换");
    assert_eq!(server_stats.transport_switches, 1, "服务端恰一次 QUIC→TCP 切换");
    assert_eq!(client_stats.transport_mode, "TCP", "客户端会话结束于 TCP 模式");
    assert_eq!(server_stats.transport_mode, "TCP", "服务端会话结束于 TCP 模式");
    assert!(
        client_stats.frames_decoded >= frames_after,
        "解码计数不归零（stats={}, 观测={frames_after}）",
        client_stats.frames_decoded
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn degrade_mid_session() {
    run_degrade_scenario("mid", Duration::ZERO).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn degrade_no_upgrade() {
    // 降级完成后继续运行 3s：若存在自动升级回 QUIC，transport_switches 会 >1。
    run_degrade_scenario("no_upgrade", Duration::from_secs(3)).await;
}

// ════════════════════════════════════════════════════════════════
// 4) accept_dual_listen：服务端双监听先到者胜
// ════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
async fn accept_dual_listen() {
    init_tracing();
    let ids = make_identities("dual");

    // 案例 A：QUIC 客户端先到 → QUIC 分支胜
    {
        let (cert, key) = generate_quic_cert(&ids.server_id).expect("cert");
        let endpoint = Arc::new(QuicEndpoint::bind(0, cert, key).await.expect("quic bind"));
        let port = endpoint.local_addr().expect("addr").port();
        let tcp_listener = bind_dual_stack_tcp_listener(port).expect("tcp bind");
        let addr: SocketAddr = (Ipv6Addr::LOCALHOST, port).into();

        let accept_handle = {
            let endpoint = Arc::clone(&endpoint);
            let ids = ids.clone();
            tokio::spawn(async move {
                accept_media_transport(
                    &endpoint,
                    &tcp_listener,
                    &ids.server_im,
                    &ids.server_id,
                    &ids.client_pub,
                    None,
                    None,
                )
                .await
                .expect("dual accept")
            })
        };
        // 仅 QUIC 客户端连接。注：客户端 connect_quic_transport 内的
        // accept_bi（控制流）依赖服务端**写入**控制流才解析——M8-T026-P1
        // 起服务端 open_bi 后写 1 字节就绪标记（CONTROL_STREAM_READY，
        // transport.rs）强制 STREAM 帧发出，connect 端同步消费；本测试
        // 服务端 accept 返回后仍先发 VideoFormat 再 join（与既有流程一致）。
        let client_handle = {
            let ids = ids.clone();
            tokio::spawn(async move {
                connect_quic_transport(
                    addr,
                    &ids.client_im,
                    &ids.client_id,
                    "dual.example",
                    "desktop",
                    &ids.server_id,
                    kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&ids.server_pub).expect("server pubkey"),
                    "challenge",
                )
                .await
                .expect("quic connect")
            })
        };
        let mut server_transport = accept_handle.await.expect("accept join");
        assert_eq!(
            server_transport.mode(),
            TransportMode::Quic,
            "QUIC 先到 → QUIC 分支胜"
        );
        // 触发控制流（与真实会话的服务端首包 VideoFormat 行为一致）
        server_transport
            .send_control(&ControlMessage::VideoFormat {
                width: 320,
                height: 240,
            })
            .await
            .expect("server control write");
        let client_transport = client_handle.await.expect("client join");
        drop(client_transport);
    }

    // 案例 B：TCP 客户端先到 → TCP 分支胜（QUIC 分支 2s 超时自动让位）
    {
        let (cert, key) = generate_quic_cert(&ids.server_id).expect("cert");
        let endpoint = Arc::new(QuicEndpoint::bind(0, cert, key).await.expect("quic bind"));
        let port = endpoint.local_addr().expect("addr").port();
        let tcp_listener = bind_dual_stack_tcp_listener(port).expect("tcp bind");
        let addr: SocketAddr = (Ipv6Addr::LOCALHOST, port).into();

        let accept_handle = {
            let endpoint = Arc::clone(&endpoint);
            let ids = ids.clone();
            tokio::spawn(async move {
                accept_media_transport(
                    &endpoint,
                    &tcp_listener,
                    &ids.server_im,
                    &ids.server_id,
                    &ids.client_pub,
                    None,
                    None,
                )
                .await
                .expect("dual accept")
            })
        };
        // 仅 TCP 客户端连接（完整握手）
        let stream = TcpClient::connect(addr).await.expect("tcp connect");
        let client_handshake = tokio::spawn({
            let ids = ids.clone();
            async move {
                core_handshake::client_handshake_generic(
                    stream,
                    &ids.client_im,
                    &ids.client_id,
                    "dual.example",
                    "desktop",
                    &ids.server_id,
                    kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&ids.server_pub).expect("server pubkey"),
                    "challenge",
                )
                .await
                .expect("client handshake")
            }
        });
        let server_transport = accept_handle.await.expect("accept join");
        assert_eq!(
            server_transport.mode(),
            TransportMode::Tcp,
            "TCP 先到 → TCP 分支胜"
        );
        client_handshake.await.expect("client handshake join");
    }
}

// ════════════════════════════════════════════════════════════════
// 5) mode_forced_tcp：强制 TCP，不尝试 QUIC
// ════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
async fn mode_forced_tcp() {
    init_tracing();
    let ids = make_identities("forced");

    // 无 QUIC 端点（若客户端尝试 QUIC 拨号将失败/挂起）；仅 TCP 监听。
    let tcp_listener = Arc::new(bind_dual_stack_tcp_listener(0).expect("tcp bind"));
    let port = tcp_listener.local_addr().expect("addr").port();
    let addr: SocketAddr = (Ipv6Addr::LOCALHOST, port).into();

    let server_im = Arc::clone(&ids.server_im);
    let server_id = ids.server_id.clone();
    let client_pub = ids.client_pub.clone();
    let server_handle = tokio::spawn(async move {
        let (stream, _) = tcp_listener.accept().await.expect("accept");
        let ch = core_handshake::server_handshake_verified_with_nickname_generic(
            stream,
            &server_im,
            &server_id,
            &client_pub,
            None,
            None,
        )
        .await
        .expect("server handshake");
        Ok::<TcpMediaTransport, String>(TcpMediaTransport::from_generic(ch))
    });

    let transport = connect_media_transport(
        addr,
        TransportMode::Tcp,
        false, // 强制 TCP：无回退语义
        &ids.client_im,
        &ids.client_id,
        "forced.example",
        "desktop",
        &ids.server_id,
        kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&ids.server_pub).expect("server pubkey"),
        "challenge",
        Duration::from_secs(3),
    )
    .await
    .expect("forced TCP connect");

    assert_eq!(transport.mode(), TransportMode::Tcp, "强制 TCP 直连");
    server_handle.await.expect("server join").expect("server ok");
}
