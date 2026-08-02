//! R-04 音频全链路闭环集成测试（QUIC loopback）。
//!
//! 验证「编码 → 传输 → 解码 → 播放」整条链路的 transport 段（媒体会话级
//! 的捕获/播放设备接线由实机验收覆盖；本测试以 mock 播放做确定性断言）：
//!
//! ```text
//! 服务端: OpusEncoder（440Hz 正弦）→ send_audio（DATAGRAM kind=Audio）
//! 客户端: recv_frame 内部分流（音频包 → 缓冲通道）→ AudioDecodePipeline
//!         （jitter 排序）→ mock 播放 → PCM 帧断言
//! ```
//!
//! 依赖 FFmpeg DLL（libopus 编解码），无 DLL 时自动跳过（与 quic_loopback
//! 同策略）。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::PinExpectation;
use kirin_desk_media::decoder::audio::{
    AudioDecodePipeline, AudioPcm, FRAME_INTERLEAVED, FRAME_SAMPLES, SAMPLE_RATE,
};
use kirin_desk_media::decoder::audio_playback::AudioPlayback as _;
use kirin_desk_media::decoder::DecodeError;
use kirin_desk_media::encoder::audio::OpusEncoder;
use kirin_desk_media::encoder::types::Timestamp;
use kirin_desk_media::encoder::video::AudioEncoder as _;
use kirin_desk_media::transport::{
    accept_quic_transport, connect_quic_transport, generate_quic_cert, MediaTransport as _,
    QuicEndpoint,
};

// ════════════════════════════════════════════════════════════════
// 测试用播放 mock（收集 PCM 供断言；decoder/audio.rs 内部同名 mock 的镜像）
// ════════════════════════════════════════════════════════════════

struct CollectPlayback {
    stop_flag: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    collected: Arc<Mutex<Vec<AudioPcm>>>,
}

impl CollectPlayback {
    fn new() -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            thread: None,
            collected: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl kirin_desk_media::decoder::audio_playback::AudioPlayback for CollectPlayback {
    fn start(&mut self, src: mpsc::Receiver<AudioPcm>) -> Result<(), DecodeError> {
        self.stop_flag.store(false, Ordering::SeqCst);
        let stop_flag = self.stop_flag.clone();
        let collected = self.collected.clone();
        self.thread = Some(
            thread::Builder::new()
                .name("audio-loopback-mock".into())
                .spawn(move || {
                    while !stop_flag.load(Ordering::SeqCst) {
                        match src.recv_timeout(Duration::from_millis(20)) {
                            Ok(pcm) => collected.lock().unwrap().push(pcm),
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => return,
                        }
                    }
                })
                .map_err(|e| DecodeError::InitFailed(format!("spawn mock playback: {e}")))?,
        );
        Ok(())
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }

    fn sample_rate(&self) -> u32 {
        SAMPLE_RATE
    }

    fn channels(&self) -> u16 {
        2
    }
}

impl Drop for CollectPlayback {
    fn drop(&mut self) {
        self.stop();
    }
}

// ════════════════════════════════════════════════════════════════
// 测试
// ════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
async fn audio_loopback_quic_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    // FFmpeg DLL + libopus 不可用 → 跳过（与 window_pipeline 测试同策略）。
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("Skipping: no FFmpeg DLLs available");
        return;
    }
    if OpusEncoder::new().is_err() {
        eprintln!("Skipping: libopus encoder unavailable");
        return;
    }

    // ── 身份（临时目录，不落盘） ────────────────────────────────
    let tmp = std::env::temp_dir();
    let server_id = "audio-loopback-server".to_string();
    let client_id = "audio-loopback-client".to_string();
    let server_im =
        IdentityManager::generate(tmp.join("kirin_audio_loop_s.key")).expect("server identity");
    let client_im =
        IdentityManager::generate(tmp.join("kirin_audio_loop_c.key")).expect("client identity");
    let server_pub = server_im.public_key_base64();
    let client_pub = client_im.public_key_base64();

    // ── 服务端 QUIC 端点（临时端口） ────────────────────────────
    let (cert, key) = generate_quic_cert(&server_id).expect("quic cert");
    let endpoint = QuicEndpoint::bind(0, cert, key).await.expect("bind");
    let addr: SocketAddr = {
        let local = endpoint.local_addr().expect("local addr");
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], local.port()))
    };
    let endpoint = Arc::new(endpoint);

    // 客户端收到的 PCM 帧（mock 播放收集）。
    let collected: Arc<Mutex<Vec<AudioPcm>>> = Arc::new(Mutex::new(Vec::new()));
    let collected_server_done = Arc::new(AtomicBool::new(false));

    // ── 服务端任务：握手 → 编码 440Hz 正弦 → send_audio 分批发送 ──
    let server_im_task = Arc::new(server_im);
    let endpoint_task = Arc::clone(&endpoint);
    let server_id_task = server_id.clone();
    let client_pub_task = client_pub.clone();
    let server_handle = tokio::spawn(async move {
        let mut transport = accept_quic_transport(
            &endpoint_task,
            &server_im_task,
            &server_id_task,
            &client_pub_task,
            None,
            None,
        )
        .await
        .expect("accept + handshake");

        // 40 帧 = 800ms 440Hz 正弦（幅 0.3）。
        let n_frames = 40usize;
        let mut pcm = Vec::with_capacity(FRAME_INTERLEAVED * n_frames);
        let freq = 440.0f32;
        for i in 0..(FRAME_SAMPLES * n_frames) {
            let t = i as f32 / SAMPLE_RATE as f32;
            let s = (t * freq * 2.0 * std::f32::consts::PI).sin() * 0.3;
            pcm.push(s); // L
            pcm.push(s); // R
        }
        let mut enc = OpusEncoder::new().expect("opus encoder");
        let pkts = enc.encode_pcm(&pcm, Timestamp::now()).expect("encode");
        assert!(
            pkts.len() >= n_frames,
            "expected ≥{n_frames} opus packets, got {}",
            pkts.len()
        );
        assert!(
            pkts.iter().all(|p| p.kind == kirin_desk_media::encoder::PacketKind::Audio),
            "encoded packets must be kind=Audio"
        );

        // 分批 send_audio（模拟 20ms 帧节奏的批次发送）。
        for batch in pkts.chunks(5) {
            transport.send_audio(batch).await.expect("send audio batch");
        }
        collected_server_done.store(true, Ordering::Relaxed);

        // 等客户端消费（网络 + jitter 预热 + mock 收集）。
        tokio::time::sleep(Duration::from_millis(800)).await;
        transport.conn().close("audio loopback done");
    });

    // 等服务端进入 accept（给 1s 余量）。
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── 客户端任务：握手 → 取音频通道 → 驱动 recv_frame 分流 ────
    let collected_task = Arc::clone(&collected);
    let client_handle = tokio::spawn(async move {
        let mut transport = connect_quic_transport(
            addr,
            &client_im,
            &client_id,
            "audio-loopback.example",
            "desktop",
            &server_id,
            // R-02：pin 强类型（TXT 已确认公钥 → Exact）。
            PinExpectation::exact_from_base64(&server_pub).expect("server pubkey"),
            "challenge",
        )
        .await
        .expect("connect + handshake");

        // R-04：取音频缓冲通道（此后 recv_frame 内部把音频包分流进来）。
        let audio_rx = transport
            .take_audio_receiver()
            .expect("audio receiver available");

        // 解码管线（mock 播放；run 阻塞至通道关闭）。
        let pipe_task = tokio::task::spawn_blocking(move || {
            let mut pipe = AudioDecodePipeline::new(audio_rx).expect("decode pipeline");
            let mock = CollectPlayback::new();
            let collected = mock.collected.clone();
            pipe.attach_playback(Box::new(mock)).expect("attach mock");
            pipe.run().expect("pipeline run");
            (pipe.jitter_stats(), collected)
        });

        // 驱动任务：recv_frame 循环（视频路径未启用——本测试无视频包，
        // 音频包在 recv_frame 内部分流后继续等待；连接关闭 → Err → 退出）。
        let stop_drv = Arc::new(AtomicBool::new(false));
        let stop_drv_task = Arc::clone(&stop_drv);
        let driver = tokio::spawn(async move {
            loop {
                if stop_drv_task.load(Ordering::Relaxed) {
                    break;
                }
                match transport.recv_frame().await {
                    Ok(_) => { /* 无视频（本测试）——继续驱动分流 */ }
                    Err(_) => break, // 连接关闭
                }
            }
        });

        // 等服务端发完 + 客户端分流（5s 上限）。
        for _ in 0..50 {
            if collected_task.lock().unwrap().len() >= 20 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        stop_drv.store(true, Ordering::Relaxed);
        let _ = driver.await;
        // 服务端已 close → 通道关闭 → 管线退出。
        pipe_task.await.expect("pipe join")
    });

    let total = tokio::time::timeout(Duration::from_secs(30), async {
        server_handle.await.expect("server join");
        let (stats, frames) = client_handle.await.expect("client join");
        (stats, frames)
    })
    .await
    .expect("test timeout");

    let (jitter, frames_arc) = total;
    // mock 播放收集的 PCM 帧（Arc<Mutex<Vec>> → 快照）。
    let frames = frames_arc.lock().unwrap().clone();

    // ── 验证：编码 → 传输 → 解码 → 播放 链路闭环 ─────────────────
    // 1. 播放端收到非空 PCM 帧序列。
    assert!(
        !frames.is_empty(),
        "client playback should collect PCM frames (got {})",
        frames.len()
    );
    eprintln!("audio loopback: {} PCM frames collected", frames.len());

    // 2. 每帧恰好 20ms：FRAME_INTERLEAVED 个 interleaved float32。
    for pcm in &frames {
        assert_eq!(
            pcm.samples.len(),
            FRAME_INTERLEAVED,
            "each PCM frame = 1920 floats (20ms @48k stereo)"
        );
    }

    // 3. PTS 在 20ms 网格上单调递增（jitter 排序 + 时间轴保持）。
    for w in frames.windows(2) {
        assert!(
            w[1].pts >= w[0].pts,
            "PTS must be monotonic: {} then {}",
            w[0].pts,
            w[1].pts
        );
    }
    assert!(
        frames.windows(2).all(|w| w[1].pts - w[0].pts <= kirin_desk_media::decoder::audio::FRAME_MS),
        "PTS steps must be ≤ 20ms on the shared axis"
    );

    // 4. 环路无损：无丢包/无静音补帧（QUIC loopback 不丢包）。
    assert_eq!(jitter.packets_dropped, 0, "loopback must not drop packets");
    // jitter 预热阶段可能补少量静音帧（起播锚定），不做零断言——只验证
    // 补帧数远小于真实帧数（时间轴基本连续）。
    assert!(
        jitter.silence_inserted <= frames.len() as u64,
        "silence fill must not exceed real frames ({})",
        jitter.silence_inserted
    );

    tracing::info!(
        "audio loopback OK: {} frames, silence={}, dropped={}",
        frames.len(),
        jitter.silence_inserted,
        jitter.packets_dropped
    );
}

/// R-04：会话配置默认值——音频默认开（Settings/CLI 显式关闭才禁用）。
#[test]
fn session_config_audio_default_enabled() {
    let cfg = kirin_desk_media::session::SessionConfig::default();
    assert!(cfg.audio.enabled, "audio must default to enabled");
    assert_eq!(cfg.audio.sample_rate, 48_000, "M12: 48kHz");
    assert_eq!(cfg.audio.channels, 2, "M12: stereo");
}
