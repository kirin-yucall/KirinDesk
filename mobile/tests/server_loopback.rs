//!
//! 不需要手机：`crate::server`（监听 59990/临时端口 + core 握手复用 +
//! 回环——**真实 TCP 127.0.0.1 + 真实 core 握手双向 + 真实 libx264 软编**
//! （合成帧源喂 `server::feed_frame`），断言端到端行为。
//!
//! # 用例矩阵（任务口径 4 + 推流冒烟 1）
//!
//! 1. **正确昵称+挑战码 → 握手成功**（`orchestration::connect_and_run`
//!    拿到 SessionHandle；服务端观众注册表 +1）；
//! 2. **错昵称 → early eof 形态拒绝**（服务端裸 close 不答——防枚举口径，
//!    客户端表现为 early eof / IO 错误，不挂死）；
//!    客户端 `humanize_reject_text` 出可读文案，非 early eof）；
//! 4. **挑战码未配置 → fail-closed 拒绝**（core 零凭据路径
//!    `credentials_required` 结构化拒绝，绝不静默放行——红线⑤）；
//! 5. **推流冒烟**：合成 640x360 帧源 → 帧泵拉起 libx264 软编 → 观众经
//!    `send_big_packet` 大帧路径收到 bincode `EncodedWindow`（首窗 IDR +
//!    持续多窗）→ 断连（drop 通道两半 = 真实 FIN）→ 观众移除 → 5s 宽限
//!    停泵。观众用**裸 core 客户端**（`client_handshake_with_codecs_generic`）
//!    而非 `connect_and_run`：`SessionHandle` drop 不关 TCP（spawn 任务持有
//!    通道半），只有裸客户端 drop 两半才是真实断连，可断言观众移除路径。
//!
//! # 环境隔离
//!
//! 服务端全局态（`Server::global()`）与 `KIRIN_DATA_DIR`（identity/
//! known_hosts 落盘）均为**进程级** → 全部用例持 `SERIALIZED` 串行锁；
//! 每用例独立临时配置目录（同 `ip_mode_handshake.rs` 口径）。

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    client_handshake_with_codecs_generic, PinExpectation, SecureChannel,
};
use kirin_desk_media::transport::{ChannelTag, SecureChannelReceiver};
use kirin_desk_media::EncodedWindow;
use kirin_desk_mobile::orchestration::{self, MobileConnectParams};
use kirin_desk_mobile::server::{self, ServerConfig};

/// 进程级串行锁（服务端全局态 + KIRIN_DATA_DIR 互斥）。
static SERIALIZED: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    SERIALIZED.lock().expect("test serialization lock poisoned")
}

/// 每用例独立临时配置目录（KIRIN_DATA_DIR 指向，identity 不污染真实配置）。
fn temp_config_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kirin_mobile_srvloop_{}_{}_{}",
        tag,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("config dir");
    // SAFETY: 测试进程内设置（每用例唯一目录，互不覆盖；SERIALIZED 串行）。
    unsafe { std::env::set_var("KIRIN_DATA_DIR", &dir) };
    dir
}

fn server_config(port: u16, nickname: &str, challenge: &str) -> ServerConfig {
    ServerConfig {
        port,
        nickname: nickname.into(),
        challenge: challenge.into(),
        // relay 三件全空 = IP 直连模式（无 ID 注册）。
        relay_server_addr: String::new(),
        relay_token: String::new(),
        relay_server_pubkey: String::new(),
        device_id: String::new(),
    }
}

/// 控制端参数（地址模式：id = 被控端昵称；带外公钥 pin 免 TOFU UI）。
fn client_params(id: &str, challenge: &str, addr: &str, pubkey: &str) -> MobileConnectParams {
    MobileConnectParams {
        id: id.into(),
        nickname: "android-tester".into(),
        challenge: challenge.into(),
        server_addr: addr.into(),
        token: String::new(),
        server_pubkey: Some(pubkey.into()),
        domain: false,
    }
}

async fn connect(params: MobileConnectParams) -> Result<orchestration::SessionHandle, String> {
    tokio::time::timeout(
        Duration::from_secs(20),
        orchestration::connect_and_run(params),
    )
    .await
    .expect("connect timeout")
}

/// 统一取错误串（SessionHandle 无 Debug，不能 expect_err）。
async fn connect_err(params: MobileConnectParams) -> String {
    match connect(params).await {
        Ok(h) => {
            h.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            panic!("expected rejection, but handshake succeeded")
        }
        Err(e) => e,
    }
}

/// 轮询断言（5s 窗口，100ms 步长）——服务端任务在独立 runtime 上，状态
/// 收敛有调度延迟，不能单点断言。
async fn poll_until(f: impl Fn() -> bool) -> bool {
    for _ in 0..50 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    f()
}

/// 用例 1：正确昵称+挑战码 → 握手成功（`orchestration::connect_and_run`
/// 拿到 SessionHandle；服务端观众注册表 +1；`server::stop()` 清注册表）。
///
/// 注：控制端 `handle.stop` 只停本端输入任务，**不关 TCP**（既有控制端
/// 行为，零改动红线）——断连移除观众的真实路径由用例 5 的裸客户端
/// （drop 通道两半 = 真实 FIN）覆盖。
#[tokio::test]
async fn handshake_succeeds_with_correct_nickname_and_challenge() {
    let _g = guard();
    temp_config_dir("ok");
    let st = server::start(server_config(0, "pixie", "ch-777")).expect("server start");
    assert!(st.running);
    assert!(st.port > 0, "port 0 必须解析出临时端口");
    assert!(!st.public_key.is_empty(), "状态必须带本机公钥（控制端 pin 用）");
    let addr = format!("127.0.0.1:{}", st.port);

    let handle = connect(client_params("pixie", "ch-777", &addr, &st.public_key))
        .await
        .expect("correct credentials must connect");
    // 服务端观众注册表 +1（握手通过 ⇒ run_viewer_session 注册）。
    assert!(
        poll_until(|| server::status().viewers == 1).await,
        "viewer must be registered (viewers = {})",
        server::status().viewers
    );
    // 收尾：停客户端输入任务 + 停服务端（stop 同步清观众注册表）。
    handle.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(server::stop());
    assert_eq!(server::status().viewers, 0, "server::stop must clear viewer registry");
}

/// 用例 2：错昵称（客户端 id ≠ 服务端昵称）→ 服务端裸 close（early eof
/// 形态，防枚举口径——昵称是凭据，错昵称不下发结构化码）。
#[tokio::test]
async fn handshake_rejects_wrong_nickname_with_bare_close() {
    let _g = guard();
    temp_config_dir("nick");
    let st = server::start(server_config(0, "pixie", "ch-777")).expect("server start");
    let addr = format!("127.0.0.1:{}", st.port);
    let err = connect_err(client_params("intruder", "ch-777", &addr, &st.public_key)).await;
    assert!(
        err.to_lowercase().contains("eof")
            || err.to_lowercase().contains("i/o")
            || err.to_lowercase().contains("handshake"),
        "expected early-eof-ish failure (bare close), got: {err}"
    );
    assert!(server::stop());
}

/// 客户端 humanize 出可读文案而非裸 early eof）。
#[tokio::test]
async fn handshake_rejects_wrong_challenge_with_structured_code() {
    let _g = guard();
    temp_config_dir("chal");
    let st = server::start(server_config(0, "pixie", "ch-777")).expect("server start");
    let addr = format!("127.0.0.1:{}", st.port);
    let err = connect_err(client_params("pixie", "WRONG", &addr, &st.public_key)).await;
    assert!(
        err.to_lowercase().contains("challenge"),
        "expected humanized challenge mismatch in error, got: {err}"
    );
    assert!(
        !err.to_lowercase().contains("eof"),
        "structured reject must not surface as early eof, got: {err}"
    );
    assert!(server::stop());
}

/// 用例 4：挑战码未配置 → fail-closed（红线⑤）。core 零凭据路径
/// （无固定码 + 无 pin + 无临时窗 ⇒ `credentials_required`）结构化拒绝——
/// **绝不静默放行**（客户端带任意挑战码来也不通过：服务端无码可比）。
#[tokio::test]
async fn handshake_fails_closed_when_challenge_unconfigured() {
    let _g = guard();
    temp_config_dir("nochal");
    let st = server::start(server_config(0, "pixie", "")).expect("server start (challenge unset)");
    let addr = format!("127.0.0.1:{}", st.port);
    // 客户端猜一个挑战码来——服务端未配置 ⇒ 零凭据拒绝，不得放行。
    let err = connect_err(client_params("pixie", "guess-123", &addr, &st.public_key)).await;
    assert!(
        err.to_lowercase().contains("credentials"),
        "expected humanized credentials-required reject, got: {err}"
    );
    assert!(
        !err.to_lowercase().contains("eof"),
        "fail-closed reject must be structured (not early eof), got: {err}"
    );
    assert!(server::stop());
}

/// 用例 5：推流冒烟（合成帧源 → libx264 软编 → 观众收 EncodedWindow →
/// 断连移除 → 宽限停泵）。
///
/// 观众 = 裸 core 客户端（`client_handshake_with_codecs_generic`，与 mobile
/// 地址模式同 wire 形态：client_id=昵称、client_domain="gui-client.local"、
/// 带外 pin 服务端公钥）——drop 读写两半即真实 FIN，可断言服务端观众移除。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streaming_smoke_first_window_then_grace_stop() {
    let _g = guard();
    // 服务端 pump/broadcast 日志走 tracing（try_init 幂等；WARN 级覆盖
    // 「泵启动失败/编码错误」等关键诊断，失败时随输出展示）。
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .try_init();
    temp_config_dir("stream");
    let st = server::start(server_config(0, "stream-pc", "ch-s")).expect("server start");
    let addr = format!("127.0.0.1:{}", st.port);
    let pubkey = st.public_key.clone();

    // 合成帧源：640x360 RGBA 每帧变化（对角渐变滚动）30fps 喂入——
    // 内容持续变化 ⇒ 帧活动度高，频率门控放行，每帧一窗（低延迟模式）。
    const W: u32 = 640;
    const H: u32 = 360;
    let feed_task = std::thread::spawn(move || {
        let mut frame = vec![0u8; (W * H * 4) as usize];
        let mut tick: u8 = 0;
        loop {
            for y in 0..H {
                for x in 0..W {
                    let v = ((x.wrapping_add(y).wrapping_add(tick as u32)) % 251) as u8;
                    let o = ((y * W + x) * 4) as usize;
                    frame[o] = v;
                    frame[o + 1] = v.wrapping_mul(2);
                    frame[o + 2] = tick;
                    frame[o + 3] = 255;
                }
            }
            if !server::feed_frame(&frame, W, H, 0) {
                break; // 服务端已停 → 退出喂帧线程
            }
            tick = tick.wrapping_add(37);
            std::thread::sleep(Duration::from_millis(33));
        }
    });

    // 裸 core 观众客户端。
    // load_or_generate 首参 = 身份**文件**路径（非目录；同 ip_mode 范式）。
    let viewer_path = std::env::temp_dir().join(format!(
        "kirin_mobile_srvloop_viewer_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&viewer_path);
    let identity =
        IdentityManager::load_or_generate(viewer_path, "viewer").expect("viewer identity");
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .expect("tcp connect to mobile server");
    let g = client_handshake_with_codecs_generic(
        stream,
        &identity,
        // 地址模式 wire 形态（orchestration.rs:1089 同款）：client_id = 被控端
        // 昵称；device_type 与 mobile 客户端同值 "desktop"（服务端不校验）。
        "stream-pc",
        "gui-client.local",
        "desktop",
        "stream-pc",
        PinExpectation::exact_from_base64(&pubkey).expect("pin from status public_key"),
        "ch-s",
        vec!["h264".to_string()],
    )
    .await
    .expect("viewer handshake");
    let channel = SecureChannel {
        stream: g.stream,
        cipher: g.cipher,
        peer_id: g.peer_id,
        peer_domain: g.peer_domain,
        peer_device_type: g.peer_device_type,
        selected_codec: g.selected_codec,
        peer_os: g.peer_os,
    };
    assert_eq!(
        channel.selected_codec, "h264",
        "codec 协商必须选 h264（本端软编唯一）"
    );
    let (reader, writer) = channel.into_split();
    let _writer = writer; // 写半保持存活（drop 才发 FIN = 本用例末尾的断连手段）
    let mut receiver = SecureChannelReceiver::new(reader);

    // (a) 首窗 20s 内到达，且是 IDR 大帧（新编码器首窗必 IDR）。
    // 超时断言带服务端状态快照（观众/泵），失败时直接定位断在哪一环。
    let (tag, header, payload) = match tokio::time::timeout(
        Duration::from_secs(20),
        receiver.recv_tagged(),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let s = server::status();
            panic!("first frame recv error: {e} (viewers={} pump_active={})", s.viewers, s.pump_active)
        }
        Err(_) => {
            let s = server::status();
            panic!(
                "first window within 20s: Elapsed (viewers={} pump_active={})",
                s.viewers, s.pump_active
            )
        }
    };
    assert_eq!(tag, ChannelTag::Video, "video big frame expected");
    assert!(header.is_key(), "first window must be marked key (IDR)");
    let win: EncodedWindow = bincode::deserialize(&payload).expect("EncodedWindow on wire");
    assert!(!win.is_empty(), "window must carry encoded data");
    assert_eq!((win.base_w, win.base_h), (W, H), "window must carry frame dims");
    assert!(win.frame_count >= 1, "window must contain >=1 frame");

    // (b) 持续推流：其后 8s 内再收到 ≥4 个视频窗（低延迟逐帧关窗）。
    for i in 0..4 {
        let (tag, _h, _p) =
            tokio::time::timeout(Duration::from_secs(8), receiver.recv_tagged())
                .await
                .unwrap_or_else(|_| panic!("window #{i} not sustained within 8s"))
                .unwrap_or_else(|e| panic!("window #{i} recv error: {e}"));
        assert_eq!(tag, ChannelTag::Video);
    }

    // (c) 断连：drop 读写两半（真实 FIN）→ 服务端 EOF 移除观众。
    drop(receiver);
    drop(_writer);
    assert!(
        poll_until(|| server::status().viewers == 0).await,
        "viewer must be removed after disconnect (viewers = {})",
        server::status().viewers
    );

    // (d) 全观众离场 → 5s 宽限后停泵（泵不再空转烧 CPU）。
    assert!(
        poll_until(|| {
            let s = server::status();
            s.viewers == 0 && !s.pump_active
        })
        .await,
        "pump must grace-stop ~5s after last viewer left (pump_active = {})",
        server::status().pump_active
    );

    assert!(server::stop());
    let _ = feed_task.join();
}

/// 崩溃点：`bind_dual_stack_tcp_listener`→`TcpListener::from_std` 注册
/// reactor 时 `there is no reactor running` panic→SIGABRT）。修复
/// （`runtime().enter()` 进上下文）后必须成功启动并可停止。此前宿主 e2e
/// 全部运行于 `#[tokio::test]` 上下文内，掩盖该缺陷。刻意用非 async
/// `#[test]`（测试线程零 runtime 上下文）。
#[test]
fn r199_start_from_plain_thread_without_runtime_context_ok() {
    let _g = guard();
    temp_config_dir("r199");
    let h = std::thread::spawn(|| server::start(server_config(0, "r199probe", "ch-r199")))
        .join()
        .expect("worker thread must not panic (C-1: no reactor running abort)");
    assert!(st.running, "server must report running");
    assert!(st.port > 0, "ephemeral port must be reported (got {})", st.port);
    assert!(server::stop(), "server must stop cleanly after plain-thread start");
    // 显示"—"——device_id 须按落盘配置现读（nativeIdentity 同口径）。
    let after = server::status();
    assert!(
        !after.device_id.is_empty(),
        "device_id must resolve from disk when not running (F-2)"
    );
    assert!(
        !after.fingerprint.is_empty(),
        "fingerprint must resolve when not running (F-2)"
    );
}
