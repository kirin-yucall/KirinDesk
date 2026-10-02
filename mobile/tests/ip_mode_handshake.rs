//! 握手 early eof，从未出画面」）。
//!
//! 不需要手机/模拟器：mobile 编排层（connect_and_run → connect_and_run_address）
//! 是跨平台 Rust，宿主机上起**真实服务端握手**（core
//! `server_handshake_verified_with_nickname_generic`，即 GUI/policy 服务端
//! 校验链的核心：`verify_server_init` 昵称/挑战码/凭据门）+ 真实客户端
//! （orchestration::connect_and_run，TrustPolicy::Verified pin 免 TOFU UI）
//! 做端到端断言。
//!
//! # 根因（复现所证）
//!
//! 服务端昵称校验比对的是握手 `init.client_id`
//! （core/src/crypto/handshake.rs `verify_server_init_inner` 第 2 步）；
//! GUI 服务端对 IP/域名模式客户端（client_domain 非空）**必查昵称**
//! （ui/src/lib.rs `expected_nick_for_verify`）；桌面客户端地址模式
//! `client_id = server_id`（服务端昵称，「保持 GUI 既有行为」）恰好通过；
//! 移动端编排层误发**本机设备 ID**（"kirin-android"）→ nickname mismatch
//! → 服务端裸 close → 客户端 "early eof"。修复 = 对齐桌面：地址模式
//! client_id = 服务端昵称。
//!
//! # 连接矩阵
//!
//! 1. 正确凭据（昵称+挑战码）→ 握手成功拿到 SessionHandle；
//! 2. 错昵称（= 修复前移动端实际发的 client_id）→ 拒绝（early eof 形态）；
//! 3. 错挑战码 → GUI 形态服务端下发结构化拒绝码 `challenge_mismatch`
//! 4. 昵称含大小写 → 字面比对（不做 ID 归一化：指纹/短码小写化会破坏
//!    昵称等值——P1-A `normalize_device_id_input` 不适用于地址模式昵称）。
//!
//! # 环境隔离
//!
//! `KIRIN_DATA_DIR` 指向每测试独立临时目录（identity/known_hosts/
//! devices.json 落盘不污染真实配置）。

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    handshake_error_reject_code, server_handshake_verified_with_nickname_generic,
    server_read_init, send_handshake_reject, verify_server_init,
};
use kirin_desk_mobile::orchestration::{self, MobileConnectParams};

/// 起服务端握手（昵称 + 挑战码门）→ 返回监听地址与服务器身份公钥。
///
/// 签名 server_id = **昵称**（对齐 GUI 服务端：`server_handshake_respond_generic
/// (stream, identity, server_name, …)`，ui/src/lib.rs 8999——响应签名
/// peer_id 是 `server_name` 即昵称，客户端以同一昵称验签；两处任一不同
/// → `SignatureVerificationFailed`）。
async fn spawn_server(nickname: &str, challenge: &str) -> (String, String) {
    let dir = std::env::temp_dir().join(format!(
        "kirin_mobile_ipfix_srv_{}_{}",
        std::process::id(),
        nickname.len()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let server_id = IdentityManager::load_or_generate(dir, "server-under-test")
        .expect("server identity");
    let pubkey = server_id.public_key_base64();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let nick = nickname.to_string();
    let chall = challenge.to_string();
    tokio::spawn(async move {
        // 单连接：真实客户端行为（校验失败即关流，不答——正是 early eof 源头）。
        if let Ok((stream, _)) = listener.accept().await {
            let _ = server_handshake_verified_with_nickname_generic(
                stream,
                &server_id,
                // 签名 id = 昵称（GUI 服务端口径，见函数 doc）。
                &nick,
                "",
                Some(&nick),
                Some(&chall),
            )
            .await;
        }
    });
    (addr, pubkey)
}

/// 拒绝码（`send_handshake_reject`）后关流。对齐 ui/src/lib.rs
/// handle_incoming_connection 的拒绝分支。
async fn spawn_gui_like_server(nickname: &str, challenge: &str) -> (String, String) {
    let dir = std::env::temp_dir().join(format!(
        "kirin_mobile_ipfix_guisrv_{}_{}",
        std::process::id(),
        challenge.len()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let server_id = IdentityManager::load_or_generate(dir, "server-under-test")
        .expect("server identity");
    let pubkey = server_id.public_key_base64();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let nick = nickname.to_string();
    let chall = challenge.to_string();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let init = match server_read_init(&mut stream).await {
                Ok(i) => i,
                Err(_) => return,
            };
            if let Err(e) = verify_server_init(
                &init, "", Some(&nick), Some(&chall), false,
            ) {
                let code = handshake_error_reject_code(&e).unwrap_or("handshake_error");
                let _ = send_handshake_reject(&mut stream, code, &init.client_id).await;
                return; // 拒绝即关流（GUI 同口径）
            }
            // 校验通过走完整握手（成功路径仅用于收尾，本测试聚焦拒绝形态）。
            let _ = server_handshake_verified_with_nickname_generic(
                stream, &server_id, &nick, "", Some(&nick), Some(&chall),
            )
            .await;
        }
    });
    (addr, pubkey)
}

/// 客户端环境隔离（KIRIN_DATA_DIR 临时目录）。
fn temp_config_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kirin_mobile_ipfix_{}_{}_{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("config dir");
    // SAFETY: 测试进程内设置（每测试唯一目录，互不覆盖）。
    unsafe { std::env::set_var("KIRIN_DATA_DIR", &dir) };
    dir
}

fn client_params(id: &str, challenge: &str, addr: &str, pubkey: &str) -> MobileConnectParams {
    MobileConnectParams {
        // 地址模式：id = 服务端昵称（Dashboard 配置值，与挑战码成对）。
        id: id.into(),
        nickname: "android-tester".into(),
        challenge: challenge.into(),
        server_addr: addr.into(),
        token: String::new(),
        // 带外公钥 pin（TrustPolicy::Verified）→ 免 TOFU UI 确认路径。
        server_pubkey: Some(pubkey.into()),
        domain: false,
    }
}

async fn connect(
    params: MobileConnectParams,
) -> Result<orchestration::SessionHandle, String> {
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
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

/// 端到端：IP 直连握手成功（服务端昵称 = 凭据之一，客户端须以 client_id
/// 上报该昵称——修复后口径）。
#[tokio::test]
async fn ip_mode_handshake_succeeds_with_server_nickname() {
    temp_config_dir("ok");
    let (addr, pubkey) = spawn_server("bob-pc", "ch-123").await;
    let handle = connect(client_params("bob-pc", "ch-123", &addr, &pubkey))
        .await
        .expect("IP mode handshake must succeed");
    // 建链成功即拿到句柄（run_session 任务已启动）；立即断开收尾。
    handle.stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// 根因复现锚点：客户端把**自己的设备 ID**当 client_id 上报（修复前移动端
/// 行为，等价于 id 填本机名）→ 服务端昵称门拒绝。此用例固化「昵称是凭据，
/// 必须填服务端昵称」的口径：id ≠ 服务端昵称 ⇒ 拒绝（early eof 形态）。
#[tokio::test]
async fn ip_mode_handshake_rejects_wrong_nickname() {
    temp_config_dir("bad");
    let (addr, pubkey) = spawn_server("bob-pc", "ch-123").await;
    let params = client_params("kirin-android", "ch-123", &addr, &pubkey);
    let err = connect_err(params).await;
    // 服务端校验失败裸 close → 客户端表现为 early eof / IO 错误（而非挂死）。
    assert!(
        err.to_lowercase().contains("eof")
            || err.to_lowercase().contains("i/o")
            || err.to_lowercase().contains("handshake"),
        "expected early-eof-ish failure, got: {err}"
    );
}

/// `humanize_reject_text` 把 `challenge_mismatch|…` 译成可读文案
/// （含 "challenge code mismatch"），而非修复前的裸 early eof。
#[tokio::test]
async fn ip_mode_wrong_challenge_gets_structured_reject_code() {
    temp_config_dir("chal");
    let (addr, pubkey) = spawn_gui_like_server("bob-pc", "ch-123").await;
    let params = client_params("bob-pc", "WRONG", &addr, &pubkey);
    let err = connect_err(params).await;
    assert!(
        err.to_lowercase().contains("challenge"),
        "expected humanized structured reject in error, got: {err}"
    );
    assert!(
        !err.to_lowercase().contains("eof"),
        "structured reject must not surface as early eof, got: {err}"
    );
}

/// 昵称字面比对：大小写敏感、不做 ID 归一化（P1-A 指纹/短码小写化语义
/// 不适用于地址模式昵称——`normalize_device_id_input` 会把 `Bob-PC` 改写
/// 成小写形态导致凭据失配；修复后地址模式仅 trim）。
#[tokio::test]
async fn ip_mode_nickname_is_literal_case_sensitive() {
    temp_config_dir("case");
    let (addr, pubkey) = spawn_server("Bob-PC", "ch-123").await;
    // 大小写不同 → 昵称门拒绝。
    let err = connect_err(client_params("bob-pc", "ch-123", &addr, &pubkey)).await;
    assert!(
        err.to_lowercase().contains("eof")
            || err.to_lowercase().contains("i/o")
            || err.to_lowercase().contains("handshake"),
        "expected early-eof-ish failure, got: {err}"
    );
}

/// 路径锚点：mobile 地址模式与桌面共用 core `perform_handshake`（无独立
/// 握手实现）——proto_ver / requested_max_width 尾字段容错由 core 测试
/// 矩阵覆盖（b6c3c3e/a21652e），本用例锚定移动端行为边界：`id` 留空 →
/// server_id 回退为地址串（known_hosts 键语义不变），但昵称门按字面比对
/// 地址串 ⇒ 必拒——断言该 fail 路径稳定（可读错误，不 panic/不挂死）。
#[tokio::test]
async fn ip_mode_empty_id_falls_back_to_addr_and_is_rejected() {
    temp_config_dir("path");
    let (addr, pubkey) = spawn_server("alice-desk", "ch-9").await;
    let err = connect_err(client_params("", "ch-9", &addr, &pubkey)).await;
    assert!(
        err.to_lowercase().contains("eof")
            || err.to_lowercase().contains("i/o")
            || err.to_lowercase().contains("handshake"),
        "expected early-eof-ish failure, got: {err}"
    );
}

/// `requested_max_width` 必须等于 [`orchestration::REQUESTED_MAX_WIDTH`]
/// （1280）。服务端读侧由 `parse_handshake_init` 容错解析（旧端缺字段=0），
/// 本测试证明移动端**确实把值写上了 wire**（P1-A 期曾长期只有协议字段、
/// 客户端从未上报——防再退化成「字段存在但永远 0」）。
#[tokio::test]
async fn ip_mode_reports_requested_max_width_on_wire() {
    temp_config_dir("width");
    let dir = std::env::temp_dir().join(format!(
        "kirin_mobile_width_srv_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let server_id = IdentityManager::load_or_generate(dir, "width-server")
        .expect("server identity");
    let pubkey = server_id.public_key_base64();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let server_task = tokio::spawn(async move {
        // 只读 init（不握手成功也可断言 init 内容；正常路径下继续完成握手）。
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(init) = server_read_init(&mut stream).await {
                return Some(init.requested_max_width);
            }
        }
        None
    });
    // 客户端凭据与 spawn 对齐（昵称/挑战码服务端不校验——我们只读 init）。
    let params = MobileConnectParams {
        id: "width-pc".into(),
        nickname: "android-tester".into(),
        challenge: "ch-w".into(),
        server_addr: addr.into(),
        token: String::new(),
        server_pubkey: Some(pubkey.into()),
        domain: false,
    };
    // 设 1920 档后握手 init 必须上报 1920（设置驱动端到端证据）。
    orchestration::set_requested_max_width(1920);
    let _ = connect(params).await; // 握手结果不敏感（服务端可能不完整应答）
    let reported = server_task
        .await
        .expect("server task")
        .expect("init must be readable");
    assert_eq!(
        reported, 1920,
        "设置档位 1920 必须随握手 init 上 wire（requested_max_width）"
    );
    // 复原默认档（防影响同进程后续用例）。
    orchestration::set_requested_max_width(orchestration::DEFAULT_REQUESTED_MAX_WIDTH as i64);
}
