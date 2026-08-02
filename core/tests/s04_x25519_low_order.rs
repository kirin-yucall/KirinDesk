//! S-04（审计 F-3）：X25519 低阶点 / 全零公钥拒绝 — 握手级集成测试
//!
//! 覆盖：
//! - 服务端拒绝携带全零 / 低阶点 / 非规范编码 `client_x25519_pub` 的握手
//!   init（**拒绝且不泄露响应**：服务端不发响应即断开，攻击侧读到 EOF）；
//! - 客户端拒绝服务端响应中的低阶 `server_x25519_pub`（签名有效仍拒绝）；
//! - 低阶点黑名单 11 个经典值 + 非规范编码拒绝（RFC 7748 §6）；
//! - 正常握手回归（确认无误伤）。
//!
//! 文件按新文件名（s04_*）命名，避免与其他并发修复任务的测试文件冲突。

use std::time::Duration;

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    client_handshake_generic, server_handshake_verified_generic, HandshakeError, HandshakeInit,
    HandshakeResponse, PinExpectation,
};
use kirin_desk_core::crypto::x25519::{EphemeralSession, X25519Error};
use kirin_desk_core::network::tcp::{receive_message, send_message};

fn gen_identity(dir: &std::path::Path, name: &str) -> IdentityManager {
    IdentityManager::generate(dir.join(name)).expect("generate identity")
}

// ---- 复刻 handshake.rs 签名载荷格式（private fn，测试侧独立实现保证格式一致） ----

fn init_sig_payload(
    x25519_pub: &[u8; 32],
    nonce: &[u8; 32],
    peer_id: &str,
    domain: &str,
    device_type: &str,
) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(x25519_pub);
    p.extend_from_slice(nonce);
    p.extend_from_slice(peer_id.as_bytes());
    p.push(b'|');
    p.extend_from_slice(domain.as_bytes());
    p.push(b'|');
    p.extend_from_slice(device_type.as_bytes());
    p
}

fn resp_sig_payload(
    server_x25519: &[u8; 32],
    client_x25519: &[u8; 32],
    nonce: &[u8; 32],
    peer_id: &str,
) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(server_x25519);
    p.extend_from_slice(client_x25519);
    p.extend_from_slice(nonce);
    p.extend_from_slice(peer_id.as_bytes());
    p
}

// ---- 低阶点输入样本 ----
//
// 经典 11 值（RFC 7748 §6 低阶点清单，little-endian）：
//   u=0、u=1、u=a、u=b、u=p-1、u=p、u=p+1、u=2^255、u=2^255+1、u=2^255+a、u=2^255+b
// 另含非规范编码 u=2p（≡0，防御"按 mod p 归约"的实现路径）。

/// u = 0（全零公钥；F-3 攻击向量）
const U_ZERO: [u8; 32] = [0u8; 32];
/// u = 1（阶 4）
const U_ONE: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
];
/// u = a = 325606250916557431795983626356110631294008115727848805560023387167927233504（阶 8）
const U_A: [u8; 32] = [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
    0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
    0xb8, 0x00,
];
/// u = b = 39382357235489614581723060781553021112529911719440698176882885853963445705823（阶 8）
const U_B: [u8; 32] = [
    0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
    0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
    0x11, 0x57,
];
/// u = p - 1（阶 4，扭曲线点）
const U_P_MINUS_1: [u8; 32] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x7f,
];
/// u = p（非规范编码，≡ 0）
const U_P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x7f,
];
/// u = p + 1（非规范编码，≡ 1）
const U_P_PLUS_1: [u8; 32] = [
    0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x7f,
];
/// u = 2^255（位 255 置位变体）
const U_2_255: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 0x80;
    b
};
/// u = 2^255 + 1
const U_2_255_1: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 0x01;
    b[31] = 0x80;
    b
};
/// u = 2^255 + a
const U_2_255_A: [u8; 32] = {
    let mut b = U_A;
    b[31] = 0x80;
    b
};
/// u = 2^255 + b（b 高位字节 0x57 → 置位后 0xd7）
const U_2_255_B: [u8; 32] = [
    0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
    0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
    0x11, 0xd7,
];
/// u = 2p（非规范编码，≡ 0）
const U_2P_EXPLICIT: [u8; 32] = [
    0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,
];

/// 经典 11 值（RFC 7748 §6 低阶点清单）+ 额外非规范编码样本。
const LOW_ORDER_SAMPLES: &[[u8; 32]] = &[
    U_ZERO,
    U_ONE,
    U_A,
    U_B,
    U_P_MINUS_1,
    U_P,
    U_P_PLUS_1,
    U_2_255,
    U_2_255_1,
    U_2_255_A,
    U_2_255_B,
    U_2P_EXPLICIT,
];

/// 构造恶意握手 init：自报公钥为攻击者真实身份（签名有效），
/// `client_x25519_pub` 注入低阶点。
fn malicious_init(attacker: &IdentityManager, client_x25519_pub: [u8; 32]) -> HandshakeInit {
    let nonce = [7u8; 32];
    let payload = init_sig_payload(
        &client_x25519_pub,
        &nonce,
        "attacker",
        "evil.local",
        "desktop",
    );
    HandshakeInit {
        client_id: "attacker".to_string(),
        client_domain: "evil.local".to_string(),
        client_device_type: "desktop".to_string(),
        challenge: String::new(),
        client_ed25519_pub_base64: attacker.public_key_base64(),
        client_x25519_pub,
        nonce,
        signature: attacker.sign(&payload).to_bytes().to_vec(),
        supported_codecs: vec![],
    }
}

// ---- 测试 1：低阶点黑名单拒绝（parse_public_key 层） ----

#[test]
fn test_parse_public_key_rejects_low_order_samples() {
    for bytes in LOW_ORDER_SAMPLES {
        let err = EphemeralSession::parse_public_key(bytes);
        assert!(
            err.is_err(),
            "low-order public key must be rejected: {:02x?}",
            &bytes[..]
        );
    }
    // 全零单独验证错误类型与消息（F-3 主攻击向量）。
    match EphemeralSession::parse_public_key(&U_ZERO) {
        Err(X25519Error::InvalidPublicKey(msg)) => {
            assert!(msg.contains("all-zero"), "unexpected message: {msg}")
        }
        other => panic!("expected InvalidPublicKey(all-zero), got {other:?}"),
    }
}

// ---- 测试 2：服务端拒绝恶意 client_x25519_pub 且不泄露响应 ----

/// 一次恶意 init 握手：服务端必须 Err，且攻击侧收不到任何响应字节
/// （服务端在 `send_message` 之前完成低阶点校验 → 直接断开）。
async fn run_malicious_init_handshake(
    attacker: &IdentityManager,
    server: &IdentityManager,
    bad_pub: [u8; 32],
) -> Result<(), HandshakeError> {
    let (mut client_end, server_end) = tokio::io::duplex(65536);
    let init = malicious_init(attacker, bad_pub);
    let init_data = bincode::serialize(&init).expect("serialize init");
    send_message(&mut client_end, &init_data).await.expect("send init");

    let server_res = server_handshake_verified_generic(
        server_end,
        server,
        "server",
        &attacker.public_key_base64(), // 服务端 pin：攻击者自报身份（签名由此可验）
    )
    .await;

    // 攻击侧尝试读取响应：服务端已拒绝（未发响应并断开）→ EOF / 超时，
    // 绝不能读到 Ok（即"不泄露响应"）。
    let leaked = tokio::time::timeout(Duration::from_secs(2), receive_message(&mut client_end))
        .await;
    assert!(
        !matches!(leaked, Ok(Ok(_))),
        "server must not leak a response for low-order client public key"
    );
    server_res.map(|_| ())
}

#[tokio::test]
async fn test_server_rejects_all_zero_client_pub() {
    let dir = std::env::temp_dir().join("s04_server_zero");
    let attacker = gen_identity(&dir, "attacker");
    let server = gen_identity(&dir, "server");
    let res = run_malicious_init_handshake(&attacker, &server, U_ZERO).await;
    match res {
        Err(HandshakeError::InvalidMessage(msg)) => {
            assert!(msg.contains("X25519"), "unexpected message: {msg}")
        }
        Ok(_) => panic!("server must reject all-zero client X25519 public key"),
        Err(other) => panic!("expected InvalidMessage, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_server_rejects_low_order_client_pub() {
    let dir = std::env::temp_dir().join("s04_server_low_order");
    let attacker = gen_identity(&dir, "attacker");
    let server = gen_identity(&dir, "server");
    // 阶 8 点 u=a、阶 4 点 u=1、扭曲线阶 4 点 u=p-1、非规范编码 u=p、u=2p、位 255 变体。
    for bad_pub in [U_A, U_ONE, U_P_MINUS_1, U_P, U_2P_EXPLICIT, U_2_255, U_2_255_A] {
        let res = run_malicious_init_handshake(&attacker, &server, bad_pub).await;
        assert!(
            matches!(res, Err(HandshakeError::InvalidMessage(_))),
            "server must reject low-order client X25519 public key: {res:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- 测试 3：客户端拒绝恶意 server_x25519_pub（签名有效仍拒绝） ----

#[tokio::test]
async fn test_client_rejects_low_order_server_pub() {
    let dir = std::env::temp_dir().join("s04_client_low_order");
    let alice = gen_identity(&dir, "alice");
    let mallory = gen_identity(&dir, "mallory");
    let mallory_pub = mallory.public_key_base64();
    let (client_end, server_end) = tokio::io::duplex(65536);

    let client_fut = client_handshake_generic(
        client_end,
        &alice,
        "alice",
        "alice.local",
        "desktop",
        "mallory",
        PinExpectation::exact_from_base64(&mallory_pub).expect("mallory pubkey"),
        "",
    );
    // 恶意服务端：公钥/签名全部有效，但响应中 server_x25519_pub = 全零。
    let server_fut = async move {
        let mut server_end = server_end;
        let init =
            kirin_desk_core::crypto::handshake::server_read_init(&mut server_end).await?;
        let bad_pub = U_ZERO;
        let payload = resp_sig_payload(&bad_pub, &init.client_x25519_pub, &init.nonce, "mallory");
        let sig = mallory.sign(&payload);
        let resp = HandshakeResponse {
            server_x25519_pub: bad_pub,
            server_ed25519_pub_base64: mallory_pub.clone(),
            signature: sig.to_bytes().to_vec(),
            selected_codec: String::new(),
            server_fingerprint: String::new(),
        };
        let data = bincode::serialize(&resp)
            .map_err(|e| HandshakeError::Serialization(e.to_string()))?;
        send_message(&mut server_end, &data).await?;
        Ok::<_, HandshakeError>(())
    };
    let (client_res, _server_res) = tokio::join!(client_fut, server_fut);

    match client_res {
        Err(HandshakeError::InvalidMessage(msg)) => {
            assert!(msg.contains("X25519"), "unexpected message: {msg}")
        }
        Ok(_) => panic!("client must reject low-order server X25519 public key"),
        Err(other) => panic!("expected InvalidMessage, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- 测试 4：正常握手回归（无误伤） ----

#[tokio::test]
async fn test_normal_handshake_still_succeeds() {
    let dir = std::env::temp_dir().join("s04_regression");
    let alice = gen_identity(&dir, "alice");
    let bob = gen_identity(&dir, "bob");
    let bob_pub = bob.public_key_base64();
    let alice_pub = alice.public_key_base64();
    let (client_end, server_end) = tokio::io::duplex(65536);

    let client_fut = client_handshake_generic(
        client_end,
        &alice,
        "alice",
        "alice.local",
        "desktop",
        "bob",
        PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"),
        "",
    );
    let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
    let (client_res, server_res) = tokio::join!(client_fut, server_fut);
    assert!(client_res.is_ok(), "normal client handshake must succeed");
    assert!(server_res.is_ok(), "normal server handshake must succeed");
    let _ = std::fs::remove_dir_all(&dir);
}
