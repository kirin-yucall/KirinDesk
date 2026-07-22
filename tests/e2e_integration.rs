//! KirinDesk 端到端集成测试
//!
//! 验证跨模块的核心流程：密钥生成 → DNS注册 → 服务发现 → TCP连接 → 握手

use std::net::Ipv6Addr;

/// 测试密钥管理 + 序列化 + 发现流程的端到端一致性
#[test]
fn test_e2e_key_to_discovery_flow() {
    // 1. 生成 Ed25519 密钥对
    let path = std::env::temp_dir().join("kirin_desk_e2e_test_key");
    let identity = kirin_desk_core::crypto::ed25519::IdentityManager::generate(path)
        .expect("Should generate key pair");

    let pubkey_b64 = identity.public_key_base64();
    assert!(!pubkey_b64.is_empty(), "Public key should be non-empty");

    // 2. 构造 DeviceMeta（Kirin 协议 JSON）
    let meta = kirin_desk_dns::DeviceMeta::new(&pubkey_b64);
    let txt_json = meta.to_txt();
    assert!(txt_json.contains("ed25519:"));
    assert!(txt_json.contains(&pubkey_b64));

    // 3. 解析 DeviceMeta 并提取公钥
    let parsed = kirin_desk_dns::DeviceMeta::from_txt(&txt_json)
        .expect("Should parse DeviceMeta from TXT");
    let raw_key = parsed.raw_public_key()
        .expect("Should extract raw public key");
    assert_eq!(raw_key, pubkey_b64);

    // 4. 用解析出的公钥重建 VerifyingKey
    let verifying = kirin_desk_core::crypto::ed25519::IdentityManager::parse_public_key(raw_key)
        .expect("Should parse base64 public key");

    // 5. 签名验证
    let message = b"test-message";
    let signature = identity.sign(message);
    assert!(kirin_desk_core::crypto::ed25519::IdentityManager::verify_with_key(
        &verifying, message, &signature
    ), "Signature should verify");
}

/// 测试加密通道的端到端流程（无网络）
#[test]
fn test_e2e_encryption_channel() {
    // 1. Alice 和 Bob 各自生成 X25519 临时密钥
    let alice = kirin_desk_core::crypto::x25519::EphemeralSession::new();
    let bob = kirin_desk_core::crypto::x25519::EphemeralSession::new();

    // 2. 计算 ECDH 共享秘密
    let alice_shared = alice.diffie_hellman(bob.public_key());
    let bob_shared = bob.diffie_hellman(alice.public_key());
    assert_eq!(alice_shared, bob_shared, "ECDH shared secret must match");

    // 3. HKDF 派生会话密钥
    let alice_key = kirin_desk_core::crypto::x25519::EphemeralSession::derive_session_key(&alice_shared);
    let bob_key = kirin_desk_core::crypto::x25519::EphemeralSession::derive_session_key(&bob_shared);
    assert_eq!(alice_key, bob_key, "Session keys must match");

    // 4. AEAD 加密/解密
    let alice_cipher = kirin_desk_core::crypto::aead::AeadCipher::new(&alice_key);
    let bob_cipher = kirin_desk_core::crypto::aead::AeadCipher::new(&bob_key);

    let plaintext = b"KirinDesk E2E test message!";
    let (nonce, mut ciphertext) = alice_cipher.encrypt_simple(plaintext)
        .expect("Encryption should succeed");
    assert_ne!(ciphertext, plaintext, "Ciphertext should differ from plaintext");

    let decrypted = bob_cipher.decrypt_simple(&nonce, &mut ciphertext)
        .expect("Decryption should succeed");
    assert_eq!(decrypted, plaintext, "Decrypted text should match original");
}

/// 测试连接状态机
#[test]
fn test_e2e_connection_state_machine() {
    use kirin_desk_core::connection::{
        ConnectionManager, ConnectionEvent, ConnectionState,
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mgr = ConnectionManager::new();

        // 模拟完整连接生命周期
        mgr.apply_event(&ConnectionEvent::ConnectRequest {
            peer_id: "remote-pc".to_string(),
            ipv6: "2001:db8::1".parse().unwrap(),
            port: 3389,
        }).await;

        let conn = mgr.get("remote-pc").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Resolving);

        mgr.apply_event(&ConnectionEvent::DnsResolved).await;
        let conn = mgr.get("remote-pc").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Handshaking);

        mgr.apply_event(&ConnectionEvent::HandshakeSuccess).await;
        let conn = mgr.get("remote-pc").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Secured);

        // 断线重连
        mgr.apply_event(&ConnectionEvent::ConnectionLost("timeout".to_string())).await;
        let conn = mgr.get("remote-pc").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Reconnecting);

        mgr.apply_event(&ConnectionEvent::ReconnectSuccess).await;
        let conn = mgr.get("remote-pc").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Secured);

        // 手动断开
        mgr.apply_event(&ConnectionEvent::Disconnect).await;
        let conn = mgr.get("remote-pc").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Disconnected);
    });
}

/// 测试 IPv6 地址过滤逻辑
#[test]
fn test_e2e_ipv6_filtering() {
    // link-local 应该被过滤
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    assert!(!kirin_desk_core::network::is_global_unicast_ipv6(&link_local));

    // 全局单播应该通过
    let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(kirin_desk_core::network::is_global_unicast_ipv6(&global));

    // loopback 应该被过滤
    let loopback: Ipv6Addr = "::1".parse().unwrap();
    assert!(!kirin_desk_core::network::is_global_unicast_ipv6(&loopback));
}

/// 测试输入事件序列化端到端
#[test]
fn test_e2e_input_event_serialization() {
    use kirin_desk_input::capture::{InputEvent, MouseButton};

    let events = vec![
        InputEvent::MouseMove { x: 0.5, y: 0.5 },
        InputEvent::MouseButton { button: MouseButton::Left, pressed: true },
        InputEvent::Key { key: 0x41, pressed: true },
        InputEvent::MouseWheel { delta: 120 },
        InputEvent::Text { chars: "Hello".to_string() },
    ];

    for event in &events {
        let json = serde_json::to_string(event).expect("Serialize");
        let deserialized: InputEvent = serde_json::from_str(&json).expect("Deserialize");
        let re_json = serde_json::to_string(&deserialized).expect("Re-serialize");
        assert_eq!(json, re_json, "Serialization roundtrip should be consistent");
    }
}
