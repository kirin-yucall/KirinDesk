//! KirinDesk 核心端到端集成测试
//!
//! 仅依赖 ip6desk-core + ip6desk-dns（core 的依赖）

use std::net::Ipv6Addr;

/// 密钥管理 + 序列化端到端
#[test]
fn test_e2e_key_flow() {
    let path = std::env::temp_dir().join("kirin_desk_e2e_key");
    let identity = kirin_desk_core::crypto::ed25519::IdentityManager::generate(path)
        .expect("generate key pair");

    let pubkey_b64 = identity.public_key_base64();
    assert!(!pubkey_b64.is_empty());

    // DeviceMeta（Kirin 协议 JSON）
    let meta = kirin_desk_dns::DeviceMeta::new(&pubkey_b64);
    let txt_json = meta.to_txt();
    assert!(txt_json.contains("ed25519:"));

    let parsed = kirin_desk_dns::DeviceMeta::from_txt(&txt_json).expect("parse");
    let raw_key = parsed.raw_public_key().expect("extract key");
    assert_eq!(raw_key, pubkey_b64);

    let verifying = kirin_desk_core::crypto::ed25519::IdentityManager::parse_public_key(raw_key)
        .expect("parse base64 key");

    let msg = b"test-message";
    let sig = identity.sign(msg);
    assert!(kirin_desk_core::crypto::ed25519::IdentityManager::verify_with_key(&verifying, msg, &sig));
}

/// 加密通道端到端
#[test]
fn test_e2e_encryption() {
    let alice = kirin_desk_core::crypto::x25519::EphemeralSession::new();
    let bob = kirin_desk_core::crypto::x25519::EphemeralSession::new();

    // S-04: diffie_hellman 现返回 Result（全零输出 → ExchangeFailed）。
    let alice_shared = alice.diffie_hellman(bob.public_key()).expect("valid peer key");
    let bob_shared = bob.diffie_hellman(alice.public_key()).expect("valid peer key");
    assert_eq!(alice_shared, bob_shared);

    let alice_key = kirin_desk_core::crypto::x25519::EphemeralSession::derive_session_key(&alice_shared);
    let bob_key = kirin_desk_core::crypto::x25519::EphemeralSession::derive_session_key(&bob_shared);
    assert_eq!(alice_key, bob_key);

    let ac = kirin_desk_core::crypto::aead::AeadCipher::new(&alice_key);
    let bc = kirin_desk_core::crypto::aead::AeadCipher::new(&bob_key);

    let plaintext = b"KirinDesk E2E test!";
    let (nonce, mut ct) = ac.encrypt_simple(plaintext).unwrap();
    assert_ne!(ct, plaintext);

    let decrypted = bc.decrypt_simple(&nonce, &mut ct).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// 连接状态机
#[test]
fn test_e2e_connection_state_machine() {
    use kirin_desk_core::connection::{ConnectionManager, ConnectionEvent, ConnectionState};

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mgr = ConnectionManager::new();

        mgr.apply_event(&ConnectionEvent::ConnectRequest {
            peer_id: "remote-pc".to_string(),
            ipv6: "2001:db8::1".parse().unwrap(),
            port: 3389,
        }).await;
        assert_eq!(mgr.get("remote-pc").await.unwrap().state, ConnectionState::Resolving);

        mgr.apply_event(&ConnectionEvent::DnsResolved).await;
        assert_eq!(mgr.get("remote-pc").await.unwrap().state, ConnectionState::Handshaking);

        mgr.apply_event(&ConnectionEvent::HandshakeSuccess).await;
        assert_eq!(mgr.get("remote-pc").await.unwrap().state, ConnectionState::Secured);

        mgr.apply_event(&ConnectionEvent::ConnectionLost("timeout".to_string())).await;
        assert_eq!(mgr.get("remote-pc").await.unwrap().state, ConnectionState::Reconnecting);

        mgr.apply_event(&ConnectionEvent::ReconnectSuccess).await;
        assert_eq!(mgr.get("remote-pc").await.unwrap().state, ConnectionState::Secured);

        mgr.apply_event(&ConnectionEvent::Disconnect).await;
        assert_eq!(mgr.get("remote-pc").await.unwrap().state, ConnectionState::Disconnected);
    });
}

/// IPv6 过滤
#[test]
fn test_e2e_ipv6_filtering() {
    assert!(!kirin_desk_core::network::is_global_unicast_ipv6(&"fe80::1".parse::<Ipv6Addr>().unwrap()));
    assert!(kirin_desk_core::network::is_global_unicast_ipv6(&"2001:db8::1".parse::<Ipv6Addr>().unwrap()));
    assert!(!kirin_desk_core::network::is_global_unicast_ipv6(&"::1".parse::<Ipv6Addr>().unwrap()));
}
