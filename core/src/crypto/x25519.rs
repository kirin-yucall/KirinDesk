use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey};
use zeroize::Zeroize;

/// Error types for X25519 operations.
#[derive(Debug, thiserror::Error)]
pub enum X25519Error {
    #[error("Failed to generate ephemeral key")]
    GenerationFailed,
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("ECDH key exchange failed")]
    ExchangeFailed,
}

/// RFC 7748 §6 低阶点黑名单（little-endian 32 字节编码，安全修复 S-04 / 审计 F-3）。
///
/// 低阶 u 坐标使 ECDH 共享密钥坍缩为可预测的小集合（配合公开 HKDF salt/info，
/// 会话密钥即公开常数）。黑名单覆盖：
///
/// - **规范低阶值（5 个，经独立 Montgomery ladder 数学验证）**：
///   - `0`（阶 2 点 (0,0)）、`1`（阶 4）、`a`（阶 8）、`b`（阶 8）—— 曲线 8-挠群；
///   - `p-1 ≡ -1`（阶 4，`f(-1)` 为非剩余 → 二次扭曲线点；见 S-04 验证记录）。
/// - **非规范编码（12 个）**：所有 `v < 2^256` 且 `v ≡ 低阶值 (mod p)` 的编码
///   （`p`、`p+1`、`2p`、`2p+1`、`2p-1`、`p+a`、`p+b`）。ladder 按 mod p 运算，
///   非规范编码与规范低阶值等价，同样危险。
/// - **第 255 位置位变体（5 个）**：经典 11 值清单收录 `u + 2^255` 变体
///   （防御屏蔽高位位的实现）。规范公钥恒 `< p < 2^255`，故无误伤。
///
/// 任一命中即拒绝；纵深防御第二层为 [`EphemeralSession::diffie_hellman`] 的
/// 全零输出检查（RFC 7748 §6.1：clamp 后标量恒为 8 的倍数 → 低阶点输入输出全零）。
const LOW_ORDER_POINTS: &[[u8; 32]; 17] = &[
    // ---- 规范低阶值（曲线 8-挠群 + 扭曲线 4-挠） ----
    // u = 0（阶 2；同时为"全零公钥"）
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // u = 1（阶 4）
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // u = a = 325606250916557431795983626356110631294008115727848805560023387167927233504（阶 8）
    [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
    // u = b = 39382357235489614581723060781553021112529911719440698176882885853963445705823（阶 8）
    [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
    // u = p - 1（阶 4，扭曲线点）
    [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    // ---- 非规范编码（v ≡ 低阶值 mod p，共 7 项；p、p+1、2p-1、2p、2p+1、p+a、p+b） ----
    // v = p（≡ 0）
    [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    // v = p + 1（≡ 1）
    [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    // v = 2p - 1（≡ p-1）
    [0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    // v = 2p（≡ 0）
    [0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    // v = 2p + 1（≡ 1）
    [0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    // v = p + a（≡ a）
    [0xcd, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x80],
    // v = p + b（≡ b）
    [0x4c, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0xd7],
    // ---- 第 255 位置位变体（经典 11 值清单收录，防御高位屏蔽实现；共 5 项） ----
    // u = 2^255（≡ 19，位 255 置位；高位被屏蔽时等价 u=0）
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
    // u = 2^255 + 1
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
    // u = 2^255 + p - 1
    [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    // u = 2^255 + a
    [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x80],
    // u = 2^255 + b
    [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0xd7],
];

/// An ephemeral X25519 key exchange session.
///
/// Generates a one-time key pair and can compute ECDH shared secrets
/// with multiple peers using the same ephemeral secret.
///
/// # Security Properties
///
/// - **Forward secrecy**: A new ephemeral key is generated per session.
/// - **Deniability**: Both parties contribute equally to the shared secret.
pub struct EphemeralSession {
    /// Our ephemeral secret key bytes.
    secret_bytes: [u8; 32],
    /// Our ephemeral public key (shared with the peer).
    public_key: PublicKey,
}

impl std::fmt::Debug for EphemeralSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralSession")
            .field("public_key", &self.public_key.to_bytes())
            .finish_non_exhaustive()
    }
}

impl EphemeralSession {
    /// Generate a new ephemeral X25519 key pair.
    pub fn new() -> Self {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        // Clamp the scalar for X25519
        secret_bytes[0] &= 248;
        secret_bytes[31] &= 127;
        secret_bytes[31] |= 64;

        let public = x25519_dalek::x25519(secret_bytes, x25519_dalek::X25519_BASEPOINT_BYTES);
        let public_key = PublicKey::from(public);

        Self {
            secret_bytes,
            public_key,
        }
    }

    /// Get our ephemeral public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// Get a reference to our public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Compute the shared ECDH secret with a peer's public key.
    ///
    /// Uses our stored ephemeral secret to ensure the same key
    /// is used consistently for all DH operations in this session.
    ///
    /// S-04 / 审计 F-3（纵深防御）：RFC 7748 §6.1 要求检查全零输出——clamp 后
    /// 标量恒为 8 的倍数，低阶点输入（黑名单见 [`LOW_ORDER_POINTS`]）必然输出
    /// 全零；此处对任意输入输出全零一律报 [`X25519Error::ExchangeFailed`]。
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> Result<[u8; 32], X25519Error> {
        self.diffie_hellman_bytes(&peer_public.to_bytes())
    }

    /// Compute the shared ECDH secret from raw peer public key bytes.
    ///
    /// 同 [`Self::diffie_hellman`]：全零输出 → [`X25519Error::ExchangeFailed`]。
    pub fn diffie_hellman_bytes(
        &self,
        peer_public_bytes: &[u8; 32],
    ) -> Result<[u8; 32], X25519Error> {
        let shared = x25519_dalek::x25519(self.secret_bytes, *peer_public_bytes);
        if shared.iter().all(|&b| b == 0) {
            return Err(X25519Error::ExchangeFailed);
        }
        Ok(shared)
    }

    /// Parse a peer's public key from raw bytes.
    ///
    /// S-04 / 审计 F-3：拒绝全零公钥与 RFC 7748 §6 低阶点黑名单
    /// （[`LOW_ORDER_POINTS`]，含非规范编码）——恶意对端以低阶 u 坐标使
    /// 会话密钥坍缩为公开常数（配合公开 HKDF salt/info → 流量公开可解密）。
    pub fn parse_public_key(bytes: &[u8; 32]) -> Result<PublicKey, X25519Error> {
        if bytes.iter().all(|&b| b == 0) {
            return Err(X25519Error::InvalidPublicKey(
                "all-zero public key is a low-order point (RFC 7748 §6)".to_string(),
            ));
        }
        if LOW_ORDER_POINTS.contains(bytes) {
            return Err(X25519Error::InvalidPublicKey(
                "peer public key is a low-order point (RFC 7748 §6)".to_string(),
            ));
        }
        Ok(PublicKey::from(*bytes))
    }

    /// Derive a 256-bit symmetric key from an ECDH shared secret using HKDF-SHA256.
    pub fn derive_session_key(shared_secret: &[u8; 32]) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(b"KirinDesk-session-key"), shared_secret);
        let mut okm = [0u8; 32];
        hk.expand(b"session-encryption-key", &mut okm)
            .expect("HKDF expansion should not fail for valid length");
        okm
    }

    /// Compute ECDH + derive session key in one step.
    ///
    /// S-04（纵深防御）：ECDH 全零输出 → [`X25519Error::ExchangeFailed`]，
    /// 不进入 HKDF。
    pub fn compute_session_key(&self, peer_public: &PublicKey) -> Result<[u8; 32], X25519Error> {
        let shared = self.diffie_hellman(peer_public)?;
        Ok(Self::derive_session_key(&shared))
    }
}

impl Default for EphemeralSession {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EphemeralSession {
    fn drop(&mut self) {
        self.secret_bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_key_generation() {
        let session = EphemeralSession::new();
        let pub_bytes = session.public_key_bytes();
        assert_eq!(pub_bytes.len(), 32);
        assert!(pub_bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_ecdh_shared_secret() {
        let alice = EphemeralSession::new();
        let bob = EphemeralSession::new();

        let alice_shared = alice.diffie_hellman(bob.public_key()).expect("valid peer key");
        let bob_shared = bob.diffie_hellman(alice.public_key()).expect("valid peer key");

        // Both parties compute the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_session_key_derivation() {
        let alice = EphemeralSession::new();
        let bob = EphemeralSession::new();

        let alice_key = alice.compute_session_key(bob.public_key()).expect("valid peer key");
        let bob_key = bob.compute_session_key(alice.public_key()).expect("valid peer key");

        // Both parties derive the same session key
        assert_eq!(alice_key, bob_key);
        assert!(alice_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_different_sessions_different_keys() {
        let alice1 = EphemeralSession::new();
        let bob1 = EphemeralSession::new();
        let key1 = alice1.compute_session_key(bob1.public_key()).expect("valid peer key");

        let alice2 = EphemeralSession::new();
        let bob2 = EphemeralSession::new();
        let key2 = alice2.compute_session_key(bob2.public_key()).expect("valid peer key");

        // Different sessions produce different keys (forward secrecy)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_multiple_dh_with_same_session() {
        let alice = EphemeralSession::new();
        let bob = EphemeralSession::new();
        let charlie = EphemeralSession::new();

        // Alice can DH with multiple peers using the same session
        let key_ab1 = alice.compute_session_key(bob.public_key()).expect("valid peer key");
        let key_ab2 = alice.compute_session_key(bob.public_key()).expect("valid peer key");
        let key_ac = alice.compute_session_key(charlie.public_key()).expect("valid peer key");

        // DH with the same peer produces the same key
        assert_eq!(key_ab1, key_ab2);
        // DH with different peer produces different key
        assert_ne!(key_ab1, key_ac);
    }

    #[test]
    fn test_public_key_derived_from_secret() {
        // Verify that public key is correctly derived from secret
        let session = EphemeralSession::new();
        let expected_pub = x25519_dalek::x25519(session.secret_bytes, x25519_dalek::X25519_BASEPOINT_BYTES);
        assert_eq!(session.public_key_bytes(), expected_pub);
    }

    // ---- S-04 / 审计 F-3: 全零公钥与低阶点拒绝 ----

    #[test]
    fn test_parse_public_key_rejects_all_zero() {
        let zero = [0u8; 32];
        match EphemeralSession::parse_public_key(&zero) {
            Err(X25519Error::InvalidPublicKey(msg)) => {
                assert!(msg.contains("all-zero"), "unexpected message: {msg}")
            }
            Ok(_) => panic!("all-zero public key must be rejected"),
            Err(other) => panic!("expected InvalidPublicKey, got {other:?}"),
        }
    }

    /// 低阶点黑名单全量拒绝（RFC 7748 §6 的 11 个经典值 + 非规范/高位变体，
    /// 共 17 个编码；含任务文档点名的 u=0、u=1、u=a 三个值）。
    #[test]
    fn test_parse_public_key_rejects_all_low_order_points() {
        assert_eq!(LOW_ORDER_POINTS.len(), 17, "blacklist size must match the verified table");
        for point in LOW_ORDER_POINTS {
            assert!(
                EphemeralSession::parse_public_key(point).is_err(),
                "low-order public key must be rejected: {:02x?}",
                &point[..]
            );
        }
    }

    /// 规范生成的对端公钥不被误伤（低阶检查无误报）。
    #[test]
    fn test_parse_public_key_accepts_valid_keys() {
        for _ in 0..16 {
            let peer = EphemeralSession::new();
            let parsed = EphemeralSession::parse_public_key(&peer.public_key_bytes())
                .expect("valid generated key must parse");
            assert_eq!(parsed.to_bytes(), peer.public_key_bytes());
        }
    }

    /// S-04b 纵深防御：直接以原始字节构造低阶点（绕过 parse_public_key 校验），
    /// diffie_hellman 全零输出 → ExchangeFailed。
    #[test]
    fn test_diffie_hellman_zero_output_rejected() {
        let session = EphemeralSession::new();

        // 全零公钥：x25519(任意私钥, 0) = 0（F-3 已数学验证）。
        let zero = PublicKey::from([0u8; 32]);
        match session.diffie_hellman(&zero) {
            Err(X25519Error::ExchangeFailed) => {}
            Ok(shared) => panic!("all-zero peer key must fail, got shared secret {shared:02x?}"),
            Err(other) => panic!("expected ExchangeFailed, got {other:?}"),
        }
        assert!(matches!(
            session.compute_session_key(&zero),
            Err(X25519Error::ExchangeFailed)
        ));

        // 非规范编码 u = p（≡ 0）：diffie_hellman_bytes 同样全零拒绝。
        let p_bytes: [u8; 32] = [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(matches!(
            session.diffie_hellman_bytes(&p_bytes),
            Err(X25519Error::ExchangeFailed)
        ));

        // u = 1（阶 4）：clamp 后标量为 8 的倍数 → [8k]P = O → 输出全零 → 拒绝。
        let u1 = PublicKey::from([1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            session.diffie_hellman(&u1),
            Err(X25519Error::ExchangeFailed)
        ));
    }

    /// 正常对端公钥的共享密钥非全零（与现有 ECDH 用例一致，确认无误伤）。
    #[test]
    fn test_diffie_hellman_valid_key_not_zero() {
        let alice = EphemeralSession::new();
        let bob = EphemeralSession::new();
        let shared = alice.diffie_hellman(bob.public_key()).expect("valid peer key");
        assert!(shared.iter().any(|&b| b != 0));
        // 往返一致性（S-04b 引入 Result 后行为不变）。
        let bob_shared = bob.diffie_hellman(alice.public_key()).expect("valid peer key");
        assert_eq!(shared, bob_shared);
    }
}
