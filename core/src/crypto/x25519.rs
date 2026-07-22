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
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> [u8; 32] {
        x25519_dalek::x25519(self.secret_bytes, peer_public.to_bytes())
    }

    /// Compute the shared ECDH secret from raw peer public key bytes.
    pub fn diffie_hellman_bytes(&self, peer_public_bytes: &[u8; 32]) -> [u8; 32] {
        x25519_dalek::x25519(self.secret_bytes, *peer_public_bytes)
    }

    /// Parse a peer's public key from raw bytes.
    pub fn parse_public_key(bytes: &[u8; 32]) -> PublicKey {
        PublicKey::from(*bytes)
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
    pub fn compute_session_key(&self, peer_public: &PublicKey) -> [u8; 32] {
        let shared = self.diffie_hellman(peer_public);
        Self::derive_session_key(&shared)
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

        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());

        // Both parties compute the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_session_key_derivation() {
        let alice = EphemeralSession::new();
        let bob = EphemeralSession::new();

        let alice_key = alice.compute_session_key(bob.public_key());
        let bob_key = bob.compute_session_key(alice.public_key());

        // Both parties derive the same session key
        assert_eq!(alice_key, bob_key);
        assert!(alice_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_different_sessions_different_keys() {
        let alice1 = EphemeralSession::new();
        let bob1 = EphemeralSession::new();
        let key1 = alice1.compute_session_key(bob1.public_key());

        let alice2 = EphemeralSession::new();
        let bob2 = EphemeralSession::new();
        let key2 = alice2.compute_session_key(bob2.public_key());

        // Different sessions produce different keys (forward secrecy)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_multiple_dh_with_same_session() {
        let alice = EphemeralSession::new();
        let bob = EphemeralSession::new();
        let charlie = EphemeralSession::new();

        // Alice can DH with multiple peers using the same session
        let key_ab1 = alice.compute_session_key(bob.public_key());
        let key_ab2 = alice.compute_session_key(bob.public_key());
        let key_ac = alice.compute_session_key(charlie.public_key());

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
}
