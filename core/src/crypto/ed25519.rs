use chacha20poly1305::KeyInit;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::AeadInPlace;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroize;

/// Error types for Ed25519 operations.
#[derive(Debug, thiserror::Error)]
pub enum Ed25519Error {
    #[error("Failed to generate key pair")]
    GenerationFailed,
    #[error("Invalid private key data")]
    InvalidPrivateKey,
    #[error("Invalid public key data: {0}")]
    InvalidPublicKey(String),
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
}

/// Format for serialized encrypted private key data.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedPrivateKey {
    /// Nonce used for ChaCha20Poly1305 encryption.
    nonce: [u8; 12],
    /// Encrypted private key bytes.
    ciphertext: Vec<u8>,
}

/// Identity key manager for Ed25519 long-term identity keys.
///
/// Each device generates one Ed25519 key pair at first boot.
/// The private key is stored encrypted on disk; the public key
/// is uploaded to DNS TXT records for peer verification.
pub struct IdentityManager {
    /// Ed25519 signing key (private key).
    signing_key: SigningKey,
    /// Ed25519 verifying key (public key).
    verifying_key: VerifyingKey,
    /// Path to the encrypted key file.
    key_path: PathBuf,
}

impl std::fmt::Debug for IdentityManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityManager")
            .field("verifying_key", &self.verifying_key.to_bytes())
            .field("key_path", &self.key_path)
            .finish_non_exhaustive()
    }
}

impl IdentityManager {
    /// Generate a new Ed25519 identity key pair.
    pub fn generate(key_path: PathBuf) -> Result<Self, Ed25519Error> {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        secret_bytes.zeroize();

        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
            key_path,
        })
    }

    /// Save the private key encrypted to disk using ChaCha20Poly1305.
    pub fn save(&self, encryption_key: &[u8; 32]) -> Result<(), Ed25519Error> {
        let key_bytes = self.signing_key.to_bytes();

        let key = Key::from_slice(encryption_key);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buffer = key_bytes.to_vec();
        cipher
            .encrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|e| Ed25519Error::Encryption(e.to_string()))?;

        let encrypted = EncryptedPrivateKey {
            nonce: nonce_bytes,
            ciphertext: buffer,
        };

        let json = serde_json::to_string(&encrypted)
            .map_err(|e| Ed25519Error::Serialization(e.to_string()))?;

        if let Some(parent) = self.key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.key_path, &json)?;

        Ok(())
    }

    /// Load the private key from encrypted disk storage.
    pub fn load(key_path: PathBuf, encryption_key: &[u8; 32]) -> Result<Self, Ed25519Error> {
        let json = std::fs::read_to_string(&key_path)?;
        let encrypted: EncryptedPrivateKey = serde_json::from_str(&json)
            .map_err(|e| Ed25519Error::Serialization(e.to_string()))?;

        let key = Key::from_slice(encryption_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let mut buffer = encrypted.ciphertext;
        cipher
            .decrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|_| Ed25519Error::Encryption("decryption failed".to_string()))?;

        let key_array: [u8; 32] = buffer
            .try_into()
            .map_err(|_| Ed25519Error::InvalidPrivateKey)?;
        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
            key_path,
        })
    }

    /// Sign a message with the private key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature against the public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify(message, signature).is_ok()
    }

    /// Verify a signature for a given public key (static method).
    pub fn verify_with_key(
        public_key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> bool {
        public_key.verify(message, signature).is_ok()
    }

    /// Get the public key (VerifyingKey).
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the public key encoded as Base64 (for DNS TXT records).
    pub fn public_key_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.verifying_key.to_bytes())
    }

    /// Parse a Base64-encoded Ed25519 public key.
    pub fn parse_public_key(base64_key: &str) -> Result<VerifyingKey, Ed25519Error> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|e| Ed25519Error::InvalidPublicKey(e.to_string()))?;

        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Ed25519Error::InvalidPublicKey("expected 32 bytes".to_string()))?;

        VerifyingKey::from_bytes(&array).map_err(|e| Ed25519Error::InvalidPublicKey(e.to_string()))
    }

    /// Get the signing key reference.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Load from disk, or generate + save if not found.
    /// Uses SHA-256(device_id) as encryption key.
    pub fn load_or_generate(key_path: PathBuf, device_id: &str) -> Result<Self, Ed25519Error> {
        if key_path.exists() {
            let enc_key = derive_identity_key(device_id);
            Self::load(key_path, &enc_key)
        } else {
            let id = Self::generate(key_path)?;
            let enc_key = derive_identity_key(device_id);
            id.save(&enc_key)?;
            Ok(id)
        }
    }

    /// Default identity file path: ~/.kirin_desk/identity/ed25519.json
    pub fn default_path() -> Result<PathBuf, Ed25519Error> {
        let home = dirs_next::home_dir()
            .ok_or_else(|| Ed25519Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound, "no home dir")))?;
        Ok(home.join(".kirin_desk").join("identity").join("ed25519.json"))
    }
}

/// Derive a 32-byte encryption key from a device ID.
fn derive_identity_key(device_id: &str) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"kirindesk-identity-key:");
    hasher.update(device_id.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// 公钥指纹（M15 / SRV-SEC-KH-003）：base64 公钥 → SHA-256 → 小写十六进制、
/// 每 4 字符冒号分组（如 `a1b2:c3d4:...`，64 位十六进制 = 16 组）。
///
/// 与 `kirin-desk-utils::known_hosts::fingerprint` 算法一致（两侧均以
/// base64 公钥为输入），用于服务端返回指纹（`HandshakeResponse.server_fingerprint`）
/// 与客户端 known_hosts 指纹比对。
pub fn fingerprint(public_key_base64: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(public_key_base64.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join(":")
}

impl Drop for IdentityManager {
    fn drop(&mut self) {
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encryption_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn test_generate_key_pair() {
        let path = std::env::temp_dir().join("kirin_desk_test_ed25519");
        let manager = IdentityManager::generate(path).unwrap();
        let pub_key = manager.public_key();
        assert_eq!(pub_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let path = std::env::temp_dir().join("kirin_desk_test_sign");
        let manager = IdentityManager::generate(path).unwrap();

        let message = b"Hello, KirinDesk!";
        let signature = manager.sign(message);
        assert!(manager.verify(message, &signature));
        assert!(!manager.verify(b"Tampered message", &signature));
    }

    #[test]
    fn test_save_and_load() {
        let path = std::env::temp_dir().join("kirin_desk_test_save_load.json");
        let _ = std::fs::remove_file(&path);

        let encryption_key = test_encryption_key();
        let pub_key_base64;

        {
            let manager = IdentityManager::generate(path.clone()).unwrap();
            pub_key_base64 = manager.public_key_base64();
            manager.save(&encryption_key).unwrap();
        }

        {
            let loaded = IdentityManager::load(path.clone(), &encryption_key).unwrap();
            assert_eq!(loaded.public_key_base64(), pub_key_base64);

            let message = b"Round trip test";
            let signature = loaded.sign(message);
            assert!(loaded.verify(message, &signature));
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_public_key_base64_roundtrip() {
        let path = std::env::temp_dir().join("kirin_desk_test_base64");
        let manager = IdentityManager::generate(path).unwrap();

        let b64 = manager.public_key_base64();
        let parsed = IdentityManager::parse_public_key(&b64).unwrap();
        assert_eq!(manager.public_key().to_bytes(), parsed.to_bytes());
    }

    #[test]
    fn test_invalid_public_key() {
        let result = IdentityManager::parse_public_key("invalid-base64!!!");
        assert!(result.is_err());
    }
}
