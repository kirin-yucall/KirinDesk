use aes_gcm::{AeadInPlace, Aes256Gcm, Key, Nonce};
use aes_gcm::KeyInit;
use rand::rngs::OsRng;
use rand::RngCore;

/// Error types for AEAD encryption operations.
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: ciphertext tampered or wrong key")]
    DecryptionFailed,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid nonce")]
    InvalidNonce,
}

/// AEAD cipher for session encryption using AES-256-GCM.
///
/// Provides authenticated encryption with additional authenticated data (AAD).
/// The key is derived from an ECDH shared secret via HKDF-SHA256.
pub struct AeadCipher {
    /// AES-256-GCM cipher instance.
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for AeadCipher {
    /// 摘要 Debug：`Aes256Gcm`（aead crate）本身不实现 Debug，且会话密钥
    /// 属敏感数据——禁止输出密钥材料到日志/测试输出。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadCipher").finish_non_exhaustive()
    }
}

impl AeadCipher {
    /// Create a new AEAD cipher from a 32-byte session key.
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    /// Encrypt plaintext with associated data (AAD).
    ///
    /// Returns `(nonce, ciphertext)` where nonce is 12 random bytes
    /// and ciphertext includes the 16-byte GCM authentication tag.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AeadError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = plaintext.to_vec();
        self.cipher
            .encrypt_in_place(nonce, aad, &mut ciphertext)
            .map_err(|e| AeadError::EncryptionFailed(e.to_string()))?;

        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    /// Decrypt ciphertext with associated data (AAD).
    ///
    /// Returns the original plaintext on success.
    /// Returns `AeadError::DecryptionFailed` if the ciphertext was tampered.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &mut Vec<u8>,
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let nonce = Nonce::from_slice(nonce);

        self.cipher
            .decrypt_in_place(nonce, aad, ciphertext)
            .map_err(|_| AeadError::DecryptionFailed)?;

        Ok(ciphertext.clone())
    }

    /// Convenience: encrypt with empty AAD.
    pub fn encrypt_simple(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AeadError> {
        self.encrypt(plaintext, b"")
    }

    /// Convenience: decrypt with empty AAD.
    pub fn decrypt_simple(&self, nonce: &[u8], ciphertext: &mut Vec<u8>) -> Result<Vec<u8>, AeadError> {
        self.decrypt(nonce, ciphertext, b"")
    }

    /// Generate a random 32-byte encryption key (for local key storage).
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = AeadCipher::generate_key();
        let cipher = AeadCipher::new(&key);

        let plaintext = b"Hello, KirinDesk secure channel!";
        let (nonce, mut ciphertext) = cipher.encrypt_simple(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = cipher.decrypt_simple(&nonce, &mut ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_with_aad() {
        let key = AeadCipher::generate_key();
        let cipher = AeadCipher::new(&key);

        let plaintext = b"Sensitive data";
        let aad = b"session-context";
        let (nonce, mut ciphertext) = cipher.encrypt(plaintext, aad).unwrap();

        let decrypted = cipher.decrypt(&nonce, &mut ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_aad_fails() {
        let key = AeadCipher::generate_key();
        let cipher = AeadCipher::new(&key);

        let plaintext = b"Sensitive data";
        let (nonce, mut ciphertext) = cipher.encrypt(plaintext, b"correct-aad").unwrap();

        let result = cipher.decrypt(&nonce, &mut ciphertext, b"wrong-aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_detected() {
        let key = AeadCipher::generate_key();
        let cipher = AeadCipher::new(&key);

        let plaintext = b"Data to protect";
        let (nonce, mut ciphertext) = cipher.encrypt_simple(plaintext).unwrap();

        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = cipher.decrypt_simple(&nonce, &mut ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keys_produce_different_ciphertexts() {
        let key1 = AeadCipher::generate_key();
        let key2 = AeadCipher::generate_key();
        let cipher1 = AeadCipher::new(&key1);
        let cipher2 = AeadCipher::new(&key2);

        let plaintext = b"Same plaintext";
        let (_, ct1) = cipher1.encrypt_simple(plaintext).unwrap();
        let (_, ct2) = cipher2.encrypt_simple(plaintext).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_large_data() {
        let key = AeadCipher::generate_key();
        let cipher = AeadCipher::new(&key);

        let large_data = vec![0xABu8; 10000];
        let (nonce, mut ciphertext) = cipher.encrypt_simple(&large_data).unwrap();
        let decrypted = cipher.decrypt_simple(&nonce, &mut ciphertext).unwrap();

        assert_eq!(decrypted.len(), large_data.len());
        assert_eq!(decrypted, large_data);
    }
}
