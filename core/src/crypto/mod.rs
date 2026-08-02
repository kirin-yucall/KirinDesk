//! Zero-trust cryptography engine
//!
//! Implements the full cryptographic stack for KirinDesk:
//!
//! - **Ed25519**: Long-term identity key pairs, signing, verification
//! - **X25519**: Ephemeral key exchange (ECDH) for forward secrecy
//! - **AEAD**: AES-256-GCM symmetric encryption with HKDF key derivation
//! - **Handshake**: DNS public-key based mutual authentication protocol

pub mod ed25519;
pub mod x25519;
pub mod aead;
pub mod handshake;

// M12-MAC MAC-T006：macOS Keychain 身份存储（可选后端，默认文件式 PKCS#8）。
#[cfg(target_os = "macos")]
pub mod macos_keychain;

pub use ed25519::{Ed25519Error, IdentityManager};
pub use x25519::{EphemeralSession, X25519Error};
pub use aead::{AeadCipher, AeadError};

#[cfg(target_os = "macos")]
pub use macos_keychain::{KeychainError, MacosKeychain};
