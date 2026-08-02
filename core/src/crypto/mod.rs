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
// S-05 (F-4)：统一密钥存储后端抽象（DPAPI / Keychain / secret-tool / 文件主密钥兜底）
pub mod keystore;
// S-05b-1：Windows DPAPI（CryptProtectData，dlopen crypt32.dll）
#[cfg(target_os = "windows")]
pub mod windows_dpapi;

// M12-MAC MAC-T006 + S-05 (F-4)：macOS Keychain 身份存储，已接入 KeyStore
// 抽象并成为 macOS 默认后端；不可用时降级到 keystore 文件主密钥兜底。
#[cfg(target_os = "macos")]
pub mod macos_keychain;

pub use ed25519::{Ed25519Error, IdentityManager};
pub use x25519::{EphemeralSession, X25519Error};
pub use aead::{AeadCipher, AeadError};
// S-05：KeyStore 抽象与默认后端选择（R-13 配置加密将复用本抽象）
pub use keystore::{default_backend, KeyStore, KeyStoreError};

#[cfg(target_os = "macos")]
pub use macos_keychain::{KeychainError, MacosKeychain};
#[cfg(target_os = "windows")]
pub use windows_dpapi::DpapiKeyStore;
