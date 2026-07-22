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

pub use ed25519::{Ed25519Error, IdentityManager};
pub use x25519::{EphemeralSession, X25519Error};
pub use aead::{AeadCipher, AeadError};
