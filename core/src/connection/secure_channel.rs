/// Secure channel wrapper — re-exported from handshake module.
///
/// The `SecureChannel` struct and its encrypt/decrypt methods
/// are defined in `crate::crypto::handshake` alongside the
/// handshake protocol. This module re-exports for convenience.
pub use crate::crypto::handshake::SecureChannel;
