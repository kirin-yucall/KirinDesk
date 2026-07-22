//! Connection management
pub mod manager;
pub mod reconnection;
pub mod secure_channel;

pub use manager::{ConnectionManager, ConnectionState, ConnectionEvent, ManagedConnection};
pub use secure_channel::SecureChannel;
