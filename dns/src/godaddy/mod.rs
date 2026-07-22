//! # GoDaddy DNS API 客户端
//!
//! 提供对 GoDaddy Domains API 的完整访问，支持 SRV、AAAA、TXT 三种记录类型。

pub mod auth;
pub mod client;
pub mod error;
pub mod record;

pub use auth::Auth;
pub use client::GoDaddyClient;
pub use error::GoDaddyError;
pub use record::{Record, RecordType, SrvData, TxtKeyData};
