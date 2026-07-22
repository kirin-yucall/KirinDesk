//! GoDaddy DNS module — Kirin protocol style
//!
//! # DNS Layout (Kirin + SRV hybrid)
//!
//! Each device has its own subdomain: `{device_id}.{domain}`.
//!
//! ```text
//! _remote._tcp.{device_id}.{domain}  SRV  →  0 1 {port} {device_id}.{domain}.
//! {device_id}.{domain}               TXT  →  {"key":"ed25519:base64...","proto":"ip6desk","ver":"1"}
//! {device_id}.{domain}               AAAA →  2001:db8::1
//! ```
//!
//! - **SRV**: Port (standard DNS service discovery, ISP-proof)
//! - **TXT**: JSON metadata with Ed25519 public key
//! - **AAAA**: IPv6 address

pub mod godaddy;
pub mod srv;
pub mod aaaa;
pub mod txt;
pub mod discovery;
pub mod heartbeat;

pub use txt::DeviceMeta;
pub use discovery::{DiscoveryService, DeviceInfo, DiscoveryError, discover_device};
