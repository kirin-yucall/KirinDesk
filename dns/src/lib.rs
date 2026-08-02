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
//! {device_id}.{domain}               A    →  203.0.113.7   (IPv4-only / dual-stack 设备)
//! ```
//!
//! - **SRV**: Port (standard DNS service discovery, ISP-proof)
//! - **TXT**: JSON metadata with Ed25519 public key
//! - **AAAA**: IPv6 address (optional; absent → `Ipv6Addr::UNSPECIFIED` 哨兵)
//! - **A**: IPv4 address (optional)

pub mod a;
pub mod aaaa;
pub mod discovery;
pub mod godaddy;
pub mod heartbeat;
pub mod srv;
pub mod txt;

#[cfg(test)]
pub mod test_support;

pub use discovery::{discover_device, DeviceInfo, DiscoveryError, DiscoveryService, IpFamily};
pub use txt::DeviceMeta;
