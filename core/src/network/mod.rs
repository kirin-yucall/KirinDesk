//! Network module: IPv4/IPv6 address detection and TCP wrappers
pub mod ipv4;
pub mod ipv6;
pub mod rate_limit;
pub mod tcp;

pub use ipv4::{get_global_ipv4, get_global_ipv4_addrs, is_global_unicast_ipv4, Ipv4Error};
pub use ipv6::{get_global_ipv6, get_global_ipv6_addrs, is_global_unicast_ipv6, Ipv6Error};
pub use rate_limit::{RateLimitDecision, RateLimiter, RateLimiterConfig};
