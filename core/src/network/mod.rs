//! Network module: IPv6 address detection and TCP wrappers
pub mod ipv6;
pub mod rate_limit;
pub mod tcp;

pub use ipv6::{get_global_ipv6, get_global_ipv6_addrs, is_global_unicast_ipv6, Ipv6Error};
pub use rate_limit::{RateLimitDecision, RateLimiter, RateLimiterConfig};
