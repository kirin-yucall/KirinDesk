//! Network module: IPv4/IPv6 address detection and TCP wrappers
pub mod ipv4;
pub mod ipv6;
pub mod rate_limit;
pub mod tcp;

pub use ipv4::{get_global_ipv4, get_global_ipv4_addrs, is_global_unicast_ipv4, Ipv4Error};
pub use ipv6::{get_global_ipv6, get_global_ipv6_addrs, is_global_unicast_ipv6, Ipv6Error};
pub use rate_limit::{RateLimitDecision, RateLimiter, RateLimiterConfig};

/// : 本机地址可达性三态（Dashboard 网络状态卡 IPv4/IPv6 判定用）。
///
/// 纯本机地址分类（getifaddrs/系统接口信息），**不引入网络探测开销
/// （GUI 每帧）也不外呼外部 IP 服务**（项目无遥测红线）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reachability {
    /// 无该地址族地址（协议未启用 / 无接口地址）。
    #[default]
    Unavailable,
    /// 有地址但非公网——IPv4：私网（RFC1918）/CGNAT/链路本地/保留段；
    /// IPv6：仅链路本地/ULA/过渡隧道（Teredo/6to4/ORCHID）等，对端不可直连。
    NonPublic,
    /// 公网全局单播地址（对端可直连）。
    Public,
}
