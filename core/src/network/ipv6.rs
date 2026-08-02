use std::net::Ipv6Addr;

/// Error types for IPv6 address detection.
#[derive(Debug, thiserror::Error)]
pub enum Ipv6Error {
    #[error("No global unicast IPv6 address found")]
    NoGlobalIpv6,

    #[error("Network interface error: {0}")]
    InterfaceError(String),
}

use tracing::{debug, trace};

/// Get the global unicast IPv6 address(es) for this machine.
///
/// Filters out:
/// - Link-local addresses (fe80::/10)
/// - Loopback (::1)
/// - Multicast
/// - Unspecified
///
/// Returns all qualifying addresses found.
pub fn get_global_ipv6_addrs() -> Result<Vec<Ipv6Addr>, Ipv6Error> {
    let mut addrs = Vec::new();

    let ifaces =
        get_if_addrs::get_if_addrs().map_err(|e| Ipv6Error::InterfaceError(e.to_string()))?;

    debug!("IPv6 detection: found {} network interfaces", ifaces.len());

    for iface in &ifaces {
        if let get_if_addrs::IfAddr::V6(ifv6) = &iface.addr {
            let v6 = ifv6.ip;

            // Skip loopback
            if v6.is_loopback() {
                trace!("IPv6 detection: skip loopback {}", v6);
                continue;
            }
            // Skip link-local (fe80::/10)
            let octets = v6.octets();
            if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                trace!("IPv6 detection: skip link-local {}", v6);
                continue;
            }
            // Skip multicast
            if v6.is_multicast() {
                trace!("IPv6 detection: skip multicast {}", v6);
                continue;
            }
            // Skip unspecified
            if v6.is_unspecified() {
                trace!("IPv6 detection: skip unspecified {}", v6);
                continue;
            }

            trace!("IPv6 detection: accept global {}", v6);
            addrs.push(v6);
        }
    }

    if addrs.is_empty() {
        debug!("IPv6 detection: no global IPv6 address found");
        Err(Ipv6Error::NoGlobalIpv6)
    } else {
        debug!("IPv6 detection: found {} global IPv6 address(es): {:?}", addrs.len(), addrs);
        Ok(addrs)
    }
}

/// Get the preferred global IPv6 address (first found).
pub fn get_global_ipv6() -> Result<Ipv6Addr, Ipv6Error> {
    get_global_ipv6_addrs()?
        .into_iter()
        .next()
        .ok_or(Ipv6Error::NoGlobalIpv6)
}

/// Check if an address is a global unicast IPv6 address suitable for P2P.
pub fn is_global_unicast_ipv6(addr: &Ipv6Addr) -> bool {
    if addr.is_loopback() || addr.is_multicast() || addr.is_unspecified() {
        return false;
    }
    let octets = addr.octets();
    // fe80::/10 = link-local
    if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
        return false;
    }
    true
}

/// M8-T036: 是否**公网** IPv6 地址（对端可直接访问的全局单播）。
///
/// 在 `is_global_unicast_ipv6`（仅过滤环回/链路本地/组播/未指定）基础上进一步
/// 剔除**非公网可达**段（公网检测据此判定「无公网 → 内网穿透」）：
/// - `fc00::/7` 唯一本地地址 ULA（`fd00::1` 等，局域网可达 ≠ 公网可达）
/// - `fe80::/10` 链路本地、`::1` 环回、`::` 未指定、`ff00::/8` 组播
/// - `2001:db8::/32` 文档示例段（RIPE NCC 保留）
pub fn is_public_ipv6(addr: &Ipv6Addr) -> bool {
    if addr.is_loopback() || addr.is_multicast() || addr.is_unspecified() {
        return false;
    }
    let octets = addr.octets();
    // fe80::/10 = link-local
    if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
        return false;
    }
    // fc00::/7 = ULA（唯一本地地址）
    if octets[0] == 0xfc || octets[0] == 0xfd {
        return false;
    }
    // 2001:db8::/32 = 文档示例
    if octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_global_unicast_rejects_loopback() {
        let addr: Ipv6Addr = "::1".parse().unwrap();
        assert!(!is_global_unicast_ipv6(&addr));
    }

    #[test]
    fn test_is_global_unicast_rejects_link_local() {
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(!is_global_unicast_ipv6(&addr));
    }

    #[test]
    fn test_is_global_unicast_accepts_global() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(is_global_unicast_ipv6(&addr));
    }

    #[test]
    fn test_is_global_unicast_accepts_ula() {
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(is_global_unicast_ipv6(&addr));
    }

    #[test]
    fn test_is_public_ipv6_rejects_non_public() {
        for s in [
            "fd00::1",     // ULA
            "fc00::1",     // ULA
            "fe80::1",     // 链路本地
            "::1",         // 环回
            "::",          // 未指定
            "ff02::1",     // 组播
            "2001:db8::1", // 文档示例
        ] {
            let addr: Ipv6Addr = s.parse().unwrap();
            assert!(!is_public_ipv6(&addr), "{} 不应判为公网", s);
        }
    }

    #[test]
    fn test_is_public_ipv6_accepts_public() {
        for s in ["2408:4000::1", "2606:4700:4700::1111", "2001:4860:4860::8888"] {
            let addr: Ipv6Addr = s.parse().unwrap();
            assert!(is_public_ipv6(&addr), "{} 应判为公网", s);
        }
    }

    #[test]
    fn test_is_global_unicast_rejects_multicast() {
        let addr: Ipv6Addr = "ff02::1".parse().unwrap();
        assert!(!is_global_unicast_ipv6(&addr));
    }

    #[test]
    fn test_is_global_unicast_rejects_unspecified() {
        let addr: Ipv6Addr = "::".parse().unwrap();
        assert!(!is_global_unicast_ipv6(&addr));
    }
}
