use std::net::Ipv4Addr;

/// Error types for IPv4 address detection.
#[derive(Debug, thiserror::Error)]
pub enum Ipv4Error {
    #[error("No global unicast IPv4 address found")]
    NoGlobalIpv4,

    #[error("Network interface error: {0}")]
    InterfaceError(String),
}

use tracing::{debug, trace};

/// Get the global unicast IPv4 address(es) for this machine.
///
/// Filters out:
/// - Loopback (127.0.0.0/8)
/// - Link-local (169.254.0.0/16)
/// - Multicast
/// - Unspecified
///
/// Returns all qualifying addresses found.
pub fn get_global_ipv4_addrs() -> Result<Vec<Ipv4Addr>, Ipv4Error> {
    let mut addrs = Vec::new();

    let ifaces =
        get_if_addrs::get_if_addrs().map_err(|e| Ipv4Error::InterfaceError(e.to_string()))?;

    debug!("IPv4 detection: found {} network interfaces", ifaces.len());

    for iface in &ifaces {
        if let get_if_addrs::IfAddr::V4(ifv4) = &iface.addr {
            let v4 = ifv4.ip;

            // Skip loopback
            if v4.is_loopback() {
                trace!("IPv4 detection: skip loopback {}", v4);
                continue;
            }
            // Skip link-local (169.254.0.0/16)
            if v4.is_link_local() {
                trace!("IPv4 detection: skip link-local {}", v4);
                continue;
            }
            // Skip multicast
            if v4.is_multicast() {
                trace!("IPv4 detection: skip multicast {}", v4);
                continue;
            }
            // Skip unspecified
            if v4.is_unspecified() {
                trace!("IPv4 detection: skip unspecified {}", v4);
                continue;
            }

            trace!("IPv4 detection: accept global {}", v4);
            addrs.push(v4);
        }
    }

    if addrs.is_empty() {
        debug!("IPv4 detection: no global IPv4 address found");
        Err(Ipv4Error::NoGlobalIpv4)
    } else {
        debug!("IPv4 detection: found {} global IPv4 address(es): {:?}", addrs.len(), addrs);
        Ok(addrs)
    }
}

/// Get the preferred global IPv4 address (first found).
pub fn get_global_ipv4() -> Result<Ipv4Addr, Ipv4Error> {
    get_global_ipv4_addrs()?
        .into_iter()
        .next()
        .ok_or(Ipv4Error::NoGlobalIpv4)
}

/// Check if an address is a global unicast IPv4 address suitable for P2P.
pub fn is_global_unicast_ipv4(addr: &Ipv4Addr) -> bool {
    if addr.is_loopback() || addr.is_multicast() || addr.is_unspecified() {
        return false;
    }
    // 169.254.0.0/16 = link-local
    if addr.is_link_local() {
        return false;
    }
    true
}

/// M8-T036: 是否**公网** IPv4 地址（对端可直接访问的全局单播）。
///
/// 在 `is_global_unicast_ipv4`（仅过滤环回/链路本地/组播）基础上进一步剔除
/// 私网与保留段——局域网可达 ≠ 公网可达，公网检测据此判定「无公网 → 内网穿透」：
/// - RFC 1918 私网：`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`
/// - CGNAT 共享地址段：`100.64.0.0/10`（运营商级 NAT）
/// - 保留/基准/文档段：`0.0.0.0/8`、`127.0.0.0/8`、`169.254.0.0/16`、
///   `192.0.0.0/24`、`192.0.2.0/24`（TEST-NET-1）、`198.18.0.0/15`、
///   `198.51.100.0/24`（TEST-NET-2）、`203.0.113.0/24`（TEST-NET-3）、
///   `224.0.0.0/4`（组播）、`240.0.0.0/4`（保留）
pub fn is_public_ipv4(addr: &Ipv4Addr) -> bool {
    let oct = addr.octets();
    match oct[0] {
        0 => false,                       // 0.0.0.0/8 保留
        10 => false,                      // 10.0.0.0/8 私网
        100 if (64..=127).contains(&oct[1]) => false, // 100.64.0.0/10 CGNAT
        127 => false,                     // 127.0.0.0/8 环回
        169 if oct[1] == 254 => false,    // 169.254.0.0/16 链路本地
        172 if (16..=31).contains(&oct[1]) => false, // 172.16.0.0/12 私网
        192 if oct[1] == 168 => false,    // 192.168.0.0/16 私网
        192 if oct[1] == 0 && oct[2] == 0 => false, // 192.0.0.0/24 保留
        192 if oct[1] == 0 && oct[2] == 2 => false, // 192.0.2.0/24 TEST-NET-1
        198 if oct[1] == 18 || oct[1] == 19 => false, // 198.18.0.0/15 基准
        198 if oct[1] == 51 && oct[2] == 100 => false, // 198.51.100.0/24 TEST-NET-2
        203 if oct[1] == 0 && oct[2] == 113 => false, // 203.0.113.0/24 TEST-NET-3
        224..=239 => false,               // 224.0.0.0/4 组播
        240..=255 => false,               // 240.0.0.0/4 保留
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_global_unicast_rejects_loopback() {
        let addr: Ipv4Addr = "127.0.0.1".parse().unwrap();
        assert!(!is_global_unicast_ipv4(&addr));
    }

    #[test]
    fn test_is_global_unicast_rejects_link_local() {
        let addr: Ipv4Addr = "169.254.1.1".parse().unwrap();
        assert!(!is_global_unicast_ipv4(&addr));
    }

    #[test]
    fn test_is_global_unicast_accepts_global() {
        let addr: Ipv4Addr = "8.8.8.8".parse().unwrap();
        assert!(is_global_unicast_ipv4(&addr));
    }

    #[test]
    fn test_is_global_unicast_accepts_private() {
        // 私有段（RFC 1918）也可用于局域网 P2P 直连，保留（同 IPv6 ULA 语义）。
        let addr: Ipv4Addr = "192.168.1.5".parse().unwrap();
        assert!(is_global_unicast_ipv4(&addr));
    }

    #[test]
    fn test_is_public_ipv4_rejects_private_and_reserved() {
        for s in [
            "10.1.2.3",       // RFC1918 A
            "172.16.0.1",     // RFC1918 B
            "172.31.255.255", // RFC1918 B 边界
            "192.168.1.5",    // RFC1918 C
            "100.64.0.1",     // CGNAT
            "100.127.255.254", // CGNAT 边界
            "169.254.10.10",  // 链路本地
            "127.0.0.1",      // 环回
            "0.0.0.0",        // 保留
            "192.0.2.1",      // TEST-NET-1
            "198.51.100.7",   // TEST-NET-2
            "203.0.113.9",    // TEST-NET-3
            "198.18.0.1",     // 基准
            "224.0.0.1",      // 组播
            "240.0.0.1",      // 保留
        ] {
            let addr: Ipv4Addr = s.parse().unwrap();
            assert!(!is_public_ipv4(&addr), "{} 不应判为公网", s);
        }
    }

    #[test]
    fn test_is_public_ipv4_accepts_public() {
        for s in ["8.8.8.8", "114.114.114.114", "1.2.3.4", "172.32.0.1"] {
            let addr: Ipv4Addr = s.parse().unwrap();
            assert!(is_public_ipv4(&addr), "{} 应判为公网", s);
        }
    }

    #[test]
    fn test_is_global_unicast_rejects_multicast() {
        let addr: Ipv4Addr = "224.0.0.1".parse().unwrap();
        assert!(!is_global_unicast_ipv4(&addr));
    }

    #[test]
    fn test_is_global_unicast_rejects_unspecified() {
        let addr: Ipv4Addr = "0.0.0.0".parse().unwrap();
        assert!(!is_global_unicast_ipv4(&addr));
    }
}
