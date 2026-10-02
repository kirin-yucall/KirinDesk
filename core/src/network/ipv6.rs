use std::net::Ipv6Addr;

use crate::network::Reachability;

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

///
/// 在 `is_global_unicast_ipv6`（仅过滤环回/链路本地/组播/未指定）基础上进一步
/// 剔除**非公网可达**段（公网检测据此判定「无公网 → 内网穿透」）：
/// - `fc00::/7` 唯一本地地址 ULA（`fd00::1` 等，局域网可达 ≠ 公网可达）
/// - `fe80::/10` 链路本地、`::1` 环回、`::` 未指定、`ff00::/8` 组播
/// - `2001:db8::/32` 文档示例段（RIPE NCC 保留）
///
/// 把它们当公网 → 是「IPv6 未启用仍标绿」的根因之一）：
/// - `2001:0000::/32` Teredo、`2002::/16` 6to4（Windows 隧道适配器常驻时
///   会带这类「全局形」地址）
/// - `2001:0010::/28` ORCHID、`2001:0020::/28` ORCHIDv2（保留/重叠路由）
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
    if octets[0] == 0x20 && octets[1] == 0x02 {
        return false;
    }
    if octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x00 && octets[3] == 0x00 {
        return false;
    }
    // /28 = 2001（16 位）+ 第二 hextet 高 12 位（bits 16-27）固定 → octets[2]=0x00
    // 且 octets[3] 高半字节为 0x1（ORCHID）/ 0x2（ORCHIDv2）。
    if octets[0] == 0x20
        && octets[1] == 0x01
        && octets[2] == 0x00
        && ((octets[3] & 0xf0) == 0x10 || (octets[3] & 0xf0) == 0x20)
    {
        return false;
    }
    true
}

/// `public` = 是否存在公网 IPv6 地址（`is_public_ipv6`）。供 [`reachability`]
/// 与本 crate 外部（GUI 状态映射 / 单测）复用。
pub fn classify(any: bool, public: bool) -> Reachability {
    if !any {
        Reachability::Unavailable
    } else if public {
        Reachability::Public
    } else {
        Reachability::NonPublic
    }
}

pub fn classify_addr(addr: Option<Ipv6Addr>) -> Reachability {
    match addr {
        None => Reachability::Unavailable,
        Some(a) if is_public_ipv6(&a) => Reachability::Public,
        Some(_) => Reachability::NonPublic,
    }
}

/// 无任何地址（协议未启用/无接口）→ [`Reachability::Unavailable`]；存在
/// 公网地址 → [`Reachability::Public`]；否则（仅链路本地 / ULA / 过渡隧道）
/// → [`Reachability::NonPublic`]。纯本机地址分类，**无网络探测 / 无外呼**。
pub fn reachability() -> Reachability {
    let mut any = false;
    let mut public = false;
    if let Ok(ifaces) = get_if_addrs::get_if_addrs() {
        for iface in ifaces {
            if let get_if_addrs::IfAddr::V6(ifv6) = &iface.addr {
                let a = ifv6.ip;
                if a.is_loopback() || a.is_multicast() || a.is_unspecified() {
                    continue;
                }
                any = true;
                if is_public_ipv6(&a) {
                    public = true;
                }
            }
        }
    }
    classify(any, public)
}

/// 身份卡展示：仅链路本地时如实显示地址而非一律 "N/A"，配合警告态提示。
pub fn any_ipv6() -> Option<Ipv6Addr> {
    let Ok(ifaces) = get_if_addrs::get_if_addrs() else {
        return None;
    };
    let mut fallback: Option<Ipv6Addr> = None;
    for iface in ifaces {
        if let get_if_addrs::IfAddr::V6(ifv6) = &iface.addr {
            let a = ifv6.ip;
            if a.is_loopback() || a.is_multicast() || a.is_unspecified() {
                continue;
            }
            if is_public_ipv6(&a) {
                return Some(a);
            }
            if fallback.is_none() {
                fallback = Some(a);
            }
        }
    }
    fallback
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
            // 的根因地址之一，现在必须判非公网。
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2", // Teredo
            "2002:c0a8:0001:0000:0000:0000:0000:0001", // 6to4
            "2001:0010::1", // ORCHID
            "2001:0020::1", // ORCHIDv2
        ] {
            let addr: Ipv6Addr = s.parse().unwrap();
            assert!(!is_public_ipv6(&addr), "{} 不应判为公网", s);
        }
    }

    #[test]
    fn test_is_public_ipv6_accepts_public() {
        for s in [
            "2408:4000::1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888", // Google DNS——2001:4860 前缀，非 Teredo/ORCHID
        ] {
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


    #[test]
    fn test_classify_pure_matrix() {
        use crate::network::Reachability;
        assert_eq!(classify(false, false), Reachability::Unavailable);
        assert_eq!(classify(true, false), Reachability::NonPublic);
        assert_eq!(classify(true, true), Reachability::Public);
        assert_eq!(classify(false, true), Reachability::Unavailable);
    }

    /// 无地址 → Unavailable。
    #[test]
    fn test_classify_addr_level() {
        use crate::network::Reachability;
        for s in [
            "fe80::1",      // 链路本地
            "fd00::1",      // ULA
            "2001:0000::1", // Teredo
            "2002:c0a8::1", // 6to4
        ] {
            let a: Ipv6Addr = s.parse().unwrap();
            assert_eq!(
                classify_addr(Some(a)),
                Reachability::NonPublic,
                "{s} 应判为不可直连"
            );
        }
        for s in ["2408:4000::1", "2606:4700:4700::1111"] {
            let a: Ipv6Addr = s.parse().unwrap();
            assert_eq!(classify_addr(Some(a)), Reachability::Public, "{s} 应判为公网");
        }
        assert_eq!(classify_addr(None), Reachability::Unavailable);
    }

    #[test]
    fn test_reachability_smoke() {
        use crate::network::Reachability;
        let r = reachability();
        assert!(
            matches!(r, Reachability::Unavailable | Reachability::NonPublic | Reachability::Public),
            "reachability 必须返回合法三态，got {r:?}"
        );
    }
}
