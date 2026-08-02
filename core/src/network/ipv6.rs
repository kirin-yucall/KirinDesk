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
