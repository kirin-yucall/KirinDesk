use crate::a::AManager;
use crate::aaaa::AaaaManager;
use crate::godaddy::{GoDaddyClient, GoDaddyError};
use crate::srv::SrvManager;
use crate::txt::TxtManager;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace};

/// Information about a discovered device.
///
/// Under the Kirin+SRV hybrid protocol:
/// - Each device has subdomain `{device_id}.{domain}`
/// - SRV record → port (standard service discovery)
/// - TXT record → public key + device_type (JSON DeviceMeta)
/// - AAAA record → IPv6 address (optional; `Ipv6Addr::UNSPECIFIED` sentinel when absent)
/// - A record → IPv4 address (optional)
///
/// `device_type` determines the session mode:
/// - "desktop" → remote desktop (screen + input)
/// - "server"  → remote shell (terminal PTY)
///
/// 并行契约（P5 消费，见 M8-T025_P1）：`ipv6_addr` 保持 `Ipv6Addr` 类型不变，
/// IPv4-only 设备以 `Ipv6Addr::UNSPECIFIED`（`::`）哨兵表示"无 IPv6"；
/// 地址选择一律走 `select_connect_addr`（哨兵在内部消化）。
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub subdomain: String,
    /// IPv6 地址；无 IPv6 时为 `Ipv6Addr::UNSPECIFIED`（哨兵）。
    pub ipv6_addr: Ipv6Addr,
    /// IPv4 地址；无 IPv4 时为 `None`。
    pub ipv4_addr: Option<Ipv4Addr>,
    pub port: u16,
    pub public_key_base64: String,
    pub device_type: String,
}

/// 地址族选择策略（A4：IPv6 优先；配置强制族）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    /// 自动：IPv6 可用则 v6，否则 v4。
    Auto,
    /// 强制 IPv4。
    Ipv4,
    /// 强制 IPv6。
    Ipv6,
}

impl DeviceInfo {
    /// 按策略选出连接地址（`SocketAddr` = ip + port）。
    ///
    /// 哨兵规则：`ipv6_addr == Ipv6Addr::UNSPECIFIED` 视为"无 IPv6"。
    /// - `Auto`: IPv6 可用 → v6；否则 v4（v6 黑洞回退由 P5 的建连超时实现，
    ///   本函数只负责族选择）。
    /// - `Ipv4` / `Ipv6` 强制族缺失时返回 `None`（由 P5 报错）。
    pub fn select_connect_addr(&self, family: IpFamily) -> Option<SocketAddr> {
        let has_v6 = self.ipv6_addr != Ipv6Addr::UNSPECIFIED;
        match family {
            IpFamily::Auto if has_v6 => Some(SocketAddr::new(self.ipv6_addr.into(), self.port)),
            IpFamily::Auto => self
                .ipv4_addr
                .map(|ip| SocketAddr::new(ip.into(), self.port)),
            IpFamily::Ipv4 => self
                .ipv4_addr
                .map(|ip| SocketAddr::new(ip.into(), self.port)),
            IpFamily::Ipv6 if has_v6 => Some(SocketAddr::new(self.ipv6_addr.into(), self.port)),
            IpFamily::Ipv6 => None,
        }
    }
}

/// Discovery errors.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("GoDaddy API error: {0}")]
    GoDaddy(#[from] GoDaddyError),

    #[error("Device '{0}' has no TXT metadata record")]
    TxtNotFound(String),

    #[error("Device '{0}' has no SRV record (port missing)")]
    SrvNotFound(String),

    #[error("Device '{0}' has neither AAAA (IPv6) nor A (IPv4) record")]
    NoAddress(String),

    #[error("Device '{0}' TXT record has malformed public key")]
    InvalidPublicKey(String),

    #[error("Timeout during discovery")]
    Timeout,
}

/// Local cache entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    info: DeviceInfo,
    expires_at: Instant,
}

/// Service discovery coordinator — Kirin + SRV hybrid.
///
/// Resolves a device ID via parallel DNS queries:
/// 1. **SRV** `_remote._tcp.{device_id}` → port
/// 2. **TXT** `{device_id}` → Ed25519 public key (JSON)
/// 3. **AAAA** `{device_id}` → IPv6 address (optional)
/// 4. **A** `{device_id}` → IPv4 address (optional)
pub struct DiscoveryService<'a> {
    srv_mgr: SrvManager<'a>,
    txt_mgr: TxtManager<'a>,
    aaaa_mgr: AaaaManager<'a>,
    a_mgr: AManager<'a>,
    domain: &'a str,
    cache: Mutex<HashMap<String, CacheEntry>>,
    cache_ttl: u64,
}

impl<'a> DiscoveryService<'a> {
    pub fn new(client: &'a GoDaddyClient, domain: &'a str) -> Self {
        Self {
            srv_mgr: SrvManager::new(client, domain),
            txt_mgr: TxtManager::new(client, domain),
            aaaa_mgr: AaaaManager::new(client, domain),
            a_mgr: AManager::new(client, domain),
            domain,
            cache: Mutex::new(HashMap::new()),
            cache_ttl: 50,
        }
    }

    pub fn with_cache_ttl(mut self, ttl_secs: u64) -> Self {
        self.cache_ttl = ttl_secs;
        self
    }

    /// Discover a device by ID — parallel SRV + TXT + AAAA.
    pub async fn discover(&self, device_id: &str) -> Result<DeviceInfo, DiscoveryError> {
        // Check cache
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(device_id) {
                if entry.expires_at > Instant::now() {
                    debug!(
                        "Discovery cache hit for '{}' (expires in {:?})",
                        device_id,
                        entry.expires_at - Instant::now()
                    );
                    return Ok(entry.info.clone());
                }
                debug!("Discovery cache expired for '{}'", device_id);
            } else {
                trace!("Discovery cache miss for '{}'", device_id);
            }
        }

        let subdomain = format!("{}.{}", device_id, self.domain);
        debug!(
            "Discovering '{}' via parallel SRV+TXT+AAAA+A on domain '{}'",
            device_id, self.domain
        );

        // 4-way parallel: SRV (port) + TXT (key) + AAAA (IPv6) + A (IPv4)
        let (srv_res, txt_res, aaaa_res, a_res) = tokio::join!(
            self.srv_mgr.query(device_id),
            self.txt_mgr.query(device_id),
            self.aaaa_mgr.query(device_id),
            self.a_mgr.query(device_id),
        );

        // Log each result individually for debugging which one fails
        match &srv_res {
            Ok(srv_list) => debug!(
                "Discovery SRV for '{}': {} records, first port={}",
                device_id,
                srv_list.len(),
                srv_list.first().map(|s| s.port).unwrap_or(0)
            ),
            Err(e) => debug!("Discovery SRV for '{}' FAILED: {}", device_id, e),
        }
        match &txt_res {
            Ok(meta) => {
                let pk = meta.raw_public_key().unwrap_or("<none>");
                trace!(
                    "Discovery TXT for '{}': key={}, device_type={}",
                    device_id,
                    pk,
                    meta.device_type
                );
            }
            Err(e) => debug!("Discovery TXT for '{}' FAILED: {}", device_id, e),
        }
        match &aaaa_res {
            Ok(addrs) => debug!(
                "Discovery AAAA for '{}': {} addresses, first={:?}",
                device_id,
                addrs.len(),
                addrs.first()
            ),
            Err(e) => debug!("Discovery AAAA for '{}' FAILED: {}", device_id, e),
        }
        match &a_res {
            Ok(addrs) => debug!(
                "Discovery A for '{}': {} addresses, first={:?}",
                device_id,
                addrs.len(),
                addrs.first()
            ),
            Err(e) => debug!("Discovery A for '{}' FAILED: {}", device_id, e),
        }

        let srv_list = srv_res.map_err(|_| DiscoveryError::SrvNotFound(device_id.to_string()))?;
        let meta = txt_res.map_err(|_| DiscoveryError::TxtNotFound(device_id.to_string()))?;

        let srv_data = srv_list
            .first()
            .ok_or_else(|| DiscoveryError::SrvNotFound(device_id.to_string()))?;

        // AAAA 失败或空 → Ipv6Addr::UNSPECIFIED 哨兵（"无 IPv6"）
        let ipv6_addr = match aaaa_res.as_ref() {
            Ok(addrs) => addrs.first().copied().unwrap_or(Ipv6Addr::UNSPECIFIED),
            Err(_) => Ipv6Addr::UNSPECIFIED,
        };
        // A 失败或空 → None（"无 IPv4"）
        let ipv4_addr = match a_res.as_ref() {
            Ok(addrs) => addrs.first().copied(),
            Err(_) => None,
        };
        // 两者皆无 → 设备无连接地址
        if ipv6_addr.is_unspecified() && ipv4_addr.is_none() {
            return Err(DiscoveryError::NoAddress(device_id.to_string()));
        }

        let public_key_base64 = meta
            .raw_public_key()
            .ok_or_else(|| DiscoveryError::InvalidPublicKey(device_id.to_string()))?
            .to_string();

        info!(
            "Discovered '{}': IPv6={}, IPv4={:?}, port={}, type={}",
            device_id, ipv6_addr, ipv4_addr, srv_data.port, meta.device_type
        );
        trace!(
            "Discovery '{}' pubkey (first 16): {}...",
            device_id,
            &public_key_base64[..public_key_base64.len().min(16)]
        );

        let info = DeviceInfo {
            device_id: device_id.to_string(),
            subdomain,
            ipv6_addr,
            ipv4_addr,
            port: srv_data.port,
            public_key_base64,
            device_type: meta.device_type.clone(),
        };

        // Cache
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(
                device_id.to_string(),
                CacheEntry {
                    info: info.clone(),
                    expires_at: Instant::now() + Duration::from_secs(self.cache_ttl),
                },
            );
        }

        Ok(info)
    }

    pub fn invalidate_cache(&self, device_id: &str) {
        let mut cache = self.cache.lock().unwrap();
        cache.remove(device_id);
    }

    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }
}

/// Convenience: one-shot discovery.
pub async fn discover_device(
    api_key: &str,
    api_secret: &str,
    domain: &str,
    device_id: &str,
) -> Result<DeviceInfo, DiscoveryError> {
    let client = GoDaddyClient::new(api_key, api_secret, "https://api.godaddy.com");
    let discovery = DiscoveryService::new(&client, domain);
    discovery.discover(device_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MockDns;
    use crate::txt::DeviceMeta;

    /// Seed SRV + TXT (always required) plus optional AAAA/A records.
    fn seed_device(mock: &MockDns, device_id: &str, with_v6: bool, with_v4: bool) {
        let srv = format!("0 1 3389 {}.example.com.", device_id);
        mock.set_records("SRV", &format!("_remote._tcp.{}", device_id), &[&srv], 600);
        let txt = DeviceMeta::new("testkey").to_txt();
        mock.set_records("TXT", device_id, &[&txt], 600);
        if with_v6 {
            mock.set_records("AAAA", device_id, &["2001:db8::1"], 600);
        }
        if with_v4 {
            mock.set_records("A", device_id, &["203.0.113.7"], 600);
        }
    }

    #[test]
    fn test_cache_ttl_config() {
        let client = GoDaddyClient::new("k", "s", "https://api.godaddy.com");
        let svc = DiscoveryService::new(&client, "example.com").with_cache_ttl(30);
        assert_eq!(svc.cache_ttl, 30);
    }

    #[test]
    fn test_device_info_subdomain() {
        let info = DeviceInfo {
            device_id: "my-pc".to_string(),
            subdomain: "my-pc.example.com".to_string(),
            ipv6_addr: "2001:db8::1".parse().unwrap(),
            ipv4_addr: None,
            port: 3389,
            public_key_base64: "testkey".to_string(),
            device_type: "desktop".to_string(),
        };
        assert_eq!(info.subdomain, "my-pc.example.com");
        assert_eq!(info.port, 3389);
        assert_eq!(info.device_type, "desktop");
    }

    #[tokio::test]
    async fn test_discover_ipv4_only() {
        let mock = MockDns::start().await;
        seed_device(&mock, "v4only", false, true);
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let svc = DiscoveryService::new(&client, "example.com");

        let info = svc.discover("v4only").await.unwrap();
        // 哨兵: 无 AAAA → ipv6_addr == UNSPECIFIED
        assert_eq!(info.ipv6_addr, Ipv6Addr::UNSPECIFIED);
        assert_eq!(info.ipv4_addr, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(info.port, 3389);
        assert_eq!(info.device_type, "desktop");
        assert_eq!(info.public_key_base64, "testkey");
    }

    #[tokio::test]
    async fn test_discover_ipv6_only() {
        // 回归现状: IPv6-only 设备行为与实现前完全一致
        let mock = MockDns::start().await;
        seed_device(&mock, "v6only", true, false);
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let svc = DiscoveryService::new(&client, "example.com");

        let info = svc.discover("v6only").await.unwrap();
        assert_eq!(info.ipv6_addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(info.ipv4_addr, None);
        assert_eq!(info.port, 3389);
    }

    #[tokio::test]
    async fn test_discover_dual_stack() {
        let mock = MockDns::start().await;
        seed_device(&mock, "dual", true, true);
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let svc = DiscoveryService::new(&client, "example.com");

        let info = svc.discover("dual").await.unwrap();
        assert_eq!(info.ipv6_addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(info.ipv4_addr, Some("203.0.113.7".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_discover_no_address() {
        // AAAA + A 均缺 → NoAddress（不再报 AaaaNotFound）
        let mock = MockDns::start().await;
        seed_device(&mock, "noaddr", false, false);
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let svc = DiscoveryService::new(&client, "example.com");

        let err = svc.discover("noaddr").await.unwrap_err();
        assert!(matches!(err, DiscoveryError::NoAddress(_)));
    }

    // ---- select_connect_addr 纯函数（并行契约） ----

    fn info_with(ipv6: Ipv6Addr, ipv4: Option<Ipv4Addr>) -> DeviceInfo {
        DeviceInfo {
            device_id: "dev".to_string(),
            subdomain: "dev.example.com".to_string(),
            ipv6_addr: ipv6,
            ipv4_addr: ipv4,
            port: 3389,
            public_key_base64: "testkey".to_string(),
            device_type: "desktop".to_string(),
        }
    }

    const SENTINEL: Ipv6Addr = Ipv6Addr::UNSPECIFIED;
    const V6: &str = "2001:db8::1";
    const V4: &str = "203.0.113.7";

    fn v6_socket() -> SocketAddr {
        SocketAddr::new(V6.parse::<Ipv6Addr>().unwrap().into(), 3389)
    }

    fn v4_socket() -> SocketAddr {
        SocketAddr::new(V4.parse::<Ipv4Addr>().unwrap().into(), 3389)
    }

    #[test]
    fn test_select_connect_addr_auto_v6() {
        let info = info_with(V6.parse().unwrap(), Some(V4.parse().unwrap()));
        assert_eq!(info.select_connect_addr(IpFamily::Auto), Some(v6_socket()));
    }

    #[test]
    fn test_select_connect_addr_auto_v4only() {
        // 哨兵 + v4 → Auto 回落 v4
        let info = info_with(SENTINEL, Some(V4.parse().unwrap()));
        assert_eq!(info.select_connect_addr(IpFamily::Auto), Some(v4_socket()));
    }

    #[test]
    fn test_select_connect_addr_auto_no_address() {
        let info = info_with(SENTINEL, None);
        assert_eq!(info.select_connect_addr(IpFamily::Auto), None);
    }

    #[test]
    fn test_select_connect_addr_forced() {
        // 强制族缺失 → None
        let v4only = info_with(SENTINEL, Some(V4.parse().unwrap()));
        assert_eq!(v4only.select_connect_addr(IpFamily::Ipv6), None);
        assert_eq!(
            v4only.select_connect_addr(IpFamily::Ipv4),
            Some(v4_socket())
        );

        let v6only = info_with(V6.parse().unwrap(), None);
        assert_eq!(v6only.select_connect_addr(IpFamily::Ipv4), None);
        assert_eq!(
            v6only.select_connect_addr(IpFamily::Ipv6),
            Some(v6_socket())
        );
    }
}
