use crate::godaddy::{GoDaddyClient, GoDaddyError};
use crate::txt::TxtManager;
use crate::aaaa::AaaaManager;
use crate::srv::SrvManager;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{debug, info, trace};

/// Information about a discovered device.
///
/// Under the Kirin+SRV hybrid protocol:
/// - Each device has subdomain `{device_id}.{domain}`
/// - SRV record → port (standard service discovery)
/// - TXT record → public key + device_type (JSON DeviceMeta)
/// - AAAA record → IPv6 address
///
/// `device_type` determines the session mode:
/// - "desktop" → remote desktop (screen + input)
/// - "server"  → remote shell (terminal PTY)
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub subdomain: String,
    pub ipv6_addr: Ipv6Addr,
    pub port: u16,
    pub public_key_base64: String,
    pub device_type: String,
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

    #[error("Device '{0}' has no AAAA (IPv6) record")]
    AaaaNotFound(String),

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
/// 3. **AAAA** `{device_id}` → IPv6 address
pub struct DiscoveryService<'a> {
    srv_mgr: SrvManager<'a>,
    txt_mgr: TxtManager<'a>,
    aaaa_mgr: AaaaManager<'a>,
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
                    debug!("Discovery cache hit for '{}' (expires in {:?})", device_id, entry.expires_at - Instant::now());
                    return Ok(entry.info.clone());
                }
                debug!("Discovery cache expired for '{}'", device_id);
            } else {
                trace!("Discovery cache miss for '{}'", device_id);
            }
        }

        let subdomain = format!("{}.{}", device_id, self.domain);
        debug!("Discovering '{}' via parallel SRV+TXT+AAAA on domain '{}'", device_id, self.domain);

        // Triple parallel: SRV (port) + TXT (key) + AAAA (IP)
        let (srv_res, txt_res, aaaa_res) = tokio::join!(
            self.srv_mgr.query(device_id),
            self.txt_mgr.query(device_id),
            self.aaaa_mgr.query(device_id),
        );

        // Log each result individually for debugging which one fails
        match &srv_res {
            Ok(srv_list) => debug!("Discovery SRV for '{}': {} records, first port={}", device_id, srv_list.len(), srv_list.first().map(|s| s.port).unwrap_or(0)),
            Err(e) => debug!("Discovery SRV for '{}' FAILED: {}", device_id, e),
        }
        match &txt_res {
            Ok(meta) => {
                let pk = meta.raw_public_key().unwrap_or("<none>");
                trace!("Discovery TXT for '{}': key={}, device_type={}", device_id, pk, meta.device_type);
            }
            Err(e) => debug!("Discovery TXT for '{}' FAILED: {}", device_id, e),
        }
        match &aaaa_res {
            Ok(addrs) => debug!("Discovery AAAA for '{}': {} addresses, first={:?}", device_id, addrs.len(), addrs.first()),
            Err(e) => debug!("Discovery AAAA for '{}' FAILED: {}", device_id, e),
        }

        let srv_list = srv_res.map_err(|_| DiscoveryError::SrvNotFound(device_id.to_string()))?;
        let meta = txt_res.map_err(|_| DiscoveryError::TxtNotFound(device_id.to_string()))?;
        let addrs = aaaa_res.map_err(|_| DiscoveryError::AaaaNotFound(device_id.to_string()))?;

        let srv_data = srv_list.first()
            .ok_or_else(|| DiscoveryError::SrvNotFound(device_id.to_string()))?;
        let ipv6_addr = addrs.first()
            .copied()
            .ok_or_else(|| DiscoveryError::AaaaNotFound(device_id.to_string()))?;

        let public_key_base64 = meta
            .raw_public_key()
            .ok_or_else(|| DiscoveryError::InvalidPublicKey(device_id.to_string()))?
            .to_string();

        info!(
            "Discovered '{}': IPv6={}, port={}, type={}",
            device_id, ipv6_addr, srv_data.port, meta.device_type
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
            port: 3389,
            public_key_base64: "testkey".to_string(),
            device_type: "desktop".to_string(),
        };
        assert_eq!(info.subdomain, "my-pc.example.com");
        assert_eq!(info.port, 3389);
        assert_eq!(info.device_type, "desktop");
    }
}
