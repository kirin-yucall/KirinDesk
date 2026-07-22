use crate::godaddy::GoDaddyClient;
use crate::srv::SrvManager;
use crate::aaaa::AaaaManager;
use crate::txt::{DeviceMeta, TxtManager};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{info, warn, error};

const DEFAULT_INTERVAL_SECS: u64 = 30;

/// Heartbeat service — keeps device DNS records alive.
///
/// Runs a tokio loop that:
/// 1. Periodically refreshes SRV + TXT records (reset TTL)
/// 2. Monitors IPv6 address changes, updates AAAA
/// 3. Cleans up DNS records on shutdown
pub struct HeartbeatService {
    client: Arc<GoDaddyClient>,
    domain: String,
    device_id: String,
    port: u16,
    dns_ttl: u32,
    interval: Duration,
    shutdown_tx: watch::Sender<bool>,
}

impl HeartbeatService {
    pub fn new(
        client: Arc<GoDaddyClient>,
        device_id: impl Into<String>,
        domain: impl Into<String>,
        port: u16,
        interval_secs: u64,
        dns_ttl: u32,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            client,
            domain: domain.into(),
            device_id: device_id.into(),
            port,
            dns_ttl,
            interval: Duration::from_secs(if interval_secs > 0 { interval_secs } else { DEFAULT_INTERVAL_SECS }),
            shutdown_tx,
        }
    }

    /// Run the heartbeat loop. Blocks until shutdown signal.
    ///
    /// Call `shutdown()` from another task to stop.
    pub async fn run(&self, public_key_base64: &str) {
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!(
            "Heartbeat started: {}.{}, interval={}s",
            self.device_id, self.domain, self.interval.as_secs()
        );

        // Initial registration
        self.register_all(public_key_base64).await;

        let mut last_ipv6 = detect_global_ipv6();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {
                    self.tick(public_key_base64, &mut last_ipv6).await;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow_and_update() {
                        break;
                    }
                }
            }
        }

        // Graceful cleanup
        self.cleanup().await;
        info!("Heartbeat stopped: {}", self.device_id);
    }

    /// Send shutdown signal.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    // ---- internal ----

    fn srv_mgr(&self) -> SrvManager<'_> {
        SrvManager::new(&self.client, &self.domain)
    }

    fn txt_mgr(&self) -> TxtManager<'_> {
        TxtManager::new(&self.client, &self.domain)
    }

    fn aaaa_mgr(&self) -> AaaaManager<'_> {
        AaaaManager::new(&self.client, &self.domain)
    }

    async fn register_all(&self, pubkey: &str) {
        let target = format!("{}.{}.", self.device_id, self.domain);

        // SRV (port)
        if let Err(e) = self.srv_mgr().register(&self.device_id, self.port, &target, self.dns_ttl).await {
            warn!("SRV register failed: {}", e);
        } else {
            info!("SRV: _remote._tcp.{} -> port {}", self.device_id, self.port);
        }

        // TXT (public key)
        let meta = DeviceMeta::new(pubkey);
        if let Err(e) = self.txt_mgr().register(&self.device_id, &meta, self.dns_ttl).await {
            warn!("TXT register failed: {}", e);
        } else {
            info!("TXT: {}.{} metadata registered", self.device_id, self.domain);
        }

        // AAAA (IPv6)
        if let Some(ipv6) = detect_global_ipv6() {
            if let Err(e) = self.aaaa_mgr().register(&self.device_id, ipv6, self.dns_ttl).await {
                warn!("AAAA register failed: {}", e);
            } else {
                info!("AAAA: {} -> {}", self.device_id, ipv6);
            }
        } else {
            warn!("No global IPv6 address detected");
        }
    }

    async fn tick(&self, pubkey: &str, last_ipv6: &mut Option<Ipv6Addr>) {
        // Refresh SRV + TXT
        let target = format!("{}.{}.", self.device_id, self.domain);
        if let Err(e) = self.srv_mgr().register(&self.device_id, self.port, &target, self.dns_ttl).await {
            warn!("SRV refresh failed: {}", e);
        }
        let meta = DeviceMeta::new(pubkey);
        if let Err(e) = self.txt_mgr().register(&self.device_id, &meta, self.dns_ttl).await {
            warn!("TXT refresh failed: {}", e);
        }

        // Check IPv6 change
        let current = detect_global_ipv6();
        if current != *last_ipv6 {
            if let Some(addr) = current {
                info!("IPv6 changed: {:?} -> {:?}", last_ipv6, current);
                if let Err(e) = self.aaaa_mgr().register(&self.device_id, addr, self.dns_ttl).await {
                    error!("AAAA update failed: {}", e);
                }
            }
            *last_ipv6 = current;
        }
    }

    async fn cleanup(&self) {
        info!("Cleaning up DNS records for '{}'", self.device_id);
        let _ = self.srv_mgr().remove(&self.device_id).await;
        let _ = self.txt_mgr().remove(&self.device_id).await;
        let _ = self.aaaa_mgr().remove(&self.device_id).await;
    }
}

/// Detect a global unicast IPv6 address using OS interfaces.
fn detect_global_ipv6() -> Option<Ipv6Addr> {
    let ifaces = get_if_addrs::get_if_addrs().ok()?;
    for iface in &ifaces {
        if let get_if_addrs::IfAddr::V6(ifv6) = &iface.addr {
            let v6 = ifv6.ip;
            let o = v6.octets();
            if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 { continue; } // link-local
            if v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() { continue; }
            return Some(v6);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_config() {
        let client = Arc::new(GoDaddyClient::new("k", "s", "https://api.godaddy.com"));
        let hb = HeartbeatService::new(client, "my-pc", "example.com", 3389, 30, 600);
        assert_eq!(hb.device_id, "my-pc");
        assert_eq!(hb.port, 3389);
    }

    #[test]
    fn test_link_local_filter() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let o = ll.octets();
        assert!(o[0] == 0xfe && (o[1] & 0xc0) == 0x80);
    }

    #[test]
    fn test_global_ipv6_pass() {
        let g: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let o = g.octets();
        assert!(!(o[0] == 0xfe && (o[1] & 0xc0) == 0x80));
    }
}
