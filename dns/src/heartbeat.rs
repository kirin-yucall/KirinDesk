use crate::a::AManager;
use crate::aaaa::AaaaManager;
use crate::godaddy::GoDaddyClient;
use crate::srv::SrvManager;
use crate::txt::{DeviceMeta, TxtManager};
use crate::validate;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn};

const DEFAULT_INTERVAL_SECS: u64 = 30;

/// Heartbeat service — keeps device DNS records alive.
///
/// Runs a tokio loop that:
/// 1. Periodically refreshes SRV + TXT records (reset TTL)
/// 2. Monitors IPv6 address changes, updates AAAA
/// 3. Monitors IPv4 address changes, updates A (change → register; cleared → remove)
/// 4. Cleans up DNS records on shutdown
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
            interval: Duration::from_secs(if interval_secs > 0 {
                interval_secs
            } else {
                DEFAULT_INTERVAL_SECS
            }),
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
            self.device_id,
            self.domain,
            self.interval.as_secs()
        );

        // Initial registration
        self.register_all(public_key_base64).await;

        let mut last_ipv6 = detect_global_ipv6();
        let mut last_ipv4 = detect_global_ipv4();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {
                    self.tick(public_key_base64, &mut last_ipv6, &mut last_ipv4).await;
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

    fn a_mgr(&self) -> AManager<'_> {
        AManager::new(&self.client, &self.domain)
    }

    async fn register_all(&self, pubkey: &str) {
        // S-14b / F-18: device_id/domain 在任何写入前做一次显式校验——
        // 非法配置早退 + 显式警告（不静默；各 manager 层校验为兜底）。
        if !validate::validate_device_id(&self.device_id)
            || !validate::validate_hostname(&self.domain)
        {
            warn!(
                "Heartbeat skipped: invalid device_id '{}' or domain '{}' \
                 (see dns::validate rules; device_id: [a-zA-Z0-9:_-] len 1..=128, no '.')",
                self.device_id, self.domain
            );
            return;
        }
        let target = format!("{}.{}.", self.device_id, self.domain);

        // SRV (port)
        if let Err(e) = self
            .srv_mgr()
            .register(&self.device_id, self.port, &target, self.dns_ttl)
            .await
        {
            warn!("SRV register failed: {}", e);
        } else {
            info!("SRV: _remote._tcp.{} -> port {}", self.device_id, self.port);
        }

        // TXT (public key)
        let meta = DeviceMeta::new(pubkey);
        if let Err(e) = self
            .txt_mgr()
            .register(&self.device_id, &meta, self.dns_ttl)
            .await
        {
            warn!("TXT register failed: {}", e);
        } else {
            info!(
                "TXT: {}.{} metadata registered",
                self.device_id, self.domain
            );
        }

        // AAAA (IPv6)
        if let Some(ipv6) = detect_global_ipv6() {
            if let Err(e) = self
                .aaaa_mgr()
                .register(&self.device_id, ipv6, self.dns_ttl)
                .await
            {
                warn!("AAAA register failed: {}", e);
            } else {
                info!("AAAA: {} -> {}", self.device_id, ipv6);
            }
        } else {
            warn!("No global IPv6 address detected");
        }

        // A (IPv4)
        if let Some(ipv4) = detect_global_ipv4() {
            if let Err(e) = self
                .a_mgr()
                .register(&self.device_id, ipv4, self.dns_ttl)
                .await
            {
                warn!("A register failed: {}", e);
            } else {
                info!("A: {} -> {}", self.device_id, ipv4);
            }
        } else {
            warn!("No global IPv4 address detected");
        }
    }

    async fn tick(
        &self,
        pubkey: &str,
        last_ipv6: &mut Option<Ipv6Addr>,
        last_ipv4: &mut Option<Ipv4Addr>,
    ) {
        // Refresh SRV + TXT
        let target = format!("{}.{}.", self.device_id, self.domain);
        if let Err(e) = self
            .srv_mgr()
            .register(&self.device_id, self.port, &target, self.dns_ttl)
            .await
        {
            warn!("SRV refresh failed: {}", e);
        }
        let meta = DeviceMeta::new(pubkey);
        if let Err(e) = self
            .txt_mgr()
            .register(&self.device_id, &meta, self.dns_ttl)
            .await
        {
            warn!("TXT refresh failed: {}", e);
        }

        // Check IPv6 change
        let current = detect_global_ipv6();
        if current != *last_ipv6 {
            if let Some(addr) = current {
                info!("IPv6 changed: {:?} -> {:?}", last_ipv6, current);
                if let Err(e) = self
                    .aaaa_mgr()
                    .register(&self.device_id, addr, self.dns_ttl)
                    .await
                {
                    error!("AAAA update failed: {}", e);
                }
            }
            *last_ipv6 = current;
        }

        // Check IPv4 change (A record)
        let current_v4 = detect_global_ipv4();
        self.sync_ipv4(current_v4, last_ipv4).await;
    }

    /// Sync the A record with the current global IPv4: change → register, cleared → remove.
    async fn sync_ipv4(&self, current: Option<Ipv4Addr>, last: &mut Option<Ipv4Addr>) {
        if current == *last {
            return;
        }
        match current {
            Some(addr) => {
                info!("IPv4 changed: {:?} -> {:?}", last, current);
                if let Err(e) = self
                    .a_mgr()
                    .register(&self.device_id, addr, self.dns_ttl)
                    .await
                {
                    error!("A update failed: {}", e);
                }
            }
            None => {
                info!("IPv4 cleared: {:?} -> None", last);
                if let Err(e) = self.a_mgr().remove(&self.device_id).await {
                    error!("A remove failed: {}", e);
                }
            }
        }
        *last = current;
    }

    async fn cleanup(&self) {
        info!("Cleaning up DNS records for '{}'", self.device_id);
        let _ = self.srv_mgr().remove(&self.device_id).await;
        let _ = self.txt_mgr().remove(&self.device_id).await;
        let _ = self.aaaa_mgr().remove(&self.device_id).await;
        let _ = self.a_mgr().remove(&self.device_id).await;
    }
}

/// Detect a global unicast IPv6 address using OS interfaces.
fn detect_global_ipv6() -> Option<Ipv6Addr> {
    let ifaces = get_if_addrs::get_if_addrs().ok()?;
    for iface in &ifaces {
        if let get_if_addrs::IfAddr::V6(ifv6) = &iface.addr {
            let v6 = ifv6.ip;
            let o = v6.octets();
            if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
                continue;
            } // link-local
            if v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() {
                continue;
            }
            return Some(v6);
        }
    }
    None
}

/// Interface name keywords hinting a virtual/software adapter
/// (used to prefer physical NICs when multiple candidates exist).
const VIRTUAL_IFACE_KEYWORDS: [&str; 10] = [
    "virtual",
    "vethernet",
    "vmware",
    "vmnet",
    "loopback",
    "docker",
    "tap",
    "vpn",
    "wsl",
    "bluetooth",
];

fn is_virtual_iface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    VIRTUAL_IFACE_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// 获取全局单播 IPv4（过滤回环/链路本地/组播/未指定），多网卡优先物理网卡。
/// 对标 `detect_global_ipv6()`（本文件上方）。
fn detect_global_ipv4() -> Option<Ipv4Addr> {
    let ifaces = get_if_addrs::get_if_addrs().ok()?;
    let candidates: Vec<(&str, Ipv4Addr)> = ifaces
        .iter()
        .filter_map(|iface| {
            if let get_if_addrs::IfAddr::V4(ifv4) = &iface.addr {
                Some((iface.name.as_str(), ifv4.ip))
            } else {
                None
            }
        })
        .collect();

    // Pass 0: physical-looking adapters first; Pass 1: fall back to any (incl. virtual).
    for pass in 0..2 {
        for (name, ip) in &candidates {
            if pass == 0 && is_virtual_iface(name) {
                continue;
            }
            if let Some(picked) = pick_global_ipv4([*ip]) {
                return Some(picked);
            }
        }
    }
    None
}

/// Pure filter: pick the first global unicast IPv4 from candidates.
/// Rejects loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`),
/// multicast (`224.0.0.0/4`) and unspecified (`0.0.0.0`).
fn pick_global_ipv4<I>(candidates: I) -> Option<Ipv4Addr>
where
    I: IntoIterator<Item = Ipv4Addr>,
{
    candidates.into_iter().find(|ip| {
        !ip.is_loopback() && !ip.is_link_local() && !ip.is_multicast() && !ip.is_unspecified()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MockDns;

    #[test]
    fn test_heartbeat_config() {
        let client = Arc::new(GoDaddyClient::new("k", "s", "https://api.godaddy.com"));
        let hb = HeartbeatService::new(client, "my-pc", "example.com", 3389, 30, 600);
        assert_eq!(hb.device_id, "my-pc");
        assert_eq!(hb.port, 3389);
    }

    // S-14b / F-18: 非法 device_id 早退，不产生任何 API 调用
    #[tokio::test]
    async fn test_heartbeat_skips_invalid_device_id() {
        let mock = MockDns::start().await;
        let client = Arc::new(GoDaddyClient::new("k", "s", mock.base_url()));
        let hb = HeartbeatService::new(client, "bad id!", "example.com", 3389, 30, 600);
        hb.register_all("testpubkey").await;
        assert!(mock.records_of("SRV", "_remote._tcp.bad id!").is_empty());
        assert!(mock.records_of("TXT", "bad id!").is_empty());
        assert!(mock.records_of("A", "bad id!").is_empty());
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

    #[test]
    fn test_detect_ipv4_filters() {
        // 回环/链路本地/组播/未指定全部剔除，只留全局单播
        let candidates = [
            "127.0.0.1".parse().unwrap(),
            "127.255.255.254".parse().unwrap(),
            "169.254.10.5".parse().unwrap(),
            "224.0.0.1".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            "203.0.113.7".parse().unwrap(),
        ];
        assert_eq!(
            pick_global_ipv4(candidates),
            Some("203.0.113.7".parse().unwrap())
        );
    }

    #[test]
    fn test_detect_ipv4_filters_all_rejected() {
        let candidates = [
            "127.0.0.1".parse().unwrap(),
            "169.254.10.5".parse().unwrap(),
            "224.0.0.1".parse().unwrap(),
        ];
        assert_eq!(pick_global_ipv4(candidates), None);
    }

    #[test]
    fn test_detect_ipv4_filters_global_pass() {
        // 208.67.222.222 — 全局单播，不应被过滤
        let candidates = ["208.67.222.222".parse().unwrap()];
        assert_eq!(
            pick_global_ipv4(candidates),
            Some("208.67.222.222".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn test_heartbeat_register_and_update() {
        let mock = MockDns::start().await;
        let client = Arc::new(GoDaddyClient::new("k", "s", mock.base_url()));
        let hb = HeartbeatService::new(client, "my-pc", "example.com", 3389, 30, 600);

        // 初始注册: A 记录与真实检测结果自洽（无 IPv4 环境则不应有 A 记录）
        hb.register_all("testpubkey").await;
        let detected = detect_global_ipv4();
        match detected {
            Some(ip) => assert_eq!(mock.records_of("A", "my-pc"), vec![ip.to_string()]),
            None => assert!(mock.records_of("A", "my-pc").is_empty()),
        }

        // 地址变化 → A::register 更新（192.0.2.0/24 为 TEST-NET-1，测试专用）
        let mut last = detected;
        let new_ip: Ipv4Addr = "192.0.2.77".parse().unwrap();
        hb.sync_ipv4(Some(new_ip), &mut last).await;
        assert_eq!(last, Some(new_ip));
        assert_eq!(mock.records_of("A", "my-pc"), vec![new_ip.to_string()]);

        // 清空 → A::remove
        hb.sync_ipv4(None, &mut last).await;
        assert_eq!(last, None);
        assert!(mock.records_of("A", "my-pc").is_empty());
        assert_eq!(mock.delete_count("A", "my-pc"), 1);

        // 未变化 → 无操作
        let delete_before = mock.delete_count("A", "my-pc");
        hb.sync_ipv4(None, &mut last).await;
        assert_eq!(mock.delete_count("A", "my-pc"), delete_before);

        // cleanup 对称移除
        hb.cleanup().await;
        assert_eq!(mock.delete_count("A", "my-pc"), delete_before + 1);
    }
}
