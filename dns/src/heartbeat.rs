use crate::a::AManager;
use crate::aaaa::AaaaManager;
use crate::provider::Provider;
use crate::public_ip::PublicIpFetcher;
use crate::srv::SrvManager;
use crate::txt::{DeviceMeta, TxtManager};
use crate::validate;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

const DEFAULT_INTERVAL_SECS: u64 = 30;
/// S-27（F-32）：心跳间隔**下限 10s**——过短间隔会放大对 DNS 服务商的
/// API 调用（配额/滥用风险），配置值低于下限一律收敛到下限。
const MIN_INTERVAL_SECS: u64 = 10;

/// M8-T040 (WBS 4.2): IPv4 地址策略（DDNS 双模式，需求 §4.2）。
///
/// - `Auto`：**公网出口 IP**（经 [`PublicIpFetcher`] 多源 HTTPS 获取，
///   非本机网卡地址——本需求核心语义修正，DDNS-IPV4-002/003）；
/// - `Manual`：固定地址，心跳**永不覆盖**（仅刷新 SRV/TXT 的 TTL，
///   DDNS-IPV4-004 / DDNS-SEC-005）。
#[derive(Clone)]
pub enum Ipv4Policy {
    /// 自动 = 公网出口 IP（多源按序回退 + 缓存）。
    Auto(Arc<PublicIpFetcher>),
    /// 手动固定地址（永不自动变更）。
    Manual(Ipv4Addr),
}

/// M8-T040 (WBS 4.2): IPv6 地址策略（需求 §4.3）。
///
/// - `Auto`：本机全局单播 IPv6（无端口转发需求，DDNS-IPV6-002）；
/// - `Manual`：固定地址（上游固定前缀/转发场景），永不覆盖（DDNS-IPV6-003）。
#[derive(Clone, Copy)]
pub enum Ipv6Policy {
    Auto,
    Manual(Ipv6Addr),
}

/// Heartbeat service — keeps device DNS records alive.
///
/// Runs a tokio loop that:
/// 1. Periodically refreshes SRV + TXT records (reset TTL)
/// 2. Monitors IPv6 address changes, updates AAAA
/// 3. Monitors IPv4 address changes, updates A (change → register; cleared → remove)
/// 4. Cleans up DNS records on shutdown
///
/// M9-DNS000：多服务商化——持 `Arc<dyn Provider>`（可跨任务共享），
/// 不感知厂商差异。
///
/// M8-T040：策略化——`with_policies(ipv4, ipv6)` 注入双模式策略；策略为
/// `None` 时保持旧行为（IPv4 = 本机网卡地址检测，CLI `heartbeat` 兼容面）。
pub struct HeartbeatService {
    provider: Arc<dyn Provider>,
    domain: String,
    device_id: String,
    port: u16,
    dns_ttl: u32,
    interval: Duration,
    shutdown_tx: watch::Sender<bool>,
    /// M8-T040：IPv4 策略（None = 旧行为：本机网卡全局单播检测）。
    ipv4_policy: Option<Ipv4Policy>,
    /// M8-T040：IPv6 策略（None = 旧行为：本机网卡全局单播检测）。
    ipv6_policy: Option<Ipv6Policy>,
}

impl HeartbeatService {
    pub fn new(
        provider: Arc<dyn Provider>,
        device_id: impl Into<String>,
        domain: impl Into<String>,
        port: u16,
        interval_secs: u64,
        dns_ttl: u32,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            provider,
            domain: domain.into(),
            device_id: device_id.into(),
            port,
            dns_ttl,
            // S-27（F-32）：间隔下限 10s（低于下限收敛，防 API 滥用放大）。
            interval: Duration::from_secs(if interval_secs > 0 {
                interval_secs.max(MIN_INTERVAL_SECS)
            } else {
                DEFAULT_INTERVAL_SECS
            }),
            shutdown_tx,
            ipv4_policy: None,
            ipv6_policy: None,
        }
    }

    /// M8-T040 (WBS 4.2)：注入 IPv4/IPv6 双模式策略（`None` = 旧行为）。
    /// `DdnsService` 以 `Some(Auto(fetcher))` / `Some(Manual(addr))` 装配；
    /// CLI `heartbeat` 不调用 → 保持本机网卡语义。
    pub fn with_policies(
        mut self,
        ipv4: Option<Ipv4Policy>,
        ipv6: Option<Ipv6Policy>,
    ) -> Self {
        self.ipv4_policy = ipv4;
        self.ipv6_policy = ipv6;
        self
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

        // M8-T040：初始「上次值」按策略解析（Auto(v4) 经缓存复用 register_all 的取址）。
        let mut last_ipv6 = self.resolve_ipv6();
        let mut last_ipv4 = self.resolve_ipv4().await;

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
        SrvManager::new(self.provider.as_ref(), &self.domain)
    }

    fn txt_mgr(&self) -> TxtManager<'_> {
        TxtManager::new(self.provider.as_ref(), &self.domain)
    }

    fn aaaa_mgr(&self) -> AaaaManager<'_> {
        AaaaManager::new(self.provider.as_ref(), &self.domain)
    }

    fn a_mgr(&self) -> AManager<'_> {
        AManager::new(self.provider.as_ref(), &self.domain)
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
        if !self.ipv6_manual() {
            if let Some(ipv6) = self.resolve_ipv6() {
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
        } else {
            // M8-T040：Manual 永不覆盖（DDNS-IPV6-003）——不写 AAAA。
            debug!("AAAA skipped: ipv6 mode = manual (never overwrite)");
        }

        // A (IPv4)
        if !self.ipv4_manual() {
            if let Some(ipv4) = self.resolve_ipv4().await {
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
        } else {
            // M8-T040：Manual 永不覆盖（DDNS-IPV4-004）——不写 A。
            debug!("A skipped: ipv4 mode = manual (never overwrite)");
        }
    }

    // ---- M8-T040 (WBS 4.2): 策略化地址解析 ----

    fn ipv4_manual(&self) -> bool {
        matches!(self.ipv4_policy, Some(Ipv4Policy::Manual(_)))
    }

    fn ipv6_manual(&self) -> bool {
        matches!(self.ipv6_policy, Some(Ipv6Policy::Manual(_)))
    }

    /// 当前 IPv4（按策略）：Manual → 固定值；Auto → 公网出口 IP（失败保留
    /// 上次成功值语义由调用方维护，此处返回 None）；None → 本机网卡检测。
    async fn resolve_ipv4(&self) -> Option<Ipv4Addr> {
        match &self.ipv4_policy {
            Some(Ipv4Policy::Manual(ip)) => Some(*ip),
            Some(Ipv4Policy::Auto(fetcher)) => match fetcher.fetch().await {
                Ok(ip) => Some(ip),
                Err(e) => {
                    warn!("IPv4 auto fetch failed (keep last good): {e}");
                    None
                }
            },
            None => detect_global_ipv4(),
        }
    }

    /// 当前 IPv6（按策略）：Manual → 固定值；Auto/None → 本机全局单播。
    fn resolve_ipv6(&self) -> Option<Ipv6Addr> {
        match self.ipv6_policy {
            Some(Ipv6Policy::Manual(ip)) => Some(ip),
            Some(Ipv6Policy::Auto) | None => detect_global_ipv6(),
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

        // Check IPv6 change（Manual：固定值永不变化 → 自然无操作）
        let current = self.resolve_ipv6();
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
        let current_v4 = self.resolve_ipv4().await;
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
/// M8-T040：`pub(crate)` —— DdnsService（ddns.rs）复用同一取址语义（DDNS-IPV6-002）。
pub(crate) fn detect_global_ipv6() -> Option<Ipv6Addr> {
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
    use crate::provider::mock::MockProvider;
    use crate::provider::RecordType;

    /// 读取 A 记录 data（显示形态）——MockProvider 内存态断言用。
    fn a_records(provider: &MockProvider) -> Vec<String> {
        provider
            .records_of("example.com", RecordType::A, "my-pc")
            .iter()
            .map(|r| r.data.to_display_string())
            .collect()
    }

    #[test]
    fn test_heartbeat_config() {
        let provider = Arc::new(MockProvider::new("mock"));
        let hb = HeartbeatService::new(provider, "my-pc", "example.com", 3389, 30, 600);
        assert_eq!(hb.device_id, "my-pc");
        assert_eq!(hb.port, 3389);
        assert_eq!(hb.interval, Duration::from_secs(30));
    }

    /// S-27（F-32）：心跳间隔下限 —— 配置低于 10s → 收敛到 10s；0/负 → 默认 30s。
    #[test]
    fn test_heartbeat_interval_floor() {
        let provider = Arc::new(MockProvider::new("mock"));
        let hb = HeartbeatService::new(provider.clone(), "pc", "example.com", 3389, 5, 600);
        assert_eq!(
            hb.interval,
            Duration::from_secs(MIN_INTERVAL_SECS),
            "interval below floor must clamp to 10s (S-27)"
        );
        let hb = HeartbeatService::new(provider.clone(), "pc", "example.com", 3389, 10, 600);
        assert_eq!(hb.interval, Duration::from_secs(10));
        let hb = HeartbeatService::new(provider.clone(), "pc", "example.com", 3389, 120, 600);
        assert_eq!(hb.interval, Duration::from_secs(120), "above floor unchanged");
        let hb = HeartbeatService::new(provider, "pc", "example.com", 3389, 0, 600);
        assert_eq!(hb.interval, Duration::from_secs(DEFAULT_INTERVAL_SECS));
    }

    // S-14b / F-18: 非法 device_id 早退，不产生任何 API 调用
    #[tokio::test]
    async fn test_heartbeat_skips_invalid_device_id() {
        let provider = Arc::new(MockProvider::new("mock"));
        let hb = HeartbeatService::new(provider.clone(), "bad id!", "example.com", 3389, 30, 600);
        hb.register_all("testpubkey").await;
        assert!(
            provider
                .records_of("example.com", RecordType::SRV, "_remote._tcp.bad id!")
                .is_empty()
        );
        assert!(
            provider
                .records_of("example.com", RecordType::TXT, "bad id!")
                .is_empty()
        );
        assert!(
            provider
                .records_of("example.com", RecordType::A, "bad id!")
                .is_empty()
        );
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
        let provider = Arc::new(MockProvider::new("mock"));
        let hb = HeartbeatService::new(provider.clone(), "my-pc", "example.com", 3389, 30, 600);

        // 初始注册: A 记录与真实检测结果自洽（无 IPv4 环境则不应有 A 记录）
        hb.register_all("testpubkey").await;
        let detected = detect_global_ipv4();
        match detected {
            Some(ip) => assert_eq!(a_records(&provider), vec![ip.to_string()]),
            None => assert!(a_records(&provider).is_empty()),
        }

        // 地址变化 → A::register 更新（192.0.2.0/24 为 TEST-NET-1，测试专用）。
        // MockProvider 语义：同 name+rtype 不同 data 并存（DNS 多值记录），
        // 断言新 IP 一定写入；此前检测到的 IP 若存在则保留。
        let mut last = detected;
        let new_ip: Ipv4Addr = "192.0.2.77".parse().unwrap();
        hb.sync_ipv4(Some(new_ip), &mut last).await;
        assert_eq!(last, Some(new_ip));
        let recs = a_records(&provider);
        assert!(
            recs.contains(&new_ip.to_string()),
            "A records should contain the new IP, got {recs:?}"
        );
        if let Some(ip) = detected {
            assert!(
                recs.contains(&ip.to_string()),
                "previous detected IP should be retained, got {recs:?}"
            );
        }

        // 清空 → A::remove（删除整个 name+rtype 组，含多值记录）
        hb.sync_ipv4(None, &mut last).await;
        assert_eq!(last, None);
        assert!(a_records(&provider).is_empty());
        assert_eq!(provider.delete_count(), 1);

        // 未变化 → 无操作
        let delete_before = provider.delete_count();
        hb.sync_ipv4(None, &mut last).await;
        assert_eq!(provider.delete_count(), delete_before);

        // cleanup 对称移除（SRV + TXT + AAAA + A 四条）
        hb.cleanup().await;
        assert_eq!(provider.delete_count(), delete_before + 4);
    }

    // ═══════════ M8-T040 (WBS 4.2): 策略化测试 ═══════════

    /// 构造固定值 mock 公网 IP 源（Auto 策略注入用）。
    fn fixed_ip_source(ip: &'static str) -> Arc<PublicIpFetcher> {
        use crate::public_ip::{PubIpSource, PubIpError};
        struct Fixed(&'static str);
        #[async_trait::async_trait]
        impl PubIpSource for Fixed {
            async fn fetch(&self) -> Result<Ipv4Addr, PubIpError> {
                self.0.parse().map_err(|_| {
                    PubIpError::InvalidResponse(self.0.to_string())
                })
            }
        }
        Arc::new(PublicIpFetcher::from_sources(vec![Box::new(Fixed(ip))]))
    }

    /// M8-T040：Auto(v4) 策略 → 取址走公网 IP 源（而非本机网卡）。
    #[tokio::test]
    async fn test_ipv4_auto_policy_uses_public_fetcher() {
        let fetcher = fixed_ip_source("203.0.113.55");
        let provider = Arc::new(MockProvider::new("mock"));
        let hb = HeartbeatService::new(
            provider.clone(),
            "my-pc",
            "example.com",
            3389,
            30,
            600,
        )
        .with_policies(Some(Ipv4Policy::Auto(fetcher)), None);
        // 初始注册：A 记录 = 公网出口 IP（203.0.113.55），而非本机网卡地址。
        hb.register_all("testpubkey").await;
        let recs = a_records(&provider);
        assert!(
            recs.contains(&"203.0.113.55".to_string()),
            "Auto 策略必须写公网出口 IP，got {recs:?}"
        );
    }

    /// M8-T040：Manual 策略 → register_all 不写 A/AAAA（永不覆盖，DDNS-IPV4-004）。
    #[tokio::test]
    async fn test_ipv4_manual_policy_never_writes_a() {
        let provider = Arc::new(MockProvider::new("mock"));
        let hb = HeartbeatService::new(provider.clone(), "my-pc", "example.com", 3389, 30, 600)
            .with_policies(
                Some(Ipv4Policy::Manual("203.0.113.9".parse().unwrap())),
                Some(Ipv6Policy::Manual("2001:db8::9".parse().unwrap())),
            );
        hb.register_all("testpubkey").await;
        assert!(
            provider
                .records_of("example.com", RecordType::A, "my-pc")
                .is_empty(),
            "Manual 策略心跳不得写 A 记录"
        );
        assert!(
            provider
                .records_of("example.com", RecordType::AAAA, "my-pc")
                .is_empty(),
            "Manual 策略心跳不得写 AAAA 记录"
        );
        // SRV/TXT 仍刷新（TTL 维护不涉及地址）。
        assert!(!provider
            .records_of("example.com", RecordType::SRV, "_remote._tcp.my-pc")
            .is_empty());
    }

    /// M8-T040：Manual 值不随周期变化 → tick 不产生 A 写操作。
    #[tokio::test]
    async fn test_ipv4_manual_tick_no_write() {
        let provider = Arc::new(MockProvider::new("mock"));
        let hb = HeartbeatService::new(provider.clone(), "my-pc", "example.com", 3389, 30, 600)
            .with_policies(
                Some(Ipv4Policy::Manual("203.0.113.9".parse().unwrap())),
                None,
            );
        let mut last_v6 = hb.resolve_ipv6();
        let mut last_v4 = hb.resolve_ipv4().await;
        assert_eq!(last_v4, Some("203.0.113.9".parse().unwrap()));
        hb.tick("testpubkey", &mut last_v6, &mut last_v4).await;
        // A 记录仍然为空（Manual 不写）；SRV/TXT 刷新（upsert 计数增加）。
        assert!(a_records(&provider).is_empty());
    }

    /// M8-T040：resolve_ipv6 按策略返回（Manual 固定值 / Auto=本机检测）。
    #[test]
    fn test_ipv6_policy_resolution() {
        let hb = HeartbeatService::new(
            Arc::new(MockProvider::new("mock")),
            "pc",
            "example.com",
            3389,
            30,
            600,
        )
        .with_policies(None, Some(Ipv6Policy::Manual("2001:db8::42".parse().unwrap())));
        assert_eq!(hb.resolve_ipv6(), Some("2001:db8::42".parse().unwrap()));
        assert!(hb.ipv6_manual());
        let hb2 = HeartbeatService::new(
            Arc::new(MockProvider::new("mock")),
            "pc",
            "example.com",
            3389,
            30,
            600,
        );
        assert!(!hb2.ipv4_manual());
        assert!(!hb2.ipv6_manual());
    }

    /// M8-T040：Auto 取址失败 → None（保留上次成功值语义由调用方维护）。
    #[tokio::test]
    async fn test_ipv4_auto_fetch_failure_returns_none() {
        use crate::public_ip::{PubIpError, PubIpSource};
        struct Failing;
        #[async_trait::async_trait]
        impl PubIpSource for Failing {
            async fn fetch(&self) -> Result<Ipv4Addr, PubIpError> {
                Err(PubIpError::AllSourcesFailed("全部源失败".into()))
            }
        }
        let hb = HeartbeatService::new(
            Arc::new(MockProvider::new("mock")),
            "pc",
            "example.com",
            3389,
            30,
            600,
        )
        .with_policies(
            Some(Ipv4Policy::Auto(Arc::new(PublicIpFetcher::from_sources(vec![
                Box::new(Failing),
            ])))),
            None,
        );
        assert_eq!(hb.resolve_ipv4().await, None);
    }
}
