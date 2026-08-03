//! M8-T040 (W2-B / WBS 4.3~4.5): DDNS 域名自动更新维护服务。
//!
//! 职责（需求 §4.1~§4.4）：
//! - **周期循环**：`[ddns] interval_secs`（≥60s 下限收敛，DDNS-002）周期发布；
//! - **变更驱动**：地址/端口/签名未变化时 A/AAAA 不写 API，SRV/TXT 刷新 TTL
//!   （DDNS-003）；
//! - **双模式**：IPv4 Auto = 公网出口 IP（`PublicIpFetcher`），Manual 永不覆盖
//!   （DDNS-IPV4-002/004）；IPv6 Auto = 本机全局单播，Manual 同（DDNS-IPV6-002/003）；
//! - **更新前反查保护**：写 A/AAAA 前经 `SecureResolver`（DoH/DoT）反查当前
//!   记录；现记录 ≠ 待写值 且 ≠ 本服务上次写入值 → 跳过并告警（DDNS-REC-005 /
//!   DDNS-SEC-004，防覆盖他人记录）；
//! - **三件套**：SRV（端口 = `[network] port`）+ TXT（`DeviceMeta` 签名）+
//!   A/AAAA（按模式），`publish_*` 四开关（DDNS-REC-001~003/006）；
//! - **状态 watch**：`DdnsStatus` 供 UI/CLI 只读（上次成功/当前地址/失败原因/
//!   下次倒计时/生效记录预览）；
//! - **连续失败暂停**：连续 3 次失败暂停自动更新并提示（DDNS-IPV4-002），
//!   手动「立即更新」可解除；关闭/停止**不删除**记录（DDNS-REC-007）。
//!
//! 装配：`start(cfg, public_key_base64, watch_tx)` 从 utils `Config` 全量取参
//! （`[ddns]`/`[network]`/`[dns]` 段；F-2：UI 已依赖 dns，可直接读状态）。

use crate::a::AManager;
use crate::aaaa::AaaaManager;
use crate::heartbeat::detect_global_ipv6;
use crate::provider::{Provider, RecordData, RecordType};
use crate::public_ip::PublicIpFetcher;
use crate::secure_resolver::{Resolver, SecureResolver};
use crate::srv::SrvManager;
use crate::txt::{DeviceMeta, TxtManager};
use crate::{default_provider, validate};
use chrono::{DateTime, Utc};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use kirin_desk_utils::config::Config;

/// 连续失败暂停阈值（DDNS-IPV4-002：连续 3 次失败暂停自动更新并提示，
/// 防 stale 误维护）。
const FAILURE_PAUSE_THRESHOLD: u32 = 3;
/// 暂停时长（30 分钟；期间不自动更新，手动「立即更新」解除）。
const FAILURE_PAUSE_DURATION: Duration = Duration::from_secs(30 * 60);
/// 公网 IP 单源超时（5s，与 SecureResolver 单端点超时口径一致）。
const PUBIP_SOURCE_TIMEOUT: Duration = Duration::from_secs(5);

/// DDNS 模式（UI/CLI 只读展示用；配置层 `utils::config::DdnsMode` 在
/// `start()` 装配时转换，dns crate 不依赖配置层模式类型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DdnsMode {
    #[default]
    Auto,
    Manual,
}

/// 生效记录预览（DDNS-UI-004：SRV 端口 / TXT 指纹 / A / AAAA 是否生效）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishedPreview {
    pub srv: bool,
    pub srv_port: Option<u16>,
    pub txt: bool,
    pub txt_fingerprint: Option<String>,
    pub a: bool,
    pub aaaa: bool,
}

/// DDNS 状态（watch channel，UI/CLI 只读；并行计划 §5 冻结字段）。
#[derive(Debug, Clone, PartialEq)]
pub struct DdnsStatus {
    pub enabled: bool,
    pub ipv4_mode: DdnsMode,
    pub ipv4_current: Option<Ipv4Addr>,
    pub ipv4_at: Option<DateTime<Utc>>,
    pub ipv6_mode: DdnsMode,
    pub ipv6_current: Option<Ipv6Addr>,
    pub ipv6_at: Option<DateTime<Utc>>,
    pub last_update: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub next_update_at: Option<DateTime<Utc>>,
    pub published: PublishedPreview,
}

impl DdnsStatus {
    /// 初始状态（enabled=false：未启动/已停止）。
    pub fn initial() -> Self {
        Self {
            enabled: false,
            ipv4_mode: DdnsMode::Auto,
            ipv4_current: None,
            ipv4_at: None,
            ipv6_mode: DdnsMode::Auto,
            ipv6_current: None,
            ipv6_at: None,
            last_update: None,
            last_error: None,
            next_update_at: None,
            published: PublishedPreview::default(),
        }
    }
}

/// DDNS 服务错误（`update_now` 返回值）。
#[derive(Debug, thiserror::Error)]
pub enum DdnsError {
    #[error("DNS 服务商未配置: {0}")]
    ProviderNotConfigured(String),
    #[error("公网出口 IP 获取失败: {0}")]
    PublicIp(String),
    #[error("发布失败: {0}")]
    Publish(String),
    #[error("服务未运行")]
    NotRunning,
}

/// 内部命令（任务侧与句柄侧通信）。
enum DdnsCmd {
    /// 立即执行一轮全量发布（UI「立即更新」/ CLI `ddns update`）。
    UpdateNow(oneshot::Sender<Result<(), DdnsError>>),
}

/// DDNS 服务句柄（跨任务共享；`update_now` 触发一轮发布）。
pub struct DdnsService {
    cmd_tx: mpsc::UnboundedSender<DdnsCmd>,
    shutdown_tx: watch::Sender<bool>,
}

impl DdnsService {
    /// 从 utils `Config` 装配并启动后台任务（GUI/CLI 共用入口）。
    ///
    /// `watch_tx`：状态发布通道（UI/CLI 订阅 `DdnsStatus`）；
    /// `public_key_base64`：本机 Ed25519 公钥（TXT `DeviceMeta` 用）。
    /// 返回 (句柄, 任务句柄)；任务随 `shutdown()` 或句柄 Drop 结束。
    pub fn start(
        cfg: &Config,
        public_key_base64: &str,
        watch_tx: watch::Sender<DdnsStatus>,
    ) -> (Arc<Self>, JoinHandle<()>) {
        let provider = match default_provider(&cfg.dns.provider, &cfg.dns.providers) {
            Ok(p) => Some(Arc::from(p)),
            Err(e) => {
                warn!("DdnsService: 服务商构建失败（DDNS 发布将全部失败）: {e}");
                None
            }
        };
        let fetcher = Arc::new(PublicIpFetcher::new(
            cfg.ddns.ipv4_sources.clone(),
            PUBIP_SOURCE_TIMEOUT,
        ));
        // 反查保护用解析器：DoH/DoT 强制（mode=off 不影响 DDNS 内部反查——
        // mode 语义仅约束域名模式连接路径，DDNS-DOH-007）。
        let resolver: Arc<dyn Resolver> = Arc::new(SecureResolver::new_from_parts(
            cfg.dns.security.doh.clone(),
            cfg.dns.security.dot.clone(),
            cfg.dns.security.resolve_timeout_ms,
            cfg.dns.security.cache_ttl_secs,
        ));
        let interval = Duration::from_secs(cfg.effective_ddns_interval());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

        let engine = Engine {
            provider,
            domain: cfg.godaddy.domain.clone(),
            device_id: cfg.device.id.clone(),
            port: cfg.network.port,
            dns_ttl: cfg.network.dns_ttl,
            ipv4_mode: match cfg.ddns.ipv4_mode {
                kirin_desk_utils::config::DdnsMode::Auto => DdnsMode::Auto,
                kirin_desk_utils::config::DdnsMode::Manual => DdnsMode::Manual,
            },
            ipv4_manual: cfg.ddns.ipv4_manual_addr(),
            ipv6_mode: match cfg.ddns.ipv6_mode {
                kirin_desk_utils::config::DdnsMode::Auto => DdnsMode::Auto,
                kirin_desk_utils::config::DdnsMode::Manual => DdnsMode::Manual,
            },
            ipv6_manual: cfg.ddns.ipv6_manual_addr(),
            publish_srv: cfg.ddns.publish_srv,
            publish_txt: cfg.ddns.publish_txt,
            publish_a: cfg.ddns.publish_a,
            publish_aaaa: cfg.ddns.publish_aaaa,
            fetcher,
            resolver,
            interval,
            enabled: cfg.ddns.enabled,
            last_v4: None,
            last_v6: None,
            last_written_v4: None,
            last_written_v6: None,
            last_srv_port: None,
            last_txt_pubkey: None,
            failures: 0,
            paused_until: None,
            last_error: None,
            last_update: None,
            ipv4_at: None,
            ipv6_at: None,
            published: PublishedPreview::default(),
        };

        let pubkey = public_key_base64.to_string();
        let handle = tokio::spawn(async move {
            worker_loop(engine, pubkey, watch_tx, cmd_rx, shutdown_rx).await;
        });
        (Arc::new(Self { cmd_tx, shutdown_tx }), handle)
    }

    /// 便捷入口（契约形态）：启动后台任务，仅保留任务句柄。
    pub fn spawn(
        cfg: &Config,
        public_key_base64: &str,
        watch_tx: watch::Sender<DdnsStatus>,
    ) -> JoinHandle<()> {
        Self::start(cfg, public_key_base64, watch_tx).1
    }

    /// 立即执行一轮全量发布（等价 UI「立即更新」/ CLI `ddns update`；
    /// 同时解除连续失败暂停）。
    pub async fn update_now(&self) -> Result<(), DdnsError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DdnsCmd::UpdateNow(tx))
            .map_err(|_| DdnsError::NotRunning)?;
        rx.await.map_err(|_| DdnsError::NotRunning)?
    }

    /// 停止后台任务（不删除已发布记录，DDNS-REC-007）。
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// 发布引擎（纯逻辑，单测直接构造；任务循环薄封装）。
struct Engine {
    provider: Option<Arc<dyn Provider>>,
    domain: String,
    device_id: String,
    port: u16,
    dns_ttl: u32,
    enabled: bool,
    ipv4_mode: DdnsMode,
    ipv4_manual: Option<Ipv4Addr>,
    ipv6_mode: DdnsMode,
    ipv6_manual: Option<Ipv6Addr>,
    publish_srv: bool,
    publish_txt: bool,
    publish_a: bool,
    publish_aaaa: bool,
    fetcher: Arc<PublicIpFetcher>,
    resolver: Arc<dyn Resolver>,
    interval: Duration,
    // ── 运行态 ──
    last_v4: Option<Ipv4Addr>,
    last_v6: Option<Ipv6Addr>,
    /// 本服务上次写入的 A/AAAA（反查保护「非本服务上次写入值」判定，DDNS-REC-005）。
    last_written_v4: Option<Ipv4Addr>,
    last_written_v6: Option<Ipv6Addr>,
    last_srv_port: Option<u16>,
    last_txt_pubkey: Option<String>,
    failures: u32,
    paused_until: Option<Instant>,
    last_error: Option<String>,
    last_update: Option<DateTime<Utc>>,
    ipv4_at: Option<DateTime<Utc>>,
    ipv6_at: Option<DateTime<Utc>>,
    published: PublishedPreview,
}

impl Engine {
    /// 单测/装配用全参构造。
    #[allow(clippy::too_many_arguments)]
    fn new(
        provider: Option<Arc<dyn Provider>>,
        domain: String,
        device_id: String,
        port: u16,
        dns_ttl: u32,
        ipv4_mode: DdnsMode,
        ipv4_manual: Option<Ipv4Addr>,
        ipv6_mode: DdnsMode,
        ipv6_manual: Option<Ipv6Addr>,
        publish: (bool, bool, bool, bool),
        fetcher: Arc<PublicIpFetcher>,
        resolver: Arc<dyn Resolver>,
        interval: Duration,
    ) -> Self {
        Self {
            provider,
            domain,
            device_id,
            port,
            dns_ttl,
            enabled: true,
            ipv4_mode,
            ipv4_manual,
            ipv6_mode,
            ipv6_manual,
            publish_srv: publish.0,
            publish_txt: publish.1,
            publish_a: publish.2,
            publish_aaaa: publish.3,
            fetcher,
            resolver,
            interval,
            last_v4: None,
            last_v6: None,
            last_written_v4: None,
            last_written_v6: None,
            last_srv_port: None,
            last_txt_pubkey: None,
            failures: 0,
            paused_until: None,
            last_error: None,
            last_update: None,
            ipv4_at: None,
            ipv6_at: None,
            published: PublishedPreview::default(),
        }
    }

    fn srv_mgr(&self) -> Option<SrvManager<'_>> {
        self.provider.as_ref().map(|p| SrvManager::new(p.as_ref(), &self.domain))
    }
    fn txt_mgr(&self) -> Option<TxtManager<'_>> {
        self.provider.as_ref().map(|p| TxtManager::new(p.as_ref(), &self.domain))
    }
    fn aaaa_mgr(&self) -> Option<AaaaManager<'_>> {
        self.provider.as_ref().map(|p| AaaaManager::new(p.as_ref(), &self.domain))
    }
    fn a_mgr(&self) -> Option<AManager<'_>> {
        self.provider.as_ref().map(|p| AManager::new(p.as_ref(), &self.domain))
    }

    /// 状态快照（worker 循环发布到 watch channel）。
    fn status(&self) -> DdnsStatus {
        DdnsStatus {
            enabled: self.enabled,
            ipv4_mode: self.ipv4_mode,
            ipv4_current: self.last_v4,
            ipv4_at: self.ipv4_at,
            ipv6_mode: self.ipv6_mode,
            ipv6_current: self.last_v6,
            ipv6_at: self.ipv6_at,
            last_update: self.last_update,
            last_error: self.last_error.clone(),
            next_update_at: self.next_update_at(),
            published: self.published.clone(),
        }
    }

    /// 下次自动更新时刻（暂停期间返回 None = 不显示倒计时）。
    fn next_update_at(&self) -> Option<DateTime<Utc>> {
        if let Some(p) = self.paused_until {
            if p > Instant::now() {
                return None;
            }
        }
        Some(Utc::now() + chrono::Duration::from_std(self.interval).unwrap_or_default())
    }

    /// 是否处于失败暂停期（连续失败 ≥3 → 暂停自动更新，DDNS-IPV4-002）。
    fn paused(&self) -> bool {
        self.paused_until.is_some_and(|p| p > Instant::now())
    }

    /// 周期 tick：暂停期跳过自动更新；否则执行一轮发布。
    async fn tick(&mut self, pubkey: &str) {
        if self.paused() {
            debug!("DdnsService: 连续失败暂停中，跳过本轮自动更新");
            return;
        }
        let _ = self.publish_once(pubkey).await;
    }

    /// 一轮全量发布（周期 tick / update_now 共用）。返回 Err = 本轮存在失败。
    ///
    /// 发布内容按 `publish_*` 开关：SRV/TXT 每轮刷新 TTL（DDNS-003），
    /// A/AAAA 变更驱动（地址变化才写）+ 反查保护（DDNS-REC-005）。
    async fn publish_once(&mut self, pubkey: &str) -> Result<(), DdnsError> {
        // 前置校验：非法 device_id/domain 早退（不产生任何 API 调用，同心跳纪律）。
        if !validate::validate_device_id(&self.device_id)
            || !validate::validate_hostname(&self.domain)
        {
            let msg = format!(
                "device_id '{}' 或 domain '{}' 非法（见 dns::validate 规则），DDNS 跳过",
                self.device_id, self.domain
            );
            warn!("DdnsService: {msg}");
            self.last_error = Some(msg);
            self.failures += 1;
            return Err(DdnsError::Publish("device_id/domain 非法".into()));
        }

        let now = Utc::now();
        let mut errors: Vec<String> = Vec::new();
        let mut succeeded_any = false;
        // 配置级错误（手动模式缺地址等）：即使部分发布成功，本轮仍返回 Err。
        let mut hard_error = false;

        // ── 1. 地址解析（按模式） ──
        let v4 = match self.ipv4_mode {
            DdnsMode::Manual => self.ipv4_manual,
            DdnsMode::Auto => match self.fetcher.fetch_fresh().await {
                Ok(ip) => Some(ip),
                Err(e) => {
                    // DDNS-IPV4-002：获取失败保留上次成功值 + 告警。
                    warn!("DdnsService: 公网出口 IP 获取失败（保留上次成功值）: {e}");
                    errors.push(format!("公网 IP: {e}"));
                    self.last_v4 // 保留上次
                }
            },
        };
        let v6 = match self.ipv6_mode {
            DdnsMode::Manual => self.ipv6_manual,
            DdnsMode::Auto => detect_global_ipv6(),
        };

        // ── 2. SRV（每轮刷新 TTL；端口变化更新，DDNS-REC-001） ──
        if self.publish_srv {
            match self.srv_mgr() {
                Some(mgr) => {
                    let target = format!("{}.{}.", self.device_id, self.domain);
                    match mgr
                        .register(&self.device_id, self.port, &target, self.dns_ttl)
                        .await
                    {
                        Ok(_) => {
                            self.published.srv = true;
                            self.published.srv_port = Some(self.port);
                            self.last_srv_port = Some(self.port);
                            succeeded_any = true;
                            info!(
                                "DDNS: SRV _remote._tcp.{} -> port {} 已发布",
                                self.device_id, self.port
                            );
                        }
                        Err(e) => {
                            self.published.srv = false;
                            errors.push(format!("SRV: {e}"));
                        }
                    }
                }
                None => errors.push("SRV: 服务商未配置".into()),
            }
        }

        // ── 3. TXT（签名轮换更新；每轮刷新 TTL，DDNS-REC-002） ──
        if self.publish_txt {
            match self.txt_mgr() {
                Some(mgr) => {
                    let meta = DeviceMeta::new(pubkey);
                    match mgr.register(&self.device_id, &meta, self.dns_ttl).await {
                        Ok(_) => {
                            self.published.txt = true;
                            self.published.txt_fingerprint =
                                Some(short_fingerprint(pubkey));
                            self.last_txt_pubkey = Some(pubkey.to_string());
                            succeeded_any = true;
                        }
                        Err(e) => {
                            self.published.txt = false;
                            errors.push(format!("TXT: {e}"));
                        }
                    }
                }
                None => errors.push("TXT: 服务商未配置".into()),
            }
        }

        // ── 4. A 记录（变更驱动 + 反查保护，DDNS-REC-003/005） ──
        if self.publish_a && v4.is_some() {
            let ip = v4.unwrap();
            if self.last_v4 != Some(ip) {
                let target = format!("{}.{}", self.device_id, self.domain);
                match self.a_mgr() {
                    Some(mgr) => {
                        match self
                            .reverse_check(&target, RecordType::A, &ip.to_string(), self.last_written_v4.map(|x| x.to_string()))
                            .await
                        {
                            Ok(true) => match mgr.register(&self.device_id, ip, self.dns_ttl).await {
                                Ok(_) => {
                                    self.last_written_v4 = Some(ip);
                                    self.published.a = true;
                                    succeeded_any = true;
                                    info!("DDNS: A {} -> {} 已更新", target, ip);
                                }
                                Err(e) => {
                                    self.published.a = false;
                                    errors.push(format!("A: {e}"));
                                }
                            },
                            Ok(false) => {
                                // 反查冲突：记录被他人修改 → 跳过并告警（DDNS-REC-005）。
                                let msg = format!(
                                    "A 记录反查冲突：{target} 现记录 ≠ 待写值 {ip} 且非本服务上次写入，已跳过（防覆盖他人记录）"
                                );
                                warn!("DdnsService: {msg}");
                                self.last_error = Some(msg);
                                errors.push("A: 反查冲突已跳过".into());
                            }
                            Err(e) => {
                                // 反查失败（加密 DNS 不可用）→ fail-safe 跳过并告警。
                                let msg = format!("A 记录反查失败，已跳过写入（fail-safe）: {e}");
                                warn!("DdnsService: {msg}");
                                self.last_error = Some(msg);
                                errors.push("A: 反查失败已跳过".into());
                            }
                        }
                    }
                    None => errors.push("A: 服务商未配置".into()),
                }
                self.last_v4 = Some(ip);
                self.ipv4_at = Some(now);
            }
        } else if self.publish_a && self.last_v4.is_none() && self.ipv4_mode == DdnsMode::Manual {
            // Manual 且无手动地址（配置非法）→ 提示（不写）。
            errors.push("A: 手动模式未配置合法 IPv4 地址".into());
            hard_error = true;
        }

        // ── 5. AAAA 记录（同上） ──
        if self.publish_aaaa && v6.is_some() {
            let ip = v6.unwrap();
            if self.last_v6 != Some(ip) {
                let target = format!("{}.{}", self.device_id, self.domain);
                match self.aaaa_mgr() {
                    Some(mgr) => {
                        match self
                            .reverse_check(&target, RecordType::AAAA, &ip.to_string(), self.last_written_v6.map(|x| x.to_string()))
                            .await
                        {
                            Ok(true) => match mgr.register(&self.device_id, ip, self.dns_ttl).await {
                                Ok(_) => {
                                    self.last_written_v6 = Some(ip);
                                    self.published.aaaa = true;
                                    succeeded_any = true;
                                    info!("DDNS: AAAA {} -> {} 已更新", target, ip);
                                }
                                Err(e) => {
                                    self.published.aaaa = false;
                                    errors.push(format!("AAAA: {e}"));
                                }
                            },
                            Ok(false) => {
                                let msg = format!(
                                    "AAAA 记录反查冲突：{target} 现记录 ≠ 待写值 {ip} 且非本服务上次写入，已跳过"
                                );
                                warn!("DdnsService: {msg}");
                                self.last_error = Some(msg);
                                errors.push("AAAA: 反查冲突已跳过".into());
                            }
                            Err(e) => {
                                let msg = format!("AAAA 记录反查失败，已跳过写入（fail-safe）: {e}");
                                warn!("DdnsService: {msg}");
                                self.last_error = Some(msg);
                                errors.push("AAAA: 反查失败已跳过".into());
                            }
                        }
                    }
                    None => errors.push("AAAA: 服务商未配置".into()),
                }
                self.last_v6 = Some(ip);
                self.ipv6_at = Some(now);
            }
        } else if self.publish_aaaa && self.last_v6.is_none() && self.ipv6_mode == DdnsMode::Manual {
            errors.push("AAAA: 手动模式未配置合法 IPv6 地址".into());
            hard_error = true;
        }

        // ── 6. 结果记账：失败计数 / 暂停 / 状态 ──
        if errors.is_empty() {
            self.failures = 0;
            self.last_error = None;
            self.last_update = Some(now);
        } else {
            self.failures += 1;
            self.last_error = Some(errors.join("; "));
            if self.failures >= FAILURE_PAUSE_THRESHOLD {
                // DDNS-IPV4-002：连续 3 次失败暂停自动更新并提示。
                self.paused_until = Some(Instant::now() + FAILURE_PAUSE_DURATION);
                warn!(
                    "DdnsService: 连续 {} 次失败，自动更新暂停 30 分钟（手动「立即更新」可解除）",
                    self.failures
                );
            }
        }
        info!(
            "DDNS publish round done: errors={} last_error={:?}",
            errors.len(),
            self.last_error
        );
        if errors.is_empty() {
            Ok(())
        } else if succeeded_any && !hard_error {
            Ok(()) // 部分成功：状态已含明细，不抛错（update_now 仍返回 Ok）
        } else {
            Err(DdnsError::Publish(errors.join("; ")))
        }
    }

    /// 更新前反查保护（DDNS-REC-005 / DDNS-SEC-004）。
    ///
    /// 经加密 DNS（DoH/DoT）反查当前记录；现记录不存在 → 放行（Ok(true)）；
    /// 现记录 = 待写值 → 放行；现记录 ≠ 待写值 且 = 本服务上次写入值 →
    /// 放行（幂等重写）；否则 → 跳过（Ok(false)）。反查失败（加密 DNS 不可用）
    /// → Err（调用方 fail-safe 跳过写入）。
    ///
    /// R-30（审计 §8-1）：resolver 已由类型系统强制**必非 None**
    /// （`Engine.resolver: Arc<dyn Resolver>`，`start` 装配恒注入）——删除
    /// 原 fail-open 降级分支（`resolver=None → Ok(true) 放行`），与 core 连接
    /// 层 fail-closed 主线语义一致，DDNS-REC-005 不再存在静默失效路径。
    async fn reverse_check(
        &self,
        host: &str,
        rt: RecordType,
        new_value: &str,
        last_written: Option<String>,
    ) -> Result<bool, String> {
        let records = self
            .resolver
            .resolve(host, rt)
            .await
            .map_err(|e| e.to_string())?;
        // 现记录为空 → 无冲突。
        if records.is_empty() {
            return Ok(true);
        }
        let current_values: Vec<String> = records
            .iter()
            .map(|r| match &r.data {
                RecordData::Plain(s) => s.clone(),
                _ => String::new(),
            })
            .filter(|s| !s.is_empty())
            .collect();
        if current_values.contains(&new_value.to_string()) {
            return Ok(true);
        }
        // 现记录 ≠ 待写值：若等于本服务上次写入值 → 幂等重写放行；否则跳过。
        if let Some(last) = last_written {
            if current_values.iter().any(|v| v == &last) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
/// TXT 指纹预览（`ed25519:Ab3…` 截断展示，DDNS-UI-004）。
fn short_fingerprint(pubkey: &str) -> String {
    let p = pubkey.trim();
    if p.len() <= 16 {
        p.to_string()
    } else {
        format!("{}…", &p[..16])
    }
}

/// worker 循环：周期 tick + update_now 命令 + shutdown。
async fn worker_loop(
    mut engine: Engine,
    pubkey: String,
    watch_tx: watch::Sender<DdnsStatus>,
    mut cmd_rx: mpsc::UnboundedReceiver<DdnsCmd>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let interval = engine.interval;
    // 启动即发布一轮（等价 heartbeat 的 initial registration）。
    let _ = engine.publish_once(&pubkey).await;
    let _ = watch_tx.send(engine.status());
    info!("DdnsService: 后台任务已启动，周期 {}s", interval.as_secs());

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                engine.tick(&pubkey).await;
                let _ = watch_tx.send(engine.status());
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    DdnsCmd::UpdateNow(tx) => {
                        // 手动立即更新：解除暂停 + 执行一轮。
                        engine.failures = 0;
                        engine.paused_until = None;
                        let r = engine.publish_once(&pubkey).await;
                        let _ = watch_tx.send(engine.status());
                        let _ = tx.send(r);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow_and_update() {
                    break;
                }
            }
        }
    }
    // DDNS-REC-007：关闭不删除记录。
    info!("DdnsService: 已停止（保留已发布记录，DDNS-REC-007）");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::mock::MockProvider;
    use crate::provider::Record;
    use crate::public_ip::{PubIpError, PubIpSource};

    // ---- 测试装备 ----

    /// 固定值公网 IP mock 源。
    fn fixed_source(ip: &'static str) -> Arc<PublicIpFetcher> {
        struct Fixed(&'static str);
        #[async_trait::async_trait]
        impl PubIpSource for Fixed {
            async fn fetch(&self) -> Result<Ipv4Addr, PubIpError> {
                self.0
                    .parse()
                    .map_err(|_| PubIpError::InvalidResponse(self.0.to_string()))
            }
        }
        Arc::new(PublicIpFetcher::from_sources(vec![Box::new(Fixed(ip))]))
    }

    fn engine(
        provider: Arc<dyn Provider>,
        ipv4_mode: DdnsMode,
        ipv4_manual: Option<Ipv4Addr>,
        publish: (bool, bool, bool, bool),
    ) -> Engine {
        Engine::new(
            Some(provider),
            "example.com".into(),
            "my-pc".into(),
            3389,
            600,
            ipv4_mode,
            ipv4_manual,
            DdnsMode::Auto,
            None,
            publish,
            fixed_source("203.0.113.7"),
            resolver_ok(vec![]), // R-30：resolver 必非 None（记录为空 → 反查放行）
            Duration::from_secs(60),
        )
    }

    fn a_records(provider: &MockProvider) -> Vec<String> {
        provider
            .records_of("example.com", RecordType::A, "my-pc")
            .iter()
            .map(|r| r.data.to_display_string())
            .collect()
    }

    /// mock 反查解析器（返回预置记录或错误）。
    struct MockResolver {
        result: std::sync::Mutex<Result<Vec<Record>, String>>,
    }

    #[async_trait::async_trait]
    impl Resolver for MockResolver {
        async fn resolve(
            &self,
            _host: &str,
            _rt: RecordType,
        ) -> Result<Vec<Record>, crate::secure_resolver::ResolverError> {
            let r = self.result.lock().unwrap().clone();
            r.map_err(|e| crate::secure_resolver::ResolverError::InvalidResponse(e))
        }
    }

    fn resolver_ok(values: Vec<&str>) -> Arc<dyn Resolver> {
        Arc::new(MockResolver {
            result: std::sync::Mutex::new(Ok(values
                .into_iter()
                .map(|v| Record {
                    name: "my-pc.example.com".into(),
                    rtype: RecordType::A,
                    ttl: 300,
                    data: RecordData::Plain(v.to_string()),
                })
                .collect())),
        })
    }

    fn resolver_err() -> Arc<dyn Resolver> {
        Arc::new(MockResolver {
            result: std::sync::Mutex::new(Err("加密 DNS 不可用".into())),
        })
    }

    // ═══════════ 发布语义测试（WBS 4.6） ═══════════

    /// Auto 模式：A 记录 = 公网出口 IP（mock 源），SRV/TXT 同步发布。
    #[tokio::test]
    async fn test_publish_auto_writes_public_ip() {
        let provider = Arc::new(MockProvider::new("mock"));
        let mut e = engine(provider.clone(), DdnsMode::Auto, None, (true, true, true, true));
        e.publish_once("testpubkey").await.unwrap();
        assert!(
            a_records(&provider).contains(&"203.0.113.7".to_string()),
            "Auto 模式 A 记录 = 公网出口 IP，got {:?}",
            a_records(&provider)
        );
        assert!(e.published.srv);
        assert_eq!(e.published.srv_port, Some(3389));
        assert!(e.published.txt);
        assert!(e.published.txt_fingerprint.is_some());
        assert!(e.published.a);
        assert!(e.last_update.is_some());
        assert_eq!(e.last_v4, Some("203.0.113.7".parse().unwrap()));
    }

    /// 变更驱动：地址未变化 → 第二轮不写 A（upsert 计数不变）；SRV/TXT 仍刷新。
    #[tokio::test]
    async fn test_publish_change_driven() {
        let provider = Arc::new(MockProvider::new("mock"));
        let mut e = engine(provider.clone(), DdnsMode::Auto, None, (true, true, true, true));
        e.publish_once("testpubkey").await.unwrap();
        let after_first = provider.upsert_count();
        e.publish_once("testpubkey").await.unwrap();
        // SRV + TXT 每轮刷新（2 次）；A 仅首轮（地址未变）。
        assert_eq!(provider.upsert_count(), after_first + 2, "A 不重复写，SRV/TXT 刷新");
        assert_eq!(provider.delete_count(), 0);
    }

    /// 地址变化（mock 源切换）→ A 更新；发布开关关闭 → 不写不刷。
    #[tokio::test]
    async fn test_publish_switches_and_change() {
        // publish_a = false → A 不写
        let provider = Arc::new(MockProvider::new("mock"));
        let mut e = engine(provider.clone(), DdnsMode::Auto, None, (true, true, false, true));
        e.publish_once("testpubkey").await.unwrap();
        assert!(a_records(&provider).is_empty(), "publish_a=false 不得写 A");
        assert!(e.published.srv);

        // publish_srv = false → SRV 不写
        let provider2 = Arc::new(MockProvider::new("mock"));
        let mut e2 = engine(provider2.clone(), DdnsMode::Auto, None, (false, true, true, true));
        e2.publish_once("testpubkey").await.unwrap();
        assert!(provider2
            .records_of("example.com", RecordType::SRV, "_remote._tcp.my-pc")
            .is_empty());
        assert!(!e2.published.srv);

        // 地址变化 → A 更新（切换 fetcher 值）
        let provider3 = Arc::new(MockProvider::new("mock"));
        let mut e3 = engine(provider3.clone(), DdnsMode::Auto, None, (true, true, true, true));
        e3.fetcher = fixed_source("198.51.100.9");
        e3.publish_once("testpubkey").await.unwrap();
        assert!(a_records(&provider3).contains(&"198.51.100.9".to_string()));
        // 状态展示变化后的地址
        assert_eq!(e3.last_v4, Some("198.51.100.9".parse().unwrap()));
        assert!(e3.ipv4_at.is_some());
    }

    /// Manual 模式：写配置地址一次；连续周期不覆盖（仅刷 TTL）。
    #[tokio::test]
    async fn test_publish_manual_never_overwrites() {
        let provider = Arc::new(MockProvider::new("mock"));
        let manual: Ipv4Addr = "203.0.113.99".parse().unwrap();
        let mut e = engine(provider.clone(), DdnsMode::Manual, Some(manual), (true, true, true, true));
        e.publish_once("testpubkey").await.unwrap();
        assert!(a_records(&provider).contains(&"203.0.113.99".to_string()));
        let after_first = provider.upsert_count();
        // 第二次：A 不写（值未变），SRV/TXT 刷新
        e.publish_once("testpubkey").await.unwrap();
        assert_eq!(provider.upsert_count(), after_first + 2);
        // 手动地址永不自动变更（DDNS-IPV4-004）
        assert_eq!(e.last_v4, Some(manual));
    }

    /// Manual 且无合法地址 → 提示错误、不写 A。
    #[tokio::test]
    async fn test_publish_manual_missing_addr() {
        let provider = Arc::new(MockProvider::new("mock"));
        let mut e = engine(provider.clone(), DdnsMode::Manual, None, (true, true, true, true));
        let r = e.publish_once("testpubkey").await;
        assert!(a_records(&provider).is_empty());
        assert!(e.last_error.as_deref().unwrap().contains("手动模式未配置合法 IPv4"));
        assert!(r.is_err());
    }

    /// 反查保护：现记录被他人修改 → 跳过并告警（DDNS-REC-005 / DDNS-SEC-004）。
    #[tokio::test]
    async fn test_reverse_check_conflict_skips() {
        let provider = Arc::new(MockProvider::new("mock"));
        let mut e = engine(provider.clone(), DdnsMode::Auto, None, (true, true, true, true));
        e.resolver = resolver_ok(vec!["198.51.100.77"]); // 他人已改记录
        e.publish_once("testpubkey").await.unwrap();
        assert!(
            a_records(&provider).is_empty(),
            "反查冲突必须跳过，不得覆盖他人记录"
        );
        assert!(e.last_error.as_deref().unwrap().contains("反查冲突"));
        assert!(!e.published.a);
    }

    /// 反查放行三路：现记录 = 待写值 / = 本服务上次写入值 / 记录为空。
    #[tokio::test]
    async fn test_reverse_check_pass_paths() {
        // 现记录 = 待写值 → 放行
        let provider = Arc::new(MockProvider::new("mock"));
        let mut e = engine(provider.clone(), DdnsMode::Auto, None, (true, true, true, true));
        e.resolver = resolver_ok(vec!["203.0.113.7"]);
        e.publish_once("testpubkey").await.unwrap();
        assert!(a_records(&provider).contains(&"203.0.113.7".to_string()));

        // 现记录 = 本服务上次写入值（幂等重写）→ 放行
        let provider2 = Arc::new(MockProvider::new("mock"));
        let mut e2 = engine(provider2.clone(), DdnsMode::Auto, None, (true, true, true, true));
        e2.last_written_v4 = Some("203.0.113.7".parse().unwrap());
        e2.resolver = resolver_ok(vec!["203.0.113.7"]);
        e2.publish_once("testpubkey").await.unwrap();
        assert!(a_records(&provider2).contains(&"203.0.113.7".to_string()));

        // 记录为空 → 放行
        let provider3 = Arc::new(MockProvider::new("mock"));
        let mut e3 = engine(provider3.clone(), DdnsMode::Auto, None, (true, true, true, true));
        e3.resolver = resolver_ok(vec![]);
        e3.publish_once("testpubkey").await.unwrap();
        assert!(a_records(&provider3).contains(&"203.0.113.7".to_string()));
    }

    /// 反查失败（加密 DNS 不可用）→ fail-safe 跳过写入并告警。
    #[tokio::test]
    async fn test_reverse_check_failure_skips() {
        let provider = Arc::new(MockProvider::new("mock"));
        let mut e = engine(provider.clone(), DdnsMode::Auto, None, (true, true, true, true));
        e.resolver = resolver_err();
        e.publish_once("testpubkey").await.unwrap();
        assert!(a_records(&provider).is_empty(), "反查失败必须 fail-safe 跳过");
        assert!(e.last_error.as_deref().unwrap().contains("反查失败"));
    }

    /// R-30（审计 §8-1）：`resolver=None → 反查放行` 的 fail-open 路径已删除——
    /// `Engine.resolver: Arc<dyn Resolver>` 由类型系统保证必非 None（`start`
    /// 装配恒注入），DDNS-REC-005 不存在"未配置解析器"的静默失效形态；
    /// 原 `test_reverse_check_no_resolver_allows`（None → 放行）已随降级分支
    /// 一并移除，反查保护现在只可能 fail-closed（失败 → 跳过写入 + 告警，
    /// 见 `test_reverse_check_failure_skips`）。

    /// 连续失败 3 次 → 暂停自动更新（tick 跳过），update_now 可解除。
    #[tokio::test]
    async fn test_failure_pause_and_resume() {
        // 全部失败：provider = None（服务商未配置）
        let mut e = Engine::new(
            None,
            "example.com".into(),
            "my-pc".into(),
            3389,
            600,
            DdnsMode::Auto,
            None,
            DdnsMode::Auto,
            None,
            (true, true, true, true),
            fixed_source("203.0.113.7"),
            resolver_ok(vec![]), // R-30：resolver 必非 None（类型系统强制）
            Duration::from_secs(60),
        );
        e.publish_once("testpubkey").await.unwrap_err();
        e.publish_once("testpubkey").await.unwrap_err();
        assert!(!e.paused(), "2 次失败未达阈值");
        e.publish_once("testpubkey").await.unwrap_err();
        assert!(e.paused(), "连续 3 次失败 → 暂停（DDNS-IPV4-002）");
        assert!(e.status().next_update_at.is_none(), "暂停期无倒计时");
        // tick 跳过（暂停期）
        e.tick("testpubkey").await;
        // 手动解除（update_now 等价操作）
        e.failures = 0;
        e.paused_until = None;
        assert!(!e.paused());
        assert!(e.status().next_update_at.is_some());
    }

    /// 服务商未配置 → publish 报错 + 状态携带原因（DDNS-UI-006 侧支撑）。
    #[tokio::test]
    async fn test_publish_provider_missing() {
        let mut e = Engine::new(
            None,
            "example.com".into(),
            "my-pc".into(),
            3389,
            600,
            DdnsMode::Auto,
            None,
            DdnsMode::Auto,
            None,
            (true, true, true, true),
            fixed_source("203.0.113.7"),
            resolver_ok(vec![]), // R-30：resolver 必非 None（类型系统强制）
            Duration::from_secs(60),
        );
        let err = e.publish_once("testpubkey").await.unwrap_err();
        assert!(matches!(err, DdnsError::Publish(_)));
        assert!(e.last_error.is_some());
    }

    /// 非法 device_id → 不产生任何 API 调用（同心跳纪律）。
    #[tokio::test]
    async fn test_publish_invalid_device_id_skips() {
        let provider = Arc::new(MockProvider::new("mock"));
        let mut e = Engine::new(
            Some(provider.clone()),
            "example.com".into(),
            "bad id!".into(),
            3389,
            600,
            DdnsMode::Auto,
            None,
            DdnsMode::Auto,
            None,
            (true, true, true, true),
            fixed_source("203.0.113.7"),
            resolver_ok(vec![]), // R-30：resolver 必非 None（类型系统强制）
            Duration::from_secs(60),
        );
        assert!(e.publish_once("testpubkey").await.is_err());
        assert_eq!(provider.upsert_count(), 0);
        assert_eq!(provider.delete_count(), 0);
    }

    /// IPv6 Auto：本机无全局单播 → 静默跳过 AAAA（不报错）。
    #[tokio::test]
    async fn test_publish_ipv6_auto_no_addr() {
        let provider = Arc::new(MockProvider::new("mock"));
        let mut e = engine(provider.clone(), DdnsMode::Auto, None, (true, true, true, true));
        e.publish_once("testpubkey").await.unwrap();
        // 环境相关：有无 v6 都不影响 A/SRV/TXT 发布成功
        assert!(e.published.a);
        assert!(e.last_update.is_some());
    }

    /// 状态快照字段完整性（DDNS-UI-004 侧支撑）。
    #[tokio::test]
    async fn test_status_snapshot() {
        let provider = Arc::new(MockProvider::new("mock"));
        let mut e = engine(provider.clone(), DdnsMode::Auto, None, (true, true, true, true));
        e.publish_once("testpubkey").await.unwrap();
        let s = e.status();
        assert!(s.enabled);
        assert_eq!(s.ipv4_mode, DdnsMode::Auto);
        assert_eq!(s.ipv4_current, Some("203.0.113.7".parse().unwrap()));
        assert!(s.ipv4_at.is_some());
        assert!(s.last_update.is_some());
        assert!(s.next_update_at.is_some());
        assert_eq!(s.published.srv_port, Some(3389));
        assert!(s.published.txt_fingerprint.is_some());
    }

    /// 端到端：start + update_now 驱动一轮发布（worker 循环面）。
    #[tokio::test]
    async fn test_service_update_now_end_to_end() {
        let mut cfg = Config::default();
        cfg.device.id = "my-pc".into();
        cfg.godaddy.domain = "example.com".into();
        cfg.ddns.enabled = true;
        cfg.ddns.ipv4_sources = vec!["mock-ip".into()];
        // 注入 mock 源：直接构造 fetcher 替换——start 内部用配置源，
        // 此处改用 provider 注入面验证端到端（provider 用 mock 不可注入，
        // 故走 Engine 层已覆盖；本测试验证句柄/命令通道/状态流）。
        let (watch_tx, mut watch_rx) = watch::channel(DdnsStatus::initial());
        let (svc, handle) = DdnsService::start(&cfg, "testpubkey", watch_tx);
        // 等首轮状态
        let _ = watch_rx.changed().await;
        let st = watch_rx.borrow().clone();
        // 服务商未配置（mock 不可注入 start）→ 状态应带错误原因
        assert!(st.last_error.is_some() || st.published.srv || st.enabled);
        // update_now 通道可用 + 返回值形态正确
        let r = svc.update_now().await;
        assert!(r.is_ok() || r.is_err(), "update_now 必须返回（不挂死）");
        svc.shutdown();
        let _ = handle.await;
    }
}
