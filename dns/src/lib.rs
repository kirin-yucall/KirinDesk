//! GoDaddy DNS module — Kirin protocol style
//!
//! # DNS Layout (Kirin + SRV hybrid)
//!
//! Each device has its own subdomain: `{device_id}.{domain}`.
//!
//! ```text
//! _remote._tcp.{device_id}.{domain}  SRV  →  0 1 {port} {device_id}.{domain}.
//! {device_id}.{domain}               TXT  →  {"key":"ed25519:base64...","proto":"ip6desk","ver":"1"}
//! {device_id}.{domain}               AAAA →  2001:db8::1
//! {device_id}.{domain}               A    →  203.0.113.7   (IPv4-only / dual-stack 设备)
//! ```
//!
//! - **SRV**: Port (standard DNS service discovery, ISP-proof)
//! - **TXT**: JSON metadata with Ed25519 public key
//! - **AAAA**: IPv6 address (optional; absent → `Ipv6Addr::UNSPECIFIED` 哨兵)
//! - **A**: IPv4 address (optional)
//!
//! # M9-DNS000 多服务商门面
//!
//! `provider`（抽象层）/ `providers`（20 家服务商实现）为 M9-DNS000 新增；
//! 上层只依赖 `dyn Provider`。`default_provider()` 按配置构建当前激活服务商
//! （读取 `[dns] provider` + `[dns.providers.*]`）。旧 `godaddy` 模块逻辑已
//! 迁入 `providers/godaddy` 并实现 `Provider` trait（M9-DNS001）。
//!
//! # M9-DNS021 服务层多服务商化
//!
//! 顶层服务（`srv` / `aaaa` / `a` / `txt` / `discovery` / `heartbeat`）已
//! 全部改为消费 `&dyn Provider` / `Arc<dyn Provider>`，不再引用具体服务商
//! 类型；`DiscoveryError` 经 `Provider` 变体收敛统一错误（`GoDaddyError`
//! 不再向上传播）。

pub mod a;
pub mod aaaa;
pub mod ddns;
pub mod discovery;
pub mod heartbeat;
pub mod provider;
pub mod providers;
pub mod public_ip;
pub mod secure_resolver;
pub mod srv;
pub mod txt;
pub mod validate;

pub use ddns::{DdnsError, DdnsMode, DdnsService, DdnsStatus, PublishedPreview};
pub use discovery::{discover_device, DeviceInfo, DiscoveryError, DiscoveryService, IpFamily};
pub use provider::{Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry};
pub use provider::{Record, RecordData, RecordType};
pub use public_ip::{parse_response, PubIpError, PubIpSource, PublicIpFetcher};
pub use secure_resolver::{Resolver, ResolverError, ResolvedRecord, SecureResolver};
pub use txt::DeviceMeta;

use std::collections::BTreeMap;

/// 全局服务商注册表（懒初始化；`providers::register_all` 注册全部已实现服务商）。
pub fn provider_registry() -> &'static ProviderRegistry {
    static REGISTRY: std::sync::OnceLock<ProviderRegistry> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut registry = ProviderRegistry::new();
        providers::register_all(&mut registry);
        registry
    })
}

/// 按配置构建当前激活服务商（M9-DNS000 §四 / DNS-MNT-001）。
///
/// `provider` = `[dns] provider` 注册表键名；`providers` = `[dns.providers.*]`
/// 凭据表（配置层存储原始字符串，此处转 `Credential` 并构建客户端）。
pub fn provider_from_config(
    provider: &str,
    providers: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<Box<dyn Provider>, ProviderError> {
    let fields = providers.get(provider).ok_or_else(|| {
        ProviderError::Other(format!("未配置服务商「{provider}」的凭据（[dns.providers.{provider}]）"))
    })?;
    let cred = Credential::from_config_map(provider, fields)?;
    provider_registry().build(provider, &cred)
}

/// 便捷门面：当前激活服务商 + 凭据表 → `Box<dyn Provider>`。
pub fn default_provider(
    provider: &str,
    providers: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<Box<dyn Provider>, ProviderError> {
    provider_from_config(provider, providers)
}
