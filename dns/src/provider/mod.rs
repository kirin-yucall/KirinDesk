//! M9-DNS000: Provider 抽象层（`M9-DNS000_Provider抽象接口规范.md`）
//!
//! 上层（discovery / heartbeat / srv / aaaa / txt / UI / CLI）**只依赖
//! `dyn Provider`**，不感知任何厂商差异。一个服务商 = 一个自包含子目录
//! （`dns/src/providers/<name>/`：HTTP 客户端 + 认证 + 序列化 + 错误映射），
//! 差异点（记录名格式、写入语义、SRV 表达、错误映射、限流）由适配层消化。
//!
//! 组成：
//! - [`record`]：统一 Record / RecordType / RecordData
//! - [`mock`]：`MockProvider` 内存实现（契约测试 + 上层单测）
//! - 本文件：`Provider` trait / `ProviderError` / `ProviderCapabilities` /
//!   `ProviderRegistry` / `Credential`

pub mod mock;
pub mod record;

pub use record::{Record, RecordData, RecordType};

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// 统一错误（`M9-DNS000_Provider抽象接口规范.md` §三）。
///
/// 所有服务商错误映射为该枚举，上层（UI/CLI/服务层）不感知厂商原始细节；
/// 原始错误串只允许进日志。
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("认证失败: {detail}")]
    Auth { detail: String },
    #[error("参数错误: {detail}")]
    InvalidParameter { detail: String },
    #[error("记录/域名不存在: {what}")]
    NotFound { what: String },
    #[error("限流，需等待 {retry_after:?} 秒")]
    RateLimited { retry_after: Option<u64> },
    #[error("服务商返回 {status}: {body}")]
    Server { status: u16, body: String },
    #[error("网络错误: {0}")]
    Network(#[from] reqwest::Error),
    #[error("序列化错误: {0}")]
    Json(#[from] serde_json::Error),
    #[error("服务商不支持该能力: {0}")]
    Unsupported(&'static str),
    #[error("其他: {0}")]
    Other(String),
}

/// 能力声明（DNS-MNT-013 降级判断用；如西部数码/新网不支持 SRV）。
#[derive(Debug, Clone, Default)]
pub struct ProviderCapabilities {
    /// 是否支持 SRV（不支持 → 设备注册降级为 A/AAAA+TXT，UI 给出明确提示）。
    pub srv: bool,
    /// 是否支持 NS 记录。
    pub ns: bool,
    /// 是否支持自定义 TTL（false = 使用服务商默认，忽略 Record.ttl）。
    pub ttl: bool,
    /// 是否支持修改记录名（false = 修改名称需删除重建）。
    pub rename: bool,
}

impl ProviderCapabilities {
    /// 全能力（默认假设：支持全部；个别服务商显式关闭）。
    pub fn all() -> Self {
        Self {
            srv: true,
            ns: true,
            ttl: true,
            rename: true,
        }
    }
}

/// Provider trait（`M9-DNS000_Provider抽象接口规范.md` §四）。
///
/// 全异步（reqwest + tokio），`Provider` 对象可 `Arc` 共享
/// （心跳/发现并发用）。`#[async_trait]` 保证 trait object 方法返回的
/// future 为 `Send`，可安全用于 `tokio::join!` / `tokio::spawn`。
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    /// 服务商注册表键名（如 "godaddy"、"cloudflare"），与配置 `[dns.providers.*]` 一致。
    fn name(&self) -> &'static str;

    /// 测试连接：执行最小查询（域名列表取 1 条），失败返回统一错误。
    async fn test_connection(&self) -> Result<(), ProviderError>;

    /// 域名（zone）列表。
    async fn list_domains(&self) -> Result<Vec<String>, ProviderError>;

    /// 查询记录：`name` 传 `None` 查全表；`rtype` 传 `None` 查全部类型。
    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError>;

    /// 幂等写入单条记录：存在则更新、不存在则创建。
    ///
    /// 厂商 put 语义差异由适配层消化：GoDaddy 场景 = 先查全表 → 组装目标
    /// 集合 → PUT 整组替换（同 name+rtype 其他条必须保留）。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError>;

    /// 删除单条记录（按 name+rtype 定位；统一语义 = 删除该 name+rtype 下全部记录）。
    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError>;

    /// 能力声明：SRV 是否支持等（DNS-MNT-013 降级判断用）。
    fn capabilities(&self) -> ProviderCapabilities;
}

/// 服务商注册表：name → 构造器（从配置凭据构建）。
pub struct ProviderRegistry {
    factories: HashMap<&'static str, fn(&Credential) -> Box<dyn Provider>>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// 注册一个服务商构造器（由 `providers::register_all` 统一调用）。
    pub fn register(&mut self, name: &'static str, factory: fn(&Credential) -> Box<dyn Provider>) {
        self.factories.insert(name, factory);
    }

    /// 全部已注册服务商键名（排序，供 CLI `dns list-providers` / UI 下拉框）。
    pub fn names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.factories.keys().copied().collect();
        names.sort_unstable();
        names
    }

    /// 是否已注册（未注册 = 无客户端实现）。
    pub fn has(&self, name: &str) -> bool {
        self.factories.contains_key(name)
    }

    /// 按名称 + 凭据构建 Provider 实例。
    pub fn build(
        &self,
        name: &str,
        cred: &Credential,
    ) -> Result<Box<dyn Provider>, ProviderError> {
        match self.factories.get(name) {
            Some(factory) => Ok(factory(cred)),
            None => Err(ProviderError::Other(format!("未注册的服务商: {name}"))),
        }
    }
}

/// 通用凭据容器（`M9-DNS000_Provider抽象接口规范.md` §五）。
///
/// 服务商子目录定义自己的字段并反序列化；配置层存储为
/// `[dns.providers.{name}]` 原始字符串表，经 [`Credential::from_config_map`]
/// 转换为本枚举对应变体。凭据不参与 `Display`/日志输出。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "provider", content = "cred", rename_all = "kebab-case")]
pub enum Credential {
    Godaddy {
        api_key: String,
        api_secret: String,
        api_url: String,
    },
    Cloudflare {
        api_token: String,
    },
    Aliyun {
        access_key_id: String,
        access_key_secret: String,
    },
    Dnspod {
        secret_id: String,
        secret_key: String,
    },
    Route53 {
        access_key_id: String,
        secret_access_key: String,
        region: String,
    },
    Azure {
        tenant_id: String,
        client_id: String,
        client_secret: String,
        subscription_id: String,
        resource_group: String,
    },
    Google {
        service_account_json: String,
        project: String,
    },
    Huawei {
        access_key: String,
        secret_key: String,
        region: String,
    },
    Namecheap {
        api_user: String,
        api_key: String,
        user_name: String,
        client_ip: String,
    },
    Digitalocean {
        token: String,
    },
    Vultr {
        token: String,
    },
    Linode {
        token: String,
    },
    Hetzner {
        token: String,
    },
    Ovh {
        app_key: String,
        app_secret: String,
        consumer_key: String,
    },
    Porkbun {
        api_key: String,
        secret_key: String,
    },
    Baidu {
        access_key_id: String,
        secret_access_key: String,
    },
    Volcengine {
        access_key_id: String,
        secret_access_key: String,
        region: String,
    },
    Jdcloud {
        access_key: String,
        secret_key: String,
        region: String,
    },
    Westcn {
        username: String,
        api_password: String,
        domain_key: Option<String>,
    },
    Xinnet {
        api_key: String,
        secret_key: String,
        client_ip: String,
    },
}

impl Credential {
    /// 从配置层字符串表构建对应服务商变体。
    ///
    /// `fields` 键名须与该变体字段一致（缺失 → `Other("凭据字段不完整")`，
    /// 含缺失键名，便于 UI/CLI 提示用户补全）。
    pub fn from_config_map(
        provider: &str,
        fields: &BTreeMap<String, String>,
    ) -> Result<Self, ProviderError> {
        let value = serde_json::json!({ "provider": provider, "cred": fields });
        serde_json::from_value(value).map_err(|e| {
            ProviderError::Other(format!("服务商「{provider}」凭据字段不完整: {e}"))
        })
    }

    /// 构建该凭据的配置层字符串表（供 UI 保存 / 展示回填；不包含明文日志）。
    pub fn to_config_map(&self) -> BTreeMap<String, String> {
        // 通过 serde 中转（tag/content 内嵌形态的 `cred` 字段即扁平表）。
        let value = serde_json::to_value(self).unwrap_or_default();
        value
            .get("cred")
            .and_then(|c| serde_json::from_value(c.clone()).ok())
            .unwrap_or_default()
    }
}

/// 便捷构造：provider 凭据为空的空表（`Credential::from_config_map` 校验用）。
#[cfg(test)]
pub(crate) fn cred_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_from_config_map_roundtrip() {
        let mut fields = BTreeMap::new();
        fields.insert("api_token".to_string(), "tok123".to_string());
        let cred = Credential::from_config_map("cloudflare", &fields).unwrap();
        assert!(matches!(&cred, Credential::Cloudflare { api_token } if api_token == "tok123"));
        // 往返：枚举 → 配置表 → 枚举，值不变。
        let map = cred.to_config_map();
        assert_eq!(map.get("api_token").map(String::as_str), Some("tok123"));
        let cred2 = Credential::from_config_map("cloudflare", &map).unwrap();
        assert!(matches!(cred2, Credential::Cloudflare { api_token } if api_token == "tok123"));
    }

    #[test]
    fn credential_missing_fields_reports_error() {
        let mut fields = BTreeMap::new();
        fields.insert("api_token".to_string(), "tok".to_string());
        // godaddy 需要 api_key/api_secret/api_url 三个字段。
        let err = Credential::from_config_map("godaddy", &fields).unwrap_err();
        assert!(matches!(err, ProviderError::Other(_)));
        assert!(err.to_string().contains("godaddy"));
    }

    #[test]
    fn credential_serde_tag_shape() {
        let cred = Credential::Godaddy {
            api_key: "k".into(),
            api_secret: "s".into(),
            api_url: "https://api.godaddy.com".into(),
        };
        let v = serde_json::to_value(&cred).unwrap();
        assert_eq!(v["provider"], "godaddy");
        assert_eq!(v["cred"]["api_key"], "k");
    }

    #[test]
    fn registry_names_sorted_and_unique() {
        let mut r = ProviderRegistry::new();
        r.register("b", |_| Box::new(mock::MockProvider::new("b")));
        r.register("a", |_| Box::new(mock::MockProvider::new("a")));
        r.register("a", |_| Box::new(mock::MockProvider::new("a"))); // 覆盖注册
        assert_eq!(r.names(), vec!["a", "b"]);
        assert!(r.has("a"));
        assert!(!r.has("c"));
    }

    #[test]
    fn registry_build_unknown_provider() {
        let r = ProviderRegistry::new();
        let fields = cred_map(&[("api_key", "k"), ("api_secret", "s"), ("api_url", "https://api.godaddy.com")]);
        let cred = Credential::from_config_map("godaddy", &fields).unwrap();
        match r.build("godaddy", &cred) {
            Err(ProviderError::Other(msg)) => assert!(msg.contains("未注册")),
            Ok(_) => panic!("expected Other(未注册) error, got Ok"),
            Err(e) => panic!("expected Other(未注册) error, got {e:?}"),
        }
    }
}
