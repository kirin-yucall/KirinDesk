//! M9-DNS002: Cloudflare 服务商适配
//!
//! 依据 `M9-DNS000_Provider抽象接口规范.md` 与 `M9-DNS002_Cloudflare服务商适配.md`。
//!
//! - 认证：`Credential::Cloudflare { api_token }` → `Authorization: Bearer`
//! - 记录名：**FQDN**（根 "" → 域名本身；SRV 的 service/proto 从相对名拆分）
//! - 写入语义：单条 CRUD（POST 创建 / PATCH 更新 / DELETE）；upsert = 查(type+name)
//!   → 存在同 data 则 PATCH（含 TTL）、否则 POST（不产生重复）
//! - zone_id：先按域名查 `GET /zones?name=`，缓存 5 分钟，失效自动重查
//! - 限流：429 + Retry-After 退避重试一次；错误码映射见 `error.rs`
//! - 能力全开（`ProviderCapabilities::all()`）

mod client;
mod error;

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record, RecordType,
};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// zone_id 缓存有效期（5 分钟，过期自动重查）。
const ZONE_CACHE_TTL: Duration = Duration::from_secs(300);

/// Cloudflare Provider（内部持有客户端与 zone_id 缓存；Debug 脱敏）。
pub struct CloudflareProvider {
    client: client::CloudflareClient,
    /// domain → (zone_id, 查询时刻)。
    zone_cache: Mutex<HashMap<String, (String, Instant)>>,
}

impl std::fmt::Debug for CloudflareProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareProvider").field("client", &self.client).finish()
    }
}

impl CloudflareProvider {
    /// 生产构造（官方端点）。
    pub fn new(api_token: String) -> Self {
        Self::with_base_url(api_token, client::DEFAULT_BASE_URL)
    }

    /// 测试构造：可指向 127.0.0.1 mock。
    pub(crate) fn with_base_url(api_token: String, base_url: &str) -> Self {
        Self {
            client: client::CloudflareClient::new(api_token, base_url),
            zone_cache: Mutex::new(HashMap::new()),
        }
    }

    /// 按域名解析 zone_id（缓存 5 分钟命中则不再发 zone 查找请求）。
    async fn zone_id(&self, domain: &str) -> Result<String, ProviderError> {
        {
            let cache = self.zone_cache.lock().expect("zone 缓存锁中毒");
            if let Some((zid, at)) = cache.get(domain) {
                if at.elapsed() < ZONE_CACHE_TTL {
                    return Ok(zid.clone());
                }
            }
        }
        let zid = self.client.lookup_zone_id(domain).await?;
        self.zone_cache
            .lock()
            .expect("zone 缓存锁中毒")
            .insert(domain.to_string(), (zid.clone(), Instant::now()));
        Ok(zid)
    }
}

#[async_trait::async_trait]
impl Provider for CloudflareProvider {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    /// 最小查询：域名列表取 1 条。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client
            .get("/zones", &[("per_page", "1".to_string())])
            .await
            .map(|_| ())
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.client.list_zones().await
    }

    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let zid = self.zone_id(domain).await?;
        let raws = self.client.fetch_dns_records(&zid, domain, name, rtype).await?;
        let mut out: Vec<Record> = raws.iter().filter_map(|v| client::record_from_api(v, domain)).collect();
        // 服务端 name 参数精确/包含匹配不确定 → 统一按相对名精确过滤。
        if let Some(n) = name {
            out.retain(|r| r.name.eq_ignore_ascii_case(n));
        }
        out.sort_by(|a, b| {
            (a.rtype, &a.name, a.data.to_display_string()).cmp(&(b.rtype, &b.name, b.data.to_display_string()))
        });
        Ok(out)
    }

    /// upsert：查(type+name) → 存在同 data → PATCH（含 TTL）；否则 POST（不产生重复）。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let zid = self.zone_id(domain).await?;
        let raws = self.client.fetch_dns_records(&zid, domain, Some(&rec.name), Some(rec.rtype)).await?;
        let fqdn = client::relative_to_fqdn(&rec.name, domain);
        let same = raws.iter().find(|v| {
            v.get("name")
                .and_then(|n| n.as_str())
                .map(|n| n.eq_ignore_ascii_case(&fqdn))
                .unwrap_or(false)
                && client::record_from_api(v, domain)
                    .map(|r| r.data == rec.data)
                    .unwrap_or(false)
        });
        match same {
            Some(v) => {
                let id = v.get("id").and_then(|i| i.as_str()).unwrap_or_default().to_string();
                self.client.update_record(&zid, &id, &client::record_to_update_body(rec, domain)).await?;
            }
            None => {
                self.client.create_record(&zid, &client::record_to_create_body(rec, domain)).await?;
            }
        }
        Ok(())
    }

    /// 删除该 name+rtype 下全部记录（查 id 后逐一 DELETE；无记录 → NotFound）。
    async fn delete_record(&self, domain: &str, name: &str, rtype: RecordType) -> Result<(), ProviderError> {
        let zid = self.zone_id(domain).await?;
        let fqdn = client::relative_to_fqdn(name, domain);
        let raws = self.client.fetch_dns_records(&zid, domain, Some(name), Some(rtype)).await?;
        let ids: Vec<String> = raws
            .iter()
            .filter(|v| {
                v.get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| n.eq_ignore_ascii_case(&fqdn))
                    .unwrap_or(false)
            })
            .filter_map(|v| v.get("id").and_then(|i| i.as_str()).map(String::from))
            .collect();
        if ids.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        for id in ids {
            self.client.delete_record(&zid, &id).await?;
        }
        Ok(())
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

/// 注册到全局注册表（`providers::register_all` 调用）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register(
        "cloudflare",
        |cred| -> Box<dyn Provider> {
            match cred {
                Credential::Cloudflare { api_token } => {
                    Box::new(CloudflareProvider::new(api_token.clone()))
                }
                _ => Box::new(InvalidCredentialProvider::new()),
            }
        } as fn(&Credential) -> Box<dyn Provider>,
    );
}

/// 凭据变体不匹配时的兜底 Provider（配置层正常不会触发；不打印凭据内容）。
struct InvalidCredentialProvider {
    message: String,
}

impl InvalidCredentialProvider {
    fn new() -> Self {
        Self {
            message: "凭据类型不匹配：cloudflare 需要 Credential::Cloudflare{api_token}，请检查 [dns.providers.cloudflare] 配置"
                .to_string(),
        }
    }
}

#[async_trait::async_trait]
impl Provider for InvalidCredentialProvider {
    fn name(&self) -> &'static str {
        "cloudflare"
    }
    async fn test_connection(&self) -> Result<(), ProviderError> {
        Err(ProviderError::Other(self.message.clone()))
    }
    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        Err(ProviderError::Other(self.message.clone()))
    }
    async fn query_records(
        &self,
        _domain: &str,
        _name: Option<&str>,
        _rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        Err(ProviderError::Other(self.message.clone()))
    }
    async fn upsert_record(&self, _domain: &str, _rec: &Record) -> Result<(), ProviderError> {
        Err(ProviderError::Other(self.message.clone()))
    }
    async fn delete_record(&self, _domain: &str, _name: &str, _rtype: RecordType) -> Result<(), ProviderError> {
        Err(ProviderError::Other(self.message.clone()))
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{RecordData, ProviderError};
    use client::mock::MockServer;
    use serde_json::{json, Value};

    /// 指向 mock 的测试 Provider（固定 token，认证头断言用）。
    fn provider(server: &MockServer) -> CloudflareProvider {
        CloudflareProvider::with_base_url("test-token".to_string(), &server.base_url())
    }

    fn a_rec(name: &str, ip: &str, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: RecordType::A,
            ttl,
            data: RecordData::Plain(ip.to_string()),
        }
    }

    #[tokio::test]
    async fn auth_header_is_bearer() {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        provider(&srv).list_domains().await.unwrap();
        let reqs = srv.requests();
        assert!(!reqs.is_empty(), "应至少发出一次请求");
        assert_eq!(reqs[0].auth.as_deref(), Some("Bearer test-token"));
    }

    #[tokio::test]
    async fn list_domains_returns_zone_names() {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        srv.seed_zone("z2", "kirin.dev");
        let mut doms = provider(&srv).list_domains().await.unwrap();
        doms.sort();
        assert_eq!(doms, vec!["example.com", "kirin.dev"]);
    }

    #[tokio::test]
    async fn relative_fqdn_conversion_and_zone_lookup() {
        // 互转单测（根 "" ↔ 域名；子域 ↔ FQDN；@ 归根）。
        assert_eq!(client::relative_to_fqdn("", "example.com"), "example.com");
        assert_eq!(client::relative_to_fqdn("my-pc", "example.com"), "my-pc.example.com");
        assert_eq!(client::fqdn_to_relative("my-pc.example.com", "example.com"), "my-pc");
        assert_eq!(client::fqdn_to_relative("example.com", "example.com"), "");
        assert_eq!(client::fqdn_to_relative("@", "example.com"), "");
        // 集成：根记录 upsert → 先按域名查 zone，再 POST 时 name 为域名本身。
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        let p = provider(&srv);
        p.upsert_record("example.com", &a_rec("", "203.0.113.1", 120)).await.unwrap();
        let reqs = srv.requests();
        assert!(
            reqs.iter().any(|r| r.method == "GET" && r.path.contains("/zones?name=example.com")),
            "应先发 zone 查找请求"
        );
        let post = reqs.iter().find(|r| r.method == "POST").expect("应有 POST");
        assert!(post.path.starts_with("/zones/z1/dns_records"));
        let body: Value = serde_json::from_str(&post.body).unwrap();
        assert_eq!(body["name"], "example.com");
        assert_eq!(body["content"], "203.0.113.1");
        // 回读 → 根记录相对名为 ""。
        let found = p.query_records("example.com", Some(""), Some(RecordType::A)).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "");
    }

    #[tokio::test]
    async fn upsert_creates_then_updates_without_duplicate() {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        let p = provider(&srv);
        // 不存在 → POST 创建。
        p.upsert_record("example.com", &a_rec("my-pc", "203.0.113.7", 600)).await.unwrap();
        // 存在同 name+type 同 data → PATCH 更新 TTL，不新增。
        p.upsert_record("example.com", &a_rec("my-pc", "203.0.113.7", 1200)).await.unwrap();
        // 不同 data → 新增一条（同 name+type 不同 data 并存，与统一模型一致）。
        p.upsert_record("example.com", &a_rec("my-pc", "198.51.100.9", 600)).await.unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs.iter().filter(|r| r.method == "POST").count(), 2);
        assert_eq!(reqs.iter().filter(|r| r.method == "PATCH").count(), 1);
        let patch = reqs.iter().find(|r| r.method == "PATCH").expect("应有 PATCH");
        assert!(patch.path.starts_with("/zones/z1/dns_records/rec-1"), "PATCH 应命中第一条记录: {}", patch.path);
        let body: Value = serde_json::from_str(&patch.body).unwrap();
        assert_eq!(body["content"], "203.0.113.7");
        assert_eq!(body["ttl"], 1200);
        let found = p.query_records("example.com", Some("my-pc"), Some(RecordType::A)).await.unwrap();
        assert_eq!(found.len(), 2, "不产生重复");
        let ip7 = found.iter().find(|r| r.data.to_display_string() == "203.0.113.7").unwrap();
        assert_eq!(ip7.ttl, 1200, "同 data 已更新 TTL");
    }

    #[tokio::test]
    async fn delete_removes_record_and_missing_returns_not_found() {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        srv.seed_record(json!({
            "id": "r1", "zone_id": "z1", "type": "A",
            "name": "my-pc.example.com", "content": "203.0.113.7", "ttl": 600
        }));
        let p = provider(&srv);
        p.delete_record("example.com", "my-pc", RecordType::A).await.unwrap();
        assert!(srv.records().is_empty(), "删除后记录应消失");
        // 删不存在的 → NotFound。
        let err = p.delete_record("example.com", "ghost", RecordType::A).await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }), "got {err:?}");
    }

    /// 注入故障后 query_records，返回归一化错误。
    async fn query_with_fault(status: &str, body: &str) -> ProviderError {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        srv.add_fault("/zones/z1/dns_records", status, body);
        provider(&srv).query_records("example.com", None, None).await.unwrap_err()
    }

    #[tokio::test]
    async fn error_status_mapping() {
        let boom = r#"{"success":false,"errors":[{"code":10000,"message":"boom"}]}"#;
        // 401 → Auth。
        assert!(matches!(query_with_fault("401", boom).await, ProviderError::Auth { .. }));
        // 404 → NotFound。
        assert!(matches!(query_with_fault("404", boom).await, ProviderError::NotFound { .. }));
        // 429 → RateLimited。
        assert!(matches!(query_with_fault("429", boom).await, ProviderError::RateLimited { .. }));
        // 5xx → Server。
        assert!(matches!(query_with_fault("500", boom).await, ProviderError::Server { .. }));
        // 400 + 错误码 9109（无效 Token）→ Auth（错误码优先于状态判断）。
        let invalid_token = r#"{"success":false,"errors":[{"code":9109,"message":"Invalid API Token"}]}"#;
        assert!(matches!(query_with_fault("400", invalid_token).await, ProviderError::Auth { .. }));
    }

    #[tokio::test]
    async fn zone_id_cache_queries_once() {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        let p = provider(&srv);
        // 两次写入（两次 zone_id 解析）→ 只发一次 zone 查找请求。
        p.upsert_record("example.com", &a_rec("a", "1.1.1.1", 120)).await.unwrap();
        p.upsert_record("example.com", &a_rec("b", "2.2.2.2", 120)).await.unwrap();
        assert_eq!(srv.zone_lookup_count(), 1, "zone_id 缓存生效：两次查询只发一次 zone 查找");
    }

    #[tokio::test]
    async fn srv_structured_fields_roundtrip() {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        let p = provider(&srv);
        let rec = Record {
            name: "_remote._tcp.my-pc".to_string(),
            rtype: RecordType::SRV,
            ttl: 120,
            data: RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 3389,
                target: "my-pc.example.com.".to_string(),
            },
        };
        p.upsert_record("example.com", &rec).await.unwrap();
        // POST body 形状：service/proto 从相对名拆分，name 为 FQDN。
        let reqs = srv.requests();
        let post = reqs.iter().find(|r| r.method == "POST").expect("应有 POST");
        let body: Value = serde_json::from_str(&post.body).unwrap();
        assert_eq!(body["name"], "_remote._tcp.my-pc.example.com");
        assert_eq!(body["data"]["service"], "_remote");
        assert_eq!(body["data"]["proto"], "_tcp");
        assert_eq!(body["data"]["name"], "my-pc");
        assert_eq!(body["data"]["priority"], 0);
        assert_eq!(body["data"]["port"], 3389);
        // 回读 → 统一 Record 互转一致。
        let found = p
            .query_records("example.com", Some("_remote._tcp.my-pc"), Some(RecordType::SRV))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "_remote._tcp.my-pc");
        match &found[0].data {
            RecordData::Srv { priority, weight, port, target } => {
                assert_eq!((*priority, *weight, *port), (0, 1, 3389));
                assert_eq!(target, "my-pc.example.com.");
            }
            other => panic!("期望 Srv，得到 {other:?}"),
        }
        // 幂等：同值重复 upsert → PATCH 而非新增。
        p.upsert_record("example.com", &rec).await.unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs.iter().filter(|r| r.method == "POST").count(), 1);
        assert_eq!(reqs.iter().filter(|r| r.method == "PATCH").count(), 1);
    }
}
