//! M9-DNS013: Hetzner DNS 服务商适配
//!
//! 依据 `M9-DNS000_Provider抽象接口规范.md` 与 `M9-DNS013_HetznerDNS适配.md`。
//!
//! - 认证：`Credential::Hetzner { token }` → `Auth-API-Token` 专用头（Hetzner 官方认证方式）
//! - 记录名：zone 内**相对名**（根 @/"" → ""；SRV 为 `_svc._tcp[.sub]` 形态）
//! - 写入语义：单条 CRUD（POST 创建 / PUT 更新 / DELETE）；upsert = 查(name+type)
//!   → 存在同 data 则 PUT（含 TTL）、否则 POST（不产生重复）
//! - zone_id：先按域名查 `GET /zones?search_name=`（模糊匹配不中再全量列表匹配），
//!   缓存 5 分钟，失效自动重查
//! - TXT：提交不带引号；回读剥离包裹引号（Hetzner 行为）
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

/// Hetzner DNS Provider（内部持有客户端与 zone_id 缓存；Debug 脱敏）。
pub struct HetznerProvider {
    client: client::HetznerClient,
    /// domain → (zone_id, 查询时刻)。
    zone_cache: Mutex<HashMap<String, (String, Instant)>>,
}

impl std::fmt::Debug for HetznerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HetznerProvider").field("client", &self.client).finish()
    }
}

impl HetznerProvider {
    /// 生产构造（官方端点）。
    pub fn new(token: String) -> Self {
        Self::with_base_url(token, client::DEFAULT_BASE_URL)
    }

    /// 测试构造：可指向 127.0.0.1 mock。
    pub(crate) fn with_base_url(token: String, base_url: &str) -> Self {
        Self {
            client: client::HetznerClient::new(token, base_url),
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
impl Provider for HetznerProvider {
    fn name(&self) -> &'static str {
        "hetzner"
    }

    /// 最小查询：zone 列表取 1 条。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client
            .get("/zones", &[("per_page", "1".to_string())])
            .await
            .map(|_| ())
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let zones = self.client.fetch_zones(None).await?;
        Ok(zones
            .iter()
            .filter_map(|z| z.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect())
    }

    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let zid = self.zone_id(domain).await?;
        let raws = self.client.fetch_records(&zid).await?;
        let mut out: Vec<Record> = raws.iter().filter_map(|v| client::record_from_api(v)).collect();
        if let Some(n) = name {
            out.retain(|r| r.name.eq_ignore_ascii_case(n));
        }
        if let Some(t) = rtype {
            out.retain(|r| r.rtype == t);
        }
        out.sort_by(|a, b| {
            (a.rtype, &a.name, a.data.to_display_string()).cmp(&(b.rtype, &b.name, b.data.to_display_string()))
        });
        Ok(out)
    }

    /// upsert：查(name+type) → 存在同 data → PUT（含 TTL）；否则 POST（不产生重复）。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let zid = self.zone_id(domain).await?;
        let raws = self.client.fetch_records(&zid).await?;
        let same = raws.iter().find(|v| {
            v.get("name")
                .and_then(|n| n.as_str())
                .map(|n| n == rec.name)
                .unwrap_or(false)
                && v.get("type").and_then(|t| t.as_str()) == Some(rec.rtype.as_str())
                && client::record_from_api(v)
                    .map(|r| r.data == rec.data)
                    .unwrap_or(false)
        });
        match same {
            Some(v) => {
                let id = v.get("id").and_then(|i| i.as_str()).unwrap_or_default().to_string();
                self.client.update_record(&id, &client::record_to_body(rec, &zid, false)).await?;
            }
            None => {
                self.client.create_record(&client::record_to_body(rec, &zid, true)).await?;
            }
        }
        Ok(())
    }

    /// 删除该 name+rtype 下全部记录（查 id 后逐一 DELETE；无记录 → NotFound）。
    async fn delete_record(&self, domain: &str, name: &str, rtype: RecordType) -> Result<(), ProviderError> {
        let zid = self.zone_id(domain).await?;
        let raws = self.client.fetch_records(&zid).await?;
        let ids: Vec<String> = raws
            .iter()
            .filter(|v| {
                v.get("name").and_then(|n| n.as_str()).map(|n| n == name).unwrap_or(false)
                    && v.get("type").and_then(|t| t.as_str()) == Some(rtype.as_str())
            })
            .filter_map(|v| v.get("id").and_then(|i| i.as_str()).map(String::from))
            .collect();
        if ids.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        for id in ids {
            self.client.delete_record(&id).await?;
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
        "hetzner",
        |cred| -> Box<dyn Provider> {
            match cred {
                Credential::Hetzner { token } => Box::new(HetznerProvider::new(token.clone())),
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
            message: "凭据类型不匹配：hetzner 需要 Credential::Hetzner{token}，请检查 [dns.providers.hetzner] 配置".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl Provider for InvalidCredentialProvider {
    fn name(&self) -> &'static str {
        "hetzner"
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
    fn provider(server: &MockServer) -> HetznerProvider {
        HetznerProvider::with_base_url("test-token".to_string(), &server.base_url())
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
    async fn auth_header_is_auth_api_token() {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        provider(&srv).list_domains().await.unwrap();
        let reqs = srv.requests();
        assert!(!reqs.is_empty(), "应至少发出一次请求");
        assert_eq!(reqs[0].auth.as_deref(), Some("test-token"), "Hetzner 使用 Auth-API-Token 头");
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
    async fn zone_lookup_and_root_name_mapping() {
        // 互转单测（@/"" → 根；子域相对名直传）。
        assert_eq!(client::normalize_name("@"), "");
        assert_eq!(client::normalize_name(""), "");
        assert_eq!(client::normalize_name("my-pc"), "my-pc");
        // 集成：根记录 upsert → 先 search_name 查 zone，POST body 带 zone_id、name 为空串。
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        let p = provider(&srv);
        p.upsert_record("example.com", &a_rec("", "203.0.113.1", 0)).await.unwrap();
        let reqs = srv.requests();
        assert!(
            reqs.iter().any(|r| r.method == "GET" && r.path.contains("search_name=example.com")),
            "应先按 search_name 查 zone"
        );
        let post = reqs.iter().find(|r| r.method == "POST").expect("应有 POST");
        assert!(post.path.starts_with("/api/v1/records"), "{}", post.path);
        let body: Value = serde_json::from_str(&post.body).unwrap();
        assert_eq!(body["zone_id"], "z1");
        assert_eq!(body["name"], "");
        assert_eq!(body["type"], "A");
        assert_eq!(body["value"], "203.0.113.1");
        assert!(body.get("ttl").is_none(), "TTL 0 应省略用 zone 默认");
        // 回读 → 根记录相对名为 ""。
        let found = p.query_records("example.com", Some(""), Some(RecordType::A)).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "");
        // 读 @ 形态根记录 → ""。
        srv.seed_record(json!({ "id": "r9", "zone_id": "z1", "type": "TXT", "name": "@", "value": "\"hi\"", "ttl": 300 }));
        let found = p.query_records("example.com", Some(""), Some(RecordType::TXT)).await.unwrap();
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
        // 存在同 name+type 同 data → PUT 更新 TTL，不新增。
        p.upsert_record("example.com", &a_rec("my-pc", "203.0.113.7", 1200)).await.unwrap();
        // 不同 data → 新增一条。
        p.upsert_record("example.com", &a_rec("my-pc", "198.51.100.9", 600)).await.unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs.iter().filter(|r| r.method == "POST").count(), 2);
        assert_eq!(reqs.iter().filter(|r| r.method == "PUT").count(), 1);
        let put = reqs.iter().find(|r| r.method == "PUT").expect("应有 PUT");
        assert!(put.path.starts_with("/api/v1/records/rec-1"), "{}", put.path);
        let body: Value = serde_json::from_str(&put.body).unwrap();
        assert_eq!(body["value"], "203.0.113.7");
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
        srv.seed_record(json!({ "id": "r1", "zone_id": "z1", "type": "A", "name": "my-pc", "value": "203.0.113.7", "ttl": 600 }));
        let p = provider(&srv);
        p.delete_record("example.com", "my-pc", RecordType::A).await.unwrap();
        assert!(srv.records().is_empty(), "删除后记录应消失");
        let err = p.delete_record("example.com", "ghost", RecordType::A).await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }), "got {err:?}");
    }

    /// 注入故障后 query_records，返回归一化错误。
    async fn query_with_fault(status: &str, body: &str) -> ProviderError {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        srv.add_fault("/records?zone_id", status, body);
        provider(&srv).query_records("example.com", None, None).await.unwrap_err()
    }

    #[tokio::test]
    async fn error_status_mapping() {
        let boom = r#"{"error":{"code":"boom","message":"boom"}}"#;
        assert!(matches!(query_with_fault("401", boom).await, ProviderError::Auth { .. }));
        assert!(matches!(query_with_fault("403", boom).await, ProviderError::Auth { .. }));
        assert!(matches!(query_with_fault("404", boom).await, ProviderError::NotFound { .. }));
        assert!(matches!(query_with_fault("429", boom).await, ProviderError::RateLimited { .. }));
        assert!(matches!(query_with_fault("500", boom).await, ProviderError::Server { .. }));
    }

    #[tokio::test]
    async fn srv_structured_fields_roundtrip() {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        let p = provider(&srv);
        let rec = Record {
            name: "_remote._tcp.my-pc".to_string(),
            rtype: RecordType::SRV,
            ttl: 600,
            data: RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 3389,
                target: "my-pc.example.com.".to_string(),
            },
        };
        p.upsert_record("example.com", &rec).await.unwrap();
        // POST body 形状：name 相对名、value=target、priority/weight/port 独立。
        let reqs = srv.requests();
        let post = reqs.iter().find(|r| r.method == "POST").expect("应有 POST");
        let body: Value = serde_json::from_str(&post.body).unwrap();
        assert_eq!(body["zone_id"], "z1");
        assert_eq!(body["type"], "SRV");
        assert_eq!(body["name"], "_remote._tcp.my-pc");
        assert_eq!(body["value"], "my-pc.example.com.");
        assert_eq!(body["priority"], 0);
        assert_eq!(body["weight"], 1);
        assert_eq!(body["port"], 3389);
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
        // 幂等：同值重复 upsert → PUT 而非新增。
        p.upsert_record("example.com", &rec).await.unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs.iter().filter(|r| r.method == "POST").count(), 1);
        assert_eq!(reqs.iter().filter(|r| r.method == "PUT").count(), 1);
    }

    #[tokio::test]
    async fn txt_quotes_stripped_on_read_and_unquoted_on_write() {
        let srv = MockServer::start().await;
        srv.seed_zone("z1", "example.com");
        let p = provider(&srv);
        // 写入：value 不带引号。
        let txt = Record {
            name: "my-pc".to_string(),
            rtype: RecordType::TXT,
            ttl: 300,
            data: RecordData::Plain("hello".to_string()),
        };
        p.upsert_record("example.com", &txt).await.unwrap();
        let reqs = srv.requests();
        let post = reqs.iter().find(|r| r.method == "POST").expect("应有 POST");
        let body: Value = serde_json::from_str(&post.body).unwrap();
        assert_eq!(body["value"], "hello", "TXT 提交不应带引号");
        // 回读：带引号的存储值 → 剥离。
        srv.seed_record(json!({ "id": "r8", "zone_id": "z1", "type": "TXT", "name": "quoted", "value": "\"quoted-txt\"", "ttl": 300 }));
        let found = p.query_records("example.com", Some("quoted"), Some(RecordType::TXT)).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].data, RecordData::Plain("quoted-txt".to_string()), "回读应剥离包裹引号");
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
}
