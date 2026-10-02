//! M9-DNS011: Vultr 服务商适配
//!
//! 依据 `M9-DNS000_Provider抽象接口规范.md` 与 `M9-DNS011_Vultr适配.md`。
//!
//! - 认证：`Credential::Vultr { token }` → `Authorization: Bearer`
//! - 记录名：**相对名直传**（sub 空串 = 根；SRV 为 `_svc._tcp[.sub]` 形态）
//! - 写入语义：单条 CRUD（POST 创建 / PATCH 更新 / DELETE）；upsert = 查(name+type)
//!   → 存在同 data 则 PATCH（含 TTL）、否则 POST（不产生重复）
//! - SRV data：`"priority weight port target"` 空格串（Vultr 单字符串）
//! - 分页：`meta.links.next` 跟随遍历；TTL 0 = 省略用服务商默认
//! - 限流：429 + Retry-After 退避重试一次；错误码映射见 `error.rs`
//! - 能力全开（`ProviderCapabilities::all()`）

mod client;
mod error;

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record, RecordType,
};

/// Vultr Provider（Debug 脱敏）。
pub struct VultrProvider {
    client: client::VultrClient,
}

impl std::fmt::Debug for VultrProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VultrProvider").field("client", &self.client).finish()
    }
}

impl VultrProvider {
    /// 生产构造（官方端点）。
    pub fn new(token: String) -> Self {
        Self::with_base_url(token, client::DEFAULT_BASE_URL)
    }

    /// 测试构造：可指向 127.0.0.1 mock。
    pub(crate) fn with_base_url(token: String, base_url: &str) -> Self {
        Self {
            client: client::VultrClient::new(token, base_url),
        }
    }
}

#[async_trait::async_trait]
impl Provider for VultrProvider {
    fn name(&self) -> &'static str {
        "vultr"
    }

    /// 最小查询：域名列表取 1 条。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client
            .get("/domains", &[("per_page", "1".to_string())])
            .await
            .map(|_| ())
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.client.list_domains().await
    }

    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let raws = self.client.fetch_records(domain).await?;
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

    /// upsert：查(name+type) → 存在同 data → PATCH（含 TTL）；否则 POST（不产生重复）。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let raws = self.client.fetch_records(domain).await?;
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
                self.client.update_record(domain, &id, &client::record_to_body(rec, false)).await?;
            }
            None => {
                self.client.create_record(domain, &client::record_to_body(rec, true)).await?;
            }
        }
        Ok(())
    }

    /// 删除该 name+rtype 下全部记录（查 id 后逐一 DELETE；无记录 → NotFound）。
    async fn delete_record(&self, domain: &str, name: &str, rtype: RecordType) -> Result<(), ProviderError> {
        let raws = self.client.fetch_records(domain).await?;
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
            self.client.delete_record(domain, &id).await?;
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
        "vultr",
        |cred| -> Box<dyn Provider> {
            match cred {
                Credential::Vultr { token } => Box::new(VultrProvider::new(token.clone())),
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
            message: "凭据类型不匹配：vultr 需要 Credential::Vultr{token}，请检查 [dns.providers.vultr] 配置".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl Provider for InvalidCredentialProvider {
    fn name(&self) -> &'static str {
        "vultr"
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
    fn provider(server: &MockServer) -> VultrProvider {
        VultrProvider::with_base_url("test-token".to_string(), &server.base_url())
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
        srv.seed_domain("example.com");
        provider(&srv).list_domains().await.unwrap();
        let reqs = srv.requests();
        assert!(!reqs.is_empty(), "应至少发出一次请求");
        assert_eq!(reqs[0].auth.as_deref(), Some("Bearer test-token"));
    }

    #[tokio::test]
    async fn list_domains_returns_domain_names() {
        let srv = MockServer::start().await;
        srv.seed_domain("example.com");
        srv.seed_domain("kirin.dev");
        let mut doms = provider(&srv).list_domains().await.unwrap();
        doms.sort();
        assert_eq!(doms, vec!["example.com", "kirin.dev"]);
    }

    #[tokio::test]
    async fn root_and_relative_name_passthrough() {
        // 根记录（空名）创建 → POST body name 为空串；回读相对名为 ""。
        let srv = MockServer::start().await;
        srv.seed_domain("example.com");
        let p = provider(&srv);
        p.upsert_record("example.com", &a_rec("", "203.0.113.1", 0)).await.unwrap();
        let reqs = srv.requests();
        let post = reqs.iter().find(|r| r.method == "POST").expect("应有 POST");
        assert!(post.path.starts_with("/v2/domains/example.com/records"), "{}", post.path);
        let body: Value = serde_json::from_str(&post.body).unwrap();
        assert_eq!(body["name"], "");
        assert_eq!(body["type"], "A");
        assert_eq!(body["data"], "203.0.113.1");
        assert!(body.get("ttl").is_none(), "TTL 0 应省略用默认");
        let found = p.query_records("example.com", Some(""), Some(RecordType::A)).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "");
        // 子域相对名直传（不拼域名）。
        p.upsert_record("example.com", &a_rec("my-pc", "198.51.100.9", 300)).await.unwrap();
        let reqs = srv.requests();
        let post2 = reqs.iter().filter(|r| r.method == "POST").last().expect("应有第二个 POST");
        let body2: Value = serde_json::from_str(&post2.body).unwrap();
        assert_eq!(body2["name"], "my-pc");
        assert_eq!(body2["ttl"], 300);
    }

    #[tokio::test]
    async fn upsert_creates_then_updates_without_duplicate() {
        let srv = MockServer::start().await;
        srv.seed_domain("example.com");
        let p = provider(&srv);
        // 不存在 → POST 创建。
        p.upsert_record("example.com", &a_rec("my-pc", "203.0.113.7", 600)).await.unwrap();
        // 存在同 name+type 同 data → PATCH 更新 TTL，不新增。
        p.upsert_record("example.com", &a_rec("my-pc", "203.0.113.7", 1200)).await.unwrap();
        // 不同 data → 新增一条。
        p.upsert_record("example.com", &a_rec("my-pc", "198.51.100.9", 600)).await.unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs.iter().filter(|r| r.method == "POST").count(), 2);
        assert_eq!(reqs.iter().filter(|r| r.method == "PATCH").count(), 1);
        let patch = reqs.iter().find(|r| r.method == "PATCH").expect("应有 PATCH");
        assert!(patch.path.starts_with("/v2/domains/example.com/records/rec-1"), "{}", patch.path);
        let body: Value = serde_json::from_str(&patch.body).unwrap();
        assert_eq!(body["data"], "203.0.113.7");
        assert_eq!(body["ttl"], 1200);
        let found = p.query_records("example.com", Some("my-pc"), Some(RecordType::A)).await.unwrap();
        assert_eq!(found.len(), 2, "不产生重复");
        let ip7 = found.iter().find(|r| r.data.to_display_string() == "203.0.113.7").unwrap();
        assert_eq!(ip7.ttl, 1200, "同 data 已更新 TTL");
    }

    #[tokio::test]
    async fn delete_removes_record_and_missing_returns_not_found() {
        let srv = MockServer::start().await;
        srv.seed_domain("example.com");
        srv.seed_record(
            "example.com",
            json!({ "id": "r1", "type": "A", "name": "my-pc", "data": "203.0.113.7", "ttl": 600 }),
        );
        let p = provider(&srv);
        p.delete_record("example.com", "my-pc", RecordType::A).await.unwrap();
        assert!(srv.records().is_empty(), "删除后记录应消失");
        let err = p.delete_record("example.com", "ghost", RecordType::A).await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }), "got {err:?}");
    }

    /// 注入故障后 query_records，返回归一化错误。
    async fn query_with_fault(status: &str, body: &str) -> ProviderError {
        let srv = MockServer::start().await;
        srv.seed_domain("example.com");
        srv.add_fault("/domains/example.com/records", status, body);
        provider(&srv).query_records("example.com", None, None).await.unwrap_err()
    }

    #[tokio::test]
    async fn error_status_mapping() {
        let boom = r#"{"error":"boom"}"#;
        assert!(matches!(query_with_fault("401", boom).await, ProviderError::Auth { .. }));
        assert!(matches!(query_with_fault("403", boom).await, ProviderError::Auth { .. }));
        // invalid_dns_record → InvalidParameter。
        assert!(matches!(
            query_with_fault("400", r#"{"error":"invalid_dns_record"}"#).await,
            ProviderError::InvalidParameter { .. }
        ));
        assert!(matches!(query_with_fault("404", boom).await, ProviderError::NotFound { .. }));
        assert!(matches!(query_with_fault("429", boom).await, ProviderError::RateLimited { .. }));
        assert!(matches!(query_with_fault("500", boom).await, ProviderError::Server { .. }));
    }

    #[tokio::test]
    async fn srv_single_string_data_roundtrip() {
        let srv = MockServer::start().await;
        srv.seed_domain("example.com");
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
        // POST body 形状：name 相对名直传、data 为 "priority weight port target" 空格串。
        let reqs = srv.requests();
        let post = reqs.iter().find(|r| r.method == "POST").expect("应有 POST");
        let body: Value = serde_json::from_str(&post.body).unwrap();
        assert_eq!(body["type"], "SRV");
        assert_eq!(body["name"], "_remote._tcp.my-pc");
        assert_eq!(body["data"], "0 1 3389 my-pc.example.com.");
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
