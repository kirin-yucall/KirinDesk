//! M9-DNS012: Linode（Akamai）服务商适配（《M9-DNS012_LinodeAkamai适配.md》）
//!
//! - 端点：`https://api.linode.com/v4`，`Authorization: Bearer {PAT}` 认证
//! - **需先创建 Domain 对象**：域名未加入 Linode 时返回 `NotFound` 并提示先建
//!   Domain（适配层不做注册局业务）
//! - 记录单条 CRUD：`GET/POST/PUT/DELETE /domains/{id}/records[/{rid}]`
//! - SRV 结构化：`service`/`protocol`/`priority`/`weight`/`port`/`target`，
//!   `name` 为子域（根为 ""）；统一名 `_service._protocol[.子域]` ↔ 拆分互转
//! - 能力全开（`ProviderCapabilities::all()`）

pub mod client;
pub mod error;

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordType,
};
use client::LinodeClient;

/// 生产端点（`M9-DNS012` §一：`https://api.linode.com/v4`）。
pub(crate) const DEFAULT_BASE_URL: &str = "https://api.linode.com/v4";

/// 相对名 → Linode name：根（"" 或 "@"）→ `""`；其余原样。
pub(crate) fn to_linode_name(name: &str) -> String {
    if name.is_empty() || name == "@" {
        String::new()
    } else {
        name.to_string()
    }
}

/// Linode name → 相对名：`""`（或宽松兼容的 "@"）→ `""`；其余原样。
pub(crate) fn from_linode_name(name: &str) -> String {
    if name == "@" {
        String::new()
    } else {
        name.to_string()
    }
}

/// 统一 SRV 名 `_service._protocol[.子域]` → `(service, protocol, 子域)`。
///
/// 与 Linode 的 `service`/`protocol`/`name`（子域）三字段互转；
/// 前两个标签不以 `_` 开头 → `None`（视为非法 SRV 名）。
pub(crate) fn split_srv_name(name: &str) -> Option<(String, String, String)> {
    let mut labels = name.split('.');
    let service = labels.next()?;
    let protocol = labels.next()?;
    if !service.starts_with('_') || !protocol.starts_with('_') {
        return None;
    }
    let sub = labels.collect::<Vec<_>>().join(".");
    Some((service.to_string(), protocol.to_string(), sub))
}

/// Linode 服务商实现。
pub struct LinodeProvider {
    client: LinodeClient,
}

impl LinodeProvider {
    /// 生产构建（使用默认端点 `https://api.linode.com/v4`）。
    pub fn new(token: impl Into<String>) -> Self {
        Self::with_base_url(token, DEFAULT_BASE_URL)
    }

    /// 指定端点构建（测试指向本地 mock HTTP server / 自建端点用）。
    pub fn with_base_url(token: impl Into<String>, base_url: &str) -> Self {
        Self {
            client: LinodeClient::new(token, base_url),
        }
    }
}

#[async_trait::async_trait]
impl Provider for LinodeProvider {
    fn name(&self) -> &'static str {
        "linode"
    }

    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.test_connection().await
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
        self.client.query_records(domain, name, rtype).await
    }

    async fn upsert_record(
        &self,
        domain: &str,
        rec: &Record,
    ) -> Result<(), ProviderError> {
        self.client.upsert_record(domain, rec).await
    }

    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        self.client.delete_record(domain, name, rtype).await
    }

    fn capabilities(&self) -> ProviderCapabilities {
        // M9-DNS012 §二：A/AAAA/CNAME/MX/TXT/SRV/NS 全支持，TTL 支持，rename 支持。
        ProviderCapabilities::all()
    }
}

/// 注册到全局注册表（`providers::register_all` 集成期调用）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register(
        "linode",
        (|cred| -> Box<dyn Provider> {
            let token = match cred {
                Credential::Linode { token } => token.clone(),
                _ => {
                    // 凭据变体不匹配（配置层传错服务商名）→ 空 token 兜底，
                    // 请求阶段将得到 401 → Auth 错误；凭据不会被打印。
                    tracing::warn!("linode 注册收到非 Linode 凭据变体，使用空 token 兜底");
                    String::new()
                }
            };
            Box::new(LinodeProvider::new(token))
        }) as fn(&Credential) -> Box<dyn Provider>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{RecordData};
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    // ── 契约测试 mock HTTP server（参考 dns/src/test_support.rs MockDns 模式）──

    /// 捕获的请求（认证头 / 路径 / body 断言用）。
    #[derive(Debug, Clone, Default)]
    struct Captured {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Captured {
        fn header(&self, name: &str) -> Option<String> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        }
    }

    #[derive(Default)]
    struct MockState {
        /// (id, domain) —— 模拟 Linode Domain 对象。
        domains: Vec<(u64, String)>,
        /// 服务端记录（含 id）。
        records: Vec<Value>,
        next_id: u64,
        captured: Vec<Captured>,
        /// 错误注入：(status, body)。
        error_override: Option<(u16, String)>,
    }

    struct MockServer {
        state: Arc<Mutex<MockState>>,
        addr: SocketAddr,
    }

    impl MockServer {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("绑定 mock server 失败");
            let addr = listener.local_addr().expect("mock 地址");
            let state = Arc::new(Mutex::new(MockState::default()));
            let srv_state = state.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let conn_state = srv_state.clone();
                    tokio::spawn(async move {
                        let _ = handle(stream, &conn_state).await;
                    });
                }
            });
            Self { state, addr }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn captured(&self) -> Vec<Captured> {
            self.state.lock().unwrap().captured.clone()
        }

        /// 弹出最近一次捕获的请求。
        fn last(&self) -> Captured {
            self.captured().pop().unwrap_or_default()
        }

        fn seed_domain(&self, id: u64, domain: &str) {
            self.state
                .lock()
                .unwrap()
                .domains
                .push((id, domain.to_string()));
        }

        fn seed_record(&self, rec: Value) {
            self.state.lock().unwrap().records.push(rec);
        }

        fn set_error(&self, status: u16, body: &str) {
            self.state.lock().unwrap().error_override = Some((status, body.to_string()));
        }

        fn clear_error(&self) {
            self.state.lock().unwrap().error_override = None;
        }
    }

    /// 处理一个 HTTP 连接：解析请求行/头/体 → 记录 → 路由 → 响应。
    async fn handle(
        mut stream: TcpStream,
        state: &Arc<Mutex<MockState>>,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(&mut stream);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;

        let mut headers: Vec<(String, String)> = Vec::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await? == 0 {
                break;
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).await?;
        let body = String::from_utf8_lossy(&body).to_string();

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();

        let (status, resp_body, retry_after) = {
            let mut st = state.lock().unwrap();
            st.captured.push(Captured {
                method: method.clone(),
                path: path.clone(),
                headers: headers.clone(),
                body: body.clone(),
            });
            if let Some((s, b)) = &st.error_override {
                let ra = if *s == 429 { Some(5u64) } else { None };
                (*s, b.clone(), ra)
            } else {
                route(&method, &path, &body, &mut st)
            }
        };

        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "Error",
        };
        let mut raw = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            resp_body.len()
        );
        if let Some(ra) = retry_after {
            raw.push_str(&format!("Retry-After: {ra}\r\n"));
        }
        raw.push_str("Connection: close\r\n\r\n");
        raw.push_str(&resp_body);
        stream.write_all(raw.as_bytes()).await?;
        stream.flush().await
    }

    /// 路由：模拟 Linode `/v4` 下的 domains / records 端点。
    fn route(
        method: &str,
        path: &str,
        body: &str,
        state: &mut MockState,
    ) -> (u16, String, Option<u64>) {
        let (path, _query) = path.split_once('?').unwrap_or((path, ""));
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        match (method, segs.as_slice()) {
            ("GET", ["domains"]) => {
                let data: Vec<Value> = state
                    .domains
                    .iter()
                    .map(|(id, d)| json!({"id": id, "domain": d, "type": "master"}))
                    .collect();
                let resp = json!({"data": data, "page": 1, "pages": 1, "results": data.len()});
                (200, resp.to_string(), None)
            }
            ("GET", ["domains", _id, "records"]) => {
                let records = state.records.clone();
                let resp = json!({
                    "data": records,
                    "page": 1,
                    "pages": 1,
                    "results": records.len()
                });
                (200, resp.to_string(), None)
            }
            ("POST", ["domains", _id, "records"]) => {
                let mut rec: Value =
                    serde_json::from_str(body).expect("POST records body 应为 JSON");
                state.next_id += 1;
                rec["id"] = json!(state.next_id);
                state.records.push(rec.clone());
                (200, rec.to_string(), None)
            }
            ("PUT", ["domains", _id, "records", rid]) => {
                let rid: u64 = rid.parse().unwrap_or(0);
                let mut rec: Value =
                    serde_json::from_str(body).expect("PUT records body 应为 JSON");
                if let Some(existing) = state.records.iter_mut().find(|r| r["id"] == json!(rid)) {
                    rec["id"] = json!(rid);
                    *existing = rec;
                }
                (200, "{}".to_string(), None)
            }
            ("DELETE", ["domains", _id, "records", rid]) => {
                let rid: u64 = rid.parse().unwrap_or(0);
                state.records.retain(|r| r["id"] != json!(rid));
                (200, String::new(), None)
            }
            _ => (
                404,
                json!({"errors": [{"reason": "not found"}]}).to_string(),
                None,
            ),
        }
    }

    fn provider(base: &str) -> LinodeProvider {
        LinodeProvider::with_base_url("pat123", base)
    }

    // ── 契约测试 ──

    /// 1. 认证形状：Authorization: Bearer {token}。
    #[tokio::test]
    async fn auth_shape_bearer_header() {
        let mock = MockServer::start().await;
        mock.seed_domain(1, "example.com");
        let p = provider(&mock.base_url());
        p.list_domains().await.unwrap();
        let req = mock.last();
        assert_eq!(req.header("authorization").as_deref(), Some("Bearer pat123"));
        // 凭据不打印：Debug 输出不含 token。
        let dbg = format!("{:?}", p.client);
        assert!(!dbg.contains("pat123"));
    }

    /// 2. list_domains 解析 + Domain id 匹配；未托管域名 → NotFound（提示先建 Domain）。
    #[tokio::test]
    async fn list_domains_and_domain_id_match() {
        let mock = MockServer::start().await;
        mock.seed_domain(123, "example.com");
        mock.seed_domain(456, "kirin.dev");
        let p = provider(&mock.base_url());
        assert_eq!(
            p.list_domains().await.unwrap(),
            vec!["example.com", "kirin.dev"]
        );
        let id = p.client.find_domain_id("example.com").await.unwrap();
        assert_eq!(id, 123);
        let err = p.client.find_domain_id("not-hosted.com").await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
        assert!(
            err.to_string().contains("DNS Manager"),
            "应提示先建 Domain: {err}"
        );
    }

    /// 3. 相对名 ↔ Linode name 互转（@ 根 → 空串）+ SRV 名拆分。
    #[test]
    fn name_conversion_root_and_srv_split() {
        assert_eq!(to_linode_name(""), "");
        assert_eq!(to_linode_name("@"), "");
        assert_eq!(to_linode_name("my-pc"), "my-pc");
        assert_eq!(from_linode_name(""), "");
        assert_eq!(from_linode_name("@"), "");
        assert_eq!(from_linode_name("my-pc"), "my-pc");
        // SRV：统一名 → service/protocol/子域。
        assert_eq!(
            split_srv_name("_remote._tcp.my-pc"),
            Some(("_remote".into(), "_tcp".into(), "my-pc".into()))
        );
        assert_eq!(
            split_srv_name("_remote._tcp"),
            Some(("_remote".into(), "_tcp".into(), "".into()))
        );
        assert!(split_srv_name("my-pc").is_none());
    }

    /// 4. upsert：先找 Domain id → 不存在 POST 创建，存在 PUT 更新（按记录 id）。
    #[tokio::test]
    async fn upsert_creates_then_updates() {
        let mock = MockServer::start().await;
        mock.seed_domain(123, "example.com");
        let p = provider(&mock.base_url());
        let rec = Record {
            name: "my-pc".into(),
            rtype: RecordType::A,
            ttl: 600,
            data: RecordData::Plain("203.0.113.7".into()),
        };
        // 首次：查不到 → POST /domains/{id}/records 创建。
        p.upsert_record("example.com", &rec).await.unwrap();
        let req = mock.last();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/domains/123/records");
        let body: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body["type"], "A");
        assert_eq!(body["name"], "my-pc");
        assert_eq!(body["target"], "203.0.113.7");
        assert_eq!(body["ttl_sec"], 600);
        // 再次：已存在 → PUT /domains/{id}/records/{rid} 更新（全字段）。
        p.upsert_record("example.com", &rec).await.unwrap();
        let req = mock.last();
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/domains/123/records/1");
    }

    /// 5. 域名未添加 → upsert 直接 NotFound（先建 Domain 提示）。
    #[tokio::test]
    async fn upsert_missing_domain_returns_not_found() {
        let mock = MockServer::start().await;
        let p = provider(&mock.base_url());
        let rec = Record {
            name: "my-pc".into(),
            rtype: RecordType::A,
            ttl: 600,
            data: RecordData::Plain("203.0.113.7".into()),
        };
        let err = p.upsert_record("not-hosted.com", &rec).await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
        assert!(err.to_string().contains("Linode"));
    }

    /// 6. delete：按记录 id DELETE；删不存在 → NotFound。
    #[tokio::test]
    async fn delete_by_record_id() {
        let mock = MockServer::start().await;
        mock.seed_domain(123, "example.com");
        mock.seed_record(json!({
            "id": 7, "type": "A", "name": "my-pc", "target": "203.0.113.7",
            "priority": 0, "weight": 0, "port": 0, "ttl_sec": 600
        }));
        let p = provider(&mock.base_url());
        p.delete_record("example.com", "my-pc", RecordType::A)
            .await
            .unwrap();
        let req = mock.last();
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/domains/123/records/7");
        let err = p
            .delete_record("example.com", "ghost", RecordType::A)
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }

    /// 7. 错误码映射：401/403 → Auth；400 → InvalidParameter；404 → NotFound；
    ///    429 → RateLimited（Retry-After）；5xx → Server。
    #[tokio::test]
    async fn error_code_mapping() {
        let mock = MockServer::start().await;
        let p = provider(&mock.base_url());
        for (status, body, want) in [
            (401u16, r#"{"errors":[{"reason":"unauthorized"}]}"#, "Auth"),
            (403u16, r#"{"errors":[{"reason":"forbidden"}]}"#, "Auth"),
            (400u16, r#"{"errors":[{"reason":"record_data_invalid"}]}"#, "InvalidParameter"),
            (404u16, r#"{"errors":[{"reason":"not_found"}]}"#, "NotFound"),
            (429u16, r#"{"errors":[{"reason":"rate_limit"}]}"#, "RateLimited"),
            (500u16, r#"{"errors":[{"reason":"boom"}]}"#, "Server"),
        ] {
            mock.set_error(status, body);
            let err = p.list_domains().await.unwrap_err();
            let got = match &err {
                ProviderError::Auth { .. } => "Auth",
                ProviderError::InvalidParameter { .. } => "InvalidParameter",
                ProviderError::NotFound { .. } => "NotFound",
                ProviderError::RateLimited { retry_after } => {
                    assert_eq!(*retry_after, Some(5), "429 应带 Retry-After");
                    "RateLimited"
                }
                ProviderError::Server { status: s, .. } => {
                    assert_eq!(*s, 500);
                    "Server"
                }
                _ => panic!("未预期错误: {err:?}"),
            };
            assert_eq!(got, want, "status {status}");
        }
        mock.clear_error();
    }

    /// 8. SRV 结构化往返：统一名 ↔ service/protocol/子域，target 去结尾点。
    #[tokio::test]
    async fn srv_structured_roundtrip() {
        let mock = MockServer::start().await;
        mock.seed_domain(123, "example.com");
        let p = provider(&mock.base_url());
        let srv = Record {
            name: "_remote._tcp.my-pc".into(),
            rtype: RecordType::SRV,
            ttl: 600,
            data: RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 3389,
                target: "my-pc.example.com.".into(),
            },
        };
        p.upsert_record("example.com", &srv).await.unwrap();
        let req = mock.last();
        assert_eq!(req.method, "POST");
        let body: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body["type"], "SRV");
        assert_eq!(body["service"], "_remote");
        assert_eq!(body["protocol"], "_tcp");
        assert_eq!(body["name"], "my-pc", "SRV 的 name 为子域");
        assert_eq!(body["priority"], 0);
        assert_eq!(body["weight"], 1);
        assert_eq!(body["port"], 3389);
        assert_eq!(body["target"], "my-pc.example.com", "target 应去掉结尾点");
        // 查询往返：统一名重组 + 结构化数据一致。
        let found = p
            .query_records("example.com", Some("_remote._tcp.my-pc"), Some(RecordType::SRV))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "_remote._tcp.my-pc");
        match &found[0].data {
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                assert_eq!((*priority, *weight, *port), (0, 1, 3389));
                assert_eq!(target, "my-pc.example.com");
            }
            other => panic!("期望 Srv 数据，实际 {other:?}"),
        }
    }
}
