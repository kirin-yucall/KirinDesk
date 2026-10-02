//! M9-DNS020: 新网服务商适配（《M9-DNS020_新网适配.md》）
//!
//! - 端点：`https://api.xinnet.com`（开放平台，XML/JSON；**文档不透明**）
//! - 认证：API Key + 签名 + IP 白名单；签名格式按第三方资料占位
//!   （`sign = MD5(apiKey + secretKey)`），**实现前须向新网官方获取正式 API
//!   文档**核对（见 client.rs 模块注释），保证编译与契约测试通过
//! - 记录接口：list/add/update/del（端点路径为占位约定，以官方文档为准）
//! - **能力降级**（M9-DNS020 §二矩阵：SRV ❌、NS ⚠️ 按文档置 false；
//!   AAAA ⚠️ 按文档支持保持可用）：
//!   `capabilities = { srv:false, ns:false, ttl:true, rename:true }`；
//!   upsert/delete SRV/NS → `ProviderError::Unsupported`

pub mod client;
pub mod error;

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordType,
};
use client::XinnetClient;

/// 生产端点（第三方资料占位；以官方文档为准）。
pub(crate) const DEFAULT_BASE_URL: &str = "https://api.xinnet.com";

/// 相对名 → 厂商 `host`（根 "" → "@"）。
pub(crate) fn to_vendor_name(name: &str) -> String {
    if name.is_empty() {
        "@".to_string()
    } else {
        name.to_string()
    }
}

/// 厂商 `host` → 相对名（"@" 或 "" → ""）。
pub(crate) fn from_vendor_name(name: &str) -> String {
    if name == "@" {
        String::new()
    } else {
        name.to_string()
    }
}

/// 新网服务商实现。
pub struct XinnetProvider {
    client: XinnetClient,
}

impl XinnetProvider {
    /// 生产构建（使用默认端点）。
    pub fn new(
        api_key: impl Into<String>,
        secret_key: impl Into<String>,
        client_ip: impl Into<String>,
    ) -> Self {
        Self::with_base_url(api_key, secret_key, client_ip, DEFAULT_BASE_URL)
    }

    /// 指定端点构建（测试指向本地 mock HTTP server 用）。
    pub fn with_base_url(
        api_key: impl Into<String>,
        secret_key: impl Into<String>,
        client_ip: impl Into<String>,
        base_url: &str,
    ) -> Self {
        Self {
            client: XinnetClient::new(api_key, secret_key, client_ip, base_url),
        }
    }
}

#[async_trait::async_trait]
impl Provider for XinnetProvider {
    fn name(&self) -> &'static str {
        "xinnet"
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
        // M9-DNS020 §二能力矩阵：SRV ❌、NS ⚠️（按文档置 false）、TTL ✅、改名 ✅。
        ProviderCapabilities {
            srv: false,
            ns: false,
            ttl: true,
            rename: true,
        }
    }
}

/// 注册到全局注册表（`providers::register_all` 集成期调用）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register(
        "xinnet",
        (|cred| -> Box<dyn Provider> {
            match cred {
                Credential::Xinnet {
                    api_key,
                    secret_key,
                    client_ip,
                } => Box::new(XinnetProvider::new(
                    api_key.clone(),
                    secret_key.clone(),
                    client_ip.clone(),
                )),
                _ => {
                    // 凭据变体不匹配 → 空凭据兜底，请求阶段映射为 Auth 错误；
                    // 凭据不会被打印。
                    tracing::warn!("xinnet 注册收到非 Xinnet 凭据变体，使用空凭据兜底");
                    Box::new(XinnetProvider::new("", "", ""))
                }
            }
        }) as fn(&Credential) -> Box<dyn Provider>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::RecordData;
    use md5::Digest;
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    // ── 契约测试 mock HTTP server（参考 dns/src/test_support.rs MockDns 模式）──

    /// 捕获的请求（查询/表单参数断言用）。
    #[derive(Debug, Clone, Default)]
    struct Captured {
        method: String,
        path: String,
        form: Vec<(String, String)>,
    }

    #[derive(Default)]
    struct MockState {
        domains: Vec<String>,
        /// 每条含 id/host/type/value/ttl。
        records: Vec<Value>,
        next_id: u64,
        captured: Vec<Captured>,
        /// HTTP 层错误注入：(status, body)。
        error_override: Option<(u16, String)>,
        /// 业务层错误注入（HTTP 200 但 code != 200）。
        business_error: Option<Value>,
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

        fn last(&self) -> Captured {
            self.state.lock().unwrap().captured.pop().unwrap_or_default()
        }

        fn seed_domains(&self, domains: &[&str]) {
            let mut st = self.state.lock().unwrap();
            st.domains = domains.iter().map(|d| d.to_string()).collect();
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

        fn set_business_error(&self, body: Value) {
            self.state.lock().unwrap().business_error = Some(body);
        }
    }

    /// 表单/查询参数解码（%XX 与 +）。
    fn decode_params(raw: &str) -> Vec<(String, String)> {
        raw.split('&')
            .filter(|kv| !kv.is_empty())
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (decode_component(k).to_string(), decode_component(v).to_string()))
            .collect()
    }

    fn decode_component(s: &str) -> String {
        let bytes = s.replace('+', " ").as_bytes().to_vec();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).to_string()
    }

    async fn handle(
        mut stream: TcpStream,
        state: &Arc<Mutex<MockState>>,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(&mut stream);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;

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
            // GET 参数在查询串，POST 参数在表单体。
            let (path_only, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
            let form = if method == "GET" {
                decode_params(query)
            } else {
                decode_params(&body)
            };
            st.captured.push(Captured {
                method: method.clone(),
                path: path_only.to_string(),
                form: form.clone(),
            });
            if let Some((s, b)) = &st.error_override {
                let ra = if *s == 429 { Some(5u64) } else { None };
                (*s, b.clone(), ra)
            } else if let Some(be) = &st.business_error {
                (200, be.to_string(), None)
            } else {
                route(&method, path_only, &form, &mut st)
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

    /// 路由：GET /domain/list、GET /domain/dns/list、POST /domain/dns/{add|update|delete}。
    fn route(
        method: &str,
        path: &str,
        form: &[(String, String)],
        state: &mut MockState,
    ) -> (u16, String, Option<u64>) {
        let get = |k: &str| {
            form.iter()
                .find(|(kk, _)| kk == k)
                .map(|(_, v)| v.clone())
        };
        match (method, path) {
            ("GET", "/domain/list") => {
                let domains: Vec<Value> = state
                    .domains
                    .iter()
                    .map(|d| json!({"domain": d}))
                    .collect();
                (
                    200,
                    json!({"code": 200, "message": "ok", "data": {"domains": domains}})
                        .to_string(),
                    None,
                )
            }
            ("GET", "/domain/dns/list") => {
                let records = state.records.clone();
                (
                    200,
                    json!({"code": 200, "message": "ok", "data": {"records": records}})
                        .to_string(),
                    None,
                )
            }
            ("POST", "/domain/dns/add") => {
                state.next_id += 1;
                state.records.push(json!({
                    "id": state.next_id,
                    "host": get("host").unwrap_or_default(),
                    "type": get("type").unwrap_or_default(),
                    "value": get("value").unwrap_or_default(),
                    "ttl": get("ttl").and_then(|s| s.parse::<u32>().ok()).unwrap_or(600),
                }));
                (
                    200,
                    json!({"code": 200, "message": "ok"}).to_string(),
                    None,
                )
            }
            ("POST", "/domain/dns/update") => {
                let id = get("id")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                for r in state.records.iter_mut() {
                    if r["id"] == json!(id) {
                        if let Some(h) = get("host") {
                            r["host"] = json!(h);
                        }
                        if let Some(t) = get("type") {
                            r["type"] = json!(t);
                        }
                        if let Some(v) = get("value") {
                            r["value"] = json!(v);
                        }
                        if let Some(t) = get("ttl") {
                            r["ttl"] = json!(t);
                        }
                    }
                }
                (200, json!({"code": 200, "message": "ok"}).to_string(), None)
            }
            ("POST", "/domain/dns/delete") => {
                let id = get("id")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                state.records.retain(|r| r["id"] != json!(id));
                (200, json!({"code": 200, "message": "ok"}).to_string(), None)
            }
            _ => (
                404,
                json!({"code": 404, "message": "not found"}).to_string(),
                None,
            ),
        }
    }

    fn provider(base: &str) -> XinnetProvider {
        XinnetProvider::with_base_url("key123", "sec456", "1.2.3.4", base)
    }

    // ── 契约测试 ──

    /// 1. 认证形状：apiKey + sign（MD5 可复算）+ timestamp + client_ip + format。
    #[tokio::test]
    async fn auth_shape_key_and_sign() {
        let mock = MockServer::start().await;
        mock.seed_domains(&["example.com"]);
        let p = provider(&mock.base_url());
        p.list_domains().await.unwrap();
        let req = mock.last();
        let form = req.form;
        assert_eq!(find(&form, "apiKey"), Some("key123"));
        // sign = MD5(apiKey + secretKey)（占位签名，可复算）。
        let expect = format!("{:x}", md5::Md5::digest("key123sec456"));
        assert_eq!(find(&form, "sign"), Some(expect.as_str()));
        assert!(form.iter().any(|(k, _)| k == "timestamp"), "应携带时间戳");
        assert_eq!(find(&form, "client_ip"), Some("1.2.3.4"), "IP 白名单字段");
        assert_eq!(find(&form, "format"), Some("json"));
        // 凭据不打印。
        let dbg = format!("{:?}", p.client);
        assert!(!dbg.contains("sec456"));
    }

    /// 2. 相对名 ↔ host 互转（@ 根）。
    #[test]
    fn name_conversion_root() {
        assert_eq!(to_vendor_name(""), "@");
        assert_eq!(to_vendor_name("my-pc"), "my-pc");
        assert_eq!(from_vendor_name("@"), "");
        assert_eq!(from_vendor_name(""), "");
        assert_eq!(from_vendor_name("my-pc"), "my-pc");
    }

    /// 3. list_domains 解析。
    #[tokio::test]
    async fn list_domains_parses() {
        let mock = MockServer::start().await;
        mock.seed_domains(&["example.com", "kirin.dev"]);
        let p = provider(&mock.base_url());
        assert_eq!(
            p.list_domains().await.unwrap(),
            vec!["example.com", "kirin.dev"]
        );
    }

    /// 4. upsert：不存在 → POST add；已存在 → POST update（带 id）。
    #[tokio::test]
    async fn upsert_add_then_update() {
        let mock = MockServer::start().await;
        let p = provider(&mock.base_url());
        let rec = Record {
            name: "my-pc".into(),
            rtype: RecordType::A,
            ttl: 600,
            data: RecordData::Plain("203.0.113.7".into()),
        };
        p.upsert_record("example.com", &rec).await.unwrap();
        let req = mock.last();
        assert_eq!(req.path, "/domain/dns/add");
        assert_eq!(find(&req.form, "host"), Some("my-pc"));
        assert_eq!(find(&req.form, "type"), Some("A"));
        assert_eq!(find(&req.form, "value"), Some("203.0.113.7"));
        assert_eq!(find(&req.form, "ttl"), Some("600"));
        // mock 中已存在同 host+type → update（带 id）。
        p.upsert_record("example.com", &rec).await.unwrap();
        let req = mock.last();
        assert_eq!(req.path, "/domain/dns/update");
        assert!(req.form.iter().any(|(k, _)| k == "id"), "update 应携带记录 id");
    }

    /// 5. delete：POST /domain/dns/delete 按 id；删不存在 → NotFound。
    #[tokio::test]
    async fn delete_by_record_id() {
        let mock = MockServer::start().await;
        mock.seed_record(json!({
            "id": 5, "host": "my-pc", "type": "A", "value": "203.0.113.7", "ttl": 600
        }));
        let p = provider(&mock.base_url());
        p.delete_record("example.com", "my-pc", RecordType::A)
            .await
            .unwrap();
        let req = mock.last();
        assert_eq!(req.path, "/domain/dns/delete");
        assert_eq!(find(&req.form, "id"), Some("5"));
        let err = p
            .delete_record("example.com", "ghost", RecordType::A)
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }

    /// 6. 错误码映射：HTTP 层 + 业务层（HTTP 200 但 code != 200）。
    #[tokio::test]
    async fn error_code_mapping() {
        let mock = MockServer::start().await;
        let p = provider(&mock.base_url());
        for (status, body, want) in [
            (401u16, r#"{"message":"unauthorized"}"#, "Auth"),
            (403u16, r#"{"message":"ip not allowed"}"#, "Auth"),
            (400u16, r#"{"message":"param error"}"#, "InvalidParameter"),
            (404u16, r#"{"message":"domain not exist"}"#, "NotFound"),
            (429u16, r#"{"message":"rate limited"}"#, "RateLimited"),
            (500u16, r#"{"message":"server error"}"#, "Server"),
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
        // 业务错误：HTTP 200 但 code=404 → NotFound。
        mock.set_business_error(json!({"code": 404, "message": "域名不存在"}));
        let err = p.list_domains().await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }

    /// 7. 能力降级：SRV/NS upsert → Unsupported；delete SRV → Unsupported；A 正常。
    #[tokio::test]
    async fn capability_degration_srv_ns_unsupported() {
        let mock = MockServer::start().await;
        let p = provider(&mock.base_url());
        let srv = Record {
            name: "_remote._tcp.my-pc".into(),
            rtype: RecordType::SRV,
            ttl: 600,
            data: RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 3389,
                target: "tgt.example.com.".into(),
            },
        };
        assert!(matches!(
            p.upsert_record("example.com", &srv).await,
            Err(ProviderError::Unsupported(_))
        ));
        let ns = Record {
            name: "".into(),
            rtype: RecordType::NS,
            ttl: 0,
            data: RecordData::Plain("ns1.example.net".into()),
        };
        assert!(matches!(
            p.upsert_record("example.com", &ns).await,
            Err(ProviderError::Unsupported(_))
        ));
        assert!(matches!(
            p.delete_record("example.com", "_remote._tcp.my-pc", RecordType::SRV)
                .await,
            Err(ProviderError::Unsupported(_))
        ));
        // 其他类型不受影响。
        let a = Record {
            name: "my-pc".into(),
            rtype: RecordType::A,
            ttl: 600,
            data: RecordData::Plain("203.0.113.7".into()),
        };
        p.upsert_record("example.com", &a).await.unwrap();
        assert!(p.capabilities().srv == false && p.capabilities().ns == false);
    }

    /// 8. query 解析与过滤：根 host "@" → 相对名 ""；SRV 查询降级返回空。
    #[tokio::test]
    async fn query_parses_and_filters() {
        let mock = MockServer::start().await;
        mock.seed_record(json!({
            "id": 1, "host": "@", "type": "A", "value": "203.0.113.7", "ttl": 600
        }));
        mock.seed_record(json!({
            "id": 2, "host": "my-pc", "type": "TXT", "value": "v=ed25519;k=abc", "ttl": 300
        }));
        let p = provider(&mock.base_url());
        let a = p
            .query_records("example.com", None, Some(RecordType::A))
            .await
            .unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].name, "", "@ 根 → 相对名空串");
        assert_eq!(a[0].data, RecordData::Plain("203.0.113.7".into()));
        assert_eq!(a[0].ttl, 600);
        let txt = p
            .query_records("example.com", Some("my-pc"), None)
            .await
            .unwrap();
        assert_eq!(txt.len(), 1);
        assert_eq!(txt[0].rtype, RecordType::TXT);
        // SRV 能力降级：直接返回空（不发请求）。
        assert!(
            p.query_records("example.com", None, Some(RecordType::SRV))
                .await
                .unwrap()
                .is_empty()
        );
    }

    fn find<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
        form.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}
