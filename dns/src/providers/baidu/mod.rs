//! M9-DNS016: 百度智能云（公网 DNS）Provider 适配
//!
//! - 端点：`https://dns.baidubce.com`（公网；内网 PrivateZone 不在范围）
//! - 认证：BCE 签名 `bce-auth-v1/...`（HMAC-SHA256，见 [`sign`]）
//! - 接口：`/v1/dns/zone` 域名列表 / `/v1/dns/zone/{zone}/record` 记录 CRUD
//! - 能力：全开（A/AAAA/CNAME/MX/TXT/SRV/NS，TTL，改名）

pub mod client;
pub mod error;
pub mod record;
pub mod sign;

use crate::provider::record::RecordType;
use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
};
use client::{BaiduClient, DEFAULT_BASE_URL};
use record::{to_body, to_relative_name, to_vendor_rr, RawRecord};

/// 百度智能云 Provider 实现。
pub struct BaiduProvider {
    client: BaiduClient,
}

impl BaiduProvider {
    /// 构造客户端；`base_url` 为 `None` 时使用官方端点（测试可注入 mock 地址）。
    pub fn new(access_key_id: String, secret_access_key: String, base_url: Option<String>) -> Self {
        Self {
            client: BaiduClient::new(
                access_key_id,
                secret_access_key,
                base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
            ),
        }
    }
}

/// 从凭据构建 Provider（凭据类型不匹配时返回兜底错误 Provider，不 panic）。
fn factory(cred: &Credential) -> Box<dyn Provider> {
    match cred {
        Credential::Baidu {
            access_key_id,
            secret_access_key,
        } => Box::new(BaiduProvider::new(
            access_key_id.clone(),
            secret_access_key.clone(),
            None,
        )),
        _ => Box::new(MismatchProvider::new("baidu")),
    }
}

/// 注册到全局 ProviderRegistry（name = "baidu"）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register(
        "baidu",
        |cred| -> Box<dyn Provider> { factory(cred) } as fn(&Credential) -> Box<dyn Provider>,
    );
}

#[async_trait::async_trait]
impl Provider for BaiduProvider {
    fn name(&self) -> &'static str {
        "baidu"
    }

    /// 测试连接：域名列表取一页。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.list_domains().await.map(|_| ())
    }

    /// 域名列表（`GET /v1/dns/zone`，自动分页）。
    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.client.list_domains().await
    }

    /// 查询记录：官方列表接口无 type 过滤参数 → 内存精确过滤。
    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let rr = name.map(to_vendor_rr);
        let raw = self.client.list_raw_records(domain, rr.as_deref()).await?;
        let mut out = client::to_records(raw, rtype);
        if let Some(n) = name {
            out.retain(|r| r.name == n);
        }
        Ok(out)
    }

    /// 幂等写入：查 rr+type → 存在则 PUT（recordId）→ 不存在则 POST。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let rr = to_vendor_rr(&rec.name);
        let raw = self.client.list_raw_records(domain, Some(rr.as_str())).await?;
        let exact: Vec<RawRecord> = raw
            .into_iter()
            .filter(|r| {
                to_relative_name(&r.rr) == rec.name
                    && r.rtype.eq_ignore_ascii_case(rec.rtype.as_str())
            })
            .collect();
        let body = to_body(rec);
        match exact.first() {
            Some(found) => {
                let id = found.id.clone();
                self.client.update_record(domain, &id, &body).await
            }
            None => self.client.add_record(domain, &body).await,
        }
    }

    /// 删除：按 RR+Type 定位全部匹配记录并逐个删除；无匹配 → NotFound。
    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let rr = to_vendor_rr(name);
        let raw = self.client.list_raw_records(domain, Some(rr.as_str())).await?;
        let exact: Vec<RawRecord> = raw
            .into_iter()
            .filter(|r| {
                to_relative_name(&r.rr) == name && r.rtype.eq_ignore_ascii_case(rtype.as_str())
            })
            .collect();
        if exact.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        for r in &exact {
            self.client.delete_record(domain, &r.id).await?;
        }
        Ok(())
    }

    /// 能力全开（SRV/NS/TTL/改名均支持）。
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

/// 凭据类型不匹配时的兜底 Provider。
struct MismatchProvider {
    name: &'static str,
}

impl MismatchProvider {
    fn new(name: &'static str) -> Self {
        Self { name }
    }
}

fn mismatch_error(name: &'static str) -> ProviderError {
    ProviderError::Other(format!("服务商「{name}」配置的凭据类型不匹配（需要 Baidu 凭据）"))
}

#[async_trait::async_trait]
impl Provider for MismatchProvider {
    fn name(&self) -> &'static str {
        self.name
    }
    async fn test_connection(&self) -> Result<(), ProviderError> {
        Err(mismatch_error(self.name))
    }
    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        Err(mismatch_error(self.name))
    }
    async fn query_records(
        &self,
        _domain: &str,
        _name: Option<&str>,
        _rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        Err(mismatch_error(self.name))
    }
    async fn upsert_record(&self, _domain: &str, _rec: &Record) -> Result<(), ProviderError> {
        Err(mismatch_error(self.name))
    }
    async fn delete_record(
        &self,
        _domain: &str,
        _name: &str,
        _rtype: RecordType,
    ) -> Result<(), ProviderError> {
        Err(mismatch_error(self.name))
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

#[cfg(test)]
mod mock {
    //! 极简百度 DNS mock HTTP 服务器（参考 dns/src/test_support.rs 的 MockDns 模式，
    //! 自包含于本模块，仅测试编译）。记录每次请求（方法/路径/查询/头/体）供签名断言。

    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// mock 存储的记录。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MockRecord {
        #[serde(default)]
        pub id: String,
        pub rr: String,
        #[serde(rename = "type")]
        pub rtype: String,
        pub value: String,
        pub ttl: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub priority: Option<u32>,
    }

    /// 捕获的一次请求（签名断言用）。
    #[derive(Debug, Clone)]
    pub struct Captured {
        pub method: String,
        pub path: String,
        pub query: String,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    /// 预置的下一次错误（一次性）：(状态码, code, message)。
    #[derive(Debug, Clone)]
    pub struct NextError(pub u16, pub String, pub String);

    #[derive(Default)]
    pub struct State {
        pub zones: Vec<(String, String)>, // (id, name)
        pub records: Vec<MockRecord>,
        pub requests: Vec<Captured>,
        pub posts: usize,
        pub puts: usize,
        pub deletes: usize,
        pub next_error: Option<NextError>,
        pub seq: usize,
    }

    pub struct MockServer {
        pub addr: SocketAddr,
        pub state: Arc<Mutex<State>>,
    }

    impl MockServer {
        pub async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("mock 绑定失败");
            let addr = listener.local_addr().unwrap();
            let state = Arc::new(Mutex::new(State::default()));
            let s = state.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let st = s.clone();
                    tokio::spawn(async move {
                        let _ = handle(stream, &st).await;
                    });
                }
            });
            Self { addr, state }
        }

        pub fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        pub fn inject_error(&self, status: u16, code: &str, message: &str) {
            self.state.lock().unwrap().next_error =
                Some(NextError(status, code.to_string(), message.to_string()));
        }

        pub fn last_request(&self) -> Captured {
            self.state
                .lock()
                .unwrap()
                .requests
                .last()
                .cloned()
                .expect("无请求记录")
        }
    }

    /// 查询串 → 参数表（百分号解码；签名复算用原始 query 串，不受影响）。
    pub fn parse_query(q: &str) -> HashMap<String, String> {
        q.split('&')
            .filter(|kv| !kv.is_empty())
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (pct_decode(k), pct_decode(v)))
            .collect()
    }

    /// 百分号解码（mock 专用：客户端发出的 RR 等参数为 RFC3986 编码形态）。
    pub fn pct_decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let Ok(hex) = std::str::from_utf8(&b[i + 1..i + 3]) {
                    if let Ok(v) = u8::from_str_radix(hex, 16) {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).to_string()
    }

    pub fn header_of(captured: &Captured, name: &str) -> Option<String> {
        captured
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    /// 用捕获的请求参数复算 BCE 签名（与 client 的算法一致）。
    pub fn recompute_auth(
        captured: &Captured,
        ak: &str,
        sk: &str,
        expiration: u32,
    ) -> String {
        let ts = header_of(captured, "x-bce-date").expect("缺 x-bce-date");
        let host = header_of(captured, "host").expect("缺 host");
        let auth_prefix = format!("bce-auth-v1/{ak}/{ts}/{expiration}");
        let signing_key = super::sign::hmac_sha256_hex(sk.as_bytes(), auth_prefix.as_bytes());
        let canonical = format!(
            "{}\n{}\n{}\nhost:{host}\nx-bce-date:{ts}\n",
            captured.method, captured.path, captured.query
        );
        let signature =
            super::sign::hmac_sha256_hex(signing_key.as_bytes(), canonical.as_bytes());
        format!("{auth_prefix}/host;x-bce-date/{signature}")
    }

    async fn handle(mut stream: TcpStream, state: &Arc<Mutex<State>>) -> std::io::Result<()> {
        let mut reader = BufReader::new(&mut stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;
        let mut content_length = 0usize;
        let mut headers: Vec<(String, String)> = Vec::new();
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
                headers.push((k.trim().to_string(), v.trim().to_string()));
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0u8; content_length];
        let _ = reader.read_exact(&mut body).await;
        let body = String::from_utf8_lossy(&body).to_string();

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let (path, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
        state.lock().unwrap().requests.push(Captured {
            method: method.clone(),
            path: path.to_string(),
            query: query.to_string(),
            headers,
            body: body.clone(),
        });
        let (status, resp_body) = route(&method, &path, &query, &body, state);
        let raw = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status, resp_body.len(), resp_body
        );
        stream.write_all(raw.as_bytes()).await?;
        stream.flush().await
    }

    fn route(
        method: &str,
        path: &str,
        query: &str,
        body: &str,
        state: &Arc<Mutex<State>>,
    ) -> (String, String) {
        let params = parse_query(query);
        let mut st = state.lock().unwrap();
        if let Some(NextError(status, code, message)) = st.next_error.take() {
            return (
                format!("{status} {}", status_text(status)),
                serde_json::json!({ "code": code, "message": message, "requestId": "mock-err" })
                    .to_string(),
            );
        }
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        // /v1/dns/zone —— 域名列表。
        if segs.len() == 3 && method == "GET" {
            let zones: Vec<serde_json::Value> = st
                .zones
                .iter()
                .map(|(id, name)| serde_json::json!({ "id": id, "name": name }))
                .collect();
            return (
                "200 OK".into(),
                serde_json::json!({
                    "marker": "", "isTruncated": false, "maxKeys": 100,
                    "zones": zones,
                })
                .to_string(),
            );
        }
        // /v1/dns/zone/{zone}/record —— 记录列表 / 创建。
        if segs.len() == 5 && segs[4] == "record" {
            if method == "GET" {
                let rr = params.get("rr").cloned().unwrap_or_default();
                let filtered: Vec<&MockRecord> = st
                    .records
                    .iter()
                    .filter(|r| rr.is_empty() || r.rr == rr)
                    .collect();
                return (
                    "200 OK".into(),
                    serde_json::json!({
                        "marker": "", "isTruncated": false, "maxKeys": 100,
                        "records": filtered,
                    })
                    .to_string(),
                );
            }
            if method == "POST" {
                st.seq += 1;
                let mut rec: MockRecord =
                    serde_json::from_str(body).unwrap_or_else(|_| MockRecord {
                        id: String::new(),
                        rr: String::new(),
                        rtype: String::new(),
                        value: String::new(),
                        ttl: 300,
                        priority: None,
                    });
                rec.id = format!("rec-{}", st.seq);
                st.records.push(rec);
                st.posts += 1;
                return ("200 OK".into(), String::new());
            }
        }
        // /v1/dns/zone/{zone}/record/{id} —— 更新 / 删除。
        if segs.len() == 6 && segs[4] == "record" {
            let id = segs[5];
            match method {
                "PUT" => {
                    let exists = st.records.iter().any(|r| r.id == id);
                    if !exists {
                        return (
                            "404 Not Found".into(),
                            serde_json::json!({ "code": "NoSuchRecord", "message": "record not found" })
                                .to_string(),
                        );
                    }
                    let mut rec: MockRecord = serde_json::from_str(body).unwrap();
                    rec.id = id.to_string();
                    st.records.retain(|r| r.id != id);
                    st.records.push(rec);
                    st.puts += 1;
                    return ("200 OK".into(), String::new());
                }
                "DELETE" => {
                    let before = st.records.len();
                    st.records.retain(|r| r.id != id);
                    if st.records.len() == before {
                        return (
                            "404 Not Found".into(),
                            serde_json::json!({ "code": "NoSuchRecord", "message": "record not found" })
                                .to_string(),
                        );
                    }
                    st.deletes += 1;
                    return ("200 OK".into(), String::new());
                }
                _ => {}
            }
        }
        ("404 Not Found".into(), serde_json::json!({ "code": "NoSuchRoute", "message": "bad route" }).to_string())
    }

    fn status_text(status: u16) -> String {
        match status {
            200 => "OK".into(),
            400 => "Bad Request".into(),
            403 => "Forbidden".into(),
            404 => "Not Found".into(),
            429 => "Too Many Requests".into(),
            500 => "Internal Server Error".into(),
            _ => "Error".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::{header_of, recompute_auth, MockServer};
    use super::*;
    use crate::provider::ProviderRegistry;
    use crate::provider::RecordData;

    const AK: &str = "baidu-test-ak";
    const SK: &str = "baidu-test-secret";
    const EXPIRATION: u32 = 1800;

    fn provider(mock: &MockServer) -> BaiduProvider {
        BaiduProvider::new(AK.into(), SK.into(), Some(mock.base_url()))
    }

    fn arec(name: &str, data: &str, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: RecordType::A,
            ttl,
            data: RecordData::Plain(data.to_string()),
        }
    }

    /// 契约 1：Authorization 头形状（bce-auth-v1/{ak}/{ts}/{exp}/host;x-bce-date/{sig}）
    /// 且签名可由固定密钥 + 捕获请求参数复算。
    #[tokio::test]
    async fn authorization_shape_and_recomputable() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        let _ = p.list_domains().await.unwrap();
        let captured = mock.last_request();
        let auth = header_of(&captured, "authorization").expect("缺 Authorization 头");
        assert!(
            auth.starts_with(&format!("bce-auth-v1/{AK}/")),
            "Authorization 前缀错误: {auth}"
        );
        assert!(auth.contains("/host;x-bce-date/"), "signedHeaders 应为 host;x-bce-date");
        assert_eq!(header_of(&captured, "x-bce-date").is_some(), true, "缺 x-bce-date 头");
        // 用捕获的 host/x-bce-date/query 复算 → 必须一致。
        let expected = recompute_auth(&captured, AK, SK, EXPIRATION);
        assert_eq!(auth, expected, "Authorization 可由固定密钥复算");
    }

    /// 契约 2：list_domains 解析（zones[].name）。
    #[tokio::test]
    async fn list_domains_parses() {
        let mock = MockServer::start().await;
        mock.state.lock().unwrap().zones = vec![
            ("z1".into(), "example.com".into()),
            ("z2".into(), "kirin.dev".into()),
        ];
        let p = provider(&mock);
        assert_eq!(p.list_domains().await.unwrap(), vec!["example.com", "kirin.dev"]);
    }

    /// 契约 3：upsert 查→增（不存在 → POST）。
    #[tokio::test]
    async fn upsert_adds_when_missing() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        p.upsert_record("example.com", &arec("my-pc", "203.0.113.7", 600))
            .await
            .unwrap();
        {
            let st = mock.state.lock().unwrap();
            assert_eq!(st.posts, 1);
            assert_eq!(st.puts, 0);
            assert_eq!(st.records.len(), 1);
            assert_eq!(st.records[0].rr, "my-pc");
            assert_eq!(st.records[0].value, "203.0.113.7");
        }
        let found = p
            .query_records("example.com", Some("my-pc"), Some(RecordType::A))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].data, RecordData::Plain("203.0.113.7".into()));
    }

    /// 契约 3b：upsert 查→改（已存在 → PUT），不产生重复。
    #[tokio::test]
    async fn upsert_updates_when_exists() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        p.upsert_record("example.com", &arec("my-pc", "203.0.113.7", 600))
            .await
            .unwrap();
        p.upsert_record("example.com", &arec("my-pc", "203.0.113.8", 1200))
            .await
            .unwrap();
        {
            let st = mock.state.lock().unwrap();
            assert_eq!(st.posts, 1, "第二次应走 PUT");
            assert_eq!(st.puts, 1);
            assert_eq!(st.records.len(), 1, "同 RR+type 不重复");
            assert_eq!(st.records[0].value, "203.0.113.8");
            assert_eq!(st.records[0].ttl, 1200);
        }
    }

    /// 契约 4：delete 按 RR+Type 删除；删不存在 → NotFound（404）。
    #[tokio::test]
    async fn delete_removes_and_not_found() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        p.upsert_record("example.com", &arec("my-pc", "203.0.113.7", 600))
            .await
            .unwrap();
        p.delete_record("example.com", "my-pc", RecordType::A)
            .await
            .unwrap();
        assert_eq!(mock.state.lock().unwrap().records.len(), 0);
        let err = p
            .delete_record("example.com", "ghost", RecordType::A)
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }

    /// 契约 5：错误码映射（401/403→Auth、400→InvalidParameter、404→NotFound、429→RateLimited、5xx→Server）。
    #[tokio::test]
    async fn error_code_mapping() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        mock.inject_error(403, "AccessDenied", "no permission");
        assert!(matches!(p.list_domains().await.unwrap_err(), ProviderError::Auth { .. }));
        mock.inject_error(400, "InvalidParameter", "bad param");
        assert!(matches!(
            p.list_domains().await.unwrap_err(),
            ProviderError::InvalidParameter { .. }
        ));
        mock.inject_error(404, "NoSuchDomain", "no domain");
        assert!(matches!(
            p.list_domains().await.unwrap_err(),
            ProviderError::NotFound { .. }
        ));
        mock.inject_error(429, "RateLimitExceeded", "slow down");
        assert!(matches!(
            p.list_domains().await.unwrap_err(),
            ProviderError::RateLimited { .. }
        ));
        mock.inject_error(500, "InternalError", "boom");
        assert!(matches!(
            p.list_domains().await.unwrap_err(),
            ProviderError::Server { .. }
        ));
    }

    /// 契约 6：RR 相对名转换——根 `""` ↔ `@`（写 body rr=@，读 @→""）。
    #[tokio::test]
    async fn rr_relative_name_root_conversion() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        p.upsert_record("example.com", &arec("", "203.0.113.9", 600))
            .await
            .unwrap();
        {
            let st = mock.state.lock().unwrap();
            assert_eq!(st.records[0].rr, "@");
        }
        mock.state.lock().unwrap().records.push(super::mock::MockRecord {
            id: "rec-root".into(),
            rr: "@".into(),
            rtype: "A".into(),
            value: "203.0.113.10".into(),
            ttl: 600,
            priority: None,
        });
        let found = p
            .query_records("example.com", Some(""), Some(RecordType::A))
            .await
            .unwrap();
        // upsert 写入的根记录 + 预置的根记录（均为 RR=@ → 统一模型 ""）都应返回。
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|r| r.name == ""), "根记录应统一为相对名空串");
    }

    /// 契约 7：注册表注册与 name/capabilities。
    #[test]
    fn register_and_capabilities() {
        let mut registry = ProviderRegistry::new();
        register(&mut registry);
        assert!(registry.names().contains(&"baidu"));
        let cred = Credential::Baidu {
            access_key_id: AK.into(),
            secret_access_key: SK.into(),
        };
        let p = registry.build("baidu", &cred).unwrap();
        assert_eq!(p.name(), "baidu");
        let caps = p.capabilities();
        assert!(caps.srv && caps.ns && caps.ttl && caps.rename);
    }
}
