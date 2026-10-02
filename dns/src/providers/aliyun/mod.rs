//! M9-DNS003: 阿里云云解析（Alidns）Provider 适配
//!
//! - 端点：`https://alidns.aliyuncs.com`（RPC 风格，GET + 公共参数）
//! - 认证：HMAC-SHA1 RPC 签名（见 [`sign`]）
//! - 接口：`DescribeDomains` / `DescribeDomainRecords` / `AddDomainRecord` /
//!   `UpdateDomainRecord` / `DeleteDomainRecord`
//! - 能力：全开（A/AAAA/CNAME/MX/TXT/SRV/NS，TTL，改名）
//!
//! 错误映射见 [`error`]，记录模型互转见 [`record`]。

pub mod client;
pub mod error;
pub mod record;
pub mod sign;

use crate::provider::record::RecordType;
use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
};
use client::{AliyunClient, DEFAULT_BASE_URL};
use record::{to_relative_name, to_vendor_rr, RawRecord};

/// 阿里云云解析 Provider 实现。
pub struct AliyunProvider {
    client: AliyunClient,
}

impl AliyunProvider {
    /// 构造客户端；`base_url` 为 `None` 时使用官方端点（测试可注入 mock 地址）。
    pub fn new(access_key_id: String, access_key_secret: String, base_url: Option<String>) -> Self {
        Self {
            client: AliyunClient::new(
                access_key_id,
                access_key_secret,
                base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
            ),
        }
    }
}

/// 从凭据构建 Provider（凭据类型不匹配时返回兜底错误 Provider，不 panic）。
fn factory(cred: &Credential) -> Box<dyn Provider> {
    match cred {
        Credential::Aliyun {
            access_key_id,
            access_key_secret,
        } => Box::new(AliyunProvider::new(
            access_key_id.clone(),
            access_key_secret.clone(),
            None,
        )),
        _ => Box::new(MismatchProvider::new("aliyun")),
    }
}

/// 注册到全局 ProviderRegistry（name = "aliyun"，与配置 `[dns.providers.aliyun]` 一致）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register(
        "aliyun",
        |cred| -> Box<dyn Provider> { factory(cred) } as fn(&Credential) -> Box<dyn Provider>,
    );
}

#[async_trait::async_trait]
impl Provider for AliyunProvider {
    fn name(&self) -> &'static str {
        "aliyun"
    }

    /// 测试连接：DescribeDomains 取一页（PageSize=1）。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.list_domains().await.map(|_| ())
    }

    /// 域名列表（DescribeDomains，自动分页）。
    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.client.list_domains().await
    }

    /// 查询记录：name/rtype 传 None 查全表；
    /// 关键字过滤（RRKeyWord/TypeKeyWord）后内存精确过滤。
    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let keyword = name.map(to_vendor_rr);
        let raw = self
            .client
            .list_raw_records(domain, keyword.as_deref(), rtype.map(|t| t.as_str()))
            .await?;
        Ok(client::filter_exact(raw, name, rtype))
    }

    /// 幂等写入：按 RR+Type 查询 → 存在则 Update（取 RecordId）→ 不存在则 Add。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let keyword = to_vendor_rr(&rec.name);
        let raw = self
            .client
            .list_raw_records(domain, Some(keyword.as_str()), Some(rec.rtype.as_str()))
            .await?;
        let exact: Vec<RawRecord> = raw
            .into_iter()
            .filter(|r| to_relative_name(&r.rr) == rec.name && r.rtype.eq_ignore_ascii_case(rec.rtype.as_str()))
            .collect();
        match exact.first() {
            Some(found) => {
                let record_id = found.record_id.clone();
                self.client.update_record(&record_id, domain, rec).await
            }
            None => self.client.add_record(domain, rec).await,
        }
    }

    /// 删除：按 RR+Type 定位全部匹配记录并逐个删除；无匹配 → NotFound。
    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let keyword = to_vendor_rr(name);
        let raw = self
            .client
            .list_raw_records(domain, Some(keyword.as_str()), Some(rtype.as_str()))
            .await?;
        let exact: Vec<RawRecord> = raw
            .into_iter()
            .filter(|r| to_relative_name(&r.rr) == name && r.rtype.eq_ignore_ascii_case(rtype.as_str()))
            .collect();
        if exact.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        for r in &exact {
            self.client.delete_record(&r.record_id).await?;
        }
        Ok(())
    }

    /// 能力全开（SRV/NS/TTL/改名均支持）。
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

/// 凭据类型不匹配时的兜底 Provider：所有调用返回统一错误（不 panic、不打印凭据）。
struct MismatchProvider {
    name: &'static str,
}

impl MismatchProvider {
    fn new(name: &'static str) -> Self {
        Self { name }
    }
}

fn mismatch_error(name: &'static str) -> ProviderError {
    ProviderError::Other(format!("服务商「{name}」配置的凭据类型不匹配（需要 Aliyun 凭据）"))
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
    //! 极简 Alidns mock HTTP 服务器（参考 dns/src/test_support.rs 的 MockDns 模式，
    //! 自包含于本模块，仅测试编译）。记录每次请求的 query 供签名断言。

    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// mock 存储的记录（wire 格式，与 Alidns 响应字段一致）。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MockRecord {
        #[serde(rename = "RecordId")]
        pub record_id: String,
        #[serde(rename = "RR")]
        pub rr: String,
        #[serde(rename = "Type")]
        pub rtype: String,
        #[serde(rename = "Value")]
        pub value: String,
        #[serde(rename = "TTL")]
        pub ttl: u32,
        #[serde(rename = "Priority")]
        pub priority: Option<u32>,
    }

    /// 预置的下一个错误（一次性）：(状态码, Code, Message)。
    #[derive(Debug, Clone)]
    pub struct NextError(pub u16, pub String, pub String);

    #[derive(Default)]
    pub struct State {
        pub domains: Vec<String>,
        pub records: Vec<MockRecord>,
        /// 收到的请求 query（签名/公共参数断言用）。
        pub queries: Vec<String>,
        /// 各 Action 调用计数（upsert 语义断言用）。
        pub adds: usize,
        pub updates: usize,
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

        /// 注入下一次请求的错误响应。
        pub fn inject_error(&self, status: u16, code: &str, message: &str) {
            self.state.lock().unwrap().next_error =
                Some(NextError(status, code.to_string(), message.to_string()));
        }

        /// 最近一次请求的 query。
        pub fn last_query(&self) -> String {
            self.state
                .lock()
                .unwrap()
                .queries
                .last()
                .cloned()
                .unwrap_or_default()
        }

        pub fn record_count(&self) -> usize {
            self.state.lock().unwrap().records.len()
        }
    }

    /// 解析 query 串为参数表（含百分号解码）。
    pub fn parse_query(q: &str) -> HashMap<String, String> {
        q.split('&')
            .filter(|kv| !kv.is_empty())
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (pct_decode(k), pct_decode(v)))
            .collect()
    }

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

    async fn handle(mut stream: TcpStream, state: &Arc<Mutex<State>>) -> std::io::Result<()> {
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
        let _ = reader.read_exact(&mut body).await;

        let mut parts = request_line.split_whitespace();
        let _method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("").to_string();
        let query = path.split_once('?').map(|(_, q)| q.to_string()).unwrap_or_default();
        if !query.is_empty() {
            state.lock().unwrap().queries.push(query.clone());
        }
        let (status, resp_body) = route(&query, state);
        let raw = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status, resp_body.len(), resp_body
        );
        stream.write_all(raw.as_bytes()).await?;
        stream.flush().await
    }

    /// 按 Action 路由（返回状态行 + body）。
    fn route(query: &str, state: &Arc<Mutex<State>>) -> (String, String) {
        let params = parse_query(query);
        let action = params.get("Action").cloned().unwrap_or_default();

        let mut st = state.lock().unwrap();
        // 一次性错误注入优先。
        if let Some(NextError(status, code, message)) = st.next_error.take() {
            return (
                format!("{status} {}", status_text(status)),
                serde_json::json!({ "Code": code, "Message": message, "RequestId": "mock-err" })
                    .to_string(),
            );
        }
        match action.as_str() {
            "DescribeDomains" => {
                let arr: Vec<serde_json::Value> = st
                    .domains
                    .iter()
                    .map(|d| serde_json::json!({ "DomainName": d }))
                    .collect();
                (
                    "200 OK".into(),
                    serde_json::json!({
                        "TotalCount": st.domains.len(),
                        "PageNumber": 1,
                        "PageSize": 500,
                        "Domains": { "Domain": arr },
                    })
                    .to_string(),
                )
            }
            "DescribeDomainRecords" => {
                let rr_kw = params.get("RRKeyWord").cloned().unwrap_or_default();
                let type_kw = params.get("TypeKeyWord").cloned().unwrap_or_default();
                let filtered: Vec<&MockRecord> = st
                    .records
                    .iter()
                    .filter(|r| {
                        (rr_kw.is_empty() || r.rr.contains(&rr_kw))
                            && (type_kw.is_empty() || r.rtype.eq_ignore_ascii_case(&type_kw))
                    })
                    .collect();
                let total = filtered.len();
                (
                    "200 OK".into(),
                    serde_json::json!({
                        "TotalCount": total,
                        "PageNumber": 1,
                        "PageSize": 500,
                        "DomainRecords": { "Record": filtered },
                    })
                    .to_string(),
                )
            }
            "AddDomainRecord" => {
                st.seq += 1;
                let id = format!("rec-{}", st.seq);
                st.records.push(MockRecord {
                    record_id: id.clone(),
                    rr: params.get("RR").cloned().unwrap_or_default(),
                    rtype: params.get("Type").cloned().unwrap_or_default(),
                    value: params.get("Value").cloned().unwrap_or_default(),
                    ttl: params.get("TTL").and_then(|t| t.parse().ok()).unwrap_or(600),
                    priority: params.get("Priority").and_then(|p| p.parse().ok()),
                });
                st.adds += 1;
                (
                    "200 OK".into(),
                    serde_json::json!({ "RecordId": id, "RequestId": format!("req-{}", st.seq) })
                        .to_string(),
                )
            }
            "UpdateDomainRecord" => {
                st.updates += 1;
                let id = params.get("RecordId").cloned().unwrap_or_default();
                if let Some(r) = st.records.iter_mut().find(|r| r.record_id == id) {
                    r.rr = params.get("RR").cloned().unwrap_or_else(|| r.rr.clone());
                    r.rtype = params.get("Type").cloned().unwrap_or_else(|| r.rtype.clone());
                    r.value = params.get("Value").cloned().unwrap_or_else(|| r.value.clone());
                    if let Some(t) = params.get("TTL").and_then(|t| t.parse().ok()) {
                        r.ttl = t;
                    }
                    if let Some(p) = params.get("Priority").and_then(|p| p.parse().ok()) {
                        r.priority = Some(p);
                    }
                    (
                        "200 OK".into(),
                        serde_json::json!({ "RecordId": id, "RequestId": "req-u" }).to_string(),
                    )
                } else {
                    (
                        "400 Bad Request".into(),
                        serde_json::json!({
                            "Code": "DomainRecordNotBelongToUser",
                            "Message": "record not found",
                            "RequestId": "req-u-err",
                        })
                        .to_string(),
                    )
                }
            }
            "DeleteDomainRecord" => {
                st.deletes += 1;
                let id = params.get("RecordId").cloned().unwrap_or_default();
                let before = st.records.len();
                st.records.retain(|r| r.record_id != id);
                if st.records.len() == before {
                    (
                        "400 Bad Request".into(),
                        serde_json::json!({
                            "Code": "DomainRecordNotBelongToUser",
                            "Message": "record not found",
                            "RequestId": "req-d-err",
                        })
                        .to_string(),
                    )
                } else {
                    ("200 OK".into(), serde_json::json!({ "RequestId": "req-d" }).to_string())
                }
            }
            _ => (
                "400 Bad Request".into(),
                serde_json::json!({
                    "Code": "InvalidAction",
                    "Message": format!("unknown action {action}"),
                    "RequestId": "req-a-err",
                })
                .to_string(),
            ),
        }
    }

    fn status_text(status: u16) -> String {
        match status {
            200 => "OK".into(),
            400 => "Bad Request".into(),
            403 => "Forbidden".into(),
            429 => "Too Many Requests".into(),
            500 => "Internal Server Error".into(),
            _ => "Error".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockServer;
    use super::*;
    use crate::provider::{ProviderRegistry, RecordData};

    const AK: &str = "test-ak";
    const SK: &str = "test-secret";

    fn provider(mock: &MockServer) -> AliyunProvider {
        AliyunProvider::new(AK.into(), SK.into(), Some(mock.base_url()))
    }

    fn arec(name: &str, data: &str, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: RecordType::A,
            ttl,
            data: RecordData::Plain(data.to_string()),
        }
    }

    /// 契约 1：签名请求形状——公共参数齐全，且 Signature 可由固定密钥+请求参数复算。
    #[tokio::test]
    async fn signature_query_shape_and_recomputable() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        let _ = p.list_domains().await.unwrap();
        let q = mock.last_query();
        assert!(!q.is_empty());
        let params = mock::parse_query(&q);
        // 公共参数齐全。
        for key in [
            "Action", "Version", "AccessKeyId", "SignatureMethod", "SignatureVersion",
            "SignatureNonce", "Timestamp", "Format", "Signature",
        ] {
            assert!(params.contains_key(key), "缺少公共参数 {key}");
        }
        assert_eq!(params["Version"], "2015-01-09");
        assert_eq!(params["SignatureMethod"], "HMAC-SHA1");
        assert_eq!(params["Format"], "JSON");
        assert_eq!(params["AccessKeyId"], AK);
        // 用捕获的 Timestamp/Nonce 复算签名，必须与请求中的 Signature 一致。
        let mut signed: std::collections::BTreeMap<String, String> = params
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        signed.remove("Signature");
        assert_eq!(
            crate::providers::aliyun::sign::sign_rpc(&signed, SK),
            params["Signature"],
            "Signature 可由固定密钥复算"
        );
    }

    /// 契约 2：list_domains 解析。
    #[tokio::test]
    async fn list_domains_parses() {
        let mock = MockServer::start().await;
        mock.state.lock().unwrap().domains = vec!["example.com".into(), "kirin.dev".into()];
        let p = provider(&mock);
        assert_eq!(
            p.list_domains().await.unwrap(),
            vec!["example.com", "kirin.dev"]
        );
    }

    /// 契约 3：upsert 查→增（不存在）语义。
    #[tokio::test]
    async fn upsert_adds_when_missing() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        p.upsert_record("example.com", &arec("my-pc", "203.0.113.7", 600))
            .await
            .unwrap();
        {
            let st = mock.state.lock().unwrap();
            assert_eq!(st.adds, 1);
            assert_eq!(st.updates, 0);
            assert_eq!(st.records.len(), 1);
            assert_eq!(st.records[0].rr, "my-pc");
            assert_eq!(st.records[0].value, "203.0.113.7");
        }
        // query 可见。
        let found = p
            .query_records("example.com", Some("my-pc"), Some(RecordType::A))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].data, RecordData::Plain("203.0.113.7".into()));
    }

    /// 契约 3b：upsert 查→改（已存在）语义——同 RR+Type 走 Update，不产生重复。
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
            assert_eq!(st.adds, 1, "第二次应走 Update 而非 Add");
            assert_eq!(st.updates, 1);
            assert_eq!(st.records.len(), 1, "同 RR+Type 不重复");
            assert_eq!(st.records[0].value, "203.0.113.8");
            assert_eq!(st.records[0].ttl, 1200);
        }
    }

    /// 契约 4：delete 按 RR+Type 删除；删不存在 → NotFound。
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
        // 删不存在的 → NotFound（mock 返回 DomainRecordNotBelongToUser）。
        let err = p
            .delete_record("example.com", "ghost", RecordType::A)
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }

    /// 契约 5：错误码映射（Auth / InvalidParameter / RateLimited / Server）。
    #[tokio::test]
    async fn error_code_mapping() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        mock.inject_error(403, "InvalidAccessKeyId.NotFound", "ak 不存在");
        assert!(matches!(
            p.list_domains().await.unwrap_err(),
            ProviderError::Auth { .. }
        ));
        mock.inject_error(400, "InvalidDomainName", "域名非法");
        assert!(matches!(
            p.list_domains().await.unwrap_err(),
            ProviderError::InvalidParameter { .. }
        ));
        mock.inject_error(400, "Throttling", "qps");
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

    /// 契约 6：RR 相对名转换——根 `""` ↔ `@`。
    #[tokio::test]
    async fn rr_relative_name_root_conversion() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        // 写：根记录应发 RR=@。
        p.upsert_record("example.com", &arec("", "203.0.113.9", 600))
            .await
            .unwrap();
        {
            let st = mock.state.lock().unwrap();
            assert_eq!(st.records[0].rr, "@");
        }
        // 读：mock 预置 RR=@ 的记录 → 统一模型 ""。
        mock.state.lock().unwrap().records.push(super::mock::MockRecord {
            record_id: "rec-root".into(),
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
        assert!(registry.names().contains(&"aliyun"));
        let cred = Credential::Aliyun {
            access_key_id: AK.into(),
            access_key_secret: SK.into(),
        };
        let p = registry.build("aliyun", &cred).unwrap();
        assert_eq!(p.name(), "aliyun");
        let caps = p.capabilities();
        assert!(caps.srv && caps.ns && caps.ttl && caps.rename);
    }

    /// 契约 8：凭据类型不匹配 → 统一错误而非 panic。
    #[tokio::test]
    async fn mismatched_credential_returns_error() {
        let p = MismatchProvider::new("aliyun");
        let err = p.list_domains().await.unwrap_err();
        assert!(matches!(err, ProviderError::Other(_)));
        assert!(err.to_string().contains("aliyun"));
    }
}
