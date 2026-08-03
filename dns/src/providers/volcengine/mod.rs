//! M9-DNS017: 火山引擎云解析 DNS Provider 适配
//!
//! - 端点：`https://dns.volcengineapi.com`（2025-06-23 起新端点；旧端点可回退，见 [`client`]）
//! - 认证：v4 风格 HMAC-SHA256 签名（X-Date / X-Content-Sha256 / Authorization，见 [`sign`]）
//! - 接口：ListZones / ListRecordSets / CreateRecord / UpdateRecord / DeleteRecord
//!   （官方 OpenAPI 文档复核：记录管理无 CreateRecordSet/DeleteRecordSet，
//!    以 CreateRecord/UpdateRecord/DeleteRecord 为准；UpdateRecordSet 为负载均衡开关，不使用）
//! - 能力：全开（A/AAAA/CNAME/MX/TXT/SRV/NS，TTL，改名）

pub mod client;
pub mod error;
pub mod record;
pub mod sign;

use crate::provider::record::RecordType;
use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
};
use client::VolcengineClient;
use record::{to_relative_name, RawRecordSet};

/// 火山引擎 Provider 实现。
pub struct VolcengineProvider {
    client: VolcengineClient,
}

impl VolcengineProvider {
    /// 构造客户端；`base_url` 为 `None` 时使用默认端点（测试可注入 mock 地址）。
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        region: String,
        base_url: Option<String>,
    ) -> Self {
        Self {
            client: VolcengineClient::new(
                access_key_id,
                secret_access_key,
                region,
                base_url.unwrap_or_else(VolcengineClient::default_base_url),
            ),
        }
    }
}

/// 从凭据构建 Provider（凭据类型不匹配时返回兜底错误 Provider，不 panic）。
fn factory(cred: &Credential) -> Box<dyn Provider> {
    match cred {
        Credential::Volcengine {
            access_key_id,
            secret_access_key,
            region,
        } => Box::new(VolcengineProvider::new(
            access_key_id.clone(),
            secret_access_key.clone(),
            region.clone(),
            None,
        )),
        _ => Box::new(MismatchProvider::new("volcengine")),
    }
}

/// 注册到全局 ProviderRegistry（name = "volcengine"）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register(
        "volcengine",
        |cred| -> Box<dyn Provider> { factory(cred) } as fn(&Credential) -> Box<dyn Provider>,
    );
}

#[async_trait::async_trait]
impl Provider for VolcengineProvider {
    fn name(&self) -> &'static str {
        "volcengine"
    }

    /// 测试连接：ListZones 取一页。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.list_zones().await.map(|_| ())
    }

    /// 域名列表（ListZones → ZoneName）。
    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        Ok(self
            .client
            .list_zones()
            .await?
            .into_iter()
            .map(|(_, name)| name)
            .collect())
    }

    /// 查询记录：ListRecordSets 全量 + 内存精确过滤（name/rtype）。
    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let zid = self.client.resolve_zid(domain).await?;
        let raw = self.client.list_record_sets(&zid).await?;
        Ok(raw
            .into_iter()
            .filter_map(record::from_raw)
            .filter(|r| {
                name.map(|n| r.name == n).unwrap_or(true)
                    && rtype.map(|t| t == r.rtype).unwrap_or(true)
            })
            .collect())
    }

    /// 幂等写入：查 Host+Type → 存在则 UpdateRecord（RecordSetId）→ 不存在则 CreateRecord。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let zid = self.client.resolve_zid(domain).await?;
        let raw = self.client.list_record_sets(&zid).await?;
        let exact: Vec<RawRecordSet> = raw
            .into_iter()
            .filter(|r| {
                to_relative_name(&r.host) == rec.name
                    && r.rtype.eq_ignore_ascii_case(rec.rtype.as_str())
            })
            .collect();
        match exact.first() {
            Some(found) => {
                let id = found.record_set_id.clone();
                self.client.update_record(&id, rec).await
            }
            None => self.client.create_record(&zid, rec).await,
        }
    }

    /// 删除：按 Host+Type 定位全部匹配记录集并逐个删除；无匹配 → NotFound。
    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let zid = self.client.resolve_zid(domain).await?;
        let raw = self.client.list_record_sets(&zid).await?;
        let exact: Vec<RawRecordSet> = raw
            .into_iter()
            .filter(|r| {
                to_relative_name(&r.host) == name && r.rtype.eq_ignore_ascii_case(rtype.as_str())
            })
            .collect();
        if exact.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        for r in &exact {
            self.client.delete_record(&r.record_set_id).await?;
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
    ProviderError::Other(format!("服务商「{name}」配置的凭据类型不匹配（需要 Volcengine 凭据）"))
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
    //! 极简火山引擎 DNS mock HTTP 服务器（参考 dns/src/test_support.rs 的 MockDns 模式，
    //! 自包含于本模块，仅测试编译）。记录每次请求（query + 头）供签名断言。

    use super::client::SERVICE;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// mock 存储的记录集（wire 字段名与火山接口一致）。
    #[derive(Debug, Clone, Serialize)]
    pub struct MockRecordSet {
        pub zid: String,
        #[serde(rename = "RecordSetId")]
        pub record_set_id: String,
        #[serde(rename = "Host")]
        pub host: String,
        #[serde(rename = "Type")]
        pub rtype: String,
        #[serde(rename = "Value")]
        pub value: String,
        #[serde(rename = "TTL")]
        pub ttl: u32,
        #[serde(rename = "Priority", skip_serializing_if = "Option::is_none")]
        pub priority: Option<u32>,
    }

    /// 捕获的一次请求。
    #[derive(Debug, Clone)]
    pub struct Captured {
        pub path: String,
        pub query: String,
        pub headers: Vec<(String, String)>,
    }

    /// 预置的下一次错误（一次性）：(状态码, Code, Message)。
    #[derive(Debug, Clone)]
    pub struct NextError(pub u16, pub String, pub String);

    #[derive(Default)]
    pub struct State {
        pub zones: Vec<(String, String)>, // (ZID, ZoneName)
        pub records: Vec<MockRecordSet>,
        pub requests: Vec<Captured>,
        pub creates: usize,
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

    pub fn parse_query(q: &str) -> HashMap<String, String> {
        q.split('&')
            .filter(|kv| !kv.is_empty())
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (pct_decode(k), pct_decode(v)))
            .collect()
    }

    /// 百分号解码（mock 专用：客户端发出的 Host 等参数为 RFC3986 编码形态）。
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

    /// 用捕获的请求复算火山签名（与 client 的算法一致）。
    pub fn recompute_auth(captured: &Captured, ak: &str, sk: &str, region: &str) -> String {
        let x_date = header_of(captured, "x-date").expect("缺 x-date");
        let host = header_of(captured, "host").expect("缺 host");
        let empty = super::sign::EMPTY_BODY_SHA256_HEX;
        let short_date = &x_date[..8];
        let scope = format!("{short_date}/{region}/{SERVICE}/request");
        let canonical = format!(
            "GET\n/\n{}\nhost:{host}\nx-content-sha256:{empty}\nx-date:{x_date}\n\n\
             host;x-content-sha256;x-date\n{empty}",
            captured.query
        );
        let string_to_sign = format!(
            "HMAC-SHA256\n{x_date}\n{scope}\n{}",
            super::sign::sha256_hex(canonical.as_bytes())
        );
        let k_date = super::sign::hmac_sha256(sk.as_bytes(), short_date.as_bytes());
        let k_region = super::sign::hmac_sha256(&k_date, region.as_bytes());
        let k_service = super::sign::hmac_sha256(&k_region, SERVICE.as_bytes());
        let k_signing = super::sign::hmac_sha256(&k_service, b"request");
        let signature = hex::encode(super::sign::hmac_sha256(&k_signing, string_to_sign.as_bytes()));
        format!(
            "HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders=host;x-content-sha256;x-date, \
             Signature={signature}"
        )
    }

    async fn handle(mut stream: TcpStream, state: &Arc<Mutex<State>>) -> std::io::Result<()> {
        let mut reader = BufReader::new(&mut stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;
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
            }
        }
        let mut parts = request_line.split_whitespace();
        let _method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("").to_string();
        let (path, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
        state.lock().unwrap().requests.push(Captured {
            path: path.to_string(),
            query: query.to_string(),
            headers,
        });
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
        if let Some(NextError(status, code, message)) = st.next_error.take() {
            return (
                format!("{status} {}", status_text(status)),
                serde_json::json!({
                    "ResponseMetadata": { "RequestId": "mock-err",
                        "Error": { "Code": code, "Message": message } }
                })
                .to_string(),
            );
        }
        match action.as_str() {
            "ListZones" => {
                let zones: Vec<serde_json::Value> = st
                    .zones
                    .iter()
                    .map(|(zid, name)| {
                        serde_json::json!({ "ZID": zid, "ZoneName": name, "RecordCount": 0 })
                    })
                    .collect();
                (
                    "200 OK".into(),
                    serde_json::json!({
                        "ResponseMetadata": { "RequestId": "r-zones" },
                        "Result": { "Total": st.zones.len(), "Zones": zones },
                    })
                    .to_string(),
                )
            }
            "ListRecordSets" => {
                let zid = params.get("ZID").cloned().unwrap_or_default();
                let filtered: Vec<&MockRecordSet> = st
                    .records
                    .iter()
                    .filter(|r| r.zid == zid)
                    .collect();
                (
                    "200 OK".into(),
                    serde_json::json!({
                        "ResponseMetadata": { "RequestId": "r-sets" },
                        "Result": { "Total": filtered.len(), "RecordSets": filtered },
                    })
                    .to_string(),
                )
            }
            "CreateRecord" => {
                st.seq += 1;
                let id = format!("rs-{}", st.seq);
                st.records.push(MockRecordSet {
                    zid: params.get("ZID").cloned().unwrap_or_default(),
                    record_set_id: id.clone(),
                    host: params.get("Host").cloned().unwrap_or_default(),
                    rtype: params.get("Type").cloned().unwrap_or_default(),
                    value: params.get("Value").cloned().unwrap_or_default(),
                    ttl: params.get("TTL").and_then(|t| t.parse().ok()).unwrap_or(600),
                    priority: params.get("Priority").and_then(|p| p.parse().ok()),
                });
                st.creates += 1;
                (
                    "200 OK".into(),
                    serde_json::json!({
                        "ResponseMetadata": { "RequestId": "r-create" },
                        "Result": { "RecordSetId": id },
                    })
                    .to_string(),
                )
            }
            "UpdateRecord" => {
                st.updates += 1;
                let id = params.get("RecordSetId").cloned().unwrap_or_default();
                if let Some(r) = st.records.iter_mut().find(|r| r.record_set_id == id) {
                    r.host = params.get("Host").cloned().unwrap_or_else(|| r.host.clone());
                    r.rtype = params
                        .get("Type")
                        .cloned()
                        .unwrap_or_else(|| r.rtype.clone());
                    r.value = params.get("Value").cloned().unwrap_or_else(|| r.value.clone());
                    if let Some(t) = params.get("TTL").and_then(|t| t.parse().ok()) {
                        r.ttl = t;
                    }
                    if let Some(p) = params.get("Priority").and_then(|p| p.parse().ok()) {
                        r.priority = Some(p);
                    }
                    (
                        "200 OK".into(),
                        serde_json::json!({
                            "ResponseMetadata": { "RequestId": "r-update" },
                            "Result": {},
                        })
                        .to_string(),
                    )
                } else {
                    (
                        "404 Not Found".into(),
                        serde_json::json!({
                            "ResponseMetadata": { "RequestId": "r-upd-err",
                                "Error": { "Code": "RecordNotFound", "Message": "record not found" } }
                        })
                        .to_string(),
                    )
                }
            }
            "DeleteRecord" => {
                st.deletes += 1;
                let id = params.get("RecordSetId").cloned().unwrap_or_default();
                let before = st.records.len();
                st.records.retain(|r| r.record_set_id != id);
                if st.records.len() == before {
                    (
                        "404 Not Found".into(),
                        serde_json::json!({
                            "ResponseMetadata": { "RequestId": "r-del-err",
                                "Error": { "Code": "RecordNotFound", "Message": "record not found" } }
                        })
                        .to_string(),
                    )
                } else {
                    (
                        "200 OK".into(),
                        serde_json::json!({
                            "ResponseMetadata": { "RequestId": "r-del" },
                            "Result": {},
                        })
                        .to_string(),
                    )
                }
            }
            _ => (
                "400 Bad Request".into(),
                serde_json::json!({
                    "ResponseMetadata": { "RequestId": "r-act-err",
                        "Error": { "Code": "InvalidParameter", "Message": format!("unknown action {action}") } }
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

    const AK: &str = "volc-test-ak";
    const SK: &str = "volc-test-secret";
    const REGION: &str = "cn-north-1";

    fn provider(mock: &MockServer) -> VolcengineProvider {
        VolcengineProvider::new(AK.into(), SK.into(), REGION.into(), Some(mock.base_url()))
    }

    /// 预置一个 zone（域名 → ZID）。
    fn seed_zone(mock: &MockServer, name: &str) {
        mock.state
            .lock()
            .unwrap()
            .zones
            .push(("z1".to_string(), name.to_string()));
    }

    fn arec(name: &str, data: &str, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: RecordType::A,
            ttl,
            data: RecordData::Plain(data.to_string()),
        }
    }

    /// 契约 1：签名三头形状（X-Date / X-Content-Sha256 / Authorization）
    /// 且 Authorization 可由固定密钥 + 捕获请求复算；Action/Version 公共参数齐全。
    #[tokio::test]
    async fn signature_headers_shape_and_recomputable() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        let _ = p.list_domains().await.unwrap();
        let captured = mock.last_request();
        let params = mock::parse_query(&captured.query);
        assert_eq!(params["Action"], "ListZones");
        assert_eq!(params["Version"], "2018-08-01");
        // 签名三头齐全。
        let x_date = header_of(&captured, "x-date").expect("缺 X-Date");
        assert_eq!(
            header_of(&captured, "x-content-sha256").as_deref(),
            Some(super::sign::EMPTY_BODY_SHA256_HEX),
            "X-Content-Sha256 应为空体 SHA-256"
        );
        let auth = header_of(&captured, "authorization").expect("缺 Authorization");
        assert!(auth.starts_with("HMAC-SHA256 Credential="), "算法前缀错误: {auth}");
        assert!(auth.contains(&format!("{AK}/{}/cn-north-1/dns/request", &x_date[..8])));
        assert!(auth.contains("SignedHeaders=host;x-content-sha256;x-date"));
        // 复算一致。
        let expected = recompute_auth(&captured, AK, SK, REGION);
        assert_eq!(auth, expected, "Authorization 可由固定密钥复算");
    }

    /// 契约 2：list_domains 解析（Zones → ZoneName）。
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

    /// 契约 3：upsert 查→增（CreateRecord）；ZID 由 ListZones 解析并缓存。
    #[tokio::test]
    async fn upsert_adds_when_missing() {
        let mock = MockServer::start().await;
        seed_zone(&mock, "example.com");
        let p = provider(&mock);
        p.upsert_record("example.com", &arec("my-pc", "203.0.113.7", 600))
            .await
            .unwrap();
        {
            let st = mock.state.lock().unwrap();
            assert_eq!(st.creates, 1);
            assert_eq!(st.updates, 0);
            assert_eq!(st.records.len(), 1);
            assert_eq!(st.records[0].zid, "z1", "CreateRecord 应携带解析出的 ZID");
            assert_eq!(st.records[0].host, "my-pc");
            assert_eq!(st.records[0].value, "203.0.113.7");
        }
        let found = p
            .query_records("example.com", Some("my-pc"), Some(RecordType::A))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].data, RecordData::Plain("203.0.113.7".into()));
    }

    /// 契约 3b：upsert 查→改（UpdateRecord），不产生重复。
    #[tokio::test]
    async fn upsert_updates_when_exists() {
        let mock = MockServer::start().await;
        seed_zone(&mock, "example.com");
        let p = provider(&mock);
        p.upsert_record("example.com", &arec("my-pc", "203.0.113.7", 600))
            .await
            .unwrap();
        p.upsert_record("example.com", &arec("my-pc", "203.0.113.8", 1200))
            .await
            .unwrap();
        {
            let st = mock.state.lock().unwrap();
            assert_eq!(st.creates, 1, "第二次应走 UpdateRecord");
            assert_eq!(st.updates, 1);
            assert_eq!(st.records.len(), 1, "同 Host+Type 不重复");
            assert_eq!(st.records[0].value, "203.0.113.8");
            assert_eq!(st.records[0].ttl, 1200);
        }
    }

    /// 契约 4：delete 按 Host+Type 删除；删不存在 → NotFound。
    #[tokio::test]
    async fn delete_removes_and_not_found() {
        let mock = MockServer::start().await;
        seed_zone(&mock, "example.com");
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

    /// 契约 5：错误码映射（Auth / InvalidParameter / NotFound / RateLimited / Server）。
    #[tokio::test]
    async fn error_code_mapping() {
        let mock = MockServer::start().await;
        let p = provider(&mock);
        mock.inject_error(403, "InvalidAccessKey", "ak 无效");
        assert!(matches!(p.list_domains().await.unwrap_err(), ProviderError::Auth { .. }));
        mock.inject_error(400, "InvalidParameter", "参数非法");
        assert!(matches!(
            p.list_domains().await.unwrap_err(),
            ProviderError::InvalidParameter { .. }
        ));
        mock.inject_error(404, "ZoneNotFound", "zone 不存在");
        assert!(matches!(
            p.list_domains().await.unwrap_err(),
            ProviderError::NotFound { .. }
        ));
        mock.inject_error(429, "Throttling", "限流");
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
        seed_zone(&mock, "example.com");
        let p = provider(&mock);
        // 写：根记录应发 Host=@。
        p.upsert_record("example.com", &arec("", "203.0.113.9", 600))
            .await
            .unwrap();
        {
            let st = mock.state.lock().unwrap();
            assert_eq!(st.records[0].host, "@");
        }
        // 读：mock 预置 Host=@ → 统一模型 ""。
        mock.state.lock().unwrap().records.push(super::mock::MockRecordSet {
            zid: "z1".into(),
            record_set_id: "rs-root".into(),
            host: "@".into(),
            rtype: "A".into(),
            value: "203.0.113.10".into(),
            ttl: 600,
            priority: None,
        });
        let found = p
            .query_records("example.com", Some(""), Some(RecordType::A))
            .await
            .unwrap();
        // upsert 写入的根记录 + 预置的根记录（均为 Host=@ → 统一模型 ""）都应返回。
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|r| r.name == ""), "根记录应统一为相对名空串");
    }

    /// 契约 7：注册表注册与 name/capabilities。
    #[test]
    fn register_and_capabilities() {
        let mut registry = ProviderRegistry::new();
        register(&mut registry);
        assert!(registry.names().contains(&"volcengine"));
        let cred = Credential::Volcengine {
            access_key_id: AK.into(),
            secret_access_key: SK.into(),
            region: REGION.into(),
        };
        let p = registry.build("volcengine", &cred).unwrap();
        assert_eq!(p.name(), "volcengine");
        let caps = p.capabilities();
        assert!(caps.srv && caps.ns && caps.ttl && caps.rename);
    }

    /// 契约 8：域名不在账号下 → NotFound（resolve_zid 失败路径）。
    #[tokio::test]
    async fn unknown_domain_not_found() {
        let mock = MockServer::start().await;
        seed_zone(&mock, "other.com");
        let p = provider(&mock);
        let err = p
            .query_records("example.com", None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }
}
