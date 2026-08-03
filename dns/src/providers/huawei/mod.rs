//! 华为云 DNS 服务商适配（M9-DNS008）
//!
//! - 认证：AK/SK SDK-HMAC-SHA256 签名（见 `sign`；头 `X-Sdk-Date` + `Authorization`）；
//! - 域名：`GET /v2/zones`（name 去尾点）；
//! - 记录：记录集 CRUD —— `GET /v2/zones/{zid}/recordsets` 查询（分页 marker）、
//!   `POST` 创建 / `PUT` 更新（先查后写，存在则 PUT，不存在则 POST）、`DELETE` 删除；
//! - 记录名 wire 格式：FQDN 带尾点（官方 API 定义，WebSearch 复核；本模块负责
//!   相对名 ↔ FQDN 互转，`@` 根 ↔ 域名 FQDN）；
//! - SRV/MX：`records[]` 单字符串 ↔ 类型化 `RecordData` 互转；
//! - 能力：全开（srv/ns/ttl/rename）。

pub mod client;
pub mod error;
pub mod sign;

use std::collections::HashMap;
use std::sync::Mutex;

use client::HuaweiClient;
use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordData, RecordType,
};

/// 华为云 DNS 服务商。
pub struct HuaweiProvider {
    client: HuaweiClient,
    /// domain → zone id 缓存（zone 解析一次，后续复用）。
    zone_ids: Mutex<HashMap<String, String>>,
    /// 构造期失败（注册表 factory 收到非 Huawei 凭据）：首个调用即返回该错误。
    invalid: Option<String>,
}

impl HuaweiProvider {
    pub fn new(access_key: String, secret_key: String, region: String) -> Self {
        Self {
            client: HuaweiClient::new(access_key, secret_key, region),
            zone_ids: Mutex::new(HashMap::new()),
            invalid: None,
        }
    }

    /// 从统一凭据构建（注册表 factory 用）；凭据类型不符 → 首次调用即报错。
    pub fn from_credential(cred: &Credential) -> Self {
        match cred {
            Credential::Huawei { access_key, secret_key, region } => {
                Self::new(access_key.clone(), secret_key.clone(), region.clone())
            }
            _ => Self::from_error("凭据类型错误：期望 Credential::Huawei 变体"),
        }
    }

    fn from_error(detail: &str) -> Self {
        Self {
            client: HuaweiClient::with_base_url(
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
            zone_ids: Mutex::new(HashMap::new()),
            // 错误信息挂到 zone 缓存键 ""（首个调用即返回）
            invalid: Some(detail.to_string()),
        }
    }
}

#[async_trait::async_trait]
impl Provider for HuaweiProvider {
    fn name(&self) -> &'static str {
        "huawei"
    }

    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.list_domains().await.map(|_| ())
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.ensure_valid()?;
        let zones = self.client.list_zones().await?;
        let mut names: Vec<String> = zones
            .iter()
            .map(|z| z.name.trim_end_matches('.').to_string())
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let zone = self.zone_id(domain).await?;
        let fqdn = name.map(|n| to_fqdn(domain, n));
        let recordsets = self.client.list_recordsets(&zone, fqdn.as_deref(), rtype).await?;
        let mut out = Vec::new();
        for rs in recordsets {
            // SOA/CAA 等未纳入统一模型类型 → 跳过
            let Ok(rt) = rs.rtype.parse::<RecordType>() else { continue };
            if rtype.is_some() && rtype != Some(rt) {
                continue; // 服务端已按 type 过滤，此处双保险（mock 亦不实现该过滤）
            }
            if let Some(n) = name {
                if from_fqdn(domain, &rs.name) != n {
                    continue; // 服务端为模糊搜索，此处精确过滤
                }
            }
            let rel = from_fqdn(domain, &rs.name);
            for data in &rs.records {
                out.push(Record {
                    name: rel.clone(),
                    rtype: rt,
                    ttl: rs.ttl.unwrap_or(0),
                    data: parse_rrdata(rt, data),
                });
            }
        }
        Ok(out)
    }

    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let zone = self.zone_id(domain).await?;
        let fqdn = to_fqdn(domain, &rec.name);
        let rtype = rec.rtype.as_str();
        // 先查现组（name+type）→ 存在 PUT 更新 / 不存在 POST 创建（幂等）
        let existing = self
            .client
            .list_recordsets(&zone, Some(&fqdn), Some(rec.rtype))
            .await?
            .into_iter()
            .find(|rs| rs.rtype == rtype && rs.name.eq_ignore_ascii_case(&fqdn));
        // 目标 records 数组：现组去掉被替换值 + 新值（同 name+type 其他值保留）
        let mut target: Vec<String> = match &existing {
            Some(rs) => rs
                .records
                .iter()
                .map(|s| parse_rrdata(rec.rtype, s))
                .filter(|v| v != &rec.data)
                .map(|v| rrdata_to_wire(rec.rtype, &v))
                .collect(),
            None => Vec::new(),
        };
        target.push(rrdata_to_wire(rec.rtype, &rec.data));
        let ttl = if rec.ttl > 0 {
            Some(rec.ttl)
        } else {
            existing.as_ref().and_then(|rs| rs.ttl).or(Some(300))
        };
        let body = client::RecordsetIn {
            name: fqdn.clone(),
            rtype: rtype.to_string(),
            ttl,
            records: target,
        };
        match &existing {
            // 幂等：与现有完全一致 → 不发请求
            Some(rs) => {
                if rs.records == body.records && rs.ttl == body.ttl {
                    return Ok(());
                }
                self.client.update_recordset(&zone, &rs.id, &body).await.map(|_| ())
            }
            None => self.client.create_recordset(&zone, &body).await.map(|_| ()),
        }
    }

    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let zone = self.zone_id(domain).await?;
        let fqdn = to_fqdn(domain, name);
        let rs = self
            .client
            .list_recordsets(&zone, Some(&fqdn), Some(rtype))
            .await?
            .into_iter()
            .find(|rs| rs.rtype == rtype.as_str() && rs.name.eq_ignore_ascii_case(&fqdn));
        match rs {
            Some(rs) => self.client.delete_recordset(&zone, &rs.id).await,
            None => Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            }),
        }
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

impl HuaweiProvider {
    /// 构造期失败（凭据类型不符）延迟上报。
    fn ensure_valid(&self) -> Result<(), ProviderError> {
        if let Some(detail) = &self.invalid {
            return Err(ProviderError::Other(detail.clone()));
        }
        Ok(())
    }

    /// zone id 解析 + 缓存（GET /v2/zones?name={fqdn}）。
    async fn zone_id(&self, domain: &str) -> Result<String, ProviderError> {
        self.ensure_valid()?;
        if let Some(id) = self.zone_ids.lock().unwrap().get(domain) {
            return Ok(id.clone());
        }
        let id = self.client.get_zone_id(domain).await?;
        self.zone_ids.lock().unwrap().insert(domain.to_string(), id.clone());
        Ok(id)
    }
}

/// 注册表注册（providers/mod.rs 集成者统一调用）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register("huawei", |cred| -> Box<dyn Provider> {
        Box::new(HuaweiProvider::from_credential(cred))
    } as fn(&Credential) -> Box<dyn Provider>);
}

// ── 记录名转换（相对名 ↔ FQDN 尾点，@ 根）与 RecordData 互转 ──────────────

/// 相对名 → FQDN（带尾点）：`""`/`"@"`（根）→ `"{domain}."`，`"my-pc"` → `"my-pc.{domain}."`。
pub(crate) fn to_fqdn(domain: &str, name: &str) -> String {
    let domain = domain.trim_end_matches('.');
    if name.is_empty() || name == "@" {
        format!("{domain}.")
    } else {
        format!("{name}.{domain}.")
    }
}

/// FQDN（带尾点）→ 相对名：根返回 `""`；不在该域名下 → 原样返回（无尾点）。
pub(crate) fn from_fqdn(domain: &str, fqdn: &str) -> String {
    let f = fqdn.trim_end_matches('.').to_ascii_lowercase();
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if f == d {
        return String::new();
    }
    match f.strip_suffix(&format!(".{d}")) {
        Some(rest) if !rest.is_empty() => rest.to_string(),
        _ => f,
    }
}

/// `records[]` 单条字符串 → 类型化 `RecordData`（MX/SRV 解析；TXT 剥外层引号）。
pub(crate) fn parse_rrdata(rtype: RecordType, s: &str) -> RecordData {
    let s = s.trim();
    match rtype {
        RecordType::MX => {
            let mut it = s.splitn(2, char::is_whitespace);
            let priority = it.next().and_then(|p| p.parse().ok()).unwrap_or(10);
            let exchange = it.next().unwrap_or("").trim().to_string();
            RecordData::Mx { priority, exchange }
        }
        RecordType::SRV => {
            let parts: Vec<&str> = s.split_whitespace().collect();
            if parts.len() >= 4 {
                RecordData::Srv {
                    priority: parts[0].parse().unwrap_or(0),
                    weight: parts[1].parse().unwrap_or(0),
                    port: parts[2].parse().unwrap_or(0),
                    target: parts[3].to_string(),
                }
            } else {
                RecordData::Plain(strip_quotes(s).to_string())
            }
        }
        _ => RecordData::Plain(strip_quotes(s).to_string()),
    }
}

/// 类型化 `RecordData` → `records[]` 单条字符串（MX/SRV 目标补尾点）。
pub(crate) fn rrdata_to_wire(_rtype: RecordType, data: &RecordData) -> String {
    match data {
        RecordData::Plain(v) => v.clone(),
        RecordData::Mx { priority, exchange } => {
            let ex = with_trailing_dot(exchange);
            format!("{priority} {ex}")
        }
        RecordData::Srv { priority, weight, port, target } => {
            let t = with_trailing_dot(target);
            format!("{priority} {weight} {port} {t}")
        }
    }
}

fn with_trailing_dot(s: &str) -> String {
    if s.ends_with('.') { s.to_string() } else { format!("{s}.") }
}

/// 剥 TXT 外层双引号。
fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    // ── 契约测试 mock HTTP 服务（tokio 原生 TCP，参考 dns/src/test_support.rs 模式）──

    /// 捕获的一次请求（签名重算断言用）。
    #[derive(Debug, Clone)]
    struct Captured {
        method: String,
        path: String, // 含查询串
        body: String,
        headers: Vec<(String, String)>, // 头名小写
    }

    #[derive(Default)]
    struct MockState {
        zones: Vec<serde_json::Value>,
        /// 状态化记录集（含 zone_id 字段；CRUD 更新）
        recordsets: Vec<serde_json::Value>,
        /// 对全部端点注入错误
        fail: Option<(u16, String)>,
    }

    struct MockServer {
        addr: SocketAddr,
        state: Arc<Mutex<MockState>>,
        requests: Arc<Mutex<Vec<Captured>>>,
    }

    impl MockServer {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = Arc::new(Mutex::new(MockState::default()));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let (st, rq) = (state.clone(), requests.clone());
            tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let (st, rq) = (st.clone(), rq.clone());
                    tokio::spawn(async move {
                        let _ = handle_conn(stream, &st, &rq).await;
                    });
                }
            });
            Self { addr, state, requests }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn requests(&self) -> Vec<Captured> {
            self.requests.lock().unwrap().clone()
        }

        fn set_zones(&self, zones: Vec<serde_json::Value>) {
            self.state.lock().unwrap().zones = zones;
        }

        fn set_fail(&self, status: u16, body: &str) {
            self.state.lock().unwrap().fail = Some((status, body.to_string()));
        }
    }

    fn default_zone() -> serde_json::Value {
        serde_json::json!({ "id": "z1", "name": "example.com." })
    }

    /// 构造指向 mock 的 HuaweiProvider。
    fn test_provider(server: &MockServer) -> HuaweiProvider {
        let client =
            HuaweiClient::with_base_url("AK".into(), "SK".into(), "cn-north-4".into(), server.base_url());
        HuaweiProvider { client, zone_ids: Mutex::new(HashMap::new()), invalid: None }
    }

    async fn handle_conn(
        stream: TcpStream,
        state: &Arc<Mutex<MockState>>,
        requests: &Arc<Mutex<Vec<Captured>>>,
    ) -> std::io::Result<()> {
        let (read_half, mut writer) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).await? == 0 {
            return Ok(());
        }
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
                let k = k.trim().to_ascii_lowercase();
                headers.push((k.clone(), v.trim().to_string()));
                if k == "content-length" {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            let _ = reader.read_exact(&mut body).await;
        }
        let body = String::from_utf8_lossy(&body).to_string();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        requests.lock().unwrap().push(Captured {
            method: method.clone(),
            path: path.clone(),
            body: body.clone(),
            headers: headers.clone(),
        });
        let (status, resp_body) = route(&method, &path, &body, state);
        let raw = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        writer.write_all(raw.as_bytes()).await?;
        writer.flush().await
    }

    fn parse_query(qs: &str) -> Vec<(&str, String)> {
        if qs.is_empty() {
            return Vec::new();
        }
        qs.split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                (k, v.to_string())
            })
            .collect()
    }

    fn route(
        method: &str,
        path_with_query: &str,
        body: &str,
        state: &Arc<Mutex<MockState>>,
    ) -> (String, String) {
        let (path, qs) = path_with_query.split_once('?').unwrap_or((path_with_query, ""));
        if let Some((status, err_body)) = &state.lock().unwrap().fail {
            return (format!("{status} Mock Error"), err_body.clone());
        }
        let mut state = state.lock().unwrap();
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        // GET /v2/zones（?name= 过滤；?limit= 分页——mock 单页返回全部）
        if method == "GET" && segs == ["v2", "zones"] {
            let query = parse_query(qs);
            let name_filter = query.iter().find(|(k, _)| *k == "name").map(|(_, v)| v.to_ascii_lowercase());
            let zones: Vec<serde_json::Value> = state
                .zones
                .iter()
                .filter(|z| {
                    name_filter.as_ref().map_or(true, |n| {
                        z["name"].as_str().unwrap_or("").to_ascii_lowercase() == *n
                    })
                })
                .cloned()
                .collect();
            return (
                "200 OK".into(),
                serde_json::json!({ "zones": zones, "metadata": { "total_count": zones.len() } }).to_string(),
            );
        }
        // GET /v2/zones/{zid}/recordsets
        if method == "GET" && segs.len() == 4 && segs[0] == "v2" && segs[1] == "zones" && segs[3] == "recordsets" {
            let zid = segs[2];
            let rs: Vec<serde_json::Value> = state
                .recordsets
                .iter()
                .filter(|r| r["zone_id"].as_str() == Some(zid))
                .cloned()
                .collect();
            return (
                "200 OK".into(),
                serde_json::json!({ "recordsets": rs, "metadata": { "total_count": rs.len() } }).to_string(),
            );
        }
        // POST /v2/zones/{zid}/recordsets —— 创建（分配 id，202）
        if method == "POST" && segs.len() == 4 && segs[3] == "recordsets" {
            let mut v: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::json!({}));
            let id = format!("rs{}", state.recordsets.len() + 1);
            v["id"] = serde_json::json!(id);
            v["zone_id"] = serde_json::json!(segs[2]);
            state.recordsets.push(v.clone());
            return ("202 Accepted".into(), v.to_string());
        }
        // PUT /v2/zones/{zid}/recordsets/{rid} —— 更新
        if method == "PUT" && segs.len() == 5 && segs[3] == "recordsets" {
            let rid = segs[4];
            let mut updated = None;
            for r in state.recordsets.iter_mut() {
                if r["id"].as_str() == Some(rid) {
                    let mut v: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::json!({}));
                    v["id"] = serde_json::json!(rid);
                    v["zone_id"] = r["zone_id"].clone();
                    *r = v.clone();
                    updated = Some(v);
                }
            }
            return match updated {
                Some(v) => ("202 Accepted".into(), v.to_string()),
                None => not_found(),
            };
        }
        // DELETE /v2/zones/{zid}/recordsets/{rid} —— 删除
        if method == "DELETE" && segs.len() == 5 && segs[3] == "recordsets" {
            let rid = segs[4];
            let before = state.recordsets.len();
            state.recordsets.retain(|r| r["id"].as_str() != Some(rid));
            if state.recordsets.len() < before {
                return ("202 Accepted".into(), serde_json::json!({ "id": rid }).to_string());
            }
            return not_found();
        }
        not_found()
    }

    fn not_found() -> (String, String) {
        (
            "404 Not Found".into(),
            r#"{"error_msg":"The requested resource could not be found.","error_code":"DNS.0101"}"#.into(),
        )
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// 从捕获请求重算 Authorization 头（独立于客户端管线，验证签名一致）。
    fn recompute_authorization(cap: &Captured, ak: &str, sk: &str) -> String {
        let (path, qs) = cap.path.split_once('?').unwrap_or((cap.path.as_str(), ""));
        let host = header(&cap.headers, "host").unwrap().to_string();
        let date = header(&cap.headers, "x-sdk-date").unwrap().to_string();
        let body = cap.body.clone();
        // 先收集为自有 String，最后统一转 &str，避免借用局部临时值
        let mut owned: Vec<(String, String)> = vec![
            ("host".to_string(), host.clone()),
            ("x-sdk-date".to_string(), date.clone()),
        ];
        if !body.is_empty() {
            let ct = header(&cap.headers, "content-type").unwrap().to_string();
            owned.push(("content-type".to_string(), ct));
        }
        let hdrs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let q = parse_query(qs);
        sign::authorization(ak, sk, cap.method.as_str(), path, &q, &hdrs, body.as_bytes(), &date)
    }

    fn signature_of(auth: &str) -> &str {
        auth.rsplit("Signature=").next().unwrap()
    }

    // ── FQDN ↔ 相对名（@ 根）互转 ─────────────────────────────────────────

    #[test]
    fn fqdn_conversion_roundtrip() {
        assert_eq!(to_fqdn("example.com", ""), "example.com.");
        assert_eq!(to_fqdn("example.com", "@"), "example.com.");
        assert_eq!(to_fqdn("example.com", "my-pc"), "my-pc.example.com.");
        assert_eq!(from_fqdn("example.com", "example.com."), "");
        assert_eq!(from_fqdn("example.com", "my-pc.example.com."), "my-pc");
        assert_eq!(from_fqdn("Example.COM", "My-PC.example.com."), "my-pc");
        assert_eq!(from_fqdn("example.com", "other.org."), "other.org");
    }

    #[test]
    fn rrdata_srv_mx_roundtrip() {
        let srv = parse_rrdata(RecordType::SRV, "0 1 3389 my-pc.example.com.");
        assert_eq!(
            srv,
            RecordData::Srv { priority: 0, weight: 1, port: 3389, target: "my-pc.example.com.".into() }
        );
        assert_eq!(
            rrdata_to_wire(RecordType::SRV, &RecordData::Srv { priority: 0, weight: 1, port: 3389, target: "tgt".into() }),
            "0 1 3389 tgt."
        );
        assert_eq!(
            parse_rrdata(RecordType::MX, "10 mail.example.com."),
            RecordData::Mx { priority: 10, exchange: "mail.example.com.".into() }
        );
    }

    // ── 签名头：形状 + 从捕获请求独立重算一致 ───────────────────────────────

    #[tokio::test]
    async fn authorization_header_shape_and_recompute_for_get() {
        let server = MockServer::start().await;
        server.set_zones(vec![default_zone()]);
        let provider = test_provider(&server);
        provider.list_domains().await.unwrap();
        let req = server.requests().first().unwrap().clone();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/v2/zones?limit=500");
        // X-Sdk-Date：UTC ISO8601 基本格式
        let date = header(&req.headers, "x-sdk-date").unwrap().to_string();
        assert!(
            date.len() == 16 && date.ends_with('Z') && date.as_bytes()[8] == b'T',
            "X-Sdk-Date 应为 YYYYMMDDTHHMMSSZ: {date}"
        );
        // Authorization 头形状
        let auth = header(&req.headers, "authorization").unwrap().to_string();
        assert_eq!(
            auth,
            format!("SDK-HMAC-SHA256 Access=AK, SignedHeaders=host;x-sdk-date, Signature={}",
                signature_of(&auth)),
            "GET 无 body：SignedHeaders 应仅含 host;x-sdk-date"
        );
        assert_eq!(signature_of(&auth).len(), 64);
        // 独立重算 → 一致（含规范 URI 尾部 "/"、空 body 哈希）
        let recomputed = recompute_authorization(&req, "AK", "SK");
        assert_eq!(recomputed, auth, "签名必须可由捕获请求独立重算");
    }

    #[tokio::test]
    async fn authorization_header_shape_and_recompute_for_post() {
        let server = MockServer::start().await;
        server.set_zones(vec![default_zone()]);
        let provider = test_provider(&server);
        provider
            .upsert_record(
                "example.com",
                &Record { name: "my-pc".into(), rtype: RecordType::A, ttl: 600, data: RecordData::Plain("203.0.113.7".into()) },
            )
            .await
            .unwrap();
        let req = server.requests().iter().find(|r| r.method == "POST").unwrap().clone();
        let auth = header(&req.headers, "authorization").unwrap().to_string();
        assert!(
            auth.starts_with("SDK-HMAC-SHA256 Access=AK, SignedHeaders=content-type;host;x-sdk-date, Signature="),
            "POST 带 body：SignedHeaders 应含 content-type: {auth}"
        );
        assert_eq!(header(&req.headers, "content-type"), Some("application/json"));
        // body 哈希参与签名 → 独立重算一致
        let recomputed = recompute_authorization(&req, "AK", "SK");
        assert_eq!(recomputed, auth);
    }

    // ── list_domains 解析 + zone 解析 ──────────────────────────────────────

    #[tokio::test]
    async fn list_domains_parses_zones_without_trailing_dot() {
        let server = MockServer::start().await;
        server.set_zones(vec![
            serde_json::json!({ "id": "z1", "name": "example.com." }),
            serde_json::json!({ "id": "z2", "name": "kirin.dev." }),
        ]);
        let provider = test_provider(&server);
        assert_eq!(provider.list_domains().await.unwrap(), vec!["example.com", "kirin.dev"]);
        provider.test_connection().await.unwrap();
    }

    // ── query_records：zone 解析路径 + SRV/MX 多值往返 ──────────────────────

    #[tokio::test]
    async fn query_records_parses_multivalue_and_uses_zone_id() {
        let server = MockServer::start().await;
        server.set_zones(vec![default_zone()]);
        server.state.lock().unwrap().recordsets = vec![
            serde_json::json!({ "id": "rs1", "name": "my-pc.example.com.", "type": "A", "ttl": 600, "records": ["203.0.113.7"], "zone_id": "z1" }),
            serde_json::json!({ "id": "rs2", "name": "my-pc.example.com.", "type": "TXT", "ttl": 600, "records": ["v1", "v2"], "zone_id": "z1" }),
            serde_json::json!({ "id": "rs3", "name": "_remote._tcp.my-pc.example.com.", "type": "SRV", "ttl": 600, "records": ["0 1 3389 my-pc.example.com."], "zone_id": "z1" }),
            serde_json::json!({ "id": "rs4", "name": "my-pc.example.com.", "type": "MX", "ttl": 600, "records": ["10 mail.example.com."], "zone_id": "z1" }),
        ];
        let provider = test_provider(&server);
        let all = provider.query_records("example.com", None, None).await.unwrap();
        assert_eq!(all.len(), 5, "A + TXT×2 + SRV + MX");
        // 过滤参数形状（name=FQDN 尾点 + type）
        let found = provider
            .query_records("example.com", Some("my-pc"), Some(RecordType::TXT))
            .await
            .unwrap();
        assert_eq!(found.len(), 2, "records 数组多值 → 多条 Record");
        // zone 解析用 id 拼记录集路径（取带过滤参数的那次请求，首个为全量查询）
        let requests = server.requests();
        let get = requests
            .iter()
            .find(|r| r.path.contains("/recordsets") && r.path.contains("type=TXT"))
            .unwrap();
        assert!(get.path.contains("/v2/zones/z1/recordsets"), "路径应为 zone id: {}", get.path);
        assert!(get.path.contains("name=my-pc.example.com."));
        assert!(get.path.contains("type=TXT"));
        // SRV 结构化
        let srv = provider
            .query_records("example.com", Some("_remote._tcp.my-pc"), Some(RecordType::SRV))
            .await
            .unwrap();
        assert_eq!(
            srv[0].data,
            RecordData::Srv { priority: 0, weight: 1, port: 3389, target: "my-pc.example.com.".into() }
        );
        // MX 结构化
        let mx = provider
            .query_records("example.com", Some("my-pc"), Some(RecordType::MX))
            .await
            .unwrap();
        assert_eq!(mx[0].data, RecordData::Mx { priority: 10, exchange: "mail.example.com.".into() });
    }

    // ── upsert：不存在 POST 创建 / 存在 PUT 更新 / 幂等 ─────────────────────

    #[tokio::test]
    async fn upsert_create_then_update_idempotent() {
        let server = MockServer::start().await;
        server.set_zones(vec![default_zone()]);
        let provider = test_provider(&server);
        let a1 = Record { name: "my-pc".into(), rtype: RecordType::A, ttl: 600, data: RecordData::Plain("203.0.113.7".into()) };
        // 1) 不存在 → POST 创建
        provider.upsert_record("example.com", &a1).await.unwrap();
        let requests = server.requests();
        let post = requests.iter().find(|r| r.method == "POST").unwrap();
        let body: serde_json::Value = serde_json::from_str(&post.body).unwrap();
        assert_eq!(body["name"], "my-pc.example.com.");
        assert_eq!(body["type"], "A");
        assert_eq!(body["ttl"], 600);
        assert_eq!(body["records"], serde_json::json!(["203.0.113.7"]));
        // 2) 幂等：同值再 upsert → 不发请求
        provider.upsert_record("example.com", &a1).await.unwrap();
        assert_eq!(
            server.requests().iter().filter(|r| r.method == "POST" || r.method == "PUT").count(),
            1,
            "幂等 upsert 不应再发请求"
        );
        // 3) 追加第二值 → PUT 更新（其他值保留）
        provider
            .upsert_record(
                "example.com",
                &Record { name: "my-pc".into(), rtype: RecordType::A, ttl: 600, data: RecordData::Plain("198.51.100.9".into()) },
            )
            .await
            .unwrap();
        let requests = server.requests();
        let put = requests.iter().find(|r| r.method == "PUT").unwrap();
        assert!(put.path.contains("/v2/zones/z1/recordsets/rs1"), "PUT 应带记录集 id: {}", put.path);
        let body: serde_json::Value = serde_json::from_str(&put.body).unwrap();
        assert_eq!(body["records"], serde_json::json!(["203.0.113.7", "198.51.100.9"]));
        // 4) 查询可见两条
        let found = provider
            .query_records("example.com", Some("my-pc"), Some(RecordType::A))
            .await
            .unwrap();
        assert_eq!(found.len(), 2);
    }

    // ── delete：按 id 删除；不存在 → NotFound ──────────────────────────────

    #[tokio::test]
    async fn delete_recordset_and_missing_is_not_found() {
        let server = MockServer::start().await;
        server.set_zones(vec![default_zone()]);
        server.state.lock().unwrap().recordsets = vec![
            serde_json::json!({ "id": "rs1", "name": "my-pc.example.com.", "type": "A", "ttl": 600, "records": ["203.0.113.7"], "zone_id": "z1" }),
        ];
        let provider = test_provider(&server);
        provider.delete_record("example.com", "my-pc", RecordType::A).await.unwrap();
        let requests = server.requests();
        let del = requests.iter().find(|r| r.method == "DELETE").unwrap();
        assert_eq!(del.path, "/v2/zones/z1/recordsets/rs1");
        // 已删除 → 再删 NotFound
        let err = provider.delete_record("example.com", "my-pc", RecordType::A).await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }

    // ── 错误码映射（Auth/InvalidParameter/NotFound/RateLimited/Server）──────

    #[tokio::test]
    async fn error_status_mapping() {
        let cases: Vec<(u16, &str)> = vec![
            (401, r#"{"error_msg":"鉴权失败","error_code":"APIGW.0301"}"#),
            (403, r#"{"error_msg":"无权限","error_code":"DNS.0001"}"#),
            (400, r#"{"error_msg":"参数错误","error_code":"DNS.0104"}"#),
            (404, r#"{"error_msg":"not found","error_code":"DNS.0101"}"#),
            (429, r#"{"error_msg":"请求超限","error_code":"APIGW.0308"}"#),
            (500, r#"{"error_msg":"internal","error_code":"DNS.9999"}"#),
        ];
        for (status, body) in cases {
            let server = MockServer::start().await;
            server.set_fail(status, body);
            let provider = test_provider(&server);
            let err = provider.list_domains().await.unwrap_err();
            match status {
                401 | 403 => assert!(matches!(err, ProviderError::Auth { .. }), "{status} 应为 Auth"),
                400 => assert!(matches!(err, ProviderError::InvalidParameter { .. }), "{status} 应为 InvalidParameter"),
                404 => assert!(matches!(err, ProviderError::NotFound { .. }), "{status} 应为 NotFound"),
                429 => assert!(matches!(err, ProviderError::RateLimited { .. }), "{status} 应为 RateLimited"),
                _ => assert!(matches!(err, ProviderError::Server { .. }), "{status} 应为 Server"),
            }
        }
    }
}
