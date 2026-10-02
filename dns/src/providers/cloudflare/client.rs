//! Cloudflare HTTP 客户端（M9-DNS002）
//!
//! - 端点：`{base}/zones`、`{base}/zones/{zid}/dns_records`（base 默认官方端点，
//!   测试可指向 127.0.0.1 mock，不强制 https）
//! - 认证：`Authorization: Bearer {API_TOKEN}`（凭据不参与日志/Display，Debug 脱敏）
//! - 30s 超时；User-Agent `KirinDesk/0.1.0`；429 + Retry-After（≤30s）退避重试一次
//! - 记录名互转：统一相对名 ↔ CF FQDN（根 "" → 域名）；SRV 的 service/proto 从相对名拆分
//! - 所有响应统一为 `serde_json::Value`，错误在 `error.rs` 归一化为 `ProviderError`
//!
//! 测试：`#[cfg(test)] pub(crate) mod mock` 提供自建 tokio mock HTTP 服务
//! （http://127.0.0.1 随机端口），供契约测试断言认证头/请求形状/错误码映射，
//! 不依赖 `crate::test_support`。

use crate::provider::{ProviderError, Record, RecordData, RecordType};
use reqwest::header::{AUTHORIZATION, RETRY_AFTER};
use reqwest::{Request, RequestBuilder, Response, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

/// 生产端点。
pub(crate) const DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
/// 请求超时（统一 30s）。
const TIMEOUT: Duration = Duration::from_secs(30);
/// 统一 User-Agent。
const USER_AGENT: &str = "KirinDesk/0.1.0";
/// 429 退避最大等待秒数（超过则直接返回 RateLimited）。
const MAX_BACKOFF_SECS: u64 = 30;

/// Cloudflare REST 客户端（持有 token，Debug 脱敏为 `<redacted>`）。
#[derive(Clone)]
pub(crate) struct CloudflareClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl std::fmt::Debug for CloudflareClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareClient")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl CloudflareClient {
    /// 构造客户端（token 不落日志）。
    pub(crate) fn new(token: impl Into<String>, base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .expect("构建 Cloudflare HTTP 客户端失败");
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
        }
    }

    /// 附加 Bearer 认证头。
    fn authorize(&self, req: RequestBuilder) -> RequestBuilder {
        req.header(AUTHORIZATION, format!("Bearer {}", self.token))
    }

    /// 统一发送：429 + Retry-After（≤30s）退避重试一次；其余直接返回。
    async fn send(&self, req: Request) -> Result<Value, ProviderError> {
        let mut last_retry_after: Option<u64> = None;
        for attempt in 0..2 {
            let resp = self.http.execute(req.try_clone().expect("请求应可克隆")).await?;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                let retry_after = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.trim().parse::<u64>().ok());
                last_retry_after = retry_after;
                if attempt == 0 && retry_after.map(|s| s <= MAX_BACKOFF_SECS).unwrap_or(false) {
                    tokio::time::sleep(Duration::from_secs(retry_after.unwrap_or(0))).await;
                    continue;
                }
                return Err(super::error::rate_limited(retry_after));
            }
            return Self::parse_response(resp).await;
        }
        Err(super::error::rate_limited(last_retry_after))
    }

    /// 状态 + body → 统一错误或 JSON。
    async fn parse_response(resp: Response) -> Result<Value, ProviderError> {
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(super::error::map_error(status, &text));
        }
        // Cloudflare 偶发 200 + success:false（业务错误）→ 同样归一化。
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            if v.get("success") == Some(&Value::Bool(false)) {
                return Err(super::error::map_error(status, &text));
            }
            return Ok(v);
        }
        Ok(Value::Null)
    }

    /// GET（带查询参数）。
    pub(crate) async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, ProviderError> {
        let url = format!("{}{}", self.base_url, path);
        let req = self.authorize(self.http.get(&url).query(query));
        self.send(req.build()?).await
    }

    /// POST JSON。
    pub(crate) async fn post(&self, path: &str, body: &Value) -> Result<Value, ProviderError> {
        let url = format!("{}{}", self.base_url, path);
        let req = self.authorize(self.http.post(&url).json(body));
        self.send(req.build()?).await
    }

    /// PATCH JSON。
    pub(crate) async fn patch(&self, path: &str, body: &Value) -> Result<Value, ProviderError> {
        let url = format!("{}{}", self.base_url, path);
        let req = self.authorize(self.http.patch(&url).json(body));
        self.send(req.build()?).await
    }

    /// DELETE。
    pub(crate) async fn delete(&self, path: &str) -> Result<Value, ProviderError> {
        let url = format!("{}{}", self.base_url, path);
        let req = self.authorize(self.http.delete(&url));
        self.send(req.build()?).await
    }

    /// 按域名查 zone_id（`GET /zones?name=...`；zone 缓存由 Provider 层负责）。
    pub(crate) async fn lookup_zone_id(&self, domain: &str) -> Result<String, ProviderError> {
        let v = self
            .get("/zones", &[("name", domain.to_string()), ("per_page", "50".to_string())])
            .await?;
        let zid = v
            .get("result")
            .and_then(|r| r.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|z| {
                        z.get("name")
                            .and_then(|n| n.as_str())
                            .map(|n| n.eq_ignore_ascii_case(domain))
                            .unwrap_or(false)
                    })
                    .and_then(|z| z.get("id").and_then(|i| i.as_str()))
            })
            .map(String::from);
        match zid {
            Some(id) => Ok(id),
            None => Err(ProviderError::NotFound {
                what: format!("域名/zone: {domain}"),
            }),
        }
    }

    /// 域名列表（`GET /zones?per_page=50&status=active`）。
    pub(crate) async fn list_zones(&self) -> Result<Vec<String>, ProviderError> {
        let v = self
            .get("/zones", &[("per_page", "50".to_string()), ("status", "active".to_string())])
            .await?;
        Ok(v.get("result")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|z| z.get("name").and_then(|n| n.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// 拉取 zone 下 dns_records（可选按 type/相对名过滤；分页遍历，上限 100 页防死循环）。
    pub(crate) async fn fetch_dns_records(
        &self,
        zid: &str,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Value>, ProviderError> {
        let mut all = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut query: Vec<(&str, String)> =
                vec![("per_page", "100".to_string()), ("page", page.to_string())];
            if let Some(t) = rtype {
                query.push(("type", t.as_str().to_string()));
            }
            if let Some(n) = name {
                query.push(("name", relative_to_fqdn(n, domain)));
            }
            let v = self.get(&format!("/zones/{zid}/dns_records"), &query).await?;
            if let Some(arr) = v.get("result").and_then(|r| r.as_array()) {
                all.extend(arr.iter().cloned());
            }
            let total_pages = v
                .pointer("/result_info/total_pages")
                .and_then(|p| p.as_u64())
                .unwrap_or(1) as u32;
            if page >= total_pages || page >= 100 {
                break;
            }
            page += 1;
        }
        Ok(all)
    }

    pub(crate) async fn create_record(&self, zid: &str, body: &Value) -> Result<Value, ProviderError> {
        self.post(&format!("/zones/{zid}/dns_records"), body).await
    }

    pub(crate) async fn update_record(&self, zid: &str, id: &str, body: &Value) -> Result<Value, ProviderError> {
        self.patch(&format!("/zones/{zid}/dns_records/{id}"), body).await
    }

    pub(crate) async fn delete_record(&self, zid: &str, id: &str) -> Result<Value, ProviderError> {
        self.delete(&format!("/zones/{zid}/dns_records/{id}")).await
    }
}

// ─────────────────────────── wire 格式互转 ───────────────────────────

/// 统一相对名 → CF FQDN（根 "" → 域名本身）。
pub(crate) fn relative_to_fqdn(name: &str, domain: &str) -> String {
    let domain = domain.trim_end_matches('.');
    if name.is_empty() {
        domain.to_string()
    } else {
        format!("{name}.{domain}")
    }
}

/// CF FQDN（或 `@`）→ 统一相对名（等于域名 → ""；不属于该域 → 原样返回防御）。
pub(crate) fn fqdn_to_relative(fqdn: &str, domain: &str) -> String {
    let fqdn = fqdn.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    if fqdn.is_empty() || fqdn == "@" || fqdn.eq_ignore_ascii_case(domain) {
        return String::new();
    }
    let suffix = format!(".{}", domain.to_ascii_lowercase());
    if let Some(prefix) = fqdn.to_ascii_lowercase().strip_suffix(&suffix) {
        // 按原大小写前缀截取（ASCII 小写不改变字节长度，切片安全）。
        fqdn[..prefix.len()].to_string()
    } else {
        fqdn.to_string()
    }
}

/// SRV 相对名拆解：`_remote._tcp.my-pc` → (`_remote`, `_tcp`, `my-pc`)；
/// `_remote._tcp` → (`_remote`, `_tcp`, "")。
pub(crate) fn split_srv_name(name: &str) -> (String, String, String) {
    let mut parts = name.split('.').filter(|p| !p.is_empty());
    let service = parts.next().unwrap_or("_srv").to_string();
    let proto = parts.next().unwrap_or("_tcp").to_string();
    let sub = parts.collect::<Vec<_>>().join(".");
    (service, proto, sub)
}

/// CF dns_record JSON → 统一 Record（未知类型返回 None 跳过）。
pub(crate) fn record_from_api(v: &Value, domain: &str) -> Option<Record> {
    let rtype: RecordType = v.get("type")?.as_str()?.parse().ok()?;
    let name = fqdn_to_relative(v.get("name")?.as_str()?, domain);
    let ttl = v.get("ttl").and_then(|t| t.as_u64()).unwrap_or(0) as u32;
    let data = data_from_api(v, rtype)?;
    Some(Record { name, rtype, ttl, data })
}

/// 按类型解析 content/data 为统一数据。
fn data_from_api(v: &Value, rtype: RecordType) -> Option<RecordData> {
    match rtype {
        RecordType::SRV => {
            // 优先结构化 data（service/proto/priority/weight/port/target）。
            if let Some(d) = v.get("data") {
                let priority = d.get("priority").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
                let weight = d.get("weight").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
                let port = d.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
                let target = d.get("target").and_then(|x| x.as_str()).unwrap_or("");
                if !target.is_empty() || d.get("priority").is_some() {
                    return Some(RecordData::Srv {
                        priority,
                        weight,
                        port,
                        target: target.to_string(),
                    });
                }
            }
            // 回退：content 为 "0 1 3389 tgt.example.com." 形态。
            parse_srv_content(v.get("content").and_then(|c| c.as_str()).unwrap_or(""))
        }
        RecordType::MX => {
            // CF MX content = "10 mail.example.com"（priority + 空格 + 主机）。
            let content = v.get("content").and_then(|c| c.as_str()).unwrap_or("");
            if let Some((p, host)) = content.split_once(' ') {
                Some(RecordData::Mx {
                    priority: p.trim().parse().unwrap_or(0),
                    exchange: host.trim().to_string(),
                })
            } else {
                Some(RecordData::Mx {
                    priority: 0,
                    exchange: content.trim().to_string(),
                })
            }
        }
        _ => Some(RecordData::Plain(
            v.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string(),
        )),
    }
}

/// "0 1 3389 tgt.example.com." → RecordData::Srv。
fn parse_srv_content(content: &str) -> Option<RecordData> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    Some(RecordData::Srv {
        priority: parts[0].parse().ok()?,
        weight: parts[1].parse().ok()?,
        port: parts[2].parse().ok()?,
        target: parts[3..].join(" "),
    })
}

/// 统一 Record → CF 创建 body（FQDN；SRV 结构化 data；MX content 拼接）。
pub(crate) fn record_to_create_body(rec: &Record, domain: &str) -> Value {
    let fqdn = relative_to_fqdn(&rec.name, domain);
    let ttl = if rec.ttl == 0 { 1 } else { rec.ttl }; // CF：1 = auto（有效区间 120–86400）
    match &rec.data {
        RecordData::Plain(s) => json!({ "type": rec.rtype.as_str(), "name": fqdn, "content": s, "ttl": ttl }),
        RecordData::Mx { priority, exchange } => json!({
            "type": "MX", "name": fqdn, "content": format!("{priority} {exchange}"), "ttl": ttl
        }),
        RecordData::Srv { priority, weight, port, target } => {
            let (service, proto, sub) = split_srv_name(&rec.name);
            json!({
                "type": "SRV", "name": fqdn, "ttl": ttl,
                "data": {
                    "service": service, "proto": proto, "name": sub,
                    "priority": priority, "weight": weight, "port": port, "target": target
                }
            })
        }
    }
}

/// 统一 Record → CF PATCH body（仅 content/data + ttl；type/name 不可改 → 省略，
/// 故不需 domain/FQDN）。
pub(crate) fn record_to_update_body(rec: &Record, _domain: &str) -> Value {
    let ttl = if rec.ttl == 0 { 1 } else { rec.ttl };
    let mut body = match &rec.data {
        RecordData::Plain(s) => json!({ "content": s }),
        RecordData::Mx { priority, exchange } => json!({ "content": format!("{priority} {exchange}") }),
        RecordData::Srv { priority, weight, port, target } => {
            let (service, proto, sub) = split_srv_name(&rec.name);
            json!({
                "data": {
                    "service": service, "proto": proto, "name": sub,
                    "priority": priority, "weight": weight, "port": port, "target": target
                }
            })
        }
    };
    body["ttl"] = json!(ttl);
    body
}

// ─────────────────────────── 契约测试 mock 服务 ───────────────────────────

#[cfg(test)]
pub(crate) mod mock {
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// 一次请求日志（认证头形状断言用）。
    #[derive(Debug, Clone)]
    pub(crate) struct RequestLog {
        pub method: String,
        /// 请求路径（含查询串，如 `/client/v4/zones?name=example.com&per_page=50`）。
        pub path: String,
        pub auth: Option<String>,
        pub body: String,
    }

    /// mock 状态（每个测试独立实例，互不共享）。
    #[derive(Default)]
    pub(crate) struct MockState {
        /// (zone_id, 域名) 列表。
        pub zones: Vec<(String, String)>,
        /// zone 内 dns_record（CF wire 形态，含 id/zone_id）。
        pub records: Vec<Value>,
        /// `GET /zones?name=...` 次数（zone_id 缓存断言）。
        pub zone_lookups: usize,
        /// 请求日志。
        pub requests: Vec<RequestLog>,
        /// 故障注入：路径含 key → 返回 status/body（错误码映射测试）。
        pub faults: Vec<(String, String, String)>,
        /// 自增记录 id。
        next_id: u64,
    }

    /// mock HTTP 服务句柄（127.0.0.1 随机端口；不强制 https）。
    #[derive(Clone)]
    pub(crate) struct MockServer {
        pub state: Arc<Mutex<MockState>>,
        addr: SocketAddr,
    }

    impl MockServer {
        pub(crate) async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定 mock 端口失败");
            let addr = listener.local_addr().expect("mock 地址");
            let state = Arc::new(Mutex::new(MockState::default()));
            let server_state = state.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(conn) => conn,
                        Err(_) => break,
                    };
                    let conn_state = server_state.clone();
                    tokio::spawn(async move {
                        let _ = handle_conn(stream, &conn_state).await;
                    });
                }
            });
            Self { state, addr }
        }

        pub(crate) fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        pub(crate) fn seed_zone(&self, id: &str, name: &str) {
            self.state
                .lock()
                .unwrap()
                .zones
                .push((id.to_string(), name.to_string()));
        }

        pub(crate) fn seed_record(&self, rec: Value) {
            self.state.lock().unwrap().records.push(rec);
        }

        /// 注入故障：路径含 key 即返回指定状态（错误码映射测试）。
        pub(crate) fn add_fault(&self, key: &str, status: &str, body: &str) {
            self.state
                .lock()
                .unwrap()
                .faults
                .push((key.to_string(), status.to_string(), body.to_string()));
        }

        pub(crate) fn requests(&self) -> Vec<RequestLog> {
            self.state.lock().unwrap().requests.clone()
        }

        pub(crate) fn zone_lookup_count(&self) -> usize {
            self.state.lock().unwrap().zone_lookups
        }

        pub(crate) fn records(&self) -> Vec<Value> {
            self.state.lock().unwrap().records.clone()
        }
    }

    /// 单连接：解析请求行/头/body → 路由 → 响应。
    async fn handle_conn(mut stream: TcpStream, state: &Arc<Mutex<MockState>>) -> std::io::Result<()> {
        let mut reader = BufReader::new(&mut stream);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).await? == 0 {
            return Ok(());
        }
        let mut auth: Option<String> = None;
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
                let key = k.trim();
                let val = v.trim();
                if key.eq_ignore_ascii_case("authorization") {
                    auth = Some(val.to_string());
                } else if key.eq_ignore_ascii_case("content-length") {
                    content_length = val.parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).await?;
        }
        let body = String::from_utf8_lossy(&body).to_string();

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();

        let (status_line, resp_body, extra) = {
            let mut st = state.lock().unwrap();
            st.requests.push(RequestLog {
                method: method.clone(),
                path: path.clone(),
                auth: auth.clone(),
                body: body.clone(),
            });
            route(&method, &path, &body, &mut st)
        };

        let mut raw = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            status_line,
            resp_body.len()
        );
        for (k, v) in extra {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str("Connection: close\r\n\r\n");
        raw.push_str(&resp_body);
        stream.write_all(raw.as_bytes()).await?;
        stream.flush().await
    }

    /// (状态行, body, 额外响应头)。
    fn route(method: &str, path: &str, body: &str, st: &mut MockState) -> (String, String, Vec<(String, String)>) {
        // 故障注入优先于路由。
        if let Some((_, status, fbody)) = st.faults.iter().find(|(key, _, _)| path.contains(key)) {
            return (format!("{status} Error"), fbody.clone(), Vec::new());
        }
        let (path_only, query) = path.split_once('?').unwrap_or((path, ""));
        let mut segs: Vec<&str> = path_only.split('/').filter(|s| !s.is_empty()).collect();
        // 剥离 base 路径前缀（/client/v4）。
        while !segs.is_empty() && (segs[0] == "client" || segs[0] == "v4") {
            segs.remove(0);
        }
        // /zones/{zid}/dns_records/{id}（PATCH/DELETE）
        if segs.len() == 4 && segs[0] == "zones" && segs[2] == "dns_records" {
            let id = segs[3];
            match method {
                "PATCH" => {
                    let patch: Value = serde_json::from_str(body).unwrap_or(Value::Null);
                    match st.records.iter_mut().find(|r| r["id"].as_str() == Some(id)) {
                        Some(rec) => {
                            if let Some(obj) = patch.as_object() {
                                for (k, v) in obj {
                                    rec[k] = v.clone();
                                }
                            }
                            (
                                String::from("200 OK"),
                                json!({ "success": true, "result": rec.clone() }).to_string(),
                                Vec::new(),
                            )
                        }
                        None => (
                            String::from("404 Not Found"),
                            json!({ "success": false, "errors": [{ "code": 1000, "message": "record not found" }] })
                                .to_string(),
                            Vec::new(),
                        ),
                    }
                }
                "DELETE" => {
                    let before = st.records.len();
                    st.records.retain(|r| r["id"].as_str() != Some(id));
                    if st.records.len() == before {
                        return (String::from("404 Not Found"), String::new(), Vec::new());
                    }
                    (String::from("200 OK"), json!({ "success": true, "result": {} }).to_string(), Vec::new())
                }
                _ => (String::from("405 Method Not Allowed"), String::new(), Vec::new()),
            }
        }
        // /zones/{zid}/dns_records（GET/POST）
        else if segs.len() == 3 && segs[0] == "zones" && segs[2] == "dns_records" {
            let zid = segs[1];
            let q: Vec<(String, String)> = query
                .split('&')
                .filter(|kv| !kv.is_empty())
                .filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
                .collect();
            match method {
                "GET" => {
                    let out: Vec<Value> = st
                        .records
                        .iter()
                        .filter(|r| r["zone_id"].as_str() == Some(zid))
                        .filter(|r| {
                            q.iter()
                                .find(|(k, _)| k == "type")
                                .map(|(_, v)| r["type"].as_str() == Some(v.as_str()))
                                .unwrap_or(true)
                        })
                        .filter(|r| {
                            q.iter()
                                .find(|(k, _)| k == "name")
                                .map(|(_, v)| r["name"].as_str() == Some(v.as_str()))
                                .unwrap_or(true)
                        })
                        .cloned()
                        .collect();
                    (
                        String::from("200 OK"),
                        json!({
                            "success": true,
                            "result": out,
                            "result_info": { "page": 1, "per_page": 100, "total_pages": 1 }
                        })
                        .to_string(),
                        Vec::new(),
                    )
                }
                "POST" => {
                    let mut rec: Value = serde_json::from_str(body).unwrap_or(Value::Null);
                    st.next_id += 1;
                    rec["id"] = json!(format!("rec-{}", st.next_id));
                    rec["zone_id"] = json!(zid);
                    st.records.push(rec.clone());
                    (String::from("201 Created"), json!({ "success": true, "result": rec }).to_string(), Vec::new())
                }
                _ => (String::from("405 Method Not Allowed"), String::new(), Vec::new()),
            }
        }
        // /zones（zone 查找 name=... 或域名列表）
        else if segs.len() == 1 && segs[0] == "zones" && method == "GET" {
            if query.split('&').any(|kv| kv.starts_with("name=")) {
                st.zone_lookups += 1;
                let name = query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("name="))
                    .unwrap_or("")
                    .to_string();
                let result: Vec<Value> = st
                    .zones
                    .iter()
                    .filter(|(_, n)| n == &name)
                    .map(|(id, n)| json!({ "id": id, "name": n }))
                    .collect();
                (String::from("200 OK"), json!({ "success": true, "result": result }).to_string(), Vec::new())
            } else {
                let result: Vec<Value> = st.zones.iter().map(|(id, n)| json!({ "id": id, "name": n })).collect();
                (String::from("200 OK"), json!({ "success": true, "result": result }).to_string(), Vec::new())
            }
        } else {
            (String::from("404 Not Found"), String::new(), Vec::new())
        }
    }
}
