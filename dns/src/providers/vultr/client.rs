//! Vultr HTTP 客户端（M9-DNS011）
//!
//! - 端点：`{base}/domains/{d}/records`（base 默认官方端点，测试可指向 127.0.0.1 mock）
//! - 认证：`Authorization: Bearer {TOKEN}`（凭据不参与日志/Display，Debug 脱敏）
//! - 30s 超时；User-Agent `KirinDesk/0.1.0`；429 + Retry-After（≤30s）退避重试一次
//! - 记录名：**相对名直传**（sub 字段，空串 = 根；SRV 为 `_svc._tcp[.sub]` 形态）
//! - SRV data：单字符串 `"priority weight port target"`（空格分隔）
//! - 分页：`meta.links.next`（绝对 URL）跟随遍历，上限 100 页防死循环
//! - 所有响应统一为 `serde_json::Value`，错误在 `error.rs` 归一化为 `ProviderError`
//!
//! 测试：`#[cfg(test)] pub(crate) mod mock` 提供自建 tokio mock HTTP 服务
//! （http://127.0.0.1 随机端口），不依赖 `crate::test_support`。

use crate::provider::{ProviderError, Record, RecordData, RecordType};
use reqwest::header::{AUTHORIZATION, RETRY_AFTER};
use reqwest::{Request, RequestBuilder, Response, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

/// 生产端点。
pub(crate) const DEFAULT_BASE_URL: &str = "https://api.vultr.com/v2";
/// 请求超时（统一 30s）。
const TIMEOUT: Duration = Duration::from_secs(30);
/// 统一 User-Agent。
const USER_AGENT: &str = "KirinDesk/0.1.0";
/// 429 退避最大等待秒数。
const MAX_BACKOFF_SECS: u64 = 30;
/// 分页跟随上限（防死循环）。
const MAX_PAGES: usize = 100;

/// Vultr REST 客户端（持有 token，Debug 脱敏）。
#[derive(Clone)]
pub(crate) struct VultrClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl std::fmt::Debug for VultrClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VultrClient")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl VultrClient {
    /// 构造客户端（token 不落日志）。
    pub(crate) fn new(token: impl Into<String>, base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .expect("构建 Vultr HTTP 客户端失败");
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

    /// 状态 + body → 统一错误或 JSON（204 空 body → Value::Null）。
    async fn parse_response(resp: Response) -> Result<Value, ProviderError> {
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(super::error::map_error(status, &text));
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(ProviderError::Json)
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

    /// GET 绝对 URL（分页 next 链接跟随）。
    async fn get_absolute(&self, url: &str) -> Result<Value, ProviderError> {
        let req = self.authorize(self.http.get(url));
        self.send(req.build()?).await
    }

    /// 域名列表（`GET /domains?per_page=500`，跟随 `meta.links.next`）。
    pub(crate) async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let items = self.get_paged("/domains", &[("per_page", "500".to_string())], "domains").await?;
        Ok(items
            .iter()
            .filter_map(|d| d.get("domain").and_then(|n| n.as_str()).map(String::from))
            .collect())
    }

    /// 拉取域名全部记录（分页遍历；name/type 过滤由 Provider 层做）。
    pub(crate) async fn fetch_records(&self, domain: &str) -> Result<Vec<Value>, ProviderError> {
        self.get_paged(&format!("/domains/{domain}/records"), &[("per_page", "500".to_string())], "records")
            .await
    }

    /// 通用分页遍历：首请求用 path+query，随后跟随 `meta.links.next`。
    async fn get_paged(
        &self,
        path: &str,
        query: &[(&str, String)],
        list_key: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let v = match &next {
                Some(url) => self.get_absolute(url).await?,
                None => self.get(path, query).await?,
            };
            if let Some(arr) = v.get(list_key).and_then(|a| a.as_array()) {
                out.extend(arr.iter().cloned());
            }
            next = v.pointer("/meta/links/next").and_then(|n| n.as_str()).map(String::from);
            if next.is_none() {
                break;
            }
        }
        Ok(out)
    }

    pub(crate) async fn create_record(&self, domain: &str, body: &Value) -> Result<Value, ProviderError> {
        self.post(&format!("/domains/{domain}/records"), body).await
    }

    pub(crate) async fn update_record(&self, domain: &str, id: &str, body: &Value) -> Result<Value, ProviderError> {
        self.patch(&format!("/domains/{domain}/records/{id}"), body).await
    }

    pub(crate) async fn delete_record(&self, domain: &str, id: &str) -> Result<Value, ProviderError> {
        self.delete(&format!("/domains/{domain}/records/{id}")).await
    }
}

// ─────────────────────────── wire 格式互转 ───────────────────────────

/// Vultr 记录名与统一相对名一致（空串 = 根），仅做防御性归一化（`@` → ""）。
pub(crate) fn normalize_name(name: &str) -> String {
    if name == "@" {
        String::new()
    } else {
        name.to_string()
    }
}

/// Vultr record JSON → 统一 Record（未知类型返回 None 跳过）。
pub(crate) fn record_from_api(v: &Value) -> Option<Record> {
    let rtype: RecordType = v.get("type")?.as_str()?.parse().ok()?;
    let name = normalize_name(v.get("name").and_then(|n| n.as_str()).unwrap_or(""));
    let ttl = v.get("ttl").and_then(|t| t.as_u64()).unwrap_or(0) as u32;
    let data = match rtype {
        RecordType::SRV => {
            // Vultr SRV data 为单字符串 "priority weight port target"。
            let parts: Vec<&str> = v.get("data").and_then(|d| d.as_str()).unwrap_or("").split_whitespace().collect();
            if parts.len() < 4 {
                return None;
            }
            RecordData::Srv {
                priority: parts[0].parse().ok()?,
                weight: parts[1].parse().ok()?,
                port: parts[2].parse().ok()?,
                target: parts[3..].join(" "),
            }
        }
        RecordType::MX => {
            let host = v.get("data").and_then(|d| d.as_str()).unwrap_or("").trim().to_string();
            let priority = v.get("priority").and_then(|p| p.as_u64()).unwrap_or(0) as u16;
            // 防御：data 可能为 "10 mail.example.com" 拼接形态。
            if priority == 0 && host.contains(' ') {
                let mut it = host.splitn(2, ' ');
                let p = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
                let exchange = it.next().unwrap_or("").trim().to_string();
                RecordData::Mx { priority: p, exchange }
            } else {
                RecordData::Mx { priority, exchange: host }
            }
        }
        _ => RecordData::Plain(v.get("data").and_then(|d| d.as_str()).unwrap_or("").to_string()),
    };
    Some(Record { name, rtype, ttl, data })
}

/// 统一 Record → Vultr 请求 body（name 相对名直传；TTL 0 省略用默认；SRV data 单字符串）。
pub(crate) fn record_to_body(rec: &Record, include_type: bool) -> Value {
    let mut body = json!({
        "name": rec.name,
    });
    if include_type {
        body["type"] = json!(rec.rtype.as_str());
    }
    if rec.ttl != 0 {
        body["ttl"] = json!(rec.ttl);
    }
    match &rec.data {
        RecordData::Plain(s) => {
            body["data"] = json!(s);
        }
        RecordData::Mx { priority, exchange } => {
            body["data"] = json!(exchange);
            body["priority"] = json!(priority);
        }
        RecordData::Srv { priority, weight, port, target } => {
            // Vultr SRV 无独立字段，data 为 "priority weight port target" 空格串。
            body["data"] = json!(format!("{priority} {weight} {port} {target}"));
        }
    }
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
        pub path: String,
        pub auth: Option<String>,
        pub body: String,
    }

    /// mock 状态（每个测试独立实例）。
    #[derive(Default)]
    pub(crate) struct MockState {
        pub domains: Vec<String>,
        /// record（wire 形态，含 id/domain）。
        pub records: Vec<Value>,
        pub requests: Vec<RequestLog>,
        pub faults: Vec<(String, String, String)>,
        next_id: u64,
    }

    /// mock HTTP 服务句柄（127.0.0.1 随机端口）。
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
            format!("http://{}/v2", self.addr)
        }

        pub(crate) fn seed_domain(&self, name: &str) {
            self.state.lock().unwrap().domains.push(name.to_string());
        }

        pub(crate) fn seed_record(&self, domain: &str, rec: Value) {
            let mut rec = rec;
            rec["domain"] = json!(domain);
            self.state.lock().unwrap().records.push(rec);
        }

        /// 注入故障：路径含 key 即返回指定状态。
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
        let (path_only, _query) = path.split_once('?').unwrap_or((path, ""));
        let mut segs: Vec<&str> = path_only.split('/').filter(|s| !s.is_empty()).collect();
        // 剥离 base 路径前缀（/v2）。
        while !segs.is_empty() && segs[0] == "v2" {
            segs.remove(0);
        }
        // /domains/{d}/records/{id}（PATCH/DELETE）
        if segs.len() == 4 && segs[0] == "domains" && segs[2] == "records" {
            let d = segs[1];
            let id = segs[3];
            match method {
                "PATCH" => {
                    let patch: Value = serde_json::from_str(body).unwrap_or(Value::Null);
                    match st.records.iter_mut().find(|r| r["domain"].as_str() == Some(d) && r["id"].as_str() == Some(id)) {
                        Some(rec) => {
                            if let Some(obj) = patch.as_object() {
                                for (k, v) in obj {
                                    rec[k] = v.clone();
                                }
                            }
                            (String::from("200 OK"), json!({ "record": rec.clone() }).to_string(), Vec::new())
                        }
                        None => (
                            String::from("404 Not Found"),
                            json!({ "error": "not_found" }).to_string(),
                            Vec::new(),
                        ),
                    }
                }
                "DELETE" => {
                    let before = st.records.len();
                    st.records.retain(|r| !(r["domain"].as_str() == Some(d) && r["id"].as_str() == Some(id)));
                    if st.records.len() == before {
                        return (
                            String::from("404 Not Found"),
                            json!({ "error": "not_found" }).to_string(),
                            Vec::new(),
                        );
                    }
                    (String::from("204 No Content"), String::new(), Vec::new())
                }
                _ => (String::from("405 Method Not Allowed"), String::new(), Vec::new()),
            }
        }
        // /domains/{d}/records（GET/POST）
        else if segs.len() == 3 && segs[0] == "domains" && segs[2] == "records" {
            let d = segs[1];
            match method {
                "GET" => {
                    let out: Vec<Value> = st.records.iter().filter(|r| r["domain"].as_str() == Some(d)).cloned().collect();
                    let total = out.len();
                    (
                        String::from("200 OK"),
                        json!({ "records": out, "meta": { "total": total, "links": { "next": null } } }).to_string(),
                        Vec::new(),
                    )
                }
                "POST" => {
                    let mut rec: Value = serde_json::from_str(body).unwrap_or(Value::Null);
                    st.next_id += 1;
                    rec["id"] = json!(format!("rec-{}", st.next_id));
                    rec["domain"] = json!(d);
                    st.records.push(rec.clone());
                    (String::from("200 OK"), json!({ "record": rec }).to_string(), Vec::new())
                }
                _ => (String::from("405 Method Not Allowed"), String::new(), Vec::new()),
            }
        }
        // /domains（GET 域名列表）
        else if segs.len() == 1 && segs[0] == "domains" && method == "GET" {
            let domains: Vec<Value> = st.domains.iter().map(|d| json!({ "domain": d })).collect();
            (
                String::from("200 OK"),
                json!({ "domains": domains, "meta": { "total": domains.len(), "links": { "next": null } } }).to_string(),
                Vec::new(),
            )
        } else {
            (String::from("404 Not Found"), String::new(), Vec::new())
        }
    }
}
