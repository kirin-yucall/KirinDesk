//! Hetzner DNS HTTP 客户端（M9-DNS013）
//!
//! - 端点：`{base}/zones`、`{base}/zones/{zid}/records`、`{base}/records`
//!   （base 默认官方端点，测试可指向 127.0.0.1 mock）
//! - 认证：`Auth-API-Token: {TOKEN}`（Hetzner 专用头；凭据不参与日志/Display，Debug 脱敏）
//! - 30s 超时；User-Agent `KirinDesk/0.1.0`；429 + Retry-After（≤30s）退避重试一次
//! - 记录名：zone 内**相对名**（根 @/"" → ""；SRV 为 `_svc._tcp[.sub]` 形态）
//! - TXT：提交不带引号；回读时剥离可能存在的包裹引号（Hetzner 行为）
//! - 分页：`meta.pagination.next_page` 翻页遍历，上限 100 页防死循环
//! - 所有响应统一为 `serde_json::Value`，错误在 `error.rs` 归一化为 `ProviderError`
//!
//! 测试：`#[cfg(test)] pub(crate) mod mock` 提供自建 tokio mock HTTP 服务
//! （http://127.0.0.1 随机端口），不依赖 `crate::test_support`。

use crate::provider::{ProviderError, Record, RecordData, RecordType};
use reqwest::header::RETRY_AFTER;
use reqwest::{Request, RequestBuilder, Response, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

/// 生产端点。
pub(crate) const DEFAULT_BASE_URL: &str = "https://dns.hetzner.com/api/v1";
/// 认证头名（Hetzner 专用，非 Bearer）。
pub(crate) const AUTH_HEADER: &str = "Auth-API-Token";
/// 请求超时（统一 30s）。
const TIMEOUT: Duration = Duration::from_secs(30);
/// 统一 User-Agent。
const USER_AGENT: &str = "KirinDesk/0.1.0";
/// 429 退避最大等待秒数。
const MAX_BACKOFF_SECS: u64 = 30;
/// 分页跟随上限（防死循环）。
const MAX_PAGES: usize = 100;

/// Hetzner DNS REST 客户端（持有 token，Debug 脱敏）。
#[derive(Clone)]
pub(crate) struct HetznerClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl std::fmt::Debug for HetznerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HetznerClient")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl HetznerClient {
    /// 构造客户端（token 不落日志）。
    pub(crate) fn new(token: impl Into<String>, base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .expect("构建 Hetzner DNS HTTP 客户端失败");
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
        }
    }

    /// 附加 `Auth-API-Token` 认证头。
    fn authorize(&self, req: RequestBuilder) -> RequestBuilder {
        req.header(AUTH_HEADER, self.token.clone())
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

    /// PUT JSON。
    pub(crate) async fn put(&self, path: &str, body: &Value) -> Result<Value, ProviderError> {
        let url = format!("{}{}", self.base_url, path);
        let req = self.authorize(self.http.put(&url).json(body));
        self.send(req.build()?).await
    }

    /// DELETE。
    pub(crate) async fn delete(&self, path: &str) -> Result<Value, ProviderError> {
        let url = format!("{}{}", self.base_url, path);
        let req = self.authorize(self.http.delete(&url));
        self.send(req.build()?).await
    }

    /// zone 列表（`GET /zones?per_page=100`，分页遍历；可选 search_name 模糊搜索）。
    pub(crate) async fn fetch_zones(&self, search: Option<&str>) -> Result<Vec<Value>, ProviderError> {
        let mut base: Vec<(&str, String)> = vec![("per_page", "100".to_string())];
        if let Some(s) = search {
            base.push(("search_name", s.to_string()));
        }
        self.get_paged("/zones", base, "zones").await
    }

    /// 按域名查 zone_id：先 search_name 精确匹配，未中再全量列表兜底。
    pub(crate) async fn lookup_zone_id(&self, domain: &str) -> Result<String, ProviderError> {
        let searched = self.fetch_zones(Some(domain)).await?;
        if let Some(z) = searched.iter().find(|z| zone_name_matches(z, domain)) {
            return Ok(zid_of(z));
        }
        // search_name 为模糊匹配（可能返回空/不精确）→ 全量列表兜底。
        let all = self.fetch_zones(None).await?;
        match all.iter().find(|z| zone_name_matches(z, domain)) {
            Some(z) => Ok(zid_of(z)),
            None => Err(ProviderError::NotFound {
                what: format!("域名/zone: {domain}"),
            }),
        }
    }

    /// 拉取 zone 下全部记录（`GET /records?zone_id=...`，分页遍历）。
    pub(crate) async fn fetch_records(&self, zid: &str) -> Result<Vec<Value>, ProviderError> {
        self.get_paged(
            "/records",
            vec![("zone_id", zid.to_string()), ("per_page", "100".to_string())],
            "records",
        )
        .await
    }

    /// 通用分页遍历：`meta.pagination.next_page` 翻页，上限 100 页防死循环。
    async fn get_paged(
        &self,
        path: &str,
        base_query: Vec<(&str, String)>,
        list_key: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        for _ in 0..MAX_PAGES {
            let mut query = base_query.clone();
            query.push(("page", page.to_string()));
            let v = self.get(path, &query).await?;
            if let Some(arr) = v.get(list_key).and_then(|a| a.as_array()) {
                out.extend(arr.iter().cloned());
            }
            match v.pointer("/meta/pagination/next_page").and_then(|n| n.as_u64()) {
                Some(next) if next > 0 && next as u32 > page => page = next as u32,
                _ => break,
            }
        }
        Ok(out)
    }

    pub(crate) async fn create_record(&self, body: &Value) -> Result<Value, ProviderError> {
        self.post("/records", body).await
    }

    pub(crate) async fn update_record(&self, id: &str, body: &Value) -> Result<Value, ProviderError> {
        self.put(&format!("/records/{id}"), body).await
    }

    pub(crate) async fn delete_record(&self, id: &str) -> Result<Value, ProviderError> {
        self.delete(&format!("/records/{id}")).await
    }
}

// ─────────────────────────── wire 格式互转 ───────────────────────────

/// zone 对象名与目标域名精确匹配（大小写不敏感）。
fn zone_name_matches(z: &Value, domain: &str) -> bool {
    z.get("name")
        .and_then(|n| n.as_str())
        .map(|n| n.eq_ignore_ascii_case(domain))
        .unwrap_or(false)
}

/// 取 zone id（兜底空串，调用方保证存在）。
fn zid_of(z: &Value) -> String {
    z.get("id").and_then(|i| i.as_str()).unwrap_or_default().to_string()
}

/// Hetzner 记录名（`@`/"" 均为根）→ 统一相对名（""）。
pub(crate) fn normalize_name(name: &str) -> String {
    if name == "@" {
        String::new()
    } else {
        name.to_string()
    }
}

/// TXT 值剥离包裹引号（Hetzner 回读可能带引号；提交时不带引号）。
pub(crate) fn strip_txt_quotes(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

/// Hetzner record JSON → 统一 Record（未知类型返回 None 跳过）。
pub(crate) fn record_from_api(v: &Value) -> Option<Record> {
    let rtype: RecordType = v.get("type")?.as_str()?.parse().ok()?;
    let name = normalize_name(v.get("name").and_then(|n| n.as_str()).unwrap_or(""));
    let ttl = v.get("ttl").and_then(|t| t.as_u64()).unwrap_or(0) as u32;
    let value = v.get("value").and_then(|x| x.as_str()).unwrap_or("");
    let data = match rtype {
        RecordType::SRV => RecordData::Srv {
            priority: v.get("priority").and_then(|p| p.as_u64()).unwrap_or(0) as u16,
            weight: v.get("weight").and_then(|w| w.as_u64()).unwrap_or(0) as u16,
            port: v.get("port").and_then(|p| p.as_u64()).unwrap_or(0) as u16,
            target: value.to_string(),
        },
        RecordType::MX => {
            let priority = v.get("priority").and_then(|p| p.as_u64()).unwrap_or(0) as u16;
            // 防御：value 可能为 "10 mail.example.com" 拼接形态。
            if priority == 0 && value.contains(' ') {
                let mut it = value.splitn(2, ' ');
                let p = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
                let exchange = it.next().unwrap_or("").trim().to_string();
                RecordData::Mx { priority: p, exchange }
            } else {
                RecordData::Mx { priority, exchange: value.trim().to_string() }
            }
        }
        RecordType::TXT => RecordData::Plain(strip_txt_quotes(value)),
        _ => RecordData::Plain(value.to_string()),
    };
    Some(Record { name, rtype, ttl, data })
}

/// 统一 Record → Hetzner 请求 body（name 相对名；根 ""；TXT 不带引号；TTL 0 省略用 zone 默认）。
pub(crate) fn record_to_body(rec: &Record, zid: &str, include_zone_id: bool) -> Value {
    let mut body = json!({
        "name": rec.name,
        "type": rec.rtype.as_str(),
    });
    if include_zone_id {
        body["zone_id"] = json!(zid);
    }
    if rec.ttl != 0 {
        body["ttl"] = json!(rec.ttl);
    }
    match &rec.data {
        RecordData::Plain(s) => {
            body["value"] = json!(s);
        }
        RecordData::Mx { priority, exchange } => {
            body["value"] = json!(exchange);
            body["priority"] = json!(priority);
        }
        RecordData::Srv { priority, weight, port, target } => {
            body["value"] = json!(target);
            body["priority"] = json!(priority);
            body["weight"] = json!(weight);
            body["port"] = json!(port);
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
        /// (zone_id, 域名) 列表。
        pub zones: Vec<(String, String)>,
        /// record（wire 形态，含 id/zone_id）。
        pub records: Vec<Value>,
        /// `GET /zones?search_name=...` 次数（zone_id 缓存断言）。
        pub zone_lookups: usize,
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
            format!("http://{}/api/v1", self.addr)
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
                if key.eq_ignore_ascii_case("auth-api-token") {
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
        // 剥离 base 路径前缀（/api/v1）。
        while !segs.is_empty() && (segs[0] == "api" || segs[0] == "v1") {
            segs.remove(0);
        }
        let q: Vec<(String, String)> = query
            .split('&')
            .filter(|kv| !kv.is_empty())
            .filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .collect();
        // /records/{id}（PUT/DELETE）
        if segs.len() == 2 && segs[0] == "records" {
            let id = segs[1];
            match method {
                "PUT" => {
                    let patch: Value = serde_json::from_str(body).unwrap_or(Value::Null);
                    match st.records.iter_mut().find(|r| r["id"].as_str() == Some(id)) {
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
                            json!({ "error": { "code": "404", "message": "record not found" } }).to_string(),
                            Vec::new(),
                        ),
                    }
                }
                "DELETE" => {
                    let before = st.records.len();
                    st.records.retain(|r| r["id"].as_str() != Some(id));
                    if st.records.len() == before {
                        return (
                            String::from("404 Not Found"),
                            json!({ "error": { "code": "404", "message": "record not found" } }).to_string(),
                            Vec::new(),
                        );
                    }
                    (
                        String::from("200 OK"),
                        json!({ "record": { "id": id } }).to_string(),
                        Vec::new(),
                    )
                }
                _ => (String::from("405 Method Not Allowed"), String::new(), Vec::new()),
            }
        }
        // /records（GET/POST）
        else if segs.len() == 1 && segs[0] == "records" {
            match method {
                "GET" => {
                    let zid = q.iter().find(|(k, _)| k == "zone_id").map(|(_, v)| v.clone()).unwrap_or_default();
                    let out: Vec<Value> = st.records.iter().filter(|r| r["zone_id"].as_str() == Some(zid.as_str())).cloned().collect();
                    (
                        String::from("200 OK"),
                        json!({
                            "records": out,
                            "meta": { "pagination": { "page": 1, "per_page": 100, "previous_page": null, "next_page": null, "last_page": 1 } }
                        })
                        .to_string(),
                        Vec::new(),
                    )
                }
                "POST" => {
                    let mut rec: Value = serde_json::from_str(body).unwrap_or(Value::Null);
                    st.next_id += 1;
                    rec["id"] = json!(format!("rec-{}", st.next_id));
                    st.records.push(rec.clone());
                    (String::from("200 OK"), json!({ "record": rec }).to_string(), Vec::new())
                }
                _ => (String::from("405 Method Not Allowed"), String::new(), Vec::new()),
            }
        }
        // /zones（search_name 模糊搜索或列表）
        else if segs.len() == 1 && segs[0] == "zones" && method == "GET" {
            let zones: Vec<Value> = st.zones.iter().map(|(id, n)| json!({ "id": id, "name": n })).collect();
            let search = q.iter().find(|(k, _)| k == "search_name").map(|(_, v)| v.clone());
            if search.is_some() {
                st.zone_lookups += 1;
            }
            let filtered: Vec<Value> = match &search {
                Some(s) => zones
                    .into_iter()
                    .filter(|z| z["name"].as_str().map(|n| n.contains(s.as_str())).unwrap_or(false))
                    .collect(),
                None => zones,
            };
            (
                String::from("200 OK"),
                json!({
                    "zones": filtered,
                    "meta": { "pagination": { "page": 1, "per_page": 100, "previous_page": null, "next_page": null, "last_page": 1 } }
                })
                .to_string(),
                Vec::new(),
            )
        } else {
            (String::from("404 Not Found"), String::new(), Vec::new())
        }
    }
}
