//! Google Cloud DNS 服务商适配（M9-DNS007）
//!
//! - 认证：Service Account JWT（RS256，RFC 7523）→ OAuth2 access_token（见 `sign`）；
//! - 域名：`managedZones`（dnsName 去尾点）；
//! - 记录：`rrsets` 查询 + `changes` 事务写入（additions/deletions，原子变更）；
//! - 记录名 wire 格式：FQDN 带尾点（本模块负责相对名 ↔ FQDN 互转）；
//! - SRV/MX：rrdatas 单字符串 ↔ 类型化 `RecordData` 互转；
//! - 能力：全开（srv/ns/ttl/rename）。

pub mod client;
pub mod error;
pub mod sign;

use std::collections::HashMap;
use std::sync::Mutex;

use client::GoogleClient;
use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordData, RecordType,
};

/// Google DNS 服务商。
pub struct GoogleProvider {
    client: GoogleClient,
    /// domain → zone id 缓存（zone 解析一次，后续复用）。
    zone_ids: Mutex<HashMap<String, String>>,
}

impl GoogleProvider {
    pub fn new(service_account_json: String, project: String) -> Self {
        Self {
            client: GoogleClient::new(service_account_json, project),
            zone_ids: Mutex::new(HashMap::new()),
        }
    }

    /// 从统一凭据构建（注册表 factory 用）；凭据类型不符 → 首次调用即报错。
    pub fn from_credential(cred: &Credential) -> Self {
        match cred {
            Credential::Google { service_account_json, project } => {
                Self::new(service_account_json.clone(), project.clone())
            }
            _ => Self::from_error("凭据类型错误：期望 Credential::Google 变体"),
        }
    }

    fn from_error(detail: &str) -> Self {
        Self {
            client: GoogleClient::invalid(detail),
            zone_ids: Mutex::new(HashMap::new()),
        }
    }

    /// zone id 解析 + 缓存（GET managedZones?dnsName=...）。
    async fn zone_id(&self, domain: &str) -> Result<String, ProviderError> {
        if let Some(id) = self.zone_ids.lock().unwrap().get(domain) {
            return Ok(id.clone());
        }
        let id = self.client.get_zone_id(domain).await?;
        self.zone_ids.lock().unwrap().insert(domain.to_string(), id.clone());
        Ok(id)
    }
}

#[async_trait::async_trait]
impl Provider for GoogleProvider {
    fn name(&self) -> &'static str {
        "google"
    }

    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.list_zones().await.map(|_| ())
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let zones = self.client.list_zones().await?;
        let mut names: Vec<String> = zones
            .iter()
            .map(|z| z.dns_name.trim_end_matches('.').to_string())
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
        let rrsets = self.client.list_rrsets(&zone, fqdn.as_deref(), rtype).await?;
        let mut out = Vec::new();
        for rs in rrsets {
            // SOA/CAA 等未纳入统一模型类型 → 跳过
            let Ok(rt) = rs.rtype.parse::<RecordType>() else { continue };
            if rtype.is_some() && rtype != Some(rt) {
                continue; // 服务端已按 type 过滤，此处双保险（mock 亦不实现该过滤）
            }
            if let Some(n) = name {
                if from_fqdn(domain, &rs.name) != n {
                    continue; // 服务端已精确过滤，此处双保险
                }
            }
            let rel = from_fqdn(domain, &rs.name);
            for data in &rs.rrdatas {
                out.push(Record {
                    name: rel.clone(),
                    rtype: rt,
                    ttl: rs.ttl as u32,
                    data: parse_rrdata(rt, data),
                });
            }
        }
        Ok(out)
    }

    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let zone = self.zone_id(domain).await?;
        let fqdn = to_fqdn(domain, &rec.name);
        let rtype = rec.rtype.as_str().to_string();
        // 先查现有 rrset：changes 的 deletions 必须与现组精确匹配（name/type/ttl/rrdatas）
        let existing = self
            .client
            .list_rrsets(&zone, Some(&fqdn), Some(rec.rtype))
            .await?
            .into_iter()
            .find(|rs| rs.rtype == rtype && rs.name.eq_ignore_ascii_case(&fqdn));
        let old = existing.map(|rs| (rs.ttl, rs.rrdatas.clone()));
        // 目标集合：现组去掉被替换条目 + 新条目（同 name+rtype 其他条目保留）
        let mut target: Vec<RecordData> = match &old {
            Some((_, rds)) => rds
                .iter()
                .map(|s| parse_rrdata(rec.rtype, s))
                .filter(|v| v != &rec.data)
                .collect(),
            None => Vec::new(),
        };
        target.push(rec.data.clone());
        let ttl = if rec.ttl > 0 {
            rec.ttl as u64
        } else {
            old.as_ref().map(|(t, _)| *t).unwrap_or(client::DEFAULT_TTL)
        };
        // 幂等：目标与现组一致 → 不发变更
        let same = match &old {
            Some((ot, rds)) => {
                let cur: Vec<RecordData> = rds.iter().map(|s| parse_rrdata(rec.rtype, s)).collect();
                *ot == ttl && cur == target
            }
            None => false,
        };
        if same {
            return Ok(());
        }
        let additions = vec![client::Rrset {
            name: fqdn.clone(),
            rtype: rtype.clone(),
            ttl,
            rrdatas: target.iter().map(|d| rrdata_to_wire(rec.rtype, d)).collect(),
        }];
        let deletions: Vec<client::Rrset> = match &old {
            Some((t, rds)) => vec![client::Rrset {
                name: fqdn.clone(),
                rtype: rtype.clone(),
                ttl: *t,
                rrdatas: rds.clone(),
            }],
            None => Vec::new(),
        };
        self.client.create_change(&zone, &additions, &deletions).await
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
            .list_rrsets(&zone, Some(&fqdn), Some(rtype))
            .await?
            .into_iter()
            .find(|rs| rs.rtype == rtype.as_str() && rs.name.eq_ignore_ascii_case(&fqdn));
        match rs {
            // deletions 须与现存 rrset 精确匹配（M9-DNS007：delete 填当前 rrset）
            Some(rs) => self.client.create_change(&zone, &[], &[rs]).await,
            None => Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            }),
        }
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

/// 注册表注册（providers/mod.rs 集成者统一调用）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register("google", |cred| -> Box<dyn Provider> {
        Box::new(GoogleProvider::from_credential(cred))
    } as fn(&Credential) -> Box<dyn Provider>);
}

// ── 记录名转换（相对名 ↔ FQDN 尾点）与 RecordData 互转 ──────────────────────

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

/// rrdatas 单条字符串 → 类型化 `RecordData`（MX/SRV 解析；TXT 剥外层引号）。
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
                // 兜底：格式异常按 Plain 保留原文
                RecordData::Plain(strip_quotes(s).to_string())
            }
        }
        _ => RecordData::Plain(strip_quotes(s).to_string()),
    }
}

/// 类型化 `RecordData` → rrdatas 单条字符串（MX/SRV 目标补尾点）。
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

/// 剥 TXT 外层双引号（Google 对含空格的 TXT 值会加引号返回）。
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
    use super::sign::TEST_PRIVATE_KEY_PEM;
    use client::Rrset;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    // ── 契约测试 mock HTTP 服务（tokio 原生 TCP，参考 dns/src/test_support.rs 模式）──

    /// 捕获的一次请求（签名/表单/Body 断言用）。
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
        /// 状态化 rrsets（changes 提交会更新，支持幂等/删除用例）
        rrsets: Vec<Rrset>,
        /// 对 API 端点注入错误（令牌端点除外）
        fail: Option<(u16, String, Option<u64>)>,
    }

    struct MockServer {
        addr: SocketAddr,
        state: Arc<Mutex<MockState>>,
        requests: Arc<Mutex<Vec<Captured>>>,
        token_calls: Arc<AtomicUsize>,
        changes_calls: Arc<AtomicUsize>,
    }

    impl MockServer {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = Arc::new(Mutex::new(MockState::default()));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let token_calls = Arc::new(AtomicUsize::new(0));
            let changes_calls = Arc::new(AtomicUsize::new(0));
            let (st, rq, tk, ch) = (state.clone(), requests.clone(), token_calls.clone(), changes_calls.clone());
            tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let (st, rq, tk, ch) = (st.clone(), rq.clone(), tk.clone(), ch.clone());
                    tokio::spawn(async move {
                        let _ = handle_conn(stream, &st, &rq, &tk, &ch).await;
                    });
                }
            });
            Self { addr, state, requests, token_calls, changes_calls }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn token_uri(&self) -> String {
            format!("http://{}/token", self.addr)
        }

        fn requests(&self) -> Vec<Captured> {
            self.requests.lock().unwrap().clone()
        }

        fn token_calls(&self) -> usize {
            self.token_calls.load(Ordering::SeqCst)
        }

        fn changes_calls(&self) -> usize {
            self.changes_calls.load(Ordering::SeqCst)
        }

        fn set_zones(&self, zones: Vec<serde_json::Value>) {
            self.state.lock().unwrap().zones = zones;
        }

        fn set_rrsets(&self, rrsets: Vec<Rrset>) {
            self.state.lock().unwrap().rrsets = rrsets;
        }

        fn set_fail(&self, status: u16, body: &str) {
            self.state.lock().unwrap().fail = Some((status, body.to_string(), None));
        }
    }

    fn default_zone() -> serde_json::Value {
        serde_json::json!({ "id": "zone-1", "name": "zone-1", "dnsName": "example.com." })
    }

    fn rrset(name: &str, rtype: &str, ttl: u64, rrdatas: &[&str]) -> Rrset {
        Rrset {
            name: name.to_string(),
            rtype: rtype.to_string(),
            ttl,
            rrdatas: rrdatas.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 构造指向 mock 的 GoogleProvider（service_account_json 的 token_uri 指向 mock）。
    fn test_provider(server: &MockServer) -> GoogleProvider {
        let sa_json = serde_json::json!({
            "type": "service_account",
            "project_id": "my-project",
            "private_key_id": "k1",
            "private_key": TEST_PRIVATE_KEY_PEM,
            "client_email": "dns-test@my-project.iam.gserviceaccount.com",
            "token_uri": server.token_uri(),
        })
        .to_string();
        GoogleProvider {
            client: GoogleClient::with_base_url(sa_json, "my-project".to_string(), server.base_url()),
            zone_ids: Mutex::new(HashMap::new()),
        }
    }

    async fn handle_conn(
        stream: TcpStream,
        state: &Arc<Mutex<MockState>>,
        requests: &Arc<Mutex<Vec<Captured>>>,
        token_calls: &Arc<AtomicUsize>,
        changes_calls: &Arc<AtomicUsize>,
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
        let (status, resp_body, extra) = route(&method, &path, &body, state, token_calls, changes_calls);
        let mut raw = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\n");
        for (k, v) in extra {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp_body.len(),
            resp_body
        ));
        writer.write_all(raw.as_bytes()).await?;
        writer.flush().await
    }

    fn route(
        method: &str,
        path_with_query: &str,
        body: &str,
        state: &Arc<Mutex<MockState>>,
        token_calls: &Arc<AtomicUsize>,
        changes_calls: &Arc<AtomicUsize>,
    ) -> (String, String, Vec<(String, String)>) {
        let (path, _query) = path_with_query.split_once('?').unwrap_or((path_with_query, ""));
        // 令牌端点（POST .../token）
        if method == "POST" && path.ends_with("/token") {
            token_calls.fetch_add(1, Ordering::SeqCst);
            return (
                "200 OK".into(),
                r#"{"access_token":"mock-token","expires_in":3600,"token_type":"Bearer"}"#.into(),
                vec![],
            );
        }
        // 错误注入（错误码映射契约测试）
        if let Some((status, err_body, retry)) = &state.lock().unwrap().fail {
            let extra = retry.map(|r| vec![("Retry-After".to_string(), r.to_string())]).unwrap_or_default();
            return (format!("{status} Mock Error"), err_body.clone(), extra);
        }
        let mut state = state.lock().unwrap();
        if method == "GET" && path.ends_with("/managedZones") {
            let json = serde_json::json!({ "managedZones": state.zones, "nextPageToken": serde_json::Value::Null });
            return ("200 OK".into(), json.to_string(), vec![]);
        }
        if method == "GET" && path.contains("/rrsets") {
            let json = serde_json::json!({ "rrsets": state.rrsets, "nextPageToken": serde_json::Value::Null });
            return ("200 OK".into(), json.to_string(), vec![]);
        }
        if method == "POST" && path.contains("/changes") {
            changes_calls.fetch_add(1, Ordering::SeqCst);
            apply_changes(&mut state, body);
            return (
                "200 OK".into(),
                r#"{"status":"pending","additions":[],"deletions":[]}"#.into(),
                vec![],
            );
        }
        (
            "404 Not Found".into(),
            r#"{"error":{"code":404,"message":"mock 未知路由"}}"#.into(),
            vec![],
        )
    }

    /// changes 事务应用到内存存储：additions 同 name+type 替换；deletions 精确匹配移除。
    fn apply_changes(state: &mut MockState, body: &str) {
        let req: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::json!({}));
        for add in req["additions"].as_array().unwrap_or(&Vec::new()) {
            if let Ok(rs) = serde_json::from_value::<Rrset>(add.clone()) {
                if let Some(i) = state
                    .rrsets
                    .iter()
                    .position(|r| r.name.eq_ignore_ascii_case(&rs.name) && r.rtype == rs.rtype)
                {
                    state.rrsets[i] = rs;
                } else {
                    state.rrsets.push(rs);
                }
            }
        }
        for del in req["deletions"].as_array().unwrap_or(&Vec::new()) {
            if let Ok(rs) = serde_json::from_value::<Rrset>(del.clone()) {
                state.rrsets.retain(|r| {
                    !(r.name.eq_ignore_ascii_case(&rs.name)
                        && r.rtype == rs.rtype
                        && r.ttl == rs.ttl
                        && r.rrdatas == rs.rrdatas)
                });
            }
        }
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn changes_bodies(server: &MockServer) -> Vec<serde_json::Value> {
        server
            .requests()
            .iter()
            .filter(|r| r.method == "POST" && r.path.contains("/changes"))
            .map(|r| serde_json::from_str(&r.body).unwrap_or(serde_json::json!({})))
            .collect()
    }

    // ── FQDN ↔ 相对名 互转 ────────────────────────────────────────────────

    #[test]
    fn fqdn_conversion_roundtrip() {
        assert_eq!(to_fqdn("example.com", ""), "example.com.");
        assert_eq!(to_fqdn("example.com", "@"), "example.com.");
        assert_eq!(to_fqdn("example.com", "my-pc"), "my-pc.example.com.");
        assert_eq!(from_fqdn("example.com", "example.com."), "");
        assert_eq!(from_fqdn("example.com", "my-pc.example.com."), "my-pc");
        // 大小写不敏感 + 尾点宽容
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
            rrdata_to_wire(RecordType::SRV, &RecordData::Srv {
                priority: 0, weight: 1, port: 3389, target: "tgt".into(),
            }),
            "0 1 3389 tgt."
        );
        let mx = parse_rrdata(RecordType::MX, "10 mail.example.com.");
        assert_eq!(mx, RecordData::Mx { priority: 10, exchange: "mail.example.com.".into() });
        assert_eq!(
            rrdata_to_wire(RecordType::MX, &RecordData::Mx { priority: 10, exchange: "mail".into() }),
            "10 mail."
        );
        // TXT 剥外层引号
        assert_eq!(parse_rrdata(RecordType::TXT, "\"v1\""), RecordData::Plain("v1".into()));
    }

    // ── 令牌：form 请求形状 + Bearer 缓存复用 ───────────────────────────────

    #[tokio::test]
    async fn token_request_form_and_bearer_cache_reuse() {
        let server = MockServer::start().await;
        server.set_zones(vec![default_zone()]);
        let provider = test_provider(&server);
        // 两次 API 调用 → 只应触发一次令牌请求（缓存复用）
        let _ = provider.list_domains().await.unwrap();
        let _ = provider.list_domains().await.unwrap();
        assert_eq!(server.token_calls(), 1, "Bearer 缓存应复用，两次 API 只发一次 token 请求");
        let requests = server.requests();
        // 令牌请求：表单内容断言（grant_type=jwt-bearer + 三段 JWT assertion）
        let token_req = requests
            .iter()
            .find(|r| r.method == "POST" && r.path.ends_with("/token"))
            .expect("应存在 token 请求");
        assert!(token_req.body.starts_with(
            "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion="
        ));
        let assertion = token_req.body.split("assertion=").nth(1).unwrap();
        assert_eq!(assertion.split('.').count(), 3, "assertion 必须是三段 JWT");
        // API 请求携带 Bearer 头
        let api_req = requests
            .iter()
            .find(|r| r.path.contains("/managedZones") && !r.path.contains("/token"))
            .unwrap();
        assert_eq!(header(&api_req.headers, "authorization"), Some("Bearer mock-token"));
    }

    // ── list_domains 解析（dnsName 去尾点）──────────────────────────────────

    #[tokio::test]
    async fn list_domains_parses_dns_name_without_trailing_dot() {
        let server = MockServer::start().await;
        server.set_zones(vec![
            serde_json::json!({ "id": "1", "name": "z1", "dnsName": "example.com." }),
            serde_json::json!({ "id": "2", "name": "z2", "dnsName": "kirin.dev." }),
        ]);
        let provider = test_provider(&server);
        assert_eq!(provider.list_domains().await.unwrap(), vec!["example.com", "kirin.dev"]);
        // test_connection 走同一条最小查询路径
        provider.test_connection().await.unwrap();
    }

    // ── query_records：过滤参数 + zone 解析 + SRV/MX 多值往返 ───────────────

    #[tokio::test]
    async fn query_records_filters_and_parses_multivalue() {
        let server = MockServer::start().await;
        server.set_zones(vec![default_zone()]);
        server.set_rrsets(vec![
            rrset("my-pc.example.com.", "A", 600, &["203.0.113.7"]),
            rrset("my-pc.example.com.", "TXT", 600, &["v1", "v2"]),
            rrset("_remote._tcp.my-pc.example.com.", "SRV", 600, &["0 1 3389 my-pc.example.com."]),
            rrset("my-pc.example.com.", "MX", 600, &["10 mail.example.com."]),
        ]);
        let provider = test_provider(&server);
        // 全部（无过滤）：A + TXT×2 + SRV + MX = 5 条
        let all = provider.query_records("example.com", None, None).await.unwrap();
        assert_eq!(all.len(), 5);
        // name + rtype 过滤：断言请求路径/查询参数形状
        let found = provider
            .query_records("example.com", Some("my-pc"), Some(RecordType::TXT))
            .await
            .unwrap();
        assert_eq!(found.len(), 2, "TXT 多值 → 多条 Record");
        assert!(matches!(&found[0].data, RecordData::Plain(d) if d == "v1" || d == "v2"));
        let requests = server.requests();
        // 取带过滤参数的那次 rrsets 请求（首个为全量查询，无 name/type）
        let req = requests
            .iter()
            .find(|r| r.path.contains("/rrsets") && r.path.contains("type=TXT"))
            .unwrap();
        assert!(req.path.contains("/managedZones/zone-1/rrsets"), "zone 解析后用 id 拼路径");
        assert!(req.path.contains("name=my-pc.example.com."), "name 参数为 FQDN 尾点");
        assert!(req.path.contains("type=TXT"));
        // SRV 结构化解析
        let srv = provider
            .query_records("example.com", Some("_remote._tcp.my-pc"), Some(RecordType::SRV))
            .await
            .unwrap();
        assert_eq!(srv.len(), 1);
        match &srv[0].data {
            RecordData::Srv { priority, weight, port, target } => {
                assert_eq!((*priority, *weight, *port), (0, 1, 3389));
                assert_eq!(target, "my-pc.example.com.");
            }
            other => panic!("期望 Srv，得到 {other:?}"),
        }
        // MX 结构化解析
        let mx = provider
            .query_records("example.com", Some("my-pc"), Some(RecordType::MX))
            .await
            .unwrap();
        assert_eq!(mx[0].data, RecordData::Mx { priority: 10, exchange: "mail.example.com.".into() });
    }

    // ── upsert：changes 事务 additions/deletions 形状 + 幂等 ─────────────────

    #[tokio::test]
    async fn upsert_builds_changes_transaction() {
        let server = MockServer::start().await;
        server.set_zones(vec![default_zone()]);
        let provider = test_provider(&server);
        // 1) 新增：additions 含目标集，deletions 为空
        provider
            .upsert_record(
                "example.com",
                &Record { name: "my-pc".into(), rtype: RecordType::A, ttl: 600, data: RecordData::Plain("203.0.113.7".into()) },
            )
            .await
            .unwrap();
        let bodies = changes_bodies(&server);
        assert_eq!(bodies.len(), 1);
        let add0 = &bodies[0]["additions"][0];
        assert_eq!(add0["name"], "my-pc.example.com.");
        assert_eq!(add0["type"], "A");
        assert_eq!(add0["ttl"], 600);
        assert_eq!(add0["rrdatas"], serde_json::json!(["203.0.113.7"]));
        assert_eq!(bodies[0]["deletions"], serde_json::json!([]));
        // 2) 幂等：目标与现组一致 → 不再发 changes
        provider
            .upsert_record(
                "example.com",
                &Record { name: "my-pc".into(), rtype: RecordType::A, ttl: 600, data: RecordData::Plain("203.0.113.7".into()) },
            )
            .await
            .unwrap();
        assert_eq!(server.changes_calls(), 1, "幂等 upsert 不应再发事务");
        // 3) 追加第二值（同 name+type 其他条目保留）：deletions=现组，additions=新旧全集
        provider
            .upsert_record(
                "example.com",
                &Record { name: "my-pc".into(), rtype: RecordType::A, ttl: 600, data: RecordData::Plain("198.51.100.9".into()) },
            )
            .await
            .unwrap();
        let bodies = changes_bodies(&server);
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[1]["additions"][0]["rrdatas"], serde_json::json!(["203.0.113.7", "198.51.100.9"]));
        assert_eq!(bodies[1]["deletions"][0]["rrdatas"], serde_json::json!(["203.0.113.7"]));
        assert_eq!(bodies[1]["deletions"][0]["ttl"], 600);
        // 4) 修改 TTL：deletions=现组（旧 ttl），additions=同值新 ttl
        provider
            .upsert_record(
                "example.com",
                &Record { name: "my-pc".into(), rtype: RecordType::A, ttl: 300, data: RecordData::Plain("203.0.113.7".into()) },
            )
            .await
            .unwrap();
        let bodies = changes_bodies(&server);
        let last = bodies.last().unwrap();
        assert_eq!(last["deletions"][0]["ttl"], 600, "deletions 精确匹配现组 ttl");
        assert_eq!(last["additions"][0]["ttl"], 300);
    }

    // ── delete：deletions 精确匹配；不存在 → NotFound ───────────────────────

    #[tokio::test]
    async fn delete_uses_exact_rrset_and_missing_is_not_found() {
        let server = MockServer::start().await;
        server.set_zones(vec![default_zone()]);
        server.set_rrsets(vec![rrset("my-pc.example.com.", "A", 600, &["203.0.113.7"])]);
        let provider = test_provider(&server);
        provider.delete_record("example.com", "my-pc", RecordType::A).await.unwrap();
        let bodies = changes_bodies(&server);
        assert_eq!(bodies.len(), 1);
        let del0 = &bodies[0]["deletions"][0];
        assert_eq!(del0["name"], "my-pc.example.com.");
        assert_eq!(del0["type"], "A");
        assert_eq!(del0["ttl"], 600);
        assert_eq!(del0["rrdatas"], serde_json::json!(["203.0.113.7"]));
        assert_eq!(bodies[0]["additions"], serde_json::json!([]));
        // 已删除 → 再删 NotFound
        let err = provider.delete_record("example.com", "my-pc", RecordType::A).await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }

    // ── 错误码映射（Auth/InvalidParameter/NotFound/RateLimited/Server）──────

    #[tokio::test]
    async fn error_status_mapping() {
        let cases: Vec<(u16, &str)> = vec![
            (401, r#"{"error":{"code":401,"message":"invalid_grant"}}"#),
            (403, r#"{"error":{"code":403,"message":"PermissionDenied"}}"#),
            (400, r#"{"error":{"code":400,"message":"invalidParameter"}}"#),
            (404, r#"{"error":{"code":404,"message":"notFound"}}"#),
            (429, r#"{"error":{"code":429,"message":"rateLimitExceeded"}}"#),
            (500, r#"{"error":{"code":500,"message":"internal error"}}"#),
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
