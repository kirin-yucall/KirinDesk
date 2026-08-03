//! Azure DNS 服务商适配（M9-DNS006）
//!
//! - 认证：OAuth2 客户端凭据（[`token`]），Bearer 头 + 401 强制刷新重试一次
//! - 序列化：JSON（serde_json，[`record`] 记录集模型互转）
//! - 错误：ARM `{error:{code,message}}` → 统一 [`ProviderError`]（[`error`]）
//! - 记录语义：记录集 **PUT 整组替换** → upsert 先查后写（原记录保留 + 本条更新）；
//!   根记录集名 `"@"` ↔ 统一模型 `""`
//! - 查询：recordsets 全量列表（分页跟随 nextLink）
//!
//! 注册：`register()` 以键名 `"azure"` 注册到 [`ProviderRegistry`]。
//! 能力：全开（SRV/NS/TTL/rename 均支持）。

pub mod client;
pub mod error;
pub mod record;
pub mod token;

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordType,
};
use client::AzureClient;

/// 服务商注册（由 `providers::register_all` 集成时调用）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register("azure", |cred| -> Box<dyn Provider> {
        Box::new(AzureProvider::new(cred))
    });
}

/// Azure Provider：包装 [`AzureClient`] 并实现统一契约语义。
#[derive(Clone)]
pub struct AzureProvider {
    client: AzureClient,
}

impl AzureProvider {
    /// 按凭据构造（生产端点）。
    pub fn new(cred: &Credential) -> Self {
        Self {
            client: AzureClient::new(cred),
        }
    }

    /// 测试用：注入自定义端点的客户端。
    // R-33: 仅测试模块调用（mock 端点注入）——保留接口并标注，避免 dead_code。
    #[allow(dead_code)]
    pub(crate) fn with_client(client: AzureClient) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Provider for AzureProvider {
    fn name(&self) -> &'static str {
        "azure"
    }

    /// 最小查询：dnsZones 列表（同时校验权限）。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.list_dns_zones().await.map(|_| ())
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.client.list_dns_zones().await
    }

    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let items = self.client.list_record_sets(domain).await?;
        let mut out = Vec::new();
        for item in items {
            for r in record::parse_record_set(&item) {
                if let Some(n) = name {
                    if r.name != n {
                        continue;
                    }
                }
                if let Some(t) = rtype {
                    if r.rtype != t {
                        continue;
                    }
                }
                out.push(r);
            }
        }
        Ok(out)
    }

    /// 记录集语义 upsert：先查（GET 现有记录集）→ 合并（原记录保留 + 本条更新）→
    /// PUT 整组替换（TTL 取本条，缺省沿用现有/默认 600）。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let az_name = AzureClient::azure_name(&rec.name);
        let rtype_str = rec.rtype.as_str();
        let existing = self.client.get_record_set(domain, rtype_str, &az_name).await?;
        let mut recs: Vec<Record> = match &existing {
            Some(item) => record::parse_record_set(item),
            None => Vec::new(),
        };
        let ttl = if rec.ttl != 0 {
            rec.ttl
        } else {
            recs.first().map(|r| r.ttl).unwrap_or(0)
        };
        let ttl = if ttl == 0 { record::DEFAULT_TTL } else { ttl };
        // 合并：同 data → 更新 TTL/数据；否则追加。
        if let Some(existing_rec) = recs.iter_mut().find(|r| r.data == rec.data) {
            existing_rec.ttl = ttl;
            existing_rec.data = rec.data.clone();
        } else {
            recs.push(Record {
                name: rec.name.clone(),
                rtype: rec.rtype,
                ttl,
                data: rec.data.clone(),
            });
        }
        let props = record::records_to_properties(&recs, ttl);
        self.client
            .put_record_set(domain, rtype_str, &az_name, &props)
            .await
    }

    /// delete：DELETE 整个记录集（404 → NotFound，统一语义）。
    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let az_name = AzureClient::azure_name(name);
        self.client
            .delete_record_set(domain, rtype.as_str(), &az_name)
            .await
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

#[cfg(test)]
mod tests {
    //! 契约测试：tokio mock HTTP server（127.0.0.1，参考 `dns/src/test_support.rs`
    //! MockDns 模式），断言 Bearer 头 + token 缓存/刷新、PUT 先查后写、DELETE、
    //! 错误映射、SRV/MX/TXT 结构化往返。

    use super::*;
    use crate::provider::RecordData;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    // ─────────────────────────────────────────────
    // mock HTTP server
    // ─────────────────────────────────────────────

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl RecordedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    #[derive(Default)]
    struct MockState {
        requests: Vec<RecordedRequest>,
        token_posts: usize,
        zones: Vec<String>,
        /// (zone, TYPE, azure_name) → properties。
        record_sets: HashMap<(String, String, String), serde_json::Value>,
        /// 一次性错误响应 (status, body, retry-after)。
        fail: Option<(u16, String, Option<String>)>,
    }

    #[derive(Clone)]
    struct MockAzure {
        addr: SocketAddr,
        state: Arc<Mutex<MockState>>,
    }

    impl MockAzure {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
            let addr = listener.local_addr().expect("mock addr");
            let state = Arc::new(Mutex::new(MockState::default()));
            let server_state = state.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let conn = server_state.clone();
                    tokio::spawn(async move {
                        let _ = handle_conn(stream, &conn).await;
                    });
                }
            });
            Self { addr, state }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn token_url(&self) -> String {
            format!("http://{}/tenant-1/oauth2/v2.0/token", self.addr)
        }

        fn set_zones(&self, zones: &[&str]) {
            self.state.lock().unwrap().zones = zones.iter().map(|z| z.to_string()).collect();
        }

        /// 预置一个记录集（properties 为记录集 properties JSON）。
        fn set_record_set(&self, zone: &str, rtype: &str, name: &str, properties: serde_json::Value) {
            self.state.lock().unwrap().record_sets.insert(
                (zone.to_string(), rtype.to_string(), name.to_string()),
                properties,
            );
        }

        fn token_posts(&self) -> usize {
            self.state.lock().unwrap().token_posts
        }

        fn fail_once(&self, status: u16, body: &str, retry_after: Option<&str>) {
            self.state.lock().unwrap().fail =
                Some((status, body.to_string(), retry_after.map(str::to_string)));
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.state.lock().unwrap().requests.clone()
        }

        fn count(&self, method: &str, suffix: &str) -> usize {
            self.state
                .lock()
                .unwrap()
                .requests
                .iter()
                .filter(|r| r.method == method && r.path.split('?').next().unwrap_or("").ends_with(suffix))
                .count()
        }
    }

    async fn handle_conn(mut stream: TcpStream, state: &Arc<Mutex<MockState>>) -> std::io::Result<()> {
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
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim().to_string();
                if k == "content-length" {
                    content_length = v.parse().unwrap_or(0);
                }
                headers.push((k, v));
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).await?;
        let body = String::from_utf8_lossy(&body).to_string();

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();

        let req = RecordedRequest { method, path, headers, body };
        let (status, resp_body, retry_after) = {
            let mut st = state.lock().unwrap();
            st.requests.push(req.clone());
            route(&req, &mut st)
        };

        let mut raw = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            status,
            resp_body.len()
        );
        if let Some(ra) = retry_after {
            raw.push_str(&format!("Retry-After: {ra}\r\n"));
        }
        raw.push_str("\r\n");
        raw.push_str(&resp_body);
        stream.write_all(raw.as_bytes()).await?;
        stream.flush().await
    }

    fn status_line(status: u16) -> &'static str {
        match status {
            200 => "200 OK",
            201 => "201 Created",
            204 => "204 No Content",
            400 => "400 Bad Request",
            401 => "401 Unauthorized",
            403 => "403 Forbidden",
            404 => "404 Not Found",
            429 => "429 Too Many Requests",
            500 => "500 Internal Server Error",
            _ => "500 Internal Server Error",
        }
    }

    fn arm_err(code: &str, message: &str) -> String {
        format!(r#"{{"error":{{"code":"{code}","message":"{message}"}}}}"#)
    }

    /// 请求路由：token 端点 / dnsZones / recordsets / 记录集 CRUD。
    fn route(req: &RecordedRequest, st: &mut MockState) -> (String, String, Option<String>) {
        if req.path.contains("/oauth2/v2.0/token") {
            st.token_posts += 1;
            // 每次 POST 返回不同 token（tok-1、tok-2...），便于断言刷新重试携带新 token。
            let json = format!(
                r#"{{"token_type":"Bearer","expires_in":3600,"access_token":"tok-{}"}}"#,
                st.token_posts
            );
            return (status_line(200).to_string(), json, None);
        }
        if let Some((status, body, retry)) = st.fail.take() {
            return (status_line(status).to_string(), body, retry);
        }

        let path = req.path.split('?').next().unwrap_or("").to_string();
        // /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/dnsZones[/{zone}[/recordsets|{TYPE}/{name}]]
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.len() < 7 || segs[5] != "Microsoft.Network" || segs[6] != "dnsZones" {
            return (status_line(404).to_string(), arm_err("ResourceNotFound", "bad path"), None);
        }
        match segs.len() {
            7 => {
                // dnsZones 列表。
                let value: Vec<serde_json::Value> = st
                    .zones
                    .iter()
                    .map(|z| serde_json::json!({ "name": z, "type": "Microsoft.Network/dnsZones" }))
                    .collect();
                (status_line(200).to_string(), serde_json::json!({ "value": value }).to_string(), None)
            }
            // .../dnsZones/{zone}/recordsets（segs[7]=zone, segs[8]=recordsets）。
            9 if segs[8] == "recordsets" => {
                let zone = segs[7].to_string();
                let value: Vec<serde_json::Value> = st
                    .record_sets
                    .iter()
                    .filter(|((z, _, _), _)| *z == zone)
                    .map(|((_, rtype, name), props)| {
                        serde_json::json!({
                            "name": name,
                            "type": format!("Microsoft.Network/dnsZones/{rtype}"),
                            "properties": props,
                        })
                    })
                    .collect();
                (status_line(200).to_string(), serde_json::json!({ "value": value }).to_string(), None)
            }
            // .../dnsZones/{zone}/{TYPE}/{name}（segs[7]=zone, segs[8]=TYPE, segs[9]=name）。
            10 => {
                let (zone, rtype, name) = (segs[7].to_string(), segs[8].to_string(), segs[9].to_string());
                match req.method.as_str() {
                    "GET" => match st.record_sets.get(&(zone.clone(), rtype.clone(), name.clone())) {
                        Some(props) => (
                            status_line(200).to_string(),
                            serde_json::json!({
                                "name": name,
                                "type": format!("Microsoft.Network/dnsZones/{rtype}"),
                                "properties": props,
                            })
                            .to_string(),
                            None,
                        ),
                        None => (status_line(404).to_string(), arm_err("ResourceNotFound", "record set not found"), None),
                    },
                    "PUT" => {
                        // 请求体 {"properties": {...}}。
                        let props = serde_json::from_str::<serde_json::Value>(&req.body)
                            .ok()
                            .and_then(|v| v.get("properties").cloned())
                            .unwrap_or(serde_json::Value::Null);
                        st.record_sets.insert((zone, rtype, name.clone()), props);
                        (
                            status_line(200).to_string(),
                            serde_json::json!({ "name": name }).to_string(),
                            None,
                        )
                    }
                    "DELETE" => {
                        // 记录集不存在 → 404（与真实 ARM 行为一致，供 NotFound 路径测试）。
                        if !st.record_sets.contains_key(&(zone.clone(), rtype.clone(), name.clone())) {
                            return (
                                status_line(404).to_string(),
                                arm_err("ResourceNotFound", "record set not found"),
                                None,
                            );
                        }
                        st.record_sets.remove(&(zone, rtype, name));
                        (status_line(204).to_string(), String::new(), None)
                    }
                    _ => (status_line(405).to_string(), String::new(), None),
                }
            }
            _ => (status_line(404).to_string(), arm_err("ResourceNotFound", "bad path"), None),
        }
    }

    // ─────────────────────────────────────────────
    // 测试
    // ─────────────────────────────────────────────

    const SUB: &str = "sub-1111";
    const RG: &str = "rg-1";

    fn provider(mock: &MockAzure) -> AzureProvider {
        let client = AzureClient::new_with_endpoint(
            "tenant-1",
            "client-1",
            "secret-1",
            SUB,
            RG,
            &mock.base_url(),
            Some(&mock.token_url()),
        );
        AzureProvider::with_client(client)
    }

    fn rec(name: &str, rtype: RecordType, data: RecordData, ttl: u32) -> Record {
        Record { name: name.to_string(), rtype, ttl, data }
    }

    /// 1. Bearer 头形状 + token 缓存复用（第二次请求不再取 token）。
    #[tokio::test]
    async fn bearer_header_and_token_cache() {
        let mock = MockAzure::start().await;
        mock.set_zones(&["example.com"]);
        let p = provider(&mock);

        p.list_domains().await.expect("list 1");
        p.list_domains().await.expect("list 2");

        let reqs = mock.requests();
        let arm_reqs: Vec<&RecordedRequest> = reqs
            .iter()
            .filter(|r| !r.path.contains("/oauth2/v2.0/token"))
            .collect();
        assert_eq!(arm_reqs.len(), 2);
        for r in &arm_reqs {
            assert_eq!(r.header("authorization"), Some("Bearer tok-1"), "Bearer 头");
        }
        // URL 形状：resourceGroups/{rg}/.../dnsZones?api-version=2018-05-01。
        let path = arm_reqs[0].path.clone();
        assert!(path.contains(&format!("/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Network/dnsZones")));
        assert!(path.contains("api-version=2018-05-01"), "{path}");
        // token 只获取一次（缓存复用）。
        assert_eq!(mock.token_posts(), 1, "token 缓存：两次请求只取一次");
    }

    /// 2. list_domains 解析 dnsZones name。
    #[tokio::test]
    async fn list_domains_parses_zone_names() {
        let mock = MockAzure::start().await;
        mock.set_zones(&["example.com", "kirin.dev"]);
        let p = provider(&mock);
        assert_eq!(p.list_domains().await.expect("domains"), vec!["example.com", "kirin.dev"]);
        // test_connection 走同一最小查询。
        p.test_connection().await.expect("test connection");
    }

    /// 3. query_records：全类型解析（A 多值 / TXT 数组拼接 / SRV / MX / CNAME / 根 @）。
    #[tokio::test]
    async fn query_records_all_types() {
        let mock = MockAzure::start().await;
        mock.set_record_set("example.com", "A", "my-pc", serde_json::json!({
            "TTL": 600,
            "ARecords": [{"ipv4Address": "192.0.2.1"}, {"ipv4Address": "192.0.2.2"}]
        }));
        mock.set_record_set("example.com", "TXT", "my-pc", serde_json::json!({
            "TTL": 300,
            "TXTRecords": [{"value": ["v=ed25519;", "k=abc"]}]
        }));
        mock.set_record_set("example.com", "SRV", "_sip._tcp", serde_json::json!({
            "TTL": 60,
            "SRVRecords": [{"priority": 0, "weight": 5, "port": 5060, "target": "sip.example.com"}]
        }));
        mock.set_record_set("example.com", "MX", "@", serde_json::json!({
            "TTL": 300,
            "MXRecords": [{"preference": 10, "exchange": "mail.example.com"}]
        }));
        mock.set_record_set("example.com", "CNAME", "www", serde_json::json!({
            "TTL": 300,
            "CNAMERecord": {"cname": "my-pc.example.com"}
        }));
        let p = provider(&mock);

        let all = p.query_records("example.com", None, None).await.expect("all");
        assert_eq!(all.len(), 6);
        // A 多值 → 同 name+rtype 两条。
        let a_recs: Vec<_> = all.iter().filter(|r| r.rtype == RecordType::A).collect();
        assert_eq!(a_recs.len(), 2);
        assert!(a_recs.iter().any(|r| r.data == RecordData::Plain("192.0.2.1".into())));
        // TXT 数组拼接为单值。
        let txt = all.iter().find(|r| r.rtype == RecordType::TXT).expect("txt");
        assert_eq!(txt.data, RecordData::Plain("v=ed25519;k=abc".into()));
        // SRV/MX 结构化。
        let srv = all.iter().find(|r| r.rtype == RecordType::SRV).expect("srv");
        assert_eq!(srv.name, "_sip._tcp");
        assert_eq!(srv.data, RecordData::Srv { priority: 0, weight: 5, port: 5060, target: "sip.example.com".into() });
        let mx = all.iter().find(|r| r.rtype == RecordType::MX).expect("mx");
        assert_eq!(mx.name, "", "根 '@' → 空串");
        assert_eq!(mx.data, RecordData::Mx { priority: 10, exchange: "mail.example.com".into() });

        // name/rtype 过滤。
        let filtered = p.query_records("example.com", Some("my-pc"), Some(RecordType::A)).await.unwrap();
        assert_eq!(filtered.len(), 2);
        let none = p.query_records("example.com", Some("ghost"), None).await.unwrap();
        assert!(none.is_empty());
    }

    /// 4. upsert：记录集整组替换——先 GET 现有 → 原记录保留 + 本条更新 → PUT。
    #[tokio::test]
    async fn upsert_read_then_write_full_set() {
        let mock = MockAzure::start().await;
        mock.set_record_set("example.com", "A", "my-pc", serde_json::json!({
            "TTL": 600,
            "ARecords": [{"ipv4Address": "192.0.2.1"}]
        }));
        let p = provider(&mock);

        p.upsert_record("example.com", &rec("my-pc", RecordType::A, RecordData::Plain("192.0.2.99".into()), 1200))
            .await
            .expect("upsert");

        let reqs = mock.requests();
        let get_idx = reqs.iter().position(|r| r.method == "GET" && r.path.contains("/A/my-pc")).expect("GET 先查");
        let put_idx = reqs.iter().position(|r| r.method == "PUT" && r.path.contains("/A/my-pc")).expect("PUT 后写");
        assert!(get_idx < put_idx, "先查后写");

        let put = &reqs[put_idx];
        assert!(put.path.contains(&format!(
            "/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Network/dnsZones/example.com/A/my-pc"
        )));
        assert!(put.path.contains("api-version=2018-05-01"), "{0}", put.path);
        let body: serde_json::Value = serde_json::from_str(&put.body).expect("PUT JSON");
        let props = &body["properties"];
        assert_eq!(props["TTL"], 1200);
        // 原记录保留 + 本条追加（整组替换语义）。
        assert_eq!(props["ARecords"][0]["ipv4Address"], "192.0.2.1");
        assert_eq!(props["ARecords"][1]["ipv4Address"], "192.0.2.99");

        // 记录集不存在 → 不查直接 PUT（GET 404 → 仅新记录）。
        p.upsert_record("example.com", &rec("ghost", RecordType::A, RecordData::Plain("203.0.113.7".into()), 60))
            .await
            .expect("upsert new");
        let reqs2 = mock.requests();
        let put2 = reqs2.iter().filter(|r| r.method == "PUT" && r.path.contains("/A/ghost")).last().expect("PUT ghost");
        let body2: serde_json::Value = serde_json::from_str(&put2.body).unwrap();
        assert_eq!(body2["properties"]["ARecords"][0]["ipv4Address"], "203.0.113.7");
        assert_eq!(body2["properties"]["ARecords"].as_array().unwrap().len(), 1);

        // 根记录：name "" → URL 中 "@"。
        p.upsert_record("example.com", &rec("", RecordType::A, RecordData::Plain("192.0.2.100".into()), 600))
            .await
            .expect("upsert root");
        let reqs3 = mock.requests();
        assert!(
            reqs3.iter().any(|r| r.method == "PUT" && r.path.split('?').next().unwrap_or("").ends_with("/A/@")),
            "根记录集 URL 用 @"
        );
    }

    /// 5. delete：DELETE 记录集；不存在 → NotFound。
    #[tokio::test]
    async fn delete_record_set_and_not_found() {
        let mock = MockAzure::start().await;
        mock.set_record_set("example.com", "A", "my-pc", serde_json::json!({
            "TTL": 600,
            "ARecords": [{"ipv4Address": "192.0.2.1"}]
        }));
        let p = provider(&mock);

        p.delete_record("example.com", "my-pc", RecordType::A).await.expect("delete");
        assert_eq!(mock.count("DELETE", "/A/my-pc"), 1);

        let err = p.delete_record("example.com", "ghost", RecordType::A).await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }), "{err:?}");
    }

    /// 6. 错误码映射：Auth / InvalidParameter / NotFound / RateLimited / Server。
    #[tokio::test]
    async fn error_code_mapping() {
        let mock = MockAzure::start().await;
        let p = provider(&mock);

        // 401 → Auth（注：401 会触发刷新重试一次，此处验证 403 直接 Auth；401 见 token_refresh_on_401）。
        mock.fail_once(403, &arm_err("AuthorizationFailed", "no permission"), None);
        let e = p.list_domains().await.unwrap_err();
        assert!(matches!(e, ProviderError::Auth { .. }), "{e:?}");

        mock.fail_once(400, &arm_err("InvalidResourceRecord", "bad record"), None);
        let e = p.list_domains().await.unwrap_err();
        assert!(matches!(e, ProviderError::InvalidParameter { .. }), "{e:?}");

        mock.fail_once(404, &arm_err("ResourceNotFound", "zone missing"), None);
        let e = p.list_domains().await.unwrap_err();
        assert!(matches!(e, ProviderError::NotFound { .. }), "{e:?}");

        mock.fail_once(429, &arm_err("Throttling", "slow down"), Some("7"));
        let e = p.list_domains().await.unwrap_err();
        match e {
            ProviderError::RateLimited { retry_after } => assert_eq!(retry_after, Some(7)),
            other => panic!("expected RateLimited, got {other:?}"),
        }

        mock.fail_once(500, "internal server error", None);
        let e = p.list_domains().await.unwrap_err();
        assert!(matches!(e, ProviderError::Server { status: 500, .. }), "{e:?}");
    }

    /// 7. 401 invalid_token → 强制刷新 token 并重试一次（第二次请求用新 token）。
    #[tokio::test]
    async fn token_refresh_and_retry_on_401() {
        let mock = MockAzure::start().await;
        mock.set_zones(&["example.com"]);
        let p = provider(&mock);

        // 首次 ARM 请求返回 401（token 失效）；刷新后取到的新 token 为 tok-2。
        mock.fail_once(401, &arm_err("InvalidAuthenticationToken", "expired"), None);
        let domains = p.list_domains().await.expect("retried after refresh");
        assert_eq!(domains, vec!["example.com"]);

        assert_eq!(mock.token_posts(), 2, "初取 + 401 强制刷新");
        let arm_reqs: Vec<RecordedRequest> = mock
            .requests()
            .into_iter()
            .filter(|r| !r.path.contains("/oauth2/v2.0/token"))
            .collect();
        assert_eq!(arm_reqs.len(), 2);
        assert_eq!(arm_reqs[0].header("authorization"), Some("Bearer tok-1"), "第一次用旧 token");
        assert_eq!(arm_reqs[1].header("authorization"), Some("Bearer tok-2"), "重试用刷新后的新 token");
    }

    /// 8. SRV/MX 结构化写入（PUT body SRVRecords/MXRecords 形状）+ 能力全开。
    #[tokio::test]
    async fn srv_mx_structured_write_and_capabilities() {
        let mock = MockAzure::start().await;
        mock.set_record_set("example.com", "SRV", "_sip._tcp", serde_json::json!({
            "TTL": 60,
            "SRVRecords": [{"priority": 0, "weight": 5, "port": 5060, "target": "sip.example.com"}]
        }));
        let p = provider(&mock);

        let caps = p.capabilities();
        assert!(caps.srv && caps.ns && caps.ttl && caps.rename);

        // upsert SRV：原记录保留 + 新 SRV 追加。
        p.upsert_record(
            "example.com",
            &rec(
                "_sip._tcp",
                RecordType::SRV,
                RecordData::Srv { priority: 0, weight: 5, port: 5061, target: "sip2.example.com".into() },
                60,
            ),
        )
        .await
        .expect("upsert srv");
        let reqs = mock.requests();
        let put = reqs
            .iter()
            .filter(|r| r.method == "PUT")
            .last()
            .expect("PUT");
        let body: serde_json::Value = serde_json::from_str(&put.body).unwrap();
        let arr = body["properties"]["SRVRecords"].as_array().expect("SRVRecords array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["port"], 5060);
        assert_eq!(arr[1]["target"], "sip2.example.com");

        // MX 结构化写入。
        p.upsert_record(
            "example.com",
            &rec("", RecordType::MX, RecordData::Mx { priority: 10, exchange: "mail.example.com".into() }, 300),
        )
        .await
        .expect("upsert mx");
        let reqs = mock.requests();
        let put = reqs
            .iter()
            .filter(|r| r.method == "PUT")
            .last()
            .expect("PUT mx");
        let body: serde_json::Value = serde_json::from_str(&put.body).unwrap();
        assert_eq!(body["properties"]["MXRecords"][0]["preference"], 10);
        assert_eq!(body["properties"]["MXRecords"][0]["exchange"], "mail.example.com");
        assert_eq!(body["properties"]["TTL"], 300);

        // 幂等：同 data 再 upsert → 仍 2 条（不重复）。
        p.upsert_record(
            "example.com",
            &rec(
                "_sip._tcp",
                RecordType::SRV,
                RecordData::Srv { priority: 0, weight: 5, port: 5061, target: "sip2.example.com".into() },
                120,
            ),
        )
        .await
        .expect("upsert srv again");
        let reqs = mock.requests();
        let put = reqs
            .iter()
            .filter(|r| r.method == "PUT")
            .last()
            .expect("PUT");
        let body: serde_json::Value = serde_json::from_str(&put.body).unwrap();
        assert_eq!(body["properties"]["SRVRecords"].as_array().unwrap().len(), 2);
        assert_eq!(body["properties"]["TTL"], 120, "同 data 更新 TTL");
    }
}
