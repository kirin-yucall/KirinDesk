//! AWS Route 53 服务商适配（M9-DNS005）
//!
//! - 认证：AWS SigV4（手写实现，[`sign`]）
//! - 序列化：XML 手写解析/构造（[`xml`]）
//! - 错误：Route53 XML `<ErrorResponse><Error><Code>` → 统一 [`ProviderError`]（[`error`]）
//! - 记录语义：同 name+type = 记录集（多条 Value）→ 统一模型多条同 name+rtype Record 往返；
//!   upsert 先查后组（保留原 Value）、delete 带全量 Value 的 DELETE 整集。
//! - 名称格式：相对名 ↔ FQDN.（末尾点）互转（根 `""` → `{domain}.`）
//!
//! 注册：`register()` 以键名 `"route53"` 注册到 [`ProviderRegistry`]。
//! 能力：全开（SRV/NS/TTL/rename 均支持）。

pub mod client;
pub mod error;
pub mod sign;
pub mod xml;

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record, RecordType,
};
use client::{Change, RawRecordSet, Route53Client};

/// 服务商注册（由 `providers::register_all` 集成时调用）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register("route53", |cred| -> Box<dyn Provider> {
        Box::new(Route53Provider::new(cred))
    });
}

/// Route53 Provider：包装 [`Route53Client`] 并实现统一契约语义。
#[derive(Clone)]
pub struct Route53Provider {
    client: Route53Client,
}

impl Route53Provider {
    /// 按凭据构造（生产端点）。
    pub fn new(cred: &Credential) -> Self {
        Self {
            client: Route53Client::new(cred),
        }
    }

    /// 测试用：注入自定义端点的客户端。
    pub(crate) fn with_client(client: Route53Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Provider for Route53Provider {
    fn name(&self) -> &'static str {
        "route53"
    }

    /// 最小查询：GET /hostedzone?maxitems=1。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.list_hosted_zones(Some(1)).await.map(|_| ())
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let zones = self.client.list_hosted_zones(Some(100)).await?;
        Ok(zones.into_iter().map(|z| z.name).collect())
    }

    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let zone_id = self.client.zone_id(domain).await?;
        let fqdn = name.map(|n| Route53Client::to_fqdn(domain, n));
        let type_str = rtype.map(|t| t.as_str().to_string());
        let sets = self
            .client
            .list_rrsets(&zone_id, fqdn.as_deref(), type_str.as_deref())
            .await?;
        let domain_nd = domain.trim_end_matches('.');
        let mut out = Vec::new();
        for set in sets {
            let rel = Route53Client::to_relative(&set.name, domain_nd);
            // 类型不在统一模型内（如 SOA）→ 跳过。
            let Ok(rt) = set.rtype.parse::<RecordType>() else { continue };
            if let Some(t) = rtype {
                if t != rt {
                    continue;
                }
            }
            if let Some(n) = name {
                if rel != n {
                    continue;
                }
            }
            // 记录集内每条 Value → 一条统一 Record（同 name+rtype 多条）。
            for v in &set.values {
                if let Some(data) = Route53Client::value_to_data(rt, v) {
                    out.push(Record {
                        name: rel.clone(),
                        rtype: rt,
                        ttl: set.ttl,
                        data,
                    });
                }
            }
        }
        Ok(out)
    }

    /// 记录集语义 upsert：先查现有（同 name+type）→ 原 Value 保留 + 本条更新 →
    /// 一次 ChangeResourceRecordSets（UPSERT 整个记录集，替换整集）。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let zone_id = self.client.zone_id(domain).await?;
        let fqdn = Route53Client::to_fqdn(domain, &rec.name);
        let existing = self
            .client
            .list_rrsets(&zone_id, Some(&fqdn), Some(rec.rtype.as_str()))
            .await?;
        let mut values: Vec<String> = existing
            .iter()
            .filter(|s| {
                s.name.eq_ignore_ascii_case(&fqdn) && s.rtype.eq_ignore_ascii_case(rec.rtype.as_str())
            })
            .flat_map(|s| s.values.clone())
            .collect();
        let new_value = Route53Client::record_to_value(rec);
        if !values.iter().any(|v| v == &new_value) {
            values.push(new_value);
        }
        let set = RawRecordSet {
            name: fqdn,
            rtype: rec.rtype.as_str().to_string(),
            ttl: Route53Client::normalize_ttl(rec.ttl),
            values,
        };
        self.client
            .change_rrsets(&zone_id, &[Change { action: "UPSERT", set }], None)
            .await
    }

    /// delete：定位记录集（先查），带全量 Value 执行 DELETE（缺值 Route53 校验失败）。
    /// 记录集明确不存在 → NotFound；查询后被并发删除 → 400 InvalidChangeBatch 幂等视为 Ok。
    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let zone_id = self.client.zone_id(domain).await?;
        let fqdn = Route53Client::to_fqdn(domain, name);
        let existing = self
            .client
            .list_rrsets(&zone_id, Some(&fqdn), Some(rtype.as_str()))
            .await?;
        let sets: Vec<RawRecordSet> = existing
            .into_iter()
            .filter(|s| {
                s.name.eq_ignore_ascii_case(&fqdn) && s.rtype.eq_ignore_ascii_case(rtype.as_str())
            })
            .collect();
        if sets.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        for set in &sets {
            let change = Change {
                action: "DELETE",
                set: set.clone(),
            };
            if let Err(e) = self.client.change_rrsets(&zone_id, &[change], None).await {
                if error::is_deleted_set_race(&e) {
                    continue; // 竞态：已被删除 → 幂等 Ok
                }
                return Err(e);
            }
        }
        Ok(())
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

#[cfg(test)]
mod tests {
    //! 契约测试：tokio mock HTTP server（127.0.0.1，参考 `dns/src/test_support.rs`
    //! MockDns 模式），断言 SigV4 头形状、请求 body、分页、错误映射、SRV/MX 往返。

    use super::*;
    use crate::provider::RecordData;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    // ─────────────────────────────────────────────
    // mock HTTP server
    // ─────────────────────────────────────────────

    /// 捕获到的一次完整请求。
    #[derive(Debug, Clone)]
    struct RecordedRequest {
        method: String,
        /// 含查询串（如 `/2013-04-01/hostedzone?maxitems=100`）。
        path: String,
        /// 全部请求头（键小写）。
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
        /// (zone id, zone name 无尾点)。
        zones: Vec<(String, String)>,
        /// (fqdn 带尾点, rtype, ttl, values)。
        rrsets: Vec<(String, String, u32, Vec<String>)>,
        /// 分页模拟：每页最多 n 条（None = 不分页）。
        truncate_after: Option<usize>,
        /// 一次性错误响应 (status, body, retry-after)。
        fail: Option<(u16, String, Option<String>)>,
    }

    #[derive(Clone)]
    struct MockRoute53 {
        addr: SocketAddr,
        state: Arc<Mutex<MockState>>,
    }

    impl MockRoute53 {
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

        fn set_zones(&self, zones: &[(&str, &str)]) {
            self.state.lock().unwrap().zones = zones
                .iter()
                .map(|(id, name)| (id.to_string(), name.to_string()))
                .collect();
        }

        fn set_rrsets(&self, sets: &[(String, String, u32, Vec<String>)]) {
            self.state.lock().unwrap().rrsets = sets.to_vec();
        }

        fn set_truncate_after(&self, n: usize) {
            self.state.lock().unwrap().truncate_after = Some(n);
        }

        fn fail_once(&self, status: u16, body: &str, retry_after: Option<&str>) {
            self.state.lock().unwrap().fail =
                Some((status, body.to_string(), retry_after.map(str::to_string)));
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.state.lock().unwrap().requests.clone()
        }

        /// 统计满足 method + path 后缀的请求数。
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
            "HTTP/1.1 {}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n",
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
            400 => "400 Bad Request",
            403 => "403 Forbidden",
            404 => "404 Not Found",
            429 => "429 Too Many Requests",
            500 => "500 Internal Server Error",
            _ => "500 Internal Server Error",
        }
    }

    /// 请求路由（Route53 语义：hostedzone 列表 / rrset 列表(分页) / rrset 变更）。
    fn route(req: &RecordedRequest, st: &mut MockState) -> (String, String, Option<String>) {
        if let Some((status, body, retry)) = st.fail.take() {
            return (status_line(status).to_string(), body, retry);
        }
        let path = req.path.split('?').next().unwrap_or("").to_string();
        let query = req.path.split('?').nth(1).unwrap_or("");

        if req.method == "GET" && path == "/2013-04-01/hostedzone" {
            return (status_line(200).to_string(), zones_xml(&st.zones), None);
        }
        if path.ends_with("/rrset") {
            match req.method.as_str() {
                "GET" => return (status_line(200).to_string(), rrsets_xml(st, query), None),
                "POST" => return (status_line(200).to_string(), change_response_xml(), None),
                _ => {}
            }
        }
        (status_line(404).to_string(), String::new(), None)
    }

    fn zones_xml(zones: &[(String, String)]) -> String {
        let mut s = String::from(
            "<ListHostedZonesResponse xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><HostedZones>",
        );
        for (id, name) in zones {
            s.push_str(&format!("<HostedZone><Id>/hostedzone/{id}</Id><Name>{name}.</Name></HostedZone>"));
        }
        s.push_str("</HostedZones><IsTruncated>false</IsTruncated><MaxItems>1000</MaxItems></ListHostedZonesResponse>");
        s
    }

    /// rrset 列表 XML：按 `name` 查询参数定位起点（Route53 词典序语义），
    /// 超过 `truncate_after` 则返回分页标记。
    fn rrsets_xml(st: &MockState, query: &str) -> String {
        let start_param = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("name="))
            .unwrap_or("");
        let start = match start_param {
            "" => 0,
            name => st
                .rrsets
                .iter()
                .position(|(fqdn, _, _, _)| fqdn.as_str() >= name)
                .unwrap_or(st.rrsets.len()),
        };
        let mut end = st.rrsets.len();
        let mut truncated = false;
        if let Some(n) = st.truncate_after {
            if start + n < st.rrsets.len() {
                end = start + n;
                truncated = true;
            }
        }
        let page = &st.rrsets[start..end];
        let mut s = String::from(
            "<ListResourceRecordSetsResponse xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ResourceRecordSets>",
        );
        for (fqdn, rtype, ttl, values) in page {
            s.push_str("<ResourceRecordSet><Name>");
            s.push_str(fqdn);
            s.push_str("</Name><Type>");
            s.push_str(rtype);
            s.push_str("</Type><TTL>");
            s.push_str(&ttl.to_string());
            s.push_str("</TTL><ResourceRecords>");
            for v in values {
                s.push_str("<ResourceRecord><Value>");
                s.push_str(v);
                s.push_str("</Value></ResourceRecord>");
            }
            s.push_str("</ResourceRecords></ResourceRecordSet>");
        }
        s.push_str("</ResourceRecordSets>");
        if truncated {
            let (next_fqdn, next_type, _, _) = &st.rrsets[end];
            s.push_str("<IsTruncated>true</IsTruncated>");
            s.push_str(&format!("<NextRecordName>{next_fqdn}</NextRecordName>"));
            s.push_str(&format!("<NextRecordType>{next_type}</NextRecordType>"));
        } else {
            s.push_str("<IsTruncated>false</IsTruncated>");
        }
        s.push_str("</ListResourceRecordSetsResponse>");
        s
    }

    fn change_response_xml() -> String {
        String::from(
            "<ChangeResourceRecordSetsResponse xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>",
        )
    }

    fn err_xml(code: &str, msg: &str) -> String {
        format!(
            r#"<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><Error><Type>Sender</Type><Code>{code}</Code><Message>{msg}</Message></Error><RequestId>req1</RequestId></ErrorResponse>"#
        )
    }

    // ─────────────────────────────────────────────
    // 测试
    // ─────────────────────────────────────────────

    const AK: &str = "AKIAIOSFODNN7EXAMPLE";
    const SK: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn provider(mock: &MockRoute53) -> Route53Provider {
        let client = Route53Client::new_with_endpoint(AK, SK, "us-east-1", &mock.base_url());
        Route53Provider::with_client(client)
    }

    fn rec(name: &str, rtype: RecordType, data: RecordData, ttl: u32) -> Record {
        Record { name: name.to_string(), rtype, ttl, data }
    }

    fn a_rec(name: &str, ip: &str, ttl: u32) -> Record {
        rec(name, RecordType::A, RecordData::Plain(ip.to_string()), ttl)
    }

    /// 1. Authorization 头形状：AWS4-HMAC-SHA256 Credential=.../route53/aws4_request,
    ///    SignedHeaders=host;x-amz-date, Signature=<64 hex>；x-amz-date 为 UTC ISO8601 基础格式。
    #[tokio::test]
    async fn authorization_header_shape() {
        let mock = MockRoute53::start().await;
        mock.set_zones(&[("Z1", "example.com")]);
        let p = provider(&mock);
        p.list_domains().await.expect("list domains");

        let req = mock.requests().into_iter().next().expect("one request");
        let auth = req.header("authorization").expect("authorization header");
        assert!(
            auth.starts_with(&format!("AWS4-HMAC-SHA256 Credential={AK}/")),
            "auth prefix: {auth}"
        );
        assert!(
            auth.contains("/us-east-1/route53/aws4_request, SignedHeaders=host;x-amz-date, Signature="),
            "auth shape: {auth}"
        );
        let sig = auth.split("Signature=").nth(1).expect("signature part");
        assert_eq!(sig.len(), 64, "signature must be 64 hex chars: {sig}");
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));

        let amz = req.header("x-amz-date").expect("x-amz-date header");
        assert_eq!(amz.len(), 16, "YYYYMMDDTHHMMSSZ: {amz}");
        assert!(amz.ends_with('Z'));
        assert_eq!(&amz[8..9], "T");
        assert!(
            amz[..8].chars().all(|c| c.is_ascii_digit()) && amz[9..15].chars().all(|c| c.is_ascii_digit()),
            "日期部分须为数字: {amz}"
        );
    }

    /// 2. list_domains：解析 <ListHostedZonesResponse> 的 Name（去尾点）；zone id 缓存。
    #[tokio::test]
    async fn list_domains_and_zone_id_cache() {
        let mock = MockRoute53::start().await;
        mock.set_zones(&[("Z1PA6795UKMFR9", "example.com"), ("Z2", "kirin.dev")]);
        let p = provider(&mock);

        let domains = p.list_domains().await.expect("domains");
        assert_eq!(domains, vec!["example.com", "kirin.dev"]);

        // 两次查询触发 zone 查找：第一次遍历（缓存），第二次命中缓存。
        p.query_records("example.com", None, None).await.expect("query 1");
        p.query_records("example.com", None, None).await.expect("query 2");
        assert_eq!(
            mock.count("GET", "/hostedzone"),
            2,
            "list_domains 1 次 + zone 查找 1 次（第二次查询命中缓存）"
        );
        assert_eq!(mock.count("GET", "/rrset"), 2);
    }

    /// 3. query_records：rrset 分页（IsTruncated + NextRecordName/NextRecordType 循环）。
    #[tokio::test]
    async fn query_records_paginates() {
        let mock = MockRoute53::start().await;
        mock.set_zones(&[("Z1", "example.com")]);
        mock.set_rrsets(&[
            ("a.example.com.".into(), "A".into(), 60, vec!["192.0.2.1".into()]),
            ("b.example.com.".into(), "A".into(), 60, vec!["192.0.2.2".into()]),
            ("c.example.com.".into(), "A".into(), 60, vec!["192.0.2.3".into()]),
        ]);
        mock.set_truncate_after(2);
        let p = provider(&mock);

        let all = p.query_records("example.com", None, None).await.expect("all");
        assert_eq!(all.len(), 3, "分页循环后应拿到全部 3 条");
        assert_eq!(mock.count("GET", "/rrset"), 2, "两页：IsTruncated 循环");

        // name/rtype 过滤。
        let filtered = p
            .query_records("example.com", Some("b"), Some(RecordType::A))
            .await
            .expect("filtered");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].data, RecordData::Plain("192.0.2.2".into()));
        assert_eq!(filtered[0].name, "b");
    }

    /// 4. upsert：记录集语义——原 Value 保留 + 本条更新，一次 UPSERT 批量。
    #[tokio::test]
    async fn upsert_preserves_existing_values() {
        let mock = MockRoute53::start().await;
        mock.set_zones(&[("Z1", "example.com")]);
        mock.set_rrsets(&[(
            "my-pc.example.com.".into(),
            "A".into(),
            600,
            vec!["192.0.2.1".into(), "192.0.2.2".into()],
        )]);
        let p = provider(&mock);

        p.upsert_record("example.com", &a_rec("my-pc", "203.0.113.7", 300))
            .await
            .expect("upsert");

        let reqs = mock.requests();
        let post = reqs
            .iter()
            .find(|r| r.method == "POST")
            .expect("one POST (UPSERT)");
        assert!(post.body.contains("<Action>UPSERT</Action>"));
        assert!(post.body.contains("<Name>my-pc.example.com.</Name>"));
        assert!(post.body.contains("<TTL>300</TTL>"));
        // 原 Value 保留 + 本条追加。
        assert!(post.body.contains("<Value>192.0.2.1</Value>"));
        assert!(post.body.contains("<Value>192.0.2.2</Value>"));
        assert!(post.body.contains("<Value>203.0.113.7</Value>"));

        // 幂等：同 data 再次 upsert → 仍为 3 个 Value（不重复）。
        p.upsert_record("example.com", &a_rec("my-pc", "203.0.113.7", 300))
            .await
            .expect("upsert again");
        let reqs = mock.requests();
        let post2 = reqs
            .iter()
            .filter(|r| r.method == "POST")
            .last()
            .expect("second POST");
        assert_eq!(post2.body.matches("<ResourceRecord>").count(), 3);
    }

    /// 5. upsert 根域名：相对名 "" → FQDN "{domain}."。
    #[tokio::test]
    async fn upsert_root_name_uses_domain_fqdn() {
        let mock = MockRoute53::start().await;
        mock.set_zones(&[("Z1", "example.com")]);
        let p = provider(&mock);
        p.upsert_record("example.com", &a_rec("", "192.0.2.100", 600))
            .await
            .expect("upsert root");
        let reqs = mock.requests();
        let post = reqs
            .iter()
            .find(|r| r.method == "POST")
            .expect("POST");
        assert!(post.body.contains("<Name>example.com.</Name>"), "根域名应写为 example.com.（带尾点）");
        // 查询回来根记录 name 应为 ""。
        mock.set_rrsets(&[(
            "example.com.".into(),
            "A".into(),
            600,
            vec!["192.0.2.100".into()],
        )]);
        let got = p
            .query_records("example.com", Some(""), Some(RecordType::A))
            .await
            .expect("query root");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "");
        assert_eq!(got[0].data, RecordData::Plain("192.0.2.100".into()));
    }

    /// 6. delete：DELETE 整集（带全量 Value）；记录集不存在 → NotFound（无 DELETE 调用）。
    #[tokio::test]
    async fn delete_sends_delete_action_with_all_values() {
        let mock = MockRoute53::start().await;
        mock.set_zones(&[("Z1", "example.com")]);
        mock.set_rrsets(&[(
            "my-pc.example.com.".into(),
            "A".into(),
            600,
            vec!["192.0.2.1".into(), "192.0.2.2".into()],
        )]);
        let p = provider(&mock);

        p.delete_record("example.com", "my-pc", RecordType::A)
            .await
            .expect("delete");
        let reqs = mock.requests();
        let post = reqs
            .iter()
            .find(|r| r.method == "POST")
            .expect("DELETE POST");
        assert!(post.body.contains("<Action>DELETE</Action>"));
        assert!(post.body.contains("<Name>my-pc.example.com.</Name>"));
        // DELETE 必须带当前全部 Value（否则 Route53 校验失败）。
        assert!(post.body.contains("<Value>192.0.2.1</Value>"));
        assert!(post.body.contains("<Value>192.0.2.2</Value>"));

        // 不存在的记录集 → NotFound，且不再发 DELETE。
        let posts_before = mock.count("POST", "/rrset");
        let err = p
            .delete_record("example.com", "ghost", RecordType::A)
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
        assert_eq!(mock.count("POST", "/rrset"), posts_before);
    }

    /// 7. SRV/MX 结构化往返（单值字符串 ↔ RecordData::Srv/Mx）。
    #[tokio::test]
    async fn srv_mx_structured_roundtrip() {
        let mock = MockRoute53::start().await;
        mock.set_zones(&[("Z1", "example.com")]);
        mock.set_rrsets(&[
            (
                "_sip._tcp.example.com.".into(),
                "SRV".into(),
                60,
                vec!["0 5 5060 sip.example.com.".into()],
            ),
            (
                "example.com.".into(),
                "MX".into(),
                300,
                vec!["10 mail.example.com.".into()],
            ),
        ]);
        let p = provider(&mock);

        let all = p.query_records("example.com", None, None).await.expect("all");
        assert_eq!(all.len(), 2);
        let srv = all.iter().find(|r| r.rtype == RecordType::SRV).expect("srv");
        assert_eq!(srv.name, "_sip._tcp");
        assert_eq!(srv.ttl, 60);
        assert_eq!(
            srv.data,
            RecordData::Srv {
                priority: 0,
                weight: 5,
                port: 5060,
                target: "sip.example.com.".into()
            }
        );
        let mx = all.iter().find(|r| r.rtype == RecordType::MX).expect("mx");
        assert_eq!(mx.name, "");
        assert_eq!(
            mx.data,
            RecordData::Mx {
                priority: 10,
                exchange: "mail.example.com.".into()
            }
        );

        // upsert SRV：新端口追加，原值保留（单值字符串 "0 5 5061 tgt."）。
        p.upsert_record(
            "example.com",
            &rec(
                "_sip._tcp",
                RecordType::SRV,
                RecordData::Srv {
                    priority: 0,
                    weight: 5,
                    port: 5061,
                    target: "sip2.example.com".into(),
                },
                60,
            ),
        )
        .await
        .expect("upsert srv");
        let reqs = mock.requests();
        let post = reqs
            .iter()
            .filter(|r| r.method == "POST")
            .last()
            .expect("POST");
        assert!(post.body.contains("<Value>0 5 5060 sip.example.com.</Value>"));
        assert!(post.body.contains("<Value>0 5 5061 sip2.example.com.</Value>"));
    }

    /// 8. 错误码映射：Auth / InvalidParameter / NotFound / RateLimited / Server。
    #[tokio::test]
    async fn error_code_mapping() {
        let mock = MockRoute53::start().await;
        let p = provider(&mock);

        // 凭据错误 → Auth。
        mock.fail_once(403, &err_xml("InvalidClientTokenId", "bad key"), None);
        let e = p.list_domains().await.unwrap_err();
        assert!(matches!(e, ProviderError::Auth { .. }), "{e:?}");

        // 参数非法 → InvalidParameter。
        mock.fail_once(400, &err_xml("InvalidChangeBatch", "bad batch"), None);
        let e = p.list_domains().await.unwrap_err();
        assert!(matches!(e, ProviderError::InvalidParameter { .. }), "{e:?}");

        // zone 不存在 → NotFound。
        mock.fail_once(400, &err_xml("NoSuchHostedZone", "no zone"), None);
        let e = p.list_domains().await.unwrap_err();
        assert!(matches!(e, ProviderError::NotFound { .. }), "{e:?}");

        // 限流 → RateLimited（带 Retry-After 头）。
        mock.fail_once(429, &err_xml("Throttling", "slow down"), Some("42"));
        let e = p.list_domains().await.unwrap_err();
        match e {
            ProviderError::RateLimited { retry_after } => assert_eq!(retry_after, Some(42)),
            other => panic!("expected RateLimited, got {other:?}"),
        }

        // 服务端 → Server。
        mock.fail_once(500, &err_xml("InternalFailure", "boom"), None);
        let e = p.list_domains().await.unwrap_err();
        assert!(matches!(e, ProviderError::Server { status: 500, .. }), "{e:?}");

        // 无 XML 的 404 兜底 → NotFound。
        mock.fail_once(404, "", None);
        let e = p.list_domains().await.unwrap_err();
        assert!(matches!(e, ProviderError::NotFound { .. }), "{e:?}");
    }

    /// 9. 能力全开；test_connection 走最小查询（maxitems=1）。
    #[tokio::test]
    async fn capabilities_and_test_connection() {
        let mock = MockRoute53::start().await;
        mock.set_zones(&[("Z1", "example.com")]);
        let p = provider(&mock);
        let caps = p.capabilities();
        assert!(caps.srv && caps.ns && caps.ttl && caps.rename);

        p.test_connection().await.expect("test connection");
        let req = mock.requests().into_iter().next().expect("one request");
        assert!(req.path.starts_with("/2013-04-01/hostedzone"));
        assert!(req.path.contains("maxitems=1"), "最小查询: {0}", req.path);
    }
}
