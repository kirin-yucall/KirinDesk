//! M9-DNS001: GoDaddy 服务商适配（P0 改造基准，`M9-DNS001_GoDaddy服务商适配.md`）。
//!
//! 旧 `dns/src/godaddy/` 逻辑迁入本目录并实现 `Provider` trait——本模块
//! **完全自包含**，不引用旧 godaddy 目录（旧模块由 Stage 3 删除）。上层
//! （discovery / heartbeat / srv / aaaa / txt / UI / CLI）只依赖
//! `crate::provider` 抽象层（`dyn Provider`）。
//!
//! 差异点消化：
//! - 认证：`Authorization: sso-key {key}:{secret}`（[`auth`]）；
//! - 记录名：统一相对名（"" = 根）↔ GoDaddy `@`（[`record`]）；
//! - SRV：单字符串 `0 1 {port} {target}.` ↔ `RecordData::Srv`（[`record`]）；
//! - 写入语义：GoDaddy PUT 整组替换 → upsert **先查后写**（保留同 name+type
//!   其他条）、delete = PUT 空数组（本文件 `impl Provider`）；
//! - 错误映射 + 429 指数退避重试（[`error`] / [`client`]）。

pub mod auth;
pub mod client;
pub mod error;
pub mod record;

pub use auth::Auth;
pub use client::GodaddyClient;
pub use record::{ManagedRecord, SrvData, WireRecord};

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordType,
};
use record::{managed_to_record, record_to_wire, wire_matches_rec, wire_to_record};
use std::time::Duration;
use tracing::debug;

/// GoDaddy 服务商 `Provider` 实现（薄封装：[`GodaddyClient`] 承载 HTTP 细节）。
#[derive(Clone)]
pub struct GodaddyProvider {
    client: GodaddyClient,
}

impl GodaddyProvider {
    /// 便捷构造：api_url 非法（非 https 且非环回、未设 env 放行）时 panic。
    ///
    /// 生产配置必须使用 https（S-14a / F-17）；测试/本地 mock 用
    /// `http://127.0.0.1` 环回地址（自动放行，无需开关），其他测试环境可设
    /// env `KIRIN_DNS_ALLOW_HTTP`（详见 [`GodaddyClient::try_new`]）。
    pub fn new(
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
        api_url: impl Into<String>,
    ) -> Self {
        Self::try_new(api_key, api_secret, api_url).expect(
            "GodaddyProvider::new: api_url 必须以 'https://' 开头 \
             （测试环回地址 http://127.0.0.1 自动放行；其他测试环境可设 env KIRIN_DNS_ALLOW_HTTP）",
        )
    }

    /// 可失败构造（https 强制 / 环回与 env 放行，见 [`GodaddyClient::try_new`]）。
    pub fn try_new(
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
        api_url: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            client: GodaddyClient::try_new(api_key, api_secret, api_url)?,
        })
    }

    /// 调整 429 重试的初始退避时长（测试/本地 mock 用；生产保持 1s）。
    pub fn with_backoff_base(mut self, base: Duration) -> Self {
        self.client = self.client.with_backoff_base(base);
        self
    }
}

#[async_trait::async_trait]
impl Provider for GodaddyProvider {
    fn name(&self) -> &'static str {
        "godaddy"
    }

    /// 最小查询：GET /v1/domains?limit=1（DNS-MNT-003）。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.test_connection().await
    }

    /// GET /v1/domains —— 域名列表（DNS-MNT-004）。
    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.client.list_domains().await
    }

    /// 查询记录（M9-DNS001 §三）：
    /// - `(Some(name), Some(rtype))` → `GET /records/{type}/{name}`（服务端已过滤）；
    /// - 其余组合 → `GET /v1/domains/{domain}/records` 全表 + 客户端过滤。
    ///
    /// 返回统一 `Record{name=相对名, rtype, ttl, data}`；全表路径中未知类型
    /// 记录（如 CAA 等长尾类型）跳过，不使整表查询失败。
    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        match (name, rtype) {
            (Some(n), Some(t)) => {
                // 精确端点：GET /records/{type}/{name}（404 = 空组）。
                let wires = self.client.get_records_group(domain, t.as_str(), n).await?;
                wires
                    .iter()
                    .map(|w| wire_to_record(w, t, n))
                    .collect::<Result<Vec<_>, _>>()
            }
            _ => {
                let mut out = Vec::new();
                for mr in self.client.get_all_records(domain).await? {
                    // 未知类型（SOA/CAA 等长尾）跳过，全表查询不因此失败。
                    let Ok(rt) = mr.rtype.parse::<RecordType>() else {
                        debug!("跳过未知类型记录: {}", mr.rtype);
                        continue;
                    };
                    if let Some(t) = rtype {
                        if rt != t {
                            continue;
                        }
                    }
                    let rec = managed_to_record(&mr)?;
                    if let Some(n) = name {
                        if rec.name != n {
                            continue;
                        }
                    }
                    out.push(rec);
                }
                Ok(out)
            }
        }
    }

    /// 幂等写入单条记录：**先查后写**（M9-DNS001 §三 / M9-DNS000 §四）。
    ///
    /// GoDaddy PUT 是整组替换：若直接 PUT 单条会清掉同 name+type 其他记录。
    /// 故流程为：GET 现有组（404 = 空组）→ 保留非目标条 + 替换/追加目标条
    /// （同 data 视为同一条，更新 TTL）→ PUT 整组替换。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let existing = self
            .client
            .get_records_group(domain, rec.rtype.as_str(), &rec.name)
            .await?;
        let mut target: Vec<WireRecord> = existing
            .into_iter()
            .filter(|w| !wire_matches_rec(w, rec))
            .collect();
        target.push(record_to_wire(rec));
        self.client
            .put_records(domain, rec.rtype.as_str(), &rec.name, &target)
            .await
    }

    /// 删除该 name+rtype 下全部记录：GoDaddy 语义 = `PUT /records/{type}/{name}`
    /// 空数组 `[]`（M9-DNS001 §三）。
    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        self.client.put_records(domain, rtype.as_str(), name, &[]).await
    }

    /// 能力声明：GoDaddy 全能力（SRV/NS/TTL/rename 全开，M9-DNS001 §二）。
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

/// 注册到服务商注册表（M9-DNS000 §四；由 `providers::register_all` 集成调用）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register("godaddy", |cred| -> Box<dyn Provider> {
        match cred {
            Credential::Godaddy {
                api_key,
                api_secret,
                api_url,
            } => Box::new(GodaddyProvider::new(
                api_key.clone(),
                api_secret.clone(),
                api_url.clone(),
            )),
            // 注册表按 name 分发，凭据变体不匹配仅可能因配置层 bug——显式
            // panic 尽早暴露。不打印凭据内容（凭据不参与日志输出）。
            _ => panic!("godaddy::register: 凭据变体不匹配（预期 Credential::Godaddy）"),
        }
    } as fn(&Credential) -> Box<dyn Provider>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Record, RecordData};
    use std::collections::{HashMap, VecDeque};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    // ────────────────────────────────────────────────────────────────
    // 契约测试 mock HTTP server（参考 `test_support::MockDns` 模式：
    // TcpListener + 每连接任务 + 手写 HTTP 响应；响应带 Connection: close，
    // 每个请求一个连接，顺序与脚本一一对应）。
    // ────────────────────────────────────────────────────────────────

    /// 收到的 HTTP 请求（契约断言用）。
    #[derive(Debug, Clone)]
    struct MockRequest {
        method: String,
        /// 请求路径（含 query）。
        path: String,
        /// 请求头（键小写）。
        headers: HashMap<String, String>,
        body: String,
    }

    /// 脚本化响应（按请求顺序消费；脚本耗尽 → 500）。
    struct MockResponse {
        status: u16,
        /// 附加响应头（如 Retry-After）。
        headers: Vec<(String, String)>,
        body: String,
    }

    fn resp(status: u16, body: &str) -> MockResponse {
        MockResponse {
            status,
            headers: vec![],
            body: body.to_string(),
        }
    }

    fn resp_with_headers(status: u16, headers: &[(&str, &str)], body: &str) -> MockResponse {
        MockResponse {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
        }
    }

    /// 契约测试 mock server。
    struct MockServer {
        addr: SocketAddr,
        log: Arc<Mutex<Vec<MockRequest>>>,
        script: Arc<Mutex<VecDeque<MockResponse>>>,
    }

    impl MockServer {
        async fn start(script: Vec<MockResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("绑定 mock server 失败");
            let addr = listener.local_addr().expect("mock server 地址");
            let log = Arc::new(Mutex::new(Vec::new()));
            let script = Arc::new(Mutex::new(VecDeque::from(script)));

            let server_log = log.clone();
            let server_script = script.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(conn) => conn,
                        Err(_) => break,
                    };
                    let conn_log = server_log.clone();
                    let conn_script = server_script.clone();
                    tokio::spawn(async move {
                        let _ = handle_conn(stream, conn_log, conn_script).await;
                    });
                }
            });

            Self { addr, log, script }
        }

        /// 指向 mock 的 http://127.0.0.1 基址（环回自动放行，无需开关）。
        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        /// 全部收到的请求（按时间顺序）。
        fn requests(&self) -> Vec<MockRequest> {
            self.log.lock().unwrap().clone()
        }
    }

    /// 单连接处理：读请求行/头/体 → 记录日志 → 弹出脚本响应写回。
    async fn handle_conn(
        mut stream: TcpStream,
        log: Arc<Mutex<Vec<MockRequest>>>,
        script: Arc<Mutex<VecDeque<MockResponse>>>,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(&mut stream);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;

        let mut content_length = 0usize;
        let mut headers = HashMap::new();
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
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).await?;
        let body = String::from_utf8_lossy(&body).to_string();

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();

        log.lock().unwrap().push(MockRequest {
            method,
            path,
            headers,
            body,
        });

        let r = script.lock().unwrap().pop_front().unwrap_or(MockResponse {
            status: 500,
            headers: vec![],
            body: String::new(),
        });
        let reason = match r.status {
            200 => "OK",
            401 => "Unauthorized",
            404 => "Not Found",
            422 => "Unprocessable Entity",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "Error",
        };
        let mut raw = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            r.status,
            reason,
            r.body.len()
        );
        for (k, v) in &r.headers {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str("\r\n");
        raw.push_str(&r.body);
        stream.write_all(raw.as_bytes()).await?;
        stream.flush().await
    }

    /// 测试 Provider：环回 http 自动放行 + 微小退避（429 用例快速通过）。
    fn test_provider(base: &str) -> GodaddyProvider {
        GodaddyProvider::new("test_key", "test_secret", base)
            .with_backoff_base(Duration::from_millis(2))
    }

    // ────────────────────────────────────────────────────────────────
    // 契约测试（M9-DNS000 §七 适配层模板）
    // ────────────────────────────────────────────────────────────────

    /// 契约 1：认证头形状 `Authorization: sso-key {key}:{secret}`。
    #[tokio::test]
    async fn auth_header_shape() {
        let mock = MockServer::start(vec![resp(200, r#"[{"domain":"example.com"}]"#)]).await;
        let p = test_provider(&mock.base_url());
        p.test_connection().await.unwrap();

        let reqs = mock.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].path, "/v1/domains?limit=1");
        assert_eq!(
            reqs[0].headers.get("authorization").map(String::as_str),
            Some("sso-key test_key:test_secret")
        );
    }

    /// 契约 2：list_domains 解析（含空账号空列表）。
    #[tokio::test]
    async fn list_domains_parses() {
        let mock = MockServer::start(vec![
            resp(
                200,
                r#"[{"domain":"example.com","status":"ACTIVE"},{"domain":"kirin.dev"}]"#,
            ),
            resp(200, "[]"),
        ])
        .await;
        let p = test_provider(&mock.base_url());

        assert_eq!(
            p.list_domains().await.unwrap(),
            vec!["example.com", "kirin.dev"]
        );
        // 空账号 → 空列表而非错误。
        assert!(p.list_domains().await.unwrap().is_empty());
    }

    /// 契约 3：upsert 先查后写——同 name 其他记录不丢。
    ///
    /// 断言请求序列：GET（先查）→ PUT（后写）；PUT body 含保留条 + 目标条
    /// （同 data → 替换 TTL；新 data → 追加）。
    #[tokio::test]
    async fn upsert_preserves_same_name_records() {
        let existing = r#"[{"data":"203.0.113.7","ttl":600},{"data":"198.51.100.9","ttl":600}]"#;
        let mock = MockServer::start(vec![
            resp(200, existing), // 先查：GET /records/A/my-pc
            resp(200, ""),       // 后写：PUT（同 data 条 → 替换 TTL）
            resp(200, existing), // 再查
            resp(200, ""),       // 再写（新 data → 追加）
        ])
        .await;
        let p = test_provider(&mock.base_url());

        // 同 data upsert → 更新 TTL，另一条保留。
        p.upsert_record(
            "example.com",
            &Record {
                name: "my-pc".to_string(),
                rtype: RecordType::A,
                ttl: 300,
                data: RecordData::Plain("203.0.113.7".to_string()),
            },
        )
        .await
        .unwrap();

        // 新 data upsert → 追加，原两条保留。
        p.upsert_record(
            "example.com",
            &Record {
                name: "my-pc".to_string(),
                rtype: RecordType::A,
                ttl: 600,
                data: RecordData::Plain("192.0.2.55".to_string()),
            },
        )
        .await
        .unwrap();

        let reqs = mock.requests();
        assert_eq!(reqs.len(), 4, "先查后写：GET + PUT × 2");
        assert_eq!(reqs[0].method, "GET", "第 1 个请求必须是先查");
        assert_eq!(reqs[1].method, "PUT", "第 2 个请求是后写");
        assert_eq!(reqs[1].path, "/v1/domains/example.com/records/A/my-pc");

        let put1: Vec<WireRecord> = serde_json::from_str(&reqs[1].body).unwrap();
        assert_eq!(put1.len(), 2, "同 data 条被替换（TTL 300），另一条保留");
        assert!(put1.iter().any(|w| w.data == "203.0.113.7" && w.ttl == 300));
        assert!(put1.iter().any(|w| w.data == "198.51.100.9" && w.ttl == 600));

        let put2: Vec<WireRecord> = serde_json::from_str(&reqs[3].body).unwrap();
        assert_eq!(put2.len(), 3, "新增条追加，原两条不丢");
        assert!(put2.iter().any(|w| w.data == "192.0.2.55" && w.ttl == 600));
    }

    /// 契约 4：delete = PUT 空数组（断言请求方法与 body）。
    #[tokio::test]
    async fn delete_puts_empty_array() {
        let mock = MockServer::start(vec![resp(200, "")]).await;
        let p = test_provider(&mock.base_url());

        p.delete_record("example.com", "my-pc", RecordType::A)
            .await
            .unwrap();

        let reqs = mock.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PUT");
        assert_eq!(reqs[0].path, "/v1/domains/example.com/records/A/my-pc");
        assert_eq!(reqs[0].body, "[]", "删除 = PUT 空数组");
    }

    /// 契约 5：错误码映射 401→Auth / 404→NotFound / 429→RateLimited（含退避重试）。
    #[tokio::test]
    async fn error_code_mapping() {
        // 401 → Auth。
        let mock = MockServer::start(vec![resp(401, "unauthorized")]).await;
        let p = test_provider(&mock.base_url());
        let err = p.test_connection().await.unwrap_err();
        assert!(matches!(err, ProviderError::Auth { .. }));

        // 404 → NotFound（域名级 404：全表端点，what 含域名上下文）。
        let mock = MockServer::start(vec![resp(404, "")]).await;
        let p = test_provider(&mock.base_url());
        let err = p.query_records("example.com", None, None).await.unwrap_err();
        match err {
            ProviderError::NotFound { what } => assert!(what.contains("example.com")),
            e => panic!("expected NotFound, got {e:?}"),
        }

        // 429 ×3 → 退避重试 2 次后返回 RateLimited（读 Retry-After 头）。
        let mock = MockServer::start(vec![
            resp_with_headers(429, &[("Retry-After", "12")], ""),
            resp_with_headers(429, &[("Retry-After", "12")], ""),
            resp_with_headers(429, &[("Retry-After", "12")], ""),
        ])
        .await;
        let p = test_provider(&mock.base_url());
        let err = p.test_connection().await.unwrap_err();
        match err {
            ProviderError::RateLimited { retry_after } => {
                assert_eq!(retry_after, Some(12), "retry_after 取自 Retry-After 头");
            }
            e => panic!("expected RateLimited, got {e:?}"),
        }
        assert_eq!(mock.requests().len(), 3, "429 重试 3 次请求（退避 2 次）");
    }

    /// 契约 6：SRV data ↔ RecordData::Srv 往返（查询解析 + 写入格式化）。
    #[tokio::test]
    async fn srv_roundtrip() {
        let mock = MockServer::start(vec![
            // 查询：GET /records/SRV/_remote._tcp.my-pc → data 单字符串。
            resp(200, r#"[{"data":"0 1 3389 my-pc.example.com.","ttl":600}]"#),
            // upsert：先查（404 = 空组）→ 后写（PUT body 为格式化 SRV 字符串）。
            resp(404, ""),
            resp(200, ""),
        ])
        .await;
        let p = test_provider(&mock.base_url());

        // 查询方向：单字符串 → RecordData::Srv。
        let found = p
            .query_records("example.com", Some("_remote._tcp.my-pc"), Some(RecordType::SRV))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "_remote._tcp.my-pc");
        assert_eq!(found[0].ttl, 600);
        match &found[0].data {
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                assert_eq!((*priority, *weight, *port), (0, 1, 3389));
                assert_eq!(target, "my-pc.example.com.");
            }
            other => panic!("expected Srv data, got {other:?}"),
        }

        // 写入方向：RecordData::Srv → "0 1 3389 my-pc.example.com."。
        p.upsert_record(
            "example.com",
            &Record {
                name: "_remote._tcp.my-pc".to_string(),
                rtype: RecordType::SRV,
                ttl: 600,
                data: RecordData::Srv {
                    priority: 0,
                    weight: 1,
                    port: 3389,
                    target: "my-pc.example.com.".to_string(),
                },
            },
        )
        .await
        .unwrap();

        let reqs = mock.requests();
        assert_eq!(reqs.len(), 3);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[2].method, "PUT");
        assert_eq!(
            reqs[2].path,
            "/v1/domains/example.com/records/SRV/_remote._tcp.my-pc"
        );
        let put: Vec<WireRecord> = serde_json::from_str(&reqs[2].body).unwrap();
        assert_eq!(put.len(), 1);
        assert_eq!(put[0].data, "0 1 3389 my-pc.example.com.");
        assert_eq!(put[0].ttl, 600);
    }

    /// 补充：query_records 全表 + 客户端过滤（含 "@" → "" 根名归一）。
    #[tokio::test]
    async fn query_records_full_table_and_filter() {
        let full_table = r#"[
                {"type":"A","name":"@","data":"203.0.113.7","ttl":600},
                {"type":"A","name":"my-pc","data":"198.51.100.9","ttl":600},
                {"type":"AAAA","name":"my-pc","data":"2001:db8::1","ttl":600},
                {"type":"SOA","name":"@","data":"ns1.example.com","ttl":3600}
            ]"#;
        let mock = MockServer::start(vec![
            resp(200, full_table), // 全表查询
            resp(200, full_table), // 按 name 过滤（走全表 + 客户端过滤）
            resp(200, r#"[{"data":"198.51.100.9","ttl":600}]"#), // name+type → 精确端点
        ])
        .await;
        let p = test_provider(&mock.base_url());

        // 全表：SOA 未知类型跳过，剩 3 条。
        let all = p.query_records("example.com", None, None).await.unwrap();
        assert_eq!(all.len(), 3);
        // 按 name 过滤（根记录相对名 ""）。
        let root = p.query_records("example.com", Some(""), None).await.unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].data, RecordData::Plain("203.0.113.7".into()));
        // 按 name + type 组合（走 /records/{type}/{name} 精确端点）。
        let both = p
            .query_records("example.com", Some("my-pc"), Some(RecordType::A))
            .await
            .unwrap();
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].data, RecordData::Plain("198.51.100.9".into()));
    }

    /// 补充：register 注册表注册 / name / capabilities 全开 / build 成功。
    #[test]
    fn register_build_name_and_capabilities() {
        let mut registry = ProviderRegistry::new();
        register(&mut registry);
        assert!(registry.names().contains(&"godaddy"));

        let cred = Credential::Godaddy {
            api_key: "k".to_string(),
            api_secret: "s".to_string(),
            api_url: "https://api.godaddy.com".to_string(),
        };
        let p = registry.build("godaddy", &cred).unwrap();
        assert_eq!(p.name(), "godaddy");
        let caps = p.capabilities();
        assert!(caps.srv && caps.ns && caps.ttl && caps.rename, "能力全开");
    }

    /// 补充：429 重试后在中间次返回 200 → 成功（退避重试恢复路径）。
    #[tokio::test]
    async fn rate_limit_then_success() {
        let mock = MockServer::start(vec![
            resp_with_headers(429, &[("Retry-After", "3")], ""),
            resp_with_headers(429, &[("Retry-After", "3")], ""),
            resp(200, r#"[{"domain":"example.com"}]"#),
        ])
        .await;
        let p = test_provider(&mock.base_url());
        p.test_connection().await.unwrap();
        assert_eq!(mock.requests().len(), 3, "前两次 429 退避后第三次成功");
    }
}
