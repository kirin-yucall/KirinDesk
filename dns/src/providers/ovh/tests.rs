//! M9-DNS014 契约测试：自写 tokio mock HTTP server（127.0.0.1）+ 录制官方响应样例。
//!
//! 覆盖（对照 `M9-DNS000_Provider抽象接口规范.md` §七 契约模板）：
//! 1. 认证形状（X-Ovh-* 头 + `$1$` 签名可复算，URL 含 base、body 参与签名）
//! 2. list_domains 解析
//! 3. 相对名 ↔ OVH subDomain 互转（空 = 根）；SRV/MX target 单字符串解析
//! 4. upsert（create/update 分派 + 写后 refresh；幂等二次写 → PUT）
//! 5. delete（+ refresh；删不存在 → NotFound 不 refresh）
//! 6. 错误码映射（Auth/InvalidParameter/NotFound/RateLimited/Server）
//! 7. SRV 往返（target 单字符串）+ 时间戳偏差自动校准重试

use super::client::OvhRecord;
use super::sign::signature;
use super::OvhProvider;
use crate::provider::{Provider, ProviderError, Record, RecordData, RecordType};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

// ────────────────────────────────────────────────────────────────
// 微型 mock HTTP server（参考 dns/src/test_support.rs MockDns 模式）
// ────────────────────────────────────────────────────────────────

/// 捕获到的请求。
#[derive(Debug, Clone)]
struct MockRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl MockRequest {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::json!({}))
    }
    /// 完整请求 URL（签名用）：http://{Host 头}{path}（Host 头含端口）。
    fn request_url(&self) -> String {
        let host = self.header("Host").unwrap_or_default();
        format!("http://{host}{}", self.path)
    }
}

struct MockResponse {
    status: u16,
    body: String,
}

impl MockResponse {
    fn json(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
        }
    }
    fn error(status: u16, class: &str, message: &str) -> Self {
        Self {
            status,
            body: format!(r#"{{"class":"{class}","message":"{message}"}}"#),
        }
    }
}

/// 运行中的 mock server。
struct MockApi {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<MockRequest>>>,
}

impl MockApi {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&MockRequest) -> MockResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定 mock server 失败");
        let addr = listener.local_addr().expect("mock 地址");
        let requests: Arc<Mutex<Vec<MockRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);
        let reqs = requests.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let h = handler.clone();
                let reqs = reqs.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, &h, &reqs).await;
                });
            }
        });
        Self { addr, requests }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<MockRequest> {
        self.requests.lock().unwrap().clone()
    }
}

async fn handle_connection<F>(
    mut stream: TcpStream,
    handler: &Arc<F>,
    requests: &Arc<Mutex<Vec<MockRequest>>>,
) -> std::io::Result<()>
where
    F: Fn(&MockRequest) -> MockResponse + Send + Sync,
{
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await? == 0 {
        return Ok(());
    }
    let mut headers = Vec::new();
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
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
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
    let req = MockRequest {
        method,
        path,
        headers,
        body,
    };
    requests.lock().unwrap().push(req.clone());

    let resp = handler(&req);
    let raw = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_line(resp.status),
        resp.body.len(),
        resp.body
    );
    stream.write_all(raw.as_bytes()).await?;
    stream.flush().await
}

fn status_line(status: u16) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    format!("{status} {reason}")
}

/// 构造指向 mock 的 Provider（凭据为测试固定值；app_secret 供服务端复算签名）。
const TEST_APP_KEY: &str = "app_key_1";
const TEST_APP_SECRET: &str = "app_secret_2";
const TEST_CONSUMER_KEY: &str = "consumer_key_3";

async fn provider_with(mock: &MockApi) -> OvhProvider {
    OvhProvider::new_at(
        TEST_APP_KEY.to_string(),
        TEST_APP_SECRET.to_string(),
        TEST_CONSUMER_KEY.to_string(),
        mock.base_url(),
    )
}

/// 校验请求的签名头：用捕获的 method/完整 URL（含 Host）/body/ts 复算并比对。
fn assert_signature_ok(req: &MockRequest) {
    let sig = req.header("X-Ovh-Signature").expect("缺少 X-Ovh-Signature");
    assert!(sig.starts_with("$1$"), "签名需带 $1$ 前缀");
    let ts: i64 = req
        .header("X-Ovh-Timestamp")
        .expect("缺少 X-Ovh-Timestamp")
        .parse()
        .unwrap();
    let expected = signature(
        TEST_APP_SECRET,
        TEST_CONSUMER_KEY,
        &req.method,
        &req.request_url(),
        &req.body,
        ts,
    );
    assert_eq!(
        sig,
        expected,
        "签名可复算（method={} path={} body={}）",
        req.method,
        req.path,
        req.body
    );
}

// ────────────────────────────────────────────────────────────────
// 契约测试
// ────────────────────────────────────────────────────────────────

/// 1+2. 认证形状：X-Ovh-* 四头 + `$1$` 签名可复算；list_domains 解析。
#[tokio::test]
async fn auth_headers_and_list_domains() {
    let mock = MockApi::start(|req| {
        // 服务端复算签名（与实际 OVH 行为一致：验签失败 → 401）。
        let ts: i64 = req.header("X-Ovh-Timestamp").unwrap().parse().unwrap();
        let expected = signature(
            TEST_APP_SECRET,
            TEST_CONSUMER_KEY,
            &req.method,
            &req.request_url(),
            &req.body,
            ts,
        );
        if req.header("X-Ovh-Signature").as_deref() != Some(expected.as_str()) {
            return MockResponse::error(401, "Client::Unauthorized", "NOT_CREDENTIALS");
        }
        MockResponse::json(r#"["example.com","kirin.dev"]"#)
    })
    .await;
    let p = provider_with(&mock).await;
    let domains = p.list_domains().await.unwrap();
    assert_eq!(domains, vec!["example.com", "kirin.dev"]);

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, "/domain/zone");
    assert_eq!(
        reqs[0].header("X-Ovh-Application").as_deref(),
        Some(TEST_APP_KEY)
    );
    assert_eq!(
        reqs[0].header("X-Ovh-Consumer").as_deref(),
        Some(TEST_CONSUMER_KEY)
    );
    assert!(reqs[0].header("X-Ovh-Timestamp").is_some());
    assert_signature_ok(&reqs[0]);
}

/// 3. 相对名互转：subDomain 空 = 根；SRV/MX target 单字符串解析；未知类型跳过。
#[tokio::test]
async fn query_records_converts_subdomain_and_combined_targets() {
    let state: Arc<Mutex<Vec<OvhRecord>>> = Arc::new(Mutex::new(vec![
        OvhRecord {
            id: 1,
            zone: "example.com".into(),
            field_type: "A".into(),
            sub_domain: String::new(),
            target: "203.0.113.7".into(),
            ttl: 3600,
        },
        OvhRecord {
            id: 2,
            zone: "example.com".into(),
            field_type: "SRV".into(),
            sub_domain: "_remote._tcp".into(),
            target: "0 1 3389 my-pc.example.com.".into(),
            ttl: 3600,
        },
        OvhRecord {
            id: 3,
            zone: "example.com".into(),
            field_type: "MX".into(),
            sub_domain: String::new(),
            target: "10 mail.example.com.".into(),
            ttl: 0,
        },
        OvhRecord {
            id: 4,
            zone: "example.com".into(),
            field_type: "SPF".into(),
            sub_domain: String::new(),
            target: "v=spf1 -all".into(),
            ttl: 3600,
        },
    ]));
    let mock = MockApi::start({
        let state = state.clone();
        move |req| {
            // 验签（完整 URL + body）。
            let ts: i64 = req.header("X-Ovh-Timestamp").unwrap().parse().unwrap();
            let expected = signature(
                TEST_APP_SECRET,
                TEST_CONSUMER_KEY,
                &req.method,
                &req.request_url(),
                &req.body,
                ts,
            );
            if req.header("X-Ovh-Signature").as_deref() != Some(expected.as_str()) {
                return MockResponse::error(401, "Client::Unauthorized", "NOT_CREDENTIALS");
            }
            let st = state.lock().unwrap();
            if let Some(id) = req.path.strip_prefix("/domain/zone/example.com/record/") {
                // 详情优先匹配（避免被列表前缀误判）。
                let id: i64 = id.parse().unwrap();
                let rec = st.iter().find(|r| r.id == id).expect("record 存在");
                MockResponse::json(serde_json::to_string(rec).unwrap())
            } else if req.path.starts_with("/domain/zone/example.com/record") {
                // id 列表（带或不带查询串 fieldType/subDomain）。
                let ids: Vec<i64> = st.iter().map(|r| r.id).collect();
                MockResponse::json(format!("{ids:?}"))
            } else {
                MockResponse::error(404, "Client::NotFound", "NOT_FOUND")
            }
        }
    })
    .await;
    let p = provider_with(&mock).await;
    let all = p.query_records("example.com", None, None).await.unwrap();
    // SPF 无法表达 → 跳过；其余 3 条。
    assert_eq!(all.len(), 3);
    let root_a = all.iter().find(|r| r.rtype == RecordType::A).unwrap();
    assert_eq!(root_a.name, "", "subDomain 空 = 根");
    assert_eq!(root_a.ttl, 3600);
    let srv = all.iter().find(|r| r.rtype == RecordType::SRV).unwrap();
    assert_eq!(srv.name, "_remote._tcp");
    match &srv.data {
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            assert_eq!((*priority, *weight, *port), (0, 1, 3389));
            assert_eq!(target, "my-pc.example.com.");
        }
        other => panic!("期望 Srv 数据，实际 {other:?}"),
    }
    let mx = all.iter().find(|r| r.rtype == RecordType::MX).unwrap();
    assert_eq!(
        mx.data,
        RecordData::Mx {
            priority: 10,
            exchange: "mail.example.com.".into()
        }
    );
    assert_eq!(mx.ttl, 3600, "ttl=0 → 官方默认 3600 归一化");
    // 过滤。
    let filtered = p
        .query_records("example.com", Some("_remote._tcp"), Some(RecordType::SRV))
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
}

/// 4. upsert：存在 → PUT；不存在 → POST；写后必调 refresh；幂等二次写 → PUT。
#[tokio::test]
async fn upsert_dispatches_create_or_update_and_refreshes() {
    let state: Arc<Mutex<Vec<OvhRecord>>> = Arc::new(Mutex::new(vec![OvhRecord {
        id: 42,
        zone: "example.com".into(),
        field_type: "A".into(),
        sub_domain: String::new(),
        target: "203.0.113.7".into(),
        ttl: 3600,
    }]));
    let next_id = Arc::new(Mutex::new(100i64));
    let mock = MockApi::start({
        let state = state.clone();
        let next_id = next_id.clone();
        move |req| {
            // 验签（完整 URL + body 原样）。
            let ts: i64 = req.header("X-Ovh-Timestamp").unwrap().parse().unwrap();
            let expected = signature(
                TEST_APP_SECRET,
                TEST_CONSUMER_KEY,
                &req.method,
                &req.request_url(),
                &req.body,
                ts,
            );
            if req.header("X-Ovh-Signature").as_deref() != Some(expected.as_str()) {
                return MockResponse::error(401, "Client::Unauthorized", "NOT_CREDENTIALS");
            }
            match req.method.as_str() {
                "GET" if req.path.starts_with("/domain/zone/example.com/record?") => {
                    let st = state.lock().unwrap();
                    let ids: Vec<i64> = st.iter().map(|r| r.id).collect();
                    MockResponse::json(format!("{ids:?}"))
                }
                "GET" if req.path.starts_with("/domain/zone/example.com/record/") => {
                    let id: i64 = req.path.rsplit('/').next().unwrap().parse().unwrap();
                    let st = state.lock().unwrap();
                    let rec = st.iter().find(|r| r.id == id).unwrap();
                    MockResponse::json(serde_json::to_string(rec).unwrap())
                }
                "PUT" if req.path.starts_with("/domain/zone/example.com/record/") => {
                    let id: i64 = req.path.rsplit('/').next().unwrap().parse().unwrap();
                    let mut st = state.lock().unwrap();
                    if let Some(rec) = st.iter_mut().find(|r| r.id == id) {
                        let body = req.json();
                        rec.target = body["target"].as_str().unwrap_or("").to_string();
                        rec.ttl = body["ttl"].as_u64().unwrap_or(0) as u32;
                    }
                    MockResponse::json("{}")
                }
                "POST" if req.path == "/domain/zone/example.com/record" => {
                    let mut st = state.lock().unwrap();
                    let mut nid = next_id.lock().unwrap();
                    *nid += 1;
                    let mut rec: OvhRecord = serde_json::from_value(req.json()).unwrap();
                    rec.id = *nid;
                    st.push(rec.clone());
                    MockResponse::json(serde_json::to_string(&rec).unwrap())
                }
                "POST" if req.path == "/domain/zone/example.com/refresh" => MockResponse::json("{}"),
                _ => MockResponse::error(404, "Client::NotFound", "NOT_FOUND"),
            }
        }
    })
    .await;
    let p = provider_with(&mock).await;

    // ── ① 已存在根 A（id=42）→ PUT + refresh。
    let rec = Record {
        name: String::new(),
        rtype: RecordType::A,
        ttl: 600,
        data: RecordData::Plain("9.9.9.9".into()),
    };
    p.upsert_record("example.com", &rec).await.unwrap();
    let reqs = mock.requests();
    // GET list → GET detail → PUT → refresh。
    assert_eq!(reqs.len(), 4);
    assert_eq!(reqs[0].method, "GET");
    assert!(reqs[0].path.starts_with("/domain/zone/example.com/record?"));
    assert_eq!(reqs[1].path, "/domain/zone/example.com/record/42");
    assert_eq!(reqs[2].method, "PUT");
    assert_eq!(reqs[2].path, "/domain/zone/example.com/record/42");
    assert_eq!(reqs[3].method, "POST");
    assert_eq!(reqs[3].path, "/domain/zone/example.com/refresh");
    // PUT body：相对名（根=空省略 subDomain）+ target + ttl。
    let put_body = reqs[2].json();
    assert_eq!(put_body["fieldType"], "A");
    assert_eq!(put_body["target"], "9.9.9.9");
    assert_eq!(put_body["ttl"], 600);
    assert!(put_body.get("subDomain").is_none(), "根记录省略 subDomain");
    assert_signature_ok(&reqs[2]);

    // ── ② 不存在（TXT my-pc）→ POST + refresh。
    let rec2 = Record {
        name: "my-pc".to_string(),
        rtype: RecordType::TXT,
        ttl: 0,
        data: RecordData::Plain("v=ed25519;k=abc".into()),
    };
    p.upsert_record("example.com", &rec2).await.unwrap();
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 8);
    assert_eq!(reqs[4].path, "/domain/zone/example.com/record?fieldType=TXT");
    let post = &reqs[6];
    assert_eq!(post.method, "POST");
    assert_eq!(post.path, "/domain/zone/example.com/record");
    let post_body = post.json();
    assert_eq!(post_body["fieldType"], "TXT");
    assert_eq!(post_body["subDomain"], "my-pc");
    assert_eq!(post_body["target"], "v=ed25519;k=abc");
    assert_eq!(post_body["ttl"], 3600, "ttl=0 → 官方默认 3600");
    assert_eq!(reqs[7].path, "/domain/zone/example.com/refresh", "写后必 refresh");
    assert_signature_ok(post);

    // ── ③ 幂等：再写同 (name,type) → PUT（不重复创建）。
    let rec3 = rec2.clone();
    p.upsert_record("example.com", &rec3).await.unwrap();
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 13);
    assert_eq!(reqs[11].method, "PUT");
    assert_eq!(reqs[11].path, "/domain/zone/example.com/record/101");
    assert_eq!(reqs[12].path, "/domain/zone/example.com/refresh");
}

/// 5. delete：DELETE 全部匹配 id + refresh；删不存在 → NotFound（不 refresh）。
#[tokio::test]
async fn delete_removes_and_refreshes() {
    let state: Arc<Mutex<Vec<OvhRecord>>> = Arc::new(Mutex::new(vec![
        OvhRecord {
            id: 1,
            zone: "example.com".into(),
            field_type: "A".into(),
            sub_domain: String::new(),
            target: "203.0.113.7".into(),
            ttl: 3600,
        },
        OvhRecord {
            id: 2,
            zone: "example.com".into(),
            field_type: "A".into(),
            sub_domain: "www".into(),
            target: "198.51.100.9".into(),
            ttl: 3600,
        },
    ]));
    let mock = MockApi::start({
        let state = state.clone();
        move |req| match req.method.as_str() {
            "GET" if req.path.starts_with("/domain/zone/example.com/record?") => {
                let st = state.lock().unwrap();
                let ids: Vec<i64> = st.iter().map(|r| r.id).collect();
                MockResponse::json(format!("{ids:?}"))
            }
            "GET" if req.path.starts_with("/domain/zone/example.com/record/") => {
                let id: i64 = req.path.rsplit('/').next().unwrap().parse().unwrap();
                let st = state.lock().unwrap();
                let rec = st.iter().find(|r| r.id == id).unwrap();
                MockResponse::json(serde_json::to_string(rec).unwrap())
            }
            "DELETE" if req.path.starts_with("/domain/zone/example.com/record/") => {
                let id: i64 = req.path.rsplit('/').next().unwrap().parse().unwrap();
                let mut st = state.lock().unwrap();
                st.retain(|r| r.id != id);
                MockResponse::json("{}")
            }
            "POST" if req.path == "/domain/zone/example.com/refresh" => MockResponse::json("{}"),
            _ => MockResponse::error(404, "Client::NotFound", "NOT_FOUND"),
        }
    })
    .await;
    let p = provider_with(&mock).await;
    // 删除根 A → 只删 id=1（www 保留）；GET list → GET 详情×2 → DELETE → refresh。
    p.delete_record("example.com", "", RecordType::A)
        .await
        .unwrap();
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 5);
    assert_eq!(reqs[0].method, "GET");
    assert!(reqs[0].path.starts_with("/domain/zone/example.com/record?"));
    assert_eq!(reqs[1].path, "/domain/zone/example.com/record/1");
    assert_eq!(reqs[2].path, "/domain/zone/example.com/record/2");
    assert_eq!(reqs[3].method, "DELETE");
    assert_eq!(reqs[3].path, "/domain/zone/example.com/record/1");
    assert_eq!(reqs[4].path, "/domain/zone/example.com/refresh");

    // 删不存在 → NotFound，且不触发新的 refresh。
    let before_refresh_count = mock
        .requests()
        .iter()
        .filter(|r| r.path == "/domain/zone/example.com/refresh")
        .count();
    let err = p
        .delete_record("example.com", "nope", RecordType::TXT)
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::NotFound { .. }));
    let after = mock.requests();
    assert_eq!(after.len(), 7, "GET list + GET 详情，无 DELETE/refresh");
    let refresh_count = after
        .iter()
        .filter(|r| r.path == "/domain/zone/example.com/refresh")
        .count();
    assert_eq!(refresh_count, before_refresh_count, "NotFound 不应触发 refresh");
}

/// 6. 错误码映射：HTTP 状态 → 统一错误（含错误体 message 提取）。
#[tokio::test]
async fn error_mapping() {
    let cases: Vec<(u16, Box<dyn Fn(&ProviderError) -> bool + Send>)> = vec![
        (401, Box::new(|e| matches!(e, ProviderError::Auth { .. }))),
        (403, Box::new(|e| matches!(e, ProviderError::Auth { .. }))),
        (400, Box::new(|e| matches!(e, ProviderError::InvalidParameter { .. }))),
        (404, Box::new(|e| matches!(e, ProviderError::NotFound { .. }))),
        (429, Box::new(|e| matches!(e, ProviderError::RateLimited { .. }))),
        (500, Box::new(|e| matches!(e, ProviderError::Server { status: 500, .. }))),
    ];
    for (status, check) in cases {
        let mock =
            MockApi::start(move |_req| MockResponse::error(status, "Client::X", "some detail"))
                .await;
        let p = provider_with(&mock).await;
        let err = p.list_domains().await.unwrap_err();
        assert!(check(&err), "HTTP {status} → {err:?}");
        // 错误详情含 message（错误体解析）。
        if status == 404 {
            assert!(err.to_string().contains("some detail"), "{err}");
        }
    }
    // 非时间类 403 → 直接映射 Auth，不触发 /auth/time。
    let mock = MockApi::start(|_req| {
        MockResponse::error(403, "Client::Forbidden", "NOT_GRANTED_CALL")
    })
    .await;
    let p = provider_with(&mock).await;
    let err = p.list_domains().await.unwrap_err();
    assert!(matches!(err, ProviderError::Auth { .. }));
    assert!(mock.requests().iter().all(|r| r.path != "/auth/time"));
}

/// 7a. SRV 写入：target 官方单字符串 "0 1 3389 tgt."。
#[tokio::test]
async fn srv_write_uses_combined_target_string() {
    let mock = MockApi::start(|req| match req.method.as_str() {
        "GET" if req.path.starts_with("/domain/zone/example.com/record?") => {
            MockResponse::json("[]")
        }
        "POST" if req.path == "/domain/zone/example.com/record" => {
            let body = req.json();
            MockResponse::json(format!(
                r#"{{"id":77,"fieldType":"{}","subDomain":"{}","target":"{}","ttl":{}}}"#,
                body["fieldType"].as_str().unwrap_or(""),
                body["subDomain"].as_str().unwrap_or(""),
                body["target"].as_str().unwrap_or(""),
                body["ttl"].as_u64().unwrap_or(0)
            ))
        }
        "POST" if req.path == "/domain/zone/example.com/refresh" => MockResponse::json("{}"),
        _ => MockResponse::error(404, "Client::NotFound", "NOT_FOUND"),
    })
    .await;
    let p = provider_with(&mock).await;
    let rec = Record {
        name: "_remote._tcp".to_string(),
        rtype: RecordType::SRV,
        ttl: 600,
        data: RecordData::Srv {
            priority: 0,
            weight: 1,
            port: 3389,
            target: "my-pc.example.com.".to_string(),
        },
    };
    p.upsert_record("example.com", &rec).await.unwrap();
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 3);
    let post = &reqs[1];
    assert_eq!(post.method, "POST");
    assert_eq!(post.path, "/domain/zone/example.com/record");
    let body = post.json();
    assert_eq!(body["fieldType"], "SRV");
    assert_eq!(body["subDomain"], "_remote._tcp");
    // 官方单字符串格式（DNSControl OVH provider 同款）。
    assert_eq!(body["target"], "0 1 3389 my-pc.example.com.");
    assert_eq!(reqs[2].path, "/domain/zone/example.com/refresh");
    assert_signature_ok(post);
}

/// 7b. 时间戳偏差：403 QUERY_TIME_OUT → /auth/time 校准 → 用服务器时间重试成功。
#[tokio::test]
async fn time_skew_triggers_clock_calibration_and_retry() {
    // mock 服务器时间固定为 1700000000；只接受该时间戳 + 对应签名。
    let server_ts: i64 = 1700000000;
    let mock = MockApi::start(move |req| {
        if req.path == "/auth/time" {
            return MockResponse::json(server_ts.to_string());
        }
        let ts: i64 = req
            .header("X-Ovh-Timestamp")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if ts != server_ts {
            return MockResponse::error(403, "Client::BadRequest", "Timestamp out of time range");
        }
        // 时间戳正确 → 校验签名（用服务器时间复算）。
        let expected = signature(
            TEST_APP_SECRET,
            TEST_CONSUMER_KEY,
            &req.method,
            &req.request_url(),
            &req.body,
            server_ts,
        );
        if req.header("X-Ovh-Signature").as_deref() != Some(expected.as_str()) {
            return MockResponse::error(401, "Client::Unauthorized", "INVALID_SIGNATURE");
        }
        MockResponse::json(r#"["example.com"]"#)
    })
    .await;
    let p = provider_with(&mock).await;
    let domains = p.list_domains().await.unwrap();
    assert_eq!(domains, vec!["example.com"]);
    let reqs = mock.requests();
    // 第 1 次带本地时间（≠1700000000）被 403 → /auth/time → 重试成功。
    assert_eq!(reqs.len(), 3);
    assert_eq!(reqs[0].path, "/domain/zone");
    assert_eq!(reqs[1].path, "/auth/time");
    assert_eq!(reqs[2].path, "/domain/zone");
    // 重试请求时间戳 = 服务器时间，且签名可复算。
    assert_eq!(
        reqs[2].header("X-Ovh-Timestamp").unwrap(),
        server_ts.to_string()
    );
    assert_signature_ok(&reqs[2]);
}

/// 注册表工厂：凭据变体匹配。
#[test]
fn register_factory_builds_from_credential() {
    let mut registry = crate::provider::ProviderRegistry::new();
    super::register(&mut registry);
    assert!(registry.has("ovh"));
    let cred = crate::provider::Credential::Ovh {
        app_key: "a".into(),
        app_secret: "s".into(),
        consumer_key: "c".into(),
    };
    let p = registry.build("ovh", &cred).unwrap();
    assert_eq!(p.name(), "ovh");
    // 凭据不匹配 → 构造成功但调用报错。
    let wrong = crate::provider::Credential::Cloudflare {
        api_token: "t".into(),
    };
    let p2 = registry.build("ovh", &wrong).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let err = rt.block_on(p2.list_domains()).unwrap_err();
    assert!(err.to_string().contains("不匹配"), "{err}");
}
