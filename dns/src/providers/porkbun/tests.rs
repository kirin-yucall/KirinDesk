//! M9-DNS015 契约测试：自写 tokio mock HTTP server（127.0.0.1）+ 录制官方响应样例。
//!
//! 覆盖（对照 `M9-DNS000_Provider抽象接口规范.md` §七 契约模板）：
//! 1. 认证形状（body 内 apikey/secretapikey）
//! 2. list_domains 解析
//! 3. 相对名 ↔ FQDN 互转（根 = 域名本身）
//! 4. upsert 分派（create / edit）
//! 5. delete
//! 6. 错误码映射（Auth/NotFound/RateLimited/Server/InvalidParameter）
//! 7. SRV 往返（content="weight port target" + prio）

use super::PorkbunProvider;
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
    body: String,
}

impl MockRequest {
    /// 解析 body JSON（请求体固定为 JSON）。
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::json!({}))
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
    fn plain(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
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
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
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
    let req = MockRequest {
        method,
        path,
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
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    format!("{status} {reason}")
}

/// 构造指向 mock 的 Provider（凭据为测试固定值）。
async fn provider_with(mock: &MockApi) -> PorkbunProvider {
    PorkbunProvider::new_at("pk_key_abc".to_string(), "pk_secret_xyz".to_string(), mock.base_url())
}

// ────────────────────────────────────────────────────────────────
// 契约测试
// ────────────────────────────────────────────────────────────────

/// 1+2. 认证形状（body 内 apikey/secretapikey）+ ping。
#[tokio::test]
async fn ping_sends_credentials_in_body() {
    let mock = MockApi::start(|_req| {
        MockResponse::json(r#"{"status":"SUCCESS","yourIp":"2a02:842b:5da:c101:4b81:e1b5:83f7:3e7c"}"#)
    })
    .await;
    let p = provider_with(&mock).await;
    p.test_connection().await.unwrap();
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/ping");
    let body = reqs[0].json();
    assert_eq!(body["apikey"], "pk_key_abc");
    assert_eq!(body["secretapikey"], "pk_secret_xyz");
}

/// 2b. list_domains 解析（POST /domain/listAll → domains[].domain）。
#[tokio::test]
async fn list_domains_parses_domain_field() {
    let mock = MockApi::start(|req| {
        assert_eq!(req.path, "/domain/listAll");
        MockResponse::json(
            r#"{"status":"SUCCESS","domains":[{"domain":"example.com","status":"ACTIVE"},{"domain":"kirin.dev","status":"ACTIVE"}]}"#,
        )
    })
    .await;
    let p = provider_with(&mock).await;
    let domains = p.list_domains().await.unwrap();
    assert_eq!(domains, vec!["example.com", "kirin.dev"]);
}

/// 3. 相对名 ↔ FQDN 互转：retrieve 返回 FQDN → 相对名（根 = 域名本身）。
#[tokio::test]
async fn query_records_converts_fqdn_to_relative() {
    let mock = MockApi::start(|req| {
        assert_eq!(req.path, "/dns/retrieve/example.com");
        MockResponse::json(
            r#"{"status":"SUCCESS","records":[
                {"id":"1","name":"example.com","type":"A","content":"203.0.113.7","ttl":"600","prio":"0","notes":""},
                {"id":"2","name":"www.example.com","type":"A","content":"198.51.100.9","ttl":"300","prio":"0","notes":""},
                {"id":"3","name":"_remote._tcp.example.com","type":"SRV","content":"1 3389 my-pc.example.com.","ttl":"600","prio":"0","notes":""},
                {"id":"4","name":"example.com","type":"URL","content":"https://example.com","ttl":"600","prio":"0","notes":""}
            ]}"#,
        )
    })
    .await;
    let p = provider_with(&mock).await;
    let all = p.query_records("example.com", None, None).await.unwrap();
    // URL 类型无法表达 → 跳过；其余 3 条。
    assert_eq!(all.len(), 3);
    let root = all
        .iter()
        .find(|r| r.rtype == RecordType::A && r.name.is_empty())
        .unwrap();
    assert_eq!(root.data, RecordData::Plain("203.0.113.7".into()));
    let www = all
        .iter()
        .find(|r| r.rtype == RecordType::A && r.name == "www")
        .unwrap();
    assert_eq!(www.ttl, 300);
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
    // 过滤。
    let filtered = p
        .query_records("example.com", Some("www"), Some(RecordType::A))
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "www");
}

/// 4. upsert 分派：存在 (name,type) → edit（携带 id）；不存在 → create。
#[tokio::test]
async fn upsert_dispatches_create_or_edit() {
    // 初始 1 条 A 记录（id=42）。
    let state: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(vec![
        serde_json::json!({"id":"42","name":"example.com","type":"A","content":"203.0.113.7","ttl":"600","prio":"0","notes":""}),
    ]));
    let next_id = Arc::new(Mutex::new(100i64));
    let mock = MockApi::start({
        let state = state.clone();
        let next_id = next_id.clone();
        move |req| match req.path.as_str() {
            "/dns/retrieve/example.com" => {
                let st = state.lock().unwrap();
                MockResponse::json(format!(
                    r#"{{"status":"SUCCESS","records":{}}}"#,
                    serde_json::to_string(&*st).unwrap()
                ))
            }
            p if p.starts_with("/dns/edit/") => {
                // 按 id 更新。
                let id = p.rsplit('/').next().unwrap_or("").to_string();
                let mut st = state.lock().unwrap();
                if let Some(rec) = st.iter_mut().find(|r| r["id"] == serde_json::json!(id)) {
                    let body = req.json();
                    rec["content"] = body.get("content").cloned().unwrap_or_default();
                    rec["ttl"] = body.get("ttl").cloned().unwrap_or_default();
                }
                MockResponse::json(r#"{"status":"SUCCESS"}"#)
            }
            p if p.starts_with("/dns/create/") => {
                let mut st = state.lock().unwrap();
                let mut id = next_id.lock().unwrap();
                *id += 1;
                let mut rec = req.json();
                rec["id"] = serde_json::json!(id.to_string());
                rec["name"] = serde_json::json!(format!("{}.example.com", rec.get("name").and_then(|n| n.as_str()).unwrap_or("")));
                st.push(rec.clone());
                MockResponse::json(format!(r#"{{"status":"SUCCESS","id":{id}}}"#))
            }
            _ => MockResponse::plain(404, r#"{"status":"ERROR","message":"not found"}"#),
        }
    })
    .await;
    let p = provider_with(&mock).await;

    // 已存在 A（id=42）→ edit。
    let rec = Record {
        name: String::new(), // 根
        rtype: RecordType::A,
        ttl: 1200,
        data: RecordData::Plain("9.9.9.9".into()),
    };
    p.upsert_record("example.com", &rec).await.unwrap();
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].path, "/dns/retrieve/example.com");
    assert_eq!(reqs[1].path, "/dns/edit/example.com/42");
    // 写入侧 name 为相对名（根 = 空，序列化省略该字段）+ body 含 type/content/ttl + 认证。
    let edit_body = reqs[1].json();
    assert_eq!(edit_body["type"], "A");
    assert!(edit_body.get("name").is_none(), "根记录 name 留空省略");
    assert_eq!(edit_body["content"], "9.9.9.9");
    assert_eq!(edit_body["ttl"], "1200");
    assert_eq!(edit_body["apikey"], "pk_key_abc");
    assert_eq!(edit_body["secretapikey"], "pk_secret_xyz");
    // TTL 收敛：<600 会抬到 600（此处 1200 原样）。
    assert_eq!(edit_body["ttl"], "1200");

    // 不存在（TXT）→ create。
    let rec2 = Record {
        name: "my-pc".to_string(),
        rtype: RecordType::TXT,
        ttl: 0,
        data: RecordData::Plain("v=ed25519;k=abc".into()),
    };
    p.upsert_record("example.com", &rec2).await.unwrap();
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 4);
    assert_eq!(reqs[3].path, "/dns/create/example.com");
    let create_body = reqs[3].json();
    assert_eq!(create_body["type"], "TXT");
    assert_eq!(create_body["name"], "my-pc");
    // ttl=0 → 省略字段（服务商默认）。
    assert!(create_body.get("ttl").is_none());
}

/// 4b. MX：prio 字段承载优先级。
#[tokio::test]
async fn upsert_mx_sends_prio() {
    let mock = MockApi::start(|req| match req.path.as_str() {
        "/dns/retrieve/example.com" => MockResponse::json(r#"{"status":"SUCCESS","records":[]}"#),
        p if p.starts_with("/dns/create/") => MockResponse::json(r#"{"status":"SUCCESS","id":7}"#),
        _ => MockResponse::plain(404, "not found"),
    })
    .await;
    let p = provider_with(&mock).await;
    let rec = Record {
        name: String::new(),
        rtype: RecordType::MX,
        ttl: 600,
        data: RecordData::Mx {
            priority: 10,
            exchange: "mail.example.com".into(),
        },
    };
    p.upsert_record("example.com", &rec).await.unwrap();
    let create_body = mock.requests().last().unwrap().json();
    assert_eq!(create_body["type"], "MX");
    assert_eq!(create_body["content"], "mail.example.com");
    assert_eq!(create_body["prio"], "10");
}

/// 5. delete：按 (name,type) 找到 id 逐个删除；删不存在 → NotFound。
#[tokio::test]
async fn delete_removes_matching_records() {
    let state: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(vec![
        serde_json::json!({"id":"1","name":"example.com","type":"A","content":"203.0.113.7","ttl":"600","prio":"0","notes":""}),
        serde_json::json!({"id":"2","name":"www.example.com","type":"A","content":"198.51.100.9","ttl":"600","prio":"0","notes":""}),
    ]));
    let mock = MockApi::start({
        let state = state.clone();
        move |req| match req.path.as_str() {
            "/dns/retrieve/example.com" => {
                let st = state.lock().unwrap();
                MockResponse::json(format!(
                    r#"{{"status":"SUCCESS","records":{}}}"#,
                    serde_json::to_string(&*st).unwrap()
                ))
            }
            p if p.starts_with("/dns/delete/") => {
                let id = p.rsplit('/').next().unwrap_or("").to_string();
                let mut st = state.lock().unwrap();
                st.retain(|r| r["id"] != serde_json::json!(id));
                MockResponse::json(r#"{"status":"SUCCESS"}"#)
            }
            _ => MockResponse::plain(404, r#"{"status":"ERROR","message":"not found"}"#),
        }
    })
    .await;
    let p = provider_with(&mock).await;
    // 删除根 A → 1 条（www 保留）。
    p.delete_record("example.com", "", RecordType::A)
        .await
        .unwrap();
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[1].path, "/dns/delete/example.com/1");
    // 再删不存在 → NotFound。
    let err = p
        .delete_record("example.com", "nope", RecordType::TXT)
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::NotFound { .. }));
}

/// 6. 错误码映射：业务 ERROR 关键词 + HTTP 状态码 → 统一错误。
#[tokio::test]
async fn error_mapping() {
    // 业务错误（HTTP 200 + status=ERROR）。
    let cases: Vec<(&str, &str, Box<dyn Fn(&ProviderError) -> bool + Send>)> = vec![
        (
            r#"{"status":"ERROR","message":"Invalid API key. (001)"}"#,
            "auth",
            Box::new(|e| matches!(e, ProviderError::Auth { .. })),
        ),
        (
            r#"{"status":"ERROR","message":"Domain not found"}"#,
            "notfound",
            Box::new(|e| matches!(e, ProviderError::NotFound { .. })),
        ),
        (
            r#"{"status":"ERROR","message":"Invalid record content"}"#,
            "param",
            Box::new(|e| matches!(e, ProviderError::InvalidParameter { .. })),
        ),
    ];
    for (resp, label, check) in cases {
        let resp = resp.to_string();
        let mock = MockApi::start(move |_req| MockResponse::json(resp.clone())).await;
        let p = provider_with(&mock).await;
        let err = p.test_connection().await.unwrap_err();
        assert!(check(&err), "用例 {label} → {err:?}");
    }
    // HTTP 状态码。
    let status_cases: Vec<(u16, Box<dyn Fn(&ProviderError) -> bool + Send>)> = vec![
        (404, Box::new(|e| matches!(e, ProviderError::NotFound { .. }))),
        (429, Box::new(|e| matches!(e, ProviderError::RateLimited { .. }))),
        (500, Box::new(|e| matches!(e, ProviderError::Server { status: 500, .. }))),
    ];
    for (status, check) in status_cases {
        let mock = MockApi::start(move |_req| MockResponse::plain(status, "oops")).await;
        let p = provider_with(&mock).await;
        let err = p.test_connection().await.unwrap_err();
        assert!(check(&err), "HTTP {status} → {err:?}");
    }
}

/// 7. SRV 往返：create body content="weight port target" + prio。
#[tokio::test]
async fn srv_create_uses_official_content_format() {
    let mock = MockApi::start(|req| match req.path.as_str() {
        "/dns/retrieve/example.com" => MockResponse::json(r#"{"status":"SUCCESS","records":[]}"#),
        p if p.starts_with("/dns/create/") => MockResponse::json(r#"{"status":"SUCCESS","id":9}"#),
        _ => MockResponse::plain(404, "not found"),
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
    let body = mock.requests().last().unwrap().json();
    assert_eq!(body["type"], "SRV");
    assert_eq!(body["name"], "_remote._tcp");
    // 官方格式：content = "weight port target"（priority 在 prio）。
    assert_eq!(body["content"], "1 3389 my-pc.example.com.");
    assert_eq!(body["prio"], "0");
    assert_eq!(body["ttl"], "600");
}

/// 注册表工厂：凭据变体匹配。
#[test]
fn register_factory_builds_from_credential() {
    let mut registry = crate::provider::ProviderRegistry::new();
    super::register(&mut registry);
    assert!(registry.has("porkbun"));
    let cred = crate::provider::Credential::Porkbun {
        api_key: "k".into(),
        secret_key: "s".into(),
    };
    let p = registry.build("porkbun", &cred).unwrap();
    assert_eq!(p.name(), "porkbun");
    // 凭据不匹配 → 构造成功但调用报错。
    let wrong = crate::provider::Credential::Namecheap {
        api_user: "u".into(),
        api_key: "k".into(),
        user_name: "un".into(),
        client_ip: "1.2.3.4".into(),
    };
    let p2 = registry.build("porkbun", &wrong).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let err = rt.block_on(p2.list_domains()).unwrap_err();
    assert!(err.to_string().contains("不匹配"), "{err}");
}
