//! M9-DNS004: 腾讯云 DNSPod 适配契约测试（本地 mock HTTP 服务器）
//!
//! 参考 `dns/src/test_support.rs` MockDns 模式：tokio `TcpListener` 起本地
//! `http://127.0.0.1` 服务，按官方 API 语义维护内存记录存储，并记录全部请求
//! （方法/路径/头/体）供断言。
//!
//! 覆盖 `M9-DNS000` §七 契约模板：
//! 1. Authorization 头 TC3-HMAC-SHA256 形状与 Credential 前缀；
//! 2. X-TC-* 头齐全（Action/Version/Timestamp/Nonce）；
//! 3. 签名可复算（固定密钥+时间戳 → 期望值比对，见 `sign.rs`；此处再以
//!    捕获的线上请求复算 → 与发送的 Signature 一致）；
//! 4. list_domains 解析；
//! 5. upsert 查→增/改 语义（幂等）；
//! 6. delete；
//! 7. 错误码映射（Auth/NotFound/RateLimited/Server）；
//! 8. `@` 根记录名转换（线上断言：写 "@"、读回 ""）。

use super::client::{DnspodClient, DEFAULT_LINE};
use super::sign;
use crate::provider::{ProviderError, Record, RecordData, RecordType};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

// ── 测试常量（固定凭据，签名断言用）──
const SECRET_ID: &str = "AKIDTEST123456789";
const SECRET_KEY: &str = "SKTESTSECRET123456789";

/// 捕获的 HTTP 请求（头键已转小写）。
#[derive(Debug, Clone)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: String,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// mock 存储的 DNSPod 记录（wire 形态，name 为 "@" 或相对名）。
#[derive(Debug, Clone)]
struct MockRecord {
    id: u64,
    name: String,
    rtype: String,
    value: String,
    mx: u32,
    ttl: u32,
    line: String,
}

#[derive(Default)]
struct MockState {
    requests: Vec<CapturedRequest>,
    domains: Vec<String>,
    records: Vec<MockRecord>,
    next_id: u64,
    /// 预置错误响应（status, body）；每请求消费一条，耗尽后走正常路由。
    errors: VecDeque<(u16, String)>,
}

/// 本地 mock DNSPod 服务（TC3 动作路由）。
struct MockDnspod {
    addr: SocketAddr,
    state: Arc<Mutex<MockState>>,
}

impl MockDnspod {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定 mock 服务器失败");
        let addr = listener.local_addr().expect("获取 mock 地址失败");
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
                    let _ = handle_connection(stream, &conn_state).await;
                });
            }
        });
        Self { addr, state }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn client(&self) -> DnspodClient {
        DnspodClient::new(SECRET_ID.to_string(), SECRET_KEY.to_string(), self.endpoint())
    }

    fn set_domains(&self, domains: &[&str]) {
        let mut s = self.state.lock().unwrap();
        s.domains = domains.iter().map(|d| d.to_string()).collect();
    }

    /// 预置一条记录（name 为相对名，"" = 根）。
    fn seed_record(&self, name: &str, rtype: &str, value: &str, ttl: u32) {
        let mut s = self.state.lock().unwrap();
        s.next_id += 1;
        let id = s.next_id;
        s.records.push(MockRecord {
            id,
            name: if name.is_empty() { "@".into() } else { name.into() },
            rtype: rtype.into(),
            value: value.into(),
            mx: if rtype == "MX" { 10 } else { 0 }, // MX 记录默认优先级 10
            ttl,
            line: DEFAULT_LINE.into(),
        });
    }

    /// 预置一个错误响应（每次请求消费一条）。
    fn push_error(&self, status: u16, body: &str) {
        self.state
            .lock()
            .unwrap()
            .errors
            .push_back((status, body.to_string()));
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.state.lock().unwrap().requests.clone()
    }

    fn records(&self) -> Vec<MockRecord> {
        self.state.lock().unwrap().records.clone()
    }
}

/// 连接处理：解析请求行 + 头 + 体 → 记录 → 路由 → 响应。
async fn handle_connection(
    mut stream: TcpStream,
    state: &Arc<Mutex<MockState>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await? == 0 {
        return Ok(());
    }
    let mut headers = BTreeMap::new();
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
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim().to_string();
            if key == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.insert(key, value);
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).await?;
    let body = String::from_utf8_lossy(&body).to_string();

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let req = CapturedRequest {
        method,
        path,
        headers,
        body,
    };
    let (status, resp_body) = {
        let mut s = state.lock().unwrap();
        // 预置错误优先消费。
        if let Some((st, b)) = s.errors.pop_front() {
            s.requests.push(req);
            (st, b)
        } else {
            let resp = route(&req, &mut s);
            s.requests.push(req);
            resp
        }
    };

    let raw = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        resp_body.len(),
        resp_body
    );
    stream.write_all(raw.as_bytes()).await?;
    stream.flush().await
}

/// 状态码（200/404/405…）+ body。
type Response = (u16, String);

/// DNSPod 动作路由（模拟官方 API 语义；`&mut` 以便 Create/Modify/Delete 落存储）。
fn route(req: &CapturedRequest, state: &mut MockState) -> Response {
    let action = req.header("x-tc-action").unwrap_or("").to_string();
    let params: serde_json::Value =
        serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
    let ok = |v: serde_json::Value| (200, v.to_string());

    match action.as_str() {
        "DescribeDomainList" => {
            let list: Vec<serde_json::Value> = state
                .domains
                .iter()
                .enumerate()
                .map(|(i, d)| serde_json::json!({ "DomainId": i + 1, "Name": d }))
                .collect();
            ok(serde_json::json!({
                "Response": {
                    "DomainList": list,
                    "TotalCount": state.domains.len(),
                    "RequestId": "mock-req"
                }
            }))
        }
        "DescribeRecordList" => {
            let subdomain = params.get("Subdomain").and_then(|v| v.as_str());
            let rtype = params.get("RecordType").and_then(|v| v.as_str());
            let list: Vec<serde_json::Value> = state
                .records
                .iter()
                .filter(|r| {
                    subdomain.map(|s| r.name == s).unwrap_or(true)
                        && rtype.map(|t| r.rtype == t).unwrap_or(true)
                })
                .map(|r| {
                    serde_json::json!({
                        "RecordId": r.id,
                        "Name": r.name,
                        "Type": r.rtype,
                        "Value": r.value,
                        "MX": r.mx,
                        "TTL": r.ttl,
                        "Line": r.line,
                    })
                })
                .collect();
            ok(serde_json::json!({
                "Response": {
                    "RecordList": list,
                    "TotalCount": list.len(),
                    "RequestId": "mock-req"
                }
            }))
        }
        "CreateRecord" => {
            let name = params.get("SubDomain").and_then(|v| v.as_str()).unwrap_or("@");
            let rtype = params.get("RecordType").and_then(|v| v.as_str()).unwrap_or("");
            let value = params.get("Value").and_then(|v| v.as_str()).unwrap_or("");
            let line = params
                .get("RecordLine")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_LINE);
            let id = state.next_id + 1;
            state.next_id = id;
            let mut rec = MockRecord {
                id,
                name: name.to_string(),
                rtype: rtype.to_string(),
                value: value.to_string(),
                mx: 0,
                ttl: params.get("TTL").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                line: line.to_string(),
            };
            if rec.rtype == "MX" {
                rec.mx = params.get("MX").and_then(|v| v.as_u64()).unwrap_or(10) as u32;
            }
            state.records.push(rec);
            ok(serde_json::json!({
                "Response": { "RecordId": id, "RequestId": "mock-req" }
            }))
        }
        "ModifyRecord" => {
            let record_id = params.get("RecordId").and_then(|v| v.as_u64()).unwrap_or(0);
            if let Some(idx) = state.records.iter().position(|r| r.id == record_id) {
                let rec = &mut state.records[idx];
                rec.name = params.get("SubDomain").and_then(|v| v.as_str()).unwrap_or("@").to_string();
                rec.rtype = params.get("RecordType").and_then(|v| v.as_str()).unwrap_or("").to_string();
                rec.value = params.get("Value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                rec.line = params
                    .get("RecordLine")
                    .and_then(|v| v.as_str())
                    .unwrap_or(DEFAULT_LINE)
                    .to_string();
                rec.ttl = params.get("TTL").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                if rec.rtype == "MX" {
                    rec.mx = params.get("MX").and_then(|v| v.as_u64()).unwrap_or(10) as u32;
                }
            }
            ok(serde_json::json!({
                "Response": { "RecordId": record_id, "RequestId": "mock-req" }
            }))
        }
        "DeleteRecord" => {
            let record_id = params.get("RecordId").and_then(|v| v.as_u64()).unwrap_or(0);
            state.records.retain(|r| r.id != record_id);
            ok(serde_json::json!({
                "Response": { "RequestId": "mock-req" }
            }))
        }
        _ => (404, "Not Found".to_string()),
    }
}

/// 便捷构造：统一 Record（Plain 数据）。
fn plain(name: &str, rtype: RecordType, value: &str, ttl: u32) -> Record {
    Record {
        name: name.to_string(),
        rtype,
        ttl,
        data: RecordData::Plain(value.to_string()),
    }
}

// ── 契约测试 ──

/// 1+2. Authorization 头 TC3 形状与 X-TC-* 头齐全。
#[tokio::test]
async fn authorization_shape_and_tc_headers() {
    let mock = MockDnspod::start().await;
    mock.set_domains(&["example.com"]);
    let client = mock.client();
    client.list_domains().await.unwrap();

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    let auth = req.header("authorization").unwrap();
    assert!(
        auth.starts_with(&format!("TC3-HMAC-SHA256 Credential={SECRET_ID}/")),
        "Authorization 必须以 Credential 前缀开头: {auth}"
    );
    assert!(
        auth.contains(
            "/dnspod/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature="
        ),
        "Authorization 形状错误: {auth}"
    );
    let sig = auth.split("Signature=").nth(1).unwrap();
    assert_eq!(sig.len(), 64, "Signature 必须是 64 位 hex");

    // X-TC-* 头齐全。
    assert_eq!(req.header("x-tc-action"), Some("DescribeDomainList"));
    assert_eq!(req.header("x-tc-version"), Some("2021-03-23"));
    let ts = req.header("x-tc-timestamp").unwrap();
    assert!(ts.parse::<i64>().unwrap() > 0, "X-TC-Timestamp 必须是 Unix 秒");
    let nonce = req.header("x-tc-nonce").unwrap();
    assert!(!nonce.is_empty(), "X-TC-Nonce 必须存在");
    assert_eq!(req.header("content-type"), Some("application/json; charset=utf-8"));

    // 请求体含分页参数。
    let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
    assert_eq!(body["Offset"], 0);
    assert_eq!(body["Limit"], 300);
}

/// 3. 签名可复算：用捕获的线上请求（host 含端口、body 原文、时间戳）本地复算
/// Authorization → 与请求头完全一致。
#[tokio::test]
async fn signature_recomputable_from_wire() {
    let mock = MockDnspod::start().await;
    mock.set_domains(&["example.com"]);
    let client = mock.client();
    client.list_domains().await.unwrap();

    let reqs = mock.requests();
    let req = &reqs[0];
    let host = req.header("host").unwrap();
    let ts = req.header("x-tc-timestamp").unwrap().parse::<i64>().unwrap();
    let action = req.header("x-tc-action").unwrap();
    let expected = sign::tc3_authorization(
        SECRET_ID,
        SECRET_KEY,
        sign::SERVICE,
        host,
        action,
        ts,
        &req.body,
    );
    assert_eq!(req.header("authorization").unwrap(), expected);
}

/// 4. list_domains 解析 + test_connection。
#[tokio::test]
async fn list_domains_parses() {
    let mock = MockDnspod::start().await;
    mock.set_domains(&["example.com", "kirin.dev"]);
    let domains = mock.client().list_domains().await.unwrap();
    assert_eq!(domains, vec!["example.com", "kirin.dev"]);
    mock.client().test_connection().await.unwrap();
}

/// 5. upsert 查→增/改 语义（幂等：同数据仅更新 TTL，重复 upsert 不新增）。
#[tokio::test]
async fn upsert_creates_then_updates_idempotent() {
    let mock = MockDnspod::start().await;
    let client = mock.client();

    // 首次：不存在 → CreateRecord。
    client
        .upsert_record("example.com", &plain("www", RecordType::A, "203.0.113.7", 600))
        .await
        .unwrap();
    // 同 name+type 新值 → ModifyRecord（携带原 RecordId）。
    client
        .upsert_record("example.com", &plain("www", RecordType::A, "198.51.100.9", 600))
        .await
        .unwrap();
    // 同值不同 TTL → ModifyRecord 更新 TTL。
    client
        .upsert_record("example.com", &plain("www", RecordType::A, "198.51.100.9", 1200))
        .await
        .unwrap();
    // 完全幂等（同值同 TTL）→ 不发写请求（仅查询）。
    client
        .upsert_record("example.com", &plain("www", RecordType::A, "198.51.100.9", 1200))
        .await
        .unwrap();

    let reqs = mock.requests();
    let actions: Vec<&str> = reqs
        .iter()
        .map(|r| r.header("x-tc-action").unwrap())
        .collect();
    // 4 次 upsert = 4 次查询 + 1 次创建 + 2 次修改 = 7 次请求。
    assert_eq!(reqs.len(), 7, "actions={actions:?}");

    // 创建请求体形状。
    let create = reqs
        .iter()
        .find(|r| r.header("x-tc-action") == Some("CreateRecord"))
        .unwrap();
    let cbody: serde_json::Value = serde_json::from_str(&create.body).unwrap();
    assert_eq!(cbody["SubDomain"], "www");
    assert_eq!(cbody["RecordType"], "A");
    assert_eq!(cbody["Value"], "203.0.113.7");
    assert_eq!(cbody["RecordLine"], "默认");
    assert_eq!(cbody["TTL"], 600);

    // 修改请求携带同一 RecordId，且 value 更新。
    let mods: Vec<&CapturedRequest> = reqs
        .iter()
        .filter(|r| r.header("x-tc-action") == Some("ModifyRecord"))
        .collect();
    assert_eq!(mods.len(), 2);
    let m1: serde_json::Value = serde_json::from_str(&mods[0].body).unwrap();
    assert_eq!(m1["RecordId"], 1);
    assert_eq!(m1["Value"], "198.51.100.9");
    let m2: serde_json::Value = serde_json::from_str(&mods[1].body).unwrap();
    assert_eq!(m2["RecordId"], 1);
    assert_eq!(m2["TTL"], 1200);

    // 存储中仅 1 条记录（未产生重复）。
    let recs = mock.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].value, "198.51.100.9");
    assert_eq!(recs[0].ttl, 1200);
}

/// 6. delete：按 RecordId 删除；删不存在 → NotFound。
#[tokio::test]
async fn delete_removes_and_not_found() {
    let mock = MockDnspod::start().await;
    let client = mock.client();
    client
        .upsert_record("example.com", &plain("my-pc", RecordType::A, "203.0.113.7", 600))
        .await
        .unwrap();
    client
        .delete_record("example.com", "my-pc", RecordType::A)
        .await
        .unwrap();
    assert!(mock.records().is_empty());

    let reqs = mock.requests();
    let del = reqs
        .iter()
        .find(|r| r.header("x-tc-action") == Some("DeleteRecord"))
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&del.body).unwrap();
    assert_eq!(body["RecordId"], 1);

    // 再次删除 → NotFound。
    let err = client
        .delete_record("example.com", "my-pc", RecordType::A)
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::NotFound { .. }), "得到 {err:?}");
}

/// 7. 错误码映射（Auth / InvalidParameter / NotFound / RateLimited / Server）。
#[tokio::test]
async fn error_code_mapping() {
    let mock = MockDnspod::start().await;
    let client = mock.client();

    let cases: Vec<(&str, &str)> = vec![
        ("AuthFailure.SignatureFailure", "签名校验失败"),
        ("InvalidParameter.DomainEmpty", "域名不能为空"),
        ("ResourceNotFound.Domain", "域名不存在"),
        ("RequestLimitExceeded", "请求超过频率限制"),
    ];
    for (code, msg) in cases {
        mock.push_error(
            200,
            &format!(
                r#"{{"Response":{{"Error":{{"Code":"{code}","Message":"{msg}"}},"RequestId":"r"}}}}"#
            ),
        );
    }
    mock.push_error(500, "Internal Server Error");

    assert!(matches!(client.list_domains().await, Err(ProviderError::Auth { .. })));
    assert!(matches!(
        client.list_domains().await,
        Err(ProviderError::InvalidParameter { .. })
    ));
    assert!(matches!(client.list_domains().await, Err(ProviderError::NotFound { .. })));
    assert!(matches!(
        client.list_domains().await,
        Err(ProviderError::RateLimited { .. })
    ));
    assert!(matches!(
        client.list_domains().await,
        Err(ProviderError::Server { status: 500, .. })
    ));
    // 错误队列耗尽后恢复正常。
    assert!(client.list_domains().await.is_ok());
}

/// 8. `@` 根记录名转换（线上断言：写 "@"、读回 ""）。
#[tokio::test]
async fn root_record_name_conversion() {
    let mock = MockDnspod::start().await;
    let client = mock.client();
    client
        .upsert_record("example.com", &plain("", RecordType::A, "203.0.113.7", 600))
        .await
        .unwrap();

    let reqs = mock.requests();
    let create = reqs
        .iter()
        .find(|r| r.header("x-tc-action") == Some("CreateRecord"))
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&create.body).unwrap();
    assert_eq!(body["SubDomain"], "@", "根记录必须以 @ 写入");

    // 查询返回相对名 ""。
    let recs = client
        .query_records("example.com", Some(""), Some(RecordType::A))
        .await
        .unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].name, "");
    assert_eq!(recs[0].data.to_display_string(), "203.0.113.7");
}

/// 补充：query 按 name/rtype 过滤；MX/SRV 结构化往返。
#[tokio::test]
async fn query_filters_and_structured_roundtrip() {
    let mock = MockDnspod::start().await;
    mock.seed_record("www", "A", "203.0.113.7", 600);
    mock.seed_record("www", "AAAA", "2001:db8::1", 600);
    mock.seed_record("mail", "MX", "mail.example.com", 300);
    mock.seed_record("_remote._tcp.my-pc", "SRV", "0 5 3389 pc.example.com.", 600);
    let client = mock.client();

    // name 过滤。
    let recs = client.query_records("example.com", Some("www"), None).await.unwrap();
    assert_eq!(recs.len(), 2);
    // type 过滤。
    let recs = client
        .query_records("example.com", None, Some(RecordType::A))
        .await
        .unwrap();
    assert_eq!(recs.len(), 1);
    // 全表。
    let recs = client.query_records("example.com", None, None).await.unwrap();
    assert_eq!(recs.len(), 4);

    // MX 结构化。
    let mx = recs.iter().find(|r| r.rtype == RecordType::MX).unwrap();
    match &mx.data {
        RecordData::Mx { priority, exchange } => {
            assert_eq!(*priority, 10);
            assert_eq!(exchange, "mail.example.com");
        }
        other => panic!("期望 Mx，得到 {other:?}"),
    }
    // SRV 结构化（目标剥尾点还原）。
    let srv = recs.iter().find(|r| r.rtype == RecordType::SRV).unwrap();
    match &srv.data {
        RecordData::Srv { priority, weight, port, target } => {
            assert_eq!((*priority, *weight, *port), (0, 5, 3389));
            assert_eq!(target, "pc.example.com");
        }
        other => panic!("期望 Srv，得到 {other:?}"),
    }
}
