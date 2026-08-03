//! M9-DNS018: 京东云解析适配契约测试（本地 mock HTTP 服务器）
//!
//! 参考 `dns/src/test_support.rs` MockDns 模式：tokio `TcpListener` 起本地
//! `http://127.0.0.1` 服务，按官方 V2 接口语义维护内存存储（域名 + 解析记录），
//! 并记录全部请求（方法/路径/查询/头/体）供断言。
//!
//! 覆盖 `M9-DNS000` §七 契约模板：
//! 1. Authorization 头 JDCLOUD2-HMAC-SHA256 形状与 Credential 前缀；
//! 2. 四头齐全（x-jdcloud-algorithm/date/nonce/authorization）+ SignedHeaders；
//! 3. 签名可复算（固定输入 → 期望值比对见 `sign.rs`；此处再以捕获的线上请求
//!    复算 → 与发送的 Signature 一致）；
//! 4. list_domains 解析；
//! 5. upsert 查→增/改 语义（幂等）；
//! 6. delete；
//! 7. 错误码映射（Auth/NotFound/RateLimited/Server）；
//! 8. `@` 根记录名转换。

use super::client::JdcloudClient;
use super::sign;
use crate::provider::{ProviderError, Record, RecordData, RecordType};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

// ── 测试常量（固定凭据与地域，签名断言用）──
const ACCESS_KEY: &str = "TESTAK12345678901234567890";
const SECRET_KEY: &str = "TESTSK12345678901234567890";
const REGION: &str = "cn-north-1";

/// 捕获的 HTTP 请求。
#[derive(Debug, Clone)]
struct CapturedRequest {
    method: String,
    path: String,
    query: String,
    headers: BTreeMap<String, String>,
    body: String,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// mock 存储的域名。
#[derive(Debug, Clone)]
struct MockDomain {
    id: i64,
    name: String,
}

/// mock 存储的解析记录。
#[derive(Debug, Clone)]
struct MockRR {
    id: i64,
    domain_id: i64,
    host_record: String, // "@" 或相对名
    rtype: String,
    host_value: String,
    ttl: u32,
    mx_priority: i64,
    port: i64,
    weight: i64,
}

#[derive(Default)]
struct MockState {
    requests: Vec<CapturedRequest>,
    domains: Vec<MockDomain>,
    records: Vec<MockRR>,
    next_rr_id: i64,
    /// 预置错误响应（status, body）；每请求消费一条，耗尽后走正常路由。
    errors: VecDeque<(u16, String)>,
}

/// 本地 mock 京东云解析服务（V2 路由）。
struct MockJdcloud {
    addr: SocketAddr,
    state: Arc<Mutex<MockState>>,
}

impl MockJdcloud {
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

    fn client(&self) -> JdcloudClient {
        JdcloudClient::new(
            ACCESS_KEY.to_string(),
            SECRET_KEY.to_string(),
            REGION.to_string(),
            self.endpoint(),
        )
    }

    fn set_domains(&self, domains: &[&str]) {
        let mut s = self.state.lock().unwrap();
        s.domains = domains
            .iter()
            .enumerate()
            .map(|(i, d)| MockDomain {
                id: (i + 1) as i64,
                name: d.to_string(),
            })
            .collect();
    }

    /// 预置一条记录（name 为相对名，"" = 根；默认挂在 1 号域名）。
    fn seed_record(&self, name: &str, rtype: &str, value: &str, ttl: u32) {
        let mut s = self.state.lock().unwrap();
        s.next_rr_id += 1;
        let id = s.next_rr_id;
        s.records.push(MockRR {
            id,
            domain_id: 1,
            host_record: if name.is_empty() { "@".into() } else { name.into() },
            rtype: rtype.into(),
            host_value: value.into(),
            ttl,
            mx_priority: 0,
            port: 0,
            weight: 0,
        });
    }

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

    fn records(&self) -> Vec<MockRR> {
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
    let target = parts.next().unwrap_or("").to_string();
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));

    let req = CapturedRequest {
        method,
        path: path.to_string(),
        query: query.to_string(),
        headers,
        body,
    };
    let (status, resp_body) = {
        let mut s = state.lock().unwrap();
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

/// 状态码 + body。
type Response = (u16, String);

/// 京东云 V2 路由：`/v2/regions/{region}/domain[/{domainId}/ResourceRecord[/{rrId}]]`。
fn route(req: &CapturedRequest, state: &mut MockState) -> Response {
    let segs: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() < 4 || segs[0] != "v2" || segs[1] != "regions" || segs[3] != "domain" {
        return (404, "Not Found".to_string());
    }
    let ok = |v: serde_json::Value| (200, v.to_string());
    // domainId 段（segs[4] 存在时）。
    let domain_id = segs.get(4).and_then(|s| s.parse::<i64>().ok());

    match (req.method.as_str(), segs.len()) {
        // GET /v2/regions/{region}/domain —— describeDomains。
        ("GET", 4) => {
            let list: Vec<serde_json::Value> = state
                .domains
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "id": d.id,
                        "domainName": d.name,
                        "createTime": 0,
                        "expirationDate": 0,
                        "packId": 0,
                        "packName": "免费版",
                        "resolvingStatus": "2",
                        "creator": "mock",
                        "jcloudNs": true,
                        "lockStatus": 0,
                    })
                })
                .collect();
            ok(serde_json::json!({
                "requestId": "mock-req",
                "result": {
                    "dataList": list,
                    "currentCount": list.len(),
                    "totalCount": list.len(),
                    "totalPage": 1,
                }
            }))
        }
        // GET /v2/regions/{region}/domain/{domainId}/ResourceRecord —— describeResourceRecord。
        ("GET", 6) if domain_id.is_some() => {
            let list: Vec<serde_json::Value> = state
                .records
                .iter()
                .filter(|r| r.domain_id == domain_id.unwrap())
                .map(rr_info)
                .collect();
            ok(serde_json::json!({
                "requestId": "mock-req",
                "result": {
                    "dataList": list,
                    "currentCount": list.len(),
                    "totalCount": list.len(),
                    "totalPage": 1,
                }
            }))
        }
        // POST /v2/regions/{region}/domain/{domainId}/ResourceRecord —— createResourceRecord。
        ("POST", 6) if domain_id.is_some() => {
            let params: serde_json::Value =
                serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
            state.next_rr_id += 1;
            let rr = MockRR {
                id: state.next_rr_id,
                domain_id: domain_id.unwrap(),
                host_record: params.get("hostRecord").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                rtype: params.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                host_value: params.get("hostValue").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                ttl: params.get("ttl").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                mx_priority: params.get("mxPriority").and_then(|v| v.as_i64()).unwrap_or(0),
                port: params.get("port").and_then(|v| v.as_i64()).unwrap_or(0),
                weight: params.get("weight").and_then(|v| v.as_i64()).unwrap_or(0),
            };
            let info = rr_info(&rr);
            state.records.push(rr);
            ok(serde_json::json!({
                "requestId": "mock-req",
                "result": { "dataList": [info] }
            }))
        }
        // PUT/DELETE /v2/regions/{region}/domain/{domainId}/ResourceRecord/{rrId}。
        ("PUT", 7) if domain_id.is_some() => {
            let rr_id = segs[6].parse::<i64>().unwrap_or(0);
            let params: serde_json::Value =
                serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
            if let Some(idx) = state.records.iter().position(|r| r.id == rr_id) {
                let rec = &mut state.records[idx];
                rec.host_record = params.get("hostRecord").and_then(|v| v.as_str()).unwrap_or("").to_string();
                rec.rtype = params.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
                rec.host_value = params.get("hostValue").and_then(|v| v.as_str()).unwrap_or("").to_string();
                rec.ttl = params.get("ttl").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                rec.mx_priority = params.get("mxPriority").and_then(|v| v.as_i64()).unwrap_or(0);
                rec.port = params.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
                rec.weight = params.get("weight").and_then(|v| v.as_i64()).unwrap_or(0);
            }
            ok(serde_json::json!({ "requestId": "mock-req" }))
        }
        ("DELETE", 7) if domain_id.is_some() => {
            let rr_id = segs[6].parse::<i64>().unwrap_or(0);
            state.records.retain(|r| r.id != rr_id);
            ok(serde_json::json!({ "requestId": "mock-req" }))
        }
        _ => (404, "Not Found".to_string()),
    }
}

/// 存储记录 → RRInfo 响应条目。
fn rr_info(r: &MockRR) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "hostRecord": r.host_record,
        "hostValue": r.host_value,
        "type": r.rtype,
        "ttl": r.ttl,
        "mxPriority": r.mx_priority,
        "port": r.port,
        "weight": r.weight,
        "viewValue": [-1],
        "viewName": "默认",
        "resolvingStatus": "2",
    })
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

/// 1+2. Authorization 头 JDCLOUD2 形状 + 四头齐全 + SignedHeaders。
#[tokio::test]
async fn authorization_shape_and_jdcloud_headers() {
    let mock = MockJdcloud::start().await;
    mock.set_domains(&["example.com"]);
    let client = mock.client();
    client.list_domains().await.unwrap();

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, format!("/v2/regions/{REGION}/domain"));
    assert!(req.query.contains("pageNumber=1"), "query={}", req.query);

    // 四头齐全。
    assert_eq!(req.header("x-jdcloud-algorithm"), Some("JDCLOUD2-HMAC-SHA256"));
    let date = req.header("x-jdcloud-date").unwrap();
    assert!(date.len() == 16 && date.ends_with('Z'), "x-jdcloud-date 须为 YYYYMMDDTHHMMSSZ: {date}");
    assert_eq!(req.header("x-jdcloud-nonce").unwrap().len(), 32, "nonce 应为 32 hex");
    assert_eq!(req.header("content-type"), Some("application/json"));

    // Authorization 形状。
    let auth = req.header("authorization").unwrap();
    assert!(
        auth.starts_with(&format!(
            "JDCLOUD2-HMAC-SHA256 Credential={ACCESS_KEY}/{}/",
            &date[..8]
        )),
        "Authorization 必须以 Credential 前缀开头: {auth}"
    );
    assert!(
        auth.contains(&format!(
            "/{REGION}/domainservice/jdcloud2_request, SignedHeaders=content-type;x-jdcloud-date;x-jdcloud-nonce, Signature="
        )),
        "Authorization 形状错误: {auth}"
    );
    assert_eq!(auth.split("Signature=").nth(1).unwrap().len(), 64);
}

/// 3. 签名可复算：用捕获的线上请求（方法/路径/查询/头/体 + date/nonce）复算
/// Authorization → 与请求头完全一致。
#[tokio::test]
async fn signature_recomputable_from_wire() {
    let mock = MockJdcloud::start().await;
    mock.set_domains(&["example.com"]);
    let client = mock.client();
    client.list_domains().await.unwrap();

    let reqs = mock.requests();
    let req = &reqs[0];
    let date = req.header("x-jdcloud-date").unwrap();
    let nonce = req.header("x-jdcloud-nonce").unwrap();
    // 捕获的查询串 → (k, v) 对（简单参数无编码差异）。
    let query: Vec<(&str, &str)> = req
        .query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .collect();
    let headers = [
        ("content-type", req.header("content-type").unwrap()),
        ("x-jdcloud-date", date),
        ("x-jdcloud-nonce", nonce),
    ];
    let expected = sign::jdcloud2_authorization(
        ACCESS_KEY,
        SECRET_KEY,
        REGION,
        sign::SERVICE,
        date,
        &req.method,
        &req.path,
        &query,
        &headers,
        req.body.as_bytes(),
    );
    assert_eq!(req.header("authorization").unwrap(), expected);
}

/// 4. list_domains 解析 + test_connection。
#[tokio::test]
async fn list_domains_parses() {
    let mock = MockJdcloud::start().await;
    mock.set_domains(&["example.com", "kirin.dev"]);
    let domains = mock.client().list_domains().await.unwrap();
    assert_eq!(domains, vec!["example.com", "kirin.dev"]);
    mock.client().test_connection().await.unwrap();
}

/// 5. upsert 查→增/改 语义（幂等：同数据仅更新 TTL，重复 upsert 不新增）。
#[tokio::test]
async fn upsert_creates_then_updates_idempotent() {
    let mock = MockJdcloud::start().await;
    mock.set_domains(&["example.com"]);
    let client = mock.client();

    // 首次：不存在 → createResourceRecord（POST）。
    client
        .upsert_record("example.com", &plain("www", RecordType::A, "1.2.3.4", 600))
        .await
        .unwrap();
    // 同 hostRecord+type 新值 → modifyResourceRecord（PUT /{id}）。
    client
        .upsert_record("example.com", &plain("www", RecordType::A, "5.6.7.8", 600))
        .await
        .unwrap();
    // 同值不同 TTL → PUT 更新 TTL。
    client
        .upsert_record("example.com", &plain("www", RecordType::A, "5.6.7.8", 1200))
        .await
        .unwrap();
    // 完全幂等（同值同 TTL）→ 不发写请求。
    client
        .upsert_record("example.com", &plain("www", RecordType::A, "5.6.7.8", 1200))
        .await
        .unwrap();

    let reqs = mock.requests();
    // 4 次 upsert：每次 = 解析域名 GET + 列记录 GET；写入 = 1 POST + 2 PUT。
    assert_eq!(reqs.len(), 4 * 2 + 3, "请求序列不符合预期");
    assert_eq!(
        reqs.iter().filter(|r| r.method == "POST").count(),
        1,
        "仅首次 upsert 创建"
    );
    assert_eq!(
        reqs.iter().filter(|r| r.method == "PUT").count(),
        2,
        "两次更新"
    );

    // 创建请求体形状（AddRR）。
    let create = reqs.iter().find(|r| r.method == "POST").unwrap();
    let cbody: serde_json::Value = serde_json::from_str(&create.body).unwrap();
    assert_eq!(create.path, format!("/v2/regions/{REGION}/domain/1/ResourceRecord"));
    assert_eq!(cbody["hostRecord"], "www");
    assert_eq!(cbody["hostValue"], "1.2.3.4");
    assert_eq!(cbody["type"], "A");
    assert_eq!(cbody["ttl"], 600);
    assert_eq!(cbody["viewValue"], serde_json::json!([-1]));

    // 更新请求体形状（UpdateRR，携带 domainName + rrId 路径）。
    let puts: Vec<&CapturedRequest> = reqs
        .iter()
        .filter(|r| r.method == "PUT")
        .collect();
    assert!(puts[0].path.ends_with("/ResourceRecord/1"), "PUT 路径须含 rrId: {}", puts[0].path);
    let ub0: serde_json::Value = serde_json::from_str(&puts[0].body).unwrap();
    assert_eq!(ub0["domainName"], "example.com");
    assert_eq!(ub0["hostValue"], "5.6.7.8");
    let ub1: serde_json::Value = serde_json::from_str(&puts[1].body).unwrap();
    assert_eq!(ub1["ttl"], 1200);

    // 存储仅 1 条记录。
    let recs = mock.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].host_value, "5.6.7.8");
    assert_eq!(recs[0].ttl, 1200);
}

/// 6. delete：DELETE /{rrId}；删不存在 → NotFound。
#[tokio::test]
async fn delete_removes_and_not_found() {
    let mock = MockJdcloud::start().await;
    mock.set_domains(&["example.com"]);
    let client = mock.client();
    client
        .upsert_record("example.com", &plain("my-pc", RecordType::A, "1.2.3.4", 600))
        .await
        .unwrap();
    client
        .delete_record("example.com", "my-pc", RecordType::A)
        .await
        .unwrap();
    assert!(mock.records().is_empty());

    let reqs = mock.requests();
    let del = reqs.iter().find(|r| r.method == "DELETE").unwrap();
    assert!(del.path.ends_with("/ResourceRecord/1"), "DELETE 路径须含 rrId: {}", del.path);

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
    let mock = MockJdcloud::start().await;
    let client = mock.client();

    let jd_err = |code: &str, msg: &str| {
        format!(
            r#"{{"requestId":"r","error":{{"code":"{code}","status":"BAD_REQUEST","message":"{msg}"}}}}"#
        )
    };
    mock.push_error(403, &jd_err("AccessDenied", "无权限"));
    mock.push_error(400, &jd_err("InvalidParameter", "参数非法"));
    mock.push_error(404, &jd_err("ResourceNotFound", "域名不存在"));
    mock.push_error(429, &jd_err("RequestLimitExceeded", "超频"));
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
    let mock = MockJdcloud::start().await;
    mock.set_domains(&["example.com"]);
    let client = mock.client();
    client
        .upsert_record("example.com", &plain("", RecordType::A, "1.2.3.4", 600))
        .await
        .unwrap();

    let reqs = mock.requests();
    let create = reqs.iter().find(|r| r.method == "POST").unwrap();
    let body: serde_json::Value = serde_json::from_str(&create.body).unwrap();
    assert_eq!(body["hostRecord"], "@", "根记录必须以 @ 写入");

    let recs = client
        .query_records("example.com", Some(""), Some(RecordType::A))
        .await
        .unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].name, "");
    assert_eq!(recs[0].data.to_display_string(), "1.2.3.4");
}

/// 补充：query 按 name/rtype 过滤；MX/SRV 结构化往返。
#[tokio::test]
async fn query_filters_and_structured_roundtrip() {
    let mock = MockJdcloud::start().await;
    mock.set_domains(&["example.com"]);
    mock.seed_record("www", "A", "1.2.3.4", 600);
    mock.seed_record("www", "AAAA", "2001:db8::1", 600);
    mock.seed_record("mail", "MX", "mail.example.com", 300);
    mock.seed_record("_remote._tcp.my-pc", "SRV", "pc.example.com", 600);
    // 补 SRV 的优先级/端口/权重。
    {
        let mut s = mock.state.lock().unwrap();
        let srv = s.records.iter_mut().find(|r| r.rtype == "SRV").unwrap();
        srv.mx_priority = 0;
        srv.port = 3389;
        srv.weight = 5;
    }
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
            assert_eq!(*priority, 0);
            assert_eq!(exchange, "mail.example.com");
        }
        other => panic!("期望 Mx，得到 {other:?}"),
    }
    // SRV 结构化。
    let srv = recs.iter().find(|r| r.rtype == RecordType::SRV).unwrap();
    match &srv.data {
        RecordData::Srv { priority, weight, port, target } => {
            assert_eq!((*priority, *weight, *port), (0, 5, 3389));
            assert_eq!(target, "pc.example.com");
        }
        other => panic!("期望 Srv，得到 {other:?}"),
    }
}
