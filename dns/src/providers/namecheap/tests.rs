//! M9-DNS009 契约测试：自写 tokio mock HTTP server（127.0.0.1）+ 录制官方响应样例。
//!
//! 覆盖（对照 `M9-DNS000_Provider抽象接口规范.md` §七 契约模板）：
//! 1. 认证形状（GET query：ApiUser/ApiKey/UserName/ClientIp/Command）
//! 2. list_domains 解析
//! 3. 相对名 ↔ 厂商名互转（@ 根）
//! 4. upsert（getHosts 先查 → setHosts 整组替换，其余记录不丢）
//! 5. delete
//! 6. 错误码映射（Auth/NotFound/InvalidParameter/Server）
//! 7. SRV 往返（getsrvrecords/setsrvrecords 未公开命令）

use super::{NamecheapProvider, TTL_DEFAULT};
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
    /// 不含查询串的路径。
    path: String,
    /// 解码后的查询参数。
    query: Vec<(String, String)>,
}

impl MockRequest {
    fn query_param(&self, name: &str) -> Option<String> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

/// mock 响应。
struct MockResponse {
    status: u16,
    body: String,
    content_type: &'static str,
}

impl MockResponse {
    fn xml(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            content_type: "application/xml",
        }
    }
}

/// 运行中的 mock server（每个连接一个 tokio 任务）。
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

    /// 已捕获的全部请求（按到达顺序）。
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
    // Namecheap 为 GET 表单请求，body 只需消费不参与断言。
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await?;
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let (path, query_raw) = target.split_once('?').unwrap_or((target.as_str(), ""));
    let query = query_raw
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(kv), String::new()),
        })
        .collect();

    let req = MockRequest {
        method,
        path: path.to_string(),
        query,
    };
    requests.lock().unwrap().push(req.clone());

    let resp = handler(&req);
    let raw = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_line(resp.status),
        resp.content_type,
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
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    format!("{status} {reason}")
}

/// percent-decode（配合客户端手写 percent-encoding 的断言侧解码）。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 构造指向 mock 的 Provider（凭据为测试固定值）。
///
/// base_url 带 `/xml.response` 路径后缀，与生产端点形状一致
/// （`https://api.namecheap.com/xml.response`），断言请求路径用。
async fn provider_with(mock: &MockApi) -> NamecheapProvider {
    NamecheapProvider::new_at(
        "api-user".to_string(),
        "api-key-123".to_string(),
        "user-name".to_string(),
        "203.0.113.9".to_string(),
        format!("{}/xml.response", mock.base_url()),
    )
}

/// 最小 OK 响应（无业务结果）。
fn ok_xml() -> MockResponse {
    MockResponse::xml(
        r#"<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors/>
  <CommandResponse Type="x"/>
</ApiResponse>"#,
    )
}

// ────────────────────────────────────────────────────────────────
// 契约测试
// ────────────────────────────────────────────────────────────────

/// 1+2. 认证形状 + list_domains 解析。
#[tokio::test]
async fn list_domains_sends_auth_query_params_and_parses() {
    let mock = MockApi::start(|_req| {
        MockResponse::xml(
            r#"<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors />
  <CommandResponse Type="namecheap.domains.getList">
    <DomainGetListResult>
      <Domain ID="1" Name="example.com" User="u" Created="01/01/2024" Expires="01/01/2025" IsExpired="false" IsLocked="false" AutoRenew="false" WhoisGuard="ENABLED" />
      <Domain ID="2" Name="kirin.dev" User="u" Created="01/01/2024" Expires="01/01/2025" IsExpired="false" IsLocked="false" AutoRenew="false" WhoisGuard="ENABLED" />
    </DomainGetListResult>
    <Paging><TotalItems>2</TotalItems><CurrentPage>1</CurrentPage><PageSize>100</PageSize></Paging>
  </CommandResponse>
</ApiResponse>"#,
        )
    })
    .await;
    let p = provider_with(&mock).await;
    let domains = p.list_domains().await.unwrap();
    assert_eq!(domains, vec!["example.com", "kirin.dev"]);

    // 认证形状：GET + query 参数 ApiUser/ApiKey/UserName/ClientIp/Command/SLD-TLD。
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, "/xml.response");
    assert_eq!(
        reqs[0].query_param("Command").as_deref(),
        Some("namecheap.domains.getList")
    );
    assert_eq!(reqs[0].query_param("ApiUser").as_deref(), Some("api-user"));
    assert_eq!(reqs[0].query_param("ApiKey").as_deref(), Some("api-key-123"));
    assert_eq!(reqs[0].query_param("UserName").as_deref(), Some("user-name"));
    assert_eq!(reqs[0].query_param("ClientIp").as_deref(), Some("203.0.113.9"));
    assert_eq!(reqs[0].query_param("Page").as_deref(), Some("1"));
    assert_eq!(reqs[0].query_param("PageSize").as_deref(), Some("100"));
}

/// 3. 相对名 ↔ 厂商名互转（"@" 根 ↔ ""）+ 查询过滤 + 不可表达类型跳过。
#[tokio::test]
async fn query_records_converts_root_at_sign_and_filters() {
    let mock = MockApi::start(|req| {
        match req.query_param("Command").as_deref() {
            Some("namecheap.domains.dns.getHosts") => MockResponse::xml(
                r#"<ApiResponse Status="OK"><Errors/>
<CommandResponse><DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true">
  <host HostId="1" Name="@" Type="A" Address="203.0.113.7" MXPref="0" TTL="1800"/>
  <host HostId="2" Name="www" Type="A" Address="198.51.100.9" MXPref="0" TTL="60"/>
  <host HostId="3" Name="@" Type="MX" Address="mail.example.com" MXPref="10" TTL="1800"/>
  <host HostId="4" Name="@" Type="URL" Address="http://example.com" MXPref="0" TTL="1800"/>
</DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#,
            ),
            Some("namecheap.domains.dns.getsrvrecords") => {
                // 无 SRV → 响应无 <Result>（空 zone 形态）。
                MockResponse::xml(
                    r#"<ApiResponse Status="OK"><Errors/><CommandResponse/></ApiResponse>"#,
                )
            }
            _ => ok_xml(),
        }
    })
    .await;
    let p = provider_with(&mock).await;
    let all = p.query_records("example.com", None, None).await.unwrap();
    // URL 类型无法表达 → 跳过；其余 3 条。
    assert_eq!(all.len(), 3);
    let a_root = all
        .iter()
        .find(|r| r.rtype == RecordType::A && r.name.is_empty())
        .unwrap();
    assert_eq!(a_root.data, RecordData::Plain("203.0.113.7".into()));
    assert_eq!(a_root.ttl, 1800);
    let mx = all.iter().find(|r| r.rtype == RecordType::MX).unwrap();
    assert_eq!(
        mx.data,
        RecordData::Mx {
            priority: 10,
            exchange: "mail.example.com".into()
        }
    );
    assert_eq!(mx.name, "", "MX 根记录 name 应为空");
    // 过滤：name=www + type=A。
    let filtered = p
        .query_records("example.com", Some("www"), Some(RecordType::A))
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "www");
    assert_eq!(filtered[0].ttl, 60);
}

/// 4. upsert：getHosts 先查 → setHosts 整组替换（SLD/TLD 拆分、未知类型保留、@ 根）。
#[tokio::test]
async fn upsert_replaces_group_preserving_unknown_types() {
    // mock 状态：("@",A,"203.0.113.7",1800) + ("@",URL,"http://example.com",1800)。
    let state: Arc<Mutex<Vec<(String, String, String, u32)>>> = Arc::new(Mutex::new(vec![
        ("@".to_string(), "A".to_string(), "203.0.113.7".to_string(), 1800),
        (
            "@".to_string(),
            "URL".to_string(),
            "http://example.com".to_string(),
            1800,
        ),
    ]));
    let mock = MockApi::start({
        let state = state.clone();
        move |req| {
            match req.query_param("Command").as_deref() {
                Some("namecheap.domains.dns.getHosts") => {
                    let st = state.lock().unwrap();
                    let hosts = st
                        .iter()
                        .map(|(n, t, a, ttl)| {
                            format!(
                                "<host HostId=\"1\" Name=\"{n}\" Type=\"{t}\" Address=\"{a}\" MXPref=\"0\" TTL=\"{ttl}\"/>"
                            )
                        })
                        .collect::<String>();
                    MockResponse::xml(format!(
                        "<ApiResponse Status=\"OK\"><Errors/><CommandResponse><DomainDNSGetHostsResult Domain=\"example.com\" IsUsingOurDNS=\"true\">{hosts}</DomainDNSGetHostsResult></CommandResponse></ApiResponse>"
                    ))
                }
                _ => {
                    // setHosts：把提交的 host 组写入 state（模拟整组替换）。
                    let mut st = state.lock().unwrap();
                    st.clear();
                    let mut i = 1;
                    loop {
                        match (
                            req.query_param(&format!("HostName{i}")),
                            req.query_param(&format!("RecordType{i}")),
                            req.query_param(&format!("Address{i}")),
                            req.query_param(&format!("TTL{i}")),
                        ) {
                            (Some(n), Some(t), Some(a), Some(ttl)) => {
                                st.push((
                                    n,
                                    t,
                                    a,
                                    ttl.parse().unwrap_or(TTL_DEFAULT),
                                ));
                                i += 1;
                            }
                            _ => break,
                        }
                    }
                    MockResponse::xml(
                        r#"<ApiResponse Status="OK"><Errors/><CommandResponse><DomainDNSSetHostsResult Domain="example.com" IsSuccess="true"/></CommandResponse></ApiResponse>"#,
                    )
                }
            }
        }
    })
    .await;
    let p = provider_with(&mock).await;
    let rec = Record {
        name: String::new(), // 根
        rtype: RecordType::A,
        ttl: 600,
        data: RecordData::Plain("5.6.7.8".into()),
    };
    p.upsert_record("example.com", &rec).await.unwrap();

    let reqs = mock.requests();
    // 先查后写：getHosts → setHosts。
    assert_eq!(reqs.len(), 2);
    assert_eq!(
        reqs[0].query_param("Command").as_deref(),
        Some("namecheap.domains.dns.getHosts")
    );
    assert_eq!(
        reqs[1].query_param("Command").as_deref(),
        Some("namecheap.domains.dns.setHosts")
    );
    // SLD/TLD 拆分：example.com → SLD=example, TLD=com。
    assert_eq!(reqs[1].query_param("SLD").as_deref(), Some("example"));
    assert_eq!(reqs[1].query_param("TLD").as_deref(), Some("com"));
    // 整组：URL 记录保留 + A 已更新（根名写为 "@"）。
    assert_eq!(reqs[1].query_param("HostName1").as_deref(), Some("@"));
    assert_eq!(reqs[1].query_param("RecordType1").as_deref(), Some("URL"));
    assert_eq!(reqs[1].query_param("HostName2").as_deref(), Some("@"));
    assert_eq!(reqs[1].query_param("RecordType2").as_deref(), Some("A"));
    assert_eq!(reqs[1].query_param("Address2").as_deref(), Some("5.6.7.8"));
    assert_eq!(reqs[1].query_param("TTL2").as_deref(), Some("600"));
    let st = state.lock().unwrap();
    assert_eq!(st.len(), 2, "未知类型记录不得被整组替换丢弃");
    assert!(st.contains(&(
        "@".to_string(),
        "URL".to_string(),
        "http://example.com".to_string(),
        1800
    )));
    assert!(st.contains(&("@".to_string(), "A".to_string(), "5.6.7.8".to_string(), 600)));
}

/// 4b. MX 写入：MXPref 必填 + EmailType=MX；ttl=0 → 默认 1800 收敛。
#[tokio::test]
async fn upsert_mx_sends_mxpref_and_email_type() {
    let mock = MockApi::start(|req| match req.query_param("Command").as_deref() {
        Some("namecheap.domains.dns.getHosts") => MockResponse::xml(
            r#"<ApiResponse Status="OK"><Errors/><CommandResponse><DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true"/></CommandResponse></ApiResponse>"#,
        ),
        _ => MockResponse::xml(
            r#"<ApiResponse Status="OK"><Errors/><CommandResponse><DomainDNSSetHostsResult Domain="example.com" IsSuccess="true"/></CommandResponse></ApiResponse>"#,
        ),
    })
    .await;
    let p = provider_with(&mock).await;
    let rec = Record {
        name: String::new(),
        rtype: RecordType::MX,
        ttl: 0,
        data: RecordData::Mx {
            priority: 10,
            exchange: "mail.example.com".into(),
        },
    };
    p.upsert_record("example.com", &rec).await.unwrap();
    let reqs = mock.requests();
    let set = &reqs[1];
    assert_eq!(set.query_param("HostName1").as_deref(), Some("@"));
    assert_eq!(set.query_param("RecordType1").as_deref(), Some("MX"));
    assert_eq!(
        set.query_param("Address1").as_deref(),
        Some("mail.example.com")
    );
    assert_eq!(set.query_param("MXPref1").as_deref(), Some("10"));
    assert_eq!(set.query_param("EmailType").as_deref(), Some("MX"));
    assert_eq!(set.query_param("TTL1").as_deref(), Some("1800"), "ttl=0 → 官方默认 1800");
}

/// 5. delete：整组剔除目标 (name, rtype)，其余保留；删不存在 → NotFound。
#[tokio::test]
async fn delete_removes_group_and_keeps_others() {
    let state: Arc<Mutex<Vec<(String, String, String, u32)>>> = Arc::new(Mutex::new(vec![
        ("@".to_string(), "A".to_string(), "203.0.113.7".to_string(), 1800),
        ("www".to_string(), "AAAA".to_string(), "2001:db8::1".to_string(), 60),
    ]));
    let mock = MockApi::start({
        let state = state.clone();
        move |req| match req.query_param("Command").as_deref() {
            Some("namecheap.domains.dns.getHosts") => {
                let st = state.lock().unwrap();
                let hosts = st
                    .iter()
                    .map(|(n, t, a, ttl)| {
                        format!(
                            "<host HostId=\"1\" Name=\"{n}\" Type=\"{t}\" Address=\"{a}\" MXPref=\"0\" TTL=\"{ttl}\"/>"
                        )
                    })
                    .collect::<String>();
                MockResponse::xml(format!(
                    "<ApiResponse Status=\"OK\"><Errors/><CommandResponse><DomainDNSGetHostsResult Domain=\"example.com\" IsUsingOurDNS=\"true\">{hosts}</DomainDNSGetHostsResult></CommandResponse></ApiResponse>"
                ))
            }
            _ => {
                let mut st = state.lock().unwrap();
                st.clear();
                let mut i = 1;
                loop {
                    match (
                        req.query_param(&format!("HostName{i}")),
                        req.query_param(&format!("RecordType{i}")),
                        req.query_param(&format!("Address{i}")),
                        req.query_param(&format!("TTL{i}")),
                    ) {
                        (Some(n), Some(t), Some(a), Some(ttl)) => {
                            st.push((n, t, a, ttl.parse().unwrap_or(TTL_DEFAULT)));
                            i += 1;
                        }
                        _ => break,
                    }
                }
                MockResponse::xml(
                    r#"<ApiResponse Status="OK"><Errors/><CommandResponse><DomainDNSSetHostsResult Domain="example.com" IsSuccess="true"/></CommandResponse></ApiResponse>"#,
                )
            }
        }
    })
    .await;
    let p = provider_with(&mock).await;
    p.delete_record("example.com", "", RecordType::A)
        .await
        .unwrap();
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 2);
    let set = &reqs[1];
    // 只剩 AAAA。
    assert_eq!(set.query_param("HostName1").as_deref(), Some("www"));
    assert_eq!(set.query_param("RecordType1").as_deref(), Some("AAAA"));
    assert_eq!(set.query_param("HostName2"), None, "A 组应被删除");

    // 再删不存在的 → NotFound（无第二次 setHosts）。
    let err = p
        .delete_record("example.com", "nope", RecordType::TXT)
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::NotFound { .. }));
    assert_eq!(mock.requests().len(), 3, "getHosts×2 + setHosts×1");
}

/// 6. 错误码映射：XML Status=ERROR + <Error Number> → 统一错误；HTTP 5xx → Server。
#[tokio::test]
async fn error_codes_map_to_unified_errors() {
    // 每种错误码单独起一个 mock，逐项断言。
    let cases: Vec<(u32, &str, Box<dyn Fn(&ProviderError) -> bool + Send>)> = vec![
        (1011002, "auth-bad-key", Box::new(|e| matches!(e, ProviderError::Auth { .. }))),
        (1001001, "auth-invalid", Box::new(|e| matches!(e, ProviderError::Auth { .. }))),
        (2015122, "param", Box::new(|e| matches!(e, ProviderError::InvalidParameter { .. }))),
        (2016083, "notfound", Box::new(|e| matches!(e, ProviderError::NotFound { .. }))),
        (9999999, "other", Box::new(|e| matches!(e, ProviderError::Other(_)))),
    ];
    for (number, label, check) in cases {
        let label_owned = label.to_string();
        let mock = MockApi::start(move |_req| {
            MockResponse::xml(format!(
                r#"<ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response">
  <Errors><Error Number="{number}">{label_owned}</Error></Errors>
  <RequestedCommand>namecheap.domains.getList</RequestedCommand>
</ApiResponse>"#
            ))
        })
        .await;
        let p = provider_with(&mock).await;
        let err = p.list_domains().await.unwrap_err();
        assert!(check(&err), "错误码 {number} → {:?}", err);
    }

    // HTTP 500 → Server。
    let mock = MockApi::start(|_req| MockResponse {
        status: 500,
        body: "boom".to_string(),
        content_type: "text/plain",
    })
    .await;
    let p = provider_with(&mock).await;
    let err = p.list_domains().await.unwrap_err();
    assert!(matches!(err, ProviderError::Server { status: 500, .. }), "{err:?}");
}

/// 7. SRV 往返：getsrvrecords 解析 + setsrvrecords 参数组装（未公开命令）。
#[tokio::test]
async fn srv_roundtrip_via_srv_commands() {
    let state: Arc<Mutex<Vec<(String, String, u16, u16, u16, String)>>> = Arc::new(Mutex::new(
        vec![(
            "_remote.".to_string(),
            "_tcp".to_string(),
            0u16,
            1u16,
            3389u16,
            "my-pc.example.com.".to_string(),
        )],
    ));
    let mock = MockApi::start({
        let state = state.clone();
        move |req| match req.query_param("Command").as_deref() {
            Some("namecheap.domains.dns.getHosts") => MockResponse::xml(
                r#"<ApiResponse Status="OK"><Errors/><CommandResponse><DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true"/></CommandResponse></ApiResponse>"#,
            ),
            Some("namecheap.domains.dns.getsrvrecords") => {
                let st = state.lock().unwrap();
                let recs = st
                    .iter()
                    .map(|(svc, proto, prio, w, port, tgt)| {
                        format!(
                            "<Records><Service>{svc}</Service><Protocol>{proto}</Protocol><Priority>{prio}</Priority><Weight>{w}</Weight><Port>{port}</Port><Target>{tgt}</Target></Records>"
                        )
                    })
                    .collect::<String>();
                MockResponse::xml(format!(
                    "<ApiResponse Status=\"OK\"><Errors/><CommandResponse><Result>{recs}</Result></CommandResponse></ApiResponse>"
                ))
            }
            _ => {
                // setsrvrecords：存回 state。
                let mut st = state.lock().unwrap();
                st.clear();
                let count: usize = req
                    .query_param("SrvCount")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                for i in 1..=count {
                    let g = |suffix: &str| {
                        req.query_param(&format!("{}{}", suffix, i)).unwrap_or_default()
                    };
                    st.push((
                        g("Service"),
                        g("Protocol"),
                        g("Priority").parse().unwrap_or(0),
                        g("Weight").parse().unwrap_or(0),
                        g("Port").parse().unwrap_or(0),
                        g("Target"),
                    ));
                }
                MockResponse::xml(
                    r#"<ApiResponse Status="OK"><Errors/><CommandResponse><Result><Inserted>0</Inserted><Updated>1</Updated><Deleted>0</Deleted></Result></CommandResponse></ApiResponse>"#,
                )
            }
        }
    })
    .await;
    let p = provider_with(&mock).await;

    // 查询 → 结构化 Srv 数据（往返一致）。
    let found = p
        .query_records("example.com", Some("_remote._tcp"), Some(RecordType::SRV))
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
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
        other => panic!("期望 Srv 数据，实际 {other:?}"),
    }

    // 写入：同名替换（整组），参数组 Service1/Protocol1/Priority1/Port1/Target1/Weight1。
    let rec = Record {
        name: "_remote._tcp".to_string(),
        rtype: RecordType::SRV,
        ttl: 0,
        data: RecordData::Srv {
            priority: 0,
            weight: 1,
            port: 3389,
            target: "new-pc.example.com.".to_string(),
        },
    };
    p.upsert_record("example.com", &rec).await.unwrap();
    let reqs = mock.requests();
    let set = reqs.last().unwrap();
    assert_eq!(
        set.query_param("Command").as_deref(),
        Some("namecheap.domains.dns.setsrvrecords")
    );
    assert_eq!(set.query_param("SrvCount").as_deref(), Some("1"));
    assert_eq!(set.query_param("Service1").as_deref(), Some("_remote."));
    assert_eq!(set.query_param("Protocol1").as_deref(), Some("_tcp"));
    assert_eq!(set.query_param("Priority1").as_deref(), Some("0"));
    assert_eq!(set.query_param("Weight1").as_deref(), Some("1"));
    assert_eq!(set.query_param("Port1").as_deref(), Some("3389"));
    assert_eq!(
        set.query_param("Target1").as_deref(),
        Some("new-pc.example.com.")
    );
    // 读回与写入一致。
    let st = state.lock().unwrap();
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].5, "new-pc.example.com.");
}

/// 边界：整组超过 20 条 → 提示错误，不发出 setHosts 请求。
#[tokio::test]
async fn more_than_20_hosts_reports_limit() {
    let hosts: Vec<String> = (0..21)
        .map(|i| format!("<host HostId=\"{}\" Name=\"h{i}\" Type=\"A\" Address=\"1.2.3.4\" MXPref=\"0\" TTL=\"1800\"/>", i + 1))
        .collect();
    let xml = format!(
        "<ApiResponse Status=\"OK\"><Errors/><CommandResponse><DomainDNSGetHostsResult Domain=\"example.com\" IsUsingOurDNS=\"true\">{}</DomainDNSGetHostsResult></CommandResponse></ApiResponse>",
        hosts.join("")
    );
    let mock = MockApi::start(move |req| match req.query_param("Command").as_deref() {
        Some("namecheap.domains.dns.getHosts") => MockResponse::xml(xml.clone()),
        _ => ok_xml(),
    })
    .await;
    let p = provider_with(&mock).await;
    let rec = Record {
        name: "new".to_string(),
        rtype: RecordType::A,
        ttl: 600,
        data: RecordData::Plain("9.9.9.9".into()),
    };
    let err = p.upsert_record("example.com", &rec).await.unwrap_err();
    assert!(matches!(err, ProviderError::Other(_)), "{err:?}");
    assert!(err.to_string().contains("20"), "错误信息应提示 20 条限制: {err}");
    // 只发生了 getHosts，没有 setHosts 写请求。
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].query_param("Command").as_deref(),
        Some("namecheap.domains.dns.getHosts")
    );
}

/// 注册表工厂：凭据变体匹配。
#[test]
fn register_factory_builds_from_credential() {
    let mut registry = crate::provider::ProviderRegistry::new();
    super::register(&mut registry);
    assert!(registry.has("namecheap"));
    let cred = crate::provider::Credential::Namecheap {
        api_user: "u".into(),
        api_key: "k".into(),
        user_name: "un".into(),
        client_ip: "1.2.3.4".into(),
    };
    let p = registry.build("namecheap", &cred).unwrap();
    assert_eq!(p.name(), "namecheap");
    // 凭据不匹配 → 构造成功但调用报错（不 panic、不打印凭据）。
    let wrong = crate::provider::Credential::Porkbun {
        api_key: "k".into(),
        secret_key: "s".into(),
    };
    let p2 = registry.build("namecheap", &wrong).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let err = rt.block_on(p2.list_domains()).unwrap_err();
    assert!(err.to_string().contains("不匹配"), "{err}");
}
