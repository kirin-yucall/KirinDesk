use super::auth::Auth;
use super::error::GoDaddyError;
use super::record::{ManagedRecord, Record};
use crate::validate::{self, MAX_RECORD_DATA_LEN, MAX_RESPONSE_BYTES};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::Response;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Maximum number of retries for rate-limited requests.
const MAX_RETRIES: u32 = 3;

/// Initial backoff duration for retries.
const INITIAL_BACKOFF_MS: u64 = 1000;

/// 测试环境显式放行开关（S-14a / F-17）：设置后允许 `http://` 的 `api_url`。
///
/// 仅限测试/本地 mock 使用；生产路径默认拒绝非 https 并给出明确错误。
/// 该开关**不是**静默放行：放行时 `try_new` 会输出显式 warn 标注。
const ALLOW_HTTP_ENV: &str = "KIRIN_DNS_ALLOW_HTTP";

// cfg(test) 线程放行开关：仅测试构建编译，生产二进制不可达。
// 由 `test_support::MockDns::start()`（http://127.0.0.1 mock）显式开启，
// 避免每个测试调用点重复设置环境变量。
#[cfg(test)]
thread_local! {
    static ALLOW_HTTP_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// 显式打开当前测试线程的 http 放行（仅 cfg(test) 存在；生产路径无此函数）。
#[cfg(test)]
pub(crate) fn allow_http_for_tests() {
    ALLOW_HTTP_TEST.with(|f| f.set(true));
}

/// 当前环境是否显式放行 http（env 开关 或 测试线程开关）。
fn http_allowed_for_tests() -> bool {
    #[cfg(test)]
    {
        if ALLOW_HTTP_TEST.with(|f| f.get()) {
            return true;
        }
    }
    std::env::var(ALLOW_HTTP_ENV).is_ok()
}

/// GoDaddy Domains API client.
///
/// Manages DNS records (SRV, AAAA, TXT) via the GoDaddy REST API.
///
/// # Example
///
/// ```no_run
/// use kirin_desk_dns::godaddy::client::GoDaddyClient;
///
/// # async fn example() {
/// let client = GoDaddyClient::new("api_key", "api_secret", "https://api.godaddy.com");
/// let records = client.get_records("example.com", "AAAA", "my-device").await;
/// # }
/// ```
#[derive(Clone)]
#[allow(dead_code)]
pub struct GoDaddyClient {
    /// Inner reqwest client.
    client: reqwest::Client,

    /// Authentication handler.
    auth: Arc<Auth>,

    /// Base URL for the GoDaddy API (e.g., "https://api.godaddy.com").
    base_url: String,
}

impl GoDaddyClient {
    /// Create a new GoDaddy API client.
    ///
    /// * `api_key` — GoDaddy API key from developer portal.
    /// * `api_secret` — GoDaddy API secret.
    /// * `base_url` — API base URL (production: `https://api.godaddy.com`,
    ///   OTE/test: `https://api.ote-godaddy.com`).
    ///
    /// # Panics
    ///
    /// Panics when `base_url` does not start with `https://` (S-14a / F-17).
    /// Use [`Self::try_new`] for a fallible, programmatic path.
    pub fn new(
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self::try_new(api_key, api_secret, base_url).expect(
            "GoDaddyClient::new: api_url must start with 'https://' \
             (test-only bypass: set env KIRIN_DNS_ALLOW_HTTP)",
        )
    }

    /// Fallible constructor — enforces HTTPS on `base_url` (S-14a / F-17).
    ///
    /// `http://` is rejected unless **explicitly** allowed for testing:
    /// - env var `KIRIN_DNS_ALLOW_HTTP` is set (test/local-mock only, never
    ///   in production config); or
    /// - `cfg(test)` build and the current test thread opted in via
    ///   `crate::godaddy::client::allow_http_for_tests()` (used by
    ///   `test_support::MockDns`).
    ///
    /// When the bypass is active a `warn!` is emitted so the exception is
    /// never silent; production builds never contain the cfg(test) switch.
    pub fn try_new(
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Result<Self, GoDaddyError> {
        let base_url: String = base_url.into().trim_end_matches('/').to_string();
        if !base_url.starts_with("https://") {
            if http_allowed_for_tests() {
                // 显式放行开关（仅测试环境）——不静默：带标注警告。
                warn!(
                    "{} / test allow switch active: accepting non-HTTPS GoDaddy \
                     base URL '{}' (TEST-ONLY, never set in production)",
                    ALLOW_HTTP_ENV, base_url
                );
            } else {
                return Err(GoDaddyError::Configuration(format!(
                    "api_url must start with 'https://' (got '{}'); \
                     set env {} only for explicit test-environment bypass",
                    base_url, ALLOW_HTTP_ENV
                )));
            }
        }

        let auth = Auth::new(api_key, api_secret);
        let auth_header = auth.authorization_header();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&auth_header)
                        .expect("Invalid authorization header value"),
                );
                headers.insert(
                    reqwest::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                headers.insert(
                    reqwest::header::ACCEPT,
                    HeaderValue::from_static("application/json"),
                );
                headers
            })
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("Failed to build reqwest client");

        Ok(Self {
            client,
            auth: Arc::new(auth),
            base_url,
        })
    }

    /// Build the URL for record operations.
    ///
    /// Pattern: `{base}/v1/domains/{domain}/records/{type}/{name}`
    ///
    /// 校验（S-14b / F-18）：`domain` 必须是 RFC 1123 主机名；`name` 必须是合法
    /// DNS 记录名（标签 `[a-zA-Z0-9_-]`，点分隔）——拒绝 `/ ? # 空白` 等 URL 注入。
    fn record_url(
        &self,
        domain: &str,
        record_type: &str,
        name: &str,
    ) -> Result<String, GoDaddyError> {
        if !validate::validate_hostname(domain) {
            return Err(GoDaddyError::InvalidParameters {
                body: format!(
                    "invalid domain '{}' (must be an RFC 1123 hostname)",
                    domain
                ),
            });
        }
        if !validate::validate_record_name(name) {
            return Err(GoDaddyError::InvalidParameters {
                body: format!("invalid record name '{}'", name),
            });
        }
        Ok(format!(
            "{}/v1/domains/{}/records/{}/{}",
            self.base_url, domain, record_type, name
        ))
    }

    /// GET DNS records of a specific type for a given name.
    ///
    /// Returns a list of matching records.
    ///
    /// 响应护栏（S-14c / F-19）：`Content-Length` 预检 ≤ 1 MiB + 实际字节复核；
    /// 单条 record `data` ≤ 4 KiB。
    pub async fn get_records(
        &self,
        domain: &str,
        record_type: &str,
        name: &str,
    ) -> Result<Vec<Record>, GoDaddyError> {
        let url = self.record_url(domain, record_type, name)?;
        debug!("GoDaddy GET {} {} {}", record_type, domain, name);
        let response = self.execute_with_retry(|| {
            let client = self.client.clone();
            let url = url.clone();
            async move { client.get(&url).send().await }
        })
        .await?;

        // F-19: Content-Length 预检（响应体读取前）。
        if let Some(len) = response.content_length() {
            if len as usize > MAX_RESPONSE_BYTES {
                return Err(GoDaddyError::ResponseTooLarge {
                    limit: MAX_RESPONSE_BYTES,
                    actual: len as usize,
                });
            }
        }
        // F-19: 实际字节复核（Content-Length 缺失/失真时的兜底）。
        let body = response.bytes().await?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(GoDaddyError::ResponseTooLarge {
                limit: MAX_RESPONSE_BYTES,
                actual: body.len(),
            });
        }
        let records: Vec<Record> = serde_json::from_slice(&body)?;
        // F-19: 单条 record data 长度上限。
        for record in &records {
            if record.data.len() > MAX_RECORD_DATA_LEN {
                return Err(GoDaddyError::InvalidParameters {
                    body: format!(
                        "record data exceeds {} bytes (got {}); refusing oversized record",
                        MAX_RECORD_DATA_LEN,
                        record.data.len()
                    ),
                });
            }
        }
        debug!("GoDaddy GET {} {} {} -> {} records", record_type, domain, name, records.len());
        Ok(records)
    }

    /// PUT (create/replace) DNS records at a given name.
    ///
    /// This replaces ALL records for the specified `{type}/{name}`.
    pub async fn put_records(
        &self,
        domain: &str,
        record_type: &str,
        name: &str,
        records: &[Record],
    ) -> Result<(), GoDaddyError> {
        let url = self.record_url(domain, record_type, name)?;
        // F-19: 写出侧同限（自控数据，防脏写）。
        for record in records {
            if record.data.len() > MAX_RECORD_DATA_LEN {
                return Err(GoDaddyError::InvalidParameters {
                    body: format!(
                        "record data exceeds {} bytes (got {}); refusing oversized write",
                        MAX_RECORD_DATA_LEN,
                        record.data.len()
                    ),
                });
            }
        }
        let body = serde_json::to_string(records)?;
        trace!("GoDaddy PUT {} {} {} -> body={}", record_type, domain, name, body);

        let _response = self
            .execute_with_retry(|| {
                let client = self.client.clone();
                let url = url.clone();
                let body = body.clone();
                async move { client.put(&url).body(body).send().await }
            })
            .await?;

        debug!("GoDaddy PUT {} {} {} -> OK", record_type, domain, name);
        Ok(())
    }

    /// DELETE all DNS records of a specific type for a given name.
    pub async fn delete_record(
        &self,
        domain: &str,
        record_type: &str,
        name: &str,
    ) -> Result<(), GoDaddyError> {
        let url = self.record_url(domain, record_type, name)?;
        debug!("GoDaddy DELETE {} {} {}", record_type, domain, name);

        let response = self
            .execute_with_retry(|| {
                let client = self.client.clone();
                let url = url.clone();
                async move { client.delete(&url).send().await }
            })
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(GoDaddyError::from_response(response).await)
        }
    }

    // ────────────────────────────────────────────────────────────────
    // M9-DNS000 (DNS-MNT-003/004/005): 域名维护客户端端点
    // 域名列表 / 测试连接最小查询 / 域名下全量记录查询。
    // ────────────────────────────────────────────────────────────────

    /// GET /v1/domains —— 当前账号可管理的域名列表（DNS-MNT-004）。
    ///
    /// 响应形如 `[{"domain":"example.com","status":"ACTIVE",...}, ...]`；
    /// 仅提取 `domain` 字段。本端点即 DNS-MNT-003 的「最小查询」测试连接载体。
    pub async fn list_domains(&self) -> Result<Vec<String>, GoDaddyError> {
        let url = format!("{}/v1/domains", self.base_url);
        debug!("GoDaddy GET /v1/domains");
        let response = self
            .execute_with_retry(|| {
                let client = self.client.clone();
                let url = url.clone();
                async move { client.get(&url).send().await }
            })
            .await?;
        // F-19: Content-Length 预检（响应体读取前）。
        if let Some(len) = response.content_length() {
            if len as usize > MAX_RESPONSE_BYTES {
                return Err(GoDaddyError::ResponseTooLarge {
                    limit: MAX_RESPONSE_BYTES,
                    actual: len as usize,
                });
            }
        }
        let body = response.bytes().await?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(GoDaddyError::ResponseTooLarge {
                limit: MAX_RESPONSE_BYTES,
                actual: body.len(),
            });
        }
        // `DomainItem` 只声明需要的字段，忽略其余（status/expires 等）。
        #[derive(serde::Deserialize)]
        struct DomainItem {
            domain: String,
        }
        let items: Vec<DomainItem> = serde_json::from_slice(&body)?;
        let domains: Vec<String> = items.into_iter().map(|d| d.domain).collect();
        debug!("GoDaddy GET /v1/domains -> {} domains", domains.len());
        Ok(domains)
    }

    /// GET /v1/domains/{domain}/records —— 域名下全量记录（DNS-MNT-005）。
    ///
    /// 返回每条含 类型/名称/数据/TTL 的 [`ManagedRecord`]；`record_type` 为
    /// `Some("A")` 时附加 `?type=A` 服务端筛选。`domain` 经 RFC 1123 校验
    /// （S-14b / F-18 同 `record_url`）。
    pub async fn get_all_records(
        &self,
        domain: &str,
        record_type: Option<&str>,
    ) -> Result<Vec<ManagedRecord>, GoDaddyError> {
        if !validate::validate_hostname(domain) {
            return Err(GoDaddyError::InvalidParameters {
                body: format!(
                    "invalid domain '{}' (must be an RFC 1123 hostname)",
                    domain
                ),
            });
        }
        let mut url = format!("{}/v1/domains/{}/records", self.base_url, domain);
        if let Some(t) = record_type {
            if t.is_empty() {
                return Err(GoDaddyError::InvalidParameters {
                    body: "record_type filter must not be empty".to_string(),
                });
            }
            url.push_str("?type=");
            url.push_str(t);
        }
        debug!(
            "GoDaddy GET records for {} (filter={:?})",
            domain, record_type
        );
        let response = self
            .execute_with_retry(|| {
                let client = self.client.clone();
                let url = url.clone();
                async move { client.get(&url).send().await }
            })
            .await?;
        // F-19: Content-Length 预检 + 实际字节复核。
        if let Some(len) = response.content_length() {
            if len as usize > MAX_RESPONSE_BYTES {
                return Err(GoDaddyError::ResponseTooLarge {
                    limit: MAX_RESPONSE_BYTES,
                    actual: len as usize,
                });
            }
        }
        let body = response.bytes().await?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(GoDaddyError::ResponseTooLarge {
                limit: MAX_RESPONSE_BYTES,
                actual: body.len(),
            });
        }
        let records: Vec<ManagedRecord> = serde_json::from_slice(&body)?;
        // F-19: 单条 record data 长度上限。
        for record in &records {
            if record.data.len() > MAX_RECORD_DATA_LEN {
                return Err(GoDaddyError::InvalidParameters {
                    body: format!(
                        "record data exceeds {} bytes (got {}); refusing oversized record",
                        MAX_RECORD_DATA_LEN,
                        record.data.len()
                    ),
                });
            }
        }
        debug!(
            "GoDaddy GET records {} -> {} records",
            domain,
            records.len()
        );
        Ok(records)
    }

    /// Execute an HTTP request with automatic retry on 429 (rate limit).
    async fn execute_with_retry<F, Fut>(&self, request_fn: F) -> Result<Response, GoDaddyError>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<Response, reqwest::Error>> + Send,
    {
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            let response = request_fn().await?;

            if response.status().is_success() {
                trace!("GoDaddy API response: {} {}", response.status().as_u16(), response.url());
                return Ok(response);
            }

            let status = response.status().as_u16();
            debug!("GoDaddy API error response: {} {}", status, response.url());

            if status == 429 {
                let error = GoDaddyError::from_response(response).await;
                tracing::warn!(
                    "Rate limited by GoDaddy API (attempt {}/{}), backing off...",
                    attempt + 1,
                    MAX_RETRIES
                );

                let backoff_ms = INITIAL_BACKOFF_MS * (2u64.pow(attempt));
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

                last_error = Some(error);
                continue;
            }

            return Err(GoDaddyError::from_response(response).await);
        }

        Err(last_error.unwrap_or(GoDaddyError::RateLimited {
            retry_after: 60,
            body: "max retries exceeded".to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MockDns;

    #[test]
    fn test_record_url_format() {
        let client = GoDaddyClient::new("k", "s", "https://api.godaddy.com");
        let url = client
            .record_url("example.com", "AAAA", "my-pc")
            .expect("valid domain/name");
        assert_eq!(
            url,
            "https://api.godaddy.com/v1/domains/example.com/records/AAAA/my-pc"
        );
    }

    #[test]
    fn test_record_url_with_ote() {
        let client = GoDaddyClient::new("k", "s", "https://api.ote-godaddy.com");
        let url = client
            .record_url("example.com", "TXT", "_devicekey.my-pc")
            .expect("valid domain/name");
        assert_eq!(
            url,
            "https://api.ote-godaddy.com/v1/domains/example.com/records/TXT/_devicekey.my-pc"
        );
    }

    #[test]
    fn test_record_url_rejects_invalid_domain_or_name() {
        let client = GoDaddyClient::new("k", "s", "https://api.godaddy.com");
        // F-18: 非法 domain（URL 注入字符）
        assert!(matches!(
            client.record_url("evil.com/x", "AAAA", "my-pc"),
            Err(GoDaddyError::InvalidParameters { .. })
        ));
        // F-18: 非法记录名（device_id 含 '.'/' ' 的注入面）
        assert!(matches!(
            client.record_url("example.com", "AAAA", "a b"),
            Err(GoDaddyError::InvalidParameters { .. })
        ));
        assert!(matches!(
            client.record_url("example.com", "AAAA", "a/b"),
            Err(GoDaddyError::InvalidParameters { .. })
        ));
    }

    #[test]
    fn test_client_has_auth_header() {
        let client = GoDaddyClient::new("test_key", "test_secret", "https://api.godaddy.com");
        // Verify the auth header is set by checking the internal auth field
        assert_eq!(
            client.auth.authorization_header(),
            "sso-key test_key:test_secret"
        );
    }

    // ---- S-14a / F-17: https 强制 ----

    #[test]
    fn test_https_url_accepted() {
        assert!(GoDaddyClient::try_new("k", "s", "https://api.godaddy.com").is_ok());
        assert!(GoDaddyClient::try_new("k", "s", "https://api.ote-godaddy.com").is_ok());
        // 结尾斜杠归一化
        assert!(GoDaddyClient::try_new("k", "s", "https://api.godaddy.com/").is_ok());
    }

    #[test]
    fn test_http_url_rejected() {
        // 若外部显式设置了测试放行开关则跳过（该开关是显式测试环境配置）。
        if std::env::var(ALLOW_HTTP_ENV).is_ok() {
            return;
        }
        // 可失败路径：try_new 返回 Configuration 错误。
        assert!(matches!(
            GoDaddyClient::try_new("k", "s", "http://api.godaddy.com"),
            Err(GoDaddyError::Configuration(_))
        ));
        // 非 https 协议同样拒绝。
        assert!(matches!(
            GoDaddyClient::try_new("k", "s", "ftp://api.godaddy.com"),
            Err(GoDaddyError::Configuration(_))
        ));
        assert!(matches!(
            GoDaddyClient::try_new("k", "s", "api.godaddy.com"),
            Err(GoDaddyError::Configuration(_))
        ));
        // 便捷路径（签名保持返回 Self）：非法 URL panic 并带明确信息。
        let panic_result =
            std::panic::catch_unwind(|| GoDaddyClient::new("k", "s", "http://api.godaddy.com"));
        assert!(panic_result.is_err(), "http:// base URL must panic in new()");
    }

    // ---- S-14c / F-19: 响应体 / record data 上限 ----

    #[tokio::test]
    async fn test_get_records_rejects_oversized_body() {
        let mock = MockDns::start().await;
        // > 1 MiB 单记录 → mock 返回 Content-Length > 1 MiB，客户端应拒绝。
        let big = "x".repeat(MAX_RESPONSE_BYTES + 1);
        mock.set_records("TXT", "big", &[&big], 600);
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let err = client
            .get_records("example.com", "TXT", "big")
            .await
            .unwrap_err();
        assert!(
            matches!(err, GoDaddyError::ResponseTooLarge { .. }),
            "oversized response must be rejected, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_get_records_rejects_oversized_record_data() {
        let mock = MockDns::start().await;
        // 超过 record data 上限（4 KiB）但响应体 < 1 MiB → 走 record 级拒绝。
        let data = "y".repeat(MAX_RECORD_DATA_LEN + 1);
        mock.set_records("TXT", "bigdata", &[&data], 600);
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let err = client
            .get_records("example.com", "TXT", "bigdata")
            .await
            .unwrap_err();
        assert!(
            matches!(err, GoDaddyError::InvalidParameters { .. }),
            "oversized record data must be rejected, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_put_records_rejects_oversized_record_data() {
        let mock = MockDns::start().await;
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let records = vec![Record {
            data: "z".repeat(MAX_RECORD_DATA_LEN + 1),
            ttl: 600,
        }];
        let err = client
            .put_records("example.com", "TXT", "my-pc", &records)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GoDaddyError::InvalidParameters { .. }),
            "oversized write must be rejected, got {:?}",
            err
        );
    }

    // ---- M9-DNS000 (DNS-MNT-003/004/005): 域名维护端点 ----

    #[tokio::test]
    async fn test_list_domains() {
        let mock = MockDns::start().await;
        mock.set_domains(&["example.com", "kirin.dev"]);
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let domains = client.list_domains().await.expect("list domains");
        assert_eq!(domains, vec!["example.com", "kirin.dev"]);
        // 空账号 → 空列表而非错误。
        mock.set_domains(&[]);
        let domains = client.list_domains().await.expect("empty list ok");
        assert!(domains.is_empty());
    }

    #[tokio::test]
    async fn test_get_all_records_flat_and_filtered() {
        let mock = MockDns::start().await;
        mock.set_records("A", "@", &["203.0.113.7"], 600);
        mock.set_records("AAAA", "my-pc", &["2001:db8::1"], 600);
        mock.set_records("TXT", "my-pc", &["v=ed25519;k=abc"], 300);
        let client = GoDaddyClient::new("k", "s", mock.base_url());

        // 全量：3 条（A + AAAA + TXT）。
        let all = client
            .get_all_records("example.com", None)
            .await
            .expect("all records");
        assert_eq!(all.len(), 3);
        assert!(all.iter().any(|r| r.rtype == "A" && r.name == "@"));
        assert!(all.iter().any(|r| r.rtype == "AAAA" && r.data == "2001:db8::1"));

        // 类型筛选：仅 AAAA。
        let aaaa = client
            .get_all_records("example.com", Some("AAAA"))
            .await
            .expect("filtered records");
        assert_eq!(aaaa.len(), 1);
        assert_eq!(aaaa[0].rtype, "AAAA");
        assert_eq!(aaaa[0].name, "my-pc");
        assert_eq!(aaaa[0].ttl, 600);

        // 无匹配类型 → 空列表。
        let none = client
            .get_all_records("example.com", Some("MX"))
            .await
            .expect("no-match ok");
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn test_get_all_records_rejects_invalid_domain() {
        let mock = MockDns::start().await;
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        assert!(matches!(
            client.get_all_records("evil.com/x", None).await,
            Err(GoDaddyError::InvalidParameters { .. })
        ));
        assert!(matches!(
            client.get_all_records("example.com", Some("")).await,
            Err(GoDaddyError::InvalidParameters { .. })
        ));
    }
}
