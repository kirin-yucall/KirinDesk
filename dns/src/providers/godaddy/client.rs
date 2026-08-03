//! GoDaddy Domains API HTTP 客户端（M9-DNS001）。
//!
//! 由旧 `dns/src/godaddy/client.rs` 迁移改造：请求执行 / 429 指数退避重试 /
//! S-14a HTTPS 强制 / S-14b 域名与记录名校验 / F-19 响应体与 record data 上限
//! 全部保留；错误统一映射为 `ProviderError`（见 [`super::error`]）。
//! 本模块完全自包含，不引用旧 godaddy 目录。

use super::auth::Auth;
use super::error::map_response;
use super::record::{wire_name, ManagedRecord, WireRecord};
use crate::provider::ProviderError;
use crate::validate::{self, MAX_RECORD_DATA_LEN, MAX_RESPONSE_BYTES};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::Response;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// 429 重试次数上限（共 3 次请求，退避 1s/2s/4s）。
const MAX_RETRIES: u32 = 3;

/// 初始退避时长（每次翻倍）。
const INITIAL_BACKOFF_MS: u64 = 1000;

/// 测试环境显式放行开关（S-14a / F-17）：设置后允许非 https 的 `api_url`。
///
/// 仅限测试/本地 mock 使用；生产路径默认拒绝非 https 并给出明确错误。
/// 环回地址（127.0.0.1 / localhost / ::1）无需该开关即放行——模块内 mock
/// 契约测试直接使用 `http://127.0.0.1` 环回地址，**不需要**设置任何环境
/// 变量、也不需要任何测试专用放行函数。
const ALLOW_HTTP_ENV: &str = "KIRIN_DNS_ALLOW_HTTP";

/// GoDaddy Domains API 客户端（可 Clone 共享）。
#[derive(Clone)]
pub struct GodaddyClient {
    /// 内部 reqwest 客户端。
    client: reqwest::Client,
    /// 认证处理（sso-key）。
    // R-33: 生产路径经 `client` 请求头注入，仅测试直接读取该句柄——
    // 保留字段（认证句柄生命周期归属）并标注，避免 dead_code。
    #[allow(dead_code)]
    auth: Arc<Auth>,
    /// API 基址（生产 `https://api.godaddy.com`；OTE `https://api.ote-godaddy.com`）。
    base_url: String,
    /// 429 退避基准时长（测试可经 [`Self::with_backoff_base`] 调小；生产保持 1s）。
    backoff_base: Duration,
}

impl GodaddyClient {
    /// 便捷构造：api_url 非法（非 https 且非环回、未设 env 放行）时 panic。
    ///
    /// 生产配置必须使用 https（S-14a / F-17）；测试/本地 mock 用
    /// `http://127.0.0.1` 环回地址（自动放行）或 env `KIRIN_DNS_ALLOW_HTTP`。
    pub fn new(
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self::try_new(api_key, api_secret, base_url).expect(
            "GodaddyClient::new: api_url 必须以 'https://' 开头 \
             （测试环回地址 http://127.0.0.1 自动放行；其他测试环境可设 env KIRIN_DNS_ALLOW_HTTP）",
        )
    }

    /// 可失败构造：强制 https（S-14a / F-17）。
    ///
    /// 非 https 放行规则（放行时输出 warn 标注，绝不静默）：
    /// 1. 环回地址 `http://127.0.0.1:*` / `http://localhost:*` / `http://[::1]:*`
    ///    —— 本地 mock 契约测试直接可用，**无需任何开关**；
    /// 2. env `KIRIN_DNS_ALLOW_HTTP` 已设置 —— 仅测试环境显式配置。
    pub fn try_new(
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        let base_url: String = base_url.into().trim_end_matches('/').to_string();
        if !base_url.starts_with("https://") {
            if is_loopback_http(&base_url) || http_allowed_for_tests() {
                // 显式放行（环回/测试开关）——不静默：带标注警告。
                warn!(
                    "非 https api_url（环回/{} 测试放行，仅测试环境）: '{base_url}'",
                    ALLOW_HTTP_ENV
                );
            } else {
                return Err(ProviderError::Other(format!(
                    "api_url 必须以 'https://' 开头（当前: '{base_url}'）；\
                     测试环回地址 http://127.0.0.1 自动放行，其他测试环境可设 env {ALLOW_HTTP_ENV} 显式放行"
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
                        .expect("授权头值非法（api_key/api_secret 含控制字符?）"),
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
            .expect("reqwest 客户端构建失败");

        Ok(Self {
            client,
            auth: Arc::new(auth),
            base_url,
            backoff_base: Duration::from_millis(INITIAL_BACKOFF_MS),
        })
    }

    /// 调整 429 重试的初始退避时长（测试/本地 mock 用；生产保持 1s）。
    pub fn with_backoff_base(mut self, base: Duration) -> Self {
        self.backoff_base = base;
        self
    }

    /// 记录端点 URL：`{base}/v1/domains/{domain}/records/{type}/{name}`。
    ///
    /// 校验（S-14b / F-18）：`domain` 须为 RFC 1123 主机名；`name` 为相对名
    /// （"" = 根，wire 名 "@"）——拒绝 `/ ? # 空白` 等 URL 注入字符。
    fn record_url(
        &self,
        domain: &str,
        record_type: &str,
        name: &str,
    ) -> Result<String, ProviderError> {
        if !validate::validate_hostname(domain) {
            return Err(ProviderError::InvalidParameter {
                detail: format!("非法域名 '{domain}'（须为 RFC 1123 主机名）"),
            });
        }
        if !name.is_empty() && !validate::validate_record_name(name) {
            return Err(ProviderError::InvalidParameter {
                detail: format!("非法记录名 '{name}'"),
            });
        }
        Ok(format!(
            "{}/v1/domains/{}/records/{}/{}",
            self.base_url,
            domain,
            record_type,
            wire_name(name)
        ))
    }

    /// 全表记录端点 URL：`{base}/v1/domains/{domain}/records`。
    fn records_url(&self, domain: &str) -> Result<String, ProviderError> {
        if !validate::validate_hostname(domain) {
            return Err(ProviderError::InvalidParameter {
                detail: format!("非法域名 '{domain}'（须为 RFC 1123 主机名）"),
            });
        }
        Ok(format!("{}/v1/domains/{}/records", self.base_url, domain))
    }

    /// 测试连接：GET /v1/domains?limit=1 最小查询（DNS-MNT-003 / M9-DNS001 §三）。
    ///
    /// 只要求响应为 2xx（成功状态由 [`Self::execute_with_retry`] 保证），
    /// 不读取响应体。
    pub async fn test_connection(&self) -> Result<(), ProviderError> {
        let url = format!("{}/v1/domains?limit=1", self.base_url);
        debug!("GoDaddy GET /v1/domains?limit=1 (test_connection)");
        let _response = self
            .execute_with_retry("test_connection", || {
                let client = self.client.clone();
                let url = url.clone();
                async move { client.get(&url).send().await }
            })
            .await?;
        Ok(())
    }

    /// GET /v1/domains —— 当前账号可管理的域名列表（DNS-MNT-004）。
    ///
    /// 响应形如 `[{"domain":"example.com","status":"ACTIVE",...}, ...]`；
    /// 仅提取 `domain` 字段。
    pub async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let url = format!("{}/v1/domains", self.base_url);
        debug!("GoDaddy GET /v1/domains");
        let response = self
            .execute_with_retry("list_domains", || {
                let client = self.client.clone();
                let url = url.clone();
                async move { client.get(&url).send().await }
            })
            .await?;
        // F-19: Content-Length 预检 + 实际字节复核。
        let body = self.read_body_checked(response).await?;
        // 只声明需要的字段，忽略其余（status/expires 等）。
        #[derive(serde::Deserialize)]
        struct DomainItem {
            domain: String,
        }
        let items: Vec<DomainItem> = serde_json::from_slice(&body)?;
        let domains: Vec<String> = items.into_iter().map(|d| d.domain).collect();
        debug!("GoDaddy GET /v1/domains -> {} domains", domains.len());
        Ok(domains)
    }

    /// GET /records/{type}/{name} —— 该 name+type 现有记录组（wire 形态）。
    ///
    /// GoDaddy 对该端点无记录时返回 404（= 空组）：此处归一为空列表，供
    /// upsert 先查后写与记录查询使用（域名级 404 仍映射 `NotFound`，
    /// 见 [`Self::get_all_records`]）。
    pub async fn get_records_group(
        &self,
        domain: &str,
        record_type: &str,
        name: &str,
    ) -> Result<Vec<WireRecord>, ProviderError> {
        let url = self.record_url(domain, record_type, name)?;
        debug!("GoDaddy GET {record_type} {name}.{domain}");
        let ctx = format!("GET {record_type} {name}");
        match self
            .execute_with_retry(&ctx, || {
                let client = self.client.clone();
                let url = url.clone();
                async move { client.get(&url).send().await }
            })
            .await
        {
            // 该 name+type 尚无记录（404）→ 空组。
            Err(ProviderError::NotFound { .. }) => Ok(Vec::new()),
            Err(e) => Err(e),
            Ok(response) => {
                let body = self.read_body_checked(response).await?;
                let records: Vec<WireRecord> = serde_json::from_slice(&body)?;
                // F-19: 单条 record data 长度上限。
                for record in &records {
                    self.check_data_len(&record.data)?;
                }
                Ok(records)
            }
        }
    }

    /// GET /v1/domains/{domain}/records —— 域名下全量记录（DNS-MNT-005）。
    ///
    /// 域名不存在 → 404 → `NotFound`（域名级错误映射，M9-DNS001 §三）。
    pub async fn get_all_records(&self, domain: &str) -> Result<Vec<ManagedRecord>, ProviderError> {
        let url = self.records_url(domain)?;
        debug!("GoDaddy GET records {domain}");
        let ctx = format!("GET records {domain}");
        let response = self
            .execute_with_retry(&ctx, || {
                let client = self.client.clone();
                let url = url.clone();
                async move { client.get(&url).send().await }
            })
            .await?;
        let body = self.read_body_checked(response).await?;
        let records: Vec<ManagedRecord> = serde_json::from_slice(&body)?;
        // F-19: 单条 record data 长度上限。
        for record in &records {
            self.check_data_len(&record.data)?;
        }
        debug!("GoDaddy GET records {domain} -> {} records", records.len());
        Ok(records)
    }

    /// PUT /records/{type}/{name} —— 整组替换（GoDaddy 写入语义）。
    ///
    /// 传 `&[]` 即删除该 name+type 全部记录（delete_record 语义）。
    pub async fn put_records(
        &self,
        domain: &str,
        record_type: &str,
        name: &str,
        records: &[WireRecord],
    ) -> Result<(), ProviderError> {
        let url = self.record_url(domain, record_type, name)?;
        // F-19: 写出侧同限（自控数据，防脏写）。
        for record in records {
            self.check_data_len(&record.data)?;
        }
        let body = serde_json::to_string(records)?;
        trace!("GoDaddy PUT {record_type} {name} body={body}");

        let _response = self
            .execute_with_retry(&format!("PUT {record_type} {name}"), || {
                let client = self.client.clone();
                let url = url.clone();
                let body = body.clone();
                async move { client.put(&url).body(body).send().await }
            })
            .await?;

        debug!("GoDaddy PUT {record_type} {name} -> OK");
        Ok(())
    }

    /// F-19: 单条 record data 长度上限检查（读/写两侧同限）。
    fn check_data_len(&self, data: &str) -> Result<(), ProviderError> {
        if data.len() > MAX_RECORD_DATA_LEN {
            return Err(ProviderError::InvalidParameter {
                detail: format!(
                    "record data 超过 {MAX_RECORD_DATA_LEN} 字节（实际 {}）；拒绝超大记录",
                    data.len()
                ),
            });
        }
        Ok(())
    }

    /// 发送请求：成功（2xx）直接返回响应；429 指数退避重试（退避 1s/2s/4s，
    /// 共 3 次请求）；其余状态码映射为统一错误（M9-DNS001 §三）。
    async fn execute_with_retry<F, Fut>(
        &self,
        ctx: &str,
        request_fn: F,
    ) -> Result<Response, ProviderError>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<Response, reqwest::Error>> + Send,
    {
        let mut last_error: Option<ProviderError> = None;

        for attempt in 0..MAX_RETRIES {
            let response = request_fn().await?;

            if response.status().is_success() {
                trace!(
                    "GoDaddy API 响应: {} {}",
                    response.status().as_u16(),
                    response.url()
                );
                return Ok(response);
            }

            let status = response.status().as_u16();
            debug!("GoDaddy API 错误响应: {status} {}", response.url());

            if status == 429 {
                let error = map_response(response, ctx).await;
                warn!(
                    "GoDaddy 限流(429)，第 {} 次重试（上限 {MAX_RETRIES}）: {ctx}",
                    attempt + 1
                );
                // 指数退避：初始 1s 起翻倍（1s/2s/4s；测试可经 with_backoff_base 调小）。
                let backoff = self.backoff_base * 2u32.pow(attempt);
                tokio::time::sleep(backoff).await;
                last_error = Some(error);
                continue;
            }

            return Err(map_response(response, ctx).await);
        }

        Err(last_error.unwrap_or_else(|| ProviderError::RateLimited {
            retry_after: Some(60),
        }))
    }

    /// F-19: Content-Length 预检（读取响应体前）+ 实际字节复核（1 MiB 上限）。
    async fn read_body_checked(&self, response: Response) -> Result<Vec<u8>, ProviderError> {
        if let Some(len) = response.content_length() {
            if len as usize > MAX_RESPONSE_BYTES {
                return Err(ProviderError::Other(format!(
                    "响应体过大: Content-Length {len} 字节（上限 {MAX_RESPONSE_BYTES}）"
                )));
            }
        }
        let body = response.bytes().await?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(ProviderError::Other(format!(
                "响应体过大: 实际 {} 字节（上限 {MAX_RESPONSE_BYTES}）",
                body.len()
            )));
        }
        Ok(body.to_vec())
    }
}

/// 环回 http 地址判定（127.0.0.1 / 127.x / localhost / ::1）：
/// 本地 mock 契约测试直接放行，无需 env 开关。
fn is_loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    host == "localhost" || host == "::1" || host == "127.0.0.1" || host.starts_with("127.")
}

/// env 显式放行（KIRIN_DNS_ALLOW_HTTP，仅测试环境；生产路径不设）。
fn http_allowed_for_tests() -> bool {
    std::env::var(ALLOW_HTTP_ENV).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_url_format() {
        let client = GodaddyClient::new("k", "s", "https://api.godaddy.com");
        let url = client
            .record_url("example.com", "AAAA", "my-pc")
            .expect("合法域名/记录名");
        assert_eq!(
            url,
            "https://api.godaddy.com/v1/domains/example.com/records/AAAA/my-pc"
        );
        // 根记录相对名 "" → wire "@"。
        let url = client
            .record_url("example.com", "A", "")
            .expect("根记录");
        assert_eq!(
            url,
            "https://api.godaddy.com/v1/domains/example.com/records/A/@"
        );
        // 结尾斜杠归一化。
        let client = GodaddyClient::new("k", "s", "https://api.godaddy.com/");
        let url = client
            .record_url("example.com", "A", "my-pc")
            .expect("合法");
        assert_eq!(
            url,
            "https://api.godaddy.com/v1/domains/example.com/records/A/my-pc"
        );
    }

    #[test]
    fn test_records_url_format() {
        let client = GodaddyClient::new("k", "s", "https://api.godaddy.com");
        assert_eq!(
            client.records_url("example.com").unwrap(),
            "https://api.godaddy.com/v1/domains/example.com/records"
        );
    }

    #[test]
    fn test_record_url_rejects_invalid_domain_or_name() {
        let client = GodaddyClient::new("k", "s", "https://api.godaddy.com");
        // F-18: 非法 domain（URL 注入字符）。
        assert!(matches!(
            client.record_url("evil.com/x", "AAAA", "my-pc"),
            Err(ProviderError::InvalidParameter { .. })
        ));
        // F-18: 非法记录名（含 '.'/' ' 的注入面）。
        assert!(matches!(
            client.record_url("example.com", "AAAA", "a b"),
            Err(ProviderError::InvalidParameter { .. })
        ));
        assert!(matches!(
            client.record_url("example.com", "AAAA", "a/b"),
            Err(ProviderError::InvalidParameter { .. })
        ));
    }

    #[test]
    fn test_client_has_auth_header() {
        let client = GodaddyClient::new("test_key", "test_secret", "https://api.godaddy.com");
        assert_eq!(
            client.auth.authorization_header(),
            "sso-key test_key:test_secret"
        );
    }

    // ---- S-14a / F-17: https 强制（环回自动放行，env 显式放行）----

    #[test]
    fn test_https_url_accepted() {
        assert!(GodaddyClient::try_new("k", "s", "https://api.godaddy.com").is_ok());
        assert!(GodaddyClient::try_new("k", "s", "https://api.ote-godaddy.com").is_ok());
        // 结尾斜杠归一化。
        assert!(GodaddyClient::try_new("k", "s", "https://api.godaddy.com/").is_ok());
    }

    #[test]
    fn test_loopback_http_allowed_without_switch() {
        // 环回地址：mock 契约测试路径，无需 https、无需放行开关。
        assert!(GodaddyClient::try_new("k", "s", "http://127.0.0.1:8080").is_ok());
        assert!(GodaddyClient::try_new("k", "s", "http://localhost:1234").is_ok());
        assert!(GodaddyClient::try_new("k", "s", "http://127.0.0.1").is_ok());
    }

    #[test]
    fn test_non_loopback_http_rejected_unless_env() {
        // 若外部显式设置了测试放行开关则跳过（显式测试环境配置）。
        if std::env::var(ALLOW_HTTP_ENV).is_ok() {
            return;
        }
        // 非环回 http 拒绝。
        assert!(matches!(
            GodaddyClient::try_new("k", "s", "http://api.godaddy.com"),
            Err(ProviderError::Other(_))
        ));
        // 非 http 协议同样拒绝。
        assert!(matches!(
            GodaddyClient::try_new("k", "s", "ftp://api.godaddy.com"),
            Err(ProviderError::Other(_))
        ));
        assert!(matches!(
            GodaddyClient::try_new("k", "s", "api.godaddy.com"),
            Err(ProviderError::Other(_))
        ));
        // 便捷路径（签名保持返回 Self）：非法 URL panic 并带明确信息。
        let panic_result =
            std::panic::catch_unwind(|| GodaddyClient::new("k", "s", "http://api.godaddy.com"));
        assert!(panic_result.is_err(), "http:// 基址必须在 new() 中 panic");
    }

    #[test]
    fn test_is_loopback_http() {
        assert!(is_loopback_http("http://127.0.0.1:34567"));
        assert!(is_loopback_http("http://localhost"));
        assert!(is_loopback_http("http://[::1]:8080"));
        assert!(!is_loopback_http("http://api.godaddy.com"));
        assert!(!is_loopback_http("https://127.0.0.1"));
        assert!(!is_loopback_http(""));
    }
}
