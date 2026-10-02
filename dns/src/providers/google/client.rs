//! Google Cloud DNS（dns.googleapis.com/dns/v1）HTTP 客户端
//!
//! - 认证：Service Account JWT（RFC 7523，见 `sign`）→ OAuth2 access_token，
//!   带缓存复用（到期前 5 分钟提前刷新）；
//! - 资源：`managedZones`（域名列表）/ `rrsets`（记录查询）/ `changes`（记录写入事务）；
//! - 统一 30s 超时 + `User-Agent: KirinDesk/0.1.0`；
//! - 凭据（含 JWT 断言与私钥）绝不进入日志。

use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

use super::sign::{self, ServiceAccount};
use crate::provider::{ProviderError, RecordType};

/// 记录 TTL 缺省值（Google 要求 changes 中显式给出 ttl；默认 300 秒）。
pub(crate) const DEFAULT_TTL: u64 = 300;

/// OAuth2 access_token 缓存条目。
struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

/// Google DNS v1 API 客户端。
pub struct GoogleClient {
    http: reqwest::Client,
    /// API 根：`https://dns.googleapis.com/dns/v1`（测试注入 mock 地址）。
    base_url: String,
    /// GCP 项目 ID（路径参数）。
    project: String,
    /// 构造期解析的服务账号；失败则延迟到首次取令牌时报错。
    sa: Option<ServiceAccount>,
    sa_error: Option<String>,
    /// access_token 缓存（Mutex 保证并发安全）。
    token: Mutex<Option<CachedToken>>,
}

impl GoogleClient {
    /// 生产构造：真实 API 端点；token_uri 取自服务账号 JSON。
    pub fn new(service_account_json: String, project: String) -> Self {
        Self::with_base_url(
            service_account_json,
            project,
            "https://dns.googleapis.com/dns/v1".to_string(),
        )
    }

    /// 测试注入：`base_url` 指向本地 mock HTTP 服务。
    pub(crate) fn with_base_url(service_account_json: String, project: String, base_url: String) -> Self {
        let (sa, sa_error) = match sign::parse_service_account(&service_account_json) {
            Ok(sa) => (Some(sa), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Self {
            http: Self::http_client(),
            base_url,
            project,
            sa,
            sa_error,
            token: Mutex::new(None),
        }
    }

    /// 构造期失败（如注册表 factory 收到非 Google 凭据）：首次调用即报错。
    pub(crate) fn invalid(detail: &str) -> Self {
        Self {
            http: Self::http_client(),
            base_url: String::new(),
            project: String::new(),
            sa: None,
            sa_error: Some(detail.to_string()),
            token: Mutex::new(None),
        }
    }

    fn http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("reqwest Client 构建失败")
    }

    /// 获取 OAuth2 access_token（缓存未过期直接复用）。
    async fn access_token(&self) -> Result<String, ProviderError> {
        if let Some(t) = &*self.token.lock().unwrap() {
            if t.expires_at > Instant::now() {
                return Ok(t.access_token.clone());
            }
        }
        let sa = self.sa.as_ref().ok_or_else(|| ProviderError::Auth {
            detail: self
                .sa_error
                .clone()
                .unwrap_or_else(|| "服务账号凭据缺失".to_string()),
        })?;
        let assertion = sign::build_assertion(sa, chrono::Utc::now().timestamp())?;
        // RFC 7523 §2.1：grant_type=jwt-bearer + assertion 表单提交
        let resp = self
            .http
            .post(&sa.token_uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={assertion}"
            ))
            .send()
            .await?;
        let status = resp.status();
        let retry_after = super::error::retry_after_secs(resp.headers());
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(super::error::map_error(status.as_u16(), retry_after, &text));
        }
        let tok: TokenResponse = serde_json::from_str(&text)?;
        let expires_in = tok.expires_in.unwrap_or(3600);
        // 到期前 5 分钟视为失效（M9-DNS007 验收标准：提前刷新）
        let ttl = expires_in.saturating_sub(300).max(60);
        let token = tok.access_token.clone();
        *self.token.lock().unwrap() = Some(CachedToken {
            access_token: tok.access_token,
            expires_at: Instant::now() + Duration::from_secs(ttl),
        });
        Ok(token)
    }

    /// 统一 REST 调用：Bearer 认证头 + 状态码错误映射。
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ProviderError> {
        let token = self.access_token().await?;
        let url = format!("{}{}", self.base_url, path);
        let mut req = self
            .http
            .request(method, &url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .query(query);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let retry_after = super::error::retry_after_secs(resp.headers());
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(super::error::map_error(status.as_u16(), retry_after, &text));
        }
        if text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&text).map_err(ProviderError::Json)
    }

    fn zones_path(&self, suffix: &str) -> String {
        format!("/projects/{}/managedZones{suffix}", self.project)
    }

    /// `managedZones` 列表（分页 `nextPageToken`）。
    pub async fn list_zones(&self) -> Result<Vec<ManagedZone>, ProviderError> {
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut q: Vec<(&str, String)> = vec![("maxResults", "100".to_string())];
            if let Some(t) = &page_token {
                q.push(("pageToken", t.clone()));
            }
            let page: ZonesPage =
                from_value(self.send(reqwest::Method::GET, &self.zones_path(""), &q, None).await?)?;
            let zones = page.managed_zones.unwrap_or_default();
            let len = zones.len();
            out.extend(zones);
            match page.next_page_token {
                Some(t) if !t.is_empty() && len > 0 => page_token = Some(t),
                _ => break,
            }
        }
        Ok(out)
    }

    /// 按 `dnsName`（域名 FQDN）解析 zone id（`GET .../managedZones?dnsName=`）。
    pub async fn get_zone_id(&self, domain: &str) -> Result<String, ProviderError> {
        let want = format!("{domain}.");
        let q = vec![("dnsName", want.clone())];
        let page: ZonesPage =
            from_value(self.send(reqwest::Method::GET, &self.zones_path(""), &q, None).await?)?;
        match page
            .managed_zones
            .and_then(|zs| zs.into_iter().find(|z| z.dns_name.eq_ignore_ascii_case(&want)))
        {
            Some(z) => Ok(z.id),
            None => Err(ProviderError::NotFound { what: domain.to_string() }),
        }
    }

    /// `rrsets` 列表（可按 name（FQDN）/ type 过滤；分页 `nextPageToken`）。
    pub async fn list_rrsets(
        &self,
        zone: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Rrset>, ProviderError> {
        let path = self.zones_path(&format!("/{zone}/rrsets"));
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut q: Vec<(&str, String)> = vec![("maxResults", "100".to_string())];
            if let Some(n) = name {
                q.push(("name", n.to_string()));
            }
            if let Some(t) = rtype {
                q.push(("type", t.as_str().to_string()));
            }
            if let Some(tok) = &page_token {
                q.push(("pageToken", tok.clone()));
            }
            let page: RrsetsPage =
                from_value(self.send(reqwest::Method::GET, &path, &q, None).await?)?;
            let rs = page.rrsets.unwrap_or_default();
            let len = rs.len();
            out.extend(rs);
            match page.next_page_token {
                Some(t) if !t.is_empty() && len > 0 => page_token = Some(t),
                _ => break,
            }
        }
        Ok(out)
    }

    /// `changes` 事务提交（原子：一次变更 = additions + deletions）。
    pub async fn create_change(
        &self,
        zone: &str,
        additions: &[Rrset],
        deletions: &[Rrset],
    ) -> Result<(), ProviderError> {
        let path = self.zones_path(&format!("/{zone}/changes"));
        let body = serde_json::json!({ "additions": additions, "deletions": deletions });
        self.send(reqwest::Method::POST, &path, &[], Some(body)).await?;
        Ok(())
    }
}

/// serde_json::Value → 类型化结构。
fn from_value<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, ProviderError> {
    serde_json::from_value(v).map_err(ProviderError::Json)
}

/// managedZone（域名）。
#[derive(Debug, Clone, Deserialize)]
pub struct ManagedZone {
    pub id: String,
    pub name: String,
    #[serde(rename = "dnsName")]
    pub dns_name: String,
}

/// resourceRecordSet（rrdatas 多值；`type` 为 Rust 保留字故改名 `rtype`）。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rrset {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub ttl: u64,
    #[serde(default)]
    pub rrdatas: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ZonesPage {
    #[serde(default, rename = "managedZones")]
    managed_zones: Option<Vec<ManagedZone>>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RrsetsPage {
    #[serde(default)]
    rrsets: Option<Vec<Rrset>>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}
