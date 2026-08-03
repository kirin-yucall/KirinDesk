//! 华为云 DNS（v2）HTTP 客户端：SDK-HMAC-SHA256 签名请求 + zone/recordset CRUD
//!
//! - 认证：AK/SK 签名（见 `sign`），头 `X-Sdk-Date`（UTC ISO8601 基本格式）+ `Authorization`；
//! - 端点：`https://dns.myhuaweicloud.com`（公共端点，兼容各 region）；
//! - 资源：`GET /v2/zones`（域名列表 / zone 解析）、`GET /v2/zones/{zid}/recordsets`
//!   （查询，分页 marker）、`POST/PUT/DELETE .../recordsets`（记录集 CRUD）；
//! - 记录集 wire 名称为 FQDN 带尾点（官方 API 定义，WebSearch 复核）；
//! - 统一 30s 超时 + `User-Agent: KirinDesk/0.1.0`；AK/SK 绝不进入日志。

use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};

use super::sign;
use crate::provider::{ProviderError, RecordType};

/// 华为云 DNS 客户端。
pub struct HuaweiClient {
    http: reqwest::Client,
    base_url: String,
    access_key: String,
    secret_key: String,
    /// 区域（端点公共化后仅作凭据字段保留，不参与签名）。
    #[allow(dead_code)]
    region: String,
}

impl HuaweiClient {
    /// 生产构造：真实公共端点。
    pub fn new(access_key: String, secret_key: String, region: String) -> Self {
        Self::with_base_url(
            access_key,
            secret_key,
            region,
            "https://dns.myhuaweicloud.com".to_string(),
        )
    }

    /// 测试注入：`base_url` 指向本地 mock HTTP 服务。
    pub(crate) fn with_base_url(
        access_key: String,
        secret_key: String,
        region: String,
        base_url: String,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("reqwest Client 构建失败");
        Self { http, base_url, access_key, secret_key, region }
    }

    /// Host 头值（与 reqwest 实际发送一致：非默认端口带端口号）。
    fn host_of(&self) -> String {
        let rest = self
            .base_url
            .strip_prefix("https://")
            .or_else(|| self.base_url.strip_prefix("http://"))
            .unwrap_or(&self.base_url);
        rest.split('/').next().unwrap_or("").to_string()
    }

    /// 签名 + 发送（SDK-HMAC-SHA256），返回响应 JSON。
    ///
    /// `query` 同时用于规范查询串与真实 URL（内部先排序，保证 wire 与签名一致）。
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ProviderError> {
        let payload = match &body {
            Some(v) => serde_json::to_vec(v)?,
            None => Vec::new(),
        };
        // 同一时间戳用于 X-Sdk-Date 头与 StringToSign（UTC，YYYYMMDDTHHMMSSZ）
        let date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let host = self.host_of();
        let mut headers: Vec<(&str, &str)> =
            vec![("host", host.as_str()), ("x-sdk-date", date.as_str())];
        let mut has_body = false;
        if !payload.is_empty() {
            headers.push(("content-type", "application/json"));
            has_body = true;
        }
        // 查询参数排序：规范串与真实 URL 一致（服务器亦按排序后校验）
        let mut q = query.to_vec();
        q.sort_by(|a, b| a.0.cmp(b.0));
        let auth = sign::authorization(
            &self.access_key,
            &self.secret_key,
            method.as_str(),
            path,
            &q,
            &headers,
            &payload,
            &date,
        );
        let url = format!("{}{}", self.base_url, path);
        let mut req = self
            .http
            .request(method, &url)
            .query(&q)
            .header("X-Sdk-Date", &date)
            .header("Authorization", &auth);
        if has_body {
            req = req.header(CONTENT_TYPE, "application/json").body(payload);
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

    /// `GET /v2/zones`：域名（zone）列表（分页 marker 游标）。
    pub async fn list_zones(&self) -> Result<Vec<Zone>, ProviderError> {
        let mut out = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut q: Vec<(&str, String)> = vec![("limit", "500".to_string())];
            if let Some(m) = &marker {
                q.push(("marker", m.clone()));
            }
            let page: ZonesPage =
                from_value(self.send(reqwest::Method::GET, "/v2/zones", &q, None).await?)?;
            let zones = page.zones.unwrap_or_default();
            let total = page.metadata.as_ref().and_then(|m| m.total_count).unwrap_or(u64::MAX);
            let page_len = zones.len();
            out.extend(zones);
            if page_len == 0 || out.len() as u64 >= total {
                break;
            }
            marker = out.last().map(|z| z.id.clone());
        }
        Ok(out)
    }

    /// `GET /v2/zones?name={fqdn}`：按域名精确解析 zone id（模糊搜索 → 客户端精确过滤）。
    pub async fn get_zone_id(&self, domain: &str) -> Result<String, ProviderError> {
        let want = format!("{domain}.");
        let q = vec![("name", want.clone())];
        let page: ZonesPage =
            from_value(self.send(reqwest::Method::GET, "/v2/zones", &q, None).await?)?;
        match page
            .zones
            .and_then(|zs| zs.into_iter().find(|z| z.name.eq_ignore_ascii_case(&want)))
        {
            Some(z) => Ok(z.id),
            None => Err(ProviderError::NotFound { what: domain.to_string() }),
        }
    }

    /// `GET /v2/zones/{zid}/recordsets`：记录集列表（分页；name/type 服务端预过滤，
    /// 精确匹配由上层调用方做）。
    pub async fn list_recordsets(
        &self,
        zone_id: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Recordset>, ProviderError> {
        let path = format!("/v2/zones/{zone_id}/recordsets");
        let mut out = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut q: Vec<(&str, String)> = vec![("limit", "500".to_string())];
            if let Some(n) = name {
                q.push(("name", n.to_string()));
            }
            if let Some(t) = rtype {
                q.push(("type", t.as_str().to_string()));
            }
            if let Some(m) = &marker {
                q.push(("marker", m.clone()));
            }
            let page: RecordsetsPage =
                from_value(self.send(reqwest::Method::GET, &path, &q, None).await?)?;
            let rs = page.recordsets.unwrap_or_default();
            let total = page.metadata.as_ref().and_then(|m| m.total_count).unwrap_or(u64::MAX);
            let page_len = rs.len();
            out.extend(rs);
            if page_len == 0 || out.len() as u64 >= total {
                break;
            }
            marker = out.last().map(|r| r.id.clone());
        }
        Ok(out)
    }

    /// `POST /v2/zones/{zid}/recordsets`：创建记录集（202 返回含 id）。
    pub async fn create_recordset(
        &self,
        zone_id: &str,
        rs: &RecordsetIn,
    ) -> Result<Recordset, ProviderError> {
        let path = format!("/v2/zones/{zone_id}/recordsets");
        let body = serde_json::to_value(rs)?;
        from_value(self.send(reqwest::Method::POST, &path, &[], Some(body)).await?)
    }

    /// `PUT /v2/zones/{zid}/recordsets/{rid}`：更新记录集。
    pub async fn update_recordset(
        &self,
        zone_id: &str,
        rid: &str,
        rs: &RecordsetIn,
    ) -> Result<Recordset, ProviderError> {
        let path = format!("/v2/zones/{zone_id}/recordsets/{rid}");
        let body = serde_json::to_value(rs)?;
        from_value(self.send(reqwest::Method::PUT, &path, &[], Some(body)).await?)
    }

    /// `DELETE /v2/zones/{zid}/recordsets/{rid}`：删除记录集（202）。
    pub async fn delete_recordset(&self, zone_id: &str, rid: &str) -> Result<(), ProviderError> {
        let path = format!("/v2/zones/{zone_id}/recordsets/{rid}");
        self.send(reqwest::Method::DELETE, &path, &[], None).await?;
        Ok(())
    }
}

/// serde_json::Value → 类型化结构。
fn from_value<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, ProviderError> {
    serde_json::from_value(v).map_err(ProviderError::Json)
}

/// zone（域名）。
#[derive(Debug, Clone, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
}

/// 记录集（查询响应）。
#[derive(Debug, Clone, Deserialize)]
pub struct Recordset {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    #[serde(default)]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub records: Vec<String>,
}

/// 创建/更新请求体：`{name, type, ttl, records}`。
#[derive(Debug, Clone, Serialize)]
pub struct RecordsetIn {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    pub records: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PageMeta {
    #[serde(default)]
    total_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ZonesPage {
    #[serde(default)]
    zones: Option<Vec<Zone>>,
    #[serde(default)]
    metadata: Option<PageMeta>,
}

#[derive(Debug, Deserialize)]
struct RecordsetsPage {
    #[serde(default)]
    recordsets: Option<Vec<Recordset>>,
    #[serde(default)]
    metadata: Option<PageMeta>,
}
