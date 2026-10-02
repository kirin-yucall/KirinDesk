//! M9-DNS014: OVH HTTP 客户端（三要素签名）
//!
//! - 端点：`https://api.ovh.com/1.0`
//! - 认证：X-Ovh-Application / X-Ovh-Consumer / X-Ovh-Timestamp / X-Ovh-Signature
//!   （签名算法见 `sign.rs`，WebSearch 复核官方格式）
//! - 时钟校准：403 且错误含时间关键词（QUERY_TIME_OUT 等）→ `GET /auth/time`
//!   校准偏移后**重试一次**（M9-DNS014 §三 验收标准）
//! - 接口：`/domain/zone`（列表）、`/domain/zone/{z}/record`（两段式查询：
//!   id 列表 → 逐条详情）、POST/PUT/DELETE 记录、`POST .../refresh`（写后生效）
//! - 30s 超时；User-Agent `KirinDesk/0.1.0`；凭据只进签名/头，不落日志

use super::error::map_http_error;
use super::sign::signature;
use crate::provider::ProviderError;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 官方端点（测试经 `OvhClient::new` 的 base_url 指向 127.0.0.1 mock）。
pub(crate) const PROD_BASE_URL: &str = "https://api.ovh.com/1.0";
const USER_AGENT: &str = "KirinDesk/0.1.0";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// OVH 记录默认 TTL（官方默认 3600；读取侧 0 → 3600 归一化）。
pub(crate) const TTL_DEFAULT: u32 = 3600;

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// OVH 通用记录（/domain/zone/{zone}/record）。
///
/// 序列化：创建时 id/zone 省略（服务端分配）；subDomain 空（根记录）省略字段。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct OvhRecord {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub id: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zone: String,
    #[serde(rename = "fieldType", default, skip_serializing_if = "String::is_empty")]
    pub field_type: String,
    #[serde(rename = "subDomain", default, skip_serializing_if = "String::is_empty")]
    pub sub_domain: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub ttl: u32,
}

/// OVH API 客户端。
///
/// 不实现 Clone（内部含时钟偏移 Mutex；Provider 经注册表单实例构建）。
pub(crate) struct OvhClient {
    http: reqwest::Client,
    app_key: String,
    app_secret: String,
    consumer_key: String,
    base_url: String,
    /// 服务器时间与本地时间偏移（秒）；`/auth/time` 校准后更新。
    time_offset: Mutex<i64>,
}

impl OvhClient {
    /// 构建客户端。`base_url` 生产传 [`PROD_BASE_URL`]，测试传 127.0.0.1 mock。
    pub fn new(app_key: String, app_secret: String, consumer_key: String, base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .expect("构建 OVH reqwest 客户端失败");
        Self {
            http,
            app_key,
            app_secret,
            consumer_key,
            base_url: base_url.trim_end_matches('/').to_string(),
            time_offset: Mutex::new(0),
        }
    }

    /// 当前时间戳（本地 + 校准偏移）。
    fn now(&self) -> i64 {
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        local + *self.time_offset.lock().unwrap()
    }

    /// 发起签名请求；遇时间类认证错误 → 校准时钟后重试一次。
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<serde_json::Value, ProviderError> {
        match self.request_inner(method, path, body.clone()).await {
            // 时钟偏差（QUERY_TIME_OUT / timestamp out of range 等）→ 自动校准重试。
            Err(ProviderError::Auth { detail }) if Self::is_time_error(&detail) => {
                self.calibrate_time().await?;
                self.request_inner(method, path, body).await
            }
            other => other,
        }
    }

    /// 单次签名请求（不带重试）。
    async fn request_inner(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<serde_json::Value, ProviderError> {
        let url = format!("{}{}", self.base_url, path);
        let timestamp = self.now();
        let body_str = body.unwrap_or_default();
        let sig = signature(
            &self.app_secret,
            &self.consumer_key,
            method,
            &url,
            &body_str,
            timestamp,
        );

        let builder = match method {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url),
            "PUT" => self.http.put(&url),
            "DELETE" => self.http.delete(&url),
            other => {
                return Err(ProviderError::Other(format!("不支持的 HTTP 方法: {other}")));
            }
        };
        let mut req = builder
            .header("X-Ovh-Application", &self.app_key)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("X-Ovh-Timestamp", timestamp.to_string())
            .header("X-Ovh-Signature", sig);
        if !body_str.is_empty() {
            req = req.header("Content-Type", "application/json").body(body_str);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        if (200..300).contains(&status) {
            // 部分写接口返回空体。
            if text.trim().is_empty() {
                Ok(serde_json::json!({}))
            } else {
                Ok(serde_json::from_str(&text)?)
            }
        } else {
            Err(map_http_error(status, &text))
        }
    }

    /// 时间类错误关键词（触发时钟校准重试）。
    fn is_time_error(detail: &str) -> bool {
        let lower = detail.to_lowercase();
        lower.contains("timestamp") || lower.contains("time out") || lower.contains("timeout")
    }

    /// GET /auth/time（公开端点，无需签名）：校准本地时钟偏移。
    async fn calibrate_time(&self) -> Result<(), ProviderError> {
        let url = format!("{}/auth/time", self.base_url);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        if !(200..300).contains(&status) {
            return Err(map_http_error(status, &text));
        }
        let server_ts: i64 = text.trim().parse().map_err(|_| {
            ProviderError::Other(format!("/auth/time 响应非法: {text}"))
        })?;
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        *self.time_offset.lock().unwrap() = server_ts - local;
        Ok(())
    }

    /// GET /domain/zone → 全部 zone（字符串数组）。
    pub async fn list_zones(&self) -> Result<Vec<String>, ProviderError> {
        let v = self.request("GET", "/domain/zone", None).await?;
        let zones: Vec<String> = serde_json::from_value(v)?;
        Ok(zones)
    }

    /// GET /domain/zone/{zone}/record[?fieldType=&subDomain=] → recordId 列表。
    pub async fn list_record_ids(
        &self,
        zone: &str,
        field_type: Option<&str>,
        sub_domain: Option<&str>,
    ) -> Result<Vec<i64>, ProviderError> {
        let mut q = Vec::new();
        if let Some(t) = field_type {
            q.push(format!("fieldType={t}"));
        }
        if let Some(s) = sub_domain {
            q.push(format!("subDomain={s}"));
        }
        let qs = if q.is_empty() {
            String::new()
        } else {
            format!("?{}", q.join("&"))
        };
        let path = format!("/domain/zone/{zone}/record{qs}");
        let v = self.request("GET", &path, None).await?;
        let ids: Vec<i64> = serde_json::from_value(v)?;
        Ok(ids)
    }

    /// GET /domain/zone/{zone}/record/{id} → 记录详情。
    pub async fn get_record(&self, zone: &str, id: i64) -> Result<OvhRecord, ProviderError> {
        let path = format!("/domain/zone/{zone}/record/{id}");
        let v = self.request("GET", &path, None).await?;
        Ok(serde_json::from_value(v)?)
    }

    /// POST /domain/zone/{zone}/record → 创建；返回新记录 id。
    pub async fn create_record(&self, zone: &str, rec: &OvhRecord) -> Result<i64, ProviderError> {
        let path = format!("/domain/zone/{zone}/record");
        let body = serde_json::to_string(rec)?;
        let v = self.request("POST", &path, Some(body)).await?;
        Ok(v.get("id").and_then(|i| i.as_i64()).unwrap_or(0))
    }

    /// PUT /domain/zone/{zone}/record/{id} → 更新。
    pub async fn update_record(&self, zone: &str, rec: &OvhRecord) -> Result<(), ProviderError> {
        let path = format!("/domain/zone/{zone}/record/{}", rec.id);
        let body = serde_json::to_string(rec)?;
        self.request("PUT", &path, Some(body)).await?;
        Ok(())
    }

    /// DELETE /domain/zone/{zone}/record/{id} → 删除。
    pub async fn delete_record(&self, zone: &str, id: i64) -> Result<(), ProviderError> {
        let path = format!("/domain/zone/{zone}/record/{id}");
        self.request("DELETE", &path, None).await?;
        Ok(())
    }

    /// POST /domain/zone/{zone}/refresh：OVH 要求写操作后调用才生效。
    pub async fn refresh(&self, zone: &str) -> Result<(), ProviderError> {
        let path = format!("/domain/zone/{zone}/refresh");
        self.request("POST", &path, None).await?;
        Ok(())
    }
}
