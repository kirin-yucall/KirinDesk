//! Azure DNS ARM REST 客户端（M9-DNS006）
//!
//! 端点 `https://management.azure.com`，认证 OAuth2 Bearer（见 [`super::token`]），
//! 查询参数固定 `api-version=2018-05-01`，JSON 序列化（serde_json）。
//!
//! 本文件职责：
//! - Bearer 注入 + 401 invalid_token 强制刷新重试一次（M9-DNS006 §三）；
//! - dnsZones 列表（域名列表 / test_connection）；
//! - recordsets 列表（分页跟随 `nextLink`）；
//! - 记录集 GET（先查）/ PUT（整组替换）/ DELETE；
//! - 相对名 → Azure 记录集名（根 `""` → `"@"`）。

use super::error;
use super::token::TokenManager;
use crate::provider::{Credential, ProviderError};
use serde_json::Value;
use std::time::Duration;

/// 生产端点。
const DEFAULT_ENDPOINT: &str = "https://management.azure.com";
/// 超时：30 秒（通用要求）。
const TIMEOUT: Duration = Duration::from_secs(30);
/// User-Agent（通用要求）。
const USER_AGENT: &str = "KirinDesk/0.1.0";
/// ARM API 版本（M9-DNS006 指定）。
pub(crate) const API_VERSION: &str = "2018-05-01";
/// 网络资源类型前缀。
const PROVIDER_PATH: &str = "providers/Microsoft.Network/dnsZones";

/// Azure 客户端。`Clone` 可共享（Arc 化供并发使用）。
#[derive(Clone)]
pub struct AzureClient {
    http: reqwest::Client,
    token: TokenManager,
    subscription_id: String,
    resource_group: String,
    base_url: String,
}

impl AzureClient {
    /// 生产构造（凭据来自 `Credential::Azure`）。
    pub fn new(cred: &Credential) -> Self {
        match cred {
            Credential::Azure {
                tenant_id,
                client_id,
                client_secret,
                subscription_id,
                resource_group,
            } => Self::new_with_endpoint(
                tenant_id,
                client_id,
                client_secret,
                subscription_id,
                resource_group,
                DEFAULT_ENDPOINT,
                None,
            ),
            _ => panic!(
                "azure 构造器收到非 Azure 凭据变体（注册表仅以 Azure 凭据调用本工厂）"
            ),
        }
    }

    /// 测试构造：`endpoint_override`/`token_url_override` 指向 mock（`http://127.0.0.1`）。
    pub(crate) fn new_with_endpoint(
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
        subscription_id: &str,
        resource_group: &str,
        endpoint_override: &str,
        token_url_override: Option<&str>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .expect("构建 reqwest client 失败");
        let token = TokenManager::new_with_endpoint(
            tenant_id,
            client_id,
            client_secret,
            http.clone(),
            token_url_override,
        );
        Self {
            http,
            token,
            subscription_id: subscription_id.to_string(),
            resource_group: resource_group.to_string(),
            base_url: endpoint_override.trim_end_matches('/').to_string(),
        }
    }

    // ────────────────────────────────────────────────────────────
    // 低层：Bearer + 401 刷新重试 + 状态码映射
    // ────────────────────────────────────────────────────────────

    /// 发送一次请求。401 → 强制刷新 token 重试一次（invalid_token 场景）。
    /// 返回 `(状态码, 响应体, retry-after)`。
    async fn send(
        &self,
        method: &str,
        url: &str,
        body: Option<&Value>,
    ) -> Result<(u16, String, Option<String>), ProviderError> {
        let token = self.token.get_token().await?;
        let (status, text, retry_after) = self.raw(method, url, body, &token).await?;
        if status == 401 {
            // 401 invalid_token → 强制刷新一次再重试（仅此一次，防循环）。
            let fresh = self.token.force_refresh().await?;
            return self.raw(method, url, body, &fresh).await;
        }
        Ok((status, text, retry_after))
    }

    /// 单次发送（不重试）。
    async fn raw(
        &self,
        method: &str,
        url: &str,
        body: Option<&Value>,
        token: &str,
    ) -> Result<(u16, String, Option<String>), ProviderError> {
        let mut req = self
            .http
            .request(reqwest::Method::from_bytes(method.as_bytes()).expect("合法 HTTP method"), url)
            .bearer_auth(token);
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let text = resp.text().await?;
        Ok((status, text, retry_after))
    }

    /// 状态码 → 统一错误（2xx → Ok）。
    fn check(&self, status: u16, body: &str, retry_after: Option<&str>) -> Result<(), ProviderError> {
        error::map_response(status, body, retry_after)
    }

    /// GET 一页 JSON，返回 (value 数组, nextLink)。
    async fn get_page(&self, url: &str) -> Result<(Vec<Value>, Option<String>), ProviderError> {
        let (status, body, retry_after) = self.send("GET", url, None).await?;
        self.check(status, &body, retry_after.as_deref())?;
        let json: Value = serde_json::from_str(&body)?;
        let items = json
            .get("value")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let next = json
            .get("nextLink")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok((items, next))
    }

    // ────────────────────────────────────────────────────────────
    // 域名（zone）
    // ────────────────────────────────────────────────────────────

    /// GET .../dnsZones —— 域名列表（跟随 nextLink）。
    /// 返回 zone 名称（去尾点），供 list_domains / test_connection 使用。
    pub async fn list_dns_zones(&self) -> Result<Vec<String>, ProviderError> {
        let mut out = Vec::new();
        let mut url = format!(
            "{}/subscriptions/{}/resourceGroups/{}/{PROVIDER_PATH}?api-version={API_VERSION}",
            self.base_url, self.subscription_id, self.resource_group
        );
        loop {
            let (items, next) = self.get_page(&url).await?;
            for item in &items {
                if let Some(name) = item.get("name").and_then(Value::as_str) {
                    out.push(name.trim_end_matches('.').to_string());
                }
            }
            match next {
                Some(n) => url = n,
                None => break,
            }
        }
        Ok(out)
    }

    // ────────────────────────────────────────────────────────────
    // 记录集
    // ────────────────────────────────────────────────────────────

    /// GET .../dnsZones/{zone}/recordsets —— 全部记录集（分页跟随 nextLink）。
    /// 返回原始 item JSON 列表（名称/类型/properties），由 [`super::record`] 解析。
    pub async fn list_record_sets(&self, zone: &str) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        let mut url = format!(
            "{}/subscriptions/{}/resourceGroups/{}/{PROVIDER_PATH}/{}/recordsets?api-version={API_VERSION}",
            self.base_url,
            self.subscription_id,
            self.resource_group,
            zone.trim_end_matches('.'),
        );
        loop {
            let (items, next) = self.get_page(&url).await?;
            out.extend(items);
            match next {
                Some(n) => url = n,
                None => break,
            }
        }
        Ok(out)
    }

    /// GET .../dnsZones/{zone}/{TYPE}/{name} —— 单个记录集。
    /// 404 → `Ok(None)`（供 upsert 先查后写判断是否存在）。
    pub async fn get_record_set(
        &self,
        zone: &str,
        rtype: &str,
        name: &str,
    ) -> Result<Option<Value>, ProviderError> {
        let url = self.record_set_url(zone, rtype, name);
        let (status, body, retry_after) = self.send("GET", &url, None).await?;
        if status == 404 {
            return Ok(None);
        }
        self.check(status, &body, retry_after.as_deref())?;
        Ok(Some(serde_json::from_str(&body)?))
    }

    /// PUT .../dnsZones/{zone}/{TYPE}/{name} —— 记录集整组替换。
    /// `properties` 为 `{"properties": {...}}` 外层包装或纯 properties 均可（此处传 properties）。
    pub async fn put_record_set(
        &self,
        zone: &str,
        rtype: &str,
        name: &str,
        properties: &Value,
    ) -> Result<(), ProviderError> {
        let url = self.record_set_url(zone, rtype, name);
        let body = serde_json::json!({ "properties": properties });
        let (status, text, retry_after) = self.send("PUT", &url, Some(&body)).await?;
        self.check(status, &text, retry_after.as_deref())
    }

    /// DELETE .../dnsZones/{zone}/{TYPE}/{name} —— 删除整个记录集。
    /// 404 → NotFound（由统一错误映射给出）。
    pub async fn delete_record_set(
        &self,
        zone: &str,
        rtype: &str,
        name: &str,
    ) -> Result<(), ProviderError> {
        let url = self.record_set_url(zone, rtype, name);
        let (status, text, retry_after) = self.send("DELETE", &url, None).await?;
        self.check(status, &text, retry_after.as_deref())
    }

    // ────────────────────────────────────────────────────────────
    // 工具
    // ────────────────────────────────────────────────────────────

    /// 相对名 → Azure 记录集名（根 `""` → `"@"`）。
    pub(crate) fn azure_name(name: &str) -> String {
        if name.is_empty() {
            "@".to_string()
        } else {
            name.to_string()
        }
    }

    /// 组装记录集 URL（zone 去尾点；name 为 Azure 形态）。
    fn record_set_url(&self, zone: &str, rtype: &str, name: &str) -> String {
        format!(
            "{}/subscriptions/{}/resourceGroups/{}/{PROVIDER_PATH}/{}/{}/{name}?api-version={API_VERSION}",
            self.base_url,
            self.subscription_id,
            self.resource_group,
            zone.trim_end_matches('.'),
            rtype,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_name_maps_root_to_at() {
        assert_eq!(AzureClient::azure_name(""), "@");
        assert_eq!(AzureClient::azure_name("my-pc"), "my-pc");
        assert_eq!(AzureClient::azure_name("_remote._tcp.my-pc"), "_remote._tcp.my-pc");
    }
}
