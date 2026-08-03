//! M9-DNS015: Porkbun HTTP 客户端
//!
//! - 端点：`https://api.porkbun.com/api/json/v3`（全部 POST，凭据在 JSON body）
//! - 认证：每请求 body 携带 `apikey` + `secretapikey`（无签名头）
//! - 接口：`/ping`（测试连接）、`/domain/listAll`（域名列表）、
//!   `/dns/retrieve/{domain}`（查询，name 为 FQDN）、`/dns/create|edit|delete`
//! - 30s 超时；User-Agent `KirinDesk/0.1.0`；凭据只进请求 body，不落日志

use super::error::map_error;
use crate::provider::ProviderError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 官方端点（测试经 `PorkbunClient::new` 的 base_url 指向 127.0.0.1 mock）。
pub(crate) const PROD_BASE_URL: &str = "https://api.porkbun.com/api/json/v3";
const USER_AGENT: &str = "KirinDesk/0.1.0";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Porkbun TTL 最小值（官方文档 600 秒；写入时收敛，避免读写振荡）。
pub(crate) const TTL_MIN: u32 = 600;
/// Porkbun TTL 默认值（官方默认 600）。
pub(crate) const TTL_DEFAULT: u32 = 600;

/// Porkbun 记录（读写共用）。
///
/// - retrieve 响应：`{id, name(FQDN), type, content, ttl, prio, notes}`；
/// - create/edit 请求：`{type, name(相对名/子域), content, ttl, prio}`；
///   空字段序列化时省略（id 由服务端分配、根记录 name 留空）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct PkRecord {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub rtype: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ttl: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prio: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

/// Porkbun API 客户端。
#[derive(Clone)]
pub(crate) struct PorkbunClient {
    http: reqwest::Client,
    api_key: String,
    secret_key: String,
    base_url: String,
}

impl PorkbunClient {
    /// 构建客户端。`base_url` 生产传 [`PROD_BASE_URL`]，测试传 127.0.0.1 mock。
    pub fn new(api_key: String, secret_key: String, base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .expect("构建 Porkbun reqwest 客户端失败");
        Self {
            http,
            api_key,
            secret_key,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// 统一 POST：认证字段（apikey/secretapikey）与业务字段合并进 body。
    async fn post(&self, path: &str, business: Option<&PkRecord>) -> Result<serde_json::Value, ProviderError> {
        let mut body = serde_json::json!({
            "secretapikey": self.secret_key,
            "apikey": self.api_key,
        });
        if let Some(rec) = business {
            if let Ok(obj) = serde_json::to_value(rec) {
                if let serde_json::Value::Object(map) = obj {
                    for (k, v) in map {
                        body[k] = v;
                    }
                }
            }
        }
        let url = format!("{}{}", self.base_url, path);
        let resp = self.http.post(&url).json(&body).send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        if status == 200 {
            // 业务判定：status=SUCCESS / ERROR。
            let v: serde_json::Value = serde_json::from_str(&text)?;
            match v.get("status").and_then(|s| s.as_str()) {
                Some("SUCCESS") => Ok(v),
                _ => {
                    let msg = v
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or(&text)
                        .to_string();
                    Err(map_error(status, &msg))
                }
            }
        } else {
            Err(map_error(status, &text))
        }
    }

    /// POST /ping：认证通过即成功（test_connection 用）。
    pub async fn ping(&self) -> Result<(), ProviderError> {
        let _v = self.post("/ping", None).await?;
        Ok(())
    }

    /// POST /domain/listAll → 全部域名（domains[].domain）。
    pub async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let v = self.post("/domain/listAll", None).await?;
        let mut out = Vec::new();
        if let Some(domains) = v.get("domains").and_then(|d| d.as_array()) {
            for d in domains {
                if let Some(name) = d.get("domain").and_then(|x| x.as_str()) {
                    out.push(name.to_string());
                }
            }
        }
        Ok(out)
    }

    /// POST /dns/retrieve/{domain} → 全部记录（响应 name 为 FQDN）。
    pub async fn retrieve(&self, domain: &str) -> Result<Vec<PkRecord>, ProviderError> {
        let path = format!("/dns/retrieve/{}", domain);
        let v = self.post(&path, None).await?;
        let recs: Vec<PkRecord> =
            serde_json::from_value(v.get("records").cloned().unwrap_or(serde_json::json!([])))?;
        Ok(recs)
    }

    /// POST /dns/create/{domain} → 新记录 id。
    pub async fn create(&self, domain: &str, rec: &PkRecord) -> Result<String, ProviderError> {
        let path = format!("/dns/create/{}", domain);
        let v = self.post(&path, Some(rec)).await?;
        Ok(v.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string())
    }

    /// POST /dns/edit/{domain}/{id}：按 id 更新。
    pub async fn edit(&self, domain: &str, id: &str, rec: &PkRecord) -> Result<(), ProviderError> {
        let path = format!("/dns/edit/{}/{}", domain, id);
        self.post(&path, Some(rec)).await?;
        Ok(())
    }

    /// POST /dns/delete/{domain}/{id}：按 id 删除。
    pub async fn delete(&self, domain: &str, id: &str) -> Result<(), ProviderError> {
        let path = format!("/dns/delete/{}/{}", domain, id);
        self.post(&path, None).await?;
        Ok(())
    }
}
