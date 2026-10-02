//! M9-DNS017: 火山引擎云解析 DNS HTTP 客户端
//!
//! 端点：`https://dns.volcengineapi.com`（2025-06-23 起新端点；旧端点
//! `open.volcengineapi.com` 可通过 `base_url` 覆盖回退）。
//! 风格：RPC，**GET + query 公共参数**（Action/Version），v4 风格 HMAC-SHA256 签名
//! （请求头 X-Date / X-Content-Sha256 / Authorization，见 [`super::sign`]）。
//!
//! 官方接口（已 WebSearch 复核，2026-08；记录管理为 CreateRecord/UpdateRecord/
//! DeleteRecord/ListRecordSets，Version=2018-08-01）：
//! - `ListZones`       域名（zone）列表，分页 PageNumber/PageSize → Zones[].ZID/ZoneName
//! - `ListRecordSets`  记录集列表（ZID + 分页）→ RecordSets[].RecordSetId/Host/Type/Value/TTL
//! - `CreateRecord`    添加记录（ZID/Host/Type/Value/TTL/Priority）
//! - `UpdateRecord`    更新记录（RecordSetId + 同上字段）
//! - `DeleteRecord`    删除记录（RecordSetId）
//!
//! 域名 → ZID 映射通过 ListZones 解析并缓存（Provider 生命周期内有效）。

use super::error::{check_response, unwrap_result};
use super::record::{to_params, RawRecordSet};
use super::sign::{authorization, canonical_query, EMPTY_BODY_SHA256_HEX};
use crate::provider::{ProviderError, Record};
use chrono::Utc;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

/// 新端点（2025-06 起）。
pub const DEFAULT_BASE_URL: &str = "https://dns.volcengineapi.com";
/// 旧端点（回退用，可通过环境变量 `KIRIN_DNS_VOLCENGINE_BASE_URL` 覆盖）。
pub const LEGACY_BASE_URL: &str = "https://open.volcengineapi.com";
/// API 版本。
pub const VERSION: &str = "2018-08-01";
/// 服务名（签名 CredentialScope 用）。
pub const SERVICE: &str = "dns";
/// 默认区域（凭据未配置区域时的兜底）。
pub const DEFAULT_REGION: &str = "cn-north-1";
/// 分页大小。
const PAGE_SIZE: u32 = 100;

/// 火山引擎 DNS 客户端。
#[derive(Debug, Clone)]
pub struct VolcengineClient {
    pub http: reqwest::Client,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
    pub base_url: String,
    /// 域名 → ZID 缓存（Provider 生命周期内有效；Arc 使 Client 可 Clone 共享）。
    zid_cache: Arc<Mutex<HashMap<String, String>>>,
}

impl VolcengineClient {
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        region: String,
        base_url: String,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("构建 reqwest Client 失败");
        Self {
            http,
            access_key_id,
            secret_access_key,
            region: if region.is_empty() {
                DEFAULT_REGION.to_string()
            } else {
                region
            },
            base_url,
            zid_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 端点回退：环境变量 `KIRIN_DNS_VOLCENGINE_BASE_URL` 可覆盖默认新端点。
    pub fn default_base_url() -> String {
        std::env::var("KIRIN_DNS_VOLCENGINE_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string())
    }

    /// 计算请求 Host 头（与 URL 一致，小写；含非默认端口）。
    fn host_header(&self) -> String {
        let url = reqwest::Url::parse(&self.base_url).expect("base_url 非法");
        let host = url.host_str().unwrap_or("").to_lowercase();
        match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }

    /// 发起一次已签名的 GET 请求（全部参数在 query，含 Action/Version）。
    ///
    /// `params` 为接口参数（不含 Action/Version），返回统一错误映射后的完整 JSON。
    async fn call(
        &self,
        action: &str,
        params: &mut BTreeMap<String, String>,
    ) -> Result<serde_json::Value, ProviderError> {
        params.insert("Action".into(), action.into());
        params.insert("Version".into(), VERSION.into());
        let x_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let host = self.host_header();
        // 参与签名的头（固定三头，顺序按 key 排序）。
        let mut headers = BTreeMap::new();
        headers.insert("host".into(), host.clone());
        headers.insert("x-content-sha256".into(), EMPTY_BODY_SHA256_HEX.to_string());
        headers.insert("x-date".into(), x_date.clone());
        let auth = authorization(
            "GET",
            "/",
            params,
            &headers,
            &self.access_key_id,
            &self.secret_access_key,
            &self.region,
            SERVICE,
        );
        let url = format!("{}/?{}", self.base_url, canonical_query(params));
        let resp = self
            .http
            .get(&url)
            .header("x-content-sha256", EMPTY_BODY_SHA256_HEX)
            .header("x-date", &x_date)
            .header("Authorization", auth)
            .send()
            .await?;
        let status = resp.status().as_u16();
        let body = resp.text().await?;
        check_response(status, &body)
    }

    /// 域名列表（ListZones，分页）→ (ZID, ZoneName)。
    pub async fn list_zones(&self) -> Result<Vec<(String, String)>, ProviderError> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut params = BTreeMap::new();
            params.insert("PageSize".into(), PAGE_SIZE.to_string());
            params.insert("PageNumber".into(), page.to_string());
            let v = unwrap_result(self.call("ListZones", &mut params).await?);
            let total = v.get("Total").and_then(|t| t.as_u64()).unwrap_or(0) as usize;
            let mut got = 0usize;
            if let Some(zones) = v.get("Zones").and_then(|z| z.as_array()) {
                for z in zones {
                    let zid = z.get("ZID").and_then(|i| i.as_str()).unwrap_or_default();
                    let name = z
                        .get("ZoneName")
                        .and_then(|n| n.as_str())
                        .unwrap_or_default();
                    if !zid.is_empty() && !name.is_empty() {
                        out.push((zid.to_string(), name.to_string()));
                        got += 1;
                    }
                }
            }
            if got == 0 || out.len() >= total {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    /// 域名 → ZID（ListZones 精确匹配 + 缓存）。
    pub async fn resolve_zid(&self, domain: &str) -> Result<String, ProviderError> {
        if let Some(zid) = self.zid_cache.lock().unwrap().get(domain) {
            return Ok(zid.clone());
        }
        let zones = self.list_zones().await?;
        let found = zones.into_iter().find(|(_, name)| name == domain);
        match found {
            Some((zid, _)) => {
                self.zid_cache
                    .lock()
                    .unwrap()
                    .insert(domain.to_string(), zid.clone());
                Ok(zid)
            }
            None => Err(ProviderError::NotFound {
                what: format!("域名不在火山引擎账号下: {domain}"),
            }),
        }
    }

    /// 记录集列表（ListRecordSets，分页遍历）。
    pub async fn list_record_sets(&self, zid: &str) -> Result<Vec<RawRecordSet>, ProviderError> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut params = BTreeMap::new();
            params.insert("ZID".into(), zid.to_string());
            params.insert("PageSize".into(), PAGE_SIZE.to_string());
            params.insert("PageNumber".into(), page.to_string());
            let v = unwrap_result(self.call("ListRecordSets", &mut params).await?);
            let total = v.get("Total").and_then(|t| t.as_u64()).unwrap_or(0) as usize;
            let mut got = 0usize;
            if let Some(sets) = v.get("RecordSets").and_then(|s| s.as_array()) {
                for item in sets {
                    if let Ok(raw) = serde_json::from_value::<RawRecordSet>(item.clone()) {
                        out.push(raw);
                        got += 1;
                    }
                }
            }
            if got == 0 || out.len() >= total {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    /// 添加记录（CreateRecord，ZID 必填）。
    pub async fn create_record(&self, zid: &str, rec: &Record) -> Result<(), ProviderError> {
        let mut params = to_params(rec);
        params.insert("ZID".into(), zid.to_string());
        self.call("CreateRecord", &mut params).await?;
        Ok(())
    }

    /// 更新记录（UpdateRecord，RecordSetId 必填）。
    pub async fn update_record(
        &self,
        record_set_id: &str,
        rec: &Record,
    ) -> Result<(), ProviderError> {
        let mut params = to_params(rec);
        params.insert("RecordSetId".into(), record_set_id.to_string());
        self.call("UpdateRecord", &mut params).await?;
        Ok(())
    }

    /// 删除记录（DeleteRecord，按 RecordSetId）。
    pub async fn delete_record(&self, record_set_id: &str) -> Result<(), ProviderError> {
        let mut params = BTreeMap::new();
        params.insert("RecordSetId".into(), record_set_id.to_string());
        self.call("DeleteRecord", &mut params).await?;
        Ok(())
    }
}
