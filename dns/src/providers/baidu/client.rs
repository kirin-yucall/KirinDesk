//! M9-DNS016: 百度智能云公网 DNS HTTP 客户端（BCE 签名）
//!
//! 端点：`https://dns.baidubce.com`（公网；内网 PrivateZone 不在此次范围）。
//! 接口（官方文档已 WebSearch 核实，2026-08）：
//! - `GET    /v1/dns/zone`                      查询域名列表（分页 marker/maxKeys）
//! - `GET    /v1/dns/zone/{zone}/record`        查询解析记录（rr/id/marker/maxKeys，无 type 过滤）
//! - `POST   /v1/dns/zone/{zone}/record`        添加解析记录（body {rr,type,value,ttl,priority}）
//! - `PUT    /v1/dns/zone/{zone}/record/{id}`   修改解析记录
//! - `DELETE /v1/dns/zone/{zone}/record/{id}`   删除解析记录
//!
//! 认证：请求头 `x-bce-date` + `Authorization: bce-auth-v1/...`（见 [`super::sign`]）。

use super::error::check_response;
use super::record::{RawRecord, RecordBody};
use super::sign::{bce_authorization, canonical_query, encode_path};
use crate::provider::{ProviderError, Record, RecordType};
use chrono::Utc;
use std::collections::BTreeMap;

/// 公网 DNS 默认端点。
pub const DEFAULT_BASE_URL: &str = "https://dns.baidubce.com";
/// 分页大小（官方上限 1000）。
const MAX_KEYS: u32 = 100;
/// 签名有效期（秒）。
const EXPIRATION: u32 = 1800;

/// 百度 DNS 客户端。
#[derive(Debug, Clone)]
pub struct BaiduClient {
    pub http: reqwest::Client,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub base_url: String,
}

impl BaiduClient {
    pub fn new(access_key_id: String, secret_access_key: String, base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("构建 reqwest Client 失败");
        Self {
            http,
            access_key_id,
            secret_access_key,
            base_url,
        }
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

    /// 发送已签名请求，返回 (状态码, 响应体, Retry-After)。
    ///
    /// `path` 为已编码路径；`query` 同时用于签名与 URL 构造（天然一致）。
    async fn call_raw(
        &self,
        method: &str,
        path: &str,
        query: &BTreeMap<String, String>,
        body: Option<&str>,
    ) -> Result<(u16, String, Option<u64>), ProviderError> {
        let x_bce_date = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let host = self.host_header();
        let url = format!(
            "{}{}{}",
            self.base_url,
            path,
            if query.is_empty() {
                String::new()
            } else {
                format!("?{}", canonical_query(query))
            }
        );
        let auth = bce_authorization(
            method,
            path,
            query,
            &host,
            &x_bce_date,
            &self.access_key_id,
            &self.secret_access_key,
            EXPIRATION,
        );
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| ProviderError::Other(format!("非法 HTTP 方法 {method}: {e}")))?;
        let mut req = self
            .http
            .request(method, &url)
            .header("x-bce-date", &x_bce_date)
            .header("Authorization", auth);
        if let Some(b) = body {
            req = req
                .header("Content-Type", "application/json")
                .body(b.to_string());
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        // 429 时尝试读取 Retry-After。
        let retry_after = if status == 429 {
            resp.headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
        } else {
            None
        };
        let text = resp.text().await?;
        Ok((status, text, retry_after))
    }

    /// 发送请求并做统一错误映射；成功返回 JSON（空 body → `Null`）。
    async fn call_json(
        &self,
        method: &str,
        path: &str,
        query: &BTreeMap<String, String>,
        body: Option<&str>,
    ) -> Result<serde_json::Value, ProviderError> {
        let (status, text, retry_after) = self.call_raw(method, path, query, body).await?;
        check_response(status, &text, retry_after)?;
        if text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&text).map_err(ProviderError::Json)
    }

    /// 域名列表（`GET /v1/dns/zone`，分页遍历）。
    pub async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let mut domains = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut query = BTreeMap::new();
            query.insert("maxKeys".into(), MAX_KEYS.to_string());
            if let Some(m) = &marker {
                query.insert("marker".into(), m.clone());
            }
            let v = self
                .call_json("GET", "/v1/dns/zone", &query, None)
                .await?;
            let truncated = v
                .get("isTruncated")
                .and_then(|t| t.as_bool())
                .unwrap_or(false);
            if let Some(zones) = v.get("zones").and_then(|z| z.as_array()) {
                for z in zones {
                    if let Some(name) = z.get("name").and_then(|n| n.as_str()) {
                        domains.push(name.to_string());
                    }
                }
            }
            if !truncated {
                break;
            }
            marker = v
                .get("nextMarker")
                .and_then(|m| m.as_str())
                .map(String::from);
            if marker.is_none() {
                break;
            }
        }
        Ok(domains)
    }

    /// 查询解析记录（wire 格式，分页遍历）。
    ///
    /// 官方列表接口**无 type 过滤参数**（仅 rr/id/marker/maxKeys），
    /// 类型过滤由调用方在内存完成；`rr` 传相对名（根 `@`）。
    pub async fn list_raw_records(
        &self,
        zone: &str,
        rr: Option<&str>,
    ) -> Result<Vec<RawRecord>, ProviderError> {
        let path = encode_path(&format!("/v1/dns/zone/{zone}/record"));
        let mut out = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut query = BTreeMap::new();
            query.insert("maxKeys".into(), MAX_KEYS.to_string());
            if let Some(r) = rr {
                query.insert("rr".into(), r.to_string());
            }
            if let Some(m) = &marker {
                query.insert("marker".into(), m.clone());
            }
            let v = self.call_json("GET", &path, &query, None).await?;
            let truncated = v
                .get("isTruncated")
                .and_then(|t| t.as_bool())
                .unwrap_or(false);
            if let Some(records) = v.get("records").and_then(|r| r.as_array()) {
                for item in records {
                    if let Ok(raw) = serde_json::from_value::<RawRecord>(item.clone()) {
                        out.push(raw);
                    }
                }
            }
            if !truncated {
                break;
            }
            marker = v
                .get("nextMarker")
                .and_then(|m| m.as_str())
                .map(String::from);
            if marker.is_none() {
                break;
            }
        }
        Ok(out)
    }

    /// 添加解析记录（`POST /v1/dns/zone/{zone}/record`）。
    pub async fn add_record(&self, zone: &str, body: &RecordBody) -> Result<(), ProviderError> {
        let path = encode_path(&format!("/v1/dns/zone/{zone}/record"));
        let payload = serde_json::to_string(body)?;
        self.call_json("POST", &path, &BTreeMap::new(), Some(&payload))
            .await?;
        Ok(())
    }

    /// 更新解析记录（`PUT /v1/dns/zone/{zone}/record/{recordId}`）。
    pub async fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        body: &RecordBody,
    ) -> Result<(), ProviderError> {
        let path = encode_path(&format!("/v1/dns/zone/{zone}/record/{record_id}"));
        let payload = serde_json::to_string(body)?;
        self.call_json("PUT", &path, &BTreeMap::new(), Some(&payload))
            .await?;
        Ok(())
    }

    /// 删除解析记录（`DELETE /v1/dns/zone/{zone}/record/{recordId}`）。
    pub async fn delete_record(&self, zone: &str, record_id: &str) -> Result<(), ProviderError> {
        let path = encode_path(&format!("/v1/dns/zone/{zone}/record/{record_id}"));
        self.call_json("DELETE", &path, &BTreeMap::new(), None)
            .await?;
        Ok(())
    }
}

/// 统一过滤：类型在内存精确过滤 + wire → 统一模型。
pub fn to_records(raw: Vec<RawRecord>, rtype: Option<RecordType>) -> Vec<Record> {
    raw.into_iter()
        .filter(|r| {
            rtype
                .map(|t| r.rtype.eq_ignore_ascii_case(t.as_str()))
                .unwrap_or(true)
        })
        .filter_map(super::record::from_raw)
        .collect()
}
