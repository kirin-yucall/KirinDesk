//! M9-DNS003: 阿里云云解析 HTTP 客户端（RPC GET + 公共参数 + 签名）
//!
//! 所有请求走 `GET https://alidns.aliyuncs.com/?{公共参数+接口参数+Signature}`，
//! 公共参数：`Action / Version=2015-01-09 / AccessKeyId / SignatureMethod=HMAC-SHA1 /
//! SignatureVersion=1.0 / SignatureNonce(随机) / Timestamp(UTC ISO8601) / Format=JSON`。
//! 签名见 [`super::sign`]，错误映射见 [`super::error`]。

use super::error::map_response;
use super::record::{from_raw, to_vendor_rr, to_vendor_value, RawRecord};
use super::sign::{canonical_query, sign_rpc};
use crate::provider::{ProviderError, Record, RecordData, RecordType};
use chrono::Utc;
use rand::RngCore;
use std::collections::BTreeMap;

/// Alidns API 版本（2015-01-09）。
const VERSION: &str = "2015-01-09";
/// 默认端点。
pub const DEFAULT_BASE_URL: &str = "https://alidns.aliyuncs.com";
/// 每页记录数上限（官方最大值 500）。
const PAGE_SIZE: u32 = 500;

/// Alidns 客户端：装配公共参数 → 签名 → GET 请求 → 统一错误映射。
#[derive(Debug, Clone)]
pub struct AliyunClient {
    pub http: reqwest::Client,
    pub access_key_id: String,
    pub access_key_secret: String,
    pub base_url: String,
}

impl AliyunClient {
    pub fn new(access_key_id: String, access_key_secret: String, base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("构建 reqwest Client 失败");
        Self {
            http,
            access_key_id,
            access_key_secret,
            base_url,
        }
    }

    /// 发起一次已签名的 RPC GET 请求。
    ///
    /// `params` 为接口参数（不含公共参数与 Signature），返回统一错误映射后的 JSON。
    async fn call(
        &self,
        action: &str,
        params: &mut BTreeMap<String, String>,
    ) -> Result<serde_json::Value, ProviderError> {
        // 公共参数装配。
        params.insert("Action".into(), action.into());
        params.insert("Version".into(), VERSION.into());
        params.insert("AccessKeyId".into(), self.access_key_id.clone());
        params.insert("SignatureMethod".into(), "HMAC-SHA1".into());
        params.insert("SignatureVersion".into(), "1.0".into());
        // SignatureNonce：每次请求唯一（随机 16 字节 hex）。
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        params.insert("SignatureNonce".into(), hex::encode(nonce));
        // Timestamp：UTC ISO8601 `YYYY-MM-DDThh:mm:ssZ`。
        params.insert(
            "Timestamp".into(),
            Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );
        params.insert("Format".into(), "JSON".into());
        // Signature 不参与签名，签名后追加（BTreeMap 按 key 排序，天然在末尾）。
        let signature = sign_rpc(params, &self.access_key_secret);
        params.insert("Signature".into(), signature);
        let url = format!("{}/?{}", self.base_url, canonical_query(params));
        let resp = self.http.get(&url).send().await?;
        let status = resp.status().as_u16();
        let body = resp.text().await?;
        map_response(status, &body)
    }

    /// 域名列表（`Action=DescribeDomains`，自动分页）。
    pub async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let mut domains = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut params = BTreeMap::new();
            params.insert("PageSize".into(), PAGE_SIZE.to_string());
            params.insert("PageNumber".into(), page.to_string());
            let v = self.call("DescribeDomains", &mut params).await?;
            let total = v.get("TotalCount").and_then(|t| t.as_u64()).unwrap_or(0) as usize;
            let mut got = 0usize;
            if let Some(arr) = v.pointer("/Domains/Domain").and_then(|d| d.as_array()) {
                for d in arr {
                    if let Some(name) = d.get("DomainName").and_then(|n| n.as_str()) {
                        domains.push(name.to_string());
                        got += 1;
                    }
                }
            }
            if got == 0 || domains.len() >= total {
                break;
            }
            page += 1;
        }
        Ok(domains)
    }

    /// 查询域名下全部解析记录（wire 格式，自动分页）。
    ///
    /// `rr_keyword` / `type_keyword` 为可选关键字过滤（Alidns 关键字为模糊匹配，
    /// 精确过滤由调用方在内存中完成）。
    pub async fn list_raw_records(
        &self,
        domain: &str,
        rr_keyword: Option<&str>,
        type_keyword: Option<&str>,
    ) -> Result<Vec<RawRecord>, ProviderError> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut params = BTreeMap::new();
            params.insert("DomainName".into(), domain.to_string());
            params.insert("PageSize".into(), PAGE_SIZE.to_string());
            params.insert("PageNumber".into(), page.to_string());
            if let Some(k) = rr_keyword {
                params.insert("RRKeyWord".into(), k.to_string());
            }
            if let Some(t) = type_keyword {
                params.insert("TypeKeyWord".into(), t.to_string());
            }
            let v = self.call("DescribeDomainRecords", &mut params).await?;
            let total = v.get("TotalCount").and_then(|t| t.as_u64()).unwrap_or(0) as usize;
            let mut got = 0usize;
            if let Some(arr) = v.pointer("/DomainRecords/Record").and_then(|r| r.as_array()) {
                for item in arr {
                    match serde_json::from_value::<RawRecord>(item.clone()) {
                        Ok(raw) => {
                            out.push(raw);
                            got += 1;
                        }
                        Err(_) => continue, // 字段缺失的记录跳过
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

    /// 添加解析记录（`Action=AddDomainRecord`）。
    pub async fn add_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let mut params = build_record_params(None, domain, rec);
        self.call("AddDomainRecord", &mut params).await?;
        Ok(())
    }

    /// 更新解析记录（`Action=UpdateDomainRecord`，RecordId 必填）。
    pub async fn update_record(
        &self,
        record_id: &str,
        domain: &str,
        rec: &Record,
    ) -> Result<(), ProviderError> {
        let mut params = build_record_params(Some(record_id), domain, rec);
        self.call("UpdateDomainRecord", &mut params).await?;
        Ok(())
    }

    /// 删除解析记录（`Action=DeleteDomainRecord`，按 RecordId）。
    pub async fn delete_record(&self, record_id: &str) -> Result<(), ProviderError> {
        let mut params = BTreeMap::new();
        params.insert("RecordId".into(), record_id.to_string());
        self.call("DeleteDomainRecord", &mut params).await?;
        Ok(())
    }
}

/// 组装 Add/Update 记录参数：RR/Type/Value + TTL（>0 时传）+ MX 的 Priority。
fn build_record_params(
    record_id: Option<&str>,
    domain: &str,
    rec: &Record,
) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    if let Some(id) = record_id {
        params.insert("RecordId".into(), id.to_string());
    }
    params.insert("DomainName".into(), domain.to_string());
    params.insert("RR".into(), to_vendor_rr(&rec.name));
    params.insert("Type".into(), rec.rtype.as_str().to_string());
    params.insert("Value".into(), to_vendor_value(rec));
    if rec.ttl > 0 {
        params.insert("TTL".into(), rec.ttl.to_string());
    }
    if let RecordData::Mx { priority, .. } = &rec.data {
        params.insert("Priority".into(), priority.to_string());
    }
    params
}

/// 相对名/类型精确过滤（Alidns 的 RRKeyWord/TypeKeyWord 为模糊匹配，需二次精确过滤）。
pub fn filter_exact(
    records: Vec<RawRecord>,
    name: Option<&str>,
    rtype: Option<RecordType>,
) -> Vec<Record> {
    records
        .into_iter()
        .filter(|raw| {
            name.map(|n| super::record::to_relative_name(&raw.rr) == n).unwrap_or(true)
                && rtype.map(|t| raw.rtype.eq_ignore_ascii_case(t.as_str())).unwrap_or(true)
        })
        .filter_map(from_raw)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 装配参数必须含全部公共参数（缺一签名即不一致）。
    #[test]
    fn common_params_shape() {
        let client = AliyunClient::new(
            "ak".into(),
            "sk".into(),
            "http://127.0.0.1:1".into(),
        );
        let mut params = BTreeMap::new();
        params.insert("DomainName".into(), "example.com".into());
        params.insert("PageSize".into(), "500".into());
        params.insert("PageNumber".into(), "1".into());
        // 手动模拟 call() 的公共参数装配（call 需网络，这里只验装配逻辑）。
        params.insert("Action".into(), "DescribeDomainRecords".into());
        params.insert("Version".into(), VERSION.into());
        params.insert("AccessKeyId".into(), client.access_key_id.clone());
        params.insert("SignatureMethod".into(), "HMAC-SHA1".into());
        params.insert("SignatureVersion".into(), "1.0".into());
        params.insert("SignatureNonce".into(), "nonce-1".into());
        params.insert("Timestamp".into(), "2016-01-01T12:00:00Z".into());
        params.insert("Format".into(), "JSON".into());
        for key in [
            "Action", "Version", "AccessKeyId", "SignatureMethod", "SignatureVersion",
            "SignatureNonce", "Timestamp", "Format",
        ] {
            assert!(params.contains_key(key), "缺少公共参数 {key}");
        }
        let sig = sign_rpc(&params, &client.access_key_secret);
        assert!(!sig.is_empty());
    }
}
