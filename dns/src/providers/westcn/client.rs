//! M9-DNS019: 西部数码 API 客户端（`https://api.west.cn/api/v2`，表单 + JSON）
//!
//! - 认证（用户级，官方 apiv2 文档 §身份验证）：
//!   `token = md5(username + api_password + 毫秒时间戳)`，小写 32 位 hex，
//!   有效期 10 分钟 → 每次请求重新生成；请求携带 `username`/`time`/`token`。
//! - 认证（域名级，优先）：`apidomainkey`（管理中心-域名详情右侧 ApiKey），
//!   仅限单域名操作，无法枚举域名列表。
//! - 记录接口（`M9-DNS019` §一 + acme.sh `dns_west_cn.sh` 实测）：
//!   `POST {base}/domain/dns/`，`act` 作为表单字段分发：
//!   `dnsrec.list` / `dnsrec.add` / `dnsrec.update` / `dnsrec.del`；
//!   记录名字段 `hostname`（相对名，根为 "@"）。
//! - `dnsrec.update` 语义为「删旧加新」（DDNS），与统一幂等 upsert 一致。
//! - 域名列表：官方 domain_v2 文档为 `GET {base}/domain/?act=getdomains`。
//! - 编码：官方要求 GB2312/GBK；**本项目不新增依赖（encoding_rs 不可用）**，
//!   按任务要求以 UTF-8 百分号编码提交（通常可用），GBK 严格往返待实机联调
//!   确认后补充（见报告来源说明）。

use super::error;
use super::{from_vendor_name, to_vendor_name};
use crate::provider::{ProviderError, Record, RecordData, RecordType};
use md5::Digest;
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 域名级认证参数名（管理中心-域名右侧 ApiKey）。
const API_DOMAIN_KEY: &str = "apidomainkey";

/// 西部数码 API 客户端（`Debug` 输出不打印 api_password/domain_key）。
pub(crate) struct WestcnClient {
    client: reqwest::Client,
    base_url: String,
    username: String,
    api_password: String,
    domain_key: Option<String>,
}

impl fmt::Debug for WestcnClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WestcnClient")
            .field("base_url", &self.base_url)
            .field("username", &self.username)
            .field("api_password", &"<redacted>")
            .field("domain_key", &self.domain_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// 单条解析记录（`dnsrec.list` 响应元素；字段名按 acme.sh 实测，
/// 宽松别名兼容 `id`/`host`/`type`/`value` 等官方 variant）。
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct WestcnApiRecord {
    #[serde(alias = "id", default)]
    pub(crate) record_id: Option<i64>,
    #[serde(alias = "host", default)]
    pub(crate) hostname: Option<String>,
    #[serde(alias = "type", default)]
    pub(crate) record_type: Option<String>,
    #[serde(alias = "value", default)]
    pub(crate) record_value: Option<String>,
    #[serde(default)]
    pub(crate) ttl: Option<u32>,
    #[serde(default)]
    pub(crate) priority: Option<u16>,
}

impl WestcnClient {
    /// 构建客户端：30s 超时、UA `KirinDesk/0.1.0`。
    pub(crate) fn new(
        username: impl Into<String>,
        api_password: impl Into<String>,
        domain_key: Option<String>,
        base_url: &str,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("构建西部数码 reqwest 客户端失败");
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            username: username.into(),
            api_password: api_password.into(),
            domain_key,
        }
    }

    /// 当前毫秒时间戳（token 有效期 10 分钟 → 每次请求重新生成）。
    fn now_ms(&self) -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
            .to_string()
    }

    /// `token = md5(username + api_password + 毫秒时间戳)`，小写 32 位 hex
    /// （官方 apiv2 文档 §身份验证；示例 `md5(zhangsan + 5dh232kfg!* + 1554691950854)`）。
    pub(crate) fn compute_token(&self, timestamp: &str) -> String {
        let digest = md5::Md5::digest(format!(
            "{}{}{}",
            self.username, self.api_password, timestamp
        ));
        format!("{digest:x}")
    }

    /// 认证参数：优先域名级 `apidomainkey`；否则用户级 `username`+`time`+`token`。
    fn auth_params(&self, timestamp: &str) -> Vec<(&'static str, String)> {
        match &self.domain_key {
            Some(key) => vec![(API_DOMAIN_KEY, key.clone())],
            None => vec![
                ("username", self.username.clone()),
                ("time", timestamp.to_string()),
                ("token", self.compute_token(timestamp)),
            ],
        }
    }

    /// 表单/查询串编码：UTF-8 百分号编码（RFC 3986 unreserved 原样，空格为 `+`）。
    fn encode_form(params: &[(&str, String)]) -> String {
        params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// `POST {base}/domain/dns/`：`act` 作为表单字段（与 acme.sh 实测一致）。
    async fn post_dns(
        &self,
        act: &str,
        extra: Vec<(&'static str, String)>,
    ) -> Result<serde_json::Value, ProviderError> {
        let url = format!("{}/domain/dns/", self.base_url);
        let ts = self.now_ms();
        let mut params = self.auth_params(&ts);
        params.push(("act", act.to_string()));
        params.extend(extra);
        let body = Self::encode_form(&params);
        let resp = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?;
        error::parse_response(resp).await
    }

    /// 测试连接：域名列表最小查询（域名级认证无法枚举 → 明确错误）。
    pub(crate) async fn test_connection(&self) -> Result<(), ProviderError> {
        self.list_domains().await.map(|_| ())
    }

    /// 域名列表：`GET {base}/domain/?act=getdomains`（官方 domain_v2 文档）。
    ///
    /// 域名级认证（apidomainkey）仅限单域名，无法枚举 → `Other` 明确提示。
    pub(crate) async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        if self.domain_key.is_some() {
            return Err(ProviderError::Other(
                "域名级认证（apidomainkey）仅限单域名操作，无法枚举域名列表；\
                 请改用用户级认证（username + api_password）"
                    .to_string(),
            ));
        }
        let ts = self.now_ms();
        let mut params = self.auth_params(&ts);
        params.push(("act", "getdomains".to_string()));
        params.push(("limit", "100".to_string()));
        params.push(("page", "1".to_string()));
        let url = format!("{}/domain/?{}", self.base_url, Self::encode_form(&params));
        let resp = self.client.get(&url).send().await?;
        let json = error::parse_response(resp).await?;

        let data = &json["data"];
        let items: Vec<serde_json::Value> = match data {
            serde_json::Value::Array(a) => a.clone(),
            _ => data
                .get("items")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default(),
        };
        let mut out = Vec::new();
        for it in items {
            if let Some(d) = it.get("domain").and_then(|d| d.as_str()) {
                out.push(d.to_string());
            }
        }
        Ok(out)
    }

    /// 拉取域名全部解析记录（`act=dnsrec.list`；服务端过滤不可靠 → 客户端过滤）。
    async fn query_api_records(
        &self,
        domain: &str,
    ) -> Result<Vec<WestcnApiRecord>, ProviderError> {
        let json = self
            .post_dns("dnsrec.list", vec![("domain", domain.to_string())])
            .await?;
        Ok(extract_records(&json))
    }

    /// 查询记录：按统一相对名 / 类型过滤；SRV/NS 能力降级直接返回空。
    pub(crate) async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        if let Some(t) = rtype {
            if !supported_type(t) {
                return Ok(Vec::new());
            }
        }
        let all = self.query_api_records(domain).await?;
        Ok(all
            .iter()
            .filter_map(to_unified)
            .filter(|r| {
                name.map(|n| n == r.name).unwrap_or(true)
                    && rtype.map(|t| t == r.rtype).unwrap_or(true)
            })
            .collect())
    }

    /// 幂等 upsert：查 hostname+type → 存在 `dnsrec.update`（删旧加新）→
    /// 不存在 `dnsrec.add`；SRV/NS → `Unsupported`（能力降级）。
    pub(crate) async fn upsert_record(
        &self,
        domain: &str,
        rec: &Record,
    ) -> Result<(), ProviderError> {
        if !supported_type(rec.rtype) {
            return Err(ProviderError::Unsupported(rec.rtype.as_str()));
        }
        let all = self.query_api_records(domain).await?;
        let matched = all.iter().find(|r| {
            to_unified(r)
                .map(|u| u.name == rec.name && u.rtype == rec.rtype)
                .unwrap_or(false)
        });

        let mut fields: Vec<(&'static str, String)> = vec![
            ("domain", domain.to_string()),
            ("hostname", to_vendor_name(&rec.name)),
            ("record_type", rec.rtype.as_str().to_string()),
            ("record_value", data_to_value(&rec.data)),
        ];
        if rec.ttl > 0 {
            fields.push(("ttl", rec.ttl.to_string()));
        }
        match matched {
            Some(existing) => {
                if let Some(id) = existing.record_id {
                    fields.push(("id", id.to_string()));
                }
                self.post_dns("dnsrec.update", fields).await?;
            }
            None => {
                self.post_dns("dnsrec.add", fields).await?;
            }
        }
        Ok(())
    }

    /// 删除该 (hostname, type) 下全部记录（`act=dnsrec.del`，按记录 id）；
    /// 无匹配 → `NotFound`；SRV/NS → `Unsupported`。
    pub(crate) async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        if !supported_type(rtype) {
            return Err(ProviderError::Unsupported(rtype.as_str()));
        }
        let all = self.query_api_records(domain).await?;
        let matched: Vec<WestcnApiRecord> = all
            .into_iter()
            .filter(|r| {
                to_unified(r)
                    .map(|u| u.name == name && u.rtype == rtype)
                    .unwrap_or(false)
            })
            .collect();
        if matched.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        for r in matched {
            if let Some(id) = r.record_id {
                self.post_dns(
                    "dnsrec.del",
                    vec![("domain", domain.to_string()), ("id", id.to_string())],
                )
                .await?;
            }
        }
        Ok(())
    }
}

/// 能力降级：SRV ❌ / NS ❌（《M9-DNS019》§二能力矩阵；AAAA 按文档支持保持可用）。
pub(crate) fn supported_type(rtype: RecordType) -> bool {
    !matches!(rtype, RecordType::SRV | RecordType::NS)
}

/// 统一数据 → 厂商 `record_value` 字符串（MX/SRV 为 "优先级 ... 目标" 惯例）。
fn data_to_value(data: &RecordData) -> String {
    match data {
        RecordData::Plain(v) => v.clone(),
        RecordData::Mx { priority, exchange } => format!("{priority} {exchange}"),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
    }
}

/// 从 `dnsrec.list` 响应提取记录数组（兼容 `data:[...]` 与 `data.{records|items}`）。
fn extract_records(json: &serde_json::Value) -> Vec<WestcnApiRecord> {
    let data = &json["data"];
    let arr = match data {
        serde_json::Value::Array(a) => a.clone(),
        _ => data
            .get("records")
            .or_else(|| data.get("items"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
    };
    arr.iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect()
}

/// 厂商记录 → 统一 [`Record`]（根 hostname "@" → 相对名 ""）。
fn to_unified(r: &WestcnApiRecord) -> Option<Record> {
    let raw_type = r.record_type.as_deref()?.to_ascii_uppercase();
    let rtype = RecordType::from_str(&raw_type).ok()?;
    let value = r.record_value.clone().unwrap_or_default();
    let name = from_vendor_name(r.hostname.as_deref().unwrap_or(""));
    let data = match rtype {
        RecordType::A
        | RecordType::AAAA
        | RecordType::CNAME
        | RecordType::TXT
        | RecordType::NS => RecordData::Plain(value),
        RecordType::MX => {
            // value 形如 "10 mail.example.com"，或独立 priority 字段。
            let (priority, exchange) = match value.split_once(' ') {
                Some((p, rest)) if p.parse::<u16>().is_ok() => {
                    (p.parse().unwrap_or(0), rest.to_string())
                }
                _ => (r.priority.unwrap_or(0), value),
            };
            RecordData::Mx { priority, exchange }
        }
        RecordType::SRV => {
            // 官方不支持 SRV；若服务端历史存在，按 "优先级 权重 端口 目标" 解析。
            let mut parts = value.split_whitespace();
            let priority = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let weight = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let port = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let target = parts.next().unwrap_or("").to_string();
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            }
        }
    };
    Some(Record {
        name,
        rtype,
        ttl: r.ttl.unwrap_or(0),
        data,
    })
}

/// 表单/查询百分号编码（UTF-8；RFC 3986 unreserved 原样，空格为 `+`）。
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
