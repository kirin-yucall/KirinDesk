//! M9-DNS020: 新网 API 客户端（`https://api.xinnet.com` 开放平台，XML/JSON）
//!
//! ⚠️ **文档不透明（《M9-DNS020_新网适配.md》§一/§三）**：新网域名 API 主要面向
//! 授权经销商/渠道合作伙伴，公开资料少且不一致。本客户端按第三方资料
//! （hzjcp.com 调用示例：`sign = MD5(apiKey + secretKey)`、`apiKey`/`sign`/
//! `timestamp`/`format` 参数 + IP 白名单）整理为**占位实现**，保证编译与契约
//! 测试通过；**实现前须向新网官方获取正式 API 文档**，核对签名串格式、端点
//! 路径与响应形状后替换。
//!
//! 占位约定（以官方文档为准修订）：
//! - 签名：`sign = md5(api_key + secret_key)`（小写 hex）
//! - 公共参数：`apiKey`/`sign`/`timestamp`（秒）/`client_ip`/`format=json`
//! - 域名列表：`GET /domain/list`
//! - 记录查询：`GET /domain/dns/list`
//! - 记录写入：`POST /domain/dns/add` | `/domain/dns/update` | `/domain/dns/delete`
//! - 记录名字段 `host`（相对名，根为 "@"）；响应 `{"code":200,"message":"ok","data":...}`

use super::error;
use super::{from_vendor_name, to_vendor_name};
use crate::provider::{ProviderError, Record, RecordData, RecordType};
use md5::Digest;
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 新网 API 客户端（`Debug` 输出不打印 secret_key，凭据不落日志）。
pub(crate) struct XinnetClient {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    secret_key: String,
    client_ip: String,
}

impl fmt::Debug for XinnetClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XinnetClient")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key)
            .field("secret_key", &"<redacted>")
            .field("client_ip", &self.client_ip)
            .finish()
    }
}

/// 单条解析记录（响应元素字段按第三方资料占位，宽松别名兼容）。
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct XinnetApiRecord {
    #[serde(alias = "record_id", default)]
    pub(crate) id: Option<i64>,
    #[serde(alias = "name", alias = "rr", default)]
    pub(crate) host: Option<String>,
    // 字段名 `rtype`（`type` 为关键字）；wire 上为 `type`，另兼容 `record_type`。
    #[serde(alias = "type", alias = "record_type", default)]
    pub(crate) rtype: Option<String>,
    #[serde(alias = "record_value", default)]
    pub(crate) value: Option<String>,
    #[serde(default)]
    pub(crate) ttl: Option<u32>,
}

impl XinnetClient {
    /// 构建客户端：30s 超时、UA `KirinDesk/0.1.0`。
    pub(crate) fn new(
        api_key: impl Into<String>,
        secret_key: impl Into<String>,
        client_ip: impl Into<String>,
        base_url: &str,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("构建新网 reqwest 客户端失败");
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            secret_key: secret_key.into(),
            client_ip: client_ip.into(),
        }
    }

    /// 当前 Unix 秒时间戳。
    fn now_secs() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string()
    }

    /// 签名（占位实现）：`sign = MD5(api_key + secret_key)`，小写 hex。
    ///
    /// 依据第三方资料（hzjcp.com 教程）；**实现前须向新网官方获取正式 API
    /// 文档**核对签名串格式（可能与 timestamp 拼接等）后替换。
    pub(crate) fn compute_sign(&self) -> String {
        format!(
            "{:x}",
            md5::Md5::digest(format!("{}{}", self.api_key, self.secret_key))
        )
    }

    /// 公共认证参数（含 IP 白名单字段 `client_ip`）。
    fn common_params(&self) -> Vec<(&'static str, String)> {
        vec![
            ("apiKey", self.api_key.clone()),
            ("sign", self.compute_sign()),
            ("timestamp", Self::now_secs()),
            ("client_ip", self.client_ip.clone()),
            ("format", "json".to_string()),
        ]
    }

    /// 表单/查询串编码（UTF-8 百分号编码）。
    fn encode_form(params: &[(&str, String)]) -> String {
        params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// GET 接口：公共参数 + 业务参数放查询串。
    async fn get_json(
        &self,
        path: &str,
        extra: Vec<(&'static str, String)>,
    ) -> Result<serde_json::Value, ProviderError> {
        let mut params = self.common_params();
        params.extend(extra);
        let url = format!("{}{}?{}", self.base_url, path, Self::encode_form(&params));
        let resp = self.client.get(&url).send().await?;
        error::parse_response(resp).await
    }

    /// POST 接口：公共参数 + 业务参数放表单体。
    async fn post_json(
        &self,
        path: &str,
        extra: Vec<(&'static str, String)>,
    ) -> Result<serde_json::Value, ProviderError> {
        let mut params = self.common_params();
        params.extend(extra);
        let url = format!("{}{}", self.base_url, path);
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

    /// 测试连接：域名列表最小查询。
    pub(crate) async fn test_connection(&self) -> Result<(), ProviderError> {
        self.list_domains().await.map(|_| ())
    }

    /// 域名列表（端点占位：`GET /domain/list`）。
    pub(crate) async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let json = self.get_json("/domain/list", vec![]).await?;
        Ok(extract_domains(&json))
    }

    /// 拉取域名全部解析记录（`GET /domain/dns/list`）。
    async fn query_api_records(
        &self,
        domain: &str,
    ) -> Result<Vec<XinnetApiRecord>, ProviderError> {
        let json = self
            .get_json(
                "/domain/dns/list",
                vec![("domain", domain.to_string())],
            )
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

    /// 幂等 upsert：查 (host, type) → 存在 `POST /domain/dns/update`（带 id）→
    /// 不存在 `POST /domain/dns/add`；SRV/NS → `Unsupported`（能力降级）。
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
            ("host", to_vendor_name(&rec.name)),
            ("type", rec.rtype.as_str().to_string()),
            ("value", data_to_value(&rec.data)),
        ];
        if rec.ttl > 0 {
            fields.push(("ttl", rec.ttl.to_string()));
        }
        match matched {
            Some(existing) => {
                if let Some(id) = existing.id {
                    fields.push(("id", id.to_string()));
                }
                self.post_json("/domain/dns/update", fields).await?;
            }
            None => {
                self.post_json("/domain/dns/add", fields).await?;
            }
        }
        Ok(())
    }

    /// 删除该 (host, type) 下全部记录（`POST /domain/dns/delete`，按 id）；
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
        let matched: Vec<XinnetApiRecord> = all
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
            if let Some(id) = r.id {
                self.post_json(
                    "/domain/dns/delete",
                    vec![("domain", domain.to_string()), ("id", id.to_string())],
                )
                .await?;
            }
        }
        Ok(())
    }
}

/// 能力降级：SRV ❌ / NS ⚠️（M9-DNS020 §二矩阵按文档置 false；TTL ✅、改名 ✅）。
pub(crate) fn supported_type(rtype: RecordType) -> bool {
    !matches!(rtype, RecordType::SRV | RecordType::NS)
}

/// 统一数据 → 厂商 `value` 字符串（MX/SRV 为 "优先级 ... 目标" 惯例）。
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

/// 域名列表提取：兼容 `data:["a.com",...]`、`data:[{"domain":"a.com"},...]` 与
/// `data:{"domains":[...]}` 三种占位形态。
fn extract_domains(json: &serde_json::Value) -> Vec<String> {
    let data = &json["data"];
    let arr: Vec<serde_json::Value> = match data {
        serde_json::Value::Array(a) => a.clone(),
        _ => data
            .get("domains")
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default(),
    };
    arr.iter()
        .filter_map(|it| {
            it.as_str()
                .map(String::from)
                .or_else(|| it.get("domain").and_then(|d| d.as_str()).map(String::from))
        })
        .collect()
}

/// 记录提取：兼容 `data:[...]` 与 `data:{"records":[...]}` 两种占位形态。
fn extract_records(json: &serde_json::Value) -> Vec<XinnetApiRecord> {
    let data = &json["data"];
    let arr = match data {
        serde_json::Value::Array(a) => a.clone(),
        _ => data
            .get("records")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
    };
    arr.iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect()
}

/// 厂商记录 → 统一 [`Record`]（根 host "@" → 相对名 ""）。
fn to_unified(r: &XinnetApiRecord) -> Option<Record> {
    let raw_type = r.rtype.as_deref()?.to_ascii_uppercase();
    let rtype = RecordType::from_str(&raw_type).ok()?;
    let value = r.value.clone().unwrap_or_default();
    let name = from_vendor_name(r.host.as_deref().unwrap_or(""));
    let data = match rtype {
        RecordType::A
        | RecordType::AAAA
        | RecordType::CNAME
        | RecordType::TXT
        | RecordType::NS => RecordData::Plain(value),
        RecordType::MX => {
            let (priority, exchange) = match value.split_once(' ') {
                Some((p, rest)) if p.parse::<u16>().is_ok() => {
                    (p.parse().unwrap_or(0), rest.to_string())
                }
                _ => (0, value),
            };
            RecordData::Mx { priority, exchange }
        }
        RecordType::SRV => {
            // 占位解析 "优先级 权重 端口 目标"。
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
