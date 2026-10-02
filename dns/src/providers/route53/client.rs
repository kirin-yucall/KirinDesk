//! Route53 REST-XML 客户端（M9-DNS005）
//!
//! 端点 `https://route53.amazonaws.com/2013-04-01/`，认证 AWS SigV4
//! （见 [`super::sign`]），请求/响应均为 XML（手写解析，见 [`super::xml`]）。
//!
//! 本文件职责：
//! - HTTP 发送 + SigV4 签名（含 payload 哈希、host 提取、x-amz-date）；
//! - hosted zone 列表 / zone id 查找（带缓存）；
//! - 记录集列表（分页：`IsTruncated` + `NextRecordName`/`NextRecordType` 循环）；
//! - ChangeResourceRecordSets（UPSERT/DELETE，批量一次一个 set）；
//! - 相对名 ↔ FQDN.（末尾点）互转、统一 Record ↔ Route53 Value 互转。

use super::error;
use super::sign;
use super::xml;
use crate::provider::{Credential, ProviderError, Record, RecordData, RecordType};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 生产端点（API 前缀，固定为 2013-04-01）。
const DEFAULT_ENDPOINT: &str = "https://route53.amazonaws.com";
/// 生产端点路径前缀。
const API_PREFIX: &str = "/2013-04-01";
/// 超时：30 秒（通用要求）。
const TIMEOUT: Duration = Duration::from_secs(30);
/// User-Agent（通用要求）。
const USER_AGENT: &str = "KirinDesk/0.1.0";
/// TTL=0 时使用的默认 TTL（Route53 记录集必须带 TTL）。
const DEFAULT_TTL: u32 = 600;

/// 一个原始记录集（Route53 同名同类型 = 一个记录集，内含多条 Value）。
#[derive(Debug, Clone, PartialEq)]
pub struct RawRecordSet {
    /// FQDN（带末尾点，如 `my-pc.example.com.`）。
    pub name: String,
    /// 类型大写（A/AAAA/CNAME/MX/TXT/SRV/NS）。
    pub rtype: String,
    /// TTL（秒）。
    pub ttl: u32,
    /// 记录集全部 Value（Route53 单值字符串形态）。
    pub values: Vec<String>,
}

/// ChangeResourceRecordSets 中的一条变更（Action + 完整记录集）。
#[derive(Debug, Clone)]
pub struct Change {
    /// "UPSERT" 或 "DELETE"。
    pub action: &'static str,
    /// 要写入/删除的记录集（DELETE 须带当前全部 Value，否则 Route53 校验失败）。
    pub set: RawRecordSet,
}

/// hosted zone 列表项。
#[derive(Debug, Clone)]
pub struct HostedZoneInfo {
    /// zone id（不含 `/hostedzone/` 前缀，如 `Z1PA6795UKMFR9`）。
    pub id: String,
    /// zone 名称（去末尾点，如 `example.com`）。
    pub name: String,
}

/// Route53 客户端。`Clone` 可共享（Arc 化供并发使用）。
#[derive(Clone)]
pub struct Route53Client {
    http: reqwest::Client,
    access_key_id: String,
    secret_access_key: String,
    region: String,
    base_url: String,
    /// 域名(去尾点、小写) → zone id 缓存（避免每次查询都遍历 hostedzone）。
    /// `Arc` 包裹以便 `Clone` 共享同一缓存（`Route53Client` 派生 Clone）。
    zone_cache: Arc<Mutex<HashMap<String, String>>>,
}

impl Route53Client {
    /// 生产构造（凭据来自 `Credential::Route53`）。
    pub fn new(cred: &Credential) -> Self {
        match cred {
            Credential::Route53 {
                access_key_id,
                secret_access_key,
                region,
            } => Self::new_with_endpoint(
                access_key_id,
                secret_access_key,
                region,
                DEFAULT_ENDPOINT,
            ),
            _ => panic!(
                "route53 构造器收到非 Route53 凭据变体（注册表仅以 Route53 凭据调用本工厂）"
            ),
        }
    }

    /// 指定端点构造（测试 mock 用 `http://127.0.0.1`）。
    pub(crate) fn new_with_endpoint(
        access_key_id: &str,
        secret_access_key: &str,
        region: &str,
        endpoint: &str,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .expect("构建 reqwest client 失败");
        Self {
            http,
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_access_key.to_string(),
            region: region.to_string(),
            base_url: endpoint.trim_end_matches('/').to_string(),
            zone_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ────────────────────────────────────────────────────────────
    // 低层：签名 + 发送 + 状态码映射
    // ────────────────────────────────────────────────────────────

    /// 发送一次 SigV4 签名请求。
    ///
    /// `path` 为 API 路径（如 `/2013-04-01/hostedzone/Z1/rrset`，已 URI 编码）；
    /// `query` 为原始查询参数对（统一编码排序后同时用于 URL 与签名）；
    /// `body` 为可选请求体（XML 字符串）。
    /// 返回 `(状态码, 响应体)`；网络错误直接映射为 `ProviderError::Network`。
    async fn send(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<(u16, String), ProviderError> {
        let pairs: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let q = sign::canonical_query(&pairs);
        let url = if q.is_empty() {
            format!("{}{}", self.base_url, path)
        } else {
            format!("{}{}?{}", self.base_url, path, q)
        };
        let host = host_of(&url);
        let payload_hash = match body {
            Some(b) => sign::sha256_hex(b.as_bytes()),
            None => sign::EMPTY_PAYLOAD_HASH.to_string(),
        };
        let amz_date = sign_amz_date();
        let authorization = sign::authorization_header(
            &self.access_key_id,
            &self.secret_access_key,
            &self.region,
            method,
            path,
            &pairs,
            &host,
            &payload_hash,
            &amz_date,
        );

        let mut req = self
            .http
            .request(reqwest::Method::from_bytes(method.as_bytes()).expect("合法 HTTP method"), &url)
            .header("x-amz-date", amz_date)
            .header("Authorization", authorization);
        if let Some(b) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/xml")
                .header(reqwest::header::ACCEPT, "application/xml")
                .body(b.to_string());
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let text = resp.text().await?;
        error::map_response(status, &text, retry_after.as_deref())?;
        Ok((status, text))
    }

    // ────────────────────────────────────────────────────────────
    // hosted zone
    // ────────────────────────────────────────────────────────────

    /// GET /2013-04-01/hostedzone?maxitems=... → zone 列表（Id 去前缀、Name 去尾点）。
    /// `maxitems=None` 不传参数。test_connection 用 maxitems=1 的最小查询。
    pub async fn list_hosted_zones(&self, maxitems: Option<u32>) -> Result<Vec<HostedZoneInfo>, ProviderError> {
        let maxitems_str = maxitems.map(|n| n.to_string());
        let query: Vec<(&str, &str)> = match &maxitems_str {
            Some(n) => vec![("maxitems", n.as_str())],
            None => vec![],
        };
        let (_, body) = self.send("GET", &format!("{API_PREFIX}/hostedzone"), &query, None).await?;
        let mut zones = Vec::new();
        for zone in xml::elements(&body, "HostedZone") {
            let id = xml::element_text(zone, "Id")
                .map(|s| s.trim_start_matches("/hostedzone/").to_string())
                .unwrap_or_default();
            let name = xml::element_text(zone, "Name")
                .map(|s| s.trim_end_matches('.').to_string())
                .unwrap_or_default();
            if !id.is_empty() && !name.is_empty() {
                zones.push(HostedZoneInfo { id, name });
            }
        }
        Ok(zones)
    }

    /// 域名（无尾点）→ zone id（缓存命中直接返回；否则遍历列表并缓存）。
    /// 找不到 → `NotFound`。
    pub async fn zone_id(&self, domain: &str) -> Result<String, ProviderError> {
        let key = domain.trim_end_matches('.').to_ascii_lowercase();
        if let Some(id) = self.zone_cache.lock().unwrap().get(&key) {
            return Ok(id.clone());
        }
        let zones = self.list_hosted_zones(Some(1000)).await?;
        let matched = zones
            .iter()
            .find(|z| z.name.eq_ignore_ascii_case(&key))
            .map(|z| z.id.clone());
        match matched {
            Some(id) => {
                self.zone_cache.lock().unwrap().insert(key, id.clone());
                Ok(id)
            }
            None => Err(ProviderError::NotFound {
                what: format!("hosted zone「{key}」不存在或无权访问"),
            }),
        }
    }

    // ────────────────────────────────────────────────────────────
    // 记录集
    // ────────────────────────────────────────────────────────────

    /// GET /2013-04-01/hostedzone/{id}/rrset —— 记录集列表（分页循环直至 IsTruncated=false）。
    ///
    /// `name`/`rtype` 为服务端起点筛选（Route53 语义是词典序起点而非精确过滤，
    /// 调用方仍需按需精确过滤）。
    pub async fn list_rrsets(
        &self,
        zone_id: &str,
        name: Option<&str>,
        rtype: Option<&str>,
    ) -> Result<Vec<RawRecordSet>, ProviderError> {
        let mut out = Vec::new();
        let mut next_name = name.map(str::to_string);
        let mut next_type = rtype.map(str::to_string);
        loop {
            let mut query: Vec<(&str, String)> = Vec::new();
            if let Some(n) = &next_name {
                query.push(("name", n.clone()));
            }
            if let Some(t) = &next_type {
                query.push(("type", t.clone()));
            }
            let query_refs: Vec<(&str, &str)> = query
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect();
            let path = format!("{API_PREFIX}/hostedzone/{zone_id}/rrset");
            let (_, body) = self.send("GET", &path, &query_refs, None).await?;

            for set in xml::elements(&body, "ResourceRecordSet") {
                let name = xml::element_text(set, "Name").unwrap_or_default();
                let rtype = xml::element_text(set, "Type").unwrap_or_default();
                let ttl = xml::element_text(set, "TTL")
                    .and_then(|t| t.parse::<u32>().ok())
                    .unwrap_or(0);
                let values: Vec<String> = xml::elements(set, "ResourceRecord")
                    .iter()
                    .filter_map(|rr| xml::element_text(rr, "Value"))
                    .collect();
                if !name.is_empty() && !rtype.is_empty() {
                    out.push(RawRecordSet { name, rtype, ttl, values });
                }
            }

            // 分页：IsTruncated=true 且 NextRecordName 非空 → 以 Next* 为起点继续。
            let truncated = xml::element_text(&body, "IsTruncated")
                .map(|t| t == "true")
                .unwrap_or(false);
            if !truncated {
                break;
            }
            let Some(nn) = xml::element_text(&body, "NextRecordName") else {
                break; // 没有下一页起点（防御：服务端未给出）→ 停止
            };
            next_name = Some(nn);
            next_type = xml::element_text(&body, "NextRecordType");
        }
        Ok(out)
    }

    /// POST /2013-04-01/hostedzone/{id}/rrset —— ChangeResourceRecordSets。
    /// 每次调用一个记录集（本适配层的批量粒度），成功返回 Ok。
    pub async fn change_rrsets(
        &self,
        zone_id: &str,
        changes: &[Change],
        comment: Option<&str>,
    ) -> Result<(), ProviderError> {
        let body = change_request_xml(changes, comment);
        let path = format!("{API_PREFIX}/hostedzone/{zone_id}/rrset");
        self.send("POST", &path, &[], Some(&body)).await?;
        Ok(())
    }

    // ────────────────────────────────────────────────────────────
    // 统一模型互转（相对名 ↔ FQDN. / Record ↔ Value）
    // ────────────────────────────────────────────────────────────

    /// 相对名 → FQDN.：根 `""` → `{domain}.`；否则 `{name}.{domain}.`。
    pub(crate) fn to_fqdn(domain: &str, name: &str) -> String {
        let domain = domain.trim_end_matches('.');
        if name.is_empty() {
            format!("{domain}.")
        } else {
            format!("{name}.{domain}.")
        }
    }

    /// FQDN. → 相对名：去尾点；等于域名 → `""`（根）；否则去掉 `.{domain}` 后缀。
    /// 大小写不敏感匹配（DNS 名不区分大小写）。
    pub(crate) fn to_relative(fqdn: &str, domain: &str) -> String {
        let fqdn = fqdn.trim_end_matches('.');
        let domain = domain.trim_end_matches('.');
        if fqdn.eq_ignore_ascii_case(domain) {
            return String::new();
        }
        let suffix = format!(".{domain}");
        let lower = fqdn.to_ascii_lowercase();
        let lower_suffix = suffix.to_ascii_lowercase();
        if let Some(pos) = lower.rfind(&lower_suffix) {
            fqdn[..pos].to_string()
        } else {
            fqdn.to_string()
        }
    }

    /// 统一 Record → Route53 Value 单值字符串。
    /// - Plain → 原值；
    /// - Mx → `{priority} {exchange}.`（exchange 缺尾点则补）；
    /// - Srv → `{priority} {weight} {port} {target}.`（target 缺尾点则补）。
    pub(crate) fn record_to_value(rec: &Record) -> String {
        match &rec.data {
            RecordData::Plain(v) => v.clone(),
            RecordData::Mx { priority, exchange } => {
                format!("{priority} {}", ensure_fqdn_dot(exchange))
            }
            RecordData::Srv { priority, weight, port, target } => {
                format!("{priority} {weight} {port} {}", ensure_fqdn_dot(target))
            }
        }
    }

    /// Route53 Value 单值字符串 → 统一 RecordData（MX/SRV 结构化解析）。
    pub(crate) fn value_to_data(rtype: RecordType, value: &str) -> Option<RecordData> {
        match rtype {
            RecordType::A | RecordType::AAAA | RecordType::CNAME | RecordType::TXT | RecordType::NS => {
                Some(RecordData::Plain(value.to_string()))
            }
            RecordType::MX => {
                let mut parts = value.split_whitespace();
                let priority = parts.next()?.parse::<u16>().ok()?;
                let exchange = parts.collect::<Vec<_>>().join(" ");
                if exchange.is_empty() {
                    return None;
                }
                Some(RecordData::Mx { priority, exchange })
            }
            RecordType::SRV => {
                let parts: Vec<&str> = value.split_whitespace().collect();
                if parts.len() != 4 {
                    return None;
                }
                Some(RecordData::Srv {
                    priority: parts[0].parse().ok()?,
                    weight: parts[1].parse().ok()?,
                    port: parts[2].parse().ok()?,
                    target: parts[3].to_string(),
                })
            }
        }
    }

    /// TTL 归一化：0 → 默认 600（Route53 记录集必须显式带 TTL）。
    pub(crate) fn normalize_ttl(ttl: u32) -> u32 {
        if ttl == 0 {
            DEFAULT_TTL
        } else {
            ttl
        }
    }
}

/// 从完整 URL 提取 host[:port]（与 reqwest 发送的 Host 头一致）。
fn host_of(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let end = rest.find('/').unwrap_or(rest.len());
    rest[..end].to_string()
}

/// 当前 UTC 时间 → SigV4 x-amz-date（`YYYYMMDDTHHMMSSZ`）。
fn sign_amz_date() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// 目标主机名补末尾点（MX exchange / SRV target）。
fn ensure_fqdn_dot(s: &str) -> String {
    if s.ends_with('.') {
        s.to_string()
    } else {
        format!("{s}.")
    }
}

/// 构造 ChangeResourceRecordSetsRequest XML 体。
fn change_request_xml(changes: &[Change], comment: Option<&str>) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ChangeResourceRecordSetsRequest \
         xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ChangeBatch>",
    );
    if let Some(c) = comment {
        s.push_str("<Comment>");
        s.push_str(&xml::escape(c));
        s.push_str("</Comment>");
    }
    s.push_str("<Changes>");
    for ch in changes {
        s.push_str("<Change><Action>");
        s.push_str(ch.action);
        s.push_str("</Action><ResourceRecordSet><Name>");
        s.push_str(&xml::escape(&ch.set.name));
        s.push_str("</Name><Type>");
        s.push_str(&ch.set.rtype);
        s.push_str("</Type><TTL>");
        s.push_str(&ch.set.ttl.to_string());
        s.push_str("</TTL><ResourceRecords>");
        for v in &ch.set.values {
            s.push_str("<ResourceRecord><Value>");
            s.push_str(&xml::escape(v));
            s.push_str("</Value></ResourceRecord>");
        }
        s.push_str("</ResourceRecords></ResourceRecordSet></Change>");
    }
    s.push_str("</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred() -> Credential {
        Credential::Route53 {
            access_key_id: "AK".into(),
            secret_access_key: "SK".into(),
            region: "us-east-1".into(),
        }
    }

    fn rec(name: &str, rtype: RecordType, data: RecordData, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype,
            ttl,
            data,
        }
    }

    #[test]
    fn fqdn_roundtrip() {
        // 相对名 → FQDN.：根 "" → "{domain}."。
        assert_eq!(Route53Client::to_fqdn("example.com", ""), "example.com.");
        assert_eq!(Route53Client::to_fqdn("example.com", "my-pc"), "my-pc.example.com.");
        assert_eq!(
            Route53Client::to_fqdn("example.com", "_remote._tcp.my-pc"),
            "_remote._tcp.my-pc.example.com."
        );
        // FQDN. → 相对名：根 → ""。
        assert_eq!(Route53Client::to_relative("example.com.", "example.com"), "");
        assert_eq!(Route53Client::to_relative("example.com.", "example.com."), "");
        assert_eq!(Route53Client::to_relative("my-pc.example.com.", "example.com"), "my-pc");
        assert_eq!(
            Route53Client::to_relative("_remote._tcp.my-pc.example.com.", "example.com"),
            "_remote._tcp.my-pc"
        );
        // 大小写不敏感。
        assert_eq!(Route53Client::to_relative("My-PC.EXAMPLE.COM.", "example.com"), "My-PC");
        // 非本域名的 FQDN → 原样返回（防御）。
        assert_eq!(Route53Client::to_relative("other.com.", "example.com"), "other.com");
    }

    #[test]
    fn record_to_value_conversions() {
        let c = cred();
        let _client = Route53Client::new(&c);
        // SRV：单值字符串 "0 1 3389 tgt."，target 缺尾点自动补。
        let srv = rec("_remote._tcp.my-pc", RecordType::SRV, RecordData::Srv {
            priority: 0,
            weight: 1,
            port: 3389,
            target: "my-pc.example.com".into(),
        }, 600);
        assert_eq!(Route53Client::record_to_value(&srv), "0 1 3389 my-pc.example.com.");
        // MX。
        let mx = rec("", RecordType::MX, RecordData::Mx {
            priority: 10,
            exchange: "mail.example.com".into(),
        }, 300);
        assert_eq!(Route53Client::record_to_value(&mx), "10 mail.example.com.");
        // Plain 原样。
        let a = rec("my-pc", RecordType::A, RecordData::Plain("203.0.113.7".into()), 600);
        assert_eq!(Route53Client::record_to_value(&a), "203.0.113.7");
    }

    #[test]
    fn value_to_data_structured_parse() {
        // SRV 结构化往返。
        let d = Route53Client::value_to_data(RecordType::SRV, "0 1 3389 my-pc.example.com.")
            .expect("srv parse");
        assert_eq!(
            d,
            RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 3389,
                target: "my-pc.example.com.".into()
            }
        );
        // MX。
        let d = Route53Client::value_to_data(RecordType::MX, "10 mail.example.com.").unwrap();
        assert_eq!(
            d,
            RecordData::Mx {
                priority: 10,
                exchange: "mail.example.com.".into()
            }
        );
        // Plain 类型原样。
        assert_eq!(
            Route53Client::value_to_data(RecordType::A, "192.0.2.1"),
            Some(RecordData::Plain("192.0.2.1".into()))
        );
        // 非法 SRV（字段数不足）→ None。
        assert!(Route53Client::value_to_data(RecordType::SRV, "0 1 3389").is_none());
    }

    #[test]
    fn change_request_xml_shape() {
        let set = RawRecordSet {
            name: "example.com.".into(),
            rtype: "A".into(),
            ttl: 600,
            values: vec!["192.0.2.1".into(), "192.0.2.2".into()],
        };
        let xml_body = change_request_xml(&[Change { action: "UPSERT", set }], None);
        assert!(xml_body.contains("<Action>UPSERT</Action>"));
        assert!(xml_body.contains("<Name>example.com.</Name>"));
        assert!(xml_body.contains("<TTL>600</TTL>"));
        assert!(xml_body.contains("<ResourceRecord><Value>192.0.2.1</Value></ResourceRecord>"));
        assert!(xml_body.contains("<ResourceRecord><Value>192.0.2.2</Value></ResourceRecord>"));
        // 特殊字符转义。
        let set2 = RawRecordSet {
            name: "example.com.".into(),
            rtype: "TXT".into(),
            ttl: 60,
            values: vec!["a<b&c".into()],
        };
        let xml2 = change_request_xml(&[Change { action: "UPSERT", set: set2 }], Some("c&d"));
        assert!(xml2.contains("<Value>a&lt;b&amp;c</Value>"));
        assert!(xml2.contains("<Comment>c&amp;d</Comment>"));
    }
}
