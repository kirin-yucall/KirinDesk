//! M9-DNS018: 京东云解析（云解析）HTTP 客户端（JDCLOUD2 签名 + 记录模型互转）
//!
//! 接口（官方 V2，https://docs.jdcloud.com/cn/jd-cloud-dns/api/overview，
//! 端点 `https://domainservice.jdcloud-api.com`）：
//! - `describeDomains`：GET `/v2/regions/{regionId}/domain`（pageNumber/pageSize/domainName）；
//! - `describeResourceRecord`：GET `/v2/regions/{regionId}/domain/{domainId}/ResourceRecord`
//!   （分页，hostRecord 精确过滤在本地完成）；
//! - `createResourceRecord`：POST 同上（AddRR：hostRecord/hostValue/ttl/type/
//!   mxPriority/port/weight/viewValue）；
//! - `modifyResourceRecord`：PUT `/…/ResourceRecord/{resourceRecordId}`
//!   （UpdateRR 另含 domainName）；
//! - `deleteResourceRecord`：DELETE `/…/ResourceRecord/{resourceRecordId}`。
//!
//! 差异点消化：
//! - 记录名：统一相对名（"" = 根）↔ 京东云 `@`（主机记录）；域名字→域名 ID
//!   （`describeDomains` 解析，未命中 → NotFound）；
//! - MX：`mxPriority` 字段承载优先级，`hostValue` 承载 exchange；
//! - SRV：`mxPriority`（优先级）+ `port`（端口）+ `weight`（权重）+ `hostValue`（目标）；
//! - CNAME/NS/目标：写/读均剥尾点（京东云展示形态）；
//! - 线路：统一使用默认线路 `viewValue: [-1]`（官方示例值）；
//! - upsert：查同 hostRecord+type → 同数据仅更新 TTL / 异数据修改首条 / 无则创建——幂等；
//! - delete：删除该 hostRecord+type 下全部记录。
//!
//! 凭据（`Credential::Jdcloud`）不参与任何日志/Display 输出。

use super::error;
use super::sign;
use crate::provider::{ProviderError, Record, RecordData, RecordType};
use serde_json::{json, Value};
use std::str::FromStr;
use std::time::Duration;

/// 生产端点。
pub const DEFAULT_ENDPOINT: &str = "https://domainservice.jdcloud-api.com";
/// 默认地域（凭据 region 为空时使用）。
pub const DEFAULT_REGION: &str = "cn-north-1";
/// 记录默认 TTL（秒；`Record.ttl == 0` 时使用）。
const DEFAULT_TTL: u32 = 600;
/// 默认线路 ID（官方示例：`ViewValue: -1` 表示默认线路）。
const DEFAULT_VIEW: i64 = -1;
/// 分页大小。
const PAGE_SIZE: u32 = 100;
/// 分页拉取防呆上限（避免死循环）。
const MAX_PAGES: u32 = 200;

/// 京东云单条解析记录（wire 形态，hostRecord 已转为相对名）。
#[derive(Debug, Clone)]
pub(crate) struct WireRR {
    pub id: i64,
    pub host_record: String,
    pub rtype: RecordType,
    pub host_value: String,
    pub ttl: u32,
    pub mx_priority: i64,
    pub port: i64,
    pub weight: i64,
}

/// JDCLOUD2 签名的云解析客户端。
#[derive(Debug, Clone)]
pub struct JdcloudClient {
    http: reqwest::Client,
    endpoint: String,
    access_key: String,
    secret_key: String,
    region: String,
}

impl JdcloudClient {
    /// 构建客户端（30s 超时、User-Agent "KirinDesk/0.1.0"；region 空 → 默认 cn-north-1）。
    pub fn new(
        access_key: String,
        secret_key: String,
        region: String,
        endpoint: String,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("构建 reqwest Client 失败");
        let region = if region.is_empty() {
            DEFAULT_REGION.to_string()
        } else {
            region
        };
        Self {
            http,
            endpoint,
            access_key,
            secret_key,
            region,
        }
    }

    /// 测试连接：域名列表取 1 条。
    pub async fn test_connection(&self) -> Result<(), ProviderError> {
        self.describe_domains_page(1, 1, "").await.map(|_| ())
    }

    /// 全部域名（分页拉取）。
    pub async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let mut out = Vec::new();
        let mut page_number = 1u32;
        loop {
            let (names, total) = self.describe_domains_page(page_number, PAGE_SIZE, "").await?;
            let n = names.len();
            out.extend(names.into_iter().map(|(name, _)| name));
            if out.len() as u32 >= total || n < PAGE_SIZE as usize || page_number >= MAX_PAGES {
                break;
            }
            page_number += 1;
        }
        Ok(out)
    }

    /// 域名 → 域名 ID（`describeDomains` 精确匹配；未命中 → NotFound）。
    pub(crate) async fn resolve_domain_id(&self, domain: &str) -> Result<i64, ProviderError> {
        let (domains, _) = self.describe_domains_page(1, PAGE_SIZE, domain).await?;
        domains
            .into_iter()
            .find(|(name, _)| name == domain)
            .map(|(_, id)| id)
            .ok_or_else(|| ProviderError::NotFound {
                what: format!("域名 {domain} 不存在"),
            })
    }

    /// 单页域名列表：返回 [(域名, domainId), …] 与 TotalCount。
    async fn describe_domains_page(
        &self,
        page_number: u32,
        page_size: u32,
        domain_name: &str,
    ) -> Result<(Vec<(String, i64)>, u32), ProviderError> {
        let mut query: Vec<(&str, String)> = vec![
            ("pageNumber", page_number.to_string()),
            ("pageSize", page_size.to_string()),
        ];
        if !domain_name.is_empty() {
            query.push(("domainName", domain_name.to_string()));
        }
        let path = format!("/v2/regions/{}/domain", self.region);
        let v = self
            .call("GET", &path, &query, None)
            .await?;
        let list = v
            .pointer("/result/dataList")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| {
                        Some((
                            d.get("domainName")?.as_str()?.to_string(),
                            d.get("id")?.as_i64()?,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let total = v
            .pointer("/result/totalCount")
            .and_then(|t| t.as_u64())
            .unwrap_or(0) as u32;
        Ok((list, total))
    }

    /// 查询域名下全部解析记录（wire 形态，分页拉全）。
    async fn list_rr(&self, domain_id: i64) -> Result<Vec<WireRR>, ProviderError> {
        let path = format!(
            "/v2/regions/{}/domain/{domain_id}/ResourceRecord",
            self.region
        );
        let mut out = Vec::new();
        let mut page_number = 1u32;
        loop {
            let query = vec![
                ("pageNumber", page_number.to_string()),
                ("pageSize", PAGE_SIZE.to_string()),
            ];
            let v = self.call("GET", &path, &query, None).await?;
            let page: Vec<WireRR> = v
                .pointer("/result/dataList")
                .and_then(|a| a.as_array())
                .map(|arr| arr.iter().filter_map(parse_wire_rr).collect())
                .unwrap_or_default();
            let n = page.len();
            let total = v
                .pointer("/result/totalCount")
                .and_then(|t| t.as_u64())
                .unwrap_or(0) as usize;
            out.extend(page);
            if out.len() >= total || n < PAGE_SIZE as usize || page_number >= MAX_PAGES {
                break;
            }
            page_number += 1;
        }
        Ok(out)
    }

    /// 统一查询：name=None 全表；rtype=None 全部类型（本地过滤）。
    pub async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let domain_id = self.resolve_domain_id(domain).await?;
        let mut wire = self.list_rr(domain_id).await?;
        if let Some(n) = name {
            wire.retain(|r| r.host_record == n);
        }
        if let Some(t) = rtype {
            wire.retain(|r| r.rtype == t);
        }
        Ok(wire.iter().filter_map(wire_to_record).collect())
    }

    /// 幂等 upsert：查同 hostRecord+type → 同数据仅更新 TTL / 异数据修改首条 /
    /// 无则创建。
    pub async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let domain_id = self.resolve_domain_id(domain).await?;
        let path = format!(
            "/v2/regions/{}/domain/{domain_id}/ResourceRecord",
            self.region
        );
        let ttl = if rec.ttl == 0 { DEFAULT_TTL } else { rec.ttl };
        let (host_value, mx_priority, port, weight) = record_to_wire(rec);

        let existing: Vec<WireRR> = self
            .list_rr(domain_id)
            .await?
            .into_iter()
            .filter(|r| r.host_record == rec.name && r.rtype == rec.rtype)
            .collect();

        if let Some(same) = existing.iter().find(|r| r.matches_data(rec)) {
            // 幂等：数据一致 → 仅 TTL 不一致才发起修改。
            if same.ttl != ttl {
                self.modify_rr(
                    domain,
                    domain_id,
                    same.id,
                    rec,
                    &host_value,
                    mx_priority,
                    port,
                    weight,
                    ttl,
                )
                .await?;
            }
            return Ok(());
        }
        if let Some(first) = existing.first() {
            // 存在同 hostRecord+type 但数据不同 → 修改首条。
            self.modify_rr(
                domain,
                domain_id,
                first.id,
                rec,
                &host_value,
                mx_priority,
                port,
                weight,
                ttl,
            )
            .await?;
            return Ok(());
        }
        // 不存在 → 创建（AddRR）。
        let mut body = json!({
            "hostRecord": wire_name(&rec.name),
            "hostValue": host_value,
            "ttl": ttl,
            "type": rec.rtype.as_str(),
            "viewValue": [DEFAULT_VIEW],
        });
        if let Some(mx) = mx_priority {
            body["mxPriority"] = json!(mx);
        }
        if let Some(p) = port {
            body["port"] = json!(p);
        }
        if let Some(w) = weight {
            body["weight"] = json!(w);
        }
        self.call("POST", &path, &[], Some(&body.to_string())).await?;
        Ok(())
    }

    /// 修改解析记录（UpdateRR，另含 domainName）。
    async fn modify_rr(
        &self,
        domain: &str,
        domain_id: i64,
        rr_id: i64,
        rec: &Record,
        host_value: &str,
        mx_priority: Option<i64>,
        port: Option<i64>,
        weight: Option<i64>,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        let path = format!(
            "/v2/regions/{}/domain/{domain_id}/ResourceRecord/{rr_id}",
            self.region
        );
        let mut body = json!({
            "domainName": domain,
            "hostRecord": wire_name(&rec.name),
            "hostValue": host_value,
            "ttl": ttl,
            "type": rec.rtype.as_str(),
            "viewValue": [DEFAULT_VIEW],
        });
        if let Some(mx) = mx_priority {
            body["mxPriority"] = json!(mx);
        }
        if let Some(p) = port {
            body["port"] = json!(p);
        }
        if let Some(w) = weight {
            body["weight"] = json!(w);
        }
        self.call("PUT", &path, &[], Some(&body.to_string())).await?;
        Ok(())
    }

    /// 删除该 hostRecord+type 下全部记录；无记录 → NotFound。
    pub async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let domain_id = self.resolve_domain_id(domain).await?;
        let hits: Vec<WireRR> = self
            .list_rr(domain_id)
            .await?
            .into_iter()
            .filter(|r| r.host_record == name && r.rtype == rtype)
            .collect();
        if hits.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {}.{domain}", wire_name(name)),
            });
        }
        for rr in &hits {
            let path = format!(
                "/v2/regions/{}/domain/{domain_id}/ResourceRecord/{}",
                self.region, rr.id
            );
            self.call("DELETE", &path, &[], None).await?;
        }
        Ok(())
    }

    /// 执行一次 JDCLOUD2 签名的 HTTP 请求：成功返回响应 JSON。
    ///
    /// 查询参数与 body 参与签名（body 为空 → 空串哈希）；凭据不参与日志；
    /// 错误统一经 [`error::map_error`] 映射。
    async fn call(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, String)],
        body: Option<&str>,
    ) -> Result<Value, ProviderError> {
        let date_time = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        // 32 位随机 hex 作为 nonce（京东云仅要求随机串）。
        let nonce = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        let query_refs: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let headers = [
            ("content-type", sign::CONTENT_TYPE),
            ("x-jdcloud-date", date_time.as_str()),
            ("x-jdcloud-nonce", nonce.as_str()),
        ];
        let authorization = sign::jdcloud2_authorization(
            &self.access_key,
            &self.secret_key,
            &self.region,
            sign::SERVICE,
            &date_time,
            method,
            path,
            &query_refs,
            &headers,
            body.unwrap_or("").as_bytes(),
        );

        let url = format!("{}{}", self.endpoint, path);
        let mut req = self
            .http
            .request(reqwest::Method::from_bytes(method.as_bytes()).expect("HTTP 方法合法"), &url)
            .header("x-jdcloud-algorithm", sign::ALGORITHM)
            .header("x-jdcloud-date", &date_time)
            .header("x-jdcloud-nonce", &nonce)
            .header("Content-Type", sign::CONTENT_TYPE)
            .header("Authorization", authorization)
            .query(&query_refs);
        if let Some(b) = body {
            req = req.body(b.to_string());
        }
        let resp = req.send().await?;

        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let text = resp.text().await?;
        if !(200..300).contains(&status) {
            return Err(error::map_error(status, &text, retry_after));
        }
        Ok(serde_json::from_str(&text)?)
    }
}

// ── 记录模型互转（统一模型 ↔ 京东云 wire）──

/// 相对名 → 主机记录（"" = 根 → "@"）。
fn wire_name(name: &str) -> String {
    if name.is_empty() {
        "@".to_string()
    } else {
        name.to_string()
    }
}

/// 主机记录 → 相对名（"@" → ""）。
fn rel_name(name: &str) -> String {
    if name == "@" {
        String::new()
    } else {
        name.to_string()
    }
}

/// 剥尾点（CNAME/NS 值、MX exchange、SRV target 的规范化）。
fn strip_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// 统一 Record → (hostValue, mxPriority, port, weight)。
/// - Plain：原值；CNAME/NS 剥尾点；
/// - Mx：hostValue=exchange（剥尾点），mxPriority=priority；
/// - Srv：hostValue=target（剥尾点），mxPriority=priority，port=port，weight=weight。
fn record_to_wire(rec: &Record) -> (String, Option<i64>, Option<i64>, Option<i64>) {
    match &rec.data {
        RecordData::Plain(v) => (
            match rec.rtype {
                RecordType::CNAME | RecordType::NS => strip_dot(v).to_string(),
                _ => v.clone(),
            },
            None,
            None,
            None,
        ),
        RecordData::Mx { priority, exchange } => {
            (strip_dot(exchange).to_string(), Some(*priority as i64), None, None)
        }
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => (
            strip_dot(target).to_string(),
            Some(*priority as i64),
            Some(*port as i64),
            Some(*weight as i64),
        ),
    }
}

/// wire 记录 → 统一 Record：
/// - MX → Mx{priority: mxPriority, exchange: hostValue}（剥尾点）；
/// - SRV → Srv{priority: mxPriority, weight, port, target: hostValue}（剥尾点）；
/// - 其余 → Plain（CNAME/NS 剥尾点）。
fn wire_to_record(w: &WireRR) -> Option<Record> {
    let data = match w.rtype {
        RecordType::MX => RecordData::Mx {
            priority: w.mx_priority as u16,
            exchange: strip_dot(&w.host_value).to_string(),
        },
        RecordType::SRV => RecordData::Srv {
            priority: w.mx_priority as u16,
            weight: w.weight as u16,
            port: w.port as u16,
            target: strip_dot(&w.host_value).to_string(),
        },
        RecordType::A | RecordType::AAAA | RecordType::TXT => {
            RecordData::Plain(w.host_value.clone())
        }
        RecordType::CNAME | RecordType::NS => {
            RecordData::Plain(strip_dot(&w.host_value).to_string())
        }
    };
    Some(Record {
        name: w.host_record.clone(),
        rtype: w.rtype,
        ttl: w.ttl,
        data,
    })
}

/// 解析记录响应条目（RRInfo）→ WireRR。
fn parse_wire_rr(v: &Value) -> Option<WireRR> {
    let rtype = RecordType::from_str(v.get("type")?.as_str()?).ok()?;
    Some(WireRR {
        id: v.get("id")?.as_i64()?,
        host_record: rel_name(v.get("hostRecord")?.as_str()?),
        rtype,
        host_value: v.get("hostValue").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        ttl: v.get("ttl").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        mx_priority: v.get("mxPriority").and_then(|x| x.as_i64()).unwrap_or(0),
        port: v.get("port").and_then(|x| x.as_i64()).unwrap_or(0),
        weight: v.get("weight").and_then(|x| x.as_i64()).unwrap_or(0),
    })
}

/// wire 记录是否与统一记录数据一致（幂等判断）。
///
/// 京东云对 CNAME/NS/MX exchange/SRV target 的展示形态不带尾点，但为
/// 兼容客户侧可能的带点写法，比对时两侧都剥尾点。
impl WireRR {
    fn matches_data(&self, rec: &Record) -> bool {
        match &rec.data {
            RecordData::Plain(v) => {
                let v = match rec.rtype {
                    RecordType::CNAME | RecordType::NS => strip_dot(v).to_string(),
                    _ => v.clone(),
                };
                let w = match rec.rtype {
                    RecordType::CNAME | RecordType::NS => {
                        strip_dot(&self.host_value).to_string()
                    }
                    _ => self.host_value.clone(),
                };
                w == v && self.mx_priority == 0 && self.port == 0 && self.weight == 0
            }
            RecordData::Mx { priority, exchange } => {
                self.mx_priority == *priority as i64
                    && self.port == 0
                    && self.weight == 0
                    && strip_dot(&self.host_value) == strip_dot(exchange)
            }
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                self.mx_priority == *priority as i64
                    && self.port == *port as i64
                    && self.weight == *weight as i64
                    && strip_dot(&self.host_value) == strip_dot(target)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_conversion_root() {
        assert_eq!(wire_name(""), "@");
        assert_eq!(wire_name("www"), "www");
        assert_eq!(rel_name("@"), "");
        assert_eq!(rel_name("www"), "www");
    }

    #[test]
    fn srv_wire_roundtrip() {
        let w = WireRR {
            id: 1,
            host_record: "_remote._tcp.my-pc".into(),
            rtype: RecordType::SRV,
            host_value: "pc.example.com.".into(),
            ttl: 600,
            mx_priority: 0,
            port: 3389,
            weight: 5,
        };
        let rec = wire_to_record(&w).unwrap();
        match &rec.data {
            RecordData::Srv { priority, weight, port, target } => {
                assert_eq!((*priority, *weight, *port), (0, 5, 3389));
                assert_eq!(target, "pc.example.com");
            }
            other => panic!("期望 Srv，得到 {other:?}"),
        }
        let (value, mx, port, weight) = record_to_wire(&rec);
        assert_eq!(value, "pc.example.com");
        assert_eq!((mx, port, weight), (Some(0), Some(3389), Some(5)));
        assert!(w.matches_data(&rec));
    }

    #[test]
    fn mx_wire_roundtrip() {
        let w = WireRR {
            id: 2,
            host_record: "".into(),
            rtype: RecordType::MX,
            host_value: "mail.example.com.".into(),
            ttl: 600,
            mx_priority: 10,
            port: 0,
            weight: 0,
        };
        let rec = wire_to_record(&w).unwrap();
        match &rec.data {
            RecordData::Mx { priority, exchange } => {
                assert_eq!(*priority, 10);
                assert_eq!(exchange, "mail.example.com");
            }
            other => panic!("期望 Mx，得到 {other:?}"),
        }
        let (value, mx, _, _) = record_to_wire(&rec);
        assert_eq!(value, "mail.example.com");
        assert_eq!(mx, Some(10));
        assert!(w.matches_data(&rec));
    }
}
