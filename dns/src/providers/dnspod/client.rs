//! M9-DNS004: 腾讯云 DNSPod HTTP 客户端（TC3 签名 + 记录模型互转）
//!
//! 接口（官方 `https://cloud.tencent.com/document/api/1427`，Version 2021-03-23，
//! 域名 `dnspod.tencentcloudapi.com`，POST JSON）：
//! - `DescribeDomainList`（Offset/Limit）→ 域名列表；
//! - `DescribeRecordList`（Domain + 可选 Subdomain/RecordType/Offset/Limit）→ 记录列表；
//! - `CreateRecord` / `ModifyRecord`（单条 CRUD，RecordLine="默认"）；
//! - `DeleteRecord`（按 RecordId）。
//!
//! 差异点消化：
//! - 记录名：统一相对名（"" = 根）↔ DNSPod `@`；
//! - MX：`MX` 字段承载优先级，`Value` 承载 exchange；
//! - SRV：`Value` 单串 `"{priority} {weight} {port} {target}"`（target 不带尾点，
//!   DNSPod 侧自动补点；读取时剥点还原）；
//! - CNAME/NS：写/读均剥尾点（DNSPod 展示形态）；
//! - upsert：查同 name+type（默认线路）→ 同数据仅更新 TTL / 异数据修改首条 /
//!   无则创建——幂等；
//! - delete：删除该 name+type 下全部记录（任何线路）。
//!
//! 凭据（`Credential::Dnspod`）不参与任何日志/Display 输出。

use super::error;
use super::sign;
use crate::provider::{ProviderError, Record, RecordData, RecordType};
use serde_json::{json, Value};
use std::str::FromStr;
use std::time::Duration;

/// 生产端点（`host` 参与 TC3 签名，必须与请求一致）。
pub const DEFAULT_ENDPOINT: &str = "https://dnspod.tencentcloudapi.com";
/// DNSPod 线路名（CreateRecord/ModifyRecord 必填；本适配统一管理默认线路）。
pub(crate) const DEFAULT_LINE: &str = "默认";
/// 记录默认 TTL（秒；`Record.ttl == 0` 时使用）。
const DEFAULT_TTL: u32 = 600;
/// 分页大小（DescribeRecordList 单页上限 3000）。
const PAGE_SIZE: u32 = 300;

/// DNSPod 单条记录（wire 形态，`@` 已转为相对名）。
#[derive(Debug, Clone)]
pub(crate) struct WireRecord {
    pub id: u64,
    pub name: String,
    pub rtype: RecordType,
    pub value: String,
    pub mx: u32,
    pub ttl: u32,
    pub line: String,
}

/// TC3 签名的 DNSPod 客户端。
#[derive(Debug, Clone)]
pub struct DnspodClient {
    http: reqwest::Client,
    endpoint: String,
    secret_id: String,
    secret_key: String,
}

impl DnspodClient {
    /// 构建客户端（30s 超时、User-Agent "KirinDesk/0.1.0"）。
    pub fn new(secret_id: String, secret_key: String, endpoint: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("构建 reqwest Client 失败");
        Self {
            http,
            endpoint,
            secret_id,
            secret_key,
        }
    }

    /// 测试连接：域名列表取 1 条。
    pub async fn test_connection(&self) -> Result<(), ProviderError> {
        self.list_domains_page(0, 1).await.map(|_| ())
    }

    /// 全部域名（分页拉取）。
    pub async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let mut out = Vec::new();
        let mut offset = 0u32;
        loop {
            let (page, total) = self.list_domains_page(offset, PAGE_SIZE).await?;
            let n = page.len();
            out.extend(page);
            if out.len() as u32 >= total || n < PAGE_SIZE as usize {
                break;
            }
            offset += PAGE_SIZE;
        }
        Ok(out)
    }

    /// 单页域名列表：返回 (域名列表, TotalCount)。
    pub(crate) async fn list_domains_page(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<(Vec<String>, u32), ProviderError> {
        let v = self
            .call("DescribeDomainList", json!({ "Offset": offset, "Limit": limit }))
            .await?;
        let domains = v
            .pointer("/Response/DomainList")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| d.get("Name").and_then(|n| n.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let total = v
            .pointer("/Response/TotalCount")
            .and_then(|t| t.as_u64())
            .unwrap_or(0) as u32;
        Ok((domains, total))
    }

    /// 查询记录（wire 形态；name/rtype 服务端过滤 + 本地兜底过滤，分页拉全）。
    pub(crate) async fn list_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<WireRecord>, ProviderError> {
        let mut out = Vec::new();
        let mut offset = 0u32;
        loop {
            let mut params = json!({ "Domain": domain, "Offset": offset, "Limit": PAGE_SIZE });
            if let Some(n) = name {
                params["Subdomain"] = json!(wire_name(n));
            }
            if let Some(t) = rtype {
                params["RecordType"] = json!(t.as_str());
            }
            let v = self.call("DescribeRecordList", params).await?;
            let page: Vec<WireRecord> = v
                .pointer("/Response/RecordList")
                .and_then(|a| a.as_array())
                .map(|arr| arr.iter().filter_map(parse_wire_record).collect())
                .unwrap_or_default();
            let n = page.len();
            let total = v
                .pointer("/Response/TotalCount")
                .and_then(|t| t.as_u64())
                .unwrap_or(0) as usize;
            out.extend(page);
            if out.len() >= total || n < PAGE_SIZE as usize {
                break;
            }
            offset += PAGE_SIZE;
        }
        Ok(out)
    }

    /// 统一查询：name=None 全表；rtype=None 全部类型（本地过滤兜底）。
    pub async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let mut wire = self.list_records(domain, name, rtype).await?;
        if let Some(n) = name {
            wire.retain(|r| r.name == n);
        }
        if let Some(t) = rtype {
            wire.retain(|r| r.rtype == t);
        }
        Ok(wire.iter().filter_map(wire_to_record).collect())
    }

    /// 幂等 upsert：查同 name+type（默认线路）→ 同数据仅更新 TTL / 异数据修改
    /// 首条 / 无则创建。
    pub async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let existing = self.list_records(domain, Some(&rec.name), Some(rec.rtype)).await?;
        let ttl = if rec.ttl == 0 { DEFAULT_TTL } else { rec.ttl };
        let (value, mx) = record_to_wire(rec);

        // 默认线路上的记录（本适配只管理默认线路；其他线路原样保留）。
        let mut on_default = existing.iter().filter(|r| r.line == DEFAULT_LINE);
        if let Some(same) = on_default.clone().find(|r| r.matches_data(rec)) {
            // 幂等：数据一致 → 仅 TTL 不一致才发起修改（更新 TTL）。
            if same.ttl != ttl {
                self.modify_record(
                    domain,
                    same.id,
                    &rec.name,
                    rec.rtype,
                    &value,
                    mx,
                    ttl,
                )
                .await?;
            }
            return Ok(());
        }
        if let Some(first) = on_default.next() {
            // 存在同 name+type 但数据不同 → 修改第一条。
            self.modify_record(domain, first.id, &rec.name, rec.rtype, &value, mx, ttl)
                .await?;
            return Ok(());
        }
        // 不存在 → 创建。
        // MX 优先级仅 MX 记录需要（DNSPod 对非 MX 记录传 MX 可能报参数错误）。
        let mut params = json!({
            "Domain": domain,
            "SubDomain": wire_name(&rec.name),
            "RecordType": rec.rtype.as_str(),
            "RecordLine": DEFAULT_LINE,
            "Value": value,
            "TTL": ttl,
        });
        if let Some(mx) = mx {
            params["MX"] = json!(mx);
        }
        self.call("CreateRecord", params).await?;
        Ok(())
    }

    /// 删除该 name+type 下全部记录（任何线路）；无记录 → NotFound。
    pub async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let existing = self.list_records(domain, Some(name), Some(rtype)).await?;
        if existing.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {}.{domain}", wire_name(name)),
            });
        }
        for r in &existing {
            self.call("DeleteRecord", json!({ "Domain": domain, "RecordId": r.id }))
                .await?;
        }
        Ok(())
    }

    /// ModifyRecord（内部：upsert 的更新路径）。
    async fn modify_record(
        &self,
        domain: &str,
        record_id: u64,
        name: &str,
        rtype: RecordType,
        value: &str,
        mx: Option<u32>,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        let mut params = json!({
            "Domain": domain,
            "RecordId": record_id,
            "SubDomain": wire_name(name),
            "RecordType": rtype.as_str(),
            "RecordLine": DEFAULT_LINE,
            "Value": value,
            "TTL": ttl,
        });
        // MX 优先级仅 MX 记录需要。
        if let Some(mx) = mx {
            params["MX"] = json!(mx);
        }
        self.call("ModifyRecord", params).await?;
        Ok(())
    }

    /// 执行一次 TC3 签名的 POST JSON 请求：成功返回响应 JSON（已剥离错误信封）。
    ///
    /// 凭据不参与日志；错误统一经 [`error::map_error`] 映射。
    async fn call(&self, action: &str, params: Value) -> Result<Value, ProviderError> {
        let body = serde_json::to_string(&params)?; // 签名与发送使用同一字节串
        let timestamp = chrono::Utc::now().timestamp();
        let host = host_of(&self.endpoint);
        let authorization = sign::tc3_authorization(
            &self.secret_id,
            &self.secret_key,
            sign::SERVICE,
            &host,
            action,
            timestamp,
            &body,
        );

        let resp = self
            .http
            .post(format!("{}/", self.endpoint))
            .header("X-TC-Action", action)
            .header("X-TC-Version", sign::VERSION)
            .header("X-TC-Timestamp", timestamp)
            .header("X-TC-Nonce", rand::random::<u32>())
            .header("Content-Type", sign::CONTENT_TYPE)
            .header("Authorization", authorization)
            .body(body)
            .send()
            .await?;

        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let text = resp.text().await?;

        // 非 2xx 或 body 带 Error 信封 → 统一错误映射。
        if !(200..300).contains(&status) {
            return Err(error::map_error(status, &text, retry_after));
        }
        let v: Value = serde_json::from_str(&text)?;
        if v.pointer("/Response/Error").is_some() {
            return Err(error::map_error(status, &text, retry_after));
        }
        Ok(v)
    }
}

// ── 记录模型互转（统一模型 ↔ DNSPod wire）──

/// 相对名 → DNSPod 名（"" = 根 → "@"）。
fn wire_name(name: &str) -> String {
    if name.is_empty() {
        "@".to_string()
    } else {
        name.to_string()
    }
}

/// DNSPod 名 → 相对名（"@" → ""）。
fn rel_name(name: &str) -> String {
    if name == "@" {
        String::new()
    } else {
        name.to_string()
    }
}

/// 剥尾点（CNAME/NS/MX exchange/SRV target 的规范化）。
fn strip_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// 统一 Record → wire (value, mx)：
/// - Plain（A/AAAA/TXT/NS/CNAME）：原值；CNAME/NS 剥尾点；
/// - Mx：Value=exchange（剥尾点），MX=priority；
/// - Srv：Value="{priority} {weight} {port} {target}"（target 剥尾点）。
fn record_to_wire(rec: &Record) -> (String, Option<u32>) {
    match &rec.data {
        RecordData::Plain(v) => (normalize_target(rec.rtype, v), None),
        RecordData::Mx { priority, exchange } => {
            (strip_dot(exchange).to_string(), Some(*priority as u32))
        }
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => (
            format!("{priority} {weight} {port} {}", strip_dot(target)),
            None,
        ),
    }
}

/// CNAME/NS 记录值剥尾点（DNSPod 展示形态），其余类型原样。
fn normalize_target(rtype: RecordType, value: &str) -> String {
    match rtype {
        RecordType::CNAME | RecordType::NS => strip_dot(value).to_string(),
        _ => value.to_string(),
    }
}

/// wire 记录 → 统一 Record：
/// - MX → Mx{priority: MX, exchange: Value}（剥尾点）；
/// - SRV → 解析 "p w port target" → Srv；解析失败降级为 Plain；
/// - 其余 → Plain（CNAME/NS 剥尾点）。
fn wire_to_record(w: &WireRecord) -> Option<Record> {
    let data = match w.rtype {
        RecordType::MX => RecordData::Mx {
            priority: w.mx as u16,
            exchange: strip_dot(&w.value).to_string(),
        },
        RecordType::SRV => parse_srv(&w.value).unwrap_or(RecordData::Plain(w.value.clone())),
        RecordType::A | RecordType::AAAA | RecordType::TXT => {
            RecordData::Plain(w.value.clone())
        }
        RecordType::CNAME | RecordType::NS => {
            RecordData::Plain(strip_dot(&w.value).to_string())
        }
    };
    Some(Record {
        name: w.name.clone(),
        rtype: w.rtype,
        ttl: w.ttl,
        data,
    })
}

/// 解析 DNSPod SRV 值 "{priority} {weight} {port} {target}"（4 段空格分隔）。
fn parse_srv(value: &str) -> Option<RecordData> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 4 {
        return None;
    }
    Some(RecordData::Srv {
        priority: parts[0].parse().ok()?,
        weight: parts[1].parse().ok()?,
        port: parts[2].parse().ok()?,
        target: strip_dot(parts[3]).to_string(),
    })
}

/// DescribeRecordList 响应条目 → WireRecord。
fn parse_wire_record(v: &Value) -> Option<WireRecord> {
    let rtype = RecordType::from_str(v.get("Type")?.as_str()?).ok()?;
    Some(WireRecord {
        id: v.get("RecordId")?.as_u64()?,
        name: rel_name(v.get("Name").and_then(|x| x.as_str()).unwrap_or("")),
        rtype,
        value: v.get("Value").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        mx: v.get("MX").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        ttl: v.get("TTL").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        line: v
            .get("Line")
            .and_then(|x| x.as_str())
            .unwrap_or(DEFAULT_LINE)
            .to_string(),
    })
}

/// wire 记录是否与统一记录数据一致（幂等判断）。
///
/// DNSPod 会对 CNAME/NS/MX exchange/SRV target 自动补尾点，比对时两侧
/// 都剥尾点（CNAME/NS 值在写/读两侧也做同样规范化）。
impl WireRecord {
    fn matches_data(&self, rec: &Record) -> bool {
        match &rec.data {
            RecordData::Plain(v) => {
                let v = normalize_target(rec.rtype, v);
                let w = match rec.rtype {
                    RecordType::CNAME | RecordType::NS => strip_dot(&self.value).to_string(),
                    _ => self.value.clone(),
                };
                w == v && self.mx == 0
            }
            RecordData::Mx { priority, exchange } => {
                self.mx == *priority as u32 && strip_dot(&self.value) == strip_dot(exchange)
            }
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                strip_dot(&self.value)
                    == format!("{priority} {weight} {port} {}", strip_dot(target))
            }
        }
    }
}

/// endpoint → Host 头值（含端口；与 TC3 签名 canonical host 一致）。
fn host_of(endpoint: &str) -> String {
    let url = reqwest::Url::parse(endpoint).expect("endpoint 必须是合法 URL");
    let host = url.host_str().expect("endpoint 必须含主机名");
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_with_and_without_port() {
        assert_eq!(host_of("https://dnspod.tencentcloudapi.com"), "dnspod.tencentcloudapi.com");
        assert_eq!(host_of("http://127.0.0.1:54321"), "127.0.0.1:54321");
    }

    #[test]
    fn name_conversion_root() {
        assert_eq!(wire_name(""), "@");
        assert_eq!(wire_name("www"), "www");
        assert_eq!(rel_name("@"), "");
        assert_eq!(rel_name("www"), "www");
    }

    #[test]
    fn srv_wire_roundtrip() {
        let w = WireRecord {
            id: 1,
            name: "_remote._tcp.my-pc".into(),
            rtype: RecordType::SRV,
            value: "0 5 3389 pc.example.com.".into(),
            mx: 0,
            ttl: 600,
            line: DEFAULT_LINE.into(),
        };
        let rec = wire_to_record(&w).unwrap();
        match &rec.data {
            RecordData::Srv { priority, weight, port, target } => {
                assert_eq!((*priority, *weight, *port), (0, 5, 3389));
                assert_eq!(target, "pc.example.com");
            }
            other => panic!("期望 Srv，得到 {other:?}"),
        }
        // 回写 → 同串（幂等判定成立）。
        let (value, _mx) = record_to_wire(&rec);
        assert_eq!(value, "0 5 3389 pc.example.com");
        assert!(w.matches_data(&rec));
    }

    #[test]
    fn mx_wire_roundtrip() {
        let w = WireRecord {
            id: 2,
            name: "".into(),
            rtype: RecordType::MX,
            value: "mail.example.com.".into(),
            mx: 10,
            ttl: 600,
            line: DEFAULT_LINE.into(),
        };
        let rec = wire_to_record(&w).unwrap();
        match &rec.data {
            RecordData::Mx { priority, exchange } => {
                assert_eq!(*priority, 10);
                assert_eq!(exchange, "mail.example.com");
            }
            other => panic!("期望 Mx，得到 {other:?}"),
        }
        let (value, mx) = record_to_wire(&rec);
        assert_eq!(value, "mail.example.com");
        assert_eq!(mx, Some(10));
        assert!(w.matches_data(&rec));
    }
}
