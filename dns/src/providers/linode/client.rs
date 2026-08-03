//! M9-DNS012: Linode（Akamai）API 客户端（`https://api.linode.com/v4`）
//!
//! - 认证：`Authorization: Bearer {PAT}`（个人访问令牌，需 domains 读写 scope）
//! - 域对象：`GET /domains`（分页 page/page_size）→ 按域名找 id；
//!   域名未加入 Linode 时返回 `NotFound` 并提示先建 Domain（适配层不做注册局业务）
//! - 记录：`GET/POST/PUT/DELETE /domains/{id}/records[/{rid}]`，单条 CRUD；
//!   **PUT 必须携带全部字段**
//! - SRV：`service`/`protocol`/`priority`/`weight`/`port`/`target` 结构化字段，
//!   `name` 为子域（根为 ""），统一名 `_service._protocol[.子域]` ↔ 拆分为三字段
//! - 相对名：根 → `name=""`（文档以空串示例，不用 "@"）
//! - 分页遍历：`page` 从 1 起循环至 `pages`（单页上限 500）

use super::error;
use super::{from_linode_name, split_srv_name, to_linode_name};
use crate::provider::{ProviderError, Record, RecordData, RecordType};
use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

/// 分页大小（Linode 单页上限 500）。
const PAGE_SIZE: u32 = 500;

/// `GET /domains` 列表元素（只需 id/domain/type 三个字段）。
#[derive(Debug, Deserialize)]
pub(crate) struct LinodeDomain {
    pub(crate) id: u64,
    pub(crate) domain: String,
    #[serde(default)]
    pub(crate) r#type: String,
}

/// `GET /domains/{id}/records` 列表元素。
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LinodeRecord {
    pub(crate) id: u64,
    #[serde(rename = "type")]
    pub(crate) rtype: String,
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) priority: i32,
    #[serde(default)]
    pub(crate) weight: i32,
    #[serde(default)]
    pub(crate) port: i32,
    #[serde(default)]
    pub(crate) service: Option<String>,
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    #[serde(default, rename = "ttl_sec")]
    pub(crate) ttl_sec: u32,
}

/// POST/PUT 记录请求体（PUT 必须携带全部字段；priority/weight/port 恒携带，
/// service/protocol 仅 SRV 携带）。
#[derive(Debug, Serialize)]
pub(crate) struct LinodeRecordBody {
    #[serde(rename = "type")]
    rtype: &'static str,
    name: String,
    target: String,
    #[serde(rename = "ttl_sec")]
    ttl_sec: u32,
    priority: i32,
    weight: i32,
    port: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
}

impl LinodeRecordBody {
    /// 统一 [`Record`] → Linode 请求体。
    fn from_record(rec: &Record) -> Result<Self, ProviderError> {
        let (target, priority, weight, port, service, protocol, name) = match &rec.data {
            RecordData::Plain(v) => (
                v.clone(),
                0,
                0,
                0,
                None,
                None,
                to_linode_name(&rec.name),
            ),
            RecordData::Mx { priority, exchange } => (
                exchange.clone(),
                *priority as i32,
                0,
                0,
                None,
                None,
                to_linode_name(&rec.name),
            ),
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                // 统一名 `_service._protocol[.子域]` → 拆分为 service/protocol/子域。
                let (service, protocol, sub) = split_srv_name(&rec.name).ok_or_else(|| {
                    ProviderError::InvalidParameter {
                        detail: format!(
                            "SRV 名称必须为 _service._protocol[.子域] 形式（当前: {}）",
                            rec.name
                        ),
                    }
                })?;
                // Linode 的 target 不带结尾点；去掉统一模型可能携带的结尾点。
                let target = target.strip_suffix('.').unwrap_or(target).to_string();
                (
                    target,
                    *priority as i32,
                    *weight as i32,
                    *port as i32,
                    Some(service),
                    Some(protocol),
                    sub,
                )
            }
        };
        Ok(Self {
            rtype: rec.rtype.as_str(),
            name,
            target,
            ttl_sec: rec.ttl,
            priority,
            weight,
            port,
            service,
            protocol,
        })
    }
}

/// Linode 记录 → 统一 [`Record`]；未知类型（CAA/PTR 等）返回 `None` 跳过。
pub(crate) fn to_record(lr: &LinodeRecord) -> Option<Record> {
    let rtype = RecordType::from_str(&lr.rtype).ok()?;
    let name = match rtype {
        RecordType::SRV => {
            let service = lr.service.as_deref().unwrap_or("");
            let protocol = lr.protocol.as_deref().unwrap_or("");
            if service.is_empty() || protocol.is_empty() {
                return None;
            }
            let sub = from_linode_name(&lr.name);
            if sub.is_empty() {
                format!("{service}.{protocol}")
            } else {
                format!("{service}.{protocol}.{sub}")
            }
        }
        _ => from_linode_name(&lr.name),
    };
    let data = match rtype {
        RecordType::A
        | RecordType::AAAA
        | RecordType::CNAME
        | RecordType::TXT
        | RecordType::NS => RecordData::Plain(lr.target.clone()),
        RecordType::MX => RecordData::Mx {
            priority: lr.priority.max(0) as u16,
            exchange: lr.target.clone(),
        },
        RecordType::SRV => RecordData::Srv {
            priority: lr.priority.max(0) as u16,
            weight: lr.weight.max(0) as u16,
            port: lr.port.max(0) as u16,
            target: lr.target.clone(),
        },
    };
    Some(Record {
        name,
        rtype,
        ttl: lr.ttl_sec,
        data,
    })
}

/// Linode API 客户端（`Debug` 输出不打印 token，凭据不落日志）。
pub(crate) struct LinodeClient {
    client: reqwest::Client,
    base_url: String,
}

impl fmt::Debug for LinodeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinodeClient")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl LinodeClient {
    /// 构建客户端：30s 超时、UA `KirinDesk/0.1.0`、Bearer 认证头。
    pub(crate) fn new(token: impl Into<String>, base_url: &str) -> Self {
        let token = token.into();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("KirinDesk/0.1.0")
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {token}")).unwrap_or_else(|_| {
                        HeaderValue::from_static("Bearer")
                    }),
                );
                headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
                headers
            })
            .build()
            .expect("构建 Linode reqwest 客户端失败");
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// 测试连接：最小查询（域名列表取 1 条）。
    pub(crate) async fn test_connection(&self) -> Result<(), ProviderError> {
        let url = format!("{}/domains?page_size=1", self.base_url);
        let resp = self.client.get(&url).send().await?;
        let _ = error::ensure_success(resp).await?;
        Ok(())
    }

    /// 分页遍历 `GET /domains`，返回全部域名（仅 type=master 的域）。
    pub(crate) async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        loop {
            let url = format!(
                "{}/domains?page={page}&page_size={PAGE_SIZE}",
                self.base_url
            );
            let resp = self.client.get(&url).send().await?;
            let json = error::ensure_success(resp).await?;
            let pages = json["pages"].as_u64().unwrap_or(1) as u32;
            let data: Vec<LinodeDomain> = serde_json::from_value(json["data"].clone())?;
            out.extend(
                data.into_iter()
                    .filter(|d| d.r#type == "master")
                    .map(|d| d.domain),
            );
            if page >= pages {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    /// 按域名找 Domain id；未添加到 Linode → `NotFound` 并提示先建 Domain 对象。
    pub(crate) async fn find_domain_id(&self, domain: &str) -> Result<u64, ProviderError> {
        let mut page: u32 = 1;
        loop {
            let url = format!(
                "{}/domains?page={page}&page_size={PAGE_SIZE}",
                self.base_url
            );
            let resp = self.client.get(&url).send().await?;
            let json = error::ensure_success(resp).await?;
            let pages = json["pages"].as_u64().unwrap_or(1) as u32;
            let data: Vec<LinodeDomain> = serde_json::from_value(json["data"].clone())?;
            if let Some(d) = data.into_iter().find(|d| d.domain == domain) {
                return Ok(d.id);
            }
            if page >= pages {
                break;
            }
            page += 1;
        }
        Err(ProviderError::NotFound {
            what: format!(
                "域名 {domain} 未在 Linode 添加 Domain 对象，请先在 DNS Manager 创建该 \
                 Domain 后再操作（适配层不做注册局业务）"
            ),
        })
    }

    /// 分页遍历 `GET /domains/{id}/records`。
    pub(crate) async fn list_records(
        &self,
        domain_id: u64,
    ) -> Result<Vec<LinodeRecord>, ProviderError> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        loop {
            let url = format!(
                "{}/domains/{domain_id}/records?page={page}&page_size={PAGE_SIZE}",
                self.base_url
            );
            let resp = self.client.get(&url).send().await?;
            let json = error::ensure_success(resp).await?;
            let pages = json["pages"].as_u64().unwrap_or(1) as u32;
            let data: Vec<LinodeRecord> = serde_json::from_value(json["data"].clone())?;
            out.extend(data);
            if page >= pages {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    /// 查询记录：`name`/`rtype` 过滤（统一名比对，SRV 已重组）。
    pub(crate) async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let id = self.find_domain_id(domain).await?;
        let mut out = Vec::new();
        for lr in self.list_records(id).await? {
            if let Some(rec) = to_record(&lr) {
                if name.map(|n| n == rec.name).unwrap_or(true)
                    && rtype.map(|t| t == rec.rtype).unwrap_or(true)
                {
                    out.push(rec);
                }
            }
        }
        Ok(out)
    }

    /// 按 (统一名, rtype) 找已存在的 Linode 记录（幂等 upsert 定位用）。
    async fn find_matching(
        &self,
        domain_id: u64,
        rec: &Record,
    ) -> Result<Vec<LinodeRecord>, ProviderError> {
        let all = self.list_records(domain_id).await?;
        Ok(all
            .into_iter()
            .filter(|lr| {
                lr.rtype == rec.rtype.as_str()
                    && to_record(lr).map(|r| r.name == rec.name).unwrap_or(false)
            })
            .collect())
    }

    /// 幂等 upsert：先查 (name, rtype) → 存在则 PUT（全字段）→ 不存在则 POST。
    pub(crate) async fn upsert_record(
        &self,
        domain: &str,
        rec: &Record,
    ) -> Result<(), ProviderError> {
        let id = self.find_domain_id(domain).await?;
        let body = LinodeRecordBody::from_record(rec)?;
        let existing = self.find_matching(id, rec).await?;
        if let Some(first) = existing.first() {
            let url = format!(
                "{}/domains/{id}/records/{}",
                self.base_url, first.id
            );
            let resp = self.client.put(&url).json(&body).send().await?;
            error::ensure_success(resp).await?;
        } else {
            let url = format!("{}/domains/{id}/records", self.base_url);
            let resp = self.client.post(&url).json(&body).send().await?;
            error::ensure_success(resp).await?;
        }
        Ok(())
    }

    /// 删除该 (name, rtype) 下全部记录（统一语义）；无匹配 → `NotFound`。
    pub(crate) async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let id = self.find_domain_id(domain).await?;
        let all = self.list_records(id).await?;
        let matched: Vec<u64> = all
            .into_iter()
            .filter_map(|lr| {
                if lr.rtype == rtype.as_str() {
                    match to_record(&lr) {
                        Some(r) if r.name == name => Some(lr.id),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .collect();
        if matched.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        for rid in matched {
            let url = format!("{}/domains/{id}/records/{rid}", self.base_url);
            let resp = self.client.delete(&url).send().await?;
            error::ensure_success(resp).await?;
        }
        Ok(())
    }
}
