//! M9-DNS014: OVH 服务商适配（`M9-DNS014_OVH适配.md`）
//!
//! - 端点：`https://api.ovh.com/1.0`
//! - 认证：三要素（app_key / app_secret / consumer_key）+ 每请求签名
//!   `$1$` + SHA1(AS+CK+METHOD+URL+BODY+TIMESTAMP)（官方格式，见 sign.rs）；
//!   时钟偏差 → `/auth/time` 校准后自动重试一次
//! - 写入语义：单条 CRUD（POST 创建 / PUT 更新 / DELETE 删除，按 id）；
//!   **每次写操作后自动调用 `POST /domain/zone/{zone}/refresh` 才生效**
//! - 记录名：相对名（subDomain 空 = 根）
//! - SRV / MX：经通用 record 端点，`target` 为官方单字符串
//!   （SRV：`"0 1 3389 tgt."`；MX：`"10 mail.example.com."`——
//!   DNSControl OVH provider 生产验证的同款格式）
//! - TTL：支持（官方默认 3600；读取侧 0 → 3600 归一化）
//! - 能力全开

pub mod client;
pub mod error;
pub mod sign;

#[cfg(test)]
mod tests;

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordData, RecordType,
};
use client::{OvhClient, OvhRecord, PROD_BASE_URL, TTL_DEFAULT};
use std::str::FromStr;

/// 注册 OVH 服务商（工厂从凭据构建；凭据不落日志）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register("ovh", |cred| -> Box<dyn Provider> {
        match cred {
            Credential::Ovh {
                app_key,
                app_secret,
                consumer_key,
            } => Box::new(OvhProvider::new(
                app_key.clone(),
                app_secret.clone(),
                consumer_key.clone(),
            )),
            other => Box::new(CredentialMismatchProvider::new("ovh", other)),
        }
    });
}

/// 凭据类型不匹配时的兜底 Provider：所有方法返回明确错误（工厂无法返回 Result）。
struct CredentialMismatchProvider {
    name: &'static str,
    actual: String,
}

impl CredentialMismatchProvider {
    fn new(name: &'static str, actual: &Credential) -> Self {
        // 只取 provider 标签（serde 内部形态），不打印任何凭据字段。
        let tag = serde_json::to_value(actual)
            .ok()
            .and_then(|v| v.get("provider").and_then(|p| p.as_str()).map(String::from))
            .unwrap_or_else(|| "未知".to_string());
        Self {
            name,
            actual: tag,
        }
    }

    fn err(&self) -> ProviderError {
        ProviderError::Other(format!(
            "服务商「{}」收到不匹配的凭据类型「{}」，请检查 [dns.providers.{}] 配置",
            self.name, self.actual, self.name
        ))
    }
}

#[async_trait::async_trait]
impl Provider for CredentialMismatchProvider {
    fn name(&self) -> &'static str {
        self.name
    }
    async fn test_connection(&self) -> Result<(), ProviderError> {
        Err(self.err())
    }
    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        Err(self.err())
    }
    async fn query_records(
        &self,
        _domain: &str,
        _name: Option<&str>,
        _rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        Err(self.err())
    }
    async fn upsert_record(&self, _domain: &str, _rec: &Record) -> Result<(), ProviderError> {
        Err(self.err())
    }
    async fn delete_record(
        &self,
        _domain: &str,
        _name: &str,
        _rtype: RecordType,
    ) -> Result<(), ProviderError> {
        Err(self.err())
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

/// OVH Provider 实现。
pub(crate) struct OvhProvider {
    client: OvhClient,
    caps: ProviderCapabilities,
}

impl OvhProvider {
    /// 生产构造（固定官方端点）。
    pub(crate) fn new(app_key: String, app_secret: String, consumer_key: String) -> Self {
        Self::from_client(OvhClient::new(
            app_key,
            app_secret,
            consumer_key,
            PROD_BASE_URL.to_string(),
        ))
    }

    /// 测试构造：base_url 指向 127.0.0.1 mock（见 tests.rs）。
    #[cfg(test)]
    pub(crate) fn new_at(
        app_key: String,
        app_secret: String,
        consumer_key: String,
        base_url: String,
    ) -> Self {
        Self::from_client(OvhClient::new(app_key, app_secret, consumer_key, base_url))
    }

    fn from_client(client: OvhClient) -> Self {
        Self {
            client,
            caps: ProviderCapabilities::all(),
        }
    }

    /// 查询 (subDomain, fieldType) 的现有记录详情（两段式：id 列表 → 详情）。
    async fn find_existing(
        &self,
        zone: &str,
        field_type: &str,
        sub_domain: &str,
    ) -> Result<Vec<OvhRecord>, ProviderError> {
        let ids = self
            .client
            .list_record_ids(zone, Some(field_type), None)
            .await?;
        let mut out = Vec::new();
        for id in ids {
            let detail = self.client.get_record(zone, id).await?;
            if detail.sub_domain == sub_domain {
                out.push(detail);
            }
        }
        Ok(out)
    }
}

#[async_trait::async_trait]
impl Provider for OvhProvider {
    fn name(&self) -> &'static str {
        "ovh"
    }

    /// 最小查询：GET /domain/zone（DNS-MNT-003 测试连接载体）。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.list_zones().await.map(|_| ())
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.client.list_zones().await
    }

    /// 查询：按 fieldType 取 id 列表 → 逐条详情 → 过滤 subDomain/类型。
    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let field = rtype.map(|t| t.as_str().to_string());
        let ids = self
            .client
            .list_record_ids(domain, field.as_deref(), None)
            .await?;
        let mut out = Vec::new();
        for id in ids {
            let detail = self.client.get_record(domain, id).await?;
            if let Some(rec) = ovh_to_record(&detail)? {
                out.push(rec);
            }
        }
        Ok(filter_and_sort(out, name, rtype))
    }

    /// 幂等写入：按 (subDomain, fieldType) 定位——存在 → PUT 首条；不存在 → POST；
    /// 写后自动 refresh（OVH 要求才生效）。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let target = record_to_ovh(rec)?;
        let existing = self
            .find_existing(domain, &target.field_type, &target.sub_domain)
            .await?;
        if let Some(first) = existing.first() {
            let mut upd = target.clone();
            upd.id = first.id;
            self.client.update_record(domain, &upd).await?;
        } else {
            self.client.create_record(domain, &target).await?;
        }
        self.client.refresh(domain).await
    }

    /// 删除（统一语义：删除该 name+rtype 下全部记录）；写后自动 refresh。
    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let existing = self.find_existing(domain, rtype.as_str(), name).await?;
        if existing.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        for rec in &existing {
            self.client.delete_record(domain, rec.id).await?;
        }
        self.client.refresh(domain).await
    }

    fn capabilities(&self) -> ProviderCapabilities {
        self.caps.clone()
    }
}

// ────────────────────────────────────────────────────────────────
// Record ↔ OVH 模型互转
// ────────────────────────────────────────────────────────────────

/// OVH 记录 → 统一 Record；未知类型返回 None（查询时跳过）。
fn ovh_to_record(r: &OvhRecord) -> Result<Option<Record>, ProviderError> {
    let rtype = match RecordType::from_str(&r.field_type) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let data = match rtype {
        RecordType::SRV => parse_combined_srv(&r.target)?,
        RecordType::MX => parse_combined_mx(&r.target)?,
        _ => RecordData::Plain(r.target.clone()),
    };
    Ok(Some(Record {
        name: r.sub_domain.clone(), // 相对名；空 = 根
        rtype,
        ttl: if r.ttl == 0 { TTL_DEFAULT } else { r.ttl },
        data,
    }))
}

/// 统一 Record → OVH 记录（写入用；sub_domain 空 = 根）。
fn record_to_ovh(rec: &Record) -> Result<OvhRecord, ProviderError> {
    let target = match &rec.data {
        RecordData::Plain(v) => v.clone(),
        RecordData::Mx {
            priority,
            exchange,
        } => format!("{priority} {exchange}"),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
    };
    Ok(OvhRecord {
        id: 0,
        zone: String::new(),
        field_type: rec.rtype.as_str().to_string(),
        sub_domain: rec.name.clone(),
        target,
        // 0 = 使用服务商默认（显式写 3600，避免省略字段导致 OVH 重置 TTL 的歧义）。
        ttl: if rec.ttl == 0 { TTL_DEFAULT } else { rec.ttl },
    })
}

/// SRV target 单字符串（官方格式 "0 1 3389 tgt."）→ 结构化。
fn parse_combined_srv(target: &str) -> Result<RecordData, ProviderError> {
    let tokens: Vec<&str> = target.split_whitespace().collect();
    if tokens.len() != 4 {
        return Err(ProviderError::Other(format!(
            "OVH SRV target 需 4 段（priority weight port target）: {target}"
        )));
    }
    Ok(RecordData::Srv {
        priority: parse_u16(tokens[0], "priority")?,
        weight: parse_u16(tokens[1], "weight")?,
        port: parse_u16(tokens[2], "port")?,
        target: tokens[3].to_string(),
    })
}

/// MX target 单字符串（官方格式 "10 mail.example.com."）→ 结构化。
fn parse_combined_mx(target: &str) -> Result<RecordData, ProviderError> {
    let tokens: Vec<&str> = target.splitn(2, ' ').collect();
    if tokens.len() != 2 {
        return Err(ProviderError::Other(format!(
            "OVH MX target 需 2 段（priority exchange）: {target}"
        )));
    }
    Ok(RecordData::Mx {
        priority: parse_u16(tokens[0], "priority")?,
        exchange: tokens[1].to_string(),
    })
}

fn parse_u16(s: &str, what: &str) -> Result<u16, ProviderError> {
    s.trim().parse().map_err(|_| {
        ProviderError::Other(format!("OVH {what} 非法: {s}"))
    })
}

/// 按 name（相对名）与 rtype 过滤并排序（与 mock 一致的稳定输出）。
fn filter_and_sort(
    records: Vec<Record>,
    name: Option<&str>,
    rtype: Option<RecordType>,
) -> Vec<Record> {
    let mut out: Vec<Record> = records
        .into_iter()
        .filter(|r| name.map(|n| r.name == n).unwrap_or(true))
        .filter(|r| rtype.map(|t| r.rtype == t).unwrap_or(true))
        .collect();
    out.sort_by(|a, b| {
        (a.rtype, &a.name, a.data.to_display_string()).cmp(&(b.rtype, &b.name, b.data.to_display_string()))
    });
    out
}
