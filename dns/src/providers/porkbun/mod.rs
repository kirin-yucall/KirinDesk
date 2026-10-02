//! M9-DNS015: Porkbun 服务商适配（`M9-DNS015_Porkbun适配.md`）
//!
//! - 端点：`https://api.porkbun.com/api/json/v3`（全部 POST，凭据在 body）
//! - 认证：每请求 body 携带 `apikey` + `secretapikey`
//! - 写入语义：单条 CRUD——`/dns/create`（POST）/ `/dns/edit/{id}`（POST）/
//!   `/dns/delete/{id}`（POST）；upsert 按 (相对名, 类型) 定位：存在 → edit、
//!   不存在 → create（其余同键记录保留）
//! - 记录名：retrieve 返回 **FQDN** → 适配层转相对名；写入用相对名（根留空）
//! - SRV：官方格式 `content="weight port target"` 单字符串 + `prio`=priority
//!   （WebSearch 复核：kb.porkbun.com 官方文章 + nrdcg/porkbun 官方客户端一致；
//!   读取兼容 4 段 "priority weight port target" 历史写法）
//! - TTL：官方最小 600 秒、默认 600（写入时收敛）
//! - 能力全开

pub mod client;
pub mod error;

#[cfg(test)]
mod tests;

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordData, RecordType,
};
use client::{PorkbunClient, PROD_BASE_URL, TTL_DEFAULT, TTL_MIN};
use std::str::FromStr;

/// 注册 Porkbun 服务商（工厂从凭据构建；凭据不落日志）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register("porkbun", |cred| -> Box<dyn Provider> {
        match cred {
            Credential::Porkbun {
                api_key,
                secret_key,
            } => Box::new(PorkbunProvider::new(
                api_key.clone(),
                secret_key.clone(),
            )),
            other => Box::new(CredentialMismatchProvider::new("porkbun", other)),
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

/// Porkbun Provider 实现。
pub(crate) struct PorkbunProvider {
    client: PorkbunClient,
    caps: ProviderCapabilities,
}

impl PorkbunProvider {
    /// 生产构造（固定官方端点）。
    pub(crate) fn new(api_key: String, secret_key: String) -> Self {
        Self::from_client(PorkbunClient::new(
            api_key,
            secret_key,
            PROD_BASE_URL.to_string(),
        ))
    }

    /// 测试构造：base_url 指向 127.0.0.1 mock（见 tests.rs）。
    #[cfg(test)]
    pub(crate) fn new_at(api_key: String, secret_key: String, base_url: String) -> Self {
        Self::from_client(PorkbunClient::new(api_key, secret_key, base_url))
    }

    fn from_client(client: PorkbunClient) -> Self {
        Self {
            client,
            caps: ProviderCapabilities::all(),
        }
    }
}

#[async_trait::async_trait]
impl Provider for PorkbunProvider {
    fn name(&self) -> &'static str {
        "porkbun"
    }

    /// 最小查询：POST /ping（返回 yourIp 即认证通过）。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.ping().await
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.client.list_domains().await
    }

    /// 查询：retrieve 全量 → FQDN 转相对名 → 过滤。
    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let recs = self.client.retrieve(domain).await?;
        let mut out = Vec::new();
        for r in recs {
            if let Some(rec) = pk_to_record(&r, domain)? {
                out.push(rec);
            }
        }
        Ok(filter_and_sort(out, name, rtype))
    }

    /// 幂等写入：按 (相对名, 类型) 定位——存在 → edit 首条；不存在 → create。
    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let existing = self.client.retrieve(domain).await?;
        let pk = record_to_pk(rec);
        let rel = &rec.name;
        let rtype = rec.rtype;
        match existing.iter().find(|r| {
            !r.id.is_empty()
                && RecordType::from_str(&r.rtype).ok() == Some(rtype)
                && fqdn_to_rel(&r.name, domain) == *rel
        }) {
            Some(found) => self.client.edit(domain, &found.id, &pk).await,
            None => {
                self.client.create(domain, &pk).await?;
                Ok(())
            }
        }
    }

    /// 删除（统一语义：删除该 name+rtype 下全部记录）。
    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let existing = self.client.retrieve(domain).await?;
        let ids: Vec<String> = existing
            .iter()
            .filter(|r| {
                !r.id.is_empty()
                    && RecordType::from_str(&r.rtype).ok() == Some(rtype)
                    && fqdn_to_rel(&r.name, domain) == name
            })
            .map(|r| r.id.clone())
            .collect();
        if ids.is_empty() {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        for id in ids {
            self.client.delete(domain, &id).await?;
        }
        Ok(())
    }

    fn capabilities(&self) -> ProviderCapabilities {
        self.caps.clone()
    }
}

// ────────────────────────────────────────────────────────────────
// 相对名 ↔ FQDN、Record ↔ 厂商模型互转
// ────────────────────────────────────────────────────────────────

/// FQDN → 相对名：去掉 ".{domain}" 后缀；与域名相等为根（""）。
///
/// "www.example.com" → "www"；"_remote._tcp.example.com" → "_remote._tcp"；
/// "example.com" → ""。
fn fqdn_to_rel(fqdn: &str, domain: &str) -> String {
    if fqdn == domain {
        return String::new();
    }
    if let Some(rest) = fqdn.strip_suffix(domain) {
        if let Some(trimmed) = rest.strip_suffix('.') {
            return trimmed.to_string();
        }
    }
    // 异常形态（不以域名结尾）：原样保留，避免丢数据。
    fqdn.to_string()
}

/// Porkbun 记录 → 统一 Record；未知类型返回 None（查询时跳过）。
fn pk_to_record(r: &client::PkRecord, domain: &str) -> Result<Option<Record>, ProviderError> {
    let rtype = match RecordType::from_str(&r.rtype) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let data = match rtype {
        RecordType::MX => RecordData::Mx {
            priority: parse_u16(&r.prio, "MX priority")?,
            exchange: r.content.clone(),
        },
        RecordType::SRV => parse_srv_content(&r.content, &r.prio)?,
        _ => RecordData::Plain(r.content.clone()),
    };
    Ok(Some(Record {
        name: fqdn_to_rel(&r.name, domain),
        rtype,
        ttl: parse_ttl(&r.ttl),
        data,
    }))
}

/// 统一 Record → Porkbun 记录（写入用；name 为相对子域，根留空）。
fn record_to_pk(rec: &Record) -> client::PkRecord {
    let mut out = client::PkRecord::default();
    out.name = rec.name.clone();
    out.rtype = rec.rtype.as_str().to_string();
    match &rec.data {
        RecordData::Plain(v) => out.content = v.clone(),
        RecordData::Mx {
            priority,
            exchange,
        } => {
            out.prio = priority.to_string();
            out.content = exchange.clone();
        }
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            // 官方格式：content = "weight port target"，priority 走 prio 字段。
            out.prio = priority.to_string();
            out.content = format!("{weight} {port} {target}");
        }
    }
    out.ttl = write_ttl(rec.ttl);
    out
}

/// SRV content 单字符串 → 结构化。
///
/// 官方格式：content="weight port target" + prio=priority；
/// 兼容历史/第三方 4 段写法 "priority weight port target"（prio 缺省时以首段为优先级）。
fn parse_srv_content(content: &str, prio: &str) -> Result<RecordData, ProviderError> {
    let tokens: Vec<&str> = content.split_whitespace().collect();
    let (priority, weight, port, target): (u16, u16, u16, &str) = match tokens.len() {
        3 => (
            parse_u16(prio, "SRV priority")?,
            parse_u16(tokens[0], "SRV weight")?,
            parse_u16(tokens[1], "SRV port")?,
            tokens[2],
        ),
        4 => {
            let p = if prio.is_empty() {
                parse_u16(tokens[0], "SRV priority")?
            } else {
                parse_u16(prio, "SRV priority")?
            };
            (
                p,
                parse_u16(tokens[1], "SRV weight")?,
                parse_u16(tokens[2], "SRV port")?,
                tokens[3],
            )
        }
        _ => {
            return Err(ProviderError::Other(format!(
                "Porkbun SRV content 需 3 段（weight port target）或 4 段（priority weight port target）: {content}"
            )))
        }
    };
    Ok(RecordData::Srv {
        priority,
        weight,
        port,
        target: target.to_string(),
    })
}

/// 读取侧 TTL："" / 0 → 官方默认 600。
fn parse_ttl(s: &str) -> u32 {
    s.parse().unwrap_or(TTL_DEFAULT).max(1)
}

/// 写入侧 TTL 收敛：0 → 省略字段（服务商默认 600）；<600 → 600（官方最小）。
fn write_ttl(ttl: u32) -> String {
    if ttl == 0 {
        String::new()
    } else {
        ttl.max(TTL_MIN).to_string()
    }
}

fn parse_u16(s: &str, what: &str) -> Result<u16, ProviderError> {
    s.trim().parse().map_err(|_| {
        ProviderError::Other(format!("Porkbun {what} 非法: {s}"))
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
