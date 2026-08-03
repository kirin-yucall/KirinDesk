//! M9-DNS009: Namecheap 服务商适配（`M9-DNS009_Namecheap服务商适配.md`）
//!
//! - 端点：`https://api.namecheap.com/xml.response`（GET 表单 + XML 响应，手写解析）
//! - 认证：ApiUser / ApiKey / UserName / ClientIp 四个表单参数（IP 白名单）
//! - 写入语义：**setHosts 整组替换**——先 `getHosts` 查现组 → 增/删/改目标条 →
//!   整组提交（≤20 条/次，超出报错提示）；未知类型（URL/FRAME/ALIAS/CAA/MXE 等）
//!   在整组替换中原样保留，避免误删
//! - 记录名：相对名（`@` 根 ↔ ""）
//! - SRV ⚠️：官方 setHosts 不接受 `RecordType=SRV`；经 DNSControl 验证的未公开命令
//!   `getsrvrecords` / `setsrvrecords` 实现（Service/Protocol/Priority/Weight/Port/
//!   Target 独立字段），`capabilities.srv = true`（降级判断见 DNS-MNT-013）
//! - TTL：支持（官方最小 60 秒、默认 1800；写入时收敛避免读写振荡）

pub mod client;
pub mod error;
pub mod xml;

#[cfg(test)]
mod tests;

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordData, RecordType,
};
use client::{NamecheapClient, PROD_BASE_URL, TTL_DEFAULT, TTL_MIN};
use std::str::FromStr;
use xml::{NcHost, NcSrvRecord};

/// 注册 Namecheap 服务商（工厂从凭据构建；凭据不落日志）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register("namecheap", |cred| -> Box<dyn Provider> {
        match cred {
            Credential::Namecheap {
                api_user,
                api_key,
                user_name,
                client_ip,
            } => Box::new(NamecheapProvider::new(
                api_user.clone(),
                api_key.clone(),
                user_name.clone(),
                client_ip.clone(),
            )),
            other => Box::new(CredentialMismatchProvider::new("namecheap", other)),
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

/// Namecheap Provider 实现。
pub(crate) struct NamecheapProvider {
    client: NamecheapClient,
    caps: ProviderCapabilities,
}

impl NamecheapProvider {
    /// 生产构造（固定官方端点）。
    pub(crate) fn new(
        api_user: String,
        api_key: String,
        user_name: String,
        client_ip: String,
    ) -> Self {
        Self::from_client(NamecheapClient::new(
            api_user,
            api_key,
            user_name,
            client_ip,
            PROD_BASE_URL.to_string(),
        ))
    }

    /// 测试构造：base_url 指向 127.0.0.1 mock（见 tests.rs）。
    #[cfg(test)]
    pub(crate) fn new_at(
        api_user: String,
        api_key: String,
        user_name: String,
        client_ip: String,
        base_url: String,
    ) -> Self {
        Self::from_client(NamecheapClient::new(
            api_user,
            api_key,
            user_name,
            client_ip,
            base_url,
        ))
    }

    fn from_client(client: NamecheapClient) -> Self {
        Self {
            client,
            // 能力全开（SRV 经未公开命令支持，见模块头注释；M9-DNS009 目录矩阵 ⚠️）。
            caps: ProviderCapabilities::all(),
        }
    }

    /// 非 SRV 写入：getHosts 全量 → 替换 (name, rtype) 组 → setHosts 整组提交。
    /// 未知类型记录原样保留，避免整组替换误删（与 GoDaddy 先查后写语义一致）。
    async fn upsert_host(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let mut hosts = self.client.get_hosts(domain).await?;
        let wire = wire_name(&rec.name);
        hosts.retain(|h| !(h.name == wire && h.rtype == rec.rtype.as_str()));
        hosts.push(record_to_host(rec));
        self.client.set_hosts(domain, &hosts).await
    }

    /// SRV 写入：getsrvrecords 全量 → 替换同名 → setsrvrecords 整组提交。
    async fn upsert_srv(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        let mut srvs = self.client.get_srv_records(domain).await?;
        let want = record_to_srv(rec)?;
        srvs.retain(|s| srv_wire_name(s) != rec.name);
        srvs.push(want);
        self.client.set_srv_records(domain, &srvs).await
    }

    async fn delete_host(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let mut hosts = self.client.get_hosts(domain).await?;
        let wire = wire_name(name);
        let before = hosts.len();
        hosts.retain(|h| !(h.name == wire && h.rtype == rtype.as_str()));
        if hosts.len() == before {
            return Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            });
        }
        self.client.set_hosts(domain, &hosts).await
    }

    async fn delete_srv(&self, domain: &str, name: &str) -> Result<(), ProviderError> {
        let mut srvs = self.client.get_srv_records(domain).await?;
        let before = srvs.len();
        srvs.retain(|s| srv_wire_name(s) != name);
        if srvs.len() == before {
            return Err(ProviderError::NotFound {
                what: format!("SRV {name}.{domain}"),
            });
        }
        self.client.set_srv_records(domain, &srvs).await
    }
}

#[async_trait::async_trait]
impl Provider for NamecheapProvider {
    fn name(&self) -> &'static str {
        "namecheap"
    }

    /// 最小查询：getList 第 1 页（DNS-MNT-003 测试连接载体）。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.list_domains().await.map(|_| ())
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.client.list_domains().await
    }

    /// 查询：getHosts（普通记录）+ getsrvrecords（SRV）合并后过滤。
    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let mut out = Vec::new();
        for h in self.client.get_hosts(domain).await? {
            if let Some(rec) = host_to_record(&h) {
                out.push(rec);
            }
        }
        for s in self.client.get_srv_records(domain).await? {
            out.push(srv_to_record(&s));
        }
        Ok(filter_and_sort(out, name, rtype))
    }

    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        if rec.rtype == RecordType::SRV {
            self.upsert_srv(domain, rec).await
        } else {
            self.upsert_host(domain, rec).await
        }
    }

    /// 删除（统一语义：删除该 name+rtype 下全部记录）。
    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        if rtype == RecordType::SRV {
            self.delete_srv(domain, name).await
        } else {
            self.delete_host(domain, name, rtype).await
        }
    }

    fn capabilities(&self) -> ProviderCapabilities {
        self.caps.clone()
    }
}

// ────────────────────────────────────────────────────────────────
// 相对名 ↔ Namecheap 名、Record ↔ 厂商模型互转
// ────────────────────────────────────────────────────────────────

/// Namecheap host 名 → 统一相对名（"@" 根 → ""）。
fn rel_name(name: &str) -> String {
    if name == "@" {
        String::new()
    } else {
        name.to_string()
    }
}

/// 统一相对名 → Namecheap host 名（"" 根 → "@"）。
fn wire_name(name: &str) -> String {
    if name.is_empty() {
        "@".to_string()
    } else {
        name.to_string()
    }
}

/// host → 统一 Record。无法表达的类型（URL/FRAME/ALIAS/CAA/MXE 等）返回 None：
/// 查询时跳过（写入整组替换时仍保留，见 `upsert_host`）。
fn host_to_record(h: &NcHost) -> Option<Record> {
    let rtype = RecordType::from_str(&h.rtype).ok()?;
    let data = if rtype == RecordType::MX {
        RecordData::Mx {
            priority: h.mxpref,
            exchange: h.address.clone(),
        }
    } else {
        RecordData::Plain(h.address.clone())
    };
    Some(Record {
        name: rel_name(&h.name),
        rtype,
        ttl: normalize_read_ttl(h.ttl),
        data,
    })
}

/// 读取侧 TTL 归一化：0 → 官方默认 1800。
fn normalize_read_ttl(ttl: u32) -> u32 {
    if ttl == 0 {
        TTL_DEFAULT
    } else {
        ttl
    }
}

/// 统一 Record → host（写入侧 TTL 收敛：0 → 默认 1800；<60 → 60）。
///
/// 注意：SRV 记录不经过此函数（由 `upsert_srv` 走 setsrvrecords）。
fn record_to_host(rec: &Record) -> NcHost {
    let (address, mxpref) = match &rec.data {
        RecordData::Mx {
            priority,
            exchange,
        } => (exchange.clone(), *priority),
        RecordData::Plain(v) => (v.clone(), 0),
        RecordData::Srv { .. } => (String::new(), 0),
    };
    NcHost {
        name: wire_name(&rec.name),
        rtype: rec.rtype.as_str().to_string(),
        address,
        mxpref,
        ttl: normalize_write_ttl(rec.ttl),
    }
}

fn normalize_write_ttl(ttl: u32) -> u32 {
    if ttl == 0 {
        TTL_DEFAULT
    } else {
        ttl.max(TTL_MIN)
    }
}

/// getsrvrecords 单条 → 统一 Record。
///
/// Service 通常带尾点（"_remote."）+ Protocol（"_tcp"），拼接即记录名；
/// 防御性处理 Service 无尾点的情况。
fn srv_to_record(s: &NcSrvRecord) -> Record {
    Record {
        name: srv_wire_name(s),
        rtype: RecordType::SRV,
        ttl: 0, // setsrvrecords 无 TTL 参数（Namecheap SRV 不可配 TTL）
        data: RecordData::Srv {
            priority: s.priority,
            weight: s.weight,
            port: s.port,
            target: s.target.clone(),
        },
    }
}

/// 统一 Record → setsrvrecords 参数。
///
/// "_remote._tcp" → Service="_remote." + Protocol="_tcp"（与 DNSControl 一致）。
fn record_to_srv(rec: &Record) -> Result<NcSrvRecord, ProviderError> {
    let (priority, weight, port, target) = match &rec.data {
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => (*priority, *weight, *port, target.clone()),
        _ => {
            return Err(ProviderError::InvalidParameter {
                detail: "Namecheap SRV 记录数据必须是 RecordData::Srv".to_string(),
            })
        }
    };
    let (service, protocol) = rec.name.split_once('.').ok_or_else(|| {
        ProviderError::InvalidParameter {
            detail: format!(
                "Namecheap SRV 记录名必须形如 _service._proto（当前: {}）",
                rec.name
            ),
        }
    })?;
    let service = if service.ends_with('.') {
        service.to_string()
    } else {
        format!("{service}.")
    };
    Ok(NcSrvRecord {
        service,
        protocol: protocol.to_string(),
        priority,
        weight,
        port,
        target,
    })
}

/// SRV 记录名（Service + Protocol 拼接；防御性补点）。
fn srv_wire_name(s: &NcSrvRecord) -> String {
    if s.service.ends_with('.') {
        format!("{}{}", s.service, s.protocol)
    } else {
        format!("{}.{}", s.service, s.protocol)
    }
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
