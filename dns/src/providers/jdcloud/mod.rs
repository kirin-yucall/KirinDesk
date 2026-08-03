//! M9-DNS018: 京东云解析（云解析）服务商适配（JDCLOUD2-HMAC-SHA256 签名）
//!
//! 依据：`M9-DNS018_京东云解析适配.md` / `M9-DNS000_Provider抽象接口规范.md`。
//!
//! 本模块**完全自包含**（HTTP 客户端 + JDCLOUD2 签名 + 序列化 + 错误映射），
//! 上层（discovery / heartbeat / srv / aaaa / txt / UI / CLI）只依赖
//! `crate::provider` 抽象层（`dyn Provider`）。
//!
//! 差异点消化：
//! - 认证：JDCLOUD2-HMAC-SHA256 签名（[`sign`]），头 `x-jdcloud-algorithm` /
//!   `x-jdcloud-date` / `x-jdcloud-nonce` / `authorization`；
//! - 接口：V2 优先（官方 2026-08-01 复核：`describeDomains` /
//!   `createResourceRecord` / `describeResourceRecord` / `modifyResourceRecord` /
//!   `deleteResourceRecord`，端点 `https://domainservice.jdcloud-api.com`）；
//! - 记录名：统一相对名（"" = 根）↔ 京东云 `@`；域名字 ↔ 域名 ID；
//! - 写入语义：单条 CRUD，upsert 幂等（查 → 同数据仅更新 TTL / 异数据修改 /
//!   无则创建），线路统一默认（`viewValue: [-1]`）；
//! - SRV：结构化（`mxPriority`/`port`/`weight`/`hostValue`）↔ `RecordData::Srv`；
//! - 错误映射：401/403 → Auth、400/422 → InvalidParameter、404 → NotFound、
//!   429 → RateLimited、5xx → Server（[`error`]）。
//!
//! 能力声明：全开（A/AAAA/CNAME/MX/TXT/SRV/NS + TTL + 改名），见
//! [`JdcloudProvider::capabilities`]。

mod client;
mod error;
mod sign;
#[cfg(test)]
mod tests;

pub use client::{DEFAULT_ENDPOINT, DEFAULT_REGION, JdcloudClient};

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordType,
};

/// 京东云解析 `Provider` 实现（薄封装：[`JdcloudClient`] 承载 HTTP 与签名细节）。
#[derive(Debug, Clone)]
pub struct JdcloudProvider {
    client: JdcloudClient,
}

impl JdcloudProvider {
    /// 便捷构造（生产端点 `https://domainservice.jdcloud-api.com`；
    /// region 空 → `cn-north-1`）。
    pub fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        region: impl Into<String>,
    ) -> Self {
        Self::with_endpoint(access_key, secret_key, region, DEFAULT_ENDPOINT)
    }

    /// 指定端点构造（契约测试/mock 用 `http://127.0.0.1:port`）。
    pub fn with_endpoint(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        region: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            client: JdcloudClient::new(
                access_key.into(),
                secret_key.into(),
                region.into(),
                endpoint.into(),
            ),
        }
    }
}

#[async_trait::async_trait]
impl Provider for JdcloudProvider {
    fn name(&self) -> &'static str {
        "jdcloud"
    }

    /// 测试连接：`describeDomains`（pageSize=1）。
    async fn test_connection(&self) -> Result<(), ProviderError> {
        self.client.test_connection().await
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        self.client.list_domains().await
    }

    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        self.client.query_records(domain, name, rtype).await
    }

    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        self.client.upsert_record(domain, rec).await
    }

    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        self.client.delete_record(domain, name, rtype).await
    }

    /// 全能力（A/AAAA/CNAME/MX/TXT/SRV/NS + TTL + 改名）。
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::all()
    }
}

/// 注册到服务商注册表（`providers::register_all` 调用）。
pub fn register(registry: &mut ProviderRegistry) {
    registry.register(
        "jdcloud",
        |cred| -> Box<dyn Provider> {
            match cred {
                Credential::Jdcloud {
                    access_key,
                    secret_key,
                    region,
                } => Box::new(JdcloudProvider::new(
                    access_key.clone(),
                    secret_key.clone(),
                    region.clone(),
                )),
                // 注册表按 name 分发，凭据变体不匹配仅可能因配置层 bug——显式 panic 暴露。
                other => panic!("jdcloud 注册表构造器收到非 Jdcloud 凭据变体: {other:?}"),
            }
        } as fn(&Credential) -> Box<dyn Provider>,
    );
}
