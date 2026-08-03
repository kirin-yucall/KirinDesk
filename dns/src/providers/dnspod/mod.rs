//! M9-DNS004: 腾讯云 DNSPod 服务商适配（TC3-HMAC-SHA256 签名）
//!
//! 依据：`M9-DNS004_腾讯云DNSPod适配.md` / `M9-DNS000_Provider抽象接口规范.md`。
//!
//! 本模块**完全自包含**（HTTP 客户端 + TC3 签名 + 序列化 + 错误映射），
//! 上层（discovery / heartbeat / srv / aaaa / txt / UI / CLI）只依赖
//! `crate::provider` 抽象层（`dyn Provider`）。
//!
//! 差异点消化：
//! - 认证：TC3-HMAC-SHA256 签名（[`sign`]），头 `X-TC-Action` / `X-TC-Version` /
//!   `X-TC-Timestamp` / `X-TC-Nonce` + `Authorization`；
//! - 记录名：统一相对名（"" = 根）↔ DNSPod `@`；
//! - 写入语义：单条 CRUD（`CreateRecord` / `ModifyRecord` / `DeleteRecord`），
//!   统一走「默认」线路，upsert 幂等（查 → 同数据仅更新 TTL / 异数据修改 / 无则创建）；
//! - SRV：结构化字段 ↔ 单串 `"{priority} {weight} {port} {target}"`（[`client`]）；
//! - 错误映射：`AuthFailure.*` / `UnauthorizedOperation` → Auth、
//!   `InvalidParameter.*` → InvalidParameter、`ResourceNotFound.*` → NotFound、
//!   `LimitExceeded` / `RequestLimitExceeded` → RateLimited、5xx → Server（[`error`]）。
//!
//! 能力声明：全开（A/AAAA/CNAME/MX/TXT/SRV/NS + TTL + 改名），见
//! [`DnspodProvider::capabilities`]。

mod client;
mod error;
mod sign;
#[cfg(test)]
mod tests;

pub use client::{DEFAULT_ENDPOINT, DnspodClient};

use crate::provider::{
    Credential, Provider, ProviderCapabilities, ProviderError, ProviderRegistry, Record,
    RecordType,
};

/// DNSPod `Provider` 实现（薄封装：[`DnspodClient`] 承载 HTTP 与签名细节）。
#[derive(Debug, Clone)]
pub struct DnspodProvider {
    client: DnspodClient,
}

impl DnspodProvider {
    /// 便捷构造（生产端点 `https://dnspod.tencentcloudapi.com`）。
    pub fn new(secret_id: impl Into<String>, secret_key: impl Into<String>) -> Self {
        Self::with_endpoint(secret_id, secret_key, DEFAULT_ENDPOINT)
    }

    /// 指定端点构造（契约测试/mock 用 `http://127.0.0.1:port`）。
    pub fn with_endpoint(
        secret_id: impl Into<String>,
        secret_key: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            client: DnspodClient::new(
                secret_id.into(),
                secret_key.into(),
                endpoint.into(),
            ),
        }
    }
}

#[async_trait::async_trait]
impl Provider for DnspodProvider {
    fn name(&self) -> &'static str {
        "dnspod"
    }

    /// 测试连接：`DescribeDomainList`（Limit=1）。
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
        "dnspod",
        |cred| -> Box<dyn Provider> {
            match cred {
                Credential::Dnspod {
                    secret_id,
                    secret_key,
                } => Box::new(DnspodProvider::new(secret_id.clone(), secret_key.clone())),
                // 注册表按 name 分发，凭据变体不匹配仅可能因配置层 bug——显式 panic 暴露。
                other => panic!("dnspod 注册表构造器收到非 Dnspod 凭据变体: {other:?}"),
            }
        } as fn(&Credential) -> Box<dyn Provider>,
    );
}
