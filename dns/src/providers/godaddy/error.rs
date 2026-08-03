//! HTTP 响应 → 统一 `ProviderError` 错误映射（M9-DNS001 §三「错误码映射表」）。
//!
//! | GoDaddy 状态 | 触发 | 统一错误 |
//! |---|---|---|
//! | 401/403 | 密钥无效、域不属于账号 | `Auth` |
//! | 404 | 域名/记录不存在 | `NotFound` |
//! | 422 | 记录格式非法（如 SRV data 错误） | `InvalidParameter` |
//! | 429 | 限流 | `RateLimited{retry_after}`（取 Retry-After 头）|
//! | 其他 4xx | 客户端错误 | `InvalidParameter` |
//! | 5xx | 服务端错误 | `Server` |
//!
//! reqwest / serde 错误不在此映射：`ProviderError` 带 `#[from]`，由调用点
//! `?` 透传（M9-DNS000 §三）。

use crate::provider::ProviderError;
use reqwest::header::RETRY_AFTER;

/// 从 HTTP 响应映射统一错误。`ctx` 为操作上下文（供 404 的 `what` 字段）。
///
/// Retry-After 头在读取 body 之前取（`response.text()` 会消费响应）。
pub(crate) async fn map_response(response: reqwest::Response, ctx: &str) -> ProviderError {
    let status = response.status();
    let retry_after = response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let body = response.text().await.unwrap_or_default();

    match status.as_u16() {
        401 | 403 => ProviderError::Auth { detail: body },
        404 => ProviderError::NotFound {
            what: ctx.to_string(),
        },
        422 => ProviderError::InvalidParameter { detail: body },
        429 => ProviderError::RateLimited { retry_after },
        code if status.is_client_error() => ProviderError::InvalidParameter {
            detail: format!("HTTP {code}: {body}"),
        },
        code => ProviderError::Server {
            status: code,
            body,
        },
    }
}
