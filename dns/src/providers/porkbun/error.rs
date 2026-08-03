//! M9-DNS015: Porkbun 错误 → 统一 ProviderError 映射
//!
//! 对照 `M9-DNS015_Porkbun适配.md` 错误码映射表：
//! - HTTP 401/403 → Auth；400 → InvalidParameter；404 → NotFound；
//!   429 → RateLimited；5xx → Server；
//! - HTTP 200 + `{"status":"ERROR","message":...}` 业务错误按 message 关键词分类。

use crate::provider::ProviderError;

/// Porkbun 响应/HTTP 错误 → 统一错误。
pub(crate) fn map_error(status: u16, message: &str) -> ProviderError {
    match status {
        401 | 403 => ProviderError::Auth {
            detail: format!("Porkbun HTTP {status}: {message}"),
        },
        400 => ProviderError::InvalidParameter {
            detail: format!("Porkbun HTTP {status}: {message}"),
        },
        404 => ProviderError::NotFound {
            what: format!("Porkbun HTTP {status}: {message}"),
        },
        429 => ProviderError::RateLimited { retry_after: None },
        500..=599 => ProviderError::Server {
            status,
            body: message.to_string(),
        },
        _ => map_business_error(message),
    }
}

/// HTTP 200 + `status=ERROR` 的业务错误：按 message 关键词分类
/// （"Invalid API key" → Auth；"Domain not found" → NotFound 等）。
fn map_business_error(message: &str) -> ProviderError {
    let lower = message.to_lowercase();
    if lower.contains("api key")
        || lower.contains("unauthorized")
        || lower.contains("permission")
        || lower.contains("denied")
        || lower.contains("credentials")
    {
        ProviderError::Auth {
            detail: format!("Porkbun: {message}"),
        }
    } else if lower.contains("not found") || lower.contains("no such") {
        ProviderError::NotFound {
            what: format!("Porkbun: {message}"),
        }
    } else if lower.contains("rate") || lower.contains("too many") {
        ProviderError::RateLimited { retry_after: None }
    } else if lower.contains("invalid record")
        || lower.contains("invalid")
        || lower.contains("must be")
        || lower.contains("require")
    {
        ProviderError::InvalidParameter {
            detail: format!("Porkbun: {message}"),
        }
    } else {
        ProviderError::Other(format!("Porkbun: {message}"))
    }
}
