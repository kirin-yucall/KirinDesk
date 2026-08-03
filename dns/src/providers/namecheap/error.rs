//! M9-DNS009: Namecheap 错误 → 统一 ProviderError 映射
//!
//! 对照 `M9-DNS009_Namecheap服务商适配.md` 错误码映射表：
//! - HTTP 401/403 → Auth；400 → InvalidParameter；404 → NotFound；
//!   429 → RateLimited；5xx → Server；
//! - XML `Status=ERROR` + `<Errors><Error Number=..>` 按错误码分类。

use crate::provider::ProviderError;
use crate::providers::namecheap::xml::NcError;

/// HTTP 层错误 → 统一错误。
pub(crate) fn map_http_error(status: u16, body: &str) -> ProviderError {
    match status {
        401 | 403 => ProviderError::Auth {
            detail: format!("Namecheap HTTP {status}: {body}"),
        },
        400 => ProviderError::InvalidParameter {
            detail: format!("Namecheap HTTP {status}: {body}"),
        },
        404 => ProviderError::NotFound {
            what: format!("Namecheap HTTP {status}: {body}"),
        },
        429 => ProviderError::RateLimited { retry_after: None },
        500..=599 => ProviderError::Server {
            status,
            body: body.to_string(),
        },
        _ => ProviderError::Other(format!("Namecheap HTTP {status}: {body}")),
    }
}

/// 业务层错误（`Status=ERROR` + `<Errors>`）→ 统一错误。
///
/// 错误码映射（M9-DNS009 §三）：
/// - 1001001 无效请求 / 1001010 认证错误 / 1011xxx（API Key 无效、IP 白名单、
///   账户无权等系列）→ `Auth`；
/// - 2015122 记录参数错误 → `InvalidParameter`；
/// - 2016083 域名不存在/无权 → `NotFound`；
/// - 其余 → `Other`（保留原始码与消息供 UI/日志）。
pub(crate) fn map_api_error(errors: &[NcError]) -> ProviderError {
    if let Some(first) = errors.first() {
        let all = errors
            .iter()
            .map(|e| format!("{}:{}", e.number, e.message))
            .collect::<Vec<_>>()
            .join("; ");
        match first.number {
            // 认证/权限/无效请求系列。
            1001001 | 1001010 | 1011001..=1011999 => ProviderError::Auth {
                detail: format!("Namecheap 错误码 {}: {}", first.number, all),
            },
            // 记录参数错误。
            2015122 => ProviderError::InvalidParameter {
                detail: format!("Namecheap 错误码 {}: {}", first.number, all),
            },
            // 域名不存在/无权。
            2016083 => ProviderError::NotFound {
                what: format!("Namecheap 错误码 {}: {}", first.number, all),
            },
            _ => ProviderError::Other(format!("Namecheap 错误码 {}: {}", first.number, all)),
        }
    } else {
        ProviderError::Other("Namecheap 返回 Status=ERROR 但无 <Error> 详情".to_string())
    }
}
