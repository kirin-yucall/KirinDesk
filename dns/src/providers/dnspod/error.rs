//! M9-DNS004: 腾讯云 DNSPod 错误 → 统一 `ProviderError` 映射（`M9-DNS000` §三）
//!
//! 腾讯云 API 错误信封（HTTP 状态通常仍为 200，错误在 body 内）：
//! ```json
//! { "Response": { "Error": { "Code": "AuthFailure.SignatureFailure", "Message": "…" },
//!                 "RequestId": "…" } }
//! ```
//! 少数场景（网关层）直接返回非 2xx 状态 + 纯文本/JSON body。
//!
//! 映射表（`M9-DNS004` §三）：
//! | DNSPod Code | 统一错误 |
//! |-------------|---------|
//! | `AuthFailure.*` / `UnauthorizedOperation` | `Auth` |
//! | `InvalidParameter.*` | `InvalidParameter` |
//! | `ResourceNotFound.*`（Record/Domain） | `NotFound` |
//! | `LimitExceeded` / `RequestLimitExceeded` | `RateLimited` |
//! | `InternalError` / 其他 5xx | `Server` |
//! | 其余未知 | `Other` |

use crate::provider::ProviderError;

/// HTTP 状态 → 兜底映射（body 无 Error 结构时使用，`M9-DNS000` §三 通用规则）。
pub fn map_status(status: u16, body: &str, retry_after: Option<u64>) -> ProviderError {
    match status {
        401 | 403 => ProviderError::Auth {
            detail: format!("HTTP {status}: {}", snippet(body)),
        },
        400 | 422 => ProviderError::InvalidParameter {
            detail: format!("HTTP {status}: {}", snippet(body)),
        },
        404 => ProviderError::NotFound {
            what: snippet(body),
        },
        429 => ProviderError::RateLimited { retry_after },
        500..=599 => ProviderError::Server {
            status,
            body: snippet(body),
        },
        _ => ProviderError::Other(format!("HTTP {status}: {}", snippet(body))),
    }
}

/// 完整映射：优先解析 body 的 `Response.Error` 结构，否则按 HTTP 状态兜底。
///
/// `retry_after` 取 `Retry-After` 响应头（厂商未提供时由调用方传 None）。
pub fn map_error(status: u16, body: &str, retry_after: Option<u64>) -> ProviderError {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(err) = v.pointer("/Response/Error") {
            let code = err.get("Code").and_then(|c| c.as_str()).unwrap_or("");
            let message = err
                .get("Message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            let detail = if message.is_empty() {
                format!("{code}（HTTP {status}）")
            } else {
                format!("{code}: {message}")
            };
            return map_code(code, detail, status);
        }
    }
    map_status(status, body, retry_after)
}

/// 错误码前缀 → 统一错误（`M9-DNS004` §三 映射表）。
fn map_code(code: &str, detail: String, status: u16) -> ProviderError {
    if code.starts_with("AuthFailure") || code.starts_with("UnauthorizedOperation") {
        ProviderError::Auth { detail }
    } else if code.starts_with("InvalidParameter") {
        ProviderError::InvalidParameter { detail }
    } else if code.starts_with("ResourceNotFound") {
        ProviderError::NotFound { what: detail }
    } else if code.starts_with("LimitExceeded") || code.starts_with("RequestLimitExceeded") {
        ProviderError::RateLimited { retry_after: None }
    } else if code.starts_with("InternalError") {
        ProviderError::Server { status, body: detail }
    } else {
        ProviderError::Other(detail)
    }
}

/// 截断 body（日志/错误信息不超过 512 字符，避免塞满响应原文）。
fn snippet(body: &str) -> String {
    let t = body.trim();
    if t.len() > 512 {
        format!("{}…", &t[..512])
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err_with(code: &str, msg: &str) -> String {
        format!(
            r#"{{"Response":{{"Error":{{"Code":"{code}","Message":"{msg}"}},"RequestId":"r1"}}}}"#
        )
    }

    #[test]
    fn auth_failure_maps_to_auth() {
        let e = map_error(200, &err_with("AuthFailure.SignatureFailure", "签名校验失败"), None);
        assert!(matches!(e, ProviderError::Auth { .. }));
        let e = map_error(200, &err_with("UnauthorizedOperation", "无权限"), None);
        assert!(matches!(e, ProviderError::Auth { .. }));
    }

    #[test]
    fn invalid_parameter_maps() {
        let e = map_error(200, &err_with("InvalidParameter.DomainNotExists", "域名不存在"), None);
        assert!(matches!(e, ProviderError::InvalidParameter { .. }));
    }

    #[test]
    fn resource_not_found_maps() {
        let e = map_error(200, &err_with("ResourceNotFound.Record", "记录不存在"), None);
        match e {
            ProviderError::NotFound { what } => assert!(what.contains("ResourceNotFound.Record")),
            other => panic!("期望 NotFound，得到 {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps() {
        for code in ["LimitExceeded", "RequestLimitExceeded", "LimitExceeded.Request"] {
            let e = map_error(200, &err_with(code, "请求过多"), None);
            assert!(matches!(e, ProviderError::RateLimited { .. }), "code={code}");
        }
        // Retry-After 头透传。
        let e = map_error(429, "{}", Some(30));
        assert!(matches!(e, ProviderError::RateLimited { retry_after: Some(30) }));
    }

    #[test]
    fn internal_error_and_5xx_map_to_server() {
        let e = map_error(200, &err_with("InternalError", "内部错误"), None);
        assert!(matches!(e, ProviderError::Server { .. }));
        let e = map_error(500, "Service Unavailable", None);
        assert!(matches!(e, ProviderError::Server { status: 500, .. }));
    }

    #[test]
    fn status_fallback_mapping() {
        assert!(matches!(map_error(403, "forbidden", None), ProviderError::Auth { .. }));
        assert!(matches!(map_error(400, "bad", None), ProviderError::InvalidParameter { .. }));
        assert!(matches!(map_error(404, "nope", None), ProviderError::NotFound { .. }));
    }
}
