//! M9-DNS018: 京东云解析错误 → 统一 `ProviderError` 映射（`M9-DNS000` §三）
//!
//! 京东云 OpenAPI 错误以 HTTP 状态码 + body 返回：
//! ```json
//! { "requestId": "…", "error": { "code": "InvalidSignature",
//!                                "status": "INVALID_ARGUMENT",
//!                                "message": "…" } }
//! ```
//!
//! 映射表（`M9-DNS018` §三）：
//! | HTTP / 错误 | 统一错误 |
//! |-------------|---------|
//! | 401 / 403（InvalidSignature、AccessDenied 等） | `Auth` |
//! | 400 / 422（InvalidParameter 等） | `InvalidParameter` |
//! | 404（ResourceNotFound） | `NotFound` |
//! | 429 / RequestLimitExceeded | `RateLimited` |
//! | 5xx | `Server` |

use crate::provider::ProviderError;

/// HTTP 状态码 → 统一错误（body 仅作 detail 文本）。
pub fn map_error(status: u16, body: &str, retry_after: Option<u64>) -> ProviderError {
    let detail = error_detail(body);
    match status {
        401 | 403 => ProviderError::Auth { detail },
        400 | 422 => ProviderError::InvalidParameter { detail },
        404 => ProviderError::NotFound { what: detail },
        429 => ProviderError::RateLimited { retry_after },
        500..=599 => ProviderError::Server { status, body: detail },
        _ => ProviderError::Other(format!("HTTP {status}: {detail}")),
    }
}

/// 提取错误 detail：优先 body 的 `error.code` / `error.message`，否则截断原文。
fn error_detail(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(err) = v.get("error") {
            let code = err.get("code").and_then(|c| c.as_str()).unwrap_or("");
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            if !code.is_empty() || !message.is_empty() {
                return if message.is_empty() {
                    code.to_string()
                } else {
                    format!("{code}: {message}")
                };
            }
        }
    }
    snippet(body)
}

/// 截断 body（错误信息不超过 512 字符）。
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

    fn err_body(code: &str, msg: &str) -> String {
        format!(
            r#"{{"requestId":"r1","error":{{"code":"{code}","status":"BAD_REQUEST","message":"{msg}"}}}}"#
        )
    }

    #[test]
    fn auth_maps() {
        let e = map_error(403, &err_body("AccessDenied", "无权限"), None);
        assert!(matches!(e, ProviderError::Auth { .. }));
        let e = map_error(401, "Unauthorized", None);
        assert!(matches!(e, ProviderError::Auth { .. }));
    }

    #[test]
    fn invalid_parameter_maps() {
        let e = map_error(400, &err_body("InvalidParameter", "参数非法"), None);
        assert!(matches!(e, ProviderError::InvalidParameter { .. }));
    }

    #[test]
    fn not_found_maps_with_detail() {
        let e = map_error(404, &err_body("ResourceNotFound", "域名不存在"), None);
        match e {
            ProviderError::NotFound { what } => assert!(what.contains("ResourceNotFound")),
            other => panic!("期望 NotFound，得到 {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps() {
        let e = map_error(429, "too many requests", Some(15));
        assert!(matches!(e, ProviderError::RateLimited { retry_after: Some(15) }));
        let e = map_error(429, &err_body("RequestLimitExceeded", "超频"), None);
        assert!(matches!(e, ProviderError::RateLimited { .. }));
    }

    #[test]
    fn server_maps() {
        let e = map_error(500, "boom", None);
        assert!(matches!(e, ProviderError::Server { status: 500, .. }));
        let e = map_error(502, "", None);
        assert!(matches!(e, ProviderError::Server { status: 502, .. }));
    }

    #[test]
    fn non_error_body_falls_back_to_snippet() {
        let e = map_error(400, "plain text error", None);
        assert!(matches!(e, ProviderError::InvalidParameter { .. }));
    }
}
