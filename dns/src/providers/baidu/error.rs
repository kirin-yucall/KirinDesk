//! M9-DNS016: 百度智能云错误 → 统一 `ProviderError` 映射
//!
//! 错误响应体形如 `{"code": "...", "message": "...", "requestId": "..."}`。
//! 映射以 **HTTP 状态码** 为主（`M9-DNS016` §三 错误码映射表），
//! 码/消息进入 detail；`QualifyNotPass`（未实名）等特殊码附加提示。

use crate::provider::ProviderError;

/// 检查响应状态与错误体；成功返回 `Ok(())`。
///
/// `retry_after` 取自响应头 `Retry-After`（限流时使用）。
pub fn check_response(
    status: u16,
    body: &str,
    retry_after: Option<u64>,
) -> Result<(), ProviderError> {
    if status < 400 {
        return Ok(());
    }
    let detail = extract_detail(body);
    match status {
        401 | 403 => {
            // 未实名（QualifyNotPass）等场景附加提示。
            let hint = if detail.contains("实名") || detail.contains("Qualify") {
                "（账号可能未完成实名认证）"
            } else {
                ""
            };
            Err(ProviderError::Auth {
                detail: format!("{detail}{hint}"),
            })
        }
        400 | 422 => Err(ProviderError::InvalidParameter { detail }),
        404 => Err(ProviderError::NotFound { what: detail }),
        429 => Err(ProviderError::RateLimited { retry_after }),
        500..=599 => Err(ProviderError::Server {
            status,
            body: body.to_string(),
        }),
        _ => Err(ProviderError::Other(format!("HTTP {status}: {body}"))),
    }
}

/// 从错误体中提取 `code: message` 摘要（非 JSON 时用原始 body）。
fn extract_detail(body: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => {
            let code = v.get("code").and_then(|c| c.as_str()).unwrap_or_default();
            let message = v
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or_default();
            if code.is_empty() && message.is_empty() {
                body.to_string()
            } else {
                format!("{code}: {message}")
            }
        }
        Err(_) => body.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_ok() {
        assert!(check_response(200, "", None).is_ok());
    }

    #[test]
    fn auth_maps_401_403() {
        let body = r#"{"code":"AccessDenied","message":"no permission","requestId":"r1"}"#;
        assert!(matches!(
            check_response(403, body, None).unwrap_err(),
            ProviderError::Auth { .. }
        ));
        assert!(matches!(
            check_response(401, body, None).unwrap_err(),
            ProviderError::Auth { .. }
        ));
    }

    #[test]
    fn qualify_not_pass_hints_realname() {
        let body = r#"{"code":"QualifyNotPass","message":"账号未实名","requestId":"r2"}"#;
        let err = check_response(403, body, None).unwrap_err();
        assert!(matches!(err, ProviderError::Auth { .. }));
        assert!(err.to_string().contains("实名"));
    }

    #[test]
    fn param_not_found_rate_server() {
        let body = r#"{"code":"InvalidParameter","message":"bad","requestId":"r3"}"#;
        assert!(matches!(
            check_response(400, body, None).unwrap_err(),
            ProviderError::InvalidParameter { .. }
        ));
        let body = r#"{"code":"NoSuchDomain","message":"no domain","requestId":"r4"}"#;
        assert!(matches!(
            check_response(404, body, None).unwrap_err(),
            ProviderError::NotFound { .. }
        ));
        assert!(matches!(
            check_response(429, "{\"code\":\"RateLimit\",\"message\":\"slow\"}", Some(3))
                .unwrap_err(),
            ProviderError::RateLimited { retry_after: Some(3) }
        ));
        assert!(matches!(
            check_response(500, "{\"code\":\"InternalError\",\"message\":\"x\"}", None)
                .unwrap_err(),
            ProviderError::Server { .. }
        ));
    }
}
