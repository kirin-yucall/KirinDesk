//! Azure ARM 响应错误 → 统一 ProviderError 映射（M9-DNS006 §三 错误码映射表）
//!
//! ARM 错误体 JSON：`{"error":{"code":"ResourceNotFound","message":"..."}}`。
//! 以 HTTP 状态码为主判定，`error.code` 进入 detail 便于排查。

use crate::provider::ProviderError;

/// 解析 ARM 错误体，返回 `(code, message)`（无 error 结构 → None）。
fn parse_arm_error(body: &str) -> Option<(String, String)> {
    #[derive(serde::Deserialize)]
    struct ArmError {
        error: Option<ArmErrorDetail>,
    }
    #[derive(serde::Deserialize)]
    struct ArmErrorDetail {
        #[serde(default)]
        code: Option<String>,
        #[serde(default)]
        message: Option<String>,
    }
    let parsed: Result<ArmError, _> = serde_json::from_str(body);
    match parsed {
        Ok(a) => a.error.and_then(|e| e.code.map(|c| (c, e.message.unwrap_or_default()))),
        Err(_) => None,
    }
}

/// 映射 ARM 响应为统一错误（2xx 返回 Ok）。
///
/// `retry_after` 来自 `Retry-After` 响应头（429 限流用）。
pub fn map_response(status: u16, body: &str, retry_after: Option<&str>) -> Result<(), ProviderError> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    let (code, message) = parse_arm_error(body)
        .map(|(c, m)| (Some(c), m))
        .unwrap_or_else(|| (None, body.trim().to_string()));
    let detail = match &code {
        Some(c) => format!("Azure 错误 {status} [{c}]: {}", truncate(&message, 300)),
        None => format!("Azure 错误 {status}: {}", truncate(&message, 300)),
    };

    match status {
        // 401/403：token 无效 / 无权限（AuthorizationFailed、InvalidAuthenticationToken）。
        401 | 403 => Err(ProviderError::Auth { detail }),
        // 404：zone/记录集不存在（ResourceNotFound）——先于 4xx 区间匹配。
        404 => Err(ProviderError::NotFound { what: message }),
        // 400/422：参数/记录非法（InvalidResourceRecord、InvalidType）。
        400..=422 => Err(ProviderError::InvalidParameter { detail }),
        // 429：ARM 全局限流。
        429 => Err(ProviderError::RateLimited {
            retry_after: retry_after.and_then(|v| v.trim().parse::<u64>().ok()),
        }),
        // 其他 5xx → Server。
        _ => Err(ProviderError::Server {
            status,
            body: truncate(body, 1000),
        }),
    }
}

/// 截断长响应体（错误 detail 防日志爆炸；凭据绝不入内）。
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arm_err(code: &str, message: &str) -> String {
        format!(r#"{{"error":{{"code":"{code}","message":"{message}"}}}}"#)
    }

    #[test]
    fn auth_by_status_401_403() {
        let e = map_response(401, &arm_err("InvalidAuthenticationToken", "token invalid"), None).unwrap_err();
        assert!(matches!(e, ProviderError::Auth { .. }), "{e:?}");
        let e = map_response(403, &arm_err("AuthorizationFailed", "no permission"), None).unwrap_err();
        assert!(matches!(e, ProviderError::Auth { .. }), "{e:?}");
    }

    #[test]
    fn invalid_parameter_and_not_found() {
        let e = map_response(400, &arm_err("InvalidResourceRecord", "bad record"), None).unwrap_err();
        assert!(matches!(e, ProviderError::InvalidParameter { .. }));
        let e = map_response(404, &arm_err("ResourceNotFound", "zone not found"), None).unwrap_err();
        match e {
            ProviderError::NotFound { what } => assert_eq!(what, "zone not found"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_with_retry_after() {
        let e = map_response(429, &arm_err("Throttling", "slow down"), Some("7")).unwrap_err();
        match e {
            ProviderError::RateLimited { retry_after } => assert_eq!(retry_after, Some(7)),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn server_and_ok() {
        let e = map_response(500, "Internal server error", None).unwrap_err();
        assert!(matches!(e, ProviderError::Server { status: 500, .. }));
        assert!(map_response(200, "", None).is_ok());
        assert!(map_response(204, "", None).is_ok());
        assert!(map_response(201, "", None).is_ok());
    }

    #[test]
    fn non_json_body_fallback() {
        let e = map_response(403, "<html>Forbidden</html>", None).unwrap_err();
        assert!(matches!(e, ProviderError::Auth { .. }));
    }
}
