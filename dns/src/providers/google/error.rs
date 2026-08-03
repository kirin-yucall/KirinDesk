//! Google Cloud DNS 错误 → 统一 `ProviderError` 映射（M9-DNS007 §三 错误码映射表）。
//!
//! 映射规则（以 HTTP 状态码为主）：
//! - 401/403 → `Auth`（invalid_grant / PermissionDenied 等）
//! - 400/422 → `InvalidParameter`
//! - 404     → `NotFound`
//! - 429     → `RateLimited`（`retry_after` 取 Retry-After 响应头）
//! - 5xx     → `Server`
//!
//! 错误响应体形态：`{"error": {"code": 403, "message": "..."}}`。

use reqwest::header::HeaderMap;
use serde::Deserialize;

use crate::provider::ProviderError;

/// 从响应头读取 `Retry-After`（秒）；缺失或非法 → `None`。
pub fn retry_after_secs(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
}

#[derive(Deserialize)]
struct GoogleErrorBody {
    #[serde(default)]
    error: Option<GoogleError>,
}

#[derive(Deserialize)]
struct GoogleError {
    #[serde(default)]
    code: Option<u16>,
    #[serde(default)]
    message: Option<String>,
}

/// 状态码 + 错误体 → 统一错误。
pub fn map_error(status: u16, retry_after: Option<u64>, body: &str) -> ProviderError {
    let msg = parse_message(body);
    match status {
        401 | 403 => ProviderError::Auth { detail: msg },
        400 | 422 => ProviderError::InvalidParameter { detail: msg },
        404 => ProviderError::NotFound { what: msg },
        429 => ProviderError::RateLimited { retry_after },
        500..=599 => ProviderError::Server { status, body: body.to_string() },
        _ => ProviderError::Server { status, body: body.to_string() },
    }
}

/// 提取 `error.message`；无法解析/为空时退回原始响应体。
fn parse_message(body: &str) -> String {
    if body.trim().is_empty() {
        return "服务商返回空错误体".to_string();
    }
    let msg = serde_json::from_str::<GoogleErrorBody>(body)
        .ok()
        .and_then(|b| b.error)
        .and_then(|e| e.message.clone())
        .filter(|m| !m.is_empty());
    msg.unwrap_or_else(|| body.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_matches_m9_dns007_table() {
        let body = r#"{"error":{"code":401,"message":"Request had invalid authentication credentials"}}"#;
        assert!(matches!(map_error(401, None, body), ProviderError::Auth { .. }));
        assert!(matches!(map_error(403, None, body), ProviderError::Auth { .. }));
        assert!(matches!(
            map_error(400, None, r#"{"error":{"code":400,"message":"invalidParameter"}}"#),
            ProviderError::InvalidParameter { .. }
        ));
        assert!(matches!(
            map_error(404, None, r#"{"error":{"code":404,"message":"notFound"}}"#),
            ProviderError::NotFound { .. }
        ));
        match map_error(429, Some(120), r#"{"error":{"code":429,"message":"rateLimitExceeded"}}"#) {
            ProviderError::RateLimited { retry_after } => assert_eq!(retry_after, Some(120)),
            other => panic!("期望 RateLimited，得到 {other:?}"),
        }
        match map_error(500, None, "boom") {
            ProviderError::Server { status, body } => {
                assert_eq!(status, 500);
                assert_eq!(body, "boom");
            }
            other => panic!("期望 Server，得到 {other:?}"),
        }
    }

    #[test]
    fn retry_after_parses_header() {
        let mut h = HeaderMap::new();
        assert_eq!(retry_after_secs(&h), None);
        h.insert("retry-after", "30".parse().unwrap());
        assert_eq!(retry_after_secs(&h), Some(30));
    }

    #[test]
    fn message_falls_back_to_body() {
        let err = map_error(400, None, "not-json");
        match err {
            ProviderError::InvalidParameter { detail } => assert_eq!(detail, "not-json"),
            other => panic!("期望 InvalidParameter，得到 {other:?}"),
        }
    }
}
