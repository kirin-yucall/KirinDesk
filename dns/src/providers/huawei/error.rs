//! 华为云 DNS 错误 → 统一 `ProviderError` 映射（M9-DNS008 §三 错误码映射表）。
//!
//! 映射规则（以 HTTP 状态码为主，错误码辅助）：
//! - 401/403（如 APIGW.0301 鉴权失败 / DNS.0001 无权限）→ `Auth`
//! - 400（如 DNS.0104 参数错误）→ `InvalidParameter`
//! - 404（如 DNS.0101 zone/记录集不存在）→ `NotFound`
//! - 429 / APIGW.0308（请求超限）→ `RateLimited`
//! - 5xx → `Server`
//!
//! 错误响应体形态：`{"error_msg": "...", "error_code": "DNS.0101"}`。

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
struct HuaweiErrorBody {
    #[serde(default)]
    error_msg: Option<String>,
    #[serde(default)]
    error_code: Option<String>,
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

/// 提取 `error_msg`（附带 error_code 供排查）；无法解析/为空时退回原始响应体。
fn parse_message(body: &str) -> String {
    if body.trim().is_empty() {
        return "服务商返回空错误体".to_string();
    }
    let parsed = serde_json::from_str::<HuaweiErrorBody>(body).ok();
    let msg = parsed
        .as_ref()
        .and_then(|b| b.error_msg.clone())
        .filter(|m| !m.is_empty());
    match msg {
        Some(m) => match parsed.as_ref().and_then(|b| b.error_code.clone()) {
            Some(code) => format!("{m} ({code})"),
            None => m,
        },
        None => body.trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_matches_m9_dns008_table() {
        let auth_body = r#"{"error_msg":"鉴权失败","error_code":"APIGW.0301"}"#;
        assert!(matches!(map_error(401, None, auth_body), ProviderError::Auth { .. }));
        assert!(matches!(map_error(403, None, auth_body), ProviderError::Auth { .. }));
        let err = map_error(400, None, r#"{"error_msg":"参数错误","error_code":"DNS.0104"}"#);
        match err {
            ProviderError::InvalidParameter { detail } => {
                assert!(detail.contains("DNS.0104"), "detail 应含错误码: {detail}")
            }
            other => panic!("期望 InvalidParameter，得到 {other:?}"),
        }
        assert!(matches!(
            map_error(404, None, r#"{"error_msg":"not found","error_code":"DNS.0101"}"#),
            ProviderError::NotFound { .. }
        ));
        match map_error(429, Some(5), r#"{"error_msg":"请求超限","error_code":"APIGW.0308"}"#) {
            ProviderError::RateLimited { retry_after } => assert_eq!(retry_after, Some(5)),
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
}
