//! M9-DNS014: OVH 错误 → 统一 ProviderError 映射
//!
//! 对照 `M9-DNS014_OVH适配.md` 错误码映射表：
//! - 401（NOT_CREDENTIALS 等）/ 403（NOT_GRANTED_CALL 等）→ Auth
//! - 400（INVALID_...）→ InvalidParameter
//! - 404（NOT_FOUND）→ NotFound
//! - 429 → RateLimited
//! - 5xx → Server
//!
//! 错误体形如 `{"class":"Client::NotFound","message":"..."}`，提取 message 进详情。

use crate::provider::ProviderError;

/// OVH HTTP 错误 → 统一错误。
pub(crate) fn map_http_error(status: u16, body: &str) -> ProviderError {
    let detail = extract_message(body).unwrap_or_else(|| body.to_string());
    match status {
        401 | 403 => ProviderError::Auth {
            detail: format!("OVH HTTP {status}: {detail}"),
        },
        400 => ProviderError::InvalidParameter {
            detail: format!("OVH HTTP {status}: {detail}"),
        },
        404 => ProviderError::NotFound {
            what: format!("OVH HTTP {status}: {detail}"),
        },
        429 => ProviderError::RateLimited { retry_after: None },
        500..=599 => ProviderError::Server {
            status,
            body: body.to_string(),
        },
        _ => ProviderError::Other(format!("OVH HTTP {status}: {body}")),
    }
}

/// 从 OVH 错误体提取 `message` 字段（`{"class":"...","message":"..."}`）。
fn extract_message(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("message")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
}
