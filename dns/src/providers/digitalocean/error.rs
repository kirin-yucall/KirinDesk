//! DigitalOcean 错误映射（M9-DNS010 §三「错误码映射表」）
//!
//! 规则：
//! - 401/403（token 无效 / 只读无权限）→ `Auth`
//! - 400（如错误码 40001 参数非法）→ `InvalidParameter`
//! - 404 → `NotFound`
//! - 429 → `RateLimited`（`retry_after` 由客户端按 Retry-After 头退避后填充）
//! - 其余 5xx → `Server`
//! - 其他状态 → `Other`（防御）
//!
//! 错误体形状：`{"id": "unauthenticated", "message": "..."}`，文案仅进日志。

use crate::provider::ProviderError;
use reqwest::StatusCode;
use serde_json::Value;

/// 响应体截断摘要（最多 300 字符）。
pub(crate) fn summarize(body: &str) -> String {
    let trimmed = body.trim();
    let head: String = trimmed.chars().take(300).collect();
    if trimmed.chars().count() > 300 {
        format!("{head}…")
    } else {
        head
    }
}

/// 提取 DO 错误体 message 字段（无则回退摘要）。
fn do_message(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| summarize(body))
}

/// HTTP 状态 + 响应体 → 统一 `ProviderError`。
pub(crate) fn map_error(status: StatusCode, body: &str) -> ProviderError {
    match status.as_u16() {
        401 | 403 => ProviderError::Auth { detail: do_message(body) },
        400 => ProviderError::InvalidParameter { detail: do_message(body) },
        404 => ProviderError::NotFound { what: do_message(body) },
        429 => ProviderError::RateLimited { retry_after: None },
        500..=599 => ProviderError::Server { status: status.as_u16(), body: summarize(body) },
        other => ProviderError::Other(format!("DigitalOcean 返回未知状态 {other}: {}", summarize(body))),
    }
}

/// 限流（429 退避重试后仍失败时由客户端调用）。
pub(crate) fn rate_limited(retry_after: Option<u64>) -> ProviderError {
    ProviderError::RateLimited { retry_after }
}
