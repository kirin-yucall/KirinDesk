//! Cloudflare 错误映射（M9-DNS002 §三「错误码映射表」）
//!
//! 规则：
//! - 响应体 `errors[].code == 9109`（无效 Token）→ `Auth`（优先于 HTTP 状态判断）
//! - 401/403 → `Auth`
//! - 400（如 81057 记录冲突、参数缺失）→ `InvalidParameter`
//! - 404 → `NotFound`
//! - 429 → `RateLimited`（`retry_after` 由客户端按 Retry-After 头退避后填充）
//! - 其余 5xx → `Server`
//! - 其他状态 → `Other`（防御）
//!
//! 凭据不参与任何错误文案/日志输出（原始响应体仅进日志）。

use crate::provider::ProviderError;
use reqwest::StatusCode;
use serde_json::Value;

/// 响应体截断摘要（最多 300 字符，防超长错误体刷屏）。
pub(crate) fn summarize(body: &str) -> String {
    let trimmed = body.trim();
    let head: String = trimmed.chars().take(300).collect();
    if trimmed.chars().count() > 300 {
        format!("{head}…")
    } else {
        head
    }
}

/// 提取 Cloudflare 错误体首条 message（无则回退摘要）。
fn cf_message(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.pointer("/errors/0/message").and_then(|m| m.as_str()).map(String::from))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| summarize(body))
}

/// 提取 Cloudflare 错误码（errors[0].code）。
pub(crate) fn cf_error_code(body: &str) -> Option<u32> {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.pointer("/errors/0/code").and_then(|c| c.as_u64()).map(|c| c as u32))
}

/// HTTP 状态 + 响应体 → 统一 `ProviderError`。
pub(crate) fn map_error(status: StatusCode, body: &str) -> ProviderError {
    // 9109 = 无效 API Token（部分端点以 400 返回）→ 一律 Auth。
    if cf_error_code(body) == Some(9109) {
        return ProviderError::Auth { detail: cf_message(body) };
    }
    match status.as_u16() {
        401 | 403 => ProviderError::Auth { detail: cf_message(body) },
        400 => ProviderError::InvalidParameter { detail: cf_message(body) },
        404 => ProviderError::NotFound { what: cf_message(body) },
        429 => ProviderError::RateLimited { retry_after: None },
        500..=599 => ProviderError::Server { status: status.as_u16(), body: summarize(body) },
        other => ProviderError::Other(format!("Cloudflare 返回未知状态 {other}: {}", summarize(body))),
    }
}

/// 限流（429 退避重试后仍失败时由客户端调用；retry_after 取 Retry-After 头秒数）。
pub(crate) fn rate_limited(retry_after: Option<u64>) -> ProviderError {
    ProviderError::RateLimited { retry_after }
}
