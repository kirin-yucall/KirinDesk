//! M9-DNS012: Linode（Akamai）错误映射
//!
//! 依据《M9-DNS012_LinodeAkamai适配.md》§三错误码映射表：
//!
//! | Linode 状态 | 触发 | 统一错误 |
//! |------------|------|---------|
//! | 401 | token 无效 | `Auth` |
//! | 403 | scope 不足 | `Auth` |
//! | 400/422（`record_data_invalid` 等） | 记录参数非法 | `InvalidParameter` |
//! | 404（`not_found`） | 域名/记录不存在 | `NotFound` |
//! | 429 | 限流（`Retry-After` 头） | `RateLimited` |
//! | 5xx | 服务端 | `Server` |
//!
//! 错误体格式：`{"errors":[{"reason":"...","field":"..."}]}`，
//! 取第一条 `reason` 作为错误详情（凭据/密钥不会出现在其中）。

use crate::provider::ProviderError;
use serde_json::Value;

/// 2xx 响应 → 解析为 JSON（空体 → `Null`）；
/// 非 2xx → 按状态码映射为统一 [`ProviderError`]。
pub(crate) async fn ensure_success(
    resp: reqwest::Response,
) -> Result<Value, ProviderError> {
    let status = resp.status();
    if status.is_success() {
        let bytes = resp.bytes().await?;
        if bytes.is_empty() {
            // DELETE 等成功但无响应体的情况。
            return Ok(Value::Null);
        }
        return Ok(serde_json::from_slice(&bytes)?);
    }
    Err(map_status(resp).await)
}

/// 非 2xx 响应 → 统一 [`ProviderError`]（按 M9-DNS012 §三映射表）。
pub(crate) async fn map_status(resp: reqwest::Response) -> ProviderError {
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let body = resp.text().await.unwrap_or_default();
    let detail = first_reason(&body).unwrap_or_else(|| body.clone());
    match status {
        401 | 403 => ProviderError::Auth { detail },
        400 | 422 => ProviderError::InvalidParameter { detail },
        404 => ProviderError::NotFound { what: detail },
        429 => ProviderError::RateLimited { retry_after },
        500..=599 => ProviderError::Server { status, body },
        _ => ProviderError::Other(format!("Linode 返回 {status}: {detail}")),
    }
}

/// 从 Linode 错误体 `{"errors":[{"reason":"...","field":"..."}]}` 提取第一条 reason。
fn first_reason(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let reason = v.get("errors")?.as_array()?.first()?.get("reason")?.as_str()?;
    Some(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_reason_from_linode_error_body() {
        let body = r#"{"errors":[{"reason":"record_data_invalid","field":"target"}]}"#;
        assert_eq!(first_reason(body).as_deref(), Some("record_data_invalid"));
        // 非标准错误体 → None，回退为原文。
        assert_eq!(first_reason("plain text"), None);
        assert_eq!(first_reason(r#"{"foo":1}"#), None);
    }
}
