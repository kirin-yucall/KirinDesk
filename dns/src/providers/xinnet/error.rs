//! M9-DNS020: 新网响应解析与错误映射
//!
//! ⚠️ 新网开放平台文档不透明（《M9-DNS020_新网适配.md》§一）：本模块的响应
//! 形状 `{"code":200,"message":"ok","data":...}` 为**占位约定**（兼容 200/0
//! 两种成功码），**实现前须向新网官方获取正式 API 文档**核对后修订。
//!
//! 错误映射（M9-DNS020 §三）：
//! HTTP 401/403（含 IP 白名单拒绝）→ `Auth`；400 → `InvalidParameter`；
//! 404 → `NotFound`；429 → `RateLimited`；5xx → `Server`；
//! HTTP 200 但业务 `code` 非成功 → 按 code 二次映射，其余 → `Other`。

use crate::provider::ProviderError;
use serde_json::Value;

/// 请求响应 → JSON；业务失败/HTTP 失败统一映射为 [`ProviderError`]。
pub(crate) async fn parse_response(
    resp: reqwest::Response,
) -> Result<Value, ProviderError> {
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let body = resp.text().await.unwrap_or_default();

    if status == 429 {
        return Err(ProviderError::RateLimited { retry_after });
    }
    if (200..300).contains(&status) {
        if let Ok(v) = serde_json::from_str::<Value>(&body) {
            if is_success(&v) {
                return Ok(v);
            }
            return Err(business_error(&v, &body));
        }
        // 非 JSON（官方也可能返回 XML）→ 占位：按纯文本 "success" 判定。
        if body.contains("success") {
            return Ok(Value::Null);
        }
        return Err(ProviderError::Other(format!("响应无法解析: {body}")));
    }

    let detail = body;
    Err(match status {
        401 | 403 => ProviderError::Auth { detail },
        400 | 422 => ProviderError::InvalidParameter { detail },
        404 => ProviderError::NotFound { what: detail },
        500..=599 => ProviderError::Server { status, body: detail },
        _ => ProviderError::Other(format!("新网返回 {status}: {detail}")),
    })
}

/// 成功判定（占位约定）：`code == 200` 或 `code == 0`。
fn is_success(v: &Value) -> bool {
    matches!(v.get("code").and_then(|c| c.as_i64()), Some(200) | Some(0))
}

/// HTTP 200 但业务 `code` 非成功 → 按 code 二次映射。
fn business_error(v: &Value, raw: &str) -> ProviderError {
    let msg = v
        .get("message")
        .and_then(|m| m.as_str())
        .or_else(|| v.get("msg").and_then(|m| m.as_str()))
        .unwrap_or(raw)
        .to_string();
    let code = v.get("code").and_then(|c| c.as_i64());
    match code {
        Some(401 | 403) => ProviderError::Auth { detail: msg },
        Some(400 | 422) => ProviderError::InvalidParameter { detail: msg },
        Some(404) => ProviderError::NotFound { what: msg },
        Some(429) => ProviderError::RateLimited { retry_after: None },
        _ => ProviderError::Other(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn success_detection_shapes() {
        assert!(is_success(&json!({"code": 200, "message": "ok"})));
        assert!(is_success(&json!({"code": 0})));
        assert!(!is_success(&json!({"code": 404, "message": "not found"})));
    }

    #[test]
    fn business_error_mapping() {
        assert!(matches!(
            business_error(&json!({"code": 404, "message": "域名不存在"}), ""),
            ProviderError::NotFound { .. }
        ));
        assert!(matches!(
            business_error(&json!({"code": 401, "message": "IP 不在白名单"}), ""),
            ProviderError::Auth { .. }
        ));
        assert!(matches!(
            business_error(&json!({"code": 100, "message": "其他"}), ""),
            ProviderError::Other(_)
        ));
    }
}
