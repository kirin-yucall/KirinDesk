//! M9-DNS019: 西部数码响应解析与错误映射
//!
//! 官方《西部数码业务API文档 V2.0》统一返回：
//! `{"result":200,"clientid":"...","msg":"...","errcode":N,"data":...}`
//! （`result` 200 成功，其余失败）。
//!
//! 兼容处理：
//! - `{"status":200,"success":true}` 形态（任务文档要求的 status/success 字段）；
//! - 纯文本 `success`（acme.sh `dns_west_cn.sh` 以文本包含判定）；
//! - 纯文本 `no records`（列表为空）。
//!
//! 错误映射（《M9-DNS019_西部数码适配.md》§三）：
//! HTTP 401/403 → `Auth`；400 → `InvalidParameter`；404 → `NotFound`；
//! 429 → `RateLimited`；5xx → `Server`；HTTP 200 但 `result != 200` →
//! 按 `errcode` 二次映射，其余 → `Other`。

use crate::provider::ProviderError;
use serde_json::{json, Value};

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
        // 非 JSON 响应：acme.sh 以文本 "success" 判定成功；"no records" 视为空列表。
        if body.contains("success") {
            return Ok(Value::Null);
        }
        if body.contains("no records") {
            return Ok(json!({ "data": [] }));
        }
        return Err(ProviderError::Other(format!("响应无法解析: {body}")));
    }

    let detail = body;
    Err(match status {
        401 | 403 => ProviderError::Auth { detail },
        400 | 422 => ProviderError::InvalidParameter { detail },
        404 => ProviderError::NotFound { what: detail },
        500..=599 => ProviderError::Server { status, body: detail },
        _ => ProviderError::Other(format!("西部数码返回 {status}: {detail}")),
    })
}

/// 成功判定：`result==200` 或 `success==true` 或 `status==200`。
fn is_success(v: &Value) -> bool {
    v.get("result").and_then(|x| x.as_i64()) == Some(200)
        || v.get("success").and_then(|x| x.as_bool()) == Some(true)
        || v.get("status").and_then(|x| x.as_i64()) == Some(200)
}

/// HTTP 200 但业务失败（`result != 200`）→ 按 `errcode`/`status` 二次映射。
fn business_error(v: &Value, raw: &str) -> ProviderError {
    let msg = v
        .get("msg")
        .and_then(|m| m.as_str())
        .or_else(|| v.get("message").and_then(|m| m.as_str()))
        .unwrap_or(raw)
        .to_string();
    let code = v
        .get("errcode")
        .and_then(|c| c.as_i64())
        .or_else(|| v.get("status").and_then(|c| c.as_i64()))
        // `result` 为官方文档的业务状态（200 成功，其余失败）——失败码二次映射。
        .or_else(|| v.get("result").and_then(|c| c.as_i64()));
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

    #[test]
    fn success_detection_shapes() {
        assert!(is_success(&json!({"result": 200, "clientid": "c"})));
        assert!(is_success(&json!({"status": 200, "success": true})));
        assert!(is_success(&json!({"success": true})));
        assert!(!is_success(&json!({"result": 404, "msg": "域名不存在"})));
        assert!(!is_success(&json!({"status": 1})));
    }

    #[test]
    fn business_error_mapping() {
        assert!(matches!(
            business_error(&json!({"result": 404, "msg": "域名不存在"}), ""),
            ProviderError::NotFound { .. }
        ));
        assert!(matches!(
            business_error(&json!({"errcode": 401, "msg": "token 无效"}), ""),
            ProviderError::Auth { .. }
        ));
        assert!(matches!(
            business_error(&json!({"errcode": 429, "msg": "频率超限"}), ""),
            ProviderError::RateLimited { .. }
        ));
        assert!(matches!(
            business_error(&json!({"result": 100, "msg": "其他业务错误"}), ""),
            ProviderError::Other(_)
        ));
    }
}
