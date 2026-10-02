//! M9-DNS017: 火山引擎错误 → 统一 `ProviderError` 映射
//!
//! 新版 OpenAPI（2018-08-01）错误体形如：
//! `{"ResponseMetadata": {"RequestId": "...", "Error": {"Code": "...", "Message": "..."}}}`，
//! 老版本也有顶层 `Code` 形态。映射以错误码为主、状态码兜底
//! （对照 `M9-DNS017` §三 错误码映射表）。

use crate::provider::ProviderError;

/// 检查响应：成功 → `Ok(JSON Value)`；失败 → 映射后的统一错误。
///
/// 返回的 Value 为响应整体；调用方用 [`unwrap_result`] 提取 `Result` 部分
/// （兼容新老两种响应包装形态）。
pub fn check_response(status: u16, body: &str) -> Result<serde_json::Value, ProviderError> {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return if status >= 400 {
                Err(ProviderError::Server {
                    status,
                    body: body.to_string(),
                })
            } else {
                Err(ProviderError::Other(format!("响应体不是 JSON: {body}")))
            };
        }
    };
    if let Some((code, message)) = extract_error(&v) {
        return Err(map_error_code(&code, &message, status, body));
    }
    if status >= 400 {
        return Err(ProviderError::Server {
            status,
            body: body.to_string(),
        });
    }
    Ok(v)
}

/// 从响应中提取 (错误码, 消息)：兼容 `ResponseMetadata.Error` / 顶层 `Error` / 顶层 `Code`。
fn extract_error(v: &serde_json::Value) -> Option<(String, String)> {
    let err = v
        .pointer("/ResponseMetadata/Error")
        .or_else(|| v.get("Error"))
        .or_else(|| v.get("err"))
        .cloned();
    if let Some(e) = err {
        let code = e
            .get("Code")
            .or_else(|| e.get("code"))
            .and_then(|c| c.as_str())
            .unwrap_or_default()
            .to_string();
        let message = e
            .get("Message")
            .or_else(|| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or_default()
            .to_string();
        if !code.is_empty() {
            return Some((code, message));
        }
    }
    // 老形态顶层 Code。
    if let Some(code) = v.get("Code").and_then(|c| c.as_str()) {
        if !code.is_empty() && code != "Success" {
            let message = v
                .get("Message")
                .and_then(|m| m.as_str())
                .unwrap_or_default()
                .to_string();
            return Some((code.to_string(), message));
        }
    }
    None
}

/// 提取业务数据：新版包在 `Result` 中，老版在顶层。
pub fn unwrap_result(v: serde_json::Value) -> serde_json::Value {
    match v.get("Result") {
        Some(r) => r.clone(),
        None => v,
    }
}

/// 错误码 → 统一错误（`M9-DNS017` §三 映射表 + 状态码兜底）。
fn map_error_code(code: &str, message: &str, status: u16, body: &str) -> ProviderError {
    match code {
        // 认证：AK/SK 无效、无权限。
        "InvalidAccessKey" | "InvalidAccessKeyId" | "InvalidCredential"
        | "AuthenticationFailed" | "PermissionDenied" | "Forbidden" | "Denied"
        | "UnauthorizedOperation" | "ErrAuthFailure" | "InvalidSecretKey" => ProviderError::Auth {
            detail: format!("{code}: {message}"),
        },
        // 参数非法。
        _ if code.starts_with("InvalidParameter")
            || code.starts_with("ErrParam")
            || matches!(
                code,
                "MissingParameter" | "ParamMissing" | "InvalidArgument" | "InvalidParam"
            ) =>
        {
            ProviderError::InvalidParameter {
                detail: format!("{code}: {message}"),
            }
        }
        // 不存在。
        "ZoneNotFound" | "RecordNotFound" | "RecordSetNotFound" | "ErrZoneNotFound"
        | "ErrDBNotFound" | "NotFound" | "NotExist" => ProviderError::NotFound {
            what: format!("{code}: {message}"),
        },
        // 限流。
        "Throttling" | "ThrottlingException" | "TooManyRequests" | "RateLimitExceeded"
        | "ErrRateLimit" => ProviderError::RateLimited { retry_after: None },
        // 服务端。
        "InternalError" | "ErrInternalServer" | "ErrInternal" | "ServiceUnavailable" => {
            ProviderError::Server {
                status,
                body: body.to_string(),
            }
        }
        // 未知错误码：5xx 归 Server，其余归 Other。
        _ => {
            if status >= 500 {
                ProviderError::Server {
                    status,
                    body: body.to_string(),
                }
            } else {
                ProviderError::Other(format!("{code}: {message}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_ok() {
        let body = r#"{"ResponseMetadata":{"RequestId":"r1"},"Result":{"Total":1}}"#;
        let v = check_response(200, body).unwrap();
        assert_eq!(unwrap_result(v)["Total"], 1);
    }

    #[test]
    fn auth_codes() {
        for code in ["InvalidAccessKey", "PermissionDenied"] {
            let body = format!(
                r#"{{"ResponseMetadata":{{"RequestId":"r","Error":{{"Code":"{code}","Message":"bad"}}}}}}"#
            );
            assert!(matches!(
                check_response(403, &body).unwrap_err(),
                ProviderError::Auth { .. }
            ));
        }
    }

    #[test]
    fn invalid_parameter_and_not_found() {
        let body = r#"{"ResponseMetadata":{"Error":{"Code":"InvalidParameter","Message":"bad"}}}"#;
        assert!(matches!(
            check_response(400, body).unwrap_err(),
            ProviderError::InvalidParameter { .. }
        ));
        let body = r#"{"ResponseMetadata":{"Error":{"Code":"ZoneNotFound","Message":"no zone"}}}"#;
        assert!(matches!(
            check_response(404, body).unwrap_err(),
            ProviderError::NotFound { .. }
        ));
    }

    #[test]
    fn rate_limited_and_server() {
        let body = r#"{"ResponseMetadata":{"Error":{"Code":"Throttling","Message":"slow"}}}"#;
        assert!(matches!(
            check_response(429, body).unwrap_err(),
            ProviderError::RateLimited { .. }
        ));
        let body = r#"{"ResponseMetadata":{"Error":{"Code":"InternalError","Message":"boom"}}}"#;
        assert!(matches!(
            check_response(500, body).unwrap_err(),
            ProviderError::Server { .. }
        ));
    }

    #[test]
    fn legacy_top_level_code() {
        let body = r#"{"Code":"InvalidAccessKeyId","Message":"bad","RequestId":"r"}"#;
        assert!(matches!(
            check_response(401, body).unwrap_err(),
            ProviderError::Auth { .. }
        ));
    }
}
