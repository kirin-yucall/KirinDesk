//! M9-DNS003: 阿里云云解析错误码 → 统一 `ProviderError` 映射
//!
//! 阿里云 RPC 错误响应体形如 `{"Code": "...", "Message": "...", "RequestId": "...", "HostId": "..."}`，
//! 多数错误伴随 4xx 状态码（部分错误也以 200 返回 Code 字段）。映射表见
//! `M9-DNS003_阿里云云解析适配.md` §三，对照 `M9-DNS000` §三 统一错误规范。

use crate::provider::ProviderError;

/// 检查一次响应：成功 → `Ok(JSON Value)`；失败 → 映射后的统一错误。
pub fn map_response(status: u16, body: &str) -> Result<serde_json::Value, ProviderError> {
    // 解析响应体（成功与失败均为 JSON）。
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            // 非 JSON 响应：按状态码兜底。
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
    // 错误特征：存在非 Success 的 Code 字段。
    if let Some(code) = v.get("Code").and_then(|c| c.as_str()) {
        if code != "Success" {
            let msg = v
                .get("Message")
                .and_then(|m| m.as_str())
                .unwrap_or_default();
            return Err(map_error_code(code, msg, status, body));
        }
    }
    // 无 Code 但状态码异常（如网关 5xx）。
    if status >= 400 {
        return Err(ProviderError::Server {
            status,
            body: body.to_string(),
        });
    }
    Ok(v)
}

/// 错误码 → 统一错误（`M9-DNS003` §三 错误码映射表）。
fn map_error_code(code: &str, message: &str, status: u16, body: &str) -> ProviderError {
    match code {
        // 认证：AK/SK 无效、无权限、IP 白名单拒绝。
        "InvalidAccessKeyId" | "InvalidAccessKeyId.NotFound" | "InvalidAccessKeyId.Malformed"
        | "Forbidden" | "Forbidden.AccessKeyNotEnabled" | "SignatureDoesNotMatch" => {
            ProviderError::Auth {
                detail: format!("{code}: {message}"),
            }
        }
        // 参数非法（含前缀匹配：InvalidParameter.* / InvalidDomainName 等）。
        _ if code.starts_with("InvalidParameter") || matches!(code, "InvalidDomainName" | "InvalidRR" | "InvalidValue" | "InvalidType" | "InvalidTTL" | "InvalidRecordType") => {
            ProviderError::InvalidParameter {
                detail: format!("{code}: {message}"),
            }
        }
        // 记录/域名不存在。
        "DomainRecordNotBelongToUser" | "DomainRecordNotFound" | "RecordNotFound"
        | "RecordNotExist" | "DomainNotExist" | "DomainNotFound" => ProviderError::NotFound {
            what: format!("{code}: {message}"),
        },
        // 限流：账号级 QPS（RPC 默认较低）。
        "Throttling" | "Throttling.User" | "QpsLimitExceeded" | "QPSLimitExceeded"
        | "FlowControl" => ProviderError::RateLimited { retry_after: None },
        // 服务端错误。
        "InternalError" | "ServiceUnavailable" | "SystemBusy" => {
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
    fn auth_codes() {
        for code in ["InvalidAccessKeyId.NotFound", "Forbidden"] {
            let body = format!(
                r#"{{"Code":"{code}","Message":"bad key","RequestId":"r1"}}"#
            );
            let err = map_response(403, &body).unwrap_err();
            assert!(matches!(err, ProviderError::Auth { .. }), "{code}");
        }
    }

    #[test]
    fn invalid_parameter_codes() {
        let body = r#"{"Code":"InvalidDomainName","Message":"domain bad","RequestId":"r2"}"#;
        assert!(matches!(
            map_response(400, body).unwrap_err(),
            ProviderError::InvalidParameter { .. }
        ));
        let body = r#"{"Code":"InvalidParameter.DomainName","Message":"x","RequestId":"r3"}"#;
        assert!(matches!(
            map_response(400, body).unwrap_err(),
            ProviderError::InvalidParameter { .. }
        ));
    }

    #[test]
    fn not_found_codes() {
        let body = r#"{"Code":"RecordNotFound","Message":"no","RequestId":"r4"}"#;
        assert!(matches!(
            map_response(400, body).unwrap_err(),
            ProviderError::NotFound { .. }
        ));
    }

    #[test]
    fn rate_limited_codes() {
        let body = r#"{"Code":"Throttling","Message":"slow down","RequestId":"r5"}"#;
        assert!(matches!(
            map_response(400, body).unwrap_err(),
            ProviderError::RateLimited { .. }
        ));
        let body = r#"{"Code":"QpsLimitExceeded","Message":"qps","RequestId":"r6"}"#;
        assert!(matches!(
            map_response(400, body).unwrap_err(),
            ProviderError::RateLimited { .. }
        ));
    }

    #[test]
    fn success_and_server_fallback() {
        // 成功响应（无 Code）→ Ok。
        let body = r#"{"TotalCount":1,"Domains":{"Domain":[{"DomainName":"example.com"}]}}"#;
        assert!(map_response(200, body).is_ok());
        // 未知码 + 5xx → Server。
        let body = r#"{"Code":"SomethingWeird","Message":"x","RequestId":"r7"}"#;
        assert!(matches!(
            map_response(500, body).unwrap_err(),
            ProviderError::Server { .. }
        ));
    }
}
