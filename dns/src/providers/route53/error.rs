//! Route53 响应错误 → 统一 ProviderError 映射（M9-DNS005 §三 错误码映射表）
//!
//! Route53 错误响应为 XML：`<ErrorResponse><Error><Code>...</Code><Message>...</Message></Error>...`。
//! 优先级：先按 XML `Code` 判定（更精确），无 XML 时按 HTTP 状态码兜底。

use crate::provider::ProviderError;
use super::xml;

/// 从错误响应体提取 Route53 `Code`（无 ErrorResponse 结构 → None）。
fn route53_code(body: &str) -> Option<String> {
    if !body.contains("ErrorResponse") && !body.contains("<Error>") {
        return None;
    }
    xml::element_text(body, "Code")
}

/// 映射 Route53 响应为统一错误（2xx 返回 Ok）。
///
/// `retry_after` 来自 `Retry-After` 响应头（429/SlowDown 时使用）。
pub fn map_response(status: u16, body: &str, retry_after: Option<&str>) -> Result<(), ProviderError> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    let code = route53_code(body);
    let detail = match (&code, body.trim().is_empty()) {
        (Some(c), _) => format!("Route53 错误 {status} [{c}]: {}", truncate(body, 300)),
        (None, false) => format!("Route53 错误 {status}: {}", truncate(body, 300)),
        (None, true) => format!("Route53 错误 {status}"),
    };

    if let Some(c) = &code {
        let c = c.as_str();
        // 凭据/签名错误 → Auth（InvalidClientTokenId / AccessDenied / SignatureDoesNotMatch）
        if matches!(
            c,
            "InvalidClientTokenId" | "AccessDenied" | "SignatureDoesNotMatch" | "ExpiredToken"
                | "MissingAuthenticationToken"
        ) || (401..=403).contains(&status)
        {
            return Err(ProviderError::Auth { detail });
        }
        // 资源不存在 → NotFound
        if matches!(c, "NoSuchHostedZone" | "NoSuchChange" | "NoSuchId" | "NoSuchGeoLocation")
            || status == 404
        {
            return Err(ProviderError::NotFound {
                what: xml::element_text(body, "Message").unwrap_or_else(|| detail.clone()),
            });
        }
        // 参数/记录集非法 → InvalidParameter
        if matches!(
            c,
            "InvalidInput" | "InvalidChangeBatch" | "InvalidArgument" | "InvalidType" | "InvalidDomainName"
        ) || (400..=422).contains(&status)
        {
            return Err(ProviderError::InvalidParameter { detail });
        }
        // 限流 → RateLimited（Throttling / SlowDown / TooManyRequests）
        if matches!(c, "Throttling" | "SlowDown" | "TooManyRequests" | "RequestLimitExceeded")
            || status == 429
        {
            return Err(ProviderError::RateLimited {
                retry_after: parse_retry_after(retry_after),
            });
        }
        // 服务端错误
        if (500..=599).contains(&status) || matches!(c, "InternalFailure" | "ServiceUnavailable") {
            return Err(ProviderError::Server { status, body: truncate(body, 1000) });
        }
    }
    // 兜底（无 ErrorResponse XML 或未命中任何分支）。
    match status {
        401..=403 => Err(ProviderError::Auth { detail }),
        // 404 先于 400..=422 区间匹配。
        404 => Err(ProviderError::NotFound { what: detail }),
        400..=422 => Err(ProviderError::InvalidParameter { detail }),
        429 => Err(ProviderError::RateLimited {
            retry_after: parse_retry_after(retry_after),
        }),
        500..=599 => Err(ProviderError::Server {
            status,
            body: truncate(body, 1000),
        }),
        _ => Err(ProviderError::Server { status, body: truncate(body, 1000) }),
    }
}

/// 是否属于「记录集已被删除」类错误（delete 幂等判定用）：
/// Route53 对已不存在的记录集执行 DELETE 返回 400 InvalidChangeBatch，
/// Message 形如 "Tried to delete resource record set ... but it was not found" /
/// "... does not exist"。
pub fn is_deleted_set_race(err: &ProviderError) -> bool {
    match err {
        ProviderError::InvalidParameter { detail } => {
            let d = detail.to_ascii_lowercase();
            (d.contains("invalidchangebatch") || d.contains("invalid change batch"))
                && (d.contains("not found") || d.contains("does not exist") || d.contains("not exist"))
        }
        _ => false,
    }
}

fn parse_retry_after(retry_after: Option<&str>) -> Option<u64> {
    retry_after.and_then(|v| v.trim().parse::<u64>().ok())
}

/// 截断长响应体（错误 detail 防日志爆炸；凭据绝不入内——Route53 错误体不含凭据）。
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERR_XML: &str = r#"<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <Error><Type>Sender</Type><Code>{code}</Code><Message>{msg}</Message></Error>
</ErrorResponse>"#;

    fn err(code: &str, msg: &str) -> String {
        ERR_XML.replace("{code}", code).replace("{msg}", msg)
    }

    #[test]
    fn auth_errors_by_code() {
        for code in ["InvalidClientTokenId", "AccessDenied", "SignatureDoesNotMatch"] {
            let e = map_response(403, &err(code, "denied"), None).unwrap_err();
            assert!(matches!(e, ProviderError::Auth { .. }), "{code}: {e:?}");
        }
    }

    #[test]
    fn invalid_parameter_and_not_found_by_code() {
        let e = map_response(400, &err("InvalidChangeBatch", "bad batch"), None).unwrap_err();
        assert!(matches!(e, ProviderError::InvalidParameter { .. }));
        let e = map_response(400, &err("NoSuchHostedZone", "no zone Z123"), None).unwrap_err();
        assert!(matches!(e, ProviderError::NotFound { .. }));
    }

    #[test]
    fn rate_limited_with_retry_after_header() {
        let e = map_response(429, &err("Throttling", "slow down"), Some("42")).unwrap_err();
        match e {
            ProviderError::RateLimited { retry_after } => assert_eq!(retry_after, Some(42)),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn server_error_status_fallback() {
        let e = map_response(500, "Internal server error (no xml)", None).unwrap_err();
        assert!(matches!(e, ProviderError::Server { status: 500, .. }));
        // 2xx 返回 Ok。
        assert!(map_response(200, "", None).is_ok());
        assert!(map_response(201, "", None).is_ok());
    }

    #[test]
    fn deleted_set_race_detection() {
        let e = ProviderError::InvalidParameter {
            detail: "Route53 错误 400 [InvalidChangeBatch]: Tried to delete resource record set \
                     example.com. A but it was not found"
                .to_string(),
        };
        assert!(is_deleted_set_race(&e));
        let e2 = ProviderError::InvalidParameter {
            detail: "Route53 错误 400 [InvalidChangeBatch]: other reason".to_string(),
        };
        assert!(!is_deleted_set_race(&e2));
    }
}
