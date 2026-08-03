//! GoDaddy API 认证（sso-key，M9-DNS001 §一）。
//!
//! 认证头格式：`Authorization: sso-key {api_key}:{api_secret}`。
//! 凭据字段不公开（无 `Debug` 派生），且不参与 `Display`/日志输出
//! （M9-DNS000 §五：凭据不打印）。

/// GoDaddy sso-key 认证。
pub struct Auth {
    api_key: String,
    api_secret: String,
}

impl Auth {
    pub fn new(api_key: impl Into<String>, api_secret: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            api_secret: api_secret.into(),
        }
    }

    /// 生成 Authorization 请求头值：`sso-key {key}:{secret}`。
    pub fn authorization_header(&self) -> String {
        format!("sso-key {}:{}", self.api_key, self.api_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_header_format() {
        let auth = Auth::new("test_key", "test_secret");
        assert_eq!(
            auth.authorization_header(),
            "sso-key test_key:test_secret"
        );
    }
}
