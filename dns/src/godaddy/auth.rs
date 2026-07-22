/// GoDaddy API authentication using SSO key format.
///
/// Format: `sso-key {api_key}:{api_secret}`
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

    /// Generate the Authorization header value.
    ///
    /// Format: `sso-key {key}:{secret}`
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

    #[test]
    fn test_auth_header_with_special_chars() {
        let auth = Auth::new("abc123", "xyz!@#");
        assert_eq!(
            auth.authorization_header(),
            "sso-key abc123:xyz!@#"
        );
    }
}
