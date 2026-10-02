//! Google Service Account JWT 断言签发（RFC 7519 / RFC 7523 §2.1，RS256）
//!
//! 流程（M9-DNS007）：
//! 1. 解析 `service_account_json`，提取 `client_email` / `private_key`
//!    （PEM 编码 PKCS#8 RSA 私钥）/ `token_uri`；
//! 2. JWT header = `{"alg":"RS256","typ":"JWT"}`；
//!    claims = `{"iss":client_email,"scope":<Cloud DNS 读写>,"aud":token_uri,
//!    "exp":now+3600,"iat":now}`；
//! 3. RS256 签名（`rsa` crate：PKCS#1 v1.5 填充 + SHA-256），base64url 无填充编码三段。
//!
//! 凭据安全：本模块任何错误信息都不包含私钥 / JWT 内容（凭据绝不打印/进日志）。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::provider::ProviderError;

/// OAuth2 scope：Cloud DNS 记录读写（M9-DNS007 能力全开）。
pub const CLOUD_DNS_SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";

/// 服务账号 JSON 中与本流程相关的字段（其余字段如 project_id 等忽略）。
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccount {
    pub client_email: String,
    /// PEM 编码 PKCS#8 RSA 私钥（"-----BEGIN PRIVATE KEY-----"）。
    pub private_key: String,
    /// 令牌端点；缺省取 Google 官方 `https://oauth2.googleapis.com/token`。
    #[serde(default = "default_token_uri")]
    pub token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

/// 解析 `service_account_json`（构造期调用；失败延迟到首次取令牌时上报）。
pub fn parse_service_account(json: &str) -> Result<ServiceAccount, ProviderError> {
    let sa: ServiceAccount = serde_json::from_str(json).map_err(|e| {
        ProviderError::Auth { detail: format!("service_account_json 解析失败: {e}") }
    })?;
    if sa.client_email.is_empty() || sa.private_key.is_empty() {
        return Err(ProviderError::Auth {
            detail: "service_account_json 缺少 client_email / private_key".to_string(),
        });
    }
    Ok(sa)
}

/// base64url 无填充编码。
fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    typ: &'a str,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
}

/// 构造并签发 JWT 断言（有效期 1 小时，RFC 7523 §2.1）。
///
/// 返回三段 base64url 拼接：`header.claims.signature`。
pub fn build_assertion(sa: &ServiceAccount, now: i64) -> Result<String, ProviderError> {
    let header = b64url(&serde_json::to_vec(&JwtHeader { alg: "RS256", typ: "JWT" })?);
    let claims = b64url(&serde_json::to_vec(&JwtClaims {
        iss: &sa.client_email,
        scope: CLOUD_DNS_SCOPE,
        aud: &sa.token_uri,
        exp: now + 3600,
        iat: now,
    })?);
    let signing_input = format!("{header}.{claims}");
    let signature = sign_rs256(&sa.private_key, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{signature}"))
}

/// RS256 签名：PKCS#1 v1.5 填充 + SHA-256，返回 base64url 编码的签名段。
fn sign_rs256(pem: &str, msg: &[u8]) -> Result<String, ProviderError> {
    let key = RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| {
        ProviderError::Auth { detail: format!("服务账号私钥解析失败（需 PKCS#8 PEM）: {e}") }
    })?;
    // rsa 0.9 的 Pkcs1v15Sign 要求传入「已哈希摘要」（内部按 hash_len 校验），
    // 先对消息做 SHA-256，再由方案补 DigestInfo 前缀与 PKCS#1 v1.5 填充。
    let digest = Sha256::digest(msg);
    let sig = key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .map_err(|e| ProviderError::Auth { detail: format!("JWT RS256 签名失败: {e}") })?;
    let bytes: &[u8] = sig.as_ref();
    Ok(b64url(bytes))
}

/// 测试专用固定 RSA 2048 私钥（PKCS#8 PEM；仅用于单元测试，不得用于生产）。
#[cfg(test)]
pub(crate) const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvmB81TKA0p8f/
FMkmWhFdX7T2t2MH+96UHDwsetRBs/iU6yIgRWIJYSpAcmd80BIGZm6bUWFvQC0j
u2LW71TA6V7AkvM7eNHY13Nz+kLGHPsZVb5CG4SxtroVUXmQbLx9bEAUaerQRJm6
JFuaVvUw5qQp7W4RezhQGHifmJlcyo+0eZ4n/pbh4OkfldZJ2es3pl9+ZLNTNnO9
tURM9CZar8G4AuyQFDci1voG84n/ScOyd826R+w29TpnhIu2S+dO4Zk35glEu6Hg
0wwfVSukLlhYqQAZyBO06UtZa+taw0MAyYopvWq5epGKcqV+RI5WvsBzwTjoniMo
FymbYPhXAgMBAAECggEAGwstR0qxY9qxYTZk0nzNrtlWKCdPX8PpYFtG4zzZovLi
ZqEeJOU6t6IY3UshaCYtmIG/KDms7XLvYNDz5JGAtqNangMj5fVyMFjiZarWDOga
viioAEt3sN0pJK5jMBynHRQGfH5hlUjzeikuWINrCOiEwRZZvOSC5EcYkM/yUsl4
KUBcTBIhXP9A7yRfxywJnwhurLwAqr97pNW8mCXbmKPYGEnWv5yU35HFeQOANXVK
ehgKFpJ5GDHTYOZBYbKKvpeB9XXlZQxDrEKdsH2lharB4r8djZJI9dek8Hx5C+Ro
vsOCe5w1DiuYD1EmZMS3+/tNuB0dx6aqJqYVIp8yYQKBgQDoiSd1d91a9qKIjdos
NbAHrlgEAJ0OMmgsPeQvW0qZUnsc+iqW6sbqWWc5BRegYNLExqFcUaUcEUY0gfIX
Mch6Oz+IvW66XJi/Hrby2UXqgeho23W3ZuqziKQGVVc8HhQ0ASwzaqWHf1A5JkKB
kSnMU662MLwj735GYhJFuQFpYQKBgQDBUA74tAZdINuXNBknZT2dGhauPwCWT1SD
1FdrAMrfGzdz7Woux0RiohUX5KeFG2b7FOmTHPbfwPhE5HPmAUM1c9p1F/kbN/y4
xPfrfbJ6DYgulD4ReqBwy4izyO/U2oScQKa0RNops3WhC6dXJgdS0Oz4iQaHwjcc
y0nlMq0ktwKBgQCRK17Y9PXaHfMmMPitdO7qPKtyBDgIbuueAx17exC9W0LEumDw
Sq3YC+xnKoivdQLgGekOy2G6fgZILX/HfyrbNDXb1fdUnQ428qPgREhjuKoxHCEH
WFbZskpEMe799wFB3iGMD947Ev4wT3RhkxB3IR8HWrF59b/tjLg/ktoQwQKBgFpM
YEHyLcrQr2Jo1psdYnOBHTkVetu7gLn3tUHpY9plpziCnQfu0tXT6lB34Xx+uVLt
iNHMRNFuHUppAG5fBprwXAo4QYdiVq2kbD5XP8hdi9BeNMQLaOhnWprIcKcXz7wB
Qx2Pz+yMxJSOkgNWYzNfHmJV93Pw17eeig0C5/fvAoGAMaHl69f7iYDOVJYIL2CF
y5FAOGkjpOCnIjSI+MMQr1b6Lq4P654+ehbOIdtIh8beYWZ7VJ1j7x+KYrLL0+f6
N+k6cba/vUvFPE1zhv7c+qxRDFgvWUvYO0nO6xMvHv5X976rwq7RSPBK4QD6FJeA
iwyssc13TjKTCxOIruReSFs=
-----END PRIVATE KEY-----";

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;

    fn test_sa() -> ServiceAccount {
        ServiceAccount {
            client_email: "dns-test@my-project.iam.gserviceaccount.com".to_string(),
            private_key: TEST_PRIVATE_KEY_PEM.to_string(),
            token_uri: "https://oauth2.googleapis.com/token".to_string(),
        }
    }

    #[test]
    fn jwt_three_segments_header_and_claims() {
        let jwt = build_assertion(&test_sa(), 1_752_000_000).unwrap();
        let segs: Vec<&str> = jwt.split('.').collect();
        assert_eq!(segs.len(), 3, "JWT 必须为 header.claims.signature 三段");
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segs[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segs[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "dns-test@my-project.iam.gserviceaccount.com");
        assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
        assert_eq!(claims["scope"], CLOUD_DNS_SCOPE);
        assert_eq!(claims["iat"], 1_752_000_000);
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            3600,
            "断言有效期 1 小时"
        );
        // base64url 无填充：不含 '=' 与 '+' '/' 字符
        assert!(!jwt.contains('=') && !jwt.contains('+') && !jwt.contains('/'));
    }

    #[test]
    fn jwt_signature_verifies_with_public_key() {
        // 自洽性验证：用同一密钥对公开钥验签，证明 RS256 签名路径正确。
        let jwt = build_assertion(&test_sa(), 1_752_000_000).unwrap();
        let segs: Vec<&str> = jwt.split('.').collect();
        let key = RsaPrivateKey::from_pkcs8_pem(TEST_PRIVATE_KEY_PEM).unwrap();
        let public_key = key.to_public_key();
        let sig_bytes = URL_SAFE_NO_PAD.decode(segs[2]).unwrap();
        let signing_input = format!("{}.{}", segs[0], segs[1]);
        // rsa 0.9 verify 同样要求预哈希摘要（hash_len 校验），签名以原始字节传入
        public_key
            .verify(
                Pkcs1v15Sign::new::<Sha256>(),
                &Sha256::digest(signing_input.as_bytes()),
                &sig_bytes,
            )
            .unwrap();
    }

    #[test]
    fn parse_service_account_extracts_fields() {
        let json = serde_json::json!({
            "type": "service_account",
            "project_id": "my-project",
            "private_key_id": "k1",
            "private_key": TEST_PRIVATE_KEY_PEM,
            "client_email": "svc@proj.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string();
        let sa = parse_service_account(&json).unwrap();
        assert_eq!(sa.client_email, "svc@proj.iam.gserviceaccount.com");
        assert_eq!(sa.token_uri, "https://oauth2.googleapis.com/token");
        assert!(sa.private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn parse_service_account_missing_fields_is_auth_error_and_token_uri_defaults() {
        // 空对象 → Auth 错误（不 panic，不泄漏内容）
        let err = parse_service_account("{}").unwrap_err();
        assert!(matches!(err, ProviderError::Auth { .. }));
        // token_uri 缺省 → 官方默认端点
        let json = serde_json::json!({
            "client_email": "a@b.iam.gserviceaccount.com",
            "private_key": TEST_PRIVATE_KEY_PEM,
        })
        .to_string();
        let sa = parse_service_account(&json).unwrap();
        assert_eq!(sa.token_uri, "https://oauth2.googleapis.com/token");
    }
}
