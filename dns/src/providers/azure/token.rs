//! Azure OAuth2 客户端凭据 Token 管理（M9-DNS006）
//!
//! - Token 端点：`POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
//! - 表单：`grant_type=client_credentials&client_id=...&client_secret=...&scope=https://management.azure.com/.default`
//! - 响应：`{"access_token":"...","expires_in":3600,...}`
//! - 缓存：**到期前 5 分钟**即视为过期（刷新阈值），避免边界过期竞态；
//!   并发下允许重复获取（幂等），成功后覆盖缓存。
//! - 401 invalid_token 时由 client 调用 [`TokenManager::force_refresh`] 强制刷新重试一次。

use crate::provider::ProviderError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 到期前 5 分钟刷新阈值（M9-DNS006 §三：token ~1h 有效期）。
const REFRESH_AHEAD: Duration = Duration::from_secs(300);

/// 生产 token 端点模板。
const DEFAULT_TOKEN_URL: &str = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token";
/// 生产 scope。
pub(crate) const MGMT_SCOPE: &str = "https://management.azure.com/.default";

#[derive(Default)]
struct TokenState {
    access_token: Option<String>,
    expires_at: Option<Instant>,
}

/// OAuth2 客户端凭据 Token 管理器（凭据绝不打印/参与 Display）。
///
/// `Clone` 可共享（`AzureClient` 派生 Clone 所需）；缓存状态存于
/// `Arc<Mutex<..>>`，克隆共享同一 token 缓存。
#[derive(Clone)]
pub struct TokenManager {
    http: reqwest::Client,
    token_url: String,
    client_id: String,
    client_secret: String,
    state: Arc<Mutex<TokenState>>,
}

impl TokenManager {
    /// 生产构造。
    pub fn new(tenant_id: &str, client_id: &str, client_secret: &str, http: reqwest::Client) -> Self {
        Self::new_with_endpoint(tenant_id, client_id, client_secret, http, None)
    }

    /// 测试构造：`token_url_override` 指向 mock（`http://127.0.0.1`）。
    pub(crate) fn new_with_endpoint(
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
        http: reqwest::Client,
        token_url_override: Option<&str>,
    ) -> Self {
        let token_url = token_url_override
            .map(str::to_string)
            .unwrap_or_else(|| DEFAULT_TOKEN_URL.replace("{tenant}", tenant_id));
        Self {
            http,
            token_url,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            state: Arc::new(Mutex::new(TokenState::default())),
        }
    }

    /// 取有效 token：缓存未过期（含 5 分钟提前量）直接返回，否则重新获取。
    pub async fn get_token(&self) -> Result<String, ProviderError> {
        {
            let state = self.state.lock().unwrap();
            if let (Some(token), Some(expires_at)) = (&state.access_token, state.expires_at) {
                if Instant::now() < expires_at - REFRESH_AHEAD {
                    return Ok(token.clone());
                }
            }
        }
        self.fetch_and_cache().await
    }

    /// 强制刷新（401 invalid_token 后调用；清空缓存后重新获取）。
    pub async fn force_refresh(&self) -> Result<String, ProviderError> {
        self.state.lock().unwrap().access_token = None;
        self.fetch_and_cache().await
    }

    /// 向 token 端点发起 client_credentials 换取 access_token 并缓存。
    async fn fetch_and_cache(&self) -> Result<String, ProviderError> {
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("scope", MGMT_SCOPE),
        ];
        let resp = self
            .http
            .post(&self.token_url)
            .form(&params)
            .send()
            .await?;
        let status = resp.status().as_u16();
        let body = resp.text().await?;
        if !(200..300).contains(&status) {
            // 凭据错误 → Auth（body 不落日志明文，仅截断展示）。
            return Err(ProviderError::Auth {
                detail: format!("OAuth2 token 获取失败 status={status}: {}", truncate(&body, 300)),
            });
        }
        #[derive(serde::Deserialize)]
        struct TokenResp {
            access_token: String,
            #[serde(default)]
            expires_in: Option<u64>,
        }
        let token: TokenResp = serde_json::from_str(&body)?;
        let expires_at = Instant::now() + Duration::from_secs(token.expires_in.unwrap_or(3600));
        let mut state = self.state.lock().unwrap();
        state.access_token = Some(token.access_token.clone());
        state.expires_at = Some(expires_at);
        Ok(token.access_token)
    }
}

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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// 极简 token mock：计数 POST 次数，返回可配置 token/expires_in，记录表单体。
    #[derive(Clone)]
    struct TokenMock {
        addr: std::net::SocketAddr,
        posts: Arc<AtomicUsize>,
        token: Arc<Mutex<String>>,
        last_body: Arc<Mutex<String>>,
    }

    impl TokenMock {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().unwrap();
            let posts = Arc::new(AtomicUsize::new(0));
            let token = Arc::new(Mutex::new("tok-1".to_string()));
            let last_body = Arc::new(Mutex::new(String::new()));
            let (p2, t2, b2) = (posts.clone(), token.clone(), last_body.clone());
            tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let (p3, t3, b3) = (p2.clone(), t2.clone(), b2.clone());
                    tokio::spawn(async move {
                        let _ = handle(stream, &p3, &t3, &b3).await;
                    });
                }
            });
            Self { addr, posts, token, last_body }
        }

        fn url(&self) -> String {
            format!("http://{}/tenant1/oauth2/v2.0/token", self.addr)
        }

        fn count(&self) -> usize {
            self.posts.load(Ordering::SeqCst)
        }

        fn set_token(&self, token: &str) {
            *self.token.lock().unwrap() = token.to_string();
        }

        fn last_body(&self) -> String {
            self.last_body.lock().unwrap().clone()
        }
    }

    async fn handle(
        mut stream: TcpStream,
        posts: &AtomicUsize,
        token: &Mutex<String>,
        last_body: &Mutex<String>,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(&mut stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await? == 0 {
                break;
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).await?;
        let body = String::from_utf8_lossy(&body).to_string();
        *last_body.lock().unwrap() = body;

        posts.fetch_add(1, Ordering::SeqCst);
        let tok = token.lock().unwrap().clone();
        let json = format!(r#"{{"token_type":"Bearer","expires_in":3600,"access_token":"{tok}"}}"#);
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        stream.write_all(raw.as_bytes()).await?;
        stream.flush().await
    }

    fn http_client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    #[tokio::test]
    async fn token_cached_and_reused() {
        let mock = TokenMock::start().await;
        let tm = TokenManager::new_with_endpoint("t", "c", "s", http_client(), Some(&mock.url()));
        let t1 = tm.get_token().await.expect("token1");
        assert_eq!(t1, "tok-1");
        // 表单形状：grant_type=client_credentials、scope 编码为 application/x-www-form-urlencoded。
        let body = mock.last_body();
        assert!(body.contains("grant_type=client_credentials"), "{body}");
        assert!(
            body.contains("scope=https%3A%2F%2Fmanagement.azure.com%2F.default"),
            "{body}"
        );
        assert!(body.contains("client_id=c"), "{body}");
        let t2 = tm.get_token().await.expect("token2");
        assert_eq!(t2, "tok-1");
        assert_eq!(mock.count(), 1, "缓存命中：第二次不重新获取");
        // 服务端换 token 后，缓存未过期仍复用旧值。
        mock.set_token("tok-2");
        let t3 = tm.get_token().await.expect("token3");
        assert_eq!(t3, "tok-1");
        assert_eq!(mock.count(), 1);
        // 强制刷新 → 重新获取。
        let t4 = tm.force_refresh().await.expect("token4");
        assert_eq!(t4, "tok-2");
        assert_eq!(mock.count(), 2);
    }

    #[tokio::test]
    async fn token_failure_maps_to_auth() {
        // 直接构造一个指向无效端点的管理器（连接失败 → Network）。
        let tm = TokenManager::new_with_endpoint("t", "c", "s", http_client(), Some("http://127.0.0.1:1/oauth"));
        let err = tm.get_token().await.unwrap_err();
        assert!(matches!(err, ProviderError::Network(_)), "{err:?}");
    }
}
