use super::auth::Auth;
use super::error::GoDaddyError;
use super::record::Record;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::Response;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, trace};

/// Maximum number of retries for rate-limited requests.
const MAX_RETRIES: u32 = 3;

/// Initial backoff duration for retries.
const INITIAL_BACKOFF_MS: u64 = 1000;

/// GoDaddy Domains API client.
///
/// Manages DNS records (SRV, AAAA, TXT) via the GoDaddy REST API.
///
/// # Example
///
/// ```no_run
/// use kirin_desk_dns::godaddy::client::GoDaddyClient;
///
/// # async fn example() {
/// let client = GoDaddyClient::new("api_key", "api_secret", "https://api.godaddy.com");
/// let records = client.get_records("example.com", "AAAA", "my-device").await;
/// # }
/// ```
#[derive(Clone)]
#[allow(dead_code)]
pub struct GoDaddyClient {
    /// Inner reqwest client.
    client: reqwest::Client,

    /// Authentication handler.
    auth: Arc<Auth>,

    /// Base URL for the GoDaddy API (e.g., "https://api.godaddy.com").
    base_url: String,

    /// Mutex for rate-limit synchronization.
    rate_limit_lock: Arc<Mutex<()>>,
}

impl GoDaddyClient {
    /// Create a new GoDaddy API client.
    ///
    /// * `api_key` — GoDaddy API key from developer portal.
    /// * `api_secret` — GoDaddy API secret.
    /// * `base_url` — API base URL (production: `https://api.godaddy.com`,
    ///   OTE/test: `https://api.ote-godaddy.com`).
    pub fn new(
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        let auth = Auth::new(api_key, api_secret);
        let auth_header = auth.authorization_header();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&auth_header)
                        .expect("Invalid authorization header value"),
                );
                headers.insert(
                    reqwest::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                headers.insert(
                    reqwest::header::ACCEPT,
                    HeaderValue::from_static("application/json"),
                );
                headers
            })
            .user_agent("KirinDesk/0.1.0")
            .build()
            .expect("Failed to build reqwest client");

        Self {
            client,
            auth: Arc::new(auth),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            rate_limit_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Build the URL for record operations.
    ///
    /// Pattern: `{base}/v1/domains/{domain}/records/{type}/{name}`
    fn record_url(&self, domain: &str, record_type: &str, name: &str) -> String {
        format!(
            "{}/v1/domains/{}/records/{}/{}",
            self.base_url, domain, record_type, name
        )
    }

    /// GET DNS records of a specific type for a given name.
    ///
    /// Returns a list of matching records.
    pub async fn get_records(
        &self,
        domain: &str,
        record_type: &str,
        name: &str,
    ) -> Result<Vec<Record>, GoDaddyError> {
        let url = self.record_url(domain, record_type, name);
        debug!("GoDaddy GET {} {} {}", record_type, domain, name);
        let response = self.execute_with_retry(|| {
            let client = self.client.clone();
            let url = url.clone();
            async move { client.get(&url).send().await }
        })
        .await?;

        let records: Vec<Record> = response.json().await?;
        debug!("GoDaddy GET {} {} {} -> {} records", record_type, domain, name, records.len());
        Ok(records)
    }

    /// PUT (create/replace) DNS records at a given name.
    ///
    /// This replaces ALL records for the specified `{type}/{name}`.
    pub async fn put_records(
        &self,
        domain: &str,
        record_type: &str,
        name: &str,
        records: &[Record],
    ) -> Result<(), GoDaddyError> {
        let url = self.record_url(domain, record_type, name);
        let body = serde_json::to_string(records)?;
        trace!("GoDaddy PUT {} {} {} -> body={}", record_type, domain, name, body);

        let _response = self
            .execute_with_retry(|| {
                let client = self.client.clone();
                let url = url.clone();
                let body = body.clone();
                async move { client.put(&url).body(body).send().await }
            })
            .await?;

        debug!("GoDaddy PUT {} {} {} -> OK", record_type, domain, name);
        Ok(())
    }

    /// DELETE all DNS records of a specific type for a given name.
    pub async fn delete_record(
        &self,
        domain: &str,
        record_type: &str,
        name: &str,
    ) -> Result<(), GoDaddyError> {
        let url = self.record_url(domain, record_type, name);
        debug!("GoDaddy DELETE {} {} {}", record_type, domain, name);

        let response = self
            .execute_with_retry(|| {
                let client = self.client.clone();
                let url = url.clone();
                async move { client.delete(&url).send().await }
            })
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(GoDaddyError::from_response(response).await)
        }
    }

    /// Execute an HTTP request with automatic retry on 429 (rate limit).
    async fn execute_with_retry<F, Fut>(&self, request_fn: F) -> Result<Response, GoDaddyError>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<Response, reqwest::Error>> + Send,
    {
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            let response = request_fn().await?;

            if response.status().is_success() {
                trace!("GoDaddy API response: {} {}", response.status().as_u16(), response.url());
                return Ok(response);
            }

            let status = response.status().as_u16();
            debug!("GoDaddy API error response: {} {}", status, response.url());

            if status == 429 {
                let error = GoDaddyError::from_response(response).await;
                tracing::warn!(
                    "Rate limited by GoDaddy API (attempt {}/{}), backing off...",
                    attempt + 1,
                    MAX_RETRIES
                );

                let backoff_ms = INITIAL_BACKOFF_MS * (2u64.pow(attempt));
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

                last_error = Some(error);
                continue;
            }

            return Err(GoDaddyError::from_response(response).await);
        }

        Err(last_error.unwrap_or(GoDaddyError::RateLimited {
            retry_after: 60,
            body: "max retries exceeded".to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_url_format() {
        let client = GoDaddyClient::new("k", "s", "https://api.godaddy.com");
        let url = client.record_url("example.com", "AAAA", "my-pc");
        assert_eq!(
            url,
            "https://api.godaddy.com/v1/domains/example.com/records/AAAA/my-pc"
        );
    }

    #[test]
    fn test_record_url_with_ote() {
        let client = GoDaddyClient::new("k", "s", "https://api.ote-godaddy.com");
        let url = client.record_url("example.com", "TXT", "_devicekey.my-pc");
        assert_eq!(
            url,
            "https://api.ote-godaddy.com/v1/domains/example.com/records/TXT/_devicekey.my-pc"
        );
    }

    #[test]
    fn test_client_has_auth_header() {
        let client = GoDaddyClient::new("test_key", "test_secret", "https://api.godaddy.com");
        // Verify the auth header is set by checking the internal auth field
        assert_eq!(
            client.auth.authorization_header(),
            "sso-key test_key:test_secret"
        );
    }
}
