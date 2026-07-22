use thiserror::Error;

/// Errors returned by the GoDaddy API client.
#[derive(Error, Debug)]
pub enum GoDaddyError {
    /// HTTP 429 Too Many Requests — rate limit exceeded.
    #[error("Rate limit exceeded: retry after {retry_after}s")]
    RateLimited {
        /// Seconds to wait before retrying, if provided by the server.
        retry_after: u64,
        /// Raw response body for debugging.
        body: String,
    },

    /// HTTP 422 Unprocessable Entity — invalid parameters.
    #[error("Invalid request parameters: {body}")]
    InvalidParameters {
        /// Raw response body with error details.
        body: String,
    },

    /// HTTP 4xx client error (other than 429, 422).
    #[error("Client error {status}: {body}")]
    ClientError {
        /// HTTP status code.
        status: u16,
        /// Raw response body.
        body: String,
    },

    /// HTTP 5xx server error.
    #[error("Server error {status}: {body}")]
    ServerError {
        /// HTTP status code.
        status: u16,
        /// Raw response body.
        body: String,
    },

    /// Network/transport error (connection refused, timeout, DNS resolution, etc.).
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The record was not found (HTTP 404).
    #[error("Record not found: {name} ({record_type})")]
    NotFound {
        /// Record name that was queried.
        name: String,
        /// Record type (e.g., "SRV", "AAAA", "TXT").
        record_type: String,
    },
}

impl GoDaddyError {
    /// Attempt to create a `GoDaddyError` from an HTTP response.
    pub(crate) async fn from_response(response: reqwest::Response) -> Self {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        match status.as_u16() {
            429 => GoDaddyError::RateLimited {
                retry_after: 30,
                body,
            },
            404 => GoDaddyError::NotFound {
                name: String::new(),
                record_type: String::new(),
            },
            422 => GoDaddyError::InvalidParameters { body },
            code if status.is_client_error() => GoDaddyError::ClientError {
                status: code,
                body,
            },
            code => GoDaddyError::ServerError {
                status: code,
                body,
            },
        }
    }
}
