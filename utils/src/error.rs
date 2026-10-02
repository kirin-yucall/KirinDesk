use thiserror::Error;

/// General KirinDesk error type
#[derive(Error, Debug)]
pub enum Ip6DeskError {
    #[error("Configuration error: {0}")]
    Config(#[from] super::config::ConfigError),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for Ip6DeskError {
    fn from(err: anyhow::Error) -> Self {
        Ip6DeskError::Other(err.to_string())
    }
}
