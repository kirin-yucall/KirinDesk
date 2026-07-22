use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// KirinDesk application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Device identity
    pub device: DeviceConfig,

    /// GoDaddy DNS API settings
    pub godaddy: GoDaddyConfig,

    /// Network settings
    pub network: NetworkConfig,

    /// Media settings
    pub media: MediaConfig,

    /// Logging settings
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    /// Unique device identifier (e.g., "my-pc")
    pub id: String,

    /// Human-readable device name
    pub name: String,

    /// Device nickname (used in auth: nickname + challenge)
    #[serde(default)]
    pub nickname: String,

    /// Challenge code for authentication
    #[serde(default)]
    pub challenge_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoDaddyConfig {
    /// GoDaddy API key
    pub api_key: String,

    /// GoDaddy API secret
    pub api_secret: String,

    /// Domain managed on GoDaddy (e.g., "example.com")
    pub domain: String,

    /// API base URL (production or OTE)
    #[serde(default = "default_api_url")]
    pub api_url: String,
}

fn default_api_url() -> String {
    "https://api.godaddy.com".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Listening port for remote desktop
    #[serde(default = "default_port")]
    pub port: u16,

    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// DNS record TTL
    #[serde(default = "default_ttl")]
    pub dns_ttl: u32,

    /// Allowed domains whitelist (only these can connect)
    #[serde(default)]
    pub allowed_domains: Vec<String>,

    /// If true, allow IP-mode connections (bypass domain whitelist)
    #[serde(default)]
    pub ip_mode_allowed: bool,
}

fn default_port() -> u16 {
    3389
}

fn default_heartbeat_interval() -> u64 {
    30
}

fn default_ttl() -> u32 {
    600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaConfig {
    /// Preferred encoder (auto, nvenc, vaapi, software)
    #[serde(default = "default_encoder")]
    pub encoder: String,

    /// Target framerate for screen capture
    #[serde(default = "default_framerate")]
    pub framerate: u32,

    /// Video bitrate in kbps
    #[serde(default = "default_bitrate")]
    pub bitrate: u32,
}

fn default_encoder() -> String {
    "auto".to_string()
}

fn default_framerate() -> u32 {
    30
}

fn default_bitrate() -> u32 {
    5000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (text or json)
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device: DeviceConfig {
                id: "default-device".to_string(),
                name: "My Device".to_string(),
                nickname: String::new(),
                challenge_code: String::new(),
            },
            godaddy: GoDaddyConfig {
                api_key: String::new(),
                api_secret: String::new(),
                domain: "example.com".to_string(),
                api_url: default_api_url(),
            },
            network: NetworkConfig {
                port: default_port(),
                heartbeat_interval: default_heartbeat_interval(),
                dns_ttl: default_ttl(),
                allowed_domains: Vec::new(),
                ip_mode_allowed: false,
            },
            media: MediaConfig {
                encoder: default_encoder(),
                framerate: default_framerate(),
                bitrate: default_bitrate(),
            },
            logging: LoggingConfig {
                level: default_log_level(),
                format: default_log_format(),
            },
        }
    }
}

impl Config {
    /// Load configuration from the default path
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::default_path()?;
        Self::load_from(&path)
    }

    /// Load configuration from a specific path
    pub fn load_from(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError {
                path: path.to_path_buf(),
                detail: e.to_string(),
            })?;
        Ok(config)
    }

    /// Save configuration to the default path
    pub fn save(&self) -> Result<(), ConfigError> {
        let path = Self::default_path()?;
        self.save_to(&path)
    }

    /// Save configuration to a specific path
    pub fn save_to(&self, path: &std::path::Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ConfigError::IoError {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
        }
        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;
        std::fs::write(path, &content)
            .map_err(|e| ConfigError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?;
        Ok(())
    }

    /// Get the default config directory path
    pub fn config_dir() -> Result<PathBuf, ConfigError> {
        let base = dirs_next::config_dir()
            .ok_or_else(|| ConfigError::NoHomeDir)?;
        Ok(base.join("kirin_desk"))
    }

    /// Get the default config file path
    fn default_path() -> Result<PathBuf, ConfigError> {
        Ok(Self::config_dir()?.join("default.toml"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error at {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to parse config at {path}: {detail}")]
    ParseError {
        path: PathBuf,
        detail: String,
    },
    #[error("Serialization error: {0}")]
    SerializeError(String),
    #[error("No home/config directory found")]
    NoHomeDir,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.device.id, "default-device");
        assert_eq!(config.network.port, 3389);
        assert_eq!(config.godaddy.api_url, "https://api.godaddy.com");
    }

    #[test]
    fn test_config_roundtrip() {
        let config = Config::default();
        let dir = std::env::temp_dir().join("kirin_desk_test_config");
        let path = dir.join("test.toml");

        config.save_to(&path).expect("save should succeed");
        let loaded = Config::load_from(&path).expect("load should succeed");

        assert_eq!(loaded.device.id, config.device.id);
        assert_eq!(loaded.network.port, config.network.port);

        // Cleanup
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_config_load_nonexistent() {
        let path = std::env::temp_dir().join("kirin_desk_nonexistent.toml");
        let result = Config::load_from(&path);
        assert!(result.is_err());
    }
}
