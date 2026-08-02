use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// M15-T003: 白名单条目 — 域名模式 + 可选过期时间。
///
/// 模式支持 `*.example.com` 通配前缀（匹配 `example.com` 及其任意子域）；
/// `expiry` 为 `Some` 时到期自动失效（SRV-SEC-WL-003）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WhitelistEntry {
    /// 域名模式：精确域名或 `*.example.com` 通配。
    pub pattern: String,
    /// 过期时间（UTC）；`None` 表示永久有效。
    pub expiry: Option<DateTime<Utc>>,
}

impl WhitelistEntry {
    pub fn new(pattern: &str, expiry: Option<DateTime<Utc>>) -> Self {
        Self {
            pattern: pattern.trim().to_string(),
            expiry,
        }
    }

    /// 条目是否仍有效（未过期）。
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self.expiry {
            Some(exp) => now < exp,
            None => true,
        }
    }
}

/// 判断域名是否匹配白名单模式（SRV-SEC-WL-004）。
///
/// - 精确模式：`example.com` 只匹配自身；
/// - 通配模式：`*.example.com` 匹配 `example.com` 及任意子域（`a.example.com` 等）。
pub fn whitelist_matches(domain: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    if let Some(rest) = pattern.strip_prefix("*.") {
        domain == rest || domain.ends_with(&format!(".{}", rest))
    } else {
        domain == pattern
    }
}

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

    /// M15-T008: UI 外观设置（主题模式持久化）
    #[serde(default)]
    pub ui: UiConfig,

    /// M13-T005: 无人值守模式设置（`[unattended]` 段）
    #[serde(default)]
    pub unattended: UnattendedConfig,

    /// M13-T006: 文件传输设置（`[file_transfer]` 段）
    #[serde(default)]
    pub file_transfer: FileTransferConfig,
}

/// M13-T006: 文件传输配置（`[file_transfer]` 段）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferConfig {
    /// 接收文件落盘目录（`None` → 默认 `~/Downloads/KirinDesk`）。
    #[serde(default)]
    pub download_dir: Option<String>,

    /// 单文件大小上限（字节；超限在 Offer 阶段拒绝，FT-SEC-002）。
    /// 默认 4 GiB。
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
}

fn default_max_file_size() -> u64 {
    4 * 1024 * 1024 * 1024
}

impl Default for FileTransferConfig {
    fn default() -> Self {
        Self {
            download_dir: None,
            max_file_size: default_max_file_size(),
        }
    }
}

impl FileTransferConfig {
    /// 接收目录（配置值或默认 `~/Downloads/KirinDesk`）。
    pub fn resolved_download_dir(&self) -> std::path::PathBuf {
        match &self.download_dir {
            Some(d) if !d.trim().is_empty() => std::path::PathBuf::from(d),
            _ => dirs_next::download_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("KirinDesk"),
        }
    }
}

/// M13-T005: 无人值守模式配置（`[unattended]` 段）。
///
/// `enabled` 是「自动接受连接 + 无弹窗审批」的总开关；`auto_start_on_boot`
/// 与 `auto_start_server` 独立可配 —— 开机自启不要求开启无人值守（D6）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnattendedConfig {
    /// 无人值守总开关：开启后 known_clients/白名单命中自动放行，未知设备
    /// 一律拒绝并写审计（无人工审批弹窗），temp-mode 旁路禁用。
    #[serde(default)]
    pub enabled: bool,

    /// 开机自动启动（用户级：Windows HKCU Run / Linux XDG autostart /
    /// macOS LaunchAgent，无需管理员权限）。可独立于 `enabled` 使用。
    #[serde(default)]
    pub auto_start_on_boot: bool,

    /// 应用启动时自动开启服务端（监听 network.port + DNS 注册/心跳）。
    #[serde(default = "default_auto_start_server")]
    pub auto_start_server: bool,
}

fn default_auto_start_server() -> bool {
    true
}

impl Default for UnattendedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_start_on_boot: false,
            auto_start_server: default_auto_start_server(),
        }
    }
}

/// M15-T008: UI 外观配置（`[ui]` 段）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// 主题模式: "light"（默认）| "dark" | "system"
    #[serde(default = "default_theme")]
    pub theme: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: default_theme(),
        }
    }
}

fn default_theme() -> String {
    "light".to_string()
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

    /// If true, skip whitelist check (temporary mode for headless servers)
    /// Allows any client to connect without domain whitelist approval.
    #[serde(default)]
    pub temp_mode: bool,

    /// M8-T017: 临时连接窗口时长（秒）。默认 300（5 分钟），可配置范围
    /// 60–3600——越界值经 [`NetworkConfig::effective_temp_mode_ttl`] 收敛。
    #[serde(default = "default_temp_mode_ttl_secs")]
    pub temp_mode_ttl_secs: u64,

    /// M15-T003: 白名单条目（模式 + 过期时间，`*.example.com` 通配支持）。
    /// 兼容旧 `allowed_domains`（无过期、永久有效），两者共同生效。
    #[serde(default)]
    pub whitelist: Vec<WhitelistEntry>,
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

/// M8-T017: 临时连接窗口默认时长（5 分钟）。
fn default_temp_mode_ttl_secs() -> u64 {
    300
}

/// 临时连接窗口 TTL 可配置范围（SRV-TMP-004）。
pub const TEMP_MODE_TTL_MIN: u64 = 60;
pub const TEMP_MODE_TTL_MAX: u64 = 3600;

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

    /// Log directory (auto-created). Defaults to ~/.kirin_desk/logs/
    #[serde(default)]
    pub log_dir: Option<String>,

    /// Days to keep old log files. Default: 7
    #[serde(default = "default_log_keep_days")]
    pub log_keep_days: u64,
}

fn default_log_keep_days() -> u64 { 7 }

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
                temp_mode: false,
                temp_mode_ttl_secs: default_temp_mode_ttl_secs(),
                whitelist: Vec::new(),
            },
            media: MediaConfig {
                encoder: default_encoder(),
                framerate: default_framerate(),
                bitrate: default_bitrate(),
            },
            logging: LoggingConfig {
                level: default_log_level(),
                format: default_log_format(),
                log_dir: None,
                log_keep_days: default_log_keep_days(),
            },
            ui: UiConfig::default(),
            unattended: UnattendedConfig::default(),
            file_transfer: FileTransferConfig::default(),
        }
    }
}

impl NetworkConfig {
    /// M8-T017: 临时连接窗口 TTL 收敛值（SRV-TMP-004，范围 60–3600）。
    /// 配置越界时静默收敛到边界，保证 `enable` 语义稳定。
    pub fn effective_temp_mode_ttl(&self) -> u64 {
        self.temp_mode_ttl_secs.clamp(TEMP_MODE_TTL_MIN, TEMP_MODE_TTL_MAX)
    }
}

impl Config {
    /// Load configuration from the default path
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::default_path()?;
        tracing::debug!("Config: loading from {:?}", path);
        let config = Self::load_from(&path);
        match &config {
            Ok(cfg) => tracing::info!(
                "Config loaded: device_id={}, domain={}, port={}, level={}",
                cfg.device.id, cfg.godaddy.domain, cfg.network.port, cfg.logging.level
            ),
            Err(e) => tracing::warn!("Config: failed to load from {:?}: {}", path, e),
        }
        config
    }

    /// Load configuration from a specific path
    pub fn load_from(path: &std::path::Path) -> Result<Self, ConfigError> {
        tracing::debug!("Config: reading from {:?}", path);
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
        tracing::debug!("Config: successfully parsed from {:?}", path);
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

    // ---------- M15-T003: 白名单管理（SRV-SEC-WL-001..004） ----------

    /// 当前生效的白名单模式（过滤过期条目，兼容旧 `allowed_domains`）。
    /// 返回去重后的模式列表，供握手层匹配使用。
    pub fn whitelist_active_patterns(&self, now: DateTime<Utc>) -> Vec<String> {
        let mut patterns: Vec<String> = self.network.allowed_domains.clone();
        for entry in &self.network.whitelist {
            if entry.is_active(now) && !patterns.contains(&entry.pattern) {
                patterns.push(entry.pattern.clone());
            }
        }
        patterns
    }

    /// 域名是否在白名单内（过期条目自动失效，SRV-SEC-WL-003）。
    /// 旧 `allowed_domains` 沿用历史语义（相等或任意子域）；新 `whitelist`
    /// 条目用显式模式匹配（精确或 `*.example.com` 通配）。
    pub fn whitelist_check(&self, domain: &str) -> bool {
        if self
            .network
            .allowed_domains
            .iter()
            .any(|a| domain == a || domain.ends_with(&format!(".{}", a)))
        {
            return true;
        }
        self.network
            .whitelist
            .iter()
            .any(|e| e.is_active(Utc::now()) && whitelist_matches(domain, &e.pattern))
    }

    /// 新增白名单条目（按模式去重），返回是否新增成功，并立即保存。
    /// `expiry: None` 永久有效；`Some` 到期自动失效。
    pub fn whitelist_add(
        &mut self,
        pattern: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<bool, ConfigError> {
        let pattern = pattern.trim().to_string();
        if pattern.is_empty() {
            return Ok(false);
        }
        if let Some(entry) = self
            .network
            .whitelist
            .iter_mut()
            .find(|e| e.pattern == pattern)
        {
            // 已存在 → 只更新过期时间
            entry.expiry = expiry;
            self.save()?;
            return Ok(false);
        }
        self.network.whitelist.push(WhitelistEntry::new(&pattern, expiry));
        self.save()?;
        Ok(true)
    }

    /// 删除白名单条目，返回是否删除成功，并立即保存。
    pub fn whitelist_remove(&mut self, pattern: &str) -> Result<bool, ConfigError> {
        let before_wl = self.network.whitelist.len();
        self.network.whitelist.retain(|e| e.pattern != pattern);
        let before_ad = self.network.allowed_domains.len();
        self.network.allowed_domains.retain(|d| d != pattern);
        let removed = self.network.whitelist.len() != before_wl
            || self.network.allowed_domains.len() != before_ad;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// 从 CSV 导入白名单（SRV-SEC-WL-002）。
    ///
    /// 格式：每行 `pattern[,expiry]`，`expiry` 为 RFC3339（如 `2026-08-01T12:00:00Z`）
    /// 或留空表示永久；空行与 `#` 注释行跳过；非法行跳过并计入未导入数。
    /// 返回成功导入的条目数，并立即保存。
    pub fn whitelist_import_csv(&mut self, path: &Path) -> Result<usize, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut imported = 0usize;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split(',');
            let pattern = parts.next().unwrap_or("").trim();
            let expiry_str = parts.next().map(|s| s.trim()).unwrap_or("");
            if pattern.is_empty() {
                continue;
            }
            let expiry = if expiry_str.is_empty() {
                None
            } else {
                match DateTime::parse_from_rfc3339(expiry_str) {
                    Ok(dt) => Some(dt.with_timezone(&Utc)),
                    Err(_) => continue, // 非法时间戳 → 跳过该行
                }
            };
            let _ = self.whitelist_add(pattern, expiry)?;
            imported += 1;
        }
        Ok(imported)
    }

    /// 导出白名单到 CSV（SRV-SEC-WL-002）：每行 `pattern,expiry`。
    pub fn whitelist_export_csv(&self, path: &Path) -> Result<(), ConfigError> {
        let mut lines = String::from("# pattern,expiry (RFC3339, empty = permanent)\n");
        for pattern in self.whitelist_active_patterns(Utc::now()) {
            let entry = self
                .network
                .whitelist
                .iter()
                .find(|e| e.pattern == pattern);
            let expiry = entry
                .and_then(|e| e.expiry)
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_default();
            lines.push_str(&format!("{},{}\n", pattern, expiry));
        }
        std::fs::write(path, lines).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// 导出白名单到 JSON（SRV-SEC-WL-002）。
    pub fn whitelist_export_json(&self, path: &Path) -> Result<(), ConfigError> {
        let content = serde_json::to_string_pretty(&self.network.whitelist)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;
        std::fs::write(path, content).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// 物理清除过期条目，返回清除数量（匹配时过期条目已被跳过，此方法用于清理）。
    pub fn whitelist_prune_expired(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.network.whitelist.len();
        self.network
            .whitelist
            .retain(|e| e.is_active(now));
        before - self.network.whitelist.len()
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

    // ---------- M8-T017: 临时连接 TTL 配置测试 ----------

    #[test]
    fn test_temp_mode_ttl_default() {
        let config = Config::default();
        assert_eq!(config.network.temp_mode_ttl_secs, 300);
        assert_eq!(config.network.effective_temp_mode_ttl(), 300);
    }

    #[test]
    fn test_temp_mode_ttl_clamped_to_range() {
        let mut config = Config::default();
        config.network.temp_mode_ttl_secs = 10;
        assert_eq!(config.network.effective_temp_mode_ttl(), 60);
        config.network.temp_mode_ttl_secs = 7200;
        assert_eq!(config.network.effective_temp_mode_ttl(), 3600);
        config.network.temp_mode_ttl_secs = 600;
        assert_eq!(config.network.effective_temp_mode_ttl(), 600);
    }

    // ---------- M13-T005: 无人值守配置测试 ----------

    #[test]
    fn test_unattended_defaults() {
        let config = Config::default();
        assert!(!config.unattended.enabled);
        assert!(!config.unattended.auto_start_on_boot);
        assert!(config.unattended.auto_start_server);
    }

    #[test]
    fn test_unattended_legacy_toml_missing_section() {
        // 旧配置文件无 [unattended] 段 → 加载不失败，使用默认值
        let dir = std::env::temp_dir().join("kirin_desk_test_unattended");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.device.id, "old-device");
        assert!(!loaded.unattended.enabled);
        assert!(loaded.unattended.auto_start_server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_unattended_roundtrip() {
        let mut config = Config::default();
        config.unattended.enabled = true;
        config.unattended.auto_start_on_boot = true;
        let dir = std::env::temp_dir().join("kirin_desk_test_config_unattended");
        let path = dir.join("test.toml");
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.unattended.enabled);
        assert!(loaded.unattended.auto_start_on_boot);
        assert!(loaded.unattended.auto_start_server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- 白名单测试 ----------

    #[test]
    fn test_whitelist_matches() {
        // 精确匹配
        assert!(whitelist_matches("example.com", "example.com"));
        assert!(!whitelist_matches("a.example.com", "example.com"));
        // 通配匹配：自身 + 任意子域
        assert!(whitelist_matches("example.com", "*.example.com"));
        assert!(whitelist_matches("a.example.com", "*.example.com"));
        assert!(whitelist_matches("x.y.example.com", "*.example.com"));
        assert!(!whitelist_matches("example.net", "*.example.com"));
        assert!(!whitelist_matches("evilexample.com", "*.example.com"));
        // 空模式
        assert!(!whitelist_matches("example.com", "  "));
    }

    #[test]
    fn test_whitelist_check_and_expiry() {
        let mut config = Config::default();
        config.whitelist_add("*.example.com", None).unwrap();
        config
            .whitelist_add(
                "temporary.net",
                Some(Utc::now() - chrono::Duration::minutes(1)),
            )
            .unwrap();

        assert!(config.whitelist_check("a.example.com"));
        assert!(config.whitelist_check("example.com"));
        assert!(!config.whitelist_check("other.net"));
        // 过期条目自动失效
        assert!(!config.whitelist_check("temporary.net"));
        // 清理过期条目
        assert_eq!(config.whitelist_prune_expired(Utc::now()), 1);
    }

    #[test]
    fn test_whitelist_legacy_allowed_domains_compat() {
        let mut config = Config::default();
        config.network.allowed_domains.push("legacy.example.com".to_string());
        assert!(config.whitelist_check("legacy.example.com"));
        assert!(config.whitelist_check("sub.legacy.example.com"));
        // 删除时同时清理旧字段
        assert!(config.whitelist_remove("legacy.example.com").unwrap());
        assert!(config.network.allowed_domains.is_empty());
        assert!(!config.whitelist_remove("legacy.example.com").unwrap());
    }

    #[test]
    fn test_whitelist_import_export_csv() {
        let dir = std::env::temp_dir().join("kirin_desk_test_whitelist");
        std::fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("wl.csv");

        let mut config = Config::default();
        let n = config
            .whitelist_import_csv(&dir.join("wl_in.csv"))
            .unwrap_or(0);
        assert_eq!(n, 0); // 文件不存在 → 报错路径由调用方处理，此处验证空

        std::fs::write(
            &csv,
            "# comment\n*.example.com,\npc-a.kirin.io,2026-12-31T00:00:00Z\nbad-line,not-a-date\n",
        )
        .unwrap();
        let imported = config.whitelist_import_csv(&csv).unwrap();
        assert_eq!(imported, 2);
        assert!(config.whitelist_check("pc-a.kirin.io"));
        assert!(config.whitelist_check("any.example.com"));

        // 导出 CSV 再导入到新配置
        let out = dir.join("wl_out.csv");
        config.whitelist_export_csv(&out).unwrap();
        let mut config2 = Config::default();
        let n2 = config2.whitelist_import_csv(&out).unwrap();
        assert!(n2 >= 2);
        assert!(config2.whitelist_check("pc-a.kirin.io"));

        // 导出 JSON
        let json_path = dir.join("wl.json");
        config.whitelist_export_json(&json_path).unwrap();
        assert!(std::fs::read_to_string(&json_path).unwrap().contains("pattern"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_whitelist_toml_roundtrip() {
        let mut config = Config::default();
        config
            .whitelist_add("*.example.com", Some(Utc::now() + chrono::Duration::days(1)))
            .unwrap();
        let dir = std::env::temp_dir().join("kirin_desk_test_config_wl");
        let path = dir.join("test.toml");
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.whitelist_check("a.example.com"));
        assert_eq!(loaded.network.whitelist.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
