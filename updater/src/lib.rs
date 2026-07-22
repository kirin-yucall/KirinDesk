use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Current application version (from Cargo.toml).
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// GitHub repository info for updates.
const GITHUB_OWNER: &str = "kirin-yucall";
const GITHUB_REPO: &str = "kirin_desk";

/// Update channel.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UpdateChannel {
    Stable,
    Beta,
}

/// Information about an available release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub version: String,
    pub download_url: String,
    pub checksum: String,
    pub release_date: String,
    pub release_notes: String,
}

/// Update check result.
#[derive(Debug, Clone)]
pub enum UpdateStatus {
    /// No update available.
    UpToDate,
    /// Update available with details.
    Available(ReleaseInfo),
    /// Error checking for updates.
    Error(String),
}

/// Auto-updater errors.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Failed to parse release info: {0}")]
    ParseError(String),
    #[error("Checksum mismatch")]
    ChecksumMismatch,
    #[error("Failed to write update: {0}")]
    Io(#[from] std::io::Error),
}

/// Auto-updater for KirinDesk.
///
/// Checks GitHub releases for new versions, downloads updates,
/// and prepares them for installation.
pub struct Updater {
    current_version: String,
    channel: UpdateChannel,
    data_dir: PathBuf,
}

impl Updater {
    /// Create a new updater.
    pub fn new(data_dir: PathBuf, channel: UpdateChannel) -> Self {
        Self {
            current_version: APP_VERSION.to_string(),
            channel,
            data_dir,
        }
    }

    /// Check GitHub releases for updates.
    pub async fn check_for_updates(&self) -> UpdateStatus {
        let url = format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            GITHUB_OWNER, GITHUB_REPO
        );

        let client = reqwest::Client::builder()
            .user_agent("KirinDesk-Updater/1.0")
            .build();

        let client = match client {
            Ok(c) => c,
            Err(e) => return UpdateStatus::Error(e.to_string()),
        };

        let response = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return UpdateStatus::Error(e.to_string()),
        };

        if !response.status().is_success() {
            return UpdateStatus::Error(format!("HTTP {}", response.status()));
        }

        let release: GitHubRelease = match response.json().await {
            Ok(r) => r,
            Err(e) => return UpdateStatus::Error(e.to_string()),
        };

        // Compare versions
        let remote_ver = release.tag_name.trim_start_matches('v');
        if !is_newer_version(remote_ver, &self.current_version) {
            return UpdateStatus::UpToDate;
        }

        // Find the asset (first one)
        let asset = match release.assets.first() {
            Some(a) => a,
            None => return UpdateStatus::Error("No assets in release".to_string()),
        };

        UpdateStatus::Available(ReleaseInfo {
            version: remote_ver.to_string(),
            download_url: asset.browser_download_url.clone(),
            checksum: String::new(), // GitHub doesn't provide checksums by default
            release_date: release.published_at.clone(),
            release_notes: release.body.clone(),
        })
    }

    /// Download an update to the data directory.
    pub async fn download_update(&self, release: &ReleaseInfo) -> Result<PathBuf, UpdateError> {
        let dest = self.data_dir.join(format!("kirin_desk-{}.exe", release.version));

        let client = reqwest::Client::builder()
            .user_agent("KirinDesk-Updater/1.0")
            .build()
            .map_err(|e| UpdateError::Network(e.to_string()))?;

        let response = client
            .get(&release.download_url)
            .send()
            .await
            .map_err(|e| UpdateError::Network(e.to_string()))?;

        let bytes = response
            .bytes()
            .await
            .map_err(|e| UpdateError::Network(e.to_string()))?;

        // Ensure parent directory exists
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }

        tokio::fs::write(&dest, &bytes)
            .await
            .map_err(UpdateError::Io)?;

        Ok(dest)
    }

    /// Get the current version string.
    pub fn current_version(&self) -> &str {
        &self.current_version
    }
}

/// GitHub API release response.
#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    published_at: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    browser_download_url: String,
    #[serde(default)]
    name: String,
}

/// Simple semver comparison: returns true if `new` > `current`.
fn is_newer_version(new: &str, current: &str) -> bool {
    let parse_version = |v: &str| -> Vec<u32> {
        v.split('.')
            .filter_map(|s| s.split('-').next())
            .filter_map(|s| s.parse().ok())
            .collect()
    };

    let new_parts = parse_version(new);
    let cur_parts = parse_version(current);

    for (n, c) in new_parts.iter().zip(cur_parts.iter()) {
        if n != c {
            return n > c;
        }
    }
    new_parts.len() > cur_parts.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("2.0.0", "1.0.0"));
        assert!(!is_newer_version("1.0.0", "2.0.0"));
        assert!(!is_newer_version("1.0.0", "1.0.0"));
        assert!(is_newer_version("1.1.0", "1.0.0"));
        assert!(is_newer_version("1.0.1", "1.0.0"));
        assert!(!is_newer_version("1.0.0", "1.0.1"));
        // Pre-release handling
        assert!(is_newer_version("1.0.0", "0.9.9"));
    }

    #[test]
    fn test_current_version_defined() {
        assert!(!APP_VERSION.is_empty());
    }

    #[test]
    fn test_updater_creation() {
        let updater = Updater::new(
            std::env::temp_dir().join("kirin_desk-updater-test"),
            UpdateChannel::Stable,
        );
        assert_eq!(updater.current_version(), APP_VERSION);
    }

    #[test]
    fn test_release_info_serialization() {
        let info = ReleaseInfo {
            version: "1.0.0".to_string(),
            download_url: "https://example.com/update.exe".to_string(),
            checksum: "abc123".to_string(),
            release_date: "2024-01-01".to_string(),
            release_notes: "Bug fixes".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("1.0.0"));
        let parsed: ReleaseInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "1.0.0");
    }
}
