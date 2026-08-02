//! KirinDesk 自动更新器 — M14-T005。
//!
//! 检查 GitHub Releases 获取新版本，下载更新并准备安装：
//! - 按平台挑选 release asset（windows/macos/linux 关键字 + 扩展名偏好）
//! - `download_update_with_progress` 流式下载并回报进度
//! - `should_auto_check` / `record_auto_check` 支持每周后台静默检查
//!
//! 安装流程（Windows）：下载 → 写替换脚本 → 启动脚本 → 退出应用
//! （脚本等待旧进程退出后覆盖 exe 并重启，见 `ui/src/lib.rs` 的
//!  `install_update`）。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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

/// 目标平台（决定挑选哪个 release asset）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    MacOS,
    Linux,
    Other,
}

impl Platform {
    /// 当前编译目标平台。
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Platform::Windows
        }
        #[cfg(target_os = "macos")]
        {
            Platform::MacOS
        }
        #[cfg(target_os = "linux")]
        {
            Platform::Linux
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            Platform::Other
        }
    }

    /// asset 名称关键字（命中越多得分越高）。
    fn asset_keywords(&self) -> &'static [&'static str] {
        match self {
            Platform::Windows => &["windows"],
            Platform::MacOS => &["macos", "darwin", ".dmg"],
            Platform::Linux => &["linux", ".deb", ".tar"],
            Platform::Other => &[],
        }
    }

    /// 扩展名偏好（可执行/安装包优先于压缩包），无则返回空串。
    fn preferred_extension(&self) -> &'static str {
        match self {
            Platform::Windows => ".exe",
            Platform::MacOS => ".dmg",
            Platform::Linux => ".deb",
            Platform::Other => "",
        }
    }
}

/// Information about an available release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub version: String,
    pub download_url: String,
    pub checksum: String,
    pub release_date: String,
    pub release_notes: String,
    /// 所选 asset 的文件名（展示用）。
    #[serde(default)]
    pub asset_name: String,
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
#[derive(Clone)]
pub struct Updater {
    current_version: String,
    channel: UpdateChannel,
    data_dir: PathBuf,
}

/// 上次自动检查时间戳（`{data_dir}/last_check.json`）。
#[derive(Serialize, Deserialize)]
struct LastCheck {
    epoch_secs: u64,
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

        // 按平台挑选 asset（M14-T005：替代"取第一个"）
        let platform = Platform::current();
        let asset = match pick_asset(&release.assets, platform) {
            Some(a) => a,
            None => return UpdateStatus::Error("No assets in release".to_string()),
        };

        UpdateStatus::Available(ReleaseInfo {
            version: remote_ver.to_string(),
            download_url: asset.browser_download_url.clone(),
            checksum: String::new(), // GitHub doesn't provide checksums by default
            release_date: release.published_at.clone(),
            release_notes: release.body.clone(),
            asset_name: asset.name.clone(),
        })
    }

    /// Download an update to the data directory (without progress reporting).
    pub async fn download_update(&self, release: &ReleaseInfo) -> Result<PathBuf, UpdateError> {
        self.download_update_with_progress(release, |_, _| {}).await
    }

    /// Download an update to the data directory, reporting progress.
    ///
    /// `on_progress(received_bytes, total_bytes)` 在每块下载后被调用；
    /// `total_bytes` 在服务器未提供 Content-Length 时为 `None`。
    pub async fn download_update_with_progress<F>(
        &self,
        release: &ReleaseInfo,
        on_progress: F,
    ) -> Result<PathBuf, UpdateError>
    where
        F: Fn(u64, Option<u64>) + Send + 'static,
    {
        let dest = self.data_dir.join(format!("kirin_desk-{}.exe", release.version));

        let client = reqwest::Client::builder()
            .user_agent("KirinDesk-Updater/1.0")
            .build()
            .map_err(|e| UpdateError::Network(e.to_string()))?;

        let mut response = client
            .get(&release.download_url)
            .send()
            .await
            .map_err(|e| UpdateError::Network(e.to_string()))?;
        if !response.status().is_success() {
            return Err(UpdateError::Network(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let total = response.content_length();

        // Ensure parent directory exists
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = tokio::fs::File::create(&dest).await.map_err(UpdateError::Io)?;
        let mut received: u64 = 0;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| UpdateError::Network(e.to_string()))?
        {
            received += chunk.len() as u64;
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
                .await
                .map_err(UpdateError::Io)?;
            on_progress(received, total);
        }
        tokio::io::AsyncWriteExt::flush(&mut file)
            .await
            .map_err(UpdateError::Io)?;

        Ok(dest)
    }

    /// 距上次自动检查是否已超过 `interval_days`（文件缺失视为需要检查）。
    pub fn should_auto_check(&self, interval_days: u64) -> bool {
        let now = unix_now_secs();
        let last = self
            .last_check_secs()
            .unwrap_or(0);
        now.saturating_sub(last) >= interval_days.saturating_mul(86400)
    }

    /// 记录一次自动检查时间（检查成功后调用；失败不记录以便下次重试）。
    pub fn record_auto_check(&self) -> Result<(), UpdateError> {
        let path = self.last_check_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let stamp = LastCheck {
            epoch_secs: unix_now_secs(),
        };
        std::fs::write(&path, serde_json::to_string(&stamp).map_err(|e| {
            UpdateError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?)?;
        Ok(())
    }

    /// Get the current version string.
    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    /// 数据目录（下载目录 + last_check.json 所在目录）。
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    fn last_check_path(&self) -> PathBuf {
        self.data_dir.join("last_check.json")
    }

    fn last_check_secs(&self) -> Option<u64> {
        let text = std::fs::read_to_string(self.last_check_path()).ok()?;
        serde_json::from_str::<LastCheck>(&text).ok().map(|l| l.epoch_secs)
    }
}

/// 当前 unix epoch 秒。
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

/// 按平台挑选 asset：关键字命中数计分，平分时扩展名偏好胜出；
/// 全部不命中则退回第一个 asset。
fn pick_asset<'a>(assets: &'a [GitHubAsset], platform: Platform) -> Option<&'a GitHubAsset> {
    if assets.is_empty() {
        return None;
    }
    let keywords = platform.asset_keywords();
    let preferred = platform.preferred_extension();

    let mut best: Option<(&GitHubAsset, i32)> = None;
    for asset in assets {
        let name = asset.name.to_ascii_lowercase();
        let mut score = 0i32;
        for kw in keywords {
            if name.contains(kw) {
                score += 1;
            }
        }
        if !preferred.is_empty() && name.ends_with(preferred) {
            score += 1;
        }
        let replace = match best {
            None => score > 0,
            Some((_, best_score)) => score > best_score,
        };
        if replace {
            best = Some((asset, score));
        }
    }
    best.map(|(a, _)| a).or_else(|| assets.first())
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
            asset_name: "KirinDesk-1.0.0-windows-x86_64.exe".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("1.0.0"));
        let parsed: ReleaseInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "1.0.0");
        assert_eq!(parsed.asset_name, "KirinDesk-1.0.0-windows-x86_64.exe");
        // 旧格式（无 asset_name 字段）也能解析
        let old: ReleaseInfo = serde_json::from_str(
            r#"{"version":"1.0.0","download_url":"https://x/y","checksum":"","release_date":"","release_notes":""}"#,
        )
        .unwrap();
        assert_eq!(old.asset_name, "");
    }

    #[test]
    fn test_pick_asset_windows_prefers_exe() {
        let assets = vec![
            asset("KirinDesk-1.0.0-windows-x86_64.zip"),
            asset("KirinDesk-1.0.0-windows-x86_64.exe"),
            asset("KirinDesk-1.0.0-linux-amd64.deb"),
            asset("KirinDesk-1.0.0-universal.dmg"),
        ];
        let picked = pick_asset(&assets, Platform::Windows).unwrap();
        assert_eq!(picked.name, "KirinDesk-1.0.0-windows-x86_64.exe");
    }

    #[test]
    fn test_pick_asset_platform_keyword() {
        let assets = vec![
            asset("KirinDesk-1.0.0-universal.dmg"),
            asset("KirinDesk-1.0.0-windows-x86_64.exe"),
        ];
        assert_eq!(
            pick_asset(&assets, Platform::MacOS).unwrap().name,
            "KirinDesk-1.0.0-universal.dmg"
        );
        assert_eq!(
            pick_asset(&assets, Platform::Linux).unwrap().name,
            "KirinDesk-1.0.0-universal.dmg" // 无 linux 资产 → 退回第一个
        );
    }

    #[test]
    fn test_pick_asset_empty_falls_back_first() {
        let assets = vec![
            asset("KirinDesk-1.0.0-source.tar.gz"),
            asset("KirinDesk-1.0.0-checksums.txt"),
        ];
        assert_eq!(
            pick_asset(&assets, Platform::Windows).unwrap().name,
            "KirinDesk-1.0.0-source.tar.gz"
        );
        assert!(pick_asset(&[], Platform::Windows).is_none());
    }

    #[test]
    fn test_auto_check_interval_and_record() {
        let dir = std::env::temp_dir().join(format!("kirin_desk-update-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let updater = Updater::new(dir.clone(), UpdateChannel::Stable);

        // 无记录 → 需要检查
        assert!(updater.should_auto_check(7));
        updater.record_auto_check().unwrap();
        // 刚记录 → 不需要检查
        assert!(!updater.should_auto_check(7));
        // 间隔拉满（1 天间隔、刚检查过）→ 仍不需要
        assert!(!updater.should_auto_check(1));

        // 伪造 8 天前的检查记录 → 需要检查
        let path = updater.last_check_path();
        let old = LastCheck {
            epoch_secs: unix_now_secs() - 8 * 86400,
        };
        std::fs::write(&path, serde_json::to_string(&old).unwrap()).unwrap();
        assert!(updater.should_auto_check(7));

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn asset(name: &str) -> GitHubAsset {
        GitHubAsset {
            browser_download_url: format!("https://example.com/{name}"),
            name: name.to_string(),
        }
    }
}
