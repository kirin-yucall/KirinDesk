//! KirinDesk 自动更新器 — M14-T005。
//!
//! 检查 GitHub Releases 获取新版本，下载更新并准备安装：
//! - 按平台挑选 release asset（windows/macos/linux 关键字 + 扩展名偏好）
//! - `download_update_with_progress` 流式下载并回报进度
//! - S-06a: 下载后强制按 `.sha256` 侧车校验（`release/publish.sh` + CI 随资产上传）：
//!   侧车缺失（legacy release，无校验信息）→ `ChecksumMissing` 拒绝并引导升级
//!   （legacy 通道 deprecated）；校验和不匹配 → `ChecksumMismatch`；校验失败
//!   一律删除残留文件（不落盘）。
//! - S-06b: 版本号白名单 `^[0-9][0-9A-Za-z._-]*$`（非法 tag → `InvalidTag` 拒绝）；
//!   下载文件名净化（asset 名含 `/`/`..` 等 → 回退 `kirin_desk-{版本}{平台扩展名}`）
//! - R-07: 下载目标文件名按所选 asset 命名（不再硬编码 `.exe`）
//! - `should_auto_check` / `record_auto_check` 支持每周后台静默检查
//! - R-07/S-06c: `install()` 收归安装职责——Windows 用 Win32 `MoveFileExW`
//!   （当前 exe 改名 exe.old → 复制新版 → 启动新版 → 旧镜像登记下次重启删除），
//!   不再生成/执行任何 bat/PowerShell 脚本（消除字符串拼装注入面）；
//!   macOS/Linux 返回手动安装提示。
//!
//! 安装流程（Windows）：下载 → 校验 → `MoveFileExW` 换装 → 启动新版本 → 应用退出。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Current application version (from Cargo.toml).
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// GitHub repository info for updates.
/// M8-T036: 仓库名修正为 `KirinDesk`（与 git remote origin 完全一致；
/// 检查更新走 GitHub Releases API，需在 GitHub 仓库发布 Release 后生效）。
const GITHUB_OWNER: &str = "kirin-yucall";
const GITHUB_REPO: &str = "KirinDesk";

/// Update channel.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UpdateChannel {
    Stable,
    Beta,
}

impl FromStr for UpdateChannel {
    type Err = ();

    /// R-07-S4: 配置字符串 → 通道（`release`/`stable` → Stable，`beta` → Beta；
    /// 其他取值视为解析失败，由调用方回退 Stable）。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "release" | "stable" => Ok(UpdateChannel::Stable),
            "beta" => Ok(UpdateChannel::Beta),
            _ => Err(()),
        }
    }
}

impl UpdateChannel {
    /// R-07-S4: 通道对应的 GitHub API URL——stable → `releases/latest`；
    /// beta → 全部 release 列表（取最新 prerelease）。
    fn releases_url(&self) -> String {
        let base = format!(
            "https://api.github.com/repos/{}/{}/releases",
            GITHUB_OWNER, GITHUB_REPO
        );
        match self {
            UpdateChannel::Stable => format!("{}/latest", base),
            UpdateChannel::Beta => base,
        }
    }
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
    #[error("Checksum mismatch: the downloaded file does not match the published SHA-256")]
    ChecksumMismatch,
    /// S-06a: 侧车缺失 → 拒绝（legacy release deprecated，附升级引导）。
    #[error("Checksum missing: release {0} has no SHA-256 checksum (legacy release, auto-update deprecated). Rejected for safety; please install the latest release from the official site")]
    ChecksumMissing(String),
    /// S-06b: 版本 tag 未通过白名单 `^[0-9][0-9A-Za-z._-]*$`。
    #[error("Invalid release tag '{0}': allowed pattern is ^[0-9][0-9A-Za-z._-]*$")]
    InvalidTag(String),
    #[error("Failed to write update: {0}")]
    Io(#[from] std::io::Error),
}

/// R-07-S3: 安装结果。
#[derive(Debug, Clone)]
pub enum InstallOutcome {
    /// 替换脚本已启动（Windows：旧进程退出后覆盖 exe 并重启；调用方应立即退出）。
    Restarting,
    /// 需要用户手动打开安装包（macOS/Linux），附打开方式提示。
    ManualInstall { artifact: PathBuf, hint: String },
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
        let url = self.channel.releases_url();

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
            // M8-T036: 404 = 仓库尚无 Release（更新检查的常态失败）——给出可执行
            // 的引导而非裸状态码（需在 GitHub 仓库发布 Release 后自动更新生效）。
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return UpdateStatus::Error(format!(
                    "GitHub 仓库 {}/{} 暂无 Release 发布（HTTP 404）— \
                     请在 GitHub 发布 Release 后重试",
                    GITHUB_OWNER, GITHUB_REPO
                ));
            }
            return UpdateStatus::Error(format!("HTTP {}", response.status()));
        }

        // beta 通道拉取的是 release 列表；stable 是单个对象。
        let release = match self.channel {
            UpdateChannel::Stable => match response.json::<GitHubRelease>().await {
                Ok(r) => r,
                Err(e) => return UpdateStatus::Error(e.to_string()),
            },
            UpdateChannel::Beta => match response.json::<Vec<GitHubRelease>>().await {
                Ok(list) => match pick_beta_release(&list) {
                    Some(r) => r.clone(),
                    None => return UpdateStatus::Error("No releases found".to_string()),
                },
                Err(e) => return UpdateStatus::Error(e.to_string()),
            },
        };

        self.to_update_status(release)
    }

    /// R-07: 单个 GitHub release → UpdateStatus（版本比较 + 按平台选 asset）。
    fn to_update_status(&self, release: GitHubRelease) -> UpdateStatus {
        let remote_ver = release.tag_name.trim_start_matches('v');
        // S-06b: 版本号白名单净化——非法 tag（`&`/`../` 等命令注入或路径穿越源）
        // → 拒绝更新，不进下载/安装链。
        if !is_valid_version_tag(remote_ver) {
            return UpdateStatus::Error(format!(
                "invalid release tag {:?} (allowed: ^[0-9][0-9A-Za-z._-]*$)",
                release.tag_name
            ));
        }

        // Compare versions
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
            // R-07-S1: checksum 不在检查阶段拉取——下载完成后按 `.sha256` 侧车校验。
            checksum: String::new(),
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
    ///
    /// R-07-S1/S-06a: 下载完成后强制按 `.sha256` 侧车校验（`release/publish.sh` +
    /// CI 随资产上传）：侧车缺失（legacy release）→ `ChecksumMissing` 拒绝并引导
    /// 升级；校验和不匹配 → `ChecksumMismatch`；任一校验失败 → 删除残留文件（不落盘）。
    pub async fn download_update_with_progress<F>(
        &self,
        release: &ReleaseInfo,
        on_progress: F,
    ) -> Result<PathBuf, UpdateError>
    where
        F: Fn(u64, Option<u64>) + Send + 'static,
    {
        // S-06b: 下载入口强制校验版本白名单（ReleaseInfo 可由外部构造，不信任
        // 检查阶段的净化结果）——非法 tag → 拒绝，不发任何网络请求、不落任何文件。
        if !is_valid_version_tag(&release.version) {
            return Err(UpdateError::InvalidTag(release.version.clone()));
        }

        // R-07-S2: 目标文件名按所选 asset 命名（S-06b: 不安全 asset 名回退安全模板）。
        let dest = self
            .data_dir
            .join(download_file_name_for(release, Platform::current()));

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

        // S-07 (F-8): 下载产物（安装包）新建即 0600（Unix）——安装包内可能
        // 含未公开的发布内容，且落盘期间不应被同机低权限用户读取。
        let mut opts = tokio::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(&dest).await.map_err(UpdateError::Io)?;
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

        verify_download(&client, release, &dest).await?;

        Ok(dest)
    }

    /// R-07-S3/S-06c: 安装已下载的更新文件。
    ///
    /// - Windows：弃用 bat 脚本字符串拼装（命令注入面），改用 Win32 `MoveFileExW`
    ///   三步换装：当前 exe 改名 `exe.old`（Windows 允许改名运行中的 exe）→
    ///   新版本复制到 exe 路径 → 后台启动新版本；旧镜像登记下次系统重启删除
    ///   （`MOVEFILE_DELAY_UNTIL_REBOOT`）。任一步失败回滚改名，原版本不受影响。
    ///   返回 `InstallOutcome::Restarting`——新版本进程已独立启动，调用方随即退出即可。
    /// - macOS/Linux：返回 `InstallOutcome::ManualInstall`（安装包路径 + 打开方式提示）。
    pub fn install(&self, downloaded: &Path) -> Result<InstallOutcome, UpdateError> {
        // S-06c: 安装前置校验——文件必须真实存在（不存在 → 拒绝；同时保证单测
        // 不会误触发 Windows 换装流程）。
        if !downloaded.is_file() {
            return Err(UpdateError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("update artifact not found: {}", downloaded.display()),
            )));
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::ffi::OsStrExt;
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING,
            };

            /// 路径 → 以 NUL 结尾的 UTF-16 宽字符串。
            fn wide(p: &Path) -> Vec<u16> {
                p.as_os_str().encode_wide().chain(Some(0)).collect()
            }

            /// `MoveFileExW` 封装：`new == None` 表示登记删除（DELAY_UNTIL_REBOOT）。
            fn move_file(existing: &Path, new: Option<&Path>, flags: u32) -> std::io::Result<()> {
                let new_wide = new.map(wide);
                let new_ptr = match &new_wide {
                    Some(v) => v.as_ptr(),
                    None => std::ptr::null(),
                };
                let ok = unsafe { MoveFileExW(wide(existing).as_ptr(), new_ptr, flags) };
                if ok == 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }

            let exe = std::env::current_exe()?;
            let old_exe = exe.with_extension("old");

            // 1. 当前 exe → exe.old（运行中可改名不可删）；失败 → 中止，原文件不动。
            move_file(&exe, Some(&old_exe), MOVEFILE_REPLACE_EXISTING)?;
            // 2. 新版本复制到 exe 路径；失败 → 回滚改名。
            if let Err(e) = std::fs::copy(downloaded, &exe) {
                let _ = move_file(&old_exe, Some(&exe), MOVEFILE_REPLACE_EXISTING);
                return Err(UpdateError::Io(e));
            }
            // 3. 后台启动新版本（CREATE_NO_WINDOW）；失败 → 回滚改名。
            let spawned = std::process::Command::new(&exe)
                .creation_flags(0x08000000)
                .spawn();
            if let Err(e) = spawned {
                let _ = move_file(&old_exe, Some(&exe), MOVEFILE_REPLACE_EXISTING);
                return Err(UpdateError::Io(e));
            }
            // 4. 旧镜像（exe.old）仍被本进程映像占用 → 登记下次系统重启删除。
            let _ = move_file(
                &old_exe,
                None,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT,
            );
            // 5. 清理下载残留（新版本已复制到 exe 路径）。
            let _ = std::fs::remove_file(downloaded);
            Ok(InstallOutcome::Restarting)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(InstallOutcome::ManualInstall {
                artifact: downloaded.to_path_buf(),
                hint: manual_install_hint(Platform::current()),
            })
        }
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
#[derive(Debug, Clone, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    published_at: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
    /// R-07-S4: beta 通道按该标记选最新 prerelease。
    #[serde(default)]
    prerelease: bool,
}

#[derive(Debug, Clone, Deserialize)]
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

// ---------------------------------------------------------------------------
// R-07-S1: sha256 校验和（侧车 `<asset>.sha256`，release/publish.sh 随资产上传）
// ---------------------------------------------------------------------------

/// 字节 → 小写 hex 字符串（避免为 hex 引入新依赖）。
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// 计算文件 sha256（hex 小写）。
pub fn sha256_hex(path: &Path) -> Result<String, UpdateError> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(to_hex(&hasher.finalize()))
}

/// 文件实际 sha256 与期望 hex 比对（大小写不敏感）。
pub fn verify_checksum(path: &Path, expected_hex: &str) -> bool {
    match sha256_hex(path) {
        Ok(actual) => actual.eq_ignore_ascii_case(expected_hex.trim()),
        Err(_) => false,
    }
}

/// 侧车 URL：下载 URL 追加 `.sha256`。
pub fn checksum_sidecar_url(download_url: &str) -> String {
    format!("{}.sha256", download_url)
}

/// 解析侧车内容（sha256sum 输出格式 `<hex>  <filename>`，取首个空白分隔 token）。
/// 空 / 非 64 位 hex → `ParseError`（畸形侧车视为不可信，拒绝更新）。
fn parse_sidecar_hex(text: &str) -> Result<String, UpdateError> {
    let expected = text.split_whitespace().next().unwrap_or("").trim();
    if expected.is_empty() {
        return Err(UpdateError::ParseError(
            "empty checksum sidecar".to_string(),
        ));
    }
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(UpdateError::ParseError(
            "malformed checksum sidecar (expected 64 hex chars)".to_string(),
        ));
    }
    Ok(expected.to_string())
}

/// S-06a 纯决策函数（便于单测）：侧车缺失 → `ChecksumMissing`（legacy 拒绝 +
/// 引导）；内容畸形 → `ParseError`；文件哈希不匹配 → `ChecksumMismatch`；通过 → `Ok`。
fn check_download(
    dest: &Path,
    sidecar_found: bool,
    sidecar_text: &str,
    sidecar_url: &str,
) -> Result<(), UpdateError> {
    if !sidecar_found {
        return Err(UpdateError::ChecksumMissing(sidecar_url.to_string()));
    }
    let expected = parse_sidecar_hex(sidecar_text)?;
    if !verify_checksum(dest, &expected) {
        return Err(UpdateError::ChecksumMismatch);
    }
    Ok(())
}

/// 校验已下载文件（HTTP 层封装）。S-06a 策略统一：新版本强制校验——侧车缺失
/// （legacy release）→ `ChecksumMissing` 拒绝；内容畸形/不匹配 → `ParseError`/
/// `ChecksumMismatch`；任一失败删除残留文件（拒绝的更新不落盘）。
async fn verify_download(
    client: &reqwest::Client,
    release: &ReleaseInfo,
    dest: &Path,
) -> Result<(), UpdateError> {
    let sidecar = checksum_sidecar_url(&release.download_url);
    let response = client
        .get(&sidecar)
        .send()
        .await
        .map_err(|e| UpdateError::Network(e.to_string()))?;

    let (found, text) = if response.status() == reqwest::StatusCode::NOT_FOUND {
        (false, String::new())
    } else if !response.status().is_success() {
        return Err(UpdateError::Network(format!(
            "HTTP {}",
            response.status()
        )));
    } else {
        let text = response
            .text()
            .await
            .map_err(|e| UpdateError::Network(e.to_string()))?;
        (true, text)
    };

    if let Err(e) = check_download(dest, found, &text, &sidecar) {
        // 校验失败一律清理残留文件（不落盘）。
        let _ = std::fs::remove_file(dest);
        return Err(e);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// R-07-S2: 下载目标文件名（平台化，不再硬编码 .exe）+ S-06b 净化
// ---------------------------------------------------------------------------

/// S-06b: 版本号白名单校验（`^[0-9][0-9A-Za-z._-]*$`）。
/// 非法 tag（`&`/`|`/`;`/`../` 等命令注入或路径穿越源）→ 拒绝进入下载/安装链。
pub fn is_valid_version_tag(version: &str) -> bool {
    let mut chars = version.chars();
    match chars.next() {
        Some(c) if c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// asset 文件名安全校验：纯文件名（无路径分隔符 / `..` / NUL），仅允许安全字符，
/// 长度 ≤ 255（Windows MAX_PATH 文件名上限）。
fn is_safe_asset_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    !name.contains(['/', '\\', '\0'])
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// 不安全版本串兜底净化（入口已拒绝非法 tag，此处仅防御性处理直接调用方）。
fn sanitize_version_for_filename(version: &str) -> String {
    let mut cleaned: String = version
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    // 去掉前导点（防 "../" 过滤后残留 ".." 开头，引起审计误判）。
    while cleaned.starts_with('.') {
        cleaned.remove(0);
    }
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

/// 下载目标文件名：优先用 release 所选 asset 名（publish 时按平台命名，
/// 如 `KirinDesk-1.2.3-windows-x86_64.exe`）——但仅当其为安全纯文件名
/// （S-06b，防 `../` 路径穿越与注入字符）；否则回退
/// `kirin_desk-{version}{平台扩展名}`（版本号同样白名单净化）。
pub fn download_file_name_for(release: &ReleaseInfo, platform: Platform) -> String {
    if !release.asset_name.is_empty() && is_safe_asset_name(&release.asset_name) {
        return release.asset_name.clone();
    }
    format!(
        "kirin_desk-{}{}",
        sanitize_version_for_filename(&release.version),
        platform.preferred_extension()
    )
}

// ---------------------------------------------------------------------------
// R-07-S3: 安装辅助（Windows 换装在 `Updater::install` 内用 `MoveFileExW` 实现，
// 不再生成/执行任何脚本——S-06c 消除 bat 字符串拼装注入面）
// ---------------------------------------------------------------------------

/// 非 Windows 平台的手动安装提示（按平台定制；纯函数便于跨平台单测）。
pub fn manual_install_hint(platform: Platform) -> String {
    match platform {
        Platform::MacOS => "请在 Finder 中打开该文件并拖入「应用程序」完成安装。".to_string(),
        Platform::Linux => "请用软件安装器打开该文件完成安装（如 sudo dpkg -i <file>）。".to_string(),
        _ => "请手动打开该文件完成安装。".to_string(),
    }
}

/// R-07-S4: beta 通道选 release — 最新 prerelease；无 prerelease → 最新 stable（列表首项）。
fn pick_beta_release(releases: &[GitHubRelease]) -> Option<&GitHubRelease> {
    releases
        .iter()
        .find(|r| r.prerelease)
        .or_else(|| releases.first())
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

    // ── R-07 新增测试 ──────────────────────────────────────────

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(to_hex(&[0x00, 0x01, 0x0a]), "00010a");
    }

    #[test]
    fn test_sha256_and_verify_checksum() {
        // "hello" 的 SHA-256 已知值
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let dir = std::env::temp_dir().join(format!("kirin_desk_checksum_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.bin");
        std::fs::write(&path, b"hello").unwrap();

        assert_eq!(sha256_hex(&path).unwrap(), expected);
        assert!(verify_checksum(&path, expected));
        assert!(verify_checksum(&path, &expected.to_uppercase()), "hex 大小写不敏感");
        assert!(!verify_checksum(&path, "0000000000000000000000000000000000000000000000000000000000000000"));
        assert!(!verify_checksum(&path, "not-hex"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_checksum_sidecar_url() {
        assert_eq!(
            checksum_sidecar_url("https://example.com/KirinDesk-1.0.0-windows-x86_64.exe"),
            "https://example.com/KirinDesk-1.0.0-windows-x86_64.exe.sha256"
        );
    }

    #[test]
    fn test_download_file_name_for() {
        let info = ReleaseInfo {
            version: "1.2.3".to_string(),
            download_url: "https://example.com/x".to_string(),
            checksum: String::new(),
            release_date: String::new(),
            release_notes: String::new(),
            asset_name: "KirinDesk-1.2.3-windows-x86_64.exe".to_string(),
        };
        // asset_name 非空 → 优先使用（不再硬编码 kirin_desk-{v}.exe）
        assert_eq!(
            download_file_name_for(&info, Platform::Windows),
            "KirinDesk-1.2.3-windows-x86_64.exe"
        );
        assert_eq!(
            download_file_name_for(&info, Platform::MacOS),
            "KirinDesk-1.2.3-windows-x86_64.exe"
        );

        // 回退：按平台扩展名
        let mut fallback = info.clone();
        fallback.asset_name = String::new();
        assert_eq!(
            download_file_name_for(&fallback, Platform::Windows),
            "kirin_desk-1.2.3.exe"
        );
        assert_eq!(
            download_file_name_for(&fallback, Platform::MacOS),
            "kirin_desk-1.2.3.dmg"
        );
        assert_eq!(
            download_file_name_for(&fallback, Platform::Linux),
            "kirin_desk-1.2.3.deb"
        );
        assert_eq!(
            download_file_name_for(&fallback, Platform::Other),
            "kirin_desk-1.2.3"
        );
    }

    #[test]
    fn test_update_channel_parse_and_url() {
        assert_eq!("release".parse::<UpdateChannel>().unwrap(), UpdateChannel::Stable);
        assert_eq!("stable".parse::<UpdateChannel>().unwrap(), UpdateChannel::Stable);
        assert_eq!("RELEASE".parse::<UpdateChannel>().unwrap(), UpdateChannel::Stable);
        assert_eq!(" beta ".parse::<UpdateChannel>().unwrap(), UpdateChannel::Beta);
        assert!("garbage".parse::<UpdateChannel>().is_err());
        assert!("".parse::<UpdateChannel>().is_err());

        assert!(UpdateChannel::Stable.releases_url().ends_with("/releases/latest"));
        let beta_url = UpdateChannel::Beta.releases_url();
        assert!(beta_url.ends_with("/releases"));
        assert!(!beta_url.ends_with("/latest"));
    }

    #[test]
    fn test_pick_beta_release() {
        let releases = vec![
            release("v1.0.0", false),
            release("v1.1.0-beta.1", true),
            release("v1.0.1", false),
        ];
        // 取最新 prerelease
        assert_eq!(
            pick_beta_release(&releases).unwrap().tag_name,
            "v1.1.0-beta.1"
        );
        // 无 prerelease → 最新 stable（列表首项）
        let stables = vec![release("v2.0.0", false), release("v1.0.0", false)];
        assert_eq!(pick_beta_release(&stables).unwrap().tag_name, "v2.0.0");
        // 空列表 → None
        assert!(pick_beta_release(&[]).is_none());
    }

    #[test]
    fn test_manual_install_hint() {
        let mac = manual_install_hint(Platform::MacOS);
        let linux = manual_install_hint(Platform::Linux);
        assert!(mac.contains("Finder"));
        assert!(linux.contains("dpkg"));
        assert_ne!(mac, linux);
        assert!(!manual_install_hint(Platform::Other).is_empty());
    }

    // ── S-06 新增测试（更新链完整性 + 安装注入防护）─────────────

    #[test]
    fn test_is_valid_version_tag() {
        // 合法：数字开头 + [0-9A-Za-z._-]
        for ok in [
            "1.2.3",
            "1.2.3-beta.1",
            "2.0",
            "10",
            "1.0.0.1",
            "1.0.0_build5",
            "0.9.9",
            "2026.8.2",
        ] {
            assert!(is_valid_version_tag(ok), "should accept {ok:?}");
        }
        // 非法：命令注入 / 路径穿越 / 空白 / 空串 / 非数字开头
        for bad in [
            "",
            "1.0.0&calc",
            "1.0.0|whoami",
            "1.0.0;rm",
            "1.0.0%25",
            "1.0.0^",
            "../1.0.0",
            "1.0.0/../../evil",
            "..\\1.0.0",
            "1.0.0\\evil",
            "-1.0.0",
            ".1.0.0",
            " 1.0.0",
            "v1.0.0",
            "1.0.0+build",
            "1.0.0'",
            "1.0.0\"",
            "1.0.0 ",
            "1.0.0\n",
        ] {
            assert!(!is_valid_version_tag(bad), "should reject {bad:?}");
        }
        // 注：`v` 前缀由 to_update_status 先 trim 再校验（"v1.0.0" 本身不合规）
    }

    #[test]
    fn test_to_update_status_rejects_malicious_tag() {
        let updater = Updater::new(std::env::temp_dir(), UpdateChannel::Stable);
        let assets = vec![asset("KirinDesk-1.0.0-windows-x86_64.exe")];
        // 注入元字符
        let inj = GitHubRelease {
            tag_name: "v1.0.0&whoami".to_string(),
            body: String::new(),
            published_at: String::new(),
            assets: assets.clone(),
            prerelease: false,
        };
        assert!(
            matches!(updater.to_update_status(inj), UpdateStatus::Error(_)),
            "注入 tag 必须被拒绝"
        );
        // 路径穿越
        let trav = GitHubRelease {
            tag_name: "v../evil".to_string(),
            body: String::new(),
            published_at: String::new(),
            assets: assets.clone(),
            prerelease: false,
        };
        assert!(
            matches!(updater.to_update_status(trav), UpdateStatus::Error(_)),
            "穿越 tag 必须被拒绝"
        );
        // 合法 tag 正常通过
        let ok = GitHubRelease {
            tag_name: "v2.0.0".to_string(),
            body: String::new(),
            published_at: String::new(),
            assets,
            prerelease: false,
        };
        match updater.to_update_status(ok) {
            UpdateStatus::Available(info) => assert_eq!(info.version, "2.0.0"),
            other => panic!("expected Available, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_download_rejects_invalid_tag_without_network() {
        let dir = std::env::temp_dir().join(format!("kirin_desk_s06_tag_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let updater = Updater::new(dir.clone(), UpdateChannel::Stable);
        let info = ReleaseInfo {
            version: "1.0.0&calc".to_string(),
            // 不应被访问（校验先于任何网络请求）
            download_url: "http://127.0.0.1:1/never".to_string(),
            checksum: String::new(),
            release_date: String::new(),
            release_notes: String::new(),
            asset_name: String::new(),
        };
        let err = updater.download_update(&info).await.unwrap_err();
        assert!(matches!(err, UpdateError::InvalidTag(_)));
        // 拒绝路径不得落任何文件
        assert_eq!(
            std::fs::read_dir(&dir).map(|it| it.count()).unwrap_or(0),
            0,
            "invalid tag must not persist anything"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_check_download_policy() {
        let dir = std::env::temp_dir().join(format!("kirin_desk_s06_policy_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.bin");
        std::fs::write(&path, b"hello").unwrap();
        let good = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let url = "https://example.com/KirinDesk-1.2.3-windows-x86_64.exe.sha256";

        // 侧车缺失（legacy）→ ChecksumMissing（统一策略：拒绝 + 引导，不再 fail-open）
        assert!(matches!(
            check_download(&path, false, "", url),
            Err(UpdateError::ChecksumMissing(_))
        ));
        // 空内容 → ParseError
        assert!(matches!(
            check_download(&path, true, "", url),
            Err(UpdateError::ParseError(_))
        ));
        // 畸形（非 64 hex）→ ParseError
        assert!(matches!(
            check_download(&path, true, "not-a-hex  x", url),
            Err(UpdateError::ParseError(_))
        ));
        // 内容不匹配 → ChecksumMismatch
        assert!(matches!(
            check_download(&path, true, &format!("{}  payload.bin", "0".repeat(64)), url),
            Err(UpdateError::ChecksumMismatch)
        ));
        // 正确 → Ok（hex 大小写不敏感）
        check_download(&path, true, &format!("{}  payload.bin", good.to_uppercase()), url)
            .unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_download_file_name_sanitizes_unsafe_asset() {
        let mk = |asset_name: &str| ReleaseInfo {
            version: "1.2.3".to_string(),
            download_url: "https://example.com/x".to_string(),
            checksum: String::new(),
            release_date: String::new(),
            release_notes: String::new(),
            asset_name: asset_name.to_string(),
        };
        // 安全 asset 名原样保留
        assert_eq!(
            download_file_name_for(&mk("KirinDesk-1.2.3-windows-x86_64.exe"), Platform::Windows),
            "KirinDesk-1.2.3-windows-x86_64.exe"
        );
        // 路径穿越 → 回退安全模板
        assert_eq!(
            download_file_name_for(&mk("../evil.exe"), Platform::Windows),
            "kirin_desk-1.2.3.exe"
        );
        assert_eq!(
            download_file_name_for(&mk(r"..\..\evil.exe"), Platform::Windows),
            "kirin_desk-1.2.3.exe"
        );
        // 注入字符 → 回退
        assert_eq!(
            download_file_name_for(&mk("1.0.0&whoami.exe"), Platform::Windows),
            "kirin_desk-1.2.3.exe"
        );
        // 回退名按平台扩展名（S-06b：复用 preferred_extension）
        assert_eq!(
            download_file_name_for(&mk("../../evil"), Platform::Linux),
            "kirin_desk-1.2.3.deb"
        );
        assert_eq!(
            download_file_name_for(&mk("a/b"), Platform::MacOS),
            "kirin_desk-1.2.3.dmg"
        );
        // 非法版本 + 不安全 asset → 兜底净化（防御性；正常流程入口已拒绝）
        let mut bad = mk("../evil.exe");
        bad.version = "../1.0.0&x".to_string();
        let name = download_file_name_for(&bad, Platform::Windows);
        assert!(name.starts_with("kirin_desk-"));
        assert!(!name.contains(".."));
        assert!(!name.contains('&'));
        assert!(!name.contains('/'));
        assert!(!name.contains('\\'));
    }

    #[test]
    fn test_install_rejects_missing_file() {
        let dir = std::env::temp_dir().join(format!("kirin_desk_s06_install_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let updater = Updater::new(dir.clone(), UpdateChannel::Stable);
        let missing = dir.join("does-not-exist.exe");
        assert!(updater.install(&missing).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 迷你 HTTP 服务器：按顺序响应 `(status, body)` 对（payload + 侧车各一连接）。
    async fn start_fake_update_server(
        responses: Vec<(u16, String)>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            for (status, body) in responses {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 512];
                loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                        break;
                    }
                }
                let reason = if status == 200 { "OK" } else { "Not Found" };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        (format!("http://127.0.0.1:{}", addr.port()), handle)
    }

    fn release_info_for(url: &str) -> ReleaseInfo {
        ReleaseInfo {
            version: "1.2.3".to_string(),
            download_url: url.to_string(),
            checksum: String::new(),
            release_date: String::new(),
            release_notes: String::new(),
            asset_name: "KirinDesk-1.2.3-windows-x86_64.exe".to_string(),
        }
    }

    #[tokio::test]
    async fn test_download_missing_sidecar_rejected_and_not_persisted() {
        let (base, server) = start_fake_update_server(vec![
            (200, "hello".to_string()),
            (404, String::new()),
        ])
        .await;
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_s06_missing_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let updater = Updater::new(dir.clone(), UpdateChannel::Stable);
        let url = format!("{base}/KirinDesk-1.2.3-windows-x86_64.exe");
        let err = updater
            .download_update(&release_info_for(&url))
            .await
            .unwrap_err();
        assert!(
            matches!(err, UpdateError::ChecksumMissing(_)),
            "expected ChecksumMissing, got {err:?}"
        );
        // 拒绝且不落盘
        assert!(!dir.join("KirinDesk-1.2.3-windows-x86_64.exe").exists());
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_download_mismatch_rejected_and_not_persisted() {
        let (base, server) = start_fake_update_server(vec![
            (200, "hello".to_string()),
            (
                200,
                format!(
                    "0000000000000000000000000000000000000000000000000000000000000000  KirinDesk-1.2.3-windows-x86_64.exe\n"
                ),
            ),
        ])
        .await;
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_s06_mismatch_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let updater = Updater::new(dir.clone(), UpdateChannel::Stable);
        let url = format!("{base}/KirinDesk-1.2.3-windows-x86_64.exe");
        let err = updater
            .download_update(&release_info_for(&url))
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::ChecksumMismatch));
        // 拒绝且不落盘
        assert!(!dir.join("KirinDesk-1.2.3-windows-x86_64.exe").exists());
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_download_ok_with_sidecar_persists() {
        let good = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let (base, server) = start_fake_update_server(vec![
            (200, "hello".to_string()),
            (200, format!("{good}  KirinDesk-1.2.3-windows-x86_64.exe\n")),
        ])
        .await;
        let dir = std::env::temp_dir().join(format!("kirin_desk_s06_ok_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let updater = Updater::new(dir.clone(), UpdateChannel::Stable);
        let url = format!("{base}/KirinDesk-1.2.3-windows-x86_64.exe");
        let dest = updater
            .download_update(&release_info_for(&url))
            .await
            .unwrap();
        assert_eq!(dest, dir.join("KirinDesk-1.2.3-windows-x86_64.exe"));
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello");
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn release(tag: &str, prerelease: bool) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag.to_string(),
            body: String::new(),
            published_at: String::new(),
            assets: vec![],
            prerelease,
        }
    }

    fn asset(name: &str) -> GitHubAsset {
        GitHubAsset {
            browser_download_url: format!("https://example.com/{name}"),
            name: name.to_string(),
        }
    }
}
