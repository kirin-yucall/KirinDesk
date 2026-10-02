//!
//! `release/download-ffmpeg.bat|.sh` 降级为**离线兜底**（文档口径同步调整）。
//!
//! 1. 启动时 `media::ffmpeg::ensure_loaded()` 探测（复用 `FFMPEG_LOADED` 槽，
//!    见 `ui/src/lib.rs`）；失败 → 后台线程自动开始安装；
//! 2. 双源下载：主源 BtbN/FFmpeg-Builds `latest` n8.1 win64 gpl shared zip
//!    （FFmpeg 8.1.x → avcodec-62，与偏移快照 major=62 兼容），备源
//!    gyan.dev `ffmpeg-release-full-shared.7z`（仅保留最新版，若为 9.x
//!    avcodec-63 则 7 个 DLL 名不齐 → 校验拒绝，绝不静默安装不兼容 DLL）；
//!    如实记录，不入源列表）；
//! 3. sha256 校验（fail-closed）：主源对照 BtbN 官方 `checksums.sha256` 清单，
//!    备源对照 `.sha256` 侧车；**校验值不可得 / 下载失败 / 校验不匹配一律
//!    应用内不回退）；
//! 4. 解压（zip 用 `zip` crate；7z 用 `sevenz-rust`）提取 7 个 DLL +
//!    LICENSE，校验 7 个 DLL 齐且非零；
//! 5. 部署到 exe 旁 `{exe_dir}/../ffmpeg/bin/`（`media` 加载器
//!    `LIB_SEARCH_PATHS` 首位搜索路径）；完成后提示重启应用生效
//!    （`ensure_loaded` 的 OnceLock 已固化失败结果，进程内不重载）。
//!
//! 状态经 `Arc<Mutex<SetupPhase>>` 共享给 UI 线程（Dashboard 状态行：
//! 下载中 x% / 校验中 / 解压中 / 失败原因 + 重试），下载/解压在独立线程 +
//!
//! 单测覆盖纯函数层（URL/清单解析/校验比对/路径计算/状态机/zip 提取本地
//! fixture）；涉及网络的实际下载不在测试中真跑。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// 运行所需的 7 个 FFmpeg DLL（与 `media/src/ffmpeg/dlls.rs` 加载器口径
pub const REQUIRED_DLLS: [&str; 7] = [
    "avcodec-62.dll",
    "avdevice-62.dll",
    "avformat-62.dll",
    "avutil-60.dll",
    "swresample-6.dll",
    "swscale-9.dll",
];

/// BtbN 官方 checksums.sha256 清单（`latest` release 固定资产）。
pub const BTBN_CHECKSUMS_URL: &str =
    "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/checksums.sha256";

/// 主源：BtbN n8.1 win64 gpl shared zip（FFmpeg 8.1.x → avcodec-62）。
pub const BTBN_ARCHIVE_URL: &str = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip";

/// 备源：gyan.dev 官方 full shared（.7z；仅保留最新版，可能为 9.x 不兼容，
/// 由 7-DLL 名单校验拒绝——fail-closed）。
pub const GYAN_ARCHIVE_URL: &str =
    "https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-full-shared.7z";

/// sha256 校验值获取方式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumSource {
    /// BtbN 官方 `checksums.sha256` 清单中按压缩包名查行。
    BtbNManifest,
    /// 侧车 `<url>.sha256`（gyan.dev），取首个空白分隔 token。
    Sidecar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DownloadSource {
    /// 展示名（Dashboard 状态行「下载中（BtbN 主源）x%」）。
    pub name: &'static str,
    pub archive_url: &'static str,
    pub checksum: ChecksumSource,
}

/// 双源源表（顺序即回退顺序）。
pub fn sources() -> Vec<DownloadSource> {
    vec![
        DownloadSource {
            name: "BtbN",
            archive_url: BTBN_ARCHIVE_URL,
            checksum: ChecksumSource::BtbNManifest,
        },
        DownloadSource {
            name: "gyan.dev",
            archive_url: GYAN_ARCHIVE_URL,
            checksum: ChecksumSource::Sidecar,
        },
    ]
}

// ════════════════════════════════════════════════════════════════
// 状态机（纯函数转换，UI/worker 共用；单测覆盖）
// ════════════════════════════════════════════════════════════════

/// 安装状态（Dashboard 状态行渲染依据）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupPhase {
    /// 未开始（探测通过/尚未触发）。
    Idle,
    /// 正在从 `source` 下载（percent 0-100）。
    Downloading { source: &'static str, percent: u8 },
    /// 正在拉取/比对 sha256。
    Verifying,
    /// 正在解压提取 DLL。
    Extracting,
    /// 正在校验部署结果。
    Deploying,
    /// 安装完成（提示重启应用生效）。
    Done,
    /// 全部源失败（reason 含最后失败原因；UI 提供重试）。
    Failed { reason: String },
}

/// 驱动状态机的事件（worker 产生；`next_phase` 纯函数转换，单测覆盖）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupEvent {
    Start { source: &'static str },
    Progress { percent: u8 },
    Downloaded,
    Verified,
    Extracted,
    Deployed,
    Fail(String),
}

/// 状态机转换（纯函数）：非法跃迁保持原状（worker 顺序调用，防御性）。
pub fn next_phase(cur: &SetupPhase, ev: &SetupEvent) -> SetupPhase {
    use SetupEvent as E;
    use SetupPhase as P;
    match ev {
        E::Start { source } => P::Downloading {
            source,
            percent: 0,
        },
        E::Progress { percent } => match cur {
            P::Downloading { source, .. } => P::Downloading {
                source,
                percent: *percent,
            },
            _ => cur.clone(),
        },
        E::Downloaded => P::Verifying,
        E::Verified => P::Extracting,
        E::Extracted => P::Deploying,
        E::Deployed => P::Done,
        E::Fail(reason) => P::Failed {
            reason: reason.clone(),
        },
    }
}

/// 是否处于进行中的阶段（UI 据此 request_repaint 刷新进度）。
pub fn is_active(phase: &SetupPhase) -> bool {
    !matches!(
        phase,
        SetupPhase::Idle | SetupPhase::Done | SetupPhase::Failed { .. }
    )
}

// ════════════════════════════════════════════════════════════════
// 纯函数：解析 / 校验 / 路径（单测覆盖）
// ════════════════════════════════════════════════════════════════

/// URL 末段文件名（`archive_name(".../x.zip") == "x.zip"`；无 `/` 回退整串）。
pub fn archive_name(url: &str) -> &str {
    match url.rsplit('/').next() {
        Some(n) if !n.is_empty() => n,
        _ => url,
    }
}

/// 侧车 URL：下载 URL 追加 `.sha256`（gyan.dev 口径）。
pub fn sidecar_url(url: &str) -> String {
    format!("{}.sha256", url)
}

/// 解析 BtbN `checksums.sha256` 清单：按压缩包名匹配行，取首个 token（hex）。
/// 清单格式为 sha256sum 风格 `<hex>  <filename>`（可能多行/大小写混合）。
pub fn parse_checksum_manifest(manifest: &str, archive: &str) -> Option<String> {
    for line in manifest.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 文件名含空格的可能性极低（BtbN 资产名无空格），从右找首个空白
        // 分隔 token 作为文件名、其余首 token 为 hex。
        let mut it = line.split_whitespace();
        let hex = it.next()?;
        let name = it.next()?;
        if name.eq_ignore_ascii_case(archive) {
            return Some(hex.to_ascii_lowercase());
        }
    }
    None
}

/// 解析侧车内容：取首个空白分隔 token（hex，小写化）。
pub fn parse_sidecar_checksum(text: &str) -> Option<String> {
    text.split_whitespace().next().map(|h| h.to_ascii_lowercase())
}

/// hex 比对（大小写不敏感）。
pub fn hex_ci_eq(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// 解压条目名净化：仅保留文件名分量（剥目录），含 `..`/空名/盘符 → None
/// （zip-slip 防御；我们只按名提取 DLL/LICENSE，不保留目录结构）。
pub fn sanitized_flat_name(entry_name: &str) -> Option<String> {
    let flat = entry_name.replace('\\', "/");
    if flat.contains("..") || flat.contains(':') {
        return None;
    }
    let name = flat.rsplit('/').next()?.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

/// 部署目录：`{exe_dir}/../ffmpeg/bin/`（`media` 加载器 LIB_SEARCH_PATHS
pub fn deploy_bin_dir(exe_path: &Path) -> PathBuf {
    let exe_dir = exe_path.parent().unwrap_or(Path::new("."));
    exe_dir.join("../ffmpeg/bin")
}

/// [`validate_dll_set`] 名单口径）。完整 → `Some(部署目录)`；缺失/空目录/
/// 不可读 → `None`。
///
/// 用途：①启动自检——DLL 已部署但进程内加载失败（版本不符/路径异常）时
/// 明确提示「已安装，需重启进程生效」而非重复触发下载；②安装完成后对账。
/// 纯文件检查，不触碰 `media` 加载器（其 `OnceLock` 一次性固化口径不变）。
pub fn deployed_dll_dir(exe_path: &Path) -> Option<PathBuf> {
    let bin_dir = deploy_bin_dir(exe_path);
    if !bin_dir.is_dir() {
        return None;
    }
    let found: Vec<(String, u64)> = std::fs::read_dir(&bin_dir)
        .ok()?
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| {
            (
                e.file_name().to_string_lossy().to_string(),
                e.metadata().map(|m| m.len()).unwrap_or(0),
            )
        })
        .collect();
    validate_dll_set(&found).ok()?;
    Some(bin_dir)
}

/// 校验找到的文件集合（(文件名, 字节数)）：7 个 DLL 齐且非零，否则 Err
/// （缺名清单）。zip 提取为展平名单；7z 全量解压后递归扫描亦展平传入。
pub fn validate_dll_set(found: &[(String, u64)]) -> Result<(), String> {
    for dll in REQUIRED_DLLS {
        match found.iter().find(|(n, _)| n.eq_ignore_ascii_case(dll)) {
            Some((_, sz)) if *sz > 0 => {}
            Some((_, _)) => {
                return Err(format!("{dll} 体积为 0（提取不完整）"));
            }
            None => {
                return Err(format!(
                    "缺少 {dll}——源构建可能不是 FFmpeg 8.1.x（avcodec-62）"
                ));
            }
        }
    }
    Ok(())
}

/// 字节 sha256（hex 小写）——校验比对用（与大文件流式无关，压缩包常驻内存）。
pub fn sha256_hex_bytes(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ════════════════════════════════════════════════════════════════
// worker：异步下载 + 校验 + 解压 + 部署（不阻塞 UI 线程）
// ════════════════════════════════════════════════════════════════

type PhaseSlot = Arc<Mutex<SetupPhase>>;

fn set_phase(slot: &PhaseSlot, ev: &SetupEvent) {
    if let Ok(mut ph) = slot.lock() {
        *ph = next_phase(&ph, ev);
    }
}

/// domain_panel 的 worker 模式）。返回共享状态槽供 UI 轮询渲染。
pub fn spawn_setup() -> PhaseSlot {
    let slot: PhaseSlot = Arc::new(Mutex::new(SetupPhase::Idle));
    spawn_with_slot(Arc::clone(&slot));
    slot
}

/// 在既有状态槽上（重）启动一次安装（重试按钮复用：槽置 Idle 后再调）。
pub fn spawn_with_slot(slot: PhaseSlot) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                set_phase(&slot, &SetupEvent::Fail(format!("创建下载运行时失败: {e}")));
                return;
            }
        };
        rt.block_on(run_setup(slot));
    });
}

/// 依次尝试双源；任一源成功即 Done，全部失败 → Failed（fail-closed，
/// 中途任何环节失败即弃当前源跳下一源，绝不部署半成品）。
async fn run_setup(slot: PhaseSlot) {
    let mut last_err = String::new();
    for src in sources() {
        match try_source(&src, &slot).await {
            Ok(()) => {
                set_phase(&slot, &SetupEvent::Deployed);
                tracing::info!(target: "kirin::ffmpeg_setup",
                    "FFmpeg runtime installed from {} -> OK", src.name);
                // （ffmpeg::INIT `OnceLock<Result<..>>`）在启动探测失败时已
                // 固化失败结果，且 `fn_table() -> &'static FnTable` 与该
                // OnceLock 绑定；reload 需重构整个 FFI 访问层（超本任务
                // 「参数/管线逻辑」口径、触碰编码器加载本体红线）。如实
                // 走提示路径：WARN 落日志 + UI 状态行 `Ph::Done` 渲染
                // i18n `dashboard.ffmpeg.installed_restart` 横幅。
                tracing::warn!(target: "kirin::ffmpeg_setup",
                    "FFmpeg 刚安装完成——本进程加载器已固化启动探测的失败结果 \
                     (OnceLock 一次性，进程内不可 reload)；重启进程后 H.264 \
                return;
            }
            Err(e) => {
                tracing::warn!(target: "kirin::ffmpeg_setup",
                    "FFmpeg source {} failed: {e}", src.name);
                last_err = format!("[{}] {e}", src.name);
            }
        }
    }
    set_phase(&slot, &SetupEvent::Fail(last_err));
}

async fn try_source(src: &DownloadSource, slot: &PhaseSlot) -> Result<(), String> {
    set_phase(slot, &SetupEvent::Start { source: src.name });

    // ── 下载（流式，进度回调更新 Downloading.percent）──
    let client = reqwest::Client::builder()
        .user_agent(concat!("KirinDesk/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("HTTP 客户端构建失败: {e}"))?;
    let resp = client
        .get(src.archive_url)
        .timeout(std::time::Duration::from_secs(600))
        .send()
        .await
        .map_err(|e| format!("下载失败: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("下载失败: HTTP {}", resp.status()));
    }
    let total = resp.content_length().unwrap_or(0);
    let mut bytes: Vec<u8> = Vec::with_capacity(total as usize);
    let mut resp = resp;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("下载中断: {e}"))?
    {
        bytes.extend_from_slice(&chunk);
        if total > 0 {
            let pct = ((bytes.len() as u64) * 100 / total).min(100) as u8;
            set_phase(slot, &SetupEvent::Progress { percent: pct });
        }
    }
    set_phase(slot, &SetupEvent::Downloaded);

    // ── sha256 校验（fail-closed：校验值不可得即失败，不回退数量门禁）──
    let expected = match src.checksum {
        ChecksumSource::BtbNManifest => {
            let manifest = client
                .get(BTBN_CHECKSUMS_URL)
                .timeout(std::time::Duration::from_secs(60))
                .send()
                .await
                .map_err(|e| format!("checksums.sha256 清单拉取失败: {e}"))?
                .error_for_status()
                .map_err(|e| format!("checksums.sha256 清单拉取失败: {e}"))?
                .text()
                .await
                .map_err(|e| format!("checksums.sha256 清单读取失败: {e}"))?;
            parse_checksum_manifest(&manifest, archive_name(src.archive_url))
                .ok_or_else(|| {
                    "checksums.sha256 清单中未找到对应压缩包条目（fail-closed 拒装）"
                        .to_string()
                })?
        }
        ChecksumSource::Sidecar => {
            let text = client
                .get(sidecar_url(src.archive_url))
                .timeout(std::time::Duration::from_secs(60))
                .send()
                .await
                .map_err(|e| format!("sha256 侧车拉取失败: {e}"))?
                .error_for_status()
                .map_err(|e| format!("sha256 侧车拉取失败: {e}"))?
                .text()
                .await
                .map_err(|e| format!("sha256 侧车读取失败: {e}"))?;
            parse_sidecar_checksum(&text).ok_or_else(|| {
                "sha256 侧车内容不可解析（fail-closed 拒装）".to_string()
            })?
        }
    };
    let actual = sha256_hex_bytes(&bytes);
    if !hex_ci_eq(&actual, &expected) {
        return Err(format!(
            "sha256 不匹配（期望 {expected}，实际 {actual}）——弃源拒装"
        ));
    }

    // ── 解压（zip / 7z），提取 7 DLL + LICENSE 到临时目录 ──
    let work = std::env::temp_dir().join(format!(
        "kirin-ffmpeg-setup-r56-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("临时目录创建失败: {e}"))?;
    let archive_path = work.join(archive_name(src.archive_url));
    std::fs::write(&archive_path, &bytes).map_err(|e| format!("临时文件写入失败: {e}"))?;
    let name = archive_name(src.archive_url).to_ascii_lowercase();
    if name.ends_with(".zip") {
        extract_zip_matched(&archive_path, &work)
            .map_err(|e| format!("zip 解压失败: {e}"))?;
    } else if name.ends_with(".7z") {
        let sevenz_file = std::fs::File::open(&archive_path)
            .map_err(|e| format!("7z 打开失败: {e}"))?;
        sevenz_rust::decompress(sevenz_file, &work)
            .map_err(|e| format!("7z 解压失败: {e}"))?;
        // 7z 全量解压后展平所需文件（DLL/LICENSE）到 work 根，统一后续校验。
        flatten_matched(&work)?;
    } else {
        return Err(format!("不支持的压缩包类型: {name}"));
    }
    set_phase(slot, &SetupEvent::Verified);

    // ── 校验 7 DLL 齐且非零 ──
    let mut found: Vec<(String, u64)> = Vec::new();
    for entry in std::fs::read_dir(&work).map_err(|e| format!("临时目录读取失败: {e}"))? {
        let entry = entry.map_err(|e| format!("临时目录遍历失败: {e}"))?;
        if entry.path().is_file() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if REQUIRED_DLLS
                .iter()
                .any(|d| fname.eq_ignore_ascii_case(d))
                || fname.eq_ignore_ascii_case("LICENSE")
            {
                let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
                found.push((fname, sz));
            }
        }
    }
    validate_dll_set(&found)?;
    set_phase(slot, &SetupEvent::Extracted);

    // ── 部署到 exe 旁 ffmpeg/bin（LIB_SEARCH_PATHS 首位）──
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("./kirin.exe"));
    let bin_dir = deploy_bin_dir(&exe);
    std::fs::create_dir_all(&bin_dir).map_err(|e| format!("部署目录创建失败: {e}"))?;
    for (fname, _) in &found {
        if fname.eq_ignore_ascii_case("LICENSE") {
        }
        let src_f = work.join(fname);
        let dst = bin_dir.join(fname);
        std::fs::copy(&src_f, &dst).map_err(|e| format!("部署 {fname} 失败: {e}"))?;
    }
    for (fname, _) in &found {
        if fname.eq_ignore_ascii_case("LICENSE") {
            let _ = std::fs::copy(work.join(fname), bin_dir.join("../LICENSE"));
        }
    }
    // 部署后终检（部署目录内 7 DLL 齐且非零）。
    let deployed: Vec<(String, u64)> = std::fs::read_dir(&bin_dir)
        .map_err(|e| format!("部署目录读取失败: {e}"))?
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| {
            (
                e.file_name().to_string_lossy().to_string(),
                e.metadata().map(|m| m.len()).unwrap_or(0),
            )
        })
        .collect();
    validate_dll_set(&deployed)?;
    let _ = std::fs::remove_dir_all(&work);
    Ok(())
}

/// zip 定向提取：仅解出 7 个 DLL 与 LICENSE（按净化后的文件名展平到 `out`）。
fn extract_zip_matched(zip_path: &Path, out: &Path) -> Result<(), String> {
    let f = std::fs::File::open(zip_path).map_err(|e| e.to_string())?;
    let mut ar = zip::ZipArchive::new(f).map_err(|e| e.to_string())?;
    for i in 0..ar.len() {
        let mut entry = ar.by_index(i).map_err(|e| e.to_string())?;
        if entry.is_dir() {
            continue;
        }
        let raw_name = entry.name().to_string();
        let flat = match sanitized_flat_name(&raw_name) {
            Some(n) => n,
            None => continue,
        };
        let wanted = REQUIRED_DLLS
            .iter()
            .any(|d| flat.eq_ignore_ascii_case(d))
            || flat.eq_ignore_ascii_case("LICENSE")
            || flat.eq_ignore_ascii_case("LICENSE.txt");
        if !wanted {
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut buf)
            .map_err(|e| format!("{flat}: {e}"))?;
        let dst_name = if flat.eq_ignore_ascii_case("LICENSE.txt") {
            "LICENSE".to_string()
        } else {
            flat
        };
        std::fs::write(out.join(&dst_name), &buf).map_err(|e| format!("{dst_name}: {e}"))?;
    }
    Ok(())
}

/// 7z 全量解压后，把 7 个 DLL + LICENSE（任意嵌套深度）复制展平到 `work` 根。
fn flatten_matched(work: &Path) -> Result<(), String> {
    fn walk(dir: &Path, work: &Path) -> Result<(), String> {
        for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if p.is_dir() {
                if p != work {
                    walk(&p, work)?;
                }
            } else {
                let fname = entry.file_name().to_string_lossy().to_string();
                let matched = REQUIRED_DLLS
                    .iter()
                    .any(|d| fname.eq_ignore_ascii_case(d))
                    || fname.eq_ignore_ascii_case("LICENSE");
                if matched && p.parent() != Some(work) {
                    let dst = work.join(&fname);
                    if !dst.exists() {
                        std::fs::copy(&p, &dst).map_err(|e| format!("{fname}: {e}"))?;
                    }
                }
            }
        }
        Ok(())
    }
    walk(work, work)
}

// ════════════════════════════════════════════════════════════════
// 单测（纯函数 + 本地 zip fixture；不真跑网络）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sources_dual_and_urls() {
        let srcs = sources();
        assert_eq!(srcs.len(), 2, "双源");
        assert_eq!(srcs[0].name, "BtbN");
        assert!(srcs[0].archive_url.contains("BtbN/FFmpeg-Builds"));
        assert!(srcs[0].archive_url.ends_with(".zip"));
        assert!(srcs[0].archive_url.contains("win64-gpl-shared"));
        assert!(srcs[0].archive_url.contains("8.1"), "n8.1 分支（avcodec-62）");
        assert_eq!(srcs[0].checksum, ChecksumSource::BtbNManifest);
        assert_eq!(srcs[1].name, "gyan.dev");
        assert!(srcs[1].archive_url.ends_with(".7z"));
        assert_eq!(srcs[1].checksum, ChecksumSource::Sidecar);
    }

    #[test]
    fn test_url_derivation() {
        assert_eq!(
            archive_name("https://x/y/ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip"),
            "ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip"
        );
        assert_eq!(archive_name("nosep.zip"), "nosep.zip");
        assert_eq!(archive_name("https://x/y/"), "https://x/y/");
        assert_eq!(
            sidecar_url("https://www.gyan.dev/ffmpeg/builds/a.7z"),
            "https://www.gyan.dev/ffmpeg/builds/a.7z.sha256"
        );
    }

    /// 不敏感）、未命中 None、空/坏行跳过。
    #[test]
    fn test_parse_checksum_manifest() {
        let m = "abc123  ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip\n\
                 dEF456  ffmpeg-n8.1-latest-win64-lgpl-shared-8.1.zip\n\
                 \n\
                 badline\n";
        assert_eq!(
            parse_checksum_manifest(m, "ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip"),
            Some("abc123".into())
        );
        assert_eq!(
            parse_checksum_manifest(m, "FFMPEG-N8.1-LATEST-WIN64-LGPL-SHARED-8.1.ZIP"),
            Some("def456".into()),
            "文件名大小写不敏感 + hex 小写化"
        );
        assert_eq!(parse_checksum_manifest(m, "not-there.zip"), None);
        assert_eq!(parse_checksum_manifest("", "x.zip"), None);
    }

    #[test]
    fn test_sidecar_parse_and_verify_reject() {
        assert_eq!(parse_sidecar_checksum("aabbcc  a.7z\n"), Some("aabbcc".into()));
        assert_eq!(parse_sidecar_checksum("  \n"), None);
        let data = b"kirin fixture";
        let good = sha256_hex_bytes(data);
        assert!(hex_ci_eq(&good, &good.to_uppercase()));
        // 校验失败必须拒绝：不匹配 / 空 / 非 hex。
        assert!(!hex_ci_eq(&good, "0000"));
        assert!(!hex_ci_eq("", &good));
        // 内容变化一个字节 → 摘要必变（拒绝）。
        let mut tampered = data.to_vec();
        tampered[0] ^= 1;
        assert_ne!(sha256_hex_bytes(&tampered), good);
    }

    #[test]
    fn test_deploy_bin_dir() {
        let d = deploy_bin_dir(Path::new("C:/app/bin/KirinDesk.exe"));
        assert_eq!(d, PathBuf::from("C:/app/bin/../ffmpeg/bin"));
        let d2 = deploy_bin_dir(Path::new("KirinDesk.exe"));
        assert!(d2.ends_with("ffmpeg/bin"), "无目录 exe 也指向 ../ffmpeg/bin: {d2:?}");
    }

    /// 零体积 / 目录不存在 → None（启动自检「已部署需重启」判据）。
    #[test]
    fn test_r88b3_deployed_dll_dir() {
        let dir = std::env::temp_dir().join(format!("kirin-r88b3-dlls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bin = dir.join("ffmpeg/bin");
        std::fs::create_dir_all(&bin).unwrap();
        // 假 exe（deploy_bin_dir 只取 parent：dir/app/KirinDesk.exe →
        // dir/app/../ffmpeg/bin = dir/ffmpeg/bin）。
        let exe = dir.join("app/KirinDesk.exe");
        // 目录存在但无 DLL → None。
        assert!(deployed_dll_dir(&exe).is_none(), "空部署目录 → None");
        // 写全 7 DLL（非零）→ Some。
        for dll in REQUIRED_DLLS {
            std::fs::write(bin.join(dll), b"fixture").unwrap();
        }
        let got = deployed_dll_dir(&exe);
        assert!(got.is_some(), "7 DLL 齐 → Some: {got:?}");
        assert!(got.unwrap().ends_with("ffmpeg/bin"));
        // 缺一 → None。
        std::fs::remove_file(bin.join("swscale-9.dll")).unwrap();
        assert!(deployed_dll_dir(&exe).is_none(), "缺一 DLL → None");
        // 补回但零体积 → None。
        std::fs::write(bin.join("swscale-9.dll"), b"").unwrap();
        assert!(deployed_dll_dir(&exe).is_none(), "零体积 → None");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sanitized_flat_name() {
        assert_eq!(
            sanitized_flat_name("ffmpeg-n8.1/bin/avcodec-62.dll").as_deref(),
            Some("avcodec-62.dll")
        );
        assert_eq!(sanitized_flat_name("avutil-60.dll").as_deref(), Some("avutil-60.dll"));
        assert_eq!(sanitized_flat_name("a\\b\\swscale-9.dll").as_deref(), Some("swscale-9.dll"));
        assert_eq!(sanitized_flat_name(""), None);
        assert_eq!(sanitized_flat_name("dir/"), None);
        assert_eq!(sanitized_flat_name("../evil.dll"), None);
        assert_eq!(sanitized_flat_name("C:/evil.dll"), None);
    }

    #[test]
    fn test_validate_dll_set() {
        let full: Vec<(String, u64)> = REQUIRED_DLLS
            .iter()
            .map(|d| (d.to_string(), 1024))
            .collect();
        assert!(validate_dll_set(&full).is_ok());
        // 缺 swscale-9（9.x 构建常见形态：swscale 名不同）→ 拒绝。
        let missing: Vec<(String, u64)> = full.iter().skip(1).cloned().collect();
        assert!(validate_dll_set(&missing).is_err());
        // 零体积（提取不完整）→ 拒绝。
        let zero: Vec<(String, u64)> = full
            .iter()
            .map(|(n, _)| (n.clone(), 0))
            .collect();
        assert!(validate_dll_set(&zero).is_err());
        // 名单大小写不敏感（解压源大小写差异）。
        let upper: Vec<(String, u64)> = REQUIRED_DLLS
            .iter()
            .map(|d| (d.to_uppercase(), 4096))
            .collect();
        assert!(validate_dll_set(&upper).is_ok());
    }

    /// Downloading 内更新；Fail 任意态可达。
    #[test]
    fn test_phase_transitions() {
        use SetupEvent as E;
        use SetupPhase as P;
        let mut ph = next_phase(&P::Idle, &E::Start { source: "BtbN" });
        assert_eq!(ph, P::Downloading { source: "BtbN", percent: 0 });
        ph = next_phase(&ph, &E::Progress { percent: 42 });
        assert_eq!(ph, P::Downloading { source: "BtbN", percent: 42 });
        // Progress 在非 Downloading 态被忽略（防御）。
        ph = next_phase(&ph, &E::Downloaded);
        assert_eq!(ph, P::Verifying);
        assert_eq!(next_phase(&ph, &E::Progress { percent: 9 }), P::Verifying);
        ph = next_phase(&ph, &E::Verified);
        assert_eq!(ph, P::Extracting);
        ph = next_phase(&ph, &E::Extracted);
        assert_eq!(ph, P::Deploying);
        ph = next_phase(&ph, &E::Deployed);
        assert_eq!(ph, P::Done);
        assert!(!is_active(&P::Done));
        assert!(!is_active(&P::Failed { reason: String::new() }));
        assert!(!is_active(&P::Idle));
        assert!(is_active(&P::Verifying));
        let f = next_phase(&P::Verifying, &E::Fail("sha256 mismatch".into()));
        assert_eq!(f, P::Failed { reason: "sha256 mismatch".into() });
    }

    /// 展平；zip-slip 条目（`../evil.dll`）被净化跳过。
    #[test]
    fn test_extract_zip_matched_fixture() {
        let dir = std::env::temp_dir().join(format!("kirin-r56-zipfix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("fixture.zip");
        {
            use std::io::Write;
            let f = std::fs::File::create(&zip_path).unwrap();
            let mut w = zip::ZipWriter::new(f);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            for dll in REQUIRED_DLLS {
                w.start_file(format!("ffmpeg-n8.1/bin/{dll}"), opts).unwrap();
                w.write_all(dll.as_bytes()).unwrap();
            }
            w.start_file("ffmpeg-n8.1/LICENSE.txt", opts).unwrap();
            w.write_all(b"LGPL/GPL").unwrap();
            // 干扰项：非目标文件 + zip-slip 尝试。
            w.start_file("ffmpeg-n8.1/bin/ffprobe.exe", opts).unwrap();
            w.write_all(b"not needed").unwrap();
            w.start_file("../evil.dll", opts).unwrap();
            w.write_all(b"evil").unwrap();
            w.finish().unwrap();
        }
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        extract_zip_matched(&zip_path, &out).unwrap();
        // 7 DLL 展平齐 + 内容正确 + LICENSE 归一命名；干扰/恶意条目不落地。
        for dll in REQUIRED_DLLS {
            let p = out.join(dll);
            assert!(p.is_file(), "{dll} 应被提取");
            assert_eq!(std::fs::read(&p).unwrap(), dll.as_bytes());
        }
        assert!(out.join("LICENSE").is_file(), "LICENSE.txt 归一为 LICENSE");
        assert!(!out.join("ffprobe.exe").exists());
        assert!(!dir.join("evil.dll").exists(), "zip-slip 条目不得逃逸出 out");
        // 名单校验通过。
        let found: Vec<(String, u64)> = std::fs::read_dir(&out)
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| (e.file_name().to_string_lossy().to_string(), e.metadata().unwrap().len()))
            .collect();
        assert!(validate_dll_set(&found).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sha256_known_vector() {
        assert_eq!(
            sha256_hex_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
