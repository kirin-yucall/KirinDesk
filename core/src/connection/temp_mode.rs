//! M8-T017: 临时连接 — 临时挑战码 + 短时间窗口（凭据化 temp-mode）。
//!
//! 升级旧版「纯时间窗口旁路」（ui 侧 `/tmp/kirindesk-temp` 时间戳文件）：
//!
//! 1. **默认跳过白名单**：窗口激活即生效（保持既有行为，无额外配置）；
//! 2. **临时挑战码凭据**（SRV-TMP-002）：`enable` 时生成 8 位随机码（CSPRNG，
//!    大写字母+数字，排除易混淆 `0/O/1/I`，共 32 字符），窗口期内客户端握手
//!    必须携带该码（复用 `HandshakeInit.challenge` 字段，协议零改动）；
//! 3. **短时间窗口**（SRV-TMP-004）：默认 5 分钟（`[network].temp_mode_ttl_secs`，
//!    范围 60–3600 由调用方经 `effective_temp_mode_ttl` 收敛），过期自动失效；
//! 4. **码不落盘明文**（TMP-SEC-001）：状态文件仅存 `sha256(码 ‖ 状态文件路径)`
//!    哈希（TMP-SEC-004，路径作盐防彩虹表）+ 过期时间戳——进程重启后窗口期内
//!    仍生效，但明文码只在 `enable` 返回时展示一次；
//! 5. 状态文件路径经 `dirs_next::cache_dir()` 解析（M1-T002 路径策略），
//!    同时修复旧 `/tmp` 硬编码在 Windows 原生运行下失效的缺陷。
//!
//! 安全边界（UA-ACCEPT-004）：无人值守是否禁用由调用方（CLI/GUI）在 `enable`
//! 前判定并拒绝，本管理器不感知配置。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 临时挑战码字符集（SRV-TMP-002）：大写字母（去 O/I）+ 数字（去 0/1）。
/// 32 个字符 → 32^8 ≈ 1.1e12 种组合。
const CODE_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
/// 临时挑战码长度（SRV-TMP-002）。
const CODE_LEN: usize = 8;

/// 状态文件名（位于 `cache_dir()/kirin_desk/` 下）。
const STATE_FILE_NAME: &str = "temp_mode.json";

/// 状态文件内容（SRV-TMP-003）：过期时间戳 + 加盐哈希，**不含明文码**。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TempModeFile {
    /// 窗口过期时间（unix 秒）。
    expires_at: u64,
    /// `sha256(码 ‖ 状态文件路径)` 的 hex 表示（TMP-SEC-004）。
    code_sha256: String,
}

/// 临时连接窗口状态（供状态/CLI 展示，不含明文码）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempModeState {
    /// 窗口过期时间（unix 秒）。
    pub expires_at: u64,
    /// 剩余秒数（已过期为 0）。
    pub remaining_secs: u32,
}

/// 临时连接管理器错误。
#[derive(Debug, thiserror::Error)]
pub enum TempModeError {
    #[error("I/O error at {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot resolve cache dir (no home dir)")]
    NoCacheDir,
    #[error("state file corrupt at {path}: {detail}")]
    CorruptState { path: PathBuf, detail: String },
    #[error("serialization error: {0}")]
    Serialize(String),
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// 临时连接管理器（M8-T017 / SRV-TMP-001）。
///
/// 实例无内部可变状态——所有读写都作用于状态文件，因此可安全地在
/// 握手校验（每连接）与展示（GUI 每帧倒计时）等场景各自新建实例。
#[derive(Debug, Clone)]
pub struct TempModeManager {
    state_file: PathBuf,
}

impl TempModeManager {
    /// 默认状态文件：`cache_dir()/kirin_desk/temp_mode.json`（M1-T002 路径策略）。
    /// `cache_dir()` 不可用时回退 `home_dir()/.kirin_desk/cache`。
    pub fn new() -> Result<Self, TempModeError> {
        let base = dirs_next::cache_dir().or_else(dirs_next::home_dir);
        match base {
            Some(dir) => Ok(Self::with_state_file(
                dir.join("kirin_desk").join(STATE_FILE_NAME),
            )),
            None => Err(TempModeError::NoCacheDir),
        }
    }

    /// 指定状态文件路径（测试/自测注入，避免污染真实状态）。
    pub fn with_state_file(state_file: PathBuf) -> Self {
        Self { state_file }
    }

    /// 状态文件路径（展示/审计用）。
    pub fn state_file_path(&self) -> &Path {
        &self.state_file
    }

    /// 开启临时连接（SRV-TMP-001/002）：生成 8 位临时挑战码并写入状态文件，
    /// 返回**明文码**（仅本次调用展示一次，TMP-SEC-001；旧码随文件覆盖作废）。
    ///
    /// `ttl_secs` 不做范围收敛（自测需短 TTL）；生产路径由
    /// `NetworkConfig::effective_temp_mode_ttl()` 收敛到 60–3600。
    pub fn enable(&self, ttl_secs: u64) -> Result<String, TempModeError> {
        let code = generate_code();
        let expires_at = now_secs().saturating_add(ttl_secs);
        // TMP-SEC-004：加盐哈希 `sha256(码 ‖ 状态文件路径)`，防彩虹表；
        // 状态文件只存哈希，不落明文（TMP-SEC-001）。
        let code_sha256 = salted_hash(&code, &self.state_file);
        let state = TempModeFile {
            expires_at,
            code_sha256: to_hex(&code_sha256),
        };
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| TempModeError::Serialize(e.to_string()))?;
        if let Some(parent) = self.state_file.parent() {
            fs::create_dir_all(parent).map_err(|e| TempModeError::IoError {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        fs::write(&self.state_file, json).map_err(|e| TempModeError::IoError {
            path: self.state_file.clone(),
            source: e,
        })?;
        Ok(code)
    }

    /// 手动关闭（SRV-TMP-005）：删除状态文件。返回 `true` 表示关闭前窗口仍激活
    /// （调用方据此审计"手动关闭"而非"过期清理"）。
    pub fn disable(&self) -> Result<bool, TempModeError> {
        let was_active = self.is_active();
        if self.state_file.exists() {
            fs::remove_file(&self.state_file).map_err(|e| TempModeError::IoError {
                path: self.state_file.clone(),
                source: e,
            })?;
        }
        Ok(was_active)
    }

    /// 窗口是否激活（SRV-TMP-003）：状态文件存在且未过期。
    pub fn is_active(&self) -> bool {
        match self.read_state_file() {
            Some(state) => now_secs() < state.expires_at,
            None => false,
        }
    }

    /// 校验临时挑战码（SRV-TMP-HK-001）：窗口激活且 `sha256(码 ‖ 路径)` 与
    /// 状态文件哈希一致。窗口期外一律失败（SRV-TMP-HK-003），不产生任何旁路。
    pub fn verify_challenge(&self, code: &str) -> bool {
        if !self.is_active() {
            return false;
        }
        let Some(state) = self.read_state_file() else {
            return false;
        };
        let Some(stored) = from_hex(&state.code_sha256) else {
            return false;
        };
        if stored.len() != 32 {
            return false;
        }
        let actual = salted_hash(code, &self.state_file);
        // 常量时间比较（XOR 折叠），避免时序侧信道。
        let mut diff = 0u8;
        for (a, b) in actual.iter().zip(stored.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// 剩余秒数（未激活/已过期为 0）。
    pub fn remaining_secs(&self) -> u32 {
        match self.read_state_file() {
            Some(state) => {
                let remaining = state.expires_at.saturating_sub(now_secs());
                if remaining == 0 {
                    0
                } else {
                    remaining.min(u32::MAX as u64) as u32
                }
            }
            None => 0,
        }
    }

    /// 窗口状态（未激活为 `None`；供 CLI status / GUI 倒计时展示）。
    pub fn state(&self) -> Option<TempModeState> {
        let state = self.read_state_file()?;
        if now_secs() >= state.expires_at {
            return None;
        }
        Some(TempModeState {
            expires_at: state.expires_at,
            remaining_secs: self.remaining_secs(),
        })
    }

    fn read_state_file(&self) -> Option<TempModeFile> {
        let content = fs::read_to_string(&self.state_file).ok()?;
        serde_json::from_str(&content).ok()
    }
}

/// 生成 8 位临时挑战码（SRV-TMP-002，CSPRNG）。
fn generate_code() -> String {
    let mut rng = rand::rngs::OsRng;
    (0..CODE_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CODE_CHARSET.len());
            CODE_CHARSET[idx] as char
        })
        .collect()
}

/// 加盐哈希（TMP-SEC-004）：`sha256(码 ‖ 状态文件路径)`。
fn salted_hash(code: &str, state_file: &Path) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.update(state_file.as_os_str().as_encoded_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每个测试独立目录（cargo 并行线程共用同一进程 id，必须按测试名隔离）。
    fn test_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("kirin_desk_test_temp_mode_{}", tag))
    }

    fn test_manager(tag: &str) -> TempModeManager {
        let dir = test_dir(tag);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        TempModeManager::with_state_file(dir.join(STATE_FILE_NAME))
    }

    fn cleanup(tag: &str) {
        let _ = fs::remove_dir_all(test_dir(tag));
    }

    /// 8 位码 + 字符集排除 0/O/1/I + 每次 enable 重新生成（旧码作废）。
    #[test]
    fn test_enable_generates_8char_charset_code() {
        let mgr = test_manager("charset");
        let code = mgr.enable(300).expect("enable");
        assert_eq!(code.chars().count(), CODE_LEN);
        for c in code.chars() {
            assert!(
                CODE_CHARSET.contains(&(c as u8)),
                "code char '{}' outside charset",
                c
            );
            assert!(
                !matches!(c, '0' | 'O' | '1' | 'I'),
                "code char '{}' must be excluded",
                c
            );
        }
        // 再次 enable → 新码（旧码作废）。
        let code2 = mgr.enable(300).expect("enable again");
        assert_ne!(code, code2, "re-enable must regenerate code");
        assert!(!mgr.verify_challenge(&code), "old code must be invalidated");
        assert!(mgr.verify_challenge(&code2));
        cleanup("charset");
    }

    /// enable → 正确码通过、错码/空码失败。
    #[test]
    fn test_verify_challenge() {
        let mgr = test_manager("verify");
        let code = mgr.enable(300).expect("enable");
        assert!(mgr.is_active());
        assert!(mgr.verify_challenge(&code));
        assert!(!mgr.verify_challenge("XXXXXXXX"));
        assert!(!mgr.verify_challenge(""));
        assert!(
            !mgr.verify_challenge(&code.to_lowercase()),
            "case-sensitive"
        );
        cleanup("verify");
    }

    /// TTL 边界：ttl=0 → 立即失效；ttl=1 → 约 1 秒后过期。
    #[test]
    fn test_expiry_boundary() {
        let mgr = test_manager("expiry");
        let code = mgr.enable(0).expect("enable ttl=0");
        assert!(!mgr.is_active(), "ttl=0 must expire immediately");
        assert!(!mgr.verify_challenge(&code));
        assert_eq!(mgr.remaining_secs(), 0);
        assert!(mgr.state().is_none());

        let code = mgr.enable(1).expect("enable ttl=1");
        assert!(mgr.is_active());
        assert!(mgr.verify_challenge(&code));
        assert_eq!(mgr.remaining_secs(), 1);
        std::thread::sleep(std::time::Duration::from_millis(1500));
        assert!(!mgr.is_active(), "window must expire after ttl");
        assert!(
            !mgr.verify_challenge(&code),
            "SRV-TMP-HK-003: expired code fails"
        );
        cleanup("expiry");
    }

    /// 跨进程/实例恢复：状态文件存续 → 新实例窗口仍生效、哈希校验仍通过。
    #[test]
    fn test_persistence_across_instances() {
        let dir = test_dir("persist");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join(STATE_FILE_NAME);
        let code = {
            let mgr = TempModeManager::with_state_file(path.clone());
            mgr.enable(300).expect("enable")
        };
        // 模拟进程重启：全新实例（不持有明文码）。
        let mgr = TempModeManager::with_state_file(path.clone());
        assert!(mgr.is_active(), "window survives restart (expires_at)");
        assert!(mgr.verify_challenge(&code));
        // 状态文件不含明文码（TMP-SEC-001）。
        let content = fs::read_to_string(&path).expect("state file");
        assert!(
            !content.contains(&code),
            "state file must not contain plaintext code: {}",
            content
        );
        cleanup("persist");
    }

    /// disable：删除状态文件；激活时返回 true（手动关闭），未激活返回 false。
    #[test]
    fn test_disable() {
        let mgr = test_manager("disable");
        let _ = mgr.enable(300).expect("enable");
        assert!(mgr.disable().expect("disable active"), "was active");
        assert!(!mgr.is_active());
        assert!(!mgr.state_file_path().exists());
        assert!(!mgr.disable().expect("disable inactive"), "was not active");
        cleanup("disable");
    }

    /// 加盐哈希：相同码在不同路径下哈希不同（TMP-SEC-004）。
    #[test]
    fn test_hash_salted_by_path() {
        let dir = test_dir("salt");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        let a = TempModeManager::with_state_file(dir.join("a.json"));
        let b = TempModeManager::with_state_file(dir.join("b.json"));
        let code = "ABCD2345";
        let ha = salted_hash(code, a.state_file_path());
        let hb = salted_hash(code, b.state_file_path());
        assert_ne!(ha, hb, "salt (path) must change the hash");
        cleanup("salt");
    }
}
