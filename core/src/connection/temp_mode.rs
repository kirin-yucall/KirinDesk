//! M8-T017: 临时连接 — 临时挑战码 + 短时间窗口（凭据化 temp-mode）。
//!
//! 升级旧版「纯时间窗口旁路」（ui 侧 `/tmp/kirindesk-temp` 时间戳文件）：
//!
//! 1. **默认跳过白名单**：窗口激活即生效（保持既有行为，无额外配置）；
//! 2. **临时挑战码凭据**（SRV-TMP-002）：`enable` 时生成 10 位随机码（CSPRNG，
//!    大写字母+数字，排除易混淆 `0/O/1/I`，共 32 字符；S-20 / F-25 8→10 位，
//!    32^10 ≈ 1.15e15 离线爆破不可行），窗口期内客户端握手
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

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 临时挑战码字符集（SRV-TMP-002）：大写字母（去 O/I）+ 数字（去 0/1）。
/// 32 个字符 → 32^10 ≈ 1.15e15 种组合（S-20 / F-25：8 位 1.1e12 分钟级
/// 离线爆破，升至 10 位）。
const CODE_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
/// 临时挑战码长度（SRV-TMP-002；S-20 / F-25：8 → 10）。
const CODE_LEN: usize = 10;

/// 状态文件名（位于 `cache_dir()/kirin_desk/` 下）。
const STATE_FILE_NAME: &str = "temp_mode.json";

/// S-20 (F-25)：时钟回拨防护参数 —— 墙钟相对进程内**最高观察值**回拨超过
/// 该容差（秒）即判定时钟被回拨，窗口 fail-closed 失效（防"回拨延长窗口"）。
/// NTP 小幅度回拨（≤ 5s）不误伤；反复小步回拨会逐次逼近并最终触发。
const CLOCK_BACKWARD_TOLERANCE_SECS: u64 = 5;
/// S-20 (F-25)：单调时钟与墙钟漂移上限（秒）。墙钟明显慢于单调时钟
/// （挂起恢复 / VM 时钟漂移 / 慢速回拨）超过该值 → 判定时钟异常失效。
/// 睡眠/挂起期间单调时钟多数平台不前进（墙钟照常）→ 不会误伤。
const CLOCK_DRIFT_CAP_SECS: u64 = 60;

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

/// 墙钟当前时刻（unix 秒）；测试可**按状态文件路径**注入（见 `TEST_NOW`）。
fn now_secs_for(state_file: &Path) -> u64 {
    #[cfg(test)]
    {
        // 测试注入：`set_test_now(path, v)` 模拟该路径窗口的墙钟时刻
        // （v = 0 = 未注入，走真实时钟）。按路径隔离 → 并行测试互不干扰。
        if let Some(v) = test_now_map().lock().unwrap().get(state_file) {
            if *v != 0 {
                return *v;
            }
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── S-20 (F-25): 时钟回拨防护（**按窗口**：状态文件路径为锚键）──
//
// 状态文件只存墙钟过期时间 —— 系统时钟被回拨可直接延长窗口。防护为每个
// 已观察窗口建立「进程内单调时钟锚 + 最高墙钟观察值」，双检测命中任一即
// **poison（fail-closed）**：该窗口此后判定不激活，直到下一次 `enable()`
// 重置锚（新窗口重新计，NTP 校正后的恢复路径）：
//
// 1. **回拨检测**：墙钟低于该窗口**最高观察值**超过容差
//    （`CLOCK_BACKWARD_TOLERANCE_SECS`）→ 时钟被回拨；
// 2. **单调漂移上限**：墙钟相对锚的推进明显慢于单调时钟（超过
//    `CLOCK_DRIFT_CAP_SECS`，慢速回拨/时钟停走/挂起恢复异常）→ 判定异常；
// 3. 睡眠/挂起不误伤：睡眠期间墙钟照常前进、单调时钟多数平台冻结
//    （墙钟领先单调 → 不触发检测）；NTP 小幅度回拨（≤ 5s）容忍；
// 4. 按窗口隔离：不同状态文件路径互不影响（测试与生产窗口天然隔离）；
//    锚在窗口**首次被观察**时建立 —— 先拨钟再启动进程/再启用窗口的场景
//    无法检测（登记）：窗口激活仍需明文码（文件仅存加盐哈希，32^10 ≈
//    1.15e15 离线爆破不可行），威胁面收窄为本地高权限攻击者。
#[derive(Clone, Copy)]
struct WindowClockAnchor {
    /// 锚定时刻的单调时钟（窗口首次观察/`enable` 时建立）。
    mono: Instant,
    /// 锚定时刻的墙钟（unix 秒）。
    wall: u64,
    /// 该窗口墙钟最高观察值（回拨检测基准；只增不减）。
    max_wall: u64,
    /// 命中回拨/漂移检测 → true（fail-closed，直到重新 enable）。
    poisoned: bool,
}

static WINDOW_CLOCKS: OnceLock<Mutex<HashMap<PathBuf, WindowClockAnchor>>> = OnceLock::new();

fn window_clocks() -> &'static Mutex<HashMap<PathBuf, WindowClockAnchor>> {
    WINDOW_CLOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 时钟健康检查（见模块注释；命中回拨/漂移 → 该窗口 poison 并返回 false）。
fn window_clock_healthy(state_file: &Path) -> bool {
    let now_wall = now_secs_for(state_file);
    let mut map = window_clocks().lock().unwrap();
    let anchor = map.entry(state_file.to_path_buf()).or_insert_with(|| WindowClockAnchor {
        mono: Instant::now(),
        wall: now_wall,
        max_wall: now_wall,
        poisoned: false,
    });
    if anchor.poisoned {
        return false;
    }
    // 1) 回拨检测：低于该窗口历史最高观察值超过容差。
    if now_wall.saturating_add(CLOCK_BACKWARD_TOLERANCE_SECS) < anchor.max_wall {
        anchor.poisoned = true;
        return false;
    }
    // 2) 单调漂移上限：墙钟相对锚推进明显慢于单调时钟（慢速回拨/停走）。
    let wall_elapsed = now_wall.saturating_sub(anchor.wall);
    let mono_elapsed = anchor.mono.elapsed().as_secs();
    if mono_elapsed > wall_elapsed.saturating_add(CLOCK_DRIFT_CAP_SECS) {
        anchor.poisoned = true;
        return false;
    }
    if now_wall > anchor.max_wall {
        anchor.max_wall = now_wall;
    }
    true
}

/// 新窗口开启时移除该窗口的时钟锚（新窗口重新计；NTP 校正后的恢复路径）。
fn reset_window_clock(state_file: &Path) {
    window_clocks().lock().unwrap().remove(state_file);
}

#[cfg(test)]
static TEST_NOW: OnceLock<Mutex<HashMap<PathBuf, u64>>> = OnceLock::new();
#[cfg(test)]
fn test_now_map() -> &'static Mutex<HashMap<PathBuf, u64>> {
    TEST_NOW.get_or_init(|| Mutex::new(HashMap::new()))
}
/// 测试注入：为**指定路径的窗口**模拟墙钟时刻（0 = 未注入，走真实时钟）。
/// 按路径隔离 → 并行测试/其他模块（如 handshake 二态测试）互不干扰。
#[cfg(test)]
fn set_test_now(state_file: &Path, v: u64) {
    test_now_map().lock().unwrap().insert(state_file.to_path_buf(), v);
}
#[cfg(test)]
fn reset_test_now(state_file: &Path) {
    test_now_map().lock().unwrap().remove(state_file);
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

    /// 开启临时连接（SRV-TMP-001/002）：生成 10 位临时挑战码并写入状态文件，
    /// 返回**明文码**（仅本次调用展示一次，TMP-SEC-001；旧码随文件覆盖作废）。
    ///
    /// `ttl_secs` 不做范围收敛（自测需短 TTL）；生产路径由
    /// `NetworkConfig::effective_temp_mode_ttl()` 收敛到 60–3600。
    ///
    /// S-20 (F-25)：状态文件经 `fsutil::write_private` 落盘（Unix 0600 +
    /// O_NOFOLLOW + 原子替换，S-07 收口复用）；开启同时重置时钟锚——
    /// 新窗口重新计，NTP 校正后的恢复路径。
    pub fn enable(&self, ttl_secs: u64) -> Result<String, TempModeError> {
        let code = generate_code();
        reset_window_clock(&self.state_file);
        let expires_at = now_secs_for(&self.state_file).saturating_add(ttl_secs);
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
        kirin_desk_utils::fsutil::write_private(&self.state_file, json.as_bytes())
            .map_err(|e| TempModeError::IoError {
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

    /// 窗口是否激活（SRV-TMP-003）：状态文件存在、未过期，且时钟未被回拨
    /// （S-20 / F-25：回拨检测命中 → fail-closed 不激活）。
    pub fn is_active(&self) -> bool {
        match self.read_state_file() {
            Some(state) => {
                window_clock_healthy(&self.state_file) && now_secs_for(&self.state_file) < state.expires_at
            }
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
        if !window_clock_healthy(&self.state_file) {
            return 0; // S-20 (F-25)：时钟异常 → 窗口视为不激活
        }
        match self.read_state_file() {
            Some(state) => {
                let remaining = state.expires_at.saturating_sub(now_secs_for(&self.state_file));
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
        if !window_clock_healthy(&self.state_file) {
            return None; // S-20 (F-25)：时钟异常 → 不展示窗口
        }
        let state = self.read_state_file()?;
        if now_secs_for(&self.state_file) >= state.expires_at {
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

/// 生成 10 位临时挑战码（SRV-TMP-002，CSPRNG；S-20 / F-25：8 → 10 位）。
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

    /// 10 位码 + 字符集排除 0/O/1/I + 每次 enable 重新生成（旧码作废）。
    #[test]
    fn test_enable_generates_10char_charset_code() {
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

    /// S-20 (F-25)：状态文件经 `write_private` 落盘 —— Unix 下新建文件
    /// 0600 + 父目录 0700（可被同机低权限用户读取则离线爆破哈希）。
    #[cfg(unix)]
    #[test]
    fn test_state_file_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("perms");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join(STATE_FILE_NAME);
        let mgr = TempModeManager::with_state_file(path.clone());
        let _ = mgr.enable(300).expect("enable");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "state file must be 0600");
        cleanup("perms");
    }

    /// S-20 (F-25)：时钟回拨防护 —— 墙钟回拨超过容差 → 窗口 fail-closed
    /// 失效（is_active/verify/remaining 全部门禁）；容差内小回拨不误伤；
    /// 重新 enable 重置锚与 poison 恢复正常。
    #[test]
    fn test_clock_rollback_invalidates_window() {
        let mgr = test_manager("rollback");
        set_test_now(mgr.state_file_path(), 1_000_000);
        let code = mgr.enable(300).expect("enable");
        assert!(mgr.is_active());

        // 正常前进 100s（窗口内）→ 仍激活。
        set_test_now(mgr.state_file_path(), 1_000_100);
        assert!(mgr.is_active());
        assert!(mgr.verify_challenge(&code));

        // 回拨 100s（> 容差 5s）→ 窗口失效（fail-closed），码不再可用。
        set_test_now(mgr.state_file_path(), 1_000_000);
        assert!(!mgr.is_active(), "rollback must invalidate the window");
        assert!(
            !mgr.verify_challenge(&code),
            "code must fail after clock rollback"
        );
        assert_eq!(mgr.remaining_secs(), 0);
        assert!(mgr.state().is_none());

        // 重新 enable（新窗口）→ 锚重置，poison 清除，恢复正常。
        let code2 = mgr.enable(300).expect("re-enable");
        assert!(mgr.is_active(), "re-enable resets the clock anchor");
        assert!(mgr.verify_challenge(&code2));
        set_test_now(mgr.state_file_path(), 1_000_100);
        assert!(mgr.is_active());

        reset_test_now(mgr.state_file_path());
        cleanup("rollback");
    }

    /// S-20 (F-25)：容差内小幅度回拨（≤ 5s，NTP 校正场景）不误伤窗口。
    #[test]
    fn test_clock_small_backward_within_tolerance() {
        let mgr = test_manager("tolerance");
        set_test_now(mgr.state_file_path(), 2_000_000);
        let code = mgr.enable(300).expect("enable");
        set_test_now(mgr.state_file_path(), 2_000_100);
        assert!(mgr.is_active());
        // 回拨 3s（≤ 容差）→ 仍激活。
        set_test_now(mgr.state_file_path(), 2_000_097);
        assert!(mgr.is_active());
        assert!(mgr.verify_challenge(&code));
        // 回拨累计超过容差（再回拨 3s → 相对最高观察值 6s）→ 失效。
        set_test_now(mgr.state_file_path(), 2_000_094);
        assert!(!mgr.is_active(), "cumulative rollback beyond tolerance");
        reset_test_now(mgr.state_file_path());
        cleanup("tolerance");
    }

    /// S-20 (F-25)：单调时钟漂移上限 —— 墙钟停滞而单调时钟继续（慢速
    /// 回拨/时钟停走）超过 60s → 判定异常失效（按窗口 poison）。
    #[test]
    fn test_clock_monotonic_drift_cap() {
        let mgr = test_manager("drift");
        set_test_now(mgr.state_file_path(), 3_000_000);
        let code = mgr.enable(300).expect("enable");
        assert!(mgr.is_active());
        // 模拟：该窗口的单调锚比墙钟多走 200s（墙钟停滞）。
        if let Some(anchor) = window_clocks()
            .lock()
            .unwrap()
            .get_mut(mgr.state_file_path())
        {
            anchor.mono = Instant::now() - std::time::Duration::from_secs(200);
        }
        assert!(!mgr.is_active(), "drift beyond cap must invalidate");
        assert!(!mgr.verify_challenge(&code));
        reset_test_now(mgr.state_file_path());
        cleanup("drift");
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
    /// （真实时钟路径；注入时钟按路径隔离，互不干扰。）
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
