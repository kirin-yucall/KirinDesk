//! M15-T004 / SEC-PATCH: 已知主机指纹存储（客户端 + 服务端双视角）。
//!
//! 本文件包含两个方向的「已知主机」存储（路径均经 `dirs` crate 跨平台解析，
//! 复用 `Config::config_dir()`，同 M1-T002 策略）：
//!
//! - **[`KnownClientsStore`]（服务端视角，SRV-SEC-KH-001/002）**：服务端维护
//!   `device_id → Ed25519 公钥指纹` 列表（`kirin_desk/known_clients.json`）。握手
//!   验签前，将客户端网络上来的自报公钥与本地记录比对 —— 命中且一致 → 通过；
//!   命中但不一致 → 拒绝（防 MITM）；未命中 → 走白名单/审批或 DNS TXT 比对。
//! - **[`KnownHostsStore`]（客户端视角，CLI-KH-001..004）**：客户端维护
//!   `设备 ID → 公钥指纹` 列表（`kirin_desk/known_hosts`）。首次连接用户确认
//!   远端指纹后记录；后续连接命中且一致 → 放行（并作为握手「可信公钥」最高
//!   优先级来源，优先于 DNS TXT）；命中但不一致 → **拒绝连接**；未命中 → 首次
//!   确认流程。
//!
//! 指纹为公钥 base64 的 SHA-256（小写十六进制、按 4 字符冒号分组展示），
//! 两侧算法一致（[`fingerprint`]）。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::config::Config;

/// 一条已知客户端记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownClient {
    /// 客户端 device_id（握手 `HandshakeInit.client_id`）。
    pub device_id: String,
    /// 客户端 Ed25519 公钥（base64，握手 `client_ed25519_pub_base64`）。
    pub public_key_base64: String,
    /// 公钥指纹（SHA-256 十六进制，冒号分组展示）。
    pub fingerprint: String,
    /// 首次记录时间（UTC）。
    pub first_seen: DateTime<Utc>,
    /// 最近一次成功连接时间（UTC）。
    pub last_seen: DateTime<Utc>,
}

/// 公钥比对结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMatch {
    /// 命中且公钥一致 → 通过。
    Match,
    /// 命中但公钥不一致 → 拒绝（SRV-SEC-KH-002）。
    Mismatch,
    /// 未命中 → 走白名单/审批或 DNS TXT 比对。
    Unknown,
}

/// 已知客户端存储（内存 Vec + JSON 文件）。
#[derive(Debug, Clone)]
pub struct KnownClientsStore {
    path: PathBuf,
    clients: Vec<KnownClient>,
}

/// 已知客户端存储错误。
#[derive(Debug, thiserror::Error)]
pub enum KnownClientsError {
    #[error("I/O error at {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to parse known_clients file at {path}: {detail}")]
    ParseError {
        path: PathBuf,
        detail: String,
    },
    #[error("Serialization error: {0}")]
    SerializeError(String),
    #[error("No config directory found")]
    NoConfigDir,
}

/// 计算公钥指纹：base64 公钥 → SHA-256 → 小写十六进制，每 4 字符冒号分组
/// （如 `a1b2:c3d4:...`，展示长度固定 64 位十六进制 = 20 组）。
pub fn fingerprint(public_key_base64: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_base64.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join(":")
}

/// S-15b (F-20): 加载失败（解析错误 / IO 错误）时把损坏文件保留为
/// `<path>.corrupt` 备份，便于恢复诊断。
///
/// - 不覆盖已有备份：`.corrupt` 已存在则依次尝试 `.corrupt.1` / `.corrupt.2` …
/// - 仅尽力而为：备份失败（权限不足 / 磁盘错误等）静默跳过，
///   不改变调用方的加载错误语义，也不影响加载路径返回。
fn backup_corrupt(path: &Path) {
    let Some(dir) = path.parent() else {
        return;
    };
    let base = match path.file_name() {
        Some(name) if !name.is_empty() => name.to_string_lossy().into_owned(),
        _ => return,
    };
    if dir.as_os_str().is_empty() {
        return;
    }
    for i in 0..=999 {
        let name = if i == 0 {
            format!("{base}.corrupt")
        } else {
            format!("{base}.corrupt.{i}")
        };
        let dest = dir.join(&name);
        if dest.exists() {
            continue;
        }
        let _ = std::fs::copy(path, &dest);
        return;
    }
}

impl KnownClientsStore {
    /// 默认存储路径: `{config_dir}/kirin_desk/known_clients.json`（同 M1-T002 策略）。
    pub fn default_path() -> Result<PathBuf, KnownClientsError> {
        let base = Config::config_dir().map_err(|_| KnownClientsError::NoConfigDir)?;
        Ok(base.join("known_clients.json"))
    }

    /// 从默认路径加载（文件不存在 → 空列表）。
    pub fn load() -> Result<Self, KnownClientsError> {
        let path = Self::default_path()?;
        Self::load_from(&path)
    }

    /// 空存储（默认路径不可用时用于内存态回退；`save` 会失败但调用方可忽略）。
    pub fn empty() -> Self {
        Self {
            path: PathBuf::new(),
            clients: Vec::new(),
        }
    }

    /// 从指定路径加载（文件不存在 → 空列表）。
    ///
    /// S-15b (F-20): 加载失败（解析错误 / IO 错误）时把损坏文件保留为
    /// `<path>.corrupt` 备份（不覆盖已有备份，详见 [`backup_corrupt`]）。
    pub fn load_from(path: &Path) -> Result<Self, KnownClientsError> {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let clients: Vec<KnownClient> = match serde_json::from_str(&content) {
                    Ok(clients) => clients,
                    Err(e) => {
                        backup_corrupt(path);
                        return Err(KnownClientsError::ParseError {
                            path: path.to_path_buf(),
                            detail: e.to_string(),
                        });
                    }
                };
                Ok(Self {
                    path: path.to_path_buf(),
                    clients,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: path.to_path_buf(),
                clients: Vec::new(),
            }),
            Err(e) => {
                backup_corrupt(path);
                Err(KnownClientsError::IoError {
                    path: path.to_path_buf(),
                    source: e,
                })
            }
        }
    }

    /// 保存到默认路径。
    pub fn save(&self) -> Result<(), KnownClientsError> {
        self.save_to(&self.path)
    }

    /// 保存到指定路径（自动创建父目录）。
    ///
    /// S-07 (F-8) / S-15 (F-20): 经 `fsutil::write_private` 落盘——同目录
    /// 随机名临时文件 + Unix `fsync` + `rename` 原子替换（0600/0700/O_NOFOLLOW），
    /// 崩溃/断电不产生半截文件、不丢失已确认指纹。
    pub fn save_to(&self, path: &Path) -> Result<(), KnownClientsError> {
        let content = serde_json::to_string_pretty(&self.clients)
            .map_err(|e| KnownClientsError::SerializeError(e.to_string()))?;
        crate::fsutil::write_private(path, content.as_bytes()).map_err(|e| {
            KnownClientsError::IoError {
                path: path.to_path_buf(),
                source: e,
            }
        })?;
        Ok(())
    }

    /// 全部已知客户端（按 `first_seen` 升序）。
    pub fn clients(&self) -> &[KnownClient] {
        &self.clients
    }

    /// 按 device_id 查询记录。
    pub fn lookup(&self, device_id: &str) -> Option<&KnownClient> {
        self.clients.iter().find(|c| c.device_id == device_id)
    }

    /// 比对客户端公钥（SRV-SEC-KH-002）：
    /// 命中且一致 → `Match`；命中但不一致 → `Mismatch`；未命中 → `Unknown`。
    pub fn check(&self, device_id: &str, claimed_key_base64: &str) -> KeyMatch {
        match self.lookup(device_id) {
            Some(known) => {
                if known.public_key_base64 == claimed_key_base64 {
                    KeyMatch::Match
                } else {
                    KeyMatch::Mismatch
                }
            }
            None => KeyMatch::Unknown,
        }
    }

    /// 新增或更新记录（按 device_id 去重）。`upsert` 覆盖原公钥，仅应在
    /// 用户显式确认（如审批接受 / known-hosts add 命令）时调用 —— 公钥变化
    /// 默认应走 `check` 拒绝路径，不得自动覆盖。
    pub fn upsert(&mut self, device_id: &str, public_key_base64: &str) {
        let fp = fingerprint(public_key_base64);
        let now = Utc::now();
        match self
            .clients
            .iter_mut()
            .find(|c| c.device_id == device_id)
        {
            Some(existing) => {
                existing.public_key_base64 = public_key_base64.to_string();
                existing.fingerprint = fp;
                existing.last_seen = now;
            }
            None => self.clients.push(KnownClient {
                device_id: device_id.to_string(),
                public_key_base64: public_key_base64.to_string(),
                fingerprint: fp,
                first_seen: now,
                last_seen: now,
            }),
        }
    }

    /// 刷新 `last_seen`（连接成功时调用，不改公钥）。
    pub fn touch(&mut self, device_id: &str) {
        if let Some(c) = self.clients.iter_mut().find(|c| c.device_id == device_id) {
            c.last_seen = Utc::now();
        }
    }

    /// 删除记录，返回是否删除成功。
    pub fn remove(&mut self, device_id: &str) -> bool {
        let before = self.clients.len();
        self.clients.retain(|c| c.device_id != device_id);
        self.clients.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 每测试独立目录（并行测试互不干扰——共享目录 + 尾部 remove_dir_all 会竞态）。
    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("kirin_desk_test_known_clients_{}", name))
    }

    #[test]
    fn test_fingerprint_format() {
        let fp = fingerprint("ed25519testkey");
        // 64 位十六进制 → 冒号分组 → 79 字符；全小写十六进制字符集
        assert_eq!(fp.len(), 79);
        assert_eq!(fp.split(':').count(), 16);
        assert!(fp.chars().all(|c| c == ':' || c.is_ascii_hexdigit()));
        // 相同输入 → 相同指纹
        assert_eq!(fingerprint("ed25519testkey"), fp);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = test_dir("roundtrip");
        let path = dir.join("known_clients.json");
        let mut store = KnownClientsStore::load_from(&path).unwrap();
        store.upsert("pc-a", "ed25519:key-a");
        store.save_to(&path).unwrap();

        let loaded = KnownClientsStore::load_from(&path).unwrap();
        assert_eq!(loaded.clients().len(), 1);
        let c = &loaded.clients()[0];
        assert_eq!(c.device_id, "pc-a");
        assert_eq!(c.public_key_base64, "ed25519:key-a");
        assert_eq!(c.fingerprint, fingerprint("ed25519:key-a"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_missing_file_returns_empty() {
        let path = std::env::temp_dir().join("kirin_desk_no_such_known_clients.json");
        let store = KnownClientsStore::load_from(&path).unwrap();
        assert!(store.clients().is_empty());
    }

    #[test]
    fn test_check_match_mismatch_unknown() {
        let dir = test_dir("check");
        let mut store = KnownClientsStore::load_from(&dir.join("known_clients.json")).unwrap();
        store.upsert("pc-a", "ed25519:key-a");
        assert_eq!(store.check("pc-a", "ed25519:key-a"), KeyMatch::Match);
        assert_eq!(store.check("pc-a", "ed25519:evil"), KeyMatch::Mismatch);
        assert_eq!(store.check("pc-b", "ed25519:key-a"), KeyMatch::Unknown);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_upsert_overwrites_and_dedup() {
        let dir = test_dir("upsert");
        let mut store = KnownClientsStore::load_from(&dir.join("known_clients.json")).unwrap();
        store.upsert("pc-a", "key-1");
        store.upsert("pc-a", "key-2");
        store.upsert("pc-b", "key-1");
        assert_eq!(store.clients().len(), 2);
        assert_eq!(store.lookup("pc-a").unwrap().public_key_base64, "key-2");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_remove_client() {
        let dir = test_dir("remove");
        let mut store = KnownClientsStore::load_from(&dir.join("known_clients.json")).unwrap();
        store.upsert("pc-a", "key-1");
        assert!(store.remove("pc-a"));
        assert!(store.clients().is_empty());
        assert!(!store.remove("pc-a"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_parse_failure_backs_up_corrupt() {
        let dir = test_dir("corrupt");
        let path = dir.join("known_clients.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, b"{ not valid json !!!").unwrap();

        // S-15b: 解析失败 → 返回 ParseError，同时损坏文件保留为 .corrupt 备份
        let err = KnownClientsStore::load_from(&path).unwrap_err();
        assert!(matches!(err, KnownClientsError::ParseError { .. }));

        let backup = dir.join("known_clients.json.corrupt");
        assert!(backup.exists(), ".corrupt backup must exist");
        assert_eq!(fs::read(&backup).unwrap(), b"{ not valid json !!!");
        assert!(path.exists(), "original file must be kept");

        // 再次失败 → 追加序号 .corrupt.1（不覆盖已有备份）
        let err2 = KnownClientsStore::load_from(&path).unwrap_err();
        assert!(matches!(err2, KnownClientsError::ParseError { .. }));
        assert!(
            dir.join("known_clients.json.corrupt.1").exists(),
            "second backup must use numbered suffix"
        );
        assert_eq!(fs::read(&backup).unwrap(), b"{ not valid json !!!");
        let _ = fs::remove_dir_all(&dir);
    }
}

// ── 客户端视角：已知主机指纹验证（CLI-KH-001..004 / M15-T004） ──────────────

/// 客户端「已知主机」记录：设备 ID → 公钥指纹。
///
/// 指纹算法与 [`fingerprint`] 一致（base64 公钥文本的 SHA-256，冒号分组），
/// 因此服务端 `known_clients` 与客户端 `known_hosts` 对同一公钥串产生相同指纹，
/// 两侧可交叉核对。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHost {
    /// 设备标识（与 `SavedDevice.id` 同源：`{device-id}` / `{id}.{domain}`）。
    pub id: String,
    /// 公钥指纹（SHA-256，冒号分组小写十六进制）。
    pub fingerprint: String,
    /// 首次确认时间（UTC）。
    pub confirmed_at: DateTime<Utc>,
}

/// 客户端指纹校验结果（CLI-KH-003）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintStatus {
    /// known_hosts 命中且指纹一致 → 放行。
    Match,
    /// known_hosts 命中但指纹不一致 → **拒绝连接**（防 MITM，不是仅警告）。
    Mismatch,
    /// 未命中 → 走首次确认流程（CLI-KH-001）。
    Unknown,
}

/// 客户端已知主机存储错误。
#[derive(Debug, thiserror::Error)]
pub enum KnownHostsError {
    #[error("I/O error at {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to parse known_hosts file at {path}: {detail}")]
    ParseError {
        path: PathBuf,
        detail: String,
    },
    #[error("Serialization error: {0}")]
    SerializeError(String),
    #[error("No config directory found")]
    NoConfigDir,
}

/// 客户端已知主机指纹存储（内存 Vec + JSON 文件，`kirin_desk/known_hosts`）。
#[derive(Debug, Clone)]
pub struct KnownHostsStore {
    path: PathBuf,
    hosts: Vec<KnownHost>,
}

impl KnownHostsStore {
    /// 默认存储路径: `{config_dir}/kirin_desk/known_hosts`（CLI-KH-002，同 M1-T002 策略）。
    pub fn default_path() -> Result<PathBuf, KnownHostsError> {
        let base = Config::config_dir().map_err(|_| KnownHostsError::NoConfigDir)?;
        Ok(base.join("known_hosts"))
    }

    /// 从默认路径加载（文件不存在 → 空列表）。
    pub fn load() -> Result<Self, KnownHostsError> {
        let path = Self::default_path()?;
        Self::load_from(&path)
    }

    /// 从指定路径加载（文件不存在 → 空列表）。
    ///
    /// S-15b (F-20): 加载失败（解析错误 / IO 错误）时把损坏文件保留为
    /// `<path>.corrupt` 备份（不覆盖已有备份，详见 [`backup_corrupt`]）。
    pub fn load_from(path: &Path) -> Result<Self, KnownHostsError> {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let hosts: Vec<KnownHost> = match serde_json::from_str(&content) {
                    Ok(hosts) => hosts,
                    Err(e) => {
                        backup_corrupt(path);
                        return Err(KnownHostsError::ParseError {
                            path: path.to_path_buf(),
                            detail: e.to_string(),
                        });
                    }
                };
                Ok(Self {
                    path: path.to_path_buf(),
                    hosts,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: path.to_path_buf(),
                hosts: Vec::new(),
            }),
            Err(e) => {
                backup_corrupt(path);
                Err(KnownHostsError::IoError {
                    path: path.to_path_buf(),
                    source: e,
                })
            }
        }
    }

    /// 保存到默认路径。
    pub fn save(&self) -> Result<(), KnownHostsError> {
        self.save_to(&self.path)
    }

    /// 保存到指定路径（自动创建父目录）。
    ///
    /// S-07 (F-8) / S-15 (F-20): 经 `fsutil::write_private` 落盘——同目录
    /// 随机名临时文件 + Unix `fsync` + `rename` 原子替换（0600/0700/O_NOFOLLOW），
    /// 崩溃/断电不产生半截文件、不丢失已确认指纹。
    pub fn save_to(&self, path: &Path) -> Result<(), KnownHostsError> {
        let content = serde_json::to_string_pretty(&self.hosts)
            .map_err(|e| KnownHostsError::SerializeError(e.to_string()))?;
        crate::fsutil::write_private(path, content.as_bytes()).map_err(|e| {
            KnownHostsError::IoError {
                path: path.to_path_buf(),
                source: e,
            }
        })?;
        Ok(())
    }

    /// 已保存的已知主机记录。
    pub fn hosts(&self) -> &[KnownHost] {
        &self.hosts
    }

    /// 按设备 ID 查指纹（未命中返回 None）。
    pub fn fingerprint_of_id(&self, id: &str) -> Option<&str> {
        self.hosts
            .iter()
            .find(|h| h.id == id)
            .map(|h| h.fingerprint.as_str())
    }

    /// 指纹校验三态判定（CLI-KH-003）：
    /// 命中且一致 → `Match`；命中但不一致 → `Mismatch`（拒绝连接）；未命中 → `Unknown`。
    pub fn check(&self, id: &str, public_key_base64: &str) -> FingerprintStatus {
        match self.fingerprint_of_id(id) {
            Some(stored) if stored == fingerprint(public_key_base64) => FingerprintStatus::Match,
            Some(_) => FingerprintStatus::Mismatch,
            None => FingerprintStatus::Unknown,
        }
    }

    /// 首次确认后记录（CLI-KH-002）：按 `id` 去重，更新指纹与确认时间并保存。
    /// 返回记录的指纹。
    pub fn confirm(&mut self, id: &str, public_key_base64: &str) -> Result<String, KnownHostsError> {
        let fp = fingerprint(public_key_base64);
        let entry = KnownHost {
            id: id.to_string(),
            fingerprint: fp.clone(),
            confirmed_at: Utc::now(),
        };
        match self.hosts.iter_mut().find(|h| h.id == id) {
            Some(existing) => *existing = entry,
            None => self.hosts.push(entry),
        }
        self.save()?;
        Ok(fp)
    }

    /// 删除已知主机记录，返回是否删除成功（并保存）。
    pub fn remove(&mut self, id: &str) -> Result<bool, KnownHostsError> {
        let before = self.hosts.len();
        self.hosts.retain(|h| h.id != id);
        if self.hosts.len() != before {
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    /// 每测试独立目录（并行测试互不干扰——共享目录 + 尾部 remove_dir_all 会竞态）。
    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("kirin_desk_test_known_hosts_{}", name))
    }

    /// 与 core `IdentityManager::public_key_base64()` 同格式的合法 32 字节 base64
    /// （全 0 公钥 = 43 个 'A' + '='）。
    const SAMPLE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const SAMPLE_KEY_2: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    #[test]
    fn test_check_three_states() {
        let dir = test_dir("check");
        let path = dir.join("known_hosts");
        let mut store = KnownHostsStore::load_from(&path).unwrap();
        store.confirm("pc-a", SAMPLE_KEY).unwrap();

        // 命中且一致 → Match
        assert_eq!(store.check("pc-a", SAMPLE_KEY), FingerprintStatus::Match);
        // 命中但不一致 → Mismatch（拒绝连接）
        assert_eq!(store.check("pc-a", SAMPLE_KEY_2), FingerprintStatus::Mismatch);
        // 未命中 → Unknown
        assert_eq!(store.check("pc-b", SAMPLE_KEY), FingerprintStatus::Unknown);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_confirm_upsert_and_persist() {
        let dir = test_dir("persist");
        let path = dir.join("known_hosts");
        let mut store = KnownHostsStore::load_from(&path).unwrap();
        let fp = store.confirm("pc-c", SAMPLE_KEY).unwrap();
        assert_eq!(fp, fingerprint(SAMPLE_KEY));
        assert_eq!(store.hosts().len(), 1);

        // 重新加载 → 持久化成功
        let reloaded = KnownHostsStore::load_from(&path).unwrap();
        assert_eq!(reloaded.fingerprint_of_id("pc-c").unwrap(), &fp);

        // 重复确认（公钥变化）→ upsert 更新指纹，不新增记录
        store.confirm("pc-c", SAMPLE_KEY_2).unwrap();
        assert_eq!(store.hosts().len(), 1);
        assert_eq!(store.check("pc-c", SAMPLE_KEY_2), FingerprintStatus::Match);
        assert_eq!(store.check("pc-c", SAMPLE_KEY), FingerprintStatus::Mismatch);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_remove_host_persists() {
        let dir = test_dir("remove");
        let path = dir.join("known_hosts");
        let mut store = KnownHostsStore::load_from(&path).unwrap();
        store.confirm("pc-d", SAMPLE_KEY).unwrap();
        assert!(store.remove("pc-d").unwrap());
        assert!(!store.remove("pc-d").unwrap());
        assert!(store.hosts().is_empty());
        // 删除已持久化
        let reloaded = KnownHostsStore::load_from(&path).unwrap();
        assert!(reloaded.hosts().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_missing_file_returns_empty() {
        let path = std::env::temp_dir().join("kirin_desk_no_such_known_hosts_file");
        let store = KnownHostsStore::load_from(&path).unwrap();
        assert!(store.hosts().is_empty());
    }

    #[test]
    fn test_default_path_under_config_dir() {
        let path = KnownHostsStore::default_path().unwrap();
        let file_name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(file_name, "known_hosts");
    }

    #[test]
    fn test_interrupted_write_leaves_original_intact() {
        let dir = test_dir("interrupt");
        let path = dir.join("known_hosts");
        let mut store = KnownHostsStore::load_from(&path).unwrap();
        store.confirm("pc-a", SAMPLE_KEY).unwrap();
        let original = fs::read(&path).unwrap();

        // S-15a: 模拟崩溃——写入中途句柄被 drop（rename 未执行），同目录只留下
        // 半截临时文件。目标文件必须完好、可加载，且不阻塞后续保存。
        let mut partial =
            std::fs::File::create(dir.join("known_hosts.tmp.0123456789abcdef")).unwrap();
        partial.write_all(b"{\"hosts\": [{\"id\": \"pc-").unwrap();
        drop(partial); // 模拟进程中断（write_private 的失败清理同效）

        let reloaded = KnownHostsStore::load_from(&path).unwrap();
        assert_eq!(
            reloaded.fingerprint_of_id("pc-a").unwrap(),
            &fingerprint(SAMPLE_KEY)
        );
        assert_eq!(fs::read(&path).unwrap(), original, "original must be intact");

        // 崩溃残留的半截临时文件不阻塞后续保存（write_private 随机名 +
        // create_new 独占，绝不触碰既有条目），保存后加载完整
        store.confirm("pc-b", SAMPLE_KEY_2).unwrap();
        let reloaded2 = KnownHostsStore::load_from(&path).unwrap();
        assert_eq!(reloaded2.hosts().len(), 2);
        assert_eq!(reloaded2.check("pc-b", SAMPLE_KEY_2), FingerprintStatus::Match);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_atomic_replace_reader_never_sees_partial() {
        let dir = test_dir("atomic");
        let path = dir.join("known_hosts");
        let mut store = KnownHostsStore::load_from(&path).unwrap();
        store.confirm("pc-a", SAMPLE_KEY).unwrap();

        // S-15a: 后台线程反复保存，主线程同时反复加载——任何时刻读到的都必须是
        // 完整可解析文件（截断直写会出现空/半截内容 → load 失败）。
        let wpath = path.clone();
        let writer = std::thread::spawn(move || {
            let mut s = KnownHostsStore::load_from(&wpath).unwrap();
            for i in 0..100u32 {
                s.confirm(&format!("pc-{}", i % 8), SAMPLE_KEY_2).unwrap();
            }
        });

        let mut reads = 0u32;
        let mut torn = 0u32;
        while !writer.is_finished() && reads < 50_000 {
            reads += 1;
            if KnownHostsStore::load_from(&path).is_err() {
                torn += 1;
            }
        }
        writer.join().unwrap();

        assert_eq!(torn, 0, "reader observed torn/partial known_hosts content");
        assert!(reads > 0);
        // 写入全部完成后文件完整（pc-a + pc-0..pc-7 = 9 条）
        let final_store = KnownHostsStore::load_from(&path).unwrap();
        assert_eq!(final_store.hosts().len(), 9);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_parse_failure_backs_up_corrupt() {
        let dir = test_dir("corrupt");
        let path = dir.join("known_hosts");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, b"{ not valid json !!!").unwrap();

        // S-15b: 解析失败 → 返回 ParseError，同时损坏文件保留为 .corrupt 备份
        let err = KnownHostsStore::load_from(&path).unwrap_err();
        assert!(matches!(err, KnownHostsError::ParseError { .. }));

        let backup = dir.join("known_hosts.corrupt");
        assert!(backup.exists(), ".corrupt backup must exist");
        assert_eq!(fs::read(&backup).unwrap(), b"{ not valid json !!!");
        assert!(path.exists(), "original file must be kept");

        // 再次失败 → 追加序号 .corrupt.1（不覆盖已有备份）
        let err2 = KnownHostsStore::load_from(&path).unwrap_err();
        assert!(matches!(err2, KnownHostsError::ParseError { .. }));
        assert!(
            dir.join("known_hosts.corrupt.1").exists(),
            "second backup must use numbered suffix"
        );
        assert_eq!(fs::read(&backup).unwrap(), b"{ not valid json !!!");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_io_error_returns_error_without_backup() {
        // S-15b: 路径是目录 → 读取必败（IO 错误）：加载返回 Err 且不 panic；
        // 目录不可复制，备份静默跳过（不产生 .corrupt，错误语义不变）。
        let dir = test_dir("iodir");
        let path = dir.join("known_hosts");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir(&path).unwrap();

        let err = KnownHostsStore::load_from(&path).unwrap_err();
        assert!(matches!(err, KnownHostsError::IoError { .. }));
        assert!(!dir.join("known_hosts.corrupt").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
