//! M10: 设备列表持久化 — `SavedDevice` 与 `DeviceStore`。
//!
//! 连接成功的设备自动保存到 `kirin_desk/devices.json`（路径经 `dirs` crate
//! 跨平台解析，与 M1-T002 配置路径策略一致，复用 `Config::config_dir()`）。
//!
//! 按 `id`（DNS 子域标识 `{id}.{domain}`）去重：重复连接只更新记录并刷新
//! `last_seen`，`upsert`/`load` 后按 `last_seen` 降序排列（Devices 页"最近连接排前"）。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::config::Config;

/// 一条已保存的远端设备记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedDevice {
    /// DNS 子域标识（`{id}.{domain}` 用于 SRV/TXT/AAAA 发现）。
    pub id: String,
    /// 用户可见别名（连接时作为昵称发送给服务端）。
    pub nickname: String,
    /// IPv6 地址（发现结果）。
    pub ipv6: String,
    /// 服务端口（SRV 记录）。
    pub port: u16,
    /// Ed25519 公钥（base64，DNS TXT 记录值，握手时强制验证）。
    pub pubkey: String,
    /// 设备类型: "desktop"（远程桌面）| "server"（远程终端）。
    pub device_type: String,
    /// 上次成功连接时间（UTC）。
    pub last_seen: DateTime<Utc>,
    /// 所在域名（DNS 发现用）。
    pub domain: String,
}

/// 设备列表持久化存储（内存 Vec + JSON 文件）。
#[derive(Debug, Clone)]
pub struct DeviceStore {
    path: PathBuf,
    devices: Vec<SavedDevice>,
}

/// 设备存储错误。
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("I/O error at {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to parse devices file at {path}: {detail}")]
    ParseError {
        path: PathBuf,
        detail: String,
    },
    #[error("Serialization error: {0}")]
    SerializeError(String),
    #[error("No config directory found")]
    NoConfigDir,
}

impl DeviceStore {
    /// 默认设备文件路径: `{config_dir}/kirin_desk/devices.json`（同 M1-T002 策略）。
    pub fn default_path() -> Result<PathBuf, DeviceError> {
        let base = Config::config_dir().map_err(|_| DeviceError::NoConfigDir)?;
        Ok(base.join("devices.json"))
    }

    /// 从默认路径加载（文件不存在 → 空列表）。
    pub fn load() -> Result<Self, DeviceError> {
        let path = Self::default_path()?;
        Self::load_from(&path)
    }

    /// 从指定路径加载（文件不存在 → 空列表）。
    pub fn load_from(path: &Path) -> Result<Self, DeviceError> {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let devices: Vec<SavedDevice> = serde_json::from_str(&content)
                    .map_err(|e| DeviceError::ParseError {
                        path: path.to_path_buf(),
                        detail: e.to_string(),
                    })?;
                let mut store = Self {
                    path: path.to_path_buf(),
                    devices,
                };
                store.sort_by_last_seen();
                Ok(store)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: path.to_path_buf(),
                devices: Vec::new(),
            }),
            Err(e) => Err(DeviceError::IoError {
                path: path.to_path_buf(),
                source: e,
            }),
        }
    }

    /// 保存到默认路径。
    pub fn save(&self) -> Result<(), DeviceError> {
        self.save_to(&self.path)
    }

    /// 保存到指定路径（自动创建父目录）。
    pub fn save_to(&self, path: &Path) -> Result<(), DeviceError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| DeviceError::IoError {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let content = serde_json::to_string_pretty(&self.devices)
            .map_err(|e| DeviceError::SerializeError(e.to_string()))?;
        std::fs::write(path, &content).map_err(|e| DeviceError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }

    /// 已保存设备（按 `last_seen` 降序）。
    pub fn devices(&self) -> &[SavedDevice] {
        &self.devices
    }

    /// 新增或更新设备：按 `id` 去重（重复则整体替换并保留新 `last_seen`），
    /// 之后按 `last_seen` 降序重排。调用方构造时 `last_seen` 应填 `Utc::now()`。
    pub fn upsert(&mut self, device: SavedDevice) {
        if let Some(existing) = self.devices.iter_mut().find(|d| d.id == device.id) {
            *existing = device;
        } else {
            self.devices.push(device);
        }
        self.sort_by_last_seen();
    }

    /// 删除设备记录，返回是否删除成功。
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.devices.len();
        self.devices.retain(|d| d.id != id);
        self.devices.len() != before
    }

    /// 编辑设备：更新别名、域名、端口，返回是否找到该设备。
    pub fn update(&mut self, id: &str, nickname: &str, domain: &str, port: u16) -> bool {
        match self.devices.iter_mut().find(|d| d.id == id) {
            Some(d) => {
                d.nickname = nickname.to_string();
                d.domain = domain.to_string();
                d.port = port;
                true
            }
            None => false,
        }
    }

    fn sort_by_last_seen(&mut self) {
        self.devices
            .sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sample_device(id: &str, nickname: &str, last_seen: DateTime<Utc>) -> SavedDevice {
        SavedDevice {
            id: id.to_string(),
            nickname: nickname.to_string(),
            ipv6: "2001:db8::1".to_string(),
            port: 3389,
            pubkey: "ed25519:testkey".to_string(),
            device_type: "desktop".to_string(),
            last_seen,
            domain: "example.com".to_string(),
        }
    }

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join("kirin_desk_test_devices")
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = test_dir();
        let path = dir.join("devices.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-a", "PC A", Utc::now()));
        store.save_to(&path).unwrap();

        let loaded = DeviceStore::load_from(&path).unwrap();
        assert_eq!(loaded.devices().len(), 1);
        let d = &loaded.devices()[0];
        assert_eq!(d.id, "pc-a");
        assert_eq!(d.nickname, "PC A");
        assert_eq!(d.port, 3389);
        assert_eq!(d.device_type, "desktop");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_missing_file_returns_empty() {
        let path = std::env::temp_dir().join("kirin_desk_no_such_devices.json");
        let store = DeviceStore::load_from(&path).unwrap();
        assert!(store.devices().is_empty());
    }

    #[test]
    fn test_upsert_dedup_by_id() {
        let path = test_dir().join("devices_dedup.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-a", "old name", Utc::now()));
        store.upsert(sample_device("pc-a", "new name", Utc::now()));
        store.upsert(sample_device("pc-b", "PC B", Utc::now()));
        assert_eq!(store.devices().len(), 2);
        let a = store.devices().iter().find(|d| d.id == "pc-a").unwrap();
        assert_eq!(a.nickname, "new name");
        let _ = fs::remove_dir_all(test_dir());
    }

    #[test]
    fn test_sorted_by_last_seen_desc() {
        let path = test_dir().join("devices_sort.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        let t1 = Utc::now() - chrono::Duration::hours(2);
        let t2 = Utc::now();
        let t3 = Utc::now() - chrono::Duration::hours(1);
        store.upsert(sample_device("old", "old", t1));
        store.upsert(sample_device("new", "new", t2));
        store.upsert(sample_device("mid", "mid", t3));
        // 最近连接排前
        assert_eq!(store.devices()[0].id, "new");
        assert_eq!(store.devices()[1].id, "mid");
        assert_eq!(store.devices()[2].id, "old");
        let _ = fs::remove_dir_all(test_dir());
    }

    #[test]
    fn test_remove_device() {
        let path = test_dir().join("devices_remove.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-a", "PC A", Utc::now()));
        store.upsert(sample_device("pc-b", "PC B", Utc::now()));
        assert!(store.remove("pc-a"));
        assert_eq!(store.devices().len(), 1);
        assert_eq!(store.devices()[0].id, "pc-b");
        // 删除不存在的返回 false
        assert!(!store.remove("pc-a"));
        let _ = fs::remove_dir_all(test_dir());
    }

    #[test]
    fn test_update_device() {
        let path = test_dir().join("devices_update.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-a", "PC A", Utc::now()));
        assert!(store.update("pc-a", "新别名", "kirin.example.com", 9000));
        let a = &store.devices()[0];
        assert_eq!(a.nickname, "新别名");
        assert_eq!(a.domain, "kirin.example.com");
        assert_eq!(a.port, 9000);
        // 不存在的设备返回 false
        assert!(!store.update("ghost", "x", "y", 1));
        let _ = fs::remove_dir_all(test_dir());
    }
}
