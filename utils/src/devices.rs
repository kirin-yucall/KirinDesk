//! M10: 设备列表持久化 — `SavedDevice` 与 `DeviceStore`。
//!
//! 连接成功的设备自动保存到 `kirin_desk/devices.json`（路径经 `dirs` crate
//! 跨平台解析，与 M1-T002 配置路径策略一致，复用 `Config::config_dir()`）。
//!
//! 按 `id`（DNS 子域标识 `{id}.{domain}`）去重：重复连接只更新记录并刷新
//! `last_seen`。
//!
//! M8-T037: 展示顺序改为**手动排序优先**——列表按 `sort_order` 升序展示；
//! `upsert` 新设备追加到末尾（`sort_order = max + 1`，不打乱手动排序）；
//! 旧数据（`sort_order` 全为默认 0）首次加载按 `last_seen` 降序迁移为连续序号。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::config::Config;

/// 一条已保存的远端设备记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedDevice {
    /// DNS 子域标识（`{id}.{domain}` 用于 SRV/TXT/AAAA 发现）。
    pub id: String,
    /// 用户可见别名（连接时作为昵称发送给服务端；允许为空，展示时回退 id）。
    pub nickname: String,
    /// 备注名（M8-T037：用户本地标注，不参与连接；默认空）。
    #[serde(default)]
    pub remark: String,
    /// 挑战码（M8-T037：连接时预填 Connect 表单；默认空 = 无挑战码）。
    #[serde(default)]
    pub challenge: String,
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
    /// 手动排序序号（M8-T037：列表按此升序展示；上移/下移交换相邻项）。
    #[serde(default)]
    pub sort_order: u32,
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
                // M8-T037: 旧数据迁移——所有记录 sort_order 均为默认 0 时（旧版
                // 无该字段），按 last_seen 降序生成连续序号（保持"最近连接排前"
                // 既有体验，迁移后由用户手动接管）。
                if !store.devices.is_empty()
                    && store.devices.iter().all(|d| d.sort_order == 0)
                {
                    store.sort_by_last_seen();
                    for (i, d) in store.devices.iter_mut().enumerate() {
                        d.sort_order = i as u32;
                    }
                }
                store.sort_by_order();
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
    ///
    /// S-07 (F-8): 经 `fsutil::write_private` 落盘（0600/0700/O_NOFOLLOW；
    /// 设备表含公钥等标识信息）。
    pub fn save_to(&self, path: &Path) -> Result<(), DeviceError> {
        let content = serde_json::to_string_pretty(&self.devices)
            .map_err(|e| DeviceError::SerializeError(e.to_string()))?;
        crate::fsutil::write_private(path, content.as_bytes()).map_err(|e| DeviceError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }

    /// 已保存设备（按 `last_seen` 降序）。
    pub fn devices(&self) -> &[SavedDevice] {
        &self.devices
    }

    /// 新增或更新设备：按 `id` 去重（重复则整体替换并保留新 `last_seen`）。
    /// M8-T037: 新设备追加到列表末尾（`sort_order = max + 1`）；更新既有
    /// 记录**不改变其 sort_order**（不打乱手动排序）。调用方构造时
    /// `last_seen` 应填 `Utc::now()`。
    pub fn upsert(&mut self, device: SavedDevice) {
        if let Some(existing) = self.devices.iter_mut().find(|d| d.id == device.id) {
            *existing = device;
        } else {
            let order = self
                .devices
                .iter()
                .map(|d| d.sort_order)
                .max()
                .map(|m| m + 1)
                .unwrap_or(0);
            self.devices.push(SavedDevice { sort_order: order, ..device });
        }
        self.sort_by_order();
    }

    /// 删除设备记录，返回是否删除成功。
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.devices.len();
        self.devices.retain(|d| d.id != id);
        self.devices.len() != before
    }

    /// 编辑设备：备注名 / 地址(IP 或域名) / 端口 / 昵称 / 挑战码，返回是否
    /// 找到该设备（M8-T037：昵称/挑战码/备注名允许为空——空昵称=展示回退 id，
    /// 空挑战码=无挑战码）。
    ///
    /// 地址解析：`host` 可解析为 IP → 更新 `ipv6` 并清空 `domain`；否则视为
    /// 域名 → 更新 `domain`（`ipv6` 保留原直连回退值）；`host` 为空 → 地址
    /// 两字段均保持原值（选择性保存——未改的字段不被覆盖）。
    pub fn update(
        &mut self,
        id: &str,
        remark: &str,
        host: &str,
        port: u16,
        nickname: &str,
        challenge: &str,
    ) -> bool {
        match self.devices.iter_mut().find(|d| d.id == id) {
            Some(d) => {
                d.remark = remark.to_string();
                d.nickname = nickname.to_string();
                d.challenge = challenge.to_string();
                d.port = port;
                let host = host.trim();
                if host.is_empty() {
                    // 地址未修改 → 保持原值。
                } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    d.ipv6 = ip.to_string();
                    d.domain = String::new();
                } else {
                    d.domain = host.to_string();
                }
                true
            }
            None => false,
        }
    }

    /// 上移：与上一项交换 `sort_order` 并重排，返回是否成功（首项 → false）。
    pub fn move_up(&mut self, id: &str) -> bool {
        let idx = self
            .devices
            .iter()
            .position(|d| d.id == id)
            .unwrap_or(usize::MAX);
        if idx == usize::MAX || idx == 0 {
            return false;
        }
        self.swap_order(idx - 1, idx);
        true
    }

    /// 下移：与下一项交换 `sort_order` 并重排，返回是否成功（末项 → false）。
    pub fn move_down(&mut self, id: &str) -> bool {
        let idx = self
            .devices
            .iter()
            .position(|d| d.id == id)
            .unwrap_or(usize::MAX);
        if idx == usize::MAX || idx + 1 >= self.devices.len() {
            return false;
        }
        self.swap_order(idx, idx + 1);
        true
    }

    /// 交换两条记录的 sort_order 后按序号重排（等价于交换列表相邻位置）。
    fn swap_order(&mut self, a: usize, b: usize) {
        let oa = self.devices[a].sort_order;
        self.devices[a].sort_order = self.devices[b].sort_order;
        self.devices[b].sort_order = oa;
        self.sort_by_order();
    }

    fn sort_by_order(&mut self) {
        self.devices.sort_by_key(|d| d.sort_order);
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
            remark: String::new(),
            challenge: String::new(),
            ipv6: "2001:db8::1".to_string(),
            port: 3389,
            pubkey: "ed25519:testkey".to_string(),
            device_type: "desktop".to_string(),
            last_seen,
            domain: "example.com".to_string(),
            sort_order: 0,
        }
    }

    /// 每个测试独立临时目录——避免并行测试共享目录互相 `remove_dir_all`
    /// 产生竞态（IoError NotFound）。
    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("kirin_desk_test_devices_{name}"))
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = test_dir("rt");
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
        let path = test_dir("dedup").join("devices_dedup.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-a", "old name", Utc::now()));
        store.upsert(sample_device("pc-a", "new name", Utc::now()));
        store.upsert(sample_device("pc-b", "PC B", Utc::now()));
        assert_eq!(store.devices().len(), 2);
        let a = store.devices().iter().find(|d| d.id == "pc-a").unwrap();
        assert_eq!(a.nickname, "new name");
        let _ = fs::remove_dir_all(test_dir("dedup"));
    }

    #[test]
    fn test_new_devices_append_to_end() {
        // M8-T037: 新设备 sort_order = max + 1，追加列表末尾（手动排序不被新设备打断）。
        let path = test_dir("append").join("devices_append.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-a", "PC A", Utc::now()));
        store.upsert(sample_device("pc-b", "PC B", Utc::now()));
        // 模拟手动排序：pc-b 移到最前。
        assert!(store.move_up("pc-b"));
        assert_eq!(store.devices()[0].id, "pc-b");
        assert_eq!(store.devices()[1].id, "pc-a");
        // 新设备追加末尾，不打乱手动顺序。
        store.upsert(sample_device("pc-c", "PC C", Utc::now()));
        assert_eq!(
            store.devices().iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            vec!["pc-b", "pc-a", "pc-c"]
        );
        let _ = fs::remove_dir_all(test_dir("append"));
    }

    #[test]
    fn test_upsert_existing_keeps_sort_order() {
        let path = test_dir("keep_order").join("devices_keep_order.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-a", "PC A", Utc::now()));
        store.upsert(sample_device("pc-b", "PC B", Utc::now()));
        assert!(store.move_up("pc-b"));
        // 再次连接 pc-b（last_seen 刷新）→ 顺序保持。
        store.upsert(sample_device("pc-b", "PC B", Utc::now()));
        assert_eq!(store.devices()[0].id, "pc-b");
        assert_eq!(store.devices()[1].id, "pc-a");
        let _ = fs::remove_dir_all(test_dir("keep_order"));
    }

    #[test]
    fn test_move_up_down() {
        let path = test_dir("move").join("devices_move.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("a", "A", Utc::now()));
        store.upsert(sample_device("b", "B", Utc::now()));
        store.upsert(sample_device("c", "C", Utc::now()));
        assert_eq!(store.devices()[0].id, "a");
        // b 上移 → [b, a, c]
        assert!(store.move_up("b"));
        assert_eq!(
            store.devices().iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            vec!["b", "a", "c"]
        );
        // b 下移 → [a, b, c]
        assert!(store.move_down("b"));
        assert_eq!(
            store.devices().iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        // 首项上移 / 末项下移 → false
        assert!(!store.move_up("a"));
        assert!(!store.move_down("c"));
        // 未知 id → false
        assert!(!store.move_up("ghost"));
        // 移动后序号连续（保存重载后顺序保持）
        store.save_to(&path).unwrap();
        let loaded = DeviceStore::load_from(&path).unwrap();
        assert_eq!(
            loaded.devices().iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        let _ = fs::remove_dir_all(test_dir("move"));
    }

    #[test]
    fn test_legacy_devices_migrated_by_last_seen() {
        // M8-T037: 旧格式（无 sort_order/remark/challenge 字段）加载不失败；
        // sort_order 全缺省 → 按 last_seen 降序迁移。
        let dir = test_dir("legacy");
        let path = dir.join("devices_legacy.json");
        let legacy = r#"[
            {"id":"old","nickname":"Old","ipv6":"2001:db8::1","port":3389,
             "pubkey":"k","device_type":"desktop","last_seen":"2026-08-01T00:00:00Z","domain":"d.com"},
            {"id":"new","nickname":"New","ipv6":"2001:db8::2","port":3389,
             "pubkey":"k","device_type":"desktop","last_seen":"2026-08-03T00:00:00Z","domain":"d.com"}
        ]"#;
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, legacy).unwrap();
        let store = DeviceStore::load_from(&path).unwrap();
        assert_eq!(store.devices().len(), 2);
        // 最近连接排前（new 在前）。
        assert_eq!(store.devices()[0].id, "new");
        assert_eq!(store.devices()[1].id, "old");
        // 新字段默认值。
        assert_eq!(store.devices()[0].remark, "");
        assert_eq!(store.devices()[0].challenge, "");
        assert_eq!(store.devices()[0].sort_order, 0);
        assert_eq!(store.devices()[1].sort_order, 1);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_sorted_by_last_seen_desc() {
        // 旧数据迁移路径依赖 last_seen 降序；此测试验证迁移前的排序基准。
        let path = test_dir("sort").join("devices_sort.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        let t1 = Utc::now() - chrono::Duration::hours(2);
        let t2 = Utc::now();
        let t3 = Utc::now() - chrono::Duration::hours(1);
        store.upsert(sample_device("old", "old", t1));
        store.upsert(sample_device("new", "new", t2));
        store.upsert(sample_device("mid", "mid", t3));
        // 新设备追加末尾（upsert 顺序），手动排序未介入时保持插入序。
        assert_eq!(
            store.devices().iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            vec!["old", "new", "mid"]
        );
        let _ = fs::remove_dir_all(test_dir("sort"));
    }

    #[test]
    fn test_remove_device() {
        let path = test_dir("remove").join("devices_remove.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-a", "PC A", Utc::now()));
        store.upsert(sample_device("pc-b", "PC B", Utc::now()));
        assert!(store.remove("pc-a"));
        assert_eq!(store.devices().len(), 1);
        assert_eq!(store.devices()[0].id, "pc-b");
        // 删除不存在的返回 false
        assert!(!store.remove("pc-a"));
        let _ = fs::remove_dir_all(test_dir("remove"));
    }

    #[test]
    fn test_update_device() {
        let path = test_dir("update").join("devices_update.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-a", "PC A", Utc::now()));
        assert!(store.update(
            "pc-a", "家里台式机", "2001:db8::9", 9000, "新昵称", "secret-code"
        ));
        let a = &store.devices()[0];
        assert_eq!(a.remark, "家里台式机");
        assert_eq!(a.nickname, "新昵称");
        assert_eq!(a.challenge, "secret-code");
        assert_eq!(a.ipv6, "2001:db8::9");
        assert_eq!(a.domain, "");
        assert_eq!(a.port, 9000);
        // 域名输入 → 更新 domain，ipv6 保留原值（直连回退）。
        assert!(store.update("pc-a", "", "pc-a.example.com", 9000, "新昵称", ""));
        let a = &store.devices()[0];
        assert_eq!(a.domain, "pc-a.example.com");
        assert_eq!(a.ipv6, "2001:db8::9");
        assert_eq!(a.challenge, "", "空挑战码 = 无挑战码");
        // 空 host → 地址两字段均保持原值（选择性保存）。
        assert!(store.update("pc-a", "备注", "", 9000, "新昵称", "c"));
        let a = &store.devices()[0];
        assert_eq!(a.remark, "备注");
        assert_eq!(a.domain, "pc-a.example.com");
        assert_eq!(a.ipv6, "2001:db8::9");
        // 不存在的设备返回 false
        assert!(!store.update("ghost", "", "", 1, "", ""));
        let _ = fs::remove_dir_all(test_dir("update"));
    }
}
