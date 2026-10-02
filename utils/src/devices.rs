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

///
/// 旧版本 `SavedDevice` 无此字段，回填只能靠「domain 为空 + id 是否指纹形态」
/// 猜测（BUG-R85-1：非指纹 ID〔自定义 ID / relay 注册键 `HD-XXXX`〕的 ID 模式
/// 记录被误判为 IP 模式，把会话显示 label 当 IP 回填）。新模式记录显式落库，
/// 旧记录反序列化落 `Unknown` → 回填回落既有启发式（行为不变）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceConnMode {
    /// 未知（旧版记录默认值）→ 回填/展示按既有启发式（空 domain + 指纹形态 = ID）。
    #[default]
    Unknown,
    /// 设备 ID 模式连接（键 = 完整设备 ID / relay 注册键；无直连 IP/域名地址，
    /// `ipv6`/`port` 无意义，保存层不写值）。
    Id,
    /// IP / 域名模式连接（`ipv6`/`domain` 为真实地址）。
    Ip,
}

/// 一条已保存的远端设备记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedDevice {
    /// DNS 子域标识（`{id}.{domain}` 用于 SRV/TXT/AAAA 发现）。
    pub id: String,
    /// 用户可见别名（连接时作为昵称发送给服务端；允许为空，展示时回退 id）。
    ///
    /// （`ui::fill_connect_from_device` 原样回填，不动态跟随设备 ID /
    /// 备注名 / 远控用户名）。语义按 mode 分治：
    /// - **ID 模式** = 用户展示标签（wire 中性）；取值来源 = 连接表单输入
    ///   `nickname == id` 是**合法保存值**（旧自动保存残留形态亦原样保留），
    ///   读取点仅 trim 空白归一（[`normalize_legacy_id_nicknames`]）；
    ///   自动保存恒为 `server_id`，不得改动（读取点零触碰）。
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
    /// [`DeviceConnMode::Unknown`]，回填/展示回落既有启发式，旧 devices.json
    /// 加载不失败）。
    #[serde(default)]
    pub mode: DeviceConnMode,
    /// [`crate::osinfo::KNOWN_OS_TYPES`] 常量集成员；**空 = 旧对端未通告/
    /// 未知**——展示层回退既有 server/desktop 角色徽标，不猜）。
    ///
    /// 尾部追加 `#[serde(default)]`：旧 devices.json（无此字段）加载不
    /// 失败（同 `mode` 先例）；`upsert` 合并语义 = 入参非空刷新 / 入参空
    /// 保留既有值（旧对端再连不擦除新端已通告值）。
    #[serde(default)]
    pub os_type: String,
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
                // 仅 trim 首尾空白，**值原样保留**（== id 是合法保存值，
                // 保存什么回填什么；内存态，不写回磁盘——与上方 sort_order
                // 迁移同款「读取点迁移」模式）。
                normalize_legacy_id_nicknames(&mut store.devices);
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

    /// 新增或更新设备：按 `id` 去重。
    ///
    /// **保留用户字段**——旧实现 `*existing = device` 整条替换，而自动保存
    /// 路径（`ui::save_device_to_store`）每次连接成功都构造
    /// `SavedDevice { nickname: server_id, remark: "", challenge: "",
    /// sort_order: 0, … }` → 用户在编辑弹窗设置的**备注名**/挑战码被下次
    /// 连接成功即冲掉、手动排序被 `sort_order = 0` 打乱（文档宣称不改变
    /// sort_order 但代码违反，两设备测试巧合通过）。
    ///
    /// - **连接派生（恒刷新）**：`ipv6`/`port`/`pubkey`/`device_type`/
    ///   `last_seen`/`domain`/`mode`。
    ///   入参空（旧对端未通告）保留既有值——旧对端再连不擦除新端已通告值。
    /// - **`nickname` 按入参 mode 分治**：
    ///   - **IP 模式 = 握手凭据**（红线：客户端发 `connect_nickname`，服务端
    ///     按昵称绑定响应签名并对照配置昵称校验，不匹配即结构化拒绝
    ///     `nickname_mismatch`——见 `ui::policy::response_signature_bind_id`
    ///     与 `core::crypto::handshake::verify_server_init_inner`）；表单回填
    ///     `fill_connect_from_device` 直接以 `SavedDevice.nickname` 为发送值 →
    ///     合并**必须刷新**为自动保存值（== 本次成功凭据，即旧整条替换
    ///     语义）；若保留用户编辑值，「编辑昵称→手动改表单连成」场景将丢失
    ///     回填自修复 → 后续点设备连接恒发旧值被拒。发送值全场景与旧实现
    ///     逐位一致，wire 零变更。
    ///   - **ID 模式 = 纯展示标签**（wire 凭据 = device_id + challenge，
    ///     「点连接昵称框不回填已保存昵称」根因）：
    ///     - 入参 nickname trim 后非空 **且 ≠ id**（= 用户显式昵称：连接
    ///       表单输入 / mobile 真实输入）→ **刷新**（「保存什么回填什么」，
    ///       最后保存值为准）；
    ///       `server_id`、mobile 空回退 `device_id`）→ **保留既有值**；
    ///       仅既有为空时填空（残留不覆盖已设置值——同机 CLI/mobile 自动
    ///       保存不会把桌面用户昵称冲成设备 ID）。
    ///     边界：用户把 ID 模式昵称**故意**设为与设备 ID 完全相同 → 与
    ///     残留不可区分，按残留口径（不刷新；概率极低，后果 = 编辑弹窗
    ///     或改表单其他值重设即可）。
    /// - **用户字段（恒保留）**：`remark`/`challenge`/`sort_order`。`id` 为
    ///   匹配键，两侧相等。
    ///
    /// M8-T037: 新设备追加到列表末尾（`sort_order = max + 1`，全字段写入
    /// 入参值——IP 模式自动保存路径 `nickname = server_id`（凭据）落库；
    /// `last_seen` 应填 `Utc::now()`。
    pub fn upsert(&mut self, device: SavedDevice) {
        if let Some(existing) = self.devices.iter_mut().find(|d| d.id == device.id) {
            // 连接派生字段：刷新为本次连接结果。
            existing.ipv6 = device.ipv6;
            existing.port = device.port;
            existing.pubkey = device.pubkey;
            existing.device_type = device.device_type;
            existing.last_seen = device.last_seen;
            existing.domain = device.domain;
            existing.mode = device.mode;
            // 对端通告值；入参空（旧对端未通告 / 不支持平台）→ 保留既有值
            // （旧对端再连不擦除新端已落库值；空值不猜不补）。
            if !device.os_type.is_empty() {
                existing.os_type = device.os_type;
            }
            // nickname == 本次成功凭据（`save_device_to_store` 恒以
            // server_id 落值）→ 刷新（红线，发送值逐位不变，杜绝回填
            // 自修复丢失后恒发编辑旧值被 `nickname_mismatch` 拒绝）；
            // ≠ id）刷新 / 残留形态（== id 或空）保留既有值、仅空时填空。
            if device.mode == DeviceConnMode::Ip {
                existing.nickname = device.nickname;
            } else {
                let in_nick = device.nickname.trim();
                if !in_nick.is_empty() && in_nick != existing.id.trim() {
                    // 用户显式昵称（连接表单输入 / mobile 真实值）→ 刷新。
                    existing.nickname = device.nickname;
                } else if existing.nickname.trim().is_empty() && !in_nick.is_empty() {
                    // 新记录经自动保存首次获得昵称）；既有非空 → 保留。
                    existing.nickname = device.nickname;
                }
            }
            // 用户字段（remark/challenge/sort_order）：保留既有记录值，
            // 不被自动保存冲掉。
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

/// 空白类归一，值原样保留**（纯函数，可单测）。
///
/// 保存残留定案），用户 09-09 晚间反馈「点连接昵称框未回填已保存昵称」。
/// PM 裁定口径：**昵称 = 独立持久化字段，保存什么回填什么，不做 ==id
/// 显式设置，两者不可区分，一律原样回填）。本函数仅保留首尾空白 trim
/// （旧记录空白包裹残留形态不原样进连接表单；显示层
/// `ui::device_display_name` 与本归一同为 trim 口径，无冲突）。
///
/// **范围**（与 `ui::device_record_is_id_mode` 判定**逐字同口径**）：
/// - `mode == Id` → ID 模式记录；
///   （64 hex）→ 启发式 ID 模式记录；
/// - **IP/DNS 记录绝不触碰**：IP 模式 `nickname == id == server_id` 是握手
///   拒绝），必须逐位原样保留（连 trim 也不做）。
pub(crate) fn normalize_legacy_id_nicknames(devices: &mut [SavedDevice]) {
    for d in devices.iter_mut() {
        if !record_is_id_mode(d) {
            continue;
        }
        d.nickname = d.nickname.trim().to_string();
    }
}

/// Unknown 记录启发式）。
fn record_is_id_mode(d: &SavedDevice) -> bool {
    match d.mode {
        DeviceConnMode::Id => true,
        DeviceConnMode::Ip => false,
        DeviceConnMode::Unknown => d.domain.is_empty() && is_fingerprint_shaped_id(&d.id),
    }
}

/// 指纹形态判定（与 `ui::is_fingerprint_shaped` 同口径）：去除冒号与空白后
/// 恰为 64 个 ASCII 十六进制字符。
fn is_fingerprint_shaped_id(s: &str) -> bool {
    let stripped: String = s
        .chars()
        .filter(|c| !matches!(*c, ':' | ' ' | '\t' | '\r' | '\n'))
        .collect();
    stripped.len() == 64 && stripped.chars().all(|c| c.is_ascii_hexdigit())
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
            mode: DeviceConnMode::Ip,
            os_type: String::new(),
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
        // 合并刷新为自动保存值（`"new name"`，与旧整条替换逐位一致）；
        // 用户字段（备注/挑战码/排序）保留断言见 `test_r86u_upsert_merge_*`
        // 两例（IP/ID 分治）。
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


    #[test]
    fn test_r85a_legacy_json_without_mode_deserializes_as_unknown() {
        // 旧 devices.json（无 mode 字段）反序列化不得失败；无字段 → Unknown。
        let dir = test_dir("r85a_legacy");
        let path = dir.join("devices_r85a_legacy.json");
        let legacy = r#"[
            {"id":"HD-62EC5BC9","nickname":"办公室","ipv6":"办公室 (HD-62EC5BC9, via relay Direct)","port":0,
             "pubkey":"k","device_type":"desktop","last_seen":"2026-09-01T00:00:00Z","domain":""},
            {"id":"pc-a","nickname":"PC A","ipv6":"2001:db8::1","port":3389,
             "pubkey":"k","device_type":"desktop","last_seen":"2026-09-02T00:00:00Z","domain":"d.com"}
        ]"#;
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, legacy).unwrap();
        let store = DeviceStore::load_from(&path).unwrap();
        assert_eq!(store.devices().len(), 2);
        assert!(
            store.devices().iter().all(|d| d.mode == DeviceConnMode::Unknown),
            "旧记录 mode 一律落 Unknown（回填侧再回落启发式）"
        );
        // 旧记录其余字段原样保留（脏 ipv6 值不在此层清洗，展示/回填层处理）。
        let hd = store.devices().iter().find(|d| d.id == "HD-62EC5BC9").unwrap();
        assert_eq!(hd.ipv6, "办公室 (HD-62EC5BC9, via relay Direct)");
        assert_eq!(hd.port, 0);
        assert!(hd.domain.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_r85a_mode_roundtrip_and_explicit_values() {
        // 新字段序列化往返（id/ip 显式值）+ 未知枚举字符串 fail-closed（报错而非静默）。
        let dir = test_dir("r85a_rt");
        let path = dir.join("devices_r85a_rt.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        let mut d = sample_device("HD-62EC5BC9", "办公室", Utc::now());
        d.mode = DeviceConnMode::Id;
        d.domain = String::new();
        d.ipv6 = String::new();
        d.port = 0;
        store.upsert(d);
        let mut e = sample_device("pc-b", "PC B", Utc::now());
        e.mode = DeviceConnMode::Ip;
        store.upsert(e);
        store.save_to(&path).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"mode\": \"id\""), "Id 序列化 snake_case: {raw}");
        assert!(raw.contains("\"mode\": \"ip\""), "Ip 序列化 snake_case: {raw}");

        let loaded = DeviceStore::load_from(&path).unwrap();
        let hd = loaded.devices().iter().find(|d| d.id == "HD-62EC5BC9").unwrap();
        assert_eq!(hd.mode, DeviceConnMode::Id);
        let pb = loaded.devices().iter().find(|d| d.id == "pc-b").unwrap();
        assert_eq!(pb.mode, DeviceConnMode::Ip);

        // 非法 mode 值 → 解析失败（fail-closed，不静默吞）。
        let bad = r#"[{"id":"x","nickname":"x","remark":"","challenge":"","ipv6":"","port":0,
                       "pubkey":"k","device_type":"desktop","last_seen":"2026-09-01T00:00:00Z",
                       "domain":"","sort_order":0,"mode":"wat"}]"#;
        let bad_path = dir.join("bad.json");
        fs::write(&bad_path, bad).unwrap();
        assert!(DeviceStore::load_from(&bad_path).is_err());
        let _ = fs::remove_dir_all(dir);
    }


    #[test]
    fn test_r86u_upsert_merge_ip_refreshes_credential_preserves_user_fields() {
        // 已有 IP 模式设备再 upsert（模拟 `save_device_to_store` 自动保存
        // 入参形态：nickname=server_id、remark/challenge 空、sort_order=0）→
        // 连接派生字段（ipv6/port/pubkey/device_type/last_seen/domain/mode）
        // 刷新；**nickname 按 B3 分治刷新为本次成功凭据**（IP 模式 nickname
        // = 握手发送值来源，保留编辑旧值会破坏回填自修复）；用户字段
        // （remark/challenge/sort_order）保留。
        let path = test_dir("r86u_merge").join("devices_r86u_merge.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        let first = sample_device("pc-a", "pc-a", Utc::now());
        store.upsert(first);
        // 用户在编辑弹窗设置（`update` 同形态写入）：备注名 + 误改昵称 +
        // 挑战码。
        assert!(store.update("pc-a", "办公室台式机", "", 0, "office-pc", "sec-code"));
        store.upsert(sample_device("pc-b", "pc-b", Utc::now()));
        // 手动排序：pc-b 提到最前（pc-a → sort_order 1）。
        assert!(store.move_up("pc-b"));
        let before = store.devices().iter().find(|d| d.id == "pc-a").unwrap();
        assert_eq!(before.sort_order, 1);

        // 再次连接成功（用户手动在表单填回正确凭据 "pc-a" 连成）→ 自动
        // 保存入参（新派生值 + 用户字段"默认值"，nickname=本次成功凭据）。
        let later = Utc::now() + chrono::Duration::hours(1);
        store.upsert(SavedDevice {
            id: "pc-a".to_string(),
            nickname: "pc-a".to_string(), // server_id 自动落值 = 本次成功凭据
            remark: String::new(),
            challenge: String::new(),
            ipv6: "240e:1234:5678:9::77".to_string(),
            port: 59990,
            pubkey: "ed25519:rotated".to_string(),
            device_type: "server".to_string(),
            last_seen: later,
            domain: "office.example.com".to_string(),
            sort_order: 0,
            mode: DeviceConnMode::Ip,
        });

        let a = store.devices().iter().find(|d| d.id == "pc-a").unwrap();
        // 连接派生字段：刷新为本次连接结果。
        assert_eq!(a.ipv6, "240e:1234:5678:9::77");
        assert_eq!(a.port, 59990);
        assert_eq!(a.pubkey, "ed25519:rotated");
        assert_eq!(a.device_type, "server");
        assert_eq!(a.last_seen, later);
        assert_eq!(a.domain, "office.example.com");
        assert_eq!(a.mode, DeviceConnMode::Ip);
        assert_eq!(a.os_type, "windows-11", "os_type 非空入参刷新");
        // B3 凭据红线：IP 模式 nickname 刷新为本次成功凭据（== id，旧整条
        // 替换语义逐位一致）——回填 `fill_connect_from_device` 发送值不变，
        // 编辑误改的 "office-pc" 不再被发出（旧实现同此行为）。
        assert_eq!(a.nickname, "pc-a", "IP 模式 nickname = 凭据，恒刷新");
        // 用户字段：保留编辑弹窗设置，不被自动保存冲掉（用户「备注名被
        // 冲掉」修复点）。
        assert_eq!(a.remark, "办公室台式机", "remark 保留用户值");
        assert_eq!(a.challenge, "sec-code", "challenge 保留用户值");
        assert_eq!(a.sort_order, 1, "sort_order 保留手动排序（不被 0 打乱）");
        // 手动排序整体不被刷新打乱。
        assert_eq!(store.devices()[0].id, "pc-b");
        assert_eq!(store.devices()[1].id, "pc-a");
        let _ = fs::remove_dir_all(test_dir("r86u_merge"));
    }

    #[test]
    fn test_r86u_upsert_merge_id_mode_preserves_nickname() {
        // ID 模式记录：nickname 是纯展示标签（wire 凭据 = device_id +
        // challenge，nickname 仅入日志）→ 合并**保留用户值**（展示修复在
        // ID 模式同样生效）；连接派生字段照常刷新；入参形态 = 自动保存
        // （nickname = 被拨设备 ID == id）。
        let path = test_dir("r86u_merge_id").join("devices_r86u_merge_id.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-b", "pc-b", Utc::now())); // sort_order 0
        let first = sample_device("HD-62EC5BC9A1", "HD-62EC5BC9A1", Utc::now());
        store.upsert(first); // sort_order 1
        // 用户在编辑弹窗设置展示昵称（`update` 同形态写入）。
        assert!(store.update("HD-62EC5BC9A1", "机房 1 号", "", 0, "机柜 A 上位机", "code-x"));
        // 手动排序：HD 提到最前（sort_order 0），pc-b → 1。
        assert!(store.move_up("HD-62EC5BC9A1"));
        let before = store.devices().iter().find(|d| d.id == "HD-62EC5BC9A1").unwrap();
        assert_eq!(before.sort_order, 0);

        // 再次 ID 模式连接成功 → 自动保存入参（nickname == 被拨 ID == id）。
        let later = Utc::now() + chrono::Duration::hours(2);
        let mut fresh = sample_device("HD-62EC5BC9A1", "HD-62EC5BC9A1", later);
        fresh.mode = DeviceConnMode::Id;
        fresh.domain = String::new();
        fresh.ipv6 = String::new();
        fresh.port = 0;
        fresh.pubkey = "ed25519:rotated-id".to_string();
        store.upsert(fresh);

        let a = store.devices().iter().find(|d| d.id == "HD-62EC5BC9A1").unwrap();
        // 连接派生字段：刷新。
        assert_eq!(a.last_seen, later);
        assert_eq!(a.pubkey, "ed25519:rotated-id");
        assert_eq!(a.mode, DeviceConnMode::Id);
        // 用户字段：ID 模式 nickname 保留展示标签（不被 ==id 的自动保存
        // 值冲掉）+ 备注/挑战码/排序保留。
        assert_eq!(a.nickname, "机柜 A 上位机", "ID 模式 nickname = 展示标签，保留用户值");
        assert_eq!(a.remark, "机房 1 号");
        assert_eq!(a.challenge, "code-x");
        assert_eq!(a.sort_order, 0, "sort_order 保留手动排序（不被 0 打乱）");
        assert_eq!(store.devices()[0].id, "HD-62EC5BC9A1");
        assert_eq!(store.devices()[1].id, "pc-b");
        let _ = fs::remove_dir_all(test_dir("r86u_merge_id"));
    }

    #[test]
    fn test_r86u_upsert_new_device_full_write() {
        // 新建设备：全字段写入入参值（自动保存口径 nickname = server_id 落库）
        // + sort_order = max + 1 追加末尾（新建行为不变）。
        let path = test_dir("r86u_new").join("devices_r86u_new.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(sample_device("pc-a", "pc-a", Utc::now()));
        let mut fresh = sample_device("HD-62EC5BC9", "HD-62EC5BC9", Utc::now());
        fresh.mode = DeviceConnMode::Id;
        fresh.domain = String::new();
        fresh.ipv6 = String::new();
        fresh.port = 0;
        store.upsert(fresh.clone());
        assert_eq!(store.devices().len(), 2);
        let n = store.devices().iter().find(|d| d.id == "HD-62EC5BC9").unwrap();
        // 新设备全字段原样落库（`SavedDevice` 无 PartialEq 派生 → 逐字段断言）。
        assert_eq!(n.id, fresh.id);
        assert_eq!(n.nickname, fresh.nickname, "nickname = server_id 自动落值");
        assert_eq!(n.remark, fresh.remark);
        assert_eq!(n.challenge, fresh.challenge);
        assert_eq!(n.ipv6, fresh.ipv6);
        assert_eq!(n.port, fresh.port);
        assert_eq!(n.pubkey, fresh.pubkey);
        assert_eq!(n.device_type, fresh.device_type);
        assert_eq!(n.last_seen, fresh.last_seen);
        assert_eq!(n.domain, fresh.domain);
        assert_eq!(n.mode, fresh.mode);
        assert_eq!(n.sort_order, 1, "追加末尾（max + 1）");
        assert_eq!(store.devices()[1].id, "HD-62EC5BC9");
        let _ = fs::remove_dir_all(test_dir("r86u_new"));
    }


    const R98_FP: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";

    fn r98_device(id: &str, nickname: &str, domain: &str, mode: DeviceConnMode) -> SavedDevice {
        let mut d = sample_device(id, nickname, Utc::now());
        d.domain = domain.to_string();
        d.mode = mode;
        d
    }

    /// （PM 裁定：保存什么回填什么，不做 ==id 清空）：① ID 模式
    /// nickname==id（自动保存残留形态）原样保留；② ID 模式用户显式昵称
    /// （≠id）保留；③ ID 模式空昵称保持空；④ 首尾空白 → trim（值保留，
    /// B3，连 trim 也不做）；⑥ 旧 Unknown 记录启发式（domain 空 + 64hex
    /// 指纹 id）视同 ID 模式原样保留；⑦ Unknown + 有 domain（DNS 记录）
    /// 不动；⑧ Unknown + domain 空 + 非指纹 id（自定义 ID）= 启发式非
    /// ID，不动（与 `ui::device_record_is_id_mode` 回填路由同口径）。
    #[test]
    fn test_r98_normalize_legacy_id_nickname_matrix() {
        // 保存值，回填原样）；备注/挑战码等用户字段不受影响。
        let mut d = r98_device("HD-62EC5BC9", "HD-62EC5BC9", "", DeviceConnMode::Id);
        d.remark = "备注名".to_string();
        d.challenge = "code-x".to_string();
        let mut v = vec![d];
        normalize_legacy_id_nicknames(&mut v);
        assert_eq!(v[0].remark, "备注名", "用户字段不受归一影响");
        assert_eq!(v[0].challenge, "code-x");

        // ② ID + 用户显式昵称（≠id）→ 原样保留。
        let mut v = vec![r98_device("HD-62EC5BC9", "客厅电脑", "", DeviceConnMode::Id)];
        normalize_legacy_id_nicknames(&mut v);
        assert_eq!(v[0].nickname, "客厅电脑", "② 用户昵称保留");

        // ③ ID + 空昵称 → 保持空（幂等）。
        let mut v = vec![r98_device("HD-62EC5BC9", "", "", DeviceConnMode::Id)];
        normalize_legacy_id_nicknames(&mut v);
        assert_eq!(v[0].nickname, "", "③ 空昵称幂等");

        let mut v = vec![r98_device("HD-62EC5BC9", " HD-62EC5BC9 ", "", DeviceConnMode::Id)];
        normalize_legacy_id_nicknames(&mut v);
        assert_eq!(v[0].nickname, "HD-62EC5BC9", "④ 空白包裹的残留值 trim 保留");
        let mut v = vec![r98_device("HD-62EC5BC9", " 客厅电脑 ", "", DeviceConnMode::Id)];
        normalize_legacy_id_nicknames(&mut v);
        assert_eq!(v[0].nickname, "客厅电脑", "④′ 用户昵称首尾空白 trim");

        // ⑤ IP 模式 nickname==id = 握手凭据（server_id）→ **绝不动**。
        let mut v = vec![r98_device("srv-cred", "srv-cred", "", DeviceConnMode::Ip)];
        normalize_legacy_id_nicknames(&mut v);
        assert_eq!(v[0].nickname, "srv-cred", "⑤ IP 凭据零触碰");

        // ⑥ 旧 Unknown 记录 + domain 空 + 64hex 指纹 id → 启发式 ID 模式 →
        let mut v = vec![r98_device(R98_FP, R98_FP, "", DeviceConnMode::Unknown)];
        normalize_legacy_id_nicknames(&mut v);
        assert_eq!(v[0].nickname, R98_FP, "⑥ 旧指纹 ID 记录原样保留");

        // ⑦ Unknown + 有 domain（DNS 记录，IP 凭据形态）→ 不动。
        let mut v = vec![r98_device("dns-host", "dns-host", "example.com", DeviceConnMode::Unknown)];
        normalize_legacy_id_nicknames(&mut v);
        assert_eq!(v[0].nickname, "dns-host", "⑦ DNS 记录零触碰");

        // ⑧ Unknown + domain 空 + 非指纹 id（自定义 ID）→ 启发式非 ID → 不动
        // （与 ui 回填路由同口径：此类旧记录走 IP 分支，凭据形态保留）。
        let mut v = vec![r98_device("pc-custom", "pc-custom", "", DeviceConnMode::Unknown)];
        normalize_legacy_id_nicknames(&mut v);
        assert_eq!(v[0].nickname, "pc-custom", "⑧ 非指纹自定义 ID 零触碰");
    }

    /// 端到端：旧 devices.json（ID 模式记录 nickname==id 残留 + 空白包裹
    /// trim 空白；内存态，磁盘文件不改写）。
    #[test]
    fn test_r98_load_from_normalizes_legacy_id_nickname() {
        let path = test_dir("r98_load").join("devices_r98_load.json");
        let legacy = vec![
            r98_device("HD-62EC5BC9", "HD-62EC5BC9", "", DeviceConnMode::Id),
            r98_device("HD-77AA88BB", " 客厅电脑 ", "", DeviceConnMode::Id),
            r98_device("srv-cred", "srv-cred", "", DeviceConnMode::Ip),
        ];
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();
        let store = DeviceStore::load_from(&path).unwrap();
        let id_rec = store.devices().iter().find(|d| d.id == "HD-62EC5BC9").unwrap();
        assert_eq!(
            id_rec.nickname, "HD-62EC5BC9",
        );
        let user_rec = store.devices().iter().find(|d| d.id == "HD-77AA88BB").unwrap();
        assert_eq!(user_rec.nickname, "客厅电脑", "用户昵称仅 trim 首尾空白");
        let ip_rec = store.devices().iter().find(|d| d.id == "srv-cred").unwrap();
        assert_eq!(ip_rec.nickname, "srv-cred", "IP 凭据读入后原样保留");
        // 读取点归一不写回磁盘（磁盘仍为旧值；下次 save 自然落新值）。
        let on_disk = fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("\"HD-62EC5BC9\""), "磁盘文件未被读取点归一改写");
        let _ = fs::remove_dir_all(test_dir("r98_load"));
    }


    /// 刷新（连接表单值 = 最后保存意图，「保存什么回填什么」）；② 既有
    /// （CLI/mobile 残留回退）→ 以 ==id 值填空；④ 既有用户值 + 入参 ==id
    /// （残留）→ 保留用户值（同机 CLI/mobile 自动保存不冲掉桌面设置值）；
    /// ⑤ 遗留记录 nickname==id + 入参显式值 → 刷新（用户遗留记录修正点）；
    /// ⑦ 用户字段 remark/challenge/sort_order 恒保留（回归钉）。
    #[test]
    fn test_r101_upsert_id_nickname_merge_matrix() {
        let path = |name: &str| test_dir(name).join("devices_r101.json");
        let mk_existing = |nickname: &str| {
            let mut d = r98_device("HD-62EC5BC9", nickname, "", DeviceConnMode::Id);
            d.remark = "备注名".to_string();
            d.challenge = "code-x".to_string();
            d.sort_order = 3;
            d
        };
        let mk_incoming = |nickname: &str| {
            r98_device("HD-62EC5BC9", nickname, "", DeviceConnMode::Id)
        };

        // ① 既有用户值 + 入参显式值（≠id）→ 刷新。
        let mut store = DeviceStore::load_from(&path("r101_m1")).unwrap();
        store.devices.push(mk_existing("客厅电脑"));
        store.upsert(mk_incoming("书房电脑"));
        assert_eq!(store.devices()[0].nickname, "书房电脑", "① 用户显式值刷新");

        let mut store = DeviceStore::load_from(&path("r101_m2")).unwrap();
        store.devices.push(mk_existing(""));
        store.upsert(mk_incoming("客厅电脑"));
        assert_eq!(store.devices()[0].nickname, "客厅电脑", "② 空槽回填表单值");

        // ③ 既有空 + 入参 ==id（CLI/mobile 残留回退）→ 以 ==id 值填空。
        let mut store = DeviceStore::load_from(&path("r101_m3")).unwrap();
        store.devices.push(mk_existing(""));
        store.upsert(mk_incoming("HD-62EC5BC9"));
        assert_eq!(
            store.devices()[0].nickname, "HD-62EC5BC9",
            "③ ==id 残留填空（回填原样口径下 ==id 为合法保存值）"
        );

        // ④ 既有用户值 + 入参 ==id（残留）→ 保留用户值。
        let mut store = DeviceStore::load_from(&path("r101_m4")).unwrap();
        store.devices.push(mk_existing("客厅电脑"));
        store.upsert(mk_incoming("HD-62EC5BC9"));
        assert_eq!(store.devices()[0].nickname, "客厅电脑", "④ 残留不覆盖已设置值");

        // ⑤ 遗留记录 nickname==id + 入参显式值 → 刷新（用户遗留记录修正点）。
        let mut store = DeviceStore::load_from(&path("r101_m5")).unwrap();
        store.devices.push(mk_existing("HD-62EC5BC9"));
        store.upsert(mk_incoming("客厅电脑"));
        assert_eq!(store.devices()[0].nickname, "客厅电脑", "⑤ 遗留 ==id 记录刷新为显式值");

        let mut store = DeviceStore::load_from(&path("r101_m6")).unwrap();
        let mut existing_ip = r98_device("srv-cred", "old-cred", "", DeviceConnMode::Ip);
        existing_ip.sort_order = 1;
        store.devices.push(existing_ip);
        store.upsert(r98_device("srv-cred", "srv-cred", "", DeviceConnMode::Ip));
        assert_eq!(store.devices()[0].nickname, "srv-cred", "⑥ IP 凭据刷新语义不变");

        // ⑦ 用户字段 remark/challenge/sort_order 恒保留（回归钉）。
        let mut store = DeviceStore::load_from(&path("r101_m7")).unwrap();
        store.devices.push(mk_existing("客厅电脑"));
        store.upsert(mk_incoming("书房电脑"));
        assert_eq!(store.devices()[0].remark, "备注名", "remark 保留");
        assert_eq!(store.devices()[0].challenge, "code-x", "challenge 保留");
        assert_eq!(store.devices()[0].sort_order, 3, "sort_order 不被自动保存打乱");
    }

    /// nickname = 用户显式值 / ==id 残留两种形态落盘 → `load_from` 读回
    /// **原样**（仅 trim）→ 与 `ui::fill_connect_from_device` 纯 clone 回填
    /// （ui 侧 r98 族 ③ 例断言）衔接成「保存什么回填什么」完整链。
    #[test]
    fn test_r101_save_load_roundtrip_nickname_verbatim() {
        let path = test_dir("r101_rt").join("devices_r101_rt.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        store.upsert(r98_device("HD-62EC5BC9", "客厅电脑", "", DeviceConnMode::Id));
        store.upsert(r98_device("HD-11223344", "HD-11223344", "", DeviceConnMode::Id));
        store
            .upsert(r98_device("srv-cred", "srv-cred", "example.com", DeviceConnMode::Ip));
        store.save_to(&path).unwrap();

        let loaded = DeviceStore::load_from(&path).unwrap();
        assert_eq!(
            loaded.devices().iter().find(|d| d.id == "HD-62EC5BC9").unwrap().nickname,
            "客厅电脑",
            "用户显式昵称落盘读回原样"
        );
        assert_eq!(
            loaded.devices().iter().find(|d| d.id == "HD-11223344").unwrap().nickname,
            "HD-11223344",
        );
        assert_eq!(
            loaded.devices().iter().find(|d| d.id == "srv-cred").unwrap().nickname,
            "srv-cred",
            "IP 凭据往返逐位一致"
        );
        let _ = fs::remove_dir_all(test_dir("r101_rt"));
    }


    /// 字段落空串 = 未通告（展示层回退角色徽标）。
    #[test]
    fn test_r137_10b_legacy_json_without_os_type_loads_empty() {
        let dir = test_dir("r137_10b_legacy");
        let path = dir.join("devices_r137_10b_legacy.json");
        let legacy = r#"[
            {"id":"HD-62EC5BC9","nickname":"办公室","ipv6":"2001:db8::1","port":3389,
             "pubkey":"k","device_type":"desktop","last_seen":"2026-09-01T00:00:00Z",
             "domain":"d.com","mode":"id"}
        ]"#;
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, legacy).unwrap();
        let store = DeviceStore::load_from(&path).unwrap();
        assert_eq!(store.devices().len(), 1);
        assert_eq!(store.devices()[0].os_type, "", "无字段 → 空串（未通告）");
        let _ = fs::remove_dir_all(dir);
    }

    /// ① 既有空 + 入参非空 → 落值（新端首次通告）；② 既有值 + 入参新值 →
    /// 刷新（对端升级 OS）；③ 既有值 + 入参空（旧对端未通告）→ **保留既有
    /// 值**（旧对端再连不擦除）；④ 未知值原样落库（展示层回退不猜，本层
    /// 不做域校验拦截 = 通告值如实记录）；⑤ 新建设备全字段含 os_type 原样
    /// 落库。
    #[test]
    fn test_r137_10b_upsert_os_type_merge_matrix() {
        let path = |n: &str| test_dir(n).join("devices_r137_10b.json");
        let with_os = |os: &str| {
            let mut d = sample_device("pc-a", "pc-a", Utc::now());
            d.os_type = os.to_string();
            d
        };

        // ① 既有空 + 入参非空 → 落值。
        let mut store = DeviceStore::load_from(&path("r137_10b_m1")).unwrap();
        store.upsert(sample_device("pc-a", "pc-a", Utc::now()));
        store.upsert(with_os("macos"));
        assert_eq!(store.devices()[0].os_type, "macos", "① 空槽落首次通告值");

        // ② 既有值 + 入参新值 → 刷新。
        let mut store = DeviceStore::load_from(&path("r137_10b_m2")).unwrap();
        store.upsert(with_os("windows-10"));
        store.upsert(with_os("windows-11"));
        assert_eq!(store.devices()[0].os_type, "windows-11", "② 对端 OS 升级刷新");

        // ③ 既有值 + 入参空（旧对端未通告）→ 保留既有值（不擦除）。
        let mut store = DeviceStore::load_from(&path("r137_10b_m3")).unwrap();
        store.upsert(with_os("windows-11"));
        store.upsert(sample_device("pc-a", "pc-a", Utc::now())); // os_type = ""
        assert_eq!(
            store.devices()[0].os_type,
            "windows-11",
            "③ 旧对端空通告不擦除已落库值"
        );

        // ④ 未知值原样落库（域约束在展示层回退，不落库层猜/拒）。
        let mut store = DeviceStore::load_from(&path("r137_10b_m4")).unwrap();
        store.upsert(with_os("freebsd-14"));
        assert_eq!(store.devices()[0].os_type, "freebsd-14", "④ 未知值如实落库");

        // ⑤ 新建设备 os_type 原样落库。
        let mut store = DeviceStore::load_from(&path("r137_10b_m5")).unwrap();
        store.upsert(with_os("linux"));
        assert_eq!(store.devices()[0].os_type, "linux", "⑤ 新建全字段原样");
        for n in ["r137_10b_m1", "r137_10b_m2", "r137_10b_m3", "r137_10b_m4", "r137_10b_m5"] {
            let _ = fs::remove_dir_all(test_dir(n));
        }
    }

    /// 落盘→读回往返（os_type 非空/空两形态均原样）。
    #[test]
    fn test_r137_10b_os_type_roundtrip() {
        let path = test_dir("r137_10b_rt").join("devices_r137_10b_rt.json");
        let mut store = DeviceStore::load_from(&path).unwrap();
        let mut a = sample_device("pc-a", "pc-a", Utc::now());
        a.os_type = "windows-11".to_string();
        store.upsert(a);
        store.upsert(sample_device("pc-b", "pc-b", Utc::now())); // 空通告
        store.save_to(&path).unwrap();

        let loaded = DeviceStore::load_from(&path).unwrap();
        assert_eq!(
            loaded.devices().iter().find(|d| d.id == "pc-a").unwrap().os_type,
            "windows-11",
            "非空值往返原样"
        );
        assert_eq!(
            loaded.devices().iter().find(|d| d.id == "pc-b").unwrap().os_type,
            "",
            "空值往返原样"
        );
        let _ = fs::remove_dir_all(test_dir("r137_10b_rt"));
    }
}
