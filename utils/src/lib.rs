//! Utility module: config, logging, error types

// 它都必须经这把共享锁串行（原先锁私有于 config.rs 测试模块，logging 模块
// 单测无锁可用；各模块自持独立锁互不互斥 → 并发测试 env 互染，历史已踩坑，
// 见 config.rs 原锁注记）。
#[cfg(test)]
pub(crate) static KIRIN_DATA_DIR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod audit;
pub mod autostart;
pub mod config;
// M8-T035: DNS 域名维护服务商注册表（Settings → DNS 组动态表单的事实源）。
pub mod dns_providers;
// M8-T031: 系统设备 ID 派生（空配置 → 硬盘 UUID / machine-id / 平台 UUID）。
pub mod device;
pub mod logging;
pub mod error;
pub mod devices;
// S-07 (F-8): 私密文件写入统一入口（0600/0700/O_NOFOLLOW + 原子替换）。
pub mod fsutil;
// 仅 Windows 编译——Unix 走 0600/0700 chmod 语义）。
#[cfg(windows)]
pub mod wacl;
// 共用同一文件——build script 不能依赖本 crate lib；banner commit 冻结修复）。
pub mod git_ref;
pub mod known_hosts;
// SavedDevice.os_type 落库值的域约束 = KNOWN_OS_TYPES 常量集）。
pub mod osinfo;
// M8-T038 (P2): 系统 UI 语言识别（`[ui].language = "system"` 跟随系统用）。
pub mod locale;
// 本批先行实现模块本体与单测；config.rs 字段接线与迁移（R13-S1 后半/S3）
pub mod secure;
