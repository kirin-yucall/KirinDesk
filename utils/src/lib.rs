//! Utility module: config, logging, error types

pub mod audit;
pub mod autostart;
pub mod config;
pub mod logging;
pub mod error;
pub mod devices;
// S-07 (F-8): 私密文件写入统一入口（0600/0700/O_NOFOLLOW + 原子替换）。
pub mod fsutil;
pub mod known_hosts;
// R-13 (M15-T005): 配置敏感字段加密存储（密文格式/密钥来源分层/脱敏）。
// 本批先行实现模块本体与单测；config.rs 字段接线与迁移（R13-S1 后半/S3）
// 随波次 2 合并后落地（见 task_docs/修复任务/E_安全打磨R-12至R-13.md）。
pub mod secure;
