//! M15-T002: 审计日志 — 所有安全事件写入 `~/.kirin_desk/logs/audit.log`。
//!
//! 路径经 `dirs` crate 跨平台解析（复用 `logging::default_log_dir()` 约定，
//! 同 M1-T002 路径解析策略）。每条记录即时追加 + flush，行格式：
//! `2026-08-01T12:00:00.000Z | 事件类型 | 详情`。
//!
//! 事件类型（SRV-SEC-AUDIT-002）：连接请求、握手成功/失败、身份认证、
//! 审批操作、速率限制拒绝、断开。

use chrono::Utc;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::logging::default_log_dir;

/// 审计事件类型（SRV-SEC-AUDIT-002）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEvent {
    /// 连接请求到达。
    ConnectionRequest,
    /// 握手成功（SecureChannel 建立）。
    HandshakeSuccess,
    /// 握手失败（签名/格式/超时等）。
    HandshakeFailure,
    /// 身份认证失败（公钥 pin 不一致、域名未授权等）。
    AuthFailure,
    /// 审批接受。
    ApprovalAccepted,
    /// 审批拒绝。
    ApprovalRejected,
    /// 速率限制拒绝。
    RateLimited,
    /// 连接断开。
    Disconnect,
    /// M8-T019 (PRIV-SEC-001): 隐私模式开启（黑屏/锁屏）。
    /// detail 含等级与发起方，如 `level=black initiator=remote`。
    PrivacyEnabled,
    /// M8-T019 (PRIV-SEC-001): 隐私模式关闭（客户端请求恢复屏幕 / 本地逃生舱）。
    PrivacyDisabled,
    /// M8-T019 (PRIV-SEC-001): 隐私模式降级（Black→Lock）或执行失败。
    PrivacyDegraded,
    /// M8-T019 (PRIV-SEC-001): 断连 / 本地解锁自动恢复。
    PrivacyRecovered,
    /// M8-T020 (SKEY-SEC-002): 特殊键锁屏请求（复用 T019 锁屏调用）。
    /// detail 含来源，如 `ip=... client=... combo=LockScreen`。
    LockScreen,
    /// M8-T017: 临时连接窗口开启（生成临时挑战码）。
    TempModeEnabled,
    /// M8-T017: 临时连接窗口手动关闭。
    TempModeDisabled,
    /// M8-T017: 临时连接窗口过期（倒计时归零/残留状态文件清理）。
    TempModeExpired,
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            AuditEvent::ConnectionRequest => "connection_request",
            AuditEvent::HandshakeSuccess => "handshake_success",
            AuditEvent::HandshakeFailure => "handshake_failure",
            AuditEvent::AuthFailure => "auth_failure",
            AuditEvent::ApprovalAccepted => "approval_accepted",
            AuditEvent::ApprovalRejected => "approval_rejected",
            AuditEvent::RateLimited => "rate_limited",
            AuditEvent::Disconnect => "disconnect",
            AuditEvent::PrivacyEnabled => "privacy_enabled",
            AuditEvent::PrivacyDisabled => "privacy_disabled",
            AuditEvent::PrivacyDegraded => "privacy_degraded",
            AuditEvent::PrivacyRecovered => "privacy_recovered",
            AuditEvent::LockScreen => "lock_screen",
            AuditEvent::TempModeEnabled => "temp_mode_enabled",
            AuditEvent::TempModeDisabled => "temp_mode_disabled",
            AuditEvent::TempModeExpired => "temp_mode_expired",
        };
        f.write_str(s)
    }
}

/// 审计日志写入器（追加模式，即时 flush）。
#[derive(Debug)]
pub struct AuditLogger {
    path: PathBuf,
    file: File,
}

/// 审计日志错误。
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("I/O error at {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("No log directory found")]
    NoLogDir,
}

impl AuditLogger {
    /// 默认审计日志路径: `{home}/.kirin_desk/logs/audit.log`（同 `logging::default_log_dir()`）。
    pub fn default_path() -> PathBuf {
        default_log_dir().join("audit.log")
    }

    /// 打开（创建）默认路径的审计日志。
    pub fn open_default() -> Result<Self, AuditError> {
        Self::open(&Self::default_path())
    }

    /// 打开（创建）指定路径的审计日志（自动创建父目录）。
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AuditError::IoError {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| AuditError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// 记录一条审计事件（追加 + 即时 flush）。
    pub fn record(&mut self, event: AuditEvent, detail: &str) -> Result<(), AuditError> {
        let line = format!(
            "{} | {} | {}\n",
            Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event,
            detail
        );
        self.file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.flush())
            .map_err(|e| AuditError::IoError {
                path: self.path.clone(),
                source: e,
            })
    }

    /// 审计日志路径（测试/展示用）。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_path() -> PathBuf {
        std::env::temp_dir()
            .join("kirin_desk_test_audit")
            .join("audit.log")
    }

    #[test]
    fn test_record_appends_and_flushes() {
        let path = test_path();
        let _ = fs::remove_file(&path);

        let mut logger = AuditLogger::open(&path).unwrap();
        logger.record(AuditEvent::ConnectionRequest, "ip=[::1]").unwrap();
        logger.record(AuditEvent::HandshakeSuccess, "client=pc-a").unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("connection_request"));
        assert!(lines[0].contains("ip=[::1]"));
        assert!(lines[1].contains("handshake_success"));
        assert!(lines[1].contains("client=pc-a"));

        // 追加模式：再次打开不覆盖
        drop(logger);
        let mut logger = AuditLogger::open(&path).unwrap();
        logger.record(AuditEvent::Disconnect, "peer=pc-a").unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 3);

        let _ = fs::remove_dir_all(std::env::temp_dir().join("kirin_desk_test_audit"));
    }

    #[test]
    fn test_record_event_display() {
        assert_eq!(AuditEvent::ConnectionRequest.to_string(), "connection_request");
        assert_eq!(AuditEvent::AuthFailure.to_string(), "auth_failure");
        assert_eq!(AuditEvent::RateLimited.to_string(), "rate_limited");
        // M8-T019 (PRIV-SEC-001): 隐私事件 display。
        assert_eq!(AuditEvent::PrivacyEnabled.to_string(), "privacy_enabled");
        assert_eq!(AuditEvent::PrivacyDisabled.to_string(), "privacy_disabled");
        assert_eq!(AuditEvent::PrivacyDegraded.to_string(), "privacy_degraded");
        assert_eq!(AuditEvent::PrivacyRecovered.to_string(), "privacy_recovered");
        // M8-T017: 临时连接事件 display。
        assert_eq!(AuditEvent::TempModeEnabled.to_string(), "temp_mode_enabled");
        assert_eq!(AuditEvent::TempModeDisabled.to_string(), "temp_mode_disabled");
        assert_eq!(AuditEvent::TempModeExpired.to_string(), "temp_mode_expired");
    }

    #[test]
    fn test_record_privacy_event_with_detail() {
        // 独立路径，避免与 test_record_appends_and_flushes 并行共享文件竞态。
        let path = std::env::temp_dir()
            .join("kirin_desk_test_audit_privacy")
            .join("audit.log");
        let _ = fs::remove_file(&path);

        let mut logger = AuditLogger::open(&path).unwrap();
        logger
            .record(AuditEvent::PrivacyEnabled, "level=black initiator=remote")
            .unwrap();
        logger
            .record(AuditEvent::PrivacyRecovered, "event=disconnect level=black initiator=system")
            .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("privacy_enabled"));
        assert!(lines[0].contains("level=black initiator=remote"));
        assert!(lines[1].contains("privacy_recovered"));

        let _ = fs::remove_dir_all(std::env::temp_dir().join("kirin_desk_test_audit_privacy"));
    }
}
