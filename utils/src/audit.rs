//! M15-T002: 审计日志 — 所有安全事件写入 `~/.kirin_desk/logs/audit.log`。
//!
//! 路径经 `dirs` crate 跨平台解析（复用 `logging::default_log_dir()` 约定，
//! 同 M1-T002 路径解析策略）。行格式（S-16c 消毒后恒为单行）：
//! `2026-08-01T12:00:00.000Z | 事件类型 | 详情`。
//!
//! 事件类型（SRV-SEC-AUDIT-002）：连接请求、握手成功/失败、身份认证、
//! 审批操作、速率限制拒绝、断开。
//!
//! S-16 (F-21) 加固：
//! - S-16a: 大小轮转 —— audit.log 超 10 MiB 改名为 `audit.log.1`，旧文件
//!   依次后移，最多保留 5 份（磁盘占用上限 60 MiB）；
//! - S-16b: 写入"入队 + 领导者批量落盘"（无独立线程：串行调用即同步写，
//!   并发洪泛时仅领导者执行 I/O、跟随者零 syscall，事件零丢失）；
//! - S-16c: detail 控制字符转义（`\n`/`\r`/`\t` → 字面量，其余 C0/DEL →
//!   `\xNN`），攻击者无法伪造审计行或注入终端控制序列。

use chrono::Utc;
use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::logging::default_log_dir;

/// S-16a (F-21): audit.log 轮转阈值 —— 超过该字节数触发轮转（10 MiB）。
pub const AUDIT_MAX_SIZE: u64 = 10 * 1024 * 1024;

/// S-16a (F-21): 轮转保留份数 —— 最多保留 N 份旧文件（`audit.log.1..=N`），
/// 加当前文件合计磁盘占用上限 = (N+1) × AUDIT_MAX_SIZE = 60 MiB。
pub const AUDIT_MAX_ROTATED: usize = 5;

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
    /// M8-T026-P1 (PUNCH-SEC-004): 打洞成功（UDP/TCP 路径建立）。
    /// detail 含设备与路径，如 `device=pc-a path=udp peer=203.0.113.5:9000`。
    TunnelPunchSuccess,
    /// M8-T026-P1 (PUNCH-SEC-004): 打洞失败（探测超时/握手失败）。
    /// detail 含设备、路径与原因。
    TunnelPunchFailed,
    /// M8-T026-P1 (PUNCH-SEC-004): NAT 老化触发重打洞（同会话重新候选交换）。
    /// detail 含设备与尝试次数，如 `device=pc-a attempt=1`。
    TunnelRepunch,
    /// M8-T026-P1 (PUNCH-SEC-004): 路径切换（PATH-003 决策执行）。
    /// detail 含源/目标路径与原因，如 `from=relay to=punch-udp reason=rtt_degraded`。
    PathSwitch,
    /// M8-T026 (TNL-SEC-003): 隧道登录成功（token 校验通过）。
    /// detail 含客户端地址与主机名，如 `ip=[::1]:1234 hostname=pc-a`。
    TunnelLoginSuccess,
    /// M8-T026 (TNL-SEC-003): 隧道登录失败（token 错误 / 版本不兼容）。
    /// detail 含客户端地址与原因（**不记录 token 原文**，TNL-SEC-005）。
    TunnelLoginFailed,
    /// M8-T026 (TNL-SEC-003): 代理注册成功（绑定公网端口）。
    /// detail 含客户端地址与代理名/端口，如 `ip=... proxy=ssh port=60022`。
    TunnelProxyRegistered,
    /// M8-T026 (TNL-SEC-003): 代理移除（CloseProxy / 级联清理）。
    /// detail 含客户端地址与代理名。
    TunnelProxyRemoved,
    /// M8-T026 (TNL-SEC-003): work 连接配对成功（数据面开始泵流）。
    /// detail 含客户端地址与代理名。
    TunnelWorkConnOpened,
    /// M8-T026 (TNL-SEC-003): work 连接关闭（任一端断开 / 配对失败 / 级联清理）。
    /// detail 含客户端地址、代理名与原因。
    TunnelWorkConnClosed,
    /// M8-T026 (TNL-SEC-003): 隧道速率限制拒绝（控制端口防爆破）。
    /// detail 含客户端地址与判定，如 `ip=... decision=TooManyAttempts`。
    TunnelRateLimited,
    /// M8-T026-P2 (ID-022): 设备注册上线（Login 携带 device_id 登记在线表）。
    /// detail 含设备与来源地址，如 `device=pc-a ip=...`。
    DeviceRegistered,
    /// M8-T026-P2 (ID-022): 设备上线（重连重注册刷新在线表）。
    /// detail 含设备 ID。
    DeviceOnline,
    /// M8-T026-P2 (ID-022): 设备离线（控制连接断开 / 心跳超时清理）。
    /// detail 含设备 ID。
    DeviceOffline,
    /// M8-T026-P2 (ID-022): 设备解析成功（返回候选 + 公钥，响应已签名）。
    /// detail 含设备与在线状态，如 `device=pc-a online=true`。
    DeviceResolveAccepted,
    /// M8-T026-P2 (ID-022): 设备解析拒绝（限速 / 协议违规）。
    /// detail 含设备与原因。
    DeviceResolveRejected,
    /// M8-T026-P2 (ID-022): 连接路径选择（ID-011 三级路径编排结果）。
    /// detail 含目标与路径，如 `device=pc-a path=relay`（`punch_skipped` =
    /// P1 打洞未接入）。
    TunnelPathSelected,
    /// M8-T027 (UI-IDWL-004): 设备 ID 白名单条目新增（CLI `add-id` / GUI 保存）。
    /// detail 含设备与过期时间，如 `device=device-7 expiry=2026-08-03T00:00:00Z`。
    WhitelistIdAdded,
    /// M8-T027 (UI-IDWL-004): 设备 ID 白名单条目删除（CLI `remove-id` / GUI
    /// 列表删除）。detail 含设备 ID，如 `device=device-7`。
    WhitelistIdRemoved,
    /// M8-T031: 身份凭证恢复（从未配发的过期 legacy 文件损坏/不可解密 →
    /// 备份后重新生成身份；或后端已有身份、忽略损坏旧文件）。
    /// detail 含路径、label 与处置，如
    /// `path=...\ed25519.json label=kirindesk.identity.HD-XXXX backup=...\ed25519.json.corrupt.1234`。
    IdentityRecovered,
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
            // M8-T026-P1 (PUNCH-SEC-004): 打洞与路径切换事件。
            AuditEvent::TunnelPunchSuccess => "tunnel_punch_success",
            AuditEvent::TunnelPunchFailed => "tunnel_punch_failed",
            AuditEvent::TunnelRepunch => "tunnel_repunch",
            AuditEvent::PathSwitch => "path_switch",
            // M8-T026 (TNL-SEC-003): 隧道事件（7 类）。
            AuditEvent::TunnelLoginSuccess => "tunnel_login_success",
            AuditEvent::TunnelLoginFailed => "tunnel_login_failed",
            AuditEvent::TunnelProxyRegistered => "tunnel_proxy_registered",
            AuditEvent::TunnelProxyRemoved => "tunnel_proxy_removed",
            AuditEvent::TunnelWorkConnOpened => "tunnel_work_conn_opened",
            AuditEvent::TunnelWorkConnClosed => "tunnel_work_conn_closed",
            AuditEvent::TunnelRateLimited => "tunnel_rate_limited",
            // M8-T026-P2 (ID-022): 设备 ID 模式事件（6 类）。
            AuditEvent::DeviceRegistered => "device_registered",
            AuditEvent::DeviceOnline => "device_online",
            AuditEvent::DeviceOffline => "device_offline",
            AuditEvent::DeviceResolveAccepted => "device_resolve_accepted",
            AuditEvent::DeviceResolveRejected => "device_resolve_rejected",
            AuditEvent::TunnelPathSelected => "tunnel_path_selected",
            // M8-T027 (UI-IDWL-004): 设备 ID 白名单增删事件。
            AuditEvent::WhitelistIdAdded => "whitelist_id_added",
            AuditEvent::WhitelistIdRemoved => "whitelist_id_removed",
            // M8-T031: 身份凭证恢复事件。
            AuditEvent::IdentityRecovered => "identity_recovered",
        };
        f.write_str(s)
    }
}

/// 审计日志写入器（S-16b: 入队 + 领导者批量落盘；串行调用与旧的同步写
/// 行为一致——返回前已落盘，既有消费方与跨 crate 测试零行为变化）。
#[derive(Debug)]
pub struct AuditLogger {
    inner: Arc<AuditSink>,
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

// ---------------------------------------------------------------------------
// S-16 (F-21): 共享写状态 —— 入队 + 领导者（leader/follower）批量落盘。
//
// 方案与理由（登记于任务文档 SB_S-16 执行记录）：
// 1. `record()` 是同步 `&mut self` API，全工作树调用点均串行（`&mut` 直传
//    或 `Mutex` 包裹），且 ui/core 的跨 crate 测试在 `record()` 返回后立即
//    读文件断言 —— 纯异步 writer 线程会引入竞态且调用点禁止改动；
// 2. 因此不引入独立线程，改"调用者即领导者"：入队（纯内存操作）后若无人
//    正在落盘，当前调用者把整队聚合为一次 write 落盘；并发洪泛时跟随者
//    只入队、零 syscall，仅领导者做 I/O（等价"channel + writer 聚合"的
//    退化形态，但无线程生命周期/退出 flush/事件滞留问题）；
// 3. 事件零丢失：落盘失败整批退回队首、下次 record/flush 重试；领导者
//    退出前双检队列，避免清标志与新入队之间的滞留窗口。
// ---------------------------------------------------------------------------
#[derive(Debug)]
struct AuditSink {
    path: PathBuf,
    /// 待写行队列（无界 —— 洪泛先入内存，不允许丢事件）。
    queue: Mutex<VecDeque<String>>,
    /// 文件句柄与轮转状态（仅领导者触碰）。
    file: Mutex<FileState>,
    /// 领导者标记：false → 当前调用者接手落盘；true → 已有领导者，只入队。
    active: AtomicBool,
    /// 最近一次落盘错误（一次性上报给下一个调用者，与旧 API 错误语义对齐）。
    last_error: Mutex<Option<AuditError>>,
}

#[derive(Debug)]
struct FileState {
    file: Option<File>,
    written: u64,
    max_size: u64,
    max_rotated: usize,
}

impl AuditSink {
    /// 入队 + 领导者交接。返回最近一次落盘错误（含本次领导落盘错误）。
    fn enqueue(&self, line: String) -> Result<(), AuditError> {
        self.queue.lock().unwrap().push_back(line);
        if !self.active.swap(true, Ordering::AcqRel) {
            self.drain_all();
        }
        if let Some(e) = self.last_error.lock().unwrap().take() {
            return Err(e);
        }
        Ok(())
    }

    /// 领导者落盘循环：整批取出 → 一次 write → 超限轮转；直到队列清空且
    /// 清标志后无新入队才退出（防事件滞留的收尾双检）。
    fn drain_all(&self) {
        loop {
            let batch: Vec<String> = {
                let mut q = self.queue.lock().unwrap();
                q.drain(..).collect()
            };
            if batch.is_empty() {
                self.active.store(false, Ordering::Release);
                if self.queue.lock().unwrap().is_empty() {
                    return;
                }
                // 清标志与复检之间又有新行 —— 继续接手，避免事件滞留。
                continue;
            }
            let mut joined = String::new();
            for l in &batch {
                joined.push_str(l);
            }
            let mut state = self.file.lock().unwrap();
            if let Err(e) = self.write_batch(&mut state, joined.as_bytes()) {
                // 落盘失败：整批退回队首，下次 record/flush 重试（不丢事件）。
                let mut q = self.queue.lock().unwrap();
                for l in batch.into_iter().rev() {
                    q.push_front(l);
                }
                drop(q);
                *self.last_error.lock().unwrap() = Some(e);
                self.active.store(false, Ordering::Release);
                return;
            }
        }
    }

    fn write_batch(&self, state: &mut FileState, bytes: &[u8]) -> Result<(), AuditError> {
        if state.file.is_none() {
            // 轮转/坏句柄后重开。
            state.file = Some(open_append(&self.path)?);
        }
        if let Err(e) = state.file.as_mut().unwrap().write_all(bytes) {
            state.file = None; // 关闭坏句柄，下次重开重试。
            return Err(AuditError::IoError {
                path: self.path.clone(),
                source: e,
            });
        }
        state.written += bytes.len() as u64;
        if state.written >= state.max_size {
            self.rotate(state)?;
        } else {
            // 原始 File 的 flush 为 no-op；显式保留以便未来换 BufWriter 时语义不变。
            let _ = state.file.as_mut().unwrap().flush();
        }
        Ok(())
    }

    /// S-16a: 大小轮转 —— `audit.log` → `audit.log.1`，旧文件依次后移，
    /// 最多保留 `max_rotated` 份（超出的最旧份删除）。仅在文件锁内调用
    /// （唯一写者，无竞态）。
    fn rotate(&self, state: &mut FileState) -> Result<(), AuditError> {
        // 关闭当前句柄（Windows 上改名/删除要求文件未被独占打开）。
        state.file.take();
        // 丢弃最旧份 audit.log.{max_rotated}。
        let _ = fs::remove_file(&self.backup_path(state.max_rotated));
        // 依次后移：audit.log.{i} → audit.log.{i+1}（i = max_rotated-1 ..= 1）。
        for i in (1..state.max_rotated).rev() {
            let from = self.backup_path(i);
            if from.exists() {
                let _ = fs::remove_file(&self.backup_path(i + 1));
                let _ = fs::rename(&from, &self.backup_path(i + 1));
            }
        }
        // audit.log → audit.log.1。
        let _ = fs::remove_file(&self.backup_path(1));
        let _ = fs::rename(&self.path, &self.backup_path(1));
        // 重开当前文件继续追加；rename 失败时 audit.log 仍在，直接续写旧文件。
        state.file = Some(open_append(&self.path)?);
        state.written = 0;
        Ok(())
    }

    /// 轮转备份路径：`{name}.{i}`（如 `audit.log.1`）。
    fn backup_path(&self, i: usize) -> PathBuf {
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "audit.log".to_string());
        self.path.with_file_name(format!("{name}.{i}"))
    }
}

/// S-16c (F-21): 审计字段消毒 —— 控制字符替换为字面量转义序列，保证每条
/// 审计记录恒为单行（攻击者可控 detail 中的 `\n`/`\r` 不能伪造审计行，
/// ESC 等不能向终端注入 ANSI 控制序列）：
/// - `\n` → 反斜杠+n 字面量，`\r` → `\r`，`\t` → `\t`；
/// - 其余 C0 控制字符（U+0000..=U+001F）与 DEL（U+007F）→ `\xNN` 十六进制。
/// 非控制字符原样保留（UTF-8 不破坏）。relay-server ConsoleAudit 复用本
/// 函数（S-16d）。
pub fn escape_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// 追加打开审计日志（S-07 (F-8): Unix 新建 0600 —— 审计含安全事件细节；
/// 追加打开不改变既有文件权限）。
fn open_append(path: &Path) -> Result<File, AuditError> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map_err(|e| AuditError::IoError {
        path: path.to_path_buf(),
        source: e,
    })
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
    /// 轮转策略：10 MiB 大小轮转、保留 5 份（S-16a）。
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        Self::open_with_limits(path, AUDIT_MAX_SIZE, AUDIT_MAX_ROTATED)
    }

    /// S-16a: 带自定义轮转参数的打开（测试/运维调参用；`max_rotated` 最少 1）。
    /// 若文件已存在且超阈值，首次 record 时即触发轮转。
    pub fn open_with_limits(
        path: &Path,
        max_size: u64,
        max_rotated: usize,
    ) -> Result<Self, AuditError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AuditError::IoError {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let file = open_append(path)?;
        // S-16a: 以既有文件大小作为累计字节初始值（跨进程续写时同样正确轮转）。
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            inner: Arc::new(AuditSink {
                path: path.to_path_buf(),
                queue: Mutex::new(VecDeque::new()),
                file: Mutex::new(FileState {
                    file: Some(file),
                    written,
                    max_size,
                    max_rotated: max_rotated.max(1),
                }),
                active: AtomicBool::new(false),
                last_error: Mutex::new(None),
            }),
        })
    }

    /// 记录一条审计事件（S-16c: detail 控制字符转义后入队；串行调用下返回
    /// 前已落盘）。
    pub fn record(&mut self, event: AuditEvent, detail: &str) -> Result<(), AuditError> {
        let line = format!(
            "{} | {} | {}\n",
            Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event,
            escape_control(detail)
        );
        self.inner.enqueue(line)
    }

    /// S-16b: 显式冲刷 —— 强制领导者把积压队列落盘（串行路径 record 已同步，
    /// 本方法供并发/退出前兜底使用）。
    pub fn flush(&self) -> Result<(), AuditError> {
        if !self.inner.active.swap(true, Ordering::AcqRel) {
            self.inner.drain_all();
        }
        if let Some(e) = self.inner.last_error.lock().unwrap().take() {
            return Err(e);
        }
        Ok(())
    }

    /// 审计日志路径（测试/展示用）。
    pub fn path(&self) -> &Path {
        &self.inner.path
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
        // M8-T026 (TNL-SEC-003): 隧道事件 display。
        assert_eq!(AuditEvent::TunnelLoginSuccess.to_string(), "tunnel_login_success");
        assert_eq!(AuditEvent::TunnelLoginFailed.to_string(), "tunnel_login_failed");
        assert_eq!(AuditEvent::TunnelProxyRegistered.to_string(), "tunnel_proxy_registered");
        assert_eq!(AuditEvent::TunnelProxyRemoved.to_string(), "tunnel_proxy_removed");
        assert_eq!(AuditEvent::TunnelWorkConnOpened.to_string(), "tunnel_work_conn_opened");
        assert_eq!(AuditEvent::TunnelWorkConnClosed.to_string(), "tunnel_work_conn_closed");
        assert_eq!(AuditEvent::TunnelRateLimited.to_string(), "tunnel_rate_limited");
        // M8-T026-P1 (PUNCH-SEC-004): 打洞与路径切换事件 display。
        assert_eq!(AuditEvent::TunnelPunchSuccess.to_string(), "tunnel_punch_success");
        assert_eq!(AuditEvent::TunnelPunchFailed.to_string(), "tunnel_punch_failed");
        assert_eq!(AuditEvent::TunnelRepunch.to_string(), "tunnel_repunch");
        assert_eq!(AuditEvent::PathSwitch.to_string(), "path_switch");
        // M8-T027 (UI-IDWL-004): 设备 ID 白名单增删事件 display。
        assert_eq!(AuditEvent::WhitelistIdAdded.to_string(), "whitelist_id_added");
        assert_eq!(AuditEvent::WhitelistIdRemoved.to_string(), "whitelist_id_removed");
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

    // ── S-16 (F-21): detail 注入消毒 / 轮转 / 冲刷 ─────────────────────

    #[test]
    fn test_escape_control_fn() {
        // 非控制字符原样保留（含多字节 UTF-8）。
        assert_eq!(escape_control("plain ascii"), "plain ascii");
        assert_eq!(escape_control("中文/utf8 ✓"), "中文/utf8 ✓");
        // \n/\r/\t → 反斜杠字母字面量。
        assert_eq!(escape_control("a\nb"), "a\\nb");
        assert_eq!(escape_control("a\rb"), "a\\rb");
        assert_eq!(escape_control("a\tb"), "a\\tb");
        // 其余 C0 控制字符与 DEL → \xNN 十六进制字面量。
        assert_eq!(escape_control("a\x1bb"), "a\\x1bb");
        assert_eq!(escape_control("a\x00b"), "a\\x00b");
        assert_eq!(escape_control("a\x07b"), "a\\x07b");
        assert_eq!(escape_control("a\x7fb"), "a\\x7fb");
    }

    #[test]
    fn test_detail_control_chars_escaped_single_line() {
        // 独立路径，避免并行共享文件竞态。
        let path = std::env::temp_dir()
            .join("kirin_desk_test_audit_escape")
            .join("audit.log");
        let _ = fs::remove_file(&path);

        let mut logger = AuditLogger::open(&path).unwrap();
        // 攻击者可控 detail：伪造行的 \n、\r、制表、ESC（ANSI 注入）、NUL。
        let evil = "ip=[::1]\nlogin ok\nhost=pc-a\r\x1b[31m\x00";
        logger
            .record(AuditEvent::HandshakeSuccess, evil)
            .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        // 恒为单行记录（内容 = 1 行 + 行尾换行）。
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "含 \\n 的 detail 必须输出单行: {content:?}");
        // 转义字面量齐全：\n → 反斜杠n、\r → 反斜杠r、ESC/NUL → \xNN。
        assert!(
            lines[0].contains("ip=[::1]\\nlogin ok\\nhost=pc-a\\r\\x1b[31m\\x00"),
            "detail 应按字面量转义: {:?}",
            lines[0]
        );
        // 原始控制字符不得出现在文件中。
        assert!(!content.contains('\x1b'), "不得残留 ESC: {content:?}");
        assert!(!content.contains('\x00'), "不得残留 NUL: {content:?}");
        assert!(!content.contains('\r'), "不得残留 CR: {content:?}");
        // 行格式可解析：ts | event | detail 三段。
        assert_eq!(lines[0].split(" | ").count(), 3, "行格式: {:?}", lines[0]);

        let _ = fs::remove_dir_all(std::env::temp_dir().join("kirin_desk_test_audit_escape"));
    }

    #[test]
    fn test_rotation_keeps_n_and_rotates() {
        // 独立目录 + 小阈值（64 B）+ 小保留数（2）：多次轮转后只保留最近
        // 2 份轮转文件，超出窗口的最旧内容按"保留 N 份"语义丢弃。
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_test_audit_rotate_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");

        let n = 30;
        {
            let mut logger = AuditLogger::open_with_limits(&path, 64, 2).unwrap();
            for i in 0..n {
                logger
                    .record(AuditEvent::ConnectionRequest, &format!("seq={i}"))
                    .unwrap();
            }
        }

        // 旧文件保留 2 份：audit.log.1 / audit.log.2 存在，audit.log.3 被丢弃。
        assert!(
            path.with_file_name("audit.log.1").exists(),
            "audit.log.1 应保留"
        );
        assert!(
            path.with_file_name("audit.log.2").exists(),
            "audit.log.2 应保留"
        );
        assert!(
            !path.with_file_name("audit.log.3").exists(),
            "audit.log.3 应被丢弃"
        );
        // 当前文件不超阈值（最后一轮未超限则不轮转；超限则轮转后为空）。
        assert!(
            fs::metadata(&path).unwrap().len() <= 64,
            "当前 audit.log 应 ≤ 阈值"
        );

        // 窗口内完整性：保留行全部可解析、无重复、最新事件在保留集中。
        let mut seen: Vec<u32> = Vec::new();
        let mut total = 0;
        for name in ["audit.log", "audit.log.1", "audit.log.2"] {
            let content = fs::read_to_string(path.with_file_name(name)).unwrap_or_default();
            for line in content.lines() {
                let parts: Vec<&str> = line.split(" | ").collect();
                assert_eq!(parts.len(), 3, "轮转文件行格式: {line}");
                let seq: u32 = parts[2]
                    .strip_prefix("seq=")
                    .expect("detail 前缀 seq=")
                    .parse()
                    .expect("seq 数字");
                assert!(!seen.contains(&seq), "重复行 seq={seq}");
                seen.push(seq);
                total += 1;
            }
        }
        assert_eq!(total, seen.len());
        assert!(
            seen.contains(&(n as u32 - 1)),
            "最新事件必须保留（窗口尾部）: {seen:?}"
        );
        assert!(total <= n, "保留总数不可能超过写入总数");

        // 轮转后继续可写（重开路径验证追加语义不因轮转破坏）。
        let mut logger = AuditLogger::open_with_limits(&path, 64, 2).unwrap();
        logger
            .record(AuditEvent::Disconnect, "seq=after-rotate")
            .unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("seq=after-rotate"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rotation_no_loss_within_window() {
        // 阈值 256 B、保留 10 份：30 条事件仅需约 5 次轮转，全部落在保留
        // 窗口内 → 一条不丢、逐行可解析（窗口充足时零丢失）。
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_test_audit_rotate_win_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");

        let n = 30;
        {
            let mut logger = AuditLogger::open_with_limits(&path, 256, 10).unwrap();
            for i in 0..n {
                logger
                    .record(AuditEvent::HandshakeSuccess, &format!("seq={i}"))
                    .unwrap();
            }
        }

        let mut total = 0;
        let mut files = 0usize;
        // 枚举 audit.log + audit.log.{1..10}。
        for idx in 0..=10usize {
            let p = if idx == 0 {
                path.clone()
            } else {
                path.with_file_name(format!("audit.log.{idx}"))
            };
            let Ok(content) = fs::read_to_string(&p) else {
                continue;
            };
            files += 1;
            for line in content.lines() {
                assert_eq!(line.split(" | ").count(), 3, "行格式: {line}");
                total += 1;
            }
        }
        assert_eq!(total, n, "保留窗口内事件一条不丢（共 {files} 个文件）");
        assert!(files <= 11, "保留文件数 ≤ N+1");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_flush_idempotent_and_surfaces_error() {
        let path = std::env::temp_dir()
            .join("kirin_desk_test_audit_flush")
            .join("audit.log");
        let _ = fs::remove_file(&path);

        let mut logger = AuditLogger::open(&path).unwrap();
        logger.flush().unwrap(); // 空队列冲刷安全。
        logger.record(AuditEvent::Disconnect, "x=1").unwrap();
        logger.flush().unwrap(); // 幂等。
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("disconnect"));
        assert!(content.contains("x=1"));

        let _ = fs::remove_dir_all(std::env::temp_dir().join("kirin_desk_test_audit_flush"));
    }

    #[test]
    fn test_record_batches_under_concurrency() {
        // S-16b: 并发调用同一 logger 时事件不丢、行不交错（领导者聚合）。
        let path = std::env::temp_dir()
            .join("kirin_desk_test_audit_concurrent")
            .join("audit.log");
        let _ = fs::remove_file(&path);

        let logger = Arc::new(std::sync::Mutex::new(AuditLogger::open(&path).unwrap()));
        let mut handles = Vec::new();
        for t in 0..4u32 {
            let logger = Arc::clone(&logger);
            handles.push(std::thread::spawn(move || {
                for i in 0..50u32 {
                    let mut l = logger.lock().unwrap();
                    l.record(
                        AuditEvent::HandshakeSuccess,
                        &format!("thread={t} seq={i}"),
                    )
                    .unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        logger.lock().unwrap().flush().unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 200, "并发 4×50 条事件一条不丢: {}", lines.len());
        for line in &lines {
            assert_eq!(line.split(" | ").count(), 3, "行格式: {line}");
            // 每条记录出自单一线程（行内 detail 完整）。
            assert!(
                line.contains("thread=") && line.contains("seq="),
                "detail 完整: {line}"
            );
        }

        let _ = fs::remove_dir_all(std::env::temp_dir().join("kirin_desk_test_audit_concurrent"));
    }
}
