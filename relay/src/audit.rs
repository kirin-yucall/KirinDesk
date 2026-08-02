//! M8-T026 T002: 隧道审计（TNL-SEC-003）。
//!
//! relay 保持零 `core`/`utils` 依赖（TNL-NF-004），因此审计通过注入的
//! [`AuditSink`] 回调对外暴露；集成方（如 CLI `tunnel serve`）把事件映射到
//! `utils/src/audit.rs` 的 `AuditEvent`（Tunnel* 系列变体）落盘。
//!
//! 事件对齐 TNL-SEC-003 的 7 个变体，detail 含客户端地址与代理名。

use std::net::SocketAddr;

/// 隧道审计事件（对齐 TNL-SEC-003）。
#[derive(Debug, Clone)]
pub enum TunnelAuditEvent {
    /// 登录成功（token 校验通过）。
    LoginSuccess { client: SocketAddr, hostname: String },
    /// 登录失败（token 错误 / 版本不兼容 / 协议违规）。
    LoginFailed { client: SocketAddr, reason: String },
    /// 代理注册成功（绑定公网端口）。
    ProxyRegistered { client: SocketAddr, name: String, port: u16 },
    /// 代理移除（CloseProxy / 级联清理）。
    ProxyRemoved { client: SocketAddr, name: String },
    /// work 连接配对成功（数据面开始泵流）。
    WorkConnOpened { client: SocketAddr, name: String },
    /// work 连接关闭（任一端断开 / 配对失败 / 级联清理）。
    WorkConnClosed { client: SocketAddr, name: String, reason: String },
    /// 速率限制拒绝（TNL-SEC-002）。
    RateLimited { client: SocketAddr, reason: String },
    /// M8-T026-P1 (PUNCH-006): 打洞候选登记受理（含服务器观察地址附加）。
    PunchCandidateRegistered { client: SocketAddr, device_id: String },
    /// M8-T026-P1 (PUNCH-PROTO-003/005/006): 候选互转 / 结果 / 探测透传。
    PunchForwarded { client: SocketAddr, device_id: String },
    /// M8-T026-P1 (PUNCH-SEC-003): 未知 session_id 丢弃。
    PunchUnknownSession { client: SocketAddr, session_id: String },
    /// M8-T026-P2 (ID-001): 设备注册上线（Login 携带 device_id 登记在线表）。
    DeviceRegistered { client: SocketAddr, device_id: String },
    /// M8-T026-P2 (ID-004): 设备注册拒绝（同 ID 不同公钥 → 后到者拒绝）。
    DeviceRejected { client: SocketAddr, device_id: String, reason: String },
    /// M8-T026-P2 (ID-003): 设备离线（控制连接断开 / 心跳超时清理）。
    DeviceOffline { client: SocketAddr, device_id: String },
    /// M8-T026-P2 (ID-010 / ID-SEC-002): 解析受理（online 标记设备是否在线）。
    DeviceResolveAccepted { client: SocketAddr, device_id: String, online: bool },
    /// M8-T026-P2 (ID-SEC-002): 解析限速拒绝（响应仍为统一文案）。
    DeviceResolveRejected { client: SocketAddr, device_id: String, reason: String },
    /// M8-T026-P2 (§8.1): 设备级中继配对成功（双端流开始泵流）。
    TunnelRelayOpened { target: String, from: String, conn_id: u64 },
    /// M8-T026-P2 (§8.1): 设备级中继关闭（任一端断开 / 配对失败）。
    TunnelRelayClosed { target: String, conn_id: u64, reason: String },
    /// S-09（审计 F-9）：候选登记归属校验拒绝 —— 会话为**非自身** device_id
    /// 提交候选（跨设备覆盖/投毒）或会话未注册设备 → 丢弃 + 审计。
    /// detail 含客户端地址、目标 device_id 与原因（`PunchUnknownSession` 风格）。
    CandidateRegisterRejected { client: SocketAddr, device_id: String, reason: String },
}

/// 审计回调（可注入；`None` = 不记录）。
/// `Debug` 为 supertrait，便于含审计引用的配置结构 derive `Debug`。
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    fn record(&self, event: TunnelAuditEvent);
}

/// 空审计（默认，丢弃全部事件）。
#[derive(Debug)]
pub struct NoopAudit;

impl AuditSink for NoopAudit {
    fn record(&self, _event: TunnelAuditEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct Collect(Mutex<Vec<TunnelAuditEvent>>);

    impl AuditSink for Collect {
        fn record(&self, event: TunnelAuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[test]
    fn test_sink_invocation() {
        let sink = Arc::new(Collect::default());
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        sink.record(TunnelAuditEvent::LoginSuccess {
            client: addr,
            hostname: "pc-a".into(),
        });
        sink.record(TunnelAuditEvent::RateLimited {
            client: addr,
            reason: "TooManyAttempts".into(),
        });
        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], TunnelAuditEvent::LoginSuccess { .. }));
    }
}
