//! T002: 隧道审计（TNL-SEC-003）。
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
    /// (PUNCH-006): 打洞候选登记受理（含服务器观察地址附加）。
    PunchCandidateRegistered { client: SocketAddr, device_id: String },
    /// (PUNCH-PROTO-003/005/006): 候选互转 / 结果 / 探测透传。
    PunchForwarded { client: SocketAddr, device_id: String },
    /// (PUNCH-SEC-003): 未知 session_id 丢弃。
    PunchUnknownSession { client: SocketAddr, session_id: String },
    /// (ID-001): 设备注册上线（Login 携带 device_id 登记在线表）。
    DeviceRegistered { client: SocketAddr, device_id: String },
    /// (ID-004): 设备注册拒绝（同 ID 不同公钥 → 后到者拒绝）。
    DeviceRejected { client: SocketAddr, device_id: String, reason: String },
    /// (ID-003): 设备离线（控制连接断开 / 心跳超时清理）。
    DeviceOffline { client: SocketAddr, device_id: String },
    /// (ID-010 / ID-SEC-002): 解析受理（online 标记设备是否在线）。
    DeviceResolveAccepted { client: SocketAddr, device_id: String, online: bool },
    /// (ID-SEC-002): 解析限速拒绝（响应仍为统一文案）。
    DeviceResolveRejected { client: SocketAddr, device_id: String, reason: String },
    /// (§8.1): 设备级中继配对成功（双端流开始泵流）。
    TunnelRelayOpened { target: String, from: String, conn_id: u64 },
    /// (§8.1): 设备级中继关闭（任一端断开 / 配对失败）。
    TunnelRelayClosed { target: String, conn_id: u64, reason: String },
    /// S-09（审计 F-9）：候选登记归属校验拒绝 —— 会话为**非自身** device_id
    /// 提交候选（跨设备覆盖/投毒）或会话未注册设备 → 丢弃 + 审计。
    /// detail 含客户端地址、目标 device_id 与原因（`PunchUnknownSession` 风格）。
    CandidateRegisterRejected { client: SocketAddr, device_id: String, reason: String },
    // 凭据零落盘：以下变体只携 device_id/domain/指纹/错误语义，禁 token/
    // 挑战码/密钥材料（集成方映射控制台行时经 escape_control 转义）。
    /// `target_domain` = 被允许发现本设备的目标中继域；`quota_used/limit`
    DirUpserted {
        client: SocketAddr,
        device_id: String,
        target_domain: String,
        domain: String,
        quota_used: usize,
        quota_limit: usize,
    },
    /// (device_id, target_domain)）。
    DirDeleted { client: SocketAddr, device_id: String, target_domain: String },
    /// 显式错误帧，`code` = DirErrorCode v2 冻结字符串，`device_id` = 帧内
    /// 设备 ID 归一形态〔缺帧/解码前失败 = 空串〕）。
    DirWriteRejected {
        client: SocketAddr,
        device_id: String,
        code: String,
        detail: String,
    },
    /// `used/limit` = 配额水位；不清存量，只拒新增）。覆盖两类超限：
    /// 两者 wire 码同为 `quota_exceeded`，审计靠 used/limit 数值与 detail 行区分）。
    DirQuotaRejected {
        client: SocketAddr,
        device_id: String,
        used: usize,
        limit: usize,
    },
    /// 不符 / 签名验败 / 废帧保留位到达等，fail-closed 断连；数据帧阶段的
    /// 推送整批拒收走 [`Self::PushRejected`] 独立行，避免双行）。
    InterconnectRejected { peer: SocketAddr, fp: String, reason: String },
    /// 保留取证 + 重建空库；WARN 级，不静默丢数据）。**机制不变 = 沿用
    DirDbCorruptRebuilt { detail: String },
    /// 结构校验后审计丢弃，不静默忽略（`frame` = 帧类型号）。
    /// 丢弃 + 审计（不按旧语义处理，§5 点位 18）。
    DirFrameDropped { client: SocketAddr, frame: u8 },
    // v1 pull 行族（Peer*/Sync*/DirEntryAdjudicated）随 pull 链拆除（§7）；
    // 凭据零落盘：以下变体只携 domain/fp/计数/错误语义（集成方映射控制台
    // 行时经 escape_control 转义攻击者可控字段，fp 为派生指纹原样）。
    /// 声明式 + 周期重推兜底，§3 T1⑧）。`fp` = 接收方（target）指纹。
    PushOk { target_domain: String, fp: String, entries: usize, epoch: u64 },
    /// 变化，入 outbox 退避重试，§3 T4）。`fp` = 接收方指纹（解析前失败
    PushFailed { target_domain: String, fp: String, reason: String },
    /// §2.3/§5）。`peer` = 推送方域，`fp` = 推送方指纹（DNS-TXT 现场解析
    PushRejected { peer_domain: String, fp: String, reason: String },
    /// applied` 行素材。
    PushApplied { source_fp: String, entries: usize, removed: usize, epoch: u64 },
    PushOutboxEnqueued { target_domain: String },
    PushOutboxPruned { target_domain: String, n: usize, reason: String },
    PushSourceExpired { fp: String, rows: usize },
    DirRowExpired { device_id: String, target_domain: String },
    /// （目标中继无互联 token 转发凭证缓存——fail-closed 不推裸批；outbox
    PushSkippedNoToken { target_domain: String, reason: String },
    /// `ip_quota` 0 = 不限〔同时启动 WARN〕；五参 = 设计 §2.6 冻结默认值面）。
    DirStartupConfig {
        ip_quota: usize,
        repush_interval: u64,
        push_ttl: u64,
        liveness_ttl: u64,
        per_source_cap: usize,
    },
    /// （最小间隔 60s；超频 = 忽略 refresh 臂，**列表照常应答**——节流只
    DirRefreshThrottled { client: SocketAddr },
    // 尾部追加，wire 零改审计内部面）────────────────────────────────────
    /// 整表拉取恒留痕——设备名单外露可见性面，`rows` = 应答条目数）。
    DirListAllQueried { client: SocketAddr, rows: usize },
    /// dir list throttled` 行素材。
    DirListThrottled { client: SocketAddr },
    // 尾部追加，wire 零改审计内部面）────────────────────────────────────
    /// 行、本次写入来自不同键——典型：键 K 配额满 → 换 IP/前缀续灌）。
    /// **告警面零拦截**（裁定口径：维持 500/IP 现值 + 行为可见，不误伤
    /// NAT 群体）。`from_key` = 旧键（多键 `;` 连接），`to_key` = 本次键。
    DirQuotaKeyMigrated {
        client: SocketAddr,
        device_id: String,
        from_key: String,
        to_key: String,
    },
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
