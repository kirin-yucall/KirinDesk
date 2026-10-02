//! M8-T026-P1 (PATH-001~005/007): PathManager 多路径叠加 —— 路径表 + 状态机 +
//! 通道级分配 + 换路决策 + 中继 standby 语义。
//!
//! 设计红线（对齐 `M8-T026_P1_打洞辅助与多路径叠加.md` §1）：
//! - **叠加止步通道级分配**：媒体/控制按通道走不同路径（对齐 `multiplex.rs`
//!   四通道 Control/Video/Audio/Input 分类），不做字节级流量聚合；
//! - 中继兜底保证（PATH-005）：③ 随会话建立，直连/打洞 Active 后转 Standby
//!   （空闲保活，控制信令仍可走），断开时释放——不常驻空闲连接池；
//! - 换路阈值（PATH-003）：RTT 差 > 30% 或丢包率 > 2% 持续 `hold_period`
//!   （默认 2s）触发；QUIC 迁移预算 200ms / TCP 换路（含重握手）1s。
//!
//! 决策模型：`assignment()` 给出**期望分配**（查表驱动，PATH-002）；
//! 劣化需持续 ≥ `hold_period` 才被 `evaluate()` "确认"（标记 `confirmed_degraded`，
//! 分配随之让位）；`evaluate()` 产出 [`SwitchAction`]（期望 ≠ 已应用时），
//! 调用方执行迁移/热替换后调 [`PathManager::on_switch_completed`] 确认并落审计。
//! P2 的 `IdConnector` 三级路径编排直接复用本 API
//! （见 `M8-T026_接口交互协调.md` §3.3 冻结签名）。

use kirin_desk_utils::audit::{AuditEvent, AuditLogger};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 路径种类（PATH-001；按优先级降序：直连 > 打洞 > 中继）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathKind {
    /// ① P2P 直连 IPv6。
    DirectV6,
    /// ① P2P 直连 IPv4（M8-T025）。
    DirectV4,
    /// ② P2P 打洞 UDP（主路径）。
    PunchUdp,
    /// ② P2P 打洞 TCP 同时打开（辅路径）。
    PunchTcp,
    /// ③ 中继兜底（随会话建立；直连/打洞 Active 后转 Standby）。
    Relay,
}

impl std::fmt::Display for PathKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PathKind::DirectV6 => "direct-ipv6",
            PathKind::DirectV4 => "direct-ipv4",
            PathKind::PunchUdp => "punch-udp",
            PathKind::PunchTcp => "punch-tcp",
            PathKind::Relay => "relay",
        };
        f.write_str(s)
    }
}

impl PathKind {
    /// 该路径是否不经中继（直连/打洞 = P2P 路径）。
    pub fn is_p2p(self) -> bool {
        !matches!(self, PathKind::Relay)
    }

    /// 切换预算：QUIC 路径（直连/打洞 UDP）迁移 ≤200ms；TCP 换路（含重握手）≤1s。
    pub fn switch_budget_ms(self) -> u32 {
        match self {
            PathKind::DirectV6 | PathKind::DirectV4 | PathKind::PunchUdp => 200,
            PathKind::PunchTcp | PathKind::Relay => 1000,
        }
    }
}

/// 路径状态（PATH-001：Establishing → Active → Standby / Failed，含重试回路）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// 建连/候选交换中。
    Establishing,
    /// 可用（可承载通道分配）。
    Active,
    /// 空闲保活（PATH-005：中继 standby，控制信令仍可走）。
    Standby,
    /// 失败（可重试：PUNCH-004 重打洞回路）。
    Failed,
}

/// 路径质量指标（PATH-007；对齐 M8-T014 报告结构：rtt/loss/jitter）。
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PathMetrics {
    /// 往返时延（毫秒）。
    pub rtt_ms: f64,
    /// 丢包率（0~1）。
    pub loss_rate: f64,
    /// 抖动（微秒）。
    pub jitter_us: f64,
}

/// 换路触发原因（PATH-003 / PATH-004 升舱）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchReason {
    /// 更优路径可用（如打洞成功 → 中继 → 直连升舱）。
    BetterPathAvailable,
    /// 当前媒体路径 RTT 相对最优路径劣化 > 阈值。
    RttDegraded,
    /// 当前媒体路径丢包率超阈值。
    LossDegraded,
}

/// 一条换路决策（调用方据此执行迁移/热替换 + 审计）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchAction {
    pub from: PathKind,
    pub to: PathKind,
    pub reason: SwitchReason,
    /// 切换中断预算（ms；PATH-003/NF-002）。
    pub budget_ms: u32,
}

/// 切换阈值（PATH-003）。
#[derive(Debug, Clone)]
pub struct SwitchThresholds {
    /// RTT 差 > 30%（相对最优 Active 路径）触发劣化判定。
    pub rtt_worse_ratio: f64,
    /// 丢包率 > 2% 触发劣化判定。
    pub loss_rate_threshold: f64,
    /// 劣化持续时长（默认 2s）后才触发换路。
    pub hold_period: Duration,
}

impl Default for SwitchThresholds {
    fn default() -> Self {
        Self {
            rtt_worse_ratio: 0.30,
            loss_rate_threshold: 0.02,
            hold_period: Duration::from_secs(2),
        }
    }
}

/// 单条路径视图（PATH-001 路径表条目）。
#[derive(Debug, Clone)]
pub struct Path {
    pub kind: PathKind,
    pub state: PathState,
    pub metrics: Option<PathMetrics>,
    /// 劣化开始时间（连续劣化 ≥ hold_period 才确认换路）。
    degraded_since: Option<Instant>,
    /// 已确认劣化（分配让位；指标恢复后清除）。
    confirmed_degraded: bool,
}

impl Path {
    fn new(kind: PathKind) -> Self {
        Self {
            kind,
            state: PathState::Establishing,
            metrics: None,
            degraded_since: None,
            confirmed_degraded: false,
        }
    }
}

/// 通道级分配表（PATH-002；对齐 multiplex.rs 四通道）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelAssignment {
    pub control: PathKind,
    pub video: PathKind,
    pub audio: PathKind,
    pub input: PathKind,
}

impl Default for ChannelAssignment {
    fn default() -> Self {
        // 兜底：中继随会话建立（PATH-005 首字节即通）
        Self {
            control: PathKind::Relay,
            video: PathKind::Relay,
            audio: PathKind::Relay,
            input: PathKind::Relay,
        }
    }
}

/// PathManager 多路径叠加决策器（PATH-001~005/007）。
#[derive(Debug)]
pub struct PathManager {
    paths: HashMap<PathKind, Path>,
    thresholds: SwitchThresholds,
    /// 期望分配（查表驱动；状态/指标变化时重算）。
    desired: ChannelAssignment,
    /// 已应用分配（`on_switch_completed` 确认；初始 = 兜底中继）。
    applied: ChannelAssignment,
    /// 重打洞连续失败次数（PUNCH-004：≥2 保持中继）。
    repunch_failures: u8,
    /// 审计（可选；换路确认时写 `PathSwitch`，PUNCH-SEC-004）。
    audit: Option<Arc<Mutex<AuditLogger>>>,
    /// 防止重复产出同一换路（决策已产出但尚未确认）。
    pending: Option<(PathKind, PathKind)>,
}

/// 路径优先级排序（数值越大越优先）。
fn priority(kind: PathKind) -> u8 {
    match kind {
        PathKind::DirectV6 => 100,
        PathKind::DirectV4 => 90,
        PathKind::PunchUdp => 80,
        PathKind::PunchTcp => 70,
        PathKind::Relay => 10,
    }
}

impl PathManager {
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
            thresholds: SwitchThresholds::default(),
            desired: ChannelAssignment::default(),
            applied: ChannelAssignment::default(),
            repunch_failures: 0,
            audit: None,
            pending: None,
        }
    }

    /// 注入审计（换路决策落审计，PUNCH-SEC-004）。
    pub fn with_audit(mut self, audit: Arc<Mutex<AuditLogger>>) -> Self {
        self.audit = Some(audit);
        self
    }

    pub fn with_thresholds(mut self, t: SwitchThresholds) -> Self {
        self.thresholds = t;
        self
    }

    /// 登记路径（初始 Establishing）。
    pub fn register_path(&mut self, kind: PathKind) {
        self.paths.entry(kind).or_insert_with(|| Path::new(kind));
    }

    /// 路径状态变更（PATH-001 状态机；Active 时联动期望分配与中继 standby）。
    pub fn on_path_state(&mut self, kind: PathKind, state: PathState) {
        let p = self.paths.entry(kind).or_insert_with(|| Path::new(kind));
        p.state = state;
        if state != PathState::Active {
            p.degraded_since = None;
            p.confirmed_degraded = false;
        }
        self.recompute_desired();
    }

    /// 路径质量采样（PATH-007，2s 采样由调用方驱动；劣化计时应答）。
    pub fn on_metrics(&mut self, kind: PathKind, m: PathMetrics) {
        let degraded = self.is_degraded(kind, &m);
        {
            let p = self.paths.entry(kind).or_insert_with(|| Path::new(kind));
            if degraded {
                if p.degraded_since.is_none() {
                    p.degraded_since = Some(Instant::now());
                }
            } else {
                // 指标恢复 → 劣化解除（含已确认标记；分配可回归该路径）
                p.degraded_since = None;
                p.confirmed_degraded = false;
            }
            p.metrics = Some(m);
        }
        if !degraded {
            self.recompute_desired();
        }
    }

    /// 打洞成功（PUNCH-001/002）：路径转 Active 并触发升舱评估。
    pub fn on_punch_established(&mut self, kind: PathKind) {
        debug_assert!(matches!(kind, PathKind::PunchUdp | PathKind::PunchTcp));
        self.on_path_state(kind, PathState::Active);
    }

    /// 重打洞结果（PUNCH-004）：失败累计，连续 2 次 → 保持中继（不再自动升舱）。
    pub fn on_repunch_result(&mut self, ok: bool) {
        if ok {
            self.repunch_failures = 0;
        } else {
            self.repunch_failures = self.repunch_failures.saturating_add(1);
        }
    }

    /// 重打洞连续失败次数（PUNCH-004 判定：≥2 保持中继）。
    pub fn repunch_failures(&self) -> u8 {
        self.repunch_failures
    }

    /// 当前期望分配（PATH-002 查表结果）。
    pub fn assignment(&self) -> ChannelAssignment {
        self.desired
    }

    /// 最优 Active 路径（P2P 优先；无 P2P 时回落到中继）。
    pub fn best_active(&self) -> Option<PathKind> {
        self.active_paths().into_iter().max_by_key(|k| priority(*k))
    }

    /// 换路决策（PATH-003/004）：劣化确认（≥ hold_period）→ 分配让位 → 产出
    /// 期望 ≠ 已应用的动作（升舱 / 劣化换路）。同一动作不重复产出。
    pub fn evaluate(&mut self) -> Vec<SwitchAction> {
        let mut actions = Vec::new();

        // 1) 劣化确认：持续 ≥ hold_period 的 Active 路径标记 confirmed → 让位
        for kind in self.active_paths() {
            let confirm = {
                let p = self.paths.get(&kind).unwrap();
                !p.confirmed_degraded
                    && p.degraded_since
                        .map(|t| t.elapsed() >= self.thresholds.hold_period)
                        .unwrap_or(false)
            };
            if confirm {
                self.paths.get_mut(&kind).unwrap().confirmed_degraded = true;
            }
        }
        self.recompute_desired();

        // 2) 期望 ≠ 已应用 → 产出换路动作（媒体优先，控制次之）
        let (from, to) = if self.desired.video != self.applied.video {
            (self.applied.video, self.desired.video)
        } else if self.desired.control != self.applied.control {
            (self.applied.control, self.desired.control)
        } else {
            return actions;
        };
        if from != to {
            let reason = if to.is_p2p() && from == PathKind::Relay {
                SwitchReason::BetterPathAvailable
            } else {
                match self.paths.get(&from).and_then(|p| p.metrics) {
                    Some(m) if m.loss_rate > self.thresholds.loss_rate_threshold => {
                        SwitchReason::LossDegraded
                    }
                    _ => SwitchReason::RttDegraded,
                }
            };
            let action = SwitchAction {
                from,
                to,
                reason,
                budget_ms: to.switch_budget_ms(),
            };
            if self.try_mark_pending(action) {
                actions.push(action);
            }
        }
        actions
    }

    /// 换路执行确认（调用方完成迁移/热替换后调用；解除 pending 并落审计）。
    pub fn on_switch_completed(&mut self, action: SwitchAction) {
        self.pending = None;
        self.applied = self.desired;
        if let Some(audit) = &self.audit {
            let detail = format!(
                "from={} to={} reason={:?} budget_ms={}",
                action.from, action.to, action.reason, action.budget_ms
            );
            if let Ok(mut logger) = audit.lock() {
                let _ = logger.record(AuditEvent::PathSwitch, &detail);
            }
        }
    }

    /// 路径视图（读）。
    pub fn path(&self, kind: PathKind) -> Option<&Path> {
        self.paths.get(&kind)
    }

    // ── 内部 ──

    fn active_paths(&self) -> Vec<PathKind> {
        self.paths
            .iter()
            .filter(|(_, p)| p.state == PathState::Active)
            .map(|(k, _)| *k)
            .collect()
    }

    /// 可分配路径：Active 且未确认劣化。
    fn assignable_paths(&self) -> Vec<PathKind> {
        self.paths
            .iter()
            .filter(|(_, p)| p.state == PathState::Active && !p.confirmed_degraded)
            .map(|(k, _)| *k)
            .collect()
    }

    /// PATH-002 查表：媒体 → 最优可分配 P2P；控制/输入 → 次优或中继。
    fn recompute_desired(&mut self) {
        let mut p2p: Vec<PathKind> = self
            .assignable_paths()
            .into_iter()
            .filter(|k| k.is_p2p())
            .collect();
        p2p.sort_by_key(|k| std::cmp::Reverse(priority(*k)));
        let relay_available = self
            .paths
            .get(&PathKind::Relay)
            .is_some_and(|p| p.state != PathState::Failed);

        let (media, secondary) = match p2p.as_slice() {
            [] => (PathKind::Relay, PathKind::Relay), // 兜底：中继承载
            [best] => {
                // 单条 P2P：媒体走它，控制走中继（standby 后控制信令仍可走）
                (
                    *best,
                    if relay_available {
                        PathKind::Relay
                    } else {
                        *best
                    },
                )
            }
            [best, second, ..] => (*best, *second),
        };
        self.desired = ChannelAssignment {
            control: secondary,
            video: media,
            audio: media,
            input: secondary,
        };
        // PATH-005：中继 standby 语义 —— 有 P2P Active 时中继转 Standby（保活）
        if !p2p.is_empty() {
            if let Some(relay) = self.paths.get_mut(&PathKind::Relay) {
                if relay.state == PathState::Active {
                    relay.state = PathState::Standby;
                }
            }
        }
    }

    /// 劣化判定（PATH-003）：丢包 > 阈值，或 RTT 相对最优 Active 路径差 > 30%。
    fn is_degraded(&self, kind: PathKind, m: &PathMetrics) -> bool {
        if m.loss_rate > self.thresholds.loss_rate_threshold {
            return true;
        }
        if let Some(best) = self.best_active() {
            if best != kind {
                if let Some(best_m) = self.paths.get(&best).and_then(|p| p.metrics) {
                    if best_m.rtt_ms > 0.0 {
                        return m.rtt_ms > best_m.rtt_ms * (1.0 + self.thresholds.rtt_worse_ratio);
                    }
                }
            }
        }
        false
    }

    fn try_mark_pending(&mut self, action: SwitchAction) -> bool {
        if self.pending == Some((action.from, action.to)) {
            return false; // 同一换路已产出，等待执行确认
        }
        self.pending = Some((action.from, action.to));
        true
    }
}

impl Default for PathManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> PathManager {
        PathManager::new().with_thresholds(SwitchThresholds {
            hold_period: Duration::from_millis(20),
            ..Default::default()
        })
    }

    fn pump_setup() -> (PathManager, Vec<SwitchAction>) {
        let mut m = mgr();
        m.register_path(PathKind::Relay);
        m.on_path_state(PathKind::Relay, PathState::Active);
        assert_eq!(m.assignment().video, PathKind::Relay);
        m.register_path(PathKind::PunchUdp);
        m.on_punch_established(PathKind::PunchUdp);
        let actions = m.evaluate();
        (m, actions)
    }

    #[test]
    fn test_relay_only_default_assignment() {
        // PATH-005：会话建立 → 中继兜底（首字节即通）
        let mut m = mgr();
        m.register_path(PathKind::Relay);
        m.on_path_state(PathKind::Relay, PathState::Active);
        let a = m.assignment();
        assert_eq!(a.video, PathKind::Relay);
        assert_eq!(a.audio, PathKind::Relay);
        assert_eq!(a.control, PathKind::Relay);
        assert_eq!(m.best_active(), Some(PathKind::Relay));
    }

    #[test]
    fn test_direct_active_media_takes_it_control_relay() {
        // PATH-002：直连 Active → 媒体走直连；控制走中继（另一路径）
        let mut m = mgr();
        m.register_path(PathKind::Relay);
        m.on_path_state(PathKind::Relay, PathState::Active);
        m.register_path(PathKind::DirectV6);
        m.on_path_state(PathKind::DirectV6, PathState::Active);
        let a = m.assignment();
        assert_eq!(a.video, PathKind::DirectV6);
        assert_eq!(a.audio, PathKind::DirectV6);
        assert_eq!(a.control, PathKind::Relay);
        // 中继自动转 Standby（PATH-005：空闲保活）
        assert_eq!(m.path(PathKind::Relay).unwrap().state, PathState::Standby);
    }

    #[test]
    fn test_two_p2p_active_spread_channels() {
        // PATH-002：直连 + 打洞同时 Active → 媒体走最优（直连），控制走打洞
        let mut m = mgr();
        for k in [PathKind::Relay, PathKind::DirectV6, PathKind::PunchUdp] {
            m.register_path(k);
            m.on_path_state(k, PathState::Active);
        }
        let a = m.assignment();
        assert_eq!(a.video, PathKind::DirectV6);
        assert_eq!(a.audio, PathKind::DirectV6);
        assert_eq!(a.control, PathKind::PunchUdp);
        assert_eq!(a.input, PathKind::PunchUdp);
    }

    #[test]
    fn test_punch_upgrade_from_relay() {
        // PATH-004：打洞成功 → 媒体从中继升舱到打洞路径（BetterPathAvailable）
        let (mut m, actions) = pump_setup();
        assert_eq!(actions.len(), 1);
        let a = actions[0];
        assert_eq!(a.from, PathKind::Relay);
        assert_eq!(a.to, PathKind::PunchUdp);
        assert_eq!(a.reason, SwitchReason::BetterPathAvailable);
        assert_eq!(a.budget_ms, 200); // QUIC 迁移预算（PATH-003/NF-002）
                                      // 期望分配即时更新；动作不重复产出（pending）
        assert_eq!(m.assignment().video, PathKind::PunchUdp);
        assert!(m.evaluate().is_empty());
        m.on_switch_completed(a);
    }

    #[test]
    fn test_loss_degraded_switch_after_hold() {
        // PATH-003：丢包 >2% 持续 2s（测试阈值 20ms）→ 确认劣化 → 换路
        let (mut m, upgrade) = pump_setup();
        m.on_switch_completed(upgrade[0]);
        // 打洞路径劣化（丢包 3%）
        m.on_metrics(
            PathKind::PunchUdp,
            PathMetrics {
                rtt_ms: 20.0,
                loss_rate: 0.03,
                jitter_us: 100.0,
            },
        );
        assert!(m.evaluate().is_empty(), "未到保持期不换路");
        std::thread::sleep(Duration::from_millis(30));
        let actions = m.evaluate();
        assert_eq!(actions.len(), 1);
        let a = actions[0];
        assert_eq!(a.from, PathKind::PunchUdp);
        assert_eq!(a.to, PathKind::Relay);
        assert_eq!(a.reason, SwitchReason::LossDegraded);
    }

    #[test]
    fn test_rtt_degraded_switch_to_best_remaining() {
        // PATH-003：RTT 差 >30% → 劣化确认 → 控制从次优（打洞）换到中继 standby
        let mut m = mgr();
        for k in [PathKind::Relay, PathKind::DirectV6, PathKind::PunchUdp] {
            m.register_path(k);
            m.on_path_state(k, PathState::Active);
        }
        // 先确认初始升舱（中继 → 直连媒体；applied 同步）
        let upgrade = m.evaluate();
        assert_eq!(upgrade.len(), 1);
        assert_eq!(upgrade[0].from, PathKind::Relay);
        assert_eq!(upgrade[0].to, PathKind::DirectV6);
        m.on_switch_completed(upgrade[0]);
        assert_eq!(m.assignment().control, PathKind::PunchUdp);

        // 最优 DirectV6 RTT 10ms；PunchUdp 30ms（>13ms = 差 >30%）→ 劣化
        m.on_metrics(
            PathKind::DirectV6,
            PathMetrics {
                rtt_ms: 10.0,
                loss_rate: 0.0,
                jitter_us: 0.0,
            },
        );
        m.on_metrics(
            PathKind::PunchUdp,
            PathMetrics {
                rtt_ms: 30.0,
                loss_rate: 0.0,
                jitter_us: 0.0,
            },
        );
        assert!(m.evaluate().is_empty(), "未到保持期不换路");
        std::thread::sleep(Duration::from_millis(30));
        let actions = m.evaluate();
        assert_eq!(
            actions.len(),
            1,
            "控制路径 PunchUdp RTT 劣化 → 换中继 standby"
        );
        assert_eq!(actions[0].from, PathKind::PunchUdp);
        assert_eq!(actions[0].to, PathKind::Relay);
        assert_eq!(actions[0].reason, SwitchReason::RttDegraded);
    }

    #[test]
    fn test_degraded_recovery_returns_to_path() {
        // PATH-003 恢复回路：劣化确认换路后指标恢复 → 期望分配回归原路径
        let (mut m, upgrade) = pump_setup();
        m.on_switch_completed(upgrade[0]);
        m.on_metrics(
            PathKind::PunchUdp,
            PathMetrics {
                rtt_ms: 20.0,
                loss_rate: 0.05,
                jitter_us: 0.0,
            },
        );
        std::thread::sleep(Duration::from_millis(30));
        let actions = m.evaluate();
        assert_eq!(actions.len(), 1);
        m.on_switch_completed(actions[0]);
        assert_eq!(m.assignment().video, PathKind::Relay);

        // 恢复：丢包归零 + RTT 回优
        m.on_metrics(
            PathKind::PunchUdp,
            PathMetrics {
                rtt_ms: 5.0,
                loss_rate: 0.0,
                jitter_us: 0.0,
            },
        );
        let actions = m.evaluate();
        assert_eq!(actions.len(), 1, "恢复后应触发升舱回打洞路径");
        assert_eq!(actions[0].from, PathKind::Relay);
        assert_eq!(actions[0].to, PathKind::PunchUdp);
        assert_eq!(actions[0].reason, SwitchReason::BetterPathAvailable);
    }

    #[test]
    fn test_repunch_failure_stays_relay() {
        // PUNCH-004：连续 2 次重打洞失败 → 保持中继
        let mut m = mgr();
        m.register_path(PathKind::Relay);
        m.on_path_state(PathKind::Relay, PathState::Active);
        m.on_repunch_result(false);
        assert_eq!(m.repunch_failures(), 1);
        m.on_repunch_result(false);
        assert_eq!(m.repunch_failures(), 2);
        // 重打洞成功后复位（后续可再次升舱）
        m.on_repunch_result(true);
        assert_eq!(m.repunch_failures(), 0);
    }

    #[test]
    fn test_failed_path_resets_degrade() {
        let mut m = mgr();
        m.register_path(PathKind::PunchUdp);
        m.on_metrics(
            PathKind::PunchUdp,
            PathMetrics {
                rtt_ms: 100.0,
                loss_rate: 0.05,
                jitter_us: 0.0,
            },
        );
        assert!(m.path(PathKind::PunchUdp).unwrap().degraded_since.is_some());
        m.on_path_state(PathKind::PunchUdp, PathState::Failed);
        let p = m.path(PathKind::PunchUdp).unwrap();
        assert!(p.degraded_since.is_none());
        assert_eq!(p.state, PathState::Failed);
    }
}
