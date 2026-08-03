//! M8-T026-P2: 客户端设备 ID 连接编排（ID-010~015）。
//!
//! 职责对照：
//! - ID-010 解析：`connect --id <device_id>` → 服务器 `ResolveDevice` →
//!   `DeviceInfo`（候选 + 公钥 + 在线状态）；
//! - ID-SEC-001 验签：`DeviceInfo` 必须由服务器 Ed25519 私钥签名
//!   （`[tunnel] server_pubkey` 预置公钥验签），伪造/篡改 → 拒绝；
//! - ID-011 三级路径编排（叠加语义，对齐 P1）：
//!   ① 直连候选（IPv6/IPv4 TCP 并行尝试）→ ② 打洞（P1 hook 已接入，
//!   R-18b：`[`Self::try_punch`]` 经 rendezvous 交换候选 + UDP 探测 /
//!   TCP 同时打开，成功路径 `PathKind::PunchUdp/PunchTcp`，接入点见
//!   `task_docs/共享层/M8-T026_P2_与P1并行开发交互文档.md`）
//!   → ③ 设备级中继兜底（`TunnelConn`，§8.1，随会话建立保证连通）；
//! - ID-013 握手不变：直连/中继路径返回的流上由调用方执行 Ed25519 双向握手
//!   （`client_handshake_with_confirm_generic` 等现有逻辑零改动复用），
//!   白名单/挑战码/临时码校验保持生效；打洞 TCP 路径（`PathKind::PunchTcp`）
//!   的 Ed25519 双向握手已在打洞内完成（PUNCH-SEC-001，公钥 pin 强制比对），
//!   返回流不再重复握手；
//! - ID-012 公钥 pin：`ed25519_pub` 与 known_hosts / DNS TXT 的一致性检查
//!   由调用方完成（CLI `cli_resolve_trust` 三态判定，首次指纹确认）。
//!
//! 路径枚举复用 P1 `path_manager::PathKind`（PATH-001，本 crate 不重复定义）。

// 路径枚举复用 P1 `path_manager::PathKind`（PATH-001，本 crate 不重复定义）。
pub use crate::connection::path_manager::PathKind;
use crate::connection::punch::{PunchConfig, PunchHandshake, PunchModes, PunchResult, PunchSession};
use crate::crypto::ed25519::IdentityManager;
use crate::crypto::handshake::PinExpectation;
use ed25519_dalek::VerifyingKey;
use kirin_desk_relay::id_client;
use kirin_desk_relay::id_client::collect_local_candidates;
use kirin_desk_relay::protocol::{Candidate, CandidateKind, DeviceInfo};
use kirin_desk_relay::registry::Registry;
use kirin_desk_utils::audit::AuditLogger;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// 默认拨号/响应超时（对齐 relay `DEFAULT_CONNECT_TIMEOUT`，5s）。
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 单候选直连尝试超时（建连快、失败快速让位中继）。
pub const DIRECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// ID 模式配置。
#[derive(Debug, Clone)]
pub struct IdModeConfig {
    /// relay 服务器地址：`host:port` / `ipv4:port` / `[ipv6]:port`。
    pub server_addr: String,
    /// token 认证（TNL-SEC-001）。
    pub token: String,
    /// 服务器 Ed25519 公钥（ID-SEC-001 验签；`[tunnel] server_pubkey` 预置）。
    pub server_pubkey: VerifyingKey,
    /// 拨号/响应超时（打洞阶段整体预算亦复用此值，PUNCH-PROTO-007）。
    pub connect_timeout: Duration,
    /// 打洞握手身份（ID-011 ② / PUNCH-SEC-001：打洞 TCP 路径内建 Ed25519
    /// 双向握手所需签名身份）。`None` = `try_punch` 时懒加载默认身份
    /// （`~/.kirin_desk/identity/ed25519.json`，与 GUI/CLI 同路径语义）。
    pub identity: Option<Arc<IdentityManager>>,
    /// 打洞 rendezvous 地址（R-08b：relay-server `--rendezvous-port` 独立
    /// 监听；候选登记/互转/结果透传不经隧道主端口）。`None` = 未配置
    /// rendezvous —— 打洞阶段跳过（debug 日志注明，路径选择如实落中继，
    /// 不再产生 `punch_skipped` 审计）。
    pub punch_rendezvous_addr: Option<SocketAddr>,
}

impl IdModeConfig {
    /// 从配置字符串构造（`server_pubkey_base64` 解析失败 → `None`）。
    pub fn try_new(
        server_addr: &str,
        token: &str,
        server_pubkey_base64: &str,
    ) -> Result<Self, IdConnectError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(server_pubkey_base64)
            .map_err(|_| IdConnectError::Config("server_pubkey is not valid base64".to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdConnectError::Config("server_pubkey must be 32 bytes".to_string()))?;
        let server_pubkey = VerifyingKey::from_bytes(&arr)
            .map_err(|e| IdConnectError::Config(format!("invalid server pubkey: {e}")))?;
        Ok(Self {
            server_addr: server_addr.to_string(),
            token: token.to_string(),
            server_pubkey,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            identity: None,
            punch_rendezvous_addr: None,
        })
    }

    /// 注入打洞握手身份（测试/复用既有身份；`None` 时 `try_punch` 懒加载
    /// 默认身份 `~/.kirin_desk/identity/ed25519.json`）。
    pub fn with_identity(mut self, identity: Arc<IdentityManager>) -> Self {
        self.identity = Some(identity);
        self
    }

    /// 注入打洞 rendezvous 地址（R-08b 部署形态：relay-server
    /// `--rendezvous-port` 独立监听，与隧道主端口并存）。
    pub fn with_punch_rendezvous(mut self, addr: SocketAddr) -> Self {
        self.punch_rendezvous_addr = Some(addr);
        self
    }
}

/// 连接错误。
#[derive(Debug, thiserror::Error)]
pub enum IdConnectError {
    #[error("config error: {0}")]
    Config(String),
    /// ID-014：服务器不可达（需配置 `[tunnel] server_addr`）。
    #[error("relay server unreachable: {0}")]
    ServerUnreachable(String),
    #[error("resolve failed: {0}")]
    ResolveFailed(String),
    #[error("login rejected: {0}")]
    LoginRejected(String),
    /// ID-SEC-001：服务器签名校验失败（伪造/篡改响应）。
    #[error("relay server signature verification failed")]
    SignatureVerification,
    /// ID-010：目标离线或不存在（统一文案，ID-SEC-002 防枚举）。
    #[error("device is offline or not registered: {0}")]
    DeviceUnavailable(String),
    /// 三级路径全部失败。
    #[error("all connection paths failed: {0}")]
    NoPath(String),
    #[error("relay error: {0}")]
    Relay(String),
}

/// ID 连接器（ID-010~013 编排）。
pub struct IdConnector {
    cfg: IdModeConfig,
}

impl IdConnector {
    pub fn new(cfg: IdModeConfig) -> Self {
        Self { cfg }
    }

    /// 当前配置（`status` 展示用）。
    pub fn config(&self) -> &IdModeConfig {
        &self.cfg
    }

    /// ID-010 + ID-SEC-001：解析目标设备（一次性控制连接 + 验签）。
    pub async fn resolve(&self, device_id: &str) -> Result<DeviceInfo, IdConnectError> {
        let timeout = self.cfg.connect_timeout;
        let info = id_client::resolve_device_verified(
            &self.cfg.server_addr,
            &self.cfg.token,
            device_id,
            &self.cfg.server_pubkey,
            timeout,
        )
        .await
        .map_err(|e| match e {
            id_client::IdClientError::SignatureVerification => {
                IdConnectError::SignatureVerification
            }
            id_client::IdClientError::LoginRejected(r) => IdConnectError::LoginRejected(r),
            id_client::IdClientError::Connect { .. }
            | id_client::IdClientError::Timeout(_)
            | id_client::IdClientError::Io(_) => IdConnectError::ServerUnreachable(e.to_string()),
            other => IdConnectError::ResolveFailed(other.to_string()),
        })?;
        Ok(info)
    }

    /// ID-010 辅助：解析结果是否可用（在线 + 有公钥 + 有候选）。
    pub fn is_connectable(info: &DeviceInfo) -> bool {
        info.payload.online && !info.payload.ed25519_pub.is_empty()
    }

    /// ID-011 ①：直连候选并行尝试 —— 首个 TCP 建连成功者胜出
    /// （候选按优先级降序，v6/v4 并行，单候选 2s 超时）。
    pub async fn try_direct(&self, info: &DeviceInfo) -> Option<(PathKind, TcpStream)> {
        let mut tcp_cands: Vec<(PathKind, SocketAddr)> = info
            .payload
            .candidates
            .iter()
            .filter(|c| c.kind == CandidateKind::Tcp && !c.addr.ip().is_unspecified())
            .map(|c| {
                let kind = match c.addr.ip() {
                    IpAddr::V6(_) => PathKind::DirectV6,
                    IpAddr::V4(_) => PathKind::DirectV4,
                };
                (kind, c.addr)
            })
            .collect();
        // 按优先级降序（候选列表本身已排序，这里兜底再排一次）。
        tcp_cands.sort_by(|a, b| b.1.port().cmp(&a.1.port())); // 排序仅稳定，不改变语义
        if tcp_cands.is_empty() {
            return None;
        }
        debug!("id mode: {} direct candidates", tcp_cands.len());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(PathKind, TcpStream)>(tcp_cands.len());
        let mut handles = Vec::new();
        for (kind, addr) in tcp_cands {
            let tx = tx.clone();
            handles.push(tokio::spawn(async move {
                match tokio::time::timeout(DIRECT_ATTEMPT_TIMEOUT, TcpStream::connect(addr)).await {
                    Ok(Ok(s)) => {
                        debug!("id mode: direct {} ok via {}", kind, addr);
                        let _ = tx.send((kind, s)).await;
                    }
                    _ => {
                        debug!("id mode: direct {} failed via {}", kind, addr);
                    }
                }
            }));
        }
        drop(tx);
        let result = rx.recv().await;
        for h in handles {
            h.abort();
        }
        result
    }

    /// ID-011 ③：设备级中继兜底（§8.1 `TunnelConn` 数据连接；
    /// 目标离线 → 统一文案，ID-SEC-002）。
    pub async fn open_relay(
        &self,
        target: &str,
        from_peer: &str,
    ) -> Result<TcpStream, IdConnectError> {
        let stream = id_client::open_tunnel(
            &self.cfg.server_addr,
            &self.cfg.token,
            target,
            from_peer,
            self.cfg.connect_timeout,
        )
        .await
        .map_err(|e| match e {
            id_client::IdClientError::DeviceUnavailable(r) => IdConnectError::DeviceUnavailable(r),
            id_client::IdClientError::Connect { .. } | id_client::IdClientError::Timeout(_) => {
                IdConnectError::ServerUnreachable(e.to_string())
            }
            other => IdConnectError::Relay(other.to_string()),
        })?;
        Ok(stream)
    }

    /// ID-011 ②：打洞路径（P1 hook 接入，R-18b，PUNCH-001~006）——
    /// 直连失败后经 rendezvous（R-08b：relay-server `--rendezvous-port`
    /// 独立监听）交换候选并发起 UDP 探测 / TCP 同时打开：
    /// - 候选来源：`DeviceInfo.payload.candidates`（UDP 条目即打洞候选；
    ///   服务器观察地址 OBSERVED_CANDIDATE_PRIORITY=200 的 TCP 条目为
    ///   NAT 后可达地址，PUNCH-PROTO-001）；
    /// - 会话：复用 `punch::PunchSession::establish()`（本端生成 128 位随机
    ///   `session_id` 并 pin，PUNCH-SEC-003 —— 对端（设备侧）经打洞会话参与，
    ///   见 [`Self::try_punch_with_session`]）；
    /// - 结果映射：TCP 同时打开成功（`PathKind::PunchTcp`，PUNCH-SEC-001
    ///   双向握手已在打洞内完成）→ 返回已握手通道的底层流（调用方不再重复
    ///   握手）；UDP 成功（`PathKind::PunchUdp`）→ socket 属媒体层 QUIC
    ///   升级路径（`M8-T026_接口交互协调.md` §3.6 PunchUpgradeEvent），初始
    ///   编排无法以 `TcpStream` 交付，记成功审计后返回 `None`（让位中继）；
    ///   失败/无候选/未配置 rendezvous → `None`。
    ///
    /// `None` 仅表示打洞阶段未交付可用的 TCP 流——调用方（[`Self::connect_stream`]）
    /// 据此降级③中继兜底；审计由调用方以 `TunnelPathSelected` 如实记录最终
    /// 路径（不再出现 `punch_skipped`）。
    pub async fn try_punch(&self, info: &DeviceInfo, from_peer: &str) -> Option<(PathKind, TcpStream)> {
        self.try_punch_with_session(info, from_peer, None).await
    }

    /// 同 [`Self::try_punch`]，但由调用方固定打洞会话（PUNCH-SEC-003：
    /// 发起方生成 `session_id` 后经现有控制连接告知对端；对端以
    /// `punch::PunchSession::with_session_id` 复用同一会话 —— 设备侧响应器
    /// 与 self-test 双端配对经此入口）。`session_id = None` = 本端生成
    /// 随机会话（独立尝试）。
    pub async fn try_punch_with_session(
        &self,
        info: &DeviceInfo,
        from_peer: &str,
        session_id: Option<[u8; 16]>,
    ) -> Option<(PathKind, TcpStream)> {
        let cfg = self.build_punch_config(info, from_peer).await?;
        let identity = self.punch_identity(from_peer)?;
        info!(
            "id mode: punch attempt for '{}' via rendezvous {}",
            info.payload.device_id, cfg.rendezvous_addr
        );
        // 打洞会话（发起方 pin；PUNCH-SEC-003）。
        let mut session = match session_id {
            Some(sid) => PunchSession::with_session_id(cfg, identity, sid),
            None => {
                let mut s = PunchSession::new(cfg, identity);
                s.pin_session();
                s
            }
        };
        // PUNCH-SEC-004：成功/失败审计（默认审计文件；不可用时跳过落盘）。
        if let Ok(logger) = AuditLogger::open_default() {
            session.set_audit(Arc::new(Mutex::new(logger)));
        }
        // 整体预算 = connect_timeout（PUNCH-PROTO-007 快速失败，让位中继）。
        let result = match timeout(self.cfg.connect_timeout, session.establish()).await {
            Ok(r) => r,
            Err(_) => {
                debug!(
                    "id mode: punch timed out after {:?}",
                    self.cfg.connect_timeout
                );
                return None;
            }
        };
        match result {
            PunchResult::TcpEstablished { channel } => {
                info!("id mode: punch tcp established (peer '{}')", channel.peer_id);
                Some((PathKind::PunchTcp, channel.stream))
            }
            PunchResult::UdpEstablished { socket, peer_addr } => {
                // UDP 打洞成功：socket 属媒体层 QUIC 升级路径（§3.6），初始
                // 编排（TcpStream 语义）无法交付 —— 记录后让位中继。
                info!("id mode: punch udp established with {peer_addr} (media upgrade path)");
                drop(socket);
                None
            }
            PunchResult::Failed { reason } => {
                debug!("id mode: punch failed: {reason}");
                None
            }
        }
    }

    /// 打洞配置构造（候选/rendezvous/公钥 pin/本地地址族选择，PUNCH-PROTO-001）。
    async fn build_punch_config(&self, info: &DeviceInfo, from_peer: &str) -> Option<PunchConfig> {
        // 1) 打洞候选（跳过通配地址；UDP 条目 = UDP 探测目标；TCP 条目
        //    （含服务器观察地址）= TCP 同时打开目标）。
        let cands: Vec<Candidate> = info
            .payload
            .candidates
            .iter()
            .filter(|c| !c.addr.ip().is_unspecified())
            .cloned()
            .collect();
        if cands.is_empty() {
            debug!("id mode: punch skipped — no candidates");
            return None;
        }
        let has_udp = cands.iter().any(|c| c.kind == CandidateKind::Udp);
        let has_tcp = cands.iter().any(|c| c.kind == CandidateKind::Tcp);

        // 2) rendezvous（R-08b：独立监听；未配置 → 打洞无路由目标，跳过 ——
        //    路径选择如实落中继，不再产生 punch_skipped）。
        let rendezvous_addr = match self.cfg.punch_rendezvous_addr {
            Some(a) => a,
            None => {
                debug!(
                    "id mode: punch skipped — no rendezvous configured \
                     (set [tunnel] rendezvous_addr / --rendezvous-port)"
                );
                return None;
            }
        };

        // 3) 对端公钥 pin（PUNCH-SEC-001：打洞 TCP 握手与直连同强度身份校验）。
        let peer_pin = match PinExpectation::exact_from_base64(&info.payload.ed25519_pub) {
            Ok(p) => p,
            Err(e) => {
                warn!("id mode: punch peer pin invalid: {e}");
                return None;
            }
        };

        // 4) 本端打洞地址：候选含回环（同机/self-test）→ 回环地址；否则取本机
        //    接口地址（relay::id_client::collect_local_candidates 复用，族与
        //    对端最高优先级候选一致 —— R-17）；都不可得 → 通配地址。
        let best_v6 = cands
            .iter()
            .max_by_key(|c| c.priority)
            .map(|c| match c.addr.ip() {
                // v4-mapped（双栈监听下服务器视角的 v4 地址，::ffff:a.b.c.d）
                // 按 v4 处理（`is_ipv4_mapped` 暂不稳定，手动判断）。
                IpAddr::V6(v6) => {
                    let o = v6.octets();
                    !(o[..10].iter().all(|&b| b == 0) && o[10] == 0xFF && o[11] == 0xFF)
                }
                IpAddr::V4(_) => false,
            })
            .unwrap_or(false);
        let local_ip = self.pick_local_ip(&cands, best_v6).await;

        Some(PunchConfig {
            rendezvous_addr,
            device_id: from_peer.to_string(),
            local_ip,
            // 快速失败预算：id_mode 打洞是首连阶段的加速路径，整体受
            // connect_timeout 约束（外层 timeout），单段参数取较紧值。
            probe_interval: Duration::from_millis(200),
            max_probes: 5,
            tcp_open_timeout: self.cfg.connect_timeout.min(Duration::from_secs(5)),
            peer_timeout: self
                .cfg
                .connect_timeout
                .min(crate::connection::punch::PEER_CANDIDATES_TIMEOUT),
            max_repunch_attempts: 0,
            modes: PunchModes {
                udp: has_udp,
                tcp: has_tcp,
            },
            handshake: PunchHandshake {
                // ID 模式无域名（ID-013：访问控制由调用方握手/挑战码承担；
                // 打洞内握手以 device_id + 公钥 pin 校验身份，PUNCH-SEC-001）。
                domain: String::new(),
                device_type: "desktop".to_string(),
                peer_device_id: info.payload.device_id.clone(),
                peer_pin,
                challenge: String::new(),
            },
        })
    }

    /// 本端打洞绑定地址选择（R-17：与对端地址族匹配，避免 bind/connect 族错误）。
    async fn pick_local_ip(&self, cands: &[Candidate], want_v6: bool) -> IpAddr {
        // 同机场景（候选含回环地址）→ 回环地址（self-test / 同机直连验证）。
        if cands.iter().any(|c| c.addr.ip().is_loopback()) {
            return if want_v6 {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            };
        }
        // 生产：本机非回环接口地址（打洞候选必须可被对端寻址，0.0.0.0 不可达；
        // 复用 relay::id_client::collect_local_candidates，族优先）。
        let local = collect_local_candidates(&[]).await;
        let preferred = local
            .iter()
            .find(|c| c.addr.ip().is_ipv6() == want_v6 && !c.addr.ip().is_unspecified());
        if let Some(c) = preferred.or_else(|| local.first()) {
            if !c.addr.ip().is_unspecified() {
                return c.addr.ip();
            }
        }
        // 兜底：通配地址（对端探测通常不可达 → 打洞失败 → 中继兜底）。
        if want_v6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
    }

    /// 打洞握手身份（PUNCH-SEC-001）：注入身份优先，否则懒加载默认身份。
    fn punch_identity(&self, from_peer: &str) -> Option<Arc<IdentityManager>> {
        if let Some(id) = &self.cfg.identity {
            return Some(Arc::clone(id));
        }
        let path = match IdentityManager::default_path() {
            Ok(p) => p,
            Err(e) => {
                warn!("id mode: punch identity path unavailable: {e}");
                return None;
            }
        };
        match IdentityManager::load_or_generate(path, from_peer) {
            Ok(id) => Some(Arc::new(id)),
            Err(e) => {
                warn!("id mode: punch identity unavailable: {e}");
                None
            }
        }
    }

    /// ID-011：三级路径编排（叠加语义，对齐 P1）——
    /// ① 直连（并行候选）→ ② 打洞（P1 hook 接入，R-18b：经 rendezvous 交换
    /// 候选 + UDP 探测 / TCP 同时打开，PUNCH-001~006）→ ③ 中继兜底
    /// （保证首字节即通）。
    ///
    /// 返回 `(PathKind, TcpStream)`：
    /// - 直连/中继路径：调用方在该流上执行 Ed25519 双向握手（ID-013，
    ///   访问控制零降级）；
    /// - 打洞 TCP 路径（`PathKind::PunchTcp`）：Ed25519 双向握手已在打洞内
    ///   完成（PUNCH-SEC-001，公钥 pin 强制比对），返回流**不再重复握手**。
    pub async fn connect_stream(
        &self,
        info: &DeviceInfo,
        from_peer: &str,
    ) -> Result<(PathKind, TcpStream), IdConnectError> {
        // ① 直连候选（并行）。
        if let Some((kind, stream)) = self.try_direct(info).await {
            info!("id mode: path selected = {kind} (direct)");
            return Ok((kind, stream));
        }
        // ② 打洞（P1 hook 接入，R-18b；成功走 PunchUdp/PunchTcp，审计
        //    如实记录；无候选/未配置 rendezvous/失败 → None → ③ 中继兜底）。
        if let Some((kind, stream)) = self.try_punch(info, from_peer).await {
            info!("id mode: path selected = {kind} (punch)");
            return Ok((kind, stream));
        }
        // ③ 中继兜底（§8.1）。
        let stream = self.open_relay(&info.payload.device_id, from_peer).await?;
        info!(
            "id mode: path selected = relay (target '{}')",
            info.payload.device_id
        );
        Ok((PathKind::Relay, stream))
    }
}

/// ID-SEC-001 独立验签工具（`verify_device_info` 静态入口，供调用方复用）。
pub fn verify_device_info(verify_key: &VerifyingKey, info: &DeviceInfo) -> bool {
    Registry::verify_device_info(verify_key, info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kirin_desk_relay::protocol::{Candidate, DeviceInfoPayload};
    use kirin_desk_relay::rendezvous::RendezvousServer;

    fn test_config() -> IdModeConfig {
        // 从 seed 派生合法 ed25519 密钥对（VerifyingKey::from_bytes 对任意
        // 字节会做曲线点校验，随意字节可能非法）。
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        IdModeConfig {
            server_addr: "127.0.0.1:1".to_string(),
            token: "t".to_string(),
            server_pubkey: sk.verifying_key(),
            connect_timeout: Duration::from_secs(1),
            identity: None,
            punch_rendezvous_addr: None,
        }
    }

    fn sample_info(online: bool) -> DeviceInfo {
        DeviceInfo {
            payload: DeviceInfoPayload {
                device_id: "pc-a".to_string(),
                candidates: vec![
                    Candidate {
                        addr: "[2001:db8::1]:3389".parse().unwrap(),
                        kind: CandidateKind::Tcp,
                        priority: 100,
                    },
                    Candidate {
                        addr: "203.0.113.5:9000".parse().unwrap(),
                        kind: CandidateKind::Udp,
                        priority: 50,
                    },
                ],
                ed25519_pub: if online {
                    "pub-a".to_string()
                } else {
                    String::new()
                },
                online,
                ts: 1_752_000_000,
            },
            signature: vec![],
        }
    }

    #[test]
    fn test_is_connectable() {
        assert!(IdConnector::is_connectable(&sample_info(true)));
        assert!(!IdConnector::is_connectable(&sample_info(false)));
        // 在线但无公钥 → 不可连接（ID-SEC-003 只返回已注册设备信息）。
        let mut info = sample_info(true);
        info.payload.ed25519_pub.clear();
        assert!(!IdConnector::is_connectable(&info));
    }

    #[tokio::test]
    async fn test_try_direct_no_candidates() {
        let cfg = test_config();
        let connector = IdConnector::new(cfg);
        let mut info = sample_info(true);
        info.payload.candidates.clear();
        assert!(connector.try_direct(&info).await.is_none());
    }

    #[tokio::test]
    async fn test_try_direct_connectable_localhost() {
        // 回环可直连候选：bind 临时端口作为候选 → 直连成功。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // 立即关闭，让直连尝试只验证建连。
            drop(stream);
        });
        let info = DeviceInfo {
            payload: DeviceInfoPayload {
                device_id: "pc-a".to_string(),
                candidates: vec![Candidate {
                    addr,
                    kind: CandidateKind::Tcp,
                    priority: 100,
                }],
                ed25519_pub: "pub-a".to_string(),
                online: true,
                ts: 1_752_000_000,
            },
            signature: vec![],
        };
        let connector = IdConnector::new(test_config());
        let (kind, stream) = connector
            .try_direct(&info)
            .await
            .expect("direct must succeed");
        assert_eq!(kind, PathKind::DirectV4);
        assert!(stream.peer_addr().is_ok());
        accept_task.await.unwrap();
    }

    #[test]
    fn test_config_pubkey_parsing() {
        // 非法 base64 → 拒绝。
        assert!(IdModeConfig::try_new("a:1", "t", "not-base64!!").is_err());
        // 合法 32 字节 base64（全零）→ 接受。
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let cfg = IdModeConfig::try_new("a:1", "t", &b64).unwrap();
        assert_eq!(cfg.server_addr, "a:1");
        // 长度不对 → 拒绝。
        let b64_short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(IdModeConfig::try_new("a:1", "t", &b64_short).is_err());
    }

    /// 进程内 rendezvous（R-08b 形态：独立监听）+ 双端临时身份
    /// （对齐 punch.rs 测试基底；临时目录按 pid+序号隔离）。
    async fn punch_harness(
        ctrl_id: &str,
        dev_id: &str,
    ) -> (
        Arc<RendezvousServer>,
        SocketAddr,
        Arc<IdentityManager>,
        Arc<IdentityManager>,
    ) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let server = Arc::new(RendezvousServer::bind(0).await.unwrap());
        let mut addr = server.local_addr();
        if addr.ip().is_unspecified() {
            addr = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, addr.port()));
        }
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(tokio::sync::watch::channel(false).1).await;
        });

        let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_idmode_punch_{}_{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ctrl = Arc::new(IdentityManager::generate(dir.join(ctrl_id)).unwrap());
        let dev = Arc::new(IdentityManager::generate(dir.join(dev_id)).unwrap());
        (server, addr, ctrl, dev)
    }

    #[tokio::test]
    async fn test_try_punch_no_candidates() {
        // 无打洞候选 → 打洞阶段不可发起 → None（中继兜底）。
        let connector = IdConnector::new(
            test_config().with_punch_rendezvous("127.0.0.1:1".parse().unwrap()),
        );
        let mut info = sample_info(true);
        info.payload.candidates.clear();
        assert!(connector.try_punch(&info, "ctrl-a").await.is_none());
    }

    #[tokio::test]
    async fn test_try_punch_skips_without_rendezvous() {
        // 未配置 rendezvous（生产默认形态）→ 打洞阶段跳过（None）——
        // 路径选择如实落中继，不再出现 punch_skipped。
        let connector = IdConnector::new(test_config());
        assert!(
            connector
                .try_punch(&sample_info(true), "ctrl-a")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_try_punch_tcp_establishes() {
        // R-18b：直连失败 → 打洞（TCP 同时打开 + 内建 Ed25519 双向握手，
        // PUNCH-002 / PUNCH-SEC-001）→ PunchTcp 路径交付。
        let (_rv, rv_addr, ctrl_ident, dev_ident) = punch_harness("ctrl-a", "dev-b").await;
        let sid = [0x42u8; 16];
        // 设备侧打洞会话（同一会话，PUNCH-SEC-003；对端 pin = 控制器公钥）。
        let mut dev_cfg = PunchConfig::loopback("dev-b");
        dev_cfg.rendezvous_addr = rv_addr;
        dev_cfg.handshake.peer_device_id = "ctrl-a".into();
        dev_cfg.handshake.peer_pin =
            PinExpectation::exact_from_base64(&ctrl_ident.public_key_base64()).unwrap();
        dev_cfg.modes = PunchModes { udp: false, tcp: true };
        let mut dev_punch = PunchSession::with_session_id(dev_cfg, Arc::clone(&dev_ident), sid);

        // 控制器：DeviceInfo 含回环 TCP 候选（本端绑定 127.0.0.1；
        // 打洞实际目标来自 rendezvous 候选交换）。
        let info = DeviceInfo {
            payload: DeviceInfoPayload {
                device_id: "dev-b".to_string(),
                candidates: vec![Candidate {
                    addr: "127.0.0.1:1".parse().unwrap(),
                    kind: CandidateKind::Tcp,
                    priority: 100,
                }],
                ed25519_pub: dev_ident.public_key_base64(),
                online: true,
                ts: 1_752_000_000,
            },
            signature: vec![],
        };
        let connector = IdConnector::new(
            IdModeConfig {
                connect_timeout: Duration::from_secs(3),
                ..test_config()
            }
            .with_identity(Arc::clone(&ctrl_ident))
            .with_punch_rendezvous(rv_addr),
        );
        let (ctrl_res, dev_res) = tokio::join!(
            connector.try_punch_with_session(&info, "ctrl-a", Some(sid)),
            dev_punch.establish(),
        );
        let (kind, stream) = ctrl_res.expect("punch-tcp must establish");
        assert_eq!(kind, PathKind::PunchTcp);
        assert!(stream.peer_addr().is_ok(), "punch stream must be connected");
        match dev_res {
            PunchResult::TcpEstablished { channel } => {
                assert_eq!(channel.peer_id, "ctrl-a", "PUNCH-SEC-001 内建握手身份");
            }
            other => panic!("device side expected TcpEstablished, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_try_punch_fails_without_peer() {
        // 打洞尝试发起但无对端响应 → 快速失败（受 connect_timeout 约束）→
        // None（调用方降级中继兜底）。
        let (_rv, rv_addr, ctrl_ident, dev_ident) = punch_harness("ctrl-a", "dev-b").await;
        let info = DeviceInfo {
            payload: DeviceInfoPayload {
                device_id: "dev-b".to_string(),
                candidates: vec![Candidate {
                    addr: "127.0.0.1:1".parse().unwrap(),
                    kind: CandidateKind::Tcp,
                    priority: 100,
                }],
                ed25519_pub: dev_ident.public_key_base64(),
                online: true,
                ts: 1_752_000_000,
            },
            signature: vec![],
        };
        let connector = IdConnector::new(
            test_config()
                .with_identity(Arc::clone(&ctrl_ident))
                .with_punch_rendezvous(rv_addr),
        );
        let started = std::time::Instant::now();
        let r = connector.try_punch(&info, "ctrl-a").await;
        assert!(r.is_none(), "无对端响应 → 打洞失败 → 中继兜底");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "打洞失败判定需快速（connect_timeout 约束）"
        );
    }
}
