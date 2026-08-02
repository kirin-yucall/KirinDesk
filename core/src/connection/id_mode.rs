//! M8-T026-P2: 客户端设备 ID 连接编排（ID-010~015）。
//!
//! 职责对照：
//! - ID-010 解析：`connect --id <device_id>` → 服务器 `ResolveDevice` →
//!   `DeviceInfo`（候选 + 公钥 + 在线状态）；
//! - ID-SEC-001 验签：`DeviceInfo` 必须由服务器 Ed25519 私钥签名
//!   （`[tunnel] server_pubkey` 预置公钥验签），伪造/篡改 → 拒绝；
//! - ID-011 三级路径编排（叠加语义，对齐 P1）：
//!   ① 直连候选（IPv6/IPv4 TCP 并行尝试）→ ② 打洞（**P1 并行开发**：
//!   [`super::punch::PunchSession`] 已落地，接入点见
//!   `task_docs/共享层/M8-T026_P2_与P1并行开发交互文档.md`，本阶段留 hook，
//!   路径选择由调用方审计 `TunnelPathSelected=punch_skipped`）
//!   → ③ 设备级中继兜底（`TunnelConn`，§8.1，随会话建立保证连通）；
//! - ID-013 握手不变：任何路径返回的流上由调用方执行 Ed25519 双向握手
//!   （`client_handshake_with_confirm_generic` 等现有逻辑零改动复用），
//!   白名单/挑战码/临时码校验保持生效；
//! - ID-012 公钥 pin：`ed25519_pub` 与 known_hosts / DNS TXT 的一致性检查
//!   由调用方完成（CLI `cli_resolve_trust` 三态判定，首次指纹确认）。
//!
//! 路径枚举复用 P1 `path_manager::PathKind`（PATH-001，本 crate 不重复定义）。

// 路径枚举复用 P1 `path_manager::PathKind`（PATH-001，本 crate 不重复定义）。
pub use crate::connection::path_manager::PathKind;
use ed25519_dalek::VerifyingKey;
use kirin_desk_relay::id_client;
use kirin_desk_relay::protocol::{CandidateKind, DeviceInfo};
use kirin_desk_relay::registry::Registry;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
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
    /// 拨号/响应超时。
    pub connect_timeout: Duration,
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
        })
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
            | id_client::IdClientError::Io(_) => {
                IdConnectError::ServerUnreachable(e.to_string())
            }
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
    pub async fn try_direct(
        &self,
        info: &DeviceInfo,
    ) -> Option<(PathKind, TcpStream)> {
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
                match tokio::time::timeout(DIRECT_ATTEMPT_TIMEOUT, TcpStream::connect(addr)).await
                {
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
            id_client::IdClientError::DeviceUnavailable(r) => {
                IdConnectError::DeviceUnavailable(r)
            }
            id_client::IdClientError::Connect { .. } | id_client::IdClientError::Timeout(_) => {
                IdConnectError::ServerUnreachable(e.to_string())
            }
            other => IdConnectError::Relay(other.to_string()),
        })?;
        Ok(stream)
    }

    /// ID-011：三级路径编排（叠加语义，对齐 P1）——
    /// ① 直连（并行候选）→ ② 打洞（**P1 hook**：`try_punch` 接口由 P1 并行
    /// 开发按 `M8-T026_P2_与P1并行开发交互文档.md` 接入，本阶段跳过并审计
    /// `TunnelPathSelected=punch_skipped`）→ ③ 中继兜底（保证首字节即通）。
    ///
    /// 返回 `(PathKind, TcpStream)`：调用方在该流上执行 Ed25519 双向握手
    /// （ID-013，访问控制零降级）。
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
        // ② 打洞 —— P1 并行开发接入点（PUNCH-001~006）：
        //    接口约定：`try_punch(&self, info, from_peer) -> Option<(PathKind, TcpStream)>`，
        //    复用 relay `PeerCandidates` / `PunchProbe`（协议消息已定义）；
        //    本阶段跳过（审计 `TunnelPathSelected=punch_skipped (P1 pending)`）。
        warn!("id mode: punch path skipped (P1 in progress) — falling back to relay");
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

    fn test_config() -> IdModeConfig {
        // 从 seed 派生合法 ed25519 密钥对（VerifyingKey::from_bytes 对任意
        // 字节会做曲线点校验，随意字节可能非法）。
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        IdModeConfig {
            server_addr: "127.0.0.1:1".to_string(),
            token: "t".to_string(),
            server_pubkey: sk.verifying_key(),
            connect_timeout: Duration::from_secs(1),
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
                ed25519_pub: if online { "pub-a".to_string() } else { String::new() },
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
        let (kind, stream) = connector.try_direct(&info).await.expect("direct must succeed");
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
}
