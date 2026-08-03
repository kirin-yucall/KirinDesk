use crate::connection::client::ConnectionOptions;
use std::net::{IpAddr, SocketAddr};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Connection state.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Idle,
    Resolving,
    Handshaking,
    Secured,
    Reconnecting,
    Disconnected,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Idle => write!(f, "Idle"),
            ConnectionState::Resolving => write!(f, "Resolving"),
            ConnectionState::Handshaking => write!(f, "Handshaking"),
            ConnectionState::Secured => write!(f, "Secured"),
            ConnectionState::Reconnecting => write!(f, "Reconnecting"),
            ConnectionState::Disconnected => write!(f, "Disconnected"),
        }
    }
}

/// Events that trigger state transitions.
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// R-19b：地址字段泛化为 `SocketAddr`（v4/v6 统一，对齐 M8-T025-P2 模式）。
    /// 事件层应用 [`canonical_addr`] 规范化——v4-mapped v6 呈现为真实 v4。
    ConnectRequest {
        peer_id: String,
        addr: SocketAddr,
    },
    DnsResolved,
    HandshakeSuccess,
    HandshakeFailed(String),
    ConnectionLost(String),
    ReconnectSuccess,
    ReconnectFailed(String),
    Disconnect,
}

/// R-03 (R03-S2)：重连上下文——断线后按原规格自动重连所需的 peer 规格
/// （域名/IP、期望公钥 pin、确认策略、凭据）。首次建连成功后登记，
/// `reconnection::try_connect` 据此重建连接。
#[derive(Clone)]
pub struct ReconnectContext {
    /// 建连规格（含信任策略与凭据；重连复用同一身份，不重建）。
    pub options: ConnectionOptions,
    /// 展示/日志用昵称。
    pub server_id: String,
}

/// A managed connection to a remote device.
#[derive(Clone)]
pub struct ManagedConnection {
    pub state: ConnectionState,
    pub peer_id: String,
    /// R-19b：对端地址（v4/v6 统一视角，v4-mapped 已规范化为真实 v4）。
    pub peer_addr: Option<SocketAddr>,
    pub reconnect_attempts: u32,
    pub max_reconnect_attempts: u32,
    /// R-03 (R03-S2)：重连上下文（`attempt_reconnect` 据此重建连接）。
    pub reconnect_ctx: Option<ReconnectContext>,
}

impl std::fmt::Debug for ManagedConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedConnection")
            .field("state", &self.state)
            .field("peer_id", &self.peer_id)
            .field("peer_addr", &self.peer_addr)
            .field("reconnect_attempts", &self.reconnect_attempts)
            .field("max_reconnect_attempts", &self.max_reconnect_attempts)
            .field(
                "reconnect_ctx",
                &self.reconnect_ctx.as_ref().map(|_| "<set>"),
            )
            .finish()
    }
}

impl ManagedConnection {
    pub fn new(peer_id: impl Into<String>) -> Self {
        Self {
            state: ConnectionState::Idle,
            peer_id: peer_id.into(),
            peer_addr: None,
            reconnect_attempts: 0,
            max_reconnect_attempts: 5,
            reconnect_ctx: None,
        }
    }

    /// R-03 (R03-S2)：登记重连上下文（断线后自动重连用）。
    pub fn set_reconnect_context(&mut self, ctx: ReconnectContext) {
        self.reconnect_ctx = Some(ctx);
    }

    /// R-03 (R03-S2)：进入重连状态——`Secured` 经 `ConnectionLost` 事件归一
    /// （记录断开原因）；其它状态直接置位（如建连失败的自动重试）。
    pub fn enter_reconnecting(&mut self) {
        if self.state == ConnectionState::Secured {
            self.apply_event(&ConnectionEvent::ConnectionLost(
                "connection lost".to_string(),
            ));
        } else {
            self.transition_to(ConnectionState::Reconnecting);
        }
    }

    pub fn apply_event(&mut self, event: &ConnectionEvent) {
        match (&self.state, event) {
            (
                ConnectionState::Idle,
                ConnectionEvent::ConnectRequest { peer_id, addr },
            ) => {
                self.peer_id = peer_id.clone();
                self.peer_addr = Some(canonical_addr(*addr));
                self.transition_to(ConnectionState::Resolving);
            }
            (ConnectionState::Resolving, ConnectionEvent::DnsResolved) => {
                self.transition_to(ConnectionState::Handshaking);
            }
            (ConnectionState::Handshaking, ConnectionEvent::HandshakeSuccess) => {
                self.reconnect_attempts = 0;
                self.transition_to(ConnectionState::Secured);
            }
            (ConnectionState::Handshaking, ConnectionEvent::HandshakeFailed(_)) => {
                self.transition_to(ConnectionState::Idle);
            }
            (ConnectionState::Secured, ConnectionEvent::ConnectionLost(_)) => {
                self.transition_to(ConnectionState::Reconnecting);
            }
            (ConnectionState::Reconnecting, ConnectionEvent::ReconnectSuccess) => {
                self.reconnect_attempts = 0;
                self.transition_to(ConnectionState::Secured);
            }
            (ConnectionState::Reconnecting, ConnectionEvent::ReconnectFailed(_))
            | (ConnectionState::Reconnecting, ConnectionEvent::Disconnect) => {
                self.transition_to(ConnectionState::Idle);
            }
            (_, ConnectionEvent::Disconnect) => {
                self.transition_to(ConnectionState::Disconnected);
            }
            _ => {
                warn!("Invalid state transition: {:?} -> {:?}", self.state, event);
            }
        }
    }

    fn transition_to(&mut self, new_state: ConnectionState) {
        info!(
            "Connection '{}': {} -> {}",
            self.peer_id, self.state, new_state
        );
        self.state = new_state;
    }
}

/// R-19b：事件层地址规范化——v4-mapped v6（`::ffff:a.b.c.d`）呈现为真实 v4
/// 地址（前缀剥离），原生 v6 保持不变。保证事件层视角 v4/v6 统一（与传输层
/// 双栈能力一致；即使调用方直接构造 v4-mapped 地址，事件层亦不泄漏该形态）。
fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    match addr.ip().to_canonical() {
        IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
        IpAddr::V6(v6) => SocketAddr::new(IpAddr::V6(v6), addr.port()),
    }
}

/// Connection manager.
pub struct ConnectionManager {
    connections: Mutex<Vec<ManagedConnection>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: Mutex::new(Vec::new()),
        }
    }

    pub async fn apply_event(&self, event: &ConnectionEvent) {
        let mut conns = self.connections.lock().await;
        match event {
            ConnectionEvent::ConnectRequest { peer_id, .. } => {
                debug!("ConnectionManager: ConnectRequest for '{}'", peer_id);
                if let Some(conn) = conns.iter_mut().find(|c| c.peer_id == *peer_id) {
                    conn.apply_event(event);
                } else {
                    let mut conn = ManagedConnection::new(peer_id);
                    conn.apply_event(event);
                    conns.push(conn);
                }
            }
            _ => {
                debug!("ConnectionManager: broadcasting event {:?}", event);
                for conn in conns.iter_mut() {
                    conn.apply_event(event);
                }
            }
        }
    }

    pub async fn get(&self, peer_id: &str) -> Option<ManagedConnection> {
        let conns = self.connections.lock().await;
        conns.iter().find(|c| c.peer_id == peer_id).cloned()
    }

    pub async fn secured_connections(&self) -> Vec<ManagedConnection> {
        let conns = self.connections.lock().await;
        conns
            .iter()
            .filter(|c| c.state == ConnectionState::Secured)
            .cloned()
            .collect()
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_state_transitions() {
        let mut conn = ManagedConnection::new("test-peer");

        conn.apply_event(&ConnectionEvent::ConnectRequest {
            peer_id: "test-peer".to_string(),
            addr: SocketAddr::new("2001:db8::1".parse().unwrap(), 3389),
        });
        assert_eq!(conn.state, ConnectionState::Resolving);

        conn.apply_event(&ConnectionEvent::DnsResolved);
        assert_eq!(conn.state, ConnectionState::Handshaking);

        conn.apply_event(&ConnectionEvent::HandshakeSuccess);
        assert_eq!(conn.state, ConnectionState::Secured);

        conn.apply_event(&ConnectionEvent::ConnectionLost("timeout".to_string()));
        assert_eq!(conn.state, ConnectionState::Reconnecting);

        conn.apply_event(&ConnectionEvent::ReconnectSuccess);
        assert_eq!(conn.state, ConnectionState::Secured);

        conn.apply_event(&ConnectionEvent::Disconnect);
        assert_eq!(conn.state, ConnectionState::Disconnected);
    }

    #[test]
    fn test_invalid_transition_ignored() {
        let mut conn = ManagedConnection::new("test");
        assert_eq!(conn.state, ConnectionState::Idle);
        conn.apply_event(&ConnectionEvent::HandshakeSuccess);
        assert_eq!(conn.state, ConnectionState::Idle);
    }

    // R-03 (R03-S2): enter_reconnecting 归一化入口（Secured → ConnectionLost 事件；
    // 其它状态直接置位）。
    #[test]
    fn test_enter_reconnecting() {
        let mut conn = ManagedConnection::new("test-peer");
        conn.apply_event(&ConnectionEvent::ConnectRequest {
            peer_id: "test-peer".to_string(),
            addr: SocketAddr::new("2001:db8::1".parse().unwrap(), 3389),
        });
        conn.apply_event(&ConnectionEvent::DnsResolved);
        conn.apply_event(&ConnectionEvent::HandshakeSuccess);
        assert_eq!(conn.state, ConnectionState::Secured);
        conn.enter_reconnecting();
        assert_eq!(conn.state, ConnectionState::Reconnecting);
        // 幂等：再次调用不改变状态。
        conn.enter_reconnecting();
        assert_eq!(conn.state, ConnectionState::Reconnecting);
    }

    // ── R-19b：v4/v6 混合用例（地址字段泛化为 SocketAddr + v4-mapped 规范化） ──

    /// v4 对端事件 → 事件层呈现为真实 v4 地址（非 `::ffff:` 前缀）。
    #[test]
    fn test_connect_request_v4_presented_as_v4() {
        let mut conn = ManagedConnection::new("v4-peer");
        conn.apply_event(&ConnectionEvent::ConnectRequest {
            peer_id: "v4-peer".to_string(),
            addr: SocketAddr::new(Ipv4Addr::new(192, 168, 1, 50).into(), 3389),
        });
        let addr = conn.peer_addr.expect("peer_addr 应已登记");
        assert_eq!(
            addr,
            SocketAddr::new(Ipv4Addr::new(192, 168, 1, 50).into(), 3389)
        );
        assert!(
            matches!(addr, SocketAddr::V4(_)),
            "v4 对端应呈现为 v4 地址: {addr}"
        );
        assert!(
            !addr.ip().to_string().starts_with("::ffff:"),
            "不应残留 v4-mapped 前缀: {addr}"
        );
    }

    /// 调用方直接构造 v4-mapped v6（`::ffff:203.0.113.7`）→ 事件层规范化
    /// 为真实 v4（前缀剥离）。
    #[test]
    fn test_connect_request_v4_mapped_canonicalized() {
        let mut conn = ManagedConnection::new("mapped-peer");
        let v4_mapped = SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x7107), // ::ffff:203.0.113.7
            8080,
            0,
            0,
        );
        assert!(v4_mapped.ip().to_string().starts_with("::ffff:"));
        conn.apply_event(&ConnectionEvent::ConnectRequest {
            peer_id: "mapped-peer".to_string(),
            addr: SocketAddr::V6(v4_mapped),
        });
        let addr = conn.peer_addr.expect("peer_addr 应已登记");
        assert_eq!(
            addr,
            SocketAddr::new(Ipv4Addr::new(203, 0, 113, 7).into(), 8080),
            "v4-mapped 应呈现为真实 v4"
        );
        assert!(!addr.ip().to_string().starts_with("::ffff:"));
    }

    /// 原生 v6 事件 → 事件层原样保留 v6（既有 IPv6 路径零回归）。
    #[test]
    fn test_connect_request_v6_preserved() {
        let mut conn = ManagedConnection::new("v6-peer");
        let v6 = SocketAddr::new("2001:db8::1".parse().unwrap(), 3389);
        conn.apply_event(&ConnectionEvent::ConnectRequest {
            peer_id: "v6-peer".to_string(),
            addr: v6,
        });
        let addr = conn.peer_addr.expect("peer_addr 应已登记");
        assert_eq!(addr, v6);
        assert!(matches!(addr, SocketAddr::V6(_)));
    }

    /// canonical_addr 纯函数：v4-mapped 剥离前缀；原生 v4/v6 原样。
    #[test]
    fn test_canonical_addr_mixed() {
        // v4 原样。
        let v4 = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 22);
        assert_eq!(canonical_addr(v4), v4);
        // 原生 v6 原样。
        let v6 = SocketAddr::new("2001:db8::2".parse().unwrap(), 22);
        assert_eq!(canonical_addr(v6), v6);
        // v4-mapped v6 → 真实 v4。
        let mapped = SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001), // ::ffff:10.0.0.1
            22,
            0,
            0,
        );
        assert_eq!(canonical_addr(SocketAddr::V6(mapped)), v4);
        // v4 SocketAddrV4 分支直接覆盖。
        let v4_direct = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 22);
        assert_eq!(canonical_addr(SocketAddr::V4(v4_direct)), v4);
    }
}
