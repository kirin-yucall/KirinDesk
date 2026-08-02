use crate::connection::client::ConnectionOptions;
use std::net::Ipv6Addr;
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
    ConnectRequest {
        peer_id: String,
        ipv6: Ipv6Addr,
        port: u16,
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
    pub peer_ipv6: Option<Ipv6Addr>,
    pub peer_port: Option<u16>,
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
            .field("peer_ipv6", &self.peer_ipv6)
            .field("peer_port", &self.peer_port)
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
            peer_ipv6: None,
            peer_port: None,
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
                ConnectionEvent::ConnectRequest {
                    peer_id,
                    ipv6,
                    port,
                },
            ) => {
                self.peer_id = peer_id.clone();
                self.peer_ipv6 = Some(*ipv6);
                self.peer_port = Some(*port);
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
    use std::net::Ipv6Addr;

    #[test]
    fn test_state_transitions() {
        let mut conn = ManagedConnection::new("test-peer");

        conn.apply_event(&ConnectionEvent::ConnectRequest {
            peer_id: "test-peer".to_string(),
            ipv6: "2001:db8::1".parse().unwrap(),
            port: 3389,
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
            ipv6: "2001:db8::1".parse().unwrap(),
            port: 3389,
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
}
