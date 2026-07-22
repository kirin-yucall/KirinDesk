use crate::connection::manager::{ManagedConnection, ConnectionEvent};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

/// Reconnection backoff strategy.
///
/// Exponential backoff: 1s, 2s, 4s, 8s, 16s, capped at 30s.
fn backoff_duration(attempt: u32) -> Duration {
    let secs = std::cmp::min(1u64 << attempt, 30);
    Duration::from_secs(secs)
}

/// Attempt to reconnect a lost connection.
///
/// Returns `true` if reconnection succeeded.
pub async fn attempt_reconnect(conn: &mut ManagedConnection) -> bool {
    while conn.reconnect_attempts < conn.max_reconnect_attempts {
        conn.reconnect_attempts += 1;
        let delay = backoff_duration(conn.reconnect_attempts);
        info!(
            "Reconnecting to '{}' (attempt {}/{}) in {}s",
            conn.peer_id,
            conn.reconnect_attempts,
            conn.max_reconnect_attempts,
            delay.as_secs()
        );

        sleep(delay).await;

        // Attempt connection
        match try_connect(conn).await {
            Ok(()) => {
                info!("Reconnected to '{}'", conn.peer_id);
                conn.apply_event(&ConnectionEvent::ReconnectSuccess);
                return true;
            }
            Err(e) => {
                warn!("Reconnect attempt {} failed: {}", conn.reconnect_attempts, e);
            }
        }
    }

    warn!(
        "Gave up reconnecting to '{}' after {} attempts",
        conn.peer_id, conn.max_reconnect_attempts
    );
    conn.apply_event(&ConnectionEvent::ReconnectFailed("max attempts".to_string()));
    false
}

/// Try to establish a connection (placeholder — actual impl uses DNS discovery + handshake).
async fn try_connect(_conn: &ManagedConnection) -> Result<(), String> {
    // In production, this would:
    // 1. Call DiscoveryService::discover() for SRV + AAAA + TXT
    // 2. Connect via TcpClient::connect(ipv6, port)
    // 3. Run handshake protocol
    // For now, return error to test reconnection logic
    Err("Connection not implemented at this layer".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::manager::ManagedConnection;

    #[test]
    fn test_backoff_duration() {
        assert_eq!(backoff_duration(0), Duration::from_secs(1));
        assert_eq!(backoff_duration(1), Duration::from_secs(2));
        assert_eq!(backoff_duration(2), Duration::from_secs(4));
        assert_eq!(backoff_duration(3), Duration::from_secs(8));
        assert_eq!(backoff_duration(4), Duration::from_secs(16));
        assert_eq!(backoff_duration(5), Duration::from_secs(30)); // capped
    }

    #[tokio::test]
    async fn test_max_reconnect_attempts() {
        let mut conn = ManagedConnection::new("test");
        conn.max_reconnect_attempts = 2;
        conn.reconnect_attempts = 2;
        // Exceeded max — should give up
        assert!(!attempt_reconnect(&mut conn).await);
    }
}
