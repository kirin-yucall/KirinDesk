use crate::connection::client::{connect_peer, resolve_peer, ConnectError, RefusalReason};
use crate::connection::manager::{ConnectionEvent, ManagedConnection};
use crate::crypto::handshake::SecureChannel;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

/// Reconnection backoff strategy.
///
/// Exponential backoff: 1s, 2s, 4s, 8s, 16s, capped at 30s
/// （第 N 次尝试等待 `backoff_duration(N-1)`）。
fn backoff_duration(attempt: u32) -> Duration {
    let secs = std::cmp::min(1u64 << attempt, 30);
    Duration::from_secs(secs)
}

/// R-03 (R03-S5)：重连失败（含最终原因与不可重连分类，供 UI/CLI 明确文案）。
#[derive(Debug)]
pub struct ReconnectFailure {
    /// 最终原因（最后一次尝试的错误 / 放弃说明）。
    pub reason: String,
    /// 不可重连分类（凭据过期 / 信任变更 / 服务端不可达）。
    pub refusal: RefusalReason,
}

impl ReconnectFailure {
    /// R03-S5：明确原因文案（"无法自动重连（原因）"，不静默失败）。
    pub fn message(&self) -> String {
        self.refusal.message(&self.reason)
    }
}

/// Attempt to reconnect a lost connection with exponential backoff
/// （1s/2s/4s/8s/16s，上限 30s；至多 `max_reconnect_attempts` 次）。
///
/// 成功后经 [`ManagedConnection::apply_event`] 触发 `ReconnectSuccess`（回到
/// `Secured`、重试计数清零）并返回**新建立的 [`SecureChannel`]**——调用方据此
/// 续接会话（媒体重协商 / IDR，见 R03-S3）。
///
/// - `on_attempt`：每次尝试前回调（1 基尝试序号；UI 进度"第 N 次/M 次"）；
/// - `stop`：置位即中止退避循环（窗口关闭等场景）。
pub async fn attempt_reconnect(
    conn: &mut ManagedConnection,
    on_attempt: Option<Arc<dyn Fn(u32) + Send + Sync>>,
    stop: Option<Arc<AtomicBool>>,
) -> Result<SecureChannel, ReconnectFailure> {
    if conn.reconnect_ctx.is_none() {
        // R03-S5：无重连上下文（peer 规格未登记）→ 显式失败，不重试。
        return Err(ReconnectFailure {
            reason: "no reconnect context (peer spec not recorded)".to_string(),
            refusal: RefusalReason::Other,
        });
    }
    conn.enter_reconnecting();

    let stopped = || {
        stop.as_ref()
            .map(|s| s.load(Ordering::Relaxed))
            .unwrap_or(false)
    };
    if stopped() {
        return Err(ReconnectFailure {
            reason: "reconnect cancelled (session closed)".to_string(),
            refusal: RefusalReason::Other,
        });
    }

    let mut last_error: Option<ConnectError> = None;
    while conn.reconnect_attempts < conn.max_reconnect_attempts {
        conn.reconnect_attempts += 1;
        let attempt = conn.reconnect_attempts;
        if let Some(cb) = &on_attempt {
            cb(attempt);
        }
        // 退避：第 1 次等 1s、第 2 次 2s …（上限 30s）；等待可被 stop 中断。
        let delay = backoff_duration(attempt.saturating_sub(1));
        info!(
            "Reconnecting to '{}' (attempt {}/{} in {}s)",
            conn.peer_id,
            attempt,
            conn.max_reconnect_attempts,
            delay.as_secs()
        );
        let deadline = tokio::time::Instant::now() + delay;
        loop {
            if stopped() {
                return Err(ReconnectFailure {
                    reason: "reconnect cancelled (session closed)".to_string(),
                    refusal: RefusalReason::Other,
                });
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            sleep(Duration::from_millis(200)).await;
        }

        // Attempt connection (R03-S2: 抽取链路 — 发现 → 信任 → TCP → pin 握手)。
        match try_connect(conn).await {
            Ok(channel) => {
                info!("Reconnected to '{}'", conn.peer_id);
                conn.apply_event(&ConnectionEvent::ReconnectSuccess);
                return Ok(channel);
            }
            Err(e) => {
                warn!("Reconnect attempt {} failed: {}", attempt, e);
                last_error = Some(e);
            }
        }
    }

    warn!(
        "Gave up reconnecting to '{}' after {} attempts",
        conn.peer_id, conn.max_reconnect_attempts
    );
    conn.apply_event(&ConnectionEvent::ReconnectFailed(
        "max attempts".to_string(),
    ));
    let refusal = last_error
        .as_ref()
        .map(ConnectError::refusal_reason)
        .unwrap_or(RefusalReason::Other);
    Err(ReconnectFailure {
        reason: last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "max reconnect attempts reached".to_string()),
        refusal,
    })
}

/// Try to re-establish the connection using the recorded reconnect context
/// （R03-S2：调用抽取后的建连链路，同一身份/凭据，不重建身份）。
async fn try_connect(conn: &ManagedConnection) -> Result<SecureChannel, ConnectError> {
    let ctx = conn
        .reconnect_ctx
        .as_ref()
        .ok_or(ConnectError::NoReconnectContext)?;
    // 阶段 1：目标解析（domain 模式重新发现——地址可能已变化）。
    let peer = resolve_peer(&ctx.options).await?;
    // 阶段 2：TCP + pin/确认握手。
    let outcome = connect_peer(&ctx.options, &peer).await?;
    Ok(outcome.channel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::client::{ConnectionOptions, TrustPolicy};
    use crate::connection::manager::{ConnectionState, ManagedConnection, ReconnectContext};
    use crate::crypto::ed25519::IdentityManager;
    use crate::crypto::handshake::server_handshake_verified;
    use std::sync::Mutex;

    fn tmp_identity(tag: &str) -> IdentityManager {
        IdentityManager::generate(std::env::temp_dir().join(format!(
            "kirindesk_reconnection_{}_{}",
            tag,
            std::process::id()
        )))
        .unwrap()
    }

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
        assert!(attempt_reconnect(&mut conn, None, None).await.is_err());
    }

    #[tokio::test]
    async fn test_no_context_is_explicit_failure() {
        let mut conn = ManagedConnection::new("test");
        conn.max_reconnect_attempts = 1;
        let err = attempt_reconnect(&mut conn, None, None).await.unwrap_err();
        // R03-S5: 明确原因，不静默。
        assert!(err.message().contains("无法自动重连"));
        assert_eq!(err.refusal, RefusalReason::Other);
    }

    /// R-03 (R03-S2/S6)：建连 → 杀连接 → 退避重连成功（身份不重建 = 同一
    /// identity 复用；`ReconnectSuccess` 状态事件；重试计数清零）。
    #[tokio::test]
    async fn test_reconnect_loopback_success() {
        let alice = tmp_identity("alice");
        let bob = tmp_identity("bob");
        let bob_pub = bob.public_key_base64();
        let alice_pub = alice.public_key_base64();
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = async {
            // 两轮握手（首连 + 重连），每轮收到一条消息证明链路活。
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
                let mut ch = server_handshake_verified(stream, &bob, "bob", &alice_pub)
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = ch.receive().await.map_err(|e| e.to_string())?;
            }
            Ok::<_, String>(())
        };
        let client = async {
            let opts = ConnectionOptions {
                target: "::1".to_string(),
                port: addr.port(),
                server_id: "bob".to_string(),
                challenge: String::new(),
                device_type: "desktop".to_string(),
                client_identity: Arc::new(alice),
                client_id: "alice".to_string(),
                client_domain: "alice.local".to_string(),
                dns: None,
                trust: TrustPolicy::Verified(bob_pub),
            };
            let peer = resolve_peer(&opts).await.map_err(|e| e.to_string())?;
            let mut ch = connect_peer(&opts, &peer)
                .await
                .map_err(|e| e.to_string())?
                .channel;
            ch.send(b"hello-1").await.map_err(|e| e.to_string())?;
            drop(ch); // 模拟断线

            let mut conn = ManagedConnection::new("bob");
            conn.max_reconnect_attempts = 3;
            conn.set_reconnect_context(ReconnectContext {
                options: opts,
                server_id: "bob".to_string(),
            });
            let progress: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
            let progress_cb = progress.clone();
            let mut ch2 = attempt_reconnect(
                &mut conn,
                Some(Arc::new(move |n: u32| {
                    if let Ok(mut p) = progress_cb.lock() {
                        p.push(n);
                    }
                })),
                None,
            )
            .await
            .map_err(|e| e.message())?;
            assert_eq!(
                conn.state,
                ConnectionState::Secured,
                "ReconnectSuccess state"
            );
            assert_eq!(conn.reconnect_attempts, 0, "attempts reset after success");
            assert_eq!(
                *progress.lock().unwrap(),
                vec![1],
                "must succeed on first reconnect attempt"
            );
            ch2.send(b"hello-2").await.map_err(|e| e.to_string())?;
            Ok::<_, String>(())
        };
        let (s, c) = tokio::join!(server, client);
        assert!(s.is_ok(), "server side failed: {:?}", s);
        assert!(c.is_ok(), "client side failed: {:?}", c);
    }

    /// R-03 (R03-S5)：服务端已下线 → 重连失败给出明确分类（服务端不可达）。
    #[tokio::test]
    async fn test_reconnect_refusal_server_down() {
        let alice = tmp_identity("alice-down");
        // 绑定后立即关闭端口 → TCP 必拒绝。
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let opts = ConnectionOptions {
            target: "::1".to_string(),
            port,
            server_id: "peer".to_string(),
            challenge: String::new(),
            device_type: "desktop".to_string(),
            client_identity: Arc::new(alice),
            client_id: "me".to_string(),
            client_domain: "me.local".to_string(),
            dns: None,
            trust: TrustPolicy::Verified("unused".to_string()),
        };
        let mut conn = ManagedConnection::new("peer");
        conn.max_reconnect_attempts = 1;
        conn.set_reconnect_context(ReconnectContext {
            options: opts,
            server_id: "peer".to_string(),
        });
        let err = attempt_reconnect(&mut conn, None, None).await.unwrap_err();
        assert_eq!(err.refusal, RefusalReason::ServerUnreachable);
        assert!(err.message().contains("无法自动重连"), "explicit message");
        // 放弃后回到 Idle（ReconnectFailed 事件）。
        assert_eq!(conn.state, ConnectionState::Idle);
    }
}
