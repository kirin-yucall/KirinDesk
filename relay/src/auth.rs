//! M8-T026-P3: 挑战-响应认证共用逻辑（TNL-SEC-006~010 / TNL-PROTO-009~013）。
//!
//! 客户端登录的统一挑战-响应流程（探测 → 挑战 → 证明 → 回执校验），供
//! `client.rs`（T003 端口代理）与 `id_client.rs`（P2 设备 ID 两条路径：
//! `connect_session` 注册 / `resolve_device` 一次性解析）共用，保证两条
//! 路径认证语义一致（口令永不明文上线、双向认证、fail-closed）。
//! 服务端两阶段握手在 `server.rs` `handle_challenge_login`。

use crate::protocol::{auth_digest, decode_control, read_frame, ControlMsg, ProtocolError};
use std::time::Duration;
use tokio::io::AsyncRead;

/// 客户端认证错误（调用方映射到各自错误枚举，语义保持一致）。
#[derive(Debug, thiserror::Error)]
pub enum ClientAuthError {
    /// 认证流程超时（服务器未应答挑战 / 未回 LoginResp）。
    #[error("auth timeout: {0}")]
    Timeout(String),
    /// 协议错误。
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    /// 登录被拒（`LoginResp{ok:false}`，含服务器原因）。
    #[error("login rejected: {0}")]
    LoginRejected(String),
    /// fail-closed（TNL-SEC-008）：无口令客户端连需口令的服务器。
    #[error("server requires challenge-response auth, but no token is configured locally")]
    NoTokenForChallenge,
    /// fail-closed（TNL-SEC-008）：带口令客户端连未认证（legacy）服务器。
    #[error(
        "server did not issue an auth challenge (unauthenticated server); refusing to continue with token configured (TNL-SEC-008)"
    )]
    LegacyServerRejected,
    /// 双向认证失败（T4）：回执与本地计算值不一致。
    #[error("server auth receipt verification failed (T4)")]
    ServerReceiptMismatch,
    /// 双向认证失败（T4）：`ok=true` 但未携带回执。
    #[error("server login response lacks auth receipt (T4)")]
    ServerReceiptMissing,
    /// 意外响应。
    #[error("unexpected auth response: {0}")]
    Unexpected(String),
    /// 发送失败。
    #[error("auth send failed: {0}")]
    Send(String),
}

/// 认证结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// 挑战-响应完成（双向认证通过）。
    Challenged,
    /// 服务器未挑战（legacy 无口令模式）；仅无口令客户端可继续。
    Legacy,
}

/// Login 的会话字段（调用方注入；token 与 auth 字段由 [`authenticate`]
/// 控制，口令原文永不上线 TNL-SEC-006）。
#[derive(Debug, Clone)]
pub struct LoginFields {
    pub version: String,
    pub hostname: String,
    pub device_id: Option<String>,
    pub ed25519_pub: Option<String>,
}

/// 构造 Login 帧：token 恒为空串（口令永不明文上线，TNL-SEC-006）；
/// 探测帧只带 `auth_nonce`，证明帧带 `auth_digest`（TNL-PROTO-011）。
fn login_msg(
    fields: &LoginFields,
    client_nonce: Option<[u8; 16]>,
    digest: Option<Vec<u8>>,
) -> ControlMsg {
    ControlMsg::Login {
        token: String::new(),
        version: fields.version.clone(),
        hostname: fields.hostname.clone(),
        device_id: fields.device_id.clone(),
        ed25519_pub: fields.ed25519_pub.clone(),
        auth_nonce: client_nonce,
        auth_digest: digest,
    }
}

/// 16 字节 CSPRNG 随机 nonce（TNL-NF-006；`rand::thread_rng` = ChaCha12 CSPRNG）。
pub fn random_nonce() -> [u8; 16] {
    use rand::RngCore;
    let mut n = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

/// 客户端证明（TNL-PROTO-013）：`HMAC-SHA256(token, server_nonce ‖ client_nonce)`。
pub fn client_digest(token: &[u8], server_nonce: &[u8; 16], client_nonce: &[u8; 16]) -> Vec<u8> {
    let mut data = Vec::with_capacity(32);
    data.extend_from_slice(server_nonce);
    data.extend_from_slice(client_nonce);
    auth_digest(token, &data)
}

/// 服务端回执（TNL-PROTO-013）：`HMAC-SHA256(token, client_nonce)`。
pub fn server_digest(token: &[u8], client_nonce: &[u8; 16]) -> Vec<u8> {
    auth_digest(token, client_nonce)
}

/// 常数时间字节比较（TNL-SEC-001 延续；digest 校验防时序侧信道）。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 客户端登录认证流程（TNL-SEC-006/007/008、TNL-PROTO-009~013）：
///
/// ① 探测：Login#1 携带 `auth_nonce`（token 恒为空串，口令永不明文上线）；
/// ② 服务器挑战 `AuthChallenge{nonce}` → ③ 证明：Login#2 携带
/// `auth_digest = HMAC(token, server_nonce ‖ client_nonce)` → ④ 回执校验：
/// `server_digest = HMAC(token, client_nonce)` 常数时间比对（防伪造服务器 T4）。
///
/// 服务器未挑战（legacy 无口令模式）→ 客户端带口令时 fail-closed 拒绝
/// （TNL-SEC-008），无口令时按 legacy 继续（TNL-SEC-010）。
pub async fn authenticate<R, F, Fut, E>(
    reader: &mut R,
    mut send: F,
    token: &str,
    connect_timeout: Duration,
    fields: &LoginFields,
) -> Result<AuthOutcome, ClientAuthError>
where
    R: AsyncRead + Unpin,
    F: FnMut(&ControlMsg) -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let client_nonce = random_nonce();
    // ① 探测（Login#1：不含任何口令信息）。
    send(&login_msg(fields, Some(client_nonce), None))
        .await
        .map_err(|e| ClientAuthError::Send(e.to_string()))?;
    let (ty, payload) = read_auth_frame(reader, connect_timeout, "auth challenge").await?;
    match decode_control(ty, &payload)? {
        // ② 服务器挑战（口令模式）。
        ControlMsg::AuthChallenge { nonce: server_nonce } => {
            if token.is_empty() {
                // fail-closed：无口令客户端拒绝向需口令的服务器继续（TNL-SEC-008）。
                return Err(ClientAuthError::NoTokenForChallenge);
            }
            // ③ 证明（Login#2）。
            let digest = client_digest(token.as_bytes(), &server_nonce, &client_nonce);
            send(&login_msg(fields, Some(client_nonce), Some(digest)))
                .await
                .map_err(|e| ClientAuthError::Send(e.to_string()))?;
            let (ty, payload) = read_auth_frame(reader, connect_timeout, "auth proof response").await?;
            match decode_control(ty, &payload)? {
                ControlMsg::LoginResp {
                    ok: true,
                    auth_digest: Some(receipt),
                    ..
                } => {
                    // ④ 回执校验（双向认证，T4）。
                    let expect = server_digest(token.as_bytes(), &client_nonce);
                    if !constant_time_eq(&receipt, &expect) {
                        return Err(ClientAuthError::ServerReceiptMismatch);
                    }
                    Ok(AuthOutcome::Challenged)
                }
                ControlMsg::LoginResp {
                    ok: true,
                    auth_digest: None,
                    ..
                } => Err(ClientAuthError::ServerReceiptMissing),
                ControlMsg::LoginResp {
                    ok: false, err, ..
                } => Err(ClientAuthError::LoginRejected(
                    err.unwrap_or_else(|| "login failed".to_string()),
                )),
                other => Err(ClientAuthError::Unexpected(format!(
                    "expected LoginResp, got {other:?}"
                ))),
            }
        }
        // 服务器未挑战（legacy 无口令模式）。
        ControlMsg::LoginResp { ok: true, .. } => {
            if !token.is_empty() {
                // fail-closed：带口令客户端拒绝未认证服务器（TNL-SEC-008）。
                return Err(ClientAuthError::LegacyServerRejected);
            }
            Ok(AuthOutcome::Legacy)
        }
        ControlMsg::LoginResp { ok: false, err, .. } => Err(ClientAuthError::LoginRejected(
            err.unwrap_or_else(|| "login failed".to_string()),
        )),
        other => Err(ClientAuthError::Unexpected(format!(
            "expected AuthChallenge or LoginResp, got {other:?}"
        ))),
    }
}

/// 限时读一帧（认证流程用；超时 → `Timeout`）。
async fn read_auth_frame<R>(
    reader: &mut R,
    connect_timeout: Duration,
    what: &str,
) -> Result<(u8, Vec<u8>), ClientAuthError>
where
    R: AsyncRead + Unpin,
{
    tokio::time::timeout(connect_timeout, read_frame(reader))
        .await
        .map_err(|_| ClientAuthError::Timeout(what.to_string()))?
        .map_err(ClientAuthError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{encode_control, PROTOCOL_VERSION};
    use tokio::io::{AsyncWriteExt, DuplexStream};

    /// fake 服务器读一帧并解码。
    async fn server_read(stream: &mut DuplexStream) -> ControlMsg {
        let (ty, payload) = read_frame(stream).await.unwrap();
        decode_control(ty, &payload).unwrap()
    }

    /// fake 服务器写一帧。
    async fn server_send(stream: &mut DuplexStream, msg: &ControlMsg) {
        let frame = encode_control(msg).unwrap();
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();
    }

    fn fields() -> LoginFields {
        LoginFields {
            version: PROTOCOL_VERSION.to_string(),
            hostname: "pc-a".to_string(),
            device_id: None,
            ed25519_pub: None,
        }
    }

    /// 运行 [`authenticate`] 的测试夹具：fake 服务器执行 `server` 闭包；
    /// 客户端写半经 `Arc<Mutex>` 共享（future 不得借用 send 参数，
    /// 见 [`authenticate`] 泛型约束）。
    async fn run_auth<SF, FutS>(
        token: &str,
        server: SF,
    ) -> Result<AuthOutcome, ClientAuthError>
    where
        SF: FnOnce(DuplexStream) -> FutS,
        FutS: std::future::Future<Output = ()> + Send + 'static,
    {
        let (client, server_side) = tokio::io::duplex(65536);
        let (mut client_r, client_w) = tokio::io::split(client);
        let srv = tokio::spawn(server(server_side));
        let send_w = std::sync::Arc::new(tokio::sync::Mutex::new(client_w));
        let send = move |msg: &ControlMsg| {
            let w = send_w.clone();
            let msg = msg.clone();
            async move {
                let mut w = w.lock().await;
                let frame = encode_control(&msg).map_err(|e| e.to_string())?;
                w.write_all(&frame).await.map_err(|e| e.to_string())?;
                w.flush().await.map_err(|e| e.to_string())
            }
        };
        let outcome = authenticate(
            &mut client_r,
            send,
            token,
            Duration::from_secs(2),
            &fields(),
        )
        .await;
        srv.await.unwrap();
        outcome
    }

    #[tokio::test]
    async fn test_authenticate_challenge_flow() {
        // 全流程：探测 → 挑战 → 证明 → 回执校验 → Challenged。
        let token = "super-secret-token";
        let token_owned = token.to_string();
        let outcome = run_auth(token, move |mut server| async move {
            let probe = server_read(&mut server).await;
            let ControlMsg::Login {
                token: t,
                auth_nonce: Some(client_nonce),
                auth_digest: None,
                ..
            } = probe
            else {
                panic!("bad probe: {probe:?}");
            };
            // 探测帧不含口令原文（TNL-SEC-006）。
            assert!(t.is_empty());
            let server_nonce = [9u8; 16];
            server_send(&mut server, &ControlMsg::AuthChallenge { nonce: server_nonce }).await;
            let proof = server_read(&mut server).await;
            let ControlMsg::Login {
                token: t2,
                auth_nonce,
                auth_digest: Some(d),
                ..
            } = proof
            else {
                panic!("bad proof: {proof:?}");
            };
            assert!(t2.is_empty());
            assert_eq!(auth_nonce, Some(client_nonce));
            assert_eq!(
                d,
                client_digest(token_owned.as_bytes(), &server_nonce, &client_nonce)
            );
            let receipt = server_digest(token_owned.as_bytes(), &client_nonce);
            server_send(
                &mut server,
                &ControlMsg::LoginResp {
                    ok: true,
                    err: None,
                    server_version: PROTOCOL_VERSION.to_string(),
                    auth_digest: Some(receipt),
                },
            )
            .await;
        })
        .await
        .unwrap();
        assert_eq!(outcome, AuthOutcome::Challenged);
    }

    #[tokio::test]
    async fn test_authenticate_forged_receipt_rejected() {
        // T4：伪造回执（错误 server_digest）→ 客户端拒绝。
        let err = run_auth("super-secret-token", |mut server| async move {
            let _ = server_read(&mut server).await; // 探测
            server_send(&mut server, &ControlMsg::AuthChallenge { nonce: [1u8; 16] }).await;
            let _ = server_read(&mut server).await; // 证明（不校验）
            server_send(
                &mut server,
                &ControlMsg::LoginResp {
                    ok: true,
                    err: None,
                    server_version: PROTOCOL_VERSION.to_string(),
                    auth_digest: Some(vec![0xde, 0xad, 0xbe, 0xef]), // 伪造回执
                },
            )
            .await;
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ClientAuthError::ServerReceiptMismatch));
    }

    #[tokio::test]
    async fn test_authenticate_legacy_fail_closed() {
        // fail-closed（TNL-SEC-008）：带口令客户端连未认证（legacy）服务器
        // → LegacyServerRejected；无口令客户端 → Legacy 继续。
        let err = run_auth("secret-token", |mut server| async move {
            let _ = server_read(&mut server).await; // 探测
            server_send(
                &mut server,
                &ControlMsg::LoginResp {
                    ok: true,
                    err: None,
                    server_version: PROTOCOL_VERSION.to_string(),
                    auth_digest: None, // 未挑战直接 ok（legacy 服务器）
                },
            )
            .await;
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ClientAuthError::LegacyServerRejected));

        let outcome = run_auth("", |mut server| async move {
            let _ = server_read(&mut server).await; // 探测
            server_send(
                &mut server,
                &ControlMsg::LoginResp {
                    ok: true,
                    err: None,
                    server_version: PROTOCOL_VERSION.to_string(),
                    auth_digest: None,
                },
            )
            .await;
        })
        .await
        .unwrap();
        assert_eq!(outcome, AuthOutcome::Legacy);
    }

    #[tokio::test]
    async fn test_authenticate_no_token_fail_closed() {
        // fail-closed（TNL-SEC-008）：无口令客户端连需口令的服务器 →
        // NoTokenForChallenge（不发送证明）。
        let err = run_auth("", |mut server| async move {
            let _ = server_read(&mut server).await; // 探测
            server_send(&mut server, &ControlMsg::AuthChallenge { nonce: [2u8; 16] }).await;
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ClientAuthError::NoTokenForChallenge));
    }

    #[tokio::test]
    async fn test_wire_frames_contain_no_token_bytes() {
        // TNL-SEC-006 验收：探测帧 + 证明帧均不含 token 原文字节。
        let token = "hunter2-wire-leak-check";
        let token_owned = token.to_string();
        let outcome = run_auth(token, move |mut server| async move {
            // 读探测帧并抓原始字节（read_frame 已剥离帧头，raw 帧 = 头 + 负载）。
            let raw = read_raw_frame(&mut server).await;
            assert!(!raw.windows(token_owned.len()).any(|w| w == token_owned.as_bytes()));
            // 解码探测帧拿 client_nonce（回执计算用）。
            let (ty, payload) = crate::protocol::decode_frame(&raw).unwrap();
            let client_nonce = match crate::protocol::decode_control(ty, payload).unwrap() {
                ControlMsg::Login {
                    auth_nonce: Some(n),
                    ..
                } => n,
                other => panic!("bad probe: {other:?}"),
            };
            server_send(&mut server, &ControlMsg::AuthChallenge { nonce: [5u8; 16] }).await;
            let raw2 = read_raw_frame(&mut server).await;
            assert!(!raw2.windows(token_owned.len()).any(|w| w == token_owned.as_bytes()));
            // 证明帧负载可正常解码（证明不含口令原文）。
            let (ty, payload) = crate::protocol::decode_frame(&raw2).unwrap();
            let msg = crate::protocol::decode_control(ty, payload).unwrap();
            assert!(matches!(
                msg,
                ControlMsg::Login { auth_digest: Some(_), .. }
            ));
            // 回执（双向认证收尾，authenticate 等待 LoginResp）。
            let receipt = server_digest(token_owned.as_bytes(), &client_nonce);
            server_send(
                &mut server,
                &ControlMsg::LoginResp {
                    ok: true,
                    err: None,
                    server_version: PROTOCOL_VERSION.to_string(),
                    auth_digest: Some(receipt),
                },
            )
            .await;
        })
        .await
        .unwrap();
        assert_eq!(outcome, AuthOutcome::Challenged);
    }

    /// 读原始帧字节（[type:u8][len:u32 BE][payload]）。
    async fn read_raw_frame(stream: &mut DuplexStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut header = [0u8; crate::protocol::FRAME_HEADER_LEN];
        stream.read_exact(&mut header).await.unwrap();
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        let mut raw = header.to_vec();
        raw.extend_from_slice(&payload);
        raw
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
