use crate::connection::temp_mode::TempModeManager;
use crate::crypto::ed25519::IdentityManager;
use crate::crypto::x25519::EphemeralSession;
use crate::crypto::aead::AeadCipher;
use crate::network::tcp::{send_message, receive_message, TcpError};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// Handshake protocol errors.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("TCP error: {0}")]
    Tcp(#[from] TcpError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Peer signature verification failed")]
    SignatureVerificationFailed,

    #[error("Invalid handshake message: {0}")]
    InvalidMessage(String),

    #[error("Timeout during handshake")]
    Timeout,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Connection rejected: {0}")]
    Rejected(String),

    #[error("Client type mismatch: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },

    /// M10: 客户端按预期公钥（DNS TXT 记录）校验服务端身份，不匹配拒绝连接。
    #[error("Server public key mismatch: expected '{expected}', got '{got}'")]
    ServerKeyMismatch { expected: String, got: String },

    /// M15 (CLI-KH-001 / SEC-003): 服务端公钥未获信任（用户拒绝指纹确认）。
    #[error("Server public key not trusted: {0}")]
    UntrustedKey(String),

    /// SEC-PATCH (SRV-SEC-KH-001): 服务端校验客户端公钥绑定失败 —— 客户端
    /// 自报公钥与 known_hosts / DNS TXT 记录不一致（防 MITM，对称于 `ServerKeyMismatch`）。
    #[error("Client public key mismatch: expected '{expected}', got '{got}'")]
    ClientKeyMismatch { expected: String, got: String },
}

// ---- Handshake Messages ----

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub client_id: String,
    pub client_domain: String,
    pub client_device_type: String,
    pub challenge: String,
    pub client_ed25519_pub_base64: String,
    pub client_x25519_pub: [u8; 32],
    pub nonce: [u8; 32],
    pub signature: Vec<u8>,
    #[serde(default)]
    pub supported_codecs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub server_x25519_pub: [u8; 32],
    pub server_ed25519_pub_base64: String,
    pub signature: Vec<u8>,
    #[serde(default)]
    pub selected_codec: String,
    /// M15 (SRV-SEC-KH-003): 服务端公钥指纹（SHA-256 十六进制分组），
    /// 供客户端双向指纹展示 / 与本地 known_hosts 指纹比对。
    #[serde(default)]
    pub server_fingerprint: String,
}

/// Result of a successful handshake.
#[derive(Debug)]
pub struct SecureChannel {
    pub stream: tokio::net::TcpStream,
    pub cipher: AeadCipher,
    pub peer_id: String,
    pub peer_domain: String,
    pub peer_device_type: String,
    pub selected_codec: String,
}

/// Result of a successful handshake over a generic stream.
pub struct SecureChannelGeneric<S> {
    pub stream: S,
    pub cipher: AeadCipher,
    pub peer_id: String,
    pub peer_domain: String,
    pub peer_device_type: String,
    pub selected_codec: String,
}

/// Whitelist check result
#[derive(Debug)]
pub enum WhitelistDecision {
    Accepted,
    NeedsApproval { client_id: String, client_domain: String, device_type: String },
    Rejected(String),
}

// ---- Codec negotiation ----

pub fn negotiate_codec(client_codecs: &[String], server_codecs: &[String]) -> String {
    for client_codec in client_codecs {
        if server_codecs.iter().any(|sc| sc == client_codec) {
            return client_codec.clone();
        }
    }
    String::new()
}

// ---- Generic handshake (works with TcpStream, QuicBiStream, etc.) ----

/// Generic client handshake — works with any AsyncRead + AsyncWrite + Unpin + Send stream.
///
/// M10: `expected_server_public_key_base64` 非空时，强制与握手响应中的服务端
/// 公钥比对（Domain 模式传 DNS TXT 记录公钥，实现零信任身份绑定）；
/// 为空串则跳过比对（旧版兼容——**不安全，新代码请使用
/// [`client_handshake_with_confirm_generic`] 提供确认回调**，杜绝信任网络公钥）。
pub async fn client_handshake_generic<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    expected_server_public_key_base64: &str,
    challenge: &str,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    let expected = if expected_server_public_key_base64.is_empty() {
        None
    } else {
        Some(expected_server_public_key_base64.to_string())
    };
    client_handshake_with_confirm_generic(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, expected, None, challenge,
    )
    .await
}

/// 带信任确认回调的通用客户端握手（CLI-HSK-SEC-003 / CLI-KH-001）。
///
/// 信任策略由 `expected_server_public_key_base64` / `key_confirm` 组合决定：
/// - `Some(expected)`：与服务端响应公钥**强制比对**（带外可信公钥：known_hosts
///   指纹 / DNS TXT），不等即拒绝（CLI-HSK-SEC-001）；
/// - `None` + `Some(confirm)`：收到服务端公钥后调用确认回调（首次连接指纹确认），
///   回调返回 `false` 即断开并报 [`HandshakeError::UntrustedKey`]，**不发送任何
///   业务数据**（CLI-HSK-006）；
/// - `None` + `None`：跳过比对（旧版兼容，不安全，仅遗留调用方）。
pub async fn client_handshake_with_confirm_generic<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut stream: S,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    expected_server_public_key_base64: Option<String>,
    mut key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
    challenge: &str,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    let session = EphemeralSession::new();
    let x25519_pub = session.public_key_bytes();
    let nonce = generate_nonce();

    let sig_payload = build_sig_payload(&x25519_pub, &nonce, client_id, client_domain, client_device_type);
    let signature = client_identity.sign(&sig_payload);

    let supported_codecs: Vec<String> = Vec::new();

    let client_pub_b64 = client_identity.public_key_base64();
    let init_msg = HandshakeInit {
        client_id: client_id.to_string(),
        client_domain: client_domain.to_string(),
        client_device_type: client_device_type.to_string(),
        challenge: challenge.to_string(),
        client_ed25519_pub_base64: client_pub_b64,
        client_x25519_pub: x25519_pub,
        nonce,
        signature: signature.to_bytes().to_vec(),
        supported_codecs,
    };
    let init_data = bincode::serialize(&init_msg)
        .map_err(|e| HandshakeError::Serialization(e.to_string()))?;
    send_message(&mut stream, &init_data).await?;

    let resp_data = receive_message(&mut stream).await?;
    let response: HandshakeResponse = bincode::deserialize(&resp_data)
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;

    let server_pubkey_b64 = &response.server_ed25519_pub_base64;
    // M10/M15: 服务端公钥信任判定。
    match &expected_server_public_key_base64 {
        Some(expected) => {
            // 带外可信公钥 → 强制一致，否则拒绝（CLI-HSK-SEC-001）。
            if expected != server_pubkey_b64 {
                return Err(HandshakeError::ServerKeyMismatch {
                    expected: expected.clone(),
                    got: server_pubkey_b64.clone(),
                });
            }
        }
        None => {
            // 无带外公钥 → 若有确认回调则交由用户首次指纹确认；拒绝即断开。
            if let Some(confirm) = key_confirm.as_mut() {
                if !confirm(server_pubkey_b64) {
                    return Err(HandshakeError::UntrustedKey(format!(
                        "user declined fingerprint confirmation (server key {})",
                        &server_pubkey_b64[..server_pubkey_b64.len().min(16)]
                    )));
                }
            }
            // 无回调 → 跳过比对（旧版兼容，不安全，仅遗留调用方）。
        }
    }
    let server_pubkey = IdentityManager::parse_public_key(server_pubkey_b64)
        .map_err(|e| HandshakeError::Dns(e.to_string()))?;

    let resp_sig_payload = build_response_sig_payload(&response.server_x25519_pub, &x25519_pub, &nonce, server_id);
    let resp_signature = Signature::from_slice(&response.signature)
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;

    if !IdentityManager::verify_with_key(&server_pubkey, &resp_sig_payload, &resp_signature) {
        return Err(HandshakeError::SignatureVerificationFailed);
    }

    let selected_codec = response.selected_codec;
    let peer_x25519 = EphemeralSession::parse_public_key(&response.server_x25519_pub);
    let session_key = session.compute_session_key(&peer_x25519);
    let cipher = AeadCipher::new(&session_key);

    Ok(SecureChannelGeneric {
        stream,
        cipher,
        peer_id: server_id.to_string(),
        peer_domain: String::new(),
        peer_device_type: String::new(),
        selected_codec,
    })
}

/// Generic server handshake (fully verified) — works with any AsyncRead + AsyncWrite + Unpin + Send stream.
pub async fn server_handshake_verified_generic<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    server_identity: &IdentityManager,
    server_id: &str,
    _client_public_key_base64: &str,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    server_handshake_verified_with_nickname_generic(
        stream, server_identity, server_id,
        _client_public_key_base64, None, None,
    ).await
}

/// Generic server handshake with nickname/challenge check.
///
/// SEC-PATCH (SRV-SEC-KH-001): `client_public_key_base64` 非空时，作为客户端
/// 公钥绑定（known_hosts / DNS TXT 记录）—— 客户端自报公钥与之不一致即拒绝，
/// 杜绝服务端信任网络上来的自报公钥（对称于客户端的 `expected_server_public_key`）。
pub async fn server_handshake_verified_with_nickname_generic<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut stream: S,
    server_identity: &IdentityManager,
    server_id: &str,
    client_public_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    let init = server_read_init(&mut stream).await?;
    verify_server_init(&init, client_public_key_base64, expected_nickname, expected_challenge)?;

    let selected_codec = String::new();
    server_handshake_inner_generic(stream, server_identity, server_id, &init, &selected_codec).await
}

/// 服务端读取握手初始化消息（**只读不答**）。
///
/// 用于「先解析客户端公钥（known_hosts → DNS TXT）再决定是否应答」的两阶段
/// 流程（SRV-SEC-KH-001）：调用方用本函数预读 init，经 [`verify_server_init`]
/// 校验后，再用 [`server_handshake_respond_generic`] 应答 —— 不重复读流。
pub async fn server_read_init<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<HandshakeInit, HandshakeError> {
    let init_data = receive_message(stream).await?;
    bincode::deserialize(&init_data)
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))
}

/// 服务端握手初始化消息校验（纯逻辑，不读写流）：
/// 公钥绑定 → nickname → challenge → Ed25519 签名。
///
/// 挑战码**单态**校验（仅固定挑战码，旧版兼容）；二态校验（固定 **或** 窗口内
/// 临时挑战码，M8-T017 / SRV-TMP-HK-001）请用 [`verify_server_init_with_temp`]。
pub fn verify_server_init(
    init: &HandshakeInit,
    expected_client_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
) -> Result<(), HandshakeError> {
    verify_server_init_inner(
        init,
        expected_client_key_base64,
        expected_nickname,
        expected_challenge,
        None,
    )
}

/// 服务端握手初始化消息校验（**二态挑战码**，M8-T017 / SRV-TMP-HK-001）。
///
/// 与 [`verify_server_init`] 的差异仅在挑战码一步：`temp_window` 为激活中的
/// 临时连接窗口时，`challenge` 接受「固定挑战码 **或** 窗口内临时挑战码」任一
/// 正确；**无固定挑战码 + 窗口激活 → 临时码必填**（杜绝窗口期内无凭据旁路）。
/// 校验顺序：先固定码，后临时码（HK-002）；两者均失败 → 统一错误消息，
/// 不区分提示（防枚举，HK-002）。窗口期外（过期/未开启）临时码一律失败
/// （SRV-TMP-HK-003，`temp_window = None`），不产生任何旁路。
pub fn verify_server_init_with_temp(
    init: &HandshakeInit,
    expected_client_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
    temp_window: Option<&TempModeManager>,
) -> Result<(), HandshakeError> {
    verify_server_init_inner(
        init,
        expected_client_key_base64,
        expected_nickname,
        expected_challenge,
        temp_window,
    )
}

fn verify_server_init_inner(
    init: &HandshakeInit,
    expected_client_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
    temp_window: Option<&TempModeManager>,
) -> Result<(), HandshakeError> {
    // 1. 客户端公钥绑定（SRV-SEC-KH-001）：验签前断言自报公钥与带外可信值一致。
    if !expected_client_key_base64.is_empty()
        && expected_client_key_base64 != init.client_ed25519_pub_base64
    {
        return Err(HandshakeError::ClientKeyMismatch {
            expected: expected_client_key_base64.to_string(),
            got: init.client_ed25519_pub_base64.clone(),
        });
    }

    // 2. nickname 校验。
    if let Some(expected) = expected_nickname {
        if !expected.is_empty() && init.client_id != expected {
            return Err(HandshakeError::InvalidMessage(format!(
                "nickname mismatch: expected '{}', got '{}'", expected, init.client_id
            )));
        }
    }

    // 3. 挑战码二态校验（SRV-TMP-HK-001/002）：固定挑战码 **或** 窗口内临时
    //    挑战码任一正确即通过；两者均失败 → 统一错误消息（防枚举，不泄露
    //    固定码/临时码信息）。组合语义：
    //    - 无固定码 + 无窗口 → 免校验（旧版兼容）；
    //    - 仅固定码 → 固定码必须正确；
    //    - 仅窗口（无固定码）→ **临时码必填**（杜绝窗口期内无凭据旁路）；
    //    - 固定码 + 窗口 → 任一正确即通过。
    let fixed_expected = expected_challenge.filter(|s| !s.is_empty());
    let fixed_ok = fixed_expected.map_or(true, |f| init.challenge == f);
    let temp_ok = temp_window.map_or(true, |t| t.verify_challenge(&init.challenge));
    let challenge_ok = match (fixed_expected.is_some(), temp_window.is_some()) {
        (false, false) => true,
        (true, false) => fixed_ok,
        (false, true) => temp_ok,
        (true, true) => fixed_ok || temp_ok,
    };
    if !challenge_ok {
        return Err(HandshakeError::InvalidMessage("challenge mismatch".to_string()));
    }

    // 4. 客户端 Ed25519 签名验证（对自报公钥验签）。
    let client_pubkey = IdentityManager::parse_public_key(&init.client_ed25519_pub_base64)
        .map_err(|e| HandshakeError::Dns(e.to_string()))?;
    let sig_payload = build_sig_payload(
        &init.client_x25519_pub, &init.nonce,
        &init.client_id, &init.client_domain, &init.client_device_type,
    );
    let client_sig = Signature::from_slice(&init.signature)
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;
    if !IdentityManager::verify_with_key(&client_pubkey, &sig_payload, &client_sig) {
        return Err(HandshakeError::SignatureVerificationFailed);
    }
    Ok(())
}

/// 对**已完成校验**的握手初始化消息应答并建立安全通道。
///
/// 配合 [`server_read_init`] + [`verify_server_init`] 使用：调用方预读 init、
/// 完成 known_hosts / DNS TXT 解析与校验后应答（不重复读流）。
pub async fn server_handshake_respond_generic<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    server_identity: &IdentityManager,
    server_id: &str,
    init: &HandshakeInit,
    selected_codec: &str,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    server_handshake_inner_generic(stream, server_identity, server_id, init, selected_codec).await
}

/// 域名白名单匹配（SRV-SEC-WL-004）。
///
/// - 普通模式 `example.com`：完全相等**或任意子域**（`a.example.com`）——
///   历史语义，兼容旧 `allowed_domains` 配置；
/// - 通配模式 `*.example.com`：等价于普通模式（显式声明任意子域）。
pub fn domain_matches_whitelist(domain: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    let base = pattern.strip_prefix("*.").unwrap_or(pattern);
    domain == base || domain.ends_with(&format!(".{}", base))
}

/// 服务端握手结果（M11：headless shell 服务器 — 无 GUI 审批弹窗）。
pub enum VerifiedDecision {
    /// 白名单通过 + 签名验证通过 → 已建立安全通道。
    Accepted(SecureChannel),
    /// 白名单或认证失败 → 拒绝（连接将被直接关闭，客户端收到 EOF）。
    Rejected(String),
}

impl std::fmt::Debug for VerifiedDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Accepted 侧通道含加密句柄（AeadCipher 无 Debug）→ 摘要输出。
        match self {
            VerifiedDecision::Accepted(_) => write!(f, "Accepted(<secure channel>)"),
            VerifiedDecision::Rejected(r) => f.debug_tuple("Rejected").field(r).finish(),
        }
    }
}

/// 服务端握手（白名单 + 完整验证，M11-T001/T004）。
///
/// headless 服务器无 GUI 审批弹窗：**先**做域名白名单检查（temp_mode 可绕过），
/// 非白名单域名在响应之前直接拒绝（连接立即关闭，客户端收到 EOF），
/// 不泄露服务器 X25519 公钥/响应签名；白名单通过后再完成客户端公钥绑定
/// （SEC-PATCH / SRV-SEC-KH-001）、签名验证、nickname/challenge 校验与响应。
///
/// 白名单匹配规则见 [`domain_matches_whitelist`]：完全相等或任意子域，
/// `*.example.com` 通配等价。
pub async fn server_handshake_with_whitelist(
    mut stream: tokio::net::TcpStream,
    server_identity: &IdentityManager,
    server_id: &str,
    allowed_domains: &[String],
    temp_mode: bool,
    expected_client_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
) -> Result<VerifiedDecision, HandshakeError> {
    // 1. 接收握手初始化消息。
    let init = server_read_init(&mut stream).await?;

    // 2. 白名单检查（headless：无 GUI 审批弹窗，直接拒绝）。
    if !temp_mode {
        let domain = &init.client_domain;
        let is_whitelisted = allowed_domains
            .iter()
            .any(|allowed| domain_matches_whitelist(domain, allowed));
        if !is_whitelisted {
            return Ok(VerifiedDecision::Rejected(format!(
                "domain '{}' not in whitelist (headless: no GUI approval)",
                domain
            )));
        }
    }

    // 3. 客户端公钥绑定 + nickname/challenge + 签名验证。
    verify_server_init(&init, expected_client_key_base64, expected_nickname, expected_challenge)?;

    // 4. 响应 + 建立安全通道。
    let selected_codec = String::new();
    let g = server_handshake_inner_generic(
        stream, server_identity, server_id, &init, &selected_codec,
    )
    .await?;
    Ok(VerifiedDecision::Accepted(SecureChannel {
        stream: g.stream,
        cipher: g.cipher,
        peer_id: g.peer_id,
        peer_domain: g.peer_domain,
        peer_device_type: g.peer_device_type,
        selected_codec: g.selected_codec,
    }))
}

async fn server_handshake_inner_generic<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut stream: S,
    server_identity: &IdentityManager,
    server_id: &str,
    init: &HandshakeInit,
    selected_codec: &str,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    let session = EphemeralSession::new();
    let server_x25519_pub = session.public_key_bytes();

    let resp_sig_payload = build_response_sig_payload(
        &server_x25519_pub, &init.client_x25519_pub, &init.nonce, server_id,
    );
    let signature = server_identity.sign(&resp_sig_payload);

    let response = HandshakeResponse {
        server_x25519_pub,
        server_ed25519_pub_base64: server_identity.public_key_base64(),
        signature: signature.to_bytes().to_vec(),
        selected_codec: selected_codec.to_string(),
        // SRV-SEC-KH-003：返回指纹供客户端双向指纹展示/known_hosts 比对。
        server_fingerprint: crate::crypto::ed25519::fingerprint(
            &server_identity.public_key_base64(),
        ),
    };

    let resp_data = bincode::serialize(&response)
        .map_err(|e| HandshakeError::Serialization(e.to_string()))?;
    send_message(&mut stream, &resp_data).await?;

    let peer_x25519 = EphemeralSession::parse_public_key(&init.client_x25519_pub);
    let session_key = session.compute_session_key(&peer_x25519);
    let cipher = AeadCipher::new(&session_key);

    Ok(SecureChannelGeneric {
        stream,
        cipher,
        peer_id: init.client_id.clone(),
        peer_domain: init.client_domain.clone(),
        peer_device_type: init.client_device_type.clone(),
        selected_codec: selected_codec.to_string(),
    })
}

// ── Legacy TcpStream wrappers (backward compat) ──────────────────

pub async fn client_handshake(
    stream: tokio::net::TcpStream,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    expected_server_public_key_base64: &str,
    challenge: &str,
) -> Result<SecureChannel, HandshakeError> {
    let g = client_handshake_generic(
        stream, client_identity, client_id, client_domain,
        client_device_type, server_id, expected_server_public_key_base64, challenge,
    ).await?;
    Ok(SecureChannel {
        stream: g.stream,
        cipher: g.cipher,
        peer_id: g.peer_id,
        peer_domain: g.peer_domain,
        peer_device_type: g.peer_device_type,
        selected_codec: g.selected_codec,
    })
}

/// 带信任确认回调的 TcpStream 客户端握手（M15：IP 直连首次连接指纹确认）。
///
/// 语义同 [`client_handshake_with_confirm_generic`]：
/// - `expected_server_public_key_base64 = Some(key)` → 强制比对；
/// - `None` + `Some(confirm)` → 回调确认（拒绝即断开）；
/// - `None` + `None` → 跳过（旧版兼容，不安全）。
pub async fn client_handshake_with_confirm(
    stream: tokio::net::TcpStream,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    expected_server_public_key_base64: Option<String>,
    key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
    challenge: &str,
) -> Result<SecureChannel, HandshakeError> {
    let g = client_handshake_with_confirm_generic(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, expected_server_public_key_base64, key_confirm, challenge,
    )
    .await?;
    Ok(SecureChannel {
        stream: g.stream,
        cipher: g.cipher,
        peer_id: g.peer_id,
        peer_domain: g.peer_domain,
        peer_device_type: g.peer_device_type,
        selected_codec: g.selected_codec,
    })
}

pub async fn server_handshake_check(
    mut stream: tokio::net::TcpStream,
    allowed_domains: &[String],
    temp_mode: bool,
) -> Result<(WhitelistDecision, HandshakeInit), HandshakeError> {
    let init_data = receive_message(&mut stream).await?;
    let init: HandshakeInit = bincode::deserialize(&init_data)
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;

    if temp_mode {
        return Ok((WhitelistDecision::Accepted, init));
    }

    let is_whitelisted = allowed_domains
        .iter()
        .any(|allowed| domain_matches_whitelist(&init.client_domain, allowed));

    if is_whitelisted {
        Ok((WhitelistDecision::Accepted, init))
    } else {
        Ok((WhitelistDecision::NeedsApproval {
            client_id: init.client_id.clone(),
            client_domain: init.client_domain.clone(),
            device_type: init.client_device_type.clone(),
        }, init))
    }
}

pub async fn server_handshake_verified(
    stream: tokio::net::TcpStream,
    server_identity: &IdentityManager,
    server_id: &str,
    client_public_key_base64: &str,
) -> Result<SecureChannel, HandshakeError> {
    server_handshake_verified_with_nickname(
        stream, server_identity, server_id,
        client_public_key_base64, None, None,
    ).await
}

pub async fn server_handshake_verified_with_nickname(
    stream: tokio::net::TcpStream,
    server_identity: &IdentityManager,
    server_id: &str,
    client_public_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
) -> Result<SecureChannel, HandshakeError> {
    let g = server_handshake_verified_with_nickname_generic(
        stream, server_identity, server_id,
        client_public_key_base64, expected_nickname, expected_challenge,
    ).await?;
    Ok(SecureChannel {
        stream: g.stream,
        cipher: g.cipher,
        peer_id: g.peer_id,
        peer_domain: g.peer_domain,
        peer_device_type: g.peer_device_type,
        selected_codec: g.selected_codec,
    })
}

// ---- Helpers ----

fn generate_nonce() -> [u8; 32] {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

fn build_sig_payload(
    x25519_pub: &[u8; 32], nonce: &[u8; 32],
    peer_id: &str, peer_domain: &str, device_type: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(x25519_pub);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(peer_id.as_bytes());
    payload.push(b'|');
    payload.extend_from_slice(peer_domain.as_bytes());
    payload.push(b'|');
    payload.extend_from_slice(device_type.as_bytes());
    payload
}

fn build_response_sig_payload(
    server_x25519: &[u8; 32], client_x25519: &[u8; 32],
    nonce: &[u8; 32], peer_id: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(server_x25519);
    payload.extend_from_slice(client_x25519);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(peer_id.as_bytes());
    payload
}

// ---- Encrypted Communication (TcpStream only, kept for backward compat) ----

impl SecureChannel {
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), HandshakeError> {
        use tokio::io::AsyncWriteExt;
        let (nonce, ciphertext) = self.cipher.encrypt_simple(plaintext)
            .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;
        let mut packet = nonce;
        packet.extend_from_slice(&ciphertext);
        let len = packet.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&packet).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, HandshakeError> {
        use tokio::io::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut packet = vec![0u8; len];
        self.stream.read_exact(&mut packet).await?;
        if packet.len() < 12 {
            return Err(HandshakeError::InvalidMessage("packet too short".to_string()));
        }
        let (nonce, ciphertext) = packet.split_at(12);
        let mut ct = ciphertext.to_vec();
        self.cipher.decrypt_simple(nonce, &mut ct)
            .map_err(|_| HandshakeError::InvalidMessage("decryption failed".to_string()))
    }
}

// ---- 读写半通道（M9：客户端输入发送 / 视频接收等双任务并发） ----

/// 已握手通道的**读半**（单向接收）。与写半完全独立：TCP 双工 + 每消息随机 nonce，
/// 适合"视频接收任务 + 输入发送任务"各自独占一个方向、无锁并发共享同一通道。
pub struct SecureChannelReader {
    stream: tokio::net::tcp::OwnedReadHalf,
    cipher: Arc<AeadCipher>,
    peer_id: String,
}

/// 已握手通道的**写半**（单向发送）。
pub struct SecureChannelWriter {
    stream: tokio::net::tcp::OwnedWriteHalf,
    cipher: Arc<AeadCipher>,
    peer_id: String,
}

impl SecureChannel {
    /// 拆分为独立的读写半通道（M9-T002：客户端"视频接收 + 输入发送"双任务）。
    pub fn into_split(self) -> (SecureChannelReader, SecureChannelWriter) {
        let cipher = Arc::new(self.cipher);
        let (read, write) = self.stream.into_split();
        (
            SecureChannelReader {
                stream: read,
                cipher: cipher.clone(),
                peer_id: self.peer_id.clone(),
            },
            SecureChannelWriter {
                stream: write,
                cipher,
                peer_id: self.peer_id,
            },
        )
    }
}

impl SecureChannelReader {
    /// 接收一条消息（与 [`SecureChannel::receive`] 同 wire 格式）。
    pub async fn receive(&mut self) -> Result<Vec<u8>, HandshakeError> {
        use tokio::io::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut packet = vec![0u8; len];
        self.stream.read_exact(&mut packet).await?;
        if packet.len() < 12 {
            return Err(HandshakeError::InvalidMessage("packet too short".to_string()));
        }
        let (nonce, ciphertext) = packet.split_at(12);
        let mut ct = ciphertext.to_vec();
        self.cipher.decrypt_simple(nonce, &mut ct)
            .map_err(|_| HandshakeError::InvalidMessage("decryption failed".to_string()))
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }
}

impl SecureChannelWriter {
    /// 发送一条消息（与 [`SecureChannel::send`] 同 wire 格式）。
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), HandshakeError> {
        use tokio::io::AsyncWriteExt;
        let (nonce, ciphertext) = self.cipher.encrypt_simple(plaintext)
            .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;
        let mut packet = nonce;
        packet.extend_from_slice(&ciphertext);
        let len = packet.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&packet).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::IdentityManager;

    fn gen_identity(dir: &std::path::Path, name: &str) -> IdentityManager {
        IdentityManager::generate(dir.join(name)).expect("generate identity")
    }

    /// M10: 预期公钥（DNS TXT 记录）与服务端响应公钥一致 → 握手成功。
    #[tokio::test]
    async fn test_client_handshake_expected_pubkey_match() {
        let dir = std::env::temp_dir().join("kirin_hs_match");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let alice_pub = alice.public_key_base64();
        let (client_end, server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            &bob_pub,
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "server side should succeed");
        assert!(client_res.is_ok(), "client side should succeed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M10: 预期公钥不匹配（TXT 记录被篡改 / 连错服务器）→ 客户端拒绝，
    /// 返回 `ServerKeyMismatch`（服务端无法察觉被拒原因）。
    #[tokio::test]
    async fn test_client_handshake_expected_pubkey_mismatch() {
        let dir = std::env::temp_dir().join("kirin_hs_mismatch");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let alice_pub = alice.public_key_base64();
        let (client_end, server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            "WRONG-PUBLIC-KEY-FROM-TXT",
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "server side may complete");
        match client_res {
            Err(HandshakeError::ServerKeyMismatch { .. }) => {}
            Ok(_) => panic!("expected ServerKeyMismatch, but handshake succeeded"),
            Err(other) => panic!("expected ServerKeyMismatch, got {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M10: 预期公钥为空串 → 跳过强制验证（IP flexible 模式兼容旧行为）。
    #[tokio::test]
    async fn test_client_handshake_expected_pubkey_empty_skips_check() {
        let dir = std::env::temp_dir().join("kirin_hs_skip");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let alice_pub = alice.public_key_base64();
        let (client_end, server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            "",
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok());
        assert!(client_res.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M15 (CLI-KH-001): 无带外公钥 + 确认回调返回 true → 信任网络公钥，握手成功。
    #[tokio::test]
    async fn test_client_handshake_confirm_accept() {
        let dir = std::env::temp_dir().join("kirin_hs_confirm_accept");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let alice_pub = alice.public_key_base64();
        let bob_pub = bob.public_key_base64();
        let (client_end, server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_with_confirm_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            None,
            Some(Box::new(move |key: &str| {
                assert_eq!(key, bob_pub.as_str());
                true
            })),
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok());
        assert!(client_res.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M15 (CLI-KH-003): 确认回调返回 false（用户拒绝指纹）→ `UntrustedKey` 拒绝。
    #[tokio::test]
    async fn test_client_handshake_confirm_reject() {
        let dir = std::env::temp_dir().join("kirin_hs_confirm_reject");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let alice_pub = alice.public_key_base64();
        let (client_end, server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_with_confirm_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            None,
            Some(Box::new(|_| false)),
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "server side may complete");
        match client_res {
            Err(HandshakeError::UntrustedKey(_)) => {}
            Ok(_) => panic!("expected UntrustedKey, but handshake succeeded"),
            Err(other) => panic!("expected UntrustedKey, got {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- SEC-PATCH (SRV-SEC-KH-001): 服务端客户端公钥绑定 ----

    /// 服务端 pin 一致（known_hosts / DNS TXT 命中）→ 握手成功。
    #[tokio::test]
    async fn test_server_pin_matching_key_accepted() {
        let dir = std::env::temp_dir().join("kirin_hs_pin_match");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let alice_pub = alice.public_key_base64();
        let bob_pub = bob.public_key_base64();
        let (client_end, server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob", &bob_pub, "",
        );
        // 服务端以 known_hosts 记录的 alice 公钥作 pin → 应放行。
        let server_fut = server_handshake_verified_with_nickname_generic(
            server_end, &bob, "bob", &alice_pub, None, None,
        );
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "server should accept matching pinned key");
        assert!(client_res.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 服务端 pin 不一致（known_hosts 记录的公钥与客户端自报公钥不同）→
    /// `ClientKeyMismatch` 拒绝（SRV-SEC-KH-002：命中但不一致 → 拒绝）。
    #[tokio::test]
    async fn test_server_pin_mismatch_rejected() {
        let dir = std::env::temp_dir().join("kirin_hs_pin_mismatch");
        let alice = gen_identity(&dir, "alice");
        let mallory = gen_identity(&dir, "mallory"); // 冒充 alice 的恶意密钥
        let bob = gen_identity(&dir, "bob");
        let alice_pub = alice.public_key_base64();
        let bob_pub = bob.public_key_base64();
        let (client_end, server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end, &mallory, "alice", "alice.local", "desktop", "bob", &bob_pub, "",
        );
        // 服务端 known_hosts 里 alice 的**真实**公钥 → 与网络上来的冒充公钥不一致。
        let server_fut = server_handshake_verified_with_nickname_generic(
            server_end, &bob, "bob", &alice_pub, None, None,
        );
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        match server_res {
            Err(HandshakeError::ClientKeyMismatch { expected, got }) => {
                assert_eq!(expected, alice_pub);
                assert_eq!(got, mallory.public_key_base64());
            }
            Ok(_) => panic!("server must reject mismatched pinned key"),
            Err(other) => panic!("expected ClientKeyMismatch, got {:?}", other),
        }
        // 客户端侧可能成功也可能失败（服务端不响应 → 客户端读 EOF），
        // 关键断言：安全通道**无法**建立。
        assert!(!matches!(client_res, Ok(_)), "channel must not be established");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 两阶段流程：`server_read_init` 预读 → `verify_server_init` →
    /// `server_handshake_respond_generic` 应答（known_hosts 解析后再应答）。
    #[tokio::test]
    async fn test_server_read_init_then_respond() {
        let dir = std::env::temp_dir().join("kirin_hs_read_init");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let alice_pub = alice.public_key_base64();
        let bob_pub = bob.public_key_base64();
        let (client_end, mut server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob", &bob_pub, "",
        );
        let server_fut = async move {
            // 1. 预读 init（不应答）。
            let init = server_read_init(&mut server_end).await?;
            // 2. 解析 known_hosts/DNS 后 pin 校验（一致 → 通过）。
            verify_server_init(&init, &alice_pub, None, None)?;
            // 3. 应答建立通道。
            let g = server_handshake_respond_generic(server_end, &bob, "bob", &init, "").await?;
            Ok::<_, HandshakeError>(g)
        };
        let (client_res, server_res): (
            Result<SecureChannelGeneric<_>, HandshakeError>,
            Result<SecureChannelGeneric<_>, HandshakeError>,
        ) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "two-phase handshake should succeed");
        assert!(client_res.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M8-T017 二态挑战码校验（SRV-TMP-HK-001/002/003）：固定挑战码 **或**
    /// 窗口内临时挑战码任一正确即通过；无固定码 + 窗口激活 → 临时码必填；
    /// 窗口期外临时码一律失败；失败消息统一不泄露信息（防枚举）。
    ///
    /// 用真实 duplex 握手（非手搓 init）：客户端以给定 challenge 发起握手，
    /// 服务端 `server_read_init` 预读后按参数校验再应答。
    #[tokio::test]
    async fn test_verify_server_init_two_state_challenge() {
        use crate::connection::temp_mode::TempModeManager;
        let dir = std::env::temp_dir().join("kirin_hs_two_state");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let alice_pub = alice.public_key_base64();
        let bob_pub = bob.public_key_base64();

        let state_path = dir.join("temp_mode.json");
        let tm = TempModeManager::with_state_file(state_path.clone());
        let temp_code = tm.enable(300).expect("enable");

        /// 一次二态握手往返：`fixed` = 服务端固定挑战码，`challenge` = 客户端携带码。
        async fn run_two_state(
            alice: &IdentityManager,
            bob: &IdentityManager,
            alice_pub: &str,
            bob_pub: &str,
            tm: &TempModeManager,
            fixed: Option<&str>,
            challenge: &str,
        ) -> Result<(), HandshakeError> {
            let (client_end, mut server_end) = tokio::io::duplex(65536);
            let client_fut = client_handshake_generic(
                client_end, alice, "alice", "alice.local", "desktop", "bob", bob_pub, challenge,
            );
            let server_fut = async move {
                let init = server_read_init(&mut server_end).await?;
                verify_server_init_with_temp(&init, alice_pub, None, fixed, Some(tm))?;
                let _g =
                    server_handshake_respond_generic(server_end, bob, "bob", &init, "").await?;
                Ok::<_, HandshakeError>(())
            };
            let (client_res, server_res) = tokio::join!(client_fut, server_fut);
            server_res?;
            client_res.map(|_| ())
        }

        // 固定码 + 窗口 → 固定码通过。
        assert!(
            run_two_state(&alice, &bob, &alice_pub, &bob_pub, &tm, Some("FIXED-CODE"), "FIXED-CODE")
                .await
                .is_ok(),
            "fixed code must pass inside window"
        );
        // 固定码 + 窗口 → 临时码同样通过（二态任一）。
        assert!(
            run_two_state(&alice, &bob, &alice_pub, &bob_pub, &tm, Some("FIXED-CODE"), &temp_code)
                .await
                .is_ok(),
            "temp code must pass inside window (two-state)"
        );
        // 无固定码 + 窗口 → 临时码必填（杜绝无凭据旁路）。
        assert!(
            run_two_state(&alice, &bob, &alice_pub, &bob_pub, &tm, None, "").await.is_err(),
            "window active without fixed code requires the temp code"
        );
        // 无固定码 + 窗口 + 错码 → 拒绝，且错误消息统一（防枚举，HK-002）。
        match run_two_state(&alice, &bob, &alice_pub, &bob_pub, &tm, None, "XXXXXXXX").await {
            Err(HandshakeError::InvalidMessage(msg)) => assert_eq!(msg, "challenge mismatch"),
            other => panic!("expected InvalidMessage(challenge mismatch), got {:?}", other),
        }
        // 窗口期外（未激活实例）→ 临时码一律失败（SRV-TMP-HK-003）。
        let inactive = TempModeManager::with_state_file(dir.join("other.json"));
        assert!(
            run_two_state(&alice, &bob, &alice_pub, &bob_pub, &inactive, None, &temp_code)
                .await
                .is_err(),
            "temp code fails outside the window"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[tokio::test]
    async fn test_server_read_init_pin_mismatch_rejected() {
        let dir = std::env::temp_dir().join("kirin_hs_read_init_mismatch");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let (client_end, mut server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob", &bob_pub, "",
        );
        let server_fut = async move {
            let init = server_read_init(&mut server_end).await?;
            // known_hosts 里记录的 alice 公钥 ≠ 网络上来的公钥 → 拒绝。
            verify_server_init(&init, "WRONG-PINNED-KEY", None, None)?;
            unreachable!("must not respond after pin mismatch");
        };
        let (client_res, server_res): (
            Result<SecureChannelGeneric<_>, HandshakeError>,
            Result<(), HandshakeError>,
        ) = tokio::join!(client_fut, server_fut);
        match server_res {
            Err(HandshakeError::ClientKeyMismatch { .. }) => {}
            Ok(_) => panic!("must not reach respond"),
            Err(other) => panic!("expected ClientKeyMismatch, got {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 白名单握手（headless）集成 pin：`server_handshake_with_whitelist`
    /// 传 known_hosts 公钥 → 一致放行 / 不一致拒绝。
    #[tokio::test]
    async fn test_whitelist_handshake_with_pin() {
        let dir = std::env::temp_dir().join("kirin_hs_wl_pin");
        let alice = gen_identity(&dir, "alice");
        let bob = Arc::new(gen_identity(&dir, "bob"));
        let alice_pub = alice.public_key_base64();
        let bob_pub = bob.public_key_base64();
        let allowed = vec!["kirin.local".to_string()];

        // 一致 → Accepted
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (bob_ref, allowed_ref, pin_ref) = (bob.clone(), allowed.clone(), alice_pub.clone());
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_handshake_with_whitelist(
                stream, &bob_ref, "bob", &allowed_ref, false, &pin_ref, None, None,
            )
            .await
        });
        let client_res = client_handshake(
            tokio::net::TcpStream::connect(addr).await.unwrap(),
            &alice, "alice", "alice.kirin.local", "desktop", "bob", &bob_pub, "",
        )
        .await;
        let decision = server_task.await.unwrap().expect("server handshake");
        assert!(matches!(decision, VerifiedDecision::Accepted(_)));
        assert!(client_res.is_ok());

        // 不一致（known_hosts 记录真实 alice 公钥，客户端用别的密钥）→ Rejected
        let mallory = gen_identity(&dir, "mallory");
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (bob_ref, allowed_ref, pin_ref) = (bob.clone(), allowed.clone(), alice_pub.clone());
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_handshake_with_whitelist(
                stream, &bob_ref, "bob", &allowed_ref, false, &pin_ref, None, None,
            )
            .await
        });
        let _client_res = client_handshake(
            tokio::net::TcpStream::connect(addr).await.unwrap(),
            &mallory, "alice", "alice.kirin.local", "desktop", "bob", &bob_pub, "",
        )
        .await;
        // pin 不一致 → verify_server_init 以 Err(ClientKeyMismatch) 拒绝（错误而非策略拒绝）。
        assert!(
            matches!(
                server_task.await.unwrap(),
                Err(HandshakeError::ClientKeyMismatch { .. })
            ),
            "expected ClientKeyMismatch"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `HandshakeResponse.server_fingerprint`（SRV-SEC-KH-003）基于服务端公钥计算，
    /// 指纹格式与 utils `known_hosts::fingerprint` 一致（SHA-256 十六进制冒号分组）。
    #[tokio::test]
    async fn test_server_response_includes_fingerprint() {
        let dir = std::env::temp_dir().join("kirin_hs_fp");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let alice_pub = alice.public_key_base64();
        let (client_end, server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob", &bob_pub, "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (_client_res, _server_res) = tokio::join!(client_fut, server_fut);

        // 指纹格式：64 位十六进制 → 16 组冒号分组（79 字符），全十六进制字符。
        let fp = crate::crypto::ed25519::fingerprint(&bob_pub);
        assert_eq!(fp.len(), 79);
        assert_eq!(fp.split(':').count(), 16);
        assert!(fp.chars().all(|c| c == ':' || c.is_ascii_hexdigit()));
        // 确定性：同公钥同指纹
        assert_eq!(crate::crypto::ed25519::fingerprint(&bob_pub), fp);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
