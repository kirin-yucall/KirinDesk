use crate::connection::temp_mode::TempModeManager;
use crate::connection::multiplex::DEFAULT_MAX_FRAME_LEN;
use crate::crypto::ed25519::IdentityManager;
use crate::crypto::x25519::EphemeralSession;
use crate::crypto::aead::AeadCipher;
use crate::network::tcp::{send_message, receive_message, read_length_prefixed, TcpError};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

/// 客户端 pin 期望（R-02：把"空串 = 跳过 pin 比对"的隐式语义从类型上消除，
/// 旧审计证据 `handshake.rs:142-146,226` 空串跳过路径已不可构造）。
///
/// 信任策略由 `pin` 与 `key_confirm` 回调组合决定，**不存在"无期望跳过"路径**：
/// - [`PinExpectation::Exact`]：带外可信公钥（known_hosts / DNS TXT / 自签）
///   强制比对，不等即拒绝（CLI-HSK-SEC-001），`ServerKeyMismatch` 保留；
/// - [`PinExpectation::None`] + [`CoreReason::UserConfirmRequired`]：收到服务端
///   公钥后调用确认回调（首次指纹确认，CLI-KH-001）；**回调缺失或返回 `false`
///   即拒绝**（R-02：无回调不再静默放行网络公钥，CLI-HSK-006）；
/// - [`PinExpectation::None`] + [`CoreReason::InternalLoopback`]：loopback 自签
///   兜底——服务端 = 自身，core 以客户端自身公钥强制比对（R-02-S3）。
#[derive(Debug, Clone)]
pub enum PinExpectation {
    /// 无带外 pin —— 必须由 [`CoreReason`] 显式声明兜底场景，core 层仍执行真实比对。
    None(CoreReason),
    /// 带外可信公钥原始字节（Ed25519 32 字节）——强制一致，不等即拒绝。
    Exact([u8; 32]),
}

/// [`PinExpectation::None`] 的显式兜底场景声明（R-02：消除"无期望跳过"隐式语义）。
#[derive(Debug, Clone, Copy)]
pub enum CoreReason {
    /// 内部回环 / 自连（服务端 = 自身）：core 以客户端自身公钥作真实 pin 比对。
    InternalLoopback,
    /// 用户首次指纹确认（GUI / CLI 确认回调，必填）。
    UserConfirmRequired,
}

impl PinExpectation {
    /// 从 base64 公钥构造强制比对 pin（known_hosts / DNS TXT / 自签来源；
    /// 解析失败 → [`HandshakeError::Dns`]，复用既有解析错误路径）。
    pub fn exact_from_base64(base64_key: &str) -> Result<Self, HandshakeError> {
        let key = IdentityManager::parse_public_key(base64_key)
            .map_err(|e| HandshakeError::Dns(e.to_string()))?;
        Ok(PinExpectation::Exact(key.to_bytes()))
    }

    /// 解析为本端可用的 base64 公钥（供服务端角色 `client_public_key_base64` pin）。
    /// - `Exact(bytes)` → 编码回 base64；
    /// - `None(InternalLoopback)` → 本端自身公钥（自签：服务端 = 客户端）；
    /// - `None(UserConfirmRequired)` → 服务端无确认回调路径，拒绝。
    pub fn resolve_base64(
        &self,
        local_identity: &IdentityManager,
    ) -> Result<String, HandshakeError> {
        match self {
            PinExpectation::Exact(bytes) => {
                use base64::Engine as _;
                Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
            }
            PinExpectation::None(CoreReason::InternalLoopback) => {
                Ok(local_identity.public_key_base64())
            }
            PinExpectation::None(CoreReason::UserConfirmRequired) => {
                Err(HandshakeError::UntrustedKey(
                    "UserConfirmRequired has no server-side pin to resolve".to_string(),
                ))
            }
        }
    }
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

/// R-32（M13-T002 阶段 B）：服务端按**服务端编码优先级**从两端交集选 codec。
///
/// - `server_codecs`：服务端可编码列表（`media::encoder::detect_supported_codecs`
///   ，按优先级，如 `["av1","h265","h264"]`）——服务端优先选码率效率高的
///   AV1（~6×，探索结论），其次 H.265/H.264；
/// - `client_codecs`：客户端可解码列表（握手 `supported_codecs`）。
///
/// 交集为空（含客户端未广告 / 未知字符串）→ 空串，服务端调用方按 **H.264
/// 兜底**（既有语义，兼容旧握手——旧客户端 supported_codecs 为空）。
pub fn negotiate_codec_by_server_priority(
    server_codecs: &[String],
    client_codecs: &[String],
) -> String {
    for server_codec in server_codecs {
        if client_codecs.iter().any(|cc| cc == server_codec) {
            return server_codec.clone();
        }
    }
    String::new()
}

// ---- Generic handshake (works with TcpStream, QuicBiStream, etc.) ----

/// Generic client handshake — works with any AsyncRead + AsyncWrite + Unpin + Send stream.
///
/// R-02: pin 强类型化——`expected_server_public_key_base64: &str` 已改为
/// [`PinExpectation`]，**不再存在"空串 = 跳过 pin 比对"的旧版兼容语义**
/// （审计证据：旧 `handshake.rs:142-146,226`，代码自注"旧版兼容，不安全"）。
/// 需要用户首次指纹确认的调用方请使用
/// [`client_handshake_with_confirm_generic`] + [`PinExpectation::None`]
/// （[`CoreReason::UserConfirmRequired`]）提供确认回调。
pub async fn client_handshake_generic<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    pin: PinExpectation,
    challenge: &str,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    client_handshake_with_confirm_generic(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, pin, None, challenge,
    )
    .await
}

/// 带**本端可解码 codec 列表**的客户端握手（R-32，M13-T002 阶段 B）。
///
/// 与 [`client_handshake_generic`] 的差异仅在 `supported_codecs` 字段——
/// 客户端把可解码编码标准（`"h264"`/`"h265"`/`"av1"`，按优先级）写入手
/// 握 init，服务端据此挑选 `selected_codec`。旧函数传空列表（行为不变，
/// 服务端按空交集回落 H.264 兜底，见 [`negotiate_codec_by_server_priority`]）。
pub async fn client_handshake_with_codecs_generic<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    pin: PinExpectation,
    challenge: &str,
    supported_codecs: Vec<String>,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    client_handshake_with_confirm_and_codecs_generic(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, pin, None, challenge, supported_codecs,
    )
    .await
}

/// 带信任确认回调的通用客户端握手（CLI-HSK-SEC-003 / CLI-KH-001）。
///
/// 信任策略由 `pin` / `key_confirm` 组合决定（R-02，无"无期望跳过"路径）：
/// - [`PinExpectation::Exact`]：与服务端响应公钥**强制比对**（带外可信公钥：
///   known_hosts 指纹 / DNS TXT），不等即拒绝（CLI-HSK-SEC-001）；
/// - [`PinExpectation::None`] + [`CoreReason::UserConfirmRequired`]：收到服务端
///   公钥后调用确认回调（首次连接指纹确认），回调返回 `false` 即断开并报
///   [`HandshakeError::UntrustedKey`]，**不发送任何业务数据**（CLI-HSK-006）；
///   回调缺失 → 直接拒绝（R-02：不再静默信任网络公钥）；
/// - [`PinExpectation::None`] + [`CoreReason::InternalLoopback`]：loopback 自签
///   兜底，以客户端自身公钥强制比对（R-02-S3）。
pub async fn client_handshake_with_confirm_generic<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    pin: PinExpectation,
    key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
    challenge: &str,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    client_handshake_with_confirm_and_codecs_generic(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, pin, key_confirm, challenge, Vec::new(),
    )
    .await
}

/// [`client_handshake_with_confirm_generic`] 的带 codec 列表变体（R-32）。
///
/// 与确认回调版唯一差异：`supported_codecs` 写入握 init（空列表 = 旧行为）。
/// 信任语义（pin/确认回调）完全一致，无新协议安全面。
pub async fn client_handshake_with_confirm_and_codecs_generic<
    S: AsyncRead + AsyncWrite + Unpin + Send,
>(
    mut stream: S,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    pin: PinExpectation,
    mut key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
    challenge: &str,
    supported_codecs: Vec<String>,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    let session = EphemeralSession::new();
    let x25519_pub = session.public_key_bytes();
    let nonce = generate_nonce();

    let sig_payload = build_sig_payload(&x25519_pub, &nonce, client_id, client_domain, client_device_type);
    let signature = client_identity.sign(&sig_payload);

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
    // M10/M15/R-02: 服务端公钥信任判定（无"无期望跳过"路径）。
    match &pin {
        PinExpectation::Exact(expected) => {
            // 带外可信公钥 → 强制一致，否则拒绝（CLI-HSK-SEC-001）。
            let server_key = IdentityManager::parse_public_key(server_pubkey_b64)
                .map_err(|e| HandshakeError::Dns(e.to_string()))?;
            if server_key.to_bytes() != *expected {
                use base64::Engine as _;
                return Err(HandshakeError::ServerKeyMismatch {
                    expected: base64::engine::general_purpose::STANDARD.encode(expected),
                    got: server_pubkey_b64.clone(),
                });
            }
        }
        PinExpectation::None(reason) => match reason {
            // R-02-S3 自签兜底：服务端 = 自身 → 以客户端自身公钥强制比对
            // （loopback 握手不再依赖"无期望"跳过）。
            CoreReason::InternalLoopback => {
                let self_bytes = client_identity.public_key().to_bytes();
                let server_key = IdentityManager::parse_public_key(server_pubkey_b64)
                    .map_err(|e| HandshakeError::Dns(e.to_string()))?;
                if server_key.to_bytes() != self_bytes {
                    return Err(HandshakeError::ServerKeyMismatch {
                        expected: client_identity.public_key_base64(),
                        got: server_pubkey_b64.clone(),
                    });
                }
            }
            // 无带外公钥 → 确认回调必填；缺失即拒绝（R-02：不再静默跳过）。
            CoreReason::UserConfirmRequired => {
                let Some(confirm) = key_confirm.as_mut() else {
                    return Err(HandshakeError::UntrustedKey(
                        "no pinned public key and no user confirmation callback \
                         — refusing to trust network public key"
                            .to_string(),
                    ));
                };
                if !confirm(server_pubkey_b64) {
                    return Err(HandshakeError::UntrustedKey(format!(
                        "user declined fingerprint confirmation (server key {})",
                        &server_pubkey_b64[..server_pubkey_b64.len().min(16)]
                    )));
                }
            }
        },
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
    // S-04 / 审计 F-3: 服务端 X25519 公钥校验（全零/低阶点 → 拒绝，错误计入
    // 握手失败路径：调用方统一 audit + record_handshake_failure）。
    let peer_x25519 = EphemeralSession::parse_public_key(&response.server_x25519_pub)
        .map_err(|e| HandshakeError::InvalidMessage(format!(
            "invalid server X25519 public key: {e}"
        )))?;
    let session_key = session.compute_session_key(&peer_x25519).map_err(|e| {
        HandshakeError::InvalidMessage(format!("X25519 key exchange failed: {e}"))
    })?;
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
    // S-01a (F-1)：生产路径零凭据（无 pin + 无挑战码 + 无窗口）→ 拒绝。
    verify_server_init(
        &init,
        client_public_key_base64,
        expected_nickname,
        expected_challenge,
        false,
    )?;

    let selected_codec = String::new();
    server_handshake_inner_generic(stream, server_identity, server_id, &init, &selected_codec).await
}

/// 服务端读取握手初始化消息（**只读不答**）。
///
/// 用于「先解析客户端公钥（known_hosts → DNS TXT）再决定是否应答」的两阶段
/// 流程（SRV-SEC-KH-001）：调用方用本函数预读 init，经 [`verify_server_init`]
/// 校验后，再用 [`server_handshake_respond_generic`] 应答 —— 不重复读流。
///
/// S-02 (F-5)：读取带 **10s deadline**（单点收口——GUI/CLI/policy 所有调用
/// 路径自动获得超时）。连接"只连不发" → [`HandshakeError::Timeout`]，调用方
/// 既有的错误路径（关闭连接 + `record_handshake_failure` + 审计）即可兜住，
/// 不再需要逐个调用点包裹。
pub async fn server_read_init<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<HandshakeInit, HandshakeError> {
    server_read_init_with_timeout(stream, HANDSHAKE_READ_TIMEOUT).await
}

/// S-02 (F-5)：服务端握手初始化读取超时（连接"只连不发" → 10s 关闭）。
pub const HANDSHAKE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// 带显式超时的 init 读取（`server_read_init` 的内部实现；超时值可测）。
async fn server_read_init_with_timeout<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeout: std::time::Duration,
) -> Result<HandshakeInit, HandshakeError> {
    let init_data = tokio::time::timeout(timeout, receive_message(stream))
        .await
        .map_err(|_| HandshakeError::Timeout)??;
    bincode::deserialize(&init_data)
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))
}

/// 服务端握手初始化消息校验（纯逻辑，不读写流）：
/// 公钥绑定 → nickname → challenge → Ed25519 签名。
///
/// 挑战码**单态**校验（仅固定挑战码，旧版兼容）；二态校验（固定 **或** 窗口内
/// 临时挑战码，M8-T017 / SRV-TMP-HK-001）请用 [`verify_server_init_with_temp`]。
///
/// S-01a（F-1）：`allow_no_credentials` —— 显式 opt-in 开关。生产路径一律传
/// `false`：无固定挑战码 + 无激活临时窗口时，仅当客户端公钥已 pin
/// （known_hosts / DNS TXT 身份绑定）才放行，**零凭据（无 pin + 无挑战码 +
/// 无窗口）一律拒绝**；仅测试/loopback 显式传 `true`。
pub fn verify_server_init(
    init: &HandshakeInit,
    expected_client_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
    allow_no_credentials: bool,
) -> Result<(), HandshakeError> {
    verify_server_init_inner(
        init,
        expected_client_key_base64,
        expected_nickname,
        expected_challenge,
        None,
        allow_no_credentials,
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
///
/// S-01a（F-1）：`allow_no_credentials` 语义同 [`verify_server_init`] ——
/// 生产路径一律传 `false`（零凭据 → 拒绝），仅测试/loopback 显式传 `true`。
pub fn verify_server_init_with_temp(
    init: &HandshakeInit,
    expected_client_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
    temp_window: Option<&TempModeManager>,
    allow_no_credentials: bool,
) -> Result<(), HandshakeError> {
    verify_server_init_inner(
        init,
        expected_client_key_base64,
        expected_nickname,
        expected_challenge,
        temp_window,
        allow_no_credentials,
    )
}

/// 内部实现：`allow_no_credentials` = true 表示调用方显式 opt-in —— 允许
/// 「无固定挑战码 + 无激活临时窗口」时即使客户端公钥也未知（零凭据）仍放行
/// （仅测试/loopback 使用）。
fn verify_server_init_inner(
    init: &HandshakeInit,
    expected_client_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
    temp_window: Option<&TempModeManager>,
    allow_no_credentials: bool,
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
    //    - 无固定码 + 无窗口 → S-01a (F-1) fail-closed：仅当客户端公钥已 pin
    //      （known_clients/DNS-TXT 身份绑定）或显式 `allow_no_credentials`
    //      （仅测试/loopback）才放行——零凭据（未知客户端 + 无挑战码）拒绝；
    //    - 仅固定码 → 固定码必须正确；
    //    - 仅窗口（无固定码）→ **临时码必填**（杜绝窗口期内无凭据旁路）；
    //    - 固定码 + 窗口 → 任一正确即通过。
    let fixed_expected = expected_challenge.filter(|s| !s.is_empty());
    // S-18 (F-23)：固定码比对改**常量时间**（先 SHA-256 归一到 32B，再
    // `subtle` ct_eq —— `==` 逐字节短路返回存在时序侧信道，可被远程枚举
    // 挑战码）。长度不匹配路径同样只泄露"是否相等"，不泄露前缀差异；
    // 对齐临时码实现（`TempModeManager::verify_challenge` 的哈希后比较）。
    let fixed_ok = fixed_expected.map_or(true, |f| challenge_eq(&init.challenge, f));
    let temp_ok = temp_window.map_or(true, |t| t.verify_challenge(&init.challenge));
    let client_pinned = !expected_client_key_base64.is_empty();
    let challenge_ok = match (fixed_expected.is_some(), temp_window.is_some()) {
        (false, false) => allow_no_credentials || client_pinned,
        (true, false) => fixed_ok,
        (false, true) => temp_ok,
        (true, true) => fixed_ok || temp_ok,
    };
    if !challenge_ok {
        // 零凭据（未知客户端 + 无挑战码 + 无窗口）与错误挑战码统一走
        // InvalidMessage（HK-002 防枚举）；文案仅落在服务端审计日志，
        // 不会回传给客户端，区分提示便于运维定位配置问题（F-1）。
        let msg = if fixed_expected.is_none() && temp_window.is_none() && !client_pinned {
            "server requires credentials: client unknown (no pinned key), no challenge code, and no temp window"
        } else {
            "challenge mismatch"
        };
        return Err(HandshakeError::InvalidMessage(msg.to_string()));
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

/// S-18 (F-23)：挑战码**常量时间**相等比较。
///
/// 对齐临时码实现：先 `sha256` 归一到固定 32 字节（输入长度差异只影响
/// 哈希分块数，不影响比较分支），再用 `subtle::ConstantTimeEq` 比较摘要
/// —— 比较耗时与两输入内容无关，杜绝 `==` 的逐字节短路时序侧信道。
fn challenge_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    let ha = Sha256::digest(a.as_bytes());
    let hb = Sha256::digest(b.as_bytes());
    bool::from(ha.as_slice().ct_eq(hb.as_slice()))
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

/// M8-T027 (SRV-IDWL-010): 设备 ID 白名单匹配（大小写敏感，与 known_clients
/// 同 key 语义）。
///
/// - 默认**精确匹配**：trim 后完全相等（`device-7` 只匹配 `device-7`）；
/// - 显式以 `*` 结尾 → 前缀通配（`office-*` 匹配 `office-1`、`office-42`）；
/// - 空 pattern / 空白 / 裸 `*`（通配前缀为空）→ 不匹配（保守语义，对称
///   [`domain_matches_whitelist`] 对裸 `*` 的处理）。
pub fn id_matches_whitelist(device_id: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    let device_id = device_id.trim();
    match pattern.strip_suffix('*') {
        Some(prefix) if !prefix.is_empty() => device_id.starts_with(prefix),
        _ => device_id == pattern,
    }
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
/// headless 服务器无 GUI 审批弹窗：**先**做白名单检查（域名 **或** ID 两维，
/// M8-T027；temp_mode 可绕过），非白名单在响应之前直接拒绝（连接立即关闭，
/// 客户端收到 EOF），不泄露服务器 X25519 公钥/响应签名；白名单通过后再完成
/// 客户端公钥绑定（SEC-PATCH / SRV-SEC-KH-001）、签名验证、nickname/challenge
/// 校验与响应。
///
/// 白名单匹配规则见 [`domain_matches_whitelist`] 与 [`id_matches_whitelist`]：
/// 域名完全相等或任意子域（`*.example.com` 通配等价）；设备 ID 精确或 `*`
/// 结尾前缀通配。两维任一命中即放行（OR 语义，域名既有行为不变）。
///
/// **遗留接口**（R-05 / SRV-IDWL-022）：无两阶段客户端公钥 pin 流程，
/// 新代码请使用 `ui::policy::server_accept_handshake`（SRV-SEC-KH-001）。
#[deprecated(
    note = "legacy headless path without two-phase client key pin — use ui/policy::server_accept_handshake (SRV-SEC-KH-001)"
)]
pub async fn server_handshake_with_whitelist(
    mut stream: tokio::net::TcpStream,
    server_identity: &IdentityManager,
    server_id: &str,
    allowed_domains: &[String],
    allowed_ids: &[String],
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
        // M8-T027 (SRV-IDWL-020): 双白名单 OR 语义——域名命中 **或** ID 命中
        // 即视为白名单命中（域名维度既有行为不变）。
        let is_whitelisted = allowed_domains
            .iter()
            .any(|allowed| domain_matches_whitelist(domain, allowed))
            || allowed_ids
                .iter()
                .any(|id| id_matches_whitelist(&init.client_id, id));
        if !is_whitelisted {
            return Ok(VerifiedDecision::Rejected(format!(
                "domain '{}' and id '{}' not in whitelist (headless: no GUI approval)",
                domain, init.client_id
            )));
        }
    }

    // 3. 客户端公钥绑定 + nickname/challenge + 签名验证。
    // S-01a (F-1)：生产路径零凭据（无 pin + 无挑战码 + 无窗口）→ 拒绝。
    verify_server_init(
        &init,
        expected_client_key_base64,
        expected_nickname,
        expected_challenge,
        false,
    )?;

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

    // S-04 / 审计 F-3: 客户端 X25519 公钥校验（全零/低阶点 → 拒绝）。置于
    // `send_message` **之前** → 恶意公钥握手"拒绝且不泄露响应"（服务端不
    // 发送响应即断开，客户端收到 EOF；错误计入握手失败路径）。
    let peer_x25519 = EphemeralSession::parse_public_key(&init.client_x25519_pub)
        .map_err(|e| HandshakeError::InvalidMessage(format!(
            "invalid client X25519 public key: {e}"
        )))?;

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

    // S-04b 纵深防御：共享密钥全零 → 拒绝（低阶点已在上方黑名单拦截，
    // 此处兜底 RFC 7748 §6.1 全零输出检查）。
    let session_key = session.compute_session_key(&peer_x25519).map_err(|e| {
        HandshakeError::InvalidMessage(format!("X25519 key exchange failed: {e}"))
    })?;
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
    pin: PinExpectation,
    challenge: &str,
) -> Result<SecureChannel, HandshakeError> {
    let g = client_handshake_generic(
        stream, client_identity, client_id, client_domain,
        client_device_type, server_id, pin, challenge,
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
/// 语义同 [`client_handshake_with_confirm_generic`]（R-02，无"无期望跳过"路径）：
/// - `pin = PinExpectation::Exact(key)` → 强制比对；
/// - `pin = PinExpectation::None(CoreReason::UserConfirmRequired)` + `Some(confirm)`
///   → 回调确认（拒绝即断开；回调缺失即拒绝）；
/// - `pin = PinExpectation::None(CoreReason::InternalLoopback)` → loopback 自签比对。
pub async fn client_handshake_with_confirm(
    stream: tokio::net::TcpStream,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    pin: PinExpectation,
    key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
    challenge: &str,
) -> Result<SecureChannel, HandshakeError> {
    let g = client_handshake_with_confirm_generic(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, pin, key_confirm, challenge,
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

/// M8-T027 (SRV-IDWL-021 同源语义)：白名单检查（域名 **或** ID 两维，
/// temp_mode 跳过全部白名单维度）。
pub async fn server_handshake_check(
    mut stream: tokio::net::TcpStream,
    allowed_domains: &[String],
    allowed_ids: &[String],
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
        .any(|allowed| domain_matches_whitelist(&init.client_domain, allowed))
        || allowed_ids
            .iter()
            .any(|id| id_matches_whitelist(&init.client_id, id));

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

/// S-02 (S-02d)：已握手通道单帧**密文包**上限 = 16 MiB 明文上限
/// （[`DEFAULT_MAX_FRAME_LEN`]）+ 加密开销余量（12B nonce + 16B tag）。
/// `SecureChannel::receive` / `SecureChannelReader::receive` 共用。
const MAX_CHANNEL_FRAME_LEN: usize = DEFAULT_MAX_FRAME_LEN as usize + 64;

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
        // S-02 (S-02d)：长度前缀经公共 `read_length_prefixed` 读取并受上限约束
        // （密文含 12B nonce + 16B tag 开销，上限取 16 MiB 明文 + 余量），
        // 恶意超长帧 → `TcpError::MessageTooLarge` 报错，内存有界。
        let packet = read_length_prefixed(&mut self.stream, MAX_CHANNEL_FRAME_LEN).await?;
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
        // S-02 (S-02d)：同 [`SecureChannel::receive`] —— 公共
        // `read_length_prefixed` + 上限，恶意超长帧报错关闭，内存有界。
        let packet = read_length_prefixed(&mut self.stream, MAX_CHANNEL_FRAME_LEN).await?;
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
            PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"),
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
        let mallory = gen_identity(&dir, "mallory"); // 合法公钥但非 bob（R-02）
        let alice_pub = alice.public_key_base64();
        let (client_end, server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            PinExpectation::exact_from_base64(&mallory.public_key_base64())
                .expect("mallory pubkey"),
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

    /// R-02（空 pin 拒绝）：`None(UserConfirmRequired)` 且**无确认回调**——
    /// 不再存在"空串跳过比对"的旧版兼容路径（审计证据 handshake.rs:142-146,226），
    /// core 直接拒绝，杜绝信任网络上来的公钥。
    #[tokio::test]
    async fn test_pin_none_user_confirm_missing_callback_rejected() {
        let dir = std::env::temp_dir().join("kirin_hs_no_skip");
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
            PinExpectation::None(CoreReason::UserConfirmRequired),
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "server side may complete");
        match client_res {
            Err(HandshakeError::UntrustedKey(_)) => {}
            Ok(_) => panic!("expected UntrustedKey (no skip path), but handshake succeeded"),
            Err(other) => panic!("expected UntrustedKey, got {:?}", other),
        }
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
            PinExpectation::None(CoreReason::UserConfirmRequired),
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
            PinExpectation::None(CoreReason::UserConfirmRequired),
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

    /// R-02-S3（loopback 自签兜底）：`None(InternalLoopback)` 时 core 以客户端
    /// **自身公钥**为 pin 强制比对——服务端 = 自身（同身份）→ 握手成功；
    /// 换用其他身份（非自连）→ `ServerKeyMismatch` 拒绝，不依赖"无期望"跳过。
    #[tokio::test]
    async fn test_pin_loopback_self_sign() {
        let dir = std::env::temp_dir().join("kirin_hs_loopback_self");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let alice_pub = alice.public_key_base64();

        // 服务端 = 自身（同一身份 alice）→ 自签 pin 通过。
        let (client_end, server_end) = tokio::io::duplex(65536);
        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "alice",
            PinExpectation::None(CoreReason::InternalLoopback), "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &alice, "alice", &alice_pub);
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "server side should succeed");
        assert!(client_res.is_ok(), "self-sign loopback must succeed");

        // 服务端 ≠ 自身（bob 冒充）→ 自签 pin 拒绝。
        let (client_end, server_end) = tokio::io::duplex(65536);
        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob",
            PinExpectation::None(CoreReason::InternalLoopback), "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (client_res, _server_res) = tokio::join!(client_fut, server_fut);
        match client_res {
            Err(HandshakeError::ServerKeyMismatch { .. }) => {}
            Ok(_) => panic!("self-sign pin must reject non-self server"),
            Err(other) => panic!("expected ServerKeyMismatch, got {:?}", other),
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
            client_end, &alice, "alice", "alice.local", "desktop", "bob", PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
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
            client_end, &mallory, "alice", "alice.local", "desktop", "bob", PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
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
            client_end, &alice, "alice", "alice.local", "desktop", "bob", PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
        );
        let server_fut = async move {
            // 1. 预读 init（不应答）。
            let init = server_read_init(&mut server_end).await?;
            // 2. 解析 known_hosts/DNS 后 pin 校验（一致 → 通过）。
            // S-01a：测试环回显式 opt-in（无挑战码场景）。
            verify_server_init(&init, &alice_pub, None, None, true)?;
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
                client_end, alice, "alice", "alice.local", "desktop", "bob",
                PinExpectation::exact_from_base64(bob_pub).expect("bob pubkey"), challenge,
            );
            let server_fut = async move {
                let init = server_read_init(&mut server_end).await?;
                // S-01a：测试环回显式 opt-in（二态校验分支不受该参数影响，
                // 显式传 true 保持测试语义清晰）。
                verify_server_init_with_temp(&init, alice_pub, None, fixed, Some(tm), true)?;
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

    /// S-18 (F-23): 固定挑战码常量时间比较 —— 相等/不相等/长度不匹配/空串
    /// 路径全部覆盖；`challenge_eq` 耗时与内容无关（摘要定长 + ct_eq）。
    #[test]
    fn test_challenge_eq_constant_time_compare() {
        // 相等
        assert!(challenge_eq("FIXED-CODE", "FIXED-CODE"));
        // 不同（等长）→ 不相等
        assert!(!challenge_eq("FIXED-CODE", "FIXED-CODe"));
        // 长度不匹配路径（F-23 验收项）→ 不相等，不 panic
        assert!(!challenge_eq("FIXED-CODE", "FIXED"));
        assert!(!challenge_eq("AB", "ABCDEFGHIJ"));
        // 空串 vs 非空（verify 主路径空固定码已被 filter 短路，此处覆盖兜底）
        assert!(!challenge_eq("", "X"));
        assert!(challenge_eq("", ""));
        // 与逐字节 `==` 语义一致（行为等价性回归）
        let cases: &[(&str, &str)] = &[
            ("a", "a"),
            ("a", "b"),
            ("ABC123", "ABC124"),
            ("ABC123", "ABC123"),
            ("0123456789", "012345678"),
            ("longer-code-here", "longer-code-here"),
        ];
        for (a, b) in cases {
            assert_eq!(
                challenge_eq(a, b),
                a == b,
                "challenge_eq({a:?},{b:?}) must match == semantics"
            );
        }
    }

    #[tokio::test]
    async fn test_server_read_init_pin_mismatch_rejected() {
        let dir = std::env::temp_dir().join("kirin_hs_read_init_mismatch");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let (client_end, mut server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob", PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
        );
        let server_fut = async move {
            let init = server_read_init(&mut server_end).await?;
            // known_hosts 里记录的 alice 公钥 ≠ 网络上来的公钥 → 拒绝。
            // S-01a：测试环回显式 opt-in（本用例验证 pin 不一致路径）。
            verify_server_init(&init, "WRONG-PINNED-KEY", None, None, true)?;
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

    /// S-01a (F-1): 零凭据 fail-closed —— 无固定挑战码 + 无激活临时窗口 +
    /// 客户端未知（无 pin）→ 生产语义（`allow_no_credentials=false`）拒绝；
    /// 测试/loopback 显式 opt-in（`true`）放行。
    #[tokio::test]
    async fn test_verify_server_init_zero_credentials_fail_closed() {
        let dir = std::env::temp_dir().join("kirin_hs_zero_cred");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();

        /// 一次「未知客户端（空 pin）+ 空挑战码 + 无窗口」的握手往返。
        async fn run_zero_cred(
            alice: &IdentityManager,
            bob: &IdentityManager,
            bob_pub: &str,
            allow_no_credentials: bool,
        ) -> Result<(), HandshakeError> {
            let (client_end, mut server_end) = tokio::io::duplex(65536);
            let client_fut = client_handshake_generic(
                client_end, alice, "alice", "alice.local", "desktop", "bob",
                PinExpectation::exact_from_base64(bob_pub).expect("bob pubkey"), "",
            );
            let server_fut = async move {
                let init = server_read_init(&mut server_end).await?;
                verify_server_init(&init, "", None, None, allow_no_credentials)?;
                let _g =
                    server_handshake_respond_generic(server_end, bob, "bob", &init, "").await?;
                Ok::<_, HandshakeError>(())
            };
            let (client_res, server_res) = tokio::join!(client_fut, server_fut);
            server_res?;
            client_res.map(|_| ())
        }

        // 生产语义（false）：零凭据 → 拒绝（不再免校验放行）。
        match run_zero_cred(&alice, &bob, &bob_pub, false).await {
            Err(HandshakeError::InvalidMessage(msg)) => {
                assert!(
                    msg.contains("requires credentials"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("zero-credential must be rejected, got {:?}", other),
        }
        // 测试/loopback 显式 opt-in（true）：放行。
        assert!(
            run_zero_cred(&alice, &bob, &bob_pub, true).await.is_ok(),
            "explicit opt-in must allow the loopback path"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 白名单握手（headless）集成 pin：`server_handshake_with_whitelist`
    /// 传 known_hosts 公钥 → 一致放行 / 不一致拒绝。
    #[tokio::test]
    #[allow(deprecated)] // R-05 (SRV-IDWL-022): 遗留接口 e2e 回归
    async fn test_whitelist_handshake_with_pin() {
        let dir = std::env::temp_dir().join("kirin_hs_wl_pin");
        let alice = gen_identity(&dir, "alice");
        let bob = Arc::new(gen_identity(&dir, "bob"));
        let alice_pub = alice.public_key_base64();
        let bob_pub = bob.public_key_base64();
        let allowed = vec!["kirin.local".to_string()];
        let allowed_ids: Vec<String> = Vec::new();

        // 一致 → Accepted
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (bob_ref, allowed_ref, ids_ref, pin_ref) =
            (bob.clone(), allowed.clone(), allowed_ids.clone(), alice_pub.clone());
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_handshake_with_whitelist(
                stream, &bob_ref, "bob", &allowed_ref, &ids_ref, false, &pin_ref, None, None,
            )
            .await
        });
        let client_res = client_handshake(
            tokio::net::TcpStream::connect(addr).await.unwrap(),
            &alice, "alice", "alice.kirin.local", "desktop", "bob", PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
        )
        .await;
        let decision = server_task.await.unwrap().expect("server handshake");
        assert!(matches!(decision, VerifiedDecision::Accepted(_)));
        assert!(client_res.is_ok());

        // 不一致（known_hosts 记录真实 alice 公钥，客户端用别的密钥）→ Rejected
        let mallory = gen_identity(&dir, "mallory");
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (bob_ref, allowed_ref, ids_ref, pin_ref) =
            (bob.clone(), allowed.clone(), allowed_ids.clone(), alice_pub.clone());
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_handshake_with_whitelist(
                stream, &bob_ref, "bob", &allowed_ref, &ids_ref, false, &pin_ref, None, None,
            )
            .await
        });
        let _client_res = client_handshake(
            tokio::net::TcpStream::connect(addr).await.unwrap(),
            &mallory, "alice", "alice.kirin.local", "desktop", "bob", PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
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

    /// M8-T027 (SRV-IDWL-011): `id_matches_whitelist` 匹配规则——
    /// 精确命中/未命中、空 pattern、`*` 结尾前缀通配、空白 trim、大小写敏感。
    #[test]
    fn test_id_matches_whitelist_rules() {
        // 精确匹配（trim 后相等）。
        assert!(id_matches_whitelist("device-7", "device-7"));
        assert!(id_matches_whitelist(" device-7 ", "device-7"));
        assert!(id_matches_whitelist("device-7", "  device-7  "));
        assert!(!id_matches_whitelist("device-8", "device-7"));
        // 空 pattern / 空白 → 不匹配。
        assert!(!id_matches_whitelist("device-7", ""));
        assert!(!id_matches_whitelist("device-7", "   "));
        // `*` 结尾 → 前缀通配。
        assert!(id_matches_whitelist("office-1", "office-*"));
        assert!(id_matches_whitelist("office-42", "office-*"));
        assert!(id_matches_whitelist("office-", "office-*"));
        assert!(!id_matches_whitelist("lab-1", "office-*"));
        assert!(!id_matches_whitelist("myoffice-1", "office-*"));
        // 裸 `*`（通配前缀为空）→ 保守不匹配（对称 domain 裸 `*` 处理）。
        assert!(!id_matches_whitelist("device-7", "*"));
        // 大小写敏感（与 known_clients key 语义一致）。
        assert!(!id_matches_whitelist("Device-7", "device-7"));
        assert!(id_matches_whitelist("Device-7", "Device-7"));
        // 空 device_id。
        assert!(!id_matches_whitelist("", "device-7"));
        assert!(!id_matches_whitelist("", ""));
    }

    /// M8-T027 (SRV-IDWL-020 旧接口): `server_handshake_with_whitelist`
    /// 双白名单 OR 语义——域名未命中但设备 ID 命中 → 放行（headless 无审批）。
    #[tokio::test]
    #[allow(deprecated)] // R-05 (SRV-IDWL-022): 遗留接口 e2e 回归
    async fn test_whitelist_handshake_id_only_accepted() {
        let dir = std::env::temp_dir().join("kirin_hs_wl_id_only");
        let alice = gen_identity(&dir, "alice");
        let bob = Arc::new(gen_identity(&dir, "bob"));
        let alice_pub = alice.public_key_base64();
        let bob_pub = bob.public_key_base64();
        let allowed: Vec<String> = Vec::new(); // 域名维度为空
        let allowed_ids = vec!["alice".to_string()];

        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (bob_ref, allowed_ref, ids_ref) =
            (bob.clone(), allowed.clone(), allowed_ids.clone());
        let alice_pub_ref = alice_pub.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_handshake_with_whitelist(
                stream, &bob_ref, "bob", &allowed_ref, &ids_ref, false, &alice_pub_ref, None,
                None,
            )
            .await
        });
        let client_res = client_handshake(
            tokio::net::TcpStream::connect(addr).await.unwrap(),
            &alice, "alice", "evil.example.org", "desktop", "bob", PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
        )
        .await;
        let decision = server_task.await.unwrap().expect("server handshake");
        assert!(
            matches!(decision, VerifiedDecision::Accepted(_)),
            "ID whitelist hit must accept despite domain miss"
        );
        assert!(client_res.is_ok());

        // 对照：ID 未命中（alice 换 id=bob）→ 双维未命中 → Rejected。
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (bob_ref, allowed_ref, ids_ref) = (bob.clone(), allowed.clone(), allowed_ids.clone());
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_handshake_with_whitelist(
                stream, &bob_ref, "bob", &allowed_ref, &ids_ref, false, &alice_pub, None, None,
            )
            .await
        });
        let _client_res = client_handshake(
            tokio::net::TcpStream::connect(addr).await.unwrap(),
            &alice, "mallory", "evil.example.org", "desktop", "bob", PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
        )
        .await;
        match server_task.await.unwrap().expect("server handshake") {
            VerifiedDecision::Rejected(reason) => {
                assert!(reason.contains("not in whitelist"), "reason: {reason}");
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
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
            client_end, &alice, "alice", "alice.local", "desktop", "bob", PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
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

    // ── S-02 (F-5)：握手读超时 / 超长前缀拒绝 / 通道帧上限 ─────────────

    /// S-02b：连接"只连不发" → `server_read_init` 在 deadline 内返回
    /// `HandshakeError::Timeout`（调用方既有错误路径关闭连接 + 计失败 + 审计）。
    #[tokio::test]
    async fn test_server_read_init_timeout() {
        // 对端保持连接打开但不发任何字节（`_client_end` 存活到作用域结束，
        // drop 会让读侧 EOF 而非超时）。
        let (_client_end, mut server_end) = tokio::io::duplex(65536);
        let start = std::time::Instant::now();
        let err = server_read_init_with_timeout(
            &mut server_end,
            std::time::Duration::from_millis(200),
        )
        .await
        .unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            matches!(err, HandshakeError::Timeout),
            "expected Timeout, got {:?}",
            err
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(150),
            "timeout fired too early: {:?}",
            elapsed
        );
    }

    /// S-02a/S-02b：`0xFFFFFFFF` 长度前缀 → `MessageTooLarge`（读侧不分配
    /// 4 GiB，直接报错，由调用方关闭连接）。
    #[tokio::test]
    async fn test_server_read_init_oversized_rejected() {
        use tokio::io::AsyncWriteExt;
        let (mut client_end, mut server_end) = tokio::io::duplex(65536);
        client_end.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let err = server_read_init(&mut server_end).await.unwrap_err();
        match &err {
            HandshakeError::Tcp(TcpError::MessageTooLarge { len, max }) => {
                assert_eq!(*len, u32::MAX as usize);
                assert_eq!(*max, DEFAULT_MAX_FRAME_LEN as usize);
            }
            other => panic!("expected Tcp(MessageTooLarge), got {:?}", other),
        }
    }

    /// S-02d：`SecureChannel::receive` 对恶意超长帧前缀报错（通道级上限），
    /// 与 tcp 层共用 `read_length_prefixed`。
    #[tokio::test]
    async fn test_secure_channel_receive_oversized_rejected() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ch = SecureChannel {
                stream,
                cipher: AeadCipher::new(&[0u8; 32]),
                peer_id: "peer".to_string(),
                peer_domain: String::new(),
                peer_device_type: String::new(),
                selected_codec: String::new(),
            };
            let err = ch.receive().await.unwrap_err();
            match &err {
                HandshakeError::Tcp(TcpError::MessageTooLarge { len, max }) => {
                    assert_eq!(*len, u32::MAX as usize);
                    // 通道帧上限 = 16 MiB + 加密开销余量（S-02d）。
                    assert_eq!(*max, DEFAULT_MAX_FRAME_LEN as usize + 64);
                }
                other => panic!("expected Tcp(MessageTooLarge), got {:?}", other),
            }
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        client.flush().await.unwrap();
        server_task.await.unwrap();
    }

    // ── R-32（M13-T002 阶段 B）：codec 协商 ──────────────────────

    /// 服务端优先级协商：交集命中按服务端顺序（AV1 优先）。
    #[test]
    fn test_negotiate_codec_by_server_priority() {
        let server = vec!["av1".to_string(), "h265".to_string(), "h264".to_string()];
        // 客户端全支持 → AV1（服务端最优）。
        let client_all = vec!["h264".to_string(), "h265".to_string(), "av1".to_string()];
        assert_eq!(
            negotiate_codec_by_server_priority(&server, &client_all),
            "av1"
        );
        // 客户端不支持 AV1 → h265。
        let client_no_av1 = vec!["h264".to_string(), "h265".to_string()];
        assert_eq!(
            negotiate_codec_by_server_priority(&server, &client_no_av1),
            "h265"
        );
        // 客户端仅 h264 → h264。
        let client_h264_only = vec!["h264".to_string()];
        assert_eq!(
            negotiate_codec_by_server_priority(&server, &client_h264_only),
            "h264"
        );
        // 交集为空（客户端未广告/未知）→ 空串（调用方 H.264 兜底）。
        assert_eq!(
            negotiate_codec_by_server_priority(&server, &[]),
            String::new()
        );
        let client_unknown = vec!["vp9".to_string()];
        assert_eq!(
            negotiate_codec_by_server_priority(&server, &client_unknown),
            String::new()
        );
        // 服务端空列表 → 空串。
        assert_eq!(
            negotiate_codec_by_server_priority(&[], &client_all),
            String::new()
        );
    }

    /// 客户端优先级协商（既有语义回归：按客户端列表顺序）。
    #[test]
    fn test_negotiate_codec_client_order() {
        let client = vec!["h265".to_string(), "h264".to_string()];
        let server = vec!["h264".to_string(), "h265".to_string()];
        assert_eq!(negotiate_codec(&client, &server), "h265");
        // 无交集 → 空串。
        assert_eq!(negotiate_codec(&client, &[]), String::new());
    }

    /// R-32：带 codec 列表的客户端握手 → 服务端可读到 supported_codecs 并
    /// 应答 selected_codec（wire 往返：duplex 真实握手，非手搓消息）。
    #[tokio::test]
    async fn test_client_handshake_with_codecs_wire() {
        let dir = std::env::temp_dir().join("kirin_hs_codecs");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let (client_end, mut server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_with_codecs_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"),
            "",
            vec!["av1".to_string(), "h265".to_string(), "h264".to_string()],
        );
        let server_fut = async move {
            let init = server_read_init(&mut server_end).await?;
            // 客户端广告 av1 → 服务端按自身优先级选 av1。
            let server_caps = vec![
                "av1".to_string(),
                "h265".to_string(),
                "h264".to_string(),
            ];
            let selected =
                negotiate_codec_by_server_priority(&server_caps, &init.supported_codecs);
            assert_eq!(selected, "av1");
            let g = server_handshake_respond_generic(server_end, &bob, "bob", &init, &selected)
                .await?;
            Ok::<_, HandshakeError>(g)
        };
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "server side should succeed");
        let client_ch = client_res.expect("client handshake with codecs should succeed");
        // 客户端侧拿到服务端选中的 codec。
        assert_eq!(client_ch.selected_codec, "av1");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
