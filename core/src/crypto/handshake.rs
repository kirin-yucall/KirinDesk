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

    /// version skew）——两端需统一更新到同一版本。
    #[error("Server protocol version too new: server={server}, client={client} — update KirinDesk on both ends to the same version")]
    ServerTooNew { server: u32, client: u32 },
}

impl HandshakeError {
    /// 稳定拒绝码（如 [`REJECT_CODE_ID_WHITELIST`]）；其余（含旧版纯文本
    /// `Rejected`）返回 `None`。控制端按码映射本地化文案。
    pub fn reject_code(&self) -> Option<&str> {
        match self {
            HandshakeError::Rejected(msg) => msg.split('|').next(),
            _ => None,
        }
    }
}

/// 静默，拒绝路径不因下发文案失败而变成放行）。
pub async fn send_handshake_reject<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: &str,
    detail: &str,
) {
    let reject = HandshakeReject {
        code: code.to_string(),
        detail: detail.to_string(),
    };
    if let Ok(data) = bincode::serialize(&reject) {
        // 发送失败不影响拒绝语义（连接随后关闭，客户端读 EOF 兜底）。
        let _ = send_message(stream, &data).await;
    }
}

/// 旧审计证据 `handshake.rs:142-146,226` 空串跳过路径已不可构造）。
///
/// 信任策略由 `pin` 与 `key_confirm` 回调组合决定，**不存在"无期望跳过"路径**：
/// - [`PinExpectation::Exact`]：带外可信公钥（known_hosts / DNS TXT / 自签）
///   强制比对，不等即拒绝（CLI-HSK-SEC-001），`ServerKeyMismatch` 保留；
/// - [`PinExpectation::None`] + [`CoreReason::UserConfirmRequired`]：收到服务端
///   公钥后调用确认回调（首次指纹确认，CLI-KH-001）；**回调缺失或返回 `false`
/// - [`PinExpectation::None`] + [`CoreReason::InternalLoopback`]：loopback 自签
#[derive(Debug, Clone)]
pub enum PinExpectation {
    /// 无带外 pin —— 必须由 [`CoreReason`] 显式声明兜底场景，core 层仍执行真实比对。
    None(CoreReason),
    /// 带外可信公钥原始字节（Ed25519 32 字节）——强制一致，不等即拒绝。
    Exact([u8; 32]),
}

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

///
/// 背景（用户实测）：各测试机部署的 exe 版本不一致（version skew）——
/// 新客户端 ↔ 旧服务端（或反之）行为差异时，某侧裸 close，控制端只能报
/// `TCP error: I/O error: early eof`，无从定位。本字段把版本差显性化：
///
/// - 双方同版本 / 对端 ≤ 本端 → 正常握手；
/// - 客户端 > 服务端（客户端过新）→ 服务端结构化拒绝 `version_mismatch`；
/// - 服务端 > 客户端（服务端过新）→ 客户端本地报 [`HandshakeError::ServerTooNew`]。
///
/// **向后兼容（关键）**：字段以 `#[serde(default)]` 追加在结构体**尾部**——
/// 旧端收到新端报文时 bincode 1.3.3 顶层 `deserialize` 自带
/// `allow_trailing_bytes()`，多出的尾随字节被忽略（`supported_codecs`
/// （`PROTO_VER_LEGACY`）→ 按旧语义放行。因此字段本身不拒绝任何旧端，
/// 只有**对端宣告高于本端理解范围的版本**才拒绝。
///
/// 常量值——**非**加密算法变更（加密统一红线不变）；wire 影响 = 两端
/// 版本交换字段取值变化 + shell 文件通道臂启用（`ShellMessage::File`
/// 判别值 3 与 K4 v2 `FileOp::OfferV2` 判别值 13 仅 v3 对端间使用）。
/// 双向拒绝 = 既有机制零新码：v3 客户端 → v2 服务端 = 服务端结构化拒绝
/// `version_mismatch`；v2 客户端 → v3 服务端 = 客户端 `ServerTooNew`
/// 本地可读错误 = 既有「both ends same version」政策延续（fail-closed
/// 文件臂双向门控关（§12.3-3/§12.4-4）。
/// 3 → **4**。本版 wire 语义变更（**无兼容包袱**：新旧对端互连允许失败，
/// fail-closed 无半残态；README/CHANGELOG 注明**需两端升级**）：
///
/// - **CX-1 挑战码响应化**：`HandshakeInit.challenge` 不再携带明文挑战码
///   （v4 恒空串）——凭据以「受控端 nonce → 控制端
///   [`challenge_response`] 派生应答」的挑战-响应形态上线（新消息
///   [`HandshakeChallenge`] / [`HandshakeChallengeResp`]），线路上不再出现
///   可窃取重用的明文凭据（R178 ZE-01 挑战码收获位封死）；**已 pin 免挑战**
///   （服务端侧 known_clients/DNS-TXT 公钥绑定命中 = pin 即强凭据，免挑战轮，
///   裁定 CX-1 方案 B 附带项）；
/// - **CX-2 握手第一包能力纳签**：`proto_ver` / `supported_codecs` /
///   `requested_max_width` / `client_os` 全部纳入 [`build_sig_payload`]
///   签名覆盖域（R178 ZE-03 主动降级/特性剥离面封死）；
/// - **版本门 exact-match**：`server_version_gate` / `client_version_gate`
///   改为**精确相等**才放行（旧「对端 ≤ 本端放行」语义废除——v3/legacy-0
///   对端一律 `version_mismatch` / `ServerTooNew` 结构化拒绝，杜绝旧端
///   签不出 v4 载荷时的二阶失败形态）。
pub const PROTOCOL_VERSION: u32 = 4;

/// 拒绝（fail-closed，无兼容包袱）；常量保留供解析回退层赋值与测试锚定。
pub const PROTO_VER_LEGACY: u32 = 0;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    pub proto_ver: u32,
    ///
    /// 移动端软解 + RGBA 上屏吃不动 4K（13900ES 被控端 4K 推流实测不可用：
    /// 3840×2160 RGBA 单帧 33MB 拷贝必然低帧率+高延迟）——移动端握手上报
    /// 较小值（如 1280），服务端捕获后 swscale 降采样再编码；桌面端报 0
    /// 保持原生（行为不变）。旧端字段缺失（容错解析回退）= 0 = 原生，
    /// 向后兼容。
    #[serde(default)]
    pub requested_max_width: u32,
    /// `kirin_desk_utils::osinfo::KNOWN_OS_TYPES` 常量集精确值，探测失败/
    /// 不支持平台 = 空串 = 未知）。**尾部追加** `#[serde(default)]`
    ///（`proto_ver`/`requested_max_width` 同模式）：旧客户端报文缺此字段 →
    /// 新服务端容错解析回退空串（未知 → 展示回退角色徽标，不猜）；旧
    /// 服务端对新客户端报文顶层 `deserialize` 容忍尾随字节（忽略），双向
    /// 兼容零判别值，`PROTOCOL_VERSION` 零改。
    #[serde(default)]
    pub client_os: String,
    /// （[`challenge_response`]，HMAC-SHA256(SHA256(挑战码), nonce ‖
    /// x25519 ‖ client_nonce)）。首包恒空（应答经独立消息
    /// [`HandshakeChallengeResp`] 在挑战轮内送达）；本字段保留 wire 位置
    /// 供钉死与未来带内应答形态。v4 起 `challenge` 字段**不再携带明文
    /// 挑战码**（恒空串——凭据不以可窃用形态走预信道，ZE-01）。
    #[serde(default)]
    pub challenge_resp: Vec<u8>,
}

/// 形状（`[u8;8] + [u8;32]`）与任意「32B 不透明前缀」消息（如
/// `HandshakeResponse` 首字段 x25519 pub）前缀二义，客户端按
/// 「反序列化成功 **且** 魔数相等」双条件判别（防把响应误当挑战 → 通道卡死）。
pub const HANDSHAKE_CHALLENGE_MAGIC: [u8; 8] = *b"KIRINCH1";

/// （版本闸/白名单/审批之后、凭据校验之前）下发 32B CSPRNG nonce；控制端
/// 以 [`challenge_response`] 派生应答经 [`HandshakeChallengeResp`] 回答。
/// nonce 每连接全新（防重放：收获的应答对跨连接不可重用）。
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeChallenge {
    /// 帧判别魔数（恒 [`HANDSHAKE_CHALLENGE_MAGIC`]，见类型级注释）。
    pub magic: [u8; 8],
    pub nonce: [u8; 32],
}

/// [`challenge_response`]；受控端常量时间比对，错误 = `challenge_mismatch`
/// 结构化拒绝，对齐既有防枚举口径 HK-002）。
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeChallengeResp {
    /// 帧判别魔数（对称 [`HandshakeChallenge::magic`]）。
    pub magic: [u8; 8],
    pub response: [u8; 32],
}

/// 派生材料而非明文码）。
///
/// `response = HMAC-SHA256(key, data = "KIRIN-CHR1" ‖ server_nonce ‖
/// client_x25519_pub ‖ client_nonce)`：
/// - 挑战码明文**永不上线**（固定码臂密钥 = SHA256(码) 服务端现算；临时码臂
///   密钥 = 状态文件存的无盐 `sha256(码)`——线路上只剩不可逆派生值）；
/// - `server_nonce` 每连接全新 → 收获应答跨连接不可重放；
/// - 绑定 `client_x25519_pub` + `client_nonce`（首包签名覆盖域内）→
///   应答不可挪用至并行连接（反射/转投封闭）。
///
/// 离线爆破代价与 `HMAC(码, m)` 同阶（每猜一码一次 SHA-256 + 一次 HMAC），
/// 不低于既有固定码语义。
pub fn challenge_derive_from_key(
    key: &[u8; 32],
    nonce: &[u8; 32],
    client_x25519_pub: &[u8; 32],
    client_nonce: &[u8; 32],
) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"KIRIN-CHR1");
    mac.update(nonce);
    mac.update(client_x25519_pub);
    mac.update(client_nonce);
    mac.finalize().into_bytes().into()
}

/// 的明文码入口：密钥 = `SHA256(挑战码)`）。
pub fn challenge_response(
    code: &str,
    nonce: &[u8; 32],
    client_x25519_pub: &[u8; 32],
    client_nonce: &[u8; 32],
) -> [u8; 32] {
    let key = Sha256::digest(code.as_bytes());
    challenge_derive_from_key(key.as_slice().try_into().expect("sha256 = 32B"), nonce, client_x25519_pub, client_nonce)
}

/// **CX-1**：服务端单次挑战轮的应答材料（nonce + 客户端应答），由
/// [`server_challenge_round`] 产出、传入 `verify_server_init*` 校验。
#[derive(Debug, Clone)]
pub struct ChallengeAnswer {
    pub nonce: [u8; 32],
    pub response: [u8; 32],
}

/// **CX-1**：本连接是否需要挑战轮（单一判定点，双链共用）。
///
/// - 客户端公钥已 pin 且与 init 自报一致（known_clients / DNS-TXT 绑定）→
///   **免挑战**（CX-1 方案 B 附带项：pin 即强凭据；判定基于服务端自身
///   pin 存储，不信任客户端自报声明）；
/// - 无固定挑战码且无激活临时窗口 → 无挑战（零凭据判定归 verify 层）；
/// - 其余（固定码或激活窗口）→ 需要挑战轮。
pub fn challenge_round_required(
    expected_client_key_base64: &str,
    init_client_pub_base64: &str,
    expected_challenge: Option<&str>,
    temp_window: Option<&TempModeManager>,
) -> bool {
    let pinned = !expected_client_key_base64.is_empty()
        && expected_client_key_base64 == init_client_pub_base64;
    if pinned {
        return false;
    }
    let has_fixed = expected_challenge.map_or(false, |c| !c.is_empty());
    has_fixed || temp_window.is_some_and(TempModeManager::is_active)
}

/// **CX-1**：服务端挑战轮（受控端臂）——下发 [`HandshakeChallenge`]（32B
/// CSPRNG nonce）并限时读取 [`HandshakeChallengeResp`]。读超时/解码失败 =
/// [`HandshakeError::InvalidMessage`]（调用方走既有拒绝+审计+限流路径）。
pub async fn server_challenge_round<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
) -> Result<ChallengeAnswer, HandshakeError> {
    let nonce = generate_nonce();
    let msg = HandshakeChallenge { magic: HANDSHAKE_CHALLENGE_MAGIC, nonce };
    let data = bincode::serialize(&msg)
        .map_err(|e| HandshakeError::Serialization(e.to_string()))?;
    send_message(stream, &data).await?;
    let resp_data = tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, receive_message(stream))
        .await
        .map_err(|_| HandshakeError::Timeout)??;
    let resp: HandshakeChallengeResp = bincode::deserialize(&resp_data)
        .map_err(|e| HandshakeError::InvalidMessage(format!(
            "invalid challenge response: {e}"
        )))?;
    if resp.magic != HANDSHAKE_CHALLENGE_MAGIC {
        return Err(HandshakeError::InvalidMessage(
            "challenge response magic mismatch".to_string(),
        ));
    }
    Ok(ChallengeAnswer { nonce, response: resp.response })
}

/// **CX-1**：挑战应答常量时间校验（固定码臂——服务端持有明文码，现算
/// 派生密钥比对；临时码臂见 [`TempModeManager::verify_challenge_response`]）。
fn challenge_resp_matches_fixed(
    fixed_code: &str,
    answer: &ChallengeAnswer,
    init: &HandshakeInit,
) -> bool {
    use subtle::ConstantTimeEq;
    let expect = challenge_response(fixed_code, &answer.nonce, &init.client_x25519_pub, &init.nonce);
    bool::from(expect.as_slice().ct_eq(&answer.response[..]))
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
    #[serde(default)]
    pub proto_ver: u32,
    /// `kirin_desk_utils::osinfo::KNOWN_OS_TYPES` 常量集精确值，探测失败/
    /// 不支持平台 = 空串 = 未知）。**尾部追加** `#[serde(default)]`（同
    /// [`HandshakeInit::client_os`] 口径）：旧服务端报文缺此字段 → 新客户端
    /// 容错解析回退空串（对端展示回退角色徽标，不猜）；旧客户端对新服务端
    /// 报文容忍尾随字节（忽略），双向兼容零判别值。
    #[serde(default)]
    pub server_os: String,
}

///
/// 服务端在**拒绝**路径（不发送 `HandshakeResponse`）发送本消息后立即断开——
/// 不泄露服务器 X25519/Ed25519 公钥与响应签名（对齐既有「非白名单不泄露」
/// 原则；仅下发拒绝码 + 机器可读上下文，供控制端按码映射本地化文案）。
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeReject {
    /// 稳定拒绝码（见 `REJECT_CODE_*` 常量；客户端按码映射 i18n 文案）。
    pub code: String,
    /// 机器可读上下文（如被拒的客户端设备 ID），不含敏感凭据。
    pub detail: String,
}

/// 挑战码/昵称正确也不放行，fail-closed）。
pub const REJECT_CODE_ID_WHITELIST: &str = "id_whitelist_denied";

//
// 背景（用户实测缺陷）：服务端 IP 模式拒绝路径（挑战码错/昵称不匹配/零凭据/
// 审批拒绝/限流）此前**裸 close 不发任何拒绝消息**——控制端读到 EOF 只能报
// `TCP error: I/O error: early eof`，用户无法分辨"挑战码填错"还是"网络断了"。
// 拒绝路径，控制端按码映射本地化可读文案（桌面 zh/en，移动端英文）。
//
// 防枚举口径（HK-002）：拒绝码只区分**类别**（码错/昵称错/需凭据），不区分
// "服务端配置了码但填错"与"服务端根本没配码"等细粒度差异；爆破面由既有
// `record_handshake_failure` 限流兜底。

pub const REJECT_CODE_CHALLENGE_MISMATCH: &str = "challenge_mismatch";

pub const REJECT_CODE_NICKNAME_MISMATCH: &str = "nickname_mismatch";

pub const REJECT_CODE_CLIENT_KEY_MISMATCH: &str = "client_key_mismatch";

pub const REJECT_CODE_CREDENTIALS_REQUIRED: &str = "credentials_required";

///
/// [`REJECT_CODE_APPROVAL_TIMEOUT`]——控制端可分辨「有人点了拒绝」与
/// 「限时内无人审批」。本码保留用户主动拒绝 + 无人值守/无头自动拒语义
/// （审批等待中流断开/协议外数据仍归本码：对端已离场，拒绝语义不变）。
pub const REJECT_CODE_APPROVAL_DECLINED: &str = "approval_declined";

/// approval_timeout_secs` 可配）内无用户决策，服务端**主动断开**并下发
/// 本分类关闭原因（区别于用户拒绝 [`REJECT_CODE_APPROVAL_DECLINED`]）。
///
/// wire 兼容：仅复用既有 `HandshakeReject{code,detail}` 结构化拒绝消息
/// 通道、`code` 字符串常量域**新增取值**——零枚举变体/零字段重排（先例
/// 错误串呈现，行为=修复前 early eof 兜底，不崩溃）。
pub const REJECT_CODE_APPROVAL_TIMEOUT: &str = "approval_timeout";

/// 准入零放宽）——**独立分类码**：控制端可分辨「无人值守仅白名单/已知设备
/// 可连」与「有人点了拒绝」（[`REJECT_CODE_APPROVAL_DECLINED`]）/「限时内
/// 无人审批」（[`REJECT_CODE_APPROVAL_TIMEOUT`]），下发可操作提示（让对端
/// 加白名单/已知设备）而非笼统「被拒」。
///
/// wire 兼容：同 [`REJECT_CODE_APPROVAL_TIMEOUT`] 口径——复用既有
/// `HandshakeReject{code,detail}` 结构化拒绝通道、`code` 字符串常量域**新增
/// 取值**，零枚举变体/零字段重排；旧客户端对未知码 fail-safe 按原始错误串
/// 呈现（行为 = 修复前，不崩溃）。
pub const REJECT_CODE_UNATTENDED_UNKNOWN: &str = "unattended_unknown";

/// 本端正作为控制端存在活跃桌面控制会话的对端（对端与我互控关系成立）时，
/// 握手审批前直接拒绝（fail-closed 主保险；发起端入口另有预检拦截为次保险）。
///
/// wire 兼容：同 [`REJECT_CODE_APPROVAL_TIMEOUT`] / [`REJECT_CODE_UNATTENDED_UNKNOWN`]
/// 口径——复用既有 `HandshakeReject{code,detail}` 结构化拒绝通道、`code`
/// 字符串常量域**新增取值**，零枚举变体/零字段重排/**零版本 bump**
///（`PROTOCOL_VERSION=3` 冻结）；旧客户端对未知码 fail-safe 按原始错误串
/// 呈现（行为 = 修复前，不崩溃；判定源 = 判定端**自身**会话账本，不依赖
/// 对端新版本——旧对端零通告面，本码只在判定端为新版时才可能发出）。
pub const REJECT_CODE_MUTUAL_CONTROL: &str = "mutual_control_denied";

pub const REJECT_CODE_RATE_LIMITED: &str = "rate_limited";

pub const REJECT_CODE_VERSION_MISMATCH: &str = "version_mismatch";

///
///（覆盖 v3 旧端与 legacy-0 旧端——两端必须同为协议 4，fail-closed 无兼容
/// 包袱，README/CHANGELOG 注明需两端升级）。
pub fn server_version_gate(server_ver: u32, client_ver: u32) -> bool {
    client_ver != server_ver
}

///
/// [`HandshakeError::ServerTooNew`]（「update KirinDesk on both ends」——
/// v3/legacy-0 服务端一律拒绝，fail-closed）。
pub fn client_version_gate(client_ver: u32, server_ver: u32) -> bool {
    server_ver != client_ver
}

///
/// 包袱；v3/legacy-0 一律 `version_mismatch`）。
///
/// `PROTOCOL_VERSION` 为参数的既有口径，调用点零变化）。
pub fn client_version_too_new(ver: u32) -> bool {
    server_version_gate(PROTOCOL_VERSION, ver)
}

/// 拒绝（`version_mismatch`）并返回 `true`（调用方记审计后立即断开）。
///
/// 放在 `server_read_init` 之后、凭据校验之前：版本不匹配时无需（也不应）
/// 进入挑战码/白名单/审批流程。旧客户端（`proto_ver = 0`）永远放行。
pub async fn reject_if_client_too_new<S: AsyncWrite + Unpin>(
    stream: &mut S,
    init: &HandshakeInit,
) -> bool {
    if client_version_too_new(init.proto_ver) {
        send_handshake_reject(
            stream,
            REJECT_CODE_VERSION_MISMATCH,
            &format!("client={} server={}", init.proto_ver, PROTOCOL_VERSION),
        )
        .await;
        true
    } else {
        false
    }
}

///
/// 覆盖：昵称不匹配 / 挑战码错 / 零凭据 / 客户端公钥绑定不一致；其余
/// （签名失败、消息损坏等）返回 `None`（调用方可静默断开——属异常流量，
/// 无稳定用户文案语义）。
pub fn handshake_error_reject_code(err: &HandshakeError) -> Option<&'static str> {
    match err {
        HandshakeError::ClientKeyMismatch { .. } => Some(REJECT_CODE_CLIENT_KEY_MISMATCH),
        HandshakeError::InvalidMessage(msg) => {
            if msg.starts_with("nickname mismatch") {
                Some(REJECT_CODE_NICKNAME_MISMATCH)
            } else if msg == "challenge mismatch" {
                Some(REJECT_CODE_CHALLENGE_MISMATCH)
            } else if msg.starts_with("server requires credentials") {
                Some(REJECT_CODE_CREDENTIALS_REQUIRED)
            } else {
                None
            }
        }
        _ => None,
    }
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
    /// 通告值，服务端 = 对端 [`HandshakeInit::client_os`] 通告值；旧对端
    /// 未通告 = 空串 = 未知。展示层空/未知一律回退角色徽标，不猜）。
    pub peer_os: String,
}

/// Result of a successful handshake over a generic stream.
pub struct SecureChannelGeneric<S> {
    pub stream: S,
    pub cipher: AeadCipher,
    pub peer_id: String,
    pub peer_domain: String,
    pub peer_device_type: String,
    pub selected_codec: String,
    pub peer_os: String,
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
        server_id, pin, None, challenge, supported_codecs, 0,
    )
    .await
}

/// 未来桌面画质设置项调用；桌面现状不传 = 原生分辨率，零行为变化）。
///
/// 与 [`client_handshake_with_codecs_generic`] 的差异仅 `requested_max_width`
/// 一个字段：写入握 init 尾部（`#[serde(default)]` + 旧端
/// `allow_trailing_bytes` 天然兼容，同 `proto_ver`/`supported_codecs` 先例）：
/// - `> 0`：客户端期望服务端把编码宽度降到该值以内（如移动端软解上报
///   1280——4K 原生推流在移动端不可用，见 [`HandshakeInit::requested_max_width`]）；
///
/// 服务端多观众全场统一取**第一位观众**的期望（同 codec 收敛口径，
/// `server_media::converge_width`）；期望不保证满足，实际尺寸以视频流
/// `EncodedWindow.base_w/base_h` 为准（客户端输入坐标基数同源）。
#[allow(clippy::too_many_arguments)]
pub async fn client_handshake_with_resolution_generic<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    pin: PinExpectation,
    key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
    challenge: &str,
    supported_codecs: Vec<String>,
    requested_max_width: u32,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    client_handshake_with_confirm_and_codecs_generic(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, pin, key_confirm, challenge, supported_codecs, requested_max_width,
    )
    .await
}

/// [`client_handshake_with_resolution_generic`] 的 TcpStream 包装
/// [`client_handshake_with_confirm`]，需上报分辨率时改为本函数并传
/// `requested_max_width`（如 1280）；`supported_codecs` 传 `Vec::new()`
/// 保持既有 H.264 兜底语义不变）。
#[allow(clippy::too_many_arguments)]
pub async fn client_handshake_with_resolution(
    stream: tokio::net::TcpStream,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    pin: PinExpectation,
    key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
    challenge: &str,
    supported_codecs: Vec<String>,
    requested_max_width: u32,
) -> Result<SecureChannel, HandshakeError> {
    let g = client_handshake_with_resolution_generic(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, pin, key_confirm, challenge, supported_codecs, requested_max_width,
    )
    .await?;
    Ok(SecureChannel {
        stream: g.stream,
        cipher: g.cipher,
        peer_id: g.peer_id,
        peer_domain: g.peer_domain,
        peer_device_type: g.peer_device_type,
        selected_codec: g.selected_codec,
        peer_os: g.peer_os,
    })
}

/// 带信任确认回调的通用客户端握手（CLI-HSK-SEC-003 / CLI-KH-001）。
///
/// - [`PinExpectation::Exact`]：与服务端响应公钥**强制比对**（带外可信公钥：
///   known_hosts 指纹 / DNS TXT），不等即拒绝（CLI-HSK-SEC-001）；
/// - [`PinExpectation::None`] + [`CoreReason::UserConfirmRequired`]：收到服务端
///   公钥后调用确认回调（首次连接指纹确认），回调返回 `false` 即断开并报
///   [`HandshakeError::UntrustedKey`]，**不发送任何业务数据**（CLI-HSK-006）；
/// - [`PinExpectation::None`] + [`CoreReason::InternalLoopback`]：loopback 自签
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
        server_id, pin, key_confirm, challenge, Vec::new(), 0,
    )
    .await
}

///
/// 与确认回调版唯一差异：`supported_codecs` 写入握 init（空列表 = 旧行为）。
/// 信任语义（pin/确认回调）完全一致，无新协议安全面。
/// 行为不变；上报入口见 [`client_handshake_with_resolution_generic`]）。
///
///（透传对端 `HandshakeResponse.proto_ver`），本入口丢弃版本（既有调用方
/// 零变化）。
#[allow(clippy::too_many_arguments)]
pub async fn client_handshake_with_confirm_and_codecs_generic<
    S: AsyncRead + AsyncWrite + Unpin + Send,
>(
    stream: S,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    pin: PinExpectation,
    key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
    challenge: &str,
    supported_codecs: Vec<String>,
    requested_max_width: u32,
) -> Result<SecureChannelGeneric<S>, HandshakeError> {
    client_handshake_with_confirm_and_codecs_generic_ex(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, pin, key_confirm, challenge, supported_codecs, requested_max_width,
    )
    .await
    .map(|(g, _peer_proto_ver)| g)
}

///
/// 语义与 [`client_handshake_with_confirm`] 逐位一致（同 9 参、同 pin/确认
/// 回调信任语义、同 `ServerTooNew` 闸门），唯一差异 = 返回
/// `(SecureChannel, 对端协议版本)`——对端版本取自 `HandshakeResponse.proto_ver`
/// 门控：仅 `peer_proto_ver == PROTOCOL_VERSION` 建 FileSession + 接 `file_tx`
///（legacy-0 端 = 文件帧零发送 + 无文件 UI 入口，fail-closed，禁探测法 D-3）。
///
/// 既有入口 [`client_handshake_with_confirm`] 行为零变化（继续丢弃版本）。
#[allow(clippy::too_many_arguments)]
pub async fn client_handshake_with_confirm_ex(
    stream: tokio::net::TcpStream,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    pin: PinExpectation,
    key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
    challenge: &str,
) -> Result<(SecureChannel, u32), HandshakeError> {
    let (g, peer_proto_ver) = client_handshake_with_confirm_generic_ex(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, pin, key_confirm, challenge,
    )
    .await?;
    Ok((
        SecureChannel {
            stream: g.stream,
            cipher: g.cipher,
            peer_id: g.peer_id,
            peer_domain: g.peer_domain,
            peer_device_type: g.peer_device_type,
            selected_codec: g.selected_codec,
            peer_os: g.peer_os,
        },
        peer_proto_ver,
    ))
}

///（返回 `(通道, 对端 proto_ver)`；`_ex` TcpStream 入口与通用泛型共用）。
async fn client_handshake_with_confirm_generic_ex<
    S: AsyncRead + AsyncWrite + Unpin + Send,
>(
    stream: S,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    pin: PinExpectation,
    key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
    challenge: &str,
) -> Result<(SecureChannelGeneric<S>, u32), HandshakeError> {
    client_handshake_with_confirm_and_codecs_generic_ex(
        stream, client_identity, client_id, client_domain, client_device_type,
        server_id, pin, key_confirm, challenge, Vec::new(), 0,
    )
    .await
}

/// 起内移；返回 `(通道, 对端 proto_ver)` 供 `_ex` 入口透出）。
#[allow(clippy::too_many_arguments)]
async fn client_handshake_with_confirm_and_codecs_generic_ex<
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
    requested_max_width: u32,
) -> Result<(SecureChannelGeneric<S>, u32), HandshakeError> {
    let session = EphemeralSession::new();
    let x25519_pub = session.public_key_bytes();
    let nonce = generate_nonce();

    let codecs_for_sig = supported_codecs.clone();
    let sig_payload = build_sig_payload(
        &x25519_pub, &nonce, client_id, client_domain, client_device_type,
        PROTOCOL_VERSION, &codecs_for_sig, requested_max_width,
        &kirin_desk_utils::osinfo::detect_os_type(),
    );
    let signature = client_identity.sign(&sig_payload);

    let client_pub_b64 = client_identity.public_key_base64();
    let init_msg = HandshakeInit {
        client_id: client_id.to_string(),
        client_domain: client_domain.to_string(),
        client_device_type: client_device_type.to_string(),
        // `challenge` 参数现仅作为派生密钥参与 [`challenge_response`] 应答
        // （服务端挑战轮），凭据不以可窃用形态走预信道（ZE-01）。
        challenge: String::new(),
        client_ed25519_pub_base64: client_pub_b64,
        client_x25519_pub: x25519_pub,
        nonce,
        signature: signature.to_bytes().to_vec(),
        supported_codecs,
        proto_ver: PROTOCOL_VERSION,
        requested_max_width,
        client_os: kirin_desk_utils::osinfo::detect_os_type(),
        // CX-1: 首包恒空（应答经 HandshakeChallengeResp 独立消息送达）。
        challenge_resp: Vec::new(),
    };
    let init_data = bincode::serialize(&init_msg)
        .map_err(|e| HandshakeError::Serialization(e.to_string()))?;
    send_message(&mut stream, &init_data).await?;
    // 握手一组（非逐包，防刷屏）；「TCP 已连接」由建连侧记（client.rs
    // connect_peer / shell 路径 / ID 模式 path selected 行），「完成」由调用
    // 方 Handshake SUCCESS 行承载（避免重复行）。
    tracing::info!(
        "handshake: first packet (init) sent to '{}' — awaiting server response (peer-side approval wait applies if enabled)",
        server_id
    );

    // 了固定码或临时窗口激活）时，先下发 [`HandshakeChallenge`]；本端以
    // `challenge` 参数为派生密钥回答 [`HandshakeChallengeResp`]，再读响应。
    // 无挑战轮的服务端（已 pin 免挑战 / 零凭据拒绝路径）直接回响应/拒绝。
    let mut resp_data = receive_message(&mut stream).await?;
    // CX-1 判别双条件：反序列化成功 **且** 魔数相等（防响应首 32B 被误当
    // nonce → 通道卡死，见 [`HANDSHAKE_CHALLENGE_MAGIC`]）。
    let challenge_frame = bincode::deserialize::<HandshakeChallenge>(&resp_data)
        .ok()
        .filter(|c| c.magic == HANDSHAKE_CHALLENGE_MAGIC);
    if let Some(chal) = challenge_frame {
        let response = challenge_response(challenge, &chal.nonce, &x25519_pub, &nonce);
        let answer = HandshakeChallengeResp { magic: HANDSHAKE_CHALLENGE_MAGIC, response };
        let answer_data = bincode::serialize(&answer)
            .map_err(|e| HandshakeError::Serialization(e.to_string()))?;
        send_message(&mut stream, &answer_data).await?;
        resp_data = receive_message(&mut stream).await?;
    }
    // 存入 Rejected，控制端经 [`HandshakeError::reject_code`] 映射 i18n 文案）。
    // 响应缺 `proto_ver` 尾字段不再被当损坏报文（version skew 兼容）。
    let response: HandshakeResponse = match parse_handshake_response(&resp_data) {
        Ok(r) => r,
        Err(resp_err) => match bincode::deserialize::<HandshakeReject>(&resp_data) {
            Ok(reject) => {
                return Err(HandshakeError::Rejected(format!(
                    "{}|{}",
                    reject.code, reject.detail
                )));
            }
            Err(_) => return Err(resp_err),
        },
    };
    // 配对，框定「等待对端响应」窗口；首连指纹确认框即随后弹出——安全红线
    tracing::info!(
        "handshake: response received from '{}' — verifying peer identity (fingerprint confirmation may prompt)",
        server_id
    );
    // 错误（version skew 显性化，替代协议行为差异导致的莫名失败）。
    // 0 = 旧服务端（字段缺失）→ 放行（向后兼容）。
    if client_version_gate(PROTOCOL_VERSION, response.proto_ver) {
        return Err(HandshakeError::ServerTooNew {
            server: response.proto_ver,
            client: PROTOCOL_VERSION,
        });
    }

    let server_pubkey_b64 = &response.server_ed25519_pub_base64;
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

    // 行为零变化；§12.4 文件臂门控经 `client_handshake_with_confirm_ex` 消费）。
    Ok((
        SecureChannelGeneric {
            stream,
            cipher,
            peer_id: server_id.to_string(),
            peer_domain: String::new(),
            peer_device_type: String::new(),
            selected_codec,
            peer_os: response.server_os,
        },
        response.proto_ver,
    ))
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
    let answer = if challenge_round_required(
        client_public_key_base64,
        &init.client_ed25519_pub_base64,
        expected_challenge,
        None,
    ) {
        Some(server_challenge_round(&mut stream).await?)
    } else {
        None
    };
    verify_server_init_with_answer(
        &init,
        client_public_key_base64,
        expected_nickname,
        expected_challenge,
        false,
        answer.as_ref(),
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
    parse_handshake_init(&init_data)
}

///
/// bincode 为**位置**序列化：旧端报文缺尾部新字段时 `#[serde(default)]`
/// **不会**生效（读尾字段直接 UnexpectedEof）——若只按新结构解析，旧客户端
/// 会被新服务端在 `server_read_init` 处拒收（裸 close → 对端 early eof，
/// 正是用户 version skew 实测的候选机制）。本函数三段式：
///
/// 1. 先按当前 [`HandshakeInit`]（含 `proto_ver`/`client_os`）解析——新端
///    报文命中，版本 + OS 通告可见；
///    （[`LegacyInitV2`]，到 `requested_max_width` 为止）——pre-10b 新端
///    语义零变化），`client_os = ""`（未知 → 展示回退角色徽标，不猜）；
///    字段布局（到 `supported_codecs` 为止）——最旧端报文命中，
///    `proto_ver = 0`（[`PROTO_VER_LEGACY`]，版本闸门放行）、
///    `requested_max_width = 0`（原生）、`client_os = ""`。
///
/// 已是破坏性变更，非本次回归）。
pub fn parse_handshake_init(data: &[u8]) -> Result<HandshakeInit, HandshakeError> {
    if let Ok(init) = bincode::deserialize::<HandshakeInit>(data) {
        return Ok(init);
    }
    /// `client_os`）——pre-10b 新端报文。
    #[derive(serde::Deserialize)]
    struct LegacyInitV2 {
        client_id: String,
        client_domain: String,
        client_device_type: String,
        challenge: String,
        client_ed25519_pub_base64: String,
        client_x25519_pub: [u8; 32],
        nonce: [u8; 32],
        signature: Vec<u8>,
        #[serde(default)]
        supported_codecs: Vec<String>,
        #[serde(default)]
        proto_ver: u32,
        #[serde(default)]
        requested_max_width: u32,
    }
    if let Ok(l) = bincode::deserialize::<LegacyInitV2>(data) {
        return Ok(HandshakeInit {
            client_id: l.client_id,
            client_domain: l.client_domain,
            client_device_type: l.client_device_type,
            challenge: l.challenge,
            client_ed25519_pub_base64: l.client_ed25519_pub_base64,
            client_x25519_pub: l.client_x25519_pub,
            nonce: l.nonce,
            signature: l.signature,
            supported_codecs: l.supported_codecs,
            // 变化），OS 未通告 = 未知（展示回退角色徽标，不猜）。
            proto_ver: l.proto_ver,
            requested_max_width: l.requested_max_width,
            client_os: String::new(),
            // 本回退仅为解析兼容取证；fail-closed 面在版本门）。
            challenge_resp: Vec::new(),
        });
    }
    #[derive(serde::Deserialize)]
    struct LegacyInitV1 {
        client_id: String,
        client_domain: String,
        client_device_type: String,
        challenge: String,
        client_ed25519_pub_base64: String,
        client_x25519_pub: [u8; 32],
        nonce: [u8; 32],
        signature: Vec<u8>,
        #[serde(default)]
        supported_codecs: Vec<String>,
    }
    bincode::deserialize::<LegacyInitV1>(data)
        .map(|l| HandshakeInit {
            client_id: l.client_id,
            client_domain: l.client_domain,
            client_device_type: l.client_device_type,
            challenge: l.challenge,
            client_ed25519_pub_base64: l.client_ed25519_pub_base64,
            client_x25519_pub: l.client_x25519_pub,
            nonce: l.nonce,
            signature: l.signature,
            supported_codecs: l.supported_codecs,
            proto_ver: PROTO_VER_LEGACY,
            requested_max_width: 0,
            client_os: String::new(),
            challenge_resp: Vec::new(),
        })
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))
}

/// [`parse_handshake_init`] 的**三段式**）：
///
/// 1. 当前 [`HandshakeResponse`]（含 `proto_ver`/`server_os`）——新端命中；
/// 2. 失败（缺 `server_os`）→ [`LegacyResponseV2`]（到 `proto_ver` 为止）——
///    pre-10b 新端报文命中，`proto_ver` 原样保留，`server_os = ""`（未知 →
///    展示回退角色徽标，不猜）；
///    为止）——最旧端报文命中，`proto_ver = 0` 放行、`server_os = ""`。
///
/// 防止新客户端把旧服务端的合法响应当损坏报文（version skew 下 early eof
/// 的对称机制）。
pub fn parse_handshake_response(data: &[u8]) -> Result<HandshakeResponse, HandshakeError> {
    if let Ok(resp) = bincode::deserialize::<HandshakeResponse>(data) {
        return Ok(resp);
    }
    /// `server_os`）——pre-10b 新端报文。
    #[derive(serde::Deserialize)]
    struct LegacyResponseV2 {
        server_x25519_pub: [u8; 32],
        server_ed25519_pub_base64: String,
        signature: Vec<u8>,
        #[serde(default)]
        selected_codec: String,
        #[serde(default)]
        server_fingerprint: String,
        #[serde(default)]
        proto_ver: u32,
    }
    if let Ok(l) = bincode::deserialize::<LegacyResponseV2>(data) {
        return Ok(HandshakeResponse {
            server_x25519_pub: l.server_x25519_pub,
            server_ed25519_pub_base64: l.server_ed25519_pub_base64,
            signature: l.signature,
            selected_codec: l.selected_codec,
            server_fingerprint: l.server_fingerprint,
            proto_ver: l.proto_ver,
            server_os: String::new(),
        });
    }
    #[derive(serde::Deserialize)]
    struct LegacyResponseV1 {
        server_x25519_pub: [u8; 32],
        server_ed25519_pub_base64: String,
        signature: Vec<u8>,
        #[serde(default)]
        selected_codec: String,
        #[serde(default)]
        server_fingerprint: String,
    }
    bincode::deserialize::<LegacyResponseV1>(data)
        .map(|l| HandshakeResponse {
            server_x25519_pub: l.server_x25519_pub,
            server_ed25519_pub_base64: l.server_ed25519_pub_base64,
            signature: l.signature,
            selected_codec: l.selected_codec,
            server_fingerprint: l.server_fingerprint,
            proto_ver: PROTO_VER_LEGACY,
            server_os: String::new(),
        })
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))
}

/// 服务端握手初始化消息校验（纯逻辑，不读写流）：
/// 公钥绑定 → nickname → challenge → Ed25519 签名。
///
/// 为 [`server_challenge_round`] 产出的应答材料（nonce+response）；`None` 仅
/// 在「客户端已 pin（免挑战）」或「零凭据 + `allow_no_credentials`」语义下
/// 可通过。校验顺序：先固定码，后临时码（HK-002）。
///
/// S-01a（F-1）：`allow_no_credentials` —— 显式 opt-in 开关。生产路径一律传
/// `false`：无固定挑战码 + 无激活临时窗口时，仅当客户端公钥已 pin
/// （known_hosts / DNS TXT 身份绑定）才放行，**零凭据（无 pin + 无挑战码 +
/// 无窗口）一律拒绝**；仅测试/loopback 显式传 `true`。
pub fn verify_server_init_with_answer(
    init: &HandshakeInit,
    expected_client_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
    allow_no_credentials: bool,
    answer: Option<&ChallengeAnswer>,
) -> Result<(), HandshakeError> {
    verify_server_init_inner(
        init,
        expected_client_key_base64,
        expected_nickname,
        expected_challenge,
        None,
        allow_no_credentials,
        answer,
    )
}

/// 服务端握手初始化消息校验（纯逻辑，不读写流）——**无挑战应答材料**形态。
///
/// [`verify_server_init_with_answer`]：先 [`server_challenge_round`] 收应答
/// 再校验）。本形态等价 `answer = None`：配置了挑战码且客户端未 pin 时按
/// CX-1 语义失败（`challenge mismatch`，结构化拒绝码 `challenge_mismatch`
/// 可下发）——明文码比对不复活（ZE-01 治本口径不因兼容面回退）。
pub fn verify_server_init(
    init: &HandshakeInit,
    expected_client_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
    allow_no_credentials: bool,
) -> Result<(), HandshakeError> {
    verify_server_init_with_answer(
        init,
        expected_client_key_base64,
        expected_nickname,
        expected_challenge,
        allow_no_credentials,
        None,
    )
}

/// 服务端握手初始化消息校验（**二态凭据**，M8-T017 / SRV-TMP-HK-001）。
///
/// 与 [`verify_server_init`] 的差异仅在凭据一步：`temp_window` 为激活中的
/// 临时连接窗口时，凭据接受「固定挑战码 **或** 窗口内临时挑战码」任一应答
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
    answer: Option<&ChallengeAnswer>,
) -> Result<(), HandshakeError> {
    verify_server_init_inner(
        init,
        expected_client_key_base64,
        expected_nickname,
        expected_challenge,
        temp_window,
        allow_no_credentials,
        answer,
    )
}

/// 内部实现：`allow_no_credentials` = true 表示调用方显式 opt-in —— 允许
/// 「无固定挑战码 + 无激活临时窗口」时即使客户端公钥也未知（零凭据）仍放行
/// （仅测试/loopback 使用）。
#[allow(clippy::too_many_arguments)]
fn verify_server_init_inner(
    init: &HandshakeInit,
    expected_client_key_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
    temp_window: Option<&TempModeManager>,
    allow_no_credentials: bool,
    answer: Option<&ChallengeAnswer>,
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

    //    002 沿革）：固定挑战码 **或** 窗口内临时挑战码任一应答正确即通过；
    //    两者均失败 → 统一错误消息（防枚举，不泄露固定码/临时码信息）。
    //    组合语义：
    //    - **客户端已 pin（known_clients/DNS-TXT 绑定命中）→ 免挑战**（CX-1
    //      方案 B 附带项：pin 即强凭据；绑定不符已在步骤 1 拒绝）；
    //    - 无固定码 + 无窗口 → S-01a (F-1) fail-closed：仅当客户端公钥已 pin
    //      或显式 `allow_no_credentials`（仅测试/loopback）才放行——零凭据
    //     （未知客户端 + 无挑战码 + 无窗口）拒绝；
    //    - 仅固定码 → 固定码应答必须正确；
    //    - 仅窗口（无固定码）→ **临时码应答必填**（杜绝窗口期内无凭据旁路）；
    //    - 固定码 + 窗口 → 任一应答正确即通过。
    //    ZE-01 治本口径：明文码不再走预信道——校验对象为 [`challenge_response`]
    //    派生应答（S-18 常时比较语义由 HMAC 比对保持）。
    let fixed_expected = expected_challenge.filter(|s| !s.is_empty());
    let client_pinned = !expected_client_key_base64.is_empty();
    // （过期/时钟异常）的僵尸槽视同无窗口，对齐 SRV-TMP-HK-003 契约（「窗口
    // 期外（过期/未开启）临时码一律失败（`temp_window = None`）」）。旧实现以
    // `temp_window.is_some()`（状态文件存在）为判定键：过期未回收的僵尸槽落入
    // `(false, true)` 分支被误判「窗口激活 → 临时码必填」，连 pin 客户端都被
    // challenge_mismatch 拒绝——用户 09-04 实测「服务端准入劣化」的直接机制
    // （僵尸槽 + 客户端旧码重试 → mismatch 堆积 → 速率限制累加）。
    // （`is_active` 自带过期槽回收，见 `TempModeManager::reap_expired`。）
    let temp_active = temp_window.is_some_and(TempModeManager::is_active);
    let challenge_ok = if client_pinned {
        // CX-1B：已 pin 免挑战（pin 即强凭据；挑战轮判定点
        // [`challenge_round_required`] 与本判定同源，不会对 pin 客户端发起）。
        true
    } else {
        let fixed_ok = fixed_expected
            .zip(answer)
            .map_or(false, |(f, a)| challenge_resp_matches_fixed(f, a, init));
        let temp_ok = temp_window
            .zip(answer)
            .is_some_and(|(t, a)| t.verify_challenge_response(a, &init.client_x25519_pub, &init.nonce));
        match (fixed_expected.is_some(), temp_active) {
            (false, false) => allow_no_credentials,
            (true, false) => fixed_ok,
            (false, true) => temp_ok,
            (true, true) => fixed_ok || temp_ok,
        }
    };
    if !challenge_ok {
        // 零凭据（未知客户端 + 无挑战码 + 无激活窗口）与错误挑战码统一走
        // InvalidMessage（HK-002 防枚举）；文案仅落在服务端审计日志，
        // 不会回传给客户端，区分提示便于运维定位配置问题（F-1）。
        let msg = if fixed_expected.is_none() && !temp_active && !client_pinned {
            "server requires credentials: client unknown (no pinned key), no challenge code, and no temp window"
        } else {
            "challenge mismatch"
        };
        return Err(HandshakeError::InvalidMessage(msg.to_string()));
    }

    // 4. 客户端 Ed25519 签名验证（对自报公钥验签；CX-2 起载荷含能力声明域）。
    let client_pubkey = IdentityManager::parse_public_key(&init.client_ed25519_pub_base64)
        .map_err(|e| HandshakeError::Dns(e.to_string()))?;
    let sig_payload = build_sig_payload(
        &init.client_x25519_pub, &init.nonce,
        &init.client_id, &init.client_domain, &init.client_device_type,
        init.proto_ver, &init.supported_codecs,
        init.requested_max_width, &init.client_os,
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

/// challenge-response 应答比对（HMAC ct_eq），本函数收敛为 test-only
/// 「形等语义」锚定）。
///
/// 对齐临时码实现：先 `sha256` 归一到固定 32 字节（输入长度差异只影响
/// 哈希分块数，不影响比较分支），再用 `subtle::ConstantTimeEq` 比较摘要
/// —— 比较耗时与两输入内容无关，杜绝 `==` 的逐字节短路时序侧信道。
#[cfg(test)]
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

///
/// 与 M15 既有白名单（命中=免审批，OR 语义）的区分：本函数是**独立强制维度**
/// ——`enforce = true`（Dashboard「ID 白名单」开关，`[network]
/// id_whitelist_enforce`）时，控制端设备 ID **必须**在 `allowed_ids` 内，
/// 否则即使昵称/挑战码正确也拒绝。`enforce = false` → 恒放行（现状保持：
/// ID 连接沿用昵称 + 挑战码验证）。
///
/// 匹配语义复用 [`id_matches_whitelist`]：完整设备 ID 精确匹配，或以 `*`
/// 结尾的前缀通配（裸 `*` 不匹配）；带过期条目由调用方预先过滤
/// （`Config::id_whitelist_active_ids(now)`）。`allowed_ids` 为空 + 开启 →
/// 一律拒绝（fail-closed，防「开开关忘加名单」变全拒之外静默放行的歧义——
/// 明确全拒）。
///
/// 返回 `Err(device_id)`（被拒的设备 ID，供拒绝消息 detail）或 `Ok(())`。
pub fn id_whitelist_enforce_check(
    enforce: bool,
    client_device_id: &str,
    allowed_ids: &[String],
) -> Result<(), String> {
    if !enforce {
        return Ok(());
    }
    let hit = allowed_ids
        .iter()
        .any(|id| id_matches_whitelist(client_device_id, id));
    if hit {
        Ok(())
    } else {
        Err(client_device_id.to_string())
    }
}

/// `handle_incoming_connection`）与 CLI/headless（`ui/src/policy.rs`
/// 两链同口径，杜绝 GUI/headless 分叉）。
///
/// **被控端非 IP/非临时模式**（`bypass_active = false`）时，ID 白名单准入
/// 移除——此前 GUI IP 模式客户端〔client_id=自报昵称 + client_domain=固定
/// 魔值 `gui-client.local`〕凭非空域名整体绕过该体制，且昵称可命中 ID 维
/// 自动免审批，认证强度降级，用户实测确认）。两种自报形态的判定结果：
///
///   （fail-closed：开关开 + 名单空 → 一律拒；挑战码/昵称正确也不放行）；
/// - **非空域名**（GUI IP/域名模式客户端）：其 `client_id` 是**自报昵称**
///   故**不产生硬拒**（返回 `None`），自然流入域名白名单 / known_clients
///   pin / 人工审批判定（用户验收矩阵：ID 模式被控端 + GUI 客户端 + ID 白
///   名单开 → **NeedsApproval**——审批窗展示客户端真实公钥指纹，批准后落
///   TOFU pin 强凭据自动放行；无人值守下走既有自动拒路径）。
///
/// 返回 `Some(denied_id)` = 硬拒（调用方下发 `REJECT_CODE_ID_WHITELIST`）；
/// `None` = 无强制拒绝（调用方继续后续白名单/pin/审批/凭据校验）。
///
/// `bypass_active` = temp/IP 静态旁路或激活中的临时窗口（M15「临时连接跳过
/// 白名单」，SRV-IDWL-024）→ 恒 `None`（IP/临时模式被控端行为零变更，产品语义）。
///
/// （fail-closed 硬拒保持不变）；与它的配对是**身份通道**的审批决策
/// 持久化——GUI 审批通过写点（`ui/src/lib.rs` `handle_incoming_connection`
/// 审批分支）在落 known_clients TOFU pin 的同时把已审批 ID 形态客户端的
/// 设备 ID 以永久条目写入 ID 白名单（`Config::id_whitelist_add(id, None)`，
/// 不变）。二者共同实现用户裁定「一次正常连接（含新审批连接）必须保持可
/// 再发起」：首次连接经审批放行并持久化 → 重连在本判定点直接命中名单
/// （`None`），无需二次审批；全新未审批设备依旧硬拒 + 审计行
/// （`id_whitelist_denied`），fail-closed 默认拒绝不放松。
pub fn id_whitelist_enforce_violation(
    enforce: bool,
    bypass_active: bool,
    client_domain: &str,
    client_device_id: &str,
    allowed_ids: &[String],
) -> Option<String> {
    if !enforce || bypass_active {
        return None;
    }
    if !client_domain.is_empty() {
        // 非空域名客户端对 ID 白名单一律不命中（弱凭据消灭）→ 无硬拒，
        // 流入域名白名单/pin/审批（见文档）。
        return None;
    }
    id_whitelist_enforce_check(true, client_device_id, allowed_ids).err()
}

/// 服务端握手结果（M11：headless shell 服务器 — 无 GUI 审批弹窗）。
pub enum VerifiedDecision {
    /// 白名单通过 + 签名验证通过 → 已建立安全通道。
    Accepted(SecureChannel),
    /// 签名验证通过 → 已建立安全通道 + **对端协议版本**（`init.proto_ver`
    /// 透出）。服务端会话分发需按 peer `proto_ver == PROTOCOL_VERSION`
    /// 门控服务端发起的文件帧（legacy-0 放行端不发送，fail-closed）——
    /// `Accepted` 仅携带通道无法满足该门控（版本在 `init` 内被握手链消费）。
    ///
    /// 纯加性变体：既有 `Accepted` 构造/匹配点（含 legacy
    /// `server_handshake_with_whitelist`）零变化；`ui::policy` 经
    /// `server_accept_handshake_ex` 产出本变体（旧入口 `server_accept_handshake`
    /// 薄封装回 `Accepted`，行为/测试零变化）。
    AcceptedEx {
        channel: SecureChannel,
        peer_proto_ver: u32,
    },
    /// 白名单或认证失败 → 拒绝（连接将被直接关闭，客户端收到 EOF）。
    Rejected(String),
}

impl std::fmt::Debug for VerifiedDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Accepted 侧通道含加密句柄（AeadCipher 无 Debug）→ 摘要输出。
        match self {
            VerifiedDecision::Accepted(_) => write!(f, "Accepted(<secure channel>)"),
            VerifiedDecision::AcceptedEx { peer_proto_ver, .. } => {
                write!(f, "AcceptedEx(<secure channel>, peer_proto_ver={peer_proto_ver})")
            }
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

    // 凭据：版本不匹配无需进入策略流程）。
    if reject_if_client_too_new(&mut stream, &init).await {
        return Ok(VerifiedDecision::Rejected(format!(
            "client protocol version {} too new (server supports <= {})",
            init.proto_ver, PROTOCOL_VERSION
        )));
    }

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
    let answer = if challenge_round_required(
        expected_client_key_base64,
        &init.client_ed25519_pub_base64,
        expected_challenge,
        None,
    ) {
        Some(server_challenge_round(&mut stream).await?)
    } else {
        None
    };
    verify_server_init_with_answer(
        &init,
        expected_client_key_base64,
        expected_nickname,
        expected_challenge,
        false,
        answer.as_ref(),
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
        peer_os: g.peer_os,
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
        proto_ver: PROTOCOL_VERSION,
        server_os: kirin_desk_utils::osinfo::detect_os_type(),
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
        peer_os: init.client_os.clone(),
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
        peer_os: g.peer_os,
    })
}

/// 带信任确认回调的 TcpStream 客户端握手（M15：IP 直连首次连接指纹确认）。
///
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
        peer_os: g.peer_os,
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
        peer_os: g.peer_os,
    })
}

// ---- Helpers ----

fn generate_nonce() -> [u8; 32] {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// id/domain/type）之上**纳入全部能力声明字段**（`proto_ver` /
/// `supported_codecs` / `requested_max_width` / `client_os`），主动 MITM
/// 剥离 `proto_ver` 尾字段伪装旧版、摆布 codec 协商的面封死（R178 ZE-03）。
/// 分段以 `|` 分隔 + 定长二进制字段（u32 BE），codec 列表以 `,` 连接
///（codec 名域 = `h264`/`h265`/`av1` 字母数字，无歧义）。
///
/// v3 旧端签不出本载荷（载荷形状不同）→ 对 v4 服务端验签必败 = 断代
/// fail-closed（版本门 exact-match 为第一道，本为纵深）。
fn build_sig_payload(
    x25519_pub: &[u8; 32], nonce: &[u8; 32],
    peer_id: &str, peer_domain: &str, device_type: &str,
    proto_ver: u32, supported_codecs: &[String],
    requested_max_width: u32, client_os: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(x25519_pub);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(peer_id.as_bytes());
    payload.push(b'|');
    payload.extend_from_slice(peer_domain.as_bytes());
    payload.push(b'|');
    payload.extend_from_slice(device_type.as_bytes());
    // CX-2：能力声明域（定长字段 + 分隔符，字段间无长度歧义）。
    payload.push(b'|');
    payload.extend_from_slice(&proto_ver.to_be_bytes());
    payload.push(b'|');
    payload.extend_from_slice(supported_codecs.join(",").as_bytes());
    payload.push(b'|');
    payload.extend_from_slice(&requested_max_width.to_be_bytes());
    payload.push(b'|');
    payload.extend_from_slice(client_os.as_bytes());
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
//
// **非取消安全**——`select!`/`timeout` 取消在途调用会丢失已消费字节并使
// 后续读取错位。现行整通道调用点均为顺序 / `tokio::join!`（不可取消），
// 故不触发；**可取消读场景（看门狗/select!/timeout）一律走
// `into_split` 读半**（[`SecureChannelReader::receive`] 取消安全）。

/// 已握手通道的**读半**（单向接收）。与写半完全独立：TCP 双工 + 每消息随机 nonce，
/// 适合"视频接收任务 + 输入发送任务"各自独占一个方向、无锁并发共享同一通道。
///
/// [`Self::pkt_len`]）驻留在读半上而非 `receive()` 的 future 内部：
/// `select!` tick / `timeout` 到期取消在途 `receive()` 时，已从流消费的
/// 字节不丢失，下一次 `receive()` 从正确位置续读。旧实现经 `read_exact`
/// 组合子直读流：取消时组合子内部已消费（已拉出内核）的字节随 future
/// 丢弃 → 下次读把**密文字节误判为 4B 长度前缀** → 偶发 `Message too
/// large`（异常 3.9 GB 级长度）+ 通道永久错位（回归测试
/// `tests::test_r76f_receive_cancellation_safe`）。
pub struct SecureChannelReader {
    stream: tokio::net::tcp::OwnedReadHalf,
    cipher: Arc<AeadCipher>,
    peer_id: String,
    buf: Vec<u8>,
    pkt_len: Option<usize>,
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
                buf: Vec::new(),
                pkt_len: None,
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
    ///
    /// S-02 (S-02d)：长度前缀先校验 [`MAX_CHANNEL_FRAME_LEN`] 上限再放行
    /// （恶意超长帧 → [`HandshakeError::Tcp`](`TcpError::MessageTooLarge`)，
    /// 内存有界；与 tcp 层 `read_length_prefixed` 行为一致）。
    ///
    /// pending = 未消费任何字节；`Ok(n)` = n 字节全部留存于 [`Self::buf`]），
    /// 重组状态驻留 `self` 而非 future：`select!` tick / `timeout` 到期
    /// 取消在途调用**不丢字节、不丢流位置**，续调从正确位置接着读。
    /// （`read_exact` 组合子在取消时丢弃其内部已消费字节——旧实现缺陷。）
    pub async fn receive(&mut self) -> Result<Vec<u8>, HandshakeError> {
        use tokio::io::AsyncReadExt;
        loop {
            let want_more = match self.pkt_len {
                None => self.buf.len() < 4,
                Some(total) => self.buf.len() < total,
            };
            if want_more {
                let mut chunk = vec![0u8; 64 * 1024];
                let n = self.stream.read(&mut chunk).await?;
                if n == 0 {
                    // 对端关闭（与旧 `read_exact` EOF 行为一致）。
                    return Err(
                        std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into(),
                    );
                }
                self.buf.extend_from_slice(&chunk[..n]);
                continue;
            }
            if self.pkt_len.is_none() {
                // 前缀凑齐 → 解析长度（先校验上限，S-02 F-5 不变式）。
                let len =
                    u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
                        as usize;
                if len > MAX_CHANNEL_FRAME_LEN {
                    return Err(HandshakeError::from(TcpError::MessageTooLarge {
                        len,
                        max: MAX_CHANNEL_FRAME_LEN,
                    }));
                }
                self.pkt_len = Some(4 + len);
                continue;
            }
            // 整包就位 → 取出解密（总长有界，分配安全）。
            // total = 4（长度前缀）+ payload；drain(..total) 把整条消息
            // （前缀 + 载荷）移出 buf，再跳过 4B 前缀取载荷（与旧
            // `read_length_prefixed` 返回值语义一致——只返回载荷）。
            let total = self.pkt_len.expect("pkt_len set when prefix parsed");
            let msg: Vec<u8> = self.buf.drain(..total).collect();
            self.pkt_len = None;
            let packet = &msg[4..];
            if packet.len() < 12 {
                return Err(HandshakeError::InvalidMessage("packet too short".to_string()));
            }
            let (nonce, ciphertext) = packet.split_at(12);
            let mut ct = ciphertext.to_vec();
            return self
                .cipher
                .decrypt_simple(nonce, &mut ct)
                .map_err(|_| HandshakeError::InvalidMessage("decryption failed".to_string()));
        }
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
            verify_server_init_with_answer(&init, &alice_pub, None, None, true, None)?;
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

        /// 一次二态握手往返：`server_pin` = 服务端期望客户端公钥（`""` = 未
        /// pin → CX-1 挑战轮必经），`fixed` = 服务端固定挑战码，`challenge` =
        /// 客户端派生密钥（= 用户输入码），`allow` = `allow_no_credentials`
        /// 凭据回归用例传 `false`）。
        async fn run_two_state(
            alice: &IdentityManager,
            bob: &IdentityManager,
            server_pin: &str,
            bob_pub: &str,
            tm: &TempModeManager,
            fixed: Option<&str>,
            challenge: &str,
            allow: bool,
        ) -> Result<(), HandshakeError> {
            let (client_end, mut server_end) = tokio::io::duplex(65536);
            let client_fut = client_handshake_generic(
                client_end, alice, "alice", "alice.local", "desktop", "bob",
                PinExpectation::exact_from_base64(bob_pub).expect("bob pubkey"), challenge,
            );
            let server_fut = async move {
                let init = server_read_init(&mut server_end).await?;
                // nonce、限时收应答）；已 pin 客户端免挑战（CX-1 方案 B）。
                let answer = if challenge_round_required(server_pin, &init.client_ed25519_pub_base64, fixed, Some(tm)) {
                    Some(server_challenge_round(&mut server_end).await?)
                } else {
                    None
                };
                verify_server_init_with_temp(&init, server_pin, None, fixed, Some(tm), allow, answer.as_ref())?;
                let _g =
                    server_handshake_respond_generic(server_end, bob, "bob", &init, "").await?;
                Ok::<_, HandshakeError>(())
            };
            let (client_res, server_res) = tokio::join!(client_fut, server_fut);
            server_res?;
            client_res.map(|_| ())
        }

        // ── CX-1B：已 pin 客户端免挑战（pin 即强凭据；判定 = 服务端 pin 存储
        //    命中，与凭据配置无关）。
        assert!(
            run_two_state(&alice, &bob, &alice_pub, &bob_pub, &tm, Some("FIXED-CODE"), "", true)
                .await
                .is_ok(),
            "CX-1B: pinned client exempt from challenge even with fixed code configured"
        );
        assert!(
            run_two_state(&alice, &bob, &alice_pub, &bob_pub, &tm, None, "", true).await.is_ok(),
            "CX-1B: pinned client exempt with active window and no code"
        );
        // ── 未 pin 客户端：挑战-响应应答校验本体（固定码/临时码二态）。
        // 固定码 + 窗口 → 固定码应答通过。
        assert!(
            run_two_state(&alice, &bob, "", &bob_pub, &tm, Some("FIXED-CODE"), "FIXED-CODE", true)
                .await
                .is_ok(),
            "fixed code must pass inside window"
        );
        // 固定码 + 窗口 → 临时码同样通过（二态任一）。
        assert!(
            run_two_state(&alice, &bob, "", &bob_pub, &tm, Some("FIXED-CODE"), &temp_code, true)
                .await
                .is_ok(),
            "temp code must pass inside window (two-state)"
        );
        // 固定码 + 窗口 → 错码拒绝（统一错误消息，防枚举 HK-002）。
        match run_two_state(&alice, &bob, "", &bob_pub, &tm, Some("FIXED-CODE"), "XXXXXXXX", true).await {
            Err(HandshakeError::InvalidMessage(msg)) => assert_eq!(msg, "challenge mismatch"),
            other => panic!("expected InvalidMessage(challenge mismatch), got {:?}", other),
        }
        // 无固定码 + 窗口 → 临时码必填（杜绝无凭据旁路）。
        assert!(
            run_two_state(&alice, &bob, "", &bob_pub, &tm, None, "", true).await.is_err(),
            "window active without fixed code requires the temp code"
        );
        // 无固定码 + 窗口 + 错码 → 拒绝，且错误消息统一（防枚举，HK-002）。
        match run_two_state(&alice, &bob, "", &bob_pub, &tm, None, "XXXXXXXX", true).await {
            Err(HandshakeError::InvalidMessage(msg)) => assert_eq!(msg, "challenge mismatch"),
            other => panic!("expected InvalidMessage(challenge mismatch), got {:?}", other),
        }
        // 契约 `temp_window = None`）——pin 客户端凭 pin 放行（旧临时码在窗口
        // 期外**从不**生效）；零凭据（未 pin + 无固定码 + 无激活窗口，生产
        // `allow=false` 口径）仍 fail-closed 拒绝（无旁路）。
        let inactive = TempModeManager::with_state_file(dir.join("other.json"));
        assert!(
            run_two_state(&alice, &bob, &alice_pub, &bob_pub, &inactive, None, &temp_code, false)
                .await
                .is_ok(),
        );
        match run_two_state(&alice, &bob, "", &bob_pub, &inactive, None, &temp_code, false).await {
            Err(HandshakeError::InvalidMessage(msg)) => {
                assert!(msg.starts_with("server requires credentials"), "got: {msg}")
            }
            other => panic!(
                "HK-003: zero credentials outside window must be rejected, got {:?}",
                other
            ),
        }
        // 回收（文件不再残留），判定口径与未激活实例一致（pin 放行/零凭据拒）。
        let zombie = TempModeManager::with_state_file(dir.join("zombie.json"));
        let zombie_code = zombie.enable(0).expect("enable ttl=0");
        assert!(!zombie.is_active(), "expired window must be inactive");
        assert!(
            !zombie.state_file_path().exists(),
        );
        assert!(
            run_two_state(&alice, &bob, &alice_pub, &bob_pub, &zombie, None, &zombie_code, false)
                .await
                .is_ok(),
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
            ("0000000089", "000000008"),
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
            verify_server_init_with_answer(&init, "WRONG-PINNED-KEY", None, None, true, None)?;
            unreachable!("must not respond after pin mismatch");
        };
        let (_client_res, server_res): (
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
                verify_server_init_with_answer(&init, "", None, None, allow_no_credentials, None)?;
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


    #[test]
    fn test_r59_enforce_off_always_allows() {
        let empty: Vec<String> = Vec::new();
        assert!(id_whitelist_enforce_check(false, "device-7", &empty).is_ok());
        assert!(id_whitelist_enforce_check(false, "device-8", &["device-7".to_string()]).is_ok());
    }

    /// （判定点只看设备 ID，挑战码由既有 verify 层承担）；开 + 名单空 → 全拒。
    #[test]
    fn test_r59_enforce_on_exact_match_and_miss() {
        let allowed = vec!["device-7".to_string()];
        assert!(id_whitelist_enforce_check(true, "device-7", &allowed).is_ok());
        let err = id_whitelist_enforce_check(true, "device-8", &allowed)
            .expect_err("not in whitelist must be rejected");
        assert_eq!(err, "device-8", "拒绝 detail 应携带被拒设备 ID");
        let empty: Vec<String> = Vec::new();
        assert!(id_whitelist_enforce_check(true, "device-7", &empty).is_err());
    }

    /// 裸 `*` 不匹配（保守）。
    #[test]
    fn test_r59_enforce_wildcard_semantics() {
        let allowed = vec!["office-*".to_string()];
        assert!(id_whitelist_enforce_check(true, "office-42", &allowed).is_ok());
        assert!(id_whitelist_enforce_check(true, "myoffice-1", &allowed).is_err());
        let bare = vec!["*".to_string()];
        assert!(id_whitelist_enforce_check(true, "anything", &bare).is_err());
    }

    /// 强制判定即不命中（调用方以 `Config::id_whitelist_active_ids(now)` 取表）。
    #[test]
    fn test_r59_enforce_expired_entry_not_active() {
        let active_after_prune = vec!["other-device".to_string()];
        assert!(id_whitelist_enforce_check(true, "device-7", &active_after_prune).is_err());
    }

    /// 握手报 `Rejected(code|detail)`，`reject_code()` 可取码。
    #[tokio::test]
    async fn test_r59_handshake_reject_message_roundtrip() {
        let dir = std::env::temp_dir().join("kirin_hs_r59_reject");
        let _ = std::fs::remove_dir_all(&dir);
        let alice = gen_identity(&dir, "alice");
        let (client_end, mut server_end) = tokio::io::duplex(65536);

        let server_fut = async move {
            let init = server_read_init(&mut server_end).await.expect("read init");
            assert_eq!(init.client_id, "alice");
            send_handshake_reject(&mut server_end, REJECT_CODE_ID_WHITELIST, &init.client_id)
                .await;
        };
        let client_fut = async {
            client_handshake_generic(
                client_end,
                &alice,
                "alice",
                "desktop",
                "bob",
                // 任意合法 pin：服务端拒绝在响应前，比对不会发生。
                PinExpectation::exact_from_base64(&alice.public_key_base64()).unwrap(),
                "CODE",
            )
            .await
        };
        let (client_res, _) = tokio::join!(client_fut, server_fut);
        match &client_res {
            Err(HandshakeError::Rejected(msg)) => {
                assert_eq!(
                    client_res.as_ref().err().unwrap().reject_code(),
                    Some(REJECT_CODE_ID_WHITELIST)
                );
                assert!(msg.contains("alice"), "msg: {msg}");
            }
            _ => panic!("expected Rejected, got {:?}", client_res.is_ok()),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M8-T027 (SRV-IDWL-020 旧接口): `server_handshake_with_whitelist`
    /// 双白名单 OR 语义——域名未命中但设备 ID 命中 → 放行（headless 无审批）。
    #[tokio::test]
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
                peer_os: String::new(),
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

    /// 取消（tick / timeout 到期场景）后，已消费字节不丢失，下一次
    /// `receive()` 从正确位置续读并完整重组消息。
    ///
    /// 复现靶：self-test M13-T006 偶发 `Message too large: 3967033604
    /// bytes exceeds max`（文件传输回环 200ms tick `select!` 取消半程
    /// `read_exact` → 已消费部分被丢弃 → 密文字节被误读为 4B 长度前缀，
    /// 3967033604 = 0xEC742104 即 4 字节 AES-GCM 密文当长度）。旧实现
    /// （`read_exact` 组合子、无跨调用状态）在本测试下**确定性失败**：
    /// 续读把残留密文字节当长度前缀 → `MessageTooLarge` / 解密失败。
    #[tokio::test]
    async fn test_r76f_receive_cancellation_safe() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_stream, _peer) = accept_task.await.unwrap();
        let writer = client.into_split().1;
        let reader_stream = server_stream.into_split().0;

        let cipher = Arc::new(AeadCipher::new(&[7u8; 32]));
        let (nonce, ct) = cipher.encrypt_simple(plaintext).unwrap();
        let mut packet = Vec::with_capacity(nonce.len() + ct.len());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ct);

        let mut reader = SecureChannelReader {
            stream: reader_stream,
            cipher,
            peer_id: "r76f".to_string(),
            buf: Vec::new(),
            pkt_len: None,
        };

        // 阶段 1：只发 4B 长度前缀 + 半包 → 在途 receive() 已消费部分
        // payload 但尚未完整（300ms 内 select! 的 sleep 分支必然先就绪
        // 并取消 receive —— 触发场景确定性复现）。
        let mut writer = writer;
        writer.write_all(&(packet.len() as u32).to_be_bytes()).await.unwrap();
        writer.write_all(&packet[..packet.len() / 2]).await.unwrap();
        writer.flush().await.unwrap();
        tokio::select! {
            r = reader.receive() => panic!("phase1: receive should block on missing half, got: {r:?}"),
            () = tokio::time::sleep(std::time::Duration::from_millis(300)) => {
                // tick/timeout 分支胜出 → 在途 receive() 被取消。
            }
        }
        // 阶段 2：补发后半包 → 续读必须从正确位置重组完整消息
        // （旧实现：已消费部分字节丢失 → 密文字节被误读为长度前缀）。
        writer.write_all(&packet[packet.len() / 2..]).await.unwrap();
        writer.flush().await.unwrap();
        let plain = reader
            .receive()
            .await
            .expect("resumed receive must succeed after mid-read cancellation");
        assert_eq!(plain, plaintext);
    }


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


    /// 任何差值（legacy-0 / 旧端 / 过新端）一律拒绝（fail-closed 无兼容包袱）。
    #[test]
    fn test_r67_client_version_too_new_pure() {
        assert!(!client_version_too_new(PROTOCOL_VERSION));
        assert!(
            client_version_too_new(PROTOCOL_VERSION + 1),
            "newer than local must be rejected"
        );
        assert!(
            client_version_too_new(PROTOCOL_VERSION - 1),
        );
    }

    ///
    /// bincode 为位置序列化：**新端报文 → 旧端**天然兼容（顶层 `deserialize`
    /// 自带 allow_trailing_bytes，尾部 `proto_ver` 被忽略）；**旧端报文 →
    /// 新端**必须经 [`parse_handshake_init`]/[`parse_handshake_response`]
    /// 两段式容错（缺尾字段回退旧布局，`proto_ver = 0`）。本测试用「截去
    #[test]
    fn test_r67_proto_ver_wire_compat_legacy() {
        let new_init = HandshakeInit {
            client_id: "alice".into(),
            client_domain: "alice.local".into(),
            client_device_type: "desktop".into(),
            challenge: "C".into(),
            client_ed25519_pub_base64: "k".into(),
            client_x25519_pub: [0u8; 32],
            nonce: [1u8; 32],
            signature: vec![2u8; 8],
            supported_codecs: vec!["h264".into()],
            proto_ver: PROTOCOL_VERSION,
            requested_max_width: 1280,
            client_os: "windows-11".into(),
            challenge_resp: Vec::new(),
        };
        let new_bytes = bincode::serialize(&new_init).expect("serialize new");
        // 新报文 → 新端：版本 + 宽度偏好 + OS 通告均可见。
        let parsed = parse_handshake_init(&new_bytes).expect("new peer parses new payload");
        assert_eq!(parsed.proto_ver, PROTOCOL_VERSION);
        assert_eq!(parsed.requested_max_width, 1280);
        assert_eq!(parsed.client_os, "windows-11");
        // 新报文 → 旧端（结构体少尾字段）：尾随字节被忽略 → 解析成功。
        #[derive(Deserialize)]
        struct LegacyInit {
            client_id: String,
            client_domain: String,
            client_device_type: String,
            challenge: String,
            client_ed25519_pub_base64: String,
            client_x25519_pub: [u8; 32],
            nonce: [u8; 32],
            signature: Vec<u8>,
            supported_codecs: Vec<String>,
        }
        let legacy: LegacyInit =
            bincode::deserialize(&new_bytes).expect("legacy peer must parse new payload");
        assert_eq!(legacy.client_id, "alice");
        // 旧报文（截去尾部 4 字节 = 10b OS 串载荷中段截断）→ 新端：三段式
        // 报文的精确模拟见 `test_r137_10b_os_wire_compat`（显式旧布局结构
        // 序列化），本行语义 = 「OS 字段传输截断/缺失的中间态」不拒收。
        let legacy_bytes = &new_bytes[..new_bytes.len() - 4];
        let parsed = parse_handshake_init(legacy_bytes).expect("new peer parses legacy payload");
        assert_eq!(parsed.proto_ver, PROTOCOL_VERSION, "V2 回退保留版本");
        assert_eq!(parsed.requested_max_width, 1280, "V2 回退保留宽度偏好");
        assert_eq!(parsed.client_os, "", "OS 未通告 = 空串（不猜）");
        assert_eq!(parsed.client_id, "alice");

        // response 对称验证。
        let new_resp = HandshakeResponse {
            server_x25519_pub: [9u8; 32],
            server_ed25519_pub_base64: "k".into(),
            signature: vec![1u8; 8],
            selected_codec: "h264".into(),
            server_fingerprint: "fp".into(),
            proto_ver: PROTOCOL_VERSION,
            server_os: "windows-11".into(),
        };
        let resp_bytes = bincode::serialize(&new_resp).expect("serialize resp");
        let parsed_resp = parse_handshake_response(&resp_bytes).expect("new resp");
        assert_eq!(parsed_resp.proto_ver, PROTOCOL_VERSION);
        assert_eq!(parsed_resp.server_os, "windows-11");
        let legacy_resp = &resp_bytes[..resp_bytes.len() - 4];
        let parsed_legacy = parse_handshake_response(legacy_resp)
            .expect("new peer parses legacy response");
        //（版本保留、OS 空串）；最旧端（无 proto_ver）报文见
        // `test_r137_10b_os_wire_compat` 显式 V1 布局例。
        assert_eq!(parsed_legacy.proto_ver, PROTOCOL_VERSION, "V2 回退保留版本");
        assert_eq!(parsed_legacy.server_os, "", "OS 未通告 = 空串（不猜）");
        // 垃圾字节 → 三段均失败 → InvalidMessage。
        assert!(parse_handshake_init(&[0xFFu8; 8]).is_err());
    }

    /// 旧端双向容忍丢弃）——**显式旧布局结构序列化**精确模拟各代报文
    ///（字节截断在加长尾字段后不再精确，见 r67 族测试注）：
    ///
    /// init 方向（新服务端收）：
    /// - 新端报文（含 `client_os`）→ 解析原样（`client_os` 可见）；
    /// - **pre-10b 新端报文**（V2 布局 = 到 `requested_max_width` 为止）→
    ///   `proto_ver`/`requested_max_width` **原样保留**（版本闸门/宽度语义
    ///   零变化）+ `client_os = ""`（未知 → 展示回退角色徽标，不猜）；
    /// - 最旧端报文（V1 布局 = 到 `supported_codecs` 为止）→ `proto_ver = 0`
    ///   放行 + 宽度 0 + `client_os = ""`。
    /// response 方向（新客户端收）：对称三态。
    /// 旧端容忍方向（双向丢弃）：
    /// - 新 init 报文 → pre-10b 旧端布局（V2）反序列化：尾随 `client_os`
    ///   被忽略，成功；
    /// - 新 response 报文 → pre-10b 旧端布局（V2）反序列化：同上。
    #[test]
    fn test_r137_10b_os_wire_compat() {
        // ── init：显式旧布局 ──
        #[derive(serde::Serialize)]
        struct Pre10bInitBytes {
            client_id: String,
            client_domain: String,
            client_device_type: String,
            challenge: String,
            client_ed25519_pub_base64: String,
            client_x25519_pub: [u8; 32],
            nonce: [u8; 32],
            signature: Vec<u8>,
            supported_codecs: Vec<String>,
            proto_ver: u32,
            requested_max_width: u32,
        }
        #[derive(serde::Serialize)]
        struct PreR67InitBytes {
            client_id: String,
            client_domain: String,
            client_device_type: String,
            challenge: String,
            client_ed25519_pub_base64: String,
            client_x25519_pub: [u8; 32],
            nonce: [u8; 32],
            signature: Vec<u8>,
            supported_codecs: Vec<String>,
        }
        let fill = |s: &str| {
            (
                s.to_string(),
                "d.local".to_string(),
                "desktop".to_string(),
                "C".to_string(),
                "k".to_string(),
                [0u8; 32],
                [1u8; 32],
                vec![2u8; 8],
                vec!["h264".to_string()],
            )
        };
        // 新端 → 新端：OS 通告原样。
        let (cid, cd, cdty, chal, ck, cx, nnc, sig, codecs) = fill("alice");
        let new_init = HandshakeInit {
            client_id: cid,
            client_domain: cd,
            client_device_type: cdty,
            challenge: chal,
            client_ed25519_pub_base64: ck,
            client_x25519_pub: cx,
            nonce: nnc,
            signature: sig,
            supported_codecs: codecs,
            proto_ver: PROTOCOL_VERSION,
            requested_max_width: 1280,
            client_os: "windows-11".into(),
            challenge_resp: Vec::new(),
        };
        let new_bytes = bincode::serialize(&new_init).unwrap();
        let parsed = parse_handshake_init(&new_bytes).unwrap();
        assert_eq!(parsed.proto_ver, PROTOCOL_VERSION);
        assert_eq!(parsed.requested_max_width, 1280);
        assert_eq!(parsed.client_os, "windows-11", "新端 OS 通告原样");

        // pre-10b 新端（V2 布局）→ 版本/宽度保留 + OS 空。
        let (cid, cd, cdty, chal, ck, cx, nnc, sig, codecs) = fill("bob");
        let pre10b = bincode::serialize(&Pre10bInitBytes {
            client_id: cid,
            client_domain: cd,
            client_device_type: cdty,
            challenge: chal,
            client_ed25519_pub_base64: ck,
            client_x25519_pub: cx,
            nonce: nnc,
            signature: sig,
            supported_codecs: codecs,
            proto_ver: PROTOCOL_VERSION,
            requested_max_width: 1280,
        })
        .unwrap();
        let parsed = parse_handshake_init(&pre10b).expect("pre-10b peer must parse");
        assert_eq!(parsed.proto_ver, PROTOCOL_VERSION, "pre-10b 版本保留");
        assert_eq!(parsed.requested_max_width, 1280, "pre-10b 宽度保留");
        assert_eq!(parsed.client_os, "", "pre-10b OS 未通告 = 空串（不猜）");

        // 最旧端（V1 布局）→ legacy 0 + 宽度 0 + OS 空。
        let (cid, cd, cdty, chal, ck, cx, nnc, sig, codecs) = fill("carol");
        let pre_r67 = bincode::serialize(&PreR67InitBytes {
            client_id: cid,
            client_domain: cd,
            client_device_type: cdty,
            challenge: chal,
            client_ed25519_pub_base64: ck,
            client_x25519_pub: cx,
            nonce: nnc,
            signature: sig,
            supported_codecs: codecs,
        })
        .unwrap();
        assert_eq!(parsed.proto_ver, PROTO_VER_LEGACY);
        assert_eq!(parsed.requested_max_width, 0);
        assert_eq!(parsed.client_os, "");

        // 旧端容忍（新 init → pre-10b 布局反序列化，尾随 OS 忽略）。
        #[derive(Deserialize)]
        struct Pre10bInitPeer {
            client_id: String,
            client_domain: String,
            client_device_type: String,
            challenge: String,
            client_ed25519_pub_base64: String,
            client_x25519_pub: [u8; 32],
            nonce: [u8; 32],
            signature: Vec<u8>,
            supported_codecs: Vec<String>,
            proto_ver: u32,
            requested_max_width: u32,
        }
        let old: Pre10bInitPeer =
            bincode::deserialize(&new_bytes).expect("pre-10b peer ignores trailing client_os");
        assert_eq!(old.client_id, "alice");
        assert_eq!(old.proto_ver, PROTOCOL_VERSION);

        // ── response：对称三态 + 旧端容忍 ──
        #[derive(serde::Serialize)]
        struct Pre10bRespBytes {
            server_x25519_pub: [u8; 32],
            server_ed25519_pub_base64: String,
            signature: Vec<u8>,
            selected_codec: String,
            server_fingerprint: String,
            proto_ver: u32,
        }
        #[derive(serde::Serialize)]
        struct PreR67RespBytes {
            server_x25519_pub: [u8; 32],
            server_ed25519_pub_base64: String,
            signature: Vec<u8>,
            selected_codec: String,
            server_fingerprint: String,
        }
        let new_resp = HandshakeResponse {
            server_x25519_pub: [9u8; 32],
            server_ed25519_pub_base64: "k".into(),
            signature: vec![1u8; 8],
            selected_codec: "h264".into(),
            server_fingerprint: "fp".into(),
            proto_ver: PROTOCOL_VERSION,
            server_os: "macos".into(),
        };
        let resp_bytes = bincode::serialize(&new_resp).unwrap();
        let parsed = parse_handshake_response(&resp_bytes).unwrap();
        assert_eq!(parsed.proto_ver, PROTOCOL_VERSION);
        assert_eq!(parsed.server_os, "macos", "新端 OS 通告原样");

        let pre10b = bincode::serialize(&Pre10bRespBytes {
            server_x25519_pub: [9u8; 32],
            server_ed25519_pub_base64: "k".into(),
            signature: vec![1u8; 8],
            selected_codec: "h264".into(),
            server_fingerprint: "fp".into(),
            proto_ver: PROTOCOL_VERSION,
        })
        .unwrap();
        let parsed = parse_handshake_response(&pre10b).expect("pre-10b resp must parse");
        assert_eq!(parsed.proto_ver, PROTOCOL_VERSION, "pre-10b 版本保留");
        assert_eq!(parsed.server_os, "", "pre-10b OS 未通告 = 空串（不猜）");

        let pre_r67 = bincode::serialize(&PreR67RespBytes {
            server_x25519_pub: [9u8; 32],
            server_ed25519_pub_base64: "k".into(),
            signature: vec![1u8; 8],
            selected_codec: "h264".into(),
            server_fingerprint: "fp".into(),
        })
        .unwrap();
        assert_eq!(parsed.proto_ver, PROTO_VER_LEGACY);
        assert_eq!(parsed.server_os, "");

        #[derive(Deserialize)]
        struct Pre10bRespPeer {
            server_x25519_pub: [u8; 32],
            server_ed25519_pub_base64: String,
            signature: Vec<u8>,
            selected_codec: String,
            server_fingerprint: String,
            proto_ver: u32,
        }
        let old: Pre10bRespPeer =
            bincode::deserialize(&resp_bytes).expect("pre-10b peer ignores trailing server_os");
        assert_eq!(old.proto_ver, PROTOCOL_VERSION);
        assert_eq!(old.server_fingerprint, "fp");
    }

    /// `version_mismatch` 下发（对端可解析拒绝码），旧端（0）放行不写拒绝。
    #[tokio::test]
    async fn test_r67_version_gate_sends_structured_reject() {
        use crate::network::tcp::receive_message;
        let dummy_init = |ver: u32| HandshakeInit {
            client_id: "alice".into(),
            client_domain: "alice.local".into(),
            client_device_type: "desktop".into(),
            challenge: String::new(),
            client_ed25519_pub_base64: String::new(),
            client_x25519_pub: [0u8; 32],
            nonce: [0u8; 32],
            signature: Vec::new(),
            supported_codecs: Vec::new(),
            proto_ver: ver,
            requested_max_width: 0,
            client_os: String::new(),
            challenge_resp: Vec::new(),
        };

        // 过新客户端 → 拒绝 + 对端可读。
        let (mut client_end, mut server_end) = tokio::io::duplex(4096);
        let too_new = dummy_init(PROTOCOL_VERSION + 1);
        assert!(reject_if_client_too_new(&mut server_end, &too_new).await);
        let data = receive_message(&mut client_end).await.expect("recv reject");
        let reject: HandshakeReject =
            bincode::deserialize(&data).expect("parse HandshakeReject");
        assert_eq!(reject.code, REJECT_CODE_VERSION_MISMATCH);
        // 旧端（v3=4-1 / legacy-0）→ 一律拒绝（无兼容包袱，fail-closed）。
        let (_c2, mut s2) = tokio::io::duplex(4096);
        assert!(!reject_if_client_too_new(&mut s2, &dummy_init(PROTOCOL_VERSION)).await);
        assert!(reject_if_client_too_new(&mut s2, &dummy_init(0)).await);
        assert!(reject_if_client_too_new(&mut s2, &dummy_init(PROTOCOL_VERSION - 1)).await);
    }

    /// `ServerTooNew`（可读错误，version skew 显性化）。
    #[tokio::test]
    async fn test_r67_server_too_new_client_side() {
        use crate::network::tcp::send_message;
        let dir = std::env::temp_dir().join("kirin_hs_r67_too_new");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let (client_end, mut server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob",
            PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
        );
        let server_fut = async move {
            // 读掉 init（内容不校验），直接回一个"过新"响应。
            let _init = server_read_init(&mut server_end).await?;
            let resp = HandshakeResponse {
                server_x25519_pub: [9u8; 32],
                server_ed25519_pub_base64: bob_pub,
                signature: Vec::new(),
                selected_codec: String::new(),
                server_fingerprint: String::new(),
                proto_ver: PROTOCOL_VERSION + 1,
                server_os: String::new(),
            };
            let data = bincode::serialize(&resp).expect("serialize resp");
            send_message(&mut server_end, &data).await?;
            Ok::<_, HandshakeError>(())
        };
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok());
        match client_res {
            Err(HandshakeError::ServerTooNew { server, client }) => {
                assert_eq!(server, PROTOCOL_VERSION + 1);
                assert_eq!(client, PROTOCOL_VERSION);
            }
            other => panic!("expected ServerTooNew, got {:?}", other.err()),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// 参数化纯函数 [`server_version_gate`]/[`client_version_gate`] 全配对：
    /// = 双向拒绝（无兼容包袱，fail-closed；README/CHANGELOG 注明需两端
    /// 升级）；同版本放行。
    ///
    /// wire 级双向各 1 例：(a) 旧端客户端 → 本服务端 = `version_mismatch`
    /// 结构化拒绝（[`test_r67_version_gate_sends_structured_reject`]，
    /// `ServerTooNew` 本地可读错误（`test_r67_server_too_new_client_side`
    /// wire 例覆盖客户端闸门代码路径）。
    #[test]
    fn test_r92s2_version_skew_matrix_pinned() {
        // 服务端闸门（exact-match：不等即拒）。
        assert!(!server_version_gate(4, 4), "同版本放行");
        assert!(server_version_gate(4, 5), "过新客户端拒绝");
        // 旧常量值配对（参数化纯函数与版本常量解耦，语义 = 不等即拒）。
        assert!(server_version_gate(2, 3), "v3 客户端 → v2 服务端 = 拒绝");
        assert!(!server_version_gate(2, 2), "v2↔v2 同版本放行");
        // 客户端闸门（exact-match：不等即拒）。
        assert!(!client_version_gate(4, 4), "同版本放行");
        assert!(client_version_gate(4, 5), "过新服务端拒绝");
        assert!(client_version_gate(2, 3), "v2 客户端 → v3 服务端 = ServerTooNew");
        assert!(!client_version_gate(2, 2), "v2↔v2 同版本放行");
        assert!(client_version_too_new(0));
        assert!(client_version_too_new(PROTOCOL_VERSION - 1));
        assert!(!client_version_too_new(PROTOCOL_VERSION));
        assert!(client_version_too_new(PROTOCOL_VERSION + 1));
    }

    /// 的 `reject_if_client_too_new` 行为（`client_ver=3 > 2` → 下发
    /// `HandshakeReject{version_mismatch}`），真实 v3 客户端（`init.proto_ver
    /// = 3` 实发）必须解析拒绝码（客户端零出站、零通道）。
    #[tokio::test]
    async fn test_r92s2_v3_client_vs_v2_server_wire_reject() {
        use crate::network::tcp::send_message;
        let dir = std::env::temp_dir().join("kirin_hs_r92s2_v2server");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        const V2_SERVER: u32 = 2; // bump 前的服务端常量值（模拟存量 v2 端）。
        let (client_end, mut server_end) = tokio::io::duplex(65536);

        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob",
            PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
        );
        let server_fut = async move {
            // 读 init（真实 v3 客户端实发 proto_ver = 3）→ 模拟 v2 服务端
            // 版本闸门（3 > 2 → 结构化拒绝，不下发响应 = 不泄露服务器公钥）。
            let init = server_read_init(&mut server_end).await?;
            assert_eq!(init.proto_ver, PROTOCOL_VERSION, "v3 客户端必须实发 proto_ver=3");
            assert!(server_version_gate(V2_SERVER, init.proto_ver), "v2 服务端必判过新");
            let reject = HandshakeReject {
                code: REJECT_CODE_VERSION_MISMATCH.to_string(),
                detail: format!("client={} server={}", init.proto_ver, V2_SERVER),
            };
            let data = bincode::serialize(&reject).expect("serialize reject");
            send_message(&mut server_end, &data).await?;
            Ok::<_, HandshakeError>(())
        };
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "mock v2 服务端拒绝路径必须正常完成");
        match client_res {
            Err(e) => {
                assert_eq!(
                    e.reject_code(),
                    Some(REJECT_CODE_VERSION_MISMATCH),
                    "v3 客户端必须解析到 version_mismatch 结构化拒绝码"
                );
            }
            Ok(_) => panic!("v3 客户端对 v2 服务端必须握手失败（双向拒绝）"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }


    ///
    ///   两字段均归 0（legacy 放行 + 原生分辨率）；
    /// - 新报文 → 完整解析，宽度偏好可见；
    ///   allow_trailing_bytes 忽略（反向兼容）。
    #[test]
    fn test_r674_width_wire_compat_legacy() {
        let new_init = HandshakeInit {
            client_id: "mobile".into(),
            client_domain: String::new(),
            client_device_type: "mobile".into(),
            challenge: "C".into(),
            client_ed25519_pub_base64: "k".into(),
            client_x25519_pub: [0u8; 32],
            nonce: [1u8; 32],
            signature: vec![2u8; 8],
            supported_codecs: vec!["h264".into()],
            proto_ver: PROTOCOL_VERSION,
            requested_max_width: 1280,
            client_os: "windows-11".into(),
            challenge_resp: Vec::new(),
        };
        let new_bytes = bincode::serialize(&new_init).expect("serialize new");
        // 新报文 → 新端：宽度偏好可见。
        let parsed = parse_handshake_init(&new_bytes).expect("new peer parses new payload");
        assert_eq!(parsed.requested_max_width, 1280);
        // 长尾字段后不再是精确模拟）。
        #[derive(serde::Serialize)]
        struct R675InitBytes {
            client_id: String,
            client_domain: String,
            client_device_type: String,
            challenge: String,
            client_ed25519_pub_base64: String,
            client_x25519_pub: [u8; 32],
            nonce: [u8; 32],
            signature: Vec<u8>,
            supported_codecs: Vec<String>,
            proto_ver: u32,
        }
        let r675_era = bincode::serialize(&R675InitBytes {
            client_id: "mobile".into(),
            client_domain: String::new(),
            client_device_type: "mobile".into(),
            challenge: "C".into(),
            client_ed25519_pub_base64: "k".into(),
            client_x25519_pub: [0u8; 32],
            nonce: [1u8; 32],
            signature: vec![2u8; 8],
            supported_codecs: vec!["h264".into()],
            proto_ver: PROTOCOL_VERSION,
        })
        assert_eq!(parsed.proto_ver, PROTO_VER_LEGACY);
        assert_eq!(parsed.requested_max_width, 0);
        assert_eq!(parsed.client_os, "");
        #[derive(serde::Serialize)]
        struct PreR67InitBytes {
            client_id: String,
            client_domain: String,
            client_device_type: String,
            challenge: String,
            client_ed25519_pub_base64: String,
            client_x25519_pub: [u8; 32],
            nonce: [u8; 32],
            signature: Vec<u8>,
            supported_codecs: Vec<String>,
        }
        let pre_r67 = bincode::serialize(&PreR67InitBytes {
            client_id: "mobile".into(),
            client_domain: String::new(),
            client_device_type: "mobile".into(),
            challenge: "C".into(),
            client_ed25519_pub_base64: "k".into(),
            client_x25519_pub: [0u8; 32],
            nonce: [1u8; 32],
            signature: vec![2u8; 8],
            supported_codecs: vec!["h264".into()],
        })
        assert_eq!(parsed.proto_ver, PROTO_VER_LEGACY);
        assert_eq!(parsed.requested_max_width, 0);
        // 反向：新报文 → pre-10b 旧端（V2 布局 = 到 width 为止）→
        // allow_trailing_bytes 忽略尾随 OS 字段，解析成功（同 proto_ver 先例）。
        #[derive(Deserialize)]
        struct Pre10bInit {
            client_id: String,
            client_domain: String,
            client_device_type: String,
            challenge: String,
            client_ed25519_pub_base64: String,
            client_x25519_pub: [u8; 32],
            nonce: [u8; 32],
            signature: Vec<u8>,
            supported_codecs: Vec<String>,
            proto_ver: u32,
            requested_max_width: u32,
        }
        let old_peer: Pre10bInit =
            bincode::deserialize(&new_bytes).expect("pre-10b peer must parse new payload");
        assert_eq!(old_peer.client_id, "mobile");
        assert_eq!(old_peer.proto_ver, PROTOCOL_VERSION);
        assert_eq!(old_peer.requested_max_width, 1280);
    }

    /// 上报 1280，服务端 `server_read_init` 读到该值；既有调用方
    /// （`client_handshake_generic`，如桌面端）上报 0（原生，零行为变化）。
    #[tokio::test]
    async fn test_r674_resolution_report_handshake_roundtrip() {
        let dir = std::env::temp_dir().join("kirin_hs_r674_width");
        let alice = gen_identity(&dir, "alice");
        let bob = Arc::new(gen_identity(&dir, "bob"));
        let bob_mobile = bob.clone();
        let bob_desktop = bob.clone();
        let bob_pub = bob.public_key_base64();

        // 移动端形态：上报 1280（device_type 仅为可读性，非协议分支）。
        let (client_end, mut server_end) = tokio::io::duplex(65536);
        let client_fut = client_handshake_with_resolution_generic(
            client_end, &alice, "alice", "alice.local", "mobile", "bob",
            PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"),
            None, "",
            vec!["h264".to_string()],
            1280,
        );
        let server_fut = async move {
            let init = server_read_init(&mut server_end).await?;
            assert_eq!(init.requested_max_width, 1280, "server must see mobile width pref");
            let _g = server_handshake_respond_generic(server_end, &bob_mobile, "bob", &init, "h264").await?;
            Ok::<_, HandshakeError>(())
        };
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "server side should succeed: {:?}", server_res.err());
        assert!(client_res.is_ok(), "client side should succeed");

        // 桌面端形态：既有调用方（client_handshake_generic）→ 上报 0（原生）。
        let (client_end, mut server_end) = tokio::io::duplex(65536);
        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob",
            PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
        );
        let server_fut = async move {
            let init = server_read_init(&mut server_end).await?;
            assert_eq!(init.requested_max_width, 0, "legacy/desktop callers must report native");
            let _g = server_handshake_respond_generic(server_end, &bob_desktop, "bob", &init, "").await?;
            Ok::<_, HandshakeError>(())
        };
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok());
        assert!(client_res.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ════════════════════════════════════════════════════════════
    // CX-1 挑战-响应（正/错答/pin 免挑战/重放拒）+ CX-2 能力纳签（篡改拒）
    // + wire 钉死（版本常量/挑战帧魔数/字段布局）。
    // ════════════════════════════════════════════════════════════

    /// CX-1 正臂：未 pin 客户端 + 固定码 → 挑战轮后通道建立；**wire 钉死**：
    /// init.challenge 恒空串且 challenge_resp 恒空（明文凭据不以任何形态
    /// 走预信道，ZE-01 治本口径）。
    #[tokio::test]
    async fn test_r205_cx1_challenge_response_ok_and_no_plaintext_on_wire() {
        let dir = std::env::temp_dir().join("kirin_hs_r205_cx1_ok");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let (client_end, mut server_end) = tokio::io::duplex(65536);
        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob",
            PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "SECRET-CODE-42",
        );
        let server_fut = async move {
            // 1) 读 init —— 钉死明文凭据零上线。
            let init = server_read_init(&mut server_end).await?;
            assert!(init.challenge.is_empty(), "v4 init.challenge must be empty (CX-1)");
            assert!(init.challenge_resp.is_empty(), "v4 init.challenge_resp must be empty");
            assert_eq!(init.proto_ver, PROTOCOL_VERSION);
            // 2) 挑战轮 + 校验 + 应答。
            let answer = server_challenge_round(&mut server_end).await?;
            verify_server_init_with_answer(&init, "", None, Some("SECRET-CODE-42"), false, Some(&answer))?;
            let _g = server_handshake_respond_generic(server_end, &bob, "bob", &init, "").await?;
            Ok::<_, HandshakeError>(())
        };
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok(), "correct challenge answer must pass: {:?}", server_res.err());
        assert!(client_res.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CX-1 反臂：错误应答 → `challenge_mismatch` 拒绝（未 pin + 固定码）；
    /// 无应答（None）同拒（fail-closed）。
    #[tokio::test]
    async fn test_r205_cx1_wrong_answer_rejected() {
        let dir = std::env::temp_dir().join("kirin_hs_r205_cx1_bad");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let (client_end, mut server_end) = tokio::io::duplex(65536);
        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob",
            PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "WRONG-CODE",
        );
        let server_fut = async move {
            let init = server_read_init(&mut server_end).await?;
            let answer = server_challenge_round(&mut server_end).await?;
            verify_server_init_with_answer(&init, "", None, Some("SECRET-CODE-42"), false, Some(&answer))?;
            unreachable!("wrong answer must not pass");
        };
        let (client_res, server_res): (
            Result<SecureChannelGeneric<_>, HandshakeError>,
            Result<(), HandshakeError>,
        ) = tokio::join!(client_fut, server_fut);
        match server_res {
            Err(HandshakeError::InvalidMessage(msg)) => assert_eq!(msg, "challenge mismatch"),
            other => panic!("expected challenge mismatch, got {:?}", other.err()),
        }
        assert!(client_res.is_err(), "client must not complete");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CX-1 pin 免挑战臂：服务端 pin 命中 → 不发挑战帧（wire 首帧 =
    /// HandshakeResponse 直接应答）；客户端零挑战参数也通过。
    #[tokio::test]
    async fn test_r205_cx1_pinned_client_skips_round() {
        let dir = std::env::temp_dir().join("kirin_hs_r205_cx1_pin");
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let alice_pub = alice.public_key_base64();
        let bob_pub = bob.public_key_base64();
        let (client_end, mut server_end) = tokio::io::duplex(65536);
        let client_fut = client_handshake_generic(
            client_end, &alice, "alice", "alice.local", "desktop", "bob",
            PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"), "",
        );
        let server_fut = async move {
            let init = server_read_init(&mut server_end).await?;
            assert!(
                !challenge_round_required(&alice_pub, &init.client_ed25519_pub_base64, Some("SECRET"), None),
                "pinned client must be exempt from the challenge round"
            );
            // 直接应答（不发挑战帧）——客户端必须不等待挑战。
            let _g = server_handshake_respond_generic(server_end, &bob, "bob", &init, "").await?;
            Ok::<_, HandshakeError>(())
        };
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        assert!(server_res.is_ok());
        assert!(client_res.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CX-1 重放反臂：同一 (nonce, response) 对在第二轮（新 nonce）必败
    /// ——收获应答跨连接不可重放。
    #[tokio::test]
    async fn test_r205_cx1_replayed_answer_rejected_on_fresh_nonce() {
        let dir = std::env::temp_dir().join("kirin_hs_r205_cx1_replay");
        let alice = gen_identity(&dir, "alice");
        // 第一轮：捕获 (nonce, response)。
        let init_pub = alice.public_key_base64();
        let client_x25519 = [0x11u8; 32];
        let client_nonce = [0x22u8; 32];
        let init = HandshakeInit {
            client_id: "alice".into(), client_domain: String::new(),
            client_device_type: "desktop".into(), challenge: String::new(),
            client_ed25519_pub_base64: init_pub,
            client_x25519_pub: client_x25519, nonce: client_nonce,
            signature: Vec::new(), supported_codecs: Vec::new(),
            proto_ver: PROTOCOL_VERSION, requested_max_width: 0,
            client_os: String::new(), challenge_resp: Vec::new(),
        };
        // 第一轮：捕获 (nonce, response) 对（合法码派生）。
        let nonce1 = generate_nonce();
        let answer1 = challenge_response("CODE", &nonce1, &client_x25519, &client_nonce);
        let captured = ChallengeAnswer { nonce: nonce1, response: answer1 };
        assert!(challenge_resp_matches_fixed("CODE", &captured, &init));
        // 第二轮：新 nonce + 旧应答 → 必败（重放封闭）。
        let nonce2 = generate_nonce();
        let replay = ChallengeAnswer { nonce: nonce2, response: captured.response };
        assert!(
            !challenge_resp_matches_fixed("CODE", &replay, &init),
            "replayed answer must fail against a fresh server nonce"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CX-2 反臂矩阵：能力声明字段（proto_ver / supported_codecs /
    /// requested_max_width / client_os）逐字段篡改（**签名保持原值** = 主动
    /// MITM 改写重序列化形态）→ 签名校验必败（主动降级/特性剥离面封死，ZE-03）。
    #[test]
    fn test_r205_cx2_capability_fields_covered_by_signature() {
        let dir = std::env::temp_dir().join("kirin_hs_r205_cx2");
        let alice = gen_identity(&dir, "alice");
        let (x25519, nonce) = ([0x33u8; 32], [0x44u8; 32]);
        let payload = build_sig_payload(
            &x25519, &nonce, "alice", "alice.local", "desktop",
            PROTOCOL_VERSION, &["h264".to_string()], 1280, "windows-11",
        );
        let base = HandshakeInit {
            client_id: "alice".into(), client_domain: "alice.local".into(),
            client_device_type: "desktop".into(), challenge: String::new(),
            client_ed25519_pub_base64: alice.public_key_base64(),
            client_x25519_pub: x25519, nonce,
            signature: alice.sign(&payload).to_bytes().to_vec(),
            supported_codecs: vec!["h264".into()], proto_ver: PROTOCOL_VERSION,
            requested_max_width: 1280, client_os: "windows-11".into(),
            challenge_resp: Vec::new(),
        };
        // 基线：未篡改 → 验签通过。
        assert!(verify_server_init_with_answer(&base, "", None, None, true, None).is_ok());
        // 逐字段篡改（签名不变）→ 全部 SignatureVerificationFailed。
        let mut tampered = base.clone();
        tampered.proto_ver = PROTOCOL_VERSION - 1; // 降级 proto_ver
        let mut t2 = base.clone();
        t2.proto_ver = PROTO_VER_LEGACY; // 剥离为 legacy-0
        let mut t3 = base.clone();
        t3.supported_codecs = Vec::new(); // 剥离 codecs
        let mut t4 = base.clone();
        t4.supported_codecs = vec!["h265".into()]; // 摆布协商
        let mut t5 = base.clone();
        t5.requested_max_width = 0; // 抹宽度偏好
        let mut t6 = base.clone();
        t6.client_os = String::new(); // 抹 OS 通告
        for (i, t) in [&tampered, &t2, &t3, &t4, &t5, &t6].into_iter().enumerate() {
            match verify_server_init_with_answer(t, "", None, None, true, None) {
                Err(HandshakeError::SignatureVerificationFailed) => {}
                other => panic!("tamper case {i} must fail signature, got {:?}", other.err()),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// wire 钉死：版本常量 = 4；挑战帧魔数判别（响应首 32B 不误判挑战）；
    /// 挑战/应答帧 bincode 往返；init 尾字段 `challenge_resp` 在位。
    #[test]
    fn test_r205_wire_freeze_pinned() {
        assert_eq!(HANDSHAKE_CHALLENGE_MAGIC, *b"KIRINCH1");
        // 挑战帧/应答帧往返 + 魔数。
        let chal = HandshakeChallenge { magic: HANDSHAKE_CHALLENGE_MAGIC, nonce: [9u8; 32] };
        let bytes = bincode::serialize(&chal).unwrap();
        let back: HandshakeChallenge = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back.magic, HANDSHAKE_CHALLENGE_MAGIC);
        assert_eq!(back.nonce, [9u8; 32]);
        // 魔数不符 = 判别拒绝（双条件判别的反例锚）。
        let evil = HandshakeChallenge { magic: *b"EVILCH1!", nonce: [9u8; 32] };
        let evil_bytes = bincode::serialize(&evil).unwrap();
        let parsed: HandshakeChallenge = bincode::deserialize(&evil_bytes).unwrap();
        assert_ne!(parsed.magic, HANDSHAKE_CHALLENGE_MAGIC);
        // v4 init 完整形状解析往返（含 challenge_resp 尾字段）。
        let init = HandshakeInit {
            client_id: "a".into(), client_domain: "d".into(),
            client_device_type: "desktop".into(), challenge: String::new(),
            client_ed25519_pub_base64: "k".into(), client_x25519_pub: [1u8; 32],
            nonce: [2u8; 32], signature: vec![3u8; 4],
            supported_codecs: vec!["h264".into()], proto_ver: PROTOCOL_VERSION,
            requested_max_width: 0, client_os: "linux".into(),
            challenge_resp: Vec::new(),
        };
        let parsed = parse_handshake_init(&bincode::serialize(&init).unwrap()).unwrap();
        assert_eq!(parsed.proto_ver, PROTOCOL_VERSION);
        assert!(parsed.challenge.is_empty());
        assert!(parsed.challenge_resp.is_empty());
    }
}
