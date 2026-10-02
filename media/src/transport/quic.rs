//! QUIC 最小端点封装。
//!
//! 仅用于 quinn 的 DATAGRAM + 流能力，**不参与安全决策**。
//! 自签名 Ed25519 证书仅满足 quinn API 要求，不验证证书链。
//! 真正的加密由 `MediaCipher`（封装 core 的 `AeadCipher`）完成。
//!
//! # S-17 接线门禁（F-22 · 接线前必读）
//!
//! 本模块的 rustls 客户端校验 [`SkipServerVerification`] 全放行是**有意设计**
//! （仅协议合规；自签名证书无链可验，本层不做证书校验）——安全完全依赖上层
//! Ed25519 握手：客户端 `connect_quic_transport` 的 `server_pin: PinExpectation`
//! 强制校验服务端身份（R-02 强类型化，无"无期望跳过"路径），服务端
//! `accept_quic_transport` 经 `server_handshake_verified_with_nickname_generic`
//! 做白名单/审批/挑战码策略层校验。
//!
//! **任何未来把 QUIC 传输接入主流程的改动，必须先满足 `transport/mod.rs`
//! 声明处的接线门禁，禁止任何绕过校验的快捷方式**（如恢复"空串 / 忽略 pin"
//! 或给 `SkipServerVerification` 之外再开放行口）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::TransportConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{debug, warn};

use crate::transport::TransportError;

// ════════════════════════════════════════════════════════════════
// 证书生成
// ════════════════════════════════════════════════════════════════

/// 生成满足 quinn 要求的自签名 Ed25519 证书。
pub fn generate_quic_cert(device_id: &str) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

    let key_pair = KeyPair::generate_for(&PKCS_ED25519)
        .map_err(|e| TransportError::Quic(format!("rcgen key generation: {e}")))?;

    let mut params = CertificateParams::new(vec![device_id.to_string()])
        .map_err(|e| TransportError::Quic(format!("rcgen params: {e}")))?;
    params.not_before = time::OffsetDateTime::now_utc()
        .checked_sub(time::Duration::days(1))
        .unwrap_or(time::OffsetDateTime::now_utc());
    params.not_after = time::OffsetDateTime::now_utc()
        .checked_add(time::Duration::days(3650))
        .unwrap_or(time::OffsetDateTime::now_utc());
    params.distinguished_name = rcgen::DistinguishedName::new();

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TransportError::Quic(format!("rcgen self_signed: {e}")))?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    Ok((cert_der, key_der))
}

// ════════════════════════════════════════════════════════════════
// SkipServerVerification — 不验证对端证书（有意设计，S-17 门禁 · 勿改）
// ════════════════════════════════════════════════════════════════
//
// 审计证据（安全审计报告 2026-08-02 §4 F-22）：本结构体对 TLS 对端证书
// 全部放行，安全性完全依赖上层 Ed25519 握手。这是"仅协议合规"的有意设计：
// 证书为自签名（`generate_quic_cert`），本层无链可验，**不要**在 TLS 层
// "修复"（补齐证书校验属职责外，徒增维护负担且不构成真实防护）。
//
// 客户端侧服务端身份校验由握手层承担：`connect_quic_transport` 的
// `server_pin: PinExpectation`（R-02 强类型化——旧的 `_server_pubkey_base64`
// 占位参数已取消，不存在"空串 = 跳过 pin 比对"的路径）。任何接入主流程的
// 改动禁止绕过该校验（S-17 接线门禁，详见 transport/mod.rs）。

struct SkipServerVerification;

impl std::fmt::Debug for SkipServerVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkipServerVerification").finish()
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ════════════════════════════════════════════════════════════════
// QUIC 端点配置
// ════════════════════════════════════════════════════════════════

/// 安装 rustls 进程级 CryptoProvider（ring，一次）。
///
/// rustls 0.23 的 `builder()` 需要进程级 provider；`install_default` 只能
/// 成功一次，重复调用返回 `AlreadyInstalled`（忽略）。
fn ensure_crypto_provider() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    let _ = ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// 创建最小 QUIC 客户端配置。
pub fn make_client_config() -> quinn::ClientConfig {
    ensure_crypto_provider();
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .expect("QuicClientConfig from rustls ClientConfig");

    let mut transport = TransportConfig::default();
    // M8-T025 P5-3：idle 超时 30s → 10s —— 会话降级判定辅助（QUIC 失效时
    // is_alive() 尽快翻转 false，配合会话层 500ms 轮询触发 TCP 重建；M8-T009 §12.2）。
    transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

    let mut config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    config.transport_config(Arc::new(transport));
    config
}

/// 创建最小 QUIC 服务端配置。
pub fn make_server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<quinn::ServerConfig, TransportError> {
    ensure_crypto_provider();
    let crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_der,
            )),
        )
        .map_err(|e| TransportError::Quic(format!("rustls server config: {e}")))?;

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|e| TransportError::Quic(format!("QuicServerConfig: {e}")))?;

    let mut transport = TransportConfig::default();
    // M8-T025 P5-3：同客户端 —— idle 10s，会话降级判定辅助。
    transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

// ════════════════════════════════════════════════════════════════
// MediaCipher
// ════════════════════════════════════════════════════════════════

/// 媒体加密上下文（包装 core 的 AeadCipher）。
pub struct MediaCipher {
    cipher: kirin_desk_core::crypto::AeadCipher,
}
impl MediaCipher {
    /// 从 32 字节 session_key 创建加密上下文。
    pub fn new(session_key: &[u8; 32]) -> Self {
        Self {
            cipher: kirin_desk_core::crypto::AeadCipher::new(session_key),
        }
    }

    /// 从已有的 AeadCipher 创建（从 core handshake 结果提取）。
    pub fn new_from_aead(cipher: kirin_desk_core::crypto::AeadCipher) -> Self {
        Self { cipher }
    }

    /// 加密: 返回 `nonce (12B) || ciphertext`。
    pub fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>, TransportError> {
        let (nonce, ciphertext) = self
            .cipher
            .encrypt_simple(plain)
            .map_err(|e| TransportError::Crypto(e.to_string()))?;
        let mut out = nonce;
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// 解密: 从 `nonce || ciphertext` 中提取并解密。
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        if data.len() < 12 {
            return Err(TransportError::ShortDatagram {
                got: data.len(),
                need: 12,
            });
        }
        let (nonce, ciphertext) = data.split_at(12);
        let mut ct = ciphertext.to_vec();
        self.cipher
            .decrypt_simple(nonce, &mut ct)
            .map_err(|e| TransportError::Crypto(e.to_string()))
    }
}

// ════════════════════════════════════════════════════════════════
// QuicConnection
// ════════════════════════════════════════════════════════════════

/// QUIC 连接句柄。
pub struct QuicConnection {
    conn: quinn::Connection,
}

impl QuicConnection {
    pub fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// 克隆底层 quinn 连接句柄（诊断探针 / 多任务共享统计用）。
    pub fn clone_quic(&self) -> QuicConnection {
        QuicConnection::new(self.conn.clone())
    }

    /// 发送 DATAGRAM（quinn 0.11 用 Bytes）。
    pub async fn send_datagram(&self, data: &[u8]) -> Result<(), TransportError> {
        use bytes::Bytes;
        self.conn
            .send_datagram(Bytes::copy_from_slice(data))
            .map_err(|e| TransportError::Quic(e.to_string()))
    }

    /// 接收 DATAGRAM。
    pub async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let bytes = self
            .conn
            .read_datagram()
            .await
            .map_err(|e| TransportError::Quic(e.to_string()))?;
        Ok(bytes.to_vec())
    }

    /// 打开双向可靠流。
    pub async fn open_bi(&self) -> Result<(quinn::SendStream, quinn::RecvStream), TransportError> {
        self.conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Quic(e.to_string()))
    }

    /// 接受双向可靠流。
    pub async fn accept_bi(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), TransportError> {
        self.conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::Quic(e.to_string()))
    }

    /// 关闭连接。
    pub fn close(&self, reason: &str) {
        self.conn.close(0u32.into(), reason.as_bytes());
    }

    /// 连接是否存活。
    pub fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
    }

    /// 连接关闭原因（诊断用）。
    pub fn close_reason_str(&self) -> String {
        match self.conn.close_reason() {
            None => "alive".to_string(),
            Some(quinn::ConnectionError::ApplicationClosed(c)) => {
                format!(
                    "app-closed code={} reason={:?}",
                    c.error_code,
                    String::from_utf8_lossy(&c.reason)
                )
            }
            Some(e) => format!("{e:?}"),
        }
    }

    /// RTT（毫秒）。
    pub fn rtt(&self) -> u64 {
        self.conn.rtt().as_millis() as u64
    }

    /// 当前拥塞窗口（字节）。
    ///
    /// 自适应策略的恢复条件 C（cwnd 连续增长）与 cwnd 崩溃检测
    /// （T009 §6.6.2 / §6.1）消费该值。
    pub fn congestion_window(&self) -> u64 {
        self.conn.stats().path.cwnd
    }

    /// 路径诊断（诊断用）：cwnd/in_flight 等信息。
    pub fn path_diag(&self) -> String {
        let s = self.conn.stats();
        format!(
            "cwnd={} rtt={:?} sent={} lost={} congestion_events={} frame_tx_dg={} frame_rx_dg={}",
            s.path.cwnd,
            s.path.rtt,
            s.path.sent_packets,
            s.path.lost_packets,
            s.path.congestion_events,
            s.frame_tx.datagram,
            s.frame_rx.datagram,
        )
    }

    /// 本地地址（M8-T026-P1 PATH-007 路径采样：识别当前源地址/映射变化）。
    pub fn local_ip(&self) -> Option<std::net::IpAddr> {
        self.conn.local_ip()
    }

    /// 对端地址（PATH-007 采样：当前路径对端端点）。
    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// UDP 收发统计（诊断用）：`(tx_datagrams, tx_bytes, rx_datagrams, rx_bytes)`。
    pub fn udp_stats(&self) -> (u64, u64, u64, u64) {
        let s = self.conn.stats();
        (
            s.udp_tx.datagrams,
            s.udp_tx.bytes,
            s.udp_rx.datagrams,
            s.udp_rx.bytes,
        )
    }
}

// ════════════════════════════════════════════════════════════════
// QuicEndpoint
// ════════════════════════════════════════════════════════════════

/// 绑定 UDP socket：优先双栈（`[::]:port` + IPV6_V6ONLY=false，可收 v4-mapped），
/// 平台不支持双栈（socket 创建/bind 失败或 `set_only_v6(false)` 失败）→ 回退
/// `0.0.0.0:port`（仅 v4，`warn!` 告警）。见 M8-T025_P3 Task P3-1。
///
/// 说明：`std::net::UdpSocket` 没有 `set_only_v6`（仅 `TcpSocket` 有），
/// 双栈 socket 需经 socket2 预建（bind 前设 V6ONLY=false，与 quinn 内部一致）。
fn bind_udp_socket(port: u16) -> std::io::Result<std::net::UdpSocket> {
    bind_udp_socket_inner(port, true)
}

/// `try_dual_stack=false` 仅供测试注入（模拟双栈不可用，直接验证 v4 回退路径）。
fn bind_udp_socket_inner(
    port: u16,
    try_dual_stack: bool,
) -> std::io::Result<std::net::UdpSocket> {
    if try_dual_stack {
        if let Ok(socket) = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
            let dual_ok = socket.set_only_v6(false).is_ok()
                && socket
                    .bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())
                    .is_ok();
            if dual_ok {
                // 双栈 socket 转回 std，交给 quinn::Endpoint::new 包装
                return Ok(socket.into());
            }
        }
        warn!(
            "dual-stack bind [::]:{port} unavailable on this platform, \
             falling back to IPv4-only 0.0.0.0:{port}"
        );
    }
    std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
}

/// QUIC 传输端点。
pub struct QuicEndpoint {
    endpoint: quinn::Endpoint,
}

impl QuicEndpoint {
    /// 绑定 UDP 端口（双栈优先；平台不支持 → 回退仅 v4）。
    pub async fn bind(
        port: u16,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, TransportError> {
        let server_config = make_server_config(cert_der, key_der)?;
        let socket = bind_udp_socket(port)?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| TransportError::Quic("no quinn runtime available".into()))?;

        // `Endpoint::server` 内部走 `Endpoint::new` + 默认 config；此处直接
        // `new` 以便传入预建的双栈 socket（语义等价，双栈由 socket 决定）。
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(|e| TransportError::Io(e))?;

        debug!(
            "QuicEndpoint::bind -> UDP {}",
            endpoint.local_addr()?
        );
        Ok(Self { endpoint })
    }

    /// 拨号到远程端点（v4/v6 均可）。
    pub async fn connect(
        addr: SocketAddr,
        device_id: &str,
    ) -> Result<QuicConnection, TransportError> {
        let client_config = make_client_config();
        // 按目标地址族选择客户端端点绑定地址：v6-mapped 拨号存在平台差异
        // （Linux 需 IPV6_V6ONLY=0 且行为不一致），按族绑定最稳。
        let bind_addr = if addr.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0)) // v4 目标 → v4 端点
        } else {
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)) // v6 目标 → v6 端点
        };
        let endpoint =
            quinn::Endpoint::client(bind_addr).map_err(|e| TransportError::Io(e))?;

        let conn = endpoint
            .connect_with(client_config, addr, device_id)
            .map_err(|e| TransportError::Quic(e.to_string()))?
            .await
            .map_err(|e| TransportError::Quic(e.to_string()))?;

        debug!("QuicEndpoint::connect -> {addr} connected");
        Ok(QuicConnection::new(conn))
    }

    // ════════════════════════════════════════════════════════════
    // M8-T026-P1 (PUNCH-001 / PATH-004): 预建 socket 端点（打洞路径复用）
    // ════════════════════════════════════════════════════════════

    /// 服务端：在**外部预建的 socket**（打洞成功后交还的 UDP socket）上建端点。
    ///
    /// 打洞 socket 的 NAT 映射已通过探测建立（PUNCH-001），QUIC 直接复用
    /// 该映射（同五元组），无需新建 socket——连接迁移（PATH-004）的落点。
    pub async fn from_socket(
        socket: std::net::UdpSocket,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, TransportError> {
        let server_config = make_server_config(cert_der, key_der)?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| TransportError::Quic("no quinn runtime available".into()))?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(|e| TransportError::Io(e))?;
        debug!("QuicEndpoint::from_socket -> UDP {}", endpoint.local_addr()?);
        Ok(Self { endpoint })
    }

    /// 客户端：在外部预建的 socket（打洞 socket）上建**客户端**端点。
    pub async fn client_on(socket: std::net::UdpSocket) -> Result<Self, TransportError> {
        let runtime = quinn::default_runtime()
            .ok_or_else(|| TransportError::Quic("no quinn runtime available".into()))?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .map_err(|e| TransportError::Io(e))?;
        debug!("QuicEndpoint::client_on -> UDP {}", endpoint.local_addr()?);
        Ok(Self { endpoint })
    }

    /// 客户端：从本端点（打洞 socket 端点）拨号到对端打洞地址。
    pub async fn connect_on(
        &self,
        addr: SocketAddr,
        device_id: &str,
    ) -> Result<QuicConnection, TransportError> {
        let client_config = make_client_config();
        let conn = self
            .endpoint
            .connect_with(client_config, addr, device_id)
            .map_err(|e| TransportError::Quic(e.to_string()))?
            .await
            .map_err(|e| TransportError::Quic(e.to_string()))?;
        debug!("QuicEndpoint::connect_on -> {addr} connected");
        Ok(QuicConnection::new(conn))
    }

    /// NAT 重绑（RFC 9000 连接迁移 / PATH-004）：换本地 socket 而不重建连接。
    ///
    /// quinn 0.11：客户端换源地址后，服务端侧（`server_config.migration` 默认
    /// 开启）经 PATH_CHALLENGE 自动验证并迁移，**无重握手、近乎零中断**。
    /// 用于打洞映射老化（PUNCH-004 重打洞）或接口切换场景。
    pub fn rebind(&self, socket: std::net::UdpSocket) -> Result<(), TransportError> {
        self.endpoint
            .rebind(socket)
            .map_err(|e| TransportError::Io(e))
    }

    /// 等待并接受连接。
    pub async fn accept(&self) -> Result<(QuicConnection, SocketAddr), TransportError> {
        let incoming =
            self.endpoint
                .accept()
                .await
                .ok_or_else(|| TransportError::ConnectionClosed {
                    reason: "endpoint closed".into(),
                })?;

        let connecting = incoming
            .accept()
            .map_err(|e| TransportError::Quic(format!("incoming accept: {e}")))?;
        let remote = connecting.remote_address();
        let conn = connecting
            .await
            .map_err(|e| TransportError::Quic(e.to_string()))?;

        debug!("QuicEndpoint::accept <- {remote}");
        Ok((QuicConnection::new(conn), remote))
    }

    /// 本地地址。
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|e| TransportError::Io(e))
    }
}

// ════════════════════════════════════════════════════════════════
// Error conversion
// ════════════════════════════════════════════════════════════════

impl From<rcgen::Error> for TransportError {
    fn from(e: rcgen::Error) -> Self {
        TransportError::Quic(format!("rcgen: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_quic_cert() {
        let (cert, key) = generate_quic_cert("test-device").unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
    }

    #[test]
    fn test_media_cipher_roundtrip() {
        let key = [0xABu8; 32];
        let cipher = MediaCipher::new(&key);
        let plain = b"Hello QUIC media!";
        let encrypted = cipher.encrypt(plain).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_media_cipher_tamper_detected() {
        let key = [0xABu8; 32];
        let cipher = MediaCipher::new(&key);
        let plain = b"Sensitive media data";
        let mut encrypted = cipher.encrypt(plain).unwrap();
        if !encrypted.is_empty() {
            let last = encrypted.len() - 1;
            encrypted[last] ^= 0xFF;
        }
        let result = cipher.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_bind_dual_stack_port() {
        let (cert, key) = generate_quic_cert("test-device").unwrap();
        let endpoint = QuicEndpoint::bind(0, cert, key).await.unwrap();
        let addr = endpoint.local_addr().unwrap();
        assert_ne!(addr.port(), 0, "bind(0) must assign a real port");
        // 平台支持双栈（IPV6_V6ONLY=false 生效）时应绑在 [::]；否则回退 v4 —— 两者皆合法
        let probe = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        if probe.set_only_v6(false).is_ok() {
            assert!(addr.is_ipv6(), "dual-stack platform should bind [::], got {addr}");
        }
    }

    #[test]
    fn test_bind_v4_fallback() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        // 捕获 warn 日志，验证回退路径告警
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let logs: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_logs = Arc::clone(&logs);
        let sink = move || Sink(Arc::clone(&sink_logs));
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .with_writer(sink)
                .finish(),
        );

        // 1) 注入：跳过双栈尝试 → 直接验证 v4 回退绑定（跨平台确定性）
        let injected = bind_udp_socket_inner(0, false).unwrap();
        assert!(injected.local_addr().unwrap().is_ipv4());
        assert_ne!(injected.local_addr().unwrap().port(), 0);

        // 2) 真实回退：用 v6-only socket 占住 [::]:port → 双栈 bind 应失败 → warn + v4
        //    （Windows 允许 UDP 重复 bind，无法构造确定性冲突时跳过日志断言，
        //     该部分在 Linux 等平台上生效）
        let blocker = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let conflict_constructible = blocker.set_only_v6(true).is_ok()
            && blocker
                .bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)).into())
                .is_ok();
        if conflict_constructible {
            let port = blocker.local_addr().unwrap().as_socket().unwrap().port();
            let probe = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            let _ = probe.set_only_v6(false);
            let dup_conflicts = probe
                .bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())
                .is_err();
            if dup_conflicts {
                let socket = bind_udp_socket(port).unwrap();
                let addr = socket.local_addr().unwrap();
                assert!(addr.is_ipv4(), "fallback should bind IPv4, got {addr}");
                assert_eq!(addr.port(), port, "fallback should keep requested port");
                let captured = String::from_utf8_lossy(&logs.lock().unwrap()).to_string();
                assert!(
                    captured.contains("falling back to IPv4-only"),
                    "expected fallback warning, got: {captured}"
                );
            }
        }
    }
}
