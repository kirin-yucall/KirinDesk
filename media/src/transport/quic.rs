//! QUIC 最小端点封装。
//!
//! 仅用于 quinn 的 DATAGRAM + 流能力，**不参与安全决策**。
//! 自签名 Ed25519 证书仅满足 quinn API 要求，不验证证书链。
//! 真正的加密由 `MediaCipher`（封装 core 的 `AeadCipher`）完成。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::TransportConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use tracing::debug;

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
// SkipServerVerification — 不验证对端证书
// ════════════════════════════════════════════════════════════════

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
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));

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
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));

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

/// QUIC 传输端点。
pub struct QuicEndpoint {
    endpoint: quinn::Endpoint,
}

impl QuicEndpoint {
    /// 绑定 UDP 端口。
    pub async fn bind(
        port: u16,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, TransportError> {
        let server_config = make_server_config(cert_der, key_der)?;
        let addr: SocketAddr = ([0, 0, 0, 0, 0, 0, 0, 0], port).into();

        let endpoint =
            quinn::Endpoint::server(server_config, addr).map_err(|e| TransportError::Io(e))?;

        debug!(
            "QuicEndpoint::bind -> UDP [::]:{}",
            endpoint.local_addr()?.port()
        );
        Ok(Self { endpoint })
    }

    /// 拨号到远程端点。
    pub async fn connect(
        addr: SocketAddr,
        device_id: &str,
    ) -> Result<QuicConnection, TransportError> {
        let client_config = make_client_config();
        let endpoint = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)))
            .map_err(|e| TransportError::Io(e))?;

        let conn = endpoint
            .connect_with(client_config, addr, device_id)
            .map_err(|e| TransportError::Quic(e.to_string()))?
            .await
            .map_err(|e| TransportError::Quic(e.to_string()))?;

        debug!("QuicEndpoint::connect -> {addr} connected");
        Ok(QuicConnection::new(conn))
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
}
