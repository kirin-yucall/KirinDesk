//! M8-T026-P1 (PUNCH-001 / PATH-004): 打洞路径 → 媒体传输桥。
//!
//! core 的 `PunchSession` 只负责打通 UDP 路径（交还 socket）；本模块把
//! **打洞 socket 上的 QUIC 媒体传输**建起来：
//! - `QuicEndpoint::from_socket`/`client_on`（预建 socket → quinn 端点，
//!   QUIC 复用打洞建立的 NAT 映射，无需新建 socket/重新打洞）；
//! - `connect_quic_transport_on`/`accept_quic_transport`（Ed25519 双向握手，
//!   PUNCH-SEC-001：打洞路径不弱化身份校验）；
//! - 会话级升舱任务（`PunchUpgrade`）：订阅 `PunchUpgradeEvent`，收到
//!   `UdpEstablished` → 建立媒体传输 → 推入会话既有 swap 通道
//!   （`apply_server_swap`/`apply_client_swap` 热替换 + 强制 IDR，
//!   对齐 M8-T025 降级机制）——"中继 → 直连"升舱（PATH-004）的执行端。

use kirin_desk_core::crypto::ed25519::IdentityManager;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::transport::quic::QuicEndpoint;
use crate::transport::transport::{
    accept_quic_transport, connect_quic_transport_on, QuicMediaTransport,
};
use crate::transport::MediaTransport;
use crate::transport::TransportError;

/// 打洞升舱事件（core `PunchSession` 结果投递到媒体会话）。
#[derive(Debug)]
pub enum PunchUpgradeEvent {
    /// UDP 打洞成功：打洞 socket（探测已停止）与对端地址。
    UdpEstablished {
        socket: std::net::UdpSocket,
        peer_addr: SocketAddr,
    },
    /// 打洞失败（中继承载不受影响，PUNCH-003）。
    Failed { reason: String },
}

/// 打洞媒体握手凭据（PUNCH-SEC-001：与直连完全一致）。
#[derive(Debug, Clone)]
pub struct PunchMediaCreds {
    /// QUIC 自签名证书（`generate_quic_cert(device_id)` 产出）。
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    /// 本端 Ed25519 身份（握手签名）。
    pub identity: Arc<IdentityManager>,
    /// 本端设备 ID。
    pub device_id: String,
    /// 本端域名（服务端白名单匹配）。
    pub domain: String,
    /// 本端设备类型。
    pub device_type: String,
    /// 对端设备 ID。
    pub peer_device_id: String,
    /// 对端 Ed25519 公钥（base64，pin 绑定）。
    pub peer_public_key_base64: String,
    /// 挑战码。
    pub challenge: String,
}

/// 会话级升舱源（经既有 swap 通道热替换，PATH-004）。
pub struct PunchUpgrade {
    pub events: mpsc::UnboundedReceiver<PunchUpgradeEvent>,
    pub creds: PunchMediaCreds,
}

/// 客户端：在打洞 socket 上建立 QUIC 媒体传输（含 Ed25519 握手）。
///
/// 返回 `(endpoint, transport)`：**endpoint 必须由调用方持有**——打洞 socket
/// 的 quinn driver 由 endpoint 驱动，提前 drop 会关闭连接（"closed by peer"，
/// 已实测）；会话升舱任务持有 endpoint 直到传输被会话接管。
pub async fn connect_punch_transport(
    socket: std::net::UdpSocket,
    peer_addr: SocketAddr,
    creds: &PunchMediaCreds,
) -> Result<(QuicEndpoint, Box<QuicMediaTransport>), TransportError> {
    let endpoint = QuicEndpoint::client_on(socket).await?;
    let transport = connect_quic_transport_on(
        &endpoint,
        peer_addr,
        &creds.identity,
        &creds.device_id,
        &creds.domain,
        &creds.device_type,
        &creds.peer_device_id,
        &creds.peer_public_key_base64,
        &creds.challenge,
    )
    .await?;
    debug!("connect_punch_transport: QUIC on punch path to {peer_addr}");
    Ok((endpoint, Box::new(transport)))
}

/// 服务端：在打洞 socket 上接受 QUIC 媒体传输（含 Ed25519 握手）。
///
/// 同 [`connect_punch_transport`]：endpoint 由调用方持有（driver 生命周期）。
pub async fn accept_punch_transport(
    socket: std::net::UdpSocket,
    creds: &PunchMediaCreds,
) -> Result<(QuicEndpoint, Box<QuicMediaTransport>), TransportError> {
    let endpoint =
        QuicEndpoint::from_socket(socket, creds.cert_der.clone(), creds.key_der.clone()).await?;
    let transport = accept_quic_transport(
        &endpoint,
        &creds.identity,
        &creds.device_id,
        &creds.peer_public_key_base64,
        Some(&creds.peer_device_id),
        Some(&creds.challenge),
    )
    .await?;
    debug!("accept_punch_transport: QUIC on punch path ready");
    Ok((endpoint, Box::new(transport)))
}

/// 服务端升舱任务：订阅打洞事件 → 打洞 socket 上 accept QUIC 媒体传输 →
/// 推入会话 swap 通道（热替换 + 强制 IDR）。`stop` 置位或事件源关闭时退出。
///
/// **endpoint 生命周期**：桥函数归还的 `QuicEndpoint` 由本任务持有到任务结束
/// （quinn driver 依赖其存活；提前 drop 会关闭连接，已实测）。
pub async fn punch_upgrade_accept_task(
    mut upgrade: PunchUpgrade,
    swap_tx: mpsc::UnboundedSender<Box<dyn MediaTransport>>,
    stop: Arc<AtomicBool>,
) {
    info!("punch upgrade accept task started");
    let mut _endpoint_hold: Option<QuicEndpoint> = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match upgrade.events.recv().await {
            Some(PunchUpgradeEvent::UdpEstablished { socket, peer_addr }) => {
                debug!("punch upgrade: udp established with {peer_addr}");
                match accept_punch_transport(socket, &upgrade.creds).await {
                    Ok((endpoint, transport)) => {
                        _endpoint_hold = Some(endpoint);
                        info!("punch upgrade: media switched to punch path ({peer_addr})");
                        if swap_tx.send(transport).is_err() {
                            warn!("punch upgrade: session swap channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("punch upgrade: accept on punch path failed: {e}");
                    }
                }
            }
            Some(PunchUpgradeEvent::Failed { reason }) => {
                debug!("punch upgrade: punch failed: {reason} (relay keeps carrying)");
            }
            None => break, // 事件源关闭（PunchSession 结束）
        }
    }
}

/// 客户端升舱任务：打洞 socket 上 connect QUIC 媒体传输 → 推入 swap 通道。
pub async fn punch_upgrade_connect_task(
    mut upgrade: PunchUpgrade,
    swap_tx: mpsc::UnboundedSender<Box<dyn MediaTransport>>,
    stop: Arc<AtomicBool>,
) {
    info!("punch upgrade connect task started");
    let mut _endpoint_hold: Option<QuicEndpoint> = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match upgrade.events.recv().await {
            Some(PunchUpgradeEvent::UdpEstablished { socket, peer_addr }) => {
                debug!("punch upgrade: udp established with {peer_addr}");
                match connect_punch_transport(socket, peer_addr, &upgrade.creds).await {
                    Ok((endpoint, transport)) => {
                        _endpoint_hold = Some(endpoint);
                        info!("punch upgrade: media switched to punch path ({peer_addr})");
                        if swap_tx.send(transport).is_err() {
                            warn!("punch upgrade: session swap channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("punch upgrade: connect on punch path failed: {e}");
                    }
                }
            }
            Some(PunchUpgradeEvent::Failed { reason }) => {
                debug!("punch upgrade: punch failed: {reason} (relay keeps carrying)");
            }
            None => break,
        }
    }
}
