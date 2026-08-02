//! 传输层整合。
//!
//! 提供统一的高层 API：`MediaTransport` trait 的 `QuicMediaTransport` 实现，
//! 以及 P1F 的 `SecureChannelTransport`（SecureChannel/TCP+AEAD 主路径）。
//!
//! 身份验证直接复用 `core::crypto::handshake` 的泛型函数
//! （`client_handshake_generic` / `server_handshake_verified_generic`），
//! 通过 `QuicBiStream` 适配 quinn 的双向流。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, warn};

use crate::encoder::types::EncodedPacket;
use crate::proto::EncodedWindow;
use crate::transport::{
    bi_stream::QuicBiStream,
    datagram,
    reassembly::FrameReassembly,
    stream::{self, ChannelTag, PacketHeader, TransError},
    ControlMessage, FramePacket, LossDetector, LossStats, MediaCipher, MediaTransport,
    QuicConnection, QuicEndpoint, TcpMediaTransport, TransportError, TransportMode,
};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake as core_handshake;
use kirin_desk_core::crypto::handshake::{
    PinExpectation, SecureChannel, SecureChannelReader, SecureChannelWriter,
};

// ════════════════════════════════════════════════════════════════
// QuicMediaTransport
// ════════════════════════════════════════════════════════════════

/// 控制流就绪标记（1 字节，置于控制帧流之外）。
///
/// quinn 的流以**首个 STREAM 帧**隐式建立：`open_bi` 只分配流 ID，不产生
/// 任何网络数据。若服务端 accept 后不立即写控制流（如 M8-T026-P1 打洞
/// 升舱/迁移场景服务端只收不发），客户端 `accept_bi` 将永久挂起直至空闲
/// 超时（既有测试靠服务端立即发 VideoFormat 隐式规避）。服务端 open_bi
/// 后立即写本标记强制 STREAM 帧发出，connect 端在 accept_bi 后同步消费
/// （标记在长度前缀+密文控制帧格式之外，不影响后续帧流解析）。
const CONTROL_STREAM_READY: u8 = 0xAA;

/// QUIC 媒体传输——核心实现。
pub struct QuicMediaTransport {
    conn: QuicConnection,
    /// Arc 共享：会话层控制 task（自适应反馈接收）与媒体循环并发使用同一 cipher。
    cipher: Arc<MediaCipher>,
    frame_id_counter: u64,
    reassembly: FrameReassembly,
    /// Arc 共享：客户端反馈上报（ReportGenerator）并发读取丢包统计。
    loss_detector: Arc<std::sync::Mutex<LossDetector>>,
    control_sender: Option<quinn::SendStream>,
    control_receiver: Option<quinn::RecvStream>,
    /// R-04：音频包缓冲通道发送端（`recv_frame` 内按 DATAGRAM kind 字节分流）。
    audio_tx: Option<std::sync::mpsc::Sender<crate::decoder::AudioPacket>>,
    /// R-04：音频包缓冲通道接收端（会话取出交给 `AudioDecodePipeline`）。
    audio_rx: Option<std::sync::mpsc::Receiver<crate::decoder::AudioPacket>>,
    /// R-04：音频接收是否启用（`take_audio_receiver` 置 true；false → 接收
    /// 循环丢弃音频包，不缓冲——避免无消费者时通道无界增长）。
    audio_buffering: bool,
}

impl QuicMediaTransport {
    /// 创建新的 QUIC 媒体传输。
    pub fn new(conn: QuicConnection, cipher: MediaCipher) -> Self {
        // R-04：音频缓冲通道随传输创建（接收端由会话经 `take_audio_receiver`
        // 取出；传输 drop → 发送端关闭 → 音频线程干净退出）。
        let (audio_tx, audio_rx) = std::sync::mpsc::channel();
        Self {
            conn,
            cipher: Arc::new(cipher),
            frame_id_counter: 0,
            reassembly: FrameReassembly::new(),
            loss_detector: Arc::new(std::sync::Mutex::new(LossDetector::default())),
            control_sender: None,
            control_receiver: None,
            audio_tx: Some(audio_tx),
            audio_rx: Some(audio_rx),
            audio_buffering: false,
        }
    }

    /// 设置控制流通道。
    pub fn set_control_streams(&mut self, sender: quinn::SendStream, receiver: quinn::RecvStream) {
        self.control_sender = Some(sender);
        self.control_receiver = Some(receiver);
    }

    /// 获取 QUIC 连接引用。
    pub fn conn(&self) -> &QuicConnection {
        &self.conn
    }

    /// 拆出控制发送流（客户端反馈上报 task 用）。
    pub fn take_control_sender(&mut self) -> Option<quinn::SendStream> {
        self.control_sender.take()
    }

    /// 拆出控制接收流（服务端自适应反馈接收 task 用）。
    pub fn take_control_receiver(&mut self) -> Option<quinn::RecvStream> {
        self.control_receiver.take()
    }

    /// 加密上下文句柄（与反馈接收 task 共享）。
    pub fn cipher_handle(&self) -> Arc<MediaCipher> {
        Arc::clone(&self.cipher)
    }

    /// 丢包检测器共享句柄（客户端 ReportGenerator 注入用）。
    pub fn loss_detector_shared(&self) -> Arc<std::sync::Mutex<LossDetector>> {
        Arc::clone(&self.loss_detector)
    }

    /// 丢包统计快照（诊断用）。
    pub fn loss_stats(&self) -> LossStats {
        self.loss_detector.lock().unwrap().stats().clone()
    }

    // ── P1F §T6.3：QUIC 阶段 EncodedPacket 分派 ─────────────────
    //
    // 视频 → DATAGRAM（可丢，低优先级）
    // 音频 → 独立 DATAGRAM（中优先级）
    // 键鼠 → 可靠流（最高优先级；此处只承接 InputEcho 反向回声，真实键鼠
    //         走客户端→服务端方向，由 input crate 经同一对 bi-stream 消费）

    /// 按 [`crate::transport::QuicKind`] 把一个 EncodedPacket 发到对应 QUIC 通道。
    ///
    /// - 视频/音频：打成 `PacketHeader + payload` → 经
    ///   [`datagram::send_encrypted_frame`] 带 **kind 字节**（R-04：DATAGRAM
    ///   头 1B 区分视频/音频，接收端据此分派）→ AEAD 加密 → DATAGRAM。
    ///   超过 DATAGRAM 负载上限的视频帧应调用方先自行分片（复用 datagram 分片路径）；
    ///   本方法对单片超限返回 [`TransportError::InvalidFrame`]。
    /// - 键鼠（InputEcho）：走控制可靠流（与既有 ControlMessage 复用同一条流，
    ///   加 tag 区分）。若控制流未建立 → `ConnectionClosed`。
    pub async fn send_packet_by_kind(
        &mut self,
        pkt: &crate::encoder::types::EncodedPacket,
    ) -> Result<(), TransportError> {
        let quic_kind = crate::transport::QuicKind::from_packet_kind(pkt.kind);
        let frame_id = self.next_quic_frame_id();
        let framed = crate::transport::stream::frame_packet(pkt, frame_id, 0)
            .map_err(trans_err_to_transport)?;

        match quic_kind {
            crate::transport::QuicKind::VideoDatagram
            | crate::transport::QuicKind::AudioDatagram => {
                // 视频/音频：DATAGRAM（kind 字节区分；明文 framed 经 AEAD 加密
                // → 单个 DATAGRAM，头含 kind=Video/Audio）。
                let kind_byte = match quic_kind {
                    crate::transport::QuicKind::AudioDatagram => {
                        crate::transport::stream::PacketKindWire::Audio as u8
                    }
                    _ => crate::transport::stream::PacketKindWire::Video as u8,
                };
                datagram::send_encrypted_frame(
                    &self.conn,
                    &self.cipher,
                    frame_id as u64,
                    kind_byte,
                    &framed,
                    pkt.is_key,
                    false,
                )
                .await
            }
            crate::transport::QuicKind::InputReliable => {
                // 键鼠回声 / 显示器控制：复用控制可靠流（前缀 tag 字节区分于
                // ControlMessage）。真实键鼠（客户端→服务端）由 input crate 在
                // 反向 bi-stream 上消费。
                let sender = self.control_sender.as_mut().ok_or_else(|| {
                    TransportError::ConnectionClosed {
                        reason: "input/control reliable stream not set".into(),
                    }
                })?;
                // 约定：可靠流上每条记录 = len(4B BE) || tag(1B) || framed。
                // tag=Control(0x04) 由既有 send_control_msg 路径产出；本路径按
                // 包类型区分（InputEcho→Input(0x03)，Control→Control(0x04)）。
                let tag = match pkt.kind {
                    crate::encoder::types::PacketKind::Control => {
                        crate::transport::ChannelTag::Control
                    }
                    _ => crate::transport::ChannelTag::Input,
                };
                let mut record = Vec::with_capacity(4 + 1 + framed.len());
                let body_len = (1 + framed.len()) as u32;
                record.extend_from_slice(&body_len.to_be_bytes());
                record.push(tag as u8);
                record.extend_from_slice(&framed);
                use tokio::io::AsyncWriteExt;
                sender.write_all(&record).await.map_err(|e| {
                    TransportError::Quic(format!("input reliable stream write: {e}"))
                })?;
                Ok(())
            }
        }
    }

    /// 从 PriorityQueue 取出并按优先级发送所有就绪包（拥塞时丢视频）。
    ///
    /// 优先级：键鼠 > 音频 > 视频。发送循环每次 `pop_next()`，全空返回。
    /// 上层应在空时 sleep，避免忙转。返回成功发送的包数。
    pub async fn drain_priority_queue(
        &mut self,
        queue: &mut crate::transport::PriorityQueue,
    ) -> Result<usize, TransportError> {
        let mut sent = 0usize;
        while let Some(pkt) = queue.pop_next() {
            match self.send_packet_by_kind(&pkt).await {
                Ok(()) => sent += 1,
                Err(e) => {
                    // 发送失败（通常是 DATAGRAM 拥塞/不可写）→ 丢视频保键鼠/音频。
                    // 键鼠可靠流失败会上抛（不丢）。
                    let is_video = pkt.kind == crate::encoder::types::PacketKind::Video;
                    if is_video {
                        warn!("QUIC send failed for video frame, dropping: {e}");
                        // 继续丢视频并尝试后续包。
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(sent)
    }

    /// 分配下一个 QUIC 帧号（u32 单调，回绕后由客户端重组/有序流处理）。
    fn next_quic_frame_id(&mut self) -> u32 {
        let id = self.frame_id_counter as u32;
        self.frame_id_counter = self.frame_id_counter.wrapping_add(1);
        id
    }

    async fn send_window_inner(&mut self, window: &EncodedWindow) -> Result<(), TransportError> {
        if window.is_empty() {
            return Ok(());
        }

        let window_id = window.window_id;

        for (idx, nal_packets) in window.frames.iter().enumerate() {
            let frame_id = self.frame_id_counter;
            self.frame_id_counter += 1;

            let nal_data = concat_nal_packets(nal_packets);
            let is_key = idx == 0;
            let is_window_end = idx == window.frames.len() - 1;

            datagram::send_encrypted_frame(
                &self.conn,
                &self.cipher,
                frame_id,
                crate::transport::stream::PacketKindWire::Video as u8,
                &nal_data,
                is_key,
                is_window_end,
            )
            .await?;
        }

        debug!(
            "send_window: window_id={}, {} frames sent",
            window_id, window.frame_count
        );
        Ok(())
    }

    async fn recv_frame_inner(&mut self) -> Result<FramePacket, TransportError> {
        use std::time::Duration;
        use tokio::time::timeout;

        self.reassembly.cleanup();

        let mut attempts = 0u32;
        loop {
            attempts += 1;
            if attempts > 1000 {
                return Err(TransportError::Timeout);
            }

            let datagram = timeout(Duration::from_secs(30), async {
                datagram::recv_encrypted_datagram(&self.conn, &self.cipher).await
            })
            .await
            .map_err(|_| TransportError::Timeout)??;

            let (frame_id, packet_idx, total, kind, flags, payload) = datagram;
            debug!(
                "recv_frame_inner: dg frame_id={} pkt={}/{} kind={} flags={:#06x} payload={}B",
                frame_id,
                packet_idx,
                total,
                kind,
                flags,
                payload.len()
            );

            // R-04：按 DATAGRAM kind 字节分派——音频包（payload = stream 帧包
            // `PacketHeader + Opus`，携带 PTS/首包标记）→ 缓冲通道（未启用时
            // 丢弃）；视频走重组路径。音频恒单 DATAGRAM（frame_packet 上限
            // 1151B < 分片阈值 1157B），多片音频包视为畸形丢弃。
            if kind == crate::transport::stream::PacketKindWire::Audio as u8 {
                if packet_idx == 0 && total == 1 {
                    match crate::transport::stream::parse_frame(&payload) {
                        Ok((header, audio_payload)) => {
                            let pkt = crate::decoder::AudioPacket {
                                pts: header.pts,
                                data: audio_payload.to_vec(),
                            };
                            if self.audio_buffering {
                                if let Some(tx) = &self.audio_tx {
                                    if tx.send(pkt).is_err() {
                                        // 接收端已关闭（会话结束）→ 停止缓冲。
                                        self.audio_buffering = false;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("[Transport] malformed audio datagram: {e} — dropping");
                        }
                    }
                } else {
                    warn!(
                        "[Transport] multi-datagram audio packet (pkt={packet_idx}/{total}) — dropping"
                    );
                }
                continue;
            }

            {
                let mut ld = self.loss_detector.lock().unwrap();
                ld.record_frame(frame_id);
                ld.auto_reset();
            }

            if let Some((fid, fflags, data)) = self
                .reassembly
                .add_packet(frame_id, packet_idx, total, flags, payload)
            {
                return Ok(FramePacket {
                    frame_id: fid,
                    flags: fflags,
                    data,
                });
            }
        }
    }
}

#[async_trait]
impl super::MediaTransport for QuicMediaTransport {
    async fn send_window(&mut self, window: &EncodedWindow) -> Result<(), TransportError> {
        self.send_window_inner(window).await
    }

    async fn recv_frame(&mut self) -> Result<FramePacket, TransportError> {
        self.recv_frame_inner().await
    }

    // R-04：音频包 → 独立 DATAGRAM（中优先级，可丢；头带 kind 字节，接收端
    // 按 type 分派——与视频包互不干扰）。
    async fn send_audio(&mut self, pkts: &[EncodedPacket]) -> Result<(), TransportError> {
        for pkt in pkts {
            self.send_packet_by_kind(pkt).await?;
        }
        Ok(())
    }

    fn take_audio_receiver(&mut self) -> Option<std::sync::mpsc::Receiver<crate::decoder::AudioPacket>> {
        // 启用音频缓冲（接收循环据此分流）；再次调用返回 None（已取出）。
        let rx = self.audio_rx.take()?;
        self.audio_buffering = true;
        Some(rx)
    }

    async fn send_control(&mut self, msg: &ControlMessage) -> Result<(), TransportError> {
        let sender =
            self.control_sender
                .as_mut()
                .ok_or_else(|| TransportError::ConnectionClosed {
                    reason: "control sender not set".into(),
                })?;
        crate::transport::control::send_control_msg(sender, &self.cipher, msg).await
    }

    async fn recv_control(&mut self) -> Result<ControlMessage, TransportError> {
        let receiver =
            self.control_receiver
                .as_mut()
                .ok_or_else(|| TransportError::ConnectionClosed {
                    reason: "control receiver not set".into(),
                })?;
        crate::transport::control::recv_control_msg(receiver, &self.cipher).await
    }

    fn is_alive(&self) -> bool {
        self.conn.is_alive()
    }

    fn rtt(&self) -> u64 {
        self.conn.rtt()
    }

    async fn close(self: Box<Self>) -> Result<(), TransportError> {
        self.conn.close("transport closed");
        Ok(())
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}

// ════════════════════════════════════════════════════════════════
// 建立流程（核心代码 — 直接复用 core 的泛型 handshake）
// ════════════════════════════════════════════════════════════════

/// 创建 QUIC 传输（服务端接受连接后调用）。
///
/// 流程:
///   1. quinn 接受连接（自签名证书，不验证）
///   2. 通过 QuicBiStream 适配 → server_handshake_verified_with_nickname_generic()
///      （可选昵称 / 挑战码校验，与 TCP 路径 `server_handshake_verified_with_nickname` 一致）
///   3. 从 SecureChannelGeneric 提取 cipher → 构造 MediaCipher
///   4. 打开控制流通道 → 返回 QuicMediaTransport
pub async fn accept_quic_transport(
    endpoint: &QuicEndpoint,
    server_identity: &IdentityManager,
    server_id: &str,
    client_pubkey_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
) -> Result<QuicMediaTransport, TransportError> {
    let (conn, remote) = endpoint.accept().await?;
    debug!("accept_quic_transport: accepted from {remote}");

    let (send, recv) = conn.accept_bi().await?;
    let stream = QuicBiStream::new(send, recv);

    let ch = core_handshake::server_handshake_verified_with_nickname_generic(
        stream,
        server_identity,
        server_id,
        client_pubkey_base64,
        expected_nickname,
        expected_challenge,
    )
    .await
    .map_err(|e| TransportError::Handshake(e.to_string()))?;

    let (mut ctrl_send, ctrl_recv) = conn.open_bi().await?;
    // 控制流就绪标记（见 `CONTROL_STREAM_READY`）：服务端是控制流打开方，
    // 必须实际写 1 字节才能让对端 `accept_bi` 返回。
    ctrl_send
        .write_all(&[CONTROL_STREAM_READY])
        .await
        .map_err(|e| TransportError::Quic(format!("control stream ready: {e}")))?;
    let mut transport = QuicMediaTransport::new(conn, MediaCipher::new_from_aead(ch.cipher));
    transport.set_control_streams(ctrl_send, ctrl_recv);

    debug!("accept_quic_transport: ready from {remote}");
    Ok(transport)
}

/// 创建 QUIC 传输（客户端拨号后调用）。
///
/// 流程:
///   1. quinn 拨号连接
///   2. 通过 QuicBiStream 适配 → client_handshake_generic()
///   3. 从 SecureChannelGeneric 提取 cipher → 构造 MediaCipher
///   4. 打开控制流通道 → 返回 QuicMediaTransport
pub async fn connect_quic_transport(
    addr: SocketAddr,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    server_pin: PinExpectation,
    challenge: &str,
) -> Result<QuicMediaTransport, TransportError> {
    let conn = QuicEndpoint::connect(addr, client_id).await?;

    let (send, recv) = conn.open_bi().await?;
    let stream = QuicBiStream::new(send, recv);

    let ch = core_handshake::client_handshake_generic(
        stream,
        client_identity,
        client_id,
        client_domain,
        client_device_type,
        server_id,
        server_pin,
        challenge,
    )
    .await
    .map_err(|e| TransportError::Handshake(e.to_string()))?;

    let (ctrl_send, mut ctrl_recv) = conn.accept_bi().await?;
    // 消费服务端控制流就绪标记（与 accept_quic_transport 的
    // CONTROL_STREAM_READY 配对；标记在控制帧格式之外，直接丢弃）。
    let mut ready = [0u8; 1];
    ctrl_recv
        .read_exact(&mut ready)
        .await
        .map_err(|e| TransportError::Quic(format!("control stream ready: {e}")))?;
    let mut transport = QuicMediaTransport::new(conn, MediaCipher::new_from_aead(ch.cipher));
    transport.set_control_streams(ctrl_send, ctrl_recv);

    debug!("connect_quic_transport: ready to {addr}");
    Ok(transport)
}

/// 创建 QUIC 传输（客户端在**预建端点**上拨号——打洞路径，M8-T026-P1）。
///
/// 与 [`connect_quic_transport`] 的唯一区别：连接从外部预建的
/// `QuicEndpoint`（`QuicEndpoint::client_on` 建于打洞 socket 之上）发起，
/// 保证 QUIC 复用打洞建立的 NAT 映射（PUNCH-001）；Ed25519 握手流程一致
/// （PUNCH-SEC-001：打洞路径不弱化身份校验）。
pub async fn connect_quic_transport_on(
    endpoint: &QuicEndpoint,
    addr: SocketAddr,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    server_pin: PinExpectation,
    challenge: &str,
) -> Result<QuicMediaTransport, TransportError> {
    let conn = endpoint.connect_on(addr, client_id).await?;
    let (send, recv) = conn.open_bi().await?;
    let stream = QuicBiStream::new(send, recv);

    let ch = core_handshake::client_handshake_generic(
        stream,
        client_identity,
        client_id,
        client_domain,
        client_device_type,
        server_id,
        server_pin,
        challenge,
    )
    .await
    .map_err(|e| TransportError::Handshake(e.to_string()))?;

    let (ctrl_send, mut ctrl_recv) = conn.accept_bi().await?;
    // 消费服务端控制流就绪标记（与 accept_quic_transport 的
    // CONTROL_STREAM_READY 配对；标记在控制帧格式之外，直接丢弃）。
    let mut ready = [0u8; 1];
    ctrl_recv
        .read_exact(&mut ready)
        .await
        .map_err(|e| TransportError::Quic(format!("control stream ready: {e}")))?;
    let mut transport = QuicMediaTransport::new(conn, MediaCipher::new_from_aead(ch.cipher));
    transport.set_control_streams(ctrl_send, ctrl_recv);

    debug!("connect_quic_transport_on: ready to {addr} (punch path)");
    Ok(transport)
}

// ════════════════════════════════════════════════════════════════
// 辅助函数
// ════════════════════════════════════════════════════════════════

/// 合并 H.264 NAL 包到单个字节流。
pub fn concat_nal_packets(packets: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = packets.iter().map(|p| p.len()).sum();
    let mut result = Vec::with_capacity(total);
    for p in packets {
        result.extend_from_slice(p);
    }
    result
}

// ════════════════════════════════════════════════════════════════
// SecureChannelTransport — P1F §T6.3（SecureChannel 阶段，当前主路径）
// ════════════════════════════════════════════════════════════════
//
// 服务端 = 被控端场景：
//   服务端 ──Video/Audio──► 客户端（解码/播放）
//   客户端 ──InputEcho──► 服务端（input crate 注入）
// 共用一条 TCP 通道 + SecureChannel(AEAD AES-256-GCM)，靠前缀字节
// （ChannelTag）区分。键鼠不开裸端口，全部走加密通道。

/// SecureChannel 阶段的帧封装：`tag(1B) || framed(header + payload)`。
///
/// tag 即 [`ChannelTag`]（Video/Audio/InputEcho/Control）；framed 由
/// [`stream::frame_packet`] 产出。接收端先读 tag 分派，再按 tag 解析。
fn build_tagged_frame(tag: ChannelTag, framed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + framed.len());
    out.push(tag as u8);
    out.extend_from_slice(framed);
    out
}

/// SecureChannel **发送半传输**：独占 [`SecureChannelWriter`]（单向），
/// 单任务使用、无锁。对应 M9：客户端"输入发送"任务、服务端"视频发送"任务。
pub struct SecureChannelSender {
    writer: SecureChannelWriter,
    /// 本端分配的单调帧号（用于 PacketHeader.frame_id）。
    frame_id_counter: u32,
}

/// SecureChannel **接收半传输**：独占 [`SecureChannelReader`]（单向），
/// 单任务使用、无锁。对应 M9：服务端"输入接收"任务、客户端"视频接收"任务。
pub struct SecureChannelReceiver {
    reader: SecureChannelReader,
}

/// SecureChannel 媒体传输（完整封装）：在 [`SecureChannel`]（TCP + AEAD）上承载
/// EncodedPacket（视频/音频/键鼠）。
///
/// # 帧格式
///
/// 每条 SecureChannel 消息 = `tag(1B) || PacketHeader(HEADER_SIZE) || payload`，
/// 整体经 `SecureChannel::send`（4B BE 长度前缀 + nonce + AES-256-GCM 密文）加密。
///
/// # 方向
///
/// - `send_packets`：服务端发视频/音频给客户端。
/// - `recv_input_payload`：服务端从客户端收键鼠事件（反向同通道）。
///
/// 双任务并发（如客户端"视频接收 + 输入发送"）时用 [`SecureChannelTransport::into_split`]
/// 拆成两个半传输，各自独占一个方向、互不阻塞。
pub struct SecureChannelTransport {
    sender: Option<SecureChannelSender>,
    receiver: Option<SecureChannelReceiver>,
}

impl SecureChannelSender {
    /// 包装写半通道。
    pub fn new(writer: SecureChannelWriter) -> Self {
        Self {
            writer,
            frame_id_counter: 0,
        }
    }

    /// 分配下一个 frame_id（u32 单调，回绕后由客户端按流处理）。
    fn next_frame_id(&mut self) -> u32 {
        let id = self.frame_id_counter;
        self.frame_id_counter = self.frame_id_counter.wrapping_add(1);
        id
    }

    /// 发送一批 EncodedPacket（视频/音频/键鼠）。
    ///
    /// 每个 packet 打包为 `tag || header || payload`，单次 flush。
    /// 单包负载超过 [`stream::MAX_PACKET_PAYLOAD`] → [`TransportError::InvalidFrame`]
    /// （SecureChannel 阶段不分片；视频应走 QUIC DATAGRAM 分片路径）。
    pub async fn send_packets(&mut self, pkts: &[EncodedPacket]) -> Result<(), TransportError> {
        if pkts.is_empty() {
            return Ok(());
        }
        for pkt in pkts {
            let tag = ChannelTag::from_packet_kind(pkt.kind);
            let frame_id = self.next_frame_id();
            let framed = stream::frame_packet(pkt, frame_id, 0).map_err(trans_err_to_transport)?;
            let tagged = build_tagged_frame(tag, &framed);
            self.writer
                .send(&tagged)
                .await
                .map_err(|e| TransportError::SecureChannel(format!("send: {e}")))?;
        }
        debug!("SecureChannelSender: sent {} packets", pkts.len());
        Ok(())
    }

    /// 发送一个**大帧** EncodedPacket（M13-T006 文件传输）。
    ///
    /// 与 [`send_packets`](Self::send_packets) 的差异：跳过
    /// [`stream::MAX_PACKET_PAYLOAD`]（≈1151B）小分片检查，直接打包
    /// `tag || header || payload` 经 SecureChannel（4B 长度前缀，无小帧限制）
    /// 发送。payload 上限 [`stream::MAX_FILE_FRAME_PAYLOAD`]（16 MiB）。
    ///
    /// 仅限大块数据（如 64 KiB 文件块）；键鼠/音频/剪贴板仍走
    /// [`send_packets`](Self::send_packets) 小帧路径。
    pub async fn send_big_packet(&mut self, pkt: &EncodedPacket) -> Result<(), TransportError> {
        if pkt.data.len() > stream::MAX_FILE_FRAME_PAYLOAD {
            return Err(TransportError::InvalidFrame(format!(
                "file frame payload too large: {} bytes (max {})",
                pkt.data.len(),
                stream::MAX_FILE_FRAME_PAYLOAD
            )));
        }
        let tag = ChannelTag::from_packet_kind(pkt.kind);
        let frame_id = self.next_frame_id();
        let header = stream::PacketHeader::from_packet(pkt, frame_id, 0);
        let mut buf = Vec::with_capacity(stream::HEADER_SIZE + pkt.data.len());
        header.encode(&mut buf);
        buf.extend_from_slice(&pkt.data);
        let tagged = build_tagged_frame(tag, &buf);
        self.writer
            .send(&tagged)
            .await
            .map_err(|e| TransportError::SecureChannel(format!("send big frame: {e}")))?;
        Ok(())
    }
}

impl SecureChannelReceiver {
    /// 包装读半通道。
    pub fn new(reader: SecureChannelReader) -> Self {
        Self { reader }
    }

    /// 接收一帧（任意 tag）。返回 `(tag, header, payload)`。
    ///
    /// 用于客户端：按 tag 把 payload 分发到解码器（Video）/ 音频播放（Audio）。
    pub async fn recv_tagged(
        &mut self,
    ) -> Result<(ChannelTag, PacketHeader, Vec<u8>), TransportError> {
        let plain = self
            .reader
            .receive()
            .await
            .map_err(|e| TransportError::SecureChannel(format!("receive: {e}")))?;
        if plain.is_empty() {
            return Err(TransportError::InvalidFrame(
                "empty securechannel frame".into(),
            ));
        }
        let tag_byte = plain[0];
        let tag = ChannelTag::from_byte(tag_byte).ok_or_else(|| {
            TransportError::InvalidFrame(format!("unknown channel tag: 0x{tag_byte:02X}"))
        })?;
        let body = &plain[1..];
        let (header, payload) = stream::parse_frame(body).map_err(trans_err_to_transport)?;
        Ok((tag, header, payload.to_vec()))
    }

    /// 接收一条键鼠事件 wire bytes（客户端 → 服务端方向）。
    ///
    /// 服务端在收到 `ChannelTag::Input` 后用本方法循环消费，逐条反序列化并
    /// 喂入 [`kirin_desk_input::InputInjector`]。失败仅记日志（可靠流不重发）。
    pub async fn recv_input_payload(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            let (tag, _header, payload) = self.recv_tagged().await?;
            match tag {
                ChannelTag::Input => return Ok(payload),
                other => {
                    // 方向错误：客户端误发视频/音频到服务端注入路径 → 拒绝，记日志。
                    warn!(
                        "SecureChannelReceiver: expected Input tag, got {:?}; dropping",
                        other
                    );
                    continue;
                }
            }
        }
    }
}

impl SecureChannelTransport {
    /// 包装一个已握手的 [`SecureChannel`]（内部分拆为读写半通道）。
    pub fn new(channel: SecureChannel) -> Self {
        let (reader, writer) = channel.into_split();
        Self {
            sender: Some(SecureChannelSender::new(writer)),
            receiver: Some(SecureChannelReceiver::new(reader)),
        }
    }

    /// 拆分为独立的发送/接收半传输（M9：双任务并发场景，各方向单任务独占）。
    pub fn into_split(self) -> (SecureChannelReceiver, SecureChannelSender) {
        (
            self.receiver.expect("receiver already taken"),
            self.sender.expect("sender already taken"),
        )
    }

    /// 拆出**写半**（发送半通道），本传输保留读半（接收媒体帧）。
    ///
    /// P5 会话层用：客户端反馈 task 独占写半（send_control），主循环保留读半
    /// （recv_frame）。拆出后本传输不再能 send_*（返回 `ConnectionClosed`）。
    pub fn take_sender(&mut self) -> Option<SecureChannelSender> {
        self.sender.take()
    }

    /// 拆出**读半**（接收半通道），本传输保留写半（发送媒体/控制）。
    ///
    /// P5 会话层用：服务端控制 task 独占读半（recv_control），主循环保留写半
    /// （send_window / send_control）。拆出后本传输不再能 recv_*。
    pub fn take_receiver(&mut self) -> Option<SecureChannelReceiver> {
        self.receiver.take()
    }

    /// 发送一批 EncodedPacket（委托给发送半传输）。
    pub async fn send_packets(&mut self, pkts: &[EncodedPacket]) -> Result<(), TransportError> {
        let sender = self.sender.as_mut().ok_or_else(|| {
            TransportError::ConnectionClosed {
                reason: "sender already taken (TCP write half moved)".into(),
            }
        })?;
        sender.send_packets(pkts).await
    }

    /// 发送一个**大帧** EncodedPacket（委托给发送半传输，M13-T006 文件传输）。
    ///
    /// 语义同 [`SecureChannelSender::send_big_packet`]：跳过
    /// [`stream::MAX_PACKET_PAYLOAD`] 小分片检查，payload 上限
    /// [`stream::MAX_FILE_FRAME_PAYLOAD`]（16 MiB）。
    pub async fn send_big_packet(&mut self, pkt: &EncodedPacket) -> Result<(), TransportError> {
        let sender = self.sender.as_mut().ok_or_else(|| {
            TransportError::ConnectionClosed {
                reason: "sender already taken (TCP write half moved)".into(),
            }
        })?;
        sender.send_big_packet(pkt).await
    }

    /// 接收一帧（任意 tag，委托给接收半传输）。
    pub async fn recv_tagged(
        &mut self,
    ) -> Result<(ChannelTag, PacketHeader, Vec<u8>), TransportError> {
        let receiver = self.receiver.as_mut().ok_or_else(|| {
            TransportError::ConnectionClosed {
                reason: "receiver already taken (TCP read half moved)".into(),
            }
        })?;
        receiver.recv_tagged().await
    }

    /// 接收一条键鼠事件 wire bytes（委托给接收半传输）。
    pub async fn recv_input_payload(&mut self) -> Result<Vec<u8>, TransportError> {
        let receiver = self.receiver.as_mut().ok_or_else(|| {
            TransportError::ConnectionClosed {
                reason: "receiver already taken (TCP read half moved)".into(),
            }
        })?;
        receiver.recv_input_payload().await
    }
}

/// 把 [`TransError`]（帧封装层错误）映射到 [`TransportError`]。
fn trans_err_to_transport(e: TransError) -> TransportError {
    match e {
        TransError::MalformedHeader => {
            TransportError::InvalidFrame("malformed packet header".into())
        }
        TransError::PayloadTooLarge(got, max) => TransportError::InvalidFrame(format!(
            "payload too large: {got} bytes (max {max}; use QUIC datagram fragmentation for video)"
        )),
        TransError::NotConnected => TransportError::ConnectionClosed {
            reason: "transport not connected".into(),
        },
    }
}

// ════════════════════════════════════════════════════════════════
// 动态建连工厂（M8-T025 P5-2）
// ════════════════════════════════════════════════════════════════

/// 双栈 TCP 监听：优先 `[::]:port`（IPV6_V6ONLY=false，可收 v4-mapped 连接），
/// 平台不支持 → 回退 `0.0.0.0:port`（仅 v4）。供 P5-2 工厂与服务端会话
/// 降级接收共用（不依赖 core `TcpServer`——P2 侧冻结，且其 Windows 双栈
/// 行为与 QUIC 双栈不一致）。
pub fn bind_dual_stack_tcp_listener(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    if let Ok(socket) = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)) {
        let dual_ok = socket.set_only_v6(false).is_ok()
            && socket
                .bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())
                .is_ok();
        if dual_ok {
            socket.listen(128)?;
            return tokio::net::TcpListener::from_std(socket.into());
        }
        warn!(
            "dual-stack TCP bind [::]:{port} unavailable on this platform, \
             falling back to IPv4-only 0.0.0.0:{port}"
        );
    }
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))?;
    listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(listener)
}

/// 把泛型握手结果（`SecureChannelGeneric<TcpStream>`）收敛为 TCP 专用
/// [`SecureChannel`]（字段一一对应；工厂与测试基建共用）。
#[allow(dead_code)]
fn secure_channel_from_generic(
    ch: kirin_desk_core::crypto::handshake::SecureChannelGeneric<tokio::net::TcpStream>,
) -> SecureChannel {
    SecureChannel {
        stream: ch.stream,
        cipher: ch.cipher,
        peer_id: ch.peer_id,
        peer_domain: ch.peer_domain,
        peer_device_type: ch.peer_device_type,
        selected_codec: ch.selected_codec,
    }
}

/// 把 `core::network::tcp::TcpError` 映射为传输层错误。
fn tcp_err_to_transport(e: kirin_desk_core::network::tcp::TcpError) -> TransportError {
    use kirin_desk_core::network::tcp::TcpError;
    match e {
        TcpError::Bind { source, .. } | TcpError::Connect { source, .. } => {
            TransportError::Io(source)
        }
        TcpError::Timeout { remote: _ } => TransportError::Timeout,
        // S-02 (F-5): 长度前缀超限 → 协议级错误（上游应关闭连接）。
        TcpError::MessageTooLarge { len, max } => TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {len} > {max}"),
        )),
        TcpError::Io(e) => TransportError::Io(e),
    }
}

/// 客户端统一建连（M8-T025 §3.4 建连流程）。
///
/// - `mode = Quic` + `allow_fallback = true`：QUIC 拨号 + 完整握手优先；
///   失败/超时（`connect_timeout`，默认 3s）→ 记日志 → TCP SecureChannel 拨号
///   + 完整握手 → `TcpMediaTransport`。
/// - `mode = Quic` + `allow_fallback = false`：仅 QUIC，失败报错（B 需求可控）。
/// - `mode = Tcp`：仅 TCP（`--transport tcp` 强制路径）。
///
/// 两条路径走**同一完整握手**（`client_handshake_generic`），身份凭据
/// （昵称/挑战码/公钥绑定）完全一致——不引入新协议字段（主文档 §3.4）。
pub async fn connect_media_transport(
    addr: SocketAddr,
    mode: TransportMode,
    allow_fallback: bool,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    server_pin: PinExpectation,
    challenge: &str,
    connect_timeout: Duration,
) -> Result<Box<dyn MediaTransport>, TransportError> {
    // R-02（pin 强类型）：TCP 回退闭包捕获克隆（async 非 move 闭包按引用
    // 捕获，不能与 QUIC 分支的 move 共用同一值）。
    let server_pin_tcp = server_pin.clone();
    let connect_tcp = async {
        connect_tcp_transport(
            addr,
            client_identity,
            client_id,
            client_domain,
            client_device_type,
            server_id,
            server_pin_tcp,
            challenge,
            connect_timeout,
        )
        .await
    };

    match mode {
        TransportMode::Quic => {
            let quic = tokio::time::timeout(connect_timeout, connect_quic_transport(
                addr,
                client_identity,
                client_id,
                client_domain,
                client_device_type,
                server_id,
                server_pin,
                challenge,
            ))
            .await;
            match quic {
                Ok(Ok(t)) => Ok(Box::new(t)),
                Ok(Err(e)) if allow_fallback => {
                    warn!("QUIC connect to {addr} failed: {e} — falling back to TCP");
                    connect_tcp.await
                }
                Ok(Err(e)) => Err(e),
                Err(_) if allow_fallback => {
                    warn!(
                        "QUIC connect to {addr} timed out after {connect_timeout:?} — falling back to TCP"
                    );
                    connect_tcp.await
                }
                Err(_) => Err(TransportError::Timeout),
            }
        }
        TransportMode::Tcp => connect_tcp.await,
    }
}

/// TCP（SecureChannel）建连：`TcpClient::connect_with_timeout`（P2 签名）→
/// 完整握手 → `TcpMediaTransport`。
async fn connect_tcp_transport(
    addr: SocketAddr,
    client_identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    client_device_type: &str,
    server_id: &str,
    server_pin: PinExpectation,
    challenge: &str,
    connect_timeout: Duration,
) -> Result<Box<dyn MediaTransport>, TransportError> {
    use kirin_desk_core::network::tcp::TcpClient;

    let timeout_secs = connect_timeout.as_secs().max(1);
    let stream = TcpClient::connect_with_timeout(addr, timeout_secs)
        .await
        .map_err(tcp_err_to_transport)?;

    let ch = core_handshake::client_handshake_generic(
        stream,
        client_identity,
        client_id,
        client_domain,
        client_device_type,
        server_id,
        server_pin,
        challenge,
    )
    .await
    .map_err(|e| TransportError::Handshake(e.to_string()))?;

    let transport = TcpMediaTransport::new(secure_channel_from_generic(ch));
    debug!("connect_tcp_transport: ready to {addr}");
    Ok(Box::new(transport))
}

/// 服务端统一 accept：UDP（QUIC）+ TCP 双监听，**先到者胜**。
///
/// - QUIC 分支带 2s 超时：对端 QUIC 不可达/握手过慢不阻塞 TCP 回退
///   （客户端回退逻辑驱动，服务端无状态）。
/// - TCP 分支：`server_handshake_verified_with_nickname_generic`（昵称/挑战码/
///   白名单凭据与 QUIC 路径一致）→ `TcpMediaTransport`。
///
/// `tcp_listener` 由调用方持有（双栈绑定见 [`bind_dual_stack_tcp_listener`]）；
/// 会话中途降级时同一监听器交给会话的降级接收（P5-3）。
pub async fn accept_media_transport(
    quic_endpoint: &QuicEndpoint,
    tcp_listener: &tokio::net::TcpListener,
    server_identity: &IdentityManager,
    server_id: &str,
    client_pubkey_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
) -> Result<Box<dyn MediaTransport>, TransportError> {
    const QUIC_ACCEPT_TIMEOUT: Duration = Duration::from_secs(2);

    let quic_fut = async {
        match tokio::time::timeout(
            QUIC_ACCEPT_TIMEOUT,
            accept_quic_transport(
                quic_endpoint,
                server_identity,
                server_id,
                client_pubkey_base64,
                expected_nickname,
                expected_challenge,
            ),
        )
        .await
        {
            Ok(Ok(t)) => Some(Box::new(t) as Box<dyn MediaTransport>),
            Ok(Err(e)) => {
                warn!("QUIC accept failed: {e} — waiting on TCP");
                None
            }
            Err(_) => {
                warn!("QUIC accept timed out after {QUIC_ACCEPT_TIMEOUT:?} — waiting on TCP");
                None
            }
        }
    };

    tokio::select! {
        q = quic_fut => {
            if let Some(t) = q {
                return Ok(t);
            }
            // QUIC 无连接/失败/超时 → 等 TCP（对端回退路径驱动）
            let t = accept_tcp_transport(
                tcp_listener, server_identity, server_id, client_pubkey_base64,
                expected_nickname, expected_challenge,
            ).await?;
            Ok(Box::new(t) as Box<dyn MediaTransport>)
        }
        t = accept_tcp_transport(
            tcp_listener, server_identity, server_id, client_pubkey_base64,
            expected_nickname, expected_challenge,
        ) => {
            let t = t?;
            Ok(Box::new(t) as Box<dyn MediaTransport>)
        }
    }
}

/// TCP（SecureChannel）accept：接受连接 → 完整握手（昵称/挑战码可选）→
/// `TcpMediaTransport`。
async fn accept_tcp_transport(
    tcp_listener: &tokio::net::TcpListener,
    server_identity: &IdentityManager,
    server_id: &str,
    client_pubkey_base64: &str,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
) -> Result<TcpMediaTransport, TransportError> {
    let (stream, remote) = tcp_listener.accept().await?;
    debug!("accept_tcp_transport: accepted from {remote}");

    let ch = core_handshake::server_handshake_verified_with_nickname_generic(
        stream,
        server_identity,
        server_id,
        client_pubkey_base64,
        expected_nickname,
        expected_challenge,
    )
    .await
    .map_err(|e| TransportError::Handshake(e.to_string()))?;

    let transport = TcpMediaTransport::new(secure_channel_from_generic(ch));
    debug!("accept_tcp_transport: ready from {remote}");
    Ok(transport)
}

#[cfg(test)]
mod secure_channel_tests {
    use super::*;
    use crate::encoder::types::{PacketKind, Timestamp};
    use kirin_desk_core::crypto::ed25519::IdentityManager;
    use std::time::Instant;
    use tokio::net::TcpListener;

    /// 构造一对已握手的 SecureChannelTransport（本机回环）。
    ///
    /// 服务端用 `server_handshake_verified_generic`（白名单接受），
    /// 客户端用 `client_handshake_generic`，经 TCP 流适配，再各自包装为
    /// [`SecureChannelTransport`]。
    async fn make_transport_pair() -> (SecureChannelTransport, SecureChannelTransport) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // IdentityManager::generate 需要 key_path（仅磁盘保存用，本测试不存盘）。
        // 用临时目录下的唯一文件名（不 save，不会真正落盘）。
        let server_id = "test-server-device".to_string();
        let client_id = "test-client-device".to_string();
        let tmp = std::env::temp_dir();
        let server_im =
            IdentityManager::generate(tmp.join(format!("kirin_test_s_{server_id}.key")))
                .expect("generate server identity");
        let client_im =
            IdentityManager::generate(tmp.join(format!("kirin_test_c_{client_id}.key")))
                .expect("generate client identity");
        let server_pub = server_im.public_key_base64();
        let client_pub = client_im.public_key_base64();

        // server_id 克隆一份给 spawn 任务（client 侧也需引用，但 client 在主任务）。
        let server_id_for_task = server_id.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // 服务端白名单直接接受（verified_generic 用 client_pub 校验）。
            core_handshake::server_handshake_verified_generic(
                stream,
                &server_im,
                &server_id_for_task,
                &client_pub,
            )
            .await
            .expect("server handshake")
        });

        let client_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client_ch = core_handshake::client_handshake_generic(
            client_stream,
            &client_im,
            &client_id,
            "test.example",
            "tester",
            &server_id,
            PinExpectation::exact_from_base64(&server_pub).expect("server pubkey"),
            "challenge",
        )
        .await
        .expect("client handshake");

        let server_generic = server_handle.await.expect("server task join");
        // 把 generic 回退到 SecureChannel（TCP 专用结构）。
        let server_ch = SecureChannel {
            stream: server_generic.stream,
            cipher: server_generic.cipher,
            peer_id: server_generic.peer_id,
            peer_domain: server_generic.peer_domain,
            peer_device_type: server_generic.peer_device_type,
            selected_codec: server_generic.selected_codec,
        };
        let real_client_ch = SecureChannel {
            stream: client_ch.stream,
            cipher: client_ch.cipher,
            peer_id: client_ch.peer_id,
            peer_domain: client_ch.peer_domain,
            peer_device_type: client_ch.peer_device_type,
            selected_codec: client_ch.selected_codec,
        };
        (
            SecureChannelTransport::new(server_ch),
            SecureChannelTransport::new(real_client_ch),
        )
    }

    fn make_packet(kind: PacketKind, data: Vec<u8>, pts: u64) -> EncodedPacket {
        EncodedPacket {
            ts: Timestamp::new(Instant::now(), pts),
            kind,
            data,
            is_key: kind == PacketKind::Video,
        }
    }

    /// 回环：服务端发三类包 → 客户端按 tag 收到正确分派。
    #[tokio::test]
    async fn test_securechannel_roundtrip_dispatch() {
        let (mut server, mut client) = make_transport_pair().await;

        let pkts = vec![
            make_packet(PacketKind::Video, vec![0xAA; 32], 100),
            make_packet(PacketKind::Audio, vec![0xBB; 16], 110),
            make_packet(PacketKind::InputEcho, vec![0xCC; 8], 120),
        ];
        server.send_packets(&pkts).await.expect("send");

        // 客户端按发送顺序收到三个 tag。
        let (t1, h1, p1) = client.recv_tagged().await.expect("recv1");
        assert_eq!(t1, ChannelTag::Video);
        assert_eq!(p1, vec![0xAA; 32]);
        assert_eq!(h1.pts, 100);
        assert!(h1.is_key());

        let (t2, h2, p2) = client.recv_tagged().await.expect("recv2");
        assert_eq!(t2, ChannelTag::Audio);
        assert_eq!(p2, vec![0xBB; 16]);
        assert_eq!(h2.pts, 110);

        let (t3, h3, p3) = client.recv_tagged().await.expect("recv3");
        assert_eq!(t3, ChannelTag::Input);
        assert_eq!(p3, vec![0xCC; 8]);
        assert_eq!(h3.pts, 120);

        // frame_id 单调。
        assert!(h2.frame_id > h1.frame_id);
        assert!(h3.frame_id > h2.frame_id);
    }

    /// 反向通道：客户端发键鼠 → 服务端 recv_input_payload 收到。
    #[tokio::test]
    async fn test_input_reverse_channel() {
        let (mut server, mut client) = make_transport_pair().await;
        let input_pkt = make_packet(PacketKind::InputEcho, vec![0x11, 0x22, 0x33], 5);
        client
            .send_packets(&[input_pkt])
            .await
            .expect("client send");

        let payload = server.recv_input_payload().await.expect("recv input");
        assert_eq!(payload, vec![0x11, 0x22, 0x33]);
    }

    /// 错误 tag 拒绝：客户端在 input 通道收到非 Input 包 → 拒绝并继续。
    #[tokio::test]
    async fn test_wrong_tag_rejected() {
        let (mut server, mut client) = make_transport_pair().await;
        // 服务端先发一个 Video（客户端 recv_input_payload 应跳过），再发 Input。
        server
            .send_packets(&[
                make_packet(PacketKind::Video, vec![0xAA; 4], 1),
                make_packet(PacketKind::InputEcho, vec![0xDD; 2], 2),
            ])
            .await
            .unwrap();

        let payload = client.recv_input_payload().await.expect("recv input");
        assert_eq!(payload, vec![0xDD; 2]);
    }

    /// 空包列表：send_packets 立即返回 Ok，不发任何字节。
    #[tokio::test]
    async fn test_send_empty_packets_noop() {
        let (mut server, _client) = make_transport_pair().await;
        server.send_packets(&[]).await.expect("empty send noop");
    }

    /// tag 构造字节布局自洽。
    #[test]
    fn test_build_tagged_frame_layout() {
        let framed = vec![0x4B, 0x44, 0x01]; // 任意 framed
        let tagged = build_tagged_frame(ChannelTag::Audio, &framed);
        assert_eq!(tagged.len(), 1 + framed.len());
        assert_eq!(tagged[0], ChannelTag::Audio as u8);
        assert_eq!(&tagged[1..], &framed[..]);
    }
}

// ════════════════════════════════════════════════════════════════
// QUIC 阶段 EncodedPacket 分派测试（P1F §T6.3）
// ════════════════════════════════════════════════════════════════
//
// 真实 QUIC 端到端连接（含握手 + DATAGRAM 重组）由 M8-T013 阶段在
// `accept_quic_transport`/`connect_quic_transport` 上做集成验证；本模块只验证
// P1F 引入的「分派/优先级/成帧」逻辑，不依赖真实 quinn 连接（避免端口/SNI
// 等环境耦合）。

#[cfg(test)]
mod quic_dispatch_tests {
    use crate::encoder::types::{EncodedPacket, PacketKind, Timestamp};
    use crate::transport::{PriorityQueue, QuicKind, MAX_PACKET_PAYLOAD};
    use std::time::Instant;

    fn pkt(kind: PacketKind, pts: u64) -> EncodedPacket {
        EncodedPacket {
            ts: Timestamp::new(Instant::now(), pts),
            kind,
            data: vec![0xAB; 16],
            is_key: kind == PacketKind::Video,
        }
    }

    /// QUIC DATAGRAM 优先级：PriorityQueue 出队顺序 Input → Audio → Video，
    /// 与 QuicKind 映射一致（键鼠走 InputReliable、音频走 AudioDatagram、
    /// 视频走 VideoDatagram）。
    ///
    /// 这是 `drain_priority_queue` 内部所依赖的核心不变量：发送循环每次
    /// `pop_next()` 取最高优先级包，再按 `QuicKind::from_packet_kind` 分派通道。
    #[test]
    fn test_quic_datagram_priority_dispatch_order() {
        // 混合三类包，乱序入队。
        let mut queue = PriorityQueue::with_default_capacity();
        queue.push(pkt(PacketKind::Video, 1));
        queue.push(pkt(PacketKind::InputEcho, 2));
        queue.push(pkt(PacketKind::Audio, 3));
        queue.push(pkt(PacketKind::Video, 4));

        // 模拟发送循环：pop_next 取包 → QuicKind 映射。
        let mut dispatched: Vec<(QuicKind, u64)> = Vec::new();
        while let Some(p) = queue.pop_next() {
            dispatched.push((QuicKind::from_packet_kind(p.kind), p.ts.pts));
        }

        // 期望顺序：Input(2) → Audio(3) → Video(1) → Video(4)。
        assert_eq!(
            dispatched,
            vec![
                (QuicKind::InputReliable, 2),
                (QuicKind::AudioDatagram, 3),
                (QuicKind::VideoDatagram, 1),
                (QuicKind::VideoDatagram, 4),
            ]
        );
    }

    /// QUIC 视频帧超 DATAGRAM 负载上限 → 成帧阶段即被拒绝（frame_packet
    /// 返回 PayloadTooLarge，drain 前应阻止入队）。
    ///
    /// 这等价于 send_packet_by_kind 内的 frame_packet 调用路径（在真实
    /// conn.send_datagram 之前失败，无需网络）。
    #[test]
    fn test_quic_video_oversize_rejected_at_framing() {
        let oversize = vec![0u8; MAX_PACKET_PAYLOAD + 1];
        let p = EncodedPacket {
            ts: Timestamp::now(),
            kind: PacketKind::Video,
            data: oversize,
            is_key: true,
        };
        // frame_packet 是 send_packet_by_kind 的第一步；超限在此被拒。
        let err = crate::transport::stream::frame_packet(&p, 1, 0).unwrap_err();
        assert!(matches!(
            err,
            crate::transport::TransError::PayloadTooLarge(_, _)
        ));
    }

    /// 空队列：drain 循环 pop_next 立即返回 None → 0 发送。
    #[test]
    fn test_quic_drain_empty_queue() {
        let mut queue = PriorityQueue::with_default_capacity();
        assert!(queue.is_empty());
        assert!(queue.pop_next().is_none());
    }

    /// 拥塞场景：视频拥塞时 drop_lowest 丢视频，键鼠/音频不动；
    /// 与 drain 循环配合保证「丢视频保键鼠/音频」。
    #[test]
    fn test_quic_congestion_drops_video_only() {
        let mut queue = PriorityQueue::with_default_capacity();
        for _ in 0..3 {
            queue.push(pkt(PacketKind::Video, 1));
        }
        queue.push(pkt(PacketKind::Audio, 2));
        queue.push(pkt(PacketKind::InputEcho, 3));

        // 拥塞触发：连续两次 drop_lowest（只丢视频）。
        assert_eq!(queue.drop_lowest(), 1);
        assert_eq!(queue.drop_lowest(), 1);
        // 视频剩 1，音频/键鼠保留。
        assert_eq!(queue.len_of(crate::transport::Priority::Video), 1);
        assert_eq!(queue.len_of(crate::transport::Priority::Audio), 1);
        assert_eq!(queue.len_of(crate::transport::Priority::Input), 1);

        // drain 后只剩音频/键鼠 + 1 视频。
        let mut got: Vec<PacketKind> = Vec::new();
        while let Some(p) = queue.pop_next() {
            got.push(p.kind);
        }
        assert_eq!(
            got,
            vec![PacketKind::InputEcho, PacketKind::Audio, PacketKind::Video]
        );
    }
}
