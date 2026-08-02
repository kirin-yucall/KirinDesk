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
    ControlMessage, FramePacket, LossDetector, LossStats, MediaCipher, QuicConnection,
    QuicEndpoint, TransportError,
};

use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake as core_handshake;
use kirin_desk_core::crypto::handshake::{SecureChannel, SecureChannelReader, SecureChannelWriter};

// ════════════════════════════════════════════════════════════════
// QuicMediaTransport
// ════════════════════════════════════════════════════════════════

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
}

impl QuicMediaTransport {
    /// 创建新的 QUIC 媒体传输。
    pub fn new(conn: QuicConnection, cipher: MediaCipher) -> Self {
        Self {
            conn,
            cipher: Arc::new(cipher),
            frame_id_counter: 0,
            reassembly: FrameReassembly::new(),
            loss_detector: Arc::new(std::sync::Mutex::new(LossDetector::default())),
            control_sender: None,
            control_receiver: None,
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
    /// - 视频/音频：打成 `PacketHeader + payload` → AEAD 加密 → DATAGRAM。
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
                // 视频/音频：DATAGRAM。明文 framed 经 AEAD 加密 → 单个 DATAGRAM。
                let ciphertext = self.cipher.encrypt(&framed)?;
                self.conn.send_datagram(&ciphertext).await?;
                Ok(())
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

            let (frame_id, packet_idx, total, flags, payload) = datagram;
            debug!(
                "recv_frame_inner: dg frame_id={} pkt={}/{} flags={:#06x} payload={}B",
                frame_id,
                packet_idx,
                total,
                flags,
                payload.len()
            );

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

    let (ctrl_send, ctrl_recv) = conn.open_bi().await?;
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
    _server_pubkey_base64: &str,
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
        _server_pubkey_base64,
        challenge,
    )
    .await
    .map_err(|e| TransportError::Handshake(e.to_string()))?;

    let (ctrl_send, ctrl_recv) = conn.accept_bi().await?;
    let mut transport = QuicMediaTransport::new(conn, MediaCipher::new_from_aead(ch.cipher));
    transport.set_control_streams(ctrl_send, ctrl_recv);

    debug!("connect_quic_transport: ready to {addr}");
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
    sender: SecureChannelSender,
    receiver: SecureChannelReceiver,
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
            sender: SecureChannelSender::new(writer),
            receiver: SecureChannelReceiver::new(reader),
        }
    }

    /// 拆分为独立的发送/接收半传输（M9：双任务并发场景，各方向单任务独占）。
    pub fn into_split(self) -> (SecureChannelReceiver, SecureChannelSender) {
        (self.receiver, self.sender)
    }

    /// 发送一批 EncodedPacket（委托给发送半传输）。
    pub async fn send_packets(&mut self, pkts: &[EncodedPacket]) -> Result<(), TransportError> {
        self.sender.send_packets(pkts).await
    }

    /// 接收一帧（任意 tag，委托给接收半传输）。
    pub async fn recv_tagged(
        &mut self,
    ) -> Result<(ChannelTag, PacketHeader, Vec<u8>), TransportError> {
        self.receiver.recv_tagged().await
    }

    /// 接收一条键鼠事件 wire bytes（委托给接收半传输）。
    pub async fn recv_input_payload(&mut self) -> Result<Vec<u8>, TransportError> {
        self.receiver.recv_input_payload().await
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
            &server_pub,
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
