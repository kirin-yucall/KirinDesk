//! TCP(SecureChannel) 媒体传输 —— M8-T025 P4：TCP 优雅降级（tcp_fallback.rs）。
//!
//! 实现 [`MediaTransport`] trait 的 TCP 版本 [`TcpMediaTransport`]：给定一条
//! **已握手**的 [`SecureChannel`]（core 侧 TCP+AEAD 通道）即可完成全部媒体
//! 收发。复用 [`SecureChannelTransport`]（`transport.rs` §P1F）的 tag 分派与
//! 成帧（`stream::frame_packet`），**不做 wire 协议扩展**，与既有
//! SecureChannel 阶段字节流完全兼容。
//!
//! # 边界（M8-T025 §并行契约）
//!
//! - **不实现中途降级逻辑**（那是 P5 会话层职责）；本模块只保证：给定一条
//!   已握手的 SecureChannel → 可作为 `MediaTransport` 完成媒体收发。
//! - 媒体帧复用 `PacketHeader` + `ChannelTag` 分派；控制消息以 tag=Control
//!   的包承载（bincode 序列化，与接收侧 `recv_control` 对称解析）。
//! - 与 P2 的关系：不依赖 `TcpClient`（集成测试自建 listener）；P5 建连工厂
//!   才用 P2 的 `SocketAddr` 签名。

use std::time::Instant;

use async_trait::async_trait;
use tracing::{debug, warn};

use kirin_desk_core::crypto::handshake::SecureChannel;

use crate::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use crate::proto::EncodedWindow;
use crate::transport::{
    stream::{ChannelTag, FLAG_INCREMENTAL, FLAG_KEY, MAX_PACKET_PAYLOAD},
    transport::concat_nal_packets,
    ControlMessage, FramePacket, MediaTransport, SecureChannelReceiver, SecureChannelSender,
    SecureChannelTransport, TransportError, TransportMode,
};

/// TCP(SecureChannel) 媒体传输。给定已握手的 SecureChannel 构造。
pub struct TcpMediaTransport {
    inner: SecureChannelTransport,
    audio_tx: Option<std::sync::mpsc::SyncSender<crate::decoder::AudioPacket>>,
    audio_rx: Option<std::sync::mpsc::Receiver<crate::decoder::AudioPacket>>,
    audio_buffering: bool,
    /// （客户端空闲看门狗用）。TCP 模式控制包与媒体包同流，`recv_frame` 的
    /// `recv_tagged` 会消费它们，故服务端 keepalive（Heartbeat）在此可见——
    /// 静态屏幕（无视频帧）下看门狗不会误判 lost。
    last_rx: Option<std::time::Instant>,
    /// 未知/空 → H.264 兜底，兼容旧对端）。
    negotiated: crate::encoder::Codec,
}

impl TcpMediaTransport {
    /// 包装已握手的 SecureChannel（对称 transport.rs 的 SecureChannelTransport::new）。
    pub fn new(channel: SecureChannel) -> Self {
        let negotiated = crate::encoder::Codec::from_str(&channel.selected_codec)
            .unwrap_or(crate::encoder::Codec::H264);
        // 丢新保旧——消费者卡住时不再无界增长，且 recv 路径永不阻塞。
        let (audio_tx, audio_rx) = super::new_audio_packet_channel();
        Self {
            inner: SecureChannelTransport::new(channel),
            audio_tx: Some(audio_tx),
            audio_rx: Some(audio_rx),
            audio_buffering: false,
            last_rx: None,
            negotiated,
        }
    }

    /// 从泛型握手结果（`SecureChannelGeneric<TcpStream>`）构造——P5 建连工厂 /
    /// 服务端降级接收共用（字段一一对应，与 transport.rs 既有转换一致）。
    pub fn from_generic(
        ch: kirin_desk_core::crypto::handshake::SecureChannelGeneric<tokio::net::TcpStream>,
    ) -> Self {
        Self::new(SecureChannel {
            stream: ch.stream,
            cipher: ch.cipher,
            peer_id: ch.peer_id,
            peer_domain: ch.peer_domain,
            peer_device_type: ch.peer_device_type,
            selected_codec: ch.selected_codec,
            peer_os: ch.peer_os,
        })
    }

    /// 拆出**写半**（发送半通道），本传输保留读半（接收媒体帧）。
    ///
    /// P5 会话层用：客户端反馈 task 独占写半（send_control），主循环保留读半
    /// （recv_frame）。拆出后本传输不再能 send_*（返回 `ConnectionClosed`）。
    pub fn take_sender(&mut self) -> Option<SecureChannelSender> {
        self.inner.take_sender()
    }

    /// 拆出**读半**（接收半通道），本传输保留写半（发送媒体/控制）。
    ///
    /// P5 会话层用：服务端控制 task 独占读半（recv_control），主循环保留写半
    /// （send_window / send_control）。拆出后本传输不再能 recv_*。
    pub fn take_receiver(&mut self) -> Option<SecureChannelReceiver> {
        self.inner.take_receiver()
    }
}

#[async_trait]
impl MediaTransport for TcpMediaTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::Tcp
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }

    fn negotiated_codec(&self) -> crate::encoder::Codec {
        self.negotiated
    }

    // SecureChannel 阶段字节流完全兼容，接收侧 recv_tagged 按 tag 分派）。
    async fn send_audio(&mut self, pkts: &[EncodedPacket]) -> Result<(), TransportError> {
        self.inner.send_packets(pkts).await
    }

    fn take_audio_receiver(&mut self) -> Option<std::sync::mpsc::Receiver<crate::decoder::AudioPacket>> {
        // 启用音频缓冲（recv_frame 据此分流）；再次调用返回 None（已取出）。
        let rx = self.audio_rx.take()?;
        self.audio_buffering = true;
        Some(rx)
    }

    async fn send_window(&mut self, window: &EncodedWindow) -> Result<(), TransportError> {
        if window.is_empty() {
            return Ok(());
        }
        let window_id = window.window_id;

        // 逐帧 concat NAL → EncodedPacket（kind=Video，首帧 is_key=true，
        // pts=frame 序）。frame_id 由 SecureChannelSender 内部单调计数分配
        // （复用其包构造，不做第二套帧号源）。
        //
        // 超 MAX_PACKET_PAYLOAD 的帧走 send_big_packet（SecureChannel 4B 长度
        // 前缀，无小帧限制）；其余帧批量 send_packets。两种路径 wire 格式一致
        // （tag || header || payload），接收侧 recv_tagged 对称解析。
        let mut batch: Vec<EncodedPacket> = Vec::with_capacity(window.frames.len());
        for (idx, nal_packets) in window.frames.iter().enumerate() {
            let nal_data = concat_nal_packets(nal_packets);
            let pkt = EncodedPacket {
                ts: Timestamp::new(Instant::now(), idx as u64),
                kind: PacketKind::Video,
                data: nal_data,
                is_key: idx == 0,
            };
            if pkt.data.len() > MAX_PACKET_PAYLOAD {
                if !batch.is_empty() {
                    self.inner.send_packets(&batch).await?;
                    batch.clear();
                }
                self.inner.send_big_packet(&pkt).await?;
            } else {
                batch.push(pkt);
            }
        }
        if !batch.is_empty() {
            self.inner.send_packets(&batch).await?;
        }

        debug!(
            "TcpMediaTransport: send_window: window_id={}, {} frames sent",
            window_id, window.frame_count
        );
        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<FramePacket, TransportError> {
        loop {
            let (tag, header, payload) = self.inner.recv_tagged().await?;
            // 空闲看门狗时间戳（客户端 session 经 `last_recv_any` 读取）。
            self.last_rx = Some(std::time::Instant::now());
            match tag {
                ChannelTag::Video => {
                    // TCP 无分片/乱序 → 不经过 reassembly，直接组装。
                    return Ok(FramePacket {
                        frame_id: header.frame_id as u64,
                        flags: (header.flags & (FLAG_KEY | FLAG_INCREMENTAL)) as u16,
                        data: payload,
                    });
                }
                ChannelTag::Audio => {
                    // 未启用（take_audio_receiver 未被调用）→ 丢弃，不缓冲。
                    let pkt = crate::decoder::AudioPacket {
                        pts: header.pts,
                        data: payload,
                    };
                    if self.audio_buffering {
                        if let Some(tx) = &self.audio_tx {
                            // 已记），接收路径永不阻塞；接收端已关闭（会话
                            // 结束）→ 停止缓冲。
                            if super::try_enqueue_audio_packet(tx, pkt)
                                == super::AudioEnqueue::Disconnected
                            {
                                self.audio_buffering = false;
                            }
                        }
                    }
                    continue;
                }
                ChannelTag::Control => {
                    // keepalive 等）与媒体同流到达。客户端会话主循环不读
                    // 控制路径（与 QUIC 一致，见 session.rs 看门狗注释），
                    // 此处消费即弃；到达时刻已在上方记录（看门狗据此判定
                    // 对端存活）。日志降为 debug——静态屏幕下每 3s 一个，
                    // 若用 warn 会刷屏。
                    debug!(
                        "TcpMediaTransport: control packet in media stream (e.g. keepalive) — consumed"
                    );
                }
                other => {
                    // 方向性错误：媒体接收路径收到 Input 等非媒体 tag →
                    // 丢弃并继续（与 recv_input_payload 同款策略）。
                    warn!(
                        "TcpMediaTransport: expected Video tag, got {:?}; dropping",
                        other
                    );
                    continue;
                }
            }
        }
    }

    async fn send_control(&mut self, msg: &ControlMessage) -> Result<(), TransportError> {
        // bincode 序列化 → tag=Control 的包走 send_packets 单包（wire 格式与
        // SecureChannel 阶段既有 Control 消息一致，接收侧 recv_control 对称解析）。
        let plain = bincode::serialize(msg)
            .map_err(|e| TransportError::SecureChannel(format!("bincode serialize: {e}")))?;
        let pkt = EncodedPacket {
            ts: Timestamp::now(),
            kind: PacketKind::Control,
            data: plain,
            is_key: false,
        };
        // 异常超大控制消息（如巨型显示器列表）→ 大帧路径兜底；wire 格式不变。
        if pkt.data.len() > MAX_PACKET_PAYLOAD {
            self.inner.send_big_packet(&pkt).await
        } else {
            self.inner.send_packets(&[pkt]).await
        }
    }

    async fn recv_control(&mut self) -> Result<ControlMessage, TransportError> {
        loop {
            let (tag, _header, payload) = self.inner.recv_tagged().await?;
            self.last_rx = Some(std::time::Instant::now());
            match tag {
                ChannelTag::Control => {
                    return bincode::deserialize(&payload).map_err(|e| {
                        TransportError::SecureChannel(format!("bincode deserialize: {e}"))
                    });
                }
                other => {
                    // 方向性错误：控制接收路径收到媒体 tag → 丢弃并继续。
                    warn!(
                        "TcpMediaTransport: expected Control tag, got {:?}; dropping",
                        other
                    );
                    continue;
                }
            }
        }
    }

    fn is_alive(&self) -> bool {
        // TCP 连接存活由内核/读错误体现；读错误在 recv_* 返回 Err 时暴露。
        // 中途断链检测依赖 recv_* 错误或 P5 心跳，不由本方法承担。
        true
    }

    fn rtt(&self) -> u64 {
        // 无 QUIC stats；P5 的 TCP 自适应分支不消费 RTT 决策。
        0
    }

    fn last_recv_any(&self) -> Option<std::time::Instant> {
        self.last_rx
    }

    async fn close(self: Box<Self>) -> Result<(), TransportError> {
        // drop inner → SecureChannel 关闭（TCP FIN）。
        drop(self.inner);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::types::PacketKind;
    use kirin_desk_core::crypto::ed25519::IdentityManager;
    use kirin_desk_core::crypto::handshake as core_handshake;
    use std::time::Duration;
    use tokio::net::TcpListener;

    /// 构造一对已握手的 TcpMediaTransport（本机回环）。
    ///
    /// 服务端用 `server_handshake_verified_generic`（白名单接受），
    /// 客户端用 `client_handshake_generic`，经 TCP 流适配，再各自包装为
    /// [`TcpMediaTransport`]（对照 transport.rs:666-735 既有测试基建）。
    async fn make_transport_pair() -> (TcpMediaTransport, TcpMediaTransport) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_id = "test-server-device".to_string();
        let client_id = "test-client-device".to_string();
        let tmp = std::env::temp_dir();
        let server_im =
            IdentityManager::generate(tmp.join(format!("kirin_tcp_s_{server_id}.key")))
                .expect("generate server identity");
        let client_im =
            IdentityManager::generate(tmp.join(format!("kirin_tcp_c_{client_id}.key")))
                .expect("generate client identity");
        let server_pub = server_im.public_key_base64();
        let client_pub = client_im.public_key_base64();

        let server_id_for_task = server_id.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
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
            kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&server_pub).expect("server pubkey"),
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
            peer_os: server_generic.peer_os,
        };
        let real_client_ch = SecureChannel {
            stream: client_ch.stream,
            cipher: client_ch.cipher,
            peer_id: client_ch.peer_id,
            peer_domain: client_ch.peer_domain,
            peer_device_type: client_ch.peer_device_type,
            selected_codec: client_ch.selected_codec,
            peer_os: client_ch.peer_os,
        };
        (
            TcpMediaTransport::new(server_ch),
            TcpMediaTransport::new(real_client_ch),
        )
    }

    fn make_packet(kind: PacketKind, data: Vec<u8>, is_key: bool) -> EncodedPacket {
        EncodedPacket {
            ts: Timestamp::new(Instant::now(), 0),
            kind,
            data,
            is_key,
        }
    }

    /// 构造一个窗口：每帧单个 NAL 包。
    fn make_window(window_id: u64, frame_data: Vec<Vec<u8>>) -> EncodedWindow {
        EncodedWindow::new(
            window_id,
            320,
            240,
            frame_data.into_iter().map(|f| vec![f]).collect(),
        )
    }

    /// `mode() == Tcp`；既有实现（QuicMediaTransport）依赖的默认方法返回 Quic。
    #[tokio::test]
    async fn test_mode_returns_tcp() {
        let (server, _client) = make_transport_pair().await;
        assert_eq!(server.mode(), TransportMode::Tcp);

        // 默认方法契约：不覆写 mode() 的实现默认返回 Quic（QuicMediaTransport
        // 零改动依赖此默认值；本 stub 即代表既有实现）。
        struct DefaultModeStub;
        #[async_trait]
        impl MediaTransport for DefaultModeStub {
            async fn send_window(
                &mut self,
                _window: &EncodedWindow,
            ) -> Result<(), TransportError> {
                Ok(())
            }
            async fn recv_frame(&mut self) -> Result<FramePacket, TransportError> {
                unreachable!("stub")
            }
            async fn send_control(
                &mut self,
                _msg: &ControlMessage,
            ) -> Result<(), TransportError> {
                Ok(())
            }
            async fn recv_control(&mut self) -> Result<ControlMessage, TransportError> {
                unreachable!("stub")
            }
            fn is_alive(&self) -> bool {
                true
            }
            fn rtt(&self) -> u64 {
                0
            }
            async fn close(self: Box<Self>) -> Result<(), TransportError> {
                Ok(())
            }
        }
        assert_eq!(DefaultModeStub.mode(), TransportMode::Quic);
    }

    /// 回环：send_window(2 帧) → recv_frame ×2 → 数据一致、is_key 正确
    /// （首个 true/次个 false）、frame_id 单调。
    #[tokio::test]
    async fn test_send_window_recv_frame_roundtrip() {
        let (mut server, mut client) = make_transport_pair().await;

        let window = make_window(7, vec![vec![0xAA; 100], vec![0xBB; 64]]);
        server.send_window(&window).await.expect("send window");

        let f1 = client.recv_frame().await.expect("recv frame 1");
        assert_eq!(f1.data, vec![0xAA; 100]);
        assert_ne!(f1.flags & FLAG_KEY as u16, 0, "first frame is key");

        let f2 = client.recv_frame().await.expect("recv frame 2");
        assert_eq!(f2.data, vec![0xBB; 64]);
        assert_eq!(f2.flags & FLAG_KEY as u16, 0, "second frame is incremental");

        assert!(f2.frame_id > f1.frame_id, "frame_id monotonic");
    }

    /// 回环：> MAX_PACKET_PAYLOAD 帧 → send_big_packet 路径收发一致。
    #[tokio::test]
    async fn test_send_window_large_frame() {
        let (mut server, mut client) = make_transport_pair().await;

        let big = vec![0xCD; MAX_PACKET_PAYLOAD + 1000];
        let window = make_window(8, vec![vec![0x11; 32], big.clone(), vec![0x22; 16]]);
        server.send_window(&window).await.expect("send window");

        let f1 = client.recv_frame().await.expect("recv frame 1");
        assert_eq!(f1.data, vec![0x11; 32]);
        assert_ne!(f1.flags & FLAG_KEY as u16, 0, "first frame is key");

        let f2 = client.recv_frame().await.expect("recv big frame");
        assert_eq!(f2.data, big);
        assert_eq!(f2.flags & FLAG_KEY as u16, 0, "big frame is incremental");

        let f3 = client.recv_frame().await.expect("recv frame 3");
        assert_eq!(f3.data, vec![0x22; 16]);
        assert!(f3.frame_id > f2.frame_id, "frame_id monotonic");
    }

    /// 全部 ControlMessage 变体往返一致。
    #[tokio::test]
    async fn test_control_roundtrip() {
        use crate::proto::DisplayInfo;
        use kirin_desk_core::connection::privacy::PrivacyLevel;

        let (mut server, mut client) = make_transport_pair().await;

        let msgs: Vec<ControlMessage> = vec![
            ControlMessage::AdaptiveConfig {
                qp: 28,
                frame_ratio: 0.5,
                force_idr: true,
            },
            ControlMessage::FeedbackReport {
                loss_rate: 0.03,
                rtt_ms: 45,
                received_bitrate: 2_500_000,
                frame_id: 1024,
                missing_frames: vec![1010, 1015],
            },
            ControlMessage::CodecNegotiation {
                supported_codecs: vec!["h264".into(), "h265_qsv".into()],
                selected_codec: Some("h264".into()),
            },
            ControlMessage::VideoFormat {
                width: 1920,
                height: 1080,
            },
            ControlMessage::DisplayListReq,
            ControlMessage::DisplayListResp {
                displays: vec![DisplayInfo {
                    index: 0,
                    name: "\\\\.\\DISPLAY1".into(),
                    width: 1920,
                    height: 1080,
                    is_primary: true,
                }],
            },
            ControlMessage::DisplaySelect { index: 1 },
            ControlMessage::DisplaySelectNack {
                reason: "invalid monitor index 9".into(),
            },
            ControlMessage::Heartbeat { timestamp_ms: 12345 },
            ControlMessage::WindowAck {
                window_id: 42,
                decoded_frames: 7,
                decode_duration_ms: 12.5,
            },
            ControlMessage::PrivacyMode {
                level: PrivacyLevel::Black,
                on: true,
            },
            ControlMessage::PrivacyModeAck {
                ok: true,
                active_level: Some(PrivacyLevel::Lock),
            },
            ControlMessage::Disconnect {
                reason: "bye".into(),
            },
        ];

        for msg in &msgs {
            server.send_control(msg).await.expect("send control");
        }
        for msg in &msgs {
            let got = client.recv_control().await.expect("recv control");
            assert_eq!(&got, msg);
        }
    }

    /// 干扰）；未启用音频时丢弃。
    #[tokio::test]
    async fn test_wrong_tag_dropped() {
        let (mut server, mut client) = make_transport_pair().await;

        // 服务端先发 Audio（客户端 recv_frame 应转入音频通道），再发两个 Video。
        server
            .inner
            .send_packets(&[
                make_packet(PacketKind::Audio, vec![0xEE; 16], true),
                make_packet(PacketKind::Video, vec![0x11; 32], true),
                make_packet(PacketKind::Video, vec![0x22; 32], false),
            ])
            .await
            .expect("send packets");

        // 未启用音频（take_audio_receiver 未被调用）→ 音频包被丢弃，视频照常。
        let f1 = client.recv_frame().await.expect("recv frame 1");
        assert_eq!(f1.data, vec![0x11; 32]);

        let f2 = client.recv_frame().await.expect("recv frame 2");
        assert_eq!(f2.data, vec![0x22; 32]);

        // 启用音频 → 音频包进入缓冲通道（PTS/数据完整），视频仍照常返回。
        let (mut server2, mut client2) = make_transport_pair().await;
        let audio_rx = client2.take_audio_receiver().expect("audio receiver");
        server2
            .inner
            .send_packets(&[
                make_packet(PacketKind::Audio, vec![0xEE; 16], true),
                make_packet(PacketKind::Video, vec![0x33; 32], true),
            ])
            .await
            .expect("send packets");

        let v = client2.recv_frame().await.expect("recv video");
        assert_eq!(v.data, vec![0x33; 32], "video unaffected by audio dispatch");

        // 音频包经缓冲通道可消费（std mpsc，会话侧 AudioDecodePipeline 读取）。
        let audio = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match audio_rx.recv() {
                    Ok(p) => return p,
                    Err(_) => panic!("audio channel closed unexpectedly"),
                }
            }
        })
        .await
        .expect("audio packet should arrive");
        assert_eq!(audio.data, vec![0xEE; 16]);
    }

    /// close 后对端 recv 返回错误（TCP FIN 传播）。
    #[tokio::test]
    async fn test_close() {
        let (server, mut client) = make_transport_pair().await;

        Box::new(server).close().await.expect("close");

        // drop 传播异步（TCP FIN）→ 带时限等待对端读错误。
        let result = tokio::time::timeout(Duration::from_secs(5), client.recv_frame()).await;
        match result {
            Ok(Err(_)) => {} // 期望：对端已关闭 → 读错误
            Ok(Ok(frame)) => panic!("expected error after close, got frame {frame:?}"),
            Err(_) => panic!("recv_frame did not error after close (timeout)"),
        }
    }
}
