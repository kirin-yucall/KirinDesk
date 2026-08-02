//! 媒体 DATAGRAM 协议。
//!
//! 媒体帧的分片、加密、组装。
//! 每帧拆分为多个 DATAGRAM（~1172 字节原始数据），
//! 接收端根据 header 中的 frame_id/packet_index 重组。
//!
//! # R-04（音频接线）：DATAGRAM 头新增 kind 字节
//!
//! 音频包与视频包同走 DATAGRAM（P1F：可丢、不同优先级），接收端必须按
//! type 区分。DATAGRAM 头在既有 `frame_id/packet_index/total/flags` 基础上
//! 追加 1B `kind`（[`PacketKindWire`] 的 Video/Audio 值，0x01/0x02）：
//!
//! ```text
//! frame_id(8B LE) + packet_index(2B LE) + total_packets(2B LE) + kind(1B) + flags(2B LE) = 15B
//! ```
//!
//! - 视频：payload = NAL 分片（同旧布局，仅多 1B kind）。
//! - 音频：payload = `PacketHeader(21B) + Opus`（[`stream::frame_packet`] 产出，
//!   携带 PTS/首包标记；音频恒单 DATAGRAM，不分片）。
//!
//! [`PacketKindWire`]: crate::transport::stream::PacketKindWire
//! [`stream::frame_packet`]: crate::transport::stream::frame_packet

use crate::transport::{MediaCipher, QuicConnection, TransportError};

// ════════════════════════════════════════════════════════════════
// 常量
// ════════════════════════════════════════════════════════════════

/// QUIC DATAGRAM 最大大小（推荐 ~1200B，避免 IP 分片）。
pub const MAX_DATAGRAM_SIZE: usize = 1200;

/// AEAD 加密开销：12B nonce + 16B tag = 28 bytes。
pub const AEAD_OVERHEAD: usize = 12 + 16;

/// DATAGRAM 帧头部大小：frame_id(8B) + packet_index(2B) + total_packets(2B)
/// + kind(1B) + flags(2B) = 15B。
///
/// R-04：14B → 15B（新增 kind 字节，见[模块文档](self)）。
pub const FRAME_HEADER_SIZE: usize = 15;

// ════════════════════════════════════════════════════════════════
// FramePacket — 接收端返回的已组装帧
// ════════════════════════════════════════════════════════════════

/// 接收到的帧（已解密、已重组）。
#[derive(Debug, Clone)]
pub struct FramePacket {
    /// 帧序号（单调递增）。
    pub frame_id: u64,
    /// 标志位。
    ///   bit 0 = KEY_FRAME (IDR)
    ///   bit 1 = LAST_PACKET (最后一帧最后一片)
    ///   bit 2 = WINDOW_END (窗口边界)
    pub flags: u16,
    /// H.264 NAL 单元数据（已重组完整帧）。
    pub data: Vec<u8>,
}

// ════════════════════════════════════════════════════════════════
// 发送
// ════════════════════════════════════════════════════════════════

/// 加密并发送一帧（可能含多个 DATAGRAM 分片）。
///
/// `kind` = [`PacketKindWire`](crate::transport::stream::PacketKindWire) 的
/// wire 字节（视频 0x01 / 音频 0x02）——接收端据此分派（R-04：音频包与
/// 视频包同通道区分 type）。
pub async fn send_encrypted_frame(
    conn: &QuicConnection,
    cipher: &MediaCipher,
    frame_id: u64,
    kind: u8,
    nal_data: &[u8],
    is_key: bool,
    is_window_end: bool,
) -> Result<(), TransportError> {
    // 分片
    let max_payload = MAX_DATAGRAM_SIZE - AEAD_OVERHEAD - FRAME_HEADER_SIZE;
    let packets: Vec<&[u8]> = if nal_data.len() > max_payload {
        nal_data.chunks(max_payload).collect()
    } else {
        vec![nal_data]
    };

    let total = packets.len() as u16;
    for (i, chunk) in packets.iter().enumerate() {
        // 构建明文 payload: header (15B) + NAL data
        let flags = (if is_key { 0x01u16 } else { 0x00 })
            | (if i == total as usize - 1 { 0x02 } else { 0x00 })
            | (if is_window_end { 0x04 } else { 0x00 });

        let mut plain = Vec::with_capacity(FRAME_HEADER_SIZE + chunk.len());
        plain.extend_from_slice(&frame_id.to_le_bytes()); // 8B
        plain.extend_from_slice(&(i as u16).to_le_bytes()); // 2B
        plain.extend_from_slice(&total.to_le_bytes()); // 2B
        plain.push(kind); // 1B（R-04：视频/音频分派）
        plain.extend_from_slice(&flags.to_le_bytes()); // 2B
        plain.extend_from_slice(chunk); // NAL data / stream 帧包

        // 加密（AEAD 自动加 nonce + tag）
        let ciphertext = cipher.encrypt(&plain)?;

        // 通过 QUIC DATAGRAM 发送
        conn.send_datagram(&ciphertext).await?;
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════
// 接收
// ════════════════════════════════════════════════════════════════

/// 接收并解密一个 DATAGRAM。
///
/// 返回 `(frame_id, packet_index, total_packets, kind, flags, payload)`。
/// `kind` = [`PacketKindWire`](crate::transport::stream::PacketKindWire) wire
/// 字节——接收端按此把音频包从媒体通道中分派出来（R-04）。
pub async fn recv_encrypted_datagram(
    conn: &QuicConnection,
    cipher: &MediaCipher,
) -> Result<(u64, u16, u16, u8, u16, Vec<u8>), TransportError> {
    // 接收 DATAGRAM
    let data = conn.recv_datagram().await?;

    // 解密
    let plain = cipher.decrypt(&data)?;

    // 解析头部
    if plain.len() < FRAME_HEADER_SIZE {
        return Err(TransportError::ShortDatagram {
            got: plain.len(),
            need: FRAME_HEADER_SIZE,
        });
    }

    let frame_id = u64::from_le_bytes(plain[0..8].try_into().unwrap());
    let packet_idx = u16::from_le_bytes(plain[8..10].try_into().unwrap());
    let total = u16::from_le_bytes(plain[10..12].try_into().unwrap());
    let kind = plain[12];
    let flags = u16::from_le_bytes(plain[13..15].try_into().unwrap());
    let payload = plain[15..].to_vec();

    Ok((frame_id, packet_idx, total, kind, flags, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MediaCipher;

    fn make_test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    struct MockQuicConnection {
        packets: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl MockQuicConnection {
        fn new() -> Self {
            Self {
                packets: std::sync::Mutex::new(Vec::new()),
            }
        }

        async fn push_packet(&self, data: Vec<u8>) {
            self.packets.lock().unwrap().push(data);
        }
    }

    // Since we can't easily mock QuicConnection without its inner,
    // test the encrypt/decrypt roundtrip at the algorithm level

    #[test]
    fn test_max_payload_calculation() {
        // 1200 - 28 - 15 = 1157 bytes per datagram
        assert_eq!(MAX_DATAGRAM_SIZE, 1200);
        assert_eq!(AEAD_OVERHEAD, 28);
        assert_eq!(FRAME_HEADER_SIZE, 15);
        // max_payload for NAL data: 1200 - 28 - 15 = 1157
        let max_payload = MAX_DATAGRAM_SIZE - AEAD_OVERHEAD - FRAME_HEADER_SIZE;
        assert_eq!(max_payload, 1157);
    }

    #[test]
    fn test_datagram_encrypt_decrypt_roundtrip() {
        let cipher = MediaCipher::new(&make_test_key());
        let nal_data = vec![0xABu8; 100];
        let frame_id = 42u64;
        let kind = 0x01; // PacketKindWire::Video（R-04 kind 字节）
        let is_key = true;
        let is_window_end = false;

        // Manual: simulate send_encrypted_frame's plain building
        let max_payload = MAX_DATAGRAM_SIZE - AEAD_OVERHEAD - FRAME_HEADER_SIZE;
        let packets: Vec<&[u8]> = if nal_data.len() > max_payload {
            nal_data.chunks(max_payload).collect()
        } else {
            vec![&nal_data]
        };

        let total = packets.len() as u16;
        for (i, chunk) in packets.iter().enumerate() {
            let flags = (if is_key { 0x01u16 } else { 0x00 })
                | (if i == total as usize - 1 { 0x02 } else { 0x00 })
                | (if is_window_end { 0x04 } else { 0x00 });

            let mut plain = Vec::with_capacity(FRAME_HEADER_SIZE + chunk.len());
            plain.extend_from_slice(&frame_id.to_le_bytes());
            plain.extend_from_slice(&(i as u16).to_le_bytes());
            plain.extend_from_slice(&total.to_le_bytes());
            plain.push(kind);
            plain.extend_from_slice(&flags.to_le_bytes());
            plain.extend_from_slice(chunk);

            let ciphertext = cipher.encrypt(&plain).unwrap();

            // Simulate recv
            let decrypted = cipher.decrypt(&ciphertext).unwrap();
            assert_eq!(decrypted.len(), FRAME_HEADER_SIZE + chunk.len());

            let got_frame_id = u64::from_le_bytes(decrypted[0..8].try_into().unwrap());
            let got_idx = u16::from_le_bytes(decrypted[8..10].try_into().unwrap());
            let got_total = u16::from_le_bytes(decrypted[10..12].try_into().unwrap());
            let got_kind = decrypted[12];
            let got_flags = u16::from_le_bytes(decrypted[13..15].try_into().unwrap());
            let got_payload = &decrypted[15..];

            assert_eq!(got_frame_id, frame_id);
            assert_eq!(got_idx, i as u16);
            assert_eq!(got_total, total);
            assert_eq!(got_kind, kind, "kind byte survives roundtrip");
            assert_eq!(got_flags, flags);
            assert_eq!(got_payload, *chunk);
        }
    }

    #[test]
    fn test_datagram_multi_packet() {
        let cipher = MediaCipher::new(&make_test_key());
        // Create data larger than max_payload (1157)
        let big_nal = vec![0xCDu8; 3000];

        let max_payload = MAX_DATAGRAM_SIZE - AEAD_OVERHEAD - FRAME_HEADER_SIZE;
        let packets: Vec<&[u8]> = big_nal.chunks(max_payload).collect();
        // 3000 / 1157 → 3 chunks (1157 + 1157 + 686)
        assert_eq!(packets.len(), 3);

        let total = packets.len() as u16;
        let mut assembled = Vec::new();

        for (i, chunk) in packets.iter().enumerate() {
            let flags: u16 = (if i == total as usize - 1 { 0x02 } else { 0x00 });

            let mut plain = Vec::with_capacity(FRAME_HEADER_SIZE + chunk.len());
            plain.extend_from_slice(&0u64.to_le_bytes());
            plain.extend_from_slice(&(i as u16).to_le_bytes());
            plain.extend_from_slice(&total.to_le_bytes());
            plain.push(0x01);
            plain.extend_from_slice(&flags.to_le_bytes());
            plain.extend_from_slice(chunk);

            let ciphertext = cipher.encrypt(&plain).unwrap();
            let decrypted = cipher.decrypt(&ciphertext).unwrap();

            let got_kind = decrypted[12];
            let got_flags = u16::from_le_bytes(decrypted[13..15].try_into().unwrap());
            let payload = &decrypted[15..];
            assembled.extend_from_slice(payload);

            // Last packet has LAST_PACKET flag
            if i == total as usize - 1 {
                assert_eq!(got_flags & 0x02, 0x02);
            }
            assert_eq!(got_kind, 0x01);
        }

        assert_eq!(assembled.len(), 3000);
        assert_eq!(assembled, big_nal);
    }
}
