//! 媒体 DATAGRAM 协议。
//!
//! 媒体帧的分片、加密、组装。
//! 每帧拆分为多个 DATAGRAM（~1172 字节原始数据），
//! 接收端根据 header 中的 frame_id/packet_index 重组。

use crate::transport::{MediaCipher, QuicConnection, TransportError};

// ════════════════════════════════════════════════════════════════
// 常量
// ════════════════════════════════════════════════════════════════

/// QUIC DATAGRAM 最大大小（推荐 ~1200B，避免 IP 分片）。
pub const MAX_DATAGRAM_SIZE: usize = 1200;

/// AEAD 加密开销：12B nonce + 16B tag = 28 bytes。
pub const AEAD_OVERHEAD: usize = 12 + 16;

/// DATAGRAM 帧头部大小：frame_id(8B) + packet_index(2B) + total_packets(2B) + flags(2B) = 14B。
pub const FRAME_HEADER_SIZE: usize = 14;

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
pub async fn send_encrypted_frame(
    conn: &QuicConnection,
    cipher: &MediaCipher,
    frame_id: u64,
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
        // 构建明文 payload: header (14B) + NAL data
        let flags = (if is_key { 0x01u16 } else { 0x00 })
            | (if i == total as usize - 1 { 0x02 } else { 0x00 })
            | (if is_window_end { 0x04 } else { 0x00 });

        let mut plain = Vec::with_capacity(FRAME_HEADER_SIZE + chunk.len());
        plain.extend_from_slice(&frame_id.to_le_bytes()); // 8B
        plain.extend_from_slice(&(i as u16).to_le_bytes()); // 2B
        plain.extend_from_slice(&total.to_le_bytes()); // 2B
        plain.extend_from_slice(&flags.to_le_bytes()); // 2B
        plain.extend_from_slice(chunk); // NAL data

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
/// 返回 `(frame_id, packet_index, total_packets, flags, payload)`。
pub async fn recv_encrypted_datagram(
    conn: &QuicConnection,
    cipher: &MediaCipher,
) -> Result<(u64, u16, u16, u16, Vec<u8>), TransportError> {
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
    let flags = u16::from_le_bytes(plain[12..14].try_into().unwrap());
    let payload = plain[14..].to_vec();

    Ok((frame_id, packet_idx, total, flags, payload))
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
        // 1200 - 28 - 14 = 1158 bytes per datagram
        assert_eq!(MAX_DATAGRAM_SIZE, 1200);
        assert_eq!(AEAD_OVERHEAD, 28);
        assert_eq!(FRAME_HEADER_SIZE, 14);
        // max_payload for NAL data: 1200 - 28 - 14 = 1158
        let max_payload = MAX_DATAGRAM_SIZE - AEAD_OVERHEAD - FRAME_HEADER_SIZE;
        assert_eq!(max_payload, 1158);
    }

    #[test]
    fn test_datagram_encrypt_decrypt_roundtrip() {
        let cipher = MediaCipher::new(&make_test_key());
        let nal_data = vec![0xABu8; 100];
        let frame_id = 42u64;
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
            plain.extend_from_slice(&flags.to_le_bytes());
            plain.extend_from_slice(chunk);

            let ciphertext = cipher.encrypt(&plain).unwrap();

            // Simulate recv
            let decrypted = cipher.decrypt(&ciphertext).unwrap();
            assert_eq!(decrypted.len(), FRAME_HEADER_SIZE + chunk.len());

            let got_frame_id = u64::from_le_bytes(decrypted[0..8].try_into().unwrap());
            let got_idx = u16::from_le_bytes(decrypted[8..10].try_into().unwrap());
            let got_total = u16::from_le_bytes(decrypted[10..12].try_into().unwrap());
            let got_flags = u16::from_le_bytes(decrypted[12..14].try_into().unwrap());
            let got_payload = &decrypted[14..];

            assert_eq!(got_frame_id, frame_id);
            assert_eq!(got_idx, i as u16);
            assert_eq!(got_total, total);
            assert_eq!(got_flags, flags);
            assert_eq!(got_payload, *chunk);
        }
    }

    #[test]
    fn test_datagram_multi_packet() {
        let cipher = MediaCipher::new(&make_test_key());
        // Create data larger than max_payload (1158)
        let big_nal = vec![0xCDu8; 3000];

        let max_payload = MAX_DATAGRAM_SIZE - AEAD_OVERHEAD - FRAME_HEADER_SIZE;
        let packets: Vec<&[u8]> = big_nal.chunks(max_payload).collect();
        // 3000 / 1158 → 3 chunks (1158 + 1158 + 684)
        assert_eq!(packets.len(), 3);

        let total = packets.len() as u16;
        let mut assembled = Vec::new();

        for (i, chunk) in packets.iter().enumerate() {
            let flags: u16 = (if i == total as usize - 1 { 0x02 } else { 0x00 });

            let mut plain = Vec::with_capacity(FRAME_HEADER_SIZE + chunk.len());
            plain.extend_from_slice(&0u64.to_le_bytes());
            plain.extend_from_slice(&(i as u16).to_le_bytes());
            plain.extend_from_slice(&total.to_le_bytes());
            plain.extend_from_slice(&flags.to_le_bytes());
            plain.extend_from_slice(chunk);

            let ciphertext = cipher.encrypt(&plain).unwrap();
            let decrypted = cipher.decrypt(&ciphertext).unwrap();

            let got_flags = u16::from_le_bytes(decrypted[12..14].try_into().unwrap());
            let payload = &decrypted[14..];
            assembled.extend_from_slice(payload);

            // Last packet has LAST_PACKET flag
            if i == total as usize - 1 {
                assert_eq!(got_flags & 0x02, 0x02);
            }
        }

        assert_eq!(assembled.len(), 3000);
        assert_eq!(assembled, big_nal);
    }
}
