//! EncodedPacket 网络帧封装（P1F §T6.1）。
//!
//! 把 [`crate::encoder::types::EncodedPacket`]（视频/音频/键鼠回声）打包为
//! 带 **Annex B 自定义头** 的字节流，供两条传输栈分派：
//!
//! - **SecureChannel 阶段**：单条 TCP 通道复用，前缀字节（[`ChannelTag`]）
//!   区分 Video/Audio/InputEcho/Control。客户端按 tag 分发到对应 handler。
//! - **QUIC 阶段**：按 [`QuicKind`] 分通道——视频/音频走 DATAGRAM（可丢，
//!   不同优先级），键鼠走可靠流（不丢，最高优先级）。
//!
//! # 帧头格式（大端序，固定 17 字节）
//!
//! ```text
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | magic(2)  | ver(1) | kind(1) | flags(1)| frame_id(4)                  |
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | pts(8)                                                              |
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | payload_len(4)                                                      |
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | payload...                                                          |
//! ```
//!
//! # 关键约束
//!
//! - `pts` = 会话相对毫秒（源自统一 [`Timestamp`]，不引入 NTP）。
//! - 键鼠/音频**必须 ≤ DATAGRAM 上限**（单包）；视频超上限 → 分片（复用
//!   [`crate::transport::reassembly`]/[`crate::transport::datagram`]）。
//! - 首包含 extradata（flags bit2）→ 客户端初始化解码器（P1C 已保证）。
//! - `frame_id` 回绕（u32）→ 可靠流无乱序；DATAGRAM 靠重组。
//!
//! [`Timestamp`]: crate::encoder::types::Timestamp

use crate::encoder::types::{EncodedPacket, PacketKind};
use crate::transport::datagram::{AEAD_OVERHEAD, MAX_DATAGRAM_SIZE};

// ════════════════════════════════════════════════════════════════
// 常量
// ════════════════════════════════════════════════════════════════

/// 帧头魔数 `"KD"`（0x4B44），用于快速识别本协议帧。
pub const HEADER_MAGIC: u16 = 0x4B44;

/// 帧头协议版本（当前 1）。
pub const HEADER_VERSION: u8 = 1;

/// 帧头固定字节数：magic(2) + version(1) + kind(1) + flags(1)
/// + frame_id(4) + pts(8) + payload_len(4) = 21 字节。
///
/// 注意：设计文档（T6.1）描述「17B」基于旧布局；本实现按字段实际累加
/// 得 21B（pts 为 8B 会话毫秒，frame_id/payload_len 各 4B）。常量以字段
/// 实际大小为准，测试同时以本常量校验，保证编/解码对称。
pub const HEADER_SIZE: usize = 2 + 1 + 1 + 1 + 4 + 8 + 4;

/// flags 位：bit0 = IDR 关键帧（视频）/ 会话首包（音频）。
pub const FLAG_KEY: u8 = 1 << 0;
/// flags 位：bit1 = 增量（RLE）数据。
pub const FLAG_INCREMENTAL: u8 = 1 << 1;
/// flags 位：bit2 = 携带 extradata（解码器初始化用）。
pub const FLAG_EXTRADATA: u8 = 1 << 2;

/// DATAGRAM 上限（明文负载最大字节数）。
///
/// = [`MAX_DATAGRAM_SIZE`] − [`AEAD_OVERHEAD`] − [`HEADER_SIZE`]。
/// 键鼠/音频单包必须 ≤ 此值；视频超过则走 DATAGRAM 分片（reassembly）。
pub const MAX_PACKET_PAYLOAD: usize = MAX_DATAGRAM_SIZE
    .saturating_sub(AEAD_OVERHEAD)
    .saturating_sub(HEADER_SIZE);

/// 文件传输单帧明文负载上限（M13-T006）。
///
/// 与 core 侧 [`Multiplexer::DEFAULT_MAX_FRAME_LEN`]（16 MiB）对齐的概念上限；
/// 文件块（64 KiB）经 SecureChannel 大帧直接发送，**不**走本文件 1151B
/// 小分片路径（[`frame_packet`] 的 `MAX_PACKET_PAYLOAD` 检查）。
pub const MAX_FILE_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

// ════════════════════════════════════════════════════════════════
// PacketHeader
// ════════════════════════════════════════════════════════════════

/// EncodedPacket 网络帧头（Annex B 裸流 + 自定义头）。
///
/// 大端序固定布局，[`HEADER_SIZE`] 字节。详见[模块文档](self)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// 魔数，固定 [`HEADER_MAGIC`]（0x4B44）。
    pub magic: u16,
    /// 协议版本，当前 [`HEADER_VERSION`]（1）。
    pub version: u8,
    /// 包类型 → wire byte（[`PacketKindWire`]）。
    pub kind: PacketKindWire,
    /// 标志位：bit0=KEY、bit1=INCREMENTAL、bit2=EXTRADATA。
    pub flags: u8,
    /// 单调递增帧号（客户端去重/排序）。会话内单调；u32 回绕后由重组/可靠流处理。
    pub frame_id: u32,
    /// 会话相对毫秒 PTS（源自统一 [`Timestamp`]）。
    ///
    /// [`Timestamp`]: crate::encoder::types::Timestamp
    pub pts: u64,
    /// 负载字节数（Annex B 码流 / Opus / RLE 数据）。
    pub payload_len: u32,
}

/// wire 上的包类型字节（与 [`PacketKind`] 双向映射）。
///
/// 选用显式 `u8` wire 编码而非 `repr(u8)` enum，避免 ABI 耦合、便于
/// SecureChannel/QUIC 共用同一前缀语义（与 [`ChannelTag`] 对齐）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKindWire {
    /// 视频（Annex B）。
    Video = 0x01,
    /// 音频（Opus）。
    Audio = 0x02,
    /// 键鼠回声（可靠流镜像）。
    InputEcho = 0x03,
    /// 剪贴板文本（UTF-8，M13-T003）。
    Clipboard = 0x05,
    /// 文件传输帧（bincode [`FileTransferFrame`]，M13-T006）。
    FileTransfer = 0x06,
    /// 显示器/隐私等控制消息（bincode [`ControlMessage`]，M8-T018；
    /// 0x04 与 [`ChannelTag::Control`] 对齐，SecureChannel 路径 tag 分帧）。
    Control = 0x04,
}

impl PacketKindWire {
    /// wire byte → enum；未知值返回 `None`。
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Video),
            0x02 => Some(Self::Audio),
            0x03 => Some(Self::InputEcho),
            0x04 => Some(Self::Control),
            0x05 => Some(Self::Clipboard),
            0x06 => Some(Self::FileTransfer),
            _ => None,
        }
    }

    /// 映射到接口层 [`PacketKind`]。
    pub fn to_packet_kind(self) -> PacketKind {
        match self {
            Self::Video => PacketKind::Video,
            Self::Audio => PacketKind::Audio,
            Self::InputEcho => PacketKind::InputEcho,
            Self::Control => PacketKind::Control,
            Self::Clipboard => PacketKind::Clipboard,
            Self::FileTransfer => PacketKind::FileTransfer,
        }
    }
}

impl From<PacketKind> for PacketKindWire {
    fn from(k: PacketKind) -> Self {
        match k {
            PacketKind::Video => Self::Video,
            PacketKind::Audio => Self::Audio,
            PacketKind::InputEcho => Self::InputEcho,
            PacketKind::Control => Self::Control,
            PacketKind::Clipboard => Self::Clipboard,
            PacketKind::FileTransfer => Self::FileTransfer,
        }
    }
}

impl PacketHeader {
    /// 从 EncodedPacket + 分配的 frame_id 构造帧头。
    ///
    /// `flags` 自动置 KEY 位（当 `pkt.is_key == true`）；extradata/incremental
    /// 位由调用方按需 OR 进 `extra_flags`。
    pub fn from_packet(pkt: &EncodedPacket, frame_id: u32, extra_flags: u8) -> Self {
        let mut flags = extra_flags;
        if pkt.is_key {
            flags |= FLAG_KEY;
        }
        Self {
            magic: HEADER_MAGIC,
            version: HEADER_VERSION,
            kind: PacketKindWire::from(pkt.kind),
            flags,
            frame_id,
            pts: pkt.ts.pts,
            payload_len: pkt.data.len() as u32,
        }
    }

    /// 大端序编码到 `buf`（追加 17B + payload）。
    ///
    /// 调用方负责保证 `buf` 容量；本方法只追加头与 payload。
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.push(self.version);
        buf.push(self.kind as u8);
        buf.push(self.flags);
        buf.extend_from_slice(&self.frame_id.to_be_bytes());
        buf.extend_from_slice(&self.pts.to_be_bytes());
        buf.extend_from_slice(&self.payload_len.to_be_bytes());
    }

    /// 解码：从 `buf` 起始处读取 17B 头。
    ///
    /// - 长度不足 [`HEADER_SIZE`] → [`TransError::MalformedHeader`]。
    /// - magic/version/kind 非法 → [`TransError::MalformedHeader`]。
    pub fn decode(buf: &[u8]) -> Result<Self, TransError> {
        if buf.len() < HEADER_SIZE {
            return Err(TransError::MalformedHeader);
        }
        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        if magic != HEADER_MAGIC {
            return Err(TransError::MalformedHeader);
        }
        let version = buf[2];
        if version != HEADER_VERSION {
            return Err(TransError::MalformedHeader);
        }
        let kind = PacketKindWire::from_byte(buf[3]).ok_or(TransError::MalformedHeader)?;
        let flags = buf[4];
        let frame_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        let pts = u64::from_be_bytes([
            buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16],
        ]);
        let payload_len = u32::from_be_bytes([buf[17], buf[18], buf[19], buf[20]]);
        Ok(Self {
            magic,
            version,
            kind,
            flags,
            frame_id,
            pts,
            payload_len,
        })
    }

    /// 是否关键帧（IDR / 会话首包）。
    pub fn is_key(&self) -> bool {
        self.flags & FLAG_KEY != 0
    }
}

// ════════════════════════════════════════════════════════════════
// 成帧辅助
// ════════════════════════════════════════════════════════════════

/// 把一个 EncodedPacket 打包为 `header(17B) + payload` 字节流。
///
/// 用于 SecureChannel 阶段（同 TCP 流，前缀字节由调用方再追加）或
/// 单片 DATAGRAM（payload ≤ [`MAX_PACKET_PAYLOAD`]）。
///
/// 超过 [`MAX_PACKET_PAYLOAD`] → [`TransError::PayloadTooLarge`]（视频应
/// 走 DATAGRAM 分片路径，不由本函数处理）。
pub fn frame_packet(
    pkt: &EncodedPacket,
    frame_id: u32,
    extra_flags: u8,
) -> Result<Vec<u8>, TransError> {
    if pkt.data.len() > MAX_PACKET_PAYLOAD {
        return Err(TransError::PayloadTooLarge(
            pkt.data.len(),
            MAX_PACKET_PAYLOAD,
        ));
    }
    let header = PacketHeader::from_packet(pkt, frame_id, extra_flags);
    let mut buf = Vec::with_capacity(HEADER_SIZE + pkt.data.len());
    header.encode(&mut buf);
    buf.extend_from_slice(&pkt.data);
    Ok(buf)
}

/// 从一段完整帧（`header + payload`，不含 SecureChannel 前缀）解析出
/// `(PacketHeader, payload)`。
///
/// 仅做长度一致性校验：`buf.len()` 必须等于 `HEADER_SIZE + payload_len`。
pub fn parse_frame(buf: &[u8]) -> Result<(PacketHeader, &[u8]), TransError> {
    let header = PacketHeader::decode(buf)?;
    let payload_start = HEADER_SIZE;
    let payload_end = payload_start
        .checked_add(header.payload_len as usize)
        .ok_or(TransError::MalformedHeader)?;
    if buf.len() < payload_end {
        return Err(TransError::MalformedHeader);
    }
    Ok((header, &buf[payload_start..payload_end]))
}

// ════════════════════════════════════════════════════════════════
// 通道分派 tag
// ════════════════════════════════════════════════════════════════

/// SecureChannel 阶段通道标签（前缀字节，区分同一条 TCP 流上的子通道）。
///
/// 数值与 [`PacketKindWire`] 对齐（Video/Audio/Input），新增 `Control`
/// 用于既有的控制/心跳通道（M3-DNS004 心跳归属）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelTag {
    /// 视频。
    Video = 0x01,
    /// 音频。
    Audio = 0x02,
    /// 键鼠（可靠流方向：客户端→服务端）。
    Input = 0x03,
    /// 控制/心跳（DNS 心跳归属确认通道）。
    Control = 0x04,
    /// 剪贴板文本（M13-T003，双向）。
    Clipboard = 0x05,
    /// 文件传输（M13-T006，双向，64 KiB 大帧走可靠流）。
    FileTransfer = 0x06,
}

impl ChannelTag {
    /// wire byte → enum；未知 → `None`。
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Video),
            0x02 => Some(Self::Audio),
            0x03 => Some(Self::Input),
            0x04 => Some(Self::Control),
            0x05 => Some(Self::Clipboard),
            0x06 => Some(Self::FileTransfer),
            _ => None,
        }
    }

    /// 把 [`PacketKind`] 映射到对应通道标签。
    pub fn from_packet_kind(k: PacketKind) -> Self {
        match k {
            PacketKind::Video => Self::Video,
            PacketKind::Audio => Self::Audio,
            PacketKind::InputEcho => Self::Input,
            PacketKind::Control => Self::Control,
            PacketKind::Clipboard => Self::Clipboard,
            PacketKind::FileTransfer => Self::FileTransfer,
        }
    }
}

// ════════════════════════════════════════════════════════════════
// QUIC 通道分派
// ════════════════════════════════════════════════════════════════

/// QUIC 阶段媒体通道归属。
///
/// 决定一个 [`EncodedPacket`] 走哪条 QUIC 通路：
/// - `VideoDatagram`：可丢，最低优先级（拥塞先丢视频）。
/// - `AudioDatagram`：独立 DATAGRAM，中优先级（人耳敏感）。
/// - `InputReliable`：可靠流，最高优先级（不可丢，背压阻塞）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicKind {
    /// 视频 → DATAGRAM（可丢弃）。
    VideoDatagram,
    /// 音频 → 独立 DATAGRAM（中优先级）。
    AudioDatagram,
    /// 键鼠 → 可靠流（最高优先级）。
    InputReliable,
}

impl QuicKind {
    /// 按 [`PacketKind`] 决定 QUIC 通道归属。
    pub fn from_packet_kind(k: PacketKind) -> Self {
        match k {
            PacketKind::Video => Self::VideoDatagram,
            PacketKind::Audio => Self::AudioDatagram,
            PacketKind::InputEcho => Self::InputReliable,
            // 剪贴板走可靠流（不可丢，与键鼠同权）。
            PacketKind::Clipboard => Self::InputReliable,
            // M13-T006: 文件走可靠流（不可丢，不重；背压阻塞）。
            PacketKind::FileTransfer => Self::InputReliable,
            // M8-T018: 显示器/隐私等控制消息走可靠流（不可丢，低延迟敏感）。
            PacketKind::Control => Self::InputReliable,
        }
    }
}

// ════════════════════════════════════════════════════════════════
// TransError
// ════════════════════════════════════════════════════════════════

/// 帧封装/分派错误（与 [`crate::transport::TransportError`] 并存——本层只关心
/// 帧头/通道分派的合法性，传输层 I/O 错误仍由 `TransportError` 表达）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransError {
    /// 头长度不足 / magic / version / kind 不符。
    #[error("malformed packet header")]
    MalformedHeader,
    /// 负载超上限（[`MAX_PACKET_PAYLOAD`]）。视频应走 DATAGRAM 分片。
    #[error("payload too large: {0} bytes (max {1})")]
    PayloadTooLarge(usize, usize),
    /// 传输通道未建立（例如 QUIC 未连接时发包）。
    #[error("transport not connected")]
    NotConnected,
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::types::{PacketKind, Timestamp};
    use std::time::Instant;

    fn make_packet(kind: PacketKind, data: Vec<u8>, is_key: bool, pts: u64) -> EncodedPacket {
        EncodedPacket {
            ts: Timestamp::new(Instant::now(), pts),
            kind,
            data,
            is_key,
        }
    }

    #[test]
    fn test_header_roundtrip() {
        let pkt = make_packet(PacketKind::Video, vec![0xAB; 100], true, 12345);
        let header = PacketHeader::from_packet(&pkt, 42, FLAG_EXTRADATA);
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_SIZE);

        let decoded = PacketHeader::decode(&buf).expect("decode");
        assert_eq!(decoded.magic, HEADER_MAGIC);
        assert_eq!(decoded.version, HEADER_VERSION);
        assert_eq!(decoded.kind, PacketKindWire::Video);
        assert_eq!(decoded.flags & FLAG_KEY, FLAG_KEY);
        assert_eq!(decoded.flags & FLAG_EXTRADATA, FLAG_EXTRADATA);
        assert_eq!(decoded.frame_id, 42);
        assert_eq!(decoded.pts, 12345);
        assert_eq!(decoded.payload_len, 100);
        assert!(decoded.is_key());
    }

    #[test]
    fn test_header_bad_magic() {
        let pkt = make_packet(PacketKind::Audio, vec![0xCD; 50], false, 1);
        let mut header = PacketHeader::from_packet(&pkt, 1, 0);
        header.magic = 0xFFFF; // 篡改
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let err = PacketHeader::decode(&buf).unwrap_err();
        assert_eq!(err, TransError::MalformedHeader);
    }

    #[test]
    fn test_header_too_short() {
        let short = [0u8; HEADER_SIZE - 1];
        let err = PacketHeader::decode(&short).unwrap_err();
        assert_eq!(err, TransError::MalformedHeader);
    }

    #[test]
    fn test_header_bad_version() {
        let pkt = make_packet(PacketKind::Video, vec![], false, 0);
        let mut header = PacketHeader::from_packet(&pkt, 0, 0);
        header.version = 99;
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(PacketHeader::decode(&buf), Err(TransError::MalformedHeader));
    }

    #[test]
    fn test_header_bad_kind() {
        let mut buf = vec![0x4B, 0x44, HEADER_VERSION, 0xFF, 0x00];
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(buf.len(), HEADER_SIZE);
        assert_eq!(PacketHeader::decode(&buf), Err(TransError::MalformedHeader));
    }

    #[test]
    fn test_payload_oversize() {
        // 构造一个超上限的 EncodedPacket。
        let oversized = vec![0u8; MAX_PACKET_PAYLOAD + 1];
        let pkt = make_packet(PacketKind::Video, oversized, false, 0);
        let err = frame_packet(&pkt, 0, 0).unwrap_err();
        match err {
            TransError::PayloadTooLarge(got, max) => {
                assert_eq!(got, MAX_PACKET_PAYLOAD + 1);
                assert_eq!(max, MAX_PACKET_PAYLOAD);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn test_frame_packet_and_parse_roundtrip() {
        let payload = vec![0x11, 0x22, 0x33, 0x44];
        let pkt = make_packet(PacketKind::Audio, payload.clone(), true, 999);
        let framed = frame_packet(&pkt, 7, 0).expect("frame");
        // framed = header(HEADER_SIZE) + payload
        assert_eq!(framed.len(), HEADER_SIZE + payload.len());

        let (header, parsed_payload) = parse_frame(&framed).expect("parse");
        assert_eq!(header.frame_id, 7);
        assert_eq!(header.pts, 999);
        assert_eq!(header.kind, PacketKindWire::Audio);
        assert!(header.is_key());
        assert_eq!(parsed_payload, &payload[..]);
    }

    #[test]
    fn test_parse_frame_payload_truncated() {
        let payload = vec![0x11; 200];
        let pkt = make_packet(PacketKind::Video, payload, false, 0);
        let framed = frame_packet(&pkt, 1, 0).expect("frame");
        // 截断到 HEADER_SIZE + 10（少于 payload_len）
        let truncated = &framed[..HEADER_SIZE + 10];
        assert_eq!(
            parse_frame(truncated).unwrap_err(),
            TransError::MalformedHeader
        );
    }

    #[test]
    fn test_channel_tag_mapping() {
        assert_eq!(
            ChannelTag::from_packet_kind(PacketKind::Video),
            ChannelTag::Video
        );
        assert_eq!(
            ChannelTag::from_packet_kind(PacketKind::Audio),
            ChannelTag::Audio
        );
        assert_eq!(
            ChannelTag::from_packet_kind(PacketKind::InputEcho),
            ChannelTag::Input
        );
        assert_eq!(
            ChannelTag::from_packet_kind(PacketKind::Clipboard),
            ChannelTag::Clipboard
        );
        assert_eq!(
            ChannelTag::from_packet_kind(PacketKind::FileTransfer),
            ChannelTag::FileTransfer
        );
        assert_eq!(ChannelTag::from_byte(0x04), Some(ChannelTag::Control));
        assert_eq!(ChannelTag::from_byte(0x06), Some(ChannelTag::FileTransfer));
        assert_eq!(ChannelTag::from_byte(0xFF), None);
    }

    #[test]
    fn test_quic_kind_mapping() {
        assert_eq!(
            QuicKind::from_packet_kind(PacketKind::Video),
            QuicKind::VideoDatagram
        );
        assert_eq!(
            QuicKind::from_packet_kind(PacketKind::Audio),
            QuicKind::AudioDatagram
        );
        assert_eq!(
            QuicKind::from_packet_kind(PacketKind::InputEcho),
            QuicKind::InputReliable
        );
        assert_eq!(
            QuicKind::from_packet_kind(PacketKind::Clipboard),
            QuicKind::InputReliable
        );
        assert_eq!(
            QuicKind::from_packet_kind(PacketKind::FileTransfer),
            QuicKind::InputReliable
        );
        // M8-T018: 显示器/隐私等控制走可靠流（不可丢，低延迟敏感）。
        assert_eq!(
            QuicKind::from_packet_kind(PacketKind::Control),
            QuicKind::InputReliable
        );
    }

    #[test]
    fn test_packet_kind_wire_roundtrip() {
        for k in [
            PacketKind::Video,
            PacketKind::Audio,
            PacketKind::InputEcho,
            PacketKind::Clipboard,
            PacketKind::FileTransfer,
            // M8-T018: 显示器控制 wire 0x04（与 ChannelTag::Control 对齐）。
            PacketKind::Control,
        ] {
            let wire = PacketKindWire::from(k);
            assert_eq!(wire.to_packet_kind(), k);
        }
        // 未知 wire byte → None。
        assert_eq!(PacketKindWire::from_byte(0x00), None);
        assert_eq!(PacketKindWire::from_byte(0x99), None);
        // M8-T018: Control tag 映射（复用既有 ChannelTag::Control 0x04）。
        assert_eq!(
            ChannelTag::from_packet_kind(PacketKind::Control),
            ChannelTag::Control
        );
        assert_eq!(ChannelTag::from_byte(0x04), Some(ChannelTag::Control));
    }

    #[test]
    fn test_max_payload_constant() {
        // DATAGRAM 上限常量自洽。
        assert_eq!(
            MAX_PACKET_PAYLOAD,
            MAX_DATAGRAM_SIZE - AEAD_OVERHEAD - HEADER_SIZE
        );
        // 非零正值（确保 AEAD + HEADER 未溢出）。
        assert!(MAX_PACKET_PAYLOAD > 0);
    }
}
