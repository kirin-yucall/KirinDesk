//! 控制流协议。
//!
//! 通过 QUIC 可靠流传输控制消息，内容用 MediaCipher 加密。
//! 复用 SecureChannel 的 长度前缀 (4B LE) + nonce (12B) + ciphertext 模式。

use bincode;
use serde::{Deserialize, Serialize};
use tracing::debug;

use kirin_desk_core::connection::privacy::PrivacyLevel;

use crate::proto::DisplayInfo;
use crate::transport::{MediaCipher, TransportError};

// ════════════════════════════════════════════════════════════════
// 消息类型
// ════════════════════════════════════════════════════════════════

/// 控制消息枚举（bincode 序列化）。
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ControlMessage {
    /// 自适应配置推送（服务端 → 编码器）
    AdaptiveConfig {
        qp: u32,
        frame_ratio: f64,
        force_idr: bool,
    },

    /// 反馈报告（客户端 → 服务端）
    ///
    /// 注意: `rtt_ms` 为 u64，精度 ~1ms。（微秒级精度需要在 wire 格式上增加字段，
    /// 当前 Phase 4 阶段 1ms 精度对远程桌面自适应足够。）
    FeedbackReport {
        loss_rate: f64,
        rtt_ms: u64,
        received_bitrate: u64,
        frame_id: u64,
        missing_frames: Vec<u64>,
    },

    /// 编解码协商（连接建立初期）
    CodecNegotiation {
        supported_codecs: Vec<String>,
        selected_codec: Option<String>,
    },

    /// 视频格式（服务端 → 客户端，会话开始时推送）。
    ///
    /// 客户端解码 DATAGRAM 重组帧时需要输出分辨率（wire 帧头不携带
    /// 宽高信息，M8-T009 §3.5）。会话建立后服务端立即推送一次，
    /// 分辨率变更（显示器模式切换）时重新推送。
    VideoFormat { width: u32, height: u32 },

    // ── M8-T018 多显示器查看 ──────────────────────────────────
    /// 显示器列表请求（客户端 → 服务端）。握手完成后客户端主动发送
    /// （SRV-MON-004）；热插拔后客户端可手动刷新（MON-NF-001）。
    DisplayListReq,

    /// 显示器列表响应（服务端 → 客户端，SRV-MON-002）。
    /// 负载为 [`crate::proto::DisplayInfo`] 列表（bincode 序列化）。
    DisplayListResp { displays: Vec<DisplayInfo> },

    /// 切换捕获显示器（客户端 → 服务端，SRV-MON-003）。
    /// 越界索引 → 服务端响应 [`DisplaySelectNack`]（或保持当前屏）。
    DisplaySelect { index: u32 },

    /// 切换被拒（索引越界 / 捕获源重建失败等）。客户端提示并保持当前屏。
    DisplaySelectNack { reason: String },

    /// 连接心跳
    Heartbeat { timestamp_ms: u64 },

    /// 窗口确认
    WindowAck {
        window_id: u64,
        decoded_frames: u32,
        decode_duration_ms: f64,
    },

    /// M8-T019 (SRV-PRIV-001): 隐私模式控制（客户端 → 服务端）。
    ///
    /// 黑屏（Level 1）：被控端屏幕被全屏纯黑覆盖窗口遮挡，客户端画面与
    /// 输入注入照常（黑屏 ≠ 发送黑帧）；锁屏（Level 2）：系统锁屏，锁屏后
    /// 注入暂停、解锁自动恢复（SRV-PRIV-015）。`on = true` 开启 /
    /// `false` 恢复屏幕。服务端断连自动恢复（SRV-PRIV-014，无网络依赖）。
    PrivacyMode {
        level: PrivacyLevel,
        on: bool,
    },

    /// M8-T019 (SRV-PRIV-002): 隐私模式响应（服务端 → 客户端）。
    ///
    /// `ok = false` → 拒绝（平台锁屏调用失败等）；`active_level` 为服务端
    /// **实际生效**等级——请求 Black 但无 GUI 时降级为 Lock（SRV-PRIV-013），
    /// 客户端据此 toast 提示降级。
    PrivacyModeAck {
        ok: bool,
        active_level: Option<PrivacyLevel>,
    },

    /// 断开连接
    Disconnect { reason: String },
}

// ════════════════════════════════════════════════════════════════
// 发送
// ════════════════════════════════════════════════════════════════

/// 加密控制消息并通过 QUIC 可靠流发送。
pub async fn send_control_msg(
    stream: &mut quinn::SendStream,
    cipher: &MediaCipher,
    msg: &ControlMessage,
) -> Result<(), TransportError> {
    let plain = bincode::serialize(msg)
        .map_err(|e| TransportError::Quic(format!("bincode serialize: {e}")))?;

    let encrypted = cipher.encrypt(&plain)?;

    // 长度前缀 (4B LE) + 密文
    let len = encrypted.len() as u32;
    let mut buf = Vec::with_capacity(4 + encrypted.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&encrypted);

    use tokio::io::AsyncWriteExt;
    stream
        .write_all(&buf)
        .await
        .map_err(|e| TransportError::Quic(format!("control send: {e}")))?;

    debug!(
        "send_control_msg: type={} ({} bytes encrypted)",
        msg_type_name(msg),
        buf.len()
    );

    Ok(())
}

// ════════════════════════════════════════════════════════════════
// 接收
// ════════════════════════════════════════════════════════════════

/// 从 QUIC 可靠流接收并解密控制消息。
pub async fn recv_control_msg(
    stream: &mut quinn::RecvStream,
    cipher: &MediaCipher,
) -> Result<ControlMessage, TransportError> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| TransportError::ConnectionClosed {
            reason: format!("control stream read: {e}"),
        })?;
    let len = u32::from_le_bytes(len_buf) as usize;

    let mut encrypted = vec![0u8; len];
    stream
        .read_exact(&mut encrypted)
        .await
        .map_err(|e| TransportError::ConnectionClosed {
            reason: format!("control stream read payload: {e}"),
        })?;

    let plain = cipher.decrypt(&encrypted)?;

    let msg: ControlMessage = bincode::deserialize(&plain)
        .map_err(|e| TransportError::Quic(format!("bincode deserialize: {e}")))?;

    debug!("recv_control_msg: type={}", msg_type_name(&msg));

    Ok(msg)
}

// ════════════════════════════════════════════════════════════════
// 辅助
// ════════════════════════════════════════════════════════════════

fn msg_type_name(msg: &ControlMessage) -> &'static str {
    match msg {
        ControlMessage::AdaptiveConfig { .. } => "AdaptiveConfig",
        ControlMessage::FeedbackReport { .. } => "FeedbackReport",
        ControlMessage::CodecNegotiation { .. } => "CodecNegotiation",
        ControlMessage::VideoFormat { .. } => "VideoFormat",
        ControlMessage::DisplayListReq => "DisplayListReq",
        ControlMessage::DisplayListResp { .. } => "DisplayListResp",
        ControlMessage::DisplaySelect { .. } => "DisplaySelect",
        ControlMessage::DisplaySelectNack { .. } => "DisplaySelectNack",
        ControlMessage::Heartbeat { .. } => "Heartbeat",
        ControlMessage::WindowAck { .. } => "WindowAck",
        ControlMessage::PrivacyMode { .. } => "PrivacyMode",
        ControlMessage::PrivacyModeAck { .. } => "PrivacyModeAck",
        ControlMessage::Disconnect { .. } => "Disconnect",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_config_serde() {
        let msg = ControlMessage::AdaptiveConfig {
            qp: 28,
            frame_ratio: 0.5,
            force_idr: true,
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_feedback_report_serde() {
        let msg = ControlMessage::FeedbackReport {
            loss_rate: 0.03,
            rtt_ms: 45,
            received_bitrate: 2_500_000,
            frame_id: 1024,
            missing_frames: vec![1010, 1015],
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_codec_negotiation_serde() {
        let msg = ControlMessage::CodecNegotiation {
            supported_codecs: vec!["h264".into(), "h265_qsv".into()],
            selected_codec: Some("h264".into()),
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_video_format_serde() {
        let msg = ControlMessage::VideoFormat {
            width: 1920,
            height: 1080,
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_heartbeat_serde() {
        let msg = ControlMessage::Heartbeat {
            timestamp_ms: 12345,
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_window_ack_serde() {
        let msg = ControlMessage::WindowAck {
            window_id: 42,
            decoded_frames: 7,
            decode_duration_ms: 12.5,
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    // M8-T019 (SRV-PRIV-001/002): 隐私模式控制消息 wire 往返。
    #[test]
    fn test_privacy_mode_serde() {
        for level in [PrivacyLevel::Black, PrivacyLevel::Lock] {
            for on in [true, false] {
                let msg = ControlMessage::PrivacyMode { level, on };
                let data = bincode::serialize(&msg).unwrap();
                let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
                assert_eq!(msg, deserialized);
            }
        }
    }

    #[test]
    fn test_privacy_mode_ack_serde() {
        // 成功 + 实际生效等级（含降级：请求 Black → 返回 Lock）。
        let msg = ControlMessage::PrivacyModeAck {
            ok: true,
            active_level: Some(PrivacyLevel::Lock),
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);

        // 拒绝 / 恢复屏幕（无活跃等级）。
        let msg = ControlMessage::PrivacyModeAck {
            ok: false,
            active_level: None,
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_disconnect_serde() {
        let msg = ControlMessage::Disconnect {
            reason: "bye".into(),
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    // ════════════════════════════════════════════════════════════
    // M8-T018 多显示器：DisplayList 序列化往返 / 越界索引 Nack
    // ════════════════════════════════════════════════════════════

    fn sample_display_list() -> Vec<DisplayInfo> {
        vec![
            DisplayInfo {
                index: 0,
                name: "\\\\.\\DISPLAY1".into(),
                width: 1920,
                height: 1080,
                is_primary: true,
            },
            DisplayInfo {
                index: 1,
                name: "\\\\.\\DISPLAY2".into(),
                width: 2560,
                height: 1440,
                is_primary: false,
            },
        ]
    }

    #[test]
    fn test_display_list_req_serde() {
        // 空负载变体往返（bincode 序列化）。
        let msg = ControlMessage::DisplayListReq;
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_display_list_resp_serde() {
        let msg = ControlMessage::DisplayListResp {
            displays: sample_display_list(),
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
        // 字段内容逐项校验（防 bincode 位置格式错位）。
        match deserialized {
            ControlMessage::DisplayListResp { displays } => {
                assert_eq!(displays.len(), 2);
                assert_eq!(displays[0].index, 0);
                assert_eq!(displays[0].name, "\\\\.\\DISPLAY1");
                assert_eq!(displays[0].width, 1920);
                assert_eq!(displays[0].height, 1080);
                assert!(displays[0].is_primary);
                assert!(!displays[1].is_primary);
                assert_eq!(displays[1].width, 2560);
            }
            other => panic!("expected DisplayListResp, got {:?}", other),
        }
    }

    #[test]
    fn test_display_select_serde() {
        let msg = ControlMessage::DisplaySelect { index: 1 };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        assert_eq!(deserialized, ControlMessage::DisplaySelect { index: 1 });
    }

    #[test]
    fn test_display_select_nack_serde() {
        // 越界索引 → Nack（SRV-MON-003）：原因串往返一致。
        let msg = ControlMessage::DisplaySelectNack {
            reason: "invalid monitor index 9".into(),
        };
        let data = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
        match deserialized {
            ControlMessage::DisplaySelectNack { reason } => {
                assert_eq!(reason, "invalid monitor index 9");
            }
            other => panic!("expected DisplaySelectNack, got {:?}", other),
        }
    }
}
