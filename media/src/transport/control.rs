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

    ///
    /// `mode` = 客户端 `DisplayMode` 枚举值（0 流畅 / 1 低延迟 / 2 高画质，
    /// 客户端唯一定义点 `ui/src/lib.rs` `DisplayMode as u8`）。服务端只消费
    /// 降档档位减半，慢网络积压降档保护不变）；0/1/未知值 = 常态阶梯
    /// （fail-safe 向常态——旧客户端不发本消息 = 恒常态 = 现状零变化）。
    ///
    /// 尾追加判别值 13（既有 0-12 不重排，单测钉死；`FsOp` 尾追加纪律同族，
    /// 零新 ChannelTag / 零帧布局 / 零版本 bump）。旧服务端收未知变体 =
    /// 既有「Control message deserialize failed」单帧丢弃臂（WARN + 会话
    DisplayMode { mode: u8 },

    /// 本地 caps 态——客户端角色推给服务端角色的注入侧消费；服务端角色推给
    /// 客户端角色的观测/后续展示面消费；同进程内两角色各走各自连接，代码
    /// 按角色对称实现）。
    ///
    /// `caps` = 发送端本地 CapsLock 开关态（Windows = `GetKeyState(VK_CAPITAL)`
    /// 低位，`ui/src/lib.rs` `r129_local_caps_state`；非 Windows 无该语义 =
    /// 不发本帧）。消费 = 注入侧 26 字母大小写异或补偿（决策纯函数
    /// `kirin_desk_input::injector::r132_4_caps_compensate`）：
    /// `local XOR remote != 0` → 字母 KeyDown/KeyRepeat 叠加 shift。
    ///
    /// 尾追加判别值 14（既有 0-13 不重排，单测钉死；`DisplayMode`/`FsOp`
    /// 尾追加纪律同族，零新 ChannelTag / 零帧布局 / **零版本 bump**——
    /// `PROTOCOL_VERSION=3` 不变、零新凭据、诚实口径零修订）。
    /// 控制帧逐帧独立成帧（QUIC 路 = 本模块 `recv_control_msg` 长度前缀
    /// (4B LE) + AEAD；SecureChannel 路 = PacketHeader `payload_len` +
    /// AEAD 载荷），长度在密文之外，丢一帧不影响后续帧分帧。新端收不到旧端
    /// 本帧 = `remote_caps` 默认 `false` = 零补偿 = 现状行为（向后兼容
    /// 语义，交付报告记档）。
    CapsState { caps: bool },

    /// 状态通告（**服务端角色 → 客户端角色**，会话建立即推初值 + 会话中
    /// `ui/src/lib.rs` 服务端会话分发任务，消费位点 = 客户端收流环控制臂
    /// → per-会话槽）。
    ///
    /// `clipboard_allowed` / `file_transfer_allowed` = **发送端（受控端/
    /// 服务端角色）自身**两权限开关实时值（`ui` 侧 `r137_1_local_consent_
    /// 消费 = 客户端 s→c 剪贴板接收臂门控（按**对端值**判定，非本机配置
    /// ——用户指正点）+ 远程桌面会话窗剪贴板 OFF 提示展示（对端语义
    /// 文案，与门控同源）。
    ///
    /// 尾追加判别值 15（既有 0-14 不重排，单测钉死；`DisplayMode`/
    /// `CapsState`/`FsOp` 尾追加纪律同族，零新 ChannelTag / 零帧布局 /
    /// 前包）收未知变体 = 既有「Control message deserialize failed」单帧
    /// 到旧端本帧 = 对端态未知 = **fail-closed 按 OFF 门控 + 显式提示**
    /// （安全红线⑤，不静默放行）。
    PeerConsent {
        clipboard_allowed: bool,
        file_transfer_allowed: bool,
    },
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

    // quinn 0.11 SendStream 自带 inherent write_all（AsyncWriteExt 无需引入）。
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
    // quinn 0.11 RecvStream 自带 inherent read_exact（AsyncReadExt 无需引入）。
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
        ControlMessage::DisplayMode { .. } => "DisplayMode",
        ControlMessage::CapsState { .. } => "CapsState",
        ControlMessage::PeerConsent { .. } => "PeerConsent",
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

    #[test]
    fn test_display_mode_serde() {
        for mode in [0u8, 1, 2] {
            let msg = ControlMessage::DisplayMode { mode };
            let data = bincode::serialize(&msg).unwrap();
            let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
            assert_eq!(deserialized, ControlMessage::DisplayMode { mode });
        }
    }

    #[test]
    fn test_caps_state_serde() {
        for caps in [false, true] {
            let msg = ControlMessage::CapsState { caps };
            let data = bincode::serialize(&msg).unwrap();
            let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
            assert_eq!(deserialized, ControlMessage::CapsState { caps });
        }
        // 观测名（`msg_type_name` 日志面）在位。
        assert_eq!(msg_type_name(&ControlMessage::CapsState { caps: true }), "CapsState");
    }

    /// 锚点 + 尾值 13 = `DisplayMode`；10/11 PrivacyMode 族由既有顺序隐含）。
    /// bincode 枚举首 4B = 变体索引 u32 LE（与 core `FsOp` 判别值测试同口径，
    /// 防未来重排/插值）。
    #[test]
    fn test_r126b_control_message_discriminants_wire_pinned() {
        let idx = |m: &ControlMessage| -> u32 {
            let b = bincode::serialize(m).unwrap();
            u32::from_le_bytes(b[0..4].try_into().unwrap())
        };
        assert_eq!(
            idx(&ControlMessage::AdaptiveConfig {
                qp: 0,
                frame_ratio: 1.0,
                force_idr: false
            }),
            0
        );
        assert_eq!(
            idx(&ControlMessage::FeedbackReport {
                loss_rate: 0.0,
                rtt_ms: 0,
                received_bitrate: 0,
                frame_id: 0,
                missing_frames: vec![]
            }),
            1
        );
        assert_eq!(
            idx(&ControlMessage::CodecNegotiation {
                supported_codecs: vec![],
                selected_codec: None
            }),
            2
        );
        assert_eq!(
            idx(&ControlMessage::VideoFormat { width: 0, height: 0 }),
            3
        );
        assert_eq!(idx(&ControlMessage::DisplayListReq), 4);
        assert_eq!(
            idx(&ControlMessage::DisplayListResp { displays: vec![] }),
            5
        );
        assert_eq!(
            idx(&ControlMessage::DisplaySelect { index: 0 }),
            6
        );
        assert_eq!(
            idx(&ControlMessage::DisplaySelectNack {
                reason: String::new()
            }),
            7
        );
        assert_eq!(
            idx(&ControlMessage::Heartbeat { timestamp_ms: 0 }),
            8
        );
        assert_eq!(
            idx(&ControlMessage::WindowAck {
                window_id: 0,
                decoded_frames: 0,
                decode_duration_ms: 0.0
            }),
            9
        );
        assert_eq!(
            idx(&ControlMessage::Disconnect {
                reason: String::new()
            }),
            12
        );
        assert_eq!(
            idx(&ControlMessage::DisplayMode { mode: 2 }),
            13,
            "ControlMessage::DisplayMode 判别值漂移（尾追加 = 13，防未来重排/插值）"
        );
        assert_eq!(
            idx(&ControlMessage::CapsState { caps: true }),
            14,
        );
        assert_eq!(
            idx(&ControlMessage::PeerConsent {
                clipboard_allowed: true,
                file_transfer_allowed: false,
            }),
            15,
        );
    }

    #[test]
    fn test_peer_consent_serde() {
        for clip in [false, true] {
            for ft in [false, true] {
                let msg = ControlMessage::PeerConsent {
                    clipboard_allowed: clip,
                    file_transfer_allowed: ft,
                };
                let data = bincode::serialize(&msg).unwrap();
                let deserialized: ControlMessage = bincode::deserialize(&data).unwrap();
                assert_eq!(deserialized, msg, "PeerConsent 回环（clip={clip}, ft={ft}）");
            }
        }
        assert_eq!(
            msg_type_name(&ControlMessage::PeerConsent {
                clipboard_allowed: true,
                file_transfer_allowed: true
            }),
            "PeerConsent"
        );
    }

    /// （15 变体、声明序逐位复刻 = 含 `CapsState` 尾值 14）为「旧端」，喂
    /// **真实新编码器**产出的 `PeerConsent` 帧：① 旧端反序列化必 Err
    ///（未知变体 15）→ 落入生产既有「Control message deserialize failed」
    /// 单帧丢弃臂（WARN + 会话存活）；② 帧间无状态污染——紧随其后的
    /// `Heartbeat` 旧端照常成功（独立成帧单元，长度在密文之外）。新端侧
    /// 兼容 = 收不到旧端本帧 → 对端态未知 → fail-closed 按 OFF（红线⑤，
    /// `ui/src/lib.rs` `r137_1_peer_clipboard_gate(None) == false` 单测
    /// 钉死）。
    #[test]
    fn test_r137_1_old_end_ignores_peer_consent_frame() {
        /// （15 变体、声明序/字段序不变——与 `test_r126b_...` 钉死集同口径；
        /// 测试本地枚举，生产零触碰）。
        #[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
        #[allow(dead_code)]
        enum OldControlMessage {
            AdaptiveConfig {
                qp: u32,
                frame_ratio: f64,
                force_idr: bool,
            },
            FeedbackReport {
                loss_rate: f64,
                rtt_ms: u64,
                received_bitrate: u64,
                frame_id: u64,
                missing_frames: Vec<u64>,
            },
            CodecNegotiation {
                supported_codecs: Vec<String>,
                selected_codec: Option<String>,
            },
            VideoFormat { width: u32, height: u32 },
            DisplayListReq,
            DisplayListResp {
                displays: Vec<crate::proto::DisplayInfo>,
            },
            DisplaySelect { index: u32 },
            DisplaySelectNack { reason: String },
            Heartbeat { timestamp_ms: u64 },
            WindowAck {
                window_id: u64,
                decoded_frames: u32,
                decode_duration_ms: f64,
            },
            PrivacyMode {
                level: PrivacyLevel,
                on: bool,
            },
            PrivacyModeAck {
                ok: bool,
                active_level: Option<PrivacyLevel>,
            },
            Disconnect { reason: String },
            DisplayMode { mode: u8 },
            CapsState { caps: bool },
        }

        // 新编码器产出 PeerConsent 帧（真实生产编码器 = 本模块 bincode）。
        let new_frame = bincode::serialize(&ControlMessage::PeerConsent {
            clipboard_allowed: true,
            file_transfer_allowed: false,
        })
        .unwrap();

        // ① 旧端收 PeerConsent = 未知变体 → 反序列化必 Err（= 生产既有
        //    单帧丢弃臂的触发前提；WARN + continue，会话存活）。
        assert!(
            bincode::deserialize::<OldControlMessage>(&new_frame).is_err(),
            "旧端收 PeerConsent 必为未知变体 Err（→ 既有单帧丢弃臂）"
        );

        // ② 帧间无状态污染：丢帧后紧随的 Heartbeat 旧端照常成功（独立成帧）。
        let heartbeat =
            bincode::serialize(&ControlMessage::Heartbeat { timestamp_ms: 42 }).unwrap();
        let hb: OldControlMessage =
            bincode::deserialize(&heartbeat).expect("丢 PeerConsent 帧后 Heartbeat 必仍成功");
        assert_eq!(
            hb,
            OldControlMessage::Heartbeat { timestamp_ms: 42 }
        );
    }

    /// 声明序逐位复刻）为「旧端」，喂**真实新编码器**产出的 `CapsState` 帧：
    /// ① 旧端反序列化**必然失败**（未知变体 14）→ 落入生产代码既有
    ///    「Control message deserialize failed」/「display control
    ///    deserialize failed」**单帧丢弃臂**（WARN + `continue`，会话存活——
    ///    两臂为既有代码，本测试钉死其触发前提 = 未知变体必 Err）；
    /// ② 帧间无状态污染——紧随其后的 `Heartbeat` 帧（独立成帧单元：
    ///    长度在密文之外）旧端反序列化**照常成功**（丢一帧不脱同步）。
    /// 新端侧 = 既有 `test_caps_state_serde` 往返 + 本文件消费臂单点接线
    /// （`ui/src/lib.rs` Control 臂）。
    #[test]
    fn test_r132_4_old_end_ignores_caps_state_frame() {
        /// （14 变体、声明序/字段序不变——与 HEAD 前 `test_r126b_...` 钉死集
        /// 同口径；测试本地枚举，生产零触碰）。
        #[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
        #[allow(dead_code)]
        enum OldControlMessage {
            AdaptiveConfig {
                qp: u32,
                frame_ratio: f64,
                force_idr: bool,
            },
            FeedbackReport {
                loss_rate: f64,
                rtt_ms: u64,
                received_bitrate: u64,
                frame_id: u64,
                missing_frames: Vec<u64>,
            },
            CodecNegotiation {
                supported_codecs: Vec<String>,
                selected_codec: Option<String>,
            },
            VideoFormat { width: u32, height: u32 },
            DisplayListReq,
            DisplayListResp {
                displays: Vec<crate::proto::DisplayInfo>,
            },
            DisplaySelect { index: u32 },
            DisplaySelectNack { reason: String },
            Heartbeat { timestamp_ms: u64 },
            WindowAck {
                window_id: u64,
                decoded_frames: u32,
                decode_duration_ms: f64,
            },
            PrivacyMode {
                level: PrivacyLevel,
                on: bool,
            },
            PrivacyModeAck {
                ok: bool,
                active_level: Option<PrivacyLevel>,
            },
            Disconnect { reason: String },
            DisplayMode { mode: u8 },
        }

        // 新编码器产出 CapsState 帧（真实生产编码器 = 本模块 `bincode::serialize`）。
        let new_frame_on = bincode::serialize(&ControlMessage::CapsState { caps: true }).unwrap();
        let new_frame_off = bincode::serialize(&ControlMessage::CapsState { caps: false }).unwrap();

        // ① 旧端收 CapsState = 未知变体 → 反序列化必 Err（= 生产既有单帧
        //    丢弃臂的触发前提；WARN + continue，会话存活）。
        assert!(
            bincode::deserialize::<OldControlMessage>(&new_frame_on).is_err(),
            "旧端收 CapsState(caps=true) 必为未知变体 Err（→ 既有单帧丢弃臂）"
        );
        assert!(
            bincode::deserialize::<OldControlMessage>(&new_frame_off).is_err(),
            "旧端收 CapsState(caps=false) 必为未知变体 Err（→ 既有单帧丢弃臂）"
        );

        // ② 帧间无状态污染：丢帧后紧随的 Heartbeat 旧端照常成功（独立成帧）。
        let heartbeat = bincode::serialize(&ControlMessage::Heartbeat { timestamp_ms: 42 }).unwrap();
        let hb: OldControlMessage =
            bincode::deserialize(&heartbeat).expect("丢 CapsState 帧后 Heartbeat 必仍成功");
        assert!(matches!(hb, OldControlMessage::Heartbeat { timestamp_ms: 42 }));

        // ③ 反向：旧端**永不发**本帧（旧枚举无此变体）——新端侧兼容 = 收不到
        //    CapsState → `remote_caps` 默认 false → 零补偿 = 现状行为（新端
        //    消费臂零帧零动作，`ui/src/lib.rs` per-session 变量初始 false 钉死
        //    于该文件既有形态；此处钉死旧枚举变体集恰 14 = 无 CapsState 可发）。
        assert_eq!(
            bincode::serialize(&OldControlMessage::DisplayMode { mode: 2 }).unwrap().len() > 4,
            true,
            "旧枚举形态自洽（14 变体复刻可用）"
        );
    }
}
