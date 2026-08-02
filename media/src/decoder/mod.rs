//! 解码层入口：接口层 + 模块声明（P2A §T1.1；P2B 完成 video/ 实现）。
//!
//! # 架构（M8-T015 多层级拆分）
//!
//! ```text
//! media/decoder/
//! ├── mod.rs         # 接口层：DecodedFrame / DecoderPacket / AudioPacket /
//! │                  #         DecodeError / DecodeStats + VideoDecoder/AudioDecoder trait
//! ├── factory.rs     # 后端检测与回退链（qsv→cuvid→d3d11va→vt→vaapi→软解）
//! ├── video/
//! │   ├── mod.rs     # VideoDecoderPipeline（流式 receive 循环 + extradata 管理 + IDR 恢复）
//! │   ├── ffmpeg_hw.rs  # FFmpeg 硬件解码后端（hwframe_transfer + sws NV12→RGBA）
//! │   └── ffmpeg_sw.rs  # 软解回退（YUV420P → RGBA，流式循环）
//! ├── audio.rs       # libopus 解码 + jitter buffer + 音频解码流水线（P2C 实现）
//! ├── audio_playback.rs # 平台音频播放：AudioPlayback trait + WASAPI 共享渲染
//! │                  #   （macOS/Linux 留桩，P2C-mac/linux 阶段实现）
//! └── render.rs      # DecodedFrame → egui + 抖动缓冲（P2D 实现，本阶段占位）
//! ```
//!
//! 与编码层（`encoder/`，P1A–P1G）对称：接口层类型对称 `EncoderPacket`/
//! `VideoEncoder`，`ffmpeg/` 基础设施层（dlls/types/error/api/scale）共用，
//! 本模块不重复拆分。
//!
//! # 历史
//!
//! 旧单文件解码器 `decoder.rs` 已迁移到 `decoder_legacy.rs`（P2A 过渡），
//! P2B 完成 `video/` 流式逻辑迁移后删除（见 [`factory::create_video_decoder`]
//! 与 [`video::VideoDecoderPipeline`]）。
//!
//! # 边界
//!
//! 解码层只依赖 `ffmpeg/`（共用）+ `encoder::types`（Codec 等纯类型）；
//! 不 import egui / capture / encoder 后端。渲染（P2D）由 UI 层消费
//! [`DecodedFrame`]，本模块不感知 egui。

pub mod audio;
pub mod audio_playback;
// Linux PipeWire 播放（M8-T015 P2C T3.3 Linux 侧 / R-14-S4）。
#[cfg(target_os = "linux")]
pub mod pipewire_playback;
pub mod factory;
pub mod render;
pub mod video;

// P2D：渲染桥（抖动缓冲 + 通道投递）提升到解码层命名空间，UI 层经
// `kirin_desk_media::decoder::RenderBridge` 消费（lib.rs 再重导出）。
pub use render::RenderBridge;

use crate::encoder::types::Codec;

// ════════════════════════════════════════════════════════════════
// 数据类型
// ════════════════════════════════════════════════════════════════

/// 解码后的视频帧（RGBA + 时间戳）。
#[derive(Debug, Clone)]
pub struct DecodedFrame {
    /// 会话相对毫秒 PTS（与编码 `EncodedPacket.ts.pts` 同轴）。
    pub pts: u64,
    pub width: u32,
    pub height: u32,
    /// RGBA 像素数据：width × height × 4 字节。
    pub rgba: Vec<u8>,
    /// 是否来自 IDR 关键帧。
    pub is_key: bool,
}

/// 视频解码输入（自 EncodedWindow / 重组帧 转换）。
#[derive(Debug, Clone)]
pub struct DecoderPacket {
    /// 会话相对毫秒 PTS（PTS 携带方案 A：frame_id 线性近似，见
    /// [`frame_id_to_pts`]；方案细节见 P2A §T1.1「PTS 携带方案」）。
    pub pts: u64,
    /// Annex B 码流（H.264/H.265 NAL + start code）。
    pub data: Vec<u8>,
    /// IDR 标志（DATAGRAM flags bit0 = KEY_FRAME）。
    pub is_key: bool,
    /// SPS/PPS/VPS（仅 IDR 且首包含 extradata 时；编码侧参数变更重发）。
    pub extradata: Option<Vec<u8>>,
}

/// 音频解码输入。
#[derive(Debug, Clone)]
pub struct AudioPacket {
    pub pts: u64,
    /// Opus 帧（20ms，与编码层 P1D 一致）。
    pub data: Vec<u8>,
}

/// 解码统计（扩展 `adaptive/report.rs` 既有 DecodeStats；P2B 接入 report）。
#[derive(Debug, Clone, Default)]
pub struct DecodeStats {
    pub frames_decoded: u64,
    pub frames_dropped: u64,
    pub avg_decode_ms: f64,
    pub max_decode_ms: f64,
    /// P2B 新增：IDR 请求次数（参考链断裂触发）。
    pub idr_requests: u64,
    /// P2B 新增：画面冻结次数（IDR 丢失等待恢复）。
    pub freeze_count: u64,
}

// ════════════════════════════════════════════════════════════════
// Trait
// ════════════════════════════════════════════════════════════════

/// 视频解码器 trait（对称编码层 [`VideoEncoder`](crate::encoder::VideoEncoder)）。
pub trait VideoDecoder: Send {
    /// 流式解码：喂入一帧 Annex B，返回 0..N 个解码帧。
    ///
    /// 流式语义：内部循环 `avcodec_receive_frame` 直到 EAGAIN。
    /// 一帧输入可能产出 0 帧（参考帧未就绪）、1 帧（远控 IPPP 常规）、N 帧
    /// （B 帧重排，远控禁用但兼容）。
    fn decode(&mut self, packet: &DecoderPacket) -> Result<Vec<DecodedFrame>, DecodeError>;

    /// extradata（SPS/PPS/VPS）变更时重配上下文。
    /// 编码侧分辨率/参数变更会随下一个 IDR 重发 extradata（编码层 Step 4）。
    fn update_extradata(&mut self, extradata: &[u8]) -> Result<(), DecodeError>;

    /// 刷新参考帧缓冲（请求关键帧前调用，或连接恢复时）。
    fn flush(&mut self);

    /// 上报连续解码错误（receive 异常时由上层调用），达阈值触发 IDR 请求。
    ///
    /// 返回 `true` 表示本次调用触发了关键帧请求（上层应发送 force_idr 控制
    /// 消息）。由 `VideoDecoderPipeline` 实现（P2B 接入 session）。
    fn report_error(&mut self) -> bool;

    /// 请求关键帧（IDR 丢失/参考链断裂）：flush（清参考帧缓冲）+ 统计
    /// （`idr_requests`/`freeze_count`）。
    ///
    /// 返回 `true` 表示已触发——上层应发送
    /// `ControlMessage::AdaptiveConfig{force_idr:true}` 让服务端强制下一帧
    /// IDR（M8-T014 自适应；P2B §T2.3 IDR 恢复策略）。
    fn request_keyframe(&mut self) -> bool;

    fn codec(&self) -> Codec; // H264 | H265
    fn is_hardware(&self) -> bool;
    /// 真实后端名（"h264_qsv" | "h264_cuvid" | "h264" | ...）。
    /// P2B 起返回 String：`VideoDecoderPipeline` 的后端名运行时才确定。
    fn name(&self) -> String;
    fn stats(&self) -> DecodeStats; // 供 ReportGenerator 读取
}

/// 音频解码器 trait（对称编码层 [`AudioEncoder`](crate::encoder::AudioEncoder)）。
pub trait AudioDecoder: Send {
    /// Opus 包（20ms）→ PCM（float32 interleaved stereo）。
    fn decode(&mut self, packet: &AudioPacket) -> Result<Vec<f32>, DecodeError>;
    fn sample_rate(&self) -> u32; // 48000
    fn channels(&self) -> u16; // 2
}

// ════════════════════════════════════════════════════════════════
// DecodeError
// ════════════════════════════════════════════════════════════════

/// 解码层错误（接口层定义，P2A §T1.1）。
#[derive(Debug, Clone)]
pub enum DecodeError {
    /// FFmpeg DLLs 未加载或函数未找到。
    InitFailed(String),
    /// 编解码器未找到或不支持。
    CodecNotFound(String),
    /// FFmpeg avcodec 返回错误。
    AvError(crate::ffmpeg::AvError),
    /// 码流数据无效或截断。
    InvalidData(String),
    /// 解码器未产出帧（EAGAIN/EOF，非错误但调用方需感知）。
    NoOutput,
    /// 分辨率不匹配或无效。
    InvalidDimensions(u32, u32),
    /// extradata 无效（SPS/PPS 解析失败）。
    InvalidExtradata(String),
    /// 当前平台不支持该能力（如 macOS/Linux 暂无音频播放实现，解码完成但
    /// 静音，视频/键鼠不受影响；P2C-mac/linux 阶段实现）。与
    /// [`CodecNotFound`](Self::CodecNotFound) 区分：后者指后端缺失，本变体
    /// 指平台级能力缺失。与编码层 [`EncodeError::UnsupportedPlatform`]
    /// (crate::encoder::EncodeError) 对称。
    UnsupportedPlatform(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::InitFailed(m) => write!(f, "decoder init failed: {}", m),
            DecodeError::CodecNotFound(m) => write!(f, "codec not found: {}", m),
            DecodeError::AvError(e) => write!(f, "avcodec error: {}", e),
            DecodeError::InvalidData(m) => write!(f, "invalid data: {}", m),
            DecodeError::NoOutput => write!(f, "decoder produced no output"),
            DecodeError::InvalidDimensions(w, h) => write!(f, "invalid dimensions: {}x{}", w, h),
            DecodeError::InvalidExtradata(m) => write!(f, "invalid extradata: {}", m),
            DecodeError::UnsupportedPlatform(m) => write!(f, "unsupported platform: {}", m),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<crate::ffmpeg::AvError> for DecodeError {
    fn from(e: crate::ffmpeg::AvError) -> Self {
        DecodeError::AvError(e)
    }
}

// ════════════════════════════════════════════════════════════════
// PTS 携带方案 A：frame_id 线性近似（P2A §T1.1 关键决策）
// ════════════════════════════════════════════════════════════════

/// 把 `frame_id` 线性映射为会话相对毫秒 PTS（方案 A，P2A 采用）。
///
/// 当前 wire 头部（M8-T013 §3.2，14B）无 PTS 字段，客户端单 `target_fps`
/// 下用 `frame_id × (1000/fps)` 近似即可。变帧率场景误差大（编码侧跳帧时
/// frame_id 不等间隔）；P2G 基准若验证 lip-sync 不达标，再升级方案 B
/// （wire 头加 `pts_low16`，需同步改 `transport/datagram.rs` + 编码侧）。
///
/// 实现为 `frame_id * 1000 / target_fps`（先乘后除，避免每帧截断误差；
/// 100/60fps → 1666ms）。`target_fps == 0` 防御返回 0（不 panic）。
pub fn frame_id_to_pts(frame_id: u64, target_fps: u32) -> u64 {
    if target_fps == 0 {
        return 0;
    }
    frame_id * 1000 / target_fps as u64
}

// ════════════════════════════════════════════════════════════════
// Tests（P2A §T1.1：接口层 5 例）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// DecodedFrame 可 Clone，rgba 数据完整。
    #[test]
    fn test_decoded_frame_clone() {
        let f = DecodedFrame {
            pts: 42,
            width: 4,
            height: 2,
            rgba: (0..32).map(|i| i as u8).collect(), // 32B = w×h×4
            is_key: true,
        };
        let c = f.clone();
        assert_eq!(c.pts, f.pts);
        assert_eq!(c.width, 4);
        assert_eq!(c.height, 2);
        assert_eq!(c.is_key, true);
        // rgba 长度 = w × h × 4，数据逐字节一致。
        assert_eq!(c.rgba.len(), 4 * 2 * 4);
        assert_eq!(c.rgba, f.rgba);
        // 修改副本不影响原帧（深拷贝语义）。
        let mut c2 = c.clone();
        c2.rgba[0] = 99;
        assert_eq!(f.rgba[0], 0);
    }

    /// is_key=true 时构造正确（IDR 标志）。
    #[test]
    fn test_decoder_packet_idr_flag() {
        let p = DecoderPacket {
            pts: 0,
            data: vec![0, 0, 0, 1, 0x65], // IDR NAL 起始码
            is_key: true,
            extradata: None,
        };
        assert!(p.is_key);
        assert!(p.extradata.is_none());
        assert_eq!(p.data.len(), 5);
        // 非关键帧标志翻转。
        let p2 = DecoderPacket { is_key: false, ..p };
        assert!(!p2.is_key);
    }

    /// 每变体 Display 输出可读。
    #[test]
    fn test_decode_error_display() {
        assert!(DecodeError::InitFailed("dll".into())
            .to_string()
            .contains("init failed"));
        assert!(DecodeError::CodecNotFound("h264".into())
            .to_string()
            .contains("codec not found"));
        assert!(DecodeError::AvError(crate::ffmpeg::AvError::NullPtr("ctx"))
            .to_string()
            .contains("avcodec error"));
        assert!(DecodeError::InvalidData("truncated".into())
            .to_string()
            .contains("invalid data"));
        assert!(DecodeError::NoOutput.to_string().contains("no output"));
        assert!(DecodeError::InvalidDimensions(0, 0)
            .to_string()
            .contains("invalid dimensions"));
        assert!(DecodeError::InvalidExtradata("empty".into())
            .to_string()
            .contains("invalid extradata"));
        assert!(DecodeError::UnsupportedPlatform("linux audio".into())
            .to_string()
            .contains("unsupported platform"));
        // std::error::Error 兼容（From<AvError> 链路）。
        fn takes_err(e: &dyn std::error::Error) -> String {
            e.to_string()
        }
        assert!(takes_err(&DecodeError::InvalidExtradata("x".into())).contains("extradata"));
    }

    /// Default 全零，idr_requests/freeze_count 默认 0。
    #[test]
    fn test_decode_stats_default() {
        let s = DecodeStats::default();
        assert_eq!(s.frames_decoded, 0);
        assert_eq!(s.frames_dropped, 0);
        assert_eq!(s.avg_decode_ms, 0.0);
        assert_eq!(s.max_decode_ms, 0.0);
        assert_eq!(s.idr_requests, 0);
        assert_eq!(s.freeze_count, 0);
    }

    /// frame_id=100, fps=60 → pts ≈ 1666ms（方案 A 线性映射）。
    #[test]
    fn test_frame_id_to_pts_linear() {
        assert_eq!(frame_id_to_pts(100, 60), 1666);
        // 帧率缩放线性。
        assert_eq!(frame_id_to_pts(60, 60), 1000);
        assert_eq!(frame_id_to_pts(1, 30), 33);
        // fps=0 防御：不 panic，返回 0。
        assert_eq!(frame_id_to_pts(100, 0), 0);
    }
}
