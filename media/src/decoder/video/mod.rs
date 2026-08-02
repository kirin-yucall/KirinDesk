//! 视频解码入口：流式管线 + extradata 管理 + IDR 恢复（M8-T015 P2B §T2.3）。
//!
//! # 流式核心（P2B 修复）
//!
//! 旧 `decoder.rs::decode()` 在 `send_packet` 后**只调用一次**
//! `avcodec_receive_frame`，会丢失 flush 期间缓存的帧。本管线改为
//! `send_packet` → 循环 `receive_frame` 直到 EAGAIN（[`VideoBackend::receive_frames`]）。
//!
//! # IDR 恢复策略（与传输层/自适应联动）
//!
//! ```text
//! 场景：服务端发 P1(IDR) → P2 → P3(P 丢失) → P4
//!                                 ▲
//!              FrameReassembly 超时丢弃 P3
//!
//! 客户端逻辑：
//!   1. FrameReassembly.cleanup() 丢弃 P3 → LossDetector 检测到 gap(P3)
//!   2. 解码 P4（P 帧参考 P3，但 P3 缺失）→ avcodec_receive_frame 报错或花屏
//!   3. 上层调用 VideoDecoderPipeline.report_error() → consecutive_errors++
//!   4. 达 3 次 → request_keyframe() → flush（清参考帧）+ stats.idr_requests++
//!   5. 上层检测到 idr_requests 增长 → 发送
//!      ControlMessage::AdaptiveConfig { force_idr: true, .. }
//!   6. 服务端（M8-T014 自适应）收到 → 强制下一帧 IDR
//!   7. 客户端收下一个 IDR → 正常解码恢复
//! ```
//!
//! **冻结语义**：IDR 丢失期间，客户端保留上一帧 DecodedFrame（不更新
//! client_frame()），UI 显示静态画面，避免花屏。

pub mod ffmpeg_hw;
pub mod ffmpeg_sw;

use super::factory::{
    blacklist_backend, fallback_chain_for, hw_decode_disabled, is_backend_blacklisted,
    software_decoder_name,
};
use crate::decoder::{DecodeError, DecodeStats, DecodedFrame, DecoderPacket, VideoDecoder};
use crate::encoder::types::Codec;

/// 内部后端 trait（ffmpeg_hw / ffmpeg_sw 实现）。
pub trait VideoBackend: Send {
    /// 按解码器名打开后端（hw device / hwframes 就绪才返回 Ok）。
    fn open(codec: Codec, decoder_name: &str) -> Result<Self, DecodeError>
    where
        Self: Sized;

    /// 送入一帧 Annex B（内部 `avcodec_send_packet` + EAGAIN drain 重试）。
    fn send_packet(&mut self, pkt: &DecoderPacket) -> Result<(), DecodeError>;

    /// 循环取帧直到 EAGAIN（一帧输入可能产出 0..N 帧）。
    fn receive_frames(&mut self) -> Result<Vec<DecodedFrame>, DecodeError>;

    /// extradata 变更：重配上下文（close + open）。
    fn update_extradata(&mut self, extradata: &[u8]) -> Result<(), DecodeError>;

    /// 刷新参考帧缓冲。
    fn flush(&mut self);

    fn name(&self) -> &str;
    fn is_hardware(&self) -> bool;
}

/// 视频解码管线：流式解码入口（接口层 [`VideoDecoder`] 的实现者）。
///
/// 按回退链创建后端（hw 失败逐项回退，软解兜底）；`decode` 做 extradata
/// 变更检测（幂等）+ 输入校验，然后流式 send/receive。
pub struct VideoDecoderPipeline {
    backend: Box<dyn VideoBackend>, // ffmpeg_hw 或 ffmpeg_sw
    codec: Codec,
    stats: DecodeStats,
    current_extradata: Option<Vec<u8>>,
    /// 连续解码错误计数（≥3 触发重建/flush + IDR 请求）。
    consecutive_errors: u32,
    /// 是否尚未成功送入任何包（首包必须是 IDR 或携带 extradata；
    /// 首包失败后 P 帧仍被拒——上层应等待首个 IDR，重建后端也依赖此语义）。
    first_packet: bool,
    /// 是否刚重建过后端（P0-2 静默零产出防护标记）：重建后的首个 IDR
    /// 产出 0 帧 → 计 1 次错误（防"open 成功但解码坏"的后端收包零产出、
    /// 无错误 → 永不重建）；首个 IDR 产出帧即清除。
    rebuilt: bool,
}

impl VideoDecoderPipeline {
    /// 按回退链创建后端，返回第一个可用的管线实例。
    ///
    /// 链形状：`fallback_chain_for(codec)`（qsv → cuvid → d3d11va → vt →
    /// vaapi → 软解）；`open` 真实可用性（hw device 创建失败 → 下一项）。
    pub fn new(codec: Codec) -> Result<Self, DecodeError> {
        // KIRIN_DISABLE_HW_DECODE=1（驱动损坏机器/CI）：解码链直接落软解，
        // 不再尝试任何 hw 后端（本机 qsv MFX -9 的 FFmpeg 失败路径偶发
        // 堆损坏崩溃，见 factory::hw_decode_disabled）。
        if hw_decode_disabled() {
            let name = software_decoder_name(codec);
            return match ffmpeg_sw::FfmpegSwDecoder::open(codec, name) {
                Ok(b) => {
                    tracing::info!(
                        "decoder pipeline: hw decode disabled (KIRIN_DISABLE_HW_DECODE) — selected software '{name}'"
                    );
                    Ok(Self::with_backend(Box::new(b), codec))
                }
                Err(e) => Err(e),
            };
        }
        for name in fallback_chain_for(codec) {
            // 进程级黑名单（P0-2/ZM-05）："open 成功但首帧解码失败"的 hw
            // 后端（本机 qsv MFX -9）跳过——重复尝试有 FFmpeg 失败路径
            // 堆损坏崩溃风险。
            if is_backend_blacklisted(name) {
                tracing::debug!("decoder pipeline: '{}' blacklisted, skipping", name);
                continue;
            }
            let backend: Box<dyn VideoBackend> = if *name == software_decoder_name(codec) {
                match ffmpeg_sw::FfmpegSwDecoder::open(codec, name) {
                    Ok(b) => Box::new(b),
                    Err(e) => {
                        tracing::debug!("decoder pipeline: sw '{}' failed: {e}", name);
                        continue;
                    }
                }
            } else {
                match ffmpeg_hw::FfmpegHwDecoder::open(codec, name) {
                    Ok(b) => Box::new(b),
                    Err(e) => {
                        tracing::debug!("decoder pipeline: hw '{}' failed: {e}", name);
                        continue;
                    }
                }
            };
            tracing::info!(
                "decoder pipeline: selected '{}' (hw={})",
                name,
                backend.is_hardware()
            );
            return Ok(Self {
                backend,
                codec,
                stats: DecodeStats::default(),
                current_extradata: None,
                consecutive_errors: 0,
                first_packet: true,
                rebuilt: false,
            });
        }
        Err(DecodeError::CodecNotFound(format!(
            "no video decoder available for {:?}",
            codec
        )))
    }

    /// 流式解码：喂入一帧 Annex B，返回 0..N 个解码帧。
    ///
    /// 0. 输入校验：空包 → `InvalidData`；**首包**（尚未成功送入任何包）非
    ///    IDR 且无 extradata → `InvalidData`（上层应等待首个 IDR；连接建立时
    ///    服务端必发 IDR）。
    /// 1. extradata 变更检测：变更 → 后端重配（close + open）；相同 → 跳过
    ///    （幂等）。
    /// 2. send + receive（流式循环到 EAGAIN）。
    /// 3. 统计：`frames_decoded += n`；有产出 → 连续错误清零。
    pub fn decode(&mut self, packet: &DecoderPacket) -> Result<Vec<DecodedFrame>, DecodeError> {
        // 0. 输入校验（首包非 IDR 且无 extradata → 等待首个 IDR）。
        if packet.data.is_empty() {
            return Err(DecodeError::InvalidData("empty packet".into()));
        }
        if self.first_packet
            && !packet.is_key
            && packet.extradata.is_none()
            && self.current_extradata.is_none()
        {
            return Err(DecodeError::InvalidData(
                "no extradata, first frame must be IDR".into(),
            ));
        }
        // 1. extradata 变更检测：变更 → 后端重配；相同 → 跳过（幂等）。
        if let Some(ed) = &packet.extradata {
            if self.current_extradata.as_deref() != Some(ed.as_slice()) {
                self.backend.update_extradata(ed)?;
                self.current_extradata = Some(ed.clone());
                tracing::info!("VideoDecoder: extradata updated ({}B)", ed.len());
            }
        }
        // 2. send + receive（流式）。
        let first_packet = self.first_packet;
        if let Err(e) = self.backend.send_packet(packet) {
            // P0-2 强化（ZM-05 回归暴露）：hw 后端**首帧即失败** = "open
            // 成功但解码坏"（本机 h264_qsv MFX 会话建不起来，首包才报
            // -9）——立即进程级黑名单 + 软解兜底，**不等 3 次错误阈值**：
            // 每次失败尝试都走 FFmpeg 失败路径，实测 3~17 次后偶发堆损坏
            // 原生崩溃（0xc0000005）。符合 try_rebuild 注释既定意图
            // "hw 首帧失败 → 回退软解"。
            if first_packet && self.backend.is_hardware() {
                self.rebuild_after_first_failure();
            }
            return Err(e);
        }
        self.first_packet = false;
        let frames = match self.backend.receive_frames() {
            Ok(f) => f,
            Err(e) => {
                // 同上：首帧 receive 失败同样视为后端损坏（MFX -9 可能在
                // get_buffer / 首帧产出路径暴露）。
                if first_packet && self.backend.is_hardware() {
                    self.rebuild_after_first_failure();
                }
                return Err(e);
            }
        };
        // 3. 统计 + 错误重置（空产出 = 解码器缓冲中，不计为错误）。
        self.stats.frames_decoded += frames.len() as u64;
        if !frames.is_empty() {
            self.consecutive_errors = 0;
            // 重建后的后端首个 IDR 产出帧 → 恢复（清除重建标记）。
            self.rebuilt = false;
        } else if packet.is_key && self.rebuilt {
            // P0-2 静默零产出防护：重建后的后端首个 IDR 仍 0 产出 → 计 1 次
            // 错误——"open 成功但解码坏"的后端（本机 h264_cuvid）收包后
            // 静默返回 Ok(空) 无错误，consecutive_errors 不涨 → 永不重建。
            // 非 IDR 空产出是正常"参考帧缓冲中"语义，不计。达阈值后由上层
            // report_error 再次触发重建（软解兜底）。
            self.consecutive_errors += 1;
            tracing::warn!(
                "VideoDecoder: rebuilt backend '{}' produced 0 frames on IDR (silent-zero guard)",
                self.backend.name()
            );
        }
        Ok(frames)
    }

    /// 测试/注入用：直接指定后端构造管线。
    /// `pub(crate)`：供 [`factory::create_software_decoder`](crate::decoder::factory::create_software_decoder)
    /// 显式软解构造（集成测试与上层显式软解入口，P0-2）。
    pub(crate) fn with_backend(backend: Box<dyn VideoBackend>, codec: Codec) -> Self {
        Self {
            backend,
            codec,
            stats: DecodeStats::default(),
            current_extradata: None,
            consecutive_errors: 0,
            first_packet: true,
            rebuilt: false,
        }
    }

    /// 按回退链重开后端（软解优先兜底）。
    /// [`report_error`](crate::decoder::VideoDecoder::report_error) 达阈值时调用。
    ///
    /// **P0-2 修复**：hw 后端连续失败 → **优先软解兜底**（符合注释既定意图
    /// "hw 首帧失败 → 回退软解"）。旧实现按链跳过当前项会落到下一个 open
    /// 成功的 hw 后端——R-06 设备串绑定后 h264_cuvid 也能 open 成功，但收包
    /// 后**静默零产出**（无错误）→ `consecutive_errors` 不涨 → 永不重建
    /// （本机实测：qsv MFX 会话失败 → 重建落 cuvid → 0 帧）。软解 open 失败
    /// 才回退原链其余 hw 项（黑名单项跳过）。
    fn try_rebuild(&mut self) -> Option<Box<dyn VideoBackend>> {
        let current = self.backend.name().to_string();
        let sw_name = software_decoder_name(self.codec);
        if current != sw_name {
            if let Ok(b) = ffmpeg_sw::FfmpegSwDecoder::open(self.codec, sw_name) {
                tracing::warn!(
                    "decoder rebuild: hw '{}' failed — rebuilt to software '{}'",
                    current,
                    sw_name
                );
                return Some(Box::new(b));
            }
        }
        // 软解不可用（或当前已是软解）→ 按回退链跳过当前项、软解项与
        // 黑名单项，逐项重开 hw。
        for name in fallback_chain_for(self.codec) {
            if *name == current || *name == sw_name || is_backend_blacklisted(name) {
                continue;
            }
            match ffmpeg_hw::FfmpegHwDecoder::open(self.codec, name) {
                Ok(b) => return Some(Box::new(b)),
                Err(e) => {
                    tracing::debug!("decoder rebuild: hw '{}' failed: {e}", name);
                    continue;
                }
            }
        }
        None
    }
    /// 首帧失败后的即时兜底（P0-2 强化 / ZM-05）：黑名单当前 hw 后端 +
    /// 立即重建（软解优先）。
    ///
    /// 与 `report_error` 的 3 次错误阈值互补：阈值路径应对中段瞬时错误
    /// （丢包/参考链断裂），本路径应对"open 成功但解码坏"的**确定性损坏**
    /// 后端（本机 qsv MFX -9）——每次失败尝试都走 FFmpeg 失败路径，实测
    /// 3~17 次后偶发堆损坏原生崩溃（0xc0000005），重复尝试不可接受。
    fn rebuild_after_first_failure(&mut self) {
        let broken = self.backend.name().to_string();
        blacklist_backend(&broken);
        if let Some(b) = self.try_rebuild() {
            tracing::warn!(
                "VideoDecoder: first-packet failure on '{}' — rebuilt to '{}' (broken backend blacklisted)",
                broken,
                b.name()
            );
            self.backend = b;
            // 新后端未应用 extradata 且未收包 → 置 None + first_packet
            // （强制下个带 extradata 的包重配；否则等首个 IDR 恢复）。
            self.current_extradata = None;
            self.first_packet = true;
            self.rebuilt = true;
        }
    }
}

impl VideoDecoder for VideoDecoderPipeline {
    fn decode(&mut self, p: &DecoderPacket) -> Result<Vec<DecodedFrame>, DecodeError> {
        self.decode(p)
    }

    fn update_extradata(&mut self, ed: &[u8]) -> Result<(), DecodeError> {
        if ed.is_empty() {
            return Err(DecodeError::InvalidExtradata("empty".into()));
        }
        self.backend.update_extradata(ed)?;
        self.current_extradata = Some(ed.to_vec());
        Ok(())
    }

    fn flush(&mut self) {
        self.backend.flush();
    }

    /// 上报连续错误，达阈值（≥3）触发 IDR 请求（flush + idr_requests++）。
    ///
    /// 连续错误**重建**（P2B §T2.3 文件清单「连续错误重建」）：硬件后端反复
    /// 失败（如 QSV `open2` 成功但首个 MFX 会话建不起来——本机实测场景）→
    /// 跳过当前后端按回退链重开（软解兜底），恢复旧 `decoder.rs` 的
    /// 「hw 首帧失败 → 回退软解」行为；重建后仍需 IDR 才能恢复解码。
    fn report_error(&mut self) -> bool {
        self.consecutive_errors += 1;
        if self.consecutive_errors >= 3 {
            if self.backend.is_hardware() {
                if let Some(b) = self.try_rebuild() {
                    tracing::warn!(
                        "VideoDecoder: backend '{}' failed {}× consecutively — rebuilt to '{}'",
                        self.backend.name(),
                        self.consecutive_errors,
                        b.name()
                    );
                    self.backend = b;
                    // 新后端未应用 extradata 且未收包 → 置 None + first_packet
                    // （强制下个带 extradata 的包重配；否则等首个 IDR 恢复）。
                    self.current_extradata = None;
                    self.first_packet = true;
                    // P0-2 静默零产出防护：重建后首个 IDR 若 0 产出计错误
                    // （见 decode() 空产出分支）。
                    self.rebuilt = true;
                }
            }
            self.request_keyframe();
            return true;
        }
        false
    }

    /// 请求关键帧（IDR 丢失/参考链断裂）：flush（清参考帧缓冲）+ 冻结统计。
    ///
    /// 返回 true 表示已触发——上层应发送
    /// `ControlMessage::AdaptiveConfig{force_idr:true}` 让服务端强制下一帧
    /// IDR（M8-T014 自适应；P2B §T2.3 IDR 恢复策略）。
    fn request_keyframe(&mut self) -> bool {
        self.backend.flush();
        self.stats.idr_requests += 1;
        self.stats.freeze_count += 1;
        self.consecutive_errors = 0;
        tracing::warn!("VideoDecoder: keyframe requested (flush + freeze)");
        true
    }

    fn codec(&self) -> Codec {
        self.codec
    }

    fn is_hardware(&self) -> bool {
        self.backend.is_hardware()
    }

    fn name(&self) -> String {
        self.backend.name().to_string()
    }

    fn stats(&self) -> DecodeStats {
        self.stats.clone()
    }
}

/// 从 Annex B 首帧提取 SPS+PPS（含起始码）——测试素材（extradata 重配验证）。
/// `pub(crate)`：供 `ffmpeg_hw` / `ffmpeg_sw` 两个子模块的测试共享。
#[cfg(test)]
pub(crate) fn extract_sps_pps(annexb: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 4 <= annexb.len() {
        // 查找起始码 00 00 00 01 / 00 00 01。
        let sc_len = if annexb[pos..].starts_with(&[0, 0, 0, 1]) {
            4
        } else if annexb[pos..].starts_with(&[0, 0, 1]) {
            3
        } else {
            pos += 1;
            continue;
        };
        let nal_start = pos + sc_len;
        if nal_start >= annexb.len() {
            break;
        }
        let nal_type = annexb[nal_start] & 0x1F;
        let next = annexb[nal_start..]
            .windows(4)
            .position(|w| w == [0, 0, 0, 1])
            .map(|i| nal_start + i)
            .or_else(|| {
                annexb[nal_start..]
                    .windows(3)
                    .position(|w| w == [0, 0, 1])
                    .map(|i| nal_start + i)
            })
            .unwrap_or(annexb.len());
        if nal_type == 7 || nal_type == 8 {
            out.extend_from_slice(&annexb[pos..next]);
        }
        if nal_type == 5 {
            break; // 到 IDR 为止（SPS/PPS 在其前）。
        }
        pos = next;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

// ════════════════════════════════════════════════════════════════
// Tests（P2A §T1.3 骨架 3 例 + P2B §T2.3 流水线 4 例）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::types::{GpuTexture, Timestamp};
    use crate::encoder::VideoEncoderPipeline;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// mock 后端：计数 `update_extradata` / `flush` 调用。
    struct MockBackend {
        extradata_updates: Arc<AtomicU32>,
        flushes: Arc<AtomicU32>,
    }

    impl VideoBackend for MockBackend {
        fn open(_codec: Codec, _decoder_name: &str) -> Result<Self, DecodeError>
        where
            Self: Sized,
        {
            Ok(Self {
                extradata_updates: Arc::new(AtomicU32::new(0)),
                flushes: Arc::new(AtomicU32::new(0)),
            })
        }
        fn send_packet(&mut self, _pkt: &DecoderPacket) -> Result<(), DecodeError> {
            Ok(())
        }
        fn receive_frames(&mut self) -> Result<Vec<DecodedFrame>, DecodeError> {
            Ok(vec![])
        }
        fn update_extradata(&mut self, _extradata: &[u8]) -> Result<(), DecodeError> {
            self.extradata_updates.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn flush(&mut self) {
            self.flushes.fetch_add(1, Ordering::SeqCst);
        }
        fn name(&self) -> &str {
            "mock"
        }
        fn is_hardware(&self) -> bool {
            false
        }
    }

    fn mock() -> (VideoDecoderPipeline, Arc<AtomicU32>, Arc<AtomicU32>) {
        let updates = Arc::new(AtomicU32::new(0));
        let flushes = Arc::new(AtomicU32::new(0));
        let mock = MockBackend {
            extradata_updates: Arc::clone(&updates),
            flushes: Arc::clone(&flushes),
        };
        (
            VideoDecoderPipeline::with_backend(Box::new(mock), Codec::H264),
            updates,
            flushes,
        )
    }

    /// 软编多帧，返回每帧 (Annex B, is_key)。
    /// `idr_every`：每隔多少帧强制一个 IDR（0 = 仅首帧）。
    fn encode_test_frames(
        rgba_frames: &[Vec<u8>],
        w: u32,
        h: u32,
        idr_every: usize,
    ) -> Option<Vec<(Vec<u8>, bool)>> {
        let mut pipe = VideoEncoderPipeline::new(Codec::H264, None).ok()?;
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let mut out = Vec::new();
        for (i, rgba) in rgba_frames.iter().enumerate() {
            let force_idr = if idr_every == 0 {
                i == 0
            } else {
                i % idr_every == 0
            };
            pipe.set_cpu_frame(rgba, w, h, force_idr);
            let packets = pipe
                .on_frame(
                    &tex,
                    Timestamp::new(std::time::Instant::now(), i as u64 * 16),
                )
                .ok()?;
            let mut data = Vec::new();
            let mut is_key = false;
            for p in &packets {
                data.extend_from_slice(&p.data);
                is_key |= p.is_key;
            }
            if data.is_empty() {
                return None;
            }
            out.push((data, is_key));
        }
        Some(out)
    }

    fn test_rgba(w: u32, h: u32, seed: u8) -> Vec<u8> {
        let mut rgba = vec![0u8; (w * h * 4) as usize];
        for y in 0..h {
            for x in 0..w {
                let i = ((y * w + x) * 4) as usize;
                rgba[i] = x as u8 ^ seed;
                rgba[i + 1] = y as u8 ^ seed;
                rgba[i + 2] = 128;
                rgba[i + 3] = 255;
            }
        }
        rgba
    }

    /// 创建不 panic（后端存在时）；无 FFmpeg DLL / 无解码器环境返回 Err。
    #[test]
    fn test_pipeline_new() {
        match VideoDecoderPipeline::new(Codec::H264) {
            Ok(pipe) => {
                assert_eq!(pipe.codec(), Codec::H264);
                assert!(!pipe.name().is_empty(), "应暴露真实后端名");
                let _ = pipe.is_hardware();
                let stats = pipe.stats();
                assert_eq!(stats.frames_decoded, 0);
            }
            Err(DecodeError::InitFailed(_)) | Err(DecodeError::CodecNotFound(_)) => {
                // 无 FFmpeg DLL / 无 H.264 解码器（CI 环境）：不 panic。
                eprintln!("VideoDecoderPipeline::new unavailable (no FFmpeg DLLs/decoders)");
            }
            Err(other) => panic!("期望 Ok 或 InitFailed/CodecNotFound，实际: {other}"),
        }
    }

    /// 相同 extradata 二次提交不重 open（幂等）；变更后重 open。
    #[test]
    fn test_pipeline_extradata_idempotent() {
        let (mut pipe, updates, _) = mock();

        let ed = vec![0u8, 0, 0, 1, 0x67, 1, 2, 3]; // SPS 模拟
        let pkt = DecoderPacket {
            pts: 0,
            data: vec![0, 0, 0, 1, 0x65, 9, 9], // IDR NAL 模拟
            is_key: true,
            extradata: Some(ed.clone()),
        };

        // 首次提交：extradata 变更 → update_extradata 1 次。
        let frames = pipe.decode(&pkt).expect("首次 decode 应成功");
        assert!(frames.is_empty());
        assert_eq!(updates.load(Ordering::SeqCst), 1);

        // 相同 extradata 二次提交：跳过重 open（幂等）。
        let frames = pipe
            .decode(&pkt)
            .expect("相同 extradata 二次 decode 应成功");
        assert!(frames.is_empty());
        assert_eq!(
            updates.load(Ordering::SeqCst),
            1,
            "相同 extradata 不应重 open"
        );

        // extradata 变更（SPS 参数更新）：再次重 open。
        let pkt2 = DecoderPacket {
            pts: 16,
            extradata: Some(vec![0, 0, 0, 1, 0x67, 9, 9, 9]),
            ..pkt
        };
        let _ = pipe.decode(&pkt2).expect("extradata 变更 decode 应成功");
        assert_eq!(updates.load(Ordering::SeqCst), 2, "extradata 变更应重 open");
    }

    /// 首帧非 IDR 且无 extradata → Err(InvalidData)；解出首帧后 P 帧放行
    /// （P2B 修复：旧校验会对后续所有 P 帧误伤）。
    #[test]
    fn test_pipeline_first_frame_must_be_idr() {
        let (mut pipe, _, _) = mock();
        let pkt = DecoderPacket {
            pts: 0,
            data: vec![0, 0, 0, 1, 0x41], // 非 IDR NAL（P 帧模拟）
            is_key: false,
            extradata: None,
        };
        match pipe.decode(&pkt) {
            Err(DecodeError::InvalidData(m)) => assert!(m.contains("IDR")),
            other => panic!("期望 InvalidData(no extradata...)，实际: {other:?}"),
        }
        // 空包 → InvalidData（不 panic）。
        let empty = DecoderPacket {
            data: vec![],
            is_key: true,
            extradata: None,
            ..pkt
        };
        assert!(matches!(
            pipe.decode(&empty),
            Err(DecodeError::InvalidData(_))
        ));
    }

    /// 输入 pts → 输出 DecodedFrame.pts 一致（真实后端，IPPP 无重排）。
    #[test]
    fn test_pipeline_pts_passthrough() {
        let mut pipe = match VideoDecoderPipeline::new(Codec::H264) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Skipping: no decoder available: {e}");
                return;
            }
        };
        let (w, h) = (160u32, 120u32);
        let Some(frames) = encode_test_frames(&[test_rgba(w, h, 2)], w, h, 0) else {
            eprintln!("Skipping: encoder not available");
            return;
        };
        let (data, is_key) = &frames[0];
        let pkt = DecoderPacket {
            pts: 777,
            data: data.clone(),
            is_key: *is_key,
            extradata: None,
        };
        // 本机 qsv 可能 open2 成功但解码必失败（MFX 会话不可用）→ 自动 skip。
        let out = match pipe.decode(&pkt) {
            Ok(out) => out,
            Err(e) => {
                eprintln!("Skipping: pipeline decode unavailable on this machine: {e}");
                return;
            }
        };
        assert!(!out.is_empty(), "IDR 应产出帧");
        assert_eq!(out[0].pts, 777, "PTS 应透传");
        assert_eq!(out[0].width, w);
        assert_eq!(out[0].height, h);
    }

    /// 3 次连续错误 → 触发 flush + idr_requests++（IDR 恢复阈值）。
    #[test]
    fn test_pipeline_consecutive_error_triggers_flush() {
        let (mut pipe, _, flushes) = mock();

        assert!(!pipe.report_error(), "1 次错误不应触发");
        assert!(!pipe.report_error(), "2 次错误不应触发");
        assert_eq!(flushes.load(Ordering::SeqCst), 0);

        assert!(pipe.report_error(), "3 次错误应触发 IDR 请求");
        assert_eq!(flushes.load(Ordering::SeqCst), 1, "触发时 flush 一次");
        let stats = pipe.stats();
        assert_eq!(stats.idr_requests, 1);
        assert_eq!(stats.freeze_count, 1, "IDR 等待期间计冻结一次");

        // 阈值已重置：再 2 次不触发。
        assert!(!pipe.report_error());
        assert!(!pipe.report_error());
        assert_eq!(flushes.load(Ordering::SeqCst), 1);
    }

    /// 编码 6 帧（每 3 帧一个 IDR）→ 管线解码 → 产出 ≥3 DecodedFrame。
    ///
    /// 环境差异：健康机（qsv 可用或软解）6/6；本机 qsv `open2` 成功但 MFX
    /// 会话建不起来 → 解码连续 3 错 → 管线重建为软解 → 下一个 IDR 恢复
    /// （P2B §T2.3 连续错误重建）。错误上报语义与 session.rs 一致。
    #[test]
    fn test_pipeline_full_roundtrip() {
        let mut pipe = match VideoDecoderPipeline::new(Codec::H264) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Skipping: no decoder available: {e}");
                return;
            }
        };
        let (w, h) = (320u32, 240u32);
        let inputs = vec![
            test_rgba(w, h, 1),
            test_rgba(w, h, 2),
            test_rgba(w, h, 3),
            test_rgba(w, h, 4),
            test_rgba(w, h, 5),
            test_rgba(w, h, 6),
        ];
        // 每 3 帧一个 IDR：本机 qsv 若 open2 成功但解码必失败（MFX 会话不可用），
        // 管线连续 3 错 → 重建为软解 → 下一个 IDR 恢复解码。
        let Some(enc) = encode_test_frames(&inputs, w, h, 3) else {
            eprintln!("Skipping: encoder not available");
            return;
        };
        let mut total = 0usize;
        for (i, (data, is_key)) in enc.iter().enumerate() {
            let pkt = DecoderPacket {
                pts: i as u64 * 16,
                data: data.clone(),
                is_key: *is_key,
                extradata: None,
            };
            match pipe.decode(&pkt) {
                Ok(out) => total += out.len(),
                Err(e) => {
                    // 与 session 一致：上报错误（连续 ≥3 → 重建/IDR 请求）。
                    let triggered = pipe.report_error();
                    eprintln!("frame {i} decode err: {e} (reported, idr={triggered})");
                }
            }
        }
        // 健康机 6 帧；本机（qsv MFX 不可用）重建后自 IDR 恢复 ≥3 帧。
        assert!(
            total >= 3,
            "应解出 ≥3 帧（含重建后 IDR 恢复），实际 {total}"
        );
        let stats = pipe.stats();
        assert_eq!(stats.frames_decoded, total as u64);
    }
}
