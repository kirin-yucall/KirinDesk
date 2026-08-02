//! FFmpeg 软解后端（M8-T015 P2B §T2.1，迁移自 decoder_legacy.rs）。
//!
//! 软解（`h264` / `hevc`）是回退链的兜底项：任何硬件解码器不可用时使用。
//! 解码侧软解 1080p 远程桌面帧率足够（通常 <5ms/帧）。
//!
//! # 流式核心（与旧单帧原型的差异，P2B §T2.1）
//!
//! | 维度 | 旧 `decode(data,w,h)` | 新流式 |
//! |------|----------------------|--------|
//! | receive 次数 | 1 次 | 循环到 EAGAIN |
//! | PTS | 无（固定 0） | 从 `AVFrame.pts` 读取 |
//! | extradata | 无管理 | [`update_extradata`] 重 open |
//! | 输入 | `(&[u8], u32, u32)` | `DecoderPacket{pts,data,is_key,extradata}` |
//! | 输出 | `Vec<u8>`（单帧 RGBA） | `Vec<DecodedFrame>` |
//! | thread_type | 0x08（仅 frame） | 0x02（slice，无重排，低延迟） |
//!
//! 输出 YUV420P swframe → sws_scale → RGBA。会话级常驻：上下文 open 一次，
//! 反复 send/receive。

use crate::decoder::video::VideoBackend;
use crate::decoder::{DecodeError, DecodedFrame, DecoderPacket};
use crate::encoder::types::Codec;
use crate::ffmpeg;
use std::ffi::{c_int, c_void};
use std::ptr;

/// AV_PKT_FLAG_KEY（libavcodec/packet.h）。
const AV_PKT_FLAG_KEY: c_int = 0x0001;
/// FF_THREAD_SLICE（libavcodec/avcodec.h）—— 远控用 slice 线程（无重排，低延迟）。
const FF_THREAD_SLICE: i64 = 0x02;

/// FFmpeg 软件解码后端（h264 / hevc）。
///
/// 输出 YUV420P swframe → sws_scale → RGBA。
/// 会话级常驻：上下文 open 一次，反复 send/receive。
pub struct FfmpegSwDecoder {
    ctx: *mut ffmpeg::AVCodecContext,
    codec: *const ffmpeg::AVCodec,
    decoder_name: String,
    /// 当前编解码器宽高（缓存）。
    codec_width: u32,
    codec_height: u32,
    /// sws_scale 上下文（YUV420P → RGBA）。
    sws_ctx: *mut ffmpeg::SwsContext,
    frame: *mut ffmpeg::AVFrame,
    packet: *mut ffmpeg::AVPacket,
}

unsafe impl Send for FfmpegSwDecoder {}

impl VideoBackend for FfmpegSwDecoder {
    /// 打开软解后端：find_decoder → alloc_context3 → 低延迟参数 → open2。
    fn open(codec: Codec, decoder_name: &str) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let _ = codec; // 解码器名已隐含 codec（h264/hevc）；保留参数供 trait 签名。
        ffmpeg::ensure_loaded()
            .map_err(|e| DecodeError::InitFailed(format!("FFmpeg DLLs not available: {e}")))?;
        let codec = ffmpeg::avcodec_find_decoder_by_name(decoder_name)
            .map_err(|_| DecodeError::CodecNotFound(decoder_name.to_string()))?;
        let mut ctx = ffmpeg::avcodec_alloc_context3(codec)?;

        // 低延迟参数（与编码侧对称）。
        let _ = ffmpeg::av_opt_set_int(ctx as *mut c_void, "threads", 2);
        // thread_type = FF_THREAD_SLICE（无重排，远控低延迟；旧原型用 0x08 frame）。
        let _ = ffmpeg::av_opt_set_int(ctx as *mut c_void, "thread_type", FF_THREAD_SLICE);
        ffmpeg::avcodec_open2(ctx, codec).map_err(|e| {
            ffmpeg::avcodec_free_context(&mut ctx);
            DecodeError::AvError(e)
        })?;
        let frame = ffmpeg::av_frame_alloc()?;
        let packet = ffmpeg::av_packet_alloc()?;
        tracing::debug!("FfmpegSwDecoder: opened '{decoder_name}' (thread_type=slice)");
        Ok(Self {
            ctx,
            codec,
            decoder_name: decoder_name.to_string(),
            codec_width: 0,
            codec_height: 0,
            sws_ctx: ptr::null_mut(),
            frame,
            packet,
        })
    }

    fn send_packet(&mut self, pkt: &DecoderPacket) -> Result<(), DecodeError> {
        if pkt.data.is_empty() {
            return Err(DecodeError::InvalidData("empty packet".into()));
        }
        unsafe {
            (*self.packet).data = pkt.data.as_ptr() as *mut u8;
            (*self.packet).size = pkt.data.len() as c_int;
            (*self.packet).pts = pkt.pts as i64;
            (*self.packet).dts = pkt.pts as i64;
            // AV_PKT_FLAG_KEY。
            (*self.packet).flags = if pkt.is_key { AV_PKT_FLAG_KEY } else { 0 };
        }
        // EAGAIN 时先 drain 再重试（迁移自 decoder_legacy.rs:317-338，修复流式）。
        self.send_with_drain()
    }

    fn receive_frames(&mut self) -> Result<Vec<DecodedFrame>, DecodeError> {
        let mut out = Vec::new();
        loop {
            match ffmpeg::avcodec_receive_frame(self.ctx, self.frame) {
                Ok(()) => {
                    // 读帧头字段（裸指针字段访问须在 unsafe 内）。
                    let (w, h, is_key, pts) = unsafe {
                        let w = (*self.frame).width as u32;
                        let h = (*self.frame).height as u32;
                        let is_key = (*self.frame).key_frame != 0;
                        let pts = (*self.frame).pts as u64;
                        (w, h, is_key, pts)
                    };
                    if w == 0 || h == 0 {
                        ffmpeg::av_frame_unref(self.frame);
                        continue;
                    }
                    self.ensure_sws(w, h)?;
                    let rgba = self.frame_to_rgba(w, h)?;
                    out.push(DecodedFrame {
                        pts,
                        width: w,
                        height: h,
                        rgba,
                        is_key,
                    });
                    ffmpeg::av_frame_unref(self.frame);
                }
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => break,
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EOF)) => break,
                // 损坏包：跳过（返回已累积帧，不 panic；连续损坏由上层计数重建）。
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_INVALIDDATA)) => {
                    tracing::debug!("FfmpegSwDecoder: invalid data skipped");
                    break;
                }
                Err(e) => return Err(DecodeError::AvError(e)),
            }
        }
        Ok(out)
    }

    fn update_extradata(&mut self, extradata: &[u8]) -> Result<(), DecodeError> {
        if extradata.is_empty() {
            return Err(DecodeError::InvalidExtradata("empty".into()));
        }
        // 重 open：close → 设新 extradata → open。
        let _ = ffmpeg::avcodec_close(self.ctx);
        ffmpeg::set_extradata(self.ctx, extradata)?;
        ffmpeg::avcodec_open2(self.ctx, self.codec).map_err(DecodeError::AvError)?;
        // 分辨率未知：强制 ensure_sws 重建。
        self.codec_width = 0;
        self.codec_height = 0;
        tracing::info!(
            "FfmpegSwDecoder: extradata updated ({}B) + reopened",
            extradata.len()
        );
        Ok(())
    }

    fn flush(&mut self) {
        ffmpeg::avcodec_flush_buffers(self.ctx);
    }

    fn name(&self) -> &str {
        &self.decoder_name
    }

    fn is_hardware(&self) -> bool {
        false
    }
}

impl FfmpegSwDecoder {
    /// 发送失败时先 drain 解码器再重试（decoder_legacy.rs 迁移）。
    ///
    /// - `EAGAIN`：解码器缓冲满 → 循环 receive 清空后重发。
    /// - `EOF`：解码器已结束 → flush 后重发。
    /// - `INVALIDDATA`：损坏包 → 跳过（返回 Ok，上层计连续错误）。
    fn send_with_drain(&mut self) -> Result<(), DecodeError> {
        match ffmpeg::avcodec_send_packet(self.ctx, self.packet) {
            Ok(()) => {}
            Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => {
                loop {
                    match ffmpeg::avcodec_receive_frame(self.ctx, self.frame) {
                        Ok(()) => {
                            // 丢弃被 drain 的帧（返回路径在 receive_frames）。
                            ffmpeg::av_frame_unref(self.frame);
                        }
                        Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => {
                            // 清空后重发。
                            ffmpeg::avcodec_send_packet(self.ctx, self.packet)?;
                            break;
                        }
                        Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EOF)) => {
                            ffmpeg::avcodec_flush_buffers(self.ctx);
                            ffmpeg::avcodec_send_packet(self.ctx, self.packet)?;
                            break;
                        }
                        Err(e) => return Err(DecodeError::AvError(e)),
                    }
                }
            }
            // 损坏包：跳过（不 panic）。
            Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_INVALIDDATA)) => {
                tracing::debug!("FfmpegSwDecoder: send skipped invalid packet");
            }
            Err(e) => return Err(DecodeError::AvError(e)),
        }
        // 释放 packet 内部引用（data 指向调用方缓冲，不能 free，只 unref buf）。
        ffmpeg::av_packet_unref(self.packet);
        Ok(())
    }

    /// 确保 sws_scale 上下文匹配当前宽高（YUV420P → RGBA）。
    fn ensure_sws(&mut self, width: u32, height: u32) -> Result<(), DecodeError> {
        if !self.sws_ctx.is_null() && self.codec_width == width && self.codec_height == height {
            return Ok(());
        }
        if !self.sws_ctx.is_null() {
            ffmpeg::sws_freeContext(self.sws_ctx);
            self.sws_ctx = ptr::null_mut();
        }
        self.sws_ctx = ffmpeg::sws_getContext(
            width as i32,
            height as i32,
            ffmpeg::AV_PIX_FMT_YUV420P,
            width as i32,
            height as i32,
            ffmpeg::AV_PIX_FMT_RGBA,
            ffmpeg::SWS_BILINEAR,
        )
        .map_err(|e| DecodeError::InitFailed(format!("sws_getContext: {e}")))?;
        self.codec_width = width;
        self.codec_height = height;
        Ok(())
    }

    /// 当前帧（YUV420P）→ RGBA。
    fn frame_to_rgba(&mut self, width: u32, height: u32) -> Result<Vec<u8>, DecodeError> {
        let dst_stride = (width * 4) as i32;
        let buf_size = (dst_stride * height as i32) as usize;
        let mut rgba = vec![0u8; buf_size];
        let dst_data: [*mut u8; 4] = [
            rgba.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        ];
        let dst_stride_arr: [i32; 4] = [dst_stride, 0, 0, 0];

        unsafe {
            let src_data: [*const u8; 4] = [
                (*self.frame).data[0],
                (*self.frame).data[1],
                (*self.frame).data[2],
                ptr::null(),
            ];
            let src_stride: [i32; 4] = [
                (*self.frame).linesize[0],
                (*self.frame).linesize[1],
                (*self.frame).linesize[2],
                0,
            ];
            let ret = ffmpeg::sws_scale(
                self.sws_ctx,
                &src_data,
                &src_stride,
                0,
                height as i32,
                &dst_data,
                &dst_stride_arr,
            )
            .map_err(DecodeError::AvError)?;
            if ret != height as i32 {
                tracing::warn!(
                    "FfmpegSwDecoder: sws_scale returned {} lines, expected {}",
                    ret,
                    height
                );
            }
        }
        Ok(rgba)
    }
}

impl Drop for FfmpegSwDecoder {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // 1. drain 解码器（flush 尾帧）。
            let _ = ffmpeg::avcodec_send_null_packet(self.ctx);
            loop {
                match ffmpeg::avcodec_receive_frame(self.ctx, self.frame) {
                    Ok(()) => {
                        ffmpeg::av_frame_unref(self.frame);
                    }
                    Err(_) => break,
                }
            }
            ffmpeg::avcodec_free_context(&mut self.ctx);
        }
        if !self.sws_ctx.is_null() {
            ffmpeg::sws_freeContext(self.sws_ctx);
        }
        ffmpeg::av_frame_free(&mut self.frame);
        ffmpeg::av_packet_free(&mut self.packet);
    }
}

// ════════════════════════════════════════════════════════════════
// Tests（P2B §T2.1：软解 7 例）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::types::{GpuTexture, Timestamp};
    use crate::encoder::VideoEncoderPipeline;

    /// 无 DLL/libx264 时返回 None（测试据此 skip），沿用旧 decoder.rs 模式。
    fn encode_test_frames(rgba_frames: &[Vec<u8>], w: u32, h: u32) -> Option<Vec<(Vec<u8>, bool)>> {
        let mut pipe = VideoEncoderPipeline::new(Codec::H264, None).ok()?;
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let mut out = Vec::new();
        for (i, rgba) in rgba_frames.iter().enumerate() {
            pipe.set_cpu_frame(rgba, w, h, i == 0);
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

    /// 从 Annex B 首帧提取 SPS+PPS（含起始码），作为 extradata 测试素材
    /// （共享助手在 `video/mod.rs`）。
    fn extract_sps_pps(annexb: &[u8]) -> Option<Vec<u8>> {
        crate::decoder::video::extract_sps_pps(annexb)
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

    /// 创建成功（FFmpeg 可用时）。
    #[test]
    fn test_sw_decode_create() {
        match FfmpegSwDecoder::open(Codec::H264, "h264") {
            Ok(dec) => {
                assert_eq!(dec.name(), "h264");
                assert!(!dec.is_hardware());
            }
            Err(e) => eprintln!("sw decoder not available: {e} (skip)"),
        }
    }

    /// 编码一帧 → 解码 → RGBA 尺寸正确（迁移自旧 test_encode_decode_roundtrip）。
    #[test]
    fn test_sw_decode_roundtrip() {
        let mut dec = match FfmpegSwDecoder::open(Codec::H264, "h264") {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Skipping: h264 decoder not available: {e}");
                return;
            }
        };
        let (w, h) = (320u32, 240u32);
        let rgba = test_rgba(w, h, 7);
        let Some(frames) = encode_test_frames(&[rgba], w, h) else {
            eprintln!("Skipping: encoder not available");
            return;
        };
        let (data, is_key) = &frames[0];
        assert!(is_key, "首帧应为 IDR");
        assert!(data.len() > 10);

        let pkt = DecoderPacket {
            pts: 0,
            data: data.clone(),
            is_key: *is_key,
            extradata: None,
        };
        dec.send_packet(&pkt).expect("send 应成功");
        let out = dec.receive_frames().expect("receive 应成功");
        assert!(!out.is_empty(), "IDR 首帧应产出至少 1 帧");
        let df = &out[0];
        assert_eq!(df.width, w);
        assert_eq!(df.height, h);
        assert_eq!(df.rgba.len(), (w * h * 4) as usize);
        // 非空白。
        assert!(df.rgba.iter().any(|&b| b != 0), "解码帧不应全零");
    }

    /// 连续 send 多帧 → receive 累积产出（验证循环 receive 到 EAGAIN）。
    #[test]
    fn test_sw_streaming_multi_output() {
        let mut dec = match FfmpegSwDecoder::open(Codec::H264, "h264") {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Skipping: h264 decoder not available: {e}");
                return;
            }
        };
        let (w, h) = (320u32, 240u32);
        let frames = vec![test_rgba(w, h, 1), test_rgba(w, h, 2), test_rgba(w, h, 3)];
        let Some(enc) = encode_test_frames(&frames, w, h) else {
            eprintln!("Skipping: encoder not available");
            return;
        };
        let mut total = 0usize;
        let mut pts_ok = true;
        for (i, (data, is_key)) in enc.iter().enumerate() {
            let pkt = DecoderPacket {
                pts: i as u64 * 16,
                data: data.clone(),
                is_key: *is_key,
                extradata: None,
            };
            dec.send_packet(&pkt).expect("send 应成功");
            let out = dec.receive_frames().expect("receive 应成功");
            total += out.len();
            for df in &out {
                pts_ok &= df.pts == i as u64 * 16;
            }
        }
        assert!(total >= 3, "3 帧 IPPP 应产出 ≥3 帧，实际 {total}");
        assert!(pts_ok, "IPPP 每帧 pts 应透传");
    }

    /// 输入 pts=12345 → 输出 DecodedFrame.pts=12345。
    #[test]
    fn test_sw_pts_passthrough() {
        let mut dec = match FfmpegSwDecoder::open(Codec::H264, "h264") {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Skipping: h264 decoder not available: {e}");
                return;
            }
        };
        let (w, h) = (160u32, 120u32);
        let Some(frames) = encode_test_frames(&[test_rgba(w, h, 9)], w, h) else {
            eprintln!("Skipping: encoder not available");
            return;
        };
        let (data, is_key) = &frames[0];
        let pkt = DecoderPacket {
            pts: 12345,
            data: data.clone(),
            is_key: *is_key,
            extradata: None,
        };
        dec.send_packet(&pkt).unwrap();
        let out = dec.receive_frames().unwrap();
        assert!(!out.is_empty());
        assert_eq!(out[0].pts, 12345);
    }

    /// 损坏包 → 不 panic，返回空 vec。
    #[test]
    fn test_sw_invalid_packet_skipped() {
        let mut dec = match FfmpegSwDecoder::open(Codec::H264, "h264") {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Skipping: h264 decoder not available: {e}");
                return;
            }
        };
        let garbage = DecoderPacket {
            pts: 0,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03],
            is_key: true,
            extradata: None,
        };
        // 不 panic；返回 Ok（send 或 receive 侧跳过）。
        let _ = dec.send_packet(&garbage);
        let _ = dec.receive_frames();

        // 损坏后仍可恢复（下一包为合法 IDR）。
        let (w, h) = (160u32, 120u32);
        let Some(frames) = encode_test_frames(&[test_rgba(w, h, 4)], w, h) else {
            return;
        };
        let (data, is_key) = &frames[0];
        let pkt = DecoderPacket {
            pts: 16,
            data: data.clone(),
            is_key: *is_key,
            extradata: None,
        };
        dec.send_packet(&pkt).unwrap();
        let out = dec.receive_frames().unwrap();
        assert!(!out.is_empty(), "损坏包后合法 IDR 应恢复解码");
    }

    /// update_extradata 后解码正常（extradata 重配 → close + open）。
    #[test]
    fn test_sw_extradata_reopen() {
        let mut dec = match FfmpegSwDecoder::open(Codec::H264, "h264") {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Skipping: h264 decoder not available: {e}");
                return;
            }
        };
        let (w, h) = (320u32, 240u32);
        let Some(frames) = encode_test_frames(&[test_rgba(w, h, 5)], w, h) else {
            eprintln!("Skipping: encoder not available");
            return;
        };
        let (data, _) = &frames[0];
        let Some(ed) = extract_sps_pps(data) else {
            eprintln!("Skipping: no SPS/PPS in bitstream");
            return;
        };
        dec.update_extradata(&ed).expect("extradata 重配应成功");

        // 重配后仍能解码。
        let pkt = DecoderPacket {
            pts: 0,
            data: data.clone(),
            is_key: true,
            extradata: None,
        };
        dec.send_packet(&pkt).unwrap();
        let out = dec.receive_frames().unwrap();
        assert!(!out.is_empty(), "extradata 重配后应恢复解码");

        // 空 extradata → InvalidExtradata。
        assert!(matches!(
            dec.update_extradata(&[]),
            Err(DecodeError::InvalidExtradata(_))
        ));
    }

    /// 解码器 thread_type=0x02（slice 线程，无重排）。
    #[test]
    fn test_sw_thread_type_slice() {
        let dec = match FfmpegSwDecoder::open(Codec::H264, "h264") {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Skipping: h264 decoder not available: {e}");
                return;
            }
        };
        let mut thread_type: i64 = -1;
        match ffmpeg::av_opt_get_int(dec.ctx as *mut c_void, "thread_type", &mut thread_type) {
            Ok(()) => assert_eq!(
                thread_type, FF_THREAD_SLICE,
                "thread_type 应为 0x02 (slice)"
            ),
            Err(e) => {
                // 个别 FFmpeg 构建不允许读回该选项：跳过（配置已在 open 时 av_opt_set）。
                eprintln!("av_opt_get_int(thread_type) unavailable: {e} (skip)");
            }
        }
    }
}
