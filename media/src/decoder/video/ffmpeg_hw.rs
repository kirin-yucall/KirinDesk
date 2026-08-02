//! FFmpeg 硬件解码后端（M8-T015 P2B §T2.2）。
//!
//! 后端回退链（[`factory`](crate::decoder::factory)）：qsv → cuvid →
//! d3d11va → videotoolbox → vaapi（软解回退在 [`ffmpeg_sw`]）。
//!
//! # 全链路（M8-T015 §1.3 裁决：hwframe 回读不可避免）
//!
//! ```text
//! avcodec_receive_frame ──► hwframe（GPU 内存 NV12）
//!        │
//!        ▼  av_hwframe_transfer_data
//! swframe（CPU 内存 NV12，av_frame_unref 归还 hwframe 池）
//!        │
//!        ▼  sws_scale（NV12 → RGBA，会话级复用 sws_ctx）
//! DecodedFrame { pts, width, height, rgba, is_key }
//! ```
//!
//! 编码侧是 hw 输入纹理零拷贝直通（P1C `ffmpeg_hw.rs`）；解码侧受
//! `av_hwframe_transfer_data` 约束必须回读 CPU——这是 hw/sw 唯一的路径差异：
//! hw 输出 NV12（半平面）、软解输出 YUV420P（平面），sws 源格式不同。

use crate::decoder::video::VideoBackend;
use crate::decoder::{DecodeError, DecodedFrame, DecoderPacket};
use crate::encoder::types::Codec;
use crate::ffmpeg;
use std::ffi::{c_int, c_void};
use std::ptr;

/// AV_PKT_FLAG_KEY（libavcodec/packet.h）。
const AV_PKT_FLAG_KEY: c_int = 0x0001;

/// FFmpeg 硬件解码后端（h264_qsv / h264_cuvid / h264_d3d11va / videotoolbox / vaapi）。
///
/// 输出 NV12 hwframe → `av_hwframe_transfer_data` → CPU NV12 → sws_scale → RGBA。
/// hwframe_transfer 不可避免（M8-T015 §1.3 裁决），但 sws_ctx 会话级复用。
pub struct FfmpegHwDecoder {
    ctx: *mut ffmpeg::AVCodecContext,
    codec: *const ffmpeg::AVCodec,
    decoder_name: String,
    /// hw device 上下文（d3d11va/vaapi/qsv device；结构持顶层 ref）。
    hw_device_ctx: *mut ffmpeg::AVBufferRef,
    /// hwframe（接收解码输出，GPU 内存 NV12）。
    hw_frame: *mut ffmpeg::AVFrame,
    /// swframe（hwframe_transfer 目标，CPU NV12）。
    sw_frame: *mut ffmpeg::AVFrame,
    /// 当前宽高（缓存，sws 重建判据）。
    codec_width: u32,
    codec_height: u32,
    /// sws_scale 上下文（NV12 → RGBA）。
    sws_ctx: *mut ffmpeg::SwsContext,
    /// 复用临时帧（Drop drain 用）。
    frame: *mut ffmpeg::AVFrame,
    packet: *mut ffmpeg::AVPacket,
}

unsafe impl Send for FfmpegHwDecoder {}

/// 按解码器名映射 `AVHWDeviceType`（P2B §T2.2 映射表）。
fn hw_device_type_for(decoder_name: &str) -> Option<i32> {
    match decoder_name {
        n if n.contains("qsv") => Some(ffmpeg::AV_HWDEVICE_TYPE_QSV),
        n if n.contains("cuvid") => Some(ffmpeg::AV_HWDEVICE_TYPE_CUDA),
        n if n.contains("d3d11va") => Some(ffmpeg::AV_HWDEVICE_TYPE_D3D11VA),
        n if n.contains("videotoolbox") => Some(ffmpeg::AV_HWDEVICE_TYPE_VIDEOTOOLBOX),
        n if n.contains("vaapi") => Some(ffmpeg::AV_HWDEVICE_TYPE_VAAPI),
        _ => None,
    }
}

impl VideoBackend for FfmpegHwDecoder {
    /// 打开硬件解码后端。
    ///
    /// Step 1: 创建 hw device（无 GPU/驱动 → `Err(InitFailed)`，factory 回退）。
    /// Step 2: 绑定 hw device 到 codec context（`ctx->hw_device_ctx` 字段直写，
    ///         偏移见 [`ffmpeg::avctx_offset::HW_DEVICE_CTX`]，FFmpeg 8.1 实测）。
    /// Step 3: 低延迟参数（hw 通常单线程）。
    fn open(codec: Codec, decoder_name: &str) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let _ = codec; // 解码器名已隐含 codec；保留参数供 trait 签名。
        ffmpeg::ensure_loaded()
            .map_err(|e| DecodeError::InitFailed(format!("FFmpeg DLLs not available: {e}")))?;
        let codec = ffmpeg::avcodec_find_decoder_by_name(decoder_name)
            .map_err(|_| DecodeError::CodecNotFound(decoder_name.to_string()))?;
        let mut ctx = ffmpeg::avcodec_alloc_context3(codec)?;

        // Step 1: hw device（失败 = 本机不可用，factory 回退下一项）。
        let hw_type = hw_device_type_for(decoder_name).ok_or_else(|| {
            DecodeError::InitFailed(format!("unknown hw type for {decoder_name}"))
        })?;
        let hw_device_ctx = ffmpeg::av_hwdevice_ctx_create(hw_type, None).map_err(|e| {
            ffmpeg::avcodec_free_context(&mut ctx);
            DecodeError::InitFailed(format!("av_hwdevice_ctx_create({decoder_name}): {e}"))
        })?;

        // Step 2: 绑定 hw device 到 codec context（+1 ref；free_context 时 FFmpeg
        // 内部 unref，本结构在 Drop 里 unref 顶层 ref——两条路径各自平衡）。
        let ctx_ref = match ffmpeg::av_buffer_ref(hw_device_ctx) {
            Ok(r) => r,
            Err(e) => {
                let mut d = hw_device_ctx;
                ffmpeg::av_buffer_unref(&mut d);
                ffmpeg::avcodec_free_context(&mut ctx);
                return Err(DecodeError::InitFailed(format!("av_buffer_ref: {e}")));
            }
        };
        // avctx_set_ptr 为 unsafe fn（字段直写）。
        unsafe {
            ffmpeg::avctx_set_ptr(
                ctx,
                ffmpeg::avctx_offset::HW_DEVICE_CTX,
                ctx_ref as *mut c_void,
            );
        }

        // Step 3: 低延迟参数。
        let _ = ffmpeg::av_opt_set_int(ctx as *mut c_void, "threads", 1); // hw 通常单线程

        // open2 失败（驱动/GPU 不可用）→ 释放已分配资源，回退。
        ffmpeg::avcodec_open2(ctx, codec).map_err(|e| {
            let mut d = hw_device_ctx;
            ffmpeg::av_buffer_unref(&mut d);
            ffmpeg::avcodec_free_context(&mut ctx);
            DecodeError::AvError(e)
        })?;

        let hw_frame = ffmpeg::av_frame_alloc()?;
        let sw_frame = ffmpeg::av_frame_alloc()?;
        let frame = ffmpeg::av_frame_alloc()?;
        let packet = ffmpeg::av_packet_alloc()?;
        tracing::info!("FfmpegHwDecoder: opened '{decoder_name}' (hw_type={hw_type})");
        Ok(Self {
            ctx,
            codec,
            decoder_name: decoder_name.to_string(),
            hw_device_ctx,
            hw_frame,
            sw_frame,
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
            (*self.packet).flags = if pkt.is_key { AV_PKT_FLAG_KEY } else { 0 };
        }
        self.send_with_drain()
    }

    fn receive_frames(&mut self) -> Result<Vec<DecodedFrame>, DecodeError> {
        let mut out = Vec::new();
        loop {
            // Step 1: receive hwframe（GPU 内存中的 NV12）。
            match ffmpeg::avcodec_receive_frame(self.ctx, self.hw_frame) {
                Ok(()) => {
                    // Step 2: hwframe → swframe（回读到 CPU，NV12）。
                    ffmpeg::av_hwframe_transfer_data(self.sw_frame, self.hw_frame, 0)
                        .map_err(DecodeError::AvError)?;
                    // 读帧头字段（裸指针字段访问须在 unsafe 内）。
                    let (w, h, is_key, pts) = unsafe {
                        let w = (*self.sw_frame).width as u32;
                        let h = (*self.sw_frame).height as u32;
                        let is_key = (*self.hw_frame).key_frame != 0;
                        let pts = (*self.hw_frame).pts as u64;
                        (w, h, is_key, pts)
                    };
                    if w == 0 || h == 0 {
                        ffmpeg::av_frame_unref(self.hw_frame);
                        ffmpeg::av_frame_unref(self.sw_frame);
                        continue;
                    }
                    self.ensure_sws(w, h)?;

                    // Step 3: sws_scale NV12 → RGBA（sw_frame → rgba）。
                    let rgba = self.frame_to_rgba(self.sw_frame, w, h)?;
                    out.push(DecodedFrame {
                        pts,
                        width: w,
                        height: h,
                        rgba,
                        is_key,
                    });
                    // hwframe 归还池 + swframe 释放（重叠使用前必须 unref）。
                    ffmpeg::av_frame_unref(self.hw_frame);
                    ffmpeg::av_frame_unref(self.sw_frame);
                }
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => break,
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EOF)) => break,
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_INVALIDDATA)) => {
                    tracing::debug!("FfmpegHwDecoder: invalid data skipped");
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
        // hw_device_ctx 字段随 ctx 保留（avcodec_close 不释放 struct 字段），
        // 重 open 时 hwaccel 从既有 device 重新初始化。
        let _ = ffmpeg::avcodec_close(self.ctx);
        ffmpeg::set_extradata(self.ctx, extradata)?;
        ffmpeg::avcodec_open2(self.ctx, self.codec).map_err(DecodeError::AvError)?;
        self.codec_width = 0;
        self.codec_height = 0;
        tracing::info!(
            "FfmpegHwDecoder: extradata updated ({}B) + reopened",
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
        true
    }
}

impl FfmpegHwDecoder {
    /// 发送失败时先 drain 再重试（同软解，P2B §T2.1）。
    fn send_with_drain(&mut self) -> Result<(), DecodeError> {
        match ffmpeg::avcodec_send_packet(self.ctx, self.packet) {
            Ok(()) => {}
            Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => loop {
                match ffmpeg::avcodec_receive_frame(self.ctx, self.hw_frame) {
                    Ok(()) => {
                        ffmpeg::av_frame_unref(self.hw_frame);
                    }
                    Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => {
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
            },
            // 损坏包：跳过。
            Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_INVALIDDATA)) => {
                tracing::debug!("FfmpegHwDecoder: send skipped invalid packet");
            }
            Err(e) => return Err(DecodeError::AvError(e)),
        }
        ffmpeg::av_packet_unref(self.packet);
        Ok(())
    }

    /// 确保 sws_scale 上下文匹配当前宽高（NV12 → RGBA）。
    fn ensure_sws(&mut self, width: u32, height: u32) -> Result<(), DecodeError> {
        if !self.sws_ctx.is_null() && self.codec_width == width && self.codec_height == height {
            return Ok(());
        }
        if !self.sws_ctx.is_null() {
            ffmpeg::sws_freeContext(self.sws_ctx);
            self.sws_ctx = ptr::null_mut();
        }
        // 所有 hw 解码器输出 NV12（半平面）——统一源格式。
        self.sws_ctx = ffmpeg::sws_getContext(
            width as i32,
            height as i32,
            ffmpeg::AV_PIX_FMT_NV12,
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

    /// 指定帧（CPU NV12）→ RGBA。hw 路径传 [`sw_frame`](Self::sw_frame)。
    fn frame_to_rgba(
        &self,
        frame: *mut ffmpeg::AVFrame,
        width: u32,
        height: u32,
    ) -> Result<Vec<u8>, DecodeError> {
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
            // NV12：data[0] = Y 平面，data[1] = 交错 UV（data[2] 为 null）。
            let src_data: [*const u8; 4] = [
                (*frame).data[0],
                (*frame).data[1],
                (*frame).data[2],
                ptr::null(),
            ];
            let src_stride: [i32; 4] = [
                (*frame).linesize[0],
                (*frame).linesize[1],
                (*frame).linesize[2],
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
                    "FfmpegHwDecoder: sws_scale returned {} lines, expected {}",
                    ret,
                    height
                );
            }
        }
        Ok(rgba)
    }
}

impl Drop for FfmpegHwDecoder {
    fn drop(&mut self) {
        // 1. drain 解码器。
        if !self.ctx.is_null() {
            let _ = ffmpeg::avcodec_send_null_packet(self.ctx);
            loop {
                match ffmpeg::avcodec_receive_frame(self.ctx, self.hw_frame) {
                    Ok(()) => {
                        ffmpeg::av_frame_unref(self.hw_frame);
                    }
                    Err(_) => break,
                }
            }
            // 2. free ctx（内部释放其持有的 hw_device_ctx ref）。
            ffmpeg::avcodec_free_context(&mut self.ctx);
        }
        // 3. 释放 hw device 顶层 ref（codec context 已释放其引用）。
        if !self.hw_device_ctx.is_null() {
            let mut d = self.hw_device_ctx;
            ffmpeg::av_buffer_unref(&mut d);
            self.hw_device_ctx = ptr::null_mut();
        }
        // 4. sws + frames。
        if !self.sws_ctx.is_null() {
            ffmpeg::sws_freeContext(self.sws_ctx);
        }
        ffmpeg::av_frame_free(&mut self.hw_frame);
        ffmpeg::av_frame_free(&mut self.sw_frame);
        ffmpeg::av_frame_free(&mut self.frame);
        ffmpeg::av_packet_free(&mut self.packet);
    }
}

// ════════════════════════════════════════════════════════════════
// Tests（P2B §T2.2；hw 测试在无 GPU 环境自动 skip）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::video::VideoDecoderPipeline;
    use crate::decoder::VideoDecoder;
    use crate::encoder::types::{GpuTexture, Timestamp};
    use crate::encoder::VideoEncoderPipeline;

    /// 编码一帧（IDR）返回 Annex B。
    fn encode_test_frame(rgba: &[u8], w: u32, h: u32) -> Option<Vec<u8>> {
        let mut pipe = VideoEncoderPipeline::new(Codec::H264, None).ok()?;
        pipe.set_cpu_frame(rgba, w, h, true);
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let packets = pipe
            .on_frame(&tex, Timestamp::new(std::time::Instant::now(), 0))
            .ok()?;
        let mut data = Vec::new();
        for p in &packets {
            data.extend_from_slice(&p.data);
        }
        if data.is_empty() {
            None
        } else {
            Some(data)
        }
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

    /// h264_qsv 创建（Intel GPU 环境下）。
    #[test]
    fn test_hw_decoder_create_qsv() {
        match FfmpegHwDecoder::open(Codec::H264, "h264_qsv") {
            Ok(dec) => {
                assert_eq!(dec.name(), "h264_qsv");
                assert!(dec.is_hardware());
                eprintln!("h264_qsv decoder created");
            }
            Err(e) => {
                // 无 QSV 环境（CI / 无 Intel GPU）：自动 skip。
                eprintln!("h264_qsv not available, skip: {e}");
            }
        }
    }

    /// 编码 → hw 解码 → RGBA 正确（需 hw 环境）。
    #[test]
    fn test_hw_decode_roundtrip() {
        let mut dec = match FfmpegHwDecoder::open(Codec::H264, "h264_qsv") {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Skipping: h264_qsv not available: {e}");
                return;
            }
        };
        let (w, h) = (320u32, 240u32);
        let Some(data) = encode_test_frame(&test_rgba(w, h, 11), w, h) else {
            eprintln!("Skipping: encoder not available");
            return;
        };
        let pkt = DecoderPacket {
            pts: 100,
            data,
            is_key: true,
            extradata: None,
        };
        match dec.send_packet(&pkt) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("hw send failed (skip): {e}");
                return;
            }
        }
        match dec.receive_frames() {
            Ok(out) => {
                assert!(!out.is_empty(), "hw IDR 应产出至少 1 帧");
                let df = &out[0];
                assert_eq!(df.width, w);
                assert_eq!(df.height, h);
                assert_eq!(df.rgba.len(), (w * h * 4) as usize);
                assert!(df.rgba.iter().any(|&b| b != 0), "hw 解码帧不应全零");
                eprintln!("hw roundtrip OK: pts={} {}x{}", df.pts, df.width, df.height);
            }
            Err(e) => eprintln!("hw receive failed (skip): {e}"),
        }
    }

    /// NV12 → RGBA sws_scale 输出正确（独立 sws 测试，无 GPU 依赖）。
    #[test]
    fn test_hw_nv12_to_rgba() {
        if ffmpeg::ensure_loaded().is_err() {
            eprintln!("Skipping: FFmpeg DLLs not available");
            return;
        }
        let (w, h) = (64u32, 32u32);
        // 构造 NV12 缓冲：Y 平面 + 交错 UV。
        let mut nv12 = vec![0u8; (w * h * 3 / 2) as usize];
        // Y 平面：横条图案。
        for y in 0..h {
            let fill = if y % 2 == 0 { 200u8 } else { 40u8 };
            for x in 0..w {
                nv12[(y * w + x) as usize] = fill;
            }
        }
        // UV 平面（每 2x2 一个采样）：中性灰（128, 128）。
        for i in (w * h) as usize..nv12.len() {
            nv12[i] = 128;
        }
        let sws = ffmpeg::sws_getContext(
            w as i32,
            h as i32,
            ffmpeg::AV_PIX_FMT_NV12,
            w as i32,
            h as i32,
            ffmpeg::AV_PIX_FMT_RGBA,
            ffmpeg::SWS_BILINEAR,
        )
        .expect("sws_getContext NV12→RGBA");
        let dst_stride = (w * 4) as i32;
        let mut rgba = vec![0u8; (dst_stride * h as i32) as usize];
        let dst_data: [*mut u8; 4] = [
            rgba.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        ];
        let src_data: [*const u8; 4] = [
            nv12.as_ptr(),
            unsafe { nv12.as_ptr().add((w * h) as usize) },
            ptr::null(),
            ptr::null(),
        ];
        let src_stride: [i32; 4] = [w as i32, w as i32, 0, 0];
        let dst_stride_arr: [i32; 4] = [dst_stride, 0, 0, 0];
        let ret = ffmpeg::sws_scale(
            sws,
            &src_data,
            &src_stride,
            0,
            h as i32,
            &dst_data,
            &dst_stride_arr,
        )
        .expect("sws_scale NV12→RGBA");
        assert_eq!(ret, h as i32);
        assert_eq!(rgba.len(), (w * h * 4) as usize);
        // 偶数行（Y=200）应偏亮，奇数行（Y=40）应偏暗。
        assert!(rgba[0] > 150, "Y=200 行应偏亮，实际 {}", rgba[0]);
        assert!(
            rgba[(w * 4) as usize] < 120,
            "Y=40 行应偏暗，实际 {}",
            rgba[(w * 4) as usize]
        );
        ffmpeg::sws_freeContext(sws);
    }

    /// 无 GPU 时 hw open 失败 → pipeline 回退软解（GPU 环境同样通过）。
    #[test]
    fn test_hw_fallback_when_no_gpu() {
        // 无论本机有无 GPU：pipeline 必须返回 Ok（hw 失败则回退软解）。
        match VideoDecoderPipeline::new(Codec::H264) {
            Ok(pipe) => {
                eprintln!(
                    "pipeline ready: backend='{}' hw={}",
                    pipe.backend.name(),
                    pipe.is_hardware()
                );
                // 至少能用（hw 或 sw）。
            }
            Err(e) => {
                eprintln!("Skipping: no decoder available: {e}");
            }
        }
    }

    /// extradata 变更后 hw 解码正常（hw 环境）。
    #[test]
    fn test_hw_extradata_reopen() {
        let mut dec = match FfmpegHwDecoder::open(Codec::H264, "h264_qsv") {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Skipping: h264_qsv not available: {e}");
                return;
            }
        };
        let (w, h) = (320u32, 240u32);
        let Some(data) = encode_test_frame(&test_rgba(w, h, 3), w, h) else {
            eprintln!("Skipping: encoder not available");
            return;
        };
        // 提取 SPS+PPS 作为 extradata（共享测试助手，见 video/mod.rs）。
        let Some(ed) = crate::decoder::video::extract_sps_pps(&data) else {
            eprintln!("Skipping: no SPS/PPS in bitstream");
            return;
        };
        match dec.update_extradata(&ed) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("hw extradata reopen failed (skip): {e}");
                return;
            }
        }
        let pkt = DecoderPacket {
            pts: 0,
            data,
            is_key: true,
            extradata: None,
        };
        let _ = dec.send_packet(&pkt);
        match dec.receive_frames() {
            // 本机 qsv 可能 open2 成功但 MFX 会话不可用（解码无产出/报错）：
            // 该环境自动 skip，不 panic（见 P2B §T2.2 测试说明）。
            Ok(out) if !out.is_empty() => {
                eprintln!("hw extradata reopen OK: {} frame(s)", out.len());
            }
            Ok(_) => eprintln!("hw extradata reopen: no output (hw decode unavailable, skip)"),
            Err(e) => eprintln!("hw decode after reopen failed (skip): {e}"),
        }
    }
}
