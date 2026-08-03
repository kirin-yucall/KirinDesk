//! libx264 / libx265 软编回退（P1C §T3.6）。
//!
//! 从旧 `encoder/ffmpeg.rs` 迁移：保留 avcodec 调用流程、错误处理、Drop
//! 顺序；适配新 [`VideoEncoder`](super::VideoEncoder) trait（GPU 纹理 +
//! 决策驱动），sws_ctx 去重为 [`SwsConverter`](crate::ffmpeg::scale)。
//!
//! # 路径
//!
//! 软编仅作回退：GPU 内核可用时永不走软编（性能差异 10×+）。捕获层在
//! P1B 不可用时把 RGBA 经 [`VideoEncoder::set_cpu_frame`] 喂入，本编码器
//! swscale 转换 RGBA→YUV420P 后软编。低延迟：`max_b_frames=0`、`g=30~60`、
//! `refs=1`、`preset=ultrafast`、`tune=zerolatency`、`threads=1~2`、
//! `profile=66` (baseline)。
//!
//! # Edge Cases
//!
//! - libx264/libx265 不可用（FFmpeg 构建不含）→ [`create`](FfmpegSwEncoder::create)
//!   返回 [`Unsupported`](super::EncodeError::Unsupported)，外层回退纯
//!   tile-hash 增量（P1F）。
//! - 分辨率变化：[`ensure_codec_dims`] 关闭重开 + 重新 `apply_encoder_config`
//!   （`avcodec_open2` 重置参数 —— 既有 pitfall）。
//! - EAGAIN（编码器忙）：`receive_packet` 返回 -11 → break 循环，不丢帧。

use std::ffi::{c_int, c_void};
use std::ptr;

use crate::encoder::types::{
    Codec, EncodeDecision, EncodedPacket, GpuTexture, PacketKind, Timestamp,
};
use crate::encoder::video::{preprocess_encode, EncodeError, VideoEncoder};
use crate::ffmpeg;
use crate::proto::EncodeConfig;

// ── 低延迟参数（T3.2 参数表） ────────────────────────────────

/// GOP size（周期 IDR）：30~60 的中值，远控场景刷新延迟与码率的折中。
const SW_GOP_SIZE: i64 = 60;
/// 默认目标码率（2 Mbps；自适应层 P1F/P1G 联动 M8-T014 会重配）。
const SW_DEFAULT_BITRATE: i64 = 2_000_000;
/// 软编线程数（ultrafast + 1~2 线程，避免抢占编码线程）。
const SW_THREADS: i64 = 2;

/// libx264 / libx265 软编回退编码器。
///
/// 输入：CPU RGBA 缓冲（经 [`VideoEncoder::set_cpu_frame`] 喂入）。
/// 输出：H.264/H.265 Annex B 码流（`00 00 00 01` 起始码），首包携带
/// extradata（SPS/PPS）。
pub struct FfmpegSwEncoder {
    codec_kind: Codec,
    /// AVCodecContext*（不透明）。
    ctx: *mut ffmpeg::AVCodecContext,
    /// AVCodec*（保留供 reconfigure 时 reopen）。
    codec: *const ffmpeg::AVCodec,
    /// 诊断名（`"libx264"` | `"libx265"`）。
    name: &'static str,
    /// swscale RGBA→YUV420P（去重自旧 ffmpeg.rs 的内联 sws_ctx）。
    sws: Option<ffmpeg::scale::SwsConverter>,
    width: u32,
    height: u32,
    /// 复用 AVFrame（喂 avcodec_send_frame）。
    frame: *mut ffmpeg::AVFrame,
    /// 复用 AVPacket（avcodec_receive_packet）。
    packet: *mut ffmpeg::AVPacket,
    /// 转换后 YUV420P 缓冲（必须存活到 send_frame 完成）。
    frame_buf: Vec<u8>,
    /// SPS/PPS（Annex B；首包前置）。
    extradata: Vec<u8>,
    /// 待编码的 CPU RGBA（由 set_cpu_frame 喂入，encode 消费）。
    pending_rgba: Vec<u8>,
    pending_w: u32,
    pending_h: u32,
    /// 下一帧是否强制 IDR（客户端请求 / 会话首帧）。
    force_idr_next: bool,
    /// 会话 PTS 基数（单调自增，防溢出）。
    pts_counter: u64,
    /// 是否已发首包（用于决定 extradata 是否前置）。
    sent_first: bool,
}

// 编码器在单线程编码任务中独占使用；裸指针的 Send 由调用方保证（与旧
// `FfmpegEncoder` 一致）。
unsafe impl Send for FfmpegSwEncoder {}

impl FfmpegSwEncoder {
    /// 按偏好 codec 创建软编：H.264 → libx264；H.265 → libx265。
    pub fn create(pref: Codec) -> Result<Self, EncodeError> {
        ffmpeg::ensure_loaded()
            .map_err(|e| EncodeError::InitFailed(format!("FFmpeg DLLs: {e}")))?;
        let name = pref.ffmpeg_sw_name();
        match Self::try_open(name, pref) {
            Ok(enc) => {
                tracing::info!("FfmpegSwEncoder: selected software encoder '{name}'");
                Ok(enc)
            }
            Err(e) => Err(EncodeError::Unsupported(format!(
                "software encoder '{name}' unavailable: {e}"
            ))),
        }
    }

    fn try_open(name: &'static str, codec_kind: Codec) -> Result<Self, EncodeError> {
        let codec = ffmpeg::avcodec_find_encoder_by_name(name).map_err(|e| {
            EncodeError::Unsupported(format!("avcodec_find_encoder_by_name('{name}'): {e}"))
        })?;
        let ctx = ffmpeg::avcodec_alloc_context3(codec)
            .map_err(|e| EncodeError::InitFailed(format!("avcodec_alloc_context3: {e}")))?;

        // 初始尺寸占位（320×32），真实尺寸在 ensure_codec_dims 重设。
        // open_with_dict 统一做：结构体字段直写（width/height/pix_fmt/time_base，
        // 这几个字段在 FFmpeg 8.1.1 共享构建的 AVOption 表里缺失）+ 编解码器私有
        // 选项（preset/tune/profile/gop_size 等，经 av_opt_set_int_self / av_opt_set）
        // + avcodec_open2。复刻实测可工作的序列（结构体写 + open2 → send_frame OK）。
        if let Err(e) = open_with_dict(ctx, codec, codec_kind, 320, 32) {
            let mut ctx_opt = ctx;
            ffmpeg::avcodec_free_context(&mut ctx_opt);
            return Err(EncodeError::InitFailed(format!(
                "avcodec_open2('{name}'): {e}"
            )));
        }

        let frame = ffmpeg::av_frame_alloc()
            .map_err(|e| EncodeError::InitFailed(format!("av_frame_alloc: {e}")))?;
        let packet = ffmpeg::av_packet_alloc().map_err(|e| {
            let mut f = frame;
            ffmpeg::av_frame_free(&mut f);
            EncodeError::InitFailed(format!("av_packet_alloc: {e}"))
        })?;

        // 读 extradata（SPS/PPS）；avcodec 输出已是 Annex B。
        let extradata = read_extradata(ctx);

        Ok(Self {
            codec_kind,
            ctx,
            codec,
            name,
            sws: None,
            width: 320, // 匹配 open_with_dict 的探测尺寸，避免首次 encode 误触发 reopen
            height: 32,
            frame,
            packet,
            frame_buf: Vec::new(),
            extradata,
            pending_rgba: Vec::new(),
            pending_w: 0,
            pending_h: 0,
            force_idr_next: true, // 会话首帧强制 IDR。
            pts_counter: 0,
            sent_first: false,
        })
    }

    // 低延迟参数配置已统一收敛到 [`open_with_dict`]（结构体字段直写 +
    // av_opt_set + open2）。原先的 apply_encoder_config(_raw) 在 close+reopen
    // 重设路径上被弃用（FFmpeg 8.x 不支持同 ctx reopen，见 ensure_codec_dims）。

    /// 确保 codec 尺寸匹配；变化时**释放旧 ctx + 分配新 ctx + open2**。
    ///
    /// FFmpeg 8.x 不支持对同一 `AVCodecContext` close 后再 open2（libx264 的
    /// priv_data / lookahead 线程状态不会被干净重置 → send_frame 报
    /// `-542398533`）。故尺寸变化时必须 free + 重新 alloc 一个全新 ctx。
    fn ensure_codec_dims(&mut self, width: u32, height: u32) -> Result<(), EncodeError> {
        if self.width == width && self.height == height && !self.ctx.is_null() {
            return Ok(());
        }
        // 释放旧 ctx（含 close + free）。
        // R-06（M8-T030 实机暴露）：free 前必须 flush（send null + drain）——
        // 与 Drop 及 HW `ffmpeg_hw.rs::ensure_codec_dims` 对齐。libx264 不
        // flush 直接 free_context 会残留 lookahead 线程状态（实测重开新尺寸
        // 后报 "lookahead thread is already stopped" + send_frame 返回
        // -AVERROR_EXTERNAL）；修复后 320 占位 → 真实尺寸重开路径正常。
        if !self.ctx.is_null() {
            let mut ctx_ref = self.ctx;
            let _ = ffmpeg::avcodec_send_frame(ctx_ref, ptr::null());
            loop {
                match ffmpeg::avcodec_receive_packet(ctx_ref, self.packet) {
                    Ok(()) => ffmpeg::av_packet_unref(self.packet),
                    _ => break,
                }
            }
            ffmpeg::avcodec_free_context(&mut ctx_ref);
            self.ctx = std::ptr::null_mut();
        }
        // 分配全新 ctx 并 open。
        let codec = self.codec; // *const AVCodec，alloc_context3 复用
        let ctx = ffmpeg::avcodec_alloc_context3(codec).map_err(|e| {
            EncodeError::InitFailed(format!("avcodec_alloc_context3 (reinit): {e}"))
        })?;
        if let Err(e) = open_with_dict(ctx, codec, self.codec_kind, width, height) {
            let mut ctx_ref = ctx;
            ffmpeg::avcodec_free_context(&mut ctx_ref);
            return Err(EncodeError::InitFailed(format!(
                "avcodec_open2 (reinit {width}x{height}): {e}"
            )));
        }
        self.ctx = ctx;
        self.width = width;
        self.height = height;
        // sws 需按新尺寸重建。
        self.sws = None;
        self.sent_first = false; // 重开 → 重新发 extradata。
        tracing::debug!(
            "FfmpegSwEncoder: reinit {width}x{height} for '{}'",
            self.name
        );
        Ok(())
    }

    /// 确保 swscale 上下文匹配当前尺寸（RGBA→YUV420P）。
    fn ensure_sws(&mut self, width: u32, height: u32) -> Result<(), EncodeError> {
        if self.sws.is_none() || self.width != width || self.height != height {
            self.sws = Some(
                ffmpeg::scale::SwsConverter::new(
                    width as i32,
                    height as i32,
                    ffmpeg::AV_PIX_FMT_RGBA,
                    width as i32,
                    height as i32,
                    ffmpeg::AV_PIX_FMT_YUV420P,
                )
                .map_err(|e| EncodeError::InitFailed(format!("sws_getContext: {e}")))?,
            );
        }
        Ok(())
    }

    /// RGBA → AVFrame（YUV420P）；转换后数据存 `frame_buf` 保活到 send_frame。
    fn rgba_to_frame(&mut self, rgba: &[u8], width: u32, height: u32) -> Result<(), EncodeError> {
        let pix_fmt = ffmpeg::AV_PIX_FMT_YUV420P;
        let buf_size = ffmpeg::av_image_get_buffer_size(pix_fmt, width as i32, height as i32, 1)
            .map_err(|e| EncodeError::EncodeFailed(format!("av_image_get_buffer_size: {e}")))?
            as usize;
        self.frame_buf = vec![0u8; buf_size];

        unsafe {
            let mut data: [*mut u8; 4] = [ptr::null_mut(); 4];
            let mut linesize: [i32; 4] = [0; 4];
            ffmpeg::av_image_fill_arrays(
                &mut data,
                &mut linesize,
                self.frame_buf.as_mut_ptr(),
                pix_fmt,
                width as i32,
                height as i32,
                1,
            )
            .map_err(|e| EncodeError::EncodeFailed(format!("av_image_fill_arrays: {e}")))?;

            let src_data: [*const u8; 4] = [rgba.as_ptr(), ptr::null(), ptr::null(), ptr::null()];
            let src_stride: [i32; 4] = [(width * 4) as i32, 0, 0, 0];

            self.sws
                .as_ref()
                .expect("sws must be initialized before rgba_to_frame")
                .scale(&src_data, &src_stride, &data, &linesize)
                .map_err(|e| EncodeError::EncodeFailed(format!("sws_scale: {e}")))?;

            (*self.frame).data = [
                data[0],
                data[1],
                data[2],
                data[3],
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            ];
            (*self.frame).linesize = [
                linesize[0],
                linesize[1],
                linesize[2],
                linesize[3],
                0,
                0,
                0,
                0,
            ];
            (*self.frame).width = width as c_int;
            (*self.frame).height = height as c_int;
            (*self.frame).format = pix_fmt;
        }
        Ok(())
    }

    /// 编码主循环（T3.5）：send_frame → loop receive_packet → 打包 Annex B。
    ///
    /// `pts` = 会话毫秒 PTS；`force_idr` 强制 IDR（设 pict_type=I）。
    fn encode_inner(
        &mut self,
        pts: u64,
        force_idr: bool,
        ts: Timestamp,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        // 设 PTS（符号缺失回退字段写）。
        if !ffmpeg::av_frame_set_pts(self.frame, pts as i64) {
            unsafe { (*self.frame).pts = pts as i64 };
        }

        // IDR 策略（T3.5）：强制 I 帧 + 首包携带 extradata。
        if force_idr {
            unsafe {
                (*self.frame).pict_type = ffmpeg::AV_PICTURE_TYPE_I;
                (*self.frame).key_frame = 1;
            }
        } else {
            unsafe {
                (*self.frame).pict_type = ffmpeg::AV_PICTURE_TYPE_NONE;
                (*self.frame).key_frame = 0;
            }
        }

        // send_frame：EAGAIN（编码器忙）按文档继续 receive，不丢帧。
        if let Err(e) = ffmpeg::avcodec_send_frame(self.ctx, self.frame) {
            if !matches!(e, ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) {
                return Err(EncodeError::EncodeFailed(format!(
                    "avcodec_send_frame: {e}"
                )));
            }
        }

        let mut packets = Vec::new();
        self.drain_receive(&mut packets, ts)?;
        // R-32（M13-T002 阶段 B）：SVT-AV1 为异步多线程编码器（lookahead 缓冲），
        // 刚送入的帧可能尚未产出包（EAGAIN 空结果）——短等待重试排空，保证
        // 单帧调用也能及时取回已排队的包（x264/x265 zerolatency 立即出包，
        // 不触发等待，无额外延迟）。
        if packets.is_empty() && self.codec_kind == Codec::AV1 {
            for _ in 0..25 {
                std::thread::sleep(std::time::Duration::from_millis(2));
                self.drain_receive(&mut packets, ts)?;
                if !packets.is_empty() {
                    break;
                }
            }
        }
        Ok(packets)
    }

    /// 排空 `avcodec_receive_packet` 队列到 `packets`（首包前置 extradata）。
    ///
    /// 返回 `true` 表示至少收到一个包；EAGAIN（编码器忙）/ EOF 结束排空，
    /// 不丢帧（下次调用继续）。
    fn drain_receive(
        &mut self,
        packets: &mut Vec<EncodedPacket>,
        ts: Timestamp,
    ) -> Result<bool, EncodeError> {
        let mut received = false;
        loop {
            match ffmpeg::avcodec_receive_packet(self.ctx, self.packet) {
                Ok(()) => {
                    let (data, is_key) = unsafe {
                        let p = &*self.packet;
                        let size = p.size as usize;
                        let slice = if p.data.is_null() || size == 0 {
                            &[]
                        } else {
                            std::slice::from_raw_parts(p.data, size)
                        };
                        // AV_PKT_FLAG_KEY = 0x0001。
                        (slice.to_vec(), (p.flags & 0x0001) != 0)
                    };
                    // 每包必调 unref（防泄漏）。
                    ffmpeg::av_packet_unref(self.packet);

                    // 首包 / 参数变更后：前置 extradata（SPS/PPS）。
                    let prepend_extra = !self.sent_first && is_key;
                    self.sent_first = true;

                    let mut buf = Vec::with_capacity(
                        data.len()
                            + if prepend_extra {
                                self.extradata.len()
                            } else {
                                0
                            },
                    );
                    if prepend_extra && !self.extradata.is_empty() {
                        buf.extend_from_slice(&self.extradata);
                    }
                    buf.extend_from_slice(&data);

                    packets.push(EncodedPacket {
                        ts,
                        kind: PacketKind::Video,
                        data: buf,
                        is_key,
                    });
                    received = true;
                }
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => break,
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EOF)) => break,
                Err(e) => {
                    return Err(EncodeError::EncodeFailed(format!(
                        "avcodec_receive_packet: {e}"
                    )));
                }
            }
        }
        Ok(received)
    }
}

impl VideoEncoder for FfmpegSwEncoder {
    fn encode(
        &mut self,
        tex: &GpuTexture,
        ts: Timestamp,
        decision: EncodeDecision,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        // Edge Cases 预处理：null 纹理 / Static 决策短路。
        if let Some(packets) = preprocess_encode(tex, &decision)? {
            return Ok(packets);
        }

        // CPU RGBA 路径：必须先经 set_cpu_frame 喂入 RGBA。
        // 真实 GPU 纹理（handle 非空）走 hw 编码器，本软编不处理。
        if self.pending_rgba.is_empty() {
            return Err(EncodeError::InvalidConfig(
                "FfmpegSwEncoder: no pending CPU RGBA (call set_cpu_frame first)".into(),
            ));
        }

        let rgba = std::mem::take(&mut self.pending_rgba);
        let w = self.pending_w;
        let h = self.pending_h;
        self.pending_w = 0;
        self.pending_h = 0;

        // 尺寸 + sws 匹配。
        self.ensure_codec_dims(w, h)?;
        self.ensure_sws(w, h)?;

        // RGBA → YUV420P。
        self.rgba_to_frame(&rgba, w, h)?;

        // 编码。
        let force_idr = self.force_idr_next;
        self.force_idr_next = false;
        let pts = ts.pts.max(self.pts_counter);
        self.pts_counter = pts.saturating_add(1);
        self.encode_inner(pts, force_idr, ts)
    }

    fn codec(&self) -> Codec {
        self.codec_kind
    }

    fn is_hardware(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn reconfigure(&mut self, cfg: &EncodeConfig) -> Result<(), EncodeError> {
        // 码率 / 分辨率自适应（P1F/P1G 联动）：force_idr 标记 + 真实 reopen
        // 在下一次 encode 的 ensure_codec_dims 中触发（仅尺寸变化才重开）。
        if cfg.force_idr {
            self.force_idr_next = true;
        }
        Ok(())
    }

    /// CPU RGBA 喂入（软编回退适配，T3.6）。
    fn set_cpu_frame(&mut self, rgba: &[u8], w: u32, h: u32, force_idr: bool) {
        self.pending_rgba.clear();
        self.pending_rgba.extend_from_slice(rgba);
        self.pending_w = w;
        self.pending_h = h;
        if force_idr {
            self.force_idr_next = true;
        }
    }

    /// 窗口边界清参考帧（M8-T011 T2.3）。
    ///
    /// **P0-1 修复后的正确语义：软编 no-op。** 历史实现（`avcodec_flush_buffers`，
    /// 解码器语义）对活动中的 libx264 调用会摧毁编码器：第 2 个窗口起
    /// `avcodec_send_frame` 返回 `AVERROR_EXTERNAL (-542398533)`，
    /// `transport_degrade` 甚至原生崩溃（STATUS_ACCESS_VIOLATION 0xc0000005）。
    /// 修复计划建议的 send-null + drain 亦不可行（2026-08-02 实测：null 帧
    /// 后 FFmpeg 置内部 draining 标志，下一个真实帧 `avcodec_send_frame`
    /// 直接返回 `AVERROR_EOF`，同一 ctx 不可复用——该序列只适用于 Drop /
    /// `ensure_codec_dims` 这种随后释放 ctx 的场景）。
    ///
    /// 为何 no-op 安全：`tune=zerolatency` + `rc-lookahead=0` + `threads=2` +
    /// `max_b_frames=0` → 编码器内**无延迟帧、无跨窗口缓冲**；每窗口首帧强制
    /// IDR（`force_idr_next` + WindowPipeline `force_idr`），IDR 自身重置
    /// 参考链，窗口自包含性由 IDR 保证。实测 3 窗口直接序列全部成功
    /// （`Z_media模块检查与修复计划_2026-08-02.md` P0-1 实证）。
    fn flush_buffers(&mut self) {
        // 软编窗口边界无需清参考帧：zerolatency 无缓冲延迟帧，下一窗口
        // 首帧强制 IDR 即重置参考链（P0-1 实证；HW QSV 保留
        // avcodec_flush_buffers，见 ffmpeg_hw.rs 实测登记）。
        self.force_idr_next = true;
        tracing::debug!("FfmpegSwEncoder: flushed buffers (window boundary) — no-op for zerolatency software encoder");
    }
}

impl Drop for FfmpegSwEncoder {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // Flush：发送 null frame 触发输出缓冲包，再 drain（兼容旧 FFmpeg）。
            let _ = ffmpeg::avcodec_send_frame(self.ctx, ptr::null());
            loop {
                match ffmpeg::avcodec_receive_packet(self.ctx, self.packet) {
                    Ok(()) => ffmpeg::av_packet_unref(self.packet),
                    _ => break,
                }
            }
            ffmpeg::avcodec_free_context(&mut self.ctx);
        }
        // sws / frame_buf / pending_rgba 由 Drop 自动释放。
        let mut frame = self.frame;
        if !frame.is_null() {
            ffmpeg::av_frame_free(&mut frame);
        }
        let mut pkt = self.packet;
        if !pkt.is_null() {
            ffmpeg::av_packet_free(&mut pkt);
        }
    }
}

/// 从 AVCodecContext 读 extradata（SPS/PPS）。
///
/// 注意：`AVCodecContext` 在本仓库保持不透明（GyanD 8.1.1 布局风险），
/// 但 `extradata` / `extradata_size` 是该结构末尾的稳定字段。为安全读取，
/// 我们借助 avcodec_parameters_from_context 的等价路径——FFmpeg 8.x 未在
/// 动态加载表里暴露该符号，因此本函数返回空 Vec，extradata 由首包 NAL 自带
/// （H.264 Annex B 流的首个 IDR slice 前通常带 SPS/PPS，或经客户端
/// decoder.rs 重新探测）。若未来需要显式 extradata，应增加
/// avcodec_parameters_from_context 包装。
fn read_extradata(_ctx: *mut ffmpeg::AVCodecContext) -> Vec<u8> {
    Vec::new()
}

/// 经 AVDictionary 打开 codec（注入 `pix_fmt`/`width`/`height`）。
///
/// 这些字段在 `AVCodecContext` 上无对应 AVOption 条目（`av_opt_set` 返回
/// `AVERROR_OPTION_NOT_FOUND`），只能经 `avcodec_open2` 的 options 字典注入。
/// 字典在 open2 后由 FFmpeg 消费匹配项；本函数统一 free。
fn open_with_dict(
    ctx: *mut ffmpeg::AVCodecContext,
    codec: *const ffmpeg::AVCodec,
    codec_kind: Codec,
    width: u32,
    height: u32,
) -> Result<(), ffmpeg::AvError> {
    // 1) 结构体字段直写：width/height/coded_*/pix_fmt/time_base（这些字段在
    //    FFmpeg 8.1.1 共享构建的 AVOption 表里缺失，av_opt_set 无效）。偏移取自
    //    FFmpeg 8.1 头文件 offsetof，经实测确认。
    unsafe {
        ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::WIDTH, width as i32);
        ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::HEIGHT, height as i32);
        ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::CODED_WIDTH, width as i32);
        ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::CODED_HEIGHT, height as i32);
        ffmpeg::avctx_set_int(
            ctx,
            ffmpeg::avctx_offset::PIX_FMT,
            ffmpeg::AV_PIX_FMT_YUV420P,
        );
        ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::GOP_SIZE, SW_GOP_SIZE as i32);
    }
    ffmpeg::avctx_set_time_base(ctx, 1, 1000); // PTS = 毫秒
                                               // P1G：必须显式设置 framerate。time_base=1/1000 时若不设置，x264 会
                                               // 把帧率误判为 1000fps → ABR 每帧码率预算 = bitrate/1000（如 2M→250B）
                                               // → QP 推到 51 全 skip，全屏内容码率严重失真（实测 73kbps vs 目标 2M）。
    ffmpeg::avctx_set_framerate(ctx, 30, 1);
    // 2) 其它顶层 int（AVOption 表里有，flag=0 搜 obj 自身）。
    let obj = ctx as *mut c_void;
    let _ = ffmpeg::av_opt_set_int_self(obj, "b", SW_DEFAULT_BITRATE);
    // R-32（M13-T002 阶段 B）：SVT-AV1 的 `maxrate` 仅支持 CRF 模式（VBR 下
    // open2 报 "Max Bitrate only supported with CRF"，av1_probe 实测）→ AV1
    // 只设 b（VBR），跳过 maxrate。
    if codec_kind != Codec::AV1 {
        let _ = ffmpeg::av_opt_set_int_self(obj, "maxrate", SW_DEFAULT_BITRATE);
    }
    let _ = ffmpeg::av_opt_set_int_self(obj, "refs", 1);
    let _ = ffmpeg::av_opt_set_int_self(obj, "threads", SW_THREADS);
    let _ = ffmpeg::av_opt_set_int_self(obj, "max_b_frames", 0);
    let _ = ffmpeg::av_opt_set_int_self(obj, "rc-lookahead", 0);
    // 3) 编解码器私有选项（子选项，SEARCH_CHILDREN）。best-effort：不支持的
    //    选项被编码器忽略（av_opt_set 报错被吞）。
    //    R-32：AV1（SVT-AV1）用数值 preset（0~13，8 为速度/质量均衡档，
    //    av1_probe 实测路径）；无 zerolatency tune（SVT 只有 0~3 指标 tune，
    //    低延迟由 lookahead 语义保证，见 encode_inner 的 EAGAIN 排空）。
    let (preset, tune) = match codec_kind {
        Codec::H264 | Codec::H265 => ("ultrafast", Some("zerolatency")),
        Codec::AV1 => ("8", None),
    };
    let _ = ffmpeg::av_opt_set(obj, "preset", preset);
    if let Some(t) = tune {
        let _ = ffmpeg::av_opt_set(obj, "tune", t);
    }
    let profile_str = match codec_kind {
        Codec::H264 => "baseline",
        Codec::H265 => "main",
        // SVT-AV1 profile 名（main/high/professional）；失败被忽略。
        Codec::AV1 => "main",
    };
    let _ = ffmpeg::av_opt_set(obj, "profile", profile_str);
    // 4) open2（plain；opts 字典路径实测会让 send_frame 报 -542398533，故用 plain）。
    ffmpeg::avcodec_open2(ctx, codec)
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::types::DirtyTileMap;

    /// 软编可用时，输出为 Annex B（起始码 00 00 00 01 或 00 00 01）。
    #[test]
    fn test_sw_encoder_annex_b() {
        if ffmpeg::ensure_loaded().is_err() {
            eprintln!("FFmpeg libraries not available; test_sw_encoder_annex_b skipped");
            return;
        }
        let mut enc = match FfmpegSwEncoder::create(Codec::H264) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("FfmpegSwEncoder not available: {e} (expected w/o libx264)");
                return;
            }
        };
        let w = 320u32;
        let h = 240u32;
        let rgba = vec![128u8; (w * h * 4) as usize];
        enc.set_cpu_frame(&rgba, w, h, true);

        let tex = GpuTexture::new(0x1usize as *mut _, w, h); // CPU 模式：非空哨兵
        let decision = EncodeDecision::FullFrame(DirtyTileMap::default());
        let packets = enc
            .encode(&tex, Timestamp::now(), decision)
            .expect("libx264 encode should succeed (DLL loaded)");
        assert!(!packets.is_empty(), "encoder should produce ≥1 packet");
        let first = &packets[0].data;
        // Annex B 起始码：00 00 00 01 或 00 00 01。
        let starts_with_startcode = (first.len() >= 4 && first[0..4] == [0, 0, 0, 1])
            || (first.len() >= 3 && first[0..3] == [0, 0, 1]);
        assert!(
            starts_with_startcode,
            "expected Annex B start code, got {:02x?}",
            &first[..first.len().min(6)]
        );
        assert!(packets[0].is_key, "first packet should be IDR");
    }

    /// Static 决策 → 空包（编码器 0 次调用）。
    #[test]
    fn test_sw_static_zero_output() {
        if ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let Ok(mut enc) = FfmpegSwEncoder::create(Codec::H264) else {
            return;
        };
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        let packets = enc
            .encode(&tex, Timestamp::now(), EncodeDecision::Static)
            .unwrap();
        assert!(packets.is_empty());
    }

    /// 连续 3 窗口编码（每窗口边界调用 flush_buffers）全部成功——P0-1 回归
    /// 防护：原实现窗口边界调 `avcodec_flush_buffers`（解码器语义），第 2 个
    /// 窗口起 x264 lookahead 线程状态损坏 → `avcodec_send_frame` 返回
    /// `AVERROR_EXTERNAL (-542398533)`（严重时原生崩溃）。修复后窗口边界
    /// 走 send-null + drain 的编码器正确 flush，3 窗口全部正常出码。
    #[test]
    fn test_sw_encoder_multi_window_flush() {
        if ffmpeg::ensure_loaded().is_err() {
            eprintln!("FFmpeg libraries not available; test_sw_encoder_multi_window_flush skipped");
            return;
        }
        let Ok(mut enc) = FfmpegSwEncoder::create(Codec::H264) else {
            return;
        };
        let (w, h) = (320u32, 240u32);
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        for window in 0..3u32 {
            // 每窗口不同内容（真实场景窗口间画面变化）。
            let rgba = vec![(window as u8 + 1) * 16; (w * h * 4) as usize];
            enc.set_cpu_frame(&rgba, w, h, true);
            let packets = enc
                .encode(
                    &tex,
                    Timestamp::now(),
                    EncodeDecision::FullFrame(DirtyTileMap::default()),
                )
                .unwrap_or_else(|e| panic!("window {window} encode must succeed: {e}"));
            assert!(
                !packets.is_empty(),
                "window {window} must produce ≥1 packet"
            );
            assert!(packets[0].is_key, "window {window} first packet is IDR");
            // 窗口边界 flush（与 WindowPipeline 每窗口调用一致）。
            enc.flush_buffers();
        }
    }

    // ════════════════════════════════════════════════════════════
    // R-32（M13-T002 阶段 B）：SVT-AV1 码流合法性 + 解码回读
    // ════════════════════════════════════════════════════════════

    /// R-32 验收：AV1 编码器（libsvtav1）出码流合法（Annex B 起始码 +
    /// 关键帧标志）；捆绑 FFmpeg 8.1.1 full build 静态编入 libsvtav1
    /// （avcodec-62.dll 内），无独立 DLL。老构建无 SVT → 静默跳过。
    #[test]
    fn test_sw_encoder_av1_annex_b() {
        if ffmpeg::ensure_loaded().is_err() {
            eprintln!("FFmpeg libraries not available; test_sw_encoder_av1_annex_b skipped");
            return;
        }
        let Ok(mut enc) = FfmpegSwEncoder::create(Codec::AV1) else {
            eprintln!("libsvtav1 not in this FFmpeg build; skipped");
            return;
        };
        assert_eq!(enc.name(), "libsvtav1");
        assert_eq!(enc.codec(), Codec::AV1);
        let w = 320u32;
        let h = 240u32;
        let rgba = vec![128u8; (w * h * 4) as usize];
        enc.set_cpu_frame(&rgba, w, h, true);

        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let decision = EncodeDecision::FullFrame(DirtyTileMap::default());
        let packets = enc
            .encode(&tex, Timestamp::now(), decision)
            .expect("SVT-AV1 encode should succeed (DLL loaded)");
        assert!(!packets.is_empty(), "SVT-AV1 should produce ≥1 packet");
        assert!(packets[0].is_key, "first AV1 packet should be keyframe");
        let first = &packets[0].data;
        // Annex B 起始码：00 00 00 01 或 00 00 01（SVT 输出 Annex B）。
        let starts_with_startcode = (first.len() >= 4 && first[0..4] == [0, 0, 0, 1])
            || (first.len() >= 3 && first[0..3] == [0, 0, 1]);
        assert!(
            starts_with_startcode,
            "expected Annex B start code, got {:02x?}",
            &first[..first.len().min(8)]
        );
    }

    /// R-32 验收：AV1 编码 → **解码回读**（生产解码路径：软解 av1），
    /// 多帧不同内容全部可解，输出帧尺寸正确。
    #[test]
    fn test_sw_encoder_av1_decode_roundtrip() {
        if ffmpeg::ensure_loaded().is_err() {
            eprintln!("FFmpeg libraries not available; test_sw_encoder_av1_decode_roundtrip skipped");
            return;
        }
        let Ok(mut enc) = FfmpegSwEncoder::create(Codec::AV1) else {
            eprintln!("libsvtav1 not in this FFmpeg build; skipped");
            return;
        };
        let (w, h) = (320u32, 240u32);
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let mut packets_all: Vec<EncodedPacket> = Vec::new();
        for idx in 0..4u32 {
            // 不同内容帧（纯色递进 + 局部方块模拟桌面变化）。
            let mut rgba = vec![(idx as u8 + 1) * 32; (w * h * 4) as usize];
            let sq = 48usize;
            let bx = (idx as usize * 37) % ((w as usize).saturating_sub(sq));
            let by = (idx as usize * 29) % ((h as usize).saturating_sub(sq));
            for yy in by..by + sq {
                for xx in bx..bx + sq {
                    rgba[(yy * w as usize + xx) * 4] = 200;
                }
            }
            enc.set_cpu_frame(&rgba, w, h, idx == 0);
            let pkts = enc
                .encode(
                    &tex,
                    Timestamp::now(),
                    EncodeDecision::FullFrame(DirtyTileMap::default()),
                )
                .unwrap_or_else(|e| panic!("AV1 frame {idx} encode must succeed: {e}"));
            assert!(!pkts.is_empty(), "AV1 frame {idx} must produce ≥1 packet");
            packets_all.extend(pkts);
        }
        // 解码回读（生产解码链：软解 av1）。
        let mut dec = match crate::decoder::factory::create_software_decoder(Codec::AV1) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("AV1 software decoder unavailable: {e}; skipped");
                return;
            }
        };
        let mut decoded = 0usize;
        for (i, pkt) in packets_all.iter().enumerate() {
            match dec.decode(&crate::decoder::DecoderPacket {
                pts: i as u64,
                data: pkt.data.clone(),
                is_key: pkt.is_key,
                extradata: None,
            }) {
                Ok(frames) => decoded += frames.len(),
                Err(crate::decoder::DecodeError::NoOutput) => {}
                Err(e) => panic!("AV1 decode packet {i}: {e}"),
            }
        }
        assert!(
            decoded > 0,
            "AV1 bitstream must decode ≥1 frame (got {decoded})"
        );
        tracing::info!("AV1 decode roundtrip: {decoded} frames decoded");
    }
}
