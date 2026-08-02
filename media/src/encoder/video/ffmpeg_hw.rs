//! FFmpeg 硬件编码后端（P1C §T3.1–T3.5）。
//!
//! hw device 初始化、编码器链、零拷贝 hwframes 帧池、ROI 注入、低延迟
//! 参数、Annex B 打包、IDR 策略。
//!
//! # 本阶段实现深度（用户决策：Stub HW，聚焦 SW）
//!
//! HW FFI 符号声明 + safe 包装已就位（`ffmpeg::api`），`FfmpegHwEncoder` 的
//! 结构 / `HwType` / `FramePool` / `merge_tiles_to_regions`（ROI 合并算法）
//! / `apply_encoder_config`（T3.2 参数表）全部实现并可单测。但
//! [`try_open`](FfmpegHwEncoder::try_open) 在无 HW DLL/GPU 环境返回
//! [`Unsupported`](super::EncodeError::Unsupported)，[`create`](FfmpegHwEncoder::create)
//! 据此回退到 [`FfmpegSwEncoder`](super::ffmpeg_sw::FfmpegSwEncoder)。HW 管道
//! 存在但惰性，待真实 HW DLL 就绪后由 `try_open` 走通。
//!
//! # P1B↔P1C 接驳（2026-07-31）
//!
//! [`create`](FfmpegHwEncoder::create) / [`try_open`](FfmpegHwEncoder::try_open)
//! 接 `Option<&dyn GpuKernel>`：当 `kernel.is_linked()` 时
//! [`encode`](FfmpegHwEncoder::encode) 先尝试 `kernel.hw_upload(tex)` 走零拷贝
//! hwframes 路径（`av_hwframe_get_buffer` + `frame_pool.acquire/release`）；
//! 失败 / 未链接 / 无 pending 纹理 → 回退既有 CPU NV12 路径（`set_cpu_frame`
//! 喂入）。两条路径共用 `encode_inner` 的 receive_packet / 打包循环。
//!
//! **注意**：C++ 侧 `kgpu_hw_upload`（hw_bridge.cpp）当前桩实现恒返回 NULL
//! → `hw_upload` 返 `GpuKernel` 错误，本编码器自动回退 CPU NV12 路径；待
//! P1B hw_bridge.cpp 真实实现后零拷贝路径自动生效，无需改本文件。
//!
//! # 关键约束（父文档）
//!
//! - 不 spawn ffmpeg.exe；硬件编码统一经 FFmpeg（h264_nvenc 等），无直接
//!   NVENC/AMF/QSV SDK 调用。
//! - AVCodecContext 不透明，配置走 av_opt_set。
//! - ROI = AV_FRAME_DATA_REGIONS_OF_INTEREST QP 加权（非字面局部编码）。

use std::ffi::c_void;
use std::ptr;

use crate::encoder::types::{
    Codec, DirtyTileMap, EncodeDecision, EncodedPacket, GpuTexture, Timestamp,
};
use crate::encoder::video::tile_diff::GpuKernel;
use crate::encoder::video::{preprocess_encode, EncodeError, VideoEncoder};
use crate::ffmpeg;

// ── HwType（T3.1） ───────────────────────────────────────────

/// 硬件加速后端类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwType {
    D3D11VA,
    QSV,
    VIDEOTOOLBOX,
    VAAPI,
    /// 软编（无硬件加速；本枚举容纳 Software 以便回退链统一表达）。
    Software,
}

impl HwType {
    /// FFmpeg `AVHWDeviceType` 数值（来自 `ffmpeg::types::AV_HWDEVICE_TYPE_*`）。
    fn hwdevice_type(self) -> i32 {
        match self {
            HwType::D3D11VA => ffmpeg::AV_HWDEVICE_TYPE_D3D11VA,
            HwType::QSV => ffmpeg::AV_HWDEVICE_TYPE_QSV,
            HwType::VIDEOTOOLBOX => ffmpeg::AV_HWDEVICE_TYPE_VIDEOTOOLBOX,
            HwType::VAAPI => ffmpeg::AV_HWDEVICE_TYPE_VAAPI,
            HwType::Software => ffmpeg::AV_HWDEVICE_TYPE_NONE,
        }
    }

    /// 与该后端匹配的 hwframes 像素格式。
    fn pix_fmt(self) -> i32 {
        match self {
            HwType::D3D11VA => ffmpeg::AV_PIX_FMT_D3D11,
            HwType::QSV => ffmpeg::AV_PIX_FMT_QSV,
            HwType::VIDEOTOOLBOX => ffmpeg::AV_PIX_FMT_VIDEOTOOLBOX,
            HwType::VAAPI => ffmpeg::AV_PIX_FMT_VAAPI,
            HwType::Software => ffmpeg::AV_PIX_FMT_YUV420P,
        }
    }
}

// ── FfmpegHwEncoder（T3.1 Struct） ───────────────────────────

/// FFmpeg 硬件编码后端。
///
/// 所有 FFmpeg 句柄（ctx / hw_device_ctx / hw_frames_ctx）以不透明
/// `*mut c_void` 持有，仅经 `ffmpeg::api` 包装操作。
///
/// 字段对照文档 §T3.1：`hw_device_ctx`/`hw_frames_ctx` 文档写的是 `*mut c_void`
/// （不透明），此处用 `*mut AVBufferRef`（同样不透明 phantom），等价；
/// `kernel` 文档写 `Option<GpuKernelHandle>`，真实类型为 [`KgpuKernel`]
/// （P1B），经 trait object `&dyn GpuKernel` 借用（不持有所有权）。
///
/// [`KgpuKernel`]: crate::encoder::gpu_ffi::kernel::KgpuKernel
pub struct FfmpegHwEncoder {
    codec: Codec,
    name: &'static str, // "h264_nvenc" | "h264_amf" | "h264_qsv" | ...
    hw_type: HwType,
    ctx: *mut c_void, // AVCodecContext*（不透明）
    hw_device_ctx: *mut ffmpeg::AVBufferRef,
    hw_frames_ctx: *mut ffmpeg::AVBufferRef,
    width: u32,
    height: u32,
    /// 目标 hwframes 像素格式（来自 `hw_type.pix_fmt()`，调试 / 校验用）。
    #[allow(dead_code)]
    pix_fmt: i32,
    /// P1B GPU 内核句柄（借用，不持有所有权）：`is_linked()` 时启用零拷贝
    /// hw_upload 路径；`None` 或未链接 → 走 CPU NV12 路径。
    ///
    /// 存为生命周期擦除的 trait object 胖指针（`'static` 是擦除标记，非真实
    /// 生命周期）。调用方（`VideoEncoderPipeline`）的 `Box<dyn GpuKernel>`
    /// 存活长于本编码器，借用安全；构造时经 [`core::ptr::addr_of`] 转换擦除
    /// 生命周期。`Send` 由本结构的 `unsafe impl Send` 覆盖（编码线程独占）。
    kernel: Option<*const (dyn GpuKernel + 'static)>,
    frame_pool: FramePool,
    extradata: Vec<u8>,
    pts_base: u64,

    // ── CPU NV12 输入路径（QSV/nvenc/amf 在 FFmpeg 层接受 NV12 CPU 帧） ──
    sws: Option<ffmpeg::scale::SwsConverter>,
    frame: *mut ffmpeg::AVFrame,
    packet: *mut ffmpeg::AVPacket,
    frame_buf: Vec<u8>, // 转换后 NV12 缓冲（保活到 send_frame）
    pending_rgba: Vec<u8>,
    pending_w: u32,
    pending_h: u32,
    force_idr_next: bool,
    sent_first: bool,
}

unsafe impl Send for FfmpegHwEncoder {}

impl FfmpegHwEncoder {
    /// 按回退链尝试创建：nvenc → amf → qsv → videotoolbox → vaapi。
    /// 全部失败 → [`Unsupported`](EncodeError::Unsupported)（factory 回退软编）。
    ///
    /// `kernel`：可选 P1B GPU 内核（借用，不持有所有权）。`is_linked()` 时
    /// [`encode`](Self::encode) 会先尝试零拷贝 hw_upload 路径；未链接 / None
    /// 时走 CPU NV12 路径（需 [`VideoEncoder::set_cpu_frame`] 喂入）。
    ///
    /// 注意：文档 §T3.1 签名为 `kernel: Option<GpuKernelHandle>`，但
    /// `GpuKernelHandle` 在本仓库不存在——真实类型为
    /// [`KgpuKernel`](crate::encoder::gpu_ffi::kernel::KgpuKernel)（P1B）。本函数
    /// 据此接 `Option<&dyn GpuKernel>`（trait object，与 pipeline 的
    /// `Box<dyn GpuKernel>` 解引用兼容），语义等价。
    pub fn create(pref: Codec, kernel: Option<&dyn GpuKernel>) -> Result<Self, EncodeError> {
        ffmpeg::ensure_loaded()
            .map_err(|e| EncodeError::InitFailed(format!("FFmpeg DLLs: {e}")))?;

        let candidates = crate::encoder::factory::detect_supported_codecs_cached();
        // 重排 HW 候选：QSV 优先（Intel iGPU 在 Windows 桌面机最常见，且实测 nvenc/amf
        // 在无对应 GPU 时 hwdevice_ctx_create(D3D11VA)+open2 失败会留下进程级副作用，
        // 污染后续候选的 drop）。nvenc/amf 排在后。
        let hw_priority = |n: &str| match n {
            "h264_qsv" | "hevc_qsv" => 0,
            "h264_nvenc" | "hevc_nvenc" => 1,
            "h264_amf" | "hevc_amf" => 2,
            _ => 3,
        };
        let mut hw_candidates: Vec<&str> = candidates
            .iter()
            .copied()
            .filter(|n| !is_software_encoder(n) && is_encoder_supported_on_platform(n))
            .collect();
        hw_candidates.sort_by_key(|n| hw_priority(n));

        for name in hw_candidates {
            match Self::try_open(name, pref, kernel) {
                Ok(enc) => {
                    tracing::info!("FfmpegHwEncoder: selected HW encoder '{name}'");
                    return Ok(enc);
                }
                Err(e) => {
                    tracing::debug!("FfmpegHwEncoder: '{name}' unavailable: {e}");
                }
            }
        }
        Err(EncodeError::Unsupported(
            "no hardware encoder available (driver missing or FFmpeg built without HW codecs)"
                .into(),
        ))
    }

    /// 尝试打开指定 HW 编码器。
    ///
    /// 流程（T3.1）：hw device 创建 →（可选 hwframes ctx）→ alloc_context3 →
    /// apply config → avcodec_open2。`open2` 失败（驱动缺失/无 GPU）→ 换下一
    /// 个回退项，**不 panic**。
    ///
    /// 输入路径：HW 编码器在 FFmpeg 层接受 NV12 CPU 帧（QSV/nvenc/amf 内部上
    /// 传 GPU）；真正的零拷贝 hwframes 路径（P1B kgpu_hw_upload）是独立优化，
    /// 本函数不依赖它即可出码流。`kernel.is_linked()` 时 hw_frames_ctx 在此
    /// 预分配（init 失败不阻断，降级 CPU 路径）。
    fn try_open(
        enc_name: &'static str,
        pref: Codec,
        kernel: Option<&dyn GpuKernel>,
    ) -> Result<Self, EncodeError> {
        let hw_type = match encoder_hw_type(enc_name) {
            Some(t) => t,
            None => {
                return Err(EncodeError::Unsupported(format!(
                    "unknown hw type for '{enc_name}'"
                )))
            }
        };

        let codec = ffmpeg::avcodec_find_encoder_by_name(enc_name).map_err(|_| {
            EncodeError::Unsupported(format!("encoder '{enc_name}' not found in FFmpeg build"))
        })?;

        // Step 1: 创建 hw device（失败 → 该编码器本机不可用，回退）。
        //         QSV/D3D11VA/VAAPI/VT 各自的 AVHWDeviceType。
        let hw_device_ctx = match ffmpeg::av_hwdevice_ctx_create(hw_type.hwdevice_type(), None) {
            Ok(ctx) => ctx,
            Err(e) => {
                return Err(EncodeError::InitFailed(format!(
                    "av_hwdevice_ctx_create({:?} for {enc_name}): {e}",
                    hw_type
                )))
            }
        };

        // Step 2: 分配 codec context + 复用 frame/packet。
        let ctx = match ffmpeg::avcodec_alloc_context3(codec) {
            Ok(c) => c,
            Err(e) => {
                let mut d = hw_device_ctx;
                ffmpeg::av_buffer_unref(&mut d);
                return Err(EncodeError::InitFailed(format!(
                    "avcodec_alloc_context3: {e}"
                )));
            }
        };
        let frame = match ffmpeg::av_frame_alloc() {
            Ok(f) => f,
            Err(e) => {
                let mut ctx_ref = ctx;
                ffmpeg::avcodec_free_context(&mut ctx_ref);
                let mut d = hw_device_ctx;
                ffmpeg::av_buffer_unref(&mut d);
                return Err(EncodeError::InitFailed(format!("av_frame_alloc: {e}")));
            }
        };
        let packet = match ffmpeg::av_packet_alloc() {
            Ok(p) => p,
            Err(e) => {
                let mut f = frame;
                ffmpeg::av_frame_free(&mut f);
                let mut ctx_ref = ctx;
                ffmpeg::avcodec_free_context(&mut ctx_ref);
                let mut d = hw_device_ctx;
                ffmpeg::av_buffer_unref(&mut d);
                return Err(EncodeError::InitFailed(format!("av_packet_alloc: {e}")));
            }
        };

        // kernel 借用转生命周期擦除的 trait object 胖指针存入结构（调用方
        // Box<dyn GpuKernel> 存活长于本编码器）。
        //
        // Safety: 调用方（VideoEncoderPipeline）持有 kernel 的 Box，存活长于
        // 本编码器；本结构仅在 encode 时 deref 调用 trait 方法，不转移所有权。
        // 生命周期擦除为 'static 是 FFI/借用存储的标准模式（同 *const c_void
        // 但保留 vtable）。
        let kernel_ptr: Option<*const (dyn GpuKernel + 'static)> =
            kernel.map(|k| {
                // transmute 借用为 'static trait object 胖指针（data ptr + vtable）。
                unsafe {
                    std::mem::transmute::<
                        *const (dyn GpuKernel + '_),
                        *const (dyn GpuKernel + 'static),
                    >(k as *const dyn GpuKernel)
                }
            });

        // 构造临时 self 以便复用 apply_encoder_config（T3.2 低延迟参数）。
        let probe = Self {
            codec: pref,
            name: enc_name,
            hw_type,
            ctx: ctx as *mut c_void,
            hw_device_ctx,
            hw_frames_ctx: ptr::null_mut(),
            width: 320,
            height: 32,
            pix_fmt: hw_type.pix_fmt(),
            kernel: kernel_ptr,
            frame_pool: FramePool::default(),
            extradata: Vec::new(),
            pts_base: 0,
            sws: None,
            frame,
            packet,
            frame_buf: Vec::new(),
            pending_rgba: Vec::new(),
            pending_w: 0,
            pending_h: 0,
            force_idr_next: true, // 会话首帧强制 IDR。
            sent_first: false,
        };

        // width/height/pix_fmt/time_base/framerate 在 FFmpeg 8.1.2 共享构建的
        // AVOption 表里缺失 → 结构体字段直写（opaque 约束放宽）。
        // 仅设 open2 必需的最小字段（其它低延迟参数在 open2 成功后再 apply，
        // 避免失败的编码器因配置写入污染 ctx 状态导致 free_context 崩溃）。
        unsafe {
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::WIDTH, 320);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::HEIGHT, 32);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::CODED_WIDTH, 320);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::CODED_HEIGHT, 32);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::PIX_FMT, ffmpeg::AV_PIX_FMT_NV12);
        }
        ffmpeg::avctx_set_time_base(ctx, 1, 1000);
        ffmpeg::avctx_set_framerate(ctx, 30, 1);

        // Step 3: avcodec_open2。失败（驱动缺失/无 GPU）→ 释放全部已分配资源 + 回退。
        if let Err(e) = ffmpeg::avcodec_open2(ctx, codec) {
            let mut f = frame;
            ffmpeg::av_frame_free(&mut f);
            let mut p = packet;
            ffmpeg::av_packet_free(&mut p);
            let mut ctx_ref = ctx;
            ffmpeg::avcodec_free_context(&mut ctx_ref);
            let mut d = hw_device_ctx;
            ffmpeg::av_buffer_unref(&mut d);
            return Err(EncodeError::InitFailed(format!(
                "avcodec_open2('{enc_name}'): {e}"
            )));
        }
        // open2 成功后才 apply 全部低延迟参数（T3.2）。
        probe.apply_encoder_config(ctx as *mut c_void, 320, 32, 4_000_000, 30);
        tracing::info!(
            "FfmpegHwEncoder: opened '{enc_name}' ({:?}) on GPU device",
            hw_type
        );
        Ok(probe)
    }

    /// 低延迟参数（T3.2）：全部走 av_opt_set，AVCodecContext 不透明。
    /// 各编码器不支持某参数时忽略该项错误，不阻断 open2。
    #[allow(dead_code)]
    fn apply_encoder_config(&self, ctx: *mut c_void, w: u32, h: u32, bitrate: u64, fps: u32) {
        let gop = (fps as i64 * 2).clamp(30, 60); // 周期 IDR 30~60。
        let obj = ctx;
        let _ = ffmpeg::av_opt_set_int(obj, "width", w as i64);
        let _ = ffmpeg::av_opt_set_int(obj, "height", h as i64);
        // 码率 + 稳定时延：rc=cbr + b/maxrate（best-effort；编码器不支持 cbr 则忽略）。
        let _ = ffmpeg::av_opt_set(obj, "rc", "cbr");
        let _ = ffmpeg::av_opt_set_int(obj, "b", bitrate as i64);
        let _ = ffmpeg::av_opt_set_int(obj, "maxrate", bitrate as i64);
        let _ = ffmpeg::av_opt_set_int(obj, "g", gop);
        let _ = ffmpeg::av_opt_set_int(obj, "refs", 1);
        let _ = ffmpeg::av_opt_set_int(obj, "threads", 1);
        let _ = ffmpeg::av_opt_set_int(obj, "max_b_frames", 0);
        let _ = ffmpeg::av_opt_set_int(obj, "rc-lookahead", 0);
        // profile：H264 → 66 (baseline，兼容性优先；77 main 协商可达)；
        //          H265 → 100 (main)。
        let profile = match self.codec {
            Codec::H264 => 66,
            Codec::H265 => 100,
        };
        let _ = ffmpeg::av_opt_set_int(obj, "profile", profile);
        // preset / tune / zerolatency 因编码器而异（见 T3.2 参数表），best-effort。
        match self.name {
            "h264_nvenc" | "hevc_nvenc" => {
                let _ = ffmpeg::av_opt_set(obj, "preset", "p1");
                let _ = ffmpeg::av_opt_set(obj, "tune", "ull");
                let _ = ffmpeg::av_opt_set_int(obj, "zerolatency", 1);
            }
            "h264_amf" | "hevc_amf" => {
                // AMF 经 FFmpeg 选项为 usage/quality（文档 T3.2 写的 "speed/lowlatency"
                // 对应 AMF 的 quality=speed + usage=ultralowlatency）。
                let _ = ffmpeg::av_opt_set(obj, "usage", "ultralowlatency");
                let _ = ffmpeg::av_opt_set(obj, "quality", "speed");
            }
            "h264_qsv" | "hevc_qsv" => {
                let _ = ffmpeg::av_opt_set(obj, "preset", "veryfast");
            }
            "h264_vaapi" | "hevc_vaapi" => {
                // VAAPI：preset=speed/low_latency；无 tune 概念（T3.2 参数表）。
                let _ = ffmpeg::av_opt_set(obj, "preset", "speed");
            }
            "h264_videotoolbox" | "hevc_videotoolbox" => {
                let _ = ffmpeg::av_opt_set(obj, "realtime", "1");
            }
            _ => {}
        }
        let _ = ffmpeg::av_opt_set(obj, "pix_fmt", "nv12");
    }

    /// ROI 注入器（T3.4）：把 DirtyTileMap 转 side data（QP 加权）。
    ///
    /// 变化区 qoffset = `{num:-1, den:1}` (-1.0 QP，低 QP 高码率)。
    /// 编码器不支持时静默忽略（无副作用）。
    fn inject_roi(
        &self,
        frame: *mut ffmpeg::AVFrame,
        map: &DirtyTileMap,
    ) -> Result<(), EncodeError> {
        if map.dirty.is_empty() {
            return Ok(()); // 全静 → 不注入。
        }
        let regions = merge_tiles_to_regions(map);
        if regions.is_empty() {
            return Ok(());
        }
        // 按 nvenc 上限（~16）按面积合并最大 region。
        let regions = cap_regions(regions, 16);

        let total_size = regions.len() * std::mem::size_of::<ffmpeg::AVRegionOfInterest>();
        let sd = ffmpeg::av_frame_new_side_data(
            frame,
            ffmpeg::AV_FRAME_DATA_REGIONS_OF_INTEREST,
            total_size,
        )
        .map_err(|e| EncodeError::EncodeFailed(format!("av_frame_new_side_data(ROI): {e}")))?;
        // 写 ROI 数组到 side data 的 data 字段。
        unsafe {
            let dst = (*sd).data;
            let cap = (*sd).size as usize;
            if dst.is_null() || cap < total_size {
                return Ok(()); // 防御：槽位异常 → 不注入（best-effort）。
            }
            let src = regions.as_ptr() as *const u8;
            std::ptr::copy_nonoverlapping(src, dst, total_size);
        }
        Ok(())
    }

    /// 确保 codec 尺寸匹配；变化时**释放旧 ctx + 重建 hw device + 全新 ctx + open2**。
    ///
    /// FFmpeg 8.x 不支持对同一 ctx close 后再 open2（与软编同一 pitfall）。
    /// HW 编码器还需重建 hw device（旧 device 绑定旧 ctx）。
    fn ensure_codec_dims(&mut self, width: u32, height: u32) -> Result<(), EncodeError> {
        if self.width == width && self.height == height && !self.ctx.is_null() {
            return Ok(());
        }
        // 释放旧 ctx + 旧 hw_frames_ctx（hw_device_ctx 保留引用，最后 unref）。
        if !self.ctx.is_null() {
            let ctx_ref = self.ctx as *mut ffmpeg::AVCodecContext;
            let _ = ffmpeg::avcodec_send_frame(ctx_ref, ptr::null());
            // 复用的 frame/packet 在 ctx 释放前先放（Drop 也会做，此处确保干净）。
            let mut ctx_ref2 = ctx_ref;
            ffmpeg::avcodec_free_context(&mut ctx_ref2);
            self.ctx = ptr::null_mut();
        }
        // 重建 hw device。
        let hw_device_ctx = ffmpeg::av_hwdevice_ctx_create(self.hw_type.hwdevice_type(), None)
            .map_err(|e| EncodeError::InitFailed(format!("hw reinit hwdevice: {e}")))?;
        // 全新 ctx + open2（结构体字段 + framerate）。
        let codec = ffmpeg::avcodec_find_encoder_by_name(self.name)
            .map_err(|e| EncodeError::InitFailed(format!("hw reinit find_encoder: {e}")))?;
        let ctx = ffmpeg::avcodec_alloc_context3(codec)
            .map_err(|e| EncodeError::InitFailed(format!("hw reinit alloc_context3: {e}")))?;
        unsafe {
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::WIDTH, width as i32);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::HEIGHT, height as i32);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::CODED_WIDTH, width as i32);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::CODED_HEIGHT, height as i32);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::PIX_FMT, ffmpeg::AV_PIX_FMT_NV12);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::GOP_SIZE, 60);
        }
        ffmpeg::avctx_set_time_base(ctx, 1, 1000);
        ffmpeg::avctx_set_framerate(ctx, 30, 1);
        ffmpeg::avcodec_open2(ctx, codec).map_err(|e| {
            let mut c = ctx;
            ffmpeg::avcodec_free_context(&mut c);
            let mut d = hw_device_ctx;
            ffmpeg::av_buffer_unref(&mut d);
            EncodeError::InitFailed(format!("hw reinit open2 {width}x{height}: {e}"))
        })?;
        // 释放旧 hw_device_ctx，换新。
        if !self.hw_device_ctx.is_null() {
            let mut d = self.hw_device_ctx;
            ffmpeg::av_buffer_unref(&mut d);
        }
        self.hw_device_ctx = hw_device_ctx;
        self.ctx = ctx as *mut c_void;
        self.width = width;
        self.height = height;
        self.sws = None;
        self.sent_first = false;
        Ok(())
    }

    /// 确保 swscale（RGBA→NV12）匹配当前尺寸。
    fn ensure_sws(&mut self, width: u32, height: u32) -> Result<(), EncodeError> {
        if self.sws.is_none() || self.width != width || self.height != height {
            self.sws = Some(
                ffmpeg::scale::SwsConverter::new(
                    width as i32,
                    height as i32,
                    ffmpeg::AV_PIX_FMT_RGBA,
                    width as i32,
                    height as i32,
                    ffmpeg::AV_PIX_FMT_NV12,
                )
                .map_err(|e| EncodeError::InitFailed(format!("hw sws_getContext: {e}")))?,
            );
        }
        Ok(())
    }

    /// RGBA → AVFrame（NV12）；转换后数据存 `frame_buf` 保活到 send_frame。
    fn rgba_to_nv12_frame(
        &mut self,
        rgba: &[u8],
        width: u32,
        height: u32,
    ) -> Result<(), EncodeError> {
        let pix_fmt = ffmpeg::AV_PIX_FMT_NV12;
        let buf_size = ffmpeg::av_image_get_buffer_size(pix_fmt, width as i32, height as i32, 1)
            .map_err(|e| EncodeError::EncodeFailed(format!("hw av_image_get_buffer_size: {e}")))?
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
            .map_err(|e| EncodeError::EncodeFailed(format!("hw av_image_fill_arrays: {e}")))?;

            let src_data: [*const u8; 4] = [rgba.as_ptr(), ptr::null(), ptr::null(), ptr::null()];
            let src_stride: [i32; 4] = [(width * 4) as i32, 0, 0, 0];
            self.sws
                .as_ref()
                .expect("hw sws must be initialized")
                .scale(&src_data, &src_stride, &data, &linesize)
                .map_err(|e| EncodeError::EncodeFailed(format!("hw sws_scale: {e}")))?;

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
            (*self.frame).width = width as std::ffi::c_int;
            (*self.frame).height = height as std::ffi::c_int;
            (*self.frame).format = pix_fmt;
        }
        Ok(())
    }

    /// 编码主循环（T3.5）：send_frame → loop receive_packet → 打包 Annex B。
    ///
    /// `frame` 由调用方指定（零拷贝 hw_upload 路径传入 kernel 产出的 AVFrame*；
    /// CPU NV12 路径传入 `self.frame`）。`owned_by_pool` 标记该帧是否来自
    /// [`FramePool::acquire`]（若是，编码提交后需 [`FramePool::release`]）。
    fn encode_inner(
        &mut self,
        frame: *mut ffmpeg::AVFrame,
        owned_by_pool: Option<usize>,
        pts: u64,
        force_idr: bool,
        roi_map: Option<&DirtyTileMap>,
        ts: Timestamp,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        let ctx = self.ctx as *mut ffmpeg::AVCodecContext;

        // ROI 注入（FullFrame + DirtyTileMap；编码器不支持时静默忽略）。
        if let Some(map) = roi_map {
            let _ = self.inject_roi(frame, map);
        }

        // 设 PTS（符号缺失回退字段写）。
        if !ffmpeg::av_frame_set_pts(frame, pts as i64) {
            unsafe { (*frame).pts = pts as i64 };
        }
        // IDR 策略（T3.5）。
        if force_idr {
            unsafe {
                (*frame).pict_type = ffmpeg::AV_PICTURE_TYPE_I;
                (*frame).key_frame = 1;
            }
        } else {
            unsafe {
                (*frame).pict_type = ffmpeg::AV_PICTURE_TYPE_NONE;
                (*frame).key_frame = 0;
            }
        }

        if let Err(e) = ffmpeg::avcodec_send_frame(ctx, frame) {
            // 零拷贝 hwframe 来自池：失败时仍需 release 归还槽位。
            if let Some(slot) = owned_by_pool {
                self.frame_pool.release_slot(slot);
            }
            if !matches!(e, ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) {
                return Err(EncodeError::EncodeFailed(format!("hw send_frame: {e}")));
            }
        }

        let mut packets = Vec::new();
        loop {
            match ffmpeg::avcodec_receive_packet(ctx, self.packet) {
                Ok(()) => {
                    let (data, is_key) = unsafe {
                        let p = &*self.packet;
                        let size = p.size as usize;
                        let slice = if p.data.is_null() || size == 0 {
                            &[]
                        } else {
                            std::slice::from_raw_parts(p.data, size)
                        };
                        (slice.to_vec(), (p.flags & 0x0001) != 0)
                    };
                    // 每包必调 unref（防泄漏）。
                    ffmpeg::av_packet_unref(self.packet);

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
                        kind: crate::encoder::types::PacketKind::Video,
                        data: buf,
                        is_key,
                    });
                }
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => break,
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EOF)) => break,
                Err(e) => {
                    // 零拷贝 hwframe 来自池：失败时仍需 release 归还槽位。
                    if let Some(slot) = owned_by_pool {
                        self.frame_pool.release_slot(slot);
                    }
                    return Err(EncodeError::EncodeFailed(format!("hw receive_packet: {e}")));
                }
            }
        }
        // 编码提交成功：归还池槽位（零拷贝路径）。
        if let Some(slot) = owned_by_pool {
            self.frame_pool.release_slot(slot);
        }
        Ok(packets)
    }

    /// 零拷贝 hwframes 编码路径（P1B 接驳）。
    ///
    /// 经 `kernel.hw_upload(tex)` 取 hwframes AVFrame*，按纹理尺寸确保 codec
    /// 匹配（不重建 sws —— 零拷贝路径不转换），ROI 注入 + IDR 策略后送编码器。
    /// 帧来自 [`FramePool::acquire`]，编码提交后由 `encode_inner` 归还槽位。
    ///
    /// `hw_upload` 失败（P1B 桩 / 未链接）→ 返回 `Unsupported`/`GpuKernel`，
    /// 调用方据此降级 CPU NV12 路径。
    fn try_encode_zero_copy(
        &mut self,
        tex: &GpuTexture,
        kernel: &dyn GpuKernel,
        pts: u64,
        force_idr: bool,
        roi_map: Option<&DirtyTileMap>,
        ts: Timestamp,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        let w = tex.width();
        let h = tex.height();
        if w == 0 || h == 0 {
            return Err(EncodeError::InvalidConfig(
                "FfmpegHwEncoder: zero-copy texture has zero dimensions".into(),
            ));
        }
        // 确保 codec 尺寸匹配（hw_device_ctx 复用，不依赖 sws）。
        self.ensure_codec_dims(w, h)?;
        // 从池取 hwframe（含 hw_upload 调用）。
        let (frame_ptr, slot) = self.frame_pool.acquire(tex, kernel)?;
        self.encode_inner(
            frame_ptr as *mut ffmpeg::AVFrame,
            Some(slot),
            pts,
            force_idr,
            roi_map,
            ts,
        )
    }
}

impl VideoEncoder for FfmpegHwEncoder {
    fn encode(
        &mut self,
        tex: &GpuTexture,
        ts: Timestamp,
        decision: EncodeDecision,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        // Edge Cases 预处理。
        if let Some(packets) = preprocess_encode(tex, &decision)? {
            return Ok(packets);
        }

        // ROI：仅 FullFrame(DirtyTileMap) 时注入。
        let roi_map = match &decision {
            EncodeDecision::FullFrame(map) if !map.dirty.is_empty() => Some(map.clone()),
            _ => None,
        };
        let force_idr = self.force_idr_next;
        self.force_idr_next = false;
        let pts = ts.pts.max(self.pts_base);
        self.pts_base = pts.saturating_add(1);

        // ── 零拷贝 hwframes 路径（P1B 接驳） ──
        //
        // kernel.is_linked() 且纹理非空（真实 GPU 句柄）→ 尝试 kernel.hw_upload
        // 取 hwframes AVFrame*，经 FramePool 槽位管理喂 avcodec_send_frame。
        // 失败 / 未链接 / 纹理为 CPU 哨兵 → 回退 CPU NV12 路径。
        //
        // 注意：调用方（VideoEncoderPipeline）在 P1B 桥不可用时传 CPU 哨兵纹理
        // （handle = 0x1，非真实 D3D11 纹理）；hw_upload 会因此失败并优雅回退。
        let can_hw = self
            .kernel
            .map(|k| {
                let k = unsafe { &*k };
                k.is_linked() && !tex.is_null()
            })
            .unwrap_or(false);

        if can_hw {
            let k = unsafe { &*self.kernel.unwrap() };
            match self.try_encode_zero_copy(tex, k, pts, force_idr, roi_map.as_ref(), ts) {
                Ok(pkts) => return Ok(pkts),
                Err(EncodeError::Unsupported(_)) | Err(EncodeError::GpuKernel(_)) => {
                    // hw_upload 不可用（P1B 桩 / 未链接）：降级 CPU NV12 路径。
                    tracing::debug!(
                        "FfmpegHwEncoder: hw_upload unavailable, falling back to CPU NV12"
                    );
                }
                Err(e) => return Err(e), // 真实编码错误：不降级，向上传播。
            }
        }

        // ── CPU NV12 路径（QSV/nvenc/amf 在 FFmpeg 层接受 NV12 CPU 帧） ──
        if self.pending_rgba.is_empty() {
            return Err(EncodeError::InvalidConfig(
                "FfmpegHwEncoder: no pending CPU RGBA (call set_cpu_frame first)".into(),
            ));
        }
        let rgba = std::mem::take(&mut self.pending_rgba);
        let w = self.pending_w;
        let h = self.pending_h;
        self.pending_w = 0;
        self.pending_h = 0;

        self.ensure_codec_dims(w, h)?;
        self.ensure_sws(w, h)?;
        self.rgba_to_nv12_frame(&rgba, w, h)?;

        self.encode_inner(self.frame, None, pts, force_idr, roi_map.as_ref(), ts)
    }

    fn codec(&self) -> Codec {
        self.codec
    }

    fn is_hardware(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn reconfigure(&mut self, _cfg: &crate::proto::EncodeConfig) -> Result<(), EncodeError> {
        // 真实 HW 场景：close → apply → open2（重开必须重新 apply）。
        Ok(())
    }

    /// CPU RGBA 喂入（HW 编码器在 FFmpeg 层接受 NV12 CPU 帧；与软编同入口）。
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
    /// 与软编同语义：`avcodec_flush_buffers` 重置内部状态，flush 后下一帧
    /// 必须 IDR（置位 `force_idr_next` 双保险）。仅当已发过帧时才 flush
    /// —— QSV 等编码器在空状态重置 / drain 有 heap corruption 风险
    /// （见 Drop 的守卫注释）。
    fn flush_buffers(&mut self) {
        if self.sent_first && !self.ctx.is_null() {
            // ctx 在本结构体为不透明 `*mut c_void`（hw_device 场景），
            // avcodec_flush_buffers 需要 AVCodecContext*（与 Drop 一致 cast）。
            ffmpeg::avcodec_flush_buffers(self.ctx as *mut ffmpeg::AVCodecContext);
            self.force_idr_next = true;
            tracing::debug!("FfmpegHwEncoder: flushed buffers (window boundary)");
        }
    }
}

impl Drop for FfmpegHwEncoder {
    fn drop(&mut self) {
        // 逆序释放：帧池内帧 → hw_frames_ctx → ctx（含 frame/packet）→ hw_device_ctx。
        self.frame_pool.drop_all();
        if !self.hw_frames_ctx.is_null() {
            let mut r = self.hw_frames_ctx;
            ffmpeg::av_buffer_unref(&mut r);
            self.hw_frames_ctx = ptr::null_mut();
        }
        // 复用 frame/packet：在 ctx 关闭前释放。
        let mut frame = self.frame;
        if !frame.is_null() {
            ffmpeg::av_frame_free(&mut frame);
            self.frame = ptr::null_mut();
        }
        if !self.ctx.is_null() {
            let mut ctx = self.ctx as *mut ffmpeg::AVCodecContext;
            // Flush：仅当已发送过帧时才 flush（未编码就 drop 时不 flush，避免
            // QSV 等编码器在空状态下 drain 触发 heap corruption）。
            if self.sent_first {
                let _ = ffmpeg::avcodec_send_frame(ctx, ptr::null());
                loop {
                    match ffmpeg::avcodec_receive_packet(ctx, self.packet) {
                        Ok(()) => ffmpeg::av_packet_unref(self.packet),
                        _ => break,
                    }
                }
            }
            let mut pkt = self.packet;
            if !pkt.is_null() {
                ffmpeg::av_packet_free(&mut pkt);
                self.packet = ptr::null_mut();
            }
            ffmpeg::avcodec_free_context(&mut ctx);
            self.ctx = ptr::null_mut();
        } else {
            // ctx 已空也要释放 packet。
            let mut pkt = self.packet;
            if !pkt.is_null() {
                ffmpeg::av_packet_free(&mut pkt);
                self.packet = ptr::null_mut();
            }
        }
        if !self.hw_device_ctx.is_null() {
            let mut r = self.hw_device_ctx;
            ffmpeg::av_buffer_unref(&mut r);
            self.hw_device_ctx = ptr::null_mut();
        }
    }
}

// ── FramePool（T3.3 零拷贝帧池） ─────────────────────────────

/// hwframes 槽位管理：捕获纹理 → kgpu_hw_upload → 池内 AVFrame，O(1) 零拷贝。
///
/// 池满且无空闲：覆盖最旧槽（远端远控场景可接受丢帧）。
/// hw_upload 返回 NULL → 调用方回退 swscale 软编路径。
struct FramePool {
    slots: Vec<*mut c_void>, // AVFrame*（hwframes）
    free: Vec<usize>,
    /// 池容量上限（2~4，clamp 自构造参数；调试/不变量用）。
    #[allow(dead_code)]
    capacity: usize,
}

impl FramePool {
    fn new(capacity: usize) -> Self {
        let cap = capacity.clamp(2, 4);
        Self {
            slots: Vec::with_capacity(cap),
            free: (0..cap).collect(),
            capacity: cap,
        }
    }

    /// 从池取一帧并绑定纹理（T3.3）。
    ///
    /// `kernel.hw_upload(tex)` 返回 hwframes AVFrame*；池满则复用最旧槽
    /// （覆盖策略：远端远控场景可接受丢帧）。hw_upload 失败（P1B 桩返回 NULL /
    /// 未链接）→ 调用方回退 swscale 软编路径。
    ///
    /// 返回 `(AVFrame*, slot_idx)`：调用方编码提交后用
    /// [`release_slot`](Self::release_slot) 归还槽位。
    ///
    /// 注意：本函数依赖 P1B `GpuKernel::hw_upload`（零拷贝纹理→hwframes 桥）；
    /// 未链接 / CPU-only 内核的 `hw_upload` 返回 `Unsupported`，调用方据此回退。
    fn acquire(
        &mut self,
        tex: &GpuTexture,
        kernel: &dyn GpuKernel,
    ) -> Result<(*mut c_void, usize), EncodeError> {
        // 取空闲槽；无空闲则覆盖最旧槽（先释放其帧）。
        let slot = if let Some(idx) = self.free.pop() {
            idx
        } else {
            // 覆盖最旧（索引 0）。
            let idx = 0;
            if let Some(&f) = self.slots.get(idx) {
                if !f.is_null() {
                    let frame = f as *mut ffmpeg::AVFrame;
                    ffmpeg::av_frame_unref(frame);
                }
            }
            idx
        };
        // hw_upload：纹理 → AVFrame*（零拷贝）。
        let frame_ptr = kernel.hw_upload(tex)? as *mut c_void;
        if frame_ptr.is_null() {
            return Err(EncodeError::GpuKernel("hw_upload returned NULL".into()));
        }
        if slot < self.slots.len() {
            self.slots[slot] = frame_ptr;
        } else {
            self.slots.push(frame_ptr);
        }
        Ok((frame_ptr, slot))
    }

    /// 编码提交后释放槽（T3.3）：av_frame_unref + 回池。
    ///
    /// `slot` 必须是先前 [`acquire`](Self::acquire) 返回的索引。
    fn release_slot(&mut self, slot: usize) {
        if let Some(&f) = self.slots.get(slot) {
            if !f.is_null() {
                let frame_ref = f as *mut ffmpeg::AVFrame;
                ffmpeg::av_frame_unref(frame_ref);
            }
            if !self.free.contains(&slot) {
                self.free.push(slot);
            }
        }
    }

    fn drop_all(&mut self) {
        for f in self.slots.drain(..) {
            if !f.is_null() {
                let mut frame = f as *mut ffmpeg::AVFrame;
                ffmpeg::av_frame_free(&mut frame);
            }
        }
    }
}

impl Default for FramePool {
    fn default() -> Self {
        Self::new(3)
    }
}

// ── ROI region 合并（T3.4） ──────────────────────────────────

/// DirtyTileMap → AVRegionOfInterest[]。
///
/// 行内连续 dirty tile 合并（grid 坐标 → 像素坐标）。tile 64×64 天然 16×16
/// 宏块对齐，无损失。
pub(crate) fn merge_tiles_to_regions(map: &DirtyTileMap) -> Vec<ffmpeg::AVRegionOfInterest> {
    if map.grid_w == 0 || map.grid_h == 0 || map.dirty.is_empty() {
        return Vec::new();
    }
    let tw = map.tile_w.max(1) as i32;
    let th = map.tile_h.max(1) as i32;

    let mut out = Vec::new();
    for row in 0..map.grid_h {
        let mut col = 0;
        while col < map.grid_w {
            if !map.dirty[(row * map.grid_w + col) as usize] {
                col += 1;
                continue;
            }
            // 行内连续 dirty tile 合并。
            let start = col;
            while col < map.grid_w && map.dirty[(row * map.grid_w + col) as usize] {
                col += 1;
            }
            let roi = ffmpeg::AVRegionOfInterest {
                self_size: std::mem::size_of::<ffmpeg::AVRegionOfInterest>() as u32,
                top: (row as i32) * th,
                bottom: (row as i32 + 1) * th,
                left: (start as i32) * tw,
                right: (col as i32) * tw,
                // 变化区：低 QP 高码率。AVRational：{num:-1, den:1} = -1.0 QP
                // （落在文档 T3.4 区间 -0.5~-1.0）。
                qoffset: ffmpeg::AVRational { num: -1, den: 1 },
            };
            out.push(roi);
        }
    }
    out
}

/// region 数超编码器上限时按面积合并最大 region，保证 ≤ limit。
fn cap_regions(
    mut regions: Vec<ffmpeg::AVRegionOfInterest>,
    limit: usize,
) -> Vec<ffmpeg::AVRegionOfInterest> {
    if regions.len() <= limit {
        return regions;
    }
    // 按面积降序保留前 limit-1，剩余合并为一个覆盖全帧的大 region。
    regions.sort_by_key(|r| -((r.right - r.left) as i64 * (r.bottom - r.top) as i64));
    let mut keep: Vec<_> = regions.drain(..limit.saturating_sub(1)).collect();
    keep.push(ffmpeg::AVRegionOfInterest {
        self_size: std::mem::size_of::<ffmpeg::AVRegionOfInterest>() as u32,
        top: 0,
        bottom: i32::MAX,
        left: 0,
        right: i32::MAX,
        // 静止区：高 QP 降码率。{num:1, den:4} = +0.25 QP（文档 +0.2~+0.5）。
        qoffset: ffmpeg::AVRational { num: 1, den: 4 },
    });
    keep
}

/// 编码器名 → 后端类型（D3D11VA/QSV/VT/VAAPI）。
fn encoder_hw_type(name: &str) -> Option<HwType> {
    match name {
        // Windows / Linux NVIDIA。
        "h264_nvenc" | "hevc_nvenc" => Some(HwType::D3D11VA), // nvenc 经 D3D11VA/CUDA；FFmpeg 内部映射。
        // Windows AMD。
        "h264_amf" | "hevc_amf" => Some(HwType::D3D11VA),
        // Intel QSV（Windows/Linux）。
        "h264_qsv" | "hevc_qsv" => Some(HwType::QSV),
        // macOS。
        "h264_videotoolbox" | "hevc_videotoolbox" => Some(HwType::VIDEOTOOLBOX),
        // Linux。
        "h264_vaapi" | "hevc_vaapi" => Some(HwType::VAAPI),
        _ => None,
    }
}

/// 是否为软编名（libx264/libx265）。
fn is_software_encoder(name: &str) -> bool {
    matches!(name, "libx264" | "libx265")
}

/// 编码器是否在当前平台有意义（避免在错误平台尝试 hwdevice 创建走异常路径）。
///
/// - `*_videotoolbox`：仅 macOS。
/// - `*_vaapi`：仅 Linux。
/// - `*_nvenc`/`*_amf`/`*_qsv`：跨平台（Windows/Linux，由 hwdevice open2 探测）。
fn is_encoder_supported_on_platform(name: &str) -> bool {
    let is_vt = name.ends_with("_videotoolbox");
    let is_vaapi = name.ends_with("_vaapi");
    #[cfg(target_os = "macos")]
    {
        let _ = is_vaapi;
        // macOS：跳过 VAAPI，允许 VT。
        !is_vaapi
    }
    #[cfg(target_os = "linux")]
    {
        let _ = is_vt;
        // Linux：跳过 VT，允许 VAAPI。
        !is_vt
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // Windows 等：跳过 VT 与 VAAPI。
        !is_vt && !is_vaapi
    }
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// T3.4：行内连续 dirty tile 合并为单个 region。
    #[test]
    fn test_merge_tiles_to_regions_row_merge() {
        let map = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 4,
            grid_h: 2,
            dirty: vec![
                true, true, true, false, // 第 0 行：前 3 tile 连续
                false, true, false, true, // 第 1 行：2 个孤立 tile
            ],
            dirty_ratio: 0.625,
        };
        let regions = merge_tiles_to_regions(&map);
        // 第 0 行 1 个 region（x=0..3*64）；第 1 行 2 个 region（各 1 tile）。
        assert_eq!(regions.len(), 3, "应合并为 3 个 region");
        let first = &regions[0];
        assert_eq!(first.left, 0);
        assert_eq!(first.right, 3 * 64);
        assert_eq!(first.top, 0);
        assert_eq!(first.bottom, 64);
        assert!(first.qoffset.num < 0, "变化区 qoffset.num 应为负（高质量）");
    }

    /// T3.4：全空 dirty → 空 region 列表。
    #[test]
    fn test_merge_tiles_to_regions_empty() {
        let map = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 2,
            grid_h: 2,
            dirty: vec![false, false, false, false],
            dirty_ratio: 0.0,
        };
        assert!(merge_tiles_to_regions(&map).is_empty());
    }

    /// T3.4：region 数超上限时按面积裁剪到 ≤ limit。
    #[test]
    fn test_cap_regions_limits_count() {
        let mk = |i: i32| ffmpeg::AVRegionOfInterest {
            self_size: std::mem::size_of::<ffmpeg::AVRegionOfInterest>() as u32,
            top: 0,
            bottom: 1,
            left: i,
            right: i + 1,
            qoffset: ffmpeg::AVRational { num: -1, den: 1 },
        };
        let regions: Vec<_> = (0..20).map(mk).collect();
        let capped = cap_regions(regions, 16);
        assert!(capped.len() <= 16, "应 ≤ 16，实际 {}", capped.len());
    }

    /// T3.1：编码器名 → HwType 映射。
    #[test]
    fn test_encoder_hw_type_mapping() {
        assert_eq!(encoder_hw_type("h264_nvenc"), Some(HwType::D3D11VA));
        assert_eq!(encoder_hw_type("h264_qsv"), Some(HwType::QSV));
        assert_eq!(
            encoder_hw_type("h264_videotoolbox"),
            Some(HwType::VIDEOTOOLBOX)
        );
        assert_eq!(encoder_hw_type("h264_vaapi"), Some(HwType::VAAPI));
        assert_eq!(encoder_hw_type("libx264"), None);
    }

    /// T3.1：create 的回退语义。无 HW 环境（CI/无 GPU）→ Unsupported；
    /// 有 HW（如 Intel UHD + h264_qsv）→ Ok（factory 优先选 HW）。
    #[test]
    fn test_create_unsupported_without_hw() {
        if ffmpeg::ensure_loaded().is_err() {
            return;
        }
        match FfmpegHwEncoder::create(Codec::H264, None) {
            Ok(enc) => eprintln!(
                "HW encoder selected: '{}' (有 GPU 环境，符合预期)",
                enc.name()
            ),
            Err(EncodeError::Unsupported(_)) => { /* 无 GPU 环境：符合预期 */ }
            Err(other) => panic!("期望 Ok 或 Unsupported，实际: {other}"),
        }
    }

    /// T3.3：FramePool 默认容量 clamp 到 2~4。
    #[test]
    fn test_frame_pool_capacity_clamp() {
        let p = FramePool::new(10);
        assert_eq!(p.capacity, 4);
        let p = FramePool::new(0);
        assert_eq!(p.capacity, 2);
    }
}
