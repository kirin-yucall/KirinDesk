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
//!
//! [`create`](FfmpegHwEncoder::create) / [`try_open`](FfmpegHwEncoder::try_open)
//! 接 `Option<&dyn GpuKernel>`：当 `kernel.is_linked()` 时
//! [`encode`](FfmpegHwEncoder::encode) 先尝试 `kernel.hw_upload(tex)` 走零拷贝
//! hwframes 路径（`av_hwframe_get_buffer` + `frame_pool.acquire/release`）；
//! 失败 / 未链接 / 无 pending 纹理 → 回退既有 CPU NV12 路径（`set_cpu_frame`
//! 喂入）。两条路径共用 `encode_inner` 的 receive_packet / 打包循环。
//!
//! 由桩（恒 NULL）替换为真实实现（NV12 纹理零拷贝直绑 / BGRA8 GPU 内转
//! NV12，动态加载 avutil-60.dll）；本文件的零拷贝接驳（设备串绑定 +
//! FramePool 槽位 + try_encode_zero_copy）无需改动即自动生效——`hw_upload`
//! 仅在无 FFmpeg 头/DLL、device lost 或纹理格式不支持时返 `GpuKernel` 错误，
//! 编码器据此回退 CPU NV12 路径（保底不变）。零拷贝断言见
//! `gpu_ffi/kernel.rs` 的 hw_bridge 测试（test_hw_upload_frame_type /
//! test_hw_upload_zero_copy）。
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


/// 2s→1s；I 帧开销抬升是 GOP 缩短自然结果，码率阶梯不动，带宽代价用户豁免）。
/// 与 SW 路统一口径（[`crate::encoder::video::ffmpeg_sw::SW_GOP_SIZE`]，单测钉死）。
/// 替代旧 `(fps*2).clamp(30,60)` 公式（fps 全调用点恒 30，公式 @30fps → 60
/// 已废弃——T4 后 GOP 为固定 30，不再随 fps 推导）。
pub(crate) const HW_GOP_SIZE: i64 = 30;


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
    bitrate_override: Option<u64>,
    force_reopen: bool,
    ///
    /// `None` = 尚未收到过配置（首次调用视作基线，幂等 `Ok`）；用于判定
    /// 「实际变更」——参数真的变化时才显式报 `NotImplemented`，不再静默吞掉。
    last_cfg: Option<crate::proto::EncodeConfig>,
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

        // `factory::detect_supported_codecs_for`）。旧实现所有 codec 都取
        // H264 链候选——`pref=H265` 请求会误试 `h264_*` 编码器（codec 错配：
        // `codec()` 报 H265 但码流实为 H.264）。
        let candidates = crate::encoder::factory::detect_supported_codecs_for(pref);
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

        // 看不到"HW all failed"的具体原因（2026-09-04 被控端落软编 40ms+/帧
        // 无从诊断）。全失败时单条 WARN 汇总，且汇总文本嵌入返回错误
        // （向上传递到跨 codec 兜底 warn，factory.rs:142 原样携带真实原因）。
        let mut failures: Vec<(String, String)> = Vec::new();
        for name in hw_candidates {
            // 的 open2 可能在本进程内直接 0xc0000005 崩溃（win11-5825u 实测，
            // `codec_bench --prefer-hw` 与单测双双进程级死亡）。探测子进程
            // 崩溃/超时/退出码非 0 一律按"不可用"跳过，父进程绝不触碰该候选；
            // 探测结果按（编码器 × 适配器指纹）进程内记忆化，每会话不重复 fork。
            // 非 Windows 保持既有 in-process 候选链（HW open 失败在 Unix 系
            // 返回错误而非进程崩溃）。
            if let Err(reason) = hw_encoder_available(name) {
                tracing::debug!("FfmpegHwEncoder: '{name}' probe unavailable: {reason}");
                failures.push((name.to_string(), format!("probe unavailable ({reason})")));
                continue;
            }
            match Self::try_open(name, pref, kernel) {
                Ok(enc) => {
                    tracing::info!("FfmpegHwEncoder: selected HW encoder '{name}'");
                    return Ok(enc);
                }
                Err(e) => {
                    tracing::debug!("FfmpegHwEncoder: '{name}' unavailable: {e}");
                    failures.push((name.to_string(), e.to_string()));
                }
            }
        }
        let summary = hw_failure_summary(&failures);
        tracing::warn!("FfmpegHwEncoder: {summary}");
        Err(EncodeError::Unsupported(summary))
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
        // 实测定案见设计文档 §3.5）；无选定适配器时直接 None（现状）。
        let hw_device_ctx =
            match create_hw_device_with_candidates(hw_type.hwdevice_type(), &crate::gpu::hwdevice_candidates())
            {
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

        // 旧硬编码 320×32 低于 AMF 最小分辨率 128×128 → open2 被 Init 拒绝
        // （error 5 = NOT_SUPPORTED）→ AMD 机器 amf 候选被永久跳过。
        let (probe_w, probe_h) = hw_probe_dimensions(enc_name);

        // 构造临时 self 以便复用 apply_encoder_config（T3.2 低延迟参数）。
        let probe = Self {
            codec: pref,
            name: enc_name,
            hw_type,
            ctx: ctx as *mut c_void,
            hw_device_ctx,
            hw_frames_ctx: ptr::null_mut(),
            width: probe_w,
            height: probe_h,
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
            bitrate_override: None,
            force_reopen: false,
            last_cfg: None,
        };

        // width/height/pix_fmt/time_base/framerate 在 FFmpeg 8.1.1 共享构建的
        // AVOption 表里缺失 → 结构体字段直写（opaque 约束放宽）。
        // 仅设 open2 必需的最小字段（其它低延迟参数在 open2 成功后再 apply，
        // 避免失败的编码器因配置写入污染 ctx 状态导致 free_context 崩溃）。
        unsafe {
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::WIDTH, probe_w as i32);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::HEIGHT, probe_h as i32);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::CODED_WIDTH, probe_w as i32);
            ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::CODED_HEIGHT, probe_h as i32);
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
        // 真实会话码率由 ensure_codec_dims 重开时按会话分辨率另取）。
        Self::apply_encoder_config(
            ctx as *mut c_void,
            enc_name,
            pref,
            probe_w,
            probe_h,
            crate::encoder::video::rate_ladder::bitrate_for_resolution(probe_w, probe_h),
        );
        tracing::info!(
            "FfmpegHwEncoder: opened '{enc_name}' ({:?}) on GPU device",
            hw_type
        );
        Ok(probe)
    }

    /// 低延迟参数（T3.2）：全部走 av_opt_set，AVCodecContext 不透明。
    /// 各编码器不支持某参数时忽略该项错误，不阻断 open2。
    ///
    /// **共用**——修复前重开路径从不应用本配置，会话编码器以默认参数裸奔）；
    /// 补 `bufsize = b`（1s VBV，对齐软编修复口径）。
    /// 全调用点 framerate 恒 30，旧公式 `(fps*2).clamp(30,60)` 无实际意义）；
    /// 逐编码器低延迟旋钮抽提为纯函数 [`hw_low_latency_options`]（单测钉死 +
    /// qsv/vaapi/videotoolbox 补齐，见该函数注释）。
    fn apply_encoder_config(
        ctx: *mut c_void,
        enc_name: &str,
        codec: Codec,
        w: u32,
        h: u32,
        bitrate: u64,
    ) {
        let gop = HW_GOP_SIZE;
        let obj = ctx;
        let _ = ffmpeg::av_opt_set_int(obj, "width", w as i64);
        let _ = ffmpeg::av_opt_set_int(obj, "height", h as i64);
        // 码率 + 稳定时延：rc=cbr + b/maxrate（best-effort；编码器不支持 cbr 则忽略）。
        let _ = ffmpeg::av_opt_set(obj, "rc", "cbr");
        // 命中编码器私有选项（qsv 等），`av_opt_set_int_self`（flag=0）命中
        // AVCodecContext 顶层字段（bit_rate/rc_max_rate/rc_buffer_size，nvenc/
        // amf 走此路）；两路互为冗余，未命中侧被忽略。
        let _ = ffmpeg::av_opt_set_int(obj, "b", bitrate as i64);
        let _ = ffmpeg::av_opt_set_int_self(obj, "b", bitrate as i64);
        let _ = ffmpeg::av_opt_set_int(obj, "maxrate", bitrate as i64);
        let _ = ffmpeg::av_opt_set_int_self(obj, "maxrate", bitrate as i64);
        //（修复 13900ES 实测日志 `VBV maxrate specified, but no bufsize`）。
        let _ = ffmpeg::av_opt_set_int(obj, "bufsize", bitrate as i64);
        let _ = ffmpeg::av_opt_set_int_self(obj, "bufsize", bitrate as i64);
        let _ = ffmpeg::av_opt_set_int(obj, "g", gop);
        let _ = ffmpeg::av_opt_set_int(obj, "refs", 1);
        let _ = ffmpeg::av_opt_set_int(obj, "threads", 1);
        let _ = ffmpeg::av_opt_set_int(obj, "max_b_frames", 0);
        let _ = ffmpeg::av_opt_set_int(obj, "rc-lookahead", 0);
        // profile：H264 → 66 (baseline，兼容性优先；77 main 协商可达)；
        //          H265 → 100 (main)。
        // 保证枚举穷尽；HW AV1 待 AV1 HW 链并入。
        let profile = match codec {
            Codec::H264 => 66,
            Codec::H265 => 100,
            Codec::AV1 => 0,
        };
        let _ = ffmpeg::av_opt_set_int(obj, "profile", profile);
        // 纯函数 [`hw_low_latency_options`] 逐路补齐低延迟配置，单测钉死），best-effort。
        for (key, value) in Self::hw_low_latency_options(enc_name) {
            let _ = ffmpeg::av_opt_set(obj, key, value);
        }
        let _ = ffmpeg::av_opt_set(obj, "pix_fmt", "nv12");
    }

    ///
    /// 目标 = **编码器内部延迟 ≤1 帧**：无 B 帧（共享 `max_b_frames=0`）+
    /// 无 lookahead（共享 `rc-lookahead=0` + 逐路低延迟模式）+ 输出
    /// delay/async 深度 0/1 + 低延迟 tune/preset。一切经 FFmpeg libavcodec
    /// `av_opt_set`（红线：禁厂商 SDK/自研）；best-effort 语义沿 T3.2 不变：
    /// 编码器不支持的选项被忽略，不阻断 open2（fail-closed 探测链保持）。
    ///
    /// |---|---|
    /// | nvenc | preset=p1 / tune=ull / zerolatency=1（原已齐，零变化） |
    /// | amf | usage=ultralowlatency / quality=speed（原已齐，零变化；AMF 低延迟模式即该 usage 档） |
    /// | qsv | preset=veryfast / **+ async_depth=1**（FFmpeg 默认 4 = 输出缓冲 4 帧期）/ **+ extbrc=0**（默认 1 = 内置 BRC/lookahead 延迟） |
    /// | vaapi | preset=speed / **+ low_latency=1**（禁 B 帧 + 单参考低延迟模式） |
    /// | videotoolbox | realtime=1 / **+ allow_frame_reordering=0**（帧重排 = 输出延迟） |
    ///
    /// 本机生产实选路径 = qsv（09-23 日志 `selected HW encoder 'h264_qsv'`）
    /// ——async_depth/extbrc 补齐即该路径的直接受益面。
    pub(crate) fn hw_low_latency_options(
        enc_name: &str,
    ) -> &'static [(&'static str, &'static str)] {
        match enc_name {
            "h264_nvenc" | "hevc_nvenc" => &[
                ("preset", "p1"),
                ("tune", "ull"),
                ("zerolatency", "1"),
            ],
            "h264_amf" | "hevc_amf" => &[
                ("usage", "ultralowlatency"),
                ("quality", "speed"),
            ],
            "h264_qsv" | "hevc_qsv" => &[
                ("preset", "veryfast"),
                ("async_depth", "1"),
                ("extbrc", "0"),
            ],
            "h264_vaapi" | "hevc_vaapi" => &[
                ("preset", "speed"),
                ("low_latency", "1"),
            ],
            "h264_videotoolbox" | "hevc_videotoolbox" => &[
                ("realtime", "1"),
                ("allow_frame_reordering", "0"),
            ],
            _ => &[],
        }
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
        if self.width == width
            && self.height == height
            && !self.ctx.is_null()
            && !self.force_reopen
        {
            return Ok(());
        }
        let reopening = self.force_reopen;
        // 释放旧 ctx + 旧 hw_frames_ctx（hw_device_ctx 保留引用，最后 unref）。
        if !self.ctx.is_null() {
            let ctx_ref = self.ctx as *mut ffmpeg::AVCodecContext;
            let _ = ffmpeg::avcodec_send_frame(ctx_ref, ptr::null());
            // 复用的 frame/packet 在 ctx 释放前先放（Drop 也会做，此处确保干净）。
            let mut ctx_ref2 = ctx_ref;
            ffmpeg::avcodec_free_context(&mut ctx_ref2);
            self.ctx = ptr::null_mut();
        }
        let hw_device_ctx = create_hw_device_with_candidates(
            self.hw_type.hwdevice_type(),
            &crate::gpu::hwdevice_candidates(),
        )
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
            ffmpeg::avctx_set_int(
                ctx,
                ffmpeg::avctx_offset::GOP_SIZE,
                HW_GOP_SIZE as i32,
            );
        }
        ffmpeg::avctx_set_time_base(ctx, 1, 1000);
        ffmpeg::avctx_set_framerate(ctx, 30, 1);
        // 参数——修复前本路径从不调用 apply_encoder_config，探测 ctx 的配置随
        // 探测结束丢弃，会话编码器以**编码器默认参数**裸奔（码率不可控，4K 画质
        // 同样崩坏）。且必须在 open2 前：nvenc/qsv/amf 在 encoder init 时一次性
        // 读取 b/maxrate/bufsize，open 之后再写 avctx 字段不会到达编码器 RC。
        // 码率按会话分辨率取阶梯（rate_ladder）。
        // （探测路径 try_open 保持 open2 后 apply 的旧序：探针 ctx 一次性丢弃，
        // 且失败候选提前写配置有 free_context 崩溃风险，见 T3.2 注释。）
        Self::apply_encoder_config(
            ctx as *mut c_void,
            self.name,
            self.codec,
            width,
            height,
            self.bitrate_override
                .unwrap_or_else(|| crate::encoder::video::rate_ladder::bitrate_for_resolution(width, height)),
        );
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
        if reopening {
            self.force_reopen = false;
            self.force_idr_next = true;
            tracing::info!(
                "FfmpegHwEncoder: reopened '{}' at {width}x{height} bitrate={} (tier change)",
                self.name,
                self.bitrate_override
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "ladder".into())
            );
        }
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

    fn reconfigure(&mut self, cfg: &crate::proto::EncodeConfig) -> Result<(), EncodeError> {
        //
        // 审计结论（2026-08-04）：生产唯一调用点 = WindowPipeline 每窗口编码
        // 前（`window_pipeline.rs::encode_window`，`let _ =` 忽略返回值），cfg
        // 源自自适应层（`session.rs` 轮询 shared_config → `update_encode_config`）。
        // 各参数字段现状：
        // - `force_idr`：真实语义（窗口首帧/跳帧后强制 IDR）——此处置位
        //   （`set_cpu_frame` 通道亦设置，双保险），与软编 `ffmpeg_sw.rs` 对齐；
        // - `frame_ratio`：由 `WindowPipeline::select_frames` 消费，不经编码器；
        // - 分辨率变更：**不走本通道**——由 `ensure_codec_dims` 按帧懒重开
        //   （释放旧 ctx → 重建 hw device → 全新 ctx + open2）；
        // - `qp`/`preset`：自适应层（`adaptive::adjuster.rs` compute_config /
        //   handle_encode_timeout）会真实产出变更，但 HW 编码器以 cbr 码率模式
        //   运行（`apply_encoder_config` 只设 b/maxrate），QP 无对应应用路径
        //   （全仓 grep `EncodeConfig.qp` 零消费者）→ **显式 NotImplemented**，
        //   调用方据此规避（记 warning 沿用旧配置），绝不假装成功。
        if cfg.force_idr {
            self.force_idr_next = true;
        }
        // 变更检测基于上次应用的基线；无论是否变更都先推进基线
        // （首次调用 = 建立基线；随后同参调用幂等 Ok，参数真实变化才报错）。
        let changed = match &self.last_cfg {
            Some(last) => last.qp != cfg.qp || last.preset != cfg.preset,
            None => false,
        };
        self.last_cfg = Some(cfg.clone());
        if changed {
            return Err(EncodeError::NotImplemented(format!(
                "FfmpegHwEncoder('{}'): runtime QP/preset change (qp {:?} -> {:?}, preset {:?} \
                 caller should keep the previous config",
                self.name,
                self.last_cfg.as_ref().map(|c| c.qp),
                cfg.qp,
                self.last_cfg.as_ref().map(|c| c.preset.as_str()),
                cfg.preset,
            )));
        }
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

    /// `ensure_codec_dims` 的 `force_reopen` 路径重建 ctx 并在 open2 前应用
    fn set_bitrate_override(&mut self, bps: Option<u64>) {
        if self.bitrate_override != bps {
            self.bitrate_override = bps;
            self.force_reopen = true;
        }
    }

    /// 窗口边界清参考帧（T2.3）。
    ///
    /// 与软编同语义：`avcodec_flush_buffers` 重置内部状态，flush 后下一帧
    /// 必须 IDR（置位 `force_idr_next` 双保险）。仅当已发过帧时才 flush
    /// —— QSV 等编码器在空状态重置 / drain 有 heap corruption 风险
    /// （见 Drop 的守卫注释）。
    ///
    /// **ZM-01 S2 实测结论（2026-08-02，Intel UHD 770 开发机）**：
    /// - `h264_qsv`：连续 3 窗口各编码 1 帧 + `avcodec_flush_buffers` 边界
    ///   flush，无错误无崩溃 → **保持现状**（QSV 支持该调用）。
    /// - `h264_nvenc`：8.1.2 构建要求 nvenc API 13.1 / 驱动 ≥610.00，本机 591.86
    ///   不满足（open2 拒绝，无 flush 语义可测）。2026-08-02 换 GyanD 8.1.1 构建
    ///   （ffnvcodec 13.0 头，libavcodec 62.28.101）后本机 h264/hevc_nvenc 实测
    ///   出码流 ✓。
    ///   注意：nvenc open 失败路径本身会堆损坏崩溃（0xc0000005/0xc0000374），
    ///   为既有隐患（更老驱动仍适用）；生产路径（软编优先 factory + qsv 兜底）
    ///   在本机不触达，不在本批次修复范围，登记观察。
    /// - 软编（libx264）同问题已修复（见 `ffmpeg_sw.rs::flush_buffers`，改
    ///   send-null + drain）。
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


/// 探测/初始 open2 尺寸统一采用 640×480（各 HW 编码器公开最小约束之上的
/// 安全值）。
///
///
/// | 后端 | 最小约束 | 320×32 旧探测尺寸 |
/// |------|----------|--------------------|
/// | AMF (VCN) | **128×128**（win11-5825u 实测：320×96/64×64 拒绝，128×128/320×128 接受；`AMFVideoEncoderHW` MinWidth/MinHeight caps） | 高 32 < 128 → **Init 拒绝（AMF error 5 = NOT_SUPPORTED）** |
/// | NVENC | H.264 145×49（NVIDIA 文档；HEVC 129×129） | 高 32 < 49 → 同样低于下限 |
/// | QSV | 16×16（Intel 文档） | 合法 |
/// | VideoToolbox | 16×16 | 合法 |
/// | VAAPI | 驱动相关（典型 16×16 + 对齐） | 多数合法 |
///
/// 历史缺陷：探测统一 320×32（源自软编占位尺寸），在 AMF 机器上 open2 即被
/// 拒（`encoder->Init() failed with error 5`）→ 候选被跳过 → AMD 机器永远
/// 落软编。OBS 等软件用正常分辨率探测所以无此问题。
///
/// **本函数只决定探测/初始 open2 尺寸**：真实会话分辨率不经此函数（首帧
/// `ensure_codec_dims` 按协商尺寸重开编码器）。保留 `enc_name` 入参以便
/// 未来按编码器精细化（如某后端上限/下限变化时单点调整）。
pub(crate) fn hw_probe_dimensions(_enc_name: &str) -> (u32, u32) {
    (640, 480)
}

/// 创建 hw device：按候选设备串逐个尝试绑定（§3.5）。
///
/// 候选顺序（[`crate::gpu::device_strings`]）：LUID 高32-低32 → 低32-高32 →
/// 描述名。
///
/// - `candidates` 为空（无选定适配器 / 非 Windows）→ 直接 `None`（现状
///   默认设备行为，GPU-NF-002；videotoolbox/vaapi 平台行为不变）；
/// - `candidates` 非空但全部失败 → **返回错误**（该编码器在本机不可用）——
///   让回退链自然继续：如 `KIRIN_GPU_PREFER=nvidia` 时 qsv 子设备（Intel
///   专属）创建失败 → create 落 nvenc（用 NVIDIA 串成功）。若此处 None
///   兜底，qsv 会在 FFmpeg 默认设备（Intel）上"成功"，单 GPU 绑定失效
///   （设计文档 §3.5）。
///
/// 绑定成功输出 info 日志（GPU-NF-005）；单个候选失败仅 debug。
fn create_hw_device_with_candidates(
    device_type: i32,
    candidates: &[String],
) -> Result<*mut ffmpeg::AVBufferRef, EncodeError> {
    if candidates.is_empty() {
        // 无选定适配器：保持现状默认设备行为（GPU-NF-002）。
        return ffmpeg::av_hwdevice_ctx_create(device_type, None).map_err(|e| {
            EncodeError::InitFailed(format!("av_hwdevice_ctx_create(default device): {e}"))
        });
    }
    for d in candidates {
        // 描述名含 NUL 时跳过（理论不可能，防御）。
        let Ok(c) = std::ffi::CString::new(d.as_str()) else {
            continue;
        };
        match ffmpeg::av_hwdevice_ctx_create(device_type, Some(&c)) {
            Ok(ctx) => {
                tracing::info!("FfmpegHwEncoder: hwdevice created on '{d}'");
                return Ok(ctx);
            }
            Err(e) => {
                tracing::debug!("FfmpegHwEncoder: hwdevice '{d}' failed: {e}");
            }
        }
    }
    Err(EncodeError::InitFailed(
        "av_hwdevice_ctx_create: all candidate device strings failed \
         (GPU binding mismatch, fallback chain continues)"
            .into(),
    ))
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
// ════════════════════════════════════════════════════════════════

/// 宿主可执行（UI `kirin_desk` / `codec_bench` 等）在 main 顶部经
/// [`probe_cli_entrypoint`] 拦截本参数，一次性探测后以退出码交付结果。
pub const PROBE_HW_ENCODER_ARG: &str = "--probe-hw-encoder";

/// 子进程探测超时（正常 open2 探测 <1s；超时按不可用处理并 kill）。
#[cfg(target_os = "windows")]
const PROBE_SUBPROC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// 探测子进程"干净失败"退出码（open2/设备创建报错）。父进程口径：
/// **只有 exit 0 才算可用**——panic（101）、原生崩溃（Windows
/// 0xC0000005 = 3221225477 等）、超时 kill、spawn 失败一律不可用。
const PROBE_EXIT_UNAVAILABLE: i32 = 3;

/// 探测允许的 HW 编码器白名单（同时充当 argv 名 → `&'static str` 的桥梁）。
const PROBE_KNOWN_ENCODERS: &[&str] = &[
    "h264_nvenc",
    "hevc_nvenc",
    "h264_amf",
    "hevc_amf",
    "h264_qsv",
    "hevc_qsv",
    "h264_videotoolbox",
    "hevc_videotoolbox",
    "h264_vaapi",
    "hevc_vaapi",
];

#[cfg(target_os = "windows")]
fn hw_probe_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, bool>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, bool>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 探测缓存键：编码器名 + 选定适配器指纹（vendor + LUID）。
///
/// 记忆化口径：任务要求按 **(vendor, 驱动版本)** 记忆化——进程存活期内
/// 驱动版本不变，故"编码器 × 适配器指纹"的进程内键与之等价（适配器
/// 切换/重枚举后键变化，探测重新执行）。每会话（每次
/// [`FfmpegHwEncoder::create`]）命中缓存即不再 fork。
#[cfg(target_os = "windows")]
fn probe_cache_key(enc_name: &str) -> String {
    let fp = crate::gpu::selected_adapter()
        .map(|a| format!("{:04x}-{:x}", a.vendor_id, a.luid))
        .unwrap_or_else(|| "default-device".to_string());
    format!("{enc_name}|{fp}")
}

/// 某 HW 编码器在本机是否可用（Windows：子进程隔离探测 + 记忆化；
/// 非 Windows：恒 Ok，保持既有 in-process 候选链行为）。
///
/// （探测跳过/退出码/超时/spawn 失败），供 [`FfmpegHwEncoder::create`]
/// 的全失败 WARN 汇总与错误消息使用（info 级可诊断，修复 2026-09-04
/// 被控端"HW all failed"无原因可查）。
fn hw_encoder_available(enc_name: &str) -> Result<(), String> {
    #[cfg(not(target_os = "windows"))]
    {
        // 返回而非进程崩溃，无隔离必要；子进程口径的跨平台推广待需求。
        let _ = enc_name;
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        // 逃生开关：KIRIN_HW_PROBE_DISABLE=1 → 不 fork、视全部 HW 候选不可用
        // （优雅落软编）；不写缓存（解除开关后恢复真实探测）。
        if std::env::var_os("KIRIN_HW_PROBE_DISABLE").is_some() {
            return Err("KIRIN_HW_PROBE_DISABLE=1 逃生开关（不 fork 探测）".to_string());
        }
        let key = probe_cache_key(enc_name);
        if let Ok(map) = hw_probe_cache().lock() {
            if let Some(&v) = map.get(&key) {
                return if v {
                    Ok(())
                } else {
                    Err("探测已记忆化为不可用（编码器×适配器指纹）".to_string())
                };
            }
        }
        let res = run_probe_subprocess(enc_name);
        if let Ok(mut map) = hw_probe_cache().lock() {
            map.insert(key, res.is_ok());
        }
        res
    }
}

/// [`PROBE_SUBPROC_TIMEOUT`]——由 [`FfmpegHwEncoder::create`] 同步路径调用，
/// 结果已记忆化（每键每进程至多阻塞一次）。
///
/// 供全失败 WARN 汇总。
#[cfg(target_os = "windows")]
fn run_probe_subprocess(enc_name: &str) -> Result<(), String> {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("hw probe: current_exe() failed: {e} — '{enc_name}' unavailable");
            return Err(format!("current_exe() 失败: {e}"));
        }
    };
    let mut child = match Command::new(exe)
        .arg(PROBE_HW_ENCODER_ARG)
        .arg(enc_name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("hw probe: spawn failed: {e} — '{enc_name}' unavailable");
            return Err(format!("spawn 失败: {e}"));
        }
    };
    let deadline = Instant::now() + PROBE_SUBPROC_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                // 崩溃（0xC0000005 等）/ panic / 干净失败统一不可用。
                tracing::info!(
                    "hw probe: '{enc_name}' unavailable in isolated subprocess \
                    status.code()
                );
                return Err(format!(
                    status.code()
                ));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::warn!(
                        "hw probe: '{enc_name}' exceeded {PROBE_SUBPROC_TIMEOUT:?} — unavailable"
                    );
                    return Err(format!("探测超时（>{PROBE_SUBPROC_TIMEOUT:?}）"));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                tracing::warn!("hw probe: try_wait failed: {e} — '{enc_name}' unavailable");
                return Err(format!("try_wait 失败: {e}"));
            }
        }
    }
}

///
/// `failures` = `[(编码器名, 失败原因)]`（保持候选尝试顺序）。空 = 无候选
/// 可试（回退链为空 / 全被平台过滤）。用途：① [`FfmpegHwEncoder::create`]
/// 全失败时的单条 WARN；② 返回 [`EncodeError::Unsupported`] 的文本——向上传递
/// 到跨 codec 兜底 warn（factory.rs），让 info 级日志携带真实失败原因。
fn hw_failure_summary(failures: &[(String, String)]) -> String {
    if failures.is_empty() {
        return "no HW encoder available (no candidates: FFmpeg build 无 HW 编码器或全被平台过滤)"
            .to_string();
    }
    let parts: Vec<String> = failures
        .iter()
        .map(|(name, reason)| format!("{name}: {reason}"))
        .collect();
    format!("no HW encoder available — {}", parts.join("; "))
}

/// 一次性探测并以退出码交付结果。**必须在一切应用初始化之前调用**
/// （GUI/CLI/参数解析/FFmpeg 自动下载之前——见 ui `run()` 与 codec_bench
/// `main()` 顶部拦截点）。
///
/// 返回 `Some(code)` = 本次进程即探测（调用方立即 `exit(code)`）；
/// `None` = 常规启动（参数不匹配）。
pub fn probe_cli_entrypoint() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    let i = args.iter().position(|a| a == PROBE_HW_ENCODER_ARG)?;
    let name = args.get(i + 1)?.clone();
    Some(probe_child_main(&name))
}

/// 320×32 低于 AMF 最小 128×128 触发 Init error 5；成功即 drop）。退出码：
/// 0 = 可用；[`PROBE_EXIT_UNAVAILABLE`] = 干净失败；panic → 101（Rust 默认）；
/// 原生崩溃（老驱动 amf/nvenc open 的 0xc0000005）由 OS 交付非零码——
/// 父进程统一按不可用处理，这正是崩溃隔离的意义所在。
fn probe_child_main(name: &str) -> i32 {
    // 白名单匹配（拒绝任意 argv 注入 FFmpeg 编码器名）。
    let Some(&enc_name) = PROBE_KNOWN_ENCODERS.iter().find(|n| **n == name) else {
        return PROBE_EXIT_UNAVAILABLE;
    };
    // 对齐 GPU 偏好（env 口径；config 文件口径由父进程的适配器选择通常一致，
    // 不一致时探测偏保守方向 = 误判不可用 → 落软编，安全）。
    let pref = crate::gpu::GpuPreferences {
        prefer: crate::gpu::preference_from_env(
            std::env::var("KIRIN_GPU_PREFER").ok(),
            crate::gpu::GpuPreference::Auto,
        ),
        ..crate::gpu::GpuPreferences::default()
    };
    let _ = crate::gpu::apply_preferences(pref);
    // FFmpeg DLL 加载（`try_open` 假定父路径 `create` 已 ensure_loaded——
    // 探针进程独立，必须自加载；失败按不可用交付）。
    if ffmpeg::ensure_loaded().is_err() {
        return PROBE_EXIT_UNAVAILABLE;
    }
    match FfmpegHwEncoder::try_open(enc_name, Codec::H264, None) {
        Ok(_probe) => 0, // 成功打开即视为可用（probe 随即 drop 释放全部句柄）。
        Err(_) => PROBE_EXIT_UNAVAILABLE,
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

    /// 「名: 原因」按序以 "; " 连接（WARN 汇总与错误消息共用，info 级可
    /// 诊断"HW all failed"的真实原因）。
    #[test]
    fn test_r76d_hw_failure_summary() {
        assert_eq!(
            hw_failure_summary(&[]),
            "no HW encoder available (no candidates: FFmpeg build 无 HW 编码器或全被平台过滤)"
        );
        let s = hw_failure_summary(&[
            (
                "h264_qsv".into(),
                "av_hwdevice_ctx_create(QSV for h264_qsv): No such device".into(),
            ),
        ]);
        assert!(s.starts_with("no HW encoder available — h264_qsv:"), "s: {s}");
        assert!(s.contains("av_hwdevice_ctx_create"), "s: {s}");
        assert!(s.contains("h264_nvenc: probe unavailable"), "s: {s}");
        assert_eq!(s.matches("; ").count(), 1, "两个候选一个分隔符: {s}");
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

    // ════════════════════════════════════════════════════════════════
    // 骨架构造器不触碰 FFmpeg 句柄（全 null / 空缓冲），仅验证
    // reconfigure 的纯状态逻辑（基线判定 / force_idr / 显式错误）。
    // ════════════════════════════════════════════════════════════════

    fn hw_encoder_skeleton() -> FfmpegHwEncoder {
        FfmpegHwEncoder {
            codec: Codec::H264,
            name: "h264_qsv",
            hw_type: HwType::QSV,
            ctx: ptr::null_mut(),
            hw_device_ctx: ptr::null_mut(),
            hw_frames_ctx: ptr::null_mut(),
            width: 640,
            height: 480,
            pix_fmt: 0,
            kernel: None,
            frame_pool: FramePool::new(2),
            extradata: Vec::new(),
            pts_base: 0,
            sws: None,
            frame: ptr::null_mut(),
            packet: ptr::null_mut(),
            frame_buf: Vec::new(),
            pending_rgba: Vec::new(),
            pending_w: 0,
            pending_h: 0,
            force_idr_next: false,
            sent_first: false,
            bitrate_override: None,
            force_reopen: false,
            last_cfg: None,
        }
    }

    fn enc_cfg(qp: u32, preset: &str, force_idr: bool) -> crate::proto::EncodeConfig {
        crate::proto::EncodeConfig {
            qp,
            force_idr,
            frame_ratio: 1.0,
            preset: preset.into(),
        }
    }

    /// 首次调用（无基线）→ 幂等 Ok，且 force_idr 真实置位。
    #[test]
    fn test_reconfigure_first_call_is_ok() {
        let mut enc = hw_encoder_skeleton();
        assert!(enc.reconfigure(&enc_cfg(22, "medium", true)).is_ok());
        assert!(enc.force_idr_next, "force_idr 应置位");
        assert_eq!(enc.last_cfg.as_ref().map(|c| c.qp), Some(22));
    }

    /// 相同参数重复调用 → Ok（无实际变更，不报错）。
    #[test]
    fn test_reconfigure_same_config_ok() {
        let mut enc = hw_encoder_skeleton();
        let cfg = enc_cfg(22, "medium", false);
        assert!(enc.reconfigure(&cfg).is_ok());
        assert!(enc.reconfigure(&cfg).is_ok(), "同参数应幂等 Ok");
        assert!(!enc.force_idr_next, "force_idr=false 不应置位");
    }

    /// QP 实际变更 → 显式 NotImplemented（不再静默成功）；force_idr 仍应用。
    #[test]
    fn test_reconfigure_qp_change_not_implemented() {
        let mut enc = hw_encoder_skeleton();
        assert!(enc.reconfigure(&enc_cfg(22, "medium", false)).is_ok());
        let err = enc
            .reconfigure(&enc_cfg(26, "medium", true))
            .expect_err("QP 变更必须显式报错，不再静默成功");
        assert!(
            matches!(err, EncodeError::NotImplemented(_)),
            "期望 NotImplemented，实际: {err}"
        );
        assert!(err.to_string().contains("not implemented"));
        // 报错前 force_idr 已应用（双保险通道）。
        assert!(enc.force_idr_next, "报错同时 force_idr 仍应置位");
        // 基线已推进到新值（后续同参调用 Ok）。
        assert_eq!(enc.last_cfg.as_ref().map(|c| c.qp), Some(26));
        assert!(enc.reconfigure(&enc_cfg(26, "medium", false)).is_ok());
    }

    /// preset 实际变更 → 显式 NotImplemented。
    #[test]
    fn test_reconfigure_preset_change_not_implemented() {
        let mut enc = hw_encoder_skeleton();
        assert!(enc.reconfigure(&enc_cfg(22, "medium", false)).is_ok());
        let err = enc
            .reconfigure(&enc_cfg(22, "ultrafast", false))
            .expect_err("preset 变更必须显式报错");
        assert!(matches!(err, EncodeError::NotImplemented(_)));
        assert_eq!(enc.last_cfg.as_ref().map(|c| c.preset.as_str()), Some("ultrafast"));
    }

    /// force_idr 单独变化（qp/preset 不变）→ Ok 且置位（软编同语义）。
    #[test]
    fn test_reconfigure_force_idr_only_ok() {
        let mut enc = hw_encoder_skeleton();
        assert!(enc.reconfigure(&enc_cfg(22, "medium", false)).is_ok());
        assert!(enc.reconfigure(&enc_cfg(22, "medium", true)).is_ok());
        assert!(enc.force_idr_next);
    }

    // ════════════════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════════════════

    /// 白名单拒绝：非白名单编码器名（含软编名/注入变体）不触碰 FFmpeg，
    /// 直接以 PROBE_EXIT_UNAVAILABLE 退出（argv 注入面封死）。
    #[test]
    fn test_probe_child_main_rejects_non_whitelisted_encoder() {
        assert_eq!(probe_child_main("libx264"), PROBE_EXIT_UNAVAILABLE);
        assert_eq!(probe_child_main("h264_nvenc_malicious"), PROBE_EXIT_UNAVAILABLE);
        assert_eq!(probe_child_main(""), PROBE_EXIT_UNAVAILABLE);
        assert_eq!(probe_child_main("libx265"), PROBE_EXIT_UNAVAILABLE);
    }

    /// 白名单形状：只含已知 HW 编码器名、无软编名、无重复。
    #[test]
    fn test_probe_whitelist_shape() {
        assert!(PROBE_KNOWN_ENCODERS.contains(&"h264_amf"));
        assert!(PROBE_KNOWN_ENCODERS.contains(&"h264_qsv"));
        assert!(PROBE_KNOWN_ENCODERS.contains(&"h264_nvenc"));
        assert!(!PROBE_KNOWN_ENCODERS.iter().any(|n| is_software_encoder(n)));
        let mut sorted = PROBE_KNOWN_ENCODERS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), PROBE_KNOWN_ENCODERS.len(), "白名单不得有重复项");
    }

    /// 常规启动（无 --probe-hw-encoder 参数）→ 入口不触发（None）。
    /// cargo test 进程参数由 libtest 持有，不含本隐藏参数。
    #[test]
    fn test_probe_cli_entrypoint_not_triggered_without_flag() {
        assert!(probe_cli_entrypoint().is_none());
    }

    /// 记忆化键口径（Windows）：同名稳定、异名区分、含适配器指纹段。
    #[cfg(target_os = "windows")]
    #[test]
    fn test_probe_cache_key_scopes_by_encoder_and_adapter() {
        let k1 = probe_cache_key("h264_amf");
        let k2 = probe_cache_key("h264_amf");
        let k3 = probe_cache_key("h264_qsv");
        assert_eq!(k1, k2, "同名编码器键必须稳定（命中缓存不重复 fork）");
        assert_ne!(k1, k3, "异名编码器键必须区分");
        assert!(
            k1.starts_with("h264_amf|"),
            "键必须以编码器名开头（含适配器指纹段）: {k1}"
        );
    }

    // ════════════════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════════════════

    /// 所有探测白名单编码器（含未知名兜底）的探测尺寸必须在已知 HW 最小
    /// QSV/VT/VAAPI ≥16×16。取最严的 128×128 下限断言。
    #[test]
    fn test_hw_probe_dimensions_above_all_hw_minimums() {
        let mut names: Vec<&str> = PROBE_KNOWN_ENCODERS.to_vec();
        names.push("h264_unknown_backend"); // 未知名兜底路径同样必须安全。
        for name in names {
            let (w, h) = hw_probe_dimensions(name);
            assert!(
                w >= 128 && h >= 128,
            );
        }
    }

    /// 探测尺寸必须为正偶数（YUV420/NV12 色度子采样要求，宽高奇数会在
    /// 部分 HW 后端 open2 被拒）。
    #[test]
    fn test_hw_probe_dimensions_even_and_pure() {
        for name in PROBE_KNOWN_ENCODERS {
            let (w, h) = hw_probe_dimensions(name);
            assert!(w > 0 && h > 0, "探测尺寸必须为正");
            assert_eq!(w % 2, 0, "'{name}' 探测宽 {w} 必须为偶数（NV12 子采样）");
            assert_eq!(h % 2, 0, "'{name}' 探测高 {h} 必须为偶数（NV12 子采样）");
            // 纯函数：同名重复调用结果一致。
            assert_eq!(hw_probe_dimensions(name), (w, h), "探测尺寸决策必须为纯函数");
        }
    }

    // ════════════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════════════

    /// 与 SW 路统一口径（旧 `(fps*2).clamp(30,60)` 公式不得复活）。
    #[test]
    fn test_r136_hw_gop_size_pinned() {
        assert_eq!(
            HW_GOP_SIZE,
            crate::encoder::video::ffmpeg_sw::SW_GOP_SIZE,
            "T4：SW/HW 两路 GOP 必须统一（SW_GOP_SIZE = HW_GOP_SIZE）"
        );
    }

    /// 无 B 帧（共享 max_b_frames=0）+ 无 lookahead（共享 rc-lookahead=0）+
    /// 输出 delay/async 深度 0/1 + 逐路低延迟 tune/preset。
    /// 无真硬件环境时本表即配置断言面（特性检测回退路径见
    /// `test_create_unsupported_without_hw` / `test_r136_hw_gop_effective_interval_real_hw`）。
    #[test]
    fn test_r136_hw_low_latency_options_per_path() {
        // nvenc：p1（最快 preset）+ ull（低延迟 tune）+ zerolatency=1（输出零延迟帧）。
        assert_eq!(
            FfmpegHwEncoder::hw_low_latency_options("h264_nvenc"),
            &[("preset", "p1"), ("tune", "ull"), ("zerolatency", "1")]
        );
        assert_eq!(
            FfmpegHwEncoder::hw_low_latency_options("hevc_nvenc"),
            FfmpegHwEncoder::hw_low_latency_options("h264_nvenc"),
            "hevc_nvenc 与 h264_nvenc 同路径口径"
        );
        // amf：ultralowlatency usage（AMF 低延迟模式）+ speed quality。
        assert_eq!(
            FfmpegHwEncoder::hw_low_latency_options("h264_amf"),
            &[("usage", "ultralowlatency"), ("quality", "speed")]
        );
        // qsv：veryfast + **async_depth=1**（输出深度默认 4 帧→1）+ **extbrc=0**
        // （内置 BRC/lookahead 关，默认 1）——本机生产实选路径（09-23 日志 h264_qsv）。
        assert_eq!(
            FfmpegHwEncoder::hw_low_latency_options("h264_qsv"),
            &[
                ("preset", "veryfast"),
                ("async_depth", "1"),
                ("extbrc", "0"),
            ]
        );
        // vaapi：speed + **low_latency=1**（禁 B 帧 + 单参考低延迟模式）。
        assert_eq!(
            FfmpegHwEncoder::hw_low_latency_options("h264_vaapi"),
            &[("preset", "speed"), ("low_latency", "1")]
        );
        // videotoolbox：realtime + **allow_frame_reordering=0**（帧重排 = 输出延迟）。
        assert_eq!(
            FfmpegHwEncoder::hw_low_latency_options("h264_videotoolbox"),
            &[("realtime", "1"), ("allow_frame_reordering", "0")]
        );
        // 未知/软编名 → 空表（best-effort 语义：不写旋钮、不阻断）。
        assert!(FfmpegHwEncoder::hw_low_latency_options("h264_unknown_backend").is_empty());
        assert!(FfmpegHwEncoder::hw_low_latency_options("libx264").is_empty());
    }

    /// HW → `create` 回 `Unsupported` → 诚实 skip，不造假自检）。
    ///
    /// 探测——测试二进制无 `probe_cli_entrypoint` 拦截（仅宿主 exe 有），
    /// 探测子进程失败 → 候选不可用 → 本测在 Windows 测试进程内恒走
    /// Unsupported 分支跳过；真硬件 GOP 实测经真实宿主进程执行（临时探针
    /// `r136_gop_probe`，数值见交付报告）。非 Windows 带真 GPU 环境则实编
    /// 300 帧 @30fps pts，断言周期 IDR 有效间隔落在设计带
    /// [gop×0.5, gop×1.25]（wrapper fps/pts 映射实测系数 ~0.68，SW 200 帧
    /// 探针口径：gop=60→每 41 帧）。
    #[test]
    fn test_r136_hw_gop_effective_interval_real_hw() {
        if ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let mut enc = match FfmpegHwEncoder::create(Codec::H264, None) {
            Ok(e) => e,
            Err(EncodeError::Unsupported(_)) => {
                eprintln!(
                    "no HW encoder available (feature detection: skip, 不造假自检); \
                );
                return;
            }
            Err(e) => panic!("HW create 返回非 Unsupported 错误: {e}"),
        };
        // 300 帧 @30fps（33ms/帧 pts，生产节奏同口径），伪随机内容逼出真实码流。
        let (w, h) = (640u32, 480u32);
        let mut seed = 0x9E3779B97F4A7C15u64;
        let mut key_frames: Vec<u32> = Vec::new();
        for i in 0..300u32 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(i as u64 + 1);
            let mut rgba = Vec::with_capacity((w * h * 4) as usize);
            for _ in 0..(w * h) {
                seed ^= seed >> 12;
                rgba.extend_from_slice(&[
                    seed as u8,
                    (seed >> 8) as u8,
                    (seed >> 16) as u8,
                    0xFF,
                ]);
            }
            enc.set_cpu_frame(&rgba, w, h, i == 0);
            let tex = GpuTexture::new(0x1usize as *mut _, w, h);
            let ts = Timestamp::new(std::time::Instant::now(), i as u64 * 33);
            let pkts = enc
                .encode(&tex, ts, EncodeDecision::FullFrame(DirtyTileMap::default()))
                .unwrap_or_else(|e| panic!("HW 帧 {i} 编码失败: {e}"));
            if pkts.iter().any(|p| p.is_key) {
                key_frames.push(i);
            }
        }
        // 有效间隔 = 相邻 key 帧帧号差（首帧 i=0 为会话 IDR，不计间隔）。
        let gaps: Vec<u32> = key_frames.windows(2).map(|w2| w2[1] - w2[0]).collect();
        if gaps.is_empty() {
            panic!(
                enc.name(),
                HW_GOP_SIZE,
                key_frames
            );
        }
        let mut sorted = gaps.clone();
        sorted.sort_unstable();
        let median = sorted[sorted.len() / 2];
        eprintln!(
            enc.name(),
            key_frames,
            median,
            HW_GOP_SIZE
        );
        assert!(
            median >= HW_GOP_SIZE as u32 / 2 && median <= HW_GOP_SIZE as u32 * 5 / 4,
            enc.name(),
            median,
            HW_GOP_SIZE
        );
    }
}
