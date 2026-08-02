//! Safe Rust wrappers around the FFmpeg C API.
//!
//! All functions here validate pointers, map FFmpeg's negative return codes to
//! [`AvError`], and panic on null from alloc functions (those indicate OOM or
//! corrupted state). The opaque [`AVCodecContext`] is configured exclusively
//! via `av_opt_set_int` / `av_opt_set` — never by writing struct fields.
//!
//! # Safety
//!
//! FFmpeg's C API is inherently unsafe. These wrappers:
//! - Validate pointers before dereference
//! - Track lifetimes of allocated objects (callers must pair alloc/free)
//! - Ensure the function table is loaded before any call

#![allow(non_camel_case_types, dead_code)]

use std::ffi::{c_void, CStr};
use std::ptr;

use super::dlls::fn_table;
use super::error::{av_result, AvError};
use super::types::{
    AVBufferRef, AVChannelLayout, AVCodec, AVCodecContext, AVFrame, AVFrameSideData, AVPacket,
    SwsContext, AV_CODEC_ID_H264, AV_CODEC_ID_H265,
};

// ── Version ──────────────────────────────────────────────────

pub fn avcodec_version() -> u32 {
    unsafe { (fn_table().avcodec_version)() }
}

pub fn format_version(ver: u32) -> String {
    format!(
        "{}.{}.{}",
        (ver >> 16) & 0xFF,
        (ver >> 8) & 0xFF,
        ver & 0xFF
    )
}

// ── Codec lookup ─────────────────────────────────────────────

pub fn avcodec_find_encoder(codec_id: i32) -> Result<*const AVCodec, AvError> {
    let f = fn_table();
    let ptr = unsafe { (f.avcodec_find_encoder)(codec_id) };
    if ptr.is_null() {
        Err(AvError::CodecNotFound(format!("encoder id={}", codec_id)))
    } else {
        Ok(ptr)
    }
}

pub fn avcodec_find_decoder(codec_id: i32) -> Result<*const AVCodec, AvError> {
    let f = fn_table();
    let ptr = unsafe { (f.avcodec_find_decoder)(codec_id) };
    if ptr.is_null() {
        Err(AvError::CodecNotFound(format!("decoder id={}", codec_id)))
    } else {
        Ok(ptr)
    }
}

pub fn avcodec_find_encoder_by_name(name: &str) -> Result<*const AVCodec, AvError> {
    let f = fn_table();
    let cname = std::ffi::CString::new(name)
        .map_err(|_| AvError::InvalidArgs(format!("encoder name '{}' contains null byte", name)))?;
    let ptr = unsafe { (f.avcodec_find_encoder_by_name)(cname.as_ptr()) };
    if ptr.is_null() {
        Err(AvError::CodecNotFound(format!("encoder name='{}'", name)))
    } else {
        Ok(ptr)
    }
}

pub fn avcodec_find_decoder_by_name(name: &str) -> Result<*const AVCodec, AvError> {
    let f = fn_table();
    let cname = std::ffi::CString::new(name)
        .map_err(|_| AvError::InvalidArgs(format!("decoder name '{}' contains null byte", name)))?;
    let ptr = unsafe { (f.avcodec_find_decoder_by_name)(cname.as_ptr()) };
    if ptr.is_null() {
        Err(AvError::CodecNotFound(format!("decoder name='{}'", name)))
    } else {
        Ok(ptr)
    }
}

pub fn find_h264_encoder() -> Result<*const AVCodec, AvError> {
    avcodec_find_encoder(AV_CODEC_ID_H264)
}

pub fn find_h265_encoder() -> Result<*const AVCodec, AvError> {
    avcodec_find_encoder(AV_CODEC_ID_H265)
}

pub fn find_h264_decoder() -> Result<*const AVCodec, AvError> {
    avcodec_find_decoder(AV_CODEC_ID_H264)
}

// ── Codec context (opaque) ───────────────────────────────────

pub fn avcodec_alloc_context3(codec: *const AVCodec) -> Result<*mut AVCodecContext, AvError> {
    if codec.is_null() {
        return Err(AvError::NullPtr("codec"));
    }
    let f = fn_table();
    let ctx = unsafe { (f.avcodec_alloc_context3)(codec) };
    if ctx.is_null() {
        Err(AvError::NullPtr("avcodec_alloc_context3"))
    } else {
        Ok(ctx)
    }
}

pub fn avcodec_open2(ctx: *mut AVCodecContext, codec: *const AVCodec) -> Result<(), AvError> {
    let f = fn_table();
    let ret = unsafe { (f.avcodec_open2)(ctx, codec, ptr::null_mut()) };
    av_result(ret)
}

/// 带 options 字典打开 codec（官方推荐路径，用于 `pix_fmt`/`width`/`height` 这类
/// 无 AVOption 条目的字段 —— av_opt_set 会 OPTION_NOT_FOUND，经字典在 open2 时注入）。
///
/// `opts` 由调用方构造（经 [`av_dict_set`]）；FFmpeg open2 后会消费并清空匹配项。
/// 调用方仍需在 open2 后 [`av_dict_free`]。
pub fn avcodec_open2_with_opts(
    ctx: *mut AVCodecContext,
    codec: *const AVCodec,
    opts: *mut *mut super::types::AVDictionary,
) -> Result<(), AvError> {
    let f = fn_table();
    let ret = unsafe { (f.avcodec_open2)(ctx, codec, opts as *mut *mut c_void) };
    av_result(ret)
}

/// `av_dict_set` — 插入键值对（flags=0 覆盖既有值）。符号缺失返回 LoadFailed。
pub fn av_dict_set(
    pm: *mut *mut super::types::AVDictionary,
    key: &str,
    value: &str,
) -> Result<(), AvError> {
    let ckey = std::ffi::CString::new(key)
        .map_err(|_| AvError::InvalidArgs(format!("dict key '{key}' contains null")))?;
    let cval = std::ffi::CString::new(value)
        .map_err(|_| AvError::InvalidArgs(format!("dict value '{value}' contains null")))?;
    let f = fn_table();
    let set = f
        .av_dict_set
        .ok_or_else(|| AvError::LoadFailed("av_dict_set not resolved".into()))?;
    av_result(unsafe { set(pm, ckey.as_ptr(), cval.as_ptr(), 0) })
}

/// `av_dict_free` — 释放字典。null 安全；符号缺失静默返回（Drop 路径）。
pub fn av_dict_free(pm: &mut *mut super::types::AVDictionary) {
    if pm.is_null() {
        return;
    }
    let Some(init) = super::dlls::init_get() else {
        return;
    };
    let Ok((_, table)) = init else {
        return;
    };
    if let Some(free) = table.av_dict_free {
        unsafe { free(pm as *mut *mut super::types::AVDictionary) };
        *pm = ptr::null_mut();
    }
}

pub fn avcodec_close(ctx: *mut AVCodecContext) -> Result<(), AvError> {
    let f = fn_table();
    if let Some(close_fn) = f.avcodec_close {
        av_result(unsafe { close_fn(ctx) })
    } else {
        Ok(()) // avcodec_free_context will handle cleanup
    }
}

pub fn avcodec_free_context(ctx: &mut *mut AVCodecContext) {
    let f = fn_table();
    unsafe { (f.avcodec_free_context)(ctx as *mut *mut AVCodecContext) };
}

// ── Safe context configuration via av_opt ────────────────────

/// Set an integer option on an AVCodecContext (or any av object).
pub fn av_opt_set_int(obj: *mut c_void, name: &str, val: i64) -> Result<(), AvError> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| AvError::InvalidArgs(format!("option name '{}' contains null byte", name)))?;
    let f = fn_table();
    // AV_OPT_SEARCH_CHILDREN = 0x0001
    let ret = unsafe { (f.av_opt_set_int)(obj, cname.as_ptr(), val, 0x0001) };
    av_result(ret)
}

/// Read back an integer option (e.g. `thread_type` 校验）。
pub fn av_opt_get_int(obj: *mut c_void, name: &str, out_val: &mut i64) -> Result<(), AvError> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| AvError::InvalidArgs(format!("option name '{}' contains null byte", name)))?;
    let f = fn_table();
    // AV_OPT_SEARCH_CHILDREN = 0x0001（与 av_opt_set_int 对称）。
    let ret = unsafe { (f.av_opt_get_int)(obj, cname.as_ptr(), 0x0001, out_val) };
    av_result(ret)
}

/// Set an integer option searching the object itself (AV_OPT_SEARCH flag = 0).
///
/// 用于 AVCodecContext 的**顶层字段**（`pix_fmt` / `width` / `height` / `g` /
/// `profile`-int / `max_b_frames` ...）：这些选项挂在 `obj` 本身，不在子选项
/// 里，必须用 flag=0（搜 obj 自身）而非 [`av_opt_set_int`] 的 `SEARCH_CHILDREN`
/// （0x0001 只搜子项，会漏掉这些字段）。
pub fn av_opt_set_int_self(obj: *mut c_void, name: &str, val: i64) -> Result<(), AvError> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| AvError::InvalidArgs(format!("option name '{}' contains null byte", name)))?;
    let f = fn_table();
    let ret = unsafe { (f.av_opt_set_int)(obj, cname.as_ptr(), val, 0) };
    av_result(ret)
}

/// Set a pixel-format option via the dedicated `av_opt_set_pixel_fmt`.
///
/// 普通的 [`av_opt_set_int`] 对 `AV_OPT_TYPE_PIXEL_FMT`（如 `pix_fmt`）会返回
/// `AVERROR_OPTION_NOT_FOUND`，必须用本专用 setter。符号缺失时返回 `LoadFailed`。
pub fn av_opt_set_pixel_fmt(obj: *mut c_void, name: &str, val: i32) -> Result<(), AvError> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| AvError::InvalidArgs(format!("option name '{}' contains null byte", name)))?;
    let f = fn_table();
    let set = f
        .av_opt_set_pixel_fmt
        .ok_or_else(|| AvError::LoadFailed("av_opt_set_pixel_fmt not resolved".into()))?;
    // 用 flag=0（搜 obj 自身）。
    let ret = unsafe { set(obj, cname.as_ptr(), val, 0) };
    av_result(ret)
}

// ── AVCodecContext 字段直写（opaque 约束放宽） ────────────────
//
// FFmpeg 8.1.2 共享构建（GyanD/BtbN full shared）的 AVCodecContext AVOption 表
// 缺少 width/height/pix_fmt/time_base 条目（pix_fmt 完全不在表里）—— av_opt_set*
// 返回 AVERROR_OPTION_NOT_FOUND，AVDictionary 也不被 open2 消费。libx264/h264_qsv
// 在 open2 时强制要求这些字段已设，故需结构体字段直写。
//
// 偏移取自 FFmpeg 8.1 `libavcodec/avcodec.h` 的 `offsetof(AVCodecContext, x)`，
// 经运行时实测确认（libx264 open2 成功出码流）。**升级 FFmpeg 主版本时必须重核**。

/// AVCodecContext 字段偏移（FFmpeg 8.1.2 x86-64，经实测确认）。
pub mod avctx_offset {
    /// `uint8_t *extradata`。
    pub const EXTRADATA: usize = 72;
    /// `int extradata_size`。
    pub const EXTRADATA_SIZE: usize = 80;
    /// `AVRational time_base`（num:i32 @ +0, den:i32 @ +4）。
    pub const TIME_BASE: usize = 84;
    /// `AVRational framerate`（num:i32 @ +0, den:i32 @ +4）。
    pub const FRAMERATE: usize = 100;
    /// `int width`。
    pub const WIDTH: usize = 112;
    /// `int height`。
    pub const HEIGHT: usize = 116;
    /// `int coded_width`。
    pub const CODED_WIDTH: usize = 120;
    /// `int coded_height`。
    pub const CODED_HEIGHT: usize = 124;
    /// `enum AVPixelFormat pix_fmt`。
    pub const PIX_FMT: usize = 136;
    /// `int gop_size`（经 av_opt_set_int_self 也能设；保留供直写路径）。
    pub const GOP_SIZE: usize = 332;
    /// `AVBufferRef *hw_frames_ctx`（hw 解码器回读/零拷贝路径用）。
    pub const HW_FRAMES_CTX: usize = 552;
    /// `AVBufferRef *hw_device_ctx`（hw 解码器 open2 前绑定 hw device）。
    pub const HW_DEVICE_CTX: usize = 560;
}

/// 写 `AVCodecContext` 的 int 字段（按 [`avctx_offset`] 偏移）。
///
/// # Safety
/// `off` 必须是 [`avctx_offset`] 中经验证的偏移；写错偏移会破坏 ctx（segfault）。
pub unsafe fn avctx_set_int(ctx: *mut super::types::AVCodecContext, off: usize, val: i32) {
    (ctx as *mut u8).add(off).cast::<i32>().write(val);
}

/// 写 `AVCodecContext.time_base`（AVRational = num/den）。
pub fn avctx_set_time_base(ctx: *mut super::types::AVCodecContext, num: i32, den: i32) {
    unsafe {
        avctx_set_int(ctx, avctx_offset::TIME_BASE, num);
        avctx_set_int(ctx, avctx_offset::TIME_BASE + 4, den);
    }
}

/// 写 `AVCodecContext.framerate`（AVRational = num/den，如 30/1）。
/// QSV open2 要求该字段已设，否则报 "Current frame rate is unsupported"。
pub fn avctx_set_framerate(ctx: *mut super::types::AVCodecContext, num: i32, den: i32) {
    unsafe {
        avctx_set_int(ctx, avctx_offset::FRAMERATE, num);
        avctx_set_int(ctx, avctx_offset::FRAMERATE + 4, den);
    }
}

/// 读 `AVCodecContext` 的 int 字段（调试/校验用）。
pub unsafe fn avctx_get_int(ctx: *const super::types::AVCodecContext, off: usize) -> i32 {
    (ctx as *const u8).add(off).cast::<i32>().read()
}

/// 写 `AVCodecContext` 的指针字段（按 [`avctx_offset`] 偏移）。
///
/// 用于 `extradata` / `hw_device_ctx` / `hw_frames_ctx` 这类 FFmpeg 8.x
/// 共享构建中无对应 AVOption 条目的字段（同 width/pix_fmt 的直写路径）。
///
/// # Safety
/// `off` 必须是 [`avctx_offset`] 中经验证的指针字段偏移；写错会破坏 ctx。
pub unsafe fn avctx_set_ptr(ctx: *mut super::types::AVCodecContext, off: usize, val: *mut c_void) {
    (ctx as *mut u8).add(off).cast::<*mut c_void>().write(val);
}

/// 读 `AVCodecContext` 的指针字段（调试/校验用）。
pub unsafe fn avctx_get_ptr(ctx: *const super::types::AVCodecContext, off: usize) -> *mut c_void {
    (ctx as *const u8).add(off).cast::<*mut c_void>().read()
}

/// 设置 `AVCodecContext.extradata`（SPS/PPS/VPS，解码端重配用）。
///
/// FFmpeg 8.x 共享构建无 `extradata` 的 AVOption 条目，走字段直写
/// （[`avctx_offset::EXTRADATA`]）。内存用 `av_mallocz` 分配——所有权归
/// AVCodecContext，`avcodec_free_context` 时经 `av_freep` 释放。
/// 旧的 extradata 先释放再替换（幂等）。
pub fn set_extradata(ctx: *mut AVCodecContext, data: &[u8]) -> Result<(), AvError> {
    if ctx.is_null() {
        return Err(AvError::NullPtr("ctx"));
    }
    if data.is_empty() {
        return Err(AvError::InvalidArgs("extradata is empty".into()));
    }
    let f = fn_table();
    unsafe {
        // 1. 释放旧 extradata（若存在）。
        let old = (ctx as *mut u8).add(avctx_offset::EXTRADATA) as *mut *mut c_void;
        if !old.read().is_null() {
            (f.av_freep)(old);
        }
        // 2. av_mallocz 分配 + 拷贝（对齐到 FFmpeg 要求的 32 字节扩展）。
        let buf = (f.av_mallocz)(data.len() + 32) as *mut u8;
        if buf.is_null() {
            return Err(AvError::NullPtr("av_mallocz"));
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
        old.write(buf as *mut c_void);
        // 3. 写 extradata_size（data.len()，不含扩展填充）。
        (ctx as *mut u8)
            .add(avctx_offset::EXTRADATA_SIZE)
            .cast::<i32>()
            .write(data.len() as i32);
    }
    Ok(())
}

/// Set a string option.
pub fn av_opt_set(obj: *mut c_void, name: &str, val: &str) -> Result<(), AvError> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| AvError::InvalidArgs(format!("option name '{}' contains null byte", name)))?;
    let cval = std::ffi::CString::new(val)
        .map_err(|_| AvError::InvalidArgs(format!("option value '{}' contains null byte", val)))?;
    let f = fn_table();
    let ret = unsafe { (f.av_opt_set)(obj, cname.as_ptr(), cval.as_ptr(), 0x0001) };
    av_result(ret)
}

/// Convenience: set pixel format by name (e.g. "yuv420p", "nv12").
pub fn av_opt_set_pix_fmt(ctx: *mut AVCodecContext, pix_fmt_name: &str) -> Result<(), AvError> {
    av_opt_set(ctx as *mut c_void, "pix_fmt", pix_fmt_name)
}

/// Convenience: set codec‑specific parameters as a string of key=value pairs.
pub fn av_opt_set_kv(ctx: *mut AVCodecContext, key: &str, value: &str) -> Result<(), AvError> {
    av_opt_set(ctx as *mut c_void, key, value)
}

// ── Encoding API ─────────────────────────────────────────────

pub fn avcodec_send_frame(ctx: *mut AVCodecContext, frame: *const AVFrame) -> Result<(), AvError> {
    let f = fn_table();
    av_result(unsafe { (f.avcodec_send_frame)(ctx, frame) })
}

pub fn avcodec_receive_packet(ctx: *mut AVCodecContext, pkt: *mut AVPacket) -> Result<(), AvError> {
    let f = fn_table();
    av_result(unsafe { (f.avcodec_receive_packet)(ctx, pkt) })
}

pub fn avcodec_send_eoi(ctx: *mut AVCodecContext) -> Result<(), AvError> {
    avcodec_send_frame(ctx, ptr::null())
}

// ── Decoding API ─────────────────────────────────────────────

pub fn avcodec_send_packet(ctx: *mut AVCodecContext, pkt: *const AVPacket) -> Result<(), AvError> {
    let f = fn_table();
    av_result(unsafe { (f.avcodec_send_packet)(ctx, pkt) })
}

pub fn avcodec_send_null_packet(ctx: *mut AVCodecContext) -> Result<(), AvError> {
    avcodec_send_packet(ctx, ptr::null())
}

pub fn avcodec_receive_frame(ctx: *mut AVCodecContext, frame: *mut AVFrame) -> Result<(), AvError> {
    let f = fn_table();
    av_result(unsafe { (f.avcodec_receive_frame)(ctx, frame) })
}

pub fn avcodec_flush_buffers(ctx: *mut AVCodecContext) {
    unsafe { (fn_table().avcodec_flush_buffers)(ctx) };
}

// ── Hardware-context API (P1C 硬件编码层) ────────────────────
//
// 这些包装对应 FFmpeg libavutil/hwcontext.h。HW 符号在纯 SW 构建中可能
// 缺失（FnTable 里是 `Option<...>`）；缺失时返回 `LoadFailed`，调用方
// （FfmpegHwEncoder::try_open）据此回退软编。所有 HW 结构对 Rust 不透明，
// 仅返回裸指针，由调用方配对 free。

/// 创建 HW device context（返回引用计数的 `AVBufferRef`）。
///
/// `device` 为可选的平台特定设备句柄名（通常 `NULL` 让 FFmpeg 自建）。
pub fn av_hwdevice_ctx_create(
    device_type: i32,
    device: Option<&std::ffi::CStr>,
) -> Result<*mut AVBufferRef, AvError> {
    let f = fn_table();
    let create = f
        .av_hwdevice_ctx_create
        .ok_or_else(|| AvError::LoadFailed("av_hwdevice_ctx_create not resolved".into()))?;
    let dev_ptr = device.map(|c| c.as_ptr()).unwrap_or(std::ptr::null());
    let mut ctx: *mut AVBufferRef = std::ptr::null_mut();
    let ret = unsafe {
        create(
            &mut ctx as *mut *mut AVBufferRef,
            device_type,
            dev_ptr,
            std::ptr::null_mut(),
            0,
        )
    };
    av_result(ret)?;
    if ctx.is_null() {
        return Err(AvError::NullPtr("av_hwdevice_ctx_create"));
    }
    Ok(ctx)
}

/// 按名字查 HW device 类型（如 `"d3d11va"` / `"qsv"` / `"vaapi"`）。
/// 未知名返回 `AV_HWDEVICE_TYPE_NONE`（0）。
pub fn av_hwdevice_find_type_by_name(name: &str) -> Result<i32, AvError> {
    let f = fn_table();
    let lookup = f
        .av_hwdevice_find_type_by_name
        .ok_or_else(|| AvError::LoadFailed("av_hwdevice_find_type_by_name not resolved".into()))?;
    let cname = std::ffi::CString::new(name).map_err(|_| {
        AvError::InvalidArgs(format!("hwdevice name '{}' contains null byte", name))
    })?;
    Ok(unsafe { lookup(cname.as_ptr()) })
}

/// 从 HW device context 分配 HW frames context（引用计数）。
pub fn av_hwframe_ctx_alloc(device_ctx: *mut AVBufferRef) -> Result<*mut AVBufferRef, AvError> {
    let f = fn_table();
    let alloc = f
        .av_hwframe_ctx_alloc
        .ok_or_else(|| AvError::LoadFailed("av_hwframe_ctx_alloc not resolved".into()))?;
    if device_ctx.is_null() {
        return Err(AvError::NullPtr("device_ctx"));
    }
    let r = unsafe { alloc(device_ctx) };
    if r.is_null() {
        Err(AvError::NullPtr("av_hwframe_ctx_alloc"))
    } else {
        Ok(r)
    }
}

/// 初始化 HW frames context（在调用方设置完 `AVHWFramesContext` 字段后）。
///
/// 注意：`AVHWFramesContext` 字段需要写入，但本仓库该结构保持不透明——
/// 真实 HW 编码场景须由 FfmpegHwEncoder 经 `av_opt_set` 间接配置；当前
/// stub 实现不调用本函数（HW 路径惰性）。函数提供以备 HW DLL 就绪后启用。
pub fn av_hwframe_ctx_init(frames_ctx: *mut AVBufferRef) -> Result<(), AvError> {
    let f = fn_table();
    let init = f
        .av_hwframe_ctx_init
        .ok_or_else(|| AvError::LoadFailed("av_hwframe_ctx_init not resolved".into()))?;
    if frames_ctx.is_null() {
        return Err(AvError::NullPtr("frames_ctx"));
    }
    av_result(unsafe { init(frames_ctx) })
}

/// 从 HW frames pool 分配一个 hwframe（绑定到 `frame->hw_frames_ctx`）。
pub fn av_hwframe_get_buffer(
    hwframes_ctx: *mut AVBufferRef,
    frame: *mut AVFrame,
) -> Result<(), AvError> {
    let f = fn_table();
    let get = f
        .av_hwframe_get_buffer
        .ok_or_else(|| AvError::LoadFailed("av_hwframe_get_buffer not resolved".into()))?;
    if hwframes_ctx.is_null() || frame.is_null() {
        return Err(AvError::NullPtr("hwframe_get_buffer args"));
    }
    av_result(unsafe { get(hwframes_ctx, frame, 0) })
}

/// 释放一个 `AVBufferRef` 引用（hw device / hw frames ctx 用）。
/// 传入后会把指针置 null，幂等。
pub fn av_buffer_unref(refp: &mut *mut AVBufferRef) {
    if refp.is_null() {
        return;
    }
    // 静默容忍未加载场景（Drop 路径不应 panic）。
    let Some(init) = super::dlls::init_get() else {
        return;
    };
    let Ok((_, table)) = init else { return };
    if let Some(unref) = table.av_buffer_unref {
        unsafe { unref(refp as *mut *mut AVBufferRef) };
        *refp = std::ptr::null_mut();
    }
}

/// `av_buffer_ref` — 引用计数 +1，返回同一缓冲的新引用。
///
/// 用于把 hw device 的引用同时交给 AVCodecContext（open2 前绑定
/// `ctx->hw_device_ctx`）与调用方结构：双方各持一个 ref，各自 unref。
/// 符号缺失（纯 SW 构建）返回 `LoadFailed`。
pub fn av_buffer_ref(buf: *mut AVBufferRef) -> Result<*mut AVBufferRef, AvError> {
    let f = fn_table();
    let r = f
        .av_buffer_ref
        .ok_or_else(|| AvError::LoadFailed("av_buffer_ref not resolved".into()))?;
    if buf.is_null() {
        return Err(AvError::NullPtr("buf"));
    }
    let new = unsafe { r(buf) };
    if new.is_null() {
        Err(AvError::NullPtr("av_buffer_ref"))
    } else {
        Ok(new)
    }
}

/// `av_hwframe_transfer_data(dst, src, flags)` — 把 hwframe（GPU 内存）回读
/// 为 swframe（CPU 内存，布局由 hw 解码器输出像素格式决定，通常 NV12）。
///
/// `dst` 为可复用的目标帧（调用方先 `av_frame_unref`，成功后布局被填充）；
/// `src` 为接收自 `avcodec_receive_frame` 的 hwframe。返回后 `src` 可
/// `av_frame_unref` 归还 hwframe 池。符号缺失返回 `LoadFailed`（hw 路径回退）。
pub fn av_hwframe_transfer_data(
    dst: *mut AVFrame,
    src: *const AVFrame,
    flags: std::ffi::c_int,
) -> Result<(), AvError> {
    let f = fn_table();
    let transfer = f
        .av_hwframe_transfer_data
        .ok_or_else(|| AvError::LoadFailed("av_hwframe_transfer_data not resolved".into()))?;
    if dst.is_null() || src.is_null() {
        return Err(AvError::NullPtr("av_hwframe_transfer_data args"));
    }
    av_result(unsafe { transfer(dst, src, flags) })
}

/// 给 AVFrame 附加 side data（ROI = `AV_FRAME_DATA_REGIONS_OF_INTEREST`）。
/// 返回 side data 指针；调用方按 side_type 的布局写入 `data` 字段。
pub fn av_frame_new_side_data(
    frame: *mut AVFrame,
    side_type: i32,
    size: usize,
) -> Result<*mut AVFrameSideData, AvError> {
    let f = fn_table();
    let new_sd = f
        .av_frame_new_side_data
        .ok_or_else(|| AvError::LoadFailed("av_frame_new_side_data not resolved".into()))?;
    if frame.is_null() {
        return Err(AvError::NullPtr("frame"));
    }
    let sd = unsafe { new_sd(frame, side_type, size) };
    if sd.is_null() {
        Err(AvError::NullPtr("av_frame_new_side_data"))
    } else {
        Ok(sd)
    }
}

/// 查询 AVFrame 是否已附某类 side data。
pub fn av_frame_get_side_data(
    frame: *const AVFrame,
    side_type: i32,
) -> Option<*const AVFrameSideData> {
    let init = super::dlls::init_get()?;
    let (_, table) = init.as_ref().ok()?;
    let get_sd = table.av_frame_get_side_data?;
    if frame.is_null() {
        return None;
    }
    let p = unsafe { get_sd(frame, side_type) };
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}

/// 设帧 PTS（编码主循环调用）。符号缺失时返回 false，调用方可用直接字段写
/// `(*frame).pts = pts` 作回退（FFmpeg 8.x 共享构建已导出该符号）。
pub fn av_frame_set_pts(frame: *mut AVFrame, pts: i64) -> bool {
    let Some(init) = super::dlls::init_get() else {
        return false;
    };
    let Ok((_, table)) = init else {
        return false;
    };
    if let Some(set) = table.av_frame_set_pts {
        if !frame.is_null() {
            unsafe { set(frame, pts) };
            return true;
        }
    }
    false
}

// ── Audio channel-layout / frame-buffer API（P1D 音频编码用） ─────────
//
// libopus 经 avcodec 编码要求 AVFrame.ch_layout / AVCodecContext.ch_layout
// 设置为 NATIVE 布局，并经 av_frame_get_buffer 分配 planar float32 平面缓冲。
// 这些包装在 FFmpeg DLL 缺符号时返回 `LoadFailed`，音频编码器据此回退
// `Unsupported`（视频/键鼠流水线不受影响）。
//
// 注意：`AVFrame.ch_layout` 字段在 FFmpeg 8.x 的结构里位于 `flags` 之后、
// `duration` 之前，本仓库 AVFrame 映射未覆盖该区域。为避免触碰不稳定 ABI，
// 音频路径经本节 `av_frame_set_ch_layout` 用 FFmpeg 官方 API 设置该字段，
// 而非直接写字段。

/// `av_channel_layout_copy(dst, src)` —— 把 NATIVE 布局按值复制到 `dst`。
///
/// 用于把 `AVChannelLayout::stereo()` 写到 `AVCodecContext.ch_layout` 或
/// `AVFrame.ch_layout`。`dst`/`src` 指向 `AVChannelLayout`（24 字节）。
pub fn av_channel_layout_copy(
    dst: *mut AVChannelLayout,
    src: *const AVChannelLayout,
) -> Result<(), AvError> {
    let f = fn_table();
    let copy = f
        .av_channel_layout_copy
        .ok_or_else(|| AvError::LoadFailed("av_channel_layout_copy not resolved".into()))?;
    if dst.is_null() || src.is_null() {
        return Err(AvError::NullPtr("av_channel_layout_copy args"));
    }
    av_result(unsafe { copy(dst, src) })
}

/// `av_channel_layout_default(ch_layout, nb_channels)` —— 填一个默认 NATIVE 布局。
pub fn av_channel_layout_default(
    ch_layout: *mut AVChannelLayout,
    nb_channels: i32,
) -> Result<(), AvError> {
    let f = fn_table();
    let default_fn = f
        .av_channel_layout_default
        .ok_or_else(|| AvError::LoadFailed("av_channel_layout_default not resolved".into()))?;
    if ch_layout.is_null() {
        return Err(AvError::NullPtr("ch_layout"));
    }
    unsafe { default_fn(ch_layout, nb_channels) };
    // av_channel_layout_default 返回 void；视作成功。
    Ok(())
}

/// `av_channel_layout_uninit(ch_layout)` —— 释放 CUSTOM 布局的 `u.map`。
/// NATIVE 布局无资源，幂等安全（Drop 路径用）。
pub fn av_channel_layout_uninit(ch_layout: *mut AVChannelLayout) {
    let Some(init) = super::dlls::init_get() else {
        return;
    };
    let Ok((_, table)) = init else {
        return;
    };
    if let Some(uninit) = table.av_channel_layout_uninit {
        if !ch_layout.is_null() {
            unsafe { uninit(ch_layout) };
        }
    }
}

/// `av_frame_get_buffer(frame, align)` —— 按 frame->format/nb_samples/ch_layout
/// 分配音/视频平面缓冲。音频 planar float32 挂到 data[0..nb_channels]。
///
/// 调用前须设置 `frame->format`、`frame->nb_samples`、`frame->ch_layout`
/// （经 [`av_frame_set_ch_layout`]）。返回的缓冲由 `av_frame_free` 释放。
pub fn av_frame_get_buffer(frame: *mut AVFrame, align: i32) -> Result<(), AvError> {
    let f = fn_table();
    let get = f
        .av_frame_get_buffer
        .ok_or_else(|| AvError::LoadFailed("av_frame_get_buffer not resolved".into()))?;
    if frame.is_null() {
        return Err(AvError::NullPtr("frame"));
    }
    av_result(unsafe { get(frame, align) })
}

/// 给 AVFrame 设置 ch_layout（音频编码必需）。
///
/// FFmpeg 8.x 用 `AVChannelLayout` 取代了旧的 `channel_layout`/`channels`，且
/// libopus 编码器在 `avcodec_send_frame` 时会读 `frame->ch_layout`。本仓库的
/// `AVFrame` 映射未覆盖该字段（ABI 不稳定，视频路径只读 `flags` 之前的字段），
/// 故这里按 FFmpeg 8.x（Win64）的字段偏移（见 [`AVFRAME_CH_LAYOUT_OFFSET`]）
/// 算出 `&frame->ch_layout`，再经官方 `av_channel_layout_copy` 写入 NATIVE 立体声
/// 布局（无资源所有权，可安全按值覆盖）。
///
/// 字段偏移仅对 FFmpeg ≥ 7 成立；符号缺失（旧/精简构建）返回 `LoadFailed`，
/// 调用方据此回退 `Unsupported`。
pub fn av_frame_set_ch_layout(
    frame: *mut AVFrame,
    stereo: &AVChannelLayout,
) -> Result<(), AvError> {
    if frame.is_null() {
        return Err(AvError::NullPtr("frame"));
    }
    let ch_layout_ptr =
        unsafe { (frame as *mut u8).add(AVFRAME_CH_LAYOUT_OFFSET) } as *mut AVChannelLayout;
    av_channel_layout_copy(ch_layout_ptr, stereo as *const AVChannelLayout)
}

/// `AVFrame.ch_layout` 字段在 FFmpeg 8.x（Win64 ABI）结构中的字节偏移。
///
/// 按 `libavutil/frame.h`（release/8.1）字段顺序在 64-bit ABI 上累加 + 对齐得到。
/// 关键里程碑（字节偏移）：data@0、linesize@64、extended_data@96、width@104、
/// height@108、nb_samples@112、format@116、pict_type@120、sample_aspect_ratio@124、
/// pts@136、pkt_dts@144、time_base@152、quality@160、opaque@168、sample_rate@180、
/// buf[8]@184、extended_buf@248、nb_extended_buf@256、side_data@264、nb_side_data@272、
/// flags@276、best_effort_timestamp@304、metadata@312、hw_frames_ctx@328、
/// opaque_ref@336、crop_top@344、crop_bottom@352、crop_left@360、crop_right@368、
/// private_ref@376（8B，结束于 384）。
///
/// `ch_layout`（AVChannelLayout，24B/align 8）紧跟 private_ref 之后 → **偏移 384**。
/// 该偏移对 FFmpeg 7/8（新声道布局 API）成立；本仓库仅在音频路径使用。
const AVFRAME_CH_LAYOUT_OFFSET: usize = 384;

// ── Frame / Packet lifecycle ─────────────────────────────────

pub fn av_frame_alloc() -> Result<*mut AVFrame, AvError> {
    let f = fn_table();
    let frame = unsafe { (f.av_frame_alloc)() };
    if frame.is_null() {
        Err(AvError::NullPtr("av_frame_alloc"))
    } else {
        Ok(frame)
    }
}

pub fn av_frame_free(frame: &mut *mut AVFrame) {
    if frame.is_null() {
        return;
    }
    unsafe { (fn_table().av_frame_free)(frame as *mut *mut AVFrame) };
}

/// 重置帧到初始状态（释放引用的缓冲/side-data），供解码/编码循环重用同一帧。
/// 幂等；null 指针安全。
pub fn av_frame_unref(frame: *mut AVFrame) {
    if frame.is_null() {
        return;
    }
    unsafe { (fn_table().av_frame_unref)(frame) };
}

pub fn av_packet_alloc() -> Result<*mut AVPacket, AvError> {
    let f = fn_table();
    let pkt = unsafe { (f.av_packet_alloc)() };
    if pkt.is_null() {
        Err(AvError::NullPtr("av_packet_alloc"))
    } else {
        Ok(pkt)
    }
}

pub fn av_packet_unref(pkt: *mut AVPacket) {
    if pkt.is_null() {
        return;
    }
    unsafe {
        (fn_table().av_packet_unref)(pkt);
    }
}

pub fn av_packet_free(pkt: &mut *mut AVPacket) {
    if pkt.is_null() {
        return;
    }
    unsafe { (fn_table().av_packet_free)(pkt as *mut *mut AVPacket) };
}

// ── Image utilities ──────────────────────────────────────────

pub fn av_image_get_buffer_size(
    pix_fmt: i32,
    width: i32,
    height: i32,
    align: i32,
) -> Result<i32, AvError> {
    let f = fn_table();
    let size = unsafe { (f.av_image_get_buffer_size)(pix_fmt, width, height, align) };
    if size < 0 {
        Err(AvError::Code(size))
    } else {
        Ok(size)
    }
}

pub fn av_image_fill_arrays(
    dst_data: &mut [*mut u8; 4],
    dst_linesize: &mut [i32; 4],
    ptr: *const u8,
    pix_fmt: i32,
    width: i32,
    height: i32,
    align: i32,
) -> Result<(), AvError> {
    let f = fn_table();
    let ret = unsafe {
        (f.av_image_fill_arrays)(
            dst_data.as_mut_ptr(),
            dst_linesize.as_mut_ptr(),
            ptr,
            pix_fmt,
            width,
            height,
            align,
        )
    };
    av_result(ret)
}

pub fn av_get_pix_fmt(name: &str) -> i32 {
    let cname = std::ffi::CString::new(name).unwrap_or_default();
    unsafe { (fn_table().av_get_pix_fmt)(cname.as_ptr()) }
}

pub fn av_get_pix_fmt_name(pix_fmt: i32) -> String {
    let ptr = unsafe { (fn_table().av_get_pix_fmt_name)(pix_fmt) };
    if ptr.is_null() {
        "Unknown".to_string()
    } else {
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

// ── Swscale (raw access; see `scale.rs` for the RAII wrapper) ──

pub const SWS_BILINEAR: i32 = 2;
pub const SWS_BICUBIC: i32 = 4;
pub const SWS_FAST_BILINEAR: i32 = 1;
pub const SWS_POINT: i32 = 0x10;
pub const SWS_AREA: i32 = 0x20;

pub fn sws_getContext(
    src_w: i32,
    src_h: i32,
    src_fmt: i32,
    dst_w: i32,
    dst_h: i32,
    dst_fmt: i32,
    flags: i32,
) -> Result<*mut SwsContext, AvError> {
    let f = fn_table();
    let ctx = unsafe {
        (f.sws_getContext)(
            src_w,
            src_h,
            src_fmt,
            dst_w,
            dst_h,
            dst_fmt,
            flags,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
        )
    };
    if ctx.is_null() {
        Err(AvError::NullPtr("sws_getContext"))
    } else {
        Ok(ctx)
    }
}

pub fn sws_scale(
    ctx: *mut SwsContext,
    src_slice: &[*const u8; 4],
    src_stride: &[i32; 4],
    src_slice_y: i32,
    src_slice_h: i32,
    dst: &[*mut u8; 4],
    dst_stride: &[i32; 4],
) -> Result<i32, AvError> {
    let f = fn_table();
    let ret = unsafe {
        (f.sws_scale)(
            ctx,
            src_slice.as_ptr(),
            src_stride.as_ptr(),
            src_slice_y,
            src_slice_h,
            dst.as_ptr() as *const *mut u8,
            dst_stride.as_ptr(),
        )
    };
    if ret < 0 {
        Err(AvError::Code(ret as i32))
    } else {
        Ok(ret)
    }
}

pub fn sws_freeContext(ctx: *mut SwsContext) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        (fn_table().sws_freeContext)(ctx);
    }
}

// ════════════════════════════════════════════════════════════════
// Tests (migrated from sys.rs)
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::super::dlls::ensure_loaded;
    use super::*;

    #[test]
    fn test_load_all_dlls() {
        let result = ensure_loaded();
        match result {
            Ok(_) => {
                let ver = avcodec_version();
                assert!(ver > 0);
                eprintln!("avcodec version: {}", format_version(ver));
            }
            Err(e) => eprintln!("FFmpeg libraries not available (OK for CI): {}", e),
        }
    }

    #[test]
    fn test_find_encoder() {
        if ensure_loaded().is_err() {
            return;
        }
        let _ = find_h264_encoder();
        let _ = find_h265_encoder();
    }

    #[test]
    fn test_find_decoder() {
        if ensure_loaded().is_err() {
            return;
        }
        assert!(find_h264_decoder().is_ok());
    }

    #[test]
    fn test_frame_packet_lifecycle() {
        if ensure_loaded().is_err() {
            return;
        }
        let mut frame = av_frame_alloc().unwrap();
        av_frame_free(&mut frame);
        assert!(frame.is_null());

        let mut pkt = av_packet_alloc().unwrap();
        av_packet_free(&mut pkt);
        assert!(pkt.is_null());
    }

    #[test]
    fn test_pixel_format_lookup() {
        if ensure_loaded().is_err() {
            return;
        }
        use super::super::types::{AV_PIX_FMT_NV12, AV_PIX_FMT_YUV420P};
        assert_eq!(av_get_pix_fmt("nv12"), AV_PIX_FMT_NV12);
        assert_eq!(av_get_pix_fmt_name(AV_PIX_FMT_YUV420P), "yuv420p");
    }

    #[test]
    fn test_image_buffer_size() {
        if ensure_loaded().is_err() {
            return;
        }
        use super::super::types::AV_PIX_FMT_YUV420P;
        let size = av_image_get_buffer_size(AV_PIX_FMT_YUV420P, 1920, 1080, 1).unwrap();
        assert_eq!(size, (1920 * 1080 * 3 / 2) as i32);
    }
}
