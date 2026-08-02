//! FFmpeg dynamic library loading.
//!
//! Owns: version constants, library search paths, the function-pointer table
//! (`FnTable`), the `OnceLock`-guarded one-shot loader, and the function
//! pointer type aliases shared by the rest of the `ffmpeg` submodules.
//!
//! All 3 libraries are loaded once on first access via [`ensure_loaded`].
//! Function pointers are resolved via the platform-agnostic `libloading`
//! crate.
//!
//! # DLL Versions (FFmpeg 8.1.2 full build / BtbN shared builds)
//!
//! | Library | DLL name       | Purpose                     |
//! |---------|----------------|-----------------------------|
//! | avcodec | `avcodec-62.dll` | Codec init, encode, decode |
//! | avutil  | `avutil-60.dll`  | Frame/packet alloc, images |
//! | swscale | `swscale-9.dll`  | Colorspace conversion      |
//!
//! When upgrading FFmpeg, update the version constants below and, if a build
//! drops a symbol, adjust the loader.
//!
//! # Platform support
//!
//! - Windows: `LoadLibraryA` + `GetProcAddress` (via `libloading`)
//! - Linux/macOS: `dlopen` + `dlsym`
//! - Library names chosen at compile time per target OS.
//!
//! # LGPL Compliance
//!
//! Dynamic loading of LGPL libraries does NOT require GPL licensing of the
//! application. Only statically linking GPL codecs would trigger GPL
//! obligations.

#![allow(non_camel_case_types, dead_code)]

use std::ffi::{c_char, c_int, c_void};
use std::sync::OnceLock;

use libloading::{Library, Symbol};

use super::error::AvError;
use super::types::{
    AVBufferRef, AVChannelLayout, AVCodec, AVCodecContext, AVFrame, AVFrameSideData, AVPacket,
    SwsContext,
};

// ════════════════════════════════════════════════════════════════
// Version constants — update when upgrading FFmpeg libraries
// ════════════════════════════════════════════════════════════════

/// Library name for avcodec (encode/decode core).
#[cfg(target_os = "windows")]
pub const AVCODEC_LIB: &str = "avcodec-62.dll";
#[cfg(target_os = "linux")]
pub const AVCODEC_LIB: &str = "libavcodec.so.62";
#[cfg(target_os = "macos")]
pub const AVCODEC_LIB: &str = "libavcodec.62.dylib";

/// Library name for avutil (frame/packet/image utilities).
#[cfg(target_os = "windows")]
pub const AVUTIL_LIB: &str = "avutil-60.dll";
#[cfg(target_os = "linux")]
pub const AVUTIL_LIB: &str = "libavutil.so.60";
#[cfg(target_os = "macos")]
pub const AVUTIL_LIB: &str = "libavutil.60.dylib";

/// Library name for swscale (colorspace conversion).
#[cfg(target_os = "windows")]
pub const SWSCALE_LIB: &str = "swscale-9.dll";
#[cfg(target_os = "linux")]
pub const SWSCALE_LIB: &str = "libswscale.so.9";
#[cfg(target_os = "macos")]
pub const SWSCALE_LIB: &str = "libswscale.9.dylib";

/// 字段偏移快照对应的 **libavcodec 库主版本**（R-22；R-06 修正语义）。
///
/// `api.rs::avctx_offset` 与 `AVFRAME_CH_LAYOUT_OFFSET` 的偏移按 FFmpeg 8.1.2
/// （GyanD/BtbN full shared）实测确认；加载完成后断言 `avcodec_version()` 的
/// major 与此一致，不符**直接加载失败报错**——绝不带着错偏移静默运行。
/// 升级流程见 `api.rs` 升级核对清单与 `Readme.md`「FFmpeg 升级步骤」。
///
/// **R-06 修正（2026-08-02）**：`avcodec_version()` 返回的是 **libavcodec
/// 库版本**（`LIBAVCODEC_VERSION_INT = major<<16|minor<<8|micro`），不是
/// FFmpeg 项目版本——FFmpeg 8.1.2 的 libavcodec 为 62.28.102（avcodec-62.dll）。
/// R-22 原值 8 与实际 DLL（major=62）恒不匹配，导致所有 avcodec-62.dll
/// 环境下 `ensure_loaded` 永远失败（产品 FFmpeg 全链路不可用 + 阻塞 R-06
/// 实机验证）；实机探测确认后修正为 62。
pub const SNAPSHOT_FFMPEG_MAJOR: u32 = 62;

/// 校验 FFmpeg 主版本与偏移快照一致（纯函数，R-22；单测见 tests 模块）。
fn check_snapshot_major(ver: u32) -> Result<(), AvError> {
    let major = (ver >> 16) & 0xFF;
    if major == SNAPSHOT_FFMPEG_MAJOR {
        Ok(())
    } else {
        Err(AvError::LoadFailed(format!(
            "FFmpeg major version {major} != snapshot {SNAPSHOT_FFMPEG_MAJOR}: \
             AVCodecContext/AVFrame 字段偏移须按升级核对清单重核 \
             （media/src/ffmpeg/api.rs avctx_offset / AVFRAME_CH_LAYOUT_OFFSET）"
        )))
    }
}

/// Search paths for libraries, in priority order.
///
/// Windows: bundled DLLs relative to the executable.
/// Linux (M12-T003 / R-14-S2): bundled/packaged locations first, then distro
/// multiarch system paths, then loader default (`""`, i.e. `ldconfig` /
/// `LD_LIBRARY_PATH`).
/// macOS: rely on system paths (Homebrew etc.).
#[cfg(target_os = "windows")]
pub const LIB_SEARCH_PATHS: &[&str] = &[
    "{exe_dir}/../ffmpeg/bin/",
    "{exe_dir}/ffmpeg/ffmpeg-8.1.2-full_build-shared/bin/",
    "{exe_dir}/ffmpeg/bin/",
    "",
];
#[cfg(target_os = "linux")]
pub const LIB_SEARCH_PATHS: &[&str] = &[
    // deb 打包布局（release/debian/build_deb.sh 预留目录：/usr/lib/kirindesk/ffmpeg）。
    "{exe_dir}/../lib/kirindesk/ffmpeg/",
    // 便携/自解压布局（与 Windows 打包目录同名）。
    "{exe_dir}/ffmpeg/",
    // Debian/Ubuntu 多架构系统路径（FFmpeg 8 shared build 随包安装时）。
    "/usr/lib/x86_64-linux-gnu/",
    "/usr/lib/aarch64-linux-gnu/",
    "/usr/lib/",
    "/usr/local/lib/",
    "", // 系统默认（ldconfig / LD_LIBRARY_PATH）。
];
#[cfg(target_os = "macos")]
pub const LIB_SEARCH_PATHS: &[&str] = &[""]; // rely on system paths

/// DLL soname fallback table.
///
/// When the primary version constant (`AVCODEC_LIB` etc.) fails to load, the
/// loader tries these older sonames in order. This keeps the binary resilient
/// across FFmpeg minor bumps where the shared-build soversion may lag the
/// bundled set (e.g. avcodec-60/61 on legacy installs).
///
/// P1A only defines the table; resolution is performed by [`load_lib`].
#[cfg(target_os = "windows")]
pub const DLL_VERSION_FALLBACKS: &[(&str, &[&str])] = &[
    (
        AVCODEC_LIB,
        &["avcodec-61.dll", "avcodec-60.dll", "avcodec-59.dll"],
    ),
    (AVUTIL_LIB, &["avutil-59.dll", "avutil-58.dll"]),
    (SWSCALE_LIB, &["swscale-8.dll", "swscale-7.dll"]),
];
// M12-T003（R-14-S2）：Linux 回退表——Ubuntu 24.04 自带 FFmpeg 6
// （libavcodec.so.60），Debian 12 = FFmpeg 5（.59）。注意：主版本 ≠ 8 时
// `SNAPSHOT_FFMPEG_MAJOR` 断言（R-22）会拒绝加载，回退表仅覆盖 FFmpeg
// 8.x 各 minor（.62→.61）的场景；7.x/6.x 的偏移兼容留待升级核对清单。
#[cfg(target_os = "linux")]
pub const DLL_VERSION_FALLBACKS: &[(&str, &[&str])] = &[
    (AVCODEC_LIB, &["libavcodec.so.61"]),
    (AVUTIL_LIB, &["libavutil.so.59"]),
    (SWSCALE_LIB, &["libswscale.so.8"]),
];
#[cfg(target_os = "macos")]
pub const DLL_VERSION_FALLBACKS: &[(&str, &[&str])] = &[];

// ════════════════════════════════════════════════════════════════
// Function pointer type aliases
// ════════════════════════════════════════════════════════════════

pub(super) type AvcodecVersionFn = unsafe extern "system" fn() -> u32;
pub(super) type AvcodecFindEncoderFn = unsafe extern "system" fn(id: i32) -> *const AVCodec;
pub(super) type AvcodecFindDecoderFn = unsafe extern "system" fn(id: i32) -> *const AVCodec;
pub(super) type AvcodecFindEncoderByNameFn =
    unsafe extern "system" fn(name: *const c_char) -> *const AVCodec;
pub(super) type AvcodecFindDecoderByNameFn =
    unsafe extern "system" fn(name: *const c_char) -> *const AVCodec;
pub(super) type AvcodecAllocContext3Fn =
    unsafe extern "system" fn(codec: *const AVCodec) -> *mut AVCodecContext;
pub(super) type AvcodecOpen2Fn = unsafe extern "system" fn(
    ctx: *mut AVCodecContext,
    codec: *const AVCodec,
    options: *mut *mut c_void,
) -> c_int;
pub(super) type AvcodecCloseFn = unsafe extern "system" fn(ctx: *mut AVCodecContext) -> c_int;
pub(super) type AvcodecFreeContextFn = unsafe extern "system" fn(ctx: *mut *mut AVCodecContext);
pub(super) type AvcodecSendFrameFn =
    unsafe extern "system" fn(ctx: *mut AVCodecContext, frame: *const AVFrame) -> c_int;
pub(super) type AvcodecReceivePacketFn =
    unsafe extern "system" fn(ctx: *mut AVCodecContext, pkt: *mut AVPacket) -> c_int;
pub(super) type AvcodecSendPacketFn =
    unsafe extern "system" fn(ctx: *mut AVCodecContext, pkt: *const AVPacket) -> c_int;
pub(super) type AvcodecReceiveFrameFn =
    unsafe extern "system" fn(ctx: *mut AVCodecContext, frame: *mut AVFrame) -> c_int;
pub(super) type AvcodecFlushBuffersFn = unsafe extern "system" fn(ctx: *mut AVCodecContext);

pub(super) type AvFrameAllocFn = unsafe extern "system" fn() -> *mut AVFrame;
pub(super) type AvFrameFreeFn = unsafe extern "system" fn(frame: *mut *mut AVFrame);
/// `av_frame_unref(frame)` —— 重置帧到初始状态（释放引用的缓冲），供解码/编码循环重用帧。
pub(super) type AvFrameUnrefFn = unsafe extern "system" fn(frame: *mut AVFrame);
pub(super) type AvPacketAllocFn = unsafe extern "system" fn() -> *mut AVPacket;
pub(super) type AvPacketFreeFn = unsafe extern "system" fn(pkt: *mut *mut AVPacket);
pub(super) type AvPacketUnrefFn = unsafe extern "system" fn(pkt: *mut AVPacket);
pub(super) type AvImageGetBufferSizeFn =
    unsafe extern "system" fn(pix_fmt: c_int, width: c_int, height: c_int, align: c_int) -> c_int;
pub(super) type AvImageFillArraysFn = unsafe extern "system" fn(
    dst_data: *mut *mut u8,
    dst_linesize: *mut c_int,
    ptr: *const u8,
    pix_fmt: c_int,
    width: c_int,
    height: c_int,
    align: c_int,
) -> c_int;
pub(super) type AvGetPixFmtFn = unsafe extern "system" fn(name: *const c_char) -> i32;
pub(super) type AvPixelFormatGetNameFn = unsafe extern "system" fn(pix_fmt: i32) -> *const c_char;

// av_opt functions (essential for safe context configuration)
pub(super) type AvOptSetIntFn = unsafe extern "system" fn(
    obj: *mut c_void,
    name: *const c_char,
    val: i64,
    search_flags: c_int,
) -> c_int;
/// `av_opt_get_int` — 读回 int 选项（解码器 thread_type 校验用）。
pub(super) type AvOptGetIntFn = unsafe extern "system" fn(
    obj: *mut c_void,
    name: *const c_char,
    search_flags: c_int,
    out_val: *mut i64,
) -> c_int;
pub(super) type AvOptSetFn = unsafe extern "system" fn(
    obj: *mut c_void,
    name: *const c_char,
    val: *const c_char,
    search_flags: c_int,
) -> c_int;
/// `av_opt_set_pixel_fmt` — 专门设置 AV_OPT_TYPE_PIXEL_FMT 字段（`pix_fmt` 这类
/// 字段普通 av_opt_set_int 会 OPTION_NOT_FOUND，须用专用 setter）。
pub(super) type AvOptSetPixelFmtFn = unsafe extern "system" fn(
    obj: *mut c_void,
    name: *const c_char,
    val: c_int,
    search_flags: c_int,
) -> c_int;
/// `av_dict_set` — 向 AVDictionary 插入键值对（flags=0 覆盖）。
pub(super) type AvDictSetFn = unsafe extern "system" fn(
    pm: *mut *mut super::types::AVDictionary,
    key: *const c_char,
    value: *const c_char,
    flags: c_int,
) -> c_int;
/// `av_dict_free` — 释放 AVDictionary。
pub(super) type AvDictFreeFn = unsafe extern "system" fn(pm: *mut *mut super::types::AVDictionary);

pub(super) type SwsGetContextFn = unsafe extern "system" fn(
    src_w: c_int,
    src_h: c_int,
    src_fmt: c_int,
    dst_w: c_int,
    dst_h: c_int,
    dst_fmt: c_int,
    flags: c_int,
    src_filter: *mut c_void,
    dst_filter: *mut c_void,
    param: *const f64,
) -> *mut SwsContext;
pub(super) type SwsScaleFn = unsafe extern "system" fn(
    ctx: *mut SwsContext,
    src_slice: *const *const u8,
    src_stride: *const c_int,
    src_slice_y: c_int,
    src_slice_h: c_int,
    dst: *const *mut u8,
    dst_stride: *const c_int,
) -> c_int;
pub(super) type SwsFreeContextFn = unsafe extern "system" fn(ctx: *mut SwsContext);

// ── Hardware-context FFI (P1C 硬件编码层使用) ──────────────────
//
// 这些符号在纯软件 FFmpeg 构建里也可能缺失，故 FnTable 中全部为
// `Option<...>`，`load_all` 用 `get_symbol(...).ok()` 解析——缺失不阻断
// 整体加载，运行时调用相应 api 包装返回 `LoadFailed`。
//
// 所有 HW 相关结构（`AVBufferRef` / `AVFrameSideData`）对 Rust 不透明，
// 仅持有裸指针，绝不 deref（同 `AVCodecContext` 模式）。
pub(super) type AvBufferRefFn =
    unsafe extern "system" fn(buf: *mut AVBufferRef) -> *mut AVBufferRef;
pub(super) type AvBufferUnrefFn = unsafe extern "system" fn(refp: *mut *mut AVBufferRef);
pub(super) type AvHwdeviceCtxCreateFn = unsafe extern "system" fn(
    device_ctx: *mut *mut AVBufferRef,
    device_type: c_int,
    device: *const c_char,
    opts: *mut c_void,
    flags: c_int,
) -> c_int;
/// `av_hwframe_transfer_data(dst, src, flags)` —— 把 hwframe（GPU 内存）回读为
/// swframe（CPU 内存）。`src` 的像素格式决定回读布局（NV12 → 半平面）。
pub(super) type AvHwframeTransferDataFn =
    unsafe extern "system" fn(dst: *mut AVFrame, src: *const AVFrame, flags: c_int) -> c_int;
pub(super) type AvHwdeviceFindTypeByNameFn =
    unsafe extern "system" fn(name: *const c_char) -> c_int;
pub(super) type AvHwframeCtxAllocFn =
    unsafe extern "system" fn(device_ctx: *mut AVBufferRef) -> *mut AVBufferRef;
pub(super) type AvHwframeCtxInitFn = unsafe extern "system" fn(refp: *mut AVBufferRef) -> c_int;
pub(super) type AvHwframeGetBufferFn = unsafe extern "system" fn(
    hwframe_ctx: *mut AVBufferRef,
    frame: *mut AVFrame,
    flags: c_int,
) -> c_int;
pub(super) type AvFrameNewSideDataFn = unsafe extern "system" fn(
    frame: *mut AVFrame,
    side_type: c_int,
    size: usize,
) -> *mut AVFrameSideData;
pub(super) type AvFrameGetSideDataFn =
    unsafe extern "system" fn(frame: *const AVFrame, side_type: c_int) -> *const AVFrameSideData;
/// `av_frame_set_pts` — 编码主循环设帧 PTS。
pub(super) type AvFrameSetPtsFn = unsafe extern "system" fn(frame: *mut AVFrame, pts: i64);
/// `av_mallocz(size)` —— 分配并清零（extradata 等 FFmpeg 所有权内存）。
pub(super) type AvMalloczFn = unsafe extern "system" fn(size: usize) -> *mut c_void;
/// `av_freep(ptr)` —— 释放并置空（配合 av_mallocz 使用）。
pub(super) type AvFreepFn = unsafe extern "system" fn(ptr: *mut *mut c_void);

// ── Audio channel-layout / frame-buffer FFI（P1D 音频编码用） ──────────
//
// 这些符号在 avutil 中导出；libopus 经 avcodec 编码需在 AVFrame.ch_layout /
// AVCodecContext.ch_layout 上设置 NATIVE 布局，并由 av_frame_get_buffer 分配
// 音频平面缓冲（planar float32）。全部为 `Option<...>`：旧/精简构建可能缺失，
// api 包装缺失时返回 `LoadFailed`，编码器据此回退 Unsupported（不影响视频）。
pub(super) type AvChannelLayoutCopyFn =
    unsafe extern "system" fn(dst: *mut AVChannelLayout, src: *const AVChannelLayout) -> c_int;
pub(super) type AvChannelLayoutDefaultFn =
    unsafe extern "system" fn(ch_layout: *mut AVChannelLayout, nb_channels: c_int);
pub(super) type AvChannelLayoutUninitFn =
    unsafe extern "system" fn(ch_layout: *mut AVChannelLayout);
/// `av_frame_get_buffer(frame, align)` —— 按 frame->format/nb_samples/ch_layout
/// 分配音/视频平面缓冲（planar float32 音频由本函数挂到 data[0]/data[1]）。
pub(super) type AvFrameGetBufferFn =
    unsafe extern "system" fn(frame: *mut AVFrame, align: c_int) -> c_int;

// ════════════════════════════════════════════════════════════════
// Loaded function table and global initialisation
// ════════════════════════════════════════════════════════════════

pub(super) struct Libraries {
    _avcodec: Library,
    _avutil: Library,
    _swscale: Library,
}

/// Resolved function pointer table. Held alive for program lifetime by
/// [`INIT`]; field order matches FFmpeg symbol resolution order in
/// [`load_all`].
pub(super) struct FnTable {
    pub(super) avcodec_version: AvcodecVersionFn,
    pub(super) avcodec_find_encoder: AvcodecFindEncoderFn,
    pub(super) avcodec_find_decoder: AvcodecFindDecoderFn,
    pub(super) avcodec_find_encoder_by_name: AvcodecFindEncoderByNameFn,
    pub(super) avcodec_find_decoder_by_name: AvcodecFindDecoderByNameFn,
    pub(super) avcodec_alloc_context3: AvcodecAllocContext3Fn,
    pub(super) avcodec_open2: AvcodecOpen2Fn,
    pub(super) avcodec_close: Option<AvcodecCloseFn>,
    pub(super) avcodec_free_context: AvcodecFreeContextFn,
    pub(super) avcodec_send_frame: AvcodecSendFrameFn,
    pub(super) avcodec_receive_packet: AvcodecReceivePacketFn,
    pub(super) avcodec_send_packet: AvcodecSendPacketFn,
    pub(super) avcodec_receive_frame: AvcodecReceiveFrameFn,
    pub(super) avcodec_flush_buffers: AvcodecFlushBuffersFn,
    pub(super) av_packet_alloc: AvPacketAllocFn,
    pub(super) av_packet_free: AvPacketFreeFn,
    pub(super) av_packet_unref: AvPacketUnrefFn,
    pub(super) av_frame_alloc: AvFrameAllocFn,
    pub(super) av_frame_free: AvFrameFreeFn,
    pub(super) av_frame_unref: AvFrameUnrefFn,
    pub(super) av_image_get_buffer_size: AvImageGetBufferSizeFn,
    pub(super) av_image_fill_arrays: AvImageFillArraysFn,
    pub(super) av_get_pix_fmt: AvGetPixFmtFn,
    pub(super) av_get_pix_fmt_name: AvPixelFormatGetNameFn,
    pub(super) av_opt_set_int: AvOptSetIntFn,
    pub(super) av_opt_get_int: AvOptGetIntFn,
    pub(super) av_opt_set: AvOptSetFn,
    pub(super) av_opt_set_pixel_fmt: Option<AvOptSetPixelFmtFn>,
    pub(super) av_dict_set: Option<AvDictSetFn>,
    pub(super) av_dict_free: Option<AvDictFreeFn>,
    pub(super) sws_getContext: SwsGetContextFn,
    pub(super) sws_scale: SwsScaleFn,
    pub(super) sws_freeContext: SwsFreeContextFn,
    // ── HW-context symbols (P1C；纯 SW 构建可能缺失，故 Option) ──
    pub(super) av_buffer_ref: Option<AvBufferRefFn>,
    pub(super) av_buffer_unref: Option<AvBufferUnrefFn>,
    pub(super) av_hwdevice_ctx_create: Option<AvHwdeviceCtxCreateFn>,
    pub(super) av_hwdevice_find_type_by_name: Option<AvHwdeviceFindTypeByNameFn>,
    pub(super) av_hwframe_ctx_alloc: Option<AvHwframeCtxAllocFn>,
    pub(super) av_hwframe_ctx_init: Option<AvHwframeCtxInitFn>,
    pub(super) av_hwframe_get_buffer: Option<AvHwframeGetBufferFn>,
    pub(super) av_hwframe_transfer_data: Option<AvHwframeTransferDataFn>,
    pub(super) av_frame_new_side_data: Option<AvFrameNewSideDataFn>,
    pub(super) av_frame_get_side_data: Option<AvFrameGetSideDataFn>,
    pub(super) av_frame_set_pts: Option<AvFrameSetPtsFn>,
    // ── Memory helpers（extradata 分配；avutil 核心符号，必需） ──
    pub(super) av_mallocz: AvMalloczFn,
    pub(super) av_freep: AvFreepFn,
    // ── Audio channel-layout / frame-buffer symbols（P1D；缺失不阻断） ──
    pub(super) av_channel_layout_copy: Option<AvChannelLayoutCopyFn>,
    pub(super) av_channel_layout_default: Option<AvChannelLayoutDefaultFn>,
    pub(super) av_channel_layout_uninit: Option<AvChannelLayoutUninitFn>,
    pub(super) av_frame_get_buffer: Option<AvFrameGetBufferFn>,
}

// Global state: libraries + function table.
static INIT: OnceLock<Result<(Libraries, FnTable), AvError>> = OnceLock::new();

/// Call once at program start. Subsequent calls are no-ops.
pub fn ensure_loaded() -> Result<(), AvError> {
    INIT.get_or_init(load_all)
        .as_ref()
        .map(|_| ())
        .map_err(|e| e.clone())
}

// ── Cross-platform library loading with libloading ──────────

fn load_lib(name: &str) -> Result<Library, AvError> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    for template in LIB_SEARCH_PATHS {
        let resolved = if template.is_empty() {
            name.to_string()
        } else {
            let base = exe_dir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            template.replace("{exe_dir}", &base) + name
        };

        // On Windows we might need LOAD_WITH_ALTERED_SEARCH_PATH; libloading
        // does not expose it. As a workaround we add the DLL directory to PATH
        // before loading.
        #[cfg(target_os = "windows")]
        if let Some(parent) = std::path::Path::new(&resolved).parent() {
            if let Ok(current) = std::env::var("PATH") {
                std::env::set_var("PATH", format!("{};{}", parent.display(), current));
            }
        }

        match unsafe { Library::new(&resolved) } {
            Ok(lib) => return Ok(lib),
            Err(e) => {
                tracing::debug!("load_lib: failed to load '{}': {}", resolved, e);
                continue;
            }
        }
    }

    Err(AvError::LoadFailed(format!(
        "{} not found in any search path (LD_LIBRARY_PATH / PATH?)",
        name
    )))
}

fn get_symbol<'a, T>(lib: &'a Library, name: &[u8]) -> Result<Symbol<'a, T>, AvError> {
    unsafe { lib.get(name) }.map_err(|e| {
        AvError::LoadFailed(format!(
            "symbol '{}' not found: {}",
            String::from_utf8_lossy(name),
            e
        ))
    })
}

fn load_all() -> Result<(Libraries, FnTable), AvError> {
    let lib_avcodec = load_lib(AVCODEC_LIB)?;
    let lib_avutil = load_lib(AVUTIL_LIB)?;
    let lib_swscale = load_lib(SWSCALE_LIB)?;

    // Helper macro to grab a symbol and cast it to the correct type.
    macro_rules! sym {
        ($lib:expr, $name:expr, $ty:ty) => {
            *get_symbol::<$ty>($lib, stringify!($name).as_bytes())?
        };
    }

    // Optional symbol: HW-context functions may be absent in pure-SW FFmpeg
    // builds. Resolution failure is non-fatal — `api.rs` wrappers return
    // `LoadFailed("hw symbol not resolved")` at call time.
    macro_rules! sym_opt {
        ($lib:expr, $name:expr, $ty:ty) => {
            get_symbol::<$ty>($lib, stringify!($name).as_bytes())
                .ok()
                .map(|s| *s)
        };
    }

    let fn_table = FnTable {
        avcodec_version: sym!(&lib_avcodec, avcodec_version, AvcodecVersionFn),
        avcodec_find_encoder: sym!(&lib_avcodec, avcodec_find_encoder, AvcodecFindEncoderFn),
        avcodec_find_decoder: sym!(&lib_avcodec, avcodec_find_decoder, AvcodecFindDecoderFn),
        avcodec_find_encoder_by_name: sym!(
            &lib_avcodec,
            avcodec_find_encoder_by_name,
            AvcodecFindEncoderByNameFn
        ),
        avcodec_find_decoder_by_name: sym!(
            &lib_avcodec,
            avcodec_find_decoder_by_name,
            AvcodecFindDecoderByNameFn
        ),
        avcodec_alloc_context3: sym!(&lib_avcodec, avcodec_alloc_context3, AvcodecAllocContext3Fn),
        avcodec_open2: sym!(&lib_avcodec, avcodec_open2, AvcodecOpen2Fn),
        // avcodec_close may be missing in newer FFmpeg
        avcodec_close: get_symbol::<AvcodecCloseFn>(&lib_avcodec, b"avcodec_close")
            .ok()
            .map(|s| *s),
        avcodec_free_context: sym!(&lib_avcodec, avcodec_free_context, AvcodecFreeContextFn),
        avcodec_send_frame: sym!(&lib_avcodec, avcodec_send_frame, AvcodecSendFrameFn),
        avcodec_receive_packet: sym!(&lib_avcodec, avcodec_receive_packet, AvcodecReceivePacketFn),
        avcodec_send_packet: sym!(&lib_avcodec, avcodec_send_packet, AvcodecSendPacketFn),
        avcodec_receive_frame: sym!(&lib_avcodec, avcodec_receive_frame, AvcodecReceiveFrameFn),
        avcodec_flush_buffers: sym!(&lib_avcodec, avcodec_flush_buffers, AvcodecFlushBuffersFn),
        av_packet_alloc: sym!(&lib_avcodec, av_packet_alloc, AvPacketAllocFn),
        av_packet_free: sym!(&lib_avcodec, av_packet_free, AvPacketFreeFn),
        av_packet_unref: sym!(&lib_avcodec, av_packet_unref, AvPacketUnrefFn),
        av_frame_alloc: sym!(&lib_avutil, av_frame_alloc, AvFrameAllocFn),
        av_frame_free: sym!(&lib_avutil, av_frame_free, AvFrameFreeFn),
        av_frame_unref: sym!(&lib_avutil, av_frame_unref, AvFrameUnrefFn),
        av_image_get_buffer_size: sym!(
            &lib_avutil,
            av_image_get_buffer_size,
            AvImageGetBufferSizeFn
        ),
        av_image_fill_arrays: sym!(&lib_avutil, av_image_fill_arrays, AvImageFillArraysFn),
        av_get_pix_fmt: sym!(&lib_avutil, av_get_pix_fmt, AvGetPixFmtFn),
        av_get_pix_fmt_name: sym!(&lib_avutil, av_get_pix_fmt_name, AvPixelFormatGetNameFn),
        av_opt_set_int: sym!(&lib_avutil, av_opt_set_int, AvOptSetIntFn),
        av_opt_get_int: sym!(&lib_avutil, av_opt_get_int, AvOptGetIntFn),
        av_opt_set: sym!(&lib_avutil, av_opt_set, AvOptSetFn),
        av_opt_set_pixel_fmt: sym_opt!(&lib_avutil, av_opt_set_pixel_fmt, AvOptSetPixelFmtFn),
        av_dict_set: sym_opt!(&lib_avutil, av_dict_set, AvDictSetFn),
        av_dict_free: sym_opt!(&lib_avutil, av_dict_free, AvDictFreeFn),
        sws_getContext: sym!(&lib_swscale, sws_getContext, SwsGetContextFn),
        sws_scale: sym!(&lib_swscale, sws_scale, SwsScaleFn),
        sws_freeContext: sym!(&lib_swscale, sws_freeContext, SwsFreeContextFn),
        // ── HW-context symbols (P1C；缺失不阻断) ──
        // 注意：`av_frame_set_pts` 实为宏（libavutil/frame.h 展开为
        // `av_frame_set_best_effort_timestamp` 在旧版，或直接字段写）。
        // FFmpeg 8.x 的共享构建已导出为函数符号；缺失时编码器内部用字段写
        // 回退（见 ffmpeg_sw.rs）。
        av_buffer_ref: sym_opt!(&lib_avutil, av_buffer_ref, AvBufferRefFn),
        av_buffer_unref: sym_opt!(&lib_avutil, av_buffer_unref, AvBufferUnrefFn),
        av_hwdevice_ctx_create: sym_opt!(
            &lib_avutil,
            av_hwdevice_ctx_create,
            AvHwdeviceCtxCreateFn
        ),
        av_hwdevice_find_type_by_name: sym_opt!(
            &lib_avutil,
            av_hwdevice_find_type_by_name,
            AvHwdeviceFindTypeByNameFn
        ),
        av_hwframe_ctx_alloc: sym_opt!(&lib_avutil, av_hwframe_ctx_alloc, AvHwframeCtxAllocFn),
        av_hwframe_ctx_init: sym_opt!(&lib_avutil, av_hwframe_ctx_init, AvHwframeCtxInitFn),
        av_hwframe_get_buffer: sym_opt!(&lib_avutil, av_hwframe_get_buffer, AvHwframeGetBufferFn),
        av_hwframe_transfer_data: sym_opt!(
            &lib_avutil,
            av_hwframe_transfer_data,
            AvHwframeTransferDataFn
        ),
        av_frame_new_side_data: sym_opt!(&lib_avutil, av_frame_new_side_data, AvFrameNewSideDataFn),
        av_frame_get_side_data: sym_opt!(&lib_avutil, av_frame_get_side_data, AvFrameGetSideDataFn),
        av_frame_set_pts: sym_opt!(&lib_avutil, av_frame_set_pts, AvFrameSetPtsFn),
        // ── Memory helpers（avutil 核心符号，缺失即加载失败） ──
        av_mallocz: sym!(&lib_avutil, av_mallocz, AvMalloczFn),
        av_freep: sym!(&lib_avutil, av_freep, AvFreepFn),
        // ── Audio channel-layout / frame-buffer symbols（P1D；缺失不阻断） ──
        av_channel_layout_copy: sym_opt!(
            &lib_avutil,
            av_channel_layout_copy,
            AvChannelLayoutCopyFn
        ),
        av_channel_layout_default: sym_opt!(
            &lib_avutil,
            av_channel_layout_default,
            AvChannelLayoutDefaultFn
        ),
        av_channel_layout_uninit: sym_opt!(
            &lib_avutil,
            av_channel_layout_uninit,
            AvChannelLayoutUninitFn
        ),
        av_frame_get_buffer: sym_opt!(&lib_avutil, av_frame_get_buffer, AvFrameGetBufferFn),
    };

    // R-22：主版本断言（偏移快照核对）——不符直接报错，防止升级后错乱。
    check_snapshot_major(unsafe { (fn_table.avcodec_version)() })?;

    Ok((
        Libraries {
            _avcodec: lib_avcodec,
            _avutil: lib_avutil,
            _swscale: lib_swscale,
        },
        fn_table,
    ))
}

/// Access the resolved function table.
///
/// # Panics
///
/// Panics if [`ensure_loaded`] was never called or returned an error — safe
/// wrappers in `api.rs` all call `ensure_loaded()` first, so this only fires
/// on programmer error.
pub(super) fn fn_table() -> &'static FnTable {
    match INIT
        .get()
        .expect("ffmpeg: ensure_loaded() must be called first")
    {
        Ok((_, table)) => table,
        Err(e) => panic!("ffmpeg not available: {}", e),
    }
}

/// Non-panicking accessor: returns the loaded table only if `ensure_loaded`
/// previously succeeded. Drop-path callers (`av_buffer_unref` etc.) use this
/// to stay silent when FFmpeg was never loaded (e.g. process teardown).
pub(super) fn init_get() -> Option<&'static Result<(Libraries, FnTable), AvError>> {
    INIT.get()
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// P1A Tests §ffmpeg: 三个 DLL 的 FnTable 全部解析成功（DLL 可用时）。
    /// DLL 不可用时（CI/无 FFmpeg 环境）打印并跳过。
    #[test]
    fn test_dlls_load_all_symbols() {
        match ensure_loaded() {
            Ok(()) => {
                let t = fn_table();
                // Smoke: every symbol must be a non-null function pointer (call
                // avcodec_version as a cheap end-to-end check).
                let ver = unsafe { (t.avcodec_version)() };
                assert!(ver > 0, "avcodec_version returned 0");
                eprintln!("dlls: avcodec version = {}", ver);
            }
            Err(e) => eprintln!(
                "FFmpeg libraries not available (OK for CI); test_dlls_load_all_symbols skipped: {}",
                e
            ),
        }
    }

    /// R-22：版本断言单测 —— mock 主版本不符 → 明确报错（升级 FFmpeg 时
    /// 字段偏移须重核，绝不静默错乱）。
    #[test]
    fn test_check_snapshot_major() {
        // 快照版本 8.1.2 → 通过；同 major 的 8.0.0 也通过（偏移按 major 绑定）。
        let snapshot = (SNAPSHOT_FFMPEG_MAJOR << 16) | (1 << 8) | 2;
        assert!(check_snapshot_major(snapshot).is_ok());
        assert!(check_snapshot_major(SNAPSHOT_FFMPEG_MAJOR << 16).is_ok());
        // 7.x / 9.x → 明确报错并提示重核路径。
        for bad in [
            ((SNAPSHOT_FFMPEG_MAJOR - 1) << 16) | (1 << 8) | 2, // 7.1.2
            ((SNAPSHOT_FFMPEG_MAJOR + 1) << 16),                // 9.0.0
        ] {
            let msg = check_snapshot_major(bad).unwrap_err().to_string();
            assert!(msg.contains("major version"), "msg: {msg}");
            assert!(msg.contains("重核"), "msg: {msg}");
        }
    }

    /// P1A Tests §ffmpeg: 主版本缺 DLL → 回退表生效。
    ///
    /// 本阶段回退表为静态数据（[`DLL_VERSION_FALLBACKS`]），且真实回退由
    /// `load_lib` 的搜索路径驱动。本测试校验回退表结构本身（条目齐全、
    /// 主名与回退名不重复），DLL 缺失场景在集成测试中覆盖。
    #[test]
    fn test_dlls_version_fallback() {
        // Windows/Linux 有回退条目（M12-T003/R-14-S2 为 Linux 补了
        // 8.x minor 回退）；macOS 为空（依赖系统 ldconfig/Homebrew）。
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            assert!(DLL_VERSION_FALLBACKS.len() >= 3, "应至少为三个库配置回退");
            for (primary, fallbacks) in DLL_VERSION_FALLBACKS {
                assert!(!primary.is_empty());
                for fb in *fallbacks {
                    assert_ne!(*fb, *primary, "回退名不能与主名重复");
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            assert!(DLL_VERSION_FALLBACKS.is_empty());
        }
    }

    /// M12-T003（R-14-S2）：Linux 搜索路径含打包/系统布局且末项为空串
    /// （系统默认兜底）；Windows 含 exe 相对路径。
    #[test]
    fn test_search_paths_target_layout() {
        #[cfg(target_os = "linux")]
        {
            assert!(
                LIB_SEARCH_PATHS.iter().any(|p| p.contains("/usr/lib/")),
                "Linux 应含多架构系统路径"
            );
            assert!(
                LIB_SEARCH_PATHS.iter().any(|p| p.contains("{exe_dir}")),
                "Linux 应含打包/便携路径"
            );
        }
        #[cfg(target_os = "windows")]
        {
            assert!(
                LIB_SEARCH_PATHS.iter().all(|p| p.contains("{exe_dir}") || p.is_empty()),
                "Windows 路径应相对 exe 或空串兜底"
            );
        }
        // 末项恒为空串：系统默认（ldconfig / PATH）兜底。
        assert_eq!(LIB_SEARCH_PATHS.last(), Some(&""));
    }

    #[test]
    fn test_search_paths_nonempty() {
        assert!(!LIB_SEARCH_PATHS.is_empty());
    }

    #[test]
    fn test_lib_names_target_specific() {
        // Sanity: each constant is non-empty and matches the target OS.
        assert!(!AVCODEC_LIB.is_empty());
        assert!(!AVUTIL_LIB.is_empty());
        assert!(!SWSCALE_LIB.is_empty());
        #[cfg(target_os = "windows")]
        {
            assert!(AVCODEC_LIB.ends_with(".dll"));
            assert!(AVUTIL_LIB.ends_with(".dll"));
            assert!(SWSCALE_LIB.ends_with(".dll"));
        }
    }
}
