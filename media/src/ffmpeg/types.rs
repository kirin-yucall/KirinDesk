//! FFmpeg C-compatible type definitions.
//!
//! Contains: codec id / pixel format / picture type constants, `AV*` struct
//! partial mappings (only fields we read), and function-pointer type aliases
//! used by [`crate::ffmpeg::dlls`].
//!
//! All structs are `#[repr(C)]` partial mappings — only the fields we access.
//! `AVCodecContext` stays **opaque** (`_data: [u8; 0]`); all configuration
//! flows through `av_opt_set_int` / `av_opt_set` (see `api.rs`).

#![allow(non_camel_case_types, dead_code)]

use std::ffi::{c_int, c_void};

// `c_char` is used only inside `#[cfg(test)]` below; import it there to avoid
// an unused-import warning in non-test builds.
// `AvError` is referenced by `api.rs`, not this module.

// ════════════════════════════════════════════════════════════════
// AVCodecID
// ════════════════════════════════════════════════════════════════

pub const AV_CODEC_ID_NONE: i32 = 0;
pub const AV_CODEC_ID_H264: i32 = 27;
pub const AV_CODEC_ID_H265: i32 = 173;
pub const AV_CODEC_ID_VP8: i32 = 139;
pub const AV_CODEC_ID_VP9: i32 = 167;
pub const AV_CODEC_ID_AV1: i32 = 213;

/// `AV_CODEC_ID_OPUS` — libavcodec opus 编解码器（P1D 音频编码用）。
///
/// 数值取自 FFmpeg `libavcodec/codec_id.h`（Opus 在 `AV_CODEC_ID_AUDIO` 段）。
/// Opus = `AV_CODEC_ID_FIRST_AUDIO`(0x10000) + 12 = 86076。
pub const AV_CODEC_ID_OPUS: i32 = 86076;

// ── AVSampleFormat（P1D 音频编码用；libavutil/samplefmt.h） ──────────
//
// 枚举顺序：NONE=-1, U8=0, S16=1, S32=2, FLT=3, DBL=4, U8P=5, S16P=6,
// S32P=7, FLTP=8, DBLP=9, S64=10, S64P=11。后缀 P = planar（逐声道平面）。
//
// libopus 经 FFmpeg avcodec 要求 planar float32（FLTP）；WASAPI 环回原生产
// packed float32（FLT，interleaved）——编码前需 deinterleave。

/// packed float32（interleaved）—— WASAPI 环回原生格式。
pub const AV_SAMPLE_FMT_FLT: i32 = 3;
/// planar float32（逐声道）—— libopus 编码器要求的输入格式。
pub const AV_SAMPLE_FMT_FLTP: i32 = 8;
/// packed signed 16-bit PCM —— 16-bit 兜底格式。
pub const AV_SAMPLE_FMT_S16: i32 = 1;
/// planar signed 16-bit PCM。
pub const AV_SAMPLE_FMT_S16P: i32 = 6;

// ════════════════════════════════════════════════════════════════
// AVPixelFormat (common subset)
// ════════════════════════════════════════════════════════════════

pub const AV_PIX_FMT_NONE: i32 = -1;
pub const AV_PIX_FMT_YUV420P: i32 = 0;
pub const AV_PIX_FMT_NV12: i32 = 23;
pub const AV_PIX_FMT_RGB0: i32 = 130;
pub const AV_PIX_FMT_RGBA: i32 = 26;
pub const AV_PIX_FMT_BGRA: i32 = 28;
pub const AV_PIX_FMT_BGR0: i32 = 133;
pub const AV_PIX_FMT_YUVJ420P: i32 = 12;

// ── Hardware pixel formats (P1C 硬件编码层使用；本阶段先定义常量) ──
//
// 数值取自 FFmpeg libavutil/pixfmt.h（FFmpeg 7.x/8.x 稳定值）。
// 仅作 av_hwframe / hw_frames_ctx 契约，编码器侧用 av_opt_set_pix_fmt
// 而非直接比较这些数值，因此即便主版本微调也不会影响安全包装路径。
pub const AV_PIX_FMT_D3D11: i32 = 1000085;
pub const AV_PIX_FMT_D3D11VA_VLD: i32 = 83;
pub const AV_PIX_FMT_DXVA2_VLD: i32 = 80;
pub const AV_PIX_FMT_VAAPI: i32 = 8192; // AV_PIX_FMT_VAAPI 偏移起点
pub const AV_PIX_FMT_VIDEOTOOLBOX: i32 = 8193;
pub const AV_PIX_FMT_QSV: i32 = 8194;
pub const AV_PIX_FMT_CUDA: i32 = 8195;

// ════════════════════════════════════════════════════════════════
// AVPictureType
// ════════════════════════════════════════════════════════════════

pub const AV_PICTURE_TYPE_NONE: i32 = 0;
pub const AV_PICTURE_TYPE_I: i32 = 1;
pub const AV_PICTURE_TYPE_P: i32 = 2;
pub const AV_PICTURE_TYPE_B: i32 = 3;

// ════════════════════════════════════════════════════════════════
// AVFrame side-data types (P1C ROI side data 用)
// ════════════════════════════════════════════════════════════════

/// `AV_FRAME_DATA_REGIONS_OF_INTEREST` — libavutil frame.h。
/// 用于大动分支把 DirtyTileMap 转 ROI side data 喂给硬件编码器（P1C）。
pub const AV_FRAME_DATA_REGIONS_OF_INTEREST: i32 = 12;

// ════════════════════════════════════════════════════════════════
// Struct definitions (partial, repr(C))
// ════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AVRational {
    pub num: c_int,
    pub den: c_int,
}

// ════════════════════════════════════════════════════════════════
// AVChannelLayout / AVChannelOrder（P1D 音频编码用）
// ════════════════════════════════════════════════════════════════
//
// 数值与布局取自 FFmpeg 8.x `libavutil/channel_layout.h`。
// `AVFrame.ch_layout` 与 `AVCodecContext.ch_layout` 均为此类型。
//
// # 安全
//
// 这是**值类型**：对 `AV_CHANNEL_ORDER_NATIVE`/`UNSPEC` 布局，`u.mask`
// 为纯位掩码、`opaque` 为 NULL，整结构可按值拷贝、可直接覆盖写入，无资源
// 所有权。**切勿**对 `AV_CHANNEL_ORDER_CUSTOM` 布局（`u.map` 指向分配内存）
// 按值拷贝后 double-free —— 本仓库音频路径只用 NATIVE 立体声。

/// `AVChannelOrder` 枚举值（libavutil/channel_layout.h）。
pub const AV_CHANNEL_ORDER_UNSPEC: i32 = 0;
pub const AV_CHANNEL_ORDER_NATIVE: i32 = 1;
pub const AV_CHANNEL_ORDER_CUSTOM: i32 = 2;
pub const AV_CHANNEL_ORDER_AMBISONIC: i32 = 3;

/// 声道位掩码位（AVChannel 枚举；libavutil/channel_layout.h）。
pub const AV_CHAN_FRONT_LEFT: i32 = 0;
pub const AV_CHAN_FRONT_RIGHT: i32 = 1;
pub const AV_CHAN_FRONT_CENTER: i32 = 2;

/// `AV_CH_LAYOUT_STEREO = AV_CH_FRONT_LEFT | AV_CH_FRONT_RIGHT`（位掩码）。
pub const AV_CH_LAYOUT_STEREO: u64 = (1 << AV_CHAN_FRONT_LEFT) | (1 << AV_CHAN_FRONT_RIGHT);
/// `AV_CH_LAYOUT_MONO = AV_CH_FRONT_CENTER`（位掩码）。
pub const AV_CH_LAYOUT_MONO: u64 = 1 << AV_CHAN_FRONT_CENTER;

/// FFmpeg 8.x `AVChannelLayout`（libavutil/channel_layout.h）。
///
/// 仅用于按值构造一个 NATIVE 立体声布局（`order=NATIVE`、`nb_channels=2`、
/// `u.mask=AV_CH_LAYOUT_STEREO`、`opaque=NULL`）后覆盖写入到
/// `AVFrame.ch_layout` / `AVCodecContext.ch_layout`。
///
/// 布局（64-bit ABI）：`order`(enum=4) + `nb_channels`(int=4) + `u`(union 8) +
/// `opaque`(ptr=8) = 24 字节，align 8。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AVChannelLayout {
    /// `AVChannelOrder`。
    pub order: c_int,
    /// 声道数。
    pub nb_channels: c_int,
    /// 详情联合：NATIVE 布局用 `mask`（声道位掩码）。
    pub mask: u64,
    /// 私有数据指针（NATIVE 立体声布局为 NULL）。
    pub opaque: *mut c_void,
}

impl AVChannelLayout {
    /// 构造 NATIVE 立体声布局（等价 `AV_CHANNEL_LAYOUT_STEREO` 宏）。
    pub const fn stereo() -> Self {
        Self {
            order: AV_CHANNEL_ORDER_NATIVE,
            nb_channels: 2,
            mask: AV_CH_LAYOUT_STEREO,
            opaque: std::ptr::null_mut(),
        }
    }

    /// 构造 NATIVE 单声道布局（等价 `AV_CHANNEL_LAYOUT_MONO` 宏）。
    pub const fn mono() -> Self {
        Self {
            order: AV_CHANNEL_ORDER_NATIVE,
            nb_channels: 1,
            mask: AV_CH_LAYOUT_MONO,
            opaque: std::ptr::null_mut(),
        }
    }

    /// 是否为无所有权（NATIVE/UNSPEC）布局，可安全按值覆盖写入。
    pub fn is_value_owned(&self) -> bool {
        matches!(
            self.order,
            AV_CHANNEL_ORDER_NATIVE | AV_CHANNEL_ORDER_UNSPEC
        )
    }
}

// `AVChannelLayout` 不拥有资源（NATIVE 立体声布局 opaque=NULL），跨线程传递安全。
unsafe impl Send for AVChannelLayout {}
unsafe impl Sync for AVChannelLayout {}

#[repr(C)]
#[derive(Debug)]
pub struct AVFrame {
    pub data: [*mut u8; 8],
    pub linesize: [c_int; 8],
    pub extended_data: *mut *mut u8,
    pub width: c_int,
    pub height: c_int,
    pub nb_samples: c_int,
    pub format: c_int,
    pub key_frame: c_int,
    pub pict_type: c_int,
    pub sample_aspect_ratio: AVRational,
    pub pts: i64,
    pub pkt_dts: i64,
    pub coded_picture_number: c_int,
    pub display_picture_number: c_int,
    pub quality: c_int,
    pub interlaced_frame: c_int,
    pub top_field_first: c_int,
    pub repeat_pict: c_int,
    pub color_primaries: c_int,
    pub color_trc: c_int,
    pub colorspace: c_int,
    pub color_range: c_int,
    pub chroma_location: c_int,
    pub flags: c_int,
    _padding: [u8; 64],
}

#[repr(C)]
#[derive(Debug)]
pub struct AVPacket {
    pub buf: *mut c_void,
    pub pts: i64,
    pub dts: i64,
    pub data: *mut u8,
    pub size: c_int,
    pub stream_index: c_int,
    pub flags: c_int,
    pub duration: i64,
    pub pos: i64,
    _padding: [u8; 8],
}

#[repr(C)]
pub struct AVCodec {
    _data: [u8; 0],
    _marker: std::marker::PhantomData<(*mut u8, std::marker::PhantomPinned)>,
}

// AVCodecContext：字段经 av_opt_set 配置；但 width/height/pix_fmt/time_base 在
// FFmpeg 8.1.2 共享构建（GyanD full shared）的 AVOption 表里**缺失**（pix_fmt
// 完全不在表里），只能结构体字段直写（见 `api::AVCtxField` 偏移常量，取自
// FFmpeg 8.1 `libavcodec/avcodec.h` offsetof）。这些偏移随 FFmpeg 主版本变化，
// 升级 FFmpeg 时必须重新核对。
#[repr(C)]
pub struct AVCodecContext {
    _data: [u8; 0],
    _marker: std::marker::PhantomData<(*mut u8, std::marker::PhantomPinned)>,
}

#[repr(C)]
pub struct SwsContext {
    _data: [u8; 0],
    _marker: std::marker::PhantomData<(*mut u8, std::marker::PhantomPinned)>,
}

// ── Opaque HW-context types (P1C 硬件编码层使用) ──────────────
//
// `AVBufferRef` 与 `AVFrameSideData` 都是 FFmpeg 内部结构，本仓库仅持有
// 不透明指针（同 `AVCodecContext` 的处理方式）：分配/释放/字段写入全部走
// `api.rs` 的 safe 包装，绝不直接 deref。这避免了 GyanD 8.1.2 共享构建
// AVCodecContext 布局不兼容的同类 segfault 风险。

/// `AVBufferRef` — FFmpeg 引用计数缓冲（hw device / hw frames ctx 都用它承载）。
#[repr(C)]
pub struct AVBufferRef {
    _data: [u8; 0],
    _marker: std::marker::PhantomData<(*mut u8, std::marker::PhantomPinned)>,
}

/// `AVFrameSideData` — AVFrame 旁挂数据（ROI = AV_FRAME_DATA_REGIONS_OF_INTEREST）。
///
/// 部分映射：仅暴露 `data` / `size`（写 ROI 数组用），其余字段保持不透明。
/// FFmpeg libavutil/frame.h 8.x 64 位布局：`{ AVBufferRef *buf (off 0);
/// uint8_t *data (off 8); int size (off 16); ... }`。
#[repr(C)]
pub struct AVFrameSideData {
    /// 引用计数缓冲（FFmpeg 持有，外部不释放）。
    pub buf: *mut AVBufferRef,
    /// side data 载荷（ROI 数组写这里）。
    pub data: *mut u8,
    /// `data` 字节数。
    pub size: c_int,
    _rest: [u8; 0],
}

/// `AVDictionary` — FFmpeg 键值对字典（`avcodec_open2` 的 options 参数）。
///
/// 不透明：仅经 `av_dict_set` / `av_dict_free` 操作。用于把 `pix_fmt` /
/// `width` / `height` 这类字段（无对应 AVOption 条目，av_opt_set 会
/// OPTION_NOT_FOUND）经字典在 `avcodec_open2` 时统一注入。
#[repr(C)]
pub struct AVDictionary {
    _data: [u8; 0],
    _marker: std::marker::PhantomData<(*mut u8, std::marker::PhantomPinned)>,
}

// ════════════════════════════════════════════════════════════════
// AVHWDeviceType (P1C 硬件编码层 hw device 创建用)
// ════════════════════════════════════════════════════════════════
//
// 数值取自 FFmpeg libavutil/hwcontext.h `enum AVHWDeviceType`（7.x/8.x 稳定）。
// 仅作 `av_hwdevice_ctx_create` / `av_hwdevice_find_type_by_name` 的契约，
// 实际使用经 api 包装，不直接比较裸数值。

pub const AV_HWDEVICE_TYPE_NONE: i32 = 0;
pub const AV_HWDEVICE_TYPE_VDPAU: i32 = 1;
pub const AV_HWDEVICE_TYPE_CUDA: i32 = 2;
pub const AV_HWDEVICE_TYPE_VAAPI: i32 = 3;
pub const AV_HWDEVICE_TYPE_DXVA2: i32 = 4;
pub const AV_HWDEVICE_TYPE_QSV: i32 = 5;
pub const AV_HWDEVICE_TYPE_VIDEOTOOLBOX: i32 = 6;
pub const AV_HWDEVICE_TYPE_D3D11VA: i32 = 7;
pub const AV_HWDEVICE_TYPE_DRM: i32 = 8;
pub const AV_HWDEVICE_TYPE_OPENCL: i32 = 9;
pub const AV_HWDEVICE_TYPE_MEDIACODEC: i32 = 10;

// ── AVRegionOfInterest (P1C 硬件编码 ROI side data) ──────────
//
// 定义于 libavutil/opt.h `AVRegionOfInterest`，随 side data 附加到 AVFrame。
// 本阶段仅定义结构契约，P1C 在大动分支组装 ROI 列表时使用。

/// FFmpeg ROI side data 单元（每个 dirty tile 组装的矩形）。
///
/// `self_size` 必须为 `size_of::<AVRegionOfInterest>()`，FFmpeg 据此遍历。
/// `qoffset` 为编码器量化偏置（[`AVRational`]）：负值 = 更高质量。FFmpeg
/// libavutil/opt.h 定义其为 `AVRational`，例如 `{num:-1, den:1}` = -1.0 QP。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AVRegionOfInterest {
    /// Must be `size_of::<Self>()` — FFmpeg uses it to stride the side-data blob.
    pub self_size: u32,
    /// Distance from top edge of the frame (pixels).
    pub top: c_int,
    /// Distance from top edge + height (pixels).
    pub bottom: c_int,
    /// Distance from left edge of the frame (pixels).
    pub left: c_int,
    /// Distance from left edge + width (pixels).
    pub right: c_int,
    /// Quantizer offset as `AVRational` (num/den). Negative = higher quality.
    /// T3.4：变化区 `{num:-1, den:1}` (-1.0 QP)；静止区 `{num:1, den:4}` (+0.25 QP)。
    pub qoffset: AVRational,
}

impl Default for AVRegionOfInterest {
    fn default() -> Self {
        Self {
            self_size: std::mem::size_of::<Self>() as u32,
            top: 0,
            bottom: 0,
            left: 0,
            right: 0,
            qoffset: AVRational { num: 0, den: 1 },
        }
    }
}

// Function pointer type aliases live in `dlls.rs` (they are only needed for
// the function-table loader). This module only owns data types and constants.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_avrational_layout() {
        // Sanity: AVRational stays 2 × c_int.
        assert_eq!(
            std::mem::size_of::<AVRational>(),
            2 * std::mem::size_of::<c_int>()
        );
    }

    #[test]
    fn test_roi_default_self_size() {
        let roi = AVRegionOfInterest::default();
        assert_eq!(
            roi.self_size as usize,
            std::mem::size_of::<AVRegionOfInterest>()
        );
    }

    #[test]
    fn test_pix_fmt_constants_distinct() {
        // Pixel formats we look up must not collide with NONE.
        assert_ne!(AV_PIX_FMT_NV12, AV_PIX_FMT_NONE);
        assert_ne!(AV_PIX_FMT_YUV420P, AV_PIX_FMT_NONE);
        // HW formats live in the high range, distinct from the SW ones we use.
        assert_ne!(AV_PIX_FMT_VAAPI, AV_PIX_FMT_NV12);
    }

    #[test]
    fn test_hwdevice_type_constants_distinct() {
        // P1C: hw device types we may create must be non-NONE and mutually distinct.
        assert_ne!(AV_HWDEVICE_TYPE_D3D11VA, AV_HWDEVICE_TYPE_NONE);
        assert_ne!(AV_HWDEVICE_TYPE_QSV, AV_HWDEVICE_TYPE_NONE);
        assert_ne!(AV_HWDEVICE_TYPE_VAAPI, AV_HWDEVICE_TYPE_NONE);
        assert_ne!(AV_HWDEVICE_TYPE_VIDEOTOOLBOX, AV_HWDEVICE_TYPE_NONE);
        assert_ne!(AV_HWDEVICE_TYPE_D3D11VA, AV_HWDEVICE_TYPE_QSV);
    }
}
