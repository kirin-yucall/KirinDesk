//! FFmpeg libavcodec in-process FFI bindings.
//!
//! Provides safe Rust wrappers around FFmpeg's avcodec, avutil, and swscale
//! libraries loaded dynamically at runtime. No static linking, no system headers.
//!
//! # Architecture
//!
//! ```text
//! ffmpeg/
//! ├── mod.rs     # Sub-module declarations + public re-exports
//! ├── dlls.rs    # DLL loading, OnceLock, function-pointer table (FnTable)
//! ├── types.rs   # AVCodecID / AVPixelFormat constants, AV* structs, ROI
//! ├── error.rs   # AvError enum + av_result helpers + AVERROR constants
//! ├── api.rs     # Safe wrapper functions (avcodec_*, av_frame_*, sws_*, …)
//! └── scale.rs   # SwsConverter RAII wrapper (RGBA↔NV12↔YUV420P)
//! ```
//!
//! The previous monolithic `sys.rs` (948 lines) was split into the five files
//! above per P1A §T1.4. All symbols are re-exported from here, so existing
//! `use crate::ffmpeg;` + `ffmpeg::AVCodecContext` / `ffmpeg::ensure_loaded` /
//! `ffmpeg::AvError` references keep working unchanged.
//!
//! # DLL Versions (FFmpeg 8.1.x full build / GyanD shared builds)
//!
//! | Library    | DLL name       | Purpose                     |
//! |------------|----------------|-----------------------------|
//! | avcodec    | avcodec-62.dll | Codec init, encode, decode  |
//! | avutil     | avutil-60.dll  | Frame/packet alloc, images  |
//! | swscale    | swscale-9.dll  | Colorspace conversion       |
//!
//! When upgrading FFmpeg, update the version constants in `dlls.rs`.
//!
//! # Safety
//!
//! FFmpeg C API is inherently unsafe. The safe wrappers in `api.rs`:
//! - Validate pointers before dereference
//! - Track lifetimes of allocated objects
//! - Ensure the function table is loaded before any call
//! - Panic on null pointers from alloc functions (OOM / corrupted state)

pub mod api;
pub mod dlls;
pub mod error;
pub mod scale;
pub mod types;

// Re-export everything so existing `ffmpeg::X` references are unchanged after
// the sys.rs split. Order doesn't matter; names don't collide across modules.
pub use api::*;
pub use dlls::ensure_loaded;
pub use error::*;
pub use types::*;
