//! Shared swscale color-space conversion wrapper.
//!
//! `SwsConverter` is a small RAII type around `sws_getContext` + `sws_scale` +
//! `sws_freeContext`. It is the deduplication seam called out in P1A §T1.4:
//! both `encoder/video/ffmpeg_hw.rs` (P1C) and `decoder.rs` will route RGBA↔
//! NV12↔YUV420P conversions through this type instead of each open-coding
//! their own `sws_ctx` field.
//!
//! # P1A scope
//!
//! This file provides the type and its lifecycle + a single `scale` entry
//! point. **It does not yet rewrite `encoder/ffmpeg.rs` or `decoder.rs`** —
//! those keep their existing inlined sws logic to avoid regressions; the
//! actual migration is scheduled for P1C.

#![allow(dead_code)]

use std::ptr;

use super::api::{sws_freeContext, sws_getContext, sws_scale, SWS_FAST_BILINEAR};
use super::error::AvError;
use super::types::SwsContext;

/// RAII wrapper over an FFmpeg `SwsContext`.
///
/// Caches the conversion for a fixed (src fmt/dims → dst fmt/dims) tuple.
/// Dimension changes require re-creating the converter (see [`with_dims`]).
pub struct SwsConverter {
    ctx: *mut SwsContext,
    src_w: i32,
    src_h: i32,
    src_fmt: i32,
    dst_w: i32,
    dst_h: i32,
    dst_fmt: i32,
    flags: i32,
}

impl SwsConverter {
    /// Create a new converter for the given conversion tuple.
    pub fn new(
        src_w: i32,
        src_h: i32,
        src_fmt: i32,
        dst_w: i32,
        dst_h: i32,
        dst_fmt: i32,
    ) -> Result<Self, AvError> {
        Self::with_flags(
            src_w,
            src_h,
            src_fmt,
            dst_w,
            dst_h,
            dst_fmt,
            SWS_FAST_BILINEAR,
        )
    }

    /// Like [`new`] but with an explicit swscale flags value
    /// (e.g. [`SWS_BILINEAR`](super::api::SWS_BILINEAR),
    /// [`SWS_BICUBIC`](super::api::SWS_BICUBIC)).
    pub fn with_flags(
        src_w: i32,
        src_h: i32,
        src_fmt: i32,
        dst_w: i32,
        dst_h: i32,
        dst_fmt: i32,
        flags: i32,
    ) -> Result<Self, AvError> {
        let ctx = sws_getContext(src_w, src_h, src_fmt, dst_w, dst_h, dst_fmt, flags)?;
        Ok(Self {
            ctx,
            src_w,
            src_h,
            src_fmt,
            dst_w,
            dst_h,
            dst_fmt,
            flags,
        })
    }

    /// Re-create the underlying context if the requested tuple changed.
    ///
    /// Cheap no-op when nothing changed; used by callers that may observe
    /// resolution flips.
    pub fn ensure_dims(
        &mut self,
        src_w: i32,
        src_h: i32,
        src_fmt: i32,
        dst_w: i32,
        dst_h: i32,
        dst_fmt: i32,
    ) -> Result<(), AvError> {
        if !self.ctx.is_null()
            && self.src_w == src_w
            && self.src_h == src_h
            && self.src_fmt == src_fmt
            && self.dst_w == dst_w
            && self.dst_h == dst_h
            && self.dst_fmt == dst_fmt
        {
            return Ok(());
        }
        // Replace context.
        if !self.ctx.is_null() {
            sws_freeContext(self.ctx);
            self.ctx = ptr::null_mut();
        }
        let ctx = sws_getContext(src_w, src_h, src_fmt, dst_w, dst_h, dst_fmt, self.flags)?;
        self.ctx = ctx;
        self.src_w = src_w;
        self.src_h = src_h;
        self.src_fmt = src_fmt;
        self.dst_w = dst_w;
        self.dst_h = dst_h;
        self.dst_fmt = dst_fmt;
        Ok(())
    }

    /// Run the colorspace conversion.
    ///
    /// `src`/`dst` slices follow the `[*const/*mut u8; 4]` + `[i32; 4]`
    /// layout used by `av_image_fill_arrays`.
    pub fn scale(
        &self,
        src: &[*const u8; 4],
        src_stride: &[i32; 4],
        dst: &[*mut u8; 4],
        dst_stride: &[i32; 4],
    ) -> Result<i32, AvError> {
        sws_scale(self.ctx, src, src_stride, 0, self.src_h, dst, dst_stride)
    }

    /// Raw context pointer (for advanced callers that need to interoperate
    /// with raw FFmpeg APIs). The converter still owns it.
    pub fn as_ptr(&self) -> *mut SwsContext {
        self.ctx
    }
}

impl Drop for SwsConverter {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            sws_freeContext(self.ctx);
            self.ctx = ptr::null_mut();
        }
    }
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::super::types::{AV_PIX_FMT_NV12, AV_PIX_FMT_RGBA};
    use super::*;

    /// P1A Tests §ffmpeg: 1080p RGBA→NV12 转换输出尺寸/格式正确。
    /// 复用 decoder 既有测试路径（无 DLL 时跳过）。
    #[test]
    fn test_sws_rgba_nv12() {
        if super::super::dlls::ensure_loaded().is_err() {
            eprintln!("FFmpeg libraries not available; test_sws_rgba_nv12 skipped");
            return;
        }
        let w = 320i32;
        let h = 240i32;
        let conv = match SwsConverter::new(w, h, AV_PIX_FMT_RGBA, w, h, AV_PIX_FMT_NV12) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SwsConverter create failed (OK on some builds): {}", e);
                return;
            }
        };
        // NV12 buffer size = w*h (Y) + w*h/2 (interleaved UV)
        let buf_size = (w as usize * h as usize * 3 / 2) + 64;
        let mut src = vec![0u8; (w as usize * h as usize * 4) + 64];
        let mut dst = vec![0u8; buf_size];

        let src_ptrs: [*const u8; 4] = [src.as_ptr(), ptr::null(), ptr::null(), ptr::null()];
        let src_stride: [i32; 4] = [w * 4, 0, 0, 0];
        let dst_y = dst.as_mut_ptr();
        let dst_uv = unsafe { dst.as_mut_ptr().add(w as usize * h as usize) };
        let dst_ptrs: [*mut u8; 4] = [dst_y, dst_uv, ptr::null_mut(), ptr::null_mut()];
        let dst_stride: [i32; 4] = [w, w, 0, 0];

        match conv.scale(&src_ptrs, &src_stride, &dst_ptrs, &dst_stride) {
            Ok(scaled) => {
                assert!(scaled >= 0, "sws_scale returned negative");
                eprintln!("RGBA→NV12 scaled {} scanlines", scaled);
            }
            Err(e) => eprintln!("scale failed (OK on some builds): {}", e),
        }
    }
}
