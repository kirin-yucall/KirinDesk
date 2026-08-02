//! FFmpeg error codes, error enum and result helpers.
//!
//! Self-contained: no dependency on other `ffmpeg` submodules, so it can be
//! referenced from `types.rs` / `api.rs` / `dlls.rs` without cycles.

#![allow(non_camel_case_types, dead_code)]

// ════════════════════════════════════════════════════════════════
// Error codes (negative on failure, mirrors FFmpeg AVERROR macros)
// ════════════════════════════════════════════════════════════════

pub const AVERROR_SUCCESS: i32 = 0;

/// Mirror of FFmpeg's `AVERROR(e)` = `-e` for errno-style codes.
const fn averror(e: i32) -> i32 {
    -e
}

pub const AVERROR_IO: i32 = averror(5);
pub const AVERROR_PERM: i32 = averror(1);
pub const AVERROR_NOENT: i32 = averror(2);
pub const AVERROR_EAGAIN: i32 = averror(11);
pub const AVERROR_NOMEM: i32 = averror(12);
pub const AVERROR_INVALIDDATA: i32 = averror(22);
/// FFmpeg's literal AVERROR_EOF magic value.
pub const AVERROR_EOF: i32 = -541478725;
pub const AVERROR_BSF_NOT_FOUND: i32 = -1179861248;
pub const AVERROR_DECODER_NOT_FOUND: i32 = -1128612191;
pub const AVERROR_ENCODER_NOT_FOUND: i32 = -1128205312;
pub const AVERROR_UNKNOWN: i32 = averror(99);

/// `true` when an FFmpeg return value signals an error (negative).
pub fn is_av_error(ret: i32) -> bool {
    ret < 0
}

// ════════════════════════════════════════════════════════════════
// AvError enum
// ════════════════════════════════════════════════════════════════

/// Error type returned by all `ffmpeg::api` wrappers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvError {
    /// Raw FFmpeg return code (negative).
    Code(i32),
    /// DLL or symbol loading failed.
    LoadFailed(String),
    /// FFmpeg returned a null pointer where one was required.
    NullPtr(&'static str),
    /// Caller-supplied argument was invalid (e.g. embedded NUL byte).
    InvalidArgs(String),
    /// Codec lookup failed.
    CodecNotFound(String),
    /// Unsupported pixel format / codec id.
    UnsupportedFormat(i32),
}

impl std::fmt::Display for AvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AvError::Code(c) => {
                let label = match *c {
                    AVERROR_EAGAIN => "EAGAIN (need more input)",
                    AVERROR_EOF => "EOF (end of stream)",
                    AVERROR_NOMEM => "Out of memory",
                    AVERROR_INVALIDDATA => "Invalid data",
                    AVERROR_IO => "I/O error",
                    AVERROR_DECODER_NOT_FOUND => "Decoder not found",
                    AVERROR_ENCODER_NOT_FOUND => "Encoder not found",
                    AVERROR_BSF_NOT_FOUND => "Bitstream filter not found",
                    _ => "Unknown error",
                };
                write!(f, "AVError({}): {}", c, label)
            }
            AvError::LoadFailed(s) => write!(f, "Load failed: {}", s),
            AvError::NullPtr(s) => write!(f, "Null pointer: {}", s),
            AvError::InvalidArgs(s) => write!(f, "Invalid args: {}", s),
            AvError::CodecNotFound(s) => write!(f, "Codec not found: {}", s),
            AvError::UnsupportedFormat(fmt) => write!(f, "Unsupported pixel format: {}", fmt),
        }
    }
}

impl std::error::Error for AvError {}

/// Convert an FFmpeg return code into a `Result<(), AvError>`.
pub fn av_result(ret: i32) -> Result<(), AvError> {
    if ret >= 0 {
        Ok(())
    } else {
        Err(AvError::Code(ret))
    }
}

/// Convert an FFmpeg return code, yielding `val` on success.
pub fn av_result_with<T: From<i32>>(ret: i32, val: T) -> Result<T, AvError> {
    if ret >= 0 {
        Ok(val)
    } else {
        Err(AvError::Code(ret))
    }
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// P1A Tests §ffmpeg: AVERROR 映射为可读文本（核心几个错误码）。
    #[test]
    fn test_av_error_display() {
        assert_eq!(
            AvError::Code(AVERROR_EAGAIN).to_string(),
            format!("AVError({}): EAGAIN (need more input)", AVERROR_EAGAIN)
        );
        assert!(AvError::Code(AVERROR_EOF).to_string().contains("EOF"));
        assert!(AvError::Code(AVERROR_NOMEM)
            .to_string()
            .contains("Out of memory"));
        assert!(AvError::Code(AVERROR_INVALIDDATA)
            .to_string()
            .contains("Invalid data"));
        // Unknown code falls back to generic label.
        assert!(AvError::Code(-99999).to_string().contains("Unknown error"));

        // Non-code variants.
        assert!(AvError::LoadFailed("avcodec-62".into())
            .to_string()
            .contains("Load failed: avcodec-62"));
        assert!(AvError::NullPtr("ctx")
            .to_string()
            .contains("Null pointer: ctx"));
        assert!(AvError::CodecNotFound("h264".into())
            .to_string()
            .contains("Codec not found: h264"));
    }

    #[test]
    fn test_av_result_helpers() {
        assert!(av_result(0).is_ok());
        assert!(av_result(42).is_ok());
        assert!(matches!(av_result(-1), Err(AvError::Code(-1))));
        assert!(is_av_error(-1));
        assert!(!is_av_error(0));

        assert_eq!(av_result_with(0, 7).unwrap(), 7);
        assert!(av_result_with::<i32>(-5, 7).is_err());
    }

    #[test]
    fn test_averror_implements_std_error() {
        fn takes_err(e: &dyn std::error::Error) -> String {
            e.to_string()
        }
        let err = AvError::Code(AVERROR_EOF);
        assert!(takes_err(&err).contains("EOF"));
    }
}
