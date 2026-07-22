use std::process::{Child, Command, Stdio};
use std::io::Write;
use tracing::{info, warn};

/// Available hardware encoders.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncoderType {
    /// Auto-detect best available.
    Auto,
    /// NVIDIA NVENC (H.264)
    Nvenc,
    /// AMD AMF (H.264)
    Amf,
    /// Software x264
    Software,
}

/// FFmpeg encoder configuration.
#[derive(Debug, Clone)]
pub struct EncodeConfig {
    /// Encoder to use.
    pub encoder: EncoderType,
    /// Output framerate.
    pub framerate: u32,
    /// Video bitrate (kbps).
    pub bitrate: u32,
    /// Output width (0 = input width).
    pub width: u32,
    /// Output height (0 = input height).
    pub height: u32,
    /// GOP size (keyframe interval).
    pub gop: u32,
    /// Preset (e.g., "p4" for NVENC, "medium" for x264).
    pub preset: String,
}

impl Default for EncodeConfig {
    fn default() -> Self {
        Self {
            encoder: EncoderType::Auto,
            framerate: 30,
            bitrate: 5000,
            width: 0,
            height: 0,
            gop: 60,
            preset: "p4".to_string(),
        }
    }
}

/// Encoder errors.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("FFmpeg not found in PATH")]
    FfmpegNotFound,
    #[error("FFmpeg process error: {0}")]
    ProcessError(String),
    #[error("Failed to write frame to encoder: {0}")]
    WriteError(String),
    #[error("Encoder not initialized")]
    NotInitialized,
}

/// FFmpeg-based H.264 video encoder.
///
/// Spawns FFmpeg as a subprocess and pipes raw RGBA frames to stdin.
/// Produces H.264 Annex-B byte stream on stdout.
pub struct FfmpegEncoder {
    process: Option<Child>,
    config: EncodeConfig,
}

impl FfmpegEncoder {
    pub fn new(config: EncodeConfig) -> Self {
        Self {
            process: None,
            config,
        }
    }

    /// Initialize the FFmpeg encoder subprocess.
    pub fn init(&mut self, width: u32, height: u32) -> Result<(), EncodeError> {
        let out_w = if self.config.width > 0 { self.config.width } else { width };
        let out_h = if self.config.height > 0 { self.config.height } else { height };

        let encoder_name = self.resolve_encoder();
        let preset = &self.config.preset;

        let args = self.build_ffmpeg_args(&encoder_name, preset, out_w, out_h);

        info!("Starting FFmpeg encoder: {} {}x{} {}kbps {}fps",
            encoder_name, out_w, out_h, self.config.bitrate, self.config.framerate);

        let process = Command::new("ffmpeg")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| EncodeError::ProcessError(format!("Failed to start ffmpeg: {}", e)))?;

        self.process = Some(process);
        Ok(())
    }

    /// Encode a raw RGBA frame.
    ///
    /// Returns encoded H.264 data (may be empty for non-keyframes
    /// if the encoder buffers multiple frames).
    pub fn encode(&mut self, rgba_data: &[u8]) -> Result<Vec<u8>, EncodeError> {
        let process = self.process.as_mut().ok_or(EncodeError::NotInitialized)?;
        let stdin = process.stdin.as_mut().ok_or(EncodeError::NotInitialized)?;

        stdin.write_all(rgba_data)
            .map_err(|e| EncodeError::WriteError(e.to_string()))?;

        // FFmpeg outputs encoded data in chunks — we need to read available data
        let stdout = process.stdout.as_mut().ok_or(EncodeError::NotInitialized)?;
        let mut buf = Vec::new();
        use std::io::Read;
        // Try to read without blocking
        stdout.take(1024 * 1024).read_to_end(&mut buf).ok();

        Ok(buf)
    }

    /// Finalize encoding and get remaining buffered data.
    pub fn finish(&mut self) -> Result<Vec<u8>, EncodeError> {
        if let Some(mut process) = self.process.take() {
            // Close stdin to signal EOF
            drop(process.stdin.take());

            use std::io::Read;
            let mut remaining = Vec::new();
            process.stdout.take().unwrap().read_to_end(&mut remaining).ok();
            let _ = process.wait();
            info!("FFmpeg encoder finished");
            Ok(remaining)
        } else {
            Ok(Vec::new())
        }
    }

    fn resolve_encoder(&self) -> String {
        match self.config.encoder {
            EncoderType::Nvenc => "h264_nvenc".to_string(),
            EncoderType::Amf => "h264_amf".to_string(),
            EncoderType::Software => "libx264".to_string(),
            EncoderType::Auto => {
                // Auto-detect: prefer NVENC, then AMF, then software
                if Self::check_encoder("h264_nvenc") { "h264_nvenc" }
                else if Self::check_encoder("h264_amf") { "h264_amf" }
                else { "libx264" }
                .to_string()
            }
        }
    }

    fn check_encoder(name: &str) -> bool {
        let output = Command::new("ffmpeg")
            .args(["-encoders"])
            .output()
            .ok();
        output.map_or(false, |o| String::from_utf8_lossy(&o.stdout).contains(name))
    }

    fn build_ffmpeg_args(&self, encoder: &str, preset: &str, w: u32, h: u32) -> Vec<String> {
        let video_size = format!("{}x{}", w, h);
        let framerate = self.config.framerate.to_string();
        let bitrate = format!("{}k", self.config.bitrate);
        let gop = self.config.gop.to_string();

        vec![
            "-f".to_string(), "rawvideo".to_string(),
            "-pixel_format".to_string(), "rgba".to_string(),
            "-video_size".to_string(), video_size,
            "-framerate".to_string(), framerate,
            "-i".to_string(), "-".to_string(),
            "-c:v".to_string(), encoder.to_string(),
            "-preset".to_string(), preset.to_string(),
            "-b:v".to_string(), bitrate,
            "-g".to_string(), gop,
            "-f".to_string(), "h264".to_string(),
            "-".to_string(),
        ]
    }
}

impl Drop for FfmpegEncoder {
    fn drop(&mut self) {
        if self.process.is_some() {
            let _ = self.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_config_default() {
        let cfg = EncodeConfig::default();
        assert_eq!(cfg.framerate, 30);
        assert_eq!(cfg.bitrate, 5000);
        assert_eq!(cfg.gop, 60);
    }

    #[test]
    fn test_auto_encoder_detection() {
        let result = FfmpegEncoder::check_encoder("h264_nvenc");
        // Just verify it doesn't crash
        println!("NVENC available: {}", result);
    }

    #[test]
    fn test_build_ffmpeg_args() {
        let cfg = EncodeConfig::default();
        let mut enc = FfmpegEncoder::new(cfg);
        let args = enc.build_ffmpeg_args("libx264", "medium", 1920, 1080);
        assert!(args.contains(&"-f".to_string()));
        assert!(args.contains(&"rawvideo".to_string()));
        assert!(args.contains(&"libx264".to_string()));
    }
}
