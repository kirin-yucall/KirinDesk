use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tracing::{info, warn};

/// A single captured frame.
#[derive(Debug, Clone)]
pub struct Frame {
    /// RGBA pixel data.
    pub data: Vec<u8>,
    /// Frame width.
    pub width: u32,
    /// Frame height.
    pub height: u32,
    /// Capture timestamp.
    pub timestamp: Instant,
}

/// Screen capture configuration.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub framerate: u32,
    pub monitor_index: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self { framerate: 30, monitor_index: 0 }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("No monitors found")]
    NoMonitors,
    #[error("Monitor index {0} out of range")]
    MonitorNotFound(usize),
    #[error("Capture failed: {0}")]
    CaptureFailed(String),
}

/// Screen capture session using DXGI (Windows) via `screenshots` crate.
pub struct ScreenCapture {
    pub config: CaptureConfig,
    running: Arc<AtomicBool>,
}

impl ScreenCapture {
    pub fn new(config: CaptureConfig) -> Self {
        Self { config, running: Arc::new(AtomicBool::new(false)) }
    }

    /// Capture a single frame.
    pub fn capture_frame(config: &CaptureConfig) -> Result<Frame, CaptureError> {
        let screens = screenshots::Screen::all()
            .map_err(|e| CaptureError::CaptureFailed(e.to_string()))?;

        let screen = screens.get(config.monitor_index)
            .ok_or(CaptureError::MonitorNotFound(config.monitor_index))?;

        let image = screen.capture()
            .map_err(|e| CaptureError::CaptureFailed(e.to_string()))?;

        Ok(Frame {
            data: image.rgba().clone(),
            width: image.width(),
            height: image.height(),
            timestamp: Instant::now(),
        })
    }

    /// Start continuous capture loop.
    pub async fn start<F>(&self, mut on_frame: F) -> Result<(), CaptureError>
    where
        F: FnMut(Frame),
    {
        self.running.store(true, Ordering::SeqCst);
        let frame_duration = std::time::Duration::from_secs_f64(1.0 / self.config.framerate as f64);
        info!("Screen capture started: monitor={}, {}fps", self.config.monitor_index, self.config.framerate);

        while self.running.load(Ordering::SeqCst) {
            let start = Instant::now();
            match Self::capture_frame(&self.config) {
                Ok(frame) => on_frame(frame),
                Err(e) => warn!("Frame capture failed: {}", e),
            }
            let elapsed = start.elapsed();
            if elapsed < frame_duration {
                tokio::time::sleep(frame_duration - elapsed).await;
            }
        }
        info!("Screen capture stopped");
        Ok(())
    }

    pub fn stop(&self) { self.running.store(false, Ordering::SeqCst); }

    /// List available monitors.
    pub fn list_monitors() -> Result<Vec<MonitorInfo>, CaptureError> {
        let screens = screenshots::Screen::all()
            .map_err(|e| CaptureError::CaptureFailed(e.to_string()))?;
        Ok(screens.iter().map(|s| MonitorInfo {
            width: s.display_info.width as u32,
            height: s.display_info.height as u32,
            is_primary: s.display_info.is_primary,
        }).collect())
    }
}

#[derive(Debug, Clone)]
pub struct MonitorInfo {
    pub width: u32,
    pub height: u32,
    pub is_primary: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let cfg = CaptureConfig::default();
        assert_eq!(cfg.framerate, 30);
    }

    #[test]
    fn test_monitor_info() {
        let m = MonitorInfo { width: 1920, height: 1080, is_primary: true };
        assert_eq!(m.width, 1920);
        assert!(m.is_primary);
    }
}
