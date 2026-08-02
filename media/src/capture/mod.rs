//! 跨平台屏幕捕获抽象层。
//!
//! # 后端（与 task_docs 设计一致，M8-T008 §Step 1）
//!
//! | 平台 | 后端 | 状态 |
//! |------|------|------|
//! | Windows | `windows-capture` crate（唯一后端，无 WGC/DXGI/GDI 回退链） | ✅ 已实现 |
//! | macOS | `zed-scap` crate（ScreenCaptureKit，M12-MAC MAC-T001） | ✅ 已实现 |
//! | Linux | `zed-scap` | ⏳ M12（见 远控服务端_需求文档 §3.2.2） |
//!
//! 旧后端（wgc/dxgi/gdi/pipewire）已按 M8-T008 设计删除。

pub mod factory;

#[cfg(target_os = "windows")]
pub mod windows_capture;

#[cfg(target_os = "macos")]
pub mod zed_scap;

pub use factory::{create_capture_source, enumerate_monitors, list_monitors};

use std::time::Instant;

use crate::proto::DirtyRect;

// ════════════════════════════════════════════════════════════════
// CaptureFrame
// ════════════════════════════════════════════════════════════════

/// 一次捕获的结果。
pub enum CaptureFrame {
    /// windows-capture crate 帧（Windows 唯一后端）。
    WindowsCapture(WindowsCaptureFrame),
    /// zed-scap crate 帧（macOS，ScreenCaptureKit）。
    ZedScap(ZedScapFrame),
}

impl CaptureFrame {
    pub fn data(&self) -> &[u8] {
        match self {
            CaptureFrame::WindowsCapture(f) => &f.data,
            CaptureFrame::ZedScap(f) => &f.data,
        }
    }

    pub fn width(&self) -> u32 {
        match self {
            CaptureFrame::WindowsCapture(f) => f.width,
            CaptureFrame::ZedScap(f) => f.width,
        }
    }

    pub fn height(&self) -> u32 {
        match self {
            CaptureFrame::WindowsCapture(f) => f.height,
            CaptureFrame::ZedScap(f) => f.height,
        }
    }

    pub fn timestamp(&self) -> Instant {
        match self {
            CaptureFrame::WindowsCapture(f) => f.timestamp,
            CaptureFrame::ZedScap(f) => f.timestamp,
        }
    }

    /// 返回此帧的 dirty rects 列表。
    ///
    /// windows-capture 的 `Frame::dirty_regions()` 提供 dirty rects；
    /// zed-scap（ScreenCaptureKit）不暴露脏区信息 → 恒空列表
    /// （捕获层无完整 dirty rects 信息 → Tile-Hash Diff 仍是前置优化层，
    /// 见 M8-T008 §Step 1）。
    pub fn dirty_rects(&self) -> &[DirtyRect] {
        match self {
            CaptureFrame::WindowsCapture(f) => &f.dirty_rects,
            CaptureFrame::ZedScap(f) => &f.dirty_rects,
        }
    }
}

/// windows-capture crate 捕获帧。
pub struct WindowsCaptureFrame {
    /// RGBA pixel data
    pub data: Vec<u8>,
    /// 宽度（像素）
    pub width: u32,
    /// 高度（像素）
    pub height: u32,
    /// dirty rects（通过 windows-capture 的 Frame::dirty_regions() 获取）
    pub dirty_rects: Vec<DirtyRect>,
    /// 捕获线程回调内处理耗时（不含等待）
    pub processing_time: std::time::Duration,
    /// 捕获时间戳
    pub timestamp: Instant,
}

/// zed-scap crate 捕获帧（macOS，ScreenCaptureKit）。
///
/// 结构体本身平台无关（与 [`WindowsCaptureFrame`] 同模式，定义在此处），
/// macOS 后端实现在 `zed_scap.rs`（`cfg(target_os = "macos")` 门控）。
pub struct ZedScapFrame {
    /// RGBA pixel data（zed-scap 原生 BGRA，已转 RGBA 对齐统一管线）
    pub data: Vec<u8>,
    /// 宽度（像素）
    pub width: u32,
    /// 高度（像素）
    pub height: u32,
    /// dirty rects（zed-scap 无脏区信息 → 恒空，上游 diff 层兜底）
    pub dirty_rects: Vec<DirtyRect>,
    /// 捕获时间戳（帧到达时刻）
    pub timestamp: Instant,
}

// ════════════════════════════════════════════════════════════════
// CaptureError
// ════════════════════════════════════════════════════════════════

/// 捕获操作错误。
#[derive(Debug, Clone)]
pub enum CaptureError {
    /// 捕获超时（指定等待时间内无屏幕变化）。
    Timeout,
    /// 连接丢失（需 recreate）。
    AccessLost,
    /// 通用捕获失败。
    Capture(String),
    /// 无可用显示器。
    NoMonitor,
    /// 无效的显示器索引。
    InvalidMonitor,
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::Timeout => write!(f, "capture timeout (no screen change)"),
            CaptureError::AccessLost => write!(f, "capture access lost — recreate required"),
            CaptureError::Capture(s) => write!(f, "capture failed: {s}"),
            CaptureError::NoMonitor => write!(f, "no monitor available"),
            CaptureError::InvalidMonitor => write!(f, "invalid monitor index"),
        }
    }
}

impl std::error::Error for CaptureError {}

// ════════════════════════════════════════════════════════════════
// MonitorInfo
// ════════════════════════════════════════════════════════════════

/// 显示器信息。
#[derive(Debug, Clone)]
pub struct MonitorInfo {
    pub id: usize,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub is_primary: bool,
}

// ════════════════════════════════════════════════════════════════
// ScreenCaptureSource trait
// ════════════════════════════════════════════════════════════════

/// 跨平台屏幕捕获接口。
pub trait ScreenCaptureSource: Send {
    /// 阻塞直到屏幕有实际变化，返回最新帧。
    ///
    /// - windows-capture 模式：后台线程回调推帧，此处阻塞接收。
    fn wait_for_frame(&mut self) -> Result<CaptureFrame, CaptureError>;

    /// M8-T018（MON-NF-002）：带超时的等待——静默屏幕（长时间无画面变化）
    /// 时，上层可定期醒来处理显示器切换命令；超时返回 [`CaptureError::Timeout`]。
    /// 默认实现等价旧行为（无限等待）；Windows 后端用 `recv_timeout` 实现。
    fn wait_for_frame_timeout(
        &mut self,
        _timeout: std::time::Duration,
    ) -> Result<CaptureFrame, CaptureError> {
        self.wait_for_frame()
    }

    /// 当前捕获分辨率 `(width, height)`。
    fn resolution(&self) -> (u32, u32);

    /// 显示器信息列表。
    fn monitor_info(&self) -> &[MonitorInfo];

    /// 切换到指定显示器（按索引）。
    fn switch_monitor(&mut self, index: usize) -> Result<(), CaptureError>;

    /// 重建捕获源（AccessLost / 分辨率变更后调用）。
    fn recreate(&mut self) -> Result<(), CaptureError>;
}
