//! Windows Capture 后端 — 使用 `windows-capture` crate。
//!
//! Windows 唯一后端（M8-T008 §Step 1，无 WGC/DXGI/GDI 回退链）。
//!
//! 使用 `start_free_threaded()` 在后台线程运行捕获事件循环，
//! 通过 `mpsc` channel 向主线程投递帧数据。
//!
//! 依赖 `windows-capture` crate v2.0.0。

#![cfg(target_os = "windows")]

use crate::capture::{CaptureError, CaptureFrame, DirtyRect, MonitorInfo, ScreenCaptureSource};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Instant;

use windows_capture::capture::{CaptureControl, Context, GraphicsCaptureApiHandler};
use windows_capture::frame::Frame;
use windows_capture::monitor::Monitor;
use windows_capture::settings::{
    ColorFormat, CursorCaptureSettings, DirtyRegionSettings, DrawBorderSettings,
    MinimumUpdateIntervalSettings, SecondaryWindowSettings, Settings,
};

// ════════════════════════════════════════════════════════════════
// 从 channel 传递的内部帧结构
// ════════════════════════════════════════════════════════════════

/// 从捕获线程传递到主线程的一帧数据。
pub struct CapturedFrame {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub row_pitch: u32,
    pub dirty_rects: Vec<DirtyRect>,
    /// 回调内处理耗时（buffer 读取 + 像素拷贝 + dirty 提取）
    pub processing_time: std::time::Duration,
    pub capture_start: Instant,
}

// ════════════════════════════════════════════════════════════════
// GraphicsCaptureApiHandler 实现
// ════════════════════════════════════════════════════════════════

struct WcHandler {
    frame_tx: mpsc::Sender<CapturedFrame>,
    stop_flag: Arc<AtomicBool>,
}

impl GraphicsCaptureApiHandler for WcHandler {
    type Flags = (mpsc::Sender<CapturedFrame>, Arc<AtomicBool>);
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn new(ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
        Ok(Self {
            frame_tx: ctx.flags.0,
            stop_flag: ctx.flags.1,
        })
    }

    fn on_frame_arrived(
        &mut self,
        frame: &mut Frame<'_>,
        _capture_control: windows_capture::graphics_capture_api::InternalCaptureControl,
    ) -> Result<(), Self::Error> {
        let capture_start = Instant::now();
        let w = frame.width();
        let h = frame.height();

        // 读取像素数据
        let mut buf = frame.buffer()?;
        let row_pitch = buf.row_pitch();
        let data = if buf.has_padding() {
            // 去掉行填充，保留 w*4 每行
            let mut flat = Vec::with_capacity((w * h * 4) as usize);
            let raw = buf.as_raw_buffer();
            let src_stride = row_pitch as usize;
            let dst_stride = (w * 4) as usize;
            for y in 0..h as usize {
                let src_start = y * src_stride;
                flat.extend_from_slice(&raw[src_start..src_start + dst_stride]);
            }
            flat
        } else {
            buf.as_raw_buffer().to_vec()
        };

        // 读取 dirty rects
        let dirty_rects: Vec<DirtyRect> = frame
            .dirty_regions()
            .unwrap_or_default()
            .iter()
            .map(|r| DirtyRect {
                x: r.x.max(0) as u32,
                y: r.y.max(0) as u32,
                w: r.width.max(0) as u32,
                h: r.height.max(0) as u32,
            })
            .collect();

        let capture_end = Instant::now();

        let _ = self.frame_tx.send(CapturedFrame {
            data,
            width: w,
            height: h,
            row_pitch,
            dirty_rects,
            processing_time: capture_end - capture_start,
            capture_start,
        });

        Ok(())
    }

    fn on_closed(&mut self) -> Result<(), Self::Error> {
        self.stop_flag.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════
// 显示器枚举（windows-capture 唯一后端，替代旧 GDI/DXGI 枚举）
// ════════════════════════════════════════════════════════════════

/// 显示器名称是否虚拟（M8-T030 §3.3 显示器关键词表；大小写不敏感子串匹配）。
///
/// `virtual_keywords`（全局偏好）非空时覆盖默认表（适配器 + 显示器共用开关）。
fn is_virtual_monitor(name: &str) -> bool {
    let prefs = crate::gpu::preferences();
    if prefs.virtual_keywords.is_empty() {
        crate::gpu::matches_keywords(name, crate::gpu::DEFAULT_MONITOR_KEYWORDS)
    } else {
        let kw: Vec<&str> = prefs.virtual_keywords.iter().map(|s| s.as_str()).collect();
        crate::gpu::matches_keywords(name, &kw)
    }
}

/// 枚举显示器（M8-T030 过滤虚拟屏），返回过滤后列表 + 索引映射。
///
/// `real_indices[i]` = 过滤后索引 `i` → windows-capture **1-based 全量索引**
/// （设计文档 §3.6，消除"过滤列表索引 vs 全量索引错位"隐患）。
///
/// - `filter_virtual`（全局偏好，默认 true）时按名称关键词剔除虚拟屏；
///   关闭时全部保留（`is_virtual` 字段仍标记，供审计）。
/// - 过滤后 `MonitorInfo.id` 重新编号为过滤位置（0-based 连续），
///   `switch_monitor` 与 wire 索引（`DisplayInfo.index`）天然一致。
fn enumerate_monitors_filtered() -> Result<(Vec<MonitorInfo>, Vec<usize>), CaptureError> {
    let monitors = Monitor::enumerate()
        .map_err(|e| CaptureError::Capture(format!("Monitor::enumerate: {e}")))?;
    let primary_raw = Monitor::primary()
        .map(|m| m.as_raw_hmonitor())
        .unwrap_or(std::ptr::null_mut());
    let filter_virtual = crate::gpu::preferences().filter_virtual;
    let total = monitors.len();

    let mut out = Vec::with_capacity(total);
    let mut real_indices = Vec::with_capacity(total);
    for (i, m) in monitors.into_iter().enumerate() {
        let name = m.name().unwrap_or_default();
        let is_virtual = is_virtual_monitor(&name);
        if filter_virtual && is_virtual {
            tracing::debug!(
                "Monitor: filtered virtual display '{name}' (1-based full index {})",
                i + 1
            );
            continue;
        }
        out.push(MonitorInfo {
            id: out.len(), // 过滤后位置重新编号（0-based 连续）。
            name,
            width: m.width().unwrap_or(0),
            height: m.height().unwrap_or(0),
            is_primary: m.as_raw_hmonitor() == primary_raw,
            is_virtual,
        });
        real_indices.push(i + 1); // windows-capture 1-based 全量索引。
    }
    if out.is_empty() {
        return Err(CaptureError::NoMonitor);
    }
    tracing::info!(
        "Monitor: enumerated {} monitor(s), {} virtual filtered ({} real)",
        total,
        total - out.len(),
        out.len()
    );
    Ok((out, real_indices))
}

/// 枚举所有显示器（过滤虚拟屏；公开 API，供 factory::list_monitors）。
pub fn enumerate_monitors() -> Result<Vec<MonitorInfo>, CaptureError> {
    enumerate_monitors_filtered().map(|(list, _)| list)
}

// ════════════════════════════════════════════════════════════════
// WindowsCaptureBackend — ScreenCaptureSource
// ════════════════════════════════════════════════════════════════

/// 使用 `windows-capture` crate 的捕获源（Windows 唯一后端）。
pub struct WindowsCaptureBackend {
    /// 从后台线程接收帧
    frame_rx: mpsc::Receiver<CapturedFrame>,
    /// 控制句柄（用于 stop）
    capture_control: Option<CaptureControl<WcHandler, Box<dyn std::error::Error + Send + Sync>>>,
    /// 停止信号
    stop_flag: Arc<AtomicBool>,
    /// 显示器列表
    monitors: Vec<MonitorInfo>,
    /// M8-T030（R-06）：过滤后索引 → windows-capture 1-based 全量索引映射
    /// （虚拟屏剔除后 `Monitor::from_index` 必须用全量索引，否则列表错位）。
    real_indices: Vec<usize>,
    /// 当前显示器索引
    monitor_index: usize,
    /// 当前分辨率
    width: u32,
    height: u32,
    /// 后台线程句柄（CaptureControl 内部已管理线程，但确保 Drop 顺序）
    _thread: Option<thread::JoinHandle<()>>,
}

unsafe impl Send for WindowsCaptureBackend {}

impl WindowsCaptureBackend {
    /// 创建 windows-capture 后端。
    ///
    /// `monitor_index`: 0-based 显示器索引（过滤虚拟屏后的位置）。
    pub fn new(monitor_index: usize) -> Result<Self, CaptureError> {
        // 1. 枚举显示器（M8-T030 过滤虚拟屏；windows-capture 唯一后端）
        let (monitors, real_indices) = enumerate_monitors_filtered()?;
        if monitor_index >= monitors.len() {
            return Err(CaptureError::InvalidMonitor);
        }

        // 2. 使用 windows-capture 的 Monitor API 获取显示器（1-based 全量索引
        //    ——经 real_indices 映射，消除虚拟屏过滤后的索引错位）。
        let wc_monitor = Monitor::from_index(real_indices[monitor_index])
            .map_err(|e| CaptureError::Capture(format!("Monitor::from_index: {e}")))?;
        let w = wc_monitor.width().unwrap_or(monitors[monitor_index].width);
        let h = wc_monitor
            .height()
            .unwrap_or(monitors[monitor_index].height);

        // 3. 创建 channel + 停止信号
        let (frame_tx, frame_rx) = mpsc::channel::<CapturedFrame>();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let flags = (frame_tx, stop_flag.clone());

        // 4. 构建 Settings + 启动捕获
        let settings = Settings::new(
            wc_monitor,
            CursorCaptureSettings::Default,
            DrawBorderSettings::Default,
            SecondaryWindowSettings::Default,
            MinimumUpdateIntervalSettings::Default,
            DirtyRegionSettings::Default,
            ColorFormat::Rgba8,
            flags,
        );

        // 5. 在后台线程启动（start_free_threaded 返回 CaptureControl）
        let capture_control = WcHandler::start_free_threaded(settings)
            .map_err(|e| CaptureError::Capture(format!("windows-capture start failed: {e}")))?;

        tracing::info!(
            "WindowsCaptureBackend: started for monitor {} ({}x{})",
            monitor_index,
            w,
            h
        );

        Ok(Self {
            frame_rx,
            capture_control: Some(capture_control),
            stop_flag,
            monitors,
            real_indices,
            monitor_index,
            width: w,
            height: h,
            _thread: None,
        })
    }

    fn stop_capture(&mut self) {
        if let Some(ctrl) = self.capture_control.take() {
            let _ = ctrl.stop();
        }
        self.stop_flag.store(true, Ordering::SeqCst);
        // Drain remaining frames
        while self.frame_rx.try_recv().is_ok() {}
    }
}

impl ScreenCaptureSource for WindowsCaptureBackend {
    fn wait_for_frame(&mut self) -> Result<CaptureFrame, CaptureError> {
        let captured = self
            .frame_rx
            .recv()
            .map_err(|_| CaptureError::Capture("windows-capture channel closed".into()))?;

        let frame = CaptureFrame::WindowsCapture(crate::capture::WindowsCaptureFrame {
            data: captured.data,
            width: captured.width,
            height: captured.height,
            dirty_rects: captured.dirty_rects,
            processing_time: captured.processing_time,
            timestamp: Instant::now(),
        });

        Ok(frame)
    }

    /// M8-T018（MON-NF-002）：静默屏幕（无帧到达）时按超时醒来——上层借此
    /// 处理显示器切换命令，切换延迟与屏幕活动度解耦。
    fn wait_for_frame_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<CaptureFrame, CaptureError> {
        let captured = self
            .frame_rx
            .recv_timeout(timeout)
            .map_err(|e| match e {
                std::sync::mpsc::RecvTimeoutError::Timeout => CaptureError::Timeout,
                _ => CaptureError::Capture("windows-capture channel closed".into()),
            })?;

        let frame = CaptureFrame::WindowsCapture(crate::capture::WindowsCaptureFrame {
            data: captured.data,
            width: captured.width,
            height: captured.height,
            dirty_rects: captured.dirty_rects,
            processing_time: captured.processing_time,
            timestamp: Instant::now(),
        });

        Ok(frame)
    }

    fn resolution(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn monitor_info(&self) -> &[MonitorInfo] {
        &self.monitors
    }

    fn switch_monitor(&mut self, index: usize) -> Result<(), CaptureError> {
        if index >= self.monitors.len() {
            return Err(CaptureError::InvalidMonitor);
        }
        // 相同索引 → 无操作（避免无谓的捕获源重建）。
        if index == self.monitor_index {
            return Ok(());
        }

        // Stop old capture
        self.stop_capture();

        // Start new capture（M8-T030：经 real_indices 映射全量索引）。
        let wc_monitor = Monitor::from_index(self.real_indices[index])
            .map_err(|e| CaptureError::Capture(format!("Monitor::from_index: {e}")))?;
        let w = wc_monitor.width().unwrap_or(self.monitors[index].width);
        let h = wc_monitor.height().unwrap_or(self.monitors[index].height);

        let (frame_tx, frame_rx) = mpsc::channel::<CapturedFrame>();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let flags = (frame_tx, stop_flag.clone());

        let settings = Settings::new(
            wc_monitor,
            CursorCaptureSettings::Default,
            DrawBorderSettings::Default,
            SecondaryWindowSettings::Default,
            MinimumUpdateIntervalSettings::Default,
            DirtyRegionSettings::Default,
            ColorFormat::Rgba8,
            flags,
        );

        let capture_control = WcHandler::start_free_threaded(settings)
            .map_err(|e| CaptureError::Capture(format!("windows-capture switch: {e}")))?;

        self.frame_rx = frame_rx;
        self.capture_control = Some(capture_control);
        self.stop_flag = stop_flag;
        self.monitor_index = index;
        self.width = w;
        self.height = h;

        Ok(())
    }

    fn recreate(&mut self) -> Result<(), CaptureError> {
        self.stop_capture();
        // 短暂延迟后重新创建
        std::thread::sleep(std::time::Duration::from_millis(100));
        self.switch_monitor(self.monitor_index)
    }
}

impl Drop for WindowsCaptureBackend {
    fn drop(&mut self) {
        self.stop_capture();
    }
}
