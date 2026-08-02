//! macOS 屏幕捕获后端 — `zed-scap` crate（ScreenCaptureKit 封装，macOS 12+）。
//!
//! M12-MAC（MAC-T001，设计依据：`远控服务端_需求文档.md §3.2.3`）：
//! - 使用 `zed-scap = "=0.0.8-zed"`（crates.io 上 zed-industries/scap 的发布版，
//!   ScreenCaptureKit 后端，系统内置框架，无第三方运行时依赖）。
//! - 权限：Screen Recording（TCC）。`Capturer::build` 内部会检查
//!   `is_supported` + `has_permission`；本后端不自动弹窗（由 UI/CLI 调用
//!   [`request_permission`] 引导用户，见 `UI_需求文档.md` 权限流程）。
//! - 输出：`Frame::BGRA` → 转换 **RGBA**（与 windows-capture 的 `Rgba8` 输出、
//!   编码层 `AV_PIX_FMT_RGBA` 源格式一致，见 `ffmpeg_sw.rs`/`ffmpeg_hw.rs`）。
//! - dirty rects：zed-scap 不暴露脏区信息 → 空列表（由上游 Tile-Hash Diff 前置
//!   优化层兜底，与 M8-T008 §Step 1 一致）。
//!
//! # 线程模型
//!
//! `Capturer::get_next_frame` 阻塞等待引擎回调（内部 mpsc），与
//! [`ScreenCaptureSource::wait_for_frame`] 的阻塞语义一致；捕获线程独占
//! 本后端（`unsafe impl Send` 的理由见下）。
//!
//! # 构建目标
//!
//! `rustup target add aarch64-apple-darwin x86_64-apple-darwin`（macOS 12.0+）。
//! 本文件仅在 macOS 编译（`#![cfg(target_os = "macos")]`），Windows 构建不受影响。

#![cfg(target_os = "macos")]

use std::time::Instant;

use scap::capturer::{Capturer, Options, Resolution};
use scap::frame::{Frame, FrameType};
use scap::Target;

use crate::capture::{CaptureError, CaptureFrame, MonitorInfo, ScreenCaptureSource, ZedScapFrame};
use crate::proto::DirtyRect;

/// macOS 捕获后端（zed-scap / ScreenCaptureKit）。
pub struct ZedScapBackend {
    /// zed-scap 捕获器（捕获线程独占；见下方 `unsafe impl Send` 说明）。
    capturer: Capturer,
    /// 当前目标显示器索引（对应 [`MonitorInfo::id`]，与 Windows 后端语义一致）。
    monitor_index: usize,
    /// 最近一次捕获分辨率（`get_output_frame_size` 的兜底）。
    last_size: (u32, u32),
}

// SAFETY: `Capturer` 内部为引擎句柄 + `mpsc::Receiver`（Send）。引擎各平台
// 句柄在 macOS 为 `CGDisplayID`（u32 包装）等可安全跨线程移动的值，无
// thread-affine 状态（捕获回调在引擎内部线程，经 channel 投递帧）；本后端
// 仅由单条捕获线程使用。与 `OpusEncoder` 的 `unsafe impl Send` 同模式
// （句柄 + 线程独占，由调用方保证）。
unsafe impl Send for ZedScapBackend {}

impl ZedScapBackend {
    /// 创建捕获源（按显示器索引选择目标；索引越界回退主显示器）。
    ///
    /// - 平台不支持（非 macOS 不会编译到此）→ NotSupported。
    /// - 无 Screen Recording 权限 → `Capture`（提示授权，不自动弹窗）。
    pub fn new(monitor_index: usize) -> Result<Self, CaptureError> {
        if !scap::is_supported() {
            return Err(CaptureError::Capture(
                "ScreenCaptureKit not supported on this macOS version (need 12.0+)".into(),
            ));
        }
        if !scap::has_permission() {
            return Err(CaptureError::Capture(
                "macOS screen recording permission not granted — \
                 System Settings → Privacy & Security → Screen Recording"
                    .into(),
            ));
        }

        let targets = scap::get_all_targets()
            .map_err(|e| CaptureError::Capture(format!("scap::get_all_targets: {e}")))?;
        let displays: Vec<&Target> = targets
            .iter()
            .filter(|t| matches!(t, Target::Display(_)))
            .collect();
        let target = displays
            .get(monitor_index)
            .copied()
            .or_else(|| displays.first().copied());

        let options = Options {
            fps: 30,
            show_cursor: true,
            show_highlight: false,
            target: target.cloned(),
            crop_area: None,
            output_type: FrameType::BGRAFrame,
            output_resolution: Resolution::Captured, // 原始分辨率（与 windows-capture 一致）
            excluded_targets: None,
        };

        let mut capturer = Capturer::build(options)
            .map_err(|e| CaptureError::Capture(format!("scap::Capturer::build: {e}")))?;
        // 引擎就绪后必须显式 start（SCStream::start 才真正开始投递帧；
        // 否则 get_next_frame 会永远阻塞等待）。构造后即启动，与
        // windows-capture 后端在 new() 里就跑事件循环的契约一致。
        capturer.start_capture();
        tracing::info!(
            "Capture: selected zed-scap (ScreenCaptureKit) monitor_index={monitor_index}"
        );
        Ok(Self {
            capturer,
            monitor_index,
            last_size: (0, 0),
        })
    }

    /// 请求 Screen Recording 权限（供 UI/CLI 引导调用；本后端构造时不自弹窗）。
    pub fn request_permission() -> bool {
        if scap::has_permission() {
            return true;
        }
        scap::request_permission()
    }

    /// 按当前目标重建捕获器（显示器切换 / AccessLost 恢复）。
    ///
    /// 旧流先 stop，再经 [`Self::new`] 重建（build + start 一步完成）。
    fn rebuild(&mut self, monitor_index: usize) -> Result<(), CaptureError> {
        self.capturer.stop_capture();
        let rebuilt = Self::new(monitor_index)?;
        *self = rebuilt;
        Ok(())
    }
}

impl ScreenCaptureSource for ZedScapBackend {
    fn wait_for_frame(&mut self) -> Result<CaptureFrame, CaptureError> {
        // 阻塞等待引擎投递帧（与 windows-capture 的通道阻塞语义一致）。
        let frame = self
            .capturer
            .get_next_frame()
            .map_err(|e| CaptureError::Capture(format!("scap::get_next_frame: {e}")))?;

        let (data, width, height) = match frame {
            Frame::BGRA(f) => {
                let w = f.width.max(0) as u32;
                let h = f.height.max(0) as u32;
                (bgra_to_rgba(&f.data), w, h)
            }
            other => {
                return Err(CaptureError::Capture(format!(
                    "unexpected zed-scap frame type: {other:?} (expect BGRAFrame)"
                )));
            }
        };
        if width == 0 || height == 0 {
            return Err(CaptureError::Capture(
                "zed-scap frame has zero dimensions".into(),
            ));
        }
        self.last_size = (width, height);

        Ok(CaptureFrame::ZedScap(ZedScapFrame {
            data,
            width,
            height,
            dirty_rects: Vec::new(), // zed-scap 无脏区信息（上游 diff 层兜底）
            timestamp: Instant::now(),
        }))
    }

    fn resolution(&self) -> (u32, u32) {
        // zed-scap 引擎的输出尺寸查询需 &mut（get_output_frame_size），且
        // ScreenCaptureKit 首帧前可能未就绪 → 以最近一帧实际尺寸为准。
        self.last_size
    }

    fn monitor_info(&self) -> &[MonitorInfo] {
        // 显示器列表在 factory::list_monitors 提供；本后端不缓存（切显示器经
        // switch_monitor 重建），返回空列表避免与 factory 重复。
        &[]
    }

    fn switch_monitor(&mut self, index: usize) -> Result<(), CaptureError> {
        self.rebuild(index)?;
        self.monitor_index = index;
        Ok(())
    }

    fn recreate(&mut self) -> Result<(), CaptureError> {
        self.rebuild(self.monitor_index)
    }
}

/// BGRA → RGBA（交换 R/B 通道；`data` 必须为 4 字节/像素的整数倍）。
///
/// windows-capture 后端输出 `Rgba8`，编码层按 `AV_PIX_FMT_RGBA` 做 swscale；
/// zed-scap 原生输出 BGRA，这里对齐后再进入统一管线（SRV-CAP-MAC-003）。
fn bgra_to_rgba(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for px in data.chunks_exact(4) {
        out.push(px[2]); // R
        out.push(px[1]); // G
        out.push(px[0]); // B
        out.push(px[3]); // A
    }
    out
}

/// 枚举所有显示器（zed-scap targets 中过滤 Display）。
///
/// ScreenCaptureKit 的 `Display` 不含尺寸字段（macOS 分支），宽高暂置 0，
/// 由首帧实际分辨率填充（`wait_for_frame` 后调用 `resolution()` 为准）。
pub fn enumerate_monitors() -> Result<Vec<MonitorInfo>, CaptureError> {
    if !scap::has_permission() {
        return Err(CaptureError::Capture(
            "macOS screen recording permission not granted".into(),
        ));
    }
    let targets = scap::get_all_targets()
        .map_err(|e| CaptureError::Capture(format!("scap::get_all_targets: {e}")))?;
    let mut out = Vec::new();
    for (i, t) in targets.iter().enumerate() {
        if let Target::Display(d) = t {
            out.push(MonitorInfo {
                id: i,
                name: d.title.clone(),
                width: 0,
                height: 0,
                is_primary: i == 0, // ScreenCaptureKit 首个 display 为主显示器
            });
        }
    }
    if out.is_empty() {
        return Err(CaptureError::NoMonitor);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BGRA→RGBA 通道交换正确（纯函数，Windows 主机也能跑）。
    #[test]
    fn test_bgra_to_rgba_swap() {
        // BGRA: B=10 G=20 R=30 A=255 → RGBA: 30,20,10,255。
        let bgra = vec![10u8, 20, 30, 255, 1, 2, 3, 4];
        let rgba = bgra_to_rgba(&bgra);
        assert_eq!(rgba, vec![30, 20, 10, 255, 3, 2, 1, 4]);
    }

    /// 非 4 字节整倍数的尾部被丢弃（防御：chunks_exact 语义）。
    #[test]
    fn test_bgra_to_rgba_trailing_dropped() {
        let bgra = vec![1u8, 2, 3, 4, 5];
        let rgba = bgra_to_rgba(&bgra);
        assert_eq!(rgba.len(), 4);
    }

    /// 空输入 → 空输出。
    #[test]
    fn test_bgra_to_rgba_empty() {
        assert!(bgra_to_rgba(&[]).is_empty());
    }
}
