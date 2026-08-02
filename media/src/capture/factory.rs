//! 工厂函数 — 根据平台自动选择捕获源。
//!
//! - Windows: `windows-capture` crate 唯一后端（M8-T008 §Step 1，无回退链）。
//! - macOS: `zed-scap` crate（ScreenCaptureKit，M12-MAC MAC-T001）。
//! - Linux: zed-scap（M12 落地，见 远控服务端_需求文档 §3.2.2）。

use crate::capture::{CaptureError, MonitorInfo, ScreenCaptureSource};
use crate::proto::DisplayInfo;

/// 根据目标平台自动选择捕获源。
///
/// - Windows: windows-capture（唯一后端）
/// - macOS: zed-scap（ScreenCaptureKit；无 Screen Recording 权限时返回
///   `Capture` 错误，由 UI/CLI 调 `zed_scap::ZedScapBackend::request_permission()`
///   引导授权）
/// - Linux: TODO(M12) zed-scap
#[allow(unused_variables)]
pub fn create_capture_source(
    monitor_index: usize,
) -> Result<Box<dyn ScreenCaptureSource>, CaptureError> {
    #[cfg(target_os = "windows")]
    {
        let cap = crate::capture::windows_capture::WindowsCaptureBackend::new(monitor_index)?;
        tracing::info!("Capture: selected windows-capture crate");
        Ok(Box::new(cap))
    }

    #[cfg(target_os = "macos")]
    {
        let cap = crate::capture::zed_scap::ZedScapBackend::new(monitor_index)?;
        tracing::info!("Capture: selected zed-scap (ScreenCaptureKit)");
        Ok(Box::new(cap))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        // TODO(M12): zed-scap 后端（Linux），见 远控服务端_需求文档 §3.2.2
        Err(CaptureError::Capture(
            "capture on this platform requires zed-scap (M12, see task_docs)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `MonitorInfo` → `DisplayInfo` 纯映射（主屏标记 / 索引 / 分辨率保真）。
    #[test]
    fn test_monitor_to_display_mapping() {
        let m = MonitorInfo {
            id: 1,
            name: "\\\\.\\DISPLAY2".into(),
            width: 2560,
            height: 1440,
            is_primary: false,
        };
        let d = monitor_to_display(&m);
        assert_eq!(d.index, 1);
        assert_eq!(d.name, "\\\\.\\DISPLAY2");
        assert_eq!(d.width, 2560);
        assert_eq!(d.height, 1440);
        assert!(!d.is_primary);
    }

    /// 兜底默认屏（无显示器环境 → 单屏列表非空，客户端下拉恒可用）。
    #[test]
    fn test_default_display_info() {
        let d = default_display_info();
        assert_eq!(d.index, 0);
        assert!(d.is_primary);
        assert!(d.width > 0 && d.height > 0);
    }
}

/// 枚举所有可用显示器。
pub fn list_monitors() -> Result<Vec<MonitorInfo>, CaptureError> {
    #[cfg(target_os = "windows")]
    {
        crate::capture::windows_capture::enumerate_monitors()
    }

    #[cfg(target_os = "macos")]
    {
        crate::capture::zed_scap::enumerate_monitors()
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Err(CaptureError::NoMonitor)
    }
}

/// M8-T018（SRV-CAP-MON-001）：枚举显示器为 wire 格式（`DisplayListResp` 负载）。
///
/// 遍历平台枚举结果（Windows `Monitor::from_index` 体系 / macOS zed-scap 列表）；
/// 枚举失败或为空 → 上报 1 个默认屏（index 0，1920x1080 主屏）兜底，不报错——
/// 客户端下拉始终可用（单屏被控端即"1 项"）。
pub fn enumerate_monitors() -> Vec<DisplayInfo> {
    let monitors = match list_monitors() {
        Ok(m) if !m.is_empty() => m,
        _ => {
            tracing::warn!(
                "enumerate_monitors: no monitor enumerated — reporting 1 default screen"
            );
            return vec![default_display_info()];
        }
    };
    monitors.iter().map(monitor_to_display).collect()
}

/// `MonitorInfo` → wire `DisplayInfo`（纯映射，便于单测）。
pub fn monitor_to_display(m: &MonitorInfo) -> DisplayInfo {
    DisplayInfo {
        index: m.id as u32,
        name: m.name.clone(),
        width: m.width,
        height: m.height,
        is_primary: m.is_primary,
    }
}

/// 枚举兜底：1 个默认屏（无显示器环境/枚举失败时保证列表非空）。
pub fn default_display_info() -> DisplayInfo {
    DisplayInfo {
        index: 0,
        name: "Default".into(),
        width: 1920,
        height: 1080,
        is_primary: true,
    }
}
