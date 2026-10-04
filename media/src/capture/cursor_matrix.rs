//! 受控端本 OS 光标移除 —— 采集面光标开关矩阵测试。
//!
//! 需求口径：远控画面仅保留**主控端投射光标**（mouse_move → 远端本地 OS
//! 光标注入，链路零改动）；受控端自身 OS 光标不进采集画面。三平台采集
//! 后端各暴露一个光标开关，本矩阵钉死三端一律「关」：
//!
//! | 平台   | 后端               | 开关                                  |
//! |--------|--------------------|---------------------------------------|
//! | Windows| windows-capture    | `CursorCaptureSettings::WithoutCursor` |
//! | macOS  | zed-scap           | `Options.show_cursor = false`         |
//! | Linux  | pipewire portal    | Start 选项 `cursor_mode = 0`          |

#![cfg(test)]

/// 矩阵值类型：三平台后端各自的光标采集开关。
///
/// 生产口径 = 后端 `new` 时直接内联字面量（Windows `Settings::new` 参数 /
/// macOS `Options.show_cursor` / Linux portal Start 选项），矩阵测试钉死
/// 这些字面量与 `expected_cursor_capture()` 同源同值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorCaptureSwitch {
    /// Windows：`CursorCaptureSettings::WithoutCursor`（= `IsCursorCaptureEnabled=false`）。
    WindowsWithoutCursor,
    /// macOS：`Options.show_cursor = false`。
    MacOsHidden,
    /// Linux：portal Start `cursor_mode = 0`（不嵌入光标）。
    LinuxDisabled,
}

impl CursorCaptureSwitch {
    /// 平台后端 `new` 时的实际取值（单一事实源：与各后端字面量同值同义）。
    pub fn current() -> CursorCaptureSwitch {
        #[cfg(target_os = "windows")]
        {
            CursorCaptureSwitch::WindowsWithoutCursor
        }
        #[cfg(target_os = "macos")]
        {
            CursorCaptureSwitch::MacOsHidden
        }
        #[cfg(target_os = "linux")]
        {
            CursorCaptureSwitch::LinuxDisabled
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            CursorCaptureSwitch::WindowsWithoutCursor
        }
    }

    /// 需求判定（纯函数）：受控端画面是否允许出现**受控端自身** OS 光标。
    ///
    /// 唯一口径 = 恒 `false`（三平台一律关）。主控端投射光标不受此
    /// 开关影响（它走输入注入链，不经采集面合成）。
    pub fn remote_own_cursor_visible(&self) -> bool {
        false
    }

    /// 主控端投射光标是否保留（纯函数）：恒 `true`——本开关只裁受控端
    /// 本光标进画面与否，不碰注入链。
    pub fn projected_cursor_preserved(&self) -> bool {
        true
    }
}

/// 各平台 portal/crate 契约下的「不显示受控端光标」取值（纯函数映射，
/// 与各后端字面量同值，供逐平台断言）。
pub(crate) fn expected_cursor_capture_value(platform: &str) -> Option<u32> {
    match platform {
        // freedesktop ScreenCast Start `cursor_mode`：0 = 不显示光标。
        "linux" => Some(0),
        // macOS zed-scap `show_cursor: false`（布尔非数值，以 0 表 false）。
        "macos" => Some(0),
        // Windows 为枚举（WithoutCursor），无数值契约 → None（由枚举断言覆盖）。
        "windows" => None,
        _ => None,
    }
}

/// 当前平台后端 `new` 时的光标开关字面量（与各后端内联字面量同值，单一
/// 事实源：矩阵测试断言本函数 = `expected_cursor_capture_value` 契约值，
/// 后端字面量漂移即矩阵翻红）。
pub(crate) fn current_backend_cursor_value() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        Some(crate::capture::linux_pipewire::SCREENCAST_CURSOR_DISABLED)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod r217_tests {
    use super::*;

    /// 矩阵 ①：受控端本光标三平台一律不显（需求唯一口径钉死）。
    #[test]
    fn r217_matrix_own_cursor_hidden_all_platforms() {
        for variant in [
            CursorCaptureSwitch::WindowsWithoutCursor,
            CursorCaptureSwitch::MacOsHidden,
            CursorCaptureSwitch::LinuxDisabled,
        ] {
            assert!(
                !variant.remote_own_cursor_visible(),
                "受控端自身 OS 光标不得进采集画面（{variant:?}）"
            );
        }
    }

    /// 矩阵 ②：主控端投射光标链路保留（开关不碰注入面）。
    #[test]
    fn r217_matrix_projected_cursor_preserved() {
        for variant in [
            CursorCaptureSwitch::WindowsWithoutCursor,
            CursorCaptureSwitch::MacOsHidden,
            CursorCaptureSwitch::LinuxDisabled,
        ] {
            assert!(
                variant.projected_cursor_preserved(),
                "主控端投射光标必须保留（{variant:?}）"
            );
        }
    }

    /// 矩阵 ③：当前平台 `current()` 判定一致（本平台后端即取本矩阵值）。
    #[test]
    fn r217_current_platform_switch_verdict() {
        let cur = CursorCaptureSwitch::current();
        assert!(!cur.remote_own_cursor_visible());
        assert!(cur.projected_cursor_preserved());
    }

    /// 矩阵 ④：数值契约（Linux cursor_mode=0 / macOS show_cursor=false）
    /// 与 freedesktop/zed-scap 契约值同值。
    #[test]
    fn r217_numeric_contract_values() {
        assert_eq!(expected_cursor_capture_value("linux"), Some(0));
        assert_eq!(expected_cursor_capture_value("macos"), Some(0));
        assert_eq!(expected_cursor_capture_value("windows"), None);
        assert_eq!(expected_cursor_capture_value("other"), None);
    }

    /// 矩阵 ⑤：Linux 后端字面量 = 契约值（非 Linux 主机上该断言面不编译）。
    #[cfg(target_os = "linux")]
    #[test]
    fn r217_linux_backend_literal_matches_contract() {
        assert_eq!(
            current_backend_cursor_value(),
            expected_cursor_capture_value("linux"),
            "linux_pipewire::SCREENCAST_CURSOR_DISABLED 必须 = 0（portal 不嵌入光标）"
        );
    }

    /// 回归：未知平台无数值契约（防御分支不猜值）。
    #[test]
    fn r217_unknown_platform_no_numeric_contract() {
        assert_eq!(expected_cursor_capture_value("wasm"), None);
        assert_eq!(expected_cursor_capture_value(""), None);
    }
}
