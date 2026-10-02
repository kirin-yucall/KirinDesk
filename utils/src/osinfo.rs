//! R-137-10b（甲方第五轮复测第 14 项③，PM 裁定授权扩沿）：本机 OS 类型
//! 枚举 + 探测。
//!
//! 用途：握手 `HandshakeInit.client_os` / `HandshakeResponse.server_os`
//! 尾部追加可选字段的数据源（core 侧消费），落库 `SavedDevice.os_type`
//! （UI 侧设备页/连接下拉类型徽标位优先展示）。
//!
//! **枚举收敛为常量集**（PM 要求）——仅下列精确值合法；探测失败/不支持
//! 平台 → 空串（未知）。UI 展示层对**空/未知值一律回退既有 server/desktop
//! 角色徽标，不猜**（回退矩阵见 `ui::device_type_badge`）。

/// Windows 11（`CurrentBuildNumber ≥ 22000`）。
pub const OS_WINDOWS_11: &str = "windows-11";
/// Windows 10（`CurrentBuildNumber < 22000`）。
pub const OS_WINDOWS_10: &str = "windows-10";
/// Windows（注册表读取失败等无法细分 10/11 时的兜底精确值）。
pub const OS_WINDOWS: &str = "windows";
/// macOS。
pub const OS_MACOS: &str = "macos";
/// Linux。
pub const OS_LINUX: &str = "linux";

/// 合法枚举全集（常量集单点——新增枚举值只在此处 + 本模块探测分支落位）。
pub const KNOWN_OS_TYPES: &[&str] =
    &[OS_WINDOWS_11, OS_WINDOWS_10, OS_WINDOWS, OS_MACOS, OS_LINUX];

/// 精确成员判定（大小写敏感——wire 值只认常量集精确串，不猜）。
pub fn is_known_os_type(v: &str) -> bool {
    KNOWN_OS_TYPES.contains(&v)
}

/// 探测本机 OS 类型（返回 [`KNOWN_OS_TYPES`] 成员；不支持平台/探测失败 →
/// 空串 = 未知，UI 侧回退角色徽标）。
///
/// Windows 细分 10/11：读 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
/// 的 `CurrentBuildNumber`（Win8+ 在案的 REG_SZ/u32 值）——
/// `≥ 22000` = Windows 11 首个内部构建线（22000 = 21H2/Win11 起始），
/// 否则 Windows 10；键/值读取失败 → 仍知是 Windows → 兜底 `windows`
/// （不猜具体版本）。
pub fn detect_os_type() -> String {
    #[cfg(target_os = "windows")]
    {
        return windows_build().unwrap_or_else(|| OS_WINDOWS.to_string());
    }
    #[cfg(target_os = "macos")]
    {
        return OS_MACOS.to_string();
    }
    #[cfg(target_os = "linux")]
    {
        return OS_LINUX.to_string();
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        // 其他平台（本仓无构建目标）= 未知，不猜。
        String::new()
    }
}

/// Windows 构建号细分（10/11）；任何读取失败 → `None`（调用方兜底
/// `OS_WINDOWS`）。
#[cfg(target_os = "windows")]
fn windows_build() -> Option<String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    const NT_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    const BUILD_VALUE: &str = "CurrentBuildNumber";
    let build: u32 = {
        let hk = RegKey::predef(HKEY_LOCAL_MACHINE);
        let nt = hk
            .open_subkey_with_flags(NT_KEY, KEY_READ)
            .ok()?;
        // Win8+ 为 REG_SZ；个别镜像为 REG_DWORD——两形态都收。
        match nt.get_value(BUILD_VALUE) {
            Ok(v) => v,
            Err(_) => {
                let s: String = nt.get_value(BUILD_VALUE).ok()?;
                s.trim().parse().ok()?
            }
        }
    };
    Some(if build >= 22000 {
        OS_WINDOWS_11.to_string()
    } else {
        OS_WINDOWS_10.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 常量集成员判定矩阵（PM 要求「枚举收敛为常量集、未知值回退不猜」的
    /// 数据层钉死）：5 个精确值命中；空串/近形值/大小写变体一律不命中。
    #[test]
    fn known_os_type_matrix() {
        for v in KNOWN_OS_TYPES {
            assert!(is_known_os_type(v), "constant set member must hit: {v}");
        }
        for v in ["", "windows-95", "win11", "Windows 11", "WINDOWS-11", "macos-14", "Linux"] {
            assert!(!is_known_os_type(v), "unknown/near-miss value must not hit: {v}");
        }
    }

    /// 探测函数自洽：返回值 ∈ 常量集 ∪ {""}（不产常量集外值）。
    #[test]
    fn detect_returns_known_or_empty() {
        let v = detect_os_type();
        assert!(
            v.is_empty() || is_known_os_type(&v),
            "detect_os_type must return a constant-set member or empty, got {v:?}"
        );
    }

    /// 本环境（Windows 构建线）= 10/11 精确值（构建号探测链在案）。
    #[cfg(target_os = "windows")]
    #[test]
    fn detect_on_windows_is_10_or_11() {
        let v = detect_os_type();
        assert!(
            v == OS_WINDOWS_10 || v == OS_WINDOWS_11,
            "this host (Win10/11 build line) must resolve to a precise value, got {v:?}"
        );
    }
}
