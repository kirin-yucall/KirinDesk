//! M8-T031: 系统设备 ID 派生 —— 身份 `[device] id` 留空时用系统稳定标识
//! 自动生成（Windows 系统盘卷序列号 / Linux machine-id / macOS IOPlatformUUID），
//! 同一卷/系统内稳定；全部失败兜底主机名，再兜底 `kirindesk-local`。
//!
//! | 平台 | 来源 | 格式 | 降级链 |
//! |---|---|---|---|
//! | Windows | kernel32 `GetVolumeInformationW`（dlopen）取系统盘卷序列号 | `HD-XXXXXXXX`（8 位大写 HEX） | 失败 → 主机名 |
//! | Linux | `/etc/machine-id` | `MACHINE-<前 32 位>` | 失败 → 主机名 |
//! | macOS | `ioreg -rd1 -c IOPlatformExpertDevice` 解析 `IOPlatformUUID` | `MAC-<前 36 位>` | 失败 → 主机名 |
//! | 兜底 | 主机名（COMPUTERNAME / HOSTNAME） | 原样 | `kirindesk-local` |

/// `[device] id` 是否应视为"未填写"（留空即自动；`default-device` 为旧版
/// 占位符，视为未填写，M8-T031）。
pub fn id_is_auto(id: &str) -> bool {
    let id = id.trim();
    id.is_empty() || id == "default-device"
}

/// 解析生效设备 ID：`id_is_auto` → 系统自动派生；否则**原样**返回显式值。
pub fn effective_device_id(configured: &str) -> String {
    if id_is_auto(configured) {
        system_device_id()
    } else {
        configured.to_string()
    }
}

/// 系统稳定设备 ID（平台分派；永不返回空串）。
pub fn system_device_id() -> String {
    #[cfg(target_os = "windows")]
    {
        imp::system_device_id()
    }
    #[cfg(target_os = "linux")]
    {
        imp::system_device_id()
    }
    #[cfg(target_os = "macos")]
    {
        imp::system_device_id()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        fallback_hostname()
    }
}

/// 主机名兜底（Windows COMPUTERNAME / 其余 HOSTNAME；均空 → `kirindesk-local`）。
fn fallback_hostname() -> String {
    #[cfg(target_os = "windows")]
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    #[cfg(not(target_os = "windows"))]
    let host = {
        let from_env = std::env::var("HOSTNAME").unwrap_or_default();
        if from_env.is_empty() {
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        } else {
            from_env
        }
    };
    if host.is_empty() {
        "kirindesk-local".to_string()
    } else {
        host
    }
}

// ════════════════════════════════════════════════════════════════
// 平台实现
// ════════════════════════════════════════════════════════════════

/// Windows：kernel32 `GetVolumeInformationW`（dlopen，仿
/// `core/src/crypto/windows_dpapi.rs` 的 `DpapiDlls` 模式，Library 保活），
/// 取系统盘（`SystemDrive` → `C:` → home 盘）卷序列号 → `HD-XXXXXXXX`。
#[cfg(target_os = "windows")]
mod imp {
    use super::fallback_hostname;
    use libloading::{Library, Symbol};
    use std::os::windows::ffi::OsStrExt;
    use std::sync::OnceLock;

    /// `GetVolumeInformationW` 签名（kernel32，Windows SDK 头文件）。
    type GetVolumeInformationWFn = unsafe extern "system" fn(
        root_path: *const u16,
        volume_name: *mut u16,
        volume_name_size: u32,
        serial_number: *mut u32,
        max_component_len: *mut u32,
        file_system_flags: *mut u32,
        file_system_name: *mut u16,
        file_system_name_size: u32,
    ) -> i32;

    /// 已解析的 kernel32 函数表（Library 句柄保活，进程生命周期内不卸载）。
    struct Kernel32Dlls {
        _kernel32: Library,
        get_volume_information: GetVolumeInformationWFn,
    }

    static K32: OnceLock<Result<Kernel32Dlls, String>> = OnceLock::new();

    impl Kernel32Dlls {
        fn get() -> Option<&'static Kernel32Dlls> {
            K32.get_or_init(Self::load).as_ref().ok()
        }

        fn load() -> Result<Self, String> {
            // SAFETY: 系统固定路径 DLL；加载后仅解析符号（与 DpapiDlls 同模式）。
            let kernel32 = unsafe { Library::new("kernel32.dll") }
                .map_err(|e| format!("dlopen kernel32.dll: {e}"))?;

            macro_rules! sym {
                ($lib:expr, $name:literal, $ty:ty) => {
                    // SAFETY: 符号名与类型来自 Windows SDK 头文件。
                    unsafe { $lib.get::<$ty>($name.as_bytes()) }
                        .map(|s: Symbol<'_, $ty>| *s)
                        .map_err(|e| format!("symbol '{}': {e}", $name))?
                        as $ty
                };
            }

            Ok(Self {
                get_volume_information: sym!(
                    &kernel32,
                    "GetVolumeInformationW",
                    GetVolumeInformationWFn
                ),
                _kernel32: kernel32,
            })
        }
    }

    /// 系统盘 root（`GetVolumeInformationW` 需要 `C:\` 形式）。
    fn system_root() -> String {
        if let Ok(sd) = std::env::var("SystemDrive") {
            let sd = sd.trim_end_matches('\\');
            if !sd.is_empty() {
                return sd.to_string();
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let drive: String = home.chars().take(2).collect();
            if drive.ends_with(':') {
                return drive;
            }
        }
        "C:".to_string()
    }

    /// 取卷序列号（失败 → None，走主机名兜底）。
    fn volume_serial(root: &str) -> Option<u32> {
        let dlls = Kernel32Dlls::get()?;
        let root = format!("{}\\", root.trim_end_matches('\\'));
        let root_wide: Vec<u16> = std::ffi::OsStr::new(&root)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut serial: u32 = 0;
        let mut max_component: u32 = 0;
        let mut fs_flags: u32 = 0;
        let mut volume_name = vec![0u16; 260];
        let mut fs_name = vec![0u16; 260];
        // SAFETY: root_wide NUL 结尾；缓冲区长度与大小参数一致。
        let ok = unsafe {
            (dlls.get_volume_information)(
                root_wide.as_ptr(),
                volume_name.as_mut_ptr(),
                volume_name.len() as u32,
                &mut serial,
                &mut max_component,
                &mut fs_flags,
                fs_name.as_mut_ptr(),
                fs_name.len() as u32,
            )
        };
        (ok != 0).then_some(serial)
    }

    pub(super) fn system_device_id() -> String {
        let root = system_root();
        if let Some(serial) = volume_serial(&root) {
            return format!("HD-{serial:08X}");
        }
        tracing::warn!(
            target: "device",
            "GetVolumeInformationW failed for root {root:?}; falling back to hostname"
        );
        fallback_hostname()
    }
}

/// Linux：`/etc/machine-id` 前 32 位 → `MACHINE-<32>`；失败 → 主机名。
#[cfg(target_os = "linux")]
mod imp {
    use super::fallback_hostname;

    pub(super) fn system_device_id() -> String {
        if let Ok(content) = std::fs::read_to_string("/etc/machine-id") {
            let id = content.trim();
            if !id.is_empty() {
                let first32: String = id.chars().take(32).collect();
                return format!("MACHINE-{first32}");
            }
        }
        tracing::warn!(target: "device", "cannot read /etc/machine-id; falling back to hostname");
        fallback_hostname()
    }
}

/// macOS：`ioreg -rd1 -c IOPlatformExpertDevice` 解析 `IOPlatformUUID` →
/// `MAC-<36>`；失败 → 主机名。
#[cfg(target_os = "macos")]
mod imp {
    use super::fallback_hostname;

    /// 从 ioreg 输出中解析 `"IOPlatformUUID" = "XXXX-...-XXXX"`。
    fn parse_io_platform_uuid(output: &str) -> Option<String> {
        for line in output.lines() {
            let line = line.trim();
            let Some(idx) = line.find("IOPlatformUUID") else {
                continue;
            };
            let rest = &line[idx + "IOPlatformUUID".len()..];
            let Some(eq) = rest.find('=') else {
                continue;
            };
            let value = rest[eq + 1..].trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        None
    }

    pub(super) fn system_device_id() -> String {
        if let Ok(out) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(uuid) = parse_io_platform_uuid(&text) {
                let first36: String = uuid.chars().take(36).collect();
                return format!("MAC-{first36}");
            }
        }
        tracing::warn!(target: "device", "cannot read IOPlatformUUID via ioreg; falling back to hostname");
        fallback_hostname()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_is_auto() {
        assert!(id_is_auto(""));
        assert!(id_is_auto("default-device"));
        assert!(id_is_auto("  "));
        assert!(!id_is_auto("my-pc"));
        assert!(!id_is_auto("HD-1234ABCD"));
    }

    #[test]
    fn test_effective_device_id_explicit_preserved() {
        assert_eq!(effective_device_id("my-pc"), "my-pc");
        assert_eq!(effective_device_id("HD-1234ABCD"), "HD-1234ABCD");
    }

    #[test]
    fn test_effective_device_id_auto_non_empty_and_deterministic() {
        let a = effective_device_id("");
        assert!(!a.is_empty(), "auto device id must never be empty");
        let b = effective_device_id("");
        assert_eq!(a, b, "auto device id must be deterministic within a process");
        // 旧占位符视为未填写 → 同样走自动
        assert_eq!(effective_device_id("default-device"), a);
    }

    #[test]
    fn test_system_device_id_never_empty() {
        let id = system_device_id();
        assert!(!id.is_empty());
    }

    #[test]
    fn test_system_device_id_platform_prefix() {
        let id = system_device_id();
        #[cfg(target_os = "windows")]
        {
            // 成功路径 `HD-XXXXXXXX`（8 位大写 HEX）；失败兜底主机名（非空断言已覆盖）。
            if let Some(hex) = id.strip_prefix("HD-") {
                assert_eq!(hex.len(), 8, "expected HD-XXXXXXXX, got {id}");
                assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "not hex: {id}");
                assert_eq!(hex, hex.to_ascii_uppercase());
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(m) = id.strip_prefix("MACHINE-") {
                assert!(m.len() <= 32);
            }
        }
        #[cfg(target_os = "macos")]
        {
            if let Some(m) = id.strip_prefix("MAC-") {
                assert!(m.len() <= 36);
            }
        }
    }

    #[test]
    fn test_fallback_hostname_never_empty() {
        assert!(!fallback_hostname().is_empty());
    }
}
