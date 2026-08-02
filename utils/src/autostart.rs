//! M13-T005: 用户级开机自启（Unattended Mode 子能力）
//!
//! 三平台统一接口 `install()` / `uninstall()` / `is_installed()`，全部为
//! **用户级**机制（无需管理员权限）：
//!
//! | 平台    | 机制                     | 落点                                  |
//! |---------|--------------------------|---------------------------------------|
//! | Windows | HKCU Run 注册表键        | `HKCU\...\CurrentVersion\Run`（值 `KirinDesk`） |
//! | Linux   | XDG autostart            | `$XDG_CONFIG_HOME/autostart/kirindesk.desktop`  |
//! | macOS   | LaunchAgent              | `~/Library/LaunchAgents/com.kirindesk.plist`    |
//!
//! 所有路径经 `dirs_next` 解析（遵循 M1-T002 路径解析策略，不写死 `~`）。
//! 自启拉起时统一追加 `--autostart` 参数（UA-BOOT-004）。

use std::io;
use std::path::PathBuf;

/// 自启注册错误。
#[derive(Debug, thiserror::Error)]
pub enum AutostartError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: io::Error,
    },
    #[error("Windows registry error: {0}")]
    Registry(String),
    #[error("Unsupported platform for autostart")]
    UnsupportedPlatform,
}

/// 自启命令统一格式：`"<当前可执行文件>" --autostart`
fn command_line() -> Result<String, AutostartError> {
    let exe = std::env::current_exe()
        .map_err(|e| AutostartError::Io {
            path: "<current_exe>".into(),
            source: e,
        })?
        .to_string_lossy()
        .to_string();
    Ok(format!("\"{}\" --autostart", exe))
}

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const VALUE_NAME: &str = "KirinDesk";

    fn run_key() -> Result<RegKey, AutostartError> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_WRITE)
            .map_err(|e| AutostartError::Registry(e.to_string()))
    }

    pub fn install() -> Result<(), AutostartError> {
        let key = run_key()?;
        key.set_value(VALUE_NAME, &command_line()?)
            .map_err(|e| AutostartError::Registry(e.to_string()))
    }

    pub fn uninstall() -> Result<(), AutostartError> {
        let key = run_key()?;
        // 幂等：值不存在时视为已移除
        match key.delete_value(VALUE_NAME) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AutostartError::Registry(e.to_string())),
        }
    }

    pub fn is_installed() -> bool {
        run_key()
            .and_then(|key| {
                key.get_value::<String, _>(VALUE_NAME)
                    .map_err(|e| AutostartError::Registry(e.to_string()))
            })
            .map(|v| v.contains("--autostart"))
            .unwrap_or(false)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    /// `$XDG_CONFIG_HOME/autostart/kirindesk.desktop`（缺省 `~/.config/autostart/`）
    pub fn desktop_file() -> PathBuf {
        dirs_next::config_dir()
            .unwrap_or_else(|| PathBuf::from(".config"))
            .join("autostart")
            .join("kirindesk.desktop")
    }

    pub fn install() -> Result<(), AutostartError> {
        let path = desktop_file();
        let content = format!(
            "[Desktop Entry]\nType=Application\nName=KirinDesk\nComment=KirinDesk remote desktop (unattended)\nExec={}\nX-GNOME-Autostart-enabled=true\n",
            command_line()?
        );
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AutostartError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        std::fs::write(&path, content).map_err(|e| AutostartError::Io {
            path: path.clone(),
            source: e,
        })
    }

    pub fn uninstall() -> Result<(), AutostartError> {
        let path = desktop_file();
        match std::fs::remove_file(&path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AutostartError::Io {
                path: path.clone(),
                source: e,
            }),
        }
    }

    pub fn is_installed() -> bool {
        desktop_file().is_file()
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    /// `~/Library/LaunchAgents/com.kirindesk.plist`
    pub fn plist_file() -> PathBuf {
        dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library")
            .join("LaunchAgents")
            .join("com.kirindesk.plist")
    }

    pub fn install() -> Result<(), AutostartError> {
        let path = plist_file();
        // 拆出可执行文件与参数，写入 plist ProgramArguments
        let exe = std::env::current_exe()
            .map_err(|e| AutostartError::Io {
                path: "<current_exe>".into(),
                source: e,
            })?
            .to_string_lossy()
            .to_string();
        let content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.kirindesk</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>--autostart</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#
        );
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AutostartError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        std::fs::write(&path, content).map_err(|e| AutostartError::Io {
            path: path.clone(),
            source: e,
        })
    }

    pub fn uninstall() -> Result<(), AutostartError> {
        let path = plist_file();
        match std::fs::remove_file(&path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AutostartError::Io {
                path: path.clone(),
                source: e,
            }),
        }
    }

    pub fn is_installed() -> bool {
        plist_file().is_file()
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod imp {
    use super::*;
    pub fn install() -> Result<(), AutostartError> {
        Err(AutostartError::UnsupportedPlatform)
    }
    pub fn uninstall() -> Result<(), AutostartError> {
        Err(AutostartError::UnsupportedPlatform)
    }
    pub fn is_installed() -> bool {
        false
    }
}

/// 注册用户级开机自启（UA-BOOT-001）。幂等：已注册时重复调用直接成功。
pub fn install() -> Result<(), AutostartError> {
    imp::install()
}

/// 移除开机自启（UA-BOOT-001）。幂等：未注册时调用直接成功。
pub fn uninstall() -> Result<(), AutostartError> {
    imp::uninstall()
}

/// 检测开机自启是否已注册（UA-BOOT-002）。以系统实际状态为准。
pub fn is_installed() -> bool {
    imp::is_installed()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 自启 install → is_installed → uninstall 往返（各平台走各自机制）。
    /// 清理保证幂等：无论成功与否，测试结束后自启均被移除。
    #[test]
    fn test_autostart_roundtrip() {
        let _ = uninstall(); // 清理现场
        assert!(!is_installed(), "autostart should not be installed initially");

        install().expect("install should succeed");
        assert!(is_installed(), "autostart should be installed after install()");

        // 重复 install 幂等
        install().expect("re-install should succeed");
        assert!(is_installed());

        uninstall().expect("uninstall should succeed");
        assert!(!is_installed(), "autostart should be removed after uninstall()");

        // 重复 uninstall 幂等
        uninstall().expect("re-uninstall should succeed");
        assert!(!is_installed());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_desktop_file_content() {
        let _ = uninstall();
        install().unwrap();
        let content = std::fs::read_to_string(imp::desktop_file()).unwrap();
        assert!(content.contains("[Desktop Entry]"));
        assert!(content.contains("Exec="));
        assert!(content.contains("--autostart"));
        let _ = uninstall();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_plist_content() {
        let _ = uninstall();
        install().unwrap();
        let content = std::fs::read_to_string(imp::plist_file()).unwrap();
        assert!(content.contains("com.kirindesk"));
        assert!(content.contains("<key>RunAtLoad</key>"));
        assert!(content.contains("--autostart"));
        let _ = uninstall();
    }
}
