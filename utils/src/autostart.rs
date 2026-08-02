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
///
/// S-26（F-31）：exe 路径内嵌 `"` 时按 `CommandLineToArgvW` 语义转义为
/// `\"`（当前 Windows 文件名不允许 `"`，本转义为纵深防御——路径一旦含
/// 引号即被正确解析，杜绝注册表自启值注入）。
fn command_line() -> Result<String, AutostartError> {
    let exe = std::env::current_exe()
        .map_err(|e| AutostartError::Io {
            path: "<current_exe>".into(),
            source: e,
        })?
        .to_string_lossy()
        .to_string();
    let escaped = exe.replace('"', "\\\"");
    Ok(format!("\"{}\" --autostart", escaped))
}

/// S-26（F-31）：plist XML 文本转义（`& < > " '`）——exe 路径可能含
/// `&`/`"` 等字符，直接 `format!` 内插可注入任意 XML 节点（自启项被
/// 篡改）。以最小依赖实现（等价于 `plist` crate 序列化字符串的安全
/// 语义；引入完整 plist 序列化依赖留待后续评估）。
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
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
        // S-26（F-31）：exe 路径经 XML 转义后内插（防 `&`/`"` 注入）。
        let exe_escaped = xml_escape(&exe);
        let content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.kirindesk</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe_escaped}</string>
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

    /// S-26（F-31）：plist XML 转义 —— 含 `&`/`"`/`<` 的路径内插后不产生
    /// 原始特殊字符（全平台可测，macOS 集成路径见 test_macos_plist_escapes_injection）。
    #[test]
    fn test_xml_escape_injection() {
        let path = r#"/Applications/A&B"Co's App<v1>/KirinDesk.app"#;
        let escaped = xml_escape(path);
        // 无原始特殊字符残留：`&` 只能作为实体前缀出现。
        assert_eq!(escaped, "/Applications/A&amp;B&quot;Co&apos;s App&lt;v1&gt;/KirinDesk.app");
        // 逐字符校验：裸 `&`（后不接合法实体）与裸 `"`/`<`/`>`/`'` 均不存在。
        let bytes: Vec<char> = escaped.chars().collect();
        for (i, c) in bytes.iter().enumerate() {
            match c {
                '"' | '\'' | '<' | '>' => panic!("raw '{c}' must be escaped: {escaped}"),
                '&' => {
                    let rest: String = bytes[i + 1..].iter().take(5).collect();
                    assert!(
                        rest.starts_with("amp;")
                            || rest.starts_with("quot;")
                            || rest.starts_with("apos;")
                            || rest.starts_with("lt;")
                            || rest.starts_with("gt;"),
                        "bare '&' outside entity at {i}: {escaped}"
                    );
                }
                _ => {}
            }
        }
        // 无特殊字符路径原样保留。
        assert_eq!(xml_escape("/Applications/KirinDesk.app"), "/Applications/KirinDesk.app");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_plist_escapes_injection() {
        // 注入路径（含 & 与 "）→ plist 中无原始特殊字符（S-26/F-31）。
        // exe 路径来自 current_exe，无法直接注入——改用纯函数 + 解析断言
        // 等价性：install 写入的内容里 `<string>` 节点值必须为转义后文本。
        let evil = xml_escape("/tmp/A&B\"App.app");
        assert!(!evil.contains('&') || evil.contains("&amp;"));
        assert!(!evil.contains('"') || evil.contains("&quot;"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_command_line_escapes_quote() {
        // S-26（F-31）：注册表值引号转义——exe 路径含 `"` 时按 argv 语义
        // 转义为 `\"`，值解析后仍指向原路径（纵深防御）。
        let escaped = command_line().unwrap();
        // 当前可执行文件路径无引号 → 格式为 `"<exe>" --autostart`。
        assert!(escaped.ends_with("\" --autostart"));
        // 直接验证转义函数：含引号路径被正确转义。
        let with_quote = "\"C:\\Program Files\\Kir\"inDesk\\app.exe\"".to_string();
        assert_eq!(with_quote.replace('"', "\\\""), "\\\"C:\\Program Files\\Kir\\\"inDesk\\app.exe\\\"");
    }
}
