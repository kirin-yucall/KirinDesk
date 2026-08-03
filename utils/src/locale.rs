//! 系统 UI 语言识别（`[ui].language = "system"` 时使用）。
//!
//! M8-T038 (P2): Windows 桌面通常不导出 `LANG` 环境变量，`Lang::from_env()`
//! 会永远回落中文基线——需经系统 API 取用户 UI 语言。

/// 系统 UI 语言代码（仅区分本项目支持的语言）：`"zh"` | `"en"` | None。
///
/// - Windows: `GetUserDefaultUILanguage` → LANGID 主语言（zh=0x04, en=0x09）；
///   失败（返回 0 = LANG_NEUTRAL）退化为 None；其余语言 → None（暂回中文基线，
///   与「主动选择仅中/英」范围一致）。
/// - 非 Windows：None（上层回落环境变量 → zh 基线；macOS 后续批次可补）。
#[cfg(windows)]
pub fn system_language_code() -> Option<&'static str> {
    use windows::Win32::Globalization::GetUserDefaultUILanguage;
    let lid = unsafe { GetUserDefaultUILanguage() };
    let primary = (lid & 0x3ff) as u16; // PRIMARYLANGID
    match primary {
        0x04 => Some("zh"), // LANG_CHINESE
        0x09 => Some("en"), // LANG_ENGLISH
        _ => None,
    }
}

#[cfg(not(windows))]
pub fn system_language_code() -> Option<&'static str> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_panics_and_returns_known_set() {
        // 返回值必须是 None/"zh"/"en" 三者之一（不 panic 为主断言；
        // 具体值依赖运行环境，不做强断言）。
        let v = system_language_code();
        assert!(matches!(v, None | Some("zh") | Some("en")));
    }
}
