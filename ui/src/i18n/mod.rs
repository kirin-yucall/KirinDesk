//! R-12 (M15-T007): 国际化基础设施（先行交付；文案抽取随 M8-T038 波次 2）。
//!
//! M8-T038 (P2): 键值表由单一 `TABLE` 拆为**按页面分区的静态表文件**
//! （`common/settings/connect/dashboard/devices/domain/session/widgets`），
//! 波次 2 各文案任务独占自己的分区文件 → 并发加键零冲突；
//! [`ALL`] 汇总并配重复键断言单测（撞车即测试失败）。
//!
//! # 使用方式
//!
//! ```ignore
//! use crate::t;
//! label.text(t!("settings.title"));
//! ```
//!
//! # 回退规则
//!
//! - 当前语言缺键 → 回退中文（zh 为基线语言包）；
//! - 中文也缺键 → 原样返回键名（**绝不 panic**，便于发现漏翻译）。
//!
//! # 语言选择
//!
//! - 默认跟随系统：环境变量（`LANG`/`LC_ALL`/`LC_MESSAGES`/`LANGUAGE`）优先；
//!   缺失时经 `kirin_desk_utils::locale::system_language_code()`（Windows
//!   `GetUserDefaultUILanguage`）；仍失败 → 中文基线（见 [`system`]）；
//! - 运行期 [`set_lang`] 即时切换（Settings 语言下拉，持久化到 `[ui].language`）；
//!   [`set_lang_code`] 按配置值（`"system"`/`"zh"`/`"en"`）设置；
//! - 进程级 [`CURRENT`] 原子状态。

use std::sync::atomic::{AtomicU8, Ordering};

mod common;
mod connect;
mod dashboard;
mod devices;
mod domain;
mod session;
mod settings;
mod tunnel;
mod widgets;

// R-33: Lang 转换接口与语言常量当前未被调用（M8-T038 语言选项固定中文基线，
// 语言切换/持久化接线时启用）——整组标注，避免 dead_code。
#[allow(dead_code)]
/// 中文语言代码。
pub const LANG_ZH: &str = "zh";
/// 英文语言代码。
pub const LANG_EN: &str = "en";

/// 支持的语言。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// 中文（基线语言包）。
    Zh,
    /// English.
    En,
}

impl Lang {
    /// BCP-47 语言代码（`"zh"` / `"en"`）。
    #[allow(dead_code)]
    pub fn code(self) -> &'static str {
        match self {
            Lang::Zh => LANG_ZH,
            Lang::En => LANG_EN,
        }
    }

    /// 由语言代码解析；`en*` → 英文，其余 → [`Lang::Zh`]（宽松前缀解析，
    /// 兼容 `"en-US"` 等变体；未知代码不报错）。
    #[allow(dead_code)]
    pub fn from_code(code: &str) -> Lang {
        let c = code.to_ascii_lowercase();
        if c == LANG_EN || c.starts_with("en-") {
            Lang::En
        } else {
            Lang::Zh
        }
    }

    /// 跟随系统默认语言（环境变量 `LANG`/`LC_ALL`/`LC_MESSAGES`/`LANGUAGE`，
    /// `zh*` → 中文，`en*` → 英文，其余/缺失 → 中文基线）。
    ///
    /// 注：GUI 场景个别平台（如 Windows 桌面）可能不导出 `LANG`，此时回落
    /// 中文基线——M8-T038 起上层优先经 [`system()`]（含系统 API 兜底）。
    #[allow(dead_code)]
    pub fn from_env() -> Lang {
        env_lang().unwrap_or(Lang::Zh)
    }
}

/// 环境变量语言命中（与 [`Lang::from_env`] 同判定，但区分「缺失」与「zh 命中」——
/// [`system()`] 需要：未命中才继续查系统 API）。
fn env_lang() -> Option<Lang> {
    for var in ["LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.to_ascii_lowercase();
            if v.starts_with("zh") {
                return Some(Lang::Zh);
            }
            if v.starts_with("en") {
                return Some(Lang::En);
            }
        }
    }
    None
}

/// 系统语言：环境变量（`LANG`/`LC_ALL`/`LC_MESSAGES`/`LANGUAGE`）优先；
/// 缺失时经 `kirin_desk_utils::locale::system_language_code()`（Windows
/// `GetUserDefaultUILanguage`）；仍失败 → 中文基线（不 panic）。
pub fn system() -> Lang {
    if let Some(lang) = env_lang() {
        return lang;
    }
    match kirin_desk_utils::locale::system_language_code() {
        Some("en") => Lang::En,
        Some("zh") => Lang::Zh,
        _ => Lang::Zh,
    }
}

/// 按配置值设置语言：`"system"` → [`system()`]；`"zh"`/`"en"` → 显式；
/// 未知值 → [`system()`] 兜底（不 panic）。
pub fn set_lang_code(code: &str) {
    let lang = match code {
        "zh" => Lang::Zh,
        "en" => Lang::En,
        // "system" 与未知值（含旧配置脏值）→ 跟随系统兜底，不 panic。
        _ => system(),
    };
    set_lang(lang);
}

/// 当前语言（进程级；UI 线程 [`set_lang`] 即时生效）。0 = Zh，1 = En。
static CURRENT: AtomicU8 = AtomicU8::new(0);

/// 当前语言。
pub fn current() -> Lang {
    if CURRENT.load(Ordering::Relaxed) == 1 {
        Lang::En
    } else {
        Lang::Zh
    }
}

/// 切换当前语言（立即生效；持久化由 Settings 语言选项完成）。
pub fn set_lang(lang: Lang) {
    CURRENT.store(if lang == Lang::En { 1 } else { 0 }, Ordering::Relaxed);
}

/// 全部分区表（查找顺序 = 数组顺序；common 最前——公共键优先命中）。
pub static ALL: &[&[(&str, &str, &str)]] = &[
    common::TABLE,
    settings::TABLE,
    connect::TABLE,
    dashboard::TABLE,
    devices::TABLE,
    domain::TABLE,
    session::TABLE,
    tunnel::TABLE,
    widgets::TABLE,
];

/// 按当前语言取文案；缺键回退中文，再缺原样返回键名（不 panic）。
pub fn tr(key: &'static str) -> &'static str {
    tr_lang(current(), key)
}

/// 按指定语言取文案（单测/多语言预览用）。
pub fn tr_lang(lang: Lang, key: &'static str) -> &'static str {
    for table in ALL {
        for &(k, zh, en) in *table {
            if k == key {
                return match lang {
                    Lang::Zh => zh,
                    Lang::En => {
                        if en.is_empty() {
                            zh
                        } else {
                            en
                        }
                    }
                };
            }
        }
    }
    key
}

/// `t!("key")` → 当前语言文案；缺键回退中文，再缺原样返回键名（不 panic）。
#[macro_export]
#[doc(hidden)]
macro_rules! t {
    ($key:literal) => {
        $crate::i18n::tr($key)
    };
}

/// 按当前语言取文案并填入位置参数（`{0}`/`{1}`…，zh/en 模板占位符一一对应）。
///
/// `format!` 要求格式串为字面量，无法直接 `format!(t!(key), …)` —— M8-T038
/// 动态文案统一经本函数做 `{0}`/`{1}` 顺序替换（参数经 `to_string()` 归一）。
pub fn tr_fmt(key: &'static str, args: &[String]) -> String {
    let mut s = tr(key).to_string();
    for (i, a) in args.iter().enumerate() {
        s = s.replace(&format!("{{{}}}", i), a);
    }
    s
}

/// `tf!("key", arg…)` → 当前语言模板 + 位置参数填充（`{0}`/`{1}`…）。
#[macro_export]
#[doc(hidden)]
macro_rules! tf {
    ($key:literal $(, $arg:expr)*) => {
        $crate::i18n::tr_fmt($key, &[$(($arg).to_string()),*])
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};

    /// env 与进程级语言状态相关测试串行执行（并行测试隔离）。
    static SYS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn sys_lock() -> &'static Mutex<()> {
        SYS_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn tr_lang_zh_en_lookup() {
        assert_eq!(tr_lang(Lang::Zh, "settings.title"), "设置");
        assert_eq!(tr_lang(Lang::En, "settings.title"), "Settings");
        assert_eq!(tr_lang(Lang::Zh, "app.name"), "麒麟桌面");
        assert_eq!(tr_lang(Lang::En, "app.name"), "KirinDesk");
    }

    #[test]
    fn en_missing_key_falls_back_to_zh() {
        // "settings.about" 的 en 为空串（未翻译）→ En 查询应回退中文。
        assert_eq!(tr_lang(Lang::Zh, "settings.about"), "关于");
        assert_eq!(tr_lang(Lang::En, "settings.about"), "关于");
    }

    #[test]
    fn unknown_key_returns_key_not_panic() {
        // 缺键（中文表也没有）→ 原样返回键名，绝不 panic。
        assert_eq!(tr_lang(Lang::Zh, "no.such.key"), "no.such.key");
        assert_eq!(tr_lang(Lang::En, "no.such.key"), "no.such.key");
    }

    #[test]
    fn tr_uses_current_lang() {
        let _g = sys_lock().lock().unwrap();
        set_lang(Lang::Zh);
        assert_eq!(tr("settings.title"), "设置");
        set_lang(Lang::En);
        assert_eq!(tr("settings.title"), "Settings");
        set_lang(Lang::Zh); // 复位，避免污染其它测试
    }

    #[test]
    fn set_lang_current_roundtrip() {
        let _g = sys_lock().lock().unwrap();
        set_lang(Lang::Zh);
        assert_eq!(current(), Lang::Zh);
        set_lang(Lang::En);
        assert_eq!(current(), Lang::En);
        set_lang(Lang::Zh);
    }

    #[test]
    fn from_code_cases() {
        assert_eq!(Lang::from_code("zh"), Lang::Zh);
        assert_eq!(Lang::from_code("en"), Lang::En);
        assert_eq!(Lang::from_code("EN"), Lang::En);
        assert_eq!(Lang::from_code("en-US"), Lang::En);
        assert_eq!(Lang::from_code("zh-CN"), Lang::Zh);
        assert_eq!(Lang::from_code("fr"), Lang::Zh); // 未知 → 基线中文
        assert_eq!(Lang::from_code(""), Lang::Zh);
    }

    #[test]
    fn lang_code_matches() {
        assert_eq!(Lang::Zh.code(), "zh");
        assert_eq!(Lang::En.code(), "en");
    }

    #[test]
    fn from_env_parses_lang_vars() {
        let _g = sys_lock().lock().unwrap();
        std::env::set_var("LANG", "zh_CN.UTF-8");
        assert_eq!(Lang::from_env(), Lang::Zh);
        std::env::set_var("LANG", "en_US.UTF-8");
        assert_eq!(Lang::from_env(), Lang::En);
        std::env::remove_var("LANG");
        std::env::set_var("LC_ALL", "en_GB");
        assert_eq!(Lang::from_env(), Lang::En);
        std::env::remove_var("LC_ALL");
        assert_eq!(Lang::from_env(), Lang::Zh); // 无环境 → 中文基线
    }

    // ---------- M8-T038 (P2): set_lang_code / system() / 重复键断言 ----------

    #[test]
    fn set_lang_code_cases() {
        let _g = sys_lock().lock().unwrap();
        // "system"：env 命中优先（zh → Zh；en → En）。
        std::env::set_var("LANG", "zh_CN.UTF-8");
        set_lang_code("system");
        assert_eq!(current(), Lang::Zh);
        std::env::set_var("LANG", "en_US.UTF-8");
        set_lang_code("system");
        assert_eq!(current(), Lang::En);
        // 显式 "zh" / "en" 覆盖 env。
        std::env::set_var("LANG", "en_US.UTF-8");
        set_lang_code("zh");
        assert_eq!(current(), Lang::Zh);
        set_lang_code("en");
        assert_eq!(current(), Lang::En);
        // 未知值 → system() 兜底（当前 env=en → En），不 panic。
        set_lang_code("fr");
        assert_eq!(current(), Lang::En);
        std::env::remove_var("LANG");
        set_lang(Lang::Zh); // 复位
    }

    #[test]
    fn system_resolves() {
        let _g = sys_lock().lock().unwrap();
        // env 命中优先。
        std::env::set_var("LANG", "zh_CN.UTF-8");
        assert_eq!(system(), Lang::Zh);
        std::env::set_var("LANG", "en_US.UTF-8");
        assert_eq!(system(), Lang::En);
        // 无 env → 依赖平台（Windows 返回系统语言或 zh 基线）：不 panic 且 ∈ {Zh, En}。
        std::env::remove_var("LANG");
        std::env::remove_var("LC_ALL");
        std::env::remove_var("LC_MESSAGES");
        std::env::remove_var("LANGUAGE");
        let v = system();
        assert!(matches!(v, Lang::Zh | Lang::En));
    }

    #[test]
    fn table_no_duplicate_keys() {
        // 并发加键撞车防线：全部分区表聚合后键名不得重复。
        let mut seen = HashSet::new();
        for table in ALL {
            for &(k, _, _) in *table {
                assert!(
                    seen.insert(k),
                    "duplicate i18n key across partition tables: {k}"
                );
            }
        }
    }

    #[test]
    fn tr_fmt_fills_positional_args() {
        let _g = sys_lock().lock().unwrap();
        set_lang(Lang::Zh);
        // {0}/{1} 顺序替换；zh/en 模板占位符一一对应。
        assert_eq!(
            tr_fmt("settings.status.autostart_failed", &["boom".to_string()]),
            "已保存，但自启注册失败: boom"
        );
        set_lang(Lang::En);
        assert_eq!(
            tr_fmt("settings.status.autostart_failed", &["boom".to_string()]),
            "Saved, but autostart registration failed: boom"
        );
        // 缺键 → 模板为键名本身，替换后仍是键名（不 panic）。
        assert_eq!(tr_fmt("no.such.fmt", &["x".to_string()]), "no.such.fmt");
        set_lang(Lang::Zh); // 复位
    }
}
