//! R-12 (M15-T007): 国际化基础设施（先行交付；文案抽取 S2~S4 随波次 3）。
//!
//! 审计背景（`功能审计报告_2026-08-02.md` §4 P2-8）：`ui/src/i18n.rs`
//! 不存在，中英硬编码混排（如 `lib.rs` 设置页中文与英文同框）。
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
//! - 默认跟随系统（`LANG`/`LC_ALL`/`LC_MESSAGES`/`LANGUAGE`，`zh*` → 中文）；
//! - 运行期 [`set_lang`] 即时切换（Settings 语言下拉，R12-S3 持久化到
//!   `[ui].language`）；进程级 [`CURRENT`] 原子状态。
//!
//! # 波次约定
//!
//! 本文件为 R-12 波次 3 前的先行基础设施（**新文件**，与波次 1/2 的
//! lib.rs/cli.rs 区域改动零冲突）；键值表随 S2~S5 文案抽取增量补充。
//! 见 `task_docs/修复任务/E_安全打磨R-12至R-13.md` R-12。

use std::sync::atomic::{AtomicU8, Ordering};

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
    pub fn code(self) -> &'static str {
        match self {
            Lang::Zh => LANG_ZH,
            Lang::En => LANG_EN,
        }
    }

    /// 由语言代码解析；`en*` → 英文，其余 → [`Lang::Zh`]（宽松前缀解析，
    /// 兼容 `"en-US"` 等变体；未知代码不报错）。
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
    /// 注：GUI 场景个别平台（如 Windows 桌面）可能不导出 `LANG`，
    /// 此时回落中文基线——属可接受降级，R12-S3 提供用户显式选择。
    pub fn from_env() -> Lang {
        for var in ["LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE"] {
            if let Ok(v) = std::env::var(var) {
                let v = v.to_ascii_lowercase();
                if v.starts_with("zh") {
                    return Lang::Zh;
                }
                if v.starts_with("en") {
                    return Lang::En;
                }
            }
        }
        Lang::Zh
    }
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

/// 切换当前语言（立即生效；持久化由 R12-S3 在 Settings 完成）。
pub fn set_lang(lang: Lang) {
    CURRENT.store(if lang == Lang::En { 1 } else { 0 }, Ordering::Relaxed);
}

/// 编译期键值表：(key, zh, en)。`en` 为空串 = 该键未翻译 → 回退中文。
///
/// 种子条目供基础设施单测引用（`settings.about` 故意留空 en 验证回退）；
/// R12-S2 起随文案抽取增量补充。
static TABLE: &[(&str, &str, &str)] = &[
    ("app.name", "麒麟桌面", "KirinDesk"),
    ("settings.title", "设置", "Settings"),
    ("settings.language", "语言", "Language"),
    ("settings.about", "关于", ""), // en 未翻译 → 回退中文
    ("common.ok", "确定", "OK"),
    ("common.cancel", "取消", "Cancel"),
];

/// 按当前语言取文案；缺键回退中文，再缺原样返回键名（不 panic）。
pub fn tr(key: &'static str) -> &'static str {
    tr_lang(current(), key)
}

/// 按指定语言取文案（单测/多语言预览用）。
pub fn tr_lang(lang: Lang, key: &'static str) -> &'static str {
    for &(k, zh, en) in TABLE {
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
