//!
//! (P2): 键值表由单一 `TABLE` 拆为**按页面分区的静态表文件**
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
    /// 中文基线——上层优先经 [`system()`]（含系统 API 兜底）。
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
/// `format!` 要求格式串为字面量，无法直接 `format!(t!(key), …)` —— 
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

    /// 基线（进程默认态）；`drop`（**含 panic 展开路径**）再复位回中文。
    /// 修复前两条泄漏路径：①用例中途 panic → `CURRENT` 永久滞留非中文 →
    /// 其后全部跨文件 `t!` 比对漂移（常驻污染，E2V 四证归因的 i18n CURRENT
    /// 竞态侧）；②复位依赖各用例自觉（原仅行尾注释式复位），无统一保证。
    /// 生产 `t!`/`CURRENT`/`set_lang` 函数体与语义**零触碰**（仅测试区状态
    /// 卫生）。
    struct LangResetGuard;

    impl LangResetGuard {
        fn new() -> Self {
            set_lang(Lang::Zh);
            Self
        }
    }

    impl Drop for LangResetGuard {
        fn drop(&mut self) {
            set_lang(Lang::Zh);
        }
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
        let _g = crate::cli::r92ti_global_lock::lock_global();
        let _lang = LangResetGuard::new();
        set_lang(Lang::Zh);
        assert_eq!(tr("settings.title"), "设置");
        set_lang(Lang::En);
        assert_eq!(tr("settings.title"), "Settings");
        set_lang(Lang::Zh); // 复位（LangResetGuard::drop 兜底，含 panic 路径）
    }

    #[test]
    fn set_lang_current_roundtrip() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        let _lang = LangResetGuard::new();
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
        // 他线程写期间 r82a 组的 KIRIN_DATA_DIR 读可瞬读失败/读旧值）。
        // 本例纯函数（`Lang::from_env` 不触 `CURRENT`）→ 只需锁，无需复位守卫。
        let _g = crate::cli::r92ti_global_lock::lock_global();
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

    // ---------- set_lang_code / system() / 重复键断言 ----------

    #[test]
    fn set_lang_code_cases() {
        // = 双全局态 → 同锁域 + 入口/出口强制复位。
        let _g = crate::cli::r92ti_global_lock::lock_global();
        let _lang = LangResetGuard::new();
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
        // 本例只调纯函数 `system()`（不触 `CURRENT`）→ 只需锁，无需复位守卫。
        let _g = crate::cli::r92ti_global_lock::lock_global();
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

    /// 前缀 + playing / muted / disabled 三键已随渲染点移除而成对删除，
    /// 全树 0 命中（本测试动态拼接键名，避免测试自身成为 grep 命中；
    /// 配对完整性 = 键不存在即成对删除成立，`table_no_duplicate_keys`
    /// 回归其余配对面）。工具栏 `session.toolbar.audio_play` 保留（零
    /// 改动红线，同测断言钉死）。
    #[test]
    fn r132_8_audio_badge_keys_removed() {
        for suffix in ["playing", "muted", "disabled"] {
            let key = format!("session.statusbar.audio_{suffix}");
            for table in ALL {
                for &(k, _, _) in *table {
                    assert_ne!(
                        k, key.as_str(),
                    );
                }
            }
        }
        // 工具栏按钮键保留（用户认可图标态，零改动红线）。
        let toolbar_kept = ALL
            .iter()
            .any(|table| table.iter().any(|&(k, _, _)| k == "session.toolbar.audio_play"));
    }

    /// 「连接提示」残留未移除干净）：设备 ID 框双格式长提示键对已随
    /// 渲染点整体删除，键表 0 残留（本测试动态拼接键名，避免测试自身
    /// 成为全树 grep 命中；配对完整性 = 键不存在即成对删除成立，
    /// `table_no_duplicate_keys` 回归其余配对面）。保留面锚 = 连接页
    /// 其余 hover-only 提示键（IP 框 2 键 / ID 三钮 1 键，纯悬停显示
    /// 可保留口径）与设备 ID 框标签/占位两键不得删除。
    #[test]
    fn r145_removed_device_id_hint_key_gone() {
        let removed = format!("connect.hint.{}", "device_id_full");
        for table in ALL {
            for &(k, _, _) in *table {
                assert_ne!(
                    k, removed.as_str(),
                );
            }
        }
        // 保留面锚：hover-only 提示键（未移除干净对象之外的判定 = 保留）
        // 与设备 ID 框标签/占位（框体唯一常驻文案，零改动红线）不得删除。
        for kept in [
            "connect.hint.ip_mode",
            "connect.hint.ip_whitelist_na",
            "connect.hint.id_mode",
            "connect.label.device_id",
            "connect.placeholder.device_id",
        ] {
            let present = ALL
                .iter()
                .any(|table| table.iter().any(|&(k, _, _)| k == kept));
        }
    }

    /// `dashboard.file_transfer.*` 五键 + 旧队列面板专属 `filepanel.*` 十键
    /// 随仪表盘卡/旧面板成对删除，全树 0 命中（本测试静态键名清单 = 交付
    /// 报告键清单同源；配对完整性 = 键不存在即成对删除成立，
    /// `table_no_duplicate_keys` 回归其余配对面）。保留面锚：
    /// `session.toolbar.file`（Shell 窗 📁 = 文件传输模式钮）与
    /// `clip.upload.started`（剪贴板上传派发 toast，文案引用已改文件
    /// 传输模式窗）不得删除。
    #[test]
    fn r137_11_removed_file_ui_keys_gone() {
        const REMOVED: [&str; 15] = [
            "dashboard.file_transfer.title",
            "dashboard.file_transfer.empty",
            "dashboard.file_transfer.target",
            "dashboard.file_transfer.target_default",
            "dashboard.file_transfer.paste_hint",
            "filepanel.title",
            "filepanel.active_fmt",
            "filepanel.empty",
            "filepanel.status.queued",
            "filepanel.status.waiting",
            "filepanel.status.sending",
            "filepanel.status.paused",
            "filepanel.status.completed",
            "filepanel.status.failed",
            "filepanel.status.cancelled",
        ];
        for key in REMOVED {
            for table in ALL {
                for &(k, _, _) in *table {
                    assert_ne!(
                        k, key,
                    );
                }
            }
        }
        // 保留面锚①：Shell 窗 📁（文件传输模式 = 文件管理器）钮键零触碰。
        let toolbar_kept = ALL
            .iter()
            .any(|table| table.iter().any(|&(k, _, _)| k == "session.toolbar.file"));
        // 保留面锚②：剪贴板上传派发 toast 键在位 + 文案引用 = 文件传输模式窗
        // （原「📁 面板」旧入口引用不得回潮）。
        let clip_started = ALL
            .iter()
            .find_map(|table| table.iter().find(|&&(k, _, _)| k == "clip.upload.started"))
            .copied();
        let Some((_, zh, en)) = clip_started else {
        };
        assert!(
            zh.contains("文件传输模式窗") && en.contains("file transfer mode window"),
        );
    }

    /// 分享面 + 行内操作（测试/应用）移除键 grep 门禁——35 键随 UI 面成对
    /// 删除，全树 0 命中（本测试静态键名清单 = 交付报告移除清单同源；配对
    /// 完整性 = 键不存在即成对删除成立，`table_no_duplicate_keys` 回归其余
    /// 配对面）。保留面锚：`tunnel.nodes.title`/`add`/`delete`（用户原文
    /// 口径两按钮）+ `pick`/`applied`（「从中继服务器选择」回填下拉零回归）
    /// 不得删除。
    #[test]
    fn r137_13_removed_node_import_share_keys_gone() {
        const REMOVED: [&str; 35] = [
            // 导入三通道入口（文件/二维码/粘贴 JSON）+ 提示。
            "tunnel.nodes.import_file",
            "tunnel.nodes.import_file_hint",
            "tunnel.nodes.import_qr",
            "tunnel.nodes.import_qr_hint",
            "tunnel.nodes.import_paste",
            "tunnel.nodes.paste_hint",
            "tunnel.nodes.import_btn",
            // 分享面（复制/文件/二维码 三通道 + 成功/失败/警示）。
            "tunnel.nodes.share_copy",
            "tunnel.nodes.share_copy_ok",
            "tunnel.nodes.share_file",
            "tunnel.nodes.share_file_ok",
            "tunnel.nodes.share_file_fail",
            "tunnel.nodes.share_qr",
            "tunnel.nodes.share_qr_ok",
            "tunnel.nodes.share_qr_fail",
            "tunnel.nodes.share_fail",
            "tunnel.nodes.share_warn",
            // 行内「测试」（TCP 探活功能随面移除，死码退役）。
            "tunnel.nodes.test",
            "tunnel.nodes.testing",
            "tunnel.nodes.reachable",
            "tunnel.nodes.unreachable",
            "tunnel.nodes.test_hint",
            // 行内「应用」（回填保留在「从中继服务器选择」下拉，行按钮移除）。
            "tunnel.nodes.apply",
            "tunnel.nodes.apply_hint",
            // 导入解析错误映射（parse_node_share_json 死码退役）。
            "tunnel.nodes.err_json",
            "tunnel.nodes.err_not_object",
            "tunnel.nodes.err_version_missing",
            "tunnel.nodes.err_version",
            "tunnel.nodes.err_type_missing",
            "tunnel.nodes.err_type",
            "tunnel.nodes.err_field_type",
            "tunnel.nodes.err_addr_empty",
            "tunnel.nodes.err_read",
            "tunnel.nodes.err_qr",
            // 导入成功反馈。
            "tunnel.nodes.imported",
        ];
        for key in REMOVED {
            for table in ALL {
                for &(k, _, _) in *table {
                    assert_ne!(
                        k, key,
                    );
                }
            }
        }
        // 保留面锚：用户原文口径两按钮 + 回填下拉零回归面。
        for kept in [
            "tunnel.nodes.title",
            "tunnel.nodes.add",
            "tunnel.nodes.delete",
            "tunnel.nodes.pick",
            "tunnel.nodes.applied",
        ] {
            let present = ALL
                .iter()
                .any(|table| table.iter().any(|&(k, _, _)| k == kept));
        }
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
        let _g = crate::cli::r92ti_global_lock::lock_global();
        let _lang = LangResetGuard::new();
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
