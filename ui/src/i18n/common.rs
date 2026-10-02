//! M8-T038 (P2): 公共键值表（全页面共用）。
//!
//! 条目格式 `(key, zh, en)`；`en` 为空串 = 该键未翻译 → 回退中文
//! （`settings.about` 故意留空 en 验证回退路径，勿补全）。
//! M8-T038 (P2) 独占本文件，其它任务不得增删。

pub static TABLE: &[(&str, &str, &str)] = &[
    ("app.name", "麒麟桌面", "KirinDesk"),
    ("settings.title", "设置", "Settings"),
    ("settings.language", "语言", "Language"),
    ("settings.about", "关于", ""), // en 未翻译 → 回退中文
    ("common.ok", "确定", "OK"),
    ("common.cancel", "取消", "Cancel"),
    // 随 Settings 语言切换即时刷新（tray::Tray::set_labels）。
    ("tray.tooltip",
     "KirinDesk 正在运行（左键单击显示主窗口）",
     "KirinDesk is running (left-click to show the main window)"),
    ("tray.show", "显示主窗口", "Show main window"),
    ("tray.quit", "退出", "Exit"),
];

#[cfg(test)]
mod r74d_tests {
    use crate::i18n::{tr_lang, Lang};
    use super::TABLE;

    #[test]
    fn tray_keys_zh_en_pairs() {
        for key in ["tray.tooltip", "tray.show", "tray.quit"] {
            let (_, zh, en) = TABLE
                .iter()
                .find(|&(k, _, _)| *k == key)
                .unwrap_or_else(|| panic!("missing i18n key: {key}"));
            assert!(!zh.is_empty(), "zh empty for {key}");
            assert!(!en.is_empty(), "en empty for {key}");
            assert_ne!(tr_lang(Lang::Zh, key), key, "zh lookup miss for {key}");
            assert_ne!(tr_lang(Lang::En, key), key, "en lookup miss for {key}");
        }
    }
}
