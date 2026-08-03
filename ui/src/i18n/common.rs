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
];
