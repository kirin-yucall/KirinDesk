//! (P5): Devices 页键值表（zh 基线 + en 全量）。
//! 本分区文件由 独占认领。
//!
//! zh 为基线语言包；en 全量翻译（不得留空串）。
//! 动态文案模板使用 `{0}`/`{1}` 位置参数，zh/en 占位符一一对应。
//! 协调说明：`devices.menu.*` 与 Connect 页设备列表共用（P4 消费本表键，
//! 不另行定义，避免同义双键——见完成登记）。
//! `devices.empty`/`devices.count` 去「已保存」化；`devices.remark_empty`
//! 随备注行移除而删除；新增单行行类型徽标 `devices.kind.*` 与名称+备注
//! 悬浮提示模板 `devices.tip_with_remark`。

pub static TABLE: &[(&str, &str, &str)] = &[
    // ── 页面标题 / 空态 / 计数 ──
    ("devices.title", "设备", "Devices"),
    ("devices.empty",
     "暂无设备。先连接一个设备——连接成功后自动保存。",
     "No devices yet. Connect to a device first — it is saved automatically."),
    ("devices.count",
     "共 {0} 个设备 — 单击自动填入 Connect 页，右键打开菜单",
     "{0} device(s) — click to auto-fill the Connect page, right-click for the menu"),

    ("devices.kind.server", "服务端", "Server"),
    ("devices.kind.desktop", "桌面", "Desktop"),
    ("devices.tip_with_remark", "{0}（{1}）", "{0} ({1})"),

    //    通告/未知值 → 回退上方 devices.kind.* 角色徽标，不猜） ──
    ("devices.os.windows_11", "Windows 11", "Windows 11"),
    ("devices.os.windows_10", "Windows 10", "Windows 10"),
    ("devices.os.windows", "Windows", "Windows"),
    ("devices.os.macos", "macOS", "macOS"),
    ("devices.os.linux", "Linux", "Linux"),

    // ── 卡片按钮 ──
    ("devices.btn.connect", "连接", "Connect"),
    ("devices.btn.edit", "编辑", "Edit"),
    ("devices.btn.delete", "删除", "Delete"),
    ("devices.btn.up", "↑上移", "↑Up"),
    ("devices.btn.down", "↓下移", "↓Down"),

    // ── 右键菜单（Connect 页设备列表共用）──
    ("devices.menu.connect", "连接", "Connect"),
    ("devices.menu.edit", "编辑", "Edit"),
    ("devices.menu.delete", "删除", "Delete"),

    // ── 编辑弹窗 ──
    ("devices.edit.title", "编辑设备", "Edit device"),
    ("devices.edit.id_label", "设备 ID: {0}", "Device ID: {0}"),
    ("devices.edit.nickname", "昵称：", "Nickname:"),
    ("devices.edit.host", "地址 (IP/域名)：", "Address (IP/Domain):"),
    ("devices.edit.remark", "备注名：", "Remark:"),
    ("devices.edit.challenge", "挑战码：", "Challenge code:"),
    ("devices.edit.optional", "选填", "optional"),
    ("devices.edit.port", "端口：", "Port:"),

    // ── 上次在线（format_last_seen 共用）──
    ("devices.last_seen_today", "今天 {0}", "Today {0}"),
];

#[cfg(test)]
mod r74d_tests {
    use crate::i18n::{tr_lang, Lang};
    use super::TABLE;

    #[test]
    fn saved_wording_removed() {
        let removed_key = concat!("devices.saved_", "badge");
        assert!(
            !TABLE.iter().any(|&(k, _, _)| k == removed_key),
        );
        for &(k, zh, _) in TABLE {
            assert!(
                !zh.contains("已保存"),
                "devices key {k} still contains 已保存: {zh}"
            );
        }
    }

    /// 中英成对、非空、可命中。
    #[test]
    fn r74d_new_keys_zh_en_pairs() {
        for key in [
            "devices.kind.server",
            "devices.kind.desktop",
            "devices.tip_with_remark",
            "devices.os.windows_11",
            "devices.os.windows_10",
            "devices.os.windows",
            "devices.os.macos",
            "devices.os.linux",
        ] {
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
