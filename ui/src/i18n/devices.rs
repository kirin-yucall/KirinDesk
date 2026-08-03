//! M8-T038 (P5): Devices 页键值表（zh 基线 + en 全量）。
//! 本分区文件由 M8-T038_P5 独占认领。
//!
//! zh 为基线语言包；en 全量翻译（不得留空串）。
//! 动态文案模板使用 `{0}`/`{1}` 位置参数，zh/en 占位符一一对应。
//! 协调说明：`devices.menu.*` / `devices.saved_badge` 与 Connect 页设备列表共用
//! （P4 消费本表键，不另行定义，避免同义双键——见完成登记）。

pub static TABLE: &[(&str, &str, &str)] = &[
    // ── 页面标题 / 空态 / 计数 ──
    ("devices.title", "设备", "Devices"),
    ("devices.empty",
     "暂无已保存设备。先连接一个设备——连接成功后自动保存。",
     "No saved devices yet. Connect to a device first — it is saved automatically."),
    ("devices.count",
     "已保存 {0} 个设备 — 单击自动填入 Connect 页，右键打开菜单",
     "{0} saved device(s) — click to auto-fill the Connect page, right-click for the menu"),
    ("devices.saved_badge", "已保存", "saved"),
    ("devices.remark_empty", "—", "—"),

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
