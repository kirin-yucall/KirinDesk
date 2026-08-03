//! M8-T038 (P3): Settings 页键值表（zh 基线 + en 全量）。
//! 本分区文件由 M8-T038_P3 独占认领。
//!
//! zh 为基线语言包（当前界面文案统一后的中文版本）；en 全量翻译（不得留空串）。
//! 动态文案模板使用 `{0}`/`{1}` 位置参数，zh/en 占位符一一对应。

pub static TABLE: &[(&str, &str, &str)] = &[
    // ── 分组标题 ──
    // M8-T039: `settings.tunnel.*` 全部键随 Settings Tunnel 分组整体删除——
    // 内网穿透迁至顶部导航独立页（tunnel.rs 分区，键前缀 `tunnel.*`）。
    ("settings.unattended.title", "无人值守模式", "Unattended Mode"),
    ("settings.identity.title", "身份", "Identity"),
    ("settings.whitelist.title", "白名单", "Whitelist"),
    ("settings.logging.title", "日志", "Logging"),
    ("settings.appearance.title", "外观", "Appearance"),
    ("settings.update.title", "更新", "Update"),
    // 关于分组标题：common.rs 的 `settings.about` 保留为「en 空串回退」样例
    // （R-12 基建单测引用），本页改用独立键。
    ("settings.about.title", "关于", "About"),
    ("settings.about.tagline", "P2P 远程桌面 — 安全直连。", "P2P Remote Desktop — secure direct connections."),

    // ── Unattended Mode ──
    ("settings.unattended.desc",
     "无人值守：开机自启 + 自动开启服务端 + 受信任设备自动接受连接（远程桌面远控 / 远程 Shell PTY 均可）。",
     "Unattended: auto-start on boot + auto-enable the server + trusted devices are auto-accepted (remote desktop control / remote Shell PTY)."),
    ("settings.unattended.master", "无人值守模式", "Unattended Mode"),
    ("settings.unattended.master_hint",
     "开：开机自启 + 默认受控跟随开启 + 受信任设备自动接受连接；关：两子开关跟随关闭（仅改配置，不停止运行中的监听）。",
     "On: auto-start + default-controlled follow along, trusted devices auto-accepted; Off: both sub-switches follow off (config only; running listeners keep working)."),
    ("settings.unattended.autostart", "开机自启", "Start on boot"),
    ("settings.unattended.autostart_hint",
     "开：注册到系统登录自启（保存时生效）；可独立开关，不影响无人值守。",
     "On: register at OS logon (takes effect on Save); can be toggled independently."),
    ("settings.unattended.default_controlled", "默认受控", "Default controlled"),
    ("settings.unattended.default_controlled_hint",
     "开：程序启动即自动开启服务端监听（无需手动开「允许受控」），切换即启动监听；关闭不影响已运行的监听。",
     "On: starts the server listener automatically at launch (no need to enable 'Allow controlled' manually); toggling on starts listening; off does not stop a running listener."),
    ("settings.unattended.registered", "已注册到系统登录自启", "registered at OS logon"),
    ("settings.unattended.not_registered", "未注册", "not registered"),
    ("settings.unattended.security_hint",
     "⚠ 无人值守下：known_clients/白名单命中的连接自动放行（远控或 PTY）；未知设备一律拒绝（无审批弹窗）；temp-mode 旁路禁用。建议先在 Whitelist / known-hosts 中配置受信任设备。",
     "⚠ Under unattended mode: connections matching known_clients/whitelist are auto-approved (remote control or PTY); unknown devices are always rejected (no approval dialog); temp-mode bypass is disabled. Configure trusted devices in Whitelist / known-hosts first."),

    // ── Identity ──
    ("settings.identity.device_id", "设备 ID：", "Device ID:"),
    ("settings.identity.auto_hint", "留空 = 自动（系统硬盘 UUID）", "empty = automatic (system disk UUID)"),
    ("settings.identity.moved_hint",
     "Nickname / Challenge Code / Listen Port 已移至 Dashboard「服务端设置」。",
     "Nickname / Challenge Code / Listen Port moved to Dashboard 'Server settings'."),

    // ── Whitelist ──
    ("settings.whitelist.allowed_domains", "允许的域名：", "Allowed Domains:"),
    ("settings.whitelist.domains_hint", "（逗号分隔，一个或多个域名）", "(comma-separated, one or more domains)"),
    ("settings.whitelist.domain_secure", "域名白名单更安全。", "Domain whitelist is more secure."),
    ("settings.whitelist.non_whitelisted_dialog",
     "非白名单客户端连接会触发审批弹窗。",
     "Non-whitelisted clients trigger an approval dialog."),
    ("settings.whitelist.headless_hint",
     "无头服务器请启用临时模式（Temp Mode），否则客户端将被拒绝。",
     "On headless servers, enable Temp Mode or clients are rejected."),
    ("settings.whitelist.allowed_ids", "允许的设备 ID：", "Allowed Device IDs:"),
    ("settings.whitelist.ids_hint",
     "（逗号或换行分隔设备 ID；精确匹配、区分大小写，`office-*` = 前缀通配；保存后立即生效）",
     "(comma or newline separated device IDs; exact match, case-sensitive, `office-*` = prefix wildcard; takes effect immediately after Save)"),
    ("settings.whitelist.entries_label", "ID 白名单条目：", "ID whitelist entries:"),
    ("settings.whitelist.expired_fmt", "（已过期 {0}）", "(expired {0})"),
    ("settings.whitelist.expires_fmt", "（将于 {0} 过期）", "(expires {0})"),
    ("settings.whitelist.permanent", "（永久）", "(permanent)"),
    ("settings.whitelist.remove", "✕ 移除", "✕ Remove"),

    // ── Logging ──
    ("settings.logging.config_hint",
     "日志级别 / 格式 / 保留天数在 config/default.toml 中配置。",
     "Log level / format / keep days are configured in config/default.toml."),

    // ── Appearance ──
    ("settings.appearance.theme", "主题：", "Theme:"),
    ("settings.appearance.light", "明亮", "Light"),
    ("settings.appearance.dark", "深色", "Dark"),
    ("settings.appearance.system", "跟随系统", "System"),

    // ── Update ──
    ("settings.update.current_version", "当前版本：", "Current version:"),
    ("settings.update.checking", "正在检查更新...", "Checking for updates..."),
    ("settings.update.check_button", "检查更新", "Check for updates"),
    ("settings.update.new_version", "新版本", "New version"),
    ("settings.update.download_button", "下载更新", "Download update"),
    ("settings.update.install_restart", "安装并重启", "Install & Restart"),
    ("settings.update.downloaded_fmt", "已下载到 {0}。{1}", "Downloaded to {0}. {1}"),
    ("settings.update.up_to_date", "您已是最新版本。", "You are up to date."),
    ("settings.update.error_fmt", "更新错误：{0}", "Update error: {0}"),

    // ── 底部 Save ──
    ("settings.save", "保存", "Save"),
    ("settings.status.saved", "已保存", "Saved"),
    ("settings.status.autostart_failed",
     "已保存，但自启注册失败: {0}",
     "Saved, but autostart registration failed: {0}"),
    ("settings.status.save_failed", "保存失败: {0}", "Save failed: {0}"),
];
