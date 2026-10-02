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
    ("settings.filetransfer.title", "文件传输", "File Transfer"),
    ("settings.filetransfer.download_dir",
     "默认文件传输接收目录",
     "Default file transfer receive directory"),
    ("settings.filetransfer.download_dir_ph",
     "如 C:\\Users\\你\\Downloads\\KirinDesk（留空或非法 = 框内报错，不静默）",
     "e.g. C:\\Users\\you\\Downloads\\KirinDesk (blank/invalid = in-box error, never silent)"),
    ("settings.filetransfer.download_dir_hint",
     "接收文件（Offer 发送 / 剪贴板粘贴拉取）未指定落点时的默认目录；显示即当前生效值，变更即时生效（无需重启）。默认 = 系统下载文件夹下的 KirinDesk 子目录。",
     "Landing directory for received files (Offer sends / clipboard fetch) when no target is specified. The displayed value is the currently effective one; changes take effect immediately (no restart). Default = KirinDesk subfolder of the system Downloads folder."),
    ("settings.filetransfer.browse", "浏览…", "Browse…"),
    ("settings.filetransfer.browse_hint",
     "打开系统文件夹选择对话框（选择后即时生效）",
     "Open the native folder picker (takes effect immediately on selection)"),
    ("settings.filetransfer.err_empty",
     "路径不能为空（如需默认目录，直接填写默认路径或重新浏览）",
     "Path must not be empty (fill the default path or browse again to restore the default)"),
    ("settings.filetransfer.err_invalid_chars",
     "路径含非法字符（< > : \" | ? * 等，盘符 C:\\ 除外）",
     "Path contains invalid characters (< > : \" | ? * etc.; drive prefix C:\\ is fine)"),
    ("settings.filetransfer.err_is_file",
     "该路径已存在但不是目录",
     "This path exists but is not a directory"),
    //（默认开；关闭 = 回退应用内两段式粘贴）。
    ("settings.filetransfer.clip_direct",
     "剪贴板文件直贴（复制即传）",
     "Clipboard file direct paste (copy-to-sync)"),
    ("settings.filetransfer.clip_direct_hint",
     "开启后：对端复制文件时本机后台预取至缓存并写入系统剪贴板（资源管理器 Ctrl+V 即得）；本机复制文件也会自动送至对端缓存。走既有传输授权链；写系统剪贴板会覆盖现有内容。关闭 = 回退应用内两段式粘贴。",
     "When on: files copied on the peer are prefetched to a local cache and written to this machine's system clipboard (paste directly in Explorer); files copied locally are auto-sent to the peer cache. Uses the existing transfer authorization chain; writing the system clipboard overwrites its current content. Off = in-app two-step paste."),
    ("settings.update.title", "更新", "Update"),
    // 关于分组标题：common.rs 的 `settings.about` 保留为「en 空串回退」样例
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

    // 设置分组 + 开关 + 说明 + 受控端拒绝 toast（tf! 带 {0} = 对端设备 ID）。
    ("settings.mutual.title", "互控互斥（安全）", "Mutual-Control Exclusion (Security)"),
    ("settings.mutual.toggle", "禁止互相控制", "Forbid mutual control"),
    ("settings.mutual.toggle_hint",
     "开（默认）：本机正在控制某设备期间，该设备反向控制本机将被拒绝并提示；本机反向发起同样被拦截。关：恢复允许互控（双向同时控制可能互相干扰，建议保持开启）。",
     "On (default): while this machine is controlling a device, reverse control attempts from that device are rejected with a notice, and reverse initiation from this side is blocked as well. Off: restores mutual control (simultaneous control in both directions can interfere; keeping this on is recommended)."),
    ("settings.mutual.rejected_toast",
     "已按禁止互控策略拒绝来自 {0} 的反向控制请求（本机正在控制该设备）",
     "Reverse control request from {0} rejected by the forbid-mutual-control policy (this machine is currently controlling that device)"),

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
    ("settings.whitelist.id_enforce",
     "ID 白名单强制（开启后仅白名单内设备 ID 可发起 ID 连接）",
     "Enforce ID whitelist (when ON, only whitelisted device IDs may connect by ID)"),
    ("settings.whitelist.id_enforce_hint",
     "默认关闭：ID 连接沿用昵称 + 挑战码验证。开启后设备 ID 不在名单即使昵称/挑战码正确也拒绝（fail-closed）；临时连接窗口激活时跳过。开关与 Dashboard「ID 模式」区块入口同一状态。",
     "Off by default: ID connections rely on nickname + challenge verification. When ON, device IDs outside the list are rejected even with correct nickname/challenge (fail-closed); an active temp-connect window skips it. This toggle is the same state as the Dashboard \"ID Mode\" block."),
    ("settings.whitelist.expired_fmt", "（已过期 {0}）", "(expired {0})"),
    ("settings.whitelist.expires_fmt", "（将于 {0} 过期）", "(expires {0})"),
    ("settings.whitelist.permanent", "（永久）", "(permanent)"),
    ("settings.whitelist.remove", "✕ 移除", "✕ Remove"),

    // ── Logging ──
    ("settings.logging.config_hint",
     "日志级别 / 格式 / 保留天数在 config/default.toml 中配置。",
     "Log level / format / keep days are configured in config/default.toml."),

    // ── Appearance ──
    // Light/Dark 两模式；旧 theme="system" 配置解析回落 Light）。
    ("settings.appearance.theme", "主题：", "Theme:"),
    ("settings.appearance.light", "明亮", "Light"),
    ("settings.appearance.dark", "深色", "Dark"),

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

    // 2026-09-28 裁定：呈现面显著化，零行为变化）：设置页常显警示
    // （danger 描边框 + 文案；与连接页同口径）。──
    ("settings.r204.warning",
];
