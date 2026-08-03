//! M8-T038 (P4): Connect 页键值表（zh 基线 + en 全量）。
//! 本分区文件由 M8-T038_P4 独占认领。
//!
//! zh 为基线语言包（当前界面文案统一后的中文版本）；en 全量翻译（不得留空串）。
//! 动态文案模板使用 `{0}`/`{1}` 位置参数，zh/en 占位符一一对应。
//! 注：`devices.saved_badge` / `devices.menu.*` 与 Devices 页共用（P5 键表定义，
//! 此处仅消费，避免同义双键——合并协调见完成登记）。

pub static TABLE: &[(&str, &str, &str)] = &[
    // ── 页面标题 / 模式 / 日志 ──
    ("connect.title", "连接设备", "Connect to Device"),
    ("connect.mode.ip", "IP 模式（直接 IP 连接）", "IP Mode (direct IP connection)"),
    ("connect.mode.domain", "域名模式（DNS 发现）", "Domain Mode (DNS-based discovery)"),
    ("connect.mode.id", "ID 模式（relay 设备 ID）", "ID Mode (relay device ID)"),
    ("connect.log.title", "连接日志：", "Connection Log:"),
    ("connect.log.empty", "（暂无连接日志）", "(no connection log yet)"),

    // ── 表单标签 / 占位 ──
    ("connect.label.ip", "IP 地址：", "IP Address:"),
    ("connect.label.port", "端口：", "Port:"),
    ("connect.label.nickname", "昵称（发送给服务端）：", "Nickname (sent to server):"),
    ("connect.label.challenge", "挑战码（发送给服务端）：", "Challenge (sent to server):"),
    ("connect.label.device_id", "设备 ID：", "Device ID:"),
    ("connect.label.domain", "域名：", "Domain:"),
    ("connect.placeholder.required", "必填", "required"),

    // ── 表单校验 / 错误 ──
    ("connect.error.ip_invalid", "不是有效的 IP 地址（IPv4 或 IPv6）", "Not a valid IP address (IPv4 or IPv6)"),
    ("connect.error.port_invalid", "端口必须为 1-65535", "Port must be 1-65535"),
    ("connect.error.nickname_required", "昵称为必填项", "Nickname is required"),
    ("connect.error.challenge_required", "挑战码为必填项", "Challenge is required"),
    ("connect.error.device_id_required", "设备 ID 为必填项", "Device ID is required"),
    ("connect.error.domain_required", "域名为必填项", "Domain is required"),
    ("connect.error.ip_empty", "请输入 IP 地址（IPv4 或 IPv6）", "Enter an IP address (IPv4 or IPv6)"),
    ("connect.error.port_empty", "请输入有效端口", "Enter a valid port"),
    ("connect.error.nickname_empty", "请输入设备昵称", "Enter the device nickname"),
    ("connect.error.device_id_empty", "请输入设备 ID", "Enter the device ID"),
    ("connect.error.domain_empty", "请输入远端域名", "Enter the remote domain"),
    ("connect.error.godaddy_missing",
     "GoDaddy API 未配置 — 请先在 Settings 中配置",
     "GoDaddy API not configured — configure it in Settings first"),

    // ── 按钮 ──
    ("connect.button.connect", "连接", "Connect"),
    ("connect.button.shell", "连接 Shell", "Connect Shell"),
    ("connect.button.goto_settings", "跳转到 Settings", "Go to Settings"),

    // ── ID 模式 ──
    ("connect.id.tunnel_missing",
     "ID 模式需配置 [tunnel] server_addr / token / server_pubkey",
     "ID mode requires [tunnel] server_addr / token / server_pubkey"),
    ("connect.id.via_relay", "经 relay {0}", "via relay {0}"),
    ("connect.id.error_configure",
     "ID 模式未配置：请在 config 中设置 [tunnel] server_addr/token/server_pubkey",
     "ID mode not configured: set [tunnel] server_addr/token/server_pubkey in config"),

    // ── 提示行 ──
    ("connect.hint.ip_mode", "IP 模式：直接 TCP，无 DNS 解析。", "IP mode: direct TCP, no DNS resolution."),
    ("connect.hint.ip_whitelist_na", "域名白名单不适用。", "Domain whitelist does not apply."),
    ("connect.hint.id_mode",
     "ID 模式：relay 服务器解析设备；路径 直连 → 打洞 → 中继。",
     "ID mode: relay server resolves the device; direct → punch → relay paths."),
    ("connect.hint.domain_whitelist", "域名白名单已强制执行。", "Domain whitelist is enforced."),
    ("connect.hint.domain_whitelist_only",
     "仅接受 Settings 中白名单内的域名。",
     "Only whitelisted domains in Settings are accepted."),
    ("connect.hint.domain_tip",
     "提示：通过 SRV（端口）+ TXT（公钥）+ AAAA（IPv6）自动发现。",
     "Tip: auto-discovers via SRV (port) + TXT (key) + AAAA (IPv6)."),

    // ── GoDaddy 引导 ──
    ("connect.godaddy.unconfigured", "GoDaddy API 未配置", "GoDaddy API not configured"),
    ("connect.godaddy.guide",
     "请先在 Settings 配置 GoDaddy API，才能使用 DNS 域名发现。",
     "Configure the GoDaddy API in Settings first to use DNS domain discovery."),

    // ── 操作反馈 ──
    ("connect.dedup_hit", "已有该设备的连接窗口，已聚焦", "A connection window for this device already exists — focused"),
    ("connect.ready", "就绪：{0}@[{1}]:{2}", "Ready: {0}@[{1}]:{2}"),
    ("connect.ready_domain", "就绪：{0}@{1}（域名模式自动发现）", "Ready: {0}@{1} (Domain mode auto-discovery)"),

    // ── 连接过的设备列表 ──
    ("connect.devices.title", "连接过的设备:", "Previously connected devices:"),
    ("connect.devices.empty", "暂无记录 — 连接成功后自动保存", "No records yet — saved automatically after a successful connection"),

    // ── M8-T040 (W3-A): 域名模式加密 DNS 解析状态行（DDNS-UI-007）──
    ("connect.dnssec.resolving", "加密 DNS 解析中（DoH/DoT）…", "Resolving via encrypted DNS (DoH/DoT)…"),
    ("connect.dnssec.resolved", "加密 DNS 解析完成（{0}）", "Encrypted DNS resolved ({0})"),
    // R-30（审计 §8-2）：解析返回合法空列表时如实提示（连接沿用 discovery 地址，行为不变）。
    ("connect.dnssec.no_records", "加密 DNS 解析完成：无记录（沿用发现地址连接）", "Encrypted DNS resolved: no records (connecting via discovered address)"),
    ("connect.dnssec.refused", "加密 DNS 不可用，连接被拒（域名模式强制 DoH/DoT，DDNS-DOH-003）", "Encrypted DNS unavailable — connection refused (Domain mode requires DoH/DoT, DDNS-DOH-003)"),
];
