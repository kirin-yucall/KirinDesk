//! M8-T038 (P5): Dashboard 页键值表（zh 基线 + en 全量）。
//! 本分区文件由 M8-T038_P5 独占认领。
//!
//! zh 为基线语言包；en 全量翻译（不得留空串）。
//! 动态文案模板使用 `{0}`/`{1}` 位置参数，zh/en 占位符一一对应。
//! 公网检测提示为 M8-T037 用户要求逐字文案——zh 模板保持逐字不变。

pub static TABLE: &[(&str, &str, &str)] = &[
    // ── 页面标题 / 身份卡 ──
    ("dashboard.title", "仪表盘", "Dashboard"),
    ("dashboard.identity.title", "身份", "Identity"),
    ("dashboard.identity.device_id", "设备 ID：", "Device ID:"),
    ("dashboard.identity.ipv6", "IPv6：", "IPv6:"),
    ("dashboard.identity.ipv4", "IPv4：", "IPv4:"),
    ("dashboard.identity.domain", "域名：", "Domain:"),
    ("dashboard.identity.listen_port", "监听端口：", "Listen Port:"),
    // M8-T037 逐字文案（zh 不改动）。
    ("dashboard.identity.dot_public", "公网地址，可直连", "Public address — directly connectable"),
    ("dashboard.identity.dot_private",
     "非公网地址，建议开启内网穿透或端口转发",
     "Non-public address — consider enabling intranet traversal or port forwarding"),
    ("dashboard.identity.probing", "公网检测中…", "Probing public reachability…"),
    ("dashboard.identity.no_public",
     "无公网地址建议开启内网穿透或端口转发",
     "No public address — consider enabling intranet traversal or port forwarding"),

    // ── Server 卡 ──
    ("dashboard.server.title", "服务器", "Server"),
    ("dashboard.server.allow_controlled", "允许受控", "Allow controlled"),
    ("dashboard.server.allow_controlled_hint",
     "开：开始监听（下次生效昵称/挑战码/工作模式）；关：停止监听。bind 失败时开关自动回位并显示原因。",
     "On: start listening (nickname/challenge/mode take effect next start); Off: stop listening. On bind failure the switch snaps back and shows the reason."),
    ("dashboard.server.listening", "监听中 :{0}", "Listening :{0}"),
    ("dashboard.server.start_failed", "启动失败: {0}", "Start failed: {0}"),
    ("dashboard.server.stopped", "已停止", "Stopped"),
    ("dashboard.server.allow_mic", "允许麦克风", "Allow microphone"),
    ("dashboard.server.audio_direction", "服务端声音 → 客户端", "server audio → client"),
    ("dashboard.server.allow_mic_hint",
     "关：服务端不再发送本机声音——运行中会话立即停止，再开即恢复（无需重连）",
     "Off: the server stops sending local audio — running sessions stop immediately; turning back on resumes without reconnecting"),
    ("dashboard.server.mode_label", "工作模式：{0}", "Working mode: {0}"),
    ("dashboard.server.mode_ip", "IP 模式", "IP Mode"),
    ("dashboard.server.mode_domain", "域名模式", "Domain Mode"),
    ("dashboard.server.mode_hint",
     "点击互换（下次启动服务端生效；保存后重启保持）",
     "Click to toggle (takes effect on next server start; persists after Save & restart)"),
    ("dashboard.server.status_listening", "监听中", "Listening"),

    // ── 临时连接 ──
    ("dashboard.temp.title", "临时连接", "Temp connection"),
    ("dashboard.temp.unavailable", "无人值守模式下不可用", "Unavailable under unattended mode"),
    ("dashboard.temp.remaining",
     "剩余 {0}:{1}（窗口期内跳过白名单）",
     "Remaining {0}:{1} (whitelist bypassed during the window)"),
    ("dashboard.temp.hint",
     "窗口期内跳过白名单（默认 5 分钟，过期自动关闭）",
     "Bypasses the whitelist during the window (default 5 minutes, auto-closes after expiry)"),
    ("dashboard.temp.toggle_hint",
     "开：生成 10 位临时挑战码并限时跳过域名白名单；关：立即恢复白名单验证；过期自动回位（逐连接判定，无需重连）。",
     "On: generates a 10-digit temp challenge code and bypasses the domain whitelist for a limited time; Off: restores whitelist verification immediately; auto-resets on expiry (per-connection, no reconnect needed)."),
    ("dashboard.temp.closed", "临时连接已关闭", "Temp connection closed"),
    ("dashboard.temp.expired", "临时连接已失效", "Temp connection expired"),
    ("dashboard.temp.enabled", "临时连接已开启（{0} 分钟）", "Temp connection enabled ({0} min)"),
    ("dashboard.temp.enable_failed", "开启失败：{0}", "Enable failed: {0}"),
    ("dashboard.temp.hide_code", "隐藏临时码", "Hide temp code"),
    ("dashboard.temp.hidden", "临时码已隐藏（仅展示一次）", "Temp code hidden (shown only once)"),
    ("dashboard.temp.not_stored",
     "临时码已在开启时展示一次，未落盘保存（TMP-SEC-001）；再次查看需重新开启（生成新码）。",
     "The temp code was shown once at enable time and is not persisted (TMP-SEC-001); to see it again, re-enable (generates a new code)."),
    ("dashboard.temp.window_note",
     "窗口期内跳过域名白名单，任何持有此码的客户端均可连接。",
     "The domain whitelist is bypassed during the window — any client holding this code can connect."),
    ("dashboard.temp.badge_on", "临时模式：开启（跳过白名单）", "Temp Mode: ON (whitelist bypassed)"),
    ("dashboard.temp.window_badge", "临时窗口：开启", "Temp Window: ON"),

    // ── 状态行 / 徽标 ──
    ("dashboard.unattended_badge", "无人值守", "Unattended"),
    ("dashboard.pending_fmt", "待审批连接 {0} 个", "{0} pending connection(s)"),

    // ── 高危警告（F-1/F-2）──
    ("dashboard.risk.high_risk",
     "⚠ 高风险：白名单旁路（IP/临时模式）已开启但挑战码为空——旁路连接携带零凭据，将被拒绝（fail-closed）。请在下方「服务端设置」配置挑战码以放行。",
     "⚠ HIGH RISK: whitelist bypass (IP/Temp mode) is ON but Challenge Code is empty — bypass connections carry zero credentials and will be REJECTED (fail-closed, F-1/F-2). Set a challenge code in Server settings below to allow them."),

    // ── 服务端设置卡 ──
    ("dashboard.server_settings.title", "服务端设置", "Server settings"),
    ("dashboard.server_settings.port_invalid", "端口需为 1–65535", "Port must be 1-65535"),
    ("dashboard.server_settings.port", "端口：", "Port:"),
    ("dashboard.server_settings.nickname", "昵称：", "Nickname:"),
    ("dashboard.server_settings.challenge", "挑战码：", "Challenge Code:"),
    ("dashboard.server_settings.required", "必填", "required"),
    ("dashboard.server_settings.optional", "选填", "optional"),
    ("dashboard.server_settings.desc",
     "服务端启动时读取本值——下次启动服务端生效（不热改已运行会话）。传入客户端必须携带该昵称；挑战码为白名单旁路放行的前提。",
     "Read at server start — takes effect on next start (running sessions are not hot-updated). Connecting clients must carry this nickname; the challenge code is a prerequisite for whitelist bypass."),
    ("dashboard.server_settings.save", "保存", "Save"),
    ("dashboard.status.saved", "已保存（下次启动服务端生效）", "Saved (takes effect on next server start)"),
    ("dashboard.status.save_failed", "保存失败: {0}", "Save failed: {0}"),

    // ── 文件传输卡 / Live Log ──
    ("dashboard.file_transfer.title", "文件传输（服务端）", "File transfer (server)"),
    ("dashboard.file_transfer.empty",
     "无已连接客户端 — 客户端连接后，可拖拽文件到本窗口推送（服务端 → 客户端）。\n客户端推送的文件将静默接收至下载目录。",
     "No client connected — once a client connects, drag files into this window to push them (server → client).\nFiles pushed by the client are silently received into the download directory."),
    ("dashboard.log.title", "实时日志", "Live Log"),
    ("dashboard.log.empty", "（暂无日志输出）", "(no log output yet)"),
];
