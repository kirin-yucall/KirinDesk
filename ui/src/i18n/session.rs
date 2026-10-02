//! M8-T038 (P6): 会话窗口与弹窗键值表（zh 基线 + en 全量）。
//! 本分区文件由 M8-T038_P6 独占认领。
//!
//! zh 为基线语言包；en 全量翻译（不得留空串）。
//! 动态文案模板使用 `{0}`/`{1}` 位置参数，zh/en 占位符一一对应。
//! 含全局导航（标签页/状态栏）——位于 P6 声明的 lib.rs 3893-5250 区域带内。

pub static TABLE: &[(&str, &str, &str)] = &[
    // ── 全局导航（标签页 / 状态栏）──
    ("session.tab.dashboard", "仪表盘", "Dashboard"),
    ("session.tab.domain", "域名", "Domain"),
    ("session.tab.devices", "设备", "Devices"),
    ("session.tab.connect", "连接", "Connect"),
    ("session.tab.settings", "设置", "Settings"),
    ("session.pending_fmt", "⚡ {0} 个待审批！", "⚡ {0} pending!"),
    ("session.statusbar.dns_na", "DNS: 未配置", "DNS: Not configured"),
    ("session.statusbar.dns_ready", "DNS: 就绪", "DNS: Ready"),
    ("session.statusbar.server_listening", "服务端：监听中", "Server: Listening"),
    ("session.statusbar.server_stopped", "服务端：已停止", "Server: Stopped"),
    ("session.statusbar.copied", "已复制：{0}", "Copied: {0}"),

    // ── 弹窗（panic / 审批 / 指纹确认 / 文件接收）──
    ("dialog.panic.title", "程序异常（panic）", "Program Panic"),
    ("dialog.panic.body",
     "程序发生未处理异常（panic），可能不稳定。建议尽快重启应用。",
     "An unhandled panic occurred; the app may be unstable. It is recommended to restart soon."),
    ("dialog.panic.log_label", "日志文件：", "Log file:"),
    ("dialog.close", "关闭", "Close"),
    ("dialog.approve.title", "传入连接", "Incoming Connection"),
    ("dialog.approve.desc",
     "白名单外的设备正在尝试连接：",
     "A device outside your whitelist is trying to connect:"),
    ("dialog.approve.domain", "域名：{0}", "Domain: {0}"),
    ("dialog.approve.fingerprint", "指纹：{0}", "Fingerprint: {0}"),
    ("dialog.approve.known_hint",
     "批准后此公钥写入 known_clients，下次同设备连接自动放行",
     "On approval this public key is written to known_clients; the next connection from this device is auto-approved"),
    ("dialog.approve.accept", "✓ 接受", "✓ Accept"),
    ("dialog.approve.reject", "✗ 拒绝", "✗ Reject"),
    // 与审批弹窗 `dialog.approve.desc` 同源语义，短文案适配气泡尺寸）。
    ("dialog.approve.balloon",
     "设备 {0} 正在请求连接——左键托盘图标打开审批",
     "Device {0} is requesting a connection — left-click the tray icon to approve"),
    ("dialog.pubkey_fmt", "公钥：{0}…", "Pubkey: {0}…"),
    ("dialog.fingerprint.title", "首次连接指纹确认", "First-connection fingerprint confirmation"),
    ("dialog.fingerprint.body",
     "这是第一次连接该设备。请核对远端 Ed25519 公钥指纹，\n与设备持有者提供的指纹一致才可继续（防中间人攻击）。",
     "This is the first connection to this device. Verify the remote Ed25519 public key fingerprint —\ncontinue only if it matches the fingerprint provided by the device owner (MITM protection)."),
    ("dialog.fingerprint.device_label", "设备：", "Device:"),
    ("dialog.fingerprint.sha_hint", "服务端 Ed25519 公钥的 SHA-256", "SHA-256 of the server's Ed25519 public key"),
    ("dialog.fingerprint.short_code_hint",
     "⚠ 本次由短码发起：短码一致不能证明身份——必须与对端展示的完整 79 位指纹逐段比对后才能接受",
     "⚠ Started from a short code: a matching short code does NOT prove identity — accept only after comparing the full 79-char fingerprint segment by segment"),
    ("dialog.fingerprint.confirm", "✓ 接受并连接", "✓ Accept & Connect"),
    ("dialog.fingerprint.reject", "✗ 拒绝", "✗ Reject"),
    ("dialog.file_received.title", "📁 文件接收完成", "📁 File received"),

    // ── 会话窗口标题 ──
    // 标题括注键——案 A 下文件会话握手 device_type="shell"，标题括注按
    // `win.kind` 映射为「文件传输」而非 "(shell)"。本岗先入表（A2 消费）。
    ("session.window.file", "文件传输", "File Transfer"),

    // ── 会话窗口状态栏 ──
    ("session.statusbar.shell_hint", "远程 Shell — PTY 会话（ANSI + 回滚）", "Remote Shell — PTY session (ANSI + scrollback)"),
    ("session.statusbar.fps_placeholder", "FPS: --  BW: --  Res: --", "FPS: --  BW: --  Res: --"),
    // 徽标移除而删除（与右端显示器下拉重复，用户裁定冗余）；`primary_suffix`
    // 仍被显示器下拉选项行使用（保留）。
    ("session.statusbar.primary_suffix", " [主屏]", " [primary]"),
    ("session.statusbar.nack", "⛔ {0}", "⛔ {0}"),
    ("session.statusbar.privacy_black", "🛡 黑屏", "🛡 Black screen"),
    ("session.statusbar.privacy_lock", "🔒 锁屏", "🔒 Locked"),
    // disabled）随状态栏音频徽标渲染点移除而成对删除（zh/en 同 tuple）——
    // 按钮（图标态 🔊/🔇）零改动保留。三键名全树 0 命中由 i18n 测试钉死。

    // ── 会话窗口工具栏 ──
    ("session.toolbar.display_placeholder", "显示器", "Display"),
    ("session.toolbar.display_refresh", "刷新显示器列表", "Refresh display list"),
    // 说明）。zh/en 成对申报。
    // → 「后续版本提供」口径移除；三档说明整体 = **暂稿**（用户终稿 = 待用户
    ("session.toolbar.display_mode.title",
     "显示模式（点击三选一：流畅 / 低延迟 / 高画质）\n低延迟=永远优先展示最新画面，网络慢时直接跳过旧帧（允许跳变）；流畅=逐帧现状；高画质=编码目标码率升至分辨率阶梯 2 倍，文字与细节更清晰（耗带宽更高，网络慢时自动降档优先保流畅）",
     "Display mode (click to pick one of three: Smooth / Low latency / High quality)\nLow latency = always show the newest picture first, skipping stale frames when the network is slow (jumps allowed); Smooth = frame by frame as-is; High quality = 2x target bitrate for sharper text and detail (uses more bandwidth; slow networks still degrade first to keep things smooth)"),
    ("session.toolbar.display_mode.smooth", "流畅", "Smooth"),
    ("session.toolbar.display_mode.low_latency", "低延迟", "Low latency"),
    ("session.toolbar.display_mode.high_quality", "高画质", "High quality"),
    ("session.toolbar.special_keys", "特殊键 (Win / Alt+Tab / 锁屏)", "Special keys (Win / Alt+Tab / Lock)"),
    // 移除，`session.toolbar.caps_lock` / `kp_multiply` / `kp_decimal` 三键零
    // 消费一并删除（zh/en 成对删除，配对完整性由单测回归钉死）。
    // 用户「开音频」操作落在客户端侧控件（🔊/🎤 均不写被控端
    // server_audio_allowed），79 端置位行零命中；「听到服务端声音」的
    // 唯一开关在被控端 Dashboard「服务端音频」，客户端侧必须指路。
    ("session.toolbar.audio_play", "播放音频：服务端声音 → 本机（关闭 = 静音）。本机无声时：先在被控端 Dashboard 打开「服务端音频」开关", "Play audio: server sound → this machine (off = mute). If silent: enable the \"Server audio\" switch on the controlled end's Dashboard first"),
    ("session.toolbar.mic", "麦克风：本机麦克风 → 服务端播放（talkback，默认关）。与「听到服务端声音」无关——那是被控端 Dashboard 的「服务端音频」开关", "Microphone: this machine's mic → server playback (talkback, off by default). Unrelated to hearing the server's sound — that is the \"Server audio\" switch on the controlled end's Dashboard"),
    ("session.toolbar.file", "文件传输面板 (拖拽发送)", "File transfer panel (drag & drop to send)"),
    ("session.toolbar.fullscreen", "全屏 (F11)", "Fullscreen (F11)"),
    ("session.toolbar.disconnect", "断开连接", "Disconnect"),
    // 两钮迷你条（原单把手消费移除，`session.toolbar.handle` 键随之零消费
    // 删除；新键 `session.toolbar.expand` zh/en 成对）。
    ("session.toolbar.collapse",
     "收起工具栏：画面顶部留「全屏 + 展开工具栏」两钮迷你条（点击展开）",
     "Collapse toolbar: leaves a mini bar with Fullscreen + Expand buttons at the top (click Expand to restore)"),
    ("session.toolbar.hide",
     "隐藏工具栏：全幅画面；鼠标移到窗顶边缘（或右上角标记）临时找回",
     "Hide toolbar: full-screen video; move the mouse to the top window edge (or the top-right mark) to bring it back"),
    ("session.toolbar.restore",
     "恢复工具栏常驻",
     "Restore toolbar to always visible"),
    ("session.toolbar.expand",
     "展开工具栏",
     "Expand toolbar"),
    ("session.toolbar.drag",
     "拖动移动工具栏（位置仅本会话记忆）",
     "Drag to move the toolbar (position remembered for this session)"),

    // ── 特殊键面板 ──
    ("session.special_key.title", "特殊键", "Special keys"),
    ("session.special_key.macos_alt_tab",
     "被控端为 macOS：不支持 Alt+Tab（Cmd+Tab 为系统 UI）",
     "Remote is macOS: Alt+Tab unsupported (Cmd+Tab is the system UI)"),
    ("session.special_key.cac_hint",
     "Ctrl+Alt+Del 为系统安全序列，普通进程不可注入 — 以「锁屏」代替",
     "Ctrl+Alt+Del is a system secure sequence that normal processes cannot inject — use \"Lock\" instead"),
    ("session.special_key.win_e", "Win+E", "Win+E"),
    ("session.special_key.win_d", "Win+D", "Win+D"),
    ("session.special_key.win_l", "Win+L", "Win+L"),
    ("session.special_key.win_r", "Win+R", "Win+R"),
    ("session.special_key.alt_tab", "Alt+Tab", "Alt+Tab"),
    ("session.special_key.ctrl_shift_esc", "Ctrl+Shift+Esc", "Ctrl+Shift+Esc"),
    ("session.special_key.alt_f4", "Alt+F4", "Alt+F4"),
    ("session.special_key.ctrl_esc", "Ctrl+Esc", "Ctrl+Esc"),
    ("session.special_key.lock_screen", "锁屏", "Lock"),
    ("session.special_key.win_e_hint", "打开文件资源管理器", "Open File Explorer"),
    ("session.special_key.win_d_hint", "显示桌面", "Show desktop"),
    ("session.special_key.win_l_hint", "锁定（Win+L 可注入）", "Lock (Win+L is injectable)"),
    ("session.special_key.win_r_hint", "打开运行对话框", "Open the Run dialog"),
    ("session.special_key.alt_tab_hint",
     "切换窗口（被控端前台无捕获窗口时）",
     "Switch windows (when the remote foreground has no capture window)"),
    ("session.special_key.ctrl_shift_esc_hint", "打开任务管理器", "Open Task Manager"),
    ("session.special_key.alt_f4_hint", "关闭前台窗口", "Close the foreground window"),
    ("session.special_key.ctrl_esc_hint", "打开开始菜单", "Open the Start menu"),
    ("session.special_key.lock_screen_hint",
     "系统限制（Ctrl+Alt+Del 不可注入），以锁屏代替",
     "System restriction (Ctrl+Alt+Del not injectable) — use lock instead"),

    // ── 隐私菜单 / toast ──
    ("session.privacy.menu_idle", "🛡 隐私", "🛡 Privacy"),
    ("session.privacy.menu_black", "🛡 黑屏", "🛡 Black screen"),
    ("session.privacy.menu_lock", "🛡 锁屏", "🛡 Locked"),
    ("session.privacy.black_action", "隐藏被控端屏幕（黑屏）", "Hide the remote screen (black)"),
    ("session.privacy.black_hint",
     "被控端屏幕被纯黑覆盖；远程操作与输入注入照常",
     "The remote screen is covered in pure black; remote control and input injection keep working"),
    ("session.privacy.lock_action", "锁定被控端", "Lock the remote"),
    ("session.privacy.lock_hint",
     "系统锁屏；锁屏后输入注入暂停，解锁自动恢复",
     "System lock; input injection pauses while locked and resumes on unlock"),
    ("session.privacy.restore", "恢复屏幕", "Restore screen"),
    ("session.privacy.locked_note", "被控端已锁定，输入暂停", "Remote is locked — input paused"),
    ("session.privacy.input_paused",
     "🔒 被控端已锁定，输入暂停（解锁后自动恢复）",
     "🔒 Remote is locked — input paused (resumes automatically after unlock)"),
    ("session.privacy.toast_title", "🛡 隐私模式", "🛡 Privacy mode"),

    ("session.focus.lost_hint",
     "⚠ 未聚焦 —— 点击窗口恢复键盘控制",
     "⚠ Not focused — click the window to restore keyboard control"),

    // ── 断线 / 重连覆盖层 ──
    ("session.reconnect.lost", "连接已断开", "Connection lost"),
    // 收到任何视频帧——区别于普通断连：连接建立成功但对端未产出画面流，
    // 典型 = 对端服务异常/未出流，而非网络中断）。
    ("session.reconnect.lost_no_frame",
     "连接已建立但未收到画面流",
     "Connection established but no video stream received"),
    ("session.reconnect.button", "重新连接", "Reconnect"),
    ("session.reconnect.retrying", "自动重连中（第 {0} 次/共 {1} 次）", "Auto-reconnecting (attempt {0} of {1})"),
    ("session.reconnect.unsupported",
     "无法自动重连（该连接方式不支持自动重连，请手动重连）",
     "Cannot auto-reconnect (this connection type does not support auto-reconnect; please reconnect manually)"),

    // ── Shell 终端 ──
    ("session.shell_not_initialized", "Shell 终端未初始化。", "Shell terminal not initialized."),

    // ── 连接失败引导提示（policy.rs 消费；zh 逐字保持，单测断言子串）──
    ("policy.challenge_hint.temp",
     "提示：此挑战码符合临时连接码格式。连接被拒通常是：\n  \
      1) 临时窗口已过期或未开启 —— 请服务端执行 `kirin_desk status` 确认（Temp Mode: ACTIVE）；\n  \
      2) 窗口已过期 —— 请服务端重新执行 `kirin_desk temp-mode` 获取新码；\n  \
      3) 码输入有误 —— 逐字符核对（临时码不含 0/O/1/I）。",
     "Hint: this challenge code matches the temp-connection format. A rejected connection usually means:\n  \
      1) The temp window has expired or was never opened — ask the server to run `kirin_desk status` (Temp Mode: ACTIVE);\n  \
      2) The window has expired — ask the server to run `kirin_desk temp-mode` again for a new code;\n  \
      3) The code was entered incorrectly — check it character by character (temp codes exclude 0/O/1/I)."),
    ("policy.challenge_hint.fixed",
     "提示：连接被拒通常是对端挑战码/凭据校验未通过：\n  \
      1) 固定挑战码错误 —— 与服务端 `challenge_code` 配置核对；\n  \
      2) 若使用临时连接码 —— 窗口可能已过期，请服务端重新执行 `kirin_desk temp-mode`；\n  \
      3) 确认服务端未处于无人值守模式（该模式下无临时放行路径）。",
     "Hint: a rejected connection usually means the remote challenge/credential check failed:\n  \
      1) Wrong fixed challenge code — compare it with the server's `challenge_code` config;\n  \
      2) If using a temp code — the window may have expired; ask the server to run `kirin_desk temp-mode` again;\n  \
      3) Make sure the server is not in unattended mode (no temp bypass path in that mode)."),
];
