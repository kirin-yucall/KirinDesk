//! M8-T038 (P4): Connect 页键值表（zh 基线 + en 全量）。
//! 本分区文件由 M8-T038_P4 独占认领。
//!
//! zh 为基线语言包（当前界面文案统一后的中文版本）；en 全量翻译（不得留空串）。
//! 动态文案模板使用 `{0}`/`{1}` 位置参数，zh/en 占位符一一对应。
//! 注：`devices.menu.*` 与 Devices 页共用（P5 键表定义，此处仅消费，避免

pub static TABLE: &[(&str, &str, &str)] = &[
    // ── 页面标题 / 模式 / 日志 ──
    ("connect.title", "连接设备", "Connect to Device"),
    ("connect.mode.ip", "IP 模式（直接 IP 连接）", "IP Mode (direct IP connection)"),
    ("connect.mode.domain", "域名模式（DNS 发现）", "Domain Mode (DNS-based discovery)"),
    ("connect.mode.id", "ID 模式（relay 设备 ID）", "ID Mode (relay device ID)"),
    ("connect.log.title", "连接日志：", "Connection Log:"),
    ("connect.log.empty", "（暂无连接日志）", "(no connection log yet)"),
    // 传输行「目录」段（蓝字可点击复制路径）+ 悬停 1s 提示 + 本机端标识 +
    // 对端目录未知标记（协议仅暴露根相对形态，对端绝对根不可知）。
    ("connect.log.dir", "目录", "dir"),
    ("connect.log.dir_tip", "点击复制路径", "Click to copy path"),
    ("connect.log.side_local", "本机", "local"),
    ("connect.log.side_peer", "对端", "peer"),
    ("connect.log.dir_root", "根", "root"),
    // （下载散落）+ 同名冲突后写覆盖。zh/en 成对。
    ("connect.log.r154_landing_fallback", "下载落点未命中（登记过期或同名覆写），已改存到默认接收目录", "Download landing miss (registry expired or same-name overwritten) — saved to default download directory"),
    ("connect.log.r154_landing_conflict", "同名文件落点登记被后写覆盖（取最后一次登记）", "Same-name file landing registry overwritten (last registration wins)"),
    // 终态 / 对端开关自动拒绝 / 配置损坏 fail-closed。zh/en 成对。
    ("connect.log.r155_entry_off_root", "上传条目在允许目录之外，已跳过（该文件未发送）", "Upload entry outside allowed roots — skipped (file not sent)"),
    ("connect.log.r155_zero_batch", "上传未能入队（条目全部无效或在允许目录之外）——任务已终止", "Upload could not be enqueued (all entries invalid or outside allowed roots) — task terminated"),
    ("connect.log.r155_consent_declined", "对方文件传输开关已关闭，传输被自动拒绝", "Peer file transfer switch is OFF — transfer auto-declined"),
    ("connect.log.r155_config_invalid", "配置文件损坏或不可读——文件传输/剪贴板开关按关处理（fail-closed）", "Config file corrupt or unreadable — transfer/clipboard switches fail-closed OFF"),
    // 拒绝 / s→c ClipMeta 到达 / 拉取派发 / 目录展开完成。zh/en 成对。
    ("connect.log.r156_paste_upload", "粘贴上传已开始：目录 {0} 个、文件 {1} 个", "Paste upload started: {0} director(ies), {1} file(s)"),
    ("connect.log.r156_dir_rejected", "剪贴板中 {0} 个目录条目无法粘贴上传（无远端落点语境，请打开文件传输窗后重试）", "{0} director(ies) in the clipboard cannot be pasted for upload (no remote landing context — open the file transfer window and retry)"),
    ("connect.log.r156_clip_meta", "对端已共享剪贴板文件清单（{0} 项）——可在文件传输窗 Ctrl+V 拉取", "Peer shared a clipboard file list ({0} item(s)) — press Ctrl+V in the file transfer window to fetch"),
    ("connect.log.r156_fetch_dispatch", "剪贴板拉取已派发：文件 {0} 个、目录 {1} 个（目录将逐层展开后逐文件拉取）", "Clipboard fetch dispatched: {0} file(s), {1} director(ies) (directories expand level by level, then per-file fetch)"),
    ("connect.log.r156_fetch_done", "剪贴板目录拉取完成：文件 {0} 个、展开目录 {1} 个", "Clipboard directory fetch finished: {0} file(s) fetched, {1} director(ies) expanded"),
    // （预取开始/就绪/失败降级/目录边界/c→s 直传；zh/en 成对）。
    ("connect.log.r166_prefetch_started", "直贴预取中：{0} 个文件后台拉取至本机缓存（完成后系统剪贴板可直接粘贴）", "Direct paste prefetch: fetching {0} file(s) to local cache in background (system clipboard will be ready when complete)"),
    ("connect.log.r166_prefetch_ready", "直贴就绪：{0} 个文件已写入系统剪贴板，资源管理器/桌面 Ctrl+V 即可粘贴", "Direct paste ready: {0} file(s) written to the system clipboard — press Ctrl+V in Explorer/desktop to paste"),
    ("connect.log.r166_prefetch_failed", "直贴预取未完成（超时/对端中断），已回退应用内两段式粘贴；缓存已清理", "Direct paste prefetch incomplete (timeout/peer interrupted) — fell back to in-app two-step paste; cache cleaned"),
    ("connect.log.r166_dirs_fallback", "直贴阶段一暂不含文件夹条目——本批走应用内两段式粘贴（文件传输窗可用）", "Direct paste phase 1 skips folder entries — batch uses in-app two-step paste (file transfer window)"),
    ("connect.log.r166_c2s_started", "直贴上传中：{0} 个文件送至对端缓存（对端系统剪贴板就绪后可直接粘贴）", "Direct paste upload: sending {0} file(s) to peer cache (peer system clipboard will be ready to paste)"),
    // + 渲染完成/失败回退行。zh/en 成对。
    ("connect.log.r194_armed", "延迟渲染已布防：对端复制 {0} 个文件（零数据传输，粘贴时按需拉取，资源管理器 Ctrl+V 可直接粘贴）", "Delayed rendering armed: peer copied {0} file(s) (zero data on copy — fetched on paste; Ctrl+V in Explorer works directly)"),
    ("connect.log.r194_render_done", "按需拉取完成：{0} 个文件已就绪，本次系统粘贴已供数", "On-demand fetch complete: {0} file(s) ready — system paste served"),
    ("connect.log.r194_render_fail", "按需拉取未完成（{0}/{1} 个文件，超时或对端不可达）——本次系统粘贴未供数，请改用文件传输窗 Ctrl+V 拉取", "On-demand fetch incomplete ({0}/{1} file(s), timeout or peer unreachable) — system paste not served; use Ctrl+V in the file transfer window instead"),
    // 回退两段式，连接页 Warn 一行。zh/en 成对。
    ("connect.log.r186_cache_dir_refused", "直贴缓存目录异常（符号链接/联接），已拒绝使用并回退两段式粘贴", "Direct paste cache directory abnormal (symlink/junction) — refused and fell back to two-step paste"),
    // 非文本输入）= 连接页 Warn 显式提示（修前零动作静默，egui 默认文本
    // 粘贴读 OS 板空报错误现）。zh/en 成对。
    ("connect.log.r164_paste_focus_hint", "剪贴板粘贴未执行（焦点不在文件面板）：请点击文件面板后按 Ctrl+V", "Clipboard paste skipped (file panel not focused): click the file panel, then press Ctrl+V"),
    // 传输日志行模板（「目录」段在构建函数内独立成段，不走 {n} 占位）：
    // `从（{0}）` + 目录段 + `到（{1}）` + 目录段 + `文件或文件夹（{2}）`
    // [+ 失败后缀 `—— 失败：{3}`]。
    // 指出「那个文件传输可能是下载也可能是上传」，方向语义须入行首，
    // 从/到两侧按事件真实方向归属（不得固定一侧）。
    ("connect.log.transfer.dir_upload", "上传：", "Upload: "),
    ("connect.log.transfer.dir_download", "下载：", "Download: "),
    ("connect.log.transfer.from", "从（{0}）", "From ({0})"),
    ("connect.log.transfer.to", " 到（{0}）", " to ({0})"),
    ("connect.log.transfer.what", " 文件或文件夹（{0}）", " file or folder ({0})"),
    ("connect.log.transfer.failed", " —— 失败：{0}", " — failed: {0}"),

    // ── 表单标签 / 占位 ──
    ("connect.label.ip", "IP 地址：", "IP Address:"),
    ("connect.label.port", "端口：", "Port:"),
    ("connect.label.nickname", "昵称（发送给服务端）：", "Nickname (sent to server):"),
    ("connect.label.challenge", "挑战码（发送给服务端）：", "Challenge (sent to server):"),
    // 与 Dashboard 身份卡的 DNS 设备别名（设备 ID，新格式 10 位数字字母混合；
    // 旧设备 HD- 格式）明确区分。
    ("connect.label.device_id", "设备 ID（短码 / 完整指纹均可）：", "Device ID (short code or full fingerprint):"),
    ("connect.placeholder.device_id",
     "粘贴 10 位短码或完整设备 ID（自动去空格/冒号、忽略大小写）",
     "Paste the 10-char short code or the full device ID (spaces/colons & case are normalized)"),
    // 已随渲染点整体删除（用户要求移除；门禁 = i18n/mod.rs
    // r145_removed_device_id_hint_key_gone，注释避全键名字面量）。
    ("connect.label.domain", "域名：", "Domain:"),
    ("connect.label.id_nickname", "昵称（会话显示名）：", "Nickname (session display name):"),
    ("connect.label.id_challenge", "挑战码（目标设备）：", "Challenge (target device):"),
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
    ("connect.error.challenge_empty", "请输入目标设备挑战码", "Enter the target device's challenge code"),
    ("connect.error.domain_empty", "请输入远端域名", "Enter the remote domain"),
    ("connect.error.godaddy_missing",
     "GoDaddy API 未配置 — 请先在 Settings 中配置",
     "GoDaddy API not configured — configure it in Settings first"),
    // 结构化拒绝文案，本键只覆盖「等待中」）──
    ("connect.status.waiting_approval", "等待对方审批中…", "Waiting for remote approval…"),
    // 倒计时结束按钮恢复可用——防打穿对端限流 SRV-SEC-RL-001/002）。
    ("connect.status.retry_backoff",
     "连接失败退避中，{0} 秒后可再试（连续失败等待自动拉长，避免对端限流/封禁）",
     "Backing off after connection failure — retry in {0}s (repeated failures lengthen the wait to avoid peer rate-limiting / ban)"),
    // 连接的状态修改为灰色并提示等待受控端允许受控」；PM 裁定：不做协议级
    // 「审批中」信号，用超时态+既有文案实现，零 wire 变更）：
    // `waiting_peer` = 状态区主文案（≥2.5s 未收到对端响应时点火，`{0}` = 等待
    // 计时秒数）；`waiting_peer_hint`/`_hint_first` = 次级中性提示（若对方开启
    // 审批需其确认后继续；首连追加指纹确认预告——安全红线不可免）；
    // `verifying` = 响应已收到子相位（验签/指纹确认，确认框为主呈现）──
    ("connect.status.waiting_peer",
     "等待受控端批准/处理中…（{0}s）",
     "Waiting for the controlled side to approve / process… ({0}s)"),
    ("connect.status.waiting_peer_hint",
     "若对方开启审批，需其确认后会话继续；连接完成前请勿重复点击连接",
     "If the remote side has approval enabled, the session continues after they confirm; please do not click Connect repeatedly until it completes"),
    ("connect.status.waiting_peer_hint_first",
     "若对方开启审批，需其确认后会话继续；首次连接还需在本机确认对方指纹",
     "If the remote side has approval enabled, the session continues after they confirm; a first connection also requires confirming the peer's fingerprint on this machine"),
    ("connect.status.verifying",
     "已收到对端响应，正在校验对方身份…",
     "Response received — verifying the peer's identity…"),
    // 确认期状态显示「等待对方审批中…」被误认为对方审批、干等 2m36s）：
    // `fp_confirm` = 指纹确认 gate 开启期间连接页状态行主文案（该阶段对端
    // 并非在等审批，是本机在等用户确认对端指纹；仅显示层覆盖，原始状态串
    // 不变 → busy/看门狗/置灰判定零变化）；`balloon.fingerprint` = 托盘
    ("connect.status.fp_confirm",
     "等待本机确认对端指纹…",
     "Waiting for local confirmation of the peer's fingerprint…"),
    ("connect.balloon.fingerprint",
     "首次连接需在本机确认对端指纹——请留意主窗口的指纹确认框比对后继续",
     "First connection — please confirm the peer's fingerprint in the main window's dialog before continuing"),

    ("connect.error.challenge_mismatch",
     "挑战码错误：目标设备拒绝了连接（请核对挑战码后重试）",
     "Challenge code mismatch: refused by the target device (check the challenge code and retry)"),
    ("connect.error.nickname_mismatch",
     "昵称不匹配：目标设备拒绝了连接（请核对目标昵称）",
     "Nickname mismatch: refused by the target device (check the target nickname)"),
    ("connect.error.client_key_mismatch",
     "目标拒绝：身份指纹不匹配（该设备已绑定其它客户端身份，或本机身份已轮换）",
     "Refused by target: identity fingerprint mismatch (the device is bound to a different client identity, or this machine's identity was rotated)"),
    ("connect.error.credentials_required",
     "目标设备要求凭据：请填写正确的挑战码后重试（服务端未配置挑战码时需在其设置中配置）",
     "The target device requires credentials: enter the correct challenge code and retry (if none is configured, set one in the target's settings)"),
    // `connect.error.approval_timeout`——旧服务端超时仍发本码，滚动升级
    // 期新客户端对旧服务端超时呈现为「被拒」，属可接受退化，不崩溃）。
    ("connect.error.approval_declined",
     "对方拒绝了连接请求（目标设备未审批放行）",
     "The remote side declined the connection request (not approved on the target device)"),
    // 层「对方离线」分类——B③ 四类状态呈现（审批中/超时/被拒/离线）配套，
    // 控制端不再呈现裸 "TCP early eof" 式传输错误 ──
    ("connect.error.approval_timeout",
     "对方审批超时：目标设备限时内无人审批，已主动断开——请确认目标设备有人处理审批后重试（或检查其审批提示音/托盘气泡）",
     "Approval timed out on the target: no one approved within the time limit and it closed the connection — verify the target device gets its approval prompt (tray/sound), then retry"),
    // 自动拒，UA-ACCEPT-002 准入语义零放宽）——可操作提示（区别于笼统
    // 「被拒」：告知对方设备处于无人值守模式、需加白名单/已知设备）。
    ("connect.error.unattended_unknown",
     "目标设备处于无人值守模式：仅白名单/已知设备可连接，请让对端将本设备加入白名单或已知设备",
     "The target device is in unattended mode: only whitelisted / known devices may connect — ask the peer to add this device to their whitelist or known clients"),
    ("connect.error.peer_offline",
     "对方离线：与目标设备的连接被中断（目标可能已关机/离线，或目标侧服务停止/模式切换）——请确认目标在线后重试",
     "Remote device offline: the connection was interrupted (it may be powered off, or its service stopped/mode-switched) — verify it is online, then retry"),
    // 级临时封禁（SRV-SEC-RL-001/002）；本端已自动退避，连续点击只会延长封禁。
    ("connect.error.rate_limited",
     "连接尝试过于频繁，已被目标设备限流（限流窗约 30 秒，连续失败可能触发更长的临时封禁）——本端已进入自动退避，倒计时结束后再试，请勿连续点击",
     "Too many connection attempts: rate-limited by the target device (window ≈ 30s; repeated failures can trigger a longer temporary ban) — this end is backing off automatically; retry after the countdown, avoid rapid repeated clicks"),
    ("connect.error.version_mismatch",
     "目标设备 KirinDesk 版本不兼容（协议版本不一致）——请两端更新到同一版本后重试",
     "Incompatible KirinDesk version on the target (protocol version mismatch) — update both ends to the same version and retry"),

    // denied = 被叫端兜底拒绝（新结构化拒绝码 mutual_control_denied，
    // 受控端准入臂 fail-closed 发出）；blocked = 发起端预检拦截（ID 模式
    // 入口在发起前自检：目标正控制本端）。
    ("connect.error.mutual_control_denied",
     "对端已按禁止互控策略拒绝：对端正在控制本机，反向控制被拒绝——待对端会话结束后重试（或在设置中关闭「禁止互相控制」）",
     "Rejected by the target under the forbid-mutual-control policy: the target is currently controlling this machine, so reverse control was denied — retry after that session ends (or turn off 'Forbid mutual control' in Settings)"),
    ("connect.error.mutual_control_blocked",
     "已按禁止互控策略拦截：目标设备正在控制本机，禁止反向发起控制——待该会话结束后重试（或在设置中关闭「禁止互相控制」）",
     "Blocked by the forbid-mutual-control policy: the target is currently controlling this machine — retry after that session ends (or turn off 'Forbid mutual control' in Settings)"),

    // 失败/异常路径全写终态（identity 缺失/非法可信公钥/指纹确认失败/线程 panic）
    // + 看门狗超时自动复位（按钮恢复可用）──────────────────────────────
    ("connect.error.identity_missing",
     "本机设备身份未加载，无法建立安全通道",
     "No local device identity loaded — cannot establish a secure channel"),
    ("connect.error.trusted_key_invalid",
     "带外可信公钥格式无效，连接已取消",
     "Out-of-band trusted public key is invalid — connection aborted"),
    ("connect.error.trust_rejected",
     "目标设备指纹未通过确认（不匹配或已取消），连接已终止",
     "Target device fingerprint not confirmed (mismatch or cancelled) — connection aborted"),
    ("connect.error.connect_thread_panic",
     "连接任务发生内部异常，按钮已恢复——请重试",
     "Internal error in the connection task — the button is restored, please try again"),
    ("connect.error.busy_timeout",
     "连接超时：长时间未收到目标设备响应（不可达或处理卡死）——按钮已恢复，请重试",
     "Connection timed out: the target never responded (unreachable or stuck) — the button is restored, please try again"),
    ("connect.error.waiting_timeout",
     "等待对方审批超时（长时间无响应）——按钮已恢复，请重试",
     "Waiting for remote approval timed out (no response) — the button is restored, please try again"),

    // 弹窗——内联状态行只留 Handshake FAILED + 分类文案首句，完整分类文案 +
    // 3 条排查提示进「查看详情」弹窗，不再挤压连接表单/底栏）──
    ("connect.failure_detail.title", "连接失败详情", "Connection failure details"),
    ("connect.failure_detail.show", "查看详情", "Details"),

    // ── 按钮 ──
    // 「远程桌面」——键名 `connect.button.connect` 不动（三表单调用点零改动），
    // 键文改 = 用户连接入口双选项命名（远程桌面/文件传输）直接落位。
    ("connect.button.connect", "远程桌面", "Remote Desktop"),
    ("connect.button.file", "文件传输", "File Transfer"),
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
    ("connect.id.history", "连接历史：", "Connection history:"),
    ("connect.id.history_pick", "选择已连接过的设备 ID…", "Pick a previously connected device ID…"),
    ("connect.id.qr_import", "从二维码图片识别…", "Recognize from QR image…"),
    ("connect.id.qr_import_hint",
     "选择包含设备 ID 二维码的图片文件；二维码只允许携带设备 ID 与昵称，含挑战码等凭据字段或解析失败将被拒绝（fail-closed）。",
     "Pick an image file containing the device ID QR; the QR may only carry the device ID and nickname — any credential field (e.g. challenge) or parse failure is rejected (fail-closed)."),
    ("connect.id.qr_import_ok", "二维码识别成功：{0}", "QR recognized: {0}"),
    ("connect.id.qr_import_fail",
     "二维码识别失败（内容不合法或解析失败，已拒绝 fail-closed）：{0}",
     "QR recognition failed (invalid content or parse failure — rejected, fail-closed): {0}"),
    ("connect.id.node", "relay 节点：", "Relay node:"),
    ("connect.id.node_pick", "选择节点（回填 [tunnel] 三件套）…", "Pick a node (fill [tunnel] triple)…"),
    ("connect.id.node_applied",
     "已把节点 {0} 回填到 [tunnel]（已保存；本次 ID 模式连接经该节点）",
     "Node {0} applied to [tunnel] (saved; this ID-mode connection goes via it)"),
    // 登录提示；`node_applied` 键保留零回归锚（生产面改用本键）。
    ("connect.id.node_applied_ix",
     "已把节点 {0} 应用到 [tunnel]（地址 + 公钥，已保存；节点 Token = 中继互联凭据，不用于客户端登录，登录 Token 保持原值）",
     "Node {0} applied to [tunnel] (address + pubkey saved; the node token is a relay interconnect credential, not used for client login — the login token is left unchanged)"),
    ("connect.id.node_apply_fail", "节点回填 [tunnel] 失败：{0}", "Failed to apply node to [tunnel]: {0}"),
    ("connect.id.node_missing", "节点不存在（可能已被删除）", "Node not found (it may have been deleted)"),
    ("connect.ready_id", "就绪：{0}（ID 模式，点击连接）", "Ready: {0} (ID mode — click Connect)"),
    ("connect.id.error_identity_missing",
     "设备 ID 模式：未加载本机身份",
     "ID mode: no local identity loaded"),
    ("connect.id.error_pubkey_missing",
     "ID 模式未配置 server_pubkey（tunnel serve 启动时输出）",
     "ID mode: server_pubkey not configured (printed at tunnel serve startup)"),
    ("connect.id.error_config", "ID 模式配置错误: {0}", "ID mode config error: {0}"),
    ("connect.id.error_resolve_signature",
     "解析响应签名校验失败（ID-SEC-001）— 可能 server_pubkey 错误或中间人",
     "Resolve response signature verification failed (ID-SEC-001) — wrong server_pubkey or MITM"),
    ("connect.id.error_resolve_failed", "解析失败: {0}", "Resolve failed: {0}"),
    // ≠ 在线）；「设备离线」高频场景 = 对端 KirinDesk 未运行或未点启动服务端。
    ("connect.id.error_offline",
     "设备 '{0}' 离线或未注册——请确认对方 KirinDesk 正在运行且已点击「启动服务端」（ID 在线注册随服务端启动生效，仅进程开着不算在线）",
     "Device '{0}' is offline or not registered — make sure the peer's KirinDesk is running AND its server has been started (ID registration goes online with the server; the app being open alone is not enough)"),
    ("connect.id.error_short_code_miss",
     "短码 '{0}' 未唯一命中（不存在或多台设备同前缀，服务器不区分二者）——请输入完整 79 位设备 ID 连接",
     "Short code '{0}' did not resolve uniquely (no match or multiple devices share the prefix; the server does not distinguish) — enter the full 79-char device ID"),
    ("connect.id.error_fingerprint_mismatch",
     "known_hosts 指纹不匹配 '{0}' — 拒绝连接（MITM 防护）",
     "known_hosts fingerprint mismatch for '{0}' — connection refused (MITM protection)"),
    ("connect.id.error_connect_failed", "连接失败（全部路径）: {0}", "Connection failed (all paths): {0}"),
    // 时自动落对方 ID 白名单，本拒因只出现在**从未被批准**的设备上。
    ("connect.id.error_whitelist_denied",
     "连接被拒：本设备 ID 未获对方 ID 白名单授权（对方已开启 ID 白名单强制，即使昵称和挑战码正确也不放行）——请在对方设备接受本设备的连接审批，或在对方「设置 → 白名单」把本设备 ID 加入 ID 白名单后再连",
     "Connection rejected: your device ID is not authorized by the peer's ID whitelist (whitelist enforcement is on; rejected even with correct nickname and challenge code) — approve this device's connection on the peer, or add its device ID to the peer's ID whitelist (Settings → Whitelist), then reconnect"),

    // ── 提示行 ──
    ("connect.hint.ip_mode", "IP 模式：直接 TCP，无 DNS 解析。", "IP mode: direct TCP, no DNS resolution."),
    ("connect.hint.ip_whitelist_na", "域名白名单不适用。", "Domain whitelist does not apply."),
    // 准确口径：控制端无需输入端口（目标由 relay 候选解析）；被控端监听
    // 端口转发/放行；中继兜底不依赖入站端口。
    ("connect.hint.id_mode",
     "ID 模式：控制端无需输入端口（目标地址由 relay 候选解析）；被控端监听端口（Server 设置，默认 59990）供直连/打洞——NAT 后需端口转发或放行该端口；中继兜底无需入站端口。",
     "ID mode: no port entry on the controller (the target is addressed via relay candidates); the controlled end listens on its Server port (default 59990) for direct/punch — forward or open this port behind NAT; the relay fallback needs no inbound port."),
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
    ("connect.dnssec.no_records", "加密 DNS 解析完成：无记录（沿用发现地址连接）", "Encrypted DNS resolved: no records (connecting via discovered address)"),
    ("connect.dnssec.refused", "加密 DNS 不可用，连接被拒（域名模式强制 DoH/DoT，DDNS-DOH-003）", "Encrypted DNS unavailable — connection refused (Domain mode requires DoH/DoT, DDNS-DOH-003)"),

    // 2026-09-28 裁定：呈现面显著化，零行为变化）：连接页常显警示（danger
    // 描边框 + 文案；挑战码泄露/会话被恶意利用时爆炸半径 = 远端整盘）。──
    ("connect.r204.warning",
];
