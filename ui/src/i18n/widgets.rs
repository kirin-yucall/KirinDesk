//! M8-T038 (P6): 组件默认文案键值表（zh 基线 + en 全量）。
//! 本分区文件由 M8-T038_P6 独占认领。
//!
//! 仅收录组件自带默认文案（调用方传入的 text/tooltip 由各页任务负责）；
//! 文件面板（file_panel.rs）为会话窗口组件，键亦归本表。

pub static TABLE: &[(&str, &str, &str)] = &[
    ("widgets.copy", "复制", "Copy"),
    ("widgets.paste", "粘贴", "Paste"),
    ("widgets.secret.hide", "隐藏", "Hide"),
    ("widgets.secret.show", "显示", "Show"),

    // ── 文件面板（file_panel.rs）──
    // empty/status.queued|waiting|sending|paused|completed|failed|
    // cancelled）随 `show_file_panel` 渲染体移除——全仓 grep 零他消费
    // （清单入交付报告）；btn.*/dir.*/cancelled_note 为全部任务 tab 共用
    // 键，保留。
    ("filepanel.dir.upload", "↑ 发送", "↑ Send"),
    ("filepanel.dir.download", "↓ 接收", "↓ Receive"),
    ("filepanel.btn.pause", "暂停", "Pause"),
    ("filepanel.btn.cancel", "取消", "Cancel"),
    ("filepanel.btn.resume", "恢复", "Resume"),
    ("filepanel.btn.cancel_queue", "取消排队", "Cancel queue"),
    ("filepanel.btn.show_in_folder", "在文件夹中显示", "Show in folder"),
    ("filepanel.btn.clear", "清除", "Clear"),
    ("filepanel.cancelled_note", "已取消 — 无残留文件", "Cancelled — no leftover files"),
    // 上限；0=不限由 E 岗以占位文案「不限」填充）。
    // 注（口径偏差如实登记）：设计 §2.5 原样 en 文案 "Session quota" 缺
    // 占位符，按本模块「zh/en 模板占位符一一对应」规则归一为带 {0}-{3}。
    ("filepanel.quota", "会话配额 {0}/{1} · {2}/{3} 文件", "Session quota {0}/{1} · {2}/{3} files"),

    ("filemgr.tab.manager", "文件管理器", "File Manager"),
    ("filemgr.tab.tasks", "全部任务", "All Transfers"),
    ("filemgr.local", "本地", "Local"),
    ("filemgr.remote", "远端", "Remote"),
    // 用户 09-22 口径修正：本地树根 = 「此电脑」（盘符是根下的目录层，非根）。
    ("filemgr.pc_root", "此电脑", "This PC"),
    // 目录层，非根——与本地「此电脑」同口径；保留键 `REMOTE_PC_ROOT_KEY`
    // 走既有 `FsOp::List{path}` 字符串通道，零新 wire op）。
    ("filemgr.pc_root_remote", "远端电脑", "Remote PC"),
    ("filemgr.col.name", "名称", "Name"),
    ("filemgr.col.size", "大小", "Size"),
    ("filemgr.col.modified", "修改时间", "Modified"),
    ("filemgr.col.type", "类型", "Type"),
    ("filemgr.btn.up", "⬆ 上上级", "⬆ Up"),
    ("filemgr.btn.down", "⬇ 下载", "⬇ Download"),
    ("filemgr.btn.mkdir", "新建目录", "New folder"),
    ("filemgr.btn.rename", "改名", "Rename"),
    ("filemgr.btn.delete", "删除", "Delete"),
    ("filemgr.btn.refresh", "🔄 刷新", "🔄 Refresh"),
    // 恒 wire List；zh/en 成对，全局成对单测自动覆盖）。
    ("filemgr.btn.force_refresh", "刷新", "Refresh"),
    // dot 惯例；远端 = dot 前缀〔wire 无属性字段，能力边界如实〕）。
    ("filemgr.show_hidden", "显示隐藏文件", "Show hidden files"),
    ("filemgr.btn.show_in_folder", "在系统资源管理器中显示", "Show in Explorer"),
    ("filemgr.empty.local", "此目录为空", "Empty"),
    ("filemgr.empty.remote", "对方版本不支持浏览（仅传输）", "Peer too old (transfer only)"),
    // {0}=名称 {1}=大小 {2}=类型；§1.7 破坏性防护弹窗（取消 = 零 wire 帧）。
    ("filemgr.confirm.delete",
     "确定删除「{0}」（{1}，{2}）？此操作将在远端直接执行（会话授权内），服务端无二次确认",
     "Delete \"{0}\" ({1}, {2})? Executed directly on remote (session-authorized), no server-side re-confirmation"),
    ("filemgr.confirm.rename", "确定改名「{0}」→「{1}」？", "Rename \"{0}\" → \"{1}\"?"),
    // FsErrCode 可读化（S10：对端只见码，本地映射为可读文案）。
    ("filemgr.err.not_found", "文件或目录不存在", "Not found"),
    ("filemgr.err.denied", "权限不足", "Access denied"),
    ("filemgr.err.outside_root", "路径超出允许范围", "Path outside root"),
    ("filemgr.err.io", "IO 错误", "IO error"),
    ("filemgr.err.rate", "操作过于频繁，请稍后重试", "Rate limited, retry later"),
    ("filemgr.err.timeout", "操作超时", "Operation timed out"),
    ("filemgr.err.already_exists", "目标已存在", "Target already exists"),
    //    zh/en 占位符一一对应，缺键回退口径同本表惯例）──
    // 类型列（§2.2 表头 名称|大小|修改时间|类型）。
    ("filemgr.type.dir", "目录", "Directory"),
    ("filemgr.type.file", "文件", "File"),
    ("filemgr.type.symlink", "链接", "Symlink"),
    // 栏头操作按钮（框图 1 verbatim）。
    ("filemgr.btn.send_selected", "⬆ 发送所选", "⬆ Send selection"),
    ("filemgr.btn.recv_selected", "⬇ 接收所选", "⬇ Receive selection"),
    // 分页（500/页，§2.2）。
    ("filemgr.page_fmt", "第 {0} 页", "Page {0}"),
    ("filemgr.page.more", "更多 ↓", "More ↓"),
    // 栏内状态。
    ("filemgr.loading", "加载中…", "Loading…"),
    ("filemgr.busy", "前一操作进行中，请稍后", "Previous operation in progress, retry later"),
    ("filemgr.queue_full", "传输队列已满，请稍后重试", "Transfer queue is full, retry later"),
    // 复制粘贴（§2.6.1①：复制非移动；同栏粘贴 = v1 无移动 no-op）。
    ("filemgr.clipboard.empty", "无已复制项", "Nothing copied"),
    ("filemgr.paste.same_pane", "本栏粘贴不支持（v1 无移动）", "Same-pane paste not supported (no move in v1)"),
    // 非文本输入）= 面板状态行显式提示（修前零动作静默）。zh/en 成对。
    ("filemgr.paste.focus_hint", "剪贴板内容已就绪，请点击文件面板后按 Ctrl+V", "Clipboard content is ready — click the file panel, then press Ctrl+V"),
    // {0}=项数。
    ("filemgr.select.copied", "已复制 {0} 项（Ctrl/Cmd+V 粘贴）", "{0} item(s) copied — Ctrl/Cmd+V to paste"),
    ("filemgr.enqueued.send", "已入队发送 {0} 项", "Queued {0} item(s) to send"),
    ("filemgr.enqueued.recv", "已入队接收 {0} 项", "Queued {0} item(s) to receive"),
    // 文件夹编排（§2.6.1②：{0}=源 {1}=已完成 {2}=总数；深度上限 {0} 层）。
    ("filemgr.job_fmt", "文件夹传输 {0}（{1}/{2}）", "Folder transfer {0} ({1}/{2})"),
    ("filemgr.depth_limit", "已达深度上限（{0} 层），更深目录未展开", "Depth limit reached ({0} levels); deeper dirs not expanded"),
    // 取消中断的状态行 + 目录收集失败计数徽标（{0}=项数；失败清单 =
    ("filemgr.dl.cancelled",
     "文件夹下载已取消（已中断，未入队条目不再传输）",
     "Folder download cancelled (aborted; remaining entries not transferred)"),
    ("filemgr.dl_failed",
     "目录收集失败 {0} 项（清单见日志）",
     "{0} dir(s) failed to collect (list in log)"),
    // 被用户取消中断的状态行 + 空目录创建失败计数徽标（{0}=项数；失败清单
    ("filemgr.ul.cancelled",
     "文件夹上传已取消（已中断，未入队条目不再传输）",
     "Folder upload cancelled (aborted; remaining entries not transferred)"),
    ("filemgr.ul_failed",
     "空目录创建失败 {0} 项（清单见日志）",
     "{0} dir(s) failed to create (list in log)"),
    // 改名/新建目录输入校验。
    ("filemgr.rename.invalid", "名称无效（不可为空、不可含分隔符）", "Invalid name (non-empty, no separators)"),
    // 传输条（框图 1 在位项）。
    ("filemgr.transfer_bar", "传输", "Transfers"),
    //    （`filemgr.quick.*`/`filemgr.arrow.*` 增量键；与 filepanel.*/clip.*
    //    命名空间隔离，占位符一一对应——本组零占位符）──
    // 顶栏常用目录快捷区（本机=桌面/下载/文档〔岗内定案，可配置留待后续〕；
    // 远端=远端根目录〔对端 fs 根下唯一静态已知路径〕）。
    ("filemgr.quick.local", "本机常用", "Local quick"),
    ("filemgr.quick.desktop", "桌面", "Desktop"),
    ("filemgr.quick.downloads", "下载", "Downloads"),
    ("filemgr.quick.documents", "文档", "Documents"),
    ("filemgr.quick.remote", "远端常用", "Remote quick"),
    ("filemgr.quick.root", "根目录", "Root"),
    // 快捷键体系挂上可见树链）。
    ("filemgr.pc_home_remote", "主目录", "Home"),
    // 中缝箭头 tooltip（enable 口径 = 两侧均选中且目标为目录）。
    ("filemgr.arrow.down_tip",
     "← 将远端所选下载到本地所选目录（两侧均需选中，目标须为目录）",
     "← Download remote selection into the selected local directory (select on both sides; target must be a directory)"),
    ("filemgr.arrow.up_tip",
     "→ 将本地所选上传到远端所选目录（两侧均需选中，目标须为目录）",
     "→ Upload local selection into the selected remote directory (select on both sides; target must be a directory)"),
    // 箭头 fail-closed 状态行（目标侧选中非目录时调用面提示）。
    ("filemgr.arrow.need_dir",
     "箭头目标须为目录（请在目标侧选中一个目录）",
     "Arrow target must be a directory (select one directory on the target side)"),
    //    一一对应；`filemgr.tab.manager`/`filemgr.tab.tasks` 既有键直接可用）──
    // 框图 2 五组组头。
    ("filepanel.group.running", "进行中", "In Progress"),
    ("filepanel.group.queued", "排队（并发 ≤3）", "Queued (max 3 concurrent)"),
    ("filepanel.group.pending", "待续传（断点）", "Resume (breakpoint)"),
    ("filepanel.group.failed", "失败", "Failed"),
    ("filepanel.group.cancelled", "已取消", "Cancelled"),
    ("filepanel.group.completed", "完成（本会话）", "Completed (this session)"),
    // 文件夹任务成组组头（§2.6.1②：{0}=文件夹名 {1}=已完成 {2}=总文件数）。
    ("filepanel.group.folder_fmt",
     "文件夹传输 {0}（{1}/{2} 完成）",
     "Folder transfer {0} ({1}/{2} done)"),
    // 组内按钮（框图 2 在位项）。
    ("filepanel.btn.retry", "▶ 重试", "▶ Retry"),
    ("filepanel.btn.discard", "✕ 放弃", "✕ Discard"),
    // 底行（框图 2 底行 verbatim：清除已完成 + 断点残留 N 项）。
    ("filepanel.btn.clear_completed", "🧹 清除已完成", "🧹 Clear completed"),
    ("filepanel.residue_fmt", "断点残留 {0} 项", "Breakpoint remnants: {0}"),
    // 配额条 0=不限 占位（D2 注释预留口径：「0=不限由 E 岗以占位文案『不限』填充」）。
    ("filepanel.quota.unlimited", "不限", "unlimited"),
    // 待续传行注（§4.2/§4.3）。
    ("filepanel.resume.last_session", "上次会话断点", "last session breakpoint"),
    ("filepanel.resume.source_missing", "源文件不存在", "Source file missing"),
    ("filepanel.resume.waiting_offer", "等待对方重发 Offer", "Waiting for peer re-offer"),

    //    占位符一一对应，缺键回退口径同本表惯例）──
    // 「无事件」形态定版：本机板仅含文件时 egui-winit 不产 Paste/Key 事件，
    // 该次 Ctrl+V 既不上 wire 也不上传——窗内提示板文件态与粘贴上传能力）。
    ("clip.badge.upload_hint",
     "本机板含 {0} 个文件 — 会话窗 Ctrl+V 上传到服务端",
     "{0} file(s) on clipboard — Ctrl+V in the session window to upload"),
    // {0}=入队文件数。粘贴上传派发 toast（文件传输模式窗「全部任务」tab
    // 为主反馈面；面板未开态下补一行防零感知；粘贴的 Ctrl+V 本身被吞不
    // （已移除）→ 同步改为文件传输模式窗（终稿报 PM 备案）。
    ("clip.upload.started",
     "正在上传 {0} 个文件到服务端（文件传输模式窗可查进度/取消）",
     "Uploading {0} file(s) to server (see the file transfer mode window for progress/cancel)"),
    // {0}=实际入队数 {1}=粘贴总数。K8（设计 §7.3）：单次粘贴批量 ≤64——前 64
    ("clip.upload.truncated",
     "仅前 {0} 个文件入队上传（共 {1} 个，K8 单批上限 64）— 请分批复制",
     "Only the first {0} of {1} file(s) queued (batch limit 64) — copy in batches"),
    // {0}=文件名。上传完成 toast（v1 主反馈 = 文件传输模式窗「全部任务」
    ("clip.upload.done", "已上传到服务端：{0}", "Uploaded to server: {0}"),
    ("clip.fetch.done", "已从服务端拉取 {0} 个文件到下载目录", "Fetched {0} file(s) from server to download dir"),
    // {0}=根外文件数。根外提示（设计 §7.2：文件在 fs_roots 全部根外 →
    ("clip.fetch.outside_root",
     "{0} 个文件在允许根之外，不可拉取（其余已入队）",
     "{0} file(s) are outside the allowed roots (skipped; the rest are queued)"),
    // {0}=文件数。远端文件占位文本头（零消费终版预留：接收臂置 pending 后写本
    // 终版 i18n 化 = 本键；占位覆盖本机原文本 = B 路线固有成本已披露 §1.2）。
    ("clip.placeholder.header",
     "[KirinDesk 远端文件] {0} 个文件（会话窗 Ctrl+V 拉取）",
     "[KirinDesk remote files] {0} file(s) (Ctrl+V in the session window to fetch)"),

    //    zh/en 占位符一一对应，缺键回退口径同本表惯例；house style 同
    //    filemgr.*/filepanel.*/clip.* 先例）──
    //    truncated/accept/saveas/cancel/default_dir_hint）随弹窗渲染体退役
    //    发送侧等待行/结算文案面（开关模型下唯一 consent 感知面）。
    // 发送侧等待态（状态行徽标；UI「等待对方确认」）。
    ("consent.waiting", "等待对方确认", "Waiting for peer consent"),
    // {0}=倒计时 mm:ss {1}=文件数（5min 常量 Q11）。
    ("consent.waiting_countdown", "等待对方确认 {0}（{1} 个文件）", "Waiting for peer consent {0} ({1} file(s))"),
    // 结算文案（§8.6：超时行 Failed「对方未确认（超时）」）。
    ("consent.timeout", "对方未确认（超时）", "Peer did not confirm (timeout)"),
    ("consent.declined", "对方取消了传输", "Peer declined the transfer"),
    // {0}=文件数（ok 结算 = 真实传输行归全局任务面板）。
    ("consent.transferring", "对方已确认，传输中（{0} 个文件）", "Peer confirmed, transferring ({0} file(s))"),
    ("consent.send_failed", "发送失败", "Send failed"),
    //    toast/tooltip 键（提案案 = 技术过渡口径，用户终稿 F 复测后 G 岗
    //    统一改；zh/en 占位符一一对应，house style 同上方 consent.*/clip.*）──
    // {0}=文件数。ON 路径自动接受非阻塞 toast（同意族；三选弹窗随 B3
    //    退役——两开关态均不弹框，本 toast 为唯一接收感知面之一）。
    ("consent.auto_accepted",
     "已自动接收对方发来的 {0} 个文件（开关开）",
     "Auto-accepted {0} file(s) from peer (switch on)"),
    // {0}=文件数。OFF 路径自动 `Declined` 接收侧 toast（发送端等待行结算
    //    「对方取消了传输」= 既有 `consent.declined` 键零变化）。
    ("consent.switch_declined",
     "已自动拒绝对方发来的 {0} 个文件（文件传输开关关）",
     "Auto-declined {0} file(s) from peer (file transfer switch off)"),
    // 异常 tooltip（Dashboard 卡区展示点，PM 裁定①）：配置文件存在但
    //    损坏/不可读 = 两开关显示关（fail-closed 按关）并说明异常原因；
    //    首启缺文件态 = 显示开（默认），不出本提示。
    ("consent.config_invalid_hint",
     "配置文件异常——文件传输与剪贴板均按关闭处理，请检查配置文件",
     "Config file is invalid — file transfer and clipboard are treated as OFF. Check the config file"),
    //    `consent.config_invalid_hint` 语义（复用，前句一致）+ {0}=文件路径
    //    + {1}=出错键名；键名不可提取时走 `consent.config_invalid_banner_path`
    //    （仅路径，无键位）。
    ("consent.config_invalid_banner",
     "配置文件异常——文件传输与剪贴板均按关闭处理，请检查配置文件：{0}（出错键：{1}）",
     "Config file is invalid — file transfer and clipboard are treated as OFF. Check the config file: {0} (offending key: {1})"),
    ("consent.config_invalid_banner_path",
     "配置文件异常——文件传输与剪贴板均按关闭处理，请检查配置文件：{0}",
     "Config file is invalid — file transfer and clipboard are treated as OFF. Check the config file: {0}"),
    // B3 消费（目录感知粘贴落点回退 toast：当前浏览文件夹不可用 = 回退
    //    download_dir + 通知，§12.3/PM 裁定②）——本岗先入表防缺键。
    ("clip.fetch.fallback",
     "无法定位当前浏览文件夹——已改存到下载目录",
     "Current browse folder unavailable — saved to the download dir instead"),
    ("clip.fetch.dirs_started",
     "正在展开对端剪贴板目录（{0} 个）——文件将逐层展开后逐个拉取",
     "Expanding {0} peer clipboard director(ies) — files are fetched level by level"),
    ("clip.fetch.dir_desktop_unsupported",
     "{0} 个目录条目暂不支持在远程桌面窗粘贴拉取——请在文件传输窗中粘贴",
     "{0} director(ies) cannot be fetched via paste in the remote-desktop window — paste in the file transfer window instead"),
    ("clip.paste.dir_desktop_skipped",
     "{0} 个目录条目无法从远程桌面窗粘贴上传——请在文件传输窗中粘贴",
     "{0} director(ies) cannot be pasted for upload from the remote-desktop window — paste in the file transfer window instead"),
    ("filemgr.clip.dir_no_context",
     "剪贴板含目录，但当前无远端落点语境——请先打开对端文件传输窗再粘贴",
     "Clipboard contains directories but no remote landing context — open the peer file transfer window first, then paste"),
    //    入口键（zh/en 成对；默认焦点「跳过」= 不再静默改名；「全部应用」
    //    = 本粘贴会话有效，RustDesk default_overwrite_strategy 同口径）。
    ("filemgr.clip.conflict_title",
     "同名冲突",
     "Name conflict"),
    ("filemgr.clip.conflict_body",
     "落点已存在同名文件：{0}（{1}）。「覆盖」= 删除旧文件后重新拉取；「跳过」= 不拉取该文件；「全部应用」= 本批后续同名文件均按覆盖处理、不再询问。",
     "A file with the same name already exists at the destination: {0} ({1}). 'Overwrite' = delete the old file and fetch again; 'Skip' = do not fetch this file; 'Apply to all' = overwrite all later same-name files in this batch without asking."),
    ("filemgr.clip.conflict_overwrite",
     "覆盖",
     "Overwrite"),
    ("filemgr.clip.conflict_skip",
     "跳过",
     "Skip"),
    ("filemgr.clip.conflict_apply_all",
     "全部应用",
     "Apply to all"),
    ("filemgr.clip.cancel",
     "取消",
     "Cancel"),
    ("filemgr.clip.cancelled",
     "已取消：已收 {0}/已跳 {1}/未派 {2}",
     "Cancelled: received {0}, skipped {1}, pending {2}"),
    ("filemgr.clip.expanding",
     "目录拉取中…",
     "Fetching directory…"),
    // 臂 ② 本地门（PM 裁定③）：剪贴板开关关 = 粘贴拉取**不派发**
    //    （本地门，零 wire，对端无涉）。
    ("clip.paste_disabled",
     "剪贴板开关已关闭——粘贴拉取未执行",
     "Clipboard switch is off — paste fetch not dispatched"),
    //    上轮 09-22 用户复测开关反复翻转多落 OFF 窗产生「无效」误判 →
    //    OFF 态在文件传输窗/剪贴板 UI 常驻一行提示，防误测）。
    //    两横幅读**本机**开关 → 指向「本机」……
    //    重订（本卡改向）**：权限判定与提示以**对端受控机（会话中服务端
    //    角色）**的设置为准，非本机实例自己的 server 配置（用户逐字指正：
    //    「它检测的是客户端所在设备的服务端设置而不是远控服务端的设置」）。
    //    判定源 = 对端会话内通告值（ControlMessage::PeerConsent 控制平面 /
    //    consent 快照 / 服务端实时开关）；对端未通告（旧版本对端）= fail-closed
    //    按 OFF + `*_peer_unknown_banner` 显式文案（红线⑤，不静默放行）。
    //    自身设备面两开关语义零变化（Dashboard 卡区展示 / 自身作为服务端时
    //    的本地门控 / 自身 push 方向门控 = 本机配置面，不涉本组键）。──
    // 文件传输窗（文件管理器）：对端（远端服务端）`file_transfer_allowed`
    // OFF 常驻提示。门控面（对端 FileSession consent 裁决 + 构造快照）：
    // 对端 OFF = 对端自动 `Declined` 本机发来的上传（consent 路径）；文件
    // 浏览（List）/拉取下载（Fetch，←「接收所选」）不受对端本开关门控。
    ("consent.file_transfer_off_banner",
     "对端（受控端）「允许文件传输」开关为 OFF：对端会自动拒绝本机发来的文件上传（本机「发送所选」/Ctrl+V 文件上传不生效）。文件浏览与下载（「接收所选」/← 拉取）不受影响。如需向对端发送上传，请在 对端 设置 开启「允许文件传输」。",
     "The peer (controlled side)'s 'Allow file transfer' switch is OFF: the peer automatically declines file uploads sent by this machine ('Send selection' / Ctrl+V file uploads will not take effect). File browsing and downloads ('Receive selection' / ← pull) are not affected. To send uploads to the peer, enable 'Allow file transfer' in the peer's Settings."),
    // 剪贴板相关 UI（会话窗 + 文件传输窗）：对端（受控端）
    // `clipboard_allowed` OFF 常驻提示。门控面（s→c 接收臂按对端通告值
    // 门控 + 对端自身 push/apply 臂按对端本机值门控——对端 OFF 时双向
    // 剪贴板同步均被对端侧封死）。
    ("consent.clipboard_off_banner",
     "对端（受控端）「允许剪贴板」开关为 OFF：会话内剪贴板文本/文件同步被对端门控（本机无法接收对端同步、对端也不接收本机同步）。如需剪贴板同步，请在 对端 设置 开启「允许剪贴板」。",
     "The peer (controlled side)'s 'Allow clipboard' switch is OFF: clipboard text/file sync in the session is gated by the peer (this machine can neither receive the peer's sync nor have its sync accepted by the peer). To enable clipboard sync, turn on 'Allow clipboard' in the peer's Settings."),
    // 文案（红线⑤：对端态未知 = 按 OFF 门控 + 如实提示，不静默放行）。
    // 会话窗（剪贴板面）+ 文件传输窗（文件传输面）各一。
    ("consent.clipboard_peer_unknown_banner",
     "对端（受控端）剪贴板权限状态未知（未通告，可能为旧版本对端）：会话内剪贴板同步按 OFF 门控（fail-closed）。如对端已开启剪贴板，请将两端升级到同版本后重连。",
     "The peer (controlled side)'s clipboard permission is unknown (not announced; possibly an older version): clipboard sync in the session is gated as OFF (fail-closed). If the peer allows clipboard, upgrade both ends to the same version and reconnect."),
    ("consent.file_transfer_peer_unknown_banner",
     "对端（受控端）文件传输权限状态未知（未通告，可能为旧版本对端）：本机发送的文件上传可能被对端拒绝，按 OFF 门控（fail-closed）。如对端已开启文件传输，请将两端升级到同版本后重连。",
     "The peer (controlled side)'s file-transfer permission is unknown (not announced; possibly an older version): file uploads from this machine may be declined by the peer; gated as OFF (fail-closed). If the peer allows file transfer, upgrade both ends to the same version and reconnect."),
];
