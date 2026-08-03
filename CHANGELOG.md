# Changelog

本项目变更日志，格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本语义遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。
里程碑（M1–M15）与任务状态见 `task_docs/M0-完整路线图M1-M15.md`。

## [Unreleased]

### Added
- M9-DNS000 多服务商 DNS 域名维护客户端（M9-DNS001~024，20 家服务商全量落地）：
  - Provider 抽象层（`dns/src/provider/`）：`Provider` trait（test_connection /
    list_domains / query_records / upsert_record / delete_record / capabilities）、
    统一 `Record`/`RecordData`（Plain/Mx/Srv）与 `RecordType`、统一 `ProviderError`
    （Auth/InvalidParameter/NotFound/RateLimited/Server/Network/Json/Unsupported/
    Other）、`ProviderRegistry` + `Credential` 枚举（20 变体）、`MockProvider`
    契约测试基建
  - 20 家服务商适配（`dns/src/providers/`，M9-DNS001~020）：GoDaddy（旧模块迁移+
    trait 化）、Cloudflare、阿里云云解析、腾讯云 DNSPod（TC3）、AWS Route 53
    （SigV4+XML）、Azure DNS（OAuth2）、Google Cloud DNS（RS256 JWT）、华为云 DNS、
    Namecheap（XML）、DigitalOcean、Vultr、Linode、Hetzner DNS、OVH（三要素签名）、
    Porkbun、百度智能云（BCE）、火山引擎云解析、京东云解析（JDCLOUD2）、西部数码
    （MD5 token，SRV/NS 能力降级）、新网（SRV 能力降级）；每服务商自包含 mock
    契约测试（≥5 用例/家）
  - 服务层多服务商化（M9-DNS021）：srv/aaaa/a/txt/discovery/heartbeat 全部改为
    `&dyn Provider` / `Arc<dyn Provider>`，`DiscoveryError` 新增 `Provider` 变体，
    `discover_device(provider, domain, device_id)`；旧 `dns/src/godaddy/` 模块删除
  - 配置结构（§四）：`[dns] provider` + `[dns.providers.*]` 每服务商凭据表；
    旧 `[godaddy]` 表加载时自动迁移并写回；`utils::dns_providers` 注册表全量
    20 家（UI 下拉框数据源）
  - UI（M9-DNS022）：Domain 页「服务商」卡下拉框列出全部 20 家（注册表驱动）、
    凭据表单按服务商动态渲染（secret 👁）、测试连接、域名列表、记录 CRUD、
    SRV/NS 能力降级提示（西部数码/新网）、文案泛化（GoDaddy → DNS 服务商）
  - CLI（M9-DNS023）：`dns` 子命令组（list-providers / set-provider / test /
    domains / records / add / update / delete / register / unregister）；
    `register`/`discover`/`connect` 链路走当前激活 provider，旧用法零破坏
- M8-T040 DDNS 域名自动更新维护 + 域名模式 DoH/DoT 强制（P1~P6 全量落地，
  WBS/并行计划见 `task_docs/共享层/DNS域名维护客户端/M8-T040_*`）：
  - 配置（P1）：`[ddns]` 段（enabled/interval_secs≥60 下限收敛/ipv4 与 ipv6
    双模式 auto|manual/ipv4_sources/publish_srv|txt|a|aaaa 四开关）+ `[dns.security]`
    段（mode 默认 enforce/doh/dot 端点/resolve_timeout_ms/cache_ttl_secs）；
    `interval_secs` 未设置回退 `[network] heartbeat_interval`（§5.3 兼容迁移）
  - dns 基础件（P2）：`public_ip.rs` 公网出口 IP 获取器（`PubIpSource` trait +
    ipify/ip.sb/icanhazip 三源 HTTPS 严格 `Ipv4Addr` 校验 + 按序回退 + 缓存 +
    拒绝 HTML/劫持页/特殊地址）；`secure_resolver.rs` DoH/DoT 加密解析器
    （`application/dns-json` 三端兼容解析 + rustls DoT wire 编解码 A/AAAA/SRV/TXT
    四型 + 端点优先序 + 缓存 50s + 单端点 5s/总 15s 超时 + fail-closed）
  - 引擎（P3）：`HeartbeatService` 策略化（`Ipv4Policy::Auto(PublicIpFetcher)|
    Manual`、`Ipv6Policy::Auto|Manual`，Manual 永不覆盖）；`ddns.rs` 新
    `DdnsService`（周期编排 + 变更驱动 + publish_* 开关 + 更新前 DoH/DoT 反查
    保护 + 连续 3 次失败暂停 + `DdnsStatus` watch 状态回读 + 关闭不删记录）
  - core/media 接线（P4）：`core::dns::resolve_for_connect` 唯一域名模式解析
    入口（红线：禁止 `to_socket_addrs`/`TcpStream::connect(&str)` 直连）；
    `ConnectError` 新增 `EncryptedDnsRequired`/`DnsResolveFailed`；服务端启动
    自检 `server_dns_self_check`（SRV/TXT/A 一致性校验 + 告警）
  - UI（P5）：Domain 页「DDNS 维护」卡（总开关/周期/TTL/IPv4 与 IPv6 双模式/
    只读自动值+重新检测/生效记录预览/状态行倒计时/立即更新/保存/服务商未配置
    整卡禁用）；Connect 页域名模式加密 DNS 状态行（解析中/完成/拒连原因）；
    i18n `ddns.*` 键（domain 分区）+ `connect.dnssec.*` 键（connect 分区）
  - CLI（P7）：`ddns` 子命令组（status/enable/disable/set-ipv4/set-ipv6/update）
    + `dns resolve <host> [--type]` 加密解析调试 + `serve` 域名模式自检联动 +
    `[ddns] enabled` 策略化维护；self-test 新增 DOH 段（3 项）+ DDNS 段（4 项）
  - **行为变更**：IPv4 自动 = **公网出口 IP**（非本机网卡地址，核心语义修正）；
    域名模式全部 DNS 解析强制 DoH/DoT，全部端点不可用 → **fail-closed 拒连**
    （不回退明文）；`[dns.security] mode=off` 仅限 IP 模式使用
- M8-T039 Tunnel 内网穿透独立页 + Server 多监听 + Token ✏️📋 + 通用工具化：
  - 独立页（P3）：`Tab::Tunnel`（🚇 标签，Connect 与 Settings 之间）；Settings
    页「Tunnel (内网穿透)」分组与保存分支整体移除（`settings.tunnel.*` 10 键随删，
    防死键）；Tunnel 页自带「保存」（落盘 mode/server_addr/token/bind_addrs/
    bind_port/port_range/proxies，**不写 `enabled`**）+ 定位文案改为「通用 TCP
    反向代理」口径（发布个人网站示例 + 明文流量提示）；i18n 新分区
    `ui/src/i18n/tunnel.rs`（`tunnel.*` 键，P4 `tunnel.server.*` / P5 `tunnel.run.*`
    表尾追加）
  - 配置基建（P1）：`TunnelConfig` 新增 `bind_addrs`（逗号分隔多地址，默认
    `"0.0.0.0,::"`，serde 缺省兜底）+ `auto_start`（GUI 最后运行状态，默认 false，
    CLI 不读、与 `enabled` 语义独立）；`parse_bind_addr_list`（纯 std，GUI 校验 +
    CLI 组装共用）与 `generate_random_token`（32 字节 OsRng → 64 hex，TNL-SEC-009）；
    `config/default.toml [tunnel]` 追加两字段默认值与注释（GUI 可编辑，Linux 仍可
    改文件 + CLI 完整部署）
  - relay 多监听器（P2）：`TunnelServerConfig.bind_addr → bind_addrs: Vec<SocketAddr>`
    （破坏性变更，使用点全仓 3 处可控：self-test 迁移 / serve 走默认 / relay-server
    零改动自动兼容）；空列表 = 旧默认双栈回退（语义零变化）；多地址每地址独立
    `TcpListener`、**IPv6 一律 `set_only_v6(true)`**（与 v4 显式监听并存，规避平台
    双栈差异与 Linux 下 `::` 先占 v4 的 EADDRINUSE 冲突）；`run()` 每 listener 一个
    accept 任务（JoinSet 汇合）；`tunnel serve` 可选读取 `bind_addrs`（非法值
    fail-closed 拒绝启动，默认行为不变）；新增 4 个多地址/v6-only/回退单测
  - Server 区块（P4）：监听地址（多地址校验：非 IP/空段/域名红边）/ 端口
    （1-65535）/ 端口范围（`start-end`，复用 cli.rs `parse_tunnel_port_range` 提升
    `pub(crate)`）输入 + 校验；非法值红边且**禁用保存**（`tunnel_save_allowed` 挂
    表单校验，与渲染红边同源）；`::` 单地址弱色提示补 `0.0.0.0`；Token 行
    **✏️📋 仅 Server 区块**：✏️ 生成 64 hex 高熵 Token 并**立即落盘**，📋 复用
    `copy_button`（空 token 禁用）；Client 区块 Token 行保持现状（密文 + 👁，无 ✏️📋）
  - GUI 运行能力（P5）：Tunnel 页「▶ 启动 / ■ 停止」（`TunnelRuntimeState` 静态槽
    仿 `ServerRuntimeState`，自建 tokio runtime 后台运行，进程内 `TunnelClient`/
    `TunnelServer`）；启动 = fail-closed 校验（server 空 token 拒绝 / 短 token 警告；
    client 校验 server_addr）→ 自动落盘当前表单 → `auto_start=true` 落盘 → 后台
    运行；停止 = `auto_start=false` 落盘 + 优雅关闭（client `stop()` / server
    `shutdown_handle()` 广播）；**启动失败保留 intent**（`auto_start` 不回位，状态行
    「启动失败: <原因>（配置保持启用，下次启动将自动重试）」）；首帧自动恢复
    （`auto_start=true` → 按上次模式自动启动，失败跨帧展示原因）；状态行
    「● 运行中 :port (addrs) / ○ 已停止」；GUI 启停不写 `enabled`（CLI 设备注册
    语义零变化）
  - 门禁：`cargo check --workspace --all-targets` 全绿；utils 118 + relay 91（含
    新增 4）+ ui 110（含 i18n 重复键断言）全过；`--cli self-test` 回归通过
  - 跨平台补齐（P16b，08-03）：独立服务端 `relay-server` 新增 `--bind-addrs`
    参数（多监听地址，逗号分隔、仅本机 IP，v6 一律 v6-only）——Linux/macOS
    无 GUI 部署主路径（Docker/systemd/裸机）获得与 Windows GUI Server 区块
    相同的多监听能力；空 = 默认双栈回退（行为零变化）、非法值 fail-closed
    拒绝启动、`--help`/启动横幅展示实际监听地址；`Config::parse` 新增单测；
    发布文档同步（`release/server/README.md` 参数表 + `BUILD_LINUX.md` /
    `relay-server.service` / docker compose & Dockerfile 示例）
- M8-T038 连接状态迁移 + 语言选项与文案统一：
  - 连接状态迁移（P1）：Connect 页移除顶部状态点行与表单内 3 处 Stepper 渲染
    （保留 step/busy 推导驱动按钮禁用/⏳）、删除 3 处进度快照类表单反馈写入；
    会话窗口（弹出页）工具栏之下、显示画面之前新增 `conn_state_{wid}` 状态条
    （状态点 + Stepper，随弹出页出现/消失；Shell 会话 `[shell] ` 前缀剥离后
    颜色/步数判定一致）；点击 Connect 后进度仅见于右侧连接日志
  - 语言选项（P3）：Settings → Appearance 新增 Language 三段
    （System / 中文 / English），镜像 Theme 四件套（App 字段 / 启动应用 /
    即时切换 / Save 落盘），持久化 `[ui].language`（默认 `"system"` 跟随系统）
  - 语言基建（P2）：`utils` 新增 `locale::system_language_code()`（Windows
    `GetUserDefaultUILanguage`，`Win32_Globalization` feature）+ `UiConfig.language`
    + `i18n::system()` / `set_lang_code()`（env 优先 → 系统 API → zh 基线）；
    i18n 键值表重构为**按页面分区**的 `ui/src/i18n/{common,settings,connect,
    dashboard,devices,domain,session,widgets}.rs`（`ALL` 汇总 + 重复键断言单测，
    并发加键零冲突）；新增 `tf!` 宏（`{0}/{1}` 位置参数模板，`format!` 不支持
    运行期格式串的替代实现）
  - GUI 全界面文案统一（P3~P6，约 430 键）：Settings / Connect / Dashboard /
    Devices / Domain（含 domain_panel.rs）/ 会话窗口（状态栏徽标、工具栏 tooltip、
    特殊键、隐私菜单、断线重连覆盖层）/ 四类弹窗（panic、审批、指纹确认、文件
    接收完成）/ 组件默认 tooltip / 文件面板 / 连接失败引导提示全部 `t!()` 化
    （zh 基线 + en 全量翻译）；CLI 提示语（P1）保持现状
- R-02 握手 pin 强制加固（安全收尾 P0，审计 P3-17）：
  - `core` 新增强类型 `PinExpectation { None(CoreReason), Exact([u8;32]) }` / `CoreReason { InternalLoopback, UserConfirmRequired }`；`client_handshake_generic` / `client_handshake_with_confirm_generic` / `client_handshake` / `client_handshake_with_confirm` 的 pin 参数全部强类型化——**删除"空串 = 跳过 pin 比对"的旧版兼容路径**（`None(UserConfirmRequired)` 无确认回调即拒绝，杜绝信任网络公钥）
  - loopback 自签兜底：`None(InternalLoopback)` 以客户端自身公钥强制比对（服务端 = 自身），`PunchConfig::loopback` / `PunchHandshake.peer_pin` 不再有空串形态；`PinExpectation::resolve_base64` 供服务端角色（punch）解析
  - 调用点显式化：`core`（punch、shell/file_transfer e2e）、`media`（`PunchMediaCreds.peer_pin`、`ClientDegrade.server_pin`、`connect_quic_transport(_on)` / `connect_media_transport` 参数）、`ui`（cli.rs 全部连接命令 + self-test、lib.rs `ClientTrust` 两分支）——grep 空串 pin 零命中
  - 新增用例：空 pin 拒绝（无回调 `UntrustedKey`）、loopback 自签通过/非自签拒绝（`ServerKeyMismatch`）、错误 pin 拒绝回归；core 138 项 + media 363 项 + e2e 全过
- M8-T030 单 GPU 硬件加速与虚拟设备过滤（R-06）：
  - `media/src/gpu/` 新建：`AdapterInfo/AdapterKind/GpuPreference/GpuPreferences` + 厂商分类（Intel 0x8086 / NVIDIA 0x10DE / AMD 0x1002）+ 虚拟驱动过滤（`DXGI_ADAPTER_FLAG_SOFTWARE` / vendor 0x1414 / 关键词黑名单 sunlogin·oray·向日葵·virtual·idd·parsec·spacedesk 等，可配置覆盖）+ 单 GPU 选择策略（LUID 显式 → 过滤 → 类别 → auto → None）；`OnceLock` 首用缓存（GPU-NF-006）
  - Windows DXGI `EnumAdapters1` 枚举（`media/src/gpu/windows.rs`）+ 选定适配器上创建 D3D11 设备（`KgpuKernel::init` 复用入口，GPU-FR-006）
  - 编码/解码 HW 设备显式绑定：`av_hwdevice_ctx_create` 按候选设备串绑定选定 GPU（`ffmpeg_hw.rs` 两侧）。**R-06 实测定案**：FFmpeg 8.1.2 d3d11va 设备串只接受十进制适配器索引（`atoi` 解析；LUID 十六进制静默变 0 无效）——`device_strings` 输出 `[DXGI 枚举索引]`；候选非空全失败 → 回退链继续（env=nvidia 时 qsv MFX 失败自然落 nvenc 绑定 NVIDIA），候选为空 → None 现状默认设备（GPU-NF-002）
  - 虚拟显示器过滤：`enumerate_monitors` 按名称关键词剔除虚拟屏 + `MonitorInfo.is_virtual` + `real_indices` 索引映射（过滤后 `switch_monitor` 不错位，GPU-FR-007）
  - 脏点 CPU 兜底：`TileDiff::classify_cpu` 真实 CPU tile-hash（64×64 tile 全像素 CRC32 + 帧间 diff → 三态决策，与 GPU hash 语义一致），无 GPU 内核时决策链路可用（GPU-FR-008）
  - 配置 `[media.gpu]`（prefer / filter_virtual / virtual_keywords）+ `KIRIN_GPU_PREFER` env 覆盖（env > config > auto，GPU-FR-009）；设计文档 `task_docs/共享层/M8-T030_单GPU硬件加速与虚拟设备过滤_需求设计.md`
  - 顺带修复：`SNAPSHOT_FFMPEG_MAJOR` 8→62（`avcodec_version()` 返回 libavcodec 库版本 62.28.102，原值导致 avcodec-62.dll 环境下 FFmpeg 全链路加载失败）；软编 `FfmpegSwEncoder::ensure_codec_dims` free 前 flush（对齐 HW/Drop，libx264 lookahead 线程残留）
- M8-T018 多显示器查看模式（客户端查看 + 服务端捕获热切换）：
  - 协议：`ControlMessage::DisplayListReq / DisplayListResp / DisplaySelect / DisplaySelectNack` + `proto::DisplayInfo`（bincode，复用可靠流/控制通道）；`PacketKind::Control` → `ChannelTag::Control`（0x04，与既有控制/心跳通道对齐）
  - 服务端：`factory::enumerate_monitors()`（Windows `Monitor::from_index` 体系 / macOS zed-scap；空时兜底 1 个默认屏）；`ScreenCaptureSource::wait_for_frame_timeout`（静默屏幕定期醒来处理切换，Windows `recv_timeout` 实现）；`switch_monitor` 会话内热切换（同索引 no-op）→ 下一窗口强制 IDR + 重推 `VideoFormat`
  - 客户端：连接建立自动请求显示器列表（CLI-MON-001）；连接窗口工具栏「显示器」下拉（`名称 分辨率 [主屏]`）+ ⟳ 手动刷新，切换即发 `DisplaySelect`，Nack 状态栏 ⛔ 提示；状态栏显示当前屏名称/分辨率徽标
  - 坐标映射跟随（CLI-MON-010 / SRV-MON-010）：客户端归一化基数 = 当前所选显示器分辨率（随窗口 base_w/base_h 更新）；服务端 `InputInjector::set_resolution` 切换后同步换算基准，按屏分辨率回归测试（屏0/屏1 全范围）
  - 单测：DisplayList 序列化往返、越界索引 Nack、wire kind/tag 映射、坐标换算边界；需求文档 `task_docs/共享层/M8-T018_多显示器查看模式.md`
- M13-T006 文件传输（双向 File Transfer，复用 SecureChannel AEAD 加密通道）：
  - 帧协议 `ChannelTag::FileTransfer = 0x06` + `PacketKind::FileTransfer`（64 KiB 大帧，避开 1200B 小分片路径；`SecureChannelSender::send_big_packet`）
  - 滑窗发送（窗口 64 块）+ 累积 Ack/Nack + 块超时重传 + 空闲死链判定；接收侧分片重组 `.part` → 整体 SHA-256 校验 → 原子 rename，取消回滚无残留
  - 断点续传：`transfers_client/server.json` 元数据持久化，重连后双方进度协商续传（重复块不落盘）
  - 会话内并发任务队列 ≤3（FIFO）；路径消毒（绝对路径/`..`/盘符/NUL/非法字符全拒）、单文件大小限制（默认 4 GiB）、transfer_id 去重、同名自动改名
  - UI：连接窗口「📁」文件面板（任务列表/进度条/速度/取消/暂停/恢复/在文件夹中显示）+ 拖拽发送；服务端 Dashboard 文件面板（推送/接收）+ 接收完成弹窗
  - CLI：`send <path> <host> [port] [nickname]` / `recv <host> [port] [nickname]`；`serve` 无头静默接收；`self-test` 含文件传输往返自测
  - 配置段 `[file_transfer]`（download_dir / max_file_size）；全链路测试 `core/tests/file_transfer_e2e.rs`
- M13-T005 无人值守模式（Unattended Mode）：
  - 用户级开机自启（Windows HKCU Run / Linux XDG autostart / macOS LaunchAgent，无需管理员），`--autostart` 参数启动，最小化窗口
  - 无人值守开启后应用启动自动开启服务端；known_clients/白名单命中自动放行（远程桌面远控 / 远程 Shell PTY 单端口会话分发），未知设备自动拒绝 + 审计，temp-mode 旁路禁用
  - Settings 页「Unattended Mode」卡片（总开关 + 自启/自动开服务端子选项 + 注册状态）+ Dashboard 徽标
  - CLI：`unattended <on|off|status>`、`autostart <enable|disable|status>`、`serve [port] --unattended`
  - 配置段 `[unattended]`（enabled / auto_start_on_boot / auto_start_server），需求文档 `task_docs/共享层/M13-T005_无人值守模式.md`
- M14 发布与打包：
  - GitHub Actions CI：三平台 build/test + release 打包（Windows zip / Ubuntu deb / macOS dmg）自动上传
  - Windows NSIS 安装包（`release/install.nsi`）+ 改进的 `release/install.bat`（含 FFmpeg DLL、身份/日志目录、快捷方式）
  - Ubuntu .deb 包（`release/debian/`，含 systemd 服务 `kirindesk.service`）
  - macOS 通用二进制 .app + .dmg 打包脚本（`release/macos/build_universal.sh` / `create_dmg.sh`）
  - 自动更新：Settings Update 面板（检查 / 下载进度 / 安装重启）+ 每周后台检查（updater 按平台选 asset）
  - 版本发布脚本 `release/publish.sh`（tag + changelog + gh release create）

### Changed

- M8-T038 行为变更：点击 Connect 后 Connect 页不再显示连接进度（顶部状态点 /
  表单 Stepper / 底部进度快照已移除），进度可见于弹出页状态条与右侧连接日志；
  首次使用可能短暂无进度反馈，属预期（用户主动要求，见
  `task_docs/UI/M8-T038_UI改动需求设计_2026-08-03.md` §7-5）
- FFmpeg 捆绑构建 8.1.2 → **GyanD 8.1.1**（决策记录与实测见
  `task_docs/共享层/M8-T030_单GPU硬件加速与虚拟设备过滤_需求设计.md` §5.2；
  Readme 下载链接已更新；**捆绑目录已替换并回归通过**）：8.1.2 构建捆绑 ffnvcodec 13.1 头，
  `h264_nvenc` 要求 NVIDIA 驱动 ≥610.00；8.1.1 捆绑 ffnvcodec 13.0 头，兼容 591 系
  主流驱动（libavcodec 同为 62，偏移快照兼容；本机 591.86 实测 h264/hevc_nvenc
  出码流 ✓）。顺带修正文档/注释中构建来源标注（BtbN → GyanD，实测 `ffmpeg -version`
  为 www.gyan.dev）。nvenc open 失败路径堆损坏崩溃（驱动不满足时）既有隐患对更老
  驱动仍适用，登记观察

### Fixed

- **视频无画面（阻断，修复计划 2026-08-03 P0）**：服务端捕获循环把编码窗口
  （`EncodedWindow`，4K 下 ~125KB）经 `SecureChannelSender::send_packets` 发送，
  超过 `MAX_PACKET_PAYLOAD`（≈1151B）小分片上限 → `payload too large` → 捕获循环
  退出 → 客户端画面空白。改为 `send_big_packet` 大帧路径（16MiB 上限，线格式
  `PacketHeader + payload` 一致，客户端 parse_frame 零改动，新旧互通）——
  与 M13-T006 文件传输同路径（`ui/src/lib.rs`）
- **opus 编码器不可用（修复计划 2026-08-03 P1）**：`avcodec_find_encoder
  (AV_CODEC_ID_OPUS)` 返回 libopus（支持 s16 / packed f32），代码却强制
  `sample_fmt=fltp`（libopus **不支持** planar f32）→ `avcodec_open2` EINVAL →
  麦克风/环回音频全不可用（原错误文案误判"构建缺 libopus"）。改为显式
  `avcodec_find_encoder_by_name("libopus")` + 帧格式 `AV_SAMPLE_FMT_FLT`，
  单平面整块拷贝（顺带去掉 deinterleave 循环），注释/文档同步修正
  （`media/src/encoder/audio/mod.rs`）；media lib 374 项测试全绿
- **音频发送路径防御性加固（修复计划 2026-08-03 P2）**：音频发送原走
  `send_packets` 小分片路径，超限（如未来音频码率自适应/配置化提码率至
  opus 上限 510kbps → 单帧 1275B > 1151B）即 `break` 整条音频静音，且与
  "音频可丢、低优先级"（R-04）语义不符。新增 `send_audio_packets`：≤1151B
  走小分片路径（保持 QUIC 迁移语义），超限走 `send_big_packet`，失败仅丢批
  不中断循环；服务端环回 + 客户端麦克风两处调用点同步替换
  （`ui/src/lib.rs`）。注：当前码率硬常量 64kbps（M12），20ms 帧 ≈160B，
  现路径不会超限，此为防御性加固
- **明亮主题视频画布深字压深底（R-27）**：`theme.video_bg` 明亮值由深色
  `#0D1117` 改为浅色 `#F6F8FA`（与 `theme.bg` 同色）——断线/重连覆盖层
  （fg 1.20:1 → 14.84:1）、"等待视频流"占位（4.16 → 4.27:1 同既有例外）、
  状态点 danger（3.53 → 5.03:1）在明亮主题下恢复可读；深色主题恒 `#000000`
  零变化。远程 Shell 终端画布改为显式纯黑填充（M11-T002 经典深色 ANSI
  调色板与主题解耦的落地，深色主题视觉不变）。新增
  `test_video_bg_theme_alignment` 锁定"明亮=浅底/深色=深底"+ 画布文字对比度，
  `test_palette_contrast` 底色矩阵纳入 `video_bg`
  （`ui/src/theme.rs`、`ui/src/lib.rs`；设计文档
  `task_docs/修复任务/U_R-27_明亮主题画布浅色化与域名页徽标移除.md`）
- **域名页服务商名 Info 徽标移除（R-27）**：`domain_panel.rs` 服务商卡不再以
  Info 语义（品牌蓝 `#0969DA`）徽标渲染服务商名（如 "GoDaddy"，观感误认品牌
  logo）；服务商名保留于 ComboBox 选中文本，配置状态徽标（已配置/未配置）
  不受影响（`ui/src/domain_panel.rs`）
- **M8-T040 收尾三小问题（R-30，审计 §8 三小问题）**：
  - 反查保护 fail-open 删除：`Engine.resolver` 改 `Arc<dyn Resolver>`（类型系统
    强制必非 None，编译期消灭 None 构造路径），`reverse_check` 删 `Ok(true)`
    降级分支，`start()` 装配恒注入——DDNS-REC-005 不再存在静默失效路径，
    与 core 连接层 fail-closed 主线语义一致（`dns/src/ddns.rs`）
  - GUI 加密解析空结果状态行如实：解析返回合法空列表时状态行显示
    「无记录」（i18n 新增 `connect.dnssec.no_records` 键），连接沿用
    discovery 地址继续、行为不变（`ui/src/lib.rs`、`ui/src/i18n/connect.rs`）
  - DoT 域名形态端点：`secure_resolver.rs` 端点接受 `host:port` 域名形态
    （如 `dns.example.com:853`）——解析 IP 建连 + SNI 携带域名 + 证书按
    域名校验（webpki-roots 信任根与强制校验不变）；新增 4 项 mock 契约
    测试（解析形态 / SNI 域名 / 建连地址解析 / 构造过滤）（`dns/src/secure_resolver.rs`）
- **打包线程上限 8 → 4（用户要求 2026-08-04）**：`release/package.bat`
  `CARGO_BUILD_JOBS=8 → 4`；`.cargo/config.toml` `jobs = 8 → 4`（大小核机器
  超限并行会死机，工作区所有 cargo 命令统一上限 4）

## [v0.1.0] - 2026-07-31

### Added
- M1：工作区 7 crates 骨架、配置加载/保存（`~/.kirin_desk`）、日志系统（文件+控制台双输出、旧日志清理）
- M2：零信任加密引擎（Ed25519 身份、X25519 ECDH、AES-256-GCM、ChaCha20-Poly1305）
- M3：DNS 服务注册与发现（GoDaddy SRV/AAAA/TXT CRUD、三路并行发现、心跳保活、本地缓存）
- M4：TCP 连接层（IPv6 双栈、全挑战-响应握手、SecureChannel AEAD、指数退避重连）
- M5：媒体基础（屏幕捕获、JPEG 编解码、远程输入事件定义）*
- M6：egui GUI（Dashboard/Devices/Connect/Settings 四标签页）+ CLI 8 子命令、身份加载、连接窗口、审批弹窗、实时日志
- M7：测试体系（81 单元测试、`--cli self-test` 端到端自测）
- M8：QUIC 窗口式 H.264 媒体传输（FFmpeg libavcodec 编解码、WGC 捕获、自适应反馈闭环、解码层 P2A–P2D）
- M9：FFmpeg 硬件编码（nvenc/amf/qsv/vaapi/videotoolbox 经 FFmpeg 统一栈）
- M10：Domain 模式 DNS 发现连接、设备列表持久化（devices.json）、Devices 页增强
- M11：远程 Shell（PTY 模式）、终端窗口 UI、CLI shell
- M12：Linux 支持（pipewire 捕获、VAAPI、uinput 输入）*
- M12-MAC：macOS 支持（zed-scap 捕获、CGEvent 输入、CoreAudio 环回、VideoToolbox、Keychain 身份存储）
- M13：音频捕获/播放、剪贴板共享（arboard）*

\* 部分功能为骨架/占位，细节见对应设计文档。

[Unreleased]: https://github.com/kirin-yucall/kirin_desk/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/kirin-yucall/kirin_desk/releases/tag/v0.1.0
