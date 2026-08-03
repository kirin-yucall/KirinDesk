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

- **R-15b hw_bridge 零拷贝真实实现（审计 §4-5 / §2-P1-5，修复计划 2026-08-04 WBS 3.3）**：
  `libkirin_gpu/src/hw_bridge.cpp` 的 `kgpu_hw_upload` 由桩（恒 NULL）替换为
  **真实实现**——NV12 纹理经 `AVD3D11FrameDescriptor` 零拷贝直绑
  （无 `av_hwframe_transfer_data`、无 CPU 往返）、BGRA8 纹理由 D3D11 像素
  着色器两 Pass 在 GPU 内转 NV12（BT.601 limited，零 CPU；测试校验才回读）；
  `AVHWDeviceContext` 手工包装内核 D3D11 device（与 capture 同实例前提），
  `avutil-60.dll` 运行时动态加载（与 media 架构红线一致，不静态链接导入库）。
  Rust 侧（`gpu_ffi/kernel.rs` 等）接驳激活并新增 7 个测试：零拷贝绑定断言
  （`test_hw_upload_frame_type` / `test_hw_upload_zero_copy`）、BGRA GPU 转换
  绑定、C 侧自检（含 BT.601 内容校验，UV 平面读回受 Intel 驱动限制时软跳过）、
  三态决策（首帧 FullFrame/同帧 Static/微变 Incremental，微变读回 ≤16KB）、
  1080p 基准 **GPU 0.65ms/帧 < 2ms**（CPU 回退 22~27ms/帧，P1G 对比数据）。
  随附修复两个休眠 bug（该 C++ 内核首次实机编译运行）：
  (1) `hash_buf_b` 缺 `D3D11_BIND_UNORDERED_ACCESS` → swap 后 UAV 创建失败 →
  三态恒 FULLFRAME（`d3d11_context.cpp`）；(2) 源文件 UTF-8 编码在 MSVC
  CP936 代码页下解析错位 → `target_compile_options(/utf-8)`。
  另：`media/build.rs` 自动探测仓库内 FFmpeg 8.1.1 dev 头（include/lib 随
  捆绑 8.1.1 shared build，`KG_HAVE_FFMPEG_HEADERS` 生效）；`AV_PIX_FMT_D3D11`
  常量核对为 8.1.1 实测枚举值 171；`kgpu_init/shutdown` 引用计数化（多持有者
  并行安全，生产单次 init/shutdown 语义不变）
- **R-20b 身份存储 PKCS#8 宣称修正（审计 §2-P3-18，修复计划 2026-08-04 WBS 3.7）**：
  `core/src/crypto/ed25519.rs` 存储格式注释/文档与实现对齐——Ed25519 私钥
  落盘为**自定义加密存储（AEAD + AAD 上下文）**：JSON `{nonce, ciphertext}`、
  ChaCha20Poly1305（当前 AAD 为空字节串）、密钥由 device_id 派生；明确
  **不实现真 PKCS#8**（避免无谓复杂度），该格式现仅作 legacy 迁移源
  （`try_migrate_legacy`），新存储走 KeyStore 后端（DPAPI/Keychain/secret-tool）。
  全仓 grep 核对：其余 PKCS#8 提及均为真实使用（Google OAuth RSA PEM、
  rcgen 证书、relay 服务器密钥 PKCS#8 DER），无虚假宣称残留
- **R-22b FFmpeg 字段偏移硬编码核对清单（审计 §2-P3-21，修复计划 2026-08-04 WBS 3.8）**：
  `media/src/ffmpeg/api.rs` 头部升级核对清单补齐**运行时验证方法**（偏移
  重核后回归：`dlls.rs` major 断言单测、符号表加载、`quic_loopback`/
  `quic_bisect` 出码流 + 解码回读、`avctx_get_int/get_ptr` 读回自检）；
  `dlls.rs` 版本断言（`SNAPSHOT_FFMPEG_MAJOR=62`）与「偏移依赖」说明保持
  不变——主版本不符直接拒绝加载，绝不带错偏移运行。无逻辑改动
- **R-23b HW 编码器 reconfigure 空实现收口（审计 §2-P3-22，修复计划 2026-08-04 WBS 3.9）**：
  `FfmpegHwEncoder::reconfigure` 不再 `Ok(())` 静默成功。审计结论：生产唯一
  调用点 = `WindowPipeline` 每窗口编码前；自适应层会真实产出 QP/preset 变更，
  但 HW 编码器以 cbr 码率模式运行（QP 全仓零消费者，分辨率走
  `ensure_codec_dims` 懒重开）→ 参数真实变化时返回显式
  `EncodeError::NotImplemented`（新增变体），`force_idr` 真实置位（与软编
  对齐），无变化幂等 `Ok`；调用方（`window_pipeline.rs`）显式规避——记
  warning 沿用旧配置继续编码。新增 5 个单测锁定三态行为
  （`media/src/encoder/video/ffmpeg_hw.rs`）
- **R-33 ui/dns/utils warnings 归零（审计 §1 构建列，修复计划 2026-08-04 WBS 3.10）**：
  本任务范围内 `cargo check` 警告从 39 条降至 0（ui 23 + dns 8 + utils 2 +
  core 2 基线；不含并行任务在途代码）：未用 import 删除（BLOCK_SIZE/
  FileTransferError/stat_card/FontDefinitions/ResolverError/Read/ButtonKind/
  ButtonState/action_button）、未用变量与赋值收敛（pos/use_temp_key/
  unattended/state_file）、f64→f32 字面量显式化（`1.5_f32` 等 10 处）、
  DoH JSON 契约字段 non_snake_case 标注、dead_code 标注带理由（dns 测试
  注入接口与 Google 错误体字段、macOS 专用 xml_escape）、
  `kirin_gpu_linked` cfg 在 ui/Cargo.toml 声明（与 media 同配置）
- **R-19b ConnectRequest SocketAddr 泛化（审计 §2-P3-19，修复计划 2026-08-04 WBS 3.6）**：
  连接事件层地址视角从 v6-only 泛化为 v4/v6 统一（传输层已双栈，事件层不再 v6-only）：
  `ConnectionEvent::ConnectRequest` 的 `ipv6+port` 字段合并为 `addr: SocketAddr`
  （对齐 M8-T025-P2 泛化模式，`core/src/connection/manager.rs`），`ManagedConnection`
  的 `peer_ipv6/peer_port` 合并为 `peer_addr: Option<SocketAddr>`；`TcpServer::accept`
  改返回 `SocketAddr` 且 v4-mapped v6（`::ffff:` 前缀）在事件层呈现为真实 v4 地址
  （`core/src/network/tcp.rs`，map_addr 前缀剥离）；UI 服务端连接处理签名同步
  （`ui/src/lib.rs::handle_incoming_connection`）。core 新增 v4/v6 混合用例
  （v4 直连呈现真实 v4、v4-mapped 规范化、原生 v6 保留、canonical_addr 纯函数）；
  core 218 项 lib 测试全绿
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
- **配置加密接线（R-13b，审计 §2-P2-9 / §4-9 / §6.6）**：`utils/src/secure.rs`
  （ChaCha20Poly1305 密文 `{v: base64(nonce‖ciphertext)}` + DPAPI/macOS
  Keychain/`KIRIN_CONFIG_KEY` 主密钥分层 + AAD 上下文绑定）由零调用点接线到
  配置存取全链路：
  - S1 存取：`Config::save_to` 保存前加密敏感字段（`[godaddy]` api_key/
    api_secret、`[tunnel]` token、`device` challenge_code、`[dns.providers.*]`
    敏感 key——api_key/api_secret/api_token/token/secret_key 等 13 个，与
    `dns_providers` 注册表 secret 字段 drift 测试守护）；`Config::load_from`
    加载后解密为内存明文；AAD 绑定配置段上下文（`godaddy.api_key`、
    `dns.providers.<name>.<key>`），防跨字段替换（`utils/src/config.rs`）
  - S2 迁移：旧明文敏感字段首次加载自动加密重写（幂等，二次加载不重写）；
    解密失败（主密钥变更/丢失/密文篡改）→ 加载 fail-closed
    （`ConfigError::Decrypt`，不把密文当凭据用）；写回失败显式告警且
    `write_private` 原子替换保证不半写坏配置；`[godaddy]`→`[dns.providers]`
    旧迁移同步加密落盘
  - S3 脱敏：`config show` 输出配置加密状态（密钥源 + 启用与否）与隧道
    令牌掩码；密钥/令牌不进 CLI 输出（`ui/src/cli.rs` cmd_config 区）；
    `[ddns]`/`[dns.security]` 评估结论：无凭据（公网 IP/公开端点/超时参数）
    → 不入加密域，保持明文（审计 §6.6）
  - S4 密钥环缺失：无密钥源（Linux 无桌面密钥环且未设 `KIRIN_CONFIG_KEY`）
    → fail-open 明文 + 醒目告警一次，不阻断开发使用；密钥提供者按配置目录
    进程内缓存（`secure::key_provider_for`），无密文文件加载不触碰密钥环
    （模板/新配置零副作用）
  - 新增单测 14 项：密文往返/落盘无明文/迁移自动重写/幂等/fail-closed
    （错误密钥、损坏密文）/注册表 drift 守护/密钥源缓存等（utils 145 项
    全绿）；Readme 宣称恢复"已实现"表述由波次 3 R-25b 按证据定稿
- **打洞两端缝合（R-08b，审计 §4-4 / §2-P2-12）**：P1 打洞由"库内就绪、
  运行时无路径"缝合为真实部署形态：
  - S1 帧分发（`relay/src/server.rs` 帧分发区）：`run_session` 新增
    `PunchResult` / `PathProbe` / `PathProbeAck` 匹配分支（与既有
    `CandidateRegister` 路径并列），不再落入 `_ =>` 忽略——经进程内
    rendezvous 打洞处理（透传对端 + 审计）；`CandidateRegister`（session_id=Some）
    并行接入 rendezvous（隧道控制连接成为打洞会话参与者，登记/互转/限速/
    审计复用 PUNCH-006）；无 rendezvous 挂载时打洞帧解码校验后审计丢弃
    （不静默忽略），坏帧判死（TNL-PROTO-007）；会话清理同步移除打洞会话表
    槽位（PUNCH-003 无残留）
  - S2 部署入口（`relay-server/src/main.rs`）：新增 `--rendezvous-port`
    （默认 7001）与 `--no-rendezvous`，进程内启动 `RendezvousServer`（登记/
    互转/限速/审计复用）；非法值（非数字/0）、`--no-rendezvous` 与
    `--rendezvous-port` 矛盾、与 `--bind-port` 同号 → 一律 fail-closed
    exit(2)（对齐 `--bind-addrs` 口径）；`RendezvousServer::serve` 连接任务
    JoinSet 跟踪，优雅关闭中止全部连接任务（无残留协程）
  - S3 验证与文档：`release/server/README.md` 更新 `--rendezvous-port`/
    `--no-rendezvous` 参数表与防火墙放行口径（7000 + 7001 + 端口范围）；
    新增 relay 库内 e2e 3 项（打洞端口候选交换+优雅关闭 / 隧道控制连接
    打洞互转+透传+无残留 / 无 rendezvous 审计丢弃+坏帧判死）+ relay-server
    二进制部署 e2e 1 项（真实进程 → 打洞候选交换 → 审计 stdout 输出）+ 
    main.rs 参数解析单测 4 项（relay 94 / relay-server 13 项全绿）
- **TCP_NODELAY 全仓接入（R-31，审计 §4-3 / O4）**：Windows 默认 Nagle
  开启下大视频帧后紧跟的小包（音频/键鼠）被滞留（在途未 ACK 时小段不
  立即发出），对交互延迟影响大于帧路径选择——全仓 TCP 连接建立后统一
  关闭 Nagle：
  - `core/src/network/tcp.rs` 新增 `set_nodelay` 辅助（追加式，R-19b 波次 2
    accept 事件视图区不受影响），`TcpServer::accept` 侧接入；新增 2 项单测
    （helper 生效 / accept 侧 nodelay 读回）
  - core 客户端连接点：`connect_peer` TCP 建立后接入
    （`core/src/connection/client.rs`）
  - relay 隧道连接建立处：主 accept 循环 + `proxy_listener` work 公网连接
    （`relay/src/server.rs` 连接建立 nodelay 区，与 R-08b 帧分发区互不越界；
    relay 为叶子 crate 不依赖 core，直接调 `TcpStream::set_nodelay`）
  - media TCP transport：客户端 `connect_tcp_transport` + 服务端
    `accept_tcp_transport` 两处接入（`media/src/transport/transport.rs`）
  - grep `set_nodelay` 全仓 6 调用点（core 连接/accept + relay 隧道×2 +
    media TCP×2）；失败不致命（连接仍可用，仅延迟优化失效，告警处理）；
    全量回归 1537 项全绿 + `--cli self-test` 全过；小包频繁发送的流量开销
    变化并入 R-26b A 组延迟实测项
- **CLI identity/version 子命令（R-09b，审计 §4-6 / §2-P2-10）**：补齐
  08-02 审计遗留的 CLI 缺口（`ui/src/cli.rs` dispatch/help/`CliCommand`
  变体区，只增不改）：
  - `version`：程序版本 + 核心 crate 版本表（`env!("CARGO_PKG_VERSION")`，
    覆盖 core/dns/input/media/relay/relay-server/updater/utils/ui 九个工作区
    成员；`VERSION_TABLE_CRATES` 以 `include_str!` 内联各成员 Cargo.toml，
    单测守护"全部成员 `version.workspace = true`"，版本表不会静默失真）
  - `identity`：Device ID（`effective_device_id` 语义，与 GUI Dashboard
    身份卡一致）、Ed25519 公钥（32 字节小写 hex + base64）、SHA-256 指纹
    （`core::crypto::ed25519::fingerprint`，与 known_hosts 比对算法一致）、
    密钥文件路径（`IdentityManager::default_path`，同 GUI 路径）、known_hosts
    条目数与存储路径（复用 `KnownHostsStore`）；`--json` 输出单行 JSON
    （device_id/ed25519_public_key_hex/ed25519_public_key_base64/
    fingerprint_sha256/key_file/known_hosts_path/known_hosts_count 七字段，
    jq 可解析，供脚本集成）
  - `--help` 同步（COMMANDS 两行 + EXAMPLES 两行）；`cli_tests` 新增单测：
    dispatch 映射、`--json` 精确匹配、JSON 字段契约（单行 + serde 往返
    解析 + 字段集完整）、版本表 workspace 版本守护；ui 测试全绿 +
    `--cli self-test` 全过 + 全量回归只增不减
- **macOS 多显示器坐标偏移（R-21b，审计 §4-10 / §2-P3-20）**：
  `input/src/macos.rs` 注入坐标由"恒以主显示器为原点"补齐多屏布局偏移换算
  （对齐 `M8-T018_多显示器查看模式.md` 坐标映射）：
  - 多屏布局换算纯函数（跨平台可单测）：`DisplayRect`（`CGDisplayBounds`
    全局原点 + 像素/逻辑尺寸，`scale()` = 每 point 像素数，Retina 各屏独立）+
    `to_global_point`（局部像素 → 全局 CGEvent point，公式
    `origin + local_px / scale`——副屏在**左/上**时全局坐标为负、**右/下**
    为正）+ `select_display_by_resolution`（按像素分辨率匹配"选中显示器"，
    M8-T018 归一化基数 = 所选屏分辨率）+ `primary_display_index`（主屏 =
    全局原点 (0,0)）
  - 运行时接入：`to_display_point` 经 `CGGetActiveDisplayList` 枚举活跃
    显示器布局（新增 `CGDisplayPixelsHigh` / `CGGetActiveDisplayList` 两个
    dlopen 符号，输出缓冲 32 上限），按注入器传入的选中屏分辨率
    （`InputInjector::set_resolution` 显示器切换时同步更新）匹配目标屏并
    叠加其全局原点偏移；无匹配/枚举失败回退主显示器（`CGMainDisplayID`，
    与修复前行为一致，不崩溃）
  - 新增 9 项单测：副屏在左/上/右/下四象限偏移、Retina 2x scale、主屏无
    偏移回归、分辨率匹配/无匹配/空表、主屏索引回退、scale 非法尺寸回退
    1:1（input 43 → 52 项全绿）；同分辨率多屏取首个匹配为已知限制（注入
    接口未携带屏索引，分辨率匹配为最小可行方案），实机验证项登记 R-26b
    J03（需 macOS 设备，待设备）
- **AV1 阶段 B 接入（R-32，审计 §4-8 / §2-P3-23，M13-T002 阶段 B）**：
  R-16 阶段 A（av1_probe 探索，SVT-AV1 链路验证 + 码率效率 ~6×）结论接入
  产品路径：
  - `Codec::AV1` 枚举变体（`media/src/encoder/types.rs`）+ 协商字符串
    `as_str`/`from_str`（`"av1"`，与 h264/h265 同族 wire 格式，序列化兼容）；
    `ffmpeg_sw_name` → `libsvtav1`
  - 编码能力协商接线（session/proto 路径）：客户端握手
    `supported_codecs` 携带本端**可解码**列表（`decoder::client_supported_codecs`，
    按 [av1, h265, h264] 优先级，解码链存在性过滤）；服务端
    `negotiate_codec_by_server_priority`（core 新增，服务端编码优先级
    AV1 → H.265 → H.264 从交集挑选，交集为空 → 空串 → 客户端 H.264 兜底，
    兼容旧客户端空广告）；`core::crypto::handshake` 新增追加式
    `client_handshake_with_codecs_generic`（旧函数委托空列表，行为不变）；
    服务端两侧握手（`ui/src/policy.rs::server_accept_handshake` + GUI
    `ui/src/lib.rs` 内联握手）均按 `encoder::detect_supported_codecs_cached()`
    协商应答
  - 编码器接入（SVT-AV1）：捆绑 FFmpeg 8.1.1 full build 勘察结论 =
    **含 libsvtav1**（静态编入 avcodec-62.dll，无独立 SvtAv1 DLL；ffmpeg.exe
    `-encoders` 实测确认 libsvtav1/libaom-av1/librav1e + libdav1d/av1 解码器）。
    `ffmpeg_sw.rs::open_with_dict` AV1 专用参数（preset=8 数值档、跳过
    maxrate——SVT VBR 下 maxrate 报 "Max Bitrate only supported with CRF"、
    无 zerolatency tune）+ `encode_inner` EAGAIN 短等待排空（SVT 异步
    lookahead，单帧调用也能取回包，x264/x265 零额外延迟）；
    `decoder::factory` AV1 解码链（软解 `av1`，HW AV1 待零拷贝桥后评估——
    规避 h264_qsv 同族 MFX 驱动损坏崩溃风险）
  - 回退链（验收口径）：`factory::create_video_encoder` 跨 codec 兜底——
    AV1 全链（libsvtav1 → libaom_av1 → librav1e）不可用 → **自动回退
    H.264（libx264）且无报错**；AV1 暂不接 HW（`FfmpegHwEncoder` 候选名
    表 h264/hevc 系与 AV1 不匹配，待 AV1 HW 链并入）；会话层按协商结果
    创建编码/解码器（`ui/src/lib.rs` 服务端编码器 + 客户端解码器、
    `media/src/session.rs` 经 `MediaTransport::negotiated_codec`，默认 H.264
    零改动）
  - 单测：Codec wire 往返、AV1 回退链形状 + 跨 codec 兜底（无 AV1 编码器
    → H.264 且不报错）、协商函数（服务端优先级/客户端顺序/交集空）、
    带 codec 列表握手 wire 往返（服务端读到 supported_codecs 并应答
    selected_codec=av1）、AV1 码流合法性（Annex B 起始码 + 关键帧）、
    AV1 编码 → 解码回读（生产解码链软解 av1，多帧全可解）；全量回归
    只增不减
- **id_mode 打洞 hook 接入（R-18b，审计 §4-7 / §2-P3-16）**：
  `core/src/connection/id_mode.rs` 三级路径由"直连→中继"两级补齐为
  "直连→打洞→中继"真三级：
  - S1 打洞 hook（`IdConnector::try_punch` / `try_punch_with_session`）：
    直连失败后经 rendezvous（R-08b `--rendezvous-port` 独立监听）交换候选
    + UDP 探测 / TCP 同时打开（复用 `punch::PunchSession::establish()`，
    PUNCH-001~006）；候选来源 = `DeviceInfo`（UDP 条目 + 服务器观察地址
    OBSERVED 条目，PUNCH-PROTO-001）；会话复用 PUNCH-SEC-003（发起方生成
    128 位随机 session_id 并 pin，`try_punch_with_session` 供经控制面告知
    对端后的配对入口）；单段参数取快速失败预算（整体受 connect_timeout
    约束，PUNCH-PROTO-007）
  - S2 结果映射：TCP 同时打开成功（`PunchTcp`，PUNCH-SEC-001 内建 Ed25519
    双向握手 + 公钥 pin 强制比对，返回流不再重复握手）→ 路径交付；UDP
    成功（`PunchUdp`）→ socket 属媒体层 QUIC 升级路径（`M8-T026_接口交互
    协调.md` §3.6），初始编排以中继为控制面让位；失败/无候选/未配置
    rendezvous → 中继兜底（连通性不降级）
  - S3 配置与审计：`IdModeConfig` 新增 `identity`（打洞握手身份，None 懒
    加载默认身份 `~/.kirin_desk/identity/ed25519.json`）与
    `punch_rendezvous_addr`（None = 未配置跳过，不再产生 `punch_skipped`，
    路径选择如实审计）；打洞尝试/成败写 utils 审计（PUNCH-SEC-004）；
    本端打洞地址按对端族选择（回环/本机接口，R-17），pin 取自解析响应
  - S4 测试：core 新增 4 项单测（无候选跳过 / 未配置 rendezvous 跳过 /
    打洞 TCP 建立——进程内 rendezvous + 对端会话，PunchTcp + 内建握手
    身份 / 无对端快速失败）+ self-test 增段 `R-18b id_mode punch path`
    （子用例 A：直连失败 → 打洞发起（rendezvous 候选登记审计）→ 降中继；
    子用例 B：设备侧会话同 session 响应 → punch-tcp 建立 + 双端互转审计）；
    core 225 项全绿 + `--cli self-test` 全过 + 全量回归只增不减
  - 遗留：设备侧打洞响应器（relay `id_client` 接 `PeerCandidates` + 探测
    应答）与 `[tunnel] rendezvous_addr` 配置接线为后续任务——当前生产默认
    未注入 rendezvous 时打洞阶段跳过（日志注明），已配置时打洞尝试发起并
    审计，无响应自动降中继
- **说明（R-25b 复核，2026-08-04）**：波次 2 部分任务改动经并行提交 `28696ed`
  合入，内容完整经复核——该混合提交同时携带代码（R-15b hw_bridge 零拷贝等）
  与 Readme/文档修正，未拆分改写历史，逐项核对无遗漏、无冲突

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
