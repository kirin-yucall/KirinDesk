# 🦄 KirinDesk — 颠覆 SSH 与传统远程桌面的新一代 P2P 远程控制

**P2P 直连优先 · 服务器辅助打洞 · 中继兜底可选 · 零 TLS 证书 · 端到端加密**

> **English:** [Readme.md](Readme.md) ｜ **中文:** 本文件

**告别 SSH · 告别 RDP · 告别中心化中转 — 未来的远程控制，设备与设备直接对话。**

---

## 💜 用爱发电 · 纯公益项目

KirinDesk 由一位个人开发者在业余时间出于热爱打造并维护，**是一个不含任何盈利内容的纯公益项目**：

- **分文不取** — 无订阅、无付费功能、无 "Pro" 版本
- **无广告、无追踪、无遥测** — 不收集任何数据，没有统计分析
- **无账号体系、无厂商绑定** — 你的设备永远完全属于你自己
- **完全开源** — 在 [License](#license) 许可下自由使用、学习、修改与分享

支撑这个项目运转的唯一"货币"是 ❤️。如果 KirinDesk 对你有所帮助，最好的回报是点一个 ⭐、提交一个 bug，或把它分享给需要的人。

## 🚀 为什么选择 KirinDesk？

KirinDesk 的目标只有一个：**让 SSH 和所有传统远程桌面产品退休。**

传统远程控制的世界充满痛点：

- **SSH** — 22 端口全球可扫，密码爆破攻击无休无止，只能靠 fail2ban 这类补丁式防守；
- **RDP / VNC** — 认证依赖中心化服务，端口 24 小时暴露，流量缺乏端到端加密；
- **TeamViewer / AnyDesk 等商业产品** — 流量全部经过厂商中心化服务器中转，服务中断、数据泄露、隐私疑云始终挥之不去。

**KirinDesk 给出终极答案：设备之间直接握手。**

```
传统方案                                  KirinDesk（直连路径）
─────────                                  ─────────────────────
设备 ──▶ 中心服务器 ──▶ 设备                设备 ──▶ 设备
        (中转 / 可断 / 可窃听)              (直连 / 无中间人)
```

- **P2P 直连优先** — IPv6 让每一台设备全球可达，设备与设备之间直接建立点对点加密隧道，数据不经过任何第三方；当直连不可达（NAT/防火墙/地址漂移）时，**可选的服务器辅助打洞**（rendezvous 只牵线、不进数据面，打洞成功后仍为双端直连）与**设备 ID 中继兜底**保证连通，端到端加密全程不变。
- **DNS 即去中心化公告板** — 通过 DNS（20 家服务商）的 SRV（端口）+ AAAA（IPv6 地址）+ TXT（设备公钥）记录动态注册与发现设备，天然去中心化，没有可以停摆、可以审查的中心服务。
- **零信任端到端加密** — 摒弃传统 TLS 证书体系，Ed25519 身份密钥 + X25519 ECDH + AEAD（AES-256-GCM），每次会话独立派生密钥，具备前向安全性——长期密钥泄露也不影响历史会话。
- **取代 SSH** — Server 模式将远程 Shell 提升到新高度：无端口暴露、域名白名单、挑战码 + 签名双重认证。
- **域名 + 设备 ID 白名单（而非 IP 白名单）** — 白名单用域名或设备 ID 表达而非 IP 地址：名称稳定、人类可读、可随地址变化自动保持有效，且与 DNS 身份注册表天然一致；设备 ID 支持精确 / `*` 前缀通配 / 可过期条目，域名与 ID **任一命中即放行**，临时连接可跳过全部白名单，既方便又安全。

### 与传统方案对比

| 维度 | 传统 SSH | RDP / VNC | 商业远程桌面 | **KirinDesk** |
|------|---------|-----------|-------------|---------------|
| 连接方式 | 端口直连 | 端口直连 | 中心化服务器中转 | **P2P 直连优先 + 打洞辅助** |
| 中继服务器 | 无 | 无 | 必需 | **可选（自建：打洞牵线 + 兜底）** |
| 端口暴露 | 22 全球可扫 | 可扫 | 无 | **无固定端口暴露** |
| 认证方式 | 密码/密钥 | 密码/证书 | 厂商账号 | 挑战码 + Ed25519 签名 |
| 加密强度 | 传输级 | 弱/无 | 取决于厂商 | **端到端 AEAD，前向安全** |
| 访问控制 | — | — | 厂商账号 | **域名 + 设备 ID 白名单（严格模式）** |
| 隐私 | — | — | 流量经第三方 | **端到端加密，中继不可读** |
| 去中心化 | ✗ | ✗ | ✗ | **✓ 完全去中心化** |

---

## ✨ 核心特性

- **IPv6 / IPv4 直连优先** — 利用 IPv6 全球可达性直连，无需端口映射；直连不可达时走服务器辅助打洞（rendezvous 仅牵线，数据面双端直连）+ 设备 ID 中继兜底；IPv6 优先 + IPv4 双栈支持
- **零信任加密** — Ed25519 身份密钥 + X25519 ECDH + AEAD（AES-256-GCM / ChaCha20-Poly1305），每次会话独立派生密钥；握手 pin **强制比对**（已删除"空串跳过"兼容路径）；敏感配置（API 密钥、Token、挑战码）加密落盘（R-13 已接线，详见下文"配置加密"）
- **DNS 去中心化发现 — 20 家服务商** — 支持 GoDaddy、Cloudflare、阿里云、腾讯 DNSPod、AWS Route 53、Azure、Google Cloud、华为云、Namecheap、DigitalOcean、Vultr、Linode、Hetzner、OVH、Porkbun、百度智能云、火山引擎、京东云、西部数码、新网；SRV + AAAA + TXT 三路并行查询，心跳保活
- **域名 + 设备 ID 白名单（严格模式）** — 访问控制用稳定名称表达而非易变 IP；域名或设备 ID（精确 / `*` 前缀通配 / 可过期）任一命中即放行；临时模式签发 10 位一次性挑战码并跳过白名单，应急直达
- **双模式连接 + 传输自动降级** — 域名模式（DNS 发现，推荐）或 IPv6/IPv4 直连模式；QUIC 优先，会话中途自动优雅降级 TCP（续传不中断）
- **远程桌面** — FFmpeg libavcodec H.264/H.265 编码/解码，硬件加速（NVENC/AMF/QSV/VAAPI/libx264）+ QSV 硬解与软解回退；单 GPU 选择 + 虚拟驱动/虚拟显示器过滤（向日葵/IDD/Parsec 等）；多显示器查看与热切换；隐私模式（黑屏/锁屏）
- **自适应媒体管道** — 70ms 窗口化 QUIC 传输（数据报 + 可靠流、丢包检测）+ 实时编码参数反馈闭环
- **音频** — 捕获与播放、麦克风回传被控端（Opus）、会话内三开关
- **远程 Shell** — 无头 Ubuntu Server 远程终端（PTY，替代 SSH）
- **文件传输** — 双向、加密、断点续传（滑窗 ACK、SHA-256 校验、原子改名）；GUI 拖拽发送 + CLI `send` / `recv`
- **无人值守模式** — 用户级开机自启 + 白名单/已知客户端自动放行，无需审批弹窗
- **内网穿透（Tunnel）** — FRP 式通用 TCP 反向代理：把内网 TCP 服务（SSH/RDP/HTTP…）映射到公网 relay 服务器；SCRAM 式挑战-响应口令认证（口令永不明文上线）、服务器端口全可自定义（`--bind-port` / `--bind-addrs` / `--rendezvous-port`）、客户端任意自定义端口 + token 连接、多地址监听、GUI 一键启停并自动恢复；独立 `relay-server` 支持 Docker/systemd/无头部署；可选服务器辅助打洞 + 设备 ID 中继兜底
- **剪贴板共享** — 跨设备复制粘贴（加密通道内传输）
- **国际化（i18n）** — GUI 全界面 中文 / English，默认跟随系统语言
- **安全加固** — 连接速率限制、审计日志（30+ 事件）、SSH 式 known-hosts 指纹确认、配置加密
- **跨平台** — Windows（egui GUI + CLI）、Linux（pipewire 捕获、VAAPI、uinput）、macOS（zed-scap、VideoToolbox、Keychain 身份存储）
- **自动日志** — 每日轮转日志文件 `~/.kirin_desk/logs/kirindesk-YYYY-MM-DD.log`，自动清理旧日志
- **开箱即用的发布体系** — NSIS 安装包（Windows）、.deb + systemd 服务（Ubuntu）、通用 .app + .dmg（macOS）、应用内自动更新（release/beta 通道）

## 🆕 近期更新（2026-08）

自 v0.1.0 以来，一批重大功能与安全加固已落地——完整记录见 [CHANGELOG.md](CHANGELOG.md)：

- **DNS 多服务商客户端（20 家）** — 记录 CRUD（A/AAAA/CNAME/MX/TXT/SRV/NS）、测试连接、域名列表；Domain 页 + `dns` CLI
- **Tunnel 内网穿透独立页** — FRP 式反向代理，GUI 一键启停与状态自动恢复、多地址监听、Token 一键生成/复制；独立 `relay-server`（Docker/systemd）
- **国际化（i18n）** — GUI 全界面 中文 / English（默认跟随系统）
- **文件传输** — 加密、断点续传、双向
- **无人值守模式** — 开机自启、白名单/已知客户端自动放行
- **多显示器查看** — 会话窗口工具栏实时切换显示器
- **单 GPU 与虚拟设备过滤** — 自动选中真实 GPU，过滤虚拟驱动/虚拟显示器
- **安全加固** — 握手 pin 强制比对、配置加密（R-13）、设备 ID 白名单、SCRAM 式穿透认证、速率限制与审计日志

## 快速开始

### Windows

从 [release](release/) 下载 `KirinDesk.exe`，双击启动 GUI。
或使用命令行模式：

```batch
KirinDesk.exe --cli setup          # 交互式配置向导
KirinDesk.exe --cli register my-pc # 注册设备到 DNS
KirinDesk.exe --cli serve 3389     # 启动服务端
```

### Ubuntu Server

```bash
# 依赖
sudo apt install build-essential libssl-dev pkg-config \
  libx11-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev libwayland-dev libavcodec-dev \
  libavutil-dev libswscale-dev

git clone <repo>
cd KirinDesk
# --jobs 4: 线程数上限(硬性约束),禁止满线程打包——大小核设备线程过多会死机
cargo build --release -p kirin-desk-ui --jobs 4

# 配置与服务端
./target/release/kirin-desk-ui --cli setup
./target/release/kirin-desk-ui --cli register my-server 22
./target/release/kirin-desk-ui --cli serve 22
```

### 克隆后从源码构建

```bash
git clone https://github.com/kirin-yucall/KirinDesk.git
cd KirinDesk
```

**1. 前端依赖** —— `ui/frontend/node_modules/` 被 `.gitignore` 忽略（不入库）,clone 后需先还原:

```bash
cd ui/frontend
npm ci                # 按 package-lock.json 安装
npm run build         # 生成 dist/(Tauri 应用运行时读取)
cd ../..
```

**2. FFmpeg 二进制** —— `ffmpeg/ffmpeg-8.1.1-full_build-shared/` 被 `.gitignore` 忽略（不入库,clone 后目录不存在,`git ls-files ffmpeg/` 应为空）,需自行下载还原:

1. 下载 [ffmpeg-8.1.1-full_build-shared.zip](https://github.com/GyanD/codexffmpeg/releases/download/8.1.1/ffmpeg-8.1.1-full_build-shared.zip)(GyanD 共享版;链接 2026-08-03 实测可下载);
2. 解压后**整个目录放到** `ffmpeg/ffmpeg-8.1.1-full_build-shared/`(zip 内目录名一致,无需改名)——加载器按此目录名搜索(见 `media/src/ffmpeg/dlls.rs`);
3. 自检:确认 `bin/` 下存在 `avcodec-62.dll`(libavcodec 62.28.101)、`avutil-60.dll`、`swscale-9.dll` 等共享库(缺库加载会直接失败)。

> **为何用 8.1.1 而非 8.1.2**:8.1.2 构建捆绑 ffnvcodec 13.1 头,`h264_nvenc` 要求 NVIDIA 驱动 ≥610.00;8.1.1 捆绑 13.0 头,兼容 591 系主流驱动(本机 591.86 实测出码流 ✓,2026-08-02)。两者均为 libavcodec 62,硬编码偏移快照(`SNAPSHOT_FFMPEG_MAJOR = 62`)兼容——决策记录见 `task_docs/共享层/M8-T030_单GPU硬件加速与虚拟设备过滤_需求设计.md` §5.2。
>
> 若要直接运行发布版 `release/KirinDesk.exe`,还需把其中的 DLL(`avcodec-62.dll`、`avutil-60.dll`、`swscale-9.dll` 等)复制到 `release/ffmpeg/bin/`。

**FFmpeg 升级步骤**(R-22):编解码路径对 `AVCodecContext`/`AVFrame` 结构体字段按**硬编码字节偏移**直写,偏移基于 FFmpeg **8.1.1**(avcodec-62/avutil-60,libavcodec 62.28.101)实测验证(8.1.x 同 major 62 兼容)。升级主版本时:

1. 逐一重核 `media/src/ffmpeg/api.rs` 中的全部偏移(`avctx_offset::*`、`AVFRAME_CH_LAYOUT_OFFSET`),对照新版 `avcodec.h`/`frame.h` 的 `offsetof` —— 核对清单已内联在常量上方;
2. 同步更新 `media/src/ffmpeg/dlls.rs` 中的库名/so 名(`AVCODEC_LIB` 等)、`DLL_VERSION_FALLBACKS` 与 `SNAPSHOT_FFMPEG_MAJOR`。加载器检测到主版本与快照不符会**直接报错**,绝不带过期偏移静默运行;
3. 核对 `FnTable` 符号表(必需符号缺失 → 加载失败;可选 HW 符号 → 功能降级);
4. 更新本文件与内联清单中的版本快照字样。

**3. 编译** —— `target/` 由 cargo 生成（git 忽略）,不入库:

```bash
cargo build --release -p kirin-desk-ui --jobs 4
```

> ⚠️ **线程限制(硬性约束):** 打包机为大小核(big.LITTLE)架构设计,可能有 bug,
> **编译/打包线程过多会死机**——所有构建、打包、测试命令必须限制并行度
> (`--jobs 4` 或 `CARGO_BUILD_JOBS=4`),**禁止满线程**,详见
> `task_docs/共享层/M14_发布与打包.md` 硬性约束章节。

### 客户端连接

```bash
# 域名模式（DNS 自动发现端口 + IPv6 + 公钥）
KirinDesk.exe --cli connect my-server.example.com 22 mynickname

# IP 模式（直接指定 IPv6 + 端口）
KirinDesk.exe --cli connect 2001:db8::1 3389 mynickname
```

### 内网穿透（Tunnel）加密认证

relay 服务器（`tunnel serve`）的登录认证采用 **挑战-响应（SCRAM 式）** 加密验证
（M8-T026-P3，协议 v1.1.0）：

- **口令永不明文上线**：登录报文仅携带随机数与 HMAC-SHA256 证明（`auth_digest`），
  网络抓包无法获得口令原文；
- **双向认证**：服务器以自身回执证明口令知识，伪造服务器会被客户端拒绝并断开；
- **fail-closed**：`tunnel serve` 在 `[tunnel].token` 为空时**拒绝启动**；
  配置了口令的客户端拒绝连接未认证（无口令）的服务器；
- **口令质量**：建议使用 ≥32 字节高熵随机串（`openssl rand -base64 32`）；
  长度不足 16 字符会收到警告。

**升级注意事项**：服务端与客户端需使用**同版本**（同仓库发布）。
旧版本客户端（v1.0）连接已配置口令的新服务端会被明确拒绝并提示
`upgrade client`；新版本客户端连接旧版本服务端时会明确报错（等待挑战超时或
服务器未认证拒绝）。两端请同步升级。

**部署**：`relay-server --bind-port 7000 --rendezvous-port 7001 --token <高熵token>`
—— 控制端口、rendezvous（打洞）端口与监听地址（`--bind-addrs`）全部可自定义；
客户端以 `[tunnel] server_addr = "relay.example.com:<自定义端口>"` + 相同 token
连接（服务端亦可经 `KIRIN_RELAY_TOKEN` 环境变量提供）。完整参考：
`release/server/README.md`。

**Tunnel 独立页（M8-T039，2026-08-03）**：内网穿透已从 Settings 页迁出，升级为
顶部导航独立标签页（🚇 Tunnel，位于 Connect 与 Settings 之间）——Client/Server
分区配置、Server 多地址监听（`bind_addrs`，默认 `0.0.0.0,::`，IPv6 一律 v6-only）、
Token ✏️ 一键生成（32 字节高熵，点击立即落盘）与 📋 复制、代理列表、GUI 一键
启动/停止（运行状态经 `auto_start` 持久化，重启自动恢复）；无头环境走 CLI
`tunnel start/serve/status` 或独立服务端 `relay-server`（新增 `--bind-addrs`
多监听参数，Docker/systemd 部署主路径）。

## GUI 操作

| 标签页 | 功能 |
|--------|------|
| **Dashboard** | 设备信息总览（Device ID、IPv6/IPv4、端口、白名单）；允许受控/服务端开关；临时连接卡片 |
| **Domain** | DNS 服务商管理 — 20 家服务商、凭据、测试连接、域名列表、记录 CRUD（A/AAAA/CNAME/MX/TXT/SRV/NS） |
| **Devices** | 已发现/连接的设备列表（昵称、备注、手动排序） |
| **Connect** | 连接远程设备 — IPv6/IPv4+Port 或 Domain+Nickname+Challenge 两种表单 + 实时连接日志 |
| **Tunnel** | 内网穿透 — 通用 TCP 反向代理：Client/Server 配置、监听地址、Token ✏️📋、代理列表、一键启停（状态自动恢复） |
| **Settings** | Device ID、Nickname、Challenge Code、DNS 服务商与凭据、白名单、连接模式、传输、语言（System/中文/English）、无人值守、更新 |

## 安全架构

```
+---------------------------+       +---------------------------+
|  Client (控制端)          |       |  Server (被控端)           |
|                           |       |                           |
|  FFmpeg libavcodec 解码   |       |  FFmpeg libavcodec 编码   |
|  ├─ h264_qsv / h264       |       |  ├─ h264_nvenc            |
|  ├─ hevc_qsv / hevc       |       |  ├─ h264_amf              |
|  └─ swscale YUV→RGBA      |       |  ├─ h264_qsv              |
|                           |       |  ├─ h264_vaapi            |
|                           |       |  └─ libx264               |
|        ↕                  |       |        ↕                  |
|  KirinDesk P2P 加密隧道   |──────▶│  KirinDesk P2P 加密隧道   |
|  ├─ Ed25519 身份验证      |  P2P  │  ├─ Ed25519 身份验证      |
|  ├─ X25519 ECDH 密钥交换  |  IPv6 │  ├─ X25519 ECDH 密钥交换  |
|  └─ AEAD AES-256-GCM     |       │  └─ AEAD AES-256-GCM     |
+---------------------------+       +---------------------------+
            ↑                                ↑
            │      DNS（20 家服务商）         │
            │  (SRV + AAAA + TXT 记录)       │
            +────────────────────────────────+
```

> **直连路径**：设备 ⇄ 设备（IPv6/IPv4），中间无任何节点。**辅助路径（可选）**：
> 自建 `relay-server` 承担 rendezvous 打洞——仅交换候选、**不进数据面**，打洞成功
> 后仍为双端直连（UDP 打洞 + QUIC）；打洞失败时按设备 ID 中继兜底（端到端加密
> 不变，服务器只能转发密文）。服务器端口（控制 / rendezvous / 监听地址）全部
> 可自定义；客户端以 SCRAM 式 token 连接任意自定义端口。

## 项目结构

```
KirinDesk/
├── core/          # 核心：加密（Ed25519/X25519/AEAD/握手）、网络（TCP/IPv4/IPv6）、打洞与多路径
├── dns/           # DNS 模块：20 家服务商适配、SRV/AAAA/A/TXT 管理、服务发现与心跳
├── media/         # 媒体：屏幕/音频捕获、FFmpeg libavcodec 编解码、GPU 选择、QUIC/TCP 传输、自适应反馈
├── input/         # 远程输入：Windows SendInput / Linux uinput / macOS CGEvent
├── relay/         # 内网穿透：通用 TCP 反向代理客户端/服务端、打洞 rendezvous、设备 ID 注册表
├── relay-server/  # 独立穿透服务端二进制（Docker / systemd / 无头部署）
├── ui/            # 用户界面：egui（桌面 GUI，i18n 中英）+ CLI
├── updater/       # 自动更新（检查 / 下载 / 安装）
├── utils/         # 工具库：配置（加密）、日志、错误类型、审计
├── ffmpeg/        # FFmpeg 8.1.1 共享库（avcodec-62/avutil-60/swscale-9;git 忽略,clone 后还原）
├── config/        # 配置结构与默认值
└── release/       # 发布产物与安装包（NSIS / deb / dmg）
```

## 命令行命令

```
kirin_desk <command> [options]

  setup                Interactive configuration wizard
  config               Show current configuration
  register [id] [p]    Register device with DNS (current provider)
  discover <id>        Discover a remote device (current DNS provider)
  dns <subcommand>     DNS 域名维护（M9-DNS023）：list-providers | set-provider
                       <name> | test [provider] | domains |
                       records <domain> [type] | add|update <domain> <type>
                       <name> <data> [--ttl N] [--priority N --weight N
                       --port N] | delete <domain> <type> <name> |
                       register <device-id> <port> | unregister <device-id>
  connect <t> [p] [n]  Connect to device — domain (DNS discovery + TXT key
                       binding) or IPv6/IPv4
                       挑战码：交互式输入（TTY）或 --challenge-stdin（管道）
                       [--transport auto|quic|tcp] [--ip-family auto|ipv4|ipv6]
                       [--no-audio]
  send <path> <host> [p] [n]  Send a file to the remote (encrypted, resumable)
  recv <host> [p] [n]         Receive files pushed by the remote
  shell [port]         Remote shell server (domain/ID whitelist enforced)
  shell <host> [p] [n] Connect to a remote shell (PTY mode)
  serve [port]         Start listening（[--unattended] 自动放行）
  known-hosts          List / add / remove 受信客户端密钥（SSH 式）
  whitelist            List / add / remove 域名与设备 ID 白名单、CSV 导入导出
                       （whitelist add-id/remove-id）
  temp-mode [off]      开启 5 分钟临时窗口：临时挑战码 + 跳过白名单
  unattended <on|off|status>  无人值守模式（自动放行、自动开服务端）
  autostart <enable|disable|status>  系统用户级开机自启
  tunnel start         Run tunnel client (frpc): map local TCP services to the
                       public relay server
  tunnel serve         Run tunnel server (frps) on this machine
  tunnel status        Show tunnel configuration and proxy list
  status               Show system status
  self-test            End-to-end self test
  help                 Show this help
```

## 配置

```toml
[device]
id = ""              # 留空 = 自动（硬盘 UUID / machine-id / IOPlatformUUID）
nickname = "my-pc"
challenge_code = ""  # 服务端必填（fail-closed）

[dns]
provider = "godaddy" # 20 家服务商任选；凭据加密落盘（R-13）

# M8-T040: 域名模式加密 DNS 强制（服务端 + 客户端，默认 enforce）
[dns.security]
mode = "enforce"      # enforce（域名模式强制 DoH/DoT，fail-closed）| off（仅 IP 模式）
doh = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve", "https://dns.alidns.com/resolve"]
dot = ["1.1.1.1:853", "8.8.8.8:853", "2400:3200::1:853"]
resolve_timeout_ms = 5000
cache_ttl_secs = 50

# M8-T040: DDNS 域名自动更新维护（GUI Domain 页「DDNS 维护」卡读写）
[ddns]
enabled = false       # 总开关（默认关；关闭不删除已发布记录）
interval_secs = 300   # 更新周期（下限 60s；未设置回退 [network] heartbeat_interval）
ipv4_mode = "auto"    # auto = 公网出口 IP（多源 HTTPS）| manual = 固定地址（永不覆盖）
ipv4_manual = ""
ipv4_sources = ["ipify", "ip.sb", "icanhazip"]
ipv6_mode = "auto"    # auto = 本机全局单播 | manual = 固定地址（永不覆盖）
ipv6_manual = ""
publish_srv = true    # SRV（远控端口）/ TXT（签名指纹）/ A / AAAA 四开关
publish_txt = true
publish_a = true
publish_aaaa = true

[network]
port = 3389
allowed_domains = ["example.com"]
allowed_ids = []     # 设备 ID 白名单（精确匹配；`*` 后缀 = 前缀通配）

[media]
encoder = "auto"     # auto | nvenc | amf | qsv | vaapi | libx264
framerate = 30
bitrate = 5000       # kbps

[media.gpu]
prefer = "auto"      # auto | intel | nvidia | amd | luid:0x…（或 KIRIN_GPU_PREFER）
filter_virtual = true

[transport]
mode = "auto"        # auto | quic | tcp（会话中途优雅降级）
ip_family = "auto"   # auto | ipv4 | ipv6

[file_transfer]
download_dir = ""    # 默认 ~/Downloads/KirinDesk
max_file_size = 4294967296  # 单文件上限 4 GiB

[tunnel]
enabled = false      # FRP 式反向代理 — 可选能力，默认关闭
mode = "client"      # client | server
server_addr = ""     # 公网 relay 服务器（域名 / IP，支持 :port 后缀）
token = ""           # SCRAM 式口令认证；永不明文上线
bind_addrs = "0.0.0.0,::"    # server 监听地址（逗号分隔可多个）
port_range = "60000-61000"

[logging]
level = "info"
format = "text"
```

### 配置加密（R-13）

敏感字段——DNS 服务商 API Key/Secret、Tunnel token、挑战码等——**不以明文写入配置文件**，以
ChaCha20Poly1305 密文存储（格式 `{v: base64(nonce‖ciphertext)}`，AAD 绑定
字段上下文，防跨字段替换）。可在配置文件中 grep 验证无明文。

主密钥来源分层（自动选择，无需手动配置）：

| 平台 | 密钥来源 |
|------|---------|
| Windows | DPAPI（当前用户级保护，blob 存 `config_dir/kirin_config_key.dpapi`） |
| macOS | Keychain 通用密码条目（`kirindesk-config-key`） |
| 无密钥环平台 / 任意平台覆盖 | 环境变量 `KIRIN_CONFIG_KEY`（口令，PBKDF2-HMAC-SHA256 派生，优先级最高） |
| 全部不可用 | **fail-open**：明文存储 + 启动醒目警告（不阻断开发使用） |

迁移行为：旧明文配置首次加载时**自动加密重写**（`#[serde(default)]` 兼容旧字段；
幂等，二次加载不重写）；写回失败不破坏原文件（`write_private` 原子替换，内存态
配置继续可用）。密钥/令牌不写日志、不进 `config show` / `status` 输出（掩码 `****`）。

实现证据（R-13b 已实现，2026-08-04）：`utils/src/config.rs` `save_to`/`load_from`/
`encrypt_sensitive_fields`/`decrypt_sensitive_fields`/`field_context`（密文 `{v:...}` +
AAD 段上下文绑定）、`utils/src/secure.rs` `key_provider_for`/`encrypt_with_provider`/
`decrypt_field`/`KeySource::label`（DPAPI / Keychain / PBKDF2 分层）、`ui/src/cli.rs`
`config show`（Encryption 状态 + Tunnel Token 掩码）；单测 14 项（utils 145 全绿），
详见 `task_docs/修复任务/W1_R-13b_配置加密接线.md` §7。

## License

Apache 2.0（KirinDesk 核心）+ LGPL（FFmpeg 库，动态加载）

> KirinDesk 是个人开发者用爱发电的纯公益项目——无任何盈利内容、无广告、无遥测。永远如此。
