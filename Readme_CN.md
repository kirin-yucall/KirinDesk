# 🦄 KirinDesk — 颠覆 SSH 与传统远程桌面的新一代 P2P 远程控制

**完全去中心化 · 纯 P2P 直连 · 零中继服务器 · 零 TLS 证书 · 端到端加密**

> **English:** [Readme.md](Readme.md) ｜ **中文:** 本文件

**告别 SSH · 告别 RDP · 告别中心化中转 — 未来的远程控制，设备与设备直接对话。**

---

## 🚀 为什么选择 KirinDesk？

KirinDesk 的目标只有一个：**让 SSH 和所有传统远程桌面产品退休。**

传统远程控制的世界充满痛点：

- **SSH** — 22 端口全球可扫，密码爆破攻击无休无止，只能靠 fail2ban 这类补丁式防守；
- **RDP / VNC** — 认证依赖中心化服务，端口 24 小时暴露，流量缺乏端到端加密；
- **TeamViewer / AnyDesk 等商业产品** — 流量全部经过厂商中心化服务器中转，服务中断、数据泄露、隐私疑云始终挥之不去。

**KirinDesk 给出终极答案：设备之间直接握手。**

```
传统方案                                  KirinDesk
─────────                                  ─────────
设备 ──▶ 中心服务器 ──▶ 设备                设备 ──▶ 设备
        (中转 / 可断 / 可窃听)              (直连 / 无中间人)
```

- **完全 P2P 去中心化** — 无需中继服务器、无需 STUN/TURN、无需公网端口映射。IPv6 让每一台设备全球可达，设备与设备之间直接建立点对点加密隧道，数据不经过任何第三方。
- **DNS 即去中心化公告板** — 通过 GoDaddy DNS 的 SRV（端口）+ AAAA（IPv6 地址）+ TXT（设备公钥）记录动态注册与发现设备，天然去中心化，没有可以停摆、可以审查的中心服务。
- **零信任端到端加密** — 摒弃传统 TLS 证书体系，Ed25519 身份密钥 + X25519 ECDH + AEAD（AES-256-GCM），每次会话独立派生密钥，具备前向安全性——长期密钥泄露也不影响历史会话。
- **取代 SSH** — Server 模式将远程 Shell 提升到新高度：无端口暴露、域名白名单、挑战码 + 签名双重认证。
- **域名白名单（而非 IP 白名单）** — 白名单用域名表达而非 IP 地址：域名稳定、人类可读、可随地址变化自动保持有效，且与 DNS 身份注册表天然一致，既方便又安全。

### 与传统方案对比

| 维度 | 传统 SSH | RDP / VNC | 商业远程桌面 | **KirinDesk** |
|------|---------|-----------|-------------|---------------|
| 连接方式 | 端口直连 | 端口直连 | 中心化服务器中转 | **纯 P2P 直连** |
| 中继服务器 | 无 | 无 | 必需 | **完全不需要** |
| 端口暴露 | 22 全球可扫 | 可扫 | 无 | **无固定端口暴露** |
| 认证方式 | 密码/密钥 | 密码/证书 | 厂商账号 | 挑战码 + Ed25519 签名 |
| 加密强度 | 传输级 | 弱/无 | 取决于厂商 | **端到端 AEAD，前向安全** |
| 访问控制 | — | — | 厂商账号 | **域名白名单（严格模式）** |
| 隐私 | — | — | 流量经第三方 | **零中间人，数据不出你的网络** |
| 去中心化 | ✗ | ✗ | ✗ | **✓ 完全去中心化** |

---

## ✨ 核心特性

- **IPv6 直连** — 利用 IPv6 全球可达性，无需 STUN/TURN/中继
- **零信任加密** — Ed25519 身份密钥 + X25519 ECDH + AEAD（AES-256-GCM / ChaCha20-Poly1305），每次会话独立派生密钥
- **DNS 去中心化发现** — 通过 GoDaddy DNS 自动注册/发现设备（SRV + AAAA + TXT 三路并行查询），心跳保活
- **域名白名单（严格模式）** — 仅允许白名单域名发起连接
- **双模式连接** — 域名模式（DNS 发现，推荐） 或 IP 模式（直连 IPv6）
- **远程桌面** — FFmpeg libavcodec H.264/H.265 编码/解码，硬件加速（NVENC/AMF/QSV/VAAPI/libx264）+ QSV 硬解与软解回退
- **自适应媒体管道** — 70ms 窗口化 QUIC 传输（数据报 + 可靠流、丢包检测）+ 实时编码参数反馈闭环
- **远程 Shell** — 无头 Ubuntu Server 远程终端（PTY，替代 SSH）
- **跨平台** — Windows（egui GUI + CLI）、Linux（pipewire 捕获、VAAPI、uinput）、macOS（zed-scap、VideoToolbox、Keychain 身份存储）
- **自动日志** — 每日轮转日志文件 `~/.kirin_desk/logs/kirindesk-YYYY-MM-DD.log`，自动清理旧日志
- **开箱即用的发布体系** — NSIS 安装包（Windows）、.deb + systemd 服务（Ubuntu）、通用 .app + .dmg（macOS）、应用内自动更新

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
cargo build --release -p kirin-desk-ui

# 配置与服务端
./target/release/kirin-desk-ui --cli setup
./target/release/kirin-desk-ui --cli register my-server 22
./target/release/kirin-desk-ui --cli serve 22
```

### 客户端连接

```bash
# 域名模式（DNS 自动发现端口 + IPv6 + 公钥）
KirinDesk.exe --cli connect my-server.example.com 22 mynickname

# IP 模式（直接指定 IPv6 + 端口）
KirinDesk.exe --cli connect 2001:db8::1 3389 mynickname
```

## GUI 操作

| 标签页 | 功能 |
|--------|------|
| **Dashboard** | 设备信息总览（Device ID、IPv6、端口、域名白名单） |
| **Connect** | 连接远程设备 — 支持 IPv6+Port 或 Domain+Nickename+Challenge 两种表单 |
| **Settings** | 配置 Device ID、Nickname、Challenge Code、GoDaddy API、域名白名单、连接模式 |
| **Devices** | 已发现/连接的设备列表 |

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
            │        GoDaddy DNS             │
            │  (SRV + AAAA + TXT 记录)       │
            +────────────────────────────────+
```

## 项目结构

```
KirinDesk/
├── core/          # 核心：加密（Ed25519/X25519/AEAD/握手）、网络（TCP/IPv6）、连接管理
├── dns/           # DNS 模块：GoDaddy API 客户端、SRV/AAAA/TXT 管理、服务发现与心跳
├── media/         # 媒体：屏幕/音频捕获、FFmpeg libavcodec 编解码、QUIC 传输、自适应反馈
├── input/         # 远程输入：Windows SendInput / Linux uinput / macOS CGEvent
├── ui/            # 用户界面：egui（桌面 GUI） + CLI
├── updater/       # 自动更新（检查 / 下载 / 安装）
├── utils/         # 工具库：配置、日志、错误类型
├── ffmpeg/        # FFmpeg 8.1.2 共享库（avcodec-62/avutil-60/swscale-9）
├── config/        # 配置结构与默认值
└── release/       # 发布产物与安装包（NSIS / deb / dmg）
```

## 命令行命令

```
kirin_desk <command> [options]

  setup                Interactive configuration wizard
  config               Show current configuration
  register [id] [p]    Register device with GoDaddy DNS
  discover <id>        Discover a remote device
  connect <t> [p] [c]  Connect to device (domain or IPv6)
  shell [port]         Remote shell server (domain whitelist)
  serve [port]         Start listening for connections
  status               Show system status
  self-test            End-to-end self test
  help                 Show this help
```

## 配置

```toml
[device]
id = "my-pc"
nickname = "my-pc"
challenge_code = "my-secret"

[godaddy]
api_key = "..."
api_secret = "..."
domain = "example.com"

[network]
port = 3389
allowed_domains = ["example.com"]
ip_mode_allowed = false

[codec]
# 编码设置
h264_bitrate = 5000000    # 目标码率 (bps)
framerate = 30            # 目标帧率
# 解码设置
enable_hw_decode = true   # 启用硬件解码 (DXVA/VAAPI)

[logging]
level = "info"
format = "text"
```

## License

Apache 2.0（KirinDesk 核心）+ LGPL（FFmpeg 库，动态加载）
