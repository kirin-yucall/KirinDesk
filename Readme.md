# KirinDesk — P2P Remote Desktop

**IPv6 + Zero Trust 加密 + 去中心化 DNS 发现**

KirinDesk 是一个基于 IPv6 直连的 P2P 远程桌面/远程 Shell 软件。无需中继服务器，不依赖传统 TLS 证书 — 通过 **GoDaddy DNS API** 管理 SRV（端口）、AAAA（IPv6 地址）和 TXT（设备公钥）记录，实现去中心化设备发现与端到端加密。

## 核心特性

- **IPv6 直连** — 利用 IPv6 全球可达性，无需 STUN/TURN/中继
- **零信任加密** — Ed25519 身份密钥 + X25519 ECDH + AEAD（AES-256-GCM），每次会话独立派生密钥
- **DNS 去中心化发现** — 通过 GoDaddy DNS 自动注册/发现设备（SRV + AAAA + TXT 三路并行查询）
- **双模式连接** — 域名模式（DNS 发现，推荐） 或 IP 模式（直连 IPv6）
- **远程桌面** — 跨平台屏幕捕获 + 硬件编码（NVENC/VAAPI）+ 远程输入注入
- **远程 Shell** — 无头 Ubuntu Server 远程终端（替代 SSH）
- **域名白名单** — 严格模式仅允许白名单域名发起连接
- **跨平台** — Windows GUI（egui）/ 命令行 / Linux Server

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
  libxkbcommon-dev libwayland-dev libpipewire-0.3-dev \
  libpulse-dev libudev-dev ffmpeg libavcodec-dev

git clone <repo>
cd KirinDesk
cargo build --release -p kirin-desk-ui

# 配置与服务端
./target/release/kirin-desk-ui --cli setup
./target/release/kirin-desk-ui --cli register my-server 22
./target/release/kirin-desk-ui --cli serve 22    # 远程 Shell 模式
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

在 Settings 中切换 **IP Mode** 和 **Domain Mode** 后，Connect 页会自动切换对应表单。

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
  help                 Show this help
```

## 安全架构

```
+---------------------------+       +---------------------------+
|  Client (控制端)          |       |  Server (被控端)           |
|                           |       |                           |
|  1. 查询 DNS TXT 获取公钥 |       |  1. Ed25519 身份密钥对    |
|  2. 生成 X25519 临时密钥   |──────▶|  2. 验签 + 挑战码验证      |
|  3. ECDH 派生会话密钥     |  P2P  |  3. ECDH 派生会话密钥     |
|  4. AEAD 加密音视频/控制  | IPv6  |  4. AEAD 解密并响应       |
+---------------------------+       +---------------------------+
            ↑                                ↑
            |        GoDaddy DNS             |
            |  (SRV + AAAA + TXT 记录)       |
            +────────────────────────────────+
```

- **Ed25519** — 长期身份密钥，公钥存 DNS TXT 记录
- **X25519** — 临时会话密钥交换（ECDH）
- **AEAD** — AES-256-GCM / ChaCha20，每次会话独立派生
- **前向安全** — 长期密钥泄露不影响历史会话

## 项目结构

```
KirinDesk/
├── core/          # 核心：加密（Ed25519/X25519/AEAD/握手）、网络（TCP/IPv6）
├── dns/           # DNS 模块：GoDaddy API 客户端、SRV/AAAA/TXT 管理、服务发现
├── media/         # 媒体处理：屏幕捕获、FFmpeg 硬件编码、音频、流传输
├── input/         # 远程输入：Windows SendInput / Linux uinput
├── ui/            # 用户界面：egui（桌面 GUI） + CLI
├── updater/       # 自动更新
├── utils/         # 工具库：配置、日志、错误类型
└── tests/         # 集成测试
```

## Ubuntu Server 模式（远程 Shell）

KirinDesk 可作为 SSH 的安全替代方案运行在无头服务器上。

| 特性 | 传统 SSH | KirinDesk Server |
|------|---------|------------------|
| 端口暴露 | 22/tcp，全球可扫 | 自定义端口，仅白名单域名可连 |
| 认证 | 密码/密钥 | 昵称 + 挑战码 + Ed25519 签名 |
| 域名限制 | 无 | 域名白名单（严格模式） |
| 加密 | SSH 传输加密 | AES-256-GCM AEAD + X25519 ECDH |
| 前向安全 | 依赖 KEX 算法 | ✓ 会话级 |
| IPv6 | 需额外配置 | ✓ 原生 |

```bash
# 服务端
./kirin-desk-ui --cli serve 22

# 客户端
KirinDesk.exe --cli connect my-server.example.com 22 mynickname
```

## 从源码构建

```bash
git clone <repo>
cd KirinDesk

# 所有 crate
cargo build --release

# 仅 GUI/CLI 二进制
cargo build --release -p kirin-desk-ui

# 运行测试
cargo test --target-dir /tmp/kirin-target
```

### Windows 构建要求

- Build Tools for Visual Studio（MSVC 工具链）
- FFmpeg Shared Build（设置 `FFMPEG_DIR` 环境变量）
- Rust 工具链：`rustup default stable`

## 配置

配置文件位于 `~/.config/kirin_desk/default.toml`（Linux）或 `%APPDATA%/kirin_desk/default.toml`（Windows）。

主要配置项：

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
```

## License

MIT
