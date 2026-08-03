# KirinDesk — 发布包使用说明

P2P 远程桌面 · IPv6/IPv4 直连优先 · 服务器辅助打洞 · 零 TLS 证书 · 端到端加密

> 💜 **个人开发者用爱发电的纯公益项目** —— 无订阅、无广告、无遥测。完整介绍与
> 架构见仓库根目录 [`Readme.md`](../Readme.md)（中文：[`Readme_CN.md`](../Readme_CN.md)）。

本目录是**已构建的发布产物**。下面只讲"拿到发布包后怎么装、怎么用"。

## 一、Windows 桌面端

本目录已附 `KirinDesk.exe`（egui 原生 GUI，含 CLI 回退）。

### 安装

- **便携版**：直接双击 `KirinDesk.exe` 运行（需连同 `ffmpeg/bin/` 下共享库一起解压，
  否则编解码加载会失败）。
- **正式安装**：以管理员身份运行 `install.bat`（走 `install.nsi` 的 NSIS 流程，
  安装到 `%LOCALAPPDATA%\KirinDesk`），之后从开始菜单启动。

> 发布二进制不再入库跟踪，正式发布走 CI release job 的 artifacts + `checksums.txt`
> 校验（S-28 / F-33）。

### 主要功能

- **Dashboard** — 设备信息总览（Device ID、IPv6/IPv4、端口、白名单），允许受控/服务端
  开关，临时连接卡片
- **Domain** — DNS 服务商管理（20 家），凭据、测试连接、域名列表、记录 CRUD
  （A/AAAA/CNAME/MX/TXT/SRV/NS），DDNS 自动维护
- **Devices** — 已发现/连接设备（昵称、备注、手动排序）
- **Connect** — 连接远程设备：IPv6/IPv4+Port 或 Domain+Nickname+Challenge，实时连接日志
- **Tunnel** — 内网穿透（通用 TCP 反向代理）：Client/Server 配置、监听地址、Token、
  代理列表、GUI 一键启停（运行状态自动恢复）
- **Settings** — Device ID、Nickname、Challenge Code、DNS 服务商与凭据、白名单、连接模式、
  传输、语言（System/中文/English）、无人值守、更新

### 连接模式

**Domain 模式（推荐，严格）**：通过 DNS 自动发现端口 + IPv6 + 公钥，白名单强制。
```
Target:   my-pc.example.com
Nickname: my-device
Challenge: [交互式输入或 --challenge-stdin]
[Connect (DNS)]
```

**IP 模式**：直接指定 IPv6/IPv4 + 端口（首次连接需确认指纹）。
```
IPv6:     2001:db8::1
Port:     3389
Nickname: my-device
[Connect (IP)]
```

### CLI 用法

```bash
KirinDesk.exe --cli setup            # 交互式配置向导
KirinDesk.exe --cli register my-pc   # 注册设备到 DNS
KirinDesk.exe --cli serve 3389       # 启动服务端
KirinDesk.exe --cli connect my-pc.example.com 22 mynick   # 连接
KirinDesk.exe --cli tunnel start     # 内网穿透客户端
KirinDesk.exe --cli status           # 系统状态
KirinDesk.exe --cli self-test        # 端到端自检
KirinDesk.exe --cli help             # 完整命令列表
```

完整 CLI（含 `dns`/`whitelist`/`temp-mode`/`unattended`/`known-hosts` 等子命令）见
根目录 Readme 的「CLI Commands」章节。

## 二、Ubuntu Server（无头 / 远程 Shell）

设备类型为 "server" 时自动走终端模式（PTY，替代 SSH）。从源码构建见
[`BUILD_UBUNTU.md`](BUILD_UBUNTU.md)。

```bash
# 服务端（无头 Ubuntu）
kirin_desk --cli shell 22
kirin_desk --cli serve 3389

# 客户端（任意平台）
kirin_desk --cli connect server.example.com 22 mynickname
```

`.deb` 包（含 systemd 服务）构建脚本在 `release/debian/`。

## 三、内网穿透服务端（relay-server）

见 [`server/`](server/) —— Windows 用本目录 `relay-server.exe`；Linux 推荐 Docker 部署
（`server/docker/`）或原生编译（`server/BUILD_LINUX.md`，附 systemd 示例）。

```bash
relay-server --bind-port 7000 --token <高熵token≥32字节> --port-range 60000-61000
```

完整参数与安全建议见 [`server/README.md`](server/README.md)。

## 四、安全要点

- **域名 + 设备 ID 白名单（严格模式）**：任一命中即放行；临时模式签发 10 位一次性
  挑战码并跳过白名单（5 分钟窗口），应急直达
- **挑战码 + Ed25519 签名** 双重认证
- **AEAD 端到端加密**（AES-256-GCM / ChaCha20-Poly1305），每次会话独立派生密钥，前向安全
- **握手 pin 强制比对**（已删除"空串跳过"兼容路径）
- **配置加密**（R-13）：敏感字段（DNS 凭据、Tunnel token、挑战码）加密落盘，密钥源分层
  （Windows DPAPI / macOS Keychain / `KIRIN_CONFIG_KEY`；无密钥源时 fail-open 明文 + 警告）
- **审计日志**：30+ 事件，连接速率限制，SSH 式 known-hosts 指纹确认

## 五、配置与日志

- 配置文件：`%USERPROFILE%\.kirin_desk\default.toml`（结构见根目录 Readme「Configuration」）
- 日志：每日轮转 `~/.kirin_desk/logs/kirindesk-YYYY-MM-DD.log`，自动清理

## 发布流程

见 [`PUBLISH.md`](PUBLISH.md) —— 一键发布（`publish.sh` + CI 三平台打包）/
手动发布流程，以及「Settings → 检查更新」链路的资产命名与 `.sha256` 侧车规范。

## License

Apache 2.0（KirinDesk 核心）+ LGPL（FFmpeg 库，动态加载）
