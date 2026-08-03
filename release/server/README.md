# KirinDesk 内网穿透服务端 — relay-server

frps 等价的独立服务端二进制（M8-T026），部署在**公网服务器**上，
供内网机器通过 `kirin_desk tunnel start`（或独立 client）回连建隧道。

- Windows：直接使用本目录 `relay-server.exe`（已构建）。
- Linux：**推荐 Docker 部署**（`docker/` 下 Dockerfile + compose，一键
  `docker compose up -d`）；原生编译/裸机部署见 `BUILD_LINUX.md`
  （含 systemd 示例 `relay-server.service`）。

## 快速开始（Windows）

```bat
relay-server.exe --bind-port 7000 --token <高熵token≥32字节> --port-range 60000-61000
```

显式 IPv4+IPv6 双监听（多地址，可选）：

```bat
relay-server.exe --bind-addrs 0.0.0.0,:: --bind-port 7000 --token <高熵token≥32字节> --port-range 60000-61000
```

启动后控制台会打印服务器 Ed25519 公钥（**客户端 ID 模式须预置
`[tunnel] server_pubkey`**）与监听地址。`Ctrl+C` 优雅退出。

打洞（P2P 穿透，M8-T026-P1）默认随服务端启用：另开一个监听端口
`--rendezvous-port`（默认 `7001`）承载打洞候选登记/互转/限速/审计
（**只做牵线，不进入数据面**，PUNCH-SEC-002）；不需要时可
`--no-rendezvous` 关闭：

```bat
relay-server.exe --bind-port 7000 --rendezvous-port 7001 --token <高熵token≥32字节>
```

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--bind-addrs <IP,IP,…>` | 空（默认双栈） | 监听地址列表（逗号分隔，可多个，仅本机 IP，IPv4/IPv6 均可；**v6 地址一律 v6-only**——`::` 只收 IPv6、`0.0.0.0` 只收 IPv4，两者并存互不冲突）；留空 = 默认双栈回退（`[::]` 优先 + `0.0.0.0` 回退，行为同旧版）；非法值拒绝启动 |
| `--bind-port <PORT>` | `7000` | 控制端口；`[::]` 优先（显式关闭 `IPV6_V6ONLY` 双栈）、`0.0.0.0` 回退 |
| `--rendezvous-port <PORT>` | `7001` | 打洞 rendezvous 端口（P1 打洞候选登记/互转/限速/审计，PUNCH-006）；**须与 `--bind-port` 不同**，非法值（非数字/0）或冲突拒绝启动 |
| `--no-rendezvous` | 启用 | 关闭打洞 rendezvous（不监听 `--rendezvous-port`）；与 `--rendezvous-port` 同时给出为冲突，拒绝启动 |
| `--token <TOKEN>` | 空（告警） | 客户端认证 token；也可经环境变量 `KIRIN_RELAY_TOKEN` 提供（推荐，避免进程列表泄露） |
| `--port-range <S-E>` | 无 | 自动分配端口范围（客户端 `remote_port=0` 请求用），如 `60000-61000`（须与客户端 `[tunnel] port_range` 默认值一致并同步放行防火墙） |
| `--server-key <PATH>` | `~/.kirin_desk/relay_server_key.pem` | Ed25519 服务器密钥；不存在则自动生成并持久化（ID-SEC-001） |
| `--max-proxies <N>` | `32` | 每会话代理数量上限 |
| `--max-work-conns <N>` | `100` | 每代理并发 work 连接上限 |
| `--help` / `--version` | | 帮助 / 版本 |

日志级别由环境变量 `RUST_LOG` 控制（默认 `info`）；审计事件（登录、代理注册、
设备上线/离线、打洞、设备级中继等，TNL-SEC-003）实时输出到 stdout。

## 客户端连接

客户端（KirinDesk 主程序）配置 `~/.kirin_desk/default.toml`：

```toml
[tunnel]
enabled = true
mode = "client"
server_addr = "relay.example.com:7000"
token = "<与 --token 相同>"
server_pubkey = "<服务端启动时打印的 Server pubkey>"   # ID 模式验签用

[[tunnel.proxies]]
name = "rdp"
local_addr = "127.0.0.1"
local_port = 3389
remote_port = 0            # 0 = 从服务端 --port-range 自动分配
```

运行：`kirin_desk tunnel start`。

## 安全建议（发布口径）

- token 必须高熵随机串（≥32 字节）；空 token 服务端启动时会告警（任何人可登录）。
- 公网防火墙建议仅放行**控制端口（`--bind-port`，默认 7000）**、**打洞
  rendezvous 端口（`--rendezvous-port`，默认 7001，若未 `--no-rendezvous`）**
  与端口范围（`--port-range`），并用 systemd/服务方式守护进程；打洞数据面为
  双端直连（UDP 打洞 + QUIC），不经过服务器，**无需**为打洞探测额外放行
  服务器端口（PUNCH-PROTO-004 探测在打洞 socket 上直发）。`--no-rendezvous`
  部署可仅放行控制端口与端口范围。
- 数据面 V1 为明文管道（设计依据：应用层已加密——SSH/RDP/TLS 等自带加密）；
  穿透明文协议（HTTP 等）时流量裸露，敏感场景请经 KirinDesk SecureChannel。
- 支持 IPv4/IPv6 双栈客户端（Windows 上显式 `IPV6_V6ONLY=false`，对齐 Linux
  默认行为；M8-T025）。
