# KirinDesk 内网穿透服务端 — relay-server

frps 等价的独立服务端二进制（M8-T026），部署在**公网服务器**上，
供内网机器通过 `kirin_desk tunnel start`（或独立 client）回连建隧道。

- Windows：直接使用本目录 `relay-server.exe`（已构建）。
- Linux：**推荐 Docker 一键部署（免编译）**——向用户分发**离线镜像包
  （`release/dist/kirin-relay-server-v0.2.0-x86_64.tar.gz`）+ `deploy.sh`
  一键脚本 + compose/.env 模板**，`docker load` + `bash deploy.sh` 即完成
  部署，无需任何编译，见下方「Docker 一键部署（免编译）」。原生编译/裸机
  部署见 `BUILD_LINUX.md`（含 systemd 示例 `relay-server.service`）。


**交付物**（由维护者用 `release/server/docker/build-image.sh` 产出，
存于 `release/dist/`）：离线镜像包 `kirin-relay-server-v0.2.0-x86_64.tar.gz`
+ `sha256` 侧车 + `deploy.sh` + `docker-compose.yml` + `.env.example` +
本文件（README.md）。架构仅 **x86_64（linux/amd64）**。

**三步部署**（目标服务器装有 Docker Engine/Desktop，可离线）：

```bash
tar -xzf kirin-relay-server-v0.2.0-x86_64.tar.gz   # 解包（含脚本与 compose）
cd kirin-relay-server-v0.2.0-docker
bash deploy.sh -i kirin-relay-server-v0.2.0-x86_64.tar.gz
```

`yucall/kirin-relay-server:0.2.0`（+ `latest`）——在线服务器可直接
`docker pull yucall/kirin-relay-server:0.2.0` 并把 compose 的 `image:` 改为该
镜像后 `docker compose up -d`；**离线场景仍走上方一键包**（详见
`docker/README.md`「从 Docker Hub 拉取（可选）」）。

`deploy.sh` 会自动：① 导入离线镜像（本地已有则跳过）→ ② 生成 `.env`
（无 token 时用 `openssl rand -hex 32` 自动生成高熵 token 写入；`.env`
③ `docker compose up -d` → ④ 等待就绪并从日志提取打印 **Server pubkey** →
⑤ 打印防火墙提示与客户端配置要点。重复运行**幂等**：不重建容器、不覆盖
已有 `.env` token。

手动三步（等价）：

```bash
docker load -i kirin-relay-server-v0.2.0-x86_64.tar.gz
cp .env.example .env   # 填入高熵 token（或运行 deploy.sh 自动生成）
docker compose up -d
docker compose logs -f      # 查看 Server pubkey（客户端 ID 模式预置用）
docker compose down         # 停止（密钥卷保留，pubkey 不变）
```

**维护者自建镜像**（改源码后重打包）：在仓库根执行
`bash release/server/docker/build-image.sh`（构建 + `docker save|gzip`
导出 + sha256 侧车），或手动 `docker build -f release/server/docker/Dockerfile
-t kirin-relay-server:0.2.0 .` 后用 compose 的 `--build`。公共仓库分发走
已在线上，镜像带 OCI labels）；维护者推送命令：
`docker tag kirin-relay-server:0.2.0 yucall/kirin-relay-server:0.2.0 && docker push yucall/kirin-relay-server:0.2.0`（`:latest` 同法）。

直接绑定主机，防火墙**主机直开** `7000/tcp`（控制）、`7001/tcp`（打洞
（代理端口范围）；无 docker-proxy 开销（bridge 全量 1001 端口发布在小规格
实例实测不可行），`compose down`/`restart` 秒级。打洞数据面为双端直连
（UDP 打洞 + QUIC），不经过服务器，无需为打洞探测额外放行服务器端口。
host 与 bridge 变体切换、小规格实例警示见 `docker/README.md`「网络模式」。


`deploy.sh` 部署成功末尾会在**部署目录**自动生成 `kirin-node.json`——客户端
可导入的节点配置文件（分享格式 **v1，不带签名**；导入时公钥指纹过目 TOFU

```json
{
  "v": 1,
  "type": "kirin-node",
  "name": "我的家庭节点",
  "server_addr": "relay.example.com:7000",
  "token": "<relay token>",
  "server_pubkey": "<Ed25519 公钥，base64（STANDARD，32 字节 44 字符）>",
  "note": "自建节点，用爱发电",
  "created": "2026-08-30T12:00:00Z"
}
```

- **新增 deploy.sh 选项**：`--name <名称>`（节点名称，默认 `$(hostname)`）、
  `--addr <host:port>`（客户端可达地址）、`--note <备注>`（可选备注）。
- **server_addr 必须是客户端可达的 地址:端口**：默认 host 网络下端口为
  `7000`（compose 默认 `--bind-port 7000`）。**自定义 `--bind-port`（见
  `docker/docker-compose.yml` 尾部自定义端口示例）时，`--addr` 的端口必须
  与之对应**——例如 `--bind-port 9000` 部署则 `--addr relay.example.com:9000`。
  未指定 `--addr` 时文件中 `server_addr` 留空、脚本打印醒目 TODO——
  **分发前请手填**（脚本不瞎猜公网地址；离线一键包不做公网探测）。
- **分发提示**：把此文件发给你的用户，或在客户端导入。**分享此文件即公开
  token**——任何人拿到即可使用本节点，请像密码一样保管；文件权限 600
  （仅属主可读）。更换 token 的流程：改 `.env` 的 `KIRIN_RELAY_TOKEN` →
  `docker compose up -d`（env 变化触发容器重建）→ 重跑 `deploy.sh` 刷新
  本文件。
- **幂等**：重复运行 `deploy.sh` 覆盖更新 `kirin-node.json`（token/pubkey
  与 `.env` 及容器现状同步刷新）。
- **server_pubkey 编码口径**：Ed25519 公钥 32 字节的 base64（STANDARD
  字母表）——与服务端启动打印的 `Server pubkey` 行同一串、与客户端
  `[tunnel] server_pubkey` 口径一致，导入无需任何转换。

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
| `--token <TOKEN>` | 空（告警） | 客户端认证 token；也可经环境变量 `KIRIN_RELAY_TOKEN` 提供。**注意暴露面**：CLI 参数可入 shell history 与 `ps`/进程命令行；推荐 `--token-file` |
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
  shell history 与 `ps`/进程命令行暴露面；文件权限 0600、目录仅服务账户
  可读，更新 token = 改文件重启）；`KIRIN_RELAY_TOKEN` 次之（注意环境变量
  会被子进程继承）；`--token` 最后（history/ps 可见）。三者同给时
  `--token-file` 胜出并打印 WARN；空 token 一律 fail-closed 拒启
  （`--allow-empty-token` 显式放行除外）。
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


`token_hash` = hex(sha256(token))〕/ 设备缓存 token / 设备目录条目 /
`chmod 0600`、本卡新建父目录 `0700`（best-effort——收紧失败仅 WARN
不拒启）。

- **Windows 部署红线**：Windows 无程序化 ACL 收紧（零外部依赖口径，不启
  `icacls` 子进程）——服务启动会打印 WARN 提醒，**请人工确认 relay.db
  所在卷 ACL 仅服务账户可读**（移除 `Users`/`Everyone` 读权），或把数据
  目录放在仅服务账户可访问的私有目录（如 `%ProgramData%` 下自建目录并
  显式收紧 ACL）。
- **WAL 伴生文件**：启用 WAL 后 `relay.db-wal` / `relay.db-shm` 与库同目录
  随库同卷生成，权限随目录继承——收紧目录 ACL 即一并覆盖，无需单独处理。
- **容器部署（卷挂载权限 / 以非 root 运行）**：
  - 挂载卷属主与运行用户一致，目录权限建议 `0700`、库文件 `0600`；
    不要以 root 运行容器（镜像内以普通用户运行，或 compose 里指定
    `user: "1000:1000"` 等与卷属主匹配的非 root UID）。
  - 宿主机 bind mount 前先 `chown`/`chmod` 好目录再启动；跨机备份介质
    同样按 `0600` 保管 relay.db（含 token 等敏感面）。
