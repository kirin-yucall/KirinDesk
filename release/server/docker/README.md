# KirinDesk relay-server — Docker 一键部署包

默认 **host 网络**，适配小规格公网实例）：
无需任何编译，`docker load` + `docker compose up -d`（或一条 `deploy.sh`）
即完成部署。架构：**x86_64（linux/amd64）**。

## 包内容

| 文件 | 用途 |
|------|------|
| `kirin-relay-server-v0.2.0-x86_64.tar.gz` | 离线镜像包（`docker load` 导入） |
| `kirin-relay-server-v0.2.0-x86_64.tar.gz.sha256` | 镜像包校验（`sha256sum -c`） |
| `kirin-relay-server-v0.2.0-docker.zip.sha256` | zip 一键包校验（`sha256sum -c`） |
| `deploy.sh` | 一键部署脚本（load + 生成 token + up + 打印 pubkey） |
| `docker-compose.yml` | 服务编排（默认引用已 load 的镜像 `kirin-relay-server:0.2.0`；默认 **host 网络**，见「网络模式」） |
| `.env.example` | 环境变量模板（token 必填，fail-closed） |
| `README.md` | 本文件 |

## 三步部署

目标服务器需装有 Docker Engine/Desktop（含 compose 插件，可离线）。

```bash
# 1. 解包
tar -xzf kirin-relay-server-v0.2.0-docker.tar.gz    # 或解压 zip
cd kirin-relay-server-v0.2.0-docker

# 2. 一键部署（推荐）
bash deploy.sh -i kirin-relay-server-v0.2.0-x86_64.tar.gz
# 可选 -t <token> 指定 token；不提供且 .env 不存在时自动生成高熵 token
```

`deploy.sh` 自动完成：导入离线镜像 → 生成/复用 `.env` token →
`docker compose up -d` → 等待就绪 → 打印 **Server pubkey** 与防火墙提示。

手动等价步骤：

```bash
docker load -i kirin-relay-server-v0.2.0-x86_64.tar.gz
sha256sum -c kirin-relay-server-v0.2.0-x86_64.tar.gz.sha256   # 可选校验
cp .env.example .env      # 填入高熵 token（≥32 字节）：
                          #   openssl rand -hex 32
docker compose up -d
docker compose logs -f    # 查看 Server pubkey（客户端 ID 模式预置用）
```


2026-08-08，linux/amd64，仓库
`https://hub.docker.com/r/yucall/kirin-relay-server`）。**在线服务器**可跳过
离线包直接拉取：

```bash
docker pull yucall/kirin-relay-server:0.2.0
```

随后将 `docker-compose.yml` 的 `image:` 改为
`yucall/kirin-relay-server:0.2.0`，直接 `docker compose up -d`（token 仍走
`.env` fail-closed，密钥卷持久化 / 优雅退出 / host 网络行为不变）。
**离线场景仍走一键包**（`docker load` + `deploy.sh`），公共仓库仅作在线可选项。


relay 类纯 TCP 服务（frps 等价）在 **Linux 服务器上的推荐/标准做法**，优点：

- **无 docker-proxy 开销**：bridge 模式每发布一个端口就起一个 docker-proxy
  进程（全量发布 `60000-61000` 共 1001 端口 ≈ 2008 个进程）；host 模式零
  proxy，内存占用低。
  优雅退出，不再受大量 docker-proxy 拆除/重建拖慢。
- **端口直接绑定主机**：`7000/7001/60000-61000` 直接在主机上监听，
  防火墙主机直开即可，无需端口映射。

> ⚠️ **小规格实例警示（实证）**：若需切换回 **bridge 可移植变体**（Docker
> Desktop / macOS / 需要端口隔离的场景），删除 compose 中 `network_mode:
> host` 一行并启用注释的 `ports:` 块即可。但 bridge **全量发布
> 60000-61000（1001 端口）需 ≥2G 内存**（每端口一个 docker-proxy），且
> restart/down 慢（1001 端口 proxy 拆除/重建以分钟计）。公网 Debian 云主机
> （阿里云 ECS **2vCPU/1.6G**，Docker 29.7.2 + Compose v5.4.0）实测：
> bridge 全量 1001 端口发布触发 **docker-proxy 进程风暴**（load 峰值 28+、
> sshd 无法派生会话、compose up 20+ 分钟不返回、主机失联约 1 小时），
> 2C1.6G 实测不可行。**小规格公网实例务必使用 host 网络默认配置。**

## 校验

解包后按需校验（可选，防传输损坏 / 篡改）：

```bash
# 镜像包校验
sha256sum -c kirin-relay-server-v0.2.0-x86_64.tar.gz.sha256
# zip 一键包校验
sha256sum -c kirin-relay-server-v0.2.0-docker.zip.sha256
```

zip 一键包侧车 `kirin-relay-server-v0.2.0-docker.zip.sha256` 与
`kirin-relay-server-v0.2.0-docker.zip` 置于同级目录时执行上述命令，
输出 `OK` 即校验通过。


容器已启用 `init: true`，且 relay-server 内建 SIGTERM/SIGINT 优雅退出
`docker stop` 会先向进程发送 SIGTERM，relay-server 收到后快速关闭全部
监听与连接，正常退出（exit 0），不再出现旧版 10 秒超时强杀（dockerd
`using the force`、exit 137）。

docker-proxy 进程需拆除/重建（bridge 全量 1001 端口发布时仅 proxy 拆除

```bash
docker compose restart    # 重启：秒级完成，密钥卷保留、pubkey 不变
docker compose down       # 停止并移除容器（不带 -v，密钥卷保留、pubkey 不变）
docker compose down -v    # 停止并删除容器 + 密钥卷（慎用，删除后 pubkey 变化）
```

## 客户端连接

客户端（KirinDesk 主程序）配置 `~/.kirin_desk/default.toml`：

```toml
[tunnel]
enabled = true
mode = "client"
server_addr = "<本服务器公网IP或域名>:7000"
token = "<与 .env 中 KIRIN_RELAY_TOKEN 相同>"
server_pubkey = "<服务端启动时打印的 Server pubkey>"   # ID 模式验签用

[[tunnel.proxies]]
name = "rdp"
local_addr = "127.0.0.1"
local_port = 3389
remote_port = 0            # 0 = 从服务端 --port-range 自动分配
```

运行：`kirin_desk tunnel start`。

## 防火墙

端口映射概念——直接在主机上放行（ufw / firewalld / 云安全组）：

| 端口 | 用途 |
|------|------|
| `7000/tcp` | 控制端口（必须） |
| `60000-61000/tcp` | 代理数据端口范围（`remote_port=0` 自动分配用） |

打洞数据面为双端直连（UDP 打洞 + QUIC），不经过服务器，**无需**为打洞
探测额外放行服务器端口。

```bash
# ufw 示例（host 网络主机直开）
sudo ufw allow 7000/tcp && sudo ufw allow 7001/tcp
sudo ufw allow 60000:61000/tcp
```

> bridge 变体（删除 `network_mode: host` 并启用 ports 块）下端口映射为
> 容器内→主机等价端口，防火墙放行口径不变。

## 升级

```bash
# 1. 导入新版本离线镜像（如 0.3.0）
docker load -i kirin-relay-server-v0.3.0-x86_64.tar.gz
# 2. 修改 docker-compose.yml 的 image 行 tag 为 0.3.0
# 3. 重建容器（密钥卷 relay-server-key 保留，pubkey 不变，客户端无需改）
docker compose up -d
```

密钥持久化在卷 `relay-server-key`（挂载 `/home/relay/.kirin_desk`），
容器重建后 **Server pubkey 不变**，客户端预置的 `server_pubkey` 无需更新。

## 卸载

```bash
docker compose down -v    # 停止并删除容器 + 密钥卷（慎用 -v，删除后 pubkey 变化）
docker image rm kirin-relay-server:0.2.0   # 删除镜像（可选）
rm -f .env                                  # 删除本机 token 配置（可选）
```

不带 `-v` 的 `docker compose down` 仅停止容器，密钥卷保留、pubkey 不变。

## 常见问题

- **`docker compose up -d` 报 `KIRIN_RELAY_TOKEN` 未设置**：`.env` 缺失或
  token 为空。已 fail-closed 拒绝启动（安全设计），复制 `.env.example` 为
  `.env` 并填高熵 token 后重试，或直接运行 `deploy.sh` 自动生成。
- **容器反复重启 / exited**：查日志 `docker compose logs --tail=50 relay-server`。
  常见原因为 token 未配置（fail-closed 退出）。
- **pubkey 变化**：密钥卷被删除（`down -v`）或未挂载卷。正常重建容器不会变。
