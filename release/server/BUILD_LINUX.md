# relay-server — Linux 编译引导

KirinDesk 内网穿透服务端（frps 等价）在 **Linux 上由用户本机编译**：
产物是单静态依赖二进制（tokio 全异步，无 OpenSSL/系统库依赖），
拷到任意 Linux x86_64 服务器即可运行。

部署方式二选一：

| 方式 | 适用 | 说明 |
|---|---|---|
| **Docker 一键部署（免编译，推荐）** | 有 Docker 的服务器，想拿包即用 | 离线镜像包 + `deploy.sh`，无需任何编译，见「Docker 部署」 |
| **原生二进制 + systemd** | 无 Docker / 偏好裸机 | 本文件主体内容，附 systemd 示例 |

## Docker 部署（推荐，免编译）


**交付物**：`release/dist/kirin-relay-server-v0.2.0-x86_64.tar.gz`（离线镜像，
维护者用 `release/server/docker/build-image.sh` 产出）+ `deploy.sh` +
`docker-compose.yml` + `.env.example` + `README.md`，架构仅 **x86_64**。
用户在目标服务器（装有 Docker，可完全离线）三步部署：

```bash
tar -xzf kirin-relay-server-v0.2.0-x86_64.tar.gz   # 解包
cd kirin-relay-server-v0.2.0-docker
bash deploy.sh -i kirin-relay-server-v0.2.0-x86_64.tar.gz
```

`deploy.sh` 自动：导入离线镜像 → 生成/复用 `.env` token（自动生成高熵 token）
→ `docker compose up -d` → 等待就绪 → 打印 **Server pubkey** 与防火墙提示；
幂等可重复运行。

等价手动步骤（离线包解压后）：

```bash
docker load -i kirin-relay-server-v0.2.0-x86_64.tar.gz
cp .env.example .env        # 填写高熵 token（KIRIN_RELAY_TOKEN）
docker compose up -d

docker compose logs -f      # 查看 Server pubkey（客户端 ID 模式预置用）
docker compose down         # 停止（密钥卷保留，pubkey 不变）
```

要点：

  docker-proxy 开销（bridge 全量 1001 端口发布在小规格实例实测不可行）、
  `down`/`restart` 秒级；host 与 bridge 变体切换及小规格实例警示见
  `docker/README.md`「网络模式」。
- **token 不落盘**：经环境变量 `KIRIN_RELAY_TOKEN` 注入；`.env` 缺失时
  compose 直接报错退出（fail-closed，TNL-SEC-006）。
- **密钥持久化**：Ed25519 服务器密钥存于卷 `relay-server-key`
  容器重建后 pubkey 不变，客户端 `server_pubkey` 无需同步更新。
- **防火墙**：host 网络下**主机直开** `7000/tcp`（控制）、`7001/tcp`
  `60000-61000/tcp`（代理端口范围）。
- **健康检查**：镜像内置 `HEALTHCHECK`（bash `/dev/tcp` 探测 7000/tcp），
  `docker compose ps` 可见 healthy 状态。

### 维护者自建镜像

改源码后重打包（需要源码 + Docker，非普通用户路径）：

```bash
cd <仓库根目录>
bash release/server/docker/build-image.sh          # 构建 + save|gzip 导出 + sha256
# 或手动：
#   docker build -f release/server/docker/Dockerfile -t kirin-relay-server:0.2.0 .
#   cd release/server/docker && docker compose up -d --build
```

单独用 docker run（镜像已 load）：

```bash
docker run -d --name kirin-relay --restart unless-stopped \
  -e KIRIN_RELAY_TOKEN="$TOKEN" \
  -p 7000:7000/tcp -p 7001:7001/tcp -p 60000-61000:60000-61000/tcp \
  -v relay-server-key:/home/relay/.kirin_desk \
  kirin-relay-server:0.2.0
```

> 镜像源现状无镜像仓库账号，暂不做 GHCR 推送；后续有仓库后追加
> `docker tag` + `docker push` 即可（镜像已带 OCI labels）。

## 前置（原生编译）

- Rust 稳定版工具链（推荐 rustup）：

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source "$HOME/.cargo/env"
  rustc --version   # 需 ≥ 1.70（edition 2021 即可，建议保持最新）
  ```

- 无需系统库（relay 不依赖 openssl / ffmpeg 等）。

## 编译

```bash
git clone <仓库地址> kirin_desk
cd kirin_desk

# 仅编译内网穿透服务端（relay-server crate，含 relay 库）
cargo build --release -p relay-server

# 产物
ls -lh target/release/relay-server
```

> 说明：`cargo build --release -p relay-server` 只构建服务端所需依赖，
> 不会编译整个 KirinDesk 工作区（GUI/FFmpeg 等），首次约 1-2 分钟，
> 之后增量秒级。

## 部署

```bash
sudo install -m 0755 target/release/relay-server /usr/local/bin/relay-server

# 生成高熵 token
TOKEN=$(openssl rand -hex 32)
echo "KIRIN_RELAY_TOKEN=$TOKEN"   # 保存，分发给客户端

# 前台试运行（公钥首次启动自动生成并打印）
relay-server --bind-port 7000 --port-range 60000-61000
# 显式 IPv4+IPv6 双监听（可选；v6 一律 v6-only，留空 = 默认双栈回退）：
# relay-server --bind-addrs 0.0.0.0,:: --bind-port 7000 --port-range 60000-61000
```

## systemd 守护（推荐）

编辑 `/etc/systemd/system/relay-server.service`（模板见同目录
`relay-server.service`）：

```ini
[Unit]
Description=KirinDesk Relay Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=KIRIN_RELAY_TOKEN=<你的高熵token>
# ExecStart=/usr/local/bin/relay-server --bind-port 7000 --token-file /etc/kirin/relay_token --port-range 60000-61000
ExecStart=/usr/local/bin/relay-server --bind-port 7000 --port-range 60000-61000
# 打洞 rendezvous 默认 7001 随服务启用（--rendezvous-port 7001，防火墙放行）；
# 如需关闭打洞：追加 --no-rendezvous
# 如需显式多监听（IPv4+IPv6 双监听，v6 一律 v6-only）：
# ExecStart=/usr/local/bin/relay-server --bind-addrs 0.0.0.0,:: --bind-port 7000 --port-range 60000-61000
Restart=on-failure
RestartSec=3
# 密钥持久化在 /root/.kirin_desk/relay_server_key.pem（首次启动自动生成）
# 换机部署时备份该文件，否则客户端预置的 server_pubkey 需同步更新

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now relay-server
journalctl -u relay-server -f   # 查看日志/审计
```

`SO_REUSEADDR` 已设置，重启可立即重绑同端口。


Unix 下程序启动即自动收紧目录库权限：`relay.db` → `0600`、程序新建的父
目录 → `0700`（best-effort，失败仅 WARN 不拒启）。**以非 root 运行**
（systemd `User=` 指定专用用户，数据目录属主与之一致；模板
`relay-server.service` 已注明数据目录路径），WAL 伴生文件
`relay.db-wal`/`relay.db-shm` 同目录随库同卷、随目录权限继承。备份介质按
`0600` 保管。详见 `release/server/README.md`「文件权限」节。

## 防火墙

```bash
# firewalld 示例：放行控制端口 7000 + 打洞 rendezvous 7001 + 代理端口范围
sudo firewall-cmd --permanent --add-port=7000/tcp
sudo firewall-cmd --permanent --add-port=7001/tcp
sudo firewall-cmd --permanent --add-port=60000-61000/tcp
sudo firewall-cmd --reload
```

## 客户端侧对照

- 普通代理模式：`kirin_desk tunnel start`（配置 `[tunnel] server_addr/token`）。
- ID 模式：客户端 `[tunnel] server_pubkey` 填服务端启动日志中的
  `Server pubkey`（Ed25519 公钥，ID-SEC-001 验签）。

## 可选：静态链接（musl）

如需彻底无 glibc 依赖的静态二进制（如 Alpine 容器/任意发行版），
可用 zig 交叉编译（Windows/macOS 上亦可）：

```bash
cargo install cargo-zigbuild
cargo zigbuild --release -p relay-server --target x86_64-unknown-linux-musl
ls -lh target/x86_64-unknown-linux-musl/release/relay-server
```

Linux 本机原生编译（glibc 动态链接）已足够日常部署，无需此步。
