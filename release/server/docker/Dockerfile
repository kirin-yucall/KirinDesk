# syntax=docker/dockerfile:1
# KirinDesk 内网穿透服务端（relay-server）容器镜像 —— 多阶段构建。
#
# 构建镜像（在仓库根目录执行，.dockerignore 已排除 target/.git/ffmpeg 等）：
#   docker build -f release/server/docker/Dockerfile -t kirin-relay-server .
# 或直接部署：docker compose（见同目录 docker-compose.yml）。

# ── 阶段 1：编译 ─────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder
WORKDIR /build
# gcc/libc6-dev：get_if_addrs 等依赖的 C 工具链（保险起见安装；
# relay 本身无 OpenSSL/FFmpeg 系统依赖，镜像体积可控）
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
# 复制整个 workspace（Cargo.lock 锁定依赖版本，构建可复现）
COPY Cargo.toml Cargo.lock ./
COPY core core
COPY dns dns
COPY media media
COPY input input
COPY relay relay
COPY relay-server relay-server
COPY ui ui
COPY updater updater
COPY utils utils
# 仅编译内网穿透服务端（其余 member 只作为 workspace 成员存在，不会编译）
RUN cargo build --release -p relay-server

# ── 阶段 2：运行 ─────────────────────────────────────────────
FROM debian:bookworm-slim
# 非 root 运行：默认控制端口 7000 与端口范围均为非特权端口（<1024 需自行
# 调整 USER/端口或改用 systemd 部署）
RUN useradd --system --create-home --shell /usr/sbin/nologin relay
WORKDIR /app
COPY --from=builder /build/target/release/relay-server /app/relay-server
USER relay
# token 经环境变量提供（不落盘、不进进程列表；镜像内默认空值，必须注入）
ENV KIRIN_RELAY_TOKEN=""
# 服务器 Ed25519 密钥持久化目录（默认 ~/.kirin_desk/relay_server_key.pem，
# 挂载卷后重建容器 pubkey 不变，客户端 server_pubkey 无需更新）
VOLUME ["/home/relay/.kirin_desk"]
EXPOSE 7000/tcp
ENTRYPOINT ["/app/relay-server"]
# 默认参数；docker run 可用尾随参数覆盖，如：
#   docker run ... kirin-relay-server --bind-port 9000 --port-range 50000-50099
#   docker run ... kirin-relay-server --bind-addrs 0.0.0.0,:: --bind-port 9000 --port-range 50000-50099
CMD ["--bind-port", "7000", "--port-range", "60000-60099"]
