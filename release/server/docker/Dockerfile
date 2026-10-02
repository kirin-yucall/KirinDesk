# syntax=docker/dockerfile:1
# KirinDesk 内网穿透服务端（relay-server）容器镜像 —— 多阶段构建。
#
# 维护者自建镜像（在仓库根目录执行，.dockerignore 已排除 target/.git/ffmpeg 等）：
#   bash release/server/docker/build-image.sh
#   或：docker build -f release/server/docker/Dockerfile -t kirin-relay-server:0.2.0 .
# 用户部署（免编译）：见同目录 docker-compose.yml / deploy.sh / 一键包内 README.md。

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
# 版本构建参数：仅影响 OCI label 与镜像 tag，不改二进制行为
# （工作区 Cargo.toml version=0.2.0，构建时可按需 --build-arg 覆盖）
ARG VERSION=0.2.0

# OCI 规范 labels（`docker inspect` 可见；org.opencontainers.image.source
# 指向仓库主页，发布渠道按现状为主仓库，GHCR 推送预留见 BUILD_LINUX.md）
LABEL org.opencontainers.image.title="KirinDesk relay-server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="KirinDesk 内网穿透服务端（frps 等价，含打洞 rendezvous）" \
      org.opencontainers.image.source="https://github.com/KirinDesk/KirinDesk"

# 非 root 运行：默认控制端口 7000 与端口范围均为非特权端口（<1024 需自行
# 调整 USER/端口或改用 systemd 部署）
RUN useradd --system --create-home --shell /usr/sbin/nologin relay
# 命名卷首次挂载会以 root 属主创建挂载点，relay 写密钥触发 EPERM。在镜像中
# 以 relay 属主预建后，Docker 首次挂载命名卷会复制目录属主，容器内可写。
RUN mkdir -p /home/relay/.kirin_desk && chown relay:relay /home/relay/.kirin_desk
WORKDIR /app
COPY --from=builder /build/target/release/relay-server /app/relay-server
USER relay
# HOME。relay-server 密钥默认路径经 `HOME` 解析（registry::default_key_path），
# 无 HOME 时回退到 "."（=WORKDIR /app），非 root 写 /app/.kirin_desk 触发
# EPERM 启动即失败。显式设 HOME=/home/relay 后密钥落到 VOLUME 挂载目录。
ENV HOME=/home/relay
# token 经环境变量提供（不落盘、不进进程列表；镜像内默认空值，必须注入）
ENV KIRIN_RELAY_TOKEN=""
# 服务器 Ed25519 密钥持久化目录（默认 ~/.kirin_desk/relay_server_key.pem，
# 挂载卷后重建容器 pubkey 不变，客户端 server_pubkey 无需更新）
VOLUME ["/home/relay/.kirin_desk"]
EXPOSE 7000/tcp
# HEALTHCHECK：debain:bookworm-slim 自带 bash，用 /dev/tcp 探测控制端口
# （无需额外安装 curl/wget；容器内以非 root 运行，仅需连本机回环端口）。
# bash 缺失的替代方案：改用 `CMD-SHELL` + 原生 exec（如 /proc 探测）——本镜像
# 固定 debian:bookworm-slim 自带 bash，无需替代。
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/7000' || exit 1
ENTRYPOINT ["/app/relay-server"]
# 默认参数；docker run 可用尾随参数覆盖，如：
#   docker run ... kirin-relay-server:0.2.0 --bind-port 9000 --port-range 50000-50099
#   docker run ... kirin-relay-server:0.2.0 --bind-addrs 0.0.0.0,:: --bind-port 9000 --port-range 50000-50099
# --server-key 显式指定到 VOLUME 挂载目录（与默认解析路径一致，见 ENV HOME）；
# --rendezvous-port 7001 显式对齐 README 打洞端口口径（默认值即 7001）。
CMD ["--bind-port", "7000", "--port-range", "60000-61000", \
     "--rendezvous-port", "7001", \
     "--server-key", "/home/relay/.kirin_desk/relay_server_key.pem"]
