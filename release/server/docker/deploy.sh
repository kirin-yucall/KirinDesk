#!/usr/bin/env bash
#
# 客户端可导入的节点配置 kirin-node.json——分享格式 v1，不带签名）
#
# 用法：
#   bash deploy.sh [--help]
#   bash deploy.sh -i kirin-relay-server-v0.2.0-x86_64.tar.gz
#   bash deploy.sh -i kirin-relay-server-v0.2.0-x86_64.tar.gz -t <token>
#   bash deploy.sh -i kirin-relay-server-v0.2.0-x86_64.tar.gz \
#       --name "我的家庭节点" --addr relay.example.com:7000
#
# 流程：导入离线镜像（-i，可选）→ 准备 .env（自动生成高熵 token）→
#       docker compose up -d → 等待就绪 → 打印 Server pubkey 与防火墙提示 →
# 幂等：重复运行不重建容器、不覆盖已有 .env token、kirin-node.json 覆盖更新。
#      防火墙为「主机直开」7000/7001/60000-61000（脚本尾部会打印）。
#
# 要求：本机已安装 Docker Engine/Desktop（含 compose 插件）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IMAGE="kirin-relay-server:0.2.0"
SERVICE="relay-server"
ENV_FILE=".env"
ENV_EXAMPLE=".env.example"
PLACEHOLDER="CHANGE_ME_high_entropy_token_32+bytes"

IMAGE_TAR=""
TOKEN_ARG=""
NODE_NAME=""
NODE_ADDR=""
NODE_NOTE=""

log()  { printf '[deploy] %s\n' "$*"; }
die()  { printf '[deploy] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'

用法: bash deploy.sh [选项]

选项:
  -i <tar.gz>   离线镜像包路径；本地无目标镜像时自动 `docker load -i`
  -t <token>    高熵 token（≥32 字节）；不提供且 .env 不存在时自动生成
                （openssl rand -hex 32）写入 .env
  --name <名称>    节点名称，写入导出的 kirin-node.json（默认 $(hostname)）
  --addr <host:port>  客户端可达地址，写入 kirin-node.json 的 server_addr；
                不提供则留空并打印醒目 TODO 提示手填（不瞎猜公网地址）
  --note <备注>    可选备注，写入 kirin-node.json 的 note
  --help, -h    显示本帮助

说明:
  - 幂等：重复运行不重建容器、不覆盖已有 .env token；kirin-node.json 覆盖更新
  - 完成后打印 Server pubkey（客户端 ID 模式预置 [tunnel] server_pubkey）
  - 部署成功末尾自动生成 kirin-node.json（客户端节点配置，分享格式 v1 不带
    ⚠ 分享此文件即公开 token，任何人拿到即可使用本节点（见 README
    「节点配置导出」）
    bridge 变体（删 network_mode: host + 启用 ports 块）仅用于
    Docker Desktop/macOS 等场景，小规格公网实例务必用 host（见 README「网络模式」）
  - 防火墙需放行 7000/tcp + 7001/tcp（打洞）+ 60000-61000/tcp
EOF
  exit 0
}

# ── 参数解析 ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -i)  IMAGE_TAR="${2:?deploy.sh: -i 需要参数}"; shift 2 ;;
    -t)  TOKEN_ARG="${2:?deploy.sh: -t 需要参数}"; shift 2 ;;
    --name)  NODE_NAME="${2:?deploy.sh: --name 需要参数}"; shift 2 ;;
    --addr)  NODE_ADDR="${2:?deploy.sh: --addr 需要参数}"; shift 2 ;;
    --note)  NODE_NOTE="${2:?deploy.sh: --note 需要参数}"; shift 2 ;;
    --help|-h) usage ;;
    *)   die "未知参数: $1（见 deploy.sh --help）" ;;
  esac
done

# ── 环境探测 ─────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "未找到 docker 命令，请先安装 Docker"

COMPOSE=()
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  die "未找到 docker compose（请升级 Docker 或安装 compose 插件）"
fi

[[ -f "$ENV_EXAMPLE" ]] || die "缺少 $ENV_EXAMPLE（一键包文件不完整）"

# ── 1. 导入离线镜像（本地已有则跳过，幂等） ──────────────────
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  [[ -n "$IMAGE_TAR" ]] && log "本地已存在 $IMAGE，跳过 docker load（幂等）"
else
  if [[ -n "$IMAGE_TAR" ]]; then
    [[ -f "$IMAGE_TAR" ]] || die "离线镜像包不存在: $IMAGE_TAR"
    log "导入离线镜像: $IMAGE_TAR"
    docker load -i "$IMAGE_TAR"
  else
    die "本地无镜像 $IMAGE；请用 -i <离线tar.gz> 提供离线镜像包"
  fi
fi

# ── 2. 准备 .env（token） ────────────────────────────────────
set_token_in_env() {  # $1 = token
  local token="$1" tmp="$ENV_FILE.tmp"
  awk -v t="$token" '
    /^KIRIN_RELAY_TOKEN=/ { print "KIRIN_RELAY_TOKEN=" t; found=1; next }
    { print }
    END { if (!found) print "KIRIN_RELAY_TOKEN=" t }
  ' "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
}

generate_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif [[ -r /dev/urandom ]]; then
    tr -dc 'a-f0-9' < /dev/urandom | head -c 64 || true
  else
    die "无法生成高熵 token（缺少 openssl 与 /dev/urandom）"
  fi
}

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  log "已从 $ENV_EXAMPLE 复制 .env"
  if [[ -n "$TOKEN_ARG" ]]; then
    set_token_in_env "$TOKEN_ARG"
    log "已将 -t 提供的 token 写入 .env"
  else
    set_token_in_env "$(generate_token)"
    log "已自动生成高熵 token 写入 .env（客户端需用同一 token）"
  fi
else
  # .env 已存在：幂等，不覆盖已有 token
  [[ -n "$TOKEN_ARG" ]] && log "检测到已有 .env，忽略 -t（不覆盖已有 token）"
fi

# fail-closed 校验：token 为空或仍为占位符 → 自动生成真实 token
CURRENT_TOKEN="$(grep -E '^KIRIN_RELAY_TOKEN=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true)"
if [[ -z "$CURRENT_TOKEN" || "$CURRENT_TOKEN" == "$PLACEHOLDER" ]]; then
  set_token_in_env "$(generate_token)"
  log "检测到 .env token 为空/占位符，已自动生成新 token 写入 .env"
fi

chmod 600 "$ENV_FILE"

# ── 3. docker compose up -d ──────────────────────────────────
log "启动容器（${COMPOSE[*]} up -d）"
"${COMPOSE[@]}" up -d

# ── 4. 等待就绪并提取 Server pubkey ─────────────────────────
log "等待容器就绪（最多 90 秒）..."
PUBKEY=""
for _ in $(seq 1 30); do
  STATE="$("${COMPOSE[@]}" ps --format '{{.State}}' "$SERVICE" 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ "$STATE" == "exited" || "$STATE" == "created" ]]; then
    echo "--- 容器状态: $STATE，日志如下 ---"
    "${COMPOSE[@]}" logs --tail=50 "$SERVICE" 2>/dev/null || true
    die "容器启动失败（常见原因：.env 中 token 未配置导致 fail-closed 拒绝启动）"
  fi
  PUBKEY="$("${COMPOSE[@]}" logs "$SERVICE" 2>/dev/null | grep -m1 'Server pubkey' | sed 's/.*Server pubkey: //' || true)"
  if [[ -n "$PUBKEY" ]]; then
    log "容器已就绪"
    break
  fi
  sleep 3
done

if [[ -z "$PUBKEY" ]]; then
  echo "--- 容器最近日志 ---"
  "${COMPOSE[@]}" logs --tail=50 "$SERVICE" 2>/dev/null || true
  die "90 秒内未检测到 Server pubkey，容器可能未就绪（见上方日志）"
fi

# ── 5. 输出部署结果 ─────────────────────────────────────────
echo ""
echo "================ relay-server 部署完成 ================"
echo "镜像: $IMAGE"
echo "容器: kirin-relay-server（restart: unless-stopped）"
echo "Server pubkey: $PUBKEY"
echo "  ^ 客户端 ID 模式须将上面 pubkey 预置到 [tunnel] server_pubkey"
echo ""
echo "客户端配置要点（~/.kirin_desk/default.toml 的 [tunnel] 段）:"
echo "  mode          = \"client\""
echo "  server_addr   = <本服务器公网 IP 或域名>:7000"
echo "  token         = <与 .env 中 KIRIN_RELAY_TOKEN 相同>"
echo "  server_pubkey = \"$PUBKEY\""
echo ""
echo "  7000/tcp            控制端口"
echo "  60000-61000/tcp     代理数据端口范围"
echo "  ufw 示例: sudo ufw allow 7000/tcp && sudo ufw allow 7001/tcp"
echo "            sudo ufw allow 60000:61000/tcp"
echo ""
echo "常用命令:"
echo "  查看日志:    ${COMPOSE[*]} logs -f"
echo "  重启:        ${COMPOSE[*]} restart"
echo "  查看状态:    ${COMPOSE[*]} ps"
echo "========================================================="

# 字段口径（PM 定稿）：v / type / name / server_addr / token / server_pubkey
# / note / created。token 自 .env 读（CURRENT_TOKEN）、pubkey 取容器日志
# 提取值（PUBKEY）——二者与客户端 [tunnel] 段口径一致（pubkey = Ed25519
# 32 字节 base64 STANDARD，即服务启动打印的同一串，导入无需转换）。
# 本文件本身即分发给用户的凭据载体（用户自愿），但绝不把 token 打到日志；
NODE_FILE="kirin-node.json"
if [[ -z "$NODE_NAME" ]]; then
  NODE_NAME="$(hostname 2>/dev/null || true)"
  [[ -n "$NODE_NAME" ]] || NODE_NAME="kirin-node"
fi

json_escape() {  # $1 = 原始串 → JSON 字符串内容（转义 \ 与 "，拒绝控制字符）
  local s="$1"
  # 注：bash 变量不可能携带 NUL（赋值/命令替换即截断），故只查 \n \r \t
  if [[ "$s" == *$'\n'* || "$s" == *$'\r'* || "$s" == *$'\t'* ]]; then
    die "节点名称/备注含控制字符（换行/Tab 等），请重试"
  fi
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

# 先转义后生成（fail-closed）：控制字符命中 die → 赋值状态非零 → set -e 中止，
# 不会写出半吊子文件（若在 printf 参数里内联 $()，失败会被 printf 吞掉）。
NODE_NAME_ESC="$(json_escape "$NODE_NAME")"
NODE_ADDR_ESC="$(json_escape "$NODE_ADDR")"
NODE_TOKEN_ESC="$(json_escape "$CURRENT_TOKEN")"
NODE_PUBKEY_ESC="$(json_escape "$PUBKEY")"
NODE_NOTE_ESC="$(json_escape "$NODE_NOTE")"
NODE_CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  printf '{\n'
  printf '  "v": 1,\n'
  printf '  "type": "kirin-node",\n'
  printf '  "name": "%s",\n'          "$NODE_NAME_ESC"
  printf '  "server_addr": "%s",\n'   "$NODE_ADDR_ESC"
  printf '  "token": "%s",\n'         "$NODE_TOKEN_ESC"
  printf '  "server_pubkey": "%s",\n' "$NODE_PUBKEY_ESC"
  printf '  "note": "%s",\n'          "$NODE_NOTE_ESC"
  printf '  "created": "%s"\n'        "$NODE_CREATED"
  printf '}\n'
} > "$NODE_FILE"
chmod 600 "$NODE_FILE"

echo ""
echo "已生成: $SCRIPT_DIR/$NODE_FILE（权限 600 仅属主可读）"
if [[ -n "$NODE_ADDR" ]]; then
  echo "  server_addr = $NODE_ADDR（--addr 指定）"
else
  echo "  ⚠⚠ TODO: server_addr 为空——未指定 --addr，脚本不瞎猜公网地址"
  echo "     分发前请编辑 $NODE_FILE 手填: server_addr = <公网IP或域名>:<客户端可达端口>"
  echo "     （默认端口 7000；若 compose 自定义了 --bind-port，端口须与之对应）"
fi
echo "  节点名称     = $NODE_NAME"
echo "  ⚠ 分享此文件即公开 token——任何人拿到即可使用本节点，请像密码一样保管。"
echo "幂等: 重复运行 deploy.sh 会覆盖更新此文件（token/pubkey 变化时同步刷新）。"
echo "========================================================="
