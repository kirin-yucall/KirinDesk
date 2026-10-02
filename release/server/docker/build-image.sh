#!/usr/bin/env bash
#
#
# 用法（在仓库根目录执行，或本脚本内已自动定位仓库根）：
#   bash release/server/docker/build-image.sh
#   bash release/server/docker/build-image.sh --tag 0.2.1
#
# 产出：
#   release/dist/kirin-relay-server-v<版本>-x86_64.tar.gz   # docker save | gzip 离线镜像
#   release/dist/kirin-relay-server-v<版本>-x86_64.tar.gz.sha256
#
# 说明：产物仅供 x86_64（linux/amd64）架构；release/dist/ 已被 .gitignore
#       忽略，不入版本库。镜像 tag 默认 kirin-relay-server:0.2.0（与
#       docker-compose.yml / deploy.sh 默认一致）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

die() { printf '[build-image] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[build-image] %s\n' "$*"; }

TAG="0.2.0"   # 默认版本，可用 --tag 覆盖
# 也可自动从 workspace 读取（未显式给 --tag 时优先用仓库版本）：
if [[ $# -eq 0 ]]; then
  REPO_VERSION="$(grep -m1 '^version *=' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/' || true)"
  [[ -n "$REPO_VERSION" ]] && TAG="$REPO_VERSION"
fi

usage() {
  cat <<'EOF'
KirinDesk relay-server 维护者构建 + 离线包导出

用法: bash release/server/docker/build-image.sh [--tag <版本>]

选项:
  --tag <版本>   镜像 tag 与产物版本（默认读仓库 Cargo.toml version）
  --help         显示本帮助

步骤:
  1. docker build -f release/server/docker/Dockerfile \
        -t kirin-relay-server:<版本> <仓库根>
  2. docker save <镜像> | gzip → release/dist/kirin-relay-server-v<版本>-x86_64.tar.gz
  3. 生成 sha256 侧车（同目录 .sha256）

Windows（WSL2）提示: 在 Git Bash 内执行
  wsl -d Ubuntu bash release/server/docker/build-image.sh
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="${2:?build-image.sh: --tag 需要参数}"; shift 2 ;;
    --help|-h) usage ;;
    *) die "未知参数: $1（见 build-image.sh --help）";;
  esac
done

command -v docker >/dev/null 2>&1 || die "未找到 docker 命令"

IMAGE="kirin-relay-server:${TAG}"
OUT_DIR="$REPO_ROOT/release/dist"
ARCH="x86_64"
ARTIFACT="kirin-relay-server-v${TAG}-${ARCH}.tar.gz"

mkdir -p "$OUT_DIR"

# ── 1. 构建 ─────────────────────────────────────────────────
log "构建镜像: $IMAGE（build context = 仓库根 $REPO_ROOT）"
docker build \
  -f "$SCRIPT_DIR/Dockerfile" \
  -t "$IMAGE" \
  --build-arg VERSION="$TAG" \
  "$REPO_ROOT"

# ── 2. docker save | gzip 导出离线包 ────────────────────────
log "导出离线镜像: $OUT_DIR/$ARTIFACT"
docker save "$IMAGE" | gzip -9 > "$OUT_DIR/$ARTIFACT"

# ── 3. sha256 侧车 ──────────────────────────────────────────
log "生成 sha256 侧车"
( cd "$OUT_DIR" && sha256sum "$ARTIFACT" > "$ARTIFACT.sha256" )
SIZE="$(du -h "$OUT_DIR/$ARTIFACT" | cut -f1)"
SHA="$(awk '{print $1}' "$OUT_DIR/$ARTIFACT.sha256")"

log "完成:"
log "  镜像     $IMAGE"
log "  产物     $OUT_DIR/$ARTIFACT ($SIZE)"
log "  sha256   $SHA"
log "  侧车     $OUT_DIR/$ARTIFACT.sha256"
echo ""
echo "分发与部署:"
echo "  # 把 tar.gz + sha256 + deploy.sh + docker-compose.yml + .env.example + README.md 拷到目标服务器"
echo "  tar -xzf $ARTIFACT"
echo "  cd <解压目录>"
echo "  bash deploy.sh -i $ARTIFACT"
echo ""
echo "Windows（WSL2）调用提示（在 Git Bash 内）:"
echo "  wsl -d Ubuntu bash release/server/docker/build-image.sh"
