#!/usr/bin/env bash
# KirinDesk 本地发布准备脚本（无凭据部分）—— 供实机验证后正式发布使用。
#
# 职责（不需要任何 GitHub 凭据）：
#   1. CHANGELOG [Unreleased] → [vX.Y.Z] 归档（Keep a Changelog）
#   2. cargo check 刷新 Cargo.lock（版本号已在构建前 bump，此处保证一致）
#   3. git commit "release: X.Y.Z"
#   4. git tag vX.Y.Z（annotated，GPG 可用则签名）
#   5. 为 release/dist/ 全部产物生成 .sha256 侧车 + checksums.txt
#   6. 打印 push + GitHub Release 的上传命令（gh CLI / REST API 二选一，需凭据）
#
# 用法: release/publish_local.sh <X.Y.Z>
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

VERSION="${1:?usage: release/publish_local.sh <X.Y.Z>}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "error: 版本号须为 X.Y.Z" >&2; exit 1; }
TAG="v${VERSION}"

[ -n "$(git status --porcelain)" ] && { echo "error: 工作区有未提交改动，先提交/stash：" >&2; git status --porcelain >&2; exit 1; }
git tag -l "${TAG}" | grep -q . && { echo "error: tag ${TAG} 已存在" >&2; exit 1; }

# 1. CHANGELOG 归档（同 publish.sh 2b 片段）
python3 - "${VERSION}" "${TAG}" <<'EOF'
import re, sys, datetime
version, tag = sys.argv[1], sys.argv[2]
date = datetime.date.today().isoformat()
p = "CHANGELOG.md"
text = open(p, encoding="utf-8").read()
m = re.search(r"## \[Unreleased\](.*?)(?=\n## \[|$)", text, re.S)
if not m:
    sys.exit(f"error: {p} 缺少 [Unreleased] 段")
body = m.group(1).rstrip() + "\n"
release_section = f"## [{tag}] - {date}\n{body}\n"
new_unreleased = "## [Unreleased]\n\n### Added\n\n（开发中功能，发布时移入版本段）\n"
text = text.replace(m.group(0), release_section + new_unreleased, 1)
text += f"[{tag}]: https://github.com/kirin-yucall/KirinDesk/releases/tag/{tag}\n"
open(p, "w", encoding="utf-8").write(text)
print(f"CHANGELOG.md: [Unreleased] -> [{tag}] - {date}")
EOF

# 2. 刷新 Cargo.lock（对齐 workspace 版本）
echo "==> cargo check --workspace（刷新 Cargo.lock）..."
cargo check --workspace --quiet

# 3. commit
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "release: ${VERSION}" --quiet
echo "==> commit: release: ${VERSION}"

# 4. tag
if command -v gpg >/dev/null 2>&1 && git config --get user.signingkey >/dev/null 2>&1; then
  git tag -s "${TAG}" -m "KirinDesk ${VERSION}" || git tag -a "${TAG}" -m "KirinDesk ${VERSION}"
else
  git tag -a "${TAG}" -m "KirinDesk ${VERSION}"
fi
echo "==> tag: ${TAG}"

# 5. 侧车 + 清单（全部 release/dist 产物）
DIST="${ROOT}/release/dist"
if [ -d "${DIST}" ]; then
  HASH_TOOL=(sha256sum); command -v sha256sum >/dev/null 2>&1 || HASH_TOOL=(shasum -a 256)
  : > "${DIST}/checksums.txt"
  for f in "${DIST}"/*; do
    [ -f "${f}" ] || continue
    base="$(basename "${f}")"
    [ "${base}" = "checksums.txt" ] && continue
    hex="$("${HASH_TOOL[@]}" "${f}" | awk '{print $1}')"
    printf '%s\n' "${hex}" > "${f}.sha256"
    printf '%s  %s\n' "${hex}" "${base}" >> "${DIST}/checksums.txt"
  done
  echo "==> 生成 $(find "${DIST}" -maxdepth 1 -name '*.sha256' | wc -l) 个 .sha256 侧车 + checksums.txt（$(wc -l < "${DIST}/checksums.txt") 项）"
else
  echo "warning: release/dist 不存在，跳过侧车生成"
fi

echo
echo "✅ 本地准备完成。后续需要凭据的步骤（二选一）："
echo
echo "── 方式 A：gh CLI（安装: winget install GitHub.cli；登录: gh auth login）──"
echo "  git push origin HEAD ${TAG}"
echo "  gh release create ${TAG} --title \"KirinDesk ${VERSION}\" --notes \"<CHANGELOG 版本段>\" \\"
echo "      release/dist/* release/dist/*.sha256 release/dist/checksums.txt"
echo
echo "── 方式 B：REST API（export GH_TOKEN=<PAT，repo 权限> 后）──"
echo "  git push origin HEAD ${TAG}"
echo "  REL_ID=\$(curl -s -X POST https://api.github.com/repos/kirin-yucall/KirinDesk/releases \\"
echo "      -H \"Authorization: Bearer \$GH_TOKEN\" -H \"Accept: application/vnd.github+json\" \\"
echo "      -d \"{\\\"tag_name\\\":\\\"${TAG}\\\",\\\"name\\\":\\\"KirinDesk ${VERSION}\\\",\\\"draft\\\":true}\" | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"id\"])')"
echo "  for f in release/dist/* release/dist/checksums.txt; do"
echo "    [ -f \"\$f\" ] || continue"
echo "    curl -s -X POST \"https://uploads.github.com/repos/kirin-yucall/KirinDesk/releases/\$REL_ID/assets?name=\$(basename \"\$f\")\" \\"
echo "        -H \"Authorization: Bearer \$GH_TOKEN\" -H \"Content-Type: application/octet-stream\" --data-binary \"@\$f\" >/dev/null"
echo "  done"
echo "  （draft=true 上传完成后手动改 publish，或去掉 draft 直接发布）"
