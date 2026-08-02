#!/usr/bin/env bash
# KirinDesk 版本发布脚本 — M14-T006
#
# 流程：版本号写入 Cargo.toml → CHANGELOG 归档 → commit → GPG 签名 tag →
#       push（触发 CI release job 打包）→ gh run watch → 下载产物 → gh release create。
#
# 用法：
#   release/publish.sh <X.Y.Z>            # GPG 签名 tag（需要已配置签名 key）
#   release/publish.sh <X.Y.Z> --no-sign  # 降级为普通 annotated tag
#
# 前置：git、gh CLI、python3（解析 Cargo.toml / CHANGELOG.md）。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

VERSION="${1:?usage: publish.sh <X.Y.Z> [--no-sign]}"
SIGN=1
[ "${2:-}" = "--no-sign" ] && SIGN=0

[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "error: 版本号须为 X.Y.Z（当前: ${VERSION}）" >&2
    exit 1
}
TAG="v${VERSION}"

command -v gh >/dev/null 2>&1 || { echo "error: 需要 GitHub CLI (gh)" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "error: 需要 git" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "error: 需要 python3" >&2; exit 1; }

# ── 1. 前置校验 ──────────────────────────────────────────────
if [ -n "$(git status --porcelain)" ]; then
    echo "error: 工作区有未提交改动，先提交或 stash：" >&2
    git status --porcelain >&2
    exit 1
fi
if git tag -l "${TAG}" | grep -q .; then
    echo "error: tag ${TAG} 已存在" >&2
    exit 1
fi
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "${BRANCH}" != "main" ] && [ "${BRANCH}" != "master" ]; then
    echo "warning: 当前分支 ${BRANCH}（建议 main/master 发布），继续（Enter 继续 / Ctrl-C 中止）..."
    read -r _ || true
fi

# ── 2. 版本号写入 workspace Cargo.toml + CHANGELOG 归档 ───────
echo "==> 版本 ${VERSION}（tag ${TAG}，签名=$([ ${SIGN} -eq 1 ] && echo on || echo off)）"

python3 - "${VERSION}" "${TAG}" <<'EOF'
import re, sys, datetime

version, tag = sys.argv[1], sys.argv[2]
date = datetime.date.today().isoformat()

# 2a. workspace 版本号（各 crate 用 version.workspace = true 继承）
p = "Cargo.toml"
text = open(p, encoding="utf-8").read()
new_text, n = re.subn(r'^version\s*=\s*"[0-9]+\.[0-9]+\.[0-9]+"', f'version = "{version}"',
                      text, count=1, flags=re.M)
if n == 0:
    sys.exit(f"error: {p} 未找到 version 字段")
open(p, "w", encoding="utf-8").write(new_text)

# 2b. CHANGELOG：Unreleased 段 → 版本段，顶部重建 Unreleased
p = "CHANGELOG.md"
text = open(p, encoding="utf-8").read()
m = re.search(r"## \[Unreleased\](.*?)(?=\n## \[|$)", text, re.S)
if not m:
    sys.exit(f"error: {p} 缺少 [Unreleased] 段")
body = m.group(1).rstrip() + "\n"
release_section = f"## [{tag}] - {date}\n{body}\n"
new_unreleased = "## [Unreleased]\n\n### Added\n\n（开发中功能，发布时移入版本段）\n"
text = text.replace(m.group(0), release_section + new_unreleased, 1)
text += f"[{tag}]: https://github.com/kirin-yucall/kirin_desk/releases/tag/{tag}\n"
open(p, "w", encoding="utf-8").write(text)
print(f"CHANGELOG.md: [Unreleased] → [{tag}] - {date}")
EOF

# 2c. 同步 Cargo.lock（cargo 会按新版本号刷新锁文件）
echo "==> cargo check（刷新 Cargo.lock）..."
cargo check --workspace --quiet

git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "release: ${VERSION}" --quiet
echo "==> commit: release: ${VERSION}"

# ── 3. 签名 tag + push（push 触发 CI release job） ───────────
if [ ${SIGN} -eq 1 ]; then
    git tag -s "${TAG}" -m "KirinDesk ${VERSION}" || {
        echo "warning: GPG 签名失败（未配置签名 key？），降级为普通 tag（--no-sign）" >&2
        SIGN=0
        git tag -a "${TAG}" -m "KirinDesk ${VERSION}"
    }
else
    git tag -a "${TAG}" -m "KirinDesk ${VERSION}"
fi
echo "==> tag: ${TAG}"

git push origin HEAD --quiet
git push origin "${TAG}" --quiet
echo "==> pushed ${BRANCH} + ${TAG}（CI release job 已触发）"

# ── 4. 等待 CI 打包并下载产物 ─────────────────────────────────
echo "==> 等待 CI release job 完成（首次触发含 ci job，可能较久）..."
if gh run watch --exit-status >/dev/null 2>&1; then
    echo "==> CI 通过，下载产物..."
    rm -rf "${ROOT}/release/dist/ci"
    gh run download -D "${ROOT}/release/dist/ci" --pattern 'kirindesk-*' >/dev/null 2>&1 || \
        echo "warning: 产物下载失败，跳过（release create 将只上传本地产物）"
else
    echo "warning: gh run watch 失败（CI 未触发或失败），请人工确认构建后重新运行本脚本"
fi

# ── 5. gh release create（本地产物 + CI 下载产物） ───────────
NOTES="$(python3 - "${TAG}" <<'EOF'
import re, sys
text = open("CHANGELOG.md", encoding="utf-8").read()
tag = sys.argv[1]
m = re.search(rf"## \[{re.escape(tag)}\](.*?)(?=\n## \[|$)", text, re.S)
print((m.group(1).strip() if m else f"KirinDesk {tag}")[:8000])
EOF
)"

echo "==> 上传产物并创建 GitHub Release..."
FILES=()
for pat in "${ROOT}/release/dist/"*.exe "${ROOT}/release/dist/"*.zip "${ROOT}/release/dist/"*.deb \
           "${ROOT}/release/dist/"*.dmg "${ROOT}/release/dist/ci/"*/*; do
    for f in ${pat}; do
        [ -f "${f}" ] && FILES+=("${f}")
    done
done

# ── 5.5 生成 sha256 侧车（R-07：updater 下载后校验，`<asset>.sha256`） ──
# updater 在下载完资产后拉取 `{download_url}.sha256` 强制校验（S-06 统一策略：
# 侧车缺失 → `ChecksumMissing` 拒绝，legacy 通道 deprecated 并引导用户升级）——
# 本脚本从本次发布起一律为每个资产生成侧车，杜绝"无校验资产"发布。
CHECKSUM_FILES=()
if command -v sha256sum >/dev/null 2>&1; then
    HASH_TOOL=(sha256sum)
else
    HASH_TOOL=(shasum -a 256)   # macOS 无 sha256sum
fi
for f in "${FILES[@]}"; do
    "${HASH_TOOL[@]}" "${f}" | awk '{print $1}' > "${f}.sha256"
    CHECKSUM_FILES+=("${f}.sha256")
done
echo "==> 生成 $((${#CHECKSUM_FILES[@]})) 个 sha256 侧车"

# ── 5.6 生成 checksums.txt（S-06d：全资产 SHA-256 汇总清单，随 release 上传） ──
# CI release job 亦生成同名清单；本文件供人工核验，并作为二期发布者 Ed25519
# 签名（checksums.txt.sig，计划二期）的载体。
CHECKSUMS_TXT="${ROOT}/release/dist/checksums.txt"
: > "${CHECKSUMS_TXT}"
for f in "${FILES[@]}"; do
    hex="$("${HASH_TOOL[@]}" "${f}" | awk '{print $1}')"
    echo "${hex}  $(basename "${f}")" >> "${CHECKSUMS_TXT}"
done
echo "==> 生成 checksums.txt（$(wc -l < "${CHECKSUMS_TXT}") 项）"

gh release create "${TAG}" \
    --title "KirinDesk ${VERSION}" \
    --notes "${NOTES}" \
    "${FILES[@]}" "${CHECKSUM_FILES[@]}" "${CHECKSUMS_TXT}" 2>/dev/null || {
    echo "warning: 自动创建失败，请手动执行：" >&2
    echo "  gh release create ${TAG} --title \"KirinDesk ${VERSION}\" --notes \"${NOTES}\"" >&2
    echo "  gh release upload ${TAG} release/dist/*.exe release/dist/*.zip release/dist/*.deb release/dist/*.dmg" >&2
    echo "  gh release upload ${TAG} release/dist/*.sha256" >&2
    echo "  gh release upload ${TAG} release/dist/checksums.txt" >&2
    exit 1
}

echo "✅ 发布完成: https://github.com/kirin-yucall/kirin_desk/releases/tag/${TAG}"
