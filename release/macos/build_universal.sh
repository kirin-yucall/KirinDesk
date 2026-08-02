#!/usr/bin/env bash
# KirinDesk macOS 通用二进制 + .app bundle 组装 — M14-T004
#
# 前置：macOS 12+，Xcode Command Line Tools（lipo/codesign/plutil）。
# 用法：
#   release/macos/build_universal.sh [版本号]
#     - 版本号缺省时从 workspace Cargo.toml 读取（用于写回 Info.plist）
# 流程：
#   1. cargo build --release（aarch64-apple-darwin 与 x86_64-apple-darwin 各一次）
#   2. lipo -create 合并 → Contents/MacOS/kirindesk（通用二进制）
#   3. 拷贝 FFmpeg dylib → Contents/Resources/ffmpeg/（dlopen 动态加载，无需改名）
#   4. 可选 icon.icns → Contents/Resources/（缺失时移除 CFBundleIconFile 声明）
#   5. codesign --force --deep ad-hoc 签名（开发阶段；正式发布换开发者证书）
# 之后运行 create_dmg.sh 制作安装镜像。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
APP_DIR="${SCRIPT_DIR}/KirinDesk.app"
CONTENTS="${APP_DIR}/Contents"

VERSION="${1:-}"
if [ -z "${VERSION}" ]; then
    VERSION="$(cargo metadata --manifest-path "${ROOT}/Cargo.toml" --no-deps --format-version 1 \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["packages"][0]["version"])')"
fi

echo "==> KirinDesk macOS universal build: v${VERSION}"

# 1. 双架构 release 构建
echo "==> cargo build --release (aarch64 + x86_64) ..."
(cd "${ROOT}" && CARGO_TARGET_DIR=target-ci cargo build --release -p kirin-desk-ui \
    --target aarch64-apple-darwin --target x86_64-apple-darwin)
ARM_BIN="${ROOT}/target-ci/aarch64-apple-darwin/release/kirin-desk-ui"
X64_BIN="${ROOT}/target-ci/x86_64-apple-darwin/release/kirin-desk-ui"
[ -x "${ARM_BIN}" ] && [ -x "${X64_BIN}" ] || { echo "error: 双架构产物缺失" >&2; exit 1; }

# 2. lipo 通用二进制
mkdir -p "${CONTENTS}/MacOS" "${CONTENTS}/Resources"
echo "==> lipo universal binary"
lipo -create "${ARM_BIN}" "${X64_BIN}" -output "${CONTENTS}/MacOS/kirindesk"

# 3. FFmpeg dylib（与 media/src/ffmpeg/dlls.rs 的 macOS 库名一致）
if [ -d "${ROOT}/release/ffmpeg" ] && ls "${ROOT}/release/ffmpeg"/libavcodec*.dylib >/dev/null 2>&1; then
    echo "==> copy FFmpeg dylibs"
    mkdir -p "${CONTENTS}/Resources/ffmpeg"
    cp "${ROOT}/release/ffmpeg"/libavcodec.*.dylib "${CONTENTS}/Resources/ffmpeg/"
    cp "${ROOT}/release/ffmpeg"/libavutil.*.dylib  "${CONTENTS}/Resources/ffmpeg/"
    cp "${ROOT}/release/ffmpeg"/libswscale.*.dylib "${CONTENTS}/Resources/ffmpeg/"
    cp "${ROOT}/release/ffmpeg"/LICENSE            "${CONTENTS}/Resources/ffmpeg/LICENSE" 2>/dev/null || true
else
    echo "==> warning: 未找到 FFmpeg dylib（release/ffmpeg/libav*.dylib），跳过内嵌"
fi

# 4. 图标（可选）
if [ -f "${SCRIPT_DIR}/icon.icns" ]; then
    cp "${SCRIPT_DIR}/icon.icns" "${CONTENTS}/Resources/icon.icns"
else
    echo "==> warning: icon.icns 缺失，从 Info.plist 移除 CFBundleIconFile"
    /usr/libexec/PlistBuddy -c "Delete :CFBundleIconFile" "${CONTENTS}/Info.plist" 2>/dev/null || true
fi

# 5. 版本写回 Info.plist
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${VERSION}" "${CONTENTS}/Info.plist" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string ${VERSION}" "${CONTENTS}/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${VERSION}" "${CONTENTS}/Info.plist" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string ${VERSION}" "${CONTENTS}/Info.plist"

# 6. ad-hoc codesign（开发阶段；正式发布：codesign --sign "Developer ID Application: ..."）
echo "==> codesign (ad-hoc, deep)"
codesign --force --deep --sign - "${APP_DIR}"

echo "==> ${APP_DIR}"
