#!/usr/bin/env bash
# macOS .dmg 制作脚本（M14-T004 / M12-MAC MAC-T005）。
#
# 前置：KirinDesk.app 已按 Contents/README.md 组装完毕
#   （MacOS/kirindesk 通用二进制 + Resources/ffmpeg/*.dylib + Info.plist）。
#
# 用法：
#   ./release/macos/create_dmg.sh [输出目录] [版本号]
# 输出：KirinDesk-<version>-<arch>.dmg（arch = universal / aarch64 / x86_64）

set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)/KirinDesk.app"
OUT_DIR="${1:-$(cd "$(dirname "$0")/../.." && pwd)/release/dist}"
VERSION="${2:-0.1.0}"
DMG_NAME="KirinDesk-${VERSION}-universal.dmg"
DMG_PATH="${OUT_DIR}/${DMG_NAME}"
STAGING_DIR="${OUT_DIR}/staging"

if [ ! -f "${APP_DIR}/Contents/Info.plist" ]; then
    echo "error: ${APP_DIR}/Contents/Info.plist 缺失" >&2
    exit 1
fi
if [ ! -x "${APP_DIR}/Contents/MacOS/kirindesk" ]; then
    echo "error: ${APP_DIR}/Contents/MacOS/kirindesk 缺失（先做通用二进制）" >&2
    exit 1
fi

mkdir -p "${STAGING_DIR}"
rm -rf "${STAGING_DIR}/KirinDesk.app"
cp -R "${APP_DIR}" "${STAGING_DIR}/KirinDesk.app"

# 开发阶段 ad-hoc 签名（正式发布换开发者证书）：
#   codesign --force --deep --sign "Developer ID Application: ..." KirinDesk.app
codesign --force --deep --sign - "${STAGING_DIR}/KirinDesk.app"

mkdir -p "${OUT_DIR}"
rm -f "${DMG_PATH}"
hdiutil create -volname "KirinDesk" -srcfolder "${STAGING_DIR}" \
    -ov -format UDZO "${DMG_PATH}"
rm -rf "${STAGING_DIR}"

echo "✅ ${DMG_PATH}"
