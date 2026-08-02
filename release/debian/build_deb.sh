#!/usr/bin/env bash
# KirinDesk Ubuntu .deb 打包脚本 — M14-T003
#
# 前置：Linux 环境（dpkg-deb），Ubuntu 20.04+ / Debian 11+。
# 用法：
#   release/debian/build_deb.sh [版本号] [--build]
#     - 版本号缺省时从 workspace Cargo.toml 读取
#     - --build 时先 cargo build --release（否则复用现有 target-ci/release 产物）
# 输出：release/dist/kirin-desk_<version>_<arch>.deb
#
# 布局：
#   /usr/bin/kirindesk                        可执行文件
#   /etc/kirindesk/default.toml               默认配置（用户可改）
#   /lib/systemd/system/kirindesk.service     systemd 无头服务
# 依赖：libssl3 / libx11-6 / libwayland-client0 / ffmpeg（见 control.in）
# 注意：程序 dlopen 的是 libavcodec.so.62（FFmpeg 8）；Ubuntu 24.04 自带
#       FFmpeg 6（libavcodec60），需系统 FFmpeg 8 或后续随包内嵌 .so。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${ROOT}/release/dist"

VERSION="${1:-}"
if [ -z "${VERSION}" ]; then
    VERSION="$(cargo metadata --manifest-path "${ROOT}/Cargo.toml" --no-deps --format-version 1 \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["packages"][0]["version"])')"
fi
ARCH="$(dpkg --print-architecture)"

echo "==> KirinDesk deb: v${VERSION} ${ARCH}"

if [ "${2:-}" = "--build" ] || [ ! -x "${ROOT}/target-ci/release/kirin-desk-ui" ]; then
    echo "==> cargo build --release ..."
    (cd "${ROOT}" && CARGO_TARGET_DIR=target-ci cargo build --release -p kirin-desk-ui)
fi
BIN="${ROOT}/target-ci/release/kirin-desk-ui"
[ -x "${BIN}" ] || { echo "error: binary not found at ${BIN}" >&2; exit 1; }

STAGING="$(mktemp -d)"
trap 'rm -rf "${STAGING}"' EXIT

# 组装 deb 目录树
mkdir -p "${STAGING}/DEBIAN" \
         "${STAGING}/usr/bin" \
         "${STAGING}/etc/kirindesk" \
         "${STAGING}/lib/systemd/system"

sed -e "s/%VERSION%/${VERSION}/g" -e "s/%ARCH%/${ARCH}/g" \
    "${SCRIPT_DIR}/control.in" > "${STAGING}/DEBIAN/control"
cp "${SCRIPT_DIR}/postinst" "${STAGING}/DEBIAN/postinst"
cp "${SCRIPT_DIR}/postrm"   "${STAGING}/DEBIAN/postrm"
chmod 755 "${STAGING}/DEBIAN/postinst" "${STAGING}/DEBIAN/postrm"

cp "${BIN}" "${STAGING}/usr/bin/kirindesk"
cp "${ROOT}/config/default.toml" "${STAGING}/etc/kirindesk/default.toml"
cp "${SCRIPT_DIR}/kirindesk.service" "${STAGING}/lib/systemd/system/kirindesk.service"

mkdir -p "${DIST_DIR}"
DEB="${DIST_DIR}/kirin-desk_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "${STAGING}" "${DEB}" >/dev/null

echo "==> ${DEB}"
