#!/usr/bin/env bash
# ============================================================
#
#  与 release/download-ffmpeg.bat 功能对等：
#  从 BtbN/FFmpeg-Builds（ffmpeg.org 官方推荐构建方）下载 FFmpeg 8.1.x
#  avformat-62 / avutil-60 / swresample-6 / swscale-9）：
#    Windows（Git Bash）：bin/*.dll → <target>/bin/
#    Linux：              lib/libavcodec.so.62 等 → <target>/（便携布局）
#    macOS：              无官方共享构建 → 提示用 Homebrew（不下载）
#
#  源与回退（2026-08-18 实测可达性）：
#    Windows 主源：BtbN GitHub release  ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip
#    Windows 备源：gyan.dev 官方        ffmpeg-release-full-shared.7z（需 7z 解压；
#                  当前可能为 9.x，avcodec-63 与快照 major=62 不兼容时明确报错）
#    Linux 主源：  BtbN GitHub release  ffmpeg-n8.1-latest-linux64-gpl-shared-8.1.tar.xz
#    注意：清华 TUNA 镜像当前不提供 FFmpeg builds（2026-08-18 实测 404）。
#
#  幂等：目标已含 7 个运行库且非空 → 跳过（--force 强制重下）。
#  校验：sha256 对照 BtbN 发布 checksums.sha256 / gyan.dev 侧车；校验值
#        不可得时回退「数量 + 文件名 + 非零体积」最小门禁。
#  红线：无遥测；仅在用户显式运行时才联网下载。
#
#  用法：
#    download-ffmpeg.sh                # 默认下载到 release/ffmpeg/
#    download-ffmpeg.sh --target DIR   # 指定输出目录
#    download-ffmpeg.sh --url URL      # 指定自定义直链（zip/7z/tar.xz）
#    download-ffmpeg.sh --force        # 目标已存在时强制重新下载
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/ffmpeg"
CUSTOM_URL=""
FORCE=0

# ── 参数解析 ──────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --url)    CUSTOM_URL="$2"; shift ;;
        --target) TARGET="$2"; shift ;;
        --force)  FORCE=1 ;;
        -h|--help)
            echo "用法: download-ffmpeg.sh [--url URL] [--target DIR] [--force]"
            exit 0 ;;
        *) echo "error: 未知参数: $1" >&2; exit 2 ;;
    esac
    shift
done


# ── 平台判定（可用 KIRIN_FFMPEG_PLATFORM=linux|windows 强制，便于
#    Windows 上为 Linux 打包等交叉场景；默认按 uname 自动判定）──
PLATFORM="${KIRIN_FFMPEG_PLATFORM:-}"
if [ -z "${PLATFORM}" ]; then
    case "$(uname -s)" in
        Linux*)  PLATFORM="linux" ;;
        MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
        Darwin*)
            echo "macOS 无官方 FFmpeg 共享构建下载源（BtbN/gyan.dev 均只出 Windows/Linux）。"
            echo "请改用 Homebrew：brew install ffmpeg （提供 libavcodec.62.dylib 等，"
            echo "或 brew install ffmpeg@8）。KirinDesk 会自动经系统搜索路径动态加载。"
            exit 0 ;;
        *)
            echo "error: 未知平台 $(uname -s)" >&2
            exit 2 ;;
    esac
fi
case "${PLATFORM}" in
    linux|windows) ;;
    *) echo "error: KIRIN_FFMPEG_PLATFORM 须为 linux|windows" >&2; exit 2 ;;
esac

if [ "${PLATFORM}" = "windows" ]; then
    # avcodec/avdevice/avformat=.dll（-62）、avfilter=-11、avutil=-60、
    # swresample=-6、swscale=-9（与 release/ffmpeg/bin 同名）。
                     avformat-62.dll avutil-60.dll swresample-6.dll swscale-9.dll )
    REQUIRED_SO=()
    BIN_DIR="${TARGET}/bin"
    PRIMARY_URL="https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip"
    FALLBACK_URL="https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-full-shared.7z"
else
    # avcodec/avformat/avdevice=.so.62、avfilter=.so.11、avutil=.so.60、
    # swresample=.so.6、swscale=.so.9（BtbN linux64 共享构建 lib/ 布局）。
    REQUIRED_NAMES=()
    REQUIRED_SO=( libavcodec.so.62 libavdevice.so.62 libavfilter.so.11 \
                  libavformat.so.62 libavutil.so.60 libswresample.so.6 libswscale.so.9 )
    BIN_DIR="${TARGET}"
    PRIMARY_URL="https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-n8.1-latest-linux64-gpl-shared-8.1.tar.xz"
    FALLBACK_URL=""
fi

# ══════════════════════════════════════════════════════════
#  子例程：尝试单个源（下载 → sha256 校验 → 解压 → 提取）
#  $1 = URL；成功返回 0，失败返回 1
# ══════════════════════════════════════════════════════════
try_source() {
    local url="$1"
    local archive="${url##*/}"
    local zpath="${WORK}/${archive}"
    local expected="" local_hash="" n

    echo "   下载 ${archive} ..."
    curl -fL --retry 2 --connect-timeout 30 -o "${zpath}" "${url}" || return 1
    echo "   已下载 $(wc -c < "${zpath}") bytes"

    # ── sha256 校验（尽力而为）──
    if [ "${url}" = "${PRIMARY_URL}" ]; then
        curl -fL --connect-timeout 30 -s -o "${WORK}/checksums.sha256" \
            "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/checksums.sha256" || true
        expected="$(awk -v f="${archive}" '$2 == f {print $1}' "${WORK}/checksums.sha256" 2>/dev/null | head -1 || true)"
    else
        curl -fL --connect-timeout 30 -s -o "${WORK}/sidecar.sha256" "${url}.sha256" || true
        expected="$(awk '{print $1; exit}' "${WORK}/sidecar.sha256" 2>/dev/null || true)"
    fi
    if [ -n "${expected}" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            local_hash="$(sha256sum "${zpath}" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
            local_hash="$(shasum -a 256 "${zpath}" | awk '{print $1}')"
        fi
        if [ "${local_hash}" = "${expected}" ]; then
            echo "   [OK] sha256 一致: ${local_hash}"
        else
            echo "   [FAIL] sha256 不一致！（预期 ${expected}，实际 ${local_hash}）" >&2
            echo "          源可能在发布间更新，或下载损坏。终止本源。" >&2
            return 1
        fi
    else
        echo "   [WARN] 未能取得官方校验值，改用 DLL 数量/文件名门禁。"
    fi

    # ── 解压 ──────────────────────────────────────────────
    case "${archive}" in
        *.zip)
            if command -v unzip >/dev/null 2>&1; then
                ( cd "${WORK}" && unzip -q "${archive}" ) || return 1
            else
                ( cd "${WORK}" && tar -xf "${archive}" ) || return 1
            fi
            ;;
        *.tar.xz)
            # 真实 Linux 下 GNU tar 正常建符号链接；MSYS/Windows 下因文件
            # 系统权限无法建链接会报错（真实 .so 文件仍解出）——容忍错误，
            # 后续按 soname 匹配复制真实文件；解出数量由本源门禁兜底。
            if command -v tar >/dev/null 2>&1; then
                tar -xJf "${zpath}" -C "${WORK}" >/dev/null 2>&1 || true
            else
                echo "   [FAIL] 需要 tar（解压 tar.xz）" >&2
                return 1
            fi
            ;;
        *.7z)
            if command -v 7z >/dev/null 2>&1; then
                ( cd "${WORK}" && 7z x -y "${archive}" >/dev/null ) || return 1
            elif command -v 7za >/dev/null 2>&1; then
                ( cd "${WORK}" && 7za x -y "${archive}" >/dev/null ) || return 1
            else
                echo "   [FAIL] 需要 7-Zip（7z/7za）解压 .7z 包，但未找到。" >&2
                echo "          请安装 7-Zip 后重试，或改用 --url 提供 zip 直链。" >&2
                return 1
            fi
            ;;
        *)
            echo "   [FAIL] 不支持的归档类型: ${archive}" >&2
            return 1 ;;
    esac

    # ── 提取 7 个运行库 ────────────────────────────────────
    if [ "${PLATFORM}" = "windows" ]; then
        n=0
        for dll in "${REQUIRED_NAMES[@]}"; do
            [ -s "${BIN_DIR}/${dll}" ] && continue
            found="$(find "${WORK}" -type f -name "${dll}" 2>/dev/null | head -1)"
            if [ -n "${found}" ]; then
                cp -f "${found}" "${BIN_DIR}/${dll}"
                n=$((n + 1))
            fi
        done
    else
        n=0
        for so in "${REQUIRED_SO[@]}"; do
            [ -s "${BIN_DIR}/${so}" ] && continue
            # 兼容「符号链接缺失」场景（MSYS/Windows）：匹配 soname 或
            # 版本化真实文件（libavcodec.so.62 或 libavcodec.so.62.28.102）。
            found="$(find "${WORK}" \( -type l -o -type f \) \( -name "${so}" -o -name "${so}.*" \) 2>/dev/null | head -1)"
            if [ -n "${found}" ]; then
                # -L：解引用符号链接，复制真实文件（独立目录可运行）
                cp -fL "${found}" "${BIN_DIR}/${so}"
                n=$((n + 1))
            fi
        done
    fi

    # ── LICENSE（尽力而为）────────────────────────────────
    lic="$(find "${WORK}" -maxdepth 3 -iname "LICENSE*" 2>/dev/null | head -1)"
    [ -n "${lic}" ] && cp -f "${lic}" "${TARGET}/LICENSE" 2>/dev/null || true

    # ── 本源门禁：找到 7 个才视为成功 ──────────────────────
    n=0
    for item in "${REQUIRED_NAMES[@]}" "${REQUIRED_SO[@]}"; do
        [ -s "${BIN_DIR}/${item}" ] && n=$((n + 1))
    done
    if [ "${n}" != "7" ]; then
        echo "   [WARN] 本源 ${archive} 中未找到全部 7 个所需运行库（仅 ${n} 个）。" >&2
        echo "          可能是构建主版本不匹配（avcodec 非 62）——交由主流程回退下一源。" >&2
        for item in "${REQUIRED_NAMES[@]}" "${REQUIRED_SO[@]}"; do
            rm -f "${BIN_DIR}/${item}"
        done
        return 1
    fi
    return 0
}

echo "============================================================"
echo "============================================================"
echo
echo "输出目录: ${TARGET}"
mkdir -p "${BIN_DIR}"

# ── 幂等检查 ──────────────────────────────────────────────
if [ "${FORCE}" = "0" ] && [ "${PLATFORM}" = "windows" ]; then
    complete=1
    for dll in "${REQUIRED_NAMES[@]}"; do
        [ -s "${BIN_DIR}/${dll}" ] || complete=0
    done
    if [ "${complete}" = "1" ]; then
        echo "[SKIP] ${BIN_DIR} 已含全部 7 个运行库且非空，无需下载。"
        echo "       如需强制重新下载请加 --force。"
        exit 0
    fi
elif [ "${FORCE}" = "0" ]; then
    complete=1
    for so in "${REQUIRED_SO[@]}"; do
        [ -s "${BIN_DIR}/${so}" ] || complete=0
    done
    if [ "${complete}" = "1" ]; then
        echo "[SKIP] ${BIN_DIR} 已含全部 7 个运行库且非空，无需下载。"
        echo "       如需强制重新下载请加 --force。"
        exit 0
    fi
fi

command -v curl >/dev/null 2>&1 || { echo "error: 需要 curl" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kirin-ffmpeg-dl.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

ok=0
if [ -n "${CUSTOM_URL}" ]; then
    echo
    echo "[1/3] 使用自定义 URL 下载..."
    if try_source "${CUSTOM_URL}"; then ok=1; else
        echo "[ERROR] 自定义 URL 下载/校验失败: ${CUSTOM_URL}" >&2
        exit 1
    fi
fi
if [ "${ok}" = "0" ]; then
    echo
    echo "[1/3] 主源（BtbN FFmpeg 8.1 共享构建）..."
    if ! try_source "${PRIMARY_URL}"; then
        if [ -n "${FALLBACK_URL}" ]; then
            echo "      主源失败，回退备源（gyan.dev）..."
            if ! try_source "${FALLBACK_URL}"; then
                echo "[ERROR] 主源与备源均下载失败。" >&2
                exit 1
            fi
        else
            echo "[ERROR] 主源下载失败。可改用发行版包（见 BUILD_UBUNTU.md）或 --url。" >&2
            exit 1
        fi
    fi
fi

# ── 最终门禁 ──────────────────────────────────────────────
echo
echo "[3/3] 校验提取结果..."
count=0
missing=""
for item in "${REQUIRED_NAMES[@]}" "${REQUIRED_SO[@]}"; do
    if [ -s "${BIN_DIR}/${item}" ]; then
        count=$((count + 1))
    else
        missing="${missing} ${item}"
    fi
done
if [ "${count}" != "7" ]; then
    echo "[ERROR] 提取结果不完整：仅找到 ${count}/7。" >&2
    echo "       缺失:${missing}" >&2
    echo "       这通常意味着下载的构建为 FFmpeg 9.x（avcodec-63），与 KirinDesk" >&2
    echo "       偏移快照（avcodec major=62）不兼容——请使用默认 BtbN 8.1 源。" >&2
    exit 1
fi

echo
echo "============================================================"
echo "   Done! 7 个 FFmpeg 运行库已就绪："
echo "   ${BIN_DIR}"
echo "============================================================"
exit 0

