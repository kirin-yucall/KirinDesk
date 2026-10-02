#!/usr/bin/env bash
# ============================================================================
#
# 产物：libavcodec.so / libavutil.so / libswscale.so（8.1.1 → avcodec 62，
#       与桌面端动态加载口径一致；Android 惯例 soname 无版本后缀）。
#
#   - 解码：LGPL 内置软解（H.264/HEVC + P1-B 音频 opus/pcm_s16le）+ swscale
#     （均为 FFmpeg 内置 C 解码器，无需外部库）；
#     包装（`--enable-libx264 --enable-gpl`），x264 本体经 NDK 工具链交叉
#     编译为**静态库**链入 libavcodec.so（不新增第 4 个 .so，三件套口径
#     不变，libavcodec 体积增大）；
#   - 合规口径：**GPL 动态链接**——应用（Kotlin）不直接链接 GPL 代码，
#     经 `System.loadLibrary` 动态加载 libavcodec.so（.so 随 APK 的
#     jniLibs 分发），开源协议文件随仓库 mobile/ffmpeg-android/licenses/
#     （x264-COPYING，GPLv2+）+ 本脚本头注释说明。
# 工具链：Android NDK r27+/r28 clang（`--target-os=android --arch=aarch64`）。
# 对齐：16KB 页对齐（`-Wl,-z,max-page-size=16384`，Android 15+ 政策）。
#
# 运行环境（二选一，自动检测）：
#   1) Linux / WSL 原生：需要 make + NDK（$ANDROID_NDK_HOME 或 --ndk）。
#   2) Windows Git Bash：自动落入 Docker（debian）容器内执行本脚本同一逻辑，
#      Linux NDK / FFmpeg / x264 缓存在 mobile/ffmpeg-android/.cache/
#      （NDK 首次约 700MB；勿删 .cache）。
#
# 用法：
#   ./build.sh [--ndk /path/to/ndk] [--api 26] [--force-x264]
# 产物输出：prebuilt/arm64-v8a/*.so + prebuilt/arm64-v8a.sha256
# 验证证据（构建日志 + verify 段）：
#   - make install 前 llvm-nm 未 strip 产物（构建树 libavcodec/libavcodec.so）：
#     x264 符号面（x264_encoder_open 等）+ config.h CONFIG_LIBX264==1
#   - 最终 .so（已 strip）：strings 取证——编码器名 "libx264"（描述表）
#     + x264 本体 SEI 串 "H.264/MPEG-4 AVC codec"（只可能来自 x264 代码）
#   - readelf -d SONAME 复核（无版本后缀）
# ============================================================================
set -euo pipefail

FFMPEG_VERSION=8.1.1
# x264 版本 = videolan/x264 **stable 分支 HEAD**（x264 不发布带版本号的
# 源码包，stable 分支即最新稳定线；FFmpeg 8.1.1 的 libx264 包装对 x264
# 16x API 稳定兼容）。GitLab archive 端点取快照 tarball（容器无需 git clone）。
X264_REF=stable
X264_URL="https://code.videolan.org/videolan/x264/-/archive/$X264_REF/x264-$X264_REF.tar.gz"
X264_SRC_NAME="x264-$X264_REF"

API=26                       # minSdk 26（研究文档第 3 节版本矩阵）
NDK_VERSION_R=28c            # 下载的 Linux NDK 发行版版本（Docker 路径用）
HOST_TAG_LINUX=linux-x86_64
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="$SCRIPT_DIR/.cache"
SRC_DIR="$CACHE_DIR/src/ffmpeg-$FFMPEG_VERSION"
X264_SRC_DIR="$CACHE_DIR/src/$X264_SRC_NAME"
X264_PREFIX="$CACHE_DIR/x264-prefix"     # x264 静态库安装前缀（缓存，不入库）
OUT_DIR="$SCRIPT_DIR/prebuilt/arm64-v8a"
LICENSES_DIR="$SCRIPT_DIR/licenses"
JOBS="${JOBS:-8}"
FORCE_X264=0

# FFmpeg 源码镜像：官方源（华为云镜像 2026-08 实测返回 HTML 占位页，已弃用）
FFMPEG_URLS=(
  "https://ffmpeg.org/releases/ffmpeg-$FFMPEG_VERSION.tar.xz"
)
NDK_URLS=(
  "https://dl.google.com/android/repository/android-ndk-r$NDK_VERSION_R-linux.zip"
)

log() { echo "[build.sh] $*"; }
die() { echo "[build.sh][FATAL] $*" >&2; exit 1; }

# 原始参数先快照：下方 while 会 shift 消费光 $@，而 Windows→Docker 分支
# 必须把**同一组参数**转发进容器内二次执行（否则 --force-x264 静默丢失
# → 缓存的非 PIC 旧 x264.a 被复用，pkg-config 交叉链接测试必挂——实测踩坑）。
ORIGINAL_ARGS=("$@")
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ndk) NDK_ROOT_OVERRIDE="$2"; shift 2 ;;
    --api) API="$2"; shift 2 ;;
    --force-x264) FORCE_X264=1; shift ;;
    *) die "未知参数: $1" ;;
  esac
done

fetch() { # fetch <dest-file> <url...>（dest 已存在且非空则跳过）
  local dest="$1"; shift
  [[ -s "$dest" ]] && return 0
  local url
  for url in "$@"; do
    log "下载 $url"
    if curl -fSL --retry 3 -o "$dest.part" "$url"; then mv "$dest.part" "$dest"; return 0; fi
  done
  die "全部镜像下载失败: $*"
}

download_src() {
  mkdir -p "$CACHE_DIR/src"
  if [[ ! -d "$SRC_DIR" ]]; then
    fetch "$CACHE_DIR/src/ffmpeg-$FFMPEG_VERSION.tar.xz" "${FFMPEG_URLS[@]}"
    tar -xJf "$CACHE_DIR/src/ffmpeg-$FFMPEG_VERSION.tar.xz" -C "$CACHE_DIR/src"
  fi
  if [[ ! -d "$X264_SRC_DIR" ]]; then
    fetch "$CACHE_DIR/src/x264-$X264_REF.tar.gz" "$X264_URL"
    tar -xzf "$CACHE_DIR/src/x264-$X264_REF.tar.gz" -C "$CACHE_DIR/src"
  fi
}

resolve_ndk() { # 设置 NDK_ROOT
  if [[ -n "${NDK_ROOT_OVERRIDE:-}" && -d "$NDK_ROOT_OVERRIDE" ]]; then NDK_ROOT="$NDK_ROOT_OVERRIDE"; return; fi
  if [[ -n "${ANDROID_NDK_HOME:-}" && -d "$ANDROID_NDK_HOME" ]]; then NDK_ROOT="$ANDROID_NDK_HOME"; return; fi
  local cand
  for cand in "$CACHE_DIR/ndk/android-ndk-r$NDK_VERSION_R" \
              "/d/Android/Sdk/ndk/28.2.13676358"; do
    [[ -d "$cand" ]] && { NDK_ROOT="$cand"; return; }
  done
  # 本机不存在可用 NDK（Windows 上的 Git Bash 无原生 make，也走不了 Windows NDK
  # 的 shell 构建）→ 下载 Linux NDK 到缓存（容器内可执行）。
  mkdir -p "$CACHE_DIR/ndk"
  fetch "$CACHE_DIR/ndk/android-ndk-r$NDK_VERSION_R-linux.zip" "${NDK_URLS[@]}"
  unzip -q -o "$CACHE_DIR/ndk/android-ndk-r$NDK_VERSION_R-linux.zip" -d "$CACHE_DIR/ndk"
  NDK_ROOT="$CACHE_DIR/ndk/android-ndk-r$NDK_VERSION_R"
}

#
# - x264 的 configure 是自家 shell 脚本（非 autotools）：**不支持 `--cc=` /
#   `--as=` / `--disable-shared`**（传入会被忽略并继续用默认 cc → 容器内
#   "No working C compiler found" 假阴性）；交叉编译器经 **CC 环境变量**
#   传入（可含 `--target=` 标志，configure 自检编译与 make 均用它）；
# - aarch64 上 x264 有手写 .S 汇编（cabac/mc/pixel…），其 `movrel` 宏按
#   `PIC` 宏切换寻址：未定义 PIC → `ldr reg,=sym`（R_AARCH64_ABS64 绝对
#   重定位，链入 .so 必报 "recompile with -fPIC"）；定义 PIC → ADRP+ADD。
#   x264 只在 `--enable-shared` 或显式 **`--enable-pic`** 时才给
#   ASFLAGS 加 `-DPIC`（静态构建默认 pic=no——实测踩坑，FFmpeg
#   require_pkg_config 交叉链接测试因此失败），故显式传 --enable-pic；
# - `-fPIC`（extra-cflags）：C 对象位置无关（--enable-pic 亦会加，双保险）；
# - `--disable-cli`：不产 x264 可执行（被控端只需编码器）；
# - `--disable-opencl`：Android 无 OCL 生态，禁掉防探测；
# - `--disable-swscale --disable-lavf`：x264 自用测试设施（预览/读流），
#   与 FFmpeg 集成无关，禁掉免探测系统库。
build_x264() {
  local TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/$HOST_TAG_LINUX"
  [[ -d "$TOOLCHAIN" ]] || TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/windows-x86_64"
  local CC_BIN="$TOOLCHAIN/bin/clang"
  [[ -x "$CC_BIN" ]] || CC_BIN="$TOOLCHAIN/bin/clang.exe"

  if [[ -f "$X264_PREFIX/lib/libx264.a" && "$FORCE_X264" -eq 0 ]]; then
    log "x264 静态库已缓存（$X264_PREFIX/lib/libx264.a；--force-x264 可强制重编）"
    return 0
  fi
  rm -rf "$X264_PREFIX"
  log "x264（$X264_REF）交叉编译开始"
  (
    cd "$X264_SRC_DIR"
    # 交叉编译器经 CC 环境变量传入（--target 内嵌）；AR/RANLIB 用 NDK
    # llvm 工具（静态库归档格式一致）。
    CC="$CC_BIN --target=aarch64-linux-android$API" \
    AR="$TOOLCHAIN/bin/llvm-ar" \
    RANLIB="$TOOLCHAIN/bin/llvm-ranlib" \
    ./configure \
      --host="aarch64-linux-android" \
      --enable-static --enable-pic \
      --disable-cli --disable-opencl \
      --disable-swscale --disable-lavf \
      --extra-cflags="-Os -fPIC" \
      --prefix="$X264_PREFIX"
    AR="$TOOLCHAIN/bin/llvm-ar" RANLIB="$TOOLCHAIN/bin/llvm-ranlib" make -j"$JOBS"
    make install
  )
  [[ -f "$X264_PREFIX/lib/libx264.a" ]] || die "x264 静态库未产出"
  log "x264 静态库完成：$X264_PREFIX/lib/libx264.a"
}

build_ffmpeg() {
  local TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/$HOST_TAG_LINUX"
  [[ -d "$TOOLCHAIN" ]] || TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/windows-x86_64"
  [[ -d "$TOOLCHAIN" ]] || die "NDK toolchain 目录不存在: $NDK_ROOT"
  local CC="$TOOLCHAIN/bin/clang"
  [[ -x "$CC" ]] || CC="$TOOLCHAIN/bin/clang.exe"

  cd "$SRC_DIR"
  rm -f ffbuild/config.mak # 强制重新 configure（幂等）

  # Android soname 口径：FFmpeg configure 对 target-os=android 默认生成
  # 无版本后缀的 SLIBNAME（libNAME.so）且 SONAME 同名——构建后用 readelf 复核。
  #
  # 为 FFmpeg GPL 组件。x264 依赖发现走 **pkg-config**（FFmpeg 8.1 configure
  # 对 libx264 是 `require_pkg_config`：`--pkg-config=false` 下该检查必失败
  # → 编码器被软禁 `WARNING: Disabled libx264_encoder`、CONFIG_LIBX264=0、
  # x264 代码不链入——实测踩坑，勿改回）：PKG_CONFIG_PATH 指向上方 x264
  # `make install` 产出的 x264.pc（$X264_PREFIX/lib/pkgconfig）。extra-cflags/
  # ldflags 里的 -I/-L/-lx264 保留为冗余保险（最终链接兜底）。
  export PKG_CONFIG_PATH="$X264_PREFIX/lib/pkgconfig"
  ./configure \
    --target-os=android --arch=aarch64 \
    --enable-cross-compile --disable-autodetect \
    --cc="$CC" \
    --ar="$TOOLCHAIN/bin/llvm-ar" \
    --nm="$TOOLCHAIN/bin/llvm-nm" \
    --ranlib="$TOOLCHAIN/bin/llvm-ranlib" \
    --strip="$TOOLCHAIN/bin/llvm-strip" \
    --sysroot="$TOOLCHAIN/sysroot" \
    --extra-cflags="--target=aarch64-linux-android$API -Os -fPIC -I$X264_PREFIX/include" \
    --extra-ldflags="--target=aarch64-linux-android$API -Wl,-z,max-page-size=16384 -L$X264_PREFIX/lib -lx264" \
    --enable-shared --disable-static \
    --disable-everything \
    --enable-gpl \
    --enable-libx264 \
    --enable-decoder=h264,hevc,opus,pcm_s16le \
    --enable-encoder=libx264 \
    --enable-swscale \
    --disable-programs --disable-doc --disable-network --disable-iconv --disable-zlib \
    --disable-avdevice --disable-avformat --disable-avfilter --disable-swresample \
    --libdir="$OUT_DIR" --shlibdir="$OUT_DIR"

  make -j"$JOBS"

  # 注意：FFmpeg 8.x 构建树里 .so 落在 per-library 子目录（libavcodec/
  # libavcodec.so → libavcodec.so.62 符号链接），不在树根。
  log "libx264 验证（install 前 llvm-nm 未 strip libavcodec.so）："
  local pre_so="$SRC_DIR/libavcodec/libavcodec.so"
  [[ -e "$pre_so" ]] || die "未找到构建产物 $pre_so"
  # 注意：管道内 grep **不用 -m**（-m 提前退出 → 上游 SIGPIPE(141) →
  # pipefail 下整条管道判败 → 误 die；实测踩坑，2026-08-30 构建 8）。
  # 模式限定 x264 编码器 API 符号（内部 macroblock 函数面太大不列）。
  "$TOOLCHAIN/bin/llvm-nm" -C "$pre_so" 2>/dev/null \
    | grep -E " x264_encoder_(open|encode|close)" \
    | sed 's/^/[build.sh]   nm /' \
    || die "libavcodec.so 未见 x264 符号——libx264 未链入（检查 PKG_CONFIG_PATH/x264.pc）"
  grep -q "#define CONFIG_LIBX264 1" config.h \
    || die "config.h CONFIG_LIBX264 非 1——编码器未真正启用"

  install_license() {
    local src="$X264_SRC_DIR/COPYING"
    [[ -f "$src" ]] || { log "x264 COPYING 缺失（源树未含？），跳过 licenses 同步"; return 0; }
    mkdir -p "$LICENSES_DIR"
    cp -f "$src" "$LICENSES_DIR/x264-COPYING"
    log "协议文件同步：licenses/x264-COPYING（GPLv2+，x264 本体）"
  }
  install_license

  rm -rf "$OUT_DIR"
  make install
}

verify() {
  local TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/$HOST_TAG_LINUX"
  [[ -d "$TOOLCHAIN" ]] || TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/windows-x86_64"
  cd "$OUT_DIR"
  local so
  for so in libavcodec.so libavutil.so libswscale.so; do
    [[ -f "$so" ]] || die "缺少产物 $so"
  done
  # sha256 清单（入库；产物本体是否入库由 PM 裁定）
  ( cd "$OUT_DIR" && sha256sum libavcodec.so libavutil.so libswscale.so \
      > "$SCRIPT_DIR/prebuilt/arm64-v8a.sha256" )
  # soname 复核（Android 无版本后缀口径；16KB 页对齐为链接参数，readelf
  # 段对齐可由 PM 复核脚本抽查，此处不阻断）。
  local soname
  soname=$(readelf -d libavcodec.so | sed -n 's/.*Library soname: \[\(.*\)\].*/\1/p')
  [[ "$soname" == "libavcodec.so" ]] || die "libavcodec.so SONAME 异常: '$soname'（期望 libavcodec.so）"
  # 说明：x264 静态链入后符号不导出（FFmpeg libavcodec.ver 只导出 av_*，
  # llvm-nm -D 查不到 x264_* 属预期）；strip 后 .symtab 也没了，故最终
  # 产物用 strings 取证：
  #   a) "libx264" = FFmpeg 编码器描述表 .name（avcodec_find_encoder 按名
  #      查找用）——编码器注册表在 .so 内；
  #   b) "H.264/MPEG-4 AVC codec" = x264 encoder/set.c 的 SEI 负载串
  #      （FFmpeg 源码无此串，只可能来自 x264 代码本体）——x264 代码链入。
  log "libx264 验证（最终产物 strings 取证）："
  # 同上：管道内 grep 不用 -m（SIGPIPE×pipefail 误判）。
  strings libavcodec.so | grep -E "^libx264$|x264_encoder" | sed 's/^/[build.sh]   str /' \
    || strings libavcodec.so | grep -F "libx264" | sed 's/^/[build.sh]   str /' \
    || die "最终 libavcodec.so 未见 libx264 编码器名"
  strings libavcodec.so | grep -F "H.264/MPEG-4 AVC codec" \
    | sed 's/^/[build.sh]   str /' \
    || die "最终 libavcodec.so 未见 x264 SEI 串——x264 代码本体未链入"
  log "产物："
  ls -l "$OUT_DIR"
  log "sha256 清单：prebuilt/arm64-v8a.sha256"
}

# ---------- 入口 ----------
case "$(uname -s)" in
  Linux*)
    command -v make >/dev/null || die "缺少 make（apt install make）"
    download_src
    resolve_ndk
    log "NDK: $NDK_ROOT"
    build_x264
    build_ffmpeg
    verify
    ;;
  MINGW*|MSYS*|CYGWIN*)
    # Windows Git Bash：借 Docker（debian）执行同一脚本（Linux 分支）。
    command -v docker >/dev/null || die "Git Bash 下需要 Docker（或改用 WSL 运行本脚本）"
    docker version >/dev/null 2>&1 || die "Docker 引擎未运行"
    log "Git Bash 检测 → Docker 容器内构建（缓存挂载 $CACHE_DIR）"
    mkdir -p "$CACHE_DIR"
    WIN_SCRIPT=$(cd "$SCRIPT_DIR" && pwd -W 2>/dev/null || echo "$SCRIPT_DIR")
    # 部分网络（本机 2026-08 实测）过滤到 deb.debian.org 的 80 端口明文
    # HTTP → 容器 apt-get update 必挂（debconf 后 "Unable to locate
    # package make"）。HTTPS 同主机可达。debian:bookworm-slim 无
    # ca-certificates（鸡生蛋：装 ca-certificates 本身就要 apt），解法：
    # 把宿主机 Git for Windows 自带 CA 包挂载进容器放到 apt 的标准路径，
    # 并把 deb822 源（sources.list.d/debian.sources）http:// 改 https://。
    # 宿主机找不到 CA 包时保持旧行为（http 源，适合 80 端口可达的网络）。
    # 同机 TLS 还有**逐连接随机中断**（实测：同 host:port 主仓库 InRelease
    # 成功而 security InRelease "non-properly terminated"，重试即过）——
    # 容器 apt 全局 `Acquire::Retries 5` 兜底（apt.conf.d/99r69b-retries）。
    CA_SRC=""
    for ca_cand in "/c/Program Files/Git/usr/ssl/certs/ca-bundle.crt" \
                   "/c/Program Files/Git/mingw64/etc/ca-bundle.crt" \
                   "$(dirname "$(command -v bash)")/../usr/ssl/certs/ca-bundle.crt"; do
      [[ -f "$ca_cand" ]] && { CA_SRC="$ca_cand"; break; }
    done
    CA_MOUNT=()
    if [[ -n "$CA_SRC" ]]; then
      CA_MOUNT=(-v "$(cygpath -w "$CA_SRC"):/tmp/host-ca-bundle.crt:ro")
      log "apt https 化：挂载宿主机 CA 包 $CA_SRC"
    fi
    # MSYS_NO_PATHCONV=1：阻止 Git Bash 把容器内路径 /work 改写成 Windows 路径。
    # 原始参数经 `bash -c '...' _ "${ORIGINAL_ARGS[@]}"` 转发进容器（见上方
    # 快照注释：while 解析已消费光 $@，必须用 ORIGINAL_ARGS）。
    MSYS_NO_PATHCONV=1 docker run --rm \
      "${CA_MOUNT[@]}" \
      -v "$WIN_SCRIPT":/work \
      -e JOBS="$JOBS" \
      -w /work \
      debian:bookworm-slim \
      bash -c 'if [[ -f /tmp/host-ca-bundle.crt ]]; then mkdir -p /etc/ssl/certs && install -m 644 /tmp/host-ca-bundle.crt /etc/ssl/certs/ca-certificates.crt && sed -i "s|http://|https://|g" /etc/apt/sources.list.d/debian.sources; fi && echo "Acquire::Retries \"5\";" > /etc/apt/apt.conf.d/99r69b-retries && apt-get update -qq && apt-get install -y -qq --no-install-recommends make git gcc binutils libc6-dev curl xz-utils unzip ca-certificates perl pkg-config >/dev/null && chmod +x build.sh && ./build.sh "$@"' _ "${ORIGINAL_ARGS[@]}"
    ;;
  *)
    die "不支持的平台: $(uname -s)"
    ;;
esac
