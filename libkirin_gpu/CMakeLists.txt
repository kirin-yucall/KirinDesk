# ════════════════════════════════════════════════════════════════
# libkirin_gpu — 静态库（P1B §T2.1）
# ════════════════════════════════════════════════════════════════
#
# GPU 侧零拷贝内核：Tile-Hash Diff compute shader、tile blit + RLE、
# 纹理 → FFmpeg hwframes 桥。
#
# 平台：
#   - Windows：D3D11 Compute 主实现（HLSL）
#   - Linux：  VAAPI 桩（KG_ERR_NOTIMPL，编译不阻断）
#   - macOS：  Metal 桩（KG_ERR_NOTIMPL，编译不阻断）
#
# FFmpeg 头（hw_bridge 真实实现）：可选。
#   传入 -DFFMPEG_INCLUDE_DIR=... 时启用 KG_HAVE_FFMPEG_HEADERS；
#   否则 hw_bridge.cpp 走桩（kgpu_hw_upload 返回 NULL），P1C 软编回退。
#
# 使用方：media/src/encoder/gpu_ffi/build.rs（cmake::Config）。
# CMake / VS 工具链缺失时由 build.rs 降级为 CPU-only（不构建本工程）。

cmake_minimum_required(VERSION 3.16)
project(libkirin_gpu LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 默认静态库（与 build.rs 的 rustc-link-lib=static 一致）。
add_library(kirin_gpu STATIC
    src/d3d11_context.cpp
    src/tile_hash.cpp
    src/blit_rle.cpp
    src/hw_bridge.cpp
)

target_include_directories(kirin_gpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ── 平台选择 ────────────────────────────────────────────────────
if(WIN32)
    target_compile_definitions(kirin_gpu PRIVATE KG_PLATFORM_WINDOWS=1)
    # 仅 Windows 包含 d3d11_context.cpp（Linux/macOS 走平台桩）。
    # d3d11_context.cpp / tile_hash.cpp / blit_rle.cpp 内部用 #ifdef _WIN32
    # 选择是否编译真实路径。
    target_link_libraries(kirin_gpu PRIVATE
        d3d11
        dxgi
        d3dcompiler
    )
else()
    # 非 Windows：把平台桩加入构建（保证 kgpu_* 符号导出完整）。
    if(APPLE)
        target_sources(kirin_gpu PRIVATE src/mac_metal.cpp)
    else()
        target_sources(kirin_gpu PRIVATE src/linux_vaapi.cpp)
    endif()
endif()

# ── FFmpeg 头（可选，hw_bridge 真实实现；R-15b 接入）──────────────
#   传入 -DFFMPEG_INCLUDE_DIR=<含 libavutil/ 的目录>（必须）；
#   -DFFMPEG_LIB_DIR=<含 avutil-60.def/avutil.lib 的目录>（可选，仅供
#   运行时定位 DLL 目录与校验；本工程**不静态链接** FFmpeg 导入库——
#   与架构红线一致，avutil-60.dll 由 hw_bridge.cpp 运行时动态加载）。
if(DEFINED FFMPEG_INCLUDE_DIR)
    target_include_directories(kirin_gpu PRIVATE ${FFMPEG_INCLUDE_DIR})
    target_compile_definitions(kirin_gpu PRIVATE KG_HAVE_FFMPEG_HEADERS=1)

    # 编译期烘焙 avutil-60.dll 候选目录（运行时加载顺序见 hw_bridge.cpp）：
    #   KIRIN_FFMPEG_BIN_DIR env > KG_FFMPEG_BIN_DIR（此处）> 裸名/应用目录。
    # include 与 lib 通常同级（.../bin 与 .../include 同父目录）。
    get_filename_component(_ffmpeg_parent "${FFMPEG_INCLUDE_DIR}" DIRECTORY)
    set(_ffmpeg_bin_candidates "${_ffmpeg_parent}/bin")
    if(DEFINED FFMPEG_LIB_DIR)
        get_filename_component(_lib_parent "${FFMPEG_LIB_DIR}" DIRECTORY)
        list(APPEND _ffmpeg_bin_candidates "${_lib_parent}/bin")
    endif()
    set(KG_FFMPEG_BIN_DIR "")
    foreach(_d ${_ffmpeg_bin_candidates})
        if(EXISTS "${_d}/avutil-60.dll")
            set(KG_FFMPEG_BIN_DIR "${_d}")
            break()
        endif()
    endforeach()
    if(KG_FFMPEG_BIN_DIR)
        # Windows 路径反斜杠转正斜杠（C 字符串转义安全；Win32 API 均接受）。
        string(REPLACE "\\" "/" _bin_slash "${KG_FFMPEG_BIN_DIR}")
        target_compile_definitions(kirin_gpu PRIVATE "KG_FFMPEG_BIN_DIR=\"${_bin_slash}\"")
        message(STATUS "libkirin_gpu: FFmpeg runtime DLL dir: ${KG_FFMPEG_BIN_DIR}")
    else()
        message(STATUS "libkirin_gpu: FFmpeg avutil-60.dll not found next to headers; runtime loader falls back to bare name/env")
    endif()

    message(STATUS "libkirin_gpu: FFmpeg headers enabled (${FFMPEG_INCLUDE_DIR})")
else()
    message(STATUS "libkirin_gpu: FFmpeg headers NOT provided -> hw_bridge stub (kgpu_hw_upload=NULL)")
endif()

# ── Windows MSVC：Unicode 宏（避免 min/max 冲突）────────────────
if(WIN32)
    target_compile_definitions(kirin_gpu PRIVATE NOMINMAX)
endif()

# ── MSVC：源文件统一 UTF-8（R-15b 首次 MSVC 实测修复）───────────
# 仓库源文件含中文注释与盒线字符（UTF-8 无 BOM）；MSVC 默认按系统
# 代码页（zh-CN 为 936/GBK）解析，多字节序列会导致注释/宏解析错位
# （C4819 告警 + C4430/C2059/C2377 级联报错，错误行号指向注释行）。
# /utf-8 同时声明源与执行字符集（与 Rust 侧 UTF-8 一致）。
# 注意：须用 target_compile_options（add_compile_options 晚于 add_library
# 时对已创建目标不生效）。
if(MSVC)
    target_compile_options(kirin_gpu PRIVATE /utf-8)
endif()
