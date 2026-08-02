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

# ── FFmpeg 头（可选，hw_bridge 真实实现）────────────────────────
if(DEFINED FFMPEG_INCLUDE_DIR)
    target_include_directories(kirin_gpu PRIVATE ${FFMPEG_INCLUDE_DIR})
    target_compile_definitions(kirin_gpu PRIVATE KG_HAVE_FFMPEG_HEADERS=1)
    message(STATUS "libkirin_gpu: FFmpeg headers enabled (${FFMPEG_INCLUDE_DIR})")
else()
    message(STATUS "libkirin_gpu: FFmpeg headers NOT provided -> hw_bridge stub (kgpu_hw_upload=NULL)")
endif()

# ── Windows MSVC：Unicode 宏（避免 min/max 冲突）────────────────
if(WIN32)
    target_compile_definitions(kirin_gpu PRIVATE NOMINMAX)
endif()
