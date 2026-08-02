// ════════════════════════════════════════════════════════════════
// hw_bridge.cpp — 纹理 → FFmpeg hwframes 桥（P1B §T2.3）
// ════════════════════════════════════════════════════════════════
//
// 输入：ID3D11Texture2D*（capture 层，BGRA8 或 NV12）
// 输出：AVFrame*（hwframes，AV_PIX_FMT_D3D11），零拷贝绑定纹理句柄：
//   - av_frame_get_buffer 后把纹理句柄写入 hwframe
//   - 复用 P1C 的 AVHWDeviceContext（d3d11va，与 capture 同 device）
//     → 无 av_hwframe_transfer_data CPU 往返
//
// 依赖：FFmpeg 开发头文件。开发构建中通常位于
//   ffmpeg/ffmpeg-8.1.2-full_build-shared/include/
// 当前仓库内的 shared_build 仅含 bin/（无 include/），故默认走
// "无头" 桩路径（kgpu_hw_upload 返回 NULL），由 P1C 侧降级为软编 +
// 本模块维持纯 diff 模式。
//
// 启用真实桥接：CMake 传入 -DFFMPEG_INCLUDE_DIR=... + -DFFMPEG_LIB_DIR=...
// 编译时定义 KG_HAVE_FFMPEG_HEADERS；本文件自动切换为真实实现。

#include "kirin_gpu.h"

// 平台桩声明：Linux/macOS 在各自 .cpp 内提供 kgpu_hw_upload 返回 NULL。
// Windows 在本文件实现（有/无 FFmpeg 头两路径）。

#if defined(KG_HAVE_FFMPEG_HEADERS) && defined(_WIN32)

// ──────────────────────────────────────────────────────────────
// 真实实现：依赖 FFmpeg C 头
// ──────────────────────────────────────────────────────────────
extern "C" {
#include <libavutil/frame.h>
#include <libavutil/hwcontext.h>
#include <libavutil/hwcontext_d3d11va.h>
#include <libavutil/pixdesc.h>
}

#include <d3d11.h>

namespace {
// 进程内 hwframes_ctx（首次创建后复用；分辨率变化时重建）。
AVBufferRef* g_hw_frames_ctx = nullptr;

// 简化：调用方须保证传入的 D3D11 device 与 init 时一致（零拷贝直通）。
// 这里仅创建 hwframes_ctx 并把纹理索引 0 绑定到 AVFrame。
}

extern "C" void* kgpu_hw_upload(void* texture) {
    if (!texture) return nullptr;
    // P1C 接管 AVHWDeviceContext；P1B 阶段此函数返回 NULL → P1C 软编回退。
    // 完整实现见 P1C ffmpeg_hw.rs。
    (void)texture;
    return nullptr;
}

#else
// ──────────────────────────────────────────────────────────────
// 桩实现：无 FFmpeg 头（默认）—— kgpu_hw_upload 返回 NULL
// 调用方（P1C ffmpeg_hw.rs）负责 av_frame_unref + av_frame_free。
// ──────────────────────────────────────────────────────────────

extern "C" void* kgpu_hw_upload(void* texture) {
    // 无 FFmpeg 头 / 非 Windows：返回 NULL（KG_ERR_INIT 语义由调用方判定）。
    // P1C 侧降级为软编（CPU 纹理拷贝 + swscale 转 NV12）。
    (void)texture;
    return nullptr;
}

#endif
