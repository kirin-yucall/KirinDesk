// ════════════════════════════════════════════════════════════════
// internal.h — libkirin_gpu 内部跨 .cpp 共享声明（非 ABI）
// ════════════════════════════════════════════════════════════════
//
// 仅在 libkirin_gpu 内部 #include；不对外暴露（与 kirin_gpu.h 区分）。
// 在 d3d11_context.cpp（Windows）/ linux_vaapi.cpp（Linux）/ mac_metal.cpp
// （macOS）中各自定义 KgContext 并通过本头共享内部接口。

#pragma once

#include "kirin_gpu.h"

#include <cstdint>
#include <mutex>

namespace kirin_gpu {

// 平台无关的 RLE 编码 / 解码（blit_rle.cpp 提供，供 Rust 侧测试也覆盖）。
//
// RLE 格式（简单字节游程）：
//   [repeat:u8][value:u8] * N
//   repeat == 0 表示该游程长度 256（最大打包单位），允许连续多组。
//
// 返回压缩后字节数（≤ src_len * 2，最坏 1 字节膨胀）。
uint32_t rle_encode(const uint8_t* src, uint32_t src_len,
                    uint8_t* dst, uint32_t dst_cap);

// RLE 解码：返回解压后字节数；dst 太小返回 0xFFFFFFFF。
uint32_t rle_decode(const uint8_t* src, uint32_t src_len,
                    uint8_t* dst, uint32_t dst_cap);

// 平台提供的 KgContext 内部访问器（d3d11_context.cpp / 平台桩实现）。
// Windows：返回真实 KgContext*；Linux/macOS：返回 nullptr（永远 not-implemented）。
struct KgContext;
KgContext* context_get();
std::mutex& context_mutex();

// hw_bridge 生命周期钩子（hw_bridge.cpp 提供；d3d11_context.cpp 的
// kgpu_shutdown 在持有 context_mutex 时调用；无 FFmpeg 头时为空实现）。
void hw_bridge_shutdown();

// 平台无关的 KgContext 描述（用于内部诊断；不强求每平台都填）。
struct KgContextInfo {
    uint32_t width;
    uint32_t height;
    uint32_t grid_w;
    uint32_t grid_h;
    bool     initialized;
};

} // namespace kirin_gpu
