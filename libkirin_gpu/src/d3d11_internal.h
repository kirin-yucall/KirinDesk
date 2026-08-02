// ════════════════════════════════════════════════════════════════
// d3d11_internal.h — libkirin_gpu Windows 内部共享（KgContext + helper）
// ════════════════════════════════════════════════════════════════
//
// 仅 Windows 平台、libkirin_gpu 内部使用。把 KgContext 完整结构定义于此，
// 供 d3d11_context.cpp / tile_hash.cpp / blit_rle.cpp 共享，避免在多个 .cpp
// 中重复定义导致布局漂移。
//
// 非 Windows 平台不包含本头（CMakeLists.txt 按平台编译对应 .cpp）。

#pragma once

#include "kirin_gpu.h"
#include "internal.h"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <d3d11.h>

namespace kirin_gpu {

constexpr uint32_t kTileW   = 64;
constexpr uint32_t kTileH   = 64;
constexpr uint32_t kGroupX  = 8;   // numthreads(8,8,1)
constexpr uint32_t kGroupY  = 8;

// ── KgContext：进程内常驻状态 ────────────────────────────────────
struct KgContext {
    ID3D11Device*           device   = nullptr;  // 自建或复用
    ID3D11DeviceContext*    ctx      = nullptr;
    bool                    owns_device = false;

    ID3D11ComputeShader*    hash_cs  = nullptr;   // Pass1
    ID3D11ComputeShader*    diff_cs  = nullptr;   // Pass2 (Diff + Decide)
    ID3D11ComputeShader*    blit_cs  = nullptr;   // Pass3 (dirty 索引聚合)

    ID3D11Buffer*           hash_buf_a = nullptr; // 当前帧 hash
    ID3D11Buffer*           hash_buf_b = nullptr; // 上一帧 hash
    ID3D11Buffer*           dirty_map  = nullptr; // dirty 位图 UAV
    ID3D11Buffer*           count_buf  = nullptr; // [0]=dirty 总数
    ID3D11Buffer*           indices_buf = nullptr; // dirty 索引
    ID3D11Buffer*           staging    = nullptr;  // 读回用

    ID3D11ShaderResourceView*  hash_srv_a = nullptr;
    ID3D11ShaderResourceView*  hash_srv_b = nullptr;
    ID3D11UnorderedAccessView* hash_uav_a = nullptr;
    ID3D11UnorderedAccessView* dirty_uav  = nullptr;
    ID3D11UnorderedAccessView* count_uav  = nullptr;
    ID3D11UnorderedAccessView* indices_uav  = nullptr;

    ID3D11Buffer*           consts    = nullptr;  // CB 常量

    // KgTileMap.dirty 的最近一次分配（C++ 侧分配 → 调用方只读）。
    // 下一帧 tile_hash 或 shutdown 时释放。RAII 保证无泄漏。
    uint8_t*                last_dirty = nullptr;
    uint32_t                last_dirty_cap = 0;

    uint32_t                width  = 0;
    uint32_t                height = 0;
    uint32_t                grid_w = 0;
    uint32_t                grid_h = 0;
    uint32_t                total  = 0;

    bool                    initialized = false;
};

// ── 共享 helper（d3d11_context.cpp 实现）────────────────────────
// 检测分辨率变化并按需重建 grid 缓冲（含 ping-pong b 初始化为 0）。
bool ensure_grid_for(KgContext* c, uint32_t w, uint32_t h);
// 清零计数 / 索引缓冲（每帧 Pass 前调用）。
void reset_counters(KgContext* c);
// 更新常量缓冲（grid_w/h, tile, total）。
void update_consts(KgContext* c, uint32_t grid_w, uint32_t grid_h,
                   uint32_t tile, uint32_t total);
// 分配 / 重分配 staging（读回用），返回是否成功。
bool alloc_staging(KgContext* c, uint32_t bytes);
// ping-pong：Pass2 完成后交换 hash_a / hash_b（下帧 diff 对象 = 本次 hash）。
void swap_hash_buffers(KgContext* c);
// 分配（或复用）KgTileMap.dirty 的 CPU 镜像缓冲；返回的指针在下次调用 / shutdown 失效。
uint8_t* alloc_dirty_mirror(KgContext* c, uint32_t bytes);

} // namespace kirin_gpu

#endif // _WIN32
