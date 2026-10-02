// ════════════════════════════════════════════════════════════════
// tile_hash_hlsl.h — 内嵌 HLSL compute shader 源码（P1B §T2.2）
// ════════════════════════════════════════════════════════════════
//
// 三个 CS 的 HLSL 源以 C 字符串字面量内嵌，由 d3d11_context.cpp 在运行期
// 用 D3DCompile 编译为字节码（避免 build 期依赖 fxc / DXC）。
//
// Tile 网格：tile_w = tile_h = 64；每 Tile 由一个 workgroup (8×8 线程) 处理。
// 输入纹理：BGRA8（与 windows-capture 默认输出一致）。

#pragma once

#include <cstdint>

namespace kirin_gpu {

// ── Pass1：并行哈希（Workgroup = 1 Tile，8×8 线程）──────────────
// 每 Thread 处理 8×8 子块，4 采样点取均值，组内 shared memory 规约，
// 得每 tile 的 {sum_r, sum_g, sum_b, crc32}，写入 RWStructuredBuffer<uint4>。
// 输入：Texture2D src（BGRA8）
// 输出：RWStructuredBuffer<uint4> g_HashA（当前帧 hash，每 tile 一项）
inline constexpr const char* kHashCS = R"HLSL(
cbuffer Consts : register(b0) {
    uint g_grid_w;
    uint g_grid_h;
    uint g_tile;
    uint g_pad0;
};

Texture2D<unorm float4> src : register(t0);  // BGRA8
RWStructuredBuffer<uint4> g_HashA : register(u0);  // 每 tile 一项 (r,g,b,crc)

#define TILE 64
#define GROUP 8
#define THREAD_BLOCK (TILE / GROUP)  // 8 -> 每 thread 8x8 子块

groupshared uint s_r[64];
groupshared uint s_g[64];
groupshared uint s_b[64];

uint crc32_step(uint crc, uint b) {
    crc ^= b;
    for (int i = 0; i < 8; ++i)
        crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1u));
    return crc;
}

[numthreads(GROUP, GROUP, 1)]
void HashCS(uint3 tid : SV_DispatchThreadID, uint3 gid : SV_GroupID,
            uint gidx : SV_GroupIndex) {
    uint tile_x = gid.x;
    uint tile_y = gid.y;
    uint2 origin = uint2(tile_x * TILE, tile_y * TILE);
    uint2 lo = origin + uint2(tid.x * THREAD_BLOCK, tid.y * THREAD_BLOCK);

    // 4 采样点均值（每 thread 一个 8x8 子块的角点采样）。
    uint sr = 0, sg = 0, sb = 0;
    [unroll]
    for (int i = 0; i < 4; ++i) {
        uint2 p = lo + uint2((i & 1) * 4, (i >> 1) * 4);
        float4 c = src.Load(int3(p, 0));
        // BGRA8 unorm → 0..1，转 0..255。
        sr += uint(c.z * 255.0 + 0.5);  // R 在 BGRA 第 3 字节
        sg += uint(c.y * 255.0 + 0.5);
        sb += uint(c.x * 255.0 + 0.5);
    }
    sr >>= 2; sg >>= 2; sb >>= 2;  // 平均

    // 本 thread 的局部 CRC32（含子块均值）。
    uint crc = 0xFFFFFFFFu;
    crc = crc32_step(crc, sr);
    crc = crc32_step(crc, sg);
    crc = crc32_step(crc, sb);
    crc = ~crc;

    // shared mem 规约（求和 + CRC 折叠）。
    s_r[gidx] = sr;
    s_g[gidx] = sg;
    s_b[gidx] = sb;
    GroupMemoryBarrierWithGroupSync();

    // 第 0 个 thread 汇总本 tile。
    if (gidx == 0) {
        uint R = 0, G = 0, B = 0, C = 0xFFFFFFFFu;
        [unroll]
        for (uint k = 0; k < 64; ++k) {
            R += s_r[k];
            G += s_g[k];
            B += s_b[k];
            C = crc32_step(C, s_r[k]);
            C = crc32_step(C, s_g[k]);
            C = crc32_step(C, s_b[k]);
        }
        C = ~C;
        g_HashA[tile_y * g_grid_w + tile_x] = uint4(R, G, B, C);
    }
}
)HLSL";

// ── Pass2：GPU 内 Diff（与上一帧 hash 对比，统计 dirty 计数）─────
// 读 g_HashA（当前帧）与 g_HashB（上一帧）；任意分量差 > 阈值 → InterlockedAdd 计数。
// 计算 dirty_ratio，回写 g_Decision（0 静 / 1 微变 / 2 大动）。
// 1 个 workgroup (1,1,1) 做最终汇总：读 g_DirtyCount，决定 decision。
inline constexpr const char* kDiffCS = R"HLSL(
cbuffer Consts : register(b0) {
    uint g_grid_w;
    uint g_grid_h;
    uint g_tile;
    uint g_total;            // grid_w * grid_h
};

StructuredBuffer<uint4> g_HashA : register(t0);  // 当前帧
StructuredBuffer<uint4> g_HashB : register(t1);  // 上一帧
RWStructuredBuffer<uint> g_DirtyMap : register(u0);  // 每 tile 0/1
RWStructuredBuffer<uint> g_DirtyCount : register(u1); // [0]=dirty 总数
RWStructuredBuffer<uint> g_Decision : register(u2);   // [0]=decision

#define THRESH 6u   // 任一分量差 > THRESH 视为 dirty

[numthreads(64, 1, 1)]
void DiffCS(uint3 tid : SV_DispatchThreadID) {
    if (tid.x >= g_total) return;
    uint4 a = g_HashA[tid.x];
    uint4 b = g_HashB[tid.x];
    // |a - b| 任意分量 > THRESH → dirty。
    uint dr = a.x > b.x ? a.x - b.x : b.x - a.x;
    uint dg = a.y > b.y ? a.y - b.y : b.y - a.y;
    uint db = a.z > b.z ? a.z - b.z : b.z - a.z;
    uint dc = a.w ^ b.w;
    bool dirty = (dr > THRESH) || (dg > THRESH) || (db > THRESH) || (dc != 0u);
    g_DirtyMap[tid.x] = dirty ? 1u : 0u;
    if (dirty) InterlockedAdd(g_DirtyCount[0], 1u);
}

[numthreads(1, 1, 1)]
void DecideCS() {
    uint dirty_total = g_DirtyCount[0];
    if (dirty_total == 0u) {
        g_Decision[0] = 0u;  // Static
        return;
    }
    float ratio = (float)dirty_total / (float)max(g_total, 1u);
    // 微变阈值 5%；> 5% 视为大动。
    g_Decision[0] = ratio < 0.05f ? 1u : 2u;
}
)HLSL";

// ── Pass3：tile blit（微变分支：dirty tile 拷贝到 staging）──────
// 简化：本阶段用 CopySubresourceRegion 在 CPU 侧逐 tile 拷贝（d3d11_context.cpp），
// 本 CS 仅做 dirty 索引聚合（写连续 dirty tile 索引到 g_Indices）。
inline constexpr const char* kBlitCS = R"HLSL(
cbuffer Consts : register(b0) {
    uint g_grid_w;
    uint g_grid_h;
    uint g_tile;
    uint g_total;
};

StructuredBuffer<uint> g_DirtyMap : register(t0);
RWStructuredBuffer<uint> g_Indices : register(u0);  // 连续 dirty 索引
RWStructuredBuffer<uint> g_Count   : register(u1);   // [0]=数量

[numthreads(64, 1, 1)]
void BlitCS(uint3 tid : SV_DispatchThreadID) {
    if (tid.x >= g_total) return;
    if (g_DirtyMap[tid.x] != 0u) {
        uint slot;
        InterlockedAdd(g_Count[0], 1u, slot);
        g_Indices[slot] = tid.x;
    }
}
)HLSL";

} // namespace kirin_gpu
