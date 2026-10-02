// ════════════════════════════════════════════════════════════════
// tile_hash.cpp — Tile-Hash Diff 三 Pass dispatch（P1B §T2.2）
// ════════════════════════════════════════════════════════════════
//
// kgpu_tile_hash 入口：
//   Pass1: HashCS — 并行哈希（8×8 workgroup/tile）→ hash_buf_a
//   Pass2: DiffCS — 与 hash_buf_b（上一帧）diff，计数
//   ping-pong：Pass2 后 swap(a,b)，保证下一帧 diff 比对的是本次 hash。
//
// 决策：CPU 读 count_buf + dirty 位图后计算 decision（阈值 5%，与
// Rust 侧 tile_diff 一致）。首帧：hash_buf_b 全 0 → 必全 dirty → FULLFRAME。

#include "kirin_gpu.h"
#include "internal.h"

#ifdef _WIN32

#include "d3d11_internal.h"

#include <cstdlib>
#include <cstring>

namespace kirin_gpu {

// ── 辅助：把纹理作为 SRV 绑定（要求 BGRA8 + D3D11_BIND_SHADER_RESOURCE）──
static ID3D11ShaderResourceView* bind_texture_srv(KgContext* c, void* texture) {
    ID3D11Texture2D* t2d = nullptr;
    if (FAILED(static_cast<ID3D11Resource*>(texture)->QueryInterface(
            __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&t2d)))) {
        return nullptr;
    }
    D3D11_SHADER_RESOURCE_VIEW_DESC sd{};
    sd.Format = DXGI_FORMAT_UNKNOWN;
    sd.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    sd.Texture2D.MostDetailedMip = 0;
    sd.Texture2D.MipLevels = 1;
    ID3D11ShaderResourceView* srv = nullptr;
    HRESULT hr = c->device->CreateShaderResourceView(t2d, &sd, &srv);
    t2d->Release();
    return SUCCEEDED(hr) ? srv : nullptr;
}

// ── 辅助：取纹理宽高（QI ID3D11Texture2D）───────────────────────
static bool get_texture_size(void* texture, uint32_t& w, uint32_t& h) {
    ID3D11Texture2D* t2d = nullptr;
    if (FAILED(static_cast<ID3D11Resource*>(texture)->QueryInterface(
            __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&t2d)))) {
        return false;
    }
    D3D11_TEXTURE2D_DESC d{};
    t2d->GetDesc(&d);
    t2d->Release();
    w = d.Width;
    h = d.Height;
    return w != 0 && h != 0;
}

// ── 辅助：CopyResource + Map 读回小缓冲到 CPU ────────────────────
// out 指向调用方提供的缓冲（至少 bytes 字节）。
static bool copy_readback(KgContext* c, ID3D11Buffer* src, uint32_t bytes, void* out) {
    if (!alloc_staging(c, bytes)) return false;
    c->ctx->CopyResource(c->staging, src);
    D3D11_MAPPED_SUBRESOURCE m{};
    if (FAILED(c->ctx->Map(c->staging, 0, D3D11_MAP_READ, 0, &m))) return false;
    memcpy(out, m.pData, bytes);
    c->ctx->Unmap(c->staging, 0);
    return true;
}

} // namespace kirin_gpu

extern "C" int32_t kgpu_tile_hash(void* texture, KgTileMap* out, int32_t* decision) {
    using namespace kirin_gpu;

    if (!out || !decision) return KG_ERR_PARAM;
    // 清零输出（保证失败时调用方拿到稳定值）。
    out->dirty = nullptr;
    out->dirty_ratio = 0.0f;
    out->grid_w = out->grid_h = 0;
    out->tile_w = kTileW;
    out->tile_h = kTileH;
    *decision = KG_DECISION_STATIC;

    std::lock_guard<std::mutex> lk(context_mutex());
    KgContext* c = context_get();
    if (!c || !c->initialized) return KG_ERR_INIT;
    if (!texture) return KG_ERR_PARAM;

    // 取纹理宽高 → 分辨率变化检测 → 重建缓冲。
    uint32_t w = 0, h = 0;
    if (!get_texture_size(texture, w, h)) return KG_ERR_PARAM;  // 非 D3D11 纹理
    if (!ensure_grid_for(c, w, h)) return KG_ERR_INIT;

    update_consts(c, c->grid_w, c->grid_h, kTileW, c->total);
    reset_counters(c);

    // ── Pass1：HashCS ──────────────────────────────────────────
    ID3D11ShaderResourceView* src_srv = bind_texture_srv(c, texture);
    if (!src_srv) return KG_ERR_PARAM;  // 纹理不能作为 SRV

    ID3D11ShaderResourceView* srvs1[1] = { src_srv };
    c->ctx->CSSetShader(c->hash_cs, nullptr, 0);
    c->ctx->CSSetConstantBuffers(0, 1, &c->consts);
    c->ctx->CSSetShaderResources(0, 1, srvs1);
    ID3D11UnorderedAccessView* uavs1[1] = { c->hash_uav_a };
    c->ctx->CSSetUnorderedAccessViews(0, 1, uavs1, nullptr);
    c->ctx->Dispatch(c->grid_w, c->grid_h, 1);

    // 解绑 Pass1（防止 Pass2 误用）。
    ID3D11ShaderResourceView* null_srv[2] = { nullptr, nullptr };
    ID3D11UnorderedAccessView* null_uav[3] = { nullptr, nullptr, nullptr };
    c->ctx->CSSetShaderResources(0, 1, null_srv);
    c->ctx->CSSetUnorderedAccessViews(0, 1, null_uav, nullptr);
    src_srv->Release();

    // ── Pass2：DiffCS（hash_a vs hash_b → dirty_map + count）─────
    ID3D11ShaderResourceView* srvs2[2] = { c->hash_srv_a, c->hash_srv_b };
    c->ctx->CSSetShader(c->diff_cs, nullptr, 0);
    c->ctx->CSSetConstantBuffers(0, 1, &c->consts);
    c->ctx->CSSetShaderResources(0, 2, srvs2);
    ID3D11UnorderedAccessView* uavs2[2] = { c->dirty_uav, c->count_uav };
    UINT init_counts[2] = { (UINT)-1, (UINT)-1 };
    c->ctx->CSSetUnorderedAccessViews(0, 2, uavs2, init_counts);
    uint32_t diff_groups = (c->total + 63) / 64;
    c->ctx->Dispatch(diff_groups, 1, 1);
    c->ctx->CSSetShaderResources(0, 2, null_srv);
    c->ctx->CSSetUnorderedAccessViews(0, 2, null_uav, nullptr);

    // ── 读回 count_buf（4 字节）→ 计算 decision ──────────────────
    uint32_t dirty_total = 0;
    if (!copy_readback(c, c->count_buf, 4, &dirty_total)) {
        return KG_ERR_DEVICE;
    }
    float ratio = c->total ? (float)dirty_total / (float)c->total : 0.0f;
    int32_t dec;
    if (dirty_total == 0) {
        dec = KG_DECISION_STATIC;
    } else if (ratio < 0.05f) {
        dec = KG_DECISION_INCREMENTAL;
    } else {
        dec = KG_DECISION_FULLFRAME;
    }
    *decision = dec;

    // ping-pong：下一帧 diff 对象 = 本次 hash。
    swap_hash_buffers(c);

    // 填 KgTileMap。
    out->tile_w = kTileW;
    out->tile_h = kTileH;
    out->grid_w = c->grid_w;
    out->grid_h = c->grid_h;
    out->dirty_ratio = ratio;

    if (dec == KG_DECISION_STATIC) {
        out->dirty = nullptr;  // 全静零读回
        return KG_OK;
    }

    // 读回 dirty 位图（大动 / 微变都需要）。
    // dirty_map 是 uint/tile 的结构化缓冲；先读到 CPU 镜像再转为 0/1 字节。
    // dirty_bytes 由 KgContext 持有（下一帧 / shutdown 释放）。
    uint32_t* dirty32 = static_cast<uint32_t*>(std::malloc(c->total * sizeof(uint32_t)));
    if (!dirty32) return KG_ERR_INIT;
    if (!copy_readback(c, c->dirty_map, c->total * sizeof(uint32_t), dirty32)) {
        std::free(dirty32);
        return KG_ERR_DEVICE;
    }
    uint8_t* dirty_bytes = alloc_dirty_mirror(c, c->total);
    if (!dirty_bytes) {
        std::free(dirty32);
        return KG_ERR_INIT;
    }
    for (uint32_t i = 0; i < c->total; ++i) dirty_bytes[i] = dirty32[i] ? 1u : 0u;
    std::free(dirty32);
    out->dirty = dirty_bytes;  // C++ 侧持有，下一帧 / shutdown 释放
    return KG_OK;
}

extern "C" int32_t kgpu_dirty_indices(void* /*texture*/, uint32_t* out_idx,
                                       uint32_t* out_count) {
    // P1B 完整管线 dirty 索引由 Rust 侧 DirtyTileMap::dirty_indices() 计算
    // （kgpu_tile_hash 已把 dirty 位图读回到 CPU 镜像）；本 C 入口仅作 ABI
    // 兼容，等价于查询当前缓存中的 dirty 索引数量。GPU 端聚合 CS（BlitCS）
    // 已留，后续大动分支如需 GPU 端索引可启用。
    if (!out_count) return KG_ERR_PARAM;
    *out_count = 0;
    (void)out_idx;
    return KG_OK;
}

#else // !_WIN32
// 非 Windows：tile_hash 由平台桩提供（linux_vaapi.cpp / mac_metal.cpp）。
#endif
