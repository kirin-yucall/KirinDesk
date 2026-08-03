// ════════════════════════════════════════════════════════════════
// d3d11_context.cpp — KgContext 生命周期 + D3D11 device/CS/双缓冲（P1B §T2.1）
// ════════════════════════════════════════════════════════════════
//
// 承载：
//   - KgContext 全局状态（device / context / 3 个 CS / hash 双缓冲 / staging）
//   - kgpu_init / kgpu_shutdown 幂等生命周期
//   - 分辨率变化：内部重建缓冲（不重建 device）
//   - device lost（DXGI_ERROR_DEVICE_REMOVED）→ KG_ERR_DEVICE
//
// 编译条件：本 .cpp 仅在 Windows 下参与构建（CMakeLists.txt 控制）；
// Linux/macOS 走对应平台桩（linux_vaapi.cpp / mac_metal.cpp），返回
// KG_ERR_NOTIMPL。

#include "kirin_gpu.h"
#include "internal.h"

#ifdef _WIN32

#include "d3d11_internal.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <d3d11.h>
#include <dxgi.h>
#include <d3dcompiler.h>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <new>

#include "tile_hash_hlsl.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")

namespace kirin_gpu {

// ── 进程内单例（未初始化时为 nullptr）────────────────────────────
static KgContext*           g_ctx  = nullptr;
static std::mutex           g_mtx;
// R-15b（2026-08-04，并行单测实测修复）：持有者引用计数。
// 幂等 init 的语义扩展：kgpu_init 每成功一次 +1，kgpu_shutdown 每调用
// 一次 -1，归零才释放。生产路径（init 一次 / shutdown 一次）行为不变；
// 多持有者（Rust 单测并行各持内核句柄、Drop 各自 shutdown）不再互相
// 杀死共享上下文（实测 0xc0000005：一个测试 Drop → shutdown 释放 device，
// 并行中其它测试仍在使用 → 悬垂）。
static int32_t              g_ctx_refs = 0;

KgContext* context_get()    { return g_ctx; }
std::mutex& context_mutex() { return g_mtx; }

// ── 辅助：COM 安全 Release ───────────────────────────────────────
template <typename T>
inline void safe_release(T*& p) {
    if (p) { p->Release(); p = nullptr; }
}

// ── 辅助：编译内嵌 HLSL → CS ────────────────────────────────────
static ID3D11ComputeShader* compile_cs(ID3D11Device* dev,
                                       const char* src,
                                       const char* entry,
                                       const char* target) {
    ID3DBlob* code = nullptr;
    ID3DBlob* errs = nullptr;
    UINT flags = D3DCOMPILE_OPTIMIZATION_LEVEL3;
    HRESULT hr = D3DCompile(src, strlen(src), nullptr, nullptr, nullptr,
                            entry, target, flags, 0, &code, &errs);
    if (errs) errs->Release();
    if (FAILED(hr)) {
        if (code) code->Release();
        return nullptr;
    }
    ID3D11ComputeShader* cs = nullptr;
    hr = dev->CreateComputeShader(code->GetBufferPointer(), code->GetBufferSize(),
                                  nullptr, &cs);
    code->Release();
    return cs;
}

// ── 辅助：创建结构化 buffer（带 stride）──────────────────────────
static ID3D11Buffer* create_structured(ID3D11Device* dev, uint32_t elem_bytes,
                                       uint32_t elem_count, UINT bind_flags) {
    D3D11_BUFFER_DESC d{};
    d.ByteWidth = elem_bytes * elem_count;
    d.Usage = D3D11_USAGE_DEFAULT;
    d.BindFlags = bind_flags;
    d.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
    d.StructureByteStride = elem_bytes;
    ID3D11Buffer* buf = nullptr;
    if (FAILED(dev->CreateBuffer(&d, nullptr, &buf))) return nullptr;
    return buf;
}

// ── 共享 helper：分配当前网格的所有缓冲 ───────────────────────────
static bool alloc_grid_buffers(KgContext* c) {
    safe_release(c->hash_buf_a);
    safe_release(c->hash_buf_b);
    safe_release(c->dirty_map);
    safe_release(c->count_buf);
    safe_release(c->indices_buf);
    safe_release(c->hash_srv_a);
    safe_release(c->hash_srv_b);
    safe_release(c->hash_uav_a);
    safe_release(c->dirty_uav);
    safe_release(c->count_uav);
    safe_release(c->indices_uav);

    c->total = c->grid_w * c->grid_h;
    if (c->total == 0) return false;

    // hash：uint4(16B)/tile，UAV + SRV（Pass1 写、Pass2 读）。
    UINT hash_bind = D3D11_BIND_UNORDERED_ACCESS | D3D11_BIND_SHADER_RESOURCE;
    c->hash_buf_a = create_structured(c->device, 16, c->total, hash_bind);
    // R-15b 修复（2026-08-04，首次 MSVC 实测）：hash_buf_b 也必须含
    // D3D11_BIND_UNORDERED_ACCESS——swap_hash_buffers 每帧把 UAV 重建到
    // 当前的 hash_buf_a（轮流指向前 buf_a / 前 buf_b）；原代码 buf_b 仅
    // SHADER_RESOURCE 绑定，轮到它时 CreateUnorderedAccessView 失败且
    // hr 被忽略 → UAV 为 null → Pass1 空写 → diff 恒全 dirty（FULLFRAME
    // 永不收敛，1080p 实测 dirty_ratio 恒 1.0）。
    c->hash_buf_b = create_structured(c->device, 16, c->total, hash_bind);
    if (!c->hash_buf_a || !c->hash_buf_b) return false;

    // dirty 位图：uint/tile（UAV + SRV 便于读回 / Pass3 聚合）。
    c->dirty_map = create_structured(c->device, 4, c->total, hash_bind);
    if (!c->dirty_map) return false;

    // count / indices：uint，UAV。
    c->count_buf   = create_structured(c->device, 4, 1, D3D11_BIND_UNORDERED_ACCESS);
    c->indices_buf = create_structured(c->device, 4, c->total, D3D11_BIND_UNORDERED_ACCESS);
    if (!c->count_buf || !c->indices_buf) return false;

    // UAV。
    {
        D3D11_UNORDERED_ACCESS_VIEW_DESC u{};
        u.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
        u.Format = DXGI_FORMAT_UNKNOWN;
        u.Buffer.FirstElement = 0;
        u.Buffer.NumElements = c->total;
        if (FAILED(c->device->CreateUnorderedAccessView(c->hash_buf_a, &u, &c->hash_uav_a))) return false;
        if (FAILED(c->device->CreateUnorderedAccessView(c->dirty_map, &u, &c->dirty_uav))) return false;
        if (FAILED(c->device->CreateUnorderedAccessView(c->indices_buf, &u, &c->indices_uav))) return false;
        u.Buffer.NumElements = 1;
        if (FAILED(c->device->CreateUnorderedAccessView(c->count_buf, &u, &c->count_uav))) return false;
    }
    // SRV。
    {
        D3D11_SHADER_RESOURCE_VIEW_DESC s{};
        s.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
        s.Format = DXGI_FORMAT_UNKNOWN;
        s.Buffer.FirstElement = 0;
        s.Buffer.NumElements = c->total;
        if (FAILED(c->device->CreateShaderResourceView(c->hash_buf_a, &s, &c->hash_srv_a))) return false;
        if (FAILED(c->device->CreateShaderResourceView(c->hash_buf_b, &s, &c->hash_srv_b))) return false;
    }

    // hash_buf_b 初始化为 0（首帧 diff 必为全 dirty）。
    static const uint32_t zero16[4] = {0, 0, 0, 0};
    for (uint32_t i = 0; i < c->total; ++i) {
        c->ctx->UpdateSubresource(c->hash_buf_b, 0, nullptr, zero16, 0, 0);
    }
    return true;
}

bool alloc_staging(KgContext* c, uint32_t bytes) {
    safe_release(c->staging);
    D3D11_BUFFER_DESC d{};
    d.ByteWidth = bytes;
    d.Usage = D3D11_USAGE_STAGING;
    d.BindFlags = 0;
    d.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    return SUCCEEDED(c->device->CreateBuffer(&d, nullptr, &c->staging));
}

bool ensure_grid_for(KgContext* c, uint32_t w, uint32_t h) {
    if (w == 0 || h == 0) return false;
    if (c->width == w && c->height == h && c->hash_buf_a) return true;
    c->width = w;
    c->height = h;
    c->grid_w = (w + kTileW - 1) / kTileW;
    c->grid_h = (h + kTileH - 1) / kTileH;
    return alloc_grid_buffers(c);
}

void reset_counters(KgContext* c) {
    static const uint32_t zero[1] = {0};
    c->ctx->UpdateSubresource(c->count_buf, 0, nullptr, zero, 0, 0);
    // 清首个索引槽（防止上一帧残留）。
    c->ctx->UpdateSubresource(c->indices_buf, 0, nullptr, zero, 4, 0);
}

void update_consts(KgContext* c, uint32_t grid_w, uint32_t grid_h,
                   uint32_t tile, uint32_t total) {
    if (!c->consts) {
        D3D11_BUFFER_DESC d{};
        d.ByteWidth = 16;
        d.Usage = D3D11_USAGE_DYNAMIC;
        d.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        d.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
        if (FAILED(c->device->CreateBuffer(&d, nullptr, &c->consts))) return;
    }
    D3D11_MAPPED_SUBRESOURCE m{};
    if (SUCCEEDED(c->ctx->Map(c->consts, 0, D3D11_MAP_WRITE_DISCARD, 0, &m))) {
        uint32_t* p = static_cast<uint32_t*>(m.pData);
        p[0] = grid_w; p[1] = grid_h; p[2] = tile; p[3] = total;
        c->ctx->Unmap(c->consts, 0);
    }
}

void swap_hash_buffers(KgContext* c) {
    std::swap(c->hash_buf_a, c->hash_buf_b);
    std::swap(c->hash_srv_a, c->hash_srv_b);
    // hash_uav_a 是 hash_buf_a 的 UAV；hash_buf_b 无 UAV（只读），交换后保持
    // hash_uav_a 与 hash_buf_a 绑定关系：交换 buf 后，下次 ensure 不会重建；
    // 因此 UAV 也需重建指向新 hash_buf_a。简化：重新生成 UAV。
    if (c->hash_uav_a) { c->hash_uav_a->Release(); c->hash_uav_a = nullptr; }
    D3D11_UNORDERED_ACCESS_VIEW_DESC u{};
    u.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
    u.Format = DXGI_FORMAT_UNKNOWN;
    u.Buffer.FirstElement = 0;
    u.Buffer.NumElements = c->total;
    c->device->CreateUnorderedAccessView(c->hash_buf_a, &u, &c->hash_uav_a);
}

// 分配（或复用）KgTileMap.dirty 的 CPU 镜像缓冲。
// 若容量不足则释放旧缓冲重新分配；上一帧返回的指针在下次调用时失效。
uint8_t* alloc_dirty_mirror(KgContext* c, uint32_t bytes) {
    if (c->last_dirty_cap < bytes) {
        if (c->last_dirty) { std::free(c->last_dirty); c->last_dirty = nullptr; }
        c->last_dirty = static_cast<uint8_t*>(std::malloc(bytes));
        c->last_dirty_cap = bytes;
    }
    return c->last_dirty;
}

// ════════════════════════════════════════════════════════════════
// C ABI：kgpu_init / kgpu_shutdown
// ════════════════════════════════════════════════════════════════

static int32_t kgpu_init_impl(void* device_handle) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_ctx) {
        // 幂等：已初始化则引用计数 +1（多持有者场景），保持首个 device。
        ++g_ctx_refs;
        return KG_OK;
    }

    KgContext* c = new (std::nothrow) KgContext();
    if (!c) return KG_ERR_INIT;

    HRESULT hr = S_OK;
    if (device_handle) {
        // device_handle 平台语义见 kirin_gpu.h：Windows = ID3D11Device*。
        // 复用调用方 device（windows-capture → 与编码器同 device，零拷贝直通）。
        auto dev = static_cast<ID3D11Device*>(device_handle);
        dev->AddRef();
        c->device = dev;
        c->owns_device = false;
    } else {
        D3D_FEATURE_LEVEL fl;
        UINT flags = 0;
        hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                               flags, nullptr, 0, D3D11_SDK_VERSION,
                               &c->device, &fl, &c->ctx);
        if (FAILED(hr)) { delete c; return KG_ERR_INIT; }
        c->owns_device = true;
    }

    if (!c->ctx) {
        // GetImmediateContext 返回 void（D3D11）；失败仅表现为 ctx 为空。
        c->device->GetImmediateContext(&c->ctx);
        if (!c->ctx) {
            if (c->owns_device) c->device->Release();
            delete c;
            return KG_ERR_INIT;
        }
    }

    // 编译 3 个 CS（内嵌 HLSL 字符串）。
    c->hash_cs = compile_cs(c->device, kHashCS, "HashCS", "cs_5_0");
    c->diff_cs = compile_cs(c->device, kDiffCS, "DiffCS", "cs_5_0");
    c->blit_cs = compile_cs(c->device, kBlitCS, "BlitCS", "cs_5_0");
    if (!c->hash_cs || !c->diff_cs || !c->blit_cs) {
        safe_release(c->hash_cs);
        safe_release(c->diff_cs);
        safe_release(c->blit_cs);
        safe_release(c->ctx);
        if (c->owns_device) c->device->Release();
        delete c;
        return KG_ERR_INIT;
    }

    c->initialized = true;
    g_ctx_refs = 1;
    g_ctx = c;
    return KG_OK;
}

static void kgpu_shutdown_impl(void) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!g_ctx) return;
    // R-15b：引用计数归零才真正释放（多持有者安全）。
    if (--g_ctx_refs > 0) return;
    KgContext* c = g_ctx;
    g_ctx = nullptr;

    // hw_bridge 先释放（其 AVHWDeviceContext 持有本 device 的引用，须在
    // device 释放前 unref；本函数已持 g_mtx，hw_bridge_shutdown 不加锁）。
    hw_bridge_shutdown();

    // 逆序释放：CS → 缓冲 → context → device。
    safe_release(c->hash_cs);
    safe_release(c->diff_cs);
    safe_release(c->blit_cs);
    safe_release(c->hash_uav_a);
    safe_release(c->hash_srv_a);
    safe_release(c->hash_srv_b);
    safe_release(c->dirty_uav);
    safe_release(c->count_uav);
    safe_release(c->indices_uav);
    safe_release(c->hash_buf_a);
    safe_release(c->hash_buf_b);
    safe_release(c->dirty_map);
    safe_release(c->count_buf);
    safe_release(c->indices_buf);
    safe_release(c->staging);
    safe_release(c->consts);
    if (c->last_dirty) { std::free(c->last_dirty); c->last_dirty = nullptr; }
    safe_release(c->ctx);
    if (c->owns_device) safe_release(c->device);
    delete c;
}

} // namespace kirin_gpu

extern "C" {

int32_t kgpu_init(void* device_handle) {
    return kirin_gpu::kgpu_init_impl(device_handle);
}

void* kgpu_device_handle(void) {
    std::lock_guard<std::mutex> lk(kirin_gpu::g_mtx);
    return kirin_gpu::g_ctx ? static_cast<void*>(kirin_gpu::g_ctx->device) : nullptr;
}

void kgpu_shutdown(void) {
    kirin_gpu::kgpu_shutdown_impl();
}

} // extern "C"

#endif // _WIN32
