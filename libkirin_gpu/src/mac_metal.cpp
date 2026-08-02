// ════════════════════════════════════════════════════════════════
// mac_metal.cpp — macOS 平台桩（P1B §T2.1 边界）
// ════════════════════════════════════════════════════════════════
//
// P1B 先 Windows（D3D11 Compute 主实现）；macOS Metal 后端留桩。
// 本文件提供 kgpu_* 的 macOS 实现，全部返回 KG_ERR_NOTIMPL / NULL，
// 保证 CMake 在 macOS 上仍能产出 libkirin_gpu 静态库（符号完整）且
// 不阻断 cargo build。

#include "kirin_gpu.h"

#if defined(__APPLE__) && !defined(_WIN32)

extern "C" {

int32_t kgpu_init(void* /*device_handle*/) {
    // device_handle 平台语义：macOS = MTLDevice（待）。当前桩未实现。
    return KG_ERR_NOTIMPL;  // macOS Metal 待实现
}

void kgpu_shutdown(void) {
    // 幂等空操作（无状态）。
}

int32_t kgpu_tile_hash(void* /*texture*/, KgTileMap* /*out*/, int32_t* /*decision*/) {
    return KG_ERR_NOTIMPL;
}

int32_t kgpu_blit_tiles_rle(void* /*texture*/, const KgTileMap* /*map*/,
                            uint8_t* /*out*/, uint32_t* /*out_len*/) {
    return KG_ERR_NOTIMPL;
}

void* kgpu_hw_upload(void* /*texture*/) {
    return nullptr;
}

int32_t kgpu_dirty_indices(void* /*texture*/, uint32_t* /*out_idx*/, uint32_t* /*out_count*/) {
    return KG_ERR_NOTIMPL;
}

} // extern "C"

#endif // __APPLE__
