// ════════════════════════════════════════════════════════════════
// kirin_gpu.h — libkirin_gpu 的 C ABI 头（P1B §T2.1）
// ════════════════════════════════════════════════════════════════
//
// GPU 侧零拷贝内核：Tile-Hash Diff compute shader、tile blit + RLE、
// 纹理 → FFmpeg hwframes 桥。C++ 内核只做 "GPU 内搬运算"，无业务逻辑；
// 不直连 NVENC/AMF/QSV SDK（FFmpeg 侧由 P1C 负责）；不 spawn 任何 exe。
//
// 设计目标：纹理永不回读 CPU；唯一读回为微变分支 RLE（几 KB）与大动分支
// dirty 索引（≤ 几 KB）。详见 task_docs/共享层/M8-T008_P1B_C++零拷贝GPU内核.md。
//
// 平台：
//   - Windows：D3D11 Compute（HLSL）主实现
//   - Linux：  VAAPI 桩（KG_ERR_NOTIMPL，编译不阻断）
//   - macOS：  Metal 桩（KG_ERR_NOTIMPL，编译不阻断）

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── 错误码 ───────────────────────────────────────────────────────
#define KG_OK            0
#define KG_ERR_INIT      (-1)   // 初始化失败（device / CS 编译 / FFmpeg 头缺失）
#define KG_ERR_PARAM     (-2)   // 参数非法（null 纹理 / 0 宽高）
#define KG_ERR_DEVICE    (-3)   // GPU 设备丢失 / 驱动异常（DXGI_ERROR_DEVICE_REMOVED）
#define KG_ERR_NOTIMPL   (-4)   // 平台未实现（Linux/macOS 桩）

// ── 决策三态（与 Rust EncodeDecision 对应）─────────────────────
#define KG_DECISION_STATIC       0   // 全静 → 编码层零输出
#define KG_DECISION_INCREMENTAL  1   // 微变 → tile 增量（RLE）
#define KG_DECISION_FULLFRAME    2   // 大动 → ROI Mask + 编码器

// ── 脏块地图（GPU diff 输出 + ROI Mask）────────────────────────
// dirty 数组生命周期：由 C++ 侧分配，调用方只读，kgpu_shutdown 时释放。
// dirty 仅在 decision != KG_DECISION_STATIC 时回填（全静时保持空 / 0）。
typedef struct KgTileMap {
    uint32_t tile_w;        // 64
    uint32_t tile_h;        // 64
    uint32_t grid_w;        // ceil(width  / tile_w)
    uint32_t grid_h;        // ceil(height / tile_h)
    uint8_t *dirty;         // 逐 tile 0/1，len = grid_w * grid_h（CPU 镜像，仅大动/微变填充）
    float    dirty_ratio;   // 0.0 ~ 1.0；全静 = 0.0，首帧 = 1.0
} KgTileMap;

// ── 生命周期 ────────────────────────────────────────────────────
// 初始化一次，进程内常驻。
//   device_handle 平台语义：Windows=ID3D11Device* / Linux=VkDevice(待) / macOS=MTLDevice(待)；
//   可为 NULL（自建 device）；非 NULL 则复用调用方 device（Windows: windows-capture 的
//   D3D11 device → 与编码器同 device，零拷贝直通）。
//   桩契约：Linux/macOS 后端当前返回 KG_ERR_NOTIMPL；Rust 侧 GpuKernel=None
//   → tile_diff CPU 回退，不阻断编译/运行。
int32_t kgpu_init(void *device_handle);

// 幂等关闭（重复调用安全）。释放 device / CS / 缓冲。
void    kgpu_shutdown(void);

// ── Tile-Hash Diff：显存内完成（Pass1 哈希 + Pass2 diff + Pass3 脏块地图）──
//   texture：D3D11 ID3D11Texture2D*（capture 层 BGRA8）
//   out->dirty 仅在非全静时回填（大动: 全 dirty 位图；微变: 位图 + 后续 RLE）
//   decision：KG_DECISION_STATIC / INCREMENTAL / FULLFRAME
int32_t kgpu_tile_hash(void *texture, KgTileMap *out, int32_t *decision);

// ── tile blit：提取 dirty tile 像素 → RLE 压缩写入 out ─────────
//   out_len：返回压缩后字节数（KB 级）。
//   仅微变分支调用（decision == KG_DECISION_INCREMENTAL）。
int32_t kgpu_blit_tiles_rle(void *texture, const KgTileMap *map,
                            uint8_t *out, uint32_t *out_len);

// ── 纹理 → FFmpeg hwframes 桥（零拷贝绑定纹理句柄）─────────────
//   返回 AVFrame*（d3d11va hwframes，AV_PIX_FMT_D3D11）。
//   失败返回 NULL（无 FFmpeg 头 / device lost）。
//   调用方须 av_frame_unref + av_frame_free。
void   *kgpu_hw_upload(void *texture);

// ── dirty 索引读回（大动分支 ROI 组装用，≤ 几 KB）──────────────
//   out_idx：调用方分配的 u32 数组（容量 = grid_w * grid_h）
//   out_count：返回实际 dirty 数量
int32_t kgpu_dirty_indices(void *texture, uint32_t *out_idx, uint32_t *out_count);

#ifdef __cplusplus
} // extern "C"
#endif
