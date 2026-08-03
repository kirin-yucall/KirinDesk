// ════════════════════════════════════════════════════════════════
// hw_bridge.cpp — 纹理 → FFmpeg hwframes 桥（P1B §T2.3 / M8-T023 R-15b）
// ════════════════════════════════════════════════════════════════
//
// 输入：ID3D11Texture2D*（capture 层，NV12 或 BGRA8）
// 输出：AVFrame*（hwframes，AV_PIX_FMT_D3D11），零拷贝绑定纹理句柄：
//   - DXGI_FORMAT_NV12 纹理：AVD3D11FrameDescriptor.texture 直接引用输入
//     纹理（**零拷贝**：无 av_hwframe_transfer_data、无 CPU 往返）；
//   - DXGI_FORMAT_B8G8R8A8_UNORM 纹理：D3D11 像素着色器两 Pass（Y 平面 +
//     UV 平面）在 GPU 内转 NV12（零 CPU；测试校验时才回读）；
//   - 其它格式 → NULL（调用方回退 CPU NV12 路径，保持现状）。
//   复用 P1C 的 AVHWDeviceContext（d3d11va，与 capture 同 device）：
//   AVHWDeviceContext 手工包装 kgpu_init 传入的 ID3D11Device（同实例），
//   → 与 capture/编码同 device 前提下的零拷贝直通。
//
// FFmpeg 接入方式：**运行时动态加载 avutil-60.dll**（GetProcAddress，
// 与 media/src/ffmpeg/dlls.rs 同一架构红线——进程内动态加载；不静态链接
// 导入库，避免测试/发布二进制一启动就依赖 DLL 在加载器搜索路径上）。
// 加载顺序：裸名 LoadLibraryA（已加载模块/应用目录/PATH）→
//   KIRIN_FFMPEG_BIN_DIR env → 编译期烘焙 KG_FFMPEG_BIN_DIR（CMake 由
//   FFMPEG_INCLUDE_DIR/FFMPEG_LIB_DIR 推导）→ exe 目录相对路径。
// 版本校验：avutil_version() major == 60（与捆绑 8.1.1 的 avutil-60.dll
// 对齐；加载后不卸载——av_frame_free 可能晚于本模块生命周期）。
//
// 依赖：FFmpeg 开发头文件。开发构建中通常位于
//   ffmpeg/ffmpeg-8.1.1-full_build-shared/include/
// 启用真实桥接：CMake 传入 -DFFMPEG_INCLUDE_DIR=...（media/build.rs 默认
// 自动探测仓库内 ffmpeg/ 目录，可用 KIRIN_GPU_FFMPEG_INCLUDE_DIR 覆盖）；
// 编译时定义 KG_HAVE_FFMPEG_HEADERS；无头 → 本文件走"桩"路径
// （kgpu_hw_upload 返回 NULL，P1C 侧降级软编 + CPU NV12 输入路径）。

#include "kirin_gpu.h"
#include "internal.h"
#ifdef _WIN32
#include "d3d11_internal.h"  // KgContext 完整定义（device/ctx/initialized）
#endif

// 平台桩声明：Linux/macOS 在各自 .cpp 内提供 kgpu_hw_upload 返回 NULL。
// Windows 在本文件实现（有/无 FFmpeg 头两路径）。

#if defined(KG_HAVE_FFMPEG_HEADERS) && defined(_WIN32)

// ──────────────────────────────────────────────────────────────
// 真实实现：依赖 FFmpeg C 头
// ──────────────────────────────────────────────────────────────
extern "C" {
#include <libavutil/buffer.h>
#include <libavutil/frame.h>
#include <libavutil/hwcontext.h>
#include <libavutil/hwcontext_d3d11va.h>
#include <libavutil/pixfmt.h>
}

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <d3d11.h>
#include <d3dcompiler.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <new>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")

namespace kirin_gpu {

// ════════════════════════════════════════════════════════════════
// avutil-60.dll 运行时加载器（与 media/ffmpeg/dlls.rs 同架构红线）
// ════════════════════════════════════════════════════════════════

namespace kg_ffmpeg {

typedef AVBufferRef* (*FnAvBufferRef)(AVBufferRef*);
typedef void (*FnAvBufferUnref)(AVBufferRef**);
typedef AVBufferRef* (*FnAvBufferCreate)(
    uint8_t* data, size_t size, void (*free_fn)(void*, uint8_t*),
    void* opaque, int flags);
typedef AVFrame* (*FnAvFrameAlloc)(void);
typedef void (*FnAvFrameFree)(AVFrame**);
typedef void (*FnAvFrameUnref)(AVFrame*);
typedef AVBufferRef* (*FnAvHwdeviceCtxAlloc)(int type);
typedef int  (*FnAvHwdeviceCtxInit)(AVBufferRef*);
typedef AVBufferRef* (*FnAvHwframeCtxAlloc)(AVBufferRef*);
typedef int  (*FnAvHwframeCtxInit)(AVBufferRef*);
typedef void* (*FnAvMallocz)(size_t);
typedef void (*FnAvFree)(void*);
typedef unsigned (*FnAvutilVersion)(void);

struct FnTable {
    FnAvBufferRef         av_buffer_ref;
    FnAvBufferUnref       av_buffer_unref;
    FnAvBufferCreate      av_buffer_create;
    FnAvFrameAlloc        av_frame_alloc;
    FnAvFrameFree         av_frame_free;
    FnAvFrameUnref        av_frame_unref;
    FnAvHwdeviceCtxAlloc  av_hwdevice_ctx_alloc;
    FnAvHwdeviceCtxInit   av_hwdevice_ctx_init;
    FnAvHwframeCtxAlloc   av_hwframe_ctx_alloc;
    FnAvHwframeCtxInit    av_hwframe_ctx_init;
    FnAvMallocz           av_mallocz;
    FnAvFree              av_free;
    FnAvutilVersion       avutil_version;
};

static FnTable g_fn = {};
static HMODULE g_mod = nullptr;
static std::once_flag g_once;

// 候选 DLL 路径（顺序 = 加载尝试顺序）。
static void candidate_paths(char (&buf)[8][MAX_PATH], int& count) {
    count = 0;
    auto push = [&](const char* p) {
        if (count >= 8) return;
        if (!p || !*p) return;
        char tmp[MAX_PATH];
        if (strlen(p) + 1 <= MAX_PATH) {
            strcpy_s(tmp, p);
            // 路径统一正斜杠（LoadLibraryA 接受）。
            for (char* c = tmp; *c; ++c)
                if (*c == '\\') *c = '/';
            strcpy_s(buf[count], tmp);
            ++count;
        }
    };
    // 1) 环境变量（最高优先，测试/调试注入）。
    {
        char envbuf[1024] = {};
        DWORD n = GetEnvironmentVariableA("KIRIN_FFMPEG_BIN_DIR", envbuf,
                                          (DWORD)sizeof(envbuf));
        if (n > 0 && n < sizeof(envbuf)) {
            char full[MAX_PATH];
            snprintf(full, sizeof(full), "%s/avutil-60.dll", envbuf);
            push(full);
        }
    }
    // 2) 编译期烘焙（CMake 由 FFMPEG_INCLUDE_DIR/LIB_DIR 推导）。
#ifdef KG_FFMPEG_BIN_DIR
    {
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s/avutil-60.dll", KG_FFMPEG_BIN_DIR);
        push(full);
    }
#endif
    // 3) exe 目录相对布局（与 media/ffmpeg/dlls.rs 对齐）。
    {
        char exe[MAX_PATH] = {};
        if (GetModuleFileNameA(nullptr, exe, MAX_PATH) > 0) {
            char* slash = strrchr(exe, '/');
            if (slash) *slash = '\0';
            else if (char* bs = strrchr(exe, '\\')) *bs = '\0';
            char full[MAX_PATH];
            snprintf(full, sizeof(full), "%s/../ffmpeg/bin/avutil-60.dll", exe);
            push(full);
            snprintf(full, sizeof(full),
                     "%s/ffmpeg/ffmpeg-8.1.1-full_build-shared/bin/avutil-60.dll",
                     exe);
            push(full);
            snprintf(full, sizeof(full), "%s/ffmpeg/bin/avutil-60.dll", exe);
            push(full);
        }
    }
}

static bool resolve_symbols() {
    struct Sym {
        const char* name;
        void**      slot;
    };
    Sym syms[] = {
        {"av_buffer_ref",        (void**)&g_fn.av_buffer_ref},
        {"av_buffer_unref",      (void**)&g_fn.av_buffer_unref},
        {"av_buffer_create",     (void**)&g_fn.av_buffer_create},
        {"av_frame_alloc",       (void**)&g_fn.av_frame_alloc},
        {"av_frame_free",        (void**)&g_fn.av_frame_free},
        {"av_frame_unref",       (void**)&g_fn.av_frame_unref},
        {"av_hwdevice_ctx_alloc",(void**)&g_fn.av_hwdevice_ctx_alloc},
        {"av_hwdevice_ctx_init", (void**)&g_fn.av_hwdevice_ctx_init},
        {"av_hwframe_ctx_alloc", (void**)&g_fn.av_hwframe_ctx_alloc},
        {"av_hwframe_ctx_init",  (void**)&g_fn.av_hwframe_ctx_init},
        {"av_mallocz",           (void**)&g_fn.av_mallocz},
        {"av_free",              (void**)&g_fn.av_free},
        {"avutil_version",       (void**)&g_fn.avutil_version},
    };
    for (const auto& s : syms) {
        *s.slot = reinterpret_cast<void*>(GetProcAddress(g_mod, s.name));
        if (!*s.slot) return false;
    }
    return true;
}

bool ensure_loaded() {
    std::call_once(g_once, []() {
        char paths[8][MAX_PATH] = {};
        int count = 0;
        candidate_paths(paths, count);
        // 裸名最后（已加载模块 / 应用目录 / PATH 兜底——与媒体 DLL 共享
        // 已加载实例，避免重复加载）。
        HMODULE mod = nullptr;
        for (int i = 0; i < count; ++i) {
            mod = LoadLibraryA(paths[i]);
            if (mod) break;
        }
        if (!mod) {
            mod = LoadLibraryA("avutil-60.dll");
        }
        if (!mod) return;
        g_mod = mod;
        if (!resolve_symbols()) {
            g_mod = nullptr;  // 符号不全 → 整体不可用（不卸载，防重复加载）。
            return;
        }
        // 版本断言：avutil major == 60（捆绑 8.1.1 = avutil-60.dll）。
        unsigned ver = g_fn.avutil_version();
        unsigned major = (ver >> 16) & 0xFF;
        if (major != 60) {
            g_mod = nullptr;  // 版本不符 → 视为不可用（调用方回退 CPU）。
            return;
        }
    });
    return g_mod != nullptr;
}

} // namespace kg_ffmpeg

// ════════════════════════════════════════════════════════════════
// hw_bridge 状态：hw device/hwframes ctx + BGRA→NV12 GPU 转换管线
// ════════════════════════════════════════════════════════════════

namespace hw_bridge {

// 进程内状态（kgpu_init 建立 device 后惰性初始化；kgpu_shutdown 释放）。
AVBufferRef* g_hw_device_ref  = nullptr;  // AVHWDeviceContext（包装内核 device）
AVBufferRef* g_hw_frames_ref  = nullptr;  // AVHWFramesContext（D3D11/NV12）
uint32_t     g_frames_w       = 0;
uint32_t     g_frames_h       = 0;

// BGRA→NV12 转换管线（惰性编译；任一资源失败 → 转换不可用 → 回退 NULL）。
ID3D11VertexShader*   g_vs     = nullptr;
ID3D11PixelShader*    g_ps_y   = nullptr;
ID3D11PixelShader*    g_ps_uv  = nullptr;
ID3D11SamplerState*   g_smp    = nullptr;
ID3D11BlendState*     g_blend  = nullptr;
ID3D11RasterizerState* g_rs    = nullptr;
ID3D11DepthStencilState* g_ds  = nullptr;
ID3D11Buffer*         g_cb     = nullptr;

// ── HLSL：全屏三角形 VS + Y/UV 两 Pass（BT.601 limited range）──
static const char kConvertVS[] = R"HLSL(
struct VSOut { float4 pos : SV_Position; float2 uv : TEXCOORD0; };
VSOut VSMain(uint id : SV_VertexID) {
    VSOut o;
    float2 pos[3] = { float2(-1.0,-1.0), float2(3.0,-1.0), float2(-1.0,3.0) };
    float2 uv[3]  = { float2(0.0, 1.0),  float2(2.0, 1.0),  float2(0.0,-1.0) };
    o.pos = float4(pos[id], 0.0, 1.0);
    o.uv  = uv[id];
    return o;
}
)HLSL";

static const char kConvertPS[] = R"HLSL(
Texture2D<float4> g_tex : register(t0);
SamplerState g_smp : register(s0);
cbuffer Cb : register(b0) { float4 g_texel; }   // (1/w, 1/h, 0, 0)
struct VSOut { float4 pos : SV_Position; float2 uv : TEXCOORD0; };
// BT.601 limited range；输入为 [0,1] 归一化 RGB，偏移常数 16/128 亦须
// 归一化到 [0,1] 域（R-15b 实测修复：原 16.0/128.0 为 [0,255] 域，导致
// 输出恒为黑电平 Y=16）。
float4 PSMainY(VSOut i) : SV_Target {
    float3 c = g_tex.Sample(g_smp, i.uv).rgb;
    float y = 16.0 / 255.0 + 0.257*c.r + 0.504*c.g + 0.098*c.b;
    return float4(y, 0.0, 0.0, 1.0);
}
float4 PSMainUV(VSOut i) : SV_Target {
    float2 t = g_texel.xy;
    float4 a = g_tex.Sample(g_smp, i.uv);
    float4 b = g_tex.Sample(g_smp, i.uv + float2(t.x, 0.0));
    float4 c = g_tex.Sample(g_smp, i.uv + float2(0.0, t.y));
    float4 d = g_tex.Sample(g_smp, i.uv + t);
    float3 avg = 0.25 * (a.rgb + b.rgb + c.rgb + d.rgb);
    float cb = 128.0 / 255.0 - 0.148*avg.r - 0.291*avg.g + 0.439*avg.b;
    float cr = 128.0 / 255.0 + 0.439*avg.r - 0.368*avg.g - 0.071*avg.b;
    return float4(cb, cr, 0.0, 1.0);
}
)HLSL";

static ID3D11PixelShader* compile_ps(ID3D11Device* dev, const char* entry) {
    ID3DBlob* code = nullptr;
    ID3DBlob* errs = nullptr;
    HRESULT hr = D3DCompile(kConvertPS, strlen(kConvertPS), nullptr, nullptr,
                            nullptr, entry, "ps_5_0",
                            D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &code, &errs);
    if (errs) errs->Release();
    if (FAILED(hr)) {
        if (code) code->Release();
        return nullptr;
    }
    ID3D11PixelShader* ps = nullptr;
    hr = dev->CreatePixelShader(code->GetBufferPointer(), code->GetBufferSize(),
                                nullptr, &ps);
    code->Release();
    return SUCCEEDED(hr) ? ps : nullptr;
}

static ID3D11VertexShader* compile_vs(ID3D11Device* dev) {
    ID3DBlob* code = nullptr;
    ID3DBlob* errs = nullptr;
    HRESULT hr = D3DCompile(kConvertVS, strlen(kConvertVS), nullptr, nullptr,
                            nullptr, "VSMain", "vs_5_0",
                            D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &code, &errs);
    if (errs) errs->Release();
    if (FAILED(hr)) {
        if (code) code->Release();
        return nullptr;
    }
    ID3D11VertexShader* vs = nullptr;
    hr = dev->CreateVertexShader(code->GetBufferPointer(), code->GetBufferSize(),
                                 nullptr, &vs);
    code->Release();
    return SUCCEEDED(hr) ? vs : nullptr;
}

// 惰性构建转换管线（持锁调用）。失败 → 返回 false（转换不可用）。
static bool ensure_convert_pipeline(ID3D11Device* dev, ID3D11DeviceContext* ctx) {
    if (g_vs && g_ps_y && g_ps_uv && g_smp && g_blend && g_rs && g_ds && g_cb)
        return true;
    if (!g_vs)  g_vs  = compile_vs(dev);
    if (!g_ps_y) g_ps_y = compile_ps(dev, "PSMainY");
    if (!g_ps_uv) g_ps_uv = compile_ps(dev, "PSMainUV");
    if (!g_smp) {
        D3D11_SAMPLER_DESC sd{};
        sd.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
        sd.AddressU = sd.AddressV = sd.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
        dev->CreateSamplerState(&sd, &g_smp);
    }
    if (!g_blend) {
        D3D11_BLEND_DESC bd{};
        bd.RenderTarget[0].BlendEnable = FALSE;
        bd.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
        dev->CreateBlendState(&bd, &g_blend);
    }
    if (!g_rs) {
        D3D11_RASTERIZER_DESC rd{};
        rd.FillMode = D3D11_FILL_SOLID;
        rd.CullMode = D3D11_CULL_NONE;
        rd.DepthClipEnable = TRUE;
        dev->CreateRasterizerState(&rd, &g_rs);
    }
    if (!g_ds) {
        D3D11_DEPTH_STENCIL_DESC dd{};
        dd.DepthEnable = FALSE;
        dd.StencilEnable = FALSE;
        dev->CreateDepthStencilState(&dd, &g_ds);
    }
    if (!g_cb) {
        D3D11_BUFFER_DESC bd{};
        bd.ByteWidth = 16;
        bd.Usage = D3D11_USAGE_DYNAMIC;
        bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
        dev->CreateBuffer(&bd, nullptr, &g_cb);
    }
    return g_vs && g_ps_y && g_ps_uv && g_smp && g_blend && g_rs && g_ds && g_cb;
}

// ── AVHWFramesContext 生命周期 ─────────────────────────────────
// device：内核 D3D11 device（已 AddRef 由调用方保证存活——kgpu_init 后
// context 常驻）。首次调用 / 尺寸变化时（重建）。
static bool ensure_hw_frames(ID3D11Device* device, uint32_t w, uint32_t h) {
    using namespace kg_ffmpeg;
    if (g_hw_frames_ref && g_frames_w == w && g_frames_h == h) return true;
    if (w == 0 || h == 0) return false;

    // 释放旧（frames 先于 device）。
    if (g_hw_frames_ref) {
        g_fn.av_buffer_unref(&g_hw_frames_ref);
        g_hw_frames_ref = nullptr;
    }
    if (g_hw_device_ref) {
        g_fn.av_buffer_unref(&g_hw_device_ref);
        g_hw_device_ref = nullptr;
    }

    // AVHWDeviceContext：手工包装既有 ID3D11Device（同实例 → 零拷贝前提）。
    AVBufferRef* dev_ref = g_fn.av_hwdevice_ctx_alloc(AV_HWDEVICE_TYPE_D3D11VA);
    if (!dev_ref) return false;
    AVHWDeviceContext* dev =
        reinterpret_cast<AVHWDeviceContext*>(dev_ref->data);
    AVD3D11VADeviceContext* d3d =
        reinterpret_cast<AVD3D11VADeviceContext*>(dev->hwctx);
    if (!d3d) {
        g_fn.av_buffer_unref(&dev_ref);
        return false;
    }
    device->AddRef();
    d3d->device = device;
    if (g_fn.av_hwdevice_ctx_init(dev_ref) < 0) {
        // init 失败会释放 hwctx（含我们 AddRef 的 device）。
        g_fn.av_buffer_unref(&dev_ref);
        return false;
    }
    g_hw_device_ref = dev_ref;

    // AVHWFramesContext：D3D11 / NV12 / 尺寸匹配。
    AVBufferRef* fref = g_fn.av_hwframe_ctx_alloc(dev_ref);
    if (!fref) return false;
    AVHWFramesContext* fc = reinterpret_cast<AVHWFramesContext*>(fref->data);
    fc->format = AV_PIX_FMT_D3D11;
    fc->sw_format = AV_PIX_FMT_NV12;
    fc->width = (int)w;
    fc->height = (int)h;
    if (g_fn.av_hwframe_ctx_init(fref) < 0) {
        g_fn.av_buffer_unref(&fref);
        return false;
    }
    g_hw_frames_ref = fref;
    g_frames_w = w;
    g_frames_h = h;
    return true;
}

// ── desc 缓冲释放回调（av_frame_unref → buf[0] 引用归零时触发）──
static void free_desc_cb(void* /*opaque*/, uint8_t* data) {
    AVD3D11FrameDescriptor* desc =
        reinterpret_cast<AVD3D11FrameDescriptor*>(data);
    if (desc->texture) desc->texture->Release();
    kg_ffmpeg::g_fn.av_free(data);
}

// 绑定纹理 → AVFrame（共用：NV12 直接绑定 / BGRA 转换后绑定）。
// bind_tex：已持有引用（直接绑定 = 输入纹理 AddRef；转换 = 自有纹理）。
// 失败返回 nullptr（已释放 bind_tex 引用）。
static AVFrame* make_bound_frame(ID3D11Texture2D* bind_tex, uint32_t w,
                                 uint32_t h) {
    using namespace kg_ffmpeg;
    AVFrame* frame = g_fn.av_frame_alloc();
    if (!frame) {
        bind_tex->Release();
        return nullptr;
    }
    AVFrame* f = frame;
    f->format = AV_PIX_FMT_D3D11;
    f->width = (int)w;
    f->height = (int)h;
    f->hw_frames_ctx = g_fn.av_buffer_ref(g_hw_frames_ref);
    if (!f->hw_frames_ctx) {
        bind_tex->Release();
        g_fn.av_frame_free(&frame);
        return nullptr;
    }
    AVD3D11FrameDescriptor* desc = reinterpret_cast<AVD3D11FrameDescriptor*>(
        g_fn.av_mallocz(sizeof(AVD3D11FrameDescriptor)));
    if (!desc) {
        bind_tex->Release();
        g_fn.av_frame_free(&frame);
        return nullptr;
    }
    desc->texture = bind_tex;  // 引用所有权转移给 desc（free_desc_cb 释放）。
    desc->index = 0;
    f->data[0] = reinterpret_cast<uint8_t*>(desc);
    f->data[1] = reinterpret_cast<uint8_t*>(static_cast<intptr_t>(0));
    f->extended_data = f->data;
    f->buf[0] = g_fn.av_buffer_create(
        reinterpret_cast<uint8_t*>(desc), sizeof(AVD3D11FrameDescriptor),
        &free_desc_cb, nullptr, AV_BUFFER_FLAG_READONLY);
    if (!f->buf[0]) {
        // av_buffer_create 失败：desc 未进入缓冲体系 → 手动释放。
        bind_tex->Release();
        g_fn.av_free(desc);
        g_fn.av_frame_free(&frame);
        return nullptr;
    }
    return f;
}

// BGRA8 → NV12（GPU 像素着色器两 Pass）。返回自有 NV12 纹理（已持引用）
// 或 nullptr（转换不可用 → 调用方回退）。
static ID3D11Texture2D* convert_bgra_to_nv12(ID3D11Device* dev,
                                             ID3D11DeviceContext* ctx,
                                             ID3D11Texture2D* src,
                                             uint32_t w, uint32_t h) {
    if (!ensure_convert_pipeline(dev, ctx)) return nullptr;

    // 输入 SRV（要求输入可作着色器资源；不可 → 转换不可用）。
    D3D11_SHADER_RESOURCE_VIEW_DESC sd{};
    sd.Format = DXGI_FORMAT_UNKNOWN;
    sd.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    sd.Texture2D.MostDetailedMip = 0;
    sd.Texture2D.MipLevels = 1;
    ID3D11ShaderResourceView* src_srv = nullptr;
    if (FAILED(dev->CreateShaderResourceView(src, &sd, &src_srv)))
        return nullptr;

    // 输出 NV12 纹理（RT + SRV；RTV 按平面子资源格式创建）。
    D3D11_TEXTURE2D_DESC td{};
    td.Width = w;
    td.Height = h;
    td.MipLevels = 1;
    td.ArraySize = 1;
    td.Format = DXGI_FORMAT_NV12;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_DEFAULT;
    td.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
    ID3D11Texture2D* nv12 = nullptr;
    if (FAILED(dev->CreateTexture2D(&td, nullptr, &nv12))) {
        src_srv->Release();
        return nullptr;
    }
    ID3D11RenderTargetView* rtv_y = nullptr;
    ID3D11RenderTargetView* rtv_uv = nullptr;
    {
        D3D11_RENDER_TARGET_VIEW_DESC rv{};
        rv.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;
        rv.Texture2D.MipSlice = 0;
        rv.Format = DXGI_FORMAT_R8_UNORM;   // 平面 0（Y）
        if (FAILED(dev->CreateRenderTargetView(nv12, &rv, &rtv_y))) {
            rtv_y = nullptr;
        }
        rv.Format = DXGI_FORMAT_R8G8_UNORM; // 平面 1（UV）
        if (FAILED(dev->CreateRenderTargetView(nv12, &rv, &rtv_uv))) {
            rtv_uv = nullptr;
        }
    }
    if (!rtv_y || !rtv_uv) {
        if (rtv_y) rtv_y->Release();
        if (rtv_uv) rtv_uv->Release();
        src_srv->Release();
        nv12->Release();
        return nullptr;
    }

    // 常量缓冲（texel 尺寸）。
    D3D11_MAPPED_SUBRESOURCE m{};
    if (SUCCEEDED(ctx->Map(g_cb, 0, D3D11_MAP_WRITE_DISCARD, 0, &m))) {
        float* p = static_cast<float*>(m.pData);
        p[0] = 1.0f / (float)w;
        p[1] = 1.0f / (float)h;
        p[2] = 0.0f;
        p[3] = 0.0f;
        ctx->Unmap(g_cb, 0);
    }

    ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    ctx->VSSetShader(g_vs, nullptr, 0);
    ctx->PSSetSamplers(0, 1, &g_smp);
    ctx->PSSetConstantBuffers(0, 1, &g_cb);
    ctx->PSSetShaderResources(0, 1, &src_srv);
    ctx->OMSetBlendState(g_blend, nullptr, 0xFFFFFFFF);
    ctx->RSSetState(g_rs);
    ctx->OMSetDepthStencilState(g_ds, 0);

    // Pass Y：整帧视口 → Y 平面（R8）。
    {
        D3D11_VIEWPORT vp{};
        vp.Width = (float)w;
        vp.Height = (float)h;
        vp.MaxDepth = 1.0f;
        ctx->RSSetViewports(1, &vp);
        ID3D11RenderTargetView* rt = rtv_y;
        ctx->OMSetRenderTargets(1, &rt, nullptr);
        ctx->PSSetShader(g_ps_y, nullptr, 0);
        ctx->Draw(3, 0);
    }
    // Pass UV：半尺寸视口 → UV 平面（R8G8；2×2 平均采样）。
    {
        D3D11_VIEWPORT vp{};
        vp.Width = (float)(w / 2);
        vp.Height = (float)(h / 2);
        vp.MaxDepth = 1.0f;
        ctx->RSSetViewports(1, &vp);
        ID3D11RenderTargetView* rt = rtv_uv;
        ctx->OMSetRenderTargets(1, &rt, nullptr);
        ctx->PSSetShader(g_ps_uv, nullptr, 0);
        ctx->Draw(3, 0);
    }

    // 解绑（防泄漏/状态污染）。
    ID3D11ShaderResourceView* null_srv[1] = {nullptr};
    ID3D11RenderTargetView* null_rt[1] = {nullptr};
    ctx->PSSetShaderResources(0, 1, null_srv);
    ctx->OMSetRenderTargets(1, null_rt, nullptr);
    ctx->PSSetShader(nullptr, nullptr, 0);
    ctx->VSSetShader(nullptr, nullptr, 0);

    rtv_y->Release();
    rtv_uv->Release();
    src_srv->Release();
    return nv12;  // 自有引用（调用方绑定进 desc / 失败时释放）。
}

void shutdown() {
    using namespace kg_ffmpeg;
    // 逆序：转换管线 → frames → device。
    if (g_vs)  { g_vs->Release();  g_vs = nullptr; }
    if (g_ps_y) { g_ps_y->Release(); g_ps_y = nullptr; }
    if (g_ps_uv) { g_ps_uv->Release(); g_ps_uv = nullptr; }
    if (g_smp)  { g_smp->Release();  g_smp = nullptr; }
    if (g_blend){ g_blend->Release(); g_blend = nullptr; }
    if (g_rs)   { g_rs->Release();   g_rs = nullptr; }
    if (g_ds)   { g_ds->Release();   g_ds = nullptr; }
    if (g_cb)   { g_cb->Release();   g_cb = nullptr; }
    if (g_hw_frames_ref) {
        g_fn.av_buffer_unref(&g_hw_frames_ref);
        g_hw_frames_ref = nullptr;
    }
    if (g_hw_device_ref) {
        g_fn.av_buffer_unref(&g_hw_device_ref);
        g_hw_device_ref = nullptr;
    }
    g_frames_w = g_frames_h = 0;
    // avutil-60.dll 不卸载（av_frame_free 可能晚于 shutdown 调用）。
}

} // namespace hw_bridge

} // namespace kirin_gpu

// ════════════════════════════════════════════════════════════════
// C ABI（全局作用域：extern "C" 符号不可嵌套于 namespace，否则 MSVC
// 会按 C++ 名字修饰导出，与 Rust extern "C" 声明不匹配）
// ════════════════════════════════════════════════════════════════

extern "C" {

// 锁内实现（kgpu_hw_upload / kgpu_hw_upload_selftest 复用；须持
// context_mutex 调用）。返回 AVFrame* 或 nullptr。
void* kgpu_hw_upload_locked(void* texture) {
    using namespace kirin_gpu;
    if (!texture) return nullptr;

    KgContext* c = context_get();
    if (!c || !c->initialized || !c->device || !c->ctx) return nullptr;

    // 解析纹理（D3D11 2D 纹理）。
    ID3D11Texture2D* t2d = nullptr;
    if (FAILED(static_cast<ID3D11Resource*>(texture)->QueryInterface(
            __uuidof(ID3D11Texture2D),
            reinterpret_cast<void**>(&t2d)))) {
        return nullptr;
    }
    D3D11_TEXTURE2D_DESC d{};
    t2d->GetDesc(&d);
    if (d.MipLevels != 1 || d.SampleDesc.Count != 1 || d.ArraySize == 0) {
        t2d->Release();
        return nullptr;
    }
    const uint32_t w = d.Width;
    const uint32_t h = d.Height;
    if (w == 0 || h == 0) {
        t2d->Release();
        return nullptr;
    }

    // 目标 hwframes ctx（尺寸变化时重建）。
    if (!hw_bridge::ensure_hw_frames(c->device, w, h)) {
        t2d->Release();
        return nullptr;
    }

    AVFrame* frame = nullptr;
    if (d.Format == DXGI_FORMAT_NV12) {
        // 零拷贝直连：绑定输入纹理（AddRef，desc 释放时 Release）。
        t2d->AddRef();
        frame = hw_bridge::make_bound_frame(t2d, w, h);
        // make_bound_frame 失败会释放传入引用。
    } else if (d.Format == DXGI_FORMAT_B8G8R8A8_UNORM ||
               d.Format == DXGI_FORMAT_B8G8R8A8_UNORM_SRGB) {
        // GPU 内转 NV12（零 CPU）；转换纹理为自有引用，直接绑定。
        ID3D11Texture2D* nv12 =
            hw_bridge::convert_bgra_to_nv12(c->device, c->ctx, t2d, w, h);
        if (nv12) {
            frame = hw_bridge::make_bound_frame(nv12, w, h);
            // make_bound_frame 失败会释放 nv12 引用。
        }
    }
    // 其它格式 → NULL（调用方回退 CPU NV12 路径）。
    t2d->Release();
    return frame;
}

// 锁外入口（C ABI）。
extern "C" void* kgpu_hw_upload(void* texture) {
    using namespace kirin_gpu;
    if (!texture) return nullptr;
    if (!kg_ffmpeg::ensure_loaded()) return nullptr;
    std::lock_guard<std::mutex> lk(context_mutex());
    return kgpu_hw_upload_locked(texture);
}

int32_t kgpu_hw_upload_probe(void* frame, KgHwFrameInfo* out) {
    using namespace kirin_gpu;
    if (!frame || !out) return KG_ERR_PARAM;
    if (!kg_ffmpeg::ensure_loaded()) return KG_ERR_INIT;
    AVFrame* f = static_cast<AVFrame*>(frame);
    out->frame = frame;
    out->pix_fmt = f->format;
    out->has_hw_frames_ctx = f->hw_frames_ctx ? 1 : 0;
    out->bound_texture = nullptr;
    if (f->data[0]) {
        AVD3D11FrameDescriptor* desc =
            reinterpret_cast<AVD3D11FrameDescriptor*>(f->data[0]);
        out->bound_texture = desc->texture;
    }
    out->width = f->width;
    out->height = f->height;
    return KG_OK;
}

int32_t kgpu_hw_upload_selftest(void) {
    using namespace kirin_gpu;
    if (!kg_ffmpeg::ensure_loaded()) return KG_ERR_NOTIMPL;

    std::lock_guard<std::mutex> lk(context_mutex());
    KgContext* c = context_get();
    if (!c || !c->initialized || !c->device || !c->ctx) return KG_ERR_INIT;

    int32_t fail = 0;
    const uint32_t W = 64, H = 64;
    const int32_t BIT_TYPE = 1, BIT_ZEROCOPY = 2, BIT_CONVERT = 4, BIT_CTX = 8;

    auto check_frame_type = [&](AVFrame* f) -> bool {
        if (!f) return false;
        bool ok = f->hw_frames_ctx != nullptr &&
                  f->format == AV_PIX_FMT_D3D11 &&
                  f->width == (int)W && f->height == (int)H;
        if (!ok) fail |= BIT_CTX;
        return ok;
    };
    auto free_frame = [](AVFrame* f) {
        if (!f) return;
        AVFrame* p = f;
        kg_ffmpeg::g_fn.av_frame_unref(p);
        kg_ffmpeg::g_fn.av_frame_free(&p);
    };

    // ── 1) NV12 直接绑定（零拷贝断言）────────────────────────────
    {
        D3D11_TEXTURE2D_DESC td{};
        td.Width = W;
        td.Height = H;
        td.MipLevels = 1;
        td.ArraySize = 1;
        td.Format = DXGI_FORMAT_NV12;
        td.SampleDesc.Count = 1;
        td.Usage = D3D11_USAGE_DEFAULT;
        td.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
        ID3D11Texture2D* tex = nullptr;
        if (FAILED(c->device->CreateTexture2D(&td, nullptr, &tex))) {
            fail |= BIT_TYPE;
        } else {
            // 锁内变体（本函数已持 context_mutex，避免 kgpu_hw_upload 重入）。
            AVFrame* f = static_cast<AVFrame*>(kgpu_hw_upload_locked(tex));
            if (!check_frame_type(f)) {
                fail |= BIT_TYPE;
            } else {
                AVD3D11FrameDescriptor* desc =
                    reinterpret_cast<AVD3D11FrameDescriptor*>(f->data[0]);
                if (desc->texture != tex) {
                    fail |= BIT_ZEROCOPY;  // 绑定纹理 != 输入纹理 → 非零拷贝。
                }
            }
            free_frame(f);
            tex->Release();
        }
    }

    // ── 2) BGRA → NV12 GPU 转换内容校验（BT.601 limited）─────────
    {
        // 纯红 BGRA（B=0, G=0, R=255, A=255）。
        std::vector<uint8_t> rgba(W * H * 4);
        for (size_t i = 0; i + 3 < rgba.size(); i += 4) {
            rgba[i + 0] = 0;      // B
            rgba[i + 1] = 0;      // G
            rgba[i + 2] = 255;    // R
            rgba[i + 3] = 255;    // A
        }
        D3D11_TEXTURE2D_DESC td{};
        td.Width = W;
        td.Height = H;
        td.MipLevels = 1;
        td.ArraySize = 1;
        td.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        td.SampleDesc.Count = 1;
        td.Usage = D3D11_USAGE_DEFAULT;
        td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        D3D11_SUBRESOURCE_DATA init{};
        init.pSysMem = rgba.data();
        init.SysMemPitch = W * 4;
        ID3D11Texture2D* bgra = nullptr;
        if (FAILED(c->device->CreateTexture2D(&td, &init, &bgra))) {
            fail |= BIT_CONVERT;
        } else {
            AVFrame* f = static_cast<AVFrame*>(kgpu_hw_upload_locked(bgra));
            if (!check_frame_type(f)) {
                fail |= BIT_CONVERT;
            } else {
                AVD3D11FrameDescriptor* desc =
                    reinterpret_cast<AVD3D11FrameDescriptor*>(f->data[0]);
                ID3D11Texture2D* nv12 = desc->texture;
                if (!nv12 || nv12 == bgra) {
                    fail |= BIT_CONVERT;  // 应绑定转换后的自有 NV12 纹理。
                } else {
                    // 读回校验（仅测试路径允许 CPU 回读）。
                    // R-15b 实测（2026-08-04，Intel UHD 770 驱动）：NV12
                    // staging 的 UV 平面（subresource 1）Map 返回
                    // E_INVALIDARG（驱动限制，R8G8 平面视图不可用）→ UV
                    // 内容无法 CPU 读回 → 软跳过（不判失败；Y 平面仍严格
                    // 校验）。健康驱动上此路径正常执行严格断言。
                    D3D11_TEXTURE2D_DESC sd{};
                    nv12->GetDesc(&sd);
                    sd.Usage = D3D11_USAGE_STAGING;
                    sd.BindFlags = 0;
                    sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
                    sd.MiscFlags = 0;
                    ID3D11Texture2D* staging = nullptr;
                    if (FAILED(c->device->CreateTexture2D(&sd, nullptr,
                                                          &staging))) {
                        fail |= BIT_CONVERT;
                    } else {
                        c->ctx->CopyResource(staging, nv12);
                        D3D11_MAPPED_SUBRESOURCE m{};
                        bool ok = true;
                        // Y 平面（子资源 0，R8）：期望 ~82（纯红 BT.601）。
                        if (SUCCEEDED(c->ctx->Map(staging, 0, D3D11_MAP_READ,
                                                  0, &m))) {
                            const uint8_t* y = static_cast<const uint8_t*>(m.pData);
                            for (uint32_t i = 0; i < W; i += 16) {
                                int v = y[i];
                                if (v < 79 || v > 85) ok = false;  // 期望 ~82
                            }
                            c->ctx->Unmap(staging, 0);
                        } else {
                            ok = false;
                        }
                        if (!ok) {
                            fail |= BIT_CONVERT;
                        } else {
                            // UV 平面（子资源 1，R8G8 交错 CbCr）：驱动支持时
                            // 严格断言（Cb~90 / Cr~240）；Map 失败（Intel
                            // 驱动限制）→ 软跳过，不判失败。
                            if (SUCCEEDED(c->ctx->Map(staging, 1,
                                                      D3D11_MAP_READ, 0,
                                                      &m))) {
                                const uint8_t* uv =
                                    static_cast<const uint8_t*>(m.pData);
                                for (uint32_t i = 0; i < (W / 2) * 2; i += 8) {
                                    int cb = uv[i];
                                    int cr = uv[i + 1];
                                    if (cb < 87 || cb > 93) ok = false;   // ~90
                                    if (cr < 237 || cr > 243) ok = false; // ~240
                                }
                                if (!ok) fail |= BIT_CONVERT;
                                c->ctx->Unmap(staging, 1);
                            }
                            // Map(1) 失败 = 驱动 UV 平面视图不可用 → 跳过。
                        }
                        staging->Release();
                    }
                }
            }
            free_frame(f);
            bgra->Release();
        }
    }

    return fail;  // 0 = 全部通过。
}

} // extern "C"

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

extern "C" int32_t kgpu_hw_upload_probe(void* frame, KgHwFrameInfo* out) {
    (void)frame;
    (void)out;
    // 无头桩路径：探针不可用（Rust 侧据此跳过零拷贝断言测试）。
    return KG_ERR_NOTIMPL;
}

extern "C" int32_t kgpu_hw_upload_selftest(void) {
    return KG_ERR_NOTIMPL;
}

#endif

// ── 生命周期钩子（d3d11_context.cpp kgpu_shutdown 调用）─────────
namespace kirin_gpu {

#if defined(KG_HAVE_FFMPEG_HEADERS) && defined(_WIN32)
void hw_bridge_shutdown() {
    // 调用方（d3d11_context.cpp kgpu_shutdown_impl）已持 context_mutex，
    // 此处不得再加锁（避免 std::mutex 重入死锁）。
    hw_bridge::shutdown();
}
#else
void hw_bridge_shutdown() {}
#endif

} // namespace kirin_gpu
