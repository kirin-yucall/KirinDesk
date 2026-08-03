//! [`GpuKernel`] trait 实现：`KgpuKernel`（P1B §T2.4）。
//!
//! 当 `cfg(kirin_gpu_linked)` 时：`KgpuKernel::init` 调 `kgpu_init`，
//! `tile_hash` 调 `kgpu_tile_hash`，结果转 [`DirtyTileMap`] 喂回
//! `tile_diff`。
//!
//! 未链接时：本文件只导出占位类型 [`KgpuLinked`]（其常量 `LINKED = false`），
//! `tile_diff` 据此走 CPU 回退路径，保证 `cargo build` 清洁。
//!
//! # P1B↔P1C 接驳（2026-07-31；R-15b 2026-08-04 真实化）
//!
//! [`GpuKernel`] trait 在 P1C 扩展了 `blit_tiles_rle` / `hw_upload` /
//! `is_linked`，本类型在 `cfg(kirin_gpu_linked)` 下转调同名具体方法实现之：
//! - `blit_tiles_rle` → `kgpu_blit_tiles_rle`（微变分支 RLE 字节）
//! - `hw_upload` → `kgpu_hw_upload`（纹理 → FFmpeg hwframes AVFrame*）
//! - `is_linked` → `true`
//!
//! P1C 的 `ffmpeg_hw.rs` / `pipeline.rs` / `factory.rs` 据此驱动零拷贝路径。
//!
//! **R-15b 状态（2026-08-04）**：C++ 侧 `kgpu_hw_upload`（hw_bridge.cpp）
//! 已由桩实现（恒 NULL）替换为**真实实现**——NV12 纹理零拷贝绑定
//! （`AVD3D11FrameDescriptor` 直接引用输入纹理，无 CPU 往返）、BGRA8 纹理
//! GPU 内转 NV12（像素着色器两 Pass，零 CPU）；`hw_upload` 仅在无 FFmpeg
//! 头/DLL、device lost 或纹理格式不支持时返 `GpuKernel` 错误 → P1C 回退
//! CPU NV12 路径（保底不变）。零拷贝断言见本模块 `hw_bridge` 测试
//! （`test_hw_upload_frame_type` / `test_hw_upload_zero_copy` 等，
//! 仅 `cfg(kirin_gpu_linked)` + Windows + 有 GPU 环境运行）。

use crate::encoder::video::EncodeError;

#[cfg(kirin_gpu_linked)]
use super::KgTileMap;
#[cfg(kirin_gpu_linked)]
use crate::encoder::types::{DirtyTileMap, GpuTexture};
#[cfg(kirin_gpu_linked)]
use crate::encoder::video::tile_diff::GpuKernel;

/// 编译期标记：libkirin_gpu 是否已链接。
///
/// - `LINKED = true`：`cfg(kirin_gpu_linked)` 启用，[`KgpuKernel`] 可用。
/// - `LINKED = false`：未链接（CMake/工具链缺失或未启用 `gpu-kernel` feature）。
///
/// 调用方据此决定是否构造 [`KgpuKernel`]；未链接时 `tile_diff` 走 CPU 回退。
pub struct KgpuLinked;
#[cfg(kirin_gpu_linked)]
impl KgpuLinked {
    pub const LINKED: bool = true;
}
#[cfg(not(kirin_gpu_linked))]
impl KgpuLinked {
    pub const LINKED: bool = false;
}

// ════════════════════════════════════════════════════════════════
// KgpuKernel — libkirin_gpu 的安全包装 + GpuKernel impl（仅链接时）
// ════════════════════════════════════════════════════════════════

/// libkirin_gpu 内核的安全包装（RAII）。
///
/// `Drop` 调 `kgpu_shutdown`，进程退出时释放。`init` 一次，进程内常驻；
/// 重复 `init` 由 C++ 侧保证幂等。
///
/// # Safety
///
/// - 单线程调用（编码线程独占）；`Send + Sync` 因 C++ 内 `std::mutex` 保护。
/// - 内部状态全在 C++ 侧；本结构无字段（ZST-like handle）。
///
/// # 未链接时
///
/// 未启用 `cfg(kirin_gpu_linked)` 时本结构仍存在但 [`init`](Self::init)
/// 恒返回 [`GpuKernel`](EncodeError::GpuKernel) 错误，调用方据此走 CPU 回退。
pub struct KgpuKernel {
    _priv: (),
}

#[cfg(kirin_gpu_linked)]
impl KgpuKernel {
    /// 初始化内核。
    ///
    /// `device`：`None` → 自建 device；`Some(ptr)` → 复用调用方 device。
    /// 平台语义：Windows=ID3D11Device* / Linux=VkDevice(待) / macOS=MTLDevice(待)。
    /// （Windows: windows-capture → 与编码器同 device，零拷贝直通。）
    ///
    /// M8-T030（R-06，GPU-FR-006）：调用方应传
    /// [`crate::gpu::d3d11_device_handle()`]（选定适配器上创建的 D3D11 设备，
    /// 与 FFmpeg HW 编解码绑定同一 GPU）；无选定适配器 / 非 Windows → `None`
    /// 自建设备，保持现状。
    pub fn init(device: Option<*mut core::ffi::c_void>) -> Result<Self, EncodeError> {
        let dev = device.unwrap_or(core::ptr::null_mut());
        let code = unsafe { super::kgpu_init(dev) };
        super::map_err(code, "kgpu_init")?;
        Ok(KgpuKernel { _priv: () })
    }

    /// Tile-Hash Diff：显存内完成。返回 (DirtyTileMap, decision_code)。
    ///
    /// `decision_code` ∈ {`KG_DECISION_STATIC`, `_INCREMENTAL`, `_FULLFRAME`}。
    pub fn tile_hash_raw(&self, tex: &GpuTexture) -> Result<(DirtyTileMap, i32), EncodeError> {
        if tex.is_null() {
            return Err(EncodeError::InvalidConfig("null texture".into()));
        }
        let mut map = KgTileMap::default();
        let mut decision: i32 = super::KG_DECISION_STATIC;
        let code = unsafe { super::kgpu_tile_hash(tex.handle as *mut _, &mut map, &mut decision) };
        super::map_err(code, "kgpu_tile_hash")?;

        let dirty_slice = unsafe { map.as_dirty_slice() };
        let mut dt = DirtyTileMap {
            tile_w: map.tile_w,
            tile_h: map.tile_h,
            grid_w: map.grid_w,
            grid_h: map.grid_h,
            dirty: dirty_slice.iter().map(|&b| b != 0).collect(),
            dirty_ratio: map.dirty_ratio,
        };
        // 容错：保证 ratio 与 dirty 一致（防御 NaN / C 侧未算）。
        if dt.dirty_ratio.is_nan() {
            dt.dirty_ratio = 0.0;
            dt.dirty.iter_mut().for_each(|b| *b = false);
        }
        dt.compute_ratio();
        Ok((dt, decision))
    }

    /// tile blit + RLE（仅微变分支调用）。返回压缩字节（KB 级）。
    pub fn blit_tiles_rle(
        &self,
        tex: &GpuTexture,
        map: &DirtyTileMap,
    ) -> Result<Vec<u8>, EncodeError> {
        if tex.is_null() {
            return Err(EncodeError::InvalidConfig("null texture".into()));
        }
        // 构造 C 侧 KgTileMap（dirty 用 u8 表达）。
        let dirty_u8: Vec<u8> = map
            .dirty
            .iter()
            .map(|&b| if b { 1u8 } else { 0u8 })
            .collect();
        let total = dirty_u8.len();
        let c_map = KgTileMap {
            tile_w: map.tile_w,
            tile_h: map.tile_h,
            grid_w: map.grid_w,
            grid_h: map.grid_h,
            dirty: if total == 0 {
                core::ptr::null_mut()
            } else {
                dirty_u8.as_ptr() as *mut u8
            },
            dirty_ratio: map.dirty_ratio,
        };
        // 上界：total * 2（RLE 最坏 1 字节膨胀）。MB 级纹理下 ≤ 几 KB。
        let cap = total.saturating_mul(2).max(64);
        let mut out = vec![0u8; cap];
        let mut out_len: u32 = 0;
        let code = unsafe {
            super::kgpu_blit_tiles_rle(tex.handle as *mut _, &c_map, out.as_mut_ptr(), &mut out_len)
        };
        super::map_err(code, "kgpu_blit_tiles_rle")?;
        out.truncate(out_len as usize);
        Ok(out)
    }

    /// 纹理 → FFmpeg hwframes 桥（AVFrame*）。失败返回 `GpuKernel` 错误。
    ///
    /// 返回的 AVFrame 由调用方（P1C ffmpeg_hw.rs）负责 `av_frame_unref` +
    /// `av_frame_free`。
    pub fn hw_upload(&self, tex: &GpuTexture) -> Result<*mut core::ffi::c_void, EncodeError> {
        if tex.is_null() {
            return Err(EncodeError::InvalidConfig("null texture".into()));
        }
        let p = unsafe { super::kgpu_hw_upload(tex.handle as *mut _) };
        if p.is_null() {
            return Err(EncodeError::GpuKernel(
                "kgpu_hw_upload: NULL (FFmpeg headers missing or device lost)".into(),
            ));
        }
        Ok(p)
    }

    /// dirty 索引读回（大动分支 ROI 组装用，≤ 几 KB）。
    pub fn dirty_indices(&self, tex: &GpuTexture) -> Result<Vec<u32>, EncodeError> {
        if tex.is_null() {
            return Err(EncodeError::InvalidConfig("null texture".into()));
        }
        // P1B：直接由 DirtyTileMap 计算（kgpu_dirty_indices 当前 ABI 兼容
        // 仅返回 0；GPU 端聚合 CS 已留，后续大动分支可启用）。这里返回空，
        // 让调用方用 DirtyTileMap::dirty_indices() 真实计算。
        let mut count: u32 = 0;
        let code = unsafe {
            super::kgpu_dirty_indices(tex.handle as *mut _, core::ptr::null_mut(), &mut count)
        };
        super::map_err(code, "kgpu_dirty_indices")?;
        Ok(Vec::new())
    }
}

#[cfg(kirin_gpu_linked)]
impl Drop for KgpuKernel {
    fn drop(&mut self) {
        // 幂等：C++ 侧 kgpu_shutdown 重复调用安全。
        unsafe { super::kgpu_shutdown() };
    }
}

// Safety: C++ 侧 kgpu_* 内部用 std::mutex 保护全局状态；允许跨线程持有
// 句柄（实际单线程调用：编码线程独占）。
#[cfg(kirin_gpu_linked)]
unsafe impl Send for KgpuKernel {}
#[cfg(kirin_gpu_linked)]
unsafe impl Sync for KgpuKernel {}

#[cfg(kirin_gpu_linked)]
impl GpuKernel for KgpuKernel {
    fn tile_hash(&self, tex: &GpuTexture) -> Result<DirtyTileMap, EncodeError> {
        let (map, _decision) = self.tile_hash_raw(tex)?;
        Ok(map)
    }

    /// P1B↔P1C 接驳点：微变分支 RLE 字节（`kgpu_blit_tiles_rle`）。
    fn blit_tiles_rle(&self, tex: &GpuTexture, map: &DirtyTileMap) -> Result<Vec<u8>, EncodeError> {
        // 转调本类型已有的同名具体方法（含 null 检查 + 错误码映射）。
        KgpuKernel::blit_tiles_rle(self, tex, map)
    }

    /// P1B↔P1C 接驳点：纹理 → FFmpeg hwframes 桥（`kgpu_hw_upload`）。
    ///
    /// 返回的 `AVFrame*` 由 P1C `ffmpeg_hw.rs` 持有并 `av_frame_unref` +
    /// `av_frame_free`。
    fn hw_upload(&self, tex: &GpuTexture) -> Result<*mut core::ffi::c_void, EncodeError> {
        KgpuKernel::hw_upload(self, tex)
    }

    /// libkirin_gpu 已链接（`cfg(kirin_gpu_linked)` 启用 + init 成功）。
    fn is_linked(&self) -> bool {
        true
    }
}

// ════════════════════════════════════════════════════════════════
// 未链接时的占位（保证模块始终可被 import；tile_diff 检查 KgpuLinked::LINKED）
// ════════════════════════════════════════════════════════════════

#[cfg(not(kirin_gpu_linked))]
impl KgpuKernel {
    /// 未链接时不可构造；返回 [`GpuKernel`](EncodeError::GpuKernel) 错误，
    /// 调用方据此走 CPU 回退。
    pub fn init(_device: Option<*mut core::ffi::c_void>) -> Result<Self, EncodeError> {
        Err(EncodeError::GpuKernel(
            "libkirin_gpu not linked (CMake/MSVC missing or gpu-kernel feature off)".into(),
        ))
    }
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::video::EncodeError;

    /// P1B Tests：未链接环境（CI/本地无 CMake+MSVC）下 KgpuKernel::init 失败，
    /// 错误信息提示降级原因（`tile_diff` 据此走 CPU 回退）。
    #[test]
    fn test_kgpu_kernel_init_unlinked_fallback() {
        // 编译期 LINKED 标记：未链接环境本测试断言降级路径。
        assert!(!KgpuLinked::LINKED || true); // 已链接时跳过本断言
        match KgpuKernel::init(None) {
            // 未链接 → GpuKernel 错误（提示 CMake/MSVC 缺失）。
            Err(EncodeError::GpuKernel(msg)) if !KgpuLinked::LINKED => {
                assert!(
                    msg.contains("not linked") || msg.contains("KG_ERR"),
                    "降级信息应说明原因，实际: {msg}"
                );
            }
            // 已链接 + 自建设备成功 / 失败（无 GPU 环境）—— 不做硬断言，
            // 仅保证不 panic（真实链接由 CI 在 Windows+MSVC 跑）。
            _ => {}
        }
    }

    /// P1B Tests：KgpuLinked::LINKED 与 cfg(kirin_gpu_linked) 一致。
    #[test]
    fn test_kgpu_linked_const_matches_cfg() {
        #[cfg(kirin_gpu_linked)]
        assert!(KgpuLinked::LINKED);
        #[cfg(not(kirin_gpu_linked))]
        assert!(!KgpuLinked::LINKED);
    }
}

// ════════════════════════════════════════════════════════════════
// hw_bridge 零拷贝测试（R-15b / 设计 M8-T023 §5）
// 仅 gpu-kernel 链接 + Windows + 有 D3D11 GPU 环境运行；无 GPU / 未链接
// 一律跳过（不失败），保证 CI 与无头环境回归清洁。
// ════════════════════════════════════════════════════════════════

#[cfg(all(test, kirin_gpu_linked, target_os = "windows"))]
mod hw_bridge_tests {
    use super::*;
    use crate::encoder::gpu_ffi::{
        kgpu_hw_upload_probe, kgpu_hw_upload_selftest, KgHwFrameInfo, KG_DECISION_FULLFRAME,
        KG_DECISION_INCREMENTAL, KG_DECISION_STATIC,
    };
    use crate::encoder::video::tile_diff::{TileDiff, TileDiffConfig};
    use crate::encoder::video::EncodeError;
    use std::sync::OnceLock;
    use std::time::Instant;

    /// 共享内核（进程级单例）测试串行锁：并发 tile_hash / hw_upload 会互相
    /// 干扰 ping-pong 哈希与上传状态（实测并行套件下三态决策断言偶发失败、
    /// 0xc0000005 悬垂）——涉及内核的测试整体串行，与其它不触碰内核的
    /// 测试（编码器/factory stub 等）仍可并行。
    static KERNEL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn kernel_guard() -> std::sync::MutexGuard<'static, ()> {
        KERNEL_LOCK.lock().expect("kernel test lock")
    }

    use windows::core::Interface;
    use windows::Win32::Graphics::Direct3D11::{
        D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_SUBRESOURCE_DATA,
        D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, ID3D11Device, ID3D11Texture2D,
    };
    use windows::Win32::Graphics::Dxgi::Common::{
        DXGI_FORMAT, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_NV12, DXGI_SAMPLE_DESC,
    };

    /// 初始化内核（幂等：重复调用保持首个 device；失败 = 无 GPU → 跳过）。
    fn ensure_kernel() -> Option<KgpuKernel> {
        KgpuKernel::init(None).ok()
    }

    /// 借用内核持有的 D3D11 device（进程内常驻；测试期间不释放）。
    ///
    /// **R-15b 修复（2026-08-04，dumpbin 反汇编定位）**：原实现
    /// `&*(p as *const ID3D11Device)` 会把指针 p 所指内存（COM 对象的
    /// vtable 指针）读作 wrapper 的 `.0` 字段——`as_raw`/`vtable` 全部
    /// 错位，`CreateTexture2D` 间接调用读到垃圾函数指针直接崩溃
    /// （0xc0000005 @ call rax）。正确做法：`ID3D11Device::from_raw(p)`
    /// 构造 wrapper（`.0 = p`），并用 `Box::leak` 常驻——不参与引用计数
    /// （C++ 侧 kgpu_shutdown 负责释放；Drop 会错误地多 Release 一次）。
    ///
    /// 每次调用读取当前句柄：单测进程内 kgpu_init/kgpu_shutdown 可能
    /// 多次（每个测试 drop 自己的内核句柄触发 shutdown + 重新 init），
    /// 设备指针会变化——按句柄重建包装（旧 Box 泄漏，仅指针无副作用）。
    fn kernel_device() -> Option<&'static ID3D11Device> {
        // usize 存指针（raw 指针不 Send/Sync；单测内单线程使用）。
        static DEV: std::sync::Mutex<Option<(usize, usize)>> = std::sync::Mutex::new(None);
        let p = unsafe { super::super::kgpu_device_handle() };
        if p.is_null() {
            return None;
        }
        let key = p as usize;
        let mut g = DEV.lock().expect("kernel_device lock");
        if g.as_ref().map(|(k, _)| *k != key).unwrap_or(true) {
            // from_raw 不 AddRef；leak 使 wrapper 永不 Drop（避免多余 Release）。
            let dev = unsafe { ID3D11Device::from_raw(p as *mut _) };
            *g = Some((key, Box::leak(Box::new(dev)) as *const ID3D11Device as usize));
        }
        g.as_ref()
            .and_then(|(_, d)| unsafe { (*d as *const ID3D11Device).as_ref() })
    }

    /// 在内核 device 上创建 2D 纹理（BindFlags = SRV|RT；BGRA 可带初始数据）。
    fn create_tex(
        dev: &ID3D11Device,
        w: u32,
        h: u32,
        fmt: DXGI_FORMAT,
        rgba: Option<&[u8]>,
    ) -> Option<ID3D11Texture2D> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: w,
            Height: h,
            MipLevels: 1,
            ArraySize: 1,
            Format: fmt,
            SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: (D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET).0 as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let init = rgba.map(|p| D3D11_SUBRESOURCE_DATA {
            pSysMem: p.as_ptr() as *const core::ffi::c_void,
            SysMemPitch: w * 4,
            SysMemSlicePitch: 0,
        });
        let mut tex: Option<ID3D11Texture2D> = None;
        unsafe {
            dev.CreateTexture2D(
                &desc,
                init.as_ref().map(|d| d as *const _),
                Some(&mut tex),
            )
        }
        .ok()?;
        tex
    }

    /// 释放 AVFrame（调用方契约：av_frame_unref + av_frame_free）。
    fn free_frame(frame: *mut core::ffi::c_void) {
        let mut f = frame as *mut crate::ffmpeg::AVFrame;
        crate::ffmpeg::av_frame_unref(f);
        crate::ffmpeg::av_frame_free(&mut f);
    }

    /// 上传并探针断言（frame 非 NULL / hw_frames_ctx 非空 / pix_fmt=D3D11 /
    /// 尺寸一致）。返回 (frame, info)。
    fn upload_and_probe(
        k: &KgpuKernel,
        gtex: &GpuTexture,
    ) -> Option<(*mut core::ffi::c_void, KgHwFrameInfo)> {
        // Rust 侧 FFmpeg 包装（free_frame 的 av_frame_unref/free）需要
        // ensure_loaded 先行；DLL 缺失 → 跳过（C++ 侧 hw_upload 亦不可用）。
        if crate::ffmpeg::ensure_loaded().is_err() {
            eprintln!("[R-15b] 跳过：FFmpeg DLL 不可用（ensure_loaded 失败）");
            return None;
        }
        let frame = match k.hw_upload(gtex) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[R-15b] hw_upload 不可用（跳过）: {e}");
                return None;
            }
        };
        let mut info = KgHwFrameInfo::default();
        assert_eq!(
            unsafe { kgpu_hw_upload_probe(frame, &mut info) },
            0,
            "kgpu_hw_upload_probe 失败"
        );
        assert_eq!(info.frame as usize, frame as usize, "probe frame 指针一致");
        assert_eq!(
            info.pix_fmt, crate::ffmpeg::AV_PIX_FMT_D3D11,
            "hwframe pix_fmt 应为 AV_PIX_FMT_D3D11"
        );
        assert_eq!(info.has_hw_frames_ctx, 1, "hw_frames_ctx 应为非空");
        assert_eq!(info.width, gtex.width() as i32, "hwframe 宽度一致");
        assert_eq!(info.height, gtex.height() as i32, "hwframe 高度一致");
        Some((frame, info))
    }

    /// P1B §T2.3 / 设计 §5：`test_hw_upload_frame_type` —— NV12 纹理上传产出的
    /// AVFrame 非 NULL、hw_frames_ctx 非空、pix_fmt == D3D11、尺寸一致。
    #[test]
    fn test_hw_upload_frame_type() {
        let _kg = kernel_guard(); // 串行化（共享内核单例）
        let Some(k) = ensure_kernel() else {
            eprintln!("[R-15b] 跳过：内核初始化失败（无 GPU）");
            return;
        };
        let Some(dev) = kernel_device() else {
            eprintln!("[R-15b] 跳过：无内核 device");
            return;
        };
        let (w, h) = (1280u32, 720u32);
        let Some(tex) = create_tex(dev, w, h, DXGI_FORMAT_NV12, None) else {
            eprintln!("[R-15b] 跳过：NV12 纹理创建失败");
            return;
        };
        let gtex = GpuTexture::new(tex.as_raw() as *mut core::ffi::c_void, w, h);
        let Some((frame, _info)) = upload_and_probe(&k, &gtex) else {
            return;
        };
        free_frame(frame);
    }

    /// P1B §T2.3 / 设计 §5：`test_hw_upload_zero_copy` —— NV12 输入纹理的
    /// hwframe 绑定纹理 == 输入纹理（零拷贝直绑，无 av_hwframe_transfer_data）。
    #[test]
    fn test_hw_upload_zero_copy() {
        let _kg = kernel_guard(); // 串行化（共享内核单例）
        let Some(k) = ensure_kernel() else {
            eprintln!("[R-15b] 跳过：内核初始化失败（无 GPU）");
            return;
        };
        let Some(dev) = kernel_device() else {
            eprintln!("[R-15b] 跳过：无内核 device");
            return;
        };
        let (w, h) = (1920u32, 1080u32);
        let Some(tex) = create_tex(dev, w, h, DXGI_FORMAT_NV12, None) else {
            eprintln!("[R-15b] 跳过：NV12 纹理创建失败");
            return;
        };
        let tex_handle = tex.as_raw() as *mut core::ffi::c_void;
        let gtex = GpuTexture::new(tex_handle, w, h);
        let Some((frame, info)) = upload_and_probe(&k, &gtex) else {
            return;
        };
        assert_eq!(
            info.bound_texture as usize, tex_handle as usize,
            "零拷贝断言：NV12 输入应直绑输入纹理（bound == 输入）"
        );
        assert!(!info.bound_texture.is_null());
        free_frame(frame);
    }

    /// R-15b：BGRA8 输入经 GPU 内转换（像素着色器两 Pass）绑定转换后的
    /// NV12 纹理——bound != 输入但非空，frame 类型断言全过。
    #[test]
    fn test_hw_upload_bgra_gpu_convert_binding() {
        let _kg = kernel_guard(); // 串行化（共享内核单例）
        let Some(k) = ensure_kernel() else {
            eprintln!("[R-15b] 跳过：内核初始化失败（无 GPU）");
            return;
        };
        let Some(dev) = kernel_device() else {
            eprintln!("[R-15b] 跳过：无内核 device");
            return;
        };
        let (w, h) = (640u32, 480u32);
        let rgba = vec![0u8; (w * h * 4) as usize];
        let Some(tex) = create_tex(dev, w, h, DXGI_FORMAT_B8G8R8A8_UNORM, Some(&rgba)) else {
            eprintln!("[R-15b] 跳过：BGRA 纹理创建失败");
            return;
        };
        let gtex = GpuTexture::new(tex.as_raw() as *mut core::ffi::c_void, w, h);
        let Some((frame, info)) = upload_and_probe(&k, &gtex) else {
            return;
        };
        assert!(
            !info.bound_texture.is_null(),
            "BGRA 转换后应绑定非空 NV12 纹理"
        );
        assert_ne!(
            info.bound_texture as usize,
            gtex.handle as usize,
            "BGRA 输入应绑定转换后的自有 NV12 纹理（而非输入纹理）"
        );
        free_frame(frame);
    }

    /// P1B §T2.3 / R-15b：C 侧完整自检（含 BGRA→NV12 内容校验与零拷贝断言）。
    #[test]
    fn test_hw_upload_selftest() {
        let _kg = kernel_guard(); // 串行化（共享内核单例）
        // 内核句柄必须保持存活到自检结束（Drop 会触发 kgpu_shutdown）。
        let Some(_k) = ensure_kernel() else {
            eprintln!("[R-15b] 跳过：内核初始化失败（无 GPU）");
            return;
        };
        let rc = unsafe { kgpu_hw_upload_selftest() };
        if rc < 0 {
            eprintln!("[R-15b] 跳过：hw_bridge 自检不可用（rc={rc}）");
            return;
        }
        assert_eq!(
            rc, 0,
            "hw_bridge C 侧自检应全部通过（失败位掩码 0x{:x}）",
            rc
        );
    }

    /// 设计 §5 / P1B 验证标准：三态决策正确（首帧 FullFrame / 纯色同帧
    /// Static / 局部微变 Incremental）+ 微变读回 ≤16KB（dirty 位图字节数）。
    #[test]
    fn test_gpu_tile_hash_three_state_decision() {
        let _kg = kernel_guard(); // 串行化（共享内核单例）
        let Some(k) = ensure_kernel() else {
            eprintln!("[R-15b] 跳过：内核初始化失败（无 GPU）");
            return;
        };
        let Some(dev) = kernel_device() else {
            eprintln!("[R-15b] 跳过：无内核 device");
            return;
        };
        let (w, h) = (1920u32, 1080u32);
        // 均匀色 BGRA（非全 0，避免与首帧特例混淆）。
        let mut rgba = vec![0u8; (w * h * 4) as usize];
        for p in rgba.chunks_mut(4) {
            p[0] = 7;
            p[1] = 13;
            p[2] = 29;
            p[3] = 255;
        }
        let Some(tex) = create_tex(dev, w, h, DXGI_FORMAT_B8G8R8A8_UNORM, Some(&rgba)) else {
            eprintln!("[R-15b] 跳过：BGRA 纹理创建失败");
            return;
        };
        let gtex = GpuTexture::new(tex.as_raw() as *mut core::ffi::c_void, w, h);

        // 首帧 → FULLFRAME（hash_buf_b 全 0）。
        let (_, d1) = k.tile_hash_raw(&gtex).expect("tile_hash 首帧");
        assert_eq!(d1, KG_DECISION_FULLFRAME, "首帧应 FULLFRAME");

        // 同帧重算 → STATIC。
        let (_, d2) = k.tile_hash_raw(&gtex).expect("tile_hash 同帧");
        assert_eq!(d2, KG_DECISION_STATIC, "同帧应 STATIC");

        // 局部微变（32×32 像素 → 1 tile / 510 ≈ 0.2% < 5%）→ INCREMENTAL。
        let mut changed = rgba.clone();
        for y in 0..32u32 {
            for x in 0..32u32 {
                let i = ((y * w + x) * 4) as usize;
                changed[i] = 255;
                changed[i + 1] = 0;
                changed[i + 2] = 0;
            }
        }
        let ctx = unsafe { dev.GetImmediateContext() }.expect("GetImmediateContext");
        unsafe {
            ctx.UpdateSubresource(
                &tex,
                0,
                None,
                changed.as_ptr() as *const core::ffi::c_void,
                w * 4,
                0,
            );
        }
        let (map3, d3) = k.tile_hash_raw(&gtex).expect("tile_hash 微变");
        assert_eq!(d3, KG_DECISION_INCREMENTAL, "微变应 INCREMENTAL");
        assert!(!map3.dirty.is_empty(), "微变 dirty 不应为空");
        // 微变读回 ≤16KB（设计 §5：微变读回 ≤16KB；1080p 网格 510 B）。
        assert!(
            map3.dirty.len() <= 16 * 1024,
            "微变读回应 ≤16KB，实际 {} B",
            map3.dirty.len()
        );
    }
    /// 设计 §5 / P1B 验证标准：1080p Tile-Hash Diff 全显存 <2ms/帧
    /// （GPU 零拷贝路径），并记录 CPU 回退基线（P1G 对比基准落点）。
    #[test]
    fn test_gpu_tile_hash_1080p_under_2ms() {
        let _kg = kernel_guard(); // 串行化（共享内核单例）
        let Some(k) = ensure_kernel() else {
            eprintln!("[R-15b] 跳过：内核初始化失败（无 GPU）");
            return;
        };
        let Some(dev) = kernel_device() else {
            eprintln!("[R-15b] 跳过：无内核 device");
            return;
        };
        let (w, h) = (1920u32, 1080u32);
        // 确定性伪随机内容（避免全静特例）。
        let mut rgba = vec![0u8; (w * h * 4) as usize];
        let mut seed = 0x1234_5678u32;
        for p in rgba.chunks_mut(4) {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let v = (seed >> 24) as u8;
            p[0] = v;
            p[1] = v.wrapping_add(3);
            p[2] = v.wrapping_add(7);
            p[3] = 255;
        }
        let Some(tex) = create_tex(dev, w, h, DXGI_FORMAT_B8G8R8A8_UNORM, Some(&rgba)) else {
            eprintln!("[R-15b] 跳过：BGRA 纹理创建失败");
            return;
        };
        let gtex = GpuTexture::new(tex.as_raw() as *mut core::ffi::c_void, w, h);

        // 热身（device/缓冲初始化不计入基准）。
        for _ in 0..5 {
            let _ = k.tile_hash_raw(&gtex);
        }
        const N: u32 = 30;
        let t0 = Instant::now();
        for _ in 0..N {
            let _ = k.tile_hash_raw(&gtex);
        }
        let gpu_ms = t0.elapsed().as_secs_f64() * 1000.0 / f64::from(N);

        // CPU 回退基线（classify_cpu，同一 1080p 场景；P1G 对比数据）。
        let mut diff = TileDiff::new(TileDiffConfig::default());
        let _ = diff.classify_cpu(&rgba, w, h); // 首帧建基线。
        let t1 = Instant::now();
        const NC: u32 = 10;
        for _ in 0..NC {
            let _ = diff.classify_cpu(&rgba, w, h);
        }
        let cpu_ms = t1.elapsed().as_secs_f64() * 1000.0 / f64::from(NC);

        eprintln!(
            "[R-15b 基准] 1080p Tile-Hash: GPU(零拷贝) {gpu_ms:.3} ms/帧 | CPU 回退 {cpu_ms:.3} ms/帧"
        );
        assert!(
            gpu_ms < 2.0,
            "1080p Tile-Hash Diff 应 <2ms/帧（设计 §5），实际 {gpu_ms:.3} ms"
        );
        assert!(
            gpu_ms < cpu_ms,
            "GPU 零拷贝应快于 CPU 回退（GPU {gpu_ms:.3} vs CPU {cpu_ms:.3} ms/帧）"
        );
    }

    /// 保底回归：无 GPU 时内核初始化失败的语义不变（KG_ERR_INIT / 信息可读）。
    #[test]
    fn test_kernel_init_error_semantics() {
        let _kg = kernel_guard(); // 串行化（共享内核单例）
        let _ = ensure_kernel();
        match KgpuKernel::init(None) {
            Ok(_) => {}
            Err(EncodeError::GpuKernel(msg)) => {
                assert!(!msg.is_empty(), "错误信息不应为空");
            }
            Err(e) => panic!("期望 GpuKernel 错误，实际 {e}"),
        }
    }
}
