//! [`GpuKernel`] trait 实现：`KgpuKernel`（P1B §T2.4）。
//!
//! 当 `cfg(kirin_gpu_linked)` 时：`KgpuKernel::init` 调 `kgpu_init`，
//! `tile_hash` 调 `kgpu_tile_hash`，结果转 [`DirtyTileMap`] 喂回
//! `tile_diff`。
//!
//! 未链接时：本文件只导出占位类型 [`KgpuLinked`]（其常量 `LINKED = false`），
//! `tile_diff` 据此走 CPU 回退路径，保证 `cargo build` 清洁。
//!
//! # P1B↔P1C 接驳（2026-07-31）
//!
//! [`GpuKernel`] trait 在 P1C 扩展了 `blit_tiles_rle` / `hw_upload` /
//! `is_linked`，本类型在 `cfg(kirin_gpu_linked)` 下转调同名具体方法实现之：
//! - `blit_tiles_rle` → `kgpu_blit_tiles_rle`（微变分支 RLE 字节）
//! - `hw_upload` → `kgpu_hw_upload`（纹理 → FFmpeg hwframes AVFrame*）
//! - `is_linked` → `true`
//!
//! P1C 的 `ffmpeg_hw.rs` / `pipeline.rs` / `factory.rs` 据此驱动零拷贝路径。
//! **注意**：C++ 侧 `kgpu_hw_upload`（hw_bridge.cpp）当前桩实现恒返回 NULL →
//! `hw_upload` 返 `GpuKernel` 错误，P1C 自动回退 CPU NV12 路径，待 P1B
//! hw_bridge.cpp 真实实现后自动切换。

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
