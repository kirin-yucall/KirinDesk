//! GPU 内核 FFI 绑定（P1B §T2.4）。
//!
//! 根级 C++ 工程 `libkirin_gpu/` 的 Rust 薄 FFI 绑定，承载：
//! - [`KgpuKernel`]：[`GpuKernel`] trait 实现（init / tile_hash / blit_rle /
//!   hw_upload / dirty_indices），RAII 持有 `kgpu_shutdown` 调用权。
//! - 错误码映射：`KG_ERR_*` → [`EncodeError::GpuKernel`] / `InvalidConfig`。
//!
//! # 链接状态：`cfg(kirin_gpu_linked)`
//!
//! `build.rs` 检测到 CMake + 工具链可用时（且启用 `gpu-kernel` feature），
//! emit `cargo:rustc-cfg=kirin_gpu_linked`；否则**不链接** libkirin_gpu，
//! 本模块降级为"纯接口"：[`KgpuKernel::init`] 返回 [`EncodeError::GpuKernel`]
//! （`tile_diff` 随即走 CPU 回退路径），不阻断 `cargo build`。
//!
//! # 边界
//!
//! - 单线程调用：编码线程独占；`unsafe impl Send/Sync` 仅当 C++ 侧内部互斥
//!   （`kgpu_*` 内 `std::mutex` 保护）。
//! - `GpuTexture.handle == null` → [`EncodeError::InvalidConfig`]。
//! - device lost（`KG_ERR_DEVICE`）→ [`EncodeError::GpuKernel`]，P1C 触发
//!   编码器失效回退。
//!
//! [`GpuKernel`]: crate::encoder::video::tile_diff::GpuKernel

pub mod kernel;

pub use kernel::{KgpuKernel, KgpuLinked};

// ════════════════════════════════════════════════════════════════
// C ABI 错误码（与 include/kirin_gpu.h 保持一致）
// ════════════════════════════════════════════════════════════════

pub const KG_OK: i32 = 0;
pub const KG_ERR_INIT: i32 = -1;
pub const KG_ERR_PARAM: i32 = -2;
pub const KG_ERR_DEVICE: i32 = -3;
pub const KG_ERR_NOTIMPL: i32 = -4;

pub const KG_DECISION_STATIC: i32 = 0;
pub const KG_DECISION_INCREMENTAL: i32 = 1;
pub const KG_DECISION_FULLFRAME: i32 = 2;

/// C 侧 `KgTileMap`（与 `include/kirin_gpu.h` 布局一致）。
///
/// `dirty` 由 C++ 侧分配，本结构只持有裸指针 + 长度；读取时用
/// [`as_dirty_slice`](Self::as_dirty_slice) 安全切片。
#[repr(C)]
#[derive(Debug)]
pub struct KgTileMap {
    pub tile_w: u32,
    pub tile_h: u32,
    pub grid_w: u32,
    pub grid_h: u32,
    pub dirty: *mut u8,
    pub dirty_ratio: f32,
}

impl Default for KgTileMap {
    fn default() -> Self {
        Self {
            tile_w: 64,
            tile_h: 64,
            grid_w: 0,
            grid_h: 0,
            dirty: core::ptr::null_mut(),
            dirty_ratio: 0.0,
        }
    }
}

impl KgTileMap {
    /// `dirty` 切片（长度 = `grid_w * grid_h`）。null / 0 长度时返回空切片。
    ///
    /// # Safety
    ///
    /// 调用方须保证 `dirty` 来自 `kgpu_tile_hash` 返回的有效指针（C++ 侧
    /// 持有，下一次 `tile_hash` / `shutdown` 失效）。
    pub unsafe fn as_dirty_slice(&self) -> &[u8] {
        if self.dirty.is_null() {
            return &[];
        }
        let len = (self.grid_w as usize) * (self.grid_h as usize);
        if len == 0 {
            return &[];
        }
        unsafe { core::slice::from_raw_parts(self.dirty, len) }
    }
}

// ════════════════════════════════════════════════════════════════
// extern "C" 声明（仅 kirin_gpu_linked 时链接；否则符号不解析）
// ════════════════════════════════════════════════════════════════

#[cfg(kirin_gpu_linked)]
#[link(name = "kirin_gpu", kind = "static")]
extern "C" {
    /// `device_handle` 平台语义：Windows=ID3D11Device* / Linux=VkDevice(待) /
    /// macOS=MTLDevice(待)。NULL → 自建 device。
    pub(crate) fn kgpu_init(device_handle: *mut core::ffi::c_void) -> i32;
    pub(crate) fn kgpu_shutdown();
    pub(crate) fn kgpu_tile_hash(
        texture: *mut core::ffi::c_void,
        out: *mut KgTileMap,
        decision: *mut i32,
    ) -> i32;
    pub(crate) fn kgpu_blit_tiles_rle(
        texture: *mut core::ffi::c_void,
        map: *const KgTileMap,
        out: *mut u8,
        out_len: *mut u32,
    ) -> i32;
    pub(crate) fn kgpu_hw_upload(texture: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    pub(crate) fn kgpu_dirty_indices(
        texture: *mut core::ffi::c_void,
        out_idx: *mut u32,
        out_count: *mut u32,
    ) -> i32;

    // RLE 编解码（blit_rle.cpp 导出，供 Rust 单测覆盖一致算法）。
    pub(crate) fn kgpu_rle_encode(src: *const u8, src_len: u32, dst: *mut u8, dst_cap: u32) -> u32;
    pub(crate) fn kgpu_rle_decode(src: *const u8, src_len: u32, dst: *mut u8, dst_cap: u32) -> u32;
}

/// 错误码 → `EncodeError`。
///
/// - `KG_OK` → `Ok(())`
/// - `KG_ERR_PARAM` → [`InvalidConfig`](EncodeError::InvalidConfig)
/// - 其它 → [`GpuKernel`](EncodeError::GpuKernel)（含可读上下文）
//
// 仅在 `cfg(kirin_gpu_linked)` 下被 `kernel.rs` 调用；未链接时本函数无调用点，
// `#[allow(dead_code)]` 抑制警告（保留以备链接后立即生效）。
#[allow(dead_code)]
pub(crate) fn map_err(code: i32, ctx: &str) -> Result<(), crate::encoder::video::EncodeError> {
    use crate::encoder::video::EncodeError;
    match code {
        KG_OK => Ok(()),
        KG_ERR_PARAM => Err(EncodeError::InvalidConfig(format!("{ctx}: KG_ERR_PARAM"))),
        KG_ERR_INIT => Err(EncodeError::GpuKernel(format!("{ctx}: KG_ERR_INIT"))),
        KG_ERR_DEVICE => Err(EncodeError::GpuKernel(format!("{ctx}: KG_ERR_DEVICE"))),
        KG_ERR_NOTIMPL => Err(EncodeError::GpuKernel(format!("{ctx}: KG_ERR_NOTIMPL"))),
        other => Err(EncodeError::GpuKernel(format!(
            "{ctx}: unknown kgpu code {other}"
        ))),
    }
}

/// 决策码 → `EncodeDecision`（仅做映射，不构造 map；map 由调用方组装）。
//
// 诊断辅助；未链接时无调用点，`#[allow(dead_code)]` 抑制警告。
#[allow(dead_code)]
pub(crate) fn decision_code_to_str(code: i32) -> &'static str {
    match code {
        KG_DECISION_STATIC => "Static",
        KG_DECISION_INCREMENTAL => "Incremental",
        KG_DECISION_FULLFRAME => "FullFrame",
        _ => "Unknown",
    }
}

// ════════════════════════════════════════════════════════════════
// 纯 Rust RLE（未链接时的等价实现，与 blit_rle.cpp 完全一致）
// ════════════════════════════════════════════════════════════════
//
// 供 cpu_fallback 路径与单测使用；保证链接与否算法一致（断言见 tests）。

/// RLE 编码（与 `kgpu_rle_encode` 等价）：`[count:u8][value:u8] * N`。
/// 返回压缩后字节数；`dst` 容量不足返回 0。
pub fn rle_encode_rust(src: &[u8], dst: &mut [u8]) -> u32 {
    let mut oi = 0u32;
    let mut i = 0usize;
    while i < src.len() {
        let v = src[i];
        let mut run: u32 = 1;
        while run < 255 {
            let next = i + run as usize;
            if next >= src.len() || src[next] != v {
                break;
            }
            run += 1;
        }
        if oi as usize + 1 >= dst.len() {
            return 0;
        }
        dst[oi as usize] = run as u8;
        dst[oi as usize + 1] = v;
        oi += 2;
        i += run as usize;
    }
    oi
}

/// RLE 解码（与 `kgpu_rle_decode` 等价）。返回解压后字节数；
/// 源长度非偶 / `dst` 不足返回 `u32::MAX`。
pub fn rle_decode_rust(src: &[u8], dst: &mut [u8]) -> u32 {
    if src.len() & 1 != 0 {
        return u32::MAX;
    }
    let mut oi = 0u32;
    let mut i = 0usize;
    while i + 1 < src.len() {
        let count = src[i] as usize;
        let v = src[i + 1];
        if oi as usize + count > dst.len() {
            return u32::MAX;
        }
        for k in 0..count {
            dst[oi as usize + k] = v;
        }
        oi += count as u32;
        i += 2;
    }
    oi
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rle_roundtrip_rust() {
        // 已知图案 → 压缩 → 解压后逐字节一致。
        let raw: Vec<u8> = (0..256)
            .map(|i| if i % 64 < 32 { 0xAA } else { 0x55 })
            .collect();
        let mut comp = vec![0u8; raw.len() * 2];
        let n = rle_encode_rust(&raw, &mut comp);
        assert!(n > 0, "压缩应成功");
        assert!(
            (n as usize) < raw.len(),
            "对大块纯色应明显压缩: comp={} raw={}",
            n,
            raw.len()
        );
        let mut dec = vec![0u8; raw.len()];
        let d = rle_decode_rust(&comp[..n as usize], &mut dec);
        assert_eq!(d, raw.len() as u32);
        assert_eq!(&dec[..], &raw[..], "解压后应与原数据逐字节一致");
    }

    #[test]
    fn test_rle_solid_color_ratio() {
        // 纯色屏 RLE 压缩比 ≥ 95%（字节 << 原始）。
        let raw = vec![0x42u8; 4096];
        let mut comp = vec![0u8; raw.len() * 2];
        let n = rle_encode_rust(&raw, &mut comp);
        assert!(n > 0);
        let ratio = n as f32 / raw.len() as f32;
        assert!(ratio < 0.05, "压缩比应 ≥ 95%（实际压缩率 {:.4}）", ratio);
    }

    #[test]
    fn test_rle_uneven_source_decode_fails() {
        // 奇数长度源 → 解码失败（u32::MAX）。
        let bad = [1u8, 2, 3];
        let mut dst = [0u8; 16];
        assert_eq!(rle_decode_rust(&bad, &mut dst), u32::MAX);
    }

    #[test]
    fn test_kg_tile_map_default_and_slice() {
        let m = KgTileMap::default();
        assert_eq!(m.tile_w, 64);
        assert!(unsafe { m.as_dirty_slice() }.is_empty()); // null → 空
    }
}
