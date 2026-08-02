//! 决策逻辑：Tile-Hash Diff（P1A §T1.2）。
//!
//! 把 [`DirtyTileMap`] 转成 [`EncodeDecision`]（全静 / 微变 / 大动）。
//! 实际的 hash/diff 由 GPU 内核（P1B，[`GpuKernel`] trait）在显存内完成；
//! kernel 缺省时走 CPU 回退（[`TileDiff::cpu_tile_hash`]）。
//!
//! # P1A 现状
//!
//! - `GpuTexture.handle` 是 opaque 指针（D3D11/VAAPI），本阶段没有 C++ 内核
//!   把它读回内存；因此 [`TileDiff::cpu_tile_hash`] 在缺内核时返回
//!   [`GpuKernel`](EncodeError::GpuKernel) 错误而不是伪造数据。
//! - 决策分级逻辑（[`TileDiff::decide`]/[`merge_regions`]）是**纯 CPU + 可测**
//!   的，所有 P1A 单测都走这条路径（构造 `DirtyTileMap` 直接喂入）。
//! - 首帧 / 分辨率变化 / 全静连续帧等 Edge Cases 在 [`TileDiff::decide`] 内处理。

use super::EncodeError;
use crate::encoder::types::{DirtyTileMap, EncodeDecision, GpuTexture, TileRegion};

// ════════════════════════════════════════════════════════════════
// TileDiffConfig
// ════════════════════════════════════════════════════════════════

/// 决策阈值（可调，默认按设计文档：64×64 tile，5% 微变上限）。
#[derive(Debug, Clone, Copy)]
pub struct TileDiffConfig {
    /// tile 尺寸（像素，默认 64）。
    pub tile_w: u32,
    /// tile 尺寸（像素，默认 64）。
    pub tile_h: u32,
    /// 微变上限（默认 0.05 = 5%）。`dirty_ratio < incremental_ratio` → 微变。
    pub incremental_ratio: f32,
}

impl Default for TileDiffConfig {
    fn default() -> Self {
        Self {
            tile_w: 64,
            tile_h: 64,
            incremental_ratio: 0.05,
        }
    }
}

// ════════════════════════════════════════════════════════════════
// TileDiff — 决策器
// ════════════════════════════════════════════════════════════════

/// 决策器：把 [`DirtyTileMap`] 转成 [`EncodeDecision`]。
///
/// 实际 hash/diff 由 GPU 内核（P1B）或 CPU 回退完成；本结构只持有阈值与
/// 上一帧的网格信息（用于首帧 / 分辨率变化判定）。
pub struct TileDiff {
    cfg: TileDiffConfig,
    /// 上一帧 tile hash（GPU 内核模式哨兵：`None` = 首帧，全量 dirty）。
    ///
    /// P1A 阶段：真实 hash 由 GPU 内核（P1B）产出；本字段用作"是否首帧"
    /// 的哨兵。P1B 接入后存储实际 hash 值。
    prev_hash: Option<Vec<u64>>,
    /// 上次见到的网格尺寸（用于检测分辨率变化 → 重置）。
    last_grid: Option<(u32, u32)>,
    /// M8-T030（R-06）：CPU 兜底路径的上一帧 tile hash（真实 CRC32 值，
    /// 由 [`cpu_tile_hash_rgba`](Self::cpu_tile_hash_rgba) 维护，与 `prev_hash`
    /// 哨兵解耦——`decide` 的首帧/分辨率变化逻辑不覆盖本字段）。
    cpu_prev: Option<Vec<u64>>,
}

impl TileDiff {
    /// 创建决策器。
    pub fn new(cfg: TileDiffConfig) -> Self {
        Self {
            cfg,
            prev_hash: None,
            last_grid: None,
            cpu_prev: None,
        }
    }

    /// 当前阈值配置（诊断/测试用）。
    pub fn cfg(&self) -> TileDiffConfig {
        self.cfg
    }

    /// 是否处于首帧（`prev_hash` 未初始化）。
    pub fn is_first_frame(&self) -> bool {
        self.prev_hash.is_none()
    }

    /// 主入口：对到达帧分级。
    ///
    /// - `kernel = Some(k)`：调 `k.tile_hash(tex)` 在 GPU 显存内完成 hash/diff
    /// - `kernel = None`：走 CPU 回退 [`cpu_tile_hash`]（P1A 阶段因无纹理读回
    ///   能力而返回 [`GpuKernel`](EncodeError::GpuKernel) 错误）
    ///
    /// 拿到 map 后统一进入 [`decide`](Self::decide) 分级。
    pub fn classify(
        &mut self,
        tex: &GpuTexture,
        kernel: Option<&dyn GpuKernel>,
    ) -> Result<EncodeDecision, EncodeError> {
        // Step 1: 计算 DirtyTileMap
        let map = match kernel {
            Some(k) => k.tile_hash(tex)?,
            None => self.cpu_tile_hash(tex)?,
        };
        // Step 2: 分级
        Ok(self.decide(map))
    }

    /// 决策分级（纯 CPU + 可测）：把一个 [`DirtyTileMap`] 转 [`EncodeDecision`]。
    ///
    /// 处理 Edge Cases：
    /// - 首帧（`prev_hash == None`）：全量 dirty → 大动，初始化哨兵
    /// - 分辨率变化（map 网格 ≠ `last_grid`）：重置哨兵，首帧按大动处理
    /// - `dirty_ratio` 为 NaN：当作全静（防御）
    /// - 全静连续帧：`prev_hash` 保持不变（不更新），节省开销
    ///
    /// 返回值归一化：`Static` / `Incremental(merge_regions(map))` / `FullFrame(map)`。
    pub fn decide(&mut self, mut map: DirtyTileMap) -> EncodeDecision {
        let grid = (map.grid_w, map.grid_h);

        // 首帧 / 分辨率变化：全量 dirty，按大动处理。
        let is_first_or_res_changed = self.prev_hash.is_none() || self.last_grid != Some(grid);
        if is_first_or_res_changed {
            let count = (map.grid_w as usize) * (map.grid_h as usize);
            map.dirty = vec![true; count];
            map.dirty_ratio = if count == 0 { 0.0 } else { 1.0 };
            // 初始化哨兵 + 记录网格；hash 值待 P1B 填实际数据。
            self.prev_hash = Some(vec![0u64; count]);
            self.last_grid = Some(grid);
            return EncodeDecision::FullFrame(map);
        }

        // NaN 防御：当作全静。
        if map.dirty_ratio.is_nan() {
            map.dirty_ratio = 0.0;
            map.dirty.iter_mut().for_each(|b| *b = false);
        }
        // 保证 ratio 与 dirty 一致（容错：调用方可能没算 ratio）。
        map.compute_ratio();
        let ratio = map.dirty_ratio;

        if ratio == 0.0 {
            // 全静：prev_hash 保持不变（Edge Case：节省更新开销）。
            EncodeDecision::Static
        } else if ratio < self.cfg.incremental_ratio {
            let regions = merge_regions(&map);
            EncodeDecision::Incremental(regions)
        } else {
            EncodeDecision::FullFrame(map)
        }
    }

    /// CPU 回退：把纹理读回内存逐 tile 计算（与 GPU hash 算法一致：
    /// 每 tile 采样点均值 + CRC32）。
    ///
    /// **现状**：`GpuTexture.handle` 为 opaque 指针，本函数无法读到像素——
    /// 纹理路径缺内核时仍返回 [`GpuKernel`](EncodeError::GpuKernel) 错误。
    /// M8-T030（R-06，GPU-FR-008）真实 CPU 兜底走
    /// [`cpu_tile_hash_rgba`](Self::cpu_tile_hash_rgba)（捕获层 CPU 帧 RGBA
    /// 直接喂入，见 [`classify_cpu`](Self::classify_cpu)）。
    fn cpu_tile_hash(&mut self, tex: &GpuTexture) -> Result<DirtyTileMap, EncodeError> {
        if tex.is_null() {
            return Err(EncodeError::InvalidConfig("null texture".into()));
        }
        // 无 P1B 纹理读回能力：交给上层提供 GPU 内核（kernel=Some）。
        Err(EncodeError::GpuKernel(
            "CPU tile-hash requires CPU frame data (call classify_cpu with RGBA)".into(),
        ))
    }

    /// **真实 CPU 兜底**（M8-T030 GPU-FR-008）：对 CPU 帧 RGBA 做逐 tile
    /// CRC32 哈希 + 与上一帧 diff，产出 [`DirtyTileMap`]。
    ///
    /// - 输入：捕获层 CPU 帧（BGRA8 `&[u8]` + 宽高，`CapturedFrame.data`）；
    ///   `GpuTexture` 为哨兵指针时不依赖纹理读回（设计文档 §3.7）。
    /// - 算法：按 `cfg.tile_w × tile_h`（默认 64×64）分块，每 tile 对全部
    ///   像素 RGBA 字节算 CRC32（全采样，与 GPU hash 语义一致——P1B
    ///   tile_hash_hlsl.h 全像素均值折叠进 CRC32），与 `cpu_prev` 帧间比对
    ///   → dirty map。
    /// - 首帧 / 分辨率变化（网格数变化）→ 全量 dirty（`decide` 亦按首帧处理）。
    /// - 触发条件：无 GPU 内核（`kernel = None` / 未链接）时的 CPU 路径
    ///   （pipeline 在 `tex.is_null()` 时经 [`classify_cpu`](Self::classify_cpu)
    ///   调用本函数）。
    fn cpu_tile_hash_rgba(
        &mut self,
        rgba: &[u8],
        w: u32,
        h: u32,
    ) -> Result<DirtyTileMap, EncodeError> {
        let (w, h) = (w as usize, h as usize);
        if rgba.len() < w.saturating_mul(h).saturating_mul(4) {
            return Err(EncodeError::InvalidConfig(
                "cpu tile-hash: frame buffer smaller than w*h*4".into(),
            ));
        }
        let tw = self.cfg.tile_w.max(1) as usize;
        let th = self.cfg.tile_h.max(1) as usize;
        let grid_w = w.div_ceil(tw).max(1);
        let grid_h = h.div_ceil(th).max(1);
        if w == 0 || h == 0 {
            return Err(EncodeError::InvalidConfig(
                "cpu tile-hash: zero-size frame".into(),
            ));
        }
        let count = grid_w * grid_h;
        let mut hashes = Vec::with_capacity(count);
        for ty in 0..grid_h {
            for tx in 0..grid_w {
                hashes.push(tile_crc32(rgba, w, h, tw, th, tx, ty) as u64);
            }
        }
        // 帧间 diff：首帧 / 网格变化 → 全量 dirty。
        let mut dirty = vec![true; count];
        let mut dirty_count = count;
        if let Some(prev) = &self.cpu_prev {
            if prev.len() == count {
                dirty_count = 0;
                for (i, &h) in hashes.iter().enumerate() {
                    if prev[i] == h {
                        dirty[i] = false;
                    } else {
                        dirty_count += 1;
                    }
                }
            }
        }
        self.cpu_prev = Some(hashes);
        let mut map = DirtyTileMap {
            tile_w: self.cfg.tile_w,
            tile_h: self.cfg.tile_h,
            grid_w: grid_w as u32,
            grid_h: grid_h as u32,
            dirty,
            dirty_ratio: dirty_count as f32 / count as f32,
        };
        map.compute_ratio();
        Ok(map)
    }

    /// **CPU 兜底决策入口**（M8-T030 GPU-FR-008 / R06-S7 验收）：无 GPU 内核
    /// 时对 CPU 帧 RGBA 走真实 tile-hash diff → 三态决策（全静/微变/大动）。
    ///
    /// pipeline 在 CPU 路径（`tex.is_null()`）调用；任何机器可用（环境无关）。
    pub fn classify_cpu(
        &mut self,
        rgba: &[u8],
        w: u32,
        h: u32,
    ) -> Result<EncodeDecision, EncodeError> {
        let map = self.cpu_tile_hash_rgba(rgba, w, h)?;
        Ok(self.decide(map))
    }
}

impl Default for TileDiff {
    fn default() -> Self {
        Self::new(TileDiffConfig::default())
    }
}

// ════════════════════════════════════════════════════════════════
// GpuKernel trait — GPU 内核接口（P1B 实现 C++ 侧）
// ════════════════════════════════════════════════════════════════

/// GPU 内核 trait（P1B 实现 C++ 侧；本阶段留接口 + CPU 回退）。
///
/// P1B 的 `libkirin_gpu` 通过 FFI 实现本 trait，把 `tile_hash`（Pass1 哈希 +
/// Pass2 diff + Pass3 脏块地图）全部在显存内完成，输出 [`DirtyTileMap`]。
///
/// # P1B↔P1C 接驳（2026-07-31）
///
/// trait 在 P1C 阶段扩展为完整 P1B 内核接口：除 [`tile_hash`](GpuKernel::tile_hash)
/// 外，新增 [`blit_tiles_rle`](GpuKernel::blit_tiles_rle) /
/// [`hw_upload`](GpuKernel::hw_upload) / [`is_linked`](GpuKernel::is_linked)。
/// P1C 的 [`crate::encoder::video::ffmpeg_hw::FfmpegHwEncoder`] /
/// [`crate::encoder::video::pipeline::VideoEncoderPipeline`] /
/// [`crate::encoder::factory::create_video_encoder`] 据此驱动零拷贝 hwframes
/// 与微变 RLE 增量。
///
/// 默认实现（`blit_tiles_rle`/`hw_upload` 返回 `Unsupported`、`is_linked` 返
/// `false`）保证既有 CPU-only 测试桩（如本文件 `StubKernel`）与未链接
/// `libkirin_gpu` 的环境编译/运行不受影响 —— 调用方据 `is_linked()` 自动降级。
pub trait GpuKernel: Send {
    /// 对纹理做 tile hash + 与上一帧 diff，产出 [`DirtyTileMap`]。
    fn tile_hash(&self, tex: &GpuTexture) -> Result<DirtyTileMap, EncodeError>;

    /// tile blit + RLE（仅微变分支调用）。返回压缩字节（KB 级）。
    ///
    /// 默认返回 [`Unsupported`](EncodeError::Unsupported)：CPU-only 内核 / 未链接
    /// `libkirin_gpu` 时调用方据 [`is_linked`](Self::is_linked) 短路，不进本路径。
    /// P1B 的 [`KgpuKernel`](crate::encoder::gpu_ffi::kernel::KgpuKernel) 在
    /// `cfg(kirin_gpu_linked)` 下实现真实路径（`kgpu_blit_tiles_rle`）。
    fn blit_tiles_rle(
        &self,
        _tex: &GpuTexture,
        _map: &DirtyTileMap,
    ) -> Result<Vec<u8>, EncodeError> {
        Err(EncodeError::Unsupported(
            "kernel does not support blit_tiles_rle (CPU-only / not linked)".into(),
        ))
    }

    /// 纹理 → FFmpeg hwframes 桥（返回 `AVFrame*`）。失败返回 `Unsupported`。
    ///
    /// 返回的 `AVFrame*` 由调用方（P1C `ffmpeg_hw.rs`）负责 `av_frame_unref` +
    /// `av_frame_free`。
    ///
    /// 默认返回 [`Unsupported`](EncodeError::Unsupported)：CPU-only 内核 / 未链接
    /// 时调用方据 [`is_linked`](Self::is_linked) 短路，回退 CPU NV12 路径。
    fn hw_upload(&self, _tex: &GpuTexture) -> Result<*mut std::ffi::c_void, EncodeError> {
        Err(EncodeError::Unsupported(
            "kernel does not support hw_upload (CPU-only / not linked)".into(),
        ))
    }

    /// 内核是否真实链接了 `libkirin_gpu`（即 C++ D3D11/VAAPI 后端可用）。
    ///
    /// `false`（默认）→ 调用方走 CPU 回退：tile_diff 用 [`TileDiff::cpu_tile_hash`]，
    /// 编码器走软编 / HW NV12 CPU 路径，微变分支止于坐标指令。
    /// `true` → 启用零拷贝 hwframes（HW 编码器优先）+ 微变 RLE append。
    fn is_linked(&self) -> bool {
        false
    }
}

// ════════════════════════════════════════════════════════════════
// CPU tile CRC32（M8-T030 GPU-FR-008；无外部依赖）
// ════════════════════════════════════════════════════════════════

/// CRC32（IEEE 802.3，poly 0xEDB88320）查表初始化。
fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB88320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *entry = c;
    }
    table
}

/// 逐 tile CRC32（**全采样**，与 GPU hash 语义一致——P1B `tile_hash_hlsl.h`
/// 每 8×8 子块全像素均值折叠进 CRC32；CPU 兜底对 tile 内全部像素的
/// RGBA 字节做 CRC32，无采样漏检）。
///
/// `x0/y0` 为 tile 起点；边缘 tile 超出帧边界部分 clamp（不越界）。
fn tile_crc32(
    rgba: &[u8],
    w: usize,
    h: usize,
    tw: usize,
    th: usize,
    tx: usize,
    ty: usize,
) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(crc32_table);
    let x_end = ((tx + 1) * tw).min(w);
    let y_end = ((ty + 1) * th).min(h);
    let mut c = 0xFFFF_FFFFu32;
    for y in (ty * th)..y_end {
        let row = &rgba[y * w * 4..y * w * 4 + x_end * 4];
        for &b in row[(tx * tw * 4)..].iter() {
            c = table[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
        }
    }
    c ^ 0xFFFF_FFFF
}

// ════════════════════════════════════════════════════════════════
// merge_regions — 邻接 tile 合并为矩形
// ════════════════════════════════════════════════════════════════

/// 邻接 tile 合并：同一行连续 dirty tile 合并为一个 [`TileRegion`]。
///
/// 输入 [`DirtyTileMap`]（行主序 dirty 数组），输出矩形列表。每个 region
/// 至少 1×1，宽度 = 同行连续 dirty tile 数；不做跨行合并（简化 + 与 RLE
/// 增量编码一致）。
pub fn merge_regions(map: &DirtyTileMap) -> Vec<TileRegion> {
    let mut regions = Vec::new();
    if map.grid_w == 0 || map.grid_h == 0 {
        return regions;
    }
    for row in 0..map.grid_h {
        let mut col = 0u32;
        while col < map.grid_w {
            let idx = (row * map.grid_w + col) as usize;
            if idx < map.dirty.len() && map.dirty[idx] {
                // 起始 col，向右吞并连续 dirty。
                let start = col;
                let mut end = col;
                while end + 1 < map.grid_w {
                    let next_idx = (row * map.grid_w + (end + 1)) as usize;
                    if next_idx < map.dirty.len() && map.dirty[next_idx] {
                        end += 1;
                    } else {
                        break;
                    }
                }
                regions.push(TileRegion {
                    x: start,
                    y: row,
                    w: end - start + 1,
                    h: 1,
                });
                col = end + 1;
            } else {
                col += 1;
            }
        }
    }
    regions
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn map_4x4(dirty: &[bool]) -> DirtyTileMap {
        assert_eq!(dirty.len(), 16);
        let mut m = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 4,
            grid_h: 4,
            dirty: dirty.to_vec(),
            dirty_ratio: 0.0,
        };
        m.compute_ratio();
        m
    }

    /// P1A Tests：0 dirty → Static。
    #[test]
    fn test_classify_static() {
        let mut d = TileDiff::default();
        // 先喂一帧"首帧"建立 last_grid（否则会被首帧逻辑改成大动）。
        let first = map_4x4(&[false; 16]);
        let _ = d.decide(first);
        // 第二帧全静 → Static。
        let decision = d.decide(map_4x4(&[false; 16]));
        assert!(matches!(decision, EncodeDecision::Static), "全静应 Static");
    }

    /// P1A Tests：2 个 tile dirty（<5%）→ Incremental。
    ///
    /// 4×4 = 16 tile，2 dirty = 12.5% > 5%；为满足"<5%"条件，用更大网格：
    /// 8×8 = 64 tile，2 dirty ≈ 3.1% < 5% → Incremental。
    #[test]
    fn test_classify_incremental() {
        let mut d = TileDiff::default();
        // 首帧建立 last_grid（8×8）。
        let mut first = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 8,
            grid_h: 8,
            dirty: vec![false; 64],
            dirty_ratio: 0.0,
        };
        first.compute_ratio();
        let _ = d.decide(first);

        // 第二帧 2 dirty（3.1%）→ Incremental。
        let mut dirty = vec![false; 64];
        dirty[5] = true;
        dirty[6] = true; // 同行连续 → 合并为 1 region
        let mut m = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 8,
            grid_h: 8,
            dirty,
            dirty_ratio: 0.0,
        };
        m.compute_ratio();
        let decision = d.decide(m);
        match decision {
            EncodeDecision::Incremental(regions) => {
                // 同行 col5/col6 连续 → 1 个 2×1 region。
                assert_eq!(regions.len(), 1, "同行连续 dirty 应合并为 1 region");
                assert_eq!(
                    regions[0],
                    TileRegion {
                        x: 5,
                        y: 0,
                        w: 2,
                        h: 1
                    }
                );
            }
            other => panic!("期望 Incremental，实际: {:?}", other),
        }
    }

    /// P1A Tests：≥5% → FullFrame。
    #[test]
    fn test_classify_fullframe() {
        let mut d = TileDiff::default();
        // 首帧建立 last_grid（4×4）。
        let _ = d.decide(map_4x4(&[false; 16]));
        // 第二帧 1 dirty（1/16 = 6.25% > 5%）→ FullFrame。
        let mut dirty = vec![false; 16];
        dirty[0] = true;
        let decision = d.decide(map_4x4(&dirty));
        match decision {
            EncodeDecision::FullFrame(m) => assert!((m.dirty_ratio - 0.0625).abs() < 1e-6),
            other => panic!("期望 FullFrame，实际: {:?}", other),
        }
    }

    /// P1A Tests：prev_hash=None → 全 dirty 大动（首帧）。
    #[test]
    fn test_first_frame_fullframe() {
        let mut d = TileDiff::default();
        assert!(d.is_first_frame());
        // 喂一个全静的 map，首帧应被强制改为全 dirty 大动。
        let decision = d.decide(map_4x4(&[false; 16]));
        match decision {
            EncodeDecision::FullFrame(m) => {
                assert_eq!(m.dirty_ratio, 1.0, "首帧应全 dirty");
                assert!(m.dirty.iter().all(|b| *b), "首帧所有 tile 应 dirty");
            }
            other => panic!("首帧应 FullFrame，实际: {:?}", other),
        }
        assert!(!d.is_first_frame(), "首帧后 prev_hash 应初始化");
    }

    /// P1A Tests：尺寸变化 → prev_hash 清空 + 全量。
    #[test]
    fn test_resolution_change_reset() {
        let mut d = TileDiff::default();
        // 首帧 4×4。
        let _ = d.decide(map_4x4(&[false; 16]));
        assert!(!d.is_first_frame());
        assert_eq!(d.last_grid, Some((4, 4)));

        // 尺寸变化到 8×8（全静输入），应重置 + 全 dirty 大动。
        let mut m = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 8,
            grid_h: 8,
            dirty: vec![false; 64],
            dirty_ratio: 0.0,
        };
        m.compute_ratio();
        let decision = d.decide(m);
        match decision {
            EncodeDecision::FullFrame(map) => {
                assert_eq!(map.dirty_ratio, 1.0, "分辨率变化应按首帧全 dirty");
                assert!(map.dirty.iter().all(|b| *b));
            }
            other => panic!("分辨率变化应 FullFrame，实际: {:?}", other),
        }
        assert_eq!(d.last_grid, Some((8, 8)));
    }

    /// P1A Tests：同行连续 tile 合并为 1 矩形。
    #[test]
    fn test_merge_regions_row() {
        // 4×4：第 0 行 col1~col3 连续 dirty，第 2 行 col0 单 dirty。
        let mut dirty = vec![false; 16];
        dirty[1] = true;
        dirty[2] = true;
        dirty[3] = true;
        dirty[8] = true; // row=2, col=0
        let m = map_4x4(&dirty);
        let regions = merge_regions(&m);
        assert_eq!(regions.len(), 2);
        // 行主序：row0 的 region 在前。
        assert!(regions.contains(&TileRegion {
            x: 1,
            y: 0,
            w: 3,
            h: 1
        }));
        assert!(regions.contains(&TileRegion {
            x: 0,
            y: 2,
            w: 1,
            h: 1
        }));
    }

    #[test]
    fn test_merge_regions_empty_and_noncontiguous() {
        // 全静 → 无 region。
        let m = map_4x4(&[false; 16]);
        assert!(merge_regions(&m).is_empty());

        // 非连续：col0 + col2（col1 静）→ 两个 1×1 region。
        let mut dirty = vec![false; 16];
        dirty[0] = true;
        dirty[2] = true;
        let m = map_4x4(&dirty);
        let regions = merge_regions(&m);
        assert_eq!(regions.len(), 2);
        assert!(regions.iter().all(|r| r.w == 1));
    }

    #[test]
    fn test_classify_with_gpu_kernel_error_on_null_tex() {
        // kernel=None + null 纹理 → InvalidConfig（在 cpu_tile_hash 入口）。
        let mut d = TileDiff::default();
        let tex = GpuTexture::new(ptr::null_mut(), 0, 0);
        let err = d.classify(&tex, None).unwrap_err();
        assert!(matches!(err, EncodeError::InvalidConfig(_)));
    }

    #[test]
    fn test_classify_without_kernel_returns_gpukernel_error() {
        // kernel=None + 非空纹理 → GpuKernel 错误（纹理路径无像素可读；
        // 真实 CPU 兜底走 classify_cpu，见 test_cpu_hash_* 系列）。
        let mut d = TileDiff::default();
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        let err = d.classify(&tex, None).unwrap_err();
        match err {
            EncodeError::GpuKernel(msg) => assert!(msg.contains("classify_cpu")),
            other => panic!("期望 GpuKernel 错误，实际: {:?}", other),
        }
    }

    #[test]
    fn test_nan_ratio_treated_as_static() {
        let mut d = TileDiff::default();
        let _ = d.decide(map_4x4(&[false; 16])); // 建立网格
        let m = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 4,
            grid_h: 4,
            dirty: vec![true; 16], // dirty 但 ratio=NaN
            dirty_ratio: f32::NAN,
        };
        let decision = d.decide(m);
        // NaN 防御 → 当作全静。
        assert!(matches!(decision, EncodeDecision::Static));
    }

    // ════════════════════════════════════════════════════════════
    // M8-T030（R-06）：CPU tile-hash 兜底测试（环境无关，GPU-FR-008）
    // ════════════════════════════════════════════════════════════

    /// 640×480 纯色帧（80 tiles：10×8；改 1 tile = 1.25% < 5% → Incremental）。
    fn solid_frame(w: u32, h: u32, fill: u8) -> Vec<u8> {
        vec![fill; (w * h * 4) as usize]
    }

    /// 在帧内画一个小方块（改写局部像素）。
    fn patch(frame: &mut [u8], w: u32, h: u32, x: u32, y: u32, bw: u32, bh: u32, val: u8) {
        for py in y..(y + bh).min(h) {
            for px in x..(x + bw).min(w) {
                let i = ((py * w + px) * 4) as usize;
                frame[i] = val;
                frame[i + 1] = val;
                frame[i + 2] = val;
            }
        }
    }

    /// 首帧 → FullFrame（全 dirty）。
    #[test]
    fn test_cpu_hash_first_frame_fullframe() {
        let mut d = TileDiff::default();
        let (w, h) = (640u32, 480u32);
        let frame = solid_frame(w, h, 128);
        let decision = d.classify_cpu(&frame, w, h).unwrap();
        match decision {
            EncodeDecision::FullFrame(map) => {
                assert_eq!(map.dirty_ratio, 1.0, "首帧应全 dirty");
                assert!(map.dirty.iter().all(|b| *b));
            }
            other => panic!("首帧应 FullFrame，实际: {:?}", other),
        }
    }

    /// 帧间无变化 → Static（纯色第二帧）。
    #[test]
    fn test_cpu_hash_static_unchanged() {
        let mut d = TileDiff::default();
        let (w, h) = (640u32, 480u32);
        let frame = solid_frame(w, h, 128);
        let _ = d.classify_cpu(&frame, w, h).unwrap(); // 首帧建立基线。
        let decision = d.classify_cpu(&frame, w, h).unwrap();
        assert!(
            matches!(decision, EncodeDecision::Static),
            "无变化应 Static，实际: {decision:?}"
        );
    }

    /// 局部微变（1 tile / 80 = 1.25% < 5%）→ Incremental（1 个 region）。
    #[test]
    fn test_cpu_hash_incremental_small_change() {
        let mut d = TileDiff::default();
        let (w, h) = (640u32, 480u32);
        let mut frame = solid_frame(w, h, 128);
        let _ = d.classify_cpu(&frame, w, h).unwrap(); // 首帧基线。
        // 改写第 1 个 tile（0..64, 0..64）内的一个小方块。
        patch(&mut frame, w, h, 10, 10, 20, 20, 200);
        let decision = d.classify_cpu(&frame, w, h).unwrap();
        match decision {
            EncodeDecision::Incremental(regions) => {
                assert!(!regions.is_empty(), "微变应产出 region");
                // 所有 region 应落在改动 tile 所在行（tile 网格坐标）。
                assert!(
                    regions.iter().all(|r| r.y == 0),
                    "改动在第 0 行 tile，region 应只含 y=0: {regions:?}"
                );
            }
            other => panic!("1/80 变化应 Incremental，实际: {other:?}"),
        }
    }

    /// 大动（≥5% tiles）→ FullFrame。
    #[test]
    fn test_cpu_hash_fullframe_many_changes() {
        let mut d = TileDiff::default();
        let (w, h) = (640u32, 480u32);
        let mut frame = solid_frame(w, h, 128);
        let _ = d.classify_cpu(&frame, w, h).unwrap(); // 首帧基线。
        // 改写 6 个 tile（前 3 行 × 前 2 列区域）→ 6/80 = 7.5% > 5% → FullFrame。
        patch(&mut frame, w, h, 0, 0, 128, 192, 200);
        let decision = d.classify_cpu(&frame, w, h).unwrap();
        match decision {
            EncodeDecision::FullFrame(map) => {
                assert!((map.dirty_ratio - 0.075).abs() < 1e-4, "ratio={}", map.dirty_ratio);
            }
            other => panic!("≥5% 变化应 FullFrame，实际: {other:?}"),
        }
    }

    /// 分辨率变化 → 重置基线 + FullFrame。
    #[test]
    fn test_cpu_hash_resolution_change_resets() {
        let mut d = TileDiff::default();
        let frame1 = solid_frame(640, 480, 128);
        let _ = d.classify_cpu(&frame1, 640, 480).unwrap();
        // 尺寸变化：即使内容全同也应按首帧处理（网格数变化）。
        let frame2 = solid_frame(320, 240, 128);
        let decision = d.classify_cpu(&frame2, 320, 240).unwrap();
        assert!(
            matches!(decision, EncodeDecision::FullFrame(_)),
            "分辨率变化应 FullFrame，实际: {decision:?}"
        );
    }

    /// 缓冲长度不匹配 → InvalidConfig（防御）。
    #[test]
    fn test_cpu_hash_buffer_too_small() {
        let mut d = TileDiff::default();
        let err = d.classify_cpu(&[0u8; 16], 640, 480).unwrap_err();
        assert!(matches!(err, EncodeError::InvalidConfig(_)));
    }

    /// 零尺寸帧 → InvalidConfig。
    #[test]
    fn test_cpu_hash_zero_frame() {
        let mut d = TileDiff::default();
        let err = d.classify_cpu(&[], 0, 0).unwrap_err();
        assert!(matches!(err, EncodeError::InvalidConfig(_)));
    }

    /// tile CRC32 对内容敏感：同位置改 1 字节 → hash 必变（防误判全静）。
    #[test]
    fn test_tile_crc32_sensitive_to_single_byte() {
        let (w, h) = (64usize, 64usize);
        let a = vec![0u8; w * h * 4];
        let mut b = a.clone();
        b[10] = 1; // 单个字节差异。
        let ha = tile_crc32(&a, w, h, 64, 64, 0, 0);
        let hb = tile_crc32(&b, w, h, 64, 64, 0, 0);
        assert_ne!(ha, hb, "1 字节差异必须改变 tile hash");
    }

    /// 一个最小的 GpuKernel stub，验证 classify(kernel=Some) 路径把决策
    /// 委托给内核产出的 map + decide。
    struct StubKernel {
        map: DirtyTileMap,
    }
    impl GpuKernel for StubKernel {
        fn tile_hash(&self, _tex: &GpuTexture) -> Result<DirtyTileMap, EncodeError> {
            Ok(self.map.clone())
        }
    }

    /// P1B↔P1C 接驳 Tests：GpuKernel trait 的默认实现 —— `blit_tiles_rle` /
    /// `hw_upload` 返回 `Unsupported`，`is_linked` 返回 `false`。CPU-only /
    /// 未链接内核据此被调用方识别并降级（既有 StubKernel 不 override 即自动获得）。
    #[test]
    fn test_gpu_kernel_trait_defaults() {
        let k = StubKernel {
            map: DirtyTileMap::default(),
        };
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        // 默认 is_linked = false。
        assert!(!k.is_linked());
        // 默认 blit_tiles_rle / hw_upload 返回 Unsupported。
        let r = k.blit_tiles_rle(&tex, &k.map);
        assert!(matches!(r, Err(EncodeError::Unsupported(_))));
        let r = k.hw_upload(&tex);
        assert!(matches!(r, Err(EncodeError::Unsupported(_))));
    }

    #[test]
    fn test_classify_with_kernel_uses_kernel_map() {
        let mut d = TileDiff::default();
        // 首帧走内核 map。
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        let first_map = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 4,
            grid_h: 4,
            dirty: vec![false; 16],
            dirty_ratio: 0.0,
        };
        let kernel = StubKernel { map: first_map };
        let decision = d.classify(&tex, Some(&kernel)).unwrap();
        // 首帧 → FullFrame（全 dirty）。
        assert!(matches!(decision, EncodeDecision::FullFrame(_)));
        assert!(!d.is_first_frame());
    }
}
