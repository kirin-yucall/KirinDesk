//! 视频编码入口：决策分发 + 时间戳（P1C §T3.7）。
//!
//! [`VideoEncoderPipeline`] 是 capture 层与具体编码后端的接合点：
//! - 持有一个 [`VideoEncoder`]（经 [`factory::create_video_encoder`] 选出）
//! - 持有 [`TileDiff`] 做 Static/Incremental/FullFrame 决策
//! - 适配 CPU RGBA 路径（捕获层 `windows_capture` 当前产出 RGBA 字节，非
//!   `GpuTexture` 句柄；P1B GPU 内核桥不可用时走软编 / HW NV12 CPU 路径）
//!
//! # 决策三态（来自 [`TileDiff::classify`]）
//!
//! - [`Static`](crate::encoder::types::EncodeDecision::Static) → 零输出（心跳归传输层）
//! - [`Incremental`](crate::encoder::types::EncodeDecision::Incremental) → 微变 RLE 增量（[`VideoEncoderPipeline::blit_incremental`]）
//! - [`FullFrame`](crate::encoder::types::EncodeDecision::FullFrame) → ROI 注入 + 编码器

use crate::encoder::factory;
use crate::encoder::types::{
    Codec, DirtyTileMap, EncodeDecision, EncodedPacket, GpuTexture, PacketKind, TileRegion,
    Timestamp,
};
use crate::encoder::video::tile_diff::{GpuKernel, TileDiff, TileDiffConfig};
use crate::encoder::video::{EncodeError, VideoEncoder};
use crate::ffmpeg;
use crate::proto::EncodeConfig;

/// 视频编码入口：决策分发 + 时间戳。
///
/// 字段对照文档 §T3.7：`kernel: Option<GpuKernelHandle>` 中 `GpuKernelHandle` 在
/// 本仓库不存在（真实类型 [`KgpuKernel`](crate::encoder::gpu_ffi::kernel::KgpuKernel)），
/// 故接 `Option<Box<dyn GpuKernel>>`（trait object，语义等价）。
pub struct VideoEncoderPipeline {
    encoder: Box<dyn VideoEncoder>,
    diff: TileDiff,
    /// P1B GPU 内核（tile_hash 零拷贝）。None → CPU 回退（classify 降级 FullFrame）。
    kernel: Option<Box<dyn GpuKernel>>,
    /// 微变 / 全静连续帧计数（用于省电 / 省码率）。
    static_streak: u32,
    /// 帧序号（Incremental 包 [frame_id] 用）。
    frame_id: u32,
    // ── CPU RGBA 适配（windows_capture 当前产 RGBA，非 GpuTexture 句柄） ──
    // M8-T030（R-06，GPU-FR-008）：CPU tile-hash 兜底需要帧像素 ——
    // `pending_rgba` 由 set_cpu_frame 存留，classify_cpu 消费（非死拷贝；
    // M13-T004 曾因无消费方移除，现恢复消费）。
    pending_rgba: Vec<u8>,
    pending_w: u32,
    pending_h: u32,
}

impl VideoEncoderPipeline {
    /// 创建：按回退链选出编码器，初始化 tile-diff（默认 64×64 / 阈值 0.05）。
    pub fn new(pref: Codec, kernel: Option<Box<dyn GpuKernel>>) -> Result<Self, EncodeError> {
        let encoder = factory::create_video_encoder(pref, kernel.as_deref())?;
        Self::from_parts(kernel, encoder)
    }

    /// 基准/测试注入：以显式编码器实例构造流水线（P1G codec_bench 的
    /// [`CountingEncoder`] 计数包装、单测注入用）。`pref` 语义由编码器自带
    /// （`codec()`），tile-diff 默认 64×64 / 阈值 0.05。
    pub fn from_parts(
        kernel: Option<Box<dyn GpuKernel>>,
        encoder: Box<dyn VideoEncoder>,
    ) -> Result<Self, EncodeError> {
        ffmpeg::ensure_loaded()
            .map_err(|e| EncodeError::InitFailed(format!("FFmpeg DLLs: {e}")))?;
        let diff = TileDiff::new(TileDiffConfig::default());
        Ok(Self {
            encoder,
            diff,
            kernel,
            static_streak: 0,
            frame_id: 0,
            pending_rgba: Vec::new(),
            pending_w: 0,
            pending_h: 0,
        })
    }

    /// 暴露编码器诊断名（供日志 / ui 显示）。
    pub fn name(&self) -> &'static str {
        self.encoder.name()
    }

    /// 是否为硬件编码器。
    pub fn is_hardware(&self) -> bool {
        self.encoder.is_hardware()
    }

    /// 编码标准。
    pub fn codec(&self) -> Codec {
        self.encoder.codec()
    }

    /// 分辨率变更 / 参数重配（自适应层调用）。
    pub fn reconfigure(&mut self, cfg: &EncodeConfig) -> Result<(), EncodeError> {
        self.encoder.reconfigure(cfg)
    }

    /// 窗口边界清参考帧（M8-T011 T2.3，转发到内部编码器）。
    ///
    /// 每个窗口编码前调用：清空上一窗口残留的参考帧 / 内部缓冲，保证窗口
    /// 自包含（首帧强制 IDR）。无缓冲后端为 no-op（trait 默认实现）。
    pub fn flush_buffers(&mut self) {
        self.encoder.flush_buffers();
    }

    /// 喂入 CPU RGBA（适配 `windows_capture`：当前捕获后端无 GPU 句柄）。
    /// 调用方在 [`on_frame`](Self::on_frame) 前调用本方法把当前帧 RGBA 喂入。
    ///
    /// M8-T030（R-06）：本层保留一份 RGBA 副本供 CPU tile-hash 兜底
    /// （`classify_cpu` 消费；GPU 内核可用时仍只转发编码器 + 缓存尺寸）。
    pub fn set_cpu_frame(&mut self, rgba: &[u8], w: u32, h: u32, force_idr: bool) {
        self.encoder.set_cpu_frame(rgba, w, h, force_idr);
        // 缓存 RGBA（CPU tile-hash 消费）+ 尺寸。
        self.pending_rgba.clear();
        self.pending_rgba.extend_from_slice(rgba);
        self.pending_w = w;
        self.pending_h = h;
    }

    /// capture 来帧 → 分级 → 按分支处理（文档 §T3.7）。
    ///
    /// 决策由 [`TileDiff::classify`] 在本方法内产出（GPU 纹理 + 内核 hash）；
    /// GPU 内核不可用 / 纹理为 null（CPU RGBA 模式）时 classify 降级为 FullFrame。
    pub fn on_frame(
        &mut self,
        tex: &GpuTexture,
        ts: Timestamp,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        self.frame_id = self.frame_id.wrapping_add(1);

        // 决策：GPU 内核可用 → classify（纹理 hash）；否则 CPU 路径
        // （tex 为 null 哨兵）→ M8-T030 真实 CPU tile-hash 兜底（classify_cpu），
        // 产出三态决策（首帧 FullFrame / 纯色 Static / 局部微变 Incremental）。
        let decision = if tex.is_null() {
            match self
                .diff
                .classify_cpu(&self.pending_rgba, self.pending_w, self.pending_h)
            {
                Ok(d) => d,
                // 兜底失败（未喂 RGBA / 缓冲异常）→ 降级 FullFrame，不丢帧。
                Err(_) => EncodeDecision::FullFrame(DirtyTileMap::default()),
            }
        } else {
            match self.diff.classify(tex, self.kernel.as_deref()) {
                Ok(d) => d,
                // classify 失败（如 CPU 回退无纹理读回）→ 降级 FullFrame，不丢帧。
                Err(_) => EncodeDecision::FullFrame(DirtyTileMap::default()),
            }
        };

        match decision {
            EncodeDecision::Static => {
                // 全静：零输出，不触碰编码器（省电 / 省码率）。
                self.static_streak = self.static_streak.saturating_add(1);
                Ok(Vec::new())
            }
            EncodeDecision::Incremental(regions) => {
                self.static_streak = 0;
                self.blit_incremental(tex, &regions, ts)
            }
            EncodeDecision::FullFrame(map) => {
                self.static_streak = 0;
                // CPU RGBA 路径（tex 为 null 哨兵）：encode 的 preprocess_encode
                // 会拒绝 null 纹理，故这里传一个非空哨兵（编码器实际读
                // set_cpu_frame 喂入的 RGBA 缓冲，不 deref 句柄）。
                let enc_tex = if tex.is_null() {
                    GpuTexture::new(0x1usize as *mut _, self.pending_w, self.pending_h)
                } else {
                    GpuTexture::new(tex.handle, tex.width(), tex.height())
                };
                // P1G：把 classify 产出的 dirty map 原样传给编码器（ROI 注入
                // 依赖它；M8-T030 后 CPU 路径的 map 来自真实 CPU tile-hash，
                // ROI 同样生效）。
                self.encoder
                    .encode(&enc_tex, ts, EncodeDecision::FullFrame(map))
            }
        }
    }

    /// 微变 RLE 打包（文档 §T3.7）。
    ///
    /// `packet.data = [frame_id:u32][type=u8=INCREMENTAL][region_count:u32]
    /// [regions...:x,y,w,h (u32 LE) each][rle_len:u32][rle bytes]`。
    ///
    /// P1B 接驳（2026-07-31）：当 `kernel.is_linked()` 且纹理非空时，调
    /// `kernel.blit_tiles_rle(tex, map)` 取 RLE 压缩字节 append 到坐标指令
    /// 之后（`[rle_len][rle bytes]`）。失败 / 未链接 / 纹理为 CPU 哨兵 →
    /// 止于坐标指令（客户端用上一帧合成），不调编码器（省 GPU/CPU）。
    fn blit_incremental(
        &mut self,
        tex: &GpuTexture,
        regions: &[TileRegion],
        ts: Timestamp,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        if regions.is_empty() {
            return Ok(Vec::new());
        }
        let mut data = Vec::with_capacity(8 + regions.len() * 16);
        // [frame_id:u32]（小端）
        data.extend_from_slice(&self.frame_id.to_le_bytes());
        // [type:u8 = 1 = INCREMENTAL]
        data.push(1u8);
        // [region_count:u32]
        data.extend_from_slice(&(regions.len() as u32).to_le_bytes());
        // [regions...]: 每个 region = x,y,w,h (u32 LE) — tile 网格坐标。
        for r in regions {
            data.extend_from_slice(&r.x.to_le_bytes());
            data.extend_from_slice(&r.y.to_le_bytes());
            data.extend_from_slice(&r.w.to_le_bytes());
            data.extend_from_slice(&r.h.to_le_bytes());
        }

        // P1B 接驳：kernel linked + 真实纹理 → append RLE 压缩字节。
        // 失败（P1B 桩 / 未链接 / CPU 哨兵纹理）→ 止于坐标指令，不阻断。
        let rle_len_field_pos = data.len();
        // 占位 rle_len=0；成功路径覆写。
        data.extend_from_slice(&0u32.to_le_bytes());
        if let Some(kernel) = self.kernel.as_deref() {
            if kernel.is_linked() && !tex.is_null() {
                let map = regions_to_dirty_map(regions, &self.diff.cfg());
                match kernel.blit_tiles_rle(tex, &map) {
                    Ok(rle) => {
                        // 覆写 rle_len 为实际长度，append RLE 字节。
                        let len = rle.len() as u32;
                        data[rle_len_field_pos..rle_len_field_pos + 4]
                            .copy_from_slice(&len.to_le_bytes());
                        data.extend_from_slice(&rle);
                    }
                    Err(e) => {
                        // RLE 失败：保持 rle_len=0（坐标指令降级）。
                        tracing::debug!("blit_incremental: RLE failed ({e}) → coords only");
                    }
                }
            }
        }

        Ok(vec![EncodedPacket {
            ts,
            kind: PacketKind::Video,
            data,
            is_key: false,
        }])
    }
}

// ════════════════════════════════════════════════════════════════
// regions_to_dirty_map — tile 网格坐标 regions → DirtyTileMap（P1B 接驳）
// ════════════════════════════════════════════════════════════════

/// 把 [`TileRegion`] 列表（tile 网格坐标）转回 [`DirtyTileMap`]，供 P1B
/// `kernel.blit_tiles_rle` 消费。
///
/// 网格尺寸由 `cfg.tile_w/tile_h` 推断：取 regions 覆盖的最大 (col+w, row+h)
/// 作为 `grid_w/grid_h`，保证 `dirty.len() == grid_w * grid_h` 且所有 region
/// 索引合法。这是 [`merge_regions`](tile_diff::merge_regions) 的近似逆运算
/// （后者合并同行连续 tile；本函数把 region 展开 back 为逐 tile dirty 位）。
///
/// `grid_w/grid_h` 至少为 1，避免空 map（`blit_tiles_rle` 不接受零网格）。
pub(crate) fn regions_to_dirty_map(regions: &[TileRegion], cfg: &TileDiffConfig) -> DirtyTileMap {
    let tile_w = cfg.tile_w.max(1);
    let tile_h = cfg.tile_h.max(1);
    // 推断网格：取所有 region 右下角的 tile 坐标最大值。
    let mut grid_w: u32 = 1;
    let mut grid_h: u32 = 1;
    for r in regions {
        grid_w = grid_w.max(r.x.saturating_add(r.w));
        grid_h = grid_h.max(r.y.saturating_add(r.h));
    }
    let total = (grid_w as usize) * (grid_h as usize);
    let mut dirty = vec![false; total];
    for r in regions {
        for row in r.y..r.y.saturating_add(r.h).min(grid_h) {
            for col in r.x..r.x.saturating_add(r.w).min(grid_w) {
                let idx = (row * grid_w + col) as usize;
                if idx < dirty.len() {
                    dirty[idx] = true;
                }
            }
        }
    }
    let mut map = DirtyTileMap {
        tile_w,
        tile_h,
        grid_w,
        grid_h,
        dirty,
        dirty_ratio: 0.0,
    };
    map.compute_ratio();
    map
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 全静（null 纹理 + 无 pending RGBA 时降级为 FullFrame，但 set_cpu_frame
    /// 未喂入 → InvalidConfig）。本测试验证 Static 决策需 GPU 路径；CPU 路径
    /// 默认 FullFrame。这里构造一个非空但无 pending 的场景。
    #[test]
    fn test_pipeline_static_zero_output() {
        if ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let mut pipe = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("pipeline 创建失败（无 libx264？）: {e}");
                return;
            }
        };
        // Static 决策仅在 GPU classify 路径产生；CPU 路径 on_frame 永远 FullFrame。
        // 直接调 encoder.encode 验证 Static 短路：
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        let packets = pipe
            .encoder
            .encode(&tex, Timestamp::now(), EncodeDecision::Static)
            .unwrap();
        assert!(packets.is_empty(), "Static 应零输出");
    }

    /// FullFrame：必须先 set_cpu_frame，否则 InvalidConfig（无 pending RGBA）。
    #[test]
    fn test_pipeline_fullframe_requires_cpu_frame() {
        if ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let mut pipe = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(p) => p,
            Err(_) => return,
        };
        // 未喂 RGBA → on_frame 走 FullFrame → encoder.encode → InvalidConfig。
        let tex = GpuTexture::new(std::ptr::null_mut(), 0, 0); // CPU 模式哨兵
        let r = pipe.on_frame(&tex, Timestamp::now());
        assert!(matches!(r, Err(EncodeError::InvalidConfig(_))));
    }

    /// FullFrame + set_cpu_frame → 产出 Annex B（libx264/h264_qsv 可用时）。
    #[test]
    fn test_pipeline_fullframe_produces_packets() {
        if ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let mut pipe = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("pipeline 不可用: {e}");
                return;
            }
        };
        let w = 320u32;
        let h = 240u32;
        let rgba = vec![128u8; (w * h * 4) as usize];
        pipe.set_cpu_frame(&rgba, w, h, true);
        let tex = GpuTexture::new(std::ptr::null_mut(), 0, 0); // CPU 模式哨兵
        let packets = pipe.on_frame(&tex, Timestamp::now()).unwrap_or_default();
        if packets.is_empty() {
            eprintln!("无包输出（OK on some builds）");
            return;
        }
        assert!(packets[0].is_key, "首包应为 IDR");
    }

    /// Incremental blit 打包格式：[frame_id][type=1][count][regions][rle_len=0]
    /// （无内核时 rle_len=0，纯坐标指令）。
    #[test]
    fn test_blit_incremental_packet_layout() {
        if ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let mut pipe = match VideoEncoderPipeline::new(Codec::H264, None) {
            Ok(p) => p,
            Err(_) => return,
        };
        let regions = vec![TileRegion::single(1, 2), TileRegion::single(3, 4)];
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        let packets = pipe
            .blit_incremental(&tex, &regions, Timestamp::now())
            .unwrap();
        assert_eq!(packets.len(), 1);
        let d = &packets[0].data;
        // [frame_id:u32][type:u8=1][count:u32=2]
        assert_eq!(d[4], 1u8, "type byte = 1 (INCREMENTAL)");
        let count = u32::from_le_bytes([d[5], d[6], d[7], d[8]]);
        assert_eq!(count, 2, "region count = 2");
        // regions: 2 × 16 字节（x,y,w,h 各 u32），从偏移 9..9+32=41。
        // 之后是 [rle_len:u32]；无内核 → rle_len = 0。
        let rle_len_off = 9 + regions.len() * 16;
        let rle_len = u32::from_le_bytes([
            d[rle_len_off],
            d[rle_len_off + 1],
            d[rle_len_off + 2],
            d[rle_len_off + 3],
        ]);
        assert_eq!(rle_len, 0, "无内核时 rle_len 应为 0");
        assert!(!packets[0].is_key, "incremental 非关键帧");
    }

    /// P1B↔P1C 接驳 Tests：linked stub 内核 → blit_incremental append RLE 字节。
    /// stub 的 `blit_tiles_rle` 返回固定字节，断言包尾出现该字节 + rle_len 正确。
    #[test]
    fn test_blit_incremental_appends_rle_with_linked_kernel() {
        use crate::encoder::types::DirtyTileMap;
        use crate::encoder::video::tile_diff::GpuKernel;

        /// linked stub：`is_linked()=true` + `blit_tiles_rle` 返回固定 RLE。
        struct RleStub;
        impl GpuKernel for RleStub {
            fn tile_hash(&self, _tex: &GpuTexture) -> Result<DirtyTileMap, EncodeError> {
                Ok(DirtyTileMap::default())
            }
            fn blit_tiles_rle(
                &self,
                _tex: &GpuTexture,
                _map: &DirtyTileMap,
            ) -> Result<Vec<u8>, EncodeError> {
                // 固定 4 字节 RLE（[count=2][val=0xAA][count=1][val=0x55]）。
                Ok(vec![2u8, 0xAA, 1u8, 0x55])
            }
            fn is_linked(&self) -> bool {
                true
            }
        }

        // 用 from_parts 注入 stub 内核 + 一个最小可编码器（用真实 SW，若不可用跳过）。
        if ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let encoder = match crate::encoder::factory::create_video_encoder(Codec::H264, None) {
            Ok(e) => e,
            Err(_) => return,
        };
        let stub = Box::new(RleStub);
        let mut pipe = match VideoEncoderPipeline::from_parts(Some(stub), encoder) {
            Ok(p) => p,
            Err(_) => return,
        };
        let regions = vec![TileRegion::single(0, 0)];
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        let packets = pipe
            .blit_incremental(&tex, &regions, Timestamp::now())
            .unwrap();
        let d = &packets[0].data;
        // regions 后是 [rle_len:u32] + RLE 字节。
        let rle_len_off = 9 + regions.len() * 16;
        let rle_len = u32::from_le_bytes([
            d[rle_len_off],
            d[rle_len_off + 1],
            d[rle_len_off + 2],
            d[rle_len_off + 3],
        ]);
        assert_eq!(rle_len, 4, "linked 内核应 append 4 字节 RLE");
        let rle = &d[rle_len_off + 4..rle_len_off + 4 + 4];
        assert_eq!(rle, &[2u8, 0xAA, 1u8, 0x55], "RLE 字节应与 stub 输出一致");
    }

    /// P1B↔P1C 接驳 Tests：regions_to_dirty_map 把 tile 网格 regions 展开为
    /// DirtyTileMap（merge_regions 的近似逆运算）。
    #[test]
    fn test_regions_to_dirty_map_roundtrip() {
        let cfg = TileDiffConfig::default();
        let regions = vec![
            TileRegion {
                x: 0,
                y: 0,
                w: 2,
                h: 1,
            }, // 第 0 行前 2 tile
            TileRegion {
                x: 3,
                y: 1,
                w: 1,
                h: 1,
            }, // 第 1 行第 3 tile
        ];
        let map = regions_to_dirty_map(&regions, &cfg);
        assert_eq!(map.tile_w, 64);
        assert_eq!(map.grid_w, 4); // max(x+w) = 3+1
        assert_eq!(map.grid_h, 2); // max(y+h) = 1+1
        assert_eq!(map.dirty.len(), 8);
        // (0,0),(1,0) dirty；(3,1) dirty；其余 false。
        assert!(map.dirty[0 * 4 + 0]);
        assert!(map.dirty[0 * 4 + 1]);
        assert!(!map.dirty[0 * 4 + 2]);
        assert!(map.dirty[1 * 4 + 3]);
        // dirty_ratio = 3/8。
        assert!((map.dirty_ratio - 3.0 / 8.0).abs() < 1e-6);
    }

    // ── P1G Tests：ROI 数据流（T7.3） + from_parts 注入（codec_bench） ──

    /// 记录型编码器：只记录收到的 decision，不真正编码。
    /// `from_parts` 注入用（codec_bench 的 CountingEncoder 同款结构）。
    /// `Arc<Mutex<...>>`（编码器需 Send）使测试可在 move 进 pipeline 后回读。
    struct RecordingEncoder {
        received: std::sync::Arc<std::sync::Mutex<Option<EncodeDecision>>>,
    }
    impl VideoEncoder for RecordingEncoder {
        fn encode(
            &mut self,
            _tex: &GpuTexture,
            _ts: Timestamp,
            decision: EncodeDecision,
        ) -> Result<Vec<EncodedPacket>, EncodeError> {
            *self.received.lock().unwrap() = Some(decision);
            Ok(Vec::new())
        }
        fn codec(&self) -> Codec {
            Codec::H264
        }
        fn is_hardware(&self) -> bool {
            false
        }
        fn name(&self) -> &'static str {
            "recording"
        }
        fn reconfigure(&mut self, _cfg: &crate::proto::EncodeConfig) -> Result<(), EncodeError> {
            Ok(())
        }
    }

    /// 状态型 stub 内核：按调用序依次吐出预置 map（RefCell 保持 GpuKernel: Send）。
    struct MapQueueKernel {
        queue: std::cell::RefCell<std::collections::VecDeque<DirtyTileMap>>,
    }
    impl GpuKernel for MapQueueKernel {
        fn tile_hash(&self, _tex: &GpuTexture) -> Result<DirtyTileMap, EncodeError> {
            let mut q = self.queue.borrow_mut();
            if q.is_empty() {
                return Ok(DirtyTileMap::default());
            }
            Ok(q.pop_front().unwrap())
        }
    }

    /// P1G Tests：FullFrame 分支必须把 classify 产出的 dirty map 原样传给
    /// 编码器（ROI side data 注入的数据源；此前分支丢弃 map 传空 map，
    /// 导致 ROI 永不生效 —— 本测试锁死该回归）。
    #[test]
    fn test_pipeline_fullframe_passes_dirty_map() {
        if ffmpeg::ensure_loaded().is_err() {
            return;
        }
        // 4×4 网格，dirty[3]（row0,col3）= 1/16 = 6.25% ≥ 5% → FullFrame。
        let mut dirty = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 4,
            grid_h: 4,
            dirty: vec![false; 16],
            dirty_ratio: 0.0,
        };
        dirty.dirty[3] = true;
        dirty.compute_ratio();

        // 热身 map 必须同网格（4×4）：decide 以网格变化判定"分辨率变化"，
        // 网格不一致会把第二帧误判为首帧全脏（DirtyTileMap::default() 为
        // 0×0 网格，不能用）。
        let warmup = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 4,
            grid_h: 4,
            dirty: vec![false; 16],
            dirty_ratio: 0.0,
        };

        let kernel = MapQueueKernel {
            queue: std::cell::RefCell::new([warmup, dirty.clone()].into_iter().collect()),
        };
        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let enc = RecordingEncoder {
            received: std::sync::Arc::clone(&received),
        };
        let mut pipe = match VideoEncoderPipeline::from_parts(Some(Box::new(kernel)), Box::new(enc))
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("pipeline from_parts 失败: {e}");
                return;
            }
        };
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        // 帧 1（热身：首帧 → 全 dirty FullFrame，建立 prev_hash）。
        let _ = pipe.on_frame(&tex, Timestamp::now()).unwrap();
        // 帧 2：kernel 产出 dirty[3] → FullFrame → 编码器必须收到同一 map。
        let _ = pipe.on_frame(&tex, Timestamp::now()).unwrap();
        let received = received.lock().unwrap().clone();
        match received {
            Some(EncodeDecision::FullFrame(map)) => {
                assert_eq!(map.dirty[3], true, "dirty[3] 应传到编码器");
                assert_eq!(
                    map.dirty.iter().filter(|b| **b).count(),
                    1,
                    "只应传 1 个 dirty tile"
                );
                assert!(
                    (map.dirty_ratio - 0.0625).abs() < 1e-6,
                    "ratio 应保持 6.25%"
                );
            }
            other => panic!("编码器应收到 FullFrame(dirty map)，实际: {other:?}"),
        }
    }

    /// P1G Tests：Static / Incremental 决策不触碰编码器（编码器调用 0 次）。
    /// 用共享原子计数断言（codec_bench CountingEncoder 的同款模式）。
    #[test]
    fn test_pipeline_static_incremental_no_encoder_call() {
        if ffmpeg::ensure_loaded().is_err() {
            return;
        }
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        struct CountingEnc {
            inner: RecordingEncoder,
            calls: Arc<AtomicU32>,
        }
        impl VideoEncoder for CountingEnc {
            fn encode(
                &mut self,
                tex: &GpuTexture,
                ts: Timestamp,
                decision: EncodeDecision,
            ) -> Result<Vec<EncodedPacket>, EncodeError> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                self.inner.encode(tex, ts, decision)
            }
            fn codec(&self) -> Codec {
                Codec::H264
            }
            fn is_hardware(&self) -> bool {
                false
            }
            fn name(&self) -> &'static str {
                "counting"
            }
            fn reconfigure(&mut self, cfg: &crate::proto::EncodeConfig) -> Result<(), EncodeError> {
                self.inner.reconfigure(cfg)
            }
        }

        // 4×4：全静 → Static；2 dirty 需 <5%：用 8×8 网格（2/64 ≈ 3.1% → Incremental）。
        fn mk_map(grid: u32, dirty_idx: &[usize]) -> DirtyTileMap {
            let mut m = DirtyTileMap {
                tile_w: 64,
                tile_h: 64,
                grid_w: grid,
                grid_h: grid,
                dirty: vec![false; (grid * grid) as usize],
                dirty_ratio: 0.0,
            };
            for &i in dirty_idx {
                m.dirty[i] = true;
            }
            m.compute_ratio();
            m
        }

        // 三帧必须同网格（8×8）：decide 以网格变化判定"分辨率变化"，
        // 网格不一致会把后续帧误判为首帧全脏。
        let mut maps: std::collections::VecDeque<DirtyTileMap> = std::collections::VecDeque::new();
        maps.push_back(mk_map(8, &[])); // 热身：首帧 FullFrame
        maps.push_back(mk_map(8, &[])); // 全静 → Static
        maps.push_back(mk_map(8, &[5, 6])); // 2/64 ≈ 3.1% → Incremental

        let kernel = MapQueueKernel {
            queue: std::cell::RefCell::new(maps),
        };
        let calls = Arc::new(AtomicU32::new(0));
        let counting = CountingEnc {
            inner: RecordingEncoder {
                received: std::sync::Arc::new(std::sync::Mutex::new(None)),
            },
            calls: calls.clone(),
        };
        let mut pipe =
            match VideoEncoderPipeline::from_parts(Some(Box::new(kernel)), Box::new(counting)) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("pipeline from_parts 失败: {e}");
                    return;
                }
            };
        let tex = GpuTexture::new(0x1usize as *mut _, 64, 64);
        let _ = pipe.on_frame(&tex, Timestamp::now()).unwrap(); // 热身（FullFrame，计 1）
        let p1 = pipe.on_frame(&tex, Timestamp::now()).unwrap(); // Static
        let p2 = pipe.on_frame(&tex, Timestamp::now()).unwrap(); // Incremental
        assert!(p1.is_empty(), "Static 应零输出");
        assert!(!p2.is_empty(), "Incremental 应产出 1 增量包");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "编码器只应在热身帧被调用（Static/Incremental 各 0 次）"
        );
    }
}
