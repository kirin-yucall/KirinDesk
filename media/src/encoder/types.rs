//! 接口层纯数据类型（P1A §T1.1）。
//!
//! 本文件承载编码层接口层的不含 trait 的数据类型：
//! [`Timestamp`] / [`DirtyTileMap`] / [`TileRegion`] / [`Codec`] /
//! [`PacketKind`] / [`EncodedPacket`] / [`GpuTexture`]。
//!
//! trait（[`crate::encoder::video::VideoEncoder`] /
//! [`crate::encoder::video::AudioEncoder`]）与新 [`EncodeError`] enum 定义在
//! `video/mod.rs`，避免与本文件纯数据耦合。
//!
//! # 边界
//!
//! 与现有 P1A 之前的旧 `encoder::VideoEncoder` trait（签名
//! `encode(&mut self, rgba, w, h)`）并存；二者位于不同模块路径，互不冲突。
//! P1C 完成硬件/软编码后端迁移后再合并。

use std::time::Instant;

// ════════════════════════════════════════════════════════════════
// Timestamp — 统一时间戳（单调时钟 + 会话相对 PTS）
// ════════════════════════════════════════════════════════════════

/// 统一时间戳：单调时钟 (`std::time::Instant`) 自捕获时刻起算。
///
/// 三条流水线（视频/音频/键鼠）通过此类型同步。
/// - `instant`：捕获时刻的单调时钟（用于本机时序测量 / 抖动统计）
/// - `pts`：会话相对毫秒 PTS（从会话起始起算，供客户端对齐）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    /// 捕获时刻的单调时钟。
    pub instant: Instant,
    /// 会话相对毫秒 PTS（从会话起始起算，供客户端对齐）。
    pub pts: u64,
}

impl Timestamp {
    /// 创建：pts 由调用方会话时钟分配（`monotonic_ms - session_start_ms`）。
    pub fn new(instant: Instant, pts: u64) -> Self {
        Self { instant, pts }
    }

    /// 自 now 起算的 Timestamp（pts = 0，测试/回退用）。
    pub fn now() -> Self {
        Self {
            instant: Instant::now(),
            pts: 0,
        }
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

// ════════════════════════════════════════════════════════════════
// DirtyTileMap — Tile-Hash Diff 的输出，兼作 ROI Mask
// ════════════════════════════════════════════════════════════════

/// 脏块地图：Tile-Hash Diff 的输出，兼作 ROI Mask。
///
/// `dirty` 长度 = `grid_w * grid_h`，逐 tile（行主序）标记是否变化。
/// 由 [`crate::encoder::video::tile_diff`] 产出，喂给大动分支作为 ROI。
#[derive(Debug, Clone, Default)]
pub struct DirtyTileMap {
    /// tile 尺寸（默认 64×64）。
    pub tile_w: u32,
    /// tile 尺寸（默认 64×64）。
    pub tile_h: u32,
    /// 网格宽 = `ceil(width / tile_w)`。
    pub grid_w: u32,
    /// 网格高 = `ceil(height / tile_h)`。
    pub grid_h: u32,
    /// 逐 tile 标记，`len = grid_w * grid_h`。
    pub dirty: Vec<bool>,
    /// 0.0 ~ 1.0；由 [`compute_ratio`](Self::compute_ratio) 填充。
    pub dirty_ratio: f32,
}

impl DirtyTileMap {
    /// 从 `dirty` 计数计算 `dirty_ratio`；全空时 ratio = 0。
    ///
    /// NaN 防御：若 `dirty` 为空（0 tiles），ratio 保持 0.0。
    pub fn compute_ratio(&mut self) {
        let total = self.dirty.len();
        if total == 0 {
            self.dirty_ratio = 0.0;
            return;
        }
        let count = self.dirty.iter().filter(|b| **b).count();
        self.dirty_ratio = count as f32 / total as f32;
    }

    /// dirty tile 索引列表（升序），用于大动分支 ROI 组装 / 微变分支提取。
    pub fn dirty_indices(&self) -> Vec<u32> {
        self.dirty
            .iter()
            .enumerate()
            .filter_map(|(i, b)| if *b { Some(i as u32) } else { None })
            .collect()
    }
}

// ════════════════════════════════════════════════════════════════
// TileRegion — 一个脏块矩形区域（tile 坐标单位）
// ════════════════════════════════════════════════════════════════

/// 一个脏块矩形区域（tile 网格坐标单位）。
///
/// 由 [`merge_regions`](crate::encoder::video::tile_diff::merge_regions)
/// 把同行的连续 dirty tile 合并产出，喂给微变分支做 RLE 增量提取。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TileRegion {
    /// tile 网格坐标（左上）。
    pub x: u32,
    /// tile 网格坐标（左上）。
    pub y: u32,
    /// tile 网格宽高。
    pub w: u32,
    /// tile 网格宽高。
    pub h: u32,
}

impl TileRegion {
    /// 单 tile region（1×1）。
    pub fn single(x: u32, y: u32) -> Self {
        Self { x, y, w: 1, h: 1 }
    }
}

// ════════════════════════════════════════════════════════════════
// Codec / PacketKind / EncodedPacket
// ════════════════════════════════════════════════════════════════

/// 编码标准（H.264 默认 / H.265 协商 / AV1（R-32，M13-T002 阶段 B））。
///
/// 注意：与旧 `encoder::Codec`（含 `Jpeg`）并存于不同模块路径；P1C 合并。
/// 新增变体走**字符串协商**（[`as_str`](Self::as_str) / [`from_str`](Self::from_str)），
/// 不触碰既有 wire 格式（握手/控制消息均为字符串，向后兼容）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    H264,
    H265,
    /// AV1（SVT-AV1 软编；协商存在，运行时不可用时由
    /// [`crate::encoder::factory::create_video_encoder`] 自动回退 H.264）。
    AV1,
}

impl Codec {
    /// FFmpeg 编码器短名（默认软编回退名）。
    pub fn ffmpeg_sw_name(self) -> &'static str {
        match self {
            Codec::H264 => "libx264",
            Codec::H265 => "libx265",
            // R-32（M13-T002）：SVT-AV1 为 FFmpeg full build 默认 AV1 软编
            // （av1_probe 已验证链路；libaom_av1/librav1e 为回退链候补）。
            Codec::AV1 => "libsvtav1",
        }
    }

    /// 握手/控制消息协商字符串（wire 格式，与既有 `CODEC_H264="h264"` /
    /// `CODEC_H265="h265"` 同族）：`"h264"` | `"h265"` | `"av1"`。
    pub fn as_str(self) -> &'static str {
        match self {
            Codec::H264 => "h264",
            Codec::H265 => "h265",
            Codec::AV1 => "av1",
        }
    }

    /// 从协商字符串解析；未知/空串 → `None`（调用方按 H.264 兜底）。
    pub fn from_str(s: &str) -> Option<Codec> {
        match s {
            "h264" => Some(Codec::H264),
            "h265" => Some(Codec::H265),
            "av1" => Some(Codec::AV1),
            _ => None,
        }
    }
}

/// 包类型（视频/音频/键鼠回声/剪贴板/文件传输/控制）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Video,
    Audio,
    InputEcho,
    /// M13-T003: 剪贴板文本推送（UTF-8，客户端 ⇄ 服务端双向）。
    Clipboard,
    /// M13-T006: 文件传输块（双向，64 KiB 大帧，走可靠流）。
    FileTransfer,
    /// M8-T018: 显示器控制消息（bincode [`ControlMessage`]，双向可靠流；
    /// 走既有的 `ChannelTag::Control`，SecureChannel 路径复用 tag 分帧）。
    ///
    /// [`ControlMessage`]: crate::transport::ControlMessage
    Control,
}

// ════════════════════════════════════════════════════════════════
// EncodeDecision — 决策结果三态（GPU 闭环产出）
// ════════════════════════════════════════════════════════════════

/// 决策结果三态（GPU 闭环产出）。
///
/// 由 [`crate::encoder::video::tile_diff::TileDiff::classify`] 产出，
/// 决定 [`VideoEncoder`](crate::encoder::video::VideoEncoder) 走哪条路径。
///
/// - [`Static`](Self::Static)：全静 → 编码层零输出（心跳归传输层 M3-DNS004）
/// - [`Incremental`](Self::Incremental)：微变 → tile 增量（RLE）；坐标指令仅作编码器失效回退
/// - [`FullFrame`](Self::FullFrame)：大动 → ROI Mask + 编码器
#[derive(Debug, Clone)]
pub enum EncodeDecision {
    /// 全静 → 编码层零输出（心跳归传输层 M3-DNS004）。
    Static,
    /// 微变 → tile 增量（RLE）；坐标指令仅作编码器失效回退。
    Incremental(Vec<TileRegion>),
    /// 大动 → ROI Mask + 编码器。
    FullFrame(DirtyTileMap),
}

/// 统一输出包：视频/音频同构，携带时间戳。
///
/// - 视频：`data` = Annex B（H.264/H.265），`is_key` = IDR
/// - 音频：`data` = Opus 帧，`is_key` = 会话首包
#[derive(Debug, Clone)]
pub struct EncodedPacket {
    /// 包时间戳（捕获时刻单调时钟 + 会话 PTS）。
    pub ts: Timestamp,
    /// 包类型。
    pub kind: PacketKind,
    /// 码流数据：视频 = Annex B；音频 = Opus 帧。
    pub data: Vec<u8>,
    /// 是否为关键帧（视频 IDR / 音频会话首包）。
    pub is_key: bool,
}

// ════════════════════════════════════════════════════════════════
// GpuTexture — 跨平台 GPU 纹理句柄（C++ 内核输入）
// ════════════════════════════════════════════════════════════════

/// 跨平台 GPU 纹理句柄（C++ 内核输入），由 capture 层产出。
///
/// 本阶段先定义 opaque 类型，P1B 接入真实句柄。
/// - Windows：`handle` = `ID3D11Texture2D*`
/// - Linux：`handle` = VAAPI surface
///
/// 句柄为 null 表示无效纹理，编码层应返回
/// [`InvalidConfig("null texture")`](crate::encoder::video::EncodeError::InvalidConfig)，
/// 不 panic。
#[derive(Debug, Clone, Copy)]
pub struct GpuTexture {
    /// D3D11 `ID3D11Texture2D*` / VAAPI surface。`pub(crate)` 仅供内核桥接。
    pub(crate) handle: *mut std::ffi::c_void,
    pub(crate) width: u32,
    pub(crate) height: u32,
}

impl GpuTexture {
    /// 构造一个句柄（P1B 由 capture 层调用）。
    pub fn new(handle: *mut std::ffi::c_void, width: u32, height: u32) -> Self {
        Self {
            handle,
            width,
            height,
        }
    }

    /// 句柄是否为 null（无效纹理）。
    pub fn is_null(&self) -> bool {
        self.handle.is_null()
    }

    /// 纹理宽度（像素）。
    pub fn width(&self) -> u32 {
        self.width
    }

    /// 纹理高度（像素）。
    pub fn height(&self) -> u32 {
        self.height
    }
}

// Safety: GpuTexture 只承载指针不拥有资源；跨线程使用时须在 capture 侧
// 保证纹理存活（捕获帧的生命周期由 capture 层管理，本结构仅借用）。
unsafe impl Send for GpuTexture {}
unsafe impl Sync for GpuTexture {}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// P1A Tests：pts 单调递增（构造序列单调）。
    #[test]
    fn test_timestamp_pts_monotonic() {
        let t0 = Timestamp::new(Instant::now(), 0);
        let t1 = Timestamp::new(Instant::now(), 16);
        let t2 = Timestamp::new(Instant::now(), 33);
        assert!(t1.pts > t0.pts);
        assert!(t2.pts > t1.pts);
        // now() 默认 pts=0，用于测试/回退。
        assert_eq!(Timestamp::now().pts, 0);
    }

    /// P1A Tests：compute_ratio 数学正确（0 / 0.5 / 1.0）。
    #[test]
    fn test_dirty_map_ratio() {
        // 全静 → 0.0
        let mut m = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 2,
            grid_h: 2,
            dirty: vec![false, false, false, false],
            dirty_ratio: 0.0,
        };
        m.compute_ratio();
        assert_eq!(m.dirty_ratio, 0.0);

        // 一半 → 0.5
        m.dirty = vec![true, false, false, true];
        m.compute_ratio();
        assert_eq!(m.dirty_ratio, 0.5);

        // 全 dirty → 1.0
        m.dirty = vec![true, true, true, true];
        m.compute_ratio();
        assert_eq!(m.dirty_ratio, 1.0);

        // 空地图 → 0.0（NaN 防御）
        let mut empty = DirtyTileMap::default();
        empty.compute_ratio();
        assert_eq!(empty.dirty_ratio, 0.0);
        assert!(!empty.dirty_ratio.is_nan());
    }

    /// P1A Tests：dirty_indices 升序且只含 dirty tile。
    #[test]
    fn test_dirty_indices_order() {
        let m = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 4,
            grid_h: 1,
            dirty: vec![false, true, false, true],
            dirty_ratio: 0.5,
        };
        let idx = m.dirty_indices();
        assert_eq!(idx, vec![1, 3]); // 升序
                                     // 全静
        let m2 = DirtyTileMap {
            tile_w: 64,
            tile_h: 64,
            grid_w: 3,
            grid_h: 1,
            dirty: vec![false, false, false],
            dirty_ratio: 0.0,
        };
        assert!(m2.dirty_indices().is_empty());
    }

    #[test]
    fn test_gpu_texture_null_check() {
        let null_tex = GpuTexture::new(std::ptr::null_mut(), 0, 0);
        assert!(null_tex.is_null());

        // 非空句柄（用一个伪造的非空指针；不 deref，仅查 is_null）
        let fake_handle = 0x1usize as *mut std::ffi::c_void;
        let tex = GpuTexture::new(fake_handle, 1920, 1080);
        assert!(!tex.is_null());
        assert_eq!(tex.width(), 1920);
        assert_eq!(tex.height(), 1080);
    }

    #[test]
    fn test_codec_sw_name() {
        assert_eq!(Codec::H264.ffmpeg_sw_name(), "libx264");
        assert_eq!(Codec::H265.ffmpeg_sw_name(), "libx265");
        // R-32（M13-T002 阶段 B）：AV1 软编名 = SVT-AV1。
        assert_eq!(Codec::AV1.ffmpeg_sw_name(), "libsvtav1");
    }

    /// R-32（S1 验收）：AV1 枚举序列化兼容——协商字符串往返 + 未知回退。
    #[test]
    fn test_codec_wire_string_roundtrip() {
        assert_eq!(Codec::H264.as_str(), "h264");
        assert_eq!(Codec::H265.as_str(), "h265");
        assert_eq!(Codec::AV1.as_str(), "av1");
        // 往返：所有变体 as_str → from_str 恒等。
        for c in [Codec::H264, Codec::H265, Codec::AV1] {
            assert_eq!(Codec::from_str(c.as_str()), Some(c), "{c:?} roundtrip");
        }
        // 未知/空串 → None（调用方按 H.264 兜底，不 panic）。
        assert_eq!(Codec::from_str(""), None);
        assert_eq!(Codec::from_str("vp9"), None);
        assert_eq!(Codec::from_str("AV1"), None); // 大小写敏感（与既有 h264 一致）
    }

    #[test]
    fn test_tile_region_single() {
        let r = TileRegion::single(2, 3);
        assert_eq!(
            r,
            TileRegion {
                x: 2,
                y: 3,
                w: 1,
                h: 1
            }
        );
    }
}
