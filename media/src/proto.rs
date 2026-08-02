//! 媒体管道内部数据结构定义。
//!
//! 包含 RawFrame、WindowConfig、EncodeConfig、EncodedWindow 等核心类型。
//! 【优化】此模块作为底层数据结构层，不依赖任何具体的捕获后端（如 capture 模块）。

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::SystemTime;

// ════════════════════════════════════════════════════════════════
// DirtyRect — 脏矩形区域
// ════════════════════════════════════════════════════════════════

/// 【优化】将 DirtyRect 移入 proto 层，解除 proto 对 capture 模块的反向依赖。
/// capture 模块（如 DXGI）在构建 RawFrame 时，直接引用此类型即可。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirtyRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

// ════════════════════════════════════════════════════════════════
// RawFrame — 捕获后的原始帧
// ════════════════════════════════════════════════════════════════

/// 捕获原始帧（RGBA 像素数据）。
/// 【优化】使用 Arc<Vec<u8>> 实现零拷贝传递，避免跨线程/跨管道时的内存深拷贝。
#[derive(Debug, Clone)]
pub struct RawFrame {
    /// RGBA pixel data (width × height × 4 bytes)
    /// 使用 Arc 包裹，使得帧数据在 capture -> pipeline -> encoder 传递时仅增加引用计数。
    pub data: Arc<Vec<u8>>,
    /// 宽度（像素）
    pub width: u32,
    /// 高度（像素）
    pub height: u32,
    /// 【优化】使用 SystemTime 替代 Instant。
    /// Instant 是单调时钟，绝对不能用于跨网络或跨进程的时间戳对齐。
    pub timestamp: SystemTime,
    /// dirty rects（若有，DXGI 模式下来自原生 API）
    pub dirty_rects: Vec<DirtyRect>,
    /// 是否强制此帧为 IDR（窗口第一帧 / 重建后 / 编码器重置）
    pub force_key: bool,
}

impl RawFrame {
    /// 从 RGBA 数据创建新帧。
    pub fn new(data: Vec<u8>, width: u32, height: u32) -> Self {
        Self {
            data: Arc::new(data),
            width,
            height,
            timestamp: SystemTime::now(),
            dirty_rects: Vec::new(),
            force_key: false,
        }
    }

    /// 获取像素数据的切片引用。
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

// ════════════════════════════════════════════════════════════════
// DisplayInfo — 显示器信息（M8-T018 多显示器查看）
// ════════════════════════════════════════════════════════════════

/// 显示器信息（`DisplayListResp` 负载项，bincode 序列化）。
///
/// M8-T018：客户端据此渲染"显示器"下拉（名称/分辨率/主屏标记），
/// 坐标映射基数 = 所选显示器分辨率（CLI-MON-010）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayInfo {
    /// 显示器索引（0-based，与捕获侧 `Monitor::from_index` 约定一致）。
    pub index: u32,
    /// 显示器名称（如 "\\\\.\\DISPLAY1" / "Built-in Retina Display"）。
    pub name: String,
    /// 分辨率宽度（像素）。
    pub width: u32,
    /// 分辨率高度（像素）。
    pub height: u32,
    /// 是否主显示器。
    pub is_primary: bool,
}

// ════════════════════════════════════════════════════════════════
// WindowConfig — 窗口管理器配置
// ════════════════════════════════════════════════════════════════

/// 窗口配置。
/// 【优化】使用 derive(Default) 配合 #[default] 属性，新增字段时不易遗漏默认值。
#[derive(Debug, Clone)]
pub struct WindowConfig {
    /// 窗口时长（毫秒，默认 70ms）
    pub window_duration_ms: u64,
    /// 窗口内最大帧数（默认 10）
    pub max_frames_per_window: u32,
    /// 空闲超时——无画面变化时提前关闭窗口（毫秒，默认 200ms）
    pub idle_timeout_ms: u64,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            window_duration_ms: 70,
            max_frames_per_window: 10,
            idle_timeout_ms: 200,
        }
    }
}

// ════════════════════════════════════════════════════════════════
// EncodeConfig — 编码配置（可动态更新）
// ════════════════════════════════════════════════════════════════

/// 编码配置（由自适应策略动态调整）。
#[derive(Debug, Clone)]
pub struct EncodeConfig {
    /// QP 值 (0-51)，默认 22
    pub qp: u32,
    /// 是否强制下一帧为 IDR
    pub force_idr: bool,
    /// 帧保留比例 (0.0~1.0)，<1.0 时跳帧
    pub frame_ratio: f64,
    /// 编码器预设字符串
    pub preset: String,
}

impl Default for EncodeConfig {
    fn default() -> Self {
        Self {
            qp: 22,
            force_idr: false,
            frame_ratio: 1.0,
            preset: "ultrafast".into(),
        }
    }
}

// ════════════════════════════════════════════════════════════════
// EncodedWindow — 编码后的窗口结果
// ════════════════════════════════════════════════════════════════

/// 编码后的窗口结果。
/// 【优化】
/// 1. 使用 bytes::Bytes 替代 Vec<u8>，支持零拷贝切片。
/// 2. 扁平化存储 NALU 单元，消除 Vec<Vec<Vec<u8>>> 带来的严重内存碎片和分配器开销。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive] // 防止外部直接构造非法状态，强制使用构造函数
pub struct EncodedWindow {
    /// 窗口序号（单调递增）
    pub window_id: u64,
    /// 窗口内实际编码的帧数
    pub frame_count: u32,
    /// 原始捕获宽度
    pub base_w: u32,
    /// 原始捕获高度
    pub base_h: u32,
    /// 对齐后的编码宽度（16 的倍数）
    pub aligned_w: u32,
    /// 对齐后的编码高度
    pub aligned_h: u32,

    /// 【核心优化】所有 NALU 的扁平列表。
    /// 配合 frame_nalu_counts 使用，避免三层嵌套 Vec 导致的缓存未命中。
    pub nalus: Vec<Bytes>,
    /// 每帧包含的 NALU 数量。
    /// 例如：[2, 3] 表示第 0 帧有 2 个 NALU (nalus[0..2])，第 1 帧有 3 个 NALU (nalus[2..5])。
    pub frame_nalu_counts: Vec<usize>,

    /// 编码耗时（毫秒）
    pub encode_duration_ms: f64,

    /// 旧格式兼容字段：每个帧的编码后包列表。
    /// 迁移到 nalus + frame_nalu_counts 后的过渡字段。
    pub frames: Vec<Vec<Vec<u8>>>,
}

impl EncodedWindow {
    /// 构造一个编码窗口（legacy `frames` 格式）。
    ///
    /// `#[non_exhaustive]` 阻止外部直接构造，本构造函数供传输层测试
    /// （quic_transport_flow）与调试工具使用；正式编码路径由
    /// [`crate::window_pipeline::WindowPipeline`] 产出。
    pub fn new(window_id: u64, base_w: u32, base_h: u32, frames: Vec<Vec<Vec<u8>>>) -> Self {
        let frame_count = frames.len() as u32;
        let aligned_w = ((base_w + 15) / 16) * 16;
        let aligned_h = ((base_h + 15) / 16) * 16;
        Self {
            window_id,
            frame_count,
            base_w,
            base_h,
            aligned_w,
            aligned_h,
            nalus: vec![],
            frame_nalu_counts: vec![],
            frames,
            encode_duration_ms: 0.0,
        }
    }

    /// 是否为空窗口（无编码帧）。
    ///
    /// 注意：窗口数据可能填在扁平 `nalus`（新格式）或旧 `frames`（遗留格式）
    /// 任意一个字段——两者皆空才算空窗口。
    pub fn is_empty(&self) -> bool {
        self.frame_count == 0 || (self.nalus.is_empty() && self.frames.is_empty())
    }

    /// 获取指定帧的 NALU 切片。
    pub fn get_frame_nalus(&self, frame_index: usize) -> Option<&[Bytes]> {
        if frame_index >= self.frame_nalu_counts.len() {
            return None;
        }

        // 计算该帧在扁平 nalus 数组中的起始和结束偏移
        let start: usize = self.frame_nalu_counts[..frame_index].iter().sum();
        let count = self.frame_nalu_counts[frame_index];
        let end = start + count;

        self.nalus.get(start..end)
    }
}
