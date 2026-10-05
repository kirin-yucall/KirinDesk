//! 可变帧率控制器。
//!
//! # 目标
//!
//! 根据屏幕内容活动度动态调节编码/发送帧率，降低静态场景的 CPU 与带宽消耗：
//!
//! | 场景 | 活动度 | 目标帧率 |
//! |------|--------|---------|
//! | 静止桌面（连续 N 窗口无/少变化） | ≤ `static_ratio` | 1 fps（`static_fps`） |
//! | 运动（滚动/游戏） | ≥ `motion_ratio` | 30 fps（`motion_fps`） |
//!
//! # 机制
//!
//! - **静帧检测**：活动度 EMA 连续 `static_confirm_windows` 个窗口低于阈值才降频
//!   （迟滞，避免单个静止窗口触发抖动）。
//! - **运动检测**：活动度冲高立即恢复高帧率（无确认延迟，运动响应最快）。
//! - **频率门控**：`should_encode` 按目标帧率的最小间隔放行窗口编码；未放行的
//!   窗口保持打开继续收集最新帧，恢复编码时内容仍是最新的。
//!
//! # 活动度定义
//!
//! 归一化变化 tile 比例（0.0 = 全静，1.0 = 整屏变化），由
//! [`tile_activity`] 对相邻两帧 RGBA 采样计算——每 tile 取 5 个采样点
//! （4 角 + 中心），一次比较仅 ~10KB 读取（1080p，64×64 tile），远低于
//! 全帧逐像素比对（8MB）。
//!
//! # 与自适应引擎的关系
//!
//! 两者正交互补：本模块是**内容驱动**的帧率控制（场景是否变化）；
//! `AdaptiveEngine` 是**网络驱动**的画质/帧率控制（拥塞与否）。
//! 网络降级通过 `EncodeConfig.frame_ratio` 在窗口内跳帧；本模块在窗口
//! 边界整体跳过编码窗口。窗口级跳过后的 `EncodedWindow` 为 frame_count=0
//! 的空窗口，会话层按静默窗口处理（与 idle 超时语义一致）。

use std::time::{Duration, Instant};

use crate::proto::DirtyRect;

/// 默认 tile 尺寸（与编码器前置决策层 `TileDiffConfig` 一致：64×64）。
pub const DEFAULT_TILE_W: u32 = 64;
pub const DEFAULT_TILE_H: u32 = 64;

/// 每 tile 采样点数（4 角 + 中心）。
const SAMPLES_PER_TILE: usize = 5;

/// 帧率档位配置。
#[derive(Debug, Clone, Copy)]
pub struct FpsGovernorConfig {
    /// 活动度 ≤ 此值视为静态（默认 0.001）。
    pub static_ratio: f64,
    /// 活动度 ≥ 此值视为运动（默认 0.05）。
    pub motion_ratio: f64,
    /// 静态档目标帧率（默认 1）。
    pub static_fps: f64,
    /// 中间态下 10fps 观感明显卡顿，用户裁定交互场景至少 15-30fps）。
    pub low_fps: f64,
    /// 运动档目标帧率（默认 30）。
    pub motion_fps: f64,
    /// 连续静态窗口数，达到后才降频（默认 3，迟滞）。
    pub static_confirm_windows: u32,
    /// 活动度 EMA 平滑系数（默认 0.2）。
    pub ema_alpha: f64,
}

impl Default for FpsGovernorConfig {
    fn default() -> Self {
        Self {
            static_ratio: 0.001,
            motion_ratio: 0.05,
            static_fps: 1.0,
            low_fps: 15.0,
            motion_fps: 30.0,
            static_confirm_windows: 3,
            ema_alpha: 0.2,
        }
    }
}

///
/// 抖动）与门控间隔同量级时，严格 `>=` 判定使 30fps 内容在 30fps 档位被
/// 随机拒绝 → 2 帧窗口批量 + 节奏空洞（25.1fps 实出、e2e p95 215ms）。
/// 10% 容差放行上界 ≈ 档位 ×1.11（30→33fps），开销可忽略。
const GATE_TOLERANCE_FRACTION: f64 = 0.9;

/// 可变帧率控制器。
pub struct FpsGovernor {
    cfg: FpsGovernorConfig,
    /// 活动度 EMA（0.0~1.0）。
    activity_ema: f64,
    /// 连续静态窗口计数（迟滞确认）。
    static_windows: u32,
    /// 当前目标帧率。
    target_fps: f64,
    /// 上次实际编码时间（频率门控用）。
    last_encoded: Option<Instant>,
    /// 由调用方在每次 feed 前按「最近输入时刻」设置——高分辨率屏的小变化
    /// （悬停/菜单/光标级内容）可能被 tile 采样误判为静态 → 1fps 钉死，
    /// 交互地板保证「人在操作」期间至少中间档。
    floor_fps: f64,
}

impl FpsGovernor {
    /// 创建控制器（默认配置）。
    pub fn new() -> Self {
        Self::with_config(FpsGovernorConfig::default())
    }

    /// 创建控制器（自定义配置）。
    pub fn with_config(cfg: FpsGovernorConfig) -> Self {
        Self {
            cfg,
            // EMA 初始为 0（静帧假设）：静态场景即时降频；运动首帧
            // （feed(1.0) → EMA 0.2 ≥ motion_ratio）即时升频，双向最优。
            activity_ema: 0.0,
            static_windows: 0,
            target_fps: cfg.motion_fps,
            last_encoded: None,
            floor_fps: 0.0,
        }
    }

    /// 喂入一帧的活动度（0.0~1.0），更新 EMA 与目标帧率。
    ///
    /// 返回更新后的目标帧率（与 [`target_fps`](Self::target_fps) 一致）。
    pub fn feed(&mut self, activity: f64) -> f64 {
        let a = activity.clamp(0.0, 1.0);
        // EMA 平滑（防单帧抖动）。
        self.activity_ema += (a - self.activity_ema) * self.cfg.ema_alpha;
        let ema = self.activity_ema;

        if ema >= self.cfg.motion_ratio {
            // 运动：立即恢复高帧率，清零静态计数。
            self.static_windows = 0;
            self.target_fps = self.cfg.motion_fps;
        } else if ema <= self.cfg.static_ratio {
            // 静态候选：连续确认才降到底档；确认中停中间档。
            self.static_windows = self.static_windows.saturating_add(1);
            if self.static_windows >= self.cfg.static_confirm_windows {
                self.target_fps = self.cfg.static_fps;
            } else {
                self.target_fps = self.cfg.low_fps;
            }
        } else {
            self.static_windows = 0;
            self.target_fps = self.cfg.low_fps;
        }
        // （地板只升不降；运动档 ≥ 地板时无效果）。
        self.target_fps = self.target_fps.max(self.floor_fps);
        self.target_fps
    }

    /// 在每次 [`feed`](Self::feed) 前更新；地板作用于**下一次** feed 的
    /// 档位裁决与后续 [`should_encode`](Self::should_encode) 间隔。
    pub fn set_floor(&mut self, fps: f64) {
        self.floor_fps = fps.max(0.0);
    }

    /// 当前交互地板（诊断）。
    pub fn floor_fps(&self) -> f64 {
        self.floor_fps
    }

    /// 当前目标帧率。
    pub fn target_fps(&self) -> f64 {
        self.target_fps
    }

    /// 当前活动度 EMA（诊断）。
    pub fn activity(&self) -> f64 {
        self.activity_ema
    }

    /// 当前配置（诊断/测试）。
    pub fn config(&self) -> FpsGovernorConfig {
        self.cfg
    }

    /// 频率门控：距上次编码是否已到目标间隔，允许编码下一窗口。
    ///
    /// 首个窗口恒放行（无历史）。未放行时窗口保持打开继续收集帧，
    /// 由调用方跳过本次编码（返回空窗口语义）。
    ///
    /// 判定——见常量注释（严格 `>=` 在档边界随机拒绝同频源）。
    pub fn should_encode(&self, now: Instant) -> bool {
        match self.last_encoded {
            None => true,
            Some(t) => {
                let allow = (1.0 / self.target_fps.max(0.1)) * GATE_TOLERANCE_FRACTION;
                now.checked_duration_since(t)
                    .unwrap_or(Duration::ZERO)
                    .as_secs_f64()
                    >= allow
            }
        }
    }

    /// 记录一次实际编码（门控基准时间）。
    pub fn mark_encoded(&mut self, now: Instant) {
        self.last_encoded = Some(now);
    }

    /// 当前目标帧率对应的最小窗口间隔。
    pub fn interval(&self) -> Duration {
        Duration::from_secs_f64(1.0 / self.target_fps.max(0.1))
    }

    /// 重置（新连接/会话开始时）。
    pub fn reset(&mut self) {
        self.activity_ema = 0.0;
        self.static_windows = 0;
        self.target_fps = self.cfg.motion_fps;
        self.last_encoded = None;
        self.floor_fps = 0.0;
    }
}

impl Default for FpsGovernor {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════
// tile_activity — 静帧/运动检测的采样比较
// ════════════════════════════════════════════════════════════════

/// 计算两帧 RGBA 之间的活动度：变化 tile 数 / 总 tile 数（0.0~1.0）。
///
/// 每 tile 采样 5 个点（4 角 + 中心，各 4 字节 RGBA），任一采样点不同即视为
/// 该 tile 变化。与编码器前置决策层（`TileDiff`）同用 64×64 tile 网格，
/// 语义一致（"tile 变化数"）。
///
/// # 参数
///
/// - `cur` / `prev` — 当前帧 / 上一帧 RGBA（长度必须 ≥ w*h*4）
/// - `w` / `h` — 帧宽高（像素）
/// - `tile_w` / `tile_h` — tile 尺寸（默认 64×64）
///
/// 任意参数非法（长度不足 / 零尺寸）返回 1.0（视为大动，安全侧）。
pub fn tile_activity(
    cur: &[u8],
    prev: &[u8],
    w: u32,
    h: u32,
    tile_w: u32,
    tile_h: u32,
) -> f64 {
    let w = w.max(1);
    let h = h.max(1);
    let tile_w = tile_w.max(1);
    let tile_h = tile_h.max(1);
    let stride = w as usize * 4;
    let need = stride * h as usize;
    if cur.len() < need || prev.len() < need {
        return 1.0;
    }

    let grid_w = w.div_ceil(tile_w);
    let grid_h = h.div_ceil(tile_h);
    let mut changed: u64 = 0;

    for ty in 0..grid_h {
        for tx in 0..grid_w {
            // tile 像素范围（右/下边缘可能超出帧尺寸——按帧内实际范围采样）。
            let x0 = tx * tile_w;
            let y0 = ty * tile_h;
            let x1 = ((tx + 1) * tile_w).min(w).saturating_sub(1);
            let y1 = ((ty + 1) * tile_h).min(h).saturating_sub(1);

            // 5 个采样点：4 角 + 中心。
            let pts = [
                (x0, y0),
                (x1, y0),
                (x0, y1),
                (x1, y1),
                ((x0 + x1) / 2, (y0 + y1) / 2),
            ];
            debug_assert_eq!(pts.len(), SAMPLES_PER_TILE, "采样点数须与常量一致");
            let mut tile_changed = false;
            for &(sx, sy) in pts.iter() {
                let off = sy as usize * stride + sx as usize * 4;
                if cur[off..off + 4] != prev[off..off + 4] {
                    tile_changed = true;
                    break;
                }
            }
            if tile_changed {
                changed += 1;
            }
        }
    }

    let total = (grid_w * grid_h).max(1) as f64;
    changed as f64 / total
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

///
/// 捕获层（DXGI `GetDirtyRects` 同源）提供的重绘区域是 OS 直接产出的
/// 可信信号——光标级小变化（悬停/菜单/光标拖动）tile 5 点采样看不见
/// （采样点不动 → `tile_activity`=0），但 dirty rect 一定非空。
///
/// 越界矩形按帧范围裁剪；`w`/`h` 为 0 → 0.0（无信号，不视为大动）；
/// 空 rects → 0.0。面积和超过整帧（重叠 rects）截断到 1.0。
pub fn dirty_rects_area_ratio(rects: &[DirtyRect], w: u32, h: u32) -> f64 {
    if w == 0 || h == 0 {
        return 0.0;
    }
    let total = w as f64 * h as f64;
    let mut area: f64 = 0.0;
    for r in rects {
        let x0 = r.x as i64;
        let y0 = r.y as i64;
        let x1 = (r.x.saturating_add(r.w)) as i64;
        let y1 = (r.y.saturating_add(r.h)) as i64;
        if x1 <= x0 || y1 <= y0 {
            continue;
        }
        let cx0 = x0.max(0);
        let cy0 = y0.max(0);
        let cx1 = x1.min(w as i64);
        let cy1 = y1.min(h as i64);
        if cx1 > cx0 && cy1 > cy0 {
            area += (cx1 - cx0) as f64 * (cy1 - cy0) as f64;
        }
    }
    (area / total).min(1.0)
}

///
/// 口径（PM 裁定）：`dirty_rects` 非空且像素面积占比 >0 → 活动度**至少为
/// 中间档**。实现取 `max(tile_act, max(dirty_ratio, mid))`：
///
/// - `mid` = (static_ratio + motion_ratio) / 2——按**当前配置**恒落在
///   （static, motion）开区间 → 档位裁决必落中间档（不钉静态 1fps，
///   也不误升运动档）；
/// - `dirty_ratio ≥ mid`（大面积重绘，如 ≥motion_ratio 的整屏刷新）→
///   直接以面积占比为活动度，自然升运动档；
/// - `dirty_ratio ≤ 0`（rects 缺失/空/零面积）→ 原样返回 `tile_act`
///
/// 根治场景（用户「鼠标移动后画面才跟上」）：光标级小变化 tile 采样
/// 活动度 0 → 连续 3 窗确认 → 钉死静态 1fps；dirty rect 兜底后活动度
/// 恒 ≥ 中间档下界，交互画面随动。
pub fn activity_with_dirty_fallback(
    tile_act: f64,
    dirty_ratio: f64,
    cfg: &FpsGovernorConfig,
) -> f64 {
    if dirty_ratio <= 0.0 {
        return tile_act;
    }
    let mid = (cfg.static_ratio + cfg.motion_ratio) / 2.0;
    tile_act.max(dirty_ratio.max(mid))
}

// ── 测试 ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: u32, h: u32, fill: u8) -> Vec<u8> {
        vec![fill; (w * h * 4) as usize]
    }

    // ── tile_activity ──────────────────────────────────────────

    /// 相同帧 → 活动度 0（静帧）。
    #[test]
    fn test_activity_identical_frames() {
        let f = frame(640, 480, 128);
        let a = tile_activity(&f, &f, 640, 480, 64, 64);
        assert_eq!(a, 0.0);
    }

    /// 完全不同的帧 → 活动度 1（大动）。
    #[test]
    fn test_activity_all_changed() {
        let a = frame(640, 480, 10);
        let b = frame(640, 480, 200);
        let a = tile_activity(&a, &b, 640, 480, 64, 64);
        assert_eq!(a, 1.0);
    }

    /// 单 tile 变化 → 活动度 = 1 / tile 总数。
    #[test]
    fn test_activity_single_tile() {
        // 128×128，tile 64 → 2×2 = 4 tile。改中心采样点（64,64）→ 右下 tile 变化。
        let mut a = frame(128, 128, 0);
        let mut b = frame(128, 128, 0);
        let off = (64 * 128 + 64) * 4; // (x=64, y=64)
        b[off] = 255;
        let activity = tile_activity(&a, &b, 128, 128, 64, 64);
        assert!(
            (activity - 0.25).abs() < 1e-9,
            "1/4 tile changed, got {activity}"
        );
        // 边界 tile（x=127, y=127）→ 中心点采样也变 → 仍是 1/4（同 tile）。
        let off2 = (127 * 128 + 127) * 4;
        b[off2] = 255;
        let activity2 = tile_activity(&a, &b, 128, 128, 64, 64);
        assert!((activity2 - 0.25).abs() < 1e-9);
    }

    /// 非 64 对齐尺寸（100×100）→ 边缘 tile 按帧内范围采样，不越界。
    #[test]
    fn test_activity_unaligned_size() {
        let a = frame(100, 100, 7);
        let b = frame(100, 100, 7);
        // 修改右下角边缘像素（在最后一个 tile 内）。
        let off = (99 * 100 + 99) * 4;
        let mut c = b.clone();
        c[off] = 42;
        let activity = tile_activity(&a, &c, 100, 100, 64, 64);
        // 2×2 tile 网格，1 tile 变 → 0.25。
        assert!((activity - 0.25).abs() < 1e-9);
    }

    /// 长度不足 → 安全侧 1.0。
    #[test]
    fn test_activity_short_buffer_returns_full() {
        let a = vec![0u8; 4];
        let b = vec![0u8; 4];
        assert_eq!(tile_activity(&a, &b, 640, 480, 64, 64), 1.0);
        assert_eq!(tile_activity(&[], &[], 0, 0, 64, 64), 1.0);
    }


    /// dirty_rects 面积占比：空/零尺寸/越界裁剪/重叠截断。
    #[test]
    fn test_r88b3_dirty_rects_area_ratio() {
        use crate::proto::DirtyRect;
        // 空 rects / 零帧尺寸 → 0（无信号）。
        assert_eq!(dirty_rects_area_ratio(&[], 640, 480), 0.0);
        assert_eq!(dirty_rects_area_ratio(&[DirtyRect { x: 0, y: 0, w: 8, h: 8 }], 0, 0), 0.0);
        // 单 rect 精确占比（640×480 = 307200 px；16×16 = 256 px）。
        let r = dirty_rects_area_ratio(&[DirtyRect { x: 100, y: 100, w: 16, h: 16 }], 640, 480);
        assert!((r - 256.0 / 307_200.0).abs() < 1e-12, "got {r}");
        // 越界 rect 按帧范围裁剪（右/下溢出裁掉，左上负值从 0 起）。
        let over = dirty_rects_area_ratio(&[DirtyRect { x: 600, y: 400, w: 100, h: 100 }], 640, 480);
        // 帧内部分 = 40×80 = 3200 px。
        assert!((over - 3200.0 / 307_200.0).abs() < 1e-12, "got {over}");
        let neg = dirty_rects_area_ratio(&[DirtyRect { x: 0, y: 0, w: 32, h: 32 }], 640, 480);
        assert!((neg - 1024.0 / 307_200.0).abs() < 1e-12);
        // 完全在帧外 → 0。
        assert_eq!(dirty_rects_area_ratio(&[DirtyRect { x: 700, y: 500, w: 10, h: 10 }], 640, 480), 0.0);
        // 零面积 rect（w=0）→ 0。
        assert_eq!(dirty_rects_area_ratio(&[DirtyRect { x: 5, y: 5, w: 0, h: 8 }], 640, 480), 0.0);
        // 重叠 rects 面积和超过整帧 → 截断 1.0。
        let both = [
            DirtyRect { x: 0, y: 0, w: 640, h: 480 },
            DirtyRect { x: 0, y: 0, w: 640, h: 480 },
        ];
        assert_eq!(dirty_rects_area_ratio(&both, 640, 480), 1.0);
    }

    /// 兜底核心口径：tile 采样 0（光标级盲点）+ 微小 dirty rect 非空
    /// → 活动度抬到中间档（mid），档位裁决不落静态；大面积 → 运动档；
    /// rects 缺失 → tile 原样回落。
    #[test]
    fn test_r88b3_activity_dirty_fallback_tiers() {
        let cfg = FpsGovernorConfig::default(); // static 0.001 / motion 0.05
        let mid = (cfg.static_ratio + cfg.motion_ratio) / 2.0; // 0.0255
        // ① 光标级盲点：tile=0 + 光标 rect（16×16 @1920×1080 ≈ 0.000124）
        //    → mid（严格高于 static_ratio → 永不钉静态档）。
        let cursor_ratio = 256.0 / (1920.0 * 1080.0);
        let a = activity_with_dirty_fallback(0.0, cursor_ratio, &cfg);
        assert!((a - mid).abs() < 1e-12, "光标级应抬到中间档 mid, got {a}");
        assert!(a > cfg.static_ratio && a < cfg.motion_ratio);
        // ② 大面积重绘：dirty_ratio ≥ mid → 取 dirty_ratio（可升运动档）。
        let b = activity_with_dirty_fallback(0.0, 0.5, &cfg);
        assert!((b - 0.5).abs() < 1e-12, "大面积取面积占比, got {b}");
        assert!(b >= cfg.motion_ratio, "≥motion_ratio → 运动档");
        // ③ tile 已有更高值 → 不被压低（max 语义）。
        let c = activity_with_dirty_fallback(0.8, cursor_ratio, &cfg);
        assert!((c - 0.8).abs() < 1e-12);
        // ④ rects 缺失（ratio=0）→ tile 原样（行为逐位不变）。
        assert_eq!(activity_with_dirty_fallback(0.0, 0.0, &cfg), 0.0);
        assert_eq!(activity_with_dirty_fallback(0.3, 0.0, &cfg), 0.3);
        // ⑤ 档位裁决亲证：tile=0 + 光标 rect 的治理器 → 中间档 low_fps，
        //    而非静态档（对照：无 rects 同像素流会降静态档）。
        let mut g = FpsGovernor::with_config(cfg);
        let fed = activity_with_dirty_fallback(0.0, cursor_ratio, &cfg);
        for _ in 0..40 {
            g.feed(fed);
        }
        assert_eq!(g.target_fps(), cfg.low_fps, "dirty 兜底后应停中间档");
        let mut g2 = FpsGovernor::with_config(cfg);
        for _ in 0..40 {
            g2.feed(0.0); // 无 rects 回落路径
        }
        assert_eq!(g2.target_fps(), cfg.static_fps, "无 rects 仍按 tile=0 降静态档");
    }

    // ── FpsGovernor 状态机 ─────────────────────────────────────

    /// 初始：运动档，首窗口必放行。
    #[test]
    fn test_governor_initial() {
        let g = FpsGovernor::new();
        assert_eq!(g.target_fps(), 30.0);
        assert!(g.should_encode(Instant::now()), "first window always encodes");
    }

    /// 连续静态窗口 → 目标帧率阶梯下降 30 → 15 → 1（迟滞确认）。
    #[test]
    fn test_governor_static_downgrade() {
        let mut g = FpsGovernor::new();
        // 第 1 个静态窗口：EMA 0.8→0.64（alpha=0.2）→ 仍 ≥0.05？0.64 ≥ 0.05 → 运动档。
        // EMA 衰减到 <0.05 需要约 15 个窗口；直接喂 0.0 活动度看梯度。
        let mut target = 30.0;
        for i in 0..40u32 {
            let t = g.feed(0.0);
            if i == 39 {
                target = t;
            }
        }
        assert_eq!(target, g.cfg.static_fps, "静态确认后应到底档 1fps");
        assert!(
            g.static_windows >= g.cfg.static_confirm_windows,
            "需连续静态确认才降频"
        );
        // 再喂一个静态窗口 → 保持 1fps。
        assert_eq!(g.feed(0.0), 1.0);
    }

    /// 运动恢复 → 立即升回 30fps（无确认延迟）。
    #[test]
    fn test_governor_motion_resume() {
        let mut g = FpsGovernor::new();
        for _ in 0..40 {
            g.feed(0.0); // 降到 1fps
        }
        assert_eq!(g.target_fps(), 1.0);
        assert_eq!(g.feed(1.0), 30.0, "运动恢复应立即升频");
        assert_eq!(g.static_windows, 0, "运动清零静态计数");
    }

    #[test]
    fn test_governor_mid_activity() {
        let mut g = FpsGovernor::new();
        // 直接构造 EMA 在中位：先喂运动，再喂 0.01（>static_ratio <motion_ratio）。
        g.feed(1.0);
        for _ in 0..40 {
            g.feed(0.01);
        }
        assert_eq!(g.target_fps(), 15.0);
    }

    /// 单窗口静止不足确认 → 停在中间档（迟滞防抖动）。
    #[test]
    fn test_governor_single_static_no_confirmation() {
        let mut g = FpsGovernor::new();
        g.feed(1.0);
        // 单个静态窗口后仍应 ≥ 中间档（未达确认数，EMA 也仍高）。
        let t = g.feed(0.0);
        assert!(t >= 10.0, "单个静态窗口不应直接跳到底档, got {t}");
    }

    // ── 频率门控 ───────────────────────────────────────────────

    /// 门控：目标 30fps（间隔 33ms）→ 33ms 内不放行，到达后放行。
    #[test]
    fn test_governor_rate_gate() {
        let mut g = FpsGovernor::new();
        let t0 = Instant::now();
        g.mark_encoded(t0);
        assert!(!g.should_encode(t0), "刚编码后不应立即放行");
        assert!(
            !g.should_encode(t0 + Duration::from_millis(20)),
            "30fps 间隔 33ms 内不应放行"
        );
        assert!(
            g.should_encode(t0 + Duration::from_millis(40)),
            "超过间隔应放行"
        );
        // 静态档：间隔 1000ms。
        for _ in 0..40 {
            g.feed(0.0);
        }
        assert_eq!(g.target_fps(), 1.0);
        assert!(
            !g.should_encode(t0 + Duration::from_millis(100)),
            "1fps 间隔 1s 内不放行"
        );
        assert!(
            g.should_encode(t0 + Duration::from_secs(2)),
            "1fps 间隔过后放行"
        );
    }

    /// 放行（旧严格 `>=` 在 33.3ms 才放行；32ms 处旧判定为 false）。
    #[test]
    fn test_governor_gate_tolerance() {
        let mut g = FpsGovernor::new(); // 初始运动档 30fps（默认配置）
        let t0 = Instant::now();
        g.mark_encoded(t0);
        assert!(!g.should_encode(t0 + Duration::from_millis(25)), "25ms < 30ms 容差线");
        assert!(
            g.should_encode(t0 + Duration::from_millis(32)),
            "32ms ≥ 30ms 容差线应放行（旧严格口径 33.3ms 会拒绝）"
        );
        // 静态档：1000ms → 900ms 容差。
        for _ in 0..40 {
            g.feed(0.0);
        }
        assert_eq!(g.target_fps(), 1.0);
        assert!(!g.should_encode(t0 + Duration::from_millis(800)), "800ms < 900ms");
        assert!(
            g.should_encode(t0 + Duration::from_millis(950)),
            "950ms ≥ 900ms 容差线应放行（旧严格口径 1000ms 会拒绝）"
        );
    }

    /// 地板只升不降；reset 清除。
    #[test]
    fn test_governor_interaction_floor() {
        let mut g = FpsGovernor::with_config(FpsGovernorConfig {
            static_fps: 1.0,
            low_fps: 30.0,
            motion_fps: 60.0,
            ..FpsGovernorConfig::default()
        });
        // 无地板：连续静态 → 静态档 1fps（高分辨率小变化误判场景）。
        for _ in 0..40 {
            g.feed(0.0);
        }
        assert_eq!(g.target_fps(), 1.0);
        // 交互地板 = 中间档 → 静态启发式不再钉死 1fps。
        g.set_floor(30.0);
        assert_eq!(g.feed(0.0), 30.0, "交互地板把静态档抬到中间档");
        // 地板释放 → 回静态档。
        g.set_floor(0.0);
        assert_eq!(g.feed(0.0), 1.0, "地板释放后回静态档");
        // 地板只升不降：运动档 60 > 地板 30。
        g.set_floor(30.0);
        assert_eq!(g.feed(1.0), 60.0, "运动档不受低于它的地板影响");
        // reset 清除地板。
        g.reset();
        assert_eq!(g.floor_fps(), 0.0, "reset 清地板");
        // 负值地板按 0 处理（防御）。
        g.set_floor(-5.0);
        assert_eq!(g.floor_fps(), 0.0);
    }

    /// reset 恢复初始状态。
    #[test]
    fn test_governor_reset() {
        let mut g = FpsGovernor::new();
        for _ in 0..40 {
            g.feed(0.0);
        }
        g.mark_encoded(Instant::now());
        assert_eq!(g.target_fps(), 1.0);
        g.reset();
        assert_eq!(g.target_fps(), 30.0);
        assert!(g.should_encode(Instant::now()));
        assert_eq!(g.activity(), 0.0);
    }
}
