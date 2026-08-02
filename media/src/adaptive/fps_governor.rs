//! 可变帧率控制器（M13-T002）。
//!
//! # 目标
//!
//! 根据屏幕内容活动度动态调节编码/发送帧率，降低静态场景的 CPU 与带宽消耗：
//!
//! | 场景 | 活动度 | 目标帧率 |
//! |------|--------|---------|
//! | 静止桌面（连续 N 窗口无/少变化） | ≤ `static_ratio` | 1 fps（`static_fps`） |
//! | 少量变化（窗口/光标移动、中间态） | 两者之间 | 10 fps（`low_fps`） |
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
//! # 与自适应引擎（M8-T014）的关系
//!
//! 两者正交互补：本模块是**内容驱动**的帧率控制（场景是否变化）；
//! `AdaptiveEngine` 是**网络驱动**的画质/帧率控制（拥塞与否）。
//! 网络降级通过 `EncodeConfig.frame_ratio` 在窗口内跳帧；本模块在窗口
//! 边界整体跳过编码窗口。窗口级跳过后的 `EncodedWindow` 为 frame_count=0
//! 的空窗口，会话层按静默窗口处理（与 idle 超时语义一致）。

use std::time::{Duration, Instant};

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
    /// 中间档目标帧率（默认 10）。
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
            low_fps: 10.0,
            motion_fps: 30.0,
            static_confirm_windows: 3,
            ema_alpha: 0.2,
        }
    }
}

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
            // 中间态（少量变化）：10fps，重置静态计数。
            self.static_windows = 0;
            self.target_fps = self.cfg.low_fps;
        }
        self.target_fps
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
    pub fn should_encode(&self, now: Instant) -> bool {
        match self.last_encoded {
            None => true,
            Some(t) => now.checked_duration_since(t).unwrap_or(Duration::ZERO) >= self.interval(),
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

    // ── FpsGovernor 状态机 ─────────────────────────────────────

    /// 初始：运动档，首窗口必放行。
    #[test]
    fn test_governor_initial() {
        let g = FpsGovernor::new();
        assert_eq!(g.target_fps(), 30.0);
        assert!(g.should_encode(Instant::now()), "first window always encodes");
    }

    /// 连续静态窗口 → 目标帧率阶梯下降 30 → 10 → 1（迟滞确认）。
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

    /// 中间态（少量变化）→ 10fps。
    #[test]
    fn test_governor_mid_activity() {
        let mut g = FpsGovernor::new();
        // 直接构造 EMA 在中位：先喂运动，再喂 0.01（>static_ratio <motion_ratio）。
        g.feed(1.0);
        for _ in 0..40 {
            g.feed(0.01);
        }
        assert_eq!(g.target_fps(), 10.0);
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
