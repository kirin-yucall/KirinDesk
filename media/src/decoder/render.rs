//! 渲染桥（M8-T015 P2D）：视频抖动缓冲 + 解码线程 ↔ UI 线程通道投递。
//!
//! # 职责
//!
//! - [`VideoJitterBuffer`]：视频抖动缓冲——按 PTS 升序排序、乱序容错、
//!   丢帧追时（lip-sync 对齐音频主时钟，容限 2 帧）、PTS 跳变重置。
//! - [`RenderBridge`]：解码线程（`push_decoded`）与 UI 线程（`pop_render`）
//!   之间的 mpsc 通道桥；UI 侧 drain 通道 → 抖动缓冲 → 取下一帧渲染。
//!
//! # 线程模型（P2D §T4.3 最终版）
//!
//! ```text
//! [解码线程] push_decoded() ──mpsc channel──► [UI 线程] pop_render()
//!    │ 专用 std::thread                          │ egui repaint（~60fps）
//!    │ 阻塞 FFmpeg 调用                          │ drain + jitter 独占
//!    │                                           │
//! [音频线程] sync_audio_clock(pts) ──────────────►│ jitter lip-sync 对齐
//! ```
//!
//! 共享状态集中于 `Arc<Inner>`：
//! - `mpsc::Sender`（Send + Sync）——解码线程无锁直发；
//! - `Mutex<Receiver>`——仅 UI 线程访问（pop_render 时 drain）；
//! - `Mutex<VideoJitterBuffer>`——UI 线程写、音频线程 `sync_audio_clock`
//!   写（故 Mutex 保护，锁内只做轻量插入）。
//!
//! 通道用原子深度计数器近似有界（容量 4，满则丢新帧）：UI 最小化长时间
//! 不 pop 时防止无限积压（丢的帧由抖动缓冲追时吸收，解码线程永不阻塞）。
//!
//! # 边界
//!
//! 解码层**不依赖 egui**：本模块只做缓冲与时间轴管理，UI 层消费
//! [`DecodedFrame`] 自行上传 `egui::ColorImage`/`TextureHandle`。

use crate::decoder::DecodedFrame;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ════════════════════════════════════════════════════════════════
// VideoJitterBuffer（P2D §T4.1）
// ════════════════════════════════════════════════════════════════

/// 视频抖动缓冲：抗网络抖动 + PTS 排序 + 丢帧追时。
///
/// 深度 1~2 帧（16~33ms），比音频浅（视频对延迟更敏感）。
/// 按 PTS 升序输出；乱序帧插入；超时未到的间隙触发丢帧追时。
pub struct VideoJitterBuffer {
    /// 待输出帧队列（按 pts 升序）
    pending: VecDeque<DecodedFrame>,
    /// 最大缓冲深度（帧数，默认 2）
    max_depth: usize,
    /// 单帧时长（毫秒，默认 16 = 60fps）
    frame_ms: u64,
    /// 音频主时钟：当前音频播放 PTS（lip-sync 对齐用，0 = 未启用）
    audio_clock_pts: u64,
    /// 上次渲染的 PTS
    last_rendered_pts: Option<u64>,
    /// 上次渲染时刻（检测超时冻结）
    last_render_time: Instant,
    /// 统计：丢帧数（追时）
    frames_dropped: u64,
}

impl VideoJitterBuffer {
    pub fn new(max_depth: usize, frame_ms: u64) -> Self {
        Self {
            pending: VecDeque::new(),
            max_depth,
            frame_ms,
            audio_clock_pts: 0,
            last_rendered_pts: None,
            last_render_time: Instant::now(),
            frames_dropped: 0,
        }
    }

    /// 插入一帧（按 PTS 升序）。
    ///
    /// - 过期帧（`pts <= last_rendered_pts`）直接丢弃；
    /// - PTS 跳变（IDR 恢复后，差距 > 5×frame_ms）→ 清空缓冲重置
    ///   （避免按旧轴大量误丢新帧）；
    /// - 缓冲溢出 → 丢最旧帧（避免延迟累积）。
    pub fn push(&mut self, frame: DecodedFrame) {
        if let Some(last) = self.last_rendered_pts {
            if frame.pts <= last {
                self.frames_dropped += 1;
                return; // 过期帧
            }
            // PTS 跳变（IDR 恢复 / 编码侧重置）：清空重排，避免误判过期。
            if frame.pts > last.saturating_add(self.frame_ms * 5) {
                self.clear();
            }
        }
        let pos = self
            .pending
            .iter()
            .position(|f| f.pts > frame.pts)
            .unwrap_or(self.pending.len());
        self.pending.insert(pos, frame);

        // 缓冲溢出：丢最旧帧（避免延迟累积）
        while self.pending.len() > self.max_depth {
            self.pending.pop_front();
            self.frames_dropped += 1;
        }
    }

    /// 取下一帧渲染。
    ///
    /// 返回策略：
    /// - 缓冲未达 1 帧 → None（等待）
    /// - 无音频时钟（audio_clock_pts=0）→ 直接弹出队首（视频自走，按 PTS 顺序）
    /// - 队首帧 PTS <= audio_clock_pts + 容限 → 弹出所有 ≤ 容限的帧，只渲染
    ///   最新一帧（追时：丢中间帧）
    /// - 队首帧 PTS > audio_clock_pts + 容限 → None（等待音频时钟推进）
    pub fn pop_render(&mut self) -> Option<DecodedFrame> {
        if self.pending.is_empty() {
            return None;
        }

        // 无音频时钟 → 直接渲染（视频自走，按 PTS 顺序）
        if self.audio_clock_pts == 0 {
            let f = self.pending.pop_front()?;
            self.last_rendered_pts = Some(f.pts);
            self.last_render_time = Instant::now();
            return Some(f);
        }

        // lip-sync：视频对齐音频时钟
        let tolerance = self.frame_ms * 2; // 容限 2 帧（~33ms @60fps）
        let front_pts = self.pending.front()?.pts;

        if front_pts <= self.audio_clock_pts + tolerance {
            // 弹出所有早于音频时钟的帧（只保留最新一帧渲染，丢中间追时）
            let mut latest = None;
            while let Some(front) = self.pending.front() {
                if front.pts <= self.audio_clock_pts + tolerance {
                    let f = self.pending.pop_front().unwrap();
                    if latest.is_some() {
                        self.frames_dropped += 1; // 中间帧丢弃追时
                    }
                    latest = Some(f);
                } else {
                    break;
                }
            }
            if let Some(f) = latest {
                self.last_rendered_pts = Some(f.pts);
                self.last_render_time = Instant::now();
                return Some(f);
            }
        }

        // 队首 PTS 超前音频时钟 → 等待
        None
    }

    /// 更新音频主时钟（音频播放线程回调）。
    pub fn sync_audio_clock(&mut self, audio_pts: u64) {
        self.audio_clock_pts = audio_pts;
    }

    /// 检测冻结：超过 N 毫秒未渲染（且缓冲非空——说明时间轴被卡住）。
    pub fn is_frozen(&self, timeout: Duration) -> bool {
        self.last_render_time.elapsed() > timeout && !self.pending.is_empty()
    }

    /// 清空缓冲（连接重置 / IDR 恢复时）。
    pub fn clear(&mut self) {
        self.pending.clear();
        self.last_rendered_pts = None;
    }

    /// 统计：丢帧数（过期 + 溢出 + 追时）。
    pub fn frames_dropped(&self) -> u64 {
        self.frames_dropped
    }

    /// 当前缓冲深度（帧数）。
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

// ════════════════════════════════════════════════════════════════
// RenderBridge（P2D §T4.2）
// ════════════════════════════════════════════════════════════════

/// 通道积压上限（近似有界队列）：UI 最小化时防无限增长。
const CHANNEL_CAP: usize = 4;

/// 渲染桥：连接解码线程与 UI 线程。
///
/// - 解码线程：调用 [`push_decoded`](Self::push_decoded) 投递 `DecodedFrame`
/// - UI 线程：调用 [`pop_render`](Self::pop_render) 取最新帧（经抖动缓冲）
/// - 音频线程：调用 [`sync_audio_clock`](Self::sync_audio_clock) 对齐 lip-sync
///
/// `Clone` 为轻量 Arc 复制（解码线程/UI 线程各持一份）。
///
/// > 注：P2D §T4.2 初稿的 `new() -> (Self, Receiver)` 签名因 `mpsc::Receiver`
/// > 非 Sync 不可跨线程共享，被 §T4.3「最终线程模型」取代：Receiver 由
/// > 桥内部持有（`Mutex` 包装供 UI 线程独占），`new` 直接返回桥自身。
pub struct RenderBridge {
    inner: Arc<BridgeInner>,
}

struct BridgeInner {
    /// 解码 → UI 的帧通道
    tx: mpsc::Sender<DecodedFrame>,
    /// UI 侧接收端（pop_render 时 drain，仅 UI 线程访问）
    rx: Mutex<mpsc::Receiver<DecodedFrame>>,
    /// UI 侧抖动缓冲（UI 线程写；音频线程仅 sync_audio_clock）
    jitter: Mutex<VideoJitterBuffer>,
    /// 通道积压深度（近似有界队列）
    depth: AtomicUsize,
}

impl RenderBridge {
    /// 创建渲染桥。
    ///
    /// - `jitter_depth`：抖动缓冲深度（帧数，视频建议 2）
    /// - `frame_ms`：单帧时长（毫秒，60fps → 16）
    pub fn new(jitter_depth: usize, frame_ms: u64) -> Self {
        let (tx, rx) = mpsc::channel::<DecodedFrame>();
        Self {
            inner: Arc::new(BridgeInner {
                tx,
                rx: Mutex::new(rx),
                jitter: Mutex::new(VideoJitterBuffer::new(jitter_depth, frame_ms)),
                depth: AtomicUsize::new(0),
            }),
        }
    }

    /// 解码线程：投递一帧到通道。
    ///
    /// 通道积压达上限（UI 未及时消费）→ 丢新帧（抖动缓冲会追时），
    /// 解码线程永不阻塞。
    pub fn push_decoded(&self, frame: DecodedFrame) {
        if self.inner.depth.load(Ordering::Relaxed) >= CHANNEL_CAP {
            return; // 积压超限：丢帧（jitter 追时吸收）
        }
        if self.inner.tx.send(frame).is_ok() {
            self.inner.depth.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// UI 线程：drain 通道到抖动缓冲，返回下一帧渲染（无帧 → None）。
    ///
    /// 锁序：先 rx（drain，作用域结束即释放）后 jitter——与
    /// [`sync_audio_clock`](Self::sync_audio_clock)（仅 jitter）无死锁。
    pub fn pop_render(&self) -> Option<DecodedFrame> {
        {
            let rx = self.inner.rx.lock().unwrap();
            loop {
                match rx.try_recv() {
                    Ok(f) => {
                        self.inner.depth.fetch_sub(1, Ordering::Relaxed);
                        self.inner.jitter.lock().unwrap().push(f);
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => break, // 解码线程退出
                }
            }
        }
        self.inner.jitter.lock().unwrap().pop_render()
    }

    /// UI 线程：更新音频主时钟（lip-sync 对齐）。
    pub fn sync_audio_clock(&self, audio_pts: u64) {
        self.inner
            .jitter
            .lock()
            .unwrap()
            .sync_audio_clock(audio_pts);
    }

    /// 检测画面冻结（解码/网络停顿，缓冲有帧但时间轴卡住）。
    pub fn is_frozen(&self, timeout: Duration) -> bool {
        self.inner.jitter.lock().unwrap().is_frozen(timeout)
    }

    /// 清空缓冲（连接重置 / IDR 恢复时）。
    pub fn clear(&self) {
        {
            let rx = self.inner.rx.lock().unwrap();
            while rx.try_recv().is_ok() {
                self.inner.depth.fetch_sub(1, Ordering::Relaxed);
            }
        }
        self.inner.jitter.lock().unwrap().clear();
    }
}

impl Clone for RenderBridge {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

// ════════════════════════════════════════════════════════════════
// Tests（P2D §T4.1 / §T4.2 测试表）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 2×2 RGBA 测试帧（16B 像素）。
    fn frame(pts: u64) -> DecodedFrame {
        DecodedFrame {
            pts,
            width: 2,
            height: 2,
            rgba: vec![0u8; 16],
            is_key: false,
        }
    }

    // ── VideoJitterBuffer ───────────────────────────────────────

    /// 顺序到达 → 顺序渲染。
    #[test]
    fn test_video_jitter_in_order() {
        let mut j = VideoJitterBuffer::new(4, 16);
        j.push(frame(0));
        j.push(frame(16));
        j.push(frame(33));
        assert_eq!(j.pop_render().unwrap().pts, 0);
        assert_eq!(j.pop_render().unwrap().pts, 16);
        assert_eq!(j.pop_render().unwrap().pts, 33);
        assert!(j.pop_render().is_none());
        assert_eq!(j.frames_dropped(), 0);
    }

    /// 乱序 → push 排序后顺序渲染。
    #[test]
    fn test_video_jitter_out_of_order() {
        let mut j = VideoJitterBuffer::new(4, 16);
        j.push(frame(33));
        j.push(frame(0));
        j.push(frame(16));
        assert_eq!(j.pop_render().unwrap().pts, 0);
        assert_eq!(j.pop_render().unwrap().pts, 16);
        assert_eq!(j.pop_render().unwrap().pts, 33);
    }

    /// 过期帧（pts <= last_rendered_pts）→ 丢弃。
    #[test]
    fn test_video_jitter_stale_dropped() {
        let mut j = VideoJitterBuffer::new(4, 16);
        j.push(frame(0));
        assert_eq!(j.pop_render().unwrap().pts, 0);
        // 渲染过 pts=0 后再来 pts=0 → 过期丢弃。
        j.push(frame(0));
        j.push(frame(16));
        assert_eq!(j.pop_render().unwrap().pts, 16);
        assert!(j.pop_render().is_none());
        assert_eq!(j.frames_dropped(), 1);
    }

    /// 超 max_depth → 丢最旧。
    #[test]
    fn test_video_jitter_overflow_drop_oldest() {
        let mut j = VideoJitterBuffer::new(2, 16);
        j.push(frame(0));
        j.push(frame(16));
        j.push(frame(33));
        j.push(frame(50));
        assert_eq!(j.pending_len(), 2); // 0/16 被挤出
        assert_eq!(j.pop_render().unwrap().pts, 33);
        assert_eq!(j.pop_render().unwrap().pts, 50);
        assert!(j.pop_render().is_none());
        assert_eq!(j.frames_dropped(), 2);
    }

    /// 音频时钟推进 → 弹出多帧追时（只渲染最新 ≤ 容限 的帧，中间丢弃）。
    #[test]
    fn test_video_jitter_lip_sync_chase() {
        let mut j = VideoJitterBuffer::new(4, 16); // frame_ms=16 → 容限 32
        j.push(frame(150));
        j.push(frame(166));
        j.push(frame(183));
        j.push(frame(200));
        j.sync_audio_clock(151);
        // 阈值 = 151 + 2×16 = 183 → 150/166/183 全弹，只渲染最新 183；
        // 150/166 追时丢弃（文档示例：音频时钟 150 处 183 恰在容限边界外）。
        let f = j.pop_render().unwrap();
        assert_eq!(f.pts, 183);
        assert_eq!(j.frames_dropped(), 2);
        // 200 超前时钟 → 等待。
        assert!(j.pop_render().is_none());
        // 音频推进 → 放行。
        j.sync_audio_clock(200);
        assert_eq!(j.pop_render().unwrap().pts, 200);
    }

    /// PTS 跳变（> 5×frame_ms，IDR 恢复）→ 清空重置，不按旧轴误丢。
    #[test]
    fn test_video_jitter_pts_jump_clear() {
        let mut j = VideoJitterBuffer::new(4, 16); // 5×16 = 80
        j.push(frame(100));
        assert_eq!(j.pop_render().unwrap().pts, 100);
        // 跳变 900ms >> 80ms → 重置后新帧正常入队/渲染（不被判过期）。
        j.push(frame(1000));
        assert_eq!(j.pop_render().unwrap().pts, 1000);
        assert_eq!(j.frames_dropped(), 0);
    }

    /// 长时间未渲染 + 缓冲非空 → is_frozen=true；时间轴恢复后解除。
    #[test]
    fn test_video_jitter_frozen_detect() {
        let mut j = VideoJitterBuffer::new(4, 16);
        j.sync_audio_clock(1); // 启用音频时钟（非 0 哨兵）
        j.push(frame(1000)); // 超前时钟 → pop 返回 None，缓冲滞留
        assert!(j.pop_render().is_none());
        std::thread::sleep(Duration::from_millis(5));
        assert!(j.is_frozen(Duration::from_millis(1)));
        // 音频追上 → 放行渲染 → 冻结解除。
        j.sync_audio_clock(2000);
        assert_eq!(j.pop_render().unwrap().pts, 1000);
        assert!(!j.is_frozen(Duration::from_millis(1)));
    }

    // ── RenderBridge ────────────────────────────────────────────

    /// push 一帧 → pop 返回该帧。
    #[test]
    fn test_render_bridge_push_pop() {
        let b = RenderBridge::new(4, 16);
        b.push_decoded(frame(42));
        let f = b.pop_render().unwrap();
        assert_eq!(f.pts, 42);
        assert!(b.pop_render().is_none());
    }

    /// 多帧 push → pop 顺序一致（经通道 + 抖动缓冲）。
    #[test]
    fn test_render_bridge_order_preserved() {
        let b = RenderBridge::new(4, 16);
        b.push_decoded(frame(33));
        b.push_decoded(frame(0));
        b.push_decoded(frame(16));
        assert_eq!(b.pop_render().unwrap().pts, 0);
        assert_eq!(b.pop_render().unwrap().pts, 16);
        assert_eq!(b.pop_render().unwrap().pts, 33);
        assert!(b.pop_render().is_none());
    }

    /// sync_audio_clock 后 pop_render 受时钟影响（超前 → 等待）。
    #[test]
    fn test_render_bridge_audio_sync() {
        let b = RenderBridge::new(4, 16);
        b.sync_audio_clock(10); // 容限 32 → 1000 超前
        b.push_decoded(frame(1000));
        assert!(b.pop_render().is_none());
        b.sync_audio_clock(2000);
        assert_eq!(b.pop_render().unwrap().pts, 1000);
    }

    /// 通道积压达上限 → 丢新帧（近似有界队列，防 UI 最小化无限积压）。
    #[test]
    fn test_render_bridge_channel_cap_drop() {
        let b = RenderBridge::new(16, 16); // jitter 深度大，排除其溢出干扰
        for pts in [0u64, 16, 33, 50, 66] {
            b.push_decoded(frame(pts));
        }
        // 5 帧中第 5 帧被通道容量丢弃（CHANNEL_CAP = 4）。
        let mut popped = Vec::new();
        while let Some(f) = b.pop_render() {
            popped.push(f.pts);
        }
        assert_eq!(popped, vec![0, 16, 33, 50]);
    }

    /// Clone 轻量 + 跨线程（Send + Sync）编译期保证（T4.3 线程拓扑前提）。
    #[test]
    fn test_render_bridge_clone_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RenderBridge>();

        let b = RenderBridge::new(2, 16);
        let c = b.clone();
        c.push_decoded(frame(1));
        assert_eq!(b.pop_render().unwrap().pts, 1);
    }
}
