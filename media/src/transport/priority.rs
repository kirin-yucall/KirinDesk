//! DATAGRAM 发送优先级调度（P1F §T6.2）。
//!
//! 按优先级 [`Priority`] 出队三条独立队列：**键鼠(0) > 音频(1) > 视频(2)**。
//!
//! # 调度规则
//!
//! - [`PriorityQueue::pop_next`]：每次取非空中最高优先级的包；Input 永先、
//!   Audio 次之、Video 最后。
//! - **键鼠队列永不丢**（可靠流背压：不丢，只阻塞发送循环）；只有 Video 队列
//!   会在拥塞时被 [`PriorityQueue::drop_lowest`] 丢弃。
//! - 队列全空 → [`PriorityQueue::pop_next`] 返回 `None`，发送循环 sleep（不忙转）。
//!
//! # 设计动机
//!
//! 人耳对音频断续比视频卡顿更敏感，键鼠断续则直接影响操作；故拥塞时优先丢视频、
//! 保音频、键鼠不可丢。键鼠走可靠流，本队列只承载它的「优先级出队」语义
//! （拥塞时仍阻塞发送循环，不丢）。

use std::collections::VecDeque;

use crate::encoder::types::{EncodedPacket, PacketKind};

// ════════════════════════════════════════════════════════════════
// Priority
// ════════════════════════════════════════════════════════════════

/// DATAGRAM 发送优先级。数值越小优先级越高。
///
/// - [`Priority::Input`] = 0（键鼠，最高）
/// - [`Priority::Audio`] = 1（音频，中）
/// - [`Priority::Video`] = 2（视频，最低；拥塞先丢）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Priority {
    /// 键鼠（最高优先级，0）。
    Input = 0,
    /// 音频（中优先级，1）。
    Audio = 1,
    /// 视频（最低优先级，2）。
    Video = 2,
}

impl Priority {
    /// 按 [`PacketKind`] 映射到发送优先级。
    pub fn from_packet_kind(k: PacketKind) -> Self {
        match k {
            PacketKind::Video => Self::Video,
            PacketKind::Audio => Self::Audio,
            PacketKind::InputEcho => Self::Input,
            // M13-T003: 剪贴板文本——小载荷、低延迟敏感度，归入音频档
            // （中优先级，不受 max_len 拥塞丢弃）。
            PacketKind::Clipboard => Self::Audio,
            // M13-T006: 文件块——可靠流背压，归入音频档（不参与拥塞丢弃）。
            PacketKind::FileTransfer => Self::Audio,
            // M8-T018: 控制消息（显示器/隐私等，bincode ControlMessage）——
            // 低延迟敏感，与键鼠同权（最高优先级，可靠流不受拥塞丢弃）。
            PacketKind::Control => Self::Input,
        }
    }

    /// 队列索引（0/1/2，与枚举判别式一致）。
    fn index(self) -> usize {
        self as usize
    }
}

// ════════════════════════════════════════════════════════════════
// PriorityQueue
// ════════════════════════════════════════════════════════════════

/// DATAGRAM 发送队列：按优先级出队；拥塞时先丢视频。
///
/// 内部三条 [`VecDeque`]（Input/Audio/Video）；`max_len` 是单队列长度上限，
/// 仅对 Video 队列生效（拥塞丢包阈值）。键鼠/音频队列**不被丢弃**
/// （键鼠可靠流背压、音频保真）。
///
/// # 拥塞策略
///
/// - `push` 时若 Video 队列达到 `max_len`，自动 [`Self::drop_lowest`] 一次
///   （丢视频队首），保证新视频帧不挤掉键鼠/音频。
/// - 上层发送循环应在 `pop_next` 返回 `None`（队列空）时 sleep，避免忙转。
pub struct PriorityQueue {
    queues: [VecDeque<EncodedPacket>; 3],
    /// 单队列上限（拥塞丢包阈值）；0 表示不限。
    max_len: usize,
}

impl PriorityQueue {
    /// 创建：`max_len` 为单队列上限（推荐 32~64）。
    pub fn new(max_len: usize) -> Self {
        Self {
            queues: [
                const { VecDeque::new() },
                const { VecDeque::new() },
                const { VecDeque::new() },
            ],
            max_len,
        }
    }

    /// 默认上限（每队列 64 包）。
    pub fn with_default_capacity() -> Self {
        Self::new(64)
    }

    /// 设置单队列上限（运行期可调，自适应联动 P1G）。
    pub fn set_max_len(&mut self, max_len: usize) {
        self.max_len = max_len;
    }

    /// 入队：按 `pkt.kind` → 对应优先级队列。
    ///
    /// Video 队列达 `max_len` 时自动 [`Self::drop_lowest`]（丢视频队首）。
    /// Input/Audio 不受 `max_len` 限制（不丢）。
    pub fn push(&mut self, pkt: EncodedPacket) {
        let idx = Priority::from_packet_kind(pkt.kind).index();
        // 仅 Video 队列做拥塞丢弃。
        if idx == Priority::Video.index()
            && self.max_len > 0
            && self.queues[idx].len() >= self.max_len
        {
            self.queues[idx].pop_front();
        }
        self.queues[idx].push_back(pkt);
    }

    /// 出队下一个包：优先非空的高优先级队列。
    ///
    /// 顺序：Input → Audio → Video；全空返回 `None`。
    pub fn pop_next(&mut self) -> Option<EncodedPacket> {
        for q in &mut self.queues {
            if let Some(pkt) = q.pop_front() {
                return Some(pkt);
            }
        }
        None
    }

    /// 拥塞时丢视频队首，返回丢弃数（0 或 1）。
    ///
    /// 只动 Video 队列；键鼠/音频不动（保音频、不可丢键鼠）。
    /// 上层在检测到拥塞（如 DATAGRAM send 失败、队列膨胀）时调用。
    pub fn drop_lowest(&mut self) -> usize {
        let v_idx = Priority::Video.index();
        if self.queues[v_idx].pop_front().is_some() {
            1
        } else {
            0
        }
    }

    /// 当前总长度（三队列之和）。
    pub fn len(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
    }

    /// 是否全部为空。
    pub fn is_empty(&self) -> bool {
        self.queues.iter().all(|q| q.is_empty())
    }

    /// 指定优先级队列当前长度（诊断/自适应观测用）。
    pub fn len_of(&self, prio: Priority) -> usize {
        self.queues[prio.index()].len()
    }

    /// 清空所有队列（连接重置时）。
    pub fn clear(&mut self) {
        for q in &mut self.queues {
            q.clear();
        }
    }
}

impl Default for PriorityQueue {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

// ════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::types::{PacketKind, Timestamp};
    use std::time::Instant;

    fn pkt(kind: PacketKind, mark: u8) -> EncodedPacket {
        EncodedPacket {
            ts: Timestamp::new(Instant::now(), mark as u64),
            kind,
            data: vec![mark],
            is_key: false,
        }
    }

    #[test]
    fn test_priority_ordering() {
        // 数值越小优先级越高。
        assert!(Priority::Input < Priority::Audio);
        assert!(Priority::Audio < Priority::Video);
    }

    #[test]
    fn test_priority_from_packet_kind() {
        assert_eq!(
            Priority::from_packet_kind(PacketKind::InputEcho),
            Priority::Input
        );
        assert_eq!(
            Priority::from_packet_kind(PacketKind::Audio),
            Priority::Audio
        );
        assert_eq!(
            Priority::from_packet_kind(PacketKind::Video),
            Priority::Video
        );
    }

    #[test]
    fn test_priority_pop_order() {
        // 混入三队列 → 出队顺序 Input → Audio → Video。
        let mut q = PriorityQueue::with_default_capacity();
        q.push(pkt(PacketKind::Video, 1));
        q.push(pkt(PacketKind::Audio, 2));
        q.push(pkt(PacketKind::InputEcho, 3));
        q.push(pkt(PacketKind::Video, 4));
        q.push(pkt(PacketKind::Audio, 5));

        let order: Vec<u8> = std::iter::from_fn(|| q.pop_next())
            .map(|p| p.data[0])
            .collect();

        // 期望：Input(3) → Audio(2),(5) → Video(1),(4)
        assert_eq!(order, vec![3, 2, 5, 1, 4]);
    }

    #[test]
    fn test_drop_lowest_video() {
        // 拥塞 → 只丢视频，键鼠/音频不动。
        let mut q = PriorityQueue::with_default_capacity();
        q.push(pkt(PacketKind::InputEcho, 10));
        q.push(pkt(PacketKind::Audio, 20));
        q.push(pkt(PacketKind::Video, 30));
        q.push(pkt(PacketKind::Video, 31));

        let dropped = q.drop_lowest();
        assert_eq!(dropped, 1);
        // Video 队列少一个，其余不变。
        assert_eq!(q.len_of(Priority::Video), 1);
        assert_eq!(q.len_of(Priority::Input), 1);
        assert_eq!(q.len_of(Priority::Audio), 1);

        // 再次 drop_lowest 丢剩下一个视频。
        let dropped2 = q.drop_lowest();
        assert_eq!(dropped2, 1);
        assert_eq!(q.len_of(Priority::Video), 0);

        // 视频空后再 drop → 0，不影响其他。
        let dropped3 = q.drop_lowest();
        assert_eq!(dropped3, 0);
        assert_eq!(q.len_of(Priority::Input), 1);
        assert_eq!(q.len_of(Priority::Audio), 1);
    }

    #[test]
    fn test_queue_empty_none() {
        // 全空 → None。
        let mut q = PriorityQueue::with_default_capacity();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert!(q.pop_next().is_none());
    }

    #[test]
    fn test_input_backpressure() {
        // 键鼠队列不为空时 pop_next 总是先返回 Input。
        let mut q = PriorityQueue::with_default_capacity();
        // 即使视频/音频堆积，Input 永先出队。
        for _ in 0..5 {
            q.push(pkt(PacketKind::Video, 1));
            q.push(pkt(PacketKind::Audio, 2));
        }
        q.push(pkt(PacketKind::InputEcho, 99));
        q.push(pkt(PacketKind::InputEcho, 100));

        let first = q.pop_next().unwrap();
        assert_eq!(first.kind, PacketKind::InputEcho);
        let second = q.pop_next().unwrap();
        assert_eq!(second.kind, PacketKind::InputEcho);
        // Input 队列清空后才轮到音频。
        let third = q.pop_next().unwrap();
        assert_eq!(third.kind, PacketKind::Audio);
    }

    #[test]
    fn test_video_max_len_drops_oldest() {
        // Video 队列达 max_len → 新包挤掉队首（丢视频）。
        let mut q = PriorityQueue::new(2);
        q.push(pkt(PacketKind::Video, 1));
        q.push(pkt(PacketKind::Video, 2));
        assert_eq!(q.len_of(Priority::Video), 2);
        // 第三包 → 挤掉第一包。
        q.push(pkt(PacketKind::Video, 3));
        assert_eq!(q.len_of(Priority::Video), 2);

        // 队首应为 2（1 被丢）。
        let out: Vec<u8> = std::iter::from_fn(|| q.pop_next())
            .map(|p| p.data[0])
            .collect();
        assert_eq!(out, vec![2, 3]);
    }

    #[test]
    fn test_audio_input_never_dropped_by_max_len() {
        // Audio/Input 不受 max_len 限制（不丢）。
        let mut q = PriorityQueue::new(1);
        for m in 1..=5u8 {
            q.push(pkt(PacketKind::Audio, m));
            q.push(pkt(PacketKind::InputEcho, m));
        }
        // 5 个音频 + 5 个键鼠全部保留。
        assert_eq!(q.len_of(Priority::Audio), 5);
        assert_eq!(q.len_of(Priority::Input), 5);
        assert_eq!(q.len(), 10);
    }

    #[test]
    fn test_clear() {
        let mut q = PriorityQueue::with_default_capacity();
        q.push(pkt(PacketKind::Video, 1));
        q.push(pkt(PacketKind::Audio, 2));
        q.push(pkt(PacketKind::InputEcho, 3));
        assert!(!q.is_empty());

        q.clear();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn test_max_len_zero_unlimited() {
        // max_len = 0 表示不限（视频也不丢）。
        let mut q = PriorityQueue::new(0);
        for _ in 0..100 {
            q.push(pkt(PacketKind::Video, 1));
        }
        assert_eq!(q.len_of(Priority::Video), 100);
    }
}
