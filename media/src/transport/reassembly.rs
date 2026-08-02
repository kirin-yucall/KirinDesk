//! 帧重组缓冲区。
//!
//! DATAGRAM 分片可能乱序到达，此模块负责按 `frame_id` 重组，
//! 并在超时后清理未完成的帧。

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// 帧重组缓冲区。
pub struct FrameReassembly {
    /// frame_id → 重组缓冲区
    buffers: HashMap<u64, ReassemblyBuffer>,
    /// 已完成的 frame_id 队列（按完成顺序）
    completed: VecDeque<u64>,
    /// 最大待处理帧数
    max_pending: usize,
    /// 超时时间
    timeout: Duration,
}

struct ReassemblyBuffer {
    /// 总分片数
    total_packets: u16,
    /// 各分片数据（None = 未收到）
    packets: Vec<Option<Vec<u8>>>,
    /// 标志位
    flags: u16,
    /// 插入时间
    inserted_at: Instant,
}

impl FrameReassembly {
    /// 创建新的重组缓冲区。
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
            completed: VecDeque::new(),
            max_pending: 64,
            timeout: Duration::from_millis(200),
        }
    }

    /// 设置超时时间。
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 设置最大待处理帧数。
    pub fn with_max_pending(mut self, max: usize) -> Self {
        self.max_pending = max;
        self
    }

    /// 添加一个分片。若帧收齐则返回 `(frame_id, flags, data)`。
    pub fn add_packet(
        &mut self,
        frame_id: u64,
        packet_idx: u16,
        total_packets: u16,
        flags: u16,
        payload: Vec<u8>,
    ) -> Option<(u64, u16, Vec<u8>)> {
        // 检查是否已有缓冲区
        if !self.buffers.contains_key(&frame_id) {
            // 限制待处理帧数
            if self.buffers.len() >= self.max_pending {
                // 溢出时清理最老的
                self.evict_oldest();
            }

            self.buffers.insert(
                frame_id,
                ReassemblyBuffer {
                    total_packets,
                    packets: vec![None; total_packets as usize],
                    flags,
                    inserted_at: Instant::now(),
                },
            );
        }

        let buf = self.buffers.get_mut(&frame_id).unwrap();

        // 更新标志（保留所有标志位的 OR）
        buf.flags |= flags;

        // 存储分片
        if (packet_idx as usize) < buf.packets.len() {
            buf.packets[packet_idx as usize] = Some(payload);
        }

        // 检查是否收齐
        if buf.packets.iter().all(|p| p.is_some()) {
            // 组装
            let mut data = Vec::new();
            for p in buf.packets.iter() {
                if let Some(chunk) = p {
                    data.extend_from_slice(chunk);
                }
            }
            let flags = buf.flags;
            self.buffers.remove(&frame_id);
            self.completed.push_back(frame_id);
            return Some((frame_id, flags, data));
        }

        None
    }

    /// 清理超时未完成的帧，返回被清理的 frame_id 列表。
    pub fn cleanup(&mut self) -> Vec<u64> {
        let now = Instant::now();
        let timeout = self.timeout;
        let mut expired = Vec::new();

        self.buffers.retain(|&frame_id, buf| {
            if now.duration_since(buf.inserted_at) >= timeout {
                expired.push(frame_id);
                false
            } else {
                true
            }
        });

        // 清理 completed 中过期的引用
        while let Some(&id) = self.completed.front() {
            if expired.contains(&id) || !self.buffers.contains_key(&id) {
                self.completed.pop_front();
            } else {
                break;
            }
        }

        expired
    }

    /// 清空所有缓冲（连接重置时）。
    pub fn clear(&mut self) {
        self.buffers.clear();
        self.completed.clear();
    }

    /// 当前待处理的帧数。
    pub fn pending_count(&self) -> usize {
        self.buffers.len()
    }

    /// 检查某帧是否已完成（在 completed 队列中）。
    pub fn is_completed(&self, frame_id: u64) -> bool {
        // 已完成的帧不在 buffers 中
        !self.buffers.contains_key(&frame_id)
    }

    /// 移除最老的缓冲区。
    fn evict_oldest(&mut self) {
        let oldest = self
            .buffers
            .iter()
            .min_by_key(|(_, buf)| buf.inserted_at)
            .map(|(id, _)| *id);

        if let Some(id) = oldest {
            self.buffers.remove(&id);
        }
    }
}

impl Default for FrameReassembly {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reassembly_in_order() {
        let mut ra = FrameReassembly::new();

        // Single packet frame
        let result = ra.add_packet(1, 0, 1, 0x02, vec![0xAB, 0xCD]);
        assert_eq!(result, Some((1, 0x02, vec![0xAB, 0xCD])));
    }

    #[test]
    fn test_reassembly_multi_packet() {
        let mut ra = FrameReassembly::new();

        // First packet
        let result = ra.add_packet(1, 1, 3, 0x00, vec![0x01, 0x02]);
        assert!(result.is_none());

        // Second packet (out of order)
        let result = ra.add_packet(1, 0, 3, 0x00, vec![0xAA, 0xBB]);
        assert!(result.is_none());

        // Last packet
        let result = ra.add_packet(1, 2, 3, 0x02, vec![0xCC]);
        assert_eq!(result, Some((1, 0x02, vec![0xAA, 0xBB, 0x01, 0x02, 0xCC])));
    }

    #[test]
    fn test_reassembly_out_of_order() {
        let mut ra = FrameReassembly::new();

        // Last packet arrives first
        let result = ra.add_packet(5, 2, 3, 0x02, vec![0x99]);
        assert!(result.is_none());

        // Middle packet
        let result = ra.add_packet(5, 1, 3, 0x00, vec![0x88]);
        assert!(result.is_none());

        // First packet — now complete
        let result = ra.add_packet(5, 0, 3, 0x00, vec![0x77]);
        assert_eq!(result, Some((5, 0x02, vec![0x77, 0x88, 0x99])));
    }

    #[test]
    fn test_reassembly_timeout() {
        let mut ra =
            FrameReassembly::with_timeout(FrameReassembly::new(), Duration::from_millis(1));

        // Add incomplete frame
        let result = ra.add_packet(10, 0, 2, 0x00, vec![0x11]);
        assert!(result.is_none());

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        let expired = ra.cleanup();
        assert_eq!(expired, vec![10]);
        assert_eq!(ra.pending_count(), 0);
    }

    #[test]
    fn test_reassembly_clear() {
        let mut ra = FrameReassembly::new();

        // Multi-packet: frame 1 is partial
        ra.add_packet(1, 0, 2, 0x00, vec![0x11]);
        // Single-packet: frame 2 is complete -> removed from buffers
        ra.add_packet(2, 0, 1, 0x00, vec![0x22]);

        // Only frame 1 is pending (frame 2 auto-completed)
        assert_eq!(ra.pending_count(), 1);

        ra.clear();
        assert_eq!(ra.pending_count(), 0);
    }

    #[test]
    fn test_reassembly_max_pending() {
        let mut ra = FrameReassembly::with_max_pending(FrameReassembly::new(), 2);

        // Both partial
        ra.add_packet(1, 0, 2, 0x00, vec![0x11]);
        ra.add_packet(2, 0, 2, 0x00, vec![0x22]);

        assert_eq!(ra.pending_count(), 2);

        // Third partial frame should evict oldest (frame 1)
        ra.add_packet(3, 0, 2, 0x00, vec![0x33]);

        assert_eq!(ra.pending_count(), 2);
        // Frame 1 should be gone
        assert!(!ra.buffers.contains_key(&1));
    }

    #[test]
    fn test_reassembly_multiple_frames() {
        let mut ra = FrameReassembly::new();

        // Frame 1: complete
        assert_eq!(
            ra.add_packet(1, 0, 1, 0x02, vec![0x11]),
            Some((1, 0x02, vec![0x11]))
        );
        // Frame 2: complete
        assert_eq!(
            ra.add_packet(2, 0, 1, 0x02, vec![0x22]),
            Some((2, 0x02, vec![0x22]))
        );
        // Frame 3: partial
        assert!(ra.add_packet(3, 0, 2, 0x00, vec![0x33]).is_none());
    }
}
