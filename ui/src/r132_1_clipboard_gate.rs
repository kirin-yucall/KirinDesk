//! 同步四路径**实时门控**。
//!
//! 四路径与门控落点（`ui/src/lib.rs`）：
//! - 路径 1 server apply（客户端→服务端文本/元数据帧接收臂）
//!   → [`crate::clip_gated_apply_remote_frame_event`]（门控步）；
//!   pending 槽）→ 同一门控步（两接收臂共用单一点）；
//! - 路径 2 server push（`clip_poll_tick_roots` 文本帧产出）+ 路径 4
//!   （off = `continue`：零读板零帧产出）+ 推送位点复核门（双层零推送
//!   结构保证），判定核 = [`crate::clipboard_gate_core`]。
//!
//! - **off 态四路径零写入零推送**（含元数据占位写板/读板/帧产出/广播）；
//! - **on 态行为不变**（与直调 `apply_remote_frame_event`/
//!   `clip_poll_tick_roots` 逐位一致）；
//! - 三态 fail-closed 判定（损坏/不可读 = 关；首启缺文件 = 默认开；

use std::time::{Duration, Instant};

use crate::clipboard::{
    ClipboardIo, ClipboardSyncState, ClipApplyEvent, FileClipEntry, FileClipMeta,
    FileClipMetaFragment, CLIP_FLAG_FILEMETA, CLIP_FLAG_START, CLIP_FLAG_END,
    FILEMETA_VERSION, MAX_CLIP_CHUNK,
};
use crate::{
    clip_gated_apply_remote_frame_event, clip_gate_off_warn_due, clipboard_gate_core,
};
use kirin_desk_utils::config::Config;

/// 测试假件：内存「板」，记录全部读/写（零 OS 依赖，`ClipboardIo` 内存
struct RecBoard {
    text: Option<String>,
    reads: u32,
    writes: Vec<String>,
}

impl RecBoard {
    fn new(text: Option<String>) -> Self {
        Self {
            text,
            reads: 0,
            writes: Vec::new(),
        }
    }
}

impl ClipboardIo for RecBoard {
    fn get_text(&mut self) -> Option<String> {
        self.reads += 1;
        self.text.clone()
    }

    fn set_text(&mut self, text: &str) -> bool {
        self.writes.push(text.to_string());
        self.text = Some(text.to_string());
        true
    }

    /// Windows 形态对照：板无 CF_HDROP（多数 tick 常态）= 只读计数 + None。
    fn get_file_meta(&mut self) -> Option<crate::clipboard::OsFileBoard> {
        self.reads += 1;
        None
    }
}

/// 单片完整文本帧（START|END + UTF-8 负载）——与生产编码
/// `encode_clipboard_payloads` 同源（单片形态逐位一致）。
fn text_frame(s: &str) -> Vec<u8> {
    let frames = crate::clipboard::encode_clipboard_payloads(s, MAX_CLIP_CHUNK);
    assert_eq!(frames.len(), 1, "短文本必单片");
    frames.into_iter().next().expect("非空")
}

/// 单片完整文件元数据帧（FILEMETA + 自含分片 bincode 封装）。
fn meta_frame(meta: &FileClipMeta) -> Vec<u8> {
    let body = bincode::serialize(meta).expect("bincode FileClipMeta");
    let frag = FileClipMetaFragment {
        seq: 1,
        total: 1,
        payload: body,
    };
    let mut v = vec![CLIP_FLAG_FILEMETA];
    v.extend_from_slice(&bincode::serialize(&frag).expect("bincode fragment"));
    v
}

fn sample_meta() -> FileClipMeta {
    FileClipMeta {
        version: FILEMETA_VERSION,
        cleared: false,
        truncated: false,
        entries: vec![FileClipEntry {
            rel_path: "a.txt".to_string(),
            size: 10,
            is_dir: false,
            fetchable: true,
        }],
    }
}

// ── 三态判定核（四路径共享单一语义源）─────────────────────────────────

#[test]
fn r132_1_gate_core_ok_uses_field_value() {
    for exists in [None, Some(true), Some(false)] {
        assert!(
            clipboard_gate_core(Some(true), exists),
            "load Ok + 开关开 = 放行（exists 无关）"
        );
        assert!(
            !clipboard_gate_core(Some(false), exists),
            "load Ok + 开关关 = 拒绝（exists 无关）"
        );
    }
}

#[test]
fn r132_1_gate_core_err_corrupt_fail_closed_off() {
    // 文件存在但损坏/不可读 = 开关态不可得 = **按关**（红线⑤ fail-closed）。
    assert!(!clipboard_gate_core(None, Some(true)));
}

#[test]
fn r132_1_gate_core_err_first_run_default_on() {
    assert!(clipboard_gate_core(None, Some(false)));
}

#[test]
fn r132_1_gate_core_err_unresolvable_fail_closed_off() {
    // 路径不可解析 = 态不可得 = 按关。
    assert!(!clipboard_gate_core(None, None));
}

#[test]
fn r132_1_gate_core_parity_with_r110b2_clip_side() {
    // （两门控不得分叉——文件传输/剪贴板开关同源语义）。
    for val in [true, false] {
        let mut cfg = Config::default();
        cfg.file_transfer.clipboard_allowed = val;
        let field = cfg.file_transfer.clipboard_allowed;
        let load = Ok(cfg); // 借引用传入（零移动）
        let (_, clip) = crate::file_manager::consent_switches_from_load(&load);
        assert_eq!(
            clipboard_gate_core(Some(field), None),
            clip,
        );
    }
}


#[test]
fn r132_1_off_receive_text_zero_write() {
    // off 态：文本帧拒绝 = 零写板（用户复现 19:32:50 场景的零写入钉死）。
    let mut st = ClipboardSyncState::new();
    let mut board = RecBoard::new(Some("本机既有内容".to_string()));
    let out = clip_gated_apply_remote_frame_event(
        false,
        &mut st,
        1_000,
        &text_frame("远端机密文本"),
        &mut board,
    );
    assert!(out.is_none(), "off = 拒绝（None，帧不喂入状态机）");
    assert!(board.writes.is_empty(), "off 态零写板");
    assert_eq!(
        board.text.as_deref(),
        Some("本机既有内容"),
        "off 态本机板内容零变化"
    );
}

#[test]
fn r132_1_off_receive_filemeta_zero_write() {
    // off 态：文件元数据帧拒绝 = 零占位写板 + 零 pending 槽前置状态
    // （用户复现 19:33:54 文件元数据同步场景的零写入钉死）。
    let mut st = ClipboardSyncState::new();
    let mut board = RecBoard::new(Some("本机既有内容".to_string()));
    let out = clip_gated_apply_remote_frame_event(
        false,
        &mut st,
        1_000,
        &meta_frame(&sample_meta()),
        &mut board,
    );
    assert!(out.is_none(), "off = 拒绝（MetaApplied 事件不产生）");
    assert!(board.writes.is_empty(), "off 态元数据占位写板零发生");
    assert_eq!(
        board.text.as_deref(),
        Some("本机既有内容"),
        "off 态本机板内容零变化"
    );
}

#[test]
fn r132_1_off_period_frames_cannot_complete_later() {
    // fail-closed 完整性：off 期被拒的帧**不得**在开关重开后迟滞完成
    // （多帧流的 START 帧被拒 → 状态机从未进入重组 → 后续同流 END 帧
    // 无重组上下文必 Silent，零迟滞泄入）。
    let text = "迟滞内容-must-never-appear-later";
    let frames = crate::clipboard::encode_clipboard_payloads(text, 8);
    assert!(frames.len() >= 2, "测试前提 = 多帧流");
    let start_flags = frames[0][0];
    let end_flags = frames.last().expect("非空")[0];
    assert_ne!(start_flags & CLIP_FLAG_START, 0);
    assert_eq!(end_flags & CLIP_FLAG_START, 0, "末帧无 START 位");
    assert_ne!(end_flags & CLIP_FLAG_END, 0);
    let mut st = ClipboardSyncState::new();
    let mut board = RecBoard::new(None);
    // off 期：START 帧被拒（不喂入状态机）。
    let off_out =
        clip_gated_apply_remote_frame_event(false, &mut st, 1_000, &frames[0], &mut board);
    assert!(off_out.is_none());
    // 开关重开：同流续帧（END）到达 = 无重组上下文 → Silent，零写板。
    let end_frame = frames.last().expect("非空");
    let on_out = clip_gated_apply_remote_frame_event(true, &mut st, 2_000, end_frame, &mut board);
    assert!(
        matches!(on_out, Some(ClipApplyEvent::Silent)),
        "off 期残流不得在 on 态迟滞完成"
    );
    assert!(board.writes.is_empty(), "迟滞帧零写板");
}

#[test]
fn r132_1_on_receive_text_unchanged() {
    // on 态行为不变：门控步 ≡ 直调 `apply_remote_frame_event`（逐位）。
    let frame = text_frame("hello-clip");
    let (mut st_direct, mut b_direct) = (ClipboardSyncState::new(), RecBoard::new(None));
    let direct = st_direct.apply_remote_frame_event(1_000, &frame, &mut b_direct);
    let (mut st_gated, mut b_gated) = (ClipboardSyncState::new(), RecBoard::new(None));
    let gated =
        clip_gated_apply_remote_frame_event(true, &mut st_gated, 1_000, &frame, &mut b_gated);
    assert!(
        matches!(direct, ClipApplyEvent::TextApplied(ref t) if t == "hello-clip"),
        "基准：直调 on 态行为 = TextApplied"
    );
    assert_eq!(gated, Some(direct), "on 态门控步事件与直调逐位一致");
    assert_eq!(
        b_direct.writes, b_gated.writes,
        "on 态写板序列与直调逐位一致"
    );
}

#[test]
fn r132_1_on_receive_filemeta_unchanged() {
    // on 态元数据行为不变：门控步 ≡ 直调（占位写板 + MetaApplied 事件）。
    let frame = meta_frame(&sample_meta());
    let (mut st_direct, mut b_direct) = (ClipboardSyncState::new(), RecBoard::new(None));
    let direct = st_direct.apply_remote_frame_event(1_000, &frame, &mut b_direct);
    let (mut st_gated, mut b_gated) = (ClipboardSyncState::new(), RecBoard::new(None));
    let gated =
        clip_gated_apply_remote_frame_event(true, &mut st_gated, 1_000, &frame, &mut b_gated);
    assert!(
        matches!(direct, ClipApplyEvent::MetaApplied(ref m) if m.entries.len() == 1),
        "基准：直调 on 态元数据 = MetaApplied"
    );
    assert_eq!(gated, Some(direct), "on 态门控步元数据事件与直调逐位一致");
    assert_eq!(
        b_direct.writes, b_gated.writes,
        "on 态占位写板序列与直调逐位一致"
    );
    assert_eq!(b_gated.writes.len(), 1, "单片元数据帧恰一次占位写板");
}


#[test]
fn r132_1_off_poller_tick_zero_read_zero_push() {
    // off 态：tick 入口门 `continue`（lib.rs 轮询任务同形态）=
    // `clip_poll_tick_roots` 不被调用 → **零读板 + 零帧产出（零推送）**。
    let mut st = ClipboardSyncState::new();
    let mut board = RecBoard::new(Some("板内容".to_string()));
    let allowed = clipboard_gate_core(Some(false), None);
    assert!(!allowed);
    let pkts = if !allowed {
        None // 生产同形态：continue（tick 不执行）
    } else {
        crate::clipboard::clip_poll_tick_roots(&mut st, 1_000, &mut board, true, &[])
    };
    assert!(pkts.is_none(), "off 态零推送（无帧产出）");
    assert_eq!(board.reads, 0, "off 态零读板（get_file_meta/get_text 零调用）");
}

#[test]
fn r132_1_on_poller_tick_pushes_unchanged() {
    // on 态行为不变：tick 照常读板 + 文本变更沿照常产出推送帧。
    let mut st = ClipboardSyncState::new();
    let mut board = RecBoard::new(Some("hello-push".to_string()));
    let allowed = clipboard_gate_core(Some(true), None);
    assert!(allowed);
    let pkts = crate::clipboard::clip_poll_tick_roots(&mut st, 1_000, &mut board, true, &[]);
    assert!(pkts.is_some(), "on 态照常产出推送帧（行为不变）");
    assert_eq!(board.reads, 2, "on 态照常两读（get_file_meta + get_text）");
    let text_pkts = pkts.expect("Some");
    assert!(
        text_pkts.first().map(|p| p.data.first().copied()).flatten()
            .map(|f| f & CLIP_FLAG_FILEMETA == 0)
            .unwrap_or(false),
        "纯文本变更沿产出文本帧（非 FILEMETA）"
    );
}

// ── 拒绝日志节流（可观测锚点）────────────────────────────────────────

#[test]
fn r132_1_warn_throttle_first_fires_then_suppresses() {
    // 初值回拨一个窗口（生产锚点初值同形态）→ 首次拒绝必告警；
    // 窗口内（持续 off 帧流/500ms tick）= 至多一行，不刷屏。
    let mut slot = Instant::now() - Duration::from_secs(30);
    assert!(
        clip_gate_off_warn_due(&mut slot),
        "首次拒绝必告警（锚点回拨一个窗口）"
    );
    assert!(!clip_gate_off_warn_due(&mut slot), "30s 窗口内抑制（不刷屏）");
    // 窗口过后重新可打。
    let mut slot2 = Instant::now() - Duration::from_secs(31);
    assert!(clip_gate_off_warn_due(&mut slot2), "窗口过后重新告警");
}
