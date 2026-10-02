//!
//! 风格对齐 `core/tests/file_transfer_e2e.rs`：真实 127.0.0.1 TCP 回环 +
//! 完整 core 握手（Ed25519/X25519 + AEAD SecureChannel 读写半）+ 进程内
//! 驱动发送方（`SlideWindowSender`）与接收方（`ChunkReceiver`）状态机对。
//! Wire 用 core 视角简化分帧（`[tag 0x06][bincode(FileTransferFrame)]`）；
//! media 层 `PacketHeader` 封装（`PacketKind::FileTransfer` → `send_big_packet`）
//!
//! # 用例
//!
//! 1. `reachability_smoke_call_surface` — B 岗调用面 pub 可达性（编译期证据
//!    + 常量/帧往返/状态机构造/调度器/持久化存储/media 包装断言）；
//! 2. `small_file_1kb_roundtrip` — 小文件 1KB（1 块）：SHA-256 一致 +
//!    `.part` → 原子 rename 落盘 + 完成事件（FinishAck）正确；
//! 3. `sliding_window_5mb` — 中等文件 5 MiB = 80 块 > `WINDOW_SIZE`(64)，
//!    必走多窗/滑窗路径：同上断言；
//! 4. `resume_with_store_persistence` — 断点：收 2 块后中断（`.part` 保留）
//!    → `TransferStore` 断点持久化文件正确生成（save_to → load_from 往返、
//!    字段逐一比对、part_path 在位）→ 重连按持久化值续传，最终 SHA-256 一致。
//!
//! # 环境
//!
//! 身份密钥对写入进程级唯一临时路径（同 core e2e 口径），不依赖
//! `KIRIN_DATA_DIR`；下载目录用每用例独立临时目录，收尾删除。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use kirin_desk_core::connection::file_transfer::{
    block_len, block_offset, derive_transfer_id, sanitize_filename, sha256_bytes, sha256_file,
    total_blocks_for, unique_target_path, validate_block_count, ChunkReceiver, FileOfferMeta,
    FileOp, FileTransferFrame, SlideWindowSender, StoredTransfer, TransferScheduler,
    TransferStore, DEFAULT_MAX_FILE_SIZE, BLOCK_SIZE, WINDOW_SIZE,
};
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    client_handshake, server_handshake_verified, PinExpectation, SecureChannel,
    SecureChannelReader, SecureChannelWriter,
};
use kirin_desk_media::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use kirin_desk_media::transport::ChannelTag;

/// 帧 tag（与 media `ChannelTag::FileTransfer = 0x06` 对齐，冒烟用例断言）。
const FT_TAG: u8 = 0x06;

// ════════════════════════════════════════════════════════════════
// 通道/驱动（与 core e2e 同构；经 mobile crate 依赖树引用 core/media）
// ════════════════════════════════════════════════════════════════

/// 建立一对真实握手通道（本机回环 TCP + Ed25519/X25519 + AEAD）。
async fn make_channel_pair() -> (
    SecureChannelReader,
    SecureChannelWriter,
    SecureChannelReader,
    SecureChannelWriter,
) {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tmp = std::env::temp_dir();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let server_im = IdentityManager::generate(tmp.join(format!(
        "kirin_mob_ft_e2e_server_{}_{}.key",
        std::process::id(),
        seq
    )))
    .unwrap();
    let client_im = IdentityManager::generate(tmp.join(format!(
        "kirin_mob_ft_e2e_client_{}_{}.key",
        std::process::id(),
        seq
    )))
    .unwrap();
    let server_pub = server_im.public_key_base64();
    let client_pub = client_im.public_key_base64();
    let (cr, sr): (SecureChannel, SecureChannel) = tokio::join!(
        async {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            client_handshake(
                stream,
                &client_im,
                "mob-ft-client",
                "mob-ft.local",
                "android",
                "mob-ft-server",
                PinExpectation::exact_from_base64(&server_pub).expect("server pubkey"),
                "",
            )
            .await
            .unwrap()
        },
        async {
            let (stream, _) = listener.accept().await.unwrap();
            server_handshake_verified(stream, &server_im, "mob-ft-server", &client_pub)
                .await
                .unwrap()
        },
    );
    let (c_r, c_w) = cr.into_split();
    let (s_r, s_w) = sr.into_split();
    (c_r, c_w, s_r, s_w)
}

/// 发一帧：`[tag][bincode(frame)]`。
async fn send_frame(writer: &mut SecureChannelWriter, frame: &FileTransferFrame) {
    let bytes = frame.encode().unwrap();
    let mut wire = Vec::with_capacity(1 + bytes.len());
    wire.push(FT_TAG);
    wire.extend_from_slice(&bytes);
    writer.send(&wire).await.unwrap();
}

/// 收一帧（跳过非文件 tag）。
async fn recv_frame(reader: &mut SecureChannelReader) -> FileTransferFrame {
    loop {
        let wire = reader.receive().await.unwrap();
        if let Some(rest) = wire.strip_prefix(&[FT_TAG]) {
            return FileTransferFrame::decode(rest).unwrap();
        }
    }
}

/// 生成伪随机测试文件（LCG，确定性）。
fn make_source_file(dir: &Path, name: &str, size: u64) -> (PathBuf, Vec<u8>, [u8; 32]) {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join(name);
    let mut rng = 0xDEAD_BEEF_CAFE_F00Du64;
    let mut content = Vec::new();
    while (content.len() as u64) < size {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        content.push((rng >> 33) as u8);
    }
    std::fs::write(&path, &content).unwrap();
    let sha = sha256_bytes(&content);
    (path, content, sha)
}

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kirin_mob_ft_e2e_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 接收端驱动：Offer → 校验 → Accept（携带续传进度）→ 收块 Ack →
/// Finish 整体校验 → 原子落盘 → FinishAck。返回 (transfer_id, 最终路径)。
#[allow(clippy::too_many_arguments)]
async fn drive_receiver(
    reader: &mut SecureChannelReader,
    writer: &mut SecureChannelWriter,
    recv_dir: PathBuf,
    max_file_size: u64,
    resume_from: u32,
) -> Result<(u64, PathBuf), String> {
    let offer = recv_frame(reader).await;
    if offer.op != FileOp::Offer {
        return Err(format!("expected Offer, got {:?}", offer.op));
    }
    let tid = offer.transfer_id;
    let meta: FileOfferMeta =
        bincode::deserialize(&offer.data).map_err(|e| format!("offer meta: {e}"))?;
    let checked = ChunkReceiver::validate_offer(&meta, max_file_size)
        .map_err(|e| format!("offer rejected: {e}"))?;
    let mut recv = ChunkReceiver::new(tid);
    recv.begin(&checked, &recv_dir, offer.sha256, resume_from)
        .map_err(|e| format!("begin: {e}"))?;
    // Accept（断点协商）。
    let mut accept = FileTransferFrame::simple(tid, FileOp::Accept, 0);
    accept.data = bincode::serialize(&resume_from).unwrap();
    send_frame(writer, &accept).await;
    // 数据块 → Ack（累积）；Finish → 整体校验 → 原子落盘 → FinishAck。
    loop {
        let frame = recv_frame(reader).await;
        match frame.op {
            FileOp::Data => {
                recv.on_data(frame.seq, &frame.data)
                    .map_err(|e| format!("on_data: {e}"))?;
                let ack = FileTransferFrame::simple(tid, FileOp::Ack, recv.next_seq().saturating_sub(1));
                send_frame(writer, &ack).await;
            }
            FileOp::Finish => {
                if !recv.is_complete() {
                    return Err("Finish before all blocks received".into());
                }
                recv.verify().map_err(|e| format!("verify: {e}"))?;
                let final_path = recv.commit().map_err(|e| format!("commit: {e}"))?;
                let mut fa = FileTransferFrame::simple(tid, FileOp::FinishAck, 0);
                fa.data = final_path.to_string_lossy().to_string().into_bytes();
                send_frame(writer, &fa).await;
                return Ok((tid, final_path));
            }
            FileOp::Cancel => {
                recv.cancel();
                return Err("receiver: cancelled by peer".into());
            }
            other => return Err(format!("receiver: unexpected {:?}", other)),
        }
    }
}

/// 发送端驱动：Offer → Accept → 滑窗发块（Ack/Nack 推进）→ Finish → FinishAck。
async fn drive_sender(
    reader: &mut SecureChannelReader,
    writer: &mut SecureChannelWriter,
    src: &Path,
    salt: &str,
    resume_seq: u32,
) -> Result<u64, String> {
    let size = std::fs::metadata(src).map_err(|e| format!("metadata: {e}"))?.len();
    let name = src.file_name().unwrap().to_string_lossy().to_string();
    let sha = sha256_file(src).map_err(|e| format!("sha: {e}"))?;
    let tid = derive_transfer_id(&name, size, salt);
    let mut sender = SlideWindowSender::new(tid, name.clone(), size, sha)
        .map_err(|e| format!("sender: {e}"))?;
    sender.local_resume_seq = resume_seq;
    let mut file = std::fs::File::open(src).map_err(|e| format!("open: {e}"))?;

    // 1. Offer。
    let meta = FileOfferMeta { name, size };
    send_frame(
        writer,
        &FileTransferFrame::offer(tid, &meta, sender.total_blocks(), sha),
    )
    .await;
    // 2. Accept（续传协商）。
    let accept = recv_frame(reader).await;
    if accept.op != FileOp::Accept {
        let reason = String::from_utf8_lossy(&accept.data).to_string();
        return Err(format!("offer rejected: {reason}"));
    }
    let remote_next = bincode::deserialize::<u32>(&accept.data).unwrap_or(0);
    sender.on_accept(remote_next);
    // 3. 滑窗发送 + 确认。
    loop {
        while let Some(seq) = sender.next_unsent_seq() {
            let len = block_len(seq, size);
            let off = block_offset(seq);
            use std::io::{Read, Seek, SeekFrom};
            file.seek(SeekFrom::Start(off))
                .map_err(|e| format!("seek: {e}"))?;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf).map_err(|e| format!("read: {e}"))?;
            let frame = FileTransferFrame {
                transfer_id: tid,
                op: FileOp::Data,
                seq,
                total_blocks: sender.total_blocks(),
                data: buf,
                sha256: [0u8; 32],
            };
            send_frame(writer, &frame).await;
            sender.mark_sent(seq);
        }
        if sender.all_acked() {
            break;
        }
        let frame = recv_frame(reader).await;
        match frame.op {
            FileOp::Ack => {
                sender.on_ack(frame.seq);
            }
            FileOp::Nack => {
                sender.on_nack(frame.seq);
            }
            FileOp::Cancel => return Err("sender: cancelled by peer".into()),
            other => return Err(format!("sender: unexpected {:?}", other)),
        }
    }
    // 4. Finish → FinishAck。
    send_frame(
        writer,
        &FileTransferFrame {
            transfer_id: tid,
            op: FileOp::Finish,
            seq: 0,
            total_blocks: sender.total_blocks(),
            data: Vec::new(),
            sha256: sender.sha256,
        },
    )
    .await;
    let fa = recv_frame(reader).await;
    if fa.op != FileOp::FinishAck {
        return Err(format!("expected FinishAck, got {:?}", fa.op));
    }
    Ok(tid)
}

/// 双向通道对（收发各一对读写半）。
struct Pair {
    c_reader: SecureChannelReader,
    c_writer: SecureChannelWriter,
    s_reader: SecureChannelReader,
    s_writer: SecureChannelWriter,
}

async fn make_pair() -> Pair {
    let (c_r, c_w, s_r, s_w) = make_channel_pair().await;
    Pair { c_reader: c_r, c_writer: c_w, s_reader: s_r, s_writer: s_w }
}

// ════════════════════════════════════════════════════════════════
// 测试用例
// ════════════════════════════════════════════════════════════════

/// 用例 1：B 岗调用面 pub 可达性冒烟（编译期证据 + 行为断言）。
///
/// 常量（BLOCK_SIZE/WINDOW_SIZE/DEFAULT_MAX_FILE_SIZE）、帧构造/编解码、
/// 发送/接收状态机、Offer 校验（路径穿越 fail-closed）、调度器、
/// TransferStore 断点持久化、media `ChannelTag`/`PacketKind`/`EncodedPacket`。
#[test]
fn reachability_smoke_call_surface() {
    // 测试确实运行在 mobile crate 上下文中（rlib 链接在位）。
    assert!(kirin_desk_mobile::version().contains("kirin-mobile"));

    // 协议常量。
    assert_eq!(BLOCK_SIZE, 64 * 1024);
    assert_eq!(WINDOW_SIZE, 64);
    assert_eq!(DEFAULT_MAX_FILE_SIZE, 4 * 1024 * 1024 * 1024);
    // 帧 tag 与 media ChannelTag 对齐（红线：走既有 0x06 通道，不自研）。
    assert_eq!(ChannelTag::FileTransfer as u8, FT_TAG);
    assert_eq!(ChannelTag::from_byte(FT_TAG), Some(ChannelTag::FileTransfer));

    // 帧构造 + 编解码往返。
    let meta = FileOfferMeta { name: "a.bin".into(), size: 100 };
    let frame = FileTransferFrame::offer(1, &meta, 1, [7u8; 32]);
    let wire = frame.encode().expect("encode");
    let back = FileTransferFrame::decode(&wire).expect("decode");
    assert_eq!(back, frame);

    // 发送状态机：构造 + 窗口推进。
    let mut sender =
        SlideWindowSender::new(1, "a.bin".into(), 100, [7u8; 32]).expect("sender new");
    assert_eq!(sender.total_blocks(), 1);
    assert_eq!(sender.total_blocks(), total_blocks_for(100) as u32);
    // 注意：状态机本身**不**门控 Accept 前取号（构造后即可取块）——
    // Offer→Accept 顺序由驱动层保证（桌面 FileSession 与 B 岗接线须先等
    // Accept 再 on_accept + 发块）。此处固化该语义供 B 岗参照。
    assert_eq!(sender.next_unsent_seq(), Some(0), "构造后即可取号（驱动层须先等 Accept）");
    sender.on_accept(0);
    assert_eq!(sender.next_unsent_seq(), Some(0));
    sender.mark_sent(0);
    assert_eq!(sender.on_ack(0), 1);
    assert!(sender.all_acked());

    // 接收状态机：构造 + Offer 校验（路径穿越 fail-closed，安全红线）。
    let _recv = ChunkReceiver::new(1);
    assert!(
        ChunkReceiver::validate_offer(
            &FileOfferMeta { name: "..\\..\\evil.exe".into(), size: 100 },
            DEFAULT_MAX_FILE_SIZE,
        )
        .is_err(),
        "路径穿越必须在 Offer 阶段拒绝"
    );
    let checked =
        ChunkReceiver::validate_offer(&meta, DEFAULT_MAX_FILE_SIZE).expect("validate offer");
    assert_eq!(checked.name, "a.bin");

    // 纯函数调用面。
    assert_eq!(total_blocks_for(0), 0);
    assert_eq!(total_blocks_for(1), 1);
    assert_eq!(block_offset(3), 3 * BLOCK_SIZE);
    assert_eq!(block_len(0, 100), 100);
    assert_eq!(block_len(1, 100), 0);
    assert!(validate_block_count(100, 1).is_ok());
    assert!(validate_block_count(100, 2).is_err());
    assert!(sanitize_filename("../x").is_err());
    assert_eq!(sanitize_filename("ok.bin").unwrap(), "ok.bin");
    // SHA-256 空串已知值（自校验口径）。
    assert_eq!(sha256_bytes(b""), [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
        0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
        0x78, 0x52, 0xb8, 0x55,
    ]);

    // 落盘辅助：unique_target_path（去重后缀）。
    let dir = tmp_dir("reach");
    let p = unique_target_path(&dir, "a.bin");
    assert!(p.ends_with("a.bin"));

    // 调度器：push 只入队、pop_ready 才占并发槽；并发上限 3（FIFO）。
    let mut sched = TransferScheduler::new();
    assert!(sched.push(1u64));
    assert_eq!(sched.queued(), 1);
    assert_eq!(sched.active(), 0);
    assert_eq!(sched.pop_ready(), Some(1u64));
    assert_eq!(sched.active(), 1);
    for i in 0..2u64 {
        sched.push(i);
        assert_eq!(sched.pop_ready(), Some(i));
    }
    assert_eq!(sched.active(), 3);
    sched.push(99u64);
    assert_eq!(sched.pop_ready(), None, "并发满 3，第 4 个任务排队");
    assert_eq!(sched.queued(), 1);
    // 一个活跃任务完成 → 99 调度进；随后 3 槽全还，状态归零。
    sched.finish_one();
    assert_eq!(sched.pop_ready(), Some(99u64));
    for _ in 0..3 {
        sched.finish_one();
    }
    assert_eq!(sched.active(), 0);
    assert!(!sched.has_pending());

    // 断点持久化存储：upsert → find 往返。
    let mut store = TransferStore::new();
    store.upsert(StoredTransfer {
        transfer_id: 9,
        name: "a.bin".into(),
        size: 100,
        direction: "recv".into(),
        next_seq: 1,
        sha256: Some([7u8; 32]),
        part_path: None,
    });
    let entry = store.find(9).expect("store entry");
    assert_eq!(entry.next_seq, 1);

    // media 包装：帧 → EncodedPacket（与桌面 file_packet 同模式，B 岗照抄）。
    let pkt = EncodedPacket {
        ts: Timestamp::now(),
        kind: PacketKind::FileTransfer,
        data: wire,
        is_key: false,
    };
    assert!(matches!(pkt.kind, PacketKind::FileTransfer));

    let _ = std::fs::remove_dir_all(&dir);
}

/// 用例 2：小文件 1KB（1 块）全链路：SHA-256 一致 + 原子 rename 落盘 +
/// 完成事件（发送方收到 FinishAck、接收方返回最终路径）。
#[tokio::test]
async fn small_file_1kb_roundtrip() {
    let dir = tmp_dir("small");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    let (src, content, sha) = make_source_file(&src_dir, "small_1kb.bin", 1024);
    assert_eq!(content.len(), 1024);

    let pair = make_pair().await;
    let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
    let (s_res, c_res) = tokio::join!(
        async { drive_sender(&mut c_reader, &mut c_writer, &src, "mob-salt-small", 0).await },
        async {
            drive_receiver(
                &mut s_reader,
                &mut s_writer,
                recv_dir.clone(),
                DEFAULT_MAX_FILE_SIZE,
                0,
            )
            .await
        },
    );
    s_res.expect("sender 完成事件 = 收到 FinishAck");
    let (tid, final_path) = c_res.expect("receiver ok");
    assert_eq!(tid, derive_transfer_id("small_1kb.bin", 1024, "mob-salt-small"));

    // 原子落盘：最终名存在、非 .part、字节级一致、SHA-256 一致。
    assert!(final_path.exists());
    assert!(!final_path.to_string_lossy().ends_with(".part"), "最终路径不得是 .part");
    let on_disk = std::fs::read(&final_path).expect("read final");
    assert_eq!(on_disk, content);
    assert_eq!(sha256_file(&final_path).unwrap(), sha);

    // 无 .part 残留（commit = rename，不是 copy）。
    let leftovers: Vec<_> = std::fs::read_dir(&recv_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
        .collect();
    assert!(leftovers.is_empty(), "no .part leftover");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 用例 3：中等文件 5 MiB = 80 块 > WINDOW_SIZE(64)——必走多窗/滑窗路径
/// （窗口满 64 块 → Ack 累积推进 → 续发 16 块）：同上断言。
#[tokio::test]
async fn sliding_window_5mb() {
    let dir = tmp_dir("sliding");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    // 80 × 64 KiB = 5 MiB（≥5MB；80 > 64 = WINDOW_SIZE，触发滑窗）。
    let size = BLOCK_SIZE * 80;
    assert!(size >= 5 * 1024 * 1024);
    assert!((size / BLOCK_SIZE) as usize > WINDOW_SIZE, "必须超过窗口大小");
    let (src, content, sha) = make_source_file(&src_dir, "mid_5mb.bin", size);

    let pair = make_pair().await;
    let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
    let (s_res, c_res) = tokio::join!(
        async { drive_sender(&mut c_reader, &mut c_writer, &src, "mob-salt-mid", 0).await },
        async {
            drive_receiver(
                &mut s_reader,
                &mut s_writer,
                recv_dir.clone(),
                DEFAULT_MAX_FILE_SIZE,
                0,
            )
            .await
        },
    );
    s_res.expect("sender 完成事件 = 收到 FinishAck");
    let (tid, final_path) = c_res.expect("receiver ok");
    assert_eq!(tid, derive_transfer_id("mid_5mb.bin", size, "mob-salt-mid"));
    assert_eq!(total_blocks_for(size), 80);

    // 落盘正确性：字节级一致 + SHA-256 一致 + 无 .part 残留。
    let on_disk = std::fs::read(&final_path).expect("read final");
    assert_eq!(on_disk, content, "5MB 文件字节级一致");
    assert_eq!(sha256_file(&final_path).unwrap(), sha);
    let leftovers: Vec<_> = std::fs::read_dir(&recv_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
        .collect();
    assert!(leftovers.is_empty(), "no .part leftover");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 用例 4：断点续传 + `TransferStore` 断点持久化文件正确生成。
///
/// 阶段 1：收 2 块后中断（`.part` 保留）；按桌面 `FileSession::save_store`
/// 同模式（load_from → 读改写 → save_to）落 `transfers_recv.json`，断言
/// 文件生成 + 往返解析 + 字段逐一正确；阶段 2：按持久化的 `next_seq`
/// 续传，最终 SHA-256 一致、无 `.part` 残留。
#[tokio::test]
async fn resume_with_store_persistence() {
    let dir = tmp_dir("resume");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    std::fs::create_dir_all(&recv_dir).unwrap();
    let (src, content, sha) = make_source_file(&src_dir, "resume_mob.bin", BLOCK_SIZE * 4);
    let size = content.len() as u64;
    let tid = derive_transfer_id("resume_mob.bin", size, "mob-salt-resume");

    // 阶段 1：接收前 2 块后中断（接收端 drop，模拟进程断线）。
    {
        let pair = make_pair().await;
        let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
        let recv_dir_phase1 = recv_dir.clone();
        let recv_task = tokio::spawn(async move {
            let offer = recv_frame(&mut s_reader).await;
            assert_eq!(offer.op, FileOp::Offer);
            let meta: FileOfferMeta = bincode::deserialize(&offer.data).unwrap();
            let checked =
                ChunkReceiver::validate_offer(&meta, DEFAULT_MAX_FILE_SIZE).unwrap();
            let mut recv = ChunkReceiver::new(tid);
            recv.begin(&checked, &recv_dir_phase1, offer.sha256, 0).unwrap();
            let mut accept = FileTransferFrame::simple(tid, FileOp::Accept, 0);
            accept.data = bincode::serialize(&0u32).unwrap();
            send_frame(&mut s_writer, &accept).await;
            for _ in 0..2 {
                let f = recv_frame(&mut s_reader).await;
                assert_eq!(f.op, FileOp::Data);
                recv.on_data(f.seq, &f.data).unwrap();
                let ack =
                    FileTransferFrame::simple(tid, FileOp::Ack, recv.next_seq().saturating_sub(1));
                send_frame(&mut s_writer, &ack).await;
            }
            recv.next_seq() // 2
        });
        // 发送端：Offer + 前 2 块后放弃（不等确认）。
        let mut sender =
            SlideWindowSender::new(tid, "resume_mob.bin".into(), size, sha).unwrap();
        let mut file = std::fs::File::open(&src).unwrap();
        send_frame(
            &mut c_writer,
            &FileTransferFrame::offer(
                tid,
                &FileOfferMeta { name: "resume_mob.bin".into(), size },
                sender.total_blocks(),
                sha,
            ),
        )
        .await;
        let _ = recv_frame(&mut c_reader).await; // Accept
        sender.on_accept(0);
        for _ in 0..2 {
            let seq = sender.next_unsent_seq().unwrap();
            let mut buf = vec![0u8; block_len(seq, size)];
            use std::io::{Read, Seek, SeekFrom};
            file.seek(SeekFrom::Start(block_offset(seq))).unwrap();
            file.read_exact(&mut buf).unwrap();
            send_frame(
                &mut c_writer,
                &FileTransferFrame {
                    transfer_id: tid,
                    op: FileOp::Data,
                    seq,
                    total_blocks: sender.total_blocks(),
                    data: buf,
                    sha256: [0u8; 32],
                },
            )
            .await;
            sender.mark_sent(seq);
        }
        // 中断：双方 drop。
        let resume = recv_task.await.unwrap();
        assert_eq!(resume, 2);
        // .part 保留且长度 = 2 块。
        let part = recv_dir.join("resume_mob.bin.part");
        assert!(part.exists(), ".part kept for resume");
        assert_eq!(std::fs::metadata(&part).unwrap().len(), BLOCK_SIZE * 2);

        // 断点持久化（桌面 FileSession::save_store 同模式：load → 改 → save）。
        let store_path = dir.join("transfers_recv.json");
        let mut store = TransferStore::new();
        store.upsert(StoredTransfer {
            transfer_id: tid,
            name: "resume_mob.bin".into(),
            size,
            direction: "recv".into(),
            next_seq: resume,
            sha256: Some(sha),
            part_path: Some(part.to_string_lossy().to_string()),
        });
        store.save_to(&store_path).expect("断点持久化文件生成");

        // 断言：文件生成 + 往返解析 + 字段逐一正确。
        assert!(store_path.exists(), "transfers_recv.json 已生成");
        let reloaded = TransferStore::load_from(&store_path).expect("持久化文件可解析");
        let entry = reloaded.find(tid).expect("断点记录在位");
        assert_eq!(entry.name, "resume_mob.bin");
        assert_eq!(entry.size, size);
        assert_eq!(entry.direction, "recv");
        assert_eq!(entry.next_seq, 2, "断点 = 下一块序号");
        assert_eq!(entry.sha256, Some(sha));
        let saved_part = entry.part_path.as_deref().expect("part_path 已持久化");
        assert_eq!(saved_part, part.to_string_lossy().to_string());
        assert!(Path::new(saved_part).exists(), "持久化的 part_path 指向真实 .part");
    }

    // 阶段 2：重连，按持久化值续传（接收方 resume_from=2，发送方 local_resume_seq=2）。
    let store_path = dir.join("transfers_recv.json");
    let resume_from = TransferStore::load_from(&store_path)
        .expect("re-load")
        .find(tid)
        .map(|e| e.next_seq)
        .expect("resume seq from store");
    assert_eq!(resume_from, 2);

    let pair = make_pair().await;
    let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
    let (s_res, c_res) = tokio::join!(
        async { drive_sender(&mut c_reader, &mut c_writer, &src, "mob-salt-resume", resume_from).await },
        async {
            drive_receiver(
                &mut s_reader,
                &mut s_writer,
                recv_dir.clone(),
                DEFAULT_MAX_FILE_SIZE,
                resume_from,
            )
            .await
        },
    );
    s_res.expect("续传 sender ok（FinishAck）");
    let (rtid, final_path) = c_res.expect("续传 receiver ok");
    assert_eq!(rtid, tid);
    assert_eq!(std::fs::read(&final_path).unwrap(), content, "续传后文件一致");
    assert_eq!(sha256_file(&final_path).unwrap(), sha);
    // 完成后无 .part 残留；生产侧此时应 remove 断点记录（TransferStore::remove）。
    assert!(!recv_dir.join("resume_mob.bin.part").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

// ════════════════════════════════════════════════════════════════
// + media 层 `send_big_packet`/`recv_tagged` 大帧路径 + 收侧 0x06 tag 路由，
// 全走生产编排层；真实 core 握手通道对复用上方 `make_pair`）
// ════════════════════════════════════════════════════════════════

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kirin_desk_mobile::file_transfer::{
    spawn_session, Direction, FileTransferHandle, TransferEntry, TransferState,
};
use kirin_desk_media::transport::{SecureChannelReceiver, SecureChannelSender};

/// `KIRIN_DATA_DIR` 进程级串行锁（env 为进程全局：生产接线用例独占，
/// Drop 时恢复，防与同进程其他用例互相污染）。
static FT_ENV_LOCK: Mutex<()> = Mutex::new(());

struct FtEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    /// 隔离目录须贯穿整个测试进程，否则同进程后续日志/审计写回落真实 home）。
    original: Option<std::ffi::OsString>,
}

/// 置 `KIRIN_DATA_DIR` 为本用例临时目录（RAII：Drop 自动恢复原值）。
fn ft_env_guard(dir: &Path) -> FtEnvGuard {
    let lock = FT_ENV_LOCK.lock().unwrap();
    std::env::set_var("KIRIN_DATA_DIR", dir);
    FtEnvGuard { _lock: lock, original }
}

impl Drop for FtEnvGuard {
    fn drop(&mut self) {
        match self.original.clone() {
            Some(v) => std::env::set_var("KIRIN_DATA_DIR", v),
            None => std::env::remove_var("KIRIN_DATA_DIR"),
        }
    }
}

/// 生产接线：半通道包 media 层（单 writer `Arc<Mutex<SecureChannelSender>>`
/// + 收半）+ spawn `file_transfer` 会话 + 泵任务（模拟 orchestration/server
/// 接收循环 0x06 分支：`recv_tagged` → `decode` → mpsc 馈送）。
fn spawn_ft_side(
    rt: &tokio::runtime::Runtime,
    reader: SecureChannelReader,
    writer: SecureChannelWriter,
    role: &'static str,
    salt: &str,
) -> (FileTransferHandle, tokio::task::JoinHandle<()>) {
    let sender = Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(writer)));
    let mut receiver = SecureChannelReceiver::new(reader);
    let (handle, frame_tx) =
        spawn_session(rt, sender, salt.to_string(), role, DEFAULT_MAX_FILE_SIZE);
    let pump = rt.spawn(async move {
        loop {
            match receiver.recv_tagged().await {
                Ok((ChannelTag::FileTransfer, _header, payload)) => {
                    if let Ok(frame) = FileTransferFrame::decode(&payload) {
                        if frame_tx.send(frame).is_err() {
                            break; // 文件会话任务已退出
                        }
                    }
                }
                Ok(_) => {} // 其余 tag 忽略（与生产接线同口径）
                Err(_) => break, // 断连
            }
        }
    });
    (handle, pump)
}

/// 轮询 snapshot 直至谓词命中（返回命中条目）；超时 → None。
async fn wait_entry(
    handle: &FileTransferHandle,
    timeout: Duration,
    mut pred: impl FnMut(&TransferEntry) -> bool,
) -> Option<TransferEntry> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        for e in handle.snapshot() {
            if pred(&e) {
                return Some(e);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// 目录内 `.part` 文件列表。
fn list_parts(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name();
            if n.to_string_lossy().ends_with(".part") {
                out.push(e.path());
            }
        }
    }
    out
}

/// 等目录出现首个 `.part`（Accept → begin 落盘起点）。
async fn wait_for_part(dir: &Path, timeout: Duration) -> Option<PathBuf> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(p) = list_parts(dir).into_iter().next() {
            return Some(p);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// 断言双端断点 store（`transfers_{role}.json`，双端分文件）已清理该 tid。
fn assert_store_clean(cfg_dir: &Path, tid: u64) {
    for role in ["client", "server"] {
        let sp = cfg_dir.join(format!("transfers_{role}.json"));
        let store = TransferStore::load_from(&sp).unwrap_or_default();
        assert!(
            store.find(tid).is_none(),
            "role {role} 断点 store 应已清理 tid {tid}"
        );
    }
}

/// `EncodedPacket(0x06)` + `send_big_packet` 大帧 + 生产 `file_transfer`
/// 会话（发送侧 Offer→Accept 门控 + 接收侧 tag 路由 + 用户门控 Accept）+
/// 落盘断言（字节一致/SHA-256/无 `.part` 残留）+ 双端断点 store 清理。
#[tokio::test]
async fn full_chain_production_roundtrip() {
    let dir = tmp_dir("fullchain");
    let cfg_dir = dir.join("config");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();
    // 80 块 = 5 MiB > WINDOW_SIZE(64)：生产驱动必走多窗/滑窗路径。
    let size = BLOCK_SIZE * 80;
    let (src, content, sha) = make_source_file(&src_dir, "full_5mb.bin", size);
    let _guard = ft_env_guard(&cfg_dir);

    let rt = kirin_desk_mobile::runtime();
    let Pair {
        c_reader,
        c_writer,
        s_reader,
        s_writer,
    } = make_pair().await;
    let (c_handle, c_pump) = spawn_ft_side(&rt, c_reader, c_writer, "client", "mob-salt-full");
    let (s_handle, s_pump) = spawn_ft_side(&rt, s_reader, s_writer, "server", "mob-salt-full");

    // 发送方：推本地文件（双向语义；控制端/被控端同一入口）。
    c_handle.start_send(&src).expect("start_send");
    // 接收方：OfferPending（等待用户决定）→ 接受（落盘目录为入参）。
    let offer = wait_entry(
        &s_handle,
        Duration::from_secs(10),
        |e| e.direction == Direction::Recv && e.state == TransferState::OfferPending,
    )
    .await
    .expect("接收方应见 OfferPending");
    s_handle
        .respond_offer(offer.transfer_id, true, recv_dir.clone())
        .expect("respond accept");
    // 双方等完成（发送方 = FinishAck 事件；接收方 = 整体校验 + 落盘）。
    wait_entry(
        &c_handle,
        Duration::from_secs(60),
        |e| e.transfer_id == offer.transfer_id && e.state == TransferState::Completed,
    )
    .await
    .expect("发送方应 Completed（收到 FinishAck）");
    let s_done = wait_entry(
        &s_handle,
        Duration::from_secs(60),
        |e| {
            e.transfer_id == offer.transfer_id
                && e.direction == Direction::Recv
                && e.state == TransferState::Completed
        },
    )
    .await
    .expect("接收方应 Completed（校验通过 + 落盘）");

    // 落盘断言：最终路径在目标目录、非 .part、字节一致、SHA-256 一致。
    let final_path =
        PathBuf::from(s_done.path.expect("接收方 Completed 应带最终路径"));
    assert!(
        final_path.starts_with(&recv_dir),
        "最终路径应在目标目录内: {final_path:?}"
    );
    assert!(!final_path.to_string_lossy().ends_with(".part"));
    assert_eq!(
        std::fs::read(&final_path).expect("read final"),
        content,
        "5MB 文件字节级一致"
    );
    assert_eq!(sha256_file(&final_path).unwrap(), sha, "SHA-256 一致");
    assert!(list_parts(&recv_dir).is_empty(), "无 .part 残留");

    // 双端断点 store 清理（完成即 remove）。
    assert_store_clean(&cfg_dir, offer.transfer_id);

    c_pump.abort();
    s_pump.abort();
    drop(c_handle);
    drop(s_handle);
    let _ = std::fs::remove_dir_all(&dir);
}

/// （reason 透传 "declined"）并清理（条目 Failed + 断点 store 清理）；
/// 接收方任务终止（Cancelled）、无 `.part` 残留（落盘从未发生）。
#[tokio::test]
async fn reject_path_no_part_no_store() {
    let dir = tmp_dir("reject");
    let cfg_dir = dir.join("config");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();
    let (src, _content, _sha) = make_source_file(&src_dir, "rej_1kb.bin", 1024);
    let _guard = ft_env_guard(&cfg_dir);

    let rt = kirin_desk_mobile::runtime();
    let Pair {
        c_reader,
        c_writer,
        s_reader,
        s_writer,
    } = make_pair().await;
    let (c_handle, c_pump) =
        spawn_ft_side(&rt, c_reader, c_writer, "client", "mob-salt-rej");
    let (s_handle, s_pump) =
        spawn_ft_side(&rt, s_reader, s_writer, "server", "mob-salt-rej");

    c_handle.start_send(&src).expect("start_send");
    let offer = wait_entry(
        &s_handle,
        Duration::from_secs(10),
        |e| e.state == TransferState::OfferPending,
    )
    .await
    .expect("接收方应见 OfferPending");
    // 用户拒绝。
    s_handle
        .respond_offer(offer.transfer_id, false, recv_dir.clone())
        .expect("respond reject");

    // 发送方：Reject → Failed（reason 透传 declined）+ 断点清理。
    let c_e = wait_entry(
        &c_handle,
        Duration::from_secs(10),
        |e| e.transfer_id == offer.transfer_id && e.state == TransferState::Failed,
    )
    .await
    .expect("发送方应收到 Reject → Failed");
    assert!(
        c_e.reason.contains("declined"),
        "拒绝原因应透传: {}",
        c_e.reason
    );
    // 接收方：任务 Cancelled + 无 .part 残留（落盘从未发生）+ 目标目录为空。
    wait_entry(
        &s_handle,
        Duration::from_secs(10),
        |e| e.transfer_id == offer.transfer_id && e.state == TransferState::Cancelled,
    )
    .await
    .expect("接收方任务应 Cancelled");
    assert!(list_parts(&recv_dir).is_empty(), "无 .part 残留");
    assert!(
        std::fs::read_dir(&recv_dir).unwrap().next().is_none(),
        "目标目录应为空"
    );
    assert_store_clean(&cfg_dir, offer.transfer_id);

    c_pump.abort();
    s_pump.abort();
    drop(c_handle);
    drop(s_handle);
    let _ = std::fs::remove_dir_all(&dir);
}

/// （FT-SEC-006 无残留泄漏）+ 双端 `TransferStore` 清理 + 双方条目
/// Cancelled（发送方收到 Cancel 帧）。
#[tokio::test]
async fn cancel_path_part_removed_store_cleaned() {
    let dir = tmp_dir("cancel");
    let cfg_dir = dir.join("config");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();
    // 128 MiB = 2048 块：保证 .part 出现后有足够「传输中」窗口供确定
    // 性取消（避免整传先完成导致 flaky）。
    let size = BLOCK_SIZE * 2048;
    let (src, _content, _sha) = make_source_file(&src_dir, "cancel_128mb.bin", size);
    let _guard = ft_env_guard(&cfg_dir);

    let rt = kirin_desk_mobile::runtime();
    let Pair {
        c_reader,
        c_writer,
        s_reader,
        s_writer,
    } = make_pair().await;
    let (c_handle, c_pump) =
        spawn_ft_side(&rt, c_reader, c_writer, "client", "mob-salt-cancel");
    let (s_handle, s_pump) =
        spawn_ft_side(&rt, s_reader, s_writer, "server", "mob-salt-cancel");

    c_handle.start_send(&src).expect("start_send");
    let offer = wait_entry(
        &s_handle,
        Duration::from_secs(30),
        |e| e.state == TransferState::OfferPending,
    )
    .await
    .expect("接收方应见 OfferPending");
    s_handle
        .respond_offer(offer.transfer_id, true, recv_dir.clone())
        .expect("respond accept");

    // `.part` 出现（Accept → begin → 落盘起点）→ 本地取消（确定性：不
    // 依赖恰好捕获 Receiving 状态）。
    let part = wait_for_part(&recv_dir, Duration::from_secs(15))
        .await
        .expect(".part 应出现（接收方已开始落盘）");
    s_handle.cancel(offer.transfer_id).expect("cancel");

    // 先等取消被处理（条目 Cancelled）——cancel 是异步命令（mpsc → 引擎
    // 任务），须等处理完成再断言 .part 删除。
    wait_entry(
        &s_handle,
        Duration::from_secs(10),
        |e| e.transfer_id == offer.transfer_id && e.state == TransferState::Cancelled,
    )
    .await
    .expect("接收方任务应 Cancelled");
    // .part 删除 + 无残留。
    assert!(!part.exists(), ".part 应在 cancel 后删除");
    assert!(list_parts(&recv_dir).is_empty(), "无 .part 残留");
    // 发送方收到 Cancel 帧 → 亦 Cancelled。
    wait_entry(
        &c_handle,
        Duration::from_secs(10),
        |e| e.transfer_id == offer.transfer_id && e.state == TransferState::Cancelled,
    )
    .await
    .expect("发送方应收到 Cancel 帧 → Cancelled");
    assert_store_clean(&cfg_dir, offer.transfer_id);

    c_pump.abort();
    s_pump.abort();
    drop(c_handle);
    drop(s_handle);
    let _ = std::fs::remove_dir_all(&dir);
}
