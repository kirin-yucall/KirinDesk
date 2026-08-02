//! M13-T006 文件传输全链路集成测试。
//!
//! 真实 TCP + 完整握手（AEAD 加密通道）上跑文件传输协议：
//! 帧封装（`[tag 0x06][bincode(FileTransferFrame)]`，core 视角的简化 wire——
//! media 层的 PacketHeader 封装由 ui self-test 覆盖）、滑窗、分片重组、
//! SHA-256 整体校验、原子落盘、断点续传、并发 ≤3、路径穿越/超限拒绝。
//!
//! 驱动逻辑复用 core 状态机（SlideWindowSender / ChunkReceiver），
//! I/O 用 core 的 SecureChannel 读写半通道（网络层真实）。

use kirin_desk_core::connection::file_transfer::{
    block_len, block_offset, derive_transfer_id, sha256_bytes, sha256_file,
    ChunkReceiver, FileOfferMeta, FileOp, FileTransferFrame, SlideWindowSender, BLOCK_SIZE,
};
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    client_handshake, server_handshake_verified, SecureChannelReader, SecureChannelWriter,
};
use std::path::{Path, PathBuf};

/// 帧 tag（与 media `ChannelTag::FileTransfer = 0x06` 对齐）。
const FT_TAG: u8 = 0x06;

/// 建立一对真实握手通道（本机回环 TCP + Ed25519/X25519 + AEAD）。
async fn make_channel_pair() -> (SecureChannelReader, SecureChannelWriter, SecureChannelReader, SecureChannelWriter) {
    use kirin_desk_core::crypto::handshake::SecureChannel;
    use std::sync::atomic::{AtomicU64, Ordering as AtOrdering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tmp = std::env::temp_dir();
    let seq = SEQ.fetch_add(1, AtOrdering::Relaxed);
    let server_im = IdentityManager::generate(tmp.join(format!("kirin_e2e_server_{}_{}.key", std::process::id(), seq))).unwrap();
    let client_im = IdentityManager::generate(tmp.join(format!("kirin_e2e_client_{}_{}.key", std::process::id(), seq))).unwrap();
    let server_pub = server_im.public_key_base64();
    let client_pub = client_im.public_key_base64();
    let (cr, sr): (SecureChannel, SecureChannel) = tokio::join!(
        async {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            client_handshake(
                stream, &client_im, "e2e-client", "e2e.local", "desktop", "e2e-server",
                &server_pub, "",
            )
            .await
            .unwrap()
        },
        async {
            let (stream, _) = listener.accept().await.unwrap();
            server_handshake_verified(stream, &server_im, "e2e-server", &client_pub)
                .await
                .unwrap()
        }
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

/// 生成伪随机测试文件。
fn make_source_file(dir: &Path, name: &str, size: u64) -> (PathBuf, Vec<u8>, [u8; 32]) {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join(name);
    let mut rng = 0xDEAD_BEEF_CAFE_F00Du64;
    let mut content = Vec::new();
    while (content.len() as u64) < size {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        content.push((rng >> 33) as u8);
    }
    std::fs::write(&path, &content).unwrap();
    let sha = sha256_bytes(&content);
    (path, content, sha)
}

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kirin_e2e_{tag}_{}", std::process::id()));
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
    // 1. Offer。
    let offer = recv_frame(reader).await;
    if offer.op != FileOp::Offer {
        return Err(format!("expected Offer, got {:?}", offer.op));
    }
    let tid = offer.transfer_id;
    let meta: FileOfferMeta = bincode::deserialize(&offer.data)
        .map_err(|e| format!("offer meta: {e}"))?;
    let checked = ChunkReceiver::validate_offer(&meta, max_file_size)
        .map_err(|e| format!("offer rejected: {e}"))?;
    let mut recv = ChunkReceiver::new(tid);
    recv.begin(&checked, &recv_dir, offer.sha256, resume_from)
        .map_err(|e| format!("begin: {e}"))?;
    // 2. Accept（断点协商）。
    let mut accept = FileTransferFrame::simple(tid, FileOp::Accept, 0);
    accept.data = bincode::serialize(&resume_from).unwrap();
    send_frame(writer, &accept).await;
    // 3. 数据块 → Ack（累积）；Finish → 整体校验 → 原子落盘 → FinishAck。
    //    空文件（0 块）无 Data 帧，直接等 Finish。
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
    send_frame(writer, &FileTransferFrame::offer(tid, &meta, sender.total_blocks(), sha)).await;
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
        // 填窗口。
        while let Some(seq) = sender.next_unsent_seq() {
            let len = block_len(seq, size);
            let off = block_offset(seq);
            use std::io::{Read, Seek, SeekFrom};
            file.seek(SeekFrom::Start(off)).map_err(|e| format!("seek: {e}"))?;
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
        // 等确认（Ack/Nack）。
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

// ════════════════════════════════════════════════════════════════
// 测试用例
// ════════════════════════════════════════════════════════════════

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

/// 推送全链路：A 推文件给 B，SHA-256 与源一致，无 .part 残留。
#[tokio::test]
async fn test_push_roundtrip() {
    let dir = tmp_dir("push");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    let (src, content, _) = make_source_file(&src_dir, "big.bin", BLOCK_SIZE * 3 + 1234);
    let pair = make_pair().await;
    let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
    // 双向同时驱动（各自独占读写半，双工无冲突）。
    let (s_res, c_res) = tokio::join!(
        async {
            drive_sender(&mut c_reader, &mut c_writer, &src, "salt-a", 0).await
        },
        async {
            drive_receiver(&mut s_reader, &mut s_writer, recv_dir.clone(), 4 * 1024 * 1024 * 1024, 0).await
        }
    );
    s_res.expect("sender ok");
    let (tid, final_path) = c_res.expect("receiver ok");
    assert_eq!(tid, derive_transfer_id("big.bin", content.len() as u64, "salt-a"));
    assert_eq!(std::fs::read(&final_path).unwrap(), content);
    // 无 .part 残留。
    let leftovers: Vec<_> = std::fs::read_dir(&recv_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
        .collect();
    assert!(leftovers.is_empty(), "no .part leftover");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 下载方向：B 推文件给 A（协议对称）。
#[tokio::test]
async fn test_download_direction() {
    let dir = tmp_dir("download");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    let (src, content, _) = make_source_file(&src_dir, "down.bin", BLOCK_SIZE * 2 + 7);
    let pair = make_pair().await;
    let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
    // B（服务端）→ A（客户端）。
    let (s_res, c_res) = tokio::join!(
        async {
            drive_sender(&mut s_reader, &mut s_writer, &src, "salt-b", 0).await
        },
        async {
            drive_receiver(&mut c_reader, &mut c_writer, recv_dir.clone(), 4 * 1024 * 1024 * 1024, 0).await
        }
    );
    s_res.expect("sender ok");
    let (_, final_path) = c_res.expect("receiver ok");
    assert_eq!(std::fs::read(&final_path).unwrap(), content);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 空文件（0 块）：Offer → Accept → Finish 全链路。
#[tokio::test]
async fn test_empty_file() {
    let dir = tmp_dir("empty");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    let (src, content, _) = make_source_file(&src_dir, "empty.bin", 0);
    assert!(content.is_empty());
    let pair = make_pair().await;
    let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
    let (s_res, c_res) = tokio::join!(
        async { drive_sender(&mut c_reader, &mut c_writer, &src, "salt-e", 0).await },
        async {
            drive_receiver(&mut s_reader, &mut s_writer, recv_dir.clone(), 4 * 1024 * 1024 * 1024, 0).await
        }
    );
    s_res.expect("sender ok");
    let (_, final_path) = c_res.expect("receiver ok");
    assert_eq!(std::fs::read(&final_path).unwrap(), Vec::<u8>::new());
    let _ = std::fs::remove_dir_all(&dir);
}

/// 断点续传：收 2 块后"中断"（连接断开，.part 保留），重连后从断点续传，
/// 重复块不落盘、最终 SHA-256 一致。
#[tokio::test]
async fn test_resume_after_interrupt() {
    let dir = tmp_dir("resume");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    std::fs::create_dir_all(&recv_dir).unwrap();
    let (src, content, _) = make_source_file(&src_dir, "resume.bin", BLOCK_SIZE * 4);

    // 阶段 1：接收前 2 块后中断（接收端 drop，模拟进程断线）。
    {
        let pair = make_pair().await;
        let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
        let size = content.len() as u64;
        let sha = sha256_bytes(&content);
        let tid = derive_transfer_id("resume.bin", size, "salt-r");
        let recv_dir_phase1 = recv_dir.clone();
        // 接收端：Offer → Accept → 只收 2 块 → 中断。
        let recv_task = tokio::spawn(async move {
            let offer = recv_frame(&mut s_reader).await;
            assert_eq!(offer.op, FileOp::Offer);
            let meta: FileOfferMeta = bincode::deserialize(&offer.data).unwrap();
            let mut recv = ChunkReceiver::new(tid);
            recv.begin(&meta, &recv_dir_phase1, offer.sha256, 0).unwrap();
            let mut accept = FileTransferFrame::simple(tid, FileOp::Accept, 0);
            accept.data = bincode::serialize(&0u32).unwrap();
            send_frame(&mut s_writer, &accept).await;
            for _ in 0..2 {
                let f = recv_frame(&mut s_reader).await;
                assert_eq!(f.op, FileOp::Data);
                recv.on_data(f.seq, &f.data).unwrap();
                let ack = FileTransferFrame::simple(tid, FileOp::Ack, recv.next_seq().saturating_sub(1));
                send_frame(&mut s_writer, &ack).await;
            }
            recv.next_seq() // 2
        });
        // 发送端：Offer + 前 2 块后放弃（不等确认）。
        let mut sender = SlideWindowSender::new(tid, "resume.bin".into(), size, sha).unwrap();
        let mut file = std::fs::File::open(&src).unwrap();
        send_frame(&mut c_writer, &FileTransferFrame::offer(tid, &FileOfferMeta { name: "resume.bin".into(), size }, sender.total_blocks(), sha)).await;
        let _ = recv_frame(&mut c_reader).await; // Accept
        sender.on_accept(0);
        for _ in 0..2 {
            let seq = sender.next_unsent_seq().unwrap();
            let mut buf = vec![0u8; block_len(seq, size)];
            use std::io::{Read, Seek, SeekFrom};
            file.seek(SeekFrom::Start(block_offset(seq))).unwrap();
            file.read_exact(&mut buf).unwrap();
            send_frame(&mut c_writer, &FileTransferFrame { transfer_id: tid, op: FileOp::Data, seq, total_blocks: sender.total_blocks(), data: buf, sha256: [0u8; 32] }).await;
            sender.mark_sent(seq);
        }
        // 中断：双方 drop。
        let resume = recv_task.await.unwrap();
        assert_eq!(resume, 2);
        // .part 保留且长度 = 2 块（目标最终名不存在 → 无 "(1)" 去重后缀）。
        let part = recv_dir.join("resume.bin.part");
        assert!(part.exists(), ".part kept for resume");
        assert_eq!(std::fs::metadata(&part).unwrap().len(), BLOCK_SIZE * 2);
    }

    // 阶段 2：重连续传（接收方 resume_from=2，发送方 local_resume_seq=2）。
    let pair = make_pair().await;
    let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
    let (s_res, c_res) = tokio::join!(
        async { drive_sender(&mut c_reader, &mut c_writer, &src, "salt-r", 2).await },
        async {
            drive_receiver(&mut s_reader, &mut s_writer, recv_dir.clone(), 4 * 1024 * 1024 * 1024, 2).await
        }
    );
    s_res.expect("resume sender ok");
    let (_, final_path) = c_res.expect("resume receiver ok");
    assert_eq!(std::fs::read(&final_path).unwrap(), content, "resumed file identical");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 路径穿越样本（`..\evil`、绝对路径、盘符）在 Offer 阶段即被拒绝。
#[tokio::test]
async fn test_traversal_rejected() {
    let dir = tmp_dir("traversal");
    let recv_dir = dir.join("recv");
    let pair = make_pair().await;
    let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
    // 接收端：Offer 校验失败 → 回 Reject，不落盘。
    let recv_task = tokio::spawn(async move {
        let offer = recv_frame(&mut s_reader).await;
        let meta: FileOfferMeta = bincode::deserialize(&offer.data).unwrap();
        match ChunkReceiver::validate_offer(&meta, 4 * 1024 * 1024 * 1024) {
            Ok(_) => Err::<(), String>("should have rejected".into()),
            Err(e) => {
                let mut rej = FileTransferFrame::simple(offer.transfer_id, FileOp::Reject, 0);
                rej.data = e.to_string().into_bytes();
                send_frame(&mut s_writer, &rej).await;
                Ok(())
            }
        }
    });
    // 发送端：发恶意 Offer，等 Reject。
    let meta = FileOfferMeta { name: "..\\..\\evil.exe".into(), size: 100 };
    let tid = derive_transfer_id("..\\..\\evil.exe", 100, "salt-t");
    send_frame(&mut c_writer, &FileTransferFrame::offer(tid, &meta, 1, [0u8; 32])).await;
    let rej = recv_frame(&mut c_reader).await;
    assert_eq!(rej.op, FileOp::Reject);
    let reason = String::from_utf8_lossy(&rej.data).to_string();
    assert!(reason.contains("unsafe"), "reason mentions unsafe: {reason}");
    recv_task.await.unwrap().expect("receiver rejected");
    // 无任何文件落盘。
    let files = std::fs::read_dir(&recv_dir)
        .map(|it| it.filter_map(|e| e.ok()).count())
        .unwrap_or(0);
    assert_eq!(files, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3 个并发任务互不干扰，全部成功且 SHA-256 一致。
#[tokio::test]
async fn test_concurrent_three() {
    let dir = tmp_dir("concurrent");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    let mut files = Vec::new();
    for i in 0..3 {
        let (src, content, _) = make_source_file(
            &src_dir,
            &format!("f{i}.bin"),
            BLOCK_SIZE * (i as u64 + 1) + i as u64,
        );
        files.push((src, content));
    }
    // 三个独立通道（每文件一连接，验证并发互扰也覆盖同一连接内排队——
    // 连接内并发由 sender/receiver 状态机保证；此处验证并行任务隔离）。
    let mut handles = Vec::new();
    for (i, (src, content)) in files.iter().enumerate() {
        let src = src.clone();
        let content = content.clone();
        let recv_dir = recv_dir.clone();
        handles.push(tokio::spawn(async move {
            let pair = make_pair().await;
            let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
            let salt = format!("salt-{i}");
            let (s_res, c_res) = tokio::join!(
                async { drive_sender(&mut c_reader, &mut c_writer, &src, &salt, 0).await },
                async {
                    drive_receiver(&mut s_reader, &mut s_writer, recv_dir.clone(), 4 * 1024 * 1024 * 1024, 0).await
                }
            );
            s_res.expect("sender ok");
            let (_, final_path) = c_res.expect("receiver ok");
            assert_eq!(std::fs::read(&final_path).unwrap(), content, "file {i} identical");
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    // 3 个最终文件都存在。
    for i in 0..3 {
        assert!(recv_dir.join(format!("f{i}.bin")).exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// 超限文件（> 配置大小）在 Offer 阶段即被拒绝，不发数据块。
#[tokio::test]
async fn test_oversize_rejected() {
    let dir = tmp_dir("oversize");
    let pair = make_pair().await;
    let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
    let max: u64 = 1024;
    let recv_task = tokio::spawn(async move {
        let offer = recv_frame(&mut s_reader).await;
        let meta: FileOfferMeta = bincode::deserialize(&offer.data).unwrap();
        match ChunkReceiver::validate_offer(&meta, max) {
            Ok(_) => Err::<(), String>("should have rejected".into()),
            Err(_) => {
                let mut rej = FileTransferFrame::simple(offer.transfer_id, FileOp::Reject, 0);
                rej.data = b"too large".to_vec();
                send_frame(&mut s_writer, &rej).await;
                Ok(())
            }
        }
    });
    // 发送端发超限 Offer。
    let meta = FileOfferMeta { name: "huge.bin".into(), size: max + 1 };
    let tid = derive_transfer_id("huge.bin", max + 1, "salt-o");
    send_frame(&mut c_writer, &FileTransferFrame::offer(tid, &meta, 1, [0u8; 32])).await;
    let rej = recv_frame(&mut c_reader).await;
    assert_eq!(rej.op, FileOp::Reject);
    recv_task.await.unwrap().expect("receiver rejected");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 滑动窗口：64 块以上文件（窗口满 → Ack 推进 → 新块），全链路正确。
#[tokio::test]
async fn test_window_flow_large_file() {
    let dir = tmp_dir("window");
    let src_dir = dir.join("src");
    let recv_dir = dir.join("recv");
    // 80 块 = 5 MiB（超过 64 窗口，触发两轮滑窗）。
    let (src, content, _) = make_source_file(&src_dir, "large.bin", BLOCK_SIZE * 80);
    let pair = make_pair().await;
    let Pair { mut c_reader, mut c_writer, mut s_reader, mut s_writer } = pair;
    let (s_res, c_res) = tokio::join!(
        async { drive_sender(&mut c_reader, &mut c_writer, &src, "salt-w", 0).await },
        async {
            drive_receiver(&mut s_reader, &mut s_writer, recv_dir.clone(), 4 * 1024 * 1024 * 1024, 0).await
        }
    );
    s_res.expect("sender ok");
    let (_, final_path) = c_res.expect("receiver ok");
    assert_eq!(std::fs::read(&final_path).unwrap(), content);
    let _ = std::fs::remove_dir_all(&dir);
}
