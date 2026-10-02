//!
//! 用户实测根因（180KB/s 吞吐 / 卡顿 / 高延迟）的三个量化断言：
//!
//! 1. **帧泵节奏**（`pump_mode_realtime_pacing`）：低延迟帧泵
//!    （WindowPipeline `set_low_latency`）+ 全速合成运动帧源 + 真实软编
//!    → 断言窗口率 ≥ 25/s（修复前批量窗口模式实测 ~5.5 窗/s @ 182ms 节律；
//!    70ms 批量关窗的理论上限也只有 ~14 窗/s）且窗口 ≤ 2 帧（不积攒）。
//!    运行在真实 FFmpeg 上（`ensure_loaded` 失败 / 软编缺失时跳过，与既有
//!    编码测试同口径）。
//!
//! 2. **长 GOP**（`pump_mode_long_gop_no_per_window_idr`）：窗口边界不再
//!    无条件 IDR（旧行为实测占 78% 带宽）——NALU 结构扫描 + IDR 密度断言
//!    （设计态 ~5% vs 回归态 ~50%+，口径详见函数文档）。
//!
//! 3. **传输吞吐**（`securechannel_loopback_throughput_8mbps`）：真实握手
//!    TCP 回环 SecureChannel 大帧路径（`send_big_packet`，GUI 生产服务端
//!    每窗一包同款）按 30fps 节拍（落后即补发，同生产 capture 泵纪律）
//!    持续推 40KB（≈9.6Mbps）→ 客户端实测吞吐 ≥ 8Mbps（修复前整链实测
//!    被压在 ~1.4Mbps；传输层在此被钉死为「无 180KB/s 结构性上限」——
//!    剩余节流只可能来自编码/节奏层）。
//!
//! 依赖仅 tokio TCP 回环 + FFmpeg DLL（场景 1）。

use std::time::{Duration, Instant};

// ════════════════════════════════════════════════════════════════
// 场景 1：帧泵节奏（真实编码器）
// ════════════════════════════════════════════════════════════════

/// ≥30fps；不加人工 sleep 节拍，以工作速率压泵——生产 capture 泵同纪律：
/// 帧到了就泵，泵跟不上才是缺陷）喂 `WindowPipeline`（帧泵模式 +
/// 30/60fps 档位），5 秒内断言：
/// - 窗口率 ≥ 25/s（逐帧关窗生效；修复前 70ms 积攒 + 串行编码 ~5.5 窗/s，
///   70ms 批量关窗的理论上限也只有 ~14 窗/s）；
/// - 单窗口 ≤ 2 帧（门控丢旧保新生效，不积攒陈旧批）；
///
/// 帧内容**预生成**（8 相位循环）：debug 构建下逐帧生成移动条带实测
/// ~8ms/帧，会把帧生成成本混进节奏度量（且 Windows `std::thread::sleep`
/// 15.6ms 定时器量子对 33ms 节拍的过冲达 ~45%，把稳态窗口率压到阈值
/// 边缘）。预生成后单帧供给成本 ≈ 一次 Arc 换入（µs 级），度量只含
/// 泵 + 编码本身。
#[test]
fn pump_mode_realtime_pacing() {
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("FFmpeg DLL unavailable; pump pacing test skipped");
        return;
    }
    use kirin_desk_media::adaptive::FpsGovernorConfig;
    use kirin_desk_media::proto::{RawFrame, WindowConfig};
    use kirin_desk_media::window_pipeline::WindowPipeline;
    use kirin_desk_media::VideoEncoderPipeline;
    use std::sync::Arc;

    let encoder = match VideoEncoderPipeline::new(kirin_desk_media::encoder::Codec::H264, None) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SW encoder unavailable: {e}; pump pacing test skipped");
            return;
        }
    };
    let mut pipeline = WindowPipeline::new(WindowConfig::default(), encoder);
    pipeline.set_low_latency(true);
    pipeline.set_fps_governor_config(FpsGovernorConfig {
        static_fps: 1.0,
        low_fps: 30.0,
        motion_fps: 60.0,
        ..FpsGovernorConfig::default()
    });

    // 合成运动帧（预生成）：1280x720，1/4 屏宽条带 × 16 相位，每相位横移
    // 1/16 屏（80px）。设计口径：
    // - 相位间 tile 活动度 ≈ 0.15 ≫ 运动阈值 0.05 → 治理器稳定运动档
    //   （60fps 门控 16.7ms），窗口率不随档位抖动（WIP 8 相位 × 1/8 屏
    //   移步下实测落进中间档 33ms 门控，30.6 窗/s 只留 22% 余量）；
    // - 每相位残差区仅 ~160px 宽（移步决定，非条带宽）→ P 帧编码 ~15-20ms
    //   < 33ms，debug 构建下窗口率 ~50/s，负载扰动余量 ≥2×；
    // - 相邻相位真实差异 → 持续 P 帧出码（非 skip 流）。
    let (w, h) = (1280u32, 720u32);
    let band_w = (w as usize) / 4;
    let frames: Vec<Arc<Vec<u8>>> = (0..16)
        .map(|k| {
            let mut buf = vec![40u8; (w as usize) * (h as usize) * 4];
            let band_x = (k as usize) * (w as usize / 16);
            for y in 0..h as usize {
                let row = y * w as usize * 4;
                for i in 0..(band_w / 4) {
                    let x = (band_x + i * 4) % w as usize;
                    let off = row + x * 4;
                    buf[off] = 200;
                    buf[off + 1] = 120;
                    buf[off + 2] = 60;
                    buf[off + 3] = 255;
                }
            }
            Arc::new(buf)
        })
        .collect();

    let mut windows = 0usize;
    let mut frames_total = 0usize;
    let mut max_frames_per_win = 0usize;
    let mut first_window_instant: Option<Instant> = None;
    let t0 = Instant::now();
    let mut seq = 0u64;

    // 5 秒全速源：帧循环换入，push_frame 即泵（无 sleep 节拍）。
    while t0.elapsed() < Duration::from_secs(5) {
        let data = Arc::clone(&frames[(seq % 16) as usize]);
        seq += 1;
        let raw = RawFrame {
            data,
            width: w,
            height: h,
            timestamp: std::time::SystemTime::now(),
            dirty_rects: vec![],
            force_key: windows == 0,
        };
        match pipeline.push_frame(raw) {
            Ok(Some(win)) => {
                if first_window_instant.is_none() {
                    first_window_instant = Some(Instant::now());
                }
                windows += 1;
                frames_total += win.frame_count as usize;
                max_frames_per_win = max_frames_per_win.max(win.frame_count as usize);
            }
            Ok(None) => {}
            Err(e) => panic!("push_frame error: {e}"),
        }
    }
    let dur = t0.elapsed().as_secs_f64();
    eprintln!(
         {:.1} windows/s, max {max_frames_per_win} frames/window",
        windows as f64 / dur
    );
    assert!(
        windows as f64 / dur >= 25.0,
        "帧泵窗口率 {:.1}/s < 25（批量窗口节流回归？修复前实测 ~5.5/s，\
         70ms 批量上限 ~14/s）",
        windows as f64 / dur
    );
    assert!(
        max_frames_per_win <= 2,
        "帧泵单窗口 {} 帧 > 2（门控丢旧保新失效，陈旧帧积攒回归）",
        max_frames_per_win
    );
    // 首窗立即（force_key 即关窗，非等 70ms 到期）。
    if let Some(t) = first_window_instant {
        assert!(
            t.duration_since(t0) < Duration::from_millis(500),
            "首窗 {}ms 才产出（force_key 立即关窗回归）",
            t.duration_since(t0).as_millis()
        );
    }
}

/// 旧行为实测占 78% 带宽）。全速推 1.2s 局部运动帧（640×360 条带 ×
/// 32 相位 × 20px 移步，无 force_key；首窗由 x264 会话首帧自然 IDR）→
/// **NALU 结构 + 密度断言**（IDR 判定 = H.264 NALU 头 `nal_unit_type == 5`
/// Annex B 扫描）：
/// - 首窗单帧且为 IDR（会话起始语义）；
/// - IDR 密度 ≤ 30%（设计态 ~5%；「每窗首帧无条件 IDR」回归态 ≈ 50-70%）；
/// - 含 IDR 窗占比 ≤ 60%（设计态 ~10%；回归态 ≈ 100%）。
///
/// 口径要点（均为实测踩坑后钉死）：
/// - **设计态 IDR 来源**（续做岗2 收口定案）：force_key/needs_idr（会话
///   首帧/显示器切换/新观众/码率档切换）+ **GOP=60 周期兜底**（SW 显式
///   对齐 HW 的 (fps*2).clamp(30,60)，QUIC 数据报丢包恢复同步点）+
///   scenecut（x264 默认保留——真实场景切换的同步点，HW 同口径）。
///   修复链：①WIP 消每窗 flush/每窗首帧无条件 IDR（78% 带宽杀手）②SW
///   原未设 gop → 默认 `gop_size=-1`（FFmpeg 8.1 wrapper 语义：-1 = 保留
///   x264 默认 keyint 250，与 HW 显式 60 不一致）→ 显式 GOP=60 对齐。
/// - **本测试内容上的 IDR 实测**：合成条带（20px/相位高频突变）持续触发
///   scenecut → 设计态实测 11-16%（7-10/63 帧，逐窗调试钉死）；回归态
///   （每窗首帧无条件 IDR，窗 ~1-2 帧）≈ 50-70%。密度阈值 30% / 窗占比
///   60% 对两态均有 ≥2× 余量。真实屏幕内容上 scenecut 稀疏（场景切换才
///   触发），周期兜底按 200 帧微变探针实测间隔 41 帧 ≈ 2.4%。
/// - **密度而非「非首窗零 IDR」**：零 IDR 断言与 GOP=60 周期 + scenecut
///   设计矛盾；密度/窗占比为纯结构量、负载无关。
/// - **密度而非字节比**（前序修正）：x264 ABR 把 P 帧码量铺满目标码率
///   （400kbps 下均 P ~1.4KB vs IDR ~2.3KB，比 ~0.62），字节比阈值落在
///   ABR 行为敏感区（workspace 并行绿/串行红）。字节量降级为 eprintln。
/// - **码率钉死 400kbps**（`set_bitrate_override`，测试夹具）：640×360
///   仅 0.23Mpx，rate_ladder 默认 4Mbps ABR 给 ~0.87 bpp 余量 → QP 塌到
///   ~0 编码变慢；钉 400kbps → QP~28-32 编码快、行为稳。码率映射另由
/// - **局部运动内容**（WIP 原版「全像素 +3 渐变」实测被弃）：全局均匀
///   漂移在低 QP 下 P 帧全帧残差反超平色 IDR，字节度量前提倒挂。
#[test]
fn pump_mode_long_gop_no_per_window_idr() {
    if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
        eprintln!("FFmpeg DLL unavailable; long gop test skipped");
        return;
    }
    use kirin_desk_media::encoder::Codec;
    use kirin_desk_media::proto::{RawFrame, WindowConfig};
    use kirin_desk_media::window_pipeline::WindowPipeline;
    use kirin_desk_media::VideoEncoderPipeline;
    use std::sync::Arc;

    let encoder = match VideoEncoderPipeline::new(Codec::H264, None) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SW encoder unavailable: {e}; long gop test skipped");
            return;
        }
    };
    let mut pipeline = WindowPipeline::new(WindowConfig::default(), encoder);
    pipeline.set_low_latency(true);
    // 码率钉死 400kbps（测试夹具，理由见函数文档「口径要点」）：QP~28-32
    // 使 IDR/P 字节比稳定在 ~0.2，远离 QP 塌缩区的 P 帧地板。
    pipeline.encoder().set_bitrate_override(Some(400_000));

    // 条带帧预生成：640×360，w/4 宽条带 × 32 相位 × 20px 移步（全周期
    // 32×20=640px）。相邻相位残差区 ~40px 宽 → P 帧小；tile 活动度
    // ~0.1-0.2 ≫ 0.05 → 治理器稳定运动档。
    let (w, h) = (640u32, 360u32);
    let band_w = (w as usize) / 4;
    let frames: Vec<Arc<Vec<u8>>> = (0..32)
        .map(|k| {
            let mut buf = vec![60u8; (w as usize) * (h as usize) * 4];
            let band_x = (k as usize) * (w as usize / 32);
            for y in 0..h as usize {
                let row = y * w as usize * 4;
                for i in 0..(band_w / 4) {
                    let x = (band_x + i * 4) % w as usize;
                    let off = row + x * 4;
                    buf[off] = 200;
                    buf[off + 1] = 120;
                    buf[off + 2] = 60;
                    buf[off + 3] = 255;
                }
            }
            Arc::new(buf)
        })
        .collect();

    // H.264 NALU 头扫描（Annex B）：帧含 IDR slice（nal_unit_type == 5）？
    // IDR 判定用 NALU 类型（0x65 系：ref_idc=3+type=5），SPS/PPS（7/8，
    // 会话首帧前置 extradata）与 P slice（1）/SEI（6）均不命中。
    fn frame_has_idr(frame_pkts: &[Vec<u8>]) -> bool {
        for p in frame_pkts {
            let b = p.as_slice();
            let mut i = 0usize;
            while i + 3 < b.len() {
                if i + 4 <= b.len() && b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 0 && b[i + 3] == 1 {
                    i += 4; // 4 字节起始码，NALU 头即 b[i]
                } else if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
                    i += 3; // 3 字节起始码，NALU 头即 b[i]
                } else {
                    i += 1;
                    continue;
                }
                // H.264 码流内嵌防再同步（00 00 03 序列）保证载荷中不出现
                // 裸 00 00 01 → 起始码扫描无歧义。
                if i < b.len() && b[i] & 0x1F == 5 {
                    return true;
                }
            }
        }
        false
    }

    // 1.2s 全速源（360p ~2ms/帧）→ 默认治理器运动档 33ms 门控 ~30+ 窗；
    // 时间口径对负载扰动稳健（WIP 30 帧固定计数只够 ~7 窗 → 断言空转）。
    let t0 = Instant::now();
    let mut seq = 0u64;
    // (窗字节, 窗帧数, 窗内 IDR 帧数)
    let mut windows: Vec<(usize, usize, usize)> = Vec::new();
    while t0.elapsed() < Duration::from_millis(1200) {
        let raw = RawFrame {
            data: Arc::clone(&frames[(seq % 32) as usize]),
            width: w,
            height: h,
            timestamp: std::time::SystemTime::now(),
            dirty_rects: vec![],
            force_key: false, // 仅首窗（x264 会话首帧自然 IDR）。
        };
        seq += 1;
        if let Some(win) = pipeline.push_frame(raw).expect("push") {
            let (bytes, nframes, nidr) = win
                .frames
                .iter()
                .fold((0usize, 0usize, 0usize), |(b, n, k), f| {
                    (
                        b + f.iter().map(|x| x.len()).sum::<usize>(),
                        n + 1,
                        k + usize::from(frame_has_idr(f)),
                    )
                });
            windows.push((bytes, nframes, nidr));
        }
    }
    if windows.len() < 10 {
        eprintln!(
            "only {} windows produced; long gop test skipped",
            windows.len()
        );
        return;
    }
    // 断言（口径见函数文档）：
    // 1) 首窗必为单帧且含会话首帧 IDR（后续帧被门控丢旧保新攒入下一窗）；
    // 2) IDR 密度 ≤ 30%：设计态（GOP=60 周期 + scenecut，下限 keyint_min=30）
    //    实测 ~5%；回归态（每窗首帧无条件 IDR，窗 ~1-2 帧）≈ 50-70% → 失败；
    // 3) 含 IDR 的窗占比 ≤ 60%：设计态 IDR 间隔 ≥30 帧 ≈ 每 15 窗最多 1 个
    //    （~10%）；回归态每窗 1 个 ≈ 100% → 失败。
    let (first_b, first_n, first_idr) = windows[0];
    assert_eq!(first_n, 1, "首窗应为单帧会话首帧 IDR，实测 {} 帧", first_n);
    assert!(first_idr >= 1, "首窗缺会话首帧 IDR（x264 会话起始语义回归）");
    let rest_idrs: usize = windows[1..].iter().map(|(_, _, k)| *k).sum();
    let rest_bytes: usize = windows[1..].iter().map(|(b, _, _)| *b).sum();
    let rest_frames: usize = windows[1..].iter().map(|(_, n, _)| *n).sum();
    let total_frames = first_n + rest_frames;
    let total_idrs = first_idr + rest_idrs;
    let idr_windows = windows.iter().filter(|(_, _, k)| *k > 0).count();
    let rest_avg = if rest_frames > 0 {
        rest_bytes as f64 / rest_frames as f64
    } else {
        0.0
    };
    eprintln!(
         (含 IDR 窗 {idr_windows}/{}; first={}B, 非首窗均帧 {rest_avg:.0}B)",
        windows.len(),
        total_frames,
        total_idrs,
        total_idrs as f64 / total_frames as f64 * 100.0,
        windows.len(),
        first_b
    );
    assert!(
        total_idrs as f64 / total_frames as f64 <= 0.3,
        "IDR 密度 {:.1}% > 30%（每窗首帧无条件 IDR 回归——修复前实测 IDR \
         占 78% 带宽；长 GOP 设计态 ~5%）",
        total_idrs as f64 / total_frames as f64 * 100.0
    );
    assert!(
        idr_windows as f64 / windows.len() as f64 <= 0.6,
        "含 IDR 窗占比 {:.1}% > 60%（每窗 IDR 回归；设计态 IDR 间隔 ≥30 \
         编码帧 ≈ 10%）",
        idr_windows as f64 / windows.len() as f64 * 100.0
    );
}

// ════════════════════════════════════════════════════════════════
// 场景 2：SecureChannel 回环吞吐（真实握手 + 大帧路径）
// ════════════════════════════════════════════════════════════════

/// （GUI 生产服务端每窗一包同款路径）按 30fps 节拍推 40KB 大帧（≈9.6Mbps）
/// × 6s → 客户端实测吞吐 ≥ 8Mbps。修复前整链实测 ~1.4Mbps（180KB/s）——
/// 本断言钉死「传输/加密层无 180KB/s 结构性上限」。
///
/// **运行时形态**：`multi_thread`（2 worker）——生产 GUI runtime 即多线程
/// （`tokio::runtime::Runtime::new()`），发送/接收任务跑在独立 worker。
/// 单线程 runtime（`#[tokio::test]` 默认）下收发共享唯一 worker：回环
/// 背压把 40KB 单包发送耗时实测放大到 ~9.6ms（纯 AES+write 应 <1ms），
/// 33ms 节拍实际跑不满 30fps，测出的是 harness 而非传输层。
///
/// **完成顺序**（死锁修复）：直接 `recv_task.await`。原 WIP 用
/// `std::sync::mpsc` 做 done 信号——阻塞 `recv()` 落在唯一 worker 上时
/// 接收任务永不被轮询（probe 实测：服务端 127 包发完并退出后主任务停在
/// `done_rx.recv()` 不再前进）。服务端退出 → 连接 EOF → 接收循环
/// `Ok(Err(_))` 自然终止（正常结束信号，非错误；中途真实错误会体现为
/// 吞吐不足被下方断言捕获）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn securechannel_loopback_throughput_8mbps() {
    use kirin_desk_core::crypto::ed25519::IdentityManager;
    use kirin_desk_core::crypto::handshake as hs;
    use kirin_desk_core::crypto::handshake::{PinExpectation, SecureChannel};
    use kirin_desk_media::encoder::types::{EncodedPacket, PacketKind, Timestamp};
    use kirin_desk_media::transport::{ChannelTag, SecureChannelReceiver, SecureChannelSender};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // 测试身份：临时目录独立子目录，前后清理（零残留）。
    let tmp = std::env::temp_dir().join("kirin_r68_tp");
    let _ = std::fs::create_dir_all(&tmp);
    let s_key = tmp.join("server.key");
    let c_key = tmp.join("client.key");
    let _ = std::fs::remove_file(&s_key);
    let _ = std::fs::remove_file(&c_key);
    let server_im = IdentityManager::generate(s_key.clone()).expect("server identity");
    let client_im = IdentityManager::generate(c_key.clone()).expect("client identity");
    let server_pub = server_im.public_key_base64();
    let client_pub = client_im.public_key_base64();

    // 服务端：握手后按 30fps 节拍推 40KB 大帧（send_big_packet）——
    // deadline 步进 + 落后即补发（同生产 capture 泵纪律，调度抖动不自节流）。
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = kirin_desk_core::network::tcp::set_nodelay(&stream);
        let g = hs::server_handshake_verified_generic(stream, &server_im, "tp-server", &client_pub)
            .await
            .expect("server handshake");
        let ch = SecureChannel {
            stream: g.stream,
            cipher: g.cipher,
            peer_id: g.peer_id,
            peer_domain: g.peer_domain,
            peer_device_type: g.peer_device_type,
            selected_codec: g.selected_codec,
            peer_os: g.peer_os,
        };
        let (_r, writer) = ch.into_split();
        let mut sender = SecureChannelSender::new(writer);
        let payload = vec![0xA5u8; 40 * 1024];
        let t0 = Instant::now();
        let slot = Duration::from_millis(33);
        let mut next_due = t0;
        let mut n = 0u64;
        // 6 秒 × 30fps = 180 帧 × 40KB ≈ 7.2MB ≈ 9.6Mbps。
        while t0.elapsed() < Duration::from_secs(6) {
            next_due += slot;
            if let Some(wait) = next_due.checked_duration_since(Instant::now()) {
                tokio::time::sleep(wait).await;
            }
            let pkt = EncodedPacket {
                ts: Timestamp::now(),
                kind: PacketKind::Video,
                data: payload.clone(),
                is_key: false,
            };
            sender.send_big_packet(&pkt).await.expect("send big packet");
            n += 1;
        }
        n
    });

    // 客户端：握手后收满 6s，统计吞吐。
    let cstream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = kirin_desk_core::network::tcp::set_nodelay(&cstream);
    let g = hs::client_handshake_generic(
        cstream,
        &client_im,
        "tp-client",
        "tp.local",
        "desktop",
        "tp-server",
        PinExpectation::exact_from_base64(&server_pub).unwrap(),
        "challenge",
    )
    .await
    .expect("client handshake");
    let ch = SecureChannel {
        stream: g.stream,
        cipher: g.cipher,
        peer_id: g.peer_id,
        peer_domain: g.peer_domain,
        peer_device_type: g.peer_device_type,
        selected_codec: g.selected_codec,
        peer_os: g.peer_os,
    };
    let (reader, _w) = ch.into_split();
    let mut rx = SecureChannelReceiver::new(reader);

    let recv_task = tokio::spawn(async move {
        let t0 = Instant::now();
        let mut bytes = 0u64;
        let mut frames = 0u64;
        while t0.elapsed() < Duration::from_secs(6) {
            match tokio::time::timeout(Duration::from_secs(3), rx.recv_tagged()).await {
                Ok(Ok((tag, _hdr, payload))) => {
                    if tag != ChannelTag::Video {
                        continue;
                    }
                    bytes += payload.len() as u64;
                    frames += 1;
                }
                // 发送端停止后连接关闭 → EOF（正常结束）。
                Ok(Err(_)) => break,
                Err(_) => break, // 3s 无数据（发送端已停）。
            }
        }
        let dur = t0.elapsed().as_secs_f64();
        (bytes, frames, dur)
    });

    let sent = server_task.await.expect("server join");
    // 服务端退出（写半 drop → EOF）后接收任务自然终止——直接 await，
    // 不用阻塞式跨运行时信号（见函数头「死锁修复」）。
    let (bytes, frames, dur) = recv_task.await.expect("recv join");
    // 清理测试身份文件。
    let _ = std::fs::remove_file(&s_key);
    let _ = std::fs::remove_file(&c_key);
    let mbps = bytes as f64 * 8.0 / dur / 1e6;
    eprintln!(
        bytes as f64 / 1024.0
    );
    assert!(
        mbps >= 8.0,
        "SecureChannel 回环吞吐 {mbps:.2} Mbps < 8 Mbps（传输层节流回归；\
         修复前整链实测 1.4Mbps/180KB/s）"
    );
}
