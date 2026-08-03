//! R-16（M13-T002）：AV1 编码探索实验。
//!
//! 探测本机 FFmpeg 构建中的 AV1 编码器（libsvtav1 / libaom_av1 / librav1e）
//! 可用性，对可用编码器跑 720p/30fps 合成桌面场景基准（码率/每帧耗时），
//! 与 libx264 对照；码流经 libdav1d 解码回读验证合法性。
//!
//! 输出数据供 `M13-T002_AV1探索报告.md` 引用（决策：采纳 / 搁置）。
//!
//! 用法：`cargo run --release -p kirin-desk-media --bin av1_probe`

use std::time::Instant;

use kirin_desk_media::ffmpeg;

// ── 基准参数 ────────────────────────────────────────────────
/// 编码帧数（默认 30 帧 = 1s @30fps；可传参 `av1_probe <frames>` 跑长序列，
/// 让 SVT VBR 速率控制收敛，码率对照更准）。
const FRAMES_DEFAULT: usize = 30;
/// 目标码率（4 Mbps；x264 与 AV1 同目标，对照码率-耗时-画质权衡）。
const BITRATE: i64 = 4_000_000;
/// 候选编码器（AV1 三实现 + x264 对照）。
const CANDIDATES: &[&str] = &["libsvtav1", "libaom_av1", "librav1e", "libx264"];

/// 合成场景分辨率（720p 桌面级）。
const W: u32 = 1280;
const H: u32 = 720;

/// 单编码器基准结果。
struct Bench {
    encoder: &'static str,
    ok: bool,
    note: String,
    frames: usize,
    bytes: usize,
    /// 总耗时（ms；诊断字段，输出走 kbps/avg_frame_ms——ZM-05 警告清理登记）
    #[allow(dead_code)]
    elapsed_ms: f64,
    kbps: f64,
    /// 平均每帧编码耗时（ms；不含帧合成）。
    avg_frame_ms: f64,
}

impl Bench {
    fn fail(encoder: &'static str, note: String) -> Self {
        Self {
            encoder,
            ok: false,
            note,
            frames: 0,
            bytes: 0,
            elapsed_ms: 0.0,
            kbps: 0.0,
            avg_frame_ms: 0.0,
        }
    }
}

fn main() {
    // 帧数参数（长序列让 SVT VBR 速率控制收敛，码率对照更准）：
    // `av1_probe [frames]`，默认 30。
    let frames: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(FRAMES_DEFAULT);
    if let Err(e) = ffmpeg::ensure_loaded() {
        eprintln!("FFmpeg not available: {e}");
        eprintln!("（需 bundled FFmpeg 8.1.1 shared build，见 release/）");
        std::process::exit(1);
    }
    println!("== R-16 AV1 probe ==");
    println!(
        "avcodec version: {}",
        ffmpeg::format_version(ffmpeg::avcodec_version())
    );

    // 1. 可用性探测。
    let mut available: Vec<&str> = Vec::new();
    for name in CANDIDATES {
        let ok = ffmpeg::avcodec_find_encoder_by_name(name).is_ok();
        println!(
            "  encoder {name}: {}",
            if ok { "available" } else { "NOT in build" }
        );
        if ok {
            available.push(name);
        }
    }

    // 2. 编码基准。
    println!(
        "\n== bench: {W}x{H} @30fps, {frames} frames, target {} kbps ==",
        BITRATE / 1000
    );
    let mut results: Vec<Bench> = Vec::new();
    for name in available {
        let b = bench(name, frames);
        // AV1 码流即时验证（LAST_BITSTREAM 为单槽全局——须在下一编码器跑前消费）。
        let decode_note = if b.ok && b.encoder.starts_with("libs") {
            let bs = LAST_BITSTREAM.get().unwrap().lock().unwrap().clone();
            match decode_verify(&bs) {
                Ok(n) => format!(", decoded {n} frames (bitstream valid)"),
                Err(e) => format!(", decode verify FAILED: {e}"),
            }
        } else {
            String::new()
        };
        println!(
            "  {:<12} {}{}",
            name,
            if b.ok {
                format!(
                    "{} frames, {:>8} B, {:>7.1} kbps, {:>6.2} ms/frame",
                    b.frames, b.bytes, b.kbps, b.avg_frame_ms
                )
            } else {
                format!("FAILED: {}", b.note)
            },
            decode_note
        );
        results.push(b);
    }

    println!("\n（数据入 M13-T002 探索报告，决策登记 M0 路线图）");
}

// ── 编码基准 ────────────────────────────────────────────────

use std::sync::Mutex;
use std::sync::OnceLock;

/// 最近一次成功编码的码流（供解码验证；单线程实验，全局足够）。
static LAST_BITSTREAM: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();

fn last_bitstream() -> &'static Mutex<Vec<u8>> {
    LAST_BITSTREAM.get_or_init(|| Mutex::new(Vec::new()))
}

/// 编码器私有选项（best-effort；不支持的选项被编码器忽略）。
///
/// 速率控制：SVT-AV1 的 `maxrate` 仅支持 CRF 模式、CBR 不支持
/// RANDOM_ACCESS（实测报 bad parameter）→ AV1 用 VBR（只设 `b`），
/// x264 同目标 `b` 对照。
fn apply_encoder_opts(ctx: *mut std::ffi::c_void, name: &str) {
    match name {
        // SVT-AV1：preset 0（最慢）~ 13（最快），8 为速度/质量均衡档；
        // VBR：只设 b（maxrate 会触发 "Max Bitrate only supported with CRF"）。
        "libsvtav1" => {
            let _ = ffmpeg::av_opt_set(ctx, "preset", "8");
        }
        // libaom：cpu-used 0~8（越大越快）。
        "libaom_av1" => {
            let _ = ffmpeg::av_opt_set_int_self(ctx, "cpu-used", 8);
        }
        // rav1e：speed 0~10。
        "librav1e" => {
            let _ = ffmpeg::av_opt_set_int_self(ctx, "speed", 8);
        }
        // 对照：与生产软编同参数（ffmpeg_sw.rs open_with_dict）。
        "libx264" => {
            let _ = ffmpeg::av_opt_set(ctx, "preset", "ultrafast");
            let _ = ffmpeg::av_opt_set(ctx, "tune", "zerolatency");
        }
        _ => {}
    }
}

fn bench(name: &'static str, frames: usize) -> Bench {
    let codec = match ffmpeg::avcodec_find_encoder_by_name(name) {
        Ok(c) => c,
        Err(e) => return Bench::fail(name, format!("find_encoder: {e}")),
    };
    let ctx = match ffmpeg::avcodec_alloc_context3(codec) {
        Ok(c) => c,
        Err(e) => return Bench::fail(name, format!("alloc_context3: {e}")),
    };

    // 结构体字段直写（AVOption 表缺失的字段；与 ffmpeg_sw.rs 同模式）。
    unsafe {
        ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::WIDTH, W as i32);
        ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::HEIGHT, H as i32);
        ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::CODED_WIDTH, W as i32);
        ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::CODED_HEIGHT, H as i32);
        ffmpeg::avctx_set_int(
            ctx,
            ffmpeg::avctx_offset::PIX_FMT,
            ffmpeg::AV_PIX_FMT_YUV420P,
        );
        ffmpeg::avctx_set_int(ctx, ffmpeg::avctx_offset::GOP_SIZE, 60);
    }
    ffmpeg::avctx_set_time_base(ctx, 1, 1000);
    ffmpeg::avctx_set_framerate(ctx, 30, 1);

    let obj = ctx as *mut std::ffi::c_void;
    // VBR 目标码率（AV1 与 x264 同目标，对照码率-耗时；maxrate/max_b_frames
    // 对 SVT 有兼容问题（见 apply_encoder_opts），统一不设——x264 的
    // zerolatency tune 已禁 B 帧）。
    let _ = ffmpeg::av_opt_set_int_self(obj, "b", BITRATE);
    apply_encoder_opts(obj, name);

    if let Err(e) = ffmpeg::avcodec_open2(ctx, codec) {
        let mut c = ctx;
        ffmpeg::avcodec_free_context(&mut c);
        return Bench::fail(name, format!("open2: {e}（构建是否含该编码器？）"));
    }

    // 帧缓冲（YUV420P：Y=w*h，UV 各 w*h/4）。
    let y_size = (W * H) as usize;
    let mut frame_buf = vec![0u8; y_size + y_size / 2];
    let frame = match ffmpeg::av_frame_alloc() {
        Ok(f) => f,
        Err(e) => {
            let mut c = ctx;
            ffmpeg::avcodec_free_context(&mut c);
            return Bench::fail(name, format!("av_frame_alloc: {e}"));
        }
    };
    let packet = match ffmpeg::av_packet_alloc() {
        Ok(p) => p,
        Err(e) => {
            let mut f = frame;
            ffmpeg::av_frame_free(&mut f);
            let mut c = ctx;
            ffmpeg::avcodec_free_context(&mut c);
            return Bench::fail(name, format!("av_packet_alloc: {e}"));
        }
    };

    // 合成帧数据数组（fill_arrays 目标；保活到 send_frame）。
    let mut data: [*mut u8; 4] = [std::ptr::null_mut(); 4];
    let mut linesize: [std::ffi::c_int; 4] = [0; 4];
    if let Err(e) = ffmpeg::av_image_fill_arrays(
        &mut data,
        &mut linesize,
        frame_buf.as_ptr(),
        ffmpeg::AV_PIX_FMT_YUV420P,
        W as i32,
        H as i32,
        1,
    ) {
        let mut f = frame;
        ffmpeg::av_frame_free(&mut f);
        let mut p = packet;
        ffmpeg::av_packet_free(&mut p);
        let mut c = ctx;
        ffmpeg::avcodec_free_context(&mut c);
        return Bench::fail(name, format!("av_image_fill_arrays: {e}"));
    }

    let mut total_bytes = 0usize;
    let mut total_ms = 0.0f64;
    let mut encoded = 0usize;
    let mut bitstream: Vec<u8> = Vec::new();
    let start_all = Instant::now();

    for idx in 0..frames {
        // 合成当前帧（渐变 + 移动方块）。
        synth_frame(&mut frame_buf, W, H, idx);
        unsafe {
            // AVFrame.data/linesize 为 [ptr;8]（YUV420P 用前 3 槽）。
            (*frame).data = [
                data[0],
                data[1],
                data[2],
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ];
            (*frame).linesize = [linesize[0], linesize[1], linesize[2], 0, 0, 0, 0, 0];
            (*frame).width = W as std::ffi::c_int;
            (*frame).height = H as std::ffi::c_int;
            (*frame).format = ffmpeg::AV_PIX_FMT_YUV420P;
            (*frame).pts = idx as i64;
            if idx == 0 {
                (*frame).key_frame = 1;
                (*frame).pict_type = ffmpeg::AV_PICTURE_TYPE_I;
            } else {
                (*frame).key_frame = 0;
                (*frame).pict_type = ffmpeg::AV_PICTURE_TYPE_NONE;
            }
        }

        let t0 = Instant::now();
        if let Err(e) = ffmpeg::avcodec_send_frame(ctx, frame) {
            let mut f = frame;
            ffmpeg::av_frame_free(&mut f);
            let mut p = packet;
            ffmpeg::av_packet_free(&mut p);
            let mut c = ctx;
            ffmpeg::avcodec_free_context(&mut c);
            return Bench::fail(name, format!("send_frame #{idx}: {e}"));
        }
        loop {
            match ffmpeg::avcodec_receive_packet(ctx, packet) {
                Ok(()) => {
                    unsafe {
                        let p = &*packet;
                        if !p.data.is_null() && p.size > 0 {
                            let slice = std::slice::from_raw_parts(p.data, p.size as usize);
                            total_bytes += slice.len();
                            bitstream.extend_from_slice(slice);
                        }
                    }
                    ffmpeg::av_packet_unref(packet);
                    encoded += 1;
                }
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => break,
                Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EOF)) => break,
                Err(e) => {
                    let mut f = frame;
                    ffmpeg::av_frame_free(&mut f);
                    let mut p = packet;
                    ffmpeg::av_packet_free(&mut p);
                    let mut c = ctx;
                    ffmpeg::avcodec_free_context(&mut c);
                    return Bench::fail(name, format!("receive_packet #{idx}: {e}"));
                }
            }
        }
        total_ms += t0.elapsed().as_secs_f64() * 1000.0;
    }
    // Flush：drain 尾部包。编码器异步（SVT/rav1e 线程池 + lookahead 缓冲），
    // EAGAIN 时短等待重试（最多 ~1s），确保 flush 帧全部取出。
    let _ = ffmpeg::avcodec_send_frame(ctx, std::ptr::null());
    let mut retries = 100;
    loop {
        match ffmpeg::avcodec_receive_packet(ctx, packet) {
            Ok(()) => {
                unsafe {
                    let p = &*packet;
                    if !p.data.is_null() && p.size > 0 {
                        let slice = std::slice::from_raw_parts(p.data, p.size as usize);
                        total_bytes += slice.len();
                        bitstream.extend_from_slice(slice);
                        encoded += 1;
                    }
                }
                ffmpeg::av_packet_unref(packet);
                retries = 100; // 有产出 → 重置重试预算。
            }
            Err(ffmpeg::AvError::Code(ffmpeg::AVERROR_EAGAIN)) => {
                if retries == 0 {
                    break;
                }
                retries -= 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            _ => break,
        }
    }
    let elapsed_ms = start_all.elapsed().as_secs_f64() * 1000.0;

    let mut f = frame;
    ffmpeg::av_frame_free(&mut f);
    let mut p = packet;
    ffmpeg::av_packet_free(&mut p);
    let mut c = ctx;
    ffmpeg::avcodec_free_context(&mut c);

    let secs = elapsed_ms / 1000.0;
    let kbps = if secs > 0.0 {
        total_bytes as f64 * 8.0 / 1000.0 / secs
    } else {
        0.0
    };
    *last_bitstream().lock().unwrap() = bitstream;

    Bench {
        encoder: name,
        ok: true,
        note: String::new(),
        frames: encoded,
        bytes: total_bytes,
        elapsed_ms,
        kbps,
        avg_frame_ms: total_ms / frames.max(1) as f64,
    }
}

/// 合成 YUV420P 帧：亮度渐变 + 移动方块（模拟桌面内容变化）。
fn synth_frame(buf: &mut [u8], w: u32, h: u32, frame_idx: usize) {
    let y_size = (w * h) as usize;
    let (y_plane, uv) = buf.split_at_mut(y_size);
    let wu = w as usize;
    let hu = h as usize;
    // Y：横向渐变 + 帧间亮度摆动（避免全静止 → 码率失真）。
    for yi in 0..hu {
        for xi in 0..wu {
            let base = (xi as f32 / w as f32) * 160.0
                + ((frame_idx as f32 * 5.0 + yi as f32 * 0.1) % 60.0);
            y_plane[yi * wu + xi] = (base as u8).min(235).max(16);
        }
    }
    // 移动方块（128×128，沿对角线运动）。
    let sz = 128usize;
    let bx = (frame_idx * 17) % (wu.saturating_sub(sz));
    let by = (frame_idx * 11) % (hu.saturating_sub(sz));
    for yi in by..by + sz {
        for xi in bx..bx + sz {
            y_plane[yi * wu + xi] = 220;
        }
    }
    // UV：中性灰。
    uv.fill(128);
}

/// AV1 码流 → libdav1d（回退 av1）解码，返回产出帧数。
///
/// SVT-AV1/libaom 输出 Annex B（带 4 字节起始码）——整段码流作为一个
/// packet 喂入，FFmpeg 解码器按起始码切帧。
fn decode_verify(bitstream: &[u8]) -> Result<usize, String> {
    // 诊断：Annex B 起始码检测（00 00 00 01 / 00 00 01）。
    let head = &bitstream[..bitstream.len().min(16)];
    let annexb = bitstream.windows(4).any(|w| w == [0, 0, 0, 1])
        || bitstream.windows(3).any(|w| w == [0, 0, 1]);
    eprintln!(
        "decode_verify: {} bytes, annexb={}, head={head:02x?}",
        bitstream.len(),
        annexb
    );
    let codec = ffmpeg::avcodec_find_decoder_by_name("libdav1d")
        .or_else(|_| ffmpeg::avcodec_find_decoder_by_name("av1"))
        .map_err(|e| format!("no AV1 decoder: {e}"))?;
    let ctx = ffmpeg::avcodec_alloc_context3(codec).map_err(|e| e.to_string())?;
    let _ = ffmpeg::av_opt_set_int(ctx as *mut std::ffi::c_void, "threads", 2);
    ffmpeg::avcodec_open2(ctx, codec).map_err(|e| format!("decoder open2: {e}"))?;
    let frame = ffmpeg::av_frame_alloc().map_err(|e| e.to_string())?;
    let packet = ffmpeg::av_packet_alloc().map_err(|e| e.to_string())?;

    let mut decoded = 0usize;
    unsafe {
        (*packet).data = bitstream.as_ptr() as *mut u8;
        (*packet).size = bitstream.len() as std::ffi::c_int;
        (*packet).pts = 0;
    }
    if ffmpeg::avcodec_send_packet(ctx, packet).is_err() {
        // 部分构建对超大单包拒绝——退化为逐块喂入。
        let mut pos = 0usize;
        while pos < bitstream.len() {
            let chunk_end = (pos + 65536).min(bitstream.len());
            unsafe {
                (*packet).data = bitstream[pos..chunk_end].as_ptr() as *mut u8;
                (*packet).size = (chunk_end - pos) as std::ffi::c_int;
            }
            if ffmpeg::avcodec_send_packet(ctx, packet).is_err() {
                break;
            }
            while ffmpeg::avcodec_receive_frame(ctx, frame).is_ok() {
                unsafe {
                    if (*frame).width > 0 && (*frame).height > 0 {
                        decoded += 1;
                    }
                }
                ffmpeg::av_frame_unref(frame);
            }
            pos = chunk_end;
        }
    } else {
        while ffmpeg::avcodec_receive_frame(ctx, frame).is_ok() {
            unsafe {
                if (*frame).width > 0 && (*frame).height > 0 {
                    decoded += 1;
                }
            }
            ffmpeg::av_frame_unref(frame);
        }
    }
    // Flush 尾部。
    if ffmpeg::avcodec_send_null_packet(ctx).is_ok() {
        while ffmpeg::avcodec_receive_frame(ctx, frame).is_ok() {
            unsafe {
                if (*frame).width > 0 {
                    decoded += 1;
                }
            }
            ffmpeg::av_frame_unref(frame);
        }
    }

    let mut f = frame;
    ffmpeg::av_frame_free(&mut f);
    let mut p = packet;
    ffmpeg::av_packet_free(&mut p);
    let mut c = ctx;
    ffmpeg::avcodec_free_context(&mut c);

    if decoded == 0 {
        Err("no frames decoded".into())
    } else {
        Ok(decoded)
    }
}
