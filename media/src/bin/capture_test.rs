//! 测试 windows-capture 后端：捕获帧、计时、保存 BMP。
//!
//! 用法：
//!   cargo run --release --bin capture-test -- [monitor_index] [duration_ms]
//!
//! 示例：
//!   cargo run --release --bin capture-test        # monitor 0, 200ms
//!   cargo run --release --bin capture-test 1 500  # monitor 1, 500ms

#![cfg(target_os = "windows")]

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use kirin_desk_media::capture::ScreenCaptureSource;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let monitor_index: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let duration_ms: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200);

    println!("=== windows-capture 捕获测试 ===");
    println!("显示器索引: {}", monitor_index);
    println!("捕获时长: {}ms", duration_ms);
    println!();

    // 创建输出目录
    let output_dir = PathBuf::from(
        std::env::current_dir().unwrap_or_default()
    ).join("capture_test_output");
    let _ = fs::create_dir_all(&output_dir);
    println!("输出目录: {}", output_dir.display());

    // 1. 创建捕获后端
    println!("\n[1/3] 创建捕获后端...");
    let mut cap = match kirin_desk_media::capture::windows_capture::WindowsCaptureBackend::new(
        monitor_index,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("创建失败: {e}");
            std::process::exit(1);
        }
    };

    let (w, h) = cap.resolution();
    println!("  分辨率: {}x{}", w, h);
    println!("  显示器数: {}", cap.monitor_info().len());

    // 2. 在时间窗口内捕获帧
    println!("\n[2/3] 捕获 {}ms...", duration_ms);
    let start = Instant::now();
    let window_end = start + std::time::Duration::from_millis(duration_ms);
    let mut frames: Vec<(Vec<u8>, u32, u32, Instant, usize, std::time::Duration)> = Vec::new();

    while Instant::now() < window_end {
        let frame_start = Instant::now();
        match cap.wait_for_frame() {
            Ok(capture_frame) => {
                let elapsed = frame_start.elapsed();
                let (data, fw, fh, dirty_rects, proc_time) = match &capture_frame {
                    kirin_desk_media::capture::CaptureFrame::WindowsCapture(f) => {
                        // 帧携带捕获线程回调内的真实处理耗时
                        (
                            f.data.clone(),
                            f.width,
                            f.height,
                            f.dirty_rects.len(),
                            f.processing_time,
                        )
                    }
                    _ => continue,
                };
                frames.push((data, fw, fh, frame_start, dirty_rects, proc_time));
                println!(
                    "  帧 #{}: {}x{}, 等帧={:?}, 捕获处理={:?}, dirty={}",
                    frames.len(),
                    fw,
                    fh,
                    elapsed,
                    proc_time,
                    dirty_rects
                );
            }
            Err(kirin_desk_media::capture::CaptureError::Timeout) => {}
            Err(e) => {
                eprintln!("  捕获错误: {e}");
                break;
            }
        }
    }

    let elapsed_total = start.elapsed();
    println!("\n  共捕获 {} 帧, 耗时 {:?}", frames.len(), elapsed_total);

    // 3. 保存 BMP
    println!("\n[3/3] 保存 BMP 到 {} ...", output_dir.display());
    for (i, (data, w, h, _ts, dirty_count, _pt)) in frames.iter().enumerate() {
        let filename = format!(
            "frame_{:04}_w{}x{}_d{}.bmp",
            i, w, h, dirty_count
        );
        let path = output_dir.join(&filename);
        match save_rgba_as_bmp(data, *w, *h, &path) {
            Ok(_) => println!("  ✓ {} ({}x{}, {} dirty rects)", filename, w, h, dirty_count),
            Err(e) => eprintln!("  ✗ {} 保存失败: {}", filename, e),
        }
    }

    println!("\n=== 测试完成 ===");
    println!("输出目录: {}", output_dir.display());
    println!(
        "帧率: {:.1} fps (共 {} 帧 / {:?})",
        frames.len() as f64 / elapsed_total.as_secs_f64(),
        frames.len(),
        elapsed_total
    );

    // 等待用户按键关闭（保持窗口打开）
    println!("\n按 Enter 键退出...");
    let _ = std::io::stdin().read_line(&mut String::new());
}

/// 将 RGBA 数据保存为 32-bit BMP 文件。
fn save_rgba_as_bmp(data: &[u8], w: u32, h: u32, path: &PathBuf) -> std::io::Result<()> {
    use std::io::Write;

    let row_size = ((w * 32 + 31) / 32) * 4; // BMP 行对齐到 4 字节
    let pixel_data_size = row_size * h;
    let file_size = 14 + 40 + pixel_data_size;

    let mut file = fs::File::create(path)?;

    // BMP 文件头 (14 bytes)
    file.write_all(b"BM")?;
    file.write_all(&(file_size as u32).to_le_bytes())?;
    file.write_all(&[0u8; 4])?; // reserved
    file.write_all(&(14u32 + 40).to_le_bytes())?; // offset to pixel data

    // DIB 头 (40 bytes) - BITMAPINFOHEADER
    file.write_all(&40u32.to_le_bytes())?; // header size
    file.write_all(&w.to_le_bytes())?;
    file.write_all(&h.to_le_bytes())?;
    file.write_all(&1u16.to_le_bytes())?; // planes
    file.write_all(&32u16.to_le_bytes())?; // bpp
    file.write_all(&0u32.to_le_bytes())?; // compression (BI_RGB)
    file.write_all(&pixel_data_size.to_le_bytes())?;
    file.write_all(&[0u8; 16])?; // resolution and colors

    // 像素数据 (BGRA, bottom-up): 转换 RGBA → BGRA
    for y in (0..h).rev() {
        let row_start = (y * w * 4) as usize;
        let row_end = row_start + (w * 4) as usize;
        let row = &data[row_start..row_end];
        for pixel in row.chunks(4) {
            // RGBA → BGRA
            file.write_all(&[pixel[2], pixel[1], pixel[0], pixel[3]])?;
        }
        // 行填充（对齐到 4 字节）
        let padding = row_size - w * 4;
        for _ in 0..padding {
            file.write_all(&[0])?;
        }
    }

    Ok(())
}
