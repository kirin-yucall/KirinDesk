//! 编码层三场景基准（P1G §T7.1 / T7.3）。
//!
//! 用法：
//!   cargo run --release --bin codec_bench -- --scene all --frames 300 --resolution 1920x1080
//!   cargo run --release --bin codec_bench -- --scene static --json
//!
//! 场景（合成帧驱动，无需真实捕获/GPU 纹理；1080p 三场景全跑 <1 分钟）：
//!   static       全静：静止桌面纹理 ×N 帧 → 编码器调用 0 / 输出 0 包 / 读回 0 字节
//!   incremental  微变：鼠标移动 + 小窗口闪烁（dirty <5%）→ 编码器调用 0 /
//!                RLE 增量包 ≤16KB/帧；读回 ≤16KB/帧
//!   fullframe    大动：全屏滚动（dirty 100%）→ 编码器调用 = 帧数；
//!                码率 ≈ 目标 CBR（±20%）；ROI side data 随帧
//!
//! 度量口径（与文档一致）：
//!   - 编码器调用 = `VideoEncoder::encode` 调用次数（sw/hw 后端内部 1:1 对应
//!     `avcodec_send_frame`；Static/Incremental 分支不触碰编码器，计数为 0）
//!   - 读回字节 = BenchKernel 记账（模拟 P1B GPU 内核的 CPU 读回量）：
//!     全静 0 / 微变脏 tile RLE 压缩字节（`rle_encode_rust`，与 blit_rle.cpp
//!     一致算法）/ 大动 dirty 索引（4B × 脏块数）
//!   - Tile-Hash 耗时 = CPU 参考实现（采样 CRC32）实测；`KgpuLinked::LINKED`
//!     为 false（无 cmake/feature off）时 GPU <2ms 阈值记 SKIP（不可测），
//!     CPU 回退基线如实输出
//!
//! 帧结构：每场景先 1 帧热身（首帧按设计强制 FullFrame 建 prev_hash，不计入
//! 指标），随后 N 帧进入稳态度量。退出码：0 = 阈值全过；1 = 存在 FAIL；
//! 2 = 致命错误（FFmpeg DLL 缺失等）。

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use kirin_desk_media::encoder::gpu_ffi::kernel::KgpuLinked;
use kirin_desk_media::encoder::gpu_ffi::rle_encode_rust;
use kirin_desk_media::encoder::types::{
    Codec, DirtyTileMap, EncodeDecision, EncodedPacket, GpuTexture, Timestamp,
};
use kirin_desk_media::encoder::video::tile_diff::GpuKernel;
use kirin_desk_media::encoder::video::{EncodeError, VideoEncoder};
use kirin_desk_media::encoder::{factory, FfmpegHwEncoder, VideoEncoderPipeline};

// ════════════════════════════════════════════════════════════════
// CLI 参数
// ════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SceneSel {
    All,
    Static,
    Incremental,
    FullFrame,
}

struct Args {
    scene: SceneSel,
    frames: u32,
    w: u32,
    h: u32,
    /// CBR 目标（kbps）。0 = 不检查码率（仅报告）。
    target_kbps: u32,
    codec: Codec,
    json: bool,
    /// 优先尝试硬件编码器（nvenc 平台 ROI 必测路径；失败自动回退软编）。
    prefer_hw: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            scene: SceneSel::All,
            frames: 300,
            w: 1920,
            h: 1080,
            target_kbps: 2000,
            codec: Codec::H264,
            json: false,
            prefer_hw: false,
        }
    }
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--scene" => {
                let v = it
                    .next()
                    .ok_or("--scene 需要值: all|static|incremental|fullframe")?;
                a.scene = match v.as_str() {
                    "all" => SceneSel::All,
                    "static" => SceneSel::Static,
                    "incremental" => SceneSel::Incremental,
                    "fullframe" => SceneSel::FullFrame,
                    other => return Err(format!("未知场景: {other}")),
                };
            }
            "--frames" => {
                a.frames = it
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("--frames 需要正整数")?;
            }
            "--resolution" => {
                let v = it
                    .next()
                    .ok_or("--resolution 需要 WxH，如 1920x1080")?;
                let (w, h) = v
                    .split_once(['x', 'X'])
                    .ok_or("--resolution 格式应为 WxH")?;
                a.w = w.parse().map_err(|_| format!("宽度非法: {w}"))?;
                a.h = h.parse().map_err(|_| format!("高度非法: {h}"))?;
            }
            "--target-bitrate-kbps" => {
                a.target_kbps = it
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("--target-bitrate-kbps 需要正整数")?;
            }
            "--codec" => {
                let v = it.next().ok_or("--codec 需要 h264|h265")?;
                a.codec = match v.as_str() {
                    "h264" => Codec::H264,
                    "h265" => Codec::H265,
                    other => return Err(format!("未知 codec: {other}")),
                };
            }
            "--json" => a.json = true,
            "--prefer-hw" => a.prefer_hw = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("未知参数: {other}")),
        }
    }
    if a.w == 0 || a.h == 0 || a.frames == 0 {
        return Err("分辨率与帧数必须为正".into());
    }
    Ok(a)
}

fn print_usage() {
    println!(
        "codec_bench — 编码层三场景基准（P1G T7.1）\n\
         \n\
         用法: codec_bench [选项]\n\
         \n\
         --scene <all|static|incremental|fullframe>   场景（默认 all）\n\
         --frames <N>                                  稳态度量帧数（默认 300，另 +1 热身）\n\
         --resolution <WxH>                            分辨率（默认 1920x1080）\n\
         --target-bitrate-kbps <K>                     CBR 目标，±20% 判定（默认 2000；0=仅报告）\n\
         --codec <h264|h265>                           编码标准（默认 h264）\n\
         --prefer-hw                                   优先硬件编码器（ROI 必测路径）\n\
         --json                                        JSON 输出\n\
         \n\
         退出码: 0=阈值全过  1=存在 FAIL  2=致命错误"
    );
}

// ════════════════════════════════════════════════════════════════
// 合成场景（三场景 × 确定性 RGBA 帧）
// ════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SceneKind {
    /// 静止桌面纹理：每帧完全相同的平色桌面（底 + 任务栏 + 窗口矩形）。
    Static,
    /// 微变：静止桌面 + 移动光标（24×24）+ 闪烁窗口（96×96 交替纯色）。
    Incremental,
    /// 大动：全屏滚动渐变（三通道独立位移，保证每帧每 tile 都变）。
    FullFrame,
}

/// 合成帧生成器：`frame(idx)` 填充内部缓冲并返回引用（避免逐帧分配）。
struct SceneGen {
    kind: SceneKind,
    w: u32,
    h: u32,
    buf: Vec<u8>,
    /// 微变场景：光标左上角（像素坐标，随帧移动）。
    cursor_x: u32,
    cursor_y: u32,
}

impl SceneGen {
    fn new(kind: SceneKind, w: u32, h: u32) -> Self {
        Self {
            kind,
            w,
            h,
            buf: vec![0u8; (w * h * 4) as usize],
            cursor_x: 0,
            cursor_y: 0,
        }
    }

    /// 生成第 `idx` 帧（idx=0 热身 / idx≥1 稳态）。返回内部缓冲引用。
    fn frame(&mut self, idx: u32) -> &[u8] {
        self.base_background();
        match self.kind {
            SceneKind::Static => {}
            SceneKind::Incremental => {
                // 光标：每帧移动（回到桌面图案上）。
                self.cursor_x = (idx * 17) % (self.w - 32);
                self.cursor_y = (idx * 11) % (self.h / 2 - 32);
                self.draw_cursor(self.cursor_x, self.cursor_y);
                // 小窗口闪烁：64×32 在两相近灰色间切换（帧差 RLE 代价
                // ≈ 4KB，真实"光标 + 小窗闪烁"微变场景）。
                let bx = self.w - 4 * 64;
                let by = self.h / 2 - 32;
                let color = if idx % 2 == 0 {
                    [0xD8, 0xD8, 0xD8, 0xFF]
                } else {
                    [0xB4, 0xB4, 0xB4, 0xFF]
                };
                self.fill_rect(bx, by, 64, 32, color);
            }
            SceneKind::FullFrame => {
                // 全屏视频/大动内容：8px 细棋盘（<16px 宏块粒度 → I16 无法
                // 平坦化）+ 移动高对比矩形 + 移动色带。设计要点：内容必须让
                // x264 无法"平坦化作弊"——纯随机噪声/大块棋盘会被 ABR 用
                // QP51 全 skip（量化步长 228 吞掉残差、I16 块均值化），
                // 宏块内细纹理 + 大范围运动产生真实残差 → 码率真实。
                // （与 ffmpeg testsrc2 行为对标：2M ABR 下 QP≈34/39）
                let s = idx * 5;
                let rx = ((idx * 37) % (self.w - 200)) as i32;
                let ry = ((idx * 29) % (self.h - 200)) as i32;
                let rx2 = ((idx * 53 + 640) % (self.w - 160)) as i32;
                let ry2 = ((idx * 47 + 320) % (self.h - 160)) as i32;
                let mut p = 0usize;
                for y in 0..self.h {
                    let chk_row = (y as i32 / 8 + s as i32 / 4) & 1;
                    for x in 0..self.w {
                        // 8px 细棋盘：宏块(16×16)内含 2×2 黑白块 → 真实纹理。
                        let chk = (chk_row + (x as i32 / 8)) & 1;
                        let (mut r, mut g, mut b) = if chk == 0 {
                            (0xE8, 0xE8, 0xE8)
                        } else {
                            (0x28, 0x28, 0x28)
                        };
                        // 两个移动高对比矩形（运动补偿无法匹配 → 大残差）。
                        let xi = x as i32;
                        let yi = y as i32;
                        if xi >= rx && xi < rx + 200 && yi >= ry && yi < ry + 200 {
                            r = 0xFF;
                            g = 0xFF;
                            b = 0xFF;
                        } else if xi >= rx2 && xi < rx2 + 160 && yi >= ry2 && yi < ry2 + 160 {
                            r = 0x20;
                            g = 0xA0;
                            b = 0xFF;
                        }
                        self.buf[p] = r;
                        self.buf[p + 1] = g;
                        self.buf[p + 2] = b;
                        self.buf[p + 3] = 0xFF;
                        p += 4;
                    }
                }
            }
        }
        &self.buf
    }

    /// 平色桌面：浅灰底 + 底部任务栏 + 两个窗口矩形（纯色，RLE 可压缩）。
    fn base_background(&mut self) {
        let w = self.w;
        let h = self.h;
        let bg = [0xE6, 0xE6, 0xE6, 0xFF];
        let taskbar = [0x3C, 0x3C, 0x3C, 0xFF];
        let win_a = [0xC9, 0xD4, 0xE0, 0xFF];
        let win_b = [0xF0, 0xE3, 0xC4, 0xFF];

        // 底 + 任务栏逐行填充（行主序，每行整行写，比逐像素快）。
        for y in 0..h {
            let row = (y * w * 4) as usize;
            let color = if y >= h - 48 { taskbar } else { bg };
            for x in 0..w {
                let p = row + (x * 4) as usize;
                self.buf[p..p + 4].copy_from_slice(&color);
            }
        }
        // 窗口 A（左中）、窗口 B（右下偏上）。
        self.fill_rect(w / 4, h / 4, w / 2, h / 3, win_a);
        self.fill_rect(w / 2 + w / 8, h / 3, w / 5, h / 5, win_b);
    }

    /// 填充矩形（越界裁剪）。
    fn fill_rect(&mut self, x: u32, y: u32, rw: u32, rh: u32, color: [u8; 4]) {
        let w = self.w;
        let h = self.h;
        for yy in y..y + rh {
            if yy >= h {
                break;
            }
            let row = (yy * w * 4) as usize;
            for xx in x..x + rw {
                if xx >= w {
                    break;
                }
                let p = row + (xx * 4) as usize;
                self.buf[p..p + 4].copy_from_slice(&color);
            }
        }
    }

    /// 光标：24×24 白色 + 2px 黑边（近似真实鼠标指针的纯色表达）。
    fn draw_cursor(&mut self, x: u32, y: u32) {
        self.fill_rect(x, y, 24, 24, [0x00, 0x00, 0x00, 0xFF]); // 黑边底
        self.fill_rect(x + 2, y + 2, 20, 20, [0xFF, 0xFF, 0xFF, 0xFF]); // 白芯
    }
}

// ════════════════════════════════════════════════════════════════
// BenchKernel — CPU 参考 tile-hash（P1B GPU 内核的记账替身）
// ════════════════════════════════════════════════════════════════

/// 运行期计数器（读回字节断言 / Tile-Hash 耗时，P1G 指标）。
#[derive(Debug, Clone, Default)]
struct KernelStats {
    /// 已度量帧数（热身帧后归零）。
    frames: u32,
    /// tile-hash 累计耗时（ms；CPU 参考实现实测）。
    hash_ms_total: f64,
    /// 累计读回字节（按决策分支记账：静态 0 / 微变 RLE / 大动索引）。
    readback_total: u64,
}

#[derive(Default)]
struct KernelInner {
    /// 上一帧各 tile 哈希（None = 首帧）。
    prev_hash: Option<Vec<u64>>,
    /// 当前帧 RGBA（bench 每帧喂入；tile-hash 与 RLE 记账的数据源）。
    current: Vec<u8>,
    /// 上一帧 RGBA（delta-RLE 记账：`kgpu_blit_tiles_rle` 对帧差压缩）。
    prev: Vec<u8>,
    stats: KernelStats,
}

/// `GpuKernel` 的 CPU 参考实现：采样 CRC32 + 均值（文档 T1.2 算法），
/// 逐 tile 与上一帧比对产出 [`DirtyTileMap`]，同时记读取回账本。
struct BenchKernel {
    w: u32,
    h: u32,
    tile_w: u32,
    tile_h: u32,
    inner: Arc<Mutex<KernelInner>>,
}

impl BenchKernel {
    fn new(w: u32, h: u32, tile_w: u32, tile_h: u32) -> Self {
        Self {
            w,
            h,
            tile_w,
            tile_h,
            inner: Arc::new(Mutex::new(KernelInner::default())),
        }
    }

    /// 单 tile 哈希：8×8 采样网格（步长 8px）逐字节 CRC32 + 均值混合。
    /// 与文档「采样点均值 + CRC32」一致；GPU 内核同算法在显存内完成。
    fn tile_hash_of(buf: &[u8], w: u32, h: u32, tw: u32, th: u32, tx: u32, ty: u32) -> u64 {
        let mut crc: u32 = 0xFFFF_FFFF;
        let mut sum: u32 = 0;
        let mut n: u32 = 0;
        let x0 = tx * tw;
        let y0 = ty * th;
        let x1 = (x0 + tw).min(w);
        let y1 = (y0 + th).min(h);
        let mut y = y0;
        while y < y1 {
            let mut x = x0;
            while x < x1 {
                let p = (y * w + x) as usize * 4;
                let v = (buf[p] as u32) << 16 | (buf[p + 1] as u32) << 8 | buf[p + 2] as u32;
                crc = CRC32_TABLE[((crc ^ v) & 0xFF) as usize] ^ (crc >> 8);
                crc = CRC32_TABLE[((crc ^ (v >> 8)) & 0xFF) as usize] ^ (crc >> 8);
                crc = CRC32_TABLE[((crc ^ (v >> 16)) & 0xFF) as usize] ^ (crc >> 8);
                sum += v;
                n += 1;
                x += 8;
            }
            y += 8;
        }
        ((crc as u64) << 32) | (if n == 0 { 0 } else { sum / n }) as u64
    }

    /// 读回记账（白名单策略，见模块注释）：
    /// - 无脏 tile → 0 字节（全静：diff 全程在显存内）
    /// - 微变（<5%）→ 脏 tile **帧差**（current ^ prev）的 RLE 压缩字节数
    ///   （与 blit_rle.cpp 一致：`[count:u8][value:u8]` 对差帧压缩——真实
    ///   鼠标移动场景差帧几乎全零，零长游程压到 2B/255B）
    /// - 大动（≥5%）→ dirty 索引（4B × 脏块数，≤ 几 KB）
    #[allow(clippy::too_many_arguments)]
    fn readback_bytes(
        map: &DirtyTileMap,
        current: &[u8],
        prev: &[u8],
        w: u32,
        h: u32,
        tile_w: u32,
        tile_h: u32,
    ) -> u64 {
        let indices = map.dirty_indices();
        if indices.is_empty() {
            return 0;
        }
        if map.dirty_ratio < 0.05 {
            // RLE：逐脏 tile 计算帧差并压缩，累加压缩后字节。
            let mut total: u64 = 0;
            let grid_w = map.grid_w.max(1);
            for idx in indices {
                let tx = idx % grid_w;
                let ty = idx / grid_w;
                let x0 = (tx * tile_w) as usize;
                let y0 = (ty * tile_h) as usize;
                let x1 = (x0 + tile_w as usize).min(w as usize);
                let y1 = (y0 + tile_h as usize).min(h as usize);
                if x1 <= x0 || y1 <= y0 {
                    continue;
                }
                // 逐行收集 tile 帧差（current ^ prev）到临时缓冲。
                let mut delta = Vec::with_capacity((x1 - x0) * (y1 - y0) * 4);
                for yy in y0..y1 {
                    let row = yy * w as usize;
                    let a = &current[(row + x0) * 4..(row + x1) * 4];
                    let b = prev.get((row + x0) * 4..(row + x1) * 4);
                    match b {
                        Some(b) if b.len() == a.len() => {
                            for (ca, cb) in a.iter().zip(b) {
                                delta.push(ca ^ cb);
                            }
                        }
                        // 无上一帧（首帧）→ 差 = 当前帧本身。
                        _ => delta.extend_from_slice(a),
                    }
                }
                if delta.is_empty() {
                    continue;
                }
                let mut comp = vec![0u8; delta.len().saturating_mul(2).max(2)];
                let n = rle_encode_rust(&delta, &mut comp);
                total += if n == 0 {
                    delta.len() as u64 // 压缩失败（容量）→ 按原始字节计（保守）
                } else {
                    n as u64
                };
            }
            total
        } else {
            // 大动：dirty 索引读回。
            indices.len() as u64 * 4
        }
    }
}

impl GpuKernel for BenchKernel {
    fn tile_hash(&self, _tex: &GpuTexture) -> Result<DirtyTileMap, EncodeError> {
        let t0 = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let grid_w = self.w.div_ceil(self.tile_w);
        let grid_h = self.h.div_ceil(self.tile_h);
        let total = (grid_w * grid_h) as usize;

        let cur = inner.current.clone(); // 快照（避免锁内长计算）
        if cur.is_empty() {
            return Err(EncodeError::InvalidConfig("BenchKernel: no frame fed".into()));
        }

        // 逐 tile 哈希（一次遍历同时产出 hashes + dirty map）。
        let mut hashes = Vec::with_capacity(total);
        let mut dirty = vec![false; total];
        for ty in 0..grid_h {
            for tx in 0..grid_w {
                let hash = Self::tile_hash_of(
                    &cur, self.w, self.h, self.tile_w, self.tile_h, tx, ty,
                );
                let idx = (ty * grid_w + tx) as usize;
                let changed = inner.prev_hash.as_ref().map_or(true, |pv| pv[idx] != hash);
                dirty[idx] = changed;
                hashes.push(hash);
            }
        }
        inner.prev_hash = Some(hashes);

        let mut map = DirtyTileMap {
            tile_w: self.tile_w,
            tile_h: self.tile_h,
            grid_w,
            grid_h,
            dirty,
            dirty_ratio: 0.0,
        };
        map.compute_ratio();

        // 读回记账（按决策政策）；随后 current 晋升为 prev。
        let readback = Self::readback_bytes(
            &map, &cur, &inner.prev, self.w, self.h, self.tile_w, self.tile_h,
        );
        inner.prev = cur;
        let s = &mut inner.stats;
        s.frames += 1;
        s.hash_ms_total += t0.elapsed().as_secs_f64() * 1000.0;
        s.readback_total += readback;

        Ok(map)
    }
}

// CRC32（IEEE 802.3，表驱动）。
const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}
static CRC32_TABLE: [u32; 256] = crc32_table();

// ════════════════════════════════════════════════════════════════
// CountingEncoder — encode() 调用计数包装（encoder_calls 指标）
// ════════════════════════════════════════════════════════════════

struct CountingEncoder {
    inner: Box<dyn VideoEncoder>,
    calls: Arc<AtomicU32>,
}

impl VideoEncoder for CountingEncoder {
    fn encode(
        &mut self,
        tex: &GpuTexture,
        ts: Timestamp,
        decision: EncodeDecision,
    ) -> Result<Vec<EncodedPacket>, EncodeError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.encode(tex, ts, decision)
    }
    fn codec(&self) -> Codec {
        self.inner.codec()
    }
    fn is_hardware(&self) -> bool {
        self.inner.is_hardware()
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn reconfigure(&mut self, cfg: &kirin_desk_media::proto::EncodeConfig) -> Result<(), EncodeError> {
        self.inner.reconfigure(cfg)
    }
    fn set_cpu_frame(&mut self, rgba: &[u8], w: u32, h: u32, force_idr: bool) {
        self.inner.set_cpu_frame(rgba, w, h, force_idr);
    }
}

// ════════════════════════════════════════════════════════════════
// 结果与断言
// ════════════════════════════════════════════════════════════════

/// 单场景基准结果（字段与 P1G 文档 `BenchResult` 一一对应）。
#[derive(Debug, Clone)]
struct BenchResult {
    scene: &'static str,
    frames: u32,
    fps: f32,
    encoder_calls: u32,
    packets: u32,
    bytes_total: u64,
    avg_bitrate_kbps: f32,
    avg_readback_bytes: f32,
    tile_hash_ms_avg: f32,
    /// 单帧最大输出字节（微变分支 ≤16KB 判定）。
    max_packet_bytes: u32,
}

#[derive(Debug, Clone)]
enum Verdict {
    Pass,
    Fail(String),
    Skip(String),
}

impl Verdict {
    fn is_fail(&self) -> bool {
        matches!(self, Verdict::Fail(_))
    }
}

/// 名义帧率（码率折算用；30fps = 远程桌面典型帧率）。
const NOMINAL_FPS: f32 = 30.0;

fn run_scene(
    kind: SceneKind,
    args: &Args,
) -> Result<(BenchResult, String, bool), String> {
    let w = args.w;
    let h = args.h;
    let frames = args.frames;

    // 编码器：默认回退链；--prefer-hw 先试硬编（nvenc 等）。
    let inner: Box<dyn VideoEncoder> = if args.prefer_hw {
        match FfmpegHwEncoder::create(args.codec, None) {
            Ok(e) => Box::new(e),
            Err(e) => {
                eprintln!("[warn] --prefer-hw: 硬件编码器不可用（{e}），回退软编");
                factory::create_video_encoder(args.codec, None)
                    .map_err(|e| format!("编码器创建失败: {e}"))?
            }
        }
    } else {
        factory::create_video_encoder(args.codec, None)
            .map_err(|e| format!("编码器创建失败: {e}"))?
    };

    let calls = Arc::new(AtomicU32::new(0));
    let kernel = BenchKernel::new(w, h, 64, 64);
    let kernel_handle = kernel.inner.clone();
    let mut pipe = VideoEncoderPipeline::from_parts(
        Some(Box::new(kernel)),
        Box::new(CountingEncoder { inner, calls: calls.clone() }),
    )
    .map_err(|e| format!("pipeline 初始化失败: {e}"))?;
    let enc_name = pipe.name().to_string();
    let is_hw = pipe.is_hardware();

    let mut scene = SceneGen::new(kind, w, h);
    let tex = GpuTexture::new(0x1usize as *mut _, w, h);

    // 热身帧（首帧强制 FullFrame 建 prev_hash；不计入任何指标）。
    let warm = scene.frame(0);
    kernel_handle.lock().unwrap().current = warm.to_vec();
    pipe.set_cpu_frame(warm, w, h, true);
    pipe.on_frame(&tex, ts(0)).map_err(|e| format!("热身帧失败: {e}"))?;
    calls.store(0, Ordering::Relaxed);
    kernel_handle.lock().unwrap().stats = KernelStats::default();

    // 稳态度量。
    let t0 = Instant::now();
    let mut packets_total = 0u32;
    let mut bytes_total = 0u64;
    let mut max_packet_bytes = 0u32;
    for i in 1..=frames {
        let rgba = scene.frame(i);
        kernel_handle.lock().unwrap().current = rgba.to_vec();
        pipe.set_cpu_frame(rgba, w, h, false);
        let packets = pipe
            .on_frame(&tex, ts(i))
            .map_err(|e| format!("第 {i} 帧失败: {e}"))?;
        packets_total += packets.len() as u32;
        let frame_bytes: u64 = packets.iter().map(|p| p.data.len() as u64).sum();
        bytes_total += frame_bytes;
        max_packet_bytes = max_packet_bytes.max(frame_bytes as u32);
    }
    let elapsed = t0.elapsed().as_secs_f64();
    let fps = if elapsed > 0.0 { frames as f32 / elapsed as f32 } else { 0.0 };

    let stats = kernel_handle.lock().unwrap().stats.clone();
    let avg_readback = if stats.frames > 0 {
        stats.readback_total as f32 / stats.frames as f32
    } else {
        0.0
    };
    let tile_hash_ms = if stats.frames > 0 {
        stats.hash_ms_total as f32 / stats.frames as f32
    } else {
        0.0
    };
    // 码率按名义 30fps 折算（与实际处理速率解耦）。
    let bitrate = if frames > 0 {
        bytes_total as f32 * 8.0 / (frames as f32 / NOMINAL_FPS) / 1000.0
    } else {
        0.0
    };

    let scene_name = match kind {
        SceneKind::Static => "static",
        SceneKind::Incremental => "incremental",
        SceneKind::FullFrame => "fullframe",
    };
    Ok((
        BenchResult {
            scene: scene_name,
            frames,
            fps,
            encoder_calls: calls.load(Ordering::Relaxed),
            packets: packets_total,
            bytes_total,
            avg_bitrate_kbps: bitrate,
            avg_readback_bytes: avg_readback,
            tile_hash_ms_avg: tile_hash_ms,
            max_packet_bytes,
        },
        enc_name,
        is_hw,
    ))
}

/// 场景阈值断言（P1G 通过条件表）。
fn checks_for(
    kind: SceneKind,
    r: &BenchResult,
    args: &Args,
    is_hw: bool,
) -> Vec<(&'static str, Verdict)> {
    match kind {
        SceneKind::Static => vec![
            ("全静 编码器调用 == 0", if r.encoder_calls == 0 { Verdict::Pass } else { Verdict::Fail(format!("实际 {}", r.encoder_calls)) }),
            ("全静 输出包 == 0", if r.packets == 0 { Verdict::Pass } else { Verdict::Fail(format!("实际 {}", r.packets)) }),
            ("全静 读回 == 0", if r.avg_readback_bytes == 0.0 { Verdict::Pass } else { Verdict::Fail(format!("实际 {:.1} B/帧", r.avg_readback_bytes)) }),
        ],
        SceneKind::Incremental => {
            // 5% 阈值需要足够 tile 粒度：<100 tile 时 5% 不足 5 个 tile，
            // 任何可见内容（光标/闪烁）都会超阈值 → 记 SKIP（非失败）。
            let grid_tiles = (args.w.div_ceil(64) * args.h.div_ceil(64)) as u32;
            if grid_tiles < 100 {
                return vec![(
                    "微变 场景粒度",
                    Verdict::Skip(format!(
                        "分辨率 {}x{} 网格仅 {grid_tiles} tile，<5% 粒度不可表达（建议 ≥1024x768）",
                        args.w, args.h
                    )),
                )];
            }
            vec![
                ("微变 编码器调用 == 0", if r.encoder_calls == 0 { Verdict::Pass } else { Verdict::Fail(format!("实际 {}", r.encoder_calls)) }),
                ("微变 读回 ≤ 16KB/帧", if r.avg_readback_bytes <= 16.0 * 1024.0 { Verdict::Pass } else { Verdict::Fail(format!("实际 {:.1} B/帧", r.avg_readback_bytes)) }),
                ("微变 增量包 ≤ 16KB/帧", if r.max_packet_bytes <= 16 * 1024 { Verdict::Pass } else { Verdict::Fail(format!("实际 {:.1} KB", r.max_packet_bytes as f32 / 1024.0)) }),
            ]
        }
        SceneKind::FullFrame => {
            let mut checks = vec![];
            // 编码器调用断言：HW 口径（"编码器调用 = 帧数"要求编码速度 ≥
            // 供给速度；软编 1080p 全屏 <30fps 时 EAGAIN 吸收是 backpressure
            // 正常行为，记录交付率）。
            if is_hw {
                checks.push((
                    "大动 编码器调用 == 帧数",
                    if r.encoder_calls == r.frames {
                        Verdict::Pass
                    } else {
                        Verdict::Fail(format!("实际 {} / {}", r.encoder_calls, r.frames))
                    },
                ));
            } else {
                checks.push((
                    "大动 编码器调用 == 帧数（HW 口径）",
                    Verdict::Skip(format!(
                        "软编回退：{}/{} 帧进入编码器（其余被 EAGAIN backpressure 吸收，交付率 {:.0}%）",
                        r.encoder_calls,
                        r.frames,
                        r.encoder_calls as f32 / r.frames as f32 * 100.0
                    )),
                ));
            }
            // 帧率阈值按文档口径只对硬件编码器强制（"≥25fps @1080p（硬件
            // 编码器）"）；软编回退（libx264）记录实测值，不判失败。
            if is_hw {
                checks.push((
                    "大动 帧率 ≥ 25fps @1080p",
                    if r.fps >= 25.0 {
                        Verdict::Pass
                    } else {
                        Verdict::Fail(format!("实际 {:.1} fps", r.fps))
                    },
                ));
            } else {
                checks.push((
                    "大动 帧率 ≥ 25fps @1080p（HW 口径）",
                    Verdict::Skip(format!(
                        "软编回退（非 HW 目标路径）→ 记录实测 {:.1} fps",
                        r.fps
                    )),
                ));
            }
            // 码率 CBR ±20%（自适应反馈 T014 可调；--target-bitrate-kbps 0 = 跳过）。
            if args.target_kbps > 0 {
                let dev = (r.avg_bitrate_kbps - args.target_kbps as f32).abs() / args.target_kbps as f32;
                if dev <= 0.20 {
                    checks.push(("大动 码率 ±20% CBR", Verdict::Pass));
                } else {
                    checks.push(("大动 码率 ±20% CBR", Verdict::Fail(format!("目标 {} kbps，实际 {:.0} kbps（偏差 {:.0}%）", args.target_kbps, r.avg_bitrate_kbps, dev * 100.0))));
                }
            }
            // Tile-Hash：GPU <2ms 仅在真实内核可链接时成立；本机（无 cmake /
            // feature off）记 SKIP 并输出 CPU 回退基线。
            if KgpuLinked::LINKED {
                checks.push(("Tile-Hash GPU < 2ms", Verdict::Skip("GPU 内核已链接，但合成帧无真实纹理，需 capture 集成后实测".into())));
            } else {
                checks.push(("Tile-Hash GPU < 2ms（CPU 回退基线）", Verdict::Skip(format!("GPU 内核未链接（cmake/feature off）→ 仅记录 CPU 回退 {:.2} ms/帧", r.tile_hash_ms_avg))));
            }
            checks
        }
    }
}

// ════════════════════════════════════════════════════════════════
// T7.3: ROI 生效验证（带 side data vs 不带，同帧对比）
// ════════════════════════════════════════════════════════════════

struct RoiReport {
    encoder: String,
    is_hardware: bool,
    frames: u32,
    bytes_with_roi: u64,
    bytes_without_roi: u64,
    delta_pct: f32,
    verdict: Verdict,
}

/// 中心区域 dirty map（变化区 = 中 40% × 40%）。
fn center_dirty_map(w: u32, h: u32, tile_w: u32, tile_h: u32) -> DirtyTileMap {
    let grid_w = w.div_ceil(tile_w);
    let grid_h = h.div_ceil(tile_h);
    let x0 = grid_w / 3;
    let x1 = grid_w * 2 / 3;
    let y0 = grid_h / 3;
    let y1 = grid_h * 2 / 3;
    let mut dirty = vec![false; (grid_w * grid_h) as usize];
    for ty in y0..y1 {
        for tx in x0..x1 {
            dirty[(ty * grid_w + tx) as usize] = true;
        }
    }
    let mut map = DirtyTileMap {
        tile_w,
        tile_h,
        grid_w,
        grid_h,
        dirty,
        dirty_ratio: 0.0,
    };
    map.compute_ratio();
    map
}

/// 同帧内容 × 两次编码：带 ROI side data（中心变化区 map）vs 不带（空 map）。
/// 输出码流总大小对比：ROI 后应更优或持平。
fn roi_ab_compare(args: &Args) -> Result<RoiReport, String> {
    let w = args.w;
    let h = args.h;
    let frames = args.frames.min(60).max(10); // ROI 对比用 ≤60 帧足够。

    let create_enc = || -> Result<Box<dyn VideoEncoder>, String> {
        if args.prefer_hw {
            match FfmpegHwEncoder::create(args.codec, None) {
                Ok(e) => return Ok(Box::new(e)),
                Err(e) => eprintln!("[warn] --prefer-hw: 硬件编码器不可用（{e}），回退软编"),
            }
        }
        factory::create_video_encoder(args.codec, None).map_err(|e| format!("编码器创建失败: {e}"))
    };

    let tex = GpuTexture::new(0x1usize as *mut _, w, h);
    let roi_map = center_dirty_map(w, h, 64, 64);
    let mut scene_a = SceneGen::new(SceneKind::FullFrame, w, h);

    // Pass A：带 ROI。
    let mut enc = create_enc()?;
    let encoder_name = enc.name().to_string();
    let is_hw = enc.is_hardware();
    let mut bytes_with_roi = 0u64;
    for i in 0..frames {
        let rgba = scene_a.frame(i);
        enc.set_cpu_frame(rgba, w, h, i == 0);
        let packets = enc
            .encode(&tex, ts(i), EncodeDecision::FullFrame(roi_map.clone()))
            .map_err(|e| format!("ROI pass A 第 {i} 帧: {e}"))?;
        bytes_with_roi += packets.iter().map(|p| p.data.len() as u64).sum::<u64>();
    }
    drop(enc);

    // Pass B：不带 ROI（空 map → 编码器无 side data）。
    let mut enc = create_enc()?;
    let mut scene_b = SceneGen::new(SceneKind::FullFrame, w, h);
    let mut bytes_without_roi = 0u64;
    for i in 0..frames {
        let rgba = scene_b.frame(i);
        enc.set_cpu_frame(rgba, w, h, i == 0);
        let packets = enc
            .encode(&tex, ts(i), EncodeDecision::FullFrame(DirtyTileMap::default()))
            .map_err(|e| format!("ROI pass B 第 {i} 帧: {e}"))?;
        bytes_without_roi += packets.iter().map(|p| p.data.len() as u64).sum::<u64>();
    }

    let delta_pct = if bytes_without_roi > 0 {
        (bytes_with_roi as f32 - bytes_without_roi as f32) / bytes_without_roi as f32 * 100.0
    } else {
        0.0
    };

    // 判定（P1G T7.3）：nvenc 等硬件平台必测（ROI 应更优或持平）；
    // 软编（libx264）记录支持情况，不判定失败；hw 编码器在 CPU 输入路径
    // 未产出包（需 P1B 零拷贝桥）→ 记录跳过。
    let verdict = if bytes_with_roi == 0 && bytes_without_roi == 0 {
        Verdict::Skip(format!("{encoder_name}: CPU 输入路径未产出包（需 P1B kgpu_hw_upload 零拷贝桥），ROI 验证待接入后实测"))
    } else if is_hw {
        if delta_pct <= 5.0 {
            Verdict::Pass
        } else {
            Verdict::Fail(format!("ROI 后码流增大约 {:.1}%（期望 ≤5% 持平）", delta_pct))
        }
    } else {
        Verdict::Skip(format!("{encoder_name}（软编回退）：记录支持情况，非判定平台（nvenc/vaapi/videotoolbox 必测）"))
    };

    Ok(RoiReport {
        encoder: encoder_name,
        is_hardware: is_hw,
        frames,
        bytes_with_roi,
        bytes_without_roi,
        delta_pct,
        verdict,
    })
}

fn ts(pts_ms: u32) -> Timestamp {
    Timestamp::new(Instant::now(), pts_ms as u64)
}

// ════════════════════════════════════════════════════════════════
// 输出
// ════════════════════════════════════════════════════════════════

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("参数错误: {e}");
            print_usage();
            std::process::exit(2);
        }
    };
    if let Err(e) = kirin_desk_media::ffmpeg::ensure_loaded() {
        eprintln!("FFmpeg DLL 不可用: {e}\n（部署目录 release/ffmpeg/bin 或 PATH 需含 avcodec-62/avutil-60/swscale-9）");
        std::process::exit(2);
    }

    let scenes: Vec<SceneKind> = match args.scene {
        SceneSel::All => vec![SceneKind::Static, SceneKind::Incremental, SceneKind::FullFrame],
        SceneSel::Static => vec![SceneKind::Static],
        SceneSel::Incremental => vec![SceneKind::Incremental],
        SceneSel::FullFrame => vec![SceneKind::FullFrame],
    };

    let mut results: Vec<(BenchResult, String, bool)> = Vec::new();
    let mut all_checks: Vec<(String, String, Verdict)> = Vec::new();
    let mut roi_report: Option<RoiReport> = None;

    for kind in &scenes {
        let (r, enc_name, is_hw) = match run_scene(*kind, &args) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("场景 {:?} 运行失败: {e}", kind);
                std::process::exit(2);
            }
        };
        let checks = checks_for(*kind, &r, &args, is_hw);
        all_checks.extend(
            checks
                .into_iter()
                .map(|(label, v)| (r.scene.to_string(), label.to_string(), v)),
        );
        results.push((r, enc_name, is_hw));
    }

    // ROI 对比（T7.3）。
    if args.scene != SceneSel::Static {
        match roi_ab_compare(&args) {
            Ok(rep) => roi_report = Some(rep),
            Err(e) => {
                eprintln!("ROI 对比失败: {e}");
                std::process::exit(2);
            }
        }
    }

    let any_fail = all_checks.iter().any(|(_, _, v)| v.is_fail())
        || roi_report.as_ref().map(|r| r.verdict.is_fail()).unwrap_or(false);

    if args.json {
        print_json(&args, &results, &roi_report, &all_checks);
    } else {
        print_table(&args, &results, &roi_report, &all_checks);
    }

    std::process::exit(if any_fail { 1 } else { 0 });
}

fn print_table(
    args: &Args,
    results: &[(BenchResult, String, bool)],
    roi: &Option<RoiReport>,
    checks: &[(String, String, Verdict)],
) {
    println!("=== codec_bench · 编码层三场景基准（P1G T7.1） ===");
    println!(
        "参数: scene={:?} frames={} res={}x{} codec={:?} target={}kbps prefer_hw={}",
        args.scene, args.frames, args.w, args.h, args.codec, args.target_kbps, args.prefer_hw
    );
    println!("GPU 内核链接: {}（{}）", KgpuLinked::LINKED, if KgpuLinked::LINKED { "真实 kgpu_* 可用" } else { "CPU 参考 tile-hash 回退" });
    println!();
    println!(
        "{:<12} {:>6} {:>8} {:>12} {:>8} {:>10} {:>12} {:>14} {:>10}",
        "场景", "帧数", "fps", "编码器调用", "包数", "总字节", "码率kbps", "读回B/帧", "tilehash ms"
    );
    for (r, enc_name, is_hw) in results {
        println!(
            "{:<12} {:>6} {:>8.1} {:>12} {:>8} {:>10} {:>12.0} {:>14.1} {:>10.2}   [{} {}]",
            r.scene,
            r.frames,
            r.fps,
            r.encoder_calls,
            r.packets,
            r.bytes_total,
            r.avg_bitrate_kbps,
            r.avg_readback_bytes,
            r.tile_hash_ms_avg,
            if *is_hw { "HW" } else { "SW" },
            enc_name,
        );
    }
    println!();
    println!("--- 阈值断言（P1G 通过条件） ---");
    for (scene, label, v) in checks {
        match v {
            Verdict::Pass => println!("  [PASS] {scene} · {label}"),
            Verdict::Fail(msg) => println!("  [FAIL] {scene} · {label} — {msg}"),
            Verdict::Skip(msg) => println!("  [SKIP] {scene} · {label} — {msg}"),
        }
    }
    if let Some(r) = roi {
        println!();
        println!("--- ROI 生效验证（T7.3，同帧 A/B） ---");
        println!(
            "  编码器: {}（{}）· {} 帧",
            r.encoder,
            if r.is_hardware { "HW" } else { "SW" },
            r.frames
        );
        println!(
            "  带 ROI: {} 字节 / 不带: {} 字节 → 差异 {}{:+.1}%",
            r.bytes_with_roi,
            r.bytes_without_roi,
            if r.delta_pct >= 0.0 { "+" } else { "" },
            r.delta_pct
        );
        match &r.verdict {
            Verdict::Pass => println!("  [PASS] ROI 生效（码流更优或持平）"),
            Verdict::Fail(msg) => println!("  [FAIL] {msg}"),
            Verdict::Skip(msg) => println!("  [SKIP] {msg}"),
        }
    }
    let n_fail = checks.iter().filter(|(_, _, v)| v.is_fail()).count()
        + if roi.as_ref().map(|r| r.verdict.is_fail()).unwrap_or(false) { 1 } else { 0 };
    println!();
    if n_fail == 0 {
        println!("结果: 全部阈值通过 ✓");
    } else {
        println!("结果: {n_fail} 项 FAIL ✗");
    }
}

fn print_json(
    _args: &Args,
    results: &[(BenchResult, String, bool)],
    roi: &Option<RoiReport>,
    checks: &[(String, String, Verdict)],
) {
    // 手写 JSON（字段全是 ASCII 数值/短标识，无需序列化依赖）。
    println!("{{");
    println!("  \"scenarios\": {{");
    let mut first = true;
    for (r, enc_name, is_hw) in results {
        println!(
            "{}  \"{}\": {{\"encoder\":\"{}\",\"hw\":{},\"frames\":{},\"fps\":{:.2},\"encoder_calls\":{},\"packets\":{},\"bytes_total\":{},\"avg_bitrate_kbps\":{:.1},\"avg_readback_bytes\":{:.1},\"tile_hash_ms_avg\":{:.2},\"max_packet_bytes\":{}}}",
            if first { "  " } else { "  ," },
            r.scene,
            enc_name,
            is_hw,
            r.frames,
            r.fps,
            r.encoder_calls,
            r.packets,
            r.bytes_total,
            r.avg_bitrate_kbps,
            r.avg_readback_bytes,
            r.tile_hash_ms_avg,
            r.max_packet_bytes,
        );
        first = false;
    }
    println!("  }},");
    println!("  \"gpu_linked\": {},", KgpuLinked::LINKED);
    println!("  \"checks\": [");
    let mut first = true;
    for (scene, label, v) in checks {
        let (status, msg) = match v {
            Verdict::Pass => ("PASS", String::new()),
            Verdict::Fail(m) => ("FAIL", m.clone()),
            Verdict::Skip(m) => ("SKIP", m.clone()),
        };
        println!(
            "{}  {{\"scene\":\"{}\",\"label\":\"{}\",\"status\":\"{}\",\"msg\":\"{}\"}}",
            if first { "  " } else { "  ," },
            scene,
            label,
            status,
            msg.replace('"', "'"),
        );
        first = false;
    }
    println!("  ],");
    match roi {
        Some(r) => {
            let (status, msg) = match &r.verdict {
                Verdict::Pass => ("PASS", String::new()),
                Verdict::Fail(m) => ("FAIL", m.clone()),
                Verdict::Skip(m) => ("SKIP", m.clone()),
            };
            println!(
                "  \"roi\": {{\"encoder\":\"{}\",\"hw\":{},\"frames\":{},\"bytes_with_roi\":{},\"bytes_without_roi\":{},\"delta_pct\":{:.2},\"status\":\"{}\",\"msg\":\"{}\"}}",
                r.encoder,
                r.is_hardware,
                r.frames,
                r.bytes_with_roi,
                r.bytes_without_roi,
                r.delta_pct,
                status,
                msg.replace('"', "'"),
            );
        }
        None => println!("  \"roi\": null"),
    }
    println!("}}");
}

// ════════════════════════════════════════════════════════════════
// Tests（纯逻辑：场景 dirty 率 / RLE 读回上限 / CLI / 中心 map）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 用 BenchKernel 的参考哈希统计相邻两帧的 dirty 比率。
    fn dirty_ratio_between(kind: SceneKind, w: u32, h: u32, idx: u32) -> f32 {
        let mut scene = SceneGen::new(kind, w, h);
        let mut kernel = BenchKernel::new(w, h, 64, 64);
        let handle = kernel.inner.clone();
        handle.lock().unwrap().current = scene.frame(0).to_vec();
        let first = kernel.tile_hash(&GpuTexture::new(0x1usize as *mut _, w, h)).unwrap();
        assert!(first.dirty_ratio > 0.0, "首帧应全脏（建 prev_hash）");
        handle.lock().unwrap().current = scene.frame(idx).to_vec();
        let map = kernel.tile_hash(&GpuTexture::new(0x1usize as *mut _, w, h)).unwrap();
        map.dirty_ratio
    }

    #[test]
    fn test_static_scene_zero_dirty() {
        let r = dirty_ratio_between(SceneKind::Static, 1920, 1080, 50);
        assert_eq!(r, 0.0, "全静场景相邻帧不应有脏 tile");
    }

    #[test]
    fn test_incremental_scene_dirty_below_5pct() {
        let r = dirty_ratio_between(SceneKind::Incremental, 1920, 1080, 100);
        assert!(r > 0.0, "微变场景应有脏 tile");
        assert!(r < 0.05, "微变场景 dirty 必须 <5%（实际 {:.2}%）", r * 100.0);
    }

    #[test]
    fn test_fullframe_scene_all_dirty() {
        // idx=1：s=5, s/4=1（奇数）vs frame(0) s/4=0 → 棋盘相位翻转，
        // 每 tile 必脏（注意 idx=5 时 s/4=6 为偶数 → 相位不变 → 不脏）。
        let r = dirty_ratio_between(SceneKind::FullFrame, 1920, 1080, 1);
        assert!(r >= 0.99, "大动场景应接近全脏（实际 {:.2}%）", r * 100.0);
    }

    /// 微变场景的 RLE 读回记账必须 ≤ 16KB（白名单上限）。
    /// 口径 = 内核统计：脏 tile 帧差（current^prev）的 RLE 压缩字节。
    #[test]
    fn test_incremental_readback_within_16kb() {
        // 先验证 rle_encode_rust 本身：纯色块应压到 ~130 字节。
        let flat = vec![0xE6u8; 16384];
        let mut comp = vec![0u8; 32768];
        let n = rle_encode_rust(&flat, &mut comp);
        assert!(n < 1024, "纯色块 RLE 应强烈压缩，实际 n={n}");

        let w = 1920u32;
        let h = 1080u32;
        let mut scene = SceneGen::new(SceneKind::Incremental, w, h);
        let kernel = BenchKernel::new(w, h, 64, 64);
        let handle = kernel.inner.clone();
        handle.lock().unwrap().current = scene.frame(0).to_vec();
        let _ = kernel.tile_hash(&GpuTexture::new(0x1usize as *mut _, w, h)).unwrap();
        for idx in 1..10 {
            handle.lock().unwrap().current = scene.frame(idx).to_vec();
            let map = kernel.tile_hash(&GpuTexture::new(0x1usize as *mut _, w, h)).unwrap();
            let stats = handle.lock().unwrap().stats.clone();
            let rb = stats.readback_total / stats.frames.max(1) as u64;
            eprintln!(
                "frame {idx}: dirty={} ratio={:.4} rb_avg={rb} B",
                map.dirty_indices().len(),
                map.dirty_ratio
            );
            assert!(rb <= 16 * 1024, "帧 {idx} 读回 {rb} B 超过 16KB");
        }
    }

    #[test]
    fn test_center_dirty_map_shape() {
        let m = center_dirty_map(1920, 1080, 64, 64);
        assert_eq!(m.grid_w, 30);
        assert_eq!(m.grid_h, 17);
        assert!(m.dirty_ratio > 0.0 && m.dirty_ratio < 1.0);
        // 中 1/3~2/3 → 约 1/9 面积。
        assert!((m.dirty_ratio - 1.0 / 9.0).abs() < 0.05, "ratio={}", m.dirty_ratio);
    }

    #[test]
    fn test_crc32_table_sanity() {
        // CRC32("123456789") = 0xCBF43926（IEEE 参考向量）。
        let mut crc: u32 = 0xFFFF_FFFF;
        for b in b"123456789" {
            crc = CRC32_TABLE[((crc ^ *b as u32) & 0xFF) as usize] ^ (crc >> 8);
        }
        assert_eq!(crc ^ 0xFFFF_FFFF, 0xCBF4_3926);
    }

    #[test]
    fn test_parse_args_resolution() {
        // 直接调内部解析不可行（读 env），验证核心解析函数逻辑：
        // 构造 args 结构体检查默认值（覆盖 main 的参数路径由手动测试验证）。
        let a = Args::default();
        assert_eq!(a.frames, 300);
        assert_eq!((a.w, a.h), (1920, 1080));
        assert_eq!(a.target_kbps, 2000);
    }

    /// 判别性测试：直连软编喂两帧完全不同的内容，P 帧不应是 skip。
    /// 若此测试失败 → FfmpegSwEncoder 链路问题；若通过 → bench 喂帧问题。
    #[test]
    fn test_sw_encoder_sees_frame_differences() {
        if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let Ok(mut enc) = kirin_desk_media::encoder::FfmpegSwEncoder::create(Codec::H264) else {
            return;
        };
        let (w, h) = (320u32, 240u32);
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let frame_a = vec![10u8; (w * h * 4) as usize];
        let frame_b = vec![200u8; (w * h * 4) as usize];
        enc.set_cpu_frame(&frame_a, w, h, true);
        let p1 = enc
            .encode(&tex, ts(0), EncodeDecision::FullFrame(DirtyTileMap::default()))
            .unwrap();
        let s1: usize = p1.iter().map(|p| p.data.len()).sum();
        enc.set_cpu_frame(&frame_b, w, h, false);
        let p2 = enc
            .encode(&tex, ts(16), EncodeDecision::FullFrame(DirtyTileMap::default()))
            .unwrap();
        let s2: usize = p2.iter().map(|p| p.data.len()).sum();
        eprintln!("frame A bytes={s1}, frame B bytes={s2}");
        assert!(s2 > 200, "完全不同帧的 P 帧不应是 skip（s2={s2}）");
    }

    /// 判别性测试 2：SceneGen::FullFrame 连续帧喂直连编码器，逐帧大小。
    /// 若 P 帧全 ~26B → 场景内容在编码链路上没有变化。
    #[test]
    fn test_scene_fullframe_encoder_sees_change() {
        if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let (w, h) = (320u32, 240u32);
        let mut scene = SceneGen::new(SceneKind::FullFrame, w, h);
        let Ok(mut enc) = kirin_desk_media::encoder::FfmpegSwEncoder::create(Codec::H264) else {
            return;
        };
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let mut sizes = Vec::new();
        for i in 0..6 {
            let rgba = scene.frame(i);
            enc.set_cpu_frame(rgba, w, h, i == 0);
            let pk = enc
                .encode(&tex, ts(i * 16), EncodeDecision::FullFrame(DirtyTileMap::default()))
                .unwrap();
            sizes.push(pk.iter().map(|p| p.data.len()).sum::<usize>());
        }
        eprintln!("scene fullframe(320x240) 帧大小序列: {sizes:?}");
        // 首帧 I + 后续帧：若所有帧 ~6857/26 模式 → 内容没变化。
        assert!(sizes[1] > 200, "第 2 帧不应是 skip（{sizes:?}）");
    }

    /// 判别性测试 2b：1080p 复现（怀疑分辨率相关）。
    #[test]
    fn test_scene_fullframe_1080p_encoder_sees_change() {
        if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let (w, h) = (1920u32, 1080u32);
        let mut scene = SceneGen::new(SceneKind::FullFrame, w, h);
        let Ok(mut enc) = kirin_desk_media::encoder::FfmpegSwEncoder::create(Codec::H264) else {
            return;
        };
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let mut sizes = Vec::new();
        for i in 0..4 {
            let rgba = scene.frame(i);
            enc.set_cpu_frame(rgba, w, h, i == 0);
            let pk = enc
                .encode(&tex, ts(i * 16), EncodeDecision::FullFrame(DirtyTileMap::default()))
                .unwrap();
            sizes.push(pk.iter().map(|p| p.data.len()).sum::<usize>());
        }
        eprintln!("scene fullframe(1080p, 噪声±24) 帧大小序列: {sizes:?}");
        assert!(sizes[1] > 200, "1080p 第 2 帧不应是 skip（{sizes:?}）");
    }

    /// 判别性测试 2c：1080p + 强噪声（±100）——隔离 sws 丢内容 vs 量化吞残差。
    #[test]
    fn test_scene_fullframe_1080p_loud_noise() {
        if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let (w, h) = (1920u32, 1080u32);
        let mut scene = SceneGen::new(SceneKind::FullFrame, w, h);
        let Ok(mut enc) = kirin_desk_media::encoder::FfmpegSwEncoder::create(Codec::H264) else {
            return;
        };
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let mut sizes = Vec::new();
        for i in 0..4 {
            let mut rgba = scene.frame(i).to_vec();
            // 强噪声覆盖（±100）：若 sws 正常，P 帧必然巨大。
            for px in rgba.chunks_exact_mut(4) {
                let n = ((i as usize * 7919 + px[0] as usize * 31) % 201) as u8;
                px[0] = px[0].wrapping_add(n);
                px[1] = px[1].wrapping_add(n.wrapping_mul(2) & 0xC7);
            }
            enc.set_cpu_frame(&rgba, w, h, i == 0);
            let pk = enc
                .encode(&tex, ts(i * 16), EncodeDecision::FullFrame(DirtyTileMap::default()))
                .unwrap();
            sizes.push(pk.iter().map(|p| p.data.len()).sum::<usize>());
        }
        eprintln!("scene fullframe(1080p, 噪声±100) 帧大小序列: {sizes:?}");
        assert!(sizes[1] > 1000, "强噪声 1080p 第 2 帧不应是 skip（{sizes:?}）");
    }

    /// 判别性测试 4：编码→解码回环，验证编码器收到的内容是否真的变化。
    /// 若解码出的相邻帧相同 → 编码链路丢内容；若不同 → 场景/统计问题。
    #[test]
    fn test_encode_decode_loopback_content_changes() {
        if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let (w, h) = (320u32, 240u32);
        let mut scene = SceneGen::new(SceneKind::FullFrame, w, h);
        let Ok(mut enc) = kirin_desk_media::encoder::FfmpegSwEncoder::create(Codec::H264) else {
            return;
        };
        let Ok(mut dec) = kirin_desk_media::decoder::factory::create_video_decoder(Codec::H264)
        else {
            eprintln!("解码器不可用，跳过");
            return;
        };
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let mut decoded_frames: Vec<Vec<u8>> = Vec::new();
        for i in 0..4 {
            let rgba = scene.frame(i);
            enc.set_cpu_frame(rgba, w, h, i == 0);
            let pk = enc
                .encode(&tex, ts(i * 16), EncodeDecision::FullFrame(DirtyTileMap::default()))
                .unwrap();
            for p in &pk {
                let pkt = kirin_desk_media::decoder::DecoderPacket {
                    pts: p.ts.pts,
                    data: p.data.clone(),
                    is_key: p.is_key,
                    extradata: None,
                };
                if let Ok(frames) = dec.decode(&pkt) {
                    for df in frames {
                        decoded_frames.push(df.rgba);
                    }
                }
            }
        }
        eprintln!("解码帧数: {}", decoded_frames.len());
        if decoded_frames.len() >= 2 {
            let d = decoded_frames[0]
                .iter()
                .zip(&decoded_frames[1])
                .filter(|(a, b)| a != b)
                .count();
            eprintln!("解码帧 0 vs 1 差异: {d} 字节（总 {}）", decoded_frames[0].len());
            assert!(d > 1000, "解码帧应明显不同（d={d}）");
        }
    }

    /// 判别性测试 6：1080p 编码→解码回环，验证编码器输入是否被抹平。
    #[test]
    fn test_encode_decode_1080p_content() {
        if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let (w, h) = (1920u32, 1080u32);
        let mut scene = SceneGen::new(SceneKind::FullFrame, w, h);
        let Ok(mut enc) = kirin_desk_media::encoder::FfmpegSwEncoder::create(Codec::H264) else {
            return;
        };
        let Ok(mut dec) = kirin_desk_media::decoder::factory::create_video_decoder(Codec::H264)
        else {
            eprintln!("解码器不可用，跳过");
            return;
        };
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let mut decoded: Vec<Vec<u8>> = Vec::new();
        for i in 0..3 {
            let rgba = scene.frame(i);
            enc.set_cpu_frame(rgba, w, h, i == 0);
            let pk = enc
                .encode(&tex, ts(i * 16), EncodeDecision::FullFrame(DirtyTileMap::default()))
                .unwrap();
            for p in &pk {
                let pkt = kirin_desk_media::decoder::DecoderPacket {
                    pts: p.ts.pts,
                    data: p.data.clone(),
                    is_key: p.is_key,
                    extradata: None,
                };
                if let Ok(frames) = dec.decode(&pkt) {
                    for df in frames {
                        decoded.push(df.rgba);
                    }
                }
            }
        }
        eprintln!("1080p 解码帧数: {}", decoded.len());
        if decoded.len() >= 2 {
            let d0 = decoded[0]
                .iter()
                .zip(&decoded[1])
                .filter(|(a, b)| a != b)
                .count();
            // 统计 I 帧像素方差（平坦 vs 噪声）。
            let f0 = &decoded[0];
            let mean = f0.iter().map(|&v| v as u64).sum::<u64>() / f0.len() as u64;
            let var = f0
                .iter()
                .map(|&v| {
                    let d = v as i64 - mean as i64;
                    d * d
                })
                .sum::<i64>()
                / f0.len() as i64;
            eprintln!(
                "1080p 解码: 帧0vs1 差异 {d0} 字节 | I 帧均值 {mean} 方差 {var}"
            );
            assert!(d0 > 10000, "1080p 解码帧应不同（d0={d0}）");
        }
    }
    /// 若全 ~26B → pipeline 路径丢内容（与直连 1970kbps 对比）。
    #[test]
    fn test_pipeline_fullframe_bytes_change() {
        if kirin_desk_media::ffmpeg::ensure_loaded().is_err() {
            return;
        }
        let (w, h) = (320u32, 240u32);
        let mut scene = SceneGen::new(SceneKind::FullFrame, w, h);
        let kernel = BenchKernel::new(w, h, 64, 64);
        let handle = kernel.inner.clone();
        let mut pipe = match VideoEncoderPipeline::from_parts(
            Some(Box::new(kernel)),
            factory::create_video_encoder(Codec::H264, None).unwrap(),
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("pipeline 创建失败: {e}");
                return;
            }
        };
        let tex = GpuTexture::new(0x1usize as *mut _, w, h);
        let mut sizes = Vec::new();
        for i in 0..4 {
            let rgba = scene.frame(i);
            handle.lock().unwrap().current = rgba.to_vec();
            pipe.set_cpu_frame(rgba, w, h, i == 0);
            let pk = pipe.on_frame(&tex, ts(i * 16)).unwrap();
            sizes.push(pk.iter().map(|p| p.data.len()).sum::<usize>());
        }
        eprintln!("pipeline fullframe 帧大小序列: {sizes:?}");
        assert!(sizes[1] > 200, "pipeline 第 2 帧不应是 skip（{sizes:?}）");
    }

    #[test]
    fn test_scene_consecutive_frame_diffs() {
        let (w, h) = (320u32, 240u32);
        let mut scene = SceneGen::new(SceneKind::FullFrame, w, h);
        let mut prev = scene.frame(0).to_vec();
        for i in 1..6 {
            let cur = scene.frame(i).to_vec();
            let diff = prev
                .iter()
                .zip(&cur)
                .filter(|(a, b)| a != b)
                .count();
            eprintln!("frame {i} vs {}: {diff} 字节不同", i - 1);
            assert!(diff > 0, "相邻帧内容应不同（frame {i}）");
            prev = cur;
        }
    }
}
