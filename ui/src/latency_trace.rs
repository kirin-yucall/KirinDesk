//!
//! # 设计口径
//!
//!   解析顺序 **env `KIRIN_LATENCY_TRACE` 优先**（显式值一律胜出，含显式
//!   关闭 `"0"`——逃生口，可压过 config 与内置默认）→ 其次 config
//!   `[debug] latency_trace` 显式值（`Some(true/false)` 定夺）→ env 未设且
//!   config 无显式值（缺文件/缺段/缺键）→ **内置默认开**
//!   （**临时默认开（用户 2026-09-06 裁定）**：「debug 模式直接做进包里
//!   默认，后续 bug 修复了再清理」；**回收条件**：迟滞归因完成、相关 bug
//!   而落空，config 侧通道补上「改配置重启即可开」的正式路径）。启动自检行
//!   `latency_trace gate=on|off (source=env|config|default)`（lib.rs
//!   `run()` 打，双端可见）供复测对账。
//!   未开启时所有入口只有一个 `OnceLock` 读 + 分支，逐帧路径零分配。
//! - **周期汇总**：每 5s 一条 INFO 汇总（各段 p50/p95/n），**不打扰动每帧**
//!   ——采样本身仅一次 `epoch_ms()`（SystemTime 一次调用）+ 一次 `push`
//!   （容量上限环形，满丢最旧）。
//! - **跨端关联**：服务端 capture 时刻经 wire 既有 `PacketHeader.pts` 旁路
//!   字段携带（开启时视频窗大帧包 `ts.pts = capture epoch ms`；未开启时
//!   `pts = 0` 与现状逐字节一致，**零协议变更**）。客户端仅在 trace 开启
//!   且 `pts` 为 epoch 量级（> 1e12）时消费；旧客户端/未开启客户端忽略。
//! - **时钟口径**：进程内各段用 epoch 毫秒差（同一 `SystemTime` 源，单调
//!   性在毫秒粒度足够）；跨端段（capture→recv/render）用墙钟 epoch 关联——
//!   **本机回环无时钟漂移**（实机 LAN 跨机时跨端段仅供参考，进程内各段
//!   不受影响）。
//!
//! # 段定义（全部 ms）
//!
//! | 段（服务端进程） | 含义 |
//! |---|---|
//! | `enc`  | capture 提交 → 编码完成（含降采样/编码器内部） |
//! | `bus`  | 编码完成 → 进入广播总线（bincode 序列化 + 广播锁） |
//! | `sendq`| 观众发送任务出队 → 加密写半通道写完成（含锁竞争 + AES + TCP 写） |
//!
//! | 段（客户端进程） | 含义 |
//! |---|---|
//! | `xfer`  | 服务端 capture → 客户端 recv 完整（网络 + 服务端 sendq 合计） |
//! | `decode`| recv 完整 → 解码完成（含解码线程排队 + FFmpeg 解码） |
//! | `render`| 解码完成 → UI pop 上屏（含抖动缓冲 + repaint 节奏） |
//! | `e2e`   | capture → render（端到端，用户体感口径） |
//!
//! 回环 bench（`r77d_latency_bench_loopback`）同进程双端采样，结束后
//! `snapshot()` 一次性取全表（不消费样本，与周期汇总互不干扰）。

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 段标识（服务端 3 + 客户端 4；索引即注册表槽位）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// 服务端：capture 提交 → 编码完成。
    Enc,
    /// 服务端：编码完成 → 进入广播总线。
    Bus,
    /// 服务端：观众发送任务出队 → 写完成。
    Sendq,
    /// 客户端：capture（服务端）→ recv 完整（跨端，含网络 + 服务端发送）。
    Xfer,
    /// 客户端：recv → 解码完成。
    Decode,
    /// 客户端：解码完成 → UI 渲染。
    Render,
    /// 客户端：capture → render（端到端）。
    E2E,
}

/// 段顺序（索引 = 注册表槽位；与 `Stage` 定义顺序严格一致）。
const ALL_STAGES: [Stage; 7] = [
    Stage::Enc,
    Stage::Bus,
    Stage::Sendq,
    Stage::Xfer,
    Stage::Decode,
    Stage::Render,
    Stage::E2E,
];

const STAGE_COUNT: usize = ALL_STAGES.len();

/// 单段样本容量上限（≈2 分钟 @60fps 或更久；满丢最旧，防无界增长）。
const STAGE_CAP: usize = 4096;

/// 周期汇总间隔（5s，口径见模块文档）。
const SUMMARY_INTERVAL: Duration = Duration::from_secs(5);

/// 包里默认，后续 bug 修复了再清理」；**临时**默认开，迟滞归因完成、相关
/// bug 清理后回收为关。**单一点**：config 结构体无显式值（`None`——
/// `utils::config::DebugConfig::latency_trace` 文档）且 env 未设时落本值；
/// 回收时改本常量为 `false` 即可，config 显式值/env 逃生口语义不变）。
const DEFAULT_GATE_ON: bool = true;

/// **env 优先**（`env_val` 有值即定夺：1/true/yes 不区分大小写 → on；
/// 其余显式值（如 `"0"`/`"off"`）→ off，**覆盖** config 显式值与内置
/// 默认——逃生口）；env 未设（`None`）→ config 有显式值（`Some`）定夺；
/// env 未设且 config 无显式值（`None`：缺文件/缺段/缺键）→ 内置默认
///
/// 返回 `(enabled, source)`：`source ∈ {"env", "config", "default"}`
/// （`"config"` = config 显式值生效；`"default"` = env 与 config 显式值
/// 皆无 → 内置默认）。
pub(crate) fn resolve_gate(
    env_val: Option<&str>,
    config_enabled: Option<bool>,
) -> (bool, &'static str) {
    match env_val.map(|s| s.trim().to_ascii_lowercase()) {
        Some(v) => (matches!(v.as_str(), "1" | "true" | "yes"), "env"),
        None => match config_enabled {
            Some(v) => (v, "config"),
            None => (DEFAULT_GATE_ON, "default"),
        },
    }
}

///
/// `None`（无配置文件/损坏〔如测试环境〕/缺 `[debug]` 段或缺键）→ 落内置
/// 默认（开，不阻断）。仅门控初始化时调用一次（`OnceLock` 内），非逐帧路径。
fn config_latency_trace() -> Option<bool> {
    // `and_then`（非 `map`）：字段本身即 `Option<bool>`，`load()` 失败（None）
    // 与字段缺省（None）同归 `None` = 落内置默认。
    kirin_desk_utils::config::Config::load().ok().and_then(|c| c.debug.latency_trace)
}

/// 门控解析结果（进程级一次性）：`(enabled, source)`。
///
/// `source` 供启动自检行（lib.rs `run()`：`latency_trace gate=on|off
pub(crate) fn gate_state() -> (bool, &'static str) {
    static S: OnceLock<(bool, &'static str)> = OnceLock::new();
    *S.get_or_init(|| {
        let env_val = std::env::var("KIRIN_LATENCY_TRACE").ok();
        resolve_gate(env_val.as_deref(), config_latency_trace())
    })
}

/// trace 门控：`KIRIN_LATENCY_TRACE` 优先、config `[debug] latency_trace`
pub(crate) fn enabled() -> bool {
    gate_state().0
}

/// 墙钟 epoch 毫秒（跨端关联锚点；时钟不可用 → 0，调用方按 0 跳过）。
pub(crate) fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// epoch 量级判定：wire pts 旁路字段是否携带了 capture 时刻
/// （< 1e12 视为未携带/旧格式 → 跨端段不采样）。
pub(crate) fn is_epoch_ts(v: u64) -> bool {
    v > 1_000_000_000_000
}

/// 纯函数：百分位（线性索引取整；空 → 0.0）。不排序入参（内部拷贝排序，
/// 周期汇总/快照各段样本量 ≤ 4096，开销可忽略）。
pub(crate) fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut s: Vec<f64> = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((s.len() as f64 - 1.0) * p.clamp(0.0, 1.0)) as usize;
    s[idx.min(s.len() - 1)]
}

/// 单段样本环形缓冲。
struct StageSamples {
    q: VecDeque<f64>,
}

fn registry() -> &'static Mutex<Vec<StageSamples>> {
    static R: OnceLock<Mutex<Vec<StageSamples>>> = OnceLock::new();
    R.get_or_init(|| {
        let mut v = Vec::with_capacity(STAGE_COUNT);
        for _ in 0..STAGE_COUNT {
            v.push(StageSamples {
                q: VecDeque::with_capacity(STAGE_CAP),
            });
        }
        Mutex::new(v)
    })
}

/// 记录一个段样本（ms）。未开启 → 仅一次 `enabled()` 读即返回。
/// 负值（时钟回拨异常）丢弃。
pub(crate) fn record(stage: Stage, ms: f64) {
    if !enabled() || ms < 0.0 {
        return;
    }
    push_sample(stage, ms);
}

/// 环形缓冲写入（门控外——单测经 `record_internal` 直测容量/逐出逻辑，
/// 不受进程级 env 门控影响）。
#[cfg(test)]
pub(crate) fn record_internal(stage: Stage, ms: f64) {
    if ms < 0.0 {
        return;
    }
    push_sample(stage, ms);
}

/// 环形写入本体（门控外；负值防御在调用方）。
fn push_sample(stage: Stage, ms: f64) {
    let mut r = registry().lock().unwrap();
    let s = &mut r[stage as usize];
    if s.q.len() >= STAGE_CAP {
        s.q.pop_front();
    }
    s.q.push_back(ms);
}

/// 段名（汇总行/快照用）。
fn stage_name(stage: Stage) -> &'static str {
    match stage {
        Stage::Enc => "enc",
        Stage::Bus => "bus",
        Stage::Sendq => "sendq",
        Stage::Xfer => "xfer",
        Stage::Decode => "decode",
        Stage::Render => "render",
        Stage::E2E => "e2e",
    }
}

/// 段摘要（快照行元素）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct StageSummary {
    pub stage: Stage,
    pub n: usize,
    pub p50: f64,
    pub p95: f64,
    pub max: f64,
}

/// 全段快照（**不消费样本**——周期汇总与本方法共用环形缓冲）。
/// 无样本的段不返回（调用方按 n>0 过滤语义）。
pub(crate) fn snapshot() -> Vec<StageSummary> {
    let r = registry().lock().unwrap();
    r.iter()
        .enumerate()
        .filter_map(|(i, s)| {
            if s.q.is_empty() {
                return None;
            }
            let v: Vec<f64> = s.q.iter().copied().collect();
            Some(StageSummary {
                stage: ALL_STAGES[i],
                n: v.len(),
                p50: percentile(&v, 0.5),
                p95: percentile(&v, 0.95),
                max: v
                    .iter()
                    .copied()
                    .fold(f64::NEG_INFINITY, f64::max),
            })
        })
        .collect()
}

/// 周期汇总行：距上次 ≥ 5s 且有新样本 → INFO 一行（本侧有样本的段）。
/// 返回是否打了一行（调用方据此维护 `last_tick`）。
///
/// 同进程 bench 场景（服务端+客户端同进程）两侧共享注册表——任一侧调用
/// 都可能汇总全部段；生产上两侧分进程，各自只见到本侧段。
pub(crate) fn maybe_summary(side: &str, last_tick: &mut Instant) -> bool {
    if !enabled() {
        return false;
    }
    let now = Instant::now();
    if now.duration_since(*last_tick) < SUMMARY_INTERVAL {
        return false;
    }
    let snap = snapshot();
    if snap.is_empty() {
        return false;
    }
    *last_tick = now;
    for s in &snap {
        line.push_str(&format!(
            " | {} n={} p50={:.1} p95={:.1} max={:.1}",
            stage_name(s.stage),
            s.n,
            s.p50,
            s.p95,
            s.max
        ));
    }
    tracing::info!("{line}");
    true
}

/// 供调用方初始化 5s 计时起点。
pub(crate) fn first_tick() -> Instant {
    Instant::now()
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

///
///   0 = 服务端全局流槽位——捕获/编码/广播为全局单实例，非 per-观众）。
///   同全局槽位口径）。
///   观众会话——新会话 = 新键 = 重新进入「前 3 帧全量」窗）。
///   session_id = 客户端会话——wire 到达 → 重组入队完成）。
///   同 per-会话口径——wire 到达锚点 → 解码完成）。
///   同 per-会话口径——解码完成 → 渲染提交/纹理上传）。
///   同 per-会话口径——批次首事件入队 → flush 发送完成）。
pub(crate) const R123_STREAM_VID: u8 = 0;
pub(crate) const R123_STREAM_SND: u8 = 1;
pub(crate) const R123_STREAM_IN: u8 = 2;
pub(crate) const R123_STREAM_CLI_RCV: u8 = 3;
pub(crate) const R123_STREAM_CLI_DEC: u8 = 4;
pub(crate) const R123_STREAM_CLI_RND: u8 = 5;
pub(crate) const R123_STREAM_CLI_IN: u8 = 6;

///
/// 挂点 = lib.rs 工具栏段 `toolbar_width_trace_lines` 两行 INFO（G1/G2 下轮
/// 用户宽窗复测定判锚）。**键口径** = `r123_step(wid, R133_STREAM_TBW, …)`
/// 首参按**窗 id**（非 session_id）复用 → per-窗独立全量窗/节流窗
pub(crate) const R133_STREAM_TBW: u8 = 7;

/// 链路对账；定稿口径）。
const R123_BURST: u32 = 3;

/// 口径）。
const R123_INTERVAL_MS: u64 = 1000;

/// 最坏=各流重出 3 条全量行，有界噪声，防长驻多会话无界增长）。
const R123_REGISTRY_CAP: usize = 256;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct R123ThrottleState {
    /// 本流已**输出**帧数（仅输出时 +1；节流不输出不计数——「未输出不
    /// 重置」口径的一半）。
    emitted: u32,
    /// 最近一次**输出**帧的 epoch ms 锚点（0 = 未输出；恒单调非降——
    /// 时钟回拨防御）。
    last_emit_ms: u64,
}

fn r123_registry() -> &'static Mutex<HashMap<u64, R123ThrottleState>> {
    static R: OnceLock<Mutex<HashMap<u64, R123ThrottleState>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 无溢出风险）。
pub(crate) fn r123_stream_key(session_id: u64, stream: u8) -> u64 {
    (session_id << 8) | (stream & 0xFF) as u64
}

///
/// 语义（每流每会话，设计定稿）：
/// - **前 3 帧全量**：`emitted < 3` 恒输出（与时间间隔无关）；
/// - **之后 ≥1000ms 1 帧/秒**：`now - last_emit ≥ 1000` 输出，否则节流；
/// - **未输出不重置**：被节流（未输出）的帧不触碰锚点——1000ms 窗恒自
///   最近**输出**帧起算；
/// - **时钟回拨防御**：`now < 锚点` → elapsed 饱和 0 → 未到期，不输出、
///   不动锚点（无 panic/无负数）；全量窗内锚点亦仅单调非降（`max`）
///   推进（回拨最坏=窗后延、少出行，安全向）。
pub(crate) fn r123_throttle_step(st: &mut R123ThrottleState, now_ms: u64) -> bool {
    if st.emitted < R123_BURST {
        st.emitted += 1;
        st.last_emit_ms = st.last_emit_ms.max(now_ms);
        return true;
    }
    let elapsed = now_ms.saturating_sub(st.last_emit_ms);
    if elapsed >= R123_INTERVAL_MS {
        st.last_emit_ms = now_ms;
        true
    } else {
        false
    }
}

/// 同门控同源）。
///
/// `now_ms` = 调用方提供的**进程内** epoch ms 锚点（各挂点传自身管线锚
/// 点——视频=编码完成、音频=广播环到达、输入=注入完成；不额外起时钟）。
pub(crate) fn r123_step(session_id: u64, stream: u8, now_ms: u64) -> bool {
    if !enabled() {
        return false;
    }
    let mut m = r123_registry().lock().unwrap();
    if m.len() > R123_REGISTRY_CAP {
        m.clear();
    }
    let st = m.entry(r123_stream_key(session_id, stream)).or_default();
    r123_throttle_step(st, now_ms)
}

pub(crate) fn r123_ev_tag(kind: &kirin_desk_input::injector::InputKind) -> &'static str {
    use kirin_desk_input::injector::InputKind as K;
    match kind {
        K::MouseMove => "mm",
        K::MouseButton => "mb",
        K::MouseWheel => "mw",
        K::KeyDown => "kd",
        K::KeyUp => "ku",
        K::KeyRepeat => "kr",
        K::Text => "tx",
        K::SpecialKey => "sk",
    }
}

///
/// 收口：原行仅 `ev` 短码=kind 级，**无法辨别到达的是哪把键**——「到达即注入
/// 成功」时仍无键身份）。映射走 `kirin_desk_input::windows` 双表
/// （`map_vk`/`map_scan_code`——**观测口径**，与注入路径零耦合、零 wire 触
/// 碰：只读 `ev`，不改事件）。
///
/// 口径：仅键类事件（KeyDown/KeyUp/KeyRepeat）出双码；鼠标/Text/SpecialKey
/// 无单键身份 → `(None, None)`（行显示 `-`）；键判别式未覆盖 → 单侧 `None`
/// （另一侧仍如实显示）。
pub(crate) fn r123_key_vk_scan(ev: &kirin_desk_input::injector::InputEvent) -> (Option<u16>, Option<u16>) {
    use kirin_desk_input::injector::InputKind as K;
    match ev.kind {
        K::KeyDown | K::KeyUp | K::KeyRepeat => (
            kirin_desk_input::windows::map_vk(ev.key),
            kirin_desk_input::windows::map_scan_code(ev.key),
        ),
        _ => (None, None),
    }
}

/// （`0x3A`）；`≥0x100`（扩展 scan 前缀形态，如 `0xE05B`）→ 四位（`0xE053`）。
/// 零键内容红线不破：仅数字/十六进制形态，无键名。
pub(crate) fn r123_fmt_code(c: Option<u16>) -> String {
    match c {
        None => "-".to_string(),
        Some(v) if v >= 0x100 => format!("0x{v:04X}"),
        Some(v) => format!("0x{v:02X}"),
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

///
/// `decoded_new` = 本次解码产出新帧（解码线程 `decode` 返回非空）；
/// 重绘请求无效且致 eframe 陈旧 deadline busy 泵——故隐藏不触发）。
///
/// 语义（白名单修复=「**只提前不落后** + 隐藏不触发 + 16ms 泵兜底」）：
/// - 新帧 + 可见 → `true`：解码线程 `push_decoded` 成功后**立即**请求主窗
///   重绘（`server_media::request_main_repaint`），不再等下一次 16ms 泵
///   tick（帧到达后平均 ~8ms/最多 16ms 的泵周期等待=用户「持续操作跟手性」
///   头号可疑源）；
/// - 无新帧（解码器缓冲中零产出）→ `false`：屏上无新东西可呈现，不扰动；
/// - 隐藏 → `false`：不触发（窗口恢复时 UI 自身新帧会读到最新渲染桥）。
///
/// 「只提前不落后」由调用结构保证：既有 16ms 泵（`request_repaint_after`）
/// **保留兜底零改动**，本决策仅可能把重绘提前到解码完成时刻；`egui` 的
/// `request_repaint` 幂等（已有重绘在途时重复请求无副作用）。
pub(crate) fn r123_repaint_decision(decoded_new: bool, window_visible: bool) -> bool {
    decoded_new && window_visible
}

// ════════════════════════════════════════════════════════════════
//
// - T2（前置仪表）：xfer/e2e 跨端段原式 `now_cli.saturating_sub(capture_srv)`
//   跨机时钟未补偿 → 负值恒吞零（09-23 双端日志 xfer p50=0 max=0 在案）=
//   传输段「恒 0 不可归因」。修 = 会话级偏置 Δ 自锚（本段
//   [`r135_10_bias_observe`]，滚动 floor 锚定——报告 §2 握手对表方法在
//   进程内固化：raw = wire + Δ，wire ≥ 0 → Δ_est = min(近窗 raw)）+
//   负校准值**显式丢弃 + WARN 计数**（禁 `saturating_sub` 静默吞零）。
//   Δ 为**会话级**状态（重连/新会话 = 新条目重新自锚）；滚动窗对时钟
//   步进（NTP 重锚/漂移）自愈——无需一次性锚的再校准逻辑。
// - T1：抖动缓冲深度固定 2（RenderBridge::new(2,16)，lib.rs）→ 自适应
//   1-2（LAN 稳态 1；j 尾部〔在途 ≥2 连续出现〕→ 临时 2；持续稳定 → 回 1）。
//   调整，media crate 零改动。
// - T3：dec_commit（解码完成→渲染提交）> 500ms → WARN 行（帧键 pts +
//   前 1s UI 主线程帧预算上下文——区分「单次 egui 通过主导」〔trap
//   家族：pass_max ≈ dec_commit〕与「泵未调度」〔winit/隐藏窗：gap_max
//   ≈ dec_commit〕）。
//
// 「门控逃生口只关日志行，不关修复」同口径）；仅观测行经 `enabled()`。
// ════════════════════════════════════════════════════════════════

pub(crate) const R135_STREAM_BIAS: u8 = 8;

/// 本身罕见，节流车道仅兜底防抖）。
pub(crate) const R135_STREAM_JITTER: u8 = 9;

/// 之后 1 行/秒——UI 楔死时每帧 >500ms 的刷屏上界）。
pub(crate) const R135_STREAM_STALL: u8 = 10;

/// + 之后 ≥1000ms 1 行/秒——鼠标移动突发期每帧一行须节流封顶）。
/// 零碰撞（`r135_10_stream_keys_no_collision` 单测一并钉死）。
pub(crate) const R137_STREAM_LOCAL_SEG: u8 = 11;

/// T2：滚动窗样本数（floor 锚定基础；@窗口到达率 ~6-10/s ≈ 7-10s 数据）。
pub(crate) const R135_10_BIAS_WIN: usize = 64;

/// T2：锚定生效最小样本数（不足 → 无 Δ → xfer/e2e 不采样〔计数 pre_skip，
/// 锚定行带出〕）。@窗口到达率 ≈ 0.8-1.3s 锚定延迟。
pub(crate) const R135_10_BIAS_MIN_SAMPLES: usize = 8;

/// T2：|Δ 变化| ≥ 本值（ms）→ reanchored 观测行（时钟步进/大漂移信号；
/// 小于本值的滚动窗 min 抖动 = wire 宽度内常态，不换锚防基线抖动）。
pub(crate) const R135_10_BIAS_REANCHOR_MS: i64 = 100;

/// T3：渲染停顿守卫阈值（ms；dec_commit **> 本值** → WARN 行。09-23
/// 基线 max=2054ms / p95=29ms → 500ms 档 = 尖峰全捕获、常态零行）。
pub(crate) const R135_10_STALL_MS: u64 = 500;

/// T1：自适应深度下界（帧；LAN 稳态目标——拆除固定 2 帧的无效缓冲）。
pub(crate) const R135_10_JIT_MIN: usize = 1;

pub(crate) const R135_10_JIT_MAX: usize = 2;

/// T1：j ≥ 2（尾部证据）连续泵 tick 数 → 升 2（@60Hz 泵 2 tick ≈ 32ms
/// 持续在途 = 非孤立乱序的单泵周期瞬时，防单帧毛刺误升）。**采样点 =
/// 泵周期起点、排空（drain/pop）前**：j = 自上一泵周期起解码线程累计
/// 的桥**精确**在途（通道积压 + jitter pending，
/// `RenderBridge::inflight_frames`，无静默丢弃高估）——排空前口径才是
/// 「积压压力」信号（@19fps 健康 ∈{0,1}）；排空后口径会被同 tick 的
/// drain 消解，尾部不可观测。
pub(crate) const R135_10_JIT_RAISE_STREAK: u32 = 2;

/// T1：（depth=2 时）j ≤ 1 连续泵 tick 数 → 回 1（@60Hz 泵 30 tick ≈ 0.5s
/// 稳态 = 抖动期结束）。
pub(crate) const R135_10_JIT_LOWER_STREAK: u32 = 30;

/// T3：泵循环采样环容量（@60fps ≈ 5s；覆盖 1s 上下文窗 + 2s 级尖峰裕量）。
pub(crate) const R135_10_PUMP_RING_CAP: usize = 300;

/// T2：单会话偏置自校准状态（纯数据；接收循环观测、UI 泵读 Δ）。
#[derive(Debug, Clone, Default)]
pub(crate) struct R135_10BiasCalib {
    /// 滚动 raw 窗（客户端 recv epoch − 服务端 capture epoch，ms 有符号）。
    win: VecDeque<i64>,
    /// 当前锚定 Δ（ms；None = 未达最小样本数）。
    delta: Option<i64>,
    /// xfer 负校准显式丢弃计数（时钟回拨/窗外快样本；禁静默吞零）。
    neg_xfer: u64,
    /// e2e 负校准显式丢弃计数（同源语义）。
    neg_e2e: u64,
    /// 锚定前跳采计数（无 Δ = 不采样，设计内跳过非异常；锚定行带出）。
    pre_skip: u64,
}

impl R135_10BiasCalib {
    /// 当前锚定 Δ（UI 泵 e2e 段读取；None = 未锚定 → e2e 不采样）。
    pub(crate) fn delta(&self) -> Option<i64> {
        self.delta
    }

    /// 锚定前跳采计数。
    pub(crate) fn pre_skip(&self) -> u64 {
        self.pre_skip
    }

    /// 观测一个 raw 样本（接收循环逐窗调用）。
    ///
    /// 返回 `(delta, 事件)`：事件 = 锚定/再锚定（调用点经 `r123_step`
    ///
    /// 再锚定纪律：滚动 min 每样本都可能微动（wire 宽度内 ≈ ±40ms）→
    /// **仅** |Δ 变化| ≥ [`R135_10_BIAS_REANCHOR_MS`] 才换锚（防 xfer
    /// 基线逐帧漂移）；小于本值时保留旧锚。
    pub(crate) fn observe(&mut self, raw: i64) -> (Option<i64>, R135_10BiasEvent) {
        self.win.push_back(raw);
        if self.win.len() > R135_10_BIAS_WIN {
            self.win.pop_front();
        }
        let new_delta = r135_10_bias_delta_iter(self.win.iter().copied());
        let event = match (self.delta, new_delta) {
            (None, Some(d)) => {
                self.delta = Some(d);
                R135_10BiasEvent::Anchored
            }
            (Some(prev), Some(d)) if (d - prev).unsigned_abs() >= R135_10_BIAS_REANCHOR_MS as u64 => {
                self.delta = Some(d);
                R135_10BiasEvent::Reanchored { prev }
            }
            // (None,None)〔锚定前常态〕/ (Some,None)〔不可达：窗达最小
            // 样本后不再缩小〕/ (Some,Some) 未达 reanchor 阈值 → 零事件。
            _ => R135_10BiasEvent::None,
        };
        (self.delta, event)
    }
}

/// T2：锚定事件（观测行源；调用点格式化 + 节流）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum R135_10BiasEvent {
    /// 无事件（常态：滚动窗 min 抖动 < reanchor 阈值）。
    None,
    /// 首次锚定（Δ 自 None → Some）。
    Anchored,
    /// 再锚定（|Δ 变化| ≥ 阈值；prev = 旧锚）。
    Reanchored { prev: i64 },
}

/// T2 纯函数：floor 锚定 Δ 估计。
///
/// 语义：`raw = wire_true + Δ`（Δ = 客户端时钟偏移 − 服务端时钟偏移，
/// 会话内常量；wire_true ≥ 0）→ **min(近窗 raw) = Δ + min(wire) ≈ Δ**
/// （最快帧零点）。窗内样本不足 [`R135_10_BIAS_MIN_SAMPLES`] → None。
///
/// 相对一次性握手锚：滚动窗对时钟步进自愈（全窗平移 → min 平移 →
/// 下轮 reanchored），漂移（179 两天 ~3.1s ≈ 18ns/s）窗内可忽略。
///
/// 迭代器核（单趟 count+min，零分配）：`R135_10BiasCalib::win` 为
/// `VecDeque`（不 Deref 成切片——可回绕），观测点/单测经
/// `.iter().copied()`（或 `std::iter::empty()`）走本函数。
pub(crate) fn r135_10_bias_delta_iter(win: impl Iterator<Item = i64>) -> Option<i64> {
    let mut min: Option<i64> = None;
    let mut n = 0usize;
    for v in win {
        n += 1;
        min = Some(min.map_or(v, |m| m.min(v)));
    }
    (n >= R135_10_BIAS_MIN_SAMPLES).then(|| min)
        .flatten()
}

/// T2：校准结果（三态——禁二态：「未锚定」与「负值」处置不同，
/// 前者设计内跳过〔计数 pre_skip〕，后者异常显式丢弃〔计数 + WARN〕）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum R135_10Calib {
    /// 可记录校准值（ms，≥ 0）。
    Ok(i64),
    /// 未锚定（Δ 未达最小样本数）→ 跳过采样。
    PreAnchor,
    /// 负校准值（时钟回拨/窗外快样本）→ 显式丢弃 + WARN 计数。
    Negative { raw: i64, delta: i64 },
}

/// T2 纯函数：`raw − Δ` 校准 + 三态裁决（单测钉死；调用点计数/打行）。
pub(crate) fn r135_10_calibrate(raw: i64, delta: Option<i64>) -> R135_10Calib {
    let Some(d) = delta else {
        return R135_10Calib::PreAnchor;
    };
    let cal = raw - d;
    if cal < 0 {
        R135_10Calib::Negative { raw, delta: d }
    } else {
        R135_10Calib::Ok(cal)
    }
}

/// T2 行构造：首次锚定（行格式钉死单测）。
pub(crate) fn r135_10_bias_anchored_line(sid: u64, delta: i64, n: usize, pre_skip: u64) -> String {
    format!(
    )
}

/// T2 行构造：再锚定（时钟步进/漂移信号；行格式钉死单测）。
pub(crate) fn r135_10_bias_reanchored_line(
    sid: u64,
    prev: i64,
    delta: i64,
    n: usize,
) -> String {
    format!(
    )
}

/// T2 行构造：负校准显式丢弃（WARN；stage ∈ {xfer, e2e}；行格式钉死单测）。
pub(crate) fn r135_10_xfer_neg_line(
    sid: u64,
    stage: &str,
    raw: i64,
    delta: i64,
    discards: u64,
) -> String {
    format!(
    )
}

/// 流注册表同纪律；实际并发会话数远小于上限）。
fn r135_10_bias_registry() -> &'static Mutex<HashMap<u64, R135_10BiasCalib>> {
    static R: OnceLock<Mutex<HashMap<u64, R135_10BiasCalib>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// T2：接收循环入口——观测 raw 样本，返回 (Δ, 事件)。
///
/// 返回的 Δ 即**已含本样本**后的锚（事件行 n 字段 = 本窗样本数，调用点
/// 经 `r123_step` 节流后打行；门控关 = 事件丢弃、状态维护照常）。
pub(crate) fn r135_10_bias_observe(
    session_id: u64,
    raw: i64,
) -> (Option<i64>, R135_10BiasEvent, usize) {
    let mut m = r135_10_bias_registry().lock().unwrap();
    if m.len() > 256 {
        m.clear();
    }
    let st = m.entry(session_id).or_default();
    let (delta, event) = st.observe(raw);
    (delta, event, st.win.len())
}

/// T2：UI 泵读取当前 Δ（e2e 段校准；None = 未锚定 → e2e 不采样）。
pub(crate) fn r135_10_bias_delta_for(session_id: u64) -> Option<i64> {
    let m = r135_10_bias_registry().lock().unwrap();
    m.get(&session_id).and_then(|s| s.delta())
}

/// T2：锚定前跳采计数 +1（xfer/e2e 采样点 Δ 未就绪时调用；设计内跳过，
/// 非异常——计数于 anchored 行 `pre_skip` 字段带出，零逐帧行）。
pub(crate) fn r135_10_pre_skip_inc(session_id: u64) {
    let mut m = r135_10_bias_registry().lock().unwrap();
    if let Some(st) = m.get_mut(&session_id) {
        st.pre_skip += 1;
    }
}

/// T2：锚定前跳采计数读取（anchored 行 `pre_skip` 字段源）。
pub(crate) fn r135_10_pre_skip_count(session_id: u64) -> u64 {
    let m = r135_10_bias_registry().lock().unwrap();
    m.get(&session_id).map_or(0, |s| s.pre_skip())
}

/// T2：负校准显式丢弃记账 + 返回 WARN 触发态（`count == 1 || count % 1000 == 0`
pub(crate) fn r135_10_neg_discard(
    session_id: u64,
    stage: &str,
    raw: i64,
    delta: i64,
) -> Option<String> {
    let mut m = r135_10_bias_registry().lock().unwrap();
    let st = m.get_mut(&session_id)?;
    let count = if stage == "xfer" {
        st.neg_xfer += 1;
        st.neg_xfer
    } else {
        st.neg_e2e += 1;
        st.neg_e2e
    };
    if count == 1 || count % 1000 == 0 {
        Some(r135_10_xfer_neg_line(session_id, stage, raw, delta, count))
    } else {
        None
    }
}

// ── T1：自适应抖动深度 ───────────────────────────────────────────

/// T1：单会话自适应深度状态（纯数据；UI 泵周期起点 tick、桥消费）。
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct R135_10JitterState {
    /// 当前深度（帧；1|2。新会话 Default depth=0 → 首次 tick 归一 1 =
    /// LAN 稳态目标，拆除固定 2 帧无效缓冲）。
    pub depth: usize,
    /// j ≥ 2（尾部证据）连续样本数。
    pub tail_streak: u32,
    /// （depth=2）j ≤ 1（稳态证据）连续样本数。
    pub stable_streak: u32,
}

/// T1 纯函数：单步深度裁决（**单测钉死**；j = 本样本时刻在途帧数）。
///
/// - `depth < 2 ∧ j ≥ 2 ∧ tail_streak ≥ R135_10_JIT_RAISE_STREAK` → 升 2
///   （reason=`tail`——连续在途 = 抖动期，加深防丢帧）；
/// - `depth > 1 ∧ j ≤ 1 ∧ stable_streak ≥ R135_10_JIT_LOWER_STREAK` → 回 1
///   （reason=`stable`——持续稳态，拆回最低延迟）；
/// - 其余 = 保持（沿触发才返回 Some((old,new,reason))）。
///
/// 初始归一：`depth=0`（新状态）→ 首样本即置 1（无论 j 值——稳态目标
/// 先行，尾部证据随后才允许升 2）。
pub(crate) fn r135_10_jitter_tick(
    st: &mut R135_10JitterState,
    j: usize,
) -> Option<(usize, usize, &'static str)> {
    if st.depth == 0 {
        st.depth = R135_10_JIT_MIN;
    }
    if j >= 2 {
        st.tail_streak = st.tail_streak.saturating_add(1);
        st.stable_streak = 0;
        if st.depth < R135_10_JIT_MAX && st.tail_streak >= R135_10_JIT_RAISE_STREAK {
            let old = st.depth;
            st.depth = R135_10_JIT_MAX;
            Some((old, st.depth, "tail"))
        } else {
            None
        }
    } else {
        st.tail_streak = 0;
        st.stable_streak = st.stable_streak.saturating_add(1);
        if st.depth > R135_10_JIT_MIN && st.stable_streak >= R135_10_JIT_LOWER_STREAK {
            let old = st.depth;
            st.depth = R135_10_JIT_MIN;
            Some((old, st.depth, "stable"))
        } else {
            None
        }
    }
}

/// T1 行构造：深度沿（INFO；行格式钉死单测）。
pub(crate) fn r135_10_jitter_line(
    sid: u64,
    old: usize,
    new: usize,
    reason: &str,
    j: usize,
) -> String {
}

/// T1：per-会话深度状态注册表（256 条目上限超限整体 clear，同纪律）。
fn r135_10_jitter_registry() -> &'static Mutex<HashMap<u64, R135_10JitterState>> {
    static R: OnceLock<Mutex<HashMap<u64, R135_10JitterState>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// T1：解码线程入口——单步裁决；Some = 本样本触发深度沿（调用点
/// `bridge.set_jitter_depth(new)` + 经 `r123_step` 节流打行）。
///
/// 帧数（`RenderBridge::inflight_frames`——通道积压 + jitter pending 的
/// **精确**值，无静默丢弃高估——区别于 `r123_inflight` 的上界近似
/// 语义〔其文档「只高估不低估」= j 观测字段口径，T1 决策不用]）。
pub(crate) fn r135_10_jitter_observe(
    session_id: u64,
    j: usize,
) -> Option<(usize, usize, &'static str)> {
    let mut m = r135_10_jitter_registry().lock().unwrap();
    if m.len() > 256 {
        m.clear();
    }
    let st = m.entry(session_id).or_default();
    r135_10_jitter_tick(st, j)
}

// ── T3：渲染停顿守卫（UI 主线程帧预算观测） ──────────────────────

/// T3：单泵循环采样（Desktop 窗每 egui 通过一条；UI 线程独占写）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct R135_10PumpSample {
    /// 循环起点 epoch ms（时钟回拨防御：上下文汇总按序对，回拨对跳过）。
    pub start_ms: u64,
    /// 本循环通过耗时 ms（egui 通过本体——trap 家族归因位：pass_max
    /// ≈ dec_commit → 单次 egui 通过主导）。
    pub pass_ms: u64,
    /// 本循环输入事件数（`ctx.input` events；交互负载上下文）。
    pub ev_n: u32,
}

/// T3：泵上下文汇总（stall 行字段源；判读口径见结构注释）。
///
/// **窗口径 = 前 1s ∪ 最近 [`R135_10_PUMP_CTX_MIN`] 个已完成循环 + 尾间隔**。
/// 2s 级尖峰时「前 1s」在检点时刻恰是尖峰本体（窗内无已完成循环）→
/// 并集 + 尾间隔保证 stall 区间两侧形态始终可观测：
/// - `pass_max_ms ≈ dec_commit` → 单次 egui 通过主导（trap 家族：该长通过
///   作为已完成循环入环）；
/// - `gap_max_ms（尾间隔）≈ dec_commit ∧ pass_max 小` → 泵未调度（winit
///   停摆/窗口隐藏）或当前通过进行中且长（当前循环样本闭包结束才入环，
///   检点时只能经尾间隔观测——两形态同签，记交付报告）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct R135_10Ui1sCtx {
    /// 窗内泵循环数。
    pub n: usize,
    /// 窗内通过耗时合计 ms（帧预算总负载）。
    pub pass_sum_ms: u64,
    /// 窗内单循环最大通过耗时 ms（trap 家族归因位）。
    pub pass_max_ms: u64,
    /// 窗内相邻循环最大间隔 **含尾间隔**（窗内最晚起点 → now；泵未调度
    /// / 当前通过长 归因位）。
    pub gap_max_ms: u64,
    /// 窗内输入事件合计（交互负载；0 = 纯观看形态）。
    pub ev_sum: u32,
}

/// T3：上下文必含的最近已完成循环数（尖峰窗退化保底——见
/// [`R135_10Ui1sCtx`] 窗口径）。
pub(crate) const R135_10_PUMP_CTX_MIN: usize = 4;

/// T3 纯函数：泵上下文汇总（**单测钉死**；ring = 按序泵采样；时钟回拨对
/// 〔后条 start < 前条 start〕gap 跳过、样本仍计入；start > now 的样本
/// （时钟前跳）排除）。
pub(crate) fn r135_10_ui1s_ctx(
    ring: &VecDeque<R135_10PumpSample>,
    now_ms: u64,
) -> R135_10Ui1sCtx {
    let mut out = R135_10Ui1sCtx::default();
    let min_idx = ring.len().saturating_sub(R135_10_PUMP_CTX_MIN);
    let mut prev_start: Option<u64> = None;
    let mut max_start: Option<u64> = None;
    for (i, s) in ring.iter().enumerate() {
        if s.start_ms > now_ms {
            continue; // 时钟前跳样本：排除（gap 链不参与）
        }
        let in_window = now_ms.saturating_sub(s.start_ms) <= 1000 || i >= min_idx;
        if !in_window {
            continue;
        }
        out.n += 1;
        out.pass_sum_ms = out.pass_sum_ms.saturating_add(s.pass_ms);
        if s.pass_ms > out.pass_max_ms {
            out.pass_max_ms = s.pass_ms;
        }
        out.ev_sum = out.ev_sum.saturating_add(s.ev_n);
        if let Some(p) = prev_start {
            if s.start_ms >= p {
                let gap = s.start_ms - p;
                if gap > out.gap_max_ms {
                    out.gap_max_ms = gap;
                }
            }
        }
        prev_start = Some(s.start_ms);
        if max_start.map_or(true, |m| s.start_ms > m) {
            max_start = Some(s.start_ms);
        }
    }
    // 尾间隔：窗内最晚循环起点 → now（当前循环样本尚未入环时的唯一
    // 观测位——「当前通过进行中且长」/「最后完成循环后泵停摆」）。
    if let Some(m) = max_start {
        let tail = now_ms.saturating_sub(m);
        if tail > out.gap_max_ms {
            out.gap_max_ms = tail;
        }
    }
    out
}

/// T3 行构造：stall WARN（帧键 pts + 前 1s 上下文；行格式钉死单测）。
pub(crate) fn r135_10_stall_line(
    sid: u64,
    pts: u64,
    dec_commit_ms: u64,
    ctx: &R135_10Ui1sCtx,
) -> String {
    format!(
         n1s={} pass_sum={}ms pass_max={}ms gap_max={}ms ev1s={}",
        ctx.n, ctx.pass_sum_ms, ctx.pass_max_ms, ctx.gap_max_ms, ctx.ev_sum
    )
}

/// T3：per-会话泵采样环注册表（UI 线程独占写；256 条目上限超限 clear）。
fn r135_10_pump_registry() -> &'static Mutex<HashMap<u64, VecDeque<R135_10PumpSample>>> {
    static R: OnceLock<Mutex<HashMap<u64, VecDeque<R135_10PumpSample>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// T3：泵循环守卫——Desktop 窗视口闭包**入口**构造（`let _g = …`），
/// Drop（闭包所有返回路径含早退）落 (起点, pass_ms, ev_n) 入环。
///
/// pass_ms = 闭包入口→Drop 的墙钟时长 = 本 egui 通过耗时（含渲染提交）；
/// 守卫自身持 `Instant`（跨线程安全，UI 线程独占语义由调用点保证）。
pub(crate) struct R135_10PumpCycleGuard {
    session_id: u64,
    start: Instant,
    start_ms: u64,
    ev_n: u32,
}

impl R135_10PumpCycleGuard {
    /// 构造（闭包入口单点调用；`ev_n` = 本帧输入事件数——调用点读
    /// `ctx.input(|i| i.events.len())` 传入）。
    pub(crate) fn new(session_id: u64, ev_n: u32) -> Self {
        Self {
            session_id,
            start: Instant::now(),
            start_ms: epoch_ms(),
            ev_n,
        }
    }
}

impl Drop for R135_10PumpCycleGuard {
    fn drop(&mut self) {
        let pass_ms = self.start.elapsed().as_millis() as u64;
        let mut m = r135_10_pump_registry().lock().unwrap();
        if m.len() > 256 {
            m.clear();
        }
        let ring = m.entry(self.session_id).or_default();
        if ring.len() >= R135_10_PUMP_RING_CAP {
            ring.pop_front();
        }
        ring.push_back(R135_10PumpSample {
            start_ms: self.start_ms,
            pass_ms,
            ev_n: self.ev_n,
        });
    }
}

/// T3：读取前 1s 上下文（stall 行构造用；UI 线程调用）。
pub(crate) fn r135_10_ui1s_ctx_for(session_id: u64, now_ms: u64) -> R135_10Ui1sCtx {
    let m = r135_10_pump_registry().lock().unwrap();
    match m.get(&session_id) {
        Some(ring) => r135_10_ui1s_ctx(ring, now_ms),
        None => R135_10Ui1sCtx::default(),
    }
}

/// 行 `gap` 字段源：**事件→帧**段上界（鼠标事件到达后，其所在 egui 通过
/// 的「起点→完成」结束点即本事件被处理/入队的最晚锚；间隔 = 上一通过
/// 结束后至今 = 本事件在帧调度侧的等待上界）。
///
/// （首帧 / 会话清槽后）→ 0（保守 = 不夸大延迟）；saturating 防时钟回拨。
pub(crate) fn r135_10_frame_gap_ms(session_id: u64, now_ms: u64) -> u64 {
    let m = r135_10_pump_registry().lock().unwrap();
    match m.get(&session_id) {
        Some(ring) => ring
            .back()
            .map(|s| now_ms.saturating_sub(s.start_ms.saturating_add(s.pass_ms)))
            .unwrap_or(0),
        None => 0,
    }
}

/// 与 r123_inflight 清槽同位点；三注册表一并 remove 防会话间残留）。
pub(crate) fn r135_10_session_cleanup(session_id: u64) {
    if let Ok(mut m) = r135_10_bias_registry().lock() {
        m.remove(&session_id);
    }
    if let Ok(mut m) = r135_10_jitter_registry().lock() {
        m.remove(&session_id);
    }
    if let Ok(mut m) = r135_10_pump_registry().lock() {
        m.remove(&session_id);
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;


    /// env 优先：显式值一律胜出（含**显式关闭覆盖 config 开**与**显式关闭
    /// 最高优先级，"0" 必须能压住 config=true 也能压住内置默认）。
    #[test]
    fn r81e_gate_env_priority() {
        assert_eq!(
            resolve_gate(Some("1"), Some(false)),
            (true, "env"),
            "env=1 开（config 显式关）"
        );
        assert_eq!(
            resolve_gate(Some("TRUE"), Some(false)),
            (true, "env"),
            "大小写不敏感"
        );
        assert_eq!(
            resolve_gate(Some("0"), Some(true)),
            (false, "env"),
            "env=0 显式关必须覆盖 config=true"
        );
        assert_eq!(
            resolve_gate(Some("0"), None),
            (false, "env"),
        );
        assert_eq!(
            resolve_gate(Some("off"), Some(true)),
            (false, "env"),
            "任意非真值 env 皆覆盖 config"
        );
        assert_eq!(
            resolve_gate(Some("  yes  "), None),
            (true, "env"),
            "trim 后判定（压内置默认）"
        );
    }

    /// env 未设 → config 显式值定夺（开/关）；env 与 config 显式值皆无
    /// 裁定「debug 模式直接做进包里默认，后续 bug 修复了再清理」；临时
    /// 口径，迟滞归因完成、相关 bug 清理后回收为关）。
    #[test]
    fn r81e_gate_config_and_default_on() {
        assert_eq!(
            resolve_gate(None, Some(true)),
            (true, "config"),
            "env 未设 + config 显式开 → on(config)"
        );
        assert_eq!(
            resolve_gate(None, Some(false)),
            (false, "config"),
            "env 未设 + config 显式关 → off(config)（config 侧逃生口）"
        );
        assert_eq!(
            resolve_gate(None, None),
            (true, "default"),
        );
    }

    /// 百分位：单元素 / 空 / 均匀序列 p50、p95。
    #[test]
    fn r77d_percentile_basic() {
        assert_eq!(percentile(&[], 0.5), 0.0, "空 → 0");
        assert_eq!(percentile(&[42.0], 0.5), 42.0);
        assert_eq!(percentile(&[42.0], 0.95), 42.0);
        // 1..=100 → p50=50（索引 (100-1)*0.5=49.5→49 → 50），p95=95（94.05→94 → 95）。
        let v: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        assert_eq!(percentile(&v, 0.5), 50.0);
        assert_eq!(percentile(&v, 0.95), 95.0);
        assert_eq!(percentile(&v, 0.0), 1.0, "p0 = 最小值");
        assert_eq!(percentile(&v, 1.0), 100.0, "p1 = 最大值");
        // 乱序输入与有序等价（内部排序）。
        let mut shuffled = v.clone();
        shuffled.reverse();
        assert_eq!(percentile(&shuffled, 0.95), 95.0);
    }

    /// 百分位：p 越界钳制（<0 / >1）。
    #[test]
    fn r77d_percentile_clamp() {
        let v = vec![10.0, 20.0, 30.0];
        assert_eq!(percentile(&v, -1.0), 10.0);
        assert_eq!(percentile(&v, 2.0), 30.0);
    }

    /// epoch 量级判定：会话相对 pts（小值）vs 墙钟 epoch（大值）。
    #[test]
    fn r77d_epoch_ts_detection() {
        assert!(!is_epoch_ts(0), "未携带（0）");
        assert!(!is_epoch_ts(1_000), "会话相对小 pts");
        assert!(!is_epoch_ts(999_999_999_999), "恰好 1e12 以下");
        assert!(is_epoch_ts(1_700_000_000_000), "epoch 毫秒");
        assert!(is_epoch_ts(u64::MAX));
    }

    /// 环形容量：超限丢最旧（新样本留在尾部）。
    ///
    /// 注：用 `Stage::Decode` 槽（本模块其它单测不写该槽——全局注册表
    /// 进程级共享，并行测试须槽隔离）。
    #[test]
    fn r77d_stage_cap_eviction() {
        // 直测环形缓冲（record_internal 绕进程级 env 门控）。
        for i in 0..=STAGE_CAP as u64 {
            record_internal(Stage::Decode, i as f64);
        }
        let snap = snapshot();
        let x = snap.iter().find(|s| s.stage == Stage::Decode).unwrap();
        assert_eq!(x.n, STAGE_CAP, "容量上限");
        // 最旧（i=0 被逐出）：最小值应为 1.0；最新在尾部。
        // 注意：锁卫兵必须在本块内 drop——后续 record_internal/snapshot
        // 会再取同一把非重入 Mutex，跨调用持锁 = 自死锁。
        let v: Vec<f64> = {
            let r = registry().lock().unwrap();
            r[Stage::Decode as usize].q.iter().copied().collect()
        };
        assert_eq!(*v.first().unwrap(), 1.0, "最旧样本被逐出");
        assert_eq!(*v.last().unwrap(), STAGE_CAP as f64);
        // 负值不落（record_internal 自身也防御时钟回拨）。
        let n_before = x.n;
        record_internal(Stage::Decode, -5.0);
        assert_eq!(
            snapshot().iter().find(|s| s.stage == Stage::Decode).unwrap().n,
            n_before
        );
    }

    /// 负值（时钟回拨防御）不 panic 不落样本（与门控态无关：`record` 对
    /// `ms < 0` 恒提前返回）。
    ///
    /// `KIRIN_DATA_DIR` 隔离目录下无配置文件 → 落内置默认开）门控态 =
    /// **default-on**，旧「测试环境默认门控关闭 → record 无副作用」前提
    /// 退役；关态决策语义由纯函数 `resolve_gate` 钉死（r81e 族：
    /// `resolve_gate(None, Some(false)) → off`、`resolve_gate(Some("0"), _)
    /// → off`；`record` 在 `enabled()=false` 时单分支提前返回）。
    #[test]
    fn r77d_negative_and_gate() {
        let enc_n = |snap: &[StageSummary]| {
            snap.iter()
                .filter(|s| s.stage == Stage::Enc)
                .map(|s| s.n)
                .sum::<usize>()
        };
        // 负值不 panic、不落样本（无论门控开/关）。
        let before = enc_n(&snapshot());
        record(Stage::Enc, -1.0);
        record(Stage::Enc, -5.5);
        assert_eq!(enc_n(&snapshot()), before, "负值不 panic 不落样本");
    }

    /// 快照不消费样本（两次一致）+ 段名不重复。
    ///
    /// 注：非消费断言只看 `Stage::E2E`（本模块其它单测不写该槽——并行
    /// 测试槽隔离）；段名唯一性对全表断言（只读，无竞态）。
    #[test]
    fn r77d_snapshot_non_draining() {
        let e2e_n = |snap: &[StageSummary]| {
            snap.iter()
                .filter(|s| s.stage == Stage::E2E)
                .map(|s| s.n)
                .sum::<usize>()
        };
        let a = snapshot();
        let b = snapshot();
        assert_eq!(e2e_n(&a), e2e_n(&b), "快照不得消费样本");
        let names: Vec<&str> = a.iter().map(|s| stage_name(s.stage)).collect();
        let mut u = names.clone();
        u.sort_unstable();
        u.dedup();
        assert_eq!(names.len(), u.len(), "段名唯一");
    }


    /// 前 3 帧全量：密集到达（间隔 0/1/2ms）前 3 帧恒输出，第 4/5 帧节流
    /// （未过 1000ms 窗）；全量窗输出计数=3。
    #[test]
    fn r123_throttle_burst_first3() {
        let mut st = R123ThrottleState::default();
        assert!(r123_throttle_step(&mut st, 0), "第 1 帧全量");
        assert!(r123_throttle_step(&mut st, 1), "第 2 帧全量");
        assert!(r123_throttle_step(&mut st, 2), "第 3 帧全量");
        assert!(!r123_throttle_step(&mut st, 3), "第 4 帧节流（+1ms < 1000ms）");
        assert!(!r123_throttle_step(&mut st, 500), "第 5 帧节流（+498ms < 1000ms）");
        assert_eq!(st.emitted, 3, "全量窗后输出计数停在 3");
        assert_eq!(st.last_emit_ms, 2, "锚点=最后输出帧（第 3 帧）时刻");
    }

    /// 节流窗 + 未输出不重置：全量窗后 500/999ms 帧被节流且**不重置锚点**
    /// → 自锚点满 1000ms 的帧（t=1000+1000 相对锚点）输出；输出后窗重新
    /// 起算（紧随的帧又被节流）。
    #[test]
    fn r123_throttle_window_no_reset_on_suppressed() {
        let mut st = R123ThrottleState::default();
        // 全量窗：t=0/1/2 输出（锚点=2）。
        for t in 0..3u64 {
            assert!(r123_throttle_step(&mut st, t));
        }
        // 锚点=2：t=502（+500）/t=1001（+999）节流；被节流帧不重置锚点。
        assert!(!r123_throttle_step(&mut st, 502), "+500ms 节流");
        assert!(!r123_throttle_step(&mut st, 1001), "+999ms 节流");
        assert_eq!(st.last_emit_ms, 2, "被节流帧不得重置锚点");
        // t=1002（+1000 恰满）→ 输出，锚点推进 1002。
        assert!(r123_throttle_step(&mut st, 1002), "+1000ms 恰满输出");
        assert_eq!(st.last_emit_ms, 1002);
        // 紧随帧（+1ms）窗重新起算 → 节流。
        assert!(!r123_throttle_step(&mut st, 1003), "输出后窗重新起算");
        assert!(r123_throttle_step(&mut st, 2002), "下一秒输出");
    }

    /// 时钟回拨防御：锚点推进后 now 回落到锚点之前 → elapsed 饱和 0 →
    /// 不输出、不动锚点、无 panic；时钟追上（now ≥ 锚点+1000）恢复输出。
    /// 全量窗内回拨同理（锚点仅单调非降）。
    #[test]
    fn r123_throttle_clock_rewind() {
        let mut st = R123ThrottleState::default();
        for t in [0u64, 1, 2] {
            assert!(r123_throttle_step(&mut st, t));
        }
        // 回拨至锚点（2）之前：t=0/1 → 节流且锚点不动。
        assert!(!r123_throttle_step(&mut st, 0), "回拨 now<锚点 → 节流");
        assert!(!r123_throttle_step(&mut st, 1));
        assert_eq!(st.last_emit_ms, 2, "回拨不得回退锚点");
        assert_eq!(st.emitted, 3, "回拨帧不得计入输出计数");
        // 时钟追上：t=2002（+1000）→ 恢复输出。
        assert!(r123_throttle_step(&mut st, 2002), "时钟追上后恢复输出");
        // 全量窗内回拨：新状态，第 2 帧时刻早于第 1 帧 → 锚点不回退。
        let mut st2 = R123ThrottleState::default();
        assert!(r123_throttle_step(&mut st2, 5000));
        assert!(r123_throttle_step(&mut st2, 100), "全量窗恒输出（含回拨时刻）");
        assert_eq!(st2.last_emit_ms, 5000, "全量窗锚点仅 max 推进");
    }

    /// 多流独立：不同 (session_id, stream) 键各自独立全量窗/节流窗（经
    /// 注册表入口 `r123_step`）；键构成 `session_id<<8|stream` 不碰撞
    /// （会话 1 的 vid ≠ 会话 0 的 snd 高位混叠形态）。
    #[test]
    fn r123_throttle_multi_stream_independent() {
        // 键构成不碰撞（stream 仅占低 8 位）。
        assert_eq!(r123_stream_key(1, R123_STREAM_VID), (1u64 << 8) | 0);
        assert_eq!(r123_stream_key(0, R123_STREAM_SND), 1);
        assert_ne!(
            r123_stream_key(1, R123_STREAM_VID),
            r123_stream_key(0, R123_STREAM_SND)
        );
        assert_ne!(
            r123_stream_key(0, R123_STREAM_IN),
            r123_stream_key(0, R123_STREAM_VID)
        );
        // 注册表入口：门控关 → 恒 false（零状态触碰；测试进程门控态不定
        // ——此处只断言纯函数面 + 键隔离，门控语义由 r81e 族钉死）。
        if !enabled() {
            assert!(!r123_step(9100, R123_STREAM_IN, 0));
            return;
        }
        // 三流同刻密集到达：各自前 3 全量、第 4 帧各自节流，互不串扰。
        let a = (9101u64, R123_STREAM_IN);
        let b = (9102u64, R123_STREAM_IN);
        let c = (0u64, R123_STREAM_VID);
        for i in 0..5u64 {
            for &(sid, stream) in [&a, &b, &c] {
                let expect = i < 3;
                assert_eq!(
                    r123_step(sid, stream, i),
                    expect,
                    "流 ({sid},{stream}) 第 {i} 帧（i<3 全量，否则节流）"
                );
            }
        }
        // 1s 后：三流各自独立恢复输出（各自的窗各自起算）。
        assert!(r123_step(a.0, a.1, 1000 + 2));
        assert!(r123_step(b.0, b.1, 1000 + 2));
        assert!(r123_step(c.0, c.1, 1000 + 2));
        // 紧随帧再节流（各自锚点各自 1002）。
        assert!(!r123_step(a.0, a.1, 1003 + 2));
        assert!(!r123_step(b.0, b.1, 1003 + 2));
        assert!(!r123_step(c.0, c.1, 1003 + 2));
    }

    /// srv-in 行 `ev` 短码：8 类事件全表钉死（防再开/防误改）。
    #[test]
    fn r123_ev_tag_matrix() {
        use kirin_desk_input::injector::InputKind as K;
        assert_eq!(r123_ev_tag(&K::MouseMove), "mm");
        assert_eq!(r123_ev_tag(&K::MouseButton), "mb");
        assert_eq!(r123_ev_tag(&K::MouseWheel), "mw");
        assert_eq!(r123_ev_tag(&K::KeyDown), "kd");
        assert_eq!(r123_ev_tag(&K::KeyUp), "ku");
        assert_eq!(r123_ev_tag(&K::KeyRepeat), "kr");
        assert_eq!(r123_ev_tag(&K::Text), "tx");
        assert_eq!(r123_ev_tag(&K::SpecialKey), "sk");
    }


    /// 钉死——五盲区键 vk/scan 对账 + 非键事件零身份 + 扩展前缀四位数形态 +
    /// 未覆盖 `-`）。
    #[test]
    fn r129_key_vk_scan_and_fmt() {
        use kirin_desk_input::injector::{InputEvent, InputKind as K, Key};
        // 五盲区键 wire 判别式 → (VK, scan)：CapsLock(0x39) / KpMultiply(0x66)
        // / KpDecimal(0x67) / NumLock(0x68) / Super(0x56)。
        let ev = InputEvent::key(K::KeyDown, Key::CapsLock, 0);
        // 为常量错位，`windows::map_vk` 本岗修）。
        assert_eq!(r123_key_vk_scan(&ev), (Some(0x14), Some(0x3A)));
        let ev = InputEvent::key(K::KeyUp, Key::KpMultiply, 0);
        assert_eq!(r123_key_vk_scan(&ev), (Some(0x6A), Some(0x37)));
        let ev = InputEvent::key(K::KeyDown, Key::KpDecimal, 0);
        assert_eq!(r123_key_vk_scan(&ev), (Some(0x6E), Some(0x53)));
        let ev = InputEvent::key(K::KeyRepeat, Key::NumLock, 0);
        assert_eq!(r123_key_vk_scan(&ev), (Some(0x90), Some(0x45)));
        let ev = InputEvent::key(K::KeyDown, Key::Super, 0);
        assert_eq!(r123_key_vk_scan(&ev), (Some(0x5B), Some(0xE05B)));
        // 非键事件：无单键身份 → 双 None。
        assert_eq!(r123_key_vk_scan(&InputEvent::mouse_move(1, 2)), (None, None));
        assert_eq!(r123_key_vk_scan(&InputEvent::text("x")), (None, None));
        // 格式化：None → `-`；非扩展两位；扩展前缀（≥0x100）四位大写。
        assert_eq!(r123_fmt_code(None), "-");
        assert_eq!(r123_fmt_code(Some(0x3A)), "0x3A");
        assert_eq!(r123_fmt_code(Some(0x1A)), "0x1A");
        assert_eq!(r123_fmt_code(Some(0xE05B)), "0xE05B");
        assert_eq!(r123_fmt_code(Some(0x6A)), "0x6A");
    }


    /// 新帧+可见 → true（立即请求重绘，不等 16ms 泵）/ 无新帧 → false
    /// 口径）。
    #[test]
    fn r123_repaint_decision_matrix() {
        assert!(
            r123_repaint_decision(true, true),
            "新帧 + 可见 → 触发（帧到达即呈现）"
        );
        assert!(
            !r123_repaint_decision(false, true),
            "无新帧（解码器零产出）→ 不触发"
        );
        assert!(
            !r123_repaint_decision(true, false),
        );
        assert!(
            !r123_repaint_decision(false, false),
            "无新帧 + 隐藏 → 不触发"
        );
    }

    /// cli-* 与 session 0/1 的 srv-* 两两相异，cli-* 内部亦两两相异）。
    #[test]
    fn r123_client_stream_keys_no_collision() {
        let cli = [
            R123_STREAM_CLI_RCV,
            R123_STREAM_CLI_DEC,
            R123_STREAM_CLI_RND,
            R123_STREAM_CLI_IN,
        ];
        let srv = [R123_STREAM_VID, R123_STREAM_SND, R123_STREAM_IN];
        for c in cli {
            for s in srv {
                assert_ne!(r123_stream_key(0, c), r123_stream_key(0, s));
            }
        }
        for (i, a) in cli.iter().enumerate() {
            for b in cli.iter().skip(i + 1) {
                assert_ne!(r123_stream_key(0, *a), r123_stream_key(0, *b));
            }
        }
        // 会话维度：会话 1 的 cli-rcv ≠ 会话 0 的 cli-dec（无高位混叠）。
        assert_ne!(
            r123_stream_key(1, R123_STREAM_CLI_RCV),
            r123_stream_key(0, R123_STREAM_CLI_DEC)
        );
    }


    #[test]
    fn r135_10_bias_delta_floor_anchor() {
        assert_eq!(r135_10_bias_delta_iter(std::iter::empty()), None, "空窗 → None");
        let short: Vec<i64> = vec![-31_460; R135_10_BIAS_MIN_SAMPLES - 1];
        assert_eq!(
            r135_10_bias_delta_iter(short.iter().copied()),
            None,
            "不足最小样本数 → None"
        );
        // 09-23 分布口径回放（报告 §3/§4）：wire p50≈5/p95≈45，Δ≈−31460
        // → raw ≈ wire + Δ（全负；floor 锚 = 最快帧零点）。
        let win: Vec<i64> = [5i64, 45, 12, 3, 18, 41, 7, 22, 9, 38, 6, 15]
            .into_iter()
            .map(|w| w - 31460)
            .collect();
        assert_eq!(
            r135_10_bias_delta_iter(win.iter().copied()),
            Some(3 - 31460),
            "floor = min(raw) = Δ + min(wire)"
        );
        // 时钟步进自愈：全窗 +1_000_000（NTP 前跳 1 小时）→ min 平移。
        let stepped: Vec<i64> = win.iter().map(|v| v + 1_000_000).collect();
        assert_eq!(
            r135_10_bias_delta_iter(stepped.iter().copied()),
            Some(3 - 31460 + 1_000_000),
            "滚动窗对时钟步进平移自愈"
        );
    }

    /// Negative（显式丢弃，禁 saturating 吞零）。
    #[test]
    fn r135_10_calibrate_three_state() {
        assert_eq!(
            r135_10_calibrate(-31455, Some(-31460)),
            R135_10Calib::Ok(5),
            "raw−Δ = wire 正值 → 可记录"
        );
        assert_eq!(
            r135_10_calibrate(-31460, Some(-31460)),
            R135_10Calib::Ok(0),
            "恰零点 → Ok(0)（非 Negative）"
        );
        assert_eq!(
            r135_10_calibrate(-31461, Some(-31460)),
            R135_10Calib::Negative {
                raw: -31461,
                delta: -31460
            },
            "负校准值 → 显式丢弃态（非静默 0）"
        );
        assert_eq!(
            r135_10_calibrate(-31455, None),
            R135_10Calib::PreAnchor,
            "未锚定 → 跳过采样"
        );
    }

    /// （滚动 min 抖动 < reanchor 阈值）/ 再锚定沿（|Δ 变化| ≥ 阈值）。
    #[test]
    fn r135_10_bias_observe_state_machine() {
        let mut st = R135_10BiasCalib::default();
        // 前 7 样本：未锚定、零事件。
        for i in 0..(R135_10_BIAS_MIN_SAMPLES - 1) {
            let (d, e) = st.observe(-31460 + i as i64);
            assert_eq!(d, None, "锚定前 Δ=None");
            assert_eq!(e, R135_10BiasEvent::None);
        }
        // 第 8 样本：锚定沿（Δ = 窗 min = −31460）。
        let (d, e) = st.observe(-31452);
        assert_eq!(d, Some(-31460));
        assert_eq!(e, R135_10BiasEvent::Anchored);
        assert_eq!(st.pre_skip(), 0, "pre_skip 仅由调用点采样侧计数");
        // 常态：wire 宽度内 min 微动（<100ms）→ 零事件、旧锚保留。
        for i in 0..20i64 {
            let (_, e) = st.observe(-31460 + 40 + i); // min 可能上移但 <100
            assert_eq!(e, R135_10BiasEvent::None, "窗口内常态零 reanchor 事件");
        }
        // 时钟步进 +500ms：旧窗样本逐一滑出（滚动窗 64 槽）→ 窗 min 先
        // 逐 +1ms 爬升（diff < 100 → 零事件）→ 旧样本全出后 min 跳至新
        // epoch → |Δ 变化| = 500 ≥ 100 → reanchored 沿（自愈定案位）。
        let mut saw_reanchor = false;
        for k in 0..(R135_10_BIAS_WIN + 1) {
            let (_, e) = st.observe(-31460 + 500 + (k % 20) as i64);
            match e {
                R135_10BiasEvent::Reanchored { prev } => {
                    assert_eq!(prev, -31460, "reanchor prev = 旧锚");
                    saw_reanchor = true;
                    break;
                }
                R135_10BiasEvent::None => {}
                R135_10BiasEvent::Anchored => panic!("再锚不得重发 Anchored"),
            }
        }
        assert!(saw_reanchor, "时钟步进后滚动窗必然再锚定");
        assert_eq!(
            st.delta(),
            Some(-31460 + 500),
            "再锚定 Δ = 新窗 min（全样本 ≥ 新 epoch 起点）"
        );
    }

    #[test]
    fn r135_10_bias_line_format_pinned() {
        assert_eq!(
            r135_10_bias_anchored_line(7, -31460, 64, 12),
        );
        assert_eq!(
            r135_10_bias_reanchored_line(7, -31460, -30960, 80),
        );
        assert_eq!(
            r135_10_xfer_neg_line(7, "xfer", -31461, -31460, 1),
        );
        assert_eq!(
            r135_10_xfer_neg_line(9, "e2e", -5, -4, 1000),
        );
    }

    /// 稳态 30 连回 1 / 孤立毛刺不误升。
    #[test]
    fn r135_10_jitter_tick_state_machine() {
        let mut st = R135_10JitterState::default();
        // 初始：首样本（j=0）→ 归一 1（无沿事件：归一非深度变化）。
        assert_eq!(r135_10_jitter_tick(&mut st, 0), None);
        assert_eq!(st.depth, R135_10_JIT_MIN, "初始归一 = LAN 稳态目标 1");
        // 孤立毛刺（j=2 单帧）→ 不升（streak 未达 2）。
        assert_eq!(r135_10_jitter_tick(&mut st, 2), None);
        assert_eq!(r135_10_jitter_tick(&mut st, 0), None, "毛刺后重置 streak");
        assert_eq!(st.depth, 1);
        // 尾部两连（j≥2 × 2）→ 升 2。
        assert_eq!(r135_10_jitter_tick(&mut st, 2), None);
        assert_eq!(
            r135_10_jitter_tick(&mut st, 3),
            Some((1, 2, "tail")),
            "第 2 连尾部证据 → 升 2"
        );
        assert_eq!(st.depth, R135_10_JIT_MAX);
        // depth=2：j≤1 未达 30 连 → 保持。
        for _ in 0..(R135_10_JIT_LOWER_STREAK - 1) {
            assert_eq!(r135_10_jitter_tick(&mut st, 1), None);
        }
        // 期间一次 j=2 打断稳态计数 → 重新累计（不回 1）。
        assert_eq!(r135_10_jitter_tick(&mut st, 2), None);
        assert_eq!(st.depth, 2, "稳态计数被尾部打断不得回 1");
        let mut last = None;
        for _ in 0..R135_10_JIT_LOWER_STREAK {
            last = r135_10_jitter_tick(&mut st, 0);
        }
        assert_eq!(last, Some((2, 1, "stable")), "30 连稳态 → 回 1");
        assert_eq!(st.depth, 1);
        // depth=1 时稳态计数不得触发沿（只有尾部可升）。
        for _ in 0..(R135_10_JIT_LOWER_STREAK + 10) {
            assert_eq!(r135_10_jitter_tick(&mut st, 0), None);
        }
        assert_eq!(st.depth, 1);
    }

    #[test]
    fn r135_10_jitter_line_format_pinned() {
        assert_eq!(
            r135_10_jitter_line(3, 1, 2, "tail", 2),
        );
        assert_eq!(
            r135_10_jitter_line(3, 2, 1, "stable", 0),
        );
    }

    /// A（长通过已完成入环 → pass_max ≈ dec_commit）/ 尖峰形态 B（泵停摆 →
    /// 尾间隔 ≈ dec_commit）/ 回拨对 gap 跳过 / 前跳样本排除 / 空环全零。
    #[test]
    fn r135_10_ui1s_ctx_summary() {
        let now = 1_000_000u64;
        // 常态：@60fps 前 1s 循环（16ms 间隔，末条起点 now-12）。
        let mut ring = VecDeque::new();
        for i in (0..60u64).rev() {
            ring.push_back(R135_10PumpSample {
                start_ms: now - 12 - i * 16,
                pass_ms: 16,
                ev_n: 1,
            });
        }
        let ctx = r135_10_ui1s_ctx(&ring, now);
        assert_eq!(ctx.n, 60, "前 1s 窗循环数");
        assert_eq!(ctx.pass_max_ms, 16, "常态单循环通过上界");
        // gap_max = max(循环间隔 16〔泵周期〕, 尾间隔 12) = 16——健康泵基线
        // gap 恰为泵周期；尖峰（停摆/长通过）= gap 远超本值才可归因。
        assert_eq!(ctx.gap_max_ms, 16, "gap_max = 泵周期基线（循环间隔 > 尾间隔 12）");
        assert_eq!(ctx.ev_sum, 60);
        // 形态 A：2054ms 长通过作为**已完成循环**入环（起点 now-2060）+
        // 其前 4 个正常循环（尖峰窗退化：前 1s 内无循环，靠最近 4 条保底）。
        let mut ring_a = VecDeque::new();
        for i in (0..4u64).rev() {
            ring_a.push_back(R135_10PumpSample {
                start_ms: now - 2060 - 16 - i * 16,
                pass_ms: 16,
                ev_n: 0,
            });
        }
        ring_a.push_back(R135_10PumpSample {
            start_ms: now - 2060,
            pass_ms: 2054,
            ev_n: 0,
        });
        let ctx_a = r135_10_ui1s_ctx(&ring_a, now);
        assert_eq!(ctx_a.n, 4, "最近 4 条保底（含长通过条；最旧 1 条出窗）");
        assert_eq!(ctx_a.pass_max_ms, 2054, "trap 家族归因位（pass_max ≈ dec_commit）");
        assert_eq!(ctx_a.gap_max_ms, 2060, "尾间隔 ≈ 长通过起点距");
        // 形态 B：泵停摆——末条完成循环在 now-2070（16ms 正常通过），
        // 其后 2070ms 零循环。
        let mut ring_b = VecDeque::new();
        for i in (0..4u64).rev() {
            ring_b.push_back(R135_10PumpSample {
                start_ms: now - 2070 - i * 16,
                pass_ms: 16,
                ev_n: 0,
            });
        }
        let ctx_b = r135_10_ui1s_ctx(&ring_b, now);
        assert_eq!(ctx_b.n, 4);
        assert_eq!(ctx_b.pass_max_ms, 16, "停摆形态通过正常");
        assert_eq!(ctx_b.gap_max_ms, 2070, "泵未调度归因位（尾间隔 ≈ dec_commit）");
        // 回拨对：后条 start 早于前条 → gap 跳过（不污染 gap_max）。
        let mut ring_c = VecDeque::new();
        ring_c.push_back(R135_10PumpSample { start_ms: now - 500, pass_ms: 10, ev_n: 0 });
        ring_c.push_back(R135_10PumpSample { start_ms: now - 800, pass_ms: 10, ev_n: 0 });
        let ctx_c = r135_10_ui1s_ctx(&ring_c, now);
        assert_eq!(ctx_c.n, 2);
        assert_eq!(ctx_c.gap_max_ms, 500, "回拨对 gap 跳过，尾间隔 = 500（最晚起点）");
        // 前跳样本（start > now）排除。
        let mut ring_d = ring_c.clone();
        ring_d.push_back(R135_10PumpSample { start_ms: now + 50, pass_ms: 999, ev_n: 9 });
        let ctx_d = r135_10_ui1s_ctx(&ring_d, now);
        assert_eq!(ctx_d.n, 2, "前跳样本不计入");
        assert_eq!(ctx_d.ev_sum, 0);
        // 空环 = 全零（首帧/清槽后）。
        let empty = r135_10_ui1s_ctx(&VecDeque::new(), now);
        assert_eq!(empty, R135_10Ui1sCtx::default());
    }

    #[test]
    fn r135_10_stall_line_format_pinned() {
        let ctx = R135_10Ui1sCtx {
            n: 3,
            pass_sum_ms: 2082,
            pass_max_ms: 2054,
            gap_max_ms: 17,
            ev_sum: 7,
        };
        assert_eq!(
            r135_10_stall_line(5, 28293, 2054, &ctx),
             n1s=3 pass_sum=2082ms pass_max=2054ms gap_max=17ms ev1s=7"
        );
        // 阈值语义（调用点判定式 `dec_commit > R135_10_STALL_MS` 同式
        // 复现——恰好 500 不触发、501 触发）：
        let fire = |dec_commit: u64| dec_commit > R135_10_STALL_MS;
        assert!(!fire(R135_10_STALL_MS), "恰 500ms 不触发（> 严格大于）");
        assert!(fire(R135_10_STALL_MS + 1), "501ms 触发");
    }

    /// 本地段流一并入列钉死）。
    #[test]
    fn r135_10_stream_keys_no_collision() {
        let streams = [
            R123_STREAM_VID, R123_STREAM_SND, R123_STREAM_IN, R123_STREAM_CLI_RCV,
            R123_STREAM_CLI_DEC, R123_STREAM_CLI_RND, R123_STREAM_CLI_IN, R133_STREAM_TBW,
            R135_STREAM_BIAS, R135_STREAM_JITTER, R135_STREAM_STALL, R137_STREAM_LOCAL_SEG,
        ];
        for (i, a) in streams.iter().enumerate() {
            for b in streams.iter().skip(i + 1) {
                assert_ne!(a, b, "流常量两两相异");
                assert_ne!(
                    r123_stream_key(1, *a),
                    r123_stream_key(0, *b),
                    "跨会话键不混叠"
                );
            }
        }
    }


    /// 有已完成样本 → `now − (样本 start + pass)`（saturating 防回拨）。
    #[test]
    fn r137_7_frame_gap_helper() {
        // 测试专用会话号（注册表按 sid 键控；收尾清槽防跨测试残留）。
        let sid = 990_001u64;
        assert_eq!(r135_10_frame_gap_ms(sid, 1_000), 0, "无环 → 0");
        // 守卫 Drop 落一条已完成样本 → gap = now − (start + pass)。
        let _g = R135_10PumpCycleGuard::new(sid, 1);
        drop(_g);
        let now = epoch_ms();
        let (start_ms, pass_ms) = {
            let m = r135_10_pump_registry().lock().unwrap();
            let s = m.get(&sid).unwrap().back().unwrap();
            (s.start_ms, s.pass_ms)
        };
        let expect = now.saturating_sub(start_ms.saturating_add(pass_ms));
        assert_eq!(r135_10_frame_gap_ms(sid, now), expect);
        // now 早于完成点（时钟回拨形态）→ saturating = 0（不产生 u64 下溢）。
        assert_eq!(r135_10_frame_gap_ms(sid, 0), 0, "回拨 → 0 不 panic");
        r135_10_session_cleanup(sid);
    }
}
