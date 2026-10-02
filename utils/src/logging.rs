//! Logging system with auto-rotating file output, log cleanup,
//! and optional in-memory buffer for GUI display.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing::{debug, info};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::prelude::*;

/// Local time formatter using chrono (system local time, not UTC).
struct LocalTimer;
impl FormatTime for LocalTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        use chrono::Local;
        write!(w, "{}", Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"))
    }
}

/// Default log directory: `$KIRIN_DATA_DIR/logs/`（env 已设且非空白时），
/// 否则 `~/.kirin_desk/logs/`。
///
/// T04 起），日志仍恒追加真实 `~/.kirin_desk/logs/`（历波哨兵例外的源头；
/// audit.log 亦经本函数派生，同被根治）。口径与 [`crate::config::Config::config_dir`]
/// **逐位不变**（生产零变化）；设了 → `<env>/logs`。
pub fn default_log_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("KIRIN_DATA_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir).join("logs");
        }
    }
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kirin_desk")
        .join("logs")
}

/// Default number of days to keep log files.
pub const DEFAULT_KEEP_DAYS: u64 = 7;

/// Default total size cap (bytes) for all managed log files
/// (`kirindesk-*.log`). 启动/跨日轮转点清理：总大小超过上限后按日期从旧到新
/// 删除（保留今日文件），防止日志无界增长耗尽磁盘。
pub const DEFAULT_MAX_LOG_BYTES: u64 = 50 * 1024 * 1024; // 50 MiB

/// 受管日志文件命名约定（外部兼容，勿改）：`kirindesk-YYYY-MM-DD.log`。
const LOG_FILE_PREFIX: &str = "kirindesk-";
const LOG_FILE_SUFFIX: &str = ".log";

///
/// 每 60s 一行 `info!("[heartbeat]")`：把「死亡窗口」从 09-15 22:04 原生硬崩溃
/// 实证的 23.5s 夹到 ≤60s（末次心跳 → 下进程启动行 = 精确死亡区间）。
pub const HEARTBEAT_INTERVAL_SECS: u64 = 60;

/// 匹配 → 心跳关；未设/空值/其它值 → 开）。
pub const HEARTBEAT_ENV: &str = "KIRIN_LOG_HEARTBEAT";

///
/// `raw` = env 原值（`None` = 未设）。口径：**fail-open**——仅 `0`/`off`/`false`
/// 三值（大小写不敏感、`trim` 后）判关；其余（含未设/空白/任意其它串）判开
/// （心跳是低频观测，误配置不应使其静默失效）。
pub fn heartbeat_enabled(raw: Option<&str>) -> bool {
    !matches!(
        raw.map(str::trim).map(|v| v.to_ascii_lowercase()).as_deref(),
        Some("0") | Some("off") | Some("false")
    )
}

/// 「每进程一套 writer / 一条 banner」同口径；重复 init 调用不重复起线程）。
static HEARTBEAT_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

///
/// 线程每 [`HEARTBEAT_INTERVAL_SECS`] 秒 `info!("[heartbeat]")` 一行（经全局
/// subscriber 落主日志/控制台/GUI 缓冲——与既有 banner 行同路）。正常进程退出
/// （主线程返回 / `process::exit`）连同收割本线程——**无需 join、退出路径
/// 不起线程并留一行 debug 对账。
fn spawn_heartbeat_once() {
    use std::sync::atomic::Ordering;
    if HEARTBEAT_STARTED.swap(true, Ordering::SeqCst) {
        return; // 本进程已有心跳（或已被逃生口否决）
    }
    if !heartbeat_enabled(std::env::var(HEARTBEAT_ENV).ok().as_deref()) {
        return;
    }
    let ok = std::thread::Builder::new()
        .name("kirin-logger-heartbeat".into())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
            info!("[heartbeat]");
        })
        .is_ok();
    if !ok {
    }
}

/// GUI 主循环结束 `run()` 尾 / CLI 正常退出——三处均经本函数单点输出）。
///
/// 与心跳配对圈定「死亡窗口」：末次 `[heartbeat]` → 本行 `logger stopping`
/// → 下一进程 `KirinDesk logger started` = 精确死亡区间（09-15 22:04 事件
/// 的 23.5s 盲区即「无收尾行 + 无心跳」所致）。
pub fn log_stopping() {
    info!("logger stopping");
}

/// A thread-safe ring buffer of log lines for GUI display.
/// Stores at most `capacity` lines, dropping oldest first.
pub struct LogBuffer {
    inner: Mutex<LogBufferInner>,
}

struct LogBufferInner {
    lines: VecDeque<String>,
    /// UI 侧增量拉取 [`LogBuffer::drain_after`] 的水位基准（`all()` 无法
    /// 表达「自上次读取后的新增」，连接页日志框错误行通道消费）。
    seqs: VecDeque<u64>,
    next_seq: u64,
    capacity: usize,
}

impl LogBuffer {
    /// Create a new buffer with the given capacity.
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(LogBufferInner {
                lines: VecDeque::with_capacity(capacity),
                seqs: VecDeque::with_capacity(capacity),
                // ——初始水位 0 必须能拉到 seq 首行，0 基会与首行冲突丢行）。
                next_seq: 1,
                capacity,
            }),
        })
    }

    /// Push a line (appended by a newline) into the buffer.
    pub fn push(&self, line: String) {
        let mut inner = self.inner.lock().unwrap();
        let seq = inner.next_seq;
        inner.next_seq += 1;
        while inner.lines.len() >= inner.capacity {
            inner.lines.pop_front();
            inner.seqs.pop_front();
        }
        inner.lines.push_back(line);
        inner.seqs.push_back(seq);
    }

    /// 最后返回行的 seq（无新行 = 水位不动）。
    ///
    /// 三种情形：
    /// - 空缓冲 → 水位对齐至已发放 seq（防 clear/全逐出后重拉洪泛），返回空；
    /// - **水位落后于环最旧行**（UI 长时间未取行、环已逐出缺口段）→ resync：
    ///   返回当前全部行（日志框补最近上下文，文件日志为全量权威），水位 = 最新 seq；
    /// - 水位在环内 → 仅返回新增段（正常每帧路径）。
    pub fn drain_after(&self, last: &mut u64) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        if inner.lines.is_empty() {
            *last = inner.next_seq.saturating_sub(1);
            return Vec::new();
        }
        let oldest = inner.seqs[0];
        if *last + 1 < oldest {
            // resync（缺口已不可达）。
            let out: Vec<String> = inner.lines.iter().cloned().collect();
            *last = *inner.seqs.back().expect("非空环必有最新 seq");
            return out;
        }
        let out: Vec<String> = inner
            .lines
            .iter()
            .zip(inner.seqs.iter())
            .filter(|(_, s)| **s > *last)
            .map(|(l, _)| l.clone())
            .collect();
        if !out.is_empty() {
            // seq 严格递增 → 返回段最大 seq = 环内 > *last 的末位。
            *last = *inner
                .seqs
                .iter()
                .rev()
                .find(|s| **s > *last)
                .expect("out 非空必有匹配 seq");
        }
        out
    }

    /// Return all current lines joined as a single string.
    pub fn all(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.lines.iter().map(|l| l.as_str()).collect::<Vec<_>>().join("")
    }

    /// M15-T008: 清空全部缓冲行（LogView「Clear」按钮用）。
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.lines.clear();
        inner.seqs.clear();
    }

    /// Return a shared reference (Arc) to self – convenience wrapper.
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

use std::sync::Arc;

/// 签名（level/format/dir/keep_days）。
///
/// tracing 全局 subscriber 每进程只能成功注册一次：重复 `init_logging*`
/// 执行到底，尾部 banner（`info!`）仍会经**既有** subscriber 发出 → 主日志/
/// 控制台多出一行 "KirinDesk logger started"（09-05 本机日志实证：self-test
/// 8 个会话的 info→debug 双 banner，根因 = `ui/src/cli.rs:4889` 二次 init；
/// 请求的 debug 级别实际从未生效，级别保持首次 init 值——banner 是误导性
/// 输出）。重复调用基于此状态短路，保证「每进程一套 writer / 一条 banner」，
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitSignature {
    level: String,
    format: String,
    dir: String,
    keep_days: u64,
}

static INIT_SIGNATURE: Mutex<Option<InitSignature>> = Mutex::new(None);

/// 「单 writer / 单 banner」对账与单测断言用。
pub fn init_signature() -> Option<InitSignature> {
    INIT_SIGNATURE.lock().ok().and_then(|s| s.clone())
}

/// Initialize the logging system with defaults.
pub fn init_logging(level: &str, format: &str) {
    init_logging_with(level, format, &default_log_dir(), DEFAULT_KEEP_DAYS, None);
}

/// Initialize logging with explicit settings and optional in-memory buffer.
pub fn init_logging_with(
    level: &str,
    format: &str,
    log_dir: &Path,
    keep_days: u64,
    gui_buffer: Option<Arc<LogBuffer>>,
) {
    // 不再静默）：eprintln CLI 侧可见；tracing 侧进文件（GUI 无控制台，日志
    // 视图对账）。已初始化后不重跑 cleanup/ensure、不再试 `try_init`（避免
    let requested = InitSignature {
        level: level.to_string(),
        format: format.to_string(),
        dir: log_dir.display().to_string(),
        keep_days,
    };
    {
        let guard = INIT_SIGNATURE.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(first) = guard.as_ref() {
            let note = if *first == requested {
                "same params (idempotent no-op)".to_string()
            } else {
                format!(
                    "params differ: requested level={} format={} dir={} keep_days={} — ignored",
                    requested.level, requested.format, requested.dir, requested.keep_days
                )
            };
            eprintln!(
                first.level, first.format, first.dir, first.keep_days
            );
            tracing::warn!(
                first.level, first.format, first.dir, first.keep_days
            );
            return;
        }
    }

    // Ensure log directory exists
    if let Err(e) = fs::create_dir_all(log_dir) {
        eprintln!("[logging] WARN: cannot create log dir {:?}: {}", log_dir, e);
    }

    // 不删今日文件，多实例安全）。
    cleanup_old_logs_with_limits(log_dir, keep_days, DEFAULT_MAX_LOG_BYTES);

    // **惰性**的（首个通过过滤的事件才开文件）：若启动后始终无事件达到
    // 阈值（级别过严 / `RUST_LOG` 全排除）或文件层未生效（`try_init` 失败，
    // 如全局 subscriber 已被先行注册），主日志文件全程不存在，而独立通道
    // audit.log 照常落盘 → 「主日志缺失」且无迹可查（2026-09-05 09:00 实测
    // 复现）。提前打开保证 init 即有文件；打开失败显式 stderr（CLI 侧可见；
    // GUI 子系统无控制台，靠 self-test / 日志视图对账），不再静默降级为
    if let Err(e) = ensure_main_log_file(log_dir) {
        eprintln!(
            log_dir
        );
    }

    // S-23（F-28）：`RUST_LOG` 超长上限提示 —— 超长过滤器串（> 4 KiB）
    // 可能是环境注入/误配置，直接忽略并回退默认级别（日志初始化零信任）。
    const RUST_LOG_MAX_LEN: usize = 4096;
    if std::env::var("RUST_LOG")
        .map(|v| v.len() > RUST_LOG_MAX_LEN)
        .unwrap_or(false)
    {
        eprintln!(
            "[logging] WARN: RUST_LOG exceeds {} chars — ignored, using level '{}' (S-23)",
            RUST_LOG_MAX_LEN, level
        );
    }
    let env_filter = match std::env::var("RUST_LOG") {
        Ok(v) if !v.is_empty() && v.len() <= RUST_LOG_MAX_LEN => {
            EnvFilter::try_new(&v).unwrap_or_else(|_| EnvFilter::new(level))
        }
        Ok(v) if !v.is_empty() => EnvFilter::new(level),
        _ => EnvFilter::new(level),
    };

    // Console layer (stderr)
    let timer = LocalTimer;
    let console_layer = fmt::layer()
        .compact()
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(true)
        .with_line_number(true)
        .with_timer(timer);

    // Build file writer（跨日轮转点清理复用调用方 keep_days 与默认总大小上限）
    let file_writer =
        RotatingFileWriter::new_with_limits(log_dir.to_path_buf(), keep_days, DEFAULT_MAX_LOG_BYTES);

    // Optional GUI buffer wrapper
    let writer = BufferedWriter::new(file_writer, gui_buffer);

    match format {
        "json" => {
            let json_layer = fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(true)
                .with_line_number(true)
                .with_ansi(false)
                .with_writer(writer);

            // 完全不生效）不再 `.ok()` 静默——显式 stderr 标记，避免「无主
            // 日志且无任何告警」的排查盲区。
            if tracing_subscriber::registry()
                .with(env_filter)
                .with(console_layer)
                .with(json_layer)
                .try_init()
                .is_err()
            {
                eprintln!(
                );
            }
        }
        _ => {
            let text_layer = fmt::layer()
                .compact()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(true)
                .with_line_number(true)
                .with_ansi(false)
                .with_timer(LocalTimer)
                .with_writer(writer);

            if tracing_subscriber::registry()
                .with(env_filter)
                .with(console_layer)
                .with(text_layer)
                .try_init()
                .is_err()
            {
                eprintln!(
                );
            }
        }
    }

    debug!(
        "Logging initialized: level={}, format={}, dir={:?}, keep_days={}",
        level, format, log_dir, keep_days
    );
    info!(
        // 是 early eof 排查主线索，日志自证版本后不再依赖口头确认部署版本。
        // git 不可用时 "unknown"）——同 version 不同构建（迭代波内多包）
        // 可判定双端各自部署构建号，复测对账不再依赖口头确认。
        "KirinDesk logger started (version={}, commit={}, RUST_LOG={}, logs at {:?})",
        env!("CARGO_PKG_VERSION"),
        env!("KIRIN_GIT_COMMIT"),
        std::env::var("RUST_LOG").unwrap_or_else(|_| level.to_string()),
        log_dir
    );

    // 重复调用均短路（含「全局已被外部 subscriber 占据」场景：重复调用同样
    let mut sig = INIT_SIGNATURE.lock().unwrap_or_else(|p| p.into_inner());
    if sig.is_none() {
        *sig = Some(requested);
    }

    spawn_heartbeat_once();
}

// ---------------------------------------------------------------------------
// Helper: composite writer: file + optional GUI in-memory buffer
// ---------------------------------------------------------------------------
struct BufferedWriter {
    file: RotatingFileWriter,
    gui: Option<Arc<LogBuffer>>,
}

impl BufferedWriter {
    fn new(file: RotatingFileWriter, gui: Option<Arc<LogBuffer>>) -> Self {
        Self { file, gui }
    }
}

impl<'a> fmt::MakeWriter<'a> for BufferedWriter {
    type Writer = BufferedGuard;

    fn make_writer(&'a self) -> Self::Writer {
        BufferedGuard {
            file: self.file.make_writer(),
            gui: self.gui.clone(),
            buf: Vec::new(),
        }
    }
}

struct BufferedGuard {
    file: RotatingFileGuard,
    gui: Option<Arc<LogBuffer>>,
    buf: Vec<u8>,
}

impl Write for BufferedGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Write to file
        let n = self.file.write(buf)?;
        // Buffer for GUI (capture full lines)
        self.buf.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        // Push buffered content as GUI lines (split on newline)
        if let Some(ref gui) = self.gui {
            let s = String::from_utf8_lossy(&self.buf);
            for line in s.lines() {
                if !line.is_empty() {
                    let clean = strip_ansi_escapes(line);
                    gui.push(clean + "\n");
                }
            }
        }
        self.buf.clear();
        Ok(())
    }
}

/// Remove ANSI escape sequences from a string.
fn strip_ansi_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until 'm' (end of ANSI escape)
            while let Some(n) = chars.next() {
                if n == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

/// 最近一次 panic 摘要（GUI 弹窗用；`take_panic_message` 消费一次后为 None）。
static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

/// 今日日志文件路径：`{log_dir}/kirindesk-{YYYY-MM-DD}.log`（与轮转文件命名一致）。
pub fn current_log_path(log_dir: &Path) -> PathBuf {
    log_dir.join(format!("kirindesk-{}.log", RotatingFileWriter::today()))
}

///
/// 主日志文件此前只在「首个通过过滤的事件」时打开（惰性）：级别过严 /
/// 文件层未生效（`try_init` 失败）时文件全程不存在，而独立通道 audit.log
/// 照常写入 → 排查盲区。提前打开（append 模式）保证 init 即有文件；
pub fn ensure_main_log_file(log_dir: &Path) -> io::Result<PathBuf> {
    let date = RotatingFileWriter::today();
    let path = log_dir.join(format!("kirindesk-{date}.log"));
    open_log_append(&path)?;
    Ok(path)
}

/// stderr、tracing 日志与今日日志文件，并把摘要存入静态槽供 GUI 弹窗
/// （`take_panic_message`）。正常路径零影响；重复调用覆盖安装。
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let payload = panic_payload_text(info);
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".to_string());
        let backtrace = std::backtrace::Backtrace::capture();

        let msg = format!(
            "PANIC at {location}\n  message: {payload}\n  backtrace:\n{backtrace}"
        );

        // 1) 控制台恒写（无 subscriber 也能看到）
        eprintln!("{}", msg);
        // 2) 有 subscriber 时进日志系统（含 GUI 环形缓冲）
        tracing::error!("{}", msg);
        // 3) 直接追加今日日志文件（不依赖 subscriber 是否初始化）
        append_to_log_file(&msg);
        // 4) 摘要进静态槽 → GUI 弹窗（附日志路径，见 ui 侧 show_panic_dialog）
        let log_path = current_log_path(&default_log_dir());
        if let Ok(mut slot) = LAST_PANIC.lock() {
            *slot = Some(format!(
                "{payload}\n\n位置：{location}\n\n完整信息见日志：{path}",
                payload = payload,
                location = location,
                path = log_path.display()
            ));
        }
    }));
}

/// 消费最近一次 panic 摘要（无 panic 或已消费 → None）。
pub fn take_panic_message() -> Option<String> {
    LAST_PANIC.lock().ok().and_then(|mut s| s.take())
}

fn panic_payload_text(info: &std::panic::PanicHookInfo) -> String {
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// 追加写入今日日志文件（hook 专用：即使 tracing 未初始化也有落盘记录）。
fn append_to_log_file(msg: &str) {
    append_to_log_file_in(&default_log_dir(), msg);
}

/// 追加打开日志文件（S-07b：Unix 新建日志 0600——日志可能含敏感信息；
/// 追加打开不改变既有文件权限）。
///
/// S-23（F-28）：Unix 加 `O_NOFOLLOW`——日志路径可被 symlink 指向任意
/// 文件（含覆盖写/追加污染），拒绝跟随。
fn open_log_append(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

fn append_to_log_file_in(dir: &Path, msg: &str) {
    if fs::create_dir_all(dir).is_err() {
        return; // stderr 已输出，不重复告警
    }
    let path = current_log_path(dir);
    if let Ok(mut f) = open_log_append(&path) {
        let _ = writeln!(f, "{}", msg.trim_end());
        let _ = f.flush();
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
struct RotatingFileWriter {
    dir: PathBuf,
    keep_days: u64,
    max_bytes: u64,
    state: Mutex<FileState>,
}

struct FileState {
    current_date: String,
    file: Option<File>,
}

impl RotatingFileWriter {
    fn new_with_limits(dir: PathBuf, keep_days: u64, max_bytes: u64) -> Self {
        Self {
            dir,
            keep_days,
            max_bytes,
            state: Mutex::new(FileState {
                current_date: String::new(),
                file: None,
            }),
        }
    }

    fn today() -> String {
        chrono::Local::now().format("%Y-%m-%d").to_string()
    }

    fn open_file(&self, date: &str) -> io::Result<File> {
        let path = self.dir.join(format!("kirindesk-{}.log", date));
        // S-07b: 新建日志 0600（日志可能含敏感信息）。
        open_log_append(&path)
    }
}

impl<'a> fmt::MakeWriter<'a> for RotatingFileWriter {
    type Writer = RotatingFileGuard;

    fn make_writer(&'a self) -> Self::Writer {
        let today = Self::today();
        let mut state = self.state.lock().unwrap();

        if state.current_date != today {
            if let Ok(f) = self.open_file(&today) {
                state.current_date = today.clone();
                state.file = Some(f);
                // 至多一次、开销小；持 state 锁运行不影响其它写入路径（清理
                // 不触碰 state）。不删今日文件，多实例安全。
                cleanup_old_logs_with_limits(&self.dir, self.keep_days, self.max_bytes);
            } else {
                eprintln!("[logging] Failed to open log file for {}", today);
            }
        }

        if state.file.is_none() {
            if let Ok(f) = self.open_file(&today) {
                state.current_date = today;
                state.file = Some(f);
            }
        }

        RotatingFileGuard {
            file: state.file.as_ref().and_then(|f| f.try_clone().ok()),
        }
    }
}

struct RotatingFileGuard {
    file: Option<File>,
}

impl Write for RotatingFileGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.file {
            Some(f) => f.write(buf),
            None => {
                let stderr = io::stderr();
                stderr.lock().write(buf)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.file {
            Some(f) => f.flush(),
            None => io::stderr().flush(),
        }
    }
}

// ---------------------------------------------------------------------------
// Old-log cleanup
// ---------------------------------------------------------------------------

/// 序列化清理调用（幂等；启动初始化与跨日轮转点调用，串行防重入）。
static CLEANUP_LOCK: Mutex<()> = Mutex::new(());

/// 单次清理的内部实现：收集受管日志文件（`kirindesk-YYYY-MM-DD.log`），
/// 返回按日期升序（最旧在前）的列表，供两趟删除使用。
fn collect_managed_logs(log_dir: &Path) -> Vec<(String, PathBuf, u64)> {
    let entries = match fs::read_dir(log_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut files: Vec<(String, PathBuf, u64)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) if n.starts_with(LOG_FILE_PREFIX) && n.ends_with(LOG_FILE_SUFFIX) => n,
            _ => continue, // 非本程序文件（audit.log 等）一律不动
        };
        let date_str = &fname[LOG_FILE_PREFIX.len()..fname.len() - LOG_FILE_SUFFIX.len()];
        if chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d").is_err() {
            continue; // 不符合 `YYYY-MM-DD` 的命名（含未来可能的归档名）不纳入清理
        }
        let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        files.push((date_str.to_string(), path, len));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

/// 删除早于 `keep_days` 的受管日志文件（保留期清理）。
fn cleanup_by_retention(files: &[(String, PathBuf, u64)], cutoff: chrono::DateTime<chrono::Local>, today: &str) -> u64 {
    let mut removed = 0u64;
    for (date_str, path, _) in files {
        if date_str == today {
            continue; // 今日文件可能正被写入（含其它实例），绝不删除
        }
        let date = match chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            Ok(d) => d,
            Err(_) => continue,
        };
        let file_time = date
            .and_hms_opt(0, 0, 0)
            .map(|dt| dt.and_local_timezone(chrono::Local).unwrap())
            .unwrap_or_default();
        if file_time < cutoff && fs::remove_file(path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// 总大小上限清理：保留期清理完成后，若剩余受管文件总大小超过 `max_bytes`，
/// 从最旧开始删除（跳过今日文件），直到总大小 ≤ `max_bytes`。
fn cleanup_by_size(files: &[(String, PathBuf, u64)], max_bytes: u64, today: &str) -> u64 {
    let mut total: u64 = 0;
    let mut remaining: Vec<&(String, PathBuf, u64)> = Vec::new();
    for f in files {
        if f.1.exists() {
            total += f.2;
            remaining.push(f);
        }
    }
    if total <= max_bytes {
        return 0;
    }
    let mut removed = 0u64;
    for f in remaining {
        if total <= max_bytes {
            break;
        }
        if f.0 == today {
            continue; // 今日文件不参与大小清理（可能正被写入）
        }
        if fs::remove_file(&f.1).is_ok() {
            total = total.saturating_sub(f.2);
            removed += 1;
        }
    }
    removed
}

///
/// 规则（全部约束同时满足，顺序执行）：
/// 1. 仅处理 `kirindesk-YYYY-MM-DD.log`（命名前缀/后缀过滤，不删非本程序文件）；
/// 2. 删除早于 `keep_days` 的文件（保留期，默认 7 天）；
/// 3. 若剩余文件总大小超过 `max_bytes`（默认 50 MiB），从最旧开始删除到上限以内；
/// 4. 永不删除「今日」文件（可能正被本进程/其它实例追加写入）；
/// 5. 幂等、线程安全（内部串行锁）；重复执行结果一致，多实例并发安全。
pub fn cleanup_old_logs_with_limits(log_dir: &Path, keep_days: u64, max_bytes: u64) {
    let _guard = CLEANUP_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let cutoff = chrono::Local::now() - chrono::Duration::days(keep_days as i64);
    let today = RotatingFileWriter::today();

    let files = collect_managed_logs(log_dir);
    if files.is_empty() {
        return;
    }

    let mut removed = 0u64;
    removed += cleanup_by_retention(&files, cutoff, &today);
    removed += cleanup_by_size(&files, max_bytes, &today);

    if removed > 0 {
        eprintln!(
            "[logging] Cleaned up {} old log file(s) from {:?}",
            removed, log_dir
        );
    }
}

/// 向后兼容的清理入口：默认保留期 + 默认总大小上限（50 MiB）。
pub fn cleanup_old_logs(log_dir: &Path, keep_days: u64) {
    cleanup_old_logs_with_limits(log_dir, keep_days, DEFAULT_MAX_LOG_BYTES);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_cleanup_removes_old_logs() {
        let dir = std::env::temp_dir().join("kirin_desk_test_log_cleanup");
        let _ = fs::create_dir_all(&dir);

        let old_date = (chrono::Local::now() - chrono::Duration::days(30))
            .format("%Y-%m-%d")
            .to_string();
        let old_path = dir.join(format!("kirindesk-{}.log", old_date));
        let _ = fs::write(&old_path, b"old");

        let recent_date = (chrono::Local::now() - chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();
        let recent_path = dir.join(format!("kirindesk-{}.log", recent_date));
        let _ = fs::write(&recent_path, b"recent");

        let other_path = dir.join("other-file.txt");
        let _ = fs::write(&other_path, b"not a log");

        cleanup_old_logs(&dir, 7);

        assert!(!old_path.exists(), "old log should be deleted");
        assert!(recent_path.exists(), "recent log should be kept");
        assert!(other_path.exists(), "non-log file should not be deleted");

        let _ = fs::remove_dir_all(&dir);
    }


    /// 在 `dir` 下创建 `kirindesk-{date}.log` 并写入 `size` 字节内容。
    fn make_log_file(dir: &Path, date: &str, size: usize) -> PathBuf {
        let p = dir.join(format!("kirindesk-{}.log", date));
        fs::write(&p, vec![b'x'; size]).unwrap();
        p
    }

    fn date_str(days_ago: i64) -> String {
        (chrono::Local::now() - chrono::Duration::days(days_ago))
            .format("%Y-%m-%d")
            .to_string()
    }

    #[test]
    fn test_cleanup_size_cap_removes_oldest() {
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_test_log_sizecap_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let today = RotatingFileWriter::today();
        make_log_file(&dir, &today, 100);
        make_log_file(&dir, &date_str(1), 200);
        make_log_file(&dir, &date_str(2), 300);
        make_log_file(&dir, &date_str(3), 400);

        // 总大小 1000 > 上限 500：从最旧开始删（400 → 300），删到总大小 ≤ 500。
        cleanup_old_logs_with_limits(&dir, 7, 500);

        assert!(dir.join(format!("kirindesk-{}.log", today)).exists(), "今日文件必须保留");
        assert!(dir.join(format!("kirindesk-{}.log", date_str(1))).exists(), "最近一天应保留");
        assert!(!dir.join(format!("kirindesk-{}.log", date_str(2))).exists(), "第二旧应被删除");
        assert!(!dir.join(format!("kirindesk-{}.log", date_str(3))).exists(), "最旧应被删除");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_never_deletes_today() {
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_test_log_today_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let today = RotatingFileWriter::today();
        make_log_file(&dir, &today, 100_000); // 今日文件单独即超上限
        make_log_file(&dir, &date_str(1), 10_000);

        cleanup_old_logs_with_limits(&dir, 7, 5 * 1024);

        assert!(dir.join(format!("kirindesk-{}.log", today)).exists(), "今日文件绝不删除");
        assert!(!dir.join(format!("kirindesk-{}.log", date_str(1))).exists(), "非今日文件按上限删除");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_ignores_non_program_files() {
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_test_log_foreign_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let today = RotatingFileWriter::today();
        make_log_file(&dir, &today, 100);
        // 非本程序文件：audit.log（同目录审计日志）、随机 txt、非日期命名 log。
        fs::write(dir.join("audit.log"), vec![b'a'; 10_000]).unwrap();
        fs::write(dir.join("random.txt"), vec![b'b'; 10_000]).unwrap();
        fs::write(dir.join("kirindesk-notes.log"), vec![b'c'; 10_000]).unwrap();

        cleanup_old_logs_with_limits(&dir, 7, 500);

        assert!(dir.join("audit.log").exists(), "audit.log 不得删除");
        assert!(dir.join("random.txt").exists(), "非日志文件不得删除");
        assert!(dir.join("kirindesk-notes.log").exists(), "非日期命名不得删除");
        assert!(dir.join(format!("kirindesk-{}.log", today)).exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_retention_and_cap_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_test_log_idem_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        make_log_file(&dir, &date_str(30), 100);
        make_log_file(&dir, &date_str(1), 100);

        // 首次：保留期清理删除 30 天前文件。
        cleanup_old_logs_with_limits(&dir, 7, DEFAULT_MAX_LOG_BYTES);
        assert!(!dir.join(format!("kirindesk-{}.log", date_str(30))).exists(), "超保留期应删除");
        assert!(dir.join(format!("kirindesk-{}.log", date_str(1))).exists());

        // 幂等：重复执行结果不变、无副作用。
        cleanup_old_logs_with_limits(&dir, 7, DEFAULT_MAX_LOG_BYTES);
        assert!(dir.join(format!("kirindesk-{}.log", date_str(1))).exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_today_format() {
        let t = RotatingFileWriter::today();
        assert_eq!(t.len(), 10);
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[7..8], "-");
    }

    #[test]
    fn test_log_buffer() {
        let buf = LogBuffer::new(3);
        buf.push("a\n".into());
        buf.push("b\n".into());
        buf.push("c\n".into());
        assert_eq!(buf.all(), "a\nb\nc\n");
        buf.push("d\n".into());
        assert_eq!(buf.all(), "b\nc\nd\n", "oldest should be evicted");
    }


    #[test]
    fn r142_1_drain_after_incremental_and_idempotent() {
        let buf = LogBuffer::new(4);
        let mut last: u64 = 0;
        assert_eq!(buf.drain_after(&mut last), Vec::<String>::new(), "空缓冲零行");
        buf.push("L1\n".into());
        buf.push("L2\n".into());
        assert_eq!(buf.drain_after(&mut last), vec!["L1\n", "L2\n"], "首次拉全部");
        assert_eq!(buf.drain_after(&mut last), Vec::<String>::new(), "重复拉 = 零行（水位不动）");
        buf.push("L3\n".into());
        assert_eq!(buf.drain_after(&mut last), vec!["L3\n"], "仅新增段");
    }

    #[test]
    fn r142_1_drain_after_eviction_resync() {
        // 容量 3：水位滞后（模拟 UI 未取行、环逐出缺口）→ resync 全量返回。
        let buf = LogBuffer::new(3);
        buf.push("A\n".into());
        buf.push("B\n".into());
        let mut last: u64 = 0; // 从未取行
        buf.push("C\n".into());
        buf.push("D\n".into()); // A 被逐出
        let out = buf.drain_after(&mut last);
        assert_eq!(out, vec!["B\n", "C\n", "D\n"], "resync = 当前全部行（补最近上下文）");
        // resync 后水位 = 最新 seq → 再次拉取零行。
        assert_eq!(buf.drain_after(&mut last), Vec::<String>::new());
        buf.push("E\n".into());
        assert_eq!(buf.drain_after(&mut last), vec!["E\n"], "resync 后续增正常");
    }

    #[test]
    fn r142_1_drain_after_clear_resets_lines_not_seq() {
        let buf = LogBuffer::new(3);
        buf.push("A\n".into());
        let mut last: u64 = 0;
        assert_eq!(buf.drain_after(&mut last), vec!["A\n"]);
        buf.push("B\n".into());
        buf.clear();
        // 空缓冲 → 水位对齐已发放 seq（B 的 seq=2），零行。
        assert_eq!(buf.drain_after(&mut last), Vec::<String>::new());
        assert_eq!(last, 2, "水位 = 已发放最大 seq（单调不回退）");
        buf.push("C\n".into());
        assert_eq!(buf.drain_after(&mut last), vec!["C\n"], "clear 后新行 seq 延续");
    }

    #[test]
    fn r142_1_drain_watermark_partial_buffer_window() {
        // 水位在环内但环头部已含 ≤水位 行：仅返回 >水位 段。
        let buf = LogBuffer::new(5);
        for s in ["A\n", "B\n", "C\n", "D\n", "E\n"] {
            buf.push(s.into());
        }
        let mut last: u64 = 1; // 已取过 A（A 的 seq=1）
        assert_eq!(buf.drain_after(&mut last), vec!["B\n", "C\n", "D\n", "E\n"]);
        assert_eq!(last, 5); // E 的 seq=5
    }

    #[test]
    fn test_strip_ansi() {
        let input = "\x1b[32mINFO\x1b[0m test";
        assert_eq!(strip_ansi_escapes(input), "INFO test");
    }


    #[test]
    fn test_panic_hook_records_message() {
        install_panic_hook(); // 幂等：覆盖安装
        // 子线程触发受控 panic（join 返回 Err 不影响本测试）
        let h = std::thread::spawn(|| {
        });
        assert!(h.join().is_err());

        let msg = take_panic_message().expect("panic 摘要应被记录");
        assert!(msg.contains("完整信息见日志"), "摘要附日志路径: {msg}");
        // 消费一次后为 None
        assert!(take_panic_message().is_none());
    }

    #[test]
    fn test_append_to_log_file() {
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_test_panic_log_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        append_to_log_file_in(&dir, "boom\nbacktrace line");
        let text = fs::read_to_string(current_log_path(&dir)).unwrap();
        assert!(text.contains("boom"));
        assert!(text.contains("backtrace line"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_current_log_path() {
        let p = current_log_path(Path::new("/tmp/logs"));
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("kirindesk-"), "命名与轮转文件一致: {name}");
        assert!(name.ends_with(".log"));
        // 日期段为 YYYY-MM-DD（与 RotatingFileWriter::today 一致）
        let date = &name["kirindesk-".len()..name.len() - ".log".len()];
        assert_eq!(date.len(), 10);
        assert_eq!(&date[4..5], "-");
        assert_eq!(&date[7..8], "-");
    }


    #[test]
    fn test_ensure_main_log_file_creates_today_file() {
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_test_mainlog_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = ensure_main_log_file(&dir).expect("提前打开今日主日志文件");
        assert!(path.exists(), "主日志文件必须被提前创建");
        assert_eq!(path, current_log_path(&dir), "命名与轮转文件命名一致");

        // 幂等：重复创建为追加、不截断既有内容（多实例/重启安全）。
        fs::write(&path, b"seed\n").unwrap();
        ensure_main_log_file(&dir).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "seed\n");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_init_logging_creates_main_log_even_when_filter_excludes_all() {
        // （见下方 INIT_TEST_LOCK/testing_reset_init_state 注记）。
        let _g = init_test_serial();
        testing_reset_init_state();
        // level=off：无任何事件通过过滤 → 主日志文件仍必须在 init 时存在
        // （旧实现：无事件 → 文件全程不创建 = 「主日志缺失」盲区；
        // audit.log 走独立通道不受影响，正是 09-05 09:00 实测症状）。
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_test_mainlog_off_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        init_logging_with("off", "text", &dir, 7, None);
        assert!(
            current_log_path(&dir).exists(),
        );

        let _ = fs::remove_dir_all(&dir);
    }

    //
    // init-once 状态（`INIT_SIGNATURE`）与 tracing 全局 subscriber 都是
    // 进程级的：任一测试先跑会「赢得」全局注册，其余 init 调用走到
    // `try_init` 必然失败。故全部 init 类测试必须经同一把锁串行，并在
    // 开跑前重置 init-once 状态，避免相互污染（先跑者签名残留会让后跑者
    // 被短路、断言非确定）。

    static INIT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn init_test_serial() -> std::sync::MutexGuard<'static, ()> {
        INIT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// 测试专用：清空 init-once 状态（生产语义 = 每进程一次 init，无重置
    /// 入口；此函数仅供本模块单测使用）。
    fn testing_reset_init_state() {
        *INIT_SIGNATURE.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    fn r78c_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_test_r78c_{tag}_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_r78c_repeat_init_keeps_single_writer() {
        // 重复 init（参数不同——self-test 路径 cli.rs:4889 的 init_logging("debug")
        // 相对启动期 config 级 init 正是此形态）必须短路：签名保持首次
        // （单 writer 保持）、第二目录不产生文件（cleanup/ensure 不重跑）、
        // 首次 init 的产物不受影响。
        let _g = init_test_serial();
        testing_reset_init_state();
        let dir_a = r78c_test_dir("single");
        let dir_b = r78c_test_dir("second");

        // 首次 init：dirA（level=off 防事件穿透过滤产生噪音行）。
        init_logging_with("off", "text", &dir_a, 7, None);
        let first = init_signature().expect("首次 init 后必须记录签名");
        assert_eq!(first.dir, dir_a.display().to_string());

        // 二次 init（模拟 self-test 的 debug 请求）→ 短路。
        init_logging_with("debug", "text", &dir_b, 7, None);
        assert_eq!(
            init_signature(),
            Some(first.clone()),
            "二次 init 不得改写 writer 签名（单 writer 保持）"
        );
        assert!(
            !current_log_path(&dir_b).exists(),
            "二次 init 不得为第二目录建立第二套文件"
        );
        assert!(
            current_log_path(&dir_a).exists(),
            "首次 init 的主日志文件必须完好"
        );

        let _ = fs::remove_dir_all(&dir_a);
        let _ = fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn test_r78c_repeat_init_same_params_idempotent() {
        // 同参重复调用（任意路径二次 init）= 幂等 no-op：签名不变、既有
        let _g = init_test_serial();
        testing_reset_init_state();
        let dir = r78c_test_dir("idem");

        init_logging_with("off", "text", &dir, 7, None);
        let first = init_signature().expect("首次 init 后必须记录签名");
        // 模拟既有日志内容（如首条 banner 行）。
        fs::write(current_log_path(&dir), b"seed\n").unwrap();

        init_logging_with("off", "text", &dir, 7, None);
        assert_eq!(
            init_signature(),
            Some(first),
            "同参重复 init 签名必须不变"
        );
        assert_eq!(
            fs::read_to_string(current_log_path(&dir)).unwrap(),
            "seed\n",
            "重复 init 不得改动既有日志内容（不截断/不重复写）"
        );

        let _ = fs::remove_dir_all(&dir);
    }


    /// 时**恢复原值**（而非简单 remove_var）：全量门禁经命令行恒带
    /// KIRIN_DATA_DIR 隔离目录，本测试若把 env 抽干会改变同二进制内其他
    /// 测试进程级前提（config.rs env 覆盖测试同款纪律，且本守卫更严）。
    struct ConfigDirEnvGuard {
        original: Option<std::ffi::OsString>,
    }

    impl ConfigDirEnvGuard {
        /// `value=None` = 移除 env；`Some` = 设为指定值。
        fn set(value: Option<&std::ffi::OsStr>) -> Self {
            let original = std::env::var_os("KIRIN_DATA_DIR");
            match value {
                Some(v) => std::env::set_var("KIRIN_DATA_DIR", v),
                None => std::env::remove_var("KIRIN_DATA_DIR"),
            }
            Self { original }
        }
    }

    impl Drop for ConfigDirEnvGuard {
        fn drop(&mut self) {
            // Drop 序 = 声明逆序：guard 先于锁 guard 释放 → env 恢复发生在
            // 持锁窗口内，零互染。
            match self.original.clone() {
                Some(v) => std::env::set_var("KIRIN_DATA_DIR", v),
                None => std::env::remove_var("KIRIN_DATA_DIR"),
            }
        }
    }

    fn legacy_home_log_dir() -> PathBuf {
        // 修复前口径：home/.kirin_desk/logs（home 缺失回落 "."——与原码逐位一致）。
        dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".kirin_desk")
            .join("logs")
    }

    #[test]
    fn test_r87w_default_log_dir_env_override() {
        let _lock = crate::KIRIN_DATA_DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("kirin_r87w_logdir_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let _g = ConfigDirEnvGuard::set(Some(dir.as_os_str()));
        let got = default_log_dir();
        assert_eq!(got, dir.join("logs"), "KIRIN_DATA_DIR 已设 → <env>/logs");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r87w_default_log_dir_unset_matches_legacy() {
        let _lock = crate::KIRIN_DATA_DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _g = ConfigDirEnvGuard::set(None);
        let got = default_log_dir();
        assert_eq!(
            got,
            legacy_home_log_dir(),
            "未设 env → 返回值与修复前 home 口径逐位一致（生产零变化）"
        );
    }

    #[test]
    fn test_r87w_default_log_dir_blank_falls_back_home() {
        let _lock = crate::KIRIN_DATA_DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _g = ConfigDirEnvGuard::set(Some("   ".as_ref()));
        let got = default_log_dir();
        assert_eq!(
            got,
            legacy_home_log_dir(),
        );
    }


    /// 常量 = 代码内可配置，无运行时配置项）。
    #[test]
    fn r119_heartbeat_interval_constant() {
        assert_eq!(HEARTBEAT_INTERVAL_SECS, 60, "心跳间隔 = 60s（死亡窗口 ≤60s）");
        assert_eq!(HEARTBEAT_ENV, "KIRIN_LOG_HEARTBEAT", "逃生口 env 名固定");
    }

    #[test]
    fn r119_heartbeat_switch_pure() {
        // 默认开（fail-open：误配置不应静默关断观测）
        assert!(heartbeat_enabled(None), "未设 env = 开");
        assert!(heartbeat_enabled(Some("")), "空值 = 开");
        assert!(heartbeat_enabled(Some("1")), "1 = 开");
        assert!(heartbeat_enabled(Some("on")), "on = 开");
        // 关 = 且仅 0/off/false（大小写不敏感、trim 后）
        assert!(!heartbeat_enabled(Some("0")), "0 = 关");
        assert!(!heartbeat_enabled(Some("off")), "off = 关");
        assert!(!heartbeat_enabled(Some("FALSE")), "false（大小写不敏感）= 关");
        assert!(!heartbeat_enabled(Some(" 0 ")), "带空白 0 = 关（trim 口径）");
        // 其它值 = 开（逃生口口径：不做全量 bool 解析器）
        assert!(heartbeat_enabled(Some("no")), "no = 开（不在关值集）");
        assert!(heartbeat_enabled(Some("falsey")), "falsey = 开（非精确三值）");
    }
}
