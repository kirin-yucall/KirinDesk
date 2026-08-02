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

/// Default log directory: `~/.kirin_desk/logs/`
pub fn default_log_dir() -> PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kirin_desk")
        .join("logs")
}

/// Default number of days to keep log files.
pub const DEFAULT_KEEP_DAYS: u64 = 7;

/// A thread-safe ring buffer of log lines for GUI display.
/// Stores at most `capacity` lines, dropping oldest first.
pub struct LogBuffer {
    inner: Mutex<LogBufferInner>,
}

struct LogBufferInner {
    lines: VecDeque<String>,
    capacity: usize,
}

impl LogBuffer {
    /// Create a new buffer with the given capacity.
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(LogBufferInner {
                lines: VecDeque::with_capacity(capacity),
                capacity,
            }),
        })
    }

    /// Push a line (appended by a newline) into the buffer.
    pub fn push(&self, line: String) {
        let mut inner = self.inner.lock().unwrap();
        while inner.lines.len() >= inner.capacity {
            inner.lines.pop_front();
        }
        inner.lines.push_back(line);
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
    }

    /// Return a shared reference (Arc) to self – convenience wrapper.
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

use std::sync::Arc;

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
    // Ensure log directory exists
    if let Err(e) = fs::create_dir_all(log_dir) {
        eprintln!("[logging] WARN: cannot create log dir {:?}: {}", log_dir, e);
    }

    // Clean up old logs
    cleanup_old_logs(log_dir, keep_days);

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

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

    // Build file writer
    let file_writer = RotatingFileWriter::new(log_dir.to_path_buf());

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

            tracing_subscriber::registry()
                .with(env_filter)
                .with(console_layer)
                .with(json_layer)
                .try_init()
                .ok();
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

            tracing_subscriber::registry()
                .with(env_filter)
                .with(console_layer)
                .with(text_layer)
                .try_init()
                .ok();
        }
    }

    debug!(
        "Logging initialized: level={}, format={}, dir={:?}, keep_days={}",
        level, format, log_dir, keep_days
    );
    info!(
        "KirinDesk logger started (RUST_LOG={}, logs at {:?})",
        std::env::var("RUST_LOG").unwrap_or_else(|_| level.to_string()),
        log_dir
    );
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
// Rotating file writer (unchanged except minor cleanup)
// ---------------------------------------------------------------------------
struct RotatingFileWriter {
    dir: PathBuf,
    state: Mutex<FileState>,
}

struct FileState {
    current_date: String,
    file: Option<File>,
}

impl RotatingFileWriter {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
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
        OpenOptions::new().create(true).append(true).open(&path)
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
pub fn cleanup_old_logs(log_dir: &Path, keep_days: u64) {
    let cutoff = chrono::Local::now() - chrono::Duration::days(keep_days as i64);

    let entries = match fs::read_dir(log_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    let mut removed = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) if n.starts_with("kirindesk-") && n.ends_with(".log") => n.to_string(),
            _ => continue,
        };

        let date_str = &fname["kirindesk-".len()..fname.len() - ".log".len()];
        let date = match chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            Ok(d) => d,
            Err(_) => continue,
        };
        let file_time = date
            .and_hms_opt(0, 0, 0)
            .map(|dt| dt.and_local_timezone(chrono::Local).unwrap())
            .unwrap_or_default();

        if file_time < cutoff && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }

    if removed > 0 {
        eprintln!(
            "[logging] Cleaned up {} old log file(s) from {:?}",
            removed, log_dir
        );
    }
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
    fn test_strip_ansi() {
        let input = "\x1b[32mINFO\x1b[0m test";
        assert_eq!(strip_ansi_escapes(input), "INFO test");
    }
}
