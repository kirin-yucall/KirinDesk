//!
//! 背景：用户 09-15 22:04:47 在 179 连接界面按 Shift 切输入法时程序崩溃退出
//! 一次（再按未复现）。日志定案：断口前**零 panic/fatal 行**（本构建 panic
//! hook 会写日志文件，有受控自测 panic 先例 = 机制在位）+ 死亡窗口 23.5s 后
//! logger 重启（同版本）= **原生硬崩溃（SEH/access violation 类）或外部
//! 无法复现 → 本模块建**证据设施**：下次复现自动留 minidump + 日志标记行，
//! 即定案（本模块本体无单测面，见模块尾记档）。
//!
//! # 机制
//!
//! 启动早期（`run()` 日志系统初始化后一行，见 `lib.rs`）装进程级
//! `SetUnhandledExceptionFilter`（raw FFI，先例 = `tray.rs` 的 user32/
//! kernel32 块，零新依赖）。未处理原生异常（access violation / 非法指令 /
//! 栈溢出等）到达顶层时：
//!
//! 1. `MiniDumpWriteDump` 写 `kirindesk-native-crash-<yyyymmdd-hhmmss>.dmp`
//!    到日志目录（目录 = [`kirin_desk_utils::logging::default_log_dir`]，与
//!    主日志同口径：`KIRIN_DATA_DIR` 隔离目录优先，否则 `~/.kirin_desk/logs`）；
//!    dump 类型 = MiniDumpNormal | MiniDumpWithThreadInfo（小而精：线程上下文
//!    + 基本内存，够 SEH/access violation 定案，避免巨大 dump）；
//! 2. 追加一行 `NATIVE CRASH` 标记到当日主日志（**best effort**，失败不影响
//!    ①已写的 dump）——日志时序即刻可读「此为主生崩溃，证据文件 = ××」；
//! 3. 返回 `EXCEPTION_EXECUTE_HANDLER` → OS 干净终止进程（不挂起、不弹 WER
//!    对话框阻塞用户复测）。
//!
//! # 回调内纪律（崩溃上下文：不 panic / 不分配 / 不锁，尽量裸写）
//!
//! - **不 panic**：一切 FFI 返回值/缓冲写入有界检查；任何路径无 unwrap /
//!   无界 index / slice / `format!`——异常过滤器内再抛异常 = 直接升级为进程
//!   终止且 dump 丢失（Windows 语义：handler 内异常不再二次派发）；
//! - **不分配**：零堆分配——路径在固定栈宽缓冲拼装（前缀安装期预计算为
//!   wide），时间戳经 `GetLocalTime` + [`format_crash_ts`] 手动数字格式化
//!   （无 chrono、无 String）；
//! - **不锁**：单实例闩 = `DUMP_STARTED` AtomicBool（dump 写入期间的第二个
//!   异常/重复投递 → 跳 dump 直接终止）；
//! - `MiniDumpWriteDump` 符号安装期经 `LoadLibrary(dbghelp.dll)` +
//!   `GetProcAddress` 解析（零新链接依赖；dbghelp 不可得 → 过滤器仍安装、
//!   跳 dump = 降级证据不降级退出语义）。
//!
//! # 记档：本体无单测面
//!
//! 异常过滤器 = FFI 安装 + 崩溃上下文回调，无法在单测内安全触发真实
//! SEH（子进程触发需真实 dump 实机，留下次用户复现定案——本波目标即「复现
//! 即留证」）。可单测面 = 时间戳格式化纯函数 [`format_crash_ts`]（见测试）。

///
/// minidump 文件名 / 日志标记行的裸写格式化单入口（手动数字格式化——异常
/// 过滤器回调禁分配禁 panic，不引 chrono/String）。参数值域 = `GetLocalTime`
/// 值域（年 1601..9999 / 月 1..12 / 日 1..31 / 时 0..23 / 分 0..59 / 秒
/// 0..59）；越界输入（理论不可达）只产生畸形数字位，**不 panic**。
/// 输出恒为纯 ASCII（wide/UTF-8 双口径转换无损）。
#[cfg(any(windows, test))]
#[inline]
pub fn format_crash_ts(
    year: u16,
    month: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
) -> [u16; 15] {
    let mut ts = [0u16; 15];
    let d4 = [year / 1000, (year / 100) % 10, (year / 10) % 10, year % 10];
    for (i, d) in d4.iter().enumerate() {
        ts[i] = (b'0' as u16) + *d as u16;
    }
    let d2: [(u16, u16, usize); 5] = [
        (month / 10, month % 10, 4),
        (day / 10, day % 10, 6),
        (hour / 10, hour % 10, 9),
        (minute / 10, minute % 10, 11),
        (second / 10, second % 10, 13),
    ];
    for (tens, ones, at) in d2 {
        ts[at] = (b'0' as u16) + tens as u16;
        ts[at + 1] = (b'0' as u16) + ones as u16;
    }
    ts[8] = b'-' as u16;
    ts
}

#[cfg(windows)]
mod win {
    use std::os::raw::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::OnceLock;

    // ---------- 常量（MSDN 值） ----------

    /// EXCEPTION_EXECUTE_HANDLER：处理器完成后终止进程（不恢复执行）。
    const EXCEPTION_EXECUTE_HANDLER: u32 = 1;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const CREATE_ALWAYS: u32 = 2;
    const OPEN_ALWAYS: u32 = 4;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_END: u32 = 2;
    /// MiniDumpNormal | MiniDumpWithThreadInfo（小而精，见模块文档）。
    const MINIDUMP_TYPE: u32 = 0x0000_0001 | 0x0000_1000;
    /// 栈上宽路径缓冲容量（日志目录典型 <260 字符，600 宽字符单位充裕）。
    const PATH_BUF_UNITS: usize = 600;

    /// SYSTEMTIME（kernel32!GetLocalTime 目标；`_` 前缀字段 = 布局占位，
    /// 不读，抑 dead_code）。
    #[repr(C)]
    struct SystemTime {
        w_year: u16,
        w_month: u16,
        _w_day_of_week: u16,
        w_day: u16,
        w_hour: u16,
        w_minute: u16,
        w_second: u16,
        _w_milliseconds: u16,
    }

    /// EXCEPTION_POINTERS（回调入参；本回调只消费存在性，不读字段——
    /// 异常记录解析留 dump 分析侧）。
    #[repr(C)]
    struct ExceptionPointers {
        _exception_record: *mut c_void,
        _context_record: *mut c_void,
    }

    type UnhandledExceptionFilter =
        unsafe extern "system" fn(*const ExceptionPointers) -> u32;
    /// dbghelp!MiniDumpWriteDump（安装期 GetProcAddress 解析）。
    type MiniDumpWriteDumpFn = unsafe extern "system" fn(
        hprocess: *mut c_void,
        processid: u32,
        hfile: *mut c_void,
        dump_type: u32,
        exception: *const c_void,
        user_stream: *const c_void,
        callback: *const c_void,
    ) -> i32;

    // ---------- FFI（kernel32 由 std 恒链接，先例 = `tray.rs` kernel32 块） ----------

    #[link(name = "kernel32")]
    extern "system" {
        fn SetUnhandledExceptionFilter(
            lpfn: Option<UnhandledExceptionFilter>,
        ) -> Option<UnhandledExceptionFilter>;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            sa: *const c_void,
            disp: u32,
            attrs: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn WriteFile(
            h: *mut c_void,
            buf: *const u8,
            n: u32,
            written: *mut u32,
            ov: *mut c_void,
        ) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn SetFilePointerEx(h: *mut c_void, lo: i64, hi: *mut i64, whence: u32) -> i32;
        fn GetLocalTime(st: *mut SystemTime);
        fn GetCurrentProcess() -> *mut c_void;
        fn GetCurrentProcessId() -> u32;
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(h: *mut c_void, name: *const u8) -> *const c_void;
    }

    // ---------- 状态（安装期预计算/置定；回调只读） ----------

    /// 过滤器已安装（install 幂等）。
    static FILTER_INSTALLED: AtomicBool = AtomicBool::new(false);
    /// dump 写入中/已完成（回调重入闩）。
    static DUMP_STARTED: AtomicBool = AtomicBool::new(false);
    /// `<log_dir>\kirindesk-native-crash-`（wide，无 NUL；安装期预计算）。
    static DUMP_PREFIX: OnceLock<Vec<u16>> = OnceLock::new();
    /// `<log_dir>\kirindesk-`（wide，无 NUL；当日主日志标记行路径前缀）。
    static LOG_PREFIX: OnceLock<Vec<u16>> = OnceLock::new();
    /// MiniDumpWriteDump（None = dbghelp 不可得 → 跳 dump）。
    static MINIDUMP_FN: OnceLock<MiniDumpWriteDumpFn> = OnceLock::new();

    // ---------- 裸写助手（不 panic：全有界检查，无 slice 越界路径） ----------

    /// 纯 ASCII 字面量拷贝进字节缓冲（成功 = 新位置；溢出 = `None` 零写入）。
    fn copy_u8(dst: &mut [u8], pos: usize, s: &str) -> Option<usize> {
        let end = pos.checked_add(s.len())?;
        if end > dst.len() {
            return None;
        }
        dst[pos..end].copy_from_slice(s.as_bytes());
        Some(end)
    }

    // ---------- 回调与安装 ----------

    /// 未处理异常过滤器体（崩溃线程上下文执行；纪律见模块文档）。
    unsafe extern "system" fn on_unhandled_exception(_pe: *const ExceptionPointers) -> u32 {
        // 重入闩：dump 写入期间的第二个异常/重复投递 → 跳 dump 直接终止
        // （过滤器内再抛异常 = 进程终止且 dump 丢失）
        if DUMP_STARTED.swap(true, Ordering::SeqCst) {
            return EXCEPTION_EXECUTE_HANDLER;
        }

        // 本地时间（裸读：zeroed 结构 + 系统填充，零分配）
        let mut st: SystemTime = std::mem::zeroed();
        GetLocalTime(&mut st);
        let ts = crate::crash_dump::format_crash_ts(
            st.w_year,
            st.w_month,
            st.w_day,
            st.w_hour,
            st.w_minute,
            st.w_second,
        );

        // ── ① minidump：<log_dir>\kirindesk-native-crash-<ts>.dmp ──
        if let Some(prefix) = DUMP_PREFIX.get() {
            let mut wpath: [u16; PATH_BUF_UNITS] = [0; PATH_BUF_UNITS];
            // 容量有界检查（prefix 安装期来自真实目录，正常 < PATH_BUF_UNITS；
            // 超限 = 跳 dump，绝不越界写）
            if prefix.len() + 15 + 4 <= wpath.len() {
                wpath[..prefix.len()].copy_from_slice(prefix);
                let mut pos = prefix.len();
                wpath[pos..pos + 15].copy_from_slice(&ts);
                pos += 15;
                for c in [b'.' as u16, b'd' as u16, b'm' as u16, b'p' as u16] {
                    wpath[pos] = c;
                    pos += 1;
                }
                let hfile = CreateFileW(
                    wpath.as_ptr(),
                    GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                );
                if !hfile.is_null() && hfile as usize != usize::MAX {
                    if let Some(write_dump) = MINIDUMP_FN.get() {
                        // 返回值不检查：dump 写失败/部分写 → 进程仍须按计划
                        // 终止（过滤器不得滞留）；失败证据 = 日志标记行 + dmp 缺失
                        let _ = write_dump(
                            GetCurrentProcess(),
                            GetCurrentProcessId(),
                            hfile,
                            MINIDUMP_TYPE,
                            std::ptr::null(),
                            std::ptr::null(),
                            std::ptr::null(),
                        );
                    }
                    CloseHandle(hfile);
                }
            }
        }

        // ── ② 当日主日志标记行（best effort；失败不影响 ① 已落盘的 dump）──
        if let Some(prefix) = LOG_PREFIX.get() {
            // 文件名 = prefix + "YYYY-MM-DD" + ".log"（与主日志轮转命名一致）
            let date = [
                ts[0],
                ts[1],
                ts[2],
                ts[3],
                b'-' as u16,
                ts[4],
                ts[5],
                b'-' as u16,
                ts[6],
                ts[7],
            ];
            let mut wpath: [u16; PATH_BUF_UNITS] = [0; PATH_BUF_UNITS];
            // 容量有界检查（同上；超限 = 跳标记行，绝不越界写）
            if prefix.len() + 14 <= wpath.len() {
                wpath[..prefix.len()].copy_from_slice(prefix);
                let mut pos = prefix.len();
                wpath[pos..pos + 10].copy_from_slice(&date);
                pos += 10;
                for c in [b'.' as u16, b'l' as u16, b'o' as u16, b'g' as u16] {
                    wpath[pos] = c;
                    pos += 1;
                }
                // 标记行体（UTF-8 ASCII——与主日志既有写入口径一致）
                let mut line = [0u8; 160];
                let lpos = copy_u8(
                    &mut line,
                    0,
                    "NATIVE CRASH: unhandled native exception - minidump: kirindesk-native-crash-",
                )
                .and_then(|p| {
                    if p + 15 > line.len() {
                        return None;
                    }
                    for i in 0..15 {
                        line[p + i] = ts[i] as u8;
                    }
                    Some(p + 15)
                })
                if let Some(end) = lpos {
                    let hlog = CreateFileW(
                        wpath.as_ptr(),
                        GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        std::ptr::null(),
                        OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        std::ptr::null_mut(),
                    );
                    if !hlog.is_null() && hlog as usize != usize::MAX {
                        // 追加语义：CreateFile 打开位置 = 0 → 先 seek 文件尾
                        if SetFilePointerEx(hlog, 0, std::ptr::null_mut(), FILE_END) != 0 {
                            let mut written: u32 = 0;
                            WriteFile(
                                hlog,
                                line.as_ptr(),
                                end as u32,
                                &mut written,
                                std::ptr::null_mut(),
                            );
                        }
                        CloseHandle(hlog);
                    }
                }
            }
        }

        // OS 干净终止（不恢复执行、不挂起、不弹 WER 对话框）
        EXCEPTION_EXECUTE_HANDLER
    }

    /// 安装原生崩溃过滤器（幂等；启动早期日志系统初始化后调用一次，使安装
    /// INFO 行进日志文件）。
    pub fn install() {
        if FILTER_INSTALLED.swap(true, Ordering::SeqCst) {
            return;
        }
        let log_dir = kirin_desk_utils::logging::default_log_dir();
        let _ = std::fs::create_dir_all(&log_dir);
        {
            use std::os::windows::ffi::OsStrExt;
            let dump_prefix = log_dir.join("kirindesk-native-crash-");
            let _ = DUMP_PREFIX.set(dump_prefix.as_os_str().encode_wide().collect());
            let log_prefix = log_dir.join("kirindesk-");
            let _ = LOG_PREFIX.set(log_prefix.as_os_str().encode_wide().collect());
        }
        // dbghelp.dll：安装期解析 MiniDumpWriteDump（零新链接依赖；不可得 →
        // MINIDUMP_FN 不置 = 跳 dump，过滤器语义不变）
        let dbghelp: Vec<u16> = "dbghelp.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let hmod = unsafe { LoadLibraryW(dbghelp.as_ptr()) };
        if !hmod.is_null() {
            let p = unsafe { GetProcAddress(hmod, b"MiniDumpWriteDump\0".as_ptr()) };
            if !p.is_null() {
                // *const c_void → 函数指针（等尺寸位模式拷贝，C ABI 符号地址）
                let _ = MINIDUMP_FN.set(unsafe { std::mem::transmute_copy(&p) });
            }
        }
        let installed =
            unsafe { SetUnhandledExceptionFilter(Some(on_unhandled_exception)) }.is_some();
        if installed {
            tracing::info!(
                log_dir,
                if MINIDUMP_FN.get().is_some() {
                    "ok"
                } else {
                    "missing (dump disabled)"
                }
            );
        } else {
            tracing::warn!(
            );
        }
    }
}

#[cfg(not(windows))]
mod stub {
    /// 口径——Windows 先行，其余平台原生崩溃证据设施另立项）。
    pub fn install() {}
}

#[cfg(windows)]
pub use win::install;
#[cfg(not(windows))]
pub use stub::install;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r119_format_crash_ts() {
        let ts = format_crash_ts(2026, 9, 15, 22, 4, 7);
        let want: Vec<u16> = "20260915-220407".encode_utf16().collect();
        assert_eq!(ts.len(), 15, "恒 15 位 yyyymmdd-hhmmss");
        for (i, w) in want.iter().enumerate() {
            assert_eq!(ts[i], *w, "pos {i}");
        }
        // 09-15 22:04:47 事件时刻形态（两位零填充：分/秒 <10）
        let ts = format_crash_ts(2026, 9, 15, 22, 4, 47);
        let want: Vec<u16> = "20260915-220447".encode_utf16().collect();
        for (i, w) in want.iter().enumerate() {
            assert_eq!(ts[i], *w, "pos {i}");
        }
        // 满值边界（两位段全 9/双位年不变）
        let ts = format_crash_ts(2026, 12, 31, 23, 59, 59);
        let want: Vec<u16> = "20261231-235959".encode_utf16().collect();
        for (i, w) in want.iter().enumerate() {
            assert_eq!(ts[i], *w, "pos {i}");
        }
        // 输出恒纯 ASCII（wide 路径 / UTF-8 标记行双口径转换无损）
        for &c in &format_crash_ts(9999, 1, 1, 0, 0, 0) {
            assert!((c as u32) < 128, "非 ASCII 输出: {c}");
        }
    }
}
