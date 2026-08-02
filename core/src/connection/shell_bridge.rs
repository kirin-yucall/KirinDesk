//! M11-T001: SecureChannel PTY 桥接 — 远程 Shell（PTY 模式）
//!
//! 服务端：已握手 SecureChannel → spawn PTY（`portable-pty` crate，跨平台：
//! Windows 用 ConPTY(Windows 10+)、Linux/macOS 用 forkpty/openpty）→ 双向桥接：
//!
//! ```text
//! ch.receive → ShellStdin → PTY stdin       PTY stdout → ShellStdout → ch.send
//! ch.receive → ShellResize → PTY resize
//! ```
//!
//! 消息类型（对应 M11 设计文档的 `MediaType::Shell*`）：
//! - [`ShellMessage::ShellStdin`]：客户端键盘输入（原始字节，含 ANSI 控制序列）
//! - [`ShellMessage::ShellStdout`]：PTY 输出（原始字节，含 ANSI 颜色/光标控制）
//! - [`ShellMessage::ShellResize`]：终端尺寸变更通知（列/行）

use crate::crypto::handshake::SecureChannel;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use tokio::sync::mpsc;

/// PTY 桥接错误。
#[derive(Debug, thiserror::Error)]
pub enum ShellError {
    #[error("PTY spawn failed: {0}")]
    PtySpawn(String),

    #[error("PTY I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SecureChannel error: {0}")]
    Channel(String),

    #[error("Shell message encode/decode error: {0}")]
    Codec(String),
}

/// Shell 会话消息（M11 设计文档 `MediaType::ShellStdin/Stdout/Resize` 的落地形态）。
///
/// 与媒体流共用 SecureChannel 的 wire 格式（bincode 序列化 + AEAD 逐消息加密），
/// 每个 `ch.send()` = 一条消息。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ShellMessage {
    /// 客户端 → 服务端：键盘/粘贴输入（原始字节，含 ANSI 控制序列）。
    ShellStdin(Vec<u8>),

    /// 服务端 → 客户端：PTY 输出（原始字节，含 ANSI 颜色/光标控制）。
    ShellStdout(Vec<u8>),

    /// 客户端 → 服务端：终端尺寸变更（列/行）。
    ShellResize { cols: u16, rows: u16 },
}

impl ShellMessage {
    /// 编码为 wire 字节（bincode）。
    pub fn encode(&self) -> Result<Vec<u8>, ShellError> {
        bincode::serialize(self).map_err(|e| ShellError::Codec(e.to_string()))
    }

    /// 从 wire 字节解码。
    pub fn decode(data: &[u8]) -> Result<Self, ShellError> {
        bincode::deserialize(data).map_err(|e| ShellError::Codec(e.to_string()))
    }
}

/// 默认 PTY 尺寸（客户端连接后立即发送真实尺寸覆盖）。
pub const DEFAULT_PTY_COLS: u16 = 120;
pub const DEFAULT_PTY_ROWS: u16 = 30;

// ── PTY 会话 ─────────────────────────────────────────────────────

/// 一个运行中的 PTY 会话（master 读写端 + 子进程）。
///
/// master 的写端（stdin 方向）与读端（stdout 方向）均通过
/// [`take_writer`](Self::take_writer)/[`take_reader`](Self::take_reader)
/// 取出后交给专用阻塞线程；master 本体留在桥接任务中用于 resize。
pub struct PtySession {
    master: Box<dyn portable_pty::MasterPty + Send>,
    child: Option<Box<dyn portable_pty::Child + Send + Sync>>,
    cols: u16,
    rows: u16,
}

impl PtySession {
    /// Spawn 一个 PTY。`command` 为 None 时使用默认交互 shell
    /// （Windows: powershell；Unix: `$SHELL` 或 `/bin/bash`）。
    pub fn spawn(
        command: Option<portable_pty::CommandBuilder>,
        cols: u16,
        rows: u16,
    ) -> Result<Self, ShellError> {
        let pty_system = portable_pty::native_pty_system();
        let size = portable_pty::PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };
        let pair = pty_system
            .openpty(size)
            .map_err(|e| ShellError::PtySpawn(e.to_string()))?;

        let cmd = command.unwrap_or_else(default_shell_command);
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| ShellError::PtySpawn(e.to_string()))?;
        drop(pair.slave);

        Ok(Self {
            master: pair.master,
            child: Some(child),
            cols,
            rows,
        })
    }

    /// 当前终端尺寸（列/行）。
    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    /// 变更终端尺寸（客户端 `ShellResize` 到达时调用）。
    /// 非法尺寸（0 列/行）静默忽略，避免 PTY 后端报错。
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ShellError> {
        if cols == 0 || rows == 0 {
            return Ok(());
        }
        self.master
            .resize(portable_pty::PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| ShellError::PtySpawn(e.to_string()))?;
        self.cols = cols;
        self.rows = rows;
        Ok(())
    }

    /// 取出 PTY master 写端（stdin 方向）。
    pub fn take_writer(&mut self) -> Result<Box<dyn Write + Send>, ShellError> {
        self.master
            .take_writer()
            .map_err(|e| ShellError::PtySpawn(e.to_string()))
    }

    /// 取出 PTY master 读端（stdout 方向）。
    pub fn take_reader(&mut self) -> Result<Box<dyn Read + Send>, ShellError> {
        self.master
            .try_clone_reader()
            .map_err(|e| ShellError::PtySpawn(e.to_string()))
    }

    /// 强制终止子进程（Drop 时也会执行）。
    pub fn kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
    }

    /// 子进程是否已退出（非阻塞轮询）。
    ///
    /// 关键性：Windows ConPTY 的 master 读端在伪控制台关闭前**不会** EOF，
    /// 因此不能依赖"读端 EOF"判断 PTY 退出——必须轮询子进程状态。
    pub fn child_exited(&mut self) -> Result<bool, ShellError> {
        match self.child.as_mut() {
            Some(child) => {
                let status = child
                    .try_wait()
                    .map_err(|e| ShellError::PtySpawn(e.to_string()))?;
                Ok(status.is_some())
            }
            None => Ok(true),
        }
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// 默认交互 shell 命令（TERM 设为 xterm-256color，保证完整终端能力）。
fn default_shell_command() -> portable_pty::CommandBuilder {
    #[cfg(windows)]
    let mut cmd = {
        // ConPTY 下 PowerShell 5.1 默认控制台代码页可能为 GBK（中文乱码源）：
        // 启动参数静默切换进程级编码 + 控制台代码页为 UTF-8，无 banner/无输出。
        // -NoExit 保证命令执行后保持交互式会话（与现状无参启动等价）。
        // （M8-T021_P3 T021-05-C；DSR：powershell 不产生 ESC[6n，无应答依赖。）
        let mut c = portable_pty::CommandBuilder::new("powershell.exe");
        c.arg("-NoLogo");
        c.arg("-NoExit");
        c.arg("-Command");
        c.arg("[Console]::InputEncoding=[Text.Encoding]::UTF8; [Console]::OutputEncoding=[Text.Encoding]::UTF8; chcp 65001 | Out-Null");
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
        portable_pty::CommandBuilder::new(shell)
    };
    cmd.env("TERM", "xterm-256color");
    cmd
}

// ── 服务端桥接主循环 ─────────────────────────────────────────────

/// 服务端 PTY 桥接主循环（M11-T001）。
///
/// 已握手通道 → spawn 交互 shell → 双向桥接：
/// - **接收循环**（异步）：`ShellStdin` → PTY stdin；`ShellResize` → PTY resize
/// - **PTY 读取线程**（阻塞）：PTY stdout → `ShellStdout` → 通道发送
///
/// 任一侧断开（客户端 EOF / PTY 退出）即结束会话：
/// - 客户端断开 → kill PTY 子进程（读取线程随即 EOF 退出）；
/// - PTY 退出（读取 EOF）→ 通道写端 drop，客户端收到 EOF。
///
/// `command` 可注入（测试用），None 为默认交互 shell。
pub async fn run_shell_bridge(
    ch: SecureChannel,
    cols: u16,
    rows: u16,
    command: Option<portable_pty::CommandBuilder>,
) -> Result<(), ShellError> {
    let mut session = PtySession::spawn(command, cols, rows)?;
    session.resize(cols, rows)?;

    let (mut ch_reader, mut ch_writer) = ch.into_split();

    // PTY stdin 写入线程：消费通道下发消息（阻塞写不占用 tokio worker）。
    let mut pty_writer = session.take_writer()?;
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<ShellMessage>(256);
    std::thread::spawn(move || {
        while let Some(msg) = stdin_rx.blocking_recv() {
            match msg {
                ShellMessage::ShellStdin(bytes) => {
                    let _ = pty_writer.write_all(&bytes);
                    let _ = pty_writer.flush();
                }
                // Resize 由桥接任务直接调用 master（需持有 master 引用）。
                _ => {}
            }
        }
    });

    // PTY stdout 读取线程：阻塞读 → mpsc → 异步发送。
    let mut pty_reader = session.take_reader()?;
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // 主循环：任一侧结束即退出。
    //
    // 退出判定（跨平台关键设计）：
    // - Windows ConPTY：master 读端在伪控制台关闭前不会 EOF → 必须轮询子进程
    //   退出（`child_exited`），退出后主动销毁会话（关闭伪控制台）才能让读线程 EOF；
    // - Unix forkpty：读端自然 EOF（所有 slave fd 关闭），轮询为冗余保险。
    let mut pty_exited = false;
    loop {
        tokio::select! {
            // 客户端 → PTY
            recv = ch_reader.receive() => {
                match recv {
                    Ok(bytes) => match ShellMessage::decode(&bytes) {
                        Ok(ShellMessage::ShellStdin(data)) => {
                            if stdin_tx.send(ShellMessage::ShellStdin(data)).await.is_err() {
                                break; // 写入线程已退出（PTY 已关闭）
                            }
                        }
                        Ok(ShellMessage::ShellResize { cols, rows }) => {
                            session.resize(cols, rows)?;
                        }
                        Ok(ShellMessage::ShellStdout(_)) => { /* 服务端不应收到 */ }
                        Err(e) => return Err(e),
                    },
                    // 客户端断开（EOF/解密失败）→ 终止会话。
                    Err(e) => {
                        tracing::debug!("Shell bridge: client channel closed ({e})");
                        break;
                    }
                }
            }
            // PTY → 客户端
            out = out_rx.recv() => {
                match out {
                    Some(bytes) => {
                        let msg = ShellMessage::ShellStdout(bytes);
                        let payload = msg.encode()?;
                        if let Err(e) = ch_writer.send(&payload).await {
                            tracing::debug!("Shell bridge: send failed ({e}) — client closed");
                            break;
                        }
                    }
                    // 读端 EOF（Unix 自然 EOF / 会话已销毁）→ 结束会话。
                    None => {
                        pty_exited = true;
                        break;
                    }
                }
            }
            // 轮询子进程退出（Windows ConPTY 依赖此路径）。
            _ = tokio::time::sleep(PTY_POLL_INTERVAL) => {
                if session.child_exited()? {
                    pty_exited = true;
                    break;
                }
            }
        }
    }

    // 清理：kill 子进程 → 关闭伪控制台（Windows）→ 读线程 EOF 退出；
    // drop stdin_tx → 写线程退出。
    if !pty_exited {
        session.kill();
    }
    drop(stdin_tx);
    Ok(())
}

/// PTY 子进程退出轮询间隔。
const PTY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

// ── 测试 ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_message_roundtrip() {
        for msg in [
            ShellMessage::ShellStdin(b"ls -la\r".to_vec()),
            ShellMessage::ShellStdout("\x1b[32mOK\x1b[0m".as_bytes().to_vec()),
            ShellMessage::ShellResize {
                cols: 132,
                rows: 43,
            },
        ] {
            let wire = msg.encode().unwrap();
            let back = ShellMessage::decode(&wire).unwrap();
            assert_eq!(msg, back, "roundtrip mismatch for {msg:?}");
        }
    }

    #[test]
    fn test_shell_message_decode_rejects_garbage() {
        assert!(ShellMessage::decode(b"not-bincode").is_err());
        assert!(ShellMessage::decode(&[]).is_err());
    }

    /// 真实 PTY 冒烟测试：spawn 一个立即退出的命令并读取其输出。
    ///
    /// Windows ConPTY 已知行为：
    /// - cmd.exe 启动时会发送 `ESC[6n`（DSR 光标位置查询）并**阻塞等待响应**，
    ///   终端必须应答 `ESC[<row>;<col>R` 才会继续 → 测试内模拟终端应答；
    /// - master 读端在伪控制台关闭前不会 EOF → 用 `child_exited` 轮询退出。
    #[test]
    fn test_pty_spawn_and_read() {
        let mut cmd = shell_test_command("echo KIRIN_PTY_SMOKE");
        cmd.env("TERM", "xterm-256color");
        let mut session = PtySession::spawn(Some(cmd), 80, 24).expect("spawn pty");

        let mut reader = session.take_reader().expect("take reader");
        let mut writer = session.take_writer().expect("take writer");
        // 读取线程：输出累积到共享缓冲（ConPTY 关闭后返回 EOF 自动退出）。
        let out: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let out_thread = out.clone();
        let reader_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out_thread.lock().unwrap().extend_from_slice(&buf[..n]),
                }
            }
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut responded_dsr = false;
        loop {
            if session.child_exited().expect("try_wait") {
                break; // 命令已退出（cmd 需先应答 DSR）
            }
            assert!(
                std::time::Instant::now() < deadline,
                "pty child did not exit in 20s"
            );
            if !responded_dsr {
                let has_dsr = out.lock().unwrap().windows(4).any(|w| w == b"\x1b[6n");
                if has_dsr {
                    writer.write_all(b"\x1b[1;1R").unwrap();
                    writer.flush().unwrap();
                    responded_dsr = true;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // 关闭伪控制台 → 读线程 EOF → 线程退出。
        session.kill();
        drop(session);
        let _ = reader_thread.join();

        let all = out.lock().unwrap().clone();
        let text = String::from_utf8_lossy(&all);
        assert!(
            text.contains("KIRIN_PTY_SMOKE"),
            "pty output missing marker: {text:?}"
        );
        // cmd.exe（Windows）启动会发 DSR 查询；Unix shell 不会。
        #[cfg(windows)]
        assert!(responded_dsr, "expected DSR query from cmd.exe startup");
    }

    /// 默认 shell 命令可构造（不 spawn，避免测试环境无 shell）。
    #[test]
    fn test_default_shell_command_builds() {
        let _ = default_shell_command();
    }

    /// Windows：默认命令注入 UTF-8 代码页（T021-05-C，GBK 乱码防护）。
    #[cfg(windows)]
    #[test]
    fn test_windows_default_command_utf8() {
        let cmd = default_shell_command();
        let argv: Vec<String> = cmd
            .get_argv()
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            !argv.is_empty() && argv[0].eq_ignore_ascii_case("powershell.exe"),
            "应启动 powershell.exe，实际: {argv:?}"
        );
        assert!(
            argv.iter().any(|a| a.contains("OutputEncoding")),
            "启动参数应含 OutputEncoding: {argv:?}"
        );
        assert!(
            argv.iter().any(|a| a.contains("65001")),
            "启动参数应含 chcp 65001: {argv:?}"
        );
        // TERM 环境变量保留（xterm-256color 完整终端能力）。
        assert_eq!(
            cmd.get_env("TERM").map(|v| v.to_string_lossy().to_string()),
            Some("xterm-256color".to_owned())
        );
    }

    /// 非法尺寸 resize 静默忽略。
    #[test]
    fn test_pty_resize_guards() {
        let cmd = shell_test_command("echo hi");
        let mut session = PtySession::spawn(Some(cmd), 80, 24).expect("spawn pty");
        session.resize(0, 24).unwrap();
        session.resize(80, 0).unwrap();
        session.resize(100, 40).unwrap();
        assert_eq!(session.size(), (100, 40));
        session.kill();
    }
}

/// 测试用 shell 命令：`echo <marker>` 后立即退出。
/// Windows: `cmd.exe /C echo <marker>`；Unix: `/bin/sh -c 'echo <marker>'`。
#[cfg(test)]
fn shell_test_command(echo: &str) -> portable_pty::CommandBuilder {
    #[cfg(windows)]
    {
        let mut cmd = portable_pty::CommandBuilder::new("cmd.exe");
        cmd.arg("/C");
        cmd.arg(echo);
        cmd
    }
    #[cfg(not(windows))]
    {
        let mut cmd = portable_pty::CommandBuilder::new("/bin/sh");
        cmd.arg("-c");
        cmd.arg(echo);
        cmd
    }
}
