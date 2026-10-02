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
//!   shell 会话文件通道帧（`FileTransferFrame` 不透明字节，与 0x06 同帧体）
//!   单向剪贴板文件元数据帧（`FileClipMeta` 不透明字节，文件传输模式窗
//!   s→c 粘贴语境；老客户端吞帧会话存活）

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

    /// bincode 声明序 = 变体索引，0/1/2 字节零变化）——承载
    /// [`FileTransferFrame`](crate::connection::file_transfer::FileTransferFrame)
    /// 不透明字节（内层 = `bincode(FileTransferFrame)` 既有帧体，与 0x06 通道
    /// 同帧体；帧内 `FileOp` 字段区分帧种）。shell 通道不重分帧。
    ///
    /// **版本语义（§12.2/§12.5）**：仅 `proto_ver == 3` 对端间使用——老端
    /// bincode 见判别值 3 = 未知枚举：服务端单帧解码失败 = 会话终止
    ///（`Err(e) => return Err(e)` 不变式）；客户端 `_ => {}` 吞帧会话存活。
    /// 双向不对称 = 版本门控硬需求（发文件帧给老端 = 先版本判定，禁探测法）。
    File(Vec<u8>),

    /// 服务端 → 客户端**单向**剪贴板文件元数据帧（被控端本机板文件清单 →
    /// 主控端文件传输模式窗粘贴拉取语境）。载荷 = `bincode(FileClipMeta)`
    /// 不透明字节（ui 层自含结构，core 不解析——同 `File` 变体「桥不重帧、
    /// 不解码」纪律；`ShellMessage` 长度定界 AEAD 消息，**无需 0x05 分片**）。
    ///
    /// **版本语义（单向安全）**：**仅服务端发送**——客户端永不产生本变体
    ///（服务端解码 fail-closed 不变式 `Err(e) => return Err(e)` 零触达）；
    /// 老客户端（无本变体）bincode 解码失败 = 接收循环 `_ => {}` /
    /// `if let Ok` 吞帧、**会话存活**（shell/file 双接收循环吞帧形态 =
    /// ui 层既有不变式）→ 旧版本互通零破坏（老端仅无 s→c 剪贴板语境，
    /// PTY/文件帧链路逐位不变）。
    ClipMeta(Vec<u8>),
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
    master: Option<Box<dyn portable_pty::MasterPty + Send>>,
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
        let child = match pair.slave.spawn_command(cmd) {
            Ok(c) => c,
            Err(e) => {
                // **已建立**（Windows：`openpty` → `CreatePseudoConsole` 已拉起
                // conhost.exe --headless 服务端）——伪控制台关闭（
                // `ClosePseudoConsole`，conpty 服务端排空挂起 I/O 时可长阻塞，
                // 事故实证可挂至进程重启）同样**离 worker** 交回收线程：
                // 修前 `?` 早退在调用 worker 上 drop `pair`（master 字段 drop =
                // 次序关键：先 drop slave（仅 `Arc<Mutex<Inner>>` 克隆 = 纯引用
                // 计数，零内核调用——portable-pty 0.9.0 conpty.rs:35-37），再交
                // master → 保证 `Inner` 末次 drop（ClosePseudoConsole）落在回收
                // 线程而非调用方。
                drop(pair.slave);
                reap_pty_parts_off_worker(None, pair.master);
                return Err(ShellError::PtySpawn(e.to_string()));
            }
        };
        drop(pair.slave);

        Ok(Self {
            master: Some(pair.master),
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
            .as_mut()
            .ok_or_else(|| ShellError::PtySpawn("pty session reaped".to_string()))?
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
            .as_mut()
            .ok_or_else(|| ShellError::PtySpawn("pty session reaped".to_string()))?
            .take_writer()
            .map_err(|e| ShellError::PtySpawn(e.to_string()))
    }

    /// 取出 PTY master 读端（stdout 方向）。
    pub fn take_reader(&mut self) -> Result<Box<dyn Read + Send>, ShellError> {
        self.master
            .as_mut()
            .ok_or_else(|| ShellError::PtySpawn("pty session reaped".to_string()))?
            .try_clone_reader()
            .map_err(|e| ShellError::PtySpawn(e.to_string()))
    }

    /// 强制终止子进程（回收线程 `reap_pty_parts_off_worker`/Drop 兜底时也会执行）。
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

    ///
    /// 拆除期的阻塞内核调用——子进程 reap（`child.wait()` =
    /// WaitForSingleObject(INFINITE)）与 **Windows 伪控制台（ConPTY）master
    /// 关闭（`ClosePseudoConsole`，conpty 服务端排空挂起 I/O 时可挂数十秒至
    /// 分钟级）**——此前直接在 tokio worker 上同步执行（旧 `Drop` 内
    /// `child.wait()` + 字段 drop 关伪控制台）→ worker 线程被挂起 → 同 runtime
    /// 长驻任务（IdClient 心跳/剪贴板轮询）整体停摆 → relay 心跳超时判离线
    /// →「设备不在线」，仅重启进程可恢复。收口 = 拆出交 std 线程执行：
    /// worker 零阻塞；共享心跳（IdClient，单一长驻组件）只被会话引用、
    /// 永不被会话退出路径停止（心跳收敛复用口径，非新增心跳/非 shell 特判）。
    pub fn take_reap_parts(
        &mut self,
    ) -> Option<(Option<Box<dyn portable_pty::Child + Send + Sync>>, Box<dyn portable_pty::MasterPty + Send>)> {
        // 返回 `None` 且**不动 child 槽**。修前次序 = 先取 child 再看 master：
        // master 缺失时 child 已被白取（脱离结构体、未交回收、仅句柄随
        // 结构体 drop 关闭 = 子进程未 kill 的孤儿窗）。现次序下「部分取走」
        // 在结构上不可达。
        let master = self.master.take()?;
        let child = self.child.take();
        Some((child, master))
    }
}

/// 两个内核调用均可长阻塞——std 线程挂起无害（线程退出即释放），
/// tokio worker 挂起 = 全 runtime 停摆（事故根因，见 [`PtySession::take_reap_parts`]）。
///
/// 修前 `.ok()` 吞掉该分支——闭包随 spawn 失败被 drop：`master` 的关闭
/// `child` 仅句柄关闭**未 kill**（powershell `-NoExit` 交互进程存活并附着
/// （父进程消亡 + `--headless --server` + 高 CPU 自旋）。修后：建线程前先
/// 预备 kill 句柄克隆（`Child: ChildKiller` 超trait 的 `clone_killer`，进程
/// 句柄克隆零副作用），spawn 失败即同步 kill——`TerminateProcess` 为同步
/// 确定性击杀；此处阻塞属系统级降级（该分支仅在 OS 连 std 线程都建不出
/// 时触发，正确性 > 活性）。`master`/child 句柄已随闭包 drop 关闭
/// （HPCON 必关 = conhost 无「句柄常开」孤儿源），conhost 随句柄关闭 +
/// 子进程消亡即退。
fn reap_pty_parts_off_worker(
    child: Option<Box<dyn portable_pty::Child + Send + Sync>>,
    master: Box<dyn portable_pty::MasterPty + Send>,
) {
    let fallback_killer = child.as_ref().map(|c| c.clone_killer());
    let spawned = std::thread::Builder::new()
        .name("kirin-pty-reap".into())
        .spawn(move || {
            if let Some(mut c) = child {
                let _ = c.kill();
                let _ = c.wait();
            }
            // `drop(master)` = `ClosePseudoConsole` 在内核侧可能永久挂起
            // 成功后线程即停于该调用）；宿主进程退出时挂起的关闭随之消亡，
            // 形态，用户态无法以次序/超时打断该内核调用）→ 看门狗宽限窗后
            // 强杀仍存活的本进程归因 conhost = 零孤儿确定性收口。
            #[cfg(windows)]
            conhost_watchdog::arm();
            drop(master);
        });
    if spawned.is_err() {
        if let Some(mut k) = fallback_killer {
            let _ = k.kill();
        }
    }
}


///
/// 路径上，`drop(master)` 内的内核调用 `ClosePseudoConsole` 可**永久挂起**
/// （conpty 服务端排空挂起——回收线程日志停在「已 kill、已 wait 成功、正
/// 关伪控制台」，无下文）。宿主进程（服务端/测试）退出时挂起的关闭随线程
/// 消亡，conhost 进入**存活于一切句柄关闭之外**的僵尸态（自旋烧 CPU，事故
/// 实证 28 个孤儿、单进程累计 CPU 最高 16332s）——用户态无法以调用次序或
/// 超时打断该内核调用 → 唯一确定性收口 = **事后看门狗**：拆点布防，宽限窗
/// 后对本进程归因 conhost 仍存活者 `TerminateProcess` 强杀（与事故处置
/// 动作同种，对僵尸态 conhost 是唯一有效手段）。
///
/// 归因口径（三重过滤，第三方/跨会话 conhost 零误伤）：
/// 1. 命令行含 `--headless` = ConPTY 服务端形态（用户可见终端窗 =
/// 2. **父进程 = 当前进程**——ConPTY 服务端进程由调用进程派生
///    （`CreatePseudoConsole`），本岗取证 17/17 孤儿 conhost 的
///    ppid 均为创建方二进制；第三方 ConPTY（IDE 终端等）ppid ≠ 本进程，
///    结构上不可误伤；
/// 3. **拆点快照内**——快照于 `arm` 时（`drop(master)` 之前）取，宽限窗后
///    仅杀快照中仍存活者 → 同进程后续会话新建的 conhost 结构上不在旧快照
///    = 跨会话零误杀（压测背靠背多轮形态的护栏）。
///
/// 成本界：仅 Windows 启用；枚举（powershell = 机器标准工具，零新依赖，
/// 与本岗盘点查询同口径）与强杀全在独立 std 线程
/// 正常形态（排空完成、conhost 自退，观测最坏 6.04s < 宽限 10s）复核为空
/// = 零副作用。
#[cfg(windows)]
pub mod conhost_watchdog {
    /// 形态 = 无限，此界只需 > 正常排空即不误伤健康 conhost。
    const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

    /// 在飞看门狗句柄（测试 drain 钩子 + 完成句柄剪枝；生产路径自回收，
    /// 无外部依赖）。
    static PENDING: std::sync::Mutex<Vec<std::thread::JoinHandle<u32>>> =
        std::sync::Mutex::new(Vec::new());

    /// 已布防未完成的看门狗计数（`join_pending` 相位界：先等「布防登记」、
    /// 再等「完成」——回收线程 spawn→arm 延迟为亚毫秒级，50ms 轮询即稳健
    /// 界；仅靠 PENDING 空/非空无法区分「尚未布防」与「无看门狗」）。
    static ARMED: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// 枚举「父进程 = 当前进程的 headless conhost」（严格归因集，口径见
    /// 模块文档）。查询失败（powershell 异常等）= 返回空集——fail-open：
    /// 看门狗不激活，绝不在查询失败上误杀。
    pub(crate) fn our_headless_conhost_pids() -> Vec<u32> {
        let pid = std::process::id();
        let ps = format!(
            "(Get-CimInstance Win32_Process -Filter \"name='conhost.exe'\") | \
             Where-Object {{ $_.CommandLine -like '*--headless*' -and \
             $_.ParentProcessId -eq {pid} }} | ForEach-Object {{ $_.ProcessId }}"
        );
        let Ok(out) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .output()
        else {
            return Vec::new();
        };
        if !out.status.success() {
            return Vec::new();
        }
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.trim().parse::<u32>().ok())
            .collect()
    }

    /// 强杀给定 PID（单次 powershell 调用，尽力而为；逐个 `ErrorAction
    /// SilentlyContinue` = 单个已退不影响其余）。
    fn kill_pids(pids: &[u32]) -> u32 {
        if pids.is_empty() {
            return 0;
        }
        let ids = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let ps = format!("Stop-Process -Id {ids} -Force -ErrorAction SilentlyContinue");
        let ok = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            pids.len() as u32
        } else {
            0
        }
    }

    /// 布防看门狗（`kirin-pty-reap` 回收线程在 `drop(master)` **之前**调用
    /// ——关闭调用可能永不返回，看门狗必须先于它存在）：此刻快照归因 conhost
    /// 集 → 独立线程睡 `DRAIN_GRACE` → 复核 → 强杀快照中仍存活者。
    ///
    /// `ARMED` 计数入口自增、看门狗线程出口自减（空快照/建线程失败即时
    /// 自减）——`join_pending` 据此区分「尚未布防」（计数未起）与「无看门狗」
    /// （计数未起且已过布防延迟界），消除调用方与回收线程 spawn→arm 的
    /// 竞态（本岗首跑实证：join 先于 arm 登记 → 误判无看门狗 → 断言穿前）。
    pub fn arm() {
        ARMED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let snapshot = our_headless_conhost_pids();
        if snapshot.is_empty() {
            ARMED.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return; // 无可看管对象（已退/查询异常）
        }
        let spawned = std::thread::Builder::new()
            .name("kirin-conhost-watchdog".into())
            .spawn(move || {
                std::thread::sleep(DRAIN_GRACE);
                let survivors: Vec<u32> = our_headless_conhost_pids()
                    .into_iter()
                    .filter(|p| snapshot.contains(p))
                    .collect();
                let killed = kill_pids(&survivors);
                if killed > 0 {
                    tracing::warn!(
                        pids = ?survivors,
                        "ConPTY 看门狗：强杀 {killed} 个卡死 headless conhost \
                         塞于关闭调用 = 线程级残留有界，conhost 零孤儿）"
                    );
                }
                ARMED.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                killed
            });
        if let Ok(h) = spawned {
            let mut guard = PENDING.lock().unwrap();
            guard.retain(|h| h.is_finished()); // 生产自回收：剪已完成句柄
            guard.push(h);
        } else {
            ARMED.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// 测试钩子（跨 crate e2e 拆除收尾亦用）：等待**所有**已布防看门狗完成
    /// （强杀动作落地，零孤儿断言才不被时序穿前）；到期限未完成的句柄摘出
    /// 自回收。生产路径无调用方（句柄自回收，登记仅剪枝用）。
    ///
    /// 两相位：①等本次拆除的看门狗**布防登记**（`ARMED` 起跳——回收线程
    /// spawn→kill→wait→arm 为亚毫秒级，5s 短界即稳健；conhost 在 arm 前
    /// 已自退 = 无看门狗，短界后直接进入②）；②等**全部**布防看门狗完成
    /// （宽限窗 + 强杀调用）。
    pub fn join_pending(deadline: std::time::Duration) {
        let end = std::time::Instant::now() + deadline;
        // 相位①：等布防登记（短界 = min(5s, deadline)）。
        let reg_end = std::time::Instant::now()
            + std::time::Duration::from_secs(5).min(deadline);
        while ARMED.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            if std::time::Instant::now() >= reg_end {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // 相位②：等全部完成。
        while ARMED.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            if std::time::Instant::now() >= end {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let handles = std::mem::take(&mut *PENDING.lock().unwrap());
        for h in handles {
            if h.is_finished() {
                let _ = h.join();
            }
        }
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // 同样**绝不在 Drop 内同步 reap/关伪控制台**（旧实现的
        // `child.wait()` 即事故阻塞点之一）——统一交回收线程（含看门狗
        // 布防，与显式拆出路径同形 = 兜底不留孤儿窗）。
        if let Some((child, master)) = self.take_reap_parts() {
            reap_pty_parts_off_worker(child, master);
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

/// **文件帧桥接口（单写者解法）**。
///
/// shell 通道写端被桥任务独占（`into_split` 后 `ch_writer` 服务 PTY 输出），
/// per-连接 FileSession 的既有单写者 `Arc<Mutex<SecureChannelSender>>`
///（EncodedPacket 帧法）与 shell 通道（裸 `bincode(ShellMessage)` 无
/// EncodedPacket 层）结构性不兼容 → **文件帧经 mpsc 汇入桥**（同型既有
/// `stdin_tx`/`out_tx` `mpsc::channel(256)` 模式）：
///
/// - `incoming` = 对端到达的 [`ShellMessage::File`] 不透明字节 → 桥原样
///   转发 per-连接 FileSession 任务（**桥不重帧、不解码**——Frame 语义归
///   引擎侧 `handle_frame`）；
/// - `outgoing` = FileSession 任务产出的帧编码字节（`FileTransferFrame::encode`
///   结果）→ 桥包 [`ShellMessage::File`] 统一经 `ch_writer` 发送；
///   产出的 `bincode(FileClipMeta)` 字节 → 桥包 [`ShellMessage::ClipMeta`]
///   统一经 `ch_writer` 发送（**服务端 → 客户端单向**；推送源拆除 = 单帧
///   丢弃会话存活，客户端断开 = 发送失败走统一拆除路径）。
///
/// PTY 帧与文件帧**共用同一写端** = 帧边界零破（AEAD 逐消息定界不变）；
/// FileSession **不持有** shell 通道写端。发送端（FileSession 任务）退出
/// 时 `outgoing` 对端 drop → 桥仅收不到文件帧（PTY 不受影响）；桥退出时
/// `incoming` 对端 drop → 引擎侧转发静默失败（帧丢弃，§12.5 文件帧单帧
/// 失败不拆 PTY 会话）。
pub struct ShellFileBridgeIo {
    incoming: mpsc::UnboundedSender<Vec<u8>>,
    outgoing: mpsc::UnboundedReceiver<Vec<u8>>,
    /// 纯文件/PTY 形态逐位不变；桥 select 臂 `None` = pending 恒不命中）。
    clip_in: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    /// 0 = 未注册〔纯 PTY/legacy 形态〕）。
    pub clip_session_id: u64,
}

impl ShellFileBridgeIo {
    /// 构造桥接口（`incoming` = 桥 → 引擎侧；`outgoing` = 引擎侧 → 桥）。
    pub fn new(
        incoming: mpsc::UnboundedSender<Vec<u8>>,
        outgoing: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Self {
        Self {
            incoming,
            outgoing,
            clip_in: None,
            clip_session_id: 0,
        }
    }

    /// `clip_session_id` = ui 层注册表键，会话拆除点 deregister 消费）。
    pub fn with_clip_in(
        mut self,
        clip_in: mpsc::UnboundedReceiver<Vec<u8>>,
        clip_session_id: u64,
    ) -> Self {
        self.clip_in = Some(clip_in);
        self.clip_session_id = clip_session_id;
        self
    }
}

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
///
///（`None` = 纯 PTY 会话，legacy-0 放行端/不支持端点的文件臂门控结果，
/// §12.3-3 fail-closed）。文件帧到达 = 原样转发 per-连接 FileSession 任务
///（转发失败仅丢帧告警，**不拆 PTY**，§12.5）；FileSession 产出帧 =
/// `ShellMessage::File` 经同一 `ch_writer` 发送（单写者，帧边界零破）。
pub async fn run_shell_bridge(
    ch: SecureChannel,
    cols: u16,
    rows: u16,
    command: Option<portable_pty::CommandBuilder>,
    file_io: Option<ShellFileBridgeIo>,
) -> Result<(), ShellError> {
    let mut session = PtySession::spawn(command, cols, rows)?;
    session.resize(cols, rows)?;

    let (mut ch_reader, mut ch_writer) = ch.into_split();

    // UnboundedSender 廉价克隆）/ `file_out_rx`（引擎侧 → 本任务发送臂）。
    let (file_in_tx, mut file_out_rx, mut clip_rx) = match file_io {
        Some(io) => (Some(io.incoming), Some(io.outgoing), io.clip_in),
        None => (None, None, None),
    };

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
                        //（客户端构造面不产生本变体）——到达 = 协议误用，
                        // 静默丢弃（fail-safe 不拆会话：同 `ShellStdout` 臂
                        // 「服务端不应收到」口径）。
                        Ok(ShellMessage::ClipMeta(_)) => {}
                        // 不透明字节原样转发 per-连接 FileSession 任务（桥不解码）。
                        // 转发失败 = 引擎侧已退出（会话拆除中）→ 丢帧告警，
                        // **不拆 PTY 会话**（§12.5：文件帧单帧失败 ≠ 流级致命；
                        // 流级致命仅 `Err(e) => return Err(e)` 解码失败不变式）。
                        Ok(ShellMessage::File(payload)) => {
                            if let Some(tx) = &file_in_tx {
                                if tx.send(payload).is_err() {
                                    tracing::debug!(
                                        "Shell bridge: file session channel closed — frame dropped (PTY unaffected)"
                                    );
                                }
                            }
                            // `file_in_tx = None`（无文件臂）时收到 File 帧 =
                            // 对端向 legacy 端点发文件帧——版本门控应已阻止
                            // （§12.3-3）；到达即静默丢弃（fail-closed 兜底，
                            // 不拆会话：PTY 照常）。
                        }
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
            // 共用 `ch_writer` 单写者（select! 统一消费 = 帧边界零破）。
            file_out = async {
                match file_out_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match file_out {
                    Some(bytes) => {
                        let msg = ShellMessage::File(bytes);
                        let payload = msg.encode()?;
                        if let Err(e) = ch_writer.send(&payload).await {
                            tracing::debug!("Shell bridge: file frame send failed ({e}) — client closed");
                            break;
                        }
                    }
                    // 引擎侧文件帧源退出（per-连接 FileSession 任务结束）→
                    // 结束会话：正常运行序 = 桥先退（PTY 终止/客户端断开）→
                    // drop `file_in_tx` → 引擎任务随输入通道关闭退出，故此分支
                    // 先到 None 仅发生于引擎任务异常死亡——fail-closed 终止
                    // （文件通道整体失效时 PTY 独活无意义且掩盖故障）。
                    None => break,
                }
            }
            // 帧共用 `ch_writer` 单写者 = 帧边界零破）。**发送失败 = 客户端
            // 已断开**（既有发送臂同语义：break 走统一拆除路径）；**接收端
            // 关闭**（全局推送任务拆除 / 注册表 deregister）= 单帧丢弃、
            // 会话存活（剪贴板语境属增值面，非会话级致命——§12.5 文件帧
            // 单帧失败不拆会话同口径）。
            clip = async {
                match clip_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(bytes) = clip {
                    let msg = ShellMessage::ClipMeta(bytes);
                    let payload = msg.encode()?;
                    if let Err(e) = ch_writer.send(&payload).await {
                        tracing::debug!("Shell bridge: clip meta send failed ({e}) — client closed");
                        break;
                    }
                }
                // None = 推送源拆除（会话本任务随后自退/服务端停止）——
                // 零动作，循环续跑（不 break：PTY/文件面独立存活）。
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

    // 清理：kill 子进程（快速系统调用，worker 上安全）→ 读线程 EOF 退出；
    // drop stdin_tx → 写线程退出。
    if !pty_exited {
        session.kill();
    }
    drop(stdin_tx);
    // master/伪控制台关闭，均可长阻塞的内核调用）拆出交专用 std 回收线程——
    // tokio worker 零阻塞（详见 `PtySession::take_reap_parts` 文档；未拆出时
    // `Drop` 兜底同路径，worker 仍零阻塞）。回收线程内布防 conhost 看门狗
    if let Some(parts) = session.take_reap_parts() {
        reap_pty_parts_off_worker(parts.0, parts.1);
    }
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
            // 原样承载 FileTransferFrame 帧体，桥侧不重帧）。
            ShellMessage::File(b"inner-bincode-frame-bytes".to_vec()),
            // `bincode(FileClipMeta)`，桥侧不重帧、不解码）。
            ShellMessage::ClipMeta(b"inner-bincode-clip-meta-bytes".to_vec()),
        ] {
            let wire = msg.encode().unwrap();
            let back = ShellMessage::decode(&wire).unwrap();
            assert_eq!(msg, back, "roundtrip mismatch for {msg:?}");
        }
    }

    /// wire 钉死——bincode 枚举 = 声明序 u32 LE 索引置于 offset 0。
    /// 0/1/2 既有变体字节零变化（混版 PTY 零影响 = §12.6 用例 #9 字节级
    /// 漂移 = 旧版本互通字节级钉死）**；同构纪律 = 0x06 通道
    /// `file_transfer.rs` FileOp 判别值钉死测试。
    #[test]
    fn test_r92s2_shell_message_discriminants_wire_pinned() {
        let cases = [
            (ShellMessage::ShellStdin(vec![1]), 0u32),
            (ShellMessage::ShellStdout(vec![2]), 1),
            (ShellMessage::ShellResize { cols: 80, rows: 24 }, 2),
            (ShellMessage::File(vec![3]), 3),
            (ShellMessage::ClipMeta(vec![4]), 4),
        ];
        for (msg, expected) in cases {
            let bytes = msg.encode().unwrap();
            // bincode 枚举布局 = [u32 变体索引 LE][变体载荷] → 索引恒在
            // offset 0。
            let idx = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            assert_eq!(idx, expected, "ShellMessage 判别值漂移");
            // 编解码回环（逐位回归）。
            assert_eq!(ShellMessage::decode(&bytes).unwrap(), msg);
        }
        // 未知判别值（老端视角收 v3 文件帧 = 值 3 之外的漂移模拟；真实混版
        // 由 §12.2 版本门控双向握手拒绝拦截，此处钉「老端解码必 Err」形态）。
        let mut bad = ShellMessage::File(vec![9]).encode().unwrap();
        bad[0..4].copy_from_slice(&255u32.to_le_bytes());
        assert!(ShellMessage::decode(&bad).is_err(), "未知变体必须解码 Err");
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
        let _serial = pty_test_serial().lock().unwrap();
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
        let _serial = pty_test_serial().lock().unwrap();
        let cmd = shell_test_command("echo hi");
        let mut session = PtySession::spawn(Some(cmd), 80, 24).expect("spawn pty");
        session.resize(0, 24).unwrap();
        session.resize(80, 0).unwrap();
        session.resize(100, 40).unwrap();
        assert_eq!(session.size(), (100, 40));
        session.kill();
    }

    ///
    /// Windows ConPTY 已知行为（`test_pty_spawn_and_read` 既有口径）：
    /// cmd.exe 启动发 `ESC[6n`（DSR 光标位置查询）并**阻塞等应答**，终端
    /// 必须回 `ESC[<row>;<col>R` 才继续 → 无人应答的读端 = 子进程永挂
    /// （本岗首跑两测均因此 RED，判据先于修复有效性暴露 = 测试自身形态
    /// 钉死）。返回 JoinHandle（有界 join = 读端 EOF 判据的载体）。
    fn r133_8_reader_thread(
        mut reader: Box<dyn Read + Send>,
        mut writer: Box<dyn Write + Send>,
        out: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut responded_dsr = false;
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut acc = out.lock().unwrap();
                        acc.extend_from_slice(&buf[..n]);
                        if !responded_dsr && acc.windows(4).any(|w| w == b"\x1b[6n") {
                            responded_dsr = true;
                        }
                        drop(acc);
                        if responded_dsr {
                            let _ = writer.write_all(b"\x1b[1;1R");
                            let _ = writer.flush();
                        }
                    }
                }
            }
        })
    }

    /// child 槽不被部分取走）+ 拆除确定性——交回收线程后读端必在界内到达
    /// EOF/Err（读线程有界退出 = 伪控制台已关闭、conpty 服务端已退）。
    ///
    /// Windows ConPTY 读端在伪控制台关闭前不 EOF（既有口径，`child_exited`
    /// 注释）→ 「master 未关 = conhost outlive」的形态在此以有界 EOF 判据
    #[test]
    fn r133_8_take_reap_parts_idempotent_and_reap_deterministic() {
        let _serial = pty_test_serial().lock().unwrap();
        let cmd = shell_test_command("echo R133_8_REAP");
        let mut session = PtySession::spawn(Some(cmd), 80, 24).expect("spawn pty");
        let reader = session.take_reader().expect("take reader");
        let writer = session.take_writer().expect("take writer");
        let out: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let out2 = out.clone();
        let reader_handle = r133_8_reader_thread(reader, writer, out2);
        // 等子进程自然退出（echo 命令即退；DSR 由读取线程应答）。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "child did not exit in 20s"
            );
            if session.child_exited().expect("try_wait") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        session.kill(); // 已退出 = 幂等空操作（与 `run_shell_bridge` 清理同形）。
        let parts = session
            .take_reap_parts()
            .expect("首次 take_reap_parts 必返回 child+master");
        assert!(
            session.take_reap_parts().is_none(),
            "二次 take_reap_parts 必 None（幂等；部分取走 = 孤儿窗）"
        );
        drop(session); // Drop 兜底：已拆出 → 零动作（不双重回收）。
        reap_pty_parts_off_worker(parts.0, parts.1);
        // 拆除确定性：读线程有界退出（读端 EOF = 伪控制台关闭 = conpty
        // 服务端退出；残留排空输出先读干再 EOF）。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if reader_handle.is_finished() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "master 关闭后 30s 读端仍未 EOF（伪控制台未关闭 = conhost 可 outlive）"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        reader_handle.join().expect("reader thread panicked");
        // 会话真跑过命令（标记在输出中 = 拆除前会话链路有效，判据非空转）。
        let all = out.lock().unwrap().clone();
        assert!(
            String::from_utf8_lossy(&all).contains("R133_8_REAP"),
            "pty 输出缺会话标记: {all:?}"
        );
    }

    ///
    /// 孤儿断言的归因集 = 「父进程 = 当前进程的 headless conhost」
    /// （`conhost_watchdog::our_headless_conhost_pids`）；同二进制内并行
    /// 的 PTY 会话若同时存活会全部落入同一归因集 → 跨测试误报（压测/
    /// 零孤儿回归不得被相邻测试时序拖红）。本文件所有 PTY 起会话测试
    /// 全程持此锁。
    fn pty_test_serial() -> &'static std::sync::Mutex<()> {
        static M: std::sync::Mutex<()> = std::sync::Mutex::new(());
        &M
    }

    /// **默认 shell（powershell 交互态）kill 拆除**形态——事故定案形态
    /// `ClosePseudoConsole` 内核排空挂起 100% 复现，conhost 僵尸自旋并
    /// 存活于进程退出之后；修前每会话泄漏 1 个 headless conhost——
    /// ws/e2e/实验合计 15/15 实证）。
    ///
    /// 修后判据：看门狗（`reap_pty_parts_off_worker` 内布防）宽限窗后
    /// 强杀仍存活的本进程归因 conhost → 强杀动作落地后（`join_pending`
    /// 有界等待），严格归因集必须为**空**。本测 RED = 内核挂起复发 /
    #[cfg(windows)]
    #[test]
    fn r133_8_powershell_kill_watchdog_zero_orphan() {
        use super::conhost_watchdog;
        let _serial = pty_test_serial().lock().unwrap();
        let mut session = PtySession::spawn(None, 80, 24)
            .expect("spawn 默认 shell（powershell，生产形态）");
        let reader = session.take_reader().expect("take reader");
        let writer = session.take_writer().expect("take writer");
        let out: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let out2 = out.clone();
        let reader_handle = r133_8_reader_thread(reader, writer, out2);
        // 到交互提示符（conhost 已附着、阻塞于 ReadConsole = 事故形态前提）。
        std::thread::sleep(std::time::Duration::from_secs(4));
        assert!(
            !session.child_exited().expect("try_wait pre-kill"),
            "shell 未到交互态（提前退出 = 判据无效）"
        );
        session.kill(); // TerminateProcess（阻塞于 ReadConsole 的交互 shell）
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "child did not exit in 10s"
            );
            if session.child_exited().expect("try_wait") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let parts = session.take_reap_parts().expect("take_reap_parts");
        drop(session);
        reap_pty_parts_off_worker(parts.0, parts.1); // 内部关伪控制台前布防看门狗
        // 等看门狗强杀动作落地（宽限 10s + 枚举/强杀调用余量）。
        conhost_watchdog::join_pending(std::time::Duration::from_secs(25));
        assert!(
            conhost_watchdog::our_headless_conhost_pids().is_empty(),
        );
        let _ = reader_handle; // 读线程不 join：conhost 挂死时读端不 EOF，
        // 看门狗强杀即判据出口；读线程仅为会话有效性载体（下方输出非空
        // 断言）。测试进程退出时 OS 回收。
        let all = out.lock().unwrap().clone();
        assert!(
            !all.is_empty(),
            "pty 输出为空 = 会话未真跑（判据无效）"
        );
    }

    /// ConPTY conhost（进程树判据，可移植形态）**。
    ///
    /// 每轮 = **生产拆除形态**——默认 shell（powershell 交互态）+
    /// `TerminateProcess` kill + 与 `run_shell_bridge` 清理段同路径拆除：
    /// 内核排空挂起 100% 复现；修前每轮泄漏 1 个 conhost——
    /// ws/e2e/实验合计 15/15 实证）。
    ///
    /// 判据 = 严格归因集（`--headless` + 父进程 = 当前进程，口径见
    /// `conhost_watchdog` 模块文档）：轮首枚举基线 → 跑一轮创建/拆除
    /// （spawn → take 读写端 → 等交互态 → kill → `take_reap_parts` →
    /// `reap_pty_parts_off_worker`（内部布防看门狗）→ `join_pending`
    /// 等看门狗强杀落地）→ 轮后枚举：**不在基线的新 PID 必须为空**；
    /// 全部轮终了 vs 全局基线**净增 = 0**（跨轮累积泄漏兜底断言）。
    ///
    /// 全程持 `pty_test_serial`（归因集 = 当前进程，同二进制并行 PTY
    /// 会话会互相误报）。非 Windows 平台无 ConPTY 形态（判据不适用），
    /// 测试仅 `#[cfg(windows)]` 编译。
    #[cfg(windows)]
    #[test]
    fn r133_8_pty_stress_no_orphan_conhost() {
        use super::conhost_watchdog;
        const ROUNDS: u32 = 5;
        let _serial = pty_test_serial().lock().unwrap();
        let global_baseline = conhost_watchdog::our_headless_conhost_pids();
        for round in 1..=ROUNDS {
            let round_baseline = conhost_watchdog::our_headless_conhost_pids();
            // 生产形态创建/拆除（`run_shell_bridge` 清理段同路径；
            // 默认 shell = powershell = 事故定案形态）。
            let mut session =
                PtySession::spawn(None, 80, 24)
                    .unwrap_or_else(|e| panic!("round {round}: spawn pty 失败: {e}"));
            let reader = session.take_reader().expect("take reader");
            let writer = session.take_writer().expect("take writer");
            let out: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let out2 = out.clone();
            let reader_handle = r133_8_reader_thread(reader, writer, out2);
            // 到交互态（会话有效性前提；conhost 已附着）。
            std::thread::sleep(std::time::Duration::from_secs(3));
            assert!(
                !session.child_exited().expect("try_wait pre-kill"),
                "round {round}: shell 未到交互态（提前退出 = 判据无效）"
            );
            session.kill(); // TerminateProcess（阻塞于 ReadConsole 的交互 shell）
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                assert!(
                    std::time::Instant::now() < deadline,
                    "round {round}: child did not exit in 10s"
                );
                if session.child_exited().expect("try_wait") {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let parts = session
                .take_reap_parts()
                .expect("round {round}: take_reap_parts");
            drop(session);
            reap_pty_parts_off_worker(parts.0, parts.1); // 内部布防看门狗
            // 等看门狗强杀落地（宽限 10s + 调用余量）；join 语义同时排空
            // 此前各轮布防的看门狗（每轮窗内自完成，此处为收尾确认）。
            conhost_watchdog::join_pending(std::time::Duration::from_secs(25));
            let after = conhost_watchdog::our_headless_conhost_pids();
            let leaked: Vec<u32> = after
                .iter()
                .copied()
                .filter(|p| !round_baseline.contains(p))
                .collect();
            assert!(
                leaked.is_empty(),
                "round {round}: 孤儿 headless ConPTY conhost = {leaked:?}（轮首基线之外的新 PID 在看门狗强杀落地后仍存活）"
            );
            let all = out.lock().unwrap().clone();
            assert!(
                !all.is_empty(),
                "round {round}: pty 输出为空 = 会话未真跑（判据无效）"
            );
            let _ = reader_handle; // 读线程不 join（conhost 挂死时读端不
            // EOF；看门狗强杀即判据出口；测试进程退出时 OS 回收）。
        }
        let final_set = conhost_watchdog::our_headless_conhost_pids();
        let net_new: Vec<u32> = final_set
            .iter()
            .copied()
            .filter(|p| !global_baseline.contains(p))
            .collect();
        assert!(
            net_new.is_empty(),
            "压测累计: {net_new:?} = headless ConPTY conhost 净增（必须为零；跨轮累积泄漏兜底断言）"
        );
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
