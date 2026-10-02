//!
//!
//! # 架构
//!
//! ```text
//! 客户端物理按键
//!   │
//!         ① 提取（scancode / flags / 方向）——capture 格式在此终止，不上游（架构红线①）
//!         ② [`decide_hook_event`] 纯函数判定（门控 → injected → 白名单 → Alt+F4）
//!         ③ 封装 `injector::InputEvent`（复用既有判别式，零 wire 新增）
//!         ▼
//!      HookSink：聚焦会话 input_tx 克隆（E 岗经 [`KbdHook::set_sink`] 写入）
//!         ▼
//!      （汇入既有 mpsc 发送链 → wire → 服务端 SendInput；与 egui 路共用唯一发送路径）
//! ```
//!
//! 结构性 **fail-closed**（设计 §1.3 红线②）：
//! - 安装失败（`SetWindowsHookExW`=0）→ [`spawn`](win_impl::spawn) 返回 `Err`，调用方（E 岗）
//!   退回按钮补偿现状——绝不 panic、绝不静默全量放行；
//! - 门控读到的任何非 ACTIVE 态（含「尚未初始化」=0）→ 钩子立即透传（= 不转发，非放行）；
//! - 看门狗判定钩子失效 → 自动重装；重装失败 → 门控置 INACTIVE（退回补偿按钮）；
//! - 回调体零 panic 路径 / 零日志 / 零阻塞（代码审查门禁，见回调注释）。
//!
//! # 焦点门控（[`HookGate`]，进程级 `AtomicU8`，E 岗每帧写入，默认 INACTIVE）
//!
//! | 值 | 语义 |
//! |---|---|
//! | [`GATE_INACTIVE`] = 0 | 透传：不拦截、不转发（零留存，目标 <1µs；关会话窗后键盘行为完全本机） |
//! | [`GATE_ACTIVE_ALT_F4_SUPPRESSED`] = 2 | 转发白名单键并吞本地 + Alt 按住期 F4 转发远端并**吞本地**（态 A，PM 已裁定默认，RDP 参照） |
//!
//!
//! 态 A（`GATE_ACTIVE_ALT_F4_SUPPRESSED`）下 Alt 按住期 F4 down → **仅合成 F4 down/up 2 事件**
//! （[`Key::F4`] 复用既有判别式 0x3D，零 wire 新增）+ 吞本地 F4；**不合成任何 Alt 事件**
//! （Alt 的 down/up 全走既有 egui 路——Alt 是常规键，egui 可见、`session_key_capture` 照常转发）。
//! 弃用设计 v1.0 §3.4④ 的 4 事件方案（`AltDown[若未转发]+F4Down+F4Up+AltUp`），理由：
//! 1. 「[若未转发]」在回调时刻**不可同步判定**（Tier-2 帧戳判重本波关闭，设计 §3.3）；
//! 2. 合成 `AltUp` 会**提前释放远端 Alt**（用户可能还按着 Alt 继续其他组合）→ 远端产生 Alt
//!    毛刺（组合语义断裂）；
//! 3. 2 事件简化后两情形均正确：egui 已发 AltDown（常态：门控 ACTIVE = 聚焦 = egui 转发面
//!    开启）→ 远端 Alt+F4 成立；egui 漏发 AltDown（实际不可达）→ 远端只收裸 F4 = 无动作，
//!    属 fail-closed 侧。
//!
//! (scan 0x3B)」为 Set 1 的 **F1** 扫描码；F4 的 PS/2 Set 1 码 = **0x3E**（与本仓注入表
//! [`crate::windows::map_scan_code`] `Key::F4 => 0x3E` 锚点互证，单测
//! [`tests::r89d_alt_f4_state_a_pair`] 钉死）。本模块实现采 0x3E（[`SCAN_F4`]）。
//!
//!
//! `KBDLLHF_*` 三常量**本地定义**（值 = MSDN "KBDLLHOOKSTRUCT".flags 权威位定义，与本地
//! winapi 0.3.9 源码双源互证，详见各常量注释），不引用 winapi 的 `LLKHF_*` 常量——
//! 本地定义的理由 = **自包含**（零新依赖不变、整体规避对该组常量的依赖），**并非**
//! winapi 取值有缺陷：
//!   0x80` ≠ MSDK `0x40`（winapi 缺陷）」论断**方向颠倒**——MSDN 位表 **bit7 = 过渡态
//!   (UP)** = `KF_UP >> 8` = 0x80；本地 winapi 0.3.9 `winuser.rs:252`（`KF_UP = 0x8000`）
//!   与 `:647`（`LLKHF_UP = (KF_UP >> 8)`）= 0x80，与 MSDN **一致**。错值
//!   真实 up 事件〔bit7〕全部误判为 down → 白名单键只发 KeyDown 永不发 KeyUp、Alt 簿记
//!   永不清除、Alt+F4 在途对永久失效），回归以真实位模式钉死
//!   （[`tests::r89d2_flags_up_bit7_regression`]）；
//!   全树零命中」**不实**——`winuser.rs:644` 实存，`= (KF_EXTENDED >> 8) = 0x01`，与 MSDN
//!   位表 bit0 = Extended 一致。
//!
//!
//! 回调路径（[`ll_kbd_proc`] + [`decide_hook_event`]）**零 `tracing::`/`log::` 宏调用**
//! （input crate 日志门面 = tracing；WARN 只允许出现在看门狗/安装路径 = 线程日志非回调路径）；
//! 回调体 <1ms（Win8+ `LowLevelHooksTimeout` 默认 1000ms，余量 ≥1000×，F 岗 P99 抽样实测）；
//! 零分配（唯一例外 = sink 要求的 `Vec<InputEvent>` 通道载荷——设计 §3.1 HookSink 定义
//! 使然，决策路径本身零分配）；零阻塞（unbounded `send` 永不阻塞）；零日志、零键内容留存
//! （scan code 不复制进任何缓冲/日志，红线③）。
//!
//! `fetch_add` 计数（[`HookShared`] `stats_*` 字段——5 键位类别命中 + 转发/吞掉三向；
//! 透传由 [`KbdHookStats::passthrough`] 快照推导，省 1 次原子操作），无任何 IO/日志/分配/
//! `cb_counter` 同级成本），白名单键最多共 4 次（≈ <1µs，预算余量 ≥1000× 不变）；
//! 汇总输出全部在**非回调路径**（看门狗 60s tick / `set_gate`·`set_sink` API 沿 / `stop`），
//! 且**零键内容**（只含次数 + 键位类别标签 + 门控/sink 状态，红线③）。
//!
//! **17 分 48s 恒 0 条**（首 tick 必出而未出 = WM_TIMER 从未执行；`SetTimer` 返回值
//! 未校验）。本波三条（**回调零日志/零分配/零阻塞红线不变**，打点只在线程层）：
//! ① `SetTimer` 返回值**校验**——`=0`（MSDN：失败返回 NULL）→ WARN + **fallback 自驱动
//! 定时器线程**（1s 粒度 sleep 循环 + `PostThreadMessageW` 私有消息，观察动作仍只在
//! 钩子线程消息循环内执行；fallback 线程不 join、经投递失败自退出，退出路径零阻塞）；
//! 返回值**≠请求 ID**（同 ID 碰撞时系统另发新 ID，MSDN：WM_TIMER 的 wParam = 返回 ID）
//! → 按**实际 ID** 匹配 `WM_TIMER`（不再钉死常量比对，防「定时器在响、消息循环不认」）；
//! ② `set_gate`/`set_sink` **变化沿行附带当前计数快照**（[`format_hook_stats_edge`]——
//! 定时器路径全死时逐沿仍保有计数证据，不必等 60s）；
//! ③ 退出路径补 final 汇总行——`KbdHook::stop` 既有 `final (stop)` 行（join 后计数定格）
//! 不变，**UI 侧 `quit_all` 托盘退出先显式 `stop`**（原路径直接 `process::exit(0)` 不经
//!
//! ① 回调内追加 1 次 Relaxed 原子 `store`（[`HookShared::last_cb_at_ms`] = 上次回调的
//! UNIX epoch 毫秒；与 `stats_*` 同成本口径，**回调零日志/零分配/零阻塞红线不变**）；
//! ② 统计行新增 `last_cb_age={n}s`（距上次回调秒数，快照时推算；`n/a` = 安装后
//! 从未回调）——**钩子存活判据**：09-09 主丢失段 cb 冻结（13:16:26→13:18:54 恒 1946）
//! 旧口径下「零回调」与「无人按键」不可区分，本字段使「钩子在响但回调停更 N 秒」
//! 直接可读；
//! 沿行/终行同含该字段。
//!
//! 代码级全通〔钩子臂→门控→wire→服务端注入表〕，修复收敛为两个时序/存活缺陷）**：
//! ① **H1 send 段丢失窗**（纳秒级，聚焦丢失沿）：原实现 gate 与 sink **两步非原子**
//! 读取——UI 线程失焦沿（`set_sink(None)` → `set_gate(Inactive)`）间隙内回调可落在
//! 「转发判定已成立（gate 读为 Active）但发送端已撤（sink None）」→ 事件**未发**却
//! 仍吞本地 = 按键两端静默丢失（远端无、Caps/Num 本地态亦不翻）。修复：send 段重构
//! 为**同锁原子快照**（gate 复读 + sink 读 + 发送全在同一 `sink` 锁内，判定与发送
//! 零窗口）；判定收敛纯函数 [`decide_hook_send`]（8 格真值表，单测钉死）——转发意图
//! 成立但任一侧缺失 → **透传不吞**（fail-closed 零键损：键盘行为回落完全本机，绝不
//! 「两端都收不到」）；常态路径（gate Active + sink 在场）与原实现逐位等价（转发+吞，
//! ② **H2 看门狗单定时器盲**（持续因；与「常规键正常 + 白名单键持续死」唯一一致的
//! 形态 = 钩子存活检测失灵）：09-09 定版「`SetTimer` 返回有效 ID 但 WM_TIMER 从未
//! `SetTimer` ret=0 形态，**「返回值非零但定时器路径死」形态看门狗永久失灵** → 钩子
//! 被系统摘除（`LowLevelHooksTimeout` 超时摘除、无回调通知）永不被检知 → 白名单键
//! （物理直按路径唯一靠钩子）永久丢失。修复：fallback 自驱动定时器**常驻**
//! （`hook_thread_main` 安装成功后无条件启动，非仅 ret=0 分支）+ [`decide_watchdog_tick_due`]
//! [`HookShared::last_tick_at_ms`] 锚点。
//! ③ **小键盘簇判定**（Phase B-1「钩子补小键盘臂（若未覆盖）」）：簇余键
//! （KP0-9 / + / − / / / Enter）egui-winit 0.28.1 两映射表**均有臂**（Numpad0-9→Num0-9 /
//! NumpadAdd→Plus / NumpadSubtract→Minus / NumpadDivide→Slash / NumpadEnter→Enter）
//! = egui 路 `session_key_capture` 结构可达，钩子补臂 = Tier-1 结构不相交违例
//! （远端双发双键，设计 §3.3 红线）→ **不补**；零臂盲区仅 KP*（0x37）/ KP.（0x53）
//! [`tests::r121_numpad_cluster_zero_arm_pinned`] 钉死（含 0x4F 非扩展=KP1 /
//! 扩展=KP/ 同码异位双形态）。
//! **实机终判 = 用户复测 CapsLock / KP\* 物理直按**（本岗交付 = 代码链全通 + 两缺陷
//! 修复 + 零臂回归钉死）。
//!
//! 关切；日志定案=服务端注入链健康〔srv-in ok=1、recv=11/inject_ok=11 零失败〕+ 主控
//! 钩子全会程 hit=0/fwd=0 而 cb 14→251→2224 正常增长 + sink 反复 attach/detach〔最长
//! 24s 解挂〕）**：
//! ① **计数/匹配无条件化（观测优先）**：白名单 5 键的匹配与命中计数从「决策之后、
//! `!injected` 单一条件」上移到**回调入口提取之后立即发生**（[`classify_hook_hit`]
//! 纯函数单点，早于 [`decide_hook_event`]——匹配与计数不依赖门控/sink/焦点任何一环，
//! **物理事件**命中计既有 5 类（口径零变化），**注入形态**（`LLKHF_INJECTED` 置位）
//! 白名单命中计新增 `hit_inj` 单计数器（stats 行 `hit_inj={n}` 字段）——09-16 定案的
//! 未决二选一（白名单键的回调**从未到达**〔钩子链上游吞/事件未投递〕vs **到达但形态
//! 非物理**〔injected 置位/scan 形态异于单测假设〕）在下次复测由 `hit_inj` 与既有 5 类
//! 的分布直接判别（回调零日志/零分配/零阻塞红线不变：新增成本 = 每白名单命中至多
//! 1 次 Relaxed 原子，与既有同级）。
//! ② **两端 CapsLock 状态观测（主控侧）**：会话建立（本窗输入线首帧开启）与聚焦重获
//! 上升沿，UI 线程读 `GetKeyState(VK_CAPITAL)` 记 INFO（`local caps=on/off`）——两端
//! 无任何 CapsLock 状态同步机制的现状下，先让「主控本地态」在日志可见（会话建立/
//! 重聚焦各 1 行，用户节奏不刷屏）；**完整两端同步机制 = 设计记档，下轮立项**（本波
//! 零同步动作，只观测）。
//! ③ **服务端 srv-in 行加 vk/scan 字段**：`ev` 短码（kd/ku/kr/sk…）后补
//! 0x1A 实为 VK_SPACE 常量错位）（键盘事件经 wire Key 判别式查 VK/scan 纯映射，
//! 非键盘事件 `-`）——「到达即注入成功但无法辨别到达键」的观测缺口收口
//! （wire 格式零改动，仅日志行扩展）。
//! ④ **焦点去抖（UI 侧，`ui/src/lib.rs`）**：sink attach/detach 加迟滞——detach 需
//! **连续 ≥200ms 失焦判定**（UI 侧纯函数 `sink_attach_hysteresis`，见该模块注释），
//! sink 反复 attach/detach 的代码侧放大因子）；本地吞/聚焦语义设计不变（迟滞窗内
//! **实机终判 = 用户复测**（CapsLock/KP\* 物理直按生效 + 焦点不再抖动解挂 +
//! `local caps=` / `vk=/scan=` 观测行判读）。
//!
//! 还是「按到没转」；档案 §2：179 新包时段 9 次 sink detach 固定析取文案
//! `focus lost / session end` 不可判因 + 白名单命中零逐击日志；**表零改**——
//! 扫描码表已证不缺）**：
//! ① **sink attach/detach 原因 DEBUG 行**（[`SinkReason`] 三态：attach =
//! `focus gained` / detach = `focus lost`（会话窗仍在〔失焦/隐私锁/断连/未就绪
//! 形态〕）或 `session end`（末窗关闭））：`set_sink` 签名增 reason 实参（E 岗
//! 调用点按焦点/会话迁移原因同帧写入），沿事件出 [`format_hook_sink_debug_line`]
//! DEBUG 一行（格式钉死单测）；**既有 INFO 沿行（含计数快照）零改动**——字段
//! 口径连续 + 生产默认级别（`[logging] level = "info"`）下 DEBUG 行按需开启
//! （用户复测机 `level = "debug"` 或 `RUST_LOG` 可取得原因明细，零行为变化）。
//! ② **白名单命中 vk/scan INFO 行**（每次命中一行，低频可接受）：回调路径
//! 观察环（[`HIT_RING_CAP`] 128 槽、溢出丢最旧；回调侧仅 1 次锁 + 定长环写，
//! µs 级且仅白名单命中发生，与既有 `stats_*` 原子同级成本），**UI 线程每帧
//! drain**（[`KbdHook::drain_hit_events`]，空环零成本快路径）逐条出
//! [`format_hook_hit_line`] INFO 行（`vk`/`scan`/`key`/`form=physical|injected`
//! /`dir=down|up`；格式钉死单测）——命中时刻至多 1 帧延迟落日志。观测内容仅
//! 5 白名单键（Caps/Num/Win/KP\*/KP. 功能/锁定键，**无字符内容**——红线③「零
//! 键内容留存」意图 = 字符内容零留存，本观测面不涉字符键，PM 裁定本岗落实）。
//! **实机终判 = 用户复测**（聚焦态按键日志链完整可判：hit 行 + stats 行 +
//! 对端 srv-in 行 + caps 行四线对账，判读表见交付报告）。
//!
//! # E 岗接线 API
//!
//! ```ignore
//! use kirin_desk_input::kbd_hook::{spawn, KbdHook, HookGate};
//! let hook = spawn()?;                       // 首个 Desktop 会话窗创建时（Err → 退回按钮补偿）
//! hook.set_sink(Some(input_tx.clone()), SinkReason::FocusGained); // 聚焦切换时写（聚焦窗 input_tx 克隆；失焦/会话终 → None + 对应原因）
//! hook.set_gate(HookGate::ActiveAltF4Suppressed); // 每帧在既有 i.focused 判定块顺带写
//! hook.stop();                               // 末窗关闭/进程退出（幂等，Drop 兜底）
//! ```
//!
//! # 平台策略（设计 §5）
//!
//! Windows 先行（钩子机制仅 Windows 实现）；Linux/macOS = fail-closed 惰性桩
//! 隔离目录双实例回环 + 物理按键实测 + 回调时延抽样 + fail-closed 模拟）。

use crate::injector::{InputEvent, InputKind, Key};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;

// ═══════════════════════ 常量（平台无关；MSDK 来源见模块文档） ═══════════════════════

/// MSDN KBDLLHOOKSTRUCT.flags **位 0** = Extended（扩展键，如功能键/方向键/键区簇）。
/// 双源互证：本地 winapi 0.3.9 `winuser.rs:247`（`KF_EXTENDED = 0x0100`）/ `:644`
/// E-2「winapi 0.3.9 全树零命中」不实（`:644` 实存、值正确）；本地定义 = 自包含。
pub const KBDLLHF_EXTENDED: u32 = 0x00000001;
/// MSDN KBDLLHOOKSTRUCT.flags **位 4** = Injected（事件为注入事件）。
/// 双源互证：本地 winapi 0.3.9 `winuser.rs:645`（`LLKHF_INJECTED = 0x10`）。
pub const KBDLLHF_INJECTED: u32 = 0x00000010;
/// MSDN KBDLLHOOKSTRUCT.flags **位 7** = 过渡态 UP（键已抬起）；**位 6 = Reserved**。
/// 双源互证：本地 winapi 0.3.9 `winuser.rs:252`（`KF_UP = 0x8000`）/ `:647`
/// （`LLKHF_UP = (KF_UP >> 8)` = 0x80），与 MSDN 位表一致。
/// 颠倒（见模块文档「常量来源」节）；错值使真实 up（bit7）恒判 down。回归钉死
/// [`tests::r89d2_flags_up_bit7_regression`]。
pub const KBDLLHF_UP: u32 = 0x00000080;

/// 焦点门控：透传（不拦截、不转发；默认态 = fail-closed）。
pub const GATE_INACTIVE: u8 = 0;
/// 焦点门控：转发白名单键（Alt+F4 = 态 B 零干预）。
pub const GATE_ACTIVE: u8 = 1;
/// 焦点门控：转发白名单键 + Alt 按住期 F4 转发远端并吞本地（态 A，PM 已裁定默认）。
pub const GATE_ACTIVE_ALT_F4_SUPPRESSED: u8 = 2;

/// 表锚点逐键互证，单测 [`tests::r89d_scan_key_roundtrip_matches_injection_table`] 钉死）。
pub const SCAN_KP_MULTIPLY: u16 = 0x37; // KP*（非扩展；注入表 KpMultiply=0x37 同值）
pub const SCAN_KP_DECIMAL: u16 = 0x53;  // KP.（非扩展；0x53+扩展 = 导航 Delete，严禁混淆）
pub const SCAN_CAPS_LOCK: u16 = 0x3A;   // CapsLock（非扩展；注入表 CapsLock=0x3A 同值）
pub const SCAN_NUM_LOCK: u16 = 0x45;    // NumLock（非扩展；注入表 NumLock=0x45 同值）
pub const SCAN_WIN: u16 = 0x5B;         // LWin/RWin 共享 Set 1 码，**必须**带扩展位（前缀 0xE0）
/// F4（非扩展；Set 1）。⚠️ 设计文档 §3.4④ 所记「0x3B」= F1，本岗取证更正（见模块文档勘误节）。
pub const SCAN_F4: u16 = 0x3E;
/// 物理 Alt（态 A 的 F4 序列检测用；Alt 本身不在白名单——egui 路转发，Tier-1 不相交）。
pub const SCAN_ALT_L: u16 = 0x38; // 非扩展
pub const SCAN_ALT_R: u16 = 0x58; // 扩展

// ═══════════════════════════════════ 门控（E 岗 API 面） ═══════════════════════════════════

/// 焦点门控状态（E 岗每帧在既有 `i.focused` 判定块顺带写入；与既有捕获门控同帧同口径，
/// 设计 §3.2：钩子路永远不会比 egui 路「多开」转发面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HookGate {
    /// 透传：不拦截、不转发（默认态，fail-closed）。
    Inactive = GATE_INACTIVE as u8,
    /// 转发白名单键（Alt+F4 = 态 B 零干预）。
    Active = GATE_ACTIVE as u8,
    /// 转发白名单键 + Alt 按住期 F4 转发远端并吞本地（态 A，PM 已裁定默认，RDP 参照）。
    ActiveAltF4Suppressed = GATE_ACTIVE_ALT_F4_SUPPRESSED as u8,
}

impl HookGate {
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn from_u8(v: u8) -> Option<HookGate> {
        match v {
            GATE_INACTIVE => Some(Self::Inactive),
            GATE_ACTIVE => Some(Self::Active),
            GATE_ACTIVE_ALT_F4_SUPPRESSED => Some(Self::ActiveAltF4Suppressed),
            _ => None,
        }
    }
}

// ═══════════════════════════════ 错误类型（平台无关） ═══════════════════════════════

/// 钩子安装/线程错误（全部 → 调用方退回按钮补偿现状，fail-closed）。
#[derive(Debug, Clone, thiserror::Error)]
pub enum KbdHookError {
    /// `SetWindowsHookExW` 返回 0（系统拒绝安装，如策略禁用低层钩子）。
    #[error("WH_KEYBOARD_LL 安装失败（SetWindowsHookExW=0，GetLastError=0x{0:x}）→ 退回按钮补偿现状")]
    InstallFailed(u32),
    /// 钩子线程未在 5s 内回报安装结果（线程启动失败或系统异常）。
    #[error("钩子线程 5s 内未回报安装结果（线程启动失败或系统异常）→ 退回按钮补偿现状")]
    StartTimeout,
    /// 已有存活实例（spawn 单实例；先 `stop` 再重开）。
    #[error("钩子实例已存在（spawn 单实例；先 stop 再重开）")]
    AlreadyRunning,
    /// 线程启动失败（OS 线程资源耗尽等）。
    #[error("钩子线程启动失败：{0}")]
    ThreadSpawn(String),
    /// 非 Windows 平台（fail-closed 惰性桩，设计 §5 三平台策略）。
    #[error("非 Windows 平台：WH_KEYBOARD_LL 钩子层本波未实现（fail-closed 惰性桩，行为 = 现状按钮补偿）")]
    UnsupportedPlatform,
}

// ═══════════════════════════════ 纯决策逻辑（可单测） ═══════════════════════════════

/// 纯决策结果（零堆分配：事件为栈上构造，至多 2 个——Alt+F4 态 A 合成对）。
#[derive(Debug, Clone)]
pub struct HookDecision {
    /// 待转发事件：`count == 1` → 仅 `events[0]`；`count == 2` → `events[0..2]`
    /// （Alt+F4 态 A 合成的 F4 down/up 对，顺序 = down 在前）。
    pub events: [Option<InputEvent>; 2],
    /// 待转发事件数（0 = 不转发）。
    pub count: usize,
    /// 吞本地事件（钩子回调返回非 0）。为 `true` 的两族：① Alt+F4 态 A 的 F4
    /// 裁定：Active 族门控（`GATE_ACTIVE` / `GATE_ACTIVE_ALT_F4_SUPPRESSED`）下
    /// 白名单 5 键转发后吞本地**——会话聚焦时这些键归远端（Win 不再弹本机开始
    /// 菜单→会话窗失焦→gate 掉 Inactive→「按 Win 后画面还在但控制丢失」定版
    /// 机制根治；Caps/Num 本地状态同步不再翻转，RDP 参照语义）。Inactive 族
    /// 恒 `false`（透传，键盘行为完全本机，fail-closed 语义不变）。
    pub swallow: bool,
    /// 本事件处理后的新 Alt 按住态（回调据此更新自身簿记；态 A 的 F4 序列检测依赖它）。
    pub alt_down: bool,
    /// 本事件处理后的新 F4 合成对在途态（回调据此更新自身簿记；对应在途 F4Up 到达时吞掉，
    /// 防远端重复 KeyUp）。
    pub f4_pair_in_flight: bool,
}

impl HookDecision {
    /// 透传（不转发、不吞）。
    #[inline]
    fn passthrough(alt_down: bool, f4_pair_in_flight: bool) -> Self {
        Self {
            events: [None, None],
            count: 0,
            swallow: false,
            alt_down,
            f4_pair_in_flight,
        }
    }

    /// 吞本地（不转发）。
    #[inline]
    fn passthrough_swallow(alt_down: bool, f4_pair_in_flight: bool) -> Self {
        Self {
            events: [None, None],
            count: 0,
            swallow: true,
            alt_down,
            f4_pair_in_flight,
        }
    }
}

/// `KBDLLHOOKSTRUCT.flags` → 3 位提取（**纯函数**，零分配，可单测）。
///
/// 返回 `(is_up, extended, injected)`。位表双源互证：MSDN "KBDLLHOOKSTRUCT".flags
/// （bit0 = Extended / bit4 = Injected / **bit6 = Reserved** / bit7 = UP）+ 本地
/// winapi 0.3.9 `winuser.rs:644` / `:645` / `:252`+`:647`（详见上方常量注释）。
///
/// 内联于 `ll_kbd_proc`（FFI 不可单测），且单测 `dec` 助手 is_up 另传 bool、flags 用
/// 钉死（bit7 = up / bit6 = Reserved 不得判 up）：[`tests::r89d2_flags_up_bit7_regression`]。
#[inline]
pub fn extract_kbdllhf(flags: u32) -> (bool, bool, bool) {
    (
        flags & KBDLLHF_UP != 0,
        flags & KBDLLHF_EXTENDED != 0,
        flags & KBDLLHF_INJECTED != 0,
    )
}

/// 核心纯决策函数（**可单测**；回调只做提取 + 调本函数 + 簿记更新 + sink 发送）。
///
/// 入参 = 从 `KBDLLHOOKSTRUCT` 提取的 4 要素（scancode / flags / 方向）+ 当前门控态 +
/// 2 个簿记位；出参 = [`HookDecision`]（零堆分配）。
///
/// 判定顺序（fail-closed：任何不确定态 → 不转发、不吞）：
/// 1. 物理 Alt 抬起/按下 → 更新 `alt_down` 簿记（LAlt 0x38 非扩展 / RAlt 0x58 扩展），
///    Alt 本身透传（不在白名单——egui 路照常转发，Tier-1 结构不相交）；
///    **注入事件不参与** Alt 簿记（防其他本地进程注入键翻转状态）；
/// 2. `LLKHF_INJECTED` → 透传（**防自我注入回环**：注入事件不回捕，设计 §8 R4）；
/// 3. 门控 [`GATE_INACTIVE`] → 透传（零留存：scan code 不复制进任何缓冲/日志，目标 <1µs）；
/// 4. Alt+F4 态 A（[`GATE_ACTIVE_ALT_F4_SUPPRESSED`]）：F4 + Alt 按住 → 合成 **F4 down/up
///    2 事件**（E-5 落定，见模块文档「Alt+F4 简化落定」节）+ 吞本地 F4；
/// 5. 白名单 5 键集（[`scan_code_to_blind_key`]）→ 封装 `InputEvent::key(KeyDown|KeyUp, …, 0)`
/// 6. 其余 → 透传。
#[inline]
pub fn decide_hook_event(
    scan_code: u16,
    flags: u32,
    is_up: bool,
    gate: u8,
    alt_down: bool,
    f4_pair_in_flight: bool,
) -> HookDecision {
    let extended = flags & KBDLLHF_EXTENDED != 0;
    let injected = flags & KBDLLHF_INJECTED != 0;

    // ① Alt 簿记（仅物理事件；injected 不翻转状态）
    let is_alt = !injected
        && ((scan_code == SCAN_ALT_L && !extended) || (scan_code == SCAN_ALT_R && extended));
    let alt_down = if is_alt { !is_up } else { alt_down };

    // ② 注入事件：不回捕（无转发、无吞、无簿记翻转）
    if injected {
        return HookDecision::passthrough(alt_down, f4_pair_in_flight);
    }

    // ③ 门控关闭（含「尚未初始化」=0）：纯透传，零留存
    if gate == GATE_INACTIVE {
        return HookDecision::passthrough(alt_down, f4_pair_in_flight);
    }

    // ④ F4（仅 Alt+F4 序列语义在此处理；F4 是常规键，egui 路可见——白名单外，Tier-1 不相交）
    if !extended && scan_code == SCAN_F4 && gate == GATE_ACTIVE_ALT_F4_SUPPRESSED {
        if !is_up && alt_down && !f4_pair_in_flight {
            // Alt 按住 + F4 down → 合成完整对送远端 + 吞本地 F4（本地会话窗不关闭）。
            // 远端 Alt 态由 egui 路的 AltDown 建立（常态：门控 ACTIVE = 聚焦 = egui 转发面开启）；
            // egui 漏发 AltDown 时远端只收裸 F4 = 无动作（fail-closed 侧，E-5 两情形均正确）。
            return HookDecision {
                events: [
                    Some(InputEvent::key(InputKind::KeyDown, Key::F4, 0)),
                    Some(InputEvent::key(InputKind::KeyUp, Key::F4, 0)),
                ],
                count: 2,
                swallow: true,
                alt_down,
                f4_pair_in_flight: true,
            };
        }
        if !is_up && alt_down && f4_pair_in_flight {
            // 防御：对在途期间再收到 F4 down（Windows 下 F 键不自动重复，此分支仅防异常
            // 键盘/驱动）→ 吞掉、不再合成第二对（否则远端连关多窗）。
            return HookDecision::passthrough_swallow(alt_down, true);
        }
        if is_up && f4_pair_in_flight {
            // 对在途的 F4Up → 吞（合成对已完整送达远端；放行会给远端多余 KeyUp，
            // 本地则 down 已吞、up 再放行 = 本地看到半截事件）。
            return HookDecision::passthrough_swallow(alt_down, false);
        }
        if !is_up && !alt_down {
            // F4 无 Alt：非 Alt+F4 序列 → 清陈旧在途标记 + 透传（egui 路照常转发 F4）。
            return HookDecision::passthrough(alt_down, false);
        }
        // F4Up 无在途（按下时 Alt 未按住 → 当时透传，egui 路已发完整 down/up）→ 透传，
        // 两侧均见完整事件对，状态自愈。
        return HookDecision::passthrough(alt_down, f4_pair_in_flight);
    }

    // ⑤ 白名单 5 键集（Tier-1 结构不相交：egui-winit 两表零臂，egui 路不可能双发）
    if let Some(key) = scan_code_to_blind_key(scan_code, extended) {
        let kind = if is_up { InputKind::KeyUp } else { InputKind::KeyDown };
        // （与 Alt+F4 态 A 同款语义）。能到达本分支即 gate ∈ {ACTIVE,
        // ACTIVE_ALT_F4_SUPPRESSED}（INACTIVE 已在 ③ 透传返回）→ 会话聚焦时
        // 这些键归远端：Win 不再弹本机开始菜单（09-09 定版「按 Win 后控制丢失」
        // 机制 = 本地开始菜单→会话窗失焦→gate 掉 Inactive→全键断流），Caps/Num
        // 本地锁定态不再翻转；Inactive 族透传不受影响（键盘行为完全本机）。
        return HookDecision {
            events: [Some(InputEvent::key(kind, key, 0)), None],
            count: 1,
            swallow: true,
            alt_down,
            f4_pair_in_flight,
        };
    }

    // ⑥ 透传
    HookDecision::passthrough(alt_down, f4_pair_in_flight)
}

/// **同一原子快照**（转发意图 / 门控复读 / sink 在场）联合决定。
///
/// H1 根因（用户 09-15「依旧」诊断）：原 `ll_kbd_proc` 先读 gate（转发判定）后锁
/// sink（发送端），两步**非原子**——UI 线程聚焦丢失沿（`set_sink(None)` →
/// `set_gate(Inactive)`）间隙内回调可落在「gate 已读 Active（转发判定成立）但 sink
/// 已撤（发送端缺失）」→ 事件未发出**却仍吞本地** = 按键两端静默丢失。修复 =
/// send 段在同锁内复读 gate + 读 sink + 发送（零窗口），判定收敛本函数。
///
/// 语义（8 格真值表，[`tests::r121_decide_hook_send_matrix`] 钉死）：
/// - `forward = true`（决策要转发，白名单键 / Alt+F4 态 A 合成对）：
///   - `gate_active && sink_present` → `(send = true, swallow = true)` = 原路径
///   - 任一侧缺失（gate 已转 Inactive / sink 已撤 / sink 锁中毒）→ `(false, false)`
///     = **透传不吞**（fail-closed 零键损：键盘行为回落完全本机——「会话不再聚焦
/// - `forward = false`：`(false, swallow)` —— 无转发内容时发送恒 `false`；吞本地
///   跟随决策（Alt+F4 态 A 的吞本地路径、透传路径），与原实现一致。
#[inline]
pub fn decide_hook_send(forward: bool, swallow: bool, gate_active: bool, sink_present: bool) -> (bool, bool) {
    if forward {
        let send = gate_active && sink_present;
        (send, send && swallow)
    } else {
        (false, swallow)
    }
}

/// 盲区 5 键集：scan code（+扩展位）→ wire [`Key`]（**复用既有判别式，零 wire 新增**：
/// KP*=0x66 / KP.=0x67 / CapsLock=0x39 / NumLock=0x68 / Super=0x56）。
///
/// 扩展位口径：0x5B（Win）要求扩展位（LWin/RWin 共享 Set 1 码、前缀 0xE0，与服务端注入口径
/// 对称：`crate::windows` `Key::Super => EXTENDED | 0x5B`）；其余 4 键要求**非扩展**
/// （0x53 扩展 = 导航 Delete，0x37/0x3A/0x45 无标准扩展形态）。
///
/// 与 egui 路转发集**结构不相交**（Tier-1 判重主口径，设计 §3.3）：egui-winit 0.28.1 两映射表
/// [`tests::r89d_scan_key_roundtrip_matches_injection_table`] 以注入表往返互证锁定
/// （防未来改表引入重叠）。
///
/// **余键**（KP0-9 / + / − / / / KP-Enter，Set 1 码 0x47-0x4F / 0x50-0x53 段 / 0x1C 扩展）
/// 在 egui-winit 0.28.1 `key_from_key_code` 两表**均有臂**（Numpad0-9→Num0-9 /
/// NumpadAdd→Plus / NumpadSubtract→Minus / NumpadDivide→Slash / NumpadEnter→Enter）
/// = egui 路 `session_key_capture` 结构可达、正常聚焦下可达远端；钩子若补臂 =
/// Tier-1 结构不相交违例（**远端双发双键**，设计 §3.3 红线）→ **本表不为簇余键开臂**。
/// 全簇物理直按路径结构性完整。判定钉死
/// [`tests::r121_numpad_cluster_zero_arm_pinned`]（含 **0x4F 同码异位双形态**：非扩展
/// = KP1 / 扩展 = KP/，两键都必须恒零臂——防未来误把 KP/ 当盲区开臂）。
#[inline]
pub fn scan_code_to_blind_key(scan_code: u16, extended: bool) -> Option<Key> {
    match (scan_code, extended) {
        (SCAN_KP_MULTIPLY, false) => Some(Key::KpMultiply),
        (SCAN_KP_DECIMAL, false) => Some(Key::KpDecimal),
        (SCAN_CAPS_LOCK, false) => Some(Key::CapsLock),
        (SCAN_NUM_LOCK, false) => Some(Key::NumLock),
        (SCAN_WIN, true) => Some(Key::Super),
        _ => None,
    }
}

/// scan code/扩展位/injected 位，不依赖门控/sink/焦点任何一环，观测优先）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookHit {
    /// 物理事件（`LLKHF_INJECTED` 未置位）白名单命中——计既有 5 键位类别
    Physical(Key),
    /// 注入形态（`LLKHF_INJECTED` 置位）白名单命中——计 `hit_inj` 单计数器
    Injected(Key),
}

/// + injected 位形态拆分。
///
/// 1. 白名单匹配（scan + 扩展位，[`scan_code_to_blind_key`]）未命中 → `None`
///    （非白名单键零计数成本不变）；
/// 2. 命中 + injected 置位 → [`HookHit::Injected`]（09-16 定案未决形态②「到达
///    但形态非物理」的直接观测证据）；
/// 3. 命中 + 物理事件 → [`HookHit::Physical`]。
///
/// **无条件化论证（Phase A 定案落点）**：本函数签名**不含** gate/sink/焦点入参——
/// 匹配与计数在回调入口即发生，门控 INACTIVE / sink 未接 / 焦点抖动任一状态下
/// 白名单命中**恒被计数**（转发意图是否成立由 [`decide_hook_event`] /
/// [`decide_hook_send`] 独立决定，语义零变化）。
#[inline]
pub fn classify_hook_hit(scan_code: u16, extended: bool, injected: bool) -> Option<HookHit> {
    scan_code_to_blind_key(scan_code, extended).map(|key| {
        if injected {
            HookHit::Injected(key)
        } else {
            HookHit::Physical(key)
        }
    })
}

/// Tier-2 帧戳判重（设计 §3.3，**接口预留，本波不实现**）。
///
/// 若未来 egui/egui-winit 升级开始为某白名单键产生 `Event::Key`（两集合出现交集），
/// 判重口径 = `(scancode, 方向 down/up, UI 帧号)` 三元组：UI 帧在 `session_key_capture`
/// 后把本帧已转发键的 (scancode, 方向) 写入双缓冲帧戳（2 帧环形），钩子回调读当前帧戳、
/// 命中则跳过（egui 路已发）。本波 Tier-1 结构不相交恒成立 → 恒返回 `false`。
#[inline]
pub fn dedup_check(_frame_stamp: u64, _scan_code: u16, _is_up: bool) -> bool {
    false
}


/// 只含次数 + 键位类别计数 + 门控/sink 状态）。
///
/// 计数均为**累计值**（回调 Relaxed `fetch_add`，看门狗 60s 存活窗口的 `cb_counter`
/// 另行 swap 清零、不参与本快照——两口径互不干扰）；看门狗 tick / `stop` 读快照输出。
/// 三向口径（回调内互斥完备）：`forwarded` = 该次回调 `decision.count > 0`；
/// `swallowed` = `decision.count == 0 && decision.swallow`；其余 = 透传（推导）。
/// 注：Alt+F4 态 A 的 F4 down（合成对 + 吞本地，`count=2 && swallow=true`）计入
/// `forwarded`（一次回调计 1，不按事件数计）——诊断口径 = 回调三向，非事件数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KbdHookStats {
    /// 累计回调次数（进入钩子回调的**每个**键盘事件，含 injected 事件）。
    pub cb_total: u64,
    /// 累计 KP*（0x37 非扩展）白名单命中（物理事件；injected 不计）。
    pub hit_kp_mul: u64,
    /// 累计 KP.（0x53 非扩展）白名单命中（物理事件；injected 不计）。
    pub hit_kp_dec: u64,
    /// 累计 CapsLock（0x3A 非扩展）白名单命中（物理事件；injected 不计）。
    pub hit_caps: u64,
    /// 累计 NumLock（0x45 非扩展）白名单命中（物理事件；injected 不计）。
    pub hit_num: u64,
    /// 累计 Win（0x5B 扩展）白名单命中（物理事件；injected 不计）。
    pub hit_win: u64,
    /// 未决二选一判别观测面：`hit_inj>0` 且对应物人类别 = 0 → 到达但形态非物理；
    /// 两者皆 0 而 cb 增长 → 回调从未见该键〔上游吞/未投递〕）。不计入
    /// [`Self::hit_total`]（物理命中口径零变化）。
    pub hit_inj: u64,
    /// 累计转发次数（该次回调 `decision.count > 0`）。
    pub forwarded: u64,
    /// 累计吞掉次数（`count == 0 && decision.swallow`；态 A 吞掉的在途 F4 up 等）。
    pub swallowed: u64,
    /// 快照时刻门控态（[`GATE_INACTIVE`] / [`GATE_ACTIVE`] /
    /// [`GATE_ACTIVE_ALT_F4_SUPPRESSED`] 之值）。
    pub gate: u8,
    /// 快照时刻 sink 是否已接线（`true` = 聚焦会话 `input_tx` 已写入）。
    pub sink: bool,
    /// `last_cb_at_ms` 与快照时刻推算）。`None` = 安装后从未收到回调。
    pub last_cb_age_secs: Option<u64>,
}

impl KbdHookStats {
    /// 累计白名单命中总数（5 键位类别之和）。
    #[inline]
    pub fn hit_total(self) -> u64 {
        self.hit_kp_mul + self.hit_kp_dec + self.hit_caps + self.hit_num + self.hit_win
    }

    /// 透传次数（推导 = 回调总数 − 转发 − 吞掉；饱和减法防下溢）。
    /// 回调内三向互斥完备（`count>0` / `count==0&&swallow` / 其余），推导精确。
    #[inline]
    pub fn passthrough(self) -> u64 {
        self.cb_total
            .saturating_sub(self.forwarded)
            .saturating_sub(self.swallowed)
    }
}

///
/// 输出**零键内容**（红线③）：无 scan code / 键值——只有次数、键位类别标签
/// （KP*/KP./Caps/Num/Win）与门控/sink 状态。`label` = 输出场景
/// （如 `"60s tick"` / `"final (stop)"`）。
/// 零键内容口径不变——只含次数与类别标签）。
pub fn format_hook_stats_line(s: &KbdHookStats, label: &str) -> String {
    let gate = match HookGate::from_u8(s.gate) {
        Some(g) => format!("{g:?}"),
        None => format!("raw:{:x}", s.gate),
    };
    let last_cb_age = match s.last_cb_age_secs {
        Some(secs) => format!("{secs}s"),
        None => "n/a".to_string(),
    };
    format!(
        s.cb_total,
        s.hit_total(),
        s.hit_kp_mul,
        s.hit_kp_dec,
        s.hit_caps,
        s.hit_num,
        s.hit_win,
        s.hit_inj,
        s.forwarded,
        s.swallowed,
        s.passthrough(),
        gate,
        if s.sink { "on" } else { "off" },
    )
}

/// 计数快照拼接；**可单测**，平台无关）。
///
/// 动机：09-09 复测 60s tick 行 0 条（看门狗定时器路径失灵）⇒ 逐沿数据若只
/// 有「gate: X -> Y」一行则计数证据全丢；沿行附快照后，**定时器全死也保有
/// `label` = 快照标签（`"gate edge"` / `"sink edge"`）。零键内容（红线③）。
pub fn format_hook_stats_edge(edge: &str, s: &KbdHookStats, label: &str) -> String {
    format!("{edge} | {}", format_hook_stats_line(s, label))
}


///
/// 动机（档案 §2）：179 复测时段 9 次 sink detach，既有 INFO 沿行原因文案
/// 恒为固定析取 `"focus lost / session end"`——**不可判**按键时刻 sink=off
/// 究竟是焦点抖动（会话窗仍在、键本地透传）还是会话终。本枚举由 E 岗调用点
/// 按实际迁移原因同帧写入：attach 恒 [`SinkReason::FocusGained`]；detach 按
/// 「会话窗是否仍在存活」判 [`SinkReason::FocusLost`]（仍在：失焦/隐私锁/
/// 断连/未就绪形态）或 [`SinkReason::SessionEnd`]（末窗关闭）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkReason {
    /// attach：聚焦获得（会话窗聚焦 + 输入线就绪）。
    FocusGained,
    /// detach：焦点丢失（会话窗仍在；失焦/隐私锁/断连/未就绪形态）。
    FocusLost,
    /// detach：会话终（末个 Desktop 会话窗关闭；钩子同帧或随后经 lifecycle
    /// Stop 卸载，`final (stop)` 终汇总行接续取证）。
    SessionEnd,
}

impl SinkReason {
    /// 行内标签（纯映射；[`format_hook_sink_debug_line`] 消费，单测钉死）。
    #[inline]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FocusGained => "focus gained",
            Self::FocusLost => "focus lost",
            Self::SessionEnd => "session end",
        }
    }
}

///
/// 默认 info 下不刷屏、复测机开 debug 即得原因明细（沿事件低频，每迁移 1 行）。
pub fn format_hook_sink_debug_line(attached: bool, reason: SinkReason) -> String {
    format!(
        if attached { "attached" } else { "detached" },
        reason.label()
    )
}

///
/// 行 `vk=` 字段同口径）；`scan` = 回调所见 PS/2 Set 1 扫描码；`injected` =
/// （功能/锁定键，无字符内容）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookHitEvt {
    /// 命中的 wire [`Key`]（白名单 5 键之一，`scan_code_to_blind_key` 口径）。
    pub key: Key,
    /// Windows 虚拟键（`blind_key_vk` 映射）。
    pub vk: u16,
    /// 回调所见 PS/2 Set 1 扫描码。
    pub scan: u16,
    pub injected: bool,
    /// 键方向（`true` = up）。
    pub is_up: bool,
}

/// 达：128 次白名单命中跨越 ≥128 帧无 drain 才会发生）。
pub const HIT_RING_CAP: usize = 128;

/// 验收门禁「srv-in vk=0x6A/0x14」同口径）。
#[inline]
pub const fn blind_key_vk(key: Key) -> u16 {
    match key {
        Key::KpMultiply => 0x6A, // VK_MULTIPLY
        // winuser.h 权威值）；旧值 0x6B = **VK_ADD** = 常量错位（与 `windows::map_vk`
        // KpDecimal 臂 0x6E 跨表不一致 = 客户端命中行/服务端 srv-in 行 VK 对账
        // 错乱，本岗 SDK 交叉核验定案修复）。
        Key::KpDecimal => 0x6E,  // VK_DECIMAL
        Key::CapsLock => 0x14,   // VK_CAPITAL
        Key::NumLock => 0x90,    // VK_NUMLOCK
        Key::Super => 0x5B,      // VK_LWIN（白名单口径 = 扩展 0x5B，LWin）
        _ => 0,                  // 仅白名单键入环（防御位；不可达）
    }
}

#[inline]
pub const fn blind_key_label(key: Key) -> &'static str {
    match key {
        Key::KpMultiply => "KpMultiply",
        Key::KpDecimal => "KpDecimal",
        Key::CapsLock => "CapsLock",
        Key::NumLock => "NumLock",
        Key::Super => "Super",
        _ => "Unknown",          // 仅白名单键入环（防御位；不可达）
    }
}

///
/// CapsLock|NumLock|Super> form=<physical|injected> dir=<down|up>`——每次命中
/// 区分 down/up（一次按压 = down+up 两行）。
pub fn format_hook_hit_line(e: &HookHitEvt) -> String {
    format!(
        e.vk,
        e.scan,
        blind_key_label(e.key),
        if e.injected { "injected" } else { "physical" },
        if e.is_up { "up" } else { "down" }
    )
}


/// **断点判定**（**纯函数**，可单测）。
///
/// 输入 = 钩子统计快照（[`KbdHookStats`]，与汇总 INFO 行同源）；输出 = 断点标签
/// （三选一 a 未捕获 / b 已捕获未注入 / c 已注入未生效 的**捕获侧细分**——
/// 下一步对账锚点）。
///
/// gate/sink/焦点 → 命中证据不被门控态稀释；`forwarded` = 决策转发计数）：
/// - `cb_total = 0` → `hook_no_cb`：钩子从未收到任何回调（未装 / 未活）——
///   盲区键捕获前提不成立（先查钩子生命周期行）；
/// - `cb_total > 0 ∧ hit = 0 ∧ hit_inj = 0` → `not_delivered`：**(a) 未捕获**——
///   cb 增长」= 09-23 第四轮 179 日志定案形态：cb=40 hit=0 hit_inj=0）；
/// - `cb_total > 0 ∧ hit = 0 ∧ hit_inj > 0` → `injected_only`：**(a) 未捕获**——
///   仅注入形态命中（到达但形态非物理；物理直按仍缺）；
/// - `hit > 0 ∧ forwarded = 0` → `captured_not_forwarded`：**(a) 已捕获未转发**——
///   零键损）；
/// - `hit > 0 ∧ forwarded > 0` → `capture_ok`：捕获链正常——断点（若有）在
///   服务端注入段（b 映射 / c 补偿），对账锚 = 本端命中行 `vk/scan` ↔ 服务端
pub fn r135_2_breakpoint_verdict(s: &KbdHookStats) -> &'static str {
    if s.cb_total == 0 {
        return "hook_no_cb";
    }
    if s.hit_total() == 0 {
        return if s.hit_inj == 0 { "not_delivered" } else { "injected_only" };
    }
    if s.forwarded == 0 {
        return "captured_not_forwarded";
    }
    "capture_ok"
}

/// 用户第五轮复测 grep 锚点）。
///
/// hit_inj=<n> fwd=<n>`——零键内容（红线③：仅计数 + 标签）；`hit` = 5 物理命中
/// 类之和（`KbdHookStats::hit_total` 同口径）。
///
/// 输出位点（非回调路径，允许 tracing）：sink 接/断沿（仅 `cb_total > 0` 时，
/// 防 attach 沿 `hook_no_cb` 噪音）+ `final (stop)` 会话终结（无条件——会话级
/// 判定锚，join 后计数已定格）。
pub fn format_r135_2_verdict_line(s: &KbdHookStats) -> String {
    format!(
        r135_2_breakpoint_verdict(s),
        s.cb_total,
        s.hit_total(),
        s.hit_inj,
        s.forwarded
    )
}


pub const DRAIN_BUDGET_MS: u64 = 500;
/// 10ms 粒度轮询对回调预算余量 ≥1000× 的口径零影响）。
pub const DRAIN_STEP_MS: u64 = 10;

/// TimedOut → WARN；判定本身零 IO，回调/线程层红线不涉）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainResult {
    /// 在途 = 0 → 卸载路径立即放行。
    Drained,
    /// 在途 > 0 且预算未耗尽 → 继续等待。
    KeepWaiting,
    /// 在途 > 0 且预算耗尽 → 强制放行（调用方 WARN；绝不无限期阻塞退出路径）。
    TimedOut,
}

///
/// = 卸载瞬间回调仍被系统投递/在途；无法复现 → 建观测+防护设施，下次复现即
/// 定案）。调用点 = Windows 侧**跨线程卸载路径**（`KbdHook::shutdown` 的
/// `UnhookWindowsHookEx` 之后）：等回调在途数（回调入口 +1 / 出口 −1，
/// RAII guard 全返回路径覆盖）归零，再发退出信号、释放句柄。
///
/// 入参：`inflight` = 当前在途回调数；`elapsed_ms` = 已等待毫秒；
/// `budget_ms` = 排空预算（生产传 [`DRAIN_BUDGET_MS`]）。
#[inline]
pub fn decide_drain(inflight: u64, elapsed_ms: u64, budget_ms: u64) -> DrainResult {
    if inflight == 0 {
        DrainResult::Drained
    } else if elapsed_ms >= budget_ms {
        DrainResult::TimedOut
    } else {
        DrainResult::KeepWaiting
    }
}


///
/// 分支）→ WM_TIMER 与 fallback 私有消息**双路同活**时同周期内可各到一次
///
/// 「首 tick 必出而未出」正是 09-09 定案锚点）；否则 `now − last ≥ period/2`
/// （半周期）→ 有效 tick。取**半周期而非全周期** = 饿死防御：病态 30s 节拍
/// （两路恰异相 30s）下绝不把看门狗永久去重掉（至多每 60s 2 条有效 tick，
/// 存活检查只更敏感；churn 抑制仍由 `MAX_SUSPECT_STREAK` 管辖）；时钟回拨
/// → 饱和减法 = 0 → 判重复侧（宁漏勿错杀，与看门狗本体口径一致）。
#[inline]
pub fn decide_watchdog_tick_due(last_tick_ms: u64, now_ms: u64, period_ms: u64) -> bool {
    if last_tick_ms == 0 {
        return true;
    }
    now_ms.saturating_sub(last_tick_ms) >= period_ms / 2
}

///
/// `None` = 钩子未安装，或安装后从未回调。纯 Relaxed load（与 watchdog 快照
/// （`close-obs` 行 `kbd_age` 字段）消费——**零行为变化**：无新状态、无新
/// 日志、无决策消费（非 Windows 恒 `None` = fail-closed 桩同款口径）。
pub fn last_cb_age_secs() -> Option<u64> {
    #[cfg(windows)]
    {
        win_impl::last_cb_age_secs()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

// ═══════════════════════════ Windows：FFI 钩子线程实现 ═══════════════════════════

#[cfg(windows)]
mod win_impl {
    use super::*;
    use std::collections::VecDeque;
    use std::os::raw::c_int;
    use winapi::shared::minwindef::{LPARAM, LRESULT, WPARAM};
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::winuser::{
        CallNextHookEx, DispatchMessageW, GetLastInputInfo, GetMessageW, KillTimer,
        KBDLLHOOKSTRUCT, LASTINPUTINFO, MSG, PostThreadMessageW, SetTimer,
        SetWindowsHookExW, TranslateMessage, WH_KEYBOARD_LL, WM_QUIT, WM_TIMER,
    };

    // kernel32!GetCurrentThreadId。winapi 0.3.9 该符号在 `processthreadsapi` feature 后
    // （本 crate 未启用，且 `cargo test -p kirin-desk-input` 独立构建面不可依赖跨 crate
    // feature 统一）→ 本地声明直接链接（std 在 Windows 恒链接 kernel32）；零新依赖、零 Cargo.toml 改动。
    // user32!UnhookWindowsHookEx。winapi 0.3.9 对应签名要求的 `HHOOK` 为**私有名义类型**
    // （`*mut HHOOK__`，`HHOOK__` 私有 opaque 结构、别名未公开 → 类型不可写出，E0603/E0308）→
    // 本地以 `*mut c_void` 签名声明同一 user32 符号（C ABI 无名义类型区分，句柄值经 usize 往返无损）。
    extern "system" {
        fn GetCurrentThreadId() -> u32;
        fn UnhookWindowsHookEx(hhk: *mut std::os::raw::c_void) -> i32;
    }

    /// 看门狗周期：60s 存活窗口（设计 §8 R1 ③ / 本岗交底）。
    const WATCHDOG_PERIOD_MS: u32 = 60_000;
    /// WM_TIMER 定时器 id（进程内唯一即可）。
    const WATCHDOG_TIMER_ID: u32 = 0x89D1;
    /// `PostThreadMessageW` 投递到钩子线程队列 → 消息循环执行 `watchdog_tick`，
    /// 观察动作恒在钩子线程执行，与 WM_TIMER 路径同构；零系统消息空间碰撞）。
    const WATCHDOG_FALLBACK_MSG: u32 = 0x8001;
    /// `last_input_sample` 初值（无历史采样）。
    const NO_INPUT_SAMPLE: u32 = u32::MAX;
    /// 连续疑似摘除窗口数上限（churn 抑制：重装未愈超过该值 → 停止自动重装防摘除-重挂循环）。
    const MAX_SUSPECT_STREAK: u32 = 5;
    /// spawn 等待安装结果超时。
    const SPAWN_TIMEOUT_SECS: u64 = 5;


    /// 进程级共享状态（`Arc`；回调〔钩子线程〕/ 看门狗〔钩子线程〕/ E 岗〔UI 线程〕读写，
    /// 全原子或锁保护；本模块锁内无 panic 路径，`unwrap` 仅出现在线程自身生命周期管理）。
    pub struct HookShared {
        /// 焦点门控（E 岗每帧写；默认 [`GATE_INACTIVE`] = fail-closed，设计 §3.2）。
        pub gate: AtomicU8,
        /// 事件 sink（E 岗聚焦切换写：聚焦窗 `input_tx` 克隆；`None` = 不转发）。
        /// 写端 = UI 线程聚焦切换（低频）；读端 = 回调克隆句柄 + 非阻塞 send（µs 级）。
        pub sink: Mutex<Option<UnboundedSender<Vec<InputEvent>>>>,
        /// Alt 按住簿记（态 A；回调维护）。
        pub alt_down: AtomicBool,
        /// F4 合成对在途簿记（态 A；回调维护）。
        pub f4_pair_in_flight: AtomicBool,
        /// 当前钩子句柄（`HHOOK` as usize；看门狗重装更新 / stop 卸载）。
        pub hook: Mutex<Option<usize>>,
        /// 钩子线程 OS 线程 id（stop → `PostThreadMessageW(WM_QUIT)` 退出信号）。
        pub thread_id: AtomicU32,
        /// 回调计数（回调 `fetch_add` 1 / 看门狗每窗口 `swap` 0——「每次推进原子计数」，设计 §8 R1）。
        pub cb_counter: AtomicU64,
        /// 上一看门狗窗口的系统输入时间点（`GetLastInputInfo().dwTime`；初值 = 无采样）。
        pub last_input_sample: AtomicU32,
        /// 连续疑似摘除窗口数（churn 抑制）。
        pub suspect_streak: AtomicU32,
        /// DEGRADED 闩（重装失败 → 不再自动重挂；行为恒 = 现状按钮）。
        pub degraded: AtomicBool,
        /// 累计回调总数（每个回调事件 1；与 `cb_counter` 的 60s 窗口口径并存不互扰）。
        pub stats_cb_total: AtomicU64,
        /// 累计白名单命中：KP*（0x37 非扩展；物理事件）。
        pub stats_hit_kp_mul: AtomicU64,
        /// 累计白名单命中：KP.（0x53 非扩展；物理事件）。
        pub stats_hit_kp_dec: AtomicU64,
        /// 累计白名单命中：CapsLock（0x3A 非扩展；物理事件）。
        pub stats_hit_caps: AtomicU64,
        /// 累计白名单命中：NumLock（0x45 非扩展；物理事件）。
        pub stats_hit_num: AtomicU64,
        /// 累计白名单命中：Win（0x5B 扩展；物理事件）。
        pub stats_hit_win: AtomicU64,
        /// （回调入口计数，与 5 类物理命中同级成本；09-16 定案判别观测面）。
        pub stats_hit_inj: AtomicU64,
        /// 累计转发（该次回调 `decision.count > 0`）。
        pub stats_forwarded: AtomicU64,
        /// 累计吞掉（`count == 0 && decision.swallow`；透传 = 快照推导，不设原子）。
        pub stats_swallowed: AtomicU64,
        /// 回调 Relaxed `store`（与 `stats_*` 同成本口径；非回调路径仅 Relaxed load）。
        pub last_cb_at_ms: AtomicU64,
        /// 仅看门狗路径读写（`watchdog_tick` 入口 `swap` 推进锚点；回调路径不涉）：
        /// WM_TIMER 与 fallback 私有消息双定时器同周期异相位 → [`decide_watchdog_tick_due`]
        pub last_tick_at_ms: AtomicU64,
        pub last_stats: Mutex<KbdHookStats>,
        /// [`HIT_RING_CAP`] 定长槽、溢出丢最旧）。写端 = 回调（**仅白名单命中**，
        /// 1 次锁 + 定长环写，µs 级，零日志/零阻塞红线不变）；读端 = UI 线程
        /// [`KbdHook::drain_hit_events`]（每帧；空环 = 加锁 + 快路径返回）。
        pub hit_ring: Mutex<VecDeque<HookHitEvt>>,
    }

    impl HookShared {
        fn new() -> Self {
            Self {
                gate: AtomicU8::new(GATE_INACTIVE),
                sink: Mutex::new(None),
                alt_down: AtomicBool::new(false),
                f4_pair_in_flight: AtomicBool::new(false),
                hook: Mutex::new(None),
                thread_id: AtomicU32::new(0),
                cb_counter: AtomicU64::new(0),
                last_input_sample: AtomicU32::new(NO_INPUT_SAMPLE),
                suspect_streak: AtomicU32::new(0),
                degraded: AtomicBool::new(false),
                stats_cb_total: AtomicU64::new(0),
                stats_hit_kp_mul: AtomicU64::new(0),
                stats_hit_kp_dec: AtomicU64::new(0),
                stats_hit_caps: AtomicU64::new(0),
                stats_hit_num: AtomicU64::new(0),
                stats_hit_win: AtomicU64::new(0),
                stats_hit_inj: AtomicU64::new(0),
                stats_forwarded: AtomicU64::new(0),
                stats_swallowed: AtomicU64::new(0),
                last_cb_at_ms: AtomicU64::new(0),
                last_tick_at_ms: AtomicU64::new(0),
                last_stats: Mutex::new(KbdHookStats::default()),
                hit_ring: Mutex::new(VecDeque::with_capacity(HIT_RING_CAP)),
            }
        }

        /// 看门狗 tick / `stop`；回调路径零日志零 IO，本方法绝不在回调内使用）。
        fn snapshot_stats(&self) -> KbdHookStats {
            let last_cb_at_ms = self.last_cb_at_ms.load(Ordering::Relaxed);
            let now_ms = unix_epoch_ms();
            let last_cb_age_secs = if last_cb_at_ms == 0 {
                None
            } else {
                Some(now_ms.saturating_sub(last_cb_at_ms) / 1000)
            };
            KbdHookStats {
                cb_total: self.stats_cb_total.load(Ordering::Relaxed),
                hit_kp_mul: self.stats_hit_kp_mul.load(Ordering::Relaxed),
                hit_kp_dec: self.stats_hit_kp_dec.load(Ordering::Relaxed),
                hit_caps: self.stats_hit_caps.load(Ordering::Relaxed),
                hit_num: self.stats_hit_num.load(Ordering::Relaxed),
                hit_win: self.stats_hit_win.load(Ordering::Relaxed),
                hit_inj: self.stats_hit_inj.load(Ordering::Relaxed),
                forwarded: self.stats_forwarded.load(Ordering::Relaxed),
                swallowed: self.stats_swallowed.load(Ordering::Relaxed),
                gate: self.gate.load(Ordering::Relaxed),
                sink: self
                    .sink
                    .lock()
                    .map(|g| g.is_some())
                    .unwrap_or(false),
                last_cb_age_secs,
            }
        }
    }

    /// 兜底，年龄读数最坏为 0 不误报负值）。
    fn unix_epoch_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// SHARED Relaxed load；`last_cb_at_ms == 0`（从未回调）→ `None`。
    pub(super) fn last_cb_age_secs() -> Option<u64> {
        let guard = SHARED.lock().ok()?;
        let shared = guard.as_ref()?;
        let at = shared.last_cb_at_ms.load(Ordering::Relaxed);
        (at != 0).then(|| unix_epoch_ms().saturating_sub(at) / 1000)
    }

    /// 回调对共享状态的引用槽（回调每键访问一次；无竞争时 ~20ns，设计 §8 R2 预算内）。
    /// 单实例语义：`spawn` 写入、钩子线程退出时清空。
    static SHARED: Mutex<Option<Arc<HookShared>>> = Mutex::new(None);

    ///
    /// 回调入口 +1（[`InflightGuard::enter`]）/ 出口 −1（RAII `Drop`，全返回
    /// <1µs）；**回调零 panic/零日志/零阻塞红线不变**（guard 体仅 1 次原子
    /// 操作，无锁、无 IO、无分配）。卸载侧（`drain_inflight_callbacks`）
    /// Acquire load 观测。
    static INFLIGHT_CBS: AtomicU32 = AtomicU32::new(0);

    struct InflightGuard;

    impl InflightGuard {
        #[inline]
        fn enter() -> Self {
            INFLIGHT_CBS.fetch_add(1, Ordering::SeqCst);
            Self
        }
    }

    impl Drop for InflightGuard {
        #[inline]
        fn drop(&mut self) {
            INFLIGHT_CBS.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// `WH_KEYBOARD_LL` 回调（钩子线程专属；系统对**全系统每个键盘事件**同步调用）。
    ///
    /// **零 panic / 零日志 / 零阻塞**（E-6 口径；设计 §8 R1 ② 回调预算 <1ms）：
    /// 体 = 提取（scancode / flags / 方向）→ [`decide_hook_event`] 纯决策 → 簿记更新 →
    /// 至多一次 sink 克隆 + unbounded send（唯一分配 = sink 要求的 `Vec<InputEvent>`
    /// 通道载荷，设计 §3.1 HookSink）。任何异常路径 → `CallNextHookEx` 透传（fail-closed）。
    unsafe extern "system" fn ll_kbd_proc(n_code: c_int, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
        // 同级；零 panic/零日志/零阻塞红线不变，见 [`INFLIGHT_CBS`] 文档）
        let _inflight = InflightGuard::enter();
        if n_code < 0 {
            // 系统要求跳过钩子链 → 原样透传
            return CallNextHookEx(std::ptr::null_mut(), n_code, w_param, l_param);
        }
        let shared = match SHARED.lock() {
            Ok(g) => g.clone(),
            // 锁中毒（理论不可达：本模块锁内无 panic 路径）→ fail-closed 透传，绝不 panic
            Err(_) => return CallNextHookEx(std::ptr::null_mut(), n_code, w_param, l_param),
        };
        if let Some(shared) = shared {
            let data = &*(l_param as *const KBDLLHOOKSTRUCT);
            let scan_code = data.scanCode as u16;
            let flags = data.flags;
            let (is_up, extended, injected) = extract_kbdllhf(flags);

            // 早于决策/sink/门控：匹配与计数不依赖 gate/sink/焦点任何一环（Phase A
            // 定案：计数点若在决策之后=「门控段/解挂段」命中证据被条件化稀释）；
            // `hit_inj` 单计数器（09-16 定案未决二选一判别面：hit_inj>0 且对应物理
            // 类 = 0 → 到达但形态非物理；两者皆 0 而 cb 增长 → 回调从未见该键）。
            // 成本 = 每白名单命中至多 1 次 Relaxed 原子（与既有同级），零分配/
            // 零日志/零阻塞红线不变；转发语义仍全权交 decide_hook_event/
            // decide_hook_send（零变化）。──
            if let Some(hit) = classify_hook_hit(scan_code, extended, injected) {
                let hit_key = match hit {
                    HookHit::Physical(key) | HookHit::Injected(key) => key,
                };
                match hit {
                    HookHit::Physical(key) => {
                        match key {
                            Key::KpMultiply => {
                                shared.stats_hit_kp_mul.fetch_add(1, Ordering::Relaxed);
                            }
                            Key::KpDecimal => {
                                shared.stats_hit_kp_dec.fetch_add(1, Ordering::Relaxed);
                            }
                            Key::CapsLock => {
                                shared.stats_hit_caps.fetch_add(1, Ordering::Relaxed);
                            }
                            Key::NumLock => {
                                shared.stats_hit_num.fetch_add(1, Ordering::Relaxed);
                            }
                            Key::Super => {
                                shared.stats_hit_win.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }
                    HookHit::Injected(_) => {
                        shared.stats_hit_inj.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // INFO 行）——回调**零日志/零分配/零阻塞红线不变**：仅 1 次锁 +
                // 定长环写（预分配槽稳态零分配；溢出丢最旧，实践不可达），
                // 与既有 `stats_*` 原子同级成本（仅白名单命中发生）。──
                if let Ok(mut ring) = shared.hit_ring.lock() {
                    if ring.len() >= HIT_RING_CAP {
                        ring.pop_front();
                    }
                    ring.push_back(HookHitEvt {
                        key: hit_key,
                        vk: blind_key_vk(hit_key),
                        scan: scan_code,
                        injected,
                        is_up,
                    });
                }
            }

            let mut decision = decide_hook_event(
                scan_code,
                flags,
                is_up,
                shared.gate.load(Ordering::Relaxed),
                shared.alt_down.load(Ordering::Relaxed),
                shared.f4_pair_in_flight.load(Ordering::Relaxed),
            );
            // 看门狗窗口计数（1 次原子加；零分配、零日志）
            shared.cb_counter.fetch_add(1, Ordering::Relaxed);
            // 1 次 Relaxed 原子 store，零 IO/零日志/零分配/零阻塞，与 cb_counter 同级成本）
            shared.last_cb_at_ms.store(unix_epoch_ms(), Ordering::Relaxed);
            shared.alt_down.store(decision.alt_down, Ordering::Relaxed);
            shared.f4_pair_in_flight.store(decision.f4_pair_in_flight, Ordering::Relaxed);

            // 回调预算不变，见模块文档「回调预算」节；汇总输出全在非回调路径）──
            shared.stats_cb_total.fetch_add(1, Ordering::Relaxed);
            // 三向（互斥完备）：转发（count>0）/ 吞掉（count==0 && swallow）/ 透传（推导，省 1 原子）
            if decision.count > 0 {
                shared.stats_forwarded.fetch_add(1, Ordering::Relaxed);
            } else if decision.swallow {
                shared.stats_swallowed.fetch_add(1, Ordering::Relaxed);
            }

            // 非原子——UI 线程失焦沿 set_sink(None)→set_gate(Inactive) 间隙内回调
            // 落在「转发判定成立（gate Active）但发送端已撤（sink None）」→ 事件
            // 未发却仍吞本地 = 按键两端静默丢失。修复 = gate 复读 + sink 读 +
            // 发送全在同一 sink 锁内，判定与发送零窗口；判定收敛纯函数
            // [`decide_hook_send`]。常态路径（gate Active + sink 在场）与原实现
            let do_swallow = if decision.count > 0 {
                match shared.sink.lock() {
                    Ok(g) => {
                        // 同锁复读 gate（与 sink 同一临界区：UI 线程写端
                        // set_sink / set_gate 两操作，本临界区保证二者不可能
                        // 在「已读 gate、未读 sink」之间被部分观察到）
                        let gate_active = shared.gate.load(Ordering::Relaxed) != GATE_INACTIVE;
                        let (send, swallow) =
                            decide_hook_send(true, decision.swallow, gate_active, g.is_some());
                        if send {
                            // sink 克隆 + 非阻塞发送（unbounded send 永不阻塞；
                            // 发送失败 = 通道已关（会话终）→ 该事件丢弃 = 现状，fail-closed）
                            if let Some(tx) = g.as_ref() {
                                let mut v = Vec::with_capacity(decision.count);
                                if let Some(e) = decision.events[0].take() {
                                    v.push(e);
                                }
                                if decision.count > 1 {
                                    if let Some(e) = decision.events[1].take() {
                                        v.push(e);
                                    }
                                }
                                let _ = tx.send(v);
                            }
                        }
                        swallow
                    }
                    // sink 锁中毒（理论不可达：本模块锁内无 panic 路径）→ 发送端
                    // 按缺失处理：透传不吞（fail-closed 零键损，与函数入口
                    // SHARED 中毒处理同口径）
                    Err(_) => decide_hook_send(true, decision.swallow, false, false).1,
                }
            } else {
                decide_hook_send(false, decision.swallow, false, false).1
            };
            if do_swallow {
                return 1; // 吞本地事件（白名单键 / Alt+F4 态 A；返回非 0 = 事件不进系统分发）
            }
        }
        CallNextHookEx(std::ptr::null_mut(), n_code, w_param, l_param)
    }

    /// 卸载当前钩子 + 重装（看门狗自愈路径；返回是否成功）。
    unsafe fn reinstall_hook(shared: &HookShared) -> bool {
        if let Ok(mut g) = shared.hook.lock() {
            if let Some(h) = g.take() {
                UnhookWindowsHookEx(h as *mut std::os::raw::c_void);
            }
        }
        // hmod 对 WH_KEYBOARD_LL 被系统忽略（MSDN SetWindowsHookEx：LL 钩子类型忽略
        // hmod/dwThreadId）→ 传 null，免 `libloaderapi` feature（零 Cargo.toml 改动）。
        let h = SetWindowsHookExW(WH_KEYBOARD_LL, Some(ll_kbd_proc), std::ptr::null_mut(), 0);
        if h.is_null() {
            return false;
        }
        if let Ok(mut g) = shared.hook.lock() {
            *g = Some(h as usize);
        }
        true
    }

    /// （返回 `true` = 已排空 / `false` = 预算耗尽强制放行）。
    ///
    /// 范围口径（**只动卸载路径**）：仅 `KbdHook::shutdown`（跨线程卸载点：
    /// UI 线程卸钩，钩子线程此刻可能仍有卸载生效前投递的回调在途）调用。
    /// 另两处 `UnhookWindowsHookEx`（看门狗 `reinstall_hook` / 钩子线程退出
    /// 清理）都在**钩子线程自身**——LL 回调只经钩子线程消息循环派发，该两处
    /// 执行时在途数结构性 = 0，无需排空（记档理由；避免在钩子线程消息循环内
    /// 引入 sleep 阻塞 → `LowLevelHooksTimeout` 摘除风险）。
    ///
    /// 预算 [`DRAIN_BUDGET_MS`]（≤500ms）耗尽仍未归零 → WARN 强制放行
    /// （退出路径绝不无限期阻塞；在途残留计数留日志 = 下次复现定案证据）。
    fn drain_inflight_callbacks() -> bool {
        let start = std::time::Instant::now();
        loop {
            let inflight = INFLIGHT_CBS.load(Ordering::Acquire) as u64;
            match decide_drain(inflight, start.elapsed().as_millis() as u64, DRAIN_BUDGET_MS) {
                DrainResult::KeepWaiting => {
                    std::thread::sleep(std::time::Duration::from_millis(DRAIN_STEP_MS));
                }
                DrainResult::Drained => {
                    tracing::info!(
                        start.elapsed().as_millis()
                    );
                    return true;
                }
                DrainResult::TimedOut => {
                    tracing::warn!(
                        DRAIN_BUDGET_MS
                    );
                    return false;
                }
            }
        }
    }

    /// 60s 看门狗（**钩子线程消息循环内**执行 = 线程日志路径，非回调路径 → 允许 tracing）。
    ///
    /// 存活判据（设计 §8 R1 ③ + 本岗交底「线程侧检测钩子存活」）：
    /// `GetLastInputInfo().dwTime` **双采样**对比——本 60s 窗口内系统输入（鼠标+键盘，
    /// 系统级、与本钩子无关）活跃 + 门控非 INACTIVE + 本钩子回调计数 = 0
    /// → 钩子疑似被系统摘除（`LowLevelHooksTimeout` 超时摘除无回调通知，此为其可观测代理）。
    /// 已知误判面：窗口内仅鼠标活动无键盘 → 冗余重装一次（µs-ms 级 churn，无害）；
    /// `MAX_SUSPECT_STREAK` churn 抑制 + 回调活跃自愈复位。
    /// 处置：WARN + 自动重装；**重装失败 → 门控置 INACTIVE**（退回按钮补偿）+ DEGRADED 闩
    /// （不再自动重挂，防摘除-重挂循环）。
    ///
    /// 「cb 冻结 13:16:26→13:18:54」旧口径下「零回调」与「无人按键」不可区分；
    fn watchdog_tick(shared: &Arc<HookShared>) {
        // 双路可同活）→ 同周期内可各到一次。去重判据 = 纯函数
        // [`decide_watchdog_tick_due`]（`last==0` 首 tick 必出；距上次有效 tick
        // ≥ 半周期 = 有效）。锚点 `last_tick_at_ms` 恒推进（`swap` 返回值 = 旧锚点；
        // 重复 tick 也推进 = 防下一次误判 due）。重复 tick 直接返回：不输出统计
        // tick」口径保持。
        let now_ms = unix_epoch_ms();
        let last_tick = shared.last_tick_at_ms.swap(now_ms, Ordering::Relaxed);
        if !decide_watchdog_tick_due(last_tick, now_ms, WATCHDOG_PERIOD_MS as u64) {
            return;
        }
        // 输出条件：快照相对上次统计行有变化才输出，每 60s tick 至多 1 行。
        // 行内零键内容（只含次数 + 键位类别 + 门控/sink 状态 + 回调年龄，红线③）。
        {
            let snap = shared.snapshot_stats();
            if let Ok(mut last) = shared.last_stats.lock() {
                if snap != *last {
                    tracing::info!("{}", format_hook_stats_line(&snap, "60s tick"));
                    *last = snap;
                }
            }
        }
        let mut lii: LASTINPUTINFO = unsafe { std::mem::zeroed() };
        lii.cbSize = std::mem::size_of::<LASTINPUTINFO>() as u32;
        if unsafe { GetLastInputInfo(&mut lii) } == 0 {
            return; // API 失败 → 本窗口不判定（宁漏勿错杀）
        }
        let new_sample = lii.dwTime;
        let prev = shared.last_input_sample.swap(new_sample, Ordering::Relaxed);
        let input_in_window =
            if prev == NO_INPUT_SAMPLE { false } else { new_sample.wrapping_sub(prev) != 0 };

        let window_count = shared.cb_counter.swap(0, Ordering::Relaxed);
        let gate = shared.gate.load(Ordering::Relaxed);
        if shared.degraded.load(Ordering::Relaxed)
            || !(input_in_window && gate != GATE_INACTIVE && window_count == 0)
        {
            shared.suspect_streak.store(0, Ordering::Relaxed);
            return;
        }

        let streak = shared.suspect_streak.fetch_add(1, Ordering::Relaxed) + 1;
        if streak > MAX_SUSPECT_STREAK {
            // churn 抑制：连续多窗口疑似而重装未愈（典型 = 仅鼠标活动误判）→
            // 停止自动重装；用户键入使回调恢复（window_count>0）即自动复位。
            if streak == MAX_SUSPECT_STREAK + 1 {
                tracing::warn!(
                     停止自动重装（churn 抑制）；回调恢复活跃后自动复位"
                );
            }
            return;
        }
        if streak == 1 {
            tracing::warn!(
            );
        }
        if unsafe { reinstall_hook(shared) } {
            shared.suspect_streak.store(0, Ordering::Relaxed);
        } else {
            // 重装失败 = 钩子层确认异常 → 结构性 fail-closed：门控 Inactive（退回按钮补偿）
            // + DEGRADED 闩（本进程不再自动重挂；E 岗后续帧写门控不改变「无钩子 = 不转发」事实）
            shared.degraded.store(true, Ordering::Relaxed);
            shared.gate.store(GATE_INACTIVE, Ordering::Relaxed);
            tracing::warn!(
                unsafe { GetLastError() }
            );
        }
    }

    ///
    /// 仅限 `SetTimer` ret=0 分支）——09-09 定版形态 = 「`SetTimer` 返回**有效** ID
    /// 仅覆盖 ret=0 形态，「返回值非零但定时器路径死」形态看门狗永久失灵 → 钩子
    /// 被系统摘除（`LowLevelHooksTimeout`，无回调通知）永不被检知。常驻后双路
    /// 同活时由 `watchdog_tick` 入口的 [`decide_watchdog_tick_due`] 半周期去重
    /// 维持看门狗。
    ///
    /// 1s 粒度 sleep 循环（非单次 60s sleep）：① 每 1s 检查 `SHARED` 是否已被
    /// 钩子线程清理置空（= 钩子线程已退出）→ 自退出（≤1s，防孤儿驻留）；② 累计
    /// 满 60s → `PostThreadMessageW` 私有消息唤醒钩子线程消息循环执行
    /// `watchdog_tick`（观察动作**仍在钩子线程**执行，与 WM_TIMER 路径同构——
    /// 回调/线程层红线不变）；③ 投递失败（钩子线程已死）→ 自退出。线程自身零
    /// panic 路径（锁中毒 → 视为不退出条件，继续循环直至上述自退出，绝不 crash
    /// 宿主进程）。
    fn spawn_watchdog_fallback_timer(hook_thread_id: u32) {
        let spawned = std::thread::Builder::new()
            .name("kirin-kbd-watchdog-fb".into())
            .spawn(move || {
                let mut due = 0u32;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    // 钩子线程清理完成（SHARED 置空）→ 观察路径已随其消失，自退出。
                    if matches!(SHARED.lock(), Ok(g) if g.is_none()) {
                        break;
                    }
                    due += 1;
                    if due < WATCHDOG_PERIOD_MS / 1000 {
                        continue;
                    }
                    due = 0;
                    if unsafe { PostThreadMessageW(hook_thread_id, WATCHDOG_FALLBACK_MSG, 0, 0) } == 0
                    {
                        // 钩子线程已死（WM_QUIT 后线程函数返回）→ 自退出。
                        break;
                    }
                }
            })
            .ok();
        if spawned.is_none() {
            tracing::warn!(
            );
        }
    }

    /// 钩子线程主体：安装 → 回报 → 专属消息循环（LL 钩子回调 + 看门狗 WM_TIMER
    /// 〔实际 ID〕/fallback 私有消息 + WM_QUIT）→ 清理。
    fn hook_thread_main(
        result_tx: std::sync::mpsc::Sender<Result<Arc<HookShared>, KbdHookError>>,
        abort: Arc<AtomicBool>,
    ) {
        let shared = Arc::new(HookShared::new());
        // 单实例终核（spawn 前置检查为 TOCTOU，以本线程写入为准）
        {
            let mut g = SHARED.lock().unwrap();
            if g.is_some() {
                let _ = result_tx.send(Err(KbdHookError::AlreadyRunning));
                return;
            }
            *g = Some(Arc::clone(&shared));
        }
        shared.thread_id.store(unsafe { GetCurrentThreadId() }, Ordering::Relaxed);

        // 安装（LL 钩子回调投递到**本线程**消息循环 → 必须在本线程安装、本线程泵消息）
        let hook =
            unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(ll_kbd_proc), std::ptr::null_mut(), 0) };
        if hook.is_null() {
            let err = unsafe { GetLastError() };
            *SHARED.lock().unwrap() = None;
            // 结构性 fail-closed：安装失败 → 上报 Err，调用方（E 岗）退回按钮补偿现状；
            // 绝不 panic、绝不静默全量放行（门控此时 = INACTIVE，且钩子不存在）。
            let _ = result_tx.send(Err(KbdHookError::InstallFailed(err)));
            return;
        }
        *shared.hook.lock().unwrap() = Some(hook as usize);

        if abort.load(Ordering::SeqCst) {
            // spawn 侧已超时放弃 → 不进消息循环，立即卸载退出（防孤儿钩子）
            *shared.hook.lock().unwrap() = None;
            unsafe { UnhookWindowsHookEx(hook as *mut std::os::raw::c_void) };
            *SHARED.lock().unwrap() = None;
            return;
        }

        // 0 条 = 首 tick 必出而未出，WM_TIMER 从未执行；旧码 SetTimer 返回值未校验）──
        // ① `= 0`（MSDN：失败返回 NULL）→ WARN + fallback 自驱动定时器线程
        //    （PostThreadMessageW 私有消息，观察动作仍只在钩子线程消息循环内执行）；
        // ② `≠ 请求 ID`（同 ID 在用时系统另发新 ID，MSDN：WM_TIMER 的 wParam =
        //    **返回** ID）→ 按实际 ID 匹配，防「定时器在响、消息循环不认」。
        // 定时器 ID 为小整数（< 2^32），UINT_PTR→u32 截断无损。
        let timer_ret: u32 = unsafe {
            SetTimer(std::ptr::null_mut(), WATCHDOG_TIMER_ID as usize, WATCHDOG_PERIOD_MS, None)
        } as u32;
        if timer_ret == 0 {
            tracing::warn!(
                unsafe { GetLastError() }
            );
        } else if timer_ret != WATCHDOG_TIMER_ID as u32 {
            tracing::info!(
            );
        }
        // 09-09 定版形态 = 「ret 非零但 WM_TIMER 从未执行」→ 该形态看门狗永久失灵，
        // 钩子被系统摘除永不被检知 = 白名单键物理直按永久丢失的持续因）──
        // 双路同活时 watchdog_tick 入口半周期去重（每 60s 至多 1 条有效 tick，
        spawn_watchdog_fallback_timer(shared.thread_id.load(Ordering::Relaxed));
        let _ = result_tx.send(Ok(Arc::clone(&shared)));

        // 专属消息循环：LL 钩子回调经此投递；WM_TIMER（**实际 ID**）/ fallback
        // 私有消息 = 看门狗；WM_QUIT = stop 退出信号
        let mut msg: MSG = unsafe { std::mem::zeroed() };
        loop {
            let r = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
            if r <= 0 {
                break; // 0 = WM_QUIT（stop）；-1 = 错误（fail-closed：退出并清理）
            }
            let is_watchdog =
                (msg.message == WM_TIMER && msg.wParam as u32 == timer_ret)
                    || msg.message == WATCHDOG_FALLBACK_MSG;
            if is_watchdog {
                if abort.load(Ordering::SeqCst) {
                    break;
                }
                watchdog_tick(&shared);
            }
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        // 退出清理（同线程内：循环退出后无回调可再投递，顺序无竞争）
        unsafe {
            if timer_ret != 0 {
                let _ = KillTimer(std::ptr::null_mut(), timer_ret as usize);
            }
        }
        if let Some(h) = shared.hook.lock().unwrap().take() {
            unsafe { UnhookWindowsHookEx(h as *mut std::os::raw::c_void) };
        }
        *SHARED.lock().unwrap() = None;
    }

    /// 钩子句柄（`spawn` 成功返回；E 岗持有）。
    ///
    /// - [`set_gate`](KbdHook::set_gate)：E 岗每帧在既有 `i.focused` 判定块顺带写（同帧同口径，
    ///   设计 §3.2）；
    /// - [`set_sink`](KbdHook::set_sink)：E 岗聚焦切换写聚焦窗 `input_tx` 克隆；失焦/会话终写
    ///   `None`（多会话竞态口径设计 §8 R7：后写覆盖、瞬态旧 sink 最多延续至下一帧）；
    /// - [`stop`](KbdHook::stop)：末窗关闭/进程退出调用；幂等，`Drop` 兜底（钩子绝不超出
    ///   句柄存续期——安全红线③生命周期约束）。
    pub struct KbdHook {
        shared: Arc<HookShared>,
        thread: Option<std::thread::JoinHandle<()>>,
        stopped: bool,
    }

    impl KbdHook {
        /// 写焦点门控（E 岗每帧）。
        ///
        /// E 岗每帧写同值（`swap` 读旧值仅用于判沿）→ 日志只在真实迁移时出现，零刷屏。
        pub fn set_gate(&self, gate: HookGate) {
            let new = gate.as_u8();
            let old = self.shared.gate.swap(new, Ordering::Relaxed);
            if old != new {
                let from = HookGate::from_u8(old)
                    .map(|g| format!("{g:?}"))
                    .unwrap_or_else(|| format!("raw:{old:x}"));
                // 仅非回调路径调用——本函数 = UI 线程 API 层，允许）：60s tick 路径
                // 全死（09-09 实测形态）时逐沿仍保有计数证据，不必等 60s。
                // 快照 gate 字段 = 迁移**后**值（沿文案已含 from -> to，不丢信息）。
                let snap = self.shared.snapshot_stats();
                tracing::info!(
                    "{}",
                    format_hook_stats_edge(
                        &snap,
                        "gate edge",
                    )
                );
            }
        }

        /// 写事件 sink（E 岗聚焦切换：聚焦窗 `input_tx` 克隆；`None` = 暂停转发）。
        ///
        /// detach = [`SinkReason::FocusLost`] / [`SinkReason::SessionEnd`]，调用点按
        /// 会话窗存活态判）——沿事件额外出 1 行 DEBUG 原因行
        /// （[`format_hook_sink_debug_line`]，格式钉死单测）；**既有 INFO 沿行
        /// （含计数快照）零改动**（字段口径连续 + 生产默认 info 级别下零新增输出）。
        pub fn set_sink(&self, tx: Option<UnboundedSender<Vec<InputEvent>>>, reason: SinkReason) {
            let had = self
                .shared
                .sink
                .lock()
                .map(|g| g.is_some())
                .unwrap_or(false);
            let now = tx.is_some();
            if let Ok(mut g) = self.shared.sink.lock() {
                *g = tx;
            }
            if had != now {
                // 复测机 debug 级别/RUST_LOG 开启即得 detach 原因明细）
                tracing::debug!("{}", format_hook_sink_debug_line(now, reason));
                // 快照 sink 字段 = 切换**后**值）。
                let snap = self.shared.snapshot_stats();
                tracing::info!(
                    "{}",
                    format_hook_stats_edge(
                        &format!(
                            if now { "attached (focused session input_tx)" } else { "detached (focus lost / session end)" }
                        ),
                        &snap,
                        "sink edge",
                    )
                );
                // attach 沿恒 cb=0 = hook_no_cb 噪音，防刷屏）
                if snap.cb_total > 0 {
                    tracing::info!("{}", format_r135_2_verdict_line(&snap));
                }
            }
        }

        /// 空环 = 加锁 + 快路径返回空 vec 零成本）。调用方逐条出
        /// [`format_hook_hit_line`] INFO 行（非回调路径 → 允许 tracing）——
        pub fn drain_hit_events(&self) -> Vec<HookHitEvt> {
            self.shared
                .hit_ring
                .lock()
                .map(|mut ring| ring.drain(..).collect())
                .unwrap_or_default()
        }

        /// 卸载钩子并退出线程：`UnhookWindowsHookEx` + `PostThreadMessageW(WM_QUIT)` + join。
        /// 幂等（stop 后再 Drop 为 no-op）。
        pub fn stop(mut self) {
            self.shutdown();
        }

        fn shutdown(&mut self) {
            if self.stopped {
                return;
            }
            self.stopped = true;
            // stop 幂等由本函数入口的 `KbdHook::stopped` 守门保证，删除零行为变化）
            let unhooked = unsafe {
                match self.shared.hook.lock() {
                    Ok(mut g) => match g.take() {
                        Some(h) => {
                            UnhookWindowsHookEx(h as *mut std::os::raw::c_void);
                            true
                        }
                        None => false,
                    },
                    // 锁中毒（理论不可达：本模块锁内无 panic 路径）→ 跳排空（fail-closed）
                    Err(_) => false,
                }
            };
            // join / 释放句柄（跨线程卸载点唯一需要排空；预算 ≤500ms 绝不
            // 无限期阻塞；另两处 Unhook 为同线程、在途结构性 0，见
            // `drain_inflight_callbacks` 文档）
            if unhooked {
                drain_inflight_callbacks();
            }
            let tid = self.shared.thread_id.load(Ordering::Relaxed);
            if tid != 0 {
                unsafe { let _ = PostThreadMessageW(tid, WM_QUIT, 0, 0); }
            }
            if let Some(h) = self.thread.take() {
                let _ = h.join();
            }
            // 零键内容，只含次数 + 键位类别 + 门控/sink 状态）
            let snap = self.shared.snapshot_stats();
            tracing::info!("{}", format_hook_stats_line(&snap, "final (stop)"));
            // 即有效判定；join 后计数已定格）
            tracing::info!("{}", format_r135_2_verdict_line(&snap));
        }
    }

    impl Drop for KbdHook {
        fn drop(&mut self) {
            // 兜底：未显式 stop 即析构 → 同样卸载（钩子生命周期 ⊆ 会话窗存续期，红线③）
            self.shutdown();
        }
    }

    /// 启动钩子线程并安装 `WH_KEYBOARD_LL`（**单实例**；失败 → `Err`，调用方退回按钮补偿）。
    ///
    /// 语义（E 岗接线用）：
    /// - 首个 Desktop 会话窗创建且 `input_tx` 就绪时调用；`Err`（安装失败/超时）→ **不 panic、
    ///   不降级放行**，按钮补偿路径照常（现状行为）；
    /// - 成功后用返回值句柄 `set_sink` / `set_gate`；末窗关闭/进程退出 `stop`（或依赖 Drop）。
    pub fn spawn() -> Result<KbdHook, KbdHookError> {
        if SHARED.lock().unwrap().is_some() {
            return Err(KbdHookError::AlreadyRunning);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let abort = Arc::new(AtomicBool::new(false));
        let abort_c = Arc::clone(&abort);
        let thread = std::thread::Builder::new()
            .name("kirin-kbd-hook".into())
            .spawn(move || hook_thread_main(tx, abort_c))
            .map_err(|e| KbdHookError::ThreadSpawn(e.to_string()))?;
        match rx.recv_timeout(std::time::Duration::from_secs(SPAWN_TIMEOUT_SECS)) {
            Ok(Ok(shared)) => Ok(KbdHook {
                shared,
                thread: Some(thread),
                stopped: false,
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // 超时/线程早死：置 abort（线程若尚存将自行卸载退出，防孤儿钩子）
                abort.store(true, Ordering::SeqCst);
                Err(KbdHookError::StartTimeout)
            }
        }
    }
}

#[cfg(windows)]
pub use win_impl::{spawn, KbdHook};

// ═══════════════════════════ 非 Windows：fail-closed 惰性桩 ═══════════════════════════
// 设计 §5 三平台策略：Linux/macOS 客户端钩子层 = fail-closed（行为恒 = 现状按钮补偿）。
// 无钩子、不转发、按钮补偿照常；取 Err 使 E 岗失败路径单一化）。

#[cfg(not(windows))]
mod stub {
    use super::*;

    /// 非 Windows 钩子句柄（不可构造：`spawn` 恒 `Err`；方法为 API 面统一保留）。
    pub struct KbdHook {
        _private: (),
    }

    impl KbdHook {
        /// 写焦点门控（桩：no-op）。
        pub fn set_gate(&self, _gate: HookGate) {}

        /// 写事件 sink（桩：no-op；reason 面与 Windows 同签名）。
        pub fn set_sink(&self, _tx: Option<UnboundedSender<Vec<InputEvent>>>, _reason: SinkReason) {}

        /// 排空命中观察环（桩：恒空）。
        pub fn drain_hit_events(&self) -> Vec<HookHitEvt> {
            Vec::new()
        }

        /// 卸载（桩：no-op）。
        pub fn stop(self) {}
    }

    /// 启动钩子（非 Windows 恒 `Err`：fail-closed 惰性桩，设计 §5）。
    pub fn spawn() -> Result<KbdHook, KbdHookError> {
        Err(KbdHookError::UnsupportedPlatform)
    }
}

#[cfg(not(windows))]
pub use stub::{spawn, KbdHook};

// ═══════════════════════════════════ 单元测试 ═══════════════════════════════════
// 隔离目录双实例回环 + 物理按键实测 + 回调时延抽样 + fail-closed 模拟安装失败）。

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造决策入参（`flags` 三标志 + 方向 + 门控 + 2 簿记位）。
    #[inline]
    fn dec(
        gate: u8,
        scan: u16,
        extended: bool,
        injected: bool,
        up: bool,
        alt_down: bool,
        f4_in_flight: bool,
    ) -> HookDecision {
        let mut flags: u32 = 0;
        if extended {
            flags |= KBDLLHF_EXTENDED;
        }
        if injected {
            flags |= KBDLLHF_INJECTED;
        }
        if up {
            flags |= KBDLLHF_UP;
        }
        decide_hook_event(scan, flags, up, gate, alt_down, f4_in_flight)
    }

    /// 白名单 KP*（0x37 非扩展）：正例 down/up → KpMultiply(0x66)；反例：带扩展位 → 透传。
    #[test]
    fn r89d_whitelist_kp_multiply() {
        let d = dec(GATE_ACTIVE, SCAN_KP_MULTIPLY, false, false, false, false, false);
        assert_eq!(d.count, 1, "KP* down 应转发 1 事件");
        let e = d.events[0].as_ref().expect("事件存在");
        assert_eq!(e.kind, InputKind::KeyDown);
        assert_eq!(e.key, Key::KpMultiply as u32, "复用既有判别式 0x66");
        assert_eq!(e.modifiers, 0, "修饰位 = 0（注入侧 modifier_sync 维护）");

        let d = dec(GATE_ACTIVE, SCAN_KP_MULTIPLY, false, false, true, false, false);
        assert_eq!(d.count, 1);
        assert_eq!(d.events[0].as_ref().unwrap().kind, InputKind::KeyUp);

        // 反例：0x37 带扩展位（非标准形态）→ 不在白名单 → 透传
        let d = dec(GATE_ACTIVE, SCAN_KP_MULTIPLY, true, false, false, false, false);
        assert_eq!(d.count, 0, "扩展位 0x37 不在白名单");
        assert!(!d.swallow);
    }

    /// 白名单 KP.（0x53 非扩展）：正例 → KpDecimal(0x67)；反例：**0x53 扩展 = 导航 Delete**
    /// → 必须透传（防误判吞/转错键）。
    #[test]
    fn r89d_whitelist_kp_decimal() {
        let d = dec(GATE_ACTIVE, SCAN_KP_DECIMAL, false, false, false, false, false);
        assert_eq!(d.count, 1);
        let e = d.events[0].as_ref().unwrap();
        assert_eq!(e.kind, InputKind::KeyDown);
        assert_eq!(e.key, Key::KpDecimal as u32, "复用既有判别式 0x67");

        // 反例：0x53 + 扩展位 = Set 1 导航 Delete（windows.rs 注入表 Delete=EXTENDED|0x53）
        let d = dec(GATE_ACTIVE, SCAN_KP_DECIMAL, true, false, false, false, false);
        assert_eq!(d.count, 0, "扩展 0x53 = 导航 Delete，严禁当 KP. 转发");
        assert!(!d.swallow);
    }

    /// 白名单 CapsLock（0x3A）/ NumLock（0x45）：正例 → 0x39/0x68；反例：扩展位 → 透传。
    #[test]
    fn r89d_whitelist_caps_num_lock() {
        let d = dec(GATE_ACTIVE, SCAN_CAPS_LOCK, false, false, false, false, false);
        assert_eq!(d.count, 1);
        assert_eq!(d.events[0].as_ref().unwrap().key, Key::CapsLock as u32, "复用 0x39");
        assert_eq!(d.events[0].as_ref().unwrap().kind, InputKind::KeyDown);

        let d = dec(GATE_ACTIVE, SCAN_NUM_LOCK, false, false, false, false, false);
        assert_eq!(d.count, 1);

        let d = dec(GATE_ACTIVE, SCAN_CAPS_LOCK, true, false, false, false, false);
        assert_eq!(d.count, 0, "扩展 0x3A 不在白名单");
        let d = dec(GATE_ACTIVE, SCAN_NUM_LOCK, true, false, false, false, false);
        assert_eq!(d.count, 0, "扩展 0x45 不在白名单");
    }

    /// Win 键（0x5B）扩展位判定：LWin/RWin 共享 Set 1 码 0x5B、前缀 0xE0 → **仅扩展位**
    /// 映射 Super(0x56)；非扩展 0x5B（无标准形态）→ 透传。
    #[test]
    fn r89d_whitelist_win_requires_extended() {
        let d = dec(GATE_ACTIVE, SCAN_WIN, true, false, false, false, false);
        assert_eq!(d.count, 1);
        let e = d.events[0].as_ref().unwrap();
        assert_eq!(e.kind, InputKind::KeyDown);

        let d = dec(GATE_ACTIVE, SCAN_WIN, true, false, true, false, false);
        assert_eq!(d.events[0].as_ref().unwrap().kind, InputKind::KeyUp);

        let d = dec(GATE_ACTIVE, SCAN_WIN, false, false, false, false, false);
        assert_eq!(d.count, 0, "非扩展 0x5B 不在白名单（Win 必须扩展位）");
    }

    /// `LLKHF_INJECTED` 忽略（防自我注入回环——注入事件不回捕）：
    /// 白名单键注入事件 → 零转发零吞；注入 Alt 不翻转 `alt_down` 簿记。
    #[test]
    fn r89d_injected_ignored_no_loop() {
        // 注入 KP* → 透传
        let d = dec(GATE_ACTIVE, SCAN_KP_MULTIPLY, false, true, false, false, false);
        assert_eq!(d.count, 0, "注入事件不转发");
        assert!(!d.swallow, "注入事件不吞");

        // 注入 Alt down → 不置 alt_down
        let d = dec(
            GATE_ACTIVE_ALT_F4_SUPPRESSED,
            SCAN_ALT_L,
            false,
            true,
            false,
            false,
            false,
        );
        assert!(!d.alt_down, "注入 Alt 不翻转按住态");

        // 注入 Alt up → 不清 alt_down（保持原态）
        let d = dec(
            GATE_ACTIVE_ALT_F4_SUPPRESSED,
            SCAN_ALT_L,
            false,
            true,
            true,
            true,
            false,
        );
        assert!(d.alt_down, "注入 Alt up 不清除物理按住态");
    }

    /// 门控三态（同一 KP* down 事件）：INACTIVE = 透传不拦截不转发（fail-closed 默认态）/
    /// 白名单键行为与 ACTIVE 一致）。
    #[test]
    fn r89d_gate_three_states() {
        let d = dec(GATE_INACTIVE, SCAN_KP_MULTIPLY, false, false, false, false, false);
        assert_eq!(d.count, 0, "INACTIVE：不转发（含「尚未初始化」=0）");
        assert!(!d.swallow, "INACTIVE：不拦截");

        let d = dec(GATE_ACTIVE, SCAN_KP_MULTIPLY, false, false, false, false, false);
        assert_eq!(d.count, 1, "ACTIVE：转发白名单键");

        let d = dec(
            GATE_ACTIVE_ALT_F4_SUPPRESSED,
            SCAN_KP_MULTIPLY,
            false,
            false,
            false,
            false,
            false,
        );
        assert_eq!(d.count, 1, "态 A：白名单键转发面与 ACTIVE 一致");
    }

    /// Inactive = 纯透传（`count=0` 且 `swallow=false`：关会话窗后键盘行为完全
    /// 本机，fail-closed 语义不变）；Active / ActiveAltF4Suppressed = 转发 + 吞
    /// 本地（`count=1` 且 `swallow=true`：Win 不再弹本机开始菜单→失焦→「控制
    /// 丢失」；Caps/Num 本地锁定态不翻转；键归远端，RDP 参照）。
    #[test]
    fn r99_whitelist_gate_swallow_matrix() {
        let keys: &[(u16, bool, &str)] = &[
            (SCAN_KP_MULTIPLY, false, "KP*"),
            (SCAN_KP_DECIMAL, false, "KP."),
            (SCAN_CAPS_LOCK, false, "Caps"),
            (SCAN_NUM_LOCK, false, "Num"),
            (SCAN_WIN, true, "Win"),
        ];
        for (scan, ext, name) in keys {
            for up in [false, true] {
                // ① Inactive：透传（不转发、不吞）
                let d = dec(GATE_INACTIVE, *scan, *ext, false, up, false, false);
                assert_eq!(d.count, 0, "{name} Inactive 不转发");
                assert!(!d.swallow, "{name} Inactive 不吞（本机行为完全本机）");
                // ② Active 族：转发 + 吞本地
                for gate in [GATE_ACTIVE, GATE_ACTIVE_ALT_F4_SUPPRESSED] {
                    let d = dec(gate, *scan, *ext, false, up, false, false);
                    assert_eq!(d.count, 1, "{name} gate={gate} 转发 1 事件");
                    assert!(d.swallow, "{name} gate={gate} 吞本地（键归远端）");
                    let e = d.events[0].as_ref().expect("事件存在");
                    let want = if up { InputKind::KeyUp } else { InputKind::KeyDown };
                    assert_eq!(e.kind, want, "{name} gate={gate} up={up} 方向");
                }
            }
        }
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_F4, false, false, false, false, false);
        assert_eq!(d.count, 0, "无 Alt 的 F4 仍走 egui 路（Tier-1 不相交不变）");
        assert!(!d.swallow);
    }

    /// Alt+F4 态 A（E-5 落定 = 仅合成 F4 down/up **2 事件**、不合成 Alt 事件）：
    /// ① Alt 按住 + F4 down → 2 事件 [KeyDown(F4=0x3D), KeyUp(F4)] + 吞本地 + 对在途；
    /// ② 对在途 + F4 up → 吞（清在途）；
    /// ③ 无 Alt 的 F4 down/up → 透传（egui 路照常，Tier-1 不相交）；
    /// ⑤ 防重复：对在途期间异常 F4 down → 吞且不再合成第二对。
    #[test]
    fn r89d_alt_f4_state_a_pair() {
        // ① F4 down（Alt 按住）→ 合成 2 事件对 + 吞
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_F4, false, false, false, true, false);
        assert_eq!(d.count, 2, "态 A：合成 F4 down/up 2 事件");
        assert!(d.swallow, "态 A：吞本地 F4（本地会话窗不关闭）");
        assert!(d.f4_pair_in_flight, "合成对在途标记置位");
        let down = d.events[0].as_ref().unwrap();
        let up = d.events[1].as_ref().unwrap();
        assert_eq!(down.kind, InputKind::KeyDown);
        assert_eq!(up.kind, InputKind::KeyUp);
        assert_eq!(down.key, Key::F4 as u32, "复用既有判别式 0x3D（零 wire 新增）");
        assert_eq!(up.key, Key::F4 as u32);
        // 不合成 Alt 事件：仅 2 事件且均 F4（E-5：Alt 走既有 egui 帧差路，两情形均正确）
        assert_eq!(d.events.iter().filter(|e| e.as_ref().map_or(false, |e| e.key == Key::Alt as u32)).count(), 0);

        // ② 对在途 + F4 up → 吞 + 清在途
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_F4, false, false, true, true, true);
        assert_eq!(d.count, 0);
        assert!(d.swallow);
        assert!(!d.f4_pair_in_flight, "对在途的 up 后清标记");

        // ③ 无 Alt：F4 down / up 均透传（egui 路转发 F4，钩子不重复）
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_F4, false, false, false, false, false);
        assert_eq!(d.count, 0, "无 Alt 的 F4：egui 路处理（Tier-1 不相交）");
        assert!(!d.swallow);
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_F4, false, false, true, false, false);
        assert_eq!(d.count, 0);
        assert!(!d.swallow);

        let d = dec(GATE_ACTIVE, SCAN_F4, false, false, false, true, false);
        assert_eq!(d.count, 0, "态 B：钩子层零干预");
        assert!(!d.swallow);

        // ⑤ 防重复：对在途 + Alt 按住 + 异常 F4 down → 吞、不合成第二对
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_F4, false, false, false, true, true);
        assert_eq!(d.count, 0, "在途期间不再合成第二对（防远端连关多窗）");
        assert!(d.swallow);
        assert!(d.f4_pair_in_flight);
    }

    /// Alt 按住簿记：LAlt(0x38 非扩展) down 置位 / up 清除；RAlt(0x58 扩展) 同；
    /// 非 Alt 键不改变簿记；扩展位误配不置位。
    #[test]
    fn r89d_alt_down_tracking() {
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_ALT_L, false, false, false, false, false);
        assert!(d.alt_down, "LAlt down 置位");
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_ALT_L, false, false, true, true, false);
        assert!(!d.alt_down, "LAlt up 清除");

        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_ALT_R, true, false, false, false, false);
        assert!(d.alt_down, "RAlt(0x58+EXT) down 置位");
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_ALT_R, true, false, true, true, false);
        assert!(!d.alt_down, "RAlt up 清除");

        // 误配防护：LAlt 码带扩展位 / RAlt 码不带扩展位 → 不识别为 Alt
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_ALT_L, true, false, false, false, false);
        assert!(!d.alt_down);
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_ALT_R, false, false, false, false, false);
        assert!(!d.alt_down);

        // 非 Alt 白名单键不改变簿记
        let d = dec(GATE_ACTIVE, SCAN_NUM_LOCK, false, false, false, true, false);
        assert!(d.alt_down, "非 Alt 键保持原按住态");
    }

    /// scancode→Key 映射与三平台注入表对齐（Tier-1 结构不相交的互证锁定）：
    /// 白名单每键 `scan_code_to_blind_key` → `windows::map_scan_code` 往返 = 原 scan code
    /// （Super = 扩展 0x5B）；并钉死 wire 判别式复用值（零新增）。
    #[test]
    fn r89d_scan_key_roundtrip_matches_injection_table() {
        let cases: &[(u16, bool, Key)] = &[
            (SCAN_KP_MULTIPLY, false, Key::KpMultiply),
            (SCAN_KP_DECIMAL, false, Key::KpDecimal),
            (SCAN_CAPS_LOCK, false, Key::CapsLock),
            (SCAN_NUM_LOCK, false, Key::NumLock),
            (SCAN_WIN, true, Key::Super),
        ];
        for (scan, extended, key) in cases {
            assert_eq!(
                scan_code_to_blind_key(*scan, *extended),
                Some(*key),
                "scan 0x{scan:02X} ext={extended} → {key:?}"
            );
            // 往返互证：钩子捕获的 scan → Key → 注入表映射回同一 scan（与服务端注入对称）
            let mapped = crate::windows::map_scan_code(*key as u32)
                .unwrap_or_else(|| panic!("注入表无 {key:?} 行"));
            if *extended {
                assert_eq!(mapped & 0x00FF, *scan, "Super 低字节 = 0x5B");
                assert_ne!(mapped & 0xE000, 0, "Super 为扩展键（0xE0 前缀）");
            } else {
                assert_eq!(mapped, *scan, "{key:?} 注入表往返 = 原 scan code");
            }
        }
        assert_eq!(Key::KpMultiply as u32, 0x66);
        assert_eq!(Key::KpDecimal as u32, 0x67);
        assert_eq!(Key::CapsLock as u32, 0x39);
        assert_eq!(Key::NumLock as u32, 0x68);
        assert_eq!(Key::Super as u32, 0x56);
        assert_eq!(Key::F4 as u32, 0x3D);
        assert_eq!(Key::Alt as u32, 0x55);
        // F4 扫描码锚点（设计 §3.4④「0x3B」= F1 勘误；注入表 Key::F4 = 0x3E 互证）
        assert_eq!(crate::windows::map_scan_code(Key::F4 as u32), Some(0x3E));
        assert_eq!(SCAN_F4, 0x3E);
    }

    /// Tier-2 帧戳判重预留接口：本波恒 `false`（仅 Tier-1 结构不相交生效，设计 §3.3）。
    #[test]
    fn r89d_dedup_tier2_stub_false() {
        assert!(!dedup_check(0, SCAN_KP_MULTIPLY, false));
        assert!(!dedup_check(u64::MAX, SCAN_KP_DECIMAL, true));
        assert!(!dedup_check(42, SCAN_NUM_LOCK, false));
    }

    /// 驱动提取逻辑，断言方向。
    ///
    /// MSDN KBDLLHOOKSTRUCT.flags 位表：bit0 = Extended / bit4 = Injected /
    /// **bit6 = Reserved** / **bit7 = UP**。原缺陷常量 `KBDLLHF_UP = 0x40`（= bit6
    /// Reserved）下：真实 up 事件（bit7 = 1）误判 down、Reserved 位置位事件误判 up →
    /// 白名单 5 键只发 KeyDown 永不发 KeyUp（远端键卡死）+ Alt 簿记永不清除 +
    /// Alt+F4 在途对永久失效。原 10 例均经 `dec` 助手绕过提取点（is_up 另传 bool、
    /// flags 用同常量构造自洽）→ 结构上抓不到；本例直接以真实位模式驱动
    /// [`extract_kbdllhf`]（与 `ll_kbd_proc` 同一入口，不经 `dec`）。
    #[test]
    fn r89d2_flags_up_bit7_regression() {
        // ① 常量值钉死（双源：MSDN 位表 + winapi 0.3.9 winuser.rs :247/:644/:645/:252/:647）
        assert_eq!(KBDLLHF_EXTENDED, 0x01, "bit0 = Extended");
        assert_eq!(KBDLLHF_INJECTED, 0x10, "bit4 = Injected");
        assert_eq!(KBDLLHF_UP, 0x80, "bit7 = UP（bit6 = Reserved，不是 UP）");

        // ② 真实位模式驱动提取逻辑（旧 0x40 缺陷形态在本表逐行失败）
        for (flags, want_up, want_ext, want_inj, label) in [
            (0x00u32, false, false, false, "down"),
            (0x80u32, true, false, false, "up（bit7）"),
            (0x40u32, false, false, false, "bit6 = Reserved 不得判 up"),
            (0x01u32, false, true, false, "down + 扩展"),
            (0x81u32, true, true, false, "up + 扩展"),
            (0x10u32, false, false, true, "injected down"),
            (0x90u32, true, false, true, "injected up"),
            (0x83u32, true, true, false, "up + 扩展 + 位 1"),
        ] {
            let (is_up, extended, injected) = extract_kbdllhf(flags);
            assert_eq!(is_up, want_up, "flags=0x{flags:02X}（{label}）is_up");
            assert_eq!(extended, want_ext, "flags=0x{flags:02X}（{label}）extended");
            assert_eq!(injected, want_inj, "flags=0x{flags:02X}（{label}）injected");
        }

        // ③ 端到端方向（`ll_kbd_proc` 同调用形态：提取 → decide_hook_event）：
        //    KP*（0x37 非扩展）真实位模式 → KeyDown/KeyUp 方向正确
        for (flags, want_kind) in [
            (0x00u32, InputKind::KeyDown),
            (0x80u32, InputKind::KeyUp),
            (0x40u32, InputKind::KeyDown), // Reserved 位 ≠ up
        ] {
            let (is_up, _, _) = extract_kbdllhf(flags);
            let d = decide_hook_event(SCAN_KP_MULTIPLY, flags, is_up, GATE_ACTIVE, false, false);
            assert_eq!(d.count, 1, "flags=0x{flags:02X}：白名单键应转发 1 事件");
            assert_eq!(
                d.events[0].as_ref().expect("事件存在").kind,
                want_kind,
                "flags=0x{flags:02X}：方向"
            );
        }
    }

    /// ② 透传 = 推导（cb − fwd − swal）且三向互斥完备时精确；
    /// ③ 饱和下溢防护（异常计数组合不 panic、不环绕）；
    /// ④ 零键内容（红线③：行内无 scan code / 键值，只有次数与类别标签）；
    /// ⑤ 未知门控 u8 → `raw:` 兜底不 panic。
    #[test]
    fn r93c_stats_format_line() {
        let s = KbdHookStats {
            cb_total: 1234,
            hit_kp_mul: 1,
            hit_kp_dec: 0,
            hit_caps: 2,
            hit_num: 0,
            hit_win: 0,
            hit_inj: 1,
            forwarded: 3,
            swallowed: 0,
            gate: GATE_ACTIVE,
            sink: true,
            last_cb_age_secs: Some(42),
        };
        assert_eq!(
            format_hook_stats_line(&s, "test"),
        );

        // ② 推导透传：含吞掉的组合（cb=10, fwd=4, swal=2 → pass=4）
        let s2 = KbdHookStats {
            cb_total: 10,
            hit_win: 5,
            forwarded: 4,
            swallowed: 2,
            gate: GATE_ACTIVE_ALT_F4_SUPPRESSED,
            ..Default::default()
        };
        assert_eq!(s2.hit_total(), 5, "hit_total = 5 类别之和");
        assert_eq!(s2.passthrough(), 4, "pass = cb − fwd − swal");
        assert!(format_hook_stats_line(&s2, "x").contains("gate=ActiveAltF4Suppressed"));
        assert!(format_hook_stats_line(&s2, "x").contains("sink=off"), "默认 sink=false → off");

        // ③ 饱和下溢（异常组合 fwd+swal > cb）→ 0 而非 panic/环绕
        let s3 = KbdHookStats {
            cb_total: 3,
            forwarded: 10,
            swallowed: 5,
            ..Default::default()
        };
        assert_eq!(s3.passthrough(), 0, "saturating：不下溢不环绕");

        // ④ 零键内容（红线③）：行内不出现任何 scan code 十六进制 / 键值字面量
        let line = format_hook_stats_line(&s, "audit");
        for forbidden in ["0x37", "0x53", "0x3A", "0x45", "0x5B", "KpMultiply", "CapsLock", "NumLock"] {
            assert!(!line.contains(forbidden), "汇总行不得含键内容 {forbidden:?}: {line}");
        }

        // ⑤ 未知门控 u8 → raw 兜底
        let s5 = KbdHookStats {
            gate: 0x7F,
            ..Default::default()
        };
        assert!(format_hook_stats_line(&s5, "x").contains("gate=raw:7f"));
    }

    /// ① gate 沿行逐字钉死（沿文案 | 计数快照，快照标签 = `gate edge`）；
    /// ② sink 沿行同构（标签 = `sink edge`）；
    /// ③ 零键内容（红线③——沿行 = 沿文案 + 既有 stats 行拼接，不引入新键内容面）。
    #[test]
    fn r99c_edge_line_format() {
        let s = KbdHookStats {
            cb_total: 7,
            hit_caps: 2,
            hit_win: 1,
            hit_inj: 2,
            forwarded: 3,
            swallowed: 1,
            gate: GATE_ACTIVE,
            sink: true,
            last_cb_age_secs: Some(9),
            ..Default::default()
        };
        let line = format_hook_stats_edge(
            &s,
            "gate edge",
        );
        assert_eq!(
            line,
        );
        // ② sink 沿行同构
        let line2 = format_hook_stats_edge(
            &s,
            "sink edge",
        );
        assert_eq!(
            line2,
        );
        // ③ 零键内容（与 r93c_stats_format_line ④ 同判据）
        for forbidden in ["0x37", "0x53", "0x3A", "0x45", "0x5B", "KpMultiply", "CapsLock", "NumLock"] {
            assert!(!line.contains(forbidden), "沿行不得含键内容 {forbidden:?}: {line}");
        }
    }

    /// `Some(n)` → `last_cb_age={n}s`；`None`（安装后从未回调）→ `last_cb_age=n/a`。
    /// 09-09 复测回归：主丢失段 cb 冻结（13:16:26→13:18:54 恒 1946）旧口径下
    /// 「零回调」与「无人按键」不可区分——本字段使「回调停更 N 秒」直接可读。
    #[test]
    fn r102_stats_line_last_cb_age() {
        let s = KbdHookStats {
            cb_total: 1946,
            hit_kp_mul: 2,
            hit_kp_dec: 2,
            hit_caps: 2,
            hit_num: 0,
            hit_win: 0,
            hit_inj: 0,
            forwarded: 0,
            swallowed: 0,
            gate: GATE_ACTIVE,
            sink: true,
            last_cb_age_secs: Some(600),
        };
        // ① age = 600s（09-09 冻结段 ≈148s 同形态；钉死「停更 N 秒」读数格式）
        let line = format_hook_stats_line(&s, "60s tick");
        assert!(line.ends_with("last_cb_age=600s"), "{line}");
        // ② 安装后从未回调 → n/a（与任何 age 值可区分）
        let s2 = KbdHookStats {
            cb_total: 0,
            ..Default::default()
        };
        let line2 = format_hook_stats_line(&s2, "60s tick");
        assert!(line2.ends_with("last_cb_age=n/a"), "{line2}");
        for forbidden in [
            "0x37", "0x53", "0x3A", "0x45", "0x5B", "KpMultiply", "CapsLock", "NumLock",
        ] {
            assert!(
                !line.contains(forbidden),
                "stats 行不得含键内容 {forbidden:?}: {line}"
            );
        }
    }

    #[test]
    fn r93c_hook_gate_from_u8_roundtrip() {
        for g in [
            HookGate::Inactive,
            HookGate::Active,
            HookGate::ActiveAltF4Suppressed,
        ] {
            assert_eq!(HookGate::from_u8(g.as_u8()), Some(g), "{g:?} 往返");
        }
        assert_eq!(HookGate::from_u8(3), None, "未知 u8 → None（不 panic）");
    }


    /// = 强制放行——超时情形由调用方 WARN，本函数仅返纯数据）。
    #[test]
    fn r119_drain_decision() {
        assert_eq!(decide_drain(0, 0, 500), DrainResult::Drained, "在途 0 = 立即放行（无需等待）");
        assert_eq!(decide_drain(0, 999, 500), DrainResult::Drained, "在途 0 优先于超时（排空窗口已闭合）");
        assert_eq!(decide_drain(3, 0, 500), DrainResult::KeepWaiting, "在途 >0 且预算内 = 继续等待");
        assert_eq!(decide_drain(3, 499, 500), DrainResult::KeepWaiting, "elapsed 499 < budget 500 = 继续等待（下边界）");
        assert_eq!(decide_drain(3, 500, 500), DrainResult::TimedOut, "elapsed == budget = 强制放行（上边界）");
        assert_eq!(decide_drain(1, 1000, 500), DrainResult::TimedOut, "超预算 = 强制放行");
        // 异常组合不 panic（全比较为全序，无算术溢出路径）
        assert_eq!(decide_drain(u64::MAX, 0, 0), DrainResult::TimedOut, "budget=0 且非零在途 = 立即超时");
        assert_eq!(decide_drain(0, u64::MAX, 0), DrainResult::Drained, "零在途恒放行（与 elapsed/budget 无关）");
    }

    /// 阻塞；轮询粒度须 < 预算，否则首轮判定即已超时、等待语义空转）。
    #[test]
    fn r119_drain_budget_constants() {
        assert!(DRAIN_BUDGET_MS <= 500, "预算必须 ≤500ms（PM 裁定）");
        assert!(DRAIN_STEP_MS < DRAIN_BUDGET_MS, "轮询粒度 < 预算");
        assert!(DRAIN_STEP_MS > 0, "轮询粒度 > 0");
    }


    /// 的钩子侧映射面零臂/错码回归钉死。
    #[test]
    fn r121_vk_to_wire_map_table() {
        // 扫描码（+扩展位）→ wire Key 判别式（复用既有判别式，零 wire 新增）
        assert_eq!(scan_code_to_blind_key(0x3A, false), Some(Key::CapsLock), "CapsLock = 0x3A 非扩展");
        assert_eq!(scan_code_to_blind_key(0x37, false), Some(Key::KpMultiply), "KP* = 0x37 非扩展");
        assert_eq!(scan_code_to_blind_key(0x53, false), Some(Key::KpDecimal), "KP. = 0x53 非扩展");
        assert_eq!(scan_code_to_blind_key(0x45, false), Some(Key::NumLock), "NumLock = 0x45 非扩展");
        assert_eq!(scan_code_to_blind_key(0x5B, true), Some(Key::Super), "Win = 0x5B 必须扩展");
        // 反例形态：非扩展 0x5B 不是 Win；扩展 0x53 = 导航 Delete
        assert_eq!(scan_code_to_blind_key(0x5B, false), None, "非扩展 0x5B 非盲区键");
        assert_eq!(scan_code_to_blind_key(0x53, true), None, "扩展 0x53 = 导航 Delete");
        assert_eq!(Key::CapsLock as u32, 0x39);
        assert_eq!(Key::KpMultiply as u32, 0x66);
        assert_eq!(Key::KpDecimal as u32, 0x67);
        assert_eq!(Key::NumLock as u32, 0x68);
        assert_eq!(Key::Super as u32, 0x56);

        let d = dec(GATE_ACTIVE, SCAN_CAPS_LOCK, false, false, false, false, false);
        assert_eq!(d.count, 1, "CapsLock down 应转发 1 事件");
        let e = d.events[0].as_ref().expect("事件存在");
        assert_eq!(e.kind, InputKind::KeyDown);
        assert_eq!(e.key, Key::CapsLock as u32);
        assert_eq!(e.modifiers, 0, "修饰位 = 0（注入侧 modifier_sync 维护）");
        let d = dec(GATE_ACTIVE, SCAN_KP_MULTIPLY, false, false, true, false, false);
        assert_eq!(d.count, 1);
        assert_eq!(d.events[0].as_ref().unwrap().kind, InputKind::KeyUp, "up 方向 = KeyUp");
        // 态 A（ActiveAltF4Suppressed）同白名单语义
        let d = dec(GATE_ACTIVE_ALT_F4_SUPPRESSED, SCAN_NUM_LOCK, false, false, false, false, false);
        assert_eq!(d.count, 1);
        assert!(d.swallow);
        // Inactive 门控：同键纯透传（不转发、不吞 = 键盘行为完全本机，fail-closed）
        let d = dec(GATE_INACTIVE, SCAN_CAPS_LOCK, false, false, false, false, false);
        assert_eq!(d.count, 0, "Inactive 门控不转发");
        assert!(!d.swallow, "Inactive 门控不吞");
    }

    /// 簇余键（KP0-9 / + / − / / / KP-Enter）egui-winit 0.28.1 两表均有臂 =
    /// egui 路可达，钩子侧**必须恒零臂**（补臂 = Tier-1 远端双发双键红线）；
    #[test]
    fn r121_numpad_cluster_zero_arm_pinned() {
        // KP7 / KP8 / KP9（0x47/0x48/0x49 非扩展；egui Numpad7-9 有臂）
        for scan in [0x47u16, 0x48, 0x49] {
            assert_eq!(scan_code_to_blind_key(scan, false), None, "0x{scan:02X} 必须零臂（egui 路覆盖）");
        }
        // KP-（0x4A）
        assert_eq!(scan_code_to_blind_key(0x4A, false), None, "KP- 必须零臂（egui NumpadSubtract→Minus）");
        // KP4 / KP5 / KP6（0x4B/0x4C/0x4D）
        for scan in [0x4Bu16, 0x4C, 0x4D] {
            assert_eq!(scan_code_to_blind_key(scan, false), None, "0x{scan:02X} 必须零臂");
        }
        // KP+（0x4E）
        assert_eq!(scan_code_to_blind_key(0x4E, false), None, "KP+ 必须零臂（egui NumpadAdd→Plus）");
        // 0x4F 同码异位双形态：非扩展 = KP1 / 扩展 = KP/（**两键都必须恒零臂**）
        assert_eq!(scan_code_to_blind_key(0x4F, false), None, "0x4F 非扩展 = KP1 必须零臂（egui Numpad1）");
        assert_eq!(scan_code_to_blind_key(0x4F, true), None, "0x4F 扩展 = KP/ 必须零臂（egui NumpadDivide→Slash）");
        // KP2 / KP3（0x50/0x51）
        assert_eq!(scan_code_to_blind_key(0x50, false), None, "KP2 必须零臂");
        assert_eq!(scan_code_to_blind_key(0x51, false), None, "KP3 必须零臂");
        // KP0（0x52）
        assert_eq!(scan_code_to_blind_key(0x52, false), None, "KP0 必须零臂（egui Numpad0）");
        // KP-Enter（0x1C 扩展；egui NumpadEnter→Enter）与非扩展 0x1C（Enter）
        assert_eq!(scan_code_to_blind_key(0x1C, true), None, "0x1C 扩展 = KP-Enter 必须零臂");
        assert_eq!(scan_code_to_blind_key(0x1C, false), None, "0x1C 非扩展 = Enter 必须零臂");
        assert_eq!(scan_code_to_blind_key(0x37, false), Some(Key::KpMultiply));
        assert_eq!(scan_code_to_blind_key(0x53, false), Some(Key::KpDecimal));
        // 注入表往返互证（服务端注入面与钩子捕获面对称；防未来改表漂移）
        assert_eq!(crate::windows::map_scan_code(Key::KpMultiply as u32), Some(0x37));
        assert_eq!(crate::windows::map_scan_code(Key::KpDecimal as u32), Some(0x53));
        assert_eq!(crate::windows::map_scan_code(Key::CapsLock as u32), Some(0x3A));
    }

    /// 列 = forward（转发意图成立）/ swallow（决策吞本地意图）/ gate_active
    /// （同锁复读）/ sink_present（同锁读）→ (send, swallow)。
    #[test]
    fn r121_decide_hook_send_matrix() {
        for &forward in &[false, true] {
            for &swallow in &[false, true] {
                for &gate_active in &[false, true] {
                    for &sink_present in &[false, true] {
                        let (send, swal) = decide_hook_send(forward, swallow, gate_active, sink_present);
                        if forward {
                            // 转发意图成立：仅「gate 开 + 发送端在场」才发送（转发+吞
                            // （fail-closed 零键损——绝不「两端都收不到」）
                            let expect_send = gate_active && sink_present;
                            assert_eq!(
                                (send, swal),
                                (expect_send, expect_send && swallow),
                                "forward={forward} swallow={swallow} gate={gate_active} sink={sink_present}"
                            );
                        } else {
                            // 无转发内容：发送恒 false；吞本地跟随决策
                            // （Alt+F4 态 A 吞本地路径 / 透传路径），与原实现一致
                            assert_eq!((send, swal), (false, swallow));
                        }
                    }
                }
            }
        }
        // 关键形态显式钉死：
        // (a) 常态：gate 开 + sink 在场 → 转发 + 吞（与原实现逐位等价，零回归锚点）
        assert_eq!(decide_hook_send(true, true, true, true), (true, true));
        // (b) H1 丢失窗形态①：转发意图成立 + sink 已撤（失焦沿 set_sink(None) 之后）
        //     → 透传不吞（零键损；原实现 = 事件未发却吞本地 = 按键两端丢失）
        assert_eq!(decide_hook_send(true, true, true, false), (false, false));
        // (c) H1 丢失窗形态②：gate 已转 Inactive + sink 仍在（失焦沿 set_gate 之后）
        //     → 透传不吞（会话不再聚焦的这一刻键归本地）
        assert_eq!(decide_hook_send(true, true, false, true), (false, false));
        // (d) 两侧皆缺（sink 锁中毒 / 会话已终）→ 透传不吞
        assert_eq!(decide_hook_send(true, true, false, false), (false, false));
        // (e) 无转发内容 + 吞本地意图（Alt+F4 态 A 吞）→ (false, true)
        assert_eq!(decide_hook_send(false, true, false, false), (false, true));
        // (f) 无转发内容 + 无吞（透传）→ (false, false)（与 gate/sink 态无关）
        assert_eq!(decide_hook_send(false, false, true, true), (false, false));
    }

    /// 饿死防御 = 病态 30s 节拍绝不永久去重）。
    #[test]
    fn r121_decide_watchdog_tick_due_matrix() {
        const PERIOD: u64 = 60_000;
        assert!(decide_watchdog_tick_due(0, 60_000, PERIOD), "首 tick 必出");
        assert!(decide_watchdog_tick_due(0, 1, PERIOD), "首 tick 必出（与时点无关）");
        // ② 距上次有效 tick < 半周期（30s）→ 重复 tick（双定时器第二路）→ 不出
        assert!(!decide_watchdog_tick_due(60_000, 61_000, PERIOD), "Δ=1s 判重复（双路同周期异相位）");
        assert!(!decide_watchdog_tick_due(60_000, 89_999, PERIOD), "Δ<30s 判重复（下边界）");
        // ③ Δ ≥ 半周期 → 有效 tick
        assert!(decide_watchdog_tick_due(60_000, 90_000, PERIOD), "Δ=30s 边界 = 有效");
        assert!(decide_watchdog_tick_due(60_000, 120_000, PERIOD), "Δ=60s = 有效");
        // ④ 时钟回拨（now < last）：饱和减法 = 0 < 半周期 → 判重复侧（宁漏勿错杀）
        assert!(!decide_watchdog_tick_due(200_000, 100_000, PERIOD), "时钟回拨不误判有效");
        // ⑤ 饿死防御：病态 30s 节拍（两路恰异相 30s）下逐 tick 均有效
        //    （至多每 60s 2 条有效 tick，看门狗绝不永久静默）
        let mut last = 0u64;
        for i in 0..10 {
            last += 30_000;
            assert!(
                decide_watchdog_tick_due(last.saturating_sub(30_000), last, PERIOD),
                "30s 节拍第 {i} tick 不得被永久去重"
            );
        }
        // ⑥ 周期参数化（非魔法 60s：period=100ms 的半周期 = 50ms）
        assert!(decide_watchdog_tick_due(100, 150, 100), "period/2 边界（50ms）= 有效");
        assert!(!decide_watchdog_tick_due(100, 149, 100), "period/2 下边界 = 重复");
    }


    /// **无条件化口径钉死**：签名不含 gate/sink/焦点入参（结构性不依赖任何
    /// 转发门）；5 键位 × 物理/注入双形态全组合 + 全部反例形态（扩展位误配/
    /// 非白名单码/同码异位）。
    #[test]
    fn r129_classify_hook_hit_matrix() {
        // 正例：白名单 5 键 × 物理/注入双形态
        let cases: &[(u16, bool, Key)] = &[
            (SCAN_KP_MULTIPLY, false, Key::KpMultiply),
            (SCAN_KP_DECIMAL, false, Key::KpDecimal),
            (SCAN_CAPS_LOCK, false, Key::CapsLock),
            (SCAN_NUM_LOCK, false, Key::NumLock),
            (SCAN_WIN, true, Key::Super),
        ];
        for (scan, extended, key) in cases {
            assert_eq!(
                classify_hook_hit(*scan, *extended, false),
                Some(HookHit::Physical(*key)),
                "0x{scan:02X} ext={extended} 物理事件 → Physical({key:?})"
            );
            assert_eq!(
                classify_hook_hit(*scan, *extended, true),
                Some(HookHit::Injected(*key)),
                "0x{scan:02X} ext={extended} injected → Injected({key:?})"
            );
        }
        // 反例①：扩展位误配（Win 非扩展 / 其余四键带扩展）→ None
        assert_eq!(classify_hook_hit(SCAN_WIN, false, false), None, "非扩展 0x5B 非白名单");
        for (scan, key) in [
            (SCAN_KP_MULTIPLY, Key::KpMultiply),
            (SCAN_KP_DECIMAL, Key::KpDecimal),
            (SCAN_CAPS_LOCK, Key::CapsLock),
            (SCAN_NUM_LOCK, Key::NumLock),
        ] {
            assert_eq!(
                classify_hook_hit(scan, true, false),
                None,
                "扩展 {key:?} 非白名单形态"
            );
        }
        // 反例②：同码异位（0x53 扩展 = 导航 Delete）与非白名单码（A=0x1E /
        // Enter=0x1C 双形态 / KP1=0x4F 双形态）→ None
        assert_eq!(classify_hook_hit(0x53, true, false), None, "扩展 0x53 = 导航 Delete");
        assert_eq!(classify_hook_hit(0x1E, false, false), None, "A 非白名单");
        assert_eq!(classify_hook_hit(0x1C, false, false), None, "Enter 非白名单");
        assert_eq!(classify_hook_hit(0x1C, true, false), None, "KP-Enter 非白名单");
        assert_eq!(classify_hook_hit(0x4F, false, false), None, "KP1 非白名单");
        assert_eq!(classify_hook_hit(0x4F, true, false), None, "KP/ 非白名单");
        // 无条件化不变式：injected 位只改变形态（Physical/Injected），
        for (scan, extended) in [(0x3A, false), (0x37, false), (0x5B, true), (0x02, false), (0x53, true)] {
            let phys = classify_hook_hit(scan, extended, false).is_some();
            let inj = classify_hook_hit(scan, extended, true).is_some();
            assert_eq!(phys, inj, "0x{scan:02X} ext={extended}：命中性与 injected 位无关");
        }
    }

    #[test]
    fn r129_stats_hit_inj_field() {
        let s = KbdHookStats {
            cb_total: 100,
            hit_caps: 2,
            hit_inj: 5,
            ..Default::default()
        };
        assert_eq!(s.hit_total(), 2, "hit_total = 物理 5 类之和（hit_inj 不计入）");
        let line = format_hook_stats_line(&s, "x");
        assert!(line.contains("hit_inj=5"), "{line}");
        assert!(line.contains("hit=2 (KP*=0 KP.=0 Caps=2 Num=0 Win=0)"), "{line}");
        // 零键内容（红线③，与 r93c_stats_format_line ④ 同判据）
        for forbidden in ["0x37", "0x53", "0x3A", "0x45", "0x5B", "KpMultiply", "CapsLock"] {
            assert!(!line.contains(forbidden), "stats 行不得含键内容 {forbidden:?}: {line}");
        }
    }

    #[test]
    fn r134_5_sink_debug_line_format_pinned() {
        // 标签钉死
        assert_eq!(SinkReason::FocusGained.label(), "focus gained");
        assert_eq!(SinkReason::FocusLost.label(), "focus lost");
        assert_eq!(SinkReason::SessionEnd.label(), "session end");
        // 行形态钉死
        assert_eq!(
            format_hook_sink_debug_line(true, SinkReason::FocusGained),
        );
        assert_eq!(
            format_hook_sink_debug_line(false, SinkReason::FocusLost),
        );
        assert_eq!(
            format_hook_sink_debug_line(false, SinkReason::SessionEnd),
        );
        // 族锚点（grep 口径：与 INFO 沿行/沿快照行共享前缀）
        for line in [
            format_hook_sink_debug_line(true, SinkReason::FocusGained),
            format_hook_sink_debug_line(false, SinkReason::FocusLost),
            format_hook_sink_debug_line(false, SinkReason::SessionEnd),
        ] {
        }
    }

    /// 钉死（与验收门禁「srv-in vk=0x6A/0x14」同口径）+ form/dir 四形态。
    #[test]
    fn r134_5_hit_line_format_pinned() {
        // vk 映射表钉死（Win 虚拟键）
        assert_eq!(blind_key_vk(Key::KpMultiply), 0x6A);
        // 为常量错位，本岗修——与 `windows::map_vk` KpDecimal 臂跨表一致）。
        assert_eq!(blind_key_vk(Key::KpDecimal), 0x6E);
        assert_eq!(blind_key_vk(Key::CapsLock), 0x14);
        assert_eq!(blind_key_vk(Key::NumLock), 0x90);
        assert_eq!(blind_key_vk(Key::Super), 0x5B);
        // 键名标签钉死
        assert_eq!(blind_key_label(Key::KpMultiply), "KpMultiply");
        assert_eq!(blind_key_label(Key::KpDecimal), "KpDecimal");
        assert_eq!(blind_key_label(Key::CapsLock), "CapsLock");
        assert_eq!(blind_key_label(Key::NumLock), "NumLock");
        assert_eq!(blind_key_label(Key::Super), "Super");

        // 逐键行形态钉死（物理 down 形态 = 复测主形态）
        let cases: &[(Key, u16, &str)] = &[
        ];
        for (key, scan, want) in cases {
            let line = format_hook_hit_line(&HookHitEvt {
                key: *key,
                vk: blind_key_vk(*key),
                scan: *scan,
                injected: false,
                is_up: false,
            });
            assert_eq!(
                line.as_str(),
                *want,
                "vk/scan 与白名单表锚点逐位一致（scan_code_to_blind_key 同判）"
            );
        }

        assert_eq!(
            format_hook_hit_line(&HookHitEvt {
                key: Key::CapsLock,
                vk: 0x14,
                scan: 0x3A,
                injected: true,
                is_up: true,
            }),
        );
        assert_eq!(
            format_hook_hit_line(&HookHitEvt {
                key: Key::NumLock,
                vk: 0x90,
                scan: 0x45,
                injected: false,
                is_up: true,
            }),
        );

        // 容量常量带内（定长环；UI 帧率 drain 下溢出实践不可达）
        assert_eq!(HIT_RING_CAP, 128);
    }

    /// ① 命中观察环 push 必须位于 `ll_kbd_proc` 回调体内（classify 块内）；
    /// ② `ll_kbd_proc` 体（至下一函数 `reinstall_hook` 止）**零 `tracing::`
    /// ③ `set_sink` 沿事件出 DEBUG 原因行（`format_hook_sink_debug_line`
    ///    接线在位，既有 INFO 沿行文案零改动）。
    #[test]
    fn r134_5_callback_wiring_and_zero_log_redline() {
        let src = include_str!("kbd_hook.rs");
        let start = src
            .find("unsafe extern \"system\" fn ll_kbd_proc")
            .expect("ll_kbd_proc 在位");
        let end = src
            .find("/// 卸载当前钩子 + 重装")
            .expect("reinstall_hook 文档锚在位");
        assert!(start < end, "区间合法");
        let body = &src[start..end];
        // ① 命中观察环 push 在回调体内
        assert!(
            body.contains("ring.push_back(HookHitEvt"),
        );
        assert!(
            body.contains("blind_key_vk(hit_key)"),
            "观察环 push 缺 vk 纯映射（行 vk 字段失联）"
        );
        assert!(
            !body.contains("tracing::"),
        );
        // ③ set_sink DEBUG 原因行接线 + 既有 INFO 沿行文案零改动
        assert!(
            src.contains("tracing::debug!(\"{}\", format_hook_sink_debug_line(now, reason));"),
        );
        assert!(
            src.contains("\"attached (focused session input_tx)\""),
            "既有 INFO 沿行 attach 文案被改动（零行为变化违例）"
        );
        assert!(
            src.contains("\"detached (focus lost / session end)\""),
            "既有 INFO 沿行 detach 文案被改动（零行为变化违例）"
        );
    }

    // ========================================================================
    // ========================================================================

    /// 回归锚：cb=40 hit=0 hit_inj=0 → not_delivered）。
    #[test]
    fn r135_2_breakpoint_verdict_matrix() {
        // ① hook_no_cb：零回调（钩子未装/未活；attach 沿常态）。
        let s = KbdHookStats::default();
        assert_eq!(r135_2_breakpoint_verdict(&s), "hook_no_cb");
        // 09-23 第四轮 179 第四轮复测形态 = 用户第 6 项断点定案）。
        let mut s = KbdHookStats::default();
        s.cb_total = 40;
        s.gate = GATE_ACTIVE_ALT_F4_SUPPRESSED;
        s.sink = true;
        assert_eq!(r135_2_breakpoint_verdict(&s), "not_delivered");
        // ③ injected_only：仅注入形态命中（到达但形态非物理）。
        s.hit_inj = 2;
        assert_eq!(r135_2_breakpoint_verdict(&s), "injected_only");
        // ④ captured_not_forwarded：物理命中在而转发零（gate/sink 断点）。
        s.hit_inj = 0;
        s.hit_caps = 2;
        assert_eq!(r135_2_breakpoint_verdict(&s), "captured_not_forwarded");
        // ⑤ capture_ok：命中 + 转发俱在（断点若有在服务端注入段）。
        s.forwarded = 2;
        assert_eq!(r135_2_breakpoint_verdict(&s), "capture_ok");
        // 多类命中叠加：hit 求和口径（hit_total 同源）不改变判定分支。
        s.hit_kp_mul = 1;
        s.hit_win = 3;
        assert_eq!(r135_2_breakpoint_verdict(&s), "capture_ok");
    }

    #[test]
    fn r135_2_verdict_line_format_pinned() {
        let s = KbdHookStats::default();
        assert_eq!(
            format_r135_2_verdict_line(&s),
        );
        let mut s = KbdHookStats::default();
        s.cb_total = 40;
        assert_eq!(
            format_r135_2_verdict_line(&s),
        );
        s.hit_caps = 1;
        s.hit_kp_mul = 2;
        s.hit_inj = 1;
        s.forwarded = 3;
        s.swallowed = 1;
        assert_eq!(
            format_r135_2_verdict_line(&s),
        );
    }
}
