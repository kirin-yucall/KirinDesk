//! 的 `external fun` 实现。符号名按 `Java_com_kirindesk_mobile_NativeBridge_*`
//! 定死（T05 波 Kotlin 工程对接契约，不得改名）。
//!
//! # 桥面清单（Kotlin 侧）
//!
//! ```kotlin
//! object NativeBridge {
//!     init { System.loadLibrary("kirin_desk_mobile") } // 之前先 loadLibrary avutil/swscale/avcodec
//!     external fun nativeInit(configDir: String)
//!     external fun nativeConnect(id: String, nickname: String, challenge: String,
//!                                serverAddr: String, token: String,
//!                                serverPubkey: String?): Long
//!     external fun nativeConnect2(mode: Int, id: String, nickname: String,
//!                                 challenge: String, serverAddr: String,
//!                                 token: String, serverPubkey: String?): Long
//!     external fun nativeOnFrameCallback(handle: Long, callback: Any)
//!     // ── P1-B：音频 PCM 回调 ──
//!     external fun nativeOnAudioCallback(handle: Long, callback: Any)
//!     external fun nativeSendInput(handle: Long, type: Int, x: Double, y: Double,
//!                                  button: Int, keyFlags: Int)
//!     external fun nativeSendKey(handle: Long, keyCode: Int, down: Boolean)
//!     external fun nativeSendKey2(handle: Long, keyCode: Int, down: Boolean,
//!                                 modifiers: Int)
//!     // ── P1-B：Unicode 文本注入（中文/emoji；服务端 KEYEVENTF_UNICODE）──
//!     external fun nativeSendText(handle: Long, text: String)
//!     external fun nativeDisconnect(handle: Long)
//!     external fun nativeVersion(): String
//!     // ── P1-A 新增（TOFU 两段式 + 历史）──
//!     external fun nativePeekPendingTrust(): String?   // 待确认指纹（79 字符）或 null
//!     external fun nativeResolveTrust(accept: Boolean): Boolean
//!     external fun nativeHistory(): String             // JSON: [{id,label,last_seen}]
//!     external fun nativeSetRequestedWidth(width: Int) // 分辨率档位 0/1280/1920
//!     external fun nativeRequestedWidth(): Int         // 当前档位回显
//!     external fun nativeIdentity(): String            // JSON: {device_id,fingerprint,public_key}
//!     external fun nativeServerStart(port: Int, nickname: String,
//!         challenge: String, relayServerAddr: String, relayToken: String,
//!         relayServerPubkey: String, deviceId: String): Boolean
//!     external fun nativeServerStop(): Boolean
//!     external fun nativeServerFeedFrame(rgba: ByteArray, width: Int,
//!                                        height: Int, timestampMs: Long): Boolean
//!     external fun nativeServerStatus(): String        // JSON 状态（见 nativeServerStatus doc；
//!     external fun nativeFileTransferStart(sessionHandle: Long, path: String): Long
//!     external fun nativeFileOfferRespond(sessionHandle: Long, transferId: Long,
//!                                         accept: Boolean, targetDir: String): Boolean
//!     external fun nativeFileTransferCancel(sessionHandle: Long, transferId: Long): Boolean
//!     external fun nativeSetInputCallbackEnabled(enabled: Boolean)
//!     // 上抛回调（**静态**；Rust viewer 会话任务线程上调，实现契约见下文
//!     // 「被控端输入上抛」节，P2B-2 照抄）：
//!     fun onServerInputEvent(kind: Int, key: Int, nx: Float, ny: Float,
//!                            modifiers: Int, text: String,
//!                            baseW: Int, baseH: Int)
//! }
//! ```
//!
//!
//! 手机作为**被控端**（电脑看手机）的服务端入口，Rust 侧实现全在
//! 广播 + 软编帧泵 + relay ID 注册）。本波**只定签名**，Kotlin 侧
//! （MediaProjection 帧源/审批 UI/P2A）归波 2：
//!
//! - `nativeServerStart(port, nickname, challenge, relayServerAddr,
//!   relayToken, relayServerPubkey, deviceId)`：启动被控端服务端。
//!   `nickname` = 被控端昵称（**必填**，控制端连接凭据）；`challenge` =
//!   挑战码（空 = 未配置 → 连接全部 fail-closed 拒绝，不静默放行）；
//!   relay 三件（addr/token/serverPubkey）双非空（addr+token）⇒ 启用 ID
//!   模式注册，**serverPubkey 缺失 fail-closed 拒注册**（ID-SEC-001）；
//!   `deviceId` 空 = 公钥指纹派生。失败抛 RuntimeException（人话原因）。
//! - `nativeServerStop()`：停止服务端（停监听/帧泵/ID 注册/清观众）。
//! - `nativeServerFeedFrame(rgba, width, height, timestampMs)`：喂一帧
//!   屏幕画面（MediaProjection 回调，波 2 接 `ImageReader`；RGBA
//!   `width*height*4` 字节；`timestampMs` = epoch 毫秒，0 = now）。
//!   高频路径：槽内只留最新帧（丢旧保新），返回 false = 未运行/参数非法。
//! - `nativeServerStatus()`：JSON 状态快照——
//!   `{"running":…, "port":…, "nickname":…, "device_id":…, "fingerprint":…
//!   （79 字符，控制端 TOFU 配对核对）, "public_key":…（控制端带外 pin）,
//!   被控端寻址用）, "pump_active":…, "id_mode_enabled":…,
//!   "id_registered":…}`。
//!
//!
//! **`sessionHandle` 双角色寻址**（同一 jlong，ID 空间不相交无歧义）：
//! - **控制端** = `nativeConnect2` 返回值（`Sessions` 句柄表，自 1 起）；
//! - **被控端** = `nativeServerStatus` JSON 的 `viewer_ids` 数组元素
//!   （观众 id，基址 2^48——永不与控制端句柄撞值）。
//! 句柄无效/会话不存在/观众断连 → `nativeFileTransferStart` = **-1**、
//! `nativeFileOfferRespond`/`nativeFileTransferCancel` = **false**、
//! `nativeGetFileTransfers` = **`[]`**（fail-closed：不 panic 不抛异常；
//! 用户发起操作记 tracing warn 人话原因，轮询路径静默防日志洪泛）。
//!
//! - `nativeFileTransferStart(sessionHandle, path)` → `transfer_id`
//!   （u64 **位模式**——tid 高位为 1 时 Kotlin 侧见负 Long 属正常，
//!   **仅 -1L = 失败**）。path = 本地文件绝对路径；先按 B1 口径预检
//!   （常规文件 + 可读 metadata）并以 `derive_transfer_id(文件基名,
//!   metadata 长度, salt)` 预派生 tid（与 B1 引擎内部同 salt/name/size
//!   确定性纯函数，保证一致），再 `start_send` 排队。-1 = 句柄无效 /
//!   路径空 / 非常规文件 / 元数据不可读 / 会话已关。
//! - `nativeFileOfferRespond(sessionHandle, transferId, accept, targetDir)`
//!   → 受理成功。入向 Offer（snapshot 中 `state = "offer_pending" &&
//!   direction = "recv"` 条目）的用户决断：`accept = true` 时 `targetDir`
//!   必须是**已存在目录**（建议 `context.getExternalFilesDir(null)
//!   .absolutePath`——app 外部私有目录免存储权限）；不存在/非目录 = 结构
//!   化错误返回 false（Offer 保持 pending，可换合法目录重试——不自动建
//!   目录、不静默换目录）；`accept = false` = Reject（`targetDir` 忽略，
//!   传 `""` 即可）。
//! - `nativeFileTransferCancel(sessionHandle, transferId)` → 受理成功。
//!   未知 tid（已完成/已清理）= 无操作返回 true（调用方以 snapshot 为准）。
//! - `nativeGetFileTransfers(sessionHandle)` → JSON 数组串（格式定稿，
//!   见 `file_transfer::transfers_json` doc；字段集与键序一经定稿不得
//!   变——键序 = serde_json 确定性字母序）：
//!   `[{"direction":"send|recv","done":40,"name":"…","path":null|
//!   "/abs/path","reason":"","size":100,"speed":1.5,
//!   "state":"queued|waiting_accept|offer_pending|sending|receiving|
//!   completed|failed|cancelled","transfer_id":42}]`
//!   （`reason` = failed/cancelled 人话原因其余空串；`path` 仅接收侧
//!   完成后非 null）。
//!
//! **轮询协议（Kotlin 侧，C 岗接线）**：会话存续期间以 **500ms~1s**
//! 周期调 `nativeGetFileTransfers`（纯拉模型，零回调）——
//! - **入向 Offer 信号** = snapshot 中出现**新的** `state =
//!   "offer_pending" && direction = "recv"` 条目 → 弹窗请用户决断 →
//!   `nativeFileOfferRespond(handle, 该条 transfer_id, true|false, dir)`；
//! - 进度/速度/完成/失败一律从 snapshot 读（终态条目缓存近期 64 条，
//!   FIFO 淘汰）；
//! - 出向发送 = `nativeFileTransferStart(handle, 绝对路径)` 返回 tid 后，
//!   在 snapshot 中跟踪该 tid 进度（排队→waiting_accept→sending→终态）。
//!
//! # 回调契约
//!
//! 帧回调对象需实现（在解码线程上调——Kotlin 侧自行切主线程）：
//! ```kotlin
//! fun onFrame(width: Int, height: Int, isKey: Int, rgba: ByteArray)
//! // isKey: 1 = IDR 关键帧（首帧/恢复后可用它重置 Bitmap 尺寸）
//! ```
//!
//! 音频回调对象需实现（P1-B，在音频解码线程上调）：
//! ```kotlin
//! fun onAudio(pcm: FloatArray, sampleRate: Int, channels: Int)
//! // pcm: interleaved stereo float32（48kHz，20ms/帧 = 1920 样本）
//! // → Kotlin AudioTrack(ENCODING_PCM_FLOAT) 低延迟写入
//! ```
//!
//!
//! 手机作为被控端时，控制端（电脑/手机）的键鼠 wire 事件
//! （`injector::InputEvent`，红线⑥）由 Rust viewer 会话任务反序列化后经
//! **静态方法**上抛——无障碍服务手势注入（`dispatchGesture` 等）归 Kotlin
//! 下棒实现。
//!
//! ## 1) Kotlin 侧要实现的静态方法（`NativeBridge` 对象内）
//!
//! ```kotlin
//! // 签名逐位定死（JNI 签名 (IIFFLjava/lang/String;II)V；改签名 = 断链）：
//! fun onServerInputEvent(
//!     kind: Int,      // 事件种类（下表）
//!     key: Int,       // 语义槽（按下表 kind 解释）
//!     nx: Float,      // 归一化 x（0.0–1.0；仅鼠标位事件有效，其余 0.0f）
//!     ny: Float,      // 归一化 y（同 nx）
//!     modifiers: Int, // 修饰键位标志：1=Ctrl 2=Shift 4=Alt 8=Super（键事件有效）
//!     text: String,   // 仅 kind=6(TEXT) 非空，其余恒为 ""（永不为 null）
//!     baseW: Int,     // 编码分辨率基数宽 = 喂帧宽（0 = 服务端尚无一帧）
//!     baseH: Int      // 编码分辨率基数高（同 baseW）
//! )
//! ```
//!
//! **`kind` 参数表**（= `injector::InputKind` 变体声明序，wire 判别式空间）：
//!
//! | kind | 名称 | `key` 语义 | `nx/ny` | `modifiers` | `text` |
//! |---|---|---|---|---|---|
//! | 0 | MOUSE_MOVE | 0 | **有效**（触摸/指针移动） | 忽略 | `""` |
//! | 1 | MOUSE_BUTTON | wire 按钮位标志：1=左 2=右 4=中，bit7(0x80)=抬起（按下/抬起同一 kind，看 bit7） | **有效**（触点；Windows 注入不消费坐标，安卓侧可用可忽略） | 忽略 | `""` |
//! | 2 | MOUSE_WHEEL | `wheel_delta`（±120/格，正=上 负=下） | 无效(0) | 忽略 | `""` |
//! | 3 | KEY_DOWN | wire 键码（HID 用途码：A=0x04…Z=0x1D / Num1=0x1E…Num0=0x27 / Enter=0x28 / Esc=0x1B / Space=0x20 / 方向=0x50–0x53 等） | 无效(0) | **有效** | `""` |
//! | 4 | KEY_UP | 同 KEY_DOWN | 无效(0) | **有效** | `""` |
//! | 5 | KEY_REPEAT | 同 KEY_DOWN | 无效(0) | **有效** | `""` |
//! | 6 | TEXT | 0 | 无效(0) | 无效(0) | **Unicode 文本**（中文/emoji，走 `commitText` 或 `ACTION_INSERT_TEXT`） |
//! | 7 | SPECIAL_KEY | `SpecialCombo` 判别式：0=WinE 1=WinD 2=WinL 3=WinR 4=AltTab 5=CtrlShiftEsc 6=AltF4 7=CtrlEsc 8=LockScreen | 无效(0) | 无效(0) | `""` |
//!
//! **坐标换算口径（P2B-2 定案）**：`nx/ny` 已是**归一化**坐标（0.0–1.0）——
//! 控制端按编码分辨率把归一化乘成像素上线，Rust 侧再除回归一化上抛。
//! Kotlin 按**屏幕真实尺寸**换算：`screenPx = (nx * screenWidth).toInt()`、
//! `screenPy = (ny * screenHeight).toInt()`（`displayMetrics` 取，注意
//! 横竖屏与导航栏口径自定）。`baseW/baseH` = 编码分辨率基数（= 服务端
//! MediaProjection 喂帧尺寸）——换算**不需要**它（归一化已与分辨率解耦），
//! 仅供诊断/像素口径备用；`baseW == 0` = 服务端尚未收到任何帧（此时鼠标
//! 事件 `nx/ny` 恒 0，可安全忽略）。
//!
//! **调用线程**：Rust viewer 会话 tokio 任务线程（**非**主线程、**非**
//! JNI 线程）——Kotlin 侧如需主线程/无障碍服务绑定自行切线程（无障碍服务
//! `dispatchGesture` 本身线程无关，可直接调）。
//!
//! **回调内禁止**：长时间阻塞（单事件处理 >50ms 会拖慢控制端手感）、
//! 抛异常（Rust 侧会 `exception_clear` + 仅首次失败 warn，之后静默丢弃——
//! 异常不会回传 Kotlin 栈，请自行 try-catch 记日志）。
//!
//! ## 2) `nativeSetInputCallbackEnabled(enabled: Boolean)` 语义
//!
//! - Kotlin 无障碍服务（`AccessibilityService.onStartCommand`/onEnabled）**
//!   真正就绪**时调 `nativeSetInputCallbackEnabled(true)`；`onDisabled`/
//!   `onUnbind`/服务销毁时调 `false`。
//! - `false`（默认值，含从未调用）= Rust 侧**静默丢弃**全部输入事件（不
//!   warn、不缓存回调、会话照常——无障碍未开时注入本就无效，fail-soft
//!   红线⑤）。
//! - `true` = Rust 侧缓存 `NativeBridge` 类全局引用 +
//!   `onServerInputEvent` 静态方法句柄（**本调用自带 class 参数，无需额外
//!   注册**），此后每个 wire 输入事件都上抛。重复调 `true` 幂等（不重建
//!   引用，无泄漏）。
//! - 上抛失败（attach 失败/JNI 异常/句柄未就绪）→ Rust 侧 `tracing::warn`
//!   **一次**（每次 enabled 切换复位计数）后继续，**绝不断会话**。
//!
//! # 输入映射（`nativeSendInput` / `nativeSendKey2`）
//!
//! 分发任务消费的注入管线格式；`capture::InputEvent` 是客户端捕获侧本地
//! 格式，**不上线**——P0~P1B 误用导致服务端逐包反序列化失败丢弃 = 用户
//! 实测触摸全无反应的根因）。
//!
//! - `type`：0=移动（x/y 为 0.0–1.0 归一化坐标，按会话跟踪的服务端捕获
//!   分辨率换算像素）、1=按键、2=滚轮；
//! - `button`（type=1）：0=左、1=右、2=中（wire 位标志 1/2/4，抬起 |0x80）；
//! - `keyFlags`（type=1）：bit0=按下；type=2 时=滚轮**格数**（×120
//!   WHEEL_DELTA 后上线，对齐桌面 120/格）；
//! - `nativeSendKey/2`：keyCode = Windows VK → wire HID 判别式
//!   （`orchestration::vk_to_wire_key`）；修饰键/OEM 标点不可映射
//!   （修饰走 Key2 `modifiers` 位标志，标点/文本走 `nativeSendText`）。
//!
//! # `nativeConnect` 模式语义（P1-A）
//!
//! - `token` 非空 → **ID 模式**：`serverAddr` = relay 地址、`token` = 认证、
//!   `serverPubkey` = relay Ed25519 公钥（缺失 fail-closed 拒连）；目标设备
//!   由 `id` 指定（完整指纹 / 10 hex 短码 / 自定义 ID）；
//! - `token` 空 → 地址直连（P0）：`serverAddr` = 目标 `host:port`，
//!   `serverPubkey` 可选 = 目标带外可信公钥（强 pin）。
//!
//!
//! 用户实测缺陷修复：IP 模式混入必填 ID 字段、无模式概念。Kotlin 连接页
//! 改双 Tab（IP 连接 / ID 连接）显式选模式，本函数以 `mode: jint` 接收：
//!
//! - `0` = IP 直连：`serverAddr`（目标 host:port）+ `id`（**被控端昵称**，
//!   握手凭据——服务端按握手 `init.client_id` 比对昵称，orchestration
//!   `connect_and_run_address` 已对齐桌面 `client_id = server_id` 口径，
//!   （token 在本层强制清空双保险）；
//! - `1` = ID 模式：`id` + `serverAddr`(relay) + `token` + `serverPubkey`
//!   四项必填，缺一 fail-fast 抛异常（`serverPubkey` 由编排层 fail-closed
//!   兜底，此处前置校验给出更早的人话报错）；
//!   （`device.example.com`；SRV/TXT/A|AAAA 三件套经加密 DNS DoH/DoT
//!   发现——`orchestration::resolve_domain_peer`，复用 core
//!   `resolve_for_connect` 唯一入口）+ `id`（被控端昵称，凭据口径对齐
//!   桌面域名模式）+ 挑战码；`token`/`serverPubkey` 忽略（信任锚 = TXT
//!   公钥 + TOFU，两字段强制清空）；
//! - 其余值 fail-fast（不静默回退字段推断）。
//!
//! **实现口径**：分流只发生在 jni.rs 层——按模式规整参数后统一调既有
//! 域名分支；mode 0 规整后必得 AddressDirect、mode 1 校验后必得 IdMode、
//! mode 2 必得 Domain）。旧 `nativeConnect` 保留为遗留兼容签名（字段隐式
//!
//! # TOFU 首连指纹确认（两段式，P1-A）
//!
//! `nativeConnect` 阻塞期间（后台线程），首连（known_hosts 未命中）会挂起
//! 等待用户决策：Kotlin 侧轮询 `nativePeekPendingTrust()`（建议 200ms），
//! 非空 → 展示指纹确认对话框 → `nativeResolveTrust(true/false)` 回传。
//! 拒绝/120s 超时均按拒绝处理（fail-closed）。known_hosts 命中一致 →
//! 自动放行；命中不一致 → 直接拒连（MITM 防护，三态对齐桌面）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use jni::objects::{JByteArray, JClass, JObject, JStaticMethodID, JString};
use jni::signature::{Primitive, ReturnType};
use jni::sys::{jboolean, jdouble, jint, jlong, jstring, jvalue};
use jni::{JNIEnv, JavaVM};

use crate::orchestration::{
    build_input_event, input_type, FrameSink, InputCommand, MobileConnectParams,
};
use crate::{orchestration, Sessions};

/// `JavaVM` 全局句柄（`JNI_OnLoad` 一次性注入；帧回调在解码线程经
/// `attach_current_thread` 取回 env）。`JavaVM` 非 Clone/Copy，以引用共享。
static VM: OnceLock<JavaVM> = OnceLock::new();

fn vm() -> Option<&'static JavaVM> {
    VM.get()
}

#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut core::ffi::c_void) -> jint {
    let _ = VM.set(vm);
    // 预热全局 tokio runtime（后续 nativeConnect 直接 block_on）。
    let _ = crate::runtime();
    jni::sys::JNI_VERSION_1_6
}

/// `nativeInit(configDir)`：设 KIRIN_DATA_DIR（T04 覆盖，Kotlin 传
/// `context.getFilesDir()` 绝对路径）+ tracing 落文件
/// `{configDir}/kirin_mobile.log`（进程一次）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    config_dir: JString,
) {
    let dir: String = match env.get_string(&config_dir) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    if dir.trim().is_empty() {
        return;
    }
    // SAFETY: JNI 线程独占 env；env var 进程级一次性设置（此后所有
    // utils config_dir()/known_hosts/identity 调用均落该目录）。
    unsafe { std::env::set_var("KIRIN_DATA_DIR", &dir) };
    static LOG_INIT: OnceLock<()> = OnceLock::new();
    LOG_INIT.get_or_init(|| {
        // （logcat 不可见），被控端服务启动路径 panic → 静默 SIGABRT 无从
        // `{configDir}/kirin_mobile.log`）；②`{configDir}/kirin_panic.log`
        // 直写兜底（subscriber 未初始化/过滤时不丢）。仅记录，不改变 panic
        // 后续走向（unwind/abort 语义原样）。
        let panic_log = format!("{dir}/kirin_panic.log");
        std::panic::set_hook(Box::new(move |info| {
            let line = format!(
                "R199PANIC thread='{}' {info}",
                std::thread::current().name().unwrap_or("<unnamed>")
            );
            tracing::error!("{line}");
            eprintln!("{line}");
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&panic_log)
            {
                use std::io::Write as _;
                let _ = writeln!(f, "{line}");
            }
        }));
        // （仅 ERROR 通过），info/warn 全吞 → 落盘日志近乎空白。回退 INFO
        // 缺省（显式 RUST_LOG 仍原样生效）。
        let builder = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_ansi(false);
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{dir}/kirin_mobile.log"))
        {
            Ok(f) => {
                // File: Write + Clone → 闭包 MakeWriter（每次调用克隆句柄写，
                // 不转移闭包内所有权以保证 Fn）。
                let f2 = f.try_clone().expect("clone log file handle");
                builder.with_writer(move || f2.try_clone().expect("clone log file handle")).init();
            }
            Err(_) => {
                // 文件不可用（如只读卷）→ 退 stdout（Android 上进 logcat）。
                builder.init();
            }
        }
    });
}

/// 帧回调 JNI 实现：GlobalRef + `onFrame(IIZ[B)V` 上调。
struct JniFrameSink {
    callback: jni::objects::GlobalRef,
}

impl FrameSink for JniFrameSink {
    fn on_frame(&self, frame: &kirin_desk_media::decoder::DecodedFrame) {
        let Some(vm) = vm() else { return };
        let mut env = match vm.attach_current_thread() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("kirin-mobile: attach thread failed: {e}");
                return;
            }
        };
        let cb = self.callback.as_obj();
        // 失败（回调已释放/异常挂起）→ 记日志丢帧，不中断解码线程。
        let result = (|| -> Result<(), jni::errors::Error> {
            let arr = env.byte_array_from_slice(&frame.rgba)?;
            let raw = arr.into_raw();
            let obj = unsafe { jni::objects::JObject::from_raw(raw) };
            env.call_method(
                &cb,
                "onFrame",
                "(III[B)V",
                &[
                    jni::objects::JValue::Int(frame.width as i32),
                    jni::objects::JValue::Int(frame.height as i32),
                    jni::objects::JValue::Int(if frame.is_key { 1 } else { 0 }),
                    jni::objects::JValue::Object(&obj),
                ],
            )?;
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("kirin-mobile: onFrame callback failed: {e}");
        }
    }
}

fn throw(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new("java/lang/RuntimeException", msg);
}

/// 音频 PCM 回调 JNI 实现（P1-B）：GlobalRef + `onAudio([FII)V` 上调
/// （音频解码线程；Kotlin 侧 AudioTrack 写缓冲，须自行管理队列）。
struct JniAudioSink {
    callback: jni::objects::GlobalRef,
}

impl crate::audio::AudioSink for JniAudioSink {
    fn on_audio(&self, pcm: &[f32], sample_rate: u32, channels: u16) {
        let Some(vm) = vm() else { return };
        let mut env = match vm.attach_current_thread() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("kirin-mobile: attach thread failed (audio): {e}");
                return;
            }
        };
        let cb = self.callback.as_obj();
        let result = (|| -> Result<(), jni::errors::Error> {
            // jni 0.21 无 float_array_from_slice：new + set_region 手动构
            //（jfloat = f32，逐位拷贝零转换）。
            let arr = env.new_float_array(pcm.len() as i32)?;
            env.set_float_array_region(&arr, 0, pcm)?;
            let raw = arr.into_raw();
            let obj = unsafe { jni::objects::JObject::from_raw(raw) };
            env.call_method(
                &cb,
                "onAudio",
                "([FII)V",
                &[
                    jni::objects::JValue::Object(&obj),
                    jni::objects::JValue::Int(sample_rate as i32),
                    jni::objects::JValue::Int(channels as i32),
                ],
            )?;
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("kirin-mobile: onAudio callback failed: {e}");
        }
    }
}

/// `nativeConnect(...) -> Long`：建链（地址直连 / ID 模式）并启动会话任务，
/// 返回会话句柄（>0）；失败抛 RuntimeException。
///
/// 总超时 180s = 连接各段 + TOFU 指纹确认等待上限 120s（P1-A 起 TOFU
/// 未命中必须经用户确认，20s 不够；超时仍 fail-closed）。
///
/// 新调用方请走 `nativeConnect2`（显式模式参数）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeConnect(
    mut env: JNIEnv,
    _class: JClass,
    id: JString,
    nickname: JString,
    challenge: JString,
    server_addr: JString,
    token: JString,
    server_pubkey: JString,
) -> jlong {
    let mut get = |s: &JString| -> String { env.get_string(s).map(|v| v.into()).unwrap_or_default() };
    let params = MobileConnectParams {
        id: get(&id),
        nickname: get(&nickname),
        challenge: get(&challenge),
        server_addr: get(&server_addr),
        // P1-A：token 非空 ⇒ ID 模式（serverAddr=relay 地址）。
        token: get(&token),
        server_pubkey: {
            let t = get(&server_pubkey);
            if t.is_empty() { None } else { Some(t) }
        },
        domain: false,
    };
    connect_with_params(&mut env, params)
}

/// 前置校验在本层完成后统一走既有 `orchestration::connect_and_run`
/// （`connect_mode` 推断逻辑不变；见模块注释「nativeConnect2 显式模式参数」）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeConnect2(
    mut env: JNIEnv,
    _class: JClass,
    mode: jint,
    id: JString,
    nickname: JString,
    challenge: JString,
    server_addr: JString,
    token: JString,
    server_pubkey: JString,
) -> jlong {
    let mut get = |s: &JString| -> String { env.get_string(s).map(|v| v.into()).unwrap_or_default() };
    let mut params = MobileConnectParams {
        id: get(&id),
        nickname: get(&nickname),
        challenge: get(&challenge),
        server_addr: get(&server_addr),
        token: get(&token),
        server_pubkey: {
            let t = get(&server_pubkey);
            if t.is_empty() { None } else { Some(t) }
        },
        domain: false,
    };
    match mode {
        // 非空，与挑战码成对）；忽略 token/pubkey（token 强制清空，双保险
        // ——即使调用方误传也不影响 connect_mode 推断）。
        0 => {
            if params.id.trim().is_empty() {
                throw(&mut env, "IP mode: server nickname is required (set on the controlled device's Dashboard)");
                return -1;
            }
            params.token.clear();
            params.server_pubkey = None;
        }
        // 1 = ID 模式：id/relay 地址/token 三项前置 fail-fast（server_pubkey
        // 缺失由编排层 fail-closed 兜底，此处不重复校验以保单一报错口径）。
        1 => {
            if params.id.trim().is_empty() {
                throw(&mut env, "ID mode: device id is required");
                return -1;
            }
            if params.server_addr.trim().is_empty() {
                throw(&mut env, "ID mode: relay server address is required");
                return -1;
            }
            if params.token.trim().is_empty() {
                throw(&mut env, "ID mode: relay token is required");
                return -1;
            }
        }
        // device.example.com（SRV/TXT/A|AAAA 三件套经加密 DNS 发现，见
        // orchestration::connect_and_run_domain）；id = 被控端昵称（凭据
        // 口径对齐桌面域名/IP 模式——服务端对 client_domain 非空客户端必查
        // 模式信任锚 = TXT 公钥，不取表单公钥——强制清空双保险）。
        2 => {
            if params.server_addr.trim().is_empty() {
                throw(&mut env, "domain mode: device domain is required (e.g. device.example.com)");
                return -1;
            }
            params.token.clear();
            params.server_pubkey = None;
            params.domain = true;
        }
        other => {
            throw(&mut env, &format!("invalid connect mode {other} (0=ip, 1=id, 2=domain)"));
            return -1;
        }
    }
    connect_with_params(&mut env, params)
}

/// 两签名共用的建链执行体（180s 总超时 + TOFU 状态清理口径一致）。
fn connect_with_params(env: &mut JNIEnv, params: MobileConnectParams) -> jlong {
    let rt = crate::runtime();
    let connected = rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(180), orchestration::connect_and_run(params)).await
    });
    match connected {
        Ok(Ok(handle)) => Sessions::global().insert(handle) as jlong,
        Ok(Err(e)) => {
            // 失败路径清理待确认指纹（防脏状态泄漏到下一次连接）。
            orchestration::trust_clear_pending();
            throw(env, &e);
            -1
        }
        Err(_) => {
            orchestration::trust_clear_pending();
            throw(env, "connect timeout (180s)");
            -1
        }
    }
}

/// `nativeOnFrameCallback(handle, callback)`：注册帧回调（可重复注册换回调）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeOnFrameCallback(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    callback: jni::objects::JObject,
) {
    let global = match env.new_global_ref(&callback) {
        Ok(g) => g,
        Err(e) => {
            throw(&mut env, &format!("new_global_ref: {e}"));
            return;
        }
    };
    let sink: Arc<dyn FrameSink> = Arc::new(JniFrameSink { callback: global });
    if !Sessions::global().set_frame_sink(handle, sink) {
        throw(&mut env, "invalid session handle");
    }
}

/// `nativeOnAudioCallback(handle, callback)`（P1-B）：注册音频 PCM 回调
/// （可重复注册换回调；`onAudio([FII)V`：interleaved stereo float32、
/// 48kHz、20ms/帧）。Rust 侧解码投递，Kotlin 侧 AudioTrack 播放。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeOnAudioCallback(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    callback: jni::objects::JObject,
) {
    let global = match env.new_global_ref(&callback) {
        Ok(g) => g,
        Err(e) => {
            throw(&mut env, &format!("new_global_ref (audio): {e}"));
            return;
        }
    };
    let sink: std::sync::Arc<dyn crate::audio::AudioSink> =
        Arc::new(JniAudioSink { callback: global });
    if !Sessions::global().set_audio_sink(handle, Some(sink)) {
        throw(&mut env, "invalid session handle");
    }
}

/// `nativeSendInput(handle, type, x, y, button, keyFlags)`：手势 → wire。
///
/// 消费的注入管线格式；P0 起误用 capture 格式导致服务端逐包丢弃 → 触摸
/// 全无反应）。归一化坐标按会话跟踪的服务端捕获分辨率
/// （`Sessions::server_resolution`）换算像素（首帧未到 = (0,0) → 移动事件
/// 丢弃并告警，不误注入 (0,0)）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeSendInput(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    type_: jint,
    x: jdouble,
    y: jdouble,
    button: jint,
    key_flags: jint,
) {
    let Some(tx) = Sessions::global().input_tx(handle) else {
        throw(&mut env, "invalid session handle");
        return;
    };
    let base = Sessions::global().server_resolution(handle);
    match build_input_event(type_ as u8, x, y, button as u8, key_flags, base) {
        Some(ev) => {
            let _ = tx.send(InputCommand::Event(ev));
        }
        None => tracing::warn!(
            "nativeSendInput: invalid args type={type_} btn={button} base={base:?} (base=(0,0) = 首帧未到，移动事件丢弃)"
        ),
    }
}

/// 键事件构造共用体（nativeSendKey / nativeSendKey2）：Windows VK → wire
/// HID 判别式；不可映射 VK（修饰键/OEM 标点）→ None 告警丢弃（修饰键走
/// `modifiers` 位标志 = nativeSendKey2；标点走 nativeSendText Unicode 注入）。
fn wire_key_event(
    key_code: jint,
    down: bool,
    modifiers: u8,
) -> Option<kirin_desk_input::injector::InputEvent> {
    use kirin_desk_input::injector::{InputEvent as WireInputEvent, InputKind};
    let key = orchestration::vk_to_wire_key(key_code.clamp(0, u16::MAX as i32) as u16)?;
    Some(WireInputEvent {
        kind: if down { InputKind::KeyDown } else { InputKind::KeyUp },
        x: 0,
        y: 0,
        button: 0,
        key,
        wheel_delta: 0,
        modifiers,
        text: String::new(),
        combo: None,
    })
}

/// `nativeSendKey(handle, keyCode, down)`：键盘事件（keyCode = Windows VK；
/// [`orchestration::vk_to_wire_key`]，无修饰键位标志语义 = mods 0）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeSendKey(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    key_code: jint,
    down: jboolean,
) {
    let Some(tx) = Sessions::global().input_tx(handle) else {
        throw(&mut env, "invalid session handle");
        return;
    };
    match wire_key_event(key_code, down != 0, 0) {
        Some(ev) => {
            let _ = tx.send(InputCommand::Event(ev));
        }
        None => tracing::warn!(
            "nativeSendKey: vk {key_code:#x} not representable on wire (modifier/OEM key — use nativeSendKey2 mods or nativeSendText)"
        ),
    }
}

/// 位标志的键事件——功能键条粘滞修饰键（Shift/Ctrl/Alt/Win 锁定态）以此
/// 附带在每次按键上（wire `Key` 枚举无修饰键，修饰语义 = 事件 modifiers
/// 位标志，对齐桌面 viewer `WireInputEvent::key(kind, hid, mod_flags)`）。
///
/// `modifiers` 位定义（与 wire `injector::modifier` 对齐）：bit0=Ctrl /
/// bit1=Shift / bit2=Alt / bit3=Win。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeSendKey2(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    key_code: jint,
    down: jboolean,
    modifiers: jint,
) {
    let Some(tx) = Sessions::global().input_tx(handle) else {
        throw(&mut env, "invalid session handle");
        return;
    };
    match wire_key_event(key_code, down != 0, modifiers.clamp(0, 0xFF) as u8) {
        Some(ev) => {
            let _ = tx.send(InputCommand::Event(ev));
        }
        None => tracing::warn!(
            "nativeSendKey2: vk {key_code:#x} not representable on wire (modifier/OEM key)"
        ),
    }
}

/// （软键盘标点/大写/中文/emoji 等统一路径）——wire `injector::InputEvent`
/// Text 变体，服务端 KEYEVENTF_UNICODE 逐 UTF-16 码元注入（windows.rs
/// Text 分支），与桌面同语义，服务端零改动。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeSendText(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    text: JString,
) {
    let Some(tx) = Sessions::global().input_tx(handle) else {
        throw(&mut env, "invalid session handle");
        return;
    };
    let s: String = match env.get_string(&text) {
        Ok(v) => v.into(),
        Err(_) => return,
    };
    if s.is_empty() {
        return;
    }
    let ev = kirin_desk_input::injector::InputEvent::text(s);
    let _ = tx.send(InputCommand::Event(ev));
}

/// `nativeDisconnect(handle)`：置 stop → 输入任务/写半/接收循环/解码线程
/// 级联退出（句柄移除，重复调用幂等返回 false 不抛）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeDisconnect(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    Sessions::global().disconnect(handle);
}

/// `nativeVersion() -> String`。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    env.new_string(crate::version())
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// `nativePeekPendingTrust() -> String?`（P1-A 两段式第一段·读）：
/// 当前待确认指纹（79 字符完整指纹）或 null。Kotlin 在 `nativeConnect`
/// 阻塞期间轮询本函数（建议 200ms 间隔）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativePeekPendingTrust(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    match orchestration::trust_peek_pending() {
        Some(prompt) => env
            .new_string(prompt.fingerprint)
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// `nativeResolveTrust(accept) -> Boolean`（P1-A 两段式第二段·写）：回传
/// 用户指纹决策。返回 true = 已送达等待方；false = 无待确认请求（迟到
/// 决策/已清理，安全忽略）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeResolveTrust(
    _env: JNIEnv,
    _class: JClass,
    accept: jboolean,
) -> jboolean {
    orchestration::trust_resolve_pending(accept != 0) as jboolean
}

/// `nativeHistory() -> String`（P1-A）：连接历史 JSON
/// `[{"id":…,"label":…,"last_seen":…|null}]`（devices.json + known_hosts
/// 合并去重；空历史 = `[]`）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeHistory(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    env.new_string(orchestration::history_json())
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// （0 = 原生 / 1280 = 720p 级 / 1920 = 1080p 级；非法值编排层清洗回退
/// 1280 档）。设置页保存时调用 + App 启动回放持久化值；对已建链会话
/// 无效（档位在握手 requested_max_width 上报，下次连接生效）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeSetRequestedWidth(
    _env: JNIEnv,
    _class: JClass,
    width: jint,
) {
    orchestration::set_requested_max_width(width as i64);
}

#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeRequestedWidth(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    orchestration::requested_max_width() as jint
}

/// `{"device_id":…,"fingerprint":…,"public_key":…}`（identity 落
/// configDir/identity/ed25519.json，与握手同一身份；加载失败 → 空串，
/// fail-soft 不阻塞设置页）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeIdentity(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let json = match orchestration::identity_summary() {
        Ok(v) => v.to_string(),
        Err(e) => {
            tracing::warn!("nativeIdentity: load identity failed: {e}");
            String::new()
        }
    };
    env.new_string(json)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

// ────────────────────────────────────────────────────────────────────────────
// `crate::server`（监听/握手/推流/ID 注册）；本波只定签名，Kotlin 帧源
// （MediaProjection）与审批 UI 归波 2。
// ────────────────────────────────────────────────────────────────────────────

/// `nativeServerStart(port, nickname, challenge, relayServerAddr, relayToken,
///
/// 失败抛 RuntimeException（人话原因），正常返回 true：
/// - `nickname` 必填 = 控制端连接凭据（昵称门，字面 trim 后比对）
/// - `challenge` 空 = 未配置 → 连接全部 fail-closed 拒绝（不静默放行）
/// - relay 三件：addr+token 双非空 ⇒ 启用 ID 模式注册，此时
///   `relayServerPubkey` 缺失 fail-closed 拒注册（ID-SEC-001）
/// - `deviceId` 空 = 公钥指纹派生
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeServerStart(
    mut env: JNIEnv,
    _class: JClass,
    port: jint,
    nickname: JString,
    challenge: JString,
    relay_server_addr: JString,
    relay_token: JString,
    relay_server_pubkey: JString,
    device_id: JString,
) -> jboolean {
    let mut get = |s: &JString| -> String { env.get_string(s).map(|v| v.into()).unwrap_or_default() };
    let config = crate::server::ServerConfig {
        port: port.max(0) as u16,
        nickname: get(&nickname),
        challenge: get(&challenge),
        relay_server_addr: get(&relay_server_addr),
        relay_token: get(&relay_token),
        relay_server_pubkey: get(&relay_server_pubkey),
        device_id: get(&device_id),
    };
    (match crate::server::start(config) {
        Ok(_st) => 1,
        Err(e) => {
            tracing::warn!("nativeServerStart failed: {e}");
            throw(&mut env, &e);
            0
        }
    }) as jboolean
}

/// ID 注册/清观众）。返回 true = 确有运行实例被停；false = 未在运行（幂等）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeServerStop(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    crate::server::stop() as jboolean
}

/// `nativeServerFeedFrame(rgba, width, height, timestampMs) -> Boolean`
/// 回调）。`rgba` = `width*height*4` 字节 RGBA；`timestampMs` = epoch
/// 毫秒（0 = now）。高频路径：槽内只留最新帧（丢旧保新），返回
/// true = 已入槽；false = 服务端未运行或参数非法（不抛——热路径降噪）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeServerFeedFrame(
    env: JNIEnv,
    _class: JClass,
    rgba: JByteArray,
    width: jint,
    height: jint,
    timestamp_ms: jlong,
) -> jboolean {
    let data: Vec<u8> = match env.convert_byte_array(&rgba) {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!("nativeServerFeedFrame: byte array read failed");
            return 0;
        }
    };
    crate::server::feed_frame(&data, width.max(0) as u32, height.max(0) as u32, timestamp_ms.max(0) as u64) as jboolean
}

/// `{"running","port","nickname","device_id","fingerprint","public_key",
/// "viewers","pump_active","id_mode_enabled","id_registered"}`
/// （Kotlin 设置页/审批页回显；`fingerprint` = 79 字符控制端 TOFU 配对
/// 核对位，`public_key` 带外 pin 位）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeServerStatus(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    env.new_string(crate::server::status_json())
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

// ════════════════════════════════════════════════════════════════
//
// B1 `FileTransferHandle` 四语义（全同步、Send+Sync、可 clone）的薄封装；
// **零协议代码**（文件帧走既有 SecureChannel 0x06 分支，B1 已接线）。
// 双角色寻址：控制端 `Sessions` 句柄表（`nativeConnect2` 返回值）/
// 被控端 `Server::viewer_file_session(viewer_id)`（`viewer_id` 经
// `nativeServerStatus` `viewer_ids` 枚举，基址 2^48 与控制端句柄空间
// [1,∞) 不相交 → 先试控制端再试被控端无歧义）。fail-closed：句柄无效/
// 会话不存在 → 各导出的哨兵值（见各自 doc），不 panic 不抛异常。
// ════════════════════════════════════════════════════════════════

/// 双角色会话句柄解析（jlong）→（文件传输句柄, 对端 peer_id）。
///
/// 控制端 = `Sessions` 句柄表（`SessionHandle.files` + `SessionHandle.peer_id`）；
/// 否则被控端 = `viewer_id`（`as u64` 截断语义：负句柄 = 无对应观众 → None）。
/// None = 句柄无效（fail-closed）。
fn file_transfer_session(
    session_handle: i64,
) -> Option<(crate::file_transfer::FileTransferHandle, String)> {
    Sessions::global()
        .file_transfer_session(session_handle)
        .or_else(|| {
            crate::server::Server::global()
                .viewer_file_session(session_handle as u64)
        })
}

/// 会话盐（B1 接线口径：本端公钥 b64 + peer_id **排序拼接**，与计算方无关；
/// `session_salt` 纯函数）。与 B1 两处 `spawn_session` 取盐同源——控制端
/// `orchestration::run_session`（`load_identity().public_key_base64()`）/
/// 被控端 `server::run_viewer_session`（同身份源 `load_identity()`），
/// 身份不可得时两侧同口径回退空串（salt 仍确定性一致）。
fn file_session_salt(peer_id: &str) -> String {
    let my_id = crate::orchestration::load_identity()
        .ok()
        .map(|i| i.public_key_base64())
        .unwrap_or_default();
    crate::file_transfer::session_salt(&my_id, peer_id)
}

/// 发送本地文件（双角色均可——双向语义）。先按 B1 口径预检（常规文件 +
/// 可读 metadata）并预派生 tid（`derive_transfer_id(文件基名, metadata
/// 长度, salt)`——与 B1 引擎内部 `cmd_start_send` 同 name/size/salt 口径，
/// 确定性纯函数保证一致：name = `file_name()` 基名而非全路径，
/// file_transfer.rs:586-593/608），再 `start_send` 排队。
///
/// 返回 **u64 tid 位模式**：tid 高位为 1 时 Kotlin 侧见负 Long 属正常，
/// **仅 -1L = 失败**（句柄无效 / 路径空 / 非常规文件 / 元数据不可读 /
/// 会话已关；人话原因 tracing warn）。tid 恰好等于 u64::MAX（-1L）的碰撞
/// 概率 2^-64，忽略。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeFileTransferStart(
    mut env: JNIEnv,
    _class: JClass,
    session_handle: jlong,
    path: JString,
) -> jlong {
    let path_str: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(e) => {
            tracing::warn!("nativeFileTransferStart: get_string failed: {e}");
            return -1;
        }
    };
    if path_str.trim().is_empty() {
        tracing::warn!("nativeFileTransferStart: empty path (fail-closed)");
        return -1;
    }
    let pb = std::path::PathBuf::from(&path_str);
    // 预检 + tid 材料（B1 `start_send` 预检与 `cmd_start_send` 同口径：
    // name = 文件基名 lossy、size = metadata 长度）。
    let (name, size) = match std::fs::metadata(&pb) {
        Ok(m) if m.is_file() => (
            pb.file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default(),
            m.len(),
        ),
        Ok(_) => {
            tracing::warn!(
                "nativeFileTransferStart: not a regular file: {}",
                pb.display()
            );
            return -1;
        }
        Err(e) => {
            tracing::warn!(
                "nativeFileTransferStart: file not accessible: {}: {e}",
                pb.display()
            );
            return -1;
        }
    };
    if name.is_empty() {
        tracing::warn!(
            "nativeFileTransferStart: no file name component (path ends with a separator?): {} (fail-closed)",
            pb.display()
        );
        return -1;
    }
    let Some((files, peer_id)) = file_transfer_session(session_handle) else {
        tracing::warn!(
            "nativeFileTransferStart: invalid session handle {session_handle} (no control-side session / no active controlled-side viewer)"
        );
        return -1;
    };
    // 先派生 tid（确定性纯函数，与引擎内部同 salt/name/size → 必一致）。
    let salt = file_session_salt(&peer_id);
    let tid = kirin_desk_core::connection::file_transfer::derive_transfer_id(&name, size, &salt);
    if let Err(e) = files.start_send(pb) {
        tracing::warn!(
            "nativeFileTransferStart: start_send failed (handle={session_handle}, file={name}): {e}"
        );
        return -1;
    }
    tid as jlong
}

/// `nativeFileOfferRespond(sessionHandle, transferId, accept, targetDir)
/// `targetDir` 必须是**已存在目录**（不存在/非目录 → 结构化错误返回 false；
/// Offer 保持 pending，可换合法目录重试——B1 口径不自动建目录不静默换
/// 目录）；`accept = false` = Reject（`targetDir` 忽略，传 `""` 即可）。
/// false 亦 = 句柄无效 / 会话已关（人话原因 tracing warn）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeFileOfferRespond(
    mut env: JNIEnv,
    _class: JClass,
    session_handle: jlong,
    transfer_id: jlong,
    accept: jboolean,
    target_dir: JString,
) -> jboolean {
    let dir: String = match env.get_string(&target_dir) {
        Ok(s) => s.into(),
        Err(e) => {
            tracing::warn!("nativeFileOfferRespond: get_string failed: {e}");
            return 0;
        }
    };
    let Some((files, _)) = file_transfer_session(session_handle) else {
        tracing::warn!("nativeFileOfferRespond: invalid session handle {session_handle}");
        return 0;
    };
    (match files.respond_offer(transfer_id as u64, accept != 0, dir) {
        Ok(()) => 1,
        Err(e) => {
            tracing::warn!(
                "nativeFileOfferRespond: failed (handle={session_handle}, tid={transfer_id}, accept={}): {e}",
                accept != 0
            );
            0
        }
    }) as jboolean
}

/// `nativeFileTransferCancel(sessionHandle, transferId) -> 受理成功`
/// 删 `.part`）。未知 tid（已完成/已清理）= 无操作返回 true（B1 口径：
/// 调用方以 snapshot 为准）。false = 句柄无效 / 会话已关。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeFileTransferCancel(
    _env: JNIEnv,
    _class: JClass,
    session_handle: jlong,
    transfer_id: jlong,
) -> jboolean {
    let Some((files, _)) = file_transfer_session(session_handle) else {
        tracing::warn!("nativeFileTransferCancel: invalid session handle {session_handle}");
        return 0;
    };
    (match files.cancel(transfer_id as u64) {
        Ok(()) => 1,
        Err(e) => {
            tracing::warn!(
                "nativeFileTransferCancel: failed (handle={session_handle}, tid={transfer_id}): {e}"
            );
            0
        }
    }) as jboolean
}

/// 快照 JSON 数组（纯拉模型唯一数据源；Kotlin 侧 500ms~1s 周期轮询，
/// `crate::file_transfer::transfers_json` doc（字段顺序一经定稿不得变）。
/// 句柄无效/会话不存在 → `[]`（轮询路径 fail-soft，不 warn 防逐次日志洪泛）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeGetFileTransfers(
    env: JNIEnv,
    _class: JClass,
    session_handle: jlong,
) -> jstring {
    let json = match file_transfer_session(session_handle) {
        Some((files, _)) => crate::file_transfer::transfers_json(&files.snapshot()),
        None => "[]".to_string(),
    };
    env.new_string(json)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

// ════════════════════════════════════════════════════════════════
//
// 模式照抄音频回调先例（P1-B）：非 JVM 线程经 JavaVM
// `attach_current_thread`（jni 0.21 返回 AttachGuard——drop 时与本次
// attach 配对 detach；线程已 attached 时嵌套 guard 为 no-op 不 detach，
// 与 JniFrameSink/JniAudioSink 同一纪律）。差异：帧/音频回调走实例
// GlobalRef，输入上抛走**静态方法**——`NativeBridge` 类全局引用 +
// `onServerInputEvent` 静态方法句柄在 `nativeSetInputCallbackEnabled(true)`
// 一次性缓存（jmethodID 对线程无效性 = 跨线程可缓存，类引用必须持有以
// 防方法句柄失效，jni 0.21 JStaticMethodID 文档口径）。
//
// fail-soft（红线⑤）：未启用（默认 false）= 静默丢弃；启用后任何上抛
// 失败（attach/JNI 异常/句柄缺失）= 本事件丢弃 + 仅首次失败 warn
// （每次 enabled 切换复位），**绝不断 viewer 会话**。
// ════════════════════════════════════════════════════════════════

/// Kotlin 静态回调签名（`NativeBridge.onServerInputEvent`）——与模块注释
/// 「被控端输入上抛」参数表逐位对应（8 参：IIFFLjava/lang/String;II → V）。
const INPUT_CALLBACK_METHOD_SIG: &str = "(IIFFLjava/lang/String;II)V";

/// 上抛开关（Kotlin 无障碍服务就绪后置 true；默认 false = 静默丢弃全部
/// 输入事件——无障碍未开时注入本就无效，fail-soft 不 warn 不崩）。
static INPUT_CALLBACK_ENABLED: AtomicBool = AtomicBool::new(false);

/// 上抛失败「仅一次 warn」标记（`nativeSetInputCallbackEnabled` 每次调用
/// 复位——状态切换后的新失败值得再报一次；稳态故障不刷日志）。
static INPUT_CALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

/// 缓存的上抛目标：`NativeBridge` 类**全局引用**（持有 → 静态方法句柄
/// 生命周期受保，jni 0.21 口径）+ `onServerInputEvent` 静态方法句柄
/// （`nativeSetInputCallbackEnabled(true)` 首次成功时一次性写入；重复
/// enabled(true) 幂等不重建——GlobalRef 无泄漏）。
#[derive(Clone)]
struct InputCallbackTarget {
    class_ref: jni::objects::GlobalRef,
    method_id: JStaticMethodID,
}

/// GlobalRef(类) → `JClass`（零拷贝包装；`JObject` 非 Clone/Copy，经
/// `from_raw` 构造——与帧回调先例 `JObject::from_raw` 同模式）。
///
/// # Safety
///
/// 原始指针取自调用方持有的类**全局引用**（进程级有效），借用为本地
/// `JClass` 包装不转移所有权、不额外引用计数——sound。
fn class_from_global(g: &jni::objects::GlobalRef) -> JClass<'static> {
    // SAFETY: `g` = 类全局引用（`'static` 生命周期）——底层 class 指针进程
    // 级有效，包装出的 `JClass<'static>` 借用不越界。
    unsafe { JClass::from(JObject::from_raw(g.as_obj().as_raw())) }
}

static INPUT_CALLBACK_TARGET: Mutex<Option<InputCallbackTarget>> = Mutex::new(None);

/// 仅首次失败 warn（`INPUT_CALLBACK_WARNED` 已置位 → 静默）。
fn input_callback_warn_once(msg: String) {
    if INPUT_CALLBACK_WARNED.swap(true, Ordering::Relaxed) {
        return;
    }
    tracing::warn!("{msg}");
}

/// 缓存类全局引用 + 静态方法句柄（在 `nativeSetInputCallbackEnabled` 的
/// JNI 线程上下文执行——env 有效；失败 = 保持 None，后续事件 fail-soft
/// 丢弃 + 仅一次 warn，不抛不崩）。
fn cache_input_callback_target(env: &mut JNIEnv, class: &JClass) {
    let mut guard = INPUT_CALLBACK_TARGET.lock().unwrap();
    if guard.is_some() {
        return; // 已缓存（幂等，防 GlobalRef 泄漏）
    }
    let global = match env.new_global_ref(class) {
        Ok(g) => g,
        Err(e) => {
            input_callback_warn_once(format!(
                "input callback: NativeBridge class global ref failed: {e} — input events will be dropped"
            ));
            return;
        }
    };
    let cls = class_from_global(&global);
    match env.get_static_method_id(&cls, "onServerInputEvent", INPUT_CALLBACK_METHOD_SIG) {
        Ok(method_id) => {
            *guard = Some(InputCallbackTarget {
                class_ref: global,
                method_id,
            });
        }
        Err(e) => {
            input_callback_warn_once(format!(
                "input callback: static onServerInputEvent{INPUT_CALLBACK_METHOD_SIG} not found: {e} — Kotlin 签名不匹配，input events will be dropped"
            ));
        }
    }
}

/// 上抛一个 wire 输入事件到 Kotlin 静态 `onServerInputEvent`（viewer 会话
/// 任务线程上下文调用；参数由 `crate::server::input_event_to_jni_args`
/// 纯转换产出）。
///
/// 全程 fail-soft：任何失败 = 丢弃本事件（仅首次 warn），不传播、不 panic、
/// 不断会话。
pub fn deliver_input_event(args: &crate::server::InputEventArgs) {
    // 门禁：无障碍服务未启用（Kotlin 未置 true / 已置 false）→ 静默丢弃
    // （不 warn——这是预期状态，无障碍未开时事件自然无效）。
    if !INPUT_CALLBACK_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let Some(vm) = vm() else {
        input_callback_warn_once(
            "input callback: JavaVM not initialized (JNI_OnLoad missing?) — dropping input events".into(),
        );
        return;
    };
    // GlobalRef 内部 Arc —— clone 浅拷贝，锁内不跨 JNI 调用（防持锁调 Java）。
    let target = INPUT_CALLBACK_TARGET.lock().unwrap().as_ref().cloned();
    let Some(target) = target else {
        input_callback_warn_once(
            "input callback: target not cached (nativeSetInputCallbackEnabled(true) 未成功?) — dropping input events".into(),
        );
        return;
    };
    let result = (|| -> Result<(), String> {
        // AttachGuard：本线程未 attached → attach；guard drop → 与本次
        // attach 配对 detach（已 attached 的 runtime 线程 = 嵌套 no-op，
        // 不提前 detach——音频/帧回调同纪律）。
        let mut guard = vm
            .attach_current_thread()
            .map_err(|e| format!("attach: {e}"))?;
        let env = &mut *guard;
        let cls = class_from_global(&target.class_ref);
        let text = env.new_string(&args.text).map_err(|e| format!("new_string: {e}"))?;
        // 参数序 = 签名 (IIFFLjava/lang/String;II)：
        // kind, key, nx, ny, modifiers, text, baseW, baseH。
        let jargs: [jvalue; 8] = [
            jni::objects::JValue::Int(args.kind).as_jni(),
            jni::objects::JValue::Int(args.key).as_jni(),
            jni::objects::JValue::Float(args.nx).as_jni(),
            jni::objects::JValue::Float(args.ny).as_jni(),
            jni::objects::JValue::Int(args.modifiers).as_jni(),
            jni::objects::JValue::Object(&*text).as_jni(),
            jni::objects::JValue::Int(args.base_w as i32).as_jni(),
            jni::objects::JValue::Int(args.base_h as i32).as_jni(),
        ];
        // SAFETY: `target.class_ref` = 进程级持有的 NativeBridge 类全局引用
        // （句柄失效唯一来源 = 类卸载，全局引用阻止之）；`target.method_id`
        // 在同一类上经 GetStaticMethodID 解析（对该类恒有效）；ret = None
        // （回调 void）；8 参类型与 INPUT_CALLBACK_METHOD_SIG 逐位对应
        // （int×4 / float×2 / String / int×2）。
        let call = unsafe {
            env.call_static_method_unchecked(
                &cls,
                &target.method_id,
                ReturnType::Primitive(Primitive::Void),
                &jargs,
            )
        };
        if call.is_err() {
            // Kotlin 回调可能挂了 Java 异常 → 清除，防污染本线程后续 JNI
            // 调用（fail-soft：异常不回传 Kotlin 栈，Kotlin 侧自行 try-catch）。
            let _ = env.exception_clear();
        }
        call.map(|_| ()).map_err(|e| format!("onServerInputEvent: {e}"))
    })();
    if let Err(e) = result {
        // 会话不断：仅（首次）warn 后继续消费后续事件。
        input_callback_warn_once(format!(
            "input callback deliver failed — event dropped, viewer session continues: {e}"
        ));
    }
}

/// 开关 + 目标缓存。
///
/// - `true`：Kotlin 无障碍服务就绪后调用——Rust 缓存 `NativeBridge` 类
///   全局引用 + `onServerInputEvent` 静态方法句柄，此后 wire 输入事件全部
///   上抛。重复调用幂等。
/// - `false`（默认）：Rust 静默丢弃输入事件（无障碍未开 = 注入无效，
///   fail-soft；不 warn 刷屏）。
/// - 两种取值均复位「上抛失败仅一次 warn」计数（状态切换后的新失败再报
///   一次）。
#[no_mangle]
pub extern "system" fn Java_com_kirindesk_mobile_NativeBridge_nativeSetInputCallbackEnabled(
    mut env: JNIEnv,
    class: JClass,
    enabled: jboolean,
) {
    INPUT_CALLBACK_ENABLED.store(enabled != 0, Ordering::Relaxed);
    INPUT_CALLBACK_WARNED.store(false, Ordering::Relaxed);
    if enabled != 0 {
        cache_input_callback_target(&mut env, &class);
    }
}

/// 编译期符号自检（cargo check android target 即验证本模块可编译；
/// 运行时由 Kotlin 侧 `System.loadLibrary` + 首调验证）。
///
/// 上抛签名 `INPUT_CALLBACK_METHOD_SIG` = `(IIFFLjava/lang/String;II)V`
/// （8 参：int kind/key、float nx/ny、int modifiers、String text、
/// int baseW/baseH）——与模块注释参数表逐位对应（const 内 assert_eq!
/// 不可用，签名一致性由本注释 + Kotlin 侧首调失败 warn 锚定）。
const _: () = {
    assert!(input_type::MOVE == 0);
};
