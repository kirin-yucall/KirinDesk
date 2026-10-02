
Kotlin Compose 壳 + Rust 核心的桥接 crate（方案研究 §5）。`cdylib` 产
`libkirin_desk_mobile.so`，`rlib` 供宿主机单测。不复制逻辑：连接/握手走
`core::connection::client`（地址直连）与 `core::connection::id_mode`
（ID 模式，P1-A），数据面走 `media::transport` + `media::decoder`，
输入 wire 复用 `input::capture::InputEvent`，TOFU/历史存储复用
端（服务端）**（监听/握手/推流/ID 注册，`src/server.rs`，复用
core/relay/media 库层零改动——见下文「被控端（服务端）」章节）。

## JNI 契约

Kotlin 侧 `com.kirindesk.mobile.NativeBridge`，完整签名与回调/输入映射见
`src/jni.rs` 模块注释（符号名不得改动）。共 **22 个 JNI 导出**（P0 七个 +
P1-A 三个 `nativePeekPendingTrust` / `nativeResolveTrust` /
`nativeOnAudioCallback`（音频 PCM 回调）/ `nativeSendText`（Unicode 文本
`nativeSetRequestedWidth` / `nativeRequestedWidth`（分辨率档位）/
关；上抛静态方法 `onServerInputEvent` 为方法句柄查找，**不是**导出符
号），见下文导出表）。


IP 模式「连不上（early eof）」根因：服务端昵称门比对握手 `init.client_id`
（core `verify_server_init_inner`），桌面 GUI 地址模式历来上报
`client_id = server_id`（服务端昵称）；移动端曾误发本机设备 ID →
nickname mismatch → 裸 close → early eof。修复：地址模式 `client_id` =
被控端昵称（仅 trim，**不做**指纹/短码归一化——大小写敏感字面比对），
`id` 参数即承载该昵称（jni `nativeConnect2` 模式 0 起强制非空）。
宿主回归矩阵见 `tests/ip_mode_handshake.rs`（正确凭据过 / 错昵称 /
错挑战码（结构化拒绝码）/ 大小写敏感 / 空 id 回退地址串必拒）。

### 键盘（P1-B 增强）

- `KeyMap.mapping(c)` 单字符 → `(VK, needsShift)`：大写字母与 Shift 符号
  （`~_+{}|:"<>?`、数字行 `)!@#$%^&*(`）以 Shift 包裹序列发送
  （Shift↓+键↓+键↑+Shift↑），不再跳过；
- 功能键条（SessionScreen）：粘滞修饰键 Shift/Ctrl/Alt/Win（锁定高亮，
  可组合，如 Ctrl+Alt+Del）+ 点触键 Esc/Tab/Enter/BkSp/Del/Home/End/
  PgUp/PgDn/方向键 + F1–F12 横排滚动；断开时锁定态自动复位；
- 非 ASCII（中文/emoji）→ `nativeSendText`（wire `InputEvent::Text`，
  服务端 KEYEVENTF_UNICODE 逐 UTF-16 码元注入，与桌面同语义）。

### `nativeConnect` 模式语义（P1-A）

- `token` 非空 → **ID 模式**：`serverAddr` = relay 地址、`serverPubkey`
  = relay Ed25519 公钥（ID-SEC-001 DeviceInfo 验签，**缺失 fail-closed
  拒连**）；目标设备由 `id` 指定（完整指纹 / 10 hex 短码 / 自定义 ID，
  打洞 → 中继兜底）→ 流上 Ed25519 双向握手（对齐桌面
  `run_client_session_by_id`）。
- `token` 空 → 地址直连（P0 语义不变）：`serverAddr` = 目标 `host:port`，
  `serverPubkey` 可选 = 目标带外可信公钥（强 pin）。

### TOFU 首连指纹确认（两段式，P1-A）

known_hosts 三态：命中一致 → 自动放行；命中不一致 → 拒连（fail-closed）；
未命中 → `nativeConnect` 阻塞等待用户决策——Kotlin 轮询
`nativePeekPendingTrust()`（200ms）取 79 字符完整指纹弹确认对话框，
`nativeResolveTrust(accept)` 回传；拒绝/120s 超时均拒绝。确认后落
known_hosts 并以 Exact pin 完成握手（连接成功才落盘，对齐桌面）。

### 连接历史（P1-A）

`nativeHistory()` 返回 `[{id,label,last_seen}]`（devices.json + known_hosts
合并去重，`SavedDevice` 桌面同格式；KIRIN_DATA_DIR = filesDir）。
连接成功后自动 upsert 设备记录（`save_device_history`）。


「电脑看手机」一期：本 crate 兼作安卓被控端服务端（监听 + 握手 + 推流
量；JNI 入参 0 = 临时端口）。握手复用 core 库层（`server_read_init` /
`verify_server_init` / `send_handshake_reject`，与桌面 GUI 被控端同一校
验链）：昵称门 = 字面 trim 比对（大小写敏感）；错挑战码 → 结构化拒绝码
`challenge_mismatch`；**挑战码未配置 → fail-closed 全连接拒绝**
（`credentials_required`，不静默放行）。ID 模式（relay addr+token 双非
空）复用 `relay::id_client::IdClient` 注册，**`relay_server_pubkey` 缺失
fail-closed 拒注册**（ID-SEC-001）。帧泵 = 专用 std 线程：帧喂入槽
**latest-wins**（积压丢旧保新）→ `WindowPipeline set_low_latency` 逐帧
关窗 + `rate_ladder` 按输出分辨率取码率（libx264 经 FFmpeg，见「FFmpeg
预编三件套」）；首观众拉起 / 全退 **5s 宽限停泵**；每观众 **8 深**有界
广播缓冲（满 → 丢非关键帧标慢观众，关键帧成功投递后恢复；关键帧补投
200ms 限时超时踢出，不 backpressure 帧泵）。线上格式 = `EncodedWindow`
经 `send_big_packet`（禁自创）。宿主 e2e 5 项见 `tests/server_loopback.rs`
（握手矩阵 4 + 推流冒烟 1：首窗 IDR / 8s ≥4 窗 / 断连移除 / 5s 宽限停
泵）。

### JNI 服务端导出表（4 个，Kotlin 实现归波2）

| 导出 | 签名 | 语义 |
| --- | --- | --- |
| `nativeServerStart` | `(int port, String nickname, String challenge, String relayServerAddr, String relayToken, String relayServerPubkey, String deviceId) → boolean` | 启动服务端（port 0 = 临时端口；失败抛 RuntimeException 人话原因；nickname 必填 = 连接凭据；challenge 空 = 未配置 fail-closed） |
| `nativeServerStop` | `() → boolean` | 停止（停监听/帧泵/ID 注册/清观众；幂等，true = 确有运行实例被停） |
| `nativeServerFeedFrame` | `(byte[] rgba, int width, int height, long timestampMs) → boolean` | 喂一帧屏幕画面（`w×h×4` 字节 RGBA，timestampMs = epoch 毫秒 0 = now；槽内只留最新帧；热路径不抛异常，false = 未运行/参数非法） |
| `nativeServerStatus` | `() → String` | 状态 JSON：running/port/nickname/device_id/fingerprint/public_key/viewers/pump_active/id_mode_enabled/id_registered（fingerprint = 79 字符控制端 TOFU 配对核对位，public_key = 带外 pin 位） |

### 波2（Kotlin）对接清单

- **帧源 = MediaProjection `ImageReader`**（RGBA_8888，**maxImages=3**）：
  `onImageAvailable` 回调内 `acquireLatestImage()` → 取 plane 0 buffer 拷
  出 byte[] → `nativeServerFeedFrame(rgba, w, h, tsMs)` → 立即 `close()`
  （防 ImageReader 槽耗尽阻塞采集）；`acquireLatestImage` 天然
  latest-wins，与 Rust 侧喂入槽同构，回调内做重活会堵采集故拷贝后尽快
  归还。
- **审批 UI / 设置页回显**：轮询 `nativeServerStatus()`（viewers/
  pump_active/id_registered 状态回显；首连前向控制端出示 fingerprint
  核对 + public_key 带外 pin）。
- 音频捕获 / 输入注入（控制端键鼠入手机）= **二期**（wire `InputEvent`
  tag 消费点已在服务端连接任务预留，届时零协议改动）。
- P2A 出包（正式签名）归波2；本波不出 APK、不动 `release/`。


- **入口**：连接页 `ui/ConnectScreen.kt` 连接按钮下方「共享此手机（被控
  模式）」（`server_entry`，i18n 双语）→ `MainActivity.startServerSharing`：
  API 33+ 先链式 POST_NOTIFICATIONS（授予/拒绝后均继续）→ MediaProjection
  系统授权 launcher → `ScreenShareService.start(activity, resultCode, data)`；
  拒绝/60s 超时 → 人话原因记 SharedPreferences（`start_error`），共享页
  1s 轮询拾取展示。
- **服务 `server/ScreenShareService.kt`**（mediaProjection 前台服务）：
  顺序纪律 = ① `startForeground`（系统 5s 时限内、**先于**投影启动/捕获
  启动——Android 14 时序要求）→ ② `nativeServerStart`（**喂帧前**完成；
  失败人话原因 + 全停自毁）→ ③ 捕获启动（`getMediaProjection` →
  `ImageReader(RGBA_8888, maxImages=3)` → `createVirtualDisplay
  (AUTO_MIRROR)`）；喂帧在专用 `HandlerThread("kirin-screen-capture")`：
  `acquireLatestImage()` → plane 0 拷出 byte[]（row-stride 兼容：常规
  行距整体拷 / 非常规逐行拷）→ `nativeServerFeedFrame(rgba, w, h, nowMs)`
  → 立即 `close()`（防 ImageReader 槽耗尽堵采集）；喂帧路径异常 fail-soft
  不堵采集（Rust 热路径本不抛）。
- **停止路径（4 条，收敛 `onDestroy` teardown 同一点）**：① 共享页「停止
  共享」按钮（`stopService`）② 通知栏「停止」③ 系统撤销授权
  （`MediaProjection.Callback.onStop` → `stopSelf`）④ 启动失败
  `failStart` → `stopSelf`。teardown 顺序：`virtualDisplay.release` →
  `imageReader.close` → `projection.stop` → `nativeServerStop()`（幂等）。
- **共享页 `ui/ServerScreen.kt`**：共享设置（昵称/挑战码 fail-closed 校验
  + 端口 0=临时端口 + 可选 relay/ID 模式三件套——与连接页 relay 折叠区同一
  存储；三件套不全 = 拒启用 ID 模式）+ 本机信息区（设备 ID + 79 位指纹
  （控制端 TOFU 核对位）+ 公钥（带外 pin 位））+ 运行态（1s 轮询
  `nativeServerStatus`：端口/观众数/pump/ID 注册）+ 停止按钮。
- **Android 14 四小时上限**：平台限制（API 34+），到时系统强停
  MediaProjection 会话 → `onStop` 回调 → 服务收敛停止；**不自动重连**
  （重进共享页重新发起；自动重连 = 遗留）。
- 一期口径：旋转/屏幕尺寸变化不重建初始 surface（AUTO_MIRROR 仅方向
  镜像跟随，注释在 `ScreenShareService.startCapture`）。

### 输入注入（二期，P2B：键鼠控手机）

被控端输入链路打通：桌面控制端键鼠 → wire `InputEvent`（一期预留的
`ChannelTag::Input` 消费点，零协议改动）→ `server.rs`
`run_viewer_session` bincode 反序列化（红线⑥，与桌面服务端消费点同型）
→ 纯函数 `input_event_args` / `input_event_to_jni_args`（wire 像素按编码
分辨率基数 `frame_base` 反归一化 `nx/ny` clamp[0,1] + 基数同传）→ JNI
上抛（非 JVM 线程 `AttachGuard` attach/detach 配对；fail-soft：失败仅首
次 warn、`exception_clear`，**绝不断会话**）→ Kotlin
`NativeBridge.onServerInputEvent` 静态方法（8 参，JNI 签名
`(IIFFLjava/lang/String;II)V`，逐位对齐 jni.rs 契约）→
`AccessibilityInputService` 注入。启用开关 =
`nativeSetInputCallbackEnabled(Boolean)`：无障碍服务 `onServiceConnected`
→ `true`（Rust 侧一次性缓存类全局引用 + 静态方法句柄，幂等无泄漏）；
`onUnbind` / `onDestroy` → `false`（false / 默认 = Rust 侧静默丢弃全部输
入事件，会话照常，红线⑤ fail-soft）。

**wire→手势映射表**（`kind` = `injector::InputKind` 变体声明序；
`modifiers` 位标志：1=Ctrl 2=Shift 4=Alt 8=Super）：

| kind | 事件 | Rust 上抛 | Kotlin 注入（P2B-2 口径） |
| --- | --- | --- | --- |
| 0 | MOUSE_MOVE | `nx/ny` 归一化（0–1，越界 clamp；基数未知不产 NaN） | 仅更新触点缓存，不注入手势（Android 无悬停） |
| 1 | MOUSE_BUTTON | 按钮位 1=左 2=右 4=中，bit7(0x80)=抬起 | 左键：按下记点+时刻 / 抬起判定 **tap**（位移 <24px 且间隔 <800ms → 原地 100ms stroke）/ **drag**（单指 stroke，时长 = 实际间隔、最低 100ms）/ **long press**（≥800ms 未移动，时长 = 实际间隔）；孤儿抬起按抬起点单 tap 兜底。右键 → `GLOBAL_ACTION_BACK`，中键 → `GLOBAL_ACTION_RECENTS`（仅按下沿） |
| 2 | MOUSE_WHEEL | `wheel_delta` ±120/格（正 = 上） | 双指同向垂直滑动（位移 = \|delta\|×2px 封顶 600px；时长 100–400ms 线性；中心 = 触点缓存缺省屏幕中心） |
| 3/4/5 | KEY_DOWN / KEY_UP / KEY_REPEAT | wire HID 用途码 + `modifiers` | 键盘 MVP（见下表后「键盘 MVP」节）；KEY_UP / KEY_REPEAT 忽略 |
| 6 | TEXT | Unicode 文本（永不为 null） | 整段追加到当前焦点可编辑输入框 |
| 7 | SPECIAL_KEY | `SpecialCombo` 判别式（1=WinD 4=AltTab 8=LockScreen …） | WinD → `HOME` / AltTab → `RECENTS` / LockScreen → `LOCK_SCREEN`；Esc（HID 0x1B，经 KEY_DOWN）→ `BACK`；其余 SpecialCombo 遗留 |

**键盘 MVP（P2B-2）**：① `KEY_DOWN` HID 字母数字（A=0x04…Z=0x1D /
Num1=0x1E…Num0=0x27）+ Shift 位（→ 大写）；Ctrl/Alt/Super 参与 = 修饰组
合，不注入 ②主线程 `findFocus(FOCUS_INPUT)` + 节点 `isEditable` →
`ACTION_SET_TEXT`（现有文本 + 追加；节点不可用/拒绝 → 静默丢计数
`droppedTextEvents`）③ `kind=6` TEXT 整段追加（中文/emoji/标点）④
Backspace（HID 0x2A）删尾一字符（SET_TEXT 截短）⑤ Enter（0x28）忽略
（遗留）⑥无可编辑焦点 → 静默丢。**遗留**：Enter 提交语义 / 方向键
（0x50–0x53）/ F 键 / 修饰组合 / 滚轮 `continueStroke` 持续手势（当前每
格单次 stroke）。

**坐标口径**：`nx/ny` 已归一化（控制端按编码分辨率乘像素上线，Rust 侧再
除回归一化上抛）；Kotlin 按屏幕真实尺寸换算 `screenPx =
(nx × screenWidth).toInt()`（API 30+ `maximumWindowMetrics` / 26–29
`getRealSize`）；`baseW/baseH` = 编码分辨率基数（= 服务端喂帧尺寸），换
算不需要（归一化已与分辨率解耦），仅诊断备用；`baseW == 0`（尚无帧）左
键安全忽略，右/中/滚轮照常处理。

**隐私口径**：`accessibility_service_config.xml` =
`canPerformGestures=true` + `canRetrieveWindowContent=true`（焦点文本提
交所需）；**eventTypes 通配但 `onAccessibilityEvent` 空实现零消费**——不
监听任何无障碍事件、不读取屏幕内容；服务 description（双语）明示「仅执
行远端键鼠手势，并将远端键入文本提交到当前焦点输入框」。权限引导 = 共享
页「远程控制（键鼠）」区块（`Settings.Secure.
ENABLED_ACCESSIBILITY_SERVICES` 组件串探测，随 1s 轮询刷新；未启用 →
`ACTION_ACCESSIBILITY_SETTINGS` 系统无障碍设置跳转 + 引导文案；服务 label
「KirinDesk 远端输入 / KirinDesk remote input」）。

**P2B 门禁（P2B-3 实测）**：mobile 测试 **61/0**（50 lib（含 P2B-1 新增
14 输入上抛单测）+ 6 ip_mode + 5 server_loopback）；`.so` 重建
9,142,672 B，动态导出 22 JNI + `JNI_OnLoad` = 23（新增
`nativeSetInputCallbackEnabled`）；APK `KirinDesk-Android-P2B.apk`
20,003,025 B（sha256 `8d5937c1…b49b2`，v2+v3，证书 `eefb4167…45af` 与
P1B 系同证覆盖安装），抽包双核验（包内 `.so` 23 符号全在 +
`classes.dex` 见 `onServerInputEvent`）。


   `CARGO_TARGET_DIR=<repo>/target_mob cargo ndk -t arm64-v8a -o mobile/android/app/src/main/jniLibs build -p kirin-desk-mobile --release`
   （P2A 产物 = 9,146,528 B；符号门禁 = 21 JNI + `JNI_OnLoad`，见下「JNI
   符号一致性验证」）。
2. `cd mobile/android && JAVA_HOME=<JDK17> ./gradlew assembleRelease`（正式
   签名四件环境变量注入口径见下节；缺失任意一项回退 debug）。
3. **门禁（P2A 实测）**：mobile 测试 **47/0**（36 lib + 6 ip_mode + 5
   server_loopback，与波1 基线一致）；`apksigner verify -v` = v2+v3 true，
   证书 SHA-256 `eefb4167…45af`（与 P1B/P1B2/P1B3 同证书，覆盖安装）；
   APK 抽包核验（unzip + `llvm-nm -D`）22 符号全在包；APK 19,981,865 B，
   sha256 `7d6abf3474f69a1f0645e3d8d250da5468bf56d85909588959882aac887e8244`，
   归位 `release/KirinDesk-Android-P2A.apk` + 纯 hex 侧车。

## 构建（Windows 主机）

前置：NDK（`D:\Android\Sdk\ndk\<ver>`）、`rustup target aarch64-linux-android`、
`cargo install cargo-ndk`。

```bash
export ANDROID_HOME=/d/Android/Sdk
export ANDROID_NDK_HOME=/d/Android/Sdk/ndk/<ver>
# 编译验证（不产 .so）
cargo ndk -t arm64-v8a check -p kirin-desk-mobile
# 产 jniLibs（FFmpeg 三件套从 mobile/ffmpeg-android/prebuilt/arm64-v8a/ 由
# Gradle/cargo-ndk 拷贝步骤放进同一 jniLibs 目录）
cargo ndk -t arm64-v8a -o mobile/jniLibs build -p kirin-desk-mobile
```

以上 `cargo ndk` 均配合 `CARGO_TARGET_DIR=<repo>/target_mob`（并发岗隔离，
不与桌面默认 target 抢锁）。产正式签名 APK（P1-B 起）：

```bash
cd mobile/android
export JAVA_HOME=<JDK17>                       # 本机 D:\Android\jdk\jdk-17.0.20.1+1
export KIRIN_STORE_FILE=E:\projects_rd\\secrets\\kirindesk-release.jks
export KIRIN_STORE_PASSWORD=<口令>             # 见 secrets/kirindesk-release.password
export KIRIN_KEY_ALIAS=kirindesk
export KIRIN_KEY_PASSWORD=<口令>
./gradlew assembleRelease
# 环境变量缺失任意一项 → 自动回退 debug 签名（构建不中断，口径见
# app/build.gradle.kts 注释）。
```


`mobile/ffmpeg-android/prebuilt/arm64-v8a/` 三件套（libavcodec / libavutil
/ libswscale .so）为**含 libx264** 重编版（`build.sh`：先 NDK 交叉编译
x264 静态库，再 FFmpeg `--enable-gpl --enable-libx264
--enable-encoder=libx264`）。**GPL 合规口径**：x264 静态链入
libavcodec.so（动态符号表 0 面，GPL 自包含不外染），许可文本
`licenses/x264-COPYING` 随目录落库；完整性核对 `arm64-v8a.sha256`。重
编：`bash mobile/ffmpeg-android/build.sh`（需 NDK，口径与踩坑注释见脚本
头部）。

## JNI 符号一致性验证（门禁口径）

```bash
NM=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe
"$NM" -D --defined-only mobile/jniLibs/arm64-v8a/libkirin_desk_mobile.so \
  | grep "Java_com_kirindesk_mobile_NativeBridge_"
# 期望 22 个导出（nativeInit/nativeConnect/nativeConnect2/
# nativeOnFrameCallback/nativeOnAudioCallback/nativeSendInput/
# nativeSendKey/nativeSendKey2/nativeSendText/nativeDisconnect/
# nativeVersion/nativePeekPendingTrust/nativeResolveTrust/
# nativeHistory/nativeSetRequestedWidth/nativeRequestedWidth/
# nativeIdentity/nativeServerStart/nativeServerStop/
# nativeServerFeedFrame/nativeServerStatus/
# 22 + 1 = 23）。
```

## FFmpeg 加载顺序（Android）

Kotlin 侧在 `System.loadLibrary("kirin_desk_mobile")` **之前**按依赖序：
`avutil → swscale → avcodec`；Rust 侧 `media::ffmpeg::dlls` 以裸 soname
libavcodec.so 内含 libx264 编码器（静态链入，无需额外 .so 装载）。
