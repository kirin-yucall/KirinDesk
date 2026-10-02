
Kotlin/Compose 工程 wrapping `kirin-desk-mobile` JNI 桥（契约 = `mobile/src/jni.rs`，
`NativeBridge` 既有导出符号名不得改动，新增符号随波次追加）。仅 `arm64-v8a`。

## 构建（复现）

前置：JDK 17、Android SDK（compileSdk 35 / build-tools 34）、NDK 28.2.13676358、
`cargo-ndk`（NDK 构建 Rust 侧），Windows 需 `local.properties` 写
`sdk.dir=D:/Android/Sdk`（该文件不入库）。

```bash
# 1. Rust 侧：release 构建 libkirin_desk_mobile.so（workspace 根执行）
cargo ndk -t arm64-v8a -o mobile/android/app/src/main/jniLibs build --release -p kirin-desk-mobile

# 2. 拷 FFmpeg 三件套（vendored 于 mobile/ffmpeg-android/prebuilt/arm64-v8a/）
cp mobile/ffmpeg-android/prebuilt/arm64-v8a/libavutil.so   mobile/android/app/src/main/jniLibs/arm64-v8a/
cp mobile/ffmpeg-android/prebuilt/arm64-v8a/libswscale.so  mobile/android/app/src/main/jniLibs/arm64-v8a/
cp mobile/ffmpeg-android/prebuilt/arm64-v8a/libavcodec.so  mobile/android/app/src/main/jniLibs/arm64-v8a/

# 3. Gradle 打 release APK（四 .so 已就位于 jniLibs，随 APK 打包）
cd mobile/android && gradlew.bat assembleRelease
# 产物：app/build/outputs/apk/release/app-release.apk
```

jniLibs 四 .so（`libkirin_desk_mobile.so` + FFmpeg 三件）随本工程入库，Gradle
直接可构建，无需重跑步骤 1/2。

## 使用说明

### 模式一：地址直连（默认，P0 兼容）

1. 安装 `release/KirinDesk-Android-P1B3.apk`（正式签名 v2+v3，与 P1B/P1B2
   同证书——可直接覆盖安装升级）。
2. 电脑端（被控端）开启监听，记下本机 IP、端口（默认 59990）、设备 ID 与
   挑战码/昵称提示。
3. 手机与电脑同一局域网，App 内填写：服务器地址 `IP:59990` + 设备 ID（指纹
   或带冒号格式均可，自动归一化）+ 昵称 + 挑战码，点「连接」。

### 模式二：ID 模式（P1-A，中继/打洞/直连三级）

1. 被控端（桌面 GUI）打开 **Tunnel 页**，记下三项：`服务器地址`（relay
   `host:port`）、`token`、`公钥`（relay Ed25519 公钥 base64）。被控端需已
   注册在线（设备 ID / 10 hex 短码显示在 Dashboard）。
2. 手机 App 展开「中继 / ID 模式（高级）」，填入三项（本机持久化，下次
   免填）；**填写 token 即切换为 ID 模式**（直连地址字段不再使用）。
3. 设备 ID 支持三种形态：完整 79 位指纹（有无冒号/大小写均可，自动归一化）、
   **10 hex 短码**（Dashboard 短码行抄前缀）、自定义显式 ID（大小写敏感）。
4. 点「连接」：relay 解析（token 登录 + DeviceInfo 服务器签名验签，公钥缺失
   拒连 fail-closed）→ 直连候选并行（LAN 优先）→ 打洞（需 rendezvous，
   移动端未配置即跳过，与桌面 GUI 同口径）→ 中继兜底。


1. 被控端（桌面）以**域名模式**运行：向自有 DNS zone 发布三件套记录
   （`{device_id}.{domain}` 形态，例如设备 `device`、zone `example.com`）：
   - `_remote._tcp.device.example.com` **SRV** → `0 1 {port} device.example.com.`
   - `device.example.com` **TXT** → `{"key":"ed25519:<base64>","proto":…,"ver":…}`
   - `device.example.com` **A / AAAA** → 对端地址
2. 手机 App 切到「域名」Tab，填：**设备域名**（完整 `device.example.com`）+
   **被控端昵称**（凭据，与挑战码成对——口径对齐桌面域名/IP 模式）+ 挑战码。
3. 点「连接」：SRV（端口）+ TXT（Ed25519 公钥）+ A/AAAA（地址）三件套经
   **加密 DNS（DoH/DoT，默认 Cloudflare/Google/阿里）** 发现——与桌面
   Connect 页域名路径同款记录三件套与信任锚（TXT 公钥 → TOFU 首连确认 →
   Exact pin；差异：桌面经 DNS 服务商管理 API 发现需 zone 属主凭据，手机
   无配置面，改经加密解析器公开查询，M8-T040 红线口径不变：**解析只走
   `core::dns::resolve_for_connect` 唯一入口，绝不回退明文 DNS**）。
4. 解析失败给可读错误（中英）：域名不存在（NXDOMAIN）/ 无 A/AAAA 记录 /
   无 SRV（对端未按域名模式发布）/ 无 TXT 公钥（拒连）/ 加密 DNS 超时或
   不可用（fail-closed）。
5. TOFU/历史沿用：known_hosts 与连接历史均以**设备域名**为键（历史下拉
   回显，label = 昵称）。


- **中继服务器（ID 模式）**：server_addr / token / server_pubkey 三件——
  与连接页 ID Tab 折叠区读写**同一 SharedPreferences("relay") 存储**
  （单一数据源，两处编辑互通）。
- **连接偏好**：分辨率上报档位三选——720p（1280，默认）/ 1080p（1920）/
  原生（0 = 不上报，服务端按捕获分辨率直发）。经 `nativeSetRequestedWidth`
  驱动握手 `requested_max_width`（**下次连接生效**；服务端高负载/多观众
  收敛时可能降档，实际以视频流尺寸为准）。
- **本机信息**：设备 ID + 79 位指纹（`nativeIdentity`，与握手同一身份，
  落 `filesDir/identity/ed25519.json`）。
- **语言**：随系统 / 中文 / English（`attachBaseContext` 应用，切换即
  重建生效；关键页文案均已接入 resources）。
- **关于**：应用版本 + nativeVersion + **日志导出**（`files/kirin_mobile.log`
  经 FileProvider 走系统分享面板——可保存到文件管理器/云端/聊天工具；
  正式签名包无需 run-as）。

### TOFU 首连指纹确认（P1-A）

首次连接某设备时（known_hosts 未命中）弹出确认对话框：与被控端
Dashboard 显示的 **79 位完整指纹**逐字核对（挑战码同屏显示；短码发起时
额外警示「短码一致不能证明身份」），确认后落 known_hosts 并继续握手；
拒绝或 120s 超时则中止连接。指纹与既有记录**不一致 → 一律拒连**（防
中间人，fail-closed）。P0 的「首连自动信任」已废除。

### 连接历史（P1-A）

连接页设备 ID 输入框为历史下拉（`devices.json` + `known_hosts` 合并去重，
与桌面数据同格式，存 app filesDir）：展示 昵称/短 ID + 最近连接时间，点选
回填设备 ID。连接成功自动保存/刷新记录。

## 手势说明

- 单指移动 = 鼠标移动（坐标按 ContentScale.Fit 内容矩形归一化，黑边内自动钳制；
- 单指点击 = 左键；长按 500ms = 按住左键拖动（抬指释放）
- 双指点击 = 右键；双指上下拖 = 滚轮（约 40px/格，wire 侧 ×120 WHEEL_DELTA）
- 三指点击 = 中键
- 会话页自动 sensorLandscape 横屏 + 沉浸式全屏（隐藏系统栏，滑动暂现）；
- 底部输入条：软键盘文本**整段 Unicode 注入**（大写/Shift 符号/标点/中文/
  无效已废弃）
- 功能键条粘滞修饰键（Shift/Ctrl/Alt/Win）：以 modifiers 位标志随键下发

## i18n

连接/设置/错误文案走 `res/values/strings.xml`（默认英文）+
随系统 / 中文 / English，`attachBaseContext` 包 locale + 切换重建生效）。

## P1-A 限制（列后续）

- 无音频（P1-B）；仅 arm64-v8a；release 复用 debug keystore 签名
- 打洞需 rendezvous 独立端口配置（桌面 Tunnel/relay-server `--rendezvous-port`），
  移动端未暴露该字段——ID 模式实际路径 = 直连/中继两级（与桌面 GUI 未配
  rendezvous 时同口径）
- 指纹确认对话框期间连接线程阻塞等待（单会话语义；超时 120s fail-closed）
