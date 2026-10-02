# KirinDesk — 发布包使用说明

P2P 远程桌面 · IPv6/IPv4 直连优先 · 服务器辅助打洞 · 零 TLS 证书 · 端到端加密

> 💜 **个人开发者用爱发电的纯公益项目** —— 无订阅、无广告、无遥测。完整介绍与
> 架构见仓库根目录 [`Readme.md`](../Readme.md)（中文：[`Readme_CN.md`](../Readme_CN.md)）。

本目录是**已构建的发布产物**。下面只讲"拿到发布包后怎么装、怎么用"。

## 一、Windows 桌面端

本目录已附 `KirinDesk.exe`（egui 原生 GUI，含 CLI 回退）。

构建自 commit
`d859f14`（=origin/main，工作树干净、记录表零 🔴；增量构建 exit 0〔2m37s〕、
release 警告 4 = 既有集零新增），
`KirinDesk.exe`（24,233,984 B，sha256 `001becf929da4ee0fe60a089e683c7711370e2acc13c4073e8fbd38d040defcd`
〔侧车 `KirinDesk.exe.sha256`，`sha256sum -c` OK〕，`--cli self-test` exit 0
〔×2 全过，各次 `KIRIN_DATA_DIR` 隔离目录 + `KIRIN_NOHW_HW_DECODE=1` 前缀，
配置哨兵（`%APPDATA%\kirin_desk` 8 文件 + `~/.kirin_desk` 16 文件 **含 logs/
全量**）开工/收工**逐位一致** = 零污染；**banner `commit=d859f14` = 构建时 HEAD
亲证**×2〔banner 恒为构建时 HEAD〕；第二次=commit 后复跑核包本体未变〕）
加固（从远端拉取的文件现在能可靠写入本机剪贴板——Open 重试 ≥5 次退避 + 整序列
重试 ≥2 轮 + Set 失败回滚旧板留底，剪贴板被其他程序短暂占用时自动重试，不再
（客户端指针不再每帧无条件重发同一远端坐标——去重锚点 + 重连续接/焦点重得/
——客户端首连指纹确认可见性（指纹确认期间任务栏闪烁 + 尝试前置窗口 + 提示音，
（`4e46fda`+`30ea5cb`+`806b3de`）——原生崩溃观测+防护（原生崩溃自动留
minidump 证据文件 + 60s 心跳日志圈定时间窗，键盘钩子卸载排空在途回调，下次
（CapsLock/小键盘 \* 等白名单键物理直按存活保障——看门狗双定时器保险 + 失焦帧
（`8294566`）——会话窗工具栏/提示四项观感修复（工具栏默认/拖动态统一内容自适应
宽且可四向拖动、收缩把手点击展开 + 拖行移动〔悬停不展开〕、移除特殊键补偿按钮、
三流管线延迟埋点（视频/音频/输入三流，前 3 帧全量 + 之后 1 帧/秒节流，门控与
四流延迟埋点 + 跟手性修复（解码完成立即重绘画面，不再等固定刷新周期，远控
（`a276535`）——托盘图标自愈三件（任务栏资源管理器重启等导致托盘图标丢失时自动
重加〔TaskbarCreated 监听 + V4 重协商〕、隐藏入托盘时自检补回、创建有界重试
新增十项；诚实宣传口径 = **P2P 直连架构**（IPv6/IPv4 直连优先 + 服务器辅助打
洞）。

> **换包政策（本波 · 用户复测必读）**：**两端同版本同时替换** —— PROTOCOL_VERSION=3 不变
> v1.2 发起端直发（Offer）→ 新接收端 = 接收端开关裁决，ON = 正常接收 / OFF = Reject「传输
> 开关已关」（零内容字节）；新发起端 → 旧接收端 = 旧端丢弃 `TransferRequest` 单帧（未知
> op），会话存活，发送端等待超时/取消结算）（新旧混版复测无效；两端 banner 应同时为
> 两端在用 —— 本波一次换包覆盖全部十项修复，直接换到本包即可。**
>

> 双击新包时旧进程仍活 → 单实例守卫 748ms 即退 → 退旧后重拉仍是旧构建
> exe；banner 亲证是唯一实锤，**未亲证不得开始复测**）**：
> 1. **退旧**：托盘退出旧实例，确认进程已退出（任务管理器核 `KirinDesk.exe`
>    无残留）；
> 2. **覆盖**：拷贝新 `KirinDesk.exe` 覆盖旧文件——拷贝报「文件正在使用」
>    = 旧进程没退干净，回第 1 步；
> 3. **启动**：双击新包启动；
> 4. **亲证**：日志 grep `logger started`，`commit=d859f14` = 新包生效；
>    **非 d859f14 不得继续测**（客户端/服务端各自亲证）。
>
> 末出包，commit `cc5ae28`，24,101,888 B）及 `0a265abc…ff0d`（2026-09-09，
> 无退出入口），请勿再使用，以本包为准——用户实例重启后横幅应为
> `commit=d859f14`（banner 恒为构建时 HEAD）；更早的

### 安装

- **便携版**：直接双击 `KirinDesk.exe` 运行（需连同 `ffmpeg/bin/` 下共享库一起解压，
  否则编解码加载会失败）。
- **正式安装**：以管理员身份运行 `install.bat`（走 `install.nsi` 的 NSIS 流程，
  安装到 `%LOCALAPPDATA%\KirinDesk`），之后从开始菜单启动。

> 发布二进制不再入库跟踪，正式发布走 CI release job 的 artifacts + `checksums.txt`
> 校验（S-28 / F-33）。


KirinDesk 的 H.264/AV1 编解码**动态加载** FFmpeg 共享库（`avcodec-62.dll`、
`avutil-60.dll`、`swscale-9.dll` 等 7 个，LGPL/GPL v3）。运行目录缺库时
编解码不可用，但连接/键鼠/文件传输不受影响。

缺失即在后台自动下载安装——主源 BtbN/FFmpeg-Builds（ffmpeg.org 官方推荐
构建商，FFmpeg **8.1.x** 共享版），备源 gyan.dev 官方；下载后 sha256 对照
官方 `checksums.sha256`/侧车**强制校验（fail-closed，校验失败不安装半成品）**，
解压部署 7 个 DLL 到程序旁 `ffmpeg/bin/`。Dashboard 身份卡下方状态行实时
显示进度（下载中 x% / 校验中 / 解压中 / 完成——重启应用生效），失败时显示
原因并提供「重试」按钮。全程后台异步，不阻塞 UI；`--cli` 模式不自动联网。

`download-ffmpeg.bat`（逻辑与主程序内自动安装同源：双源 + sha256 校验 +
提取 7 个 DLL 到 `ffmpeg/bin/`），支持 `--target DIR` / `--url URL` /
`--force`，幂等。`install.bat` 检测到缺库也会提示引导。

> 注意：清华 TUNA 镜像当前**不提供** FFmpeg builds（2026-08-18 实测），故
> 默认走官方源；若日后 TUNA 提供可在源列表追加。

**完全离线方式**：携带完整 `ffmpeg/` 目录的发布包无需下载；或从任意渠道获取
FFmpeg 8.1.x shared 构建后，把 7 个 DLL 放入 `ffmpeg/bin/` 即可（文件名必须为
`avutil-60.dll` / `swresample-6.dll` / `swscale-9.dll`）。Linux/macOS 见
[`BUILD_UBUNTU.md`](BUILD_UBUNTU.md)。

### 主要功能

- **Dashboard** — 设备信息总览（Device ID、IPv6/IPv4、端口、白名单），允许受控/服务端
  开关，临时连接卡片
- **Domain** — DNS 服务商管理（20 家），凭据、测试连接、域名列表、记录 CRUD
  （A/AAAA/CNAME/MX/TXT/SRV/NS），DDNS 自动维护
- **Devices** — 已发现/连接设备（昵称、备注、手动排序）
- **Connect** — 连接远程设备：IPv6/IPv4+Port 或 Domain+Nickname+Challenge，实时连接日志
- **Tunnel** — 内网穿透（通用 TCP 反向代理）：Client/Server 配置、监听地址、Token、
  代理列表、GUI 一键启停（运行状态自动恢复）
- **Settings** — Device ID、Nickname、Challenge Code、DNS 服务商与凭据、白名单、连接模式、
  传输、语言（System/中文/English）、无人值守、更新

### 连接模式

**Domain 模式（推荐，严格）**：通过 DNS 自动发现端口 + IPv6 + 公钥，白名单强制。
```
Target:   my-pc.example.com
Nickname: my-device
Challenge: [交互式输入或 --challenge-stdin]
[Connect (DNS)]
```

**IP 模式**：直接指定 IPv6/IPv4 + 端口（首次连接需确认指纹）。
```
IPv6:     2001:db8::1
Nickname: my-device
[Connect (IP)]
```

### CLI 用法

```bash
KirinDesk.exe --cli setup            # 交互式配置向导
KirinDesk.exe --cli register my-pc   # 注册设备到 DNS
KirinDesk.exe --cli serve 59990       # 启动服务端
KirinDesk.exe --cli connect my-pc.example.com 22 mynick   # 连接
KirinDesk.exe --cli tunnel start     # 内网穿透客户端
KirinDesk.exe --cli status           # 系统状态
KirinDesk.exe --cli self-test        # 端到端自检
KirinDesk.exe --cli help             # 完整命令列表
```

完整 CLI（含 `dns`/`whitelist`/`temp-mode`/`unattended`/`known-hosts` 等子命令）见
根目录 Readme 的「CLI Commands」章节。

## 二、Ubuntu Server（无头 / 远程 Shell）

设备类型为 "server" 时自动走终端模式（PTY，替代 SSH）。从源码构建见
[`BUILD_UBUNTU.md`](BUILD_UBUNTU.md)。

```bash
# 服务端（无头 Ubuntu）
kirin_desk --cli shell 22
kirin_desk --cli serve 59990

# 客户端（任意平台）
kirin_desk --cli connect server.example.com 22 mynickname
```

`.deb` 包（含 systemd 服务）构建脚本在 `release/debian/`。

## 二·A、安卓控制端（APK）

本目录提供 `KirinDesk-Android-REL-A.apk`（**最新**，arm64-v8a，minSdk 26；
勿再使用）、
（手机↔PC 收发，口径见下「P3A：文件传输双向」））。历史阶段包 7 个
（P0/P1A/P1B/P1B2/P1B3/P2A/P2B）
已于 2026-09-06 由**用户本人删除**（用户原话：「输出文件夹的APK我删的太多了，
旧的有问题的版本我删除了。再输出包的话记得把apk也更新了，我到时候一起测」），
各阶段功能演进见下方历史节。**APK 命名口径**：P 号 = 功能阶段、尾字母 = 阶段
内修订（P1B→P1B2→P1B3、P2A→P2B 同口径；bugfix 波次续尾字母、新功能阶段进位）。

Kotlin
Compose 壳 + Rust 核心（`libkirin_desk_mobile.so` + FFmpeg
h264/hevc/opus/pcm_s16le 解码三件套）。功能：IP 直连 / ID 中继 / **域名**
三模式连接、远程画面渲染、触摸手势（单指=左键/长按拖动/双指=右键+滚轮/
三指=中键）、功能键条（粘滞 Shift/Ctrl/Alt/Win + Esc/Tab/方向键等 +
F1–F12）、软键盘文本注入（含中文/emoji/标点，KEYEVENTF_UNICODE）、音频
回放（Opus→AudioTrack）、TOFU 首连指纹确认、连接历史、会话页
sensorLandscape 横屏 + 沉浸式全屏（断开回连接页恢复竖屏）、设置页
（relay 三件套集中管理/分辨率档位/本机身份/语言/关于+日志导出）。

> **P1B2→P1B3 升级说明**：签名证书不变（同 RSA-4096 正式证书），可直接
> 覆盖安装。历史注记：P1B 包键鼠/触摸对桌面**完全无效**（客户端 wire


`KirinDesk-Android-REL-A.apk`（**最新**，20,367,277 B，sha256
`bd426be236299ccb0a06b17dde490901b2d69a21176b5c6b8493805eeeaf2c25`）——
**REL-A**）。功能面 = P3D 全量（控制端 + 被控端双向 + 文件传输双向），本波无
新功能。**`.so` 重建内容**：P3D 的 `.so` 建于 HEAD `b1caeca` 时点，不含
dirty_rects 兜底 `fps_governor.rs` + F4 软编兜底降采样 `encoder/factory.rs`）
——被控端画面同步跟手感随包升级（光标级 1fps→30fps、2 帧批窗 45%→0%）；
ui crate，均不进 mobile 编译面。包内 `libkirin_desk_mobile.so` 重建
（jniLibs 9,479,832 B，包内 strip 后 9,479,816 B），**26 JNI 导出 +
`JNI_OnLoad` = 27**（本波零新增导出，与 P3D 导出面一致；抽包符号核验通过）。
FFmpeg 三件套与 P3D **字节级一致**（抽包 hash 逐一相同：libavcodec
`c114af76…` / libavutil `86352dc9…` / libswscale `545386c2…`）。

- **门禁**：`apksigner verify -v`（build-tools 34.0.0）= **v2+v3 true**，
  证书 SHA-256 `eefb4167e84be7abd50dbc135fc8b5cff48dcb7154cb95904b14fa75b59045af`
  （CN=KirinDesk Release，RSA-4096，与 P1B 系同证）；sha256 侧车
  `KirinDesk-Android-REL-A.apk.sha256`（纯 hex 口径，同 P2B/P3A/P3B/P3C/P3D）。
- **用户复测关联项**：手机侧可感知变化 = 手机作**被控端**时画面同步迟滞修复
  随 `.so` 进包（迟滞复测以桌面双端为主口径，见桌面端「当前包」②③）；手机
  作控制端功能面零变化。ID 模式复测口径 = **双端同版本**（手机 REL-A + 桌面
  新包，双端 banner `commit=5fc10d8`）。

> **P3D→REL-A 升级说明**：签名证书不变（同 RSA-4096 正式证书，SHA-256
> `eefb4167…45af`），可直接覆盖安装无需卸载；本波仅 `.so` 重建
> 文件传输路径零改动（P3D 功能全保留）。


`KirinDesk-Android-P3D.apk`（20,367,280 B，sha256
`f2090e0015478fe805d4e0ec734cef4da85ff4766d28ee8546cb2946fa13371e`）——
被控端双向 + 文件传输双向），本波无新功能。**`.so` 重建内容**：P3C 的 `.so`
ID 中继隧道流接入 GUI 准入+会话链——双端 ID 模式复测需**双端同时换新包**：
服务端（桌面进程）不更新则隧道流仍走旧 headless 分发、临时码连接仍无画面）
生产行为零变化〕+ 卫生小项，mobile 侧零功能面变化）。包内
`libkirin_desk_mobile.so` 重建（jniLibs 9,480,032 B，包内 strip 后 9,480,016
B），**26 JNI 导出 + `JNI_OnLoad` = 27**（本波零新增导出，与 P3C 导出面一致；
抽包符号核验通过）。FFmpeg 三件套与 P3C **字节级一致**（抽包 hash 逐一相同：
libavcodec `c114af76…` / libavutil `86352dc9…` / libswscale `545386c2…`）。

- **门禁**：`apksigner verify -v`（build-tools 34.0.0）= **v2+v3 true**，
  证书 SHA-256 `eefb4167e84be7abd50dbc135fc8b5cff48dcb7154cb95904b14fa75b59045af`
  （CN=KirinDesk Release，RSA-4096，与 P1B 系同证）；sha256 侧车
  `KirinDesk-Android-P3D.apk.sha256`（纯 hex 口径，同 P2B/P3A/P3B/P3C）。
- **用户复测关联项**：手机侧功能面无直接可感知变化（本波改动集中于桌面
  服务端 ID 中继隧道流 GUI 准入链 + 主题渲染顺序）；手机包的作用 = 与桌面
  新包同基线 `.so`（`b1caeca`）。ID 模式复测口径见桌面端「当前包」两岗
  定案与用户复测清单（双端换新包、被控端桌面进程必须更新）。

> **P3C→P3D 升级说明**：签名证书不变（同 RSA-4096 正式证书，SHA-256
> `eefb4167…45af`），可直接覆盖安装无需卸载；本波仅 `.so` 重建
> 文件传输路径零改动（P3C 功能全保留）。


`KirinDesk-Android-P3C.apk`（20,367,281 B，sha256
`3a1a9e4d8cdaf78f7082924c947bf698331185799ed325e1e7cff20e5842bab8`）——
取 **P3C**）。功能面 = P3A 全量（控制端 + 被控端双向 + 文件传输双向），本波
无新功能。**`.so` 重建内容**：P3B 的 `.so` 建于 HEAD `b198ee0` 时点，不含
0x4E`〔KpAdd 正名〕+ `Key` 枚举尾部追加 `KpMultiply`=0x66/`KpDecimal`=0x67
〔Linux 0x37/0x53、macOS 0x4C/0x43 同步〕，wire 向后兼容——旧端遇新判别式仅
自动跟进、零独立实现）。包内 `libkirin_desk_mobile.so` 重建（jniLibs
9,479,888 B，包内 strip 后 9,479,872 B），**26 JNI 导出 + `JNI_OnLoad` = 27**
（本波零新增导出，与 P3B 导出面一致；抽包符号核验通过），**新格式验证：
`.so` 同串 0 命中——对照实证改动真实进包）**（strings 核验）。FFmpeg 三件套
与 P3B **字节级一致**（抽包 hash 逐一相同：libavcodec `c114af76…` /
libavutil `86352dc9…` / libswscale `545386c2…`）。

- **门禁**：`apksigner verify -v`（build-tools 34.0.0）= **v2+v3 true**，
  证书 SHA-256 `eefb4167e84be7abd50dbc135fc8b5cff48dcb7154cb95904b14fa75b59045af`
  （CN=KirinDesk Release，RSA-4096，与 P1B 系同证）；sha256 侧车
  `KirinDesk-Android-P3C.apk.sha256`（纯 hex 口径，同 P2B/P3A/P3B）。
- **用户复测关联项**：手机侧可感知变化 = ①空配置新机（或清空 `[device] id`）
  首次启动 → 自动派生 **10 位数字字母混合 ID（无 HD- 前缀，如 G7KJ2MNQ4X）**，
  旧设备 ID 原样不变 ②已保存设备备注名不再被连接成功冲掉（upsert 合并口径，
  不变）。

> **P3B→P3C 升级说明**：签名证书不变（同 RSA-4096 正式证书，SHA-256
> `eefb4167…45af`），可直接覆盖安装无需卸载；本波仅 `.so` 重建
> 文件传输路径零改动（P3A/P3B 功能全保留）。


`KirinDesk-Android-P3B.apk`（20,350,897 B，sha256
`be7e29fbf1ca7f8bcc48c7a146a0e40d025456eae2b011433ccbec3e37477296`）——
当前 HEAD `b198ee0` 重建（用户 2026-09-06 指令：旧 APK 已删、再出包须同步更新
之后取 **P3B**。功能面 = P3A 全量（控制端 + 被控端双向 + 文件传输双向），本波
`save_device_history` 保存侧显式写模式——ID 模式 `Id`、地址/域名 `Ip`；Kotlin
侧 `parseHistory` 经 org.json 宽松解析，新字段兼容）。包内
`libkirin_desk_mobile.so` 重建（jniLibs 9,467,256 B，包内 strip 后
9,467,240 B），**26 JNI 导出 + `JNI_OnLoad` = 27**（本波零新增导出，与 P3A
导出面一致；抽包符号核验通过）。FFmpeg 三件套与 P3A **字节级一致**（抽包
hash 逐一相同）。

- **门禁**：`apksigner verify -v`（build-tools 34.0.0）= **v2+v3 true**，
  证书 SHA-256 `eefb4167…45af`（CN=KirinDesk Release，RSA-4096，与 P1B 系
  同证）；sha256 侧车 `KirinDesk-Android-P3B.apk.sha256`（纯 hex 口径，同
  P2B/P3A）。
- **用户复测关联项**：手机侧可感知变化 = ①ID 模式审批超时的拒绝原因文案
  （`approval_timeout`）②设备连接历史新记录带连接模式（ID 模式记录不再与

> **P3A→P3B 升级说明**：签名证书不变（同 RSA-4096 正式证书，SHA-256
> `eefb4167…45af`），可直接覆盖安装无需卸载；本波仅 `.so` 重建
> 文件传输路径零改动（P3A 功能全保留）。


`KirinDesk-Android-P2A.apk`（**最新**，19,981,865 B，sha256
`7d6abf3474f69a1f0645e3d8d250da5468bf56d85909588959882aac887e8244`）——控制
端全功能之上，同包兼作**被控端**：手机屏幕经 libx264 编码（FFmpeg 静态链
入 `.so`）推流至桌面 KirinDesk 观看。包内 `libkirin_desk_mobile.so`
（9,146,528 B）为含 server 模块重建版：21 JNI 导出 + `JNI_OnLoad`（17 既有
+ 新增 `nativeServerStart/Stop/FeedFrame/Status` 4），抽包符号核验通过。

- **入口**：连接页连接按钮下方「共享此手机（被控模式）」→ 被控共享页
  （共享设置 = 昵称 + 挑战码 + 可选端口（0=临时端口）+ 可选 relay/ID 模式
  三件套；昵称/挑战码空 = fail-closed 校验不启动）→ 系统双授权
  （POST_NOTIFICATIONS → MediaProjection 截屏弹窗）→ 开始共享（前台服务）。
- **运行**：运行态（端口/观众数）+ 本机信息（设备 ID + 79 位指纹（控制端
  TOFU 核对位）+ 公钥（带外 pin 位））+ 1s 轮询运行态；推流 = ImageReader
  RGBA_8888×3 latest-wins 喂帧 → libx264 编码 → `EncodedWindow`；监听
  59990（与桌面同常量）；昵称门 + 挑战码（未配置 = fail-closed 全拒）；ID
  模式 relay 注册（`server_pubkey` 缺失 = 拒注册）。
- **停止**：页面停止 / 通知栏停止 / 系统撤销授权 / 启动失败 四路径收敛
  （释放虚拟显示 → 关 ImageReader → 停投影 → `nativeServerStop` 幂等停）。
- **一期不含**：音频捕获、输入注入（控制端键鼠入手机）= 二期（wire
  `InputEvent` tag 消费点已在服务端预留，届时零协议改动）。
- **Android 14 四小时上限（平台限制）**：Android 14（API 34+）设备对
  MediaProjection 会话有系统 4 小时时长上限，到时系统强停投影——本包收到
  系统回调后经既有停止路径收敛停止（共享页回到「未共享」），**不自动重
  连**；长时间使用请在上限后重进共享页重新发起（自动重连列遗留）。Android
  14 以下设备无此限制。
- **实机自测清单（一期口径，摘要）**：① P2A 覆盖安装 P1B3（同证书可直接
  升级）② 被控共享页双系统授权 → 「共享中 · 端口 59990 · 观众 0」③ 桌面
  客户端（IP 模式，昵称 + 挑战码一致）看到手机画面、画面正常 ④ 错昵称/错
  挑战码 → 拒连且原因可读 ⑤ 页面停止 → 服务销毁、观众下线 ⑥ 系统撤销
  授权 → 自动收敛停止 ⑦ ID 模式 relay 三件套齐全 → 「ID 模式：已注册」；
  `server_pubkey` 缺失则不注册 ⑧ Android 14 设备四小时上限行为（预期：
  收敛停止不崩溃，可重新发起）。

> **P1B3→P2A 升级说明**：签名证书不变（同 RSA-4096 正式证书，SHA-256
> `eefb4167…45af`），可直接覆盖安装无需卸载；本波只增被控端，控制端路径
> 零改动（P1B3 功能全保留）。


`KirinDesk-Android-P2B.apk`（**最新**，20,003,025 B，sha256
`8d5937c127c3739fd501c9823679b8b9efabd8f023f008a6ec49cb94844b49b2`）——
在 P2A 双向能力之上新增**输入注入（二期）**：桌面控制端键鼠操作手机。链
路 = wire `InputEvent` → 手机 Rust 服务端消费（一期预留的 tag 消费点，零
协议改动）→ JNI 上抛 → Kotlin `AccessibilityInputService` 系统手势注入
（`dispatchGesture`）/ 焦点输入框文本提交。包内 `libkirin_desk_mobile.so`
重建 = 9,142,672 B（P2A 9,146,528 B 增量重建），**22 JNI 导出 +
`JNI_OnLoad` = 23**（P2A 21+1 → 新增 `nativeSetInputCallbackEnabled`，
抽包符号核验通过）。

- **开启无障碍权限（前提，一次性）**：被控共享页 →「远程控制（键鼠）」区
  块 → 未启用时点「打开无障碍设置」→ 系统页面找到 **「KirinDesk 远端输
  入」**（英文系统：KirinDesk remote input）开启 → 返回共享页状态点自动回
  绿（1s 轮询探测 `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES`，无需
  手动刷新）。权限未开 = 输入事件在 Rust 侧静默丢弃（fail-soft，画面共享
  不受影响）。
- **支持的手势（鼠标）**：

  | 桌面操作 | 手机效果 |
  | --- | --- |
  | 左键点击（位移 <24px 且按住 <800ms） | 原地 tap（100ms 手势） |
  | 左键按下→移动→抬起 | 单指拖动（时长 = 实际按住间隔，最低 100ms） |
  | 左键按住 ≥800ms 不移动 | 长按（时长 = 实际按住间隔） |
  | 右键 | 系统返回（GLOBAL_ACTION_BACK） |
  | 中键 | 最近任务（GLOBAL_ACTION_RECENTS） |
  | 滚轮（±120/格，正 = 上） | 双指同向垂直滑动（位移 = \|delta\|×2px 封顶 600px，100–400ms） |
  | 仅移动（未按键） | 手机无悬停概念，仅更新触点缓存（供下次点击定位） |

- **支持的按键（键盘 MVP）**：
  - **字母/数字**（A–Z / 0–9，Shift = 大写）→ 追加到**当前焦点可编辑输入
    框**（主线程找焦点 + 系统文本提交）；
  - **Backspace** → 删除焦点输入框末尾一字符；
  - **整段文本**（含中文/emoji/标点）→ 整段追加到焦点输入框；
  - **特殊键**：Win+D → 主屏（HOME），Alt+Tab → 最近任务（RECENTS），
    Win+L → 锁屏，Esc → 返回（BACK）。
  - **暂不注入（MVP 遗留）**：Enter（提交语义未定）/ 方向键 / F 键 / 修饰
    组合（Ctrl/Alt/Super 组合，如 Ctrl+C）/ 滚轮持续手势（当前每格一次滑
    动）。
- **坐标口径**：桌面端发归一化坐标（0.0–1.0），手机端按**屏幕真实尺寸**
  换算；`baseW == 0`（服务端尚未推流）时左键安全忽略，右/中键/滚轮照常处
  理（不依赖坐标）。
- **隐私口径（无障碍服务声明）**：仅 `canPerformGestures` +
  `canRetrieveWindowContent`（焦点文本提交所需）；**不监听任何无障碍事
  件**（`onAccessibilityEvent` 空实现零消费）、不读取屏幕内容，只注入手
  势并向焦点输入框提交远端文本。
- **Android 14 四小时上限（沿用 P2A）**：平台限制（API 34+），到点系统强
  停 → 收敛停止、不自动重连；输入注入与画面共享同一前台服务，无额外限
  制，上限后重进共享页即恢复（含键鼠）。
- **实机联调矩阵（待用户执行）**：tap / 拖动 / 长按 / 右键 / 中键 / 滚轮 /
  字母数字 / Shift 大写 / 中文文本 / Backspace / Esc / Win+D / Alt+Tab /
  Win+L × 各 ROM `dispatchGesture` 识别差异 + 焦点可编辑输入框覆盖（微信
  输入框/备忘录/浏览器地址栏等）。

> **P2A→P2B 升级说明**：签名证书不变（同 RSA-4096 正式证书，SHA-256
> `eefb4167…45af`），可直接覆盖安装无需卸载；本波只增输入注入（被控端）+
> `.so` 重建，控制端路径零改动（P1B3/P2A 功能全保留）。


`KirinDesk-Android-P3A.apk`（**最新**，20,285,354 B，sha256
`31346c54b98425623ec74466850484b578af1fca0180319187ff58411f9e2363`）——
在 P2B 双向能力之上新增**文件传输双向**：手机→PC 发送 + PC→手机接收，
复用既有加密会话通道（64KiB 大帧，同桌面口径）。包内
`libkirin_desk_mobile.so` 重建（jniLibs 9,402,256 B，包内 strip 后
9,402,240 B），**26 JNI 导出 + `JNI_OnLoad` = 27**（= 既有 22 + 4 新
`nativeFileTransferStart`/`nativeFileOfferRespond`/`nativeFileTransferCancel`/
`nativeGetFileTransfers`，纯拉模型 0 回调；抽包符号核验通过）。

- **手机→PC 发送（控制端）**：会话页「发送文件」→ 系统文件选择器
  （SAF）→ 暂存（流式拷贝至应用私有 `filesDir/upload_tmp/`，4GiB 上限
  ——超限中英人话拒绝，fail-closed）→ 发送（状态 `waiting_accept` →
  `sending` → `completed`/`failed`/`cancelled`）→ 底部「文件 (n)」面板
  实时进度（进度条 + 百分比 + 速度 + 8 态人话），活跃条目可取消（无
  `.part` 残留），完成条目可分享。
- **PC→手机 接收（被控端）**：桌面控制端发文件 → 手机 Offer 弹窗
  （文件名 + 大小 + 来源观众标注；接受 / 关闭 = 拒绝）→ 接受后落盘
  `Android/data/com.kirindesk.mobile/files/Kirindesk/`（应用私有外部
  目录，免存储权限）→ 进度 → 完成通知带分享 action（系统分享面板，免
  新权限）；拒绝 → 控制端显示 failed declined，手机无落盘。
- **取消 / 进度 / 通知 / 中英**：Kotlin 1s 纯拉轮询（4 JNI 导出，零
  Rust→Kotlin 回调）；取消 = 本地即时（`.part` 删除、双端断点记录清
  理）；终态系统通知（独立 `file_transfer` 渠道，同传输 id 不重发）；
  尺寸/速度人话格式化（1024 进制 1 位小数）；界面文案 `ft_*` 46 键
  中英成对。
- **权限**：**零新增权限**（POST_NOTIFICATIONS 既有声明 + 既有链式
  请求流泛化复用；API33+（Android 13+）设备首次终态通知时按既有流程
  弹系统请求，拒绝 → 通知不可见、传输功能不受影响）。
- **实机联调清单（待用户执行）**：① PC→手机接收全流程（Offer 弹窗接受
  → 进度 → 完成通知带分享 → 落盘文件字节数/SHA-256 与源文件比对）② 拒
  绝路径（控制端状态 failed declined，手机侧无落盘）③ 手机→PC 发送
  （SAF 选择 → 暂存 → waiting_accept → sending → completed）④ 取消
  （传输中取消，双端 `.part` 无残留、断点记录清理）⑤ >4GiB 文件人话
  拒绝（中/英两 locale 各验一次）⑥ 断连清理（进行中暂存清空、无僵尸
  通知）⑦ 双观众（两台 PC 同控一部手机）各自独立 tid、文件列表不串
  ⑧ API33+（Android 13+）首次终态弹 POST_NOTIFICATIONS 请求（拒绝不
  崩）。

> **P2B→P3A 升级说明**：签名证书不变（同 RSA-4096 正式证书，SHA-256
> `eefb4167…45af`），可直接覆盖安装无需卸载；本波只增文件传输双向 +
> `.so` 重建，控制端 / 输入注入 / 画面共享路径零改动（P1B3/P2A/P2B 功
> 能全保留）。


连接页第三 Tab「域名」，字段 = **设备域名**（完整 `device.example.com`）+
**被控端昵称** + 挑战码（凭据口径对齐桌面域名模式）。被控端需以域名模式
发布 SRV/TXT/A|AAAA 三件套记录；手机侧发现与解析**仅走加密 DNS
（DoH/DoT，默认 Cloudflare/Google/阿里端点）**，绝不回退明文（fail-closed）。
信任锚 = TXT Ed25519 公钥（TOFU 首连确认 + Exact pin）；known_hosts 与
连接历史以设备域名为键。解析失败给可读中英文案（域名不存在/无记录/无 SRV/
无 TXT 公钥/超时/加密 DNS 不可用）。


- **中继服务器（ID 模式）**：server_addr / token / server_pubkey 三件，
  与连接页折叠区同一存储（单一数据源）；
- **连接偏好**：分辨率上报档位 720p（默认）/1080p/原生——下次连接生效
  （驱动握手 `requested_max_width`；服务端高负载可能降档）；
- **本机信息**：设备 ID + 79 位指纹；**语言**：随系统/中文/English；
- **关于**：版本信息 + **日志导出**（`kirin_mobile.log` 经系统分享面板
  分发——保存到文件/云端/聊天工具均可，正式签名包无需 run-as）。


IP 模式必填三项：**服务器地址:端口 + 被控端昵称 + 挑战码**。其中「被控端
昵称」是握手凭据之一——**必须与被控端桌面端 Dashboard 配置的昵称完全一致**
（大小写敏感，字面比对）；填错昵称/挑战码会被拒连（服务端结构化拒绝码，
客户端显示可读原因，不再是无提示的 `early eof`）。

### 签名口径

- **P1B 起正式签名**：RSA-4096 自签证书（CN=KirinDesk Release），v2+v3
  scheme；证书 SHA-256 指纹
  `EE:FB:41:67:E8:4B:E7:AB:D5:0D:BC:13:5F:C8:B5:CF:F4:8D:CB:71:54:CB:95:90:4B:14:FA:75:B5:90:45:AF`。
  keystore 存放于仓库外 `E:\projects_rd\secrets\`（不入库），构建时经环境变量
  `KIRIN_STORE_FILE/KIRIN_STORE_PASSWORD/KIRIN_KEY_ALIAS/KIRIN_KEY_PASSWORD`
  注入；**缺失任意一项自动回退 debug 签名**（构建永不因口令缺失而断）。
- 早期 P0/P1A 包为 debug 签名，与 P1B 正式签名**不共存安装**（签名不同需
  先卸载旧包）。

### 手机日志获取（问题排查）

应用日志写入应用私有目录 `files/kirin_mobile.log`：

```bash
# debug 签名包（P0/P1A，或口令缺失回退构建）：
adb shell run-as com.kirindesk.mobile cat files/kirin_mobile.log

# 正式签名包（P1B+，非 debuggable）——P1B3 起首选：设置页「关于 → 导出
# 日志」直接经系统分享面板分发（保存到文件/云端/聊天工具均可）；或
# Android Studio → Device Explorer →
# /data/data/com.kirindesk.mobile/files/kirin_mobile.log 拉取。
```



## 三、内网穿透服务端（relay-server）

见 [`server/`](server/) —— Windows 用本目录 `relay-server.exe`；Linux 推荐 Docker 部署
（`server/docker/`）或原生编译（`server/BUILD_LINUX.md`，附 systemd 示例）。

```bash
relay-server --bind-port 7000 --token <高熵token≥32字节> --port-range 60000-61000
```

完整参数与安全建议见 [`server/README.md`](server/README.md)。

## 四、安全要点

- **域名 + 设备 ID 白名单（严格模式）**：任一命中即放行；临时模式签发 10 位一次性
  挑战码并跳过白名单（5 分钟窗口），应急直达
- **挑战码 + Ed25519 签名** 双重认证
- **AEAD 端到端加密**（AES-256-GCM / ChaCha20-Poly1305），每次会话独立派生密钥，前向安全
- **握手 pin 强制比对**（已删除"空串跳过"兼容路径）
  （Windows DPAPI / macOS Keychain / `KIRIN_CONFIG_KEY`；无密钥源时 fail-open 明文 + 警告）
- **审计日志**：30+ 事件，连接速率限制，SSH 式 known-hosts 指纹确认


Windows 落盘后 best-effort DACL 收紧（移除 ACL 继承、仅保留当前用户 +
SYSTEM 完全控制；失败仅 WARN 不致命）；Unix 维持 `0600`/父目录 `0700`。
全量清单（均位于用户目录 `~/.kirin_desk` 内）：

| 文件 | 内容面 | 权限预期 |
|---|---|---|
| `identity.masterkey` | 身份主钥（明文密钥面） | 仅当前用户+SYSTEM；Unix 0600 |
| identity blob（加密身份） | 已加密身份材料 | 同上 |
| `known_hosts` | 对端公钥 TOFU 面 | 同上 |
| 设备存储（nodes/设备表） | 昵称、地址、指纹面 | 同上 |
| 临时挑战码状态 | 盐 hash 后挑战码 | 同上（敏感面已降级） |
| relay 私钥（控制端侧配置引用面） | 服务器私钥 `.pem` | 同上（S-07 强约束） |

**备份红线**：备份/克隆 `~/.kirin_desk` 目录时必须保持目录私有
（Unix `chmod 700`；Windows 不要拷入 `Users` 可读的共享路径）——备份介质
= 私钥与 token 同保密级。程序只收紧程序写入的文件权限位，不改动既有
文件内容；手工备份外的旧副本权限不受程序管辖，需人工自查。

## 五、配置与日志

- 配置文件：`%USERPROFILE%\.kirin_desk\default.toml`（结构见根目录 Readme「Configuration」）
- 日志：每日轮转 `~/.kirin_desk/logs/kirindesk-YYYY-MM-DD.log`，自动清理

## 发布流程

见 [`PUBLISH.md`](PUBLISH.md) —— 一键发布（`publish.sh` + CI 三平台打包）/
手动发布流程，以及「Settings → 检查更新」链路的资产命名与 `.sha256` 侧车规范。

## License

Apache 2.0（KirinDesk 核心）+ LGPL（FFmpeg 库，动态加载）
