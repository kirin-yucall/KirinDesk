# Changelog

本项目变更日志，格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本语义遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。
里程碑（M1–M15）与任务状态见 `task_docs/M0-完整路线图M1-M15.md`。

## [Unreleased]

### Added
- M8-T018 多显示器查看模式（客户端查看 + 服务端捕获热切换）：
  - 协议：`ControlMessage::DisplayListReq / DisplayListResp / DisplaySelect / DisplaySelectNack` + `proto::DisplayInfo`（bincode，复用可靠流/控制通道）；`PacketKind::Control` → `ChannelTag::Control`（0x04，与既有控制/心跳通道对齐）
  - 服务端：`factory::enumerate_monitors()`（Windows `Monitor::from_index` 体系 / macOS zed-scap；空时兜底 1 个默认屏）；`ScreenCaptureSource::wait_for_frame_timeout`（静默屏幕定期醒来处理切换，Windows `recv_timeout` 实现）；`switch_monitor` 会话内热切换（同索引 no-op）→ 下一窗口强制 IDR + 重推 `VideoFormat`
  - 客户端：连接建立自动请求显示器列表（CLI-MON-001）；连接窗口工具栏「显示器」下拉（`名称 分辨率 [主屏]`）+ ⟳ 手动刷新，切换即发 `DisplaySelect`，Nack 状态栏 ⛔ 提示；状态栏显示当前屏名称/分辨率徽标
  - 坐标映射跟随（CLI-MON-010 / SRV-MON-010）：客户端归一化基数 = 当前所选显示器分辨率（随窗口 base_w/base_h 更新）；服务端 `InputInjector::set_resolution` 切换后同步换算基准，按屏分辨率回归测试（屏0/屏1 全范围）
  - 单测：DisplayList 序列化往返、越界索引 Nack、wire kind/tag 映射、坐标换算边界；需求文档 `task_docs/共享层/M8-T018_多显示器查看模式.md`
- M13-T006 文件传输（双向 File Transfer，复用 SecureChannel AEAD 加密通道）：
  - 帧协议 `ChannelTag::FileTransfer = 0x06` + `PacketKind::FileTransfer`（64 KiB 大帧，避开 1200B 小分片路径；`SecureChannelSender::send_big_packet`）
  - 滑窗发送（窗口 64 块）+ 累积 Ack/Nack + 块超时重传 + 空闲死链判定；接收侧分片重组 `.part` → 整体 SHA-256 校验 → 原子 rename，取消回滚无残留
  - 断点续传：`transfers_client/server.json` 元数据持久化，重连后双方进度协商续传（重复块不落盘）
  - 会话内并发任务队列 ≤3（FIFO）；路径消毒（绝对路径/`..`/盘符/NUL/非法字符全拒）、单文件大小限制（默认 4 GiB）、transfer_id 去重、同名自动改名
  - UI：连接窗口「📁」文件面板（任务列表/进度条/速度/取消/暂停/恢复/在文件夹中显示）+ 拖拽发送；服务端 Dashboard 文件面板（推送/接收）+ 接收完成弹窗
  - CLI：`send <path> <host> [port] [nickname]` / `recv <host> [port] [nickname]`；`serve` 无头静默接收；`self-test` 含文件传输往返自测
  - 配置段 `[file_transfer]`（download_dir / max_file_size）；全链路测试 `core/tests/file_transfer_e2e.rs`
- M13-T005 无人值守模式（Unattended Mode）：
  - 用户级开机自启（Windows HKCU Run / Linux XDG autostart / macOS LaunchAgent，无需管理员），`--autostart` 参数启动，最小化窗口
  - 无人值守开启后应用启动自动开启服务端；known_clients/白名单命中自动放行（远程桌面远控 / 远程 Shell PTY 单端口会话分发），未知设备自动拒绝 + 审计，temp-mode 旁路禁用
  - Settings 页「Unattended Mode」卡片（总开关 + 自启/自动开服务端子选项 + 注册状态）+ Dashboard 徽标
  - CLI：`unattended <on|off|status>`、`autostart <enable|disable|status>`、`serve [port] --unattended`
  - 配置段 `[unattended]`（enabled / auto_start_on_boot / auto_start_server），需求文档 `task_docs/共享层/M13-T005_无人值守模式.md`
- M14 发布与打包：
  - GitHub Actions CI：三平台 build/test + release 打包（Windows zip / Ubuntu deb / macOS dmg）自动上传
  - Windows NSIS 安装包（`release/install.nsi`）+ 改进的 `release/install.bat`（含 FFmpeg DLL、身份/日志目录、快捷方式）
  - Ubuntu .deb 包（`release/debian/`，含 systemd 服务 `kirindesk.service`）
  - macOS 通用二进制 .app + .dmg 打包脚本（`release/macos/build_universal.sh` / `create_dmg.sh`）
  - 自动更新：Settings Update 面板（检查 / 下载进度 / 安装重启）+ 每周后台检查（updater 按平台选 asset）
  - 版本发布脚本 `release/publish.sh`（tag + changelog + gh release create）

## [v0.1.0] - 2026-07-31

### Added
- M1：工作区 7 crates 骨架、配置加载/保存（`~/.kirin_desk`）、日志系统（文件+控制台双输出、旧日志清理）
- M2：零信任加密引擎（Ed25519 身份、X25519 ECDH、AES-256-GCM、ChaCha20-Poly1305）
- M3：DNS 服务注册与发现（GoDaddy SRV/AAAA/TXT CRUD、三路并行发现、心跳保活、本地缓存）
- M4：TCP 连接层（IPv6 双栈、全挑战-响应握手、SecureChannel AEAD、指数退避重连）
- M5：媒体基础（屏幕捕获、JPEG 编解码、远程输入事件定义）*
- M6：egui GUI（Dashboard/Devices/Connect/Settings 四标签页）+ CLI 8 子命令、身份加载、连接窗口、审批弹窗、实时日志
- M7：测试体系（81 单元测试、`--cli self-test` 端到端自测）
- M8：QUIC 窗口式 H.264 媒体传输（FFmpeg libavcodec 编解码、WGC 捕获、自适应反馈闭环、解码层 P2A–P2D）
- M9：FFmpeg 硬件编码（nvenc/amf/qsv/vaapi/videotoolbox 经 FFmpeg 统一栈）
- M10：Domain 模式 DNS 发现连接、设备列表持久化（devices.json）、Devices 页增强
- M11：远程 Shell（PTY 模式）、终端窗口 UI、CLI shell
- M12：Linux 支持（pipewire 捕获、VAAPI、uinput 输入）*
- M12-MAC：macOS 支持（zed-scap 捕获、CGEvent 输入、CoreAudio 环回、VideoToolbox、Keychain 身份存储）
- M13：音频捕获/播放、剪贴板共享（arboard）*

\* 部分功能为骨架/占位，细节见对应设计文档。

[Unreleased]: https://github.com/kirin-yucall/kirin_desk/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/kirin-yucall/kirin_desk/releases/tag/v0.1.0
