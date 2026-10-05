# KirinDesk - Ubuntu Build Guide

## Requirements

- Rust 1.70+
- System packages:

```bash
sudo apt update
sudo apt install build-essential libssl-dev pkg-config \
    libx11-dev libxcb-shape0-dev libxcb-xfixes0-dev \
    libxkbcommon-dev libwayland-dev libpipewire-0.3-dev \
    libpulse-dev libudev-dev ffmpeg libavcodec-dev
```

> 说明（Linux 侧）：
> - `libpipewire-0.3-dev`：**必需**——屏幕捕获（screen-cast portal 帧流）与
>   音频捕获/播放（`pw_stream`）均经 PipeWire；pipewire crate（=0.8.0）
>   编译期经 system-deps 探测它。
> - `libpulse-dev`：可选（仅 PulseAudio 兼容层/其它构建需要；本仓库音频
>   走 PipeWire，不直接链接 libpulse）。
> - 运行时还需要：`libpipewire-0.3-0`、`xdg-desktop-portal`（+ 桌面门户
>   后端，如 xdg-desktop-portal-gnome/kde）——屏幕捕获经
>   `org.freedesktop.portal.ScreenCast` 授权；无头服务器不捕获屏幕，无需
>   门户。
> - D-Bus 客户端为纯 Rust（zbus），无额外系统包。

## 获取 FFmpeg 运行库（）

KirinDesk 的 H.264/AV1 编解码**动态加载** FFmpeg 共享库（libavcodec.so.62 /
libavutil.so.60 / libswscale.so.9 等 7 个）。**注意**：Ubuntu 24.04 发行版自带的
FFmpeg 6（libavcodec.so.60）与 KirinDesk 偏移快照（avcodec **major=62**）不兼容，
加载会被拒绝——需要 FFmpeg 8.x 的 shared 构建。

**在线方式（推荐）**：
```bash
bash release/download-ffmpeg.sh            # Linux 分支：下载 BtbN linux64-gpl-shared
                                           # tar.xz，提取 7 个 .so 到 release/ffmpeg/
```
随后把 `release/ffmpeg/` 放到程序可搜索路径之一：`{exe_dir}/ffmpeg/`（便携布局，
与 Windows 同名）、`{exe_dir}/../lib/kirindesk/ffmpeg/`（deb 打包布局），或
`/usr/lib/x86_64-linux-gnu/`（系统路径）。脚本幂等、sha256 校验、支持
`--target`/`--url`/`--force`；无遥测、仅显式触发联网。

**离线方式**：携带 `release/ffmpeg/`（7 个 `.so.62/.60/.11/.9/.6`）的发布包无需
下载；或从任何渠道获取 FFmpeg 8.x shared 构建后手动放置（文件名为
`libavcodec.so.62` / `libavdevice.so.62` / `libavfilter.so.11` /
`libavformat.so.62` / `libavutil.so.60` / `libswresample.so.6` / `libswscale.so.9`）。
macOS 请用 Homebrew（`brew install ffmpeg`，提供 libavcodec.62.dylib 等）。

## Build

```bash
git clone <repo>
cd KirinDesk
export CARGO_TARGET_DIR=/tmp/ktarget
# --jobs 8: 线程数上限(硬性约束),禁止满线程打包——大小核设备线程过多会死机
cargo build --release -p kirin-desk-ui --jobs 8
./target/release/kirin-desk-ui --cli help
```

## Usage

### Desktop Mode (GUI)
```bash
# On Ubuntu desktop with display
./target/release/kirin-desk-ui
```

### Config Wizard
```bash
./target/release/kirin-desk-ui --cli setup
# Fill in: Device ID, Nickname, Challenge, API keys, Domain whitelist
```

### Register Device
```bash
# Register as desktop
./target/release/kirin-desk-ui --cli register my-pc 3389

# Register as headless server (edit TXT to add "type":"server")
./target/release/kirin-desk-ui --cli register my-server 22
```

### Remote Shell Server (Headless Ubuntu)
```bash
./target/release/kirin-desk-ui --cli shell 22
```

### Connect from Anywhere
```bash
# Domain mode (recommended)
./target/release/kirin-desk-ui --cli connect my-pc.example.com 3389 mynickname

# IP mode
./target/release/kirin-desk-ui --cli connect 2001:db8::1 3389 mynickname

# Connect to headless server (auto shell mode when type=server)
./target/release/kirin-desk-ui --cli connect myserver.example.com 22 mynickname
```

## Tests

```bash
cargo test
# 81 tests passing
```

## Config

`~/.config/kirin_desk/default.toml`
