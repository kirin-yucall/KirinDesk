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

> 说明（R-14，M12-T001/T003/M13-T001 Linux 侧）：
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
