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

## Build

```bash
git clone <repo>
cd ip6desk
export CARGO_TARGET_DIR=/tmp/ktarget
cargo build --release -p kirin-desk-ui
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
