# KirinDesk v0.1.0

P2P Remote Desktop - IPv6 + GoDaddy DNS + Zero Trust

> 💜 **Made with love by an individual developer — a non-profit, open-source project with no monetization of any kind. No ads, no tracking, no subscriptions. Free, forever.**

## Windows Desktop App

Native Windows GUI (egui) with CLI fallback.

### Install

1. Extract all files
2. Double-click install.bat (Run as Administrator)
3. Launch KirinDesk from Start Menu

### Features

- Dashboard - device status, IPv6, API config
- Connect - Domain mode or IP mode
- Settings - API keys, nickname, challenge, domain whitelist
- Auto-detect device type (desktop/server)
- Auto-rotating logs - daily files in `%USERPROFILE%\.kirin_desk\logs\`, auto-cleanup after 7 days

### Connect Modes

**Domain Mode (strict):** Only domain connections allowed, whitelist enforced.
```
Target:   my-pc.example.com
Nickname: my-device
Challenge: [optional]
[Connect (DNS)]
```

**IP Mode (flexible):** Both domain and IP connections.
```
IPv6:     2001:db8::1
Port:     3389
Nickname: my-device
[Connect (IP)]
```

### Remote Shell (Ubuntu Server)

When device_type is "server", auto-switches to terminal mode:

```bash
# Server (headless Ubuntu)
kirin_desk --cli shell 22

# Client (any platform)
kirin_desk --cli connect server.example.com 22 mynickname
```

### CLI Mode

```bash
kirin_desk setup          # Interactive config wizard
kirin_desk config         # Show config
kirin_desk register my-pc 3389  # Register with GoDaddy DNS
kirin_desk discover my-pc       # Discover device
kirin_desk connect target.com 3389 mynick  # Connect
kirin_desk shell 22       # Remote shell server
kirin_desk serve 3389     # Generic server
kirin_desk status         # System status
kirin_desk help           # Show help
```

### Security

- Domain whitelist: only allowed domains can connect
- Nickname + challenge code authentication
- AES-256-GCM AEAD encrypted channel
- X25519 ECDH forward secrecy
- Ed25519 identity signing

### Config

`%USERPROFILE%\.kirin_desk\default.toml`

### Tests

```bash
cargo test
# 81 tests passing
```
