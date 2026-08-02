# 🦄 KirinDesk — The P2P Remote Desktop Built to Retire SSH

**Fully Decentralized · Pure P2P Direct Connect · Zero Relay Servers · Zero TLS Certificates · End-to-End Encrypted**

> **中文版:** [Readme_CN.md](Readme_CN.md) ｜ **English:** This file

---

## 💜 Made with Love — A Non-Profit Passion Project

KirinDesk is built and maintained by an individual developer in their spare time, purely out of love for the craft. **It is a 100% non-profit project with no monetization of any kind:**

- **No fees** — no subscriptions, no paid tiers, no "Pro" version
- **No ads, no tracking, no telemetry** — no data collection, no analytics
- **No account system, no vendor lock-in** — your devices belong entirely to you
- **Fully open source** — free to use, study, modify, and share under the [License](#license)

The only "currency" that keeps this project running is ❤️. If KirinDesk helps you, the best way to give back is a star ⭐, a bug report, or passing it on to someone who needs it.

## The Vision

Every device should be able to reach every other device directly — securely, privately, with no third party standing between them. That simple conviction is the entire reason KirinDesk exists. We believe the remote-control experience of the future does not route through corporate cloud farms, does not beg a relay server to stay online, and does not lean on an obscure chain of certificates. It is two devices shaking hands across the open Internet and speaking only to each other.

KirinDesk turns that belief into working software by standing on three pillars that are anything but exotic: **IPv6** gives every device a globally reachable address; **the DNS system** becomes a decentralized, censorship-resistant bulletin board where devices publish where they are and who they are; and **modern public-key cryptography** replaces the entire legacy TLS certificate apparatus with something simpler, stronger, and truly zero-trust. No relay servers. No STUN/TURN. No port forwarding. No certificate authorities. Just devices, DNS, and math.

## Why the World Needs KirinDesk

### SSH: a quarter-century of brute force and patchwork defense

For over 25 years, SSH has been the workhorse of remote administration — and for over 25 years, port 22 has been scanned by every botnet on the planet. Password brute-force attacks never stop; your only defenses are patchwork like fail2ban, nonstandard ports that amount to security by obscurity, and constant vigilance. SSH was designed in an era when the Internet was smaller and more trusting. It was never designed to face the always-on, globally scanned attack surface of today's world.

### RDP / VNC: centralized authentication, 24/7 exposure

RDP and VNC carry their own burdens. Authentication leans on centralized directory services, the control port sits exposed around the clock, and traffic frequently lacks true end-to-end encryption. They are LAN-era tools asked to do an Internet-era job — and it shows.

### Commercial remote control: your screen rides someone else's highway

TeamViewer, AnyDesk, and their peers route every pixel of your screen through vendor-owned relay infrastructure. That means a third party always can — or at least could — see what you see. It means a vendor outage becomes your outage. And it means the privacy of your remote session depends on someone else's promises.

**KirinDesk was built to retire all three.**

## The KirinDesk Answer: Pure P2P, Zero Middlemen

When you connect with KirinDesk, your device reaches out directly to the target device — not to a relay, not through a broker. The two endpoints negotiate a mutually authenticated, end-to-end encrypted tunnel and talk to each other for the life of the session. Nothing in between can read, block, or log your traffic, because nothing is in between.

```
Legacy approach                               KirinDesk
────────────────                               ─────────
device ──▶ central server ──▶ device           device ──▶ device
          (relay / outage /                    (direct / zero
           sniffable)                          middlemen)
```

With IPv6, every device is globally reachable — no NAT traversal tricks, no STUN/TURN servers, no manual port forwarding on routers that refuse to cooperate. The address is just there, and KirinDesk connects to it. It is the closest thing the Internet has to the way networking was always meant to work.

## Security Reimagined: Zero Trust, Zero Certificates

KirinDesk throws away the legacy TLS certificate system — no certificate authorities, no certificate chains, no expiry ceremonies, no PKI infrastructure to maintain. Instead, every device mints its own cryptographic identity at first run:

- An **Ed25519 long-term identity keypair** is generated on the device. The private key never leaves it (encrypted at rest), while the public key is published to the device's DNS TXT record — an unforgeable calling card.
- When two devices meet, they perform a **mutual authentication handshake**: challenge-response signed with Ed25519, key agreement via **X25519 ECDH**, and a session key derived with HKDF.
- Every byte of the session is sealed with **AEAD encryption (AES-256-GCM / ChaCha20-Poly1305)** — and every session derives a fresh key, giving the channel **perfect forward secrecy**. Even if a long-term key is ever compromised, past sessions stay sealed forever.

The result is a security model with a far smaller attack surface than the status quo: no passwords to brute-force over the wire, no certificates to forge, no trust anchor you didn't personally mint. The math does the talking.

## Domain Whitelists: Access Control That Follows Devices, Not Addresses

Access control is where KirinDesk makes one of its most elegant — and most practical — departures from convention: **whitelists are expressed in domain names, not IP addresses.**

IP-address whitelists are a maintenance nightmare. Addresses change under you — DHCP renumbering, IPv6 privacy extensions, roaming laptops, cloud instances recreated overnight. A whitelist entry that works today silently fails tomorrow, and the usual "fix" is loosening the list until it stops meaning anything. IP addresses are also meaningless to humans: a wall of `2001:db8::f3a2`-looking strings tells you nothing about who is actually allowed in.

Domain whitelists fix every one of those problems at once:

- **They are human-readable.** `alice.example.com` says exactly who is welcome — no lookup table required.
- **They survive address changes.** A device's IPv6 address may churn, but its domain name is stable by design. The whitelist keeps working while the address changes underneath it.
- **They are cryptographically verifiable.** DNS isn't just a phone book here — it is the identity registry. The whitelist entry, the published public key, and the resolved address all come from the same authoritative source, so a domain name is a real identity claim, not a guess.
- **They are enforceable with zero exposure.** In strict mode, the server simply refuses any connection that does not originate from a whitelisted domain — your access list is a list of trusted identities, not a list of addresses that happen to be correct today.

That is the kind of design that feels obvious in hindsight: move the whitelist from the layer that changes (IP) to the layer that doesn't (names), and convenience and security improve at once.

## A True SSH Replacement

KirinDesk's Server mode gives headless machines — Ubuntu servers, VPSes, cloud instances — a remote administration channel that makes legacy SSH look positively medieval. No fixed port to scan, no password to brute-force: connections are gated by the domain whitelist and proven by a challenge code plus an Ed25519 signature. Traffic rides the same end-to-end encrypted, forward-secret tunnel as the remote desktop. And because the device publishes its own DNS records, even a machine behind a brand-new IPv6 address is found by name, instantly. The remote shell runs over a PTY on the encrypted channel — the terminal you love, with security you never had.

## At a Glance: KirinDesk vs. The Old Guard

| Aspect | Traditional SSH | RDP / VNC | Commercial Remote Desktop | **KirinDesk** |
|--------|-----------------|-----------|---------------------------|---------------|
| Connectivity | Direct port | Direct port | Central server relay | **Pure P2P direct** |
| Relay server | None | None | Required | **None at all** |
| Port exposure | 22, globally scanned | Scannable | None | **No fixed port exposure** |
| Authentication | Password / key | Password / cert | Vendor account | Challenge code + Ed25519 signature |
| Encryption | Transport-level | Weak / none | Vendor-dependent | **End-to-end AEAD, forward-secret** |
| Access control | — | — | Vendor accounts | **Domain whitelist (strict mode)** |
| Privacy | — | — | Traffic via third party | **Zero middlemen** |
| Decentralized | ✗ | ✗ | ✗ | **✓ Fully decentralized** |

## Core Features

- **Pure P2P over IPv6** — direct device-to-device tunnels; no relay, no STUN/TURN, no port forwarding
- **Zero-trust cryptography** — Ed25519 identities, X25519 ECDH, AEAD (AES-256-GCM / ChaCha20-Poly1305), per-session keys with perfect forward secrecy
- **DNS as the decentralized registry** — devices self-register and self-discover via GoDaddy DNS (SRV + AAAA + TXT queried in parallel), with heartbeat keep-alive
- **Domain whitelist (strict mode)** — only whitelisted domains may initiate connections
- **Dual connection modes** — domain mode (DNS discovery, recommended) or direct IPv6 mode
- **Remote desktop** — FFmpeg libavcodec H.264/H.265 encode/decode with hardware acceleration (NVENC/AMF/QSV/VAAPI/libx264), QSV hardware decode with software fallback
- **Adaptive media pipeline** — 70 ms windowed delivery over QUIC (datagram + reliable-stream transport, loss detection) with a feedback loop that adjusts encoding in real time
- **Remote shell (PTY)** — a full SSH replacement for headless servers
- **Cross-platform** — Windows (egui GUI + CLI), Linux (pipewire capture, VAAPI, uinput), macOS (zed-scap, VideoToolbox, Keychain identity storage)
- **Automatic logging** — daily rotating logs with automatic cleanup
- **Packaged for the real world** — NSIS installer (Windows), .deb with systemd service (Ubuntu), universal .app + .dmg (macOS), and in-app auto-update

## Quick Start

### Windows

Download `KirinDesk.exe` from **GitHub Releases / CI artifacts**（S-28 / F-33：
发布二进制不再入库跟踪，发布走 CI release job 的 artifacts + checksums.txt 校验）
and double-click — or use the CLI:

```batch
KirinDesk.exe --cli setup          # interactive setup wizard
KirinDesk.exe --cli register my-pc # register device to DNS
KirinDesk.exe --cli serve 3389     # start server
```

### Ubuntu Server

```bash
# Dependencies
sudo apt install build-essential libssl-dev pkg-config \
  libx11-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev libwayland-dev libavcodec-dev \
  libavutil-dev libswscale-dev

git clone <repo>
cd KirinDesk
cargo build --release -p kirin-desk-ui

# Configure & run the server
./target/release/kirin-desk-ui --cli setup
./target/release/kirin-desk-ui --cli register my-server 22
./target/release/kirin-desk-ui --cli serve 22
```

### Build from source (after cloning)

```bash
git clone https://github.com/kirin-yucall/KirinDesk.git
cd KirinDesk
```

**1. Frontend dependencies** — `ui/frontend/node_modules/` is not tracked, restore it first:

```bash
cd ui/frontend
npm ci                # install from package-lock.json
npm run build         # generate dist/ (consumed by the Tauri app at runtime)
cd ../..
```

**2. FFmpeg binaries** — `ffmpeg/ffmpeg-8.1.2-full_build-shared/` is not tracked either:

Download [ffmpeg-8.1.2-full_build-shared.zip](https://github.com/GyanD/codexffmpeg/releases/download/8.1.2/ffmpeg-8.1.2-full_build-shared.zip) and extract it into `ffmpeg/ffmpeg-8.1.2-full_build-shared/`. To run the prebuilt `release/KirinDesk.exe`, also copy its DLLs (`avcodec-62.dll`, `avutil-60.dll`, `swscale-9.dll`, ...) into `release/ffmpeg/bin/`.

**FFmpeg upgrade steps** (R-22): the codec path writes `AVCodecContext`/`AVFrame` struct fields by hardcoded byte offsets, verified against FFmpeg **8.1.2** (avcodec-62/avutil-60). On any major upgrade:

1. Re-verify every offset in `media/src/ffmpeg/api.rs` (`avctx_offset::*`, `AVFRAME_CH_LAYOUT_OFFSET`) against the new `avcodec.h`/`frame.h` (`offsetof`) — checklist is inline above the constants.
2. Update DLL names / sonames (`AVCODEC_LIB` etc.), `DLL_VERSION_FALLBACKS`, and `SNAPSHOT_FFMPEG_MAJOR` in `media/src/ffmpeg/dlls.rs`. The loader fails fast with a clear error if the loaded major version mismatches the snapshot — never run with stale offsets.
3. Re-check the `FnTable` symbol list (required symbols fail the load; optional HW symbols degrade).
4. Update this file and the inline checklist to the new snapshot version.

**3. Build** — `target/` is generated by cargo:

```bash
cargo build --release -p kirin-desk-ui
```

### Client Connection

```bash
# Domain mode (DNS auto-discovers port + IPv6 + public key)
KirinDesk.exe --cli connect my-server.example.com 22 mynickname

# IP mode (direct IPv6 + port)
KirinDesk.exe --cli connect 2001:db8::1 3389 mynickname
```

## GUI Overview

| Tab | Function |
|-----|----------|
| **Dashboard** | Device overview (Device ID, IPv6, port, domain whitelist) |
| **Connect** | Connect to a remote device — IPv6+Port or Domain+Nickname+Challenge forms |
| **Settings** | Configure Device ID, Nickname, Challenge Code, GoDaddy API, domain whitelist, connection mode |
| **Devices** | List of discovered / connected devices |

## Security Architecture

```
+---------------------------+       +---------------------------+
|  Client (controller)      |       |  Server (controlled)      |
|                           |       |                           |
|  FFmpeg libavcodec decode |       |  FFmpeg libavcodec encode |
|  ├─ h264_qsv / h264       |       |  ├─ h264_nvenc            |
|  ├─ hevc_qsv / hevc       |       |  ├─ h264_amf              |
|  └─ swscale YUV→RGBA      |       |  ├─ h264_qsv              |
|                           |       |  ├─ h264_vaapi            |
|                           |       |  └─ libx264               |
|        ↕                  |       |        ↕                  |
|  KirinDesk P2P secure     |──────▶│  KirinDesk P2P secure     |
|  tunnel                   |  P2P  │  tunnel                   |
|  ├─ Ed25519 identity      |  IPv6 │  ├─ Ed25519 identity      |
|  ├─ X25519 ECDH key exch. |       │  ├─ X25519 ECDH key exch. |
|  └─ AEAD AES-256-GCM      |       │  └─ AEAD AES-256-GCM      |
+---------------------------+       +---------------------------+
            ↑                                ↑
            │        GoDaddy DNS             │
            │  (SRV + AAAA + TXT records)    │
            +────────────────────────────────+
```

## Project Structure

```
KirinDesk/
├── core/          # Zero-trust crypto (Ed25519/X25519/AEAD/handshake), IPv6 networking, connection management
├── dns/           # GoDaddy API client, SRV/AAAA/TXT management, service discovery & heartbeat
├── media/         # Screen/audio capture, FFmpeg libavcodec encode/decode, QUIC transport, adaptive feedback
├── input/         # Remote input: Windows SendInput / Linux uinput / macOS CGEvent
├── ui/            # egui desktop GUI + clap CLI
├── updater/       # Auto-update (check / download / install)
├── utils/         # Config, logging, error types
├── ffmpeg/        # FFmpeg 8.1.2 shared libraries (avcodec-62/avutil-60/swscale-9)
├── config/        # Configuration structures & defaults
└── release/       # Installers & packaging (NSIS / deb / dmg)
```

## CLI Commands

```
kirin_desk <command> [options]

  setup                Interactive configuration wizard
  config               Show current configuration
  register [id] [p]    Register device with GoDaddy DNS
  discover <id>        Discover a remote device
  connect <t> [p] [n]  Connect to device (domain or IPv6)
                       challenge: interactive prompt (TTY) or --challenge-stdin (pipe)
  shell [port]         Remote shell server (domain whitelist)
  serve [port]         Start listening for connections
  status               Show system status
  self-test            End-to-end self test
  help                 Show this help
```

## Configuration

```toml
[device]
id = "my-pc"
nickname = "my-pc"
challenge_code = "my-secret"

[godaddy]
api_key = "..."
api_secret = "..."
domain = "example.com"

[network]
port = 3389
allowed_domains = ["example.com"]
ip_mode_allowed = false

[codec]
# Encoding settings
h264_bitrate = 5000000    # target bitrate (bps)
framerate = 30            # target frame rate
# Decoding settings
enable_hw_decode = true   # enable hardware decode (DXVA/VAAPI)

[logging]
level = "info"
format = "text"
```

## License

Apache 2.0 (KirinDesk core) + LGPL (FFmpeg libraries, dynamically loaded)

> KirinDesk is a non-profit passion project by an individual developer (用爱发电) — no monetization, no ads, no telemetry. Ever.
