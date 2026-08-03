# 🦄 KirinDesk — The P2P Remote Desktop Built to Retire SSH

**P2P Direct First · Relay-Assisted Hole Punching · Optional Relay Fallback · Zero TLS Certificates · End-to-End Encrypted**

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

KirinDesk turns that belief into working software by standing on three pillars that are anything but exotic: **IPv6** gives every device a globally reachable address; **the DNS system** becomes a decentralized, censorship-resistant bulletin board where devices publish where they are and who they are; and **modern public-key cryptography** replaces the entire legacy TLS certificate apparatus with something simpler, stronger, and truly zero-trust. No certificate authorities. Just devices, DNS, and math — with an **optional self-hosted relay server** ready to assist when the direct path is blocked (see below).

## Why the World Needs KirinDesk

### SSH: a quarter-century of brute force and patchwork defense

For over 25 years, SSH has been the workhorse of remote administration — and for over 25 years, port 22 has been scanned by every botnet on the planet. Password brute-force attacks never stop; your only defenses are patchwork like fail2ban, nonstandard ports that amount to security by obscurity, and constant vigilance. SSH was designed in an era when the Internet was smaller and more trusting. It was never designed to face the always-on, globally scanned attack surface of today's world.

### RDP / VNC: centralized authentication, 24/7 exposure

RDP and VNC carry their own burdens. Authentication leans on centralized directory services, the control port sits exposed around the clock, and traffic frequently lacks true end-to-end encryption. They are LAN-era tools asked to do an Internet-era job — and it shows.

### Commercial remote control: your screen rides someone else's highway

TeamViewer, AnyDesk, and their peers route every pixel of your screen through vendor-owned relay infrastructure. That means a third party always can — or at least could — see what you see. It means a vendor outage becomes your outage. And it means the privacy of your remote session depends on someone else's promises.

**KirinDesk was built to retire all three.**

## The KirinDesk Answer: Direct First, Assisted When Necessary

When you connect with KirinDesk, the **direct path is always tried first**: your device reaches out straight to the target device — no broker, no third-party cloud, no middleman. The two endpoints negotiate a mutually authenticated, end-to-end encrypted tunnel and talk to each other for the life of the session.

```
Legacy approach                               KirinDesk (direct path)
────────────────                               ─────────────────────
device ──▶ central server ──▶ device           device ──▶ device
          (relay / outage /                    (direct / zero
           sniffable)                          middlemen)
```

But KirinDesk is no longer *only* pure P2P. When a direct path doesn't exist — NAT, restrictive firewall, churned addresses — an **optional self-hosted relay server** (the same `relay-server` used for 内网穿透) steps in with two assists:

- **Relay-assisted hole punching** — the server runs a rendezvous service (customizable port, `--rendezvous-port`, default 7001) that exchanges hole-punching candidates between the two devices. **It only plays matchmaker and never enters the data path** — once the punch succeeds, traffic flows device-to-device (UDP hole punching + QUIC).
- **Device-ID relay fallback** — if even punching fails, the tunnel falls back to relaying through the server by device ID. The relay never holds keys: the channel stays end-to-end encrypted, and the server can only forward ciphertext it cannot read.

Either way, no third party can read your traffic. On the direct path nothing is in between; on the assisted paths the relay is a dumb pipe.

With IPv6, every device is globally reachable — no manual port forwarding on routers that refuse to cooperate. The address is just there, and KirinDesk connects to it directly. Where a direct path is blocked, the optional relay server lends a hand as described above — direct first, assisted when necessary, end-to-end encrypted throughout.

## Security Reimagined: Zero Trust, Zero Certificates

KirinDesk throws away the legacy TLS certificate system — no certificate authorities, no certificate chains, no expiry ceremonies, no PKI infrastructure to maintain. Instead, every device mints its own cryptographic identity at first run:

- An **Ed25519 long-term identity keypair** is generated on the device. The private key never leaves it (encrypted at rest), while the public key is published to the device's DNS TXT record — an unforgeable calling card.
- When two devices meet, they perform a **mutual authentication handshake**: challenge-response signed with Ed25519, key agreement via **X25519 ECDH**, and a session key derived with HKDF.
- Every byte of the session is sealed with **AEAD encryption (AES-256-GCM / ChaCha20-Poly1305)** — and every session derives a fresh key, giving the channel **perfect forward secrecy**. Even if a long-term key is ever compromised, past sessions stay sealed forever.

The result is a security model with a far smaller attack surface than the status quo: no passwords to brute-force over the wire, no certificates to forge, no trust anchor you didn't personally mint. The math does the talking.

Hardening continues past the handshake: **handshake pins are always enforced** (the old empty-pin bypass is gone — a peer key that isn't explicitly confirmed is refused), and sensitive configuration (DNS provider keys, tunnel tokens, challenge code) is encrypted at rest (R-13, see below). Connection rate limiting, audit logging, and SSH-style known-hosts fingerprint confirmation round out the defense-in-depth.

## Domain & Device-ID Whitelists: Access Control That Follows Devices, Not Addresses

Access control is where KirinDesk makes one of its most elegant — and most practical — departures from convention: **whitelists are expressed in domain names, not IP addresses.**

IP-address whitelists are a maintenance nightmare. Addresses change under you — DHCP renumbering, IPv6 privacy extensions, roaming laptops, cloud instances recreated overnight. A whitelist entry that works today silently fails tomorrow, and the usual "fix" is loosening the list until it stops meaning anything. IP addresses are also meaningless to humans: a wall of `2001:db8::f3a2`-looking strings tells you nothing about who is actually allowed in.

Domain whitelists fix every one of those problems at once:

- **They are human-readable.** `alice.example.com` says exactly who is welcome — no lookup table required.
- **They survive address changes.** A device's IPv6 address may churn, but its domain name is stable by design. The whitelist keeps working while the address changes underneath it.
- **They are cryptographically verifiable.** DNS isn't just a phone book here — it is the identity registry. The whitelist entry, the published public key, and the resolved address all come from the same authoritative source, so a domain name is a real identity claim, not a guess.
- **They are enforceable with zero exposure.** In strict mode, the server simply refuses any connection that does not originate from a whitelisted domain — your access list is a list of trusted identities, not a list of addresses that happen to be correct today.

That is the kind of design that feels obvious in hindsight: move the whitelist from the layer that changes (IP) to the layer that doesn't (names), and convenience and security improve at once.

KirinDesk adds a second, orthogonal whitelist dimension: **device-ID whitelists**. Entries can be exact (`my-pc`) or prefix wildcards (`office-*`), optionally expiring — a match on either dimension (domain **or** ID) grants access, and temporary connections (temp mode) bypass both for emergency access.

## A True SSH Replacement

KirinDesk's Server mode gives headless machines — Ubuntu servers, VPSes, cloud instances — a remote administration channel that makes legacy SSH look positively medieval. No fixed port to scan, no password to brute-force: connections are gated by the domain / device-ID whitelist and proven by a challenge code plus an Ed25519 signature. Traffic rides the same end-to-end encrypted, forward-secret tunnel as the remote desktop. And because the device publishes its own DNS records, even a machine behind a brand-new IPv6 address is found by name, instantly. The remote shell runs over a PTY on the encrypted channel — the terminal you love, with security you never had.

## At a Glance: KirinDesk vs. The Old Guard

| Aspect | Traditional SSH | RDP / VNC | Commercial Remote Desktop | **KirinDesk** |
|--------|-----------------|-----------|---------------------------|---------------|
| Connectivity | Direct port | Direct port | Central server relay | **P2P direct, hole-punch assisted** |
| Relay server | None | None | Required | **Optional, self-hosted (punch assist + fallback)** |
| Port exposure | 22, globally scanned | Scannable | None | **No fixed port exposure** |
| Authentication | Password / key | Password / cert | Vendor account | Challenge code + Ed25519 signature |
| Encryption | Transport-level | Weak / none | Vendor-dependent | **End-to-end AEAD, forward-secret** |
| Access control | — | — | Vendor accounts | **Domain / device-ID whitelist (strict mode)** |
| Privacy | — | — | Traffic via third party | **End-to-end encrypted; relay can't read** |
| Decentralized | ✗ | ✗ | ✗ | **✓ Fully decentralized** |

## Core Features

- **P2P over IPv6 / IPv4, direct first** — device-to-device tunnels with no middleman; when a direct path is blocked, relay-assisted hole punching (rendezvous coordination only, server never in the data path) with device-ID relay fallback; IPv6-first with IPv4 dual-stack support
- **Zero-trust cryptography** — Ed25519 identities, X25519 ECDH, AEAD (AES-256-GCM / ChaCha20-Poly1305), per-session keys with perfect forward secrecy; handshake pins always enforced; sensitive config (API keys, tokens, challenge code) encrypted at rest (R-13, see below)
- **DNS as the decentralized registry — 20 providers** — self-register and self-discover through any of 20 DNS providers (GoDaddy, Cloudflare, Aliyun, DNSPod, AWS Route 53, Azure, Google Cloud DNS, Huawei, Namecheap, DigitalOcean, Vultr, Linode, Hetzner, OVH, Porkbun, Baidu Cloud, Volcano Engine, JD Cloud, West.cn, Xin Net) via SRV + AAAA + TXT records queried in parallel, with heartbeat keep-alive
- **Domain & device-ID whitelists (strict mode)** — access control expressed in stable names, not volatile IPs; domain or device-ID (exact / `*` prefix / expirable) matches; temp mode issues a 10-character one-time code with whitelist bypass for emergencies
- **Dual connection modes + automatic transport fallback** — domain mode (DNS discovery, recommended) or direct IPv6/IPv4 mode; QUIC first, with graceful in-session degradation to TCP (resume, no re-connect)
- **Remote desktop** — FFmpeg libavcodec H.264/H.265 encode/decode with hardware acceleration (NVENC/AMF/QSV/VAAPI/libx264), QSV hardware decode with software fallback; single-GPU selection with virtual driver/display filtering (sunlogin, IDD, Parsec…); multi-monitor viewing with live switching; privacy mode (black screen / lock)
- **Adaptive media pipeline** — 70 ms windowed delivery over QUIC (datagram + reliable-stream transport, loss detection) with a feedback loop that adjusts encoding in real time
- **Audio** — capture & playback, microphone talkback to the controlled machine (Opus), per-session switches
- **Remote shell (PTY)** — a full SSH replacement for headless servers
- **File transfer** — encrypted, bidirectional and resumable (windowed ACK, SHA-256 verification, atomic rename); drag & drop in the GUI, `send` / `recv` in the CLI
- **Unattended mode** — user-level boot autostart + auto-accept whitelisted/known clients, no approval dialogs
- **Tunnel (内网穿透)** — FRP-style generic TCP reverse proxy: publish local TCP services (SSH/RDP/HTTP…) on a public relay server; SCRAM-style challenge-response token auth (password never on the wire), fully customizable server ports (`--bind-port` / `--bind-addrs` / `--rendezvous-port`), clients connect to any custom port with a token; multi-address listeners, GUI start/stop with state restore; standalone `relay-server` for Docker/systemd/headless deployment; optional rendezvous-assisted hole punching + device-ID relay fallback
- **Clipboard sharing** — copy/paste across machines over the encrypted channel
- **i18n** — full GUI in 中文 / English (follows the system language by default)
- **Security hardening** — connection rate limiting, audit logging (30+ events), SSH-style known-hosts fingerprint confirmation, config encryption (R-13)
- **Cross-platform** — Windows (egui GUI + CLI), Linux (pipewire capture, VAAPI, uinput), macOS (zed-scap, VideoToolbox, Keychain identity storage)
- **Automatic logging** — daily rotating logs with automatic cleanup
- **Packaged for the real world** — NSIS installer (Windows), .deb with systemd service (Ubuntu), universal .app + .dmg (macOS), in-app auto-update with release/beta channels

## 🆕 What's New (2026-08)

Since v0.1.0 a major round of features and hardening has landed — full record in [CHANGELOG.md](CHANGELOG.md):

- **DNS client for 20 providers** — record CRUD (A/AAAA/CNAME/MX/TXT/SRV/NS), connection test, domain list; Domain tab + `dns` CLI
- **Tunnel (内网穿透) as a standalone page** — FRP-style reverse proxy with GUI start/stop & state restore, multi-address listeners, one-click token generate/copy; standalone `relay-server` (Docker/systemd)
- **i18n** — GUI fully localized 中文 / English (follows system by default)
- **File transfer** — encrypted, resumable, bidirectional
- **Unattended mode** — boot autostart, auto-accept whitelisted/known clients
- **Multi-monitor viewing** — live monitor switching from the session toolbar
- **Single-GPU & virtual-device filtering** — the real GPU is selected; virtual drivers/displays are filtered out
- **Security** — mandatory pin verification, config encryption (R-13), device-ID whitelists, SCRAM-style tunnel auth, rate limiting & audit logs

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
# --jobs 4: hard cap on build threads (no full-core packing — the packager
# device is big.LITTLE; too many threads may crash it)
cargo build --release -p kirin-desk-ui --jobs 4

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

**1. Frontend dependencies** — `ui/frontend/node_modules/` is ignored by `.gitignore` (not tracked), restore it first:

```bash
cd ui/frontend
npm ci                # install from package-lock.json
npm run build         # generate dist/ (consumed by the Tauri app at runtime)
cd ../..
```

**2. FFmpeg binaries** — `ffmpeg/ffmpeg-8.1.1-full_build-shared/` is ignored by `.gitignore` (not tracked; the folder won't exist after cloning — `git ls-files ffmpeg/` is empty), so restore it manually:

1. Download [ffmpeg-8.1.1-full_build-shared.zip](https://github.com/GyanD/codexffmpeg/releases/download/8.1.1/ffmpeg-8.1.1-full_build-shared.zip) (GyanD shared build; URL verified reachable on 2026-08-03);
2. Extract and place the whole folder at `ffmpeg/ffmpeg-8.1.1-full_build-shared/` (the zip already uses this name — no rename needed); the loader searches this exact path (see `media/src/ffmpeg/dlls.rs`);
3. Verify `bin/` contains `avcodec-62.dll` (libavcodec 62.28.101), `avutil-60.dll`, `swscale-9.dll`, etc. (a missing library fails the load).

> **Why 8.1.1 instead of 8.1.2**: the 8.1.2 build bundles ffnvcodec 13.1 headers, so `h264_nvenc` requires NVIDIA driver ≥ 610.00; 8.1.1 bundles 13.0 headers and works on the mainstream 591-series drivers (verified on this machine with driver 591.86, 2026-08-02). Both ship libavcodec 62, so the hardcoded offset snapshot (`SNAPSHOT_FFMPEG_MAJOR = 62`) stays compatible — decision record: `task_docs/共享层/M8-T030_单GPU硬件加速与虚拟设备过滤_需求设计.md` §5.2.
>
> To run the prebuilt `release/KirinDesk.exe`, also copy its DLLs (`avcodec-62.dll`, `avutil-60.dll`, `swscale-9.dll`, ...) into `release/ffmpeg/bin/`.

**FFmpeg upgrade steps** (R-22): the codec path writes `AVCodecContext`/`AVFrame` struct fields by hardcoded byte offsets, verified against FFmpeg **8.1.1** (avcodec-62/avutil-60, libavcodec 62.28.101; 8.1.x builds with major 62 are compatible). On any major upgrade:

1. Re-verify every offset in `media/src/ffmpeg/api.rs` (`avctx_offset::*`, `AVFRAME_CH_LAYOUT_OFFSET`) against the new `avcodec.h`/`frame.h` (`offsetof`) — checklist is inline above the constants.
2. Update DLL names / sonames (`AVCODEC_LIB` etc.), `DLL_VERSION_FALLBACKS`, and `SNAPSHOT_FFMPEG_MAJOR` in `media/src/ffmpeg/dlls.rs`. The loader fails fast with a clear error if the loaded major version mismatches the snapshot — never run with stale offsets.
3. Re-check the `FnTable` symbol list (required symbols fail the load; optional HW symbols degrade).
4. Update this file and the inline checklist to the new snapshot version.

**3. Build** — `target/` is generated by cargo (git-ignored, not tracked):

```bash
# --jobs 4: hard cap on build threads (no full-core packing — the packager
# device is big.LITTLE; too many threads may crash it). See M14 constraint.
cargo build --release -p kirin-desk-ui --jobs 4
```

### Client Connection

```bash
# Domain mode (DNS auto-discovers port + IPv6 + public key)
KirinDesk.exe --cli connect my-server.example.com 22 mynickname

# IP mode (direct IPv6 + port)
KirinDesk.exe --cli connect 2001:db8::1 3389 mynickname
```

### Tunnel (内网穿透) Authentication

The relay server (`tunnel serve`) login uses a **challenge-response (SCRAM-style)** scheme (protocol v1.1.0):

- **The password never crosses the wire** — the login packet carries only a random nonce and an HMAC-SHA256 proof (`auth_digest`); packet captures cannot recover the password
- **Mutual authentication** — the server proves knowledge of the password with its own receipt; a fake server is rejected and dropped by the client
- **Fail-closed** — `tunnel serve` refuses to start when `[tunnel].token` is empty; clients configured with a token refuse unauthenticated (token-less) servers
- **Token quality** — use a high-entropy random string of ≥ 32 bytes (`openssl rand -base64 32`); tokens shorter than 16 characters trigger a warning

> **Upgrade note:** server and client must run the same version (same release). Old v1.0 clients are explicitly rejected by a token-configured server with an `upgrade client` hint; new clients error out against old servers. Upgrade both ends together.

> **Deployment**: `relay-server --bind-port 7000 --rendezvous-port 7001 --token <high-entropy-token>` — control port, rendezvous (hole-punch) port and bind addresses are all customizable; clients connect via `[tunnel] server_addr = "relay.example.com:<custom-port>"` with the same token (server also accepts `KIRIN_RELAY_TOKEN`). Full reference: `release/server/README.md`.

## GUI Overview

| Tab | Function |
|-----|----------|
| **Dashboard** | Device overview (Device ID, IPv6/IPv4, port, whitelists); allow-controlled / server switches; temp-mode card |
| **Domain** | DNS provider management — 20 providers, per-provider credentials, connection test, domain list, record CRUD (A/AAAA/CNAME/MX/TXT/SRV/NS) |
| **Devices** | Discovered / connected devices (nickname, notes, manual ordering) |
| **Connect** | Connect to a remote device — IPv6/IPv4+Port or Domain+Nickname+Challenge forms, live connection log |
| **Tunnel** | 内网穿透 — generic TCP reverse proxy: client/server config, bind addresses, token ✏️📋, proxies, start/stop with state restore |
| **Settings** | Device ID, Nickname, Challenge Code, DNS provider & credentials, whitelists, connection mode, transport, language (System/中文/English), unattended mode, updates |

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
            │      DNS (20 providers)        │
            │  (SRV + AAAA + TXT records)    │
            +────────────────────────────────+
```

> **Direct path**: device ⇄ device over IPv6/IPv4, nothing in between. **Assisted path (optional)**: a self-hosted `relay-server` runs rendezvous hole punching — candidate exchange only, it never enters the data path — and falls back to relaying the end-to-end encrypted tunnel (device-ID relay) when punching fails. Server ports (control / rendezvous / bind addresses) are all customizable; clients connect to any custom port with a SCRAM-style token.

## Project Structure

```
KirinDesk/
├── core/          # Zero-trust crypto (Ed25519/X25519/AEAD/handshake), IPv6/IPv4 networking, hole punching & path manager
├── dns/           # 20 DNS provider adapters, SRV/AAAA/A/TXT management, service discovery & heartbeat
├── media/         # Screen/audio capture, FFmpeg libavcodec encode/decode, GPU selection, QUIC/TCP transport, adaptive feedback
├── input/         # Remote input: Windows SendInput / Linux uinput / macOS CGEvent
├── relay/         # Tunnel (内网穿透): generic TCP reverse proxy client/server, rendezvous, device-ID registry
├── relay-server/  # Standalone tunnel server binary (Docker / systemd / headless deployment)
├── ui/            # egui desktop GUI (i18n 中文/English) + clap CLI
├── updater/       # Auto-update (check / download / install)
├── utils/         # Config (sensitive fields encrypted at rest, R-13), logging, error types, audit
├── ffmpeg/        # FFmpeg 8.1.1 shared libs (avcodec-62/avutil-60/swscale-9; git-ignored, restore after clone)
├── config/        # Configuration structures & defaults
└── release/       # Installers & packaging (NSIS / deb / dmg)
```

## CLI Commands

```
kirin_desk <command> [options]

  setup                Interactive configuration wizard
  config               Show current configuration
  register [id] [p]    Register device with DNS (current provider)
  discover <id>        Discover a remote device (current DNS provider)
  dns <subcommand>     DNS domain maintenance (M9-DNS023): list-providers |
                       set-provider <name> | test [provider] | domains |
                       records <domain> [type] | add|update <domain> <type>
                       <name> <data> [--ttl N] [--priority N --weight N
                       --port N] | delete <domain> <type> <name> |
                       register <device-id> <port> | unregister <device-id>
  connect <t> [p] [n]  Connect to device — domain (DNS discovery + TXT key
                       binding) or IPv6/IPv4; challenge: interactive TTY
                       prompt or --challenge-stdin (pipe)
                       [--transport auto|quic|tcp] [--ip-family auto|ipv4|ipv6]
                       [--no-audio]
  send <path> <host> [p] [n]  Send a file to the remote (encrypted, resumable)
  recv <host> [p] [n]         Receive files pushed by the remote
  shell [port]         Remote shell server (domain/ID whitelist enforced)
  shell <host> [p] [n] Connect to a remote shell (PTY mode)
  serve [port]         Start listening ([--unattended] auto-accept)
  known-hosts          List / add / remove trusted client keys (SSH-style)
  whitelist            List / add / remove domain & device-ID entries, CSV
                       import/export (whitelist add-id/remove-id)
  temp-mode [off]      Enable 5-min temp window: temp challenge code + bypass
  unattended <on|off|status>  Unattended mode (auto-accept, auto-start server)
  autostart <enable|disable|status>  OS user-level boot autostart
  tunnel start         Run tunnel client (frpc): map local TCP services to the
                       public relay server
  tunnel serve         Run tunnel server (frps) on this machine
  tunnel status        Show tunnel configuration and proxy list
  status               Show system status
  self-test            End-to-end self test
  help                 Show this help
```

## Configuration

```toml
[device]
id = ""              # empty = auto (disk UUID / machine-id / IOPlatformUUID)
nickname = "my-pc"
challenge_code = ""  # required for server mode (fail-closed)

[dns]
provider = "godaddy" # any of the 20 providers; credentials encrypted at rest (R-13)

# M8-T040: encrypted DNS enforcement for domain mode (server + client, enforce by default)
[dns.security]
mode = "enforce"      # enforce (domain mode requires DoH/DoT, fail-closed) | off (IP mode only)
doh = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve", "https://dns.alidns.com/resolve"]
dot = ["1.1.1.1:853", "8.8.8.8:853", "2400:3200::1:853"]
resolve_timeout_ms = 5000
cache_ttl_secs = 50

# M8-T040: DDNS auto-update (read/written by the Domain tab "DDNS" card)
[ddns]
enabled = false       # master switch (off by default; disabling does not delete published records)
interval_secs = 300   # update period (lower bound 60s; falls back to [network] heartbeat_interval if unset)
ipv4_mode = "auto"    # auto = public egress IP (multi-source HTTPS) | manual = fixed address (never overwritten)
ipv4_manual = ""
ipv4_sources = ["ipify", "ip.sb", "icanhazip"]
ipv6_mode = "auto"    # auto = local global unicast | manual = fixed address (never overwritten)
ipv6_manual = ""
publish_srv = true    # SRV (remote port) / TXT (signature fingerprint) / A / AAAA toggles
publish_txt = true
publish_a = true
publish_aaaa = true

[network]
port = 3389
allowed_domains = ["example.com"]
allowed_ids = []     # device-ID whitelist (exact match; `*` suffix = prefix)

[media]
encoder = "auto"     # auto | nvenc | amf | qsv | vaapi | libx264
framerate = 30
bitrate = 5000       # kbps

[media.gpu]
prefer = "auto"      # auto | intel | nvidia | amd | luid:0x… (or KIRIN_GPU_PREFER)
filter_virtual = true

[transport]
mode = "auto"        # auto | quic | tcp (graceful in-session degrade)
ip_family = "auto"   # auto | ipv4 | ipv6

[file_transfer]
download_dir = ""    # default ~/Downloads/KirinDesk
max_file_size = 4294967296  # 4 GiB per file

[tunnel]
enabled = false      # FRP-style reverse proxy — optional, off by default
mode = "client"      # client | server
server_addr = ""     # public relay server (domain / IP, :port suffix)
token = ""           # SCRAM-style auth; never sent in cleartext
bind_addrs = "0.0.0.0,::"    # server listeners (multi-address, comma-separated)
port_range = "60000-61000"

[logging]
level = "info"
format = "text"
```

### Configuration Encryption (R-13)

Sensitive fields — DNS provider API keys/secrets, tunnel tokens, etc. — are **never written to the config file in cleartext**. They are stored as ChaCha20-Poly1305 ciphertext (format `{v: base64(nonce‖ciphertext)}`, with the AAD bound to the field context to prevent cross-field swapping). You can grep the config file to verify there is no plaintext.

The master key is chosen automatically from a fallback chain:

| Platform | Key source |
|----------|-----------|
| Windows | DPAPI (current-user protection; blob at `config_dir/kirin_config_key.dpapi`) |
| macOS | Keychain generic password (`kirindesk-config-key`) |
| No keyring / any platform | Env var `KIRIN_CONFIG_KEY` (passphrase, PBKDF2-HMAC-SHA256 derived — highest priority) |
| None available | **fail-open**: plaintext storage + a prominent startup warning (doesn't block development use) |

Migration is seamless: an existing plaintext config is automatically encrypted and rewritten on first load (`#[serde(default)]` keeps old fields compatible); a failed rewrite never corrupts the file (atomic replace via `write_private`, and the in-memory config keeps working). Keys/tokens are never logged and appear masked (`****`) in `config show` / `status` output.

## License

Apache 2.0 (KirinDesk core) + LGPL (FFmpeg libraries, dynamically loaded)

> KirinDesk is a non-profit passion project by an individual developer (用爱发电) — no monetization, no ads, no telemetry. Ever.
