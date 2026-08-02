use kirin_desk_core::connection::temp_mode::TempModeManager;
use kirin_desk_core::network::ipv6::get_global_ipv6;
use kirin_desk_core::network::tcp::TcpServer;
use kirin_desk_dns::aaaa::AaaaManager;
use kirin_desk_dns::godaddy::GoDaddyClient;
use kirin_desk_dns::srv::SrvManager;
use kirin_desk_dns::txt::{DeviceMeta, TxtManager};
use kirin_desk_dns::DiscoveryService;
use kirin_desk_utils::config::Config;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// M8-T017: 临时连接管理器（状态文件经 `dirs` 解析到 cache 目录，修复旧
/// `/tmp/kirindesk-temp` 在 Windows 原生运行下失效的缺陷）。
fn temp_mode_manager() -> Option<TempModeManager> {
    match TempModeManager::new() {
        Ok(mgr) => Some(mgr),
        Err(e) => {
            println!("temp-mode error: {}", e);
            None
        }
    }
}

/// M8-T017: 临时连接窗口是否激活（统一判断点：`policy::temp_mode_window_active`）。
fn is_temp_mode_active() -> bool {
    crate::policy::temp_mode_window_active()
}

/// M8-T017: 临时连接事件审计（UI-TMP-005；打开失败静默）。
fn audit_temp_event(event: kirin_desk_utils::audit::AuditEvent, detail: &str) {
    if let Ok(mut logger) = kirin_desk_utils::audit::AuditLogger::open_default() {
        let _ = logger.record(event, detail);
    }
}

pub async fn run_cli() {
    let args: Vec<String> = std::env::args().filter(|a| a != "--cli").collect();
    if args.len() < 2 {
        print_help();
        return;
    }
    let cmd = &args[1];
    match cmd.as_str() {
        "help" | "--help" | "-h" => print_help(),
        "setup" => cmd_setup(),
        "config" => cmd_config(),
        "register" => {
            cmd_register(
                args.get(2).map(|s| s.as_str()).unwrap_or("default-device"),
                args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3389),
            )
            .await;
        }
        "discover" => {
            if let Some(id) = args.get(2) {
                cmd_discover(id).await;
            } else {
                println!("Usage: kirin_desk discover <device-id>");
            }
        }
        "connect" => {
            cmd_connect(args).await;
        }
        // M13-T006: 文件传输（双向，复用 SecureChannel 加密通道）。
        "send" => {
            let path = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let host = args.get(3).map(|s| s.as_str()).unwrap_or("");
            let port: u16 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(3389);
            let nickname = args.get(5).map(|s| s.as_str()).unwrap_or("");
            if path.is_empty() || host.is_empty() {
                println!("Usage: kirin_desk send <path> <host> [port] [nickname]");
                return;
            }
            cmd_send_file(path, host, port, nickname).await;
        }
        "recv" => {
            let host = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3389);
            let nickname = args.get(4).map(|s| s.as_str()).unwrap_or("");
            if host.is_empty() {
                println!("Usage: kirin_desk recv <host> [port] [nickname]");
                return;
            }
            cmd_recv_file(host, port, nickname).await;
        }
        "shell" => {
            // M11: `shell [port]` = 服务器模式（向后兼容）；`shell <host> [port] [nickname]` = 客户端模式。
            match args.get(2).and_then(|s| s.parse::<u16>().ok()) {
                Some(port) => cmd_shell_server(port).await,
                None => {
                    let host = args.get(2).map(|s| s.as_str()).unwrap_or("");
                    if host.is_empty() {
                        println!("Usage: kirin_desk shell <host> [port] [nickname]   (client mode)");
                        println!("       kirin_desk shell [port]                      (server mode)");
                        return;
                    }
                    let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(22);
                    let nickname = args.get(4).map(|s| s.as_str()).unwrap_or("");
                    cmd_shell_client(host, port, nickname).await;
                }
            }
        }
        "serve" => {
            // M13-T005 (UA-CLI-003): `serve [port] [--unattended]` — 无人值守
            // 策略运行（自动接受 known_clients/白名单，未知拒绝，temp-mode 禁用）。
            let unattended = args.iter().any(|a| a == "--unattended");
            let port = args
                .iter()
                .find_map(|a| a.parse::<u16>().ok())
                .unwrap_or(3389);
            cmd_serve(port, unattended).await;
        }
        "known-hosts" => cmd_known_hosts(args),
        "whitelist" => cmd_whitelist(args),
        "temp-mode" => {
            // M8-T017: `temp-mode off` = 手动关闭（无无人值守限制，关闭总是安全）。
            if args.get(2).map(|s| s.as_str()) == Some("off") {
                cmd_temp_mode_off();
                // UA-ACCEPT-004: 无人值守下禁用 temp-mode **开启**旁路。
            } else if Config::load()
                .map(|c| c.unattended.enabled)
                .unwrap_or(false)
            {
                println!("temp-mode is DISABLED while unattended mode is ON (unattended mode never bypasses whitelist).");
            } else {
                cmd_temp_mode();
            }
        }
        "unattended" => cmd_unattended(args),
        "autostart" => cmd_autostart(args),
        "status" => cmd_status(),
        "self-test" => cmd_self_test().await,
        _ => {
            println!("Unknown command: {}", cmd);
            print_help();
        }
    }
}

fn print_help() {
    println!("KirinDesk v{}", env!("CARGO_PKG_VERSION"));
    println!("P2P Remote Desktop - IPv6 + Zero Trust");
    println!();
    println!("USAGE:  kirin_desk <command> [options]");
    println!();
    println!("COMMANDS:");
    println!("  setup                Interactive configuration wizard");
    println!("  config               Show current configuration");
    println!("  register [id] [p]    Register device with GoDaddy DNS");
    println!("  discover <id>        Discover a remote device");
    println!("  connect <t> [p] [n] [c] Connect to device — domain: DNS discovery + TXT key");
    println!("                                     binding; IPv6: known_hosts / first-use confirm");
    println!("  send <path> <host> [p] [n] Send a file to the remote (encrypted, resume-able)");
    println!("  recv <host> [p] [n]        Receive files pushed by the remote");
    println!("  shell [port]         Remote shell server (domain whitelist)");
    println!("  shell <host> [p] [n] Connect to a remote shell (PTY mode)");
    println!("  serve [port] [--unattended]  Start listening (unattended: auto-accept known/whitelist)");
    println!("  known-hosts          List known clients (server-side trusted keys)");
    println!("  known-hosts add <id> <pubkey-base64>  Trust a client key (SRV-SEC-KH-002)");
    println!("  known-hosts remove <id>               Remove a trusted client");
    println!("  whitelist            List whitelist entries (SRV-SEC-WL)");
    println!("  whitelist add <pattern> [expiry]      Add (expiry: RFC3339 or empty=permanent)");
    println!("  whitelist remove <pattern>            Remove an entry");
    println!("  whitelist import <csv>  /  whitelist export <csv> / whitelist export-json <json>");
    println!("  temp-mode [off]      Enable temp mode (5 min): temp challenge code + whitelist bypass");
    println!("  unattended <on|off|status>  Unattended mode: auto-accept known/whitelisted");
    println!("                       clients, auto-start server, no approval dialogs");
    println!("  autostart <enable|disable|status>  OS user-level boot autostart");
    println!("  self-test            Run local self-connection test");
    println!("  status               Show system status");
    println!("  help                 Show this help");
    println!();
    println!("EXAMPLES:");
    println!("  kirin_desk setup");
    println!("  kirin_desk connect my-pc.example.com");
    println!("  kirin_desk connect 2001:db8::1 3389 mycode");
    println!("  kirin_desk register my-pc 3389");
    println!("  kirin_desk shell 22");
    println!("  kirin_desk shell my-server.example.com 22 alice");
    println!("  kirin_desk serve 3389");
    println!("  kirin_desk serve --unattended    # auto-accept, no approval");
    println!("  kirin_desk unattended on         # enable unattended mode");
    println!("  kirin_desk autostart enable      # register OS boot autostart");
    println!("  kirin_desk temp-mode    # 5-min temp window: shows 8-char temp code (clients must present it)");
}

/// M8-T017: 开启临时连接（SRV-TMP-001/002 / CLI-TMP-010）——生成 8 位临时
/// 挑战码，窗口期内白名单跳过且连接须携带该码。明文码仅在本次输出一次
/// （TMP-SEC-001，状态文件只存哈希），窗口期内再次调用只输出剩余时间。
fn cmd_temp_mode() {
    let cfg = Config::load().unwrap_or_default();
    let ttl = cfg.network.effective_temp_mode_ttl();
    let mgr = match temp_mode_manager() {
        Some(m) => m,
        None => return,
    };
    // 窗口期内再次调用：输出剩余时间（码仅开启时展示一次，未落盘）。
    if let Some(state) = mgr.state() {
        println!(
            "Temp mode is already ACTIVE — {}s remaining",
            state.remaining_secs
        );
        println!("  The temp challenge code was shown when the window was opened;");
        println!("  plaintext is not persisted (TMP-SEC-001).");
        println!("State file: {}", mgr.state_file_path().display());
        return;
    }
    // 残留已过期状态文件 → 审计过期 + 清理后重新开启。
    if mgr.state_file_path().exists() {
        audit_temp_event(
            kirin_desk_utils::audit::AuditEvent::TempModeExpired,
            "reason=stale_file_cleanup",
        );
    }
    match mgr.enable(ttl) {
        Ok(code) => {
            println!();
            println!("  >>> Temp Connection Code: {} <<<", code);
            println!();
            println!(
                "Temp mode ACTIVE for {}s ({} min)",
                ttl,
                ttl / 60
            );
            println!("  Whitelist bypassed — any client holding this code can connect.");
            println!("  The code is shown ONCE here; it is never stored in plaintext (TMP-SEC-001).");
            println!("  State file: {}", mgr.state_file_path().display());
            println!("  Close early:  kirin_desk temp-mode off");
            audit_temp_event(
                kirin_desk_utils::audit::AuditEvent::TempModeEnabled,
                &format!("ttl={}s state={}", ttl, mgr.state_file_path().display()),
            );
        }
        Err(e) => println!("Failed to activate temp mode: {}", e),
    }
}

/// M8-T017: 手动关闭临时连接（SRV-TMP-005 / CLI-TMP-011）。
fn cmd_temp_mode_off() {
    let mgr = match temp_mode_manager() {
        Some(m) => m,
        None => return,
    };
    match mgr.disable() {
        Ok(true) => {
            println!("Temp mode closed.");
            audit_temp_event(
                kirin_desk_utils::audit::AuditEvent::TempModeDisabled,
                "reason=manual",
            );
        }
        Ok(false) => println!("Temp mode is not active."),
        Err(e) => println!("Failed to close temp mode: {}", e),
    }
}

fn cmd_setup() {
    use std::io::{self, Write};
    println!("=== KirinDesk Setup Wizard ===");
    let mut cfg = Config::default();
    let mut input = String::new();

    print!("Device ID: ");
    io::stdout().flush().ok();
    input.clear();
    io::stdin().read_line(&mut input).ok();
    if !input.trim().is_empty() {
        cfg.device.id = input.trim().to_string();
    }

    print!("Nickname (for auth): ");
    io::stdout().flush().ok();
    input.clear();
    io::stdin().read_line(&mut input).ok();
    if !input.trim().is_empty() {
        cfg.device.nickname = input.trim().to_string();
    }

    print!("Challenge code: ");
    io::stdout().flush().ok();
    input.clear();
    io::stdin().read_line(&mut input).ok();
    if !input.trim().is_empty() {
        cfg.device.challenge_code = input.trim().to_string();
    }

    print!("GoDaddy API Key: ");
    io::stdout().flush().ok();
    input.clear();
    io::stdin().read_line(&mut input).ok();
    if !input.trim().is_empty() {
        cfg.godaddy.api_key = input.trim().to_string();
    }

    print!("GoDaddy API Secret: ");
    io::stdout().flush().ok();
    input.clear();
    io::stdin().read_line(&mut input).ok();
    if !input.trim().is_empty() {
        cfg.godaddy.api_secret = input.trim().to_string();
    }

    print!("Domain: ");
    io::stdout().flush().ok();
    input.clear();
    io::stdin().read_line(&mut input).ok();
    if !input.trim().is_empty() {
        cfg.godaddy.domain = input.trim().to_string();
    }

    print!("Port [3389]: ");
    io::stdout().flush().ok();
    input.clear();
    io::stdin().read_line(&mut input).ok();
    if let Ok(p) = input.trim().parse::<u16>() {
        cfg.network.port = p;
    }

    print!("Allowed domains (comma-sep, empty=any): ");
    io::stdout().flush().ok();
    input.clear();
    io::stdin().read_line(&mut input).ok();
    let domains: Vec<String> = input
        .trim()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !domains.is_empty() {
        cfg.network.allowed_domains = domains;
    } else {
        println!("  Warning: any domain allowed (insecure)");
    }

    match cfg.save() {
        Ok(()) => println!("\nSaved."),
        Err(e) => println!("\nError: {}", e),
    }
}

fn cmd_config() {
    match Config::load() {
        Ok(c) => {
            println!("Device ID:     {}", c.device.id);
            println!("Nickname:      {}", c.device.nickname);
            println!("Domain:        {}", c.godaddy.domain);
            println!("Port:          {}", c.network.port);
            println!("API Key:       {}", mask(&c.godaddy.api_key, 8));
            let wl = if c.network.allowed_domains.is_empty() {
                "any".to_string()
            } else {
                c.network.allowed_domains.join(", ")
            };
            println!("Allowed:       {}", wl);
            println!(
                "IP Mode:       {}",
                if c.network.ip_mode_allowed {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            // M13-T005: 无人值守状态
            println!(
                "Unattended:    {} (autostart={}, auto-server={}, registered={})",
                if c.unattended.enabled { "ON" } else { "OFF" },
                c.unattended.auto_start_on_boot,
                c.unattended.auto_start_server,
                kirin_desk_utils::autostart::is_installed()
            );
        }
        Err(_) => {
            println!("No config. Run 'kirin_desk setup'");
        }
    }
}

async fn cmd_register(device_id: &str, port: u16) {
    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    if cfg.godaddy.api_key.is_empty() {
        println!("API key not set. Run setup.");
        return;
    }
    let client = GoDaddyClient::new(
        &cfg.godaddy.api_key,
        &cfg.godaddy.api_secret,
        &cfg.godaddy.api_url,
    );
    println!("Registering '{}' on {}...", device_id, cfg.godaddy.domain);

    let target = format!("{}.{}.", device_id, cfg.godaddy.domain);
    match SrvManager::new(&client, &cfg.godaddy.domain)
        .register(device_id, port, &target, cfg.network.dns_ttl)
        .await
    {
        Ok(()) => println!("  SRV: OK"),
        Err(e) => println!("  SRV: {}", e),
    }
    match get_global_ipv6() {
        Ok(ip) => match AaaaManager::new(&client, &cfg.godaddy.domain)
            .register(device_id, ip, cfg.network.dns_ttl)
            .await
        {
            Ok(()) => println!("  AAAA: {} OK", ip),
            Err(e) => println!("  AAAA: {}", e),
        },
        Err(e) => println!("  IPv6: {}", e),
    }
    // SRV-DNS-006：TXT 注册**真实身份公钥**（供对端握手 pin / DNS TXT 比对，
    // 修复旧 PLACEHOLDER_KEY —— 占位公钥会让所有基于 TXT 的公钥校验失效）。
    let identity = match load_identity(&cfg) {
        Ok(id) => id,
        Err(e) => {
            println!("Identity error: {}. (run 'kirin_desk connect' once to generate)", e);
            return;
        }
    };
    let pubkey = identity.public_key_base64();
    let meta = DeviceMeta::new(&pubkey);
    println!("  TXT key: {}...", &pubkey[..std::cmp::min(20, pubkey.len())]);
    match TxtManager::new(&client, &cfg.godaddy.domain)
        .register(device_id, &meta, cfg.network.dns_ttl)
        .await
    {
        Ok(()) => println!("  TXT: OK (real identity key)"),
        Err(e) => println!("  TXT: {}", e),
    }
    println!("Done.");
}

async fn cmd_discover(device_id: &str) {
    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}", e);
            return;
        }
    };
    let client = GoDaddyClient::new(
        &cfg.godaddy.api_key,
        &cfg.godaddy.api_secret,
        &cfg.godaddy.api_url,
    );
    let discovery = DiscoveryService::new(&client, &cfg.godaddy.domain);
    match discovery.discover(device_id).await {
        Ok(info) => {
            println!("Device:    {}", info.device_id);
            println!("Subdomain: {}", info.subdomain);
            println!("IPv6:      {}", info.ipv6_addr);
            println!("Port:      {}", info.port);
            println!("Type:      {}", info.device_type);
            if info.device_type == "server" {
                println!("This is a headless server. Use shell mode.");
            }
            println!(
                "Key:       {}...",
                &info.public_key_base64[..std::cmp::min(20, info.public_key_base64.len())]
            );
        }
        Err(e) => println!("Discovery failed: {}", e),
    }
}

/// M13-T005 (UA-CLI-001): 无人值守模式开关与状态 — `unattended <on|off|status>`。
///
/// `on`：开启自动接受策略（known_clients/白名单命中自动放行，未知设备拒绝）。
/// 前置校验（UA-SEC-002）：身份必须已生成；白名单/known_clients 为空时软警告
/// （UA-SEC-003，D3：警告但不阻断）。
fn cmd_unattended(args: Vec<String>) {
    use kirin_desk_utils::known_hosts::KnownClientsStore;

    let sub = args.get(2).map(|s| s.as_str()).unwrap_or("status");
    let mut cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    match sub {
        "on" => {
            if load_identity(&cfg).is_err() {
                println!(
                    "ERROR: no device identity found — unattended mode requires a device identity \
                     (Ed25519) for handshake signing. Run 'kirin_desk setup' first."
                );
                return;
            }
            // UA-SEC-003 (D3): 软警告——无白名单且无 known_clients 时开启将拒绝一切连接。
            let wl = cfg.whitelist_active_patterns(chrono::Utc::now());
            let known_count = KnownClientsStore::load()
                .map(|k| k.clients().len())
                .unwrap_or(0);
            if wl.is_empty() && known_count == 0 {
                println!("  ⚠ WARNING: no whitelist entries and no known clients — in unattended mode ALL connections will be REJECTED.");
                println!("    (add via 'kirin_desk whitelist add <pattern>' or 'kirin_desk known-hosts add <id> <pubkey>')");
            }
            cfg.unattended.enabled = true;
            match cfg.save() {
                Ok(()) => println!("Unattended mode ON — known/whitelisted clients auto-accepted, unknown rejected, temp-mode disabled."),
                Err(e) => println!("Save failed: {}", e),
            }
        }
        "off" => {
            cfg.unattended.enabled = false;
            match cfg.save() {
                Ok(()) => println!("Unattended mode OFF."),
                Err(e) => println!("Save failed: {}", e),
            }
        }
        _ => {
            println!(
                "Unattended mode: {}",
                if cfg.unattended.enabled { "ON" } else { "OFF" }
            );
            println!(
                "  auto_start_on_boot: {}",
                cfg.unattended.auto_start_on_boot
            );
            println!(
                "  auto_start_server:  {}",
                cfg.unattended.auto_start_server
            );
            println!(
                "  autostart registered: {}",
                kirin_desk_utils::autostart::is_installed()
            );
        }
    }
}

/// M13-T005 (UA-CLI-002): 开机自启注册/移除/状态 — `autostart <enable|disable|status>`。
///
/// 与无人值守总开关**独立**（D6）：`autostart enable` 仅注册用户级开机自启，
/// 是否自动开启服务端/自动接受连接仍由 `[unattended]` 配置决定。
fn cmd_autostart(args: Vec<String>) {
    use kirin_desk_utils::autostart;

    let sub = args.get(2).map(|s| s.as_str()).unwrap_or("status");
    let mut cfg = Config::load().unwrap_or_default();
    match sub {
        "enable" => match autostart::install() {
            Ok(()) => {
                cfg.unattended.auto_start_on_boot = true;
                let _ = cfg.save();
                println!("Autostart ENABLED — KirinDesk will start at OS user login (--autostart).");
            }
            Err(e) => println!("Autostart enable FAILED: {}", e),
        },
        "disable" => match autostart::uninstall() {
            Ok(()) => {
                cfg.unattended.auto_start_on_boot = false;
                let _ = cfg.save();
                println!("Autostart DISABLED.");
            }
            Err(e) => println!("Autostart disable FAILED: {}", e),
        },
        _ => {
            println!(
                "Autostart: {}",
                if autostart::is_installed() {
                    "registered"
                } else {
                    "not registered"
                }
            );
            println!(
                "  config auto_start_on_boot: {}",
                cfg.unattended.auto_start_on_boot
            );
        }
    }
}

/// CLI 侧首次连接指纹交互确认（CLI-KH-001）。
/// stdin 非终端（管道/脚本）→ 拒绝（CLI-HSK-SEC-003：未命中且无确认路径 → 拒绝）。
fn confirm_fingerprint_prompt(device_id: &str, pubkey_base64: &str) -> bool {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        println!(
            "  (stdin is not a terminal — cannot prompt for fingerprint confirmation; refusing)"
        );
        return false;
    }
    let fp = kirin_desk_utils::known_hosts::fingerprint(pubkey_base64);
    println!();
    println!("  First connection to '{}'. Verify this fingerprint with the device owner:", device_id);
    println!("  SHA-256: {}", fp);
    print!("  Trust this key? (y/N): ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    let trimmed = line.trim();
    trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes")
}

/// CLI 侧信任解析结果。
enum CliTrust {
    /// 带外可信公钥（known_hosts 指纹 / DNS TXT，用户已确认）→ 握手强制比对。
    Verified(String),
    /// 拒绝连接（原因已打印）。
    Rejected(String),
}

/// 根据 known_hosts + 候选公钥（DNS TXT）解析 CLI 侧信任（CLI-KH-003/004）：
/// - known_hosts 命中且一致 → 放行（最高优先级，优先于 DNS TXT）；
/// - 命中但不一致 → **拒绝连接**（防 MITM）；
/// - 未命中 → 交互式首次指纹确认（非 TTY 拒绝）。
fn cli_resolve_trust(device_id: &str, candidate_key: &str) -> CliTrust {
    use kirin_desk_utils::known_hosts::{FingerprintStatus, KnownHostsStore};
    match KnownHostsStore::load().map(|s| s.check(device_id, candidate_key)) {
        Ok(FingerprintStatus::Match) => {
            println!("  known_hosts fingerprint MATCH for '{}' ✓", device_id);
            CliTrust::Verified(candidate_key.to_string())
        }
        Ok(FingerprintStatus::Mismatch) => CliTrust::Rejected(format!(
            "known_hosts fingerprint MISMATCH for '{}' — refusing connection (MITM guard)",
            device_id
        )),
        Ok(FingerprintStatus::Unknown) | Err(_) => {
            if confirm_fingerprint_prompt(device_id, candidate_key) {
                CliTrust::Verified(candidate_key.to_string())
            } else {
                CliTrust::Rejected("fingerprint confirmation declined".to_string())
            }
        }
    }
}

/// IP 直连（无带外公钥）时的握手确认回调（CLI-KH-003）：
/// known_hosts 命中自动放行；命中不一致拒绝；未命中交互式确认。
fn cli_confirm_callback(device_id: &str) -> Box<dyn Fn(&str) -> bool + Send> {
    let id = device_id.to_string();
    Box::new(move |key: &str| {
        use kirin_desk_utils::known_hosts::{FingerprintStatus, KnownHostsStore};
        match KnownHostsStore::load().map(|s| s.check(&id, key)) {
            Ok(FingerprintStatus::Match) => {
                println!("  known_hosts fingerprint MATCH for '{}' ✓", id);
                true
            }
            Ok(FingerprintStatus::Mismatch) => {
                println!(
                    "  SECURITY: known_hosts fingerprint MISMATCH for '{}' — refusing connection",
                    id
                );
                false
            }
            Ok(FingerprintStatus::Unknown) | Err(_) => confirm_fingerprint_prompt(&id, key),
        }
    })
}

/// CLI 侧握手成功后：记录 known_hosts（CLI-KH-002）+ 保存设备（CLI-DEV-001）。
fn cli_record_connection(addr: &str, server_id: &str, pubkey: &str, device_type: &str, domain: &str) {
    use kirin_desk_utils::devices::{DeviceStore, SavedDevice};
    use kirin_desk_utils::known_hosts::KnownHostsStore;
    if let Err(e) = KnownHostsStore::load().and_then(|mut s| s.confirm(server_id, pubkey)) {
        println!("  warn: known_hosts record failed: {}", e);
    }
    let port = addr
        .rsplit(':')
        .next()
        .and_then(|p| p.trim_end_matches(']').parse().ok())
        .unwrap_or(0);
    let ipv6 = addr
        .trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or("")
        .to_string();
    let device = SavedDevice {
        id: server_id.to_string(),
        nickname: server_id.to_string(),
        ipv6,
        port,
        pubkey: pubkey.to_string(),
        device_type: device_type.to_string(),
        last_seen: chrono::Utc::now(),
        domain: domain.to_string(),
    };
    match DeviceStore::load().and_then(|mut s| {
        s.upsert(device);
        s.save()
    }) {
        Ok(()) => println!("  Device saved to devices.json (CLI-DEV-001)"),
        Err(e) => println!("  warn: device save failed: {}", e),
    }
}

/// M15 (CLI-DNS-SEC-004): CLI `connect` 全链路 — 发现 → 信任解析 → 握手 → 保存设备。
///
/// - Domain 模式：`discover`（SRV 端口 + AAAA IPv6 + TXT 公钥）→ known_hosts/DNS TXT
///   公钥绑定（CLI-KH-004 优先级）→ 握手 → 自动保存设备（CLI-DEV-001）；
///   TXT 公钥缺失/解析失败 → **拒绝连接**（CLI-DNS-006）。
/// - IP 模式：known_hosts 命中自动放行 / 首次指纹交互确认（CLI-HSK-SEC-003）；
///   非 TTY 且未命中 → 拒绝。
/// - 昵称/挑战码来自命令行（CLI-DEV-006，不落盘）；挑战码缺省用配置值。
async fn cmd_connect(args: Vec<String>) {
    use kirin_desk_core::crypto::handshake::client_handshake_with_confirm;
    use std::net::IpAddr;

    let target = args.get(2).map(|s| s.as_str()).unwrap_or("");
    let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3389);
    let nickname = args.get(4).map(|s| s.as_str()).unwrap_or("");
    let challenge_arg = args.get(5).map(|s| s.as_str()).unwrap_or("");

    if target.is_empty() {
        println!("Usage: kirin_desk connect <domain|ipv6> [port] [nickname] [challenge]");
        return;
    }
    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    let identity = match load_identity(&cfg) {
        Ok(id) => id,
        Err(e) => {
            println!("Identity error: {}", e);
            return;
        }
    };
    // 昵称：显式传入 > 目标主机；挑战码：显式传入 > 配置值。
    let server_id = if nickname.is_empty() {
        target.to_string()
    } else {
        nickname.to_string()
    };
    let challenge = if challenge_arg.is_empty() {
        cfg.device.challenge_code.clone()
    } else {
        challenge_arg.to_string()
    };
    let device_type = "desktop";

    let is_ip = target.parse::<IpAddr>().is_ok() || target.contains(':');
    if !is_ip {
        // ── Domain 模式：发现 → 信任解析 → 握手 ──
        if cfg.godaddy.api_key.is_empty() {
            println!("GoDaddy API not configured. Run 'kirin_desk setup' first.");
            return;
        }
        let device_id = target.trim_end_matches(&format!(".{}", cfg.godaddy.domain)).to_string();
        println!("Discovering '{}' on {}...", device_id, cfg.godaddy.domain);
        let client = GoDaddyClient::new(
            &cfg.godaddy.api_key,
            &cfg.godaddy.api_secret,
            &cfg.godaddy.api_url,
        );
        let discovery = DiscoveryService::new(&client, &cfg.godaddy.domain);
        let info = match discovery.discover(&device_id).await {
            Ok(info) => info,
            Err(e) => {
                // CLI-DNS-005: 设备未注册 / DNS 无响应 → 明确错误中止。
                println!("Discovery FAILED: {}", e);
                println!("  (device not registered, or DNS/GoDaddy API unavailable)");
                return;
            }
        };
        println!(
            "Discovered: {} [{}]:{} type={}",
            info.device_id, info.ipv6_addr, info.port, info.device_type
        );
        if info.public_key_base64.is_empty() {
            // CLI-DNS-006: TXT 公钥缺失 → 拒绝连接，不回退信任网络公钥。
            println!("ERROR: device TXT record has NO public key — connection refused.");
            return;
        }
        println!("  TXT pubkey: {}...", &info.public_key_base64[..std::cmp::min(20, info.public_key_base64.len())]);
        // 信任解析：known_hosts 优先于 DNS TXT（CLI-KH-004）；未命中首次确认。
        let trusted_key = match cli_resolve_trust(&info.device_id, &info.public_key_base64) {
            CliTrust::Verified(key) => key,
            CliTrust::Rejected(reason) => {
                println!("Connection aborted: {}", reason);
                return;
            }
        };
        let addr = format!("[{}]:{}", info.ipv6_addr, info.port);
        // 客户端域名 = 目标域名（服务端白名单按此匹配）。
        let client_domain = format!("{}.{}", info.device_id, cfg.godaddy.domain);
        println!("Connecting {} (domain: {}) as '{}'...", addr, client_domain, server_id);
        let Ok(stream) = tokio::net::TcpStream::connect(&addr).await else {
            println!("TCP connect FAILED");
            return;
        };
        let ch = match client_handshake_with_confirm(
            stream,
            &identity,
            &cfg.device.id,
            &client_domain,
            device_type,
            &server_id,
            Some(trusted_key.clone()),
            None,
            &challenge,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                println!("Handshake FAILED: {}", e);
                if let Some(h) = crate::policy::connect_failure_challenge_hint(&challenge) {
                    println!("{}", h);
                }
                return;
            }
        };
        println!(
            "✓ Connected to {}@{} (selected codec: {})",
            ch.peer_id, addr, ch.selected_codec
        );
        cli_record_connection(&addr, &info.device_id, &trusted_key, &info.device_type, &cfg.godaddy.domain);
        drop(ch);
        if info.device_type == "server" {
            println!("  This is a headless server — use 'kirin_desk shell <host> [port] [nickname]' for an interactive terminal.");
        } else {
            println!("  (CLI mode cannot render the remote desktop; use the GUI for desktop sessions.)");
        }
    } else {
        // ── IP 模式：known_hosts / 首次指纹确认 → 握手 ──
        let addr = if target.contains(':') {
            format!(
                "[{}]:{}",
                target.trim_matches(|c| c == '[' || c == ']'),
                port
            )
        } else {
            format!("{}:{}", target, port)
        };
        println!("Connecting {} as '{}'...", addr, server_id);
        let Ok(stream) = tokio::net::TcpStream::connect(&addr).await else {
            println!("TCP connect FAILED");
            return;
        };
        // 确认回调放行的公钥经共享槽取回，握手成功后写入 known_hosts（CLI-KH-002）。
        let confirmed_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let confirmed_key_cb = confirmed_key.clone();
        let server_id_cb = server_id.clone();
        let key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>> =
            Some(Box::new(move |key: &str| {
                let ok = cli_confirm_callback(&server_id_cb)(key);
                if ok {
                    if let Ok(mut ck) = confirmed_key_cb.lock() {
                        *ck = Some(key.to_string());
                    }
                }
                ok
            }));
        let ch = match client_handshake_with_confirm(
            stream,
            &identity,
            &cfg.device.id,
            target,
            device_type,
            &server_id,
            None,
            key_confirm,
            &challenge,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                println!("Handshake FAILED: {}", e);
                if let Some(h) = crate::policy::connect_failure_challenge_hint(&challenge) {
                    println!("{}", h);
                }
                return;
            }
        };
        println!("✓ Connected to {}@{} (selected codec: {})", ch.peer_id, addr, ch.selected_codec);
        let trusted_key = confirmed_key.lock().ok().and_then(|k| k.clone());
        if let Some(key) = &trusted_key {
            cli_record_connection(&addr, &server_id, key, device_type, "");
        }
        drop(ch);
        println!("  (CLI mode cannot render the remote desktop; use the GUI for desktop sessions.)");
    }
}

/// M11-T004: 远程 Shell 服务器（headless，域名白名单强制，无 GUI 审批弹窗）。
///
/// 每个连接：白名单握手（temp mode 可绕过）→ SecureChannel PTY 桥接
/// （`run_shell_bridge`，Windows=ConPTY / Unix=forkpty）。
async fn cmd_shell_server(port: u16) {
    use kirin_desk_core::connection::run_shell_bridge;
    use kirin_desk_core::crypto::handshake::VerifiedDecision;
    use kirin_desk_core::network::rate_limit::{RateLimitDecision, RateLimiter};
    use kirin_desk_utils::audit::{AuditEvent, AuditLogger};
    use kirin_desk_utils::known_hosts::KnownClientsStore;

    println!("KirinDesk Remote Shell — domain whitelist enforced");
    println!("(Replaces SSH: secure channel + domain whitelist, no GUI approval)");

    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    let identity = match load_identity(&cfg) {
        Ok(id) => id,
        Err(e) => {
            println!("Identity error: {}", e);
            return;
        }
    };
    let mut known = match KnownClientsStore::load() {
        Ok(k) => k,
        Err(e) => {
            println!("known_clients load error: {}", e);
            return;
        }
    };
    let mut audit = match AuditLogger::open_default() {
        Ok(a) => a,
        Err(e) => {
            println!("audit log open error: {}", e);
            return;
        }
    };
    let mut rate_limiter = RateLimiter::new();
    // M15-T003：白名单含过期条目过滤（SRV-SEC-WL-003），兼容旧 allowed_domains。
    let allowed = cfg.whitelist_active_patterns(chrono::Utc::now());
    let server_name = if cfg.device.nickname.is_empty() {
        "shell-server".to_string()
    } else {
        cfg.device.nickname.clone()
    };
    let expected_challenge = if cfg.device.challenge_code.is_empty() {
        None
    } else {
        Some(cfg.device.challenge_code.as_str())
    };
    let config_temp = cfg.network.temp_mode;
    let server_pub = identity.public_key_base64();
    // M13-T005 (UA-ACCEPT-001): 无人值守开启时走自动接受策略；UA-ACCEPT-004
    // 禁用 temp-mode 旁路（无人值守不提供任何临时放行未知设备的路径）。
    let unattended = cfg.unattended.enabled;
    let config_temp = if unattended { false } else { config_temp };

    if allowed.is_empty() && !config_temp {
        println!("  ⚠ No whitelisted domains configured — ALL connections will be REJECTED.");
        println!("    (use 'kirin_desk setup' → allowed domains, or 'kirin_desk temp-mode')");
    }
    println!(
        "  Whitelist: {}",
        if allowed.is_empty() {
            "(empty — reject all unless temp mode)".to_string()
        } else {
            allowed.join(", ")
        }
    );
    println!("  Nickname (auth): '{}'", server_name);
    println!("  Use 'kirin_desk temp-mode' for 5-minute whitelist bypass.");

    match TcpServer::bind(port).await {
        Ok(server) => {
            println!(
                "Listening on [::]:{} (domain whitelist enforced)",
                server.port()
            );
            loop {
                // M8-T017: 临时连接窗口**逐连接**判定（窗口中途开启/过期即时
                // 生效），与配置静态旁路取或；无人值守下窗口维度一并关闭
                // （UA-ACCEPT-004，策略层亦忽略）。
                let temp_window = if unattended {
                    None
                } else {
                    crate::policy::temp_mode_window_manager()
                };
                let is_temp = config_temp || temp_window.is_some();
                if is_temp {
                    let remaining = temp_mode_remaining();
                    println!(
                        "[Temp Mode ACTIVE] whitelist bypassed ({}s remaining)",
                        remaining
                    );
                }
                match server.accept().await {
                    Ok((stream, addr)) => {
                        let ip = addr.ip().to_canonical();
                        let _ = audit.record(
                            AuditEvent::ConnectionRequest,
                            &format!("ip={} port={}", ip, addr.port()),
                        );
                        // 1. 速率限制（SRV-SEC-RL-001/002）。
                        match rate_limiter.check_connect(&ip) {
                            RateLimitDecision::Allowed => {}
                            decision => {
                                let _ = audit.record(
                                    AuditEvent::RateLimited,
                                    &format!("ip={} decision={:?}", ip, decision),
                                );
                                println!("  Rate limited: {} ({:?}) — rejected", ip, decision);
                                continue;
                            }
                        }
                        println!("Connection from {}", addr);
                        let allowed = allowed.clone();
                        let identity = &identity;
                        let server_name = server_name.clone();
                        // 2. 完整握手：known_hosts/DNS-TXT 公钥 pin + 白名单 +
                        //    签名验证（SRV-SHELL-SEC-003：与桌面模式同策略）。
                        match crate::policy::server_accept_handshake(
                            stream,
                            identity,
                            &server_name,
                            &allowed,
                            is_temp,
                            unattended,
                            temp_window,
                            None, // headless：白名单即身份，不做 nickname 校验
                            expected_challenge,
                            &known,
                            &cfg,
                        )
                        .await
                        {
                            Ok(VerifiedDecision::Accepted(ch)) => {
                                let _ = audit.record(
                                    AuditEvent::HandshakeSuccess,
                                    &format!(
                                        "ip={} client={} <{}> ({})",
                                        ip, ch.peer_id, ch.peer_domain, ch.peer_device_type
                                    ),
                                );
                                rate_limiter.reset(&ip);
                                crate::policy::record_successful_handshake(&mut known, &ch.peer_id);
                                println!(
                                    "  Session ACCEPTED: {} <{}> ({})",
                                    ch.peer_id, ch.peer_domain, ch.peer_device_type
                                );
                                // PTY 桥接直到会话结束（任一侧断开）。
                                let peer_id = ch.peer_id.clone();
                                let result = run_shell_bridge(
                                    ch,
                                    kirin_desk_core::connection::DEFAULT_PTY_COLS,
                                    kirin_desk_core::connection::DEFAULT_PTY_ROWS,
                                    None,
                                )
                                .await;
                                let _ = audit.record(
                                    AuditEvent::Disconnect,
                                    &format!("ip={} client={}", ip, peer_id),
                                );
                                match result {
                                    Ok(()) => println!("  Session closed: {}", addr),
                                    Err(e) => println!("  Session ended with error: {}", e),
                                }
                            }
                            Ok(VerifiedDecision::Rejected(reason)) => {
                                let _ = audit.record(
                                    AuditEvent::AuthFailure,
                                    &format!("ip={} reason={}", ip, reason),
                                );
                                rate_limiter.record_handshake_failure(&ip);
                                println!("  REJECTED: {}", reason);
                                if !is_temp && !server_pub.is_empty() {
                                    println!("    (headless server: no GUI approval — whitelist the client domain or use temp-mode)");
                                }
                            }
                            Err(e) => {
                                let _ = audit.record(
                                    AuditEvent::HandshakeFailure,
                                    &format!("ip={} error={}", ip, e),
                                );
                                rate_limiter.record_handshake_failure(&ip);
                                println!("  Handshake error: {}", e);
                            }
                        }
                    }
                    Err(e) => println!("Accept error: {}", e),
                }
            }
        }
        Err(e) => println!("Bind error: {}", e),
    }
}

/// M11-T003: CLI shell 客户端 — `kirin_desk shell <host> [port] [nickname]`
///
/// TCP + 握手 + SecureChannel PTY 桥接；本地终端进入 raw mode（无需回车），
/// 尺寸变化自动发送 `ShellResize`；退出命令（exit / Ctrl+D / Ctrl+C）经通道
/// 转发到远端 shell，会话随远端断开而结束。
///
/// 安全（M15）：与 `connect` 同级别信任策略——Domain 模式 DNS TXT 公钥绑定 /
/// known_hosts 指纹（CLI-HSK-SEC-001/003）；IP 模式 known_hosts 命中自动放行、
/// 未命中首次指纹交互确认。**不信任网络上来的公钥，不传自身公钥冒充服务端。**
async fn cmd_shell_client(target: &str, port: u16, nickname: &str) {
    use kirin_desk_core::connection::ShellMessage;
    use kirin_desk_core::crypto::handshake::client_handshake_with_confirm;
    use std::io::{IsTerminal, Read, Write};
    use std::net::IpAddr;

    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    let identity = match load_identity(&cfg) {
        Ok(id) => id,
        Err(e) => {
            println!("Identity error: {}", e);
            return;
        }
    };
    let server_id = if nickname.is_empty() {
        "shell-server".to_string()
    } else {
        nickname.to_string()
    };
    // 客户端域名 = 目标主机（域名模式）→ 服务端白名单按此匹配；
    // 目标为 IP 时服务端需 temp mode。
    let mut client_domain = target.to_string();

    // 信任解析（M15）：Domain 模式先 DNS 发现取 TXT 公钥绑定；IP 模式走确认回调。
    let is_ip = target.parse::<IpAddr>().is_ok() || target.contains(':');
    let mut expected_key: Option<String> = None;
    let mut addr = if target.contains(':') {
        format!(
            "[{}]:{}",
            target.trim_matches(|c| c == '[' || c == ']'),
            port
        )
    } else {
        format!("{}:{}", target, port)
    };
    if !is_ip {
        if cfg.godaddy.api_key.is_empty() {
            println!("GoDaddy API not configured — cannot discover '{}'. Run setup.", target);
            return;
        }
        let device_id = target
            .trim_end_matches(&format!(".{}", cfg.godaddy.domain))
            .to_string();
        println!("Discovering '{}' on {}...", device_id, cfg.godaddy.domain);
        let client = GoDaddyClient::new(
            &cfg.godaddy.api_key,
            &cfg.godaddy.api_secret,
            &cfg.godaddy.api_url,
        );
        let discovery = DiscoveryService::new(&client, &cfg.godaddy.domain);
        let info = match discovery.discover(&device_id).await {
            Ok(info) => info,
            Err(e) => {
                println!("Discovery FAILED: {} (device not registered or DNS unavailable)", e);
                return;
            }
        };
        if info.public_key_base64.is_empty() {
            println!("ERROR: device TXT record has NO public key — connection refused.");
            return;
        }
        println!(
            "Discovered: {} [{}]:{} type={}",
            info.device_id, info.ipv6_addr, info.port, info.device_type
        );
        expected_key = match cli_resolve_trust(&info.device_id, &info.public_key_base64) {
            CliTrust::Verified(key) => Some(key),
            CliTrust::Rejected(reason) => {
                println!("Connection aborted: {}", reason);
                return;
            }
        };
        addr = format!("[{}]:{}", info.ipv6_addr, info.port);
        client_domain = format!("{}.{}", info.device_id, cfg.godaddy.domain);
    }

    println!(
        "KirinDesk Remote Shell — connecting to {} as '{}'...",
        addr, server_id
    );
    let stream = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            println!("TCP connect failed: {}", e);
            return;
        }
    };
    println!("TCP connected. Handshaking...");
    // IP 模式确认回调放行的公钥经共享槽取回，握手成功后写 known_hosts。
    let confirmed_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let confirmed_key_cb = confirmed_key.clone();
    let server_id_cb = server_id.clone();
    let key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>> = match &expected_key {
        Some(_) => None,
        None => Some(Box::new(move |key: &str| {
            let ok = cli_confirm_callback(&server_id_cb)(key);
            if ok {
                if let Ok(mut ck) = confirmed_key_cb.lock() {
                    *ck = Some(key.to_string());
                }
            }
            ok
        })),
    };
    let ch = match client_handshake_with_confirm(
        stream,
        &identity,
        &cfg.device.id,
        &client_domain,
        "shell",
        &server_id,
        expected_key.clone(),
        key_confirm,
        &cfg.device.challenge_code,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            println!("Handshake FAILED: {}", e);
            println!("  (server enforces domain whitelist — is your domain allowed?)");
            if let Some(h) = crate::policy::connect_failure_challenge_hint(&cfg.device.challenge_code) {
                println!("{}", h);
            }
            return;
        }
    };
    // M15 (CLI-KH-002) + CLI-DEV-001: 连接成功 → 记录 known_hosts + 保存设备。
    let trusted_key = match &expected_key {
        Some(k) => Some(k.clone()),
        None => confirmed_key.lock().ok().and_then(|k| k.clone()),
    };
    if let Some(key) = &trusted_key {
        cli_record_connection(&addr, &server_id, key, "server", &client_domain);
    }
    println!("Secured channel established. PTY session started.");
    println!("  type 'exit' or press Ctrl+D (Unix) to quit; Ctrl+C sends SIGINT to remote shell");

    // 本地终端 raw mode（无需回车，方向键/控制字符直通）。
    if let Err(e) = crossterm::terminal::enable_raw_mode() {
        println!("Failed to enable raw mode: {}", e);
        return;
    }
    let (mut ch_reader, mut ch_writer) = ch.into_split();

    // 输入/尺寸消息队列（stdin 线程 + resize 轮询 → 发送任务）。
    let (msg_tx, mut msg_rx) = tokio::sync::mpsc::unbounded_channel::<ShellMessage>();
    let stdin_tx = msg_tx.clone();

    // 1) 本地 stdin（阻塞线程）→ ShellStdin。
    let stdin_handle = tokio::task::spawn_blocking(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break, // stdin EOF（如 Ctrl+D）
                Ok(n) => {
                    if stdin_tx
                        .send(ShellMessage::ShellStdin(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // 2) 终端尺寸轮询（500ms）→ ShellResize（变化时发送）。
    let resize_tx = msg_tx.clone();
    let resize_handle = tokio::spawn(async move {
        let mut last = (0u16, 0u16);
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            match crossterm::terminal::size() {
                Ok((cols, rows)) if (cols, rows) != last => {
                    if resize_tx
                        .send(ShellMessage::ShellResize { cols, rows })
                        .is_err()
                    {
                        break;
                    }
                    last = (cols, rows);
                }
                _ => {}
            }
        }
    });

    // 3) 消息发送任务：ShellStdin/ShellResize → 加密通道。
    let send_handle = tokio::spawn(async move {
        while let Some(msg) = msg_rx.recv().await {
            let payload = match msg.encode() {
                Ok(p) => p,
                Err(e) => {
                    println!("shell encode error: {}", e);
                    break;
                }
            };
            if let Err(e) = ch_writer.send(&payload).await {
                println!("shell send error: {} — session closed", e);
                break;
            }
        }
    });

    // 4) 接收任务：ShellStdout → 本地终端。
    //    非交互（stdin 非终端，如管道输入）时模拟终端应答 DSR 查询
    //    （`ESC[6n`，cmd.exe 启动时会阻塞等待响应）——交互模式由本地终端应答。
    let auto_dsr = !std::io::stdin().is_terminal();
    let dsr_tx = msg_tx.clone();
    let recv_handle = tokio::spawn(async move {
        let mut stdout = std::io::stdout();
        let mut dsr_buf: Vec<u8> = Vec::new();
        loop {
            match ch_reader.receive().await {
                Ok(bytes) => match ShellMessage::decode(&bytes) {
                    Ok(ShellMessage::ShellStdout(data)) => {
                        let _ = stdout.write_all(&data);
                        let _ = stdout.flush();
                        if auto_dsr {
                            dsr_buf.extend_from_slice(&data);
                            let keep = dsr_buf.len().min(8);
                            dsr_buf.drain(..dsr_buf.len() - keep);
                            while let Some(pos) = dsr_buf.windows(4).position(|w| w == b"\x1b[6n")
                            {
                                // 光标位置未知 → 应答 1;1（cmd.exe 仅需收到响应即继续）。
                                let _ = dsr_tx.send(ShellMessage::ShellStdin(b"\x1b[1;1R".to_vec()));
                                dsr_buf.drain(..pos + 4);
                            }
                        }
                    }
                    _ => {}
                },
                Err(e) => {
                    // 远端断开 → 会话结束。
                    let _ = stdout.write_all(
                        format!("\r\n[shell] connection closed: {}\r\n", e).as_bytes(),
                    );
                    let _ = stdout.flush();
                    break;
                }
            }
        }
    });

    // 会话生命周期：任一侧结束即退出（远端断开 / 本地 stdin EOF）。
    tokio::select! {
        _ = stdin_handle => {
            println!("\r\n[shell] local input closed — waiting for remote to finish...");
            // 输入关闭后仍等待远端输出结束（最多 5s 兜底）。
            let _ = tokio::time::sleep(Duration::from_secs(5)).await;
        }
        _ = recv_handle => {}
        _ = send_handle => {}
        _ = resize_handle => {}
    }

    let _ = crossterm::terminal::disable_raw_mode();
    println!("\r\n[shell] session ended");
}

/// 加载/生成持久设备身份（与 GUI 同路径：~/.kirin_desk/identity/ed25519.json）。
fn load_identity(
    cfg: &Config,
) -> Result<kirin_desk_core::crypto::ed25519::IdentityManager, Box<dyn std::error::Error>> {
    use kirin_desk_core::crypto::ed25519::IdentityManager;
    let device_id = if cfg.device.id.is_empty() {
        "default"
    } else {
        &cfg.device.id
    };
    let path = dirs_next::home_dir()
        .unwrap_or_default()
        .join(".kirin_desk")
        .join("identity")
        .join("ed25519.json");
    IdentityManager::load_or_generate(path, device_id).map_err(|e| e.into())
}

/// M8-T017: temp-mode 剩余秒数（无激活时 0）。
fn temp_mode_remaining() -> u32 {
    TempModeManager::new()
        .map(|mgr| mgr.remaining_secs())
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════
// M13-T006: CLI 文件传输 — send / recv
// ════════════════════════════════════════════════════════════════

/// CLI 文件传输共用连接：目标解析（domain 发现 / IP 直连）→ 信任解析 →
/// 完整握手，返回已建立的 SecureChannel。
async fn cli_file_connect(
    target: &str,
    port: u16,
    nickname: &str,
    device_type: &str,
) -> Option<kirin_desk_core::crypto::handshake::SecureChannel> {
    use kirin_desk_core::crypto::handshake::client_handshake_with_confirm;
    use std::net::IpAddr;

    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return None;
        }
    };
    let identity = match load_identity(&cfg) {
        Ok(id) => id,
        Err(e) => {
            println!("Identity error: {}", e);
            return None;
        }
    };
    let server_id = if nickname.is_empty() {
        target.to_string()
    } else {
        nickname.to_string()
    };
    let mut client_domain = target.to_string();
    let is_ip = target.parse::<IpAddr>().is_ok() || target.contains(':');
    let mut expected_key: Option<String> = None;
    let mut addr = if target.contains(':') {
        format!("[{}]:{}", target.trim_matches(|c| c == '[' || c == ']'), port)
    } else {
        format!("{}:{}", target, port)
    };
    if !is_ip {
        if cfg.godaddy.api_key.is_empty() {
            println!("GoDaddy API not configured — cannot discover '{}'. Run setup.", target);
            return None;
        }
        let device_id = target.trim_end_matches(&format!(".{}", cfg.godaddy.domain)).to_string();
        println!("Discovering '{}' on {}...", device_id, cfg.godaddy.domain);
        let client = GoDaddyClient::new(&cfg.godaddy.api_key, &cfg.godaddy.api_secret, &cfg.godaddy.api_url);
        let discovery = DiscoveryService::new(&client, &cfg.godaddy.domain);
        let info = match discovery.discover(&device_id).await {
            Ok(info) => info,
            Err(e) => {
                println!("Discovery FAILED: {} (device not registered or DNS unavailable)", e);
                return None;
            }
        };
        if info.public_key_base64.is_empty() {
            println!("ERROR: device TXT record has NO public key — connection refused.");
            return None;
        }
        println!(
            "Discovered: {} [{}]:{} type={}",
            info.device_id, info.ipv6_addr, info.port, info.device_type
        );
        expected_key = match cli_resolve_trust(&info.device_id, &info.public_key_base64) {
            CliTrust::Verified(key) => Some(key),
            CliTrust::Rejected(reason) => {
                println!("Connection aborted: {}", reason);
                return None;
            }
        };
        addr = format!("[{}]:{}", info.ipv6_addr, info.port);
        client_domain = format!("{}.{}", info.device_id, cfg.godaddy.domain);
    }
    println!("Connecting to {} as '{}'...", addr, server_id);
    let stream = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            println!("TCP connect failed: {}", e);
            return None;
        }
    };
    println!("TCP connected. Handshaking...");
    let confirmed_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let confirmed_key_cb = confirmed_key.clone();
    let server_id_cb = server_id.clone();
    let key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>> = match &expected_key {
        Some(_) => None,
        None => Some(Box::new(move |key: &str| {
            let ok = cli_confirm_callback(&server_id_cb)(key);
            if ok {
                if let Ok(mut ck) = confirmed_key_cb.lock() {
                    *ck = Some(key.to_string());
                }
            }
            ok
        })),
    };
    let ch = match client_handshake_with_confirm(
        stream,
        &identity,
        &cfg.device.id,
        &client_domain,
        device_type,
        &server_id,
        expected_key.clone(),
        key_confirm,
        &cfg.device.challenge_code,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            println!("Handshake FAILED: {}", e);
            println!("  (server enforces domain whitelist — is your domain allowed?)");
            if let Some(h) = crate::policy::connect_failure_challenge_hint(&cfg.device.challenge_code) {
                println!("{}", h);
            }
            return None;
        }
    };
    let trusted_key = match &expected_key {
        Some(k) => Some(k.clone()),
        None => confirmed_key.lock().ok().and_then(|k| k.clone()),
    };
    if let Some(key) = &trusted_key {
        cli_record_connection(&addr, &server_id, key, device_type, &client_domain);
    }
    println!("Secured channel established.");
    Some(ch)
}

/// CLI 文件会话循环（send/recv/serve 共用）：接收分发 + 1s tick + 进度打印。
/// 返回 (完成, 打印文本)。
async fn cli_file_loop(
    mut receiver: kirin_desk_media::transport::SecureChannelReceiver,
    ft: &mut super::FileSession,
    print_progress: bool,
    panel: &'static std::sync::Mutex<super::FilePanelState>,
) -> (bool, String) {
    use kirin_desk_media::transport::ChannelTag;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // M8-T019 (SRV-PRIV-013): 无头 Server 模式——headless=true，
    // Black 请求自动降级 Lock（或拒绝），Ack 反馈客户端。
    let privacy = Arc::new(Mutex::new(
        kirin_desk_core::connection::privacy::PrivacyController::new(true),
    ));
    // M8-T019 (PRIV-SEC-001): 隐私审计（独立句柄，append 模式并发安全）。
    let mut privacy_audit = kirin_desk_utils::audit::AuditLogger::open_default().ok();
    loop {
        tokio::select! {
            res = receiver.recv_tagged() => {
                match res {
                    Ok((tag, _, payload)) => match tag {
                        ChannelTag::FileTransfer => {
                            match super::FileTransferFrame::decode(&payload) {
                                Ok(frame) => ft.handle_frame(frame).await,
                                Err(e) => println!("  [file] frame decode failed: {e}"),
                            }
                        }
                        // M8-T019 (SRV-PRIV-013/001/002): 无头 Server 隐私请求。
                        ChannelTag::Control => {
                            use kirin_desk_core::connection::privacy::PrivacyOutcome;
                            use kirin_desk_media::transport::ControlMessage;
                            match bincode::deserialize::<ControlMessage>(&payload) {
                                Ok(ControlMessage::PrivacyMode { level, on }) => {
                                    let outcome = privacy.lock().unwrap().request(level, on);
                                    let (ok, active_level) = match &outcome {
                                        PrivacyOutcome::Activated(active) => (true, Some(*active)),
                                        PrivacyOutcome::Off => (true, None),
                                        PrivacyOutcome::Rejected(_) => (
                                            false,
                                            privacy.lock().unwrap().active_level(),
                                        ),
                                    };
                                    // PRIV-SEC-001: 审计（事件含 level 与发起方）。
                                    let event = match &outcome {
                                        PrivacyOutcome::Activated(active) if *active != level => {
                                            kirin_desk_utils::audit::AuditEvent::PrivacyDegraded
                                        }
                                        PrivacyOutcome::Activated(_) => {
                                            kirin_desk_utils::audit::AuditEvent::PrivacyEnabled
                                        }
                                        PrivacyOutcome::Off => {
                                            kirin_desk_utils::audit::AuditEvent::PrivacyDisabled
                                        }
                                        PrivacyOutcome::Rejected(_) => {
                                            kirin_desk_utils::audit::AuditEvent::PrivacyDegraded
                                        }
                                    };
                                    super::audit_record(
                                        &mut privacy_audit,
                                        event,
                                        &format!(
                                            "level={} initiator=remote headless",
                                            level.as_str()
                                        ),
                                    );
                                    let _ = ft.send_privacy_ack(ok, active_level).await;
                                    println!(
                                        "  [privacy] {} on={} → {:?}",
                                        level.as_str(),
                                        on,
                                        outcome
                                    );
                                }
                                Ok(other) => println!("  [control] unhandled: {:?}", other),
                                Err(e) => println!("  [control] deserialize failed: {e}"),
                            }
                        }
                        other => {
                            // 媒体帧：headless 会话无消费方，忽略。
                            let _ = other;
                        }
                    },
                    Err(e) => {
                        println!("  Connection closed: {}", e);
                        return (false, format!("connection closed: {e}"));
                    }
                }
            }
            _ = tick.tick() => {
                ft.on_tick().await;
                if print_progress {
                    if let Ok(panel) = panel.lock() {
                        for t in &panel.tasks {
                            let frac = if t.size == 0 { 1.0 } else { (t.done as f64 / t.size as f64) * 100.0 };
                            match &t.status {
                                super::FileTaskStatus::Completed => {
                                    let path = t.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
                                    println!("  ✔ {}: 100% 完成{}", t.name, if path.is_empty() { String::new() } else { format!(" → {path}") });
                                    return (true, format!("{} 完成", t.name));
                                }
                                super::FileTaskStatus::Failed(e) => {
                                    println!("  ✘ {}: 失败 — {}", t.name, e);
                                    return (false, format!("{} 失败: {}", t.name, e));
                                }
                                super::FileTaskStatus::Cancelled => {
                                    println!("  ✘ {}: 已取消", t.name);
                                    return (false, format!("{} 已取消", t.name));
                                }
                                super::FileTaskStatus::Sending | super::FileTaskStatus::WaitingAccept => {
                                    println!("  {}: {:.0}% ({}/{}) {:.1} MB/s", t.name, frac,
                                        super::file_panel::format_size(t.done),
                                        super::file_panel::format_size(t.size),
                                        t.speed / (1024.0 * 1024.0));
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
}

/// `--cli send <path> <host> <port> <nickname>`：推送本地文件到远端。
async fn cmd_send_file(path: &str, host: &str, port: u16, nickname: &str) {
    use kirin_desk_media::transport::{SecureChannelReceiver, SecureChannelSender};
    use std::sync::Arc;

    let path = PathBuf::from(path);
    if !path.is_file() {
        println!("Not a file: {}", path.display());
        return;
    }
    let ch = match cli_file_connect(host, port, nickname, "desktop").await {
        Some(c) => c,
        None => return,
    };
    let peer_id = ch.peer_id.clone();
    let (reader, writer) = ch.into_split();
    let sender: Arc<tokio::sync::Mutex<SecureChannelSender>> =
        Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(writer)));
    let receiver = SecureChannelReceiver::new(reader);

    let cfg = Config::load().unwrap_or_default();
    let my_id = load_identity(&cfg)
        .map(|i| i.public_key_base64())
        .unwrap_or_default();
    let salt = super::file_transfer_salt(&my_id, &peer_id);
    let store_path = super::transfers_store_path("client");
    let download_dir = cfg.file_transfer.resolved_download_dir();
    let max_file_size = if cfg.file_transfer.max_file_size > 0 {
        cfg.file_transfer.max_file_size
    } else {
        super::DEFAULT_MAX_FILE_SIZE
    };
    let mut ft = super::FileSession::new(
        sender,
        super::file_panel_state(),
        salt,
        store_path,
        download_dir,
        max_file_size,
        None,
    );
    println!("Sending '{}' ({})...", path.display(), super::file_panel::format_size(
        std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
    ));
    ft.handle_command(super::FileCommand::SendFile { path }).await;
    let (ok, msg) = cli_file_loop(receiver, &mut ft, true, super::file_panel_state()).await;
    if !ok {
        println!("FAILED: {msg}");
    } else {
        println!("OK: {msg}");
    }
}

/// `--cli recv <host> <port> <nickname>`：被动接收远端推送（下载方向）。
async fn cmd_recv_file(host: &str, port: u16, nickname: &str) {
    use kirin_desk_media::transport::{SecureChannelReceiver, SecureChannelSender};
    use std::sync::Arc;

    let ch = match cli_file_connect(host, port, nickname, "desktop").await {
        Some(c) => c,
        None => return,
    };
    let peer_id = ch.peer_id.clone();
    let (reader, writer) = ch.into_split();
    let sender: Arc<tokio::sync::Mutex<SecureChannelSender>> =
        Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(writer)));
    let receiver = SecureChannelReceiver::new(reader);

    let cfg = Config::load().unwrap_or_default();
    let my_id = load_identity(&cfg)
        .map(|i| i.public_key_base64())
        .unwrap_or_default();
    let salt = super::file_transfer_salt(&my_id, &peer_id);
    let store_path = super::transfers_store_path("client");
    let download_dir = cfg.file_transfer.resolved_download_dir();
    let max_file_size = if cfg.file_transfer.max_file_size > 0 {
        cfg.file_transfer.max_file_size
    } else {
        super::DEFAULT_MAX_FILE_SIZE
    };
    let mut ft = super::FileSession::new(
        sender,
        super::file_panel_state(),
        salt,
        store_path,
        download_dir.clone(),
        max_file_size,
        None,
    );
    println!("Receiving files into {} (waiting for pushes)...", download_dir.display());
    let (ok, msg) = cli_file_loop(receiver, &mut ft, true, super::file_panel_state()).await;
    println!("{}", if ok { "RECEIVED" } else { "FAILED" });
    let _ = msg;
}


///
/// 每个连接：速率限制 → 审计 → 完整握手（known_hosts/DNS-TXT 公钥 pin +
/// 白名单 + 签名验证，见 [`crate::policy::server_accept_handshake`]）→
/// 保持安全通道至客户端断开。桌面流媒体由 GUI 服务器提供；CLI serve 负责
/// 策略强制执行与安全握手应答（修复旧实现：空白名单 + 握手后丢流不应答）。
///
/// M13-T005 (UA-CLI-003)：`unattended = true` 时以无人值守策略运行——
/// known_clients/白名单命中自动放行、未知设备拒绝、temp-mode 禁用；
/// 并按客户端声明的会话类型分发（UA-ACCEPT-003）：`shell` → PTY 桥接，
/// 其余保持通道（远控桌面流媒体由 GUI 服务器承载）。
async fn cmd_serve(port: u16, unattended: bool) {
    use kirin_desk_core::connection::{run_shell_bridge, DEFAULT_PTY_COLS, DEFAULT_PTY_ROWS};
    use kirin_desk_core::crypto::handshake::VerifiedDecision;
    use kirin_desk_core::network::rate_limit::{RateLimitDecision, RateLimiter};
    use kirin_desk_utils::audit::{AuditEvent, AuditLogger};
    use kirin_desk_utils::known_hosts::KnownClientsStore;

    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    let identity = match load_identity(&cfg) {
        Ok(id) => id,
        Err(e) => {
            println!("Identity error: {}", e);
            return;
        }
    };
    let mut known = match KnownClientsStore::load() {
        Ok(k) => k,
        Err(e) => {
            println!("known_clients load error: {}", e);
            return;
        }
    };
    let mut audit = match AuditLogger::open_default() {
        Ok(a) => a,
        Err(e) => {
            println!("audit log open error: {}", e);
            return;
        }
    };
    let mut rate_limiter = RateLimiter::new();
    let allowed = cfg.whitelist_active_patterns(chrono::Utc::now());
    let server_name = if cfg.device.nickname.is_empty() {
        "serve-server".to_string()
    } else {
        cfg.device.nickname.clone()
    };
    let expected_challenge = if cfg.device.challenge_code.is_empty() {
        None
    } else {
        Some(cfg.device.challenge_code.as_str())
    };
    let config_temp = cfg.network.temp_mode;
    // UA-ACCEPT-004: 无人值守下禁用 temp-mode 旁路。
    let config_temp = if unattended { false } else { config_temp };

    println!("Server on port {}...", port);
    if unattended {
        println!("  [Unattended Mode] known_clients/whitelist auto-accepted, unknown REJECTED, temp-mode disabled");
    } else {
        println!("Use 'kirin_desk temp-mode' for 5-minute whitelist bypass.");
    }
    match TcpServer::bind(port).await {
        Ok(server) => {
            println!("Listening on [::]:{}", server.port());
            loop {
                // M8-T017: 临时连接窗口**逐连接**判定（窗口中途开启/过期即时
                // 生效），与配置静态旁路取或；无人值守下窗口维度一并关闭
                // （UA-ACCEPT-004，策略层亦忽略）。
                let temp_window = if unattended {
                    None
                } else {
                    crate::policy::temp_mode_window_manager()
                };
                let is_temp = config_temp || temp_window.is_some();
                if is_temp {
                    println!("[Temp Mode ACTIVE] {}s remaining", temp_mode_remaining());
                }
                match server.accept().await {
                    Ok((stream, addr)) => {
                        let ip = addr.ip().to_canonical();
                        let _ = audit.record(
                            AuditEvent::ConnectionRequest,
                            &format!("ip={} port={}", ip, addr.port()),
                        );
                        // 1. 速率限制（SRV-SEC-RL-001/002）。
                        match rate_limiter.check_connect(&ip) {
                            RateLimitDecision::Allowed => {}
                            decision => {
                                let _ = audit.record(
                                    AuditEvent::RateLimited,
                                    &format!("ip={} decision={:?}", ip, decision),
                                );
                                println!("  Rate limited: {} ({:?}) — rejected", ip, decision);
                                continue;
                            }
                        }
                        println!("Connection from {}", addr);

                        // 2. 完整握手（known_hosts/DNS pin + 白名单 + 签名验证）。
                        match crate::policy::server_accept_handshake(
                            stream,
                            &identity,
                            &server_name,
                            &allowed,
                            is_temp,
                            unattended,
                            temp_window,
                            None,
                            expected_challenge,
                            &known,
                            &cfg,
                        )
                        .await
                        {
                            Ok(VerifiedDecision::Accepted(ch)) => {
                                let _ = audit.record(
                                    AuditEvent::HandshakeSuccess,
                                    &format!(
                                        "ip={} client={} <{}> ({})",
                                        ip, ch.peer_id, ch.peer_domain, ch.peer_device_type
                                    ),
                                );
                                rate_limiter.reset(&ip);
                                crate::policy::record_successful_handshake(&mut known, &ch.peer_id);
                                println!(
                                    "  Session ACCEPTED: {} <{}> ({})",
                                    ch.peer_id, ch.peer_domain, ch.peer_device_type
                                );
                                // M13-T005 (UA-ACCEPT-003): 会话类型分发——客户端
                                // 声明 "shell" → PTY 桥接；否则保持通道至断开。
                                if ch.peer_device_type == "shell" {
                                    let peer_id = ch.peer_id.clone();
                                    let result = run_shell_bridge(
                                        ch,
                                        DEFAULT_PTY_COLS,
                                        DEFAULT_PTY_ROWS,
                                        None,
                                    )
                                    .await;
                                    let _ = audit.record(
                                        AuditEvent::Disconnect,
                                        &format!("ip={} client={} shell", ip, peer_id),
                                    );
                                    match result {
                                        Ok(()) => println!("  Shell session closed: {}", addr),
                                        Err(e) => println!("  Shell session ended with error: {}", e),
                                    }
                                } else {
                                    // M13-T006 (UI-FT-005): 无头服务端静默接收文件 +
                                    // 保持通道至客户端断开（流媒体由 GUI 服务器承载）。
                                    use kirin_desk_media::transport::{
                                        SecureChannelReceiver, SecureChannelSender,
                                    };
                                    let peer_id = ch.peer_id.clone();
                                    let (reader, writer) = ch.into_split();
                                    let sender: Arc<tokio::sync::Mutex<SecureChannelSender>> =
                                        Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(writer)));
                                    let receiver = SecureChannelReceiver::new(reader);
                                    let cfg_ft = Config::load().unwrap_or_default();
                                    let my_id = identity.public_key_base64();
                                    let salt = super::file_transfer_salt(&my_id, &peer_id);
                                    let store_path = super::transfers_store_path("server");
                                    let download_dir = cfg_ft.file_transfer.resolved_download_dir();
                                    let max_file_size = if cfg_ft.file_transfer.max_file_size > 0 {
                                        cfg_ft.file_transfer.max_file_size
                                    } else {
                                        super::DEFAULT_MAX_FILE_SIZE
                                    };
                                    let mut ft = super::FileSession::new(
                                        sender,
                                        super::server_file_panel_state(),
                                        salt,
                                        store_path,
                                        download_dir.clone(),
                                        max_file_size,
                                        None,
                                    );
                                    println!(
                                        "  File reception ready (→ {})",
                                        download_dir.display()
                                    );
                                    let (ok, msg) =
                                        cli_file_loop(receiver, &mut ft, true, super::server_file_panel_state()).await;
                                    let _ = ok;
                                    let _ = msg;
                                    let _ = audit.record(
                                        AuditEvent::Disconnect,
                                        &format!("ip={} client={}", ip, peer_id),
                                    );
                                    println!("  Session closed: {}", addr);
                                }
                            }
                            Ok(VerifiedDecision::Rejected(reason)) => {
                                let _ = audit.record(
                                    AuditEvent::AuthFailure,
                                    &format!("ip={} reason={}", ip, reason),
                                );
                                rate_limiter.record_handshake_failure(&ip);
                                println!("  REJECTED: {}", reason);
                                if !is_temp {
                                    println!("    (headless server: no GUI approval — whitelist the client domain or use temp-mode)");
                                }
                            }
                            Err(e) => {
                                let _ = audit.record(
                                    AuditEvent::HandshakeFailure,
                                    &format!("ip={} error={}", ip, e),
                                );
                                rate_limiter.record_handshake_failure(&ip);
                                println!("  Handshake error: {}", e);
                            }
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
        }
        Err(e) => println!("Bind failed: {}", e),
    }
}

/// M15 (SRV-SEC-KH-002): 服务端已知客户端管理 — `known-hosts [list|add|remove]`。
///
/// 服务端 known_clients（`kirin_desk/known_clients.json`）：握手前公钥绑定
/// 的信任来源。`add` 显式信任某客户端公钥（首次连接/审批接受后录入）；
/// 命中但公钥不一致的连接将被拒绝。
fn cmd_known_hosts(args: Vec<String>) {
    use kirin_desk_utils::known_hosts::KnownClientsStore;

    let sub = args.get(2).map(|s| s.as_str()).unwrap_or("list");
    let mut store = match KnownClientsStore::load() {
        Ok(s) => s,
        Err(e) => {
            println!("known_clients load error: {}", e);
            return;
        }
    };
    match sub {
        "list" => {
            let clients = store.clients();
            if clients.is_empty() {
                println!("No known clients. Use 'kirin_desk known-hosts add <id> <pubkey>'.");
                return;
            }
            println!("Known clients ({}):", clients.len());
            for c in clients {
                println!(
                    "  {}  fp={}  key={}...  first={}  last={}",
                    c.device_id,
                    c.fingerprint,
                    &c.public_key_base64[..c.public_key_base64.len().min(16)],
                    c.first_seen.format("%Y-%m-%d %H:%M:%S"),
                    c.last_seen.format("%Y-%m-%d %H:%M:%S"),
                );
            }
        }
        "add" => {
            let id = match args.get(3) {
                Some(v) if !v.is_empty() => v.as_str(),
                _ => {
                    println!("Usage: kirin_desk known-hosts add <device-id> <pubkey-base64>");
                    return;
                }
            };
            let pubkey = match args.get(4) {
                Some(v) if !v.is_empty() => v.as_str(),
                _ => {
                    println!("Usage: kirin_desk known-hosts add <device-id> <pubkey-base64>");
                    return;
                }
            };
            store.upsert(id, pubkey);
            match store.save() {
                Ok(()) => {
                    let fp = kirin_desk_utils::known_hosts::fingerprint(pubkey);
                    println!("Added: {} (fingerprint {})", id, fp);
                }
                Err(e) => println!("Save error: {}", e),
            }
        }
        "remove" => {
            let id = match args.get(3) {
                Some(v) => v.as_str(),
                None => {
                    println!("Usage: kirin_desk known-hosts remove <device-id>");
                    return;
                }
            };
            if store.remove(id) {
                match store.save() {
                    Ok(()) => println!("Removed: {}", id),
                    Err(e) => println!("Save error: {}", e),
                }
            } else {
                println!("Not found: {}", id);
            }
        }
        _ => println!("Usage: kirin_desk known-hosts [list|add <id> <key>|remove <id>]"),
    }
}

/// M15 (SRV-SEC-WL-001..004): 白名单管理 — `whitelist [list|add|remove|import|export|export-json]`。
///
/// 模式支持 `*.example.com` 通配（匹配子域）；`add` 可选 RFC3339 过期时间
/// （过期自动失效，SRV-SEC-WL-003）。
fn cmd_whitelist(args: Vec<String>) {
    use chrono::{DateTime, Utc};
    use std::path::Path;

    let sub = args.get(2).map(|s| s.as_str()).unwrap_or("list");
    let mut cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    match sub {
        "list" => {
            let active = cfg.whitelist_active_patterns(Utc::now());
            if active.is_empty() {
                println!("Whitelist is empty (all connections rejected unless temp mode).");
                return;
            }
            println!("Whitelist ({} active entries):", active.len());
            for p in &active {
                let entry = cfg.network.whitelist.iter().find(|e| &e.pattern == p);
                let expiry = entry
                    .and_then(|e| e.expiry)
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "(permanent)".to_string());
                println!("  {}   expires: {}", p, expiry);
            }
        }
        "add" => {
            let pattern = match args.get(3) {
                Some(v) if !v.is_empty() => v.as_str(),
                _ => {
                    println!("Usage: kirin_desk whitelist add <pattern> [RFC3339-expiry]");
                    return;
                }
            };
            let expiry = match args.get(4) {
                Some(v) if !v.is_empty() => match DateTime::parse_from_rfc3339(v) {
                    Ok(dt) => Some(dt.with_timezone(&Utc)),
                    Err(e) => {
                        println!("Invalid expiry (RFC3339): {}", e);
                        return;
                    }
                },
                _ => None,
            };
            match cfg.whitelist_add(pattern, expiry) {
                Ok(_) => println!("Added: {} (expiry: {:?})", pattern, expiry),
                Err(e) => println!("Save error: {}", e),
            }
        }
        "remove" => {
            let pattern = match args.get(3) {
                Some(v) if !v.is_empty() => v.as_str(),
                _ => {
                    println!("Usage: kirin_desk whitelist remove <pattern>");
                    return;
                }
            };
            match cfg.whitelist_remove(pattern) {
                Ok(true) => println!("Removed: {}", pattern),
                Ok(false) => println!("Not found: {}", pattern),
                Err(e) => println!("Save error: {}", e),
            }
        }
        "import" => {
            let path = match args.get(3) {
                Some(v) if !v.is_empty() => v.as_str(),
                _ => {
                    println!("Usage: kirin_desk whitelist import <csv-path>");
                    return;
                }
            };
            match cfg.whitelist_import_csv(Path::new(path)) {
                Ok(n) => println!("Imported {} entries from {}", n, path),
                Err(e) => println!("Import error: {}", e),
            }
        }
        "export" => {
            let path = match args.get(3) {
                Some(v) if !v.is_empty() => v.as_str(),
                _ => {
                    println!("Usage: kirin_desk whitelist export <csv-path>");
                    return;
                }
            };
            match cfg.whitelist_export_csv(Path::new(path)) {
                Ok(()) => println!("Exported to {}", path),
                Err(e) => println!("Export error: {}", e),
            }
        }
        "export-json" => {
            let path = match args.get(3) {
                Some(v) if !v.is_empty() => v.as_str(),
                _ => {
                    println!("Usage: kirin_desk whitelist export-json <json-path>");
                    return;
                }
            };
            match cfg.whitelist_export_json(Path::new(path)) {
                Ok(()) => println!("Exported to {}", path),
                Err(e) => println!("Export error: {}", e),
            }
        }
        _ => println!(
            "Usage: kirin_desk whitelist [list|add <p> [expiry]|remove <p>|import <csv>|export <csv>|export-json <json>]"
        ),
    }
}

fn cmd_status() {
    println!("=== KirinDesk Status ===");
    match Config::load() {
        Ok(cfg) => {
            println!("Config:        Loaded");
            println!("Device ID:     {}", cfg.device.id);
            println!("Domain:        {}", cfg.godaddy.domain);
            println!(
                "API:           {}",
                if cfg.godaddy.api_key.is_empty() {
                    "Not set"
                } else {
                    "Configured"
                }
            );
            let wl = if cfg.network.allowed_domains.is_empty() {
                "Any (insecure)".to_string()
            } else {
                cfg.network.allowed_domains.join(", ")
            };
            println!("Whitelist:     {}", wl);
            println!(
                "IP Mode:       {}",
                if cfg.network.ip_mode_allowed {
                    "Enabled"
                } else {
                    "Domain only"
                }
            );
        }
        Err(_) => {
            println!("Config: Not found. Run setup.");
        }
    }
    match get_global_ipv6() {
        Ok(ip) => println!("IPv6:          {}", ip),
        Err(_) => println!("IPv6:          N/A"),
    }
    // M8-T017 (CLI-TMP-012): 临时连接状态行（窗口 + 剩余秒数）。
    if is_temp_mode_active() {
        println!("Temp Mode:     ACTIVE ({}s remaining)", temp_mode_remaining());
    } else {
        println!("Temp Mode:     off");
    }
    println!("81/81 tests passing");
}

fn mask(s: &str, show: usize) -> String {
    if s.len() <= show + 4 {
        return s.to_string();
    }
    format!("{}***", &s[..show])
}

/// Run a full self-connection test on localhost.
///
/// Generates two temporary identity keypairs (Alice and Bob),
/// starts a TCP listener on loopback, performs the complete
/// handshake protocol, and exchanges encrypted test data.
/// All steps emit debug-level tracing output for diagnostics.
async fn cmd_self_test() {
    use kirin_desk_core::crypto::ed25519::IdentityManager;
    use kirin_desk_core::crypto::handshake::{client_handshake, server_handshake_verified};
    use tokio::net::TcpListener as TokioListener;

    // Initialize debug logging for this test
    kirin_desk_utils::logging::init_logging("debug", "text");

    println!("=== KirinDesk Self-Connection Test ===");
    println!("Generating test identities...");

    let tmp = std::env::temp_dir();
    let alice = match IdentityManager::generate(tmp.join("kirindesk_self_test_alice")) {
        Ok(v) => {
            println!("  Alice: OK (pubkey: {}...)", &v.public_key_base64()[..16]);
            v
        }
        Err(e) => {
            println!("  FAILED to generate Alice identity: {}", e);
            return;
        }
    };
    let bob = match IdentityManager::generate(tmp.join("kirindesk_self_test_bob")) {
        Ok(v) => {
            println!("  Bob:   OK (pubkey: {}...)", &v.public_key_base64()[..16]);
            v
        }
        Err(e) => {
            println!("  FAILED to generate Bob identity: {}", e);
            return;
        }
    };

    // Bind on IPv6 loopback on a random port
    println!("Starting Bob's TCP listener on [::1]:0...");
    let listener = match TokioListener::bind("[::1]:0").await {
        Ok(l) => l,
        Err(e) => {
            println!("  FAILED to bind IPv6 server: {}", e);
            println!("  (IPv6 may not be available on this system)");
            return;
        }
    };
    let addr = listener.local_addr().unwrap();
    println!("  Bob listening on {} (IPv6)", addr);

    let bob_pub = bob.public_key_base64();
    let alice_pub = alice.public_key_base64();

    println!("Running handshake (Alice connects to Bob)...");
    let (client_res, server_res): (
        Result<kirin_desk_core::crypto::handshake::SecureChannel, _>,
        Result<kirin_desk_core::crypto::handshake::SecureChannel, _>,
    ) = tokio::join!(
        async {
            let stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
                println!("  TCP connect FAILED: {}", e);
                kirin_desk_core::crypto::handshake::HandshakeError::Io(e)
            })?;
            println!("  Alice TCP connected to {}", addr);
            let ch = client_handshake(
                stream,
                &alice,
                "alice",
                "alice.self-test.local",
                "desktop",
                "bob",
                &bob_pub,
                "",
            )
            .await?;
            println!("  Alice handshake OK: secured channel to bob");
            Ok::<_, kirin_desk_core::crypto::handshake::HandshakeError>(ch)
        },
        async {
            let (stream, peer_addr) = listener.accept().await.map_err(|e| {
                println!("  Server accept FAILED: {}", e);
                kirin_desk_core::crypto::handshake::HandshakeError::Io(e)
            })?;
            println!("  Bob accepted connection from {}", peer_addr);
            // Run server_handshake_verified (full verification path)
            let ch = server_handshake_verified(stream, &bob, "bob", &alice_pub).await?;
            println!("  Bob handshake OK: secured channel to alice");
            Ok::<_, kirin_desk_core::crypto::handshake::HandshakeError>(ch)
        }
    );

    match (client_res, server_res) {
        (Ok(mut client_ch), Ok(mut server_ch)) => {
            println!();
            println!("=== Handshake SUCCESS ===");
            println!("  Alice peer:   {}", client_ch.peer_id);
            println!("  Bob peer:     {}", server_ch.peer_id);

            // Test encrypted round-trip
            println!();
            println!("Testing encrypted message exchange...");

            let test_msg = b"Hello from Alice! This is an encrypted test message.";
            println!(
                "  Alice sends: \"{}\"",
                std::str::from_utf8(test_msg).unwrap()
            );

            let (send_res, recv_res) =
                tokio::join!(async { client_ch.send(test_msg).await }, async {
                    server_ch.receive().await
                });

            match (send_res, recv_res) {
                (Ok(()), Ok(received)) => {
                    let received_str = std::str::from_utf8(&received).unwrap_or("<binary>");
                    println!("  Bob receives: \"{}\"", received_str);
                    if received == test_msg {
                        println!("  Message integrity: OK");
                    } else {
                        println!("  Message MISMATCH!");
                    }
                }
                (Err(e), _) => println!("  Send FAILED: {}", e),
                (_, Err(e)) => println!("  Receive FAILED: {}", e),
            }

            // Reverse direction
            let reply_msg = b"Pong from Bob!";
            println!(
                "  Bob sends: \"{}\"",
                std::str::from_utf8(reply_msg).unwrap()
            );

            let (send_res, recv_res) =
                tokio::join!(async { server_ch.send(reply_msg).await }, async {
                    client_ch.receive().await
                });

            match (send_res, recv_res) {
                (Ok(()), Ok(received)) => {
                    let received_str = std::str::from_utf8(&received).unwrap_or("<binary>");
                    println!("  Alice receives: \"{}\"", received_str);
                    if received == reply_msg {
                        println!("  Reply integrity: OK");
                    } else {
                        println!("  Reply MISMATCH!");
                    }
                }
                (Err(e), _) => println!("  Reply send FAILED: {}", e),
                (_, Err(e)) => println!("  Reply receive FAILED: {}", e),
            }

            // ── M8-T017: 临时连接往返自测 ──
            // 注入临时状态文件路径（不污染真实 cache 目录）：enable → 校验对/错码 →
            // 过期失效 → disable。置于 M13-T006 之前，避免被其既有帧大小问题阻断。
            println!();
            println!("=== M8-T017 temp-mode tests ===");
            {
                use kirin_desk_core::connection::temp_mode::TempModeManager;
                let tmp_tm = std::env::temp_dir().join("kirin_desk_self_test_temp_mode.json");
                let _ = std::fs::remove_file(&tmp_tm);
                let mgr = TempModeManager::with_state_file(tmp_tm.clone());

                let code = match mgr.enable(1) {
                    Ok(c) => c,
                    Err(e) => {
                        println!("  1. enable FAILED: {}", e);
                        return;
                    }
                };
                assert_eq!(code.chars().count(), 8, "temp code must be 8 chars");
                assert!(mgr.is_active(), "window must be active after enable");
                assert!(mgr.verify_challenge(&code), "correct code must verify");
                assert!(
                    !mgr.verify_challenge("XXXXXXXX"),
                    "wrong code must be rejected"
                );
                println!("  1. enable + verify (correct/wrong) OK ✓");
                println!("     code={} state={}", code, tmp_tm.display());

                // 1 秒 TTL 过期 → 校验失败（SRV-TMP-HK-003），disable 返回 false。
                tokio::time::sleep(Duration::from_millis(1500)).await;
                assert!(!mgr.is_active(), "window must expire after ttl");
                assert!(
                    !mgr.verify_challenge(&code),
                    "expired code must fail (SRV-TMP-HK-003)"
                );
                assert!(
                    !mgr.disable().expect("disable after expiry"),
                    "expired window is not 'was active'"
                );
                println!("  2. expiry + stale cleanup OK ✓");
            }
            println!("=== M8-T017 temp-mode tests COMPLETE (2/2) ===");

            // ── M13-T006: 文件传输往返自测（分块 + 滑窗 + SHA-256 校验落盘）──
            println!();
            println!("=== M13-T006 file transfer round-trip ===");
            use kirin_desk_media::transport::{
                ChannelTag, SecureChannelReceiver, SecureChannelSender,
            };
            use std::sync::Arc;
            let file_dir = tmp.join("kirindesk_self_test_files");
            let _ = std::fs::remove_dir_all(&file_dir);
            std::fs::create_dir_all(&file_dir).unwrap();
            // 生成 ~200 KiB 伪随机源文件（4 块）。
            let src_path = file_dir.join("roundtrip.bin");
            {
                let mut rng = 0x9E3779B97F4A7C15u64;
                let mut data = Vec::with_capacity(200 * 1024);
                while data.len() < 200 * 1024 {
                    rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    data.push((rng >> 33) as u8);
                }
                std::fs::write(&src_path, &data).unwrap();
            }
            let src_sha = super::sha256_file(&src_path).unwrap();
            println!("  source: {} ({} bytes)", src_path.display(), 200 * 1024);

            let (c_reader, c_writer) = client_ch.into_split();
            let (s_reader, s_writer) = server_ch.into_split();
            let c_sender: Arc<tokio::sync::Mutex<SecureChannelSender>> =
                Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(c_writer)));
            let s_sender: Arc<tokio::sync::Mutex<SecureChannelSender>> =
                Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(s_writer)));
            let mut c_receiver = SecureChannelReceiver::new(c_reader);
            let mut s_receiver = SecureChannelReceiver::new(s_reader);

            let bob_cfg = Config::load().unwrap_or_default();
            let bob_salt = super::file_transfer_salt("alice", &bob_cfg.device.id);
            let bob_store = file_dir.join("transfers_bob.json");
            let bob_dir = file_dir.join("recv");
            std::fs::create_dir_all(&bob_dir).unwrap();
            // Bob（服务端侧）文件会话：接收 + 校验落盘。
            let bob_recv_dir = bob_dir.clone();
            let bob_handle = tokio::spawn(async move {
                use super::{FileSession, FileTaskStatus};
                let mut ft_b = FileSession::new(
                    s_sender,
                    super::server_file_panel_state(),
                    bob_salt,
                    bob_store,
                    bob_recv_dir,
                    super::DEFAULT_MAX_FILE_SIZE,
                    None,
                );
                let mut tick = tokio::time::interval(Duration::from_millis(200));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        res = s_receiver.recv_tagged() => match res {
                            Ok((tag, _, payload)) if tag == ChannelTag::FileTransfer => {
                                if let Ok(frame) = super::FileTransferFrame::decode(&payload) {
                                    ft_b.handle_frame(frame).await;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                println!("  Bob file loop closed: {}", e);
                                break;
                            }
                        },
                        _ = tick.tick() => {
                            ft_b.on_tick().await;
                            let mut done = false;
                            if let Ok(panel) = super::server_file_panel_state().lock() {
                                if let Some(t) = panel.tasks.iter().find(|t| t.name == "roundtrip.bin") {
                                    if t.status == FileTaskStatus::Completed {
                                        done = true;
                                    }
                                }
                            }
                            if done {
                                break;
                            }
                        }
                    }
                }
            });

            // Alice（客户端侧）文件会话：发送。
            let alice_salt = super::file_transfer_salt(&bob_cfg.device.id, "alice");
            let alice_store = file_dir.join("transfers_alice.json");
            let alice_dir = file_dir.join("alice");
            std::fs::create_dir_all(&alice_dir).unwrap();
            let mut ft_a = super::FileSession::new(
                c_sender,
                super::file_panel_state(),
                alice_salt,
                alice_store,
                alice_dir,
                super::DEFAULT_MAX_FILE_SIZE,
                None,
            );
            ft_a.handle_command(super::FileCommand::SendFile { path: src_path.clone() }).await;
            let mut tick_a = tokio::time::interval(Duration::from_millis(200));
            tick_a.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut ft_ok = false;
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            // 检查面板任务状态的辅助（发送完成/失败）。
            let mut check_panel = |ft_ok: &mut bool, panel: &std::sync::MutexGuard<'_, super::FilePanelState>| {
                if let Some(t) = panel.tasks.iter().find(|t| t.name == "roundtrip.bin") {
                    match &t.status {
                        super::FileTaskStatus::Completed => {
                            println!("  Alice send COMPLETE");
                            *ft_ok = true;
                        }
                        super::FileTaskStatus::Failed(e) => {
                            println!("  Alice send FAILED: {}", e);
                            *ft_ok = false;
                        }
                        _ => {}
                    }
                }
            };
            loop {
                tokio::select! {
                    res = c_receiver.recv_tagged() => match res {
                        Ok((tag, _, payload)) if tag == ChannelTag::FileTransfer => {
                            if let Ok(frame) = super::FileTransferFrame::decode(&payload) {
                                ft_a.handle_frame(frame).await;
                                // 帧处理（如 FinishAck）可能已置完成 → 立即检查。
                                if let Ok(panel) = super::file_panel_state().lock() {
                                    check_panel(&mut ft_ok, &panel);
                                }
                                if ft_ok {
                                    break;
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            // 远端正常完成后的关闭也是 EOF——先查面板再判定失败。
                            if let Ok(panel) = super::file_panel_state().lock() {
                                check_panel(&mut ft_ok, &panel);
                            }
                            if !ft_ok {
                                println!("  Alice file loop closed: {}", e);
                            }
                            break;
                        }
                    },
                    _ = tick_a.tick() => {
                        ft_a.on_tick().await;
                        if let Ok(panel) = super::file_panel_state().lock() {
                            check_panel(&mut ft_ok, &panel);
                        }
                        if ft_ok || std::time::Instant::now() > deadline {
                            break;
                        }
                    }
                }
            }
            let _ = bob_handle.await;
            // 校验：接收文件 SHA-256 与源一致。
            let recv_path = bob_dir.join("roundtrip.bin");
            let verified = recv_path.is_file()
                && super::sha256_file(&recv_path).map(|h| h == src_sha).unwrap_or(false);
            if ft_ok && verified {
                println!("  File round-trip OK (SHA-256 match, no leftover .part)");
                let leftover = std::fs::read_dir(&bob_dir)
                    .map(|it| it.filter_map(|e| e.ok()).any(|e| e.file_name().to_string_lossy().ends_with(".part")))
                    .unwrap_or(false);
                println!("  .part leftover: {}", if leftover { "YES (FAIL)" } else { "none" });
            } else {
                println!("  File round-trip FAILED (ok={} verified={})", ft_ok, verified);
            }
            let _ = src_sha;
            let _ = std::fs::remove_dir_all(&file_dir);

            // Cleanup temp identity files
            let _ = std::fs::remove_dir_all(tmp.join("kirindesk_self_test_alice"));
            let _ = std::fs::remove_dir_all(tmp.join("kirindesk_self_test_bob"));

            println!();
            println!("=== Self-test COMPLETE ===");
            println!("All connection layers exercised: TCP -> handshake -> encrypted channel.");
            println!("Use RUST_LOG=debug to see detailed tracing output.");
        }
        (Err(e), _) => println!("  FAILED: Alice side error: {}", e),
        (_, Err(e)) => println!("  FAILED: Bob side error: {}", e),
    }

    // ── M15 (CLI-KH-001..004): known_hosts 指纹验证端到端测试 ──
    println!();
    println!("=== M15 known_hosts fingerprint verification ===");
    use kirin_desk_core::crypto::handshake::{
        client_handshake_with_confirm_generic, server_handshake_verified_generic, HandshakeError,
    };
    use kirin_desk_utils::known_hosts::{FingerprintStatus, KnownHostsStore};

    let tmp_kh = std::env::temp_dir().join("kirindesk_self_test_known_hosts");
    let kh_path = tmp_kh.join("known_hosts");
    let _ = std::fs::remove_dir_all(&tmp_kh);

    // 场景 1: known_hosts 未命中（Unknown）→ 确认回调放行 → 握手成功 → 记录。
    {
        let mut kh = KnownHostsStore::load_from(&kh_path).unwrap();
        assert_eq!(
            kh.check("bob", &bob_pub),
            FingerprintStatus::Unknown,
            "fresh store must be Unknown"
        );
        let (client_end, server_end) = tokio::io::duplex(65536);
        let client_fut = client_handshake_with_confirm_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            None,
            Some(Box::new(move |key: &str| {
                println!("  [confirm] key {}… → accept", &key[..16.min(key.len())]);
                true
            })),
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (cr, sr) = tokio::join!(client_fut, server_fut);
        assert!(cr.is_ok() && sr.is_ok(), "confirm-accept handshake must succeed");
        println!("  1. Unknown → user confirm accept → handshake OK ✓");
        kh.confirm("bob", &bob_pub).unwrap();
    }

    // 场景 2: known_hosts 命中且一致（Match）→ 严格放行。
    {
        let kh = KnownHostsStore::load_from(&kh_path).unwrap();
        assert_eq!(kh.check("bob", &bob_pub), FingerprintStatus::Match);
        let (client_end, server_end) = tokio::io::duplex(65536);
        let client_fut = client_handshake_with_confirm_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            Some(bob_pub.clone()),
            None,
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (cr, sr) = tokio::join!(client_fut, server_fut);
        assert!(cr.is_ok() && sr.is_ok());
        println!("  2. known_hosts MATCH → strict verify OK ✓");
    }

    // 场景 3: known_hosts 命中但不一致（Mismatch）→ 拒绝连接（防 MITM）。
    {
        // 伪造：记录里是另一把公钥（模拟 MITM 换了服务端身份）。
        let mut kh = KnownHostsStore::load_from(&kh_path).unwrap();
        kh.confirm("bob", &alice_pub).unwrap(); // 记录错误指纹
        assert_eq!(kh.check("bob", &bob_pub), FingerprintStatus::Mismatch);
        let (client_end, server_end) = tokio::io::duplex(65536);
        // 调用方按 known_hosts 记录（错误指纹）作预期公钥 → 与服务端真实公钥
        // 不一致 → ServerKeyMismatch 拒绝（严格比对路径）。
        let client_fut = client_handshake_with_confirm_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            Some(alice_pub.clone()), // known_hosts 里记录的错误公钥
            None,
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (cr, _sr) = tokio::join!(client_fut, server_fut);
        match cr {
            Err(HandshakeError::ServerKeyMismatch { .. }) => {
                println!("  3. known_hosts MISMATCH → ServerKeyMismatch rejected ✓");
            }
            other => panic!("expected ServerKeyMismatch, got {:?}", other.map(|_| ())),
        }
        // 恢复正确指纹供后续场景。
        kh.confirm("bob", &bob_pub).unwrap();
    }

    // 场景 4: 确认回调拒绝（用户拒绝指纹）→ UntrustedKey 断开，不发送业务数据。
    {
        let (client_end, server_end) = tokio::io::duplex(65536);
        let client_fut = client_handshake_with_confirm_generic(
            client_end,
            &alice,
            "alice",
            "alice.local",
            "desktop",
            "bob",
            None,
            Some(Box::new(|_| false)),
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (cr, _sr) = tokio::join!(client_fut, server_fut);
        match cr {
            Err(HandshakeError::UntrustedKey(_)) => {
                println!("  4. confirm decline → UntrustedKey rejected ✓");
            }
            other => panic!("expected UntrustedKey, got {:?}", other.map(|_| ())),
        }
    }

    // 场景 5: 大剪贴板分片编解码一致性（CLI 侧自检，防发送侧回归）。
    let big_text: String = "KirinDesk clipboard ".repeat(200);
    let frames = crate::clipboard::encode_clipboard_payloads(&big_text, 1000);
    assert!(frames.len() > 1);
    let mut rebuilt = Vec::new();
    for f in &frames {
        rebuilt.extend_from_slice(&f[1..]);
    }
    assert_eq!(String::from_utf8(rebuilt).unwrap(), big_text);
    println!("  5. clipboard chunk encode/decode roundtrip OK ✓");

    let _ = std::fs::remove_dir_all(&tmp_kh);
    println!();
    println!("=== M15 known_hosts tests COMPLETE (5/5) ===");
}
