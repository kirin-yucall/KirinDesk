use kirin_desk_core::connection::temp_mode::TempModeManager;
use kirin_desk_core::network::ipv6::get_global_ipv6;
use kirin_desk_core::network::tcp::TcpServer;
use kirin_desk_dns::aaaa::AaaaManager;
use kirin_desk_dns::godaddy::GoDaddyClient;
use kirin_desk_dns::srv::SrvManager;
use kirin_desk_dns::txt::{DeviceMeta, TxtManager};
use kirin_desk_dns::{DiscoveryService, IpFamily};
use kirin_desk_media::transport::TransportMode;
use kirin_desk_utils::config::Config;
use std::net::Ipv6Addr;
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

// ════════════════════════════════════════════════════════════════
// M8-T026-P2：设备 ID 连接模式（ID-010~015 / ID-020 / ID-022）
// ════════════════════════════════════════════════════════════════

/// `connect --id <device_id>`：ID 解析 → 验签 → 公钥 pin → 三级路径
/// （① 直连候选 → ② 打洞 hook（P1 并行开发）→ ③ 中继兜底）→ Ed25519 握手。
///
/// 依赖 `[tunnel] server_addr / token / server_pubkey` 配置（ID-014）：
/// 缺失时提示改用 domain/IP 模式，不阻塞其他模式。
async fn cmd_connect_id(device_id: &str) {
    use kirin_desk_core::connection::id_mode::{IdConnectError, IdConnector, IdModeConfig};
    use kirin_desk_core::crypto::handshake::{
        client_handshake_with_confirm, CoreReason, PinExpectation,
    };
    use kirin_desk_utils::audit::AuditEvent;
    use std::sync::{Arc, Mutex};

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
    let tunnel = &cfg.tunnel;
    // ID-014：ID 模式需服务器配置；缺失 → 明确提示，不阻塞其他模式。
    if tunnel.server_addr.trim().is_empty() || tunnel.token.is_empty() {
        println!("ERROR: ID mode requires `[tunnel] server_addr` and `[tunnel] token`.");
        println!("  Configure them first (or use domain/IP connect modes).");
        return;
    }
    let server_pubkey = match tunnel.server_pubkey.as_deref() {
        Some(k) if !k.trim().is_empty() => k,
        _ => {
            println!("ERROR: ID mode requires `[tunnel] server_pubkey` (relay server's Ed25519 public key).");
            println!("  It is printed when the relay server starts (`tunnel serve`).");
            return;
        }
    };
    let connector = match IdModeConfig::try_new(&tunnel.server_addr, &tunnel.token, server_pubkey) {
        Ok(c) => IdConnector::new(c),
        Err(e) => {
            println!("ERROR: ID mode config invalid: {}", e);
            return;
        }
    };
    let server_id = cfg
        .device
        .nickname
        .trim()
        .split_whitespace()
        .next()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "id-connect".to_string());
    println!(
        "Resolving device '{}' via relay {}...",
        device_id, tunnel.server_addr
    );
    // ID-010：解析 + ID-SEC-001 验签。
    let info = match connector.resolve(device_id).await {
        Ok(i) => i,
        Err(IdConnectError::SignatureVerification) => {
            println!("ERROR: relay server response signature verification FAILED (ID-SEC-001).");
            println!("  Possible MITM or wrong `server_pubkey` — connection refused.");
            audit_temp_event(
                AuditEvent::DeviceResolveRejected,
                &format!("device={} reason=signature_verification_failed", device_id),
            );
            return;
        }
        Err(IdConnectError::ServerUnreachable(e)) => {
            println!("ERROR: relay server unreachable: {}", e);
            println!("  Check `[tunnel] server_addr` / network (ID mode only).");
            return;
        }
        Err(e) => {
            println!("ERROR: resolve failed: {}", e);
            return;
        }
    };
    // ID-010：离线/未知统一文案（ID-SEC-002 防枚举）。
    if !IdConnector::is_connectable(&info) {
        println!(
            "ERROR: device '{}' is offline or not registered.",
            device_id
        );
        audit_temp_event(
            AuditEvent::DeviceResolveRejected,
            &format!("device={} reason=offline_or_unknown", device_id),
        );
        return;
    }
    audit_temp_event(
        AuditEvent::DeviceResolveAccepted,
        &format!(
            "device={} online=true candidates={}",
            device_id,
            info.payload.candidates.len()
        ),
    );
    println!(
        "  Resolved: '{}' candidates={} pubkey={}...",
        device_id,
        info.payload.candidates.len(),
        &info.payload.ed25519_pub[..std::cmp::min(16, info.payload.ed25519_pub.len())]
    );
    // ID-012：公钥 pin（known_hosts 优先 / 首次指纹确认，对齐 CLI-KH-004）。
    let trusted_key = match cli_resolve_trust(device_id, &info.payload.ed25519_pub) {
        CliTrust::Verified(key) => key,
        CliTrust::Rejected(reason) => {
            println!("Connection aborted: {}", reason);
            audit_temp_event(
                AuditEvent::AuthFailure,
                &format!("device={} reason={}", device_id, reason),
            );
            return;
        }
    };
    // ID-011：三级路径编排（直连 → 打洞 hook → 中继兜底）。
    let from_peer = tunnel.device_id.clone().unwrap_or_else(|| {
        kirin_desk_utils::known_hosts::fingerprint(&identity.public_key_base64())
    });
    let (path, stream) = match connector.connect_stream(&info, &from_peer).await {
        Ok(x) => x,
        Err(e) => {
            println!("ERROR: all connection paths failed: {}", e);
            return;
        }
    };
    println!("  Path selected: {}", path);
    audit_temp_event(
        AuditEvent::TunnelPathSelected,
        &format!("device={} path={}", device_id, path),
    );
    // ID-013：任何路径上仍是 Ed25519 双向握手（公钥 pin 强制比对）。
    let confirmed_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let confirmed_key_cb = confirmed_key.clone();
    let server_id_cb = server_id.clone();
    let key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>> = Some(Box::new(move |key: &str| {
        let ok = cli_confirm_callback(&server_id_cb)(key);
        if ok {
            if let Ok(mut ck) = confirmed_key_cb.lock() {
                *ck = Some(key.to_string());
            }
        }
        ok
    }));
    let challenge = if cfg.device.challenge_code.is_empty() {
        String::new()
    } else {
        cfg.device.challenge_code.clone()
    };
    // R-02：pin 强类型——known_hosts 已确认公钥 → `Exact` 强制比对（ID-012）。
    let pin = match PinExpectation::exact_from_base64(&trusted_key) {
        Ok(p) => p,
        Err(e) => {
            println!("ERROR: invalid trusted key: {}", e);
            return;
        }
    };
    let ch = match client_handshake_with_confirm(
        stream,
        &identity,
        &cfg.device.id,
        "", // ID 模式无域名（设备侧走挑战码/临时码访问控制，ID-013）
        "desktop",
        &server_id,
        pin,
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
    println!(
        "✓ Connected to {}@{} (path: {}, selected codec: {})",
        ch.peer_id, device_id, path, ch.selected_codec
    );
    let key = confirmed_key
        .lock()
        .ok()
        .and_then(|k| k.clone())
        .unwrap_or(trusted_key);
    cli_record_connection(device_id, &server_id, &key, "desktop", "");
    drop(ch);
    println!("  (CLI mode cannot render the remote desktop; use the GUI for desktop sessions.)");
}

/// R-11: CLI 子命令枚举（dispatch 抽取为可测纯函数）。
///
/// R-09（波次 2）将在此枚举追加 `Identity`/`Version` 变体——只增不改，
/// 并同步更新 `parse_cli_command` 与 `print_help`。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum CliCommand {
    Help,
    Setup,
    Config,
    Register,
    Discover,
    Connect,
    Send,
    Recv,
    Shell,
    Serve,
    KnownHosts,
    Whitelist,
    TempMode,
    Unattended,
    Autostart,
    Tunnel,
    Status,
    SelfTest,
    /// 未识别命令（保留原文供报错/help；无子命令时为空串）。
    Unknown(String),
}

/// R-11: 从 argv 解析子命令（`args[1]`；未知/缺失 → `Unknown`）。
pub(crate) fn parse_cli_command(args: &[String]) -> CliCommand {
    match args.get(1).map(|s| s.as_str()) {
        Some("help") | Some("--help") | Some("-h") => CliCommand::Help,
        Some("setup") => CliCommand::Setup,
        Some("config") => CliCommand::Config,
        Some("register") => CliCommand::Register,
        Some("discover") => CliCommand::Discover,
        Some("connect") => CliCommand::Connect,
        Some("send") => CliCommand::Send,
        Some("recv") => CliCommand::Recv,
        Some("shell") => CliCommand::Shell,
        Some("serve") => CliCommand::Serve,
        Some("known-hosts") => CliCommand::KnownHosts,
        Some("whitelist") => CliCommand::Whitelist,
        Some("temp-mode") => CliCommand::TempMode,
        Some("unattended") => CliCommand::Unattended,
        Some("autostart") => CliCommand::Autostart,
        Some("tunnel") => CliCommand::Tunnel,
        Some("status") => CliCommand::Status,
        Some("self-test") => CliCommand::SelfTest,
        Some(other) => CliCommand::Unknown(other.to_string()),
        None => CliCommand::Unknown(String::new()),
    }
}

pub async fn run_cli() {
    let args: Vec<String> = std::env::args().filter(|a| a != "--cli").collect();
    if args.len() < 2 {
        print_help();
        return;
    }
    match parse_cli_command(&args) {
        CliCommand::Help => print_help(),
        CliCommand::Setup => cmd_setup(),
        CliCommand::Config => cmd_config(),
        CliCommand::Register => {
            cmd_register(
                args.get(2).map(|s| s.as_str()).unwrap_or("default-device"),
                args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3389),
            )
            .await;
        }
        CliCommand::Discover => {
            if let Some(id) = args.get(2) {
                cmd_discover(id).await;
            } else {
                println!("Usage: kirin_desk discover <device-id>");
            }
        }
        CliCommand::Connect => {
            // M8-T026-P2 (ID-020)：`--id <device_id>` 与 domain/IP 位置参数互斥。
            if let Some(pos) = args.iter().position(|a| a == "--id") {
                let device_id = args.get(pos + 1).map(|s| s.as_str()).unwrap_or("");
                if device_id.is_empty() || args.len() > pos + 2 {
                    println!("Usage: kirin_desk connect --id <device_id>  (cannot combine with domain/IP positional args)");
                    return;
                }
                cmd_connect_id(device_id).await;
            } else {
                cmd_connect(args).await;
            }
        }
        // M13-T006: 文件传输（双向，复用 SecureChannel 加密通道）。
        CliCommand::Send => {
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
        CliCommand::Recv => {
            let host = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3389);
            let nickname = args.get(4).map(|s| s.as_str()).unwrap_or("");
            if host.is_empty() {
                println!("Usage: kirin_desk recv <host> [port] [nickname]");
                return;
            }
            cmd_recv_file(host, port, nickname).await;
        }
        CliCommand::Shell => {
            // M11: `shell [port]` = 服务器模式（向后兼容）；`shell <host> [port] [nickname]` = 客户端模式。
            // S-01d (F-1): `--allow-no-challenge` 显式 opt-in——challenge_code 为空
            // 时默认拒绝启动（fail-closed），仅显式传旗标才放行（带高危警告）。
            let allow_no_challenge = args.iter().any(|a| a == "--allow-no-challenge");
            match args.get(2).and_then(|s| s.parse::<u16>().ok()) {
                Some(port) => cmd_shell_server(port, allow_no_challenge).await,
                None => {
                    let host = args.get(2).map(|s| s.as_str()).unwrap_or("");
                    if host.is_empty() {
                        println!(
                            "Usage: kirin_desk shell <host> [port] [nickname]   (client mode)"
                        );
                        println!(
                            "       kirin_desk shell [port]                      (server mode)"
                        );
                        return;
                    }
                    let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(22);
                    let nickname = args.get(4).map(|s| s.as_str()).unwrap_or("");
                    cmd_shell_client(host, port, nickname).await;
                }
            }
        }
        CliCommand::Serve => {
            // M13-T005 (UA-CLI-003): `serve [port] [--unattended]` — 无人值守
            // 策略运行（自动接受 known_clients/白名单，未知拒绝，temp-mode 禁用）。
            // R-14-S5：`KIRINDESK_HEADLESS=1`（release/debian/kirindesk.service
            // 环境变量）等价于 `--unattended`——无头服务器跳过 GUI 审批弹窗
            // （无桌面会话时必需，service 注释承诺的语义）。
            let unattended = args.iter().any(|a| a == "--unattended")
                || std::env::var("KIRINDESK_HEADLESS").as_deref() == Ok("1");
            let port = args
                .iter()
                .find_map(|a| a.parse::<u16>().ok())
                .unwrap_or(3389);
            // R-04：`serve --no-audio`（被控端不采集/不发送音频；CLI 覆盖 Settings）。
            // S-01d (F-1): `--allow-no-challenge` 显式 opt-in（同 shell 服务器）——
            // 需在 `strip_audio_flag`（move args）之前读取。
            let allow_no_challenge = args.iter().any(|a| a == "--allow-no-challenge");
            strip_audio_flag(args);
            cmd_serve(port, unattended, allow_no_challenge).await;
        }
        CliCommand::KnownHosts => cmd_known_hosts(args),
        CliCommand::Whitelist => cmd_whitelist(args),
        CliCommand::TempMode => {
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
        CliCommand::Unattended => cmd_unattended(args),
        CliCommand::Autostart => cmd_autostart(args),
        CliCommand::Tunnel => cmd_tunnel(args).await,
        CliCommand::Status => cmd_status(),
        CliCommand::SelfTest => cmd_self_test().await,
        CliCommand::Unknown(cmd) => {
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
    println!("  connect <t> [p] [n] Connect to device — domain: DNS discovery + TXT key");
    println!("                                     binding; IPv6: known_hosts / first-use confirm");
    println!("                                     challenge: interactive prompt (TTY, hidden input)");
    println!("                                     or --challenge-stdin (pipe; never on cmdline, F-16)");
    println!("                                     [--transport auto|quic|tcp] [--ip-family auto|ipv4|ipv6]");
    println!("                                     [--no-audio]  (R-04: disable session audio)");
    println!("  send <path> <host> [p] [n] Send a file to the remote (encrypted, resume-able)");
    println!("  recv <host> [p] [n]        Receive files pushed by the remote");
    println!("  shell [port]         Remote shell server (domain/ID whitelist enforced)");
    println!("  shell <host> [p] [n] Connect to a remote shell (PTY mode)");
    println!(
        "  serve [port] [--unattended]  Start listening (unattended: auto-accept known/whitelist)"
    );
    println!("                        [--no-audio]  (R-04: host does not capture/send audio)");
    println!("  known-hosts          List known clients (server-side trusted keys)");
    println!("  known-hosts add <id> <pubkey-base64>  Trust a client key (SRV-SEC-KH-002)");
    println!("  known-hosts remove <id>               Remove a trusted client");
    println!("  whitelist            List whitelist entries (SRV-SEC-WL / M8-T027)");
    println!(
        "  whitelist add <pattern> [expiry]      Add domain (expiry: RFC3339 or empty=permanent)"
    );
    println!("  whitelist remove <pattern>            Remove a domain entry");
    println!(
        "  whitelist add-id <device-id> [expiry] Add device ID (exact match; `*` suffix = prefix)"
    );
    println!("  whitelist remove-id <device-id>       Remove a device ID entry");
    println!("  whitelist import <csv>  /  whitelist export <csv> / whitelist export-json <json>");
    println!("                                     (CSV: domain lines + `id:<device-id>[,expiry]` lines)");
    println!(
        "  temp-mode [off]      Enable temp mode (5 min): temp challenge code + whitelist bypass"
    );
    println!("  unattended <on|off|status>  Unattended mode: auto-accept known/whitelisted");
    println!("                       clients, auto-start server, no approval dialogs");
    println!("  autostart <enable|disable|status>  OS user-level boot autostart");
    println!("  tunnel start           Run tunnel client (frpc): map local TCP services");
    println!("                         to the public relay server ([tunnel] config)");
    println!("  tunnel serve           Run tunnel server (frps) on this machine");
    println!("                         (control port + proxy port range; Ctrl+C to stop)");
    println!("  tunnel status          Show tunnel configuration and proxy list");
    println!("  self-test            Run local self-connection test");
    println!("  status               Show system status");
    println!("  help                 Show this help");
    println!();
    println!("EXAMPLES:");
    println!("  kirin_desk setup");
    println!("  kirin_desk connect my-pc.example.com");
    println!("  kirin_desk connect my-pc.example.com 3389 --transport tcp --ip-family ipv4");
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

// ════════════════════════════════════════════════════════════════
// M8-T025 P5-4：传输参数解析（CLI 覆盖配置；无参保持 auto 现状）
// ════════════════════════════════════════════════════════════════

/// 从参数表取出 `--flag <value>`（无该 flag → None）。
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// 剔除 `--transport` / `--ip-family` 参数对，恢复纯位置参数
/// （`connect <t> [p] [n]` 语义不变；flag 可出现在任意位置）。
fn strip_transport_flags(args: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        if (args[i] == "--transport" || args[i] == "--ip-family") && i + 1 < args.len() {
            i += 2;
            continue;
        }
        out.push(args[i].clone());
        i += 1;
    }
    out
}

/// 布尔 flag 是否存在（`--no-audio` 等无值 flag；与 `flag_value` 互补）。
fn flag_present(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// R-04：解析 `--no-audio` 并应用到会话级开关（CLI 覆盖 Settings 默认值；
/// 无该 flag → 保持现状）。返回剔除该 flag 后的参数表。
fn strip_audio_flag(args: Vec<String>) -> Vec<String> {
    let no_audio = flag_present(&args, "--no-audio");
    if no_audio {
        crate::set_audio_enabled(false);
        println!("  [Audio] session audio DISABLED (--no-audio)");
    }
    args.into_iter().filter(|a| a != "--no-audio").collect()
}

/// S-13 (F-16)：解析 `--challenge-stdin`（布尔 flag，无值）并剔除，
/// 恢复纯位置参数（`connect <t> [p] [n]` 语义不变；flag 可出现在任意位置）。
/// 返回（是否从 stdin 读挑战码, 剔除后的参数表）。
fn strip_challenge_flag(args: Vec<String>) -> (bool, Vec<String>) {
    let challenge_stdin = flag_present(&args, "--challenge-stdin");
    let args = args
        .into_iter()
        .filter(|a| a != "--challenge-stdin")
        .collect();
    (challenge_stdin, args)
}

/// 解析传输模式字符串 →（起始模式, 是否允许失败回退）：
/// `auto` = QUIC 优先 + 失败回退 TCP；`quic`/`tcp` = 强制（B1 可控）。
fn resolve_transport_mode(s: &str) -> Option<(TransportMode, bool)> {
    match s {
        "auto" => Some((TransportMode::Quic, true)),
        "quic" => Some((TransportMode::Quic, false)),
        "tcp" => Some((TransportMode::Tcp, false)),
        _ => None,
    }
}

/// 解析地址族字符串 → `IpFamily`（A4：auto = IPv6 优先，无 v6 用 v4）。
fn resolve_ip_family(s: &str) -> Option<IpFamily> {
    match s {
        "auto" => Some(IpFamily::Auto),
        "ipv4" => Some(IpFamily::Ipv4),
        "ipv6" => Some(IpFamily::Ipv6),
        _ => None,
    }
}

/// M8-T017: 开启临时连接（SRV-TMP-001/002 / CLI-TMP-010）——生成 10 位临时
/// 挑战码（S-20 / F-25：8 → 10），窗口期内白名单跳过且连接须携带该码。
/// 明文码仅在本次输出一次
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
            println!("Temp mode ACTIVE for {}s ({} min)", ttl, ttl / 60);
            println!("  Whitelist bypassed — any client holding this code can connect.");
            println!(
                "  The code is shown ONCE here; it is never stored in plaintext (TMP-SEC-001)."
            );
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

    // S-01e (F-1): 挑战码为服务端核心凭据（必填，安全）——允许跳过但给出
    // 显著警告：留空时 `shell`/`serve` 将拒绝启动（除非显式 --allow-no-challenge）。
    print!("Challenge code (REQUIRED for server auth, F-1): ");
    io::stdout().flush().ok();
    input.clear();
    io::stdin().read_line(&mut input).ok();
    if !input.trim().is_empty() {
        cfg.device.challenge_code = input.trim().to_string();
    } else {
        println!("  ⚠ HIGH-RISK WARNING: no challenge code set — the server will REFUSE to start");
        println!(
            "    ('shell'/'serve' fail-closed on empty challenge, F-1), unless you explicitly"
        );
        println!("    pass --allow-no-challenge (zero-credential connections rejected, NOT recommended).");
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
            println!("API Key:       {}", mask(&c.godaddy.api_key));
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
            println!(
                "Identity error: {}. (run 'kirin_desk connect' once to generate)",
                e
            );
            return;
        }
    };
    let pubkey = identity.public_key_base64();
    let meta = DeviceMeta::new(&pubkey);
    println!(
        "  TXT key: {}...",
        &pubkey[..std::cmp::min(20, pubkey.len())]
    );
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
            // M8-T025 P5-4：哨兵 IPv6（`::` = 无 v6）不再直打；双栈地址如实展示。
            println!(
                "IPv6:      {}",
                if info.ipv6_addr == Ipv6Addr::UNSPECIFIED {
                    "none".to_string()
                } else {
                    info.ipv6_addr.to_string()
                }
            );
            println!(
                "IPv4:      {}",
                info.ipv4_addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "none".to_string())
            );
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
            // UA-SEC-003 (D3): 软警告——无白名单（域名 + ID，M8-T027）且无
            // known_clients 时开启将拒绝一切连接。
            let now = chrono::Utc::now();
            let wl = cfg.whitelist_active_patterns(now);
            let id_wl = cfg.id_whitelist_active_ids(now);
            let known_count = KnownClientsStore::load()
                .map(|k| k.clients().len())
                .unwrap_or(0);
            if wl.is_empty() && id_wl.is_empty() && known_count == 0 {
                println!("  ⚠ WARNING: no whitelist entries and no known clients — in unattended mode ALL connections will be REJECTED.");
                println!("    (add via 'kirin_desk whitelist add <pattern>', 'kirin_desk whitelist add-id <device-id>', or 'kirin_desk known-hosts add <id> <pubkey>')");
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
            println!("  auto_start_server:  {}", cfg.unattended.auto_start_server);
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
                println!(
                    "Autostart ENABLED — KirinDesk will start at OS user login (--autostart)."
                );
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
    println!(
        "  First connection to '{}'. Verify this fingerprint with the device owner:",
        device_id
    );
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
fn cli_record_connection(
    addr: &str,
    server_id: &str,
    pubkey: &str,
    device_type: &str,
    domain: &str,
) {
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
        // M8-T037: 新字段默认值（CLI 自动保存路径不设备注/挑战码/排序）。
        remark: String::new(),
        challenge: String::new(),
        sort_order: 0,
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

/// S-13 (F-16)：裁剪单行输入的尾随行终止符（`\n` / `\r\n` / `\r`），
/// 保留行内空白（挑战码本身可能含空白；仅管道换行需剥离）。
fn trim_challenge_line(s: &str) -> String {
    s.trim_end_matches(|c| c == '\n' || c == '\r').to_string()
}

/// S-13 (F-16)：从 stdin 读一行挑战码（`--challenge-stdin` 管道场景），
/// 裁剪尾随换行；EOF/空行 → 空串（调用方回退配置值）。
fn read_challenge_from_stdin(reader: &mut impl std::io::BufRead) -> std::io::Result<String> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(trim_challenge_line(&line))
}

/// S-13 (F-16)：交互式提示读取挑战码——**不回显**（rpassword 跨平台实现；
/// 挑战码不得再经命令行传递，F-16）。
fn prompt_challenge_interactive() -> std::io::Result<String> {
    use rpassword::prompt_password;
    prompt_password("Challenge code (hidden input): ")
}

/// S-13 (F-16)：挑战码获取策略（入口级防护，调用方负责落参）——
/// - `--challenge-stdin` → 从 `reader` 读一行（裁剪尾随换行）；
/// - TTY → `prompt`（不回显交互输入）；
/// - 非 TTY 且无 flag → `Err`（拒绝连接并提示管道用法；不泄露凭据细节）。
/// 返回空串表示用户未提供（调用方回退 `cfg.device.challenge_code`）。
fn acquire_challenge(
    challenge_stdin: bool,
    is_tty: bool,
    reader: &mut impl std::io::BufRead,
    prompt: impl FnOnce() -> std::io::Result<String>,
) -> Result<String, String> {
    if challenge_stdin {
        return read_challenge_from_stdin(reader)
            .map_err(|e| format!("ERROR: failed to read challenge from stdin: {}", e));
    }
    if is_tty {
        return prompt()
            .map_err(|e| format!("ERROR: failed to read challenge from terminal: {}", e));
    }
    Err(
        "ERROR: no interactive terminal and no '--challenge-stdin' — cannot obtain the challenge code.\n  \
         Pipe it via stdin, e.g.: 'echo <code> | kirin_desk connect <host> --challenge-stdin'\n  \
         (F-16: never pass the challenge code on the command line — it is visible to other users.)"
            .to_string(),
    )
}

/// M15 (CLI-DNS-SEC-004): CLI `connect` 全链路 — 发现 → 信任解析 → 握手 → 保存设备。
///
/// - Domain 模式：`discover`（SRV 端口 + AAAA IPv6 + TXT 公钥）→ known_hosts/DNS TXT
///   公钥绑定（CLI-KH-004 优先级）→ 握手 → 自动保存设备（CLI-DEV-001）；
///   TXT 公钥缺失/解析失败 → **拒绝连接**（CLI-DNS-006）。
/// - IP 模式：known_hosts 命中自动放行 / 首次指纹交互确认（CLI-HSK-SEC-003）；
///   非 TTY 且未命中 → 拒绝。
/// - 昵称来自命令行（CLI-DEV-006，不落盘）；挑战码**不再接受命令行位置参数**
///   （S-13/F-16）：TTY 下 stdin 交互输入（不回显），或 `--challenge-stdin` 管道，
///   空输入回退配置值。
async fn cmd_connect(args: Vec<String>) {
    use kirin_desk_core::connection::client::{
        connect_peer, resolve_peer, ConnectError, ConnectionOptions, DnsConfig, TrustPolicy,
    };
    use std::io::IsTerminal;
    use std::net::IpAddr;

    // ── M8-T025 P5-4：`--transport` / `--ip-family`（CLI 覆盖配置；无参保持 auto）──
    let transport_flag = flag_value(&args, "--transport");
    let family_flag = flag_value(&args, "--ip-family");
    let args = strip_transport_flags(args);
    // R-04：`--no-audio`（会话级音频开关，CLI 覆盖 Settings；无参保持默认开）。
    let args = strip_audio_flag(args);
    // S-13 (F-16)：`--challenge-stdin`（管道场景；布尔 flag 无值）——先剔除，
    // 恢复纯位置参数语义（connect <t> [p] [n]）。
    let (challenge_stdin, args) = strip_challenge_flag(args);

    let target = args.get(2).map(|s| s.as_str()).unwrap_or("");
    let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3389);
    let nickname = args.get(4).map(|s| s.as_str()).unwrap_or("");
    let leftover_challenge = args.get(5).map(|s| s.as_str()).unwrap_or("");

    if target.is_empty() {
        println!("Usage: kirin_desk connect <domain|ipv6> [port] [nickname] [--challenge-stdin] [--transport auto|quic|tcp] [--ip-family auto|ipv4|ipv6] [--no-audio]");
        return;
    }
    // S-13 (F-16)：挑战码位置参数不再接受——进程命令行在 Windows 下其他用户
    // 可读（WMI/任务管理器），明文传递即泄露凭据 → fail-closed 拒绝。
    if !leftover_challenge.is_empty() {
        println!("ERROR: passing the challenge code as a positional argument is no longer supported (F-16).");
        println!("  It is visible to other users in the process command line on Windows.");
        println!("  Provide it interactively (TTY), or pipe it via: '... | kirin_desk connect <host> --challenge-stdin'");
        return;
    }
    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    // 传输模式/地址族解析（CLI > 配置；非法值 → 明确报错，先于身份/网络步骤）。
    let transport_mode_str = transport_flag
        .as_deref()
        .unwrap_or(cfg.transport.mode.as_str());
    let (transport_mode, _fallback) = match resolve_transport_mode(transport_mode_str) {
        Some(r) => r,
        None => {
            println!("ERROR: invalid --transport '{transport_mode_str}' (expected auto|quic|tcp)");
            return;
        }
    };
    let ip_family_str = family_flag
        .as_deref()
        .unwrap_or(cfg.transport.ip_family.as_str());
    let ip_family = match resolve_ip_family(ip_family_str) {
        Some(f) => f,
        None => {
            println!("ERROR: invalid --ip-family '{ip_family_str}' (expected auto|ipv4|ipv6)");
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
    // 昵称：显式传入 > 目标主机。
    let server_id = if nickname.is_empty() {
        target.to_string()
    } else {
        nickname.to_string()
    };
    // S-13 (F-16)：挑战码入口——`--challenge-stdin` 管道 / TTY 交互（不回显）/
    // 非 TTY 无 flag 拒绝连接；空输入回退配置值（CLI-DEV-006 语义不变）。
    let challenge = match acquire_challenge(
        challenge_stdin,
        std::io::stdin().is_terminal(),
        &mut std::io::stdin().lock(),
        prompt_challenge_interactive,
    ) {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => cfg.device.challenge_code.clone(),
        Err(msg) => {
            println!("{}", msg);
            return;
        }
    };
    let device_type = "desktop";

    let is_ip = target.parse::<IpAddr>().is_ok() || target.contains(':');
    // R-03 (R03-S1)：链路参数化——DNS 配置与信任策略按模式组装，链路主体
    // （discover → TXT 公钥校验 → known_hosts/确认 → pin 握手 → SecureChannel）
    // 抽取至 `core::connection::client`，供 CLI / GUI / 断线重连共用。
    let dns = if is_ip {
        None
    } else {
        if cfg.godaddy.api_key.is_empty() {
            println!("GoDaddy API not configured. Run 'kirin_desk setup' first.");
            return;
        }
        Some(DnsConfig {
            api_key: cfg.godaddy.api_key.clone(),
            api_secret: cfg.godaddy.api_secret.clone(),
            api_url: cfg.godaddy.api_url.clone(),
            domain: cfg.godaddy.domain.clone(),
            ip_family,
        })
    };
    // 确认回调共享槽（IP 模式：确认放行的公钥供握手成功后写入 known_hosts，CLI-KH-002）。
    let confirmed_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let confirmed_key_cb = confirmed_key.clone();
    let server_id_cb = server_id.clone();
    let opts = ConnectionOptions {
        target: target.to_string(),
        port,
        server_id: server_id.clone(),
        challenge: challenge.clone(),
        device_type: device_type.to_string(),
        client_identity: Arc::new(identity),
        client_id: cfg.device.id.clone(),
        // 客户端域名：IP 模式 = 目标（既有行为）；domain 模式留空由链路推导。
        client_domain: if is_ip {
            target.to_string()
        } else {
            String::new()
        },
        dns,
        trust: if is_ip {
            // 确认回调：known_hosts 命中自动放行 / 未命中交互确认（CLI-KH-003）。
            TrustPolicy::Confirm(Some(Arc::new(move |key: &str| {
                let ok = cli_confirm_callback(&server_id_cb)(key);
                if ok {
                    if let Ok(mut ck) = confirmed_key_cb.lock() {
                        *ck = Some(key.to_string());
                    }
                }
                ok
            })))
        } else {
            // 信任解析：known_hosts 优先于 DNS TXT（CLI-KH-004）；未命中首次确认。
            TrustPolicy::Resolve(Arc::new(
                |device_id: &str, key: &str| match cli_resolve_trust(device_id, key) {
                    CliTrust::Verified(k) => Ok(k),
                    CliTrust::Rejected(reason) => Err(reason),
                },
            ))
        },
    };

    if !is_ip {
        // ── Domain 模式：发现 → 信任解析 → 握手（R03-S1 抽取链路）──
        let device_id = target
            .trim_end_matches(&format!(".{}", cfg.godaddy.domain))
            .to_string();
        println!("Discovering '{}' on {}...", device_id, cfg.godaddy.domain);
        let peer = match resolve_peer(&opts).await {
            Ok(p) => p,
            Err(e) => {
                // CLI-DNS-005: 设备未注册 / DNS 无响应 → 明确错误中止。
                println!("{}", e);
                println!("  (device not registered, or DNS/GoDaddy API unavailable)");
                return;
            }
        };
        let Some(info) = &peer.discovered else {
            println!("ERROR: discovery returned no device info");
            return;
        };
        println!(
            "Discovered: {} IPv6={} IPv4={} :{} type={}",
            info.device_id,
            if info.ipv6_addr == Ipv6Addr::UNSPECIFIED {
                "none".to_string()
            } else {
                info.ipv6_addr.to_string()
            },
            info.ipv4_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "none".to_string()),
            info.port,
            info.device_type
        );
        println!(
            "  TXT pubkey: {}...",
            &info.public_key_base64[..std::cmp::min(20, info.public_key_base64.len())]
        );
        // 客户端域名 = 目标域名（服务端白名单按此匹配）。
        let client_domain = format!("{}.{}", peer.device_id, cfg.godaddy.domain);
        println!(
            "Connecting {} (domain: {}, transport: {transport_mode:?}) as '{}'...",
            peer.addr, client_domain, server_id
        );
        let outcome = match connect_peer(&opts, &peer).await {
            Ok(o) => o,
            Err(e) => {
                println!("{}", e);
                if let ConnectError::Handshake(_) = &e {
                    if let Some(h) = crate::policy::connect_failure_challenge_hint(&challenge) {
                        println!("{}", h);
                    }
                }
                return;
            }
        };
        println!(
            "✓ Connected to {}@{} (selected codec: {}, transport: {})",
            outcome.channel.peer_id, peer.addr, outcome.channel.selected_codec, transport_mode_str
        );
        if let Some(key) = &outcome.trusted_key {
            cli_record_connection(
                &peer.addr,
                &peer.device_id,
                key,
                &peer.device_type,
                &cfg.godaddy.domain,
            );
        }
        drop(outcome.channel);
        if peer.device_type == "server" {
            println!("  This is a headless server — use 'kirin_desk shell <host> [port] [nickname]' for an interactive terminal.");
        } else {
            println!(
                "  (CLI mode cannot render the remote desktop; use the GUI for desktop sessions.)"
            );
        }
    } else {
        // ── IP 模式：known_hosts / 首次指纹确认 → 握手（R03-S1 抽取链路）──
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
        let peer = match resolve_peer(&opts).await {
            Ok(p) => p,
            Err(e) => {
                println!("{}", e);
                return;
            }
        };
        let outcome = match connect_peer(&opts, &peer).await {
            Ok(o) => o,
            Err(e) => {
                println!("{}", e);
                if let ConnectError::Handshake(_) = &e {
                    if let Some(h) = crate::policy::connect_failure_challenge_hint(&challenge) {
                        println!("{}", h);
                    }
                }
                return;
            }
        };
        println!(
            "✓ Connected to {}@{} (selected codec: {})",
            outcome.channel.peer_id, addr, outcome.channel.selected_codec
        );
        let trusted_key = confirmed_key.lock().ok().and_then(|k| k.clone());
        if let Some(key) = &trusted_key {
            cli_record_connection(&addr, &server_id, key, device_type, "");
        }
        drop(outcome.channel);
        println!(
            "  (CLI mode cannot render the remote desktop; use the GUI for desktop sessions.)"
        );
    }
}

/// S-01d (F-1): 服务端启动前挑战码校验 —— `challenge_code` 为空（默认配置）
/// 时拒绝启动（fail-closed，进程不监听；对齐 `tunnel serve` 空 token 语义，
/// TNL-SEC-008），除非显式 `--allow-no-challenge`（带高危警告后放行）。
///
/// 返回 `true` = 允许继续启动。`shell server` 与 `serve` 共用。
fn server_challenge_startup_check(cfg: &Config, allow_no_challenge: bool, mode: &str) -> bool {
    if !cfg.device.challenge_code.is_empty() {
        return true;
    }
    if allow_no_challenge {
        println!(
            "  ⚠ WARNING: no challenge_code configured — starting {} with --allow-no-challenge (F-1).",
            mode
        );
        println!(
            "    Zero-credential connections (unknown client + no challenge) will be REJECTED;"
        );
        println!("    configure a challenge code with 'kirin_desk setup' to authenticate clients (recommended).");
        return true;
    }
    println!(
        "ERROR: challenge_code is empty — refusing to start {} without a challenge (F-1).",
        mode
    );
    println!("  Configure one with 'kirin_desk setup', or explicitly pass --allow-no-challenge");
    println!("  to accept zero-credential semantics (NOT recommended).");
    false
}

/// M11-T004: 远程 Shell 服务器（headless，域名白名单强制，无 GUI 审批弹窗）。
///
/// 每个连接：白名单握手（temp mode 可绕过）→ SecureChannel PTY 桥接
/// （`run_shell_bridge`，Windows=ConPTY / Unix=forkpty）。
///
/// S-01d (F-1)：`allow_no_challenge` = 显式 `--allow-no-challenge` ——
/// `challenge_code` 为空（默认配置）时拒绝启动（fail-closed，对齐
/// `tunnel serve` 空 token 语义），仅显式 opt-in 才放行（带高危警告）。
async fn cmd_shell_server(port: u16, allow_no_challenge: bool) {
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
    // S-01d (F-1)：空挑战码拒绝启动（进程不监听），除非显式 opt-in。
    if !server_challenge_startup_check(&cfg, allow_no_challenge, "shell server") {
        return;
    }
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
    // M8-T027 (SRV-IDWL-023): 设备 ID 白名单（永久 + 未过期条目），与域名维度
    // 并列传入策略层（OR 语义）。
    let allowed_ids = cfg.id_whitelist_active_ids(chrono::Utc::now());
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

    if allowed.is_empty() && allowed_ids.is_empty() && !config_temp {
        println!("  ⚠ No whitelist entries configured — ALL connections will be REJECTED.");
        println!("    (use 'kirin_desk setup' → allowed domains, 'kirin_desk whitelist add-id <device-id>', or 'kirin_desk temp-mode')");
    }
    println!(
        "  Domain whitelist: {}",
        if allowed.is_empty() {
            "(empty)".to_string()
        } else {
            allowed.join(", ")
        }
    );
    println!(
        "  ID whitelist: {}",
        if allowed_ids.is_empty() {
            "(empty)".to_string()
        } else {
            allowed_ids.join(", ")
        }
    );
    println!("  Nickname (auth): '{}'", server_name);
    println!("  Use 'kirin_desk temp-mode' for 5-minute whitelist bypass.");

    match TcpServer::bind(port).await {
        Ok(server) => {
            println!("Listening on [::]:{} (whitelist enforced)", server.port());
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
                        let allowed_ids = allowed_ids.clone();
                        let identity = &identity;
                        let server_name = server_name.clone();
                        // 2. 完整握手：known_hosts/DNS-TXT 公钥 pin + 白名单 +
                        //    签名验证（SRV-SHELL-SEC-003：与桌面模式同策略）。
                        match crate::policy::server_accept_handshake(
                            stream,
                            identity,
                            &server_name,
                            &allowed,
                            &allowed_ids,
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
    use kirin_desk_core::crypto::handshake::{
        client_handshake_with_confirm, CoreReason, PinExpectation,
    };
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
            println!(
                "GoDaddy API not configured — cannot discover '{}'. Run setup.",
                target
            );
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
                println!(
                    "Discovery FAILED: {} (device not registered or DNS unavailable)",
                    e
                );
                return;
            }
        };
        if info.public_key_base64.is_empty() {
            println!("ERROR: device TXT record has NO public key — connection refused.");
            return;
        }
        println!(
            "Discovered: {} IPv6={} IPv4={} :{} type={}",
            info.device_id,
            if info.ipv6_addr == Ipv6Addr::UNSPECIFIED {
                "none".to_string()
            } else {
                info.ipv6_addr.to_string()
            },
            info.ipv4_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "none".to_string()),
            info.port,
            info.device_type
        );
        expected_key = match cli_resolve_trust(&info.device_id, &info.public_key_base64) {
            CliTrust::Verified(key) => Some(key),
            CliTrust::Rejected(reason) => {
                println!("Connection aborted: {}", reason);
                return;
            }
        };
        // M8-T025 P5-4：按族选择连接地址（配置 `[transport].ip_family`；
        // CLI shell 无 --ip-family 参数，走配置值）。
        let family = match resolve_ip_family(&cfg.transport.ip_family) {
            Some(f) => f,
            None => {
                println!(
                    "ERROR: invalid config [transport].ip_family '{}' (expected auto|ipv4|ipv6)",
                    cfg.transport.ip_family
                );
                return;
            }
        };
        match info.select_connect_addr(family) {
            Some(a) => addr = a.to_string(),
            None => {
                println!(
                    "ERROR: 设备无可用 IPv4/IPv6 地址（ip_family={}）",
                    cfg.transport.ip_family
                );
                return;
            }
        }
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
    // R-02：pin 强类型——带外可信公钥 → `Exact` 强制比对；无 → 确认回调必填。
    let pin = match &expected_key {
        Some(k) => match PinExpectation::exact_from_base64(k) {
            Ok(p) => p,
            Err(e) => {
                println!("ERROR: invalid trusted key: {}", e);
                return;
            }
        },
        None => PinExpectation::None(CoreReason::UserConfirmRequired),
    };
    let ch = match client_handshake_with_confirm(
        stream,
        &identity,
        &cfg.device.id,
        &client_domain,
        "shell",
        &server_id,
        pin,
        key_confirm,
        &cfg.device.challenge_code,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            println!("Handshake FAILED: {}", e);
            println!("  (server enforces domain whitelist — is your domain allowed?)");
            if let Some(h) =
                crate::policy::connect_failure_challenge_hint(&cfg.device.challenge_code)
            {
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
                            while let Some(pos) = dsr_buf.windows(4).position(|w| w == b"\x1b[6n") {
                                // 光标位置未知 → 应答 1;1（cmd.exe 仅需收到响应即继续）。
                                let _ =
                                    dsr_tx.send(ShellMessage::ShellStdin(b"\x1b[1;1R".to_vec()));
                                dsr_buf.drain(..pos + 4);
                            }
                        }
                    }
                    _ => {}
                },
                Err(e) => {
                    // 远端断开 → 会话结束。
                    let _ = stdout
                        .write_all(format!("\r\n[shell] connection closed: {}\r\n", e).as_bytes());
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
    // M8-T031: 与 GUI 同一解析语义（空/旧占位 → 自动硬盘 UUID）——否则 CLI 与
    // GUI 同机身份 label 分裂（`kirindesk.identity.default` vs `HD-XXXX`），
    // 导致 `[tunnel] device_id` 指纹派生（ID-001）不一致、隧道注册分裂。
    let device_id = kirin_desk_utils::device::effective_device_id(&cfg.device.id);
    let path = dirs_next::home_dir()
        .unwrap_or_default()
        .join(".kirin_desk")
        .join("identity")
        .join("ed25519.json");
    IdentityManager::load_or_generate(path, &device_id).map_err(|e| e.into())
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
    use kirin_desk_core::crypto::handshake::{
        client_handshake_with_confirm, CoreReason, PinExpectation,
    };
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
            println!(
                "GoDaddy API not configured — cannot discover '{}'. Run setup.",
                target
            );
            return None;
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
                println!(
                    "Discovery FAILED: {} (device not registered or DNS unavailable)",
                    e
                );
                return None;
            }
        };
        if info.public_key_base64.is_empty() {
            println!("ERROR: device TXT record has NO public key — connection refused.");
            return None;
        }
        println!(
            "Discovered: {} IPv6={} IPv4={} :{} type={}",
            info.device_id,
            if info.ipv6_addr == Ipv6Addr::UNSPECIFIED {
                "none".to_string()
            } else {
                info.ipv6_addr.to_string()
            },
            info.ipv4_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "none".to_string()),
            info.port,
            info.device_type
        );
        expected_key = match cli_resolve_trust(&info.device_id, &info.public_key_base64) {
            CliTrust::Verified(key) => Some(key),
            CliTrust::Rejected(reason) => {
                println!("Connection aborted: {}", reason);
                return None;
            }
        };
        // M8-T025 P5-4：按族选择连接地址（配置 `[transport].ip_family`）。
        let family = match resolve_ip_family(&cfg.transport.ip_family) {
            Some(f) => f,
            None => {
                println!(
                    "ERROR: invalid config [transport].ip_family '{}' (expected auto|ipv4|ipv6)",
                    cfg.transport.ip_family
                );
                return None;
            }
        };
        match info.select_connect_addr(family) {
            Some(a) => addr = a.to_string(),
            None => {
                println!(
                    "ERROR: 设备无可用 IPv4/IPv6 地址（ip_family={}）",
                    cfg.transport.ip_family
                );
                return None;
            }
        }
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
    // R-02：pin 强类型——带外可信公钥 → `Exact` 强制比对；无 → 确认回调必填。
    let pin = match &expected_key {
        Some(k) => match PinExpectation::exact_from_base64(k) {
            Ok(p) => p,
            Err(e) => {
                println!("ERROR: invalid trusted key: {}", e);
                return None;
            }
        },
        None => PinExpectation::None(CoreReason::UserConfirmRequired),
    };
    let ch = match client_handshake_with_confirm(
        stream,
        &identity,
        &cfg.device.id,
        &client_domain,
        device_type,
        &server_id,
        pin,
        key_confirm,
        &cfg.device.challenge_code,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            println!("Handshake FAILED: {}", e);
            println!("  (server enforces domain whitelist — is your domain allowed?)");
            if let Some(h) =
                crate::policy::connect_failure_challenge_hint(&cfg.device.challenge_code)
            {
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
    println!(
        "Sending '{}' ({})...",
        path.display(),
        super::file_panel::format_size(std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),)
    );
    ft.handle_command(super::FileCommand::SendFile { path })
        .await;
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
    println!(
        "Receiving files into {} (waiting for pushes)...",
        download_dir.display()
    );
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
///
/// S-01d (F-1)：`allow_no_challenge` = 显式 `--allow-no-challenge` ——
/// `challenge_code` 为空（默认配置）时拒绝启动（fail-closed，对齐
/// `tunnel serve` 空 token 语义），仅显式 opt-in 才放行（带高危警告）。
async fn cmd_serve(port: u16, unattended: bool, allow_no_challenge: bool) {
    use kirin_desk_utils::audit::AuditLogger;
    use kirin_desk_utils::known_hosts::KnownClientsStore;

    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    // S-01d (F-1)：空挑战码拒绝启动（进程不监听），除非显式 opt-in。
    if !server_challenge_startup_check(&cfg, allow_no_challenge, "serve") {
        return;
    }
    // M8-T026-P2：Arc 包装（设备 ID 注册回调需 'static 捕获）。
    let identity = match load_identity(&cfg) {
        Ok(id) => std::sync::Arc::new(id),
        Err(e) => {
            println!("Identity error: {}", e);
            return;
        }
    };
    let known = match KnownClientsStore::load() {
        Ok(k) => k,
        Err(e) => {
            println!("known_clients load error: {}", e);
            return;
        }
    };
    // S-03b（审计 F-6）：进程级共享限速器 —— 本地 accept 与中继隧道流共用
    // 同一实例（每隧道流新建实例 + 占位 IP 会使中继路径爆破防护失效）。
    let rate_limiter: SharedRateLimiter = new_shared_rate_limiter();
    let allowed = cfg.whitelist_active_patterns(chrono::Utc::now());
    // M8-T027 (SRV-IDWL-023): 设备 ID 白名单（永久 + 未过期条目），与域名维度
    // 并列传入策略层（OR 语义）。
    let allowed_ids = cfg.id_whitelist_active_ids(chrono::Utc::now());
    let server_name = if cfg.device.nickname.is_empty() {
        "serve-server".to_string()
    } else {
        cfg.device.nickname.clone()
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
            // M8-T026-P2 (ID-003/ID-013)：设备 ID 模式注册（[tunnel] enabled
            // && mode=client）—— 隧道流与本地 accept 走同一连接处理
            // （serve_incoming_stream），白名单/挑战码/临时码访问控制零降级；
            // S-03b：隧道流回调捕获与本地 accept 同一共享限速器。
            let tunnel_client = start_device_registration(
                &cfg,
                identity.clone(),
                server_name.clone(),
                rate_limiter.clone(),
            )
            .await;
            let _ = tunnel_client; // 句柄持有即保持注册运行
            // S-02 (F-5): 每连接并发处理——accept 循环不因单连接"只连不发"/
            // 慢握手冻结；64 并发上限，超出者在任务内排队（信号量）。
            let conn_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
                super::SERVER_MAX_CONCURRENT_CONNECTIONS,
            ));
            // S-02: known_hosts 为跨连接共享状态（tokio Mutex —— guard 需跨
            // serve_incoming_stream 的 await 保持，std MutexGuard 非 Send）；
            // 审计日志按连接独立打开（append 模式多句柄并发安全，同隧道流
            // 回调 / GUI 隐私审计路径）。
            let known = std::sync::Arc::new(tokio::sync::Mutex::new(known));
            loop {
                match server.accept().await {
                    Ok((stream, addr)) => {
                        let ip = addr.ip().to_canonical();
                        let peer_label = addr.to_string();
                        let sem = conn_semaphore.clone();
                        let known = known.clone();
                        let rate_limiter = rate_limiter.clone();
                        let identity = identity.clone();
                        let server_name = server_name.clone();
                        let allowed = allowed.clone();
                        let allowed_ids = allowed_ids.clone();
                        let cfg = cfg.clone();
                        tokio::spawn(async move {
                            let Ok(_permit) = sem.acquire_owned().await else {
                                return;
                            };
                            // M8-T017: 临时连接窗口**逐连接**判定（窗口中途开启/
                            // 过期即时生效），与配置静态旁路取或；无人值守下窗口
                            // 维度一并关闭（UA-ACCEPT-004，策略层亦忽略）。
                            let temp_window = if unattended {
                                None
                            } else {
                                crate::policy::temp_mode_window_manager()
                            };
                            let is_temp = config_temp || temp_window.is_some();
                            if is_temp {
                                println!(
                                    "[Temp Mode ACTIVE] {}s remaining",
                                    temp_mode_remaining()
                                );
                            }
                            let expected_challenge = if cfg.device.challenge_code.is_empty() {
                                None
                            } else {
                                Some(cfg.device.challenge_code.as_str())
                            };
                            let mut audit = match AuditLogger::open_default() {
                                Ok(a) => a,
                                Err(e) => {
                                    println!(
                                        "  audit log open error (connection rejected): {}",
                                        e
                                    );
                                    return;
                                }
                            };
                            // S-03（收窄完成）：known 由 serve_incoming_stream
                            // 内部按需加锁（握手只读快照 / 成功后写回），不再
                            // 跨 await 持锁 —— spawn 任务 Send 安全。
                            serve_incoming_stream(
                                stream,
                                ip,
                                &peer_label,
                                &mut audit,
                                &rate_limiter,
                                &identity,
                                &server_name,
                                &allowed,
                                &allowed_ids,
                                is_temp,
                                unattended,
                                temp_window,
                                expected_challenge,
                                &known,
                                &cfg,
                            )
                            .await;
                        });
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
        }
        Err(e) => println!("Bind failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════
// M8-T026-P2：设备侧 ID 注册 + 隧道流处理（ID-001/003/005/013）
// ════════════════════════════════════════════════════════════════

/// M8-T026-P2 (ID-001/ID-003/ID-005)：`serve` 时启动设备 ID 注册
/// （`[tunnel] enabled && mode="client"`）：RelayClient 保持控制连接 +
/// 心跳（复用 M8-T026 心跳，ID-NF-003）+ 候选刷新；中继隧道流（§8.1）
/// 交给 `serve_incoming_stream`（与本地 accept 同一访问控制，ID-013）。
///
/// S-03b（审计 F-6）：`shared_rate_limiter` 为进程级共享限速器 —— 隧道流
/// 回调捕获其副本，与本地 accept 引用同一实例（每隧道流新建实例会使中继
/// 路径的挑战码/临时码爆破防护失效）。
///
/// 设备 ID：显式配置 `[tunnel] device_id` 或由本机身份公钥指纹派生。
async fn start_device_registration(
    cfg: &Config,
    identity: std::sync::Arc<kirin_desk_core::crypto::ed25519::IdentityManager>,
    server_name: String,
    shared_rate_limiter: SharedRateLimiter,
) -> Option<kirin_desk_relay::id_client::IdClient> {
    use kirin_desk_relay::id_client::{IdClient, IdClientConfig};
    use kirin_desk_relay::protocol::Candidate;

    let tunnel = &cfg.tunnel;
    if !tunnel.enabled || tunnel.mode != "client" {
        return None;
    }
    if tunnel.server_addr.trim().is_empty() || tunnel.token.is_empty() {
        println!(
            "  [tunnel] enabled but server_addr/token empty — device ID registration skipped."
        );
        return None;
    }
    // ID-001：显式 ID 或公钥指纹派生。
    let device_id = tunnel.device_id.clone().unwrap_or_else(|| {
        kirin_desk_utils::known_hosts::fingerprint(&identity.public_key_base64())
    });
    // ID-005：配置 extra_candidates 解析（"ip:port"）。
    let extra: Vec<Candidate> = tunnel
        .extra_candidates
        .iter()
        .filter_map(|s| {
            s.parse::<std::net::SocketAddr>()
                .ok()
                .map(|addr| Candidate {
                    addr,
                    kind: kirin_desk_relay::protocol::CandidateKind::Tcp,
                    priority: 150,
                })
        })
        .collect();
    let heartbeat_interval = Duration::from_secs(tunnel.heartbeat_interval.max(1));
    let heartbeat_timeout = Duration::from_secs(
        tunnel
            .heartbeat_timeout
            .max(heartbeat_interval.as_secs() + 1),
    );
    let client_cfg = IdClientConfig {
        server_addr: tunnel.server_addr.clone(),
        token: tunnel.token.clone(),
        device_id: device_id.clone(),
        ed25519_pub: identity.public_key_base64(),
        hostname: if server_name.is_empty() {
            "kirindesk".to_string()
        } else {
            server_name.clone()
        },
        heartbeat_interval,
        heartbeat_timeout,
        connect_timeout: Duration::from_secs(5),
        backoff_base: Duration::from_secs(1),
        backoff_max: Duration::from_secs(60),
        extra_candidates: extra,
    };
    println!(
        "  [ID Mode] registering device '{}' with relay {} ...",
        device_id, tunnel.server_addr
    );
    if tunnel
        .server_pubkey
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        println!("  [ID Mode] note: `server_pubkey` not set — `connect --id` from other devices will be rejected (ID-SEC-001).");
    }
    let client = IdClient::new(
        client_cfg,
        // S-03b（审计 F-6）：隧道流回调捕获与本地 accept 同一共享限速器
        // 实例（提取为纯函数便于单测断言同一实例引用）。
        tunnel_stream_handler(shared_rate_limiter, identity, server_name),
    );
    let runner = client.clone();
    tokio::spawn(async move {
        let _ = runner.run().await;
    });
    Some(client)
}

/// S-03b（审计 F-6）：隧道流处理回调（`IdClient` on_tunnel_stream）——
/// 捕获与本地 accept 同一进程级共享限速器实例（每隧道流新建实例会使中继
/// 路径的挑战码/临时码爆破防护失效：失败计数不跨流累积、封禁永不触发）；
/// 限速键由设备 ID 派生稳定合成地址（见 [`tunnel_rate_limit_key`]），
/// 替代占位 IP 0.0.0.0。
fn tunnel_stream_handler(
    shared_rate_limiter: SharedRateLimiter,
    identity: std::sync::Arc<kirin_desk_core::crypto::ed25519::IdentityManager>,
    server_name: String,
) -> impl Fn(tokio::net::TcpStream) + Send + Sync + 'static {
    use kirin_desk_utils::audit::AuditLogger;
    use kirin_desk_utils::known_hosts::KnownClientsStore;

    move |stream| {
        let identity = identity.clone();
        let server_name = server_name.clone();
        let shared_rate_limiter = shared_rate_limiter.clone();
        tokio::spawn(async move {
            let peer_label = format!("relay-tunnel({})", identity.public_key_base64());
            let mut audit = match AuditLogger::open_default() {
                Ok(a) => a,
                Err(_) => return,
            };
            // S-03b：进程级共享实例；限速键按对端设备 ID 派生。对端真实源
            // IP 经服务器转发不可确证；按对端 device_id（from_peer）计数需
            // IdClient 回调透传，登记二期（S-09 排后）——现按本设备 ID 派生
            //（中继路径单桶聚合，语义见 `tunnel_rate_limit_key` 注释）。
            let cfg = Config::load().unwrap_or_default();
            let device_id = cfg.tunnel.device_id.clone().unwrap_or_else(|| {
                kirin_desk_utils::known_hosts::fingerprint(&identity.public_key_base64())
            });
            let ip = tunnel_rate_limit_key(&device_id);
            // 与本地 accept 同一接口形态（Arc<Mutex>；serve_incoming_stream
            // 内部按需加锁，隧道流回调用例下为每流独立空表）。
            let known =
                std::sync::Arc::new(tokio::sync::Mutex::new(KnownClientsStore::empty()));
            // M8-T027 (SRV-IDWL-023): 隧道流与本地 accept 同一访问控制——
            // 域名 + ID 双白名单快照一并传入。
            let (allowed, allowed_ids) = allowed_snapshot();
            serve_incoming_stream(
                stream,
                ip,
                &peer_label,
                &mut audit,
                &shared_rate_limiter,
                &identity,
                &server_name,
                &allowed,
                &allowed_ids,
                false,
                false,
                None,
                None,
                &known,
                &cfg,
            )
            .await;
        });
    }
}

/// `serve_incoming_stream` 所需白名单快照（避免回调闭包捕获 cfg 生命周期）。
/// 返回 (域名维度, ID 维度) 双白名单（M8-T027 / SRV-IDWL-023）。
fn allowed_snapshot() -> (Vec<String>, Vec<String>) {
    Config::load()
        .map(|c| {
            let now = chrono::Utc::now();
            (
                c.whitelist_active_patterns(now),
                c.id_whitelist_active_ids(now),
            )
        })
        .unwrap_or_default()
}

/// S-03b（审计 F-6）：进程级共享限速器 —— `serve` 进程内本地 accept 与中继
/// 隧道流共用同一实例（每隧道流新建实例会使中继路径爆破防护失效：失败
/// 计数永不跨流累积，封禁永不触发）。std Mutex 单次操作持锁，不跨 `.await`
/// 保持。
type SharedRateLimiter =
    std::sync::Arc<std::sync::Mutex<kirin_desk_core::network::rate_limit::RateLimiter>>;

/// S-03b：共享限速器单一创建点（`cmd_serve`；测试断言本地/隧道路径引用
/// 同一实例）。
fn new_shared_rate_limiter() -> SharedRateLimiter {
    std::sync::Arc::new(std::sync::Mutex::new(
        kirin_desk_core::network::rate_limit::RateLimiter::new(),
    ))
}

/// S-03b（审计 F-6）：隧道流限速键 —— 由设备 ID 派生稳定合成地址（替代
/// 占位 0.0.0.0），同一设备 ID 跨流稳定（失败/尝试计数累积 → 共享封禁
/// 生效），不同设备 ID 互不串扰。
///
/// 布局：`fd00::/8`（ULA 私有前缀）下挂 64 位哈希于**前 64 位** —— relay
/// 侧限速器按 `/64` 聚合（F-10a），哈希置于前 64 位保证不同设备映射到
/// 不同 `/64` 桶、不被聚合坍缩到同一桶。
fn tunnel_rate_limit_key(device_id: &str) -> std::net::IpAddr {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    device_id.hash(&mut h);
    let n = h.finish();
    let b = n.to_be_bytes();
    std::net::IpAddr::V6(std::net::Ipv6Addr::new(
        0xfd00,
        u16::from_be_bytes([b[0], b[1]]),
        u16::from_be_bytes([b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
        u16::from_be_bytes([b[6], b[7]]),
        0,
        0,
        0,
    ))
}

/// 处理一条入站连接（本地 accept 或 ID 模式中继隧道流共用）：
/// 审计 → 速率限制 → 完整握手（known_hosts/DNS pin + 域名/ID 双白名单 +
/// 挑战码/临时码）→ 会话类型分发（shell PTY / 文件接收 / 保持通道）。
#[allow(clippy::too_many_arguments)]
async fn serve_incoming_stream(
    stream: tokio::net::TcpStream,
    ip: std::net::IpAddr,
    peer_label: &str,
    audit: &mut kirin_desk_utils::audit::AuditLogger,
    rate_limiter: &SharedRateLimiter,
    identity: &kirin_desk_core::crypto::ed25519::IdentityManager,
    server_name: &str,
    allowed: &[String],
    allowed_ids: &[String],
    is_temp: bool,
    unattended: bool,
    temp_window: Option<kirin_desk_core::connection::temp_mode::TempModeManager>,
    expected_challenge: Option<&str>,
    known: &tokio::sync::Mutex<kirin_desk_utils::known_hosts::KnownClientsStore>,
    cfg: &Config,
) {
    use kirin_desk_core::connection::{run_shell_bridge, DEFAULT_PTY_COLS, DEFAULT_PTY_ROWS};
    use kirin_desk_core::crypto::handshake::VerifiedDecision;
    use kirin_desk_core::network::rate_limit::RateLimitDecision;
    use kirin_desk_utils::audit::AuditEvent;

    let _ = audit.record(
        AuditEvent::ConnectionRequest,
        &format!("ip={} source={}", ip, peer_label),
    );
    // 1. 速率限制（SRV-SEC-RL-001/002；S-03b：共享实例，锁内检查不跨 await）。
    match rate_limiter.lock().unwrap().check_connect(&ip) {
        RateLimitDecision::Allowed => {}
        decision => {
            let _ = audit.record(
                AuditEvent::RateLimited,
                &format!("ip={} decision={:?}", ip, decision),
            );
            println!("  Rate limited: {} ({:?}) — rejected", ip, decision);
            return;
        }
    }
    println!("Connection from {}", peer_label);

    // 2. 完整握手（known_hosts/DNS pin + 域名/ID 双白名单 + 签名验证）。
    // S-03（并发收窄，S-02 协作）：`known` 为跨连接共享状态（Arc<Mutex>）——
    // 握手阶段只读（policy 内部多处 await）→ 锁仅覆盖快照 clone，不跨会话
    // 保持（避免长会话串行化全部连接）；成功后写回真实表（短暂加锁）。
    let known_snapshot = known.lock().await.clone();
    match crate::policy::server_accept_handshake(
        stream,
        identity,
        server_name,
        allowed,
        allowed_ids,
        is_temp,
        unattended,
        temp_window,
        None,
        expected_challenge,
        &known_snapshot,
        cfg,
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
            rate_limiter.lock().unwrap().reset(&ip);
            {
                let mut k = known.lock().await;
                crate::policy::record_successful_handshake(&mut k, &ch.peer_id);
            }
            println!(
                "  Session ACCEPTED: {} <{}> ({})",
                ch.peer_id, ch.peer_domain, ch.peer_device_type
            );
            // M13-T005 (UA-ACCEPT-003): 会话类型分发——客户端声明 "shell" →
            // PTY 桥接；否则保持通道至断开。
            if ch.peer_device_type == "shell" {
                let peer_id = ch.peer_id.clone();
                let result = run_shell_bridge(ch, DEFAULT_PTY_COLS, DEFAULT_PTY_ROWS, None).await;
                let _ = audit.record(
                    AuditEvent::Disconnect,
                    &format!("ip={} client={} shell", ip, peer_id),
                );
                match result {
                    Ok(()) => println!("  Shell session closed: {}", peer_label),
                    Err(e) => println!("  Shell session ended with error: {}", e),
                }
            } else {
                // M13-T006 (UI-FT-005): 无头服务端静默接收文件 + 保持通道至
                // 客户端断开（流媒体由 GUI 服务器承载）。
                use kirin_desk_media::transport::{SecureChannelReceiver, SecureChannelSender};
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
                println!("  File reception ready (→ {})", download_dir.display());
                let (_ok, _msg) =
                    cli_file_loop(receiver, &mut ft, true, super::server_file_panel_state()).await;
                let _ = audit.record(
                    AuditEvent::Disconnect,
                    &format!("ip={} client={}", ip, peer_id),
                );
                println!("  Session closed: {}", peer_label);
            }
        }
        Ok(VerifiedDecision::Rejected(reason)) => {
            let _ = audit.record(
                AuditEvent::AuthFailure,
                &format!("ip={} reason={}", ip, reason),
            );
            rate_limiter.lock().unwrap().record_handshake_failure(&ip);
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
            rate_limiter.lock().unwrap().record_handshake_failure(&ip);
            println!("  Handshake error: {}", e);
        }
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

/// M15 (SRV-SEC-WL-001..004) + M8-T027 (SRV-IDWL-001..008, CLI-IDWL-001..006):
/// 白名单管理 — `whitelist [list|add|add-id|remove|remove-id|import|export|export-json]`。
///
/// 域名模式支持 `*.example.com` 通配（匹配子域）；设备 ID 精确匹配（`*` 结尾
/// 前缀通配）；`add`/`add-id` 可选 RFC3339 过期时间（过期自动失效，SRV-SEC-WL-003）。
/// CSV 中 `id:` 前缀行为 ID 维（CLI-IDWL-004）。
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
    // UI-IDWL-004: 白名单增删审计（ID 维）。
    let mut audit = kirin_desk_utils::audit::AuditLogger::open_default().ok();
    match sub {
        "list" => {
            let now = Utc::now();
            let active = cfg.whitelist_active_patterns(now);
            let active_ids = cfg.id_whitelist_active_ids(now);
            if active.is_empty() && active_ids.is_empty() {
                println!("Whitelist is empty (all connections rejected unless temp mode).");
                return;
            }
            // CLI-IDWL-003: Domain / ID 两段分区显示。
            println!("Domain whitelist ({} active):", active.len());
            for p in &active {
                let entry = cfg.network.whitelist.iter().find(|e| &e.pattern == p);
                let expiry = entry
                    .and_then(|e| e.expiry)
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "(permanent)".to_string());
                println!("  {}   expires: {}", p, expiry);
            }
            if active.is_empty() {
                println!("  (empty)");
            }
            println!("ID whitelist ({} active):", active_ids.len());
            for id in &active_ids {
                let entry = cfg.network.id_whitelist.iter().find(|e| &e.device_id == id);
                let expiry = entry
                    .and_then(|e| e.expiry)
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "(permanent)".to_string());
                println!("  {}   expires: {}", id, expiry);
            }
            if active_ids.is_empty() {
                println!("  (empty)");
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
        // M8-T027 (CLI-IDWL-001): 新增设备 ID 白名单条目（expiry 留空 = 永久）。
        "add-id" => {
            let device_id = match args.get(3) {
                Some(v) if !v.is_empty() => v.as_str(),
                _ => {
                    println!("Usage: kirin_desk whitelist add-id <device-id> [RFC3339-expiry]");
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
            match cfg.id_whitelist_add(device_id, expiry) {
                Ok(_) => {
                    println!("Added ID: {} (expiry: {:?})", device_id, expiry);
                    if let Some(a) = audit.as_mut() {
                        let detail = expiry
                            .map(|t| format!("device={} expiry={}", device_id, t))
                            .unwrap_or_else(|| format!("device={} expiry=permanent", device_id));
                        let _ = a.record(
                            kirin_desk_utils::audit::AuditEvent::WhitelistIdAdded,
                            &detail,
                        );
                    }
                }
                Err(e) => println!("Save error: {}", e),
            }
        }
        // M8-T027 (CLI-IDWL-002): 删除设备 ID 白名单条目（同时清理两维）。
        "remove-id" => {
            let device_id = match args.get(3) {
                Some(v) if !v.is_empty() => v.as_str(),
                _ => {
                    println!("Usage: kirin_desk whitelist remove-id <device-id>");
                    return;
                }
            };
            match cfg.id_whitelist_remove(device_id) {
                Ok(true) => {
                    println!("Removed ID: {}", device_id);
                    if let Some(a) = audit.as_mut() {
                        let _ = a.record(
                            kirin_desk_utils::audit::AuditEvent::WhitelistIdRemoved,
                            &format!("device={}", device_id),
                        );
                    }
                }
                Ok(false) => println!("Not found: {}", device_id),
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
            "Usage: kirin_desk whitelist [list|add <p> [expiry]|add-id <device-id> [expiry]|remove <p>|remove-id <device-id>|import <csv>|export <csv>|export-json <json>]"
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
            // M8-T027 (CLI-IDWL-005): ID 白名单统计行（条目数 + 过期条目数），
            // 与域名白名单并列。
            let now = chrono::Utc::now();
            let active_ids = cfg.id_whitelist_active_ids(now);
            let expired_ids = cfg
                .network
                .id_whitelist
                .iter()
                .filter(|e| !e.is_active(now))
                .count();
            println!(
                "ID Whitelist:  {} ({} expired)",
                if active_ids.is_empty() {
                    "(empty)".to_string()
                } else {
                    active_ids.join(", ")
                },
                expired_ids
            );
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
        println!(
            "Temp Mode:     ACTIVE ({}s remaining)",
            temp_mode_remaining()
        );
    } else {
        println!("Temp Mode:     off");
    }
    // M8-T026-P2 (ID-020): Tunnel/ID 模式注册状态行。
    if let Ok(cfg) = Config::load() {
        let t = &cfg.tunnel;
        if t.enabled && t.mode == "client" {
            let device_id = t
                .device_id
                .clone()
                .unwrap_or_else(|| "(fingerprint-derived)".to_string());
            println!("Tunnel:        enabled (mode=client)");
            println!(
                "  server:      {}",
                if t.server_addr.is_empty() {
                    "(not set)"
                } else {
                    &t.server_addr
                }
            );
            println!("  device_id:   {}", device_id);
            println!(
                "  server_pubkey: {}",
                if t.server_pubkey.as_deref().unwrap_or("").is_empty() {
                    "(not set — connect --id unavailable)".to_string()
                } else {
                    format!(
                        "{}...",
                        &t.server_pubkey.as_deref().unwrap_or("")
                            [..std::cmp::min(16, t.server_pubkey.as_deref().unwrap_or("").len())]
                    )
                }
            );
            println!("  extra_candidates: {:?}", t.extra_candidates);
        } else if t.enabled {
            println!("Tunnel:        enabled (mode={})", t.mode);
        } else {
            println!("Tunnel:        off (ID 模式需 `[tunnel] enabled=true` + server 配置)");
        }
    }
}

/// 凭据掩码（S-07c，F-8）：显示 `****` + 明文末 4 位（challenge / token /
/// API key 等展示用）。空串或过短（≤4 字符）→ 全掩。仅用于展示，不改变
/// 实际配置值；调用方不得把明文凭据直接拼进输出/日志。
fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 4 {
        return "****".to_string();
    }
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("****{tail}")
}

#[cfg(test)]
mod mask_tests {
    use super::*;

    #[test]
    fn mask_shows_last_four() {
        assert_eq!(mask("abcdefgh"), "****efgh");
        assert_eq!(mask("abcde"), "****bcde");
    }

    #[test]
    fn mask_hides_short_and_empty() {
        assert_eq!(mask(""), "****");
        assert_eq!(mask("abcd"), "****");
        assert_eq!(mask("abc"), "****");
    }

    #[test]
    fn mask_never_leaks_prefix_or_full_secret() {
        // 任何输入不得包含明文前缀（S-07c 掩码基线）
        let secrets = ["super-secret-token-1234", "A1B2C3D4", "x"];
        for s in secrets {
            let m = mask(s);
            assert!(!m.contains(s), "masked output must not contain the secret");
            assert!(m.starts_with("****"), "masked output starts with ****");
        }
    }
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

    // S-24 (F-29)：自测产物（身份密钥/relay 密钥/状态文件）收敛到**单一临时
    // 子目录** `temp_dir()/kirin_desk_self_test_<pid>/`——不再散落 %TEMP% 根部；
    // 中断（含 Ctrl+C）残留只落在该可识别目录，下次运行自动清理（自愈）；
    // 正常退出整目录删除（"self-test 后临时目录为空"）。
    let tmp = std::env::temp_dir().join(format!(
        "kirin_desk_self_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create self-test temp dir");
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
                // R-02：真实 pin 比对（`Exact` 强类型）。
                kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&bob_pub)?,
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
                let tmp_tm = tmp.join("kirin_desk_self_test_temp_mode.json");
                let _ = std::fs::remove_file(&tmp_tm);
                let mgr = TempModeManager::with_state_file(tmp_tm.clone());

                let code = match mgr.enable(1) {
                    Ok(c) => c,
                    Err(e) => {
                        println!("  1. enable FAILED: {}", e);
                        return;
                    }
                };
                assert_eq!(code.chars().count(), 10, "temp code must be 10 chars (S-20)");
                assert!(mgr.is_active(), "window must be active after enable");
                assert!(mgr.verify_challenge(&code), "correct code must verify");
                assert!(
                    !mgr.verify_challenge("XXXXXXXXXX"),
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

            // ── M8-T027: 设备 ID 白名单自测（匹配规则 + 策略层决策 e2e）──
            println!();
            println!("=== M8-T027 ID whitelist tests ===");
            {
                use kirin_desk_core::crypto::handshake::{
                    client_handshake_with_confirm_generic, id_matches_whitelist, server_read_init,
                    verify_server_init, PinExpectation, VerifiedDecision,
                };
                use kirin_desk_utils::config::Config;
                use kirin_desk_utils::known_hosts::KnownClientsStore;

                // 1. 匹配规则（SRV-IDWL-010/011）：精确 / 未命中 / 空 pattern /
                //    `*` 结尾前缀通配 / 空白 trim / 大小写敏感 / 裸 `*` 保守拒绝。
                assert!(id_matches_whitelist("device-7", "device-7"));
                assert!(!id_matches_whitelist("device-8", "device-7"));
                assert!(!id_matches_whitelist("device-7", ""));
                assert!(id_matches_whitelist("office-1", "office-*"));
                assert!(id_matches_whitelist("office-42", "office-*"));
                assert!(!id_matches_whitelist("lab-1", "office-*"));
                assert!(id_matches_whitelist(" device-7 ", "device-7"));
                assert!(!id_matches_whitelist("Device-7", "device-7"));
                assert!(!id_matches_whitelist("device-7", "*"));
                println!("  1. id_matches_whitelist rules (9/9) OK ✓");

                // 2. 配置层往返（SRV-IDWL-001..008）——仅用内存 Config + 显式
                //    save_to/load_from 临时路径，不触碰真实 default.toml。
                let idwl_cfg_path = tmp.join(format!(
                    "kirindesk_self_test_idwl_{}.toml",
                    std::process::id()
                ));
                let _ = std::fs::remove_file(&idwl_cfg_path);
                let mut cfg = Config::default();
                cfg.id_whitelist_add("device-7", None).unwrap();
                cfg.id_whitelist_add(
                    "device-temp",
                    Some(chrono::Utc::now() + chrono::Duration::days(1)),
                )
                .unwrap();
                cfg.save_to(&idwl_cfg_path).unwrap();
                let loaded = Config::load_from(&idwl_cfg_path).unwrap();
                assert!(loaded.id_whitelist_check("device-7"));
                assert!(loaded.id_whitelist_check("device-temp"));
                assert!(!loaded.id_whitelist_check("device-unknown"));
                // R-05 进行中代码的编译解锁修复（id_whitelist_remove 为 &mut self）。
                let mut loaded = loaded;
                assert!(loaded.id_whitelist_remove("device-7").unwrap());
                let _ = std::fs::remove_file(&idwl_cfg_path);
                println!("  2. config add/check/remove round-trip OK ✓");

                // 3. 策略层决策 e2e：仅 ID 白名单命中 → Accepted（域名维度为空，
                //    与 policy.rs 决策表一致）；双维未命中 → Rejected（headless）。
                let dir = tmp.join("kirindesk_self_test_idwl_e2e");
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                let alice = IdentityManager::generate(dir.join("alice")).unwrap();
                let bob = IdentityManager::generate(dir.join("bob")).unwrap();
                let bob_pub = bob.public_key_base64();

                /// 一次「服务端域名/ID 双白名单 + 客户端 alice」的握手往返。
                /// `challenge` 非空时服务端以该固定挑战码校验（S-01b (F-1)：
                /// ID 白名单命中但零凭据 → 拒绝，凭据齐备才放行）。
                async fn run_idwl_pair(
                    alice: &IdentityManager,
                    bob: &IdentityManager,
                    bob_pub: &str,
                    allowed_ids: &[String],
                    challenge: &str,
                ) -> (
                    Result<
                        kirin_desk_core::crypto::handshake::SecureChannelGeneric<
                            tokio::net::TcpStream,
                        >,
                        kirin_desk_core::crypto::handshake::HandshakeError,
                    >,
                    Result<VerifiedDecision, kirin_desk_core::crypto::handshake::HandshakeError>,
                ) {
                    let listener = TokioListener::bind("[::1]:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    let server_fut = async move {
                        let (stream, _) = listener.accept().await.unwrap();
                        let cfg = Config::default();
                        let expected_challenge = if challenge.is_empty() {
                            None
                        } else {
                            Some(challenge)
                        };
                        crate::policy::server_accept_handshake(
                            stream,
                            bob,
                            "bob",
                            &[],
                            allowed_ids,
                            false,
                            false,
                            None,
                            None,
                            expected_challenge,
                            &KnownClientsStore::empty(),
                            &cfg,
                        )
                        .await
                    };
                    let client_fut = async move {
                        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                        client_handshake_with_confirm_generic(
                            stream,
                            alice,
                            "alice",
                            "evil.example.org",
                            "desktop",
                            "bob",
                            PinExpectation::exact_from_base64(bob_pub).unwrap(),
                            None,
                            challenge,
                        )
                        .await
                    };
                    tokio::join!(client_fut, server_fut)
                }

                // 3a. 域名维度为空 + ID 白名单命中 alice + 挑战码凭据 → Accepted
                //     （F-1：凭据齐备才放行）。
                let allowed_ids = vec!["alice".to_string()];
                let (client_res, decision) =
                    run_idwl_pair(&alice, &bob, &bob_pub, &allowed_ids, "TEST-CODE").await;
                assert!(
                    matches!(decision, Ok(VerifiedDecision::Accepted(_))),
                    "ID whitelist hit must be accepted (domain miss ok)"
                );
                assert!(client_res.is_ok());
                // 3a'. 对照：ID 白名单命中但**零凭据**（无挑战码）→ F-1 拒绝
                //      （IDWL-SEC-002：白名单只匹配自报 ID，身份仍需凭据）。
                let (client_res, decision) =
                    run_idwl_pair(&alice, &bob, &bob_pub, &allowed_ids, "").await;
                match decision {
                    Ok(VerifiedDecision::Rejected(reason)) => {
                        assert!(
                            reason.contains("credentials") || reason.contains("whitelist"),
                            "reason: {reason}"
                        );
                    }
                    other => panic!("expected Rejected (F-1 zero credentials), got {:?}", other),
                }
                assert!(client_res.is_err(), "channel must not be established");
                // 3b. ID 白名单不含 alice（只含其他设备）→ 双维未命中 → Rejected。
                let allowed_ids_other = vec!["other-device".to_string()];
                let (client_res, decision) =
                    run_idwl_pair(&alice, &bob, &bob_pub, &allowed_ids_other, "TEST-CODE").await;
                match decision {
                    Ok(VerifiedDecision::Rejected(reason)) => {
                        assert!(reason.contains("whitelist"), "reason: {reason}");
                    }
                    other => panic!("expected Rejected, got {:?}", other),
                }
                assert!(client_res.is_err(), "channel must not be established");
                // 3c. ID 命中但公钥不一致（known_clients pin 兜底，IDWL-SEC-001）
                //     → 仍拒绝（ClientKeyMismatch），ID 白名单不绕过公钥绑定。
                //     复用手搓两阶段：服务端以**错误** pin 校验 → 拒绝。
                let (client_end, mut server_end) = tokio::io::duplex(65536);
                let client_fut = client_handshake_with_confirm_generic(
                    client_end,
                    &alice,
                    "alice",
                    "evil.example.org",
                    "desktop",
                    "bob",
                    PinExpectation::exact_from_base64(&bob_pub).unwrap(),
                    None,
                    "",
                );
                let server_fut = async move {
                    let init = server_read_init(&mut server_end).await?;
                    // known_clients 记录的是**别的**公钥 → pin 不一致 → 拒绝。
                    verify_server_init(&init, "WRONG-PINNED-KEY", None, None, false)?;
                    Ok::<_, kirin_desk_core::crypto::handshake::HandshakeError>(())
                };
                let (client_res, server_res) = tokio::join!(client_fut, server_fut);
                assert!(
                    matches!(
                        server_res,
                        Err(
                            kirin_desk_core::crypto::handshake::HandshakeError::ClientKeyMismatch { .. }
                        )
                    ),
                    "ID whitelist must not bypass client key pin (IDWL-SEC-001)"
                );
                assert!(
                    !matches!(client_res, Ok(_)),
                    "channel must not be established"
                );
                let _ = std::fs::remove_dir_all(&dir);
                println!("  3. policy decisions: ID-hit accept / dual-miss reject / pin not bypassed OK ✓");
            }
            println!("=== M8-T027 ID whitelist tests COMPLETE (3/3) ===");

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
                    rng = rng
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
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
            ft_a.handle_command(super::FileCommand::SendFile {
                path: src_path.clone(),
            })
            .await;
            let mut tick_a = tokio::time::interval(Duration::from_millis(200));
            tick_a.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut ft_ok = false;
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            // 检查面板任务状态的辅助（发送完成/失败）。
            let mut check_panel =
                |ft_ok: &mut bool, panel: &std::sync::MutexGuard<'_, super::FilePanelState>| {
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
                && super::sha256_file(&recv_path)
                    .map(|h| h == src_sha)
                    .unwrap_or(false);
            if ft_ok && verified {
                println!("  File round-trip OK (SHA-256 match, no leftover .part)");
                let leftover = std::fs::read_dir(&bob_dir)
                    .map(|it| {
                        it.filter_map(|e| e.ok())
                            .any(|e| e.file_name().to_string_lossy().ends_with(".part"))
                    })
                    .unwrap_or(false);
                println!(
                    "  .part leftover: {}",
                    if leftover { "YES (FAIL)" } else { "none" }
                );
            } else {
                println!(
                    "  File round-trip FAILED (ok={} verified={})",
                    ft_ok, verified
                );
            }
            let _ = src_sha;
            let _ = std::fs::remove_dir_all(&file_dir);

            // ── M8-T026-P2: 设备 ID 连接模式 e2e（进程内 relay + 注册 +
            //    凭 ID 解析 → 中继路径 → Ed25519 握手 → 加密发送）──
            println!();
            println!("=== M8-T026-P2 device ID mode e2e ===");
            {
                use kirin_desk_core::connection::id_mode::{IdConnector, IdModeConfig, PathKind};
                use kirin_desk_core::crypto::handshake::{
                    client_handshake_with_confirm_generic, server_handshake_verified_generic,
                    PinExpectation,
                };
                use kirin_desk_relay::id_client::{IdClient, IdClientConfig};
                use kirin_desk_relay::server::{TunnelServer, TunnelServerConfig};
                use std::sync::Arc;

                // 1. 进程内 relay server（临时密钥 + token）。
                let tmp_key = tmp.join(format!(
                    "kirindesk_self_test_relay_key_{}.der",
                    std::process::id()
                ));
                let relay = TunnelServer::bind(TunnelServerConfig {
                    bind_port: 0,
                    // S-24 (F-29)：自测 relay 仅绑回环（127.0.0.1），
                    // 不暴露全接口（token 为已知测试值）。
                    bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                    token: "self-test-token".to_string(),
                    server_key_path: Some(tmp_key.clone()),
                    heartbeat_timeout: Duration::from_secs(2),
                    work_conn_timeout: Duration::from_secs(3),
                    ..Default::default()
                })
                .await
                .unwrap();
                let relay_port = relay.port();
                let server_pubkey_b64 = relay.server_public_key_base64();
                let srv_task = tokio::spawn(relay.run());
                let _ = std::fs::remove_file(&tmp_key);
                println!(
                    "  relay server on :{} (pubkey {}...)",
                    relay_port,
                    &server_pubkey_b64[..16.min(server_pubkey_b64.len())]
                );

                // 2. 设备侧（独立生成身份）ID 注册：控制连接 + 心跳 + 候选刷新。
                //    注意：不动函数级 alice/bob（后续 M15 段仍借用）。
                let device_id = "bob-device";
                let alice_pub_b64 = alice.public_key_base64();
                let dev_identity = kirin_desk_core::crypto::ed25519::IdentityManager::generate(
                    tmp.join("kirindesk_self_test_id_device"),
                )
                .unwrap();
                let dev_arc = Arc::new(dev_identity);
                let id_cfg = IdClientConfig {
                    // S-24 (F-29)：relay 绑 127.0.0.1 → 客户端也走 IPv4 回环。
                    server_addr: format!("127.0.0.1:{}", relay_port),
                    token: "self-test-token".to_string(),
                    device_id: device_id.to_string(),
                    ed25519_pub: dev_arc.public_key_base64(),
                    hostname: "self-test-bob".to_string(),
                    heartbeat_interval: Duration::from_millis(100),
                    heartbeat_timeout: Duration::from_millis(500),
                    connect_timeout: Duration::from_secs(2),
                    backoff_base: Duration::from_millis(50),
                    backoff_max: Duration::from_millis(500),
                    extra_candidates: Vec::new(),
                };
                let dev_arc_for_cb = dev_arc.clone();
                let dev_client = IdClient::new(id_cfg, move |stream| {
                    // §8.1 隧道流到达 → 设备侧服务端握手（Alice 公钥绑定）。
                    let dev = dev_arc_for_cb.clone();
                    let alice_pub = alice_pub_b64.clone();
                    tokio::spawn(async move {
                        match server_handshake_verified_generic(stream, &dev, "bob", &alice_pub)
                            .await
                        {
                            Ok(_) => println!("  device side: relay handshake OK"),
                            Err(e) => println!("  device side: relay handshake FAILED: {}", e),
                        }
                    });
                });
                let dev_runner = dev_client.clone();
                let dev_task = tokio::spawn(async move {
                    let _ = dev_runner.run().await;
                });
                // 等待注册完成（心跳间隔 100ms）。
                tokio::time::sleep(Duration::from_millis(300)).await;
                println!("  device registered: '{}'", device_id);

                // 3. 控制器（Alice）凭 ID 解析 → 三级路径（无直连候选 →
                //    中继兜底）→ 握手。
                let connector = IdConnector::new(
                    IdModeConfig::try_new(
                        // S-24 (F-29)：relay 绑 127.0.0.1 → 客户端也走 IPv4 回环。
                        &format!("127.0.0.1:{}", relay_port),
                        "self-test-token",
                        &server_pubkey_b64,
                    )
                    .unwrap(),
                );
                let info = connector.resolve(device_id).await.unwrap();
                assert!(IdConnector::is_connectable(&info), "device must be online");
                assert_eq!(info.payload.device_id, device_id);
                println!(
                    "  resolved: '{}' online candidates={} (signature verified)",
                    info.payload.device_id,
                    info.payload.candidates.len()
                );
                let (path, stream) = connector
                    .connect_stream(&info, "alice-device")
                    .await
                    .expect("relay path must establish");
                assert_eq!(
                    path,
                    PathKind::Relay,
                    "no direct candidates → relay fallback"
                );
                println!("  path selected: {}", path);
                let ch = client_handshake_with_confirm_generic(
                    stream,
                    &alice,
                    "alice",
                    "",
                    "desktop",
                    "bob",
                    // R-02：真实 pin 比对（`Exact` 强类型）。
                    PinExpectation::exact_from_base64(&dev_arc.public_key_base64())
                        .expect("device pubkey"),
                    None,
                    "",
                )
                .await
                .expect("handshake over relay must succeed");
                println!("  controller handshake OK via relay (peer={})", ch.peer_id);

                // 4. 第二条中继会话：加密发送（控制器 → 设备侧已握手通道）。
                let echo_connector = IdConnector::new(
                    IdModeConfig::try_new(
                        // S-24 (F-29)：relay 绑 127.0.0.1 → 客户端也走 IPv4 回环。
                        &format!("127.0.0.1:{}", relay_port),
                        "self-test-token",
                        &server_pubkey_b64,
                    )
                    .unwrap(),
                );
                let info2 = echo_connector.resolve(device_id).await.unwrap();
                let (_p2, stream2) = echo_connector
                    .connect_stream(&info2, "alice-device")
                    .await
                    .unwrap();
                let mut ch2 = client_handshake_with_confirm_generic(
                    stream2,
                    &alice,
                    "alice",
                    "",
                    "desktop",
                    "bob",
                    // R-02：真实 pin 比对（`Exact` 强类型）。
                    PinExpectation::exact_from_base64(&dev_arc.public_key_base64())
                        .expect("device pubkey"),
                    None,
                    "",
                )
                .await
                .unwrap();
                let test_msg = b"ID mode round-trip via relay";
                // SecureChannelGeneric 无 send 方法 → 字段公开，转 SecureChannel。
                let mut sc = kirin_desk_core::crypto::handshake::SecureChannel {
                    stream: ch2.stream,
                    cipher: ch2.cipher,
                    peer_id: ch2.peer_id,
                    peer_domain: ch2.peer_domain,
                    peer_device_type: ch2.peer_device_type,
                    selected_codec: ch2.selected_codec,
                };
                sc.send(test_msg).await.unwrap();
                println!("  encrypted send over relay OK ({} bytes)", test_msg.len());
                println!("  ID mode e2e: relay path handshake + encrypted send PASSED");
                dev_client.stop();
                let _ = tokio::time::timeout(Duration::from_secs(2), dev_task).await;
                srv_task.abort();
            }

            // ── M8-T026-P1: 打洞辅助与多路径叠加 ──
            //   1) 打洞：进程内 rendezvous（PUNCH-006 边界：仅登记/互转）→
            //      双端 UDP 打洞（loopback）→ socket 交还 + 审计断言
            //      （PUNCH-SEC-004）；
            //   2) PathManager：多路径分配（中继→直连升舱）+ RTT 劣化
            //      默认保持期 2s 内触发换路（PATH-002/003）。
            println!();
            println!("=== M8-T026-P1 punch tests ===");
            {
                use kirin_desk_core::connection::punch::{PunchConfig, PunchResult, PunchSession};
                use kirin_desk_relay::rendezvous::RendezvousServer;
                use std::sync::Arc;

                // 1. 进程内 rendezvous。
                let rv_server = Arc::new(RendezvousServer::bind(0).await.unwrap());
                let mut rv_addr = rv_server.local_addr();
                if rv_addr.ip().is_unspecified() {
                    rv_addr =
                        std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, rv_addr.port()));
                }
                let rv_arc = Arc::clone(&rv_server);
                let rv_task = tokio::spawn(async move {
                    let _ = rv_arc.serve(tokio::sync::watch::channel(false).1).await;
                });

                // 2. 双端独立身份 + 共享 session_id（发起方 pin，PUNCH-SEC-003）。
                // S-24 (F-29)：打洞身份密钥收敛到自测子目录。
                let p_tmp = tmp.clone();
                let p_key_a = p_tmp.join("kirindesk_self_test_punch_a");
                let p_key_b = p_tmp.join("kirindesk_self_test_punch_b");
                let pim_a = Arc::new(IdentityManager::generate(p_key_a.clone()).unwrap());
                let pim_b = Arc::new(IdentityManager::generate(p_key_b.clone()).unwrap());
                let mut cfg_a = PunchConfig::loopback("self-punch-a");
                cfg_a.rendezvous_addr = rv_addr;
                cfg_a.handshake.peer_device_id = "self-punch-b".into();
                let mut punch_a = PunchSession::new(cfg_a, Arc::clone(&pim_a));
                punch_a.pin_session();
                let sid = punch_a.session_id();
                let mut cfg_b = PunchConfig::loopback("self-punch-b");
                cfg_b.rendezvous_addr = rv_addr;
                cfg_b.handshake.peer_device_id = "self-punch-a".into();
                let mut punch_b = PunchSession::with_session_id(cfg_b, Arc::clone(&pim_b), sid);

                // 3. 审计：成功事件落盘（PUNCH-SEC-004）。
                let audit_path = p_tmp.join(format!(
                    "kirindesk_self_test_punch_audit_{}.log",
                    std::process::id()
                ));
                let _ = std::fs::remove_file(&audit_path);
                let audit = Arc::new(std::sync::Mutex::new(
                    kirin_desk_utils::audit::AuditLogger::open(&audit_path).unwrap(),
                ));
                punch_a.set_audit(Arc::clone(&audit));

                // 4. 双端并发打洞 → UDP 建立（PUNCH-001；<2s，PUNCH-NF-001）。
                let punch_started = std::time::Instant::now();
                let (ra, rb) = tokio::join!(punch_a.establish(), punch_b.establish());
                let punch_ok = matches!(ra, PunchResult::UdpEstablished { .. })
                    && matches!(rb, PunchResult::UdpEstablished { .. });
                let punch_elapsed = punch_started.elapsed();
                let audit_ok = std::fs::read_to_string(&audit_path)
                    .unwrap_or_default()
                    .contains("tunnel_punch_success");
                let _ = std::fs::remove_file(&audit_path);
                let _ = std::fs::remove_file(p_key_a);
                let _ = std::fs::remove_file(p_key_b);
                let _ = rv_task.abort();
                if punch_ok && audit_ok {
                    println!(
                        "  UDP punch established in {:?} (PUNCH-NF-001), audit tunnel_punch_success (PUNCH-SEC-004)",
                        punch_elapsed
                    );
                    println!("  punch tests: loopback UDP hole-punch + audit PASSED");
                } else {
                    println!(
                        "  punch tests FAILED: ok={punch_ok} elapsed={punch_elapsed:?} audit={audit_ok}"
                    );
                }
            }

            println!();
            println!("=== M8-T026-P1 path manager tests ===");
            {
                use kirin_desk_core::connection::path_manager::{
                    PathKind, PathManager, PathMetrics, PathState, SwitchReason,
                };
                // 1. 多路径分配：中继 + 直连 + 打洞均 Active → 确认升舱
                //    （媒体→最优 P2P，PATH-002）。
                let mut m = PathManager::new();
                for k in [PathKind::Relay, PathKind::DirectV6, PathKind::PunchUdp] {
                    m.register_path(k);
                    m.on_path_state(k, PathState::Active);
                }
                let upgrade = m.evaluate();
                let alloc_ok = upgrade.len() == 1 && upgrade[0].from == PathKind::Relay;
                if alloc_ok {
                    m.on_switch_completed(upgrade[0]);
                }
                // 2. 切换决策：控制通道（PunchUdp）RTT 30ms vs 最优直连
                //    10ms（差 >30%）→ 默认保持期 2s 后触发换路（PATH-003）。
                m.on_metrics(
                    PathKind::DirectV6,
                    PathMetrics {
                        rtt_ms: 10.0,
                        loss_rate: 0.0,
                        jitter_us: 0.0,
                    },
                );
                m.on_metrics(
                    PathKind::PunchUdp,
                    PathMetrics {
                        rtt_ms: 30.0,
                        loss_rate: 0.0,
                        jitter_us: 0.0,
                    },
                );
                tokio::time::sleep(Duration::from_millis(2100)).await;
                let actions = m.evaluate();
                let switch_ok = actions.len() == 1
                    && actions[0].from == PathKind::PunchUdp
                    && actions[0].to == PathKind::Relay
                    && actions[0].reason == SwitchReason::RttDegraded;
                if alloc_ok && switch_ok {
                    println!("  path allocation: relay -> direct upgrade confirmed (PATH-002)");
                    println!("  switch decision: RTT degraded -> relay after hold (PATH-003)");
                    println!("  path manager tests: allocation + switch decision PASSED");
                } else {
                    println!(
                        "  path manager tests FAILED: alloc_ok={alloc_ok} switch_ok={switch_ok}"
                    );
                }
            }

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
        client_handshake_with_confirm_generic, server_handshake_verified_generic, CoreReason,
        HandshakeError, PinExpectation,
    };
    use kirin_desk_utils::known_hosts::{FingerprintStatus, KnownHostsStore};

    let tmp_kh = tmp.join("kirindesk_self_test_known_hosts");
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
            // R-02：无带外公钥 → 确认回调必填（`UserConfirmRequired`，无跳过路径）。
            PinExpectation::None(CoreReason::UserConfirmRequired),
            Some(Box::new(move |key: &str| {
                println!("  [confirm] key {}… → accept", &key[..16.min(key.len())]);
                true
            })),
            "",
        );
        let server_fut = server_handshake_verified_generic(server_end, &bob, "bob", &alice_pub);
        let (cr, sr) = tokio::join!(client_fut, server_fut);
        assert!(
            cr.is_ok() && sr.is_ok(),
            "confirm-accept handshake must succeed"
        );
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
            // R-02：真实 pin 比对（`Exact` 强类型）。
            PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"),
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
            // known_hosts 里记录的错误公钥（R-02：`Exact` 强类型比对）。
            PinExpectation::exact_from_base64(&alice_pub).expect("alice pubkey"),
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
            // R-02：无带外公钥 → 确认回调必填（`UserConfirmRequired`，无跳过路径）。
            PinExpectation::None(CoreReason::UserConfirmRequired),
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

    // ── R-03 (R03-S6): 断连重连（指数退避）end-to-end ──
    println!();
    println!("=== R-03 disconnect/reconnect (exponential backoff) ===");
    {
        use kirin_desk_core::connection::client::{
            connect_peer, resolve_peer, ConnectionOptions, RefusalReason, TrustPolicy,
        };
        use kirin_desk_core::connection::manager::{
            ConnectionState, ManagedConnection, ReconnectContext,
        };
        use kirin_desk_core::connection::reconnection::attempt_reconnect;

        // 场景 1: 建连 → 杀连接（drop channel）→ 退避自动重连成功
        // （同一身份复用，不重建；`ReconnectSuccess` 状态事件）。
        {
            let listener = TokioListener::bind("[::1]:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (client_res, server_res): (Result<(), String>, Result<(), String>) = tokio::join!(
                async {
                    let opts = ConnectionOptions {
                        target: "::1".to_string(),
                        port: addr.port(),
                        server_id: "bob".to_string(),
                        challenge: String::new(),
                        device_type: "desktop".to_string(),
                        client_identity: Arc::new(alice.clone()),
                        client_id: "alice".to_string(),
                        client_domain: "alice.self-test.local".to_string(),
                        dns: None,
                        trust: TrustPolicy::Verified(bob_pub.clone()),
                    };
                    let peer = resolve_peer(&opts).await.map_err(|e| e.to_string())?;
                    let mut ch = connect_peer(&opts, &peer)
                        .await
                        .map_err(|e| e.to_string())?
                        .channel;
                    ch.send(b"reconnect-1").await.map_err(|e| e.to_string())?;
                    drop(ch); // 模拟断线（TCP 关闭）
                    println!("  1. connection dropped — auto-reconnecting (backoff)...");

                    let mut conn = ManagedConnection::new("bob");
                    conn.max_reconnect_attempts = 3;
                    conn.set_reconnect_context(ReconnectContext {
                        options: opts,
                        server_id: "bob".to_string(),
                    });
                    let progress: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
                    let progress_cb = progress.clone();
                    let mut ch2 = attempt_reconnect(
                        &mut conn,
                        Some(Arc::new(move |n: u32| {
                            if let Ok(mut p) = progress_cb.lock() {
                                p.push(n);
                            }
                        })),
                        None,
                    )
                    .await
                    .map_err(|e| e.message())?;
                    assert_eq!(
                        conn.state,
                        ConnectionState::Secured,
                        "reconnect must end Secured (ReconnectSuccess)"
                    );
                    assert_eq!(
                        *progress.lock().unwrap(),
                        vec![1],
                        "first reconnect attempt must succeed"
                    );
                    ch2.send(b"reconnect-2").await.map_err(|e| e.to_string())?;
                    Ok(())
                },
                async {
                    // 两轮握手（首连 + 重连），每轮收到一条消息证明链路活。
                    for round in 0..2 {
                        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
                        let mut ch = server_handshake_verified(stream, &bob, "bob", &alice_pub)
                            .await
                            .map_err(|e| e.to_string())?;
                        let msg = ch.receive().await.map_err(|e| e.to_string())?;
                        println!(
                            "  server: round {} received {} bytes ✓",
                            round + 1,
                            msg.len()
                        );
                    }
                    Ok(())
                },
            );
            match (client_res, server_res) {
                (Ok(()), Ok(())) => {
                    println!("  1. disconnect → backoff reconnect round-trip PASSED ✓");
                }
                (Err(e), _) => println!("  1. FAILED (client): {e}"),
                (_, Err(e)) => println!("  1. FAILED (server): {e}"),
            }
        }

        // 场景 2 (R03-S5): 服务端已下线 → 明确不可重连原因（不静默失败）。
        {
            let l2 = TokioListener::bind("[::1]:0").await.unwrap();
            let port = l2.local_addr().unwrap().port();
            drop(l2); // 立即关闭端口 → TCP 必拒
            let opts = ConnectionOptions {
                target: "::1".to_string(),
                port,
                server_id: "bob".to_string(),
                challenge: String::new(),
                device_type: "desktop".to_string(),
                client_identity: Arc::new(alice.clone()),
                client_id: "alice".to_string(),
                client_domain: "alice.self-test.local".to_string(),
                dns: None,
                trust: TrustPolicy::Verified(bob_pub.clone()),
            };
            let mut conn = ManagedConnection::new("bob");
            conn.max_reconnect_attempts = 1;
            conn.set_reconnect_context(ReconnectContext {
                options: opts,
                server_id: "bob".to_string(),
            });
            let err = attempt_reconnect(&mut conn, None, None).await.unwrap_err();
            assert_eq!(
                err.refusal,
                RefusalReason::ServerUnreachable,
                "server-down must classify as unreachable"
            );
            println!("  2. server-down refusal: {} ✓", err.message());
        }
    }
    println!("=== R-03 disconnect/reconnect tests COMPLETE (2/2) ===");

    // S-24 (F-29)：正常退出清理自测临时子目录（含全部密钥/状态文件）——
    // "self-test 后临时目录为空"。中断残留由下次运行的开头清理兜底。
    let _ = std::fs::remove_dir_all(&tmp);
    println!();
    println!("=== Self-test COMPLETE (temp artifacts cleaned: {}) ===", tmp.display());
}

// ════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════
// M8-T026 T004: CLI 内网穿透 — tunnel start / serve / status（TNL-CFG-003）
// ════════════════════════════════════════════════════════════════

/// CLI 侧隧道审计适配器：relay 审计事件 → `utils::audit` 落盘（TNL-SEC-003）。
/// token 不进入 detail（TNL-SEC-005）。
#[derive(Debug)]
struct CliTunnelAudit;

impl kirin_desk_relay::audit::AuditSink for CliTunnelAudit {
    fn record(&self, event: kirin_desk_relay::audit::TunnelAuditEvent) {
        use kirin_desk_relay::audit::TunnelAuditEvent;
        use kirin_desk_utils::audit::{AuditEvent, AuditLogger};
        let (ev, detail) = match event {
            TunnelAuditEvent::LoginSuccess { client, hostname } => (
                AuditEvent::TunnelLoginSuccess,
                format!("ip={} hostname={}", client, hostname),
            ),
            TunnelAuditEvent::LoginFailed { client, reason } => (
                AuditEvent::TunnelLoginFailed,
                format!("ip={} reason={}", client, reason),
            ),
            TunnelAuditEvent::ProxyRegistered { client, name, port } => (
                AuditEvent::TunnelProxyRegistered,
                format!("ip={} proxy={} port={}", client, name, port),
            ),
            TunnelAuditEvent::ProxyRemoved { client, name } => (
                AuditEvent::TunnelProxyRemoved,
                format!("ip={} proxy={}", client, name),
            ),
            TunnelAuditEvent::WorkConnOpened { client, name } => (
                AuditEvent::TunnelWorkConnOpened,
                format!("ip={} proxy={}", client, name),
            ),
            TunnelAuditEvent::WorkConnClosed {
                client,
                name,
                reason,
            } => (
                AuditEvent::TunnelWorkConnClosed,
                format!("ip={} proxy={} reason={}", client, name, reason),
            ),
            TunnelAuditEvent::RateLimited { client, reason } => (
                AuditEvent::TunnelRateLimited,
                format!("ip={} reason={}", client, reason),
            ),
            // M8-T026-P2 (ID-022)：设备注册/离线/解析/中继事件。
            TunnelAuditEvent::DeviceRegistered { client, device_id } => (
                AuditEvent::DeviceRegistered,
                format!("ip={} device={}", client, device_id),
            ),
            TunnelAuditEvent::DeviceRejected {
                client,
                device_id,
                reason,
            } => (
                AuditEvent::DeviceResolveRejected,
                format!("ip={} device={} reason={}", client, device_id, reason),
            ),
            TunnelAuditEvent::DeviceOffline { client, device_id } => (
                AuditEvent::DeviceOffline,
                format!("ip={} device={}", client, device_id),
            ),
            TunnelAuditEvent::DeviceResolveAccepted {
                client,
                device_id,
                online,
            } => (
                AuditEvent::DeviceResolveAccepted,
                format!("ip={} device={} online={}", client, device_id, online),
            ),
            TunnelAuditEvent::DeviceResolveRejected {
                client,
                device_id,
                reason,
            } => (
                AuditEvent::DeviceResolveRejected,
                format!("ip={} device={} reason={}", client, device_id, reason),
            ),
            TunnelAuditEvent::TunnelRelayOpened {
                target,
                from,
                conn_id,
            } => (
                AuditEvent::TunnelWorkConnOpened,
                format!("target={} from={} conn_id={}", target, from, conn_id),
            ),
            TunnelAuditEvent::TunnelRelayClosed {
                target,
                conn_id,
                reason,
            } => (
                AuditEvent::TunnelWorkConnClosed,
                format!("target={} conn_id={} reason={}", target, conn_id, reason),
            ),
            // M8-T026-P1 打洞事件（PUNCH-SEC-004）由打洞集成方落盘。
            _ => return,
        };
        if let Ok(mut logger) = AuditLogger::open_default() {
            let _ = logger.record(ev, &detail);
        }
    }
}

/// `tunnel <start|serve|status>`（TNL-CFG-003）。
async fn cmd_tunnel(args: Vec<String>) {
    let sub = args.get(2).map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "start" => cmd_tunnel_start().await,
        "serve" => cmd_tunnel_serve().await,
        "status" => cmd_tunnel_status(),
        _ => {
            println!("Usage: kirin_desk tunnel <start|serve|status>");
        }
    }
}

/// `tunnel start`：client 模式（frpc 等价，TNL-CLIENT-001~007）。
/// 长驻前台；Ctrl+C 优雅退出（发 Logout）。
async fn cmd_tunnel_start() {
    use kirin_desk_relay::client::{ProxySpec, TunnelClient, TunnelClientConfig};
    use std::sync::Arc;

    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    let t = &cfg.tunnel;
    if !t.enabled {
        println!("  WARNING: Tunnel is DISABLED ([tunnel] enabled = false).");
        println!("    Enable it in config/default.toml before starting.");
    }
    if t.server_addr.is_empty() {
        println!("ERROR: [tunnel].server_addr is empty — set the relay server address.");
        return;
    }
    // M8-T026-P3 (TNL-CFG-007)：口令为空时服务器将拒绝登录（已配置口令）
    // 或处于未认证状态（legacy），二者都不应继续 —— 提示设置口令。
    if t.token.is_empty() {
        println!(
            "  WARNING: [tunnel].token is empty — the server will refuse the login (or is unauthenticated); do not continue (TNL-SEC-008). Set a token on both sides."
        );
    }
    if t.proxies.is_empty() {
        println!("  WARNING: no proxies configured ([tunnel] proxies) — nothing will be mapped.");
    }
    let proxies: Vec<ProxySpec> = t
        .proxies
        .iter()
        .map(|p| ProxySpec {
            name: p.name.clone(),
            local_addr: p.local_addr.clone(),
            local_port: p.local_port,
            remote_port: p.remote_port,
        })
        .collect();
    let client_cfg = TunnelClientConfig {
        server_addr: t.server_addr.clone(),
        token: t.token.clone(),
        hostname: cfg.device.id.clone(),
        heartbeat_interval: Duration::from_secs(t.heartbeat_interval.max(1)),
        heartbeat_timeout: Duration::from_secs(t.heartbeat_timeout.max(1)),
        connect_timeout: Duration::from_secs(5),
        local_dial_timeout: Duration::from_secs(2),
        backoff_base: Duration::from_secs(1),
        backoff_max: Duration::from_secs(60),
        proxies,
    };
    println!("=== Tunnel client (mode=client) ===");
    println!("  Server:      {}", t.server_addr);
    for p in &cfg.tunnel.proxies {
        let remote = if p.remote_port == 0 {
            "auto".to_string()
        } else {
            p.remote_port.to_string()
        };
        println!(
            "  Proxy '{}' -> {}:{} (remote {})",
            p.name, p.local_addr, p.local_port, remote
        );
    }
    println!("  Press Ctrl+C to stop.");

    let client = Arc::new(TunnelClient::new(client_cfg));
    let stop_client = client.clone();
    let ctrl = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("\nStopping tunnel client...");
        stop_client.stop();
    });
    let _ = client.run().await;
    ctrl.abort();
    println!("Tunnel client stopped.");
}

/// `tunnel serve`：server 模式（frps 等价，TNL-SERVER-001~008）。
/// 长驻前台；Ctrl+C 停止。审计事件落盘（TNL-SEC-003）。
async fn cmd_tunnel_serve() {
    use kirin_desk_relay::server::{TunnelServer, TunnelServerConfig};
    use std::sync::Arc;

    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("Config error: {}. Run setup first.", e);
            return;
        }
    };
    let t = &cfg.tunnel;
    // M8-T026-P3 (TNL-SEC-008)：fail-closed —— 空口令拒绝启动（防服务器
    // 被任意接入滥用 / 运营者躺枪）。
    if t.token.is_empty() {
        println!(
            "ERROR: [tunnel].token is empty — refusing to start without a password (TNL-SEC-008)"
        );
        return;
    }
    // TNL-SEC-009：口令质量提示（建议 ≥32 字节高熵随机串）。
    if t.token.len() < 16 {
        println!(
            "  WARNING: [tunnel].token is shorter than 16 characters — use a high-entropy token (>=32 bytes) (TNL-SEC-009)"
        );
    }
    let port_range = parse_tunnel_port_range(&t.port_range);
    if port_range.is_none() {
        println!(
            "  WARNING: invalid [tunnel].port_range '{}' (expected \"start-end\") — remote_port=0 requests will be rejected.",
            t.port_range
        );
    }
    let srv_cfg = TunnelServerConfig {
        bind_port: t.bind_port,
        token: t.token.clone(),
        port_range,
        heartbeat_timeout: Duration::from_secs(t.heartbeat_timeout.max(1)),
        work_conn_timeout: Duration::from_secs(8),
        max_proxies: 32,
        max_concurrent_work: 100,
        rate_limit: kirin_desk_relay::rate_limit::RateLimiterConfig::default(),
        audit: Some(Arc::new(CliTunnelAudit) as Arc<dyn kirin_desk_relay::audit::AuditSink>),
        ..Default::default()
    };
    println!("=== Tunnel server (mode=server) ===");
    println!("  Control port: {}", t.bind_port);
    println!(
        "  Port range:   {}",
        if t.port_range.is_empty() {
            "(none — remote_port must be explicit)".to_string()
        } else {
            t.port_range.clone()
        }
    );
    let server = match TunnelServer::bind(srv_cfg).await {
        Ok(s) => s,
        Err(e) => {
            println!("Bind failed: {}", e);
            return;
        }
    };
    println!("Listening on port {} (Ctrl+C to stop)", server.port());
    let srv_task = tokio::spawn(server.run());
    let _ = tokio::signal::ctrl_c().await;
    srv_task.abort();
    println!("Tunnel server stopped.");
}

/// `tunnel status`：显示配置与代理列表（运行状态见前台进程日志）。
fn cmd_tunnel_status() {
    let cfg = match Config::load() {
        Ok(c) => c,
        Err(_) => {
            println!("No config. Run setup.");
            return;
        }
    };
    let t = &cfg.tunnel;
    println!("=== Tunnel Status ===");
    println!("Enabled:     {}", if t.enabled { "ON" } else { "OFF" });
    println!("Mode:        {}", t.mode);
    println!(
        "Server:      {}",
        if t.server_addr.is_empty() {
            "(not set)".to_string()
        } else {
            t.server_addr.clone()
        }
    );
    println!("Token:       {}", mask(&t.token));
    if t.mode == "server" {
        println!("Bind port:   {}", t.bind_port);
        println!("Port range:  {}", t.port_range);
    }
    println!(
        "Heartbeat:   interval {}s / timeout {}s",
        t.heartbeat_interval, t.heartbeat_timeout
    );
    if t.mode == "client" {
        println!(
            "Proxies:     {}",
            if t.proxies.is_empty() {
                "(none)".to_string()
            } else {
                format!("{}", t.proxies.len())
            }
        );
        for p in &t.proxies {
            let remote = if p.remote_port == 0 {
                "auto".to_string()
            } else {
                p.remote_port.to_string()
            };
            println!(
                "  - '{}' -> {}:{} (remote {})",
                p.name, p.local_addr, p.local_port, remote
            );
        }
    }
    println!("  (running state is printed by the foreground `tunnel start`/`serve` process)");
}

/// 解析 `"start-end"` 端口区间（TNL-CFG-001 `[tunnel].port_range`）。
fn parse_tunnel_port_range(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.trim().split_once('-')?;
    let start: u16 = a.trim().parse().ok()?;
    let end: u16 = b.trim().parse().ok()?;
    if start > end {
        return None;
    }
    Some((start, end))
}

// ════════════════════════════════════════════════════════════════
// R-11: CLI 单测（dispatch 抽取 + 参数解析纯函数；零 I/O）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod cli_tests {
    use super::*;

    fn v(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_parse_cli_command_known_commands() {
        // 全部已知子命令 → 对应变体（17 项；help 别名单测见下）
        let cases: &[(&str, CliCommand)] = &[
            ("help", CliCommand::Help),
            ("setup", CliCommand::Setup),
            ("config", CliCommand::Config),
            ("register", CliCommand::Register),
            ("discover", CliCommand::Discover),
            ("connect", CliCommand::Connect),
            ("send", CliCommand::Send),
            ("recv", CliCommand::Recv),
            ("shell", CliCommand::Shell),
            ("serve", CliCommand::Serve),
            ("known-hosts", CliCommand::KnownHosts),
            ("whitelist", CliCommand::Whitelist),
            ("temp-mode", CliCommand::TempMode),
            ("unattended", CliCommand::Unattended),
            ("autostart", CliCommand::Autostart),
            ("tunnel", CliCommand::Tunnel),
            ("status", CliCommand::Status),
            ("self-test", CliCommand::SelfTest),
        ];
        for (name, expected) in cases {
            let got = parse_cli_command(&v(&["kirin_desk", name, "extra"]));
            assert_eq!(&got, expected, "命令 {name} 应映射为 {expected:?}");
        }
    }

    #[test]
    fn test_parse_cli_command_help_aliases() {
        for alias in ["--help", "-h"] {
            assert_eq!(
                parse_cli_command(&v(&["kirin_desk", alias])),
                CliCommand::Help
            );
        }
    }

    #[test]
    fn test_parse_cli_command_unknown() {
        assert_eq!(
            parse_cli_command(&v(&["kirin_desk", "frobnicate"])),
            CliCommand::Unknown("frobnicate".to_string())
        );
    }

    #[test]
    fn test_parse_cli_command_no_subcommand() {
        assert_eq!(
            parse_cli_command(&v(&[])),
            CliCommand::Unknown(String::new())
        );
        assert_eq!(
            parse_cli_command(&v(&["kirin_desk"])),
            CliCommand::Unknown(String::new())
        );
    }

    #[test]
    fn test_parse_cli_command_extra_args_ignored_for_dispatch() {
        // dispatch 只看子命令本身；参数在分支内解析
        assert_eq!(
            parse_cli_command(&v(&["kirin_desk", "connect", "--id", "abc"])),
            CliCommand::Connect
        );
    }

    #[test]
    fn test_flag_value_found() {
        let args = v(&[
            "connect",
            "host",
            "--transport",
            "tcp",
            "--ip-family",
            "ipv4",
        ]);
        assert_eq!(flag_value(&args, "--transport"), Some("tcp".to_string()));
        assert_eq!(flag_value(&args, "--ip-family"), Some("ipv4".to_string()));
    }

    #[test]
    fn test_flag_value_missing() {
        let args = v(&["connect", "host"]);
        assert_eq!(flag_value(&args, "--transport"), None);
        assert_eq!(flag_value(&args, "--nope"), None);
    }

    #[test]
    fn test_flag_value_flag_at_end() {
        let args = v(&["connect", "--transport"]);
        assert_eq!(flag_value(&args, "--transport"), None, "flag 在末尾无值");
    }

    #[test]
    fn test_flag_value_multiple_flags() {
        let args = v(&["connect", "--id", "a", "--id", "b"]);
        assert_eq!(flag_value(&args, "--id"), Some("a".to_string()), "取首个");
    }

    #[test]
    fn test_strip_transport_flags_strips_pairs() {
        let args = v(&[
            "connect",
            "host",
            "--transport",
            "tcp",
            "--ip-family",
            "ipv4",
            "3389",
        ]);
        let stripped = strip_transport_flags(args);
        assert_eq!(stripped, v(&["connect", "host", "3389"]));
    }

    #[test]
    fn test_strip_transport_flags_keeps_positional() {
        let args = v(&["connect", "host", "3389", "nick"]);
        assert_eq!(
            strip_transport_flags(args),
            v(&["connect", "host", "3389", "nick"])
        );
    }

    #[test]
    fn test_strip_transport_flags_flag_without_value() {
        // 末尾残缺 flag：无后续值 → 保留原样
        let args = v(&["connect", "--transport"]);
        assert_eq!(strip_transport_flags(args), v(&["connect", "--transport"]));
    }

    #[test]
    fn test_resolve_transport_mode_all() {
        assert_eq!(
            resolve_transport_mode("auto"),
            Some((TransportMode::Quic, true))
        );
        assert_eq!(
            resolve_transport_mode("quic"),
            Some((TransportMode::Quic, false))
        );
        assert_eq!(
            resolve_transport_mode("tcp"),
            Some((TransportMode::Tcp, false))
        );
    }

    #[test]
    fn test_resolve_transport_mode_invalid() {
        assert_eq!(resolve_transport_mode("udp"), None);
        assert_eq!(resolve_transport_mode(""), None);
        assert_eq!(resolve_transport_mode("AUTO"), None, "大小写敏感（现状）");
    }

    #[test]
    fn test_resolve_ip_family_all() {
        assert_eq!(resolve_ip_family("auto"), Some(IpFamily::Auto));
        assert_eq!(resolve_ip_family("ipv4"), Some(IpFamily::Ipv4));
        assert_eq!(resolve_ip_family("ipv6"), Some(IpFamily::Ipv6));
    }

    #[test]
    fn test_resolve_ip_family_invalid() {
        assert_eq!(resolve_ip_family("ipv5"), None);
        assert_eq!(resolve_ip_family(""), None);
        assert_eq!(resolve_ip_family("IPV6"), None, "大小写敏感（现状）");
    }

    #[test]
    fn test_mask_short_returns_as_is() {
        // S-07c: 过短（≤4 字符）→ 全掩（防尾 4 位即全量）。
        assert_eq!(mask("abcd"), "****");
        assert_eq!(mask("abc"), "****");
        assert_eq!(mask(""), "****");
    }

    #[test]
    fn test_mask_long_masks() {
        // S-07c: `****` + 明文末 4 位，明文前缀绝不外泄。
        assert_eq!(mask("abcdefgh"), "****efgh");
        assert_eq!(mask("abcdefghijklmnop"), "****mnop");
    }

    #[test]
    fn test_parse_tunnel_port_range_valid() {
        assert_eq!(parse_tunnel_port_range("60000-61000"), Some((60000, 61000)));
        assert_eq!(parse_tunnel_port_range(" 7000-7000 "), Some((7000, 7000)));
    }

    #[test]
    fn test_parse_tunnel_port_range_invalid() {
        assert_eq!(parse_tunnel_port_range("61000-60000"), None, "start > end");
        assert_eq!(parse_tunnel_port_range("abc-def"), None);
        assert_eq!(parse_tunnel_port_range("7000"), None);
        assert_eq!(parse_tunnel_port_range(""), None);
    }

    #[test]
    fn test_parse_cli_command_all_variants_distinct() {
        // 已知命令映射互不重复（防 dispatch 表内误写同值）
        let mut seen = std::collections::HashSet::new();
        for name in [
            "setup",
            "config",
            "register",
            "discover",
            "connect",
            "send",
            "recv",
            "shell",
            "serve",
            "known-hosts",
            "whitelist",
            "temp-mode",
            "unattended",
            "autostart",
            "tunnel",
            "status",
            "self-test",
        ] {
            let got = parse_cli_command(&v(&["kirin_desk", name]));
            assert!(
                !matches!(got, CliCommand::Unknown(_)),
                "{name} 不应被判未知"
            );
            assert!(seen.insert(got), "{name} 映射重复");
        }
    }

    // ── R-04：`--no-audio` 解析（会话级音频开关；纯函数 + 全局副作用复位）──

    /// `--no-audio` → 剔除 flag + 关闭会话级音频开关；无 flag → 参数原样、开关不变。
    #[test]
    fn test_strip_audio_flag_disables_audio() {
        crate::set_audio_enabled(true); // 复位（测试间隔离）
        assert!(crate::audio_enabled(), "default audio enabled");

        let args = v(&["connect", "my-pc.example.com", "3389", "--no-audio"]);
        let stripped = strip_audio_flag(args);
        assert!(
            !stripped.iter().any(|a| a == "--no-audio"),
            "--no-audio 必须从参数表剔除"
        );
        assert_eq!(stripped.len(), 3, "位置参数保留（t/p/n）");
        assert!(!crate::audio_enabled(), "解析后音频开关关闭");

        // 无 flag → 参数原样返回，开关保持开启。
        crate::set_audio_enabled(true);
        let args2 = v(&["serve", "3389", "--unattended"]);
        let stripped2 = strip_audio_flag(args2);
        assert_eq!(
            stripped2,
            v(&["serve", "3389", "--unattended"]),
            "无 flag 原样"
        );
        assert!(crate::audio_enabled(), "音频保持开启");
        crate::set_audio_enabled(true); // 复位，避免影响其它测试
    }

    /// flag_present：布尔 flag 检测（--no-audio 无值；与 flag_value 互补）。
    #[test]
    fn test_flag_present_boolean_flags() {
        let args = v(&["serve", "--unattended", "--no-audio"]);
        assert!(flag_present(&args, "--no-audio"));
        assert!(flag_present(&args, "--unattended"));
        assert!(!flag_present(&args, "--audio"), "--audio 未定义");
        assert!(!flag_present(&[], "--no-audio"), "空参数表 → false");
    }

    // ── S-03b（审计 F-6）：进程级共享限速器接线 ────────────────────────

    /// /64 前缀（对齐 relay rate_limit bucket_key 的 IPv6 聚合语义）。
    fn bucket_prefix(ip: std::net::IpAddr) -> [u16; 4] {
        match ip {
            std::net::IpAddr::V6(v6) => {
                let s = v6.segments();
                [s[0], s[1], s[2], s[3]]
            }
            _ => [0; 4],
        }
    }

    #[test]
    fn test_tunnel_rate_limit_key_stable_and_distinct() {
        // S-03b：限速键由设备 ID 派生 → 同 ID 稳定（跨流累积 → 共享封禁
        // 生效）、异 ID 互异（互不串扰）、非占位 IP。
        let k1 = tunnel_rate_limit_key("pc-a");
        let k2 = tunnel_rate_limit_key("pc-a");
        let k3 = tunnel_rate_limit_key("pc-b");
        assert_eq!(k1, k2, "同一设备 ID 的限速键必须稳定");
        assert_ne!(k1, k3, "不同设备 ID 的限速键必须互异");
        assert!(k1.is_ipv6());
        // 哈希置于前 64 位 → 不同设备映射到不同 /64 桶（不被 F-10a 的
        // /64 聚合坍缩到同一桶）。
        assert_ne!(
            bucket_prefix(tunnel_rate_limit_key("dev-aaaa")),
            bucket_prefix(tunnel_rate_limit_key("dev-bbbb")),
            "不同设备 ID 必须落在不同 /64"
        );
    }

    #[test]
    fn test_tunnel_handler_captures_shared_rate_limiter() {
        // S-03b / 审计 F-6 验收：隧道流回调必须捕获与本地 accept 同一
        // 进程级共享限速器实例（每流新建实例 → 中继路径爆破防护失效）。
        let shared = new_shared_rate_limiter();
        let before = std::sync::Arc::strong_count(&shared);
        let identity = std::sync::Arc::new(
            kirin_desk_core::crypto::ed25519::IdentityManager::generate(
                std::env::temp_dir().join("s03-test-identity.key"),
            )
            .expect("identity generate"),
        );
        let _handler = tunnel_stream_handler(shared.clone(), identity, "s03-test".to_string());
        assert_eq!(
            std::sync::Arc::strong_count(&shared),
            before + 1,
            "隧道流回调必须持有共享限速器引用（与本地 accept 同一实例）"
        );
    }

    #[test]
    fn test_local_accept_and_tunnel_share_rate_limiter_instance() {
        // S-03b / 审计 F-6：本地 accept 与隧道流引用同一实例 + 行为一致
        //（同一键跨两路径命中同一桶）。
        use kirin_desk_core::network::rate_limit::RateLimitDecision;
        let shared = new_shared_rate_limiter();
        let local_view = shared.clone(); // cmd_serve accept 循环持有
        let tunnel_view = shared.clone(); // 隧道流回调持有（同一 Arc）
        assert!(std::sync::Arc::ptr_eq(&local_view, &tunnel_view));
        let key = tunnel_rate_limit_key("pc-a");
        // 默认窗口 30s / 3 次：本地路径消耗 3 次额度…
        for _ in 0..3 {
            assert_eq!(
                local_view.lock().unwrap().check_connect(&key),
                RateLimitDecision::Allowed
            );
        }
        // …隧道流路径在同一实例的同一键上看到第 4 次被拒（同一桶共享计数）。
        assert_eq!(
            tunnel_view.lock().unwrap().check_connect(&key),
            RateLimitDecision::TooManyAttempts,
            "隧道流与本地 accept 共用限速器 → 同一键共享计数"
        );
    }

    // ── S-13（审计 F-16）：挑战码免落命令行 ──────────────────────────

    /// 行终止符裁剪：LF / CRLF / CR / 无换行；行内空白保留。
    #[test]
    fn test_trim_challenge_line_variants() {
        assert_eq!(trim_challenge_line("secret\n"), "secret");
        assert_eq!(trim_challenge_line("secret\r\n"), "secret");
        assert_eq!(trim_challenge_line("secret\r"), "secret");
        assert_eq!(trim_challenge_line("secret"), "secret");
        assert_eq!(
            trim_challenge_line(" sec ret \n"),
            " sec ret ",
            "行内空白（含尾随空白）保留——仅剥离行终止符"
        );
        assert_eq!(trim_challenge_line(""), "");
    }

    /// `--challenge-stdin`：从 stdin 读一行并裁剪尾随换行（LF/CRLF）。
    #[test]
    fn test_read_challenge_from_stdin_trims_trailing_newline() {
        let mut lf = std::io::Cursor::new(b"my-code\n".to_vec());
        assert_eq!(read_challenge_from_stdin(&mut lf).unwrap(), "my-code");
        let mut crlf = std::io::Cursor::new(b"my-code\r\n".to_vec());
        assert_eq!(read_challenge_from_stdin(&mut crlf).unwrap(), "my-code");
        let mut no_nl = std::io::Cursor::new(b"my-code".to_vec());
        assert_eq!(read_challenge_from_stdin(&mut no_nl).unwrap(), "my-code");
    }

    /// `--challenge-stdin` 空管道（EOF/空行）→ Ok("")，由调用方回退配置值。
    #[test]
    fn test_read_challenge_from_stdin_empty_returns_empty() {
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(read_challenge_from_stdin(&mut empty).unwrap(), "");
        let mut blank_line = std::io::Cursor::new(b"\n".to_vec());
        assert_eq!(read_challenge_from_stdin(&mut blank_line).unwrap(), "");
    }

    /// 分支优先级：`--challenge-stdin` 时即使 TTY 也走管道读取（flag 显式优先）。
    #[test]
    fn test_acquire_challenge_stdin_flag_wins_over_tty() {
        let mut cursor = std::io::Cursor::new(b"piped-code\n".to_vec());
        let got = acquire_challenge(true, true, &mut cursor, || {
            panic!("prompt 不应被调用——flag 优先于 TTY 交互");
        });
        assert_eq!(got.unwrap(), "piped-code");
    }

    /// 非 TTY 且无 `--challenge-stdin` → Err（拒绝连接，提示管道用法；不泄露细节）。
    #[test]
    fn test_acquire_challenge_non_tty_rejects() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let got = acquire_challenge(false, false, &mut cursor, || {
            panic!("非 TTY 不应触发交互提示");
        });
        let err = got.expect_err("非 TTY 无凭据必须拒绝");
        assert!(
            err.contains("--challenge-stdin"),
            "错误提示必须指引管道用法: {err}"
        );
        assert!(!err.contains("secret"), "错误提示不得泄露凭据细节");
    }

    /// TTY 分支：调用注入的 prompt（不回显由 rpassword 实现），返回其值。
    #[test]
    fn test_acquire_challenge_tty_uses_prompt() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut called = 0;
        let got = acquire_challenge(false, true, &mut cursor, || {
            called += 1;
            Ok("typed-code".to_string())
        });
        assert_eq!(got.unwrap(), "typed-code");
        assert_eq!(called, 1, "prompt 恰好调用一次");
    }

    /// TTY 分支：prompt 读取出错 → Err（明确报错中止连接）。
    #[test]
    fn test_acquire_challenge_tty_prompt_error() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let got = acquire_challenge(false, true, &mut cursor, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "tty read boom",
            ))
        });
        assert!(got.is_err());
        assert!(got.unwrap_err().contains("terminal"));
    }

    /// `--challenge-stdin` 参数剔除：flag 移除、位置参数保留、无 flag 原样。
    #[test]
    fn test_strip_challenge_flag_removes_and_detects() {
        let args = v(&[
            "connect",
            "host",
            "3389",
            "nick",
            "--challenge-stdin",
            "--transport",
            "tcp",
        ]);
        let (flag, stripped) = strip_challenge_flag(args);
        assert!(flag, "flag 存在必须检测到");
        assert!(
            !stripped.iter().any(|a| a == "--challenge-stdin"),
            "flag 必须剔除"
        );
        assert_eq!(
            stripped,
            v(&["connect", "host", "3389", "nick", "--transport", "tcp"]),
            "位置参数与其它 flag 原样保留"
        );

        let (flag2, stripped2) =
            strip_challenge_flag(v(&["connect", "host", "3389", "nick"]));
        assert!(!flag2, "无 flag → false");
        assert_eq!(
            stripped2,
            v(&["connect", "host", "3389", "nick"]),
            "无 flag 参数表原样"
        );
    }
}
