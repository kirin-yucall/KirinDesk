//! M8-T026: 内网穿透服务端主程序（frps 等价，独立部署用）。
//!
//! 薄壳包装 [`kirin_desk_relay::server::TunnelServer`]：
//! - CLI 参数：`--bind-addrs` / `--bind-port` / `--token` / `--port-range` /
//!   `--server-key` / `--max-proxies` / `--max-work-conns` /
//!   `--rendezvous-port` / `--no-rendezvous`（R-08b S2）；
//! - 控制台日志（`RUST_LOG`，默认 `info`）+ 审计事件输出（stdout，
//!   TNL-SEC-003 全部事件 + P1/P2 打洞/设备事件）；
//! - 进程内启动打洞 rendezvous 服务（R-08b S2：默认 7001，`--no-rendezvous`
//!   关闭；候选登记/互转/限速/审计复用 [`kirin_desk_relay::rendezvous`]）；
//! - Ctrl+C / SIGTERM 优雅关闭（TNL-SERVER-006，双服务无残留协程）；
//! - 启动时打印服务器 Ed25519 公钥——ID 模式客户端须预置
//!   `[tunnel] server_pubkey`（ID-SEC-001）。
//!
//! 构建与部署：Windows 见 `release/server/README.md`，
//! Linux 见 `release/server/BUILD_LINUX.md`（用户本机编译）。

use kirin_desk_relay::audit::{AuditSink, TunnelAuditEvent};
use kirin_desk_relay::rate_limit::RateLimiterConfig;
use kirin_desk_relay::rendezvous::RendezvousServer;
use kirin_desk_relay::server::{TunnelServer, TunnelServerConfig};
use std::sync::Arc;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_BIND_PORT: u16 = 7000;
const DEFAULT_RENDEZVOUS_PORT: u16 = 7001;
const DEFAULT_MAX_PROXIES: usize = 32;
const DEFAULT_MAX_WORK_CONNS: usize = 100;

/// 命令行配置。
#[derive(Debug)]
struct Config {
    bind_addrs: String,
    bind_port: u16,
    token: String,
    port_range: Option<(u16, u16)>,
    server_key: Option<std::path::PathBuf>,
    max_proxies: usize,
    max_work_conns: usize,
    /// R-08b (S2)：打洞 rendezvous 端口（默认 7001）。
    rendezvous_port: u16,
    /// R-08b (S2)：打洞 rendezvous 启用（`--no-rendezvous` 关闭）。
    rendezvous_enabled: bool,
}

fn print_usage() {
    println!("relay-server v{VERSION} — KirinDesk 内网穿透服务端（frps 等价）");
    println!();
    println!("USAGE: relay-server [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --bind-addrs <IP,IP,…> 监听地址列表（逗号分隔，可多个，仅本机 IP，");
    println!("                        IPv4/IPv6 均可；v6 一律 v6-only——`::` 只收 IPv6、");
    println!("                        `0.0.0.0` 只收 IPv4，两者并存互不冲突；");
    println!("                        留空 = 默认双栈回退（[::] 优先 + 0.0.0.0 回退））");
    println!("  --bind-port <PORT>    控制端口（默认 {DEFAULT_BIND_PORT}；[::] 优先、0.0.0.0 回退，双栈）");
    println!("  --token <TOKEN>       客户端认证 token（建议高熵 ≥32 字节；");
    println!("                        也可经环境变量 KIRIN_RELAY_TOKEN 提供）");
    println!("  --port-range <S-E>    自动分配端口范围，如 \"60000-60099\"");
    println!("                        （客户端 remote_port=0 请求用）");
    println!("  --server-key <PATH>   Ed25519 服务器密钥路径");
    println!("                        （默认 ~/.kirin_desk/relay_server_key.pem，不存在则自动生成）");
    println!("  --max-proxies <N>     每会话代理数量上限（默认 {DEFAULT_MAX_PROXIES}）");
    println!("  --max-work-conns <N>  每代理并发 work 连接上限（默认 {DEFAULT_MAX_WORK_CONNS}）");
    println!("  --rendezvous-port <P> 打洞 rendezvous 端口（默认 {DEFAULT_RENDEZVOUS_PORT}；");
    println!("                        打洞候选登记/互转/限速/审计，P1 打洞用；");
    println!("                        须与 --bind-port 不同）");
    println!("  --no-rendezvous       关闭打洞 rendezvous（不监听 --rendezvous-port）");
    println!("  --help                显示本帮助");
    println!("  --version             显示版本");
}

/// 取下一参数值（支持 `--key=value` 与 `--key value` 两种写法）。
fn next_value(iter: &mut impl Iterator<Item = String>, inline: &Option<String>, name: &str) -> Result<String, String> {
    if let Some(v) = inline {
        return Ok(v.clone());
    }
    iter.next()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    let (a, b) = s.split_once('-').ok_or_else(|| format!("invalid --port-range '{s}' (expected \"start-end\")"))?;
    let a: u16 = a.trim().parse().map_err(|_| format!("invalid --port-range start '{a}'"))?;
    let b: u16 = b.trim().parse().map_err(|_| format!("invalid --port-range end '{b}'"))?;
    if a == 0 || b == 0 {
        return Err(format!("invalid --port-range '{s}': ports must be > 0"));
    }
    if a > b {
        return Err(format!("invalid --port-range '{s}': start must be <= end"));
    }
    Ok((a, b))
}

impl Config {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut cfg = Config {
            bind_addrs: String::new(),
            bind_port: DEFAULT_BIND_PORT,
            token: std::env::var("KIRIN_RELAY_TOKEN").unwrap_or_default(),
            port_range: None,
            server_key: None,
            max_proxies: DEFAULT_MAX_PROXIES,
            max_work_conns: DEFAULT_MAX_WORK_CONNS,
            rendezvous_port: DEFAULT_RENDEZVOUS_PORT,
            rendezvous_enabled: true,
        };
        // R-08b (S2)：`--rendezvous-port` 是否被显式给出（与 `--no-rendezvous`
        // 互斥校验用）。
        let mut rendezvous_port_explicit = false;
        while let Some(arg) = args.next() {
            let (key, inline) = match arg.split_once('=') {
                Some((k, v)) => (k.to_string(), Some(v.to_string())),
                None => (arg, None),
            };
            match key.as_str() {
                "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                "--version" => {
                    println!("relay-server v{VERSION}");
                    std::process::exit(0);
                }
                "--bind-addrs" => {
                    cfg.bind_addrs = next_value(&mut args, &inline, "--bind-addrs")?;
                }
                "--bind-port" => {
                    let v = next_value(&mut args, &inline, "--bind-port")?;
                    cfg.bind_port = v
                        .parse()
                        .map_err(|_| format!("invalid --bind-port '{v}'"))?;
                }
                "--token" => {
                    cfg.token = next_value(&mut args, &inline, "--token")?;
                }
                "--port-range" => {
                    let v = next_value(&mut args, &inline, "--port-range")?;
                    cfg.port_range = Some(parse_port_range(&v)?);
                }
                "--server-key" => {
                    let v = next_value(&mut args, &inline, "--server-key")?;
                    cfg.server_key = Some(v.into());
                }
                "--max-proxies" => {
                    let v = next_value(&mut args, &inline, "--max-proxies")?;
                    cfg.max_proxies = v
                        .parse()
                        .map_err(|_| format!("invalid --max-proxies '{v}'"))?;
                }
                "--max-work-conns" => {
                    let v = next_value(&mut args, &inline, "--max-work-conns")?;
                    cfg.max_work_conns = v
                        .parse()
                        .map_err(|_| format!("invalid --max-work-conns '{v}'"))?;
                }
                // R-08b (S2)：打洞 rendezvous 端口（0 拒绝 —— 部署语义上
                // 须为固定端口，对齐 --port-range 的 0 拒绝口径）。
                "--rendezvous-port" => {
                    let v = next_value(&mut args, &inline, "--rendezvous-port")?;
                    let p: u16 = v
                        .parse()
                        .map_err(|_| format!("invalid --rendezvous-port '{v}'"))?;
                    if p == 0 {
                        return Err(format!(
                            "invalid --rendezvous-port '0' (ports must be 1-65535)"
                        ));
                    }
                    cfg.rendezvous_port = p;
                    rendezvous_port_explicit = true;
                }
                "--no-rendezvous" => {
                    cfg.rendezvous_enabled = false;
                }
                _ => return Err(format!("unknown option '{key}'")),
            }
        }
        // R-08b (S2)：fail-closed 冲突校验（对齐 --bind-addrs 非法值 exit(2) 模式）。
        if !cfg.rendezvous_enabled && rendezvous_port_explicit {
            return Err(
                "conflicting options: --no-rendezvous cannot be combined with --rendezvous-port"
                    .to_string(),
            );
        }
        if cfg.rendezvous_enabled && cfg.rendezvous_port == cfg.bind_port {
            return Err(format!(
                "conflicting options: --rendezvous-port {} equals --bind-port (must differ)",
                cfg.rendezvous_port
            ));
        }
        Ok(cfg)
    }

    /// M8-T039 P16b: 解析 `--bind-addrs` 为监听地址列表（复用
    /// `utils::config::parse_bind_addr_list`，GUI/CLI 同一校验口径）。
    /// 空/纯空白 → 空列表（relay 回退默认双栈）；非法值（域名/空段）→ Err，
    /// 由调用方 fail-closed 拒绝启动（对齐 cmd_tunnel_serve 语义）。
    fn parse_bind_addrs(&self) -> Result<Vec<std::net::SocketAddr>, String> {
        kirin_desk_utils::config::parse_bind_addr_list(&self.bind_addrs, self.bind_port)
            .map_err(|e| format!("invalid --bind-addrs: {e}"))
    }
}

/// 控制台审计（TNL-SEC-003 全部事件 + P1/P2 打洞/设备事件，stdout）。
#[derive(Debug)]
struct ConsoleAudit;

impl AuditSink for ConsoleAudit {
    fn record(&self, event: TunnelAuditEvent) {
        println!("[audit] {}", console_audit_line(&event));
    }
}

/// S-16d (F-21): 构造控制台审计行 —— hostname/device_id/reason/name/
/// session_id/target/from 等**攻击者可控**字符串字段一律经
/// `escape_control` 转义（`\n` → 反斜杠n 字面量、其余控制字符 → `\xNN`），
/// 攻击者不能借字段内容伪造日志行或注入终端控制序列。client 为
/// `SocketAddr`（不能含控制字符）、port/conn_id/online 为数值类型，不转义。
fn console_audit_line(event: &TunnelAuditEvent) -> String {
    use TunnelAuditEvent::*;
    let esc = |s: &str| -> String { kirin_desk_utils::audit::escape_control(s) };
    match event {
        LoginSuccess { client, hostname } => {
            format!("login ok ip={client} host={}", esc(hostname))
        }
        LoginFailed { client, reason } => {
            format!("login FAILED ip={client} reason={}", esc(reason))
        }
        ProxyRegistered { client, name, port } => {
            format!("proxy registered ip={client} name={} port={port}", esc(name))
        }
        ProxyRemoved { client, name } => {
            format!("proxy removed ip={client} name={}", esc(name))
        }
        WorkConnOpened { client, name } => {
            format!("work conn opened ip={client} proxy={}", esc(name))
        }
        WorkConnClosed { client, name, reason } => {
            format!("work conn closed ip={client} proxy={} reason={}", esc(name), esc(reason))
        }
        RateLimited { client, reason } => {
            format!("rate limited ip={client} reason={}", esc(reason))
        }
        PunchCandidateRegistered { client, device_id } => {
            format!("punch candidate registered ip={client} device={}", esc(device_id))
        }
        PunchForwarded { client, device_id } => {
            format!("punch forwarded ip={client} device={}", esc(device_id))
        }
        PunchUnknownSession { client, session_id } => {
            format!("punch unknown session ip={client} session={}", esc(session_id))
        }
        DeviceRegistered { client, device_id } => {
            format!("device registered ip={client} id={}", esc(device_id))
        }
        DeviceRejected { client, device_id, reason } => {
            format!("device rejected ip={client} id={} reason={}", esc(device_id), esc(reason))
        }
        DeviceOffline { client, device_id } => {
            format!("device offline ip={client} id={}", esc(device_id))
        }
        DeviceResolveAccepted { client, device_id, online } => {
            format!("device resolve ip={client} id={} online={online}", esc(device_id))
        }
        DeviceResolveRejected { client, device_id, reason } => {
            format!("device resolve rejected ip={client} id={} reason={}", esc(device_id), esc(reason))
        }
        TunnelRelayOpened { target, from, conn_id } => {
            format!("relay opened target={} from={} conn={conn_id}", esc(target), esc(from))
        }
        TunnelRelayClosed { target, conn_id, reason } => {
            format!("relay closed target={} conn={conn_id} reason={}", esc(target), esc(reason))
        }
        CandidateRegisterRejected { client, device_id, reason } => {
            format!("candidate register rejected ip={client} device={} reason={}", esc(device_id), esc(reason))
        }
    }
}

// S-16e (F-21): ConsoleAudit 输出转义单测 —— 攻击者可控字段含换行/控制
// 字符时输出恒为单行且为字面量转义。
#[cfg(test)]
mod console_audit_escape_tests {
    use super::console_audit_line;
    use kirin_desk_relay::audit::TunnelAuditEvent;

    fn addr() -> std::net::SocketAddr {
        "203.0.113.5:9000".parse().unwrap()
    }

    #[test]
    fn test_login_hostname_newline_escaped() {
        // 攻击者可控 hostname：换行伪造登录行。
        let line = console_audit_line(&TunnelAuditEvent::LoginSuccess {
            client: addr(),
            hostname: "pc-a\nlogin ok ip=127.0.0.1\n".into(),
        });
        assert!(
            line.contains("host=pc-a\\nlogin ok ip=127.0.0.1\\n"),
            "hostname 换行应为字面量: {line:?}"
        );
        assert!(!line.contains('\n'), "输出必须单行: {line:?}");
    }

    #[test]
    fn test_device_id_control_chars_escaped() {
        let line = console_audit_line(&TunnelAuditEvent::DeviceRegistered {
            client: addr(),
            device_id: "dev\r\x1b[31mred".into(),
        });
        assert!(
            line.contains("id=dev\\r\\x1b[31mred"),
            "device_id 控制字符应为字面量: {line:?}"
        );
        assert!(!line.contains('\r') && !line.contains('\x1b'), "不得残留控制字符: {line:?}");
    }

    #[test]
    fn test_reason_and_target_escaped() {
        let line = console_audit_line(&TunnelAuditEvent::TunnelRelayClosed {
            target: "t\n1".into(),
            conn_id: 7,
            reason: "eof\r\n".into(),
        });
        assert!(line.contains("target=t\\n1"), "{line:?}");
        assert!(line.contains("reason=eof\\r\\n"), "{line:?}");
        assert!(!line.contains('\n'), "输出必须单行: {line:?}");
    }
}

// M8-T039 P16b: Config::parse 参数解析单测（--bind-addrs 两种写法、缺值、
// 默认空、parse_bind_addrs 合法/非法值 fail-closed）。
#[cfg(test)]
mod config_parse_tests {
    use super::Config;

    fn parse(args: &[&str]) -> Result<Config, String> {
        Config::parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn test_bind_addrs_default_empty() {
        // 不传 --bind-addrs → 空串（relay 默认双栈回退，行为与旧版一致）。
        let cfg = parse(&[]).unwrap();
        assert_eq!(cfg.bind_addrs, "");
        assert_eq!(cfg.parse_bind_addrs().unwrap(), vec![]);
    }

    #[test]
    fn test_bind_addrs_space_and_equals_forms() {
        // `--key value` 与 `--key=value` 两种写法等价。
        let cfg = parse(&["--bind-addrs", "0.0.0.0,::"]).unwrap();
        assert_eq!(cfg.bind_addrs, "0.0.0.0,::");
        let cfg = parse(&["--bind-addrs=127.0.0.1,::1"]).unwrap();
        assert_eq!(cfg.bind_addrs, "127.0.0.1,::1");
    }

    #[test]
    fn test_bind_addrs_missing_value() {
        let err = parse(&["--bind-addrs"]).unwrap_err();
        assert!(err.contains("missing value for --bind-addrs"), "{err}");
    }

    #[test]
    fn test_parse_bind_addrs_valid_list() {
        // 合法双地址 → 两个 SocketAddr（端口 = bind_port）。
        let cfg = parse(&["--bind-addrs", "0.0.0.0,::", "--bind-port", "7000"]).unwrap();
        let v = cfg.parse_bind_addrs().unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.contains(&"0.0.0.0:7000".parse().unwrap()));
        assert!(v.contains(&"[::]:7000".parse().unwrap()));
    }

    #[test]
    fn test_parse_bind_addrs_invalid_fail_closed() {
        // 域名拒绝（监听地址必须是本机 IP）→ Err（调用方 exit(2)）。
        let cfg = parse(&["--bind-addrs", "example.com"]).unwrap();
        let err = cfg.parse_bind_addrs().unwrap_err();
        assert!(err.contains("invalid --bind-addrs"), "{err}");
        // 空段拒绝。
        let cfg = parse(&["--bind-addrs", "0.0.0.0,,::"]).unwrap();
        assert!(cfg.parse_bind_addrs().is_err());
    }

    // R-08b (S2)：--rendezvous-port / --no-rendezvous 解析与冲突 fail-closed。
    #[test]
    fn test_rendezvous_defaults() {
        // 默认：启用 + 端口 7001（不传参数即打洞可用）。
        let cfg = parse(&[]).unwrap();
        assert!(cfg.rendezvous_enabled);
        assert_eq!(cfg.rendezvous_port, 7001);
    }

    #[test]
    fn test_rendezvous_port_forms_and_validation() {
        // 两种写法等价。
        let cfg = parse(&["--rendezvous-port", "8001"]).unwrap();
        assert_eq!(cfg.rendezvous_port, 8001);
        let cfg = parse(&["--rendezvous-port=9001"]).unwrap();
        assert_eq!(cfg.rendezvous_port, 9001);
        // 非法值 / 0 / 缺值 → Err（调用方 exit(2)）。
        assert!(parse(&["--rendezvous-port", "abc"]).is_err());
        assert!(parse(&["--rendezvous-port", "0"]).is_err());
        assert!(parse(&["--rendezvous-port"]).is_err());
        // 越界（u16 溢出）。
        assert!(parse(&["--rendezvous-port", "70000"]).is_err());
    }

    #[test]
    fn test_no_rendezvous_disables() {
        let cfg = parse(&["--no-rendezvous"]).unwrap();
        assert!(!cfg.rendezvous_enabled);
        // 关闭时端口保留默认值（不生效）。
        assert_eq!(cfg.rendezvous_port, 7001);
    }

    #[test]
    fn test_rendezvous_conflicts_fail_closed() {
        // --no-rendezvous 与 --rendezvous-port 矛盾 → Err。
        let err = parse(&["--no-rendezvous", "--rendezvous-port", "8001"]).unwrap_err();
        assert!(err.contains("conflicting options"), "{err}");
        // rendezvous 端口 == 控制端口 → Err（同端口双监听必然失败）。
        let err = parse(&["--bind-port", "7001", "--rendezvous-port", "7001"]).unwrap_err();
        assert!(err.contains("conflicting options"), "{err}");
        // 显式相同值（= 写法）同样拒绝。
        let err = parse(&["--bind-port=7000", "--rendezvous-port=7000"]).unwrap_err();
        assert!(err.contains("conflicting options"), "{err}");
        // --no-rendezvous 下与 --bind-port 同号不冲突（rendezvous 未启用）。
        let cfg = parse(&["--no-rendezvous", "--bind-port", "7001"]).unwrap();
        assert!(!cfg.rendezvous_enabled);
    }
}

/// 等待关闭信号：Ctrl+C（全平台）+ SIGTERM（Unix，systemd 停止用）。
async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to install SIGTERM handler: {e}");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() {
    let cfg = match Config::parse(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            print_usage();
            std::process::exit(2);
        }
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    // R-10 (M15-T006): panic hook——panic 消息 + backtrace 落 stderr（控制台）
    // 与今日日志文件（~/.kirin_desk/logs/）；无 GUI，不弹窗。
    kirin_desk_utils::logging::install_panic_hook();

    tracing::info!("relay-server v{VERSION} starting");
    if cfg.token.is_empty() {
        tracing::warn!("token is EMPTY — anyone can log in. Use --token with a high-entropy string (>=32 bytes).");
    }
    if cfg.port_range.is_none() {
        tracing::warn!("no port range configured — client remote_port=0 requests will be rejected (use --port-range \"start-end\")");
    }

    let key_path = cfg
        .server_key
        .clone()
        .unwrap_or_else(kirin_desk_relay::registry::default_key_path);
    // M8-T039 P16b: 可选显式多监听地址。空 → relay 默认双栈回退（[::] 优先 +
    // 0.0.0.0 回退，行为零变化）；非法值 fail-closed 拒绝启动（exit 2，对齐
    // 参数解析错误路径）。
    let bind_addrs = match cfg.parse_bind_addrs() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            print_usage();
            std::process::exit(2);
        }
    };
    // R-08b (S2)：进程内打洞 rendezvous 服务（登记/互转/限速/审计复用，
    // PUNCH-006 / PUNCH-SEC-002）。绑定失败 → fail-closed 拒绝启动
    // （对齐 TunnelServer 绑定失败 exit(1) 口径）；--no-rendezvous 关闭。
    let rendezvous = if cfg.rendezvous_enabled {
        let rz = match RendezvousServer::bind(cfg.rendezvous_port).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "error: rendezvous bind failed on port {}: {e}",
                    cfg.rendezvous_port
                );
                std::process::exit(1);
            }
        }
        .with_audit(Arc::new(ConsoleAudit));
        Some(Arc::new(rz))
    } else {
        None
    };
    let srv_cfg = TunnelServerConfig {
        bind_port: cfg.bind_port,
        bind_addrs,
        token: cfg.token.clone(),
        port_range: cfg.port_range,
        max_proxies: cfg.max_proxies,
        max_concurrent_work: cfg.max_work_conns,
        rate_limit: RateLimiterConfig::default(),
        audit: Some(Arc::new(ConsoleAudit)),
        server_key_path: Some(key_path.clone()),
        // R-08b (S2)：进程内打洞 rendezvous 挂载（隧道控制连接打洞帧接入）。
        rendezvous: rendezvous.clone(),
        ..Default::default()
    };

    let server = match TunnelServer::bind(srv_cfg).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: bind failed: {e}");
            std::process::exit(1);
        }
    };

    println!("=== relay-server v{VERSION} ===");
    // 多监听场景 server.port() 只报首个 listener（对齐 relay port() 语义），
    // 实际监听地址由 Bind addrs 行展示（空 = 默认双栈回退，对齐 cli.rs 显示）。
    println!("  Control port:  {}", server.port());
    println!(
        "  Bind addrs:    {}",
        if cfg.bind_addrs.trim().is_empty() {
            "(default dual-stack)".to_string()
        } else {
            cfg.bind_addrs.trim().to_string()
        }
    );
    println!(
        "  Port range:    {}",
        cfg.port_range
            .map(|(a, b)| format!("{a}-{b}"))
            .unwrap_or_else(|| "(none — remote_port must be explicit)".to_string())
    );
    println!("  Max proxies:   {} / work conns: {}", cfg.max_proxies, cfg.max_work_conns);
    println!("  Server key:    {}", key_path.display());
    println!(
        "  Server pubkey: {}",
        server.server_public_key_base64()
    );
    println!("    ^ 客户端 ID 模式须将上面 pubkey 预置到 [tunnel] server_pubkey");
    println!(
        "  Rendezvous:    {}",
        if cfg.rendezvous_enabled {
            format!("enabled on port {}", cfg.rendezvous_port)
        } else {
            "disabled (--no-rendezvous)".to_string()
        }
    );
    println!("  Press Ctrl+C to stop.");

    let handle = server.shutdown_handle();
    let srv_task = tokio::spawn(server.run());

    // R-08b (S2)：打洞 rendezvous 服务任务（stop watch 优雅关闭）。
    let rendezvous_task = match &rendezvous {
        Some(rz) => {
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let rz = Arc::clone(rz);
            Some((stop_tx, tokio::spawn(rz.serve(stop_rx))))
        }
        None => None,
    };

    wait_shutdown_signal().await;
    tracing::info!("shutdown signal received — graceful stop (TNL-SERVER-006)");
    handle.shutdown();
    let _ = srv_task.await;
    if let Some((stop_tx, task)) = rendezvous_task {
        let _ = stop_tx.send(true);
        match tokio::time::timeout(Duration::from_secs(3), task).await {
            Ok(Ok(_)) => tracing::info!("rendezvous server stopped"),
            Ok(Err(e)) => tracing::warn!("rendezvous serve task error: {e}"),
            Err(_) => tracing::warn!("rendezvous serve task did not stop in 3s"),
        }
    }
    tracing::info!("relay-server stopped");
}
