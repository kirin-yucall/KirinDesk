//! M8-T026: 内网穿透服务端主程序（frps 等价，独立部署用）。
//!
//! 薄壳包装 [`kirin_desk_relay::server::TunnelServer`]：
//! - CLI 参数：`--bind-port` / `--token` / `--port-range` / `--server-key` /
//!   `--max-proxies` / `--max-work-conns`；
//! - 控制台日志（`RUST_LOG`，默认 `info`）+ 审计事件输出（stdout，
//!   TNL-SEC-003 全部事件 + P1/P2 打洞/设备事件）；
//! - Ctrl+C / SIGTERM 优雅关闭（TNL-SERVER-006）；
//! - 启动时打印服务器 Ed25519 公钥——ID 模式客户端须预置
//!   `[tunnel] server_pubkey`（ID-SEC-001）。
//!
//! 构建与部署：Windows 见 `release/server/README.md`，
//! Linux 见 `release/server/BUILD_LINUX.md`（用户本机编译）。

use kirin_desk_relay::audit::{AuditSink, TunnelAuditEvent};
use kirin_desk_relay::rate_limit::RateLimiterConfig;
use kirin_desk_relay::server::{TunnelServer, TunnelServerConfig};
use std::sync::Arc;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_BIND_PORT: u16 = 7000;
const DEFAULT_MAX_PROXIES: usize = 32;
const DEFAULT_MAX_WORK_CONNS: usize = 100;

/// 命令行配置。
struct Config {
    bind_port: u16,
    token: String,
    port_range: Option<(u16, u16)>,
    server_key: Option<std::path::PathBuf>,
    max_proxies: usize,
    max_work_conns: usize,
}

fn print_usage() {
    println!("relay-server v{VERSION} — KirinDesk 内网穿透服务端（frps 等价）");
    println!();
    println!("USAGE: relay-server [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --bind-port <PORT>    控制端口（默认 {DEFAULT_BIND_PORT}；[::] 优先、0.0.0.0 回退，双栈）");
    println!("  --token <TOKEN>       客户端认证 token（建议高熵 ≥32 字节；");
    println!("                        也可经环境变量 KIRIN_RELAY_TOKEN 提供）");
    println!("  --port-range <S-E>    自动分配端口范围，如 \"60000-60099\"");
    println!("                        （客户端 remote_port=0 请求用）");
    println!("  --server-key <PATH>   Ed25519 服务器密钥路径");
    println!("                        （默认 ~/.kirin_desk/relay_server_key.pem，不存在则自动生成）");
    println!("  --max-proxies <N>     每会话代理数量上限（默认 {DEFAULT_MAX_PROXIES}）");
    println!("  --max-work-conns <N>  每代理并发 work 连接上限（默认 {DEFAULT_MAX_WORK_CONNS}）");
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
            bind_port: DEFAULT_BIND_PORT,
            token: std::env::var("KIRIN_RELAY_TOKEN").unwrap_or_default(),
            port_range: None,
            server_key: None,
            max_proxies: DEFAULT_MAX_PROXIES,
            max_work_conns: DEFAULT_MAX_WORK_CONNS,
        };
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
                _ => return Err(format!("unknown option '{key}'")),
            }
        }
        Ok(cfg)
    }
}

/// 控制台审计（TNL-SEC-003 全部事件 + P1/P2 打洞/设备事件，stdout）。
#[derive(Debug)]
struct ConsoleAudit;

impl AuditSink for ConsoleAudit {
    fn record(&self, event: TunnelAuditEvent) {
        use TunnelAuditEvent::*;
        let line = match event {
            LoginSuccess { client, hostname } => {
                format!("login ok ip={client} host={hostname}")
            }
            LoginFailed { client, reason } => {
                format!("login FAILED ip={client} reason={reason}")
            }
            ProxyRegistered { client, name, port } => {
                format!("proxy registered ip={client} name={name} port={port}")
            }
            ProxyRemoved { client, name } => {
                format!("proxy removed ip={client} name={name}")
            }
            WorkConnOpened { client, name } => {
                format!("work conn opened ip={client} proxy={name}")
            }
            WorkConnClosed { client, name, reason } => {
                format!("work conn closed ip={client} proxy={name} reason={reason}")
            }
            RateLimited { client, reason } => {
                format!("rate limited ip={client} reason={reason}")
            }
            PunchCandidateRegistered { client, device_id } => {
                format!("punch candidate registered ip={client} device={device_id}")
            }
            PunchForwarded { client, device_id } => {
                format!("punch forwarded ip={client} device={device_id}")
            }
            PunchUnknownSession { client, session_id } => {
                format!("punch unknown session ip={client} session={session_id}")
            }
            DeviceRegistered { client, device_id } => {
                format!("device registered ip={client} id={device_id}")
            }
            DeviceRejected { client, device_id, reason } => {
                format!("device rejected ip={client} id={device_id} reason={reason}")
            }
            DeviceOffline { client, device_id } => {
                format!("device offline ip={client} id={device_id}")
            }
            DeviceResolveAccepted { client, device_id, online } => {
                format!("device resolve ip={client} id={device_id} online={online}")
            }
            DeviceResolveRejected { client, device_id, reason } => {
                format!("device resolve rejected ip={client} id={device_id} reason={reason}")
            }
            TunnelRelayOpened { target, from, conn_id } => {
                format!("relay opened target={target} from={from} conn={conn_id}")
            }
            TunnelRelayClosed { target, conn_id, reason } => {
                format!("relay closed target={target} conn={conn_id} reason={reason}")
            }
        };
        println!("[audit] {line}");
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
    let srv_cfg = TunnelServerConfig {
        bind_port: cfg.bind_port,
        token: cfg.token.clone(),
        port_range: cfg.port_range,
        max_proxies: cfg.max_proxies,
        max_concurrent_work: cfg.max_work_conns,
        rate_limit: RateLimiterConfig::default(),
        audit: Some(Arc::new(ConsoleAudit)),
        server_key_path: Some(key_path.clone()),
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
    println!("  Control port:  {} (all interfaces, dual-stack)", server.port());
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
    println!("  Press Ctrl+C to stop.");

    let handle = server.shutdown_handle();
    let srv_task = tokio::spawn(server.run());

    wait_shutdown_signal().await;
    tracing::info!("shutdown signal received — graceful stop (TNL-SERVER-006)");
    handle.shutdown();
    let _ = srv_task.await;
    tracing::info!("relay-server stopped");
}
