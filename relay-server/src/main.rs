//! M8-T026: 内网穿透服务端主程序（frps 等价，独立部署用）。
//!
//! 薄壳包装 [`kirin_desk_relay::server::TunnelServer`]：
//! - CLI 参数：`--bind-addrs` / `--bind-port` / `--token` / `--port-range` /
//!   `--server-key` / `--max-proxies` / `--max-work-conns` /
//!   `--interconnect-port` / `--no-interconnect` / `--relay-db` /
//! - 控制台日志（`RUST_LOG`，默认 `info`）+ 审计事件输出（stdout，
//!   TNL-SEC-003 全部事件 + P1/P2 打洞/设备事件）；
//!   关闭；候选登记/互转/限速/审计复用 [`kirin_desk_relay::rendezvous`]）；
//! - 启动时打印服务器 Ed25519 公钥——ID 模式客户端须预置
//!   `[tunnel] server_pubkey`（ID-SEC-001）。
//!
//! 构建与部署：Windows 见 `release/server/README.md`，
//! Linux 见 `release/server/BUILD_LINUX.md`（用户本机编译）。
//!
//! sqlite 设备目录（[`dir_store`]，`~/.kirin_desk/relay.db`）+ CRUD 信令
//! 后端（[`dir_backend`]，relay 面 1.2.0 十帧）+ 中继互识/pull 同步
//! （[`interconnect`]，`_kirin-relay._tcp.` DNS 三件套 + core/crypto 互认）。
//! 模块拆分申报：单文件 main.rs → 三模块（设计 §8「可按设计拆模块」）。

mod dir_backend;
mod dir_store;
mod interconnect;

use kirin_desk_dns::{Resolver, SecureResolver};
use kirin_desk_relay::audit::{AuditSink, TunnelAuditEvent};
use kirin_desk_relay::rate_limit::RateLimiterConfig;
use kirin_desk_relay::registry::Registry;
use kirin_desk_relay::rendezvous::RendezvousServer;
use kirin_desk_relay::server::{TunnelServer, TunnelServerConfig};
use std::sync::Arc;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_BIND_PORT: u16 = 7000;
const DEFAULT_RENDEZVOUS_PORT: u16 = 7001;
const DEFAULT_INTERCONNECT_PORT: u16 = 7002;
const DEFAULT_MAX_PROXIES: usize = 32;
const DEFAULT_MAX_WORK_CONNS: usize = 100;
// 本岗冻结参数面 + 启动审计行）。 ──
const DEFAULT_PUSH_ENTRY_TTL: u64 = 86400; // --push-entry-ttl（B 侧 pushed 行 TTL）
const DEFAULT_DIR_LIVENESS_TTL: u64 = 86400; // --dir-liveness-ttl（A 侧 manual 行 liveness）
const DEFAULT_PUSH_PER_SOURCE_CAP: usize = 10000; // --push-per-source-cap（B 侧单源上限）

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
    rendezvous_port: u16,
    rendezvous_enabled: bool,
    interconnect_port: u16,
    interconnect_enabled: bool,
    relay_db: std::path::PathBuf,
    dns_doh: String,
    dns_dot: String,
    /// 安全审计 R-3：空 token 时是否显式放行启动（默认 fail-closed 拒绝）。
    allow_empty_token: bool,
    dir_ip_quota: usize,
    push_repush_interval: u64,
    push_entry_ttl: u64,
    dir_liveness_ttl: u64,
    push_per_source_cap: usize,
    /// 签名域 + 接收方绑定素材）。互联启用而缺失/非纯 FQDN = fail-closed 拒启动。
    relay_domain: String,
    /// 拒收旧 `/2` 推送 + 审计 reason=legacy_no_token）。
    ix_legacy_grace: bool,
    /// <unix_ts>`，unix 秒 UTC；到期自动 fail-closed）。显式给出即隐含启用
    /// 宽限形态；与 `--ix-legacy-grace` 同给 = until 优先（到期界生效于
    /// 裁决门）；非法时间戳 = 参数错误拒启（fail-closed 不猜）。
    ix_legacy_grace_until: Option<u64>,
    /// 与 `--token`/`KIRIN_RELAY_TOKEN` 同给 = **file 优先 + WARN**；读取
    /// 失败 = fail-closed 拒启。
    token_file: Option<std::path::PathBuf>,
    /// 默认 512；0 = 拒启 fail-closed 不猜）。
    max_sessions: usize,
    /// 默认 64；0 = 拒启 fail-closed 不猜）。
    preauth_per_ip: usize,
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
    println!("                        也可经环境变量 KIRIN_RELAY_TOKEN 提供；");
    println!("                        注意 history/ps 进程命令行暴露面——推荐 --token-file）");
    println!("                        KIRIN_RELAY_TOKEN 同给 = file 优先 + WARN；读取失败/");
    println!("                        空文件 = fail-closed 拒启（空 token 口径不变）");
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
    println!("  --interconnect-port <P> 中继互联端口（默认 {DEFAULT_INTERCONNECT_PORT}；");
    println!("                        中继互识/pull 同步，_kirin-relay._tcp. SRV 发布该端口；");
    println!("                        须与 --bind-port/--rendezvous-port 均不同）");
    println!("  --no-interconnect     关闭中继互联（不监听 --interconnect-port，目录 CRUD 仍可用）");
    println!("  --relay-db <PATH>     目录 sqlite 库路径（默认 ~/.kirin_desk/relay.db，");
    println!("                        与服务器密钥同卷——容器 relay-server-key 卷，compose 零改）");
    println!("  --dns-doh <CSV>       加密 DNS DoH 端点优先序（逗号分隔；");
    println!("                        缺省 = 内置 Cloudflare/Google/阿里云 DNS）");
    println!("  --dns-dot <CSV>       加密 DNS DoT 端点优先序（逗号分隔；缺省 = 内置）");
    println!("  --allow-empty-token   显式允许空 token 启动（默认空 token 拒绝启动，");
    println!("                        对齐 CLI cmd_tunnel_serve 的 TNL-SEC-008 fail-closed 口径）");
    println!("  --dir-ip-quota <N>    单 IP 注册配额（distinct 设备数；默认 {}；", dir_backend::DEFAULT_DIR_IP_QUOTA);
    println!("                        0 = 不限〔启动 WARN〕；IPv4 原址 / IPv6 /64 聚合 / mapped 归一）");
    println!("  --push-repush-interval <sec> A 侧周期重推间隔（默认 {DEFAULT_PUSH_REPUSH_INTERVAL}）");
    println!("  --push-entry-ttl <sec> B 侧 pushed 行 TTL（默认 {DEFAULT_PUSH_ENTRY_TTL}）");
    println!("  --dir-liveness-ttl <sec> A 侧 manual 行 liveness TTL（默认 {DEFAULT_DIR_LIVENESS_TTL}）");
    println!("  --push-per-source-cap <N>  B 侧单源 pushed 行上限（默认 {DEFAULT_PUSH_PER_SOURCE_CAP}）");
    println!("  --relay-domain <FQDN> 本 relay 自身 FQDN（互联启用**必填**；HELLO v2");
    println!("                        id_domain 签名域；非纯 FQDN 或缺失 = fail-closed 拒启动）");
    println!("  --ix-legacy-grace     旧版中继宽限开关（默认关 = fail-closed）：收到");
    println!("                        RELAY-DIR/2 旧握手（旧 home 推送无 token）时，");
    println!("                        开 = 按旧五门受理（迁移期放行）；关 = 拒收 + 审计");
    println!("                        reason=legacy_no_token。两端升级完成后应关闭");
    println!("                        unix 秒 UTC，过点（含等界）自动 fail-closed 恢复");
    println!("                        严格校验（忘关自愈收紧）；显式给出即隐含启用宽限；");
    println!("                        与 --ix-legacy-grace 同给 = until 优先；非法时间戳拒启");
    println!("  --max-sessions <N>    全局在线会话上限（默认 512；0 = 拒启）：超限登录");
    println!("                        fail-closed 拒绝（LoginResp ok=false 回执 + 审计）");
    println!("  --preauth-per-ip <N>  pre-auth 每 IP 并发上限（默认 64；0 = 拒启）：满额 IP");
    println!("                        新连接 ack 前就地丢弃 + 审计（慢连接/洪泛面收敛）");
    println!("  --help                显示本帮助");
    println!("  --version             显示版本");
    println!();
    println!("SUBCOMMANDS（短事务操作后即退，不进服务主循环）:");
    println!("  relay-server tokens list                列出互联 token（token 列仅前 8 位前缀，");
    println!("                                          全量只在 tokens add 时打印一次）");
    println!("  relay-server tokens add --label <必填>   生成并登记互联 token（≥32B 随机");
    println!("                                          base64url；label 空 = 拒绝退出非 0）");
    println!("  relay-server tokens revoke <id>         软撤销（行保留；id 不存在 = 报错退出非 0）");
    println!("  relay-server pubkey rotate              重生成服务器 Ed25519 密钥对（旧密钥备份");
    println!("                                          .pem.bak；rotate 后需重启服务进程生效，");
    println!("                                          DNS TXT 公钥记录必须同步更新）");
    println!("  通用选项：--relay-db <PATH>（默认 ~/.kirin_desk/relay.db）、");
    println!("            --server-key <PATH>（默认 ~/.kirin_desk/relay_server_key.pem）");
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
        return Err(format!("invalid --port-range '{a}': ports must be > 0"));
    }
    if a > b {
        return Err(format!("invalid --port-range '{s}': start must be <= end"));
    }
    Ok((a, b))
}

/// Err（fail-closed 拒启，上游 exit 2）；空文件 = Ok("")（上游空 token 门
/// 继续拦 = 仍拒启）。**文件内容零打印零日志**（错误信息只含路径与 IO
/// 错误，不含内容——红线）。
fn read_token_file(path: &std::path::Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "cannot read token file {}: {e} — refusing to start (fail-closed)",
            path.display()
        )
    })?;
    Ok(raw.lines().next().unwrap_or("").trim().to_string())
}

/// Some（文件读取成功，含空串）→ **file 优先**；`cli_token` =
/// `--token`/`KIRIN_RELAY_TOKEN` 在场面（非空 = 有冲突）；返回
/// (最终 token, 是否冲突 WARN)。file 缺失 = 既有链路原样透传
/// （`--token` > 环境变量默认——Config::parse 既有口径不变）。
fn pick_token_source(file_token: Option<&str>, cli_token: &str) -> (String, bool) {
    match file_token {
        Some(t) => (t.to_string(), !cli_token.is_empty()),
        None => (cli_token.to_string(), false),
    }
}

/// rotate 起因 = 私钥怀疑泄露时，被泄露私钥不得留盘）。README §5 同步话术。
fn rotate_bak_reminder(path: &std::path::Path) -> String {
    format!(
        "    4) After the new link is verified working, delete the old key backup {}.bak \
         (especially if this rotate was prompted by suspected key compromise).",
        path.display()
    )
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
            // （~/.kirin_desk/relay.db——容器内 = relay-server-key 卷路径）。
            interconnect_port: DEFAULT_INTERCONNECT_PORT,
            interconnect_enabled: true,
            relay_db: kirin_desk_relay::registry::default_key_path()
                .parent()
                .map(|p| p.join("relay.db"))
                .unwrap_or_else(|| std::path::PathBuf::from("relay.db")),
            dns_doh: String::new(),
            dns_dot: String::new(),
            allow_empty_token: false,
            dir_ip_quota: dir_backend::DEFAULT_DIR_IP_QUOTA,
            push_repush_interval: DEFAULT_PUSH_REPUSH_INTERVAL,
            push_entry_ttl: DEFAULT_PUSH_ENTRY_TTL,
            dir_liveness_ttl: DEFAULT_DIR_LIVENESS_TTL,
            push_per_source_cap: DEFAULT_PUSH_PER_SOURCE_CAP,
            relay_domain: String::new(),
            ix_legacy_grace: false,
            ix_legacy_grace_until: None,
            token_file: None,
            max_sessions: kirin_desk_relay::server::DEFAULT_MAX_SESSIONS,
            preauth_per_ip: kirin_desk_relay::server::DEFAULT_PREAUTH_PER_IP,
        };
        // 互斥校验用）。
        let mut rendezvous_port_explicit = false;
        // 互斥校验用）。
        let mut interconnect_port_explicit = false;
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
                "--token-file" => {
                    let v = next_value(&mut args, &inline, "--token-file")?;
                    cfg.token_file = Some(std::path::PathBuf::from(v));
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
                "--interconnect-port" => {
                    let v = next_value(&mut args, &inline, "--interconnect-port")?;
                    let p: u16 = v
                        .parse()
                        .map_err(|_| format!("invalid --interconnect-port '{v}'"))?;
                    if p == 0 {
                        return Err(format!(
                            "invalid --interconnect-port '0' (ports must be 1-65535)"
                        ));
                    }
                    cfg.interconnect_port = p;
                    interconnect_port_explicit = true;
                }
                "--no-interconnect" => {
                    cfg.interconnect_enabled = false;
                }
                "--relay-db" => {
                    let v = next_value(&mut args, &inline, "--relay-db")?;
                    if v.trim().is_empty() {
                        return Err("invalid --relay-db: empty path".to_string());
                    }
                    cfg.relay_db = v.into();
                }
                "--dns-doh" => {
                    let v = next_value(&mut args, &inline, "--dns-doh")?;
                    cfg.dns_doh = v;
                }
                "--dns-dot" => {
                    let v = next_value(&mut args, &inline, "--dns-dot")?;
                    cfg.dns_dot = v;
                }
                "--allow-empty-token" => {
                    cfg.allow_empty_token = true;
                }
                // 0 语义分两类：--dir-ip-quota 0 = 显式「不限」（启动 WARN）；
                // 其余四参 0 = 退化配置（自旋/立逝/零容量）= fail-closed 拒。
                "--dir-ip-quota" => {
                    let v = next_value(&mut args, &inline, "--dir-ip-quota")?;
                    cfg.dir_ip_quota = v
                        .parse()
                        .map_err(|_| format!("invalid --dir-ip-quota '{v}' (unsigned integer)"))?;
                }
                "--push-repush-interval" => {
                    let v = next_value(&mut args, &inline, "--push-repush-interval")?;
                    let s: u64 = v
                        .parse()
                        .map_err(|_| format!("invalid --push-repush-interval '{v}'"))?;
                    if s == 0 {
                        return Err(
                            "invalid --push-repush-interval '0' (seconds must be > 0)".to_string(),
                        );
                    }
                    cfg.push_repush_interval = s;
                }
                "--push-entry-ttl" => {
                    let v = next_value(&mut args, &inline, "--push-entry-ttl")?;
                    let s: u64 = v
                        .parse()
                        .map_err(|_| format!("invalid --push-entry-ttl '{v}'"))?;
                    if s == 0 {
                        return Err(
                            "invalid --push-entry-ttl '0' (seconds must be > 0)".to_string(),
                        );
                    }
                    cfg.push_entry_ttl = s;
                }
                "--dir-liveness-ttl" => {
                    let v = next_value(&mut args, &inline, "--dir-liveness-ttl")?;
                    let s: u64 = v
                        .parse()
                        .map_err(|_| format!("invalid --dir-liveness-ttl '{v}'"))?;
                    if s == 0 {
                        return Err(
                            "invalid --dir-liveness-ttl '0' (seconds must be > 0)".to_string(),
                        );
                    }
                    cfg.dir_liveness_ttl = s;
                }
                "--push-per-source-cap" => {
                    let v = next_value(&mut args, &inline, "--push-per-source-cap")?;
                    let n: usize = v
                        .parse()
                        .map_err(|_| format!("invalid --push-per-source-cap '{v}' (unsigned integer)"))?;
                    if n == 0 {
                        return Err(
                            "invalid --push-per-source-cap '0' (cap must be > 0; 0 = refuse all pushes)".to_string(),
                        );
                    }
                    cfg.push_per_source_cap = n;
                }
                "--relay-domain" => {
                    let v = next_value(&mut args, &inline, "--relay-domain")?;
                    cfg.relay_domain = dir_backend::normalize_domain(&v);
                }
                // 先例同构）。
                "--ix-legacy-grace" => {
                    cfg.ix_legacy_grace = true;
                }
                // 非法时间戳 = 参数错误拒启（fail-closed 不猜）。
                "--ix-legacy-grace-until" => {
                    let v = next_value(&mut args, &inline, "--ix-legacy-grace-until")?;
                    let ts: u64 = v.parse().map_err(|_| {
                        format!(
                            "invalid --ix-legacy-grace-until '{v}' (unsigned unix seconds UTC)"
                        )
                    })?;
                    cfg.ix_legacy_grace_until = Some(ts);
                    cfg.ix_legacy_grace = true;
                }
                // fail-closed 不猜；非数字 = 参数错误拒启）。
                "--max-sessions" => {
                    let v = next_value(&mut args, &inline, "--max-sessions")?;
                    let n: usize = v
                        .parse()
                        .map_err(|_| format!("invalid --max-sessions '{v}' (unsigned integer)"))?;
                    if n == 0 {
                        return Err(
                            "invalid --max-sessions '0' (must be > 0; refusing to start, fail-closed)"
                                .to_string(),
                        );
                    }
                    cfg.max_sessions = n;
                }
                "--preauth-per-ip" => {
                    let v = next_value(&mut args, &inline, "--preauth-per-ip")?;
                    let n: usize = v
                        .parse()
                        .map_err(|_| format!("invalid --preauth-per-ip '{v}' (unsigned integer)"))?;
                    if n == 0 {
                        return Err(
                            "invalid --preauth-per-ip '0' (must be > 0; refusing to start, fail-closed)"
                                .to_string(),
                        );
                    }
                    cfg.preauth_per_ip = n;
                }
                _ => return Err(format!("unknown option '{key}'")),
            }
        }
        // 到期自动 fail-closed 仍生效；不拒启——运维可能正处迁移收尾窗口）。
        if let Some(ts) = cfg.ix_legacy_grace_until {
            if crate::dir_store::now_unix_secs() >= ts {
                tracing::warn!(
                    "--ix-legacy-grace-until {ts}: expiry already in the past — legacy \
                     grace is effective-immediately-expired (fail-closed); extend the \
                     timestamp explicitly if the migration is still in flight"
                );
            }
        }
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
        if !cfg.interconnect_enabled && interconnect_port_explicit {
            return Err(
                "conflicting options: --no-interconnect cannot be combined with --interconnect-port"
                    .to_string(),
            );
        }
        if cfg.interconnect_enabled && cfg.interconnect_port == cfg.bind_port {
            return Err(format!(
                "conflicting options: --interconnect-port {} equals --bind-port (must differ)",
                cfg.interconnect_port
            ));
        }
        if cfg.interconnect_enabled
            && cfg.rendezvous_enabled
            && cfg.interconnect_port == cfg.rendezvous_port
        {
            return Err(format!(
                "conflicting options: --interconnect-port {} equals --rendezvous-port (must differ)",
                cfg.interconnect_port
            ));
        }
        // 缺失或非纯 FQDN = 拒启动（HELLO v2 id_domain 签名域必填；缺 =
        // 互认面不可建，宁拒不猜）。互联关闭时参数不参与校验（无消费端）。
        if cfg.interconnect_enabled && !dir_backend::is_pure_fqdn(&cfg.relay_domain) {
            return Err(format!(
                "--relay-domain: interconnect enabled requires a pure FQDN relay domain \
                 (got '{}' — refusing to start, fail-closed)",
                cfg.relay_domain
            ));
        }
        Ok(cfg)
    }

    fn dns_endpoints(&self, given: &str, default: &[String]) -> Vec<String> {
        if given.trim().is_empty() {
            return default.to_vec();
        }
        given
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
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

/// `DeviceOffline` 审计事件族**旁路**（设计 §3.8 hook 点；relay 隧道面
/// 零改动）：维护在线设备集（registry 活体口径，`DirLivenessProbe`）+
/// `devlast:<id>` 水位（隧道登录刷新；DirUpsert 另在 store 事务内刷新）。
/// 全部事件原样转发内层审计 sink（控制台行零变化）。
#[derive(Debug)]
struct DirLivenessBridge {
    inner: Arc<dyn AuditSink>,
    store: Arc<dir_store::DirStore>,
    online: tokio::sync::Mutex<std::collections::HashSet<String>>,
}

impl DirLivenessBridge {
    fn new(inner: Arc<dyn AuditSink>, store: Arc<dir_store::DirStore>) -> Self {
        Self {
            inner,
            store,
            online: tokio::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
}

impl AuditSink for DirLivenessBridge {
    fn record(&self, event: TunnelAuditEvent) {
        match &event {
            TunnelAuditEvent::DeviceRegistered { device_id, .. } => {
                if let Ok(mut set) = self.online.try_lock() {
                    set.insert(device_id.clone());
                }
                // devlast 水位（异步落 meta；liveness 清扫判据素材，T8）。
                let store = Arc::clone(&self.store);
                let id = device_id.clone();
                let ts = dir_store::now_unix_secs().to_string();
                tokio::spawn(async move {
                    let _ = store.set_meta(&format!("devlast:{id}"), &ts).await;
                });
            }
            TunnelAuditEvent::DeviceOffline { device_id, .. } => {
                if let Ok(mut set) = self.online.try_lock() {
                    set.remove(device_id);
                }
            }
            _ => {}
        }
        self.inner.record(event);
    }
}

impl crate::interconnect::DirLivenessProbe for DirLivenessBridge {
    /// 设备是否当前在线（registry 活体口径；锁竞争败 = false fail-safe：
    /// 清扫侧「不在注册表」判据宁保守——但 try_lock 败概率近零）。
    fn is_online(&self, device_id: &str) -> bool {
        self.online
            .try_lock()
            .map(|set| set.contains(device_id))
            .unwrap_or(false)
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
        // 攻击者可控字符串一律 escape_control（S-16d 先例）；零凭据
        // （id/domain/fp/码/数值）。行格式单测钉死（test_r140_1_audit_line
        // _formats_frozen，设计 §2.5）。
        DirUpserted {
            client,
            device_id,
            target_domain,
            domain,
            quota_used,
            quota_limit,
        } => {
            format!(
                esc(device_id),
                esc(target_domain),
                esc(domain)
            )
        }
        DirDeleted { client, device_id, target_domain } => {
            format!(
                esc(device_id),
                esc(target_domain)
            )
        }
        DirWriteRejected { client, device_id, code, detail } => {
            format!(
                esc(device_id),
                esc(detail)
            )
        }
        DirQuotaRejected { client, device_id, used, limit } => {
            format!(
                esc(device_id)
            )
        }
        // FQDN/签名互证 + 废帧保留位结构校验丢弃，§2.5 行表在案）。
        InterconnectRejected { peer, fp, reason } => {
        }
        // 可控字段 = reason/device_id 经 esc，domain FQDN 校验过 = raw，
        // fp 代码派生 = raw）。
        PushOk { target_domain, fp, entries, epoch } => {
            format!(
            )
        }
        PushFailed { target_domain, fp, reason } => {
            format!(
                esc(reason)
            )
        }
        PushRejected { peer_domain, fp, reason } => {
            format!(
                esc(reason)
            )
        }
        PushApplied { source_fp, entries, removed, epoch } => {
            format!(
            )
        }
        PushOutboxEnqueued { target_domain } => {
        }
        PushOutboxPruned { target_domain, n, reason } => {
        }
        PushSourceExpired { fp, rows } => {
        }
        DirRowExpired { device_id, target_domain } => {
            format!(
                esc(device_id)
            )
        }
        // 裸批；outbox 零触碰）。reason = 内部语义串，esc 转义。 ──
        PushSkippedNoToken { target_domain, reason } => {
            format!(
                esc(reason)
            )
        }
        // 不变机制沿用原卡号前缀（设计 §2.5 明确：损坏处置路径零改）。
        DirDbCorruptRebuilt { detail } => {
        }
        // v2 另承载废帧保留位（0x90~0x94）到达 = 结构校验 + 丢弃 + 审计
        // （设计 §5 点位 18）；行机制零改，前缀沿用。
        DirFrameDropped { client, frame } => {
        }
        // 0` = 不限时启动 WARN + 本行，设计 §2.6/§4.2）。
        DirStartupConfig {
            ip_quota,
            repush_interval,
            push_ttl,
            liveness_ttl,
            per_source_cap,
        } => {
            format!(
            )
        }
        // 60s 最小间隔；列表照常应答，只挡推送触发面）。行格式冻结申报。 ──
        DirRefreshThrottled { client } => {
        }
        // 每会话令牌桶超限）。client 为 SocketAddr 代码派生零转义面，
        // rows 数值。行格式冻结申报（任务说明 §3.1 口径）。 ──
        DirListAllQueried { client, rows } => {
        }
        DirListThrottled { client } => {
        }
        // 面零拦截；from_key/to_key = 配额键代码派生，device_id 经 esc）。
        // 行格式冻结申报。 ──
        DirQuotaKeyMigrated { client, device_id, from_key, to_key } => {
            format!(
                esc(device_id),
                esc(from_key),
                esc(to_key)
            )
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

#[cfg(test)]
mod r168_cli_tests {
    use super::{generate_ix_token, parse_sub_args, SubArgs};

    fn parse(rest: &[&str]) -> Result<SubArgs, String> {
        parse_sub_args(&rest.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn test_r168_generate_ix_token_shape() {
        // ≥32B 随机 = base64url 无填充 43 字符；URL 安全字母表；两次生成
        // 必不相同（CSPRNG）。
        let t1 = generate_ix_token();
        assert_eq!(t1.len(), 43, "32B → base64url 无填充 43 字符: {t1}");
        assert!(
            t1.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "URL-safe 字符集: {t1}"
        );
        assert_ne!(t1, generate_ix_token());
    }

    #[test]
    fn test_r168_sub_args_parse() {
        // 两种写法等价 + 位置参数（revoke <id>）。
        let a = parse(&["--relay-db", "/tmp/r.db", "revoke", "7"]).unwrap();
        assert_eq!(a.relay_db.unwrap().to_string_lossy(), "/tmp/r.db");
        assert_eq!(a.positional, vec!["revoke".to_string(), "7".to_string()]);
        let a = parse(&["--server-key=/k.pem", "--label=alpha"]).unwrap();
        assert_eq!(a.server_key.unwrap().to_string_lossy(), "/k.pem");
        assert_eq!(a.label.as_deref(), Some("alpha"));
        assert!(!a.help);
        // help 位 + 未知选项拒 + 缺值拒。
        assert!(parse(&["--help"]).unwrap().help);
        assert!(parse(&["--bogus"]).is_err());
        assert!(parse(&["--label"]).is_err());
    }
}

// M8-T039 P16b: Config::parse 参数解析单测（--bind-addrs 两种写法、缺值、
// 默认空、parse_bind_addrs 合法/非法值 fail-closed）。
#[cfg(test)]
mod config_parse_tests {
    use super::{
        pick_token_source, read_token_file, rotate_bak_reminder, Config, DEFAULT_DIR_LIVENESS_TTL,
        DEFAULT_PUSH_ENTRY_TTL, DEFAULT_PUSH_PER_SOURCE_CAP, DEFAULT_PUSH_REPUSH_INTERVAL,
    };

    fn parse(args: &[&str]) -> Result<Config, String> {
        Config::parse(args.iter().map(|s| s.to_string()))
    }

    /// Ok 断言用的解析助手 = 自动补 `--relay-domain <RD>`（值断言见
    /// `test_r140_1_*`；Err 断言路径不受影响——各类值错误先于域名校验）。
    const RD: &str = "a.relay.example.com";

    fn parse_ok(args: &[&str]) -> Config {
        let mut all: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        all.push("--relay-domain".to_string());
        all.push(RD.to_string());
        Config::parse(all.into_iter()).expect("parse_ok: domain 补齐后必须可解析")
    }

    #[test]
    fn test_bind_addrs_default_empty() {
        // 不传 --bind-addrs → 空串（relay 默认双栈回退，行为与旧版一致）。
        let cfg = parse_ok(&[]);
        assert_eq!(cfg.bind_addrs, "");
        assert_eq!(cfg.parse_bind_addrs().unwrap(), vec![]);
    }

    #[test]
    fn test_bind_addrs_space_and_equals_forms() {
        // `--key value` 与 `--key=value` 两种写法等价。
        let cfg = parse_ok(&["--bind-addrs", "0.0.0.0,::"]);
        assert_eq!(cfg.bind_addrs, "0.0.0.0,::");
        let cfg = parse_ok(&["--bind-addrs=127.0.0.1,::1"]);
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
        let cfg = parse_ok(&["--bind-addrs", "0.0.0.0,::", "--bind-port", "7000"]);
        let v = cfg.parse_bind_addrs().unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.contains(&"0.0.0.0:7000".parse().unwrap()));
        assert!(v.contains(&"[::]:7000".parse().unwrap()));
    }

    #[test]
    fn test_parse_bind_addrs_invalid_fail_closed() {
        // 域名拒绝（监听地址必须是本机 IP）→ Err（调用方 exit(2)）。
        let cfg = parse_ok(&["--bind-addrs", "example.com"]);
        let err = cfg.parse_bind_addrs().unwrap_err();
        assert!(err.contains("invalid --bind-addrs"), "{err}");
        // 空段拒绝。
        let cfg = parse_ok(&["--bind-addrs", "0.0.0.0,,::"]);
        assert!(cfg.parse_bind_addrs().is_err());
    }

    #[test]
    fn test_rendezvous_defaults() {
        // 默认：启用 + 端口 7001（不传参数即打洞可用）。
        let cfg = parse_ok(&[]);
        assert!(cfg.rendezvous_enabled);
        assert_eq!(cfg.rendezvous_port, 7001);
    }

    #[test]
    fn test_rendezvous_port_forms_and_validation() {
        // 两种写法等价。
        let cfg = parse_ok(&["--rendezvous-port", "8001"]);
        assert_eq!(cfg.rendezvous_port, 8001);
        let cfg = parse_ok(&["--rendezvous-port=9001"]);
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
        let cfg = parse_ok(&["--no-rendezvous"]);
        assert!(!cfg.rendezvous_enabled);
        // 关闭时端口保留默认值（不生效）。
        assert_eq!(cfg.rendezvous_port, 7001);
    }

    // 安全审计 R-3：--allow-empty-token 解析（默认 false，fail-closed 兜底在 main()）。
    #[test]
    fn test_allow_empty_token_flag() {
        assert!(!parse_ok(&[]).allow_empty_token);
        assert!(parse_ok(&["--allow-empty-token"]).allow_empty_token);
        // 与 --token 不冲突（显式 token 时开关无实际影响）。
        let cfg = parse_ok(&["--token", "x", "--allow-empty-token"]);
        assert!(cfg.allow_empty_token);
        // = 写法同样生效。
        assert!(parse_ok(&["--allow-empty-token=true"]).allow_empty_token);
    }


    #[test]
    fn test_r183_rotate_bak_reminder_text() {
        // 第 4 条提醒话术钉死：含 .bak 路径 + 删除动作 + 泄露语境（README §5 同步）。
        let r = rotate_bak_reminder(std::path::Path::new("/opt/relay/relay_server_key.pem"));
        assert!(r.contains("4)"), "编号第 4 条: {r}");
        assert!(r.contains("/opt/relay/relay_server_key.pem.bak"), "含备份路径: {r}");
        assert!(r.contains("delete the old key backup"), "删除动作: {r}");
        assert!(r.contains("suspected key compromise"), "泄露起因语境: {r}");
        assert!(r.contains("After the new link is verified working"), "新链路验证生效后: {r}");
    }

    #[test]
    fn test_r183_read_token_file_matrix() {
        let dir = std::env::temp_dir().join(format!("kirin_r183_tokfile_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // ① 合法单行 + 尾随换行/空白 = trim。
        let p1 = dir.join("ok.txt");
        std::fs::write(&p1, "  tok-abc-123 \n").unwrap();
        assert_eq!(read_token_file(&p1).unwrap(), "tok-abc-123");
        // ② 多行文件 = 只取首行。
        let p2 = dir.join("multi.txt");
        std::fs::write(&p2, "first-line-token\nsecond-line-ignored\n").unwrap();
        assert_eq!(read_token_file(&p2).unwrap(), "first-line-token");
        // ③ 空文件 = Ok("")（上游空 token 门继续拦 = 仍拒启）。
        let p3 = dir.join("empty.txt");
        std::fs::write(&p3, "").unwrap();
        assert_eq!(read_token_file(&p3).unwrap(), "");
        // ④ 缺文件 = Err（fail-closed）。
        let p4 = dir.join("missing.txt");
        assert!(read_token_file(&p4).unwrap_err().contains("refusing to start"));
        // ⑤ 路径为目录（读取失败类）= Err。
        assert!(read_token_file(&dir).is_err());
        // ⑥ 错误信息零含文件内容（红线：token 零落日志）。
        let err = read_token_file(&p4).unwrap_err();
        assert!(!err.contains("tok-abc"), "错误信息不得含文件内容: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r183_pick_token_source_matrix() {
        // file 优先 + 冲突 WARN 标志。
        let (t, w) = pick_token_source(Some("file-tok"), "cli-tok");
        assert_eq!(t, "file-tok");
        assert!(w, "同给 = file 胜出 + WARN");
        // 仅 file（含空串）零冲突。
        let (t, w) = pick_token_source(Some("file-tok"), "");
        assert_eq!(t, "file-tok");
        assert!(!w);
        // file 为空串 + cli 非空：file 仍优先（上游空 token 门拒启 = fail-closed
        // 不被 cli 串"救回"——空文件语义 = 置空）。
        let (t, w) = pick_token_source(Some(""), "cli-tok");
        assert_eq!(t, "");
        assert!(w);
        // 无 file = 既有链路透传（--token > env），零 WARN。
        let (t, w) = pick_token_source(None, "cli-tok");
        assert_eq!(t, "cli-tok");
        assert!(!w);
    }

    #[test]
    fn test_r183_token_file_flag_parse() {
        // --token-file 解析（含 --key=value 写法）。
        let cfg = parse_ok(&["--token-file", "/tmp/tk.txt"]);
        assert_eq!(
            cfg.token_file.as_deref(),
            Some(std::path::Path::new("/tmp/tk.txt"))
        );
        let cfg = parse_ok(&["--token-file=/tmp/tk2.txt"]);
        assert_eq!(
            cfg.token_file.as_deref(),
            Some(std::path::Path::new("/tmp/tk2.txt"))
        );
        // 缺值 = parse Err（fail-closed）。
        let mut args: Vec<String> = ["--token-file".to_string(), "--relay-domain".to_string(), RD.to_string()].into();
        assert!(Config::parse(args.drain(..)).is_err());
        // 默认 None。
        assert!(parse_ok(&[]).token_file.is_none());
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
        let cfg = parse_ok(&["--no-rendezvous", "--bind-port", "7001"]);
        assert!(!cfg.rendezvous_enabled);
    }

    // 解析与冲突 fail-closed（同构 rendezvous 先例）。
    #[test]
    fn test_r137_12_interconnect_defaults() {
        let cfg = parse_ok(&[]);
        assert!(cfg.interconnect_enabled);
        assert_eq!(cfg.interconnect_port, 7002);
        assert!(!cfg.relay_db.to_string_lossy().is_empty());
    }

    #[test]
    fn test_r137_12_interconnect_port_forms_and_validation() {
        let cfg = parse_ok(&["--interconnect-port", "8002"]);
        assert_eq!(cfg.interconnect_port, 8002);
        let cfg = parse_ok(&["--interconnect-port=9002"]);
        assert_eq!(cfg.interconnect_port, 9002);
        // 非法 / 0 / 缺值 / 越界 = Err（调用方 exit(2)）。
        assert!(parse(&["--interconnect-port", "abc"]).is_err());
        assert!(parse(&["--interconnect-port", "0"]).is_err());
        assert!(parse(&["--interconnect-port"]).is_err());
        assert!(parse(&["--interconnect-port", "70000"]).is_err());
    }

    #[test]
    fn test_r137_12_interconnect_conflicts_fail_closed() {
        // --no-interconnect 与 --interconnect-port 矛盾 → Err。
        let err = parse(&["--no-interconnect", "--interconnect-port", "8002"]).unwrap_err();
        assert!(err.contains("conflicting options"), "{err}");
        // 互联端口 == 控制端口 → Err。
        let err = parse(&["--bind-port", "7002", "--interconnect-port", "7002"]).unwrap_err();
        assert!(err.contains("conflicting options"), "{err}");
        // 互联端口 == rendezvous 端口 → Err。
        let err = parse(&["--rendezvous-port", "7002", "--interconnect-port", "7002"]).unwrap_err();
        assert!(err.contains("conflicting options"), "{err}");
        // --no-interconnect 下与控制端口同号不冲突。
        let cfg = parse_ok(&["--no-interconnect", "--bind-port", "7002"]);
        assert!(!cfg.interconnect_enabled);
        // --no-rendezvous 下互联与 7001 同号不冲突（rendezvous 未启用）。
        let cfg = parse_ok(&["--no-rendezvous", "--interconnect-port", "7001"]);
        assert_eq!(cfg.interconnect_port, 7001);
        assert!(cfg.interconnect_enabled);
    }

    #[test]
    fn test_r137_12_relay_db_and_dns_flags() {
        let cfg = parse_ok(&[
            "--relay-db",
            "/tmp/relay.db",
            "--dns-doh",
            "https://d.example/dns-query, https://d2.example/resolve",
            "--dns-dot",
            "1.1.1.1:853",
        ]);
        assert_eq!(cfg.relay_db.to_string_lossy(), "/tmp/relay.db");
        let doh = cfg.dns_endpoints(&cfg.dns_doh, &[]);
        assert_eq!(doh, vec!["https://d.example/dns-query", "https://d2.example/resolve"]);
        let dot = cfg.dns_endpoints(&cfg.dns_dot, &[]);
        assert_eq!(dot, vec!["1.1.1.1:853"]);
        // 空值 = 默认回退。
        assert_eq!(cfg.dns_endpoints("", &["def".to_string()]), vec!["def".to_string()]);
        // 空库路径 = 拒。
        assert!(parse(&["--relay-db", ""]).is_err());
    }


    #[test]
    fn test_r140_1_engine_param_defaults() {
        let cfg = parse_ok(&[]);
        assert_eq!(cfg.dir_ip_quota, crate::dir_backend::DEFAULT_DIR_IP_QUOTA);
        assert_eq!(cfg.push_repush_interval, DEFAULT_PUSH_REPUSH_INTERVAL);
        assert_eq!(cfg.push_entry_ttl, DEFAULT_PUSH_ENTRY_TTL);
        assert_eq!(cfg.dir_liveness_ttl, DEFAULT_DIR_LIVENESS_TTL);
        assert_eq!(cfg.push_per_source_cap, DEFAULT_PUSH_PER_SOURCE_CAP);
        assert_eq!(cfg.relay_domain, RD);
    }

    #[test]
    fn test_r140_1_engine_param_forms_and_validation() {
        // 两写法等价 + 合法值。
        let cfg = parse(&[
            "--relay-domain",
            RD,
            "--dir-ip-quota",
            "100",
            "--push-repush-interval",
            "1800",
            "--push-entry-ttl",
            "43200",
            "--dir-liveness-ttl",
            "3600",
            "--push-per-source-cap",
            "500",
        ])
        .unwrap();
        assert_eq!(cfg.dir_ip_quota, 100);
        assert_eq!(cfg.push_repush_interval, 1800);
        assert_eq!(cfg.push_entry_ttl, 43200);
        assert_eq!(cfg.dir_liveness_ttl, 3600);
        assert_eq!(cfg.push_per_source_cap, 500);
        // = 写法 + 域名归一（trim + 小写）；`--dir-ip-quota 0` = 不限
        // （解析放行，启动 WARN——不在解析期拒）。
        let cfg = parse(&["--relay-domain=RELAY-Example.COM", "--dir-ip-quota=0"]).unwrap();
        assert_eq!(cfg.relay_domain, "relay-example.com");
        assert_eq!(cfg.dir_ip_quota, 0);
        // 非数字 / 缺值 = Err（调用方 exit(2)）。
        assert!(parse(&["--relay-domain", RD, "--dir-ip-quota", "abc"]).is_err());
        assert!(parse(&["--relay-domain", RD, "--dir-ip-quota"]).is_err());
        assert!(parse(&["--relay-domain", RD, "--push-repush-interval", "abc"]).is_err());
        // 其余四参 0 = 退化配置 = fail-closed 拒（--dir-ip-quota 除外）。
        assert!(parse(&["--relay-domain", RD, "--push-repush-interval", "0"]).is_err());
        assert!(parse(&["--relay-domain", RD, "--push-entry-ttl", "0"]).is_err());
        assert!(parse(&["--relay-domain", RD, "--dir-liveness-ttl", "0"]).is_err());
        assert!(parse(&["--relay-domain", RD, "--push-per-source-cap", "0"]).is_err());
        assert!(parse(&["--relay-domain", RD, "--push-per-source-cap", "-5"]).is_err());
    }

    #[test]
    fn test_r140_1_relay_domain_fail_closed() {
        // 互联启用（默认）而 --relay-domain 缺失 = 拒启动（PM 裁可口径）。
        let err = parse(&[]).unwrap_err();
        assert!(err.contains("--relay-domain"), "{err}");
        // 非纯 FQDN = 拒（单标签 / 含 :port / IP 字面量）。
        for bad in ["localhost", "relay.example.com:7002", "203.0.113.7", "not-an-fqdn"] {
            let err = parse(&["--relay-domain", bad]).unwrap_err();
            assert!(err.contains("--relay-domain"), "{bad}: {err}");
        }
        // --no-interconnect + 缺失 = 不要求（无消费端）。
        let cfg = parse(&["--no-interconnect"]).unwrap();
        assert_eq!(cfg.relay_domain, "");
        // 互联启用 + 合法 FQDN = 过。
        let cfg = parse(&["--relay-domain", RD]).unwrap();
        assert!(cfg.interconnect_enabled);
        assert_eq!(cfg.relay_domain, RD);
    }

    #[test]
    fn test_r168_ix_legacy_grace_flag() {
        assert!(!parse_ok(&[]).ix_legacy_grace, "默认关 = fail-closed");
        assert!(parse_ok(&["--ix-legacy-grace"]).ix_legacy_grace);
        // = 写法同样生效（布尔 flag 忽略值面，对齐 --allow-empty-token 先例）。
        assert!(parse_ok(&["--ix-legacy-grace=true"]).ix_legacy_grace);
    }

    // UTC；非法 = 拒启 fail-closed 不猜）。
    #[test]
    fn test_r201_ix_legacy_grace_until_parse() {
        // 缺省 = 无到期界（默认 off 逐位不变）。
        let cfg = parse_ok(&[]);
        assert!(cfg.ix_legacy_grace_until.is_none());
        assert!(!cfg.ix_legacy_grace);
        // 空间写法：显式给出即隐含启用宽限形态。
        let cfg = parse_ok(&["--ix-legacy-grace-until", "1999999999"]);
        assert_eq!(cfg.ix_legacy_grace_until, Some(1999999999));
        assert!(cfg.ix_legacy_grace, "显式 until 隐含启用宽限");
        // = 写法同样生效。
        let cfg = parse_ok(&["--ix-legacy-grace-until=1999999999"]);
        assert_eq!(cfg.ix_legacy_grace_until, Some(1999999999));
        assert!(cfg.ix_legacy_grace);
        // 与手工开关共存 = until 优先（到期界生效于裁决门；手工开关冗余无害）。
        let cfg = parse_ok(&["--ix-legacy-grace", "--ix-legacy-grace-until", "1999999999"]);
        assert_eq!(cfg.ix_legacy_grace_until, Some(1999999999));
        assert!(cfg.ix_legacy_grace);
        // 非法时间戳（负号/非数字）= 参数错误拒启（fail-closed 不猜）。
        for bad in ["-1", "abc", "1.5", ""] {
            let r = parse(&["--ix-legacy-grace-until", bad]);
            assert!(r.is_err(), "--ix-legacy-grace-until {bad:?} 必须拒启");
        }
        assert!(parse(&["--ix-legacy-grace-until"]).is_err(), "缺值 = 拒启");
    }
}

// （变更须重新冻结）。
#[cfg(test)]
mod r137_12_audit_line_tests {
    use super::console_audit_line;
    use kirin_desk_relay::audit::TunnelAuditEvent;

    fn addr() -> std::net::SocketAddr {
        "203.0.113.9:9100".parse().unwrap()
    }

    #[test]
    fn test_r177_dir_refresh_throttled_line_frozen() {
        let line = console_audit_line(&TunnelAuditEvent::DirRefreshThrottled {
            client: "203.0.113.9:9100".parse().unwrap(),
        });
        assert!(!line.contains('\n'), "输出必须单行: {line:?}");
    }
    const FP: &str =
        "a1b2:c3d4:e5f6:0718:293a:4b5c:6d7e:8f90:a1b2:c3d4:e5f6:0718:293a:4b5c:6d7e:8f90";

    #[test]
    fn test_r140_1_audit_line_formats_frozen() {
        let a = addr();
        let cases: Vec<(TunnelAuditEvent, String)> = vec![
            (
                TunnelAuditEvent::DirUpserted {
                    client: a,
                    device_id: "id-1".into(),
                    target_domain: "b.example.com".into(),
                    domain: "d.example.com".into(),
                    quota_used: 7,
                    quota_limit: 500,
                },
                format!(
                ),
            ),
            (
                TunnelAuditEvent::DirDeleted {
                    client: a,
                    device_id: "id-1".into(),
                    target_domain: "b.example.com".into(),
                },
            ),
            (
                TunnelAuditEvent::DirWriteRejected {
                    client: a,
                    device_id: "id-1".into(),
                    code: "invalid_domain".into(),
                    detail: "bad domain".into(),
                },
                format!(
                ),
            ),
            (
                TunnelAuditEvent::DirQuotaRejected {
                    client: a,
                    device_id: "id-new".into(),
                    used: 500,
                    limit: 500,
                },
            ),
            (
                TunnelAuditEvent::DirStartupConfig {
                    ip_quota: 500,
                    repush_interval: 3600,
                    push_ttl: 86400,
                    liveness_ttl: 86400,
                    per_source_cap: 10000,
                },
            ),
            (
                TunnelAuditEvent::InterconnectRejected {
                    peer: a,
                    fp: FP.into(),
                    reason: "version mismatch (expected RELAY-DIR/3)".into(),
                },
                format!(
                ),
            ),
            // reason 经既有 esc 面，ts 代码派生零注入面）。
            (
                TunnelAuditEvent::InterconnectRejected {
                    peer: a,
                    fp: FP.into(),
                    reason: "legacy_no_token (grace expired at unix 1761900000)".into(),
                },
                format!(
                ),
            ),
            // ── 不变机制沿用原卡号前缀（设计 §2.5 明确）──
            (
                TunnelAuditEvent::DirDbCorruptRebuilt {
                    detail: "/home/relay/.kirin_desk/relay.db (renamed)".into(),
                },
                format!(
                ),
            ),
            (
                TunnelAuditEvent::DirFrameDropped {
                    client: a,
                    frame: 0x8b,
                },
            ),
            // 废帧保留位（0x90~0x94）到达 = 同一丢弃行（设计 §5 点位 18）。
            (
                TunnelAuditEvent::DirFrameDropped {
                    client: a,
                    frame: 0x94,
                },
            ),
            (
                TunnelAuditEvent::PushOk {
                    target_domain: "b.example.com".into(),
                    fp: FP.into(),
                    entries: 3,
                    epoch: 9,
                },
                format!(
                ),
            ),
            (
                TunnelAuditEvent::PushFailed {
                    target_domain: "b.example.com".into(),
                    fp: FP.into(),
                    reason: "connect failed (all addrs tried)".into(),
                },
                format!(
                ),
            ),
            (
                TunnelAuditEvent::PushRejected {
                    peer_domain: "a.example.com".into(),
                    fp: FP.into(),
                    reason: "A id_pub != live DNS TXT pubkey (TOFU mismatch) — refuse".into(),
                },
                format!(
                ),
            ),
            (
                TunnelAuditEvent::PushApplied {
                    source_fp: FP.into(),
                    entries: 3,
                    removed: 1,
                    epoch: 9,
                },
                format!(
                ),
            ),
            (
                TunnelAuditEvent::PushOutboxEnqueued {
                    target_domain: "b.example.com".into(),
                },
            ),
            (
                TunnelAuditEvent::PushOutboxPruned {
                    target_domain: "b.example.com".into(),
                    n: 2,
                    reason: "superseded".into(),
                },
            ),
            (
                TunnelAuditEvent::PushSourceExpired {
                    fp: FP.into(),
                    rows: 7,
                },
            ),
            (
                TunnelAuditEvent::DirRowExpired {
                    device_id: "id-9".into(),
                    target_domain: "b.example.com".into(),
                },
            ),
            (
                TunnelAuditEvent::PushSkippedNoToken {
                    target_domain: "b.example.com".into(),
                    reason: "no ix_token for target (device cache empty) — push skipped (fail-closed)".into(),
                },
            ),
        ];
        for (ev, want) in cases {
            let line = console_audit_line(&ev);
            assert_eq!(line, want, "审计行格式冻结面被破坏");
            assert!(!line.contains('\n'), "输出必须单行: {line:?}");
        }
    }

    #[test]
    fn test_r140_1_audit_line_control_chars_escaped() {
        let a = addr();
        // 攻击者可控 id/target/domain 含换行/控制字符 → 字面量转义 + 单行。
        let line = console_audit_line(&TunnelAuditEvent::DirUpserted {
            client: a,
            device_id: "evil\nid".into(),
            target_domain: "t\r\n.example.com".into(),
            domain: "d\r\n.example.com".into(),
            quota_used: 1,
            quota_limit: 500,
        });
        assert!(line.contains("id=evil\\nid"), "{line:?}");
        assert!(line.contains("target=t\\r\\n.example.com"), "{line:?}");
        assert!(line.contains("domain=d\\r\\n.example.com"), "{line:?}");
        assert!(
            !line.contains('\n') && !line.contains('\r'),
            "不得残留控制字符: {line:?}"
        );
        // 配额拒绝行（新设备 id 攻击者可控）同转义口径。
        let line = console_audit_line(&TunnelAuditEvent::DirQuotaRejected {
            client: a,
            device_id: "i\rd".into(),
            used: 500,
            limit: 500,
        });
        assert!(line.contains("id=i\\rd"), "{line:?}");
        assert!(!line.contains('\n'), "{line:?}");
        let line = console_audit_line(&TunnelAuditEvent::PushFailed {
            target_domain: "b.example.com".into(),
            fp: FP.into(),
            reason: "peer says\nfake line".into(),
        });
        assert!(line.contains("reason=peer says\\nfake line"), "{line:?}");
        assert!(!line.contains('\n'), "{line:?}");
        // liveness 行（device_id 攻击者可控）同转义口径。
        let line = console_audit_line(&TunnelAuditEvent::DirRowExpired {
            device_id: "i\rd".into(),
            target_domain: "b.example.com".into(),
        });
        assert!(line.contains("id=i\\rd"), "{line:?}");
        assert!(!line.contains('\n'), "{line:?}");
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShutdownSignal {
    Sigint,
    /// 仅 Unix 构建可达（SIGTERM 处理走 `tokio::signal::unix`）；
    /// Windows 构建恒不构造，`allow(dead_code)` 避免平台告警噪音。
    #[cfg_attr(not(unix), allow(dead_code))]
    Sigterm,
}

/// 等待关闭信号：Ctrl+C（全平台）+ SIGTERM（Unix，docker stop/systemd 用）。
/// tokio 内置 `signal` feature（workspace tokio `full` 已含），无需新依赖。
async fn wait_shutdown_signal() -> ShutdownSignal {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to install SIGTERM handler: {e}");
                let _ = tokio::signal::ctrl_c().await;
                return ShutdownSignal::Sigint;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => ShutdownSignal::Sigint,
            _ = term.recv() => ShutdownSignal::Sigterm,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        ShutdownSignal::Sigint
    }
}

// 不进服务主循环；与长驻主进程并发写 = SQLite WAL 单写者 + busy_timeout
// 5s 承接，README 提示高峰可先停服）。CLI 现场生成打印，凭据零硬编码。 ──

/// 互联 token 随机字节数（≥32B = base64url 无填充 43 字符）。
const IX_TOKEN_RANDOM_BYTES: usize = 32;

/// 生成互联 token：≥32B CSPRNG → base64url 无填充（43 字符 URL 安全）。
fn generate_ix_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut buf = [0u8; IX_TOKEN_RANDOM_BYTES];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// 子命令通用选项（`--relay-db` / `--server-key` / `--label` + 位置参数）。
#[derive(Debug, Default)]
struct SubArgs {
    relay_db: Option<std::path::PathBuf>,
    server_key: Option<std::path::PathBuf>,
    label: Option<String>,
    positional: Vec<String>,
    help: bool,
}

fn parse_sub_args(rest: &[String]) -> Result<SubArgs, String> {
    let mut out = SubArgs::default();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        let mut take_value = |name: &str| -> Result<String, String> {
            inline
                .clone()
                .or_else(|| iter.next().cloned())
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match key {
            "--relay-db" => out.relay_db = Some(take_value("--relay-db")?.into()),
            "--server-key" => out.server_key = Some(take_value("--server-key")?.into()),
            "--label" => out.label = Some(take_value("--label")?),
            "--help" | "-h" => out.help = true,
            other if other.starts_with("--") => {
                return Err(format!("unknown option '{other}' (subcommand face accepts --relay-db/--server-key/--label/--help)"))
            }
            other => out.positional.push(other.to_string()),
        }
    }
    Ok(out)
}

/// 子命令默认库路径（与 Config 默认同源：`~/.kirin_desk/relay.db`）。
fn default_relay_db_path() -> std::path::PathBuf {
    kirin_desk_relay::registry::default_key_path()
        .parent()
        .map(|p| p.join("relay.db"))
        .unwrap_or_else(|| std::path::PathBuf::from("relay.db"))
}

/// 子命令面同步小事务执行器（DirStore 异步面在独立 current-thread
/// 运行时上跑；进程即退，零常驻）。
fn sub_block_on<F, T>(f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("subcommand runtime")
        .block_on(f)
}

fn open_sub_store(db: &std::path::Path) -> Result<dir_store::DirStore, String> {
    dir_store::DirStore::open_ex(db)
        .map(|o| o.store)
        .map_err(|e| format!("relay db open failed at {}: {e}", db.display()))
}

/// `tokens` 子命令分发。返回进程退出码（0 = 成功，1 = 操作失败，2 = 用法错误）。
fn run_tokens_command(rest: &[String]) -> i32 {
    let (verb, tail) = match rest.split_first() {
        Some((v, t)) => (v.as_str(), t),
        None => {
            eprintln!("error: missing tokens subcommand (list|add|revoke)");
            print_usage();
            return 2;
        }
    };
    let args = match parse_sub_args(tail) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            print_usage();
            return 2;
        }
    };
    if args.help {
        print_usage();
        return 0;
    }
    let db = args.relay_db.clone().unwrap_or_else(default_relay_db_path);
    match verb {
        "list" => run_tokens_list(&db),
        "add" => run_tokens_add(&db, args.label.as_deref()),
        "revoke" => run_tokens_revoke(&db, args.positional.first().map(String::as_str)),
        other => {
            eprintln!("error: unknown tokens subcommand '{other}' (want list|add|revoke)");
            print_usage();
            2
        }
    }
}

/// `tokens list`：id | label | token(前 8 位…) | source | target_domain |
/// created_at | 状态。**脱敏展示**（全量 token 仅 `tokens add` 时打印一次）。
fn run_tokens_list(db: &std::path::Path) -> i32 {
    let store = match open_sub_store(db) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let rows = match sub_block_on(store.ix_list_tokens()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: list failed: {e}");
            return 1;
        }
    };
    println!("ID | LABEL | TOKEN | SOURCE | TARGET_DOMAIN | CREATED_AT | STATE");
    if rows.is_empty() {
        println!("(no interconnect tokens — create one: relay-server tokens add --label <name>)");
    }
    for r in rows {
        let state = match r.revoked_at {
            Some(ts) => format!("revoked({ts})"),
            None => "active".to_string(),
        };
        println!(
            "{} | {} | {}… | {} | {} | {} | {}",
            r.id,
            r.label,
            r.token_prefix,
            r.source,
            r.target_domain.as_deref().unwrap_or("-"),
            r.created_at,
            state
        );
    }
    0
}

/// `tokens add --label <必填>`：生成 + 登记 + **全量 token 仅此一次打印**。
fn run_tokens_add(db: &std::path::Path, label: Option<&str>) -> i32 {
    let label = match label {
        Some(l) if !l.trim().is_empty() => l.trim().to_string(),
        Some(_) => {
            eprintln!("error: --label must not be empty (refusing, fail-closed)");
            return 2;
        }
        None => {
            eprintln!("error: missing --label <NAME> (required)");
            print_usage();
            return 2;
        }
    };
    let store = match open_sub_store(db) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let token = generate_ix_token();
    let now = dir_store::now_unix_secs();
    let row = match sub_block_on(store.ix_add_cli_token(&token, &label, now)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: token create failed: {e}");
            return 1;
        }
    };
    println!("[OK] interconnect token created (id={}, source=cli)", row.id);
    println!("  label      : {}", row.label);
    println!("  created_at : {}", row.created_at);
    println!("  FULL TOKEN (shown ONLY this once — copy it now):");
    println!("    {token}");
    println!("  next `tokens list` shows the 8-char prefix only; revoke anytime via `tokens revoke {}`", row.id);
    println!("  share it with the peer relay admin, or fill it into the client form");
    println!("  (\"允许中继服务器发现\" 高级区) of devices homed on the peer relay. See README.");
    0
}

/// `tokens revoke <id>`：软撤销（行保留）；id 不存在 / 已撤销 = 报错退出非 0。
fn run_tokens_revoke(db: &std::path::Path, id_arg: Option<&str>) -> i32 {
    let id: i64 = match id_arg.map(str::parse) {
        Some(Ok(v)) => v,
        _ => {
            eprintln!("error: missing or invalid token id (usage: relay-server tokens revoke <id>)");
            return 2;
        }
    };
    let store = match open_sub_store(db) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let existing = match sub_block_on(store.ix_get_token(id)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: lookup failed: {e}");
            return 1;
        }
    };
    let row = match existing {
        Some(r) => r,
        None => {
            eprintln!("error: no such token id={id} (see `tokens list`)");
            return 1;
        }
    };
    if row.revoked_at.is_some() {
        eprintln!("error: token id={id} already revoked at {}", row.revoked_at.unwrap());
        return 1;
    }
    let now = dir_store::now_unix_secs();
    match sub_block_on(store.ix_revoke_token(id, now)) {
        Ok(true) => {
            println!("[OK] token id={id} (label='{}', prefix {}…) revoked (soft; row retained)", row.label, row.token_prefix);
            println!("  takes effect immediately: the next push carrying this token is rejected.");
            0
        }
        _ => {
            eprintln!("error: revoke failed for id={id}");
            1
        }
    }
}

/// `pubkey` 子命令分发（现仅 `rotate`）。
fn run_pubkey_command(rest: &[String]) -> i32 {
    let (verb, tail) = match rest.split_first() {
        Some((v, t)) => (v.as_str(), t),
        None => {
            eprintln!("error: missing pubkey subcommand (rotate)");
            print_usage();
            return 2;
        }
    };
    let args = match parse_sub_args(tail) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            print_usage();
            return 2;
        }
    };
    if args.help {
        print_usage();
        return 0;
    }
    match verb {
        "rotate" => run_pubkey_rotate(args.server_key.as_deref()),
        other => {
            eprintln!("error: unknown pubkey subcommand '{other}' (want rotate)");
            print_usage();
            2
        }
    }
}

/// `pubkey rotate`：重生成密钥对（旧密钥备份 .pem.bak）+ 新公钥/指纹打印
fn run_pubkey_rotate(key_path: Option<&std::path::Path>) -> i32 {
    let path = key_path
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(kirin_desk_relay::registry::default_key_path);
    // 备份与否在 rotate 前判定（首启无旧密钥 = 全新生成，如实输出不谎报）。
    let had_old = path.exists();
    let new_key = match Registry::rotate_server_key_at(&path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: server key rotate failed at {}: {e}", path.display());
            return 1;
        }
    };
    let pub_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(new_key.verifying_key().to_bytes())
    };
    let fp = interconnect::fp_of_pubkey(&new_key.verifying_key().to_bytes());
    if had_old {
        println!("[OK] server key rotated (old key backed up to {}.bak)", path.display());
    } else {
        println!("[OK] server key generated (no existing key at {} — fresh key created)", path.display());
    }
    println!("  new server pubkey (base64): {pub_b64}");
    println!("  new fingerprint ({0} chars)      : {fp}", fp.len());
    println!("  BEFORE restarting, do 1-3 (item 4 comes after the new link is verified):");
    println!("    1) Update this relay's DNS TXT public-key record NOW — peers TOFU-verify against live DNS (stale record = refuse to connect).");
    println!("    2) Update every client that preset this relay's pubkey (form pubkey / sync-source TOFU value).");
    println!("    3) Restart the relay-server process — the new key takes effect on restart.");
    println!("{}", rotate_bak_reminder(&path));
    0
}

/// 进程入口：tokens/pubkey 子命令先于 tokio 运行时分发（短事务同步直跑
/// 即退；`block_on` 禁止自 runtime 内调用，故不得置于 async main 内）。
fn main() {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    match raw_args.first().map(String::as_str) {
        Some("tokens") => std::process::exit(run_tokens_command(&raw_args[1..])),
        Some("pubkey") => std::process::exit(run_pubkey_command(&raw_args[1..])),
        _ => {}
    }
    tokio_main(raw_args);
}

#[tokio::main]
async fn tokio_main(args: Vec<String>) {
    let mut cfg = match Config::parse(args.into_iter()) {
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

    // 拒启；与 `--token`/`KIRIN_RELAY_TOKEN` 同给 = **file 优先 + WARN**
    // ——history/ps 暴露面更小的来源胜出）。文件内容零打印零日志（红线）。
    if let Some(tf) = cfg.token_file.clone() {
        match read_token_file(&tf) {
            Ok(t) => {
                let (final_token, conflict) = pick_token_source(Some(&t), &cfg.token);
                if conflict {
                    tracing::warn!(
                        "both --token-file and --token/KIRIN_RELAY_TOKEN given — using --token-file (file wins)"
                    );
                }
                cfg.token = final_token;
            }
            Err(e) => {
                eprintln!("error: {e}");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    // 安全审计 R-3：空 token 默认 fail-closed 拒绝启动（对齐 CLI
    // cmd_tunnel_serve 的 TNL-SEC-008；零凭据控制面 = 任意公网客户端可登录）。
    // `--allow-empty-token` 显式放行（仍告警，见下）。
    if cfg.token.is_empty() && !cfg.allow_empty_token {
        eprintln!(
            "error: empty token — refusing to start (zero-credential control plane). \
             Use --token <TOKEN> or environment KIRIN_RELAY_TOKEN, \
             or pass --allow-empty-token to explicitly allow it."
        );
        print_usage();
        std::process::exit(2);
    }

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

    // 服务器密钥先加载（TunnelServer::bind 内部重载同一稳定文件——零改 relay）；
    // 目录后端/互联共用同一密钥实例（自签/互认/验签零分歧）。
    let server_key = match Registry::load_or_create_server_key_at(&key_path) {
        Ok(k) => Arc::new(k),
        Err(e) => {
            eprintln!("error: server key load/create failed at {}: {e}", key_path.display());
            std::process::exit(1);
        }
    };
    // 目录 sqlite 小库（§3c fail-closed 全集）：损坏 = 改名保留取证 + 重建空库
    // + WARN + 审计（不静默丢数据）；改名失败/不支持版本 = 拒绝启动。
    let db_opened = match dir_store::DirStore::open_ex(&cfg.relay_db) {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "error: relay db open failed at {}: {e} (refusing to start)",
                cfg.relay_db.display()
            );
            std::process::exit(1);
        }
    };
    if db_opened.rebuilt {
        let detail = format!(
            "{} (corrupt file renamed to <name>.corrupt-<ts>, forensic preserved; empty db rebuilt)",
            cfg.relay_db.display()
        );
        tracing::warn!("relay db corrupt — controlled rebuild: {detail}");
        println!(
            "[audit] {}",
            console_audit_line(&TunnelAuditEvent::DirDbCorruptRebuilt { detail })
        );
    }
    // ——归属签名身份：relay.db 丢失/重装/损坏重建后 DB 内 `meta` 表 epoch
    // 双中继联测问题①，实测 5 轮变更才自然追平）。sidecar 不随库消失，
    // 启动期 `epoch_highwater_sync` 单向 max 合并 = 换库自愈；读写失败均
    // best-effort 不拒启（水位缺失 = 退回自然追平现状语义）。
    let epoch_hw_path = {
        let mut os = key_path.as_os_str().to_os_string();
        os.push(".epoch_hw");
        std::path::PathBuf::from(os)
    };
    let store = Arc::new(db_opened.store.with_epoch_sidecar(epoch_hw_path.clone()));
    match store.epoch_highwater_sync().await {
        Ok((eff, true)) => {
            tracing::warn!(
                sidecar = %epoch_hw_path.display(),
                floor = eff,
            );
            println!(
                epoch_hw_path.display()
            );
        }
        Ok((_, false)) => {}
        Err(e) => {
        }
    }
    // 加密 DNS 解析器（DoH/DoT 默认端点 = utils DnsSecurityConfig；零明文回退）。
    let dns_def = kirin_desk_utils::config::DnsSecurityConfig::default();
    let resolver: Arc<dyn Resolver> = Arc::new(SecureResolver::new_from_parts(
        cfg.dns_endpoints(&cfg.dns_doh, &dns_def.doh),
        cfg.dns_endpoints(&cfg.dns_dot, &dns_def.dot),
        dns_def.resolve_timeout_ms,
        dns_def.cache_ttl_secs,
    ));
    // 变化）+ liveness 探针（注册表活体口径）。互认未启用 = 纯 ConsoleAudit。
    let (tunnel_audit, liveness_probe): (
        Arc<dyn AuditSink>,
        Option<Arc<dyn interconnect::DirLivenessProbe>>,
    ) = if cfg.interconnect_enabled {
        let bridge = Arc::new(DirLivenessBridge::new(
            Arc::new(ConsoleAudit),
            Arc::clone(&store),
        ));
        let probe: Arc<dyn interconnect::DirLivenessProbe> = bridge.clone();
        let audit: Arc<dyn AuditSink> = bridge;
        (audit, Some(probe))
    } else {
        (Arc::new(ConsoleAudit), None)
    };
    // 失败退避/双清扫〕；引擎五参 = CLI 冻结默认值面 §2.6；resolver 注入）。
    let ic: Option<Arc<interconnect::InterconnectService>> = if cfg.interconnect_enabled {
        let engine = interconnect::EngineConfig {
            repush_interval: cfg.push_repush_interval,
            entry_ttl: cfg.push_entry_ttl,
            liveness_ttl: cfg.dir_liveness_ttl,
            per_source_cap: cfg.push_per_source_cap,
            liveness: liveness_probe,
            legacy_grace: cfg.ix_legacy_grace,
            legacy_grace_until: cfg.ix_legacy_grace_until,
        };
        Some(Arc::new(interconnect::InterconnectService::new(
            Arc::clone(&store),
            Arc::clone(&server_key),
            Arc::new(ConsoleAudit),
            Arc::clone(&resolver),
            engine,
        )))
    } else {
        None
    };
    // 互联服务 + 自域口径挂接）。
    let backend: Arc<dyn kirin_desk_relay::server::DirectoryHandler> = {
        let mut b = dir_backend::DirBackend::new(
            Arc::clone(&store),
            Arc::clone(&server_key),
            Arc::new(ConsoleAudit),
        );
        if let Some(svc) = &ic {
            b = b
                .with_push_trigger(Arc::clone(svc))
                .with_own_domain(svc.my_domain().to_string());
        }
        Arc::new(b)
    };
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
        // = liveness 素材；互认未启用 = 纯 ConsoleAudit）。
        audit: Some(tunnel_audit),
        server_key_path: Some(key_path.clone()),
        rendezvous: rendezvous.clone(),
        directory: Some(backend),
        // `--max-sessions`/`--preauth-per-ip` 可配，0 拒启已在解析期执法）。
        max_sessions: cfg.max_sessions,
        preauth_per_ip: cfg.preauth_per_ip,
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
    println!(
        "  Interconnect:  {}",
        match &ic {
            Some(svc) => {
                // 无界 on）；纯手工 on（无到期界）= WARN 提示换用显式到期
                // （bypass 无自动关闭机制，迁移期短暂排障用）。
                let grace = match cfg.ix_legacy_grace_until {
                    Some(ts) => format!("on until {ts}"),
                    None if cfg.ix_legacy_grace => "on".to_string(),
                    None => "off".to_string(),
                };
                if cfg.ix_legacy_grace && cfg.ix_legacy_grace_until.is_none() {
                    tracing::warn!(
                        "--ix-legacy-grace (manual, no expiry) — bypass has NO auto-off; \
                         prefer --ix-legacy-grace-until <unix_ts> for bounded grace"
                    );
                }
                format!(
                    "enabled on port {} (fp {}, legacy_grace={grace})",
                    cfg.interconnect_port,
                    svc.my_fp()
                )
            }
            None => "disabled (--no-interconnect)".to_string(),
        }
    );
    println!("  Relay db:      {}", cfg.relay_db.display());
    if cfg.dir_ip_quota == 0 {
        tracing::warn!(
            "--dir-ip-quota 0 — per-IP registration quota DISABLED (unlimited); \
             audit rows carry quota=<used>/0"
        );
    }
    println!(
        "[audit] {}",
        console_audit_line(&TunnelAuditEvent::DirStartupConfig {
            ip_quota: cfg.dir_ip_quota,
            repush_interval: cfg.push_repush_interval,
            push_ttl: cfg.push_entry_ttl,
            liveness_ttl: cfg.dir_liveness_ttl,
            per_source_cap: cfg.push_per_source_cap,
        })
    );
    println!("  Press Ctrl+C to stop.");

    let handle = server.shutdown_handle();
    let srv_task = tokio::spawn(server.run());

    // tick〔每 10 tick = 300s 慢扫〕；各自独立 stop watch）。
    let (mut ic_serve_task, ic_cycle_stop, mut ic_cycle_task, mut ic_sweep_task) = match &ic {
        Some(svc) => {
            let listeners = match interconnect::InterconnectService::bind_listeners(cfg.interconnect_port).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("error: interconnect bind failed: {e}");
                    std::process::exit(1);
                }
            };
            let serve_task = {
                let svc = Arc::clone(svc);
                tokio::spawn(async move {
                    let _ = svc.serve_listeners(listeners).await;
                })
            };
            let (push_stop_tx, push_stop_rx) = tokio::sync::watch::channel(false);
            let push_task = {
                let svc = Arc::clone(svc);
                tokio::spawn(async move {
                    svc.run_push_cycle(push_stop_rx).await;
                })
            };
            let (sweep_stop_tx, sweep_stop_rx) = tokio::sync::watch::channel(false);
            let sweep_task = {
                let svc = Arc::clone(svc);
                tokio::spawn(async move {
                    svc.run_sweep(sweep_stop_rx).await;
                })
            };
            (
                Some(serve_task),
                Some((push_stop_tx, sweep_stop_tx)),
                Some(push_task),
                Some(sweep_task),
            )
        }
        None => (None, None, None, None),
    };

    let rendezvous_task = match &rendezvous {
        Some(rz) => {
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let rz = Arc::clone(rz);
            Some((stop_tx, tokio::spawn(rz.serve(stop_rx))))
        }
        None => None,
    };

    let sig = wait_shutdown_signal().await;
    match sig {
        ShutdownSignal::Sigint => {
        }
        ShutdownSignal::Sigterm => {
        }
    }
    handle.shutdown();
    // server.rs），`run()` 应立即返回；此处仍加 3s 有界等待兜底——若未来
    // 回归出现不可唤醒的阻塞，进程也能按时退出，不再触发 dockerd 10s 强杀。
    match tokio::time::timeout(Duration::from_secs(3), srv_task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => tracing::warn!("tunnel server task error: {e}"),
        Ok(Err(e)) => tracing::warn!("tunnel server join error: {e}"),
        Err(_) => tracing::warn!("tunnel server did not stop in 3s (accept loop unresponsive)"),
    }
    if let Some((stop_tx, task)) = rendezvous_task {
        let _ = stop_tx.send(true);
        match tokio::time::timeout(Duration::from_secs(3), task).await {
            Ok(Ok(_)) => tracing::info!("rendezvous server stopped"),
            Ok(Err(e)) => tracing::warn!("rendezvous serve task error: {e}"),
            Err(_) => tracing::warn!("rendezvous serve task did not stop in 3s"),
        }
    }
    // 在途推送会话单次无状态，中断无残留；outbox 落盘 = 重启续推）。
    if let Some((push_tx, sweep_tx)) = &ic_cycle_stop {
        let _ = push_tx.send(true);
        let _ = sweep_tx.send(true);
    }
    if let Some(task) = ic_cycle_task.take() {
        match tokio::time::timeout(Duration::from_secs(3), task).await {
            Ok(Ok(_)) => tracing::info!("interconnect push cycle stopped"),
            Ok(Err(e)) => tracing::warn!("interconnect push cycle task error: {e}"),
            Err(_) => tracing::warn!("interconnect push cycle task did not stop in 3s"),
        }
    }
    if let Some(task) = ic_sweep_task.take() {
        match tokio::time::timeout(Duration::from_secs(3), task).await {
            Ok(Ok(_)) => tracing::info!("interconnect sweep stopped"),
            Ok(Err(e)) => tracing::warn!("interconnect sweep task error: {e}"),
            Err(_) => tracing::warn!("interconnect sweep task did not stop in 3s"),
        }
    }
    if let Some(task) = ic_serve_task.take() {
        task.abort();
        tracing::info!("interconnect listener stopped");
    }
    tracing::info!("relay-server stopped");
}
