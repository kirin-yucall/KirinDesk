use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::secure;

/// 白名单条目 — 域名模式 + 可选过期时间。
///
/// 模式支持 `*.example.com` 通配前缀（匹配 `example.com` 及其任意子域）；
/// `expiry` 为 `Some` 时到期自动失效（SRV-SEC-WL-003）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WhitelistEntry {
    /// 域名模式：精确域名或 `*.example.com` 通配。
    pub pattern: String,
    /// 过期时间（UTC）；`None` 表示永久有效。
    pub expiry: Option<DateTime<Utc>>,
}

impl WhitelistEntry {
    pub fn new(pattern: &str, expiry: Option<DateTime<Utc>>) -> Self {
        Self {
            pattern: pattern.trim().to_string(),
            expiry,
        }
    }

    /// 条目是否仍有效（未过期）。
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self.expiry {
            Some(exp) => now < exp,
            None => true,
        }
    }
}

/// (SRV-IDWL-002): ID 白名单条目 — 设备 ID + 可选过期时间。
///
/// `device_id` 为握手 `HandshakeInit.client_id`（与 known_clients 同 key，
/// 大小写敏感精确匹配）；`expiry` 为 `Some` 时到期自动失效（对称
/// [`WhitelistEntry`] 的 SRV-SEC-WL-003 语义）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdWhitelistEntry {
    /// 设备 ID：握手自报 client_id，精确匹配（大小写敏感，与 known_clients 一致）。
    pub device_id: String,
    /// 过期时间（UTC）；`None` 表示永久有效。
    pub expiry: Option<DateTime<Utc>>,
}

impl IdWhitelistEntry {
    pub fn new(device_id: &str, expiry: Option<DateTime<Utc>>) -> Self {
        Self {
            device_id: device_id.trim().to_string(),
            expiry,
        }
    }

    /// 条目是否仍有效（未过期）。
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self.expiry {
            Some(exp) => now < exp,
            None => true,
        }
    }
}

/// 判断域名是否匹配白名单模式（SRV-SEC-WL-004）。
///
/// - 精确模式：`example.com` 只匹配自身；
/// - 通配模式：`*.example.com` 匹配 `example.com` 及任意子域（`a.example.com` 等）。
pub fn whitelist_matches(domain: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    if let Some(rest) = pattern.strip_prefix("*.") {
        domain == rest || domain.ends_with(&format!(".{}", rest))
    } else {
        domain == pattern
    }
}

/// KirinDesk application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Device identity
    pub device: DeviceConfig,

    /// GoDaddy DNS API settings
    pub godaddy: GoDaddyConfig,

    /// DNS 域名维护服务商选择（`[dns]` 段，默认 "godaddy"）。
    #[serde(default)]
    pub dns: DnsConfig,

    /// DDNS 域名自动更新维护（`[ddns]` 段，域名页「DDNS 维护」卡读写）。
    #[serde(default)]
    pub ddns: DdnsConfig,

    /// Network settings
    pub network: NetworkConfig,

    /// Media settings
    pub media: MediaConfig,

    /// Logging settings
    pub logging: LoggingConfig,

    /// UI 外观设置（主题模式持久化）
    #[serde(default)]
    pub ui: UiConfig,

    /// 无人值守模式设置（`[unattended]` 段）
    #[serde(default)]
    pub unattended: UnattendedConfig,

    /// 文件传输设置（`[file_transfer]` 段）
    #[serde(default)]
    pub file_transfer: FileTransferConfig,

    /// P5-4: 传输设置（`[transport]` 段：QUIC 优先 → TCP 优雅降级）
    #[serde(default)]
    pub transport: TransportConfig,

    /// 内网穿透设置（`[tunnel]` 段：FRP 式通用 TCP 反向代理）
    #[serde(default)]
    pub tunnel: TunnelConfig,

    #[serde(default)]
    pub update: UpdateConfig,

    /// 每条目 = relay 三件套 + 展示字段；`token` 入加密域（与 `[tunnel]
    /// token` 同口径）。旧配置无本段 → 空列表（serde 缺省）。
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,

    #[serde(default)]
    pub debug: DebugConfig,

    /// 旧配置无本段 → 缺省（`alt_f4_forward = true`，serde 缺省兼容）。
    #[serde(default)]
    pub input: InputConfig,

    ///
    /// **不入库面**：`#[serde(skip)]` → 不进入 TOML/JSON 序列化，配置指纹
    /// （整份序列化哈希）与落盘形态零影响；`Default` 恒 `None`。**生产代码
    /// 永不置位** → `save()` 行为逐位不变（CLI `whitelist add-id` 等即调即存
    /// 语义保留，由回归单测钉死）。单测/自测 harness 用它把隐式 `save()`
    /// （`whitelist_add`/`id_whitelist_add` 等）引到隔离目录临时路径，杜绝测试
    #[serde(skip)]
    save_override: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// 更新通道：`release`（正式版，默认）/ `beta`（预发布）。
    #[serde(default = "default_update_channel")]
    pub channel: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            channel: default_update_channel(),
        }
    }
}

fn default_update_channel() -> String {
    "release".to_string()
}

///
/// 旧配置无本段 → 全部缺省（`#[serde(default)]` 反序列化兼容）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugConfig {
    /// p50/p95 打点 + 5s 周期汇总）；`Some(false)` = config 显式关；
    /// `None`（配置文件缺 `[debug]` 段/缺本键——含结构体级缺省，`Config`
    /// 的 `debug` 字段 `#[serde(default)]` 与本字段级 `#[serde(default)]`
    /// 同归 `None`）= **无显式值 → 落内置默认**（值在门控层
    /// `ui::latency_trace::DEFAULT_GATE_ON`，单一点）。**门控解析顺序**：env
    /// `KIRIN_LATENCY_TRACE` 优先（显式值一律胜出，含显式关闭 `"0"`），未设
    /// env 且本项有显式值 → 本项定夺；env 未设且本项 `None` → 内置默认。
    /// 包里默认，后续 bug 修复了再清理」：用户两轮复测想开打点均未随进程
    /// 迟滞归因完成、相关 bug 清理后，内置默认回收为关（`DEFAULT_GATE_ON`
    /// 改 false，届时 config 显式值/env 逃生口语义不变）。关闭态逐帧路径
    /// 零分配零开销。开启后双端启动行 `latency_trace gate=on
    /// 开不成，本项为 config 侧正式通道）。
    #[serde(default)]
    pub latency_trace: Option<bool>,

    /// `true` = 显示（现场测延迟/带宽时打开）；`false`（**默认**）= 隐藏。
    ///
    /// 用户 2026-09-08 晚间复测：「fps/bw 之类可以隐藏了」——FPS/BW/Res
    /// 徽标（含无帧时的 `FPS: --  BW: --  Res: --` 占位）属调试数据，改
    /// 默认隐藏、需要时经本开关打开。UI 消费点在会话窗状态栏（显示路径，
    /// 每帧经 `config_cache_load` mtime 比对读取，文件不变零磁盘 IO；保存
    /// 配置后下一帧热更新生效，无需重启）。**范围**：仅状态栏连接统计
    /// 移除〔与右端显示器下拉重复，用户裁定〕，本开关作用面随之仅剩
    /// FPS/BW/Res 三徽标）。
    #[serde(default = "default_debug_conn_stats_visible")]
    pub conn_stats_visible: bool,
}

impl Default for DebugConfig {
    fn default() -> Self {
        // 段的旧配置/新配置加载后与显式 `latency_trace = true` 在启动自检行
        // `source` 上必须可区分（`default` vs `config`）；内置默认（临时开，
        // 用户 2026-09-06 裁定，回收条件见字段文档）在门控层
        // `ui::latency_trace::DEFAULT_GATE_ON` 单一点生效。
        Self {
            latency_trace: None,
            conn_stats_visible: default_debug_conn_stats_visible(),
        }
    }
}

fn default_debug_conn_stats_visible() -> bool {
    // 用户 2026-09-08 复测裁定：调试数据默认不常驻（隐藏）；旧配置无本键
    // → serde 缺省 false，行为 = 新默认，无需迁移。
    false
}

///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputConfig {
    /// 远控会话窗聚焦时 Alt+F4 **转发远端 + 本地抑制**（本地会话窗不关闭，
    /// 关闭 = 断开，远端不受影响）。
    ///
    /// （安装失败 / 非 Windows 惰性桩 / 无会话窗）时行为恒 = 现状按钮补偿，
    /// 本开关不起作用（fail-closed，设计 §1.3 红线②）。
    #[serde(default = "default_input_alt_f4_forward")]
    pub alt_f4_forward: bool,
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            alt_f4_forward: default_input_alt_f4_forward(),
        }
    }
}

fn default_input_alt_f4_forward() -> bool {
    true
}

/// P5-4: 传输配置（`[transport]` 段，主文档 §3.6）。
///
/// CLI 参数（`--transport` / `--ip-family`）覆盖本配置；无参保持 auto 现状
/// （IPv6 优先 + QUIC 主路径）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// 传输模式: "auto"（QUIC 优先，失败回退 TCP）| "quic" | "tcp"
    #[serde(default = "default_transport_mode")]
    pub mode: String,

    /// 地址族策略: "auto"（IPv6 优先，无 v6 用 v4）| "ipv4" | "ipv6"
    #[serde(default = "default_ip_family")]
    pub ip_family: String,

    /// QUIC 建连/握手超时（毫秒，默认 3000）
    #[serde(default = "default_quic_connect_timeout_ms")]
    pub quic_connect_timeout_ms: u64,

    /// 会话中途降级开关（true = QUIC 失效自动 TCP 重建续传；false = 直接断连）
    #[serde(default = "default_graceful_degrade")]
    pub graceful_degrade: bool,

    /// TCP 模式反馈上报周期（毫秒，默认 500）
    #[serde(default = "default_tcp_feedback_interval_ms")]
    pub tcp_mode_feedback_interval_ms: u64,
}

fn default_transport_mode() -> String {
    "auto".to_string()
}

fn default_ip_family() -> String {
    "auto".to_string()
}

fn default_quic_connect_timeout_ms() -> u64 {
    3000
}

fn default_graceful_degrade() -> bool {
    true
}

fn default_tcp_feedback_interval_ms() -> u64 {
    500
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mode: default_transport_mode(),
            ip_family: default_ip_family(),
            quic_connect_timeout_ms: default_quic_connect_timeout_ms(),
            graceful_degrade: default_graceful_degrade(),
            tcp_mode_feedback_interval_ms: default_tcp_feedback_interval_ms(),
        }
    }
}

/// 内网穿透配置（`[tunnel]` 段，FRP 式通用 TCP 反向代理）。
///
/// 默认关闭（`enabled = false`）——可选兜底能力，与 P2P 直连并存。
/// 客户端（client）主动出站连接公网 relay 服务器，把内网 TCP 服务
/// （SSH/RDP/HTTP 等）映射到公网端口。服务端参数（bind_port/port_range/
/// heartbeat 等）不占 GUI，在 `config/default.toml` 配置；客户端填写的
/// 核心字段（server_addr / token / proxies）在 Settings 页「Tunnel
/// (内网穿透)」分组编辑（对齐 TNL-CFG-001）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// 内网穿透总开关（默认关闭；开启仅在有公网 relay 服务器时）。
    #[serde(default)]
    pub enabled: bool,

    /// 运行模式: "client"（默认，frpc 等价）| "server"（frps 等价）。
    /// `mode = "server"` 时忽略 client 字段（反之亦然，TNL-CFG-002）。
    #[serde(default = "default_tunnel_mode")]
    pub mode: String,

    /// relay 服务器地址（client 模式）：域名 / IPv4 / IPv6，支持 `:port` 后缀。
    #[serde(default)]
    pub server_addr: String,

    /// 认证 token（client 与服务端比对，常数时间比较；不写日志，TNL-SEC-005）。
    #[serde(default)]
    pub token: String,

    /// 服务端控制端口（server 模式监听，默认 7000，v4/v6 双栈）。
    #[serde(default = "default_tunnel_bind_port")]
    pub bind_port: u16,

    /// 服务端监听地址列表（server 模式，逗号分隔，可多个，IPv4/IPv6 均可）。
    /// 默认 "0.0.0.0,::" —— 显式同时监听 IPv4 与 IPv6（跨平台稳定，
    /// 不依赖单地址双栈行为；原「[::] 优先 + 0.0.0.0 回退」语义保留为空值时兜底，
    /// 见 relay `TunnelServerConfig.bind_addrs` 空列表处理）。
    #[serde(default = "default_tunnel_bind_addrs")]
    pub bind_addrs: String, // 例: "0.0.0.0,::" / "127.0.0.1" / "0.0.0.0,::,192.168.1.10"

    /// GUI 最后运行状态（§3.4.3）：GUI「启动/停止」随最后一次使用
    /// 保持；程序启动读 true → 自动恢复隧道。仅 GUI 消费，CLI 不读；
    /// 与 `enabled`（配置级总开关，CLI 消费）语义独立、互不干扰。
    #[serde(default)]
    pub auto_start: bool,

    /// 服务端自动分配端口区间（`remote_port = 0` 时），格式 `"start-end"`。
    #[serde(default = "default_tunnel_port_range")]
    pub port_range: String,

    /// 心跳间隔秒数（默认 10s，TNL-STAB-001）。
    #[serde(default = "default_tunnel_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// 心跳超时秒数（默认 30s，即连续 3 个心跳周期无响应判死）。
    #[serde(default = "default_tunnel_heartbeat_timeout")]
    pub heartbeat_timeout: u64,

    /// 连接池预建 work 连接数（P1 增强，默认 0 = 关闭，TNL-STAB-004）。
    #[serde(default)]
    pub pool_count: u32,

    /// 服务端每代理连接池上限（P1 增强，默认 5）。
    #[serde(default = "default_tunnel_max_pool_count")]
    pub max_pool_count: u32,

    /// 代理列表（client 模式）：把本地 TCP 服务映射到公网端口。
    #[serde(default)]
    pub proxies: Vec<TunnelProxy>,

    // ════════════════════════════════════════════════════════════
    // 设备 ID 模式字段（ID-001 / ID-SEC-001 / ID-005）
    // ════════════════════════════════════════════════════════════

    /// 注册设备 ID（ID-001：显式配置；`None` → 由本机身份 Ed25519 公钥
    /// 指纹派生）。仅 `enabled && mode="client"` 时生效。
    #[serde(default)]
    pub device_id: Option<String>,

    /// relay 服务器 Ed25519 公钥（base64，ID-SEC-001 验签 `DeviceInfo`）。
    /// ID 模式连接（`connect --id`）必需；缺失 → 拒绝解析并提示配置。
    #[serde(default)]
    pub server_pubkey: Option<String>,

    /// 额外连接候选（ID-005）：`"ip:port"` 列表，附加到设备候选（服务器
    /// 另自动附加观察地址）。
    #[serde(default)]
    pub extra_candidates: Vec<String>,

    /// 本端正作为控制端存在活跃桌面控制会话期间，该对端发起的反向控制
    /// 请求在准入臂直接拒绝（fail-closed，显式拒绝码 + 审计 + toast），
    /// 本端发起入口同步预检拦截；`false` = 行为与基线逐位一致（双臂零
    /// 触发，回退现状）。serde default = true：旧配置文件缺键 = 禁止
    /// （安全缺省，用户口径「按禁止执行」）。
    #[serde(default = "default_forbid_mutual_control")]
    pub forbid_mutual_control: bool,
}

/// fail-closed 安全缺省；布尔缺省 false 的 serde 惯例在此显式反转）。
fn default_forbid_mutual_control() -> bool {
    true
}

/// 一条端口代理（`[tunnel] proxies` 项，对齐 TNL-PROTO-003）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelProxy {
    /// 代理名称（唯一，如 "ssh"；同一 name 重复注册 = 更新）。
    pub name: String,

    /// 本地服务地址（域名 / IPv4 / IPv6）。
    #[serde(default)]
    pub local_addr: String,

    /// 本地服务端口。
    pub local_port: u16,

    /// 公网映射端口（0 = 由服务端从 `port_range` 自动分配）。
    #[serde(default)]
    pub remote_port: u16,
}

fn default_tunnel_mode() -> String {
    "client".to_string()
}

fn default_tunnel_bind_port() -> u16 {
    7000
}

/// server 监听地址默认值 —— 显式 IPv4+IPv6 双监听（跨平台稳定，
/// 不依赖单地址双栈行为）。
fn default_tunnel_bind_addrs() -> String {
    "0.0.0.0,::".to_string()
}

fn default_tunnel_port_range() -> String {
    "60000-61000".to_string()
}

fn default_tunnel_heartbeat_interval() -> u64 {
    10
}

fn default_tunnel_heartbeat_timeout() -> u64 {
    30
}

fn default_tunnel_max_pool_count() -> u32 {
    5
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_tunnel_mode(),
            server_addr: String::new(),
            token: String::new(),
            bind_port: default_tunnel_bind_port(),
            // server 监听地址（默认 IPv4+IPv6 双监听）+ GUI 最后运行状态
            // （默认 false —— 旧用户曾手开 enabled=true 的，缺省不自动拉起）。
            bind_addrs: default_tunnel_bind_addrs(),
            auto_start: false,
            port_range: default_tunnel_port_range(),
            heartbeat_interval: default_tunnel_heartbeat_interval(),
            heartbeat_timeout: default_tunnel_heartbeat_timeout(),
            pool_count: 0,
            max_pool_count: default_tunnel_max_pool_count(),
            proxies: Vec::new(),
            // 设备 ID 模式配置（默认关闭，None/空）。
            device_id: None,
            server_pubkey: None,
            extra_candidates: Vec::new(),
            forbid_mutual_control: default_forbid_mutual_control(),
        }
    }
}

impl TunnelConfig {
    ///
    /// `#[derive(Default)]` 使 `String` mode 字段默认空串，而 GUI 模式按钮
    /// 选中判定用 `!= "server"`、表单渲染用 `== "client"`，两处口径对空串
    /// 相反（Client 高亮却显示 Server 表单）。本方法统一兜底口径：构造/
    /// 回填/持久化前均经此归一，空串视同 `"client"`（serde default 已是
    /// client，本方法兜底手写空值与内存默认两条路径）。
    pub fn effective_mode(&self) -> &str {
        if self.mode.trim().is_empty() {
            "client"
        } else {
            &self.mode
        }
    }

    /// 解析 Settings 页代理多行文本（每行 `name|local_addr:port|remote_port`，
    /// remote_port 留空 = 服务端分配；空行与 `#` 注释行跳过；非法行跳过）。
    pub fn parse_proxy_lines(text: &str) -> Vec<TunnelProxy> {
        let mut proxies = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split('|');
            let name = parts.next().unwrap_or("").trim().to_string();
            let addr_port = parts.next().unwrap_or("").trim();
            let remote_str = parts.next().map(|s| s.trim()).unwrap_or("");
            if name.is_empty() || addr_port.is_empty() {
                continue;
            }
            let Some((addr, port_str)) = addr_port.rsplit_once(':') else {
                continue;
            };
            let Ok(local_port) = port_str.parse::<u16>() else {
                continue;
            };
            let remote_port = if remote_str.is_empty() {
                0
            } else if let Ok(p) = remote_str.parse::<u16>() {
                p
            } else {
                continue;
            };
            proxies.push(TunnelProxy {
                name,
                local_addr: addr.to_string(),
                local_port,
                remote_port,
            });
        }
        proxies
    }

    /// 格式化代理列表为多行文本（`parse_proxy_lines` 的逆操作；
    /// remote_port = 0 时省略第三段）。
    pub fn format_proxy_lines(proxies: &[TunnelProxy]) -> String {
        let mut lines = String::new();
        for p in proxies {
            let remote = if p.remote_port == 0 {
                String::new()
            } else {
                format!("|{}", p.remote_port)
            };
            lines.push_str(&format!("{}|{}:{}{}\n", p.name, p.local_addr, p.local_port, remote));
        }
        lines
    }
}

/// 解析服务端监听地址列表（GUI 校验 + CLI/共享层使用；纯 std，不引入新依赖）。
/// 逗号拆分、trim、逐个解析为 IpAddr 后拼 port；非 IP 即报错
/// （不支持域名——监听地址必须是本机 IP）。
/// 空字符串/纯空白 → Ok(vec![])（上层回退默认双栈，兼容旧配置语义）。
pub fn parse_bind_addr_list(s: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(format!("监听地址存在空段: '{s}'")); // 例 "0.0.0.0,,::"
        }
        match part.parse::<std::net::IpAddr>() {
            Ok(ip) => out.push(std::net::SocketAddr::new(ip, port)),
            Err(_) => {
                return Err(format!(
                    "无效监听地址 '{part}'（仅支持本机 IP，不支持域名）"
                ))
            }
        }
    }
    Ok(out)
}

/// 生成高熵随机 Token：32 字节 OsRng → 64 位 hex（128 bit 熵之上加倍，
/// 对齐 TNL-SEC-009「≥32 字节高熵随机串」建议；hex 无歧义、便于复制粘贴）。
pub fn generate_random_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

///
/// 数据源决策：`[nodes]` 为**独立命名候选列表**——节点本质是「relay 服务器
/// 三件套（server_addr/token/server_pubkey）」的具名条目；`[tunnel]` 段保持
/// 「当前生效」单槽配置（Tunnel 页表单与 ID 模式连接直读该段，语义不动）。
/// 两处仅经 GUI「从节点选择」回填联动，不改变 `[tunnel]` 手填路径。
///
/// 旧配置无 `[nodes]` 段 → 空列表（`#[serde(default)]` 反序列化兼容）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NodeConfig {
    /// 节点名（列表展示 + 去重键；导入时为空 → [`Config::node_add`] 自动派生
    /// 唯一名，不拒文件）。
    pub name: String,
    /// relay 服务器地址 `host:port`（端口数字 1-65535；空串 = 导出侧未填
    /// 地址，**非合法值**，导入拒绝并提示手填）。
    pub server_addr: String,
    /// ——中继↔中继互联认证凭据，随目录 DirUpsert 上交 home、由目标中继
    /// `[tunnel] token` 是两种凭据、零互写——「应用」节点不覆盖登录
    /// token）。落盘同旧口径：**入配置加密域**。
    pub token: String,
    /// relay 服务器 Ed25519 公钥（base64 STANDARD 32 字节；与 `[tunnel]
    /// server_pubkey` 同口径，导入零转换）。
    pub server_pubkey: String,
    /// 备注（展示字段，可空）。
    pub note: String,
}

impl NodeConfig {
    /// 公钥指纹——与首连指纹确认框**同口径**（[`crate::known_hosts::fingerprint`]：
    /// base64 串 SHA-256 的 hex，每 4 位冒号分组，79 字符）。导入确认框展示
    /// 供用户过目（分享格式不带签名 → TOFU 兜底）。
    pub fn fingerprint(&self) -> String {
        crate::known_hosts::fingerprint(&self.server_pubkey)
    }

    /// 短指纹（列表行展示：完整指纹前 8 hex 位）。
    pub fn fingerprint_short(&self) -> String {
        let fp = self.fingerprint();
        fp.chars().take(8).collect()
    }
}

/// 发现条目）：客户端侧上限常量（与服务端 `relay-server`
/// `dir_store::MAX_DEVICE_DIR_ENTRIES` 同值——双侧执法、值单一口径）。
/// 只拦**新增**（`node_add`）；已存量超 15 的配置不回删、`node_update`/
/// `node_remove` 不受限（删除后腾出名额可再加）。
pub const NODES_MAX_ENTRIES: usize = 15;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeAddError {
    /// 节点名已被占用（name 是唯一去重键；导入同名文件 → 拒，提示改名）。
    #[error("节点名已存在: {0}")]
    NameExists(String),
    /// 三件套（server_addr+token+server_pubkey）与既有节点完全一致——同一
    /// 节点重复导入跳过（同名同凭据无信息量）；同服务器不同 token 属不同
    /// 凭据条目，允许共存。
    #[error("节点已存在（三件套一致）: {0}")]
    TripleExists(String),
    /// 按名操作未命中（`node_update` 目标不存在）。
    #[error("节点不存在: {0}")]
    NotFound(String),
    /// 只拒新增不清存量——存量超上限不回删）。
    #[error("中继服务器发现条目已达上限（{limit}）")]
    LimitExceeded { limit: usize },
}

///
/// 地址字段校验复用（语义不变：host:port，端口 1-65535，`[IPv6]:port`）。
///
/// 接受：`域名/IPv4:port`、`[IPv6]:port`；端口数字 1-65535；host 非空、
/// 不含空白/控制字符（无括号形态 host 内不得再含 `:`）。返回 `Err` 为
/// 技术原因（UI 映射人话）。
pub fn validate_node_server_addr(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty".to_string());
    }
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (inner, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated [ in: {s}"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("missing :port in: {s}"))?;
        (inner, port)
    } else {
        s.rsplit_once(':')
            .ok_or_else(|| format!("missing :port in: {s}"))?
    };
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || (c as u32) < 0x20)
    {
        return Err(format!("invalid host in: {s}"));
    }
    if !s.starts_with('[') && host.contains(':') {
        return Err(format!("unexpected extra ':' in: {s}"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("port not a number: {port:?}"))?;
    if port == 0 {
        return Err(format!("port out of range: {port}"));
    }
    Ok(())
}

/// 文件传输配置（`[file_transfer]` 段）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferConfig {
    /// 接收文件落盘目录（`None` → 默认 `~/Downloads/KirinDesk`）。
    #[serde(default)]
    pub download_dir: Option<String>,

    /// 单文件大小上限（字节；超限在 Offer 阶段拒绝，FT-SEC-002）。
    /// 默认 4 GiB。
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// S-10b (F-11): 单会话累计接收字节配额（默认 4 GiB，与单文件上限一致，
    /// 单文件整传不误伤；`0` = 不限制）。超限后新 Offer 被拒绝；配额状态由
    /// 传输会话层跟踪（core `SessionQuota` 的 reserve/release）。
    #[serde(default = "default_session_max_bytes")]
    pub session_max_bytes: u64,

    /// S-10b (F-11): 单会话接收文件数配额（默认 64；`0` = 不限制）。
    /// 超限后新 Offer 被拒绝。
    #[serde(default = "default_session_max_files")]
    pub session_max_files: u64,

    /// `#[serde(default)]` 保旧配置兼容）。`~` 展开（仅首位）；**含 `%` 条目拒绝**
    /// （环境变量注入面，fail-closed + WARN）；会话建立时一次性 canonicalize +
    /// 大小写不敏感去重排序（core `resolve_fs_browse_roots`）。
    /// **空 = 默认 `[用户主目录]` 单条目**（非"拒绝一切"、非"全盘"——fail-closed
    /// 性质由解析期检查承担，默认值只决定"可见面"，§1.4）。
    #[serde(default)]
    pub fs_roots: Vec<String>,

    /// **空 = 写根门禁用** = 不额外限写根（受会话授权边界 × OS DACL 约束，K1
    /// 修订版：写操作对 GUI 与 headless 均开放，WinSCP/RDP 会话授权语义）；
    /// 配置后写操作（Mkdir/Rename/Delete/上传落盘）仅允许列内根，列外 = 拒绝
    /// （`PathOutsideRoot` / Offer `Reject`「写根限制」，fail-closed，§1.4 执行点）。
    #[serde(default)]
    pub fs_write_roots: Vec<String>,

    /// → 指数退避 30s/60s/120s/300s 封顶、每重连周期 ≤5 次（设计 §4.1 G1；
    #[serde(default = "default_auto_resume")]
    pub auto_resume: bool,

    /// 由 Dashboard「服务器控制」卡「允许文件传输」开关控制（设计 §12.1）：
    /// ON = 对方 `TransferRequest` 通告自动接受；OFF = 自动 `Declined` 回执。
    /// 尾追加 + serde 默认 = 旧配置缺键落开（用户 09-17「默认都开」裁定）。
    /// 门控引擎消费（含首启/损坏 fail-closed 三态）= B2 岗，本字段只持久开关值。
    #[serde(default = "default_consent_switch_on")]
    pub file_transfer_allowed: bool,

    /// 同型同默认）：ON = 对方剪贴板族文件粘贴自动接受 + 本端粘贴拉取可用；
    /// OFF = 自动拒绝 + 本端粘贴拉取禁用（设计 §12.1；门控 = B2 岗，本字段
    /// 只持久开关值）。
    #[serde(default = "default_consent_switch_on")]
    pub clipboard_allowed: bool,

    /// ON = 主控端收到对端文件元数据后后台自动预取（复用既有 FetchFile
    /// 授权链）至本地缓存目录，全部落定后把缓存内真实路径写入本机 OS
    /// 剪贴板（CF_HDROP）——Explorer/桌面 Ctrl+V 即得、零阻塞；同时本机
    /// 写其 OS 板）。OFF = 完全回退既有两段式（应用内粘贴拉取/上传），
    /// 零预取零直传。「复制即传」语义 = 用户复制动作即意图（业界
    /// RDP/RustDesk 常态）；授权链原样生效（Fetch 授权/consent/传输开关
    /// fail-closed 门控不绕过——对端开关 OFF 时元数据帧在门内即被拒，
    /// 不触发预取）。写 OS 板会覆盖本机现有剪贴板内容 = 业界常态。
    #[serde(default = "default_consent_switch_on")]
    pub clip_direct_paste: bool,
}

fn default_max_file_size() -> u64 {
    4 * 1024 * 1024 * 1024
}

/// S-10b (F-11): 单会话字节配额默认值（4 GiB，对齐 core
/// `DEFAULT_SESSION_MAX_BYTES`）。
fn default_session_max_bytes() -> u64 {
    4 * 1024 * 1024 * 1024
}

/// S-10b (F-11): 单会话文件数配额默认值（64，对齐 core
/// `DEFAULT_SESSION_MAX_FILES`）。
fn default_session_max_files() -> u64 {
    64
}

fn default_auto_resume() -> bool {
    true
}

/// （**开**——用户 09-17 裁定「默认都开」；旧配置缺键 = serde 默认 = 开）。
fn default_consent_switch_on() -> bool {
    true
}

impl Default for FileTransferConfig {
    fn default() -> Self {
        Self {
            download_dir: None,
            max_file_size: default_max_file_size(),
            session_max_bytes: default_session_max_bytes(),
            session_max_files: default_session_max_files(),
            fs_roots: Vec::new(),
            fs_write_roots: Vec::new(),
            auto_resume: default_auto_resume(),
            file_transfer_allowed: default_consent_switch_on(),
            clipboard_allowed: default_consent_switch_on(),
            clip_direct_paste: default_consent_switch_on(),
        }
    }
}

impl FileTransferConfig {
    /// 接收目录（配置值或默认 `~/Downloads/KirinDesk`）。
    pub fn resolved_download_dir(&self) -> std::path::PathBuf {
        match &self.download_dir {
            Some(d) if !d.trim().is_empty() => std::path::PathBuf::from(d),
            _ => dirs_next::download_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("KirinDesk"),
        }
    }
}

/// 无人值守模式配置（`[unattended]` 段）。
///
/// `enabled` 是「自动接受连接 + 无弹窗审批」的总开关；`auto_start_on_boot`
/// 与 `auto_start_server` 独立可配 —— 开机自启不要求开启无人值守（D6）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnattendedConfig {
    /// 无人值守总开关：开启后 known_clients/白名单命中自动放行，未知设备
    /// 一律拒绝并写审计（无人工审批弹窗），temp-mode 旁路禁用。
    #[serde(default)]
    pub enabled: bool,

    /// 开机自动启动（用户级：Windows HKCU Run / Linux XDG autostart /
    /// macOS LaunchAgent，无需管理员权限）。可独立于 `enabled` 使用。
    #[serde(default)]
    pub auto_start_on_boot: bool,

    /// 应用启动时自动开启服务端（监听 network.port + DNS 注册/心跳）。
    /// 显示名「默认受控」，默认改 **false**（三开关默认全关；
    /// 旧配置文件中显式 true 保持不变——serde default 只作用于缺失字段）。
    #[serde(default = "default_auto_start_server")]
    pub auto_start_server: bool,
}

fn default_auto_start_server() -> bool {
    false
}

impl Default for UnattendedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_start_on_boot: false,
            auto_start_server: default_auto_start_server(),
        }
    }
}

/// UI 外观配置（`[ui]` 段）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// 主题模式: "light"（默认）| "dark" | "system"
    #[serde(default = "default_theme")]
    pub theme: String,
    /// 语言: "system"（跟随系统，默认）| "zh" | "en"
    #[serde(default = "default_language")]
    pub language: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            language: default_language(),
        }
    }
}

fn default_theme() -> String {
    "light".to_string()
}

fn default_language() -> String {
    "system".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    /// Unique device identifier (e.g., "my-pc")
    pub id: String,

    /// Human-readable device name
    pub name: String,

    /// Device nickname (used in auth: nickname + challenge)
    #[serde(default)]
    pub nickname: String,

    /// Challenge code for authentication
    #[serde(default)]
    pub challenge_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoDaddyConfig {
    /// GoDaddy API key
    pub api_key: String,

    /// GoDaddy API secret
    pub api_secret: String,

    /// Domain managed on GoDaddy (e.g., "example.com")
    pub domain: String,

    /// API base URL (production or OTE)
    #[serde(default = "default_api_url")]
    pub api_url: String,
}

fn default_api_url() -> String {
    "https://api.godaddy.com".to_string()
}

/// + M9-DNS000: DNS 域名维护服务商选择（`[dns]` 段）。
///
/// - `provider`：当前激活服务商注册表键名（默认 "godaddy"；UI 下拉框 / CLI
///   `dns list-providers` 的数据源为 `dns_providers::dns_provider_defs()`）。
/// - `providers`：每服务商独立凭据表（`[dns.providers.*]`，原始字符串，
///   [`SENSITIVE_DNS_FIELD_KEYS`]）经 `secure.rs` 密文落盘 `{v:...}`，
///   加载时解密为内存明文；非敏感 key（domain/region 等）保持明文。
///
/// 迁移：旧 `[godaddy]` 表（api_key/api_secret/api_url）在加载时自动迁入
/// `[dns.providers.godaddy]` 并写回（见 `Config::load_from`）；`[godaddy]`
/// 段结构原样保留（CLI setup/register/discover/heartbeat 兼容读）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_dns_provider")]
    pub provider: String,

    /// M9-DNS000: 每服务商凭据表（`[dns.providers.<name>]`）。
    #[serde(default)]
    pub providers: BTreeMap<String, BTreeMap<String, String>>,

    /// 域名模式加密 DNS 强制（`[dns.security]` 段：DoH/DoT 端点、
    /// 强制开关；默认 enforce）。未配置该段 → 默认 enforce（安全默认）。
    #[serde(default)]
    pub security: DnsSecurityConfig,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            provider: default_dns_provider(),
            providers: BTreeMap::new(),
            security: DnsSecurityConfig::default(),
        }
    }
}

fn default_dns_provider() -> String {
    "godaddy".to_string()
}

/// 域名模式加密 DNS 强制配置（`[dns.security]` 段，需求 §5.2）。
///
/// 域名模式（服务端 + 客户端）下的全部 DNS 解析必须走 DoH/DoT（DDNS-DOH-001）；
/// `mode = "enforce"`（默认）时加密 DNS 全部端点不可用 → fail-closed 拒连
/// （DDNS-DOH-003）；`mode = "off"` 显式关闭强制——仅限 IP 模式使用，域名
/// 模式下关闭强制即自动降级为不可用并提示（DDNS-DOH-007），**绝不回退明文**。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSecurityConfig {
    /// 强制模式："enforce"（默认，域名模式强制 DoH/DoT，fail-closed）| "off"。
    #[serde(default = "default_dns_security_mode")]
    pub mode: String,

    /// DoH 端点优先序（`application/dns-json`，GET，强制 HTTPS + 证书校验）。
    #[serde(default = "default_doh_endpoints")]
    pub doh: Vec<String>,

    /// DoT 端点优先序（TLS TCP 853）。
    #[serde(default = "default_dot_endpoints")]
    pub dot: Vec<String>,

    /// 单端点超时（毫秒，默认 5000；全列表总超时 15s 在解析器侧固定）。
    #[serde(default = "default_dns_resolve_timeout_ms")]
    pub resolve_timeout_ms: u64,

    /// 解析结果缓存 TTL（秒，默认 50，沿用 discovery 缓存语义，DDNS-DOH-006）。
    #[serde(default = "default_dns_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
}

impl Default for DnsSecurityConfig {
    fn default() -> Self {
        Self {
            mode: default_dns_security_mode(),
            doh: default_doh_endpoints(),
            dot: default_dot_endpoints(),
            resolve_timeout_ms: default_dns_resolve_timeout_ms(),
            cache_ttl_secs: default_dns_cache_ttl_secs(),
        }
    }
}

/// 默认 enforce：安全默认，域名模式自启用即强制加密解析（需求 §5.3）。
fn default_dns_security_mode() -> String {
    "enforce".to_string()
}

fn default_doh_endpoints() -> Vec<String> {
    vec![
        "https://cloudflare-dns.com/dns-query".to_string(),
        "https://dns.google/resolve".to_string(),
        "https://dns.alidns.com/resolve".to_string(),
    ]
}

fn default_dot_endpoints() -> Vec<String> {
    vec![
        "1.1.1.1:853".to_string(),
        "8.8.8.8:853".to_string(),
        "2400:3200::1:853".to_string(),
    ]
}

fn default_dns_resolve_timeout_ms() -> u64 {
    5000
}

fn default_dns_cache_ttl_secs() -> u64 {
    50
}

impl DnsSecurityConfig {
    /// 是否强制加密 DNS（enforce）。未知值按安全默认 enforce 处理（不静默关闭）。
    pub fn enforce(&self) -> bool {
        !self.mode.eq_ignore_ascii_case("off")
    }
}

/// DDNS 地址获取模式（IPv4/IPv6 各一，需求 §4.2/§4.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DdnsMode {
    /// 自动：IPv4 = 公网出口 IP（外部服务），IPv6 = 本机全局单播。
    Auto,
    /// 手动：用户填写固定地址，心跳永不覆盖（仅刷新 TTL，DDNS-IPV4-004）。
    Manual,
}

/// DDNS 域名自动更新维护配置（`[ddns]` 段，需求 §5.1）。
///
/// 默认全部关闭/自动；`interval_secs` 下限 60s（防服务商 API 配额滥用，
/// DDNS-002），未设置时回退 `[network] heartbeat_interval`（§5.3 兼容迁移）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsConfig {
    /// 总开关（默认关；开启后后台 DdnsService 周期运行，DDNS-001）。
    #[serde(default)]
    pub enabled: bool,

    /// 更新周期（秒，默认 300；下限 60s 收敛；`None` = 回退 [network] heartbeat_interval）。
    #[serde(default)]
    pub interval_secs: Option<u64>,

    /// IPv4 模式（auto = 公网出口 IP；manual = 固定地址）。
    #[serde(default = "default_ddns_mode")]
    pub ipv4_mode: DdnsMode,

    /// 手动固定 IPv4（"0.0.0.0" 空占位；心跳永不覆盖，DDNS-IPV4-004）。
    #[serde(default)]
    pub ipv4_manual: String,

    /// 公网 IP 服务优先序（全部 HTTPS；默认 ipify → ip.sb → icanhazip）。
    #[serde(default = "default_ipv4_sources")]
    pub ipv4_sources: Vec<String>,

    /// IPv6 模式（auto = 本机全局单播；manual = 上游固定/转发场景）。
    #[serde(default = "default_ddns_mode")]
    pub ipv6_mode: DdnsMode,

    /// 手动固定 IPv6（"::" 空占位；心跳永不覆盖，DDNS-IPV6-003）。
    #[serde(default)]
    pub ipv6_manual: String,

    /// 自动维护 SRV（远控端口，DDNS-REC-001）。
    #[serde(default = "default_true")]
    pub publish_srv: bool,

    /// 自动维护 TXT（签名/DeviceMeta，DDNS-REC-002）。
    #[serde(default = "default_true")]
    pub publish_txt: bool,

    /// 自动维护 A 记录（DDNS-REC-003）。
    #[serde(default = "default_true")]
    pub publish_a: bool,

    /// 自动维护 AAAA 记录（DDNS-REC-003）。
    #[serde(default = "default_true")]
    pub publish_aaaa: bool,
}

fn default_true() -> bool {
    true
}

fn default_ddns_mode() -> DdnsMode {
    DdnsMode::Auto
}

fn default_ipv4_sources() -> Vec<String> {
    vec![
        "ipify".to_string(),
        "ip.sb".to_string(),
        "icanhazip".to_string(),
    ]
}

impl Default for DdnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: None,
            ipv4_mode: default_ddns_mode(),
            ipv4_manual: String::new(),
            ipv4_sources: default_ipv4_sources(),
            ipv6_mode: default_ddns_mode(),
            ipv6_manual: String::new(),
            publish_srv: default_true(),
            publish_txt: default_true(),
            publish_a: default_true(),
            publish_aaaa: default_true(),
        }
    }
}

/// DDNS 更新周期下限（60s，防服务商 API 配额滥用，DDNS-002）。
pub const DDNS_INTERVAL_MIN_SECS: u64 = 60;

impl DdnsConfig {
    /// 生效更新周期（秒）：`[ddns] interval_secs` 优先（≥60s 下限收敛）；
    /// 未设置 → 回退 `[network] heartbeat_interval`（同样 ≥60s 收敛，§5.3）。
    pub fn effective_interval_secs(&self, network_heartbeat_secs: u64) -> u64 {
        let base = self.interval_secs.unwrap_or(network_heartbeat_secs);
        base.max(DDNS_INTERVAL_MIN_SECS)
    }

    /// 手动 IPv4 地址（配置为合法 Ipv4Addr 且非 `0.0.0.0` 空占位 → `Some`）。
    pub fn ipv4_manual_addr(&self) -> Option<std::net::Ipv4Addr> {
        let s = self.ipv4_manual.trim();
        if s.is_empty() || s == "0.0.0.0" {
            return None;
        }
        s.parse().ok()
    }

    /// 手动 IPv6 地址（配置为合法 Ipv6Addr 且非 `::` 空占位 → `Some`）。
    pub fn ipv6_manual_addr(&self) -> Option<std::net::Ipv6Addr> {
        let s = self.ipv6_manual.trim();
        if s.is_empty() || s == "::" {
            return None;
        }
        s.parse().ok()
    }
}

impl Config {
    /// DDNS 生效更新周期（秒；含 [network] 回退与 60s 下限收敛）。
    pub fn effective_ddns_interval(&self) -> u64 {
        self.ddns.effective_interval_secs(self.network.heartbeat_interval)
    }
}

impl Config {
    /// M9-DNS000 (§4.2): 旧 `[godaddy]` 表 → `[dns.providers.godaddy]` 迁移。
    ///
    /// 条件：`[dns.providers]` 尚无 "godaddy" 条目 且 旧段 api_key/api_secret
    /// 任一非空。迁移仅搬 api_key/api_secret/api_url（Credential::Godaddy
    /// 字段）；`domain` 留在 `[godaddy]`（设备级域名，CLI 兼容读）。
    /// 返回 `true` = 本次发生了迁移（调用方应写回）。
    pub fn migrate_legacy_godaddy(&mut self) -> bool {
        if self.dns.providers.contains_key("godaddy") {
            return false;
        }
        let legacy_has_creds = !self.godaddy.api_key.trim().is_empty()
            || !self.godaddy.api_secret.trim().is_empty();
        if !legacy_has_creds {
            return false;
        }
        let mut fields = BTreeMap::new();
        fields.insert("api_key".to_string(), self.godaddy.api_key.clone());
        fields.insert("api_secret".to_string(), self.godaddy.api_secret.clone());
        fields.insert("api_url".to_string(), self.godaddy.api_url.clone());
        self.dns.providers.insert("godaddy".to_string(), fields);
        tracing::info!(
            "Config: migrated legacy [godaddy] credentials to [dns.providers.godaddy]"
        );
        true
    }

    /// 指定服务商已配置的凭据表（`[dns.providers.<name>]`；无 → `None`）。
    pub fn dns_provider_credentials(
        &self,
        provider: &str,
    ) -> Option<&BTreeMap<String, String>> {
        self.dns.providers.get(provider)
    }

    /// 当前激活服务商的凭据表（`[dns] provider` 对应条目；无 → `None`）。
    pub fn active_dns_provider_credentials(&self) -> Option<&BTreeMap<String, String>> {
        self.dns_provider_credentials(&self.dns.provider)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Listening port for remote desktop
    #[serde(default = "default_port")]
    pub port: u16,

    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// DNS record TTL
    #[serde(default = "default_ttl")]
    pub dns_ttl: u32,

    /// 全局 v6，端口 = 真实监听端口）——同局域网两机自动直连，不走公网
    /// 中继。分类筛排除回环/多播/CGNAT 100.64.0.0/10/链路本地（研究结论
    /// 见 relay::lan_candidates 模块注释）。默认 true；false 时仅上报
    /// `[tunnel] extra_candidates`（服务器观察地址仍附加）。serde default
    /// 兼容旧配置（缺省即 true）。
    #[serde(default = "default_report_lan_candidates")]
    pub report_lan_candidates: bool,

    /// Allowed domains whitelist (only these can connect)
    #[serde(default)]
    pub allowed_domains: Vec<String>,

    /// If true, allow IP-mode connections (bypass domain whitelist)
    #[serde(default)]
    pub ip_mode_allowed: bool,

    /// （IP/ID/Domain）之一。`ip_mode_allowed` 与 `id_mode_allowed` 两标志
    /// 共同派生当前模式（ID > IP > Domain 优先级）。ID 模式 = 本机作为
    /// 直连 TCP 仍走白名单校验（`ip_mode_allowed=false` 语义）。仅由
    /// Dashboard 工作模式切换写入（Connect 页不触碰）。
    #[serde(default)]
    pub id_mode_allowed: bool,

    /// If true, skip whitelist check (temporary mode for headless servers)
    /// Allows any client to connect without domain whitelist approval.
    #[serde(default)]
    pub temp_mode: bool,

    /// 临时连接窗口时长（秒）。默认 300（5 分钟），可配置范围
    /// 60–3600——越界值经 [`NetworkConfig::effective_temp_mode_ttl`] 收敛。
    #[serde(default = "default_temp_mode_ttl_secs")]
    pub temp_mode_ttl_secs: u64,

    /// 白名单条目（模式 + 过期时间，`*.example.com` 通配支持）。
    /// 兼容旧 `allowed_domains`（无过期、永久有效），两者共同生效。
    #[serde(default)]
    pub whitelist: Vec<WhitelistEntry>,

    /// (SRV-IDWL-001): 设备 ID 白名单 — 永久精确条目（对称
    /// `allowed_domains`；GUI Settings 文本框 / `whitelist add-id` 写入，
    /// 与 known_clients 同 key，大小写敏感）。
    #[serde(default)]
    pub allowed_ids: Vec<String>,

    /// (SRV-IDWL-002): 设备 ID 白名单带过期条目（对称 `whitelist`，
    /// `whitelist add-id <id> <RFC3339>` 写入；到期自动失效，`prune_expired` 清理）。
    #[serde(default)]
    pub id_whitelist: Vec<IdWhitelistEntry>,

    /// ID 连接沿用昵称 + 挑战码验证）。开启后：控制端设备 ID 不在
    /// `allowed_ids` / 未过期 `id_whitelist` 内 → 即使昵称和挑战码正确也拒绝
    /// （fail-closed，判定点在握手/审批链路服务端 core 层
    /// `crypto::handshake::id_whitelist_enforce_check`）。与 M15 既有白名单
    /// （命中=免审批）区分：本开关把 ID 白名单从「免审批维度」升级为
    /// 「强制放行条件」。由 Dashboard ID 模式区块开关 / Settings 白名单页写入。
    #[serde(default)]
    pub id_whitelist_enforce: bool,

    /// 未知连接（非白名单/无 pin）进入审批后，限时内无用户决策则服务端
    /// **主动断开**并下发可分类关闭原因 `approval_timeout`（wire 码
    /// `crypto::handshake::REJECT_CODE_APPROVAL_TIMEOUT`）。默认
    /// [`APPROVAL_TIMEOUT_DEFAULT`]（60s，与生产 `APPROVAL_WAIT_TIMEOUT` 同值）；
    /// 越界值经 [`NetworkConfig::effective_approval_timeout_secs`] 收敛
    /// （口径对齐 `temp_mode_ttl_secs`）。
    #[serde(default = "default_approval_timeout_secs")]
    pub approval_timeout_secs: u64,
}

fn default_port() -> u16 {
    DEFAULT_NETWORK_PORT
}

/// ① 避开 Windows RDP 默认 3389（用户反馈的直连冲突）；② 避开 relay 控制
/// 端口 7000 / rendezvous 7001；③ 低于 relay 数据段（`--port-range`，如
/// 60000-61000）起点；④ 避开常见服务 22/80/443 等。位于动态/私有区
/// （49152-65535），serde default 仅未配置时生效（旧配置显式端口不受影响）。
pub const DEFAULT_NETWORK_PORT: u16 = 59990;

fn default_heartbeat_interval() -> u64 {
    30
}

fn default_ttl() -> u32 {
    600
}

fn default_report_lan_candidates() -> bool {
    true
}

/// 临时连接窗口默认时长（5 分钟）。
fn default_temp_mode_ttl_secs() -> u64 {
    300
}

/// 临时连接窗口 TTL 可配置范围（SRV-TMP-004）。
pub const TEMP_MODE_TTL_MIN: u64 = 60;
pub const TEMP_MODE_TTL_MAX: u64 = 3600;

/// 同值（旧配置文件缺省字段 = 现行为不变）。
pub const APPROVAL_TIMEOUT_DEFAULT: u64 = 60;
/// 上限防审批槽/并发坑长挂（对齐 `PENDING_WAITING_TTL` 60s+15s 宽限量级）。
pub const APPROVAL_TIMEOUT_MIN: u64 = 10;
pub const APPROVAL_TIMEOUT_MAX: u64 = 600;

fn default_approval_timeout_secs() -> u64 {
    APPROVAL_TIMEOUT_DEFAULT
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaConfig {
    /// Preferred encoder (auto, nvenc, vaapi, software)
    #[serde(default = "default_encoder")]
    pub encoder: String,

    /// Target framerate for screen capture
    #[serde(default = "default_framerate")]
    pub framerate: u32,

    /// Video bitrate in kbps
    #[serde(default = "default_bitrate")]
    pub bitrate: u32,

    /// 旧配置无此段 → 默认值，正常解析。
    #[serde(default)]
    pub gpu: GpuConfig,
}

///
/// UI 启动时经 `kirin_desk_media::gpu::apply_preferences` 注入；
/// `KIRIN_GPU_PREFER` 环境变量在读取偏好时覆盖 `prefer`（env > config > auto）。
///
/// `Default`：`MediaConfig` 的 `#[serde(default)]` 要求本类型实现 Default
/// （并行任务接线时编译器校验发现缺失，补齐）；手写实现与字段级 serde
/// 默认值保持一致（prefer=auto / filter_virtual=true）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuConfig {
    /// 偏好：auto(默认,第一个真实硬件适配器) | intel | nvidia | amd |
    /// luid:0x…(调试)。开发机双 GPU 调试：切 intel 验 QSV / nvidia 验 NVENC。
    #[serde(default = "default_gpu_prefer")]
    pub prefer: String,

    /// 过滤虚拟驱动（适配器 + 显示器共用开关；默认 true）。
    #[serde(default = "default_gpu_filter_virtual")]
    pub filter_virtual: bool,

    /// 覆盖默认黑名单关键词（空 = 用默认表，见 §3.3）。
    #[serde(default)]
    pub virtual_keywords: Vec<String>,
}

impl Default for GpuConfig {
    fn default() -> Self {
        Self {
            prefer: default_gpu_prefer(),
            filter_virtual: default_gpu_filter_virtual(),
            virtual_keywords: Vec::new(),
        }
    }
}

fn default_gpu_prefer() -> String {
    "auto".to_string()
}

fn default_gpu_filter_virtual() -> bool {
    true
}

fn default_encoder() -> String {
    "auto".to_string()
}

fn default_framerate() -> u32 {
    30
}

fn default_bitrate() -> u32 {
    5000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (text or json)
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Log directory (auto-created). Defaults to ~/.kirin_desk/logs/
    #[serde(default)]
    pub log_dir: Option<String>,

    /// Days to keep old log files. Default: 7
    #[serde(default = "default_log_keep_days")]
    pub log_keep_days: u64,
}

fn default_log_keep_days() -> u64 { 7 }

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device: DeviceConfig {
                // 留空 = 自动（系统硬盘 UUID / machine-id / 平台 UUID）。
                id: String::new(),
                name: "My Device".to_string(),
                nickname: String::new(),
                challenge_code: String::new(),
            },
            godaddy: GoDaddyConfig {
                api_key: String::new(),
                api_secret: String::new(),
                domain: "example.com".to_string(),
                api_url: default_api_url(),
            },
            dns: DnsConfig::default(),
            ddns: DdnsConfig::default(),
            network: NetworkConfig {
                port: default_port(),
                heartbeat_interval: default_heartbeat_interval(),
                dns_ttl: default_ttl(),
                report_lan_candidates: default_report_lan_candidates(),
                allowed_domains: Vec::new(),
                ip_mode_allowed: false,
                id_mode_allowed: false,
                temp_mode: false,
                temp_mode_ttl_secs: default_temp_mode_ttl_secs(),
                whitelist: Vec::new(),
                allowed_ids: Vec::new(),
                id_whitelist: Vec::new(),
                id_whitelist_enforce: false,
                approval_timeout_secs: default_approval_timeout_secs(),
            },
            media: MediaConfig {
                encoder: default_encoder(),
                framerate: default_framerate(),
                bitrate: default_bitrate(),
                gpu: GpuConfig {
                    prefer: default_gpu_prefer(),
                    filter_virtual: default_gpu_filter_virtual(),
                    virtual_keywords: Vec::new(),
                },
            },
            logging: LoggingConfig {
                level: default_log_level(),
                format: default_log_format(),
                log_dir: None,
                log_keep_days: default_log_keep_days(),
            },
            ui: UiConfig::default(),
            unattended: UnattendedConfig::default(),
            file_transfer: FileTransferConfig::default(),
            transport: TransportConfig::default(),
            tunnel: TunnelConfig::default(),
            update: UpdateConfig::default(),
            nodes: Vec::new(),
            debug: DebugConfig::default(),
            input: InputConfig::default(),
            save_override: None,
        }
    }
}

impl NetworkConfig {
    /// 临时连接窗口 TTL 收敛值（SRV-TMP-004，范围 60–3600）。
    /// 配置越界时静默收敛到边界，保证 `enable` 语义稳定。
    pub fn effective_temp_mode_ttl(&self) -> u64 {
        self.temp_mode_ttl_secs.clamp(TEMP_MODE_TTL_MIN, TEMP_MODE_TTL_MAX)
    }

    /// [`Self::effective_temp_mode_ttl`]）。服务端审批等待据此取值；
    /// 越界配置静默收敛到边界（fail-closed：永不收敛到 0/无限等待）。
    pub fn effective_approval_timeout_secs(&self) -> u64 {
        self.approval_timeout_secs.clamp(APPROVAL_TIMEOUT_MIN, APPROVAL_TIMEOUT_MAX)
    }
}


/// 上次成功加载配置的指纹（进程内静态；`None` = 尚未成功加载过/首次）。
///
/// 仅用于决定「配置是否相对上次生效值实际变化」，从而抑制稳定运行时的
/// 高频 `Config loaded` info 刷屏。进程内比较即可，无需跨版本稳定的哈希。
static LAST_CONFIG_FINGERPRINT: Mutex<Option<u64>> = Mutex::new(None);

/// 配置指纹：整份配置序列化后哈希。
///
/// 相对 `Config::load()` 本身的「文件读取 + TOML 解析 + 敏感字段解密」
/// 开销可忽略；serde 序列化是确定性的（BTreeMap 有序），相等配置 → 相同
/// 指纹，变化配置 → 不同指纹。
fn config_fingerprint(cfg: &Config) -> u64 {
    let mut hasher = DefaultHasher::new();
    serde_json::to_vec(cfg)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

/// 门控判定（生产入口）：配置相对上次成功加载实际变化（或首次）→ `true`。
fn should_log_config_load(cfg: &Config) -> bool {
    should_log_config_load_in(&LAST_CONFIG_FINGERPRINT, config_fingerprint(cfg))
}

/// 可测试的门控实现：对传入槽位做「变化才 true」判定，锁内比较+更新，
/// 幂等、线程安全（`Mutex` 保证并发下不重复输出）。
fn should_log_config_load_in(slot: &Mutex<Option<u64>>, fingerprint: u64) -> bool {
    let mut slot = slot.lock().unwrap_or_else(|p| p.into_inner());
    if *slot == Some(fingerprint) {
        return false;
    }
    *slot = Some(fingerprint);
    true
}

// ════════════════════════════════════════════════════════════════
// （用户 09-22 三轮复测 §9：`latency_trace` 单键笔误——裸 `on` = TOML 语法错
//  / `"on"` 字符串 = 类型错——旧路径整份 Config::load() 失败 → 连接初始化
//  失败 + UI 权限开关无法翻转。修复口径：全合法形态走原严格解析（零行为
//  变化）；失败且存在 `[debug]` 段 = 段级故障隔离（主段独立解析、debug 段
//  宽松值/缺省回退，WARN 带键名，不阻塞启动/连接）；失败且无 `[debug]`
//  段（或主段亦坏）= fail-closed（附出错键名 key_hint 供启动横幅）。）
// ════════════════════════════════════════════════════════════════

/// （大小写不敏感）；域外值（含空串/`yes`/`2`/`0x1` 等）= `None`（调用方
/// 回退默认 + WARN 带键名，不阻塞）。
pub(crate) fn lenient_debug_bool(token: &str) -> Option<bool> {
    match token.trim().to_ascii_lowercase().as_str() {
        "true" | "on" | "1" => Some(true),
        "false" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// 剥外层单/双引号，得裸 token 供 [`lenient_debug_bool`]。
pub(crate) fn strip_toml_value(value: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    for c in value.trim().chars() {
        match quote {
            Some(q) => {
                out.push(c);
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => {
                    quote = Some(c);
                    out.push(c);
                }
                '#' => break,
                _ => out.push(c),
            },
        }
    }
    let s = out.trim().to_string();
    if let Some(inner) = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        return inner.to_string();
    }
    if let Some(inner) = s.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')) {
        return inner.to_string();
    }
    s
}

/// 对账锚点）。
pub(crate) fn r134_2_invalid_key_line(key: &str, value: &str) -> String {
    format!(
        "Config: [debug] {key} value '{value}' invalid (expected true/false/on/off/1/0, case-insensitive) — fallback to default (non-blocking)"
    )
}

pub(crate) fn r134_2_unknown_key_line(key: &str) -> String {
    format!("Config: [debug] unknown key '{key}' ignored (non-blocking)")
}

pub(crate) fn r134_2_bad_line_line(line: &str) -> String {
    format!("Config: [debug] unparseable line ignored (non-blocking): {line}")
}

/// 影响的对账锚点）。
pub(crate) fn r134_2_section_isolated_line() -> String {
    "Config: [debug] section strict parse failed — section isolated, lenient/default applied; rest of config unaffected".to_string()
}

/// `[debug.sub]` 子表头不命中；注释行不命中）。
fn is_debug_section_header(line: &str) -> bool {
    let t = line.trim_start();
    let Some(rest) = t.strip_prefix('[') else {
        return false;
    };
    let Some(close) = rest.find(']') else {
        return false;
    };
    let name = rest[..close].trim();
    let after = rest[close + 1..].trim_start();
    name == "debug" && (after.is_empty() || after.starts_with('#'))
}

/// 段头行（不含）或 EOF）→（剥离该段后的全文、段体）。`None` = 无该段。
/// **纯文本层操作**（不经 TOML 解析器：损坏段恰是解析器吞不下去的语法错
/// 形态，先隔离再解析）。
pub(crate) fn split_debug_section(content: &str) -> Option<(String, String)> {
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.iter().position(|l| is_debug_section_header(l))?;
    let mut end = lines.len();
    for (i, l) in lines.iter().enumerate().skip(start + 1) {
        if l.trim_start().starts_with('[') {
            end = i;
            break;
        }
    }
    let body = lines[start + 1..end].join("\n");
    let mut main: Vec<&str> = Vec::with_capacity(lines.len().saturating_sub(end - start));
    main.extend_from_slice(&lines[..start]);
    main.extend_from_slice(&lines[end..]);
    Some((main.join("\n"), body))
}

/// 解析（零行为变化）；严格失败（裸值语法错/字符串或整数类型错）→ 逐行
/// 宽松：布尔键（`latency_trace`/`conn_stats_visible`）接受宽松 token 集，
/// 域外 → 默认 + WARN 带键名；未知键/不可解析行 → 忽略 + WARN。
/// **永不报错**（段级回退由调用方语义保证：调用前整段严格解析已失败）。
pub(crate) fn parse_debug_section_lenient(body: &str) -> DebugConfig {
    if let Ok(cfg) = toml::from_str::<DebugConfig>(body) {
        return cfg;
    }
    let mut cfg = DebugConfig::default();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            tracing::warn!("{}", r134_2_bad_line_line(line));
            continue;
        };
        let key = key.trim().trim_matches(|c| c == '"' || c == '\'');
        match key {
            "latency_trace" => {
                let v = strip_toml_value(value);
                if let Some(b) = lenient_debug_bool(&v) {
                    cfg.latency_trace = Some(b);
                } else {
                    tracing::warn!("{}", r134_2_invalid_key_line(key, &v));
                }
            }
            "conn_stats_visible" => {
                let v = strip_toml_value(value);
                if let Some(b) = lenient_debug_bool(&v) {
                    cfg.conn_stats_visible = b;
                } else {
                    tracing::warn!("{}", r134_2_invalid_key_line(key, &v));
                }
            }
            _ => {
                tracing::warn!("{}", r134_2_unknown_key_line(key));
            }
        }
    }
    cfg
}

/// ——供 `ConfigError::ParseError.key_hint` → 启动横幅「文件路径 + 出错键
/// 名」。`None` = 不可提取（段头行/无 `=`/无位置信息）。
pub(crate) fn key_hint_from_error(content: &str, err: &toml::de::Error) -> Option<String> {
    let start = err.span()?.start;
    let line_start = content[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = content[line_start..]
        .find('\n')
        .map(|i| line_start + i)
        .unwrap_or(content.len());
    let line = content[line_start..line_end].trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
        return None;
    }
    let (key, _) = line.split_once('=')?;
    let key = key.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    if key.is_empty() {
        return None;
    }
    Some(key.to_string())
}

impl Config {
    /// Load configuration from the default path
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::default_path()?;
        tracing::debug!("Config: loading from {:?}", path);
        let config = Self::load_from(&path);
        match &config {
            Ok(cfg) => {
                // 首次加载或配置实际变化时仍输出 info，保留诊断能力。
                if should_log_config_load(cfg) {
                    tracing::info!(
                        "Config loaded: device_id={}, domain={}, port={}, level={}",
                        cfg.device.id, cfg.godaddy.domain, cfg.network.port, cfg.logging.level
                    );
                }
            }
            Err(e) => tracing::warn!("Config: failed to load from {:?}: {}", path, e),
        }
        config
    }

    /// Load configuration from a specific path
    pub fn load_from(path: &std::path::Path) -> Result<Self, ConfigError> {
        tracing::debug!("Config: reading from {:?}", path);
        // S-23 (F-28)：读侧 O_NOFOLLOW（`fsutil::read_private`）——配置含
        // challenge/token/GoDaddy 凭据，symlink 指向任意文件时拒绝读取
        // （S-07 后补漏项；写侧已由 write_private 覆盖）。
        let bytes = crate::fsutil::read_private(path).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        let content = String::from_utf8(bytes).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;
        // `latency_trace = on` 裸值 = TOML 语法错 / `"on"` 字符串 = 类型错，
        // 旧路径整份 load 失败 → 连接初始化失败 + 权限开关无法翻转）。
        // 全合法形态 = 原严格解析零行为变化；失败且有 `[debug]` 段 = 段级
        // 隔离（主段独立解析 + debug 段宽松值/缺省，WARN 带键名不阻塞）；
        // 失败且无 `[debug]` 段（或主段亦坏）= fail-closed + 出错键名
        // （key_hint，供启动横幅）。
        let mut config: Config = match toml::from_str::<Config>(&content) {
            Ok(c) => c,
            Err(first_err) => {
                let Some((main_content, debug_body)) = split_debug_section(&content) else {
                    return Err(ConfigError::ParseError {
                        path: path.to_path_buf(),
                        detail: first_err.to_string(),
                        key_hint: key_hint_from_error(&content, &first_err),
                    });
                };
                let mut main: Config =
                    toml::from_str(&main_content).map_err(|e2| ConfigError::ParseError {
                        path: path.to_path_buf(),
                        detail: e2.to_string(),
                        key_hint: key_hint_from_error(&main_content, &e2),
                    })?;
                tracing::warn!("{}", r134_2_section_isolated_line());
                main.debug = parse_debug_section_lenient(&debug_body);
                main
            }
        };
        // GUI 模式按钮（`!= "server"`）与表单渲染（`== "client"`）判定相反，
        // 产生「Client 高亮却显示 Server 表单」双面界面；注册放行
        // （`mode != "client"` 拒绝）同样受益。加载即归一，读方口径统一。
        if config.tunnel.mode.trim().is_empty() {
            config.tunnel.mode = default_tunnel_mode();
        }
        // 字段 → 迁移候选。解密失败（密钥丢失/篡改）→ fail-closed 拒绝加载。
        let plaintext_detected = decrypt_sensitive_fields(&mut config, &Self::key_dir(path))?;
        // M9-DNS000 (§4.2): 旧 `[godaddy]` 表 → `[dns.providers.godaddy]`
        // 自动迁移（仅当新段缺失且旧段有值时；迁移后写回，用户可见）。
        let migrated = config.migrate_legacy_godaddy();
        // （空串/`default-device`，`id_is_auto`）时，`effective_device_id`
        // 数字字母混合、无 HD- 前缀——稳定源 Windows 卷序列号 / Linux
        // 并**持久化回写** `config.device.id`——此后 relay ID 模式注册
        // （`ui/src/cli.rs start_device_registration`）、设备页、分享体系读
        // 同一落盘值，同一台机无论何时注册/展示 ID 恒定且与设备页一致。
        // **旧 ID 就旧不就新**：已落盘旧格式（HD- 短码等）/ 自定义值原样
        // 保留不迁移（旧 ID 仍合法）；仅未填写走新格式。旧缺陷：展示=HD-
        // 短码 vs 注册=公钥指纹（128 位 hex）两套 ID 并存 → 控制端 resolve
        // （HD-xxx）恒离线（"找不到 ID"）。
        let id_written_back = if crate::device::id_is_auto(&config.device.id) {
            let derived = crate::device::effective_device_id(&config.device.id);
            tracing::info!(
                "Config: [device] id 未填写，自动派生 '{}' 并回写",
                derived
            );
            config.device.id = derived;
            true
        } else {
            false
        };
        // 坏；内存态配置继续可用，不阻断（派生值确定性，下次加载重派生同值）。
        if plaintext_detected || migrated || id_written_back {
            if let Err(e) = config.save_to(path) {
                tracing::warn!(
                    "Config: 首次加载写回失败（敏感字段加密迁移 / [device] id 派生 ID；内存态配置继续可用）: {e}"
                );
            }
        }
        tracing::debug!("Config: successfully parsed from {:?}", path);
        Ok(config)
    }

    /// Save configuration to the default path
    ///
    /// 临时路径；生产恒 `None` → 行为逐位不变（即调即存语义保留）。
    pub fn save(&self) -> Result<(), ConfigError> {
        if let Some(path) = &self.save_override {
            return self.save_to(path);
        }
        let path = Self::default_path()?;
        self.save_to(&path)
    }

    /// Save configuration to a specific path
    ///
    /// S-07 (F-8): 经 `fsutil::write_private` 落盘——Unix 0600 + 父目录 0700 +
    /// O_NOFOLLOW + 原子替换（config 含 challenge/token/GoDaddy 凭据，同机
    /// 低权限用户不可读）；父目录由 write_private 自动创建。
    ///
    /// `[tunnel]` token、`device.challenge_code`、`[dns.providers.*]` 敏感
    /// key）经 `secure.rs` 加密为 `{v: base64(nonce‖ciphertext)}` 再序列化——
    /// 落盘形态无明文；AAD 绑定配置段上下文。密钥环缺失（Linux 无桌面
    /// 密钥环且未设 KIRIN_CONFIG_KEY）→ fail-open 明文 + 醒目告警
    /// （`KeyProvider::load` 一次性输出，不阻断开发使用）。
    pub fn save_to(&self, path: &std::path::Path) -> Result<(), ConfigError> {
        // 且非空，且〔不可解析为 Config 或 敏感字段非空而本次内容全空〕→
        // 先把旧文件逐字节复制为 `<file>.bak-<UTC时间戳>` 再写；**备份失败 →
        // 拒绝写**（fail-closed：无法保全旧文件时不覆盖，绝不静默冲掉）。
        if let Some(bak) = self.destructive_backup_target(path)? {
            std::fs::copy(path, &bak).map_err(|e| ConfigError::IoError {
                path: bak.clone(),
                source: e,
            })?;
            tracing::warn!(
                "Config: 检测到破坏性覆写（旧文件含非空敏感字段而新内容为空 / 旧文件不可解析）——旧文件已备份 → {:?}，继续写入",
                bak
            );
        }
        let mut clone = self.clone();
        let provider = secure::key_provider_for(&Self::key_dir(path));
        encrypt_sensitive_fields(&mut clone, &provider)?;
        let content = toml::to_string_pretty(&clone)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;
        crate::fsutil::write_private(path, content.as_bytes())
            .map_err(|e| ConfigError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?;
        Ok(())
    }

    /// Get the default config directory path
    ///
    /// `dirs_next::config_dir()` 返回 None（平台无实现），由 Kotlin 侧在 App
    /// 启动时设为 `context.getFilesDir()`；桌面端未设置该变量，行为不变。
    pub fn config_dir() -> Result<PathBuf, ConfigError> {
        if let Ok(dir) = std::env::var("KIRIN_DATA_DIR") {
            if !dir.trim().is_empty() {
                return Ok(PathBuf::from(dir));
            }
        }
        let base = dirs_next::config_dir()
            .ok_or_else(|| ConfigError::NoHomeDir)?;
        Ok(base.join("kirin_desk"))
    }

    /// Get the default config file path
    fn default_path() -> Result<PathBuf, ConfigError> {
        Ok(Self::config_dir()?.join("default.toml"))
    }

    // ---------- : 白名单管理（SRV-SEC-WL-001..004） ----------

    /// 当前生效的白名单模式（过滤过期条目，兼容旧 `allowed_domains`）。
    /// 返回去重后的模式列表，供握手层匹配使用。
    pub fn whitelist_active_patterns(&self, now: DateTime<Utc>) -> Vec<String> {
        let mut patterns: Vec<String> = self.network.allowed_domains.clone();
        for entry in &self.network.whitelist {
            if entry.is_active(now) && !patterns.contains(&entry.pattern) {
                patterns.push(entry.pattern.clone());
            }
        }
        patterns
    }

    /// 域名是否在白名单内（过期条目自动失效，SRV-SEC-WL-003）。
    /// 旧 `allowed_domains` 沿用历史语义（相等或任意子域）；新 `whitelist`
    /// 条目用显式模式匹配（精确或 `*.example.com` 通配）。
    pub fn whitelist_check(&self, domain: &str) -> bool {
        if self
            .network
            .allowed_domains
            .iter()
            .any(|a| domain == a || domain.ends_with(&format!(".{}", a)))
        {
            return true;
        }
        self.network
            .whitelist
            .iter()
            .any(|e| e.is_active(Utc::now()) && whitelist_matches(domain, &e.pattern))
    }

    /// 新增白名单条目（按模式去重），返回是否新增成功，并立即保存。
    /// `expiry: None` 永久有效；`Some` 到期自动失效。
    pub fn whitelist_add(
        &mut self,
        pattern: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<bool, ConfigError> {
        let pattern = pattern.trim().to_string();
        if pattern.is_empty() {
            return Ok(false);
        }
        if let Some(entry) = self
            .network
            .whitelist
            .iter_mut()
            .find(|e| e.pattern == pattern)
        {
            // 已存在 → 只更新过期时间
            entry.expiry = expiry;
            self.save()?;
            return Ok(false);
        }
        self.network.whitelist.push(WhitelistEntry::new(&pattern, expiry));
        self.save()?;
        Ok(true)
    }

    /// 删除白名单条目，返回是否删除成功，并立即保存。
    pub fn whitelist_remove(&mut self, pattern: &str) -> Result<bool, ConfigError> {
        let before_wl = self.network.whitelist.len();
        self.network.whitelist.retain(|e| e.pattern != pattern);
        let before_ad = self.network.allowed_domains.len();
        self.network.allowed_domains.retain(|d| d != pattern);
        let removed = self.network.whitelist.len() != before_wl
            || self.network.allowed_domains.len() != before_ad;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// 从 CSV 导入白名单（SRV-SEC-WL-002 / CLI-IDWL-004）。
    ///
    /// 格式：每行 `pattern[,expiry]`，`expiry` 为 RFC3339（如 `2026-08-01T12:00:00Z`）
    /// 或留空表示永久；**`id:` 前缀行**（`id:device-1[,expiry]`）路由到设备 ID
    /// 白名单维度；空行与 `#` 注释行跳过；非法行跳过并计入未导入数。
    /// 返回成功导入的条目数，并立即保存。
    pub fn whitelist_import_csv(&mut self, path: &Path) -> Result<usize, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut imported = 0usize;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // (CLI-IDWL-004)：`id:` 前缀行 → ID 白名单维度。
            if let Some(rest) = line.strip_prefix("id:") {
                let mut parts = rest.split(',');
                let device_id = parts.next().unwrap_or("").trim();
                let expiry_str = parts.next().map(|s| s.trim()).unwrap_or("");
                if device_id.is_empty() {
                    continue;
                }
                let Some(expiry) = Self::parse_csv_expiry(expiry_str) else {
                    continue; // 非法时间戳 → 跳过该行
                };
                let _ = self.id_whitelist_add(device_id, expiry)?;
                imported += 1;
                continue;
            }
            let mut parts = line.split(',');
            let pattern = parts.next().unwrap_or("").trim();
            let expiry_str = parts.next().map(|s| s.trim()).unwrap_or("");
            if pattern.is_empty() {
                continue;
            }
            let Some(expiry) = Self::parse_csv_expiry(expiry_str) else {
                continue; // 非法时间戳 → 跳过该行
            };
            let _ = self.whitelist_add(pattern, expiry)?;
            imported += 1;
        }
        Ok(imported)
    }

    /// 解析 CSV 行中的过期时间（RFC3339；空 → `None` = 永久；非法 → `None`，
    /// 由调用方决定跳过该行）。
    fn parse_csv_expiry(expiry_str: &str) -> Option<Option<DateTime<Utc>>> {
        if expiry_str.is_empty() {
            return Some(None);
        }
        DateTime::parse_from_rfc3339(expiry_str)
            .ok()
            .map(|dt| Some(dt.with_timezone(&Utc)))
    }

    /// 导出白名单到 CSV（SRV-SEC-WL-002 / CLI-IDWL-004）：域名行保持原格式
    /// （向后兼容），ID 行带 `id:` 前缀（可与域名行共存、往返导入）。
    pub fn whitelist_export_csv(&self, path: &Path) -> Result<(), ConfigError> {
        let mut lines = String::from(
            "# pattern,expiry (RFC3339, empty = permanent); id:<device-id>[,expiry]\n",
        );
        for pattern in self.whitelist_active_patterns(Utc::now()) {
            let entry = self
                .network
                .whitelist
                .iter()
                .find(|e| e.pattern == pattern);
            let expiry = entry
                .and_then(|e| e.expiry)
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_default();
            lines.push_str(&format!("{},{}\n", pattern, expiry));
        }
        for device_id in self.id_whitelist_active_ids(Utc::now()) {
            let entry = self
                .network
                .id_whitelist
                .iter()
                .find(|e| e.device_id == device_id);
            let expiry = entry
                .and_then(|e| e.expiry)
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_default();
            lines.push_str(&format!("id:{},{}\n", device_id, expiry));
        }
        std::fs::write(path, lines).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// 导出白名单到 JSON（SRV-SEC-WL-002 / CLI-IDWL-004）：同时输出域名与
    /// ID 两维条目。
    pub fn whitelist_export_json(&self, path: &Path) -> Result<(), ConfigError> {
        let content = serde_json::json!({
            "domains": self.network.whitelist,
            "id_whitelist": self.network.id_whitelist,
            "id_whitelist_enforce": self.network.id_whitelist_enforce,
        });
        let text = serde_json::to_string_pretty(&content)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;
        std::fs::write(path, text).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// 物理清除过期条目，返回清除数量（匹配时过期条目已被跳过，此方法用于清理）。
    pub fn whitelist_prune_expired(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.network.whitelist.len();
        self.network
            .whitelist
            .retain(|e| e.is_active(now));
        before - self.network.whitelist.len()
    }

    // ---------- : 设备 ID 白名单（SRV-IDWL-001..008） ----------

    /// Settings 白名单页写入；调用方负责 `save()` 落盘）。
    pub fn set_id_whitelist_enforce(&mut self, enforce: bool) {
        self.network.id_whitelist_enforce = enforce;
    }

    /// 当前生效的设备 ID 白名单（合并 `allowed_ids` 永久条目 + 未过期
    /// `id_whitelist` 条目，去重返回，供握手层精确匹配）。
    pub fn id_whitelist_active_ids(&self, now: DateTime<Utc>) -> Vec<String> {
        let mut ids: Vec<String> = self.network.allowed_ids.clone();
        for entry in &self.network.id_whitelist {
            if entry.is_active(now) && !ids.contains(&entry.device_id) {
                ids.push(entry.device_id.clone());
            }
        }
        ids
    }

    /// 设备 ID 是否在 ID 白名单内（`allowed_ids` 或未过期 `id_whitelist`
    /// 任一维度精确命中，SRV-IDWL-005；过期条目自动失效）。
    pub fn id_whitelist_check(&self, device_id: &str) -> bool {
        let device_id = device_id.trim();
        if self.network.allowed_ids.iter().any(|id| id == device_id) {
            return true;
        }
        self.network
            .id_whitelist
            .iter()
            .any(|e| e.device_id == device_id && e.is_active(Utc::now()))
    }

    /// 新增 ID 白名单条目（按设备 ID 去重；已存在只更新过期时间），返回
    /// 是否新增成功，并立即保存（SRV-IDWL-006）。`expiry: None` 永久有效；
    /// 永久条目已存在于 `allowed_ids` 时不再重复登记（返回 false）。
    pub fn id_whitelist_add(
        &mut self,
        device_id: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<bool, ConfigError> {
        let device_id = device_id.trim().to_string();
        if device_id.is_empty() {
            return Ok(false);
        }
        if let Some(entry) = self
            .network
            .id_whitelist
            .iter_mut()
            .find(|e| e.device_id == device_id)
        {
            // 已存在 → 只更新过期时间
            entry.expiry = expiry;
            self.save()?;
            return Ok(false);
        }
        if expiry.is_none() && self.network.allowed_ids.contains(&device_id) {
            // 永久条目已登记于 allowed_ids → 无变化
            return Ok(false);
        }
        self.network
            .id_whitelist
            .push(IdWhitelistEntry::new(&device_id, expiry));
        self.save()?;
        Ok(true)
    }

    /// 删除 ID 白名单条目（**同时清理** `allowed_ids` 与 `id_whitelist`，
    /// CLI-IDWL-002），返回是否删除成功，并立即保存。
    pub fn id_whitelist_remove(&mut self, device_id: &str) -> Result<bool, ConfigError> {
        let before_wl = self.network.id_whitelist.len();
        self.network.id_whitelist.retain(|e| e.device_id != device_id);
        let before_ai = self.network.allowed_ids.len();
        self.network.allowed_ids.retain(|id| id != device_id);
        let removed = self.network.id_whitelist.len() != before_wl
            || self.network.allowed_ids.len() != before_ai;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// 从 CSV 导入 ID 白名单（SRV-IDWL-007）。
    ///
    /// 格式：每行 `id:<device-id>[,expiry]`，`expiry` 为 RFC3339 或留空表示
    /// 永久；空行与 `#` 注释行跳过；非 `id:` 前缀行与非法行跳过。返回成功
    /// 导入的条目数，并立即保存。
    pub fn id_whitelist_import_csv(&mut self, path: &Path) -> Result<usize, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut imported = 0usize;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some(rest) = line.strip_prefix("id:") else {
                continue;
            };
            let mut parts = rest.split(',');
            let device_id = parts.next().unwrap_or("").trim();
            let expiry_str = parts.next().map(|s| s.trim()).unwrap_or("");
            if device_id.is_empty() {
                continue;
            }
            let Some(expiry) = Self::parse_csv_expiry(expiry_str) else {
                continue; // 非法时间戳 → 跳过该行
            };
            let _ = self.id_whitelist_add(device_id, expiry)?;
            imported += 1;
        }
        Ok(imported)
    }

    /// 导出 ID 白名单到 CSV（SRV-IDWL-007）：每行 `id:<device-id>,expiry`。
    pub fn id_whitelist_export_csv(&self, path: &Path) -> Result<(), ConfigError> {
        let mut lines = String::from("# id:<device-id>,expiry (RFC3339, empty = permanent)\n");
        for device_id in self.id_whitelist_active_ids(Utc::now()) {
            let entry = self
                .network
                .id_whitelist
                .iter()
                .find(|e| e.device_id == device_id);
            let expiry = entry
                .and_then(|e| e.expiry)
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_default();
            lines.push_str(&format!("id:{},{}\n", device_id, expiry));
        }
        std::fs::write(path, lines).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// 导出 ID 白名单到 JSON（SRV-IDWL-007）。
    pub fn id_whitelist_export_json(&self, path: &Path) -> Result<(), ConfigError> {
        let content = serde_json::to_string_pretty(&self.network.id_whitelist)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;
        std::fs::write(path, content).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// 物理清除过期 ID 白名单条目，返回清除数量（匹配时过期条目已被跳过，
    /// 此方法用于清理；IDWL-SEC-005）。
    pub fn id_whitelist_prune_expired(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.network.id_whitelist.len();
        self.network
            .id_whitelist
            .retain(|e| e.is_active(now));
        before - self.network.id_whitelist.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error at {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to parse config at {path}: {detail}")]
    ParseError {
        path: PathBuf,
        detail: String,
        /// 「文件路径 + 出错键名」可视化（`ui::config_invalid_banner_text`）；
        /// `None` = 不可提取（错误落在段头行/无 `=`/无位置信息）。
        /// 不参与 `Display`（既有 WARN/错误文案格式零变化）。
        key_hint: Option<String>,
    },
    #[error("Serialization error: {0}")]
    SerializeError(String),
    #[error("No home/config directory found")]
    NoHomeDir,
    /// （fail-closed，不写可能泄露的明文）。
    #[error("配置敏感字段加密失败（{field}）：{reason}")]
    Encrypt { field: String, reason: String },
    /// 变更/丢失——重装系统、更换用户或修改 KIRIN_CONFIG_KEY——或密文被篡改）。
    /// fail-closed：拒绝加载，避免把密文当凭据使用。
    #[error(
        "配置敏感字段解密失败（{field}）：{reason}——主密钥可能已变更/丢失 \
         （重装系统、更换 Windows 用户或修改 KIRIN_CONFIG_KEY），或密文被篡改"
    )]
    Decrypt { field: String, reason: String },
}

impl ConfigError {
    ///
    /// GUI 首启兜底判定用：仅 `IoError` 且 `source.kind() == NotFound` 为
    /// `true`（解析失败/解密失败/权限错误等均 `false`——那些场景绝不创建
    /// 默认文件覆盖式救场，保持 fail-closed）。
    pub fn is_not_found(&self) -> bool {
        match self {
            ConfigError::IoError { source, .. } => {
                source.kind() == std::io::ErrorKind::NotFound
            }
            _ => false,
        }
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// `[dns.providers.*]` 段中入加密域的字段 key。
///
/// 依据：`dns_providers.rs` 注册表 `secret: true` 的字段 key 全量 + 审计点名的
/// GoDaddy `api_key`/`api_secret`（旧 `[godaddy]` 段两字段均入加密域，
/// 见 `功能审计报告_2026-08-03.md` §2-P2-9）。非敏感 key（domain、region、
/// access_key_id 等标识性字段）保持明文。drift 由
/// `test_sensitive_key_list_covers_registry_secret_fields` 守护。
const SENSITIVE_DNS_FIELD_KEYS: &[&str] = &[
    "api_key",
    "api_secret",
    "api_token",
    "token",
    "secret_key",
    "secret_access_key",
    "access_key_secret",
    "client_secret",
    "app_secret",
    "consumer_key",
    "api_password",
    "domain_key",
    "service_account_json",
];

/// 是否 `[dns.providers.*]` 段的敏感字段 key（入加密域）。
fn is_sensitive_dns_field(key: &str) -> bool {
    SENSITIVE_DNS_FIELD_KEYS.contains(&key)
}

/// 敏感字段 AAD 上下文（配置段点分路径，如 `godaddy.api_key`、
/// `dns.providers.cloudflare.api_token`）——防止密文跨字段/跨段替换。
fn field_context(section: &str, key: &str) -> String {
    format!("{section}.{key}")
}

/// 密钥来源解析时的醒目警告即「按设计告警可用」路径）。
fn encrypt_sensitive_fields(
    cfg: &mut Config,
    provider: &secure::KeyProvider,
) -> Result<(), ConfigError> {
    let encrypt = |value: &str, ctx: &str| -> Result<String, ConfigError> {
        secure::encrypt_with_provider(provider, value, ctx).map_err(|e| ConfigError::Encrypt {
            field: ctx.to_string(),
            reason: e.to_string(),
        })
    };
    cfg.godaddy.api_key = encrypt(&cfg.godaddy.api_key, &field_context("godaddy", "api_key"))?;
    cfg.godaddy.api_secret =
        encrypt(&cfg.godaddy.api_secret, &field_context("godaddy", "api_secret"))?;
    cfg.tunnel.token = encrypt(&cfg.tunnel.token, &field_context("tunnel", "token"))?;
    cfg.device.challenge_code =
        encrypt(&cfg.device.challenge_code, &field_context("device", "challenge_code"))?;
    //（name 唯一且非空，见 `node_add` 派生口径——节点改名/增删不使既有密文
    // 失配：每条目 AAD 只依赖自身 name，与列表顺序/其它条目无关）。
    for node in cfg.nodes.iter_mut() {
        node.token = encrypt(&node.token, &field_context(&format!("nodes.{}", node.name), "token"))?;
    }
    for (name, fields) in cfg.dns.providers.iter_mut() {
        for (k, v) in fields.iter_mut() {
            if is_sensitive_dns_field(k) {
                *v = encrypt(v, &field_context(&format!("dns.providers.{name}"), k))?;
            }
        }
    }
    Ok(())
}

///
/// 返回 `true` = 发现非空明文敏感字段（旧明文配置，迁移加密重写候选）。
/// 密文解密失败（密钥缺失/错误/篡改）→ [`ConfigError::Decrypt`]（fail-closed，
/// 拒绝加载——避免把密文当凭据使用）。
///
/// 惰性密钥解析：文件内无任何密文字段时**不**触碰密钥环/DPAPI blob
/// （`config/default.toml` 模板与全新配置加载不产生主密钥 blob 副作用）。
fn decrypt_sensitive_fields(cfg: &mut Config, key_dir: &Path) -> Result<bool, ConfigError> {
    let map_has_ciphertext = |cfg: &Config| {
        cfg.dns.providers.values().any(|fields| {
            fields
                .iter()
                .any(|(k, v)| is_sensitive_dns_field(k) && secure::looks_encrypted(v))
        })
    };
    let has_ciphertext = secure::looks_encrypted(&cfg.godaddy.api_key)
        || secure::looks_encrypted(&cfg.godaddy.api_secret)
        || secure::looks_encrypted(&cfg.tunnel.token)
        || secure::looks_encrypted(&cfg.device.challenge_code)
        || cfg.nodes.iter().any(|n| secure::looks_encrypted(&n.token))
        || map_has_ciphertext(cfg);
    let provider = has_ciphertext.then(|| secure::key_provider_for(key_dir));

    let mut plaintext_detected = false;
    let mut decrypt_one =
        |value: &mut String, ctx: &str, has_provider: bool| -> Result<(), ConfigError> {
            if secure::looks_encrypted(value) {
                // 有密文必有 provider（has_ciphertext 扫描保证）。
                let p = provider.as_deref().expect("has_ciphertext ⇒ provider resolved");
                let pt = secure::decrypt_field(p, value, ctx).map_err(|e| {
                    ConfigError::Decrypt {
                        field: ctx.to_string(),
                        reason: e.to_string(),
                    }
                })?;
                *value = pt;
            } else if has_provider && !value.is_empty() {
                // 旧明文非空 → 迁移候选（空明文不迁移：模板/新配置不产生
                // 无谓重写，见任务文档 R13-S2 定稿）。
                plaintext_detected = true;
            }
            Ok(())
        };

    decrypt_one(&mut cfg.godaddy.api_key, &field_context("godaddy", "api_key"), provider.is_some())?;
    decrypt_one(
        &mut cfg.godaddy.api_secret,
        &field_context("godaddy", "api_secret"),
        provider.is_some(),
    )?;
    decrypt_one(&mut cfg.tunnel.token, &field_context("tunnel", "token"), provider.is_some())?;
    decrypt_one(
        &mut cfg.device.challenge_code,
        &field_context("device", "challenge_code"),
        provider.is_some(),
    )?;
    for node in cfg.nodes.iter_mut() {
        decrypt_one(
            &mut node.token,
            &field_context(&format!("nodes.{}", node.name), "token"),
            provider.is_some(),
        )?;
    }
    for (name, fields) in cfg.dns.providers.iter_mut() {
        for (k, v) in fields.iter_mut() {
            if is_sensitive_dns_field(k) {
                decrypt_one(v, &field_context(&format!("dns.providers.{name}"), k), provider.is_some())?;
            }
        }
    }
    Ok(plaintext_detected)
}

impl Config {
    /// 无父目录 → 回退配置目录/临时目录）。
    fn key_dir(path: &Path) -> PathBuf {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| Self::config_dir().unwrap_or_else(|_| std::env::temp_dir()))
    }

    ///
    /// 返回 `Some(备份路径)` = 覆写前必须先备份旧文件；`None` = 可直接写。
    /// 触发条件（任一）：
    /// 1. **损坏件保护**：目标文件存在且非空，但**不可解析**为 Config（损坏/
    ///    篡改/格式漂移）——无法对账旧内容，宁可多备份不可静默冲掉；
    ///    非空**（token/nickname/device.id/challenge_code/api_key/api_secret/
    ///    节点与 DNS provider 凭据），而**本次写入内容这些字段全空**（默认值
    ///    整份形态——测试/脚本以 `Config::default()` 覆盖用户配置的特征）。
    ///
    /// 不触发的正常路径：目标不存在/为空（首启创建）；新旧敏感字段均非空
    /// （正常保存/加密迁移/ID 短码回写——`load_from` 写回的是刚加载的完整
    /// 内容，敏感字段同值非空）。备份动作本身永不破坏数据（只增 `.bak` 文件），
    /// 误触发（如用户主动清空 token 后保存）= 多一个备份件，无副作用。
    fn destructive_backup_target(&self, path: &Path) -> Result<Option<PathBuf>, ConfigError> {
        // 不存在/目录/空文件 → 无旧内容可保全（首启创建路径）。
        match std::fs::metadata(path) {
            Ok(m) if m.is_file() && m.len() > 0 => {}
            _ => return Ok(None),
        }
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        // 纯 TOML 解析（**不经** `load_from`——避免触发其解密/派生/写回副作用，
        // 且写回会递归进入本判定）；敏感字段按磁盘形态（明文或 `{v:...}` 密文）
        // 直接判定非空，无需密钥。
        let old: Config = match toml::from_str(&content) {
            Ok(c) => c,
            Err(_) => return Ok(Some(Self::backup_path_for(path))),
        };
        if sensitive_fields_nonempty(&old) && !sensitive_fields_nonempty(self) {
            Ok(Some(Self::backup_path_for(path)))
        } else {
            Ok(None)
        }
    }

    /// `default.toml.bak-20260906T050000Z`），与原文件同目录。
    fn backup_path_for(path: &Path) -> PathBuf {
        let ts = Utc::now().format("%Y%m%dT%H%M%SZ");
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config".to_string());
        path.with_file_name(format!("{file_name}.bak-{ts}"))
    }
}

///
/// 明文：trim 后非空。密文 `{v: base64(nonce‖ct+tag)}`：解码 blob 长度 >
/// `NONCE(12) + TAG(16) = 28` 字节 ⇔ 载有实际明文（空明文加密恰为 28 字节——
/// 事故物证「token 加密空串」形态正确判空，不误触发备份）；解码失败按非空
/// 保守处理（异常内容不静默覆盖）。
fn sensitive_disk_value_nonempty(v: &str) -> bool {
    let v = v.trim();
    if v.is_empty() {
        return false;
    }
    if secure::looks_encrypted(v) {
        // 密文形态同式：`{v:` + STANDARD base64 + `}`（`secure::looks_encrypted`）。
        let body = v
            .strip_prefix("{v:")
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or("");
        match base64::engine::general_purpose::STANDARD.decode(body) {
            Ok(bytes) => bytes.len() > 28,
            Err(_) => true,
        }
    } else {
        true
    }
}

///
/// nickname / challenge_code、`[tunnel]` token、`[godaddy]` api_key/
/// api_secret、`[nodes]` 各条目 token、`[dns.providers.*]` 敏感 key 字段。
/// 内存明文态与磁盘密文态均适用（密文经 [`sensitive_disk_value_nonempty`]）。
fn sensitive_fields_nonempty(cfg: &Config) -> bool {
    if !crate::device::id_is_auto(&cfg.device.id) {
        return true;
    }
    if !cfg.device.nickname.trim().is_empty() {
        return true;
    }
    if sensitive_disk_value_nonempty(&cfg.device.challenge_code) {
        return true;
    }
    if sensitive_disk_value_nonempty(&cfg.tunnel.token) {
        return true;
    }
    if sensitive_disk_value_nonempty(&cfg.godaddy.api_key) {
        return true;
    }
    if sensitive_disk_value_nonempty(&cfg.godaddy.api_secret) {
        return true;
    }
    if cfg.nodes.iter().any(|n| sensitive_disk_value_nonempty(&n.token)) {
        return true;
    }
    cfg.dns
        .providers
        .values()
        .any(|fields| {
            fields
                .iter()
                .any(|(k, v)| is_sensitive_dns_field(k) && sensitive_disk_value_nonempty(v))
        })
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

impl Config {
    /// 节点列表只读引用。
    pub fn nodes_list(&self) -> &[NodeConfig] {
        &self.nodes
    }

    /// 按名取节点。
    pub fn node_get(&self, name: &str) -> Option<&NodeConfig> {
        self.nodes.iter().find(|n| n.name == name)
    }

    /// 加入节点（返回实际落存的条目——`name` 为空时已填入自动派生名）。
    ///
    /// 归一：name/server_addr/token/server_pubkey 全部 `trim`（粘贴通道常带
    /// 首尾空白）。去重口径（fail-closed，两重）：
    /// - **name 唯一**——空 name 自动派生 `node-{host}[-N]`（host 取
    ///   server_addr 的 host 段；冲突递增后缀，保证不撞既有名）；非空 name
    ///   已存在 → [`NodeAddError::NameExists`]（不改名不覆盖）；
    /// - **三件套去重**——server_addr+token+server_pubkey 与既有条目完全一致
    ///   → [`NodeAddError::TripleExists`]（重复导入跳过；同服务器不同 token
    ///   属不同凭据，允许共存）。
    ///
    /// `dir_store::MAX_DEVICE_DIR_ENTRIES` 同值）——`nodes.len() >= 上限`
    /// 时拒新增 → [`NodeAddError::LimitExceeded`]（**只拦新增不清存量**：
    /// 已存量超 15 的配置不回删；去重错误优先于上限错误报告——重复添加
    /// 撞名/撞三件套时用户看到的是更具体的去重原因）。上限判定放在
    /// 去重之后：既有条目重复添加（撞三件套）在任何存量规模下都应报
    /// TripleExists 而非 LimitExceeded。
    pub fn node_add(&mut self, mut node: NodeConfig) -> Result<NodeConfig, NodeAddError> {
        node.name = node.name.trim().to_string();
        node.server_addr = node.server_addr.trim().to_string();
        node.token = node.token.trim().to_string();
        node.server_pubkey = node.server_pubkey.trim().to_string();
        if node.name.is_empty() {
            node.name = self.node_auto_name(&node.server_addr);
        }
        if self.nodes.iter().any(|n| n.name == node.name) {
            return Err(NodeAddError::NameExists(node.name.clone()));
        }
        let triple_hit = self
            .nodes
            .iter()
            .find(|n| {
                n.server_addr == node.server_addr
                    && n.token == node.token
                    && n.server_pubkey == node.server_pubkey
            })
            .map(|n| n.name.clone());
        if let Some(existing) = triple_hit {
            return Err(NodeAddError::TripleExists(existing));
        }
        if self.nodes.len() >= NODES_MAX_ENTRIES {
            return Err(NodeAddError::LimitExceeded {
                limit: NODES_MAX_ENTRIES,
            });
        }
        let stored = node.clone();
        self.nodes.push(node);
        Ok(stored)
    }

    /// 删除节点（按名）。返回被删条目；未命中 `None`。
    pub fn node_remove(&mut self, name: &str) -> Option<NodeConfig> {
        let pos = self.nodes.iter().position(|n| n.name == name)?;
        Some(self.nodes.remove(pos))
    }

    /// 按名更新节点三件套/note（返回更新后的条目）。
    ///
    /// name 变更语义：`new.name` 为空 → 保留原名（不允许静默改派生名）；
    /// 非空且与原名不同 → 校验不与其它条目撞名（撞 → [`NodeAddError::NameExists`]）。
    /// 三件套变更 → 撞既有条目 → [`NodeAddError::TripleExists`]。
    pub fn node_update(&mut self, name: &str, mut new: NodeConfig) -> Result<NodeConfig, NodeAddError> {
        let pos = self
            .nodes
            .iter()
            .position(|n| n.name == name)
            .ok_or_else(|| NodeAddError::NotFound(name.to_string()))?;
        new.name = new.name.trim().to_string();
        new.server_addr = new.server_addr.trim().to_string();
        new.token = new.token.trim().to_string();
        new.server_pubkey = new.server_pubkey.trim().to_string();
        if new.name.is_empty() {
            new.name = name.to_string();
        }
        if new.name != name && self.nodes.iter().any(|n| n.name == new.name) {
            return Err(NodeAddError::NameExists(new.name.clone()));
        }
        let triple_hit = self.nodes.iter().enumerate().find(|(i, n)| {
            *i != pos
                && n.server_addr == new.server_addr
                && n.token == new.token
                && n.server_pubkey == new.server_pubkey
        });
        if let Some((_, n)) = triple_hit {
            return Err(NodeAddError::TripleExists(n.name.clone()));
        }
        let stored = new.clone();
        self.nodes[pos] = new;
        Ok(stored)
    }

    /// 空 name 自动派生：`node-{host}`（host = server_addr 的 host 段，
    /// 去括号/端口）；冲突时递增 `-2`/`-3`… 直至唯一（纯函数，无 IO）。
    fn node_auto_name(&self, server_addr: &str) -> String {
        let host = server_addr
            .strip_prefix('[')
            .map(|s| s.split(']').next().unwrap_or(s))
            .unwrap_or_else(|| server_addr.split(':').next().unwrap_or(server_addr));
        let host = host.trim();
        let base = if host.is_empty() {
            "node".to_string()
        } else {
            format!("node-{host}")
        };
        if !self.nodes.iter().any(|n| n.name == base) {
            return base;
        }
        let mut i = 2u32;
        loop {
            let cand = format!("{base}-{i}");
            if !self.nodes.iter().any(|n| n.name == cand) {
                return cand;
            }
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;


    /// 全局状态，加锁避免与其它读写 `KIRIN_DATA_DIR` 的测试并发互相污染。
    /// utils/src/lib.rs）——logging 模块 default_log_dir 单测同读写该 env，
    /// 须与这里的 env 覆盖测试互斥。
    use crate::KIRIN_DATA_DIR_LOCK;

    /// `remove_var` 抽干）——全量门禁经命令行恒带该隔离目录 env；抽干会使同进程
    /// 回落真实 `~/.kirin_desk/logs/`（历波哨兵例外的残留源）。
    fn restore_config_dir_env(original: Option<std::ffi::OsString>) {
        match original {
            Some(v) => std::env::set_var("KIRIN_DATA_DIR", v),
            None => std::env::remove_var("KIRIN_DATA_DIR"),
        }
    }

    #[test]
    fn test_config_dir_env_override_takes_priority() {
        let _guard = KIRIN_DATA_DIR_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join("kirin_t04_env_override");
        std::fs::create_dir_all(&dir).ok();
        std::env::set_var("KIRIN_DATA_DIR", &dir);
        let got = Config::config_dir().expect("env 覆盖下 config_dir 应成功");
        // 确保后续测试不受污染——先断言再清理。
        let assert_ok = got == dir;
        assert!(assert_ok, "KIRIN_DATA_DIR 应最高优先级直接生效: {got:?} != {dir:?}");
    }

    #[test]
    fn test_config_dir_env_blank_falls_back_to_platform_default() {
        let _guard = KIRIN_DATA_DIR_LOCK.lock().unwrap();
        std::env::set_var("KIRIN_DATA_DIR", "   ");
        let got = Config::config_dir().expect("空白值应回退平台默认路径而非报错");
        // 桌面（Windows/Linux/macOS）平台默认路径不应等于我们设过的空白值。
        assert_ne!(got, PathBuf::from("   "));
        assert!(
            got.ends_with("kirin_desk") || got.to_string_lossy().contains("kirin_desk"),
            "未设/空白 env 时应走 dirs_next 原路径: {got:?}"
        );
    }


    /// 使隐式 `save()`（`whitelist_add`/`id_whitelist_add` 等**即调即存** API
    /// 内部调用）落在隔离目录而非用户真实 `%APPDATA%\kirin_desk\default.toml`
    ///
    /// 每测试独立目录（并发测试不互相踩踏）；返回 `(Config, 隔离目录路径)`，
    /// 调用方随测试收尾清理目录即可。
    fn r82a_sandboxed_config(test_name: &str) -> (Config, PathBuf) {
        let dir = std::env::temp_dir().join(format!("kirin_desk_r82a_{test_name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut cfg = Config::default();
        cfg.save_override = Some(path.clone());
        (cfg, path)
    }


    /// .download_dir` 字段（零新字段）——往返：显式值 save → load 恒等；
    /// 缺省 None → `resolved_download_dir` 回退默认口径（系统下载文件夹 /
    /// KirinDesk 子目录）；空白值亦回退（不产生「空串目录」）。
    #[test]
    fn r141_2_download_dir_roundtrip_and_fallback() {
        // ① 显式值往返恒等。
        let (mut cfg, path) = r82a_sandboxed_config("r141_2_ftdir");
        let dir = "D:\\recv\\kirin_r141_2";
        cfg.file_transfer.download_dir = Some(dir.to_string());
        cfg.save_to(&path).expect("隔离目录保存");
        let loaded = Config::load_from(&path).expect("隔离目录加载");
        assert_eq!(
            loaded.file_transfer.download_dir.as_deref(),
            Some(dir),
            "显式 download_dir 读写往返恒等"
        );
        assert_eq!(
            loaded.file_transfer.resolved_download_dir(),
            PathBuf::from(dir),
            "显式值 = 回退链第一优先级"
        );
        // ② 缺省 None = 默认口径（系统下载文件夹 / KirinDesk 子目录）。
        let (cfg2, _p2) = r82a_sandboxed_config("r141_2_ftdir_default");
        assert!(cfg2.file_transfer.download_dir.is_none(), "默认配置无显式值");
        let resolved = cfg2.file_transfer.resolved_download_dir();
        assert!(
            resolved.ends_with("KirinDesk"),
            "缺省回退 = 下载文件夹 / KirinDesk 子目录: {resolved:?}"
        );
        // ③ 空白显式值 = 回退默认（不产生空串目录）。
        let (mut cfg3, _p3) = r82a_sandboxed_config("r141_2_ftdir_blank");
        cfg3.file_transfer.download_dir = Some("   ".to_string());
        assert!(
            cfg3.file_transfer.resolved_download_dir().ends_with("KirinDesk"),
            "空白值回退默认口径"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }


    /// 临时配置落盘（经 `Config::default()` 序列化保证 TOML 段完整）并加载。
    fn r76c_load_with_device_id(dir_name: &str, id: &str) -> (Config, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("kirin_desk_r76c_{dir_name}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut cfg = Config::default();
        cfg.device.id = id.to_string();
        cfg.save_to(&path).expect("临时配置保存");
        let loaded = Config::load_from(&path).expect("配置加载");
        (loaded, path)
    }

    /// 稳定性（二次加载走显式值路径，值不变）。
    #[test]
    fn r76c_empty_device_id_derives_short_code_and_persists() {
        let (cfg, path) = r76c_load_with_device_id("empty", "");
        let id = cfg.device.id.clone();
        assert!(!id.is_empty(), "派生后 device.id 非空");
        assert!(!crate::device::id_is_auto(&id), "派生值不得仍处未填写态");
        // 字符集 / 字母数字混合 / 非全 hex（防短码 guard）/ 无 HD- 前缀
        // （旧格式断言废弃；旧格式不迁移见 `r86i_legacy_device_id_not_migrated`）。
        assert_eq!(id.len(), 10, "新格式固定 10 位, got {id}");
        assert!(
            id.bytes().all(|b| crate::device::CROCKFORD_B32.contains(&b)),
            "非 Crockford base32 字符集: {id}"
        );
        assert!(crate::device::device_id_v2_shape_ok(&id), "防短码 guard: {id}");
        // 持久化回写：落盘文件包含派生 ID。
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.contains(&id),
            "落盘配置应包含派生 ID {id}:\n{on_disk}"
        );
        // 稳定性：同输入同输出——二次加载直接读持久化值。
        let cfg2 = Config::load_from(&path).expect("二次加载");
        assert_eq!(cfg2.device.id, id, "二次加载应直接复用持久化派生 ID");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// 或自定义 `[device] id` 加载后**原样保留**——不重新派生、不迁移新格式
    /// （旧 ID 仍合法；仅空配置/未填写走新格式）。
    #[test]
    fn r86i_legacy_device_id_not_migrated() {
        for (name, legacy) in [
            ("hd", "HD-62EC5BC9"),
            ("machine", "MACHINE-0000000089abcdef0000000089abcdef"),
            ("mac", "MAC-00000000-89AB-CDEF-0123-456789ABCDEF01"),
            ("custom", "my-pc"),
        ] {
            let (cfg, path) = r76c_load_with_device_id(name, legacy);
            assert_eq!(cfg.device.id, legacy, "旧 ID 须原样保留不迁移: {legacy}");
            let on_disk = std::fs::read_to_string(&path).unwrap();
            assert!(on_disk.contains(legacy), "落盘旧 ID 须未被改写: {legacy}");
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
        }
    }

    #[test]
    fn r76c_default_device_placeholder_derives_same_as_empty() {
        let (cfg_ph, path_ph) = r76c_load_with_device_id("placeholder", "default-device");
        let (cfg_empty, path_empty) = r76c_load_with_device_id("placeholder_empty", "");
        assert_eq!(
            cfg_ph.device.id, cfg_empty.device.id,
            "default-device 与空串应派生同一短码"
        );
        let _ = std::fs::remove_dir_all(path_ph.parent().unwrap());
        let _ = std::fs::remove_dir_all(path_empty.parent().unwrap());
    }

    #[test]
    fn r76c_explicit_device_id_preserved() {
        let (cfg, path) = r76c_load_with_device_id("explicit", "my-pc");
        assert_eq!(cfg.device.id, "my-pc");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("my-pc"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_config_fingerprint_stable_and_change_sensitive() {
        let a = Config::default();
        let b = a.clone();
        assert_eq!(config_fingerprint(&a), config_fingerprint(&b), "相同配置指纹一致");

        let mut c = a.clone();
        c.network.port = 60000;
        assert_ne!(config_fingerprint(&a), config_fingerprint(&c), "端口变化 → 指纹变化");

        let mut d = a.clone();
        d.logging.level = "debug".to_string();
        assert_ne!(config_fingerprint(&a), config_fingerprint(&d), "日志级别变化 → 指纹变化");
    }

    #[test]
    fn test_should_log_config_load_gating() {
        let slot = Mutex::new(None::<u64>);
        // 首次加载 → 打日志
        assert!(should_log_config_load_in(&slot, 100));
        // 相同指纹（稳定运行）→ 静默
        assert!(!should_log_config_load_in(&slot, 100));
        assert!(!should_log_config_load_in(&slot, 100));
        // 配置实际变化 → 再打
        assert!(should_log_config_load_in(&slot, 200));
        // 变回原指纹 → 视为又一次变化
        assert!(should_log_config_load_in(&slot, 100));
    }

    #[test]
    fn test_should_log_config_load_thread_safe() {
        // 8 线程并发同指纹首次调用：锁内「比较+更新」保证恰好一个返回 true，
        // 其余 false，状态收敛一致且不 panic。
        let slot = Mutex::new(None::<u64>);
        let results: Vec<bool> = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..8 {
                let slot = &slot;
                handles.push(scope.spawn(move || should_log_config_load_in(slot, 777)));
            }
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(results.iter().filter(|&&r| r).count(), 1, "并发首次应恰好一个 true");
        assert!(!should_log_config_load_in(&slot, 777), "收敛后同指纹静默");
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        // 默认留空 = 自动（系统硬盘 UUID）。
        assert!(config.device.id.is_empty());
        // 数据段 60000+ / 22/80/443；旧配置显式端口不受 serde default 影响）。
        assert_eq!(config.network.port, DEFAULT_NETWORK_PORT);
        assert_eq!(config.network.port, 59990);
        assert_eq!(config.godaddy.api_url, "https://api.godaddy.com");
    }

    /// 控制 7000、rendezvous 7001、relay 数据段 60000-61000、常见服务
    /// 22/80/443），且位于动态/私有区（49152-65535）内。
    #[test]
    fn test_default_network_port_non_conflicting() {
        let p = DEFAULT_NETWORK_PORT;
        assert_ne!(p, 3389, "不得与 Windows RDP 冲突");
        assert_ne!(p, 7000, "不得与 relay 控制端口冲突");
        assert_ne!(p, 7001, "不得与 rendezvous 端口冲突");
        assert!(!(60000..=61000).contains(&p), "不得落入 relay 数据段: {p}");
        assert!(p != 22 && p != 80 && p != 443, "不得与常见服务冲突: {p}");
        assert!((49152..=65535).contains(&p), "应在动态/私有区: {p}");
    }

    #[test]
    fn test_config_roundtrip() {
        let config = Config::default();
        let dir = std::env::temp_dir().join("kirin_desk_test_config");
        let path = dir.join("test.toml");

        config.save_to(&path).expect("save should succeed");
        let loaded = Config::load_from(&path).expect("load should succeed");

        // 同源单一事实来源）；重加载复用持久化值。
        let expected = crate::device::effective_device_id(&config.device.id);
        assert_eq!(loaded.device.id, expected, "空 device.id 应派生短码");
        assert!(!loaded.device.id.is_empty());
        let reloaded = Config::load_from(&path).expect("re-load should succeed");
        assert_eq!(reloaded.device.id, loaded.device.id, "重加载应复用持久化短码");
        assert_eq!(loaded.network.port, config.network.port);

        // Cleanup
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_config_load_nonexistent() {
        let path = std::env::temp_dir().join("kirin_desk_nonexistent.toml");
        let result = Config::load_from(&path);
        assert!(result.is_err());
    }

    // ---------- M9-DNS000 (§4.2): 旧 [godaddy] 配置迁移 ----------

    #[test]
    fn test_legacy_godaddy_migration() {
        let mut cfg = Config::default();
        cfg.godaddy.api_key = "legacy-key".to_string();
        cfg.godaddy.api_secret = "legacy-secret".to_string();
        cfg.godaddy.api_url = "https://api.godaddy.com".to_string();
        cfg.godaddy.domain = "example.com".to_string();
        // 迁移到 [dns.providers.godaddy]。
        assert!(cfg.migrate_legacy_godaddy());
        let godaddy = cfg.dns.providers.get("godaddy").expect("已迁移");
        assert_eq!(godaddy.get("api_key").map(String::as_str), Some("legacy-key"));
        assert_eq!(godaddy.get("api_secret").map(String::as_str), Some("legacy-secret"));
        assert_eq!(godaddy.get("api_url").map(String::as_str), Some("https://api.godaddy.com"));
        // domain 留在 [godaddy]（设备级域名，CLI 兼容读）。
        assert_eq!(cfg.godaddy.domain, "example.com");
        // 幂等：再次迁移不重复。
        assert!(!cfg.migrate_legacy_godaddy());
        // 新段已有 → 不覆盖。
        let mut cfg2 = Config::default();
        cfg2.godaddy.api_key = "x".to_string();
        cfg2.dns.providers.insert(
            "godaddy".to_string(),
            [("api_key".to_string(), "new-key".to_string())].into_iter().collect(),
        );
        assert!(!cfg2.migrate_legacy_godaddy());
        assert_eq!(
            cfg2.dns.providers["godaddy"].get("api_key").map(String::as_str),
            Some("new-key")
        );
        // 旧段无凭据 → 不迁移。
        let mut cfg3 = Config::default();
        assert!(!cfg3.migrate_legacy_godaddy());
    }

    #[test]
    fn test_dns_provider_credentials_helpers() {
        let mut cfg = Config::default();
        assert!(cfg.active_dns_provider_credentials().is_none());
        cfg.dns.provider = "cloudflare".to_string();
        cfg.dns.providers.insert(
            "cloudflare".to_string(),
            [("api_token".to_string(), "tok".to_string())].into_iter().collect(),
        );
        let creds = cfg.dns_provider_credentials("cloudflare").expect("存在");
        assert_eq!(creds.get("api_token").map(String::as_str), Some("tok"));
        assert_eq!(
            cfg.active_dns_provider_credentials()
                .unwrap()
                .get("api_token")
                .map(String::as_str),
            Some("tok")
        );
    }


    #[test]
    fn test_gpu_config_defaults() {
        // 默认值：auto + 过滤虚拟 + 空关键词（用默认黑名单表）。
        let config = Config::default();
        assert_eq!(config.media.gpu.prefer, "auto");
        assert!(config.media.gpu.filter_virtual);
        assert!(config.media.gpu.virtual_keywords.is_empty());
    }

    #[test]
    fn test_gpu_legacy_toml_missing_section() {
        let dir = std::env::temp_dir().join("kirin_desk_test_gpu");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.device.id, "old-device");
        assert_eq!(loaded.media.gpu.prefer, "auto");
        assert!(loaded.media.gpu.filter_virtual);
        assert!(loaded.media.gpu.virtual_keywords.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_gpu_config_roundtrip() {
        // 完整 [media.gpu] 段读写往返（含自定义关键词）。
        let mut config = Config::default();
        config.media.gpu.prefer = "nvidia".to_string();
        config.media.gpu.filter_virtual = false;
        config.media.gpu.virtual_keywords = vec!["sunlogin".to_string()];
        let dir = std::env::temp_dir().join("kirin_desk_test_config_gpu");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.toml");
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.media.gpu.prefer, "nvidia");
        assert!(!loaded.media.gpu.filter_virtual);
        assert_eq!(loaded.media.gpu.virtual_keywords, vec!["sunlogin"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- : 临时连接 TTL 配置测试 ----------

    #[test]
    fn test_temp_mode_ttl_default() {
        let config = Config::default();
        assert_eq!(config.network.temp_mode_ttl_secs, 300);
        assert_eq!(config.network.effective_temp_mode_ttl(), 300);
    }

    #[test]
    fn test_temp_mode_ttl_clamped_to_range() {
        let mut config = Config::default();
        config.network.temp_mode_ttl_secs = 10;
        assert_eq!(config.network.effective_temp_mode_ttl(), 60);
        config.network.temp_mode_ttl_secs = 7200;
        assert_eq!(config.network.effective_temp_mode_ttl(), 3600);
        config.network.temp_mode_ttl_secs = 600;
        assert_eq!(config.network.effective_temp_mode_ttl(), 600);
    }


    #[test]
    fn test_r78a_approval_timeout_default() {
        let config = Config::default();
        assert_eq!(config.network.approval_timeout_secs, APPROVAL_TIMEOUT_DEFAULT);
        assert_eq!(config.network.effective_approval_timeout_secs(), 60);
    }

    #[test]
    fn test_r78a_approval_timeout_clamped_to_range() {
        let mut config = Config::default();
        // 越界收敛（fail-closed：永不收敛到 0/无限等待）。
        config.network.approval_timeout_secs = 0;
        assert_eq!(config.network.effective_approval_timeout_secs(), APPROVAL_TIMEOUT_MIN);
        config.network.approval_timeout_secs = 999_999;
        assert_eq!(config.network.effective_approval_timeout_secs(), APPROVAL_TIMEOUT_MAX);
        // 范围内原样生效。
        config.network.approval_timeout_secs = 120;
        assert_eq!(config.network.effective_approval_timeout_secs(), 120);
    }

    // ---------- : 无人值守配置测试 ----------

    #[test]
    fn test_unattended_defaults() {
        // 三开关默认全关（含「默认受控」= auto_start_server）。
        let config = Config::default();
        assert!(!config.unattended.enabled);
        assert!(!config.unattended.auto_start_on_boot);
        assert!(!config.unattended.auto_start_server);
    }

    #[test]
    fn test_unattended_legacy_toml_missing_section() {
        // 旧配置文件无 [unattended] 段 → 加载不失败，使用默认值
        let dir = std::env::temp_dir().join("kirin_desk_test_unattended");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.device.id, "old-device");
        assert!(!loaded.unattended.enabled);
        assert!(!loaded.unattended.auto_start_server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_unattended_roundtrip() {
        let mut config = Config::default();
        config.unattended.enabled = true;
        config.unattended.auto_start_on_boot = true;
        let dir = std::env::temp_dir().join("kirin_desk_test_config_unattended");
        let path = dir.join("test.toml");
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.unattended.enabled);
        assert!(loaded.unattended.auto_start_on_boot);
        // auto_start_server 未显式设置 → 默认 false（三开关默认全关）。
        assert!(!loaded.unattended.auto_start_server);
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn r89e_input_alt_f4_forward_default_true() {
        // PM 已裁定默认态 A（转发远端 + 本地抑制）。
        let config = Config::default();
        assert!(
            config.input.alt_f4_forward,
            "默认 true = 态 A（PM 裁定）"
        );
    }

    #[test]
    fn r89e_input_alt_f4_forward_roundtrip() {
        // 显式 false 经序列化往返保留（态 B 用户配置不丢）。
        let mut config = Config::default();
        config.input.alt_f4_forward = false;
        let dir = std::env::temp_dir().join("kirin_desk_test_r89e_input");
        let path = dir.join("test.toml");
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(!loaded.input.alt_f4_forward, "显式 false 往返保留");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn r89e_input_legacy_toml_missing_section() {
        // 旧配置文件无 [input] 段 → 加载不失败，使用默认值（alt_f4_forward=true）。
        let dir = std::env::temp_dir().join("kirin_desk_test_r89e_input_legacy");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(
            loaded.input.alt_f4_forward,
            "旧配置缺 [input] 段 → 缺省 true（态 A）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn r94b_debug_conn_stats_visible_default_false() {
        // 用户 2026-09-08 复测：fps/bw 调试数据默认隐藏。
        let config = Config::default();
        assert!(
            !config.debug.conn_stats_visible,
            "默认 false = 默认隐藏"
        );
    }

    #[test]
    fn r94b_debug_conn_stats_visible_roundtrip() {
        // 显式 true 经序列化往返保留（用户开启配置不丢）。
        let mut config = Config::default();
        config.debug.conn_stats_visible = true;
        let dir = std::env::temp_dir().join("kirin_desk_test_r94b_debug");
        let path = dir.join("test.toml");
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.debug.conn_stats_visible, "显式 true 往返保留");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn r94b_debug_legacy_toml_missing_key() {
        // 旧配置兼容（r81e 同款手法：先落全量合法配置再改文件，避必填段
        // 缺漏）：① [debug] 段在但缺本键 → 字段缺省 false（隐藏）；
        // ② 整段缺失 → 结构体缺省 false（行为 = 新默认，零迁移）。
        let config = Config::default();
        let dir = std::env::temp_dir().join("kirin_desk_test_r94b_debug_legacy");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.toml");
        config.save_to(&path).unwrap();
        // 情形①：[debug] 段在、缺 conn_stats_visible 键（旧配置形态）。
        let mut text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("conn_stats_visible = false"),
            "前置：新配置落盘含显式键（替换前提）"
        );
        text = text.replace("conn_stats_visible = false", "");
        assert!(!text.contains("conn_stats_visible"), "前置：键已移除");
        std::fs::write(&path, &text).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(
            !loaded.debug.conn_stats_visible,
            "旧配置 [debug] 缺键 → 缺省 false（隐藏）"
        );
        // 情形②：[debug] 整段缺失（更早旧配置形态）。
        let mut text = std::fs::read_to_string(&path).unwrap();
        text = text.replace("[debug]", "[debug_disabled]");
        std::fs::write(&path, &text).unwrap();
        let loaded2 = Config::load_from(&path).unwrap();
        assert!(
            !loaded2.debug.conn_stats_visible,
            "旧配置缺 [debug] 段 → 缺省 false（隐藏）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- : 内网穿透配置测试 ----------

    #[test]
    fn test_tunnel_defaults() {
        let config = Config::default();
        assert!(!config.tunnel.enabled);
        assert_eq!(config.tunnel.mode, "client");
        assert!(config.tunnel.server_addr.is_empty());
        assert!(config.tunnel.token.is_empty());
        assert_eq!(config.tunnel.bind_port, 7000);
        assert_eq!(config.tunnel.port_range, "60000-61000");
        assert_eq!(config.tunnel.heartbeat_interval, 10);
        assert_eq!(config.tunnel.heartbeat_timeout, 30);
        assert_eq!(config.tunnel.pool_count, 0);
        assert_eq!(config.tunnel.max_pool_count, 5);
        assert!(config.tunnel.proxies.is_empty());
    }

    #[test]
    fn test_tunnel_legacy_toml_missing_section() {
        // 旧配置文件无 [tunnel] 段 → 加载不失败，使用默认值（TNL-CFG-001）
        let dir = std::env::temp_dir().join("kirin_desk_test_tunnel");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.device.id, "old-device");
        assert!(!loaded.tunnel.enabled);
        assert_eq!(loaded.tunnel.mode, "client");
        assert_eq!(loaded.tunnel.bind_port, 7000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tunnel_roundtrip() {
        let mut config = Config::default();
        config.tunnel.enabled = true;
        config.tunnel.server_addr = "relay.example.com:7000".to_string();
        config.tunnel.token = "secret-token".to_string();
        config.tunnel.proxies.push(TunnelProxy {
            name: "ssh".to_string(),
            local_addr: "127.0.0.1".to_string(),
            local_port: 22,
            remote_port: 0,
        });
        config.tunnel.proxies.push(TunnelProxy {
            name: "http".to_string(),
            local_addr: "127.0.0.1".to_string(),
            local_port: 8080,
            remote_port: 60080,
        });
        let dir = std::env::temp_dir().join("kirin_desk_test_config_tunnel");
        let path = dir.join("test.toml");
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.tunnel.enabled);
        assert_eq!(loaded.tunnel.server_addr, "relay.example.com:7000");
        assert_eq!(loaded.tunnel.token, "secret-token");
        assert_eq!(loaded.tunnel.proxies.len(), 2);
        assert_eq!(loaded.tunnel.proxies[0].name, "ssh");
        assert_eq!(loaded.tunnel.proxies[0].local_port, 22);
        assert_eq!(loaded.tunnel.proxies[0].remote_port, 0);
        assert_eq!(loaded.tunnel.proxies[1].remote_port, 60080);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tunnel_proxy_lines_parse() {
        // 正常行 + remote_port 留空 + 注释/空行跳过 + 非法行跳过
        let text = "\
            ssh|127.0.0.1:22|6022\n\
            rdp|192.168.1.5:3389\n\
            # comment\n\
            \n\
            bad-line-no-pipe\n\
            bad-port|127.0.0.1:not-a-port\n\
            ipv6|[::1]:2222|6023\n";
        let proxies = TunnelConfig::parse_proxy_lines(text);
        assert_eq!(proxies.len(), 3);
        assert_eq!(proxies[0].name, "ssh");
        assert_eq!(proxies[0].local_addr, "127.0.0.1");
        assert_eq!(proxies[0].local_port, 22);
        assert_eq!(proxies[0].remote_port, 6022);
        assert_eq!(proxies[1].name, "rdp");
        assert_eq!(proxies[1].local_port, 3389);
        assert_eq!(proxies[1].remote_port, 0);
        assert_eq!(proxies[2].name, "ipv6");
        assert_eq!(proxies[2].local_addr, "[::1]");
        assert_eq!(proxies[2].local_port, 2222);
        assert_eq!(proxies[2].remote_port, 6023);
    }

    #[test]
    fn test_tunnel_proxy_lines_format_roundtrip() {
        let proxies = vec![
            TunnelProxy {
                name: "ssh".to_string(),
                local_addr: "127.0.0.1".to_string(),
                local_port: 22,
                remote_port: 0,
            },
            TunnelProxy {
                name: "http".to_string(),
                local_addr: "192.168.1.5".to_string(),
                local_port: 8080,
                remote_port: 60080,
            },
        ];
        let text = TunnelConfig::format_proxy_lines(&proxies);
        let parsed = TunnelConfig::parse_proxy_lines(&text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "ssh");
        assert_eq!(parsed[0].remote_port, 0); // remote_port=0 省略第三段
        assert_eq!(parsed[1].remote_port, 60080);
    }

    // ---------- (P1): bind_addrs / auto_start 字段与工具函数测试 ----------

    #[test]
    fn test_tunnel_default_bind_addrs() {
        // 默认 "0.0.0.0,::"（显式 IPv4+IPv6 双监听）；auto_start 默认 false
        // （旧用户曾手开 enabled=true 的，缺省不自动拉起，行为兼容）。
        let tunnel = TunnelConfig::default();
        assert_eq!(tunnel.bind_addrs, "0.0.0.0,::");
        assert!(!tunnel.auto_start);
    }

    #[test]
    fn test_tunnel_legacy_toml_missing_bind_addrs_auto_start() {
        // 旧配置 [tunnel] 段缺 bind_addrs / auto_start → 加载不失败，
        // 默认值兜底生效（`#[serde(default)]`）。
        let dir = std::env::temp_dir().join("kirin_desk_test_tunnel_p1");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n\
             [tunnel]\nenabled = true\nmode = \"server\"\nbind_port = 7000\n\
             port_range = \"60000-61000\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.tunnel.enabled);
        assert_eq!(loaded.tunnel.mode, "server");
        assert_eq!(loaded.tunnel.bind_port, 7000);
        assert_eq!(loaded.tunnel.bind_addrs, "0.0.0.0,::");
        assert!(!loaded.tunnel.auto_start);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tunnel_bind_addrs_roundtrip() {
        // 显式 bind_addrs / auto_start 落盘 → 重新加载保持（P4 GUI 编辑持久化基础）。
        let dir = std::env::temp_dir().join("kirin_desk_test_tunnel_bind");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.toml");
        let mut config = Config::default();
        config.tunnel.bind_addrs = "0.0.0.0,::,192.168.1.10".to_string();
        config.tunnel.auto_start = true;
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.tunnel.bind_addrs, "0.0.0.0,::,192.168.1.10");
        assert!(loaded.tunnel.auto_start);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_bind_addr_list_empty_or_whitespace() {
        // 空串 / 纯空白 → Ok(vec![])（上层回退默认双栈，兼容旧配置语义）。
        assert!(parse_bind_addr_list("", 7000).unwrap().is_empty());
        assert!(parse_bind_addr_list("   ", 7000).unwrap().is_empty());
        assert!(parse_bind_addr_list("\n\t ", 7000).unwrap().is_empty());
    }

    #[test]
    fn test_parse_bind_addr_list_v4_v6_default() {
        // "0.0.0.0,::" + port 7000 → 两个 SocketAddr（v4 + v6 同端口）。
        let addrs = parse_bind_addr_list("0.0.0.0,::", 7000).unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(
            addrs[0],
            "0.0.0.0:7000".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            addrs[1],
            "[::]:7000".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_parse_bind_addr_list_with_whitespace() {
        // 带空白 "0.0.0.0, :: ,192.168.1.10" → 三项（逗号分隔 + 逐项 trim）。
        let addrs = parse_bind_addr_list("0.0.0.0, :: ,192.168.1.10", 7000).unwrap();
        assert_eq!(addrs.len(), 3);
        assert_eq!(
            addrs[0],
            "0.0.0.0:7000".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            addrs[1],
            "[::]:7000".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            addrs[2],
            "192.168.1.10:7000".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_parse_bind_addr_list_empty_segment() {
        // 空段 "0.0.0.0,,::" → Err（错误文案中文，指出空段）。
        let err = parse_bind_addr_list("0.0.0.0,,::", 7000).unwrap_err();
        assert!(err.contains("空段"));
    }

    #[test]
    fn test_parse_bind_addr_list_domain_rejected() {
        // 域名不支持（监听地址必须是本机 IP）。
        let err = parse_bind_addr_list("relay.example.com", 7000).unwrap_err();
        assert!(err.contains("relay.example.com"));
        assert!(err.contains("域名"));
    }

    #[test]
    fn test_parse_bind_addr_list_invalid_ip() {
        // 非 IP（"999.1.1.1"）→ Err。
        let err = parse_bind_addr_list("999.1.1.1", 7000).unwrap_err();
        assert!(err.contains("999.1.1.1"));
    }

    #[test]
    fn test_generate_random_token_hex_length() {
        // 32 字节 OsRng → 64 位 hex，全 hex 字符集（≥32 字节熵，TNL-SEC-009）。
        let token = generate_random_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_random_token_distinct() {
        // 两次调用结果不同（随机性冒烟；64 hex 位碰撞概率可忽略）。
        let a = generate_random_token();
        let b = generate_random_token();
        assert_ne!(a, b);
    }

    #[test]
    fn test_default_toml_parses() {
        // 项目模板 config/default.toml（含新增 [tunnel] 段）必须可被 Config 解析，
        // 防止模板与结构体字段脱节。
        // 回写会持久化到被加载路径；原地读仓库模板将污染模板文件（注释
        // 丢失 + 本机派生 ID 落盘 + 键文件创建），模板保持只读输入。
        let template = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/default.toml");
        let dir = std::env::temp_dir().join("kirin_desk_r76c_template");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("default.toml");
        std::fs::copy(&template, &path).unwrap();
        let cfg = Config::load_from(&path).expect("default.toml should parse");
        assert!(!cfg.tunnel.enabled);
        assert_eq!(cfg.tunnel.mode, "client");
        assert_eq!(cfg.tunnel.bind_port, 7000);
        assert_eq!(cfg.tunnel.heartbeat_interval, 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- 白名单测试 ----------

    #[test]
    fn test_whitelist_matches() {
        // 精确匹配
        assert!(whitelist_matches("example.com", "example.com"));
        assert!(!whitelist_matches("a.example.com", "example.com"));
        // 通配匹配：自身 + 任意子域
        assert!(whitelist_matches("example.com", "*.example.com"));
        assert!(whitelist_matches("a.example.com", "*.example.com"));
        assert!(whitelist_matches("x.y.example.com", "*.example.com"));
        assert!(!whitelist_matches("example.net", "*.example.com"));
        assert!(!whitelist_matches("evilexample.com", "*.example.com"));
        // 空模式
        assert!(!whitelist_matches("example.com", "  "));
    }

    #[test]
    fn test_whitelist_check_and_expiry() {
        let (mut config, _override_path) = r82a_sandboxed_config("wl_check_expiry");
        config.whitelist_add("*.example.com", None).unwrap();
        config
            .whitelist_add(
                "temporary.net",
                Some(Utc::now() - chrono::Duration::minutes(1)),
            )
            .unwrap();

        assert!(config.whitelist_check("a.example.com"));
        assert!(config.whitelist_check("example.com"));
        assert!(!config.whitelist_check("other.net"));
        // 过期条目自动失效
        assert!(!config.whitelist_check("temporary.net"));
        // 清理过期条目
        assert_eq!(config.whitelist_prune_expired(Utc::now()), 1);
    }

    #[test]
    fn test_whitelist_legacy_allowed_domains_compat() {
        let (mut config, _override_path) = r82a_sandboxed_config("wl_legacy_compat");
        config.network.allowed_domains.push("legacy.example.com".to_string());
        assert!(config.whitelist_check("legacy.example.com"));
        assert!(config.whitelist_check("sub.legacy.example.com"));
        // 删除时同时清理旧字段
        assert!(config.whitelist_remove("legacy.example.com").unwrap());
        assert!(config.network.allowed_domains.is_empty());
        assert!(!config.whitelist_remove("legacy.example.com").unwrap());
    }

    #[test]
    fn test_whitelist_import_export_csv() {
        let dir = std::env::temp_dir().join("kirin_desk_test_whitelist");
        std::fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("wl.csv");

        let (mut config, _override_path) = r82a_sandboxed_config("wl_import_csv");
        let n = config
            .whitelist_import_csv(&dir.join("wl_in.csv"))
            .unwrap_or(0);
        assert_eq!(n, 0); // 文件不存在 → 报错路径由调用方处理，此处验证空

        std::fs::write(
            &csv,
            "# comment\n*.example.com,\npc-a.kirin.io,2026-12-31T00:00:00Z\nbad-line,not-a-date\n",
        )
        .unwrap();
        let imported = config.whitelist_import_csv(&csv).unwrap();
        assert_eq!(imported, 2);
        assert!(config.whitelist_check("pc-a.kirin.io"));
        assert!(config.whitelist_check("any.example.com"));

        // 导出 CSV 再导入到新配置
        let out = dir.join("wl_out.csv");
        config.whitelist_export_csv(&out).unwrap();
        let (mut config2, _override_path2) = r82a_sandboxed_config("wl_import_csv_2");
        let n2 = config2.whitelist_import_csv(&out).unwrap();
        assert!(n2 >= 2);
        assert!(config2.whitelist_check("pc-a.kirin.io"));

        // 导出 JSON
        let json_path = dir.join("wl.json");
        config.whitelist_export_json(&json_path).unwrap();
        assert!(std::fs::read_to_string(&json_path).unwrap().contains("pattern"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_whitelist_toml_roundtrip() {
        let (mut config, _override_path) = r82a_sandboxed_config("wl_toml_rt");
        config
            .whitelist_add("*.example.com", Some(Utc::now() + chrono::Duration::days(1)))
            .unwrap();
        let dir = std::env::temp_dir().join("kirin_desk_test_config_wl");
        let path = dir.join("test.toml");
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.whitelist_check("a.example.com"));
        assert_eq!(loaded.network.whitelist.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn r81e_debug_section_defaults_and_roundtrip() {
        // 新配置结构体 = 无显式值（`None`）；内置默认「开」在门控层生效
        // 临时默认开，用户 2026-09-06 裁定；回收条件见 DebugConfig 字段文档）。
        let mut config = Config::default();
        assert_eq!(
            config.debug.latency_trace,
            None,
        );
        // 显式开往返：Some(true) → 落盘 → 重载仍开。
        config.debug.latency_trace = Some(true);
        let dir = std::env::temp_dir().join("kirin_desk_r81e_debug_cfg");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.toml");
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.debug.latency_trace, Some(true), "往返后保持 true");
        // 显式关往返（逃生口持久化）：Some(false) → 落盘 → 重载仍显式关。
        config.debug.latency_trace = Some(false);
        config.save_to(&path).unwrap();
        let loaded_off = Config::load_from(&path).unwrap();
        assert_eq!(
            loaded_off.debug.latency_trace,
            Some(false),
            "显式关往返后保持 Some(false)"
        );
        // 旧配置无 [debug] 段 → serde 缺省 None → 落内置默认（临时开，
        // 前向兼容：旧配置升级后按新默认开）。
        let legacy = std::fs::read_to_string(&path).unwrap();
        let legacy = legacy.replace("[debug]", "[debug_disabled]");
        std::fs::write(&path, legacy).unwrap();
        let loaded2 = Config::load_from(&path).unwrap();
        assert_eq!(
            loaded2.debug.latency_trace,
            None,
            "缺段 → None（落内置默认开）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn r81e_default_toml_template_debug_on() {
        // 翻转为开（用户 2026-09-06 裁定；临时口径，回收条件同结构体文档）。
        let template = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/default.toml");
        let dir = std::env::temp_dir().join("kirin_desk_r81e_template");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("default.toml");
        std::fs::copy(&template, &path).unwrap();
        let cfg = Config::load_from(&path).expect("default.toml should parse");
        assert_eq!(cfg.debug.latency_trace, Some(true), "模板默认必须开（临时）");
        assert!(!cfg.debug.conn_stats_visible, "模板 conn_stats_visible 默认关");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- : 设备 ID 白名单测试（SRV-IDWL-001..008） ----------

    #[test]
    fn test_id_whitelist_defaults_and_legacy_toml() {
        // 默认：两维均为空；旧配置（无新字段）加载不失败（向后兼容）。
        let config = Config::default();
        assert!(config.network.allowed_ids.is_empty());
        assert!(config.network.id_whitelist.is_empty());
        assert!(config.id_whitelist_active_ids(Utc::now()).is_empty());
        assert!(!config.id_whitelist_check("device-7"));

        let dir = std::env::temp_dir().join("kirin_desk_test_idwl_legacy");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.network.allowed_ids.is_empty());
        assert!(loaded.network.id_whitelist.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 保持开启（开关状态持久化，复用既有 kirin 配置文件，不另造存储）。
    #[test]
    fn test_r59_id_whitelist_enforce_toggle_persist() {
        let config = Config::default();

        let dir = std::env::temp_dir().join("kirin_desk_test_r59_enforce");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut config = Config::default();
        config.save_override = Some(path.clone());
        config.set_id_whitelist_enforce(true);
        config.id_whitelist_add("ctrl-a", None).unwrap();
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.network.id_whitelist_enforce, "开关需随配置落盘");
        assert_eq!(
            loaded.id_whitelist_active_ids(Utc::now()),
            vec!["ctrl-a".to_string()],
            "列表与开关同一存储"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_id_whitelist_add_remove_and_expiry() {
        let (mut config, _override_path) = r82a_sandboxed_config("idwl_add_remove");
        // 新增永久条目 + 带过期条目。
        assert!(config.id_whitelist_add("device-7", None).unwrap());
        assert!(
            config
                .id_whitelist_add(
                    "device-temp",
                    Some(Utc::now() + chrono::Duration::minutes(5)),
                )
                .unwrap()
        );
        // 重复添加 → false（只更新过期时间，不新增）。
        assert!(!config.id_whitelist_add("device-7", None).unwrap());
        assert!(!config.id_whitelist_add("", None).unwrap());

        let active = config.id_whitelist_active_ids(Utc::now());
        assert_eq!(active.len(), 2);
        assert!(active.contains(&"device-7".to_string()));

        // 过期条目自动失效（active_ids / check 均不命中）。
        let past = Utc::now() - chrono::Duration::minutes(1);
        config.id_whitelist_add("device-expired", Some(past)).unwrap();
        assert_eq!(config.id_whitelist_active_ids(Utc::now()).len(), 2);
        assert!(!config.id_whitelist_check("device-expired"));
        // prune 物理清理。
        assert_eq!(config.id_whitelist_prune_expired(Utc::now()), 1);
        assert_eq!(config.network.id_whitelist.len(), 2);

        // remove 同时清理 id_whitelist 与 allowed_ids 两维。
        config.network.allowed_ids.push("device-9".to_string());
        assert!(config.id_whitelist_check("device-9"));
        assert!(config.id_whitelist_remove("device-9").unwrap());
        assert!(!config.id_whitelist_check("device-9"));
        assert!(config.network.allowed_ids.is_empty());
        assert!(!config.id_whitelist_remove("device-9").unwrap());
    }

    #[test]
    fn test_id_whitelist_active_ids_dedup() {
        // allowed_ids 与 id_whitelist 同 key → 去重，且永久条目不被过期条目遮蔽。
        let (mut config, _override_path) = r82a_sandboxed_config("idwl_dedup");
        config.network.allowed_ids.push("device-7".to_string());
        config
            .id_whitelist_add("device-7", Some(Utc::now() + chrono::Duration::days(1)))
            .unwrap();
        let active = config.id_whitelist_active_ids(Utc::now());
        assert_eq!(active.len(), 1);
        assert!(config.id_whitelist_check("device-7"));
    }

    #[test]
    fn test_id_whitelist_import_export_csv() {
        let dir = std::env::temp_dir().join("kirin_desk_test_idwl_csv");
        std::fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("idwl.csv");
        std::fs::write(
            &csv,
            "# comment\nid:device-1,\nid:device-2,2026-12-31T00:00:00Z\nid:,no-id\nid:device-3,not-a-date\n",
        )
        .unwrap();
        let (mut config, _override_path) = r82a_sandboxed_config("idwl_import_csv");
        let imported = config.id_whitelist_import_csv(&csv).unwrap();
        assert_eq!(imported, 2); // 空 id 与非法时间戳行跳过
        assert!(config.id_whitelist_check("device-1"));
        assert!(config.id_whitelist_check("device-2"));
        assert!(!config.id_whitelist_check("device-3"));

        // 导出再导入到新配置（往返）。
        let out = dir.join("idwl_out.csv");
        config.id_whitelist_export_csv(&out).unwrap();
        let (mut config2, _override_path2) = r82a_sandboxed_config("idwl_import_csv_2");
        let n2 = config2.id_whitelist_import_csv(&out).unwrap();
        assert_eq!(n2, 2);
        assert!(config2.id_whitelist_check("device-1"));
        assert!(config2.id_whitelist_check("device-2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_whitelist_import_csv_routes_id_lines() {
        // 混合 CSV：域名行保持原格式，`id:` 前缀行路由到 ID 维度（CLI-IDWL-004）。
        let dir = std::env::temp_dir().join("kirin_desk_test_mixed_csv");
        std::fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("mixed.csv");
        std::fs::write(
            &csv,
            "# mixed\n*.example.com,\nid:device-7,\nid:device-8,2026-12-31T00:00:00Z\n",
        )
        .unwrap();
        let (mut config, _override_path) = r82a_sandboxed_config("mixed_csv");
        let imported = config.whitelist_import_csv(&csv).unwrap();
        assert_eq!(imported, 3);
        assert!(config.whitelist_check("a.example.com"));
        assert!(config.id_whitelist_check("device-7"));
        assert!(config.id_whitelist_check("device-8"));
        assert!(config.network.allowed_ids.is_empty(), "id: 行不进 allowed_ids");

        // 导出 CSV 同时含两维，可整体往返。
        let out = dir.join("mixed_out.csv");
        config.whitelist_export_csv(&out).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("id:device-7"));
        let (mut config2, _override_path2) = r82a_sandboxed_config("mixed_csv_2");
        let n2 = config2.whitelist_import_csv(&out).unwrap();
        assert!(n2 >= 3);
        assert!(config2.whitelist_check("a.example.com"));
        assert!(config2.id_whitelist_check("device-7"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_id_whitelist_json_and_toml_roundtrip() {
        let dir = std::env::temp_dir().join("kirin_desk_test_idwl_rt");
        std::fs::create_dir_all(&dir).unwrap();
        let (mut config, _override_path) = r82a_sandboxed_config("idwl_json_toml_rt");
        config.network.allowed_ids.push("device-7".to_string());
        config
            .id_whitelist_add("device-8", Some(Utc::now() + chrono::Duration::days(1)))
            .unwrap();
        config.whitelist_add("*.example.com", None).unwrap();

        // TOML 往返（新字段序列化 + 旧字段兼容）。
        let path = dir.join("test.toml");
        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.network.allowed_ids, vec!["device-7".to_string()]);
        assert_eq!(loaded.network.id_whitelist.len(), 1);
        assert!(loaded.id_whitelist_check("device-7"));
        assert!(loaded.id_whitelist_check("device-8"));
        assert!(loaded.whitelist_check("a.example.com"));

        // export-json 同时输出两维（CLI-IDWL-004）。
        let json_path = dir.join("wl.json");
        config.whitelist_export_json(&json_path).unwrap();
        let text = std::fs::read_to_string(&json_path).unwrap();
        assert!(text.contains("\"pattern\""), "domain 维保留 pattern 字段");
        assert!(text.contains("\"device_id\""), "JSON 含 ID 维条目");
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// `id_whitelist_add`（内部**隐式** `self.save()`）后，「真实路径」
    /// （= `KIRIN_DATA_DIR` 隔离目录下的 `default.toml`，模拟用户配置位）
    /// **逐字节不变**；隐式保存只落到 `save_override` 指向的独立隔离目录文件。
    ///
    /// self-test 的即调即存 API 每波门禁覆写一次用户真实配置（物证：
    /// device-temp+24h 残留、token 加密空串、两日 32 次 id 派生回写行）。
    #[test]
    fn r82a_sentinel_nonempty_token_id_whitelist_add_preserves_default_path() {
        let _guard = KIRIN_DATA_DIR_LOCK.lock().unwrap();
        let sandbox = std::env::temp_dir().join("kirin_desk_r82a_sentinel_default");
        let _ = std::fs::remove_dir_all(&sandbox);
        std::fs::create_dir_all(&sandbox).unwrap();
        std::env::set_var("KIRIN_DATA_DIR", &sandbox);

        // 用户模拟配置：default.toml 含非空 token + device.id + nickname。
        let real = sandbox.join("default.toml");
        let mut client = Config::default();
        client.device.id = "HD-DEADBEEF".to_string();
        client.device.nickname = "client-pc".to_string();
        client.tunnel.token = "client-token".to_string();
        client.save_to(&real).expect("用户模拟配置落盘");
        let before = std::fs::read(&real).expect("读取用户模拟配置");

        // 非空 token 实例 + override 指向**独立**隔离目录文件 → 隐式 save 不得
        // 触碰 default.toml。
        let override_path =
            std::env::temp_dir().join("kirin_desk_r82a_sentinel_override.toml");
        let _ = std::fs::remove_file(&override_path);
        let mut cfg = client;
        cfg.save_override = Some(override_path.clone());
        assert!(
            cfg.id_whitelist_add("device-x", None).unwrap(),
            "新增应成功"
        );

        // 断言 1（哨兵）：真实路径逐字节不变。
        let after = std::fs::read(&real).expect("再次读取用户模拟配置");
        // 断言 2：写入确实落到 override 目标（隔离不改变即调即存能力）。
        let on_disk = std::fs::read_to_string(&override_path)
            .expect("override 隔离目录文件应已落盘");
        assert!(on_disk.contains("device-x"), "落盘内容应含新增 ID 白名单条目");

        let _ = std::fs::remove_dir_all(&sandbox);
        let _ = std::fs::remove_file(&override_path);
    }

    /// 形态，恒 `None`）时，`id_whitelist_add` 必须**立即**落盘到
    /// `default_path`——CLI `whitelist add-id` 等命令不加显式 `save` 也持久
    /// 化的语义被 `save_override` 机制改变的可能性钉死。隔离目录化：
    /// `KIRIN_DATA_DIR` 指临时目录，`default_path` 落隔离目录内，不触碰真实
    #[test]
    fn r82a_production_id_whitelist_add_saves_to_default_path_immediately() {
        let _guard = KIRIN_DATA_DIR_LOCK.lock().unwrap();
        let sandbox = std::env::temp_dir().join("kirin_desk_r82a_prod_imm");
        let _ = std::fs::remove_dir_all(&sandbox);
        std::fs::create_dir_all(&sandbox).unwrap();
        std::env::set_var("KIRIN_DATA_DIR", &sandbox);

        let mut cfg = Config::default(); // save_override = None = 生产形态
        assert!(
            cfg.id_whitelist_add("cli-device", None).unwrap(),
            "新增应成功"
        );
        // **未调用显式 save** —— 文件必须已存在于 default_path（即调即存）。
        let default_path = Config::config_dir().expect("隔离目录 config_dir").join("default.toml");
        assert!(
            default_path.exists(),
            "即调即存：id_whitelist_add 后 default.toml 必须已落盘"
        );
        let on_disk = std::fs::read_to_string(&default_path).expect("读取隔离目录 default.toml");
        assert!(
            on_disk.contains("cli-device"),
            "落盘内容应含新增 ID 白名单条目"
        );

        let _ = std::fs::remove_dir_all(&sandbox);
    }

    /// device.id + nickname）而新内容全空（`Config::default()` 整份形态 =
    /// 事故签名）→ `save_to` 先复制 `<file>.bak-<UTC时间戳>` 再写；旧内容
    /// 逐字节保全于备份件。
    #[test]
    fn r82a_save_to_backups_when_empty_over_nonempty_sensitive() {
        let dir = std::env::temp_dir().join("kirin_desk_r82a_bak_trigger");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("default.toml");

        // 用户模拟旧配置（敏感字段非空）。
        let mut old = Config::default();
        old.device.id = "HD-DEADBEEF".to_string();
        old.device.nickname = "client-pc".to_string();
        old.tunnel.token = "tok-123".to_string();
        old.save_to(&path).expect("旧配置落盘");
        let old_content = std::fs::read(&path).expect("读取旧配置");

        // 空配置整份覆写（事故形态）→ 备份必须触发。
        Config::default().save_to(&path).expect("覆写应成功（备份后写）");

        let bak = dir
            .read_dir()
            .expect("列举目录")
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("default.toml.bak-"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        assert_eq!(bak.len(), 1, "应恰好一个备份件: {bak:?}");
        let bak_content = std::fs::read(&bak[0]).expect("读取备份件");
        assert_eq!(bak_content, old_content, "备份件须逐字节保全旧内容");

        // 新文件已是空敏感字段形态（覆写生效）。
        let new_content = std::fs::read(&path).expect("读取新文件");
        assert_ne!(new_content, old_content, "覆写应生效");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// b. 新旧敏感字段均非空（正常保存/同值重写）——两种正常路径不得产生
    /// 备份件。对照面 c：旧文件**不可解析**（损坏件）→ 必须备份（损坏件
    /// 保护分支）。
    #[test]
    fn r82a_save_to_no_backup_on_fresh_or_matching_sensitive() {
        let dir = std::env::temp_dir().join("kirin_desk_r82a_bak_skip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let backups = || {
            dir.read_dir()
                .expect("列举目录")
                .map(|e| e.unwrap().path())
                .filter(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().contains(".bak-"))
                        .unwrap_or(false)
                })
                .count()
        };

        // a. 目标不存在 → 首启创建，不备份。
        Config::default().save_to(&path).expect("首启落盘");
        assert_eq!(backups(), 0, "首启创建不得产生备份件");

        // b. 旧敏感字段非空 → 新同非空（正常保存）→ 不备份。
        let mut nonempty = Config::default();
        nonempty.device.id = "HD-11112222".to_string();
        nonempty.tunnel.token = "tok-normal".to_string();
        nonempty.save_to(&path).expect("正常保存");
        assert_eq!(backups(), 0, "新旧敏感字段均非空（正常保存）不得产生备份件");
        nonempty.save_to(&path).expect("同值重写");
        assert_eq!(backups(), 0, "同值重写不得产生备份件");

        // c.（对照面）旧文件不可解析 → 损坏件保护，必须备份。
        let corrupt = dir.join("corrupt.toml");
        std::fs::write(&corrupt, "this is not [valid toml = =").expect("写入损坏件");
        Config::default().save_to(&corrupt).expect("损坏件覆写应成功（备份后写）");
        assert_eq!(
            backups(),
            1,
            "不可解析旧文件（损坏件）必须产生备份件"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `sensitive_disk_value_nonempty` 决策表（含事故物证形态「token 加密
    /// 空串」= `{v:…}` 28B blob = 空明文 → 判空不误触发）。
    #[test]
    fn r82a_sensitive_fields_decision_table() {
        // 磁盘值口径：空/纯空白 → 空；明文非空 → 非空。
        assert!(!sensitive_disk_value_nonempty(""));
        assert!(!sensitive_disk_value_nonempty("   "));
        assert!(sensitive_disk_value_nonempty("tok"));
        // 密文口径：用真实加密器构造（空明文 blob = 28B；非空 > 28B）。
        let key = [7u8; 32];
        let empty_ct = secure::encrypt_to_string(&key, "", "unit.ctx").expect("加密空串");
        assert!(secure::looks_encrypted(&empty_ct));
        assert!(
            !sensitive_disk_value_nonempty(&empty_ct),
            "事故物证形态（token 加密空串）必须判空——不得误触发备份"
        );
        let nonempty_ct =
            secure::encrypt_to_string(&key, "real-token", "unit.ctx").expect("加密非空");
        assert!(
            sensitive_disk_value_nonempty(&nonempty_ct),
            "加密非空 token 必须判非空"
        );
        // 整体口径：全空 → false；任一非空 → true（device.id 未填写态视空）。
        let blank = Config::default();
        assert!(!sensitive_fields_nonempty(&blank));
        let mut auto_id = Config::default();
        auto_id.device.id = "default-device".to_string(); // 占位符 = 未填写态
        assert!(!sensitive_fields_nonempty(&auto_id), "default-device 占位符视空");
        let mut with_id = auto_id.clone();
        with_id.device.id = "HD-ABCD1234".to_string();
        assert!(sensitive_fields_nonempty(&with_id));
        let mut with_nick = Config::default();
        with_nick.device.nickname = "pc".to_string();
        assert!(sensitive_fields_nonempty(&with_nick));
        let mut with_token = Config::default();
        with_token.tunnel.token = "t".to_string();
        assert!(sensitive_fields_nonempty(&with_token));
    }

    // ---------- / S-10: 文件传输配额配置测试 ----------

    #[test]
    fn test_file_transfer_quota_defaults() {
        // 默认：字节配额 4 GiB + 文件数 64（S-10b/F-11）。
        let config = Config::default();
        assert_eq!(config.file_transfer.max_file_size, 4 * 1024 * 1024 * 1024);
        assert_eq!(config.file_transfer.session_max_bytes, 4 * 1024 * 1024 * 1024);
        assert_eq!(config.file_transfer.session_max_files, 64);
    }

    #[test]
    fn test_file_transfer_quota_legacy_toml_and_roundtrip() {
        // 旧配置无新字段 → 追加式默认值，加载不失败。
        let dir = std::env::temp_dir().join("kirin_desk_test_ft_quota");
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = dir.join("legacy.toml");
        std::fs::write(
            &legacy,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&legacy).unwrap();
        assert_eq!(loaded.file_transfer.session_max_bytes, 4 * 1024 * 1024 * 1024);
        assert_eq!(loaded.file_transfer.session_max_files, 64);

        // 自定义值 TOML 往返（含 0 = 不限制语义）。
        let mut cfg = Config::default();
        cfg.file_transfer.session_max_bytes = 1024;
        cfg.file_transfer.session_max_files = 2;
        let path = dir.join("quota.toml");
        cfg.save_to(&path).unwrap();
        let loaded2 = Config::load_from(&path).unwrap();
        assert_eq!(loaded2.file_transfer.session_max_bytes, 1024);
        assert_eq!(loaded2.file_transfer.session_max_files, 2);
        let mut cfg3 = Config::default();
        cfg3.file_transfer.session_max_bytes = 0;
        cfg3.file_transfer.session_max_files = 0;
        cfg3.save_to(&dir.join("quota0.toml")).unwrap();
        let loaded3 = Config::load_from(&dir.join("quota0.toml")).unwrap();
        assert_eq!(loaded3.file_transfer.session_max_bytes, 0);
        assert_eq!(loaded3.file_transfer.session_max_files, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn test_file_transfer_fs_fields_defaults_and_legacy_toml() {
        // 保旧配置兼容——旧配置文件必须能加载）。
        let config = Config::default();
        assert!(config.file_transfer.fs_roots.is_empty(), "fs_roots 默认空");
        assert!(
            config.file_transfer.fs_write_roots.is_empty(),
            "fs_write_roots 默认空（= 写根门禁用，§1.4）"
        );
        assert!(config.file_transfer.auto_resume, "auto_resume 默认开（K5）");

        let dir = std::env::temp_dir().join("kirin_desk_test_ft_fs");
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = dir.join("legacy.toml");
        std::fs::write(
            &legacy,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n\
             [file_transfer]\nmax_file_size = 1000\n",
        )
        .unwrap();
        let loaded = Config::load_from(&legacy).unwrap();
        assert_eq!(loaded.file_transfer.max_file_size, 1000, "旧字段不受影响");
        assert!(loaded.file_transfer.fs_roots.is_empty(), "旧配置 fs_roots 落默认空");
        assert!(
            loaded.file_transfer.fs_write_roots.is_empty(),
            "旧配置 fs_write_roots 落默认空（门禁用）"
        );
        assert!(loaded.file_transfer.auto_resume, "旧配置 auto_resume 落默认开");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_transfer_fs_fields_roundtrip() {
        let mut cfg = Config::default();
        cfg.file_transfer.fs_roots = vec!["D:\\share".into(), "~\\media".into()];
        cfg.file_transfer.fs_write_roots = vec!["D:\\share".into()];
        cfg.file_transfer.auto_resume = false;
        let dir = std::env::temp_dir().join("kirin_desk_test_ft_fs_rt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.toml");
        cfg.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(
            loaded.file_transfer.fs_roots,
            vec!["D:\\share".to_string(), "~\\media".to_string()]
        );
        assert_eq!(loaded.file_transfer.fs_write_roots, vec!["D:\\share".to_string()]);
        assert!(!loaded.file_transfer.auto_resume);
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn test_file_transfer_consent_switches_default_true_and_legacy_toml() {
        // B1：两开关默认开（用户「默认都开」裁定）+ 旧配置缺键 → 加载不失败、
        // 落默认开（serde 默认保旧配置兼容——旧配置文件必须能加载）+ 往返
        // 「缺键 = true」（缺键加载 → 保存 → 再加载仍开）。
        let config = Config::default();
        assert!(config.file_transfer.file_transfer_allowed, "file_transfer_allowed 默认开");
        assert!(config.file_transfer.clipboard_allowed, "clipboard_allowed 默认开");

        let dir = std::env::temp_dir().join("kirin_desk_test_ft_consent");
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = dir.join("legacy.toml");
        std::fs::write(
            &legacy,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n\
             [file_transfer]\nmax_file_size = 1000\n",
        )
        .unwrap();
        let loaded = Config::load_from(&legacy).unwrap();
        assert_eq!(loaded.file_transfer.max_file_size, 1000, "旧字段不受影响");
        assert!(
            loaded.file_transfer.file_transfer_allowed,
            "旧配置缺键 → 默认开（文件传输）"
        );
        assert!(loaded.file_transfer.clipboard_allowed, "旧配置缺键 → 默认开（剪贴板）");
        // 往返：缺键加载 → 保存（键显式写出 true）→ 再加载仍开。
        let path = dir.join("rt.toml");
        loaded.save_to(&path).unwrap();
        let reloaded = Config::load_from(&path).unwrap();
        assert!(reloaded.file_transfer.file_transfer_allowed, "缺键往返后仍开（文件传输）");
        assert!(reloaded.file_transfer.clipboard_allowed, "缺键往返后仍开（剪贴板）");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_transfer_consent_switches_roundtrip_explicit_false() {
        // B1：显式 false 往返（显式关保持关，不被 serde 默认覆盖）+ 混合态
        // （一关一开）往返保持。
        let dir = std::env::temp_dir().join("kirin_desk_test_ft_consent_rt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("both_off.toml");
        let mut off = Config::default();
        off.file_transfer.file_transfer_allowed = false;
        off.file_transfer.clipboard_allowed = false;
        off.save_to(&path).unwrap();
        let loaded_off = Config::load_from(&path).unwrap();
        assert!(
            !loaded_off.file_transfer.file_transfer_allowed,
            "显式 false 保持 false（文件传输）"
        );
        assert!(!loaded_off.file_transfer.clipboard_allowed, "显式 false 保持 false（剪贴板）");

        let path2 = dir.join("mixed.toml");
        let mut mixed = Config::default();
        mixed.file_transfer.file_transfer_allowed = false;
        mixed.file_transfer.clipboard_allowed = true;
        mixed.save_to(&path2).unwrap();
        let loaded_mixed = Config::load_from(&path2).unwrap();
        assert!(!loaded_mixed.file_transfer.file_transfer_allowed, "混合态保持（关）");
        assert!(loaded_mixed.file_transfer.clipboard_allowed, "混合态保持（开）");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r166_clip_direct_paste_default_and_roundtrip() {
        // + 显式 false 往返保持。
        let cfg = Config::default();
        assert!(
            cfg.file_transfer.clip_direct_paste,
            "clip_direct_paste 默认开"
        );
        let dir = std::env::temp_dir().join("kirin_desk_test_r166_direct_rt");
        std::fs::create_dir_all(&dir).unwrap();
        // 旧配置缺键（完整配置落盘后剥除本键行）→ serde default = 开。
        let mut base = Config::default();
        let legacy = dir.join("legacy.toml");
        base.save_to(&legacy).unwrap();
        let text = std::fs::read_to_string(&legacy).unwrap();
        let stripped: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("clip_direct_paste"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&legacy, stripped).unwrap();
        let loaded = Config::load_from(&legacy).unwrap();
        assert!(loaded.file_transfer.clip_direct_paste, "旧配置缺键 → 默认开");
        // 显式 false 往返保持。
        let path = dir.join("off.toml");
        let mut off = Config::default();
        off.file_transfer.clip_direct_paste = false;
        off.save_to(&path).unwrap();
        let loaded_off = Config::load_from(&path).unwrap();
        assert!(!loaded_off.file_transfer.clip_direct_paste, "显式 false 保持 false");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- (P2): UI 语言配置测试 ----------

    #[test]
    fn test_ui_language_defaults() {
        // 默认值："system"（跟随系统）——与 theme 的 "light" 默认互不干扰。
        let cfg = UiConfig::default();
        assert_eq!(cfg.language, "system");
        assert_eq!(cfg.theme, "light");
    }

    #[test]
    fn test_ui_language_legacy_toml_missing_field() {
        // 旧配置无 `[ui].language` → 加载不失败，取默认 "system"（P13）。
        let dir = std::env::temp_dir().join("kirin_desk_test_ui_lang");
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = dir.join("legacy.toml");
        std::fs::write(
            &legacy,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [ui]\ntheme = \"dark\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&legacy).unwrap();
        assert_eq!(loaded.ui.language, "system");
        assert_eq!(loaded.ui.theme, "dark");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ui_language_roundtrip() {
        // 显式 `language = "en"` 落盘 → 重新加载保持（P11 持久化基础）。
        let dir = std::env::temp_dir().join("kirin_desk_test_ui_lang_rt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lang.toml");
        let mut cfg = Config::default();
        cfg.ui.language = "en".to_string();
        cfg.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.ui.language, "en");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- (P1): [ddns] / [dns.security] 配置测试 ----------

    #[test]
    fn test_ddns_defaults() {
        // 默认：总开关关、auto/auto、周期回退 [network] heartbeat_interval、
        // 三源优先序、publish 四开关全开（DDNS-001/002，需求 §5.1）。
        let config = Config::default();
        assert!(!config.ddns.enabled);
        assert_eq!(config.ddns.ipv4_mode, DdnsMode::Auto);
        assert_eq!(config.ddns.ipv6_mode, DdnsMode::Auto);
        assert_eq!(config.ddns.ipv4_sources, vec!["ipify", "ip.sb", "icanhazip"]);
        assert!(config.ddns.publish_srv);
        assert!(config.ddns.publish_txt);
        assert!(config.ddns.publish_a);
        assert!(config.ddns.publish_aaaa);
        // [network] heartbeat_interval 默认 30 → 收敛到 60s 下限。
        assert_eq!(config.effective_ddns_interval(), DDNS_INTERVAL_MIN_SECS);
    }

    #[test]
    fn test_ddns_interval_floor_and_fallback() {
        // 显式 interval_secs ≥ 60 原样；30 → 收敛 60；0 → 收敛 60（下限收敛）。
        let mut cfg = DdnsConfig::default();
        cfg.interval_secs = Some(300);
        assert_eq!(cfg.effective_interval_secs(30), 300);
        cfg.interval_secs = Some(30);
        assert_eq!(cfg.effective_interval_secs(30), 60);
        cfg.interval_secs = Some(60);
        assert_eq!(cfg.effective_interval_secs(30), 60);
        // 未设置 → 回退 [network] heartbeat_interval（仍受 60s 下限约束，§5.3）。
        cfg.interval_secs = None;
        assert_eq!(cfg.effective_interval_secs(120), 120);
        assert_eq!(cfg.effective_interval_secs(30), 60);
    }

    #[test]
    fn test_ddns_manual_addr_parse() {
        // 手动地址：合法 IPv4/IPv6 解析；空/占位/非法 → None（DDNS-IPV4-004）。
        let mut cfg = DdnsConfig::default();
        assert!(cfg.ipv4_manual_addr().is_none());
        cfg.ipv4_manual = "203.0.113.7".to_string();
        assert_eq!(cfg.ipv4_manual_addr(), Some("203.0.113.7".parse().unwrap()));
        cfg.ipv4_manual = "0.0.0.0".to_string();
        assert!(cfg.ipv4_manual_addr().is_none());
        cfg.ipv4_manual = "not-an-ip".to_string();
        assert!(cfg.ipv4_manual_addr().is_none());
        cfg.ipv6_manual = "2001:db8::1".to_string();
        assert_eq!(cfg.ipv6_manual_addr(), Some("2001:db8::1".parse().unwrap()));
        cfg.ipv6_manual = "::".to_string();
        assert!(cfg.ipv6_manual_addr().is_none());
    }

    #[test]
    fn test_ddns_invalid_mode_rejected() {
        // 非法 mode 值 → 配置加载失败（拒绝，不静默回退）（WBS 2.3「非法值拒绝」）。
        let dir = std::env::temp_dir().join("kirin_desk_test_ddns_bad_mode");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"d\"\nname = \"D\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\n\
             [logging]\n\
             [ddns]\nipv4_mode = \"banana\"\n",
        )
        .unwrap();
        assert!(Config::load_from(&path).is_err(), "非法模式必须拒绝");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ddns_roundtrip() {
        // 完整 [ddns] 段读写往返（模式/地址/开关/周期全部保持）。
        let dir = std::env::temp_dir().join("kirin_desk_test_ddns_rt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ddns.toml");
        let mut cfg = Config::default();
        cfg.ddns.enabled = true;
        cfg.ddns.interval_secs = Some(180);
        cfg.ddns.ipv4_mode = DdnsMode::Manual;
        cfg.ddns.ipv4_manual = "203.0.113.9".to_string();
        cfg.ddns.ipv6_mode = DdnsMode::Manual;
        cfg.ddns.ipv6_manual = "2001:db8::9".to_string();
        cfg.ddns.publish_aaaa = false;
        cfg.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.ddns.enabled);
        assert_eq!(loaded.ddns.interval_secs, Some(180));
        assert_eq!(loaded.ddns.ipv4_mode, DdnsMode::Manual);
        assert_eq!(loaded.ddns.ipv4_manual, "203.0.113.9");
        assert_eq!(loaded.ddns.ipv6_mode, DdnsMode::Manual);
        assert_eq!(loaded.ddns.ipv6_manual, "2001:db8::9");
        assert!(loaded.ddns.publish_srv);
        assert!(!loaded.ddns.publish_aaaa);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ddns_legacy_toml_missing_section() {
        // 旧配置无 [ddns] 段 → 加载不失败，默认值兜底（追加式兼容）。
        let dir = std::env::temp_dir().join("kirin_desk_test_ddns_legacy");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"old-device\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\nencoder = \"auto\"\nframerate = 30\nbitrate = 5000\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(!loaded.ddns.enabled);
        assert_eq!(loaded.ddns.ipv4_mode, DdnsMode::Auto);
        assert_eq!(loaded.ddns.ipv4_sources.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dns_security_defaults() {
        // [dns.security] 缺省：enforce + 三组 DoH/DoT 端点 + 超时/缓存默认值。
        let sec = DnsSecurityConfig::default();
        assert!(sec.enforce());
        assert_eq!(sec.doh.len(), 3);
        assert_eq!(sec.doh[0], "https://cloudflare-dns.com/dns-query");
        assert_eq!(sec.dot.len(), 3);
        assert_eq!(sec.dot[0], "1.1.1.1:853");
        assert_eq!(sec.resolve_timeout_ms, 5000);
        assert_eq!(sec.cache_ttl_secs, 50);
    }

    #[test]
    fn test_dns_security_mode_off() {
        // mode = "off"（大小写不敏感）→ 不强制；未知值 → 安全默认 enforce。
        let sec = DnsSecurityConfig {
            mode: "off".to_string(),
            ..DnsSecurityConfig::default()
        };
        assert!(!sec.enforce());
        let sec = DnsSecurityConfig {
            mode: "OFF".to_string(),
            ..DnsSecurityConfig::default()
        };
        assert!(!sec.enforce());
        let sec = DnsSecurityConfig {
            mode: "weird".to_string(),
            ..DnsSecurityConfig::default()
        };
        assert!(sec.enforce(), "未知 mode 按 enforce 处理，不静默关闭");
    }

    #[test]
    fn test_dns_security_roundtrip_and_legacy() {
        // [dns.security] 显式配置往返 + 旧配置缺段兜底。
        let dir = std::env::temp_dir().join("kirin_desk_test_sec_rt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sec.toml");
        let mut cfg = Config::default();
        cfg.dns.security.mode = "off".to_string();
        cfg.dns.security.doh = vec!["https://dns.example.com/resolve".to_string()];
        cfg.dns.security.resolve_timeout_ms = 3000;
        cfg.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(!loaded.dns.security.enforce());
        assert_eq!(loaded.dns.security.doh.len(), 1);
        assert_eq!(loaded.dns.security.resolve_timeout_ms, 3000);
        assert_eq!(loaded.dns.security.cache_ttl_secs, 50, "未设置字段取默认");

        // 旧配置无 [dns.security] → enforce 默认（需求 §5.3 安全默认）。
        let legacy = dir.join("legacy.toml");
        std::fs::write(
            &legacy,
            "[device]\nid = \"old\"\nname = \"Old\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [dns]\nprovider = \"godaddy\"\n\
             [network]\nport = 3389\n\
             [media]\n\
             [logging]\n",
        )
        .unwrap();
        let loaded2 = Config::load_from(&legacy).unwrap();
        assert!(loaded2.dns.security.enforce());
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// 每测试独立临时根目录（并行测试互不干扰；不触碰真实用户配置）。
    fn r13b_temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_r13b_{}_{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 构造带真实敏感值的完整配置。
    fn r13b_config_with_secrets() -> Config {
        let mut cfg = Config::default();
        cfg.godaddy.api_key = "gd-key-123".to_string();
        cfg.godaddy.api_secret = "gd-secret-456".to_string();
        cfg.tunnel.token = "tunnel-token-789".to_string();
        cfg.device.challenge_code = "challenge-abc".to_string();
        cfg.dns.providers.insert(
            "cloudflare".to_string(),
            [("api_token".to_string(), "cf-token-111".to_string())]
                .into_iter()
                .collect(),
        );
        cfg.dns.providers.insert(
            "azure".to_string(),
            [
                ("tenant_id".to_string(), "t-id".to_string()),
                ("client_secret".to_string(), "az-secret-222".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        cfg.dns.providers.insert(
            "westcn".to_string(),
            [
                ("username".to_string(), "wc-user".to_string()),
                ("api_password".to_string(), "wc-pass-333".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        cfg
    }

    #[test]
    fn test_r13b_sensitive_fields_roundtrip_encrypted() {
        let dir = r13b_temp_dir("roundtrip");
        let path = dir.join("test.toml");
        let cfg = r13b_config_with_secrets();
        cfg.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.godaddy.api_key, "gd-key-123");
        assert_eq!(loaded.godaddy.api_secret, "gd-secret-456");
        assert_eq!(loaded.tunnel.token, "tunnel-token-789");
        assert_eq!(loaded.device.challenge_code, "challenge-abc");
        assert_eq!(
            loaded.dns.providers["cloudflare"].get("api_token").map(String::as_str),
            Some("cf-token-111")
        );
        assert_eq!(
            loaded.dns.providers["azure"].get("client_secret").map(String::as_str),
            Some("az-secret-222")
        );
        assert_eq!(
            loaded.dns.providers["westcn"].get("api_password").map(String::as_str),
            Some("wc-pass-333")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r13b_no_plaintext_on_disk() {
        let dir = r13b_temp_dir("noplain");
        let path = dir.join("test.toml");
        let cfg = r13b_config_with_secrets();
        cfg.save_to(&path).unwrap();
        // 首次加载：旧 [godaddy] 段有凭据 → 迁移到 [dns.providers.godaddy]
        // 并加密写回（S2 路径）。加载完成后文件内容即最终形态。
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.godaddy.api_key, "gd-key-123");
        let raw = std::fs::read_to_string(&path).unwrap();
        // 敏感明文值零命中（落盘形态验收）。
        for secret in [
            "gd-key-123",
            "gd-secret-456",
            "tunnel-token-789",
            "challenge-abc",
            "cf-token-111",
            "az-secret-222",
            "wc-pass-333",
        ] {
            assert!(!raw.contains(secret), "明文泄露: {secret}");
        }
        // 敏感 key 值均为密文格式。
        assert!(raw.contains("api_key = \"{v:"));
        assert!(raw.contains("api_secret = \"{v:"));
        assert!(raw.contains("token = \"{v:"));
        assert!(raw.contains("challenge_code = \"{v:"));
        assert!(raw.contains("api_token = \"{v:"));
        assert!(raw.contains("client_secret = \"{v:"));
        assert!(raw.contains("api_password = \"{v:"));
        // 非敏感 key 保持明文可读（设计：标识字段不入加密域）。
        assert!(raw.contains("tenant_id = \"t-id\""));
        assert!(raw.contains("username = \"wc-user\""));
        // 二次加载幂等：不再重写文件（内容稳定）。
        let _ = Config::load_from(&path).unwrap();
        let raw2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw2, raw, "密文配置二次加载不重写（幂等）");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r13b_legacy_plaintext_auto_migrates_on_load() {
        let dir = r13b_temp_dir("migrate");
        let path = dir.join("legacy.toml");
        // 旧明文配置（含旧 [godaddy] 段明文 + [dns.providers.cloudflare] 明文）。
        std::fs::write(
            &path,
            "[device]\nid = \"dev-1\"\nname = \"Old\"\nchallenge_code = \"legacy-challenge\"\n\
             [godaddy]\napi_key = \"legacy-key\"\napi_secret = \"legacy-secret\"\n\
             domain = \"example.com\"\n\
             [dns]\nprovider = \"godaddy\"\n\
             [dns.providers.cloudflare]\napi_token = \"cf-legacy-token\"\n\
             [network]\nport = 3389\n\
             [media]\n\
             [logging]\n",
        )
        .unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.device.challenge_code, "legacy-challenge");
        assert_eq!(loaded.godaddy.api_key, "legacy-key");
        assert_eq!(loaded.godaddy.api_secret, "legacy-secret");
        assert_eq!(
            loaded.dns.providers["cloudflare"].get("api_token").map(String::as_str),
            Some("cf-legacy-token")
        );
        // 迁移：旧 [godaddy] → [dns.providers.godaddy]（内存态）。
        assert_eq!(
            loaded.dns.providers["godaddy"].get("api_key").map(String::as_str),
            Some("legacy-key")
        );
        // 落盘已被自动加密重写：无明文、密文格式。
        let raw = std::fs::read_to_string(&path).unwrap();
        for secret in ["legacy-key", "legacy-secret", "cf-legacy-token", "legacy-challenge"] {
            assert!(!raw.contains(secret), "迁移后明文残留: {secret}");
        }
        assert!(raw.contains("{v:"));
        // 幂等：二次加载不再重写（文件内容稳定）。
        let _ = Config::load_from(&path).unwrap();
        let raw2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw2, raw);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r13b_empty_plaintext_rewrite_backfills_device_id() {
        // 首载的唯一写盘理由——文件被重写（落盘含派生短码 + 敏感字段统一
        // `{v:}` 密文形态、无明文残留），二次加载幂等（不再重写）。
        let dir = r13b_temp_dir("empty_r76c");
        let path = dir.join("template.toml");
        let content = "[device]\nid = \"\"\nname = \"My Device\"\nchallenge_code = \"\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [dns]\nprovider = \"godaddy\"\n\
             [network]\nport = 3389\n\
             [media]\n\
             [logging]\n";
        std::fs::write(&path, content).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.godaddy.api_key.is_empty());
        assert!(loaded.tunnel.token.is_empty());
        assert!(!loaded.device.id.is_empty(), "空 device.id 应派生短码");
        assert!(!crate::device::id_is_auto(&loaded.device.id));
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains(&loaded.device.id), "落盘应含派生短码");
        assert!(!after.contains("challenge_code = \"\""), "空敏感字段亦为 {{v:}} 密文形态");
        // 幂等：二次加载不再重写（device.id 已显式 + 无明文/迁移触发）。
        let _ = Config::load_from(&path).unwrap();
        let raw2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw2, after, "二次加载应幂等（不重写）");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r13b_decrypt_wrong_key_fails_closed() {
        // 密文配置 + 密钥不匹配（主密钥变更/丢失场景）→ 加载 fail-closed。
        let dir = r13b_temp_dir("wrongkey");
        let path = dir.join("bad.toml");
        // 用固定密钥 [9u8;32] 加密（与 DPAPI 随机主密钥必然不同）。
        let ct = crate::secure::encrypt_to_string(&[9u8; 32], "some-key", "godaddy.api_key")
            .unwrap();
        std::fs::write(
            &path,
            format!(
                "[device]\nid = \"d\"\nname = \"D\"\n\
                 [godaddy]\napi_key = \"{ct}\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
                 [network]\nport = 3389\n\
                 [media]\n\
                 [logging]\n"
            ),
        )
        .unwrap();
        let err = Config::load_from(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Decrypt { .. }), "must fail-closed: {err}");
        assert!(err.to_string().contains("godaddy.api_key"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r13b_corrupt_ciphertext_fails_closed() {
        let dir = r13b_temp_dir("corrupt");
        let path = dir.join("bad.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"d\"\nname = \"D\"\n\
             [godaddy]\napi_key = \"{v:!!!not-base64!!!}\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\nport = 3389\n\
             [media]\n\
             [logging]\n",
        )
        .unwrap();
        let err = Config::load_from(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Decrypt { .. }), "must fail-closed: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r13b_sensitive_key_list_covers_registry_secret_fields() {
        // drift 守护：dns_providers 注册表中 secret: true 的字段 key 必须全部
        // 在 SENSITIVE_DNS_FIELD_KEYS 内（新增服务商密文字段漏登记会明文落盘）。
        for def in crate::dns_providers::dns_provider_defs() {
            for field in def.fields {
                if field.secret {
                    assert!(
                        SENSITIVE_DNS_FIELD_KEYS.contains(&field.key),
                        "注册表 secret 字段 {} 未入加密域（{}）",
                        field.key,
                        def.id
                    );
                }
            }
        }
    }

    #[test]
    fn test_r13b_challenge_code_and_tunnel_roundtrip_via_legacy_path() {
        // 全空配置保存 → 敏感字段以密文落盘（空串也加密，不泄露「是否已填」），
        // 加载后仍为空串。
        let dir = r13b_temp_dir("empty_save");
        let path = dir.join("test.toml");
        let cfg = Config::default();
        cfg.save_to(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("challenge_code = \"{v:"));
        assert!(raw.contains("token = \"{v:"));
        let loaded = Config::load_from(&path).unwrap();
        assert!(loaded.device.challenge_code.is_empty());
        assert!(loaded.tunnel.token.is_empty());
        assert!(loaded.godaddy.api_key.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r13b_dns_provider_godaddy_fields_all_encrypted() {
        // [dns.providers.godaddy] 的 api_key/api_secret 与 [godaddy] 段同入加密域。
        let dir = r13b_temp_dir("gdmap");
        let path = dir.join("test.toml");
        let mut cfg = Config::default();
        cfg.dns.providers.insert(
            "godaddy".to_string(),
            [
                ("api_key".to_string(), "map-key".to_string()),
                ("api_secret".to_string(), "map-secret".to_string()),
                ("api_url".to_string(), "https://api.godaddy.com".to_string()),
                ("domain".to_string(), "example.com".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        cfg.save_to(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("map-key"));
        assert!(!raw.contains("map-secret"));
        assert!(raw.contains("api_url = \"https://api.godaddy.com\""), "api_url 非敏感保持明文");
        assert!(raw.contains("domain = \"example.com\""));
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(
            loaded.dns.providers["godaddy"].get("api_key").map(String::as_str),
            Some("map-key")
        );
        assert_eq!(
            loaded.dns.providers["godaddy"].get("api_secret").map(String::as_str),
            Some("map-secret")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// 其它错误必须 false（那些场景首启兜底不得创建默认文件覆盖救场）。
    #[test]
    fn test_r55_is_not_found_only_for_missing_file() {
        let dir = r13b_temp_dir("r55_notfound");
        let missing = dir.join("no_such_file.toml");
        let err = Config::load_from(&missing).unwrap_err();
        assert!(err.is_not_found(), "missing file must be is_not_found: {err}");

        let bad = dir.join("bad.toml");
        std::fs::write(&bad, "not = valid toml {{{").unwrap();
        let err = Config::load_from(&bad).unwrap_err();
        assert!(!err.is_not_found(), "parse error must NOT be is_not_found: {err}");

        // 逻辑非磁盘：Decrypt / SerializeError / NoHomeDir 一律 false。
        let e = ConfigError::Decrypt {
            field: "tunnel.token".to_string(),
            reason: "test".to_string(),
        };
        assert!(!e.is_not_found());
        assert!(!ConfigError::NoHomeDir.is_not_found());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// （消除「Client 高亮却显示 Server 表单」双面界面的磁盘侧来源）。
    #[test]
    fn test_r55_load_from_normalizes_empty_tunnel_mode() {
        let dir = r13b_temp_dir("r55_mode");
        let path = dir.join("empty_mode.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"d\"\nname = \"D\"\n\
             [godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n\
             [network]\n\
             [media]\n\
             [logging]\n\
             [tunnel]\nmode = \"\"\n",
        )
        .unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.tunnel.mode, "client");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r55_effective_mode_empty_falls_back_to_client() {
        let mut t = TunnelConfig::default();
        t.mode = String::new();
        assert_eq!(t.effective_mode(), "client");
        t.mode = "   ".to_string();
        assert_eq!(t.effective_mode(), "client");
        t.mode = "server".to_string();
        assert_eq!(t.effective_mode(), "server");
        t.mode = "client".to_string();
        assert_eq!(t.effective_mode(), "client");
    }

    // parse_node_share_json / node_share_json / json_str 及导入矩阵、
    // 分享往返测试随死码退役（量化面见交付报告）；`validate_node_server_addr`
    // 保留（新添加表单地址校验复用）。

    /// 32 字节 Ed25519 公钥的 base64 STANDARD 形态（44 字符，与
    /// `[tunnel] server_pubkey` 同口径）。
    fn r71b_pubkey() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([7u8; 32])
    }

    fn r71b_node(name: &str) -> NodeConfig {
        NodeConfig {
            name: name.to_string(),
            server_addr: "relay.example.com:7000".to_string(),
            token: "tok-123".to_string(),
            server_pubkey: r71b_pubkey(),
            note: String::new(),
        }
    }

    #[test]
    fn test_r71b_nodes_default_empty_and_legacy_toml() {
        // 反序列化兼容：Config::default() 空列表；旧配置无 [nodes] 段 → 空。
        assert!(Config::default().nodes.is_empty());
        let dir = r13b_temp_dir("r71b_legacy");
        let path = dir.join("legacy.toml");
        std::fs::write(
            &path,
            "[device]\nid = \"dev-1\"\nname = \"Old\"\n[godaddy]\napi_key = \"\"\napi_secret = \"\"\ndomain = \"example.com\"\n[network]\n[media]\n[logging]\n",
        )
        .unwrap();
        let cfg = Config::load_from(&path).unwrap();
        assert!(cfg.nodes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r71b_nodes_toml_roundtrip_and_token_encrypted() {
        let dir = r13b_temp_dir("r71b_rt");
        let path = dir.join("test.toml");
        let mut cfg = Config::default();
        let stored = cfg.node_add(r71b_node("home-relay")).unwrap();
        cfg.save_to(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("[[nodes]]"), "应序列化为 [[nodes]] 数组表");
        // 非敏感展示字段明文可读。
        assert!(raw.contains("name = \"home-relay\""));
        assert!(raw.contains("server_addr = \"relay.example.com:7000\""));
        assert!(raw.contains("server_pubkey = \""));
        // token 入加密域（与 [tunnel] token 同口径：落盘无明文 + {v: 密文格式）。
        assert!(!raw.contains("tok-123"), "node token 明文泄露落盘");
        assert!(raw.contains("token = \"{v:"), "node token 应为密文形态");
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.nodes, vec![stored]);
        // 加载起幂等（不重写）。
        let raw_after_first = std::fs::read_to_string(&path).unwrap();
        assert!(!loaded.device.id.is_empty(), "空 device.id 应派生短码");
        assert!(raw_after_first.contains(&loaded.device.id), "首载回写应含短码");
        let _ = Config::load_from(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), raw_after_first, "密文配置二次加载不重写");
        // 指纹 = known_hosts::fingerprint 同口径（79 字符 / 16 组 4 hex）。
        let fp = loaded.nodes[0].fingerprint();
        assert_eq!(fp.len(), 79, "指纹应为 79 字符: {fp}");
        assert_eq!(fp.split(':').count(), 16);
        assert_eq!(loaded.nodes[0].fingerprint_short(), fp.chars().take(8).collect::<String>());
        // 与 known_hosts::fingerprint 直接对拍（同源函数双保险）。
        assert_eq!(
            loaded.nodes[0].fingerprint(),
            crate::known_hosts::fingerprint(&loaded.nodes[0].server_pubkey)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_r71b_nodes_dedup_name_and_triple() {
        let mut cfg = Config::default();
        let a = r71b_node("n1");
        cfg.node_add(a.clone()).unwrap();
        // ① name 冲突 → NameExists。
        assert_eq!(
            cfg.node_add(r71b_node("n1")).unwrap_err(),
            NodeAddError::NameExists("n1".into())
        );
        // ② 三件套冲突（不同名，同 addr+token+pubkey）→ TripleExists。
        let mut b = r71b_node("n2");
        b.server_addr = a.server_addr.clone();
        b.token = a.token.clone();
        b.server_pubkey = a.server_pubkey.clone();
        assert_eq!(
            cfg.node_add(b).unwrap_err(),
            NodeAddError::TripleExists("n1".into())
        );
        // ③ 同服务器不同 token → 不同凭据条目，允许共存。
        let mut c = r71b_node("n3");
        c.token = "tok-other".into();
        assert!(cfg.node_add(c).is_ok());
        // ④ 空 name → 自动派生（node-{host}；同 host 冲突递增，两派生名互异）。
        let mut d0 = r71b_node("");
        d0.server_addr = "other.example.com:7000".into();
        let stored_d = cfg.node_add(d0).unwrap();
        assert!(!stored_d.name.is_empty());
        assert_eq!(stored_d.name, "node-other.example.com", "派生名应含 host");
        let mut e0 = r71b_node("");
        e0.server_addr = "other.example.com:7000".into();
        e0.token = "tok-e".into(); // 不同凭据，避开三件套去重
        let stored_e = cfg.node_add(e0).unwrap();
        assert_eq!(stored_e.name, "node-other.example.com-2", "同 host 第二次派生应递增");
        assert_ne!(stored_d.name, stored_e.name, "两次派生名应互异");
        assert!(cfg.node_get(&stored_d.name).is_some());
        // ⑤ update：改 note 命中；改三件套撞 n1 → TripleExists。
        let mut f = stored_d.clone();
        f.note = "changed".into();
        cfg.node_update(&stored_d.name, f.clone()).unwrap();
        assert_eq!(cfg.node_get(&stored_d.name).unwrap().note, "changed");
        let mut g = stored_d.clone();
        g.server_addr = "relay.example.com:7000".into();
        g.token = "tok-123".into();
        g.server_pubkey = r71b_pubkey();
        // 注：stored_d 派生自 r71b_node 基线 → 该三件套与 n1 同 → 撞。
        assert!(matches!(cfg.node_update(&stored_d.name, g), Err(NodeAddError::TripleExists(_))));
        // ⑥ update 不存在的名 → NotFound。
        assert!(matches!(cfg.node_update("ghost", r71b_node("x")), Err(NodeAddError::NotFound(_))));
        // ⑦ remove：命中返回条目；未命中 None。
        let removed = cfg.node_remove(&stored_d.name).unwrap();
        assert_eq!(removed.name, stored_d.name);
        assert!(cfg.node_get(&stored_d.name).is_none());
        assert!(cfg.node_remove("nope").is_none());
        assert_eq!(cfg.nodes_list().len(), 3); // n1 + n3 + stored_e
    }

    #[test]
    fn test_r149_nodes_limit_15() {
        let mut cfg = Config::default();
        // ① 第 15 条成功（14 条存量 + 新增第 15 条）。
        for i in 0..14 {
            let mut n = r71b_node(&format!("n{i:02}"));
            n.server_addr = format!("relay{i}.example.com:7000");
            cfg.node_add(n).unwrap();
        }
        let mut n15 = r71b_node("n14");
        n15.server_addr = "relay14.example.com:7000".into();
        assert!(cfg.node_add(n15).is_ok(), "第 15 条应成功");
        assert_eq!(cfg.nodes_list().len(), NODES_MAX_ENTRIES);
        // ② 第 16 条 = LimitExceeded（明确错误、不落库）。
        let mut n16 = r71b_node("n15");
        n16.server_addr = "relay15.example.com:7000".into();
        match cfg.node_add(n16) {
            Err(NodeAddError::LimitExceeded { limit }) => assert_eq!(limit, NODES_MAX_ENTRIES),
            other => panic!("期望 LimitExceeded，实得 {other:?}"),
        }
        assert_eq!(cfg.nodes_list().len(), NODES_MAX_ENTRIES, "拒绝不落库");
        // ③ 去重错误优先于上限：撞三件套仍报 TripleExists（存量满时）。
        // n00 地址 = format!("relay{i}…") i=0 → "relay0."（无补零）。
        let mut dup = r71b_node("dup");
        dup.server_addr = "relay0.example.com:7000".into(); // 与 n00 三件套一致
        assert_eq!(cfg.node_add(dup).unwrap_err(), NodeAddError::TripleExists("n00".into()));
        // ④ 删除腾出名额 → 可再加。
        cfg.node_remove("n00").unwrap();
        let mut n16b = r71b_node("n15");
        n16b.server_addr = "relay15.example.com:7000".into();
        assert!(cfg.node_add(n16b).is_ok(), "删除后应可再加");
        assert_eq!(cfg.nodes_list().len(), NODES_MAX_ENTRIES);
        // ⑤ 存量超 15 不回删：15 条经 node_add + 第 16 条直接构造（历史
        // 存量超上限形态）仍全部保留，且再新增被拒（只拦新增面，不回删面）。
        let mut legacy = Config::default();
        for i in 0..15 {
            let mut n = r71b_node(&format!("legacy{i}"));
            n.server_addr = format!("legacy{i}.example.com:7000");
            legacy.node_add(n).unwrap();
        }
        legacy.nodes.push(r71b_node("legacy-extra")); // 直接构造第 16 条（存量超上限形态）
        assert_eq!(legacy.nodes_list().len(), 16, "存量超上限不回删");
        let mut extra2 = r71b_node("legacy-extra2");
        extra2.server_addr = "legacy-extra2.example.com:7000".into();
        assert!(matches!(
            legacy.node_add(extra2),
            Err(NodeAddError::LimitExceeded { .. })
        ));
        assert_eq!(legacy.nodes_list().len(), 16, "存量条数不变");
        // ⑥ 上限常量与服务端同值（双侧执法单一口径）。
        assert_eq!(NODES_MAX_ENTRIES, 15);
    }

    #[test]
    fn test_r71b_validate_server_addr() {
        for ok in [
            "relay.example.com:7000",
            "1.2.3.4:7000",
            "[::1]:7000",
            " [fe80::1]:7001 ",
            "host.example:65535",
        ] {
            assert!(validate_node_server_addr(ok).is_ok(), "应接受: {ok}");
        }
        for bad in [
            "", "   ", "host", "host:", ":7000", "host:0", "host:99999", "host:port",
            "a:b:7000", "[::1]7000", "host :7000", "ho st:7000",
        ] {
            assert!(validate_node_server_addr(bad).is_err(), "应拒绝: {bad:?}");
        }
    }

}

// ════════════════════════════════════════════════════════════════
// （用户 09-22 三轮复测 §9：单键笔误不得阻塞启动/连接初始化）
// ════════════════════════════════════════════════════════════════
#[cfg(test)]
mod r134_2_tests {
    use super::*;

    /// 宽松值域矩阵（卡内：on/off/1/0/TRUE/CASE 变体 + 域外回退）。
    #[test]
    fn r134_2_lenient_bool_matrix() {
        for (t, want) in [
            ("true", true),
            ("false", false),
            ("on", true),
            ("off", false),
            ("1", true),
            ("0", false),
            ("TRUE", true),
            ("False", false),
            ("On", true),
            ("OFF", false),
            ("  tRue  ", true), // trim 容差
        ] {
            assert_eq!(lenient_debug_bool(t), Some(want), "token {t:?}");
        }
        // 域外值 = None（回退默认 + WARN，不阻塞）
        for bad in ["banana", "yes", "no", "2", "-1", "truee", "", " on extra", "0x1", "null"] {
            assert_eq!(lenient_debug_bool(bad), None, "域外 {bad:?} 必回退");
        }
    }

    /// 值归一：注释剥离（引号感知）+ 引号剥离。
    #[test]
    fn r134_2_strip_toml_value() {
        assert_eq!(strip_toml_value("on"), "on");
        assert_eq!(strip_toml_value("on # comment"), "on");
        assert_eq!(strip_toml_value("\"on\""), "on");
        assert_eq!(strip_toml_value("\"on\" # c"), "on");
        assert_eq!(strip_toml_value("'off'"), "off");
        assert_eq!(strip_toml_value("# only comment"), "");
        assert_eq!(strip_toml_value("true"), "true");
        assert_eq!(strip_toml_value(" 1 "), "1");
    }

    /// WARN 行格式钉死（键名必带 = 复测对账锚点）。
    #[test]
    fn r134_2_warn_line_formats() {
        assert_eq!(
            r134_2_invalid_key_line("latency_trace", "banana"),
            "Config: [debug] latency_trace value 'banana' invalid (expected true/false/on/off/1/0, case-insensitive) — fallback to default (non-blocking)"
        );
        assert_eq!(
            r134_2_invalid_key_line("conn_stats_visible", "2"),
            "Config: [debug] conn_stats_visible value '2' invalid (expected true/false/on/off/1/0, case-insensitive) — fallback to default (non-blocking)"
        );
        assert_eq!(
            r134_2_unknown_key_line("foo"),
            "Config: [debug] unknown key 'foo' ignored (non-blocking)"
        );
        assert_eq!(
            r134_2_bad_line_line("[[["),
            "Config: [debug] unparseable line ignored (non-blocking): [[["
        );
        assert_eq!(
            r134_2_section_isolated_line(),
            "Config: [debug] section strict parse failed — section isolated, lenient/default applied; rest of config unaffected"
        );
    }

    /// 段定位：主段保全 + 段头变体 + 子表头不误命中。
    #[test]
    fn r134_2_split_debug_section() {
        let content = "[device]\nid = \"x\"\n\n[debug]\nlatency_trace = on\n\n[tunnel]\nmode = \"client\"\n";
        let (main, body) = split_debug_section(content).expect("[debug] 段必命中");
        assert!(!main.contains("[debug]"), "主段不得含 [debug]: {main}");
        assert!(main.contains("id = \"x\""), "前置段保全: {main}");
        assert!(main.contains("mode = \"client\""), "后置段保全: {main}");
        // 段体含段内空行（至下一段头前的全部行）→ 语义断言用 trim。
        assert_eq!(body.trim(), "latency_trace = on");
        // 无 [debug] 段 → None
        assert!(split_debug_section("[device]\nid = \"x\"\n").is_none());
        // 段头带尾随注释
        let (m2, b2) = split_debug_section("[debug] # c\nlatency_trace = off\n").expect("注释段头命中");
        assert!(m2.trim().is_empty(), "段头剥离: {m2:?}");
        assert_eq!(b2, "latency_trace = off");
        // 子表头 / 注释行不误命中
        assert!(split_debug_section("[debug.sub]\nx = 1\n").is_none());
        assert!(split_debug_section("# [debug]\nx = 1\n").is_none());
        // 段在文件尾（无后续段）
        let (m3, b3) = split_debug_section("[a]\nb = 1\n[debug]\nk = v\n").unwrap();
        assert!(m3.contains("b = 1") && !m3.contains("[debug]"), "{m3}");
        assert_eq!(b3, "k = v");
    }

    /// 段体宽松解析矩阵（各形态 → 期望值）。
    #[test]
    fn r134_2_parse_debug_lenient_matrix() {
        // 裸值 on（TOML 语法错形态）→ Some(true)
        assert_eq!(
            parse_debug_section_lenient("latency_trace = on\n").latency_trace,
            Some(true)
        );
        // 字符串 "on"（类型错形态）→ Some(true)
        assert_eq!(
            parse_debug_section_lenient("latency_trace = \"on\"\n").latency_trace,
            Some(true)
        );
        // off / 0 / 注释尾 / 大小写
        assert_eq!(
            parse_debug_section_lenient("latency_trace = off\n").latency_trace,
            Some(false)
        );
        assert_eq!(
            parse_debug_section_lenient("latency_trace = \"0\"\n").latency_trace,
            Some(false)
        );
        assert_eq!(
            parse_debug_section_lenient("latency_trace = OFF # c\n").latency_trace,
            Some(false)
        );
        assert_eq!(
            parse_debug_section_lenient("latency_trace = 1\n").latency_trace,
            Some(true)
        );
        // 域外值 → 默认 None（回退，不阻塞）
        assert_eq!(parse_debug_section_lenient("latency_trace = banana\n").latency_trace, None);
        // 混合：坏键不伤好键
        let c = parse_debug_section_lenient("latency_trace = \"on\"\nconn_stats_visible = 1\n");
        assert_eq!(c.latency_trace, Some(true));
        assert!(c.conn_stats_visible, "conn_stats_visible = 1 → true");
        // 全合法形态 = 严格解析（零行为变化）
        let c = parse_debug_section_lenient("latency_trace = true\nconn_stats_visible = false\n");
        assert_eq!(c.latency_trace, Some(true));
        assert!(!c.conn_stats_visible);
        // 段损坏（不可解析行）→ 默认 + 可解析键仍生效
        let c = parse_debug_section_lenient("[[[\nlatency_trace = on\n");
        assert_eq!(c.latency_trace, Some(true), "坏行忽略，好键宽松生效");
        assert!(!c.conn_stats_visible, "坏行不污染缺省");
        // 未知键 → 忽略（默认）
        let c = parse_debug_section_lenient("foo = bar\nlatency_trace = on\n");
        assert_eq!(c.latency_trace, Some(true));
        // 空段 → 默认
        let c = parse_debug_section_lenient("");
        assert_eq!(
            (c.latency_trace, c.conn_stats_visible),
            (None, false),
            "空段 → DebugConfig::default()（逐字段）"
        );
    }

    /// 出错键名提取（key_hint：错误行 `=` 前键名）。
    #[test]
    fn r134_2_key_hint_from_error() {
        // 语法错行 → 键名
        let content = "[network]\nport = notaport\n";
        let err = toml::from_str::<Config>(content).unwrap_err();
        assert_eq!(key_hint_from_error(content, &err).as_deref(), Some("port"));
        // 类型错行 → 键名
        let content = "[network]\nport = \"x\"\n";
        let err = toml::from_str::<Config>(content).unwrap_err();
        assert_eq!(key_hint_from_error(content, &err).as_deref(), Some("port"));
        // 无 `=` 行（段头类错误）→ None
        let err = toml::from_str::<DeviceConfig>("[\n").unwrap_err();
        assert!(key_hint_from_error("no equals line\n", &err).is_none());
    }

    /// 集成（核心门禁 = 「非法值不阻塞连接初始化」）：[debug] 段各损坏形态
    /// → 整份配置仍可用；主段损坏 → 仍 fail-closed + key_hint。
    /// 零触碰真配置：全程 std::env::temp_dir 隔离目录（与 r81e 同先例）。
    #[test]
    fn r134_2_debug_section_isolation_e2e() {
        let dir = std::env::temp_dir().join("kirin_desk_r134_2_iso");
        std::fs::create_dir_all(&dir).expect("隔离目录建目录");
        let path = dir.join("iso.toml");
        // 基线 = 一份全合法配置（latency_trace 置 Some(true) 保证落盘行在位
        // 可替换——Option::None 落盘形态不在本岗面，见交付报告遗留）。
        let mut base = Config::default();
        base.debug.latency_trace = Some(true);
        base.save_to(&path).expect("基线落盘");
        // 替换 `latency_trace` 行为指定坏形态（行级替换，不依赖落盘格式）。
        let break_latency = |new_line: &str| {
            let content = std::fs::read_to_string(&path).expect("读回");
            let out: String = content
                .lines()
                .map(|l| {
                    if l.trim_start().starts_with("latency_trace") {
                        new_line
                    } else {
                        l
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(&path, out).expect("写坏形态");
        };
        // ① 裸值 on（TOML 语法错形态）→ 整份 load 成功 + 宽松 Some(true)
        break_latency("latency_trace = on");
        let cfg = Config::load_from(&path).expect("[debug] 裸值不得拖垮整份配置");
        assert_eq!(cfg.debug.latency_trace, Some(true), "宽松解析 on = true");
        // ② 字符串 "on"（类型错形态）→ 成功 + Some(true)
        break_latency("latency_trace = \"on\"");
        let cfg = Config::load_from(&path).expect("[debug] 字符串 on 不得拖垮整份配置");
        assert_eq!(cfg.debug.latency_trace, Some(true));
        // ③ 域外值 → 成功 + 回退默认 None
        break_latency("latency_trace = banana");
        let cfg = Config::load_from(&path).expect("[debug] 域外值不得拖垮整份配置");
        assert_eq!(cfg.debug.latency_trace, None, "域外值 → 回退默认 None");
        // ④ 段损坏（值含非法字符）→ 成功 + DebugConfig::default()
        let content = std::fs::read_to_string(&path).expect("读回");
        std::fs::write(&path, content.replace("latency_trace = banana", "latency_trace = banana {{{"))
            .expect("写段损坏");
        let cfg = Config::load_from(&path).expect("[debug] 段损坏不得拖垮整份配置");
        assert_eq!(
            (cfg.debug.latency_trace, cfg.debug.conn_stats_visible),
            (None, false),
            "段损坏 → DebugConfig::default()（逐字段，DebugConfig 无 PartialEq）"
        );
        // ⑤ 主段损坏（[debug] 无关）→ 仍 fail-closed + key_hint 带键名
        //    （fail-closed 红线⑤不松：真损坏绝不静默放过）
        let content = std::fs::read_to_string(&path).expect("读回");
        let mut replaced = false;
        let out: String = content
            .lines()
            .map(|l| {
                if !replaced && l.trim_start().starts_with("id =") {
                    replaced = true;
                    String::from("id = ") // 空值 → TOML 语法错（[device] 首行）
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(replaced, "基线文件必有 device.id 行");
        std::fs::write(&path, out).expect("写主段损坏");
        match Config::load_from(&path) {
            Err(ConfigError::ParseError { key_hint, .. }) => {
                assert_eq!(key_hint.as_deref(), Some("id"), "key_hint = 出错行键名");
            }
            other => panic!("主段损坏必须 fail-closed，实际 {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// serde 缺省钉死——旧配置文件缺键 = `true`（禁止互控，fail-closed 安全
/// 缺省，与布尔 serde 惯例缺省 false 相反故必须显式钉测）；显式 `false`
/// = 关闭（双臂判定核恒放行，全链行为回退基线）。
#[cfg(test)]
mod r169_config_tests {
    use super::*;

    #[test]
    fn r169_forbid_mutual_control_default_true() {
        // 直解 `[tunnel]` 段结构（TunnelConfig）——空表 = 全缺键 → serde
        // default 面（含 forbid_mutual_control = true）。
        let cfg: TunnelConfig = toml::from_str("").expect("parse empty tunnel table");
        assert!(
            cfg.forbid_mutual_control,
            "缺键 = 禁止互控（fail-closed 安全缺省）"
        );
        let off: TunnelConfig =
            toml::from_str("forbid_mutual_control = false\n").expect("parse off");
        assert!(!off.forbid_mutual_control, "显式 false = 关闭（回退现状）");
        let on: TunnelConfig =
            toml::from_str("forbid_mutual_control = true\n").expect("parse on");
        assert!(on.forbid_mutual_control, "显式 true = 禁止");
        // Default impl 同口径（新构造 Config 缺省一致）。
        assert!(TunnelConfig::default().forbid_mutual_control);
        // 整表回环：serde 序列化含键（save 落盘后重读保值）。
        let s = toml::to_string(&on).expect("serialize");
        let back: TunnelConfig = toml::from_str(&s).expect("roundtrip");
        assert!(back.forbid_mutual_control);
    }
}
