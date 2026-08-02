use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// M15-T003: 白名单条目 — 域名模式 + 可选过期时间。
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

/// M8-T027 (SRV-IDWL-002): ID 白名单条目 — 设备 ID + 可选过期时间。
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

    /// Network settings
    pub network: NetworkConfig,

    /// Media settings
    pub media: MediaConfig,

    /// Logging settings
    pub logging: LoggingConfig,

    /// M15-T008: UI 外观设置（主题模式持久化）
    #[serde(default)]
    pub ui: UiConfig,

    /// M13-T005: 无人值守模式设置（`[unattended]` 段）
    #[serde(default)]
    pub unattended: UnattendedConfig,

    /// M13-T006: 文件传输设置（`[file_transfer]` 段）
    #[serde(default)]
    pub file_transfer: FileTransferConfig,

    /// M8-T025 P5-4: 传输设置（`[transport]` 段：QUIC 优先 → TCP 优雅降级）
    #[serde(default)]
    pub transport: TransportConfig,

    /// M8-T026: 内网穿透设置（`[tunnel]` 段：FRP 式通用 TCP 反向代理）
    #[serde(default)]
    pub tunnel: TunnelConfig,

    /// R-07-S4: 自动更新设置（`[update]` 段：更新通道）
    #[serde(default)]
    pub update: UpdateConfig,
}

/// R-07-S4: 自动更新配置（`[update]` 段）。
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

/// M8-T025 P5-4: 传输配置（`[transport]` 段，主文档 §3.6）。
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

/// M8-T026: 内网穿透配置（`[tunnel]` 段，FRP 式通用 TCP 反向代理）。
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
    // M8-T026-P2 设备 ID 模式字段（ID-001 / ID-SEC-001 / ID-005）
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
            port_range: default_tunnel_port_range(),
            heartbeat_interval: default_tunnel_heartbeat_interval(),
            heartbeat_timeout: default_tunnel_heartbeat_timeout(),
            pool_count: 0,
            max_pool_count: default_tunnel_max_pool_count(),
            proxies: Vec::new(),
            // M8-T026-P2：设备 ID 模式配置（默认关闭，None/空）。
            device_id: None,
            server_pubkey: None,
            extra_candidates: Vec::new(),
        }
    }
}

impl TunnelConfig {
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

/// M13-T006: 文件传输配置（`[file_transfer]` 段）。
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

impl Default for FileTransferConfig {
    fn default() -> Self {
        Self {
            download_dir: None,
            max_file_size: default_max_file_size(),
            session_max_bytes: default_session_max_bytes(),
            session_max_files: default_session_max_files(),
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

/// M13-T005: 无人值守模式配置（`[unattended]` 段）。
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
    #[serde(default = "default_auto_start_server")]
    pub auto_start_server: bool,
}

fn default_auto_start_server() -> bool {
    true
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

/// M15-T008: UI 外观配置（`[ui]` 段）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// 主题模式: "light"（默认）| "dark" | "system"
    #[serde(default = "default_theme")]
    pub theme: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: default_theme(),
        }
    }
}

fn default_theme() -> String {
    "light".to_string()
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

    /// Allowed domains whitelist (only these can connect)
    #[serde(default)]
    pub allowed_domains: Vec<String>,

    /// If true, allow IP-mode connections (bypass domain whitelist)
    #[serde(default)]
    pub ip_mode_allowed: bool,

    /// If true, skip whitelist check (temporary mode for headless servers)
    /// Allows any client to connect without domain whitelist approval.
    #[serde(default)]
    pub temp_mode: bool,

    /// M8-T017: 临时连接窗口时长（秒）。默认 300（5 分钟），可配置范围
    /// 60–3600——越界值经 [`NetworkConfig::effective_temp_mode_ttl`] 收敛。
    #[serde(default = "default_temp_mode_ttl_secs")]
    pub temp_mode_ttl_secs: u64,

    /// M15-T003: 白名单条目（模式 + 过期时间，`*.example.com` 通配支持）。
    /// 兼容旧 `allowed_domains`（无过期、永久有效），两者共同生效。
    #[serde(default)]
    pub whitelist: Vec<WhitelistEntry>,

    /// M8-T027 (SRV-IDWL-001): 设备 ID 白名单 — 永久精确条目（对称
    /// `allowed_domains`；GUI Settings 文本框 / `whitelist add-id` 写入，
    /// 与 known_clients 同 key，大小写敏感）。
    #[serde(default)]
    pub allowed_ids: Vec<String>,

    /// M8-T027 (SRV-IDWL-002): 设备 ID 白名单带过期条目（对称 `whitelist`，
    /// `whitelist add-id <id> <RFC3339>` 写入；到期自动失效，`prune_expired` 清理）。
    #[serde(default)]
    pub id_whitelist: Vec<IdWhitelistEntry>,
}

fn default_port() -> u16 {
    3389
}

fn default_heartbeat_interval() -> u64 {
    30
}

fn default_ttl() -> u32 {
    600
}

/// M8-T017: 临时连接窗口默认时长（5 分钟）。
fn default_temp_mode_ttl_secs() -> u64 {
    300
}

/// 临时连接窗口 TTL 可配置范围（SRV-TMP-004）。
pub const TEMP_MODE_TTL_MIN: u64 = 60;
pub const TEMP_MODE_TTL_MAX: u64 = 3600;

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

    /// M8-T030（R-06）：单 GPU 硬件加速与虚拟设备过滤（`[media.gpu]` 段）。
    /// 旧配置无此段 → 默认值，正常解析。
    #[serde(default)]
    pub gpu: GpuConfig,
}

/// M8-T030（R-06）：单 GPU 偏好（`[media.gpu]` 段，GPU-FR-009）。
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

    /// 覆盖默认黑名单关键词（空 = 用默认表，见 M8-T030 §3.3）。
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
                id: "default-device".to_string(),
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
            network: NetworkConfig {
                port: default_port(),
                heartbeat_interval: default_heartbeat_interval(),
                dns_ttl: default_ttl(),
                allowed_domains: Vec::new(),
                ip_mode_allowed: false,
                temp_mode: false,
                temp_mode_ttl_secs: default_temp_mode_ttl_secs(),
                whitelist: Vec::new(),
                allowed_ids: Vec::new(),
                id_whitelist: Vec::new(),
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
        }
    }
}

impl NetworkConfig {
    /// M8-T017: 临时连接窗口 TTL 收敛值（SRV-TMP-004，范围 60–3600）。
    /// 配置越界时静默收敛到边界，保证 `enable` 语义稳定。
    pub fn effective_temp_mode_ttl(&self) -> u64 {
        self.temp_mode_ttl_secs.clamp(TEMP_MODE_TTL_MIN, TEMP_MODE_TTL_MAX)
    }
}

impl Config {
    /// Load configuration from the default path
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::default_path()?;
        tracing::debug!("Config: loading from {:?}", path);
        let config = Self::load_from(&path);
        match &config {
            Ok(cfg) => tracing::info!(
                "Config loaded: device_id={}, domain={}, port={}, level={}",
                cfg.device.id, cfg.godaddy.domain, cfg.network.port, cfg.logging.level
            ),
            Err(e) => tracing::warn!("Config: failed to load from {:?}: {}", path, e),
        }
        config
    }

    /// Load configuration from a specific path
    pub fn load_from(path: &std::path::Path) -> Result<Self, ConfigError> {
        tracing::debug!("Config: reading from {:?}", path);
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError {
                path: path.to_path_buf(),
                detail: e.to_string(),
            })?;
        tracing::debug!("Config: successfully parsed from {:?}", path);
        Ok(config)
    }

    /// Save configuration to the default path
    pub fn save(&self) -> Result<(), ConfigError> {
        let path = Self::default_path()?;
        self.save_to(&path)
    }

    /// Save configuration to a specific path
    ///
    /// S-07 (F-8): 经 `fsutil::write_private` 落盘——Unix 0600 + 父目录 0700 +
    /// O_NOFOLLOW + 原子替换（config 含 challenge/token/GoDaddy 凭据，同机
    /// 低权限用户不可读）；父目录由 write_private 自动创建。
    pub fn save_to(&self, path: &std::path::Path) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;
        crate::fsutil::write_private(path, content.as_bytes())
            .map_err(|e| ConfigError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?;
        Ok(())
    }

    /// Get the default config directory path
    pub fn config_dir() -> Result<PathBuf, ConfigError> {
        let base = dirs_next::config_dir()
            .ok_or_else(|| ConfigError::NoHomeDir)?;
        Ok(base.join("kirin_desk"))
    }

    /// Get the default config file path
    fn default_path() -> Result<PathBuf, ConfigError> {
        Ok(Self::config_dir()?.join("default.toml"))
    }

    // ---------- M15-T003: 白名单管理（SRV-SEC-WL-001..004） ----------

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
    /// 白名单维度（M8-T027）；空行与 `#` 注释行跳过；非法行跳过并计入未导入数。
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
            // M8-T027 (CLI-IDWL-004)：`id:` 前缀行 → ID 白名单维度。
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

    // ---------- M8-T027: 设备 ID 白名单（SRV-IDWL-001..008） ----------

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
    },
    #[error("Serialization error: {0}")]
    SerializeError(String),
    #[error("No home/config directory found")]
    NoHomeDir,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.device.id, "default-device");
        assert_eq!(config.network.port, 3389);
        assert_eq!(config.godaddy.api_url, "https://api.godaddy.com");
    }

    #[test]
    fn test_config_roundtrip() {
        let config = Config::default();
        let dir = std::env::temp_dir().join("kirin_desk_test_config");
        let path = dir.join("test.toml");

        config.save_to(&path).expect("save should succeed");
        let loaded = Config::load_from(&path).expect("load should succeed");

        assert_eq!(loaded.device.id, config.device.id);
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

    // ---------- M8-T030（R-06）: 单 GPU 配置测试 ----------

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
        // 旧配置无 [media.gpu] 段 → 加载不失败，使用默认值（R-06 验收 §5）。
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

    // ---------- M8-T017: 临时连接 TTL 配置测试 ----------

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

    // ---------- M13-T005: 无人值守配置测试 ----------

    #[test]
    fn test_unattended_defaults() {
        let config = Config::default();
        assert!(!config.unattended.enabled);
        assert!(!config.unattended.auto_start_on_boot);
        assert!(config.unattended.auto_start_server);
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
        assert!(loaded.unattended.auto_start_server);
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
        assert!(loaded.unattended.auto_start_server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- M8-T026: 内网穿透配置测试 ----------

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

    #[test]
    fn test_default_toml_parses() {
        // 项目模板 config/default.toml（含新增 [tunnel] 段）必须可被 Config 解析，
        // 防止模板与结构体字段脱节。
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/default.toml");
        let cfg = Config::load_from(&path).expect("default.toml should parse");
        assert!(!cfg.tunnel.enabled);
        assert_eq!(cfg.tunnel.mode, "client");
        assert_eq!(cfg.tunnel.bind_port, 7000);
        assert_eq!(cfg.tunnel.heartbeat_interval, 10);
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
        let mut config = Config::default();
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
        let mut config = Config::default();
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

        let mut config = Config::default();
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
        let mut config2 = Config::default();
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
        let mut config = Config::default();
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

    // ---------- M8-T027: 设备 ID 白名单测试（SRV-IDWL-001..008） ----------

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

    #[test]
    fn test_id_whitelist_add_remove_and_expiry() {
        let mut config = Config::default();
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
        let mut config = Config::default();
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
        let mut config = Config::default();
        let imported = config.id_whitelist_import_csv(&csv).unwrap();
        assert_eq!(imported, 2); // 空 id 与非法时间戳行跳过
        assert!(config.id_whitelist_check("device-1"));
        assert!(config.id_whitelist_check("device-2"));
        assert!(!config.id_whitelist_check("device-3"));

        // 导出再导入到新配置（往返）。
        let out = dir.join("idwl_out.csv");
        config.id_whitelist_export_csv(&out).unwrap();
        let mut config2 = Config::default();
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
        let mut config = Config::default();
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
        let mut config2 = Config::default();
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
        let mut config = Config::default();
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

    // ---------- M13-T006 / S-10: 文件传输配额配置测试 ----------

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
}
