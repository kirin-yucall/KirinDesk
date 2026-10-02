//!
//! 复用边界（**不复制逻辑**）：
//! - 建链（地址直连）：`core::connection::client::{resolve_peer, connect_peer}`；
//! - 建链（ID 模式，P1-A）：`core::connection::id_mode::{IdConnector, IdModeConfig}`
//!   （解析 `relay::id_client::resolve_device_verified` 含 DeviceInfo 验签 +
//!   `run_client_session_by_id` 同一库层入口）；
//! - 传输：`media::transport::{SecureChannelSender, SecureChannelReceiver}`
//!   （TCP SecureChannel 收发半，与桌面 GUI 数据面同 wire）；
//! - 解码：`media::decoder::factory::create_video_decoder`（FFmpeg 动态加载，
//!   Android 分支见 T03）；
//! - 输入：`input::capture::InputEvent`（bincode wire，服务端零改动）；
//! - TOFU/历史存储：`utils::known_hosts`（三态 + 指纹）与 `utils::devices`
//!   （devices.json，桌面同格式）——KIRIN_DATA_DIR 已指向 app filesDir。
//!
//! 本层只新增：JNI 参数 → 连接模式判定（[`connect_mode`]）、设备 ID 输入
//! 两段式 JNI 状态机（[`trust_request_ui`]/[`trust_peek_pending`]/
//! [`trust_resolve_pending`]）、连接历史合并（[`history_entries`]）、
//! 接收循环瘦身版（Video tag → `DecoderPacket` → 解码 → 帧回调，无剪贴板/
//! 文件/音频/显示器 UI 状态）、输入事件映射（纯函数，Kotlin 手势 → wire）。
//! 对齐 ui/src/lib.rs `run_client_session_by_id`（4811 起）+
//! `run_client_session_with_stream`（3648 起）的最小子集。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use kirin_desk_core::connection::client::{
    resolve_peer, ConnectionOptions, ConnectError, ConnectOutcome, ResolvedPeer, TrustPolicy,
};
use kirin_desk_core::connection::file_transfer::{
    FileTransferFrame, DEFAULT_MAX_FILE_SIZE,
};
use kirin_desk_core::connection::id_mode::{IdConnectError, IdConnector, IdModeConfig};
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    client_handshake_with_resolution, PinExpectation,
};
use kirin_desk_input::injector::{
    button as wire_button, InputEvent as WireInputEvent, Key as WireKey,
};
use kirin_desk_media::decoder::factory::create_video_decoder;
use kirin_desk_media::decoder::{frame_id_to_pts, DecoderPacket, DecodedFrame};
use kirin_desk_media::encoder::types::{EncodedPacket, PacketKind, Timestamp};
use kirin_desk_media::proto::EncodedWindow;
use kirin_desk_media::transport::{ChannelTag, SecureChannelReceiver, SecureChannelSender};
use kirin_desk_relay::protocol::{is_fingerprint_device_id, DEVICE_SHORT_CODE_LEN};
use kirin_desk_utils::config::DEFAULT_NETWORK_PORT;
use kirin_desk_utils::devices::{DeviceConnMode, DeviceStore, SavedDevice};
use kirin_desk_utils::known_hosts::{
    fingerprint, FingerprintStatus, KnownHost, KnownHostsStore,
};

// ════════════════════════════════════════════════════════════════
// 纯函数层（宿主机单测覆盖）
// ════════════════════════════════════════════════════════════════

/// JNI `nativeConnect` 参数（会话组装前的纯数据）。
#[derive(Debug, Clone)]
pub struct MobileConnectParams {
    /// 目标显示名（地址模式 = 握手 server_id / known_hosts 记录键；ID 模式
    /// = 目标设备 ID：完整指纹 / 10 hex 短码 / 自定义显式 ID）。
    pub id: String,
    /// 本端昵称（服务端白名单/审计显示用；ID 模式兼作 devices.json 昵称）。
    pub nickname: String,
    /// 挑战码（服务端校验；空 = 无挑战语义）。
    pub challenge: String,
    /// 地址模式 = 目标 "host:port"；ID 模式 = relay 服务器 "host:port"
    /// （判定见 [`connect_mode`]；缺省端口 [`DEFAULT_NETWORK_PORT`]）。
    pub server_addr: String,
    /// relay token（P1-A：非空 ⇒ ID 模式，TNL-SEC-001）。
    pub token: String,
    /// 地址模式 = 目标带外可信公钥（base64；Some → `TrustPolicy::Verified`
    /// 强 pin，P0 语义不变）；ID 模式 = relay 服务器 Ed25519 公钥
    /// （ID-SEC-001 DeviceInfo 验签；**缺失 fail-closed 拒连**，对齐桌面
    /// ui/src/lib.rs `run_client_session_by_id` server_pubkey 口径）。
    pub server_pubkey: Option<String>,
    /// `device.example.com`——SRV/TXT/A|AAAA 三件套经加密 DNS（DoH/DoT）
    /// 发现，见 [`connect_and_run_domain`]）。显式字段而非按形态推断：
    /// 域名与 IP 直连共用「仅 server_addr 非空」形态，由用户在连接页
    /// Tab 显式选择（nativeConnect2 mode=2 置位；token/pubkey 忽略并清空）。
    pub domain: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectMode {
    /// P0 地址直连（server_addr = 目标 host:port，token 空）。
    AddressDirect,
    /// ID 模式（server_addr = relay 地址，token 非空；server_pubkey 必填）。
    IdMode,
    /// 加密 DNS 发现 SRV+TXT+A|AAAA 三件套后走地址直连同管线）。
    Domain,
}

/// 连接模式判定（纯函数）：`domain` 置位 ⇒ 域名模式（`server_addr` 必须
/// 非空，token 必须为空——域名模式不走 relay）；`token` 非空 ⇒ ID 模式
/// （`server_addr` 必须同时非空）；两者皆空 ⇒ 错误（地址模式至少要目标
/// 地址）；仅 `server_addr` 非空 ⇒ 地址直连（P0 向后兼容）。
pub fn connect_mode(server_addr: &str, token: &str, domain: bool) -> Result<ConnectMode, String> {
    let has_addr = !server_addr.trim().is_empty();
    let has_token = !token.trim().is_empty();
    if domain {
        if !has_addr {
            return Err("domain is empty".into());
        }
        if has_token {
            return Err("domain mode must not set a relay token".into());
        }
        return Ok(ConnectMode::Domain);
    }
    match (has_addr, has_token) {
        (false, false) => Err("server address is empty".into()),
        (false, true) => Err("relay server address is empty (token set)".into()),
        (true, false) => Ok(ConnectMode::AddressDirect),
        (true, true) => Ok(ConnectMode::IdMode),
    }
}

/// 解析目标地址 → (host, port)。端口缺省 [`DEFAULT_NETWORK_PORT`]；
/// IPv6 字面量剥 `[]`。返回 Err(人话原因) 当地址为空。
pub fn parse_server_addr(server_addr: &str) -> Result<(String, u16), String> {
    let s = server_addr.trim();
    if s.is_empty() {
        return Err("server address is empty".into());
    }
    // [v6]:port
    if let Some(rest) = s.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(format!("invalid IPv6 address literal: {s}"));
        };
        let port: u16 = port.parse().map_err(|_| format!("invalid port: {port}"))?;
        return Ok((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        // host:port：仅当全串只有一个冒号（多冒号 = IPv6 裸字面量，无端口；
        // 带端口的 IPv6 必须写 [v6]:port，走上一分支）。
        Some((host, port))
            if s.matches(':').count() == 1
                && !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            let port: u16 = port.parse().map_err(|_| format!("invalid port: {port}"))?;
            Ok((host.to_string(), port))
        }
        _ => Ok((s.to_string(), DEFAULT_NETWORK_PORT)),
    }
}


/// 域名模式错误码（错误串前缀 `domain:<code>:`，Kotlin 侧按码映射本地化
/// 文案，未识别码回退原始串）。
pub mod domain_err {
    /// 域名格式非法（不是合法主机名）。
    pub const INVALID_HOST: &str = "domain:invalid_host:";
    /// 域名不存在（DNS NXDOMAIN / Status=3 / RCODE=3）。
    pub const NXDOMAIN: &str = "domain:nxdomain:";
    /// 域名存在但无 A/AAAA 记录（或 SRV/TXT 指定记录缺失）。
    pub const NO_RECORDS: &str = "domain:no_records:";
    /// 无 SRV 记录（端口未知——目标未按域名模式发布服务）。
    pub const NO_SRV: &str = "domain:no_srv:";
    /// 无 TXT 记录 / TXT 无 Ed25519 公钥（CLI-DNS-006：缺失即拒，不回退
    /// 信任网络公钥）。
    pub const NO_TXT: &str = "domain:no_txt:";
    /// 加密 DNS 解析超时（全列表 15s）。
    pub const TIMEOUT: &str = "domain:timeout:";
    /// 加密 DNS 不可用（未配置 / 全端点失败；fail-closed，绝不回退明文）。
    pub const DNS_UNAVAILABLE: &str = "domain:dns_unavailable:";
}

/// 拼装域名模式错误串（纯函数）：`domain:<code>:<detail>`。
pub fn domain_error(code: &str, detail: impl std::fmt::Display) -> String {
    format!("{code}{detail}")
}

/// 解析器错误 → 域名错误码（纯函数）：NXDOMAIN 识别 DoH `Status=3` 与
/// DoT `RCODE=3` 文案；Timeout → 超时；全端点失败 → DNS 不可用；其余 →
/// NO_RECORDS 兜底（响应畸形等）。返回 `(code, 原始串)`。
pub fn classify_resolver_error(err: &kirin_desk_dns::ResolverError) -> (&'static str, String) {
    use kirin_desk_dns::ResolverError;
    match err {
        ResolverError::Timeout => (domain_err::TIMEOUT, err.to_string()),
        ResolverError::AllEndpointsFailed { .. } => {
            (domain_err::DNS_UNAVAILABLE, err.to_string())
        }
        other => {
            let s = other.to_string();
            if s.contains("Status=3") || s.contains("RCODE=3") {
                (domain_err::NXDOMAIN, s)
            } else {
                (domain_err::NO_RECORDS, s)
            }
        }
    }
}

/// 设备域名合法性校验 + 规整（纯函数）：去尾点/空白；要求 ≥2 个非空标签、
/// 每标签 1–63 字符、仅 ASCII 字母/数字/连字符且不以连字符开头结尾。
/// 返回规整后域名；非法 → None（IP 字面量/端口形态也拒——域名模式只吃
/// 主机名，地址直连走 Tab 1）。
pub fn validate_domain_host(raw: &str) -> Option<String> {
    let host = raw.trim().trim_end_matches('.');
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    // IP 字面量（v4/v6 裸形态）不是设备域名。
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let mut labels = 0usize;
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        let ok = label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return None;
        }
        labels += 1;
    }
    (labels >= 2).then(|| host.to_string())
}

/// SRV 查询名（纯函数）：`_remote._tcp.{host}`（与服务端发布口径一致，
/// core/src/dns.rs `server_dns_self_check` 同款命名）。
pub fn srv_query_name(host: &str) -> String {
    format!("_remote._tcp.{host}")
}

/// 域名模式解析产物（[`resolve_domain_peer`] 输出；纯数据可单测）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDomain {
    /// 连接地址（`"[v6]:port"` / `"v4:port"`；来自加密解析，IP 字面量）。
    pub addr: String,
    /// 连接端口（SRV 发现）。
    pub port: u16,
    /// TXT Ed25519 公钥（base64；TOFU/Exact pin 锚点）。
    pub pubkey: String,
    /// 设备类型（TXT DeviceMeta；缺省 "desktop"）。
    pub device_type: String,
}

/// 域名模式发现（SRV+TXT+A|AAAA 三件套，加密 DNS；注入 resolver 可单测）：
///
/// 1. SRV `_remote._tcp.{host}` → 端口（无 SRV → [`domain_err::NO_SRV`]）；
/// 2. TXT `{host}` → DeviceMeta Ed25519 公钥（缺失/无 key → [`NO_TXT`]
///    ——CLI-DNS-006 缺失即拒）；
/// 3. 地址解析收敛 `core::dns::resolve_for_connect` **唯一入口**（M8-T040
///    红线；A/AAAA 并行、Auto 族 v6 优先；空列表 → [`NO_RECORDS`]）。
///
/// 与桌面 Connect 页域名路径（ui/src/lib.rs 10542 起）的差异：桌面经
/// `[dns.providers.*]` 服务商管理 API 发现（需 zone 属主凭据，手机端无配置
/// 面）；本层同款记录三件套改经加密解析器（DoH/DoT）公开查询，红线
/// （禁止明文 DNS / 唯一解析入口）与信任锚（TXT 公钥 → TOFU → Exact pin）
/// 口径不变。域名模式的全部 DNS 查询走加密通道，fail-closed 不回退。
pub async fn resolve_domain_peer(
    host: &str,
    resolver: &dyn kirin_desk_dns::Resolver,
) -> Result<ResolvedDomain, String> {
    use kirin_desk_dns::{RecordData, RecordType};
    let host = validate_domain_host(host)
        .ok_or_else(|| domain_error(domain_err::INVALID_HOST, raw_trim(host)))?;
    // SRV + TXT 并行（同 DiscoveryService 四路并行口径的最小子集）。
    let srv_name = srv_query_name(&host);
    let (srv_res, txt_res) = tokio::join!(
        resolver.resolve(&srv_name, RecordType::SRV),
        resolver.resolve(&host, RecordType::TXT),
    );
    // SRV：首个记录的端口（桌面/服务端同款——SRV 列表按优先级排序，
    // 取 first）。
    let port = match srv_res {
        Ok(list) => list
            .iter()
            .find_map(|r| match &r.data {
                RecordData::Srv { port, .. } => Some(*port),
                _ => None,
            })
            .ok_or_else(|| {
                domain_error(domain_err::NO_SRV, format!("{} has no SRV record", host))
            })?,
        Err(e) => {
            let (code, detail) = classify_resolver_error(&e);
            return Err(domain_error(code, detail));
        }
    };
    // TXT：DeviceMeta 公钥（CLI-DNS-006：缺失即拒，不回退信任网络公钥）。
    let (pubkey, device_type) = match txt_res {
        Ok(list) => list
            .iter()
            .find_map(|r| match &r.data {
                RecordData::Plain(s) => kirin_desk_dns::DeviceMeta::from_txt(s).and_then(|m| {
                    m.raw_public_key().map(|k| (k.to_string(), m.device_type.clone()))
                }),
                _ => None,
            })
            .ok_or_else(|| {
                domain_error(
                    domain_err::NO_TXT,
                    format!("{} has no TXT record with an Ed25519 public key", host),
                )
            })?,
        Err(e) => {
            let (code, detail) = classify_resolver_error(&e);
            return Err(domain_error(code, detail));
        }
    };
    // 地址解析：收敛 core 唯一入口（A/AAAA 并行；Auto 族 v6 优先）。
    let addrs = kirin_desk_core::dns::resolve_for_connect(
        &host,
        port,
        kirin_desk_dns::IpFamily::Auto,
        resolver,
    )
    .await
    .map_err(|e| {
        // EncryptedDnsRequired（全端点失败/强制关闭）→ DNS 不可用；其余
        //（含 NXDOMAIN 形态的 DnsResolveFailed）走分类。
        let s = e.to_string();
        if matches!(e, ConnectError::EncryptedDnsRequired(_)) {
            domain_error(domain_err::DNS_UNAVAILABLE, s)
        } else if matches!(e, ConnectError::DnsResolveFailed { .. }) {
            // core map_resolver_error 已把 AllEndpointsFailed/Timeout 归
            // EncryptedDnsRequired；此处到达的多为响应畸形——按内容细分
            // NXDOMAIN。
            let code = if s.contains("Status=3") || s.contains("RCODE=3") {
                domain_err::NXDOMAIN
            } else {
                domain_err::NO_RECORDS
            };
            domain_error(code, s)
        } else {
            domain_error(domain_err::NO_RECORDS, s)
        }
    })?;
    let addr = addrs.first().map(|a| a.to_string()).ok_or_else(|| {
        domain_error(
            domain_err::NO_RECORDS,
            format!("{} has no A/AAAA record", host),
        )
    })?;
    Ok(ResolvedDomain {
        addr,
        port,
        pubkey,
        device_type,
    })
}

/// [`validate_domain_host`] 错误细节用：原始输入 trim + 去尾点（不复析）。
fn raw_trim(s: &str) -> String {
    s.trim().trim_end_matches('.').to_string()
}



/// 判断输入是否为「10 hex 短码形态」（输入面向：大小写均可，冒号/空白剔除
/// 后恰 [`DEVICE_SHORT_CODE_LEN`] 个 ASCII 十六进制字符；canonical 为小写
/// 指纹前缀）。与桌面 ui `is_short_code_shaped` 同口径。
pub fn is_short_code_shaped_input(s: &str) -> bool {
    let t: String = s
        .trim()
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    t.chars().count() == DEVICE_SHORT_CODE_LEN && t.chars().all(|c| c.is_ascii_hexdigit())
}

/// 设备 ID 输入统一归一化（连接与持久化同源，均经本函数；对齐桌面
///
/// - 指纹形态（去冒号/空白后 64 hex，任意大小写；复用 relay
///   `is_fingerprint_device_id` 判定）→ 小写 + 每 4 字符冒号分组重组
///   canonical 指纹串（与 relay 注册键 / known_hosts 键 / devices.json 键
///   一致）——抄录漏冒号/大写不再致命；
/// - 短码形态（单一大小写风格的 10 hex）→ 小写 canonical 短码；混合大小写
///   视为自定义显式 ID 原样保留（fail-closed，宁可不改写）；
/// - 其余（自定义显式 ID，大小写敏感）→ 仅 trim。
pub fn normalize_device_id_input(raw: &str) -> String {
    let t = raw.trim();
    if is_fingerprint_device_id(t) {
        let hex: String = t
            .chars()
            .filter(|c| !matches!(c, ':' | ' ' | '\t' | '\r' | '\n'))
            .flat_map(|c| c.to_lowercase())
            .collect();
        return hex
            .as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect::<Vec<_>>()
            .join(":");
    }
    // 短码形态（单一大小写风格的 10 hex）→ 小写 canonical 短码。
    if is_short_code_shaped_input(t) {
        let has_lower = t.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = t.chars().any(|c| c.is_ascii_uppercase());
        if !(has_lower && has_upper) {
            return t.to_lowercase();
        }
    }
    t.to_string()
}

/// 判定（归一化后的）输入是否为「短码发起的连接」——10 hex、非完整指纹、
/// 已是 canonical 小写。用于：短码未唯一命中的专用文案 + 首连确认窗的
/// 额外警示置位（铁律：短码对上不免确认）+ 解析成功后以服务器签名完整
/// ID 为一切持久化键（短码只用于寻址）。
pub fn is_short_code_connection_input(device_id: &str) -> bool {
    is_short_code_shaped_input(device_id)
        && !is_fingerprint_device_id(device_id)
        && device_id == device_id.to_lowercase()
}

// ── TOFU 三态 + 首连指纹确认（两段式 JNI 状态机） ──────────────────────────

/// known_hosts 三态 → 信任动作（纯函数；对齐桌面 `known_hosts_or_confirm`
/// 三态语义：Match 放行 / Mismatch 拒绝 / Unknown 走首次确认）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAction {
    /// 命中且一致 → 放行（后续以公钥 Exact pin 强制比对）。
    Allow,
    /// 命中但不一致 → **拒绝连接**（防 MITM，fail-closed，不是仅警告）。
    Reject,
    /// 未命中 → TOFU 首次指纹确认（上调 UI；拒绝/超时均按拒绝处理）。
    Confirm,
}

/// 信任决策（纯函数，供两段式状态机与单测复用；P0 的「Unknown 自动放行」
/// 已废除——P1-A 起未命中必须经用户确认）。
pub fn trust_decision(status: FingerprintStatus) -> TrustAction {
    match status {
        FingerprintStatus::Match => TrustAction::Allow,
        FingerprintStatus::Mismatch => TrustAction::Reject,
        FingerprintStatus::Unknown => TrustAction::Confirm,
    }
}

/// 待确认指纹提示（JNI `nativePeekPendingTrust` 上调 Kotlin 的纯数据）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPrompt {
    /// 目标设备 ID（完整 ID；地址模式 = server_id）。
    pub device_id: String,
    /// 完整 79 字符指纹（SHA-256 冒号分组；与被控端 Dashboard 显示一致）。
    pub fingerprint: String,
}

/// 指纹确认等待上限（超时 = 拒绝，fail-closed；弹窗被遗忘不会挂死连接）。
pub const TRUST_CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);

struct TrustState {
    /// 单调递增代次号（防止上一次连接的迟到 resolve 决定本次连接）。
    seq: u64,
    prompt: Option<(u64, TrustPrompt)>,
    decision: Option<(u64, bool)>,
}

fn trust_state() -> &'static Mutex<TrustState> {
    static S: OnceLock<Mutex<TrustState>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(TrustState {
            seq: 0,
            prompt: None,
            decision: None,
        })
    })
}

fn trust_condvar() -> &'static std::sync::Condvar {
    static CV: OnceLock<std::sync::Condvar> = OnceLock::new();
    CV.get_or_init(std::sync::Condvar::new)
}

/// TOFU 请求 → 阻塞等待 UI 决策（两段式第一段；握手/连接线程上调用）。
/// 返回 `true` = 用户确认信任；`false` = 拒绝或超时（fail-closed）。
pub fn trust_request_ui(device_id: &str, fingerprint_str: &str) -> bool {
    trust_request_ui_timed(device_id, fingerprint_str, TRUST_CONFIRM_TIMEOUT)
}

/// [`trust_request_ui`] 的可注入超时变体（宿主机单测用短超时）。
pub fn trust_request_ui_timed(
    device_id: &str,
    fingerprint_str: &str,
    timeout: Duration,
) -> bool {
    let mut st = trust_state().lock().unwrap();
    st.seq += 1;
    let seq = st.seq;
    st.prompt = Some((
        seq,
        TrustPrompt {
            device_id: device_id.to_string(),
            fingerprint: fingerprint_str.to_string(),
        },
    ));
    st.decision = None;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some((s, ok)) = st.decision {
            if s == seq {
                st.prompt = None;
                return ok;
            }
        }
        let now = Instant::now();
        if now >= deadline {
            st.prompt = None;
            return false;
        }
        let (guard, _timeout) = trust_condvar()
            .wait_timeout(st, deadline - now)
            .unwrap();
        st = guard;
    }
}

/// 两段式第二段（读）：当前待确认指纹（无 = 无待确认请求）。Kotlin 连接
/// 期间轮询本函数，非空 → 弹指纹确认对话框。
pub fn trust_peek_pending() -> Option<TrustPrompt> {
    trust_state()
        .lock()
        .unwrap()
        .prompt
        .as_ref()
        .map(|(_, p)| p.clone())
}

/// 两段式第二段（写）：回传用户决策。返回 `true` = 本次有待确认请求且
/// 已送达（唤醒等待方）；`false` = 无待确认请求（迟到/已清理，忽略）。
pub fn trust_resolve_pending(accept: bool) -> bool {
    let mut st = trust_state().lock().unwrap();
    if let Some((seq, _)) = st.prompt {
        st.decision = Some((seq, accept));
        trust_condvar().notify_all();
        true
    } else {
        false
    }
}

/// 清理待确认请求（连接失败/中止路径调用，防脏状态泄漏到下一次连接）。
pub fn trust_clear_pending() {
    let mut st = trust_state().lock().unwrap();
    st.prompt = None;
    st.decision = None;
    trust_condvar().notify_all();
}

/// 信任判定 + TOFU 上调的组合入口（known_hosts 三态 → 放行/拒绝/问 UI）。
/// 存储不可读（如首次运行无文件）→ 按 Unknown 处理（同桌面 CLI 空库语义）。
pub fn decide_trust_ui(device_id: &str, pubkey_base64: &str) -> bool {
    let status = KnownHostsStore::load()
        .map(|s| s.check(device_id, pubkey_base64))
        .unwrap_or(FingerprintStatus::Unknown);
    match trust_decision(status) {
        TrustAction::Allow => {
            tracing::info!("mobile: known_hosts fingerprint MATCH for '{device_id}'");
            true
        }
        TrustAction::Reject => {
            tracing::error!(
                "mobile: known_hosts fingerprint MISMATCH for '{device_id}' — refusing (MITM guard)"
            );
            false
        }
        TrustAction::Confirm => {
            tracing::info!("mobile: first connect — asking user to confirm fingerprint of '{device_id}'");
            trust_request_ui(device_id, &fingerprint(pubkey_base64))
        }
    }
}

/// 握手成功后记录 known_hosts（对齐桌面 `record_known_host`；失败仅告警）。
pub fn record_trusted_key(device_id: &str, pubkey_base64: &str) {
    match KnownHostsStore::load().and_then(|mut s| s.confirm(device_id, pubkey_base64)) {
        Ok(fp) => tracing::info!("mobile: recorded known_host '{device_id}' fingerprint {fp}"),
        Err(e) => tracing::warn!("mobile: record known_host '{device_id}' failed: {e}"),
    }
}

/// 地址模式信任策略：带外公钥 → `Verified`；否则 known_hosts 三态 + TOFU
/// UI 确认回调（Unknown 不再自动放行）。回调放行时把本次公钥写入
/// `confirmed` 槽位（连接成功后落 known_hosts + 设备历史）。
fn build_trust(
    params: &MobileConnectParams,
    confirmed: Arc<Mutex<Option<String>>>,
) -> TrustPolicy {
    if let Some(key) = params.server_pubkey.as_deref().filter(|k| !k.is_empty()) {
        return TrustPolicy::Verified(key.to_string());
    }
    let device_id = if params.id.is_empty() {
        params.server_addr.trim().to_string()
    } else {
        params.id.clone()
    };
    TrustPolicy::Confirm(Some(Arc::new(move |key: &str| {
        let ok = decide_trust_ui(&device_id, key);
        if ok {
            if let Ok(mut ck) = confirmed.lock() {
                *ck = Some(key.to_string());
            }
        }
        ok
    })))
}

// ── 连接历史（devices.json + known_hosts 合并，桌面同数据格式） ─────────────

/// 历史下拉一条记录（纯数据，可单测；对齐桌面 `IdHistoryEntry`，移动端
/// 不做 DNS 模式区分——domain 为空的设备记录 + known_hosts 全量补充）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// 设备 ID（ID 模式 = 完整 ID canonical；地址模式 = server_id）。
    pub id: String,
    /// 展示标签（devices.json 昵称/备注，回退短 ID）。
    pub label: String,
    /// 最近连接时间（devices.json `last_seen`；仅 known_hosts 时 None）。
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

/// 历史下拉短 ID 标签（无昵称可用时）——去冒号取前 8 字符 + 省略号。
pub fn short_id_label(id: &str) -> String {
    let flat: String = id.chars().filter(|c| *c != ':').collect();
    let head: String = flat.chars().take(8).collect();
    if flat.chars().count() > 8 {
        format!("{head}…")
    } else {
        head
    }
}

/// 合并连接历史（纯函数，可单测；对齐桌面 `id_history_entries` 语义）：
/// - `devices.json`（连接成功后 [`save_device_history`] 以设备 ID 为键
///   自动保存，`SavedDevice` 桌面同格式）优先，`domain` 为空（非 DNS 模式）
///   的条目按 `last_seen` 降序在前；
/// - `known_hosts`（首次指纹确认记录）补充独有条目，按 `confirmed_at`
///   降序在后；
/// - 按设备 ID 去重（devices.json 优先）。
pub fn history_entries(devices: &[SavedDevice], hosts: &[KnownHost]) -> Vec<HistoryEntry> {
    let mut out: Vec<HistoryEntry> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut dev_entries: Vec<HistoryEntry> = devices
        .iter()
        .filter(|d| d.domain.is_empty())
        .map(|d| {
            let label = if !d.nickname.trim().is_empty() && d.nickname != d.id {
                d.nickname.trim().to_string()
            } else if !d.remark.trim().is_empty() {
                d.remark.trim().to_string()
            } else {
                short_id_label(&d.id)
            };
            HistoryEntry {
                id: d.id.clone(),
                label,
                last_seen: Some(d.last_seen),
            }
        })
        .collect();
    dev_entries.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    for e in dev_entries {
        if seen.insert(e.id.clone()) {
            out.push(e);
        }
    }
    let mut host_ids: Vec<&KnownHost> = hosts.iter().collect();
    host_ids.sort_by(|a, b| b.confirmed_at.cmp(&a.confirmed_at));
    for h in host_ids {
        if seen.insert(h.id.clone()) {
            out.push(HistoryEntry {
                id: h.id.clone(),
                label: short_id_label(&h.id),
                last_seen: None,
            });
        }
    }
    out
}

/// 历史下拉 JSON（JNI `nativeHistory` 返回；`last_seen` RFC3339 或 null）。
pub fn history_json() -> String {
    let devices = DeviceStore::load().map(|s| s.devices().to_vec()).unwrap_or_default();
    let hosts = KnownHostsStore::load()
        .map(|s| s.hosts().to_vec())
        .unwrap_or_default();
    let arr: Vec<serde_json::Value> = history_entries(&devices, &hosts)
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "label": e.label,
                "last_seen": e.last_seen.map(|t| t.to_rfc3339()),
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
}

/// 连接成功后保存设备历史（devices.json upsert，`SavedDevice` 桌面同格式；
/// 昵称回退设备 ID；地址/端口未知字段留空——历史合并只消费
/// id/nickname/remark/last_seen/domain）。
///
/// 连接标 `Id`、地址/域名模式标 `Ip`，桌面端点击记录回填按 mode 路由。
/// 与桌面保存路径同口径落库；空 = 旧对端未通告，upsert 合并不擦除既有值）。
pub fn save_device_history(
    device_id: &str,
    nickname: &str,
    pubkey: &str,
    mode: DeviceConnMode,
    os_type: &str,
) {
    let dev = SavedDevice {
        id: device_id.to_string(),
        nickname: if nickname.trim().is_empty() {
            device_id.to_string()
        } else {
            nickname.trim().to_string()
        },
        remark: String::new(),
        challenge: String::new(),
        sort_order: 0,
        ipv6: String::new(),
        port: 0,
        pubkey: pubkey.to_string(),
        device_type: "desktop".into(),
        last_seen: chrono::Utc::now(),
        domain: String::new(),
        mode,
        os_type: os_type.to_string(),
    };
    match DeviceStore::load() {
        Ok(mut store) => {
            store.upsert(dev);
            if let Err(e) = store.save() {
                tracing::warn!("mobile: save device history failed: {e}");
            }
        }
        Err(e) => tracing::warn!("mobile: device store load failed: {e}"),
    }
}

/// 输入类型常量（Kotlin 侧 `nativeSendInput` 的 `type` 参数）。
pub mod input_type {
    pub const MOVE: u8 = 0;
    pub const BUTTON: u8 = 1;
    pub const WHEEL: u8 = 2;
}

/// 鼠标按键常量（`nativeSendInput` 的 `button` 参数）。
pub mod mouse_button {
    pub const LEFT: u8 = 0;
    pub const RIGHT: u8 = 1;
    pub const MIDDLE: u8 = 2;
}

/// 滚轮单格 wire 增量（= Windows `WHEEL_DELTA`；对齐桌面 viewer
/// egui Line×40 = 120/格）。
pub const WHEEL_DELTA_PER_NOTCH: i32 = 120;

/// `nativeSendInput(type, x, y, button, keyFlags, base)` → 服务端注入管线
/// wire 事件（纯函数）。
///
/// 分发任务 `bincode::deserialize::<WireInputEvent>`，ui/src/lib.rs 输入
/// 接收循环），**不是** `input::capture::InputEvent`——后者是客户端捕获侧
/// 本地格式（capture.rs 模块注释明示「线上传输统一走 injector 格式」）。
/// P0 起本层误用 capture 格式序列化 → 服务端逐包 "Input event deserialize
/// failed" 静默丢弃 → 用户实测「触摸画面完全没反应」（视频正常：视频走
/// EncodedWindow 独立 wire 格式不受影响）。
///
/// - MOVE：x/y 为 0.0–1.0 归一化坐标，按 `base`（服务端捕获分辨率，接收
///   循环从 EncodedWindow.base_w/base_h 跟踪）换算**服务端像素坐标**（对齐
///   桌面 viewer `nx * base_w` 口径；服务端注入器 src=dst 基准 1:1 落点）。
///   base 未知（0，首帧未到）→ None；
/// - BUTTON：button 0/1/2（Kotlin `NativeBridge.BUTTON_*`）→ wire 位标志
///   1/2/4，抬起再 `|RELEASE(0x80)`；x/y 同 MOVE 换算（Windows 注入按钮
///   不消费坐标，填值保 wire 完整性；base 未知 → 0,0）；
/// - WHEEL：keyFlags = 格数（Kotlin 手势 40px/格）→ ×[`WHEEL_DELTA_PER_NOTCH`]；
/// - 未知 type / 越界参数 → None（调用方丢弃并记日志）。
pub fn build_input_event(
    kind: u8,
    x: f64,
    y: f64,
    button: u8,
    key_flags: i32,
    base: (u32, u32),
) -> Option<WireInputEvent> {
    /// 归一化 → 服务端像素（截断，对齐桌面 `((nx * base_w) as u32)`）。
    fn px(v: f64, dim: u32) -> Option<u32> {
        if dim == 0 {
            return None;
        }
        Some((v.clamp(0.0, 1.0) * dim as f64) as u32)
    }
    match kind {
        k if k == input_type::MOVE => {
            if !(0.0..=1.0).contains(&x) || !(0.0..=1.0).contains(&y) {
                return None;
            }
            Some(WireInputEvent::mouse_move(px(x, base.0)?, px(y, base.1)?))
        }
        k if k == input_type::BUTTON => {
            let bits = match button {
                b if b == mouse_button::LEFT => wire_button::LEFT,
                b if b == mouse_button::RIGHT => wire_button::RIGHT,
                b if b == mouse_button::MIDDLE => wire_button::MIDDLE,
                _ => return None,
            };
            let bits = if key_flags & 0x1 != 0 {
                bits
            } else {
                bits | wire_button::RELEASE
            };
            let (wx, wy) = if base.0 > 0 && base.1 > 0 {
                (px(x, base.0)?, px(y, base.1)?)
            } else {
                (0, 0)
            };
            Some(WireInputEvent::mouse_button(bits, wx, wy))
        }
        k if k == input_type::WHEEL => Some(WireInputEvent::mouse_wheel(
            key_flags.saturating_mul(WHEEL_DELTA_PER_NOTCH),
            0,
            0,
        )),
        _ => None,
    }
}

/// Kotlin VK（Windows 虚拟键码）→ wire 键码（`injector::Key` 判别式 = HID
/// 用途码空间：A=0x04…Z=0x1D / Num1=0x1E…Num0=0x27 / Enter=0x28 / F1=0x3A…）。
///
/// wire 键空间**没有**修饰键与 OEM 标点：
/// - Shift/Ctrl/Alt/Win 以事件 `modifiers` 位标志表达（Kotlin 功能键条粘滞
///   态经 `nativeSendKey2` 附带）→ 修饰 VK 返回 None；
/// - OEM 标点（VK_OEM_*）不在 `Key` 枚举 → None（标点/大写文本统一走
///   `nativeSendText` Unicode 注入，对齐桌面 egui Event::Text 路径）。
pub fn vk_to_wire_key(vk: u16) -> Option<u32> {
    Some(match vk {
        0x08 => WireKey::Backspace as u32, // VK_BACK
        0x09 => WireKey::Tab as u32,       // VK_TAB
        0x0D => WireKey::Enter as u32,     // VK_RETURN
        // 修饰键（VK_SHIFT/CONTROL/MENU/LWIN/RWIN）：wire 键空间无此键
        //（modifiers 位标志语义）→ None。
        0x10 | 0x11 | 0x12 | 0x5B | 0x5C => return None,
        0x14 => WireKey::CapsLock as u32,  // VK_CAPITAL
        0x1B => WireKey::Esc as u32,       // VK_ESCAPE
        0x20 => WireKey::Space as u32,     // VK_SPACE
        0x21 => WireKey::PageUp as u32,    // VK_PRIOR
        0x22 => WireKey::PageDown as u32,  // VK_NEXT
        0x23 => WireKey::End as u32,
        0x24 => WireKey::Home as u32,
        0x25 => WireKey::Left as u32,
        0x26 => WireKey::Up as u32,
        0x27 => WireKey::Right as u32,
        0x28 => WireKey::Down as u32,
        0x2D => WireKey::Insert as u32,
        0x2E => WireKey::Delete as u32,
        0x30 => WireKey::Num0 as u32, // 数字行 '0'
        v @ 0x31..=0x39 => WireKey::Num1 as u32 + (v - 0x31) as u32, // '1'..'9'
        v @ 0x41..=0x5A => WireKey::A as u32 + (v - 0x41) as u32,    // 'A'..'Z'
        v @ 0x70..=0x7B => WireKey::F1 as u32 + (v - 0x70) as u32,   // F1–F12
        // OEM 标点/其余 → 文本注入路径（nativeSendText）。
        _ => return None,
    })
}

/// `EncodedWindow` → 逐帧 NAL 列表（扁平 nalus + frame_nalu_counts 新格式
/// 优先，旧 `frames` 格式回退）。对齐 ui `KirinDeskApp::window_frame_nalus`。
pub fn extract_frame_nalus(window: &EncodedWindow) -> Vec<Vec<&[u8]>> {
    if !window.frame_nalu_counts.is_empty() {
        let mut out = Vec::with_capacity(window.frame_nalu_counts.len());
        let mut start = 0usize;
        for &count in &window.frame_nalu_counts {
            let end = start + count;
            out.push(
                window
                    .nalus
                    .get(start..end)
                    .map(|nalus| nalus.iter().map(|n| n.as_ref()).collect())
                    .unwrap_or_default(),
            );
            start = end;
        }
        out
    } else {
        window
            .frames
            .iter()
            .map(|frame| frame.iter().map(|nal| nal.as_slice()).collect())
            .collect()
    }
}

/// `EncodedWindow` → 解码输入包（PTS 方案 A：window_id×10+idx 线性近似，
/// 窗口首帧为 IDR）。空帧跳过。
pub fn packets_for_window(window: &EncodedWindow) -> Vec<DecoderPacket> {
    let mut out = Vec::new();
    for (idx, frame_nalus) in extract_frame_nalus(window).into_iter().enumerate() {
        if frame_nalus.is_empty() {
            continue;
        }
        let mut data = Vec::new();
        for nal in frame_nalus {
            data.extend_from_slice(nal);
        }
        out.push(DecoderPacket {
            pts: frame_id_to_pts(window.window_id * 10 + idx as u64, 60),
            data,
            is_key: idx == 0,
            extradata: None,
            capture_ms: 0,
            recv_ms: 0,
        });
    }
    out
}

/// 批量 wire 事件 → InputEcho wire 包（每事件一包，与桌面发送任务一致：
/// `bincode::serialize(&WireInputEvent)`——注入管线格式，服务端
/// `deserialize::<WireInputEvent>` 消费；序列化失败丢该事件并记日志）。
pub fn input_packets(events: &[WireInputEvent]) -> Vec<EncodedPacket> {
    events
        .iter()
        .filter_map(|ev| {
            bincode::serialize(ev).ok().map(|data| EncodedPacket {
                ts: Timestamp::now(),
                kind: PacketKind::InputEcho,
                data,
                is_key: false,
            })
        })
        .collect()
}

// ════════════════════════════════════════════════════════════════
// 会话层
// ════════════════════════════════════════════════════════════════

/// 帧回调抽象（解码线程调用；JNI 侧实现 = GlobalRef + `onFrame(IIZ[B)V`；
/// 宿主机测试实现 = 计数器/采集器）。**必须尽快返回**（同桌面
/// `run_client_session` 对 `on_frame` 的约束；Bitmap 上屏由 Kotlin 侧处理）。
pub trait FrameSink: Send + Sync {
    fn on_frame(&self, frame: &DecodedFrame);
}

/// 输入命令（JNI 线程 → 输入发送任务）。逐事件即时发送（P0；桌面按
/// 帧批次合并，安卓触摸事件频率低，不合并语义等价——服务端逐包处理）。
///
/// 修复见 [`build_input_event`]）。
pub enum InputCommand {
    Event(WireInputEvent),
}

/// 活动会话句柄（JNI 句柄表持有）。
pub struct SessionHandle {
    pub input_tx: tokio::sync::mpsc::UnboundedSender<InputCommand>,
    pub frame_sink: Arc<Mutex<Option<Arc<dyn FrameSink>>>>,
    pub stop: Arc<AtomicBool>,
    /// P1-B 音频子系统（解码线程 + PCM 回调注册表；见 crate::audio——
    pub audio: crate::audio::AudioSession,
    /// 服务端捕获分辨率跟踪（EncodedWindow.base_w/base_h，接收循环更新；
    /// 口径，服务端按此 src=dst 1:1 落点注入）。
    pub server_res: Arc<Mutex<(u32, u32)>>,
    /// 四语义 API 见 [`crate::file_transfer::FileTransferHandle`]，B2 岗 JNI 薄封装）。
    pub files: crate::file_transfer::FileTransferHandle,
    /// 供 B2 岗 JNI 按 B1 口径（本端公钥 b64 + peer_id 排序拼接）预派生
    /// `transfer_id`；仅存储不上线，状态机零影响。
    pub peer_id: String,
}

/// 身份路径：`{config_dir}/identity/ed25519.json`
/// （config_dir 由 T04 的 KIRIN_DATA_DIR 覆盖 → Kotlin `getFilesDir()`；
/// 已含 `kirin_desk` 段，见 utils config.rs config_dir）。
fn identity_path() -> Result<std::path::PathBuf, String> {
    kirin_desk_utils::config::Config::config_dir()
        .map(|d| d.join("identity").join("ed25519.json"))
        .map_err(|e| format!("config dir: {e}"))
}

/// 加载/生成本机身份（首连生成并落 config_dir，之后复用同一身份）。
pub fn load_identity() -> Result<IdentityManager, String> {
    let path = identity_path()?;
    let device_id = kirin_desk_utils::config::Config::load()
        .ok()
        .map(|c| kirin_desk_utils::device::effective_device_id(&c.device.id))
        .unwrap_or_else(|| "kirin-android".to_string());
    IdentityManager::load_or_generate(path, &device_id).map_err(|e| format!("identity: {e}"))
}

/// 设备 ID（配置 effective_device_id，与身份生成同一口径）+ 公钥指纹
/// （79 字符，与被控端 Dashboard 核对口径一致）+ 公钥 base64。
pub fn identity_summary() -> Result<serde_json::Value, String> {
    let id = load_identity()?;
    let device_id = kirin_desk_utils::config::Config::load()
        .ok()
        .map(|c| kirin_desk_utils::device::effective_device_id(&c.device.id))
        .unwrap_or_else(|| "kirin-android".to_string());
    Ok(serde_json::json!({
        "device_id": device_id,
        "fingerprint": fingerprint(&id.public_key_base64()),
        "public_key": id.public_key_base64(),
    }))
}

/// 建链 + 启动会话任务（在 runtime 上执行；`nativeConnect` block_on 本函数）。
///
/// P1-A 分派：`token` 非空 → ID 模式（[`connect_and_run_id`]：relay 解析 +
/// DeviceInfo 验签 + TOFU 三态 + `IdConnector::connect_stream` 三级路径 +
/// （[`connect_and_run_domain`]：加密 DNS 三件套发现 + 地址直连同管线）；
/// 否则地址直连（P0 语义 + TOFU UI 化 + 成功后落盘）。返回句柄；错误为
/// 人话字符串（JNI 侧抛 RuntimeException）。
pub async fn connect_and_run(params: MobileConnectParams) -> Result<SessionHandle, String> {
    let mode = connect_mode(&params.server_addr, &params.token, params.domain)?;
    let result = match mode {
        ConnectMode::AddressDirect => connect_and_run_address(params).await,
        ConnectMode::IdMode => connect_and_run_id(params).await,
        ConnectMode::Domain => connect_and_run_domain(params).await,
    };
    // `policy::handshake_rejected_hint` 码表；移动端无 i18n 层，英文）。
    result.map_err(|e| humanize_reject_text(&e))
}

/// `Connection rejected: code|detail`）替换为完整英文句子，安卓端用户不再
/// 面对裸码/early eof。未知码原样返回。
///
/// 禁止互控被叫端兜底拒绝）均为「常量域新增取值」的 wire 兼容扩展，桌面
/// `policy::handshake_rejected_hint` 已覆盖，mobile 表此前缺行 → 用户面对
/// 裸码。文案语义对齐桌面 i18n（`ui/src/i18n/connect.rs` 同两条英文串）。
pub fn humanize_reject_text(msg: &str) -> String {
    use kirin_desk_core::crypto::handshake::{
        REJECT_CODE_APPROVAL_DECLINED, REJECT_CODE_APPROVAL_TIMEOUT,
        REJECT_CODE_CHALLENGE_MISMATCH, REJECT_CODE_CLIENT_KEY_MISMATCH,
        REJECT_CODE_CREDENTIALS_REQUIRED, REJECT_CODE_ID_WHITELIST,
        REJECT_CODE_MUTUAL_CONTROL, REJECT_CODE_NICKNAME_MISMATCH,
        REJECT_CODE_RATE_LIMITED, REJECT_CODE_UNATTENDED_UNKNOWN,
        REJECT_CODE_VERSION_MISMATCH,
    };
    const TABLE: &[(&str, &str)] = &[
        (REJECT_CODE_CHALLENGE_MISMATCH, "Challenge code mismatch: refused by the target device — check the challenge code and retry"),
        (REJECT_CODE_NICKNAME_MISMATCH, "Nickname mismatch: refused by the target device — check the target nickname"),
        (REJECT_CODE_CLIENT_KEY_MISMATCH, "Refused by target: identity fingerprint mismatch (device bound to a different client identity)"),
        (REJECT_CODE_CREDENTIALS_REQUIRED, "The target device requires credentials — enter the correct challenge code and retry"),
        (REJECT_CODE_APPROVAL_TIMEOUT, "Approval timed out on the target device (no one approved in time) — check the target's approval prompt, then retry"),
        (REJECT_CODE_APPROVAL_DECLINED, "The remote side declined the connection request (not approved on the target device)"),
        (REJECT_CODE_RATE_LIMITED, "Too many attempts: rate-limited by the target device — retry later"),
        (REJECT_CODE_VERSION_MISMATCH, "Incompatible KirinDesk version on the target — update both ends to the same version"),
        (REJECT_CODE_ID_WHITELIST, "Device ID not whitelisted on the target (ID whitelist enforcement)"),
        (REJECT_CODE_UNATTENDED_UNKNOWN, "The target device is in unattended mode: only whitelisted / known devices may connect — ask the peer to add this device to their whitelist or known clients"),
        (REJECT_CODE_MUTUAL_CONTROL, "Rejected by the target under the forbid-mutual-control policy: the target is currently controlling this machine, so reverse control was denied — retry after that session ends (or turn off 'Forbid mutual control' in Settings)"),
    ];
    for (code, text) in TABLE {
        // `Rejected` 显示格式：`Connection rejected: {code}|{detail}`。
        if msg.contains(&format!("{code}|")) {
            return text.to_string();
        }
    }
    msg.to_string()
}

/// 地址直连（P0 路径；P1-A 变化：TOFU Unknown 改走 UI 确认、成功后
async fn connect_and_run_address(params: MobileConnectParams) -> Result<SessionHandle, String> {
    let (host, port) = parse_server_addr(&params.server_addr)?;
    let identity = Arc::new(load_identity().map_err(|e| format!("identity: {e}"))?);
    // 服务端昵称 = 握手凭据之一（与挑战码成对，Dashboard 配置值）——
    // **不做指纹/短码归一化**（那是 ID 模式设备 ID 的语义；服务端按
    // 字面比对昵称，改写大小写即凭据失配），仅 trim，与桌面同口径。
    let server_id = params.id.trim().to_string();
    let server_id = if server_id.is_empty() {
        params.server_addr.trim().to_string()
    } else {
        server_id
    };
    let confirmed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let trust = build_trust(
        &MobileConnectParams {
            id: server_id.clone(),
            ..params.clone()
        },
        confirmed.clone(),
    );
    let opts = ConnectionOptions {
        target: host,
        port,
        server_id: server_id.clone(),
        challenge: params.challenge.clone(),
        device_type: "desktop".into(),
        client_identity: identity,
        // 握手 init.client_id（core handshake.rs verify_server_init_inner
        // 第 2 步 `init.client_id != expected`），且 GUI 服务端对
        // client_domain 非空的 IP/域名模式客户端**必查**（ui lib.rs
        // expected_nick_for_verify）——桌面 GUI 地址模式历来以
        // `client_id = server_id`（服务端昵称）上报恰好通过（「保持 GUI
        // 既有行为」注释）；本层此前误发本机设备 ID（"kirin-android"）→
        // nickname mismatch → 服务端裸 close → 客户端 early eof
        // （宿主复现：tests/ip_mode_handshake.rs）。对齐桌面：
        // client_id = 服务端昵称。
        client_id: server_id.clone(),
        // 与桌面 GUI 地址模式同口径（服务端白名单按此匹配，见
        // ui/src/lib.rs run_client_session 注释）。
        client_domain: "gui-client.local".into(),
        dns: None,
        trust,
    };
    let peer = resolve_peer(&opts).await.map_err(|e| e.to_string())?;
    let outcome = connect_peer_with_width(&opts, &peer, requested_max_width())
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!(
        "mobile: connected to {}@{} (codec: {})",
        outcome.channel.peer_id,
        outcome.addr,
        outcome.channel.selected_codec
    );
    // 成功落盘（对齐桌面 run_client_session_with_channel 尾部）：known_hosts
    // + devices.json。Confirmed 路径 = 回调放行时捕获的公钥；Verified pin
    // 路径 = 表单带外公钥（复记幂等，巩固已知指纹）。
    let trusted_key = match confirmed.lock() {
        Ok(k) => k.clone(),
        Err(_) => None,
    }
    .or_else(|| {
        params
            .server_pubkey
            .as_deref()
            .filter(|k| !k.is_empty())
            .map(|k| k.to_string())
    });
    if let Some(key) = trusted_key {
        record_trusted_key(&server_id, &key);
        save_device_history(
            &server_id,
            &params.nickname,
            &key,
            DeviceConnMode::Ip,
            &outcome.channel.peer_os,
        );
    }
    run_session(outcome.channel).await
}

/// 本常量 = 出厂默认 + 非法值回退档）。
///
/// 取值依据：会话页 sensorLandscape 横屏下典型安卓机长边 ≥1920 物理像素，
/// ContentScale.Fit 视口对 1280 宽源已接近 1:1 乃至超采样——更高编码分辨率
/// 对观感无增益，只线性放大解码/RGBA 拷贝/Bitmap GC 负担（用户实测「有
/// 高清画面但非常不流畅」的安卓侧自身因素之一）；1280×720 落服务端码率
/// （未上报语义）。服务端不保证满足（多观众收敛等），实际尺寸以视频流
/// EncodedWindow.base_w/base_h 为准（输入坐标基数同源跟踪，不受影响）。
pub const DEFAULT_REQUESTED_MAX_WIDTH: u32 = 1280;

/// [`requested_max_width`]）。
pub const REQUESTED_MAX_WIDTH: u32 = DEFAULT_REQUESTED_MAX_WIDTH;

/// 分辨率上报档位合法值集合（设置页三档）：0 = 原生 / 1280 = 720p 级 /
/// 1920 = 1080p 级。
pub const RESOLUTION_TIERS: &[u32] = &[0, 1280, 1920];

/// 三条建链路径统一经 [`requested_max_width`] 读取，默认 1280 档）。
static REQUESTED_WIDTH: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(DEFAULT_REQUESTED_MAX_WIDTH);

/// 档位值清洗（纯函数）：仅放行 [`RESOLUTION_TIERS`] 三档，其余（含负数
/// 截断、越界、奇数）回退默认 1280 档——设置存储损坏/旧版本残留值不致
/// 上线非法宽度。
pub fn sanitize_requested_width(raw: i64) -> u32 {
    if raw < 0 || raw > u32::MAX as i64 {
        return DEFAULT_REQUESTED_MAX_WIDTH;
    }
    let w = raw as u32;
    if RESOLUTION_TIERS.contains(&w) {
        w
    } else {
        DEFAULT_REQUESTED_MAX_WIDTH
    }
}

/// 当前分辨率上报档位（握手 `requested_max_width` 取值）。
pub fn requested_max_width() -> u32 {
    let w = REQUESTED_WIDTH.load(Ordering::Relaxed);
    if RESOLUTION_TIERS.contains(&w) {
        w
    } else {
        DEFAULT_REQUESTED_MAX_WIDTH
    }
}

/// 设置分辨率档位（JNI `nativeSetRequestedWidth`；非法值回退默认档）。
pub fn set_requested_max_width(raw: i64) {
    REQUESTED_WIDTH.store(sanitize_requested_width(raw), Ordering::Relaxed);
}

///
/// core [`kirin_desk_core::connection::client::connect_peer`] 内部走
/// `perform_handshake` → `client_handshake_with_confirm`（宽度恒 0），无
/// 参数可传——core 为兄弟岗工作目录，本层以同源语义本地复刻其尾部
/// （信任解析 → SocketAddr 直连 → nodelay → 握手），仅把握手换成
/// [`client_handshake_with_resolution`]（TcpStream 包装）。信任解析只覆盖本层
/// [`build_trust`] 实际产出的 `Verified` / `Confirm` 两形态（`Resolve`
/// 本层不构造，fail-fast 拒绝）；其余逐行对齐 core（两处调用链为证：
/// GUI/CLI 地址模式同源）。
async fn connect_peer_with_width(
    opts: &ConnectionOptions,
    peer: &ResolvedPeer,
    requested_max_width: u32,
) -> Result<ConnectOutcome, ConnectError> {
    // 信任解析（与 core connect_peer 逐行对齐的 mobile 子集）。
    let trusted_key = match &opts.trust {
        TrustPolicy::Verified(key) => Some(key.clone()),
        TrustPolicy::Confirm(cb) => match peer.txt_pubkey.as_ref() {
            // domain 模式：TXT 公钥经确认回调放行后作为 pin。
            Some(txt) => {
                let ok = cb.as_ref().map(|f| f(txt)).unwrap_or(false);
                if ok {
                    Some(txt.clone())
                } else {
                    return Err(ConnectError::TrustRejected(
                        "fingerprint confirmation declined".to_string(),
                    ));
                }
            }
            // IP 模式：无带外公钥 → 回调判定（握手 key_confirm）。
            None => None,
        },
        // mobile build_trust 不构造 Resolve（fail-fast，不静默回退）。
        TrustPolicy::Resolve(_) => {
            return Err(ConnectError::TrustRejected(
                "resolve trust policy not constructed by mobile".to_string(),
            ));
        }
    };
    // 客户端域名：显式指定优先；domain 模式缺省按 `{device_id}.{domain}` 推导
    //（mobile 恒显式 "gui-client.local"，保留推导分支与 core 对齐）。
    let client_domain = if opts.client_domain.is_empty() && !peer.domain.is_empty() {
        format!("{}.{}", peer.device_id, peer.domain)
    } else {
        opts.client_domain.clone()
    };
    // M8-T040（红线，与 core 同源）：peer.addr 必须是 IP 字面量——先解析为
    // SocketAddr 再直连，禁止字符串形态直连（触发系统明文 DNS）。
    let addr: std::net::SocketAddr = peer.addr.parse().map_err(|_| {
        ConnectError::Tcp(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("peer.addr '{}' 非 IP 字面量（禁止字符串解析路径）", peer.addr),
        ))
    })?;
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(ConnectError::Tcp)?;
    // 失败不致命，按告警处理。
    if let Err(e) = kirin_desk_core::network::tcp::set_nodelay(&stream) {
        tracing::debug!("set_nodelay failed: {e}");
    }
    // pin 解析：带外公钥 → Exact 强制比对；无 → UserConfirmRequired
    //（确认回调必填，缺失即拒绝——由握手层保证，无静默放行路径）。
    let pin = match trusted_key.as_deref() {
        Some(key) => PinExpectation::exact_from_base64(key).map_err(ConnectError::Handshake)?,
        None => PinExpectation::None(
            kirin_desk_core::crypto::handshake::CoreReason::UserConfirmRequired,
        ),
    };
    // 握手确认回调（core TrustPolicy::handshake_confirm 的本地等价物——
    // 该方法 core 内私有；mobile 的 Confirm 形态必带回调或由 pin 路径绕开）。
    let key_confirm = match &opts.trust {
        TrustPolicy::Confirm(Some(cb)) => {
            let cb = cb.clone();
            Some(Box::new(move |key: &str| cb(key)) as Box<dyn Fn(&str) -> bool + Send>)
        }
        _ => None,
    };
    let channel = client_handshake_with_resolution(
        stream,
        &opts.client_identity,
        &opts.client_id,
        &client_domain,
        &opts.device_type,
        &opts.server_id,
        pin,
        key_confirm,
        &opts.challenge,
        // supported_codecs 空 = 既有 H.264 兜底语义（对齐桌面地址模式）。
        Vec::new(),
        requested_max_width,
    )
    .await
    .map_err(ConnectError::Handshake)?;
    Ok(ConnectOutcome {
        channel,
        addr: peer.addr.clone(),
        device_id: peer.device_id.clone(),
        device_type: peer.device_type.clone(),
        trusted_key,
        domain: peer.domain.clone(),
        discovered: peer.discovered.clone(),
    })
}

/// ID 模式建链（P1-A；对齐桌面 `run_client_session_by_id`，ui/src/lib.rs
/// 4811 起）：
///
/// 2. `server_pubkey` 缺失 → **fail-closed 拒连**（ID-SEC-001 验签必需，
///    对齐桌面 4847 口径）；
/// 3. `IdModeConfig::try_new` → `IdConnector::resolve`（Login token 认证 +
///    ResolveDevice + DeviceInfo 服务器签名验签）；
/// 4. 离线/未知统一文案（ID-SEC-002 防枚举；短码发起 → 专用引导文案）；
/// 5. 短码解析成功 → 以服务器签名载荷中的**完整设备 ID** 为后续一切键
///    （known_hosts 校验/记录、devices.json；短码只用于寻址）；
/// 6. known_hosts 三态（Match → Exact pin / Mismatch → 拒绝 / Unknown →
///    TOFU UI 确认后 Exact pin + 落盘）；
///    中继兜底；打洞需 rendezvous 配置，移动端未配置即跳过——与桌面 GUI
///    同口径）；
/// 8. 流上 Ed25519 双向握手（ID-013；自报身份 = 本机指纹派生 ID + 空域名，
async fn connect_and_run_id(params: MobileConnectParams) -> Result<SessionHandle, String> {
    let device_id = normalize_device_id_input(&params.id);
    if device_id.trim().is_empty() {
        return Err("device id is empty".into());
    }
    let via_short_code = is_short_code_connection_input(&device_id);
    // ID-014 + ID-SEC-001：server_pubkey 必填（fail-closed）。
    let server_pubkey = params
        .server_pubkey
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            "relay server public key is missing — required for ID mode (fail-closed)".to_string()
        })?;
    let mut cfg = IdModeConfig::try_new(
        params.server_addr.trim(),
        params.token.trim(),
        server_pubkey,
    )
    .map_err(|e| format!("ID mode config invalid: {e}"))?;
    let identity = Arc::new(load_identity().map_err(|e| format!("identity: {e}"))?);
    let from_peer = fingerprint(&identity.public_key_base64());
    cfg = cfg.with_identity(identity.clone());
    let connector = IdConnector::new(cfg);

    // 解析 + 验签（ID-010 + ID-SEC-001）。
    let info = match connector.resolve(&device_id).await {
        Ok(i) => i,
        Err(IdConnectError::SignatureVerification) => {
            return Err("relay server signature verification failed (ID-SEC-001)".into());
        }
        Err(e) => return Err(format!("resolve failed: {e}")),
    };
    // 离线/未知统一文案（ID-SEC-002；短码发起 → 专用引导）。
    if !IdConnector::is_connectable(&info) {
        return Err(if via_short_code {
            format!(
                "short code '{device_id}' did not uniquely match an online device — enter the full device ID"
            )
        } else {
            format!("device '{device_id}' is offline or not registered")
        });
    }
    // 短码 → 服务器签名载荷中的完整 ID 为后续一切键。
    let device_id = if via_short_code {
        info.payload.device_id.clone()
    } else {
        device_id
    };
    // known_hosts 三态（ID-012 公钥 pin）。
    let peer_pubkey = info.payload.ed25519_pub.clone();
    let status = KnownHostsStore::load()
        .map(|s| s.check(&device_id, &peer_pubkey))
        .unwrap_or(FingerprintStatus::Unknown);
    let (pin, confirmed_now) = match trust_decision(status) {
        TrustAction::Allow => (
            PinExpectation::exact_from_base64(&peer_pubkey)
                .map_err(|e| format!("invalid peer pubkey: {e}"))?,
            false,
        ),
        TrustAction::Reject => {
            return Err(format!(
                "known_hosts fingerprint MISMATCH for '{device_id}' — connection refused"
            ));
        }
        TrustAction::Confirm => {
            // TOFU 首连确认（两段式 JNI；拒绝/超时均 fail-closed）。
            if !trust_request_ui(&device_id, &fingerprint(&peer_pubkey)) {
                return Err("fingerprint confirmation declined".into());
            }
            (
                PinExpectation::exact_from_base64(&peer_pubkey)
                    .map_err(|e| format!("invalid peer pubkey: {e}"))?,
                true,
            )
        }
    };
    // 三级路径（直连 → 打洞(未配 rendezvous 即跳过) → 中继）。
    let (path, stream) = connector
        .connect_stream(&info, &from_peer)
        .await
        .map_err(|e| format!("ID mode connect failed: {e}"))?;
    tracing::info!("mobile: ID mode path selected = {path:?} for '{device_id}'");
    let channel = client_handshake_with_resolution(
        stream,
        &identity,
        &from_peer,
        "",
        "desktop",
        &device_id,
        pin,
        // pin 已由 known_hosts 三态/TOFU 决策（Exact 强制比对），无回调路径。
        None,
        &params.challenge,
        Vec::new(),
        requested_max_width(),
    )
    .await
    .map_err(|e| format!("handshake failed: {e}"))?;
    // 成功落盘：TOFU 确认的公钥记 known_hosts；devices.json 历史（两模式同键）。
    if confirmed_now {
        record_trusted_key(&device_id, &peer_pubkey);
    }
    save_device_history(
        &device_id,
        &params.nickname,
        &peer_pubkey,
        DeviceConnMode::Id,
        &channel.peer_os,
    );
    run_session(channel).await
}

/// 起的信任锚与凭据口径）：
///
/// 1. 设备域名规整校验（[`validate_domain_host`]）；
/// 2. 加密解析器：`[dns.security]` 配置（默认 Cloudflare/Google/阿里 DoH +
///    DoT 兜底；mode=off → fail-closed 拒连，DDNS-DOH-007，绝不回退明文）；
/// 3. 三件套发现（[`resolve_domain_peer`]）：SRV 端口 + TXT Ed25519 公钥 +
///    A|AAAA 地址（`core::dns::resolve_for_connect` 唯一入口）；
/// 4. TOFU/known_hosts 键 = **设备域名**（域名是用户可见/可复核的稳定标识；
///    桌面用 device_id 短标签，移动端取全域名避免跨 zone 碰撞）；
/// 5. 走 [`connect_peer_with_width`] 地址直连同管线（TXT 公钥 Confirm →
///    TOFU 三态 + UI 确认 → Exact pin；分辨率档位设置驱动；成功后
///    known_hosts + devices.json 落盘，历史键 = 域名）；
/// 6. 握手凭据对齐桌面域名/IP 模式：`client_id = server_id = params.id`
///    （被控端昵称——服务端对 client_domain 非空客户端必查昵称，
async fn connect_and_run_domain(params: MobileConnectParams) -> Result<SessionHandle, String> {
    let host = validate_domain_host(&params.server_addr)
        .ok_or_else(|| domain_error(domain_err::INVALID_HOST, raw_trim(&params.server_addr)))?;
    // 加密解析器（默认端点可用；mode=off/未配置 → fail-closed）。
    let cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
    let resolver = kirin_desk_core::dns::secure_resolver_from_config(&cfg).ok_or_else(|| {
        domain_error(
            domain_err::DNS_UNAVAILABLE,
            "encrypted DNS (DoH/DoT) is disabled or not configured — domain mode refuses to fall back to plaintext DNS",
        )
    })?;
    let resolved = resolve_domain_peer(&host, resolver.as_ref()).await?;
    tracing::info!(
        "mobile: domain mode '{}' -> {} (port {}, type {})",
        host,
        resolved.addr,
        resolved.port,
        resolved.device_type
    );

    let identity = Arc::new(load_identity().map_err(|e| format!("identity: {e}"))?);
    // 被控端昵称（握手凭据；空 = 域名回退——与桌面 server_id 空回退同型）。
    let server_id = {
        let t = params.id.trim();
        if t.is_empty() { host.clone() } else { t.to_string() }
    };
    // TOFU 键 = 设备域名（与握手昵称解耦：昵称是凭据，域名是身份标识）。
    let confirmed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let trust = build_trust(
        &MobileConnectParams {
            id: host.clone(),
            // 域名模式信任锚 = TXT 公钥（connect_peer_with_width Confirm 分支），
            // 表单公钥字段不参与（jni mode 2 已清空，此处双保险）。
            server_pubkey: None,
            ..params.clone()
        },
        confirmed.clone(),
    );
    let opts = ConnectionOptions {
        target: host.clone(),
        port: resolved.port,
        server_id: server_id.clone(),
        challenge: params.challenge.clone(),
        device_type: resolved.device_type.clone(),
        client_identity: identity,
        client_id: server_id.clone(),
        client_domain: "gui-client.local".into(),
        dns: None,
        trust,
    };
    let peer = ResolvedPeer {
        addr: resolved.addr.clone(),
        device_id: host.clone(),
        device_type: resolved.device_type.clone(),
        domain: String::new(),
        discovered: None,
        txt_pubkey: Some(resolved.pubkey.clone()),
    };
    let outcome = connect_peer_with_width(&opts, &peer, requested_max_width())
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!(
        "mobile: domain mode connected to {}@{} (codec: {})",
        outcome.channel.peer_id,
        outcome.addr,
        outcome.channel.selected_codec
    );
    // 成功落盘（域名键）：known_hosts + devices.json（历史下拉回显，
    // label = 昵称字段）。Confirmed 路径 = TOFU 回调放行捕获的 TXT 公钥。
    let trusted_key = match confirmed.lock() {
        Ok(k) => k.clone(),
        Err(_) => None,
    };
    if let Some(key) = trusted_key {
        record_trusted_key(&host, &key);
        save_device_history(
            &host,
            &params.nickname,
            &key,
            DeviceConnMode::Ip,
            &outcome.channel.peer_os,
        );
    }
    run_session(outcome.channel).await
}

/// 数据面会话（对齐桌面 `run_client_session_with_channel` 最小子集）：
/// 拆收发半 → 输入发送任务 / 接收循环 + 解码线程 + P1-B 音频解码线程
/// （[`crate::audio`]）；剪贴板/文件/显示器控制不做。
async fn run_session(channel: kirin_desk_core::crypto::handshake::SecureChannel) -> Result<SessionHandle, String> {
    use kirin_desk_media::encoder::Codec;

    let negotiated_codec =
        Codec::from_str(&channel.selected_codec).unwrap_or(Codec::H264);
    let peer_id = channel.peer_id.clone();
    let (reader, writer) = channel.into_split();
    let sender = Arc::new(tokio::sync::Mutex::new(SecureChannelSender::new(writer)));
    let mut receiver = SecureChannelReceiver::new(reader);

    // salt = 本端公钥 b64 + peer_id 排序拼接，桌面 ui 同口径；断点
    // transfers_client.json 落 KIRIN_DATA_DIR）。收帧馈送端由下方接收
    // 循环的 0x06 分支持有——断连（接收循环退出）即 drop → 会话任务退出。
    let (files, file_frame_tx) = crate::file_transfer::spawn_session(
        crate::runtime(),
        Arc::clone(&sender),
        crate::file_transfer::session_salt(
            &load_identity()
                .ok()
                .map(|i| i.public_key_base64())
                .unwrap_or_default(),
            &peer_id,
        ),
        "client",
        DEFAULT_MAX_FILE_SIZE,
    );

    let (input_tx, mut input_rx) =
        tokio::sync::mpsc::unbounded_channel::<InputCommand>();
    let frame_sink: Arc<Mutex<Option<Arc<dyn FrameSink>>>> =
        Arc::new(Mutex::new(None));
    let stop = Arc::new(AtomicBool::new(false));
    let audio = crate::audio::AudioSession::spawn();
    let audio_rx = audio.clone(); // 接收循环投递份（指向同一线程）
    let server_res: Arc<Mutex<(u32, u32)>> = Arc::new(Mutex::new((0, 0)));
    let server_res_rx = server_res.clone();

    // 输入发送任务：命令 → InputEcho 包 → 加密可靠流。
    {
        let sender = sender.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            while let Some(cmd) = input_rx.recv().await {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let InputCommand::Event(ev) = cmd;
                let pkts = input_packets(&[ev]);
                if let Err(e) = sender.lock().await.send_packets(&pkts).await {
                    tracing::error!("mobile: input send error: {e} — stopping");
                    break;
                }
            }
            tracing::info!("mobile: input send task exited");
            // 任务退出即 drop 本份 sender arc；writer 由会话接收循环退出
            // （对端 EOF / stop）后随最后一个 arc 一起释放 → TCP 关闭。
        });
    }

    // 解码线程：FFmpeg 解码为阻塞同步调用，专用 std::thread（同桌面拓扑）。
    let (pkt_tx, pkt_rx) = std::sync::mpsc::channel::<DecoderPacket>();
    let decode_sink = frame_sink.clone();
    let decode_handle = std::thread::Builder::new()
        .name("kirin-mobile-decode".into())
        .spawn(move || {
            let mut decoder = match create_video_decoder(negotiated_codec) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!("mobile: create decoder failed: {e}");
                    return;
                }
            };
            while let Ok(pkt) = pkt_rx.recv() {
                match decoder.decode(&pkt) {
                    Ok(frames) => {
                        // 未注册回调时帧丢弃（不缓冲；注册由 nativeOnFrameCallback
                        // 在连接前后任意时刻完成）。
                        if let Some(sink) = decode_sink.lock().unwrap().as_ref() {
                            for f in frames {
                                sink.on_frame(&f);
                            }
                        }
                    }
                    Err(e) => tracing::warn!("mobile: decode error: {e}"),
                }
            }
            tracing::info!("mobile: decode thread exited");
        })
        .map_err(|e| format!("spawn decode thread: {e}"))?;

    // 接收循环：tag 分发（Video → 解码；其余 tag P0 忽略）。
    tokio::spawn(async move {
        loop {
            let (tag, _header, payload) = match receiver.recv_tagged().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::info!("mobile: receive loop ended: {e}");
                    break;
                }
            };
            // P1-B：音频包（Opus 帧，PTS 来自帧头）→ 音频解码线程
            if tag == ChannelTag::Audio {
                audio_rx.forward(_header.pts, payload);
                continue;
            }
            // （桌面 ui 收侧 tag 路由同口径；坏帧 warn 丢弃，不断会话）。
            if tag == ChannelTag::FileTransfer {
                match FileTransferFrame::decode(&payload) {
                    Ok(frame) => {
                        let _ = file_frame_tx.send(frame);
                    }
                    Err(e) => {
                        tracing::warn!("mobile: file frame decode failed: {e}");
                    }
                }
                continue;
            }
            if tag != ChannelTag::Video {
                continue;
            }
            match bincode::deserialize::<EncodedWindow>(&payload) {
                Ok(window) => {
                    // 与桌面 viewer client_resolution 键控同源）。
                    {
                        let mut res = server_res_rx.lock().unwrap();
                        if res.0 != window.base_w || res.1 != window.base_h {
                            *res = (window.base_w, window.base_h);
                        }
                    }
                    for pkt in packets_for_window(&window) {
                        if pkt_tx.send(pkt).is_err() {
                            break; // 解码线程已退出
                        }
                    }
                }
                Err(e) => tracing::warn!("mobile: deserialize EncodedWindow failed: {e}"),
            }
        }
        // 连接关闭：pkt_tx drop → 解码线程退出；join 回收（防线程/解码器泄漏）。
        drop(pkt_tx);
        let _ = decode_handle.join();
        // writer 半：接收循环独占持有 sender 剩余 arc，退出即 drop → TCP FIN。
    });
    // sender 的接收循环份在上方闭包；此处保留 input 任务的 arc 已 clone。

    Ok(SessionHandle {
        input_tx,
        frame_sink,
        stop,
        audio,
        server_res,
        files,
        peer_id,
    })
}

// ════════════════════════════════════════════════════════════════
// Tests（宿主机可跑：纯函数 + mock 会话组装）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use kirin_desk_input::injector::InputKind;

    #[test]
    fn test_parse_server_addr() {
        assert_eq!(
            parse_server_addr("192.168.1.10").unwrap(),
            ("192.168.1.10".into(), DEFAULT_NETWORK_PORT)
        );
        assert_eq!(
            parse_server_addr("192.168.1.10:60000").unwrap(),
            ("192.168.1.10".into(), 60000)
        );
        assert_eq!(
            parse_server_addr("[fe80::1]:60001").unwrap(),
            ("fe80::1".into(), 60001)
        );
        // 无端口的 IPv6 裸字面量：不解析为 host:port（rsplit 端口段含非数字）。
        assert_eq!(
            parse_server_addr("fe80::1").unwrap(),
            ("fe80::1".into(), DEFAULT_NETWORK_PORT)
        );
        assert!(parse_server_addr("").is_err());
        assert!(parse_server_addr("[fe80::1").is_err());
        assert!(parse_server_addr("host:notaport").is_ok()); // 当作无端口主机名
    }

    // ── P1-A：连接模式判定（token/server_addr/domain → 模式 + fail-fast） ──

    #[test]
    fn test_connect_mode_matrix() {
        // 仅地址 → 地址直连（P0 向后兼容）。
        assert_eq!(
            connect_mode("192.168.1.10:59990", "", false).unwrap(),
            ConnectMode::AddressDirect
        );
        // 地址 + token → ID 模式（serverAddr 语义 = relay 地址）。
        assert_eq!(
            connect_mode("relay.example.com:7000", "tok", false).unwrap(),
            ConnectMode::IdMode
        );
        // 两空 → 错误（P0 原「地址为空」语义）。
        assert!(connect_mode("", "", false).is_err());
        // token 非空但 relay 地址缺失 → 错误（fail-fast，不静默回退直连）。
        assert!(connect_mode("  ", "tok", false).is_err());
        // 首尾空白视为空（trim 口径）。
        assert_eq!(
            connect_mode(" 192.168.1.10 ", " ", false).unwrap(),
            ConnectMode::AddressDirect
        );
        assert_eq!(
            connect_mode(" relay:7000 ", " tok ", false).unwrap(),
            ConnectMode::IdMode
        );
    }


    #[test]
    fn test_connect_mode_matrix_domain() {
        // domain 置位 + 域名 → 域名模式。
        assert_eq!(
            connect_mode("device.example.com", "", true).unwrap(),
            ConnectMode::Domain
        );
        // 域名缺失 → 错误。
        assert!(connect_mode("", "", true).is_err());
        assert!(connect_mode("  ", "", true).is_err());
        // 域名模式与 relay token 互斥（域名发现不走 relay；显式报错防
        // 调用方把 ID 模式字段误带入域名模式后静默走错管线）。
        assert!(connect_mode("device.example.com", "tok", true).is_err());
        // domain 未置位时域名字符串形态 = 地址直连（向后兼容；域名字符串
        // 由 resolve_peer 按 IP/主机名分派，模式由用户 Tab 选择驱动）。
        assert_eq!(
            connect_mode("device.example.com", "", false).unwrap(),
            ConnectMode::AddressDirect
        );
    }

    #[test]
    fn test_validate_domain_host() {
        // 合法：≥2 标签、字母数字连字符、尾点容忍、大小写保留。
        assert_eq!(
            validate_domain_host("device.example.com.").unwrap(),
            "device.example.com"
        );
        assert_eq!(
            validate_domain_host(" my-pc.example.com ").unwrap(),
            "my-pc.example.com"
        );
        assert_eq!(validate_domain_host("a.io").unwrap(), "a.io");
        // 非法：单标签 / 空标签 / 连字符开头结尾 / 非法字符 / 端口形态 /
        // IP 字面量（v4/v6）/ 超长 / 空。
        assert!(validate_domain_host("localhost").is_none());
        assert!(validate_domain_host("a..b").is_none());
        assert!(validate_domain_host("-a.example.com").is_none());
        assert!(validate_domain_host("a-.example.com").is_none());
        assert!(validate_domain_host("a_b.example.com").is_none());
        assert!(validate_domain_host("device.example.com:59990").is_none());
        assert!(validate_domain_host("192.168.1.10").is_none());
        assert!(validate_domain_host("fe80::1").is_none());
        assert!(validate_domain_host("").is_none());
        assert!(validate_domain_host(&("a".repeat(64) + ".com")).is_none());
    }

    #[test]
    fn test_srv_query_name_shape() {
        assert_eq!(srv_query_name("device.example.com"), "_remote._tcp.device.example.com");
    }

    #[test]
    fn test_classify_resolver_error() {
        use kirin_desk_dns::ResolverError;
        // NXDOMAIN：DoH Status=3 / DoT RCODE=3 文案。
        assert_eq!(
            classify_resolver_error(&ResolverError::InvalidResponse(
                "DoH Status=3（非 0）".into()
            ))
            .0,
            domain_err::NXDOMAIN
        );
        assert_eq!(
            classify_resolver_error(&ResolverError::InvalidResponse(
                "RCODE=3（非 0：SERVFAIL/NXDOMAIN 等）".into()
            ))
            .0,
            domain_err::NXDOMAIN
        );
        // 超时 / 全端点失败（fail-closed）/ 其余。
        assert_eq!(
            classify_resolver_error(&ResolverError::Timeout).0,
            domain_err::TIMEOUT
        );
        assert_eq!(
            classify_resolver_error(&ResolverError::AllEndpointsFailed {
                detail: "mock".into()
            })
            .0,
            domain_err::DNS_UNAVAILABLE
        );
        assert_eq!(
            classify_resolver_error(&ResolverError::Io("net down".into())).0,
            domain_err::NO_RECORDS
        );
    }

    /// 域名发现 mock 解析器（SRV/TXT/A/AAAA 四型可编程；async_trait 手写
    /// 太重——直接复用 core 测试同款形状的简单实现）。
    struct MockDomainResolver {
        srv_port: Option<u16>,
        txt: Option<String>,
        a: Vec<&'static str>,
        aaaa: Vec<&'static str>,
        fail_all: bool,
        nxdomain: bool,
    }

    #[async_trait::async_trait]
    impl kirin_desk_dns::Resolver for MockDomainResolver {
        async fn resolve(
            &self,
            _host: &str,
            rt: kirin_desk_dns::RecordType,
        ) -> Result<Vec<kirin_desk_dns::Record>, kirin_desk_dns::ResolverError> {
            use kirin_desk_dns::{Record, RecordData, RecordType, ResolverError};
            if self.fail_all {
                return Err(ResolverError::AllEndpointsFailed {
                    detail: "mock 全端点失败".into(),
                });
            }
            if self.nxdomain {
                return Err(ResolverError::InvalidResponse(
                    "DoH Status=3（非 0）".into(),
                ));
            }
            let rec = |data| Record {
                name: "device.example.com".into(),
                rtype: rt,
                ttl: 300,
                data,
            };
            Ok(match rt {
                RecordType::SRV => self
                    .srv_port
                    .map(|p| {
                        vec![rec(RecordData::Srv {
                            priority: 0,
                            weight: 1,
                            port: p,
                            target: "device.example.com".into(),
                        })]
                    })
                    .unwrap_or_default(),
                RecordType::TXT => self
                    .txt
                    .as_ref()
                    .map(|t| vec![rec(RecordData::Plain(t.clone()))])
                    .unwrap_or_default(),
                RecordType::A => self.a.iter().map(|s| rec(RecordData::Plain(s.to_string()))).collect(),
                RecordType::AAAA => self
                    .aaaa
                    .iter()
                    .map(|s| rec(RecordData::Plain(s.to_string())))
                    .collect(),
                _ => vec![],
            })
        }
    }

    /// TXT DeviceMeta 样例（ed25519: + base64 key，txt.rs DeviceMeta 口径）。
    const MOCK_TXT: &str = r#"{"key":"ed25519:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","proto":"kirindesk","ver":"1"}"#;

    fn mock_domain_resolver() -> MockDomainResolver {
        MockDomainResolver {
            srv_port: Some(59990),
            txt: Some(MOCK_TXT.to_string()),
            a: vec!["203.0.113.7"],
            aaaa: vec![],
            fail_all: false,
            nxdomain: false,
        }
    }

    #[tokio::test]
    async fn test_resolve_domain_peer_happy_path() {
        let r = mock_domain_resolver();
        let out = resolve_domain_peer("device.example.com", &r).await.unwrap();
        assert_eq!(out.addr, "203.0.113.7:59990");
        assert_eq!(out.port, 59990);
        assert!(out.pubkey.starts_with("BwcH"), "TXT key 去 ed25519: 前缀");
        assert_eq!(out.device_type, "desktop");
    }

    #[tokio::test]
    async fn test_resolve_domain_peer_auto_prefers_v6() {
        let r = MockDomainResolver {
            aaaa: vec!["2001:db8::1"],
            ..mock_domain_resolver()
        };
        let out = resolve_domain_peer("device.example.com", &r).await.unwrap();
        assert_eq!(out.addr, "[2001:db8::1]:59990");
    }

    #[tokio::test]
    async fn test_resolve_domain_peer_missing_records() {
        // 无 SRV → no_srv（端口未知）。
        let r = MockDomainResolver {
            srv_port: None,
            ..mock_domain_resolver()
        };
        let err = resolve_domain_peer("device.example.com", &r).await.unwrap_err();
        assert!(err.starts_with(domain_err::NO_SRV), "got {err}");
        // 无 TXT / TXT 无 key → no_txt（CLI-DNS-006 缺失即拒）。
        let r = MockDomainResolver {
            txt: None,
            ..mock_domain_resolver()
        };
        let err = resolve_domain_peer("device.example.com", &r).await.unwrap_err();
        assert!(err.starts_with(domain_err::NO_TXT), "got {err}");
        let r = MockDomainResolver {
            txt: Some(r#"{"proto":"kirindesk"}"#.into()),
            ..mock_domain_resolver()
        };
        let err = resolve_domain_peer("device.example.com", &r).await.unwrap_err();
        assert!(err.starts_with(domain_err::NO_TXT), "got {err}");
        // A/AAAA 全空 → no_records。
        let r = MockDomainResolver {
            a: vec![],
            aaaa: vec![],
            ..mock_domain_resolver()
        };
        let err = resolve_domain_peer("device.example.com", &r).await.unwrap_err();
        assert!(err.starts_with(domain_err::NO_RECORDS), "got {err}");
    }

    #[tokio::test]
    async fn test_resolve_domain_peer_error_classification() {
        // 域名不存在（NXDOMAIN）→ 可读码。
        let r = MockDomainResolver {
            nxdomain: true,
            ..mock_domain_resolver()
        };
        let err = resolve_domain_peer("ghost.example.com", &r).await.unwrap_err();
        assert!(err.starts_with(domain_err::NXDOMAIN), "got {err}");
        // 全端点失败 → dns_unavailable（fail-closed，不回退明文）。
        let r = MockDomainResolver {
            fail_all: true,
            ..mock_domain_resolver()
        };
        let err = resolve_domain_peer("device.example.com", &r).await.unwrap_err();
        assert!(err.starts_with(domain_err::DNS_UNAVAILABLE), "got {err}");
        // 非法主机名（端口形态/IP 字面量）→ invalid_host。
        let r = mock_domain_resolver();
        let err = resolve_domain_peer("192.168.1.10:59990", &r).await.unwrap_err();
        assert!(err.starts_with(domain_err::INVALID_HOST), "got {err}");
    }


    #[test]
    fn test_normalize_device_id_input_fingerprint_forms() {
        // 完整指纹（无冒号大写）→ canonical 小写冒号分组。
        let hex64 = "a1b2c3d4".repeat(8);
        let canonical: String = hex64
            .as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(normalize_device_id_input(&hex64.to_uppercase()), canonical);
        assert_eq!(normalize_device_id_input(&canonical), canonical);
        // 抄录带冒号的指纹 → 不变（已 canonical）。
        assert_eq!(normalize_device_id_input("a1b2:c3d4"), "a1b2:c3d4");
    }

    #[test]
    fn test_normalize_device_id_input_short_code_and_custom() {
        // 短码（小写/大写单一风格）→ 小写 canonical。
        assert_eq!(normalize_device_id_input("a1b2c3d4e5"), "a1b2c3d4e5");
        assert_eq!(normalize_device_id_input("A1B2C3D4E5"), "a1b2c3d4e5");
        // 混合大小写短码 → 视为自定义 ID 原样保留（fail-closed 不改写）。
        assert_eq!(normalize_device_id_input("A1b2C3d4E5"), "A1b2C3d4E5");
        // 自定义显式 ID → 仅 trim，大小写敏感。
        assert_eq!(normalize_device_id_input("  pc-Abc123  "), "pc-Abc123");
        // 11 hex 既非短码也非指纹 → 自定义 ID 原样（仅 trim）。
        assert_eq!(normalize_device_id_input("a1b2c3d4e5f"), "a1b2c3d4e5f");
    }

    #[test]
    fn test_is_short_code_connection_input() {
        // canonical 小写 10 hex → 短码发起。
        assert!(is_short_code_connection_input("a1b2c3d4e5"));
        // 大写/混合（归一化前）→ 不算（归一化后才 canonical）。
        assert!(!is_short_code_connection_input("A1B2C3D4E5"));
        // 完整指纹（64 hex）→ 不算。
        let hex64 = "a1b2c3d4".repeat(8);
        assert!(!is_short_code_connection_input(&hex64));
        // 自定义 ID → 不算。
        assert!(!is_short_code_connection_input("pc-abc123"));
    }

    // ── P1-A：TOFU 三态决策（纯函数） ──

    #[test]
    fn test_trust_decision_three_states() {
        assert_eq!(trust_decision(FingerprintStatus::Match), TrustAction::Allow);
        assert_eq!(
            trust_decision(FingerprintStatus::Mismatch),
            TrustAction::Reject,
            "指纹不一致必须拒绝（fail-closed）"
        );
        assert_eq!(
            trust_decision(FingerprintStatus::Unknown),
            TrustAction::Confirm,
            "P1-A：未命中不再自动放行（P0 TOFU 自动信任已废除）"
        );
    }

    /// TOFU 两段式状态机（全局单例——单测试函数内顺序覆盖三场景，避免
    /// 并行测试互踩共享静态）。
    #[test]
    fn test_trust_state_machine_accept_decline_timeout() {
        trust_clear_pending();
        assert!(trust_peek_pending().is_none(), "初始无待确认");
        assert!(!trust_resolve_pending(true), "无待确认时 resolve 被忽略");

        // 场景 1：请求 → 确认（accept=true）→ 放行。
        let resolver = std::thread::spawn(|| {
            for _ in 0..500 {
                if trust_peek_pending().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            trust_resolve_pending(true)
        });
        assert!(
            trust_request_ui_timed("dev-a", "aa:bb:cc", Duration::from_secs(5)),
            "用户确认 → 放行"
        );
        assert!(resolver.join().unwrap(), "resolve 命中待确认请求");
        assert!(trust_peek_pending().is_none(), "决策后待确认清理");

        // 场景 2：请求 → 拒绝（accept=false）→ 拒绝。
        let decliner = std::thread::spawn(|| {
            for _ in 0..500 {
                if trust_peek_pending().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            trust_resolve_pending(false)
        });
        assert!(
            !trust_request_ui_timed("dev-b", "dd:ee:ff", Duration::from_secs(5)),
            "用户拒绝 → 拒绝（fail-closed）"
        );
        assert!(decliner.join().unwrap());

        // 场景 3：请求 → 无人决策 → 超时拒绝。
        assert!(
            !trust_request_ui_timed("dev-c", "00:11:22", Duration::from_millis(50)),
            "超时 → 拒绝（fail-closed，弹窗被遗忘不挂死连接）"
        );
        assert!(trust_peek_pending().is_none(), "超时后待确认清理");
    }

    // ── P1-A：连接历史合并（devices.json + known_hosts，纯函数） ──

    fn dev(id: &str, nickname: &str, last_seen: chrono::DateTime<chrono::Utc>) -> SavedDevice {
        SavedDevice {
            id: id.to_string(),
            nickname: nickname.to_string(),
            remark: String::new(),
            challenge: String::new(),
            ipv6: String::new(),
            port: 0,
            pubkey: "k".into(),
            device_type: "desktop".into(),
            last_seen,
            domain: String::new(),
            sort_order: 0,
            mode: DeviceConnMode::Unknown,
            os_type: String::new(),
        }
    }

    fn host(id: &str, confirmed_at: chrono::DateTime<chrono::Utc>) -> KnownHost {
        KnownHost {
            id: id.to_string(),
            fingerprint: "ab:cd".into(),
            confirmed_at,
        }
    }

    #[test]
    fn test_history_entries_merge_and_dedupe() {
        let t1 = chrono::Utc::now() - chrono::Duration::hours(3);
        let t2 = chrono::Utc::now() - chrono::Duration::hours(1);
        let t3 = chrono::Utc::now() - chrono::Duration::hours(2);
        // devices.json：两条（乱序输入），known_hosts：一条与 devices 重复
        // （应被去重）、一条独有。
        let devices = vec![
            dev("aaaa:bbbb:0000:1111", "Office PC", t1),
            dev("cccc:dddd:2222:3333", "", t2),
        ];
        let hosts = vec![host("aaaa:bbbb:0000:1111", t3), host("eeee:ffff:4444:5555", t3)];
        let out = history_entries(&devices, &hosts);
        assert_eq!(out.len(), 3, "按 ID 去重（known_hosts 重复条不新增）");
        // devices 按 last_seen 降序在前：cccc…（t2）→ aaaa…（t1）。
        assert_eq!(out[0].id, "cccc:dddd:2222:3333");
        assert_eq!(out[1].id, "aaaa:bbbb:0000:1111");
        // known_hosts 独有条目排最后（last_seen None）。
        assert_eq!(out[2].id, "eeee:ffff:4444:5555");
        assert_eq!(out[2].last_seen, None);
        // 昵称可用 → 用昵称；无昵称 → 短 ID 标签（去冒号前 8 hex + 省略号）。
        assert_eq!(out[1].label, "Office PC");
        assert_eq!(out[0].label, "ccccdddd…");
        assert_eq!(out[2].label, "eeeeffff…");
    }

    #[test]
    fn test_history_entries_filters_dns_domain_and_remark_fallback() {
        let t = chrono::Utc::now();
        // DNS 模式记录（domain 非空）不进历史（桌面口径：设备列表负责）。
        let mut dns = dev("pc-a", "DNS 设备", t);
        dns.domain = "example.com".into();
        // 备注回退：昵称空但备注非空。
        let mut remarked = dev("bbbb:cccc", "", t);
        remarked.remark = "家里台式机".into();
        let out = history_entries(&[dns, remarked], &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "bbbb:cccc");
        assert_eq!(out[0].label, "家里台式机");
    }

    #[test]
    fn test_short_id_label() {
        assert_eq!(short_id_label("a1b2c3d4e5f6a7b8c9d0"), "a1b2c3d4…");
        assert_eq!(short_id_label("a1b2:c3d4"), "a1b2c3d4");
        assert_eq!(short_id_label("pc-a"), "pc-a");
        assert_eq!(short_id_label("00000008"), "00000008");
        assert_eq!(short_id_label("000000089"), "00000008…");
    }


    /// **根因回归钉**：移动端手势 wire 包必须能被**服务端分发任务的同一
    /// 反序列化**（`bincode::deserialize::<injector::InputEvent>`）还原——
    /// P0~P1B 期间本层误用 capture 格式，服务端逐包 "deserialize failed"
    /// 丢弃（用户实测触摸全无反应的直接根因），本测试防再度错配。
    #[test]
    fn test_input_packets_deserialize_as_server_wire() {
        let events = [
            build_input_event(0, 0.25, 0.75, 0, 0, (1920, 1080)).unwrap(),
            build_input_event(1, 0.5, 0.5, 0, 1, (1920, 1080)).unwrap(),
            build_input_event(1, 0.5, 0.5, 2, 0, (1920, 1080)).unwrap(),
            build_input_event(2, 0.0, 0.0, 0, -1, (1920, 1080)).unwrap(),
        ];
        let pkts = input_packets(&events);
        assert_eq!(pkts.len(), 4);
        for (pkt, ev) in pkts.iter().zip(&events) {
            assert!(matches!(pkt.kind, PacketKind::InputEcho));
            // 服务端同型反序列化（ui 分发任务同代码路径）。
            let back: WireInputEvent = bincode::deserialize(&pkt.data).unwrap();
            assert_eq!(back, *ev);
        }
        // 抽查语义：移动 = 服务端像素坐标；左键按下 = 位标志 1；
        // 中键抬起 = 4|0x80；滚轮 -1 格 = -120（WHEEL_DELTA）。
        let move_ev: WireInputEvent =
            bincode::deserialize(&pkts[0].data).unwrap();
        assert_eq!((move_ev.kind, move_ev.x, move_ev.y), (InputKind::MouseMove, 480, 810));
        let btn: WireInputEvent = bincode::deserialize(&pkts[1].data).unwrap();
        assert_eq!((btn.kind, btn.button), (InputKind::MouseButton, wire_button::LEFT));
        let mid_up: WireInputEvent = bincode::deserialize(&pkts[2].data).unwrap();
        assert_eq!(
            (mid_up.kind, mid_up.button),
            (InputKind::MouseButton, wire_button::MIDDLE | wire_button::RELEASE)
        );
        let wheel: WireInputEvent = bincode::deserialize(&pkts[3].data).unwrap();
        assert_eq!(
            (wheel.kind, wheel.wheel_delta),
            (InputKind::MouseWheel, -WHEEL_DELTA_PER_NOTCH)
        );
    }

    #[test]
    fn test_build_input_event_move_base_and_bounds() {
        // 归一化 → 服务端像素（截断；对齐桌面 nx*base_w 口径）。
        assert!(matches!(
            build_input_event(0, 0.5, 0.25, 0, 0, (2560, 1440)),
            Some(WireInputEvent {
                kind: InputKind::MouseMove,
                x: 1280,
                y: 360,
                ..
            })
        ));
        // 越界归一化拒绝。
        assert!(build_input_event(0, 1.5, 0.5, 0, 0, (1920, 1080)).is_none());
        // base 未知（0，首帧未到）→ 移动无坐标基数，拒绝（不误注入 0,0）。
        assert!(build_input_event(0, 0.5, 0.5, 0, 0, (0, 0)).is_none());
        // 按键/滚轮不依赖 base（坐标填 0，服务端注入不消费）。
        assert!(build_input_event(1, 0.0, 0.0, 1, 1, (0, 0)).is_some());
        assert!(build_input_event(2, 0.0, 0.0, 0, 1, (0, 0)).is_some());
        // 未知 type / 未知按键拒绝。
        assert!(build_input_event(7, 0.0, 0.0, 0, 0, (1920, 1080)).is_none());
        assert!(build_input_event(1, 0.0, 0.0, 9, 1, (1920, 1080)).is_none());
    }

    #[test]
    fn test_vk_to_wire_key_matrix() {
        use kirin_desk_input::injector::Key;
        // 字母/数字（Windows VK 与 ASCII 同值）→ HID 判别式。
        assert_eq!(vk_to_wire_key(0x41), Some(Key::A as u32));
        assert_eq!(vk_to_wire_key(0x5A), Some(Key::Z as u32));
        assert_eq!(vk_to_wire_key(0x30), Some(Key::Num0 as u32));
        assert_eq!(vk_to_wire_key(0x31), Some(Key::Num1 as u32));
        assert_eq!(vk_to_wire_key(0x39), Some(Key::Num9 as u32));
        // 控制键。
        assert_eq!(vk_to_wire_key(0x0D), Some(Key::Enter as u32));
        assert_eq!(vk_to_wire_key(0x1B), Some(Key::Esc as u32));
        assert_eq!(vk_to_wire_key(0x08), Some(Key::Backspace as u32));
        assert_eq!(vk_to_wire_key(0x09), Some(Key::Tab as u32));
        assert_eq!(vk_to_wire_key(0x20), Some(Key::Space as u32));
        assert_eq!(vk_to_wire_key(0x14), Some(Key::CapsLock as u32));
        // F1–F12 与导航/编辑键（KeyMap 功能键条全键位）。
        assert_eq!(vk_to_wire_key(0x70), Some(Key::F1 as u32));
        assert_eq!(vk_to_wire_key(0x7B), Some(Key::F12 as u32));
        assert_eq!(vk_to_wire_key(0x25), Some(Key::Left as u32));
        assert_eq!(vk_to_wire_key(0x26), Some(Key::Up as u32));
        assert_eq!(vk_to_wire_key(0x27), Some(Key::Right as u32));
        assert_eq!(vk_to_wire_key(0x28), Some(Key::Down as u32));
        assert_eq!(vk_to_wire_key(0x21), Some(Key::PageUp as u32));
        assert_eq!(vk_to_wire_key(0x22), Some(Key::PageDown as u32));
        assert_eq!(vk_to_wire_key(0x23), Some(Key::End as u32));
        assert_eq!(vk_to_wire_key(0x24), Some(Key::Home as u32));
        assert_eq!(vk_to_wire_key(0x2D), Some(Key::Insert as u32));
        assert_eq!(vk_to_wire_key(0x2E), Some(Key::Delete as u32));
        // 修饰键不在 wire 键空间（modifiers 位标志语义，Kotlin 粘滞态经
        // nativeSendKey2 附带）→ None。
        for vk in [0x10u16, 0x11, 0x12, 0x5B, 0x5C] {
            assert_eq!(vk_to_wire_key(vk), None, "modifier vk {vk:#x} must be None");
        }
        // OEM 标点（0xBA–0xC0 等）与未知 → None（文本注入路径）。
        for vk in [0xBAu16, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xDC] {
            assert_eq!(vk_to_wire_key(vk), None, "oem vk {vk:#x} must be None");
        }
    }

    /// 越界/非档位奇数如 1279）回退默认 1280 档。
    #[test]
    fn test_sanitize_requested_width() {
        assert_eq!(sanitize_requested_width(0), 0, "0 = 原生档");
        assert_eq!(sanitize_requested_width(1280), 1280, "720p 级档");
        assert_eq!(sanitize_requested_width(1920), 1920, "1080p 级档");
        assert_eq!(sanitize_requested_width(1279), DEFAULT_REQUESTED_MAX_WIDTH);
        assert_eq!(sanitize_requested_width(-1), DEFAULT_REQUESTED_MAX_WIDTH);
        assert_eq!(
            sanitize_requested_width(u32::MAX as i64 + 1),
            DEFAULT_REQUESTED_MAX_WIDTH
        );
        assert_eq!(
            sanitize_requested_width(99999),
            DEFAULT_REQUESTED_MAX_WIDTH
        );
    }

    /// 档位档值口径：默认 1280（>0 有偏好、偶数、≤720p 级带宽档）；全局
    /// 槽位默认值与清洗回退一致；set 后 get 反映（Relaxed 单值原子）。
    #[test]
    fn test_requested_max_width_default_and_set() {
        assert_eq!(requested_max_width(), DEFAULT_REQUESTED_MAX_WIDTH);
        assert_eq!(DEFAULT_REQUESTED_MAX_WIDTH % 2, 0, "偶数（编码宽度对齐友好）");
        assert!(DEFAULT_REQUESTED_MAX_WIDTH > 0 && DEFAULT_REQUESTED_MAX_WIDTH <= 1280);
        set_requested_max_width(1920);
        assert_eq!(requested_max_width(), 1920);
        set_requested_max_width(0);
        assert_eq!(requested_max_width(), 0);
        // 非法值落默认档（设置存储损坏兜底）。
        set_requested_max_width(777);
        assert_eq!(requested_max_width(), DEFAULT_REQUESTED_MAX_WIDTH);
        // 还原默认（防并行测试串档：本测试独占改全局槽位，尾部复原）。
        set_requested_max_width(DEFAULT_REQUESTED_MAX_WIDTH as i64);
    }

    #[test]
    fn test_wire_key_event_construction_roundtrip() {
        // 键事件 wire 构造（nativeSendKey2 路径）：KeyDown(A, SHIFT) 服务端
        // 同型反序列化可见 kind/key/modifiers。
        let ev = WireInputEvent {
            kind: InputKind::KeyDown,
            x: 0,
            y: 0,
            button: 0,
            key: vk_to_wire_key(0x41).unwrap(),
            wheel_delta: 0,
            modifiers: kirin_desk_input::injector::modifier::SHIFT,
            text: String::new(),
            combo: None,
        };
        let pkts = input_packets(&[ev.clone()]);
        let back: WireInputEvent = bincode::deserialize(&pkts[0].data).unwrap();
        assert_eq!(back, ev);
        assert_eq!(back.kind, InputKind::KeyDown);
        assert_eq!(back.modifiers, kirin_desk_input::injector::modifier::SHIFT);
    }

    #[test]
    fn test_packets_for_window_flat_and_legacy() {
        // 旧格式（EncodedWindow::new 构造 legacy frames）。
        let win = EncodedWindow::new(
            3,
            64,
            48,
            vec![vec![b"\x00\x00\x00\x01\x67abc".to_vec()], vec![], vec![b"\x00\x00\x00\x01\x68d".to_vec()]],
        );
        let pkts = packets_for_window(&win);
        assert_eq!(pkts.len(), 2, "空帧跳过");
        assert!(pkts[0].is_key);
        assert!(!pkts[1].is_key);
        assert_eq!(pkts[0].pts, frame_id_to_pts(30, 60));
        assert_eq!(pkts[0].data, b"\x00\x00\x00\x01\x67abc");
        assert_eq!(pkts[1].data, b"\x00\x00\x00\x01\x68d");
    }

    /// 信任策略组装（地址模式）：带外公钥 → Verified 强 pin；无 → Confirm
    /// 回调（P1-A：Unknown 走 UI，回调不再自动落盘——落盘移到连接成功后）。
    #[test]
    fn test_build_trust_verified_pin() {
        let params = MobileConnectParams {
            id: "dev1".into(),
            nickname: "n".into(),
            challenge: "c".into(),
            server_addr: "1.2.3.4".into(),
            token: String::new(),
            server_pubkey: Some("pubkey-base64".into()),
            domain: false,
        };
        // Verified 分支不依赖 known_hosts 存储（强 pin 由握手层比对）。
        let slot = Arc::new(Mutex::new(None));
        assert!(matches!(build_trust(&params, slot), TrustPolicy::Verified(k) if k == "pubkey-base64"));

        let params_none = MobileConnectParams { server_pubkey: None, ..params };
        let slot2 = Arc::new(Mutex::new(None));
        assert!(matches!(build_trust(&params_none, slot2), TrustPolicy::Confirm(Some(_))));
    }


    /// 拒绝码文案表对桌面 HEAD 拒绝码域的覆盖钉：`unattended_unknown`
    /// （对齐桌面 policy::handshake_rejected_hint / i18n 语义）；既有码与
    /// 未知码行为不回归。
    #[test]
    fn test_humanize_reject_text_covers_head_codes() {
        let u = humanize_reject_text("Connection rejected: unattended_unknown|dev-x");
        assert!(
            u.starts_with("The target device is in unattended mode"),
            "got {u}"
        );
        let m = humanize_reject_text("Connection rejected: mutual_control_denied|target=dev-b");
        assert!(m.contains("forbid-mutual-control"), "got {m}");
        assert!(
            humanize_reject_text("Connection rejected: challenge_mismatch|x")
                .starts_with("Challenge code mismatch")
        );
        assert_eq!(humanize_reject_text("early eof"), "early eof");
    }

    /// ID 模式握手段对当前桌面 HEAD（协议 v4 + CX-1 挑战轮）的互通回归：
    /// 与 [`connect_and_run_id`] 握手调用同构的字段口径（client_id = 本机
    /// 完整设备 ID、Exact pin、挑战码经共享 client 握手内 HMAC 应答）打
    /// 真实 loopback——服务端用 core v4 入口
    /// `server_handshake_verified_with_nickname_generic`（内含 CX-1 挑战轮，
    /// 绑定 = 注册设备 ID）。双端任一失败即 fail。
    #[tokio::test]
    async fn r206_id_mode_handshake_loopback_head() {
        use kirin_desk_core::crypto::handshake::server_handshake_verified_with_nickname_generic;
        // 码表内挑战码（服务端展示字符集 ABCDEFGHJKLMNPQRSTUVWXYZ23456789）。
        let challenge = "ABCDEFGH2";
        let bind_id = "test-device-b"; // 服务端注册设备 ID（签名绑定名）
        let dir = std::env::temp_dir().join(format!("kirin_r206_id_srv_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let server = IdentityManager::load_or_generate(dir.clone(), "srv-b").expect("srv identity");
        let server_pubkey = server.public_key_base64();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        let chall = challenge.to_string();
        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            server_handshake_verified_with_nickname_generic(
                stream,
                &server,
                bind_id,
                "", // 无客户端 pin 预置
                None, // ID 模式（空域名客户端）：无昵称门
                Some(&chall), // 挑战码凭据 → CX-1 挑战轮
            )
            .await
        });
        // 客户端身份 + ID 模式字段口径（connect_and_run_id 同构）。
        let dir_c =
            std::env::temp_dir().join(format!("kirin_r206_id_cli_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir_c);
        let ident = IdentityManager::load_or_generate(dir_c, "cli-a").expect("cli identity");
        let from_peer = fingerprint(&ident.public_key_base64());
        let stream = tokio::net::TcpStream::connect(addr).await.expect("tcp connect");
        let channel = client_handshake_with_resolution(
            stream,
            &ident,
            &from_peer, // client_id = 本机指纹派生 ID
            "desktop",
            bind_id, // server_id = 被拨完整设备 ID（验签绑定值）
            PinExpectation::exact_from_base64(&server_pubkey).expect("pin"),
            None,
            challenge,
            Vec::new(),
            requested_max_width(),
        )
        .await
        .expect("ID-mode handshake against HEAD v4 server must succeed");
        assert_eq!(channel.peer_id, bind_id, "服务端签名绑定名 = 注册设备 ID");
        assert!(
            srv.await.expect("srv task").is_ok(),
            "服务端侧握手（含 CX-1 挑战轮校验）须同样成功"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// 域名模式解析产物直接喂 [`connect_peer_with_width`] 的前置不变量
    /// （M8-T040 红线：`peer.addr` 必须是「IP 字面量:port」，禁止字符串
    /// 解析路径）——v4 与 v6（方括号形态）两态解析输出都可零改直连。
    #[tokio::test]
    async fn r206_resolved_domain_addr_is_ip_literal_for_connect() {
        let out = resolve_domain_peer("device.example.com", &mock_domain_resolver())
            .await
            .unwrap();
        let sa: std::net::SocketAddr = out
            .addr
            .parse()
            .expect("v4 解析产物必须为 IP 字面量:port");
        assert_eq!(sa.port(), 59990);
        let r6 = MockDomainResolver {
            aaaa: vec!["2001:db8::1"],
            ..mock_domain_resolver()
        };
        let out6 = resolve_domain_peer("device.example.com", &r6).await.unwrap();
        let sa6: std::net::SocketAddr = out6
            .addr
            .parse()
            .expect("v6 解析产物必须为 [IP 字面量]:port");
        assert!(sa6.is_ipv6() && sa6.port() == 59990);
    }
}
