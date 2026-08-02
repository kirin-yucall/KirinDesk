//! R-03 (R03-S1)：可复用客户端建连链路。
//!
//! 把 CLI `connect` 全链路（discover → TXT 公钥校验 → known_hosts/确认 → pin
//! 握手 → SecureChannel）参数化为 [`ConnectionOptions`] + [`resolve_peer`] /
//! [`connect_peer`]，供 CLI、GUI 会话与断线重连（`reconnection.rs`）共用；
//! 确认策略以回调注入（CLI 自动放行 / GUI 弹窗复用，见 [`TrustPolicy`]）。
//!
//! 链路分两阶段：
//! 1. [`resolve_peer`]——目标解析（domain：DNS 发现 + TXT 校验 + 地址族选择；
//!    IP：地址组装），无连接副作用；
//! 2. [`connect_peer`]——TCP 连接 + pin/确认握手 → [`SecureChannel`]。
//!
//! 行为与旧 `cmd_connect` 零变化（错误文案见 [`ConnectError`] Display）。

use crate::crypto::ed25519::IdentityManager;
use crate::crypto::handshake::{
    client_handshake_with_confirm, CoreReason, HandshakeError, PinExpectation, SecureChannel,
};
use kirin_desk_dns::godaddy::GoDaddyClient;
use kirin_desk_dns::{DeviceInfo, DiscoveryService, IpFamily};
use std::net::IpAddr;
use std::sync::Arc;

/// DNS 发现配置（domain 模式；`ConnectionOptions::dns = None` = IP 直连）。
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// GoDaddy API key（`[godaddy] api_key`）。
    pub api_key: String,
    /// GoDaddy API secret（`[godaddy] api_secret`）。
    pub api_secret: String,
    /// GoDaddy API 地址（`[godaddy] api_url`）。
    pub api_url: String,
    /// 托管域名（`[godaddy] domain`）。
    pub domain: String,
    /// 地址族选择策略（`--ip-family` / `[transport] ip_family`）。
    pub ip_family: IpFamily,
}

/// 客户端信任策略（R03-S1：确认策略以回调注入，CLI 自动 / GUI 弹窗复用）。
#[derive(Clone)]
pub enum TrustPolicy {
    /// 带外可信公钥（DNS TXT / known_hosts 已确认）→ 握手强制比对，不等即拒
    /// （CLI-HSK-SEC-001）。
    Verified(String),
    /// 无带外公钥 → 确认回调判定（known_hosts 命中自动放行；未命中交互/弹窗
    /// 确认，CLI-KH-001/003）。拒绝 → 握手以 `UntrustedKey` 中止。
    Confirm(Option<Arc<dyn Fn(&str) -> bool + Send + Sync>>),
    /// domain 模式：发现后以 TXT 公钥为候选，调用方解析器决定最终 pin /
    /// 拒绝（CLI: known_hosts 优先，CLI-KH-004）。
    Resolve(Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>),
}

impl TrustPolicy {
    /// 确认回调的握手形态（`client_handshake_with_confirm` 需要 `Box<dyn Fn>`）。
    fn handshake_confirm(&self) -> Option<Box<dyn Fn(&str) -> bool + Send>> {
        match self {
            TrustPolicy::Confirm(Some(cb)) => {
                let cb = cb.clone();
                Some(Box::new(move |key: &str| cb(key)))
            }
            _ => None,
        }
    }
}

/// 客户端建连规格（R03-S1：`cmd_connect` 全链路的参数化；重连上下文
/// [`crate::connection::manager::ReconnectContext`] 原样保存）。
#[derive(Clone)]
pub struct ConnectionOptions {
    /// 目标：域名（自动 DNS 发现）或 IP 字面量。
    pub target: String,
    /// IP 模式端口（domain 模式以发现记录为准）。
    pub port: u16,
    /// 服务端昵称（握手 server_id；空 = 目标）。
    pub server_id: String,
    /// 挑战码（调用方负责用配置值填充缺省）。
    pub challenge: String,
    /// 设备类型（"desktop" / "server"）。
    pub device_type: String,
    /// 客户端身份（握手签名；重连复用同一身份，不重建）。
    pub client_identity: Arc<IdentityManager>,
    /// 客户端设备 ID。
    pub client_id: String,
    /// 客户端域名（服务端白名单按此匹配）；空 = domain 模式按
    /// `{device_id}.{dns.domain}` 推导。
    pub client_domain: String,
    /// 域名模式发现配置；`None` = IP 直连。
    pub dns: Option<DnsConfig>,
    /// 信任策略（pin / 确认回调注入）。
    pub trust: TrustPolicy,
}

/// 目标解析产物（阶段 1）。
#[derive(Debug, Clone)]
pub struct ResolvedPeer {
    /// 连接地址（"[v6]:port" / "v4:port"）。
    pub addr: String,
    /// 设备 id（domain 模式 = 发现返回；IP 模式 = server_id）。
    pub device_id: String,
    pub device_type: String,
    /// GoDaddy 域名（IP 模式空串）。
    pub domain: String,
    /// domain 模式发现详情（CLI 展示用）。
    pub discovered: Option<DeviceInfo>,
    /// domain 模式 TXT 公钥（IP 模式 None）。
    pub txt_pubkey: Option<String>,
}

/// 建连结果（阶段 2；CLI 打印 / GUI 会话共用）。
#[derive(Debug)]
pub struct ConnectOutcome {
    pub channel: SecureChannel,
    /// 实际连接地址。
    pub addr: String,
    /// 设备 id（记录 known_hosts / 设备表用）。
    pub device_id: String,
    pub device_type: String,
    /// 本次握手生效的公钥（domain 模式 = 解析出的 pin；Confirm 回调路径由
    /// 调用方自持槽位读取，见 CLI-KH-002）。
    pub trusted_key: Option<String>,
    /// GoDaddy 域名（IP 模式空串）。
    pub domain: String,
    /// domain 模式发现详情（IP 模式 None）。
    pub discovered: Option<DeviceInfo>,
}

/// 建连错误（各阶段可读原因；R03-S5 不可重连分类见 [`ConnectError::refusal_reason`]）。
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("GoDaddy API not configured. Run 'kirin_desk setup' first.")]
    DnsNotConfigured,
    #[error("Discovery FAILED: {0}")]
    Discovery(String),
    #[error("ERROR: device TXT record has NO public key — connection refused.")]
    NoTxtKey,
    #[error("ERROR: 设备无可用 IPv4/IPv6 地址（ip_family={0}）")]
    NoConnectAddr(String),
    #[error("Connection aborted: {0}")]
    TrustRejected(String),
    #[error("TCP connect FAILED: {0}")]
    Tcp(std::io::Error),
    #[error("Handshake FAILED: {0}")]
    Handshake(HandshakeError),
    /// R-03 (R03-S2)：无重连上下文（peer 规格未登记）。
    #[error("no reconnect context recorded (peer spec missing)")]
    NoReconnectContext,
}

/// R-03 (R03-S5)：不可重连原因分类（UI/CLI 明确文案用，不静默失败）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// 凭据过期 / 被服务端拒绝（挑战码错误、设备类型不符…）。
    CredentialExpired,
    /// 白名单 / 信任变更（公钥 mismatch、未被信任、TXT 公钥缺失）。
    TrustChanged,
    /// 服务端不可达（下线 / DNS 失效 / 网络）。
    ServerUnreachable,
    /// 其它（瞬态 / 上下文缺失）。
    Other,
}

impl RefusalReason {
    /// R03-S5：不可重连的明确原因文案（UI 覆盖层 / CLI self-test 共用）。
    pub fn message(&self, detail: &str) -> String {
        match self {
            RefusalReason::CredentialExpired => {
                format!("无法自动重连（凭据已过期或被服务端拒绝：{detail}）")
            }
            RefusalReason::TrustChanged => {
                format!("无法自动重连（对端身份或信任已变更：{detail}）")
            }
            RefusalReason::ServerUnreachable => {
                format!("无法自动重连（服务端不可达：{detail}）")
            }
            RefusalReason::Other => format!("无法自动重连（{detail}）"),
        }
    }
}

impl ConnectError {
    /// R03-S5：错误 → 不可重连分类（凭据过期 / 信任变更 / 服务端不可达）。
    pub fn refusal_reason(&self) -> RefusalReason {
        match self {
            ConnectError::Handshake(e) => match e {
                // 凭据维度：挑战码拒绝 / 类型不匹配（服务端会话维度失效）。
                HandshakeError::Rejected(_) | HandshakeError::TypeMismatch { .. } => {
                    RefusalReason::CredentialExpired
                }
                // 信任维度：身份/公钥不一致（MITM 防护、白名单变更）。
                HandshakeError::ServerKeyMismatch { .. }
                | HandshakeError::ClientKeyMismatch { .. }
                | HandshakeError::UntrustedKey(_)
                | HandshakeError::SignatureVerificationFailed => RefusalReason::TrustChanged,
                // 其余（Io/Timeout/Dns/InvalidMessage…）= 网络/瞬态。
                _ => RefusalReason::ServerUnreachable,
            },
            ConnectError::NoTxtKey | ConnectError::TrustRejected(_) => RefusalReason::TrustChanged,
            ConnectError::DnsNotConfigured
            | ConnectError::Discovery(_)
            | ConnectError::NoConnectAddr(_)
            | ConnectError::Tcp(_) => RefusalReason::ServerUnreachable,
            ConnectError::NoReconnectContext => RefusalReason::Other,
        }
    }
}

/// 地址族显示名（错误文案与 CLI `--ip-family` 值一致）。
fn ip_family_label(family: IpFamily) -> &'static str {
    match family {
        IpFamily::Auto => "auto",
        IpFamily::Ipv4 => "ipv4",
        IpFamily::Ipv6 => "ipv6",
    }
}

/// 阶段 1：目标解析。
///
/// - Domain 模式：`DNS 发现（SRV 端口 + AAAA IPv6 + TXT 公钥）→ TXT 公钥校验
///   （CLI-DNS-006，缺失即拒）→ 地址族选择`；
/// - IP 模式：直接组装 "[v6]:port" / "v4:port"。
///
/// 无连接副作用（发现属只读网络查询）。
pub async fn resolve_peer(opts: &ConnectionOptions) -> Result<ResolvedPeer, ConnectError> {
    let is_ip = opts.target.parse::<IpAddr>().is_ok() || opts.target.contains(':');
    if !is_ip {
        // ── Domain 模式：发现 → TXT 校验 → 地址族选择 ──
        let dns = opts.dns.as_ref().ok_or(ConnectError::DnsNotConfigured)?;
        let device_id = opts
            .target
            .trim_end_matches(&format!(".{}", dns.domain))
            .to_string();
        let client = GoDaddyClient::new(&dns.api_key, &dns.api_secret, &dns.api_url);
        let discovery = DiscoveryService::new(&client, &dns.domain);
        let info = discovery
            .discover(&device_id)
            .await
            .map_err(|e| ConnectError::Discovery(e.to_string()))?;
        if info.public_key_base64.is_empty() {
            // CLI-DNS-006: TXT 公钥缺失 → 拒绝连接，不回退信任网络公钥。
            return Err(ConnectError::NoTxtKey);
        }
        let selected = info.select_connect_addr(dns.ip_family).ok_or_else(|| {
            ConnectError::NoConnectAddr(ip_family_label(dns.ip_family).to_string())
        })?;
        Ok(ResolvedPeer {
            addr: selected.to_string(),
            device_id,
            device_type: info.device_type.clone(),
            domain: dns.domain.clone(),
            discovered: Some(info.clone()),
            txt_pubkey: Some(info.public_key_base64.clone()),
        })
    } else {
        // ── IP 模式：直接组装地址 ──
        let addr = if opts.target.contains(':') {
            format!(
                "[{}]:{}",
                opts.target.trim_matches(|c| c == '[' || c == ']'),
                opts.port
            )
        } else {
            format!("{}:{}", opts.target, opts.port)
        };
        Ok(ResolvedPeer {
            addr,
            device_id: opts.server_id.clone(),
            device_type: opts.device_type.clone(),
            domain: String::new(),
            discovered: None,
            txt_pubkey: None,
        })
    }
}

/// 对已连接流执行 pin/确认握手（建连链路与 ID 模式（`connect_stream` 已建流）
/// 共用的握手入口）。
///
/// 语义同 `client_handshake_with_confirm`（R-02 强类型 pin）：
/// - `pin = PinExpectation::Exact(key)` → 强制比对（CLI-HSK-SEC-001）；
/// - `pin = None(UserConfirmRequired)` + `confirm = Some(cb)` → 回调确认
///   （拒绝即断开；**回调缺失即拒绝**，无静默放行路径）；
/// - `pin = None(InternalLoopback)` → loopback 自签比对。
#[allow(clippy::too_many_arguments)]
pub async fn perform_handshake(
    stream: tokio::net::TcpStream,
    identity: &IdentityManager,
    client_id: &str,
    client_domain: &str,
    device_type: &str,
    server_id: &str,
    challenge: &str,
    pin: PinExpectation,
    key_confirm: Option<Box<dyn Fn(&str) -> bool + Send>>,
) -> Result<SecureChannel, HandshakeError> {
    client_handshake_with_confirm(
        stream,
        identity,
        client_id,
        client_domain,
        device_type,
        server_id,
        pin,
        key_confirm,
        challenge,
    )
    .await
}

/// 阶段 2：TCP 连接 + pin/确认握手 → [`SecureChannel`]。
///
/// 信任解析顺序（R03-S1）：`Verified` 直接 pin → `Resolve` 以 TXT 公钥为候选
/// 交调用方解析器（CLI-KH-004）→ `Confirm` 经确认回调放行 TXT 公钥。
pub async fn connect_peer(
    opts: &ConnectionOptions,
    peer: &ResolvedPeer,
) -> Result<ConnectOutcome, ConnectError> {
    // 信任解析：决定本次握手的期望公钥（None = 走确认回调）。
    let trusted_key = match &opts.trust {
        TrustPolicy::Verified(key) => Some(key.clone()),
        TrustPolicy::Resolve(resolve) => {
            let txt = peer.txt_pubkey.as_ref().ok_or(ConnectError::NoTxtKey)?;
            resolve(&peer.device_id, txt)
                .map(Some)
                .map_err(ConnectError::TrustRejected)?
        }
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
            // IP 模式：无带外公钥 → 回调判定。
            None => None,
        },
    };
    // 客户端域名：显式指定优先；domain 模式缺省按 `{device_id}.{domain}` 推导。
    let client_domain = if opts.client_domain.is_empty() && !peer.domain.is_empty() {
        format!("{}.{}", peer.device_id, peer.domain)
    } else {
        opts.client_domain.clone()
    };
    let stream = tokio::net::TcpStream::connect(&peer.addr)
        .await
        .map_err(ConnectError::Tcp)?;
    // R-02：pin 强类型——已解析出公钥 → `Exact` 强制比对；无带外公钥 →
    // `UserConfirmRequired`（确认回调必填，缺失即拒绝，无静默跳过路径）。
    let pin = match trusted_key.as_deref() {
        Some(key) => PinExpectation::exact_from_base64(key).map_err(ConnectError::Handshake)?,
        None => PinExpectation::None(CoreReason::UserConfirmRequired),
    };
    let channel = perform_handshake(
        stream,
        &opts.client_identity,
        &opts.client_id,
        &client_domain,
        &opts.device_type,
        &opts.server_id,
        &opts.challenge,
        pin,
        opts.trust.handshake_confirm(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::IdentityManager;

    fn test_opts(target: &str, port: u16, trust: TrustPolicy) -> ConnectionOptions {
        ConnectionOptions {
            target: target.to_string(),
            port,
            server_id: "peer".to_string(),
            challenge: String::new(),
            device_type: "desktop".to_string(),
            client_identity: Arc::new(
                IdentityManager::generate(
                    std::env::temp_dir()
                        .join(format!("kirindesk_client_test_{}", std::process::id())),
                )
                .unwrap(),
            ),
            client_id: "me".to_string(),
            client_domain: "me.local".to_string(),
            dns: None,
            trust,
        }
    }

    #[tokio::test]
    async fn test_resolve_ip_peer() {
        let opts = test_opts("2001:db8::1", 3389, TrustPolicy::Verified("k".to_string()));
        let peer = resolve_peer(&opts).await.unwrap();
        assert_eq!(peer.addr, "[2001:db8::1]:3389");
        assert_eq!(peer.device_id, "peer");
        assert_eq!(peer.device_type, "desktop");
        assert!(peer.discovered.is_none());
        assert!(peer.txt_pubkey.is_none());
    }

    #[tokio::test]
    async fn test_resolve_ipv4_peer() {
        let opts = test_opts("192.168.1.5", 3389, TrustPolicy::Verified("k".to_string()));
        let peer = resolve_peer(&opts).await.unwrap();
        assert_eq!(peer.addr, "192.168.1.5:3389");
    }

    #[test]
    fn test_refusal_classification() {
        use crate::crypto::handshake::HandshakeError;
        // 凭据过期：服务端拒绝（挑战码/白名单拒绝）。
        assert_eq!(
            ConnectError::Handshake(HandshakeError::Rejected("challenge mismatch".into()))
                .refusal_reason(),
            RefusalReason::CredentialExpired
        );
        assert_eq!(
            ConnectError::Handshake(HandshakeError::TypeMismatch {
                expected: "desktop".into(),
                actual: "server".into()
            })
            .refusal_reason(),
            RefusalReason::CredentialExpired
        );
        // 信任变更：公钥不一致 / 未被信任 / TXT 缺失。
        assert_eq!(
            ConnectError::Handshake(HandshakeError::ServerKeyMismatch {
                expected: "a".into(),
                got: "b".into()
            })
            .refusal_reason(),
            RefusalReason::TrustChanged
        );
        assert_eq!(
            ConnectError::TrustRejected("declined".into()).refusal_reason(),
            RefusalReason::TrustChanged
        );
        assert_eq!(
            ConnectError::NoTxtKey.refusal_reason(),
            RefusalReason::TrustChanged
        );
        // 服务端不可达：TCP / 发现失败。
        assert_eq!(
            ConnectError::Tcp(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "refused"
            ))
            .refusal_reason(),
            RefusalReason::ServerUnreachable
        );
        assert_eq!(
            ConnectError::Discovery("no records".into()).refusal_reason(),
            RefusalReason::ServerUnreachable
        );
        // 其它：无重连上下文。
        assert_eq!(
            ConnectError::NoReconnectContext.refusal_reason(),
            RefusalReason::Other
        );
    }

    #[test]
    fn test_refusal_messages_not_silent() {
        let m = RefusalReason::ServerUnreachable.message("connection refused");
        assert!(
            m.contains("无法自动重连"),
            "must be explicit, not silent: {m}"
        );
        assert!(m.contains("connection refused"));
    }
}
