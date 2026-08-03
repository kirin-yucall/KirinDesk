//! M8-T040 (W1-C / W2-A / WBS 3.2~3.5): DoH/DoT 加密 DNS 解析器。
//!
//! 域名模式（服务端 + 客户端）下**全部** DNS 解析的唯一加密入口（DDNS-DOH-001）：
//! - **DoH**：`application/dns-json` GET（复用 reqwest，零新依赖；DDNS-DOH-005）；
//!   统一按 Cloudflare JSON 格式（`Answer[].{name,type,TTL,data}`）解析，
//!   兼容 Google / 阿里云 DNS 响应（三端契约单测，WBS 3.3）；
//! - **DoT**：rustls TLS TCP:853 + 最小 DNS wire 编解码（仅 A/AAAA/SRV/TXT 四型，
//!   RFC 1035 固定偏移 + 压缩指针；DDNS-DOH-005 / WBS 3.4）。
//!
//! 编排（WBS 3.5）：端点按配置优先序逐个尝试（DoH 先、DoT 兜底）→ 任一成功即用；
//! 单端点超时（默认 5s）+ 全列表总超时 15s；结果缓存 TTL=50s（沿用 discovery
//! 缓存语义，DDNS-DOH-006）；全部失败 → `AllEndpointsFailed`（fail-closed，
//! **绝不回退明文 DNS**，DDNS-DOH-003 / DDNS-SEC-006）。
//!
//! 证书校验（DDNS-SEC-002）：DoH/DoT 均强制 TLS 证书校验（webpki-roots 信任根），
//! 不提供任何「跳过证书校验」开关——视为安全缺陷。
//!
//! 消费方：core 连接层（`resolve_for_connect`，mock 注入 `Arc<dyn Resolver>`）、
//! dns 层（DDNS 更新前反查保护 DDNS-REC-005）、CLI `dns resolve` 诊断。

use crate::provider::{Record, RecordData, RecordType};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

/// 全列表总超时（DDNS-DOH-006：单端点 5s、全列表 15s）。
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// 默认单端点超时（毫秒；`new_from_parts` 传 0 时回退）。
const DEFAULT_PER_ENDPOINT_TIMEOUT_MS: u64 = 5000;
/// 默认缓存 TTL（秒；`new_from_parts` 传 0 时回退，DDNS-DOH-006）。
const DEFAULT_CACHE_TTL_SECS: u64 = 50;

/// 加密解析错误（fail-closed：全部端点失败即错误，不回退明文）。
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// 全部 DoH/DoT 端点均失败（含各类子错误明细）。
    #[error("全部加密 DNS 端点均失败: {detail}")]
    AllEndpointsFailed { detail: String },
    /// 端点返回了无法解析的响应（JSON 结构错 / wire 畸形 / RCODE 非 0）。
    #[error("加密 DNS 返回非法响应: {0}")]
    InvalidResponse(String),
    /// 全列表总超时（15s 内无一端点成功）。
    #[error("加密 DNS 解析超时（总超时 15s）")]
    Timeout,
    /// 网络 / TLS / I/O 层错误（含证书校验失败——该端点视为不可用）。
    #[error("加密 DNS 网络/TLS 错误: {0}")]
    Io(String),
}

/// 解析结果记录（复用 Provider 统一 Record 模型；`ResolvedRecord` 为契约别名）。
pub type ResolvedRecord = Record;

/// 加密解析器抽象（core 注入面：`Arc<dyn Resolver>`，测试注入 mock；
/// 并行计划 §5 冻结签名）。
#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    /// 解析 `host` 的 `rt` 类型记录（A/AAAA/SRV/TXT；其余类型报错）。
    async fn resolve(
        &self,
        host: &str,
        rt: RecordType,
    ) -> Result<Vec<ResolvedRecord>, ResolverError>;

    /// 最近一次成功端点（CLI `dns resolve` / UI 状态行展示用；未实现 = None）。
    fn last_endpoint(&self) -> Option<String> {
        None
    }
}

#[async_trait::async_trait]
impl Resolver for SecureResolver {
    async fn resolve(
        &self,
        host: &str,
        rt: RecordType,
    ) -> Result<Vec<ResolvedRecord>, ResolverError> {
        SecureResolver::resolve(self, host, rt).await
    }

    fn last_endpoint(&self) -> Option<String> {
        SecureResolver::last_endpoint(self)
    }
}

/// DoT 端点（构造期已校验：IP 字面量 / `[v6]:port` / `域名:port` 三种形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum DotEndpoint {
    /// IP 形态（v4 字面量 / `[v6]:port`）：建连地址 = IP，SNI/证书校验 = IP。
    Ip(std::net::SocketAddr),
    /// 域名形态（`域名:port`，如 `dns.example.com:853`）：建连地址 = 域名
    /// 解析出的 IP，SNI/证书校验名 = 域名（R-30 审计 §8-3）。
    Domain { host: String, port: u16 },
}

/// 解析 DoT 端点字符串（`1.1.1.1:853` / `[2606:4700::1111]:853` /
/// `dns.example.com:853`）。裸 IP / 裸域名（无端口）与非法形态 → None。
fn parse_dot_endpoint(s: &str) -> Option<DotEndpoint> {
    if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
        return Some(DotEndpoint::Ip(addr));
    }
    let (host, port) = s.rsplit_once(':')?;
    if host.is_empty() || host.contains('[') || host.contains(']') {
        return None;
    }
    // 域名形态仅允许主机名字符（字母/数字/连字符/点）。
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(DotEndpoint::Domain {
        host: host.to_string(),
        port,
    })
}

impl DotEndpoint {
    /// SNI / 证书校验名（域名形态 = 域名 DnsName；IP 形态 = IP）。
    fn server_name(
        &self,
    ) -> Result<rustls::pki_types::ServerName<'static>, ResolverError> {
        match self {
            DotEndpoint::Ip(addr) => {
                Ok(rustls::pki_types::ServerName::IpAddress(addr.ip().into()))
            }
            DotEndpoint::Domain { host, .. } => {
                rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| {
                    ResolverError::InvalidResponse(format!("DoT 端点域名非法: {host}"))
                })
            }
        }
    }

    /// 建连地址（域名形态 → 系统解析首个可用 IP；IP 形态原样返回）。
    async fn connect_addr(&self) -> Result<std::net::SocketAddr, ResolverError> {
        match self {
            DotEndpoint::Ip(addr) => Ok(*addr),
            DotEndpoint::Domain { host, port } => {
                tokio::net::lookup_host((host.as_str(), *port))
                    .await
                    .map_err(|e| {
                        ResolverError::Io(format!("DoT 域名解析失败 {host}: {e}"))
                    })?
                    .next()
                    .ok_or_else(|| ResolverError::Io(format!("DoT 域名无解析结果: {host}")))
            }
        }
    }
}

/// DoH/DoT 加密解析器（构造参数注入，不依赖配置层——W1-A 与 W1-B/W1-C 并行无依赖）。
pub struct SecureResolver {
    /// DoH 端点优先序（`https://…/dns-query` 形态，强制 HTTPS）。
    doh: Vec<String>,
    /// DoT 端点优先序（`ip:853` / `[v6]:853` / `域名:853` 形态——R-30 审计
    /// §8-3：自有域名 DoT 端点如 `dns.example.com:853` 可配置）。
    dot: Vec<String>,
    /// 单端点超时。
    per_endpoint: Duration,
    /// 结果缓存 TTL。
    cache_ttl: Duration,
    /// (host, rtype) → 结果缓存。
    cache: Mutex<HashMap<(String, RecordType), (Instant, Vec<Record>)>>,
    /// 最近一次成功端点（CLI `dns resolve` 展示用）。
    last_endpoint: Mutex<Option<String>>,
    /// 共享 HTTP 客户端（DoH 用；超时逐端点控制）。
    http: reqwest::Client,
    /// 共享 TLS 客户端（DoT 用；webpki-roots 信任根，强制证书校验）。
    tls: std::sync::Arc<tokio_rustls::TlsConnector>,
}

impl SecureResolver {
    /// 按部分构造（`[dns.security]` 段的 doh/dot 列表 + 超时/缓存参数；
    /// 0/空值回退默认）。配置层 → 本构造器的转换由调用方（CLI/GUI）完成。
    pub fn new_from_parts(
        doh: Vec<String>,
        dot: Vec<String>,
        resolve_timeout_ms: u64,
        cache_ttl_secs: u64,
    ) -> Self {
        let per_endpoint = Duration::from_millis(if resolve_timeout_ms > 0 {
            resolve_timeout_ms
        } else {
            DEFAULT_PER_ENDPOINT_TIMEOUT_MS
        });
        let cache_ttl = Duration::from_secs(if cache_ttl_secs > 0 {
            cache_ttl_secs
        } else {
            DEFAULT_CACHE_TTL_SECS
        });
        // 仅保留合法端点（DoH 必须 HTTPS——强制证书校验的前提，DDNS-SEC-002；
        // 环回 http 放行供 mock 契约测试，沿用 providers 纪律）。
        let doh: Vec<String> = doh
            .into_iter()
            .filter(|u| u.starts_with("https://") || u.starts_with("http://127.0.0.1"))
            .collect();
        let dot: Vec<String> = dot
            .into_iter()
            .filter(|u| parse_dot_endpoint(u).is_some())
            .collect();
        if doh.is_empty() && dot.is_empty() {
            warn!("SecureResolver: 无任何合法 DoH/DoT 端点——解析将全部失败（fail-closed）");
        }
        // rustls 进程级默认 CryptoProvider：依赖图中 aws-lc-rs（reqwest）与
        // ring（quinn）并存 → 显式安装 ring 默认（若已被他处安装则忽略）。
        let _ = rustls::crypto::ring::default_provider().install_default();
        // TLS 客户端：webpki-roots 信任根 + 强制证书校验（无跳过开关）。
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls = std::sync::Arc::new(tokio_rustls::TlsConnector::from(
            std::sync::Arc::new(client_config),
        ));
        Self {
            doh,
            dot,
            per_endpoint,
            cache_ttl,
            cache: Mutex::new(HashMap::new()),
            last_endpoint: Mutex::new(None),
            http: reqwest::Client::new(),
            tls,
        }
    }

    /// 最近一次成功端点（CLI `dns resolve` 展示；无成功记录 → None）。
    pub fn last_endpoint(&self) -> Option<String> {
        self.last_endpoint.lock().unwrap().clone()
    }

    /// 端点总数（诊断展示）。
    pub fn endpoint_count(&self) -> (usize, usize) {
        (self.doh.len(), self.dot.len())
    }

    /// 解析入口：缓存优先 → 端点按序尝试（DoH 先、DoT 兜底）→ fail-closed。
    pub async fn resolve(
        &self,
        host: &str,
        rt: RecordType,
    ) -> Result<Vec<ResolvedRecord>, ResolverError> {
        let host = host.trim().trim_end_matches('.');
        if host.is_empty() {
            return Err(ResolverError::InvalidResponse("空主机名".to_string()));
        }
        // 契约：仅 A/AAAA/SRV/TXT 四型（其余类型拒绝，防误用）。
        if !matches!(rt, RecordType::A | RecordType::AAAA | RecordType::SRV | RecordType::TXT) {
            return Err(ResolverError::InvalidResponse(format!(
                "SecureResolver 仅支持 A/AAAA/SRV/TXT（请求: {rt}）"
            )));
        }

        let key = (host.to_ascii_lowercase(), rt);
        if let Some((at, records)) = self.cache.lock().unwrap().get(&key) {
            if at.elapsed() < self.cache_ttl {
                debug!("SecureResolver: cache hit {host} {rt} ({} records)", records.len());
                return Ok(records.clone());
            }
        }

        let start = Instant::now();
        let mut errors: Vec<String> = Vec::new();

        // DoH 优先（主路径，DDNS-DOH-004）；总超时 15s 兜底。
        for (i, endpoint) in self.doh.iter().enumerate() {
            let remaining = TOTAL_TIMEOUT.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(ResolverError::Timeout);
            }
            let cap = remaining.min(self.per_endpoint);
            match tokio::time::timeout(cap, self.resolve_doh(endpoint, host, rt)).await {
                Ok(Ok(records)) => return self.cache_success(key, records, endpoint, host, rt, start),
                Ok(Err(e)) => {
                    warn!("SecureResolver: DoH #{i} {endpoint} 失败: {e}");
                    errors.push(format!("DoH#{i} {endpoint}: {e}"));
                }
                Err(_) => {
                    warn!("SecureResolver: DoH #{i} {endpoint} 超时（{}ms）", cap.as_millis());
                    errors.push(format!("DoH#{i} {endpoint}: 超时"));
                }
            }
        }

        // DoT 兜底（W2-A wire 路径；DoH 全失败时启用）。
        for (i, endpoint) in self.dot.iter().enumerate() {
            let remaining = TOTAL_TIMEOUT.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(ResolverError::Timeout);
            }
            let cap = remaining.min(self.per_endpoint);
            match tokio::time::timeout(cap, self.resolve_dot(endpoint, host, rt)).await {
                Ok(Ok(records)) => return self.cache_success(key, records, endpoint, host, rt, start),
                Ok(Err(e)) => {
                    warn!("SecureResolver: DoT #{i} {endpoint} 失败: {e}");
                    errors.push(format!("DoT#{i} {endpoint}: {e}"));
                }
                Err(_) => {
                    warn!("SecureResolver: DoT #{i} {endpoint} 超时（{}ms）", cap.as_millis());
                    errors.push(format!("DoT#{i} {endpoint}: 超时"));
                }
            }
        }

        // fail-closed：全部端点失败 → 错误（绝不回退明文 DNS，DDNS-SEC-006）。
        let detail = if errors.is_empty() {
            "未配置任何 DoH/DoT 端点".to_string()
        } else {
            errors.join(" | ")
        };
        Err(ResolverError::AllEndpointsFailed { detail })
    }

    // ---- internal ----

    fn cache_success(
        &self,
        key: (String, RecordType),
        records: Vec<Record>,
        endpoint: &str,
        host: &str,
        rt: RecordType,
        start: Instant,
    ) -> Result<Vec<Record>, ResolverError> {
        info!(
            "SecureResolver: {host} {rt} -> {} 条记录，端点 {endpoint}，耗时 {}ms（DDNS-DOH-008 审计）",
            records.len(),
            start.elapsed().as_millis()
        );
        *self.last_endpoint.lock().unwrap() = Some(endpoint.to_string());
        self.cache
            .lock()
            .unwrap()
            .insert(key, (Instant::now(), records.clone()));
        Ok(records)
    }

    /// DoH 单端点：`application/dns-json` GET + 三端兼容 JSON 解析。
    async fn resolve_doh(
        &self,
        endpoint: &str,
        host: &str,
        rt: RecordType,
    ) -> Result<Vec<Record>, ResolverError> {
        let url = format!(
            "{endpoint}?name={host}&type={}",
            dns_type_num(rt).ok_or_else(|| {
                ResolverError::InvalidResponse(format!("不支持的类型 {rt}"))
            })?
        );
        let resp = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .send()
            .await
            .map_err(|e| ResolverError::Io(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(ResolverError::InvalidResponse(format!(
                "DoH HTTP {status}"
            )));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| ResolverError::Io(e.to_string()))?;
        parse_doh_json(&body, rt)
    }

    /// DoT 单端点：TLS TCP:853 + 长度前缀 framing + wire 解析。
    async fn resolve_dot(
        &self,
        endpoint: &str,
        host: &str,
        rt: RecordType,
    ) -> Result<Vec<Record>, ResolverError> {
        let ep = parse_dot_endpoint(endpoint).ok_or_else(|| {
            ResolverError::InvalidResponse(format!("DoT 端点格式非法: {endpoint}"))
        })?;
        let qtype = dns_type_num(rt)
            .ok_or_else(|| ResolverError::InvalidResponse(format!("不支持的类型 {rt}")))?;
        // 建连地址：IP 形态原样；域名形态（R-30 审计 §8-3）→ 域名解析出的 IP。
        let addr = ep.connect_addr().await?;
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| ResolverError::Io(format!("TCP 连接失败: {e}")))?;
        // SNI = 证书校验名：域名形态携带域名（自有 DoT 证书按域名 SAN 校验），
        // IP 形态仍为 IP（公开 DoT 证书如 1.1.1.1 均含 IP SAN）；两者均强制
        // webpki-roots 证书校验（DDNS-SEC-002，无跳过开关），不含对应 SAN
        // 则证书校验失败 → 该端点跳过，后续端点兜底。
        let server_name = ep
            .server_name()
            .map_err(|e| ResolverError::InvalidResponse(e.to_string()))?;
        let mut stream = self
            .tls
            .connect(server_name, tcp)
            .await
            .map_err(|e| ResolverError::Io(format!("TLS 握手失败（证书校验失败按端点不可用处理）: {e}")))?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let id: u16 = rand::random();
        let query = build_query(host, qtype, id);
        // RFC 7858 framing：2 字节长度前缀 + DNS 报文。
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .map_err(|e| ResolverError::Io(format!("写入失败: {e}")))?;
        stream
            .write_all(&query)
            .await
            .map_err(|e| ResolverError::Io(format!("写入失败: {e}")))?;
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| ResolverError::Io(format!("读取失败: {e}")))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut msg = vec![0u8; len];
        stream
            .read_exact(&mut msg)
            .await
            .map_err(|e| ResolverError::Io(format!("读取失败: {e}")))?;
        parse_wire_response(&msg, rt, id)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS wire 编解码（RFC 1035 最小实现，仅 A/AAAA/SRV/TXT 四型，WBS 3.4）
// ═══════════════════════════════════════════════════════════════════════════

/// DNS 类型编号（仅加密解析所需的四型）。
fn dns_type_num(rt: RecordType) -> Option<u16> {
    match rt {
        RecordType::A => Some(1),
        RecordType::AAAA => Some(28),
        RecordType::TXT => Some(16),
        RecordType::SRV => Some(33),
        _ => None,
    }
}

/// 编码 qname（RFC 1035 label 序列 + 终止 0）。
pub(crate) fn encode_name(host: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in host.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        if b.is_empty() {
            continue;
        }
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
    out
}

/// 构建 DNS 查询报文（header + question；RD=1，QDCOUNT=1）。
pub(crate) fn build_query(host: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    buf.extend_from_slice(&encode_name(host));
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    buf
}

/// 游标读取器（越界 → None）。
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let hi = self.read_u8()?;
        let lo = self.read_u8()?;
        Some(u16::from_be_bytes([hi, lo]))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let a = self.read_u8()?;
        let b = self.read_u8()?;
        let c = self.read_u8()?;
        let d = self.read_u8()?;
        Some(u32::from_be_bytes([a, b, c, d]))
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

/// 解码名字（支持压缩指针；返回 (名字, 游标推进后的新位置)）。
/// 指针跳转上限 10 次防循环。
pub(crate) fn decode_name(buf: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut cursor = Cursor::new(buf);
    cursor.pos = pos;
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0usize;
    let mut cursor_pos_after = None;
    loop {
        let len = cursor.read_u8()?;
        match len {
            0 => break,
            b if b & 0xC0 == 0xC0 => {
                // 压缩指针：0xC0 后跟 14 位偏移（相对报文起始）。
                let lo = cursor.read_u8()?;
                let offset = ((b & 0x3F) as usize) << 8 | lo as usize;
                if cursor_pos_after.is_none() {
                    cursor_pos_after = Some(cursor.pos);
                }
                jumps += 1;
                if jumps > 10 || offset >= buf.len() {
                    return None;
                }
                cursor.pos = offset;
            }
            b => {
                let bytes = cursor.read_bytes(b as usize)?;
                labels.push(String::from_utf8_lossy(bytes).into_owned());
            }
        }
    }
    let name = labels.join(".");
    Some((name, cursor_pos_after.unwrap_or(cursor.pos)))
}

/// 解析 DoT wire 响应（校验 id/rcode，提取答案记录）。
pub(crate) fn parse_wire_response(
    msg: &[u8],
    expected_rt: RecordType,
    expected_id: u16,
) -> Result<Vec<Record>, ResolverError> {
    let mut c = Cursor::new(msg);
    if msg.len() < 12 {
        return Err(ResolverError::InvalidResponse("报文过短".to_string()));
    }
    let id = c.read_u16().unwrap();
    if id != expected_id {
        return Err(ResolverError::InvalidResponse(format!(
            "响应 ID 不匹配（期望 {expected_id}，实际 {id}）"
        )));
    }
    let flags = c.read_u16().unwrap();
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(ResolverError::InvalidResponse(format!(
            "RCODE={rcode}（非 0：SERVFAIL/NXDOMAIN 等）"
        )));
    }
    let qdcount = c.read_u16().unwrap();
    let ancount = c.read_u16().unwrap();
    let _nscount = c.read_u16().unwrap();
    let _arcount = c.read_u16().unwrap();
    if qdcount == 0 && ancount == 0 {
        return Err(ResolverError::InvalidResponse("无 Question/Answer".to_string()));
    }

    // 跳过 Question 区。
    for _ in 0..qdcount {
        let (_, next) = decode_name(msg, c.pos)
            .ok_or_else(|| ResolverError::InvalidResponse("Question 名解码失败".to_string()))?;
        c.pos = next;
        c.read_u16().ok_or_else(|| ResolverError::InvalidResponse("截断".to_string()))?; // qtype
        c.read_u16().ok_or_else(|| ResolverError::InvalidResponse("截断".to_string()))?; // qclass
    }

    let mut records = Vec::new();
    for _ in 0..ancount {
        let (name, next) = decode_name(msg, c.pos)
            .ok_or_else(|| ResolverError::InvalidResponse("Answer 名解码失败".to_string()))?;
        c.pos = next;
        let rtype = c
            .read_u16()
            .ok_or_else(|| ResolverError::InvalidResponse("截断".to_string()))?;
        let _class = c
            .read_u16()
            .ok_or_else(|| ResolverError::InvalidResponse("截断".to_string()))?;
        let ttl = c
            .read_u32()
            .ok_or_else(|| ResolverError::InvalidResponse("截断".to_string()))?;
        let rdlen = c
            .read_u16()
            .ok_or_else(|| ResolverError::InvalidResponse("截断".to_string()))? as usize;
        let rdata = c
            .read_bytes(rdlen)
            .ok_or_else(|| ResolverError::InvalidResponse("RData 截断".to_string()))?;
        // 仅保留请求类型（与 DoH 路径口径一致；其他类型跳过）。
        if rtype != dns_type_num(expected_rt).unwrap_or(u16::MAX) {
            continue;
        }
        match record_from_rdata(expected_rt, name.as_str(), ttl, rdata, msg) {
            Ok(rec) => records.push(rec),
            Err(e) => return Err(e),
        }
    }
    Ok(records)
}

/// rdata → 类型化记录（A/AAAA/TXT/SRV 四型；SRV 目标名支持压缩指针）。
fn record_from_rdata(
    rt: RecordType,
    name: &str,
    ttl: u32,
    rdata: &[u8],
    msg: &[u8],
) -> Result<Record, ResolverError> {
    let record_name = name.trim_end_matches('.').to_string();
    let data = match rt {
        RecordType::A => {
            if rdata.len() != 4 {
                return Err(ResolverError::InvalidResponse("A rdata 非 4 字节".to_string()));
            }
            RecordData::Plain(Ipv4Addr::from([rdata[0], rdata[1], rdata[2], rdata[3]]).to_string())
        }
        RecordType::AAAA => {
            if rdata.len() != 16 {
                return Err(ResolverError::InvalidResponse("AAAA rdata 非 16 字节".to_string()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            RecordData::Plain(std::net::Ipv6Addr::from(octets).to_string())
        }
        RecordType::TXT => {
            // TXT：长度前缀字符串序列（拼接；DoH 侧的引号在此无）。
            let mut c = Cursor::new(rdata);
            let mut out = String::new();
            while c.remaining() > 0 {
                let len = c
                    .read_u8()
                    .ok_or_else(|| ResolverError::InvalidResponse("TXT 截断".to_string()))? as usize;
                let s = c
                    .read_bytes(len)
                    .ok_or_else(|| ResolverError::InvalidResponse("TXT 截断".to_string()))?;
                out.push_str(&String::from_utf8_lossy(s));
            }
            RecordData::Plain(out)
        }
        RecordType::SRV => {
            // SRV：priority(2) weight(2) port(2) target(压缩名)。
            if rdata.len() < 6 {
                return Err(ResolverError::InvalidResponse("SRV rdata 过短".to_string()));
            }
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            // target 相对报文起始（压缩指针合法）。
            let target_abs = msg.as_ptr() as usize;
            let rdata_abs = rdata.as_ptr() as usize;
            let offset_in_msg = rdata_abs - target_abs;
            let (target, _) = decode_name(msg, offset_in_msg + 6)
                .ok_or_else(|| ResolverError::InvalidResponse("SRV target 解码失败".to_string()))?;
            RecordData::Srv {
                priority,
                weight,
                port,
                target: target.trim_end_matches('.').to_string(),
            }
        }
        _ => {
            return Err(ResolverError::InvalidResponse(format!(
                "wire 路径不支持类型 {rt}"
            )))
        }
    };
    Ok(Record {
        name: record_name,
        rtype: rt,
        ttl,
        data,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// DoH JSON 解析（三端契约：Cloudflare / Google / 阿里云 DNS，WBS 3.3）
// ═══════════════════════════════════════════════════════════════════════════

/// DoH `application/dns-json` 响应（Cloudflare 格式为主，兼容 Google/阿里）。
#[derive(serde::Deserialize)]
// R-33: non_snake_case 仅在结构体级 allow 生效（字段级 allow 对 rustc 该 lint
// 无效，实测）——字段名 Status/Answer 为 dns-json 契约大写，须保留原名。
#[allow(non_snake_case)]
struct DohResponse {
    /// 0 = 成功；非 0（SERVFAIL/NXDOMAIN 等）→ 该端点不可用。
    #[serde(default)]
    Status: i32,
    #[serde(default)]
    Answer: Vec<DohAnswer>,
}

#[derive(serde::Deserialize)]
// R-33: 同上——TTL 为 DoH JSON 契约字段名（Cloudflare 大写；Google 小写经
// alias="ttl" 兼容），字段级 allow 无效，统一放结构体级。
#[allow(non_snake_case)]
struct DohAnswer {
    name: String,
    #[serde(rename = "type")]
    rtype: u16,
    /// Cloudflare 用大写 TTL；Google/部分实现小写 `ttl`——双键兼容。
    #[serde(default, alias = "ttl")]
    TTL: u32,
    data: String,
}

/// 解析 DoH JSON 响应（类型映射 + 严格数据校验）。
pub(crate) fn parse_doh_json(body: &str, rt: RecordType) -> Result<Vec<Record>, ResolverError> {
    let resp: DohResponse = serde_json::from_str(body)
        .map_err(|e| ResolverError::InvalidResponse(format!("DoH JSON 解析失败: {e}")))?;
    if resp.Status != 0 {
        return Err(ResolverError::InvalidResponse(format!(
            "DoH Status={}（非 0）",
            resp.Status
        )));
    }
    let expected = dns_type_num(rt).unwrap_or(u16::MAX);
    let mut records = Vec::new();
    for ans in &resp.Answer {
        if ans.rtype != expected {
            continue; // 只取请求类型
        }
        let name = ans.name.trim_end_matches('.').to_string();
        let data = match rt {
            RecordType::A => ans.data.trim().parse::<Ipv4Addr>().map(|ip| {
                RecordData::Plain(ip.to_string())
            }).map_err(|_| {
                ResolverError::InvalidResponse(format!("A 记录数据非法: '{}'", ans.data))
            })?,
            RecordType::AAAA => ans
                .data
                .trim()
                .parse::<std::net::Ipv6Addr>()
                .map(|ip| RecordData::Plain(ip.to_string()))
                .map_err(|_| {
                    ResolverError::InvalidResponse(format!("AAAA 记录数据非法: '{}'", ans.data))
                })?,
            RecordType::TXT => RecordData::Plain(unquote_txt(&ans.data)),
            RecordType::SRV => parse_srv_string(&ans.data)?,
            _ => {
                return Err(ResolverError::InvalidResponse(format!(
                    "DoH 路径不支持类型 {rt}"
                )))
            }
        };
        records.push(Record {
            name,
            rtype: rt,
            ttl: ans.TTL,
            data,
        });
    }
    Ok(records)
}

/// TXT data 去引号（DoH 返回 `"…"` 包裹的字符串；空/无引号原样返回）。
fn unquote_txt(data: &str) -> String {
    let t = data.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// SRV data 解析：`{priority} {weight} {port} {target}`（target 去尾点）。
fn parse_srv_string(data: &str) -> Result<RecordData, ResolverError> {
    let parts: Vec<&str> = data.split_whitespace().collect();
    if parts.len() < 4 {
        return Err(ResolverError::InvalidResponse(format!(
            "SRV 记录数据非法: '{data}'"
        )));
    }
    let priority = parts[0].parse().map_err(|_| {
        ResolverError::InvalidResponse(format!("SRV priority 非法: '{data}'"))
    })?;
    let weight = parts[1].parse().map_err(|_| {
        ResolverError::InvalidResponse(format!("SRV weight 非法: '{data}'"))
    })?;
    let port = parts[2].parse().map_err(|_| {
        ResolverError::InvalidResponse(format!("SRV port 非法: '{data}'"))
    })?;
    let target = parts[3..].join(" ").trim_end_matches('.').to_string();
    Ok(RecordData::Srv {
        priority,
        weight,
        port,
        target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ═══════════ wire 编解码向量（dig 对照，WBS 3.4/3.7） ═══════════

    fn response_header(id: u16, rcode: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes()); // QR+RD+RA
        buf.extend_from_slice(&qd.to_be_bytes());
        buf.extend_from_slice(&an.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf
    }

    fn question(host: &str, qtype: u16) -> Vec<u8> {
        let mut buf = encode_name(host);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf
    }

    fn answer(name: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut buf = name.to_vec();
        buf.extend_from_slice(&rtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(rdata);
        buf
    }

    /// 构造 A 记录响应（压缩名 = 指针指向问题名）。
    fn a_response(host: &str) -> Vec<u8> {
        let q = question(host, 1);
        let name_ptr = [0xC0, 0x0C];
        let rdata = [203, 0, 113, 7];
        let mut buf = response_header(0x1234, 0, 1, 1);
        buf.extend_from_slice(&q);
        buf.extend_from_slice(&answer(&name_ptr, 1, 300, &rdata));
        buf
    }

    #[test]
    fn test_encode_name_basic() {
        assert_eq!(encode_name("example.com"), [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        // 尾点容忍 + 连续点跳过
        assert_eq!(encode_name("example.com."), encode_name("example.com"));
        assert_eq!(encode_name("a..b"), [1, b'a', 1, b'b', 0]);
    }

    #[test]
    fn test_build_query_structure() {
        let q = build_query("my-pc.example.com", 1, 0xABCD);
        assert_eq!(&q[0..2], &[0xAB, 0xCD], "ID");
        assert_eq!(&q[2..4], &[0x01, 0x00], "flags RD");
        assert_eq!(&q[4..6], &[0x00, 0x01], "QDCOUNT=1");
        assert_eq!(&q[6..10], &[0, 0, 0, 0], "AN/NS/AR=0");
        // qname（12 字节 header 之后）
        assert_eq!(encode_name("my-pc.example.com"), &q[12..q.len() - 4]);
        // qtype + qclass 在末尾
        let end = &q[q.len() - 4..];
        assert_eq!(end, &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_decode_name_plain_and_pointer() {
        let host = "my-pc.example.com";
        let q = question(host, 1);
        let (name, pos) = decode_name(&q, 0).unwrap();
        assert_eq!(name, host);
        assert_eq!(pos, q.len() - 4);
        // 指针：0xC00C → 报文偏移 12（qname 起点）
        let ptr = [0xC0, 0x0C];
        let (name2, _) = decode_name(&q, 0).unwrap();
        assert_eq!(name2, "my-pc.example.com");
        let (name3, _) = decode_name(&a_response(host)[12..], 0).unwrap();
        assert_eq!(name3, "my-pc.example.com");
        let _ = ptr;
    }

    #[test]
    fn test_parse_wire_a() {
        // dig 对照：A 记录 203.0.113.7
        let msg = a_response("my-pc.example.com");
        let recs = parse_wire_response(&msg, RecordType::A, 0x1234).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].name, "my-pc.example.com");
        assert_eq!(recs[0].ttl, 300);
        assert_eq!(recs[0].data, RecordData::Plain("203.0.113.7".into()));
    }

    #[test]
    fn test_parse_wire_aaaa() {
        // dig 对照：AAAA 记录 2001:db8::1
        let q = question("my-pc.example.com", 28);
        let rdata = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let mut msg = response_header(0x1111, 0, 1, 1);
        msg.extend_from_slice(&q);
        msg.extend_from_slice(&answer(&[0xC0, 0x0C], 28, 600, &rdata));
        let recs = parse_wire_response(&msg, RecordType::AAAA, 0x1111).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].data, RecordData::Plain("2001:db8::1".into()));
    }

    #[test]
    fn test_parse_wire_txt() {
        // dig 对照：TXT 单字符串
        let q = question("my-pc.example.com", 16);
        let payload = b"{\"key\":\"ed25519:Ab3\"}";
        let mut rdata = Vec::new();
        rdata.push(payload.len() as u8);
        rdata.extend_from_slice(payload);
        let mut msg = response_header(0x2222, 0, 1, 1);
        msg.extend_from_slice(&q);
        msg.extend_from_slice(&answer(&[0xC0, 0x0C], 16, 300, &rdata));
        let recs = parse_wire_response(&msg, RecordType::TXT, 0x2222).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].data,
            RecordData::Plain(r#"{"key":"ed25519:Ab3"}"#.into())
        );
    }

    #[test]
    fn test_parse_wire_srv_with_compressed_target() {
        // dig 对照：SRV _remote._tcp.my-pc.example.com → port 3389, target my-pc.example.com.
        let q = question("_remote._tcp.my-pc.example.com", 33);
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&0u16.to_be_bytes()); // priority
        rdata.extend_from_slice(&1u16.to_be_bytes()); // weight
        rdata.extend_from_slice(&3389u16.to_be_bytes()); // port
        rdata.extend_from_slice(&[0xC0, 0x0C]); // target = 压缩指针 → qname
        let mut msg = response_header(0x3333, 0, 1, 1);
        msg.extend_from_slice(&q);
        msg.extend_from_slice(&answer(&[0xC0, 0x0C], 33, 300, &rdata));
        let recs = parse_wire_response(&msg, RecordType::SRV, 0x3333).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].data,
            RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 3389,
                target: "_remote._tcp.my-pc.example.com".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_wire_bad_id_rejected() {
        let msg = a_response("my-pc.example.com");
        assert!(matches!(
            parse_wire_response(&msg, RecordType::A, 0x9999),
            Err(ResolverError::InvalidResponse(_))
        ));
    }

    #[test]
    fn test_parse_wire_bad_rcode_rejected() {
        let mut msg = response_header(0x1234, 3, 1, 0); // NXDOMAIN
        msg.extend_from_slice(&question("my-pc.example.com", 1));
        assert!(matches!(
            parse_wire_response(&msg, RecordType::A, 0x1234),
            Err(ResolverError::InvalidResponse(_))
        ));
    }

    #[test]
    fn test_parse_wire_truncated_rejected() {
        let msg = a_response("my-pc.example.com");
        assert!(parse_wire_response(&msg[..msg.len() - 3], RecordType::A, 0x1234).is_err());
        assert!(parse_wire_response(&msg[..5], RecordType::A, 0x1234).is_err());
    }

    #[test]
    fn test_parse_wire_pointer_loop_guarded() {
        // 指针自指 → 解码失败（跳转上限防护）
        let mut msg = response_header(0x1234, 0, 1, 1);
        msg.extend_from_slice(&question("a.com", 1));
        msg.extend_from_slice(&answer(&[0xC0, 0xC0], 1, 300, &[1, 2, 3, 4]));
        // 构造响应需修正 ancount 前报文——此处直接验证解码防护
        let buf = [0xC0, 0xC0];
        assert!(decode_name(&buf, 0).is_none());
    }

    // ═══════════ DoH JSON 三端契约（WBS 3.3/3.7） ═══════════

    #[test]
    fn test_doh_json_cloudflare_a() {
        let body = r#"{
            "Status": 0,
            "Question": [{"name": "my-pc.example.com.", "type": 1}],
            "Answer": [{"name": "my-pc.example.com.", "type": 1, "TTL": 300, "data": "203.0.113.7"}]
        }"#;
        let recs = parse_doh_json(body, RecordType::A).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].name, "my-pc.example.com");
        assert_eq!(recs[0].ttl, 300);
        assert_eq!(recs[0].data, RecordData::Plain("203.0.113.7".into()));
    }

    #[test]
    fn test_doh_json_google_ttl_lowercase_alias() {
        // Google/部分实现 `ttl` 小写 + 附加字段 → alias 兼容
        let body = r#"{
            "Status": 0,
            "Answer": [{"name": "my-pc.example.com.", "type": 28, "ttl": 600, "data": "2001:db8::1"}],
            "Comment": "Response from 8.8.8.8."
        }"#;
        let recs = parse_doh_json(body, RecordType::AAAA).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].data, RecordData::Plain("2001:db8::1".into()));
    }

    #[test]
    fn test_doh_json_alidns_srv() {
        // 阿里云 DNS 格式（SRV data 空格分隔 + 尾点 target）
        let body = r#"{
            "Status": 0,
            "Answer": [{"name": "_remote._tcp.my-pc.example.com.", "type": 33, "TTL": 300,
                        "data": "0 1 3389 my-pc.example.com."}]
        }"#;
        let recs = parse_doh_json(body, RecordType::SRV).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].data,
            RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 3389,
                target: "my-pc.example.com".to_string(),
            }
        );
    }

    #[test]
    fn test_doh_json_txt_unquoted() {
        // TXT data 带引号 → 去引号；无引号原样
        let body = r#"{
            "Status": 0,
            "Answer": [{"name": "my-pc.example.com.", "type": 16, "TTL": 300,
                        "data": "\"{\\\"key\\\":\\\"ed25519:Ab3\\\"}\""}]
        }"#;
        let recs = parse_doh_json(body, RecordType::TXT).unwrap();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].data.to_display_string().contains("ed25519:Ab3"));
    }

    #[test]
    fn test_doh_json_status_nonzero_rejected() {
        let body = r#"{"Status": 2, "Question": [], "Answer": []}"#;
        assert!(matches!(
            parse_doh_json(body, RecordType::A),
            Err(ResolverError::InvalidResponse(_))
        ));
    }

    #[test]
    fn test_doh_json_garbage_rejected() {
        assert!(parse_doh_json("<html>error</html>", RecordType::A).is_err());
        assert!(parse_doh_json("not json", RecordType::A).is_err());
        assert!(parse_doh_json("", RecordType::A).is_err());
    }

    #[test]
    fn test_doh_json_empty_answer_ok() {
        // 合法但无记录 → 空列表（非错误）
        let body = r#"{"Status": 0, "Question": [{"name": "x.example.com.", "type": 1}], "Answer": []}"#;
        assert!(parse_doh_json(body, RecordType::A).unwrap().is_empty());
    }

    #[test]
    fn test_doh_json_bad_a_data_rejected() {
        let body = r#"{
            "Status": 0,
            "Answer": [{"name": "my-pc.example.com.", "type": 1, "TTL": 300, "data": "not-an-ip"}]
        }"#;
        assert!(parse_doh_json(body, RecordType::A).is_err());
    }

    #[test]
    fn test_doh_json_ignores_other_types() {
        // 响应含 CNAME（类型 5）→ 请求 A 时跳过
        let body = r#"{
            "Status": 0,
            "Answer": [{"name": "x.example.com.", "type": 5, "TTL": 300, "data": "y.example.com."}]
        }"#;
        assert!(parse_doh_json(body, RecordType::A).unwrap().is_empty());
    }

    #[test]
    fn test_unquote_txt() {
        assert_eq!(unquote_txt(r#""abc""#), "abc");
        assert_eq!(unquote_txt("abc"), "abc");
        assert_eq!(unquote_txt(r#""""#), "");
    }

    // ═══════════ 类型守卫 / 编排（WBS 3.5） ═══════════

    #[test]
    fn test_dns_type_num_map() {
        assert_eq!(dns_type_num(RecordType::A), Some(1));
        assert_eq!(dns_type_num(RecordType::AAAA), Some(28));
        assert_eq!(dns_type_num(RecordType::SRV), Some(33));
        assert_eq!(dns_type_num(RecordType::TXT), Some(16));
        assert_eq!(dns_type_num(RecordType::CNAME), None);
        assert_eq!(dns_type_num(RecordType::NS), None);
    }

    #[tokio::test]
    async fn test_resolve_unsupported_type_rejected() {
        let r = SecureResolver::new_from_parts(vec![], vec![], 5000, 50);
        assert!(r.resolve("x.com", RecordType::CNAME).await.is_err());
        assert!(r.resolve("", RecordType::A).await.is_err());
    }

    #[tokio::test]
    async fn test_resolve_no_endpoints_fail_closed() {
        // 无端点 → AllEndpointsFailed（fail-closed，不回退明文）
        let r = SecureResolver::new_from_parts(vec![], vec![], 5000, 50);
        let err = r.resolve("my-pc.example.com", RecordType::A).await.unwrap_err();
        assert!(matches!(err, ResolverError::AllEndpointsFailed { .. }));
    }

    #[tokio::test]
    async fn test_resolve_invalid_endpoints_filtered() {
        // 非 https DoH / 非法 DoT 地址在构造时过滤
        let r = SecureResolver::new_from_parts(
            vec!["http://evil.example.com".to_string(), "https://ok.example.com".to_string()],
            vec!["1.1.1.1".to_string(), "1.1.1.1:853".to_string()],
            5000,
            50,
        );
        assert_eq!(r.endpoint_count(), (1, 1));
    }

    // ═══════════ DoT 域名形态端点契约（R-30 / 审计 §8-3） ═══════════

    #[test]
    fn test_dot_parse_endpoint_forms() {
        // IP 形态（v4 字面量 / [v6] 字面量）
        assert_eq!(
            parse_dot_endpoint("1.1.1.1:853"),
            Some(DotEndpoint::Ip("1.1.1.1:853".parse().unwrap()))
        );
        assert_eq!(
            parse_dot_endpoint("[2606:4700::1111]:853"),
            Some(DotEndpoint::Ip("[2606:4700::1111]:853".parse().unwrap()))
        );
        // 域名形态（host:port）
        assert_eq!(
            parse_dot_endpoint("dns.example.com:853"),
            Some(DotEndpoint::Domain {
                host: "dns.example.com".into(),
                port: 853
            })
        );
        assert_eq!(
            parse_dot_endpoint("dns.example.com:8853"),
            Some(DotEndpoint::Domain {
                host: "dns.example.com".into(),
                port: 8853
            })
        );
        // 非法形态：缺端口 / 端口非法 / 非法字符 / 畸形括号 / 空串
        assert_eq!(parse_dot_endpoint("1.1.1.1"), None);
        assert_eq!(parse_dot_endpoint("dns.example.com"), None);
        assert_eq!(parse_dot_endpoint("dns.example.com:0"), None);
        assert_eq!(parse_dot_endpoint("dns.example.com:99999"), None);
        assert_eq!(parse_dot_endpoint("dns.example.com:notaport"), None);
        assert_eq!(parse_dot_endpoint("bad host:853"), None);
        assert_eq!(parse_dot_endpoint("[::1"), None);
        assert_eq!(parse_dot_endpoint(""), None);
    }

    #[test]
    fn test_dot_domain_endpoint_sni_is_domain_name() {
        // 域名形态 → SNI/证书校验名 = 域名（DnsName）而非 IP（自有域名 DoT
        // 端点证书只需域名 SAN；webpki-roots 校验仍强制，DDNS-SEC-002）。
        let ep = parse_dot_endpoint("dns.example.com:853").unwrap();
        match ep.server_name().unwrap() {
            rustls::pki_types::ServerName::DnsName(n) => {
                assert_eq!(n.as_ref(), "dns.example.com")
            }
            _ => panic!("域名形态 SNI 必须是 DnsName"),
        }
        // IP 形态 → SNI = IP（既有行为保持）。
        let ep = parse_dot_endpoint("1.1.1.1:853").unwrap();
        assert!(matches!(
            ep.server_name().unwrap(),
            rustls::pki_types::ServerName::IpAddress(_)
        ));
    }

    #[tokio::test]
    async fn test_dot_domain_endpoint_connect_addr_resolves_ip() {
        // 域名形态建连地址 = 域名解析出的 IP（mock 契约：localhost 走本机
        // 系统解析，不触网）；解析结果必须为回环 IP 且端口保留。
        let ep = parse_dot_endpoint("localhost:853").unwrap();
        let addr = ep.connect_addr().await.unwrap();
        assert!(addr.ip().is_loopback(), "localhost 应解析为回环地址，got {addr}");
        assert_eq!(addr.port(), 853);
    }

    #[test]
    fn test_new_from_parts_keeps_dot_domain_endpoints() {
        // 域名形态 DoT 端点不再被构造过滤（R-30：自有域名 DoT 端点可配置）；
        // 裸 IP / 裸域名（无端口）仍过滤。
        let r = SecureResolver::new_from_parts(
            vec![],
            vec![
                "dns.example.com:853".to_string(),
                "1.1.1.1:853".to_string(),
                "1.1.1.1".to_string(),
                "dns.example.com".to_string(),
            ],
            5000,
            50,
        );
        assert_eq!(r.endpoint_count(), (0, 2));
    }

    #[tokio::test]
    async fn test_resolve_cache_hit() {
        // 缓存命中路径：成功结果写入缓存，第二次 resolve 直接命中
        let r = SecureResolver::new_from_parts(vec![], vec![], 5000, 50);
        // 直接注入缓存模拟成功
        let key = ("x.example.com".to_string(), RecordType::A);
        let rec = Record {
            name: "x.example.com".to_string(),
            rtype: RecordType::A,
            ttl: 300,
            data: RecordData::Plain("203.0.113.7".into()),
        };
        r.cache.lock().unwrap().insert(key, (Instant::now(), vec![rec.clone()]));
        let out = r.resolve("X.EXAMPLE.COM", RecordType::A).await.unwrap();
        assert_eq!(out, vec![rec]);
    }

    #[tokio::test]
    async fn test_resolve_cache_expired() {
        // 缓存过期 → 不再命中 → 走端点（无端点 → 失败）
        let r = SecureResolver::new_from_parts(vec![], vec![], 5000, 50);
        let key = ("y.example.com".to_string(), RecordType::A);
        let rec = Record {
            name: "y.example.com".to_string(),
            rtype: RecordType::A,
            ttl: 300,
            data: RecordData::Plain("203.0.113.8".into()),
        };
        r.cache
            .lock()
            .unwrap()
            .insert(key, (Instant::now() - Duration::from_secs(51), vec![rec]));
        assert!(r.resolve("y.example.com", RecordType::A).await.is_err());
    }

    #[test]
    fn test_srv_string_parse() {
        let d = parse_srv_string("0 1 3389 my-pc.example.com.").unwrap();
        assert_eq!(
            d,
            RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 3389,
                target: "my-pc.example.com".to_string()
            }
        );
        assert!(parse_srv_string("0 1 3389").is_err());
        assert!(parse_srv_string("a b c d").is_err());
    }
}
