//! M8-T040 (W1-B / WBS 3.1): 公网出口 IP 获取器。
//!
//! DDNS-IPV4-002/003：IPv4 自动模式 = **公网出口 IP**（非本机网卡地址），
//! 从外部公网 IP 服务获取；多源按配置优先序逐个尝试（默认
//! `ipify → ip.sb → icanhazip`），全部走 **HTTPS + 超时**；结果必须通过
//! `Ipv4Addr` 严格校验（拒绝 HTML/错误页劫持）。获取失败保留上次成功值 +
//! 告警由调用方（`DdnsService`）处理（本层只负责按序回退 + 缓存）。
//!
//! 解耦约定（并行计划 §5）：源列表**构造参数注入**，不依赖配置层。
//! `PubIpSource` trait 供 mock 注入（单测三路：返回垃圾/超时/成功）。

use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

/// 公网 IP 源失败错误。
#[derive(Debug, thiserror::Error)]
pub enum PubIpError {
    /// 全部源按序尝试均失败（fail-closed：不返回任何地址）。
    #[error("所有公网 IP 源均失败: {0}")]
    AllSourcesFailed(String),
    /// 源返回了无法解析为严格 Ipv4Addr 的响应（HTML/劫持页/垃圾）。
    #[error("公网 IP 源返回非法响应: {0}")]
    InvalidResponse(String),
    /// 单源请求超时。
    #[error("公网 IP 源请求超时")]
    Timeout,
    /// 网络/HTTP 层错误。
    #[error("网络错误: {0}")]
    Network(#[from] reqwest::Error),
}

/// 公网 IP 源抽象（mock 注入面，并行计划 §5 冻结签名）。
#[async_trait::async_trait]
pub trait PubIpSource: Send + Sync {
    /// 获取公网出口 IPv4（严格 `Ipv4Addr` 校验，拒绝 HTML/劫持页）。
    async fn fetch(&self) -> Result<Ipv4Addr, PubIpError>;
}

/// HTTPS 文本源实现：GET 目标 URL，响应体严格解析为 `Ipv4Addr`。
///
/// 强制 HTTPS + 证书校验（DDNS-SEC-003）；`http://127.0.0.1` 环回地址自动
/// 放行（测试 mock 端点用，沿用 providers 的 KIRIN_DNS_ALLOW_HTTP 纪律）。
pub struct HttpPubIpSource {
    url: String,
    client: reqwest::Client,
}

impl HttpPubIpSource {
    /// 构建 HTTPS 文本源（URL 必须 https://，环回 http 放行）。
    pub fn new(url: &str, timeout: Duration) -> Result<Self, PubIpError> {
        if !(url.starts_with("https://") || url.starts_with("http://127.0.0.1")) {
            return Err(PubIpError::InvalidResponse(format!(
                "公网 IP 源必须为 HTTPS（当前: '{url}'）"
            )));
        }
        let client = reqwest::Client::builder().timeout(timeout).build()?;
        Ok(Self {
            url: url.to_string(),
            client,
        })
    }
}

#[async_trait::async_trait]
impl PubIpSource for HttpPubIpSource {
    async fn fetch(&self) -> Result<Ipv4Addr, PubIpError> {
        let body = self.client.get(&self.url).send().await?.text().await?;
        parse_response(&body)
    }
}

/// 内置源键 → URL 映射（默认优先序 `ipify → ip.sb → icanhazip`，DDNS-IPV4-003）。
/// 非内置键视为自定义 URL（仍强制 HTTPS）。返回 `None` = 未知键且非 URL。
pub fn source_url(key: &str) -> Option<String> {
    match key.trim() {
        "ipify" => Some("https://api.ipify.org".to_string()),
        "ip.sb" => Some("https://api.ip.sb/ip".to_string()),
        "icanhazip" => Some("https://icanhazip.com".to_string()),
        k if k.starts_with("https://") || k.starts_with("http://127.0.0.1") => {
            Some(k.to_string())
        }
        _ => None,
    }
}

/// 严格 `Ipv4Addr` 解析：trim 后整体解析；HTML/劫持页/垃圾一律拒绝
/// （DDNS-SEC-003；IPv6 地址同样拒绝——本器只服务 A 记录）。特殊地址
/// （未指定/回环/链路本地/组播，如 `0.0.0.0`/`127.0.0.1`/`169.254.x`）同样
/// 拒绝——公网出口 IP 必须是全局单播，防劫持源塞入占位地址。
pub fn parse_response(body: &str) -> Result<Ipv4Addr, PubIpError> {
    let trimmed = body.trim();
    let ip = trimmed
        .parse::<Ipv4Addr>()
        .map_err(|_| PubIpError::InvalidResponse(format!("'{body}' 非严格 IPv4 字面量")))?;
    if ip.is_unspecified() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() {
        return Err(PubIpError::InvalidResponse(format!(
            "'{trimmed}' 非全局单播地址（公网出口 IP 必须为全局单播）"
        )));
    }
    Ok(ip)
}

/// 结果缓存 TTL（秒）：短缓存避免单次失败风暴，长轮询周期（≥60s）下不影响
/// 变更检测。
const CACHE_TTL: Duration = Duration::from_secs(25);

/// 公网出口 IP 获取器（多源按序回退 + 结果缓存）。
///
/// `fetch()` 缓存优先；`fetch_fresh()` 强制重新探测（UI「重新检测」/
/// `ddns update` 用）。连续失败计数由调用方（`DdnsService`）维护。
pub struct PublicIpFetcher {
    sources: Vec<Box<dyn PubIpSource>>,
    cache: Mutex<Option<(Instant, Ipv4Addr)>>,
}

impl PublicIpFetcher {
    /// 按源键/URL 列表构建（构造参数注入，不依赖配置层；未知键跳过并告警）。
    pub fn new(sources: Vec<String>, timeout: Duration) -> Self {
        let mut fetchers: Vec<Box<dyn PubIpSource>> = Vec::new();
        for key in &sources {
            match source_url(key) {
                Some(url) => match HttpPubIpSource::new(&url, timeout) {
                    Ok(src) => fetchers.push(Box::new(src)),
                    Err(e) => warn!("PublicIpFetcher: 源 '{key}' 构建失败: {e}"),
                },
                None => warn!("PublicIpFetcher: 未知源键 '{key}'（已跳过）"),
            }
        }
        if fetchers.is_empty() {
            warn!("PublicIpFetcher: 源列表为空或全部非法——按序回退将立即失败");
        }
        Self {
            sources: fetchers,
            cache: Mutex::new(None),
        }
    }

    /// 直接注入源列表（mock 注入面：单测 / DdnsService 装配用）。
    pub fn from_sources(sources: Vec<Box<dyn PubIpSource>>) -> Self {
        Self {
            sources,
            cache: Mutex::new(None),
        }
    }

    /// 缓存命中且未过期 → 直接返回；否则走多源按序回退。
    pub async fn fetch(&self) -> Result<Ipv4Addr, PubIpError> {
        if let Some((at, ip)) = *self.cache.lock().unwrap() {
            if at.elapsed() < CACHE_TTL {
                debug!("PublicIpFetcher: cache hit {ip}");
                return Ok(ip);
            }
        }
        self.fetch_fresh().await
    }

    /// 强制重新探测：按配置优先序逐个尝试，任一成功即用并更新缓存；
    /// 全部失败 → `AllSourcesFailed`（fail-closed，不返回任何地址）。
    pub async fn fetch_fresh(&self) -> Result<Ipv4Addr, PubIpError> {
        if self.sources.is_empty() {
            return Err(PubIpError::AllSourcesFailed(
                "未配置任何可用公网 IP 源".to_string(),
            ));
        }
        let mut errors: Vec<String> = Vec::new();
        for (i, src) in self.sources.iter().enumerate() {
            match src.fetch().await {
                Ok(ip) => {
                    info!("PublicIpFetcher: 源 #{i} 成功 -> {ip}");
                    *self.cache.lock().unwrap() = Some((Instant::now(), ip));
                    return Ok(ip);
                }
                Err(e) => {
                    warn!("PublicIpFetcher: 源 #{i} 失败: {e}");
                    errors.push(format!("#{i}: {e}"));
                }
            }
        }
        Err(PubIpError::AllSourcesFailed(errors.join(" | ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 严格校验（拒绝 HTML/劫持页/垃圾/错误格式，DDNS-IPV4-003） ----

    #[test]
    fn test_parse_response_ok() {
        assert_eq!(
            parse_response("203.0.113.7").unwrap(),
            "203.0.113.7".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            parse_response("  203.0.113.7\n").unwrap(),
            "203.0.113.7".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn test_parse_response_rejects_garbage() {
        // HTML 劫持页 / 纯文本 / 超范围 / IPv6 / 空 —— 全部拒绝
        assert!(parse_response("<html><body>203.0.113.7</body></html>").is_err());
        assert!(parse_response("203.0.113.7 is your IP").is_err());
        assert!(parse_response("999.1.1.1").is_err());
        assert!(parse_response("2001:db8::1").is_err());
        assert!(parse_response("").is_err());
        assert!(parse_response("0.0.0.0").is_err(), "0.0.0.0 非公网出口，拒绝");
    }

    #[test]
    fn test_source_url_mapping() {
        assert_eq!(source_url("ipify"), Some("https://api.ipify.org".to_string()));
        assert_eq!(source_url("ip.sb"), Some("https://api.ip.sb/ip".to_string()));
        assert_eq!(
            source_url("icanhazip"),
            Some("https://icanhazip.com".to_string())
        );
        assert_eq!(
            source_url("https://my-ip.example.net/"),
            Some("https://my-ip.example.net/".to_string())
        );
        assert_eq!(source_url("unknown-key"), None);
        assert_eq!(source_url("http://evil.example.com"), None, "非环回 http 拒绝");
    }

    // ---- mock 源（返回垃圾/超时/成功三路，WBS 3.1 验收） ----

    struct MockSource {
        result: Result<Ipv4Addr, PubIpError>,
    }

    #[async_trait::async_trait]
    impl PubIpSource for MockSource {
        async fn fetch(&self) -> Result<Ipv4Addr, PubIpError> {
            match &self.result {
                Ok(ip) => Ok(*ip),
                Err(e) => Err(match e {
                    PubIpError::Timeout => PubIpError::Timeout,
                    PubIpError::InvalidResponse(s) => PubIpError::InvalidResponse(s.clone()),
                    other => PubIpError::InvalidResponse(other.to_string()),
                }),
            }
        }
    }

    fn mock(ok: bool) -> Box<dyn PubIpSource> {
        Box::new(MockSource {
            result: if ok {
                Ok("203.0.113.7".parse::<Ipv4Addr>().unwrap())
            } else {
                Err(PubIpError::InvalidResponse("垃圾响应".into()))
            },
        })
    }

    #[tokio::test]
    async fn test_fetch_first_success() {
        let fetcher = PublicIpFetcher {
            sources: vec![mock(true)],
            cache: Mutex::new(None),
        };
        assert_eq!(fetcher.fetch().await.unwrap(), "203.0.113.7".parse::<Ipv4Addr>().unwrap());
    }

    #[tokio::test]
    async fn test_fetch_fallback_on_failure() {
        // 第一源失败（垃圾响应）→ 回退第二源成功
        let fetcher = PublicIpFetcher {
            sources: vec![mock(false), mock(true)],
            cache: Mutex::new(None),
        };
        assert_eq!(fetcher.fetch().await.unwrap(), "203.0.113.7".parse::<Ipv4Addr>().unwrap());
    }

    #[tokio::test]
    async fn test_fetch_timeout_fallback() {
        // 第一源超时 → 回退成功源
        let fetcher = PublicIpFetcher {
            sources: vec![
                Box::new(MockSource {
                    result: Err(PubIpError::Timeout),
                }),
                mock(true),
            ],
            cache: Mutex::new(None),
        };
        assert_eq!(fetcher.fetch().await.unwrap(), "203.0.113.7".parse::<Ipv4Addr>().unwrap());
    }

    #[tokio::test]
    async fn test_fetch_all_failed_fail_closed() {
        // 全部失败 → AllSourcesFailed（不返回任何地址）
        let fetcher = PublicIpFetcher {
            sources: vec![mock(false), mock(false)],
            cache: Mutex::new(None),
        };
        let err = fetcher.fetch().await.unwrap_err();
        assert!(matches!(err, PubIpError::AllSourcesFailed(_)));
    }

    #[tokio::test]
    async fn test_fetch_empty_sources() {
        let fetcher = PublicIpFetcher {
            sources: vec![],
            cache: Mutex::new(None),
        };
        assert!(matches!(
            fetcher.fetch().await.unwrap_err(),
            PubIpError::AllSourcesFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_fetch_cache_hit() {
        // 缓存命中：第二次 fetch 不再调用源
        let hit = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        struct Counting {
            n: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl PubIpSource for Counting {
            async fn fetch(&self) -> Result<Ipv4Addr, PubIpError> {
                self.n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok("203.0.113.7".parse::<Ipv4Addr>().unwrap())
            }
        }
        let fetcher = PublicIpFetcher {
            sources: vec![Box::new(Counting { n: hit.clone() })],
            cache: Mutex::new(None),
        };
        fetcher.fetch().await.unwrap();
        fetcher.fetch().await.unwrap();
        assert_eq!(hit.load(std::sync::atomic::Ordering::SeqCst), 1, "缓存命中不再探测");
        // fetch_fresh 绕过缓存
        fetcher.fetch_fresh().await.unwrap();
        assert_eq!(hit.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn test_https_enforced_for_remote_urls() {
        // 非环回 http 一律拒绝（DDNS-SEC-003：全部走 HTTPS）
        let err = HttpPubIpSource::new("http://api.example.com/", Duration::from_secs(5));
        assert!(err.is_err());
        let ok = HttpPubIpSource::new("https://api.example.com/", Duration::from_secs(5));
        assert!(ok.is_ok());
        let loopback = HttpPubIpSource::new("http://127.0.0.1:9999/", Duration::from_secs(5));
        assert!(loopback.is_ok(), "测试环回地址放行");
    }
}
