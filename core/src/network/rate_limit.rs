//! M15-T001: 速率限制（SRV-SEC-RL-001/002）— 防暴力猜测。
//!
//! - **连接频率限制**：同一聚合键在滑动窗口（默认 30s）内最多 3 次连接尝试，
//!   超限拒绝（SRV-SEC-RL-001）。
//! - **失败封禁**：握手失败累计 5 次 → 该聚合键临时封禁 15 分钟（SRV-SEC-RL-002）；
//!   握手成功后调用 [`RateLimiter::reset`] 清零失败计数。
//!
//! 参数可配置（便于测试注入小窗口），默认值符合规格。实现基于
//! `HashMap<IpAddr, Bucket>` 滑动窗口，线程外同步（调用方持锁），非异步。
//!
//! F-10 安全语义修复：
//! - **限速键聚合**（[`bucket_key`]）：IPv6 取 `/64` 前缀、IPv4 取 `/24` 前缀，
//!   防止同一子网内更换地址绕过限速；
//! - **封禁到期重置失败计数**：解封时失败计数归零（防解封后单次失败即循环封禁），
//!   并支持连续封禁时长指数递增 15m→30m→1h（`ban_escalation`，默认开启，
//!   与 Login 限速解耦独立配置）；
//! - **桶表硬上限**（`max_buckets`，默认 4096）：超出后先惰性清理空闲桶，
//!   仍超限则按 LRU 淘汰最旧桶（防大量地址撑爆内存）。

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// 默认：30s 内最多 3 次连接尝试（SRV-SEC-RL-001）。
pub const DEFAULT_MAX_ATTEMPTS: usize = 3;
/// 默认：滑动窗口 30s。
pub const DEFAULT_ATTEMPT_WINDOW: Duration = Duration::from_secs(30);
/// 默认：握手失败 5 次触发封禁（SRV-SEC-RL-002）。
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 5;
/// 默认：封禁时长 15 分钟（SRV-SEC-RL-002）。
pub const DEFAULT_BAN_DURATION: Duration = Duration::from_secs(15 * 60);
/// 默认：桶表硬上限（F-10c）。
pub const DEFAULT_MAX_BUCKETS: usize = 4096;

/// 速率限制参数。
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// 滑动窗口内允许的最大连接尝试次数。
    pub max_attempts: usize,
    /// 滑动窗口时长。
    pub attempt_window: Duration,
    /// 握手失败累计达到该值 → 封禁。
    pub failure_threshold: u32,
    /// 封禁时长（首级；`ban_escalation` 开启时按 1x→2x→4x 递增，封顶 4x）。
    pub ban_duration: Duration,
    /// 桶表硬上限（超出后 LRU 淘汰最旧桶，F-10c）。
    pub max_buckets: usize,
    /// 连续失败封禁时长指数递增（15m→30m→1h，F-10b 可选增强；默认开启）。
    pub ban_escalation: bool,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            attempt_window: DEFAULT_ATTEMPT_WINDOW,
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            ban_duration: DEFAULT_BAN_DURATION,
            max_buckets: DEFAULT_MAX_BUCKETS,
            ban_escalation: true,
        }
    }
}

/// 连接尝试判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// 放行（并已计入本次尝试）。
    Allowed,
    /// 窗口内尝试次数超限（SRV-SEC-RL-001）。
    TooManyAttempts,
    /// 该 IP 处于封禁中（SRV-SEC-RL-002）。
    Banned,
}

/// 限速键聚合（F-10a）：IPv6 取 `/64` 前缀、IPv4 取 `/24` 前缀，
/// 防止同一子网内更换地址（如 IPv6 后 64 位）绕过限速。
/// relay 侧实现与之行为对齐（TNL-NF-004 约束 relay 不依赖 core，各自复刻）。
pub fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 0))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

/// 连续封禁时长指数递增：1x → 2x → 4x（即 15m → 30m → 1h），封顶 4x。
fn escalate_ban_duration(base: Duration, ban_count: u32) -> Duration {
    let factor = 1u32 << ban_count.min(2);
    base.saturating_mul(factor)
}

/// 单聚合键的状态桶。
#[derive(Debug)]
struct Bucket {
    /// 滑动窗口内的尝试时间戳。
    attempts: VecDeque<Instant>,
    /// 握手失败累计计数（成功握手后由 `reset` 清零；封禁到期时归零）。
    handshake_failures: u32,
    /// 封禁到期时间（`None` = 未封禁）。
    banned_until: Option<Instant>,
    /// 最近一次访问时间（LRU 淘汰依据）。
    last_seen: Instant,
    /// 连续封禁次数（指数递增封禁时长用；成功握手后归零）。
    ban_count: u32,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Self {
            attempts: VecDeque::new(),
            handshake_failures: 0,
            banned_until: None,
            last_seen: now,
            ban_count: 0,
        }
    }
}

/// 速率限制器（per-聚合键 滑动窗口 + 失败封禁）。
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimiterConfig,
    buckets: HashMap<IpAddr, Bucket>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// 使用默认参数（30s/3 次、5 次失败/15 分钟封禁、4096 桶上限）。
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }

    /// 自定义参数（测试用小窗口）。
    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            config,
            buckets: HashMap::new(),
        }
    }

    /// 连接尝试检查（SRV-SEC-RL-001/002）：
    /// 封禁中 → `Banned`；窗口内尝试已满 → `TooManyAttempts`；否则计入并放行。
    pub fn check_connect(&mut self, ip: &IpAddr) -> RateLimitDecision {
        let now = Instant::now();
        let config = &self.config;
        let key = bucket_key(*ip);
        let bucket = self.buckets.entry(key).or_insert_with(|| Bucket::new(now));
        bucket.last_seen = now;

        // 清理窗口外的时间戳
        while let Some(&t) = bucket.attempts.front() {
            if now.duration_since(t) > config.attempt_window {
                bucket.attempts.pop_front();
            } else {
                break;
            }
        }

        // 封禁中？
        if let Some(until) = bucket.banned_until {
            if now < until {
                return RateLimitDecision::Banned;
            }
            // F-10b：封禁到期自动解封，并重置失败计数（防解封后单次失败即循环封禁）
            bucket.banned_until = None;
            bucket.handshake_failures = 0;
        }

        if bucket.attempts.len() >= config.max_attempts {
            return RateLimitDecision::TooManyAttempts;
        }

        bucket.attempts.push_back(now);
        self.maybe_prune(now);
        RateLimitDecision::Allowed
    }

    /// 记录一次握手失败；累计达到阈值 → 封禁该 IP（SRV-SEC-RL-002）。
    /// `ban_escalation` 开启时，封禁时长按连续封禁次数指数递增（15m→30m→1h）。
    pub fn record_handshake_failure(&mut self, ip: &IpAddr) {
        let now = Instant::now();
        let config = &self.config;
        let key = bucket_key(*ip);
        let bucket = self.buckets.entry(key).or_insert_with(|| Bucket::new(now));
        bucket.last_seen = now;

        // 封禁已到期 → 与 check_connect 一致：先解封并重置失败计数
        if let Some(until) = bucket.banned_until {
            if now >= until {
                bucket.banned_until = None;
                bucket.handshake_failures = 0;
            }
        }

        bucket.handshake_failures += 1;
        if bucket.handshake_failures >= config.failure_threshold {
            let duration = if config.ban_escalation {
                escalate_ban_duration(config.ban_duration, bucket.ban_count)
            } else {
                config.ban_duration
            };
            bucket.banned_until = Some(now + duration);
            bucket.ban_count = bucket.ban_count.saturating_add(1).min(3);
        }
    }

    /// 该 IP 是否处于封禁中。
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        match self.buckets.get(&bucket_key(*ip)).and_then(|b| b.banned_until) {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    /// 握手成功后清理该 IP 的失败计数、尝试记录与连续封禁计数（封禁状态不受影响）。
    pub fn reset(&mut self, ip: &IpAddr) {
        if let Some(bucket) = self.buckets.get_mut(&bucket_key(*ip)) {
            bucket.attempts.clear();
            bucket.handshake_failures = 0;
            bucket.ban_count = 0;
        }
    }

    /// 桶表硬上限维护（F-10c）：表大小未超上限时不做任何事；
    /// 超限时先惰性清理无活跃状态的桶，仍超限则按 LRU 淘汰最旧桶（不 panic）。
    fn maybe_prune(&mut self, now: Instant) {
        let cap = self.config.max_buckets;
        if self.buckets.len() <= cap {
            return;
        }
        let window = self.config.attempt_window;
        let ban = self.config.ban_duration;
        let idle_limit = window + ban;
        self.buckets.retain(|_, b| {
            let last = b.attempts.back().copied();
            let idle = match last {
                Some(t) => now.duration_since(t) <= idle_limit,
                None => false,
            };
            idle || b.handshake_failures > 0 || b.banned_until.is_some()
        });
        // 惰性清理后仍超上限 → LRU 淘汰最旧桶，直到回到上限以内
        while self.buckets.len() > cap {
            let oldest = self
                .buckets
                .iter()
                .min_by_key(|(_, b)| b.last_seen)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    self.buckets.remove(&k);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    /// 与 `v4` 不同的 /24（10.0.1.0/24）。
    fn v4_other(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, n))
    }

    /// 同一 /64（2001:db8::/64）内后 64 位不同的地址。
    fn v6(lo: u16, hi: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, lo, hi, 0, 0))
    }

    fn tiny_config() -> RateLimiterConfig {
        RateLimiterConfig {
            max_attempts: 3,
            attempt_window: Duration::from_millis(50),
            failure_threshold: 5,
            ban_duration: Duration::from_millis(100),
            max_buckets: DEFAULT_MAX_BUCKETS,
            ban_escalation: true,
        }
    }

    #[test]
    fn test_max_attempts_in_window() {
        let mut rl = RateLimiter::with_config(tiny_config());
        let ip = v4(1);
        for _ in 0..3 {
            assert_eq!(rl.check_connect(&ip), RateLimitDecision::Allowed);
        }
        assert_eq!(rl.check_connect(&ip), RateLimitDecision::TooManyAttempts);
        // 其他 /24 不受影响
        assert_eq!(rl.check_connect(&v4_other(2)), RateLimitDecision::Allowed);
    }

    #[test]
    fn test_window_expiry_allows_again() {
        let mut rl = RateLimiter::with_config(tiny_config());
        let ip = v4(1);
        for _ in 0..3 {
            assert_eq!(rl.check_connect(&ip), RateLimitDecision::Allowed);
        }
        assert_eq!(rl.check_connect(&ip), RateLimitDecision::TooManyAttempts);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(rl.check_connect(&ip), RateLimitDecision::Allowed);
    }

    #[test]
    fn test_failure_ban_and_expiry() {
        let mut rl = RateLimiter::with_config(tiny_config());
        let ip = v4(1);
        for _ in 0..5 {
            rl.record_handshake_failure(&ip);
        }
        assert!(rl.is_banned(&ip));
        assert_eq!(rl.check_connect(&ip), RateLimitDecision::Banned);
        // 封禁到期自动解封
        std::thread::sleep(Duration::from_millis(110));
        assert!(!rl.is_banned(&ip));
        assert_eq!(rl.check_connect(&ip), RateLimitDecision::Allowed);
    }

    #[test]
    fn test_reset_clears_failures() {
        let mut rl = RateLimiter::with_config(tiny_config());
        let ip = v4(1);
        for _ in 0..4 {
            rl.record_handshake_failure(&ip);
        }
        rl.reset(&ip);
        for _ in 0..5 {
            rl.record_handshake_failure(&ip);
        }
        // reset 已清零 → 5 次后才封禁（说明失败计数被重置过）
        assert!(rl.is_banned(&ip));
    }

    #[test]
    fn test_ban_takes_precedence_over_attempt_limit() {
        let mut rl = RateLimiter::with_config(tiny_config());
        let ip = v4(1);
        for _ in 0..5 {
            rl.record_handshake_failure(&ip);
        }
        assert_eq!(rl.check_connect(&ip), RateLimitDecision::Banned);
    }

    // ---- F-10a：限速键聚合（IPv6 /64、IPv4 /24） ----

    #[test]
    fn test_bucket_key_aggregation() {
        // IPv4 取 /24
        assert_eq!(bucket_key(v4(1)), bucket_key(v4(2)));
        assert_eq!(bucket_key(v4(255)), bucket_key(v4(0)));
        assert_ne!(bucket_key(v4(1)), bucket_key(v4_other(1)));
        // IPv6 取 /64
        assert_eq!(bucket_key(v6(1, 2)), bucket_key(v6(3, 4)));
        assert_eq!(bucket_key(v6(0xffff, 0xffff)), bucket_key(v6(0, 0)));
        assert_ne!(
            bucket_key(v6(1, 0)),
            bucket_key(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0)))
        );
        // 聚合结果本身是合法前缀（IPv4 尾字节 0、IPv6 后四段 0）
        assert_eq!(bucket_key(v4(5)), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(
            bucket_key(v6(9, 9)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
        );
    }

    #[test]
    fn test_ipv6_s64_share_quota() {
        let mut rl = RateLimiter::with_config(tiny_config());
        let a = v6(1, 1);
        let b = v6(2, 2); // 同 /64，后 64 位不同
        for _ in 0..3 {
            assert_eq!(rl.check_connect(&a), RateLimitDecision::Allowed);
        }
        // 同 /64 内换地址不能绕过限速
        assert_eq!(rl.check_connect(&b), RateLimitDecision::TooManyAttempts);
        // 不同 /64 不受影响
        let c = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0));
        assert_eq!(rl.check_connect(&c), RateLimitDecision::Allowed);
    }

    #[test]
    fn test_ipv4_s24_share_quota() {
        let mut rl = RateLimiter::with_config(tiny_config());
        for _ in 0..3 {
            assert_eq!(rl.check_connect(&v4(1)), RateLimitDecision::Allowed);
        }
        // 同 /24 内换最后一段不能绕过限速
        assert_eq!(rl.check_connect(&v4(99)), RateLimitDecision::TooManyAttempts);
        // 不同 /24 不受影响
        assert_eq!(rl.check_connect(&v4_other(1)), RateLimitDecision::Allowed);
    }

    // ---- F-10b：封禁到期重置失败计数 + 指数递增 ----

    #[test]
    fn test_unban_resets_failures() {
        let cfg = RateLimiterConfig {
            max_attempts: 3,
            attempt_window: Duration::from_millis(50),
            failure_threshold: 2,
            ban_duration: Duration::from_millis(100),
            max_buckets: DEFAULT_MAX_BUCKETS,
            ban_escalation: true,
        };
        let mut rl = RateLimiter::with_config(cfg);
        let ip = v4(1);
        // 2 次失败 → 封禁
        rl.record_handshake_failure(&ip);
        rl.record_handshake_failure(&ip);
        assert!(rl.is_banned(&ip));
        assert_eq!(rl.check_connect(&ip), RateLimitDecision::Banned);
        // 封禁到期 → 自动解封并重置失败计数
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(rl.check_connect(&ip), RateLimitDecision::Allowed);
        // 解封后单次失败不再触发封禁（旧实现会因残留计数立即再封禁）
        rl.record_handshake_failure(&ip);
        assert!(!rl.is_banned(&ip));
        // 再失败一次才达到阈值 → 封禁
        rl.record_handshake_failure(&ip);
        assert!(rl.is_banned(&ip));
    }

    #[test]
    fn test_ban_escalation_15m_30m_1h() {
        // 阶梯函数直接验证（不依赖真实时间）
        let base = Duration::from_secs(15 * 60);
        assert_eq!(escalate_ban_duration(base, 0), Duration::from_secs(15 * 60));
        assert_eq!(escalate_ban_duration(base, 1), Duration::from_secs(30 * 60));
        assert_eq!(escalate_ban_duration(base, 2), Duration::from_secs(60 * 60));
        assert_eq!(escalate_ban_duration(base, 3), Duration::from_secs(60 * 60)); // 封顶 4x
        assert_eq!(escalate_ban_duration(base, 99), Duration::from_secs(60 * 60));

        // 集成：连续两轮封禁，第二轮时长翻倍（100ms → 200ms）
        let cfg = RateLimiterConfig {
            max_attempts: 3,
            attempt_window: Duration::from_millis(50),
            failure_threshold: 2,
            ban_duration: Duration::from_millis(100),
            max_buckets: DEFAULT_MAX_BUCKETS,
            ban_escalation: true,
        };
        let mut rl = RateLimiter::with_config(cfg);
        let ip = v4(1);
        for _ in 0..2 {
            rl.record_handshake_failure(&ip);
        }
        assert!(rl.is_banned(&ip));
        // 第一轮封禁 100ms → 到期解封（check_connect 触发并重置计数）
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(rl.check_connect(&ip), RateLimitDecision::Allowed);
        // 第二轮 2 次失败 → 封禁 200ms
        for _ in 0..2 {
            rl.record_handshake_failure(&ip);
        }
        assert!(rl.is_banned(&ip));
        // 150ms 后若仍为 100ms 封禁则已到期；递增为 200ms 则仍在封禁中
        std::thread::sleep(Duration::from_millis(150));
        assert!(rl.is_banned(&ip), "第二轮封禁应递增为 200ms，150ms 后仍在封禁中");
        // 累计 250ms > 200ms → 到期
        std::thread::sleep(Duration::from_millis(100));
        assert!(!rl.is_banned(&ip));
    }

    #[test]
    fn test_ban_escalation_disabled() {
        let cfg = RateLimiterConfig {
            max_attempts: 3,
            attempt_window: Duration::from_millis(50),
            failure_threshold: 2,
            ban_duration: Duration::from_millis(100),
            max_buckets: DEFAULT_MAX_BUCKETS,
            ban_escalation: false,
        };
        let mut rl = RateLimiter::with_config(cfg);
        let ip = v4(1);
        for _ in 0..2 {
            rl.record_handshake_failure(&ip);
        }
        assert!(rl.is_banned(&ip));
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(rl.check_connect(&ip), RateLimitDecision::Allowed);
        // 第二轮仍为 100ms（不递增）
        for _ in 0..2 {
            rl.record_handshake_failure(&ip);
        }
        std::thread::sleep(Duration::from_millis(150));
        assert!(!rl.is_banned(&ip));
    }

    // ---- F-10c：桶表硬上限 + LRU 淘汰 ----

    #[test]
    fn test_bucket_cap_lru_eviction() {
        let cfg = RateLimiterConfig {
            max_attempts: 1,
            attempt_window: Duration::from_millis(50),
            failure_threshold: 5,
            ban_duration: Duration::from_millis(100),
            max_buckets: 3, // 注入小上限
            ban_escalation: true,
        };
        let mut rl = RateLimiter::with_config(cfg);
        // 填满 3 个桶（不同 /24），且每桶保留非空状态
        let a = v4(1);
        let b = v4_other(1);
        let c = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
        for ip in [a, b, c] {
            assert_eq!(rl.check_connect(&ip), RateLimitDecision::Allowed);
            // max_attempts=1：第二次即超限（确认桶内状态非空）
            assert_eq!(rl.check_connect(&ip), RateLimitDecision::TooManyAttempts);
        }
        assert_eq!(rl.buckets.len(), 3);
        // 第 4 个桶 → 超上限 → LRU 淘汰最旧桶 a；不 panic
        let d = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1));
        assert_eq!(rl.check_connect(&d), RateLimitDecision::Allowed);
        assert_eq!(rl.buckets.len(), 3);
        // 未被淘汰的 b 仍保留状态（先断言，避免重插 a 触发二次淘汰干扰）
        assert_eq!(rl.check_connect(&b), RateLimitDecision::TooManyAttempts);
        // 最旧桶 a 已被淘汰 → 重新计数（Allowed）
        assert_eq!(rl.check_connect(&a), RateLimitDecision::Allowed);
        // 重插 a 后再次超限 → 淘汰当时最旧的 c，表大小仍受控
        assert_eq!(rl.buckets.len(), 3);
        assert_eq!(rl.check_connect(&c), RateLimitDecision::Allowed);
    }

    #[test]
    fn test_bucket_cap_no_panic_many_ips() {
        let cfg = RateLimiterConfig {
            max_attempts: 3,
            attempt_window: Duration::from_millis(50),
            failure_threshold: 5,
            ban_duration: Duration::from_millis(100),
            max_buckets: 8,
            ban_escalation: true,
        };
        let mut rl = RateLimiter::with_config(cfg);
        // 大量不同 /24 的 IP 轮询 → 表大小始终受控、不 panic
        for n in 0..100u16 {
            let ip = IpAddr::V4(Ipv4Addr::new((n >> 8) as u8, (n & 0xff) as u8, 0, 1));
            rl.check_connect(&ip);
            assert!(rl.buckets.len() <= 8, "表大小超过硬上限");
        }
        assert!(rl.buckets.len() <= 8);
    }
}
