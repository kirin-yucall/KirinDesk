//! M8-T026 T002: 速率限制 — 服务端防护（TNL-SEC-002）。
//!
//! 语义与 `core/src/network/rate_limit.rs`（M15-T001，SRV-SEC-RL-001/002）
//! 完全对齐：控制端口 30s 滑窗最多 3 次连接尝试；5 次认证失败封禁 15 分钟。
//! 本模块为 relay 自持的轻量实现 —— TNL-NF-004 约束 relay 不依赖 core，
//! 因此不直接复用 core 类型，仅复刻其语义（参数可配置，便于测试注入小窗口）。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 默认：30s 内最多 3 次连接尝试（SRV-SEC-RL-001）。
pub const DEFAULT_MAX_ATTEMPTS: usize = 3;
/// 默认：滑动窗口 30s。
pub const DEFAULT_ATTEMPT_WINDOW: Duration = Duration::from_secs(30);
/// 默认：认证失败 5 次触发封禁（SRV-SEC-RL-002）。
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 5;
/// 默认：封禁时长 15 分钟（SRV-SEC-RL-002）。
pub const DEFAULT_BAN_DURATION: Duration = Duration::from_secs(15 * 60);

/// 速率限制参数（对齐 M15-T001 `RateLimiterConfig`）。
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// 滑动窗口内允许的最大连接尝试次数。
    pub max_attempts: usize,
    /// 滑动窗口时长。
    pub attempt_window: Duration,
    /// 认证失败累计达到该值 → 封禁。
    pub failure_threshold: u32,
    /// 封禁时长。
    pub ban_duration: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            attempt_window: DEFAULT_ATTEMPT_WINDOW,
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            ban_duration: DEFAULT_BAN_DURATION,
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

/// 单 IP 的状态桶。
#[derive(Debug)]
struct Bucket {
    attempts: VecDeque<Instant>,
    handshake_failures: u32,
    banned_until: Option<Instant>,
}

/// 速率限制器（per-IP 滑动窗口 + 失败封禁；线程外同步，调用方持锁）。
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
    /// 使用默认参数（30s/3 次、5 次失败/15 分钟封禁）。
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

    /// 连接尝试检查（TNL-SEC-002）：封禁中 → `Banned`；窗口内已满 →
    /// `TooManyAttempts`；否则计入并放行。
    pub fn check_connect(&mut self, ip: &IpAddr) -> RateLimitDecision {
        let now = Instant::now();
        let config = &self.config;
        let bucket = self.buckets.entry(*ip).or_insert_with(|| Bucket {
            attempts: VecDeque::new(),
            handshake_failures: 0,
            banned_until: None,
        });

        while let Some(&t) = bucket.attempts.front() {
            if now.duration_since(t) > config.attempt_window {
                bucket.attempts.pop_front();
            } else {
                break;
            }
        }

        if let Some(until) = bucket.banned_until {
            if now < until {
                return RateLimitDecision::Banned;
            }
            bucket.banned_until = None;
        }

        if bucket.attempts.len() >= config.max_attempts {
            return RateLimitDecision::TooManyAttempts;
        }

        bucket.attempts.push_back(now);
        self.maybe_prune(now);
        RateLimitDecision::Allowed
    }

    /// 记录一次认证失败；累计达到阈值 → 封禁该 IP（TNL-SEC-002）。
    pub fn record_handshake_failure(&mut self, ip: &IpAddr) {
        let config = &self.config;
        let bucket = self.buckets.entry(*ip).or_insert_with(|| Bucket {
            attempts: VecDeque::new(),
            handshake_failures: 0,
            banned_until: None,
        });
        bucket.handshake_failures += 1;
        if bucket.handshake_failures >= config.failure_threshold {
            bucket.banned_until = Some(Instant::now() + config.ban_duration);
        }
    }

    /// 该 IP 是否处于封禁中。
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        match self.buckets.get(ip).and_then(|b| b.banned_until) {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    /// 认证成功后清零该 IP 的失败计数与尝试记录（封禁状态不受影响）。
    pub fn reset(&mut self, ip: &IpAddr) {
        if let Some(bucket) = self.buckets.get_mut(ip) {
            bucket.attempts.clear();
            bucket.handshake_failures = 0;
        }
    }

    /// 惰性清理：无活跃状态的桶在表过大时移除（防恶意多 IP 撑爆内存）。
    fn maybe_prune(&mut self, now: Instant) {
        if self.buckets.len() < 1024 {
            return;
        }
        let idle_limit = self.config.attempt_window + self.config.ban_duration;
        self.buckets.retain(|_, b| {
            let last = b.attempts.back().copied();
            let idle = match last {
                Some(t) => now.duration_since(t) <= idle_limit,
                None => false,
            };
            idle || b.handshake_failures > 0 || b.banned_until.is_some()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn tiny_config() -> RateLimiterConfig {
        RateLimiterConfig {
            max_attempts: 3,
            attempt_window: Duration::from_millis(50),
            failure_threshold: 5,
            ban_duration: Duration::from_millis(100),
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
        // 其他 IP 不受影响
        assert_eq!(rl.check_connect(&v4(2)), RateLimitDecision::Allowed);
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
}
