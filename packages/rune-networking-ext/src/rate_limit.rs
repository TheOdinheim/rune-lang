// ═══════════════════════════════════════════════════════════════════════
// Rate Limit — Network-level rate limiting and throttling.
// Enforces connection rate limits per source, globally, and per
// connection bandwidth.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── RateLimitType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitType {
    PerSource,
    PerConnection,
    Global,
}

impl fmt::Display for RateLimitType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerSource => write!(f, "PerSource"),
            Self::PerConnection => write!(f, "PerConnection"),
            Self::Global => write!(f, "Global"),
        }
    }
}

// ── RateCounter ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RateCounter {
    pub count: u64,
    pub window_start: i64,
    pub window_ms: i64,
}

impl RateCounter {
    pub fn new(window_ms: i64) -> Self {
        Self {
            count: 0,
            window_start: 0,
            window_ms,
        }
    }

    pub fn increment(&mut self, now: i64) -> u64 {
        if now - self.window_start >= self.window_ms {
            self.count = 0;
            self.window_start = now;
        }
        self.count += 1;
        self.count
    }

    pub fn current_rate(&self, now: i64) -> u64 {
        if now - self.window_start >= self.window_ms {
            0
        } else {
            self.count
        }
    }
}

// ── NetworkRateLimitConfig ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRateLimitConfig {
    pub connections_per_minute_per_source: Option<u64>,
    pub bytes_per_second_per_connection: Option<u64>,
    pub global_connections_per_minute: Option<u64>,
    pub burst_multiplier: f64,
}

impl NetworkRateLimitConfig {
    pub fn default_config() -> Self {
        Self {
            connections_per_minute_per_source: Some(100),
            bytes_per_second_per_connection: Some(10_485_760), // 10 MB/s
            global_connections_per_minute: Some(1000),
            burst_multiplier: 2.0,
        }
    }

    pub fn strict() -> Self {
        Self {
            connections_per_minute_per_source: Some(10),
            bytes_per_second_per_connection: Some(1_048_576), // 1 MB/s
            global_connections_per_minute: Some(100),
            burst_multiplier: 1.5,
        }
    }

    pub fn permissive() -> Self {
        Self {
            connections_per_minute_per_source: Some(1000),
            bytes_per_second_per_connection: None,
            global_connections_per_minute: Some(10_000),
            burst_multiplier: 3.0,
        }
    }
}

// ── NetworkRateResult ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NetworkRateResult {
    pub allowed: bool,
    pub limit_type: Option<RateLimitType>,
    pub current_rate: u64,
    pub max_rate: u64,
    pub retry_after_ms: Option<u64>,
    pub detail: String,
}

// ── NetworkRateLimiter ──────────────────────────────────────────────

pub struct NetworkRateLimiter {
    config: NetworkRateLimitConfig,
    source_counts: HashMap<String, RateCounter>,
    global_count: RateCounter,
}

impl NetworkRateLimiter {
    pub fn new(config: NetworkRateLimitConfig) -> Self {
        Self {
            config,
            source_counts: HashMap::new(),
            global_count: RateCounter::new(60_000),
        }
    }

    pub fn check_connection(&mut self, source: &str, now: i64) -> NetworkRateResult {
        // Check per-source limit
        if let Some(max) = self.config.connections_per_minute_per_source {
            let counter = self
                .source_counts
                .entry(source.into())
                .or_insert_with(|| RateCounter::new(60_000));
            let rate = counter.increment(now);
            if rate > max {
                let remaining_ms =
                    counter.window_ms - (now - counter.window_start);
                return NetworkRateResult {
                    allowed: false,
                    limit_type: Some(RateLimitType::PerSource),
                    current_rate: rate,
                    max_rate: max,
                    retry_after_ms: Some(remaining_ms.max(0) as u64),
                    detail: format!("Per-source limit exceeded: {rate}/{max}"),
                };
            }
        }

        // Check global limit
        if let Some(max) = self.config.global_connections_per_minute {
            let rate = self.global_count.increment(now);
            if rate > max {
                let remaining_ms =
                    self.global_count.window_ms - (now - self.global_count.window_start);
                return NetworkRateResult {
                    allowed: false,
                    limit_type: Some(RateLimitType::Global),
                    current_rate: rate,
                    max_rate: max,
                    retry_after_ms: Some(remaining_ms.max(0) as u64),
                    detail: format!("Global limit exceeded: {rate}/{max}"),
                };
            }
        }

        NetworkRateResult {
            allowed: true,
            limit_type: None,
            current_rate: 0,
            max_rate: 0,
            retry_after_ms: None,
            detail: "Within rate limits".into(),
        }
    }

    pub fn check_bandwidth(&self, _connection_id: &str, bytes: u64) -> NetworkRateResult {
        if let Some(max_bps) = self.config.bytes_per_second_per_connection {
            if bytes > max_bps {
                return NetworkRateResult {
                    allowed: false,
                    limit_type: Some(RateLimitType::PerConnection),
                    current_rate: bytes,
                    max_rate: max_bps,
                    retry_after_ms: Some(1000),
                    detail: format!("Bandwidth limit exceeded: {bytes}/{max_bps} bytes/s"),
                };
            }
        }
        NetworkRateResult {
            allowed: true,
            limit_type: None,
            current_rate: bytes,
            max_rate: self.config.bytes_per_second_per_connection.unwrap_or(0),
            retry_after_ms: None,
            detail: "Within bandwidth limit".into(),
        }
    }

    pub fn reset_source(&mut self, source: &str) {
        self.source_counts.remove(source);
    }

    pub fn reset_all(&mut self) {
        self.source_counts.clear();
        self.global_count = RateCounter::new(60_000);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_connection_allows_within_limit() {
        let mut limiter = NetworkRateLimiter::new(NetworkRateLimitConfig::default_config());
        let r = limiter.check_connection("10.0.0.1", 1000);
        assert!(r.allowed);
    }

    #[test]
    fn test_check_connection_denies_per_source_exceeded() {
        let config = NetworkRateLimitConfig {
            connections_per_minute_per_source: Some(2),
            bytes_per_second_per_connection: None,
            global_connections_per_minute: None,
            burst_multiplier: 1.0,
        };
        let mut limiter = NetworkRateLimiter::new(config);
        limiter.check_connection("10.0.0.1", 1000);
        limiter.check_connection("10.0.0.1", 1001);
        let r = limiter.check_connection("10.0.0.1", 1002);
        assert!(!r.allowed);
        assert_eq!(r.limit_type, Some(RateLimitType::PerSource));
    }

    #[test]
    fn test_check_connection_denies_global_exceeded() {
        let config = NetworkRateLimitConfig {
            connections_per_minute_per_source: None,
            bytes_per_second_per_connection: None,
            global_connections_per_minute: Some(2),
            burst_multiplier: 1.0,
        };
        let mut limiter = NetworkRateLimiter::new(config);
        limiter.check_connection("10.0.0.1", 1000);
        limiter.check_connection("10.0.0.2", 1001);
        let r = limiter.check_connection("10.0.0.3", 1002);
        assert!(!r.allowed);
        assert_eq!(r.limit_type, Some(RateLimitType::Global));
    }

    #[test]
    fn test_rate_counter_resets_on_new_window() {
        let mut counter = RateCounter::new(60_000);
        counter.increment(1000);
        counter.increment(2000);
        assert_eq!(counter.current_rate(3000), 2);
        // New window
        let rate = counter.increment(70_000);
        assert_eq!(rate, 1);
    }

    #[test]
    fn test_rate_counter_current_rate_returns_count() {
        let mut counter = RateCounter::new(60_000);
        counter.increment(1000);
        counter.increment(2000);
        counter.increment(3000);
        assert_eq!(counter.current_rate(5000), 3);
        assert_eq!(counter.current_rate(70_000), 0); // window expired
    }

    #[test]
    fn test_default_config_values() {
        let c = NetworkRateLimitConfig::default_config();
        assert_eq!(c.connections_per_minute_per_source, Some(100));
        assert_eq!(c.bytes_per_second_per_connection, Some(10_485_760));
        assert_eq!(c.global_connections_per_minute, Some(1000));
    }

    #[test]
    fn test_strict_config_values() {
        let c = NetworkRateLimitConfig::strict();
        assert_eq!(c.connections_per_minute_per_source, Some(10));
        assert_eq!(c.global_connections_per_minute, Some(100));
    }

    #[test]
    fn test_reset_source() {
        let config = NetworkRateLimitConfig {
            connections_per_minute_per_source: Some(2),
            bytes_per_second_per_connection: None,
            global_connections_per_minute: None,
            burst_multiplier: 1.0,
        };
        let mut limiter = NetworkRateLimiter::new(config);
        limiter.check_connection("10.0.0.1", 1000);
        limiter.check_connection("10.0.0.1", 1001);
        limiter.reset_source("10.0.0.1");
        let r = limiter.check_connection("10.0.0.1", 1002);
        assert!(r.allowed);
    }

    #[test]
    fn test_reset_all() {
        let mut limiter = NetworkRateLimiter::new(NetworkRateLimitConfig::default_config());
        limiter.check_connection("10.0.0.1", 1000);
        limiter.reset_all();
        assert!(limiter.source_counts.is_empty());
    }

    #[test]
    fn test_rate_limit_type_display() {
        let types = vec![
            RateLimitType::PerSource,
            RateLimitType::PerConnection,
            RateLimitType::Global,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 3);
    }
}
