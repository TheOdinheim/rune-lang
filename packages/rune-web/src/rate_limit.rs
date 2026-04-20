// ═══════════════════════════════════════════════════════════════════════
// Rate Limit — Pluggable rate limit backend trait.
//
// Layer 3 defines the contract for rate limiting so customers can
// plug Redis, Memcached, or distributed rate limit services. This
// layer provides only in-memory reference implementations.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::WebError;

// ── RateLimitDecision ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed { remaining: u64 },
    Throttled { retry_after_secs: u64, limit: u64 },
}

impl RateLimitDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}

// ── BucketStatus ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketStatus {
    pub key: String,
    pub remaining: u64,
    pub limit: u64,
    pub reset_at: i64,
}

// ── RateLimitBackendInfo ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitBackendInfo {
    pub backend_type: String,
    pub supports_distributed: bool,
    pub algorithm: String,
}

// ── RateLimitBackend trait ─────────────────────────────────────

pub trait RateLimitBackend {
    fn check_and_consume(&mut self, key: &str, now: i64) -> RateLimitDecision;
    fn reset_bucket(&mut self, key: &str);
    fn bucket_status(&self, key: &str) -> Option<BucketStatus>;
    fn list_buckets(&self) -> Vec<&str>;
    fn backend_info(&self) -> RateLimitBackendInfo;
}

// ── InMemoryTokenBucket ────────────────────────────────────────

struct TokenBucketState {
    tokens: f64,
    last_refill: i64,
}

/// Classic token bucket with configurable capacity and refill rate.
pub struct InMemoryTokenBucket {
    buckets: HashMap<String, TokenBucketState>,
    capacity: u64,
    refill_rate_per_sec: f64,
}

impl InMemoryTokenBucket {
    pub fn new(capacity: u64, refill_rate_per_sec: f64) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity,
            refill_rate_per_sec,
        }
    }
}

impl RateLimitBackend for InMemoryTokenBucket {
    fn check_and_consume(&mut self, key: &str, now: i64) -> RateLimitDecision {
        let state = self.buckets.entry(key.to_string()).or_insert(TokenBucketState {
            tokens: self.capacity as f64,
            last_refill: now,
        });

        // Refill
        let elapsed_secs = f64::max(0.0, (now - state.last_refill) as f64);
        state.tokens = f64::min(self.capacity as f64, state.tokens + elapsed_secs * self.refill_rate_per_sec);
        state.last_refill = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            RateLimitDecision::Allowed {
                remaining: state.tokens as u64,
            }
        } else {
            let deficit = 1.0 - state.tokens;
            let retry_secs = if self.refill_rate_per_sec > 0.0 {
                (deficit / self.refill_rate_per_sec).ceil() as u64
            } else {
                60
            };
            RateLimitDecision::Throttled {
                retry_after_secs: retry_secs,
                limit: self.capacity,
            }
        }
    }

    fn reset_bucket(&mut self, key: &str) {
        self.buckets.remove(key);
    }

    fn bucket_status(&self, key: &str) -> Option<BucketStatus> {
        self.buckets.get(key).map(|s| BucketStatus {
            key: key.to_string(),
            remaining: s.tokens as u64,
            limit: self.capacity,
            reset_at: s.last_refill,
        })
    }

    fn list_buckets(&self) -> Vec<&str> {
        self.buckets.keys().map(|k| k.as_str()).collect()
    }

    fn backend_info(&self) -> RateLimitBackendInfo {
        RateLimitBackendInfo {
            backend_type: "in-memory".to_string(),
            supports_distributed: false,
            algorithm: "token-bucket".to_string(),
        }
    }
}

// ── InMemoryLeakyBucket ────────────────────────────────────────

struct LeakyBucketState {
    level: f64,
    last_drain: i64,
}

/// Leaky bucket with configurable capacity and drain rate.
pub struct InMemoryLeakyBucket {
    buckets: HashMap<String, LeakyBucketState>,
    capacity: u64,
    drain_rate_per_sec: f64,
}

impl InMemoryLeakyBucket {
    pub fn new(capacity: u64, drain_rate_per_sec: f64) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity,
            drain_rate_per_sec,
        }
    }
}

impl RateLimitBackend for InMemoryLeakyBucket {
    fn check_and_consume(&mut self, key: &str, now: i64) -> RateLimitDecision {
        let state = self.buckets.entry(key.to_string()).or_insert(LeakyBucketState {
            level: 0.0,
            last_drain: now,
        });

        // Drain
        let elapsed_secs = f64::max(0.0, (now - state.last_drain) as f64);
        state.level = f64::max(0.0, state.level - elapsed_secs * self.drain_rate_per_sec);
        state.last_drain = now;

        if state.level + 1.0 <= self.capacity as f64 {
            state.level += 1.0;
            let remaining = (self.capacity as f64 - state.level) as u64;
            RateLimitDecision::Allowed { remaining }
        } else {
            let overflow = state.level + 1.0 - self.capacity as f64;
            let retry_secs = if self.drain_rate_per_sec > 0.0 {
                (overflow / self.drain_rate_per_sec).ceil() as u64
            } else {
                60
            };
            RateLimitDecision::Throttled {
                retry_after_secs: retry_secs,
                limit: self.capacity,
            }
        }
    }

    fn reset_bucket(&mut self, key: &str) {
        self.buckets.remove(key);
    }

    fn bucket_status(&self, key: &str) -> Option<BucketStatus> {
        self.buckets.get(key).map(|s| BucketStatus {
            key: key.to_string(),
            remaining: (self.capacity as f64 - s.level) as u64,
            limit: self.capacity,
            reset_at: s.last_drain,
        })
    }

    fn list_buckets(&self) -> Vec<&str> {
        self.buckets.keys().map(|k| k.as_str()).collect()
    }

    fn backend_info(&self) -> RateLimitBackendInfo {
        RateLimitBackendInfo {
            backend_type: "in-memory".to_string(),
            supports_distributed: false,
            algorithm: "leaky-bucket".to_string(),
        }
    }
}

// ── InMemorySlidingWindow ──────────────────────────────────────

/// Fixed-window approximation with sub-window arrays.
pub struct InMemorySlidingWindow {
    windows: HashMap<String, Vec<i64>>,
    max_requests: u64,
    window_secs: i64,
}

impl InMemorySlidingWindow {
    pub fn new(max_requests: u64, window_secs: i64) -> Self {
        Self {
            windows: HashMap::new(),
            max_requests,
            window_secs,
        }
    }
}

impl RateLimitBackend for InMemorySlidingWindow {
    fn check_and_consume(&mut self, key: &str, now: i64) -> RateLimitDecision {
        let timestamps = self.windows.entry(key.to_string()).or_default();
        let cutoff = now - self.window_secs;
        timestamps.retain(|&ts| ts > cutoff);

        if (timestamps.len() as u64) < self.max_requests {
            timestamps.push(now);
            let remaining = self.max_requests - timestamps.len() as u64;
            RateLimitDecision::Allowed { remaining }
        } else {
            // Retry after the oldest request in the window expires
            let retry_secs = if let Some(&oldest) = timestamps.first() {
                let wait = (oldest + self.window_secs) - now;
                if wait > 0 { wait as u64 } else { 1 }
            } else {
                1
            };
            RateLimitDecision::Throttled {
                retry_after_secs: retry_secs,
                limit: self.max_requests,
            }
        }
    }

    fn reset_bucket(&mut self, key: &str) {
        self.windows.remove(key);
    }

    fn bucket_status(&self, key: &str) -> Option<BucketStatus> {
        self.windows.get(key).map(|timestamps| {
            BucketStatus {
                key: key.to_string(),
                remaining: self.max_requests.saturating_sub(timestamps.len() as u64),
                limit: self.max_requests,
                reset_at: timestamps.first().map(|t| t + self.window_secs).unwrap_or(0),
            }
        })
    }

    fn list_buckets(&self) -> Vec<&str> {
        self.windows.keys().map(|k| k.as_str()).collect()
    }

    fn backend_info(&self) -> RateLimitBackendInfo {
        RateLimitBackendInfo {
            backend_type: "in-memory".to_string(),
            supports_distributed: false,
            algorithm: "sliding-window".to_string(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Token Bucket ───────────────────────────────────────────

    #[test]
    fn test_token_bucket_allows_within_capacity() {
        let mut tb = InMemoryTokenBucket::new(5, 1.0);
        for _ in 0..5 {
            assert!(tb.check_and_consume("user-1", 1000).is_allowed());
        }
    }

    #[test]
    fn test_token_bucket_throttles_over_capacity() {
        let mut tb = InMemoryTokenBucket::new(2, 1.0);
        assert!(tb.check_and_consume("user-1", 1000).is_allowed());
        assert!(tb.check_and_consume("user-1", 1000).is_allowed());
        let decision = tb.check_and_consume("user-1", 1000);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_token_bucket_refills() {
        let mut tb = InMemoryTokenBucket::new(2, 1.0);
        assert!(tb.check_and_consume("user-1", 1000).is_allowed());
        assert!(tb.check_and_consume("user-1", 1000).is_allowed());
        assert!(!tb.check_and_consume("user-1", 1000).is_allowed());
        // After 2 seconds, 2 tokens refill
        assert!(tb.check_and_consume("user-1", 1002).is_allowed());
    }

    #[test]
    fn test_token_bucket_reset() {
        let mut tb = InMemoryTokenBucket::new(2, 1.0);
        tb.check_and_consume("user-1", 1000);
        tb.reset_bucket("user-1");
        assert!(tb.bucket_status("user-1").is_none());
    }

    #[test]
    fn test_token_bucket_status() {
        let mut tb = InMemoryTokenBucket::new(5, 1.0);
        tb.check_and_consume("user-1", 1000);
        let status = tb.bucket_status("user-1").unwrap();
        assert_eq!(status.limit, 5);
        assert!(status.remaining <= 4);
    }

    #[test]
    fn test_token_bucket_info() {
        let tb = InMemoryTokenBucket::new(5, 1.0);
        let info = tb.backend_info();
        assert_eq!(info.algorithm, "token-bucket");
        assert!(!info.supports_distributed);
    }

    // ── Leaky Bucket ───────────────────────────────────────────

    #[test]
    fn test_leaky_bucket_allows_within_capacity() {
        let mut lb = InMemoryLeakyBucket::new(5, 1.0);
        for _ in 0..5 {
            assert!(lb.check_and_consume("user-1", 1000).is_allowed());
        }
    }

    #[test]
    fn test_leaky_bucket_throttles_over_capacity() {
        let mut lb = InMemoryLeakyBucket::new(3, 1.0);
        for _ in 0..3 {
            assert!(lb.check_and_consume("user-1", 1000).is_allowed());
        }
        assert!(!lb.check_and_consume("user-1", 1000).is_allowed());
    }

    #[test]
    fn test_leaky_bucket_drains() {
        let mut lb = InMemoryLeakyBucket::new(2, 1.0);
        lb.check_and_consume("user-1", 1000);
        lb.check_and_consume("user-1", 1000);
        assert!(!lb.check_and_consume("user-1", 1000).is_allowed());
        // After 1 second, 1 unit drains
        assert!(lb.check_and_consume("user-1", 1001).is_allowed());
    }

    #[test]
    fn test_leaky_bucket_info() {
        let lb = InMemoryLeakyBucket::new(5, 1.0);
        assert_eq!(lb.backend_info().algorithm, "leaky-bucket");
    }

    // ── Sliding Window ─────────────────────────────────────────

    #[test]
    fn test_sliding_window_allows_within_limit() {
        let mut sw = InMemorySlidingWindow::new(5, 60);
        for t in 0..5 {
            assert!(sw.check_and_consume("user-1", 1000 + t).is_allowed());
        }
    }

    #[test]
    fn test_sliding_window_throttles_over_limit() {
        let mut sw = InMemorySlidingWindow::new(3, 60);
        for t in 0..3 {
            assert!(sw.check_and_consume("user-1", 1000 + t).is_allowed());
        }
        assert!(!sw.check_and_consume("user-1", 1003).is_allowed());
    }

    #[test]
    fn test_sliding_window_expires_old_requests() {
        let mut sw = InMemorySlidingWindow::new(2, 10);
        assert!(sw.check_and_consume("user-1", 1000).is_allowed());
        assert!(sw.check_and_consume("user-1", 1005).is_allowed());
        assert!(!sw.check_and_consume("user-1", 1009).is_allowed());
        // After window expires for first request
        assert!(sw.check_and_consume("user-1", 1011).is_allowed());
    }

    #[test]
    fn test_sliding_window_reset() {
        let mut sw = InMemorySlidingWindow::new(2, 60);
        sw.check_and_consume("user-1", 1000);
        sw.reset_bucket("user-1");
        assert!(sw.bucket_status("user-1").is_none());
    }

    #[test]
    fn test_sliding_window_info() {
        let sw = InMemorySlidingWindow::new(5, 60);
        assert_eq!(sw.backend_info().algorithm, "sliding-window");
    }

    // ── Multi-key isolation ────────────────────────────────────

    #[test]
    fn test_different_keys_independent() {
        let mut tb = InMemoryTokenBucket::new(1, 0.0);
        assert!(tb.check_and_consume("user-a", 1000).is_allowed());
        assert!(tb.check_and_consume("user-b", 1000).is_allowed());
        assert!(!tb.check_and_consume("user-a", 1000).is_allowed());
        assert!(!tb.check_and_consume("user-b", 1000).is_allowed());
    }

    #[test]
    fn test_list_buckets() {
        let mut tb = InMemoryTokenBucket::new(5, 1.0);
        tb.check_and_consume("a", 1000);
        tb.check_and_consume("b", 1000);
        assert_eq!(tb.list_buckets().len(), 2);
    }
}
