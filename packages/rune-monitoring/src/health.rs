// ═══════════════════════════════════════════════════════════════════════
// Health — liveness/readiness/dependency health checks.
//
// HealthCheck describes a probe; HealthCheckRunner stores checks, their
// latest results, and produces a HealthSummary that aggregates the
// worst-case status.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_security::SecuritySeverity;

use crate::error::{MonitoringError, MonitoringResult};

// ── HealthStatus ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HealthStatus {
    Healthy = 0,
    Degraded = 1,
    Unhealthy = 2,
    Unknown = 3,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unknown => "unknown",
        }
    }

    pub fn to_severity(&self) -> SecuritySeverity {
        match self {
            Self::Healthy => SecuritySeverity::Info,
            Self::Degraded => SecuritySeverity::Medium,
            Self::Unhealthy => SecuritySeverity::High,
            Self::Unknown => SecuritySeverity::Low,
        }
    }

    /// Worst-case combination: treat Unknown as less severe than Unhealthy
    /// but worse than Healthy.
    pub fn worst(a: Self, b: Self) -> Self {
        // Unhealthy > Degraded > Unknown > Healthy
        fn rank(s: HealthStatus) -> u8 {
            match s {
                HealthStatus::Healthy => 0,
                HealthStatus::Unknown => 1,
                HealthStatus::Degraded => 2,
                HealthStatus::Unhealthy => 3,
            }
        }
        if rank(a) >= rank(b) {
            a
        } else {
            b
        }
    }
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── HealthCheckType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HealthCheckType {
    Liveness,
    Readiness,
    Dependency,
    Performance,
    Storage,
    Memory,
    Custom(String),
}

impl fmt::Display for HealthCheckType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Liveness => f.write_str("liveness"),
            Self::Readiness => f.write_str("readiness"),
            Self::Dependency => f.write_str("dependency"),
            Self::Performance => f.write_str("performance"),
            Self::Storage => f.write_str("storage"),
            Self::Memory => f.write_str("memory"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ── HealthCheckId ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HealthCheckId(pub String);

impl HealthCheckId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for HealthCheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── HealthCheck ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub id: HealthCheckId,
    pub name: String,
    pub check_type: HealthCheckType,
    pub component: String,
    pub timeout_ms: u64,
    pub interval_ms: u64,
    pub critical: bool,
}

impl HealthCheck {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        check_type: HealthCheckType,
        component: impl Into<String>,
    ) -> Self {
        Self {
            id: HealthCheckId::new(id),
            name: name.into(),
            check_type,
            component: component.into(),
            timeout_ms: 5_000,
            interval_ms: 30_000,
            critical: false,
        }
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn with_interval(mut self, ms: u64) -> Self {
        self.interval_ms = ms;
        self
    }

    pub fn critical(mut self) -> Self {
        self.critical = true;
        self
    }
}

// ── HealthCheckResult ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub id: HealthCheckId,
    pub status: HealthStatus,
    pub message: String,
    pub duration_ms: u64,
    pub checked_at: i64,
    pub details: HashMap<String, String>,
}

impl HealthCheckResult {
    pub fn healthy(id: HealthCheckId, checked_at: i64) -> Self {
        Self {
            id,
            status: HealthStatus::Healthy,
            message: "ok".into(),
            duration_ms: 0,
            checked_at,
            details: HashMap::new(),
        }
    }

    pub fn degraded(id: HealthCheckId, msg: impl Into<String>, checked_at: i64) -> Self {
        Self {
            id,
            status: HealthStatus::Degraded,
            message: msg.into(),
            duration_ms: 0,
            checked_at,
            details: HashMap::new(),
        }
    }

    pub fn unhealthy(id: HealthCheckId, msg: impl Into<String>, checked_at: i64) -> Self {
        Self {
            id,
            status: HealthStatus::Unhealthy,
            message: msg.into(),
            duration_ms: 0,
            checked_at,
            details: HashMap::new(),
        }
    }

    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = ms;
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.details.insert(key.into(), val.into());
        self
    }
}

// ── HealthCheckRunner ─────────────────────────────────────────────────

#[derive(Default)]
pub struct HealthCheckRunner {
    pub checks: HashMap<String, HealthCheck>,
    pub results: HashMap<String, HealthCheckResult>,
}

impl HealthCheckRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, check: HealthCheck) {
        self.checks.insert(check.id.0.clone(), check);
    }

    pub fn record(&mut self, result: HealthCheckResult) -> MonitoringResult<()> {
        if !self.checks.contains_key(&result.id.0) {
            return Err(MonitoringError::HealthCheckNotFound { id: result.id.0.clone() });
        }
        self.results.insert(result.id.0.clone(), result);
        Ok(())
    }

    pub fn get_result(&self, id: &str) -> Option<&HealthCheckResult> {
        self.results.get(id)
    }

    pub fn latest_for_component(&self, component: &str) -> Vec<&HealthCheckResult> {
        self.checks
            .values()
            .filter(|c| c.component == component)
            .filter_map(|c| self.results.get(&c.id.0))
            .collect()
    }

    pub fn summary(&self) -> HealthSummary {
        let mut summary = HealthSummary::default();
        summary.total_checks = self.checks.len();
        for check in self.checks.values() {
            match self.results.get(&check.id.0) {
                None => {
                    summary.unknown += 1;
                    summary.overall = HealthStatus::worst(summary.overall, HealthStatus::Unknown);
                }
                Some(r) => {
                    match r.status {
                        HealthStatus::Healthy => summary.healthy += 1,
                        HealthStatus::Degraded => summary.degraded += 1,
                        HealthStatus::Unhealthy => {
                            summary.unhealthy += 1;
                            if check.critical {
                                summary.critical_failures += 1;
                            }
                        }
                        HealthStatus::Unknown => summary.unknown += 1,
                    }
                    summary.overall = HealthStatus::worst(summary.overall, r.status);
                }
            }
        }
        summary
    }
}

// ── HealthSummary ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct HealthSummary {
    pub total_checks: usize,
    pub healthy: usize,
    pub degraded: usize,
    pub unhealthy: usize,
    pub unknown: usize,
    pub critical_failures: usize,
    pub overall: HealthStatus,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::Healthy
    }
}

impl HealthSummary {
    pub fn is_operational(&self) -> bool {
        matches!(self.overall, HealthStatus::Healthy | HealthStatus::Degraded)
            && self.critical_failures == 0
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_worst_ordering() {
        assert_eq!(
            HealthStatus::worst(HealthStatus::Healthy, HealthStatus::Degraded),
            HealthStatus::Degraded
        );
        assert_eq!(
            HealthStatus::worst(HealthStatus::Degraded, HealthStatus::Unhealthy),
            HealthStatus::Unhealthy
        );
        assert_eq!(
            HealthStatus::worst(HealthStatus::Unknown, HealthStatus::Healthy),
            HealthStatus::Unknown
        );
        assert_eq!(
            HealthStatus::worst(HealthStatus::Unhealthy, HealthStatus::Unknown),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn test_status_to_severity() {
        assert_eq!(HealthStatus::Healthy.to_severity(), SecuritySeverity::Info);
        assert_eq!(HealthStatus::Degraded.to_severity(), SecuritySeverity::Medium);
        assert_eq!(HealthStatus::Unhealthy.to_severity(), SecuritySeverity::High);
        assert_eq!(HealthStatus::Unknown.to_severity(), SecuritySeverity::Low);
    }

    #[test]
    fn test_check_type_display() {
        assert_eq!(HealthCheckType::Liveness.to_string(), "liveness");
        assert_eq!(HealthCheckType::Readiness.to_string(), "readiness");
        assert_eq!(HealthCheckType::Dependency.to_string(), "dependency");
        assert_eq!(
            HealthCheckType::Custom("x".into()).to_string(),
            "custom:x"
        );
    }

    #[test]
    fn test_register_and_get_result() {
        let mut r = HealthCheckRunner::new();
        r.register(HealthCheck::new("db", "Database", HealthCheckType::Dependency, "db"));
        r.record(HealthCheckResult::healthy(HealthCheckId::new("db"), 1000))
            .unwrap();
        assert!(r.get_result("db").is_some());
    }

    #[test]
    fn test_record_unknown_check_errors() {
        let mut r = HealthCheckRunner::new();
        let err = r
            .record(HealthCheckResult::healthy(HealthCheckId::new("unknown"), 1000))
            .unwrap_err();
        assert!(matches!(err, MonitoringError::HealthCheckNotFound { .. }));
    }

    #[test]
    fn test_summary_all_healthy() {
        let mut r = HealthCheckRunner::new();
        r.register(HealthCheck::new("a", "A", HealthCheckType::Liveness, "svc"));
        r.register(HealthCheck::new("b", "B", HealthCheckType::Readiness, "svc"));
        r.record(HealthCheckResult::healthy(HealthCheckId::new("a"), 1))
            .unwrap();
        r.record(HealthCheckResult::healthy(HealthCheckId::new("b"), 1))
            .unwrap();
        let s = r.summary();
        assert_eq!(s.healthy, 2);
        assert_eq!(s.overall, HealthStatus::Healthy);
        assert!(s.is_operational());
    }

    #[test]
    fn test_summary_critical_failure_breaks_operational() {
        let mut r = HealthCheckRunner::new();
        r.register(
            HealthCheck::new("db", "Database", HealthCheckType::Dependency, "db").critical(),
        );
        r.record(HealthCheckResult::unhealthy(
            HealthCheckId::new("db"),
            "connection refused",
            1,
        ))
        .unwrap();
        let s = r.summary();
        assert_eq!(s.unhealthy, 1);
        assert_eq!(s.critical_failures, 1);
        assert!(!s.is_operational());
    }

    #[test]
    fn test_summary_unknown_for_missing_result() {
        let mut r = HealthCheckRunner::new();
        r.register(HealthCheck::new("a", "A", HealthCheckType::Liveness, "svc"));
        let s = r.summary();
        assert_eq!(s.unknown, 1);
        assert_eq!(s.overall, HealthStatus::Unknown);
    }

    #[test]
    fn test_latest_for_component_filter() {
        let mut r = HealthCheckRunner::new();
        r.register(HealthCheck::new("a", "A", HealthCheckType::Liveness, "api"));
        r.register(HealthCheck::new("b", "B", HealthCheckType::Readiness, "db"));
        r.record(HealthCheckResult::healthy(HealthCheckId::new("a"), 1))
            .unwrap();
        r.record(HealthCheckResult::degraded(HealthCheckId::new("b"), "slow", 1))
            .unwrap();
        assert_eq!(r.latest_for_component("api").len(), 1);
        assert_eq!(r.latest_for_component("db").len(), 1);
    }

    #[test]
    fn test_health_check_builder_options() {
        let c = HealthCheck::new("a", "A", HealthCheckType::Liveness, "svc")
            .with_timeout(1000)
            .with_interval(10_000)
            .critical();
        assert_eq!(c.timeout_ms, 1000);
        assert_eq!(c.interval_ms, 10_000);
        assert!(c.critical);
    }

    #[test]
    fn test_result_with_detail_and_duration() {
        let r = HealthCheckResult::healthy(HealthCheckId::new("a"), 100)
            .with_duration(42)
            .with_detail("k", "v");
        assert_eq!(r.duration_ms, 42);
        assert_eq!(r.details.get("k").map(String::as_str), Some("v"));
    }
}
