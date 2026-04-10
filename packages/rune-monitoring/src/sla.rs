// ═══════════════════════════════════════════════════════════════════════
// SLA — service-level agreements tracked against MetricRegistry values.
//
// An Sla binds a target (uptime, latency, error-rate, throughput,
// response-time, custom) to a metric and a comparison. SlaTracker records
// snapshots over time and produces SlaStatus / SlaViolation records.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_security::SecuritySeverity;

use crate::metric::MetricRegistry;

// ── SlaTarget ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum SlaTarget {
    /// Percentage 0..=100.
    Uptime { percent: f64 },
    /// Max allowed latency in milliseconds (compared against p95).
    Latency { p95_ms: f64 },
    /// Max allowed error rate (0..=1 or percent — caller's choice).
    ErrorRate { max: f64 },
    /// Min required throughput (ops/sec).
    Throughput { min_per_sec: f64 },
    /// Max allowed response time (ms) against latest sample.
    ResponseTime { max_ms: f64 },
    /// Custom comparison against latest sample.
    Custom { comparison: SlaComparison, value: f64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaComparison {
    Above,
    Below,
    Equal,
}

impl fmt::Display for SlaComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Above => f.write_str("above"),
            Self::Below => f.write_str("below"),
            Self::Equal => f.write_str("equal"),
        }
    }
}

// ── SlaId ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SlaId(pub String);

impl SlaId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for SlaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Sla ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Sla {
    pub id: SlaId,
    pub name: String,
    pub metric_id: String,
    pub target: SlaTarget,
    pub severity_on_breach: SecuritySeverity,
    pub description: String,
}

impl Sla {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        metric_id: impl Into<String>,
        target: SlaTarget,
    ) -> Self {
        Self {
            id: SlaId::new(id),
            name: name.into(),
            metric_id: metric_id.into(),
            target,
            severity_on_breach: SecuritySeverity::High,
            description: String::new(),
        }
    }

    pub fn with_severity(mut self, s: SecuritySeverity) -> Self {
        self.severity_on_breach = s;
        self
    }

    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }
}

// ── SlaStatus ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaState {
    Meeting,
    AtRisk,
    Breached,
    Unknown,
}

impl fmt::Display for SlaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Meeting => f.write_str("meeting"),
            Self::AtRisk => f.write_str("at-risk"),
            Self::Breached => f.write_str("breached"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SlaStatus {
    pub sla_id: SlaId,
    pub state: SlaState,
    pub observed: Option<f64>,
    pub target_description: String,
    pub checked_at: i64,
}

// ── SlaViolation ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SlaViolation {
    pub sla_id: SlaId,
    pub severity: SecuritySeverity,
    pub observed: f64,
    pub target: String,
    pub occurred_at: i64,
}

// ── SlaTracker ────────────────────────────────────────────────────────

#[derive(Default)]
pub struct SlaTracker {
    pub slas: HashMap<String, Sla>,
    pub violations: Vec<SlaViolation>,
    pub statuses: HashMap<String, SlaStatus>,
}

impl SlaTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, sla: Sla) {
        self.slas.insert(sla.id.0.clone(), sla);
    }

    pub fn get(&self, id: &str) -> Option<&Sla> {
        self.slas.get(id)
    }

    /// Evaluates every SLA against the registry, updates statuses, and
    /// pushes a SlaViolation onto the trail when a new breach is seen.
    pub fn evaluate(
        &mut self,
        registry: &MetricRegistry,
        now: i64,
    ) -> Vec<SlaStatus> {
        let mut out = Vec::new();
        let ids: Vec<String> = self.slas.keys().cloned().collect();
        for sla_id in ids {
            let sla = self.slas.get(&sla_id).unwrap().clone();
            let (state, observed) = Self::evaluate_one(&sla, registry);
            let status = SlaStatus {
                sla_id: sla.id.clone(),
                state,
                observed,
                target_description: Self::describe_target(&sla.target),
                checked_at: now,
            };
            if state == SlaState::Breached {
                if let Some(obs) = observed {
                    self.violations.push(SlaViolation {
                        sla_id: sla.id.clone(),
                        severity: sla.severity_on_breach,
                        observed: obs,
                        target: status.target_description.clone(),
                        occurred_at: now,
                    });
                }
            }
            self.statuses.insert(sla_id, status.clone());
            out.push(status);
        }
        out
    }

    fn evaluate_one(
        sla: &Sla,
        reg: &MetricRegistry,
    ) -> (SlaState, Option<f64>) {
        match &sla.target {
            SlaTarget::Uptime { percent } => {
                let obs = reg.latest(&sla.metric_id);
                match obs {
                    None => (SlaState::Unknown, None),
                    Some(v) => {
                        if v >= *percent {
                            (SlaState::Meeting, Some(v))
                        } else if v >= *percent - 0.5 {
                            (SlaState::AtRisk, Some(v))
                        } else {
                            (SlaState::Breached, Some(v))
                        }
                    }
                }
            }
            SlaTarget::Latency { p95_ms } => {
                let obs = reg.percentile(&sla.metric_id, 0.95);
                match obs {
                    None => (SlaState::Unknown, None),
                    Some(v) => {
                        if v <= *p95_ms {
                            (SlaState::Meeting, Some(v))
                        } else if v <= *p95_ms * 1.1 {
                            (SlaState::AtRisk, Some(v))
                        } else {
                            (SlaState::Breached, Some(v))
                        }
                    }
                }
            }
            SlaTarget::ErrorRate { max } => {
                let obs = reg.average(&sla.metric_id);
                match obs {
                    None => (SlaState::Unknown, None),
                    Some(v) => {
                        if v <= *max {
                            (SlaState::Meeting, Some(v))
                        } else if v <= *max * 1.2 {
                            (SlaState::AtRisk, Some(v))
                        } else {
                            (SlaState::Breached, Some(v))
                        }
                    }
                }
            }
            SlaTarget::Throughput { min_per_sec } => {
                let obs = reg.rate(&sla.metric_id);
                match obs {
                    None => (SlaState::Unknown, None),
                    Some(v) => {
                        if v >= *min_per_sec {
                            (SlaState::Meeting, Some(v))
                        } else if v >= *min_per_sec * 0.9 {
                            (SlaState::AtRisk, Some(v))
                        } else {
                            (SlaState::Breached, Some(v))
                        }
                    }
                }
            }
            SlaTarget::ResponseTime { max_ms } => {
                let obs = reg.latest(&sla.metric_id);
                match obs {
                    None => (SlaState::Unknown, None),
                    Some(v) => {
                        if v <= *max_ms {
                            (SlaState::Meeting, Some(v))
                        } else if v <= *max_ms * 1.1 {
                            (SlaState::AtRisk, Some(v))
                        } else {
                            (SlaState::Breached, Some(v))
                        }
                    }
                }
            }
            SlaTarget::Custom { comparison, value } => {
                let obs = reg.latest(&sla.metric_id);
                match obs {
                    None => (SlaState::Unknown, None),
                    Some(v) => {
                        let meets = match comparison {
                            SlaComparison::Above => v > *value,
                            SlaComparison::Below => v < *value,
                            SlaComparison::Equal => (v - *value).abs() < f64::EPSILON,
                        };
                        if meets {
                            (SlaState::Meeting, Some(v))
                        } else {
                            (SlaState::Breached, Some(v))
                        }
                    }
                }
            }
        }
    }

    fn describe_target(t: &SlaTarget) -> String {
        match t {
            SlaTarget::Uptime { percent } => format!("uptime ≥ {percent}%"),
            SlaTarget::Latency { p95_ms } => format!("p95 ≤ {p95_ms}ms"),
            SlaTarget::ErrorRate { max } => format!("error_rate ≤ {max}"),
            SlaTarget::Throughput { min_per_sec } => format!("throughput ≥ {min_per_sec}/s"),
            SlaTarget::ResponseTime { max_ms } => format!("response_time ≤ {max_ms}ms"),
            SlaTarget::Custom { comparison, value } => format!("value {comparison} {value}"),
        }
    }

    pub fn active_violations(&self) -> &[SlaViolation] {
        &self.violations
    }

    pub fn meeting_count(&self) -> usize {
        self.statuses
            .values()
            .filter(|s| s.state == SlaState::Meeting)
            .count()
    }

    pub fn breached_count(&self) -> usize {
        self.statuses
            .values()
            .filter(|s| s.state == SlaState::Breached)
            .count()
    }
}

// ── SLA templates ─────────────────────────────────────────────────────

pub fn five_nines(metric_id: &str) -> Sla {
    Sla::new("five_nines", "99.999% Uptime", metric_id, SlaTarget::Uptime { percent: 99.999 })
        .with_severity(SecuritySeverity::Critical)
}

pub fn four_nines(metric_id: &str) -> Sla {
    Sla::new("four_nines", "99.99% Uptime", metric_id, SlaTarget::Uptime { percent: 99.99 })
        .with_severity(SecuritySeverity::High)
}

pub fn three_nines(metric_id: &str) -> Sla {
    Sla::new("three_nines", "99.9% Uptime", metric_id, SlaTarget::Uptime { percent: 99.9 })
        .with_severity(SecuritySeverity::High)
}

pub fn fast_api(metric_id: &str) -> Sla {
    Sla::new("fast_api", "Fast API", metric_id, SlaTarget::Latency { p95_ms: 100.0 })
        .with_severity(SecuritySeverity::Medium)
}

pub fn standard_api(metric_id: &str) -> Sla {
    Sla::new(
        "standard_api",
        "Standard API",
        metric_id,
        SlaTarget::Latency { p95_ms: 500.0 },
    )
    .with_severity(SecuritySeverity::Medium)
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metric::{MonitoringMetric, MonitoringMetricType};

    fn registry_with_latency() -> MetricRegistry {
        let mut r = MetricRegistry::new();
        r.register(MonitoringMetric::new(
            "lat",
            "Lat",
            MonitoringMetricType::Timer,
            "ms",
        ));
        r
    }

    #[test]
    fn test_latency_meeting() {
        let mut reg = registry_with_latency();
        for v in 1..=100 {
            reg.record("lat", v as f64, v).unwrap();
        }
        let mut t = SlaTracker::new();
        t.register(fast_api("lat"));
        let statuses = t.evaluate(&reg, 100);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, SlaState::Meeting);
    }

    #[test]
    fn test_latency_breached_records_violation() {
        let mut reg = registry_with_latency();
        for _ in 0..100 {
            reg.record("lat", 2000.0, 1).unwrap();
        }
        let mut t = SlaTracker::new();
        t.register(fast_api("lat"));
        let statuses = t.evaluate(&reg, 1);
        assert_eq!(statuses[0].state, SlaState::Breached);
        assert_eq!(t.active_violations().len(), 1);
        assert_eq!(t.active_violations()[0].severity, SecuritySeverity::Medium);
    }

    #[test]
    fn test_uptime_meeting_at_risk_breached() {
        let mut reg = MetricRegistry::new();
        reg.register(MonitoringMetric::new(
            "up",
            "Uptime",
            MonitoringMetricType::Gauge,
            "percent",
        ));
        let mut t = SlaTracker::new();
        t.register(three_nines("up"));
        reg.record("up", 100.0, 1).unwrap();
        assert_eq!(t.evaluate(&reg, 1)[0].state, SlaState::Meeting);
        reg.record("up", 99.5, 2).unwrap();
        assert_eq!(t.evaluate(&reg, 2)[0].state, SlaState::AtRisk);
        reg.record("up", 50.0, 3).unwrap();
        assert_eq!(t.evaluate(&reg, 3)[0].state, SlaState::Breached);
    }

    #[test]
    fn test_error_rate_sla() {
        let mut reg = MetricRegistry::new();
        reg.register(MonitoringMetric::new(
            "err",
            "Err",
            MonitoringMetricType::Gauge,
            "",
        ));
        reg.record("err", 0.5, 1).unwrap();
        reg.record("err", 0.5, 2).unwrap();
        let mut t = SlaTracker::new();
        t.register(Sla::new(
            "e",
            "E",
            "err",
            SlaTarget::ErrorRate { max: 1.0 },
        ));
        assert_eq!(t.evaluate(&reg, 2)[0].state, SlaState::Meeting);
    }

    #[test]
    fn test_throughput_sla() {
        let mut reg = MetricRegistry::new();
        reg.register(MonitoringMetric::new(
            "r",
            "R",
            MonitoringMetricType::Counter,
            "",
        ));
        for i in 0..10 {
            reg.record("r", 1.0, i).unwrap();
        }
        let mut t = SlaTracker::new();
        t.register(Sla::new(
            "th",
            "TH",
            "r",
            SlaTarget::Throughput { min_per_sec: 0.5 },
        ));
        assert_eq!(t.evaluate(&reg, 10)[0].state, SlaState::Meeting);
    }

    #[test]
    fn test_response_time_sla() {
        let mut reg = registry_with_latency();
        reg.record("lat", 50.0, 1).unwrap();
        let mut t = SlaTracker::new();
        t.register(Sla::new(
            "rt",
            "RT",
            "lat",
            SlaTarget::ResponseTime { max_ms: 100.0 },
        ));
        assert_eq!(t.evaluate(&reg, 1)[0].state, SlaState::Meeting);
    }

    #[test]
    fn test_custom_comparison_sla() {
        let mut reg = registry_with_latency();
        reg.record("lat", 42.0, 1).unwrap();
        let mut t = SlaTracker::new();
        t.register(Sla::new(
            "c",
            "C",
            "lat",
            SlaTarget::Custom {
                comparison: SlaComparison::Below,
                value: 100.0,
            },
        ));
        assert_eq!(t.evaluate(&reg, 1)[0].state, SlaState::Meeting);
    }

    #[test]
    fn test_unknown_when_no_data() {
        let reg = registry_with_latency();
        let mut t = SlaTracker::new();
        t.register(fast_api("lat"));
        assert_eq!(t.evaluate(&reg, 1)[0].state, SlaState::Unknown);
    }

    #[test]
    fn test_meeting_and_breached_counts() {
        let mut reg = MetricRegistry::new();
        reg.register(MonitoringMetric::new(
            "up",
            "Up",
            MonitoringMetricType::Gauge,
            "",
        ));
        reg.register(MonitoringMetric::new(
            "lat",
            "Lat",
            MonitoringMetricType::Timer,
            "ms",
        ));
        reg.record("up", 100.0, 1).unwrap();
        for _ in 0..100 {
            reg.record("lat", 5000.0, 1).unwrap();
        }
        let mut t = SlaTracker::new();
        t.register(three_nines("up"));
        t.register(fast_api("lat"));
        t.evaluate(&reg, 1);
        assert_eq!(t.meeting_count(), 1);
        assert_eq!(t.breached_count(), 1);
    }

    #[test]
    fn test_all_templates() {
        let _ = five_nines("up");
        let _ = four_nines("up");
        let _ = three_nines("up");
        let _ = fast_api("lat");
        let _ = standard_api("lat");
    }

    #[test]
    fn test_describe_target_display() {
        assert!(SlaTracker::describe_target(&SlaTarget::Uptime { percent: 99.9 })
            .contains("99.9"));
        assert!(SlaTracker::describe_target(&SlaTarget::Latency { p95_ms: 100.0 })
            .contains("p95"));
    }
}
