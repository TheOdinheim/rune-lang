// ═══════════════════════════════════════════════════════════════════════
// Threshold — rule-based alerting on MetricRegistry values.
//
// ThresholdRule defines a condition + severity; ThresholdEngine evaluates
// rules against a MetricRegistry and returns ThresholdAlerts.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_security::SecuritySeverity;

use crate::metric::MetricRegistry;

// ── ThresholdCondition ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ThresholdCondition {
    /// Latest sample strictly above `value`.
    Above { value: f64 },
    /// Latest sample strictly below `value`.
    Below { value: f64 },
    /// Latest sample outside [lo, hi].
    OutsideRange { lo: f64, hi: f64 },
    /// Observed rate (samples/sec) above `value`.
    RateAbove { value: f64 },
    /// Percentile (0..=1) above `value`.
    PercentileAbove { percentile: f64, value: f64 },
    /// Running average above `value`.
    AverageAbove { value: f64 },
    /// Running average below `value`.
    AverageBelow { value: f64 },
}

impl fmt::Display for ThresholdCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Above { value } => write!(f, "above {value}"),
            Self::Below { value } => write!(f, "below {value}"),
            Self::OutsideRange { lo, hi } => write!(f, "outside [{lo},{hi}]"),
            Self::RateAbove { value } => write!(f, "rate above {value}/s"),
            Self::PercentileAbove { percentile, value } => {
                write!(f, "p{:.0} above {}", percentile * 100.0, value)
            }
            Self::AverageAbove { value } => write!(f, "avg above {value}"),
            Self::AverageBelow { value } => write!(f, "avg below {value}"),
        }
    }
}

// ── ThresholdRule ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThresholdRule {
    pub id: String,
    pub name: String,
    pub metric_id: String,
    pub condition: ThresholdCondition,
    pub severity: SecuritySeverity,
    pub description: String,
    pub enabled: bool,
}

impl ThresholdRule {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        metric_id: impl Into<String>,
        condition: ThresholdCondition,
        severity: SecuritySeverity,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            metric_id: metric_id.into(),
            condition,
            severity,
            description: String::new(),
            enabled: true,
        }
    }

    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }
}

// ── ThresholdAlertStatus ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdAlertStatus {
    Firing,
    Resolved,
}

impl fmt::Display for ThresholdAlertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Firing => f.write_str("firing"),
            Self::Resolved => f.write_str("resolved"),
        }
    }
}

// ── ThresholdAlert ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThresholdAlert {
    pub rule_id: String,
    pub metric_id: String,
    pub severity: SecuritySeverity,
    pub observed: f64,
    pub condition: String,
    pub fired_at: i64,
    pub status: ThresholdAlertStatus,
}

// ── ThresholdEngine ───────────────────────────────────────────────────

#[derive(Default)]
pub struct ThresholdEngine {
    pub rules: HashMap<String, ThresholdRule>,
    /// rule_id → currently firing alert (at most one per rule).
    pub firing: HashMap<String, ThresholdAlert>,
}

impl ThresholdEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: ThresholdRule) {
        self.rules.insert(rule.id.clone(), rule);
    }

    pub fn remove_rule(&mut self, id: &str) {
        self.rules.remove(id);
        self.firing.remove(id);
    }

    /// Evaluates all rules against `registry`. Returns the list of
    /// `ThresholdAlert`s that *transitioned* (newly firing or newly
    /// resolved) on this evaluation.
    pub fn evaluate(
        &mut self,
        registry: &MetricRegistry,
        now: i64,
    ) -> Vec<ThresholdAlert> {
        let mut transitions = Vec::new();

        for rule in self.rules.values() {
            if !rule.enabled {
                continue;
            }
            let matched = Self::eval_condition(&rule.condition, &rule.metric_id, registry);
            let was_firing = self.firing.contains_key(&rule.id);

            match (matched, was_firing) {
                (Some(obs), false) => {
                    let alert = ThresholdAlert {
                        rule_id: rule.id.clone(),
                        metric_id: rule.metric_id.clone(),
                        severity: rule.severity,
                        observed: obs,
                        condition: rule.condition.to_string(),
                        fired_at: now,
                        status: ThresholdAlertStatus::Firing,
                    };
                    transitions.push(alert);
                }
                (None, true) => {
                    if let Some(mut existing) = self.firing.remove(&rule.id) {
                        existing.status = ThresholdAlertStatus::Resolved;
                        transitions.push(existing);
                    }
                }
                _ => {}
            }
        }

        // Commit newly-firing alerts into the firing map.
        for a in &transitions {
            if a.status == ThresholdAlertStatus::Firing {
                self.firing.insert(a.rule_id.clone(), a.clone());
            }
        }
        transitions
    }

    pub fn active_alerts(&self) -> Vec<&ThresholdAlert> {
        self.firing.values().collect()
    }

    fn eval_condition(
        cond: &ThresholdCondition,
        metric_id: &str,
        reg: &MetricRegistry,
    ) -> Option<f64> {
        match cond {
            ThresholdCondition::Above { value } => {
                let v = reg.latest(metric_id)?;
                if v > *value {
                    Some(v)
                } else {
                    None
                }
            }
            ThresholdCondition::Below { value } => {
                let v = reg.latest(metric_id)?;
                if v < *value {
                    Some(v)
                } else {
                    None
                }
            }
            ThresholdCondition::OutsideRange { lo, hi } => {
                let v = reg.latest(metric_id)?;
                if v < *lo || v > *hi {
                    Some(v)
                } else {
                    None
                }
            }
            ThresholdCondition::RateAbove { value } => {
                let r = reg.rate(metric_id)?;
                if r > *value {
                    Some(r)
                } else {
                    None
                }
            }
            ThresholdCondition::PercentileAbove { percentile, value } => {
                let p = reg.percentile(metric_id, *percentile)?;
                if p > *value {
                    Some(p)
                } else {
                    None
                }
            }
            ThresholdCondition::AverageAbove { value } => {
                let a = reg.average(metric_id)?;
                if a > *value {
                    Some(a)
                } else {
                    None
                }
            }
            ThresholdCondition::AverageBelow { value } => {
                let a = reg.average(metric_id)?;
                if a < *value {
                    Some(a)
                } else {
                    None
                }
            }
        }
    }
}

// ── Built-in rule templates ───────────────────────────────────────────

pub fn high_error_rate(metric_id: &str, max: f64) -> ThresholdRule {
    ThresholdRule::new(
        "high_error_rate",
        "High Error Rate",
        metric_id,
        ThresholdCondition::AverageAbove { value: max },
        SecuritySeverity::High,
    )
    .with_description("average error rate exceeds target")
}

pub fn high_latency(metric_id: &str, p95_ms: f64) -> ThresholdRule {
    ThresholdRule::new(
        "high_latency",
        "High Latency",
        metric_id,
        ThresholdCondition::PercentileAbove { percentile: 0.95, value: p95_ms },
        SecuritySeverity::Medium,
    )
    .with_description("p95 latency exceeds SLO")
}

pub fn low_availability(metric_id: &str, min: f64) -> ThresholdRule {
    ThresholdRule::new(
        "low_availability",
        "Low Availability",
        metric_id,
        ThresholdCondition::Below { value: min },
        SecuritySeverity::High,
    )
    .with_description("availability below minimum target")
}

pub fn high_memory(metric_id: &str, max_percent: f64) -> ThresholdRule {
    ThresholdRule::new(
        "high_memory",
        "High Memory Usage",
        metric_id,
        ThresholdCondition::Above { value: max_percent },
        SecuritySeverity::Medium,
    )
    .with_description("memory usage above safe threshold")
}

pub fn queue_depth(metric_id: &str, max: f64) -> ThresholdRule {
    ThresholdRule::new(
        "queue_depth",
        "Queue Depth",
        metric_id,
        ThresholdCondition::Above { value: max },
        SecuritySeverity::Medium,
    )
    .with_description("queue depth exceeds capacity target")
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Alert deduplication, correlation, suppression
// ═══════════════════════════════════════════════════════════════════════

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ── AlertDeduplicator ────────────────────────────────────────────────

#[derive(Default)]
pub struct AlertDeduplicator {
    /// fingerprint → last fired timestamp
    pub active: HashMap<u64, i64>,
    pub dedup_window_ms: i64,
}

impl AlertDeduplicator {
    pub fn new(dedup_window_ms: i64) -> Self {
        Self {
            active: HashMap::new(),
            dedup_window_ms,
        }
    }

    fn fingerprint(alert: &ThresholdAlert) -> u64 {
        let mut hasher = DefaultHasher::new();
        alert.rule_id.hash(&mut hasher);
        alert.metric_id.hash(&mut hasher);
        hasher.finish()
    }

    /// Returns true if the alert is new (not a duplicate).
    pub fn should_fire(&mut self, alert: &ThresholdAlert, now: i64) -> bool {
        let fp = Self::fingerprint(alert);
        if let Some(&last) = self.active.get(&fp) {
            if now - last < self.dedup_window_ms {
                return false;
            }
        }
        self.active.insert(fp, now);
        true
    }

    pub fn expire(&mut self, now: i64) {
        self.active.retain(|_, &mut last| now - last < self.dedup_window_ms);
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}

// ── CorrelationRule ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub id: String,
    pub pattern: Vec<String>,
    pub window_ms: i64,
}

impl CorrelationRule {
    pub fn new(id: impl Into<String>, pattern: Vec<String>, window_ms: i64) -> Self {
        Self {
            id: id.into(),
            pattern,
            window_ms,
        }
    }
}

// ── CorrelatedAlert ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorrelatedAlert {
    pub rule_id: String,
    pub matched_rule_ids: Vec<String>,
    pub detected_at: i64,
}

// ── AlertCorrelator ──────────────────────────────────────────────────

#[derive(Default)]
pub struct AlertCorrelator {
    pub rules: Vec<CorrelationRule>,
    /// (rule_id, timestamp) of recent alerts
    pub recent_alerts: Vec<(String, i64)>,
}

impl AlertCorrelator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    pub fn record_alert(&mut self, rule_id: impl Into<String>, timestamp: i64) {
        self.recent_alerts.push((rule_id.into(), timestamp));
    }

    pub fn check_correlations(&self, now: i64) -> Vec<CorrelatedAlert> {
        let mut results = Vec::new();
        for rule in &self.rules {
            let within_window: Vec<&str> = self
                .recent_alerts
                .iter()
                .filter(|(_, ts)| now - *ts <= rule.window_ms)
                .map(|(id, _)| id.as_str())
                .collect();

            let all_match = rule
                .pattern
                .iter()
                .all(|p| within_window.iter().any(|id| *id == p));

            if all_match {
                let matched: Vec<String> = rule
                    .pattern
                    .iter()
                    .filter(|p| within_window.iter().any(|id2| *id2 == p.as_str()))
                    .cloned()
                    .collect();
                results.push(CorrelatedAlert {
                    rule_id: rule.id.clone(),
                    matched_rule_ids: matched,
                    detected_at: now,
                });
            }
        }
        results
    }

    pub fn expire(&mut self, now: i64, window_ms: i64) {
        self.recent_alerts.retain(|(_, ts)| now - *ts <= window_ms);
    }
}

// ── SuppressionRule ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SuppressionRule {
    pub id: String,
    pub pattern: String,
    pub until: i64,
    pub reason: String,
}

impl SuppressionRule {
    pub fn new(
        id: impl Into<String>,
        pattern: impl Into<String>,
        until: i64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            pattern: pattern.into(),
            until,
            reason: reason.into(),
        }
    }
}

// ── AlertSuppressor ──────────────────────────────────────────────────

#[derive(Default)]
pub struct AlertSuppressor {
    pub rules: Vec<SuppressionRule>,
}

impl AlertSuppressor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: SuppressionRule) {
        self.rules.push(rule);
    }

    pub fn should_suppress(&self, rule_id: &str, now: i64) -> bool {
        self.rules
            .iter()
            .any(|r| r.until > now && (r.pattern == rule_id || r.pattern == "*"))
    }

    pub fn expire(&mut self, now: i64) {
        self.rules.retain(|r| r.until > now);
    }

    pub fn active_count(&self, now: i64) -> usize {
        self.rules.iter().filter(|r| r.until > now).count()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metric::{MonitoringMetric, MonitoringMetricType};

    fn setup() -> (MetricRegistry, ThresholdEngine) {
        let mut r = MetricRegistry::new();
        r.register(MonitoringMetric::new(
            "latency_ms",
            "Latency",
            MonitoringMetricType::Timer,
            "ms",
        ));
        r.register(MonitoringMetric::new(
            "err_rate",
            "Err",
            MonitoringMetricType::Gauge,
            "percent",
        ));
        r.register(MonitoringMetric::new(
            "avail",
            "Avail",
            MonitoringMetricType::Gauge,
            "percent",
        ));
        let eng = ThresholdEngine::new();
        (r, eng)
    }

    #[test]
    fn test_above_fires_and_resolves() {
        let (mut r, mut e) = setup();
        e.add_rule(ThresholdRule::new(
            "lat",
            "Lat",
            "latency_ms",
            ThresholdCondition::Above { value: 100.0 },
            SecuritySeverity::High,
        ));
        r.record("latency_ms", 50.0, 1).unwrap();
        let ev = e.evaluate(&r, 1);
        assert!(ev.is_empty());
        r.record("latency_ms", 500.0, 2).unwrap();
        let ev = e.evaluate(&r, 2);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].status, ThresholdAlertStatus::Firing);
        // second evaluation while still above does NOT re-fire
        let ev = e.evaluate(&r, 3);
        assert!(ev.is_empty());
        // recovery
        r.record("latency_ms", 10.0, 4).unwrap();
        let ev = e.evaluate(&r, 4);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].status, ThresholdAlertStatus::Resolved);
    }

    #[test]
    fn test_below_condition() {
        let (mut r, mut e) = setup();
        e.add_rule(ThresholdRule::new(
            "a",
            "A",
            "avail",
            ThresholdCondition::Below { value: 99.0 },
            SecuritySeverity::Critical,
        ));
        r.record("avail", 95.0, 1).unwrap();
        assert_eq!(e.evaluate(&r, 1).len(), 1);
    }

    #[test]
    fn test_outside_range() {
        let (mut r, mut e) = setup();
        e.add_rule(ThresholdRule::new(
            "e",
            "E",
            "err_rate",
            ThresholdCondition::OutsideRange { lo: 0.0, hi: 1.0 },
            SecuritySeverity::Medium,
        ));
        r.record("err_rate", 0.5, 1).unwrap();
        assert!(e.evaluate(&r, 1).is_empty());
        r.record("err_rate", 5.0, 2).unwrap();
        assert_eq!(e.evaluate(&r, 2).len(), 1);
    }

    #[test]
    fn test_percentile_above() {
        let (mut r, mut e) = setup();
        e.add_rule(ThresholdRule::new(
            "p",
            "P",
            "latency_ms",
            ThresholdCondition::PercentileAbove { percentile: 0.95, value: 200.0 },
            SecuritySeverity::Medium,
        ));
        for v in 1..=100 {
            r.record("latency_ms", v as f64, v as i64).unwrap();
        }
        assert!(e.evaluate(&r, 100).is_empty());
        r.record("latency_ms", 5000.0, 101).unwrap();
        for _ in 0..20 {
            r.record("latency_ms", 5000.0, 102).unwrap();
        }
        let ev = e.evaluate(&r, 102);
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn test_average_above_and_below() {
        let (mut r, mut e) = setup();
        e.add_rule(ThresholdRule::new(
            "aa",
            "avg above",
            "err_rate",
            ThresholdCondition::AverageAbove { value: 1.0 },
            SecuritySeverity::High,
        ));
        e.add_rule(ThresholdRule::new(
            "ab",
            "avg below",
            "avail",
            ThresholdCondition::AverageBelow { value: 99.0 },
            SecuritySeverity::High,
        ));
        r.record("err_rate", 2.0, 1).unwrap();
        r.record("err_rate", 3.0, 2).unwrap();
        r.record("avail", 90.0, 1).unwrap();
        let ev = e.evaluate(&r, 2);
        assert_eq!(ev.len(), 2);
    }

    #[test]
    fn test_rate_above() {
        let (mut r, mut e) = setup();
        let mut reg = r;
        reg.register(MonitoringMetric::new(
            "reqs",
            "Requests",
            MonitoringMetricType::Counter,
            "",
        ));
        e.add_rule(ThresholdRule::new(
            "rr",
            "rate",
            "reqs",
            ThresholdCondition::RateAbove { value: 0.5 },
            SecuritySeverity::Medium,
        ));
        for i in 0..10 {
            reg.record("reqs", 1.0, i).unwrap();
        }
        let ev = e.evaluate(&reg, 10);
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let (mut r, mut e) = setup();
        e.add_rule(
            ThresholdRule::new(
                "x",
                "X",
                "latency_ms",
                ThresholdCondition::Above { value: 0.0 },
                SecuritySeverity::Low,
            )
            .disable(),
        );
        r.record("latency_ms", 99.0, 1).unwrap();
        assert!(e.evaluate(&r, 1).is_empty());
    }

    #[test]
    fn test_remove_rule_clears_firing() {
        let (mut r, mut e) = setup();
        e.add_rule(ThresholdRule::new(
            "x",
            "X",
            "latency_ms",
            ThresholdCondition::Above { value: 10.0 },
            SecuritySeverity::Low,
        ));
        r.record("latency_ms", 100.0, 1).unwrap();
        e.evaluate(&r, 1);
        assert_eq!(e.active_alerts().len(), 1);
        e.remove_rule("x");
        assert_eq!(e.active_alerts().len(), 0);
    }

    #[test]
    fn test_active_alerts_view() {
        let (mut r, mut e) = setup();
        e.add_rule(ThresholdRule::new(
            "x",
            "X",
            "latency_ms",
            ThresholdCondition::Above { value: 10.0 },
            SecuritySeverity::Low,
        ));
        r.record("latency_ms", 100.0, 1).unwrap();
        e.evaluate(&r, 1);
        assert_eq!(e.active_alerts().len(), 1);
    }

    #[test]
    fn test_builtin_templates() {
        let _ = high_error_rate("err_rate", 0.01);
        let r = high_latency("latency_ms", 200.0);
        assert!(matches!(
            r.condition,
            ThresholdCondition::PercentileAbove { .. }
        ));
        let _ = low_availability("avail", 99.9);
        let _ = high_memory("mem", 90.0);
        let _ = queue_depth("queue", 1000.0);
    }

    #[test]
    fn test_condition_display() {
        assert_eq!(
            ThresholdCondition::Above { value: 1.0 }.to_string(),
            "above 1"
        );
        assert_eq!(
            ThresholdCondition::Below { value: 2.0 }.to_string(),
            "below 2"
        );
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_alert_deduplication() {
        let mut dedup = AlertDeduplicator::new(5000);
        let alert = ThresholdAlert {
            rule_id: "lat".into(),
            metric_id: "latency_ms".into(),
            severity: SecuritySeverity::High,
            observed: 500.0,
            condition: "above 100".into(),
            fired_at: 1000,
            status: ThresholdAlertStatus::Firing,
        };
        assert!(dedup.should_fire(&alert, 1000));
        assert!(!dedup.should_fire(&alert, 1001)); // duplicate
        assert!(!dedup.should_fire(&alert, 4999)); // still in window
    }

    #[test]
    fn test_dedup_window_expiry() {
        let mut dedup = AlertDeduplicator::new(1000);
        let alert = ThresholdAlert {
            rule_id: "lat".into(),
            metric_id: "latency_ms".into(),
            severity: SecuritySeverity::High,
            observed: 500.0,
            condition: "above 100".into(),
            fired_at: 1000,
            status: ThresholdAlertStatus::Firing,
        };
        assert!(dedup.should_fire(&alert, 1000));
        assert!(dedup.should_fire(&alert, 2001)); // past window
    }

    #[test]
    fn test_dedup_expire_cleanup() {
        let mut dedup = AlertDeduplicator::new(1000);
        let alert = ThresholdAlert {
            rule_id: "lat".into(),
            metric_id: "latency_ms".into(),
            severity: SecuritySeverity::High,
            observed: 500.0,
            condition: "above 100".into(),
            fired_at: 1000,
            status: ThresholdAlertStatus::Firing,
        };
        dedup.should_fire(&alert, 100);
        assert_eq!(dedup.active_count(), 1);
        dedup.expire(2000);
        assert_eq!(dedup.active_count(), 0);
    }

    #[test]
    fn test_alert_correlation() {
        let mut correlator = AlertCorrelator::new();
        correlator.add_rule(CorrelationRule::new(
            "db_cascade",
            vec!["db_down".into(), "app_error".into()],
            5000,
        ));
        correlator.record_alert("db_down", 1000);
        correlator.record_alert("app_error", 1500);
        let correlated = correlator.check_correlations(2000);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].rule_id, "db_cascade");
        assert_eq!(correlated[0].matched_rule_ids.len(), 2);
    }

    #[test]
    fn test_alert_correlation_no_match() {
        let mut correlator = AlertCorrelator::new();
        correlator.add_rule(CorrelationRule::new(
            "db_cascade",
            vec!["db_down".into(), "app_error".into()],
            5000,
        ));
        correlator.record_alert("db_down", 1000);
        // app_error not recorded → no correlation
        let correlated = correlator.check_correlations(2000);
        assert!(correlated.is_empty());
    }

    #[test]
    fn test_alert_suppression() {
        let mut suppressor = AlertSuppressor::new();
        suppressor.add_rule(SuppressionRule::new("deploy_maint", "lat", 5000, "deploy in progress"));
        assert!(suppressor.should_suppress("lat", 1000));
        assert!(!suppressor.should_suppress("lat", 6000));
        assert!(!suppressor.should_suppress("other_rule", 1000));
    }

    #[test]
    fn test_suppression_wildcard() {
        let mut suppressor = AlertSuppressor::new();
        suppressor.add_rule(SuppressionRule::new("maint", "*", 5000, "maintenance"));
        assert!(suppressor.should_suppress("any_rule", 1000));
        assert!(suppressor.should_suppress("another_rule", 1000));
    }

    #[test]
    fn test_suppression_expire() {
        let mut suppressor = AlertSuppressor::new();
        suppressor.add_rule(SuppressionRule::new("s1", "lat", 100, "test"));
        assert_eq!(suppressor.active_count(50), 1);
        suppressor.expire(200);
        assert_eq!(suppressor.rules.len(), 0);
    }
}
