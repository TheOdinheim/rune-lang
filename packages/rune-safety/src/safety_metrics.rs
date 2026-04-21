// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — SafetyMetricsCollector trait for computing operational
// safety metrics: envelope compliance rate, mean time to safe state,
// violation frequency, safety case coverage. All computed values are
// String for Eq derivation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::backend::{StoredBoundaryViolationRecord, StoredShutdownRecord};
use crate::error::SafetyError;

// ── SafetyMetricSnapshot ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyMetricSnapshot {
    pub snapshot_id: String,
    pub system_id: String,
    pub computed_at: i64,
    pub envelope_compliance_rate: String,
    pub mean_time_to_safe_state: String,
    pub violation_count: String,
    pub safety_case_coverage: String,
    pub metadata: HashMap<String, String>,
}

// ── SafetyMetricsCollector trait ────────────────────────────────────

pub trait SafetyMetricsCollector {
    fn compute_envelope_compliance_rate(
        &self,
        system_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, SafetyError>;

    fn compute_mean_time_to_safe_state(
        &self,
        system_id: &str,
    ) -> Result<String, SafetyError>;

    fn compute_violation_frequency(
        &self,
        system_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, SafetyError>;

    fn list_most_violated_constraints(
        &self,
        system_id: &str,
        limit: usize,
    ) -> Vec<(String, usize)>;

    fn compute_safety_case_coverage(
        &self,
        system_id: &str,
    ) -> Result<String, SafetyError>;

    fn collector_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemorySafetyMetricsCollector ──────────────────────────────────

pub struct InMemorySafetyMetricsCollector {
    id: String,
    violations: Vec<StoredBoundaryViolationRecord>,
    shutdowns: Vec<StoredShutdownRecord>,
    case_hazard_counts: HashMap<String, (usize, usize)>, // system -> (covered, total)
}

impl InMemorySafetyMetricsCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            violations: Vec::new(),
            shutdowns: Vec::new(),
            case_hazard_counts: HashMap::new(),
        }
    }

    pub fn add_violation(&mut self, v: StoredBoundaryViolationRecord) {
        self.violations.push(v);
    }

    pub fn add_shutdown(&mut self, s: StoredShutdownRecord) {
        self.shutdowns.push(s);
    }

    pub fn set_case_coverage(
        &mut self,
        system_id: impl Into<String>,
        covered_hazards: usize,
        total_hazards: usize,
    ) {
        self.case_hazard_counts
            .insert(system_id.into(), (covered_hazards, total_hazards));
    }
}

impl SafetyMetricsCollector for InMemorySafetyMetricsCollector {
    fn compute_envelope_compliance_rate(
        &self,
        system_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, SafetyError> {
        let window_duration = window_end - window_start;
        if window_duration <= 0 {
            return Err(SafetyError::InvalidConfiguration(
                "window_end must be after window_start".into(),
            ));
        }
        let violation_time: i64 = self
            .violations
            .iter()
            .filter(|v| v.system_id == system_id && v.detected_at >= window_start && v.detected_at <= window_end)
            .map(|v| {
                let resolve = v.resolved_at.unwrap_or(window_end);
                let end = i64::min(resolve, window_end);
                let start = i64::max(v.detected_at, window_start);
                i64::max(end - start, 0)
            })
            .sum();
        let compliant_time = window_duration - violation_time;
        let rate = compliant_time as f64 / window_duration as f64;
        Ok(format!("{:.4}", rate))
    }

    fn compute_mean_time_to_safe_state(
        &self,
        system_id: &str,
    ) -> Result<String, SafetyError> {
        let resolved: Vec<i64> = self
            .violations
            .iter()
            .filter(|v| v.system_id == system_id && v.resolved_at.is_some())
            .map(|v| v.resolved_at.unwrap() - v.detected_at)
            .collect();
        if resolved.is_empty() {
            return Ok("0".into());
        }
        let mean = resolved.iter().sum::<i64>() as f64 / resolved.len() as f64;
        Ok(format!("{:.2}", mean))
    }

    fn compute_violation_frequency(
        &self,
        system_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, SafetyError> {
        let count = self
            .violations
            .iter()
            .filter(|v| {
                v.system_id == system_id
                    && v.detected_at >= window_start
                    && v.detected_at <= window_end
            })
            .count();
        Ok(count.to_string())
    }

    fn list_most_violated_constraints(
        &self,
        system_id: &str,
        limit: usize,
    ) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for v in &self.violations {
            if v.system_id == system_id {
                *counts
                    .entry(v.constraint_ref_violated.clone())
                    .or_default() += 1;
            }
        }
        let mut pairs: Vec<(String, usize)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(limit);
        pairs
    }

    fn compute_safety_case_coverage(
        &self,
        system_id: &str,
    ) -> Result<String, SafetyError> {
        match self.case_hazard_counts.get(system_id) {
            Some((covered, total)) if *total > 0 => {
                let rate = *covered as f64 / *total as f64;
                Ok(format!("{:.4}", rate))
            }
            _ => Ok("0.0000".into()),
        }
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── NullSafetyMetricsCollector ──────────────────────────────────────

pub struct NullSafetyMetricsCollector;

impl SafetyMetricsCollector for NullSafetyMetricsCollector {
    fn compute_envelope_compliance_rate(
        &self,
        _system_id: &str,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, SafetyError> {
        Ok("1.0000".into())
    }

    fn compute_mean_time_to_safe_state(
        &self,
        _system_id: &str,
    ) -> Result<String, SafetyError> {
        Ok("0".into())
    }

    fn compute_violation_frequency(
        &self,
        _system_id: &str,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, SafetyError> {
        Ok("0".into())
    }

    fn list_most_violated_constraints(
        &self,
        _system_id: &str,
        _limit: usize,
    ) -> Vec<(String, usize)> {
        Vec::new()
    }

    fn compute_safety_case_coverage(
        &self,
        _system_id: &str,
    ) -> Result<String, SafetyError> {
        Ok("0.0000".into())
    }

    fn collector_id(&self) -> &str {
        "null-metrics-collector"
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn violation(
        system: &str,
        constraint: &str,
        detected: i64,
        resolved: Option<i64>,
    ) -> StoredBoundaryViolationRecord {
        StoredBoundaryViolationRecord {
            violation_id: format!("v-{detected}"),
            envelope_id: "env-1".into(),
            system_id: system.into(),
            constraint_ref_violated: constraint.into(),
            violation_description: "test".into(),
            detected_at: detected,
            severity_at_detection: "Critical".into(),
            response_taken: "degraded".into(),
            resolved_at: resolved,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_envelope_compliance_rate() {
        let mut c = InMemorySafetyMetricsCollector::new("m1");
        // Violation from t=200 to t=400 in a window of 0-1000 => 200ms violation, 80% compliant
        c.add_violation(violation("sys-1", "c-1", 200, Some(400)));
        let rate = c
            .compute_envelope_compliance_rate("sys-1", 0, 1000)
            .unwrap();
        assert_eq!(rate, "0.8000");
    }

    #[test]
    fn test_compliance_rate_no_violations() {
        let c = InMemorySafetyMetricsCollector::new("m1");
        let rate = c
            .compute_envelope_compliance_rate("sys-1", 0, 1000)
            .unwrap();
        assert_eq!(rate, "1.0000");
    }

    #[test]
    fn test_mean_time_to_safe_state() {
        let mut c = InMemorySafetyMetricsCollector::new("m1");
        c.add_violation(violation("sys-1", "c-1", 100, Some(200))); // 100ms
        c.add_violation(violation("sys-1", "c-1", 300, Some(500))); // 200ms
        let mean = c.compute_mean_time_to_safe_state("sys-1").unwrap();
        assert_eq!(mean, "150.00"); // (100+200)/2
    }

    #[test]
    fn test_violation_frequency() {
        let mut c = InMemorySafetyMetricsCollector::new("m1");
        c.add_violation(violation("sys-1", "c-1", 100, Some(200)));
        c.add_violation(violation("sys-1", "c-2", 300, Some(400)));
        c.add_violation(violation("sys-1", "c-1", 600, None));
        let freq = c
            .compute_violation_frequency("sys-1", 0, 1000)
            .unwrap();
        assert_eq!(freq, "3");
    }

    #[test]
    fn test_most_violated_constraints() {
        let mut c = InMemorySafetyMetricsCollector::new("m1");
        c.add_violation(violation("sys-1", "c-1", 100, Some(200)));
        c.add_violation(violation("sys-1", "c-1", 200, Some(300)));
        c.add_violation(violation("sys-1", "c-2", 300, Some(400)));
        let top = c.list_most_violated_constraints("sys-1", 2);
        assert_eq!(top[0].0, "c-1");
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_safety_case_coverage() {
        let mut c = InMemorySafetyMetricsCollector::new("m1");
        c.set_case_coverage("sys-1", 3, 4);
        let cov = c.compute_safety_case_coverage("sys-1").unwrap();
        assert_eq!(cov, "0.7500");
    }

    #[test]
    fn test_safety_case_coverage_no_data() {
        let c = InMemorySafetyMetricsCollector::new("m1");
        let cov = c.compute_safety_case_coverage("sys-1").unwrap();
        assert_eq!(cov, "0.0000");
    }

    #[test]
    fn test_null_collector() {
        let c = NullSafetyMetricsCollector;
        assert!(!c.is_active());
        assert_eq!(
            c.compute_envelope_compliance_rate("s", 0, 1000).unwrap(),
            "1.0000"
        );
        assert_eq!(c.compute_mean_time_to_safe_state("s").unwrap(), "0");
        assert_eq!(
            c.compute_violation_frequency("s", 0, 1000).unwrap(),
            "0"
        );
        assert!(c.list_most_violated_constraints("s", 5).is_empty());
    }

    #[test]
    fn test_collector_id() {
        let c = InMemorySafetyMetricsCollector::new("my-metrics");
        assert_eq!(c.collector_id(), "my-metrics");
        assert!(c.is_active());
    }

    #[test]
    fn test_snapshot_eq() {
        let s = SafetyMetricSnapshot {
            snapshot_id: "snap-1".into(),
            system_id: "sys-1".into(),
            computed_at: 5000,
            envelope_compliance_rate: "0.9500".into(),
            mean_time_to_safe_state: "150.00".into(),
            violation_count: "3".into(),
            safety_case_coverage: "0.7500".into(),
            metadata: HashMap::new(),
        };
        assert_eq!(s, s.clone());
    }

    #[test]
    fn test_invalid_window() {
        let c = InMemorySafetyMetricsCollector::new("m1");
        assert!(c
            .compute_envelope_compliance_rate("s", 1000, 500)
            .is_err());
    }
}
