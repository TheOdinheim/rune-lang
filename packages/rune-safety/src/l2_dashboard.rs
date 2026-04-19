// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Safety metrics dashboard.
//
// Aggregated safety metrics for dashboard visualization and trend
// analysis, with a weighted composite safety score.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::l2_boundary::L2BoundaryStore;
use crate::l2_incident::SafetyIncidentTracker;

// ── SafetyMetrics ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SafetyMetrics {
    pub total_boundary_checks: u64,
    pub total_violations: u64,
    pub violation_rate: f64,
    pub mean_confidence: f64,
    pub incidents_open: usize,
    pub incidents_resolved: usize,
    pub constraint_pass_rate: f64,
    pub test_pass_rate: f64,
    pub last_computed_at: i64,
}

// ── SafetyTrend ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyTrend {
    Improving,
    Stable,
    Declining,
    InsufficientData,
}

impl fmt::Display for SafetyTrend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Improving => "Improving",
            Self::Stable => "Stable",
            Self::Declining => "Declining",
            Self::InsufficientData => "InsufficientData",
        };
        f.write_str(s)
    }
}

// ── SafetyDashboard ───────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SafetyDashboard {
    pub boundary_store: L2BoundaryStore,
    pub incident_tracker: SafetyIncidentTracker,
    pub metrics_history: Vec<SafetyMetrics>,
    total_checks: u64,
    total_violations: u64,
    confidence_sum: f64,
    confidence_count: u64,
}

impl SafetyDashboard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_check(&mut self, passed: bool, confidence: f64) {
        self.total_checks += 1;
        if !passed {
            self.total_violations += 1;
        }
        self.confidence_sum += confidence;
        self.confidence_count += 1;
    }

    pub fn compute_metrics(
        &mut self,
        constraint_pass_rate: f64,
        test_pass_rate: f64,
        now: i64,
    ) -> SafetyMetrics {
        let violation_rate = if self.total_checks == 0 {
            0.0
        } else {
            self.total_violations as f64 / self.total_checks as f64
        };

        let mean_confidence = if self.confidence_count == 0 {
            0.0
        } else {
            self.confidence_sum / self.confidence_count as f64
        };

        let incidents_open = self.incident_tracker.open_incidents().len();
        let incidents_resolved = self.incident_tracker.incident_count() - incidents_open;

        let metrics = SafetyMetrics {
            total_boundary_checks: self.total_checks,
            total_violations: self.total_violations,
            violation_rate,
            mean_confidence,
            incidents_open,
            incidents_resolved,
            constraint_pass_rate,
            test_pass_rate,
            last_computed_at: now,
        };

        self.metrics_history.push(metrics.clone());
        metrics
    }

    pub fn latest_metrics(&self) -> Option<&SafetyMetrics> {
        self.metrics_history.last()
    }

    pub fn safety_score(&self) -> f64 {
        let metrics = match self.latest_metrics() {
            Some(m) => m,
            None => return 0.0,
        };

        let total_incidents = metrics.incidents_open + metrics.incidents_resolved;
        let open_incident_ratio = if total_incidents == 0 {
            0.0
        } else {
            metrics.incidents_open as f64 / total_incidents as f64
        };

        (1.0 - metrics.violation_rate) * 0.3
            + metrics.constraint_pass_rate * 0.3
            + metrics.test_pass_rate * 0.2
            + (1.0 - open_incident_ratio) * 0.2
    }

    pub fn safety_trend(&self) -> SafetyTrend {
        if self.metrics_history.len() < 2 {
            return SafetyTrend::InsufficientData;
        }

        let len = self.metrics_history.len();
        let mid = len / 2;

        let older_avg: f64 = self.metrics_history[..mid]
            .iter()
            .map(|m| 1.0 - m.violation_rate)
            .sum::<f64>()
            / mid as f64;

        let newer_avg: f64 = self.metrics_history[mid..]
            .iter()
            .map(|m| 1.0 - m.violation_rate)
            .sum::<f64>()
            / (len - mid) as f64;

        let diff = newer_avg - older_avg;
        if diff > 0.05 {
            SafetyTrend::Improving
        } else if diff < -0.05 {
            SafetyTrend::Declining
        } else {
            SafetyTrend::Stable
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_record_check_tracks_totals() {
        let mut dashboard = SafetyDashboard::new();
        dashboard.record_check(true, 0.9);
        dashboard.record_check(false, 0.3);
        dashboard.record_check(true, 0.8);
        assert_eq!(dashboard.total_checks, 3);
        assert_eq!(dashboard.total_violations, 1);
    }

    #[test]
    fn test_dashboard_compute_metrics_produces_metrics() {
        let mut dashboard = SafetyDashboard::new();
        dashboard.record_check(true, 0.9);
        dashboard.record_check(false, 0.5);
        let metrics = dashboard.compute_metrics(0.8, 0.9, 1000);
        assert!((metrics.violation_rate - 0.5).abs() < f64::EPSILON);
        assert!((metrics.mean_confidence - 0.7).abs() < f64::EPSILON);
        assert_eq!(metrics.constraint_pass_rate, 0.8);
        assert_eq!(metrics.test_pass_rate, 0.9);
    }

    #[test]
    fn test_dashboard_safety_score_weighted() {
        let mut dashboard = SafetyDashboard::new();
        // No violations, perfect scores, no incidents
        dashboard.record_check(true, 0.9);
        dashboard.compute_metrics(1.0, 1.0, 1000);
        let score = dashboard.safety_score();
        // (1-0)*0.3 + 1.0*0.3 + 1.0*0.2 + (1-0)*0.2 = 0.3 + 0.3 + 0.2 + 0.2 = 1.0
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dashboard_safety_trend_improving() {
        let mut dashboard = SafetyDashboard::new();
        // Record worse metrics first
        dashboard.total_violations = 8;
        dashboard.total_checks = 10;
        dashboard.compute_metrics(0.5, 0.5, 1000);
        // Reset for better metrics
        dashboard.total_violations = 1;
        dashboard.total_checks = 10;
        dashboard.compute_metrics(0.9, 0.9, 2000);

        assert_eq!(dashboard.safety_trend(), SafetyTrend::Improving);
    }

    #[test]
    fn test_dashboard_safety_trend_declining() {
        let mut dashboard = SafetyDashboard::new();
        // Record better metrics first
        dashboard.total_violations = 0;
        dashboard.total_checks = 10;
        dashboard.compute_metrics(0.9, 0.9, 1000);
        // Worse metrics
        dashboard.total_violations = 9;
        dashboard.total_checks = 10;
        dashboard.compute_metrics(0.5, 0.5, 2000);

        assert_eq!(dashboard.safety_trend(), SafetyTrend::Declining);
    }

    #[test]
    fn test_dashboard_latest_metrics_returns_most_recent() {
        let mut dashboard = SafetyDashboard::new();
        dashboard.record_check(true, 0.9);
        dashboard.compute_metrics(0.8, 0.7, 1000);
        dashboard.compute_metrics(0.9, 0.95, 2000);
        let latest = dashboard.latest_metrics().unwrap();
        assert_eq!(latest.last_computed_at, 2000);
        assert_eq!(latest.constraint_pass_rate, 0.9);
    }
}
