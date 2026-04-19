// ═══════════════════════════════════════════════════════════════════════
// Security Metrics — MTTD, MTTR, vulnerability age, detection coverage
//
// Time-series metric store with trend analysis and a dashboard that
// aggregates posture, incidents, vulnerabilities, and metrics.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::posture::{PostureGrade, SecurityPosture};
use crate::severity::SecuritySeverity;

// ── MetricType ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Timer,
    Rate,
}

impl fmt::Display for MetricType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SecurityMetric ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecurityMetric {
    pub id: String,
    pub name: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub unit: String,
    pub measured_at: i64,
    pub source: String,
    pub tags: HashMap<String, String>,
}

impl SecurityMetric {
    fn new_metric(
        id: &str,
        name: &str,
        metric_type: MetricType,
        value: f64,
        unit: &str,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            metric_type,
            value,
            unit: unit.into(),
            measured_at: 0,
            source: "rune-security".into(),
            tags: HashMap::new(),
        }
    }

    pub fn mttd(value_hours: f64) -> Self {
        Self::new_metric("mttd", "Mean Time to Detect", MetricType::Timer, value_hours, "hours")
    }

    pub fn mttr(value_hours: f64) -> Self {
        Self::new_metric(
            "mttr",
            "Mean Time to Respond",
            MetricType::Timer,
            value_hours,
            "hours",
        )
    }

    pub fn mttc(value_hours: f64) -> Self {
        Self::new_metric(
            "mttc",
            "Mean Time to Contain",
            MetricType::Timer,
            value_hours,
            "hours",
        )
    }

    pub fn vulnerability_age(days: f64) -> Self {
        Self::new_metric(
            "vuln_age_days",
            "Average Unpatched Vulnerability Age",
            MetricType::Gauge,
            days,
            "days",
        )
    }

    pub fn patch_coverage(percentage: f64) -> Self {
        Self::new_metric(
            "patch_coverage",
            "Patch Coverage",
            MetricType::Gauge,
            percentage,
            "percent",
        )
    }

    pub fn incident_rate(per_month: f64) -> Self {
        Self::new_metric(
            "incident_rate",
            "Incident Rate",
            MetricType::Rate,
            per_month,
            "per_month",
        )
    }

    pub fn false_positive_rate(percentage: f64) -> Self {
        Self::new_metric(
            "fpr",
            "False Positive Rate",
            MetricType::Gauge,
            percentage,
            "percent",
        )
    }

    pub fn detection_coverage(percentage: f64) -> Self {
        Self::new_metric(
            "detection_coverage",
            "Detection Coverage",
            MetricType::Gauge,
            percentage,
            "percent",
        )
    }
}

// ── MetricTrend ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricTrend {
    Improving,
    Stable,
    Degrading,
    InsufficientData,
}

impl fmt::Display for MetricTrend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── MetricStore ───────────────────────────────────────────────────────

#[derive(Default)]
pub struct MetricStore {
    pub metrics: HashMap<String, Vec<SecurityMetric>>,
}

impl MetricStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, metric: SecurityMetric) {
        self.metrics.entry(metric.id.clone()).or_default().push(metric);
    }

    pub fn latest(&self, id: &str) -> Option<&SecurityMetric> {
        self.metrics.get(id).and_then(|v| v.last())
    }

    pub fn history(&self, id: &str) -> Vec<&SecurityMetric> {
        self.metrics.get(id).map(|v| v.iter().collect()).unwrap_or_default()
    }

    pub fn history_since(&self, id: &str, since: i64) -> Vec<&SecurityMetric> {
        self.metrics
            .get(id)
            .map(|v| v.iter().filter(|m| m.measured_at >= since).collect())
            .unwrap_or_default()
    }

    pub fn average(&self, id: &str) -> Option<f64> {
        let history = self.history(id);
        if history.is_empty() {
            None
        } else {
            Some(history.iter().map(|m| m.value).sum::<f64>() / history.len() as f64)
        }
    }

    pub fn max(&self, id: &str) -> Option<f64> {
        self.history(id).iter().map(|m| m.value).fold(None, |acc, v| {
            Some(match acc {
                None => v,
                Some(a) => a.max(v),
            })
        })
    }

    pub fn min(&self, id: &str) -> Option<f64> {
        self.history(id).iter().map(|m| m.value).fold(None, |acc, v| {
            Some(match acc {
                None => v,
                Some(a) => a.min(v),
            })
        })
    }

    /// Compare the first half of history with the second half. For
    /// "lower is better" metrics (mttd, mttr, vuln_age), a decreasing
    /// value is Improving. For "higher is better" (patch_coverage,
    /// detection_coverage), an increasing value is Improving.
    pub fn trend(&self, id: &str) -> MetricTrend {
        let history = self.history(id);
        if history.len() < 4 {
            return MetricTrend::InsufficientData;
        }
        let mid = history.len() / 2;
        let first_avg: f64 =
            history[..mid].iter().map(|m| m.value).sum::<f64>() / mid as f64;
        let second_avg: f64 =
            history[mid..].iter().map(|m| m.value).sum::<f64>()
                / (history.len() - mid) as f64;
        let higher_is_better = matches!(
            id,
            "patch_coverage" | "detection_coverage"
        );
        let delta = second_avg - first_avg;
        let threshold = first_avg.abs() * 0.05; // 5% change threshold
        if delta.abs() < threshold {
            MetricTrend::Stable
        } else if (delta > 0.0) == higher_is_better {
            MetricTrend::Improving
        } else {
            MetricTrend::Degrading
        }
    }
}

// ── SecurityDashboard ─────────────────────────────────────────────────

#[derive(Default)]
pub struct SecurityDashboard {
    pub metrics: MetricStore,
    pub posture: Option<SecurityPosture>,
    pub active_incidents: usize,
    pub critical_vulnerabilities: usize,
}

impl SecurityDashboard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn summary(&self) -> DashboardSummary {
        let mttd_hours = self.metrics.latest("mttd").map(|m| m.value);
        let mttr_hours = self.metrics.latest("mttr").map(|m| m.value);

        let mut overall = SecuritySeverity::Info;
        if self.critical_vulnerabilities > 0 {
            overall = SecuritySeverity::Critical;
        }
        if self.active_incidents > 5 {
            overall = overall.max(SecuritySeverity::High);
        } else if self.active_incidents > 0 {
            overall = overall.max(SecuritySeverity::Medium);
        }
        if let Some(p) = &self.posture {
            if p.grade <= PostureGrade::D {
                overall = overall.max(SecuritySeverity::High);
            } else if p.grade == PostureGrade::C {
                overall = overall.max(SecuritySeverity::Medium);
            }
        }

        DashboardSummary {
            posture_grade: self.posture.as_ref().map(|p| p.grade),
            posture_score: self.posture.as_ref().map(|p| p.score),
            active_incidents: self.active_incidents,
            critical_vulns: self.critical_vulnerabilities,
            mttd_hours,
            mttr_hours,
            overall_status: overall,
        }
    }
}

// ── DashboardSummary ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DashboardSummary {
    pub posture_grade: Option<PostureGrade>,
    pub posture_score: Option<f64>,
    pub active_incidents: usize,
    pub critical_vulns: usize,
    pub mttd_hours: Option<f64>,
    pub mttr_hours: Option<f64>,
    pub overall_status: SecuritySeverity,
}

impl fmt::Display for DashboardSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let grade = self
            .posture_grade
            .map(|g| g.to_string())
            .unwrap_or_else(|| "?".into());
        let score = self
            .posture_score
            .map(|s| format!("{s:.1}"))
            .unwrap_or_else(|| "?".into());
        write!(
            f,
            "posture={grade}({score}) incidents={} critical_vulns={} status={}",
            self.active_incidents, self.critical_vulns, self.overall_status
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — MTTD/MTTR Tracking, SLA Compliance, Metric Aggregation
// ═══════════════════════════════════════════════════════════════════════

/// Tracks detection and response times, plus incident counts.
#[derive(Debug, Clone, Default)]
pub struct SecurityMetricsTracker {
    pub detection_times_ms: Vec<i64>,
    pub response_times_ms: Vec<i64>,
    pub incidents_by_severity: HashMap<String, u64>,
    pub total_incidents: u64,
}

impl SecurityMetricsTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_detection(&mut self, detection_time_ms: i64) {
        self.detection_times_ms.push(detection_time_ms);
    }

    pub fn record_response(&mut self, response_time_ms: i64) {
        self.response_times_ms.push(response_time_ms);
    }

    pub fn record_incident(&mut self, severity: &SecuritySeverity) {
        *self
            .incidents_by_severity
            .entry(severity.to_string())
            .or_insert(0) += 1;
        self.total_incidents += 1;
    }

    pub fn mttd_ms(&self) -> Option<f64> {
        if self.detection_times_ms.is_empty() {
            None
        } else {
            Some(
                self.detection_times_ms.iter().sum::<i64>() as f64
                    / self.detection_times_ms.len() as f64,
            )
        }
    }

    pub fn mttr_ms(&self) -> Option<f64> {
        if self.response_times_ms.is_empty() {
            None
        } else {
            Some(
                self.response_times_ms.iter().sum::<i64>() as f64
                    / self.response_times_ms.len() as f64,
            )
        }
    }

    pub fn p95_detection_ms(&self) -> Option<i64> {
        Self::percentile_95(&self.detection_times_ms)
    }

    pub fn p95_response_ms(&self) -> Option<i64> {
        Self::percentile_95(&self.response_times_ms)
    }

    fn percentile_95(values: &[i64]) -> Option<i64> {
        if values.is_empty() {
            return None;
        }
        let mut sorted = values.to_vec();
        sorted.sort();
        let index = ((sorted.len() as f64 * 0.95).ceil() as usize).min(sorted.len()) - 1;
        Some(sorted[index])
    }
}

/// SLA definition for security operations.
#[derive(Debug, Clone)]
pub struct SecuritySla {
    pub max_detection_ms: i64,
    pub max_response_ms: i64,
    pub max_open_critical_incidents: u64,
}

/// Result of an SLA compliance check.
#[derive(Debug, Clone)]
pub struct SlaComplianceResult {
    pub compliant: bool,
    pub detection_compliant: bool,
    pub response_compliant: bool,
    pub violations: Vec<String>,
}

impl SecuritySla {
    pub fn check_compliance(&self, tracker: &SecurityMetricsTracker) -> SlaComplianceResult {
        let mut violations = Vec::new();

        let detection_compliant = match tracker.mttd_ms() {
            Some(mttd) => {
                if mttd > self.max_detection_ms as f64 {
                    violations.push(format!(
                        "MTTD {:.0}ms exceeds SLA {}ms",
                        mttd, self.max_detection_ms
                    ));
                    false
                } else {
                    true
                }
            }
            None => true,
        };

        let response_compliant = match tracker.mttr_ms() {
            Some(mttr) => {
                if mttr > self.max_response_ms as f64 {
                    violations.push(format!(
                        "MTTR {:.0}ms exceeds SLA {}ms",
                        mttr, self.max_response_ms
                    ));
                    false
                } else {
                    true
                }
            }
            None => true,
        };

        let critical_count = tracker
            .incidents_by_severity
            .get("Critical")
            .copied()
            .unwrap_or(0);
        if critical_count > self.max_open_critical_incidents {
            violations.push(format!(
                "{} critical incidents exceeds SLA max {}",
                critical_count, self.max_open_critical_incidents
            ));
        }

        let compliant = detection_compliant
            && response_compliant
            && critical_count <= self.max_open_critical_incidents;

        SlaComplianceResult {
            compliant,
            detection_compliant,
            response_compliant,
            violations,
        }
    }
}

/// Merge multiple trackers into one combined view.
pub fn aggregate_metrics(trackers: &[&SecurityMetricsTracker]) -> SecurityMetricsTracker {
    let mut combined = SecurityMetricsTracker::new();
    for tracker in trackers {
        combined
            .detection_times_ms
            .extend_from_slice(&tracker.detection_times_ms);
        combined
            .response_times_ms
            .extend_from_slice(&tracker.response_times_ms);
        for (sev, count) in &tracker.incidents_by_severity {
            *combined
                .incidents_by_severity
                .entry(sev.clone())
                .or_insert(0) += count;
        }
        combined.total_incidents += tracker.total_incidents;
    }
    combined
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_latest() {
        let mut store = MetricStore::new();
        store.record(SecurityMetric::mttd(3.0));
        store.record(SecurityMetric::mttd(2.0));
        assert_eq!(store.latest("mttd").unwrap().value, 2.0);
    }

    #[test]
    fn test_history_returns_all() {
        let mut store = MetricStore::new();
        store.record(SecurityMetric::mttd(3.0));
        store.record(SecurityMetric::mttd(2.0));
        store.record(SecurityMetric::mttd(1.0));
        assert_eq!(store.history("mttd").len(), 3);
    }

    #[test]
    fn test_average() {
        let mut store = MetricStore::new();
        store.record(SecurityMetric::mttd(1.0));
        store.record(SecurityMetric::mttd(2.0));
        store.record(SecurityMetric::mttd(3.0));
        assert_eq!(store.average("mttd"), Some(2.0));
    }

    #[test]
    fn test_max_and_min() {
        let mut store = MetricStore::new();
        store.record(SecurityMetric::mttd(1.0));
        store.record(SecurityMetric::mttd(5.0));
        store.record(SecurityMetric::mttd(3.0));
        assert_eq!(store.max("mttd"), Some(5.0));
        assert_eq!(store.min("mttd"), Some(1.0));
    }

    #[test]
    fn test_trend_improving_for_lower_is_better() {
        let mut store = MetricStore::new();
        // mttd improving means decreasing
        store.record(SecurityMetric::mttd(10.0));
        store.record(SecurityMetric::mttd(9.0));
        store.record(SecurityMetric::mttd(3.0));
        store.record(SecurityMetric::mttd(2.0));
        assert_eq!(store.trend("mttd"), MetricTrend::Improving);
    }

    #[test]
    fn test_trend_improving_for_higher_is_better() {
        let mut store = MetricStore::new();
        store.record(SecurityMetric::patch_coverage(50.0));
        store.record(SecurityMetric::patch_coverage(55.0));
        store.record(SecurityMetric::patch_coverage(85.0));
        store.record(SecurityMetric::patch_coverage(90.0));
        assert_eq!(store.trend("patch_coverage"), MetricTrend::Improving);
    }

    #[test]
    fn test_trend_insufficient_data() {
        let mut store = MetricStore::new();
        store.record(SecurityMetric::mttd(1.0));
        store.record(SecurityMetric::mttd(2.0));
        assert_eq!(store.trend("mttd"), MetricTrend::InsufficientData);
    }

    #[test]
    fn test_mttd_constructor() {
        let m = SecurityMetric::mttd(5.0);
        assert_eq!(m.id, "mttd");
        assert_eq!(m.value, 5.0);
        assert_eq!(m.unit, "hours");
    }

    #[test]
    fn test_mttr_constructor() {
        let m = SecurityMetric::mttr(12.0);
        assert_eq!(m.id, "mttr");
        assert_eq!(m.metric_type, MetricType::Timer);
    }

    #[test]
    fn test_dashboard_summary() {
        let mut dash = SecurityDashboard::new();
        dash.active_incidents = 3;
        dash.critical_vulnerabilities = 0;
        dash.metrics.record(SecurityMetric::mttd(4.0));
        dash.metrics.record(SecurityMetric::mttr(10.0));
        let summary = dash.summary();
        assert_eq!(summary.active_incidents, 3);
        assert_eq!(summary.mttd_hours, Some(4.0));
        assert_eq!(summary.overall_status, SecuritySeverity::Medium);
    }

    #[test]
    fn test_dashboard_summary_display() {
        let mut dash = SecurityDashboard::new();
        dash.active_incidents = 1;
        let s = dash.summary().to_string();
        assert!(s.contains("incidents=1"));
    }

    #[test]
    fn test_dashboard_critical_escalates_status() {
        let mut dash = SecurityDashboard::new();
        dash.critical_vulnerabilities = 5;
        assert_eq!(dash.summary().overall_status, SecuritySeverity::Critical);
    }

    #[test]
    fn test_history_since_filter() {
        let mut store = MetricStore::new();
        let mut m1 = SecurityMetric::mttd(1.0);
        m1.measured_at = 1000;
        let mut m2 = SecurityMetric::mttd(2.0);
        m2.measured_at = 2000;
        store.record(m1);
        store.record(m2);
        assert_eq!(store.history_since("mttd", 1500).len(), 1);
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_metrics_tracker_mttd() {
        let mut tracker = SecurityMetricsTracker::new();
        tracker.record_detection(100);
        tracker.record_detection(200);
        tracker.record_detection(300);
        assert_eq!(tracker.mttd_ms(), Some(200.0));
    }

    #[test]
    fn test_metrics_tracker_mttr() {
        let mut tracker = SecurityMetricsTracker::new();
        tracker.record_response(500);
        tracker.record_response(1000);
        assert_eq!(tracker.mttr_ms(), Some(750.0));
    }

    #[test]
    fn test_metrics_tracker_p95() {
        let mut tracker = SecurityMetricsTracker::new();
        for i in 1..=100 {
            tracker.record_detection(i * 10);
        }
        let p95 = tracker.p95_detection_ms().unwrap();
        // 95th percentile of [10,20,...,1000] = 950
        assert_eq!(p95, 950);
    }

    #[test]
    fn test_sla_compliance_passes() {
        let sla = SecuritySla {
            max_detection_ms: 1000,
            max_response_ms: 5000,
            max_open_critical_incidents: 3,
        };
        let mut tracker = SecurityMetricsTracker::new();
        tracker.record_detection(500);
        tracker.record_response(3000);
        let result = sla.check_compliance(&tracker);
        assert!(result.compliant);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_sla_compliance_fails() {
        let sla = SecuritySla {
            max_detection_ms: 100,
            max_response_ms: 200,
            max_open_critical_incidents: 0,
        };
        let mut tracker = SecurityMetricsTracker::new();
        tracker.record_detection(500);
        tracker.record_response(1000);
        tracker.record_incident(&SecuritySeverity::Critical);
        let result = sla.check_compliance(&tracker);
        assert!(!result.compliant);
        assert!(!result.detection_compliant);
        assert!(!result.response_compliant);
        assert_eq!(result.violations.len(), 3);
    }

    #[test]
    fn test_aggregate_metrics_combines() {
        let mut t1 = SecurityMetricsTracker::new();
        t1.record_detection(100);
        t1.record_detection(200);
        let mut t2 = SecurityMetricsTracker::new();
        t2.record_detection(300);
        let combined = aggregate_metrics(&[&t1, &t2]);
        assert_eq!(combined.detection_times_ms.len(), 3);
        assert_eq!(combined.mttd_ms(), Some(200.0));
    }
}
