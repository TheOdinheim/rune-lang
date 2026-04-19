// ═══════════════════════════════════════════════════════════════════════
// Status — overall system status aggregation and status page rendering.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::health::{HealthStatus, HealthSummary};
use crate::sla::SlaTracker;
use crate::threshold::ThresholdEngine;
use crate::uptime::UptimeTracker;

// ── OverallStatus ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OverallStatus {
    Operational = 0,
    Maintenance = 1,
    Degraded = 2,
    PartialOutage = 3,
    MajorOutage = 4,
}

impl OverallStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Operational => "operational",
            Self::Maintenance => "maintenance",
            Self::Degraded => "degraded",
            Self::PartialOutage => "partial-outage",
            Self::MajorOutage => "major-outage",
        }
    }
}

impl fmt::Display for OverallStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── ComponentStatusEntry ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComponentStatusEntry {
    pub name: String,
    pub status: OverallStatus,
    pub availability_percent: f64,
    pub message: String,
}

// ── SystemStatus ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SystemStatus {
    pub overall: OverallStatus,
    pub components: Vec<ComponentStatusEntry>,
    pub active_alerts: usize,
    pub breached_slas: usize,
    pub availability_percent: f64,
    pub generated_at: i64,
}

// ── StatusAggregator ──────────────────────────────────────────────────

pub struct StatusAggregator;

impl StatusAggregator {
    /// Combines a health summary, uptime tracker, threshold engine, and
    /// SLA tracker into a single SystemStatus.
    pub fn aggregate(
        health: &HealthSummary,
        uptime: &UptimeTracker,
        thresholds: &ThresholdEngine,
        slas: &SlaTracker,
        now: i64,
    ) -> SystemStatus {
        let mut components = Vec::new();
        for (name, comp) in &uptime.components {
            let avail = comp.availability_percent(now);
            let status = if comp.current == crate::uptime::ComponentStatus::Maintenance {
                OverallStatus::Maintenance
            } else if comp.current == crate::uptime::ComponentStatus::Down {
                OverallStatus::MajorOutage
            } else if avail < 99.0 {
                OverallStatus::Degraded
            } else {
                OverallStatus::Operational
            };
            components.push(ComponentStatusEntry {
                name: name.clone(),
                status,
                availability_percent: avail,
                message: comp.current.to_string(),
            });
        }
        components.sort_by(|a, b| a.name.cmp(&b.name));

        let active_alerts = thresholds.active_alerts().len();
        let breached_slas = slas.breached_count();
        let availability_percent = uptime.overall_availability(now) * 100.0;

        // Overall = worst of: health, component rollup, threshold/SLA breaches.
        let mut overall = match health.overall {
            HealthStatus::Healthy => OverallStatus::Operational,
            HealthStatus::Degraded => OverallStatus::Degraded,
            HealthStatus::Unhealthy => OverallStatus::PartialOutage,
            HealthStatus::Unknown => OverallStatus::Degraded,
        };
        if health.critical_failures > 0 {
            overall = overall.max(OverallStatus::MajorOutage);
        }
        for c in &components {
            overall = overall.max(c.status);
        }
        if breached_slas > 0 {
            overall = overall.max(OverallStatus::Degraded);
        }
        if active_alerts > 0 {
            overall = overall.max(OverallStatus::Degraded);
        }

        // All-maintenance downgrades to Maintenance rather than outage.
        if !components.is_empty()
            && components.iter().all(|c| c.status == OverallStatus::Maintenance)
        {
            overall = OverallStatus::Maintenance;
        }

        SystemStatus {
            overall,
            components,
            active_alerts,
            breached_slas,
            availability_percent,
            generated_at: now,
        }
    }
}

// ── StatusPage ────────────────────────────────────────────────────────

pub struct StatusPage;

impl StatusPage {
    pub fn render_text(status: &SystemStatus) -> String {
        let mut out = String::new();
        out.push_str(&format!("System Status: {}\n", status.overall));
        out.push_str(&format!(
            "Availability: {:.3}%\n",
            status.availability_percent
        ));
        out.push_str(&format!("Active Alerts: {}\n", status.active_alerts));
        out.push_str(&format!("Breached SLAs: {}\n", status.breached_slas));
        out.push_str(&format!("Generated at: {}\n", status.generated_at));
        out.push_str("\nComponents:\n");
        for c in &status.components {
            out.push_str(&format!(
                "  - {} [{}] {:.2}% — {}\n",
                c.name, c.status, c.availability_percent, c.message
            ));
        }
        out
    }

    pub fn render_json(status: &SystemStatus) -> String {
        let components: Vec<_> = status
            .components
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "status": c.status.as_str(),
                    "availability_percent": c.availability_percent,
                    "message": c.message,
                })
            })
            .collect();
        let value = serde_json::json!({
            "overall": status.overall.as_str(),
            "availability_percent": status.availability_percent,
            "active_alerts": status.active_alerts,
            "breached_slas": status.breached_slas,
            "generated_at": status.generated_at,
            "components": components,
        });
        value.to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Dashboard status, StatusPageBuilder, StatusHistory
// ═══════════════════════════════════════════════════════════════════════

// ── DashboardStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DashboardStatus {
    Operational = 0,
    Degraded = 1,
    Outage = 2,
}

impl DashboardStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Operational => "operational",
            Self::Degraded => "degraded",
            Self::Outage => "outage",
        }
    }
}

impl fmt::Display for DashboardStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── DashboardComponent ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DashboardComponent {
    pub name: String,
    pub status: DashboardStatus,
    pub message: String,
}

// ── StatusPageBuilder ────────────────────────────────────────────────

#[derive(Default)]
pub struct StatusPageBuilder {
    pub components: Vec<DashboardComponent>,
}

impl StatusPageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_component(
        &mut self,
        name: impl Into<String>,
        status: DashboardStatus,
        message: impl Into<String>,
    ) {
        self.components.push(DashboardComponent {
            name: name.into(),
            status,
            message: message.into(),
        });
    }

    /// Worst-of aggregation across all components.
    pub fn overall_status(&self) -> DashboardStatus {
        self.components
            .iter()
            .map(|c| c.status)
            .max()
            .unwrap_or(DashboardStatus::Operational)
    }

    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    pub fn operational_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == DashboardStatus::Operational)
            .count()
    }
}

// ── StatusHistoryEntry ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StatusHistoryEntry {
    pub status: DashboardStatus,
    pub at: i64,
    pub reason: String,
}

// ── StatusHistory ────────────────────────────────────────────────────

#[derive(Default)]
pub struct StatusHistory {
    pub entries: Vec<StatusHistoryEntry>,
}

impl StatusHistory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &mut self,
        status: DashboardStatus,
        at: i64,
        reason: impl Into<String>,
    ) {
        self.entries.push(StatusHistoryEntry {
            status,
            at,
            reason: reason.into(),
        });
    }

    pub fn latest(&self) -> Option<&StatusHistoryEntry> {
        self.entries.last()
    }

    /// Compute availability percentage over a time range.
    /// Availability = time spent Operational / total time.
    pub fn availability_percentage(&self, from: i64, to: i64) -> f64 {
        if self.entries.is_empty() || to <= from {
            return 100.0;
        }

        let mut operational_time = 0i64;
        let mut last_status = DashboardStatus::Operational;
        let mut last_time = from;

        for entry in &self.entries {
            if entry.at > to {
                break;
            }
            if entry.at > from {
                if last_status == DashboardStatus::Operational {
                    operational_time += entry.at - last_time;
                }
                last_time = entry.at;
            }
            last_status = entry.status;
        }

        // Account for time from last transition to `to`
        if last_status == DashboardStatus::Operational {
            operational_time += to - last_time;
        }

        let total = to - from;
        (operational_time as f64 / total as f64) * 100.0
    }

    pub fn transition_count(&self) -> usize {
        self.entries.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::{HealthCheck, HealthCheckId, HealthCheckResult, HealthCheckRunner, HealthCheckType};
    use crate::uptime::ComponentStatus;

    fn empty_aggregates() -> (HealthSummary, UptimeTracker, ThresholdEngine, SlaTracker) {
        (
            HealthSummary::default(),
            UptimeTracker::new(),
            ThresholdEngine::new(),
            SlaTracker::new(),
        )
    }

    #[test]
    fn test_status_ordering() {
        assert!(OverallStatus::Operational < OverallStatus::Degraded);
        assert!(OverallStatus::Degraded < OverallStatus::PartialOutage);
        assert!(OverallStatus::PartialOutage < OverallStatus::MajorOutage);
    }

    #[test]
    fn test_aggregate_operational_when_empty() {
        let (h, u, t, s) = empty_aggregates();
        let ss = StatusAggregator::aggregate(&h, &u, &t, &s, 100);
        assert_eq!(ss.overall, OverallStatus::Operational);
    }

    #[test]
    fn test_aggregate_health_degraded() {
        let mut runner = HealthCheckRunner::new();
        runner.register(HealthCheck::new("a", "A", HealthCheckType::Liveness, "svc"));
        runner
            .record(HealthCheckResult::degraded(HealthCheckId::new("a"), "slow", 1))
            .unwrap();
        let h = runner.summary();
        let (_, u, t, s) = empty_aggregates();
        let ss = StatusAggregator::aggregate(&h, &u, &t, &s, 100);
        assert_eq!(ss.overall, OverallStatus::Degraded);
    }

    #[test]
    fn test_aggregate_critical_failure_is_major_outage() {
        let mut runner = HealthCheckRunner::new();
        runner.register(
            HealthCheck::new("db", "DB", HealthCheckType::Dependency, "db").critical(),
        );
        runner
            .record(HealthCheckResult::unhealthy(HealthCheckId::new("db"), "down", 1))
            .unwrap();
        let h = runner.summary();
        let (_, u, t, s) = empty_aggregates();
        let ss = StatusAggregator::aggregate(&h, &u, &t, &s, 100);
        assert_eq!(ss.overall, OverallStatus::MajorOutage);
    }

    #[test]
    fn test_aggregate_component_down_is_major_outage() {
        let (h, mut u, t, s) = empty_aggregates();
        u.register("api", 0);
        u.record("api", ComponentStatus::Down, 10, "crash");
        let ss = StatusAggregator::aggregate(&h, &u, &t, &s, 100);
        assert_eq!(ss.overall, OverallStatus::MajorOutage);
    }

    #[test]
    fn test_aggregate_maintenance_when_all_in_maintenance() {
        let (h, mut u, t, s) = empty_aggregates();
        u.register("a", 0);
        u.record("a", ComponentStatus::Maintenance, 10, "deploy");
        let ss = StatusAggregator::aggregate(&h, &u, &t, &s, 100);
        assert_eq!(ss.overall, OverallStatus::Maintenance);
    }

    #[test]
    fn test_components_sorted_by_name() {
        let (h, mut u, t, s) = empty_aggregates();
        u.register("z", 0);
        u.register("a", 0);
        let ss = StatusAggregator::aggregate(&h, &u, &t, &s, 100);
        assert_eq!(ss.components[0].name, "a");
        assert_eq!(ss.components[1].name, "z");
    }

    #[test]
    fn test_render_text_contains_status() {
        let (h, mut u, t, s) = empty_aggregates();
        u.register("api", 0);
        let ss = StatusAggregator::aggregate(&h, &u, &t, &s, 100);
        let text = StatusPage::render_text(&ss);
        assert!(text.contains("System Status"));
        assert!(text.contains("api"));
    }

    #[test]
    fn test_render_json_valid() {
        let (h, mut u, t, s) = empty_aggregates();
        u.register("api", 0);
        let ss = StatusAggregator::aggregate(&h, &u, &t, &s, 100);
        let json = StatusPage::render_json(&ss);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["overall"], "operational");
        assert_eq!(parsed["components"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_availability_reported() {
        let (h, mut u, t, s) = empty_aggregates();
        u.register("api", 0);
        u.record("api", ComponentStatus::Down, 50, "crash");
        u.record("api", ComponentStatus::Up, 100, "fix");
        let ss = StatusAggregator::aggregate(&h, &u, &t, &s, 200);
        assert!(ss.availability_percent > 0.0);
        assert!(ss.availability_percent < 100.0);
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_dashboard_status_ordering() {
        assert!(DashboardStatus::Operational < DashboardStatus::Degraded);
        assert!(DashboardStatus::Degraded < DashboardStatus::Outage);
    }

    #[test]
    fn test_dashboard_status_display() {
        assert_eq!(DashboardStatus::Operational.as_str(), "operational");
        assert_eq!(DashboardStatus::Degraded.as_str(), "degraded");
        assert_eq!(DashboardStatus::Outage.as_str(), "outage");
    }

    #[test]
    fn test_status_page_builder_worst_of() {
        let mut builder = StatusPageBuilder::new();
        builder.add_component("api", DashboardStatus::Operational, "ok");
        builder.add_component("db", DashboardStatus::Degraded, "slow");
        builder.add_component("cache", DashboardStatus::Operational, "ok");
        assert_eq!(builder.overall_status(), DashboardStatus::Degraded);
        assert_eq!(builder.component_count(), 3);
        assert_eq!(builder.operational_count(), 2);
    }

    #[test]
    fn test_status_page_builder_outage() {
        let mut builder = StatusPageBuilder::new();
        builder.add_component("api", DashboardStatus::Operational, "ok");
        builder.add_component("db", DashboardStatus::Outage, "down");
        assert_eq!(builder.overall_status(), DashboardStatus::Outage);
    }

    #[test]
    fn test_status_page_builder_empty() {
        let builder = StatusPageBuilder::new();
        assert_eq!(builder.overall_status(), DashboardStatus::Operational);
    }

    #[test]
    fn test_status_history_availability() {
        let mut history = StatusHistory::new();
        // Operational from 0 to 80, then outage from 80 to 100
        history.record(DashboardStatus::Outage, 80, "crash");
        let avail = history.availability_percentage(0, 100);
        assert!((avail - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_status_history_full_operational() {
        let history = StatusHistory::new();
        let avail = history.availability_percentage(0, 100);
        assert!((avail - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_status_history_transitions() {
        let mut history = StatusHistory::new();
        history.record(DashboardStatus::Degraded, 10, "slow");
        history.record(DashboardStatus::Operational, 20, "recovered");
        history.record(DashboardStatus::Outage, 50, "crash");
        history.record(DashboardStatus::Operational, 60, "fixed");
        assert_eq!(history.transition_count(), 4);
        assert_eq!(history.latest().unwrap().status, DashboardStatus::Operational);
        // 0-10 operational (10), 10-20 degraded (0), 20-50 operational (30), 50-60 outage (0), 60-100 operational (40)
        let avail = history.availability_percentage(0, 100);
        assert!((avail - 80.0).abs() < f64::EPSILON);
    }
}
