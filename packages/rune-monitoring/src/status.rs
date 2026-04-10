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
}
