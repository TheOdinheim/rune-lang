// ═══════════════════════════════════════════════════════════════════════
// Audit — monitoring audit log with 11 event types and filters.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_security::SecuritySeverity;

// ── MonitoringEventType ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum MonitoringEventType {
    HealthCheckPassed { check_id: String },
    HealthCheckFailed { check_id: String, reason: String },
    HealthCheckDegraded { check_id: String, reason: String },
    ThresholdBreached { rule_id: String, observed: f64 },
    ThresholdResolved { rule_id: String },
    SlaViolation { sla_id: String, observed: f64 },
    SlaRestored { sla_id: String },
    ComponentDown { component: String, reason: String },
    ComponentUp { component: String },
    MetricCollected { metric_id: String, value: f64 },
    StatusChanged { from: String, to: String },
}

impl fmt::Display for MonitoringEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HealthCheckPassed { check_id } => {
                write!(f, "health check passed: {check_id}")
            }
            Self::HealthCheckFailed { check_id, reason } => {
                write!(f, "health check failed: {check_id} ({reason})")
            }
            Self::HealthCheckDegraded { check_id, reason } => {
                write!(f, "health check degraded: {check_id} ({reason})")
            }
            Self::ThresholdBreached { rule_id, observed } => {
                write!(f, "threshold breached: {rule_id} observed={observed}")
            }
            Self::ThresholdResolved { rule_id } => {
                write!(f, "threshold resolved: {rule_id}")
            }
            Self::SlaViolation { sla_id, observed } => {
                write!(f, "sla violation: {sla_id} observed={observed}")
            }
            Self::SlaRestored { sla_id } => write!(f, "sla restored: {sla_id}"),
            Self::ComponentDown { component, reason } => {
                write!(f, "component down: {component} ({reason})")
            }
            Self::ComponentUp { component } => write!(f, "component up: {component}"),
            Self::MetricCollected { metric_id, value } => {
                write!(f, "metric collected: {metric_id}={value}")
            }
            Self::StatusChanged { from, to } => {
                write!(f, "status changed: {from} → {to}")
            }
        }
    }
}

// ── MonitoringAuditEvent ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MonitoringAuditEvent {
    pub event_type: MonitoringEventType,
    pub severity: SecuritySeverity,
    pub timestamp: i64,
    pub details: Vec<String>,
}

impl MonitoringAuditEvent {
    pub fn new(event_type: MonitoringEventType, severity: SecuritySeverity, timestamp: i64) -> Self {
        Self {
            event_type,
            severity,
            timestamp,
            details: Vec::new(),
        }
    }

    pub fn with_detail(mut self, d: impl Into<String>) -> Self {
        self.details.push(d.into());
        self
    }

    pub fn is_threshold_event(&self) -> bool {
        matches!(
            self.event_type,
            MonitoringEventType::ThresholdBreached { .. }
                | MonitoringEventType::ThresholdResolved { .. }
        )
    }

    pub fn is_sla_event(&self) -> bool {
        matches!(
            self.event_type,
            MonitoringEventType::SlaViolation { .. } | MonitoringEventType::SlaRestored { .. }
        )
    }

    pub fn is_health_event(&self) -> bool {
        matches!(
            self.event_type,
            MonitoringEventType::HealthCheckPassed { .. }
                | MonitoringEventType::HealthCheckFailed { .. }
                | MonitoringEventType::HealthCheckDegraded { .. }
        )
    }
}

// ── MonitoringAuditLog ────────────────────────────────────────────────

#[derive(Default)]
pub struct MonitoringAuditLog {
    pub events: Vec<MonitoringAuditEvent>,
}

impl MonitoringAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: MonitoringAuditEvent) {
        self.events.push(event);
    }

    pub fn record_simple(
        &mut self,
        event_type: MonitoringEventType,
        severity: SecuritySeverity,
        timestamp: i64,
    ) {
        self.events.push(MonitoringAuditEvent::new(event_type, severity, timestamp));
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn threshold_events(&self) -> Vec<&MonitoringAuditEvent> {
        self.events.iter().filter(|e| e.is_threshold_event()).collect()
    }

    pub fn sla_events(&self) -> Vec<&MonitoringAuditEvent> {
        self.events.iter().filter(|e| e.is_sla_event()).collect()
    }

    pub fn health_events(&self) -> Vec<&MonitoringAuditEvent> {
        self.events.iter().filter(|e| e.is_health_event()).collect()
    }

    pub fn by_severity(&self, min: SecuritySeverity) -> Vec<&MonitoringAuditEvent> {
        self.events.iter().filter(|e| e.severity >= min).collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&MonitoringAuditEvent> {
        self.events.iter().filter(|e| e.timestamp >= timestamp).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_len() {
        let mut log = MonitoringAuditLog::new();
        log.record_simple(
            MonitoringEventType::HealthCheckPassed { check_id: "a".into() },
            SecuritySeverity::Info,
            1,
        );
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn test_threshold_filter() {
        let mut log = MonitoringAuditLog::new();
        log.record_simple(
            MonitoringEventType::ThresholdBreached {
                rule_id: "r1".into(),
                observed: 10.0,
            },
            SecuritySeverity::High,
            1,
        );
        log.record_simple(
            MonitoringEventType::HealthCheckPassed { check_id: "a".into() },
            SecuritySeverity::Info,
            2,
        );
        assert_eq!(log.threshold_events().len(), 1);
    }

    #[test]
    fn test_sla_filter() {
        let mut log = MonitoringAuditLog::new();
        log.record_simple(
            MonitoringEventType::SlaViolation { sla_id: "s1".into(), observed: 0.5 },
            SecuritySeverity::High,
            1,
        );
        log.record_simple(
            MonitoringEventType::SlaRestored { sla_id: "s1".into() },
            SecuritySeverity::Info,
            2,
        );
        assert_eq!(log.sla_events().len(), 2);
    }

    #[test]
    fn test_health_filter() {
        let mut log = MonitoringAuditLog::new();
        log.record_simple(
            MonitoringEventType::HealthCheckFailed {
                check_id: "a".into(),
                reason: "x".into(),
            },
            SecuritySeverity::High,
            1,
        );
        log.record_simple(
            MonitoringEventType::HealthCheckDegraded {
                check_id: "a".into(),
                reason: "slow".into(),
            },
            SecuritySeverity::Medium,
            2,
        );
        assert_eq!(log.health_events().len(), 2);
    }

    #[test]
    fn test_by_severity_filter() {
        let mut log = MonitoringAuditLog::new();
        log.record_simple(
            MonitoringEventType::HealthCheckPassed { check_id: "a".into() },
            SecuritySeverity::Info,
            1,
        );
        log.record_simple(
            MonitoringEventType::ThresholdBreached {
                rule_id: "r".into(),
                observed: 1.0,
            },
            SecuritySeverity::Critical,
            2,
        );
        let critical = log.by_severity(SecuritySeverity::High);
        assert_eq!(critical.len(), 1);
    }

    #[test]
    fn test_since_filter() {
        let mut log = MonitoringAuditLog::new();
        log.record_simple(
            MonitoringEventType::HealthCheckPassed { check_id: "a".into() },
            SecuritySeverity::Info,
            100,
        );
        log.record_simple(
            MonitoringEventType::HealthCheckPassed { check_id: "a".into() },
            SecuritySeverity::Info,
            200,
        );
        assert_eq!(log.since(150).len(), 1);
    }

    #[test]
    fn test_with_detail() {
        let e = MonitoringAuditEvent::new(
            MonitoringEventType::ComponentDown {
                component: "api".into(),
                reason: "crash".into(),
            },
            SecuritySeverity::High,
            1,
        )
        .with_detail("stack trace: ...");
        assert_eq!(e.details.len(), 1);
    }

    #[test]
    fn test_all_event_type_displays() {
        let types = [
            MonitoringEventType::HealthCheckPassed { check_id: "a".into() },
            MonitoringEventType::HealthCheckFailed {
                check_id: "a".into(),
                reason: "x".into(),
            },
            MonitoringEventType::HealthCheckDegraded {
                check_id: "a".into(),
                reason: "slow".into(),
            },
            MonitoringEventType::ThresholdBreached {
                rule_id: "r".into(),
                observed: 1.0,
            },
            MonitoringEventType::ThresholdResolved { rule_id: "r".into() },
            MonitoringEventType::SlaViolation { sla_id: "s".into(), observed: 0.5 },
            MonitoringEventType::SlaRestored { sla_id: "s".into() },
            MonitoringEventType::ComponentDown {
                component: "c".into(),
                reason: "x".into(),
            },
            MonitoringEventType::ComponentUp { component: "c".into() },
            MonitoringEventType::MetricCollected {
                metric_id: "m".into(),
                value: 1.0,
            },
            MonitoringEventType::StatusChanged {
                from: "operational".into(),
                to: "degraded".into(),
            },
        ];
        for t in types {
            assert!(!t.to_string().is_empty());
        }
    }
}
