// ═══════════════════════════════════════════════════════════════════════
// Audit — Safety-specific audit events
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::constraint::ConstraintSeverity;

// ── SafetyEventType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyEventType {
    ConstraintViolated { constraint_id: String, severity: String },
    ConstraintSatisfied { constraint_id: String },
    MonitorTriggered { monitor_id: String, response: String },
    MonitorReset { monitor_id: String },
    FailsafeActivated { failsafe_id: String, trigger: String },
    HazardIdentified { hazard_id: String, risk_level: String },
    HazardMitigated { hazard_id: String },
    BoundaryBreached { boundary_id: String, parameter: String },
    BoundaryRestored { boundary_id: String },
    SafetyAssessed { level: String },
    SafetyCaseUpdated { case_id: String, status: String },
}

impl fmt::Display for SafetyEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConstraintViolated { constraint_id, severity } => {
                write!(f, "ConstraintViolated({constraint_id}, {severity})")
            }
            Self::ConstraintSatisfied { constraint_id } => {
                write!(f, "ConstraintSatisfied({constraint_id})")
            }
            Self::MonitorTriggered { monitor_id, response } => {
                write!(f, "MonitorTriggered({monitor_id}, {response})")
            }
            Self::MonitorReset { monitor_id } => {
                write!(f, "MonitorReset({monitor_id})")
            }
            Self::FailsafeActivated { failsafe_id, trigger } => {
                write!(f, "FailsafeActivated({failsafe_id}, {trigger})")
            }
            Self::HazardIdentified { hazard_id, risk_level } => {
                write!(f, "HazardIdentified({hazard_id}, {risk_level})")
            }
            Self::HazardMitigated { hazard_id } => {
                write!(f, "HazardMitigated({hazard_id})")
            }
            Self::BoundaryBreached { boundary_id, parameter } => {
                write!(f, "BoundaryBreached({boundary_id}, {parameter})")
            }
            Self::BoundaryRestored { boundary_id } => {
                write!(f, "BoundaryRestored({boundary_id})")
            }
            Self::SafetyAssessed { level } => {
                write!(f, "SafetyAssessed({level})")
            }
            Self::SafetyCaseUpdated { case_id, status } => {
                write!(f, "SafetyCaseUpdated({case_id}, {status})")
            }
        }
    }
}

// ── SafetyAuditEvent ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyAuditEvent {
    pub event_type: SafetyEventType,
    pub severity: ConstraintSeverity,
    pub timestamp: i64,
    pub detail: String,
    pub component: Option<String>,
}

impl SafetyAuditEvent {
    pub fn new(
        event_type: SafetyEventType,
        severity: ConstraintSeverity,
        timestamp: i64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            severity,
            timestamp,
            detail: detail.into(),
            component: None,
        }
    }

    pub fn with_component(mut self, component: impl Into<String>) -> Self {
        self.component = Some(component.into());
        self
    }
}

// ── SafetyAuditLog ────────────────────────────────────────────────────

pub struct SafetyAuditLog {
    events: Vec<SafetyAuditEvent>,
}

impl SafetyAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, event: SafetyAuditEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[SafetyAuditEvent] {
        &self.events
    }

    pub fn events_by_severity(&self, severity: ConstraintSeverity) -> Vec<&SafetyAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == severity)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&SafetyAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn constraint_events(&self) -> Vec<&SafetyAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    SafetyEventType::ConstraintViolated { .. }
                        | SafetyEventType::ConstraintSatisfied { .. }
                )
            })
            .collect()
    }

    pub fn monitor_events(&self) -> Vec<&SafetyAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    SafetyEventType::MonitorTriggered { .. }
                        | SafetyEventType::MonitorReset { .. }
                )
            })
            .collect()
    }

    pub fn hazard_events(&self) -> Vec<&SafetyAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    SafetyEventType::HazardIdentified { .. }
                        | SafetyEventType::HazardMitigated { .. }
                )
            })
            .collect()
    }

    pub fn boundary_events(&self) -> Vec<&SafetyAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    SafetyEventType::BoundaryBreached { .. }
                        | SafetyEventType::BoundaryRestored { .. }
                )
            })
            .collect()
    }

    pub fn critical_events(&self) -> Vec<&SafetyAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.severity >= ConstraintSeverity::Critical)
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for SafetyAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_retrieve() {
        let mut log = SafetyAuditLog::new();
        log.record(SafetyAuditEvent::new(
            SafetyEventType::ConstraintViolated {
                constraint_id: "c1".into(),
                severity: "Critical".into(),
            },
            ConstraintSeverity::Critical,
            1000,
            "Confidence too low",
        ));
        log.record(SafetyAuditEvent::new(
            SafetyEventType::MonitorTriggered {
                monitor_id: "m1".into(),
                response: "Alert".into(),
            },
            ConstraintSeverity::Warning,
            1001,
            "Monitor triggered",
        ));
        assert_eq!(log.event_count(), 2);
    }

    #[test]
    fn test_events_by_severity() {
        let mut log = SafetyAuditLog::new();
        log.record(SafetyAuditEvent::new(
            SafetyEventType::ConstraintViolated { constraint_id: "c1".into(), severity: "Critical".into() },
            ConstraintSeverity::Critical,
            1000,
            "a",
        ));
        log.record(SafetyAuditEvent::new(
            SafetyEventType::ConstraintSatisfied { constraint_id: "c2".into() },
            ConstraintSeverity::Advisory,
            1001,
            "b",
        ));
        assert_eq!(log.events_by_severity(ConstraintSeverity::Critical).len(), 1);
    }

    #[test]
    fn test_constraint_events() {
        let mut log = SafetyAuditLog::new();
        log.record(SafetyAuditEvent::new(
            SafetyEventType::ConstraintViolated { constraint_id: "c1".into(), severity: "Critical".into() },
            ConstraintSeverity::Critical,
            1000,
            "a",
        ));
        log.record(SafetyAuditEvent::new(
            SafetyEventType::MonitorTriggered { monitor_id: "m1".into(), response: "Alert".into() },
            ConstraintSeverity::Warning,
            1001,
            "b",
        ));
        assert_eq!(log.constraint_events().len(), 1);
    }

    #[test]
    fn test_monitor_events() {
        let mut log = SafetyAuditLog::new();
        log.record(SafetyAuditEvent::new(
            SafetyEventType::MonitorTriggered { monitor_id: "m1".into(), response: "Alert".into() },
            ConstraintSeverity::Warning,
            1000,
            "a",
        ));
        log.record(SafetyAuditEvent::new(
            SafetyEventType::MonitorReset { monitor_id: "m1".into() },
            ConstraintSeverity::Advisory,
            1001,
            "b",
        ));
        assert_eq!(log.monitor_events().len(), 2);
    }

    #[test]
    fn test_hazard_events() {
        let mut log = SafetyAuditLog::new();
        log.record(SafetyAuditEvent::new(
            SafetyEventType::HazardIdentified { hazard_id: "h1".into(), risk_level: "Intolerable".into() },
            ConstraintSeverity::Critical,
            1000,
            "a",
        ));
        assert_eq!(log.hazard_events().len(), 1);
    }

    #[test]
    fn test_boundary_events() {
        let mut log = SafetyAuditLog::new();
        log.record(SafetyAuditEvent::new(
            SafetyEventType::BoundaryBreached { boundary_id: "b1".into(), parameter: "temp".into() },
            ConstraintSeverity::Critical,
            1000,
            "a",
        ));
        log.record(SafetyAuditEvent::new(
            SafetyEventType::BoundaryRestored { boundary_id: "b1".into() },
            ConstraintSeverity::Advisory,
            1001,
            "b",
        ));
        assert_eq!(log.boundary_events().len(), 2);
    }

    #[test]
    fn test_critical_events() {
        let mut log = SafetyAuditLog::new();
        log.record(SafetyAuditEvent::new(
            SafetyEventType::ConstraintViolated { constraint_id: "c1".into(), severity: "Critical".into() },
            ConstraintSeverity::Critical,
            1000,
            "a",
        ));
        log.record(SafetyAuditEvent::new(
            SafetyEventType::BoundaryBreached { boundary_id: "b1".into(), parameter: "p".into() },
            ConstraintSeverity::Catastrophic,
            1001,
            "b",
        ));
        log.record(SafetyAuditEvent::new(
            SafetyEventType::ConstraintSatisfied { constraint_id: "c2".into() },
            ConstraintSeverity::Advisory,
            1002,
            "c",
        ));
        assert_eq!(log.critical_events().len(), 2);
    }

    #[test]
    fn test_event_type_display_all() {
        let types = vec![
            SafetyEventType::ConstraintViolated { constraint_id: "c".into(), severity: "s".into() },
            SafetyEventType::ConstraintSatisfied { constraint_id: "c".into() },
            SafetyEventType::MonitorTriggered { monitor_id: "m".into(), response: "r".into() },
            SafetyEventType::MonitorReset { monitor_id: "m".into() },
            SafetyEventType::FailsafeActivated { failsafe_id: "f".into(), trigger: "t".into() },
            SafetyEventType::HazardIdentified { hazard_id: "h".into(), risk_level: "r".into() },
            SafetyEventType::HazardMitigated { hazard_id: "h".into() },
            SafetyEventType::BoundaryBreached { boundary_id: "b".into(), parameter: "p".into() },
            SafetyEventType::BoundaryRestored { boundary_id: "b".into() },
            SafetyEventType::SafetyAssessed { level: "Safe".into() },
            SafetyEventType::SafetyCaseUpdated { case_id: "sc".into(), status: "Draft".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 11);
    }

    #[test]
    fn test_since_filter() {
        let mut log = SafetyAuditLog::new();
        log.record(SafetyAuditEvent::new(
            SafetyEventType::ConstraintSatisfied { constraint_id: "c1".into() },
            ConstraintSeverity::Advisory,
            900,
            "a",
        ));
        log.record(SafetyAuditEvent::new(
            SafetyEventType::ConstraintSatisfied { constraint_id: "c2".into() },
            ConstraintSeverity::Advisory,
            1100,
            "b",
        ));
        assert_eq!(log.since(1000).len(), 1);
    }
}
