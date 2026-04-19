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
    // ── Layer 2 event types ──────────────────────────────────────
    BoundaryDefined { boundary_id: String, boundary_type: String },
    BoundaryViolationDetected { boundary_id: String, enforcement: String },
    BoundaryCheckPassed { checks: usize, violations: usize },
    ConstraintVerified { constraint_id: String, passed: bool },
    ConstraintVerificationReport { total: usize, passed: usize, safe: bool },
    SafetyTestRun { test_id: String, passed: bool, category: String },
    SafetyTestSuiteCompleted { total: usize, pass_rate: String },
    SafetyIncidentReported { incident_id: String, severity: String },
    SafetyIncidentResolved { incident_id: String, time_to_resolve_ms: String },
    CorrectiveActionAdded { incident_id: String, action_type: String },
    SafetyMetricsComputed { safety_score: String, violation_rate: String },
    SafetyTrendDetected { trend: String },
    ApprovalGateCreated { gate_id: String, gate_type: String },
    ApprovalRequested { gate_id: String, decision_id: String },
    ApprovalDecided { gate_id: String, decision_id: String, status: String },
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
            Self::BoundaryDefined { boundary_id, boundary_type } => {
                write!(f, "BoundaryDefined({boundary_id}, {boundary_type})")
            }
            Self::BoundaryViolationDetected { boundary_id, enforcement } => {
                write!(f, "BoundaryViolationDetected({boundary_id}, {enforcement})")
            }
            Self::BoundaryCheckPassed { checks, violations } => {
                write!(f, "BoundaryCheckPassed({checks}, {violations})")
            }
            Self::ConstraintVerified { constraint_id, passed } => {
                write!(f, "ConstraintVerified({constraint_id}, {passed})")
            }
            Self::ConstraintVerificationReport { total, passed, safe } => {
                write!(f, "ConstraintVerificationReport({total}, {passed}, {safe})")
            }
            Self::SafetyTestRun { test_id, passed, category } => {
                write!(f, "SafetyTestRun({test_id}, {passed}, {category})")
            }
            Self::SafetyTestSuiteCompleted { total, pass_rate } => {
                write!(f, "SafetyTestSuiteCompleted({total}, {pass_rate})")
            }
            Self::SafetyIncidentReported { incident_id, severity } => {
                write!(f, "SafetyIncidentReported({incident_id}, {severity})")
            }
            Self::SafetyIncidentResolved { incident_id, time_to_resolve_ms } => {
                write!(f, "SafetyIncidentResolved({incident_id}, {time_to_resolve_ms})")
            }
            Self::CorrectiveActionAdded { incident_id, action_type } => {
                write!(f, "CorrectiveActionAdded({incident_id}, {action_type})")
            }
            Self::SafetyMetricsComputed { safety_score, violation_rate } => {
                write!(f, "SafetyMetricsComputed({safety_score}, {violation_rate})")
            }
            Self::SafetyTrendDetected { trend } => {
                write!(f, "SafetyTrendDetected({trend})")
            }
            Self::ApprovalGateCreated { gate_id, gate_type } => {
                write!(f, "ApprovalGateCreated({gate_id}, {gate_type})")
            }
            Self::ApprovalRequested { gate_id, decision_id } => {
                write!(f, "ApprovalRequested({gate_id}, {decision_id})")
            }
            Self::ApprovalDecided { gate_id, decision_id, status } => {
                write!(f, "ApprovalDecided({gate_id}, {decision_id}, {status})")
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
            SafetyEventType::BoundaryDefined { boundary_id: "b".into(), boundary_type: "OutputRange".into() },
            SafetyEventType::BoundaryViolationDetected { boundary_id: "b".into(), enforcement: "HardStop".into() },
            SafetyEventType::BoundaryCheckPassed { checks: 5, violations: 0 },
            SafetyEventType::ConstraintVerified { constraint_id: "c".into(), passed: true },
            SafetyEventType::ConstraintVerificationReport { total: 3, passed: 3, safe: true },
            SafetyEventType::SafetyTestRun { test_id: "t".into(), passed: true, category: "Adversarial".into() },
            SafetyEventType::SafetyTestSuiteCompleted { total: 10, pass_rate: "0.9".into() },
            SafetyEventType::SafetyIncidentReported { incident_id: "i".into(), severity: "Critical".into() },
            SafetyEventType::SafetyIncidentResolved { incident_id: "i".into(), time_to_resolve_ms: "5000".into() },
            SafetyEventType::CorrectiveActionAdded { incident_id: "i".into(), action_type: "Immediate".into() },
            SafetyEventType::SafetyMetricsComputed { safety_score: "0.95".into(), violation_rate: "0.01".into() },
            SafetyEventType::SafetyTrendDetected { trend: "Improving".into() },
            SafetyEventType::ApprovalGateCreated { gate_id: "g".into(), gate_type: "PreExecution".into() },
            SafetyEventType::ApprovalRequested { gate_id: "g".into(), decision_id: "d".into() },
            SafetyEventType::ApprovalDecided { gate_id: "g".into(), decision_id: "d".into(), status: "Approved".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 26);
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
