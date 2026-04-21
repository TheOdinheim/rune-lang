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
    // ── Layer 3 event types ─────────────────────────────────────
    SafetyBackendChanged { backend_id: String },
    SafetyConstraintStored { constraint_id: String, category: String },
    SafetyConstraintRetrieved { constraint_id: String },
    SafetyEnvelopeStored { envelope_id: String, system_id: String },
    SafetyEnvelopeStatusChecked { envelope_id: String, status: String },
    StoredSafetyCaseCreated { case_id: String, methodology: String },
    StoredSafetyCaseFinalized { case_id: String },
    StoredSafetyCaseChallenged { case_id: String, reason: String },
    BoundaryViolationRecorded { violation_id: String, envelope_id: String },
    BoundaryViolationResolved { violation_id: String },
    EmergencyShutdownInitiated { shutdown_id: String, system_id: String },
    EmergencyShutdownCompleted { shutdown_id: String },
    EmergencyShutdownFailed { shutdown_id: String, reason: String },
    ReauthorizationRequested { shutdown_id: String, by: String },
    ReauthorizationGranted { shutdown_id: String, by: String },
    SafetyResponseRecommended { system_id: String, response: String },
    SafetyDataExported { format: String, system_id: String },
    SafetyDataExportFailed { format: String, reason: String },
    OperationalSafetyMetricsComputed { system_id: String, snapshot_id: String },
    SafetySubscriberRegistered { subscriber_id: String },
    SafetySubscriberRemoved { subscriber_id: String },
    SafetyLifecycleEventPublished { event_count: String },
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
            // L3 variants — delegate to type_name for consistency
            Self::SafetyBackendChanged { .. }
            | Self::SafetyConstraintStored { .. }
            | Self::SafetyConstraintRetrieved { .. }
            | Self::SafetyEnvelopeStored { .. }
            | Self::SafetyEnvelopeStatusChecked { .. }
            | Self::StoredSafetyCaseCreated { .. }
            | Self::StoredSafetyCaseFinalized { .. }
            | Self::StoredSafetyCaseChallenged { .. }
            | Self::BoundaryViolationRecorded { .. }
            | Self::BoundaryViolationResolved { .. }
            | Self::EmergencyShutdownInitiated { .. }
            | Self::EmergencyShutdownCompleted { .. }
            | Self::EmergencyShutdownFailed { .. }
            | Self::ReauthorizationRequested { .. }
            | Self::ReauthorizationGranted { .. }
            | Self::SafetyResponseRecommended { .. }
            | Self::SafetyDataExported { .. }
            | Self::SafetyDataExportFailed { .. }
            | Self::OperationalSafetyMetricsComputed { .. }
            | Self::SafetySubscriberRegistered { .. }
            | Self::SafetySubscriberRemoved { .. }
            | Self::SafetyLifecycleEventPublished { .. } => {
                f.write_str(self.type_name())
            }
        }
    }
}

impl SafetyEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::ConstraintViolated { .. } => "constraint-violated",
            Self::ConstraintSatisfied { .. } => "constraint-satisfied",
            Self::MonitorTriggered { .. } => "monitor-triggered",
            Self::MonitorReset { .. } => "monitor-reset",
            Self::FailsafeActivated { .. } => "failsafe-activated",
            Self::HazardIdentified { .. } => "hazard-identified",
            Self::HazardMitigated { .. } => "hazard-mitigated",
            Self::BoundaryBreached { .. } => "boundary-breached",
            Self::BoundaryRestored { .. } => "boundary-restored",
            Self::SafetyAssessed { .. } => "safety-assessed",
            Self::SafetyCaseUpdated { .. } => "safety-case-updated",
            Self::BoundaryDefined { .. } => "boundary-defined",
            Self::BoundaryViolationDetected { .. } => "boundary-violation-detected",
            Self::BoundaryCheckPassed { .. } => "boundary-check-passed",
            Self::ConstraintVerified { .. } => "constraint-verified",
            Self::ConstraintVerificationReport { .. } => "constraint-verification-report",
            Self::SafetyTestRun { .. } => "safety-test-run",
            Self::SafetyTestSuiteCompleted { .. } => "safety-test-suite-completed",
            Self::SafetyIncidentReported { .. } => "safety-incident-reported",
            Self::SafetyIncidentResolved { .. } => "safety-incident-resolved",
            Self::CorrectiveActionAdded { .. } => "corrective-action-added",
            Self::SafetyMetricsComputed { .. } => "safety-metrics-computed",
            Self::SafetyTrendDetected { .. } => "safety-trend-detected",
            Self::ApprovalGateCreated { .. } => "approval-gate-created",
            Self::ApprovalRequested { .. } => "approval-requested",
            Self::ApprovalDecided { .. } => "approval-decided",
            // L3
            Self::SafetyBackendChanged { .. } => "safety-backend-changed",
            Self::SafetyConstraintStored { .. } => "safety-constraint-stored",
            Self::SafetyConstraintRetrieved { .. } => "safety-constraint-retrieved",
            Self::SafetyEnvelopeStored { .. } => "safety-envelope-stored",
            Self::SafetyEnvelopeStatusChecked { .. } => "safety-envelope-status-checked",
            Self::StoredSafetyCaseCreated { .. } => "stored-safety-case-created",
            Self::StoredSafetyCaseFinalized { .. } => "stored-safety-case-finalized",
            Self::StoredSafetyCaseChallenged { .. } => "stored-safety-case-challenged",
            Self::BoundaryViolationRecorded { .. } => "boundary-violation-recorded",
            Self::BoundaryViolationResolved { .. } => "boundary-violation-resolved",
            Self::EmergencyShutdownInitiated { .. } => "emergency-shutdown-initiated",
            Self::EmergencyShutdownCompleted { .. } => "emergency-shutdown-completed",
            Self::EmergencyShutdownFailed { .. } => "emergency-shutdown-failed",
            Self::ReauthorizationRequested { .. } => "reauthorization-requested",
            Self::ReauthorizationGranted { .. } => "reauthorization-granted",
            Self::SafetyResponseRecommended { .. } => "safety-response-recommended",
            Self::SafetyDataExported { .. } => "safety-data-exported",
            Self::SafetyDataExportFailed { .. } => "safety-data-export-failed",
            Self::OperationalSafetyMetricsComputed { .. } => "operational-safety-metrics-computed",
            Self::SafetySubscriberRegistered { .. } => "safety-subscriber-registered",
            Self::SafetySubscriberRemoved { .. } => "safety-subscriber-removed",
            Self::SafetyLifecycleEventPublished { .. } => "safety-lifecycle-event-published",
        }
    }

    pub fn kind(&self) -> &str {
        self.type_name()
    }

    pub fn is_backend_event(&self) -> bool {
        matches!(
            self,
            Self::SafetyBackendChanged { .. }
                | Self::SafetyConstraintStored { .. }
                | Self::SafetyConstraintRetrieved { .. }
                | Self::SafetyEnvelopeStored { .. }
        )
    }

    pub fn is_envelope_event(&self) -> bool {
        matches!(
            self,
            Self::SafetyEnvelopeStatusChecked { .. }
                | Self::SafetyResponseRecommended { .. }
        )
    }

    pub fn is_case_event(&self) -> bool {
        matches!(
            self,
            Self::StoredSafetyCaseCreated { .. }
                | Self::StoredSafetyCaseFinalized { .. }
                | Self::StoredSafetyCaseChallenged { .. }
        )
    }

    pub fn is_shutdown_event(&self) -> bool {
        matches!(
            self,
            Self::EmergencyShutdownInitiated { .. }
                | Self::EmergencyShutdownCompleted { .. }
                | Self::EmergencyShutdownFailed { .. }
                | Self::ReauthorizationRequested { .. }
                | Self::ReauthorizationGranted { .. }
        )
    }

    pub fn is_violation_event(&self) -> bool {
        matches!(
            self,
            Self::BoundaryViolationRecorded { .. }
                | Self::BoundaryViolationResolved { .. }
        )
    }

    pub fn is_export_event(&self) -> bool {
        matches!(
            self,
            Self::SafetyDataExported { .. }
                | Self::SafetyDataExportFailed { .. }
        )
    }

    pub fn is_metrics_event(&self) -> bool {
        matches!(self, Self::OperationalSafetyMetricsComputed { .. })
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
    fn test_l3_event_type_display_and_kind() {
        let l3_types = vec![
            SafetyEventType::SafetyBackendChanged { backend_id: "b".into() },
            SafetyEventType::SafetyConstraintStored { constraint_id: "c".into(), category: "op".into() },
            SafetyEventType::SafetyConstraintRetrieved { constraint_id: "c".into() },
            SafetyEventType::SafetyEnvelopeStored { envelope_id: "e".into(), system_id: "s".into() },
            SafetyEventType::SafetyEnvelopeStatusChecked { envelope_id: "e".into(), status: "ok".into() },
            SafetyEventType::StoredSafetyCaseCreated { case_id: "sc".into(), methodology: "GSN".into() },
            SafetyEventType::StoredSafetyCaseFinalized { case_id: "sc".into() },
            SafetyEventType::StoredSafetyCaseChallenged { case_id: "sc".into(), reason: "r".into() },
            SafetyEventType::BoundaryViolationRecorded { violation_id: "v".into(), envelope_id: "e".into() },
            SafetyEventType::BoundaryViolationResolved { violation_id: "v".into() },
            SafetyEventType::EmergencyShutdownInitiated { shutdown_id: "sd".into(), system_id: "s".into() },
            SafetyEventType::EmergencyShutdownCompleted { shutdown_id: "sd".into() },
            SafetyEventType::EmergencyShutdownFailed { shutdown_id: "sd".into(), reason: "r".into() },
            SafetyEventType::ReauthorizationRequested { shutdown_id: "sd".into(), by: "a".into() },
            SafetyEventType::ReauthorizationGranted { shutdown_id: "sd".into(), by: "a".into() },
            SafetyEventType::SafetyResponseRecommended { system_id: "s".into(), response: "degrade".into() },
            SafetyEventType::SafetyDataExported { format: "JSON".into(), system_id: "s".into() },
            SafetyEventType::SafetyDataExportFailed { format: "JSON".into(), reason: "r".into() },
            SafetyEventType::OperationalSafetyMetricsComputed { system_id: "s".into(), snapshot_id: "snap".into() },
            SafetyEventType::SafetySubscriberRegistered { subscriber_id: "sub".into() },
            SafetyEventType::SafetySubscriberRemoved { subscriber_id: "sub".into() },
            SafetyEventType::SafetyLifecycleEventPublished { event_count: "5".into() },
        ];
        for t in &l3_types {
            assert!(!t.to_string().is_empty(), "Display empty for {:?}", t);
            assert!(!t.kind().is_empty(), "kind() empty for {:?}", t);
            assert!(!t.type_name().is_empty());
        }
        assert_eq!(l3_types.len(), 22);
    }

    #[test]
    fn test_is_backend_event() {
        assert!(SafetyEventType::SafetyBackendChanged { backend_id: "b".into() }.is_backend_event());
        assert!(SafetyEventType::SafetyConstraintStored { constraint_id: "c".into(), category: "o".into() }.is_backend_event());
        assert!(!SafetyEventType::EmergencyShutdownInitiated { shutdown_id: "s".into(), system_id: "x".into() }.is_backend_event());
    }

    #[test]
    fn test_is_envelope_event() {
        assert!(SafetyEventType::SafetyEnvelopeStatusChecked { envelope_id: "e".into(), status: "s".into() }.is_envelope_event());
        assert!(!SafetyEventType::SafetyBackendChanged { backend_id: "b".into() }.is_envelope_event());
    }

    #[test]
    fn test_is_case_event() {
        assert!(SafetyEventType::StoredSafetyCaseCreated { case_id: "c".into(), methodology: "m".into() }.is_case_event());
        assert!(SafetyEventType::StoredSafetyCaseFinalized { case_id: "c".into() }.is_case_event());
        assert!(SafetyEventType::StoredSafetyCaseChallenged { case_id: "c".into(), reason: "r".into() }.is_case_event());
    }

    #[test]
    fn test_is_shutdown_event() {
        assert!(SafetyEventType::EmergencyShutdownInitiated { shutdown_id: "s".into(), system_id: "x".into() }.is_shutdown_event());
        assert!(SafetyEventType::ReauthorizationGranted { shutdown_id: "s".into(), by: "a".into() }.is_shutdown_event());
    }

    #[test]
    fn test_is_violation_event() {
        assert!(SafetyEventType::BoundaryViolationRecorded { violation_id: "v".into(), envelope_id: "e".into() }.is_violation_event());
        assert!(SafetyEventType::BoundaryViolationResolved { violation_id: "v".into() }.is_violation_event());
    }

    #[test]
    fn test_is_export_event() {
        assert!(SafetyEventType::SafetyDataExported { format: "j".into(), system_id: "s".into() }.is_export_event());
        assert!(SafetyEventType::SafetyDataExportFailed { format: "j".into(), reason: "r".into() }.is_export_event());
    }

    #[test]
    fn test_is_metrics_event() {
        assert!(SafetyEventType::OperationalSafetyMetricsComputed { system_id: "s".into(), snapshot_id: "snap".into() }.is_metrics_event());
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
