// ═══════════════════════════════════════════════════════════════════════
// Security Audit Log — events for security operations
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::severity::SecuritySeverity;

// ── SecurityEventType ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityEventType {
    ThreatIdentified { category: String },
    VulnerabilityDiscovered { vuln_id: String, cvss: f64 },
    VulnerabilityPatched { vuln_id: String },
    IncidentReported { incident_id: String },
    IncidentEscalated { incident_id: String, from: String, to: String },
    IncidentResolved { incident_id: String },
    PostureAssessed { grade: String, score: f64 },
    PolicyViolation { policy_id: String, rule_id: String },
    ContextElevated { context_id: String, risk: String },
    SecurityMetricRecorded { metric_id: String, value: f64 },
    // Layer 2 event types
    AttackTreeAnalyzed { tree_name: String, paths: usize, highest_risk: f64 },
    AttackSurfaceMapped { entry_points: usize, public_unauthenticated: usize },
    CvssTemporalScored { base: f64, temporal: f64 },
    CvssEnvironmentalScored { temporal: f64, environmental: f64 },
    ContextChainVerified { chain_length: usize, valid: bool },
    ContextDiffComputed { changes: usize },
    PlaybookMatched { playbook_id: String, severity: String },
    IncidentOpenedL2 { incident_id: String, severity: String },
    IncidentEscalatedL2 { incident_id: String, level: String },
    IncidentClosedL2 { incident_id: String, time_to_resolve_ms: i64 },
    PostureScoreComputed { overall: f64, grade: String },
    PostureTrendRecorded { score: f64, direction: String },
    MttdComputed { mttd_ms: f64 },
    MttrComputed { mttr_ms: f64 },
    SlaComplianceChecked { compliant: bool, violations: usize },
    // Layer 3 event types
    SecurityPostureBackendChanged { operation: String },
    VulnerabilityRecorded { vulnerability_id: String },
    VulnerabilityTriaged { vulnerability_id: String, decision: String },
    BackendVulnerabilityRemediated { vulnerability_id: String },
    VulnerabilityReopened { vulnerability_id: String, reason: String },
    VulnerabilitySlaViolatedEvent { vulnerability_id: String, hours_open: u64, threshold_hours: u64 },
    VulnerabilityStaleDetected { vulnerability_id: String, seconds_stale: i64 },
    SecurityControlStored { control_id: String, framework: String },
    SecurityControlStatusUpdated { control_id: String, new_status: String },
    ControlFrameworkMappingQueried { source_framework: String, control_id: String },
    BackendIncidentDeclared { incident_id: String, severity: String },
    IncidentStateTransitioned { incident_id: String, from_state: String, to_state: String },
    IncidentResponseActionRecorded { incident_id: String, action_type: String },
    BackendIncidentClosed { incident_id: String },
    ThreatModelRecorded { threat_model_id: String },
    ThreatModelReviewed { threat_model_id: String },
    SecurityDataExported { format_name: String, record_type: String },
    SecurityDataExportFailed { format_name: String, error: String },
    SecuritySubscriberRegistered { subscriber_id: String },
    SecuritySubscriberRemoved { subscriber_id: String },
    SecurityEventPublishedEvent { event_type: String },
    PostureSnapshotCaptured { snapshot_id: String, overall_score: String },
    PostureDeltaComputed { system_id: String, direction: String },
    PostureDegradationDetectedEvent { system_id: String, from_score: String, to_score: String },
}

impl SecurityEventType {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ThreatIdentified { .. } => "ThreatIdentified",
            Self::VulnerabilityDiscovered { .. } => "VulnerabilityDiscovered",
            Self::VulnerabilityPatched { .. } => "VulnerabilityPatched",
            Self::IncidentReported { .. } => "IncidentReported",
            Self::IncidentEscalated { .. } => "IncidentEscalated",
            Self::IncidentResolved { .. } => "IncidentResolved",
            Self::PostureAssessed { .. } => "PostureAssessed",
            Self::PolicyViolation { .. } => "PolicyViolation",
            Self::ContextElevated { .. } => "ContextElevated",
            Self::SecurityMetricRecorded { .. } => "SecurityMetricRecorded",
            Self::AttackTreeAnalyzed { .. } => "AttackTreeAnalyzed",
            Self::AttackSurfaceMapped { .. } => "AttackSurfaceMapped",
            Self::CvssTemporalScored { .. } => "CvssTemporalScored",
            Self::CvssEnvironmentalScored { .. } => "CvssEnvironmentalScored",
            Self::ContextChainVerified { .. } => "ContextChainVerified",
            Self::ContextDiffComputed { .. } => "ContextDiffComputed",
            Self::PlaybookMatched { .. } => "PlaybookMatched",
            Self::IncidentOpenedL2 { .. } => "IncidentOpenedL2",
            Self::IncidentEscalatedL2 { .. } => "IncidentEscalatedL2",
            Self::IncidentClosedL2 { .. } => "IncidentClosedL2",
            Self::PostureScoreComputed { .. } => "PostureScoreComputed",
            Self::PostureTrendRecorded { .. } => "PostureTrendRecorded",
            Self::MttdComputed { .. } => "MttdComputed",
            Self::MttrComputed { .. } => "MttrComputed",
            Self::SlaComplianceChecked { .. } => "SlaComplianceChecked",
            Self::SecurityPostureBackendChanged { .. } => "SecurityPostureBackendChanged",
            Self::VulnerabilityRecorded { .. } => "VulnerabilityRecorded",
            Self::VulnerabilityTriaged { .. } => "VulnerabilityTriaged",
            Self::BackendVulnerabilityRemediated { .. } => "BackendVulnerabilityRemediated",
            Self::VulnerabilityReopened { .. } => "VulnerabilityReopened",
            Self::VulnerabilitySlaViolatedEvent { .. } => "VulnerabilitySlaViolatedEvent",
            Self::VulnerabilityStaleDetected { .. } => "VulnerabilityStaleDetected",
            Self::SecurityControlStored { .. } => "SecurityControlStored",
            Self::SecurityControlStatusUpdated { .. } => "SecurityControlStatusUpdated",
            Self::ControlFrameworkMappingQueried { .. } => "ControlFrameworkMappingQueried",
            Self::BackendIncidentDeclared { .. } => "BackendIncidentDeclared",
            Self::IncidentStateTransitioned { .. } => "IncidentStateTransitioned",
            Self::IncidentResponseActionRecorded { .. } => "IncidentResponseActionRecorded",
            Self::BackendIncidentClosed { .. } => "BackendIncidentClosed",
            Self::ThreatModelRecorded { .. } => "ThreatModelRecorded",
            Self::ThreatModelReviewed { .. } => "ThreatModelReviewed",
            Self::SecurityDataExported { .. } => "SecurityDataExported",
            Self::SecurityDataExportFailed { .. } => "SecurityDataExportFailed",
            Self::SecuritySubscriberRegistered { .. } => "SecuritySubscriberRegistered",
            Self::SecuritySubscriberRemoved { .. } => "SecuritySubscriberRemoved",
            Self::SecurityEventPublishedEvent { .. } => "SecurityEventPublishedEvent",
            Self::PostureSnapshotCaptured { .. } => "PostureSnapshotCaptured",
            Self::PostureDeltaComputed { .. } => "PostureDeltaComputed",
            Self::PostureDegradationDetectedEvent { .. } => "PostureDegradationDetectedEvent",
        }
    }

    // ── Layer 3 classification methods ───────────────────────────

    pub fn is_backend_event(&self) -> bool {
        matches!(self, Self::SecurityPostureBackendChanged { .. })
    }

    pub fn is_vulnerability_event(&self) -> bool {
        matches!(
            self,
            Self::VulnerabilityRecorded { .. }
                | Self::VulnerabilityTriaged { .. }
                | Self::BackendVulnerabilityRemediated { .. }
                | Self::VulnerabilityReopened { .. }
                | Self::VulnerabilitySlaViolatedEvent { .. }
                | Self::VulnerabilityStaleDetected { .. }
        )
    }

    pub fn is_control_event(&self) -> bool {
        matches!(
            self,
            Self::SecurityControlStored { .. }
                | Self::SecurityControlStatusUpdated { .. }
                | Self::ControlFrameworkMappingQueried { .. }
        )
    }

    pub fn is_incident_event(&self) -> bool {
        matches!(
            self,
            Self::BackendIncidentDeclared { .. }
                | Self::IncidentStateTransitioned { .. }
                | Self::IncidentResponseActionRecorded { .. }
                | Self::BackendIncidentClosed { .. }
        )
    }

    pub fn is_export_event(&self) -> bool {
        matches!(
            self,
            Self::SecurityDataExported { .. } | Self::SecurityDataExportFailed { .. }
        )
    }

    pub fn is_posture_event(&self) -> bool {
        matches!(
            self,
            Self::PostureSnapshotCaptured { .. }
                | Self::PostureDeltaComputed { .. }
                | Self::PostureDegradationDetectedEvent { .. }
        )
    }
}

impl fmt::Display for SecurityEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThreatIdentified { category } => write!(f, "ThreatIdentified({category})"),
            Self::VulnerabilityDiscovered { vuln_id, cvss } => {
                write!(f, "VulnerabilityDiscovered({vuln_id}, cvss={cvss})")
            }
            Self::VulnerabilityPatched { vuln_id } => write!(f, "VulnerabilityPatched({vuln_id})"),
            Self::IncidentReported { incident_id } => write!(f, "IncidentReported({incident_id})"),
            Self::IncidentEscalated { incident_id, from, to } => {
                write!(f, "IncidentEscalated({incident_id}, {from} -> {to})")
            }
            Self::IncidentResolved { incident_id } => write!(f, "IncidentResolved({incident_id})"),
            Self::PostureAssessed { grade, score } => {
                write!(f, "PostureAssessed({grade}, {score})")
            }
            Self::PolicyViolation { policy_id, rule_id } => {
                write!(f, "PolicyViolation({policy_id}/{rule_id})")
            }
            Self::ContextElevated { context_id, risk } => {
                write!(f, "ContextElevated({context_id}, {risk})")
            }
            Self::SecurityMetricRecorded { metric_id, value } => {
                write!(f, "SecurityMetricRecorded({metric_id}={value})")
            }
            Self::AttackTreeAnalyzed { tree_name, paths, highest_risk } => {
                write!(f, "AttackTreeAnalyzed({tree_name}, paths={paths}, risk={highest_risk:.2})")
            }
            Self::AttackSurfaceMapped { entry_points, public_unauthenticated } => {
                write!(f, "AttackSurfaceMapped(eps={entry_points}, pub_unauth={public_unauthenticated})")
            }
            Self::CvssTemporalScored { base, temporal } => {
                write!(f, "CvssTemporalScored(base={base:.1}, temporal={temporal:.1})")
            }
            Self::CvssEnvironmentalScored { temporal, environmental } => {
                write!(f, "CvssEnvironmentalScored(temporal={temporal:.1}, env={environmental:.1})")
            }
            Self::ContextChainVerified { chain_length, valid } => {
                write!(f, "ContextChainVerified(len={chain_length}, valid={valid})")
            }
            Self::ContextDiffComputed { changes } => {
                write!(f, "ContextDiffComputed(changes={changes})")
            }
            Self::PlaybookMatched { playbook_id, severity } => {
                write!(f, "PlaybookMatched({playbook_id}, {severity})")
            }
            Self::IncidentOpenedL2 { incident_id, severity } => {
                write!(f, "IncidentOpenedL2({incident_id}, {severity})")
            }
            Self::IncidentEscalatedL2 { incident_id, level } => {
                write!(f, "IncidentEscalatedL2({incident_id}, {level})")
            }
            Self::IncidentClosedL2 { incident_id, time_to_resolve_ms } => {
                write!(f, "IncidentClosedL2({incident_id}, ttr={time_to_resolve_ms}ms)")
            }
            Self::PostureScoreComputed { overall, grade } => {
                write!(f, "PostureScoreComputed({grade}, {overall:.1})")
            }
            Self::PostureTrendRecorded { score, direction } => {
                write!(f, "PostureTrendRecorded({score:.1}, {direction})")
            }
            Self::MttdComputed { mttd_ms } => {
                write!(f, "MttdComputed({mttd_ms:.0}ms)")
            }
            Self::MttrComputed { mttr_ms } => {
                write!(f, "MttrComputed({mttr_ms:.0}ms)")
            }
            Self::SlaComplianceChecked { compliant, violations } => {
                write!(f, "SlaComplianceChecked(compliant={compliant}, violations={violations})")
            }
            Self::SecurityPostureBackendChanged { operation } => {
                write!(f, "SecurityPostureBackendChanged({operation})")
            }
            Self::VulnerabilityRecorded { vulnerability_id } => {
                write!(f, "VulnerabilityRecorded({vulnerability_id})")
            }
            Self::VulnerabilityTriaged { vulnerability_id, decision } => {
                write!(f, "VulnerabilityTriaged({vulnerability_id}, {decision})")
            }
            Self::BackendVulnerabilityRemediated { vulnerability_id } => {
                write!(f, "BackendVulnerabilityRemediated({vulnerability_id})")
            }
            Self::VulnerabilityReopened { vulnerability_id, reason } => {
                write!(f, "VulnerabilityReopened({vulnerability_id}, {reason})")
            }
            Self::VulnerabilitySlaViolatedEvent { vulnerability_id, hours_open, threshold_hours } => {
                write!(f, "VulnerabilitySlaViolatedEvent({vulnerability_id}, {hours_open}h/{threshold_hours}h)")
            }
            Self::VulnerabilityStaleDetected { vulnerability_id, seconds_stale } => {
                write!(f, "VulnerabilityStaleDetected({vulnerability_id}, {seconds_stale}s)")
            }
            Self::SecurityControlStored { control_id, framework } => {
                write!(f, "SecurityControlStored({control_id}, {framework})")
            }
            Self::SecurityControlStatusUpdated { control_id, new_status } => {
                write!(f, "SecurityControlStatusUpdated({control_id}, {new_status})")
            }
            Self::ControlFrameworkMappingQueried { source_framework, control_id } => {
                write!(f, "ControlFrameworkMappingQueried({source_framework}/{control_id})")
            }
            Self::BackendIncidentDeclared { incident_id, severity } => {
                write!(f, "BackendIncidentDeclared({incident_id}, {severity})")
            }
            Self::IncidentStateTransitioned { incident_id, from_state, to_state } => {
                write!(f, "IncidentStateTransitioned({incident_id}, {from_state} -> {to_state})")
            }
            Self::IncidentResponseActionRecorded { incident_id, action_type } => {
                write!(f, "IncidentResponseActionRecorded({incident_id}, {action_type})")
            }
            Self::BackendIncidentClosed { incident_id } => {
                write!(f, "BackendIncidentClosed({incident_id})")
            }
            Self::ThreatModelRecorded { threat_model_id } => {
                write!(f, "ThreatModelRecorded({threat_model_id})")
            }
            Self::ThreatModelReviewed { threat_model_id } => {
                write!(f, "ThreatModelReviewed({threat_model_id})")
            }
            Self::SecurityDataExported { format_name, record_type } => {
                write!(f, "SecurityDataExported({format_name}, {record_type})")
            }
            Self::SecurityDataExportFailed { format_name, error } => {
                write!(f, "SecurityDataExportFailed({format_name}, {error})")
            }
            Self::SecuritySubscriberRegistered { subscriber_id } => {
                write!(f, "SecuritySubscriberRegistered({subscriber_id})")
            }
            Self::SecuritySubscriberRemoved { subscriber_id } => {
                write!(f, "SecuritySubscriberRemoved({subscriber_id})")
            }
            Self::SecurityEventPublishedEvent { event_type } => {
                write!(f, "SecurityEventPublishedEvent({event_type})")
            }
            Self::PostureSnapshotCaptured { snapshot_id, overall_score } => {
                write!(f, "PostureSnapshotCaptured({snapshot_id}, {overall_score})")
            }
            Self::PostureDeltaComputed { system_id, direction } => {
                write!(f, "PostureDeltaComputed({system_id}, {direction})")
            }
            Self::PostureDegradationDetectedEvent { system_id, from_score, to_score } => {
                write!(f, "PostureDegradationDetectedEvent({system_id}, {from_score} -> {to_score})")
            }
        }
    }
}

// ── SecurityAuditEvent ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecurityAuditEvent {
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub timestamp: i64,
    pub actor: String,
    pub detail: String,
    pub context_id: Option<String>,
}

// ── SecurityAuditLog ──────────────────────────────────────────────────

#[derive(Default)]
pub struct SecurityAuditLog {
    pub events: Vec<SecurityAuditEvent>,
}

impl SecurityAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: SecurityAuditEvent) {
        self.events.push(event);
    }

    pub fn events_by_severity(&self, severity: SecuritySeverity) -> Vec<&SecurityAuditEvent> {
        self.events.iter().filter(|e| e.severity == severity).collect()
    }

    pub fn events_by_type(&self, type_name: &str) -> Vec<&SecurityAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.kind() == type_name)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&SecurityAuditEvent> {
        self.events.iter().filter(|e| e.timestamp >= timestamp).collect()
    }

    pub fn critical_events(&self) -> Vec<&SecurityAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.severity >= SecuritySeverity::Critical)
            .collect()
    }

    pub fn incident_events(&self) -> Vec<&SecurityAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    SecurityEventType::IncidentReported { .. }
                        | SecurityEventType::IncidentEscalated { .. }
                        | SecurityEventType::IncidentResolved { .. }
                )
            })
            .collect()
    }

    pub fn policy_violations(&self) -> Vec<&SecurityAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, SecurityEventType::PolicyViolation { .. }))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn event(event_type: SecurityEventType, severity: SecuritySeverity, ts: i64) -> SecurityAuditEvent {
        SecurityAuditEvent {
            event_type,
            severity,
            timestamp: ts,
            actor: "test-actor".into(),
            detail: "test".into(),
            context_id: None,
        }
    }

    #[test]
    fn test_record_and_retrieve() {
        let mut log = SecurityAuditLog::new();
        log.record(event(
            SecurityEventType::ThreatIdentified {
                category: "Spoofing".into(),
            },
            SecuritySeverity::High,
            1000,
        ));
        assert_eq!(log.events.len(), 1);
    }

    #[test]
    fn test_events_by_severity() {
        let mut log = SecurityAuditLog::new();
        log.record(event(
            SecurityEventType::IncidentReported { incident_id: "i1".into() },
            SecuritySeverity::High,
            1000,
        ));
        log.record(event(
            SecurityEventType::IncidentReported { incident_id: "i2".into() },
            SecuritySeverity::Low,
            1000,
        ));
        assert_eq!(log.events_by_severity(SecuritySeverity::High).len(), 1);
    }

    #[test]
    fn test_critical_events() {
        let mut log = SecurityAuditLog::new();
        log.record(event(
            SecurityEventType::IncidentReported { incident_id: "i1".into() },
            SecuritySeverity::Critical,
            1000,
        ));
        log.record(event(
            SecurityEventType::IncidentReported { incident_id: "i2".into() },
            SecuritySeverity::Emergency,
            1000,
        ));
        log.record(event(
            SecurityEventType::IncidentReported { incident_id: "i3".into() },
            SecuritySeverity::Low,
            1000,
        ));
        assert_eq!(log.critical_events().len(), 2);
    }

    #[test]
    fn test_incident_events_filter() {
        let mut log = SecurityAuditLog::new();
        log.record(event(
            SecurityEventType::IncidentReported { incident_id: "i1".into() },
            SecuritySeverity::High,
            1000,
        ));
        log.record(event(
            SecurityEventType::IncidentResolved { incident_id: "i1".into() },
            SecuritySeverity::Info,
            2000,
        ));
        log.record(event(
            SecurityEventType::ThreatIdentified {
                category: "Spoofing".into(),
            },
            SecuritySeverity::Low,
            1500,
        ));
        assert_eq!(log.incident_events().len(), 2);
    }

    #[test]
    fn test_policy_violations_filter() {
        let mut log = SecurityAuditLog::new();
        log.record(event(
            SecurityEventType::PolicyViolation {
                policy_id: "p1".into(),
                rule_id: "r1".into(),
            },
            SecuritySeverity::High,
            1000,
        ));
        log.record(event(
            SecurityEventType::IncidentReported { incident_id: "i1".into() },
            SecuritySeverity::High,
            1000,
        ));
        assert_eq!(log.policy_violations().len(), 1);
    }

    #[test]
    fn test_since_filter() {
        let mut log = SecurityAuditLog::new();
        log.record(event(
            SecurityEventType::ThreatIdentified {
                category: "Spoofing".into(),
            },
            SecuritySeverity::Low,
            1000,
        ));
        log.record(event(
            SecurityEventType::ThreatIdentified {
                category: "Tampering".into(),
            },
            SecuritySeverity::Low,
            3000,
        ));
        assert_eq!(log.since(2000).len(), 1);
    }

    #[test]
    fn test_events_by_type() {
        let mut log = SecurityAuditLog::new();
        log.record(event(
            SecurityEventType::ThreatIdentified {
                category: "Spoofing".into(),
            },
            SecuritySeverity::Low,
            1000,
        ));
        log.record(event(
            SecurityEventType::PolicyViolation {
                policy_id: "p1".into(),
                rule_id: "r1".into(),
            },
            SecuritySeverity::High,
            1000,
        ));
        assert_eq!(log.events_by_type("ThreatIdentified").len(), 1);
        assert_eq!(log.events_by_type("PolicyViolation").len(), 1);
    }

    #[test]
    fn test_event_type_display_variants() {
        let events = [
            SecurityEventType::ThreatIdentified { category: "Spoofing".into() },
            SecurityEventType::VulnerabilityDiscovered {
                vuln_id: "v1".into(),
                cvss: 9.5,
            },
            SecurityEventType::VulnerabilityPatched { vuln_id: "v1".into() },
            SecurityEventType::IncidentReported { incident_id: "i1".into() },
            SecurityEventType::IncidentEscalated {
                incident_id: "i1".into(),
                from: "L1".into(),
                to: "L2".into(),
            },
            SecurityEventType::IncidentResolved { incident_id: "i1".into() },
            SecurityEventType::PostureAssessed {
                grade: "B".into(),
                score: 85.0,
            },
            SecurityEventType::PolicyViolation {
                policy_id: "p1".into(),
                rule_id: "r1".into(),
            },
            SecurityEventType::ContextElevated {
                context_id: "c1".into(),
                risk: "High".into(),
            },
            SecurityEventType::SecurityMetricRecorded {
                metric_id: "mttd".into(),
                value: 4.0,
            },
        ];
        for e in &events {
            assert!(!e.to_string().is_empty());
            assert!(!e.kind().is_empty());
        }
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_layer2_event_type_display_all() {
        let l2_events = [
            SecurityEventType::AttackTreeAnalyzed {
                tree_name: "api-tree".into(),
                paths: 5,
                highest_risk: 0.8,
            },
            SecurityEventType::AttackSurfaceMapped {
                entry_points: 10,
                public_unauthenticated: 3,
            },
            SecurityEventType::CvssTemporalScored { base: 8.0, temporal: 7.2 },
            SecurityEventType::CvssEnvironmentalScored { temporal: 7.2, environmental: 6.5 },
            SecurityEventType::ContextChainVerified { chain_length: 5, valid: true },
            SecurityEventType::ContextDiffComputed { changes: 3 },
            SecurityEventType::PlaybookMatched {
                playbook_id: "pb1".into(),
                severity: "High".into(),
            },
            SecurityEventType::IncidentOpenedL2 {
                incident_id: "inc-1".into(),
                severity: "Critical".into(),
            },
            SecurityEventType::IncidentEscalatedL2 {
                incident_id: "inc-1".into(),
                level: "L2".into(),
            },
            SecurityEventType::IncidentClosedL2 {
                incident_id: "inc-1".into(),
                time_to_resolve_ms: 3600000,
            },
            SecurityEventType::PostureScoreComputed { overall: 85.0, grade: "B".into() },
            SecurityEventType::PostureTrendRecorded {
                score: 85.0,
                direction: "Improving".into(),
            },
            SecurityEventType::MttdComputed { mttd_ms: 500.0 },
            SecurityEventType::MttrComputed { mttr_ms: 3000.0 },
            SecurityEventType::SlaComplianceChecked { compliant: true, violations: 0 },
        ];
        for e in &l2_events {
            assert!(!e.to_string().is_empty());
            assert!(!e.kind().is_empty());
        }
    }

    #[test]
    fn test_layer2_events_by_type() {
        let mut log = SecurityAuditLog::new();
        log.record(event(
            SecurityEventType::AttackTreeAnalyzed {
                tree_name: "test".into(),
                paths: 3,
                highest_risk: 0.7,
            },
            SecuritySeverity::Info,
            1000,
        ));
        log.record(event(
            SecurityEventType::MttdComputed { mttd_ms: 200.0 },
            SecuritySeverity::Info,
            2000,
        ));
        assert_eq!(log.events_by_type("AttackTreeAnalyzed").len(), 1);
        assert_eq!(log.events_by_type("MttdComputed").len(), 1);
    }

    // ── Layer 3 tests ────────────────────────────────────────────────

    #[test]
    fn test_layer3_event_type_display_all() {
        let l3_events = [
            SecurityEventType::SecurityPostureBackendChanged { operation: "store".into() },
            SecurityEventType::VulnerabilityRecorded { vulnerability_id: "v1".into() },
            SecurityEventType::VulnerabilityTriaged { vulnerability_id: "v1".into(), decision: "confirm".into() },
            SecurityEventType::BackendVulnerabilityRemediated { vulnerability_id: "v1".into() },
            SecurityEventType::VulnerabilityReopened { vulnerability_id: "v1".into(), reason: "regression".into() },
            SecurityEventType::VulnerabilitySlaViolatedEvent { vulnerability_id: "v1".into(), hours_open: 30, threshold_hours: 24 },
            SecurityEventType::VulnerabilityStaleDetected { vulnerability_id: "v1".into(), seconds_stale: 86400 },
            SecurityEventType::SecurityControlStored { control_id: "c1".into(), framework: "NIST".into() },
            SecurityEventType::SecurityControlStatusUpdated { control_id: "c1".into(), new_status: "Implemented".into() },
            SecurityEventType::ControlFrameworkMappingQueried { source_framework: "NIST".into(), control_id: "c1".into() },
            SecurityEventType::BackendIncidentDeclared { incident_id: "inc-1".into(), severity: "High".into() },
            SecurityEventType::IncidentStateTransitioned { incident_id: "inc-1".into(), from_state: "Declared".into(), to_state: "Triaging".into() },
            SecurityEventType::IncidentResponseActionRecorded { incident_id: "inc-1".into(), action_type: "Isolate".into() },
            SecurityEventType::BackendIncidentClosed { incident_id: "inc-1".into() },
            SecurityEventType::ThreatModelRecorded { threat_model_id: "tm-1".into() },
            SecurityEventType::ThreatModelReviewed { threat_model_id: "tm-1".into() },
            SecurityEventType::SecurityDataExported { format_name: "json".into(), record_type: "vulnerability".into() },
            SecurityEventType::SecurityDataExportFailed { format_name: "stix".into(), error: "timeout".into() },
            SecurityEventType::SecuritySubscriberRegistered { subscriber_id: "sub-1".into() },
            SecurityEventType::SecuritySubscriberRemoved { subscriber_id: "sub-1".into() },
            SecurityEventType::SecurityEventPublishedEvent { event_type: "vuln_discovered".into() },
            SecurityEventType::PostureSnapshotCaptured { snapshot_id: "snap-1".into(), overall_score: "85.0".into() },
            SecurityEventType::PostureDeltaComputed { system_id: "sys-1".into(), direction: "Improved".into() },
            SecurityEventType::PostureDegradationDetectedEvent { system_id: "sys-1".into(), from_score: "90.0".into(), to_score: "60.0".into() },
        ];
        for e in &l3_events {
            assert!(!e.to_string().is_empty());
            assert!(!e.kind().is_empty());
        }
    }

    #[test]
    fn test_layer3_classification_methods() {
        assert!(SecurityEventType::SecurityPostureBackendChanged { operation: "x".into() }.is_backend_event());
        assert!(!SecurityEventType::VulnerabilityRecorded { vulnerability_id: "v".into() }.is_backend_event());

        assert!(SecurityEventType::VulnerabilityRecorded { vulnerability_id: "v".into() }.is_vulnerability_event());
        assert!(SecurityEventType::VulnerabilitySlaViolatedEvent { vulnerability_id: "v".into(), hours_open: 1, threshold_hours: 1 }.is_vulnerability_event());
        assert!(!SecurityEventType::BackendIncidentDeclared { incident_id: "i".into(), severity: "H".into() }.is_vulnerability_event());

        assert!(SecurityEventType::SecurityControlStored { control_id: "c".into(), framework: "N".into() }.is_control_event());
        assert!(SecurityEventType::ControlFrameworkMappingQueried { source_framework: "N".into(), control_id: "c".into() }.is_control_event());

        assert!(SecurityEventType::BackendIncidentDeclared { incident_id: "i".into(), severity: "H".into() }.is_incident_event());
        assert!(SecurityEventType::BackendIncidentClosed { incident_id: "i".into() }.is_incident_event());

        assert!(SecurityEventType::SecurityDataExported { format_name: "json".into(), record_type: "v".into() }.is_export_event());
        assert!(SecurityEventType::SecurityDataExportFailed { format_name: "json".into(), error: "e".into() }.is_export_event());

        assert!(SecurityEventType::PostureSnapshotCaptured { snapshot_id: "s".into(), overall_score: "80".into() }.is_posture_event());
        assert!(SecurityEventType::PostureDegradationDetectedEvent { system_id: "s".into(), from_score: "90".into(), to_score: "60".into() }.is_posture_event());
    }

    #[test]
    fn test_layer3_events_by_type() {
        let mut log = SecurityAuditLog::new();
        log.record(event(
            SecurityEventType::VulnerabilityRecorded { vulnerability_id: "v1".into() },
            SecuritySeverity::Info,
            1000,
        ));
        log.record(event(
            SecurityEventType::PostureSnapshotCaptured { snapshot_id: "s1".into(), overall_score: "80".into() },
            SecuritySeverity::Info,
            2000,
        ));
        assert_eq!(log.events_by_type("VulnerabilityRecorded").len(), 1);
        assert_eq!(log.events_by_type("PostureSnapshotCaptured").len(), 1);
    }
}
