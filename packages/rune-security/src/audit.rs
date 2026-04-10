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
        }
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
                write!(f, "IncidentEscalated({incident_id}, {from} → {to})")
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
}
