// ═══════════════════════════════════════════════════════════════════════
// Privacy Audit Log — Immutable event trail for privacy operations
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_identity::IdentityId;

// ── PrivacyEventType ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PrivacyEventType {
    PiiDetected { category: String, field: String },
    DataAnonymized { method: String, field: String },
    DpQueryExecuted { epsilon_cost: f64, remaining: f64 },
    ConsentRecorded { purpose: String },
    ConsentWithdrawn { purpose: String },
    RightsRequestSubmitted { right: String },
    RightsRequestCompleted { right: String },
    PurposeViolation { data_id: String, purpose: String },
    RetentionExpired { data_id: String, action: String },
    PrivacyImpactAssessed { assessment_id: String, risk: String },
    MinimizationViolation { excess_fields: Vec<String> },
}

impl PrivacyEventType {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PiiDetected { .. } => "PiiDetected",
            Self::DataAnonymized { .. } => "DataAnonymized",
            Self::DpQueryExecuted { .. } => "DpQueryExecuted",
            Self::ConsentRecorded { .. } => "ConsentRecorded",
            Self::ConsentWithdrawn { .. } => "ConsentWithdrawn",
            Self::RightsRequestSubmitted { .. } => "RightsRequestSubmitted",
            Self::RightsRequestCompleted { .. } => "RightsRequestCompleted",
            Self::PurposeViolation { .. } => "PurposeViolation",
            Self::RetentionExpired { .. } => "RetentionExpired",
            Self::PrivacyImpactAssessed { .. } => "PrivacyImpactAssessed",
            Self::MinimizationViolation { .. } => "MinimizationViolation",
        }
    }

    pub fn is_violation(&self) -> bool {
        matches!(
            self,
            Self::PurposeViolation { .. } | Self::MinimizationViolation { .. }
        )
    }

    pub fn is_consent_event(&self) -> bool {
        matches!(
            self,
            Self::ConsentRecorded { .. } | Self::ConsentWithdrawn { .. }
        )
    }
}

impl fmt::Display for PrivacyEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind())
    }
}

// ── PrivacyAuditEvent ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PrivacyAuditEvent {
    pub event_type: PrivacyEventType,
    pub subject_id: Option<IdentityId>,
    pub timestamp: i64,
    pub actor: String,
    pub detail: String,
}

// ── PrivacyAuditLog ───────────────────────────────────────────────────

#[derive(Default)]
pub struct PrivacyAuditLog {
    pub events: Vec<PrivacyAuditEvent>,
}

impl PrivacyAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: PrivacyAuditEvent) {
        self.events.push(event);
    }

    pub fn events_for_subject(&self, subject: &IdentityId) -> Vec<&PrivacyAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.subject_id.as_ref() == Some(subject))
            .collect()
    }

    pub fn events_by_type(&self, kind: &str) -> Vec<&PrivacyAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.kind() == kind)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&PrivacyAuditEvent> {
        self.events.iter().filter(|e| e.timestamp >= timestamp).collect()
    }

    pub fn violations(&self) -> Vec<&PrivacyAuditEvent> {
        self.events.iter().filter(|e| e.event_type.is_violation()).collect()
    }

    pub fn consent_events(&self) -> Vec<&PrivacyAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.is_consent_event())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn event(event_type: PrivacyEventType, subject: Option<&str>, ts: i64) -> PrivacyAuditEvent {
        PrivacyAuditEvent {
            event_type,
            subject_id: subject.map(IdentityId::new),
            timestamp: ts,
            actor: "test-actor".into(),
            detail: "test".into(),
        }
    }

    #[test]
    fn test_record_and_len() {
        let mut log = PrivacyAuditLog::new();
        log.record(event(
            PrivacyEventType::ConsentRecorded { purpose: "p1".into() },
            Some("user:alice"),
            1000,
        ));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_events_for_subject() {
        let mut log = PrivacyAuditLog::new();
        log.record(event(
            PrivacyEventType::ConsentRecorded { purpose: "p1".into() },
            Some("user:alice"),
            1000,
        ));
        log.record(event(
            PrivacyEventType::ConsentRecorded { purpose: "p1".into() },
            Some("user:bob"),
            1000,
        ));
        assert_eq!(log.events_for_subject(&IdentityId::new("user:alice")).len(), 1);
    }

    #[test]
    fn test_events_by_type() {
        let mut log = PrivacyAuditLog::new();
        log.record(event(
            PrivacyEventType::PiiDetected {
                category: "Email".into(),
                field: "addr".into(),
            },
            None,
            1000,
        ));
        log.record(event(
            PrivacyEventType::ConsentRecorded { purpose: "p1".into() },
            Some("user:alice"),
            1000,
        ));
        assert_eq!(log.events_by_type("PiiDetected").len(), 1);
        assert_eq!(log.events_by_type("ConsentRecorded").len(), 1);
    }

    #[test]
    fn test_since_filter() {
        let mut log = PrivacyAuditLog::new();
        log.record(event(
            PrivacyEventType::ConsentRecorded { purpose: "p1".into() },
            None,
            1000,
        ));
        log.record(event(
            PrivacyEventType::ConsentRecorded { purpose: "p2".into() },
            None,
            3000,
        ));
        assert_eq!(log.since(2000).len(), 1);
    }

    #[test]
    fn test_violations_filter() {
        let mut log = PrivacyAuditLog::new();
        log.record(event(
            PrivacyEventType::PurposeViolation {
                data_id: "d1".into(),
                purpose: "analytics".into(),
            },
            None,
            1000,
        ));
        log.record(event(
            PrivacyEventType::ConsentRecorded { purpose: "p1".into() },
            None,
            1000,
        ));
        assert_eq!(log.violations().len(), 1);
    }

    #[test]
    fn test_consent_events_filter() {
        let mut log = PrivacyAuditLog::new();
        log.record(event(
            PrivacyEventType::ConsentRecorded { purpose: "p1".into() },
            None,
            1000,
        ));
        log.record(event(
            PrivacyEventType::ConsentWithdrawn { purpose: "p1".into() },
            None,
            2000,
        ));
        log.record(event(
            PrivacyEventType::PiiDetected {
                category: "Email".into(),
                field: "addr".into(),
            },
            None,
            3000,
        ));
        assert_eq!(log.consent_events().len(), 2);
    }

    #[test]
    fn test_event_type_kind() {
        assert_eq!(
            PrivacyEventType::ConsentRecorded { purpose: "p".into() }.kind(),
            "ConsentRecorded"
        );
        assert_eq!(
            PrivacyEventType::DpQueryExecuted {
                epsilon_cost: 0.1,
                remaining: 0.9
            }
            .kind(),
            "DpQueryExecuted"
        );
    }

    #[test]
    fn test_is_violation() {
        assert!(PrivacyEventType::PurposeViolation {
            data_id: "d".into(),
            purpose: "p".into()
        }
        .is_violation());
        assert!(!PrivacyEventType::ConsentRecorded { purpose: "p".into() }.is_violation());
    }

    #[test]
    fn test_is_consent_event() {
        assert!(PrivacyEventType::ConsentRecorded { purpose: "p".into() }.is_consent_event());
        assert!(PrivacyEventType::ConsentWithdrawn { purpose: "p".into() }.is_consent_event());
        assert!(!PrivacyEventType::PiiDetected {
            category: "Email".into(),
            field: "addr".into()
        }
        .is_consent_event());
    }

    #[test]
    fn test_empty_log() {
        let log = PrivacyAuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }
}
