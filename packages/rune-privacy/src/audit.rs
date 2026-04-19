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
    // Layer 2
    PiiRegexScanCompleted { patterns_checked: usize, matches_found: usize },
    PiiHighConfidenceMatch { pii_type: String, field: String },
    PrivacyBudgetSpent { query_id: String, epsilon_cost: f64, remaining: f64 },
    PrivacyBudgetExhausted { total_epsilon: f64 },
    GaussianNoiseApplied { sensitivity: f64, epsilon: f64, delta: f64 },
    LDiversityChecked { satisfied: bool, l: usize, violating_groups: usize },
    TClosenessChecked { satisfied: bool, max_distance: f64 },
    ReidentificationRiskAssessed { risk_level: String, score: f64 },
    ConsentVersionCreated { consent_id: String, version: u32 },
    ConsentWithdrawnCascade { consent_id: String, dependent_purposes: usize },
    ConsentProofGenerated { consent_id: String },
    DataSubjectRequestSubmitted { request_id: String, right: String },
    DataSubjectRequestCompleted { request_id: String, right: String },
    DataSubjectRequestOverdue { request_id: String, deadline: i64 },
    PiaScoreCalculated { score: f64, risk_level: String },
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
            Self::PiiRegexScanCompleted { .. } => "PiiRegexScanCompleted",
            Self::PiiHighConfidenceMatch { .. } => "PiiHighConfidenceMatch",
            Self::PrivacyBudgetSpent { .. } => "PrivacyBudgetSpent",
            Self::PrivacyBudgetExhausted { .. } => "PrivacyBudgetExhausted",
            Self::GaussianNoiseApplied { .. } => "GaussianNoiseApplied",
            Self::LDiversityChecked { .. } => "LDiversityChecked",
            Self::TClosenessChecked { .. } => "TClosenessChecked",
            Self::ReidentificationRiskAssessed { .. } => "ReidentificationRiskAssessed",
            Self::ConsentVersionCreated { .. } => "ConsentVersionCreated",
            Self::ConsentWithdrawnCascade { .. } => "ConsentWithdrawnCascade",
            Self::ConsentProofGenerated { .. } => "ConsentProofGenerated",
            Self::DataSubjectRequestSubmitted { .. } => "DataSubjectRequestSubmitted",
            Self::DataSubjectRequestCompleted { .. } => "DataSubjectRequestCompleted",
            Self::DataSubjectRequestOverdue { .. } => "DataSubjectRequestOverdue",
            Self::PiaScoreCalculated { .. } => "PiaScoreCalculated",
        }
    }

    pub fn is_violation(&self) -> bool {
        matches!(
            self,
            Self::PurposeViolation { .. }
                | Self::MinimizationViolation { .. }
                | Self::PrivacyBudgetExhausted { .. }
                | Self::DataSubjectRequestOverdue { .. }
        )
    }

    pub fn is_consent_event(&self) -> bool {
        matches!(
            self,
            Self::ConsentRecorded { .. }
                | Self::ConsentWithdrawn { .. }
                | Self::ConsentVersionCreated { .. }
                | Self::ConsentWithdrawnCascade { .. }
                | Self::ConsentProofGenerated { .. }
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

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_layer2_event_types_kind() {
        let events = vec![
            PrivacyEventType::PiiRegexScanCompleted { patterns_checked: 12, matches_found: 3 },
            PrivacyEventType::PiiHighConfidenceMatch { pii_type: "email".into(), field: "addr".into() },
            PrivacyEventType::PrivacyBudgetSpent { query_id: "q1".into(), epsilon_cost: 0.1, remaining: 0.9 },
            PrivacyEventType::PrivacyBudgetExhausted { total_epsilon: 1.0 },
            PrivacyEventType::GaussianNoiseApplied { sensitivity: 1.0, epsilon: 0.5, delta: 1e-5 },
            PrivacyEventType::LDiversityChecked { satisfied: true, l: 3, violating_groups: 0 },
            PrivacyEventType::TClosenessChecked { satisfied: false, max_distance: 0.3 },
            PrivacyEventType::ReidentificationRiskAssessed { risk_level: "Medium".into(), score: 0.4 },
            PrivacyEventType::ConsentVersionCreated { consent_id: "c1".into(), version: 2 },
            PrivacyEventType::ConsentWithdrawnCascade { consent_id: "c1".into(), dependent_purposes: 3 },
            PrivacyEventType::ConsentProofGenerated { consent_id: "c1".into() },
            PrivacyEventType::DataSubjectRequestSubmitted { request_id: "r1".into(), right: "Access".into() },
            PrivacyEventType::DataSubjectRequestCompleted { request_id: "r1".into(), right: "Access".into() },
            PrivacyEventType::DataSubjectRequestOverdue { request_id: "r1".into(), deadline: 5000 },
            PrivacyEventType::PiaScoreCalculated { score: 0.75, risk_level: "High".into() },
        ];
        let expected_kinds = [
            "PiiRegexScanCompleted", "PiiHighConfidenceMatch", "PrivacyBudgetSpent",
            "PrivacyBudgetExhausted", "GaussianNoiseApplied", "LDiversityChecked",
            "TClosenessChecked", "ReidentificationRiskAssessed", "ConsentVersionCreated",
            "ConsentWithdrawnCascade", "ConsentProofGenerated", "DataSubjectRequestSubmitted",
            "DataSubjectRequestCompleted", "DataSubjectRequestOverdue", "PiaScoreCalculated",
        ];
        for (evt, expected) in events.iter().zip(expected_kinds.iter()) {
            assert_eq!(evt.kind(), *expected);
        }
    }

    #[test]
    fn test_layer2_display() {
        let evt = PrivacyEventType::PiiRegexScanCompleted { patterns_checked: 12, matches_found: 3 };
        assert_eq!(evt.to_string(), "PiiRegexScanCompleted");
    }

    #[test]
    fn test_layer2_violations() {
        assert!(PrivacyEventType::PrivacyBudgetExhausted { total_epsilon: 1.0 }.is_violation());
        assert!(PrivacyEventType::DataSubjectRequestOverdue { request_id: "r1".into(), deadline: 5000 }.is_violation());
        assert!(!PrivacyEventType::PiiRegexScanCompleted { patterns_checked: 12, matches_found: 3 }.is_violation());
    }

    #[test]
    fn test_layer2_consent_events() {
        assert!(PrivacyEventType::ConsentVersionCreated { consent_id: "c1".into(), version: 1 }.is_consent_event());
        assert!(PrivacyEventType::ConsentWithdrawnCascade { consent_id: "c1".into(), dependent_purposes: 2 }.is_consent_event());
        assert!(PrivacyEventType::ConsentProofGenerated { consent_id: "c1".into() }.is_consent_event());
        assert!(!PrivacyEventType::PiaScoreCalculated { score: 0.5, risk_level: "Medium".into() }.is_consent_event());
    }

    #[test]
    fn test_layer2_events_in_log() {
        let mut log = PrivacyAuditLog::new();
        log.record(event(
            PrivacyEventType::PiiRegexScanCompleted { patterns_checked: 12, matches_found: 2 },
            None,
            1000,
        ));
        log.record(event(
            PrivacyEventType::PrivacyBudgetExhausted { total_epsilon: 1.0 },
            Some("user:alice"),
            2000,
        ));
        assert_eq!(log.len(), 2);
        assert_eq!(log.violations().len(), 1);
        assert_eq!(log.events_by_type("PiiRegexScanCompleted").len(), 1);
    }
}
