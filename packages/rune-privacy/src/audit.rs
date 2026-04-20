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
    // Layer 3
    PrivacyBackendChanged,
    PiiClassificationStored { classification_id: String },
    PiiClassifierInvoked { classifier_id: String },
    PiiClassifierFailed { classifier_id: String, reason: String },
    DataSubjectRecordPersisted { subject_ref: String },
    DataSubjectRequestReceived { request_id: String, request_type: String },
    DataSubjectRequestFulfilled { request_id: String },
    DataSubjectRequestRefused { request_id: String, reason: String },
    ConsentStoreChanged,
    ConsentRecordStored { consent_id: String },
    L3ConsentWithdrawn { consent_id: String },
    L3ConsentExpired { consent_id: String },
    ConsentSuperseded { old_consent_id: String, new_consent_id: String },
    RedactionApplied { strategy_id: String, category: String },
    RedactionFailed { strategy_id: String, reason: String },
    DsarExported { format: String, subject_ref: String },
    DsarExportFailed { format: String, reason: String },
    SubjectRightsSubscriberRegistered { subscriber_id: String },
    SubjectRightsSubscriberRemoved { subscriber_id: String },
    SubjectRightsEventPublished { event_type: String },
    RetentionPolicyEvaluated { policy_id: String, decision: String },
    RetentionDeletionScheduled { record_id: String },
    RetentionLegalHoldApplied { subject_ref: String, reason: String },
    ProcessingRecordPersisted { record_id: String },
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
            // Layer 3
            Self::PrivacyBackendChanged => "PrivacyBackendChanged",
            Self::PiiClassificationStored { .. } => "PiiClassificationStored",
            Self::PiiClassifierInvoked { .. } => "PiiClassifierInvoked",
            Self::PiiClassifierFailed { .. } => "PiiClassifierFailed",
            Self::DataSubjectRecordPersisted { .. } => "DataSubjectRecordPersisted",
            Self::DataSubjectRequestReceived { .. } => "DataSubjectRequestReceived",
            Self::DataSubjectRequestFulfilled { .. } => "DataSubjectRequestFulfilled",
            Self::DataSubjectRequestRefused { .. } => "DataSubjectRequestRefused",
            Self::ConsentStoreChanged => "ConsentStoreChanged",
            Self::ConsentRecordStored { .. } => "ConsentRecordStored",
            Self::L3ConsentWithdrawn { .. } => "L3ConsentWithdrawn",
            Self::L3ConsentExpired { .. } => "L3ConsentExpired",
            Self::ConsentSuperseded { .. } => "ConsentSuperseded",
            Self::RedactionApplied { .. } => "RedactionApplied",
            Self::RedactionFailed { .. } => "RedactionFailed",
            Self::DsarExported { .. } => "DsarExported",
            Self::DsarExportFailed { .. } => "DsarExportFailed",
            Self::SubjectRightsSubscriberRegistered { .. } => "SubjectRightsSubscriberRegistered",
            Self::SubjectRightsSubscriberRemoved { .. } => "SubjectRightsSubscriberRemoved",
            Self::SubjectRightsEventPublished { .. } => "SubjectRightsEventPublished",
            Self::RetentionPolicyEvaluated { .. } => "RetentionPolicyEvaluated",
            Self::RetentionDeletionScheduled { .. } => "RetentionDeletionScheduled",
            Self::RetentionLegalHoldApplied { .. } => "RetentionLegalHoldApplied",
            Self::ProcessingRecordPersisted { .. } => "ProcessingRecordPersisted",
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
                | Self::ConsentStoreChanged
                | Self::ConsentRecordStored { .. }
                | Self::L3ConsentWithdrawn { .. }
                | Self::L3ConsentExpired { .. }
                | Self::ConsentSuperseded { .. }
        )
    }

    pub fn is_backend_event(&self) -> bool {
        matches!(
            self,
            Self::PrivacyBackendChanged
                | Self::DataSubjectRecordPersisted { .. }
                | Self::ProcessingRecordPersisted { .. }
        )
    }

    pub fn is_subject_rights_event(&self) -> bool {
        matches!(
            self,
            Self::DataSubjectRequestReceived { .. }
                | Self::DataSubjectRequestFulfilled { .. }
                | Self::DataSubjectRequestRefused { .. }
                | Self::SubjectRightsSubscriberRegistered { .. }
                | Self::SubjectRightsSubscriberRemoved { .. }
                | Self::SubjectRightsEventPublished { .. }
                | Self::DsarExported { .. }
                | Self::DsarExportFailed { .. }
        )
    }

    pub fn is_redaction_event(&self) -> bool {
        matches!(
            self,
            Self::RedactionApplied { .. }
                | Self::RedactionFailed { .. }
        )
    }

    pub fn is_retention_event(&self) -> bool {
        matches!(
            self,
            Self::RetentionPolicyEvaluated { .. }
                | Self::RetentionDeletionScheduled { .. }
                | Self::RetentionLegalHoldApplied { .. }
        )
    }

    pub fn is_classification_event(&self) -> bool {
        matches!(
            self,
            Self::PiiClassificationStored { .. }
                | Self::PiiClassifierInvoked { .. }
                | Self::PiiClassifierFailed { .. }
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

    // ── Layer 3 tests ────────────────────────────────────────────────

    #[test]
    fn test_layer3_event_types_kind_and_display() {
        let events = vec![
            PrivacyEventType::PrivacyBackendChanged,
            PrivacyEventType::PiiClassificationStored { classification_id: "c1".into() },
            PrivacyEventType::PiiClassifierInvoked { classifier_id: "r1".into() },
            PrivacyEventType::PiiClassifierFailed { classifier_id: "r1".into(), reason: "timeout".into() },
            PrivacyEventType::DataSubjectRecordPersisted { subject_ref: "alice".into() },
            PrivacyEventType::DataSubjectRequestReceived { request_id: "r1".into(), request_type: "Access".into() },
            PrivacyEventType::DataSubjectRequestFulfilled { request_id: "r1".into() },
            PrivacyEventType::DataSubjectRequestRefused { request_id: "r1".into(), reason: "unverified".into() },
            PrivacyEventType::ConsentStoreChanged,
            PrivacyEventType::ConsentRecordStored { consent_id: "c1".into() },
            PrivacyEventType::L3ConsentWithdrawn { consent_id: "c1".into() },
            PrivacyEventType::L3ConsentExpired { consent_id: "c1".into() },
            PrivacyEventType::ConsentSuperseded { old_consent_id: "c1".into(), new_consent_id: "c2".into() },
            PrivacyEventType::RedactionApplied { strategy_id: "mask-1".into(), category: "Email".into() },
            PrivacyEventType::RedactionFailed { strategy_id: "mask-1".into(), reason: "no mapping".into() },
            PrivacyEventType::DsarExported { format: "JSON".into(), subject_ref: "alice".into() },
            PrivacyEventType::DsarExportFailed { format: "XML".into(), reason: "missing data".into() },
            PrivacyEventType::SubjectRightsSubscriberRegistered { subscriber_id: "s1".into() },
            PrivacyEventType::SubjectRightsSubscriberRemoved { subscriber_id: "s1".into() },
            PrivacyEventType::SubjectRightsEventPublished { event_type: "AccessRequestReceived".into() },
            PrivacyEventType::RetentionPolicyEvaluated { policy_id: "rp1".into(), decision: "Retain".into() },
            PrivacyEventType::RetentionDeletionScheduled { record_id: "r1".into() },
            PrivacyEventType::RetentionLegalHoldApplied { subject_ref: "alice".into(), reason: "litigation".into() },
            PrivacyEventType::ProcessingRecordPersisted { record_id: "pr1".into() },
        ];
        for evt in &events {
            assert!(!evt.kind().is_empty());
            assert!(!evt.to_string().is_empty());
        }
        assert_eq!(events.len(), 24);
    }

    #[test]
    fn test_layer3_consent_events() {
        assert!(PrivacyEventType::ConsentStoreChanged.is_consent_event());
        assert!(PrivacyEventType::ConsentRecordStored { consent_id: "c1".into() }.is_consent_event());
        assert!(PrivacyEventType::L3ConsentWithdrawn { consent_id: "c1".into() }.is_consent_event());
        assert!(PrivacyEventType::L3ConsentExpired { consent_id: "c1".into() }.is_consent_event());
        assert!(PrivacyEventType::ConsentSuperseded { old_consent_id: "c1".into(), new_consent_id: "c2".into() }.is_consent_event());
    }

    #[test]
    fn test_layer3_backend_events() {
        assert!(PrivacyEventType::PrivacyBackendChanged.is_backend_event());
        assert!(PrivacyEventType::DataSubjectRecordPersisted { subject_ref: "alice".into() }.is_backend_event());
        assert!(PrivacyEventType::ProcessingRecordPersisted { record_id: "pr1".into() }.is_backend_event());
        assert!(!PrivacyEventType::RedactionApplied { strategy_id: "m1".into(), category: "Email".into() }.is_backend_event());
    }

    #[test]
    fn test_layer3_subject_rights_events() {
        assert!(PrivacyEventType::DataSubjectRequestReceived { request_id: "r1".into(), request_type: "Access".into() }.is_subject_rights_event());
        assert!(PrivacyEventType::DsarExported { format: "JSON".into(), subject_ref: "alice".into() }.is_subject_rights_event());
        assert!(!PrivacyEventType::PrivacyBackendChanged.is_subject_rights_event());
    }

    #[test]
    fn test_layer3_redaction_events() {
        assert!(PrivacyEventType::RedactionApplied { strategy_id: "m1".into(), category: "Email".into() }.is_redaction_event());
        assert!(PrivacyEventType::RedactionFailed { strategy_id: "m1".into(), reason: "err".into() }.is_redaction_event());
        assert!(!PrivacyEventType::PrivacyBackendChanged.is_redaction_event());
    }

    #[test]
    fn test_layer3_retention_events() {
        assert!(PrivacyEventType::RetentionPolicyEvaluated { policy_id: "rp1".into(), decision: "Retain".into() }.is_retention_event());
        assert!(PrivacyEventType::RetentionLegalHoldApplied { subject_ref: "alice".into(), reason: "lit".into() }.is_retention_event());
        assert!(!PrivacyEventType::ConsentStoreChanged.is_retention_event());
    }

    #[test]
    fn test_layer3_classification_events() {
        assert!(PrivacyEventType::PiiClassificationStored { classification_id: "c1".into() }.is_classification_event());
        assert!(PrivacyEventType::PiiClassifierInvoked { classifier_id: "r1".into() }.is_classification_event());
        assert!(PrivacyEventType::PiiClassifierFailed { classifier_id: "r1".into(), reason: "err".into() }.is_classification_event());
        assert!(!PrivacyEventType::DsarExported { format: "JSON".into(), subject_ref: "alice".into() }.is_classification_event());
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
