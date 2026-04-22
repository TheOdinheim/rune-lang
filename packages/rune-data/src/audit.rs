// ═══════════════════════════════════════════════════════════════════════
// Audit — Data governance audit events for quality rules, data
// classification, lineage tracking, access governance, schema
// evolution, catalog management, and freshness monitoring.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── DataEventType ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataEventType {
    QualityRuleCreated { rule_id: String, dimension: String },
    QualityRuleEvaluated { rule_id: String, dataset_ref: String, passed: bool },
    QualityPolicyCreated { policy_id: String, dataset_ref: String },
    QualityPolicyViolated { policy_id: String, violation_count: String },
    DataClassified { classification_id: String, dataset_ref: String, sensitivity: String },
    DataClassificationReviewed { classification_id: String, reviewer: String },
    ClassificationPolicyCreated { policy_id: String },
    LineageRecorded { record_id: String, dataset_ref: String, stage: String },
    LineageChainVerified { chain_id: String, status: String },
    LineagePolicyCreated { policy_id: String },
    DataAccessRequested { request_id: String, dataset_ref: String, operation: String },
    DataAccessGranted { request_id: String, requester_id: String },
    DataAccessDenied { request_id: String, reason: String },
    SchemaRegistered { schema_id: String, dataset_ref: String, version: String },
    SchemaCompatibilityChecked { schema_id: String, compatibility: String },
    SchemaEvolutionPolicyCreated { policy_id: String },
    CatalogEntryRegistered { entry_id: String, dataset_ref: String },
    CatalogEntryUpdated { entry_id: String, field: String },
    CatalogEntryDeprecated { entry_id: String, reason: String },
    CatalogGovernancePolicyCreated { policy_id: String },
    FreshnessPolicyCreated { policy_id: String, dataset_ref: String },
    FreshnessAssessed { assessment_id: String, status: String },
    FreshnessAlertRaised { alert_id: String, dataset_ref: String, severity: String },
    FreshnessAlertAcknowledged { alert_id: String, acknowledged_by: String },
}

impl fmt::Display for DataEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QualityRuleCreated { rule_id, dimension } => {
                write!(f, "QualityRuleCreated({rule_id}, dimension={dimension})")
            }
            Self::QualityRuleEvaluated { rule_id, dataset_ref, passed } => {
                write!(f, "QualityRuleEvaluated({rule_id}, dataset={dataset_ref}, passed={passed})")
            }
            Self::QualityPolicyCreated { policy_id, dataset_ref } => {
                write!(f, "QualityPolicyCreated({policy_id}, dataset={dataset_ref})")
            }
            Self::QualityPolicyViolated { policy_id, violation_count } => {
                write!(f, "QualityPolicyViolated({policy_id}, violations={violation_count})")
            }
            Self::DataClassified { classification_id, dataset_ref, sensitivity } => {
                write!(f, "DataClassified({classification_id}, dataset={dataset_ref}, sensitivity={sensitivity})")
            }
            Self::DataClassificationReviewed { classification_id, reviewer } => {
                write!(f, "DataClassificationReviewed({classification_id}, reviewer={reviewer})")
            }
            Self::ClassificationPolicyCreated { policy_id } => {
                write!(f, "ClassificationPolicyCreated({policy_id})")
            }
            Self::LineageRecorded { record_id, dataset_ref, stage } => {
                write!(f, "LineageRecorded({record_id}, dataset={dataset_ref}, stage={stage})")
            }
            Self::LineageChainVerified { chain_id, status } => {
                write!(f, "LineageChainVerified({chain_id}, status={status})")
            }
            Self::LineagePolicyCreated { policy_id } => {
                write!(f, "LineagePolicyCreated({policy_id})")
            }
            Self::DataAccessRequested { request_id, dataset_ref, operation } => {
                write!(f, "DataAccessRequested({request_id}, dataset={dataset_ref}, op={operation})")
            }
            Self::DataAccessGranted { request_id, requester_id } => {
                write!(f, "DataAccessGranted({request_id}, requester={requester_id})")
            }
            Self::DataAccessDenied { request_id, reason } => {
                write!(f, "DataAccessDenied({request_id}): {reason}")
            }
            Self::SchemaRegistered { schema_id, dataset_ref, version } => {
                write!(f, "SchemaRegistered({schema_id}, dataset={dataset_ref}, version={version})")
            }
            Self::SchemaCompatibilityChecked { schema_id, compatibility } => {
                write!(f, "SchemaCompatibilityChecked({schema_id}, compat={compatibility})")
            }
            Self::SchemaEvolutionPolicyCreated { policy_id } => {
                write!(f, "SchemaEvolutionPolicyCreated({policy_id})")
            }
            Self::CatalogEntryRegistered { entry_id, dataset_ref } => {
                write!(f, "CatalogEntryRegistered({entry_id}, dataset={dataset_ref})")
            }
            Self::CatalogEntryUpdated { entry_id, field } => {
                write!(f, "CatalogEntryUpdated({entry_id}, field={field})")
            }
            Self::CatalogEntryDeprecated { entry_id, reason } => {
                write!(f, "CatalogEntryDeprecated({entry_id}): {reason}")
            }
            Self::CatalogGovernancePolicyCreated { policy_id } => {
                write!(f, "CatalogGovernancePolicyCreated({policy_id})")
            }
            Self::FreshnessPolicyCreated { policy_id, dataset_ref } => {
                write!(f, "FreshnessPolicyCreated({policy_id}, dataset={dataset_ref})")
            }
            Self::FreshnessAssessed { assessment_id, status } => {
                write!(f, "FreshnessAssessed({assessment_id}, status={status})")
            }
            Self::FreshnessAlertRaised { alert_id, dataset_ref, severity } => {
                write!(f, "FreshnessAlertRaised({alert_id}, dataset={dataset_ref}, severity={severity})")
            }
            Self::FreshnessAlertAcknowledged { alert_id, acknowledged_by } => {
                write!(f, "FreshnessAlertAcknowledged({alert_id}, by={acknowledged_by})")
            }
        }
    }
}

impl DataEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::QualityRuleCreated { .. } => "QualityRuleCreated",
            Self::QualityRuleEvaluated { .. } => "QualityRuleEvaluated",
            Self::QualityPolicyCreated { .. } => "QualityPolicyCreated",
            Self::QualityPolicyViolated { .. } => "QualityPolicyViolated",
            Self::DataClassified { .. } => "DataClassified",
            Self::DataClassificationReviewed { .. } => "DataClassificationReviewed",
            Self::ClassificationPolicyCreated { .. } => "ClassificationPolicyCreated",
            Self::LineageRecorded { .. } => "LineageRecorded",
            Self::LineageChainVerified { .. } => "LineageChainVerified",
            Self::LineagePolicyCreated { .. } => "LineagePolicyCreated",
            Self::DataAccessRequested { .. } => "DataAccessRequested",
            Self::DataAccessGranted { .. } => "DataAccessGranted",
            Self::DataAccessDenied { .. } => "DataAccessDenied",
            Self::SchemaRegistered { .. } => "SchemaRegistered",
            Self::SchemaCompatibilityChecked { .. } => "SchemaCompatibilityChecked",
            Self::SchemaEvolutionPolicyCreated { .. } => "SchemaEvolutionPolicyCreated",
            Self::CatalogEntryRegistered { .. } => "CatalogEntryRegistered",
            Self::CatalogEntryUpdated { .. } => "CatalogEntryUpdated",
            Self::CatalogEntryDeprecated { .. } => "CatalogEntryDeprecated",
            Self::CatalogGovernancePolicyCreated { .. } => "CatalogGovernancePolicyCreated",
            Self::FreshnessPolicyCreated { .. } => "FreshnessPolicyCreated",
            Self::FreshnessAssessed { .. } => "FreshnessAssessed",
            Self::FreshnessAlertRaised { .. } => "FreshnessAlertRaised",
            Self::FreshnessAlertAcknowledged { .. } => "FreshnessAlertAcknowledged",
        }
    }

    pub fn kind(&self) -> &str {
        match self {
            Self::QualityRuleCreated { .. }
            | Self::QualityRuleEvaluated { .. }
            | Self::QualityPolicyCreated { .. }
            | Self::QualityPolicyViolated { .. } => "quality",
            Self::DataClassified { .. }
            | Self::DataClassificationReviewed { .. }
            | Self::ClassificationPolicyCreated { .. } => "classification",
            Self::LineageRecorded { .. }
            | Self::LineageChainVerified { .. }
            | Self::LineagePolicyCreated { .. } => "lineage",
            Self::DataAccessRequested { .. }
            | Self::DataAccessGranted { .. }
            | Self::DataAccessDenied { .. } => "access",
            Self::SchemaRegistered { .. }
            | Self::SchemaCompatibilityChecked { .. }
            | Self::SchemaEvolutionPolicyCreated { .. } => "schema",
            Self::CatalogEntryRegistered { .. }
            | Self::CatalogEntryUpdated { .. }
            | Self::CatalogEntryDeprecated { .. }
            | Self::CatalogGovernancePolicyCreated { .. } => "catalog",
            Self::FreshnessPolicyCreated { .. }
            | Self::FreshnessAssessed { .. }
            | Self::FreshnessAlertRaised { .. }
            | Self::FreshnessAlertAcknowledged { .. } => "freshness",
        }
    }
}

// ── DataAuditEvent ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataAuditEvent {
    pub event: DataEventType,
    pub actor: String,
    pub timestamp: i64,
    pub description: String,
}

impl DataAuditEvent {
    pub fn new(
        event: DataEventType,
        actor: impl Into<String>,
        timestamp: i64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            event,
            actor: actor.into(),
            timestamp,
            description: description.into(),
        }
    }
}

// ── DataAuditLog ────────────────────────────────────────────────────

pub struct DataAuditLog {
    events: Vec<DataAuditEvent>,
}

impl DataAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, event: DataAuditEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[DataAuditEvent] {
        &self.events
    }

    pub fn events_by_kind(&self, kind: &str) -> Vec<&DataAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event.kind() == kind)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&DataAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for DataAuditLog {
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

    fn make_event(event_type: DataEventType) -> DataAuditEvent {
        DataAuditEvent::new(event_type, "agent-1", 1000, "test")
    }

    #[test]
    fn test_event_type_display_all_variants() {
        let variants = vec![
            DataEventType::QualityRuleCreated { rule_id: "qr-1".into(), dimension: "Completeness".into() },
            DataEventType::QualityRuleEvaluated { rule_id: "qr-1".into(), dataset_ref: "ds-1".into(), passed: true },
            DataEventType::QualityPolicyCreated { policy_id: "qp-1".into(), dataset_ref: "ds-1".into() },
            DataEventType::QualityPolicyViolated { policy_id: "qp-1".into(), violation_count: "3".into() },
            DataEventType::DataClassified { classification_id: "cls-1".into(), dataset_ref: "ds-1".into(), sensitivity: "Restricted".into() },
            DataEventType::DataClassificationReviewed { classification_id: "cls-1".into(), reviewer: "alice".into() },
            DataEventType::ClassificationPolicyCreated { policy_id: "cp-1".into() },
            DataEventType::LineageRecorded { record_id: "lr-1".into(), dataset_ref: "ds-1".into(), stage: "Source".into() },
            DataEventType::LineageChainVerified { chain_id: "lc-1".into(), status: "Complete".into() },
            DataEventType::LineagePolicyCreated { policy_id: "lp-1".into() },
            DataEventType::DataAccessRequested { request_id: "dar-1".into(), dataset_ref: "ds-1".into(), operation: "Read".into() },
            DataEventType::DataAccessGranted { request_id: "dar-1".into(), requester_id: "alice".into() },
            DataEventType::DataAccessDenied { request_id: "dar-2".into(), reason: "denied".into() },
            DataEventType::SchemaRegistered { schema_id: "sch-1".into(), dataset_ref: "ds-1".into(), version: "1.0.0".into() },
            DataEventType::SchemaCompatibilityChecked { schema_id: "sch-1".into(), compatibility: "FullyCompatible".into() },
            DataEventType::SchemaEvolutionPolicyCreated { policy_id: "sep-1".into() },
            DataEventType::CatalogEntryRegistered { entry_id: "ce-1".into(), dataset_ref: "ds-1".into() },
            DataEventType::CatalogEntryUpdated { entry_id: "ce-1".into(), field: "description".into() },
            DataEventType::CatalogEntryDeprecated { entry_id: "ce-1".into(), reason: "replaced".into() },
            DataEventType::CatalogGovernancePolicyCreated { policy_id: "cgp-1".into() },
            DataEventType::FreshnessPolicyCreated { policy_id: "fp-1".into(), dataset_ref: "ds-1".into() },
            DataEventType::FreshnessAssessed { assessment_id: "fa-1".into(), status: "Fresh".into() },
            DataEventType::FreshnessAlertRaised { alert_id: "fal-1".into(), dataset_ref: "ds-1".into(), severity: "Critical".into() },
            DataEventType::FreshnessAlertAcknowledged { alert_id: "fal-1".into(), acknowledged_by: "alice".into() },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
        assert_eq!(variants.len(), 24);
    }

    #[test]
    fn test_type_name_all_variants() {
        let names = vec![
            DataEventType::QualityRuleCreated { rule_id: "x".into(), dimension: "x".into() },
            DataEventType::QualityRuleEvaluated { rule_id: "x".into(), dataset_ref: "x".into(), passed: true },
            DataEventType::QualityPolicyCreated { policy_id: "x".into(), dataset_ref: "x".into() },
            DataEventType::QualityPolicyViolated { policy_id: "x".into(), violation_count: "x".into() },
            DataEventType::DataClassified { classification_id: "x".into(), dataset_ref: "x".into(), sensitivity: "x".into() },
            DataEventType::DataClassificationReviewed { classification_id: "x".into(), reviewer: "x".into() },
            DataEventType::ClassificationPolicyCreated { policy_id: "x".into() },
            DataEventType::LineageRecorded { record_id: "x".into(), dataset_ref: "x".into(), stage: "x".into() },
            DataEventType::LineageChainVerified { chain_id: "x".into(), status: "x".into() },
            DataEventType::LineagePolicyCreated { policy_id: "x".into() },
            DataEventType::DataAccessRequested { request_id: "x".into(), dataset_ref: "x".into(), operation: "x".into() },
            DataEventType::DataAccessGranted { request_id: "x".into(), requester_id: "x".into() },
            DataEventType::DataAccessDenied { request_id: "x".into(), reason: "x".into() },
            DataEventType::SchemaRegistered { schema_id: "x".into(), dataset_ref: "x".into(), version: "x".into() },
            DataEventType::SchemaCompatibilityChecked { schema_id: "x".into(), compatibility: "x".into() },
            DataEventType::SchemaEvolutionPolicyCreated { policy_id: "x".into() },
            DataEventType::CatalogEntryRegistered { entry_id: "x".into(), dataset_ref: "x".into() },
            DataEventType::CatalogEntryUpdated { entry_id: "x".into(), field: "x".into() },
            DataEventType::CatalogEntryDeprecated { entry_id: "x".into(), reason: "x".into() },
            DataEventType::CatalogGovernancePolicyCreated { policy_id: "x".into() },
            DataEventType::FreshnessPolicyCreated { policy_id: "x".into(), dataset_ref: "x".into() },
            DataEventType::FreshnessAssessed { assessment_id: "x".into(), status: "x".into() },
            DataEventType::FreshnessAlertRaised { alert_id: "x".into(), dataset_ref: "x".into(), severity: "x".into() },
            DataEventType::FreshnessAlertAcknowledged { alert_id: "x".into(), acknowledged_by: "x".into() },
        ];
        for n in &names {
            assert!(!n.type_name().is_empty());
        }
        assert_eq!(names.len(), 24);
    }

    #[test]
    fn test_kind_quality() {
        let e = DataEventType::QualityRuleCreated { rule_id: "x".into(), dimension: "x".into() };
        assert_eq!(e.kind(), "quality");
        let e = DataEventType::QualityRuleEvaluated { rule_id: "x".into(), dataset_ref: "x".into(), passed: true };
        assert_eq!(e.kind(), "quality");
        let e = DataEventType::QualityPolicyCreated { policy_id: "x".into(), dataset_ref: "x".into() };
        assert_eq!(e.kind(), "quality");
        let e = DataEventType::QualityPolicyViolated { policy_id: "x".into(), violation_count: "x".into() };
        assert_eq!(e.kind(), "quality");
    }

    #[test]
    fn test_kind_classification() {
        let e = DataEventType::DataClassified { classification_id: "x".into(), dataset_ref: "x".into(), sensitivity: "x".into() };
        assert_eq!(e.kind(), "classification");
        let e = DataEventType::DataClassificationReviewed { classification_id: "x".into(), reviewer: "x".into() };
        assert_eq!(e.kind(), "classification");
        let e = DataEventType::ClassificationPolicyCreated { policy_id: "x".into() };
        assert_eq!(e.kind(), "classification");
    }

    #[test]
    fn test_kind_lineage() {
        let e = DataEventType::LineageRecorded { record_id: "x".into(), dataset_ref: "x".into(), stage: "x".into() };
        assert_eq!(e.kind(), "lineage");
        let e = DataEventType::LineageChainVerified { chain_id: "x".into(), status: "x".into() };
        assert_eq!(e.kind(), "lineage");
        let e = DataEventType::LineagePolicyCreated { policy_id: "x".into() };
        assert_eq!(e.kind(), "lineage");
    }

    #[test]
    fn test_kind_access() {
        let e = DataEventType::DataAccessRequested { request_id: "x".into(), dataset_ref: "x".into(), operation: "x".into() };
        assert_eq!(e.kind(), "access");
        let e = DataEventType::DataAccessGranted { request_id: "x".into(), requester_id: "x".into() };
        assert_eq!(e.kind(), "access");
        let e = DataEventType::DataAccessDenied { request_id: "x".into(), reason: "x".into() };
        assert_eq!(e.kind(), "access");
    }

    #[test]
    fn test_kind_schema() {
        let e = DataEventType::SchemaRegistered { schema_id: "x".into(), dataset_ref: "x".into(), version: "x".into() };
        assert_eq!(e.kind(), "schema");
        let e = DataEventType::SchemaCompatibilityChecked { schema_id: "x".into(), compatibility: "x".into() };
        assert_eq!(e.kind(), "schema");
        let e = DataEventType::SchemaEvolutionPolicyCreated { policy_id: "x".into() };
        assert_eq!(e.kind(), "schema");
    }

    #[test]
    fn test_kind_catalog() {
        let e = DataEventType::CatalogEntryRegistered { entry_id: "x".into(), dataset_ref: "x".into() };
        assert_eq!(e.kind(), "catalog");
        let e = DataEventType::CatalogEntryUpdated { entry_id: "x".into(), field: "x".into() };
        assert_eq!(e.kind(), "catalog");
        let e = DataEventType::CatalogEntryDeprecated { entry_id: "x".into(), reason: "x".into() };
        assert_eq!(e.kind(), "catalog");
        let e = DataEventType::CatalogGovernancePolicyCreated { policy_id: "x".into() };
        assert_eq!(e.kind(), "catalog");
    }

    #[test]
    fn test_kind_freshness() {
        let e = DataEventType::FreshnessPolicyCreated { policy_id: "x".into(), dataset_ref: "x".into() };
        assert_eq!(e.kind(), "freshness");
        let e = DataEventType::FreshnessAssessed { assessment_id: "x".into(), status: "x".into() };
        assert_eq!(e.kind(), "freshness");
        let e = DataEventType::FreshnessAlertRaised { alert_id: "x".into(), dataset_ref: "x".into(), severity: "x".into() };
        assert_eq!(e.kind(), "freshness");
        let e = DataEventType::FreshnessAlertAcknowledged { alert_id: "x".into(), acknowledged_by: "x".into() };
        assert_eq!(e.kind(), "freshness");
    }

    #[test]
    fn test_audit_event_construction() {
        let event = make_event(DataEventType::QualityRuleCreated {
            rule_id: "qr-1".into(),
            dimension: "Completeness".into(),
        });
        assert_eq!(event.actor, "agent-1");
        assert_eq!(event.timestamp, 1000);
    }

    #[test]
    fn test_audit_log_record_and_retrieve() {
        let mut log = DataAuditLog::new();
        log.record(make_event(DataEventType::QualityRuleCreated {
            rule_id: "qr-1".into(),
            dimension: "Completeness".into(),
        }));
        log.record(make_event(DataEventType::DataClassified {
            classification_id: "cls-1".into(),
            dataset_ref: "ds-1".into(),
            sensitivity: "Restricted".into(),
        }));
        assert_eq!(log.event_count(), 2);
        assert_eq!(log.events().len(), 2);
    }

    #[test]
    fn test_audit_log_events_by_kind() {
        let mut log = DataAuditLog::new();
        log.record(make_event(DataEventType::QualityRuleCreated {
            rule_id: "qr-1".into(),
            dimension: "Completeness".into(),
        }));
        log.record(make_event(DataEventType::QualityPolicyViolated {
            policy_id: "qp-1".into(),
            violation_count: "5".into(),
        }));
        log.record(make_event(DataEventType::DataClassified {
            classification_id: "cls-1".into(),
            dataset_ref: "ds-1".into(),
            sensitivity: "Internal".into(),
        }));
        let quality = log.events_by_kind("quality");
        assert_eq!(quality.len(), 2);
        let classification = log.events_by_kind("classification");
        assert_eq!(classification.len(), 1);
    }

    #[test]
    fn test_audit_log_since() {
        let mut log = DataAuditLog::new();
        log.record(DataAuditEvent::new(
            DataEventType::LineageRecorded { record_id: "lr-1".into(), dataset_ref: "ds-1".into(), stage: "Source".into() },
            "agent-1", 500, "early",
        ));
        log.record(DataAuditEvent::new(
            DataEventType::LineageRecorded { record_id: "lr-2".into(), dataset_ref: "ds-1".into(), stage: "Sink".into() },
            "agent-1", 1500, "later",
        ));
        let recent = log.since(1000);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_audit_log_default() {
        let log = DataAuditLog::default();
        assert_eq!(log.event_count(), 0);
    }
}
