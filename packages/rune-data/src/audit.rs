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

    // ── Layer 2 engine variants ─────────────────────────────────────
    DatasetHashComputed { dataset_ref: String, hash: String },
    SchemaHashComputed { schema_id: String, hash: String },
    LineageHashComputed { record_id: String, hash: String },
    DataHashChainAppended { chain_id: String, link_hash: String },
    DataHashChainVerified { chain_id: String, valid: bool },
    QualityRuleEvaluatedEngine { rule_id: String, dataset_ref: String, pass_rate: String },
    QualityPolicyEvaluatedEngine { policy_id: String, dataset_ref: String, minimum_met: bool },
    DataClassificationInferred { classification_id: String, method: String },
    ClassificationReviewChecked { classification_id: String, review_due: bool },
    ClassificationComplianceChecked { classification_id: String, compliant: bool },
    LineageChainVerifiedEngine { chain_id: String, status: String },
    LineageGapDetectedEngine { chain_id: String, gap_type: String },
    LineageRecordComplianceChecked { record_id: String, compliant: bool },
    DataAccessEvaluatedEngine { request_id: String, decision: String },
    SchemaCompatibilityCheckedEngine { schema_id: String, result: String },
    SchemaEvolutionDecided { schema_id: String, decision: String },
    FreshnessEvaluatedEngine { assessment_id: String, status: String },
    FreshnessAlertGenerated { alert_id: String, severity: String },
    DataMetricsComputed { snapshot_id: String, computed_at: i64 },

    // ── Layer 3 governance variants ─────────────────────────────────
    DataGovernanceBackendChanged { backend_id: String, backend_type: String },
    StoredQualityRuleCreated { rule_id: String, stored_at: i64 },
    StoredClassificationCreated { classification_id: String, stored_at: i64 },
    StoredLineageRecordCreated { record_id: String, lineage_hash: String },
    StoredSchemaRecordCreated { schema_id: String, schema_hash: String },
    StoredCatalogEntryCreated { entry_id: String, completeness_score: String },
    QualityGovernanceEvaluated { dataset_ref: String, decision: String },
    QualityPipelineBlocked { dataset_ref: String, reason: String },
    LineageGovernanceEvaluated { dataset_ref: String, decision: String },
    LineageChainVerifiedGov { chain_id: String, decision: String },
    SchemaGovernanceEvaluated { schema_id: String, decision: String },
    SchemaHealthAssessedGov { schema_id: String, status: String },
    DataGovernanceExported { format: String, record_count: String },
    DataGovernanceExportFailed { format: String, reason: String },
    DataGovernanceMetricsComputed { snapshot_id: String, computed_at: i64 },
    DataGovernanceSubscriberRegistered { subscriber_id: String },
    DataGovernanceSubscriberRemoved { subscriber_id: String },
    DataGovernanceEventPublished { event_type: String, dataset_ref: String },
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
            // Layer 2 engine variants
            Self::DatasetHashComputed { dataset_ref, hash } => {
                write!(f, "DatasetHashComputed(dataset={dataset_ref}, hash={hash})")
            }
            Self::SchemaHashComputed { schema_id, hash } => {
                write!(f, "SchemaHashComputed({schema_id}, hash={hash})")
            }
            Self::LineageHashComputed { record_id, hash } => {
                write!(f, "LineageHashComputed({record_id}, hash={hash})")
            }
            Self::DataHashChainAppended { chain_id, link_hash } => {
                write!(f, "DataHashChainAppended({chain_id}, link={link_hash})")
            }
            Self::DataHashChainVerified { chain_id, valid } => {
                write!(f, "DataHashChainVerified({chain_id}, valid={valid})")
            }
            Self::QualityRuleEvaluatedEngine { rule_id, dataset_ref, pass_rate } => {
                write!(f, "QualityRuleEvaluatedEngine({rule_id}, dataset={dataset_ref}, rate={pass_rate})")
            }
            Self::QualityPolicyEvaluatedEngine { policy_id, dataset_ref, minimum_met } => {
                write!(f, "QualityPolicyEvaluatedEngine({policy_id}, dataset={dataset_ref}, met={minimum_met})")
            }
            Self::DataClassificationInferred { classification_id, method } => {
                write!(f, "DataClassificationInferred({classification_id}, method={method})")
            }
            Self::ClassificationReviewChecked { classification_id, review_due } => {
                write!(f, "ClassificationReviewChecked({classification_id}, due={review_due})")
            }
            Self::ClassificationComplianceChecked { classification_id, compliant } => {
                write!(f, "ClassificationComplianceChecked({classification_id}, compliant={compliant})")
            }
            Self::LineageChainVerifiedEngine { chain_id, status } => {
                write!(f, "LineageChainVerifiedEngine({chain_id}, status={status})")
            }
            Self::LineageGapDetectedEngine { chain_id, gap_type } => {
                write!(f, "LineageGapDetectedEngine({chain_id}, gap={gap_type})")
            }
            Self::LineageRecordComplianceChecked { record_id, compliant } => {
                write!(f, "LineageRecordComplianceChecked({record_id}, compliant={compliant})")
            }
            Self::DataAccessEvaluatedEngine { request_id, decision } => {
                write!(f, "DataAccessEvaluatedEngine({request_id}, decision={decision})")
            }
            Self::SchemaCompatibilityCheckedEngine { schema_id, result } => {
                write!(f, "SchemaCompatibilityCheckedEngine({schema_id}, result={result})")
            }
            Self::SchemaEvolutionDecided { schema_id, decision } => {
                write!(f, "SchemaEvolutionDecided({schema_id}, decision={decision})")
            }
            Self::FreshnessEvaluatedEngine { assessment_id, status } => {
                write!(f, "FreshnessEvaluatedEngine({assessment_id}, status={status})")
            }
            Self::FreshnessAlertGenerated { alert_id, severity } => {
                write!(f, "FreshnessAlertGenerated({alert_id}, severity={severity})")
            }
            Self::DataMetricsComputed { snapshot_id, computed_at } => {
                write!(f, "DataMetricsComputed({snapshot_id}, at={computed_at})")
            }
            // Layer 3 governance variants
            Self::DataGovernanceBackendChanged { backend_id, backend_type } => {
                write!(f, "DataGovernanceBackendChanged({backend_id}, type={backend_type})")
            }
            Self::StoredQualityRuleCreated { rule_id, stored_at } => {
                write!(f, "StoredQualityRuleCreated({rule_id}, at={stored_at})")
            }
            Self::StoredClassificationCreated { classification_id, stored_at } => {
                write!(f, "StoredClassificationCreated({classification_id}, at={stored_at})")
            }
            Self::StoredLineageRecordCreated { record_id, lineage_hash } => {
                write!(f, "StoredLineageRecordCreated({record_id}, hash={lineage_hash})")
            }
            Self::StoredSchemaRecordCreated { schema_id, schema_hash } => {
                write!(f, "StoredSchemaRecordCreated({schema_id}, hash={schema_hash})")
            }
            Self::StoredCatalogEntryCreated { entry_id, completeness_score } => {
                write!(f, "StoredCatalogEntryCreated({entry_id}, score={completeness_score})")
            }
            Self::QualityGovernanceEvaluated { dataset_ref, decision } => {
                write!(f, "QualityGovernanceEvaluated(dataset={dataset_ref}, decision={decision})")
            }
            Self::QualityPipelineBlocked { dataset_ref, reason } => {
                write!(f, "QualityPipelineBlocked(dataset={dataset_ref}): {reason}")
            }
            Self::LineageGovernanceEvaluated { dataset_ref, decision } => {
                write!(f, "LineageGovernanceEvaluated(dataset={dataset_ref}, decision={decision})")
            }
            Self::LineageChainVerifiedGov { chain_id, decision } => {
                write!(f, "LineageChainVerifiedGov({chain_id}, decision={decision})")
            }
            Self::SchemaGovernanceEvaluated { schema_id, decision } => {
                write!(f, "SchemaGovernanceEvaluated({schema_id}, decision={decision})")
            }
            Self::SchemaHealthAssessedGov { schema_id, status } => {
                write!(f, "SchemaHealthAssessedGov({schema_id}, status={status})")
            }
            Self::DataGovernanceExported { format, record_count } => {
                write!(f, "DataGovernanceExported(format={format}, records={record_count})")
            }
            Self::DataGovernanceExportFailed { format, reason } => {
                write!(f, "DataGovernanceExportFailed(format={format}): {reason}")
            }
            Self::DataGovernanceMetricsComputed { snapshot_id, computed_at } => {
                write!(f, "DataGovernanceMetricsComputed({snapshot_id}, at={computed_at})")
            }
            Self::DataGovernanceSubscriberRegistered { subscriber_id } => {
                write!(f, "DataGovernanceSubscriberRegistered({subscriber_id})")
            }
            Self::DataGovernanceSubscriberRemoved { subscriber_id } => {
                write!(f, "DataGovernanceSubscriberRemoved({subscriber_id})")
            }
            Self::DataGovernanceEventPublished { event_type, dataset_ref } => {
                write!(f, "DataGovernanceEventPublished(type={event_type}, dataset={dataset_ref})")
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
            // Layer 2 engine variants
            Self::DatasetHashComputed { .. } => "DatasetHashComputed",
            Self::SchemaHashComputed { .. } => "SchemaHashComputed",
            Self::LineageHashComputed { .. } => "LineageHashComputed",
            Self::DataHashChainAppended { .. } => "DataHashChainAppended",
            Self::DataHashChainVerified { .. } => "DataHashChainVerified",
            Self::QualityRuleEvaluatedEngine { .. } => "QualityRuleEvaluatedEngine",
            Self::QualityPolicyEvaluatedEngine { .. } => "QualityPolicyEvaluatedEngine",
            Self::DataClassificationInferred { .. } => "DataClassificationInferred",
            Self::ClassificationReviewChecked { .. } => "ClassificationReviewChecked",
            Self::ClassificationComplianceChecked { .. } => "ClassificationComplianceChecked",
            Self::LineageChainVerifiedEngine { .. } => "LineageChainVerifiedEngine",
            Self::LineageGapDetectedEngine { .. } => "LineageGapDetectedEngine",
            Self::LineageRecordComplianceChecked { .. } => "LineageRecordComplianceChecked",
            Self::DataAccessEvaluatedEngine { .. } => "DataAccessEvaluatedEngine",
            Self::SchemaCompatibilityCheckedEngine { .. } => "SchemaCompatibilityCheckedEngine",
            Self::SchemaEvolutionDecided { .. } => "SchemaEvolutionDecided",
            Self::FreshnessEvaluatedEngine { .. } => "FreshnessEvaluatedEngine",
            Self::FreshnessAlertGenerated { .. } => "FreshnessAlertGenerated",
            Self::DataMetricsComputed { .. } => "DataMetricsComputed",
            // Layer 3 governance variants
            Self::DataGovernanceBackendChanged { .. } => "DataGovernanceBackendChanged",
            Self::StoredQualityRuleCreated { .. } => "StoredQualityRuleCreated",
            Self::StoredClassificationCreated { .. } => "StoredClassificationCreated",
            Self::StoredLineageRecordCreated { .. } => "StoredLineageRecordCreated",
            Self::StoredSchemaRecordCreated { .. } => "StoredSchemaRecordCreated",
            Self::StoredCatalogEntryCreated { .. } => "StoredCatalogEntryCreated",
            Self::QualityGovernanceEvaluated { .. } => "QualityGovernanceEvaluated",
            Self::QualityPipelineBlocked { .. } => "QualityPipelineBlocked",
            Self::LineageGovernanceEvaluated { .. } => "LineageGovernanceEvaluated",
            Self::LineageChainVerifiedGov { .. } => "LineageChainVerifiedGov",
            Self::SchemaGovernanceEvaluated { .. } => "SchemaGovernanceEvaluated",
            Self::SchemaHealthAssessedGov { .. } => "SchemaHealthAssessedGov",
            Self::DataGovernanceExported { .. } => "DataGovernanceExported",
            Self::DataGovernanceExportFailed { .. } => "DataGovernanceExportFailed",
            Self::DataGovernanceMetricsComputed { .. } => "DataGovernanceMetricsComputed",
            Self::DataGovernanceSubscriberRegistered { .. } => "DataGovernanceSubscriberRegistered",
            Self::DataGovernanceSubscriberRemoved { .. } => "DataGovernanceSubscriberRemoved",
            Self::DataGovernanceEventPublished { .. } => "DataGovernanceEventPublished",
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
            // Layer 2 engine kinds
            Self::DatasetHashComputed { .. }
            | Self::SchemaHashComputed { .. }
            | Self::LineageHashComputed { .. }
            | Self::DataHashChainAppended { .. }
            | Self::DataHashChainVerified { .. } => "hashing",
            Self::QualityRuleEvaluatedEngine { .. }
            | Self::QualityPolicyEvaluatedEngine { .. } => "quality",
            Self::DataClassificationInferred { .. }
            | Self::ClassificationReviewChecked { .. }
            | Self::ClassificationComplianceChecked { .. } => "classification",
            Self::LineageChainVerifiedEngine { .. }
            | Self::LineageGapDetectedEngine { .. }
            | Self::LineageRecordComplianceChecked { .. } => "lineage",
            Self::DataAccessEvaluatedEngine { .. } => "access",
            Self::SchemaCompatibilityCheckedEngine { .. }
            | Self::SchemaEvolutionDecided { .. } => "schema",
            Self::FreshnessEvaluatedEngine { .. }
            | Self::FreshnessAlertGenerated { .. } => "freshness",
            Self::DataMetricsComputed { .. } => "metrics",
            // Layer 3 governance kinds
            Self::DataGovernanceBackendChanged { .. }
            | Self::StoredQualityRuleCreated { .. }
            | Self::StoredClassificationCreated { .. }
            | Self::StoredLineageRecordCreated { .. }
            | Self::StoredSchemaRecordCreated { .. }
            | Self::StoredCatalogEntryCreated { .. } => "backend",
            Self::QualityGovernanceEvaluated { .. }
            | Self::QualityPipelineBlocked { .. } => "quality",
            Self::LineageGovernanceEvaluated { .. }
            | Self::LineageChainVerifiedGov { .. } => "lineage",
            Self::SchemaGovernanceEvaluated { .. }
            | Self::SchemaHealthAssessedGov { .. } => "schema",
            Self::DataGovernanceExported { .. }
            | Self::DataGovernanceExportFailed { .. } => "export",
            Self::DataGovernanceMetricsComputed { .. } => "metrics",
            Self::DataGovernanceSubscriberRegistered { .. }
            | Self::DataGovernanceSubscriberRemoved { .. }
            | Self::DataGovernanceEventPublished { .. } => "streaming",
        }
    }

    pub fn is_engine_event(&self) -> bool {
        matches!(
            self,
            Self::DatasetHashComputed { .. }
            | Self::SchemaHashComputed { .. }
            | Self::LineageHashComputed { .. }
            | Self::DataHashChainAppended { .. }
            | Self::DataHashChainVerified { .. }
            | Self::QualityRuleEvaluatedEngine { .. }
            | Self::QualityPolicyEvaluatedEngine { .. }
            | Self::DataClassificationInferred { .. }
            | Self::ClassificationReviewChecked { .. }
            | Self::ClassificationComplianceChecked { .. }
            | Self::LineageChainVerifiedEngine { .. }
            | Self::LineageGapDetectedEngine { .. }
            | Self::LineageRecordComplianceChecked { .. }
            | Self::DataAccessEvaluatedEngine { .. }
            | Self::SchemaCompatibilityCheckedEngine { .. }
            | Self::SchemaEvolutionDecided { .. }
            | Self::FreshnessEvaluatedEngine { .. }
            | Self::FreshnessAlertGenerated { .. }
            | Self::DataMetricsComputed { .. }
        )
    }

    pub fn is_governance_event(&self) -> bool {
        matches!(
            self,
            Self::DataGovernanceBackendChanged { .. }
            | Self::StoredQualityRuleCreated { .. }
            | Self::StoredClassificationCreated { .. }
            | Self::StoredLineageRecordCreated { .. }
            | Self::StoredSchemaRecordCreated { .. }
            | Self::StoredCatalogEntryCreated { .. }
            | Self::QualityGovernanceEvaluated { .. }
            | Self::QualityPipelineBlocked { .. }
            | Self::LineageGovernanceEvaluated { .. }
            | Self::LineageChainVerifiedGov { .. }
            | Self::SchemaGovernanceEvaluated { .. }
            | Self::SchemaHealthAssessedGov { .. }
            | Self::DataGovernanceExported { .. }
            | Self::DataGovernanceExportFailed { .. }
            | Self::DataGovernanceMetricsComputed { .. }
            | Self::DataGovernanceSubscriberRegistered { .. }
            | Self::DataGovernanceSubscriberRemoved { .. }
            | Self::DataGovernanceEventPublished { .. }
        )
    }

    pub fn is_backend_event(&self) -> bool {
        self.kind() == "backend"
    }

    pub fn is_export_event(&self) -> bool {
        self.kind() == "export"
    }

    pub fn is_streaming_event(&self) -> bool {
        self.kind() == "streaming"
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
        let variants: Vec<DataEventType> = vec![
            // L1 (24)
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
            // L2 engine (19)
            DataEventType::DatasetHashComputed { dataset_ref: "ds-1".into(), hash: "abc".into() },
            DataEventType::SchemaHashComputed { schema_id: "sch-1".into(), hash: "def".into() },
            DataEventType::LineageHashComputed { record_id: "lr-1".into(), hash: "ghi".into() },
            DataEventType::DataHashChainAppended { chain_id: "hc-1".into(), link_hash: "jkl".into() },
            DataEventType::DataHashChainVerified { chain_id: "hc-1".into(), valid: true },
            DataEventType::QualityRuleEvaluatedEngine { rule_id: "qr-1".into(), dataset_ref: "ds-1".into(), pass_rate: "0.95".into() },
            DataEventType::QualityPolicyEvaluatedEngine { policy_id: "qp-1".into(), dataset_ref: "ds-1".into(), minimum_met: true },
            DataEventType::DataClassificationInferred { classification_id: "cls-1".into(), method: "Automated".into() },
            DataEventType::ClassificationReviewChecked { classification_id: "cls-1".into(), review_due: false },
            DataEventType::ClassificationComplianceChecked { classification_id: "cls-1".into(), compliant: true },
            DataEventType::LineageChainVerifiedEngine { chain_id: "lc-1".into(), status: "Complete".into() },
            DataEventType::LineageGapDetectedEngine { chain_id: "lc-1".into(), gap_type: "MissingRecord".into() },
            DataEventType::LineageRecordComplianceChecked { record_id: "lr-1".into(), compliant: true },
            DataEventType::DataAccessEvaluatedEngine { request_id: "dar-1".into(), decision: "Granted".into() },
            DataEventType::SchemaCompatibilityCheckedEngine { schema_id: "sch-1".into(), result: "FullyCompatible".into() },
            DataEventType::SchemaEvolutionDecided { schema_id: "sch-1".into(), decision: "Approved".into() },
            DataEventType::FreshnessEvaluatedEngine { assessment_id: "fa-1".into(), status: "Fresh".into() },
            DataEventType::FreshnessAlertGenerated { alert_id: "fal-1".into(), severity: "Warning".into() },
            DataEventType::DataMetricsComputed { snapshot_id: "snap-1".into(), computed_at: 5000 },
            // L3 governance (18)
            DataEventType::DataGovernanceBackendChanged { backend_id: "be-1".into(), backend_type: "InMemory".into() },
            DataEventType::StoredQualityRuleCreated { rule_id: "qr-1".into(), stored_at: 2000 },
            DataEventType::StoredClassificationCreated { classification_id: "cls-1".into(), stored_at: 2000 },
            DataEventType::StoredLineageRecordCreated { record_id: "lr-1".into(), lineage_hash: "abc".into() },
            DataEventType::StoredSchemaRecordCreated { schema_id: "sch-1".into(), schema_hash: "def".into() },
            DataEventType::StoredCatalogEntryCreated { entry_id: "ce-1".into(), completeness_score: "0.80".into() },
            DataEventType::QualityGovernanceEvaluated { dataset_ref: "ds-1".into(), decision: "QualityMet".into() },
            DataEventType::QualityPipelineBlocked { dataset_ref: "ds-1".into(), reason: "below threshold".into() },
            DataEventType::LineageGovernanceEvaluated { dataset_ref: "ds-1".into(), decision: "Compliant".into() },
            DataEventType::LineageChainVerifiedGov { chain_id: "lc-1".into(), decision: "Compliant".into() },
            DataEventType::SchemaGovernanceEvaluated { schema_id: "sch-1".into(), decision: "Approved".into() },
            DataEventType::SchemaHealthAssessedGov { schema_id: "sch-1".into(), status: "Healthy".into() },
            DataEventType::DataGovernanceExported { format: "json".into(), record_count: "10".into() },
            DataEventType::DataGovernanceExportFailed { format: "json".into(), reason: "IO error".into() },
            DataEventType::DataGovernanceMetricsComputed { snapshot_id: "snap-1".into(), computed_at: 5000 },
            DataEventType::DataGovernanceSubscriberRegistered { subscriber_id: "sub-1".into() },
            DataEventType::DataGovernanceSubscriberRemoved { subscriber_id: "sub-1".into() },
            DataEventType::DataGovernanceEventPublished { event_type: "QualityRuleStored".into(), dataset_ref: "ds-1".into() },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
        assert_eq!(variants.len(), 61);
    }

    #[test]
    fn test_type_name_all_variants() {
        let names: Vec<DataEventType> = vec![
            // L1 (24)
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
            // L2 engine (19)
            DataEventType::DatasetHashComputed { dataset_ref: "x".into(), hash: "x".into() },
            DataEventType::SchemaHashComputed { schema_id: "x".into(), hash: "x".into() },
            DataEventType::LineageHashComputed { record_id: "x".into(), hash: "x".into() },
            DataEventType::DataHashChainAppended { chain_id: "x".into(), link_hash: "x".into() },
            DataEventType::DataHashChainVerified { chain_id: "x".into(), valid: true },
            DataEventType::QualityRuleEvaluatedEngine { rule_id: "x".into(), dataset_ref: "x".into(), pass_rate: "x".into() },
            DataEventType::QualityPolicyEvaluatedEngine { policy_id: "x".into(), dataset_ref: "x".into(), minimum_met: true },
            DataEventType::DataClassificationInferred { classification_id: "x".into(), method: "x".into() },
            DataEventType::ClassificationReviewChecked { classification_id: "x".into(), review_due: false },
            DataEventType::ClassificationComplianceChecked { classification_id: "x".into(), compliant: true },
            DataEventType::LineageChainVerifiedEngine { chain_id: "x".into(), status: "x".into() },
            DataEventType::LineageGapDetectedEngine { chain_id: "x".into(), gap_type: "x".into() },
            DataEventType::LineageRecordComplianceChecked { record_id: "x".into(), compliant: true },
            DataEventType::DataAccessEvaluatedEngine { request_id: "x".into(), decision: "x".into() },
            DataEventType::SchemaCompatibilityCheckedEngine { schema_id: "x".into(), result: "x".into() },
            DataEventType::SchemaEvolutionDecided { schema_id: "x".into(), decision: "x".into() },
            DataEventType::FreshnessEvaluatedEngine { assessment_id: "x".into(), status: "x".into() },
            DataEventType::FreshnessAlertGenerated { alert_id: "x".into(), severity: "x".into() },
            DataEventType::DataMetricsComputed { snapshot_id: "x".into(), computed_at: 0 },
            // L3 governance (18)
            DataEventType::DataGovernanceBackendChanged { backend_id: "x".into(), backend_type: "x".into() },
            DataEventType::StoredQualityRuleCreated { rule_id: "x".into(), stored_at: 0 },
            DataEventType::StoredClassificationCreated { classification_id: "x".into(), stored_at: 0 },
            DataEventType::StoredLineageRecordCreated { record_id: "x".into(), lineage_hash: "x".into() },
            DataEventType::StoredSchemaRecordCreated { schema_id: "x".into(), schema_hash: "x".into() },
            DataEventType::StoredCatalogEntryCreated { entry_id: "x".into(), completeness_score: "x".into() },
            DataEventType::QualityGovernanceEvaluated { dataset_ref: "x".into(), decision: "x".into() },
            DataEventType::QualityPipelineBlocked { dataset_ref: "x".into(), reason: "x".into() },
            DataEventType::LineageGovernanceEvaluated { dataset_ref: "x".into(), decision: "x".into() },
            DataEventType::LineageChainVerifiedGov { chain_id: "x".into(), decision: "x".into() },
            DataEventType::SchemaGovernanceEvaluated { schema_id: "x".into(), decision: "x".into() },
            DataEventType::SchemaHealthAssessedGov { schema_id: "x".into(), status: "x".into() },
            DataEventType::DataGovernanceExported { format: "x".into(), record_count: "x".into() },
            DataEventType::DataGovernanceExportFailed { format: "x".into(), reason: "x".into() },
            DataEventType::DataGovernanceMetricsComputed { snapshot_id: "x".into(), computed_at: 0 },
            DataEventType::DataGovernanceSubscriberRegistered { subscriber_id: "x".into() },
            DataEventType::DataGovernanceSubscriberRemoved { subscriber_id: "x".into() },
            DataEventType::DataGovernanceEventPublished { event_type: "x".into(), dataset_ref: "x".into() },
        ];
        for n in &names {
            assert!(!n.type_name().is_empty());
        }
        assert_eq!(names.len(), 61);
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

    #[test]
    fn test_kind_hashing() {
        let e = DataEventType::DatasetHashComputed { dataset_ref: "x".into(), hash: "x".into() };
        assert_eq!(e.kind(), "hashing");
        let e = DataEventType::DataHashChainVerified { chain_id: "x".into(), valid: true };
        assert_eq!(e.kind(), "hashing");
    }

    #[test]
    fn test_kind_backend() {
        let e = DataEventType::DataGovernanceBackendChanged { backend_id: "x".into(), backend_type: "x".into() };
        assert_eq!(e.kind(), "backend");
        let e = DataEventType::StoredQualityRuleCreated { rule_id: "x".into(), stored_at: 0 };
        assert_eq!(e.kind(), "backend");
    }

    #[test]
    fn test_kind_export() {
        let e = DataEventType::DataGovernanceExported { format: "x".into(), record_count: "x".into() };
        assert_eq!(e.kind(), "export");
        let e = DataEventType::DataGovernanceExportFailed { format: "x".into(), reason: "x".into() };
        assert_eq!(e.kind(), "export");
    }

    #[test]
    fn test_kind_streaming() {
        let e = DataEventType::DataGovernanceSubscriberRegistered { subscriber_id: "x".into() };
        assert_eq!(e.kind(), "streaming");
        let e = DataEventType::DataGovernanceEventPublished { event_type: "x".into(), dataset_ref: "x".into() };
        assert_eq!(e.kind(), "streaming");
    }

    #[test]
    fn test_kind_metrics() {
        let e = DataEventType::DataMetricsComputed { snapshot_id: "x".into(), computed_at: 0 };
        assert_eq!(e.kind(), "metrics");
        let e = DataEventType::DataGovernanceMetricsComputed { snapshot_id: "x".into(), computed_at: 0 };
        assert_eq!(e.kind(), "metrics");
    }

    #[test]
    fn test_is_engine_event() {
        let engine = DataEventType::QualityRuleEvaluatedEngine { rule_id: "x".into(), dataset_ref: "x".into(), pass_rate: "x".into() };
        assert!(engine.is_engine_event());
        let l1 = DataEventType::QualityRuleCreated { rule_id: "x".into(), dimension: "x".into() };
        assert!(!l1.is_engine_event());
        let l3 = DataEventType::QualityGovernanceEvaluated { dataset_ref: "x".into(), decision: "x".into() };
        assert!(!l3.is_engine_event());
    }

    #[test]
    fn test_is_governance_event() {
        let gov = DataEventType::QualityGovernanceEvaluated { dataset_ref: "x".into(), decision: "x".into() };
        assert!(gov.is_governance_event());
        let l1 = DataEventType::QualityRuleCreated { rule_id: "x".into(), dimension: "x".into() };
        assert!(!l1.is_governance_event());
        let engine = DataEventType::QualityRuleEvaluatedEngine { rule_id: "x".into(), dataset_ref: "x".into(), pass_rate: "x".into() };
        assert!(!engine.is_governance_event());
    }

    #[test]
    fn test_is_backend_event() {
        let be = DataEventType::StoredQualityRuleCreated { rule_id: "x".into(), stored_at: 0 };
        assert!(be.is_backend_event());
        let non_be = DataEventType::QualityRuleCreated { rule_id: "x".into(), dimension: "x".into() };
        assert!(!non_be.is_backend_event());
    }

    #[test]
    fn test_is_export_event() {
        let exp = DataEventType::DataGovernanceExported { format: "x".into(), record_count: "x".into() };
        assert!(exp.is_export_event());
    }

    #[test]
    fn test_is_streaming_event() {
        let stream = DataEventType::DataGovernanceSubscriberRegistered { subscriber_id: "x".into() };
        assert!(stream.is_streaming_event());
    }
}
