// ═══════════════════════════════════════════════════════════════════════
// rune-data — Data pipeline governance library for the RUNE language.
// Governs data quality rules, classification and sensitivity labeling,
// lineage through transformation stages, access governance, schema
// evolution, data catalog integration, and freshness monitoring.
// ═══════════════════════════════════════════════════════════════════════

// Layer 1 modules
pub mod access;
pub mod audit;
pub mod catalog;
pub mod classification;
pub mod error;
pub mod freshness;
pub mod lineage;
pub mod quality;
pub mod schema;

// Layer 2 modules
pub mod access_evaluator;
pub mod classification_engine;
pub mod data_hash;
pub mod data_metrics;
pub mod freshness_evaluator;
pub mod lineage_verifier;
pub mod quality_engine;
pub mod schema_checker;

// Layer 3 modules
pub mod backend;
pub mod data_export;
pub mod data_governance_metrics;
pub mod data_stream;
pub mod lineage_governor;
pub mod quality_governor;
pub mod schema_governor;

// ── Re-exports: Quality ──────────────────────────────────────────────

pub use quality::{
    DataQualityDimension, DataQualityPolicy, DataQualityResult, DataQualityRule,
    QualityExpectation, QualitySeverity,
};

// ── Re-exports: Classification ───────────────────────────────────────

pub use classification::{
    ClassificationMethod, ClassificationPolicy, DataCategory, DataCategoryType,
    DataClassification, DataSensitivity,
};

// ── Re-exports: Lineage ──────────────────────────────────────────────

pub use lineage::{LineageChain, LineageChainStatus, LineagePolicy, LineageRecord, LineageStage};

// ── Re-exports: Access ───────────────────────────────────────────────

pub use access::{
    DataAccessDecision, DataAccessPolicy, DataAccessRequest, DataOperation,
};

// ── Re-exports: Schema ───────────────────────────────────────────────

pub use schema::{
    SchemaBreakingChange, SchemaChangeType, SchemaCompatibility, SchemaEvolutionPolicy,
    SchemaField, SchemaFormat, SchemaRecord,
};

// ── Re-exports: Catalog ──────────────────────────────────────────────

pub use catalog::{CatalogEntry, CatalogEntryStatus, CatalogGovernancePolicy};

// ── Re-exports: Freshness ────────────────────────────────────────────

pub use freshness::{
    FreshnessAlert, FreshnessAssessment, FreshnessPolicy, FreshnessStatus, UpdateFrequency,
};

// ── Re-exports: Audit ────────────────────────────────────────────────

pub use audit::{DataAuditEvent, DataAuditLog, DataEventType};

// ── Re-exports: Error ────────────────────────────────────────────────

pub use error::DataError;

// ── Layer 2 re-exports ──────────────────────────────────────────────

pub use access_evaluator::{AccessCheck, AccessEvaluationReport, DataAccessEvaluator};

pub use classification_engine::{
    ClassificationComplianceResult, ClassificationEngine, ClassificationReviewResult,
};

pub use data_hash::{hash_dataset_ref, hash_lineage_record, hash_schema_record, verify_hash, DataHashChain, DataHashChainLink};

pub use data_metrics::{DataMetricSnapshot, DataMetrics};

pub use freshness_evaluator::FreshnessEvaluator;

pub use lineage_verifier::{
    LineageGap, LineageGapType, LineageVerificationResult, LineageVerifier,
    RecordComplianceResult,
};

pub use quality_engine::{PolicyEvaluation, QualityEngine, QualityRuleEvaluation};

pub use schema_checker::{SchemaCompatibilityChecker, SchemaEvolutionDecision};

// ── Layer 3 re-exports ─────────────────────────────────────────────

pub use backend::{
    DataBackendInfo, DataGovernanceBackend, InMemoryDataGovernanceBackend,
    StoredCatalogEntry, StoredClassification, StoredFreshnessAssessment,
    StoredLineageRecord, StoredQualityRule, StoredSchemaRecord,
};

pub use quality_governor::{
    InMemoryQualityGovernor, NullQualityGovernor, QualityGovernanceDecision,
    QualityGovernanceResult, QualityGovernor,
};

pub use lineage_governor::{
    InMemoryLineageGovernor, LineageGovernanceDecision, LineageGovernanceResult,
    LineageGovernor, NullLineageGovernor,
};

pub use schema_governor::{
    InMemorySchemaGovernor, NullSchemaGovernor, SchemaGovernanceDecision,
    SchemaGovernor, SchemaHealthAssessment, SchemaHealthStatus,
};

pub use data_export::{
    DataCatalogExporter, DataGovernanceExporter, DataLineageExporter,
    DataQualityReportExporter, GdprDataMappingExporter, JsonDataExporter,
};

pub use data_stream::{
    DataGovernanceEventCollector, DataGovernanceEventSubscriber,
    DataGovernanceEventSubscriberRegistry, DataGovernanceLifecycleEvent,
    DataGovernanceLifecycleEventType, FilteredDataGovernanceEventSubscriber,
};

pub use data_governance_metrics::{
    DataGovernanceMetricSnapshot, DataGovernanceMetricsCollector,
    InMemoryDataGovernanceMetricsCollector, NullDataGovernanceMetricsCollector,
};
