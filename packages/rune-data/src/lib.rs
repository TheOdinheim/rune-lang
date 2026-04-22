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
