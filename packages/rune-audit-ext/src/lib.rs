// ═══════════════════════════════════════════════════════════════════════
// rune-audit-ext — unified audit store, cross-crate event correlation,
// query engine, export formats, retention enforcement, chain
// integrity verification, and event enrichment.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod correlation;
pub mod enrichment;
pub mod error;
pub mod event;
pub mod export;
pub mod integrity;
pub mod query;
pub mod retention;
pub mod store;
pub mod timeline;

pub use audit::{AuditExtAuditEvent, AuditExtEventType, AuditExtLog};
pub use correlation::{CorrelationChain, CorrelationEngine};
pub use enrichment::{Enrichment, EnrichmentCondition, EnrichmentRule, EventEnricher};
pub use error::AuditExtError;
pub use event::{
    EventCategory, EventOutcome, SourceCrate, UnifiedEvent, UnifiedEventBuilder, UnifiedEventId,
};
pub use export::{AuditExporter, ExportFormat, ExportValidation};
pub use integrity::{
    chain_health, compute_event_hash, find_gaps, verify_chain, verify_range,
    ChainAuthenticator, ChainHealth, ChainStatus,
};
pub use query::{AuditQuery, QueryEngine, QueryFilter, QueryResult, QuerySort};
pub use retention::{
    compliance_retention_policy, default_retention_policy, short_retention_policy,
    ArchiveResult, AuditRetentionPolicy, RetentionAction, RetentionManager,
    RetentionPreview, RetentionResult, RetentionScope, RetentionValidation,
};
pub use store::{
    ingest_detection_event, ingest_document_event, ingest_identity_event,
    ingest_monitoring_event, ingest_permission_event, ingest_privacy_event,
    ingest_provenance_event, ingest_security_event, ingest_shield_event, ingest_truth_event,
    AuditStore, EventIndex, StorageStats,
};
pub use timeline::{bucketize, Timeline, TimelineBuilder, TimelineEntry};
