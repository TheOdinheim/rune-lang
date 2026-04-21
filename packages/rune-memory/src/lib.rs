// ═══════════════════════════════════════════════════════════════════════
// rune-memory — Memory governance, retention policies, retrieval
// governance, isolation boundaries, and memory audit for the RUNE
// governance ecosystem. Governs the memory substrate that AI agents
// and systems use: lifecycle, isolation, retention, access control,
// sensitivity classification, RAG retrieval, and conversation history.
// ═══════════════════════════════════════════════════════════════════════

// ── Layer 1 modules ───────────────────────────────────────────────
pub mod audit;
pub mod error;
pub mod isolation;
pub mod memory;
pub mod retention;
pub mod retrieval;

// ── Layer 2 modules ───────────────────────────────────────────────
pub mod access_evaluator;
pub mod content_hash;
pub mod isolation_checker;
pub mod metrics;
pub mod redaction_engine;
pub mod retention_engine;
pub mod window_manager;

// ── Layer 3 modules ───────────────────────────────────────────────
pub mod backend;
pub mod memory_export;
pub mod memory_governance_metrics;
pub mod memory_stream;
pub mod retention_governor;
pub mod retrieval_governor;
pub mod scope_governor;

// ── Layer 1 re-exports ────────────────────────────────────────────

pub use audit::{MemoryAuditEvent, MemoryAuditLog, MemoryEventType};
pub use error::MemoryError;
pub use isolation::{
    CrossScopePolicy, IsolationBoundary, IsolationBoundaryType, IsolationViolation,
    IsolationViolationType,
};
pub use memory::{
    MemoryAccessDecision, MemoryAccessRequest, MemoryAccessType, MemoryContentType, MemoryEntry,
    MemoryIsolationLevel, MemoryScope, MemoryScopeType, MemorySensitivity,
};
pub use retention::{
    ConversationWindowPolicy, ExpiryAction, MemoryRedactionPolicy, MemoryRetentionPolicy,
    RedactionPattern, RedactionPatternType, SummarizationStrategy,
};
pub use retrieval::{
    RetrievalDecision, RetrievalGovernancePolicy, RetrievalRequest, RetrievalResult,
};

// ── Layer 2 re-exports ────────────────────────────────────────────

pub use access_evaluator::{MemoryAccessEvaluator, SensitivityClearance};
pub use content_hash::{HashChainLink, MemoryHashChain};
pub use isolation_checker::{IsolationCheckOutcome, IsolationCheckResult, IsolationChecker};
pub use metrics::{MemoryMetricSnapshot, MemoryMetrics};
pub use redaction_engine::{
    MemoryRedactionEngine, RedactedContent, RedactionAction, RedactionReport,
};
pub use retention_engine::{MemoryRetentionEngine, RetentionEvaluation, RetentionOutcome};
pub use window_manager::{ConversationWindowManager, PinnedEntryManager, WindowTrimResult};

// ── Layer 3 re-exports ────────────────────────────────────────────

pub use backend::{
    InMemoryMemoryGovernanceBackend, MemoryBackendInfo, MemoryGovernanceBackend,
    StoredIsolationBoundary, StoredIsolationViolationRecord, StoredMemoryEntry,
    StoredMemoryScope, StoredRedactionPolicy, StoredRedactionPatternRef,
    StoredRetentionPolicy, StoredRetrievalPolicy, ViolationResolutionStatus,
};
pub use memory_export::{
    GdprMemoryDeletionExporter, JsonMemoryExporter, MemoryGovernanceExporter,
    MemoryIsolationReportExporter, MemoryRetentionComplianceExporter, RetrievalAuditExporter,
};
pub use memory_governance_metrics::{
    InMemoryMemoryGovernanceMetricsCollector, MemoryGovernanceMetricSnapshot,
    MemoryGovernanceMetricsCollector, NullMemoryGovernanceMetricsCollector,
};
pub use memory_stream::{
    FilteredMemoryGovernanceEventSubscriber, MemoryGovernanceEventCollector,
    MemoryGovernanceEventSubscriber, MemoryGovernanceEventSubscriberRegistry,
    MemoryGovernanceLifecycleEvent, MemoryGovernanceLifecycleEventType,
};
pub use retention_governor::{
    InMemoryRetentionGovernor, NullRetentionGovernor, RetentionGovernanceDecision,
    RetentionGovernor, RetentionSweepResult,
};
pub use retrieval_governor::{
    DenyAllRetrievalGovernor, InMemoryRetrievalGovernor, NullRetrievalGovernor,
    RetrievalGovernanceDecision, RetrievalGovernanceResult, RetrievalGovernor,
};
pub use scope_governor::{
    InMemoryMemoryScopeGovernor, MemoryScopeGovernor, NullMemoryScopeGovernor,
    ScopeAccessDecision, ScopeHealthAssessment, ScopeHealthStatus,
};
