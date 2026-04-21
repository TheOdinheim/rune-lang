// ═══════════════════════════════════════════════════════════════════════
// rune-memory — Memory governance, retention policies, retrieval
// governance, isolation boundaries, and memory audit for the RUNE
// governance ecosystem. Governs the memory substrate that AI agents
// and systems use: lifecycle, isolation, retention, access control,
// sensitivity classification, RAG retrieval, and conversation history.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod error;
pub mod isolation;
pub mod memory;
pub mod retention;
pub mod retrieval;

// ── Re-exports ───────────────────────────────────────────────────────

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
