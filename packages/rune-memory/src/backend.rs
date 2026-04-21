// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — MemoryGovernanceBackend trait for pluggable memory
// governance storage. Defines the contract that adapter crates
// implement to connect memory governance to real persistence layers
// (vector databases, relational stores, document stores, etc.).
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::MemoryError;
use crate::isolation::{IsolationBoundaryType, IsolationViolationType};
use crate::memory::{
    MemoryContentType, MemoryIsolationLevel, MemoryScopeType, MemorySensitivity,
};
use crate::retention::{ExpiryAction, RedactionPatternType};

// ── Stored wrapper types ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMemoryEntry {
    pub entry_id: String,
    pub scope_id: String,
    pub content: String,
    pub content_type: MemoryContentType,
    pub sensitivity_level: MemorySensitivity,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub metadata: HashMap<String, String>,
    pub provenance_ref: Option<String>,
    pub stored_at: i64,
    pub last_accessed_at: Option<i64>,
    pub access_count: String,
    pub content_hash: String,
    pub retention_policy_ref: Option<String>,
}

impl StoredMemoryEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entry_id: impl Into<String>,
        scope_id: impl Into<String>,
        content: impl Into<String>,
        content_type: MemoryContentType,
        sensitivity_level: MemorySensitivity,
        created_by: impl Into<String>,
        created_at: i64,
        stored_at: i64,
        content_hash: impl Into<String>,
    ) -> Self {
        Self {
            entry_id: entry_id.into(),
            scope_id: scope_id.into(),
            content: content.into(),
            content_type,
            sensitivity_level,
            created_by: created_by.into(),
            created_at,
            expires_at: None,
            metadata: HashMap::new(),
            provenance_ref: None,
            stored_at,
            last_accessed_at: None,
            access_count: "0".into(),
            content_hash: content_hash.into(),
            retention_policy_ref: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMemoryScope {
    pub scope_id: String,
    pub scope_type: MemoryScopeType,
    pub owner_id: String,
    pub isolation_level: MemoryIsolationLevel,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
    pub entry_count: String,
    pub total_size_estimate: String,
    pub last_entry_at: Option<i64>,
}

impl StoredMemoryScope {
    pub fn new(
        scope_id: impl Into<String>,
        scope_type: MemoryScopeType,
        owner_id: impl Into<String>,
        isolation_level: MemoryIsolationLevel,
        created_at: i64,
    ) -> Self {
        Self {
            scope_id: scope_id.into(),
            scope_type,
            owner_id: owner_id.into(),
            isolation_level,
            created_at,
            metadata: HashMap::new(),
            entry_count: "0".into(),
            total_size_estimate: "0".into(),
            last_entry_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRetentionPolicy {
    pub policy_id: String,
    pub scope_pattern: String,
    pub max_age_seconds: Option<i64>,
    pub max_entries: Option<usize>,
    pub content_type_filter: Option<Vec<MemoryContentType>>,
    pub sensitivity_threshold: Option<MemorySensitivity>,
    pub on_expiry: ExpiryAction,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
    pub entries_governed: String,
    pub last_evaluated_at: Option<i64>,
}

impl StoredRetentionPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        scope_pattern: impl Into<String>,
        on_expiry: ExpiryAction,
        created_at: i64,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            scope_pattern: scope_pattern.into(),
            max_age_seconds: None,
            max_entries: None,
            content_type_filter: None,
            sensitivity_threshold: None,
            on_expiry,
            created_at,
            metadata: HashMap::new(),
            entries_governed: "0".into(),
            last_evaluated_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRedactionPolicy {
    pub policy_id: String,
    pub redaction_patterns: Vec<StoredRedactionPatternRef>,
    pub applies_to_content_types: Option<Vec<MemoryContentType>>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
    pub entries_redacted: String,
    pub last_applied_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRedactionPatternRef {
    pub pattern_id: String,
    pub pattern_type: RedactionPatternType,
    pub replacement: String,
    pub description: String,
}

impl StoredRedactionPolicy {
    pub fn new(policy_id: impl Into<String>, created_at: i64) -> Self {
        Self {
            policy_id: policy_id.into(),
            redaction_patterns: Vec::new(),
            applies_to_content_types: None,
            created_at,
            metadata: HashMap::new(),
            entries_redacted: "0".into(),
            last_applied_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRetrievalPolicy {
    pub policy_id: String,
    pub agent_id_pattern: String,
    pub allowed_collections: Vec<String>,
    pub denied_collections: Vec<String>,
    pub max_results_per_query: Option<usize>,
    pub require_provenance: bool,
    pub sensitivity_ceiling: Option<MemorySensitivity>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
    pub queries_evaluated: String,
    pub queries_denied: String,
    pub last_evaluated_at: Option<i64>,
}

impl StoredRetrievalPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        agent_id_pattern: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            agent_id_pattern: agent_id_pattern.into(),
            allowed_collections: Vec::new(),
            denied_collections: Vec::new(),
            max_results_per_query: None,
            require_provenance: false,
            sensitivity_ceiling: None,
            created_at,
            metadata: HashMap::new(),
            queries_evaluated: "0".into(),
            queries_denied: "0".into(),
            last_evaluated_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIsolationBoundary {
    pub boundary_id: String,
    pub scope_a: String,
    pub scope_b: String,
    pub boundary_type: IsolationBoundaryType,
    pub created_by: String,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
    pub violations_detected: String,
    pub last_checked_at: Option<i64>,
}

impl StoredIsolationBoundary {
    pub fn new(
        boundary_id: impl Into<String>,
        scope_a: impl Into<String>,
        scope_b: impl Into<String>,
        boundary_type: IsolationBoundaryType,
        created_by: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            boundary_id: boundary_id.into(),
            scope_a: scope_a.into(),
            scope_b: scope_b.into(),
            boundary_type,
            created_by: created_by.into(),
            created_at,
            metadata: HashMap::new(),
            violations_detected: "0".into(),
            last_checked_at: None,
        }
    }
}

// ── ViolationResolutionStatus ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationResolutionStatus {
    Open,
    Acknowledged,
    Resolved,
    Dismissed,
}

impl fmt::Display for ViolationResolutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Open => "Open",
            Self::Acknowledged => "Acknowledged",
            Self::Resolved => "Resolved",
            Self::Dismissed => "Dismissed",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIsolationViolationRecord {
    pub violation_id: String,
    pub boundary_id: String,
    pub violating_requester: String,
    pub attempted_scope: String,
    pub violation_type: IsolationViolationType,
    pub detected_at: i64,
    pub severity: MemorySensitivity,
    pub metadata: HashMap<String, String>,
    pub resolution_status: ViolationResolutionStatus,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<i64>,
}

impl StoredIsolationViolationRecord {
    pub fn new(
        violation_id: impl Into<String>,
        boundary_id: impl Into<String>,
        violating_requester: impl Into<String>,
        attempted_scope: impl Into<String>,
        violation_type: IsolationViolationType,
        detected_at: i64,
        severity: MemorySensitivity,
    ) -> Self {
        Self {
            violation_id: violation_id.into(),
            boundary_id: boundary_id.into(),
            violating_requester: violating_requester.into(),
            attempted_scope: attempted_scope.into(),
            violation_type,
            detected_at,
            severity,
            metadata: HashMap::new(),
            resolution_status: ViolationResolutionStatus::Open,
            resolved_by: None,
            resolved_at: None,
        }
    }

    pub fn resolve(&mut self, resolved_by: impl Into<String>, resolved_at: i64) {
        self.resolution_status = ViolationResolutionStatus::Resolved;
        self.resolved_by = Some(resolved_by.into());
        self.resolved_at = Some(resolved_at);
    }
}

// ── MemoryBackendInfo ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBackendInfo {
    pub backend_id: String,
    pub backend_type: String,
    pub entry_count: String,
    pub scope_count: String,
    pub policy_count: String,
    pub violation_count: String,
}

// ── MemoryGovernanceBackend trait ──────────────────────────────────

pub trait MemoryGovernanceBackend {
    // Entry operations
    fn store_memory_entry(&mut self, entry: StoredMemoryEntry) -> Result<(), MemoryError>;
    fn retrieve_memory_entry(&self, entry_id: &str) -> Result<Option<StoredMemoryEntry>, MemoryError>;
    fn delete_memory_entry(&mut self, entry_id: &str) -> Result<(), MemoryError>;
    fn list_entries_by_scope(&self, scope_id: &str) -> Vec<StoredMemoryEntry>;
    fn list_entries_by_content_type(&self, content_type: &MemoryContentType) -> Vec<StoredMemoryEntry>;
    fn list_entries_by_sensitivity(&self, sensitivity: &MemorySensitivity) -> Vec<StoredMemoryEntry>;
    fn entry_count(&self) -> usize;

    // Scope operations
    fn store_memory_scope(&mut self, scope: StoredMemoryScope) -> Result<(), MemoryError>;
    fn retrieve_memory_scope(&self, scope_id: &str) -> Result<Option<StoredMemoryScope>, MemoryError>;
    fn list_scopes_by_type(&self, scope_type: &MemoryScopeType) -> Vec<StoredMemoryScope>;
    fn list_scopes_by_owner(&self, owner_id: &str) -> Vec<StoredMemoryScope>;
    fn scope_count(&self) -> usize;

    // Retention policy operations
    fn store_retention_policy(&mut self, policy: StoredRetentionPolicy) -> Result<(), MemoryError>;
    fn retrieve_retention_policy(&self, policy_id: &str) -> Result<Option<StoredRetentionPolicy>, MemoryError>;
    fn list_retention_policies(&self) -> Vec<StoredRetentionPolicy>;

    // Redaction policy operations
    fn store_redaction_policy(&mut self, policy: StoredRedactionPolicy) -> Result<(), MemoryError>;
    fn retrieve_redaction_policy(&self, policy_id: &str) -> Result<Option<StoredRedactionPolicy>, MemoryError>;
    fn list_redaction_policies(&self) -> Vec<StoredRedactionPolicy>;

    // Retrieval policy operations
    fn store_retrieval_policy(&mut self, policy: StoredRetrievalPolicy) -> Result<(), MemoryError>;
    fn retrieve_retrieval_policy(&self, policy_id: &str) -> Result<Option<StoredRetrievalPolicy>, MemoryError>;
    fn list_retrieval_policies_by_agent(&self, agent_pattern: &str) -> Vec<StoredRetrievalPolicy>;

    // Isolation operations
    fn store_isolation_boundary(&mut self, boundary: StoredIsolationBoundary) -> Result<(), MemoryError>;
    fn retrieve_isolation_boundary(&self, boundary_id: &str) -> Result<Option<StoredIsolationBoundary>, MemoryError>;
    fn list_boundaries_by_scope(&self, scope_id: &str) -> Vec<StoredIsolationBoundary>;
    fn store_isolation_violation(&mut self, violation: StoredIsolationViolationRecord) -> Result<(), MemoryError>;
    fn list_violations_by_boundary(&self, boundary_id: &str) -> Vec<StoredIsolationViolationRecord>;

    // Lifecycle
    fn flush(&mut self) -> Result<(), MemoryError>;
    fn backend_info(&self) -> MemoryBackendInfo;
}

// ── InMemoryMemoryGovernanceBackend ───────────────────────────────

pub struct InMemoryMemoryGovernanceBackend {
    entries: HashMap<String, StoredMemoryEntry>,
    scopes: HashMap<String, StoredMemoryScope>,
    retention_policies: HashMap<String, StoredRetentionPolicy>,
    redaction_policies: HashMap<String, StoredRedactionPolicy>,
    retrieval_policies: HashMap<String, StoredRetrievalPolicy>,
    boundaries: HashMap<String, StoredIsolationBoundary>,
    violations: HashMap<String, StoredIsolationViolationRecord>,
}

impl InMemoryMemoryGovernanceBackend {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            scopes: HashMap::new(),
            retention_policies: HashMap::new(),
            redaction_policies: HashMap::new(),
            retrieval_policies: HashMap::new(),
            boundaries: HashMap::new(),
            violations: HashMap::new(),
        }
    }
}

impl Default for InMemoryMemoryGovernanceBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryGovernanceBackend for InMemoryMemoryGovernanceBackend {
    fn store_memory_entry(&mut self, entry: StoredMemoryEntry) -> Result<(), MemoryError> {
        self.entries.insert(entry.entry_id.clone(), entry);
        Ok(())
    }

    fn retrieve_memory_entry(&self, entry_id: &str) -> Result<Option<StoredMemoryEntry>, MemoryError> {
        Ok(self.entries.get(entry_id).cloned())
    }

    fn delete_memory_entry(&mut self, entry_id: &str) -> Result<(), MemoryError> {
        self.entries.remove(entry_id);
        Ok(())
    }

    fn list_entries_by_scope(&self, scope_id: &str) -> Vec<StoredMemoryEntry> {
        self.entries.values().filter(|e| e.scope_id == scope_id).cloned().collect()
    }

    fn list_entries_by_content_type(&self, content_type: &MemoryContentType) -> Vec<StoredMemoryEntry> {
        self.entries.values().filter(|e| &e.content_type == content_type).cloned().collect()
    }

    fn list_entries_by_sensitivity(&self, sensitivity: &MemorySensitivity) -> Vec<StoredMemoryEntry> {
        self.entries.values().filter(|e| &e.sensitivity_level == sensitivity).cloned().collect()
    }

    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn store_memory_scope(&mut self, scope: StoredMemoryScope) -> Result<(), MemoryError> {
        self.scopes.insert(scope.scope_id.clone(), scope);
        Ok(())
    }

    fn retrieve_memory_scope(&self, scope_id: &str) -> Result<Option<StoredMemoryScope>, MemoryError> {
        Ok(self.scopes.get(scope_id).cloned())
    }

    fn list_scopes_by_type(&self, scope_type: &MemoryScopeType) -> Vec<StoredMemoryScope> {
        self.scopes.values().filter(|s| &s.scope_type == scope_type).cloned().collect()
    }

    fn list_scopes_by_owner(&self, owner_id: &str) -> Vec<StoredMemoryScope> {
        self.scopes.values().filter(|s| s.owner_id == owner_id).cloned().collect()
    }

    fn scope_count(&self) -> usize {
        self.scopes.len()
    }

    fn store_retention_policy(&mut self, policy: StoredRetentionPolicy) -> Result<(), MemoryError> {
        self.retention_policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    fn retrieve_retention_policy(&self, policy_id: &str) -> Result<Option<StoredRetentionPolicy>, MemoryError> {
        Ok(self.retention_policies.get(policy_id).cloned())
    }

    fn list_retention_policies(&self) -> Vec<StoredRetentionPolicy> {
        self.retention_policies.values().cloned().collect()
    }

    fn store_redaction_policy(&mut self, policy: StoredRedactionPolicy) -> Result<(), MemoryError> {
        self.redaction_policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    fn retrieve_redaction_policy(&self, policy_id: &str) -> Result<Option<StoredRedactionPolicy>, MemoryError> {
        Ok(self.redaction_policies.get(policy_id).cloned())
    }

    fn list_redaction_policies(&self) -> Vec<StoredRedactionPolicy> {
        self.redaction_policies.values().cloned().collect()
    }

    fn store_retrieval_policy(&mut self, policy: StoredRetrievalPolicy) -> Result<(), MemoryError> {
        self.retrieval_policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    fn retrieve_retrieval_policy(&self, policy_id: &str) -> Result<Option<StoredRetrievalPolicy>, MemoryError> {
        Ok(self.retrieval_policies.get(policy_id).cloned())
    }

    fn list_retrieval_policies_by_agent(&self, agent_pattern: &str) -> Vec<StoredRetrievalPolicy> {
        self.retrieval_policies
            .values()
            .filter(|p| p.agent_id_pattern == agent_pattern || p.agent_id_pattern == "*")
            .cloned()
            .collect()
    }

    fn store_isolation_boundary(&mut self, boundary: StoredIsolationBoundary) -> Result<(), MemoryError> {
        self.boundaries.insert(boundary.boundary_id.clone(), boundary);
        Ok(())
    }

    fn retrieve_isolation_boundary(&self, boundary_id: &str) -> Result<Option<StoredIsolationBoundary>, MemoryError> {
        Ok(self.boundaries.get(boundary_id).cloned())
    }

    fn list_boundaries_by_scope(&self, scope_id: &str) -> Vec<StoredIsolationBoundary> {
        self.boundaries
            .values()
            .filter(|b| b.scope_a == scope_id || b.scope_b == scope_id)
            .cloned()
            .collect()
    }

    fn store_isolation_violation(&mut self, violation: StoredIsolationViolationRecord) -> Result<(), MemoryError> {
        self.violations.insert(violation.violation_id.clone(), violation);
        Ok(())
    }

    fn list_violations_by_boundary(&self, boundary_id: &str) -> Vec<StoredIsolationViolationRecord> {
        self.violations
            .values()
            .filter(|v| v.boundary_id == boundary_id)
            .cloned()
            .collect()
    }

    fn flush(&mut self) -> Result<(), MemoryError> {
        self.entries.clear();
        self.scopes.clear();
        self.retention_policies.clear();
        self.redaction_policies.clear();
        self.retrieval_policies.clear();
        self.boundaries.clear();
        self.violations.clear();
        Ok(())
    }

    fn backend_info(&self) -> MemoryBackendInfo {
        let policy_count = self.retention_policies.len()
            + self.redaction_policies.len()
            + self.retrieval_policies.len();
        MemoryBackendInfo {
            backend_id: "in-memory-memory-governance".into(),
            backend_type: "InMemory".into(),
            entry_count: self.entries.len().to_string(),
            scope_count: self.scopes.len().to_string(),
            policy_count: policy_count.to_string(),
            violation_count: self.violations.len().to_string(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> StoredMemoryEntry {
        StoredMemoryEntry::new(
            "e1", "scope-1", "test content",
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Internal,
            "agent-1", 1000, 1001, "abc123hash",
        )
    }

    fn sample_scope() -> StoredMemoryScope {
        StoredMemoryScope::new(
            "scope-1", MemoryScopeType::AgentLocal,
            "agent-1", MemoryIsolationLevel::Strict, 1000,
        )
    }

    fn sample_retention_policy() -> StoredRetentionPolicy {
        StoredRetentionPolicy::new("rp-1", "scope-*", ExpiryAction::Delete, 1000)
    }

    fn sample_redaction_policy() -> StoredRedactionPolicy {
        StoredRedactionPolicy::new("rdp-1", 1000)
    }

    fn sample_retrieval_policy() -> StoredRetrievalPolicy {
        StoredRetrievalPolicy::new("rgp-1", "agent-*", 1000)
    }

    fn sample_boundary() -> StoredIsolationBoundary {
        StoredIsolationBoundary::new(
            "ib-1", "scope-a", "scope-b",
            IsolationBoundaryType::HardIsolation,
            "admin", 1000,
        )
    }

    fn sample_violation() -> StoredIsolationViolationRecord {
        StoredIsolationViolationRecord::new(
            "iv-1", "ib-1", "agent-rogue", "scope-b",
            IsolationViolationType::CrossScopeRead,
            2000, MemorySensitivity::Sensitive,
        )
    }

    #[test]
    fn test_store_and_retrieve_entry() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_memory_entry(sample_entry()).unwrap();
        let entry = backend.retrieve_memory_entry("e1").unwrap().unwrap();
        assert_eq!(entry.entry_id, "e1");
        assert_eq!(entry.content_hash, "abc123hash");
        assert_eq!(entry.access_count, "0");
    }

    #[test]
    fn test_retrieve_nonexistent_entry() {
        let backend = InMemoryMemoryGovernanceBackend::new();
        assert!(backend.retrieve_memory_entry("none").unwrap().is_none());
    }

    #[test]
    fn test_delete_entry() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_memory_entry(sample_entry()).unwrap();
        backend.delete_memory_entry("e1").unwrap();
        assert_eq!(backend.entry_count(), 0);
    }

    #[test]
    fn test_list_entries_by_scope() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_memory_entry(sample_entry()).unwrap();
        let mut e2 = sample_entry();
        e2.entry_id = "e2".into();
        e2.scope_id = "scope-2".into();
        backend.store_memory_entry(e2).unwrap();
        assert_eq!(backend.list_entries_by_scope("scope-1").len(), 1);
    }

    #[test]
    fn test_list_entries_by_content_type() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_memory_entry(sample_entry()).unwrap();
        assert_eq!(
            backend.list_entries_by_content_type(&MemoryContentType::ConversationTurn).len(),
            1
        );
        assert_eq!(
            backend.list_entries_by_content_type(&MemoryContentType::Embedding).len(),
            0
        );
    }

    #[test]
    fn test_list_entries_by_sensitivity() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_memory_entry(sample_entry()).unwrap();
        assert_eq!(
            backend.list_entries_by_sensitivity(&MemorySensitivity::Internal).len(),
            1
        );
    }

    #[test]
    fn test_store_and_retrieve_scope() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_memory_scope(sample_scope()).unwrap();
        let scope = backend.retrieve_memory_scope("scope-1").unwrap().unwrap();
        assert_eq!(scope.scope_id, "scope-1");
        assert_eq!(scope.entry_count, "0");
    }

    #[test]
    fn test_list_scopes_by_type() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_memory_scope(sample_scope()).unwrap();
        assert_eq!(
            backend.list_scopes_by_type(&MemoryScopeType::AgentLocal).len(),
            1
        );
    }

    #[test]
    fn test_list_scopes_by_owner() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_memory_scope(sample_scope()).unwrap();
        assert_eq!(backend.list_scopes_by_owner("agent-1").len(), 1);
        assert_eq!(backend.list_scopes_by_owner("agent-2").len(), 0);
    }

    #[test]
    fn test_store_and_retrieve_retention_policy() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_retention_policy(sample_retention_policy()).unwrap();
        let p = backend.retrieve_retention_policy("rp-1").unwrap().unwrap();
        assert_eq!(p.entries_governed, "0");
    }

    #[test]
    fn test_list_retention_policies() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_retention_policy(sample_retention_policy()).unwrap();
        assert_eq!(backend.list_retention_policies().len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_redaction_policy() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_redaction_policy(sample_redaction_policy()).unwrap();
        let p = backend.retrieve_redaction_policy("rdp-1").unwrap().unwrap();
        assert_eq!(p.entries_redacted, "0");
    }

    #[test]
    fn test_store_and_retrieve_retrieval_policy() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_retrieval_policy(sample_retrieval_policy()).unwrap();
        let p = backend.retrieve_retrieval_policy("rgp-1").unwrap().unwrap();
        assert_eq!(p.queries_evaluated, "0");
    }

    #[test]
    fn test_list_retrieval_policies_by_agent() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_retrieval_policy(sample_retrieval_policy()).unwrap();
        assert_eq!(backend.list_retrieval_policies_by_agent("agent-*").len(), 1);
        assert_eq!(backend.list_retrieval_policies_by_agent("other").len(), 0);
    }

    #[test]
    fn test_store_and_retrieve_boundary() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_isolation_boundary(sample_boundary()).unwrap();
        let b = backend.retrieve_isolation_boundary("ib-1").unwrap().unwrap();
        assert_eq!(b.violations_detected, "0");
    }

    #[test]
    fn test_list_boundaries_by_scope() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_isolation_boundary(sample_boundary()).unwrap();
        assert_eq!(backend.list_boundaries_by_scope("scope-a").len(), 1);
        assert_eq!(backend.list_boundaries_by_scope("scope-c").len(), 0);
    }

    #[test]
    fn test_store_and_list_violations() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_isolation_violation(sample_violation()).unwrap();
        let violations = backend.list_violations_by_boundary("ib-1");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resolution_status, ViolationResolutionStatus::Open);
    }

    #[test]
    fn test_violation_resolve() {
        let mut v = sample_violation();
        v.resolve("admin", 3000);
        assert_eq!(v.resolution_status, ViolationResolutionStatus::Resolved);
        assert_eq!(v.resolved_by, Some("admin".into()));
        assert_eq!(v.resolved_at, Some(3000));
    }

    #[test]
    fn test_violation_resolution_status_display() {
        let statuses = vec![
            ViolationResolutionStatus::Open,
            ViolationResolutionStatus::Acknowledged,
            ViolationResolutionStatus::Resolved,
            ViolationResolutionStatus::Dismissed,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_memory_entry(sample_entry()).unwrap();
        backend.store_memory_scope(sample_scope()).unwrap();
        backend.flush().unwrap();
        assert_eq!(backend.entry_count(), 0);
        assert_eq!(backend.scope_count(), 0);
    }

    #[test]
    fn test_backend_info() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        backend.store_memory_entry(sample_entry()).unwrap();
        backend.store_memory_scope(sample_scope()).unwrap();
        backend.store_retention_policy(sample_retention_policy()).unwrap();
        let info = backend.backend_info();
        assert_eq!(info.backend_type, "InMemory");
        assert_eq!(info.entry_count, "1");
        assert_eq!(info.scope_count, "1");
        assert_eq!(info.policy_count, "1");
    }

    #[test]
    fn test_backend_default() {
        let backend = InMemoryMemoryGovernanceBackend::default();
        assert_eq!(backend.entry_count(), 0);
    }

    #[test]
    fn test_wildcard_retrieval_policy() {
        let mut backend = InMemoryMemoryGovernanceBackend::new();
        let mut p = sample_retrieval_policy();
        p.agent_id_pattern = "*".into();
        backend.store_retrieval_policy(p).unwrap();
        assert_eq!(backend.list_retrieval_policies_by_agent("any-agent").len(), 1);
    }

    #[test]
    fn test_entry_with_retention_ref() {
        let mut entry = sample_entry();
        entry.retention_policy_ref = Some("rp-1".into());
        assert_eq!(entry.retention_policy_ref, Some("rp-1".to_string()));
    }

    #[test]
    fn test_scope_with_metadata() {
        let mut scope = sample_scope();
        scope.entry_count = "42".into();
        scope.total_size_estimate = "1024".into();
        scope.last_entry_at = Some(2000);
        assert_eq!(scope.entry_count, "42");
    }
}
