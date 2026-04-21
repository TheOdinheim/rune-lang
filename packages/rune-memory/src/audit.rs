// ═══════════════════════════════════════════════════════════════════════
// Audit — Memory governance audit events for memory entry lifecycle,
// scope access, retrieval governance, isolation enforcement,
// retention policy application, and redaction.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── MemoryEventType ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryEventType {
    MemoryEntryCreated { entry_id: String, scope_id: String },
    MemoryEntryAccessed { entry_id: String, accessor_id: String },
    MemoryEntryModified { entry_id: String, modifier_id: String },
    MemoryEntryExpired { entry_id: String, policy_id: String },
    MemoryEntryDeleted { entry_id: String, reason: String },
    MemoryEntryRedacted { entry_id: String, policy_id: String },
    MemoryScopeCreated { scope_id: String, scope_type: String },
    MemoryScopeAccessGranted { scope_id: String, requester_id: String },
    MemoryScopeAccessDenied { scope_id: String, requester_id: String, reason: String },
    RetrievalRequested { request_id: String, agent_id: String, collection_id: String },
    RetrievalPermitted { request_id: String, result_count: String },
    RetrievalDenied { request_id: String, reason: String },
    RetrievalFiltered { request_id: String, original_count: String, filtered_count: String },
    IsolationBoundaryCreated { boundary_id: String },
    IsolationViolationDetected { violation_id: String, boundary_id: String },
    RetentionPolicyApplied { policy_id: String, entries_affected: String },
    RetentionPolicyExpired { policy_id: String, entries_expired: String },
    RedactionApplied { entry_id: String, policy_id: String },
    ConversationWindowTrimmed { scope_id: String, entries_removed: String },
    MemoryAccessEscalated { request_id: String, reason: String },
    // ── Layer 2 variants ──────────────────────────────────────────
    MemoryContentHashed { entry_id: String, hash: String },
    MemoryHashChainAppended { chain_length: String, chain_hash: String },
    MemoryHashChainVerified { chain_length: String, valid: String },
    RetentionEvaluated { entry_id: String, outcome: String, policy_id: String },
    RetentionScanCompleted { policy_id: String, expired_count: String },
    ContentRedacted { entry_id: String, policy_id: String, action_count: String },
    RedactionPolicyApplied { policy_id: String, entries_processed: String },
    ConversationWindowTrimExecuted { scope_id: String, removed_count: String, strategy: String },
    TokenEstimateComputed { scope_id: String, token_count: String },
    IsolationCheckPerformed { requester_scope: String, target_scope: String, outcome: String },
    AccessEvaluated { request_id: String, decision: String },
    RetrievalEvaluated { request_id: String, decision: String },
    SensitivityClearanceChecked { requester_id: String, required_level: String, result: String },
    MemoryMetricsComputed { metric_name: String, value: String },
}

impl fmt::Display for MemoryEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryEntryCreated { entry_id, scope_id } => {
                write!(f, "MemoryEntryCreated({entry_id}, scope={scope_id})")
            }
            Self::MemoryEntryAccessed { entry_id, accessor_id } => {
                write!(f, "MemoryEntryAccessed({entry_id}, by={accessor_id})")
            }
            Self::MemoryEntryModified { entry_id, modifier_id } => {
                write!(f, "MemoryEntryModified({entry_id}, by={modifier_id})")
            }
            Self::MemoryEntryExpired { entry_id, policy_id } => {
                write!(f, "MemoryEntryExpired({entry_id}, policy={policy_id})")
            }
            Self::MemoryEntryDeleted { entry_id, reason } => {
                write!(f, "MemoryEntryDeleted({entry_id}): {reason}")
            }
            Self::MemoryEntryRedacted { entry_id, policy_id } => {
                write!(f, "MemoryEntryRedacted({entry_id}, policy={policy_id})")
            }
            Self::MemoryScopeCreated { scope_id, scope_type } => {
                write!(f, "MemoryScopeCreated({scope_id}, type={scope_type})")
            }
            Self::MemoryScopeAccessGranted { scope_id, requester_id } => {
                write!(f, "MemoryScopeAccessGranted({scope_id}, to={requester_id})")
            }
            Self::MemoryScopeAccessDenied { scope_id, requester_id, reason } => {
                write!(f, "MemoryScopeAccessDenied({scope_id}, to={requester_id}): {reason}")
            }
            Self::RetrievalRequested { request_id, agent_id, collection_id } => {
                write!(f, "RetrievalRequested({request_id}, agent={agent_id}, collection={collection_id})")
            }
            Self::RetrievalPermitted { request_id, result_count } => {
                write!(f, "RetrievalPermitted({request_id}, results={result_count})")
            }
            Self::RetrievalDenied { request_id, reason } => {
                write!(f, "RetrievalDenied({request_id}): {reason}")
            }
            Self::RetrievalFiltered { request_id, original_count, filtered_count } => {
                write!(f, "RetrievalFiltered({request_id}, {original_count}→{filtered_count})")
            }
            Self::IsolationBoundaryCreated { boundary_id } => {
                write!(f, "IsolationBoundaryCreated({boundary_id})")
            }
            Self::IsolationViolationDetected { violation_id, boundary_id } => {
                write!(f, "IsolationViolationDetected({violation_id}, boundary={boundary_id})")
            }
            Self::RetentionPolicyApplied { policy_id, entries_affected } => {
                write!(f, "RetentionPolicyApplied({policy_id}, affected={entries_affected})")
            }
            Self::RetentionPolicyExpired { policy_id, entries_expired } => {
                write!(f, "RetentionPolicyExpired({policy_id}, expired={entries_expired})")
            }
            Self::RedactionApplied { entry_id, policy_id } => {
                write!(f, "RedactionApplied({entry_id}, policy={policy_id})")
            }
            Self::ConversationWindowTrimmed { scope_id, entries_removed } => {
                write!(f, "ConversationWindowTrimmed({scope_id}, removed={entries_removed})")
            }
            Self::MemoryAccessEscalated { request_id, reason } => {
                write!(f, "MemoryAccessEscalated({request_id}): {reason}")
            }
            Self::MemoryContentHashed { entry_id, hash } => {
                write!(f, "MemoryContentHashed({entry_id}, hash={hash})")
            }
            Self::MemoryHashChainAppended { chain_length, chain_hash } => {
                write!(f, "MemoryHashChainAppended(len={chain_length}, hash={chain_hash})")
            }
            Self::MemoryHashChainVerified { chain_length, valid } => {
                write!(f, "MemoryHashChainVerified(len={chain_length}, valid={valid})")
            }
            Self::RetentionEvaluated { entry_id, outcome, policy_id } => {
                write!(f, "RetentionEvaluated({entry_id}, outcome={outcome}, policy={policy_id})")
            }
            Self::RetentionScanCompleted { policy_id, expired_count } => {
                write!(f, "RetentionScanCompleted({policy_id}, expired={expired_count})")
            }
            Self::ContentRedacted { entry_id, policy_id, action_count } => {
                write!(f, "ContentRedacted({entry_id}, policy={policy_id}, actions={action_count})")
            }
            Self::RedactionPolicyApplied { policy_id, entries_processed } => {
                write!(f, "RedactionPolicyApplied({policy_id}, processed={entries_processed})")
            }
            Self::ConversationWindowTrimExecuted { scope_id, removed_count, strategy } => {
                write!(f, "ConversationWindowTrimExecuted({scope_id}, removed={removed_count}, strategy={strategy})")
            }
            Self::TokenEstimateComputed { scope_id, token_count } => {
                write!(f, "TokenEstimateComputed({scope_id}, tokens={token_count})")
            }
            Self::IsolationCheckPerformed { requester_scope, target_scope, outcome } => {
                write!(f, "IsolationCheckPerformed({requester_scope}→{target_scope}, outcome={outcome})")
            }
            Self::AccessEvaluated { request_id, decision } => {
                write!(f, "AccessEvaluated({request_id}, decision={decision})")
            }
            Self::RetrievalEvaluated { request_id, decision } => {
                write!(f, "RetrievalEvaluated({request_id}, decision={decision})")
            }
            Self::SensitivityClearanceChecked { requester_id, required_level, result } => {
                write!(f, "SensitivityClearanceChecked({requester_id}, required={required_level}, result={result})")
            }
            Self::MemoryMetricsComputed { metric_name, value } => {
                write!(f, "MemoryMetricsComputed({metric_name}={value})")
            }
        }
    }
}

impl MemoryEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::MemoryEntryCreated { .. } => "MemoryEntryCreated",
            Self::MemoryEntryAccessed { .. } => "MemoryEntryAccessed",
            Self::MemoryEntryModified { .. } => "MemoryEntryModified",
            Self::MemoryEntryExpired { .. } => "MemoryEntryExpired",
            Self::MemoryEntryDeleted { .. } => "MemoryEntryDeleted",
            Self::MemoryEntryRedacted { .. } => "MemoryEntryRedacted",
            Self::MemoryScopeCreated { .. } => "MemoryScopeCreated",
            Self::MemoryScopeAccessGranted { .. } => "MemoryScopeAccessGranted",
            Self::MemoryScopeAccessDenied { .. } => "MemoryScopeAccessDenied",
            Self::RetrievalRequested { .. } => "RetrievalRequested",
            Self::RetrievalPermitted { .. } => "RetrievalPermitted",
            Self::RetrievalDenied { .. } => "RetrievalDenied",
            Self::RetrievalFiltered { .. } => "RetrievalFiltered",
            Self::IsolationBoundaryCreated { .. } => "IsolationBoundaryCreated",
            Self::IsolationViolationDetected { .. } => "IsolationViolationDetected",
            Self::RetentionPolicyApplied { .. } => "RetentionPolicyApplied",
            Self::RetentionPolicyExpired { .. } => "RetentionPolicyExpired",
            Self::RedactionApplied { .. } => "RedactionApplied",
            Self::ConversationWindowTrimmed { .. } => "ConversationWindowTrimmed",
            Self::MemoryAccessEscalated { .. } => "MemoryAccessEscalated",
            Self::MemoryContentHashed { .. } => "MemoryContentHashed",
            Self::MemoryHashChainAppended { .. } => "MemoryHashChainAppended",
            Self::MemoryHashChainVerified { .. } => "MemoryHashChainVerified",
            Self::RetentionEvaluated { .. } => "RetentionEvaluated",
            Self::RetentionScanCompleted { .. } => "RetentionScanCompleted",
            Self::ContentRedacted { .. } => "ContentRedacted",
            Self::RedactionPolicyApplied { .. } => "RedactionPolicyApplied",
            Self::ConversationWindowTrimExecuted { .. } => "ConversationWindowTrimExecuted",
            Self::TokenEstimateComputed { .. } => "TokenEstimateComputed",
            Self::IsolationCheckPerformed { .. } => "IsolationCheckPerformed",
            Self::AccessEvaluated { .. } => "AccessEvaluated",
            Self::RetrievalEvaluated { .. } => "RetrievalEvaluated",
            Self::SensitivityClearanceChecked { .. } => "SensitivityClearanceChecked",
            Self::MemoryMetricsComputed { .. } => "MemoryMetricsComputed",
        }
    }

    pub fn kind(&self) -> &str {
        match self {
            Self::MemoryEntryCreated { .. }
            | Self::MemoryEntryAccessed { .. }
            | Self::MemoryEntryModified { .. }
            | Self::MemoryEntryExpired { .. }
            | Self::MemoryEntryDeleted { .. }
            | Self::MemoryEntryRedacted { .. } => "memory_entry",
            Self::MemoryScopeCreated { .. }
            | Self::MemoryScopeAccessGranted { .. }
            | Self::MemoryScopeAccessDenied { .. }
            | Self::MemoryAccessEscalated { .. } => "memory_scope",
            Self::RetrievalRequested { .. }
            | Self::RetrievalPermitted { .. }
            | Self::RetrievalDenied { .. }
            | Self::RetrievalFiltered { .. } => "retrieval",
            Self::IsolationBoundaryCreated { .. }
            | Self::IsolationViolationDetected { .. } => "isolation",
            Self::RetentionPolicyApplied { .. }
            | Self::RetentionPolicyExpired { .. }
            | Self::RedactionApplied { .. }
            | Self::ConversationWindowTrimmed { .. } => "retention",
            // Layer 2 kinds
            Self::MemoryContentHashed { .. }
            | Self::MemoryHashChainAppended { .. }
            | Self::MemoryHashChainVerified { .. } => "content_hash",
            Self::RetentionEvaluated { .. }
            | Self::RetentionScanCompleted { .. } => "retention_engine",
            Self::ContentRedacted { .. }
            | Self::RedactionPolicyApplied { .. } => "redaction",
            Self::ConversationWindowTrimExecuted { .. }
            | Self::TokenEstimateComputed { .. } => "window_manager",
            Self::IsolationCheckPerformed { .. } => "isolation_checker",
            Self::AccessEvaluated { .. }
            | Self::RetrievalEvaluated { .. }
            | Self::SensitivityClearanceChecked { .. } => "access_evaluator",
            Self::MemoryMetricsComputed { .. } => "metrics",
        }
    }
}

// ── MemoryAuditEvent ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MemoryAuditEvent {
    pub event: MemoryEventType,
    pub actor: String,
    pub timestamp: i64,
    pub description: String,
}

impl MemoryAuditEvent {
    pub fn new(
        event: MemoryEventType,
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

// ── MemoryAuditLog ─────────────────────────────────────────────────

pub struct MemoryAuditLog {
    events: Vec<MemoryAuditEvent>,
}

impl MemoryAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, event: MemoryAuditEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[MemoryAuditEvent] {
        &self.events
    }

    pub fn events_by_kind(&self, kind: &str) -> Vec<&MemoryAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event.kind() == kind)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&MemoryAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for MemoryAuditLog {
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

    fn make_event(event_type: MemoryEventType) -> MemoryAuditEvent {
        MemoryAuditEvent::new(event_type, "agent-1", 1000, "test")
    }

    #[test]
    fn test_event_type_display_all_variants() {
        let types: Vec<MemoryEventType> = vec![
            MemoryEventType::MemoryEntryCreated { entry_id: "e1".into(), scope_id: "s1".into() },
            MemoryEventType::MemoryEntryAccessed { entry_id: "e1".into(), accessor_id: "a1".into() },
            MemoryEventType::MemoryEntryModified { entry_id: "e1".into(), modifier_id: "m1".into() },
            MemoryEventType::MemoryEntryExpired { entry_id: "e1".into(), policy_id: "p1".into() },
            MemoryEventType::MemoryEntryDeleted { entry_id: "e1".into(), reason: "expired".into() },
            MemoryEventType::MemoryEntryRedacted { entry_id: "e1".into(), policy_id: "p1".into() },
            MemoryEventType::MemoryScopeCreated { scope_id: "s1".into(), scope_type: "AgentLocal".into() },
            MemoryEventType::MemoryScopeAccessGranted { scope_id: "s1".into(), requester_id: "a1".into() },
            MemoryEventType::MemoryScopeAccessDenied { scope_id: "s1".into(), requester_id: "a1".into(), reason: "no access".into() },
            MemoryEventType::RetrievalRequested { request_id: "r1".into(), agent_id: "a1".into(), collection_id: "docs".into() },
            MemoryEventType::RetrievalPermitted { request_id: "r1".into(), result_count: "10".into() },
            MemoryEventType::RetrievalDenied { request_id: "r1".into(), reason: "denied".into() },
            MemoryEventType::RetrievalFiltered { request_id: "r1".into(), original_count: "20".into(), filtered_count: "5".into() },
            MemoryEventType::IsolationBoundaryCreated { boundary_id: "ib-1".into() },
            MemoryEventType::IsolationViolationDetected { violation_id: "iv-1".into(), boundary_id: "ib-1".into() },
            MemoryEventType::RetentionPolicyApplied { policy_id: "rp-1".into(), entries_affected: "42".into() },
            MemoryEventType::RetentionPolicyExpired { policy_id: "rp-1".into(), entries_expired: "10".into() },
            MemoryEventType::RedactionApplied { entry_id: "e1".into(), policy_id: "rdp-1".into() },
            MemoryEventType::ConversationWindowTrimmed { scope_id: "s1".into(), entries_removed: "5".into() },
            MemoryEventType::MemoryAccessEscalated { request_id: "r1".into(), reason: "restricted scope".into() },
            MemoryEventType::MemoryContentHashed { entry_id: "e1".into(), hash: "abc".into() },
            MemoryEventType::MemoryHashChainAppended { chain_length: "5".into(), chain_hash: "def".into() },
            MemoryEventType::MemoryHashChainVerified { chain_length: "5".into(), valid: "true".into() },
            MemoryEventType::RetentionEvaluated { entry_id: "e1".into(), outcome: "Retain".into(), policy_id: "rp-1".into() },
            MemoryEventType::RetentionScanCompleted { policy_id: "rp-1".into(), expired_count: "3".into() },
            MemoryEventType::ContentRedacted { entry_id: "e1".into(), policy_id: "rdp-1".into(), action_count: "2".into() },
            MemoryEventType::RedactionPolicyApplied { policy_id: "rdp-1".into(), entries_processed: "10".into() },
            MemoryEventType::ConversationWindowTrimExecuted { scope_id: "s1".into(), removed_count: "5".into(), strategy: "TruncateOldest".into() },
            MemoryEventType::TokenEstimateComputed { scope_id: "s1".into(), token_count: "1024".into() },
            MemoryEventType::IsolationCheckPerformed { requester_scope: "sa".into(), target_scope: "sb".into(), outcome: "Allowed".into() },
            MemoryEventType::AccessEvaluated { request_id: "r1".into(), decision: "Granted".into() },
            MemoryEventType::RetrievalEvaluated { request_id: "rr-1".into(), decision: "Permitted".into() },
            MemoryEventType::SensitivityClearanceChecked { requester_id: "a1".into(), required_level: "Sensitive".into(), result: "Cleared".into() },
            MemoryEventType::MemoryMetricsComputed { metric_name: "entry_count".into(), value: "42".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 34);
    }

    #[test]
    fn test_type_name() {
        let e = MemoryEventType::MemoryEntryCreated { entry_id: "e1".into(), scope_id: "s1".into() };
        assert_eq!(e.type_name(), "MemoryEntryCreated");
        let e2 = MemoryEventType::RetrievalDenied { request_id: "r1".into(), reason: "no".into() };
        assert_eq!(e2.type_name(), "RetrievalDenied");
        let e3 = MemoryEventType::IsolationViolationDetected { violation_id: "iv-1".into(), boundary_id: "ib-1".into() };
        assert_eq!(e3.type_name(), "IsolationViolationDetected");
    }

    #[test]
    fn test_kind() {
        assert_eq!(
            MemoryEventType::MemoryEntryCreated { entry_id: "e1".into(), scope_id: "s1".into() }.kind(),
            "memory_entry"
        );
        assert_eq!(
            MemoryEventType::MemoryScopeCreated { scope_id: "s1".into(), scope_type: "AgentLocal".into() }.kind(),
            "memory_scope"
        );
        assert_eq!(
            MemoryEventType::RetrievalRequested { request_id: "r1".into(), agent_id: "a1".into(), collection_id: "docs".into() }.kind(),
            "retrieval"
        );
        assert_eq!(
            MemoryEventType::IsolationBoundaryCreated { boundary_id: "ib-1".into() }.kind(),
            "isolation"
        );
        assert_eq!(
            MemoryEventType::RetentionPolicyApplied { policy_id: "rp-1".into(), entries_affected: "42".into() }.kind(),
            "retention"
        );
    }

    #[test]
    fn test_audit_event_construction() {
        let event = MemoryAuditEvent::new(
            MemoryEventType::MemoryEntryCreated { entry_id: "e1".into(), scope_id: "s1".into() },
            "agent-1",
            1000,
            "Created entry e1",
        );
        assert_eq!(event.actor, "agent-1");
        assert_eq!(event.timestamp, 1000);
        assert_eq!(event.description, "Created entry e1");
    }

    #[test]
    fn test_audit_log_record_and_count() {
        let mut log = MemoryAuditLog::new();
        log.record(make_event(MemoryEventType::MemoryEntryCreated {
            entry_id: "e1".into(),
            scope_id: "s1".into(),
        }));
        log.record(make_event(MemoryEventType::MemoryEntryAccessed {
            entry_id: "e1".into(),
            accessor_id: "a1".into(),
        }));
        assert_eq!(log.event_count(), 2);
        assert_eq!(log.events().len(), 2);
    }

    #[test]
    fn test_audit_log_events_by_kind() {
        let mut log = MemoryAuditLog::new();
        log.record(make_event(MemoryEventType::MemoryEntryCreated {
            entry_id: "e1".into(),
            scope_id: "s1".into(),
        }));
        log.record(make_event(MemoryEventType::RetrievalRequested {
            request_id: "r1".into(),
            agent_id: "a1".into(),
            collection_id: "docs".into(),
        }));
        log.record(make_event(MemoryEventType::RetrievalDenied {
            request_id: "r2".into(),
            reason: "no access".into(),
        }));
        assert_eq!(log.events_by_kind("memory_entry").len(), 1);
        assert_eq!(log.events_by_kind("retrieval").len(), 2);
        assert_eq!(log.events_by_kind("isolation").len(), 0);
    }

    #[test]
    fn test_audit_log_since() {
        let mut log = MemoryAuditLog::new();
        log.record(MemoryAuditEvent::new(
            MemoryEventType::MemoryEntryCreated { entry_id: "e1".into(), scope_id: "s1".into() },
            "agent-1",
            500,
            "early",
        ));
        log.record(MemoryAuditEvent::new(
            MemoryEventType::MemoryEntryAccessed { entry_id: "e1".into(), accessor_id: "a1".into() },
            "agent-1",
            1500,
            "late",
        ));
        assert_eq!(log.since(1000).len(), 1);
        assert_eq!(log.since(500).len(), 2);
        assert_eq!(log.since(2000).len(), 0);
    }

    #[test]
    fn test_audit_log_default() {
        let log = MemoryAuditLog::default();
        assert_eq!(log.event_count(), 0);
    }

    #[test]
    fn test_kind_memory_access_escalated() {
        assert_eq!(
            MemoryEventType::MemoryAccessEscalated { request_id: "r1".into(), reason: "restricted".into() }.kind(),
            "memory_scope"
        );
    }

    #[test]
    fn test_kind_conversation_window_trimmed() {
        assert_eq!(
            MemoryEventType::ConversationWindowTrimmed { scope_id: "s1".into(), entries_removed: "5".into() }.kind(),
            "retention"
        );
    }

    #[test]
    fn test_type_name_all_variants() {
        let events: Vec<MemoryEventType> = vec![
            MemoryEventType::MemoryEntryCreated { entry_id: "e".into(), scope_id: "s".into() },
            MemoryEventType::MemoryEntryAccessed { entry_id: "e".into(), accessor_id: "a".into() },
            MemoryEventType::MemoryEntryModified { entry_id: "e".into(), modifier_id: "m".into() },
            MemoryEventType::MemoryEntryExpired { entry_id: "e".into(), policy_id: "p".into() },
            MemoryEventType::MemoryEntryDeleted { entry_id: "e".into(), reason: "r".into() },
            MemoryEventType::MemoryEntryRedacted { entry_id: "e".into(), policy_id: "p".into() },
            MemoryEventType::MemoryScopeCreated { scope_id: "s".into(), scope_type: "t".into() },
            MemoryEventType::MemoryScopeAccessGranted { scope_id: "s".into(), requester_id: "r".into() },
            MemoryEventType::MemoryScopeAccessDenied { scope_id: "s".into(), requester_id: "r".into(), reason: "x".into() },
            MemoryEventType::RetrievalRequested { request_id: "r".into(), agent_id: "a".into(), collection_id: "c".into() },
            MemoryEventType::RetrievalPermitted { request_id: "r".into(), result_count: "1".into() },
            MemoryEventType::RetrievalDenied { request_id: "r".into(), reason: "x".into() },
            MemoryEventType::RetrievalFiltered { request_id: "r".into(), original_count: "2".into(), filtered_count: "1".into() },
            MemoryEventType::IsolationBoundaryCreated { boundary_id: "b".into() },
            MemoryEventType::IsolationViolationDetected { violation_id: "v".into(), boundary_id: "b".into() },
            MemoryEventType::RetentionPolicyApplied { policy_id: "p".into(), entries_affected: "1".into() },
            MemoryEventType::RetentionPolicyExpired { policy_id: "p".into(), entries_expired: "1".into() },
            MemoryEventType::RedactionApplied { entry_id: "e".into(), policy_id: "p".into() },
            MemoryEventType::ConversationWindowTrimmed { scope_id: "s".into(), entries_removed: "1".into() },
            MemoryEventType::MemoryAccessEscalated { request_id: "r".into(), reason: "x".into() },
            MemoryEventType::MemoryContentHashed { entry_id: "e".into(), hash: "h".into() },
            MemoryEventType::MemoryHashChainAppended { chain_length: "1".into(), chain_hash: "h".into() },
            MemoryEventType::MemoryHashChainVerified { chain_length: "1".into(), valid: "true".into() },
            MemoryEventType::RetentionEvaluated { entry_id: "e".into(), outcome: "Retain".into(), policy_id: "p".into() },
            MemoryEventType::RetentionScanCompleted { policy_id: "p".into(), expired_count: "0".into() },
            MemoryEventType::ContentRedacted { entry_id: "e".into(), policy_id: "p".into(), action_count: "1".into() },
            MemoryEventType::RedactionPolicyApplied { policy_id: "p".into(), entries_processed: "1".into() },
            MemoryEventType::ConversationWindowTrimExecuted { scope_id: "s".into(), removed_count: "1".into(), strategy: "T".into() },
            MemoryEventType::TokenEstimateComputed { scope_id: "s".into(), token_count: "10".into() },
            MemoryEventType::IsolationCheckPerformed { requester_scope: "a".into(), target_scope: "b".into(), outcome: "ok".into() },
            MemoryEventType::AccessEvaluated { request_id: "r".into(), decision: "G".into() },
            MemoryEventType::RetrievalEvaluated { request_id: "r".into(), decision: "P".into() },
            MemoryEventType::SensitivityClearanceChecked { requester_id: "a".into(), required_level: "S".into(), result: "C".into() },
            MemoryEventType::MemoryMetricsComputed { metric_name: "m".into(), value: "1".into() },
        ];
        for event in &events {
            assert!(!event.type_name().is_empty());
        }
        assert_eq!(events.len(), 34);
    }

    #[test]
    fn test_l2_kind_content_hash() {
        assert_eq!(
            MemoryEventType::MemoryContentHashed { entry_id: "e".into(), hash: "h".into() }.kind(),
            "content_hash"
        );
        assert_eq!(
            MemoryEventType::MemoryHashChainAppended { chain_length: "1".into(), chain_hash: "h".into() }.kind(),
            "content_hash"
        );
    }

    #[test]
    fn test_l2_kind_retention_engine() {
        assert_eq!(
            MemoryEventType::RetentionEvaluated { entry_id: "e".into(), outcome: "R".into(), policy_id: "p".into() }.kind(),
            "retention_engine"
        );
        assert_eq!(
            MemoryEventType::RetentionScanCompleted { policy_id: "p".into(), expired_count: "0".into() }.kind(),
            "retention_engine"
        );
    }

    #[test]
    fn test_l2_kind_redaction() {
        assert_eq!(
            MemoryEventType::ContentRedacted { entry_id: "e".into(), policy_id: "p".into(), action_count: "1".into() }.kind(),
            "redaction"
        );
    }

    #[test]
    fn test_l2_kind_window_manager() {
        assert_eq!(
            MemoryEventType::ConversationWindowTrimExecuted { scope_id: "s".into(), removed_count: "1".into(), strategy: "T".into() }.kind(),
            "window_manager"
        );
        assert_eq!(
            MemoryEventType::TokenEstimateComputed { scope_id: "s".into(), token_count: "10".into() }.kind(),
            "window_manager"
        );
    }

    #[test]
    fn test_l2_kind_access_evaluator() {
        assert_eq!(
            MemoryEventType::AccessEvaluated { request_id: "r".into(), decision: "G".into() }.kind(),
            "access_evaluator"
        );
        assert_eq!(
            MemoryEventType::RetrievalEvaluated { request_id: "r".into(), decision: "P".into() }.kind(),
            "access_evaluator"
        );
    }

    #[test]
    fn test_l2_kind_metrics() {
        assert_eq!(
            MemoryEventType::MemoryMetricsComputed { metric_name: "m".into(), value: "1".into() }.kind(),
            "metrics"
        );
    }
}
