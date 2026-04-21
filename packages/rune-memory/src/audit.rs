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
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 20);
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
        ];
        for event in &events {
            assert!(!event.type_name().is_empty());
        }
        assert_eq!(events.len(), 20);
    }
}
