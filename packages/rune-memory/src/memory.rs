// ═══════════════════════════════════════════════════════════════════════
// Core memory entry types — MemoryEntry, MemoryScope, MemoryAccessRequest,
// MemoryAccessDecision, and supporting enums for content type,
// sensitivity, scope type, isolation level, and access type.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── MemoryContentType ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryContentType {
    ConversationTurn,
    RetrievalResult,
    WorkingContext,
    Embedding,
    Summary,
    Annotation,
    Custom { name: String },
}

impl fmt::Display for MemoryContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConversationTurn => write!(f, "ConversationTurn"),
            Self::RetrievalResult => write!(f, "RetrievalResult"),
            Self::WorkingContext => write!(f, "WorkingContext"),
            Self::Embedding => write!(f, "Embedding"),
            Self::Summary => write!(f, "Summary"),
            Self::Annotation => write!(f, "Annotation"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── MemorySensitivity ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MemorySensitivity {
    Public,
    Internal,
    Sensitive,
    Restricted,
}

impl fmt::Display for MemorySensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Public => "Public",
            Self::Internal => "Internal",
            Self::Sensitive => "Sensitive",
            Self::Restricted => "Restricted",
        };
        f.write_str(s)
    }
}

// ── MemoryScopeType ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryScopeType {
    AgentLocal,
    SessionScoped,
    TenantShared,
    Global,
    Custom { name: String },
}

impl fmt::Display for MemoryScopeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentLocal => write!(f, "AgentLocal"),
            Self::SessionScoped => write!(f, "SessionScoped"),
            Self::TenantShared => write!(f, "TenantShared"),
            Self::Global => write!(f, "Global"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── MemoryIsolationLevel ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryIsolationLevel {
    Strict,
    Shared,
    ReadShared,
    Custom { name: String },
}

impl fmt::Display for MemoryIsolationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "Strict"),
            Self::Shared => write!(f, "Shared"),
            Self::ReadShared => write!(f, "ReadShared"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── MemoryAccessType ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryAccessType {
    Read,
    Write,
    Delete,
    Search,
    List,
}

impl fmt::Display for MemoryAccessType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Read => "Read",
            Self::Write => "Write",
            Self::Delete => "Delete",
            Self::Search => "Search",
            Self::List => "List",
        };
        f.write_str(s)
    }
}

// ── MemoryAccessDecision ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryAccessDecision {
    Granted { reason: String },
    Denied { reason: String },
    PartiallyGranted {
        granted_entries: Vec<String>,
        denied_entries: Vec<String>,
        reason: String,
    },
    RequiresEscalation { reason: String },
}

impl fmt::Display for MemoryAccessDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted { reason } => write!(f, "Granted({reason})"),
            Self::Denied { reason } => write!(f, "Denied({reason})"),
            Self::PartiallyGranted {
                granted_entries,
                denied_entries,
                reason,
            } => write!(
                f,
                "PartiallyGranted(granted={}, denied={}, {reason})",
                granted_entries.len(),
                denied_entries.len()
            ),
            Self::RequiresEscalation { reason } => {
                write!(f, "RequiresEscalation({reason})")
            }
        }
    }
}

// ── MemoryEntry ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryEntry {
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
}

impl MemoryEntry {
    pub fn new(
        entry_id: impl Into<String>,
        scope_id: impl Into<String>,
        content: impl Into<String>,
        content_type: MemoryContentType,
        sensitivity_level: MemorySensitivity,
        created_by: impl Into<String>,
        created_at: i64,
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
        }
    }

    pub fn with_expiry(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_provenance(mut self, provenance_ref: impl Into<String>) -> Self {
        self.provenance_ref = Some(provenance_ref.into());
        self
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }
}

// ── MemoryScope ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryScope {
    pub scope_id: String,
    pub scope_type: MemoryScopeType,
    pub owner_id: String,
    pub isolation_level: MemoryIsolationLevel,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl MemoryScope {
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
        }
    }
}

// ── MemoryAccessRequest ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryAccessRequest {
    pub request_id: String,
    pub requester_id: String,
    pub scope_id: String,
    pub entry_id: Option<String>,
    pub access_type: MemoryAccessType,
    pub requested_at: i64,
    pub context: HashMap<String, String>,
}

impl MemoryAccessRequest {
    pub fn new(
        request_id: impl Into<String>,
        requester_id: impl Into<String>,
        scope_id: impl Into<String>,
        access_type: MemoryAccessType,
        requested_at: i64,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            requester_id: requester_id.into(),
            scope_id: scope_id.into(),
            entry_id: None,
            access_type,
            requested_at,
            context: HashMap::new(),
        }
    }

    pub fn with_entry(mut self, entry_id: impl Into<String>) -> Self {
        self.entry_id = Some(entry_id.into());
        self
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_content_type_display() {
        let types = vec![
            MemoryContentType::ConversationTurn,
            MemoryContentType::RetrievalResult,
            MemoryContentType::WorkingContext,
            MemoryContentType::Embedding,
            MemoryContentType::Summary,
            MemoryContentType::Annotation,
            MemoryContentType::Custom {
                name: "tool-output".into(),
            },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 7);
    }

    #[test]
    fn test_memory_sensitivity_display() {
        let levels = vec![
            MemorySensitivity::Public,
            MemorySensitivity::Internal,
            MemorySensitivity::Sensitive,
            MemorySensitivity::Restricted,
        ];
        for l in &levels {
            assert!(!l.to_string().is_empty());
        }
        assert_eq!(levels.len(), 4);
    }

    #[test]
    fn test_memory_sensitivity_ord() {
        assert!(MemorySensitivity::Public < MemorySensitivity::Internal);
        assert!(MemorySensitivity::Internal < MemorySensitivity::Sensitive);
        assert!(MemorySensitivity::Sensitive < MemorySensitivity::Restricted);
    }

    #[test]
    fn test_memory_scope_type_display() {
        let types = vec![
            MemoryScopeType::AgentLocal,
            MemoryScopeType::SessionScoped,
            MemoryScopeType::TenantShared,
            MemoryScopeType::Global,
            MemoryScopeType::Custom {
                name: "workflow".into(),
            },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 5);
    }

    #[test]
    fn test_memory_isolation_level_display() {
        let levels = vec![
            MemoryIsolationLevel::Strict,
            MemoryIsolationLevel::Shared,
            MemoryIsolationLevel::ReadShared,
            MemoryIsolationLevel::Custom {
                name: "tiered".into(),
            },
        ];
        for l in &levels {
            assert!(!l.to_string().is_empty());
        }
        assert_eq!(levels.len(), 4);
    }

    #[test]
    fn test_memory_access_type_display() {
        let types = vec![
            MemoryAccessType::Read,
            MemoryAccessType::Write,
            MemoryAccessType::Delete,
            MemoryAccessType::Search,
            MemoryAccessType::List,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 5);
    }

    #[test]
    fn test_memory_access_decision_display() {
        let decisions = vec![
            MemoryAccessDecision::Granted {
                reason: "authorized".into(),
            },
            MemoryAccessDecision::Denied {
                reason: "no access".into(),
            },
            MemoryAccessDecision::PartiallyGranted {
                granted_entries: vec!["e1".into()],
                denied_entries: vec!["e2".into()],
                reason: "partial".into(),
            },
            MemoryAccessDecision::RequiresEscalation {
                reason: "restricted scope".into(),
            },
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(decisions.len(), 4);
    }

    #[test]
    fn test_memory_entry_construction() {
        let entry = MemoryEntry::new(
            "e1",
            "scope-1",
            "hello world",
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Internal,
            "agent-1",
            1000,
        );
        assert_eq!(entry.entry_id, "e1");
        assert_eq!(entry.scope_id, "scope-1");
        assert_eq!(entry.content, "hello world");
        assert_eq!(entry.content_type, MemoryContentType::ConversationTurn);
        assert_eq!(entry.sensitivity_level, MemorySensitivity::Internal);
        assert_eq!(entry.created_by, "agent-1");
        assert_eq!(entry.created_at, 1000);
        assert!(entry.expires_at.is_none());
        assert!(entry.provenance_ref.is_none());
    }

    #[test]
    fn test_memory_entry_with_expiry() {
        let entry = MemoryEntry::new(
            "e1",
            "scope-1",
            "data",
            MemoryContentType::WorkingContext,
            MemorySensitivity::Public,
            "agent-1",
            1000,
        )
        .with_expiry(5000);
        assert_eq!(entry.expires_at, Some(5000));
    }

    #[test]
    fn test_memory_entry_is_expired() {
        let entry = MemoryEntry::new(
            "e1",
            "scope-1",
            "data",
            MemoryContentType::Summary,
            MemorySensitivity::Public,
            "agent-1",
            1000,
        )
        .with_expiry(5000);
        assert!(!entry.is_expired(4999));
        assert!(entry.is_expired(5000));
        assert!(entry.is_expired(6000));
    }

    #[test]
    fn test_memory_entry_no_expiry_never_expires() {
        let entry = MemoryEntry::new(
            "e1",
            "scope-1",
            "data",
            MemoryContentType::Annotation,
            MemorySensitivity::Public,
            "agent-1",
            1000,
        );
        assert!(!entry.is_expired(i64::MAX));
    }

    #[test]
    fn test_memory_entry_with_provenance() {
        let entry = MemoryEntry::new(
            "e1",
            "scope-1",
            "data",
            MemoryContentType::RetrievalResult,
            MemorySensitivity::Sensitive,
            "agent-1",
            1000,
        )
        .with_provenance("attestation-abc-123");
        assert_eq!(
            entry.provenance_ref,
            Some("attestation-abc-123".to_string())
        );
    }

    #[test]
    fn test_memory_scope_construction() {
        let scope = MemoryScope::new(
            "scope-1",
            MemoryScopeType::AgentLocal,
            "agent-1",
            MemoryIsolationLevel::Strict,
            1000,
        );
        assert_eq!(scope.scope_id, "scope-1");
        assert_eq!(scope.scope_type, MemoryScopeType::AgentLocal);
        assert_eq!(scope.owner_id, "agent-1");
        assert_eq!(scope.isolation_level, MemoryIsolationLevel::Strict);
    }

    #[test]
    fn test_memory_access_request_construction() {
        let req = MemoryAccessRequest::new("r1", "agent-1", "scope-1", MemoryAccessType::Read, 1000);
        assert_eq!(req.request_id, "r1");
        assert_eq!(req.requester_id, "agent-1");
        assert_eq!(req.scope_id, "scope-1");
        assert!(req.entry_id.is_none());
        assert_eq!(req.access_type, MemoryAccessType::Read);
    }

    #[test]
    fn test_memory_access_request_with_entry() {
        let req = MemoryAccessRequest::new("r1", "agent-1", "scope-1", MemoryAccessType::Write, 1000)
            .with_entry("e1");
        assert_eq!(req.entry_id, Some("e1".into()));
    }

    #[test]
    fn test_memory_entry_eq() {
        let e1 = MemoryEntry::new(
            "e1",
            "scope-1",
            "data",
            MemoryContentType::Embedding,
            MemorySensitivity::Restricted,
            "agent-1",
            1000,
        );
        assert_eq!(e1, e1.clone());
    }

    #[test]
    fn test_custom_content_type() {
        let ct = MemoryContentType::Custom {
            name: "chain-of-thought".into(),
        };
        assert_eq!(ct.to_string(), "Custom(chain-of-thought)");
    }

    #[test]
    fn test_memory_sensitivity_eq() {
        assert_eq!(MemorySensitivity::Public, MemorySensitivity::Public);
        assert_ne!(MemorySensitivity::Public, MemorySensitivity::Internal);
    }

    #[test]
    fn test_memory_entry_metadata() {
        let mut entry = MemoryEntry::new(
            "e1",
            "scope-1",
            "data",
            MemoryContentType::WorkingContext,
            MemorySensitivity::Public,
            "agent-1",
            1000,
        );
        entry.metadata.insert("key".into(), "value".into());
        assert_eq!(entry.metadata.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_memory_scope_metadata() {
        let mut scope = MemoryScope::new(
            "scope-1",
            MemoryScopeType::SessionScoped,
            "agent-1",
            MemoryIsolationLevel::ReadShared,
            1000,
        );
        scope.metadata.insert("session".into(), "abc".into());
        assert_eq!(scope.metadata.len(), 1);
    }

    #[test]
    fn test_memory_access_request_context() {
        let mut req = MemoryAccessRequest::new("r1", "agent-1", "scope-1", MemoryAccessType::Search, 1000);
        req.context.insert("query".into(), "test".into());
        assert_eq!(req.context.get("query"), Some(&"test".to_string()));
    }

    #[test]
    fn test_custom_scope_type() {
        let st = MemoryScopeType::Custom {
            name: "workflow".into(),
        };
        assert_eq!(st.to_string(), "Custom(workflow)");
    }

    #[test]
    fn test_custom_isolation_level() {
        let il = MemoryIsolationLevel::Custom {
            name: "tiered".into(),
        };
        assert_eq!(il.to_string(), "Custom(tiered)");
    }

    #[test]
    fn test_partially_granted_display() {
        let d = MemoryAccessDecision::PartiallyGranted {
            granted_entries: vec!["e1".into(), "e2".into()],
            denied_entries: vec!["e3".into()],
            reason: "mixed".into(),
        };
        let s = d.to_string();
        assert!(s.contains("granted=2"));
        assert!(s.contains("denied=1"));
    }
}
