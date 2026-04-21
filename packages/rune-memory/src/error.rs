// ═══════════════════════════════════════════════════════════════════════
// Error — Memory governance error types.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone)]
pub enum MemoryError {
    EntryNotFound(String),
    ScopeNotFound(String),
    AccessDenied { requester_id: String, scope_id: String, reason: String },
    IsolationViolation { boundary_id: String, reason: String },
    RetentionPolicyViolation { policy_id: String, reason: String },
    InvalidConfiguration(String),
    InvalidOperation(String),
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryNotFound(id) => write!(f, "Memory entry not found: {id}"),
            Self::ScopeNotFound(id) => write!(f, "Memory scope not found: {id}"),
            Self::AccessDenied { requester_id, scope_id, reason } => {
                write!(f, "Access denied ({requester_id}→{scope_id}): {reason}")
            }
            Self::IsolationViolation { boundary_id, reason } => {
                write!(f, "Isolation violation (boundary={boundary_id}): {reason}")
            }
            Self::RetentionPolicyViolation { policy_id, reason } => {
                write!(f, "Retention policy violation ({policy_id}): {reason}")
            }
            Self::InvalidConfiguration(detail) => {
                write!(f, "Invalid configuration: {detail}")
            }
            Self::InvalidOperation(detail) => write!(f, "Invalid operation: {detail}"),
        }
    }
}

impl std::error::Error for MemoryError {}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors: Vec<MemoryError> = vec![
            MemoryError::EntryNotFound("e1".into()),
            MemoryError::ScopeNotFound("s1".into()),
            MemoryError::AccessDenied {
                requester_id: "agent-1".into(),
                scope_id: "scope-1".into(),
                reason: "no permission".into(),
            },
            MemoryError::IsolationViolation {
                boundary_id: "ib-1".into(),
                reason: "cross-scope read".into(),
            },
            MemoryError::RetentionPolicyViolation {
                policy_id: "rp-1".into(),
                reason: "max entries exceeded".into(),
            },
            MemoryError::InvalidConfiguration("bad config".into()),
            MemoryError::InvalidOperation("bad op".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(errors.len(), 7);
    }

    #[test]
    fn test_error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(MemoryError::EntryNotFound("e1".into()));
        assert!(!err.to_string().is_empty());
    }
}
