// ═══════════════════════════════════════════════════════════════════════
// Permission Error Types
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::types::{ClassificationLevel, PermissionId, SubjectId};
use crate::grant::GrantId;
use crate::role::RoleId;

/// Errors arising from permission operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionError {
    RoleNotFound(RoleId),
    RoleAlreadyExists(RoleId),
    CircularInheritance { role: RoleId, cycle: Vec<RoleId> },
    MutualExclusionViolation { role_a: RoleId, role_b: RoleId, subject: SubjectId },
    MaxHoldersExceeded { role: RoleId, max: usize, current: usize },
    SubjectNotFound(SubjectId),
    SubjectAlreadyExists(SubjectId),
    PermissionNotFound(PermissionId),
    PermissionAlreadyExists(PermissionId),
    GrantNotFound(GrantId),
    InsufficientClearance { required: ClassificationLevel, actual: ClassificationLevel },
    InvalidOperation(String),
}

impl fmt::Display for PermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoleNotFound(id) => write!(f, "role not found: {id}"),
            Self::RoleAlreadyExists(id) => write!(f, "role already exists: {id}"),
            Self::CircularInheritance { role, cycle } => {
                write!(f, "circular inheritance at role {role}: {cycle:?}")
            }
            Self::MutualExclusionViolation { role_a, role_b, subject } => {
                write!(
                    f,
                    "mutual exclusion: subject {subject} cannot hold both {role_a} and {role_b}"
                )
            }
            Self::MaxHoldersExceeded { role, max, current } => {
                write!(f, "role {role} max holders exceeded: {current}/{max}")
            }
            Self::SubjectNotFound(id) => write!(f, "subject not found: {id}"),
            Self::SubjectAlreadyExists(id) => write!(f, "subject already exists: {id}"),
            Self::PermissionNotFound(id) => write!(f, "permission not found: {id}"),
            Self::PermissionAlreadyExists(id) => write!(f, "permission already exists: {id}"),
            Self::GrantNotFound(id) => write!(f, "grant not found: {id}"),
            Self::InsufficientClearance { required, actual } => {
                write!(
                    f,
                    "insufficient clearance: required {required}, actual {actual}"
                )
            }
            Self::InvalidOperation(msg) => write!(f, "invalid operation: {msg}"),
        }
    }
}

impl std::error::Error for PermissionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_not_found_display() {
        let e = PermissionError::RoleNotFound(RoleId::new("admin"));
        assert!(e.to_string().contains("admin"));
    }

    #[test]
    fn test_role_already_exists_display() {
        let e = PermissionError::RoleAlreadyExists(RoleId::new("admin"));
        assert!(e.to_string().contains("already exists"));
    }

    #[test]
    fn test_circular_inheritance_display() {
        let e = PermissionError::CircularInheritance {
            role: RoleId::new("a"),
            cycle: vec![RoleId::new("a"), RoleId::new("b"), RoleId::new("a")],
        };
        let s = e.to_string();
        assert!(s.contains("circular"));
        assert!(s.contains("a"));
    }

    #[test]
    fn test_mutual_exclusion_display() {
        let e = PermissionError::MutualExclusionViolation {
            role_a: RoleId::new("admin"),
            role_b: RoleId::new("auditor"),
            subject: SubjectId::new("user1"),
        };
        assert!(e.to_string().contains("mutual exclusion"));
    }

    #[test]
    fn test_max_holders_display() {
        let e = PermissionError::MaxHoldersExceeded {
            role: RoleId::new("admin"),
            max: 3,
            current: 3,
        };
        assert!(e.to_string().contains("3/3"));
    }

    #[test]
    fn test_insufficient_clearance_display() {
        let e = PermissionError::InsufficientClearance {
            required: ClassificationLevel::TopSecret,
            actual: ClassificationLevel::Public,
        };
        let s = e.to_string();
        assert!(s.contains("TopSecret"));
        assert!(s.contains("Public"));
    }

    #[test]
    fn test_all_variants_display() {
        let errors: Vec<PermissionError> = vec![
            PermissionError::SubjectNotFound(SubjectId::new("x")),
            PermissionError::SubjectAlreadyExists(SubjectId::new("x")),
            PermissionError::PermissionNotFound(PermissionId::new("p")),
            PermissionError::PermissionAlreadyExists(PermissionId::new("p")),
            PermissionError::GrantNotFound(GrantId::new("g")),
            PermissionError::InvalidOperation("test".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }
}
