// ═══════════════════════════════════════════════════════════════════════
// Error — PolicyExtError with 11 typed variants.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyExtError {
    PolicyNotFound(String),
    PolicyAlreadyExists(String),
    InvalidTransition { from: String, to: String },
    ConflictNotFound(String),
    ConflictAlreadyResolved(String),
    SimulationFailed(String),
    ImportFailed { format: String, reason: String },
    ExportFailed { format: String, reason: String },
    VersionNotFound { policy_id: String, version: String },
    InvalidExpression(String),
    InvalidOperation(String),
    SerializationFailed(String),
    PackageNotFound(String),
}

impl fmt::Display for PolicyExtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyNotFound(id) => write!(f, "policy not found: {id}"),
            Self::PolicyAlreadyExists(id) => write!(f, "policy already exists: {id}"),
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {from} → {to}")
            }
            Self::ConflictNotFound(id) => write!(f, "conflict not found: {id}"),
            Self::ConflictAlreadyResolved(id) => write!(f, "conflict already resolved: {id}"),
            Self::SimulationFailed(reason) => write!(f, "simulation failed: {reason}"),
            Self::ImportFailed { format, reason } => {
                write!(f, "import failed ({format}): {reason}")
            }
            Self::ExportFailed { format, reason } => {
                write!(f, "export failed ({format}): {reason}")
            }
            Self::VersionNotFound { policy_id, version } => {
                write!(f, "version not found: {policy_id}@{version}")
            }
            Self::InvalidExpression(reason) => write!(f, "invalid expression: {reason}"),
            Self::InvalidOperation(reason) => write!(f, "invalid operation: {reason}"),
            Self::SerializationFailed(reason) => write!(f, "serialization failed: {reason}"),
            Self::PackageNotFound(id) => write!(f, "package not found: {id}"),
        }
    }
}

impl std::error::Error for PolicyExtError {}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_display() {
        let variants: Vec<PolicyExtError> = vec![
            PolicyExtError::PolicyNotFound("p1".into()),
            PolicyExtError::PolicyAlreadyExists("p2".into()),
            PolicyExtError::InvalidTransition { from: "Draft".into(), to: "Active".into() },
            PolicyExtError::ConflictNotFound("c1".into()),
            PolicyExtError::ConflictAlreadyResolved("c2".into()),
            PolicyExtError::SimulationFailed("timeout".into()),
            PolicyExtError::ImportFailed { format: "json".into(), reason: "parse".into() },
            PolicyExtError::ExportFailed { format: "yaml".into(), reason: "io".into() },
            PolicyExtError::VersionNotFound { policy_id: "p1".into(), version: "0.1.0".into() },
            PolicyExtError::InvalidExpression("bad".into()),
            PolicyExtError::InvalidOperation("nope".into()),
            PolicyExtError::SerializationFailed("ser".into()),
            PolicyExtError::PackageNotFound("pkg-1".into()),
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }
}
