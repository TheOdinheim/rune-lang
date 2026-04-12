// ═══════════════════════════════════════════════════════════════════════
// ProvenanceError — typed errors for provenance operations.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    ArtifactNotFound(String),
    ArtifactAlreadyExists(String),
    LineageNotFound(String),
    LineageAlreadyExists(String),
    TransformationNotFound(String),
    ModelNotFound(String),
    ModelAlreadyExists(String),
    DependencyNotFound(String),
    DependencyAlreadyExists(String),
    VerificationFailed { artifact_id: String, reason: String },
    HashMismatch { expected: String, actual: String },
    CycleDetected { path: Vec<String> },
    InvalidVersion(String),
    InvalidOperation(String),
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactNotFound(id) => write!(f, "artifact not found: {id}"),
            Self::ArtifactAlreadyExists(id) => write!(f, "artifact already exists: {id}"),
            Self::LineageNotFound(id) => write!(f, "lineage not found: {id}"),
            Self::LineageAlreadyExists(id) => write!(f, "lineage already exists: {id}"),
            Self::TransformationNotFound(id) => write!(f, "transformation not found: {id}"),
            Self::ModelNotFound(id) => write!(f, "model not found: {id}"),
            Self::ModelAlreadyExists(id) => write!(f, "model already exists: {id}"),
            Self::DependencyNotFound(id) => write!(f, "dependency not found: {id}"),
            Self::DependencyAlreadyExists(id) => write!(f, "dependency already exists: {id}"),
            Self::VerificationFailed { artifact_id, reason } => {
                write!(f, "verification failed for {artifact_id}: {reason}")
            }
            Self::HashMismatch { expected, actual } => {
                write!(f, "hash mismatch: expected {expected}, got {actual}")
            }
            Self::CycleDetected { path } => write!(f, "cycle detected: {}", path.join(" → ")),
            Self::InvalidVersion(v) => write!(f, "invalid version: {v}"),
            Self::InvalidOperation(op) => write!(f, "invalid operation: {op}"),
        }
    }
}

impl std::error::Error for ProvenanceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors = [
            ProvenanceError::ArtifactNotFound("a".into()),
            ProvenanceError::ArtifactAlreadyExists("a".into()),
            ProvenanceError::LineageNotFound("l".into()),
            ProvenanceError::LineageAlreadyExists("l".into()),
            ProvenanceError::TransformationNotFound("t".into()),
            ProvenanceError::ModelNotFound("m".into()),
            ProvenanceError::ModelAlreadyExists("m".into()),
            ProvenanceError::DependencyNotFound("d".into()),
            ProvenanceError::DependencyAlreadyExists("d".into()),
            ProvenanceError::VerificationFailed {
                artifact_id: "a".into(),
                reason: "bad".into(),
            },
            ProvenanceError::HashMismatch {
                expected: "aaa".into(),
                actual: "bbb".into(),
            },
            ProvenanceError::CycleDetected {
                path: vec!["a".into(), "b".into(), "a".into()],
            },
            ProvenanceError::InvalidVersion("x".into()),
            ProvenanceError::InvalidOperation("op".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
        // Verify cycle path formatting
        let cycle = &errors[11];
        assert!(cycle.to_string().contains("a → b → a"));
    }
}
