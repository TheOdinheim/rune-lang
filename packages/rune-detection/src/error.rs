// ═══════════════════════════════════════════════════════════════════════
// DetectionError — error types for the detection crate
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionError {
    AlertNotFound(String),
    AlertAlreadyResolved(String),
    RuleNotFound(String),
    RuleAlreadyExists(String),
    InsufficientBaseline {
        profile: String,
        required: u64,
        actual: u64,
    },
    PipelineError(String),
    InvalidConfiguration(String),
    InvalidSignal(String),
    InvalidOperation(String),
}

impl fmt::Display for DetectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlertNotFound(id) => write!(f, "alert not found: {id}"),
            Self::AlertAlreadyResolved(id) => write!(f, "alert already resolved: {id}"),
            Self::RuleNotFound(id) => write!(f, "rule not found: {id}"),
            Self::RuleAlreadyExists(id) => write!(f, "rule already exists: {id}"),
            Self::InsufficientBaseline { profile, required, actual } => write!(
                f,
                "insufficient baseline for profile {profile}: required {required} observations, have {actual}"
            ),
            Self::PipelineError(msg) => write!(f, "pipeline error: {msg}"),
            Self::InvalidConfiguration(msg) => write!(f, "invalid configuration: {msg}"),
            Self::InvalidSignal(msg) => write!(f, "invalid signal: {msg}"),
            Self::InvalidOperation(msg) => write!(f, "invalid operation: {msg}"),
        }
    }
}

impl std::error::Error for DetectionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_variants() {
        let errors = [
            DetectionError::AlertNotFound("a1".into()),
            DetectionError::AlertAlreadyResolved("a1".into()),
            DetectionError::RuleNotFound("r1".into()),
            DetectionError::RuleAlreadyExists("r1".into()),
            DetectionError::InsufficientBaseline {
                profile: "user:alice".into(),
                required: 10,
                actual: 3,
            },
            DetectionError::PipelineError("stage failed".into()),
            DetectionError::InvalidConfiguration("bad threshold".into()),
            DetectionError::InvalidSignal("missing value".into()),
            DetectionError::InvalidOperation("cannot undo".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }
}
