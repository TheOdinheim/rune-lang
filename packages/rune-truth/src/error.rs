// ═══════════════════════════════════════════════════════════════════════
// TruthError — typed errors for truth verification operations.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum TruthError {
    ConfidenceCalculationFailed(String),
    ConsistencyCheckFailed(String),
    AttributionFailed(String),
    ContradictionNotFound(String),
    ContradictionAlreadyResolved(String),
    GroundTruthNotFound(String),
    ClaimNotFound(String),
    ClaimAlreadyExists(String),
    ClaimAlreadyVerified(String),
    InsufficientEvidence(String),
    InvalidScore { min: f64, max: f64, actual: f64 },
    InvalidOperation(String),
}

impl fmt::Display for TruthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfidenceCalculationFailed(s) => write!(f, "confidence calculation failed: {s}"),
            Self::ConsistencyCheckFailed(s) => write!(f, "consistency check failed: {s}"),
            Self::AttributionFailed(s) => write!(f, "attribution failed: {s}"),
            Self::ContradictionNotFound(id) => write!(f, "contradiction not found: {id}"),
            Self::ContradictionAlreadyResolved(id) => {
                write!(f, "contradiction already resolved: {id}")
            }
            Self::GroundTruthNotFound(id) => write!(f, "ground truth not found: {id}"),
            Self::ClaimNotFound(id) => write!(f, "claim not found: {id}"),
            Self::ClaimAlreadyExists(id) => write!(f, "claim already exists: {id}"),
            Self::ClaimAlreadyVerified(id) => write!(f, "claim already verified: {id}"),
            Self::InsufficientEvidence(s) => write!(f, "insufficient evidence: {s}"),
            Self::InvalidScore { min, max, actual } => {
                write!(f, "invalid score: {actual} not in [{min}, {max}]")
            }
            Self::InvalidOperation(s) => write!(f, "invalid operation: {s}"),
        }
    }
}

impl std::error::Error for TruthError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors = [
            TruthError::ConfidenceCalculationFailed("bad".into()),
            TruthError::ConsistencyCheckFailed("fail".into()),
            TruthError::AttributionFailed("attr".into()),
            TruthError::ContradictionNotFound("c1".into()),
            TruthError::ContradictionAlreadyResolved("c1".into()),
            TruthError::GroundTruthNotFound("gt1".into()),
            TruthError::ClaimNotFound("cl1".into()),
            TruthError::ClaimAlreadyExists("cl1".into()),
            TruthError::ClaimAlreadyVerified("cl1".into()),
            TruthError::InsufficientEvidence("need more".into()),
            TruthError::InvalidScore {
                min: 0.0,
                max: 1.0,
                actual: 1.5,
            },
            TruthError::InvalidOperation("op".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
        assert!(errors[10].to_string().contains("1.5"));
    }
}
