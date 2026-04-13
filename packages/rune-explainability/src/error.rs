// ═══════════════════════════════════════════════════════════════════════
// ExplainabilityError — typed errors for explainability operations.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum ExplainabilityError {
    DecisionNotFound(String),
    DecisionAlreadyExists(String),
    TraceConstructionFailed(String),
    FactorAnalysisFailed(String),
    CounterfactualGenerationFailed(String),
    NarrativeGenerationFailed(String),
    ReportGenerationFailed(String),
    InvalidFactor(String),
    InvalidWeight { min: f64, max: f64, actual: f64 },
    InvalidOperation(String),
}

impl fmt::Display for ExplainabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecisionNotFound(id) => write!(f, "decision not found: {id}"),
            Self::DecisionAlreadyExists(id) => write!(f, "decision already exists: {id}"),
            Self::TraceConstructionFailed(s) => write!(f, "trace construction failed: {s}"),
            Self::FactorAnalysisFailed(s) => write!(f, "factor analysis failed: {s}"),
            Self::CounterfactualGenerationFailed(s) => {
                write!(f, "counterfactual generation failed: {s}")
            }
            Self::NarrativeGenerationFailed(s) => write!(f, "narrative generation failed: {s}"),
            Self::ReportGenerationFailed(s) => write!(f, "report generation failed: {s}"),
            Self::InvalidFactor(s) => write!(f, "invalid factor: {s}"),
            Self::InvalidWeight { min, max, actual } => {
                write!(f, "invalid weight: {actual} not in [{min}, {max}]")
            }
            Self::InvalidOperation(s) => write!(f, "invalid operation: {s}"),
        }
    }
}

impl std::error::Error for ExplainabilityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors = [
            ExplainabilityError::DecisionNotFound("d1".into()),
            ExplainabilityError::DecisionAlreadyExists("d1".into()),
            ExplainabilityError::TraceConstructionFailed("bad".into()),
            ExplainabilityError::FactorAnalysisFailed("fail".into()),
            ExplainabilityError::CounterfactualGenerationFailed("gen".into()),
            ExplainabilityError::NarrativeGenerationFailed("nar".into()),
            ExplainabilityError::ReportGenerationFailed("rep".into()),
            ExplainabilityError::InvalidFactor("fac".into()),
            ExplainabilityError::InvalidWeight {
                min: 0.0,
                max: 1.0,
                actual: 1.5,
            },
            ExplainabilityError::InvalidOperation("op".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
        assert!(errors[8].to_string().contains("1.5"));
    }
}
