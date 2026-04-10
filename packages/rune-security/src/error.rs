// ═══════════════════════════════════════════════════════════════════════
// SecurityError — Error types for rune-security
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityError {
    ThreatModelInvalid(String),
    VulnerabilityNotFound(String),
    VulnerabilityAlreadyExists(String),
    IncidentNotFound(String),
    InvalidStatusTransition { from: String, to: String },
    EscalationFailed(String),
    PolicyEvaluationFailed(String),
    ContextDepthExceeded { max: u32, attempted: u32 },
    PostureAssessmentFailed(String),
    MetricNotFound(String),
    InvalidScore { min: f64, max: f64, actual: f64 },
    InvalidOperation(String),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThreatModelInvalid(s) => write!(f, "threat model invalid: {s}"),
            Self::VulnerabilityNotFound(id) => write!(f, "vulnerability not found: {id}"),
            Self::VulnerabilityAlreadyExists(id) => {
                write!(f, "vulnerability already exists: {id}")
            }
            Self::IncidentNotFound(id) => write!(f, "incident not found: {id}"),
            Self::InvalidStatusTransition { from, to } => {
                write!(f, "invalid status transition from {from} to {to}")
            }
            Self::EscalationFailed(s) => write!(f, "escalation failed: {s}"),
            Self::PolicyEvaluationFailed(s) => write!(f, "policy evaluation failed: {s}"),
            Self::ContextDepthExceeded { max, attempted } => {
                write!(
                    f,
                    "context depth exceeded: max {max}, attempted {attempted}"
                )
            }
            Self::PostureAssessmentFailed(s) => write!(f, "posture assessment failed: {s}"),
            Self::MetricNotFound(id) => write!(f, "metric not found: {id}"),
            Self::InvalidScore { min, max, actual } => {
                write!(f, "invalid score {actual}: must be in [{min}, {max}]")
            }
            Self::InvalidOperation(s) => write!(f, "invalid operation: {s}"),
        }
    }
}

impl std::error::Error for SecurityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_display() {
        let errs = [
            SecurityError::ThreatModelInvalid("bad".into()),
            SecurityError::VulnerabilityNotFound("v1".into()),
            SecurityError::VulnerabilityAlreadyExists("v1".into()),
            SecurityError::IncidentNotFound("i1".into()),
            SecurityError::InvalidStatusTransition {
                from: "New".into(),
                to: "Closed".into(),
            },
            SecurityError::EscalationFailed("no route".into()),
            SecurityError::PolicyEvaluationFailed("bad rule".into()),
            SecurityError::ContextDepthExceeded {
                max: 64,
                attempted: 65,
            },
            SecurityError::PostureAssessmentFailed("empty".into()),
            SecurityError::MetricNotFound("m1".into()),
            SecurityError::InvalidScore {
                min: 0.0,
                max: 10.0,
                actual: 11.0,
            },
            SecurityError::InvalidOperation("nope".into()),
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
        }
    }
}
