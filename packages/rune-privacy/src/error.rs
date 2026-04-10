// ═══════════════════════════════════════════════════════════════════════
// Privacy Error Types
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone)]
pub enum PrivacyError {
    PiiDetectionFailed(String),
    AnonymizationFailed { field: String, method: String, reason: String },
    InsufficientPrivacyBudget { required_epsilon: f64, remaining_epsilon: f64 },
    ConsentNotFound(String),
    ConsentAlreadyWithdrawn(String),
    ConsentRequired { purpose: String, subject: String },
    PurposeNotFound(String),
    PurposeViolation { data_id: String, intended: String, allowed: Vec<String> },
    RightsRequestNotFound(String),
    RightsRequestOverdue { request_id: String, deadline: i64 },
    RetentionViolation { data_id: String, max_days: u64, actual_days: u64 },
    InvalidBudget(String),
    MinimizationViolation { excess_fields: Vec<String> },
    InvalidOperation(String),
}

impl fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PiiDetectionFailed(s) => write!(f, "PII detection failed: {s}"),
            Self::AnonymizationFailed { field, method, reason } => {
                write!(f, "anonymization of field '{field}' via {method} failed: {reason}")
            }
            Self::InsufficientPrivacyBudget { required_epsilon, remaining_epsilon } => write!(
                f,
                "insufficient privacy budget: required ε={required_epsilon:.4}, remaining ε={remaining_epsilon:.4}"
            ),
            Self::ConsentNotFound(id) => write!(f, "consent not found: {id}"),
            Self::ConsentAlreadyWithdrawn(id) => write!(f, "consent already withdrawn: {id}"),
            Self::ConsentRequired { purpose, subject } => {
                write!(f, "consent required from subject {subject} for purpose {purpose}")
            }
            Self::PurposeNotFound(id) => write!(f, "purpose not found: {id}"),
            Self::PurposeViolation { data_id, intended, allowed } => write!(
                f,
                "purpose violation: data {data_id} cannot be used for '{intended}' (allowed: {allowed:?})"
            ),
            Self::RightsRequestNotFound(id) => write!(f, "rights request not found: {id}"),
            Self::RightsRequestOverdue { request_id, deadline } => {
                write!(f, "rights request {request_id} overdue (deadline: {deadline})")
            }
            Self::RetentionViolation { data_id, max_days, actual_days } => write!(
                f,
                "retention violation: {data_id} is {actual_days} days old (max {max_days})"
            ),
            Self::InvalidBudget(s) => write!(f, "invalid privacy budget: {s}"),
            Self::MinimizationViolation { excess_fields } => {
                write!(f, "data minimization violation: excess fields {excess_fields:?}")
            }
            Self::InvalidOperation(s) => write!(f, "invalid operation: {s}"),
        }
    }
}

impl std::error::Error for PrivacyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_display() {
        let errors = vec![
            PrivacyError::PiiDetectionFailed("x".into()),
            PrivacyError::AnonymizationFailed { field: "f".into(), method: "m".into(), reason: "r".into() },
            PrivacyError::InsufficientPrivacyBudget { required_epsilon: 1.0, remaining_epsilon: 0.1 },
            PrivacyError::ConsentNotFound("c1".into()),
            PrivacyError::ConsentAlreadyWithdrawn("c1".into()),
            PrivacyError::ConsentRequired { purpose: "p".into(), subject: "s".into() },
            PrivacyError::PurposeNotFound("p".into()),
            PrivacyError::PurposeViolation { data_id: "d".into(), intended: "i".into(), allowed: vec!["a".into()] },
            PrivacyError::RightsRequestNotFound("r".into()),
            PrivacyError::RightsRequestOverdue { request_id: "r".into(), deadline: 1000 },
            PrivacyError::RetentionViolation { data_id: "d".into(), max_days: 30, actual_days: 60 },
            PrivacyError::InvalidBudget("x".into()),
            PrivacyError::MinimizationViolation { excess_fields: vec!["f".into()] },
            PrivacyError::InvalidOperation("x".into()),
        ];
        for e in errors {
            assert!(!e.to_string().is_empty());
        }
    }
}
