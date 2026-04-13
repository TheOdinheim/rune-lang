// ═══════════════════════════════════════════════════════════════════════
// Error — Safety-specific error types
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum SafetyError {
    ConstraintNotFound(String),
    ConstraintAlreadyExists(String),
    ConstraintViolation { constraint_id: String, detail: String },
    MonitorNotFound(String),
    MonitorAlreadyExists(String),
    FailsafeNotFound(String),
    FailsafeAlreadyExists(String),
    HazardNotFound(String),
    HazardAlreadyExists(String),
    SafetyCaseNotFound(String),
    SafetyCaseAlreadyExists(String),
    AssessmentFailed(String),
    InvalidConfiguration(String),
    InvalidOperation(String),
}

impl fmt::Display for SafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConstraintNotFound(id) => write!(f, "Constraint not found: {id}"),
            Self::ConstraintAlreadyExists(id) => write!(f, "Constraint already exists: {id}"),
            Self::ConstraintViolation { constraint_id, detail } => {
                write!(f, "Constraint violation [{constraint_id}]: {detail}")
            }
            Self::MonitorNotFound(id) => write!(f, "Monitor not found: {id}"),
            Self::MonitorAlreadyExists(id) => write!(f, "Monitor already exists: {id}"),
            Self::FailsafeNotFound(id) => write!(f, "Failsafe not found: {id}"),
            Self::FailsafeAlreadyExists(id) => write!(f, "Failsafe already exists: {id}"),
            Self::HazardNotFound(id) => write!(f, "Hazard not found: {id}"),
            Self::HazardAlreadyExists(id) => write!(f, "Hazard already exists: {id}"),
            Self::SafetyCaseNotFound(id) => write!(f, "Safety case not found: {id}"),
            Self::SafetyCaseAlreadyExists(id) => write!(f, "Safety case already exists: {id}"),
            Self::AssessmentFailed(reason) => write!(f, "Assessment failed: {reason}"),
            Self::InvalidConfiguration(reason) => write!(f, "Invalid configuration: {reason}"),
            Self::InvalidOperation(reason) => write!(f, "Invalid operation: {reason}"),
        }
    }
}

impl std::error::Error for SafetyError {}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_display() {
        let variants: Vec<SafetyError> = vec![
            SafetyError::ConstraintNotFound("c1".into()),
            SafetyError::ConstraintAlreadyExists("c1".into()),
            SafetyError::ConstraintViolation { constraint_id: "c1".into(), detail: "d".into() },
            SafetyError::MonitorNotFound("m1".into()),
            SafetyError::MonitorAlreadyExists("m1".into()),
            SafetyError::FailsafeNotFound("f1".into()),
            SafetyError::FailsafeAlreadyExists("f1".into()),
            SafetyError::HazardNotFound("h1".into()),
            SafetyError::HazardAlreadyExists("h1".into()),
            SafetyError::SafetyCaseNotFound("sc1".into()),
            SafetyError::SafetyCaseAlreadyExists("sc1".into()),
            SafetyError::AssessmentFailed("r".into()),
            SafetyError::InvalidConfiguration("r".into()),
            SafetyError::InvalidOperation("r".into()),
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
        assert_eq!(variants.len(), 14);
    }
}
