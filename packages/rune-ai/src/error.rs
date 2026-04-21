// ═══════════════════════════════════════════════════════════════════════
// Error — AI governance error types for rune-ai
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone)]
pub enum AiError {
    ModelNotFound(String),
    DatasetNotFound(String),
    EvaluationNotFound(String),
    DeploymentNotFound(String),
    InvalidTransition { model_id: String, from: String, to: String },
    PolicyViolation { policy_id: String, reason: String },
    ApprovalRequired { model_id: String, reason: String },
    InvalidConfiguration(String),
    InvalidOperation(String),
}

impl fmt::Display for AiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelNotFound(id) => write!(f, "Model not found: {id}"),
            Self::DatasetNotFound(id) => write!(f, "Dataset not found: {id}"),
            Self::EvaluationNotFound(id) => write!(f, "Evaluation not found: {id}"),
            Self::DeploymentNotFound(id) => write!(f, "Deployment not found: {id}"),
            Self::InvalidTransition { model_id, from, to } => {
                write!(f, "Invalid transition for model {model_id}: {from} → {to}")
            }
            Self::PolicyViolation { policy_id, reason } => {
                write!(f, "Policy violation ({policy_id}): {reason}")
            }
            Self::ApprovalRequired { model_id, reason } => {
                write!(f, "Approval required for model {model_id}: {reason}")
            }
            Self::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {msg}"),
            Self::InvalidOperation(msg) => write!(f, "Invalid operation: {msg}"),
        }
    }
}

impl std::error::Error for AiError {}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors: Vec<AiError> = vec![
            AiError::ModelNotFound("model-1".into()),
            AiError::DatasetNotFound("ds-1".into()),
            AiError::EvaluationNotFound("eval-1".into()),
            AiError::DeploymentNotFound("dep-1".into()),
            AiError::InvalidTransition {
                model_id: "model-1".into(),
                from: "Draft".into(),
                to: "Deployed".into(),
            },
            AiError::PolicyViolation {
                policy_id: "pol-1".into(),
                reason: "threshold exceeded".into(),
            },
            AiError::ApprovalRequired {
                model_id: "model-1".into(),
                reason: "production deployment".into(),
            },
            AiError::InvalidConfiguration("missing field".into()),
            AiError::InvalidOperation("cannot retire active model".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
            let _ = format!("{e:?}");
            let _: &dyn std::error::Error = e;
        }
        assert_eq!(errors.len(), 9);
    }

    #[test]
    fn test_model_not_found_message() {
        let e = AiError::ModelNotFound("abc-123".into());
        assert!(e.to_string().contains("abc-123"));
        assert!(e.to_string().contains("Model not found"));
    }

    #[test]
    fn test_invalid_transition_message() {
        let e = AiError::InvalidTransition {
            model_id: "m1".into(),
            from: "Draft".into(),
            to: "Deployed".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("m1"));
        assert!(msg.contains("Draft"));
        assert!(msg.contains("Deployed"));
    }

    #[test]
    fn test_policy_violation_message() {
        let e = AiError::PolicyViolation {
            policy_id: "fp-1".into(),
            reason: "fairness threshold breached".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("fp-1"));
        assert!(msg.contains("fairness threshold breached"));
    }

    #[test]
    fn test_approval_required_message() {
        let e = AiError::ApprovalRequired {
            model_id: "m1".into(),
            reason: "production gate".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("m1"));
        assert!(msg.contains("production gate"));
    }

    #[test]
    fn test_dataset_not_found_message() {
        let e = AiError::DatasetNotFound("ds-xyz".into());
        assert!(e.to_string().contains("ds-xyz"));
    }

    #[test]
    fn test_evaluation_not_found_message() {
        let e = AiError::EvaluationNotFound("eval-99".into());
        assert!(e.to_string().contains("eval-99"));
    }

    #[test]
    fn test_deployment_not_found_message() {
        let e = AiError::DeploymentNotFound("dep-42".into());
        assert!(e.to_string().contains("dep-42"));
    }

    #[test]
    fn test_invalid_configuration_message() {
        let e = AiError::InvalidConfiguration("missing threshold".into());
        assert!(e.to_string().contains("missing threshold"));
    }

    #[test]
    fn test_invalid_operation_message() {
        let e = AiError::InvalidOperation("not allowed".into());
        assert!(e.to_string().contains("not allowed"));
    }
}
