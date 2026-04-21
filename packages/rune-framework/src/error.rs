// ═══════════════════════════════════════════════════════════════════════
// Error — Framework-level error types
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum FrameworkError {
    PipelineNotConfigured,
    StageNotFound { stage_name: String },
    StageFailed { stage_name: String, reason: String },
    StageTimeout { stage_name: String, timeout_ms: u64 },
    ComponentNotFound { component_id: String },
    ComponentUnavailable { component_id: String },
    DuplicateComponent { component_id: String },
    InvalidConfiguration { field: String, reason: String },
    WorkflowNotFound { template_name: String },
    HealthCheckFailed { reason: String },
    AuditError { reason: String },
    SerializationFailed(String),
    FrameworkNotFound(String),
}

impl fmt::Display for FrameworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PipelineNotConfigured => write!(f, "Pipeline not configured"),
            Self::StageNotFound { stage_name } => {
                write!(f, "Stage not found: {stage_name}")
            }
            Self::StageFailed { stage_name, reason } => {
                write!(f, "Stage '{stage_name}' failed: {reason}")
            }
            Self::StageTimeout {
                stage_name,
                timeout_ms,
            } => {
                write!(f, "Stage '{stage_name}' timed out after {timeout_ms}ms")
            }
            Self::ComponentNotFound { component_id } => {
                write!(f, "Component not found: {component_id}")
            }
            Self::ComponentUnavailable { component_id } => {
                write!(f, "Component unavailable: {component_id}")
            }
            Self::DuplicateComponent { component_id } => {
                write!(f, "Duplicate component: {component_id}")
            }
            Self::InvalidConfiguration { field, reason } => {
                write!(f, "Invalid configuration '{field}': {reason}")
            }
            Self::WorkflowNotFound { template_name } => {
                write!(f, "Workflow template not found: {template_name}")
            }
            Self::HealthCheckFailed { reason } => {
                write!(f, "Health check failed: {reason}")
            }
            Self::AuditError { reason } => {
                write!(f, "Audit error: {reason}")
            }
            Self::SerializationFailed(reason) => {
                write!(f, "serialization failed: {reason}")
            }
            Self::FrameworkNotFound(id) => {
                write!(f, "framework not found: {id}")
            }
        }
    }
}

impl std::error::Error for FrameworkError {}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_all_variants() {
        let variants: Vec<FrameworkError> = vec![
            FrameworkError::PipelineNotConfigured,
            FrameworkError::StageNotFound { stage_name: "s".into() },
            FrameworkError::StageFailed { stage_name: "s".into(), reason: "r".into() },
            FrameworkError::StageTimeout { stage_name: "s".into(), timeout_ms: 100 },
            FrameworkError::ComponentNotFound { component_id: "c".into() },
            FrameworkError::ComponentUnavailable { component_id: "c".into() },
            FrameworkError::DuplicateComponent { component_id: "c".into() },
            FrameworkError::InvalidConfiguration { field: "f".into(), reason: "r".into() },
            FrameworkError::WorkflowNotFound { template_name: "t".into() },
            FrameworkError::HealthCheckFailed { reason: "r".into() },
            FrameworkError::AuditError { reason: "r".into() },
            FrameworkError::SerializationFailed("s".into()),
            FrameworkError::FrameworkNotFound("f".into()),
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
        assert_eq!(variants.len(), 13);
    }
}
