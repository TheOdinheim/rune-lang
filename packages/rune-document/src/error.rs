// ═══════════════════════════════════════════════════════════════════════
// DocumentError — typed errors for document operations.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum DocumentError {
    DocumentNotFound(String),
    DocumentAlreadyExists(String),
    TemplateNotFound(String),
    InvalidStatus { from: String, to: String },
    MissingRequiredField { section: String, field: String },
    RenderingFailed { format: String, reason: String },
    ValidationFailed { gaps: Vec<String> },
    FrameworkNotSupported(String),
    InvalidOperation(String),
    SerializationFailed(String),
    VersionNotFound(String),
}

impl fmt::Display for DocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentNotFound(id) => write!(f, "document not found: {id}"),
            Self::DocumentAlreadyExists(id) => write!(f, "document already exists: {id}"),
            Self::TemplateNotFound(id) => write!(f, "template not found: {id}"),
            Self::InvalidStatus { from, to } => {
                write!(f, "invalid status transition: {from} -> {to}")
            }
            Self::MissingRequiredField { section, field } => {
                write!(f, "missing required field: {section}/{field}")
            }
            Self::RenderingFailed { format, reason } => {
                write!(f, "rendering failed ({format}): {reason}")
            }
            Self::ValidationFailed { gaps } => {
                write!(f, "validation failed: {} gap(s)", gaps.len())
            }
            Self::FrameworkNotSupported(fw) => write!(f, "framework not supported: {fw}"),
            Self::InvalidOperation(s) => write!(f, "invalid operation: {s}"),
            Self::SerializationFailed(s) => write!(f, "serialization failed: {s}"),
            Self::VersionNotFound(s) => write!(f, "version not found: {s}"),
        }
    }
}

impl std::error::Error for DocumentError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors = [
            DocumentError::DocumentNotFound("d1".into()),
            DocumentError::DocumentAlreadyExists("d1".into()),
            DocumentError::TemplateNotFound("t1".into()),
            DocumentError::InvalidStatus {
                from: "draft".into(),
                to: "archived".into(),
            },
            DocumentError::MissingRequiredField {
                section: "s1".into(),
                field: "f1".into(),
            },
            DocumentError::RenderingFailed {
                format: "json".into(),
                reason: "bad".into(),
            },
            DocumentError::ValidationFailed {
                gaps: vec!["gap1".into()],
            },
            DocumentError::FrameworkNotSupported("unknown".into()),
            DocumentError::InvalidOperation("op".into()),
            DocumentError::SerializationFailed("ser".into()),
            DocumentError::VersionNotFound("v1".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
        assert!(errors[4].to_string().contains("s1/f1"));
    }
}
