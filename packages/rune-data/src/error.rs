// ═══════════════════════════════════════════════════════════════════════
// Data governance error types — error variants for rule, dataset,
// schema, classification, lineage, and catalog lookup failures,
// policy violations, access denials, schema incompatibility, and
// invalid configuration/operation.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── DataError ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum DataError {
    RuleNotFound(String),
    DatasetNotFound(String),
    SchemaNotFound(String),
    ClassificationNotFound(String),
    LineageNotFound(String),
    CatalogEntryNotFound(String),
    PolicyViolation { policy_id: String, reason: String },
    AccessDenied { requester_id: String, dataset_ref: String, reason: String },
    SchemaIncompatible { schema_id: String, reason: String },
    InvalidConfiguration(String),
    InvalidOperation(String),
}

impl fmt::Display for DataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuleNotFound(id) => write!(f, "Rule not found: {id}"),
            Self::DatasetNotFound(id) => write!(f, "Dataset not found: {id}"),
            Self::SchemaNotFound(id) => write!(f, "Schema not found: {id}"),
            Self::ClassificationNotFound(id) => write!(f, "Classification not found: {id}"),
            Self::LineageNotFound(id) => write!(f, "Lineage not found: {id}"),
            Self::CatalogEntryNotFound(id) => write!(f, "Catalog entry not found: {id}"),
            Self::PolicyViolation { policy_id, reason } => {
                write!(f, "Policy violation ({policy_id}): {reason}")
            }
            Self::AccessDenied { requester_id, dataset_ref, reason } => {
                write!(f, "Access denied for {requester_id} on {dataset_ref}: {reason}")
            }
            Self::SchemaIncompatible { schema_id, reason } => {
                write!(f, "Schema incompatible ({schema_id}): {reason}")
            }
            Self::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {msg}"),
            Self::InvalidOperation(msg) => write!(f, "Invalid operation: {msg}"),
        }
    }
}

impl std::error::Error for DataError {}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors: Vec<DataError> = vec![
            DataError::RuleNotFound("qr-1".into()),
            DataError::DatasetNotFound("ds-1".into()),
            DataError::SchemaNotFound("sch-1".into()),
            DataError::ClassificationNotFound("cls-1".into()),
            DataError::LineageNotFound("lr-1".into()),
            DataError::CatalogEntryNotFound("ce-1".into()),
            DataError::PolicyViolation {
                policy_id: "qp-1".into(),
                reason: "pass rate below threshold".into(),
            },
            DataError::AccessDenied {
                requester_id: "user-bob".into(),
                dataset_ref: "ds-restricted".into(),
                reason: "insufficient clearance".into(),
            },
            DataError::SchemaIncompatible {
                schema_id: "sch-2".into(),
                reason: "breaking field removal".into(),
            },
            DataError::InvalidConfiguration("missing required field".into()),
            DataError::InvalidOperation("cannot delete active dataset".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(errors.len(), 11);
    }

    #[test]
    fn test_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(DataError::RuleNotFound("qr-1".into()));
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_error_debug() {
        let err = DataError::PolicyViolation {
            policy_id: "qp-1".into(),
            reason: "fail".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("PolicyViolation"));
    }

    #[test]
    fn test_access_denied_fields() {
        let err = DataError::AccessDenied {
            requester_id: "alice".into(),
            dataset_ref: "ds-secret".into(),
            reason: "not authorized".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("alice"));
        assert!(msg.contains("ds-secret"));
        assert!(msg.contains("not authorized"));
    }

    #[test]
    fn test_schema_incompatible_fields() {
        let err = DataError::SchemaIncompatible {
            schema_id: "sch-5".into(),
            reason: "type mismatch on field 'age'".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("sch-5"));
        assert!(msg.contains("age"));
    }

    #[test]
    fn test_not_found_variants() {
        let variants = vec![
            DataError::RuleNotFound("r".into()),
            DataError::DatasetNotFound("d".into()),
            DataError::SchemaNotFound("s".into()),
            DataError::ClassificationNotFound("c".into()),
            DataError::LineageNotFound("l".into()),
            DataError::CatalogEntryNotFound("e".into()),
        ];
        for v in &variants {
            assert!(v.to_string().contains("not found"));
        }
    }

    #[test]
    fn test_invalid_operation() {
        let err = DataError::InvalidOperation("cannot proceed".into());
        assert!(err.to_string().contains("cannot proceed"));
    }
}
