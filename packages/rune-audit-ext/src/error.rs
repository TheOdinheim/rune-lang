// ═══════════════════════════════════════════════════════════════════════
// Error — AuditExtError with 9 typed variants.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum AuditExtError {
    DuplicateEvent { id: String },
    EventNotFound { id: String },
    ChainBroken { expected_hash: String, actual_hash: String },
    InvalidQuery { reason: String },
    ExportFailed { format: String, reason: String },
    RetentionViolation { policy: String, reason: String },
    CorrelationNotFound { correlation_id: String },
    InvalidTimeRange { start: i64, end: i64 },
    StoreFull { max_events: usize },
}

impl fmt::Display for AuditExtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateEvent { id } => write!(f, "duplicate event: {id}"),
            Self::EventNotFound { id } => write!(f, "event not found: {id}"),
            Self::ChainBroken { expected_hash, actual_hash } => {
                write!(f, "chain broken: expected {expected_hash}, got {actual_hash}")
            }
            Self::InvalidQuery { reason } => write!(f, "invalid query: {reason}"),
            Self::ExportFailed { format, reason } => {
                write!(f, "export failed ({format}): {reason}")
            }
            Self::RetentionViolation { policy, reason } => {
                write!(f, "retention violation ({policy}): {reason}")
            }
            Self::CorrelationNotFound { correlation_id } => {
                write!(f, "correlation not found: {correlation_id}")
            }
            Self::InvalidTimeRange { start, end } => {
                write!(f, "invalid time range: {start}..{end}")
            }
            Self::StoreFull { max_events } => {
                write!(f, "store full: max {max_events} events")
            }
        }
    }
}

impl std::error::Error for AuditExtError {}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_display() {
        let variants: Vec<AuditExtError> = vec![
            AuditExtError::DuplicateEvent { id: "e1".into() },
            AuditExtError::EventNotFound { id: "e2".into() },
            AuditExtError::ChainBroken {
                expected_hash: "aaa".into(),
                actual_hash: "bbb".into(),
            },
            AuditExtError::InvalidQuery { reason: "bad".into() },
            AuditExtError::ExportFailed { format: "csv".into(), reason: "io".into() },
            AuditExtError::RetentionViolation { policy: "p1".into(), reason: "critical".into() },
            AuditExtError::CorrelationNotFound { correlation_id: "c1".into() },
            AuditExtError::InvalidTimeRange { start: 100, end: 50 },
            AuditExtError::StoreFull { max_events: 1000 },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }
}
