// ═══════════════════════════════════════════════════════════════════════
// ShieldError — typed errors for the rune-shield crate
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldError {
    InputTooLarge { len: usize, max: usize },
    InvalidEncoding(String),
    BlockedPattern(String),
    QuarantineNotFound(String),
    QuarantineAlreadyReviewed(String),
    PolicyViolation(String),
    InvalidConfiguration(String),
}

impl fmt::Display for ShieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { len, max } => {
                write!(f, "input too large: {len} bytes (max {max})")
            }
            Self::InvalidEncoding(s) => write!(f, "invalid encoding: {s}"),
            Self::BlockedPattern(s) => write!(f, "blocked pattern: {s}"),
            Self::QuarantineNotFound(id) => write!(f, "quarantine entry not found: {id}"),
            Self::QuarantineAlreadyReviewed(id) => {
                write!(f, "quarantine entry already reviewed: {id}")
            }
            Self::PolicyViolation(s) => write!(f, "policy violation: {s}"),
            Self::InvalidConfiguration(s) => write!(f, "invalid configuration: {s}"),
        }
    }
}

impl std::error::Error for ShieldError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_all_variants() {
        let errs = [
            ShieldError::InputTooLarge { len: 100, max: 50 },
            ShieldError::InvalidEncoding("utf8".into()),
            ShieldError::BlockedPattern("rm -rf".into()),
            ShieldError::QuarantineNotFound("q1".into()),
            ShieldError::QuarantineAlreadyReviewed("q2".into()),
            ShieldError::PolicyViolation("no admin".into()),
            ShieldError::InvalidConfiguration("bad".into()),
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
        }
    }
}
