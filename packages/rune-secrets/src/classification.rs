// ═══════════════════════════════════════════════════════════════════════
// Classification-Based Handling Rules
//
// Maps ClassificationLevel to data-handling requirements:
// encryption, audit, retention, access constraints.
// Bell-LaPadula: subjects cannot read above their clearance.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;
use rune_permissions::ClassificationLevel;

// ── Handling rules ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlingRules {
    pub classification: ClassificationLevel,
    pub encrypt_at_rest: bool,
    pub encrypt_in_transit: bool,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_retention_days: Option<u32>,
    pub logging_level: LoggingLevel,
    pub allow_export: bool,
    pub require_audit_trail: bool,
    pub min_key_length_bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoggingLevel {
    None,
    Summary,
    Detailed,
    Full,
}

impl fmt::Display for LoggingLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Return handling rules for a classification level.
pub fn rules_for_classification(level: ClassificationLevel) -> HandlingRules {
    match level {
        ClassificationLevel::Public => HandlingRules {
            classification: level,
            encrypt_at_rest: false,
            encrypt_in_transit: false,
            require_mfa: false,
            require_approval: false,
            max_retention_days: None,
            logging_level: LoggingLevel::None,
            allow_export: true,
            require_audit_trail: false,
            min_key_length_bits: 0,
        },
        ClassificationLevel::Internal => HandlingRules {
            classification: level,
            encrypt_at_rest: false,
            encrypt_in_transit: true,
            require_mfa: false,
            require_approval: false,
            max_retention_days: Some(365),
            logging_level: LoggingLevel::Summary,
            allow_export: true,
            require_audit_trail: false,
            min_key_length_bits: 128,
        },
        ClassificationLevel::Confidential => HandlingRules {
            classification: level,
            encrypt_at_rest: true,
            encrypt_in_transit: true,
            require_mfa: false,
            require_approval: false,
            max_retention_days: Some(180),
            logging_level: LoggingLevel::Detailed,
            allow_export: false,
            require_audit_trail: true,
            min_key_length_bits: 256,
        },
        ClassificationLevel::Restricted => HandlingRules {
            classification: level,
            encrypt_at_rest: true,
            encrypt_in_transit: true,
            require_mfa: true,
            require_approval: false,
            max_retention_days: Some(90),
            logging_level: LoggingLevel::Full,
            allow_export: false,
            require_audit_trail: true,
            min_key_length_bits: 256,
        },
        ClassificationLevel::TopSecret => HandlingRules {
            classification: level,
            encrypt_at_rest: true,
            encrypt_in_transit: true,
            require_mfa: true,
            require_approval: true,
            max_retention_days: Some(30),
            logging_level: LoggingLevel::Full,
            allow_export: false,
            require_audit_trail: true,
            min_key_length_bits: 256,
        },
    }
}

// ── Handling validation ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlingViolation {
    pub rule: String,
    pub severity: ViolationSeverity,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ViolationSeverity {
    Warning,
    Error,
    Critical,
}

impl fmt::Display for ViolationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Validate that a secret's handling meets its classification requirements.
pub fn validate_handling(
    classification: ClassificationLevel,
    is_encrypted_at_rest: bool,
    is_encrypted_in_transit: bool,
    has_audit_trail: bool,
    key_length_bits: u32,
) -> Vec<HandlingViolation> {
    let rules = rules_for_classification(classification);
    let mut violations = Vec::new();

    if rules.encrypt_at_rest && !is_encrypted_at_rest {
        violations.push(HandlingViolation {
            rule: "encrypt_at_rest".into(),
            severity: ViolationSeverity::Critical,
            message: format!("{:?} secrets must be encrypted at rest", rules.classification),
        });
    }

    if rules.encrypt_in_transit && !is_encrypted_in_transit {
        violations.push(HandlingViolation {
            rule: "encrypt_in_transit".into(),
            severity: ViolationSeverity::Critical,
            message: format!("{:?} secrets must be encrypted in transit", rules.classification),
        });
    }

    if rules.require_audit_trail && !has_audit_trail {
        violations.push(HandlingViolation {
            rule: "require_audit_trail".into(),
            severity: ViolationSeverity::Error,
            message: format!("{:?} secrets require an audit trail", rules.classification),
        });
    }

    if key_length_bits < rules.min_key_length_bits {
        violations.push(HandlingViolation {
            rule: "min_key_length".into(),
            severity: ViolationSeverity::Critical,
            message: format!(
                "{:?} requires minimum {}-bit keys, got {key_length_bits}",
                rules.classification, rules.min_key_length_bits
            ),
        });
    }

    violations
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_rules() {
        let r = rules_for_classification(ClassificationLevel::Public);
        assert!(!r.encrypt_at_rest);
        assert!(!r.encrypt_in_transit);
        assert!(!r.require_mfa);
        assert!(!r.require_approval);
        assert!(r.allow_export);
        assert_eq!(r.logging_level, LoggingLevel::None);
        assert_eq!(r.min_key_length_bits, 0);
    }

    #[test]
    fn test_internal_rules() {
        let r = rules_for_classification(ClassificationLevel::Internal);
        assert!(!r.encrypt_at_rest);
        assert!(r.encrypt_in_transit);
        assert_eq!(r.max_retention_days, Some(365));
        assert_eq!(r.min_key_length_bits, 128);
    }

    #[test]
    fn test_confidential_rules() {
        let r = rules_for_classification(ClassificationLevel::Confidential);
        assert!(r.encrypt_at_rest);
        assert!(r.encrypt_in_transit);
        assert!(!r.allow_export);
        assert!(r.require_audit_trail);
        assert_eq!(r.min_key_length_bits, 256);
    }

    #[test]
    fn test_restricted_rules() {
        let r = rules_for_classification(ClassificationLevel::Restricted);
        assert!(r.require_mfa);
        assert!(!r.require_approval);
        assert_eq!(r.max_retention_days, Some(90));
        assert_eq!(r.logging_level, LoggingLevel::Full);
    }

    #[test]
    fn test_top_secret_rules() {
        let r = rules_for_classification(ClassificationLevel::TopSecret);
        assert!(r.require_mfa);
        assert!(r.require_approval);
        assert_eq!(r.max_retention_days, Some(30));
        assert!(!r.allow_export);
    }

    #[test]
    fn test_validate_handling_no_violations() {
        let violations = validate_handling(
            ClassificationLevel::Confidential,
            true,  // encrypted at rest
            true,  // encrypted in transit
            true,  // has audit trail
            256,   // key length
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn test_validate_handling_missing_encryption() {
        let violations = validate_handling(
            ClassificationLevel::Confidential,
            false, // NOT encrypted at rest
            true,
            true,
            256,
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "encrypt_at_rest");
        assert_eq!(violations[0].severity, ViolationSeverity::Critical);
    }

    #[test]
    fn test_validate_handling_multiple_violations() {
        let violations = validate_handling(
            ClassificationLevel::TopSecret,
            false, // not encrypted
            false, // not encrypted in transit
            false, // no audit
            128,   // too short
        );
        assert_eq!(violations.len(), 4);
    }

    #[test]
    fn test_validate_handling_public_no_requirements() {
        let violations = validate_handling(
            ClassificationLevel::Public,
            false, false, false, 0,
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn test_validate_handling_key_length() {
        let violations = validate_handling(
            ClassificationLevel::Restricted,
            true, true, true,
            128, // too short for Restricted (needs 256)
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "min_key_length");
    }

    #[test]
    fn test_violation_severity_ordering() {
        assert!(ViolationSeverity::Warning < ViolationSeverity::Error);
        assert!(ViolationSeverity::Error < ViolationSeverity::Critical);
    }

    #[test]
    fn test_logging_level_display() {
        assert_eq!(LoggingLevel::Full.to_string(), "Full");
        assert_eq!(LoggingLevel::None.to_string(), "None");
    }
}
