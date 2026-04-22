// ═══════════════════════════════════════════════════════════════════════
// Data quality rule types — dimensions following DAMA-DMBOK framework
// (Completeness, Accuracy, Consistency, Timeliness, Uniqueness,
// Validity), quality expectations, severity levels, results, and
// quality policies for pipeline governance.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── DataQualityDimension ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataQualityDimension {
    Completeness,
    Accuracy,
    Consistency,
    Timeliness,
    Uniqueness,
    Validity,
    Custom { name: String },
}

impl fmt::Display for DataQualityDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completeness => f.write_str("Completeness"),
            Self::Accuracy => f.write_str("Accuracy"),
            Self::Consistency => f.write_str("Consistency"),
            Self::Timeliness => f.write_str("Timeliness"),
            Self::Uniqueness => f.write_str("Uniqueness"),
            Self::Validity => f.write_str("Validity"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── QualityExpectation ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityExpectation {
    NotNull,
    Unique,
    InRange { min: String, max: String },
    MatchesPattern { pattern: String },
    ReferentialIntegrity { reference_dataset: String, reference_field: String },
    CustomExpectation { name: String, parameters: HashMap<String, String> },
}

impl fmt::Display for QualityExpectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNull => f.write_str("NotNull"),
            Self::Unique => f.write_str("Unique"),
            Self::InRange { min, max } => write!(f, "InRange({min}..{max})"),
            Self::MatchesPattern { pattern } => write!(f, "MatchesPattern({pattern})"),
            Self::ReferentialIntegrity { reference_dataset, reference_field } => {
                write!(f, "ReferentialIntegrity({reference_dataset}.{reference_field})")
            }
            Self::CustomExpectation { name, .. } => write!(f, "CustomExpectation({name})"),
        }
    }
}

// ── QualitySeverity ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualitySeverity {
    Critical,
    Warning,
    Advisory,
}

impl fmt::Display for QualitySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => f.write_str("Critical"),
            Self::Warning => f.write_str("Warning"),
            Self::Advisory => f.write_str("Advisory"),
        }
    }
}

// ── DataQualityRule ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataQualityRule {
    pub rule_id: String,
    pub rule_name: String,
    pub dimension: DataQualityDimension,
    pub target_dataset_ref: String,
    pub target_field: Option<String>,
    pub expectation: QualityExpectation,
    pub severity: QualitySeverity,
    pub enabled: bool,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── DataQualityResult ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataQualityResult {
    pub result_id: String,
    pub rule_id: String,
    pub dataset_ref: String,
    pub passed: bool,
    pub measured_value: Option<String>,
    pub violation_count: String,
    pub violation_sample: Vec<String>,
    pub evaluated_at: i64,
    pub evaluated_by: String,
    pub metadata: HashMap<String, String>,
}

// ── DataQualityPolicy ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataQualityPolicy {
    pub policy_id: String,
    pub dataset_ref: String,
    pub rules: Vec<String>,
    pub minimum_pass_rate: String,
    pub block_on_failure: bool,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quality_dimension_display() {
        let dims = vec![
            DataQualityDimension::Completeness,
            DataQualityDimension::Accuracy,
            DataQualityDimension::Consistency,
            DataQualityDimension::Timeliness,
            DataQualityDimension::Uniqueness,
            DataQualityDimension::Validity,
            DataQualityDimension::Custom { name: "Freshness".into() },
        ];
        for d in &dims {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(dims.len(), 7);
    }

    #[test]
    fn test_quality_expectation_display() {
        let exps = vec![
            QualityExpectation::NotNull,
            QualityExpectation::Unique,
            QualityExpectation::InRange { min: "0".into(), max: "100".into() },
            QualityExpectation::MatchesPattern { pattern: "^[A-Z]".into() },
            QualityExpectation::ReferentialIntegrity {
                reference_dataset: "orders".into(),
                reference_field: "customer_id".into(),
            },
            QualityExpectation::CustomExpectation {
                name: "json_valid".into(),
                parameters: HashMap::new(),
            },
        ];
        for e in &exps {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(exps.len(), 6);
    }

    #[test]
    fn test_quality_severity_display() {
        assert_eq!(QualitySeverity::Critical.to_string(), "Critical");
        assert_eq!(QualitySeverity::Warning.to_string(), "Warning");
        assert_eq!(QualitySeverity::Advisory.to_string(), "Advisory");
    }

    #[test]
    fn test_quality_rule_construction() {
        let rule = DataQualityRule {
            rule_id: "qr-1".into(),
            rule_name: "email_not_null".into(),
            dimension: DataQualityDimension::Completeness,
            target_dataset_ref: "ds-users".into(),
            target_field: Some("email".into()),
            expectation: QualityExpectation::NotNull,
            severity: QualitySeverity::Critical,
            enabled: true,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        assert_eq!(rule.rule_id, "qr-1");
        assert_eq!(rule.dimension, DataQualityDimension::Completeness);
        assert!(rule.enabled);
        assert_eq!(rule.target_field, Some("email".into()));
    }

    #[test]
    fn test_quality_rule_dataset_level() {
        let rule = DataQualityRule {
            rule_id: "qr-2".into(),
            rule_name: "row_count_check".into(),
            dimension: DataQualityDimension::Validity,
            target_dataset_ref: "ds-orders".into(),
            target_field: None,
            expectation: QualityExpectation::InRange { min: "1".into(), max: "1000000".into() },
            severity: QualitySeverity::Warning,
            enabled: true,
            created_at: 2000,
            metadata: HashMap::new(),
        };
        assert!(rule.target_field.is_none());
    }

    #[test]
    fn test_quality_result_passed() {
        let result = DataQualityResult {
            result_id: "qres-1".into(),
            rule_id: "qr-1".into(),
            dataset_ref: "ds-users".into(),
            passed: true,
            measured_value: Some("100.0".into()),
            violation_count: "0".into(),
            violation_sample: Vec::new(),
            evaluated_at: 3000,
            evaluated_by: "pipeline-agent".into(),
            metadata: HashMap::new(),
        };
        assert!(result.passed);
        assert_eq!(result.violation_count, "0");
    }

    #[test]
    fn test_quality_result_failed_with_violations() {
        let result = DataQualityResult {
            result_id: "qres-2".into(),
            rule_id: "qr-1".into(),
            dataset_ref: "ds-users".into(),
            passed: false,
            measured_value: Some("95.5".into()),
            violation_count: "42".into(),
            violation_sample: vec!["row-101".into(), "row-205".into()],
            evaluated_at: 3000,
            evaluated_by: "pipeline-agent".into(),
            metadata: HashMap::new(),
        };
        assert!(!result.passed);
        assert_eq!(result.violation_sample.len(), 2);
    }

    #[test]
    fn test_quality_policy_construction() {
        let policy = DataQualityPolicy {
            policy_id: "qp-1".into(),
            dataset_ref: "ds-users".into(),
            rules: vec!["qr-1".into(), "qr-2".into()],
            minimum_pass_rate: "0.95".into(),
            block_on_failure: true,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        assert_eq!(policy.rules.len(), 2);
        assert!(policy.block_on_failure);
    }

    #[test]
    fn test_quality_expectation_referential_integrity() {
        let exp = QualityExpectation::ReferentialIntegrity {
            reference_dataset: "customers".into(),
            reference_field: "id".into(),
        };
        assert!(exp.to_string().contains("customers"));
        assert!(exp.to_string().contains("id"));
    }

    #[test]
    fn test_quality_expectation_custom_with_params() {
        let mut params = HashMap::new();
        params.insert("threshold".into(), "0.99".into());
        let exp = QualityExpectation::CustomExpectation {
            name: "statistical_test".into(),
            parameters: params.clone(),
        };
        assert!(exp.to_string().contains("statistical_test"));
        if let QualityExpectation::CustomExpectation { parameters, .. } = &exp {
            assert_eq!(parameters.get("threshold"), Some(&"0.99".to_string()));
        }
    }

    #[test]
    fn test_quality_rule_with_metadata() {
        let mut meta = HashMap::new();
        meta.insert("source".into(), "dbt".into());
        let rule = DataQualityRule {
            rule_id: "qr-3".into(),
            rule_name: "dbt_check".into(),
            dimension: DataQualityDimension::Accuracy,
            target_dataset_ref: "ds-sales".into(),
            target_field: None,
            expectation: QualityExpectation::Unique,
            severity: QualitySeverity::Advisory,
            enabled: false,
            created_at: 5000,
            metadata: meta,
        };
        assert!(!rule.enabled);
        assert_eq!(rule.metadata.get("source"), Some(&"dbt".to_string()));
    }

    #[test]
    fn test_quality_dimension_custom_display() {
        let dim = DataQualityDimension::Custom { name: "Conformance".into() };
        assert!(dim.to_string().contains("Conformance"));
    }

    #[test]
    fn test_quality_result_eq() {
        let r1 = DataQualityResult {
            result_id: "qres-eq".into(),
            rule_id: "qr-1".into(),
            dataset_ref: "ds-1".into(),
            passed: true,
            measured_value: None,
            violation_count: "0".into(),
            violation_sample: Vec::new(),
            evaluated_at: 1000,
            evaluated_by: "agent".into(),
            metadata: HashMap::new(),
        };
        let r2 = r1.clone();
        assert_eq!(r1, r2);
    }
}
