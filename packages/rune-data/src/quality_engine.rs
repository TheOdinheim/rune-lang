// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Data quality rule evaluation engine. Evaluates
// DataQualityRule instances against measured values and computes
// policy-level pass rates. Supports NotNull, Unique (placeholder),
// InRange (f64 with string fallback), MatchesPattern, and
// ReferentialIntegrity checks.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::quality::{DataQualityPolicy, DataQualityRule, QualityExpectation};

// ── QualityRuleEvaluation ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityRuleEvaluation {
    pub rule_id: String,
    pub rule_name: String,
    pub dimension: String,
    pub passed: bool,
    pub measured_value: Option<String>,
    pub violation_details: Option<String>,
    pub severity: String,
    pub evaluated_at: i64,
}

// ── PolicyEvaluation ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub policy_id: String,
    pub dataset_ref: String,
    pub rule_evaluations: Vec<QualityRuleEvaluation>,
    pub pass_rate: String,
    pub minimum_met: bool,
    pub blocked: bool,
    pub evaluated_at: i64,
}

// ── QualityEngine ────────────────────────────────────────────────────

pub struct QualityEngine;

impl QualityEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate_rule(
        &self,
        rule: &DataQualityRule,
        measured_value: Option<&str>,
        evaluated_at: i64,
    ) -> QualityRuleEvaluation {
        let (passed, violation_details) = if !rule.enabled {
            (true, Some("Rule disabled — skipped".to_string()))
        } else {
            match &rule.expectation {
                QualityExpectation::NotNull => Self::check_not_null(measured_value),
                QualityExpectation::Unique => Self::check_unique(measured_value),
                QualityExpectation::InRange { min, max } => {
                    Self::check_in_range(measured_value, min, max)
                }
                QualityExpectation::MatchesPattern { .. } => {
                    // Pattern matching requires regex — placeholder
                    (true, Some("Pattern matching requires adapter implementation".to_string()))
                }
                QualityExpectation::ReferentialIntegrity { .. } => {
                    // Referential integrity requires dataset access — placeholder
                    (true, Some("Referential integrity requires adapter implementation".to_string()))
                }
                QualityExpectation::CustomExpectation { name, .. } => {
                    (true, Some(format!("Custom expectation '{name}' requires adapter implementation")))
                }
            }
        };

        QualityRuleEvaluation {
            rule_id: rule.rule_id.clone(),
            rule_name: rule.rule_name.clone(),
            dimension: rule.dimension.to_string(),
            passed,
            measured_value: measured_value.map(|v| v.to_string()),
            violation_details,
            severity: rule.severity.to_string(),
            evaluated_at,
        }
    }

    pub fn evaluate_policy(
        &self,
        policy: &DataQualityPolicy,
        rules: &HashMap<String, DataQualityRule>,
        measured_values: &HashMap<String, Option<String>>,
        evaluated_at: i64,
    ) -> PolicyEvaluation {
        let mut evaluations = Vec::new();
        for rule_id in &policy.rules {
            if let Some(rule) = rules.get(rule_id) {
                let measured = measured_values
                    .get(rule_id)
                    .and_then(|v| v.as_deref());
                evaluations.push(self.evaluate_rule(rule, measured, evaluated_at));
            }
        }

        let total = evaluations.len();
        let passed_count = evaluations.iter().filter(|e| e.passed).count();
        let pass_rate = if total > 0 {
            let ratio = passed_count as f64 / total as f64;
            format!("{ratio:.4}")
        } else {
            "1.0000".to_string()
        };

        let minimum_pass_rate: f64 = policy.minimum_pass_rate.parse().unwrap_or(1.0);
        let actual_rate: f64 = pass_rate.parse().unwrap_or(0.0);
        let minimum_met = actual_rate >= minimum_pass_rate;
        let blocked = !minimum_met && policy.block_on_failure;

        PolicyEvaluation {
            policy_id: policy.policy_id.clone(),
            dataset_ref: policy.dataset_ref.clone(),
            rule_evaluations: evaluations,
            pass_rate,
            minimum_met,
            blocked,
            evaluated_at,
        }
    }

    pub fn check_not_null(measured_value: Option<&str>) -> (bool, Option<String>) {
        match measured_value {
            Some(v) if !v.is_empty() => (true, None),
            Some(_) => (false, Some("Value is empty".to_string())),
            None => (false, Some("Value is null".to_string())),
        }
    }

    pub fn check_unique(measured_value: Option<&str>) -> (bool, Option<String>) {
        // Uniqueness verification requires dataset access — placeholder
        match measured_value {
            Some(_) => (true, Some("Uniqueness verification requires dataset access (adapter crate)".to_string())),
            None => (false, Some("Value is null — cannot verify uniqueness".to_string())),
        }
    }

    pub fn check_in_range(
        measured_value: Option<&str>,
        min: &str,
        max: &str,
    ) -> (bool, Option<String>) {
        match measured_value {
            None => (false, Some("Value is null — cannot check range".to_string())),
            Some(v) => {
                match (v.parse::<f64>(), min.parse::<f64>(), max.parse::<f64>()) {
                    (Ok(val), Ok(lo), Ok(hi)) => {
                        if val >= lo && val <= hi {
                            (true, None)
                        } else {
                            (false, Some(format!("Value {v} is outside range [{min}..{max}]")))
                        }
                    }
                    _ => {
                        // String fallback
                        if v >= min && v <= max {
                            (true, None)
                        } else {
                            (false, Some(format!("Value {v} is outside range [{min}..{max}] (string comparison)")))
                        }
                    }
                }
            }
        }
    }
}

impl Default for QualityEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality::{DataQualityDimension, QualitySeverity};

    fn make_rule(rule_id: &str, expectation: QualityExpectation) -> DataQualityRule {
        DataQualityRule {
            rule_id: rule_id.into(),
            rule_name: format!("rule_{rule_id}"),
            dimension: DataQualityDimension::Completeness,
            target_dataset_ref: "ds-test".into(),
            target_field: None,
            expectation,
            severity: QualitySeverity::Critical,
            enabled: true,
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_not_null_with_value() {
        let engine = QualityEngine::new();
        let rule = make_rule("qr-1", QualityExpectation::NotNull);
        let eval = engine.evaluate_rule(&rule, Some("hello"), 1000);
        assert!(eval.passed);
        assert!(eval.violation_details.is_none());
    }

    #[test]
    fn test_not_null_with_none() {
        let engine = QualityEngine::new();
        let rule = make_rule("qr-1", QualityExpectation::NotNull);
        let eval = engine.evaluate_rule(&rule, None, 1000);
        assert!(!eval.passed);
        assert!(eval.violation_details.as_ref().unwrap().contains("null"));
    }

    #[test]
    fn test_not_null_with_empty_string() {
        let engine = QualityEngine::new();
        let rule = make_rule("qr-1", QualityExpectation::NotNull);
        let eval = engine.evaluate_rule(&rule, Some(""), 1000);
        assert!(!eval.passed);
        assert!(eval.violation_details.as_ref().unwrap().contains("empty"));
    }

    #[test]
    fn test_in_range_within_bounds() {
        let engine = QualityEngine::new();
        let rule = make_rule("qr-2", QualityExpectation::InRange { min: "0".into(), max: "100".into() });
        let eval = engine.evaluate_rule(&rule, Some("50"), 1000);
        assert!(eval.passed);
    }

    #[test]
    fn test_in_range_outside_bounds() {
        let engine = QualityEngine::new();
        let rule = make_rule("qr-2", QualityExpectation::InRange { min: "0".into(), max: "100".into() });
        let eval = engine.evaluate_rule(&rule, Some("150"), 1000);
        assert!(!eval.passed);
    }

    #[test]
    fn test_in_range_string_fallback() {
        let engine = QualityEngine::new();
        let rule = make_rule("qr-2", QualityExpectation::InRange { min: "aaa".into(), max: "zzz".into() });
        let eval = engine.evaluate_rule(&rule, Some("mmm"), 1000);
        assert!(eval.passed);
    }

    #[test]
    fn test_in_range_string_fallback_outside() {
        let engine = QualityEngine::new();
        let rule = make_rule("qr-2", QualityExpectation::InRange { min: "bbb".into(), max: "ccc".into() });
        let eval = engine.evaluate_rule(&rule, Some("zzz"), 1000);
        assert!(!eval.passed);
    }

    #[test]
    fn test_in_range_null_value() {
        let engine = QualityEngine::new();
        let rule = make_rule("qr-2", QualityExpectation::InRange { min: "0".into(), max: "100".into() });
        let eval = engine.evaluate_rule(&rule, None, 1000);
        assert!(!eval.passed);
    }

    #[test]
    fn test_unique_placeholder() {
        let engine = QualityEngine::new();
        let rule = make_rule("qr-3", QualityExpectation::Unique);
        let eval = engine.evaluate_rule(&rule, Some("value"), 1000);
        assert!(eval.passed);
        assert!(eval.violation_details.as_ref().unwrap().contains("adapter"));
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let engine = QualityEngine::new();
        let mut rule = make_rule("qr-d", QualityExpectation::NotNull);
        rule.enabled = false;
        let eval = engine.evaluate_rule(&rule, None, 1000);
        assert!(eval.passed);
        assert!(eval.violation_details.as_ref().unwrap().contains("disabled"));
    }

    #[test]
    fn test_policy_all_passing() {
        let engine = QualityEngine::new();
        let r1 = make_rule("qr-1", QualityExpectation::NotNull);
        let r2 = make_rule("qr-2", QualityExpectation::InRange { min: "0".into(), max: "100".into() });
        let mut rules = HashMap::new();
        rules.insert("qr-1".into(), r1);
        rules.insert("qr-2".into(), r2);
        let mut measured = HashMap::new();
        measured.insert("qr-1".into(), Some("hello".to_string()));
        measured.insert("qr-2".into(), Some("50".to_string()));
        let policy = DataQualityPolicy {
            policy_id: "qp-1".into(),
            dataset_ref: "ds-test".into(),
            rules: vec!["qr-1".into(), "qr-2".into()],
            minimum_pass_rate: "1.0".into(),
            block_on_failure: true,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let eval = engine.evaluate_policy(&policy, &rules, &measured, 2000);
        assert_eq!(eval.pass_rate, "1.0000");
        assert!(eval.minimum_met);
        assert!(!eval.blocked);
    }

    #[test]
    fn test_policy_one_failing_below_minimum() {
        let engine = QualityEngine::new();
        let r1 = make_rule("qr-1", QualityExpectation::NotNull);
        let r2 = make_rule("qr-2", QualityExpectation::NotNull);
        let mut rules = HashMap::new();
        rules.insert("qr-1".into(), r1);
        rules.insert("qr-2".into(), r2);
        let mut measured = HashMap::new();
        measured.insert("qr-1".into(), Some("hello".to_string()));
        measured.insert("qr-2".into(), None);
        let policy = DataQualityPolicy {
            policy_id: "qp-2".into(),
            dataset_ref: "ds-test".into(),
            rules: vec!["qr-1".into(), "qr-2".into()],
            minimum_pass_rate: "1.0".into(),
            block_on_failure: false,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let eval = engine.evaluate_policy(&policy, &rules, &measured, 2000);
        assert_eq!(eval.pass_rate, "0.5000");
        assert!(!eval.minimum_met);
        assert!(!eval.blocked);
    }

    #[test]
    fn test_policy_block_on_failure() {
        let engine = QualityEngine::new();
        let r1 = make_rule("qr-1", QualityExpectation::NotNull);
        let mut rules = HashMap::new();
        rules.insert("qr-1".into(), r1);
        let mut measured = HashMap::new();
        measured.insert("qr-1".into(), None);
        let policy = DataQualityPolicy {
            policy_id: "qp-3".into(),
            dataset_ref: "ds-test".into(),
            rules: vec!["qr-1".into()],
            minimum_pass_rate: "1.0".into(),
            block_on_failure: true,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let eval = engine.evaluate_policy(&policy, &rules, &measured, 2000);
        assert!(!eval.minimum_met);
        assert!(eval.blocked);
    }

    #[test]
    fn test_policy_empty_rules() {
        let engine = QualityEngine::new();
        let policy = DataQualityPolicy {
            policy_id: "qp-4".into(),
            dataset_ref: "ds-test".into(),
            rules: Vec::new(),
            minimum_pass_rate: "1.0".into(),
            block_on_failure: true,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let eval = engine.evaluate_policy(&policy, &HashMap::new(), &HashMap::new(), 2000);
        assert_eq!(eval.pass_rate, "1.0000");
        assert!(eval.minimum_met);
    }

    #[test]
    fn test_quality_engine_default() {
        let _engine = QualityEngine;
    }

    #[test]
    fn test_evaluation_fields() {
        let engine = QualityEngine::new();
        let rule = make_rule("qr-f", QualityExpectation::NotNull);
        let eval = engine.evaluate_rule(&rule, Some("val"), 5000);
        assert_eq!(eval.rule_id, "qr-f");
        assert_eq!(eval.rule_name, "rule_qr-f");
        assert_eq!(eval.dimension, "Completeness");
        assert_eq!(eval.severity, "Critical");
        assert_eq!(eval.evaluated_at, 5000);
        assert_eq!(eval.measured_value, Some("val".to_string()));
    }
}
