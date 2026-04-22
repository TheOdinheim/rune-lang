// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Fairness metric evaluation. Evaluates FairnessPolicy
// against measured metric values and produces overall fairness
// assessment using threshold comparison logic.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::bias_fairness::{FairnessMetricDefinition, FairnessPolicy, FairnessStatus};
use crate::evaluation_engine::compare_threshold;

// ── FairnessMetricEvaluation ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessMetricEvaluation {
    pub metric_id: String,
    pub attribute_name: String,
    pub measured_value: String,
    pub threshold_value: String,
    pub passed: bool,
    pub direction: Option<String>,
}

// ── FairnessEvaluationResult ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessEvaluationResult {
    pub policy_id: String,
    pub model_id: String,
    pub metric_evaluations: Vec<FairnessMetricEvaluation>,
    pub overall_status: FairnessStatus,
    pub assessed_at: i64,
}

// ── FairnessEvaluator ───────────────────────────────────────────────

pub struct FairnessEvaluator;

impl FairnessEvaluator {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate_fairness(
        &self,
        policy: &FairnessPolicy,
        measurements: &HashMap<(String, String), String>,
        assessed_at: i64,
    ) -> FairnessEvaluationResult {
        let mut evaluations = Vec::new();
        let mut violations = Vec::new();

        for metric in &policy.fairness_metrics {
            let attributes: Vec<&str> = if metric.applies_to_attributes.is_empty() {
                policy
                    .protected_attributes
                    .iter()
                    .map(|a| a.attribute_name.as_str())
                    .collect()
            } else {
                metric
                    .applies_to_attributes
                    .iter()
                    .map(|s| s.as_str())
                    .collect()
            };

            for attr in attributes {
                let key = (metric.metric_id.clone(), attr.to_string());
                if let Some(measured) = measurements.get(&key) {
                    let eval = self.evaluate_single_metric(metric, attr, measured);
                    if !eval.passed {
                        violations.push(format!(
                            "{} for {attr}", metric.metric_id
                        ));
                    }
                    evaluations.push(eval);
                }
            }
        }

        let overall_status = if evaluations.is_empty() {
            FairnessStatus::NotAssessed
        } else if violations.is_empty() {
            FairnessStatus::Fair
        } else {
            FairnessStatus::Unfair { violations }
        };

        FairnessEvaluationResult {
            policy_id: policy.policy_id.clone(),
            model_id: policy.model_id.clone(),
            metric_evaluations: evaluations,
            overall_status,
            assessed_at,
        }
    }

    pub fn evaluate_single_metric(
        &self,
        metric: &FairnessMetricDefinition,
        attribute_name: &str,
        measured_value: &str,
    ) -> FairnessMetricEvaluation {
        let passed = compare_threshold(measured_value, &metric.threshold_value, &metric.comparison);

        let direction = if passed {
            None
        } else {
            Some("below_threshold".to_string())
        };

        FairnessMetricEvaluation {
            metric_id: metric.metric_id.clone(),
            attribute_name: attribute_name.to_string(),
            measured_value: measured_value.to_string(),
            threshold_value: metric.threshold_value.clone(),
            passed,
            direction,
        }
    }
}

impl Default for FairnessEvaluator {
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
    use crate::bias_fairness::{
        MonitoringFrequency, ProtectedAttribute, ProtectedAttributeType,
    };
    use crate::evaluation::ThresholdComparison;

    fn make_policy() -> FairnessPolicy {
        let mut policy = FairnessPolicy::new(
            "fp-1", "model-1", MonitoringFrequency::Daily, 1000,
        );
        policy.protected_attributes.push(
            ProtectedAttribute::new("gender", ProtectedAttributeType::Gender),
        );
        policy.protected_attributes.push(
            ProtectedAttribute::new("race", ProtectedAttributeType::Race),
        );
        let mut metric = FairnessMetricDefinition::new(
            "fm-1", "demographic_parity", "0.80",
            ThresholdComparison::GreaterThanOrEqual,
        );
        metric.applies_to_attributes = vec!["gender".into(), "race".into()];
        policy.fairness_metrics.push(metric);
        policy
    }

    #[test]
    fn test_all_metrics_passing_is_fair() {
        let evaluator = FairnessEvaluator::new();
        let policy = make_policy();
        let mut measurements = HashMap::new();
        measurements.insert(("fm-1".into(), "gender".into()), "0.90".into());
        measurements.insert(("fm-1".into(), "race".into()), "0.85".into());

        let result = evaluator.evaluate_fairness(&policy, &measurements, 2000);
        assert_eq!(result.overall_status, FairnessStatus::Fair);
        assert_eq!(result.metric_evaluations.len(), 2);
        assert!(result.metric_evaluations.iter().all(|e| e.passed));
    }

    #[test]
    fn test_one_metric_failing_is_unfair() {
        let evaluator = FairnessEvaluator::new();
        let policy = make_policy();
        let mut measurements = HashMap::new();
        measurements.insert(("fm-1".into(), "gender".into()), "0.90".into());
        measurements.insert(("fm-1".into(), "race".into()), "0.70".into());

        let result = evaluator.evaluate_fairness(&policy, &measurements, 2000);
        assert!(matches!(result.overall_status, FairnessStatus::Unfair { .. }));
        if let FairnessStatus::Unfair { violations } = &result.overall_status {
            assert_eq!(violations.len(), 1);
        }
    }

    #[test]
    fn test_no_measurements_is_not_assessed() {
        let evaluator = FairnessEvaluator::new();
        let policy = make_policy();
        let measurements = HashMap::new();

        let result = evaluator.evaluate_fairness(&policy, &measurements, 2000);
        assert_eq!(result.overall_status, FairnessStatus::NotAssessed);
        assert!(result.metric_evaluations.is_empty());
    }

    #[test]
    fn test_single_metric_evaluation_pass() {
        let evaluator = FairnessEvaluator::new();
        let metric = FairnessMetricDefinition::new(
            "fm-1", "demographic_parity", "0.80",
            ThresholdComparison::GreaterThanOrEqual,
        );
        let eval = evaluator.evaluate_single_metric(&metric, "gender", "0.90");
        assert!(eval.passed);
        assert!(eval.direction.is_none());
        assert_eq!(eval.metric_id, "fm-1");
    }

    #[test]
    fn test_single_metric_evaluation_fail() {
        let evaluator = FairnessEvaluator::new();
        let metric = FairnessMetricDefinition::new(
            "fm-1", "demographic_parity", "0.80",
            ThresholdComparison::GreaterThanOrEqual,
        );
        let eval = evaluator.evaluate_single_metric(&metric, "gender", "0.60");
        assert!(!eval.passed);
        assert_eq!(eval.direction, Some("below_threshold".to_string()));
    }

    #[test]
    fn test_threshold_comparison_correctness() {
        let evaluator = FairnessEvaluator::new();
        let metric = FairnessMetricDefinition::new(
            "fm-1", "equalized_odds", "0.90",
            ThresholdComparison::GreaterThanOrEqual,
        );
        // Exactly at threshold should pass
        let eval = evaluator.evaluate_single_metric(&metric, "age", "0.90");
        assert!(eval.passed);
    }

    #[test]
    fn test_all_metrics_failing() {
        let evaluator = FairnessEvaluator::new();
        let policy = make_policy();
        let mut measurements = HashMap::new();
        measurements.insert(("fm-1".into(), "gender".into()), "0.50".into());
        measurements.insert(("fm-1".into(), "race".into()), "0.40".into());

        let result = evaluator.evaluate_fairness(&policy, &measurements, 2000);
        assert!(matches!(result.overall_status, FairnessStatus::Unfair { .. }));
        if let FairnessStatus::Unfair { violations } = &result.overall_status {
            assert_eq!(violations.len(), 2);
        }
    }

    #[test]
    fn test_policy_with_no_applies_to_uses_all_attributes() {
        let evaluator = FairnessEvaluator::new();
        let mut policy = FairnessPolicy::new(
            "fp-2", "model-2", MonitoringFrequency::Daily, 1000,
        );
        policy.protected_attributes.push(
            ProtectedAttribute::new("gender", ProtectedAttributeType::Gender),
        );
        // No applies_to_attributes set — should apply to all protected attributes
        policy.fairness_metrics.push(FairnessMetricDefinition::new(
            "fm-1", "demographic_parity", "0.80",
            ThresholdComparison::GreaterThanOrEqual,
        ));

        let mut measurements = HashMap::new();
        measurements.insert(("fm-1".into(), "gender".into()), "0.85".into());

        let result = evaluator.evaluate_fairness(&policy, &measurements, 2000);
        assert_eq!(result.overall_status, FairnessStatus::Fair);
        assert_eq!(result.metric_evaluations.len(), 1);
    }

    #[test]
    fn test_evaluator_default() {
        let _evaluator = FairnessEvaluator;
    }

    #[test]
    fn test_result_fields() {
        let evaluator = FairnessEvaluator::new();
        let policy = make_policy();
        let measurements = HashMap::new();
        let result = evaluator.evaluate_fairness(&policy, &measurements, 5000);
        assert_eq!(result.policy_id, "fp-1");
        assert_eq!(result.model_id, "model-1");
        assert_eq!(result.assessed_at, 5000);
    }
}
