// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Threshold-based evaluation engine. Evaluates
// EvaluationCriteria against measured values, supports all
// ThresholdComparison variants, and evaluates full EvaluationGates
// with weighted scoring.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::evaluation::{EvaluationCriteria, EvaluationGate, ThresholdComparison};

// ── compare_threshold ───────────────────────────────────────────────

pub fn compare_threshold(
    measured: &str,
    threshold: &str,
    comparison: &ThresholdComparison,
) -> bool {
    match comparison {
        ThresholdComparison::GreaterThan => {
            match (measured.parse::<f64>(), threshold.parse::<f64>()) {
                (Ok(m), Ok(t)) => m > t,
                _ => measured > threshold,
            }
        }
        ThresholdComparison::GreaterThanOrEqual => {
            match (measured.parse::<f64>(), threshold.parse::<f64>()) {
                (Ok(m), Ok(t)) => m >= t,
                _ => measured >= threshold,
            }
        }
        ThresholdComparison::LessThan => {
            match (measured.parse::<f64>(), threshold.parse::<f64>()) {
                (Ok(m), Ok(t)) => m < t,
                _ => measured < threshold,
            }
        }
        ThresholdComparison::LessThanOrEqual => {
            match (measured.parse::<f64>(), threshold.parse::<f64>()) {
                (Ok(m), Ok(t)) => m <= t,
                _ => measured <= threshold,
            }
        }
        ThresholdComparison::Equal => {
            match (measured.parse::<f64>(), threshold.parse::<f64>()) {
                (Ok(m), Ok(t)) => (m - t).abs() < f64::EPSILON,
                _ => measured == threshold,
            }
        }
        ThresholdComparison::WithinRange { min, max } => {
            match (measured.parse::<f64>(), min.parse::<f64>(), max.parse::<f64>()) {
                (Ok(m), Ok(lo), Ok(hi)) => m >= lo && m <= hi,
                _ => measured >= min.as_str() && measured <= max.as_str(),
            }
        }
    }
}

// ── GateRecommendation ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateRecommendation {
    Pass,
    Fail { failed_criteria: Vec<String> },
    ConditionalPass { conditions: Vec<String> },
}

impl fmt::Display for GateRecommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => f.write_str("Pass"),
            Self::Fail { failed_criteria } => {
                write!(f, "Fail({})", failed_criteria.join(", "))
            }
            Self::ConditionalPass { conditions } => {
                write!(f, "ConditionalPass({})", conditions.join(", "))
            }
        }
    }
}

// ── CriterionEvaluation ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriterionEvaluation {
    pub criteria_id: String,
    pub criteria_name: String,
    pub metric_name: String,
    pub measured_value: String,
    pub threshold_value: String,
    pub comparison_type: String,
    pub passed: bool,
    pub evaluated_at: i64,
}

// ── GateEvaluation ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateEvaluation {
    pub gate_id: String,
    pub model_id: String,
    pub criteria_results: Vec<CriterionEvaluation>,
    pub all_required_passed: bool,
    pub overall_score: Option<String>,
    pub gate_recommendation: GateRecommendation,
    pub evaluated_at: i64,
}

// ── EvaluationEngine ───────────────────────────────────────────────

pub struct EvaluationEngine;

impl EvaluationEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate_criterion(
        &self,
        criteria: &EvaluationCriteria,
        measured_value: &str,
        evaluated_at: i64,
    ) -> CriterionEvaluation {
        let passed = compare_threshold(measured_value, &criteria.threshold_value, &criteria.comparison);
        CriterionEvaluation {
            criteria_id: criteria.criteria_id.clone(),
            criteria_name: criteria.criteria_name.clone(),
            metric_name: criteria.metric_name.clone(),
            measured_value: measured_value.to_string(),
            threshold_value: criteria.threshold_value.clone(),
            comparison_type: criteria.comparison.to_string(),
            passed,
            evaluated_at,
        }
    }

    pub fn evaluate_gate(
        &self,
        gate: &EvaluationGate,
        criteria_map: &HashMap<String, EvaluationCriteria>,
        measurements: &HashMap<String, String>,
        evaluated_at: i64,
    ) -> GateEvaluation {
        let mut results = Vec::new();
        let mut failed_required = Vec::new();
        let mut failed_optional = Vec::new();
        let mut weighted_sum = 0.0_f64;
        let mut weight_total = 0.0_f64;
        let mut has_weights = false;

        for criteria_id in &gate.required_criteria {
            if let Some(criteria) = criteria_map.get(criteria_id) {
                let measured = measurements
                    .get(criteria_id)
                    .map(|s| s.as_str())
                    .unwrap_or("0");
                let eval = self.evaluate_criterion(criteria, measured, evaluated_at);

                if let Some(ref w) = criteria.weight
                    && let (Ok(weight), Ok(measured_f)) = (w.parse::<f64>(), measured.parse::<f64>())
                {
                    has_weights = true;
                    weighted_sum += weight * measured_f;
                    weight_total += weight;
                }

                if !eval.passed {
                    if criteria.required {
                        failed_required.push(criteria_id.clone());
                    } else {
                        failed_optional.push(criteria_id.clone());
                    }
                }
                results.push(eval);
            }
        }

        let all_required_passed = failed_required.is_empty();

        let overall_score = if has_weights && weight_total > 0.0 {
            let score = weighted_sum / weight_total;
            Some(format!("{score:.4}"))
        } else {
            None
        };

        let gate_recommendation = if !all_required_passed {
            GateRecommendation::Fail { failed_criteria: failed_required }
        } else if !failed_optional.is_empty() {
            GateRecommendation::ConditionalPass { conditions: failed_optional }
        } else {
            GateRecommendation::Pass
        };

        GateEvaluation {
            gate_id: gate.gate_id.clone(),
            model_id: gate.model_id.clone(),
            criteria_results: results,
            all_required_passed,
            overall_score,
            gate_recommendation,
            evaluated_at,
        }
    }
}

impl Default for EvaluationEngine {
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

    #[test]
    fn test_compare_greater_than_pass() {
        assert!(compare_threshold("0.96", "0.95", &ThresholdComparison::GreaterThan));
    }

    #[test]
    fn test_compare_greater_than_fail() {
        assert!(!compare_threshold("0.94", "0.95", &ThresholdComparison::GreaterThan));
    }

    #[test]
    fn test_compare_greater_than_equal_boundary() {
        assert!(!compare_threshold("0.95", "0.95", &ThresholdComparison::GreaterThan));
    }

    #[test]
    fn test_compare_greater_than_or_equal_pass() {
        assert!(compare_threshold("0.95", "0.95", &ThresholdComparison::GreaterThanOrEqual));
    }

    #[test]
    fn test_compare_less_than_pass() {
        assert!(compare_threshold("0.04", "0.05", &ThresholdComparison::LessThan));
    }

    #[test]
    fn test_compare_less_than_fail() {
        assert!(!compare_threshold("0.06", "0.05", &ThresholdComparison::LessThan));
    }

    #[test]
    fn test_compare_less_than_or_equal_boundary() {
        assert!(compare_threshold("0.05", "0.05", &ThresholdComparison::LessThanOrEqual));
    }

    #[test]
    fn test_compare_equal_pass() {
        assert!(compare_threshold("1.0", "1.0", &ThresholdComparison::Equal));
    }

    #[test]
    fn test_compare_equal_fail() {
        assert!(!compare_threshold("1.1", "1.0", &ThresholdComparison::Equal));
    }

    #[test]
    fn test_compare_within_range_pass() {
        assert!(compare_threshold(
            "0.5", "0.5",
            &ThresholdComparison::WithinRange { min: "0.0".into(), max: "1.0".into() },
        ));
    }

    #[test]
    fn test_compare_within_range_fail_low() {
        assert!(!compare_threshold(
            "-0.1", "-0.1",
            &ThresholdComparison::WithinRange { min: "0.0".into(), max: "1.0".into() },
        ));
    }

    #[test]
    fn test_compare_within_range_fail_high() {
        assert!(!compare_threshold(
            "1.5", "1.5",
            &ThresholdComparison::WithinRange { min: "0.0".into(), max: "1.0".into() },
        ));
    }

    #[test]
    fn test_compare_string_fallback() {
        assert!(compare_threshold("beta", "alpha", &ThresholdComparison::GreaterThan));
        assert!(!compare_threshold("alpha", "beta", &ThresholdComparison::GreaterThan));
    }

    #[test]
    fn test_evaluate_criterion_pass() {
        let engine = EvaluationEngine::new();
        let criteria = EvaluationCriteria::new(
            "ec-1", "Accuracy", "accuracy", "0.95",
            ThresholdComparison::GreaterThanOrEqual, true, 1000,
        );
        let eval = engine.evaluate_criterion(&criteria, "0.97", 2000);
        assert!(eval.passed);
        assert_eq!(eval.criteria_id, "ec-1");
        assert_eq!(eval.measured_value, "0.97");
    }

    #[test]
    fn test_evaluate_criterion_fail() {
        let engine = EvaluationEngine::new();
        let criteria = EvaluationCriteria::new(
            "ec-1", "Accuracy", "accuracy", "0.95",
            ThresholdComparison::GreaterThanOrEqual, true, 1000,
        );
        let eval = engine.evaluate_criterion(&criteria, "0.90", 2000);
        assert!(!eval.passed);
    }

    #[test]
    fn test_gate_all_pass() {
        let engine = EvaluationEngine::new();
        let gate = EvaluationGate::new(
            "gate-1", "model-1", vec!["ec-1".into(), "ec-2".into()], 1000,
        );
        let mut criteria_map = HashMap::new();
        criteria_map.insert("ec-1".into(), EvaluationCriteria::new(
            "ec-1", "Accuracy", "accuracy", "0.90",
            ThresholdComparison::GreaterThanOrEqual, true, 1000,
        ));
        criteria_map.insert("ec-2".into(), EvaluationCriteria::new(
            "ec-2", "Latency", "p99", "100",
            ThresholdComparison::LessThan, true, 1000,
        ));
        let mut measurements = HashMap::new();
        measurements.insert("ec-1".into(), "0.95".into());
        measurements.insert("ec-2".into(), "50".into());

        let eval = engine.evaluate_gate(&gate, &criteria_map, &measurements, 2000);
        assert!(eval.all_required_passed);
        assert_eq!(eval.gate_recommendation, GateRecommendation::Pass);
        assert_eq!(eval.criteria_results.len(), 2);
    }

    #[test]
    fn test_gate_required_criterion_fails() {
        let engine = EvaluationEngine::new();
        let gate = EvaluationGate::new(
            "gate-1", "model-1", vec!["ec-1".into()], 1000,
        );
        let mut criteria_map = HashMap::new();
        criteria_map.insert("ec-1".into(), EvaluationCriteria::new(
            "ec-1", "Accuracy", "accuracy", "0.95",
            ThresholdComparison::GreaterThanOrEqual, true, 1000,
        ));
        let mut measurements = HashMap::new();
        measurements.insert("ec-1".into(), "0.80".into());

        let eval = engine.evaluate_gate(&gate, &criteria_map, &measurements, 2000);
        assert!(!eval.all_required_passed);
        assert!(matches!(eval.gate_recommendation, GateRecommendation::Fail { .. }));
    }

    #[test]
    fn test_gate_optional_criterion_fails_still_passes() {
        let engine = EvaluationEngine::new();
        let gate = EvaluationGate::new(
            "gate-1", "model-1", vec!["ec-1".into(), "ec-2".into()], 1000,
        );
        let mut criteria_map = HashMap::new();
        criteria_map.insert("ec-1".into(), EvaluationCriteria::new(
            "ec-1", "Accuracy", "accuracy", "0.90",
            ThresholdComparison::GreaterThanOrEqual, true, 1000,
        ));
        criteria_map.insert("ec-2".into(), EvaluationCriteria::new(
            "ec-2", "Coverage", "coverage", "0.90",
            ThresholdComparison::GreaterThanOrEqual, false, 1000,
        ));
        let mut measurements = HashMap::new();
        measurements.insert("ec-1".into(), "0.95".into());
        measurements.insert("ec-2".into(), "0.70".into());

        let eval = engine.evaluate_gate(&gate, &criteria_map, &measurements, 2000);
        assert!(eval.all_required_passed);
        assert!(matches!(eval.gate_recommendation, GateRecommendation::ConditionalPass { .. }));
    }

    #[test]
    fn test_gate_weighted_scoring() {
        let engine = EvaluationEngine::new();
        let gate = EvaluationGate::new(
            "gate-1", "model-1", vec!["ec-1".into(), "ec-2".into()], 1000,
        );
        let mut criteria_map = HashMap::new();
        let mut c1 = EvaluationCriteria::new(
            "ec-1", "Accuracy", "accuracy", "0.90",
            ThresholdComparison::GreaterThanOrEqual, true, 1000,
        );
        c1.weight = Some("2.0".into());
        let mut c2 = EvaluationCriteria::new(
            "ec-2", "Recall", "recall", "0.80",
            ThresholdComparison::GreaterThanOrEqual, true, 1000,
        );
        c2.weight = Some("1.0".into());
        criteria_map.insert("ec-1".into(), c1);
        criteria_map.insert("ec-2".into(), c2);

        let mut measurements = HashMap::new();
        measurements.insert("ec-1".into(), "0.95".into());
        measurements.insert("ec-2".into(), "0.85".into());

        let eval = engine.evaluate_gate(&gate, &criteria_map, &measurements, 2000);
        assert!(eval.overall_score.is_some());
        // weighted = (2.0 * 0.95 + 1.0 * 0.85) / 3.0 = 2.75 / 3.0 ≈ 0.9167
        let score: f64 = eval.overall_score.unwrap().parse().unwrap();
        assert!((score - 0.9167).abs() < 0.001);
    }

    #[test]
    fn test_gate_recommendation_display() {
        assert_eq!(GateRecommendation::Pass.to_string(), "Pass");
        let fail = GateRecommendation::Fail { failed_criteria: vec!["ec-1".into()] };
        assert!(fail.to_string().contains("ec-1"));
    }

    #[test]
    fn test_evaluation_engine_default() {
        let _engine = EvaluationEngine;
    }
}
