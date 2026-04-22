// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Drift metric evaluation. Evaluates DriftPolicy against
// measured metric values, determines drift severity, and recommends
// remediation actions.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::drift::{
    DriftMetricDefinition, DriftPolicy, DriftRemediationAction, DriftSeverity, DriftStatus,
};
use crate::evaluation_engine::compare_threshold;

// ── DriftMetricEvaluation ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftMetricEvaluation {
    pub metric_id: String,
    pub measured_value: String,
    pub baseline_value: Option<String>,
    pub threshold_value: String,
    pub drift_detected: bool,
    pub severity: DriftSeverity,
}

// ── DriftEvaluationResult ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftEvaluationResult {
    pub policy_id: String,
    pub model_id: String,
    pub model_version: String,
    pub metric_evaluations: Vec<DriftMetricEvaluation>,
    pub overall_status: DriftStatus,
    pub recommended_actions: Vec<DriftRemediationAction>,
    pub evaluated_at: i64,
}

// ── DriftEvaluator ──────────────────────────────────────────────────

pub struct DriftEvaluator;

impl DriftEvaluator {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate_drift(
        &self,
        policy: &DriftPolicy,
        measurements: &HashMap<String, String>,
        model_version: &str,
        evaluated_at: i64,
    ) -> DriftEvaluationResult {
        let mut evaluations = Vec::new();
        let mut max_severity = DriftSeverity::Low;
        let mut any_drift = false;

        for metric in &policy.drift_metrics {
            if let Some(measured) = measurements.get(&metric.metric_id) {
                let eval = self.evaluate_single_metric(metric, measured);
                if eval.drift_detected {
                    any_drift = true;
                    if eval.severity > max_severity {
                        max_severity = eval.severity.clone();
                    }
                }
                evaluations.push(eval);
            }
        }

        let overall_status = if !any_drift {
            DriftStatus::NoDrift
        } else {
            match max_severity {
                DriftSeverity::Low => DriftStatus::MinorDrift {
                    details: "Low severity drift detected".to_string(),
                },
                DriftSeverity::Medium => DriftStatus::MinorDrift {
                    details: "Medium severity drift detected".to_string(),
                },
                DriftSeverity::High => DriftStatus::SignificantDrift {
                    details: "High severity drift detected".to_string(),
                },
                DriftSeverity::Critical => DriftStatus::SevereDrift {
                    details: "Critical severity drift detected".to_string(),
                },
            }
        };

        let recommended_actions = if any_drift {
            self.recommend_remediation(&max_severity, policy)
        } else {
            Vec::new()
        };

        DriftEvaluationResult {
            policy_id: policy.policy_id.clone(),
            model_id: policy.model_id.clone(),
            model_version: model_version.to_string(),
            metric_evaluations: evaluations,
            overall_status,
            recommended_actions,
            evaluated_at,
        }
    }

    pub fn evaluate_single_metric(
        &self,
        metric: &DriftMetricDefinition,
        measured_value: &str,
    ) -> DriftMetricEvaluation {
        // Drift is detected when the measured value EXCEEDS the threshold
        // (i.e., the comparison check fails — the metric is out of bounds)
        let within_threshold =
            compare_threshold(measured_value, &metric.threshold_value, &metric.comparison);
        let drift_detected = !within_threshold;

        let severity = if drift_detected {
            self.determine_severity(measured_value, &metric.threshold_value)
        } else {
            DriftSeverity::Low
        };

        DriftMetricEvaluation {
            metric_id: metric.metric_id.clone(),
            measured_value: measured_value.to_string(),
            baseline_value: metric.baseline_value.clone(),
            threshold_value: metric.threshold_value.clone(),
            drift_detected,
            severity,
        }
    }

    pub fn determine_severity(
        &self,
        measured_value: &str,
        threshold_value: &str,
    ) -> DriftSeverity {
        match (measured_value.parse::<f64>(), threshold_value.parse::<f64>()) {
            (Ok(measured), Ok(threshold)) => {
                if threshold.abs() < f64::EPSILON {
                    return DriftSeverity::Critical;
                }
                let deviation = ((measured - threshold) / threshold).abs();
                if deviation > 1.0 {
                    DriftSeverity::Critical
                } else if deviation > 0.5 {
                    DriftSeverity::High
                } else if deviation > 0.2 {
                    DriftSeverity::Medium
                } else {
                    DriftSeverity::Low
                }
            }
            _ => DriftSeverity::Medium,
        }
    }

    pub fn recommend_remediation(
        &self,
        severity: &DriftSeverity,
        policy: &DriftPolicy,
    ) -> Vec<DriftRemediationAction> {
        let actions = &policy.alerting_config.remediation_actions;
        if actions.is_empty() {
            return match severity {
                DriftSeverity::Critical => vec![DriftRemediationAction::Suspend],
                DriftSeverity::High => vec![DriftRemediationAction::Rollback],
                DriftSeverity::Medium => vec![DriftRemediationAction::Retrain],
                DriftSeverity::Low => vec![DriftRemediationAction::Alert {
                    target: "default".to_string(),
                }],
            };
        }

        // Return actions appropriate for the severity level
        match severity {
            DriftSeverity::Critical => actions.to_vec(),
            DriftSeverity::High => {
                if actions.len() > 1 {
                    actions[..actions.len() - 1].to_vec()
                } else {
                    actions.to_vec()
                }
            }
            DriftSeverity::Medium => {
                vec![actions.first().cloned().unwrap_or(DriftRemediationAction::Retrain)]
            }
            DriftSeverity::Low => {
                vec![actions
                    .first()
                    .cloned()
                    .unwrap_or(DriftRemediationAction::Alert {
                        target: "default".to_string(),
                    })]
            }
        }
    }
}

impl Default for DriftEvaluator {
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
    use crate::drift::{DriftAlertConfig, DriftDetectionWindow};
    use crate::evaluation::ThresholdComparison;

    fn make_policy() -> DriftPolicy {
        let mut policy = DriftPolicy::new(
            "dp-1", "model-1",
            DriftDetectionWindow::Sliding { window_size_hours: "24".into() },
            1000,
        );
        policy.drift_metrics.push(DriftMetricDefinition::new(
            "dm-1", "psi", "0.2",
            ThresholdComparison::LessThan,
        ));
        policy
    }

    #[test]
    fn test_no_drift_detected() {
        let evaluator = DriftEvaluator::new();
        let policy = make_policy();
        let mut measurements = HashMap::new();
        measurements.insert("dm-1".into(), "0.10".into());

        let result = evaluator.evaluate_drift(&policy, &measurements, "1.0", 2000);
        assert!(matches!(result.overall_status, DriftStatus::NoDrift));
        assert!(result.recommended_actions.is_empty());
        assert!(!result.metric_evaluations[0].drift_detected);
    }

    #[test]
    fn test_drift_detected_above_threshold() {
        let evaluator = DriftEvaluator::new();
        let policy = make_policy();
        let mut measurements = HashMap::new();
        measurements.insert("dm-1".into(), "0.30".into());

        let result = evaluator.evaluate_drift(&policy, &measurements, "1.0", 2000);
        assert!(!matches!(result.overall_status, DriftStatus::NoDrift));
        assert!(result.metric_evaluations[0].drift_detected);
        assert!(!result.recommended_actions.is_empty());
    }

    #[test]
    fn test_severity_low() {
        let evaluator = DriftEvaluator::new();
        let severity = evaluator.determine_severity("0.22", "0.2");
        assert_eq!(severity, DriftSeverity::Low);
    }

    #[test]
    fn test_severity_medium() {
        let evaluator = DriftEvaluator::new();
        let severity = evaluator.determine_severity("0.25", "0.2");
        assert_eq!(severity, DriftSeverity::Medium);
    }

    #[test]
    fn test_severity_high() {
        let evaluator = DriftEvaluator::new();
        let severity = evaluator.determine_severity("0.35", "0.2");
        assert_eq!(severity, DriftSeverity::High);
    }

    #[test]
    fn test_severity_critical() {
        let evaluator = DriftEvaluator::new();
        let severity = evaluator.determine_severity("0.50", "0.2");
        assert_eq!(severity, DriftSeverity::Critical);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(DriftSeverity::Low < DriftSeverity::Medium);
        assert!(DriftSeverity::Medium < DriftSeverity::High);
        assert!(DriftSeverity::High < DriftSeverity::Critical);
    }

    #[test]
    fn test_remediation_default_critical() {
        let evaluator = DriftEvaluator::new();
        let mut policy = make_policy();
        policy.alerting_config = DriftAlertConfig::new();
        let actions = evaluator.recommend_remediation(&DriftSeverity::Critical, &policy);
        assert_eq!(actions, vec![DriftRemediationAction::Suspend]);
    }

    #[test]
    fn test_remediation_default_low() {
        let evaluator = DriftEvaluator::new();
        let mut policy = make_policy();
        policy.alerting_config = DriftAlertConfig::new();
        let actions = evaluator.recommend_remediation(&DriftSeverity::Low, &policy);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], DriftRemediationAction::Alert { .. }));
    }

    #[test]
    fn test_remediation_with_configured_actions() {
        let evaluator = DriftEvaluator::new();
        let mut policy = make_policy();
        policy.alerting_config.remediation_actions = vec![
            DriftRemediationAction::Retrain,
            DriftRemediationAction::Rollback,
        ];
        let actions = evaluator.recommend_remediation(&DriftSeverity::Critical, &policy);
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_evaluate_single_metric_no_drift() {
        let evaluator = DriftEvaluator::new();
        let metric = DriftMetricDefinition::new(
            "dm-1", "psi", "0.2", ThresholdComparison::LessThan,
        );
        let eval = evaluator.evaluate_single_metric(&metric, "0.10");
        assert!(!eval.drift_detected);
        assert_eq!(eval.severity, DriftSeverity::Low);
    }

    #[test]
    fn test_evaluate_single_metric_with_drift() {
        let evaluator = DriftEvaluator::new();
        let metric = DriftMetricDefinition::new(
            "dm-1", "psi", "0.2", ThresholdComparison::LessThan,
        );
        let eval = evaluator.evaluate_single_metric(&metric, "0.30");
        assert!(eval.drift_detected);
        assert!(eval.severity >= DriftSeverity::Medium);
    }

    #[test]
    fn test_multiple_metrics() {
        let evaluator = DriftEvaluator::new();
        let mut policy = make_policy();
        policy.drift_metrics.push(DriftMetricDefinition::new(
            "dm-2", "kl_divergence", "0.5",
            ThresholdComparison::LessThan,
        ));
        let mut measurements = HashMap::new();
        measurements.insert("dm-1".into(), "0.10".into());
        measurements.insert("dm-2".into(), "0.80".into());

        let result = evaluator.evaluate_drift(&policy, &measurements, "1.0", 2000);
        assert_eq!(result.metric_evaluations.len(), 2);
        assert!(!result.metric_evaluations[0].drift_detected);
        assert!(result.metric_evaluations[1].drift_detected);
    }

    #[test]
    fn test_severity_string_fallback() {
        let evaluator = DriftEvaluator::new();
        let severity = evaluator.determine_severity("abc", "def");
        assert_eq!(severity, DriftSeverity::Medium);
    }

    #[test]
    fn test_evaluator_default() {
        let _evaluator = DriftEvaluator;
    }

    #[test]
    fn test_result_fields() {
        let evaluator = DriftEvaluator::new();
        let policy = make_policy();
        let measurements = HashMap::new();
        let result = evaluator.evaluate_drift(&policy, &measurements, "2.0", 5000);
        assert_eq!(result.policy_id, "dp-1");
        assert_eq!(result.model_id, "model-1");
        assert_eq!(result.model_version, "2.0");
        assert_eq!(result.evaluated_at, 5000);
    }
}
