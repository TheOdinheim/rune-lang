// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Data freshness evaluation. Evaluates data freshness
// against FreshnessPolicy, computes hours since last update,
// determines staleness, and generates alerts for stale data.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::freshness::{
    FreshnessAlert, FreshnessAssessment, FreshnessPolicy, FreshnessStatus,
};

// ── FreshnessEvaluator ───────────────────────────────────────────────

pub struct FreshnessEvaluator;

impl FreshnessEvaluator {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate_freshness(
        &self,
        policy: &FreshnessPolicy,
        last_updated_at: i64,
        current_at: i64,
    ) -> FreshnessAssessment {
        let hours = Self::compute_hours_since_update(last_updated_at, current_at);
        let is_stale = Self::is_stale(&hours, &policy.staleness_threshold_hours);
        let freshness_status = if is_stale {
            FreshnessStatus::Stale {
                hours_since_update: hours.clone(),
                threshold_hours: policy.staleness_threshold_hours.clone(),
            }
        } else {
            FreshnessStatus::Fresh {
                hours_since_update: hours.clone(),
            }
        };
        let sla_met = !is_stale;
        let assessment_id = format!("fa-{}-{current_at}", policy.policy_id);
        FreshnessAssessment {
            assessment_id,
            policy_id: policy.policy_id.clone(),
            dataset_ref: policy.dataset_ref.clone(),
            last_updated_at,
            assessed_at: current_at,
            freshness_status,
            sla_met,
            metadata: HashMap::new(),
        }
    }

    pub fn compute_hours_since_update(last_updated_at: i64, current_at: i64) -> String {
        let diff_ms = if current_at > last_updated_at {
            current_at - last_updated_at
        } else {
            0
        };
        let hours = diff_ms as f64 / (3600.0 * 1000.0);
        format!("{hours:.2}")
    }

    pub fn is_stale(hours_since_update: &str, staleness_threshold_hours: &str) -> bool {
        match (
            hours_since_update.parse::<f64>(),
            staleness_threshold_hours.parse::<f64>(),
        ) {
            (Ok(hours), Ok(threshold)) => hours > threshold,
            _ => hours_since_update > staleness_threshold_hours,
        }
    }

    pub fn generate_alert_if_stale(
        &self,
        assessment: &FreshnessAssessment,
        policy: &FreshnessPolicy,
    ) -> Option<FreshnessAlert> {
        match &assessment.freshness_status {
            FreshnessStatus::Stale { hours_since_update, threshold_hours } => {
                let alert_id = format!("fal-{}", assessment.assessment_id);
                Some(FreshnessAlert {
                    alert_id,
                    assessment_id: assessment.assessment_id.clone(),
                    dataset_ref: assessment.dataset_ref.clone(),
                    severity: policy.alerting_severity.clone(),
                    message: format!(
                        "Dataset {} is stale: {}h since update (threshold: {}h)",
                        assessment.dataset_ref, hours_since_update, threshold_hours
                    ),
                    alerted_at: assessment.assessed_at,
                    acknowledged_by: None,
                    acknowledged_at: None,
                    metadata: HashMap::new(),
                })
            }
            _ => None,
        }
    }
}

impl Default for FreshnessEvaluator {
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
    use crate::freshness::UpdateFrequency;
    use crate::quality::QualitySeverity;

    fn make_policy(threshold_hours: &str) -> FreshnessPolicy {
        FreshnessPolicy {
            policy_id: "fp-1".into(),
            dataset_ref: "ds-orders".into(),
            expected_update_frequency: UpdateFrequency::Hourly,
            staleness_threshold_hours: threshold_hours.into(),
            alerting_severity: QualitySeverity::Warning,
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_fresh_data_within_threshold() {
        let evaluator = FreshnessEvaluator::new();
        let policy = make_policy("4");
        // 1 hour ago (3600000ms)
        let assessment = evaluator.evaluate_freshness(&policy, 900_000, 4_500_000);
        assert!(assessment.sla_met);
        assert!(matches!(assessment.freshness_status, FreshnessStatus::Fresh { .. }));
    }

    #[test]
    fn test_stale_data_beyond_threshold() {
        let evaluator = FreshnessEvaluator::new();
        let policy = make_policy("4");
        // 20 hours ago
        let last_updated = 0;
        let current = 72_000_000; // 20h in ms
        let assessment = evaluator.evaluate_freshness(&policy, last_updated, current);
        assert!(!assessment.sla_met);
        assert!(matches!(assessment.freshness_status, FreshnessStatus::Stale { .. }));
    }

    #[test]
    fn test_sla_met_fresh() {
        let evaluator = FreshnessEvaluator::new();
        let policy = make_policy("24");
        let assessment = evaluator.evaluate_freshness(&policy, 1000, 3_600_000);
        assert!(assessment.sla_met);
    }

    #[test]
    fn test_sla_not_met_stale() {
        let evaluator = FreshnessEvaluator::new();
        let policy = make_policy("1");
        // 5 hours
        let assessment = evaluator.evaluate_freshness(&policy, 0, 18_000_000);
        assert!(!assessment.sla_met);
    }

    #[test]
    fn test_alert_generated_for_stale() {
        let evaluator = FreshnessEvaluator::new();
        let policy = make_policy("1");
        let assessment = evaluator.evaluate_freshness(&policy, 0, 18_000_000);
        let alert = evaluator.generate_alert_if_stale(&assessment, &policy);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, QualitySeverity::Warning);
        assert!(alert.message.contains("stale"));
    }

    #[test]
    fn test_alert_not_generated_for_fresh() {
        let evaluator = FreshnessEvaluator::new();
        let policy = make_policy("24");
        let assessment = evaluator.evaluate_freshness(&policy, 1000, 3_600_000);
        let alert = evaluator.generate_alert_if_stale(&assessment, &policy);
        assert!(alert.is_none());
    }

    #[test]
    fn test_edge_case_at_threshold() {
        let evaluator = FreshnessEvaluator::new();
        let policy = make_policy("1.00");
        // Exactly 1 hour = 3600000ms
        let assessment = evaluator.evaluate_freshness(&policy, 0, 3_600_000);
        // 1.00 hours since update, threshold 1.00 — not stale (not strictly greater)
        assert!(assessment.sla_met);
    }

    #[test]
    fn test_compute_hours_zero_diff() {
        let hours = FreshnessEvaluator::compute_hours_since_update(1000, 1000);
        assert_eq!(hours, "0.00");
    }

    #[test]
    fn test_compute_hours_negative_handled() {
        let hours = FreshnessEvaluator::compute_hours_since_update(5000, 1000);
        assert_eq!(hours, "0.00");
    }

    #[test]
    fn test_is_stale_true() {
        assert!(FreshnessEvaluator::is_stale("5.00", "4"));
    }

    #[test]
    fn test_is_stale_false() {
        assert!(!FreshnessEvaluator::is_stale("3.00", "4"));
    }

    #[test]
    fn test_freshness_evaluator_default() {
        let _e = FreshnessEvaluator;
    }

    #[test]
    fn test_alert_severity_critical() {
        let evaluator = FreshnessEvaluator::new();
        let mut policy = make_policy("1");
        policy.alerting_severity = QualitySeverity::Critical;
        let assessment = evaluator.evaluate_freshness(&policy, 0, 18_000_000);
        let alert = evaluator.generate_alert_if_stale(&assessment, &policy).unwrap();
        assert_eq!(alert.severity, QualitySeverity::Critical);
    }
}
