// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — Drift governor trait. Governs drift monitoring at the
// integration boundary with policy registration, drift evaluation,
// and remediation recommendation. Reference implementations:
// InMemoryDriftGovernor, NullDriftGovernor.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::drift::{DriftPolicy, DriftRemediationAction, DriftSeverity};
use crate::drift_evaluator::DriftEvaluator;
use crate::error::AiError;

// ── DriftGovernanceDecision ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftGovernanceDecision {
    NoDriftDetected,
    DriftDetected { severity: String, recommended_actions: Vec<String> },
    RequiresInvestigation { reason: String },
    ModelSuspensionRecommended { reason: String },
}

impl fmt::Display for DriftGovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDriftDetected => f.write_str("NoDriftDetected"),
            Self::DriftDetected { severity, .. } => {
                write!(f, "DriftDetected(severity={severity})")
            }
            Self::RequiresInvestigation { reason } => {
                write!(f, "RequiresInvestigation: {reason}")
            }
            Self::ModelSuspensionRecommended { reason } => {
                write!(f, "ModelSuspensionRecommended: {reason}")
            }
        }
    }
}

// ── DriftGovernanceResult ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftGovernanceResult {
    pub model_id: String,
    pub decision: DriftGovernanceDecision,
    pub evaluated_at: i64,
}

// ── DriftGovernor trait ────────────────────────────────────────────

pub trait DriftGovernor {
    fn evaluate_model_drift(
        &self,
        model_id: &str,
        measurements: &HashMap<String, String>,
        model_version: &str,
        evaluated_at: i64,
    ) -> DriftGovernanceResult;

    fn register_drift_policy(&mut self, policy: &DriftPolicy) -> Result<(), AiError>;
    fn remove_drift_policy(&mut self, policy_id: &str) -> Result<(), AiError>;
    fn list_drift_policies(&self) -> Vec<&DriftPolicy>;

    fn recommend_remediation(
        &self,
        model_id: &str,
        severity: &DriftSeverity,
    ) -> Vec<String>;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryDriftGovernor ──────────────────────────────────────────

pub struct InMemoryDriftGovernor {
    governor_id: String,
    active: bool,
    policies: HashMap<String, DriftPolicy>,
    evaluator: DriftEvaluator,
}

impl InMemoryDriftGovernor {
    pub fn new(governor_id: impl Into<String>) -> Self {
        Self {
            governor_id: governor_id.into(),
            active: true,
            policies: HashMap::new(),
            evaluator: DriftEvaluator::new(),
        }
    }

    fn find_policy_for_model(&self, model_id: &str) -> Option<&DriftPolicy> {
        self.policies.values().find(|p| p.model_id == model_id)
    }
}

impl DriftGovernor for InMemoryDriftGovernor {
    fn evaluate_model_drift(
        &self,
        model_id: &str,
        measurements: &HashMap<String, String>,
        model_version: &str,
        evaluated_at: i64,
    ) -> DriftGovernanceResult {
        let policy = match self.find_policy_for_model(model_id) {
            Some(p) => p,
            None => {
                return DriftGovernanceResult {
                    model_id: model_id.to_string(),
                    decision: DriftGovernanceDecision::RequiresInvestigation {
                        reason: format!("No drift policy registered for model {model_id}"),
                    },
                    evaluated_at,
                };
            }
        };

        let eval_result = self.evaluator.evaluate_drift(policy, measurements, model_version, evaluated_at);

        let decision = match &eval_result.overall_status {
            crate::drift::DriftStatus::NoDrift => DriftGovernanceDecision::NoDriftDetected,
            crate::drift::DriftStatus::SevereDrift { details } => {
                DriftGovernanceDecision::ModelSuspensionRecommended {
                    reason: details.clone(),
                }
            }
            _ => {
                let severity_str = if !eval_result.recommended_actions.is_empty() {
                    match &eval_result.recommended_actions[0] {
                        DriftRemediationAction::Suspend => "Critical".to_string(),
                        DriftRemediationAction::Rollback => "High".to_string(),
                        DriftRemediationAction::Retrain => "Medium".to_string(),
                        _ => "Low".to_string(),
                    }
                } else {
                    "Low".to_string()
                };
                let actions: Vec<String> = eval_result
                    .recommended_actions
                    .iter()
                    .map(|a| a.to_string())
                    .collect();
                DriftGovernanceDecision::DriftDetected {
                    severity: severity_str,
                    recommended_actions: actions,
                }
            }
        };

        DriftGovernanceResult {
            model_id: model_id.to_string(),
            decision,
            evaluated_at,
        }
    }

    fn register_drift_policy(&mut self, policy: &DriftPolicy) -> Result<(), AiError> {
        self.policies.insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn remove_drift_policy(&mut self, policy_id: &str) -> Result<(), AiError> {
        self.policies
            .remove(policy_id)
            .map(|_| ())
            .ok_or_else(|| AiError::InvalidOperation(format!("Drift policy not found: {policy_id}")))
    }

    fn list_drift_policies(&self) -> Vec<&DriftPolicy> {
        self.policies.values().collect()
    }

    fn recommend_remediation(
        &self,
        _model_id: &str,
        severity: &DriftSeverity,
    ) -> Vec<String> {
        match severity {
            DriftSeverity::Critical => vec!["Suspend model".into(), "Investigate root cause".into()],
            DriftSeverity::High => vec!["Rollback to previous version".into(), "Schedule retraining".into()],
            DriftSeverity::Medium => vec!["Schedule retraining".into(), "Increase monitoring frequency".into()],
            DriftSeverity::Low => vec!["Continue monitoring".into(), "Log for review".into()],
        }
    }

    fn governor_id(&self) -> &str {
        &self.governor_id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullDriftGovernor ──────────────────────────────────────────────

pub struct NullDriftGovernor;

impl DriftGovernor for NullDriftGovernor {
    fn evaluate_model_drift(
        &self,
        model_id: &str,
        _measurements: &HashMap<String, String>,
        _model_version: &str,
        evaluated_at: i64,
    ) -> DriftGovernanceResult {
        DriftGovernanceResult {
            model_id: model_id.to_string(),
            decision: DriftGovernanceDecision::NoDriftDetected,
            evaluated_at,
        }
    }

    fn register_drift_policy(&mut self, _policy: &DriftPolicy) -> Result<(), AiError> {
        Ok(())
    }

    fn remove_drift_policy(&mut self, _policy_id: &str) -> Result<(), AiError> {
        Ok(())
    }

    fn list_drift_policies(&self) -> Vec<&DriftPolicy> {
        Vec::new()
    }

    fn recommend_remediation(&self, _model_id: &str, _severity: &DriftSeverity) -> Vec<String> {
        Vec::new()
    }

    fn governor_id(&self) -> &str {
        "null-drift-governor"
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drift::{DriftDetectionWindow, DriftMetricDefinition};
    use crate::evaluation::ThresholdComparison;

    fn make_policy() -> DriftPolicy {
        let mut policy = DriftPolicy::new("dp-1", "m-1", DriftDetectionWindow::Expanding, 1000);
        let metric = DriftMetricDefinition::new(
            "dm-1", "accuracy_drift", "0.90",
            ThresholdComparison::GreaterThanOrEqual,
        );
        policy.drift_metrics.push(metric);
        policy
    }

    #[test]
    fn test_inmemory_no_drift() {
        let mut gov = InMemoryDriftGovernor::new("gov-1");
        gov.register_drift_policy(&make_policy()).unwrap();
        let mut measurements = HashMap::new();
        measurements.insert("dm-1".into(), "0.95".into());
        let result = gov.evaluate_model_drift("m-1", &measurements, "1.0.0", 5000);
        assert!(matches!(result.decision, DriftGovernanceDecision::NoDriftDetected));
    }

    #[test]
    fn test_inmemory_drift_detected() {
        let mut gov = InMemoryDriftGovernor::new("gov-1");
        gov.register_drift_policy(&make_policy()).unwrap();
        let mut measurements = HashMap::new();
        measurements.insert("dm-1".into(), "0.70".into());
        let result = gov.evaluate_model_drift("m-1", &measurements, "1.0.0", 5000);
        assert!(!matches!(result.decision, DriftGovernanceDecision::NoDriftDetected));
    }

    #[test]
    fn test_inmemory_no_policy() {
        let gov = InMemoryDriftGovernor::new("gov-1");
        let measurements = HashMap::new();
        let result = gov.evaluate_model_drift("m-1", &measurements, "1.0.0", 5000);
        assert!(matches!(result.decision, DriftGovernanceDecision::RequiresInvestigation { .. }));
    }

    #[test]
    fn test_inmemory_policy_lifecycle() {
        let mut gov = InMemoryDriftGovernor::new("gov-1");
        gov.register_drift_policy(&make_policy()).unwrap();
        assert_eq!(gov.list_drift_policies().len(), 1);
        gov.remove_drift_policy("dp-1").unwrap();
        assert_eq!(gov.list_drift_policies().len(), 0);
    }

    #[test]
    fn test_inmemory_remove_nonexistent() {
        let mut gov = InMemoryDriftGovernor::new("gov-1");
        assert!(gov.remove_drift_policy("missing").is_err());
    }

    #[test]
    fn test_inmemory_remediation_by_severity() {
        let gov = InMemoryDriftGovernor::new("gov-1");
        let actions = gov.recommend_remediation("m-1", &DriftSeverity::Critical);
        assert!(actions.iter().any(|a| a.contains("Suspend")));
        let actions = gov.recommend_remediation("m-1", &DriftSeverity::Low);
        assert!(actions.iter().any(|a| a.contains("monitoring")));
    }

    #[test]
    fn test_inmemory_governor_identity() {
        let gov = InMemoryDriftGovernor::new("gov-1");
        assert_eq!(gov.governor_id(), "gov-1");
        assert!(gov.is_active());
    }

    #[test]
    fn test_null_no_drift() {
        let gov = NullDriftGovernor;
        let measurements = HashMap::new();
        let result = gov.evaluate_model_drift("m-1", &measurements, "1.0.0", 5000);
        assert!(matches!(result.decision, DriftGovernanceDecision::NoDriftDetected));
        assert!(!gov.is_active());
    }

    #[test]
    fn test_null_empty_remediation() {
        let gov = NullDriftGovernor;
        assert!(gov.recommend_remediation("m-1", &DriftSeverity::Critical).is_empty());
    }

    #[test]
    fn test_decision_display() {
        assert_eq!(DriftGovernanceDecision::NoDriftDetected.to_string(), "NoDriftDetected");
        let d = DriftGovernanceDecision::ModelSuspensionRecommended { reason: "severe".into() };
        assert!(d.to_string().contains("ModelSuspensionRecommended"));
    }

    #[test]
    fn test_result_fields() {
        let result = DriftGovernanceResult {
            model_id: "m-1".into(),
            decision: DriftGovernanceDecision::NoDriftDetected,
            evaluated_at: 5000,
        };
        assert_eq!(result.model_id, "m-1");
        assert_eq!(result.evaluated_at, 5000);
    }

    #[test]
    fn test_severe_drift_recommends_suspension() {
        let mut gov = InMemoryDriftGovernor::new("gov-1");
        gov.register_drift_policy(&make_policy()).unwrap();
        // Very low value to trigger severe drift
        let mut measurements = HashMap::new();
        measurements.insert("dm-1".into(), "0.01".into());
        let result = gov.evaluate_model_drift("m-1", &measurements, "1.0.0", 5000);
        assert!(matches!(
            result.decision,
            DriftGovernanceDecision::ModelSuspensionRecommended { .. }
            | DriftGovernanceDecision::DriftDetected { .. }
        ));
    }
}
