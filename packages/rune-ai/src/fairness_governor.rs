// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — Fairness governor trait. Governs fairness monitoring at
// the integration boundary with policy registration, compliance
// checking, and fairness evaluation. Reference implementations:
// InMemoryFairnessGovernor, NullFairnessGovernor.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::bias_fairness::FairnessPolicy;
use crate::error::AiError;
use crate::fairness_evaluator::FairnessEvaluator;

// ── FairnessGovernanceDecision ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FairnessGovernanceDecision {
    Compliant { policy_ref: String },
    NonCompliant { violations: Vec<String>, policy_ref: String },
    RequiresRemediation { recommended_actions: Vec<String> },
    InsufficientData { reason: String },
}

impl fmt::Display for FairnessGovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compliant { policy_ref } => write!(f, "Compliant(policy={policy_ref})"),
            Self::NonCompliant { violations, .. } => {
                write!(f, "NonCompliant({} violations)", violations.len())
            }
            Self::RequiresRemediation { recommended_actions } => {
                write!(f, "RequiresRemediation({} actions)", recommended_actions.len())
            }
            Self::InsufficientData { reason } => write!(f, "InsufficientData: {reason}"),
        }
    }
}

// ── FairnessGovernanceResult ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessGovernanceResult {
    pub model_id: String,
    pub decision: FairnessGovernanceDecision,
    pub assessed_at: i64,
}

// ── FairnessGovernor trait ─────────────────────────────────────────

pub trait FairnessGovernor {
    fn evaluate_model_fairness(
        &self,
        model_id: &str,
        measurements: &HashMap<(String, String), String>,
        assessed_at: i64,
    ) -> FairnessGovernanceResult;

    fn register_fairness_policy(&mut self, policy: &FairnessPolicy) -> Result<(), AiError>;
    fn remove_fairness_policy(&mut self, policy_id: &str) -> Result<(), AiError>;
    fn list_fairness_policies(&self) -> Vec<&FairnessPolicy>;
    fn check_fairness_compliance(&self, model_id: &str, assessed_at: i64) -> FairnessGovernanceResult;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryFairnessGovernor ───────────────────────────────────────

pub struct InMemoryFairnessGovernor {
    governor_id: String,
    active: bool,
    policies: HashMap<String, FairnessPolicy>,
    evaluator: FairnessEvaluator,
}

impl InMemoryFairnessGovernor {
    pub fn new(governor_id: impl Into<String>) -> Self {
        Self {
            governor_id: governor_id.into(),
            active: true,
            policies: HashMap::new(),
            evaluator: FairnessEvaluator::new(),
        }
    }

    fn find_policy_for_model(&self, model_id: &str) -> Option<&FairnessPolicy> {
        self.policies.values().find(|p| p.model_id == model_id)
    }
}

impl FairnessGovernor for InMemoryFairnessGovernor {
    fn evaluate_model_fairness(
        &self,
        model_id: &str,
        measurements: &HashMap<(String, String), String>,
        assessed_at: i64,
    ) -> FairnessGovernanceResult {
        let policy = match self.find_policy_for_model(model_id) {
            Some(p) => p,
            None => {
                return FairnessGovernanceResult {
                    model_id: model_id.to_string(),
                    decision: FairnessGovernanceDecision::InsufficientData {
                        reason: format!("No fairness policy registered for model {model_id}"),
                    },
                    assessed_at,
                };
            }
        };

        if measurements.is_empty() {
            return FairnessGovernanceResult {
                model_id: model_id.to_string(),
                decision: FairnessGovernanceDecision::InsufficientData {
                    reason: "No measurements provided".to_string(),
                },
                assessed_at,
            };
        }

        let eval_result = self.evaluator.evaluate_fairness(policy, measurements, assessed_at);

        let decision = match &eval_result.overall_status {
            crate::bias_fairness::FairnessStatus::Fair => {
                FairnessGovernanceDecision::Compliant {
                    policy_ref: policy.policy_id.clone(),
                }
            }
            crate::bias_fairness::FairnessStatus::Unfair { violations } => {
                FairnessGovernanceDecision::NonCompliant {
                    violations: violations.clone(),
                    policy_ref: policy.policy_id.clone(),
                }
            }
            crate::bias_fairness::FairnessStatus::NotAssessed => {
                FairnessGovernanceDecision::InsufficientData {
                    reason: "Evaluation produced no assessable metrics".to_string(),
                }
            }
            crate::bias_fairness::FairnessStatus::Inconclusive { reason } => {
                FairnessGovernanceDecision::RequiresRemediation {
                    recommended_actions: vec![format!("Investigate: {reason}")],
                }
            }
        };

        FairnessGovernanceResult {
            model_id: model_id.to_string(),
            decision,
            assessed_at,
        }
    }

    fn register_fairness_policy(&mut self, policy: &FairnessPolicy) -> Result<(), AiError> {
        self.policies.insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn remove_fairness_policy(&mut self, policy_id: &str) -> Result<(), AiError> {
        self.policies
            .remove(policy_id)
            .map(|_| ())
            .ok_or_else(|| AiError::InvalidOperation(format!("Fairness policy not found: {policy_id}")))
    }

    fn list_fairness_policies(&self) -> Vec<&FairnessPolicy> {
        self.policies.values().collect()
    }

    fn check_fairness_compliance(&self, model_id: &str, assessed_at: i64) -> FairnessGovernanceResult {
        match self.find_policy_for_model(model_id) {
            Some(policy) => FairnessGovernanceResult {
                model_id: model_id.to_string(),
                decision: FairnessGovernanceDecision::Compliant {
                    policy_ref: policy.policy_id.clone(),
                },
                assessed_at,
            },
            None => FairnessGovernanceResult {
                model_id: model_id.to_string(),
                decision: FairnessGovernanceDecision::InsufficientData {
                    reason: format!("No fairness policy registered for model {model_id}"),
                },
                assessed_at,
            },
        }
    }

    fn governor_id(&self) -> &str {
        &self.governor_id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullFairnessGovernor ───────────────────────────────────────────

pub struct NullFairnessGovernor;

impl FairnessGovernor for NullFairnessGovernor {
    fn evaluate_model_fairness(
        &self,
        model_id: &str,
        _measurements: &HashMap<(String, String), String>,
        assessed_at: i64,
    ) -> FairnessGovernanceResult {
        FairnessGovernanceResult {
            model_id: model_id.to_string(),
            decision: FairnessGovernanceDecision::Compliant {
                policy_ref: "null".to_string(),
            },
            assessed_at,
        }
    }

    fn register_fairness_policy(&mut self, _policy: &FairnessPolicy) -> Result<(), AiError> {
        Ok(())
    }

    fn remove_fairness_policy(&mut self, _policy_id: &str) -> Result<(), AiError> {
        Ok(())
    }

    fn list_fairness_policies(&self) -> Vec<&FairnessPolicy> {
        Vec::new()
    }

    fn check_fairness_compliance(&self, model_id: &str, assessed_at: i64) -> FairnessGovernanceResult {
        FairnessGovernanceResult {
            model_id: model_id.to_string(),
            decision: FairnessGovernanceDecision::Compliant {
                policy_ref: "null".to_string(),
            },
            assessed_at,
        }
    }

    fn governor_id(&self) -> &str {
        "null-fairness-governor"
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
    use crate::bias_fairness::{
        FairnessMetricDefinition, MonitoringFrequency, ProtectedAttribute, ProtectedAttributeType,
    };
    use crate::evaluation::ThresholdComparison;

    fn make_policy() -> FairnessPolicy {
        let mut policy = FairnessPolicy::new("fp-1", "m-1", MonitoringFrequency::Daily, 1000);
        policy.protected_attributes.push(
            ProtectedAttribute::new("gender", ProtectedAttributeType::Gender),
        );
        let mut metric = FairnessMetricDefinition::new(
            "fm-1", "demographic_parity", "0.80",
            ThresholdComparison::GreaterThanOrEqual,
        );
        metric.applies_to_attributes = vec!["gender".into()];
        policy.fairness_metrics.push(metric);
        policy
    }

    #[test]
    fn test_inmemory_evaluate_compliant() {
        let mut gov = InMemoryFairnessGovernor::new("gov-1");
        gov.register_fairness_policy(&make_policy()).unwrap();
        let mut measurements = HashMap::new();
        measurements.insert(("fm-1".into(), "gender".into()), "0.90".into());
        let result = gov.evaluate_model_fairness("m-1", &measurements, 5000);
        assert!(matches!(result.decision, FairnessGovernanceDecision::Compliant { .. }));
    }

    #[test]
    fn test_inmemory_evaluate_non_compliant() {
        let mut gov = InMemoryFairnessGovernor::new("gov-1");
        gov.register_fairness_policy(&make_policy()).unwrap();
        let mut measurements = HashMap::new();
        measurements.insert(("fm-1".into(), "gender".into()), "0.60".into());
        let result = gov.evaluate_model_fairness("m-1", &measurements, 5000);
        assert!(matches!(result.decision, FairnessGovernanceDecision::NonCompliant { .. }));
    }

    #[test]
    fn test_inmemory_no_policy() {
        let gov = InMemoryFairnessGovernor::new("gov-1");
        let measurements = HashMap::new();
        let result = gov.evaluate_model_fairness("m-1", &measurements, 5000);
        assert!(matches!(result.decision, FairnessGovernanceDecision::InsufficientData { .. }));
    }

    #[test]
    fn test_inmemory_empty_measurements() {
        let mut gov = InMemoryFairnessGovernor::new("gov-1");
        gov.register_fairness_policy(&make_policy()).unwrap();
        let measurements = HashMap::new();
        let result = gov.evaluate_model_fairness("m-1", &measurements, 5000);
        assert!(matches!(result.decision, FairnessGovernanceDecision::InsufficientData { .. }));
    }

    #[test]
    fn test_inmemory_policy_lifecycle() {
        let mut gov = InMemoryFairnessGovernor::new("gov-1");
        gov.register_fairness_policy(&make_policy()).unwrap();
        assert_eq!(gov.list_fairness_policies().len(), 1);
        gov.remove_fairness_policy("fp-1").unwrap();
        assert_eq!(gov.list_fairness_policies().len(), 0);
    }

    #[test]
    fn test_inmemory_remove_nonexistent_policy() {
        let mut gov = InMemoryFairnessGovernor::new("gov-1");
        assert!(gov.remove_fairness_policy("missing").is_err());
    }

    #[test]
    fn test_inmemory_compliance_check() {
        let mut gov = InMemoryFairnessGovernor::new("gov-1");
        gov.register_fairness_policy(&make_policy()).unwrap();
        let result = gov.check_fairness_compliance("m-1", 5000);
        assert!(matches!(result.decision, FairnessGovernanceDecision::Compliant { .. }));
    }

    #[test]
    fn test_inmemory_compliance_check_no_policy() {
        let gov = InMemoryFairnessGovernor::new("gov-1");
        let result = gov.check_fairness_compliance("m-1", 5000);
        assert!(matches!(result.decision, FairnessGovernanceDecision::InsufficientData { .. }));
    }

    #[test]
    fn test_inmemory_governor_identity() {
        let gov = InMemoryFairnessGovernor::new("gov-1");
        assert_eq!(gov.governor_id(), "gov-1");
        assert!(gov.is_active());
    }

    #[test]
    fn test_null_always_compliant() {
        let gov = NullFairnessGovernor;
        let measurements = HashMap::new();
        let result = gov.evaluate_model_fairness("m-1", &measurements, 5000);
        assert!(matches!(result.decision, FairnessGovernanceDecision::Compliant { .. }));
        assert!(!gov.is_active());
    }

    #[test]
    fn test_decision_display() {
        let d = FairnessGovernanceDecision::Compliant { policy_ref: "fp-1".into() };
        assert!(d.to_string().contains("Compliant"));
        let d = FairnessGovernanceDecision::NonCompliant {
            violations: vec!["v1".into()], policy_ref: "fp-1".into(),
        };
        assert!(d.to_string().contains("1 violations"));
    }

    #[test]
    fn test_result_fields() {
        let result = FairnessGovernanceResult {
            model_id: "m-1".into(),
            decision: FairnessGovernanceDecision::Compliant { policy_ref: "fp-1".into() },
            assessed_at: 5000,
        };
        assert_eq!(result.model_id, "m-1");
        assert_eq!(result.assessed_at, 5000);
    }
}
