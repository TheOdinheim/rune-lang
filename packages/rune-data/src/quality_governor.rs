// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — Quality governor trait. Governs data quality at the
// integration boundary with pipeline-blocking enforcement. Reference
// implementations: InMemoryQualityGovernor, NullQualityGovernor.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::quality::{DataQualityPolicy, DataQualityRule};
use crate::quality_engine::{PolicyEvaluation, QualityEngine};

// ── QualityGovernanceDecision ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityGovernanceDecision {
    QualityMet { pass_rate: String, policy_ref: String },
    QualityFailed { pass_rate: String, failed_rules: Vec<String>, policy_ref: String },
    PipelineBlocked { reason: String, policy_ref: String },
    InsufficientData { reason: String },
}

impl fmt::Display for QualityGovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QualityMet { pass_rate, policy_ref } => {
                write!(f, "QualityMet(rate={pass_rate}, policy={policy_ref})")
            }
            Self::QualityFailed { pass_rate, failed_rules, policy_ref } => {
                write!(f, "QualityFailed(rate={pass_rate}, failed={}, policy={policy_ref})", failed_rules.len())
            }
            Self::PipelineBlocked { reason, policy_ref } => {
                write!(f, "PipelineBlocked({reason}, policy={policy_ref})")
            }
            Self::InsufficientData { reason } => {
                write!(f, "InsufficientData({reason})")
            }
        }
    }
}

// ── QualityGovernanceResult ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityGovernanceResult {
    pub dataset_ref: String,
    pub decision: QualityGovernanceDecision,
    pub evaluated_at: i64,
}

// ── QualityGovernor trait ────────────────────────────────────────────

pub trait QualityGovernor {
    fn evaluate_dataset_quality(
        &self,
        dataset_ref: &str,
        measured_values: &HashMap<String, Option<String>>,
        evaluated_at: i64,
    ) -> QualityGovernanceResult;

    fn register_quality_policy(
        &mut self,
        policy: DataQualityPolicy,
        rules: Vec<DataQualityRule>,
    );

    fn remove_quality_policy(&mut self, policy_id: &str);
    fn list_quality_policies(&self) -> Vec<&DataQualityPolicy>;

    fn check_pipeline_gate(
        &self,
        dataset_ref: &str,
        measured_values: &HashMap<String, Option<String>>,
        evaluated_at: i64,
    ) -> bool;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryQualityGovernor ──────────────────────────────────────────

pub struct InMemoryQualityGovernor {
    id: String,
    active: bool,
    engine: QualityEngine,
    policies: HashMap<String, DataQualityPolicy>,
    rules: HashMap<String, DataQualityRule>,
}

impl InMemoryQualityGovernor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            engine: QualityEngine::new(),
            policies: HashMap::new(),
            rules: HashMap::new(),
        }
    }

    fn find_policy_for_dataset(&self, dataset_ref: &str) -> Option<&DataQualityPolicy> {
        self.policies.values().find(|p| p.dataset_ref == dataset_ref)
    }

    fn evaluate_with_engine(
        &self,
        policy: &DataQualityPolicy,
        measured_values: &HashMap<String, Option<String>>,
        evaluated_at: i64,
    ) -> PolicyEvaluation {
        self.engine.evaluate_policy(policy, &self.rules, measured_values, evaluated_at)
    }
}

impl QualityGovernor for InMemoryQualityGovernor {
    fn evaluate_dataset_quality(
        &self,
        dataset_ref: &str,
        measured_values: &HashMap<String, Option<String>>,
        evaluated_at: i64,
    ) -> QualityGovernanceResult {
        let policy = match self.find_policy_for_dataset(dataset_ref) {
            Some(p) => p,
            None => {
                return QualityGovernanceResult {
                    dataset_ref: dataset_ref.to_string(),
                    decision: QualityGovernanceDecision::InsufficientData {
                        reason: format!("No quality policy found for dataset {dataset_ref}"),
                    },
                    evaluated_at,
                };
            }
        };

        let eval = self.evaluate_with_engine(policy, measured_values, evaluated_at);

        let decision = if eval.blocked {
            QualityGovernanceDecision::PipelineBlocked {
                reason: format!("Quality pass rate {} below minimum {}", eval.pass_rate, policy.minimum_pass_rate),
                policy_ref: policy.policy_id.clone(),
            }
        } else if eval.minimum_met {
            QualityGovernanceDecision::QualityMet {
                pass_rate: eval.pass_rate,
                policy_ref: policy.policy_id.clone(),
            }
        } else {
            let failed_rules: Vec<String> = eval.rule_evaluations
                .iter()
                .filter(|r| !r.passed)
                .map(|r| r.rule_id.clone())
                .collect();
            QualityGovernanceDecision::QualityFailed {
                pass_rate: eval.pass_rate,
                failed_rules,
                policy_ref: policy.policy_id.clone(),
            }
        };

        QualityGovernanceResult {
            dataset_ref: dataset_ref.to_string(),
            decision,
            evaluated_at,
        }
    }

    fn register_quality_policy(
        &mut self,
        policy: DataQualityPolicy,
        rules: Vec<DataQualityRule>,
    ) {
        for rule in rules {
            self.rules.insert(rule.rule_id.clone(), rule);
        }
        self.policies.insert(policy.policy_id.clone(), policy);
    }

    fn remove_quality_policy(&mut self, policy_id: &str) {
        self.policies.remove(policy_id);
    }

    fn list_quality_policies(&self) -> Vec<&DataQualityPolicy> {
        self.policies.values().collect()
    }

    fn check_pipeline_gate(
        &self,
        dataset_ref: &str,
        measured_values: &HashMap<String, Option<String>>,
        evaluated_at: i64,
    ) -> bool {
        let result = self.evaluate_dataset_quality(dataset_ref, measured_values, evaluated_at);
        matches!(result.decision, QualityGovernanceDecision::QualityMet { .. })
    }

    fn governor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullQualityGovernor ──────────────────────────────────────────────

pub struct NullQualityGovernor;

impl QualityGovernor for NullQualityGovernor {
    fn evaluate_dataset_quality(
        &self,
        dataset_ref: &str,
        _measured_values: &HashMap<String, Option<String>>,
        evaluated_at: i64,
    ) -> QualityGovernanceResult {
        QualityGovernanceResult {
            dataset_ref: dataset_ref.to_string(),
            decision: QualityGovernanceDecision::QualityMet {
                pass_rate: "1.0000".to_string(),
                policy_ref: "null".to_string(),
            },
            evaluated_at,
        }
    }

    fn register_quality_policy(&mut self, _policy: DataQualityPolicy, _rules: Vec<DataQualityRule>) {}
    fn remove_quality_policy(&mut self, _policy_id: &str) {}
    fn list_quality_policies(&self) -> Vec<&DataQualityPolicy> { Vec::new() }
    fn check_pipeline_gate(&self, _dataset_ref: &str, _measured_values: &HashMap<String, Option<String>>, _evaluated_at: i64) -> bool { true }
    fn governor_id(&self) -> &str { "null-quality-governor" }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality::{QualityExpectation, QualitySeverity};

    fn make_rule(id: &str, dataset: &str) -> DataQualityRule {
        DataQualityRule {
            rule_id: id.into(),
            rule_name: format!("rule_{id}"),
            dimension: crate::quality::DataQualityDimension::Completeness,
            target_dataset_ref: dataset.into(),
            target_field: None,
            expectation: QualityExpectation::NotNull,
            severity: QualitySeverity::Critical,
            enabled: true,
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn make_policy(id: &str, dataset: &str, rules: Vec<&str>) -> DataQualityPolicy {
        DataQualityPolicy {
            policy_id: id.into(),
            dataset_ref: dataset.into(),
            rules: rules.into_iter().map(String::from).collect(),
            minimum_pass_rate: "1.0".into(),
            block_on_failure: true,
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_quality_met() {
        let mut gov = InMemoryQualityGovernor::new("qg-1");
        let r1 = make_rule("qr-1", "ds-1");
        let policy = make_policy("qp-1", "ds-1", vec!["qr-1"]);
        gov.register_quality_policy(policy, vec![r1]);
        let mut measured = HashMap::new();
        measured.insert("qr-1".into(), Some("value".to_string()));
        let result = gov.evaluate_dataset_quality("ds-1", &measured, 2000);
        assert!(matches!(result.decision, QualityGovernanceDecision::QualityMet { .. }));
    }

    #[test]
    fn test_pipeline_blocked() {
        let mut gov = InMemoryQualityGovernor::new("qg-1");
        let r1 = make_rule("qr-1", "ds-1");
        let policy = make_policy("qp-1", "ds-1", vec!["qr-1"]);
        gov.register_quality_policy(policy, vec![r1]);
        let mut measured = HashMap::new();
        measured.insert("qr-1".into(), None);
        let result = gov.evaluate_dataset_quality("ds-1", &measured, 2000);
        assert!(matches!(result.decision, QualityGovernanceDecision::PipelineBlocked { .. }));
    }

    #[test]
    fn test_quality_failed_no_block() {
        let mut gov = InMemoryQualityGovernor::new("qg-1");
        let r1 = make_rule("qr-1", "ds-1");
        let mut policy = make_policy("qp-1", "ds-1", vec!["qr-1"]);
        policy.block_on_failure = false;
        gov.register_quality_policy(policy, vec![r1]);
        let mut measured = HashMap::new();
        measured.insert("qr-1".into(), None);
        let result = gov.evaluate_dataset_quality("ds-1", &measured, 2000);
        assert!(matches!(result.decision, QualityGovernanceDecision::QualityFailed { .. }));
    }

    #[test]
    fn test_insufficient_data() {
        let gov = InMemoryQualityGovernor::new("qg-1");
        let result = gov.evaluate_dataset_quality("ds-missing", &HashMap::new(), 2000);
        assert!(matches!(result.decision, QualityGovernanceDecision::InsufficientData { .. }));
    }

    #[test]
    fn test_pipeline_gate_pass() {
        let mut gov = InMemoryQualityGovernor::new("qg-1");
        let r1 = make_rule("qr-1", "ds-1");
        let policy = make_policy("qp-1", "ds-1", vec!["qr-1"]);
        gov.register_quality_policy(policy, vec![r1]);
        let mut measured = HashMap::new();
        measured.insert("qr-1".into(), Some("ok".to_string()));
        assert!(gov.check_pipeline_gate("ds-1", &measured, 2000));
    }

    #[test]
    fn test_pipeline_gate_fail() {
        let mut gov = InMemoryQualityGovernor::new("qg-1");
        let r1 = make_rule("qr-1", "ds-1");
        let policy = make_policy("qp-1", "ds-1", vec!["qr-1"]);
        gov.register_quality_policy(policy, vec![r1]);
        let mut measured = HashMap::new();
        measured.insert("qr-1".into(), None);
        assert!(!gov.check_pipeline_gate("ds-1", &measured, 2000));
    }

    #[test]
    fn test_remove_policy() {
        let mut gov = InMemoryQualityGovernor::new("qg-1");
        let r1 = make_rule("qr-1", "ds-1");
        let policy = make_policy("qp-1", "ds-1", vec!["qr-1"]);
        gov.register_quality_policy(policy, vec![r1]);
        assert_eq!(gov.list_quality_policies().len(), 1);
        gov.remove_quality_policy("qp-1");
        assert_eq!(gov.list_quality_policies().len(), 0);
    }

    #[test]
    fn test_governor_id_and_active() {
        let gov = InMemoryQualityGovernor::new("qg-1");
        assert_eq!(gov.governor_id(), "qg-1");
        assert!(gov.is_active());
    }

    #[test]
    fn test_null_governor() {
        let mut gov = NullQualityGovernor;
        let result = gov.evaluate_dataset_quality("ds-1", &HashMap::new(), 2000);
        assert!(matches!(result.decision, QualityGovernanceDecision::QualityMet { .. }));
        assert!(gov.check_pipeline_gate("ds-1", &HashMap::new(), 2000));
        assert_eq!(gov.governor_id(), "null-quality-governor");
        assert!(!gov.is_active());
        gov.register_quality_policy(
            DataQualityPolicy {
                policy_id: "x".into(), dataset_ref: "x".into(), rules: Vec::new(),
                minimum_pass_rate: "1.0".into(), block_on_failure: false, created_at: 0, metadata: HashMap::new(),
            },
            Vec::new(),
        );
        gov.remove_quality_policy("x");
        assert!(gov.list_quality_policies().is_empty());
    }

    #[test]
    fn test_decision_display() {
        let decisions = vec![
            QualityGovernanceDecision::QualityMet { pass_rate: "1.00".into(), policy_ref: "qp-1".into() },
            QualityGovernanceDecision::QualityFailed { pass_rate: "0.50".into(), failed_rules: vec!["qr-1".into()], policy_ref: "qp-1".into() },
            QualityGovernanceDecision::PipelineBlocked { reason: "blocked".into(), policy_ref: "qp-1".into() },
            QualityGovernanceDecision::InsufficientData { reason: "no data".into() },
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
    }
}
