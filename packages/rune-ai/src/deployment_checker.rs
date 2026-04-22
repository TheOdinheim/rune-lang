// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Deployment readiness assessment. Evaluates whether a
// model is ready for deployment based on model status, evaluation
// gate results, attestation presence, and training data references.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::deployment::DeploymentRequest;
use crate::evaluation_engine::GateEvaluation;
use crate::model_registry::ModelRecord;

// ── DeploymentBlockerType ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentBlockerType {
    ModelNotApproved { current_status: String },
    EvaluationGateNotPassed { gate_id: String, reason: String },
    MissingAttestation,
    MissingTrainingDataRefs,
    EnvironmentNotSupported { environment: String },
    Custom { reason: String },
}

impl fmt::Display for DeploymentBlockerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelNotApproved { current_status } => {
                write!(f, "Model not approved (status: {current_status})")
            }
            Self::EvaluationGateNotPassed { gate_id, reason } => {
                write!(f, "Evaluation gate {gate_id} not passed: {reason}")
            }
            Self::MissingAttestation => f.write_str("Missing attestation reference"),
            Self::MissingTrainingDataRefs => f.write_str("Missing training data references"),
            Self::EnvironmentNotSupported { environment } => {
                write!(f, "Environment not supported: {environment}")
            }
            Self::Custom { reason } => write!(f, "Custom: {reason}"),
        }
    }
}

// ── BlockerSeverity ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockerSeverity {
    Critical,
    Warning,
    Advisory,
}

impl fmt::Display for BlockerSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Critical => "Critical",
            Self::Warning => "Warning",
            Self::Advisory => "Advisory",
        };
        f.write_str(s)
    }
}

// ── DeploymentBlocker ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentBlocker {
    pub blocker_type: DeploymentBlockerType,
    pub severity: BlockerSeverity,
}

// ── DeploymentReadinessResult ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentReadinessResult {
    pub model_id: String,
    pub model_version: String,
    pub ready: bool,
    pub blockers: Vec<DeploymentBlocker>,
    pub checked_at: i64,
}

// ── DeploymentReadinessChecker ──────────────────────────────────────

pub struct DeploymentReadinessChecker;

impl DeploymentReadinessChecker {
    pub fn new() -> Self {
        Self
    }

    pub fn check_readiness(
        &self,
        record: &ModelRecord,
        gate_evaluation: Option<&GateEvaluation>,
        _request: &DeploymentRequest,
        checked_at: i64,
    ) -> DeploymentReadinessResult {
        let mut blockers = Vec::new();

        self.check_model_status(record, &mut blockers);
        self.check_evaluation_gate(gate_evaluation, &mut blockers);
        self.check_attestation(record, &mut blockers);
        self.check_training_data_refs(record, &mut blockers);

        let ready = !blockers.iter().any(|b| b.severity == BlockerSeverity::Critical);

        DeploymentReadinessResult {
            model_id: record.model_id.clone(),
            model_version: record.model_version.clone(),
            ready,
            blockers,
            checked_at,
        }
    }

    pub fn check_model_status(&self, record: &ModelRecord, blockers: &mut Vec<DeploymentBlocker>) {
        if !record.status.is_deployable() {
            blockers.push(DeploymentBlocker {
                blocker_type: DeploymentBlockerType::ModelNotApproved {
                    current_status: record.status.to_string(),
                },
                severity: BlockerSeverity::Critical,
            });
        }
    }

    pub fn check_evaluation_gate(
        &self,
        gate_evaluation: Option<&GateEvaluation>,
        blockers: &mut Vec<DeploymentBlocker>,
    ) {
        if let Some(eval) = gate_evaluation
            && !eval.all_required_passed
        {
            let failed: Vec<String> = eval
                .criteria_results
                .iter()
                .filter(|r| !r.passed)
                .map(|r| r.criteria_id.clone())
                .collect();
            blockers.push(DeploymentBlocker {
                blocker_type: DeploymentBlockerType::EvaluationGateNotPassed {
                    gate_id: eval.gate_id.clone(),
                    reason: format!("Failed criteria: {}", failed.join(", ")),
                },
                severity: BlockerSeverity::Critical,
            });
        }
    }

    pub fn check_environment_compatibility(
        &self,
        _request: &DeploymentRequest,
        _blockers: &mut Vec<DeploymentBlocker>,
    ) {
        // Placeholder — real environment compatibility checks require
        // deployment infrastructure knowledge that belongs in adapter crates.
    }

    fn check_attestation(&self, record: &ModelRecord, blockers: &mut Vec<DeploymentBlocker>) {
        if record.attestation_ref.is_none() {
            blockers.push(DeploymentBlocker {
                blocker_type: DeploymentBlockerType::MissingAttestation,
                severity: BlockerSeverity::Warning,
            });
        }
    }

    fn check_training_data_refs(&self, record: &ModelRecord, blockers: &mut Vec<DeploymentBlocker>) {
        if record.training_data_refs.is_empty() {
            blockers.push(DeploymentBlocker {
                blocker_type: DeploymentBlockerType::MissingTrainingDataRefs,
                severity: BlockerSeverity::Warning,
            });
        }
    }
}

impl Default for DeploymentReadinessChecker {
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
    use crate::deployment::{DeploymentEnvironment, RollbackPolicy};
    use crate::evaluation_engine::{CriterionEvaluation, GateRecommendation};
    use crate::model_registry::{ModelArchitecture, ModelStatus, ModelTaskType};

    fn make_model(status: ModelStatus) -> ModelRecord {
        let mut record = ModelRecord::new(
            "model-1", "GPT", "1.0.0",
            ModelArchitecture::Transformer,
            ModelTaskType::Classification,
            "pytorch", "alice", 1000,
        );
        record.status = status;
        record
    }

    fn make_request() -> DeploymentRequest {
        DeploymentRequest::new(
            "req-1", "model-1", "1.0.0",
            DeploymentEnvironment::Production,
            "alice", 2000,
            RollbackPolicy::Manual,
        )
    }

    fn make_passing_gate() -> GateEvaluation {
        GateEvaluation {
            gate_id: "gate-1".into(),
            model_id: "model-1".into(),
            criteria_results: vec![CriterionEvaluation {
                criteria_id: "ec-1".into(),
                criteria_name: "Accuracy".into(),
                metric_name: "accuracy".into(),
                measured_value: "0.97".into(),
                threshold_value: "0.95".into(),
                comparison_type: ">=".into(),
                passed: true,
                evaluated_at: 1500,
            }],
            all_required_passed: true,
            overall_score: None,
            gate_recommendation: GateRecommendation::Pass,
            evaluated_at: 1500,
        }
    }

    fn make_failing_gate() -> GateEvaluation {
        GateEvaluation {
            gate_id: "gate-1".into(),
            model_id: "model-1".into(),
            criteria_results: vec![CriterionEvaluation {
                criteria_id: "ec-1".into(),
                criteria_name: "Accuracy".into(),
                metric_name: "accuracy".into(),
                measured_value: "0.80".into(),
                threshold_value: "0.95".into(),
                comparison_type: ">=".into(),
                passed: false,
                evaluated_at: 1500,
            }],
            all_required_passed: false,
            overall_score: None,
            gate_recommendation: GateRecommendation::Fail {
                failed_criteria: vec!["ec-1".into()],
            },
            evaluated_at: 1500,
        }
    }

    #[test]
    fn test_approved_model_with_passing_gate_ready() {
        let checker = DeploymentReadinessChecker::new();
        let mut model = make_model(ModelStatus::Approved);
        model.attestation_ref = Some("att-1".into());
        model.training_data_refs.push("ds-1".into());
        let gate = make_passing_gate();
        let result = checker.check_readiness(&model, Some(&gate), &make_request(), 3000);
        assert!(result.ready);
        assert!(result.blockers.is_empty());
    }

    #[test]
    fn test_draft_model_blocked() {
        let checker = DeploymentReadinessChecker::new();
        let model = make_model(ModelStatus::Draft);
        let result = checker.check_readiness(&model, None, &make_request(), 3000);
        assert!(!result.ready);
        assert!(result.blockers.iter().any(|b| matches!(
            &b.blocker_type, DeploymentBlockerType::ModelNotApproved { .. }
        )));
    }

    #[test]
    fn test_failed_gate_blocked() {
        let checker = DeploymentReadinessChecker::new();
        let mut model = make_model(ModelStatus::Approved);
        model.attestation_ref = Some("att-1".into());
        model.training_data_refs.push("ds-1".into());
        let gate = make_failing_gate();
        let result = checker.check_readiness(&model, Some(&gate), &make_request(), 3000);
        assert!(!result.ready);
        assert!(result.blockers.iter().any(|b| matches!(
            &b.blocker_type, DeploymentBlockerType::EvaluationGateNotPassed { .. }
        )));
    }

    #[test]
    fn test_missing_attestation_warning() {
        let checker = DeploymentReadinessChecker::new();
        let mut model = make_model(ModelStatus::Approved);
        model.training_data_refs.push("ds-1".into());
        let gate = make_passing_gate();
        let result = checker.check_readiness(&model, Some(&gate), &make_request(), 3000);
        // Warnings don't block readiness
        assert!(result.ready);
        assert!(result.blockers.iter().any(|b| matches!(
            &b.blocker_type, DeploymentBlockerType::MissingAttestation
        )));
        assert!(result.blockers.iter().all(|b| b.severity == BlockerSeverity::Warning));
    }

    #[test]
    fn test_missing_training_data_warning() {
        let checker = DeploymentReadinessChecker::new();
        let mut model = make_model(ModelStatus::Approved);
        model.attestation_ref = Some("att-1".into());
        let gate = make_passing_gate();
        let result = checker.check_readiness(&model, Some(&gate), &make_request(), 3000);
        assert!(result.ready);
        assert!(result.blockers.iter().any(|b| matches!(
            &b.blocker_type, DeploymentBlockerType::MissingTrainingDataRefs
        )));
    }

    #[test]
    fn test_multiple_blockers() {
        let checker = DeploymentReadinessChecker::new();
        let model = make_model(ModelStatus::Draft);
        let gate = make_failing_gate();
        let result = checker.check_readiness(&model, Some(&gate), &make_request(), 3000);
        assert!(!result.ready);
        // Should have: ModelNotApproved + EvaluationGateNotPassed + MissingAttestation + MissingTrainingDataRefs
        assert!(result.blockers.len() >= 4);
    }

    #[test]
    fn test_no_gate_evaluation_provided() {
        let checker = DeploymentReadinessChecker::new();
        let mut model = make_model(ModelStatus::Approved);
        model.attestation_ref = Some("att-1".into());
        model.training_data_refs.push("ds-1".into());
        let result = checker.check_readiness(&model, None, &make_request(), 3000);
        assert!(result.ready);
    }

    #[test]
    fn test_blocker_type_display() {
        let bt = DeploymentBlockerType::ModelNotApproved { current_status: "Draft".into() };
        assert!(bt.to_string().contains("Draft"));
        let bt2 = DeploymentBlockerType::MissingAttestation;
        assert!(!bt2.to_string().is_empty());
    }

    #[test]
    fn test_blocker_severity_display() {
        assert_eq!(BlockerSeverity::Critical.to_string(), "Critical");
        assert_eq!(BlockerSeverity::Warning.to_string(), "Warning");
        assert_eq!(BlockerSeverity::Advisory.to_string(), "Advisory");
    }

    #[test]
    fn test_checker_default() {
        let _checker = DeploymentReadinessChecker;
    }
}
