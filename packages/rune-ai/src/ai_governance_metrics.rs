// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — AI governance metrics collector trait. Named
// ai_governance_metrics.rs to avoid collision with L2 ai_metrics.rs.
// Computes model approval rate, evaluation gate pass rate, deployment
// success rate, fairness compliance rate, drift detection rate, and
// model retirement rate. Reference implementations:
// InMemoryAiGovernanceMetricsCollector, NullAiGovernanceMetricsCollector.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::backend::{
    StoredDeploymentRecord, StoredDriftResult, StoredFairnessAssessment, StoredModelRecord,
};
use crate::bias_fairness::FairnessStatus;
use crate::deployment::DeploymentStatus;
use crate::drift::DriftStatus;
use crate::model_registry::ModelStatus;

// ── AiGovernanceMetricSnapshot ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiGovernanceMetricSnapshot {
    pub snapshot_id: String,
    pub computed_at: i64,
    pub model_approval_rate: String,
    pub evaluation_gate_pass_rate: String,
    pub deployment_success_rate: String,
    pub fairness_compliance_rate: String,
    pub drift_detection_rate: String,
    pub model_retirement_rate: String,
    pub total_models: String,
    pub total_deployments: String,
    pub metadata: HashMap<String, String>,
}

// ── AiGovernanceMetricsCollector trait ──────────────────────────────

pub trait AiGovernanceMetricsCollector {
    fn compute_model_approval_rate(&self, models: &[StoredModelRecord]) -> String;
    fn compute_evaluation_gate_pass_rate(&self, models: &[StoredModelRecord]) -> String;
    fn compute_deployment_success_rate(&self, deployments: &[StoredDeploymentRecord]) -> String;
    fn compute_fairness_compliance_rate(&self, assessments: &[StoredFairnessAssessment]) -> String;
    fn compute_drift_detection_rate(&self, results: &[StoredDriftResult]) -> String;
    fn compute_model_retirement_rate(&self, models: &[StoredModelRecord]) -> String;
    fn list_models_by_deployment_count(
        &self,
        models: &[StoredModelRecord],
        limit: usize,
    ) -> Vec<(String, String)>;
    fn collector_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryAiGovernanceMetricsCollector ───────────────────────────

pub struct InMemoryAiGovernanceMetricsCollector {
    collector_id: String,
    active: bool,
}

impl InMemoryAiGovernanceMetricsCollector {
    pub fn new(collector_id: impl Into<String>) -> Self {
        Self {
            collector_id: collector_id.into(),
            active: true,
        }
    }
}

impl AiGovernanceMetricsCollector for InMemoryAiGovernanceMetricsCollector {
    fn compute_model_approval_rate(&self, models: &[StoredModelRecord]) -> String {
        if models.is_empty() {
            return "0.0000".to_string();
        }
        let approved = models
            .iter()
            .filter(|m| {
                matches!(
                    m.status,
                    ModelStatus::Approved | ModelStatus::Deployed
                )
            })
            .count();
        format!("{:.4}", approved as f64 / models.len() as f64)
    }

    fn compute_evaluation_gate_pass_rate(&self, models: &[StoredModelRecord]) -> String {
        if models.is_empty() {
            return "0.0000".to_string();
        }
        let evaluated = models
            .iter()
            .filter(|m| {
                m.evaluation_count.parse::<usize>().unwrap_or(0) > 0
            })
            .count();
        format!("{:.4}", evaluated as f64 / models.len() as f64)
    }

    fn compute_deployment_success_rate(&self, deployments: &[StoredDeploymentRecord]) -> String {
        if deployments.is_empty() {
            return "0.0000".to_string();
        }
        let active = deployments
            .iter()
            .filter(|d| matches!(d.status, DeploymentStatus::Active))
            .count();
        format!("{:.4}", active as f64 / deployments.len() as f64)
    }

    fn compute_fairness_compliance_rate(&self, assessments: &[StoredFairnessAssessment]) -> String {
        if assessments.is_empty() {
            return "0.0000".to_string();
        }
        let fair = assessments
            .iter()
            .filter(|a| matches!(a.overall_status, FairnessStatus::Fair))
            .count();
        format!("{:.4}", fair as f64 / assessments.len() as f64)
    }

    fn compute_drift_detection_rate(&self, results: &[StoredDriftResult]) -> String {
        if results.is_empty() {
            return "0.0000".to_string();
        }
        let drifted = results
            .iter()
            .filter(|r| !matches!(r.overall_status, DriftStatus::NoDrift))
            .count();
        format!("{:.4}", drifted as f64 / results.len() as f64)
    }

    fn compute_model_retirement_rate(&self, models: &[StoredModelRecord]) -> String {
        if models.is_empty() {
            return "0.0000".to_string();
        }
        let retired = models
            .iter()
            .filter(|m| {
                matches!(m.status, ModelStatus::Retired | ModelStatus::Deprecated)
            })
            .count();
        format!("{:.4}", retired as f64 / models.len() as f64)
    }

    fn list_models_by_deployment_count(
        &self,
        models: &[StoredModelRecord],
        limit: usize,
    ) -> Vec<(String, String)> {
        let mut entries: Vec<(String, String)> = models
            .iter()
            .map(|m| (m.model_id.clone(), m.deployment_count.clone()))
            .collect();
        entries.sort_by(|a, b| {
            let a_count = a.1.parse::<usize>().unwrap_or(0);
            let b_count = b.1.parse::<usize>().unwrap_or(0);
            b_count.cmp(&a_count)
        });
        entries.truncate(limit);
        entries
    }

    fn collector_id(&self) -> &str {
        &self.collector_id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullAiGovernanceMetricsCollector ───────────────────────────────

pub struct NullAiGovernanceMetricsCollector;

impl AiGovernanceMetricsCollector for NullAiGovernanceMetricsCollector {
    fn compute_model_approval_rate(&self, _models: &[StoredModelRecord]) -> String {
        "0.0000".to_string()
    }

    fn compute_evaluation_gate_pass_rate(&self, _models: &[StoredModelRecord]) -> String {
        "0.0000".to_string()
    }

    fn compute_deployment_success_rate(&self, _deployments: &[StoredDeploymentRecord]) -> String {
        "0.0000".to_string()
    }

    fn compute_fairness_compliance_rate(&self, _assessments: &[StoredFairnessAssessment]) -> String {
        "1.0000".to_string()
    }

    fn compute_drift_detection_rate(&self, _results: &[StoredDriftResult]) -> String {
        "0.0000".to_string()
    }

    fn compute_model_retirement_rate(&self, _models: &[StoredModelRecord]) -> String {
        "0.0000".to_string()
    }

    fn list_models_by_deployment_count(
        &self,
        _models: &[StoredModelRecord],
        _limit: usize,
    ) -> Vec<(String, String)> {
        Vec::new()
    }

    fn collector_id(&self) -> &str {
        "null-ai-governance-metrics"
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
    use crate::backend::{StoredDeploymentRecord, StoredDriftResult, StoredModelRecord};
    use crate::deployment::DeploymentEnvironment;
    use crate::model_registry::{ModelArchitecture, ModelRecord, ModelTaskType};

    fn make_stored_model(id: &str, status: ModelStatus) -> StoredModelRecord {
        let mut record = ModelRecord::new(
            id, "Model", "1.0.0",
            ModelArchitecture::Transformer, ModelTaskType::Classification,
            "pytorch", "alice", 1000,
        );
        record.status = status;
        StoredModelRecord::from_record(&record, 5000)
    }

    fn make_stored_deployment(id: &str, status: DeploymentStatus) -> StoredDeploymentRecord {
        let mut record = crate::deployment::DeploymentRecord::new(
            id, "req-1", "m-1", "1.0.0",
            DeploymentEnvironment::Production, 3000, "alice",
        );
        record.status = status;
        StoredDeploymentRecord::from_record(&record, 5000)
    }

    fn make_stored_assessment(id: &str, status: FairnessStatus) -> StoredFairnessAssessment {
        StoredFairnessAssessment {
            assessment_id: id.into(),
            policy_id: "fp-1".into(),
            model_id: "m-1".into(),
            model_version: "1.0.0".into(),
            overall_status: status,
            assessed_at: 4000,
            assessed_by: "alice".into(),
            metadata: Default::default(),
            stored_at: 5000,
        }
    }

    fn make_stored_drift(id: &str, status: DriftStatus) -> StoredDriftResult {
        StoredDriftResult {
            result_id: id.into(),
            policy_id: "dp-1".into(),
            model_id: "m-1".into(),
            model_version: "1.0.0".into(),
            overall_status: status,
            detected_at: 4000,
            detection_window_start: 3000,
            detection_window_end: 4000,
            metadata: Default::default(),
            stored_at: 5000,
            remediation_applied: None,
        }
    }

    #[test]
    fn test_model_approval_rate() {
        let collector = InMemoryAiGovernanceMetricsCollector::new("mc-1");
        let models = vec![
            make_stored_model("m-1", ModelStatus::Approved),
            make_stored_model("m-2", ModelStatus::Draft),
            make_stored_model("m-3", ModelStatus::Deployed),
            make_stored_model("m-4", ModelStatus::Registered),
        ];
        let rate = collector.compute_model_approval_rate(&models);
        assert_eq!(rate, "0.5000");
    }

    #[test]
    fn test_model_approval_rate_empty() {
        let collector = InMemoryAiGovernanceMetricsCollector::new("mc-1");
        assert_eq!(collector.compute_model_approval_rate(&[]), "0.0000");
    }

    #[test]
    fn test_deployment_success_rate() {
        let collector = InMemoryAiGovernanceMetricsCollector::new("mc-1");
        let deployments = vec![
            make_stored_deployment("d-1", DeploymentStatus::Active),
            make_stored_deployment("d-2", DeploymentStatus::RolledBack {
                rolled_back_at: 5000, reason: "regression".into(),
            }),
        ];
        let rate = collector.compute_deployment_success_rate(&deployments);
        assert_eq!(rate, "0.5000");
    }

    #[test]
    fn test_fairness_compliance_rate() {
        let collector = InMemoryAiGovernanceMetricsCollector::new("mc-1");
        let assessments = vec![
            make_stored_assessment("fa-1", FairnessStatus::Fair),
            make_stored_assessment("fa-2", FairnessStatus::Fair),
            make_stored_assessment("fa-3", FairnessStatus::Unfair {
                violations: vec!["v1".into()],
            }),
        ];
        let rate = collector.compute_fairness_compliance_rate(&assessments);
        assert_eq!(rate, "0.6667");
    }

    #[test]
    fn test_drift_detection_rate() {
        let collector = InMemoryAiGovernanceMetricsCollector::new("mc-1");
        let results = vec![
            make_stored_drift("dr-1", DriftStatus::NoDrift),
            make_stored_drift("dr-2", DriftStatus::MinorDrift { details: "low".into() }),
        ];
        let rate = collector.compute_drift_detection_rate(&results);
        assert_eq!(rate, "0.5000");
    }

    #[test]
    fn test_model_retirement_rate() {
        let collector = InMemoryAiGovernanceMetricsCollector::new("mc-1");
        let models = vec![
            make_stored_model("m-1", ModelStatus::Retired),
            make_stored_model("m-2", ModelStatus::Deprecated),
            make_stored_model("m-3", ModelStatus::Deployed),
        ];
        let rate = collector.compute_model_retirement_rate(&models);
        assert_eq!(rate, "0.6667");
    }

    #[test]
    fn test_list_models_by_deployment_count() {
        let collector = InMemoryAiGovernanceMetricsCollector::new("mc-1");
        let mut m1 = make_stored_model("m-1", ModelStatus::Deployed);
        m1.deployment_count = "5".into();
        let mut m2 = make_stored_model("m-2", ModelStatus::Deployed);
        m2.deployment_count = "10".into();
        let mut m3 = make_stored_model("m-3", ModelStatus::Deployed);
        m3.deployment_count = "3".into();
        let top = collector.list_models_by_deployment_count(&[m1, m2, m3], 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "m-2");
        assert_eq!(top[1].0, "m-1");
    }

    #[test]
    fn test_evaluation_gate_pass_rate() {
        let collector = InMemoryAiGovernanceMetricsCollector::new("mc-1");
        let mut m1 = make_stored_model("m-1", ModelStatus::Draft);
        m1.evaluation_count = "3".into();
        let m2 = make_stored_model("m-2", ModelStatus::Draft);
        let rate = collector.compute_evaluation_gate_pass_rate(&[m1, m2]);
        assert_eq!(rate, "0.5000");
    }

    #[test]
    fn test_collector_identity() {
        let collector = InMemoryAiGovernanceMetricsCollector::new("mc-1");
        assert_eq!(collector.collector_id(), "mc-1");
        assert!(collector.is_active());
    }

    #[test]
    fn test_null_collector() {
        let collector = NullAiGovernanceMetricsCollector;
        assert_eq!(collector.compute_model_approval_rate(&[]), "0.0000");
        assert_eq!(collector.compute_fairness_compliance_rate(&[]), "1.0000");
        assert!(!collector.is_active());
        assert_eq!(collector.collector_id(), "null-ai-governance-metrics");
    }

    #[test]
    fn test_snapshot_equality() {
        let s1 = AiGovernanceMetricSnapshot {
            snapshot_id: "snap-1".into(),
            computed_at: 5000,
            model_approval_rate: "0.5000".into(),
            evaluation_gate_pass_rate: "0.7500".into(),
            deployment_success_rate: "0.9000".into(),
            fairness_compliance_rate: "0.8000".into(),
            drift_detection_rate: "0.2000".into(),
            model_retirement_rate: "0.1000".into(),
            total_models: "10".into(),
            total_deployments: "5".into(),
            metadata: Default::default(),
        };
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_empty_inputs_default_rates() {
        let collector = InMemoryAiGovernanceMetricsCollector::new("mc-1");
        assert_eq!(collector.compute_deployment_success_rate(&[]), "0.0000");
        assert_eq!(collector.compute_fairness_compliance_rate(&[]), "0.0000");
        assert_eq!(collector.compute_drift_detection_rate(&[]), "0.0000");
        assert_eq!(collector.compute_model_retirement_rate(&[]), "0.0000");
    }
}
