// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — AI governance backend trait. Defines the pluggable storage
// contract for model records, datasets, evaluations, deployments,
// fairness assessments, drift results, lifecycle policies, and
// deprecation notices. Reference implementation: InMemoryAiGovernanceBackend.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::bias_fairness::FairnessAssessment;
use crate::deployment::{DeploymentRecord, DeploymentRequest, DeploymentStatus};
use crate::drift::DriftDetectionResult;
use crate::error::AiError;
use crate::evaluation::{EvaluationGate, EvaluationResult};
use crate::lifecycle::DeprecationNotice;
use crate::lifecycle::ModelLifecyclePolicy;
use crate::model_hash::{hash_dataset_record, hash_model_record};
use crate::model_registry::{ModelArchitecture, ModelRecord, ModelStatus};
use crate::training_data::{DataQualityStatus, DatasetRecord};

// ── Stored wrapper types ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredModelRecord {
    pub model_id: String,
    pub model_name: String,
    pub model_version: String,
    pub architecture: ModelArchitecture,
    pub task_type: crate::model_registry::ModelTaskType,
    pub framework: String,
    pub created_by: String,
    pub created_at: i64,
    pub status: ModelStatus,
    pub attestation_ref: Option<String>,
    pub training_data_refs: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
    pub last_evaluated_at: Option<i64>,
    pub evaluation_count: String,
    pub deployment_count: String,
    pub model_hash: String,
    pub active_deployment_ref: Option<String>,
}

impl StoredModelRecord {
    pub fn from_record(record: &ModelRecord, stored_at: i64) -> Self {
        let model_hash = hash_model_record(record);
        Self {
            model_id: record.model_id.clone(),
            model_name: record.model_name.clone(),
            model_version: record.model_version.clone(),
            architecture: record.architecture.clone(),
            task_type: record.task_type.clone(),
            framework: record.framework.clone(),
            created_by: record.created_by.clone(),
            created_at: record.created_at,
            status: record.status.clone(),
            attestation_ref: record.attestation_ref.clone(),
            training_data_refs: record.training_data_refs.clone(),
            metadata: record.metadata.clone(),
            stored_at,
            last_evaluated_at: None,
            evaluation_count: "0".to_string(),
            deployment_count: "0".to_string(),
            model_hash,
            active_deployment_ref: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDatasetRecord {
    pub dataset_id: String,
    pub dataset_name: String,
    pub version: String,
    pub source: crate::training_data::DatasetSource,
    pub format: crate::training_data::DatasetFormat,
    pub record_count: Option<String>,
    pub size_bytes: Option<String>,
    pub created_at: i64,
    pub created_by: String,
    pub quality_status: DataQualityStatus,
    pub sensitivity_label: Option<String>,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
    pub models_using: String,
    pub dataset_hash: String,
}

impl StoredDatasetRecord {
    pub fn from_record(record: &DatasetRecord, stored_at: i64) -> Self {
        let dataset_hash = hash_dataset_record(record);
        Self {
            dataset_id: record.dataset_id.clone(),
            dataset_name: record.dataset_name.clone(),
            version: record.version.clone(),
            source: record.source.clone(),
            format: record.format.clone(),
            record_count: record.record_count.clone(),
            size_bytes: record.size_bytes.clone(),
            created_at: record.created_at,
            created_by: record.created_by.clone(),
            quality_status: record.quality_status.clone(),
            sensitivity_label: record.sensitivity_label.clone(),
            metadata: record.metadata.clone(),
            stored_at,
            models_using: "0".to_string(),
            dataset_hash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvaluationResult {
    pub result_id: String,
    pub model_id: String,
    pub model_version: String,
    pub criteria_id: String,
    pub measured_value: String,
    pub passed: bool,
    pub evaluated_at: i64,
    pub evaluated_by: String,
    pub evidence_ref: Option<String>,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
}

impl StoredEvaluationResult {
    pub fn from_result(result: &EvaluationResult, stored_at: i64) -> Self {
        Self {
            result_id: result.result_id.clone(),
            model_id: result.model_id.clone(),
            model_version: result.model_version.clone(),
            criteria_id: result.criteria_id.clone(),
            measured_value: result.measured_value.clone(),
            passed: result.passed,
            evaluated_at: result.evaluated_at,
            evaluated_by: result.evaluated_by.clone(),
            evidence_ref: result.evidence_ref.clone(),
            metadata: result.metadata.clone(),
            stored_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDeploymentRecord {
    pub deployment_id: String,
    pub request_id: String,
    pub model_id: String,
    pub model_version: String,
    pub environment: crate::deployment::DeploymentEnvironment,
    pub deployed_at: i64,
    pub deployed_by: String,
    pub status: DeploymentStatus,
    pub predecessor_deployment_id: Option<String>,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
    pub health_check_count: String,
    pub last_health_check_at: Option<i64>,
}

impl StoredDeploymentRecord {
    pub fn from_record(record: &DeploymentRecord, stored_at: i64) -> Self {
        Self {
            deployment_id: record.deployment_id.clone(),
            request_id: record.request_id.clone(),
            model_id: record.model_id.clone(),
            model_version: record.model_version.clone(),
            environment: record.environment.clone(),
            deployed_at: record.deployed_at,
            deployed_by: record.deployed_by.clone(),
            status: record.status.clone(),
            predecessor_deployment_id: record.predecessor_deployment_id.clone(),
            metadata: record.metadata.clone(),
            stored_at,
            health_check_count: "0".to_string(),
            last_health_check_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFairnessAssessment {
    pub assessment_id: String,
    pub policy_id: String,
    pub model_id: String,
    pub model_version: String,
    pub overall_status: crate::bias_fairness::FairnessStatus,
    pub assessed_at: i64,
    pub assessed_by: String,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
}

impl StoredFairnessAssessment {
    pub fn from_assessment(assessment: &FairnessAssessment, stored_at: i64) -> Self {
        Self {
            assessment_id: assessment.assessment_id.clone(),
            policy_id: assessment.policy_id.clone(),
            model_id: assessment.model_id.clone(),
            model_version: assessment.model_version.clone(),
            overall_status: assessment.overall_status.clone(),
            assessed_at: assessment.assessed_at,
            assessed_by: assessment.assessed_by.clone(),
            metadata: assessment.metadata.clone(),
            stored_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDriftResult {
    pub result_id: String,
    pub policy_id: String,
    pub model_id: String,
    pub model_version: String,
    pub overall_status: crate::drift::DriftStatus,
    pub detected_at: i64,
    pub detection_window_start: i64,
    pub detection_window_end: i64,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
    pub remediation_applied: Option<String>,
}

impl StoredDriftResult {
    pub fn from_result(result: &DriftDetectionResult, stored_at: i64) -> Self {
        Self {
            result_id: result.result_id.clone(),
            policy_id: result.policy_id.clone(),
            model_id: result.model_id.clone(),
            model_version: result.model_version.clone(),
            overall_status: result.overall_status.clone(),
            detected_at: result.detected_at,
            detection_window_start: result.detection_window_start,
            detection_window_end: result.detection_window_end,
            metadata: result.metadata.clone(),
            stored_at,
            remediation_applied: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDeprecationNotice {
    pub notice_id: String,
    pub model_id: String,
    pub model_version: String,
    pub issued_at: i64,
    pub sunset_date: Option<i64>,
    pub replacement_model_ref: Option<String>,
    pub reason: String,
    pub severity: crate::lifecycle::DeprecationSeverity,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
    pub acknowledged_count: String,
}

impl StoredDeprecationNotice {
    pub fn from_notice(notice: &DeprecationNotice, stored_at: i64) -> Self {
        Self {
            notice_id: notice.notice_id.clone(),
            model_id: notice.model_id.clone(),
            model_version: notice.model_version.clone(),
            issued_at: notice.issued_at,
            sunset_date: notice.sunset_date,
            replacement_model_ref: notice.replacement_model_ref.clone(),
            reason: notice.reason.clone(),
            severity: notice.severity.clone(),
            metadata: notice.metadata.clone(),
            stored_at,
            acknowledged_count: notice.acknowledged_by.len().to_string(),
        }
    }
}

// ── AiBackendInfo ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiBackendInfo {
    pub backend_id: String,
    pub backend_type: String,
    pub model_count: String,
    pub dataset_count: String,
    pub evaluation_count: String,
    pub deployment_count: String,
    pub assessment_count: String,
}

// ── AiGovernanceBackend trait ───────────────────────────────────────

pub trait AiGovernanceBackend {
    fn store_model_record(&mut self, record: &ModelRecord, stored_at: i64) -> Result<(), AiError>;
    fn retrieve_model_record(&self, model_id: &str) -> Result<StoredModelRecord, AiError>;
    fn delete_model_record(&mut self, model_id: &str) -> Result<(), AiError>;
    fn list_models_by_status(&self, status: &ModelStatus) -> Vec<StoredModelRecord>;
    fn list_models_by_architecture(&self, arch: &ModelArchitecture) -> Vec<StoredModelRecord>;
    fn model_count(&self) -> usize;

    fn store_dataset_record(&mut self, record: &DatasetRecord, stored_at: i64) -> Result<(), AiError>;
    fn retrieve_dataset_record(&self, dataset_id: &str) -> Result<StoredDatasetRecord, AiError>;
    fn list_datasets_by_quality(&self, status: &DataQualityStatus) -> Vec<StoredDatasetRecord>;
    fn dataset_count(&self) -> usize;

    fn store_evaluation_result(&mut self, result: &EvaluationResult, stored_at: i64) -> Result<(), AiError>;
    fn retrieve_evaluation_result(&self, result_id: &str) -> Result<StoredEvaluationResult, AiError>;
    fn list_evaluations_by_model(&self, model_id: &str) -> Vec<StoredEvaluationResult>;

    fn store_evaluation_gate(&mut self, gate: &EvaluationGate, stored_at: i64) -> Result<(), AiError>;
    fn retrieve_evaluation_gate(&self, gate_id: &str) -> Result<EvaluationGate, AiError>;

    fn store_deployment_request(&mut self, request: &DeploymentRequest, stored_at: i64) -> Result<(), AiError>;
    fn retrieve_deployment_request(&self, request_id: &str) -> Result<DeploymentRequest, AiError>;
    fn list_deployments_by_model(&self, model_id: &str) -> Vec<StoredDeploymentRecord>;

    fn store_deployment_record(&mut self, record: &DeploymentRecord, stored_at: i64) -> Result<(), AiError>;
    fn retrieve_deployment_record(&self, deployment_id: &str) -> Result<StoredDeploymentRecord, AiError>;
    fn list_active_deployments(&self) -> Vec<StoredDeploymentRecord>;

    fn store_fairness_policy(&mut self, policy: &crate::bias_fairness::FairnessPolicy, stored_at: i64) -> Result<(), AiError>;
    fn retrieve_fairness_policy(&self, policy_id: &str) -> Result<crate::bias_fairness::FairnessPolicy, AiError>;
    fn store_fairness_assessment(&mut self, assessment: &FairnessAssessment, stored_at: i64) -> Result<(), AiError>;
    fn list_assessments_by_model(&self, model_id: &str) -> Vec<StoredFairnessAssessment>;

    fn store_drift_policy(&mut self, policy: &crate::drift::DriftPolicy, stored_at: i64) -> Result<(), AiError>;
    fn retrieve_drift_policy(&self, policy_id: &str) -> Result<crate::drift::DriftPolicy, AiError>;
    fn store_drift_result(&mut self, result: &DriftDetectionResult, stored_at: i64) -> Result<(), AiError>;
    fn list_drift_results_by_model(&self, model_id: &str) -> Vec<StoredDriftResult>;

    fn store_lifecycle_policy(&mut self, policy: &ModelLifecyclePolicy, stored_at: i64) -> Result<(), AiError>;
    fn retrieve_lifecycle_policy(&self, policy_id: &str) -> Result<ModelLifecyclePolicy, AiError>;
    fn store_deprecation_notice(&mut self, notice: &DeprecationNotice, stored_at: i64) -> Result<(), AiError>;
    fn list_deprecation_notices_by_model(&self, model_id: &str) -> Vec<StoredDeprecationNotice>;

    fn flush(&mut self);
    fn backend_info(&self) -> AiBackendInfo;
}

// ── InMemoryAiGovernanceBackend ────────────────────────────────────

pub struct InMemoryAiGovernanceBackend {
    backend_id: String,
    models: HashMap<String, StoredModelRecord>,
    datasets: HashMap<String, StoredDatasetRecord>,
    evaluation_results: HashMap<String, StoredEvaluationResult>,
    evaluation_gates: HashMap<String, EvaluationGate>,
    deployment_requests: HashMap<String, DeploymentRequest>,
    deployment_records: HashMap<String, StoredDeploymentRecord>,
    fairness_policies: HashMap<String, crate::bias_fairness::FairnessPolicy>,
    fairness_assessments: HashMap<String, StoredFairnessAssessment>,
    drift_policies: HashMap<String, crate::drift::DriftPolicy>,
    drift_results: HashMap<String, StoredDriftResult>,
    lifecycle_policies: HashMap<String, ModelLifecyclePolicy>,
    deprecation_notices: HashMap<String, StoredDeprecationNotice>,
}

impl InMemoryAiGovernanceBackend {
    pub fn new(backend_id: impl Into<String>) -> Self {
        Self {
            backend_id: backend_id.into(),
            models: HashMap::new(),
            datasets: HashMap::new(),
            evaluation_results: HashMap::new(),
            evaluation_gates: HashMap::new(),
            deployment_requests: HashMap::new(),
            deployment_records: HashMap::new(),
            fairness_policies: HashMap::new(),
            fairness_assessments: HashMap::new(),
            drift_policies: HashMap::new(),
            drift_results: HashMap::new(),
            lifecycle_policies: HashMap::new(),
            deprecation_notices: HashMap::new(),
        }
    }
}

impl AiGovernanceBackend for InMemoryAiGovernanceBackend {
    fn store_model_record(&mut self, record: &ModelRecord, stored_at: i64) -> Result<(), AiError> {
        let stored = StoredModelRecord::from_record(record, stored_at);
        self.models.insert(record.model_id.clone(), stored);
        Ok(())
    }

    fn retrieve_model_record(&self, model_id: &str) -> Result<StoredModelRecord, AiError> {
        self.models
            .get(model_id)
            .cloned()
            .ok_or_else(|| AiError::ModelNotFound(model_id.to_string()))
    }

    fn delete_model_record(&mut self, model_id: &str) -> Result<(), AiError> {
        self.models
            .remove(model_id)
            .map(|_| ())
            .ok_or_else(|| AiError::ModelNotFound(model_id.to_string()))
    }

    fn list_models_by_status(&self, status: &ModelStatus) -> Vec<StoredModelRecord> {
        self.models
            .values()
            .filter(|m| &m.status == status)
            .cloned()
            .collect()
    }

    fn list_models_by_architecture(&self, arch: &ModelArchitecture) -> Vec<StoredModelRecord> {
        self.models
            .values()
            .filter(|m| &m.architecture == arch)
            .cloned()
            .collect()
    }

    fn model_count(&self) -> usize {
        self.models.len()
    }

    fn store_dataset_record(&mut self, record: &DatasetRecord, stored_at: i64) -> Result<(), AiError> {
        let stored = StoredDatasetRecord::from_record(record, stored_at);
        self.datasets.insert(record.dataset_id.clone(), stored);
        Ok(())
    }

    fn retrieve_dataset_record(&self, dataset_id: &str) -> Result<StoredDatasetRecord, AiError> {
        self.datasets
            .get(dataset_id)
            .cloned()
            .ok_or_else(|| AiError::DatasetNotFound(dataset_id.to_string()))
    }

    fn list_datasets_by_quality(&self, status: &DataQualityStatus) -> Vec<StoredDatasetRecord> {
        self.datasets
            .values()
            .filter(|d| &d.quality_status == status)
            .cloned()
            .collect()
    }

    fn dataset_count(&self) -> usize {
        self.datasets.len()
    }

    fn store_evaluation_result(&mut self, result: &EvaluationResult, stored_at: i64) -> Result<(), AiError> {
        let stored = StoredEvaluationResult::from_result(result, stored_at);
        self.evaluation_results.insert(result.result_id.clone(), stored);
        Ok(())
    }

    fn retrieve_evaluation_result(&self, result_id: &str) -> Result<StoredEvaluationResult, AiError> {
        self.evaluation_results
            .get(result_id)
            .cloned()
            .ok_or_else(|| AiError::EvaluationNotFound(result_id.to_string()))
    }

    fn list_evaluations_by_model(&self, model_id: &str) -> Vec<StoredEvaluationResult> {
        self.evaluation_results
            .values()
            .filter(|e| e.model_id == model_id)
            .cloned()
            .collect()
    }

    fn store_evaluation_gate(&mut self, gate: &EvaluationGate, _stored_at: i64) -> Result<(), AiError> {
        self.evaluation_gates.insert(gate.gate_id.clone(), gate.clone());
        Ok(())
    }

    fn retrieve_evaluation_gate(&self, gate_id: &str) -> Result<EvaluationGate, AiError> {
        self.evaluation_gates
            .get(gate_id)
            .cloned()
            .ok_or_else(|| AiError::EvaluationNotFound(gate_id.to_string()))
    }

    fn store_deployment_request(&mut self, request: &DeploymentRequest, _stored_at: i64) -> Result<(), AiError> {
        self.deployment_requests.insert(request.request_id.clone(), request.clone());
        Ok(())
    }

    fn retrieve_deployment_request(&self, request_id: &str) -> Result<DeploymentRequest, AiError> {
        self.deployment_requests
            .get(request_id)
            .cloned()
            .ok_or_else(|| AiError::DeploymentNotFound(request_id.to_string()))
    }

    fn list_deployments_by_model(&self, model_id: &str) -> Vec<StoredDeploymentRecord> {
        self.deployment_records
            .values()
            .filter(|d| d.model_id == model_id)
            .cloned()
            .collect()
    }

    fn store_deployment_record(&mut self, record: &DeploymentRecord, stored_at: i64) -> Result<(), AiError> {
        let stored = StoredDeploymentRecord::from_record(record, stored_at);
        self.deployment_records.insert(record.deployment_id.clone(), stored);
        Ok(())
    }

    fn retrieve_deployment_record(&self, deployment_id: &str) -> Result<StoredDeploymentRecord, AiError> {
        self.deployment_records
            .get(deployment_id)
            .cloned()
            .ok_or_else(|| AiError::DeploymentNotFound(deployment_id.to_string()))
    }

    fn list_active_deployments(&self) -> Vec<StoredDeploymentRecord> {
        self.deployment_records
            .values()
            .filter(|d| matches!(d.status, DeploymentStatus::Active))
            .cloned()
            .collect()
    }

    fn store_fairness_policy(&mut self, policy: &crate::bias_fairness::FairnessPolicy, _stored_at: i64) -> Result<(), AiError> {
        self.fairness_policies.insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn retrieve_fairness_policy(&self, policy_id: &str) -> Result<crate::bias_fairness::FairnessPolicy, AiError> {
        self.fairness_policies
            .get(policy_id)
            .cloned()
            .ok_or_else(|| AiError::InvalidOperation(format!("Fairness policy not found: {policy_id}")))
    }

    fn store_fairness_assessment(&mut self, assessment: &FairnessAssessment, stored_at: i64) -> Result<(), AiError> {
        let stored = StoredFairnessAssessment::from_assessment(assessment, stored_at);
        self.fairness_assessments.insert(assessment.assessment_id.clone(), stored);
        Ok(())
    }

    fn list_assessments_by_model(&self, model_id: &str) -> Vec<StoredFairnessAssessment> {
        self.fairness_assessments
            .values()
            .filter(|a| a.model_id == model_id)
            .cloned()
            .collect()
    }

    fn store_drift_policy(&mut self, policy: &crate::drift::DriftPolicy, _stored_at: i64) -> Result<(), AiError> {
        self.drift_policies.insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn retrieve_drift_policy(&self, policy_id: &str) -> Result<crate::drift::DriftPolicy, AiError> {
        self.drift_policies
            .get(policy_id)
            .cloned()
            .ok_or_else(|| AiError::InvalidOperation(format!("Drift policy not found: {policy_id}")))
    }

    fn store_drift_result(&mut self, result: &DriftDetectionResult, stored_at: i64) -> Result<(), AiError> {
        let stored = StoredDriftResult::from_result(result, stored_at);
        self.drift_results.insert(result.result_id.clone(), stored);
        Ok(())
    }

    fn list_drift_results_by_model(&self, model_id: &str) -> Vec<StoredDriftResult> {
        self.drift_results
            .values()
            .filter(|d| d.model_id == model_id)
            .cloned()
            .collect()
    }

    fn store_lifecycle_policy(&mut self, policy: &ModelLifecyclePolicy, _stored_at: i64) -> Result<(), AiError> {
        self.lifecycle_policies.insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn retrieve_lifecycle_policy(&self, policy_id: &str) -> Result<ModelLifecyclePolicy, AiError> {
        self.lifecycle_policies
            .get(policy_id)
            .cloned()
            .ok_or_else(|| AiError::InvalidOperation(format!("Lifecycle policy not found: {policy_id}")))
    }

    fn store_deprecation_notice(&mut self, notice: &DeprecationNotice, stored_at: i64) -> Result<(), AiError> {
        let stored = StoredDeprecationNotice::from_notice(notice, stored_at);
        self.deprecation_notices.insert(notice.notice_id.clone(), stored);
        Ok(())
    }

    fn list_deprecation_notices_by_model(&self, model_id: &str) -> Vec<StoredDeprecationNotice> {
        self.deprecation_notices
            .values()
            .filter(|n| n.model_id == model_id)
            .cloned()
            .collect()
    }

    fn flush(&mut self) {
        self.models.clear();
        self.datasets.clear();
        self.evaluation_results.clear();
        self.evaluation_gates.clear();
        self.deployment_requests.clear();
        self.deployment_records.clear();
        self.fairness_policies.clear();
        self.fairness_assessments.clear();
        self.drift_policies.clear();
        self.drift_results.clear();
        self.lifecycle_policies.clear();
        self.deprecation_notices.clear();
    }

    fn backend_info(&self) -> AiBackendInfo {
        AiBackendInfo {
            backend_id: self.backend_id.clone(),
            backend_type: "InMemory".to_string(),
            model_count: self.models.len().to_string(),
            dataset_count: self.datasets.len().to_string(),
            evaluation_count: self.evaluation_results.len().to_string(),
            deployment_count: self.deployment_records.len().to_string(),
            assessment_count: self.fairness_assessments.len().to_string(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bias_fairness::{FairnessPolicy, FairnessStatus, MonitoringFrequency};
    use crate::deployment::DeploymentEnvironment;
    use crate::drift::{DriftDetectionWindow, DriftPolicy, DriftStatus};
    use crate::lifecycle::{DeprecationSeverity, RetirementAction};
    use crate::model_registry::{ModelArchitecture, ModelTaskType};

    fn make_model(id: &str, status: ModelStatus) -> ModelRecord {
        let mut r = ModelRecord::new(
            id, "TestModel", "1.0.0",
            ModelArchitecture::Transformer,
            ModelTaskType::Classification,
            "pytorch", "alice", 1000,
        );
        r.status = status;
        r
    }

    fn make_dataset(id: &str) -> DatasetRecord {
        DatasetRecord::new(
            id, "TestDataset", "1.0",
            crate::training_data::DatasetSource::Internal { team: "ml".into() },
            crate::training_data::DatasetFormat::Csv,
            1000, "alice",
        )
    }

    fn make_eval_result(id: &str, model_id: &str) -> EvaluationResult {
        EvaluationResult::new(id, model_id, "1.0.0", "ec-1", "0.95", true, 2000, "alice")
    }

    fn make_deployment(id: &str, model_id: &str) -> DeploymentRecord {
        DeploymentRecord::new(
            id, "req-1", model_id, "1.0.0",
            DeploymentEnvironment::Production, 3000, "alice",
        )
    }

    #[test]
    fn test_store_and_retrieve_model() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        let model = make_model("m-1", ModelStatus::Draft);
        assert!(backend.store_model_record(&model, 5000).is_ok());
        let stored = backend.retrieve_model_record("m-1").unwrap();
        assert_eq!(stored.model_id, "m-1");
        assert_eq!(stored.stored_at, 5000);
        assert!(!stored.model_hash.is_empty());
        assert_eq!(stored.evaluation_count, "0");
        assert_eq!(stored.deployment_count, "0");
    }

    #[test]
    fn test_retrieve_nonexistent_model() {
        let backend = InMemoryAiGovernanceBackend::new("test-backend");
        assert!(backend.retrieve_model_record("missing").is_err());
    }

    #[test]
    fn test_delete_model() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        let model = make_model("m-1", ModelStatus::Draft);
        backend.store_model_record(&model, 5000).unwrap();
        assert!(backend.delete_model_record("m-1").is_ok());
        assert_eq!(backend.model_count(), 0);
    }

    #[test]
    fn test_delete_nonexistent_model() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        assert!(backend.delete_model_record("missing").is_err());
    }

    #[test]
    fn test_list_models_by_status() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        backend.store_model_record(&make_model("m-1", ModelStatus::Draft), 5000).unwrap();
        backend.store_model_record(&make_model("m-2", ModelStatus::Approved), 5000).unwrap();
        backend.store_model_record(&make_model("m-3", ModelStatus::Draft), 5000).unwrap();
        assert_eq!(backend.list_models_by_status(&ModelStatus::Draft).len(), 2);
        assert_eq!(backend.list_models_by_status(&ModelStatus::Approved).len(), 1);
    }

    #[test]
    fn test_list_models_by_architecture() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        backend.store_model_record(&make_model("m-1", ModelStatus::Draft), 5000).unwrap();
        assert_eq!(backend.list_models_by_architecture(&ModelArchitecture::Transformer).len(), 1);
        assert_eq!(backend.list_models_by_architecture(&ModelArchitecture::Cnn).len(), 0);
    }

    #[test]
    fn test_store_and_retrieve_dataset() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        let ds = make_dataset("ds-1");
        backend.store_dataset_record(&ds, 5000).unwrap();
        let stored = backend.retrieve_dataset_record("ds-1").unwrap();
        assert_eq!(stored.dataset_id, "ds-1");
        assert!(!stored.dataset_hash.is_empty());
        assert_eq!(stored.models_using, "0");
    }

    #[test]
    fn test_list_datasets_by_quality() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        backend.store_dataset_record(&make_dataset("ds-1"), 5000).unwrap();
        assert_eq!(backend.list_datasets_by_quality(&DataQualityStatus::Unknown).len(), 1);
        assert_eq!(backend.list_datasets_by_quality(&DataQualityStatus::Validated).len(), 0);
    }

    #[test]
    fn test_store_and_retrieve_evaluation_result() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        let result = make_eval_result("er-1", "m-1");
        backend.store_evaluation_result(&result, 5000).unwrap();
        let stored = backend.retrieve_evaluation_result("er-1").unwrap();
        assert_eq!(stored.result_id, "er-1");
        assert_eq!(stored.stored_at, 5000);
    }

    #[test]
    fn test_list_evaluations_by_model() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        backend.store_evaluation_result(&make_eval_result("er-1", "m-1"), 5000).unwrap();
        backend.store_evaluation_result(&make_eval_result("er-2", "m-1"), 5000).unwrap();
        backend.store_evaluation_result(&make_eval_result("er-3", "m-2"), 5000).unwrap();
        assert_eq!(backend.list_evaluations_by_model("m-1").len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_deployment() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        let dep = make_deployment("d-1", "m-1");
        backend.store_deployment_record(&dep, 5000).unwrap();
        let stored = backend.retrieve_deployment_record("d-1").unwrap();
        assert_eq!(stored.deployment_id, "d-1");
        assert_eq!(stored.health_check_count, "0");
    }

    #[test]
    fn test_list_active_deployments() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        backend.store_deployment_record(&make_deployment("d-1", "m-1"), 5000).unwrap();
        assert_eq!(backend.list_active_deployments().len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_evaluation_gate() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        let gate = EvaluationGate::new("g-1", "m-1", vec!["ec-1".into()], 1000);
        backend.store_evaluation_gate(&gate, 5000).unwrap();
        let stored = backend.retrieve_evaluation_gate("g-1").unwrap();
        assert_eq!(stored.gate_id, "g-1");
    }

    #[test]
    fn test_store_and_retrieve_deployment_request() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        let req = DeploymentRequest::new(
            "req-1", "m-1", "1.0.0", DeploymentEnvironment::Production,
            "alice", 1000, crate::deployment::RollbackPolicy::Manual,
        );
        backend.store_deployment_request(&req, 5000).unwrap();
        let stored = backend.retrieve_deployment_request("req-1").unwrap();
        assert_eq!(stored.request_id, "req-1");
    }

    #[test]
    fn test_store_fairness_policy_and_assessment() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        let policy = FairnessPolicy::new("fp-1", "m-1", MonitoringFrequency::Daily, 1000);
        backend.store_fairness_policy(&policy, 5000).unwrap();
        let stored_policy = backend.retrieve_fairness_policy("fp-1").unwrap();
        assert_eq!(stored_policy.policy_id, "fp-1");

        let assessment = FairnessAssessment::new(
            "fa-1", "fp-1", "m-1", "1.0.0", FairnessStatus::Fair, 2000, "alice",
        );
        backend.store_fairness_assessment(&assessment, 5000).unwrap();
        assert_eq!(backend.list_assessments_by_model("m-1").len(), 1);
    }

    #[test]
    fn test_store_drift_policy_and_result() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        let policy = DriftPolicy::new("dp-1", "m-1", DriftDetectionWindow::Expanding, 1000);
        backend.store_drift_policy(&policy, 5000).unwrap();
        let stored = backend.retrieve_drift_policy("dp-1").unwrap();
        assert_eq!(stored.policy_id, "dp-1");

        let result = DriftDetectionResult::new(
            "dr-1", "dp-1", "m-1", "1.0.0", DriftStatus::NoDrift, 3000, 2000, 3000,
        );
        backend.store_drift_result(&result, 5000).unwrap();
        assert_eq!(backend.list_drift_results_by_model("m-1").len(), 1);
    }

    #[test]
    fn test_store_lifecycle_policy_and_deprecation_notice() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        let policy = ModelLifecyclePolicy::new("mlp-1", "m-1", RetirementAction::Archive, 1000);
        backend.store_lifecycle_policy(&policy, 5000).unwrap();
        let stored = backend.retrieve_lifecycle_policy("mlp-1").unwrap();
        assert_eq!(stored.policy_id, "mlp-1");

        let notice = DeprecationNotice::new(
            "dn-1", "m-1", "1.0.0", 3000, "sunset", DeprecationSeverity::Warning,
        );
        backend.store_deprecation_notice(&notice, 5000).unwrap();
        assert_eq!(backend.list_deprecation_notices_by_model("m-1").len(), 1);
    }

    #[test]
    fn test_flush_clears_all() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        backend.store_model_record(&make_model("m-1", ModelStatus::Draft), 5000).unwrap();
        backend.store_dataset_record(&make_dataset("ds-1"), 5000).unwrap();
        assert_eq!(backend.model_count(), 1);
        assert_eq!(backend.dataset_count(), 1);
        backend.flush();
        assert_eq!(backend.model_count(), 0);
        assert_eq!(backend.dataset_count(), 0);
    }

    #[test]
    fn test_backend_info() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        backend.store_model_record(&make_model("m-1", ModelStatus::Draft), 5000).unwrap();
        let info = backend.backend_info();
        assert_eq!(info.backend_id, "test-backend");
        assert_eq!(info.backend_type, "InMemory");
        assert_eq!(info.model_count, "1");
    }

    #[test]
    fn test_stored_model_hash_computed_at_storage() {
        let model = make_model("m-1", ModelStatus::Draft);
        let stored = StoredModelRecord::from_record(&model, 5000);
        assert!(!stored.model_hash.is_empty());
        assert_eq!(stored.model_hash.len(), 64);
    }

    #[test]
    fn test_stored_dataset_hash_computed_at_storage() {
        let ds = make_dataset("ds-1");
        let stored = StoredDatasetRecord::from_record(&ds, 5000);
        assert!(!stored.dataset_hash.is_empty());
        assert_eq!(stored.dataset_hash.len(), 64);
    }

    #[test]
    fn test_stored_deprecation_notice_acknowledged_count() {
        let mut notice = DeprecationNotice::new(
            "dn-1", "m-1", "1.0.0", 3000, "sunset", DeprecationSeverity::Warning,
        );
        notice.acknowledged_by.push("alice".into());
        notice.acknowledged_by.push("bob".into());
        let stored = StoredDeprecationNotice::from_notice(&notice, 5000);
        assert_eq!(stored.acknowledged_count, "2");
    }

    #[test]
    fn test_list_deployments_by_model() {
        let mut backend = InMemoryAiGovernanceBackend::new("test-backend");
        backend.store_deployment_record(&make_deployment("d-1", "m-1"), 5000).unwrap();
        backend.store_deployment_record(&make_deployment("d-2", "m-2"), 5000).unwrap();
        assert_eq!(backend.list_deployments_by_model("m-1").len(), 1);
        assert_eq!(backend.list_deployments_by_model("m-3").len(), 0);
    }
}
