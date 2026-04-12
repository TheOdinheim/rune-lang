// ═══════════════════════════════════════════════════════════════════════
// Model — ML model provenance: training, evaluation, deployment history.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;
use crate::error::ProvenanceError;

// ── ModelProvenanceId ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModelProvenanceId(pub String);

impl ModelProvenanceId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for ModelProvenanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ModelArchitecture ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModelArchitecture {
    pub architecture_type: String,
    pub parameter_count: Option<u64>,
    pub layer_count: Option<u32>,
    pub context_length: Option<u64>,
    pub input_format: Option<String>,
    pub output_format: Option<String>,
    pub quantization: Option<String>,
}

impl ModelArchitecture {
    pub fn new(architecture_type: impl Into<String>) -> Self {
        Self {
            architecture_type: architecture_type.into(),
            parameter_count: None,
            layer_count: None,
            context_length: None,
            input_format: None,
            output_format: None,
            quantization: None,
        }
    }

    pub fn with_parameters(mut self, count: u64) -> Self {
        self.parameter_count = Some(count);
        self
    }

    pub fn with_layers(mut self, count: u32) -> Self {
        self.layer_count = Some(count);
        self
    }

    pub fn with_context_length(mut self, len: u64) -> Self {
        self.context_length = Some(len);
        self
    }

    pub fn with_quantization(mut self, q: impl Into<String>) -> Self {
        self.quantization = Some(q.into());
        self
    }
}

// ── TrainingRecord ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrainingRecord {
    pub dataset_artifacts: Vec<ArtifactId>,
    pub validation_artifacts: Vec<ArtifactId>,
    pub hyperparameters: HashMap<String, String>,
    pub training_started: i64,
    pub training_completed: Option<i64>,
    pub training_duration_hours: Option<f64>,
    pub compute_resources: Option<String>,
    pub framework: String,
    pub final_loss: Option<f64>,
    pub checkpoints: Vec<ArtifactId>,
    pub reproducibility_hash: Option<String>,
}

impl TrainingRecord {
    pub fn new(
        framework: impl Into<String>,
        training_started: i64,
    ) -> Self {
        Self {
            dataset_artifacts: Vec::new(),
            validation_artifacts: Vec::new(),
            hyperparameters: HashMap::new(),
            training_started,
            training_completed: None,
            training_duration_hours: None,
            compute_resources: None,
            framework: framework.into(),
            final_loss: None,
            checkpoints: Vec::new(),
            reproducibility_hash: None,
        }
    }

    pub fn with_dataset(mut self, a: ArtifactId) -> Self {
        self.dataset_artifacts.push(a);
        self
    }

    pub fn with_hyperparameter(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.hyperparameters.insert(k.into(), v.into());
        self
    }

    pub fn completed(mut self, at: i64, hours: f64) -> Self {
        self.training_completed = Some(at);
        self.training_duration_hours = Some(hours);
        self
    }

    pub fn with_final_loss(mut self, loss: f64) -> Self {
        self.final_loss = Some(loss);
        self
    }
}

// ── EvaluationRecord ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EvaluationRecord {
    pub evaluation_id: String,
    pub benchmark: String,
    pub dataset_artifact: Option<ArtifactId>,
    pub metrics: HashMap<String, f64>,
    pub evaluated_at: i64,
    pub evaluated_by: String,
    pub methodology: Option<String>,
}

impl EvaluationRecord {
    pub fn new(
        evaluation_id: impl Into<String>,
        benchmark: impl Into<String>,
        evaluated_by: impl Into<String>,
        evaluated_at: i64,
    ) -> Self {
        Self {
            evaluation_id: evaluation_id.into(),
            benchmark: benchmark.into(),
            dataset_artifact: None,
            metrics: HashMap::new(),
            evaluated_at,
            evaluated_by: evaluated_by.into(),
            methodology: None,
        }
    }

    pub fn with_metric(mut self, name: impl Into<String>, value: f64) -> Self {
        self.metrics.insert(name.into(), value);
        self
    }
}

// ── DeploymentStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentStatus {
    Active,
    Inactive,
    Retired,
    Suspended,
}

impl fmt::Display for DeploymentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Inactive => f.write_str("inactive"),
            Self::Retired => f.write_str("retired"),
            Self::Suspended => f.write_str("suspended"),
        }
    }
}

// ── DeploymentRecord ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeploymentRecord {
    pub deployment_id: String,
    pub environment: String,
    pub deployed_at: i64,
    pub deployed_by: String,
    pub endpoint: Option<String>,
    pub status: DeploymentStatus,
    pub retired_at: Option<i64>,
    pub configuration: HashMap<String, String>,
}

impl DeploymentRecord {
    pub fn new(
        deployment_id: impl Into<String>,
        environment: impl Into<String>,
        deployed_by: impl Into<String>,
        deployed_at: i64,
    ) -> Self {
        Self {
            deployment_id: deployment_id.into(),
            environment: environment.into(),
            deployed_at,
            deployed_by: deployed_by.into(),
            endpoint: None,
            status: DeploymentStatus::Active,
            retired_at: None,
            configuration: HashMap::new(),
        }
    }
}

// ── FineTuningRecord ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FineTuningRecord {
    pub base_model_artifact: ArtifactId,
    pub fine_tune_dataset: ArtifactId,
    pub method: String,
    pub hyperparameters: HashMap<String, String>,
    pub completed_at: i64,
    pub result_artifact: ArtifactId,
}

// ── ModelProvenance ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModelProvenance {
    pub id: ModelProvenanceId,
    pub artifact_id: ArtifactId,
    pub model_name: String,
    pub model_family: Option<String>,
    pub architecture: ModelArchitecture,
    pub training: Option<TrainingRecord>,
    pub evaluations: Vec<EvaluationRecord>,
    pub deployments: Vec<DeploymentRecord>,
    pub fine_tuning_history: Vec<FineTuningRecord>,
    pub attestation_chain: Vec<String>,
    pub created_at: i64,
    pub created_by: String,
    pub license: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl ModelProvenance {
    pub fn new(
        id: impl Into<String>,
        artifact_id: ArtifactId,
        model_name: impl Into<String>,
        architecture: ModelArchitecture,
        created_by: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            id: ModelProvenanceId::new(id),
            artifact_id,
            model_name: model_name.into(),
            model_family: None,
            architecture,
            training: None,
            evaluations: Vec::new(),
            deployments: Vec::new(),
            fine_tuning_history: Vec::new(),
            attestation_chain: Vec::new(),
            created_at,
            created_by: created_by.into(),
            license: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_family(mut self, family: impl Into<String>) -> Self {
        self.model_family = Some(family.into());
        self
    }

    pub fn with_training(mut self, t: TrainingRecord) -> Self {
        self.training = Some(t);
        self
    }

    pub fn with_evaluation(mut self, e: EvaluationRecord) -> Self {
        self.evaluations.push(e);
        self
    }

    pub fn with_deployment(mut self, d: DeploymentRecord) -> Self {
        self.deployments.push(d);
        self
    }

    pub fn with_fine_tuning(mut self, ft: FineTuningRecord) -> Self {
        self.fine_tuning_history.push(ft);
        self
    }

    pub fn with_license(mut self, l: impl Into<String>) -> Self {
        self.license = Some(l.into());
        self
    }
}

// ── ModelRegistry ─────────────────────────────────────────────────────

#[derive(Default)]
pub struct ModelRegistry {
    pub models: HashMap<ModelProvenanceId, ModelProvenance>,
    pub artifact_index: HashMap<ArtifactId, ModelProvenanceId>,
}

impl ModelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, prov: ModelProvenance) -> Result<(), ProvenanceError> {
        if self.models.contains_key(&prov.id) {
            return Err(ProvenanceError::ModelAlreadyExists(prov.id.0.clone()));
        }
        let mid = prov.id.clone();
        self.artifact_index
            .insert(prov.artifact_id.clone(), mid.clone());
        self.models.insert(mid, prov);
        Ok(())
    }

    pub fn get(&self, id: &ModelProvenanceId) -> Option<&ModelProvenance> {
        self.models.get(id)
    }

    pub fn for_artifact(&self, artifact_id: &ArtifactId) -> Option<&ModelProvenance> {
        self.artifact_index
            .get(artifact_id)
            .and_then(|mid| self.models.get(mid))
    }

    pub fn by_family(&self, family: &str) -> Vec<&ModelProvenance> {
        self.models
            .values()
            .filter(|m| m.model_family.as_deref() == Some(family))
            .collect()
    }

    /// Models with at least one Active deployment.
    pub fn deployed_models(&self) -> Vec<&ModelProvenance> {
        self.models
            .values()
            .filter(|m| {
                m.deployments
                    .iter()
                    .any(|d| d.status == DeploymentStatus::Active)
            })
            .collect()
    }

    /// Models whose training record includes this dataset.
    pub fn models_trained_on(&self, dataset_artifact: &ArtifactId) -> Vec<&ModelProvenance> {
        self.models
            .values()
            .filter(|m| {
                m.training
                    .as_ref()
                    .map(|t| t.dataset_artifacts.contains(dataset_artifact))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Aggregates latest evaluation metrics across all benchmarks.
    pub fn evaluation_summary(
        &self,
        id: &ModelProvenanceId,
    ) -> HashMap<String, f64> {
        let mut out = HashMap::new();
        if let Some(model) = self.models.get(id) {
            for eval in &model.evaluations {
                for (k, v) in &eval.metrics {
                    out.insert(format!("{}:{}", eval.benchmark, k), *v);
                }
            }
        }
        out
    }

    pub fn count(&self) -> usize {
        self.models.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn arch() -> ModelArchitecture {
        ModelArchitecture::new("transformer")
            .with_parameters(8_000_000_000)
            .with_layers(32)
            .with_context_length(131072)
    }

    fn basic_model(id: &str) -> ModelProvenance {
        ModelProvenance::new(
            id,
            ArtifactId::new(format!("art:{id}")),
            "test-model",
            arch(),
            "alice",
            1000,
        )
    }

    #[test]
    fn test_model_provenance_construction() {
        let m = basic_model("m1")
            .with_family("LLaMA")
            .with_license("Apache-2.0")
            .with_training(
                TrainingRecord::new("PyTorch 2.4", 1000)
                    .with_dataset(ArtifactId::new("dataset-1"))
                    .with_hyperparameter("lr", "1e-4")
                    .completed(2000, 24.5)
                    .with_final_loss(1.23),
            )
            .with_evaluation(
                EvaluationRecord::new("e1", "MMLU", "bob", 3000)
                    .with_metric("accuracy", 0.85),
            );
        assert_eq!(m.model_family.as_deref(), Some("LLaMA"));
        assert!(m.training.is_some());
        assert_eq!(m.evaluations.len(), 1);
        assert_eq!(m.evaluations[0].metrics.get("accuracy"), Some(&0.85));
    }

    #[test]
    fn test_architecture_construction() {
        let a = arch().with_quantization("int8");
        assert_eq!(a.parameter_count, Some(8_000_000_000));
        assert_eq!(a.quantization.as_deref(), Some("int8"));
    }

    #[test]
    fn test_training_record() {
        let t = TrainingRecord::new("JAX 0.4", 500)
            .with_dataset(ArtifactId::new("d1"))
            .with_hyperparameter("epochs", "10")
            .completed(600, 1.5)
            .with_final_loss(0.05);
        assert_eq!(t.dataset_artifacts.len(), 1);
        assert_eq!(t.training_duration_hours, Some(1.5));
        assert_eq!(t.final_loss, Some(0.05));
    }

    #[test]
    fn test_evaluation_record() {
        let e = EvaluationRecord::new("e1", "HumanEval", "charlie", 4000)
            .with_metric("pass@1", 0.67)
            .with_metric("pass@10", 0.92);
        assert_eq!(e.metrics.len(), 2);
    }

    #[test]
    fn test_deployment_status_display() {
        assert_eq!(DeploymentStatus::Active.to_string(), "active");
        assert_eq!(DeploymentStatus::Inactive.to_string(), "inactive");
        assert_eq!(DeploymentStatus::Retired.to_string(), "retired");
        assert_eq!(DeploymentStatus::Suspended.to_string(), "suspended");
    }

    #[test]
    fn test_deployment_record() {
        let d = DeploymentRecord::new("dep1", "production", "ops", 5000);
        assert_eq!(d.status, DeploymentStatus::Active);
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("m1")).unwrap();
        assert!(r.get(&ModelProvenanceId::new("m1")).is_some());
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn test_registry_for_artifact() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("m1")).unwrap();
        assert!(r.for_artifact(&ArtifactId::new("art:m1")).is_some());
    }

    #[test]
    fn test_registry_by_family() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("m1").with_family("LLaMA")).unwrap();
        r.register(basic_model("m2").with_family("GPT")).unwrap();
        assert_eq!(r.by_family("LLaMA").len(), 1);
    }

    #[test]
    fn test_deployed_models() {
        let mut r = ModelRegistry::new();
        r.register(
            basic_model("m1").with_deployment(DeploymentRecord::new("d1", "prod", "ops", 1)),
        )
        .unwrap();
        r.register(basic_model("m2")).unwrap();
        assert_eq!(r.deployed_models().len(), 1);
    }

    #[test]
    fn test_models_trained_on() {
        let mut r = ModelRegistry::new();
        r.register(
            basic_model("m1").with_training(
                TrainingRecord::new("PT", 1).with_dataset(ArtifactId::new("d-train")),
            ),
        )
        .unwrap();
        r.register(basic_model("m2")).unwrap();
        assert_eq!(
            r.models_trained_on(&ArtifactId::new("d-train")).len(),
            1
        );
    }

    #[test]
    fn test_evaluation_summary() {
        let mut r = ModelRegistry::new();
        r.register(
            basic_model("m1")
                .with_evaluation(
                    EvaluationRecord::new("e1", "MMLU", "b", 1).with_metric("accuracy", 0.85),
                )
                .with_evaluation(
                    EvaluationRecord::new("e2", "HumanEval", "b", 2)
                        .with_metric("pass@1", 0.67),
                ),
        )
        .unwrap();
        let summary = r.evaluation_summary(&ModelProvenanceId::new("m1"));
        assert_eq!(summary.get("MMLU:accuracy"), Some(&0.85));
        assert_eq!(summary.get("HumanEval:pass@1"), Some(&0.67));
    }

    #[test]
    fn test_duplicate_model_fails() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("m1")).unwrap();
        let err = r.register(basic_model("m1")).unwrap_err();
        assert!(matches!(err, ProvenanceError::ModelAlreadyExists(_)));
    }
}
