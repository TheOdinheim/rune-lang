// ═══════════════════════════════════════════════════════════════════════
// Transform — transformation records: what was done to data at each step.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;
use crate::error::ProvenanceError;

// ── TransformationId ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransformationId(pub String);

impl TransformationId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for TransformationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── TransformType ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformType {
    Preprocessing,
    Training,
    FineTuning,
    Evaluation,
    Inference,
    Aggregation,
    Filtering,
    Augmentation,
    Anonymization,
    Encryption,
    Compilation,
    PolicyEvaluation,
    Custom(String),
}

impl fmt::Display for TransformType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preprocessing => f.write_str("preprocessing"),
            Self::Training => f.write_str("training"),
            Self::FineTuning => f.write_str("fine-tuning"),
            Self::Evaluation => f.write_str("evaluation"),
            Self::Inference => f.write_str("inference"),
            Self::Aggregation => f.write_str("aggregation"),
            Self::Filtering => f.write_str("filtering"),
            Self::Augmentation => f.write_str("augmentation"),
            Self::Anonymization => f.write_str("anonymization"),
            Self::Encryption => f.write_str("encryption"),
            Self::Compilation => f.write_str("compilation"),
            Self::PolicyEvaluation => f.write_str("policy-evaluation"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ── ExecutionEnvironment ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExecutionEnvironment {
    pub platform: String,
    pub hardware: Option<String>,
    pub runtime: Option<String>,
    pub container_image: Option<String>,
    pub git_commit: Option<String>,
}

impl ExecutionEnvironment {
    pub fn new(platform: impl Into<String>) -> Self {
        Self {
            platform: platform.into(),
            hardware: None,
            runtime: None,
            container_image: None,
            git_commit: None,
        }
    }
}

// ── TransformationRef ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TransformationRef {
    pub transformation_id: TransformationId,
    pub step_order: u32,
}

// ── Transformation ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Transformation {
    pub id: TransformationId,
    pub name: String,
    pub description: String,
    pub transform_type: TransformType,
    pub inputs: Vec<ArtifactId>,
    pub outputs: Vec<ArtifactId>,
    pub parameters: HashMap<String, String>,
    pub executed_by: String,
    pub executed_at: i64,
    pub duration_ms: Option<u64>,
    pub environment: Option<ExecutionEnvironment>,
    pub reproducible: bool,
    pub code_ref: Option<String>,
}

impl Transformation {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        transform_type: TransformType,
        executed_by: impl Into<String>,
        executed_at: i64,
    ) -> Self {
        Self {
            id: TransformationId::new(id),
            name: name.into(),
            description: String::new(),
            transform_type,
            inputs: Vec::new(),
            outputs: Vec::new(),
            parameters: HashMap::new(),
            executed_by: executed_by.into(),
            executed_at,
            duration_ms: None,
            environment: None,
            reproducible: false,
            code_ref: None,
        }
    }

    pub fn with_input(mut self, a: ArtifactId) -> Self {
        self.inputs.push(a);
        self
    }

    pub fn with_output(mut self, a: ArtifactId) -> Self {
        self.outputs.push(a);
        self
    }

    pub fn with_parameter(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.parameters.insert(k.into(), v.into());
        self
    }

    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    pub fn reproducible(mut self) -> Self {
        self.reproducible = true;
        self
    }

    pub fn with_code_ref(mut self, r: impl Into<String>) -> Self {
        self.code_ref = Some(r.into());
        self
    }
}

// ── TransformationLog ─────────────────────────────────────────────────

#[derive(Default)]
pub struct TransformationLog {
    pub transformations: HashMap<TransformationId, Transformation>,
}

impl TransformationLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, t: Transformation) -> Result<(), ProvenanceError> {
        if self.transformations.contains_key(&t.id) {
            return Err(ProvenanceError::InvalidOperation(format!(
                "transformation {} already exists",
                t.id
            )));
        }
        self.transformations.insert(t.id.clone(), t);
        Ok(())
    }

    pub fn get(&self, id: &TransformationId) -> Option<&Transformation> {
        self.transformations.get(id)
    }

    /// All transformations that produce `artifact_id` as an output.
    pub fn for_artifact(&self, artifact_id: &ArtifactId) -> Vec<&Transformation> {
        self.transformations
            .values()
            .filter(|t| t.outputs.contains(artifact_id))
            .collect()
    }

    pub fn by_type(&self, transform_type: &TransformType) -> Vec<&Transformation> {
        self.transformations
            .values()
            .filter(|t| &t.transform_type == transform_type)
            .collect()
    }

    pub fn by_executor(&self, executor: &str) -> Vec<&Transformation> {
        self.transformations
            .values()
            .filter(|t| t.executed_by == executor)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.transformations.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn preprocess(id: &str) -> Transformation {
        Transformation::new(id, "clean data", TransformType::Preprocessing, "alice", 1000)
            .with_input(ArtifactId::new("raw"))
            .with_output(ArtifactId::new("clean"))
    }

    #[test]
    fn test_transform_type_display() {
        assert_eq!(TransformType::Preprocessing.to_string(), "preprocessing");
        assert_eq!(TransformType::Training.to_string(), "training");
        assert_eq!(TransformType::FineTuning.to_string(), "fine-tuning");
        assert_eq!(TransformType::Evaluation.to_string(), "evaluation");
        assert_eq!(TransformType::Inference.to_string(), "inference");
        assert_eq!(TransformType::Aggregation.to_string(), "aggregation");
        assert_eq!(TransformType::Filtering.to_string(), "filtering");
        assert_eq!(TransformType::Augmentation.to_string(), "augmentation");
        assert_eq!(TransformType::Anonymization.to_string(), "anonymization");
        assert_eq!(TransformType::Encryption.to_string(), "encryption");
        assert_eq!(TransformType::Compilation.to_string(), "compilation");
        assert_eq!(TransformType::PolicyEvaluation.to_string(), "policy-evaluation");
        assert_eq!(TransformType::Custom("x".into()).to_string(), "custom:x");
    }

    #[test]
    fn test_transformation_construction() {
        let t = preprocess("t1")
            .with_parameter("mode", "normalize")
            .with_duration(5000)
            .reproducible()
            .with_code_ref("abc123");
        assert_eq!(t.inputs.len(), 1);
        assert_eq!(t.outputs.len(), 1);
        assert!(t.reproducible);
        assert_eq!(t.code_ref.as_deref(), Some("abc123"));
        assert_eq!(t.duration_ms, Some(5000));
    }

    #[test]
    fn test_log_record_and_get() {
        let mut log = TransformationLog::new();
        log.record(preprocess("t1")).unwrap();
        assert!(log.get(&TransformationId::new("t1")).is_some());
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn test_log_for_artifact() {
        let mut log = TransformationLog::new();
        log.record(preprocess("t1")).unwrap();
        let found = log.for_artifact(&ArtifactId::new("clean"));
        assert_eq!(found.len(), 1);
        let empty = log.for_artifact(&ArtifactId::new("missing"));
        assert!(empty.is_empty());
    }

    #[test]
    fn test_log_by_type() {
        let mut log = TransformationLog::new();
        log.record(preprocess("t1")).unwrap();
        log.record(
            Transformation::new("t2", "train", TransformType::Training, "bob", 2000),
        )
        .unwrap();
        assert_eq!(log.by_type(&TransformType::Preprocessing).len(), 1);
        assert_eq!(log.by_type(&TransformType::Training).len(), 1);
    }

    #[test]
    fn test_log_by_executor() {
        let mut log = TransformationLog::new();
        log.record(preprocess("t1")).unwrap();
        assert_eq!(log.by_executor("alice").len(), 1);
        assert!(log.by_executor("bob").is_empty());
    }

    #[test]
    fn test_execution_environment() {
        let e = ExecutionEnvironment::new("WSL2 Ubuntu 24.04");
        assert_eq!(e.platform, "WSL2 Ubuntu 24.04");
    }
}
