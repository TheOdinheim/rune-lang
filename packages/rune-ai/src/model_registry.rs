// ═══════════════════════════════════════════════════════════════════════
// Model Registry — Core model identity, versioning, architecture,
// task type, and lifecycle status types for AI/ML model governance.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── ModelArchitecture ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelArchitecture {
    Transformer,
    Cnn,
    Rnn,
    GradientBoosted,
    LinearRegression,
    Ensemble,
    Custom { name: String },
}

impl fmt::Display for ModelArchitecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transformer => f.write_str("Transformer"),
            Self::Cnn => f.write_str("CNN"),
            Self::Rnn => f.write_str("RNN"),
            Self::GradientBoosted => f.write_str("GradientBoosted"),
            Self::LinearRegression => f.write_str("LinearRegression"),
            Self::Ensemble => f.write_str("Ensemble"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── ModelTaskType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelTaskType {
    Classification,
    Regression,
    Generation,
    Embedding,
    Ranking,
    ObjectDetection,
    Segmentation,
    ReinforcementLearning,
    Custom { name: String },
}

impl fmt::Display for ModelTaskType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Classification => f.write_str("Classification"),
            Self::Regression => f.write_str("Regression"),
            Self::Generation => f.write_str("Generation"),
            Self::Embedding => f.write_str("Embedding"),
            Self::Ranking => f.write_str("Ranking"),
            Self::ObjectDetection => f.write_str("ObjectDetection"),
            Self::Segmentation => f.write_str("Segmentation"),
            Self::ReinforcementLearning => f.write_str("ReinforcementLearning"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── ModelStatus ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelStatus {
    Draft,
    Registered,
    UnderEvaluation,
    Approved,
    Deployed,
    Deprecated,
    Retired,
    Suspended,
}

impl fmt::Display for ModelStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Draft => "Draft",
            Self::Registered => "Registered",
            Self::UnderEvaluation => "UnderEvaluation",
            Self::Approved => "Approved",
            Self::Deployed => "Deployed",
            Self::Deprecated => "Deprecated",
            Self::Retired => "Retired",
            Self::Suspended => "Suspended",
        };
        f.write_str(s)
    }
}

impl ModelStatus {
    pub fn is_deployable(&self) -> bool {
        matches!(self, Self::Approved)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Retired)
    }

    pub fn is_valid_transition(&self, to: &ModelStatus) -> bool {
        // Any status can transition to Suspended
        if matches!(to, ModelStatus::Suspended) {
            return true;
        }
        matches!(
            (self, to),
            (Self::Draft, Self::Registered)
                | (Self::Registered, Self::UnderEvaluation)
                | (Self::UnderEvaluation, Self::Approved)
                | (Self::UnderEvaluation, Self::Registered) // sent back for changes
                | (Self::Approved, Self::Deployed)
                | (Self::Deployed, Self::Deprecated)
                | (Self::Deprecated, Self::Retired)
                | (Self::Suspended, Self::Registered) // reactivation
        )
    }
}

// ── ModelRecord ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRecord {
    pub model_id: String,
    pub model_name: String,
    pub model_version: String,
    pub architecture: ModelArchitecture,
    pub task_type: ModelTaskType,
    pub framework: String,
    pub created_by: String,
    pub created_at: i64,
    pub status: ModelStatus,
    pub attestation_ref: Option<String>,
    pub training_data_refs: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl ModelRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        model_id: impl Into<String>,
        model_name: impl Into<String>,
        model_version: impl Into<String>,
        architecture: ModelArchitecture,
        task_type: ModelTaskType,
        framework: impl Into<String>,
        created_by: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            model_id: model_id.into(),
            model_name: model_name.into(),
            model_version: model_version.into(),
            architecture,
            task_type,
            framework: framework.into(),
            created_by: created_by.into(),
            created_at,
            status: ModelStatus::Draft,
            attestation_ref: None,
            training_data_refs: Vec::new(),
            metadata: HashMap::new(),
        }
    }
}

// ── VersionEntry ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionEntry {
    pub version: String,
    pub registered_at: i64,
    pub registered_by: String,
    pub change_summary: String,
    pub previous_version: Option<String>,
    pub attestation_ref: Option<String>,
}

impl VersionEntry {
    pub fn new(
        version: impl Into<String>,
        registered_at: i64,
        registered_by: impl Into<String>,
        change_summary: impl Into<String>,
    ) -> Self {
        Self {
            version: version.into(),
            registered_at,
            registered_by: registered_by.into(),
            change_summary: change_summary.into(),
            previous_version: None,
            attestation_ref: None,
        }
    }
}

// ── ModelVersionHistory ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelVersionHistory {
    pub model_id: String,
    pub versions: Vec<VersionEntry>,
}

impl ModelVersionHistory {
    pub fn new(model_id: impl Into<String>) -> Self {
        Self {
            model_id: model_id.into(),
            versions: Vec::new(),
        }
    }

    pub fn add_version(&mut self, entry: VersionEntry) {
        self.versions.push(entry);
    }

    pub fn latest_version(&self) -> Option<&VersionEntry> {
        self.versions.last()
    }

    pub fn version_count(&self) -> usize {
        self.versions.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_architecture_display() {
        let archs = vec![
            ModelArchitecture::Transformer,
            ModelArchitecture::Cnn,
            ModelArchitecture::Rnn,
            ModelArchitecture::GradientBoosted,
            ModelArchitecture::LinearRegression,
            ModelArchitecture::Ensemble,
            ModelArchitecture::Custom { name: "MyArch".into() },
        ];
        for a in &archs {
            assert!(!a.to_string().is_empty());
        }
        assert_eq!(archs.len(), 7);
    }

    #[test]
    fn test_model_task_type_display() {
        let tasks = vec![
            ModelTaskType::Classification,
            ModelTaskType::Regression,
            ModelTaskType::Generation,
            ModelTaskType::Embedding,
            ModelTaskType::Ranking,
            ModelTaskType::ObjectDetection,
            ModelTaskType::Segmentation,
            ModelTaskType::ReinforcementLearning,
            ModelTaskType::Custom { name: "MyTask".into() },
        ];
        for t in &tasks {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(tasks.len(), 9);
    }

    #[test]
    fn test_model_status_display() {
        let statuses = vec![
            ModelStatus::Draft,
            ModelStatus::Registered,
            ModelStatus::UnderEvaluation,
            ModelStatus::Approved,
            ModelStatus::Deployed,
            ModelStatus::Deprecated,
            ModelStatus::Retired,
            ModelStatus::Suspended,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 8);
    }

    #[test]
    fn test_is_deployable() {
        assert!(ModelStatus::Approved.is_deployable());
        assert!(!ModelStatus::Draft.is_deployable());
        assert!(!ModelStatus::Registered.is_deployable());
        assert!(!ModelStatus::Deployed.is_deployable());
        assert!(!ModelStatus::Retired.is_deployable());
    }

    #[test]
    fn test_is_terminal() {
        assert!(ModelStatus::Retired.is_terminal());
        assert!(!ModelStatus::Draft.is_terminal());
        assert!(!ModelStatus::Deployed.is_terminal());
        assert!(!ModelStatus::Suspended.is_terminal());
    }

    #[test]
    fn test_valid_transitions() {
        assert!(ModelStatus::Draft.is_valid_transition(&ModelStatus::Registered));
        assert!(ModelStatus::Registered.is_valid_transition(&ModelStatus::UnderEvaluation));
        assert!(ModelStatus::UnderEvaluation.is_valid_transition(&ModelStatus::Approved));
        assert!(ModelStatus::UnderEvaluation.is_valid_transition(&ModelStatus::Registered));
        assert!(ModelStatus::Approved.is_valid_transition(&ModelStatus::Deployed));
        assert!(ModelStatus::Deployed.is_valid_transition(&ModelStatus::Deprecated));
        assert!(ModelStatus::Deprecated.is_valid_transition(&ModelStatus::Retired));
        assert!(ModelStatus::Suspended.is_valid_transition(&ModelStatus::Registered));
    }

    #[test]
    fn test_invalid_transitions() {
        assert!(!ModelStatus::Draft.is_valid_transition(&ModelStatus::Deployed));
        assert!(!ModelStatus::Registered.is_valid_transition(&ModelStatus::Deployed));
        assert!(!ModelStatus::Approved.is_valid_transition(&ModelStatus::Draft));
        assert!(!ModelStatus::Retired.is_valid_transition(&ModelStatus::Draft));
        assert!(!ModelStatus::Deployed.is_valid_transition(&ModelStatus::Registered));
    }

    #[test]
    fn test_any_to_suspended() {
        let all = vec![
            ModelStatus::Draft,
            ModelStatus::Registered,
            ModelStatus::UnderEvaluation,
            ModelStatus::Approved,
            ModelStatus::Deployed,
            ModelStatus::Deprecated,
            ModelStatus::Retired,
        ];
        for s in &all {
            assert!(s.is_valid_transition(&ModelStatus::Suspended));
        }
    }

    #[test]
    fn test_model_record_construction() {
        let mut record = ModelRecord::new(
            "model-1", "GPT-Gov", "1.0.0",
            ModelArchitecture::Transformer,
            ModelTaskType::Generation,
            "pytorch", "alice", 1000,
        );
        assert_eq!(record.model_id, "model-1");
        assert_eq!(record.status, ModelStatus::Draft);
        assert!(record.attestation_ref.is_none());
        assert!(record.training_data_refs.is_empty());

        record.attestation_ref = Some("att-123".into());
        record.training_data_refs.push("ds-1".into());
        record.metadata.insert("team".into(), "ml-ops".into());
        assert_eq!(record.training_data_refs.len(), 1);
    }

    #[test]
    fn test_version_entry_construction() {
        let mut entry = VersionEntry::new("1.0.0", 1000, "alice", "initial version");
        assert_eq!(entry.version, "1.0.0");
        assert!(entry.previous_version.is_none());
        entry.previous_version = Some("0.9.0".into());
        entry.attestation_ref = Some("att-1".into());
        assert_eq!(entry.previous_version, Some("0.9.0".to_string()));
    }

    #[test]
    fn test_model_version_history() {
        let mut history = ModelVersionHistory::new("model-1");
        assert_eq!(history.version_count(), 0);
        assert!(history.latest_version().is_none());

        history.add_version(VersionEntry::new("1.0.0", 1000, "alice", "initial"));
        history.add_version(VersionEntry::new("1.1.0", 2000, "bob", "update"));
        assert_eq!(history.version_count(), 2);
        assert_eq!(history.latest_version().unwrap().version, "1.1.0");
    }

    #[test]
    fn test_suspended_to_suspended_valid() {
        // "any→Suspended" includes Suspended itself
        assert!(ModelStatus::Suspended.is_valid_transition(&ModelStatus::Suspended));
    }

    #[test]
    fn test_retired_is_not_deployable() {
        assert!(!ModelStatus::Retired.is_deployable());
        assert!(!ModelStatus::Deprecated.is_deployable());
        assert!(!ModelStatus::Suspended.is_deployable());
        assert!(!ModelStatus::UnderEvaluation.is_deployable());
    }

    #[test]
    fn test_model_record_metadata() {
        let mut record = ModelRecord::new(
            "m-2", "BERT", "2.0.0",
            ModelArchitecture::Transformer,
            ModelTaskType::Embedding,
            "tensorflow", "bob", 2000,
        );
        record.metadata.insert("team".into(), "nlp".into());
        record.metadata.insert("region".into(), "us-east-1".into());
        assert_eq!(record.metadata.len(), 2);
        assert_eq!(record.metadata["team"], "nlp");
    }

    #[test]
    fn test_version_history_empty_latest() {
        let history = ModelVersionHistory::new("model-x");
        assert!(history.latest_version().is_none());
        assert_eq!(history.version_count(), 0);
        assert_eq!(history.model_id, "model-x");
    }
}
