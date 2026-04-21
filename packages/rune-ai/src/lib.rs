// ═══════════════════════════════════════════════════════════════════════
// rune-ai — AI/ML model lifecycle governance: model registry,
// training data governance, evaluation gates, deployment approval,
// bias and fairness monitoring policy, drift detection policy,
// model retirement, audit events, and error types for the RUNE
// governance ecosystem.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod bias_fairness;
pub mod deployment;
pub mod drift;
pub mod error;
pub mod evaluation;
pub mod lifecycle;
pub mod model_registry;
pub mod training_data;

// ── Re-exports: Model Registry ──────────────────────────────────────

pub use model_registry::{
    ModelArchitecture, ModelRecord, ModelStatus, ModelTaskType, ModelVersionHistory,
    VersionEntry,
};

// ── Re-exports: Training Data ───────────────────────────────────────

pub use training_data::{
    DataGovernancePolicy, DataQualityStatus, DatasetFormat, DatasetRecord, DatasetSource,
};

// ── Re-exports: Evaluation ──────────────────────────────────────────

pub use evaluation::{
    EvaluationCriteria, EvaluationGate, EvaluationGateStatus, EvaluationResult,
    ThresholdComparison,
};

// ── Re-exports: Deployment ──────────────────────────────────────────

pub use deployment::{
    DeploymentApprovalStatus, DeploymentEnvironment, DeploymentRecord, DeploymentRequest,
    DeploymentStatus, RollbackPolicy,
};

// ── Re-exports: Bias & Fairness ─────────────────────────────────────

pub use bias_fairness::{
    FairnessAssessment, FairnessMetricDefinition, FairnessMetricResult, FairnessPolicy,
    FairnessStatus, MonitoringFrequency, ProtectedAttribute, ProtectedAttributeType,
};

// ── Re-exports: Drift ───────────────────────────────────────────────

pub use drift::{
    DriftAlertConfig, DriftDetectionResult, DriftDetectionWindow, DriftMetricDefinition,
    DriftMetricResult, DriftPolicy, DriftRemediationAction, DriftSeverity, DriftStatus,
};

// ── Re-exports: Lifecycle ───────────────────────────────────────────

pub use lifecycle::{
    DeprecationNotice, DeprecationSeverity, ModelLifecyclePolicy, ModelLifecycleTransition,
    RetirementAction,
};

// ── Re-exports: Audit ───────────────────────────────────────────────

pub use audit::{AiAuditEvent, AiAuditLog, AiEventType};

// ── Re-exports: Error ───────────────────────────────────────────────

pub use error::AiError;
