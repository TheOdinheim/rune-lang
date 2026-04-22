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

// Layer 2 modules
pub mod ai_metrics;
pub mod deployment_checker;
pub mod drift_evaluator;
pub mod evaluation_engine;
pub mod fairness_evaluator;
pub mod lifecycle_engine;
pub mod model_hash;

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

// ── Re-exports: Layer 2 — Model Hash ────────────────────────────────

pub use model_hash::{
    ModelHashChain, ModelHashChainLink, hash_dataset_record, hash_model_record,
    verify_dataset_hash, verify_model_hash,
};

// ── Re-exports: Layer 2 — Evaluation Engine ─────────────────────────

pub use evaluation_engine::{
    CriterionEvaluation, EvaluationEngine, GateEvaluation, GateRecommendation,
    compare_threshold,
};

// ── Re-exports: Layer 2 — Deployment Checker ────────────────────────

pub use deployment_checker::{
    BlockerSeverity, DeploymentBlocker, DeploymentBlockerType, DeploymentReadinessChecker,
    DeploymentReadinessResult,
};

// ── Re-exports: Layer 2 — Fairness Evaluator ────────────────────────

pub use fairness_evaluator::{
    FairnessEvaluationResult, FairnessEvaluator, FairnessMetricEvaluation,
};

// ── Re-exports: Layer 2 — Drift Evaluator ───────────────────────────

pub use drift_evaluator::{DriftEvaluationResult, DriftEvaluator, DriftMetricEvaluation};

// ── Re-exports: Layer 2 — Lifecycle Engine ──────────────────────────

pub use lifecycle_engine::{
    DeploymentAgeCheckResult, DeprecationCheckResult, LifecycleEngine,
};

// ── Re-exports: Layer 2 — AI Metrics ────────────────────────────────

pub use ai_metrics::{AiMetricSnapshot, AiMetrics};
