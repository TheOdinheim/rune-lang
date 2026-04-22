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

// Layer 3 modules
pub mod ai_export;
pub mod ai_governance_metrics;
pub mod ai_stream;
pub mod backend;
pub mod drift_governor;
pub mod fairness_governor;
pub mod model_lifecycle_governor;

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

// ── Layer 3 re-exports ─────────────────────────────────────────────

// ── Re-exports: Layer 3 — Backend ──────────────────────────────────

pub use backend::{
    AiBackendInfo, AiGovernanceBackend, InMemoryAiGovernanceBackend, StoredDatasetRecord,
    StoredDeploymentRecord, StoredDeprecationNotice, StoredDriftResult,
    StoredEvaluationResult, StoredFairnessAssessment, StoredModelRecord,
};

// ── Re-exports: Layer 3 — Model Lifecycle Governor ─────────────────

pub use model_lifecycle_governor::{
    DeploymentGovernanceDecision, InMemoryModelLifecycleGovernor, ModelHealthAssessment,
    ModelHealthStatus, ModelLifecycleGovernor, NullModelLifecycleGovernor,
    StrictModelLifecycleGovernor, TransitionGovernanceDecision,
};

// ── Re-exports: Layer 3 — Fairness Governor ────────────────────────

pub use fairness_governor::{
    FairnessGovernanceDecision, FairnessGovernanceResult, FairnessGovernor,
    InMemoryFairnessGovernor, NullFairnessGovernor,
};

// ── Re-exports: Layer 3 — Drift Governor ───────────────────────────

pub use drift_governor::{
    DriftGovernanceDecision, DriftGovernanceResult, DriftGovernor, InMemoryDriftGovernor,
    NullDriftGovernor,
};

// ── Re-exports: Layer 3 — AI Export ────────────────────────────────

pub use ai_export::{
    AiGovernanceExporter, DeploymentAuditExporter, EuAiActComplianceExporter, JsonAiExporter,
    ModelCardExporter, NistAiRmfExporter,
};

// ── Re-exports: Layer 3 — AI Event Stream ──────────────────────────

pub use ai_stream::{
    AiGovernanceEventCollector, AiGovernanceEventSubscriber,
    AiGovernanceEventSubscriberRegistry, AiGovernanceLifecycleEvent,
    AiGovernanceLifecycleEventType, FilteredAiGovernanceEventSubscriber,
};

// ── Re-exports: Layer 3 — AI Governance Metrics ────────────────────

pub use ai_governance_metrics::{
    AiGovernanceMetricSnapshot, AiGovernanceMetricsCollector,
    InMemoryAiGovernanceMetricsCollector, NullAiGovernanceMetricsCollector,
};
