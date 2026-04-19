// ═══════════════════════════════════════════════════════════════════════
// rune-framework — Governance pipeline orchestration, component
// registry, workflow templates, and health aggregation.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod config;
pub mod context;
pub mod error;
pub mod health;
pub mod pipeline;
pub mod registry;
pub mod request;
pub mod stage;
pub mod workflow;

// ── Layer 2 modules ─────────────────────────────────────────────────
pub mod l2_control_mapping;
pub mod l2_evidence;
pub mod l2_framework_registry;
pub mod l2_gap_analysis;
pub mod l2_maturity;
pub mod l2_regulatory;

pub use audit::{FrameworkAuditEvent, FrameworkAuditLog, FrameworkEventType};
pub use config::{ConfigSeverity, ConfigValidation, Environment, FrameworkConfig};
pub use context::GovernanceContext;
pub use error::FrameworkError;
pub use health::{
    ComponentHealthEntry, FrameworkHealth, FrameworkHealthAssessor, FrameworkHealthStatus,
    PipelineHealth, PipelineStats,
};
pub use pipeline::{GovernancePipeline, PipelineStageEntry};
pub use registry::{
    ComponentId, ComponentInfo, ComponentRegistry, ComponentStatus, ComponentType, SystemReadiness,
};
pub use request::{
    GovernanceDecisionResult, GovernanceOutcome, GovernanceRequest, GovernanceRequestId,
    RequestContext, ResourceInfo, StageOutcome, StageResult, SubjectInfo,
};
pub use stage::{
    compliance_stage, identity_stage, policy_stage, shield_stage, trust_stage, FailAction,
    StageDefinition, StageFn, StageType,
};
pub use workflow::{
    build_pipeline_from_template, default_evaluator_registry, StageEvaluatorRegistry,
    WorkflowStage, WorkflowTemplate,
};

// ── Layer 2 re-exports ──────────────────────────────────────────────
pub use l2_control_mapping::{
    nist_to_soc2_mappings, ControlMapping, ControlMappingStore, EquivalenceLevel,
};
pub use l2_evidence::{CollectionStatus, EvidenceCollectionTracker, EvidenceRequirement};
pub use l2_framework_registry::{
    eu_ai_act_skeleton, nist_ai_rmf_skeleton, soc2_skeleton, ControlSeverity, FrameworkControl,
    FrameworkDefinition, L2FrameworkRegistry,
};
pub use l2_gap_analysis::{
    ComplianceEvidence, ComplianceGap, EvidenceStatus, EvidenceType, GapAnalysisReport,
    GapAnalyzer, GapType,
};
pub use l2_maturity::{
    ControlMaturityAssessment, MaturityLevel, MaturityTracker, MaturityTrend,
};
pub use l2_regulatory::{
    assess_change_impact, ChangeImpact, ChangeImpactAssessment, RegulatoryChange,
    RegulatoryChangeTracker, RegulatoryChangeType, RemediationEffort,
};
