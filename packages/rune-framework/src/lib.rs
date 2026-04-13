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
