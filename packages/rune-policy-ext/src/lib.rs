// ═══════════════════════════════════════════════════════════════════════
// rune-policy-ext — policy versioning, composition, conflict detection,
// simulation, import/export, and lifecycle management.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod binding;
pub mod composition;
pub mod conflict;
pub mod error;
pub mod import_export;
pub mod lifecycle;
pub mod policy;
pub mod simulation;
pub mod version;

pub use audit::{PolicyExtAuditEvent, PolicyExtAuditLog, PolicyExtEventType};
pub use binding::{
    BindingCoverage, FrameworkBinding, FrameworkBindingRegistry, FrameworkCoverageSummary,
};
pub use composition::{
    evaluate_rule_expression, ComposedEvaluation, ComposedPolicySet, CompositionStrategy,
    MatchedRule, PolicyComposer,
};
pub use conflict::{
    ConflictDetector, ConflictResolution, ConflictSeverity, ConflictType, PolicyConflict,
    ResolutionType,
};
pub use error::PolicyExtError;
pub use import_export::{PolicyExporter, PolicyFormat, PolicyImporter};
pub use lifecycle::{LifecycleManager, LifecycleTransition};
pub use policy::{
    ManagedPolicy, ManagedPolicyId, ManagedPolicyStore, PolicyAction, PolicyDomain, PolicyRule,
    PolicyStatus, PolicyVersion, RuleExpression,
};
pub use simulation::{
    PolicySimulator, SimulationImpact, SimulationResult, SimulationRisk, SimulationRun,
    SimulationTestCase,
};
pub use version::{
    ChangeType, PolicyChange, PolicyDiff, PolicySnapshot, PolicyVersionHistory, VersionStore,
};
