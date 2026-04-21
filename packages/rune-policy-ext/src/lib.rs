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

// ── Layer 2 modules ─────────────────────────────────────────────────
pub mod l2_conflict;
pub mod l2_dependency;
pub mod l2_hierarchy;
pub mod l2_simulation;
pub mod l2_temporal;
pub mod l2_versioning;

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

// ── Layer 2 re-exports ──────────────────────────────────────────────
pub use l2_conflict::{
    resolve_conflict, ConflictResolutionStrategy, L2ConflictDetector, L2ConflictResolution,
    L2ConflictSeverity, L2PolicyConflict, PolicyConflictType, PolicyEffect, PolicyRecord,
};
pub use l2_dependency::{
    CascadeImpact, DependencyIssue, DependencyIssueType, PolicyDependencyGraph,
};
pub use l2_hierarchy::{OverrideMode, PolicyHierarchyNode, PolicyHierarchyStore};
pub use l2_simulation::{
    analyze_impact, run_simulation, ImpactRisk, L2PolicySimulation, L2SimulationResult,
    L2SimulationStore, L2SimulationTestCase, PolicyImpactAnalysis,
};
pub use l2_temporal::{PolicyRecurrence, TemporalPolicy, TemporalPolicyScheduler};
pub use l2_versioning::{
    compute_policy_hash, L2PolicyVersion, L2PolicyVersionStatus, L2PolicyVersionStore,
    VersionChainVerification,
};

// ── Layer 3 modules ─────────────────────────────────────────────────
pub mod backend;
pub mod external_evaluator_integration;
pub mod package_composer;
pub mod package_registry;
pub mod policy_export;
pub mod policy_stream;
pub mod policy_validation;

// ── Layer 3 re-exports ──────────────────────────────────────────────
pub use backend::{
    InMemoryPolicyPackageBackend, PackageDependency, PolicyPackageBackend,
    PolicyPackageBackendInfo, StoredPackageSignature, StoredPolicyEvaluationRecord,
    StoredPolicyPackage, StoredRuleSet,
};
pub use external_evaluator_integration::{
    EvaluationHandle, EvaluationPayload, EvaluationResult, EvaluatorType,
    ExternalEvaluatorIntegration, InMemoryExternalEvaluatorIntegration,
    NullExternalEvaluatorIntegration,
};
pub use package_composer::{
    ComposedPackage, InMemoryPolicyPackageComposer, NullPolicyPackageComposer,
    OverridePolicyPackageComposer, PackageCompositionStrategy, PackageConflictCategory,
    PackageConflictResolutionStrategy, PackagePolicyConflict, PolicyPackageComposer,
    UnionPolicyPackageComposer,
};
pub use package_registry::{
    CachedPolicyPackageRegistry, InMemoryPolicyPackageRegistry, NullPolicyPackageRegistry,
    PackageQuery, PolicyPackageRegistry, ReadOnlyPolicyPackageRegistry, RegistryCredentials,
    SubscriptionHandle,
};
pub use policy_export::{
    CedarPolicyExporter, JsonPolicyPackageExporter, OpaBundleExporter,
    PolicyPackageExporter, SignedBundleManifestExporter, XacmlPolicySetExporter,
};
pub use policy_stream::{
    FilteredPolicyLifecycleEventSubscriber, PolicyLifecycleEvent,
    PolicyLifecycleEventCollector, PolicyLifecycleEventSubscriber,
    PolicyLifecycleEventSubscriberRegistry, PolicyLifecycleEventType,
};
pub use policy_validation::{
    CompositePackageValidator, NullPolicyPackageValidator, PackageValidationReport,
    PolicyPackageValidator, SecurityPackageValidator, SyntacticPackageValidator,
    ValidationCheckCategory, ValidationCheckResult, ValidationSeverity,
};
