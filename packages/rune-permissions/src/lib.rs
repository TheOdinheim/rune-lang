// ═══════════════════════════════════════════════════════════════════════
// rune-permissions — Capability-Based Permission System
//
// Type-safe, auditable RBAC engine for the RUNE governance ecosystem.
// Every operation in Tiers 2-5 checks permissions through this crate.
//
// Design principles:
//   - Zero Trust Throughout: all access requires explicit permission
//   - Security Baked In: classification levels and conditions enforced
//   - Assumed Breach: audit log records every access check
//   - No Single Points of Failure: multiple role paths, direct grants
//
// Architecture:
//   types.rs    — Permission, Action, Resource, Subject, Classification
//   role.rs     — Role, RoleHierarchy, RoleAssignment
//   rbac.rs     — RbacEngine, AccessRequest, access evaluation
//   grant.rs    — Direct grants with conditions and usage tracking
//   context.rs  — Evaluation context (who, when, where, risk)
//   decision.rs — AccessDecision, NearestMiss, evaluation trace
//   error.rs    — PermissionError variants
//   store.rs    — Unified PermissionStore with audit logging
// ═══════════════════════════════════════════════════════════════════════

pub mod types;
pub mod role;
pub mod rbac;
pub mod grant;
pub mod context;
pub mod decision;
pub mod error;
pub mod store;
pub mod audit;
pub mod backend;
pub mod decision_engine;
pub mod policy_export;
pub mod decision_stream;
pub mod external_evaluator;
pub mod role_provider;
pub mod capability_verifier;

pub use types::{
    Action, ClassificationLevel, Condition, Permission, PermissionId,
    Pillar, ResourcePattern, Subject, SubjectId, SubjectType,
};
pub use role::{Role, RoleAssignment, RoleHierarchy, RoleId};
pub use rbac::{AccessRequest, RbacEngine};
pub use grant::{Grant, GrantId, GrantStore};
pub use context::EvalContext;
pub use decision::{AccessDecision, DetailedAccessDecision, EvaluationStep, FailedCheck, NearestMiss};
pub use error::PermissionError;
pub use audit::{PermissionsAuditEvent, PermissionsAuditLog};
pub use store::{
    BulkGrantResult, CascadeResult, DelegationNode, EffectivePermission,
    EvaluationCache, EvaluationStats, GrantIndex, GrantRequest, LeastPrivilegeReport,
    PermissionEvent, PermissionEventType, PermissionSnapshot, PermissionSource,
    PermissionStore, RestoreResult, RoleComparison, RoleConflict, RoleConflictType,
    SimulationResult, SimulationRisk, SodCheckResult, SodEnforcement, SodPolicy,
    SodViolation, TemporalDelegation,
};

// ── Layer 3 re-exports ──────────────────────────────────────────────

pub use backend::{
    PermissionBackend, InMemoryPermissionBackend, IdentityRef, RoleRef,
    StoredPolicyDefinition, StoredRoleDefinition, PermissionGrantRecord, PermissionBackendInfo,
};
pub use decision_engine::{
    AuthorizationDecisionEngine, AuthorizationRequest, AuthorizationDecision, EngineType,
    RbacDecisionEngine, AbacDecisionEngine, DenyAllDecisionEngine, AllowAllDecisionEngine,
    AttributeRule,
};
pub use policy_export::{
    PolicyExporter, RegoExporter, CedarExporter, XacmlExporter, OpaBundleExporter,
    JsonPolicyExporter,
};
pub use decision_stream::{
    DecisionSubscriber, DecisionSubscriberRegistry, DecisionCollector,
    FilteredDecisionSubscriber, DecisionLifecycleEvent, DecisionLifecycleEventType,
};
pub use external_evaluator::{
    ExternalPolicyEvaluator, ExternalEvaluatorType, ExternalEvaluationResult,
    NullExternalEvaluator, RecordingExternalEvaluator,
};
pub use role_provider::{
    RoleProvider, InMemoryRoleProvider, CachedRoleProvider,
};
pub use capability_verifier::{
    CapabilityVerifier, CapabilityToken, RequiredCapability, CapabilityVerificationResult,
    HmacSha3CapabilityVerifier, ExpiryAwareCapabilityVerifier, NullCapabilityVerifier,
};
