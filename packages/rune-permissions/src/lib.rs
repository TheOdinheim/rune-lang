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
pub use store::{PermissionEvent, PermissionEventType, PermissionStore};
