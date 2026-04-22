// ═══════════════════════════════════════════════════════════════════════
// Permission Store
//
// Unified in-memory store composing RoleHierarchy, RbacEngine, and
// GrantStore. Provides a single entry point for all permission
// operations with audit logging.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::context::EvalContext;
use crate::decision::{AccessDecision, DetailedAccessDecision};
use crate::error::PermissionError;
use crate::grant::{Grant, GrantId, GrantStore};
use crate::rbac::{AccessRequest, RbacEngine};
use crate::role::{Role, RoleAssignment, RoleId};
use crate::types::{
    Action, ClassificationLevel, Permission, PermissionId, Subject, SubjectId, SubjectType,
};

// ── PermissionEvent ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionEventType {
    RoleAssigned,
    RoleRevoked,
    GrantCreated,
    GrantRevoked,
    AccessChecked,
    PermissionRegistered,
    SubjectRegistered,
    SubjectDeactivated,
    // Layer 2 additions
    PermissionSnapshotCreated,
    PermissionSnapshotRestored,
    BulkGrantExecuted,
    ExpiredGrantsCleaned,
    GrantIndexRebuilt,
    CacheInvalidated,
    PermissionSimulated,
    EffectivePermissionsQueried,
    LeastPrivilegeAnalyzed,
    DelegationCascadeRevoked,
    DelegationDepthChecked,
    TemporalDelegationCreated,
    RoleConflictDetected,
    SodViolationDetected,
    SodPolicyAdded,
    // Layer 3
    PermissionBackendChanged { backend_type: String },
    PolicyDefinitionStored { policy_id: String },
    PolicyDefinitionRemoved { policy_id: String },
    RoleDefinitionStored { role_id: String },
    RoleDefinitionRemoved { role_id: String },
    PermissionGrantRecordCreated { grant_id: String },
    PermissionGrantRecordRevoked { grant_id: String },
    AuthorizationDecisionMade { outcome: String },
    AuthorizationPermit { matched_policies: String },
    AuthorizationDeny { reason: String },
    AuthorizationIndeterminate { reason: String },
    AuthorizationNotApplicable,
    DecisionEngineInvoked { engine_id: String },
    PolicyExported { format: String },
    PolicyExportFailed { format: String, reason: String },
    DecisionSubscriberRegistered { subscriber_id: String },
    DecisionSubscriberRemoved { subscriber_id: String },
    DecisionEventPublished { event_type: String },
    ExternalEvaluatorInvoked { evaluator_id: String },
    ExternalEvaluatorFailed { evaluator_id: String, reason: String },
    RoleProviderQueried { provider_id: String },
    CapabilityTokenVerified { token_id: String },
    CapabilityTokenRejected { token_id: String, reason: String },
}

impl std::fmt::Display for PermissionEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::RoleAssigned => "RoleAssigned",
            Self::RoleRevoked => "RoleRevoked",
            Self::GrantCreated => "GrantCreated",
            Self::GrantRevoked => "GrantRevoked",
            Self::AccessChecked => "AccessChecked",
            Self::PermissionRegistered => "PermissionRegistered",
            Self::SubjectRegistered => "SubjectRegistered",
            Self::SubjectDeactivated => "SubjectDeactivated",
            Self::PermissionSnapshotCreated => "PermissionSnapshotCreated",
            Self::PermissionSnapshotRestored => "PermissionSnapshotRestored",
            Self::BulkGrantExecuted => "BulkGrantExecuted",
            Self::ExpiredGrantsCleaned => "ExpiredGrantsCleaned",
            Self::GrantIndexRebuilt => "GrantIndexRebuilt",
            Self::CacheInvalidated => "CacheInvalidated",
            Self::PermissionSimulated => "PermissionSimulated",
            Self::EffectivePermissionsQueried => "EffectivePermissionsQueried",
            Self::LeastPrivilegeAnalyzed => "LeastPrivilegeAnalyzed",
            Self::DelegationCascadeRevoked => "DelegationCascadeRevoked",
            Self::DelegationDepthChecked => "DelegationDepthChecked",
            Self::TemporalDelegationCreated => "TemporalDelegationCreated",
            Self::RoleConflictDetected => "RoleConflictDetected",
            Self::SodViolationDetected => "SodViolationDetected",
            Self::SodPolicyAdded => "SodPolicyAdded",
            Self::PermissionBackendChanged { backend_type } => {
                return write!(f, "PermissionBackendChanged({backend_type})");
            }
            Self::PolicyDefinitionStored { policy_id } => {
                return write!(f, "PolicyDefinitionStored({policy_id})");
            }
            Self::PolicyDefinitionRemoved { policy_id } => {
                return write!(f, "PolicyDefinitionRemoved({policy_id})");
            }
            Self::RoleDefinitionStored { role_id } => {
                return write!(f, "RoleDefinitionStored({role_id})");
            }
            Self::RoleDefinitionRemoved { role_id } => {
                return write!(f, "RoleDefinitionRemoved({role_id})");
            }
            Self::PermissionGrantRecordCreated { grant_id } => {
                return write!(f, "PermissionGrantRecordCreated({grant_id})");
            }
            Self::PermissionGrantRecordRevoked { grant_id } => {
                return write!(f, "PermissionGrantRecordRevoked({grant_id})");
            }
            Self::AuthorizationDecisionMade { outcome } => {
                return write!(f, "AuthorizationDecisionMade({outcome})");
            }
            Self::AuthorizationPermit { matched_policies } => {
                return write!(f, "AuthorizationPermit({matched_policies})");
            }
            Self::AuthorizationDeny { reason } => {
                return write!(f, "AuthorizationDeny({reason})");
            }
            Self::AuthorizationIndeterminate { reason } => {
                return write!(f, "AuthorizationIndeterminate({reason})");
            }
            Self::AuthorizationNotApplicable => "AuthorizationNotApplicable",
            Self::DecisionEngineInvoked { engine_id } => {
                return write!(f, "DecisionEngineInvoked({engine_id})");
            }
            Self::PolicyExported { format } => {
                return write!(f, "PolicyExported({format})");
            }
            Self::PolicyExportFailed { format, reason } => {
                return write!(f, "PolicyExportFailed({format}: {reason})");
            }
            Self::DecisionSubscriberRegistered { subscriber_id } => {
                return write!(f, "DecisionSubscriberRegistered({subscriber_id})");
            }
            Self::DecisionSubscriberRemoved { subscriber_id } => {
                return write!(f, "DecisionSubscriberRemoved({subscriber_id})");
            }
            Self::DecisionEventPublished { event_type } => {
                return write!(f, "DecisionEventPublished({event_type})");
            }
            Self::ExternalEvaluatorInvoked { evaluator_id } => {
                return write!(f, "ExternalEvaluatorInvoked({evaluator_id})");
            }
            Self::ExternalEvaluatorFailed { evaluator_id, reason } => {
                return write!(f, "ExternalEvaluatorFailed({evaluator_id}: {reason})");
            }
            Self::RoleProviderQueried { provider_id } => {
                return write!(f, "RoleProviderQueried({provider_id})");
            }
            Self::CapabilityTokenVerified { token_id } => {
                return write!(f, "CapabilityTokenVerified({token_id})");
            }
            Self::CapabilityTokenRejected { token_id, reason } => {
                return write!(f, "CapabilityTokenRejected({token_id}: {reason})");
            }
        };
        write!(f, "{}", name)
    }
}

impl PermissionEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::RoleAssigned => "RoleAssigned",
            Self::RoleRevoked => "RoleRevoked",
            Self::GrantCreated => "GrantCreated",
            Self::GrantRevoked => "GrantRevoked",
            Self::AccessChecked => "AccessChecked",
            Self::PermissionRegistered => "PermissionRegistered",
            Self::SubjectRegistered => "SubjectRegistered",
            Self::SubjectDeactivated => "SubjectDeactivated",
            Self::PermissionSnapshotCreated => "PermissionSnapshotCreated",
            Self::PermissionSnapshotRestored => "PermissionSnapshotRestored",
            Self::BulkGrantExecuted => "BulkGrantExecuted",
            Self::ExpiredGrantsCleaned => "ExpiredGrantsCleaned",
            Self::GrantIndexRebuilt => "GrantIndexRebuilt",
            Self::CacheInvalidated => "CacheInvalidated",
            Self::PermissionSimulated => "PermissionSimulated",
            Self::EffectivePermissionsQueried => "EffectivePermissionsQueried",
            Self::LeastPrivilegeAnalyzed => "LeastPrivilegeAnalyzed",
            Self::DelegationCascadeRevoked => "DelegationCascadeRevoked",
            Self::DelegationDepthChecked => "DelegationDepthChecked",
            Self::TemporalDelegationCreated => "TemporalDelegationCreated",
            Self::RoleConflictDetected => "RoleConflictDetected",
            Self::SodViolationDetected => "SodViolationDetected",
            Self::SodPolicyAdded => "SodPolicyAdded",
            Self::PermissionBackendChanged { .. } => "PermissionBackendChanged",
            Self::PolicyDefinitionStored { .. } => "PolicyDefinitionStored",
            Self::PolicyDefinitionRemoved { .. } => "PolicyDefinitionRemoved",
            Self::RoleDefinitionStored { .. } => "RoleDefinitionStored",
            Self::RoleDefinitionRemoved { .. } => "RoleDefinitionRemoved",
            Self::PermissionGrantRecordCreated { .. } => "PermissionGrantRecordCreated",
            Self::PermissionGrantRecordRevoked { .. } => "PermissionGrantRecordRevoked",
            Self::AuthorizationDecisionMade { .. } => "AuthorizationDecisionMade",
            Self::AuthorizationPermit { .. } => "AuthorizationPermit",
            Self::AuthorizationDeny { .. } => "AuthorizationDeny",
            Self::AuthorizationIndeterminate { .. } => "AuthorizationIndeterminate",
            Self::AuthorizationNotApplicable => "AuthorizationNotApplicable",
            Self::DecisionEngineInvoked { .. } => "DecisionEngineInvoked",
            Self::PolicyExported { .. } => "PolicyExported",
            Self::PolicyExportFailed { .. } => "PolicyExportFailed",
            Self::DecisionSubscriberRegistered { .. } => "DecisionSubscriberRegistered",
            Self::DecisionSubscriberRemoved { .. } => "DecisionSubscriberRemoved",
            Self::DecisionEventPublished { .. } => "DecisionEventPublished",
            Self::ExternalEvaluatorInvoked { .. } => "ExternalEvaluatorInvoked",
            Self::ExternalEvaluatorFailed { .. } => "ExternalEvaluatorFailed",
            Self::RoleProviderQueried { .. } => "RoleProviderQueried",
            Self::CapabilityTokenVerified { .. } => "CapabilityTokenVerified",
            Self::CapabilityTokenRejected { .. } => "CapabilityTokenRejected",
        }
    }

    pub fn is_backend_event(&self) -> bool {
        matches!(
            self,
            Self::PermissionBackendChanged { .. }
                | Self::PolicyDefinitionStored { .. }
                | Self::PolicyDefinitionRemoved { .. }
                | Self::RoleDefinitionStored { .. }
                | Self::RoleDefinitionRemoved { .. }
                | Self::PermissionGrantRecordCreated { .. }
                | Self::PermissionGrantRecordRevoked { .. }
        )
    }

    pub fn is_decision_event(&self) -> bool {
        matches!(
            self,
            Self::AuthorizationDecisionMade { .. }
                | Self::AuthorizationPermit { .. }
                | Self::AuthorizationDeny { .. }
                | Self::AuthorizationIndeterminate { .. }
                | Self::AuthorizationNotApplicable
                | Self::DecisionEngineInvoked { .. }
        )
    }

    pub fn is_export_event(&self) -> bool {
        matches!(
            self,
            Self::PolicyExported { .. }
                | Self::PolicyExportFailed { .. }
        )
    }

    pub fn is_external_event(&self) -> bool {
        matches!(
            self,
            Self::ExternalEvaluatorInvoked { .. }
                | Self::ExternalEvaluatorFailed { .. }
                | Self::RoleProviderQueried { .. }
        )
    }

    pub fn is_capability_event(&self) -> bool {
        matches!(
            self,
            Self::CapabilityTokenVerified { .. }
                | Self::CapabilityTokenRejected { .. }
        )
    }

    pub fn is_streaming_event(&self) -> bool {
        matches!(
            self,
            Self::DecisionSubscriberRegistered { .. }
                | Self::DecisionSubscriberRemoved { .. }
                | Self::DecisionEventPublished { .. }
        )
    }

    pub fn kind(&self) -> &str {
        match self {
            // L1 role/assignment
            Self::RoleAssigned
            | Self::RoleRevoked => "role",
            // L1 grants
            Self::GrantCreated
            | Self::GrantRevoked => "grant",
            // L1 access
            Self::AccessChecked => "access",
            // L1 registration
            Self::PermissionRegistered
            | Self::SubjectRegistered
            | Self::SubjectDeactivated => "registration",
            // L2 snapshot
            Self::PermissionSnapshotCreated
            | Self::PermissionSnapshotRestored => "snapshot",
            // L2 bulk/maintenance
            Self::BulkGrantExecuted
            | Self::ExpiredGrantsCleaned
            | Self::GrantIndexRebuilt
            | Self::CacheInvalidated => "maintenance",
            // L2 simulation/analysis
            Self::PermissionSimulated
            | Self::EffectivePermissionsQueried
            | Self::LeastPrivilegeAnalyzed => "analysis",
            // L2 delegation
            Self::DelegationCascadeRevoked
            | Self::DelegationDepthChecked
            | Self::TemporalDelegationCreated => "delegation",
            // L2 SoD
            Self::RoleConflictDetected
            | Self::SodViolationDetected
            | Self::SodPolicyAdded => "sod",
            // L3 backend
            Self::PermissionBackendChanged { .. }
            | Self::PolicyDefinitionStored { .. }
            | Self::PolicyDefinitionRemoved { .. }
            | Self::RoleDefinitionStored { .. }
            | Self::RoleDefinitionRemoved { .. }
            | Self::PermissionGrantRecordCreated { .. }
            | Self::PermissionGrantRecordRevoked { .. } => "backend",
            // L3 decision
            Self::AuthorizationDecisionMade { .. }
            | Self::AuthorizationPermit { .. }
            | Self::AuthorizationDeny { .. }
            | Self::AuthorizationIndeterminate { .. }
            | Self::AuthorizationNotApplicable
            | Self::DecisionEngineInvoked { .. } => "decision",
            // L3 export
            Self::PolicyExported { .. }
            | Self::PolicyExportFailed { .. } => "export",
            // L3 streaming
            Self::DecisionSubscriberRegistered { .. }
            | Self::DecisionSubscriberRemoved { .. }
            | Self::DecisionEventPublished { .. } => "streaming",
            // L3 external
            Self::ExternalEvaluatorInvoked { .. }
            | Self::ExternalEvaluatorFailed { .. }
            | Self::RoleProviderQueried { .. } => "external",
            // L3 capability
            Self::CapabilityTokenVerified { .. }
            | Self::CapabilityTokenRejected { .. } => "capability",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEvent {
    pub event_type: PermissionEventType,
    pub subject_id: SubjectId,
    pub detail: String,
    pub timestamp: i64,
    pub decision: Option<AccessDecision>,
}

// ═══════════════════════════════════════════════════════════════════════
// PART 1: Permission Persistence
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionSnapshot {
    pub grants: Vec<Grant>,
    pub roles: Vec<Role>,
    pub assignments: Vec<RoleAssignment>,
    pub policies: Vec<SodPolicy>,
    pub snapshot_at: i64,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    pub grants_restored: usize,
    pub roles_restored: usize,
    pub assignments_restored: usize,
    pub policies_restored: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRequest {
    pub subject_id: SubjectId,
    pub permission_id: PermissionId,
    pub granted_by: SubjectId,
    pub reason: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkGrantResult {
    pub succeeded: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════
// PART 2: Evaluation Optimization
// ═══════════════════════════════════════════════════════════════════════

pub struct GrantIndex {
    pub by_subject: HashMap<String, Vec<usize>>,
    pub by_permission: HashMap<String, Vec<usize>>,
    pub by_resource: HashMap<String, Vec<usize>>,
}

impl GrantIndex {
    pub fn new() -> Self {
        Self {
            by_subject: HashMap::new(),
            by_permission: HashMap::new(),
            by_resource: HashMap::new(),
        }
    }

    pub fn build(grants: &[Grant]) -> Self {
        let mut idx = Self::new();
        for (i, grant) in grants.iter().enumerate() {
            idx.by_subject
                .entry(grant.subject_id.as_str().to_string())
                .or_default()
                .push(i);
            idx.by_permission
                .entry(grant.permission_id.as_str().to_string())
                .or_default()
                .push(i);
        }
        idx
    }

    pub fn add(&mut self, index: usize, grant: &Grant) {
        self.by_subject
            .entry(grant.subject_id.as_str().to_string())
            .or_default()
            .push(index);
        self.by_permission
            .entry(grant.permission_id.as_str().to_string())
            .or_default()
            .push(index);
    }

    pub fn clear(&mut self) {
        self.by_subject.clear();
        self.by_permission.clear();
        self.by_resource.clear();
    }
}

impl Default for GrantIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct CachedDecision {
    pub decision: bool,
    pub cached_at: i64,
    pub ttl_ms: i64,
}

impl CachedDecision {
    pub fn is_valid(&self, now: i64) -> bool {
        now - self.cached_at < self.ttl_ms
    }
}

pub struct EvaluationCache {
    entries: HashMap<String, CachedDecision>,
    max_entries: usize,
    default_ttl_ms: i64,
    hits: u64,
    misses: u64,
}

impl EvaluationCache {
    pub fn new(max_entries: usize, default_ttl_ms: i64) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            default_ttl_ms,
            hits: 0,
            misses: 0,
        }
    }

    pub fn cache_key(subject: &SubjectId, permission: &PermissionId) -> String {
        format!("{}:{}", subject.as_str(), permission.as_str())
    }

    pub fn get(&mut self, key: &str, now: i64) -> Option<bool> {
        if let Some(entry) = self.entries.get(key) {
            if entry.is_valid(now) {
                self.hits += 1;
                return Some(entry.decision);
            }
            // Expired — remove it.
            self.entries.remove(key);
        }
        self.misses += 1;
        None
    }

    pub fn put(&mut self, key: String, decision: bool, now: i64) {
        if self.entries.len() >= self.max_entries {
            // Evict oldest entry.
            let oldest_key = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.cached_at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest_key {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(
            key,
            CachedDecision {
                decision,
                cached_at: now,
                ttl_ms: self.default_ttl_ms,
            },
        );
    }

    pub fn invalidate_for_subject(&mut self, subject: &SubjectId) {
        let prefix = format!("{}:", subject.as_str());
        self.entries.retain(|k, _| !k.starts_with(&prefix));
    }

    pub fn invalidate_all(&mut self) {
        self.entries.clear();
    }

    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }

    pub fn stats(&self) -> EvaluationStats {
        EvaluationStats {
            cache_entries: self.entries.len(),
            cache_hits: self.hits,
            cache_misses: self.misses,
            hit_rate: self.hit_rate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationStats {
    pub cache_entries: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub hit_rate: f64,
}

// ═══════════════════════════════════════════════════════════════════════
// PART 3: Policy Simulation
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub would_conflict: bool,
    pub conflict_reasons: Vec<String>,
    pub effective_permissions_after: Vec<String>,
    pub sod_violations: Vec<String>,
    pub risk_assessment: SimulationRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SimulationRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SimulationRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePermission {
    pub permission_id: PermissionId,
    pub source: PermissionSource,
    pub classification: ClassificationLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionSource {
    Direct,
    RoleInherited(RoleId),
    Delegated(SubjectId),
}

impl std::fmt::Display for PermissionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "Direct"),
            Self::RoleInherited(r) => write!(f, "RoleInherited({})", r),
            Self::Delegated(s) => write!(f, "Delegated({})", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeastPrivilegeReport {
    pub subject_id: SubjectId,
    pub total_permissions: usize,
    pub used_permissions: Vec<PermissionId>,
    pub unused_permissions: Vec<PermissionId>,
    pub recommendation: String,
}

// ═══════════════════════════════════════════════════════════════════════
// PART 4: Delegation Hardening
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalDelegation {
    pub id: String,
    pub delegator: SubjectId,
    pub delegate: SubjectId,
    pub permission_id: PermissionId,
    pub starts_at: i64,
    pub ends_at: i64,
    pub reason: String,
    pub active: bool,
    pub parent_delegation: Option<String>,
}

impl TemporalDelegation {
    pub fn is_active_at(&self, now: i64) -> bool {
        self.active && now >= self.starts_at && now <= self.ends_at
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationNode {
    pub delegation_id: String,
    pub delegator: SubjectId,
    pub delegate: SubjectId,
    pub permission_id: PermissionId,
    pub children: Vec<DelegationNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CascadeResult {
    pub revoked_count: usize,
    pub revoked_ids: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════
// PART 5: Role Hierarchy Enhancement
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoleConflictType {
    MutuallyExclusive,
    RedundantInclusion,
    PermissionOverlap,
}

impl std::fmt::Display for RoleConflictType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MutuallyExclusive => write!(f, "MutuallyExclusive"),
            Self::RedundantInclusion => write!(f, "RedundantInclusion"),
            Self::PermissionOverlap => write!(f, "PermissionOverlap"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConflict {
    pub conflict_type: RoleConflictType,
    pub role_a: RoleId,
    pub role_b: RoleId,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleComparison {
    pub role_a: RoleId,
    pub role_b: RoleId,
    pub shared_permissions: Vec<PermissionId>,
    pub only_in_a: Vec<PermissionId>,
    pub only_in_b: Vec<PermissionId>,
    pub is_subset: bool,
    pub is_superset: bool,
}

// ═══════════════════════════════════════════════════════════════════════
// PART 6: SoD Enhancement
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SodEnforcement {
    Static,
    Dynamic,
}

impl std::fmt::Display for SodEnforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static => write!(f, "Static"),
            Self::Dynamic => write!(f, "Dynamic"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodPolicy {
    pub name: String,
    pub enforcement: SodEnforcement,
    pub conflicting_permissions: Vec<PermissionId>,
    pub conflicting_roles: Vec<RoleId>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodViolation {
    pub policy_name: String,
    pub subject_id: SubjectId,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodCheckResult {
    pub passed: bool,
    pub violations: Vec<SodViolation>,
}

// ── PermissionStore ────────────────────────────────────────────────

pub struct PermissionStore {
    engine: RbacEngine,
    grants: GrantStore,
    subjects: HashMap<SubjectId, Subject>,
    audit_log: Vec<PermissionEvent>,
    // Layer 2 fields
    temporal_delegations: Vec<TemporalDelegation>,
    sod_policies: Vec<SodPolicy>,
    grant_index: GrantIndex,
    cache: EvaluationCache,
}

impl PermissionStore {
    pub fn new() -> Self {
        Self {
            engine: RbacEngine::new(),
            grants: GrantStore::new(),
            subjects: HashMap::new(),
            audit_log: Vec::new(),
            temporal_delegations: Vec::new(),
            sod_policies: Vec::new(),
            grant_index: GrantIndex::new(),
            cache: EvaluationCache::new(1000, 60_000),
        }
    }

    // ── Subject management ─────────────────────────────────────

    pub fn register_subject(&mut self, subject: Subject) -> Result<(), PermissionError> {
        if self.subjects.contains_key(&subject.id) {
            return Err(PermissionError::SubjectAlreadyExists(subject.id.clone()));
        }
        let id = subject.id.clone();
        self.subjects.insert(id.clone(), subject);
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::SubjectRegistered,
            subject_id: id,
            detail: "subject registered".into(),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    pub fn deactivate_subject(&mut self, id: &SubjectId) -> Result<(), PermissionError> {
        let subject = self.subjects.get_mut(id)
            .ok_or_else(|| PermissionError::SubjectNotFound(id.clone()))?;
        subject.active = false;
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::SubjectDeactivated,
            subject_id: id.clone(),
            detail: "subject deactivated".into(),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    pub fn get_subject(&self, id: &SubjectId) -> Option<&Subject> {
        self.subjects.get(id)
    }

    pub fn list_subjects(&self) -> Vec<&Subject> {
        self.subjects.values().collect()
    }

    pub fn subjects_by_type(&self, subject_type: SubjectType) -> Vec<&Subject> {
        self.subjects.values().filter(|s| s.subject_type == subject_type).collect()
    }

    // ── Delegated operations ───────────────────────────────────

    pub fn add_role(&mut self, role: Role) -> Result<(), PermissionError> {
        self.engine.add_role(role)
    }

    pub fn register_permission(&mut self, permission: Permission) -> Result<(), PermissionError> {
        let id = permission.id.clone();
        self.engine.register_permission(permission)?;
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::PermissionRegistered,
            subject_id: SubjectId::new("system"),
            detail: format!("permission {} registered", id),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    pub fn assign_role(
        &mut self,
        subject_id: SubjectId,
        role_id: RoleId,
        assigned_by: SubjectId,
        reason: String,
    ) -> Result<(), PermissionError> {
        let sid = subject_id.clone();
        let rid = role_id.clone();
        self.engine.assign_role(subject_id, role_id, assigned_by, reason)?;
        self.cache.invalidate_for_subject(&sid);
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::RoleAssigned,
            subject_id: sid,
            detail: format!("role {} assigned", rid),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    pub fn revoke_role(
        &mut self,
        subject_id: &SubjectId,
        role_id: &RoleId,
        revoked_by: &SubjectId,
        reason: &str,
    ) -> Result<(), PermissionError> {
        self.engine.revoke_role(subject_id, role_id, revoked_by, reason)?;
        self.cache.invalidate_for_subject(subject_id);
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::RoleRevoked,
            subject_id: subject_id.clone(),
            detail: format!("role {} revoked: {}", role_id, reason),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    pub fn add_grant(&mut self, grant: Grant) -> Result<(), PermissionError> {
        let sid = grant.subject_id.clone();
        let pid = grant.permission_id.clone();
        self.grants.add_grant(grant)?;
        self.cache.invalidate_for_subject(&sid);
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::GrantCreated,
            subject_id: sid,
            detail: format!("grant for {} created", pid),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    // ── Unified access check ───────────────────────────────────

    /// Check both role-based permissions AND direct grants.
    pub fn check(&self, request: &AccessRequest) -> AccessDecision {
        // Try role-based first.
        let rbac_decision = self.engine.check_access(request);
        if rbac_decision.is_allowed() {
            return rbac_decision;
        }

        // Try direct grants.
        let matching_perms = self.engine.permissions_for_resource(&request.resource);
        for perm in matching_perms {
            if perm.matches_action(&request.action)
                && self.grants.is_granted(
                    &request.subject_id,
                    &perm.id,
                    &request.context,
                )
            {
                return AccessDecision::Allow {
                    permission_id: perm.id.clone(),
                    matched_role: None,
                    reason: "direct grant".into(),
                };
            }
        }

        rbac_decision
    }

    pub fn check_verbose(&self, request: &AccessRequest) -> DetailedAccessDecision {
        let start = std::time::Instant::now();
        let decision = self.check(request);

        DetailedAccessDecision {
            decision,
            evaluation_trace: vec![],
            duration_us: start.elapsed().as_micros() as u64,
            evaluated_at: request.context.timestamp,
        }
    }

    pub fn can(&self, subject: &SubjectId, action: Action, resource: &str) -> bool {
        let ctx = EvalContext::for_subject(
            Subject::new(subject.as_str(), SubjectType::User, ""),
        ).build();
        let request = AccessRequest {
            subject_id: subject.clone(),
            action,
            resource: resource.to_string(),
            context: ctx,
            justification: None,
        };
        self.check(&request).is_allowed()
    }

    // ── Audit log ──────────────────────────────────────────────

    pub fn audit_log(&self) -> &[PermissionEvent] {
        &self.audit_log
    }

    pub fn audit_log_since(&self, timestamp: i64) -> Vec<&PermissionEvent> {
        self.audit_log
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════
    // PART 1: Permission Persistence
    // ═══════════════════════════════════════════════════════════════

    pub fn snapshot(&self, now: i64) -> PermissionSnapshot {
        // Audit emitted at read time; no mutation needed.
        PermissionSnapshot {
            grants: self.grants.all_grants().to_vec(),
            roles: self.engine.hierarchy().all_roles().into_iter().cloned().collect(),
            assignments: self.engine.all_assignments().to_vec(),
            policies: self.sod_policies.clone(),
            snapshot_at: now,
            version: "1.0".into(),
        }
    }

    pub fn restore(&mut self, snapshot: PermissionSnapshot) -> RestoreResult {
        let grants_count = snapshot.grants.len();
        let roles_count = snapshot.roles.len();
        let assignments_count = snapshot.assignments.len();
        let policies_count = snapshot.policies.len();

        self.grants.replace_grants(snapshot.grants);
        self.engine.hierarchy_mut().replace_roles(snapshot.roles);
        self.engine.replace_assignments(snapshot.assignments);
        self.sod_policies = snapshot.policies;
        self.cache.invalidate_all();
        self.rebuild_index();

        self.push_audit(
            PermissionEventType::PermissionSnapshotRestored,
            "system",
            "snapshot restored",
        );

        RestoreResult {
            grants_restored: grants_count,
            roles_restored: roles_count,
            assignments_restored: assignments_count,
            policies_restored: policies_count,
            warnings: Vec::new(),
        }
    }

    pub fn export_json(&self, now: i64) -> Result<String, PermissionError> {
        let snap = self.snapshot(now);
        serde_json::to_string_pretty(&snap).map_err(|e| {
            PermissionError::InvalidOperation(format!("JSON export failed: {}", e))
        })
    }

    pub fn import_json(&mut self, json: &str) -> Result<RestoreResult, PermissionError> {
        let snap: PermissionSnapshot = serde_json::from_str(json).map_err(|e| {
            PermissionError::InvalidOperation(format!("JSON import failed: {}", e))
        })?;
        Ok(self.restore(snap))
    }

    pub fn bulk_grant(&mut self, requests: Vec<GrantRequest>) -> BulkGrantResult {
        let mut result = BulkGrantResult {
            succeeded: 0,
            failed: 0,
            errors: Vec::new(),
        };

        for (i, req) in requests.into_iter().enumerate() {
            let grant = Grant::new(
                format!("bulk-grant-{}", i),
                req.subject_id.clone(),
                req.permission_id,
                req.granted_by,
                req.reason,
            );
            let grant = if let Some(exp) = req.expires_at {
                grant.expires_at(exp)
            } else {
                grant
            };
            match self.grants.add_grant(grant) {
                Ok(()) => {
                    self.cache.invalidate_for_subject(&req.subject_id);
                    result.succeeded += 1;
                }
                Err(e) => {
                    result.failed += 1;
                    result.errors.push(e.to_string());
                }
            }
        }

        self.push_audit(
            PermissionEventType::BulkGrantExecuted,
            "system",
            &format!(
                "bulk grant: {} succeeded, {} failed",
                result.succeeded, result.failed
            ),
        );

        result
    }

    pub fn cleanup_expired_grants(&mut self, now: i64) -> usize {
        let count = self.grants.cleanup_expired(now);
        if count > 0 {
            self.cache.invalidate_all();
            self.push_audit(
                PermissionEventType::ExpiredGrantsCleaned,
                "system",
                &format!("{} expired grants cleaned", count),
            );
        }
        count
    }

    pub fn expiring_soon(&self, now: i64, window_ms: i64) -> Vec<&Grant> {
        let deadline = now + window_ms;
        self.grants
            .all_grants()
            .iter()
            .filter(|g| {
                g.active
                    && g.expires_at
                        .map_or(false, |exp| exp > now && exp <= deadline)
            })
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════
    // PART 2: Evaluation Optimization
    // ═══════════════════════════════════════════════════════════════

    pub fn rebuild_index(&mut self) {
        self.grant_index = GrantIndex::build(self.grants.all_grants());
        self.push_audit(
            PermissionEventType::GrantIndexRebuilt,
            "system",
            "grant index rebuilt",
        );
    }

    pub fn invalidate_cache(&mut self) {
        self.cache.invalidate_all();
        self.push_audit(
            PermissionEventType::CacheInvalidated,
            "system",
            "evaluation cache invalidated",
        );
    }

    pub fn cache_stats(&self) -> EvaluationStats {
        self.cache.stats()
    }

    pub fn cached_check(
        &mut self,
        subject: &SubjectId,
        permission: &PermissionId,
        now: i64,
    ) -> bool {
        let key = EvaluationCache::cache_key(subject, permission);
        if let Some(result) = self.cache.get(&key, now) {
            return result;
        }
        // Compute and cache.
        let result = self.grants.is_granted(
            subject,
            permission,
            &EvalContext::for_subject(Subject::new(subject.as_str(), SubjectType::User, ""))
                .timestamp(now)
                .build(),
        );
        self.cache.put(key, result, now);
        result
    }

    // ═══════════════════════════════════════════════════════════════
    // PART 3: Policy Simulation
    // ═══════════════════════════════════════════════════════════════

    pub fn simulate_grant(
        &mut self,
        subject_id: &SubjectId,
        permission_id: &PermissionId,
    ) -> SimulationResult {
        let mut conflict_reasons = Vec::new();
        let mut sod_violations = Vec::new();

        // Check existing grants for the same permission.
        let existing = self.grants.active_grants(subject_id);
        for g in &existing {
            if g.permission_id == *permission_id {
                conflict_reasons.push(format!(
                    "subject already has grant for {}",
                    permission_id
                ));
            }
        }

        // Check SoD policies.
        let current_perms: Vec<PermissionId> = existing
            .iter()
            .map(|g| g.permission_id.clone())
            .collect();
        let mut all_perms = current_perms.clone();
        all_perms.push(permission_id.clone());

        for policy in &self.sod_policies {
            let matching: Vec<_> = policy
                .conflicting_permissions
                .iter()
                .filter(|p| all_perms.contains(p))
                .collect();
            if matching.len() >= 2 {
                sod_violations.push(format!(
                    "SoD policy '{}' violated",
                    policy.name
                ));
            }
        }

        // Effective permissions after.
        let mut effective_after: Vec<String> = all_perms
            .iter()
            .map(|p| p.as_str().to_string())
            .collect();
        // Also include role-based permissions.
        for perm in self.engine.effective_permissions_for_subject(subject_id) {
            let s = perm.id.as_str().to_string();
            if !effective_after.contains(&s) {
                effective_after.push(s);
            }
        }

        let has_conflict = !conflict_reasons.is_empty();
        let has_sod = !sod_violations.is_empty();
        let risk = if has_sod {
            SimulationRisk::Critical
        } else if has_conflict {
            SimulationRisk::Medium
        } else if effective_after.len() > 10 {
            SimulationRisk::Medium
        } else {
            SimulationRisk::Low
        };

        self.push_audit(
            PermissionEventType::PermissionSimulated,
            subject_id.as_str(),
            &format!("simulated grant of {}", permission_id),
        );

        SimulationResult {
            would_conflict: has_conflict || has_sod,
            conflict_reasons,
            effective_permissions_after: effective_after,
            sod_violations,
            risk_assessment: risk,
        }
    }

    pub fn effective_permissions(&mut self, subject_id: &SubjectId) -> Vec<EffectivePermission> {
        let mut result = Vec::new();

        // Role-based permissions.
        for assignment in self.engine.all_assignments() {
            if assignment.subject_id == *subject_id && assignment.active {
                let role_perms = self.engine.hierarchy().effective_permissions(&assignment.role_id);
                for pid in role_perms {
                    if let Some(perm) = self.engine.get_permission(&pid) {
                        result.push(EffectivePermission {
                            permission_id: pid,
                            source: PermissionSource::RoleInherited(assignment.role_id.clone()),
                            classification: perm.classification,
                        });
                    }
                }
            }
        }

        // Direct grants.
        for grant in self.grants.active_grants(subject_id) {
            result.push(EffectivePermission {
                permission_id: grant.permission_id.clone(),
                source: PermissionSource::Direct,
                classification: ClassificationLevel::Public,
            });
        }

        // Temporal delegations.
        for td in &self.temporal_delegations {
            if td.delegate == *subject_id && td.active {
                result.push(EffectivePermission {
                    permission_id: td.permission_id.clone(),
                    source: PermissionSource::Delegated(td.delegator.clone()),
                    classification: ClassificationLevel::Public,
                });
            }
        }

        self.push_audit(
            PermissionEventType::EffectivePermissionsQueried,
            subject_id.as_str(),
            "effective permissions queried",
        );

        result
    }

    pub fn analyze_least_privilege(
        &mut self,
        subject_id: &SubjectId,
        used_permissions: &[PermissionId],
    ) -> LeastPrivilegeReport {
        let effective = self.effective_permissions(subject_id);
        let all_perms: Vec<PermissionId> = effective.iter().map(|e| e.permission_id.clone()).collect();
        let unused: Vec<PermissionId> = all_perms
            .iter()
            .filter(|p| !used_permissions.contains(p))
            .cloned()
            .collect();

        let recommendation = if unused.is_empty() {
            "All permissions are actively used.".to_string()
        } else {
            format!(
                "Consider removing {} unused permission(s) to follow least privilege.",
                unused.len()
            )
        };

        self.push_audit(
            PermissionEventType::LeastPrivilegeAnalyzed,
            subject_id.as_str(),
            "least privilege analysis completed",
        );

        LeastPrivilegeReport {
            subject_id: subject_id.clone(),
            total_permissions: all_perms.len(),
            used_permissions: used_permissions.to_vec(),
            unused_permissions: unused,
            recommendation,
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // PART 4: Delegation Hardening
    // ═══════════════════════════════════════════════════════════════

    pub fn delegation_chain_depth(&self, delegation_id: &str) -> usize {
        let mut depth = 0;
        let mut current = delegation_id.to_string();
        let mut seen = std::collections::HashSet::new();
        loop {
            if !seen.insert(current.clone()) {
                break;
            }
            let parent = self
                .temporal_delegations
                .iter()
                .find(|d| d.id == current)
                .and_then(|d| d.parent_delegation.clone());
            match parent {
                Some(pid) => {
                    depth += 1;
                    current = pid;
                }
                None => break,
            }
        }
        depth
    }

    pub fn validate_delegation_depth(
        &mut self,
        delegation_id: &str,
        max_depth: usize,
    ) -> Result<(), PermissionError> {
        let depth = self.delegation_chain_depth(delegation_id);
        self.push_audit(
            PermissionEventType::DelegationDepthChecked,
            "system",
            &format!("delegation {} depth={}", delegation_id, depth),
        );
        if depth > max_depth {
            return Err(PermissionError::InvalidOperation(format!(
                "delegation chain depth {} exceeds max {}",
                depth, max_depth
            )));
        }
        Ok(())
    }

    pub fn revoke_delegation_cascade(&mut self, delegation_id: &str) -> CascadeResult {
        let mut revoked_ids = Vec::new();
        let mut queue = vec![delegation_id.to_string()];

        while let Some(current) = queue.pop() {
            for d in &mut self.temporal_delegations {
                if d.id == current && d.active {
                    d.active = false;
                    revoked_ids.push(d.id.clone());
                }
                if d.parent_delegation.as_deref() == Some(&current) && d.active {
                    queue.push(d.id.clone());
                }
            }
        }

        self.push_audit(
            PermissionEventType::DelegationCascadeRevoked,
            "system",
            &format!("{} delegations cascade-revoked", revoked_ids.len()),
        );

        CascadeResult {
            revoked_count: revoked_ids.len(),
            revoked_ids,
        }
    }

    pub fn delegation_tree(&self, delegation_id: &str) -> Option<DelegationNode> {
        let root = self
            .temporal_delegations
            .iter()
            .find(|d| d.id == delegation_id)?;

        Some(self.build_delegation_node(root))
    }

    fn build_delegation_node(&self, delegation: &TemporalDelegation) -> DelegationNode {
        let children: Vec<DelegationNode> = self
            .temporal_delegations
            .iter()
            .filter(|d| d.parent_delegation.as_deref() == Some(&delegation.id))
            .map(|d| self.build_delegation_node(d))
            .collect();

        DelegationNode {
            delegation_id: delegation.id.clone(),
            delegator: delegation.delegator.clone(),
            delegate: delegation.delegate.clone(),
            permission_id: delegation.permission_id.clone(),
            children,
        }
    }

    pub fn grant_temporal_delegation(
        &mut self,
        id: impl Into<String>,
        delegator: SubjectId,
        delegate: SubjectId,
        permission_id: PermissionId,
        starts_at: i64,
        ends_at: i64,
        reason: impl Into<String>,
        parent_delegation: Option<String>,
    ) -> Result<(), PermissionError> {
        let id_str = id.into();
        if self.temporal_delegations.iter().any(|d| d.id == id_str) {
            return Err(PermissionError::InvalidOperation(format!(
                "delegation {} already exists",
                id_str
            )));
        }
        if starts_at >= ends_at {
            return Err(PermissionError::InvalidOperation(
                "delegation start must be before end".into(),
            ));
        }

        let td = TemporalDelegation {
            id: id_str,
            delegator,
            delegate: delegate.clone(),
            permission_id,
            starts_at,
            ends_at,
            reason: reason.into(),
            active: true,
            parent_delegation,
        };
        self.temporal_delegations.push(td);
        self.cache.invalidate_for_subject(&delegate);

        self.push_audit(
            PermissionEventType::TemporalDelegationCreated,
            delegate.as_str(),
            "temporal delegation created",
        );
        Ok(())
    }

    pub fn active_temporal_delegations(&self, now: i64) -> Vec<&TemporalDelegation> {
        self.temporal_delegations
            .iter()
            .filter(|d| d.is_active_at(now))
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════
    // PART 5: Role Hierarchy Enhancement
    // ═══════════════════════════════════════════════════════════════

    pub fn detect_role_conflicts(&mut self) -> Vec<RoleConflict> {
        let mut conflicts = Vec::new();
        let hierarchy = self.engine.hierarchy();
        let roles = hierarchy.all_roles();

        for i in 0..roles.len() {
            for j in (i + 1)..roles.len() {
                let a = &roles[i];
                let b = &roles[j];

                // Mutual exclusion.
                if hierarchy.are_mutually_exclusive(&a.id, &b.id) {
                    conflicts.push(RoleConflict {
                        conflict_type: RoleConflictType::MutuallyExclusive,
                        role_a: a.id.clone(),
                        role_b: b.id.clone(),
                        detail: "roles are mutually exclusive".into(),
                    });
                }

                // Redundant inclusion: one is ancestor of the other.
                if hierarchy.is_ancestor(&a.id, &b.id) {
                    conflicts.push(RoleConflict {
                        conflict_type: RoleConflictType::RedundantInclusion,
                        role_a: a.id.clone(),
                        role_b: b.id.clone(),
                        detail: format!("{} already inherits from {}", b.id, a.id),
                    });
                }

                // Permission overlap.
                let perms_a: std::collections::HashSet<_> =
                    hierarchy.effective_permissions(&a.id).into_iter().collect();
                let perms_b: std::collections::HashSet<_> =
                    hierarchy.effective_permissions(&b.id).into_iter().collect();
                let overlap: Vec<_> = perms_a.intersection(&perms_b).collect();
                if !overlap.is_empty()
                    && !hierarchy.is_ancestor(&a.id, &b.id)
                    && !hierarchy.is_ancestor(&b.id, &a.id)
                {
                    conflicts.push(RoleConflict {
                        conflict_type: RoleConflictType::PermissionOverlap,
                        role_a: a.id.clone(),
                        role_b: b.id.clone(),
                        detail: format!("{} shared permission(s)", overlap.len()),
                    });
                }
            }
        }

        if !conflicts.is_empty() {
            self.push_audit(
                PermissionEventType::RoleConflictDetected,
                "system",
                &format!("{} role conflicts detected", conflicts.len()),
            );
        }

        conflicts
    }

    pub fn compare_roles(&self, role_a: &RoleId, role_b: &RoleId) -> RoleComparison {
        let hierarchy = self.engine.hierarchy();
        let perms_a: std::collections::HashSet<_> =
            hierarchy.effective_permissions(role_a).into_iter().collect();
        let perms_b: std::collections::HashSet<_> =
            hierarchy.effective_permissions(role_b).into_iter().collect();

        let shared: Vec<PermissionId> = perms_a.intersection(&perms_b).cloned().collect();
        let only_a: Vec<PermissionId> = perms_a.difference(&perms_b).cloned().collect();
        let only_b: Vec<PermissionId> = perms_b.difference(&perms_a).cloned().collect();
        let is_subset = only_a.is_empty() && !shared.is_empty();
        let is_superset = only_b.is_empty() && !shared.is_empty();

        RoleComparison {
            role_a: role_a.clone(),
            role_b: role_b.clone(),
            shared_permissions: shared,
            only_in_a: only_a,
            only_in_b: only_b,
            is_subset,
            is_superset,
        }
    }

    pub fn role_assignment_count(&self, role_id: &RoleId) -> usize {
        self.engine
            .all_assignments()
            .iter()
            .filter(|a| a.role_id == *role_id && a.active)
            .count()
    }

    pub fn most_assigned_roles(&self, limit: usize) -> Vec<(RoleId, usize)> {
        let mut counts: HashMap<RoleId, usize> = HashMap::new();
        for a in self.engine.all_assignments() {
            if a.active {
                *counts.entry(a.role_id.clone()).or_default() += 1;
            }
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(limit);
        sorted
    }

    pub fn unassigned_roles(&self) -> Vec<RoleId> {
        let assigned: std::collections::HashSet<_> = self
            .engine
            .all_assignments()
            .iter()
            .filter(|a| a.active)
            .map(|a| a.role_id.clone())
            .collect();
        self.engine
            .hierarchy()
            .all_roles()
            .iter()
            .filter(|r| !assigned.contains(&r.id))
            .map(|r| r.id.clone())
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════
    // PART 6: SoD Enhancement
    // ═══════════════════════════════════════════════════════════════

    pub fn add_sod_policy(&mut self, policy: SodPolicy) -> Result<(), PermissionError> {
        if self.sod_policies.iter().any(|p| p.name == policy.name) {
            return Err(PermissionError::InvalidOperation(format!(
                "SoD policy '{}' already exists",
                policy.name
            )));
        }
        let name = policy.name.clone();
        self.sod_policies.push(policy);
        self.push_audit(
            PermissionEventType::SodPolicyAdded,
            "system",
            &format!("SoD policy '{}' added", name),
        );
        Ok(())
    }

    pub fn check_dynamic_sod(
        &mut self,
        subject_id: &SubjectId,
        requested_permission: &PermissionId,
    ) -> SodCheckResult {
        let mut violations = Vec::new();
        let current_perms: Vec<PermissionId> = self
            .grants
            .active_grants(subject_id)
            .iter()
            .map(|g| g.permission_id.clone())
            .collect();

        let mut all_perms = current_perms;
        all_perms.push(requested_permission.clone());

        // Also add role-based permissions.
        for perm in self.engine.effective_permissions_for_subject(subject_id) {
            if !all_perms.contains(&perm.id) {
                all_perms.push(perm.id.clone());
            }
        }

        for policy in &self.sod_policies {
            if matches!(policy.enforcement, SodEnforcement::Dynamic) || matches!(policy.enforcement, SodEnforcement::Static) {
                let matching: Vec<_> = policy
                    .conflicting_permissions
                    .iter()
                    .filter(|p| all_perms.contains(p))
                    .collect();
                if matching.len() >= 2 {
                    violations.push(SodViolation {
                        policy_name: policy.name.clone(),
                        subject_id: subject_id.clone(),
                        detail: format!(
                            "subject holds {} conflicting permissions under policy '{}'",
                            matching.len(),
                            policy.name
                        ),
                    });
                }
            }

            // Role-based SoD.
            if !policy.conflicting_roles.is_empty() {
                let active_roles: Vec<RoleId> = self
                    .engine
                    .all_assignments()
                    .iter()
                    .filter(|a| a.subject_id == *subject_id && a.active)
                    .map(|a| a.role_id.clone())
                    .collect();
                let matching_roles: Vec<_> = policy
                    .conflicting_roles
                    .iter()
                    .filter(|r| active_roles.contains(r))
                    .collect();
                if matching_roles.len() >= 2 {
                    violations.push(SodViolation {
                        policy_name: policy.name.clone(),
                        subject_id: subject_id.clone(),
                        detail: format!(
                            "subject holds {} conflicting roles under policy '{}'",
                            matching_roles.len(),
                            policy.name
                        ),
                    });
                }
            }
        }

        if !violations.is_empty() {
            self.push_audit(
                PermissionEventType::SodViolationDetected,
                subject_id.as_str(),
                &format!("{} SoD violations detected", violations.len()),
            );
        }

        SodCheckResult {
            passed: violations.is_empty(),
            violations,
        }
    }

    pub fn detect_sod_violations(&mut self) -> Vec<SodViolation> {
        let mut all_violations = Vec::new();

        // Collect all unique subject IDs.
        let subjects: std::collections::HashSet<SubjectId> = self
            .engine
            .all_assignments()
            .iter()
            .filter(|a| a.active)
            .map(|a| a.subject_id.clone())
            .collect();

        for subject_id in &subjects {
            // Use a dummy permission that won't exist — we just want to check current state.
            let dummy = PermissionId::new("__sod_check_dummy__");
            let check = self.check_dynamic_sod(subject_id, &dummy);
            all_violations.extend(check.violations);
        }

        all_violations
    }

    // ── Internal helpers ───────────────────────────────────────

    fn push_audit(&mut self, event_type: PermissionEventType, subject: &str, detail: &str) {
        self.audit_log.push(PermissionEvent {
            event_type,
            subject_id: SubjectId::new(subject),
            detail: detail.to_string(),
            timestamp: 0,
            decision: None,
        });
    }
}

impl Default for PermissionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::GrantId;
    use crate::role::Role;
    use crate::types::*;

    fn setup_store() -> PermissionStore {
        let mut store = PermissionStore::new();

        // Register roles.
        store.add_role(Role::viewer()).unwrap();
        store.add_role(Role::operator()).unwrap();
        store.add_role(Role::system_admin()).unwrap();
        store.add_role(Role::security_officer()).unwrap();

        // Register permissions.
        store.register_permission(Permission::new(
            "system:read", ResourcePattern::All, vec![Action::Read],
        )).unwrap();
        store.register_permission(Permission::new(
            "system:execute", ResourcePattern::All, vec![Action::Execute],
        )).unwrap();
        store.register_permission(Permission::new(
            "system:admin", ResourcePattern::All, vec![Action::Admin],
        ).classification(ClassificationLevel::TopSecret)).unwrap();
        store.register_permission(Permission::new(
            "audit:read", ResourcePattern::Prefix("audit/".into()),
            vec![Action::Read, Action::Audit],
        )).unwrap();

        // Register subjects.
        store.register_subject(
            Subject::new("alice", SubjectType::User, "Alice")
                .clearance(ClassificationLevel::Confidential),
        ).unwrap();
        store.register_subject(
            Subject::new("admin", SubjectType::User, "Admin")
                .clearance(ClassificationLevel::TopSecret),
        ).unwrap();

        store
    }

    // ── Original Layer 1 tests ─────────────────────────────────

    #[test]
    fn test_store_new() {
        let store = PermissionStore::new();
        assert!(store.list_subjects().is_empty());
    }

    #[test]
    fn test_register_and_get_subject() {
        let mut store = PermissionStore::new();
        store.register_subject(
            Subject::new("u1", SubjectType::User, "User 1"),
        ).unwrap();
        assert!(store.get_subject(&SubjectId::new("u1")).is_some());
    }

    #[test]
    fn test_full_workflow_allow() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "onboarding".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(
            Subject::new("alice", SubjectType::User, "Alice")
                .clearance(ClassificationLevel::Confidential),
        ).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("alice"),
            action: Action::Read,
            resource: "docs/readme".into(),
            context: ctx,
            justification: None,
        };
        assert!(store.check(&req).is_allowed());
    }

    #[test]
    fn test_full_workflow_deny() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(
            Subject::new("alice", SubjectType::User, "Alice"),
        ).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("alice"),
            action: Action::Delete, // viewer can't delete
            resource: "docs/readme".into(),
            context: ctx,
            justification: None,
        };
        assert!(store.check(&req).is_denied());
    }

    #[test]
    fn test_direct_grant_overrides_role_denial() {
        let mut store = setup_store();
        // Alice has viewer role (read-only).
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();

        // But also has a direct grant for execute.
        store.register_permission(Permission::new(
            "special:execute", ResourcePattern::Exact("task-x".into()),
            vec![Action::Execute],
        )).unwrap();
        store.add_grant(Grant::new(
            "grant-1",
            SubjectId::new("alice"),
            PermissionId::new("special:execute"),
            SubjectId::new("admin"),
            "one-time access",
        )).unwrap();

        let ctx = EvalContext::for_subject(
            Subject::new("alice", SubjectType::User, "Alice"),
        ).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("alice"),
            action: Action::Execute,
            resource: "task-x".into(),
            context: ctx,
            justification: None,
        };
        let decision = store.check(&req);
        assert!(decision.is_allowed());
        assert_eq!(decision.reason(), "direct grant");
    }

    #[test]
    fn test_audit_log_records_events() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();

        // Audit log should have: subject registrations, permission registrations, role assignment.
        assert!(!store.audit_log().is_empty());
        let role_events: Vec<_> = store.audit_log().iter()
            .filter(|e| matches!(e.event_type, PermissionEventType::RoleAssigned))
            .collect();
        assert_eq!(role_events.len(), 1);
    }

    #[test]
    fn test_audit_log_since() {
        let store = setup_store();
        // All events have timestamp 0, so since(1) returns none.
        assert!(store.audit_log_since(1).is_empty());
        // since(0) returns all.
        assert!(!store.audit_log_since(0).is_empty());
    }

    #[test]
    fn test_separation_of_duties() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("system-admin"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        let result = store.assign_role(
            SubjectId::new("alice"), RoleId::new("security-officer"),
            SubjectId::new("admin"), "r".into(),
        );
        assert!(matches!(result, Err(PermissionError::MutualExclusionViolation { .. })));
    }

    #[test]
    fn test_max_holders() {
        let mut store = setup_store();
        for i in 0..3 {
            store.assign_role(
                SubjectId::new(format!("admin{i}")), RoleId::new("system-admin"),
                SubjectId::new("root"), "r".into(),
            ).unwrap();
        }
        let result = store.assign_role(
            SubjectId::new("admin3"), RoleId::new("system-admin"),
            SubjectId::new("root"), "r".into(),
        );
        assert!(matches!(result, Err(PermissionError::MaxHoldersExceeded { .. })));
    }

    #[test]
    fn test_subjects_by_type() {
        let store = setup_store();
        let users = store.subjects_by_type(SubjectType::User);
        assert_eq!(users.len(), 2);
        let services = store.subjects_by_type(SubjectType::Service);
        assert!(services.is_empty());
    }

    #[test]
    fn test_deactivate_subject() {
        let mut store = setup_store();
        store.deactivate_subject(&SubjectId::new("alice")).unwrap();
        let subject = store.get_subject(&SubjectId::new("alice")).unwrap();
        assert!(!subject.active);
    }

    #[test]
    fn test_can_convenience() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        assert!(store.can(&SubjectId::new("alice"), Action::Read, "x"));
        assert!(!store.can(&SubjectId::new("alice"), Action::Delete, "x"));
    }

    // ── PART 1: Permission Persistence tests ───────────────────

    #[test]
    fn test_snapshot_and_restore() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        store.add_grant(Grant::new(
            "g1", SubjectId::new("alice"), PermissionId::new("system:read"),
            SubjectId::new("admin"), "test",
        )).unwrap();

        let snap = store.snapshot(1000);
        assert_eq!(snap.version, "1.0");
        assert!(!snap.grants.is_empty());
        assert!(!snap.roles.is_empty());
        assert!(!snap.assignments.is_empty());

        let mut store2 = PermissionStore::new();
        let result = store2.restore(snap);
        assert_eq!(result.grants_restored, 1);
        assert!(result.roles_restored > 0);
        assert!(result.assignments_restored > 0);
    }

    #[test]
    fn test_export_import_json() {
        let mut store = setup_store();
        store.add_grant(Grant::new(
            "g1", SubjectId::new("alice"), PermissionId::new("system:read"),
            SubjectId::new("admin"), "test",
        )).unwrap();

        let json = store.export_json(500).unwrap();
        assert!(json.contains("system:read"));

        let mut store2 = PermissionStore::new();
        let result = store2.import_json(&json).unwrap();
        assert_eq!(result.grants_restored, 1);
    }

    #[test]
    fn test_import_json_invalid() {
        let mut store = PermissionStore::new();
        assert!(store.import_json("not valid json").is_err());
    }

    #[test]
    fn test_bulk_grant() {
        let mut store = setup_store();
        let requests = vec![
            GrantRequest {
                subject_id: SubjectId::new("alice"),
                permission_id: PermissionId::new("system:read"),
                granted_by: SubjectId::new("admin"),
                reason: "bulk".into(),
                expires_at: None,
            },
            GrantRequest {
                subject_id: SubjectId::new("admin"),
                permission_id: PermissionId::new("system:execute"),
                granted_by: SubjectId::new("admin"),
                reason: "bulk".into(),
                expires_at: Some(9999),
            },
        ];
        let result = store.bulk_grant(requests);
        assert_eq!(result.succeeded, 2);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_cleanup_expired_grants() {
        let mut store = setup_store();
        store.add_grant(
            Grant::new("g1", SubjectId::new("alice"), PermissionId::new("system:read"),
                SubjectId::new("admin"), "r").expires_at(100),
        ).unwrap();
        store.add_grant(
            Grant::new("g2", SubjectId::new("alice"), PermissionId::new("system:execute"),
                SubjectId::new("admin"), "r").expires_at(9999),
        ).unwrap();

        let cleaned = store.cleanup_expired_grants(200);
        assert_eq!(cleaned, 1);
    }

    #[test]
    fn test_expiring_soon() {
        let mut store = setup_store();
        store.add_grant(
            Grant::new("g1", SubjectId::new("alice"), PermissionId::new("system:read"),
                SubjectId::new("admin"), "r").expires_at(1500),
        ).unwrap();
        store.add_grant(
            Grant::new("g2", SubjectId::new("alice"), PermissionId::new("system:execute"),
                SubjectId::new("admin"), "r").expires_at(9999),
        ).unwrap();

        let expiring = store.expiring_soon(1000, 1000);
        assert_eq!(expiring.len(), 1);
    }

    #[test]
    fn test_snapshot_includes_sod_policies() {
        let mut store = setup_store();
        store.add_sod_policy(SodPolicy {
            name: "test-policy".into(),
            enforcement: SodEnforcement::Static,
            conflicting_permissions: vec![
                PermissionId::new("system:read"),
                PermissionId::new("system:admin"),
            ],
            conflicting_roles: vec![],
            description: "test".into(),
        }).unwrap();

        let snap = store.snapshot(100);
        assert_eq!(snap.policies.len(), 1);
    }

    // ── PART 2: Evaluation Optimization tests ──────────────────

    #[test]
    fn test_grant_index_build() {
        let grants = vec![
            Grant::new("g1", SubjectId::new("alice"), PermissionId::new("p1"),
                SubjectId::new("admin"), "r"),
            Grant::new("g2", SubjectId::new("bob"), PermissionId::new("p2"),
                SubjectId::new("admin"), "r"),
        ];
        let idx = GrantIndex::build(&grants);
        assert_eq!(idx.by_subject.get("alice").unwrap().len(), 1);
        assert_eq!(idx.by_permission.get("p2").unwrap().len(), 1);
    }

    #[test]
    fn test_grant_index_add() {
        let mut idx = GrantIndex::new();
        let grant = Grant::new("g1", SubjectId::new("alice"), PermissionId::new("p1"),
            SubjectId::new("admin"), "r");
        idx.add(0, &grant);
        assert_eq!(idx.by_subject.get("alice").unwrap().len(), 1);
    }

    #[test]
    fn test_evaluation_cache_put_get() {
        let mut cache = EvaluationCache::new(10, 5000);
        cache.put("alice:p1".into(), true, 1000);
        assert_eq!(cache.get("alice:p1", 1500), Some(true));
    }

    #[test]
    fn test_evaluation_cache_expiry() {
        let mut cache = EvaluationCache::new(10, 5000);
        cache.put("alice:p1".into(), true, 1000);
        assert_eq!(cache.get("alice:p1", 7000), None);
    }

    #[test]
    fn test_evaluation_cache_invalidate_subject() {
        let mut cache = EvaluationCache::new(10, 5000);
        cache.put("alice:p1".into(), true, 1000);
        cache.put("alice:p2".into(), false, 1000);
        cache.put("bob:p1".into(), true, 1000);
        cache.invalidate_for_subject(&SubjectId::new("alice"));
        assert_eq!(cache.get("alice:p1", 1500), None);
        assert_eq!(cache.get("bob:p1", 1500), Some(true));
    }

    #[test]
    fn test_evaluation_cache_invalidate_all() {
        let mut cache = EvaluationCache::new(10, 5000);
        cache.put("alice:p1".into(), true, 1000);
        cache.invalidate_all();
        assert_eq!(cache.get("alice:p1", 1500), None);
    }

    #[test]
    fn test_evaluation_cache_hit_rate() {
        let mut cache = EvaluationCache::new(10, 5000);
        cache.put("alice:p1".into(), true, 1000);
        cache.get("alice:p1", 1500); // hit
        cache.get("alice:p2", 1500); // miss
        assert!((cache.hit_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_evaluation_cache_eviction() {
        let mut cache = EvaluationCache::new(2, 5000);
        cache.put("a:1".into(), true, 100);
        cache.put("b:1".into(), true, 200);
        cache.put("c:1".into(), true, 300); // should evict "a:1"
        assert_eq!(cache.get("a:1", 400), None);
        assert_eq!(cache.get("c:1", 400), Some(true));
    }

    #[test]
    fn test_evaluation_stats() {
        let mut cache = EvaluationCache::new(10, 5000);
        cache.put("a:1".into(), true, 100);
        cache.get("a:1", 200); // hit
        let stats = cache.stats();
        assert_eq!(stats.cache_entries, 1);
        assert_eq!(stats.cache_hits, 1);
    }

    #[test]
    fn test_rebuild_index() {
        let mut store = setup_store();
        store.add_grant(Grant::new(
            "g1", SubjectId::new("alice"), PermissionId::new("system:read"),
            SubjectId::new("admin"), "r",
        )).unwrap();
        store.rebuild_index();
        assert!(store.grant_index.by_subject.contains_key("alice"));
    }

    #[test]
    fn test_cached_check() {
        let mut store = setup_store();
        store.add_grant(Grant::new(
            "g1", SubjectId::new("alice"), PermissionId::new("system:read"),
            SubjectId::new("admin"), "r",
        )).unwrap();
        // First call: miss + compute.
        let result1 = store.cached_check(
            &SubjectId::new("alice"), &PermissionId::new("system:read"), 100,
        );
        assert!(result1);
        // Second call: hit.
        let result2 = store.cached_check(
            &SubjectId::new("alice"), &PermissionId::new("system:read"), 200,
        );
        assert!(result2);
        assert!(store.cache.hit_rate() > 0.0);
    }

    // ── PART 3: Policy Simulation tests ────────────────────────

    #[test]
    fn test_simulate_grant_no_conflict() {
        let mut store = setup_store();
        let result = store.simulate_grant(
            &SubjectId::new("alice"), &PermissionId::new("system:read"),
        );
        assert!(!result.would_conflict);
        assert!(result.conflict_reasons.is_empty());
    }

    #[test]
    fn test_simulate_grant_duplicate() {
        let mut store = setup_store();
        store.add_grant(Grant::new(
            "g1", SubjectId::new("alice"), PermissionId::new("system:read"),
            SubjectId::new("admin"), "r",
        )).unwrap();
        let result = store.simulate_grant(
            &SubjectId::new("alice"), &PermissionId::new("system:read"),
        );
        assert!(result.would_conflict);
        assert!(!result.conflict_reasons.is_empty());
    }

    #[test]
    fn test_simulate_grant_sod_violation() {
        let mut store = setup_store();
        store.add_sod_policy(SodPolicy {
            name: "read-admin-sod".into(),
            enforcement: SodEnforcement::Static,
            conflicting_permissions: vec![
                PermissionId::new("system:read"),
                PermissionId::new("system:admin"),
            ],
            conflicting_roles: vec![],
            description: "test".into(),
        }).unwrap();
        store.add_grant(Grant::new(
            "g1", SubjectId::new("alice"), PermissionId::new("system:read"),
            SubjectId::new("admin"), "r",
        )).unwrap();

        let result = store.simulate_grant(
            &SubjectId::new("alice"), &PermissionId::new("system:admin"),
        );
        assert!(result.would_conflict);
        assert!(!result.sod_violations.is_empty());
        assert!(matches!(result.risk_assessment, SimulationRisk::Critical));
    }

    #[test]
    fn test_effective_permissions_with_roles() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        let perms = store.effective_permissions(&SubjectId::new("alice"));
        assert!(!perms.is_empty());
        assert!(perms.iter().any(|p| matches!(p.source, PermissionSource::RoleInherited(_))));
    }

    #[test]
    fn test_effective_permissions_with_grants() {
        let mut store = setup_store();
        store.add_grant(Grant::new(
            "g1", SubjectId::new("alice"), PermissionId::new("system:read"),
            SubjectId::new("admin"), "r",
        )).unwrap();
        let perms = store.effective_permissions(&SubjectId::new("alice"));
        assert!(perms.iter().any(|p| matches!(p.source, PermissionSource::Direct)));
    }

    #[test]
    fn test_effective_permissions_with_delegation() {
        let mut store = setup_store();
        store.grant_temporal_delegation(
            "td1", SubjectId::new("admin"), SubjectId::new("alice"),
            PermissionId::new("system:admin"), 0, 9999, "temp access", None,
        ).unwrap();
        let perms = store.effective_permissions(&SubjectId::new("alice"));
        assert!(perms.iter().any(|p| matches!(p.source, PermissionSource::Delegated(_))));
    }

    #[test]
    fn test_analyze_least_privilege() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        let report = store.analyze_least_privilege(
            &SubjectId::new("alice"),
            &[PermissionId::new("system:read")],
        );
        assert!(report.total_permissions > 0);
        assert!(report.used_permissions.contains(&PermissionId::new("system:read")));
    }

    #[test]
    fn test_analyze_least_privilege_all_used() {
        let mut store = setup_store();
        store.add_grant(Grant::new(
            "g1", SubjectId::new("alice"), PermissionId::new("system:read"),
            SubjectId::new("admin"), "r",
        )).unwrap();
        let report = store.analyze_least_privilege(
            &SubjectId::new("alice"),
            &[PermissionId::new("system:read")],
        );
        assert!(report.unused_permissions.is_empty());
        assert!(report.recommendation.contains("actively used"));
    }

    // ── PART 4: Delegation Hardening tests ─────────────────────

    #[test]
    fn test_grant_temporal_delegation() {
        let mut store = setup_store();
        store.grant_temporal_delegation(
            "td1", SubjectId::new("admin"), SubjectId::new("alice"),
            PermissionId::new("system:read"), 100, 500, "temp", None,
        ).unwrap();
        assert_eq!(store.active_temporal_delegations(200).len(), 1);
        assert_eq!(store.active_temporal_delegations(600).len(), 0);
    }

    #[test]
    fn test_temporal_delegation_duplicate_id() {
        let mut store = setup_store();
        store.grant_temporal_delegation(
            "td1", SubjectId::new("admin"), SubjectId::new("alice"),
            PermissionId::new("system:read"), 100, 500, "temp", None,
        ).unwrap();
        assert!(store.grant_temporal_delegation(
            "td1", SubjectId::new("admin"), SubjectId::new("alice"),
            PermissionId::new("system:read"), 100, 500, "temp", None,
        ).is_err());
    }

    #[test]
    fn test_temporal_delegation_invalid_time() {
        let mut store = setup_store();
        assert!(store.grant_temporal_delegation(
            "td1", SubjectId::new("admin"), SubjectId::new("alice"),
            PermissionId::new("system:read"), 500, 100, "temp", None,
        ).is_err());
    }

    #[test]
    fn test_delegation_chain_depth() {
        let mut store = setup_store();
        store.grant_temporal_delegation(
            "td1", SubjectId::new("admin"), SubjectId::new("alice"),
            PermissionId::new("system:read"), 0, 9999, "r", None,
        ).unwrap();
        store.grant_temporal_delegation(
            "td2", SubjectId::new("alice"), SubjectId::new("bob"),
            PermissionId::new("system:read"), 0, 9999, "r", Some("td1".into()),
        ).unwrap();
        store.grant_temporal_delegation(
            "td3", SubjectId::new("bob"), SubjectId::new("charlie"),
            PermissionId::new("system:read"), 0, 9999, "r", Some("td2".into()),
        ).unwrap();

        assert_eq!(store.delegation_chain_depth("td1"), 0);
        assert_eq!(store.delegation_chain_depth("td2"), 1);
        assert_eq!(store.delegation_chain_depth("td3"), 2);
    }

    #[test]
    fn test_validate_delegation_depth_ok() {
        let mut store = setup_store();
        store.grant_temporal_delegation(
            "td1", SubjectId::new("admin"), SubjectId::new("alice"),
            PermissionId::new("system:read"), 0, 9999, "r", None,
        ).unwrap();
        assert!(store.validate_delegation_depth("td1", 5).is_ok());
    }

    #[test]
    fn test_validate_delegation_depth_exceeded() {
        let mut store = setup_store();
        store.grant_temporal_delegation(
            "td1", SubjectId::new("admin"), SubjectId::new("alice"),
            PermissionId::new("system:read"), 0, 9999, "r", None,
        ).unwrap();
        store.grant_temporal_delegation(
            "td2", SubjectId::new("alice"), SubjectId::new("bob"),
            PermissionId::new("system:read"), 0, 9999, "r", Some("td1".into()),
        ).unwrap();
        store.grant_temporal_delegation(
            "td3", SubjectId::new("bob"), SubjectId::new("charlie"),
            PermissionId::new("system:read"), 0, 9999, "r", Some("td2".into()),
        ).unwrap();
        assert!(store.validate_delegation_depth("td3", 1).is_err());
    }

    #[test]
    fn test_revoke_delegation_cascade() {
        let mut store = setup_store();
        store.grant_temporal_delegation(
            "td1", SubjectId::new("admin"), SubjectId::new("alice"),
            PermissionId::new("system:read"), 0, 9999, "r", None,
        ).unwrap();
        store.grant_temporal_delegation(
            "td2", SubjectId::new("alice"), SubjectId::new("bob"),
            PermissionId::new("system:read"), 0, 9999, "r", Some("td1".into()),
        ).unwrap();

        let result = store.revoke_delegation_cascade("td1");
        assert_eq!(result.revoked_count, 2);
        assert_eq!(store.active_temporal_delegations(100).len(), 0);
    }

    #[test]
    fn test_delegation_tree() {
        let mut store = setup_store();
        store.grant_temporal_delegation(
            "td1", SubjectId::new("admin"), SubjectId::new("alice"),
            PermissionId::new("system:read"), 0, 9999, "r", None,
        ).unwrap();
        store.grant_temporal_delegation(
            "td2", SubjectId::new("alice"), SubjectId::new("bob"),
            PermissionId::new("system:read"), 0, 9999, "r", Some("td1".into()),
        ).unwrap();

        let tree = store.delegation_tree("td1").unwrap();
        assert_eq!(tree.delegation_id, "td1");
        assert_eq!(tree.children.len(), 1);
        assert_eq!(tree.children[0].delegation_id, "td2");
    }

    #[test]
    fn test_delegation_tree_nonexistent() {
        let store = setup_store();
        assert!(store.delegation_tree("nonexistent").is_none());
    }

    // ── PART 5: Role Hierarchy Enhancement tests ───────────────

    #[test]
    fn test_detect_role_conflicts_mutual_exclusion() {
        let mut store = setup_store();
        let conflicts = store.detect_role_conflicts();
        assert!(conflicts.iter().any(|c| matches!(c.conflict_type, RoleConflictType::MutuallyExclusive)));
    }

    #[test]
    fn test_detect_role_conflicts_permission_overlap() {
        let mut store = setup_store();
        let conflicts = store.detect_role_conflicts();
        // viewer and operator both have system:read
        assert!(conflicts.iter().any(|c| matches!(c.conflict_type, RoleConflictType::PermissionOverlap)));
    }

    #[test]
    fn test_compare_roles() {
        let store = setup_store();
        let cmp = store.compare_roles(&RoleId::new("viewer"), &RoleId::new("operator"));
        // Both have system:read.
        assert!(!cmp.shared_permissions.is_empty());
        // Operator also has system:execute.
        assert!(!cmp.only_in_b.is_empty());
    }

    #[test]
    fn test_compare_roles_subset() {
        let mut store = PermissionStore::new();
        store.add_role(Role::new("base", "Base").permission("p1")).unwrap();
        store.add_role(Role::new("super", "Super").permission("p1").permission("p2")).unwrap();
        let cmp = store.compare_roles(&RoleId::new("base"), &RoleId::new("super"));
        assert!(cmp.is_subset); // base is subset of super
        assert!(!cmp.is_superset);
    }

    #[test]
    fn test_role_assignment_count() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        store.assign_role(
            SubjectId::new("admin"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        assert_eq!(store.role_assignment_count(&RoleId::new("viewer")), 2);
    }

    #[test]
    fn test_most_assigned_roles() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        store.assign_role(
            SubjectId::new("admin"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("operator"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();

        let most = store.most_assigned_roles(10);
        assert!(!most.is_empty());
        assert_eq!(most[0].0, RoleId::new("viewer"));
        assert_eq!(most[0].1, 2);
    }

    #[test]
    fn test_unassigned_roles() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        let unassigned = store.unassigned_roles();
        // operator, system-admin, security-officer are unassigned.
        assert!(unassigned.len() >= 3);
        assert!(!unassigned.contains(&RoleId::new("viewer")));
    }

    // ── PART 6: SoD Enhancement tests ──────────────────────────

    #[test]
    fn test_add_sod_policy() {
        let mut store = setup_store();
        store.add_sod_policy(SodPolicy {
            name: "test".into(),
            enforcement: SodEnforcement::Static,
            conflicting_permissions: vec![],
            conflicting_roles: vec![],
            description: "test policy".into(),
        }).unwrap();
        assert_eq!(store.sod_policies.len(), 1);
    }

    #[test]
    fn test_add_sod_policy_duplicate() {
        let mut store = setup_store();
        let policy = SodPolicy {
            name: "test".into(),
            enforcement: SodEnforcement::Static,
            conflicting_permissions: vec![],
            conflicting_roles: vec![],
            description: "test".into(),
        };
        store.add_sod_policy(policy.clone()).unwrap();
        assert!(store.add_sod_policy(policy).is_err());
    }

    #[test]
    fn test_check_dynamic_sod_no_violation() {
        let mut store = setup_store();
        store.add_sod_policy(SodPolicy {
            name: "read-admin".into(),
            enforcement: SodEnforcement::Dynamic,
            conflicting_permissions: vec![
                PermissionId::new("system:admin"),
                PermissionId::new("audit:write"),
            ],
            conflicting_roles: vec![],
            description: "test".into(),
        }).unwrap();

        let result = store.check_dynamic_sod(
            &SubjectId::new("alice"),
            &PermissionId::new("system:read"),
        );
        assert!(result.passed);
    }

    #[test]
    fn test_check_dynamic_sod_permission_violation() {
        let mut store = setup_store();
        store.add_sod_policy(SodPolicy {
            name: "read-exec".into(),
            enforcement: SodEnforcement::Dynamic,
            conflicting_permissions: vec![
                PermissionId::new("system:read"),
                PermissionId::new("system:execute"),
            ],
            conflicting_roles: vec![],
            description: "test".into(),
        }).unwrap();
        store.add_grant(Grant::new(
            "g1", SubjectId::new("alice"), PermissionId::new("system:read"),
            SubjectId::new("admin"), "r",
        )).unwrap();

        let result = store.check_dynamic_sod(
            &SubjectId::new("alice"),
            &PermissionId::new("system:execute"),
        );
        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn test_check_dynamic_sod_role_violation() {
        let mut store = setup_store();
        store.add_sod_policy(SodPolicy {
            name: "viewer-operator".into(),
            enforcement: SodEnforcement::Dynamic,
            conflicting_permissions: vec![],
            conflicting_roles: vec![
                RoleId::new("viewer"),
                RoleId::new("operator"),
            ],
            description: "test".into(),
        }).unwrap();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("operator"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();

        let result = store.check_dynamic_sod(
            &SubjectId::new("alice"),
            &PermissionId::new("system:read"),
        );
        assert!(!result.passed);
    }

    #[test]
    fn test_detect_sod_violations_across_subjects() {
        let mut store = setup_store();
        store.add_sod_policy(SodPolicy {
            name: "viewer-operator".into(),
            enforcement: SodEnforcement::Static,
            conflicting_permissions: vec![],
            conflicting_roles: vec![
                RoleId::new("viewer"),
                RoleId::new("operator"),
            ],
            description: "test".into(),
        }).unwrap();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("operator"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();

        let violations = store.detect_sod_violations();
        assert!(!violations.is_empty());
    }

    // ── PART 7: Audit Enhancement tests ────────────────────────

    #[test]
    fn test_all_23_event_types() {
        let event_types = vec![
            PermissionEventType::RoleAssigned,
            PermissionEventType::RoleRevoked,
            PermissionEventType::GrantCreated,
            PermissionEventType::GrantRevoked,
            PermissionEventType::AccessChecked,
            PermissionEventType::PermissionRegistered,
            PermissionEventType::SubjectRegistered,
            PermissionEventType::SubjectDeactivated,
            PermissionEventType::PermissionSnapshotCreated,
            PermissionEventType::PermissionSnapshotRestored,
            PermissionEventType::BulkGrantExecuted,
            PermissionEventType::ExpiredGrantsCleaned,
            PermissionEventType::GrantIndexRebuilt,
            PermissionEventType::CacheInvalidated,
            PermissionEventType::PermissionSimulated,
            PermissionEventType::EffectivePermissionsQueried,
            PermissionEventType::LeastPrivilegeAnalyzed,
            PermissionEventType::DelegationCascadeRevoked,
            PermissionEventType::DelegationDepthChecked,
            PermissionEventType::TemporalDelegationCreated,
            PermissionEventType::RoleConflictDetected,
            PermissionEventType::SodViolationDetected,
            PermissionEventType::SodPolicyAdded,
        ];
        assert_eq!(event_types.len(), 23);
        for et in &event_types {
            assert!(!et.to_string().is_empty());
            assert!(!et.type_name().is_empty());
        }
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(
            PermissionEventType::PermissionSnapshotCreated.to_string(),
            "PermissionSnapshotCreated"
        );
        assert_eq!(
            PermissionEventType::SodViolationDetected.to_string(),
            "SodViolationDetected"
        );
    }

    #[test]
    fn test_simulation_risk_display() {
        assert_eq!(SimulationRisk::Low.to_string(), "Low");
        assert_eq!(SimulationRisk::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_permission_source_display() {
        assert_eq!(PermissionSource::Direct.to_string(), "Direct");
        assert_eq!(
            PermissionSource::RoleInherited(RoleId::new("admin")).to_string(),
            "RoleInherited(admin)"
        );
        assert_eq!(
            PermissionSource::Delegated(SubjectId::new("alice")).to_string(),
            "Delegated(alice)"
        );
    }

    #[test]
    fn test_sod_enforcement_display() {
        assert_eq!(SodEnforcement::Static.to_string(), "Static");
        assert_eq!(SodEnforcement::Dynamic.to_string(), "Dynamic");
    }

    #[test]
    fn test_role_conflict_type_display() {
        assert_eq!(RoleConflictType::MutuallyExclusive.to_string(), "MutuallyExclusive");
        assert_eq!(RoleConflictType::PermissionOverlap.to_string(), "PermissionOverlap");
    }

    // ── Layer 3: Audit Enhancement Tests ─────────────────────────────

    #[test]
    fn test_layer3_event_types_display() {
        let events: Vec<PermissionEventType> = vec![
            PermissionEventType::PermissionBackendChanged { backend_type: "postgres".into() },
            PermissionEventType::PolicyDefinitionStored { policy_id: "pol-1".into() },
            PermissionEventType::PolicyDefinitionRemoved { policy_id: "pol-1".into() },
            PermissionEventType::RoleDefinitionStored { role_id: "admin".into() },
            PermissionEventType::RoleDefinitionRemoved { role_id: "admin".into() },
            PermissionEventType::PermissionGrantRecordCreated { grant_id: "g-1".into() },
            PermissionEventType::PermissionGrantRecordRevoked { grant_id: "g-1".into() },
            PermissionEventType::AuthorizationDecisionMade { outcome: "permit".into() },
            PermissionEventType::AuthorizationPermit { matched_policies: "p1,p2".into() },
            PermissionEventType::AuthorizationDeny { reason: "no access".into() },
            PermissionEventType::AuthorizationIndeterminate { reason: "error".into() },
            PermissionEventType::AuthorizationNotApplicable,
            PermissionEventType::DecisionEngineInvoked { engine_id: "rbac-1".into() },
            PermissionEventType::PolicyExported { format: "rego".into() },
            PermissionEventType::PolicyExportFailed { format: "xacml".into(), reason: "io".into() },
            PermissionEventType::DecisionSubscriberRegistered { subscriber_id: "s1".into() },
            PermissionEventType::DecisionSubscriberRemoved { subscriber_id: "s1".into() },
            PermissionEventType::DecisionEventPublished { event_type: "Permit".into() },
            PermissionEventType::ExternalEvaluatorInvoked { evaluator_id: "opa-1".into() },
            PermissionEventType::ExternalEvaluatorFailed { evaluator_id: "opa-1".into(), reason: "timeout".into() },
            PermissionEventType::RoleProviderQueried { provider_id: "ldap-1".into() },
            PermissionEventType::CapabilityTokenVerified { token_id: "tok-1".into() },
            PermissionEventType::CapabilityTokenRejected { token_id: "tok-1".into(), reason: "expired".into() },
        ];
        for e in &events {
            assert!(!e.to_string().is_empty());
            assert!(!e.type_name().is_empty());
        }
        assert_eq!(events.len(), 23);
    }

    #[test]
    fn test_layer3_backend_event_classification() {
        assert!(PermissionEventType::PolicyDefinitionStored { policy_id: "x".into() }.is_backend_event());
        assert!(PermissionEventType::RoleDefinitionRemoved { role_id: "x".into() }.is_backend_event());
        assert!(PermissionEventType::PermissionGrantRecordCreated { grant_id: "x".into() }.is_backend_event());
        assert!(!PermissionEventType::AuthorizationPermit { matched_policies: "x".into() }.is_backend_event());
    }

    #[test]
    fn test_layer3_decision_event_classification() {
        assert!(PermissionEventType::AuthorizationPermit { matched_policies: "x".into() }.is_decision_event());
        assert!(PermissionEventType::AuthorizationDeny { reason: "x".into() }.is_decision_event());
        assert!(PermissionEventType::AuthorizationNotApplicable.is_decision_event());
        assert!(PermissionEventType::DecisionEngineInvoked { engine_id: "x".into() }.is_decision_event());
        assert!(!PermissionEventType::PolicyExported { format: "x".into() }.is_decision_event());
    }

    #[test]
    fn test_layer3_export_event_classification() {
        assert!(PermissionEventType::PolicyExported { format: "rego".into() }.is_export_event());
        assert!(PermissionEventType::PolicyExportFailed { format: "x".into(), reason: "y".into() }.is_export_event());
        assert!(!PermissionEventType::AuthorizationPermit { matched_policies: "x".into() }.is_export_event());
    }

    #[test]
    fn test_layer3_external_event_classification() {
        assert!(PermissionEventType::ExternalEvaluatorInvoked { evaluator_id: "x".into() }.is_external_event());
        assert!(PermissionEventType::ExternalEvaluatorFailed { evaluator_id: "x".into(), reason: "y".into() }.is_external_event());
        assert!(PermissionEventType::RoleProviderQueried { provider_id: "x".into() }.is_external_event());
        assert!(!PermissionEventType::AuthorizationDeny { reason: "x".into() }.is_external_event());
    }

    #[test]
    fn test_layer3_capability_event_classification() {
        assert!(PermissionEventType::CapabilityTokenVerified { token_id: "x".into() }.is_capability_event());
        assert!(PermissionEventType::CapabilityTokenRejected { token_id: "x".into(), reason: "y".into() }.is_capability_event());
        assert!(!PermissionEventType::PolicyExported { format: "x".into() }.is_capability_event());
    }
}
