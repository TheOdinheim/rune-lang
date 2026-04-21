// ═══════════════════════════════════════════════════════════════════════
// Audit — Policy-ext-specific audit events.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::policy::ManagedPolicyId;

// ── PolicyExtEventType ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyExtEventType {
    PolicyCreated { domain: String },
    PolicyUpdated { field: String },
    PolicyVersioned { from: String, to: String },
    StatusTransitioned { from: String, to: String },
    ConflictDetected { severity: String, policies: String },
    ConflictResolved { resolution: String },
    SimulationRun { change_rate: f64, risk: String },
    PolicyExported { format: String },
    PolicyImported,
    FrameworkBound { framework: String, requirement: String },
    RollbackPerformed { to_version: String },

    // ── Layer 2 event types ────────────────────────────────────────
    PolicyConflictDetected { policy_a: String, policy_b: String, conflict_type: String },
    PolicyConflictResolved { conflict_id: String, strategy: String, winner: String },
    PolicyHierarchyModified { policy_id: String, parent_id: String },
    PolicyInheritanceApplied { child: String, parent: String, mode: String },
    TemporalPolicyScheduled { policy_id: String, effective_from: i64 },
    TemporalPolicyActivated { policy_id: String },
    TemporalPolicyExpired { policy_id: String },
    PolicySimulationRun { simulation_id: String, test_cases: usize, pass_rate: f64 },
    PolicyImpactAnalyzed { policy_id: String, affected: usize, risk: String },
    PolicyVersionCreated { policy_id: String, version: u32, hash_prefix: String },
    PolicyVersionDeprecated { policy_id: String, version: u32 },
    PolicyVersionChainVerified { policy_id: String, valid: bool },
    PolicyDependencyAdded { policy_id: String, depends_on: String },
    PolicyCascadeAnalyzed { policy_id: String, total_affected: usize },
    PolicyDependencyValidated { issues: usize },

    // ── Layer 3 event types ────────────────────────────────────────
    PolicyPackageBackendChanged { backend_id: String },
    PackageStored { package_id: String, namespace: String },
    PackageRetrieved { package_id: String },
    PackageDeleted { package_id: String },
    PackageVersionResolved { name: String, namespace: String, resolved_version: String },
    RuleSetStored { rule_set_id: String, package_id: String },
    PackageComposed { source_count: usize, strategy: String },
    PackagePolicyConflictDetected { conflict_id: String, conflict_type: String },
    PackagePolicyConflictResolved { conflict_id: String, resolution_strategy: String },
    PackagePublishedToRegistry { package_id: String, registry_id: String },
    PackageUnpublishedFromRegistry { package_id: String, registry_id: String },
    PackageSignatureVerified { package_id: String, signer: String },
    PackageSignatureInvalid { package_id: String, reason: String },
    PackageIntegrityVerified { package_id: String, valid: bool },
    EvaluationPayloadPrepared { payload_id: String, evaluator_type: String },
    EvaluationSubmittedToExternal { handle: String, evaluator_type: String },
    EvaluationCompletedByExternal { handle: String, outcome: String },
    EvaluationFailedByExternal { handle: String, reason: String },
    EvaluationCanceled { handle: String },
    PackageExported { package_id: String, format: String },
    PackageExportFailed { package_id: String, format: String, reason: String },
    PackageValidated { package_id: String, passed: bool, severity: String },
    PackageValidationFailed { package_id: String, reason: String },
    PolicySubscriberRegistered { subscriber_id: String },
    PolicySubscriberRemoved { subscriber_id: String },
    PolicyEventPublished { event_type: String, subscriber_count: usize },
}

impl fmt::Display for PolicyExtEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyCreated { domain } => write!(f, "policy-created:{domain}"),
            Self::PolicyUpdated { field } => write!(f, "policy-updated:{field}"),
            Self::PolicyVersioned { from, to } => write!(f, "policy-versioned:{from}→{to}"),
            Self::StatusTransitioned { from, to } => write!(f, "status-transitioned:{from}→{to}"),
            Self::ConflictDetected { severity, policies } => {
                write!(f, "conflict-detected:[{severity}] {policies}")
            }
            Self::ConflictResolved { resolution } => {
                write!(f, "conflict-resolved:{resolution}")
            }
            Self::SimulationRun { change_rate, risk } => {
                write!(f, "simulation-run:{change_rate:.0}% [{risk}]")
            }
            Self::PolicyExported { format } => write!(f, "policy-exported:{format}"),
            Self::PolicyImported => f.write_str("policy-imported"),
            Self::FrameworkBound { framework, requirement } => {
                write!(f, "framework-bound:{framework}/{requirement}")
            }
            Self::RollbackPerformed { to_version } => {
                write!(f, "rollback-performed:{to_version}")
            }
            Self::PolicyConflictDetected { policy_a, policy_b, conflict_type } => {
                write!(f, "l2-conflict-detected:{policy_a}/{policy_b}:{conflict_type}")
            }
            Self::PolicyConflictResolved { conflict_id, strategy, winner } => {
                write!(f, "l2-conflict-resolved:{conflict_id}:{strategy}→{winner}")
            }
            Self::PolicyHierarchyModified { policy_id, parent_id } => {
                write!(f, "l2-hierarchy-modified:{policy_id}→{parent_id}")
            }
            Self::PolicyInheritanceApplied { child, parent, mode } => {
                write!(f, "l2-inheritance-applied:{child}←{parent}:{mode}")
            }
            Self::TemporalPolicyScheduled { policy_id, effective_from } => {
                write!(f, "l2-temporal-scheduled:{policy_id}@{effective_from}")
            }
            Self::TemporalPolicyActivated { policy_id } => {
                write!(f, "l2-temporal-activated:{policy_id}")
            }
            Self::TemporalPolicyExpired { policy_id } => {
                write!(f, "l2-temporal-expired:{policy_id}")
            }
            Self::PolicySimulationRun { simulation_id, test_cases, pass_rate } => {
                write!(f, "l2-simulation-run:{simulation_id}:{test_cases}tc:{pass_rate:.0}%")
            }
            Self::PolicyImpactAnalyzed { policy_id, affected, risk } => {
                write!(f, "l2-impact-analyzed:{policy_id}:{affected}:{risk}")
            }
            Self::PolicyVersionCreated { policy_id, version, hash_prefix } => {
                write!(f, "l2-version-created:{policy_id}@{version}:{hash_prefix}")
            }
            Self::PolicyVersionDeprecated { policy_id, version } => {
                write!(f, "l2-version-deprecated:{policy_id}@{version}")
            }
            Self::PolicyVersionChainVerified { policy_id, valid } => {
                write!(f, "l2-version-chain-verified:{policy_id}:{valid}")
            }
            Self::PolicyDependencyAdded { policy_id, depends_on } => {
                write!(f, "l2-dependency-added:{policy_id}→{depends_on}")
            }
            Self::PolicyCascadeAnalyzed { policy_id, total_affected } => {
                write!(f, "l2-cascade-analyzed:{policy_id}:{total_affected}")
            }
            Self::PolicyDependencyValidated { issues } => {
                write!(f, "l2-dependency-validated:{issues} issues")
            }
            Self::PolicyPackageBackendChanged { backend_id } => {
                write!(f, "policy-package-backend-changed:{backend_id}")
            }
            Self::PackageStored { package_id, namespace } => {
                write!(f, "package-stored:{package_id} [{namespace}]")
            }
            Self::PackageRetrieved { package_id } => {
                write!(f, "package-retrieved:{package_id}")
            }
            Self::PackageDeleted { package_id } => {
                write!(f, "package-deleted:{package_id}")
            }
            Self::PackageVersionResolved { name, namespace, resolved_version } => {
                write!(f, "package-version-resolved:{namespace}/{name}@{resolved_version}")
            }
            Self::RuleSetStored { rule_set_id, package_id } => {
                write!(f, "rule-set-stored:{rule_set_id} [{package_id}]")
            }
            Self::PackageComposed { source_count, strategy } => {
                write!(f, "package-composed:{source_count} packages [{strategy}]")
            }
            Self::PackagePolicyConflictDetected { conflict_id, conflict_type } => {
                write!(f, "package-conflict-detected:{conflict_id} [{conflict_type}]")
            }
            Self::PackagePolicyConflictResolved { conflict_id, resolution_strategy } => {
                write!(f, "package-conflict-resolved:{conflict_id} [{resolution_strategy}]")
            }
            Self::PackagePublishedToRegistry { package_id, registry_id } => {
                write!(f, "package-published:{package_id} [{registry_id}]")
            }
            Self::PackageUnpublishedFromRegistry { package_id, registry_id } => {
                write!(f, "package-unpublished:{package_id} [{registry_id}]")
            }
            Self::PackageSignatureVerified { package_id, signer } => {
                write!(f, "package-signature-verified:{package_id} [{signer}]")
            }
            Self::PackageSignatureInvalid { package_id, reason } => {
                write!(f, "package-signature-invalid:{package_id} {reason}")
            }
            Self::PackageIntegrityVerified { package_id, valid } => {
                write!(f, "package-integrity-verified:{package_id} {}", if *valid { "ok" } else { "failed" })
            }
            Self::EvaluationPayloadPrepared { payload_id, evaluator_type } => {
                write!(f, "evaluation-payload-prepared:{payload_id} [{evaluator_type}]")
            }
            Self::EvaluationSubmittedToExternal { handle, evaluator_type } => {
                write!(f, "evaluation-submitted:{handle} [{evaluator_type}]")
            }
            Self::EvaluationCompletedByExternal { handle, outcome } => {
                write!(f, "evaluation-completed:{handle} [{outcome}]")
            }
            Self::EvaluationFailedByExternal { handle, reason } => {
                write!(f, "evaluation-failed:{handle} {reason}")
            }
            Self::EvaluationCanceled { handle } => {
                write!(f, "evaluation-canceled:{handle}")
            }
            Self::PackageExported { package_id, format } => {
                write!(f, "package-exported:{package_id} [{format}]")
            }
            Self::PackageExportFailed { package_id, format, reason } => {
                write!(f, "package-export-failed:{package_id} [{format}] {reason}")
            }
            Self::PackageValidated { package_id, passed, severity } => {
                write!(f, "package-validated:{package_id} {} [{severity}]", if *passed { "passed" } else { "failed" })
            }
            Self::PackageValidationFailed { package_id, reason } => {
                write!(f, "package-validation-failed:{package_id} {reason}")
            }
            Self::PolicySubscriberRegistered { subscriber_id } => {
                write!(f, "policy-subscriber-registered:{subscriber_id}")
            }
            Self::PolicySubscriberRemoved { subscriber_id } => {
                write!(f, "policy-subscriber-removed:{subscriber_id}")
            }
            Self::PolicyEventPublished { event_type, subscriber_count } => {
                write!(f, "policy-event-published:{event_type} ({subscriber_count} subscribers)")
            }
        }
    }
}

impl PolicyExtEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::PolicyCreated { .. } => "policy-created",
            Self::PolicyUpdated { .. } => "policy-updated",
            Self::PolicyVersioned { .. } => "policy-versioned",
            Self::StatusTransitioned { .. } => "status-transitioned",
            Self::ConflictDetected { .. } => "conflict-detected",
            Self::ConflictResolved { .. } => "conflict-resolved",
            Self::SimulationRun { .. } => "simulation-run",
            Self::PolicyExported { .. } => "policy-exported",
            Self::PolicyImported => "policy-imported",
            Self::FrameworkBound { .. } => "framework-bound",
            Self::RollbackPerformed { .. } => "rollback-performed",
            Self::PolicyConflictDetected { .. } => "l2-conflict-detected",
            Self::PolicyConflictResolved { .. } => "l2-conflict-resolved",
            Self::PolicyHierarchyModified { .. } => "l2-hierarchy-modified",
            Self::PolicyInheritanceApplied { .. } => "l2-inheritance-applied",
            Self::TemporalPolicyScheduled { .. } => "l2-temporal-scheduled",
            Self::TemporalPolicyActivated { .. } => "l2-temporal-activated",
            Self::TemporalPolicyExpired { .. } => "l2-temporal-expired",
            Self::PolicySimulationRun { .. } => "l2-simulation-run",
            Self::PolicyImpactAnalyzed { .. } => "l2-impact-analyzed",
            Self::PolicyVersionCreated { .. } => "l2-version-created",
            Self::PolicyVersionDeprecated { .. } => "l2-version-deprecated",
            Self::PolicyVersionChainVerified { .. } => "l2-version-chain-verified",
            Self::PolicyDependencyAdded { .. } => "l2-dependency-added",
            Self::PolicyCascadeAnalyzed { .. } => "l2-cascade-analyzed",
            Self::PolicyDependencyValidated { .. } => "l2-dependency-validated",
            Self::PolicyPackageBackendChanged { .. } => "policy-package-backend-changed",
            Self::PackageStored { .. } => "package-stored",
            Self::PackageRetrieved { .. } => "package-retrieved",
            Self::PackageDeleted { .. } => "package-deleted",
            Self::PackageVersionResolved { .. } => "package-version-resolved",
            Self::RuleSetStored { .. } => "rule-set-stored",
            Self::PackageComposed { .. } => "package-composed",
            Self::PackagePolicyConflictDetected { .. } => "package-conflict-detected",
            Self::PackagePolicyConflictResolved { .. } => "package-conflict-resolved",
            Self::PackagePublishedToRegistry { .. } => "package-published-to-registry",
            Self::PackageUnpublishedFromRegistry { .. } => "package-unpublished-from-registry",
            Self::PackageSignatureVerified { .. } => "package-signature-verified",
            Self::PackageSignatureInvalid { .. } => "package-signature-invalid",
            Self::PackageIntegrityVerified { .. } => "package-integrity-verified",
            Self::EvaluationPayloadPrepared { .. } => "evaluation-payload-prepared",
            Self::EvaluationSubmittedToExternal { .. } => "evaluation-submitted-to-external",
            Self::EvaluationCompletedByExternal { .. } => "evaluation-completed-by-external",
            Self::EvaluationFailedByExternal { .. } => "evaluation-failed-by-external",
            Self::EvaluationCanceled { .. } => "evaluation-canceled",
            Self::PackageExported { .. } => "package-exported",
            Self::PackageExportFailed { .. } => "package-export-failed",
            Self::PackageValidated { .. } => "package-validated",
            Self::PackageValidationFailed { .. } => "package-validation-failed",
            Self::PolicySubscriberRegistered { .. } => "policy-subscriber-registered",
            Self::PolicySubscriberRemoved { .. } => "policy-subscriber-removed",
            Self::PolicyEventPublished { .. } => "policy-event-published",
        }
    }

    pub fn kind(&self) -> &str {
        self.type_name()
    }

    pub fn is_backend_event(&self) -> bool {
        matches!(
            self,
            Self::PolicyPackageBackendChanged { .. }
                | Self::PackageStored { .. }
                | Self::PackageRetrieved { .. }
                | Self::PackageDeleted { .. }
                | Self::PackageVersionResolved { .. }
                | Self::RuleSetStored { .. }
        )
    }

    pub fn is_package_event(&self) -> bool {
        matches!(
            self,
            Self::PackageStored { .. }
                | Self::PackageRetrieved { .. }
                | Self::PackageDeleted { .. }
                | Self::PackageVersionResolved { .. }
                | Self::PackageSignatureVerified { .. }
                | Self::PackageSignatureInvalid { .. }
                | Self::PackageIntegrityVerified { .. }
        )
    }

    pub fn is_composition_event(&self) -> bool {
        matches!(
            self,
            Self::PackageComposed { .. }
                | Self::PackagePolicyConflictDetected { .. }
                | Self::PackagePolicyConflictResolved { .. }
        )
    }

    pub fn is_registry_event(&self) -> bool {
        matches!(
            self,
            Self::PackagePublishedToRegistry { .. }
                | Self::PackageUnpublishedFromRegistry { .. }
                | Self::PackageIntegrityVerified { .. }
        )
    }

    pub fn is_evaluation_event(&self) -> bool {
        matches!(
            self,
            Self::EvaluationPayloadPrepared { .. }
                | Self::EvaluationSubmittedToExternal { .. }
                | Self::EvaluationCompletedByExternal { .. }
                | Self::EvaluationFailedByExternal { .. }
                | Self::EvaluationCanceled { .. }
        )
    }

    pub fn is_export_event(&self) -> bool {
        matches!(
            self,
            Self::PackageExported { .. } | Self::PackageExportFailed { .. }
        )
    }

    pub fn is_validation_event(&self) -> bool {
        matches!(
            self,
            Self::PackageValidated { .. } | Self::PackageValidationFailed { .. }
        )
    }
}

// ── PolicyExtAuditEvent ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyExtAuditEvent {
    pub event_type: PolicyExtEventType,
    pub timestamp: i64,
    pub actor: String,
    pub detail: String,
    pub policy_id: Option<ManagedPolicyId>,
}

impl PolicyExtAuditEvent {
    pub fn new(
        event_type: PolicyExtEventType,
        actor: impl Into<String>,
        timestamp: i64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp,
            actor: actor.into(),
            detail: detail.into(),
            policy_id: None,
        }
    }

    pub fn for_policy(mut self, id: ManagedPolicyId) -> Self {
        self.policy_id = Some(id);
        self
    }
}

// ── PolicyExtAuditLog ───────────────────────────────────────────────

#[derive(Default)]
pub struct PolicyExtAuditLog {
    pub events: Vec<PolicyExtAuditEvent>,
}

impl PolicyExtAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: PolicyExtAuditEvent) {
        self.events.push(event);
    }

    pub fn events_for_policy(&self, id: &ManagedPolicyId) -> Vec<&PolicyExtAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.policy_id.as_ref() == Some(id))
            .collect()
    }

    pub fn events_by_type(&self, type_name: &str) -> Vec<&PolicyExtAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.type_name() == type_name)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&PolicyExtAuditEvent> {
        self.events.iter().filter(|e| e.timestamp >= timestamp).collect()
    }

    pub fn conflict_events(&self) -> Vec<&PolicyExtAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    PolicyExtEventType::ConflictDetected { .. }
                        | PolicyExtEventType::ConflictResolved { .. }
                )
            })
            .collect()
    }

    pub fn lifecycle_events(&self) -> Vec<&PolicyExtAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, PolicyExtEventType::StatusTransitioned { .. }))
            .collect()
    }

    pub fn simulation_events(&self) -> Vec<&PolicyExtAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, PolicyExtEventType::SimulationRun { .. }))
            .collect()
    }

    pub fn count(&self) -> usize {
        self.events.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_retrieve() {
        let mut log = PolicyExtAuditLog::new();
        log.record(
            PolicyExtAuditEvent::new(
                PolicyExtEventType::PolicyCreated { domain: "access-control".into() },
                "alice",
                1000,
                "created",
            )
            .for_policy(ManagedPolicyId::new("p1")),
        );
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn test_events_for_policy() {
        let mut log = PolicyExtAuditLog::new();
        log.record(
            PolicyExtAuditEvent::new(
                PolicyExtEventType::PolicyCreated { domain: "access-control".into() },
                "alice",
                1000,
                "created",
            )
            .for_policy(ManagedPolicyId::new("p1")),
        );
        log.record(PolicyExtAuditEvent::new(
            PolicyExtEventType::PolicyImported,
            "bob",
            2000,
            "imported",
        ));
        assert_eq!(log.events_for_policy(&ManagedPolicyId::new("p1")).len(), 1);
    }

    #[test]
    fn test_conflict_events() {
        let mut log = PolicyExtAuditLog::new();
        log.record(PolicyExtAuditEvent::new(
            PolicyExtEventType::ConflictDetected {
                severity: "High".into(),
                policies: "p1,p2".into(),
            },
            "system",
            1000,
            "conflict",
        ));
        log.record(PolicyExtAuditEvent::new(
            PolicyExtEventType::ConflictResolved { resolution: "accepted".into() },
            "alice",
            2000,
            "resolved",
        ));
        assert_eq!(log.conflict_events().len(), 2);
    }

    #[test]
    fn test_lifecycle_events() {
        let mut log = PolicyExtAuditLog::new();
        log.record(PolicyExtAuditEvent::new(
            PolicyExtEventType::StatusTransitioned { from: "Draft".into(), to: "Active".into() },
            "alice",
            1000,
            "activated",
        ));
        assert_eq!(log.lifecycle_events().len(), 1);
    }

    #[test]
    fn test_simulation_events() {
        let mut log = PolicyExtAuditLog::new();
        log.record(PolicyExtAuditEvent::new(
            PolicyExtEventType::SimulationRun { change_rate: 0.15, risk: "Moderate".into() },
            "alice",
            1000,
            "simulated",
        ));
        assert_eq!(log.simulation_events().len(), 1);
    }

    #[test]
    fn test_all_event_type_displays() {
        let types = vec![
            PolicyExtEventType::PolicyCreated { domain: "x".into() },
            PolicyExtEventType::PolicyUpdated { field: "name".into() },
            PolicyExtEventType::PolicyVersioned { from: "0.1.0".into(), to: "0.2.0".into() },
            PolicyExtEventType::StatusTransitioned { from: "Draft".into(), to: "Active".into() },
            PolicyExtEventType::ConflictDetected { severity: "High".into(), policies: "p1,p2".into() },
            PolicyExtEventType::ConflictResolved { resolution: "merged".into() },
            PolicyExtEventType::SimulationRun { change_rate: 0.1, risk: "Safe".into() },
            PolicyExtEventType::PolicyExported { format: "json".into() },
            PolicyExtEventType::PolicyImported,
            PolicyExtEventType::FrameworkBound { framework: "GDPR".into(), requirement: "Art. 5".into() },
            PolicyExtEventType::RollbackPerformed { to_version: "0.1.0".into() },
            PolicyExtEventType::PolicyConflictDetected { policy_a: "p1".into(), policy_b: "p2".into(), conflict_type: "direct".into() },
            PolicyExtEventType::PolicyConflictResolved { conflict_id: "c1".into(), strategy: "deny-overrides".into(), winner: "p2".into() },
            PolicyExtEventType::PolicyHierarchyModified { policy_id: "p1".into(), parent_id: "root".into() },
            PolicyExtEventType::PolicyInheritanceApplied { child: "c1".into(), parent: "p1".into(), mode: "extend".into() },
            PolicyExtEventType::TemporalPolicyScheduled { policy_id: "p1".into(), effective_from: 1000 },
            PolicyExtEventType::TemporalPolicyActivated { policy_id: "p1".into() },
            PolicyExtEventType::TemporalPolicyExpired { policy_id: "p1".into() },
            PolicyExtEventType::PolicySimulationRun { simulation_id: "sim-1".into(), test_cases: 10, pass_rate: 0.9 },
            PolicyExtEventType::PolicyImpactAnalyzed { policy_id: "p1".into(), affected: 50, risk: "Medium".into() },
            PolicyExtEventType::PolicyVersionCreated { policy_id: "p1".into(), version: 1, hash_prefix: "abc123".into() },
            PolicyExtEventType::PolicyVersionDeprecated { policy_id: "p1".into(), version: 1 },
            PolicyExtEventType::PolicyVersionChainVerified { policy_id: "p1".into(), valid: true },
            PolicyExtEventType::PolicyDependencyAdded { policy_id: "p1".into(), depends_on: "p2".into() },
            PolicyExtEventType::PolicyCascadeAnalyzed { policy_id: "p1".into(), total_affected: 3 },
            PolicyExtEventType::PolicyDependencyValidated { issues: 0 },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
            assert!(!t.type_name().is_empty());
        }
        assert_eq!(types.len(), 26);
    }

    #[test]
    fn test_l3_event_type_display() {
        let types = vec![
            PolicyExtEventType::PolicyPackageBackendChanged { backend_id: "b1".into() },
            PolicyExtEventType::PackageStored { package_id: "pkg-1".into(), namespace: "org".into() },
            PolicyExtEventType::PackageRetrieved { package_id: "pkg-1".into() },
            PolicyExtEventType::PackageDeleted { package_id: "pkg-1".into() },
            PolicyExtEventType::PackageVersionResolved { name: "access".into(), namespace: "org".into(), resolved_version: "1.0.0".into() },
            PolicyExtEventType::RuleSetStored { rule_set_id: "rs-1".into(), package_id: "pkg-1".into() },
            PolicyExtEventType::PackageComposed { source_count: 3, strategy: "union".into() },
            PolicyExtEventType::PackagePolicyConflictDetected { conflict_id: "c-1".into(), conflict_type: "overlapping-scope".into() },
            PolicyExtEventType::PackagePolicyConflictResolved { conflict_id: "c-1".into(), resolution_strategy: "prefer-newer".into() },
            PolicyExtEventType::PackagePublishedToRegistry { package_id: "pkg-1".into(), registry_id: "reg-1".into() },
            PolicyExtEventType::PackageUnpublishedFromRegistry { package_id: "pkg-1".into(), registry_id: "reg-1".into() },
            PolicyExtEventType::PackageSignatureVerified { package_id: "pkg-1".into(), signer: "admin".into() },
            PolicyExtEventType::PackageSignatureInvalid { package_id: "pkg-1".into(), reason: "expired".into() },
            PolicyExtEventType::PackageIntegrityVerified { package_id: "pkg-1".into(), valid: true },
            PolicyExtEventType::EvaluationPayloadPrepared { payload_id: "pay-1".into(), evaluator_type: "opa-rego".into() },
            PolicyExtEventType::EvaluationSubmittedToExternal { handle: "eval-1".into(), evaluator_type: "cedar".into() },
            PolicyExtEventType::EvaluationCompletedByExternal { handle: "eval-1".into(), outcome: "Permit".into() },
            PolicyExtEventType::EvaluationFailedByExternal { handle: "eval-1".into(), reason: "timeout".into() },
            PolicyExtEventType::EvaluationCanceled { handle: "eval-1".into() },
            PolicyExtEventType::PackageExported { package_id: "pkg-1".into(), format: "json".into() },
            PolicyExtEventType::PackageExportFailed { package_id: "pkg-1".into(), format: "xacml".into(), reason: "err".into() },
            PolicyExtEventType::PackageValidated { package_id: "pkg-1".into(), passed: true, severity: "clean".into() },
            PolicyExtEventType::PackageValidationFailed { package_id: "pkg-1".into(), reason: "bad".into() },
            PolicyExtEventType::PolicySubscriberRegistered { subscriber_id: "sub-1".into() },
            PolicyExtEventType::PolicySubscriberRemoved { subscriber_id: "sub-1".into() },
            PolicyExtEventType::PolicyEventPublished { event_type: "package-published".into(), subscriber_count: 3 },
        ];
        assert_eq!(types.len(), 26);
        for t in &types {
            assert!(!t.to_string().is_empty());
            assert!(!t.kind().is_empty());
        }
    }

    #[test]
    fn test_kind_method() {
        let event = PolicyExtEventType::PolicyCreated { domain: "access".into() };
        assert_eq!(event.kind(), "policy-created");
        let event2 = PolicyExtEventType::PackageExported { package_id: "p".into(), format: "json".into() };
        assert_eq!(event2.kind(), "package-exported");
    }

    #[test]
    fn test_is_backend_event() {
        assert!(PolicyExtEventType::PolicyPackageBackendChanged { backend_id: "b".into() }.is_backend_event());
        assert!(PolicyExtEventType::PackageStored { package_id: "p".into(), namespace: "n".into() }.is_backend_event());
        assert!(PolicyExtEventType::RuleSetStored { rule_set_id: "r".into(), package_id: "p".into() }.is_backend_event());
        assert!(!PolicyExtEventType::PackageComposed { source_count: 1, strategy: "s".into() }.is_backend_event());
    }

    #[test]
    fn test_is_package_event() {
        assert!(PolicyExtEventType::PackageStored { package_id: "p".into(), namespace: "n".into() }.is_package_event());
        assert!(PolicyExtEventType::PackageSignatureVerified { package_id: "p".into(), signer: "s".into() }.is_package_event());
        assert!(!PolicyExtEventType::PolicyCreated { domain: "d".into() }.is_package_event());
    }

    #[test]
    fn test_is_composition_event() {
        assert!(PolicyExtEventType::PackageComposed { source_count: 2, strategy: "union".into() }.is_composition_event());
        assert!(PolicyExtEventType::PackagePolicyConflictDetected { conflict_id: "c".into(), conflict_type: "t".into() }.is_composition_event());
        assert!(!PolicyExtEventType::PackageExported { package_id: "p".into(), format: "f".into() }.is_composition_event());
    }

    #[test]
    fn test_is_registry_event() {
        assert!(PolicyExtEventType::PackagePublishedToRegistry { package_id: "p".into(), registry_id: "r".into() }.is_registry_event());
        assert!(PolicyExtEventType::PackageUnpublishedFromRegistry { package_id: "p".into(), registry_id: "r".into() }.is_registry_event());
        assert!(!PolicyExtEventType::PolicyCreated { domain: "d".into() }.is_registry_event());
    }

    #[test]
    fn test_is_evaluation_event() {
        assert!(PolicyExtEventType::EvaluationPayloadPrepared { payload_id: "p".into(), evaluator_type: "e".into() }.is_evaluation_event());
        assert!(PolicyExtEventType::EvaluationSubmittedToExternal { handle: "h".into(), evaluator_type: "e".into() }.is_evaluation_event());
        assert!(PolicyExtEventType::EvaluationCanceled { handle: "h".into() }.is_evaluation_event());
        assert!(!PolicyExtEventType::PolicyCreated { domain: "d".into() }.is_evaluation_event());
    }

    #[test]
    fn test_is_export_event() {
        assert!(PolicyExtEventType::PackageExported { package_id: "p".into(), format: "f".into() }.is_export_event());
        assert!(PolicyExtEventType::PackageExportFailed { package_id: "p".into(), format: "f".into(), reason: "r".into() }.is_export_event());
        assert!(!PolicyExtEventType::PolicyCreated { domain: "d".into() }.is_export_event());
    }

    #[test]
    fn test_is_validation_event() {
        assert!(PolicyExtEventType::PackageValidated { package_id: "p".into(), passed: true, severity: "clean".into() }.is_validation_event());
        assert!(PolicyExtEventType::PackageValidationFailed { package_id: "p".into(), reason: "r".into() }.is_validation_event());
        assert!(!PolicyExtEventType::PolicyCreated { domain: "d".into() }.is_validation_event());
    }

    #[test]
    fn test_l3_events_by_type() {
        let mut log = PolicyExtAuditLog::new();
        log.record(PolicyExtAuditEvent::new(
            PolicyExtEventType::PackageExported { package_id: "p1".into(), format: "json".into() },
            "system", 1000, "",
        ));
        log.record(PolicyExtAuditEvent::new(
            PolicyExtEventType::PackageExported { package_id: "p2".into(), format: "cedar".into() },
            "system", 2000, "",
        ));
        log.record(PolicyExtAuditEvent::new(
            PolicyExtEventType::PackageValidated { package_id: "p1".into(), passed: true, severity: "clean".into() },
            "system", 3000, "",
        ));
        assert_eq!(log.events_by_type("package-exported").len(), 2);
        assert_eq!(log.events_by_type("package-validated").len(), 1);
    }
}
