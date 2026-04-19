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
        }
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
}
