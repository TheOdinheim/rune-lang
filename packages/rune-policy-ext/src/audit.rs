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
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
            assert!(!t.type_name().is_empty());
        }
        assert_eq!(types.len(), 11);
    }
}
