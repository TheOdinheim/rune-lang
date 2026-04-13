// ═══════════════════════════════════════════════════════════════════════
// Delegation — Task delegation with governance inheritance.
// When one agent delegates to another, governance constraints flow.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::agent::AgentId;
use crate::autonomy::AutonomyLevel;
use crate::error::AgentError;

// ── DelegationId ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DelegationId(pub String);

impl DelegationId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for DelegationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── DelegationConstraints ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationConstraints {
    pub max_autonomy: AutonomyLevel,
    pub allowed_actions: Vec<String>,
    pub denied_actions: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub require_checkpoint: bool,
    pub inherit_trust: bool,
    pub max_sub_delegations: u32,
    pub reporting_required: bool,
}

impl DelegationConstraints {
    pub fn new(max_autonomy: AutonomyLevel) -> Self {
        Self {
            max_autonomy,
            allowed_actions: Vec::new(),
            denied_actions: Vec::new(),
            allowed_tools: Vec::new(),
            require_checkpoint: false,
            inherit_trust: false,
            max_sub_delegations: 0,
            reporting_required: false,
        }
    }

    pub fn with_checkpoint(mut self) -> Self {
        self.require_checkpoint = true;
        self
    }

    pub fn with_inherit_trust(mut self) -> Self {
        self.inherit_trust = true;
        self
    }

    pub fn with_sub_delegations(mut self, max: u32) -> Self {
        self.max_sub_delegations = max;
        self
    }

    pub fn with_reporting(mut self) -> Self {
        self.reporting_required = true;
        self
    }

    pub fn with_allowed_actions(mut self, actions: Vec<String>) -> Self {
        self.allowed_actions = actions;
        self
    }

    pub fn with_denied_actions(mut self, actions: Vec<String>) -> Self {
        self.denied_actions = actions;
        self
    }
}

// ── DelegationStatus ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegationStatus {
    Pending,
    Accepted,
    InProgress,
    Completed { success: bool },
    Rejected { reason: String },
    Revoked { reason: String },
    TimedOut,
}

impl DelegationStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed { .. } | Self::Rejected { .. } | Self::Revoked { .. } | Self::TimedOut
        )
    }
}

impl fmt::Display for DelegationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Accepted => write!(f, "Accepted"),
            Self::InProgress => write!(f, "InProgress"),
            Self::Completed { success } => write!(f, "Completed(success={success})"),
            Self::Rejected { reason } => write!(f, "Rejected: {reason}"),
            Self::Revoked { reason } => write!(f, "Revoked: {reason}"),
            Self::TimedOut => write!(f, "TimedOut"),
        }
    }
}

// ── Delegation ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub id: DelegationId,
    pub task: String,
    pub delegator: AgentId,
    pub delegate: AgentId,
    pub constraints: DelegationConstraints,
    pub status: DelegationStatus,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    pub result: Option<String>,
    pub max_duration_ms: Option<i64>,
    pub priority: u32,
}

// ── DelegationManager ────────────────────────────────────────────────

pub struct DelegationManager {
    delegations: HashMap<DelegationId, Delegation>,
    counter: u64,
}

impl DelegationManager {
    pub fn new() -> Self {
        Self {
            delegations: HashMap::new(),
            counter: 0,
        }
    }

    pub fn delegate(
        &mut self,
        delegator: &AgentId,
        delegate: &AgentId,
        task: &str,
        constraints: DelegationConstraints,
        now: i64,
    ) -> DelegationId {
        self.counter += 1;
        let id = DelegationId::new(format!("del_{:08x}", self.counter));
        let delegation = Delegation {
            id: id.clone(),
            task: task.into(),
            delegator: delegator.clone(),
            delegate: delegate.clone(),
            constraints,
            status: DelegationStatus::Pending,
            created_at: now,
            completed_at: None,
            result: None,
            max_duration_ms: None,
            priority: 0,
        };
        self.delegations.insert(id.clone(), delegation);
        id
    }

    pub fn accept(&mut self, id: &DelegationId, now: i64) -> Result<(), AgentError> {
        let del = self
            .delegations
            .get_mut(id)
            .ok_or_else(|| AgentError::DelegationNotFound(id.0.clone()))?;
        if del.status != DelegationStatus::Pending {
            return Err(AgentError::DelegationNotPending(id.0.clone()));
        }
        del.status = DelegationStatus::Accepted;
        let _ = now;
        Ok(())
    }

    pub fn reject(&mut self, id: &DelegationId, reason: &str) -> Result<(), AgentError> {
        let del = self
            .delegations
            .get_mut(id)
            .ok_or_else(|| AgentError::DelegationNotFound(id.0.clone()))?;
        if del.status != DelegationStatus::Pending {
            return Err(AgentError::DelegationNotPending(id.0.clone()));
        }
        del.status = DelegationStatus::Rejected {
            reason: reason.into(),
        };
        Ok(())
    }

    pub fn complete(
        &mut self,
        id: &DelegationId,
        success: bool,
        result: Option<&str>,
        now: i64,
    ) -> Result<(), AgentError> {
        let del = self
            .delegations
            .get_mut(id)
            .ok_or_else(|| AgentError::DelegationNotFound(id.0.clone()))?;
        del.status = DelegationStatus::Completed { success };
        del.completed_at = Some(now);
        del.result = result.map(String::from);
        Ok(())
    }

    pub fn revoke(&mut self, id: &DelegationId, reason: &str) -> Result<(), AgentError> {
        let del = self
            .delegations
            .get_mut(id)
            .ok_or_else(|| AgentError::DelegationNotFound(id.0.clone()))?;
        del.status = DelegationStatus::Revoked {
            reason: reason.into(),
        };
        Ok(())
    }

    pub fn get(&self, id: &DelegationId) -> Option<&Delegation> {
        self.delegations.get(id)
    }

    pub fn delegations_from(&self, agent_id: &AgentId) -> Vec<&Delegation> {
        self.delegations
            .values()
            .filter(|d| &d.delegator == agent_id)
            .collect()
    }

    pub fn delegations_to(&self, agent_id: &AgentId) -> Vec<&Delegation> {
        self.delegations
            .values()
            .filter(|d| &d.delegate == agent_id)
            .collect()
    }

    pub fn active_delegations(&self) -> Vec<&Delegation> {
        self.delegations
            .values()
            .filter(|d| !d.status.is_terminal())
            .collect()
    }

    pub fn can_sub_delegate(&self, id: &DelegationId) -> bool {
        self.delegations
            .get(id)
            .is_some_and(|d| d.constraints.max_sub_delegations > 0)
    }

    pub fn delegation_depth(&self, agent_id: &AgentId) -> u32 {
        // Count how many delegation hops lead to this agent
        let mut depth = 0u32;
        let mut current = agent_id.clone();
        let mut visited = std::collections::HashSet::new();
        visited.insert(current.clone());

        loop {
            let parent = self.delegations.values().find(|d| {
                &d.delegate == &current && !d.status.is_terminal()
            });
            match parent {
                Some(d) => {
                    depth += 1;
                    if !visited.insert(d.delegator.clone()) {
                        break; // cycle detection
                    }
                    current = d.delegator.clone();
                }
                None => break,
            }
        }
        depth
    }

    pub fn count(&self) -> usize {
        self.delegations.len()
    }
}

impl Default for DelegationManager {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_constraints() -> DelegationConstraints {
        DelegationConstraints::new(AutonomyLevel::ActLowRisk)
    }

    #[test]
    fn test_delegate_creates_delegation() {
        let mut mgr = DelegationManager::new();
        let id = mgr.delegate(&AgentId::new("a1"), &AgentId::new("a2"), "analyze data", default_constraints(), 1000);
        assert!(mgr.get(&id).is_some());
        assert_eq!(mgr.get(&id).unwrap().status, DelegationStatus::Pending);
    }

    #[test]
    fn test_accept_delegation() {
        let mut mgr = DelegationManager::new();
        let id = mgr.delegate(&AgentId::new("a1"), &AgentId::new("a2"), "task", default_constraints(), 1000);
        mgr.accept(&id, 2000).unwrap();
        assert_eq!(mgr.get(&id).unwrap().status, DelegationStatus::Accepted);
    }

    #[test]
    fn test_reject_delegation() {
        let mut mgr = DelegationManager::new();
        let id = mgr.delegate(&AgentId::new("a1"), &AgentId::new("a2"), "task", default_constraints(), 1000);
        mgr.reject(&id, "too busy").unwrap();
        assert!(matches!(mgr.get(&id).unwrap().status, DelegationStatus::Rejected { .. }));
    }

    #[test]
    fn test_complete_delegation() {
        let mut mgr = DelegationManager::new();
        let id = mgr.delegate(&AgentId::new("a1"), &AgentId::new("a2"), "task", default_constraints(), 1000);
        mgr.complete(&id, true, Some("done"), 2000).unwrap();
        assert!(matches!(mgr.get(&id).unwrap().status, DelegationStatus::Completed { success: true }));
    }

    #[test]
    fn test_revoke_delegation() {
        let mut mgr = DelegationManager::new();
        let id = mgr.delegate(&AgentId::new("a1"), &AgentId::new("a2"), "task", default_constraints(), 1000);
        mgr.revoke(&id, "changed priority").unwrap();
        assert!(matches!(mgr.get(&id).unwrap().status, DelegationStatus::Revoked { .. }));
    }

    #[test]
    fn test_delegations_from() {
        let mut mgr = DelegationManager::new();
        mgr.delegate(&AgentId::new("a1"), &AgentId::new("a2"), "task1", default_constraints(), 1000);
        mgr.delegate(&AgentId::new("a1"), &AgentId::new("a3"), "task2", default_constraints(), 1000);
        mgr.delegate(&AgentId::new("a2"), &AgentId::new("a3"), "task3", default_constraints(), 1000);
        assert_eq!(mgr.delegations_from(&AgentId::new("a1")).len(), 2);
    }

    #[test]
    fn test_delegations_to() {
        let mut mgr = DelegationManager::new();
        mgr.delegate(&AgentId::new("a1"), &AgentId::new("a2"), "task1", default_constraints(), 1000);
        mgr.delegate(&AgentId::new("a3"), &AgentId::new("a2"), "task2", default_constraints(), 1000);
        assert_eq!(mgr.delegations_to(&AgentId::new("a2")).len(), 2);
    }

    #[test]
    fn test_active_delegations() {
        let mut mgr = DelegationManager::new();
        let id1 = mgr.delegate(&AgentId::new("a1"), &AgentId::new("a2"), "t1", default_constraints(), 1000);
        mgr.delegate(&AgentId::new("a1"), &AgentId::new("a3"), "t2", default_constraints(), 1000);
        mgr.complete(&id1, true, None, 2000).unwrap();
        assert_eq!(mgr.active_delegations().len(), 1);
    }

    #[test]
    fn test_can_sub_delegate() {
        let mut mgr = DelegationManager::new();
        let id1 = mgr.delegate(
            &AgentId::new("a1"), &AgentId::new("a2"), "task",
            DelegationConstraints::new(AutonomyLevel::ActLowRisk).with_sub_delegations(2),
            1000,
        );
        let id2 = mgr.delegate(
            &AgentId::new("a1"), &AgentId::new("a3"), "task",
            default_constraints(), // max_sub_delegations = 0
            1000,
        );
        assert!(mgr.can_sub_delegate(&id1));
        assert!(!mgr.can_sub_delegate(&id2));
    }

    #[test]
    fn test_delegation_depth() {
        let mut mgr = DelegationManager::new();
        mgr.delegate(&AgentId::new("a1"), &AgentId::new("a2"), "t1", default_constraints(), 1000);
        mgr.delegate(&AgentId::new("a2"), &AgentId::new("a3"), "t2", default_constraints(), 1000);
        assert_eq!(mgr.delegation_depth(&AgentId::new("a3")), 2);
        assert_eq!(mgr.delegation_depth(&AgentId::new("a2")), 1);
        assert_eq!(mgr.delegation_depth(&AgentId::new("a1")), 0);
    }

    #[test]
    fn test_delegation_constraints_inherit_trust_and_checkpoint() {
        let c = DelegationConstraints::new(AutonomyLevel::ActLowRisk)
            .with_inherit_trust()
            .with_checkpoint()
            .with_reporting();
        assert!(c.inherit_trust);
        assert!(c.require_checkpoint);
        assert!(c.reporting_required);
    }

    #[test]
    fn test_delegation_status_display() {
        let statuses = vec![
            DelegationStatus::Pending,
            DelegationStatus::Accepted,
            DelegationStatus::InProgress,
            DelegationStatus::Completed { success: true },
            DelegationStatus::Rejected { reason: "no".into() },
            DelegationStatus::Revoked { reason: "changed".into() },
            DelegationStatus::TimedOut,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 7);
    }

    #[test]
    fn test_accept_non_pending_fails() {
        let mut mgr = DelegationManager::new();
        let id = mgr.delegate(&AgentId::new("a1"), &AgentId::new("a2"), "task", default_constraints(), 1000);
        mgr.accept(&id, 2000).unwrap();
        assert!(mgr.accept(&id, 3000).is_err());
    }
}
