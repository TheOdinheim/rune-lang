// ═══════════════════════════════════════════════════════════════════════
// Action — Action authorization and execution governance.
// Every action an agent takes must be authorized and tracked.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::agent::{Agent, AgentId};
use crate::autonomy::{AutonomyEnvelope, AutonomyOutcome};
use crate::error::AgentError;

// ── ActionId ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionId(pub String);

impl ActionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for ActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ActionType ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    Read,
    Write,
    Delete,
    Execute,
    Communicate,
    Delegate,
    Escalate,
    ToolInvocation { tool_name: String },
    Custom(String),
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "Read"),
            Self::Write => write!(f, "Write"),
            Self::Delete => write!(f, "Delete"),
            Self::Execute => write!(f, "Execute"),
            Self::Communicate => write!(f, "Communicate"),
            Self::Delegate => write!(f, "Delegate"),
            Self::Escalate => write!(f, "Escalate"),
            Self::ToolInvocation { tool_name } => write!(f, "ToolInvocation({tool_name})"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

impl ActionType {
    pub fn as_str(&self) -> String {
        match self {
            Self::Read => "read".into(),
            Self::Write => "write".into(),
            Self::Delete => "delete".into(),
            Self::Execute => "execute".into(),
            Self::Communicate => "communicate".into(),
            Self::Delegate => "delegate".into(),
            Self::Escalate => "escalate".into(),
            Self::ToolInvocation { tool_name } => format!("tool:{tool_name}"),
            Self::Custom(name) => name.clone(),
        }
    }
}

// ── ActionRisk ───────────────────────────────────────────────────────

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum ActionRisk {
    Negligible = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl ActionRisk {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Negligible => "negligible",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for ActionRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── ActionStatus ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionStatus {
    Requested,
    Authorized,
    InProgress,
    Completed { success: bool },
    Denied { reason: String },
    Cancelled { reason: String },
    TimedOut,
}

impl ActionStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed { .. } | Self::Denied { .. } | Self::Cancelled { .. } | Self::TimedOut
        )
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Completed { success: true })
    }
}

impl fmt::Display for ActionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested => write!(f, "Requested"),
            Self::Authorized => write!(f, "Authorized"),
            Self::InProgress => write!(f, "InProgress"),
            Self::Completed { success } => write!(f, "Completed(success={success})"),
            Self::Denied { reason } => write!(f, "Denied: {reason}"),
            Self::Cancelled { reason } => write!(f, "Cancelled: {reason}"),
            Self::TimedOut => write!(f, "TimedOut"),
        }
    }
}

// ── AgentAction ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    pub id: ActionId,
    pub agent_id: AgentId,
    pub action_type: ActionType,
    pub description: String,
    pub target_resource: Option<String>,
    pub risk_level: ActionRisk,
    pub parameters: HashMap<String, String>,
    pub justification: Option<String>,
    pub status: ActionStatus,
    pub requested_at: i64,
    pub authorized_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub authorized_by: Option<String>,
    pub result: Option<String>,
    pub parent_action_id: Option<ActionId>,
}

// ── ActionAuthorizer ─────────────────────────────────────────────────

pub struct ActionAuthorizer {
    action_log: Vec<AgentAction>,
    counter: u64,
}

impl ActionAuthorizer {
    pub fn new() -> Self {
        Self {
            action_log: Vec::new(),
            counter: 0,
        }
    }

    pub fn authorize(
        &mut self,
        agent: &Agent,
        envelope: &AutonomyEnvelope,
        action_type: ActionType,
        resource: Option<&str>,
        risk: ActionRisk,
        justification: Option<&str>,
        now: i64,
    ) -> AgentAction {
        self.counter += 1;
        let id = ActionId::new(format!("act_{:08x}", self.counter));

        let mut action = AgentAction {
            id: id.clone(),
            agent_id: agent.id.clone(),
            action_type: action_type.clone(),
            description: format!("{} action by {}", action_type, agent.id),
            target_resource: resource.map(String::from),
            risk_level: risk,
            parameters: HashMap::new(),
            justification: justification.map(String::from),
            status: ActionStatus::Requested,
            requested_at: now,
            authorized_at: None,
            completed_at: None,
            authorized_by: None,
            result: None,
            parent_action_id: None,
        };

        // a. Check agent status
        if !agent.status.can_act() {
            action.status = ActionStatus::Denied {
                reason: format!("Agent status is {}, cannot act", agent.status),
            };
            self.action_log.push(action.clone());
            return action;
        }

        // b. Check budget
        if let Some(max) = agent.max_actions_per_session {
            if agent.actions_taken >= max {
                action.status = ActionStatus::Denied {
                    reason: format!("Budget exhausted: {}/{max}", agent.actions_taken),
                };
                self.action_log.push(action.clone());
                return action;
            }
        }

        // c. Check autonomy envelope
        let risk_str = risk.as_str();
        let check = envelope.check_action(&action_type.as_str(), resource, risk_str);

        match &check.outcome {
            AutonomyOutcome::Permitted => {
                action.status = ActionStatus::Authorized;
                action.authorized_at = Some(now);
                action.authorized_by = Some("system".into());
            }
            AutonomyOutcome::RequiresEscalation { .. }
            | AutonomyOutcome::RequiresApproval { .. }
            | AutonomyOutcome::RequiresJustification => {
                action.status = ActionStatus::Requested;
            }
            AutonomyOutcome::Denied { reason } => {
                action.status = ActionStatus::Denied {
                    reason: reason.clone(),
                };
            }
            _ => {
                action.status = ActionStatus::Denied {
                    reason: check.detail.clone(),
                };
            }
        }

        self.action_log.push(action.clone());
        action
    }

    pub fn complete(
        &mut self,
        action_id: &ActionId,
        success: bool,
        result: Option<&str>,
        now: i64,
    ) -> Result<(), AgentError> {
        let action = self
            .action_log
            .iter_mut()
            .find(|a| &a.id == action_id)
            .ok_or_else(|| AgentError::ActionNotFound(action_id.0.clone()))?;
        if action.status.is_terminal() {
            return Err(AgentError::ActionAlreadyComplete(action_id.0.clone()));
        }
        action.status = ActionStatus::Completed { success };
        action.completed_at = Some(now);
        action.result = result.map(String::from);
        Ok(())
    }

    pub fn cancel(
        &mut self,
        action_id: &ActionId,
        reason: &str,
    ) -> Result<(), AgentError> {
        let action = self
            .action_log
            .iter_mut()
            .find(|a| &a.id == action_id)
            .ok_or_else(|| AgentError::ActionNotFound(action_id.0.clone()))?;
        if action.status.is_terminal() {
            return Err(AgentError::ActionAlreadyComplete(action_id.0.clone()));
        }
        action.status = ActionStatus::Cancelled {
            reason: reason.into(),
        };
        Ok(())
    }

    pub fn get(&self, id: &ActionId) -> Option<&AgentAction> {
        self.action_log.iter().find(|a| &a.id == id)
    }

    pub fn actions_for_agent(&self, agent_id: &AgentId) -> Vec<&AgentAction> {
        self.action_log
            .iter()
            .filter(|a| &a.agent_id == agent_id)
            .collect()
    }

    pub fn pending_actions(&self) -> Vec<&AgentAction> {
        self.action_log
            .iter()
            .filter(|a| matches!(a.status, ActionStatus::Requested))
            .collect()
    }

    pub fn denied_actions(&self) -> Vec<&AgentAction> {
        self.action_log
            .iter()
            .filter(|a| matches!(a.status, ActionStatus::Denied { .. }))
            .collect()
    }

    pub fn action_count(&self) -> usize {
        self.action_log.len()
    }
}

impl Default for ActionAuthorizer {
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
    use crate::agent::AgentStatus;
    use crate::autonomy::{AutonomyEnvelope, AutonomyBoundary, AutonomyLevel};

    fn active_agent(id: &str) -> Agent {
        let mut a = Agent::new(id, "Test", crate::agent::AgentType::Autonomous, "owner", AutonomyLevel::ActMediumRisk, 1000);
        a.status = AgentStatus::Active;
        a
    }

    fn default_envelope(agent_id: &str) -> AutonomyEnvelope {
        AutonomyEnvelope::new(AgentId::new(agent_id), AutonomyLevel::ActMediumRisk)
    }

    #[test]
    fn test_authorize_creates_authorized_action() {
        let mut auth = ActionAuthorizer::new();
        let agent = active_agent("a1");
        let env = default_envelope("a1");
        let action = auth.authorize(&agent, &env, ActionType::Read, None, ActionRisk::Low, None, 1000);
        assert_eq!(action.status, ActionStatus::Authorized);
        assert_eq!(auth.action_count(), 1);
    }

    #[test]
    fn test_authorize_denies_suspended_agent() {
        let mut auth = ActionAuthorizer::new();
        let mut agent = active_agent("a1");
        agent.status = AgentStatus::Suspended { reason: "policy".into() };
        let env = default_envelope("a1");
        let action = auth.authorize(&agent, &env, ActionType::Read, None, ActionRisk::Low, None, 1000);
        assert!(matches!(action.status, ActionStatus::Denied { .. }));
    }

    #[test]
    fn test_authorize_denies_budget_exhausted() {
        let mut auth = ActionAuthorizer::new();
        let mut agent = active_agent("a1");
        agent.max_actions_per_session = Some(5);
        agent.actions_taken = 5;
        let env = default_envelope("a1");
        let action = auth.authorize(&agent, &env, ActionType::Write, None, ActionRisk::Low, None, 1000);
        assert!(matches!(action.status, ActionStatus::Denied { .. }));
    }

    #[test]
    fn test_authorize_escalation_returns_requested() {
        let mut auth = ActionAuthorizer::new();
        let agent = active_agent("a1");
        // ActMediumRisk can't handle "high" risk
        let env = AutonomyEnvelope::new(AgentId::new("a1"), AutonomyLevel::ActLowRisk)
            .with_escalation("admin");
        let action = auth.authorize(&agent, &env, ActionType::Delete, None, ActionRisk::High, None, 1000);
        assert_eq!(action.status, ActionStatus::Requested);
    }

    #[test]
    fn test_complete_action() {
        let mut auth = ActionAuthorizer::new();
        let agent = active_agent("a1");
        let env = default_envelope("a1");
        let action = auth.authorize(&agent, &env, ActionType::Read, None, ActionRisk::Low, None, 1000);
        auth.complete(&action.id, true, Some("done"), 2000).unwrap();
        assert!(auth.get(&action.id).unwrap().status.is_success());
    }

    #[test]
    fn test_cancel_action() {
        let mut auth = ActionAuthorizer::new();
        let agent = active_agent("a1");
        let env = default_envelope("a1");
        let action = auth.authorize(&agent, &env, ActionType::Write, None, ActionRisk::Low, None, 1000);
        auth.cancel(&action.id, "changed mind").unwrap();
        assert!(matches!(auth.get(&action.id).unwrap().status, ActionStatus::Cancelled { .. }));
    }

    #[test]
    fn test_actions_for_agent() {
        let mut auth = ActionAuthorizer::new();
        let a1 = active_agent("a1");
        let a2 = active_agent("a2");
        let env1 = default_envelope("a1");
        let env2 = default_envelope("a2");
        auth.authorize(&a1, &env1, ActionType::Read, None, ActionRisk::Low, None, 1000);
        auth.authorize(&a2, &env2, ActionType::Write, None, ActionRisk::Low, None, 1000);
        auth.authorize(&a1, &env1, ActionType::Execute, None, ActionRisk::Medium, None, 1000);
        assert_eq!(auth.actions_for_agent(&AgentId::new("a1")).len(), 2);
    }

    #[test]
    fn test_pending_and_denied_actions() {
        let mut auth = ActionAuthorizer::new();
        let agent = active_agent("a1");
        let env_low = AutonomyEnvelope::new(AgentId::new("a1"), AutonomyLevel::ActLowRisk)
            .with_escalation("admin");
        // This will be Requested (escalation needed)
        auth.authorize(&agent, &env_low, ActionType::Delete, None, ActionRisk::High, None, 1000);
        // Denied via boundary
        let mut env_deny = AutonomyEnvelope::new(AgentId::new("a1"), AutonomyLevel::ActMediumRisk);
        env_deny.add_boundary(
            AutonomyBoundary::new("b", "deny delete").with_denied_actions(vec!["delete".into()]),
        );
        auth.authorize(&agent, &env_deny, ActionType::Delete, None, ActionRisk::Low, None, 1000);
        assert_eq!(auth.pending_actions().len(), 1);
        assert_eq!(auth.denied_actions().len(), 1);
    }

    #[test]
    fn test_action_risk_ordering() {
        assert!(ActionRisk::Negligible < ActionRisk::Low);
        assert!(ActionRisk::Low < ActionRisk::Medium);
        assert!(ActionRisk::Medium < ActionRisk::High);
        assert!(ActionRisk::High < ActionRisk::Critical);
    }

    #[test]
    fn test_action_type_display() {
        let types = vec![
            ActionType::Read,
            ActionType::Write,
            ActionType::Delete,
            ActionType::Execute,
            ActionType::Communicate,
            ActionType::Delegate,
            ActionType::Escalate,
            ActionType::ToolInvocation { tool_name: "search".into() },
            ActionType::Custom("special".into()),
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 9);
    }

    #[test]
    fn test_action_status_is_terminal_and_success() {
        assert!(!ActionStatus::Requested.is_terminal());
        assert!(!ActionStatus::Authorized.is_terminal());
        assert!(ActionStatus::Completed { success: true }.is_terminal());
        assert!(ActionStatus::Denied { reason: "x".into() }.is_terminal());
        assert!(ActionStatus::Cancelled { reason: "x".into() }.is_terminal());
        assert!(ActionStatus::TimedOut.is_terminal());
        assert!(ActionStatus::Completed { success: true }.is_success());
        assert!(!ActionStatus::Completed { success: false }.is_success());
        assert!(!ActionStatus::Denied { reason: "x".into() }.is_success());
    }
}
