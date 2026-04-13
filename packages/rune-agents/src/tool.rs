// ═══════════════════════════════════════════════════════════════════════
// Tool — Tool-use permissions and capability grants.
// Agents must have explicit capability grants to use each tool.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::action::{ActionId, ActionRisk};
use crate::agent::AgentId;
use crate::error::AgentError;

// ── ToolId ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ToolId(pub String);

impl ToolId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for ToolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ToolDefinition ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub id: ToolId,
    pub name: String,
    pub description: String,
    pub risk_level: ActionRisk,
    pub requires_approval: bool,
    pub allowed_agents: Vec<AgentId>,
    pub denied_agents: Vec<AgentId>,
    pub max_invocations_per_session: Option<u64>,
    pub cooldown_ms: Option<i64>,
    pub side_effects: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl ToolDefinition {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        risk_level: ActionRisk,
    ) -> Self {
        Self {
            id: ToolId::new(id),
            name: name.into(),
            description: String::new(),
            risk_level,
            requires_approval: false,
            allowed_agents: Vec::new(),
            denied_agents: Vec::new(),
            max_invocations_per_session: None,
            cooldown_ms: None,
            side_effects: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_requires_approval(mut self) -> Self {
        self.requires_approval = true;
        self
    }

    pub fn with_allowed_agents(mut self, agents: Vec<AgentId>) -> Self {
        self.allowed_agents = agents;
        self
    }

    pub fn with_denied_agents(mut self, agents: Vec<AgentId>) -> Self {
        self.denied_agents = agents;
        self
    }

    pub fn with_side_effects(mut self, effects: Vec<String>) -> Self {
        self.side_effects = effects;
        self
    }
}

// ── ToolInvocationStatus ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolInvocationStatus {
    Pending,
    Approved,
    Denied { reason: String },
    InProgress,
    Completed { success: bool },
    Failed { reason: String },
}

impl fmt::Display for ToolInvocationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Approved => write!(f, "Approved"),
            Self::Denied { reason } => write!(f, "Denied: {reason}"),
            Self::InProgress => write!(f, "InProgress"),
            Self::Completed { success } => write!(f, "Completed(success={success})"),
            Self::Failed { reason } => write!(f, "Failed: {reason}"),
        }
    }
}

// ── ToolInvocation ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocation {
    pub id: String,
    pub tool_id: ToolId,
    pub agent_id: AgentId,
    pub parameters: HashMap<String, String>,
    pub status: ToolInvocationStatus,
    pub requested_at: i64,
    pub completed_at: Option<i64>,
    pub result: Option<String>,
    pub action_id: Option<ActionId>,
}

// ── ToolPermissionOutcome ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolPermissionOutcome {
    Permitted,
    Denied { reason: String },
    RequiresApproval,
    CooldownActive { remaining_ms: i64 },
    BudgetExhausted { max: u64, used: u64 },
}

impl fmt::Display for ToolPermissionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permitted => write!(f, "Permitted"),
            Self::Denied { reason } => write!(f, "Denied: {reason}"),
            Self::RequiresApproval => write!(f, "RequiresApproval"),
            Self::CooldownActive { remaining_ms } => {
                write!(f, "CooldownActive({remaining_ms}ms)")
            }
            Self::BudgetExhausted { max, used } => {
                write!(f, "BudgetExhausted({used}/{max})")
            }
        }
    }
}

// ── ToolPermission ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ToolPermission {
    pub permitted: bool,
    pub outcome: ToolPermissionOutcome,
    pub detail: String,
}

// ── ToolRegistry ─────────────────────────────────────────────────────

pub struct ToolRegistry {
    tools: HashMap<ToolId, ToolDefinition>,
    invocations: Vec<ToolInvocation>,
    invocation_counter: u64,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            invocations: Vec::new(),
            invocation_counter: 0,
        }
    }

    pub fn register_tool(&mut self, tool: ToolDefinition) -> Result<(), AgentError> {
        if self.tools.contains_key(&tool.id) {
            return Err(AgentError::ToolAlreadyExists(tool.id.0.clone()));
        }
        self.tools.insert(tool.id.clone(), tool);
        Ok(())
    }

    pub fn get_tool(&self, id: &ToolId) -> Option<&ToolDefinition> {
        self.tools.get(id)
    }

    pub fn check_permission(&self, tool_id: &ToolId, agent_id: &AgentId) -> ToolPermission {
        let Some(tool) = self.tools.get(tool_id) else {
            return ToolPermission {
                permitted: false,
                outcome: ToolPermissionOutcome::Denied {
                    reason: "Tool not found".into(),
                },
                detail: format!("Tool '{}' does not exist", tool_id),
            };
        };

        // Check denied agents
        if tool.denied_agents.contains(agent_id) {
            return ToolPermission {
                permitted: false,
                outcome: ToolPermissionOutcome::Denied {
                    reason: "Agent explicitly denied".into(),
                },
                detail: format!("Agent '{}' is denied access to tool '{}'", agent_id, tool_id),
            };
        }

        // Check allowed agents (if non-empty, agent must be in list)
        if !tool.allowed_agents.is_empty() && !tool.allowed_agents.contains(agent_id) {
            return ToolPermission {
                permitted: false,
                outcome: ToolPermissionOutcome::Denied {
                    reason: "Agent not in allowed list".into(),
                },
                detail: format!("Agent '{}' not in allowed list for tool '{}'", agent_id, tool_id),
            };
        }

        // Check requires_approval
        if tool.requires_approval {
            return ToolPermission {
                permitted: false,
                outcome: ToolPermissionOutcome::RequiresApproval,
                detail: format!("Tool '{}' requires human approval", tool_id),
            };
        }

        ToolPermission {
            permitted: true,
            outcome: ToolPermissionOutcome::Permitted,
            detail: format!("Agent '{}' permitted to use tool '{}'", agent_id, tool_id),
        }
    }

    pub fn request_invocation(
        &mut self,
        tool_id: &ToolId,
        agent_id: &AgentId,
        params: HashMap<String, String>,
        now: i64,
    ) -> Result<ToolInvocation, AgentError> {
        if !self.tools.contains_key(tool_id) {
            return Err(AgentError::ToolNotFound(tool_id.0.clone()));
        }
        self.invocation_counter += 1;
        let invocation = ToolInvocation {
            id: format!("inv_{:08x}", self.invocation_counter),
            tool_id: tool_id.clone(),
            agent_id: agent_id.clone(),
            parameters: params,
            status: ToolInvocationStatus::Pending,
            requested_at: now,
            completed_at: None,
            result: None,
            action_id: None,
        };
        self.invocations.push(invocation.clone());
        Ok(invocation)
    }

    pub fn complete_invocation(
        &mut self,
        invocation_id: &str,
        success: bool,
        result: Option<&str>,
        now: i64,
    ) -> Result<(), AgentError> {
        let inv = self
            .invocations
            .iter_mut()
            .find(|i| i.id == invocation_id)
            .ok_or_else(|| AgentError::InvalidOperation(format!("Invocation {invocation_id} not found")))?;
        inv.status = if success {
            ToolInvocationStatus::Completed { success: true }
        } else {
            ToolInvocationStatus::Failed {
                reason: result.unwrap_or("unknown").into(),
            }
        };
        inv.completed_at = Some(now);
        inv.result = result.map(String::from);
        Ok(())
    }

    pub fn invocations_for_agent(&self, agent_id: &AgentId) -> Vec<&ToolInvocation> {
        self.invocations
            .iter()
            .filter(|i| &i.agent_id == agent_id)
            .collect()
    }

    pub fn invocations_for_tool(&self, tool_id: &ToolId) -> Vec<&ToolInvocation> {
        self.invocations
            .iter()
            .filter(|i| &i.tool_id == tool_id)
            .collect()
    }

    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }
}

impl Default for ToolRegistry {
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

    #[test]
    fn test_register_and_get_tool() {
        let mut reg = ToolRegistry::new();
        reg.register_tool(ToolDefinition::new("t1", "Search", ActionRisk::Low)).unwrap();
        assert!(reg.get_tool(&ToolId::new("t1")).is_some());
        assert_eq!(reg.tool_count(), 1);
    }

    #[test]
    fn test_check_permission_permits_unlisted_agent() {
        let mut reg = ToolRegistry::new();
        reg.register_tool(ToolDefinition::new("t1", "Search", ActionRisk::Low)).unwrap();
        let perm = reg.check_permission(&ToolId::new("t1"), &AgentId::new("a1"));
        assert!(perm.permitted);
        assert_eq!(perm.outcome, ToolPermissionOutcome::Permitted);
    }

    #[test]
    fn test_check_permission_denies_denied_agent() {
        let mut reg = ToolRegistry::new();
        reg.register_tool(
            ToolDefinition::new("t1", "Search", ActionRisk::Low)
                .with_denied_agents(vec![AgentId::new("bad_agent")]),
        ).unwrap();
        let perm = reg.check_permission(&ToolId::new("t1"), &AgentId::new("bad_agent"));
        assert!(!perm.permitted);
        assert!(matches!(perm.outcome, ToolPermissionOutcome::Denied { .. }));
    }

    #[test]
    fn test_check_permission_denies_unlisted_when_allowed_set() {
        let mut reg = ToolRegistry::new();
        reg.register_tool(
            ToolDefinition::new("t1", "Search", ActionRisk::Low)
                .with_allowed_agents(vec![AgentId::new("special_agent")]),
        ).unwrap();
        let perm = reg.check_permission(&ToolId::new("t1"), &AgentId::new("other_agent"));
        assert!(!perm.permitted);
    }

    #[test]
    fn test_check_permission_requires_approval() {
        let mut reg = ToolRegistry::new();
        reg.register_tool(
            ToolDefinition::new("t1", "Dangerous", ActionRisk::Critical).with_requires_approval(),
        ).unwrap();
        let perm = reg.check_permission(&ToolId::new("t1"), &AgentId::new("a1"));
        assert!(!perm.permitted);
        assert_eq!(perm.outcome, ToolPermissionOutcome::RequiresApproval);
    }

    #[test]
    fn test_request_invocation() {
        let mut reg = ToolRegistry::new();
        reg.register_tool(ToolDefinition::new("t1", "Search", ActionRisk::Low)).unwrap();
        let inv = reg.request_invocation(
            &ToolId::new("t1"),
            &AgentId::new("a1"),
            HashMap::from([("query".into(), "test".into())]),
            1000,
        ).unwrap();
        assert_eq!(inv.status, ToolInvocationStatus::Pending);
    }

    #[test]
    fn test_complete_invocation() {
        let mut reg = ToolRegistry::new();
        reg.register_tool(ToolDefinition::new("t1", "Search", ActionRisk::Low)).unwrap();
        let inv = reg.request_invocation(&ToolId::new("t1"), &AgentId::new("a1"), HashMap::new(), 1000).unwrap();
        reg.complete_invocation(&inv.id, true, Some("found it"), 2000).unwrap();
        let updated = reg.invocations_for_agent(&AgentId::new("a1"));
        assert!(matches!(updated[0].status, ToolInvocationStatus::Completed { success: true }));
    }

    #[test]
    fn test_invocations_for_agent() {
        let mut reg = ToolRegistry::new();
        reg.register_tool(ToolDefinition::new("t1", "S1", ActionRisk::Low)).unwrap();
        reg.register_tool(ToolDefinition::new("t2", "S2", ActionRisk::Low)).unwrap();
        reg.request_invocation(&ToolId::new("t1"), &AgentId::new("a1"), HashMap::new(), 1000).unwrap();
        reg.request_invocation(&ToolId::new("t2"), &AgentId::new("a1"), HashMap::new(), 1000).unwrap();
        reg.request_invocation(&ToolId::new("t1"), &AgentId::new("a2"), HashMap::new(), 1000).unwrap();
        assert_eq!(reg.invocations_for_agent(&AgentId::new("a1")).len(), 2);
    }

    #[test]
    fn test_invocations_for_tool() {
        let mut reg = ToolRegistry::new();
        reg.register_tool(ToolDefinition::new("t1", "S1", ActionRisk::Low)).unwrap();
        reg.request_invocation(&ToolId::new("t1"), &AgentId::new("a1"), HashMap::new(), 1000).unwrap();
        reg.request_invocation(&ToolId::new("t1"), &AgentId::new("a2"), HashMap::new(), 1000).unwrap();
        assert_eq!(reg.invocations_for_tool(&ToolId::new("t1")).len(), 2);
    }

    #[test]
    fn test_tool_invocation_status_display() {
        let statuses = vec![
            ToolInvocationStatus::Pending,
            ToolInvocationStatus::Approved,
            ToolInvocationStatus::Denied { reason: "no".into() },
            ToolInvocationStatus::InProgress,
            ToolInvocationStatus::Completed { success: true },
            ToolInvocationStatus::Failed { reason: "err".into() },
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 6);
    }

    #[test]
    fn test_tool_permission_outcome_display() {
        let outcomes = vec![
            ToolPermissionOutcome::Permitted,
            ToolPermissionOutcome::Denied { reason: "no".into() },
            ToolPermissionOutcome::RequiresApproval,
            ToolPermissionOutcome::CooldownActive { remaining_ms: 5000 },
            ToolPermissionOutcome::BudgetExhausted { max: 10, used: 10 },
        ];
        for o in &outcomes {
            assert!(!o.to_string().is_empty());
        }
        assert_eq!(outcomes.len(), 5);
    }
}
