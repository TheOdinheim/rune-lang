// ═══════════════════════════════════════════════════════════════════════
// Error — Agent error types for rune-agents
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone)]
pub enum AgentError {
    AgentNotFound(String),
    AgentAlreadyExists(String),
    AgentNotActive(String),
    AgentSuspended(String),
    ActionNotFound(String),
    ActionAlreadyComplete(String),
    ToolNotFound(String),
    ToolAlreadyExists(String),
    ToolPermissionDenied { tool_id: String, agent_id: String, reason: String },
    CheckpointNotFound(String),
    CheckpointAlreadyResolved(String),
    DelegationNotFound(String),
    DelegationNotPending(String),
    CommunicationDenied { sender: String, receiver: String, reason: String },
    ReasoningChainNotFound(String),
    ReasoningChainNotActive(String),
    BudgetExhausted { agent_id: String, max: u64, used: u64 },
    InvalidOperation(String),
    // Layer 2
    ProtocolNotFound(String),
    SessionNotFound(String),
    L2TaskNotFound(String),
    // Layer 3
    SerializationFailed(String),
    GovernanceProfileNotFound(String),
    DelegationChainNotFound(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentNotFound(id) => write!(f, "Agent not found: {id}"),
            Self::AgentAlreadyExists(id) => write!(f, "Agent already exists: {id}"),
            Self::AgentNotActive(id) => write!(f, "Agent not active: {id}"),
            Self::AgentSuspended(id) => write!(f, "Agent suspended: {id}"),
            Self::ActionNotFound(id) => write!(f, "Action not found: {id}"),
            Self::ActionAlreadyComplete(id) => write!(f, "Action already complete: {id}"),
            Self::ToolNotFound(id) => write!(f, "Tool not found: {id}"),
            Self::ToolAlreadyExists(id) => write!(f, "Tool already exists: {id}"),
            Self::ToolPermissionDenied { tool_id, agent_id, reason } => {
                write!(f, "Tool {tool_id} denied for agent {agent_id}: {reason}")
            }
            Self::CheckpointNotFound(id) => write!(f, "Checkpoint not found: {id}"),
            Self::CheckpointAlreadyResolved(id) => write!(f, "Checkpoint already resolved: {id}"),
            Self::DelegationNotFound(id) => write!(f, "Delegation not found: {id}"),
            Self::DelegationNotPending(id) => write!(f, "Delegation not pending: {id}"),
            Self::CommunicationDenied { sender, receiver, reason } => {
                write!(f, "Communication denied from {sender} to {receiver}: {reason}")
            }
            Self::ReasoningChainNotFound(id) => write!(f, "Reasoning chain not found: {id}"),
            Self::ReasoningChainNotActive(id) => write!(f, "Reasoning chain not active: {id}"),
            Self::BudgetExhausted { agent_id, max, used } => {
                write!(f, "Budget exhausted for agent {agent_id}: {used}/{max}")
            }
            Self::InvalidOperation(msg) => write!(f, "Invalid operation: {msg}"),
            Self::ProtocolNotFound(id) => write!(f, "Protocol not found: {id}"),
            Self::SessionNotFound(id) => write!(f, "Session not found: {id}"),
            Self::L2TaskNotFound(id) => write!(f, "L2 task not found: {id}"),
            Self::SerializationFailed(msg) => write!(f, "Serialization failed: {msg}"),
            Self::GovernanceProfileNotFound(id) => {
                write!(f, "Governance profile not found: {id}")
            }
            Self::DelegationChainNotFound(id) => {
                write!(f, "Delegation chain not found: {id}")
            }
        }
    }
}

impl std::error::Error for AgentError {}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors: Vec<AgentError> = vec![
            AgentError::AgentNotFound("a1".into()),
            AgentError::AgentAlreadyExists("a1".into()),
            AgentError::AgentNotActive("a1".into()),
            AgentError::AgentSuspended("a1".into()),
            AgentError::ActionNotFound("act1".into()),
            AgentError::ActionAlreadyComplete("act1".into()),
            AgentError::ToolNotFound("t1".into()),
            AgentError::ToolAlreadyExists("t1".into()),
            AgentError::ToolPermissionDenied {
                tool_id: "t1".into(),
                agent_id: "a1".into(),
                reason: "denied".into(),
            },
            AgentError::CheckpointNotFound("cp1".into()),
            AgentError::CheckpointAlreadyResolved("cp1".into()),
            AgentError::DelegationNotFound("d1".into()),
            AgentError::DelegationNotPending("d1".into()),
            AgentError::CommunicationDenied {
                sender: "a1".into(),
                receiver: "a2".into(),
                reason: "blocked".into(),
            },
            AgentError::ReasoningChainNotFound("rc1".into()),
            AgentError::ReasoningChainNotActive("rc1".into()),
            AgentError::BudgetExhausted { agent_id: "a1".into(), max: 10, used: 10 },
            AgentError::InvalidOperation("bad op".into()),
            AgentError::ProtocolNotFound("proto1".into()),
            AgentError::SessionNotFound("sess1".into()),
            AgentError::L2TaskNotFound("task1".into()),
            AgentError::SerializationFailed("json error".into()),
            AgentError::GovernanceProfileNotFound("gp1".into()),
            AgentError::DelegationChainNotFound("ch1".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
            let _ = format!("{e:?}");
            let _: &dyn std::error::Error = e;
        }
        assert_eq!(errors.len(), 24);
    }
}
