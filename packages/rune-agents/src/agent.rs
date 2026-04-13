// ═══════════════════════════════════════════════════════════════════════
// Agent — Agent identity, registration, and governance profile.
// Every governed agent has a typed identity with governance metadata.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::autonomy::AutonomyLevel;
use crate::error::AgentError;

// ── AgentId ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── AgentType ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentType {
    Autonomous,
    SemiAutonomous,
    Supervised,
    Reactive,
    Orchestrator,
    Custom(String),
}

impl fmt::Display for AgentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Autonomous => write!(f, "Autonomous"),
            Self::SemiAutonomous => write!(f, "SemiAutonomous"),
            Self::Supervised => write!(f, "Supervised"),
            Self::Reactive => write!(f, "Reactive"),
            Self::Orchestrator => write!(f, "Orchestrator"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ── AgentStatus ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Idle,
    Active,
    Paused,
    Suspended { reason: String },
    Terminated { reason: String },
}

impl AgentStatus {
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Idle | Self::Active | Self::Paused)
    }

    pub fn can_act(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated { .. })
    }
}

impl fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Active => write!(f, "Active"),
            Self::Paused => write!(f, "Paused"),
            Self::Suspended { reason } => write!(f, "Suspended: {reason}"),
            Self::Terminated { reason } => write!(f, "Terminated: {reason}"),
        }
    }
}

// ── Agent ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: AgentId,
    pub name: String,
    pub description: String,
    pub agent_type: AgentType,
    pub owner: String,
    pub autonomy_level: AutonomyLevel,
    pub status: AgentStatus,
    pub trust_score: f64,
    pub capabilities: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub max_actions_per_session: Option<u64>,
    pub actions_taken: u64,
    pub created_at: i64,
    pub last_active: Option<i64>,
    pub session_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl Agent {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        agent_type: AgentType,
        owner: impl Into<String>,
        autonomy_level: AutonomyLevel,
        now: i64,
    ) -> Self {
        Self {
            id: AgentId::new(id),
            name: name.into(),
            description: String::new(),
            agent_type,
            owner: owner.into(),
            autonomy_level,
            status: AgentStatus::Idle,
            trust_score: 0.5,
            capabilities: Vec::new(),
            allowed_domains: Vec::new(),
            max_actions_per_session: None,
            actions_taken: 0,
            created_at: now,
            last_active: None,
            session_id: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = caps;
        self
    }

    pub fn with_domains(mut self, domains: Vec<String>) -> Self {
        self.allowed_domains = domains;
        self
    }

    pub fn with_budget(mut self, max: u64) -> Self {
        self.max_actions_per_session = Some(max);
        self
    }

    pub fn with_trust(mut self, score: f64) -> Self {
        self.trust_score = score;
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

// ── AgentRegistry ────────────────────────────────────────────────────

pub struct AgentRegistry {
    agents: HashMap<AgentId, Agent>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
        }
    }

    pub fn register(&mut self, agent: Agent) -> Result<(), AgentError> {
        if self.agents.contains_key(&agent.id) {
            return Err(AgentError::AgentAlreadyExists(agent.id.0.clone()));
        }
        self.agents.insert(agent.id.clone(), agent);
        Ok(())
    }

    pub fn get(&self, id: &AgentId) -> Option<&Agent> {
        self.agents.get(id)
    }

    pub fn get_mut(&mut self, id: &AgentId) -> Option<&mut Agent> {
        self.agents.get_mut(id)
    }

    pub fn by_type(&self, agent_type: &AgentType) -> Vec<&Agent> {
        self.agents
            .values()
            .filter(|a| &a.agent_type == agent_type)
            .collect()
    }

    pub fn by_status(&self, status_name: &str) -> Vec<&Agent> {
        self.agents
            .values()
            .filter(|a| {
                let name = match &a.status {
                    AgentStatus::Idle => "idle",
                    AgentStatus::Active => "active",
                    AgentStatus::Paused => "paused",
                    AgentStatus::Suspended { .. } => "suspended",
                    AgentStatus::Terminated { .. } => "terminated",
                };
                name.eq_ignore_ascii_case(status_name)
            })
            .collect()
    }

    pub fn active_agents(&self) -> Vec<&Agent> {
        self.agents
            .values()
            .filter(|a| a.status == AgentStatus::Active)
            .collect()
    }

    pub fn by_owner(&self, owner: &str) -> Vec<&Agent> {
        self.agents.values().filter(|a| a.owner == owner).collect()
    }

    pub fn by_domain(&self, domain: &str) -> Vec<&Agent> {
        self.agents
            .values()
            .filter(|a| a.allowed_domains.iter().any(|d| d == domain))
            .collect()
    }

    pub fn deregister(&mut self, id: &AgentId) -> Result<Agent, AgentError> {
        self.agents
            .remove(id)
            .ok_or_else(|| AgentError::AgentNotFound(id.0.clone()))
    }

    pub fn suspend(&mut self, id: &AgentId, reason: &str) -> Result<(), AgentError> {
        let agent = self
            .agents
            .get_mut(id)
            .ok_or_else(|| AgentError::AgentNotFound(id.0.clone()))?;
        agent.status = AgentStatus::Suspended {
            reason: reason.into(),
        };
        Ok(())
    }

    pub fn activate(&mut self, id: &AgentId) -> Result<(), AgentError> {
        let agent = self
            .agents
            .get_mut(id)
            .ok_or_else(|| AgentError::AgentNotFound(id.0.clone()))?;
        if agent.status.is_terminal() {
            return Err(AgentError::InvalidOperation(format!(
                "Cannot activate terminated agent {}",
                id
            )));
        }
        agent.status = AgentStatus::Active;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.agents.len()
    }
}

impl Default for AgentRegistry {
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

    fn sample_agent(id: &str, agent_type: AgentType) -> Agent {
        Agent::new(id, format!("Agent {id}"), agent_type, "owner1", AutonomyLevel::ActMediumRisk, 1000)
    }

    #[test]
    fn test_agent_id_construction_and_display() {
        let id = AgentId::new("agent-1");
        assert_eq!(id.to_string(), "agent-1");
    }

    #[test]
    fn test_agent_construction() {
        let agent = sample_agent("a1", AgentType::Autonomous)
            .with_capabilities(vec!["search".into()])
            .with_domains(vec!["data_analysis".into()])
            .with_budget(100)
            .with_trust(0.8)
            .with_description("Test agent");
        assert_eq!(agent.id.0, "a1");
        assert_eq!(agent.capabilities, vec!["search"]);
        assert_eq!(agent.max_actions_per_session, Some(100));
        assert_eq!(agent.trust_score, 0.8);
    }

    #[test]
    fn test_agent_type_display() {
        let types = vec![
            AgentType::Autonomous,
            AgentType::SemiAutonomous,
            AgentType::Supervised,
            AgentType::Reactive,
            AgentType::Orchestrator,
            AgentType::Custom("special".into()),
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 6);
    }

    #[test]
    fn test_agent_status_is_operational() {
        assert!(AgentStatus::Idle.is_operational());
        assert!(AgentStatus::Active.is_operational());
        assert!(AgentStatus::Paused.is_operational());
        assert!(!AgentStatus::Suspended { reason: "x".into() }.is_operational());
        assert!(!AgentStatus::Terminated { reason: "x".into() }.is_operational());
    }

    #[test]
    fn test_agent_status_can_act() {
        assert!(!AgentStatus::Idle.can_act());
        assert!(AgentStatus::Active.can_act());
        assert!(!AgentStatus::Paused.can_act());
    }

    #[test]
    fn test_agent_status_is_terminal() {
        assert!(!AgentStatus::Idle.is_terminal());
        assert!(!AgentStatus::Suspended { reason: "x".into() }.is_terminal());
        assert!(AgentStatus::Terminated { reason: "x".into() }.is_terminal());
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = AgentRegistry::new();
        reg.register(sample_agent("a1", AgentType::Autonomous)).unwrap();
        assert!(reg.get(&AgentId::new("a1")).is_some());
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_registry_duplicate_fails() {
        let mut reg = AgentRegistry::new();
        reg.register(sample_agent("a1", AgentType::Autonomous)).unwrap();
        assert!(reg.register(sample_agent("a1", AgentType::Reactive)).is_err());
    }

    #[test]
    fn test_registry_by_type_owner_domain() {
        let mut reg = AgentRegistry::new();
        reg.register(
            sample_agent("a1", AgentType::Autonomous).with_domains(vec!["data".into()]),
        ).unwrap();
        reg.register(sample_agent("a2", AgentType::Supervised)).unwrap();
        assert_eq!(reg.by_type(&AgentType::Autonomous).len(), 1);
        assert_eq!(reg.by_owner("owner1").len(), 2);
        assert_eq!(reg.by_domain("data").len(), 1);
    }

    #[test]
    fn test_registry_active_agents() {
        let mut reg = AgentRegistry::new();
        reg.register(sample_agent("a1", AgentType::Autonomous)).unwrap();
        reg.register(sample_agent("a2", AgentType::Supervised)).unwrap();
        reg.activate(&AgentId::new("a1")).unwrap();
        assert_eq!(reg.active_agents().len(), 1);
    }

    #[test]
    fn test_registry_suspend_and_activate() {
        let mut reg = AgentRegistry::new();
        reg.register(sample_agent("a1", AgentType::Autonomous)).unwrap();
        reg.suspend(&AgentId::new("a1"), "policy violation").unwrap();
        assert!(matches!(
            reg.get(&AgentId::new("a1")).unwrap().status,
            AgentStatus::Suspended { .. }
        ));
        reg.activate(&AgentId::new("a1")).unwrap();
        assert_eq!(reg.get(&AgentId::new("a1")).unwrap().status, AgentStatus::Active);
    }

    #[test]
    fn test_registry_deregister() {
        let mut reg = AgentRegistry::new();
        reg.register(sample_agent("a1", AgentType::Autonomous)).unwrap();
        let removed = reg.deregister(&AgentId::new("a1")).unwrap();
        assert_eq!(removed.id.0, "a1");
        assert_eq!(reg.count(), 0);
    }
}
