// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Agent capability governance.
//
// Structured capability governance — what each agent is allowed to do,
// with granular permissions, risk levels, and expiration.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── CapabilityType ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum CapabilityType {
    Read { resources: Vec<String> },
    Write { resources: Vec<String> },
    Execute { actions: Vec<String> },
    Delegate { delegatable_capabilities: Vec<String> },
    Communicate { channels: Vec<String> },
    Model { operations: Vec<String> },
}

impl fmt::Display for CapabilityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Read { .. } => "Read",
            Self::Write { .. } => "Write",
            Self::Execute { .. } => "Execute",
            Self::Delegate { .. } => "Delegate",
            Self::Communicate { .. } => "Communicate",
            Self::Model { .. } => "Model",
        };
        f.write_str(s)
    }
}

// ── CapabilityRiskLevel ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityRiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for CapabilityRiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        f.write_str(s)
    }
}

// ── AgentCapability ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AgentCapability {
    pub id: String,
    pub name: String,
    pub capability_type: CapabilityType,
    pub risk_level: CapabilityRiskLevel,
    pub requires_approval: bool,
    pub max_invocations_per_hour: Option<u64>,
    pub granted_at: i64,
    pub expires_at: Option<i64>,
}

impl AgentCapability {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        capability_type: CapabilityType,
        risk_level: CapabilityRiskLevel,
        granted_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            capability_type,
            risk_level,
            requires_approval: false,
            max_invocations_per_hour: None,
            granted_at,
            expires_at: None,
        }
    }

    pub fn with_expires_at(mut self, expires: i64) -> Self {
        self.expires_at = Some(expires);
        self
    }

    pub fn with_requires_approval(mut self, req: bool) -> Self {
        self.requires_approval = req;
        self
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|e| now > e)
    }
}

// ── AgentCapabilityRegistry ───────────────────────────────────────

#[derive(Debug, Default)]
pub struct AgentCapabilityRegistry {
    capabilities: HashMap<String, Vec<AgentCapability>>,
}

impl AgentCapabilityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(&mut self, agent_id: &str, capability: AgentCapability) {
        self.capabilities
            .entry(agent_id.to_string())
            .or_default()
            .push(capability);
    }

    pub fn revoke(&mut self, agent_id: &str, capability_id: &str) -> bool {
        if let Some(caps) = self.capabilities.get_mut(agent_id) {
            let before = caps.len();
            caps.retain(|c| c.id != capability_id);
            caps.len() < before
        } else {
            false
        }
    }

    pub fn has_capability(&self, agent_id: &str, capability_id: &str, now: i64) -> bool {
        self.capabilities
            .get(agent_id)
            .map(|caps| {
                caps.iter()
                    .any(|c| c.id == capability_id && !c.is_expired(now))
            })
            .unwrap_or(false)
    }

    pub fn capabilities_for_agent(&self, agent_id: &str) -> Vec<&AgentCapability> {
        self.capabilities
            .get(agent_id)
            .map(|caps| caps.iter().collect())
            .unwrap_or_default()
    }

    pub fn agents_with_capability(&self, capability_id: &str) -> Vec<&str> {
        self.capabilities
            .iter()
            .filter(|(_, caps)| caps.iter().any(|c| c.id == capability_id))
            .map(|(agent_id, _)| agent_id.as_str())
            .collect()
    }

    pub fn expired_capabilities(&self, agent_id: &str, now: i64) -> Vec<&AgentCapability> {
        self.capabilities
            .get(agent_id)
            .map(|caps| caps.iter().filter(|c| c.is_expired(now)).collect())
            .unwrap_or_default()
    }

    pub fn high_risk_capabilities(&self, agent_id: &str) -> Vec<&AgentCapability> {
        self.capabilities
            .get(agent_id)
            .map(|caps| {
                caps.iter()
                    .filter(|c| c.risk_level >= CapabilityRiskLevel::High)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn capability_count(&self, agent_id: &str) -> usize {
        self.capabilities
            .get(agent_id)
            .map(|caps| caps.len())
            .unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grant_and_has_capability() {
        let mut reg = AgentCapabilityRegistry::new();
        reg.grant("a1", AgentCapability::new(
            "cap-read", "Read data",
            CapabilityType::Read { resources: vec!["db".into()] },
            CapabilityRiskLevel::Low, 1000,
        ));
        assert!(reg.has_capability("a1", "cap-read", 2000));
        assert!(!reg.has_capability("a1", "nonexistent", 2000));
    }

    #[test]
    fn test_revoke_removes_capability() {
        let mut reg = AgentCapabilityRegistry::new();
        reg.grant("a1", AgentCapability::new(
            "cap-1", "Cap",
            CapabilityType::Execute { actions: vec!["run".into()] },
            CapabilityRiskLevel::Medium, 1000,
        ));
        assert!(reg.revoke("a1", "cap-1"));
        assert!(!reg.has_capability("a1", "cap-1", 2000));
    }

    #[test]
    fn test_has_capability_false_for_expired() {
        let mut reg = AgentCapabilityRegistry::new();
        reg.grant("a1", AgentCapability::new(
            "cap-1", "Cap",
            CapabilityType::Read { resources: vec![] },
            CapabilityRiskLevel::Low, 1000,
        ).with_expires_at(2000));
        assert!(reg.has_capability("a1", "cap-1", 1500));
        assert!(!reg.has_capability("a1", "cap-1", 2500));
    }

    #[test]
    fn test_capabilities_for_agent() {
        let mut reg = AgentCapabilityRegistry::new();
        reg.grant("a1", AgentCapability::new("c1", "A", CapabilityType::Read { resources: vec![] }, CapabilityRiskLevel::Low, 1000));
        reg.grant("a1", AgentCapability::new("c2", "B", CapabilityType::Write { resources: vec![] }, CapabilityRiskLevel::Medium, 1000));
        assert_eq!(reg.capabilities_for_agent("a1").len(), 2);
    }

    #[test]
    fn test_agents_with_capability() {
        let mut reg = AgentCapabilityRegistry::new();
        reg.grant("a1", AgentCapability::new("c1", "A", CapabilityType::Read { resources: vec![] }, CapabilityRiskLevel::Low, 1000));
        reg.grant("a2", AgentCapability::new("c1", "A", CapabilityType::Read { resources: vec![] }, CapabilityRiskLevel::Low, 1000));
        reg.grant("a3", AgentCapability::new("c2", "B", CapabilityType::Write { resources: vec![] }, CapabilityRiskLevel::Low, 1000));
        let agents = reg.agents_with_capability("c1");
        assert_eq!(agents.len(), 2);
    }

    #[test]
    fn test_high_risk_capabilities() {
        let mut reg = AgentCapabilityRegistry::new();
        reg.grant("a1", AgentCapability::new("c1", "Low", CapabilityType::Read { resources: vec![] }, CapabilityRiskLevel::Low, 1000));
        reg.grant("a1", AgentCapability::new("c2", "High", CapabilityType::Execute { actions: vec![] }, CapabilityRiskLevel::High, 1000));
        reg.grant("a1", AgentCapability::new("c3", "Critical", CapabilityType::Model { operations: vec![] }, CapabilityRiskLevel::Critical, 1000));
        let high = reg.high_risk_capabilities("a1");
        assert_eq!(high.len(), 2);
    }

    #[test]
    fn test_expired_capabilities() {
        let mut reg = AgentCapabilityRegistry::new();
        reg.grant("a1", AgentCapability::new("c1", "A", CapabilityType::Read { resources: vec![] }, CapabilityRiskLevel::Low, 1000).with_expires_at(2000));
        reg.grant("a1", AgentCapability::new("c2", "B", CapabilityType::Read { resources: vec![] }, CapabilityRiskLevel::Low, 1000).with_expires_at(5000));
        let expired = reg.expired_capabilities("a1", 3000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, "c1");
    }
}
