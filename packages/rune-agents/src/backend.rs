// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — AgentGovernanceBackend trait for pluggable storage of
// agent governance profiles, autonomy configurations, tool policies,
// delegation chain records, and governance snapshots.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::AgentError;

// ── StoredAgentGovernanceProfile ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAgentGovernanceProfile {
    pub profile_id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub agent_type: String,
    pub owner: String,
    pub autonomy_level: String,
    pub capabilities: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub governance_status: StoredAgentGovernanceStatus,
    pub created_at: i64,
    pub updated_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── StoredAgentGovernanceStatus ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StoredAgentGovernanceStatus {
    Active,
    Suspended,
    UnderReview,
    Decommissioned,
}

impl fmt::Display for StoredAgentGovernanceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Active => "Active",
            Self::Suspended => "Suspended",
            Self::UnderReview => "UnderReview",
            Self::Decommissioned => "Decommissioned",
        };
        f.write_str(s)
    }
}

// ── StoredAutonomyConfiguration ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAutonomyConfiguration {
    pub config_id: String,
    pub agent_id: String,
    pub autonomy_level: String,
    pub escalation_target: String,
    pub max_actions_per_session: String,
    pub allowed_risk_levels: Vec<String>,
    pub requires_human_oversight: bool,
    pub oversight_frequency: String,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── StoredToolPolicy ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredToolPolicy {
    pub policy_id: String,
    pub agent_id: String,
    pub tool_ref: String,
    pub decision: StoredToolPolicyDecision,
    pub justification: String,
    pub max_invocations: String,
    pub cooldown_ms: String,
    pub requires_approval: bool,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── StoredToolPolicyDecision ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StoredToolPolicyDecision {
    Allow,
    Deny,
    RequireApproval,
    AllowWithConstraints,
}

impl fmt::Display for StoredToolPolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Allow => "Allow",
            Self::Deny => "Deny",
            Self::RequireApproval => "RequireApproval",
            Self::AllowWithConstraints => "AllowWithConstraints",
        };
        f.write_str(s)
    }
}

// ── StoredDelegationChainRecord ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDelegationChainRecord {
    pub chain_id: String,
    pub delegator_id: String,
    pub delegatee_id: String,
    pub task_description: String,
    pub depth: usize,
    pub max_depth_allowed: usize,
    pub autonomy_constraint: String,
    pub chain_status: StoredDelegationChainStatus,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

// ── StoredDelegationChainStatus ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StoredDelegationChainStatus {
    Active,
    Completed,
    Revoked,
    DepthLimitExceeded,
}

impl fmt::Display for StoredDelegationChainStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Active => "Active",
            Self::Completed => "Completed",
            Self::Revoked => "Revoked",
            Self::DepthLimitExceeded => "DepthLimitExceeded",
        };
        f.write_str(s)
    }
}

// ── StoredGovernanceSnapshot ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGovernanceSnapshot {
    pub snapshot_id: String,
    pub agent_id: String,
    pub captured_at: i64,
    pub autonomy_level: String,
    pub active_tool_policies: usize,
    pub active_delegations: usize,
    pub governance_status: String,
    pub metadata: HashMap<String, String>,
}

// ── AgentGovernanceBackend trait ─────────────────────────────────────

pub trait AgentGovernanceBackend {
    // Agent governance profiles
    fn store_governance_profile(
        &mut self,
        profile: StoredAgentGovernanceProfile,
    ) -> Result<(), AgentError>;
    fn retrieve_governance_profile(
        &self,
        profile_id: &str,
    ) -> Result<Option<StoredAgentGovernanceProfile>, AgentError>;
    fn list_profiles_by_status(
        &self,
        status: &StoredAgentGovernanceStatus,
    ) -> Vec<StoredAgentGovernanceProfile>;
    fn profile_count(&self) -> usize;

    // Autonomy configurations
    fn store_autonomy_configuration(
        &mut self,
        config: StoredAutonomyConfiguration,
    ) -> Result<(), AgentError>;
    fn retrieve_autonomy_configuration(
        &self,
        config_id: &str,
    ) -> Result<Option<StoredAutonomyConfiguration>, AgentError>;
    fn list_configs_by_agent(&self, agent_id: &str) -> Vec<StoredAutonomyConfiguration>;

    // Tool policies
    fn store_tool_policy(&mut self, policy: StoredToolPolicy) -> Result<(), AgentError>;
    fn retrieve_tool_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredToolPolicy>, AgentError>;
    fn list_policies_by_agent(&self, agent_id: &str) -> Vec<StoredToolPolicy>;

    // Delegation chain records
    fn store_delegation_chain(
        &mut self,
        chain: StoredDelegationChainRecord,
    ) -> Result<(), AgentError>;
    fn retrieve_delegation_chain(
        &self,
        chain_id: &str,
    ) -> Result<Option<StoredDelegationChainRecord>, AgentError>;
    fn list_chains_by_delegator(&self, delegator_id: &str) -> Vec<StoredDelegationChainRecord>;

    // Governance snapshots
    fn store_governance_snapshot(
        &mut self,
        snapshot: StoredGovernanceSnapshot,
    ) -> Result<(), AgentError>;
    fn retrieve_governance_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<StoredGovernanceSnapshot>, AgentError>;
    fn list_snapshots_by_agent(&self, agent_id: &str) -> Vec<StoredGovernanceSnapshot>;

    // Lifecycle
    fn flush(&mut self) -> Result<(), AgentError>;
    fn backend_info(&self) -> String;
}

// ── InMemoryAgentGovernanceBackend ───────────────────────────────────

pub struct InMemoryAgentGovernanceBackend {
    profiles: HashMap<String, StoredAgentGovernanceProfile>,
    autonomy_configs: HashMap<String, StoredAutonomyConfiguration>,
    tool_policies: HashMap<String, StoredToolPolicy>,
    delegation_chains: HashMap<String, StoredDelegationChainRecord>,
    snapshots: HashMap<String, StoredGovernanceSnapshot>,
}

impl InMemoryAgentGovernanceBackend {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            autonomy_configs: HashMap::new(),
            tool_policies: HashMap::new(),
            delegation_chains: HashMap::new(),
            snapshots: HashMap::new(),
        }
    }
}

impl Default for InMemoryAgentGovernanceBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentGovernanceBackend for InMemoryAgentGovernanceBackend {
    fn store_governance_profile(
        &mut self,
        profile: StoredAgentGovernanceProfile,
    ) -> Result<(), AgentError> {
        self.profiles.insert(profile.profile_id.clone(), profile);
        Ok(())
    }

    fn retrieve_governance_profile(
        &self,
        profile_id: &str,
    ) -> Result<Option<StoredAgentGovernanceProfile>, AgentError> {
        Ok(self.profiles.get(profile_id).cloned())
    }

    fn list_profiles_by_status(
        &self,
        status: &StoredAgentGovernanceStatus,
    ) -> Vec<StoredAgentGovernanceProfile> {
        self.profiles
            .values()
            .filter(|p| &p.governance_status == status)
            .cloned()
            .collect()
    }

    fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    fn store_autonomy_configuration(
        &mut self,
        config: StoredAutonomyConfiguration,
    ) -> Result<(), AgentError> {
        self.autonomy_configs
            .insert(config.config_id.clone(), config);
        Ok(())
    }

    fn retrieve_autonomy_configuration(
        &self,
        config_id: &str,
    ) -> Result<Option<StoredAutonomyConfiguration>, AgentError> {
        Ok(self.autonomy_configs.get(config_id).cloned())
    }

    fn list_configs_by_agent(&self, agent_id: &str) -> Vec<StoredAutonomyConfiguration> {
        self.autonomy_configs
            .values()
            .filter(|c| c.agent_id == agent_id)
            .cloned()
            .collect()
    }

    fn store_tool_policy(&mut self, policy: StoredToolPolicy) -> Result<(), AgentError> {
        self.tool_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    fn retrieve_tool_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredToolPolicy>, AgentError> {
        Ok(self.tool_policies.get(policy_id).cloned())
    }

    fn list_policies_by_agent(&self, agent_id: &str) -> Vec<StoredToolPolicy> {
        self.tool_policies
            .values()
            .filter(|p| p.agent_id == agent_id)
            .cloned()
            .collect()
    }

    fn store_delegation_chain(
        &mut self,
        chain: StoredDelegationChainRecord,
    ) -> Result<(), AgentError> {
        self.delegation_chains
            .insert(chain.chain_id.clone(), chain);
        Ok(())
    }

    fn retrieve_delegation_chain(
        &self,
        chain_id: &str,
    ) -> Result<Option<StoredDelegationChainRecord>, AgentError> {
        Ok(self.delegation_chains.get(chain_id).cloned())
    }

    fn list_chains_by_delegator(&self, delegator_id: &str) -> Vec<StoredDelegationChainRecord> {
        self.delegation_chains
            .values()
            .filter(|c| c.delegator_id == delegator_id)
            .cloned()
            .collect()
    }

    fn store_governance_snapshot(
        &mut self,
        snapshot: StoredGovernanceSnapshot,
    ) -> Result<(), AgentError> {
        self.snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
        Ok(())
    }

    fn retrieve_governance_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<StoredGovernanceSnapshot>, AgentError> {
        Ok(self.snapshots.get(snapshot_id).cloned())
    }

    fn list_snapshots_by_agent(&self, agent_id: &str) -> Vec<StoredGovernanceSnapshot> {
        self.snapshots
            .values()
            .filter(|s| s.agent_id == agent_id)
            .cloned()
            .collect()
    }

    fn flush(&mut self) -> Result<(), AgentError> {
        self.profiles.clear();
        self.autonomy_configs.clear();
        self.tool_policies.clear();
        self.delegation_chains.clear();
        self.snapshots.clear();
        Ok(())
    }

    fn backend_info(&self) -> String {
        format!(
            "InMemoryAgentGovernanceBackend(profiles={}, configs={}, policies={}, chains={}, snapshots={})",
            self.profiles.len(),
            self.autonomy_configs.len(),
            self.tool_policies.len(),
            self.delegation_chains.len(),
            self.snapshots.len(),
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile(id: &str, agent_id: &str) -> StoredAgentGovernanceProfile {
        StoredAgentGovernanceProfile {
            profile_id: id.into(),
            agent_id: agent_id.into(),
            agent_name: format!("Agent {agent_id}"),
            agent_type: "Autonomous".into(),
            owner: "ops-team".into(),
            autonomy_level: "ActMediumRisk".into(),
            capabilities: vec!["search".into(), "analyze".into()],
            allowed_domains: vec!["data".into()],
            governance_status: StoredAgentGovernanceStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_config(id: &str, agent_id: &str) -> StoredAutonomyConfiguration {
        StoredAutonomyConfiguration {
            config_id: id.into(),
            agent_id: agent_id.into(),
            autonomy_level: "ActLowRisk".into(),
            escalation_target: "human-operator".into(),
            max_actions_per_session: "100".into(),
            allowed_risk_levels: vec!["low".into(), "medium".into()],
            requires_human_oversight: true,
            oversight_frequency: "every_action".into(),
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_tool_policy(id: &str, agent_id: &str) -> StoredToolPolicy {
        StoredToolPolicy {
            policy_id: id.into(),
            agent_id: agent_id.into(),
            tool_ref: "web-search".into(),
            decision: StoredToolPolicyDecision::Allow,
            justification: "approved for search".into(),
            max_invocations: "50".into(),
            cooldown_ms: "1000".into(),
            requires_approval: false,
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_chain(id: &str, delegator: &str) -> StoredDelegationChainRecord {
        StoredDelegationChainRecord {
            chain_id: id.into(),
            delegator_id: delegator.into(),
            delegatee_id: "agent-b".into(),
            task_description: "analyze dataset".into(),
            depth: 1,
            max_depth_allowed: 3,
            autonomy_constraint: "ActLowRisk".into(),
            chain_status: StoredDelegationChainStatus::Active,
            created_at: 1000,
            completed_at: None,
            metadata: HashMap::new(),
        }
    }

    fn sample_snapshot(id: &str, agent_id: &str) -> StoredGovernanceSnapshot {
        StoredGovernanceSnapshot {
            snapshot_id: id.into(),
            agent_id: agent_id.into(),
            captured_at: 2000,
            autonomy_level: "ActMediumRisk".into(),
            active_tool_policies: 3,
            active_delegations: 1,
            governance_status: "Active".into(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_store_and_retrieve_profile() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_governance_profile(sample_profile("p1", "agent-1"))
            .unwrap();
        let retrieved = backend.retrieve_governance_profile("p1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().agent_id, "agent-1");
    }

    #[test]
    fn test_list_profiles_by_status() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_governance_profile(sample_profile("p1", "a1"))
            .unwrap();
        let mut suspended = sample_profile("p2", "a2");
        suspended.governance_status = StoredAgentGovernanceStatus::Suspended;
        backend.store_governance_profile(suspended).unwrap();
        let active = backend.list_profiles_by_status(&StoredAgentGovernanceStatus::Active);
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_profile_count() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        assert_eq!(backend.profile_count(), 0);
        backend
            .store_governance_profile(sample_profile("p1", "a1"))
            .unwrap();
        assert_eq!(backend.profile_count(), 1);
    }

    #[test]
    fn test_store_and_retrieve_autonomy_config() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_autonomy_configuration(sample_config("c1", "a1"))
            .unwrap();
        let retrieved = backend.retrieve_autonomy_configuration("c1").unwrap();
        assert!(retrieved.is_some());
        assert!(retrieved.unwrap().requires_human_oversight);
    }

    #[test]
    fn test_list_configs_by_agent() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_autonomy_configuration(sample_config("c1", "a1"))
            .unwrap();
        backend
            .store_autonomy_configuration(sample_config("c2", "a1"))
            .unwrap();
        backend
            .store_autonomy_configuration(sample_config("c3", "a2"))
            .unwrap();
        assert_eq!(backend.list_configs_by_agent("a1").len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_tool_policy() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_tool_policy(sample_tool_policy("tp1", "a1"))
            .unwrap();
        let retrieved = backend.retrieve_tool_policy("tp1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().decision, StoredToolPolicyDecision::Allow);
    }

    #[test]
    fn test_list_policies_by_agent() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_tool_policy(sample_tool_policy("tp1", "a1"))
            .unwrap();
        backend
            .store_tool_policy(sample_tool_policy("tp2", "a1"))
            .unwrap();
        assert_eq!(backend.list_policies_by_agent("a1").len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_delegation_chain() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_delegation_chain(sample_chain("ch1", "a1"))
            .unwrap();
        let retrieved = backend.retrieve_delegation_chain("ch1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().depth, 1);
    }

    #[test]
    fn test_list_chains_by_delegator() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_delegation_chain(sample_chain("ch1", "a1"))
            .unwrap();
        backend
            .store_delegation_chain(sample_chain("ch2", "a1"))
            .unwrap();
        assert_eq!(backend.list_chains_by_delegator("a1").len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_snapshot() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_governance_snapshot(sample_snapshot("s1", "a1"))
            .unwrap();
        let retrieved = backend.retrieve_governance_snapshot("s1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().active_tool_policies, 3);
    }

    #[test]
    fn test_list_snapshots_by_agent() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_governance_snapshot(sample_snapshot("s1", "a1"))
            .unwrap();
        backend
            .store_governance_snapshot(sample_snapshot("s2", "a1"))
            .unwrap();
        assert_eq!(backend.list_snapshots_by_agent("a1").len(), 2);
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemoryAgentGovernanceBackend::new();
        backend
            .store_governance_profile(sample_profile("p1", "a1"))
            .unwrap();
        backend
            .store_autonomy_configuration(sample_config("c1", "a1"))
            .unwrap();
        backend.flush().unwrap();
        assert_eq!(backend.profile_count(), 0);
    }

    #[test]
    fn test_backend_info() {
        let backend = InMemoryAgentGovernanceBackend::new();
        let info = backend.backend_info();
        assert!(info.contains("InMemoryAgentGovernanceBackend"));
    }

    #[test]
    fn test_governance_status_display() {
        let statuses = vec![
            StoredAgentGovernanceStatus::Active,
            StoredAgentGovernanceStatus::Suspended,
            StoredAgentGovernanceStatus::UnderReview,
            StoredAgentGovernanceStatus::Decommissioned,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn test_tool_policy_decision_display() {
        let decisions = vec![
            StoredToolPolicyDecision::Allow,
            StoredToolPolicyDecision::Deny,
            StoredToolPolicyDecision::RequireApproval,
            StoredToolPolicyDecision::AllowWithConstraints,
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(decisions.len(), 4);
    }

    #[test]
    fn test_delegation_chain_status_display() {
        let statuses = vec![
            StoredDelegationChainStatus::Active,
            StoredDelegationChainStatus::Completed,
            StoredDelegationChainStatus::Revoked,
            StoredDelegationChainStatus::DepthLimitExceeded,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn test_retrieve_nonexistent() {
        let backend = InMemoryAgentGovernanceBackend::new();
        assert!(backend
            .retrieve_governance_profile("nonexistent")
            .unwrap()
            .is_none());
        assert!(backend
            .retrieve_autonomy_configuration("nonexistent")
            .unwrap()
            .is_none());
        assert!(backend
            .retrieve_tool_policy("nonexistent")
            .unwrap()
            .is_none());
        assert!(backend
            .retrieve_delegation_chain("nonexistent")
            .unwrap()
            .is_none());
        assert!(backend
            .retrieve_governance_snapshot("nonexistent")
            .unwrap()
            .is_none());
    }
}
