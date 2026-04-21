// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — ToolUseGovernor trait for governing agent tool-use policy
// decisions: per-agent tool access control, approval requirements,
// invocation limits, and policy management.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::AgentError;

// ── ToolGovernanceDecision ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolGovernanceDecision {
    Permit,
    Deny,
    RequireApproval,
    RateLimited,
    DeferToHuman,
}

impl fmt::Display for ToolGovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Permit => "Permit",
            Self::Deny => "Deny",
            Self::RequireApproval => "RequireApproval",
            Self::RateLimited => "RateLimited",
            Self::DeferToHuman => "DeferToHuman",
        };
        f.write_str(s)
    }
}

// ── ToolGovernanceEvaluation ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolGovernanceEvaluation {
    pub agent_id: String,
    pub tool_ref: String,
    pub decision: ToolGovernanceDecision,
    pub justification: String,
    pub remaining_invocations: Option<String>,
    pub evaluated_at: i64,
}

// ── ToolPolicyEntry ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPolicyEntry {
    pub agent_id: String,
    pub tool_ref: String,
    pub decision: ToolGovernanceDecision,
    pub max_invocations: Option<usize>,
    pub requires_justification: bool,
}

// ── ToolUseGovernor trait ───────────────────────────────────────────

pub trait ToolUseGovernor {
    fn evaluate_tool_request(
        &self,
        agent_id: &str,
        tool_ref: &str,
        context: &HashMap<String, String>,
    ) -> Result<ToolGovernanceEvaluation, AgentError>;

    fn register_tool_policy(
        &mut self,
        policy: ToolPolicyEntry,
    ) -> Result<(), AgentError>;

    fn remove_tool_policy(
        &mut self,
        agent_id: &str,
        tool_ref: &str,
    ) -> Result<(), AgentError>;

    fn list_tool_policies(&self, agent_id: &str) -> Vec<ToolPolicyEntry>;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryToolUseGovernor ─────────────────────────────────────────

pub struct InMemoryToolUseGovernor {
    id: String,
    policies: Vec<ToolPolicyEntry>,
    invocation_counts: HashMap<(String, String), usize>,
}

impl InMemoryToolUseGovernor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            policies: Vec::new(),
            invocation_counts: HashMap::new(),
        }
    }

    pub fn record_invocation(&mut self, agent_id: &str, tool_ref: &str) {
        *self
            .invocation_counts
            .entry((agent_id.into(), tool_ref.into()))
            .or_default() += 1;
    }
}

impl ToolUseGovernor for InMemoryToolUseGovernor {
    fn evaluate_tool_request(
        &self,
        agent_id: &str,
        tool_ref: &str,
        _context: &HashMap<String, String>,
    ) -> Result<ToolGovernanceEvaluation, AgentError> {
        let policy = self
            .policies
            .iter()
            .find(|p| p.agent_id == agent_id && p.tool_ref == tool_ref);

        match policy {
            Some(p) => {
                // Check invocation limit
                if let Some(max) = p.max_invocations {
                    let count = self
                        .invocation_counts
                        .get(&(agent_id.into(), tool_ref.into()))
                        .copied()
                        .unwrap_or(0);
                    if count >= max {
                        return Ok(ToolGovernanceEvaluation {
                            agent_id: agent_id.into(),
                            tool_ref: tool_ref.into(),
                            decision: ToolGovernanceDecision::RateLimited,
                            justification: format!(
                                "Invocation limit reached: {count}/{max}"
                            ),
                            remaining_invocations: Some("0".into()),
                            evaluated_at: 0,
                        });
                    }
                    let remaining = max - self
                        .invocation_counts
                        .get(&(agent_id.into(), tool_ref.into()))
                        .copied()
                        .unwrap_or(0);
                    return Ok(ToolGovernanceEvaluation {
                        agent_id: agent_id.into(),
                        tool_ref: tool_ref.into(),
                        decision: p.decision.clone(),
                        justification: "Policy matched".into(),
                        remaining_invocations: Some(remaining.to_string()),
                        evaluated_at: 0,
                    });
                }

                Ok(ToolGovernanceEvaluation {
                    agent_id: agent_id.into(),
                    tool_ref: tool_ref.into(),
                    decision: p.decision.clone(),
                    justification: "Policy matched".into(),
                    remaining_invocations: None,
                    evaluated_at: 0,
                })
            }
            None => Ok(ToolGovernanceEvaluation {
                agent_id: agent_id.into(),
                tool_ref: tool_ref.into(),
                decision: ToolGovernanceDecision::Deny,
                justification: "No policy found — default deny".into(),
                remaining_invocations: None,
                evaluated_at: 0,
            }),
        }
    }

    fn register_tool_policy(
        &mut self,
        policy: ToolPolicyEntry,
    ) -> Result<(), AgentError> {
        // Remove existing policy for same agent+tool
        self.policies
            .retain(|p| !(p.agent_id == policy.agent_id && p.tool_ref == policy.tool_ref));
        self.policies.push(policy);
        Ok(())
    }

    fn remove_tool_policy(
        &mut self,
        agent_id: &str,
        tool_ref: &str,
    ) -> Result<(), AgentError> {
        let before = self.policies.len();
        self.policies
            .retain(|p| !(p.agent_id == agent_id && p.tool_ref == tool_ref));
        if self.policies.len() == before {
            return Err(AgentError::InvalidOperation(format!(
                "No policy for agent={agent_id}, tool={tool_ref}"
            )));
        }
        Ok(())
    }

    fn list_tool_policies(&self, agent_id: &str) -> Vec<ToolPolicyEntry> {
        self.policies
            .iter()
            .filter(|p| p.agent_id == agent_id)
            .cloned()
            .collect()
    }

    fn governor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── DenyAllToolUseGovernor ──────────────────────────────────────────
// For agents that should never have tool access.

pub struct DenyAllToolUseGovernor {
    id: String,
}

impl DenyAllToolUseGovernor {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

impl ToolUseGovernor for DenyAllToolUseGovernor {
    fn evaluate_tool_request(
        &self,
        agent_id: &str,
        tool_ref: &str,
        _context: &HashMap<String, String>,
    ) -> Result<ToolGovernanceEvaluation, AgentError> {
        Ok(ToolGovernanceEvaluation {
            agent_id: agent_id.into(),
            tool_ref: tool_ref.into(),
            decision: ToolGovernanceDecision::Deny,
            justification: "All tool use denied by policy".into(),
            remaining_invocations: Some("0".into()),
            evaluated_at: 0,
        })
    }

    fn register_tool_policy(
        &mut self,
        _policy: ToolPolicyEntry,
    ) -> Result<(), AgentError> {
        Err(AgentError::InvalidOperation(
            "DenyAllToolUseGovernor does not accept policies".into(),
        ))
    }

    fn remove_tool_policy(
        &mut self,
        _agent_id: &str,
        _tool_ref: &str,
    ) -> Result<(), AgentError> {
        Err(AgentError::InvalidOperation(
            "DenyAllToolUseGovernor has no policies".into(),
        ))
    }

    fn list_tool_policies(&self, _agent_id: &str) -> Vec<ToolPolicyEntry> {
        Vec::new()
    }

    fn governor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── NullToolUseGovernor ─────────────────────────────────────────────

pub struct NullToolUseGovernor;

impl ToolUseGovernor for NullToolUseGovernor {
    fn evaluate_tool_request(
        &self,
        agent_id: &str,
        tool_ref: &str,
        _context: &HashMap<String, String>,
    ) -> Result<ToolGovernanceEvaluation, AgentError> {
        Ok(ToolGovernanceEvaluation {
            agent_id: agent_id.into(),
            tool_ref: tool_ref.into(),
            decision: ToolGovernanceDecision::Permit,
            justification: "Null governor — no tool governance".into(),
            remaining_invocations: None,
            evaluated_at: 0,
        })
    }

    fn register_tool_policy(
        &mut self,
        _policy: ToolPolicyEntry,
    ) -> Result<(), AgentError> {
        Ok(())
    }

    fn remove_tool_policy(
        &mut self,
        _agent_id: &str,
        _tool_ref: &str,
    ) -> Result<(), AgentError> {
        Ok(())
    }

    fn list_tool_policies(&self, _agent_id: &str) -> Vec<ToolPolicyEntry> {
        Vec::new()
    }

    fn governor_id(&self) -> &str {
        "null-tool-governor"
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn permit_policy(agent: &str, tool: &str) -> ToolPolicyEntry {
        ToolPolicyEntry {
            agent_id: agent.into(),
            tool_ref: tool.into(),
            decision: ToolGovernanceDecision::Permit,
            max_invocations: None,
            requires_justification: false,
        }
    }

    #[test]
    fn test_in_memory_permits_with_policy() {
        let mut gov = InMemoryToolUseGovernor::new("gov-1");
        gov.register_tool_policy(permit_policy("a1", "search"))
            .unwrap();
        let eval = gov
            .evaluate_tool_request("a1", "search", &HashMap::new())
            .unwrap();
        assert_eq!(eval.decision, ToolGovernanceDecision::Permit);
    }

    #[test]
    fn test_in_memory_default_deny() {
        let gov = InMemoryToolUseGovernor::new("gov-1");
        let eval = gov
            .evaluate_tool_request("a1", "unknown-tool", &HashMap::new())
            .unwrap();
        assert_eq!(eval.decision, ToolGovernanceDecision::Deny);
    }

    #[test]
    fn test_in_memory_rate_limited() {
        let mut gov = InMemoryToolUseGovernor::new("gov-1");
        gov.register_tool_policy(ToolPolicyEntry {
            agent_id: "a1".into(),
            tool_ref: "search".into(),
            decision: ToolGovernanceDecision::Permit,
            max_invocations: Some(2),
            requires_justification: false,
        })
        .unwrap();
        gov.record_invocation("a1", "search");
        gov.record_invocation("a1", "search");
        let eval = gov
            .evaluate_tool_request("a1", "search", &HashMap::new())
            .unwrap();
        assert_eq!(eval.decision, ToolGovernanceDecision::RateLimited);
    }

    #[test]
    fn test_in_memory_remaining_invocations() {
        let mut gov = InMemoryToolUseGovernor::new("gov-1");
        gov.register_tool_policy(ToolPolicyEntry {
            agent_id: "a1".into(),
            tool_ref: "search".into(),
            decision: ToolGovernanceDecision::Permit,
            max_invocations: Some(5),
            requires_justification: false,
        })
        .unwrap();
        gov.record_invocation("a1", "search");
        let eval = gov
            .evaluate_tool_request("a1", "search", &HashMap::new())
            .unwrap();
        assert_eq!(eval.remaining_invocations, Some("4".into()));
    }

    #[test]
    fn test_in_memory_remove_policy() {
        let mut gov = InMemoryToolUseGovernor::new("gov-1");
        gov.register_tool_policy(permit_policy("a1", "search"))
            .unwrap();
        gov.remove_tool_policy("a1", "search").unwrap();
        assert!(gov.list_tool_policies("a1").is_empty());
    }

    #[test]
    fn test_in_memory_remove_nonexistent() {
        let mut gov = InMemoryToolUseGovernor::new("gov-1");
        assert!(gov.remove_tool_policy("a1", "search").is_err());
    }

    #[test]
    fn test_in_memory_list_policies() {
        let mut gov = InMemoryToolUseGovernor::new("gov-1");
        gov.register_tool_policy(permit_policy("a1", "search"))
            .unwrap();
        gov.register_tool_policy(permit_policy("a1", "write"))
            .unwrap();
        gov.register_tool_policy(permit_policy("a2", "search"))
            .unwrap();
        assert_eq!(gov.list_tool_policies("a1").len(), 2);
    }

    #[test]
    fn test_deny_all_governor() {
        let mut gov = DenyAllToolUseGovernor::new("deny-all");
        let eval = gov
            .evaluate_tool_request("a1", "anything", &HashMap::new())
            .unwrap();
        assert_eq!(eval.decision, ToolGovernanceDecision::Deny);
        assert!(gov.register_tool_policy(permit_policy("a1", "x")).is_err());
        assert!(gov.remove_tool_policy("a1", "x").is_err());
        assert!(gov.list_tool_policies("a1").is_empty());
        assert!(gov.is_active());
    }

    #[test]
    fn test_null_governor() {
        let mut gov = NullToolUseGovernor;
        assert!(!gov.is_active());
        assert_eq!(gov.governor_id(), "null-tool-governor");
        let eval = gov
            .evaluate_tool_request("a1", "anything", &HashMap::new())
            .unwrap();
        assert_eq!(eval.decision, ToolGovernanceDecision::Permit);
        gov.register_tool_policy(permit_policy("a1", "x")).unwrap();
        gov.remove_tool_policy("a1", "x").unwrap();
        assert!(gov.list_tool_policies("a1").is_empty());
    }

    #[test]
    fn test_governance_decision_display() {
        let decisions = vec![
            ToolGovernanceDecision::Permit,
            ToolGovernanceDecision::Deny,
            ToolGovernanceDecision::RequireApproval,
            ToolGovernanceDecision::RateLimited,
            ToolGovernanceDecision::DeferToHuman,
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(decisions.len(), 5);
    }

    #[test]
    fn test_governor_id() {
        let gov = InMemoryToolUseGovernor::new("my-gov");
        assert_eq!(gov.governor_id(), "my-gov");
        assert!(gov.is_active());
    }

    #[test]
    fn test_policy_replacement() {
        let mut gov = InMemoryToolUseGovernor::new("gov-1");
        gov.register_tool_policy(permit_policy("a1", "search"))
            .unwrap();
        gov.register_tool_policy(ToolPolicyEntry {
            agent_id: "a1".into(),
            tool_ref: "search".into(),
            decision: ToolGovernanceDecision::Deny,
            max_invocations: None,
            requires_justification: false,
        })
        .unwrap();
        let policies = gov.list_tool_policies("a1");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].decision, ToolGovernanceDecision::Deny);
    }
}
