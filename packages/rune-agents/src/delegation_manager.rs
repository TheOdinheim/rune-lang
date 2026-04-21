// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — DelegationGovernor trait for governing delegation chains:
// delegation request evaluation, depth limit enforcement, chain
// recording, and the DepthLimitedDelegationGovernor composable wrapper.
//
// Named DelegationGovernor (not DelegationManager) to avoid collision
// with L1 delegation.rs DelegationManager struct. L1 manages delegation
// lifecycle; L3 governs delegation policy.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::AgentError;

// ── DelegationRequestDecision ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DelegationRequestDecision {
    Approve,
    Deny,
    RequireApproval,
    DepthLimitExceeded,
    DeferToHuman,
}

impl fmt::Display for DelegationRequestDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Approve => "Approve",
            Self::Deny => "Deny",
            Self::RequireApproval => "RequireApproval",
            Self::DepthLimitExceeded => "DepthLimitExceeded",
            Self::DeferToHuman => "DeferToHuman",
        };
        f.write_str(s)
    }
}

// ── DelegationEvaluation ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationEvaluation {
    pub delegator_id: String,
    pub delegatee_id: String,
    pub task_description: String,
    pub decision: DelegationRequestDecision,
    pub current_depth: usize,
    pub max_depth: usize,
    pub justification: String,
    pub evaluated_at: i64,
}

// ── DelegationChainEntry ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationChainEntry {
    pub chain_id: String,
    pub delegator_id: String,
    pub delegatee_id: String,
    pub task_description: String,
    pub depth: usize,
    pub created_at: i64,
}

// ── DelegationGovernor trait ────────────────────────────────────────

pub trait DelegationGovernor {
    fn evaluate_delegation_request(
        &self,
        delegator_id: &str,
        delegatee_id: &str,
        task: &str,
        current_depth: usize,
    ) -> Result<DelegationEvaluation, AgentError>;

    fn record_delegation_chain(
        &mut self,
        entry: DelegationChainEntry,
    ) -> Result<(), AgentError>;

    fn check_depth_limit(
        &self,
        delegator_id: &str,
        current_depth: usize,
    ) -> Result<bool, AgentError>;

    fn list_delegation_chains(
        &self,
        delegator_id: &str,
    ) -> Vec<DelegationChainEntry>;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryDelegationGovernor ──────────────────────────────────────

pub struct InMemoryDelegationGovernor {
    id: String,
    max_depth: usize,
    chains: Vec<DelegationChainEntry>,
    denied_delegatees: Vec<String>,
}

impl InMemoryDelegationGovernor {
    pub fn new(id: impl Into<String>, max_depth: usize) -> Self {
        Self {
            id: id.into(),
            max_depth,
            chains: Vec::new(),
            denied_delegatees: Vec::new(),
        }
    }

    pub fn add_denied_delegatee(&mut self, delegatee_id: impl Into<String>) {
        self.denied_delegatees.push(delegatee_id.into());
    }
}

impl DelegationGovernor for InMemoryDelegationGovernor {
    fn evaluate_delegation_request(
        &self,
        delegator_id: &str,
        delegatee_id: &str,
        task: &str,
        current_depth: usize,
    ) -> Result<DelegationEvaluation, AgentError> {
        // Check denied delegatees
        if self.denied_delegatees.contains(&delegatee_id.to_string()) {
            return Ok(DelegationEvaluation {
                delegator_id: delegator_id.into(),
                delegatee_id: delegatee_id.into(),
                task_description: task.into(),
                decision: DelegationRequestDecision::Deny,
                current_depth,
                max_depth: self.max_depth,
                justification: format!("Delegatee {delegatee_id} is denied"),
                evaluated_at: 0,
            });
        }

        // Check depth limit
        if current_depth >= self.max_depth {
            return Ok(DelegationEvaluation {
                delegator_id: delegator_id.into(),
                delegatee_id: delegatee_id.into(),
                task_description: task.into(),
                decision: DelegationRequestDecision::DepthLimitExceeded,
                current_depth,
                max_depth: self.max_depth,
                justification: format!(
                    "Delegation depth {current_depth} exceeds limit {}",
                    self.max_depth
                ),
                evaluated_at: 0,
            });
        }

        Ok(DelegationEvaluation {
            delegator_id: delegator_id.into(),
            delegatee_id: delegatee_id.into(),
            task_description: task.into(),
            decision: DelegationRequestDecision::Approve,
            current_depth,
            max_depth: self.max_depth,
            justification: "Delegation approved within depth limit".into(),
            evaluated_at: 0,
        })
    }

    fn record_delegation_chain(
        &mut self,
        entry: DelegationChainEntry,
    ) -> Result<(), AgentError> {
        self.chains.push(entry);
        Ok(())
    }

    fn check_depth_limit(
        &self,
        _delegator_id: &str,
        current_depth: usize,
    ) -> Result<bool, AgentError> {
        Ok(current_depth < self.max_depth)
    }

    fn list_delegation_chains(
        &self,
        delegator_id: &str,
    ) -> Vec<DelegationChainEntry> {
        self.chains
            .iter()
            .filter(|c| c.delegator_id == delegator_id)
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

// ── DepthLimitedDelegationGovernor ──────────────────────────────────
// Composable wrapper that enforces a depth limit on any DelegationGovernor.

pub struct DepthLimitedDelegationGovernor<G: DelegationGovernor> {
    inner: G,
    max_depth: usize,
}

impl<G: DelegationGovernor> DepthLimitedDelegationGovernor<G> {
    pub fn new(inner: G, max_depth: usize) -> Self {
        Self { inner, max_depth }
    }
}

impl<G: DelegationGovernor> DelegationGovernor for DepthLimitedDelegationGovernor<G> {
    fn evaluate_delegation_request(
        &self,
        delegator_id: &str,
        delegatee_id: &str,
        task: &str,
        current_depth: usize,
    ) -> Result<DelegationEvaluation, AgentError> {
        if current_depth >= self.max_depth {
            return Ok(DelegationEvaluation {
                delegator_id: delegator_id.into(),
                delegatee_id: delegatee_id.into(),
                task_description: task.into(),
                decision: DelegationRequestDecision::DepthLimitExceeded,
                current_depth,
                max_depth: self.max_depth,
                justification: format!(
                    "DepthLimitedDelegationGovernor: depth {current_depth} >= limit {}",
                    self.max_depth
                ),
                evaluated_at: 0,
            });
        }
        self.inner
            .evaluate_delegation_request(delegator_id, delegatee_id, task, current_depth)
    }

    fn record_delegation_chain(
        &mut self,
        entry: DelegationChainEntry,
    ) -> Result<(), AgentError> {
        self.inner.record_delegation_chain(entry)
    }

    fn check_depth_limit(
        &self,
        delegator_id: &str,
        current_depth: usize,
    ) -> Result<bool, AgentError> {
        if current_depth >= self.max_depth {
            return Ok(false);
        }
        self.inner.check_depth_limit(delegator_id, current_depth)
    }

    fn list_delegation_chains(
        &self,
        delegator_id: &str,
    ) -> Vec<DelegationChainEntry> {
        self.inner.list_delegation_chains(delegator_id)
    }

    fn governor_id(&self) -> &str {
        self.inner.governor_id()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── NullDelegationGovernor ──────────────────────────────────────────

pub struct NullDelegationGovernor;

impl DelegationGovernor for NullDelegationGovernor {
    fn evaluate_delegation_request(
        &self,
        delegator_id: &str,
        delegatee_id: &str,
        task: &str,
        current_depth: usize,
    ) -> Result<DelegationEvaluation, AgentError> {
        Ok(DelegationEvaluation {
            delegator_id: delegator_id.into(),
            delegatee_id: delegatee_id.into(),
            task_description: task.into(),
            decision: DelegationRequestDecision::Approve,
            current_depth,
            max_depth: usize::MAX,
            justification: "Null governor — no delegation governance".into(),
            evaluated_at: 0,
        })
    }

    fn record_delegation_chain(
        &mut self,
        _entry: DelegationChainEntry,
    ) -> Result<(), AgentError> {
        Ok(())
    }

    fn check_depth_limit(
        &self,
        _delegator_id: &str,
        _current_depth: usize,
    ) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn list_delegation_chains(
        &self,
        _delegator_id: &str,
    ) -> Vec<DelegationChainEntry> {
        Vec::new()
    }

    fn governor_id(&self) -> &str {
        "null-delegation-governor"
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

    fn sample_chain_entry(id: &str, delegator: &str) -> DelegationChainEntry {
        DelegationChainEntry {
            chain_id: id.into(),
            delegator_id: delegator.into(),
            delegatee_id: "agent-b".into(),
            task_description: "analyze data".into(),
            depth: 1,
            created_at: 1000,
        }
    }

    #[test]
    fn test_in_memory_approves_within_limit() {
        let gov = InMemoryDelegationGovernor::new("gov-1", 3);
        let eval = gov
            .evaluate_delegation_request("a1", "a2", "task", 0)
            .unwrap();
        assert_eq!(eval.decision, DelegationRequestDecision::Approve);
    }

    #[test]
    fn test_in_memory_depth_limit_exceeded() {
        let gov = InMemoryDelegationGovernor::new("gov-1", 2);
        let eval = gov
            .evaluate_delegation_request("a1", "a2", "task", 2)
            .unwrap();
        assert_eq!(eval.decision, DelegationRequestDecision::DepthLimitExceeded);
    }

    #[test]
    fn test_in_memory_denied_delegatee() {
        let mut gov = InMemoryDelegationGovernor::new("gov-1", 5);
        gov.add_denied_delegatee("bad-agent");
        let eval = gov
            .evaluate_delegation_request("a1", "bad-agent", "task", 0)
            .unwrap();
        assert_eq!(eval.decision, DelegationRequestDecision::Deny);
    }

    #[test]
    fn test_in_memory_check_depth() {
        let gov = InMemoryDelegationGovernor::new("gov-1", 3);
        assert!(gov.check_depth_limit("a1", 2).unwrap());
        assert!(!gov.check_depth_limit("a1", 3).unwrap());
    }

    #[test]
    fn test_in_memory_record_and_list_chains() {
        let mut gov = InMemoryDelegationGovernor::new("gov-1", 5);
        gov.record_delegation_chain(sample_chain_entry("ch1", "a1"))
            .unwrap();
        gov.record_delegation_chain(sample_chain_entry("ch2", "a1"))
            .unwrap();
        assert_eq!(gov.list_delegation_chains("a1").len(), 2);
        assert!(gov.list_delegation_chains("a2").is_empty());
    }

    #[test]
    fn test_depth_limited_wrapper_enforces() {
        let inner = InMemoryDelegationGovernor::new("inner", 10);
        let wrapped = DepthLimitedDelegationGovernor::new(inner, 2);
        let eval = wrapped
            .evaluate_delegation_request("a1", "a2", "task", 2)
            .unwrap();
        assert_eq!(eval.decision, DelegationRequestDecision::DepthLimitExceeded);
    }

    #[test]
    fn test_depth_limited_wrapper_delegates_within_limit() {
        let inner = InMemoryDelegationGovernor::new("inner", 10);
        let wrapped = DepthLimitedDelegationGovernor::new(inner, 5);
        let eval = wrapped
            .evaluate_delegation_request("a1", "a2", "task", 1)
            .unwrap();
        assert_eq!(eval.decision, DelegationRequestDecision::Approve);
    }

    #[test]
    fn test_depth_limited_check_depth() {
        let inner = InMemoryDelegationGovernor::new("inner", 10);
        let wrapped = DepthLimitedDelegationGovernor::new(inner, 3);
        assert!(wrapped.check_depth_limit("a1", 2).unwrap());
        assert!(!wrapped.check_depth_limit("a1", 3).unwrap());
    }

    #[test]
    fn test_depth_limited_record_and_list() {
        let inner = InMemoryDelegationGovernor::new("inner", 10);
        let mut wrapped = DepthLimitedDelegationGovernor::new(inner, 5);
        wrapped
            .record_delegation_chain(sample_chain_entry("ch1", "a1"))
            .unwrap();
        assert_eq!(wrapped.list_delegation_chains("a1").len(), 1);
    }

    #[test]
    fn test_null_governor() {
        let mut gov = NullDelegationGovernor;
        assert!(!gov.is_active());
        assert_eq!(gov.governor_id(), "null-delegation-governor");
        let eval = gov
            .evaluate_delegation_request("a1", "a2", "task", 100)
            .unwrap();
        assert_eq!(eval.decision, DelegationRequestDecision::Approve);
        assert!(gov.check_depth_limit("a1", 999).unwrap());
        gov.record_delegation_chain(sample_chain_entry("ch1", "a1"))
            .unwrap();
        assert!(gov.list_delegation_chains("a1").is_empty());
    }

    #[test]
    fn test_delegation_request_decision_display() {
        let decisions = vec![
            DelegationRequestDecision::Approve,
            DelegationRequestDecision::Deny,
            DelegationRequestDecision::RequireApproval,
            DelegationRequestDecision::DepthLimitExceeded,
            DelegationRequestDecision::DeferToHuman,
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(decisions.len(), 5);
    }

    #[test]
    fn test_governor_id() {
        let gov = InMemoryDelegationGovernor::new("my-gov", 3);
        assert_eq!(gov.governor_id(), "my-gov");
        assert!(gov.is_active());
    }
}
