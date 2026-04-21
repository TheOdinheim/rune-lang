// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — AgentGovernanceMetricsCollector trait for computing
// agent governance metrics: autonomy escalation rate, tool denial rate,
// delegation chain depth average, human oversight frequency. All
// computed values are String for Eq derivation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::backend::StoredDelegationChainRecord;
use crate::error::AgentError;

// ── AgentGovernanceMetricSnapshot ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentGovernanceMetricSnapshot {
    pub snapshot_id: String,
    pub agent_id: String,
    pub computed_at: i64,
    pub autonomy_escalation_rate: String,
    pub tool_denial_rate: String,
    pub delegation_depth_average: String,
    pub human_oversight_frequency: String,
    pub metadata: HashMap<String, String>,
}

// ── ToolDenialRecord ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ToolDenialRecord {
    pub agent_id: String,
    pub tool_ref: String,
    pub denied_at: i64,
}

// ── EscalationRecord ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EscalationRecord {
    pub agent_id: String,
    pub action: String,
    pub escalated_at: i64,
}

// ── AgentGovernanceMetricsCollector trait ────────────────────────────

pub trait AgentGovernanceMetricsCollector {
    fn compute_autonomy_escalation_rate(
        &self,
        agent_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, AgentError>;

    fn compute_tool_denial_rate(
        &self,
        agent_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, AgentError>;

    fn compute_delegation_depth_average(
        &self,
        agent_id: &str,
    ) -> Result<String, AgentError>;

    fn list_most_denied_tools(
        &self,
        agent_id: &str,
        limit: usize,
    ) -> Vec<(String, usize)>;

    fn compute_human_oversight_frequency(
        &self,
        agent_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, AgentError>;

    fn collector_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryAgentGovernanceMetricsCollector ──────────────────────────

pub struct InMemoryAgentGovernanceMetricsCollector {
    id: String,
    escalations: Vec<EscalationRecord>,
    tool_denials: Vec<ToolDenialRecord>,
    delegation_chains: Vec<StoredDelegationChainRecord>,
    total_actions: HashMap<String, usize>,
    total_tool_requests: HashMap<String, usize>,
    oversight_events: HashMap<String, Vec<i64>>,
}

impl InMemoryAgentGovernanceMetricsCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            escalations: Vec::new(),
            tool_denials: Vec::new(),
            delegation_chains: Vec::new(),
            total_actions: HashMap::new(),
            total_tool_requests: HashMap::new(),
            oversight_events: HashMap::new(),
        }
    }

    pub fn add_escalation(&mut self, record: EscalationRecord) {
        self.escalations.push(record);
    }

    pub fn add_tool_denial(&mut self, record: ToolDenialRecord) {
        self.tool_denials.push(record);
    }

    pub fn add_delegation_chain(&mut self, chain: StoredDelegationChainRecord) {
        self.delegation_chains.push(chain);
    }

    pub fn set_total_actions(&mut self, agent_id: impl Into<String>, count: usize) {
        self.total_actions.insert(agent_id.into(), count);
    }

    pub fn set_total_tool_requests(&mut self, agent_id: impl Into<String>, count: usize) {
        self.total_tool_requests.insert(agent_id.into(), count);
    }

    pub fn add_oversight_event(&mut self, agent_id: impl Into<String>, timestamp: i64) {
        self.oversight_events
            .entry(agent_id.into())
            .or_default()
            .push(timestamp);
    }
}

impl AgentGovernanceMetricsCollector for InMemoryAgentGovernanceMetricsCollector {
    fn compute_autonomy_escalation_rate(
        &self,
        agent_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, AgentError> {
        if window_end <= window_start {
            return Err(AgentError::InvalidOperation(
                "window_end must be after window_start".into(),
            ));
        }
        let escalation_count = self
            .escalations
            .iter()
            .filter(|e| {
                e.agent_id == agent_id
                    && e.escalated_at >= window_start
                    && e.escalated_at <= window_end
            })
            .count();
        let total = self.total_actions.get(agent_id).copied().unwrap_or(0);
        if total == 0 {
            return Ok("0.0000".into());
        }
        let rate = escalation_count as f64 / total as f64;
        Ok(format!("{:.4}", rate))
    }

    fn compute_tool_denial_rate(
        &self,
        agent_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, AgentError> {
        if window_end <= window_start {
            return Err(AgentError::InvalidOperation(
                "window_end must be after window_start".into(),
            ));
        }
        let denial_count = self
            .tool_denials
            .iter()
            .filter(|d| {
                d.agent_id == agent_id
                    && d.denied_at >= window_start
                    && d.denied_at <= window_end
            })
            .count();
        let total = self.total_tool_requests.get(agent_id).copied().unwrap_or(0);
        if total == 0 {
            return Ok("0.0000".into());
        }
        let rate = denial_count as f64 / total as f64;
        Ok(format!("{:.4}", rate))
    }

    fn compute_delegation_depth_average(
        &self,
        agent_id: &str,
    ) -> Result<String, AgentError> {
        let depths: Vec<usize> = self
            .delegation_chains
            .iter()
            .filter(|c| c.delegator_id == agent_id)
            .map(|c| c.depth)
            .collect();
        if depths.is_empty() {
            return Ok("0.00".into());
        }
        let avg = depths.iter().sum::<usize>() as f64 / depths.len() as f64;
        Ok(format!("{:.2}", avg))
    }

    fn list_most_denied_tools(
        &self,
        agent_id: &str,
        limit: usize,
    ) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for d in &self.tool_denials {
            if d.agent_id == agent_id {
                *counts.entry(d.tool_ref.clone()).or_default() += 1;
            }
        }
        let mut pairs: Vec<(String, usize)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(limit);
        pairs
    }

    fn compute_human_oversight_frequency(
        &self,
        agent_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, AgentError> {
        if window_end <= window_start {
            return Err(AgentError::InvalidOperation(
                "window_end must be after window_start".into(),
            ));
        }
        let count = self
            .oversight_events
            .get(agent_id)
            .map(|events| {
                events
                    .iter()
                    .filter(|&&t| t >= window_start && t <= window_end)
                    .count()
            })
            .unwrap_or(0);
        Ok(count.to_string())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── NullAgentGovernanceMetricsCollector ──────────────────────────────

pub struct NullAgentGovernanceMetricsCollector;

impl AgentGovernanceMetricsCollector for NullAgentGovernanceMetricsCollector {
    fn compute_autonomy_escalation_rate(
        &self,
        _agent_id: &str,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, AgentError> {
        Ok("0.0000".into())
    }

    fn compute_tool_denial_rate(
        &self,
        _agent_id: &str,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, AgentError> {
        Ok("0.0000".into())
    }

    fn compute_delegation_depth_average(
        &self,
        _agent_id: &str,
    ) -> Result<String, AgentError> {
        Ok("0.00".into())
    }

    fn list_most_denied_tools(
        &self,
        _agent_id: &str,
        _limit: usize,
    ) -> Vec<(String, usize)> {
        Vec::new()
    }

    fn compute_human_oversight_frequency(
        &self,
        _agent_id: &str,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, AgentError> {
        Ok("0".into())
    }

    fn collector_id(&self) -> &str {
        "null-agent-metrics-collector"
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
    use crate::backend::StoredDelegationChainStatus;

    fn sample_chain(delegator: &str, depth: usize) -> StoredDelegationChainRecord {
        StoredDelegationChainRecord {
            chain_id: format!("ch-{depth}"),
            delegator_id: delegator.into(),
            delegatee_id: "agent-b".into(),
            task_description: "task".into(),
            depth,
            max_depth_allowed: 5,
            autonomy_constraint: "ActLowRisk".into(),
            chain_status: StoredDelegationChainStatus::Active,
            created_at: 1000,
            completed_at: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_escalation_rate() {
        let mut c = InMemoryAgentGovernanceMetricsCollector::new("m1");
        c.set_total_actions("a1", 10);
        c.add_escalation(EscalationRecord {
            agent_id: "a1".into(),
            action: "deploy".into(),
            escalated_at: 500,
        });
        c.add_escalation(EscalationRecord {
            agent_id: "a1".into(),
            action: "delete".into(),
            escalated_at: 600,
        });
        let rate = c
            .compute_autonomy_escalation_rate("a1", 0, 1000)
            .unwrap();
        assert_eq!(rate, "0.2000");
    }

    #[test]
    fn test_escalation_rate_no_actions() {
        let c = InMemoryAgentGovernanceMetricsCollector::new("m1");
        let rate = c
            .compute_autonomy_escalation_rate("a1", 0, 1000)
            .unwrap();
        assert_eq!(rate, "0.0000");
    }

    #[test]
    fn test_tool_denial_rate() {
        let mut c = InMemoryAgentGovernanceMetricsCollector::new("m1");
        c.set_total_tool_requests("a1", 5);
        c.add_tool_denial(ToolDenialRecord {
            agent_id: "a1".into(),
            tool_ref: "deploy".into(),
            denied_at: 500,
        });
        let rate = c.compute_tool_denial_rate("a1", 0, 1000).unwrap();
        assert_eq!(rate, "0.2000");
    }

    #[test]
    fn test_delegation_depth_average() {
        let mut c = InMemoryAgentGovernanceMetricsCollector::new("m1");
        c.add_delegation_chain(sample_chain("a1", 1));
        c.add_delegation_chain(sample_chain("a1", 3));
        let avg = c.compute_delegation_depth_average("a1").unwrap();
        assert_eq!(avg, "2.00");
    }

    #[test]
    fn test_delegation_depth_no_data() {
        let c = InMemoryAgentGovernanceMetricsCollector::new("m1");
        let avg = c.compute_delegation_depth_average("a1").unwrap();
        assert_eq!(avg, "0.00");
    }

    #[test]
    fn test_most_denied_tools() {
        let mut c = InMemoryAgentGovernanceMetricsCollector::new("m1");
        c.add_tool_denial(ToolDenialRecord {
            agent_id: "a1".into(),
            tool_ref: "deploy".into(),
            denied_at: 100,
        });
        c.add_tool_denial(ToolDenialRecord {
            agent_id: "a1".into(),
            tool_ref: "deploy".into(),
            denied_at: 200,
        });
        c.add_tool_denial(ToolDenialRecord {
            agent_id: "a1".into(),
            tool_ref: "delete".into(),
            denied_at: 300,
        });
        let top = c.list_most_denied_tools("a1", 2);
        assert_eq!(top[0].0, "deploy");
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_human_oversight_frequency() {
        let mut c = InMemoryAgentGovernanceMetricsCollector::new("m1");
        c.add_oversight_event("a1", 100);
        c.add_oversight_event("a1", 500);
        c.add_oversight_event("a1", 900);
        let freq = c
            .compute_human_oversight_frequency("a1", 0, 1000)
            .unwrap();
        assert_eq!(freq, "3");
    }

    #[test]
    fn test_null_collector() {
        let c = NullAgentGovernanceMetricsCollector;
        assert!(!c.is_active());
        assert_eq!(
            c.compute_autonomy_escalation_rate("a1", 0, 1000).unwrap(),
            "0.0000"
        );
        assert_eq!(
            c.compute_tool_denial_rate("a1", 0, 1000).unwrap(),
            "0.0000"
        );
        assert_eq!(c.compute_delegation_depth_average("a1").unwrap(), "0.00");
        assert!(c.list_most_denied_tools("a1", 5).is_empty());
        assert_eq!(
            c.compute_human_oversight_frequency("a1", 0, 1000).unwrap(),
            "0"
        );
    }

    #[test]
    fn test_collector_id() {
        let c = InMemoryAgentGovernanceMetricsCollector::new("my-metrics");
        assert_eq!(c.collector_id(), "my-metrics");
        assert!(c.is_active());
    }

    #[test]
    fn test_snapshot_eq() {
        let s = AgentGovernanceMetricSnapshot {
            snapshot_id: "snap-1".into(),
            agent_id: "a1".into(),
            computed_at: 5000,
            autonomy_escalation_rate: "0.1000".into(),
            tool_denial_rate: "0.0500".into(),
            delegation_depth_average: "2.00".into(),
            human_oversight_frequency: "15".into(),
            metadata: HashMap::new(),
        };
        assert_eq!(s, s.clone());
    }

    #[test]
    fn test_invalid_window() {
        let c = InMemoryAgentGovernanceMetricsCollector::new("m1");
        assert!(c
            .compute_autonomy_escalation_rate("a1", 1000, 500)
            .is_err());
        assert!(c.compute_tool_denial_rate("a1", 1000, 500).is_err());
        assert!(c
            .compute_human_oversight_frequency("a1", 1000, 500)
            .is_err());
    }
}
