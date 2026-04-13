// ═══════════════════════════════════════════════════════════════════════
// Reasoning — Reasoning chain auditing and step tracking.
// Records every step of an agent's reasoning process for auditability.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::action::ActionId;
use crate::agent::AgentId;
use crate::error::AgentError;

// ── ReasoningChainId ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReasoningChainId(pub String);

impl ReasoningChainId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for ReasoningChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── StepType ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepType {
    Observation,
    Analysis,
    Planning,
    Decision,
    Execution,
    Reflection,
    Revision,
}

impl fmt::Display for StepType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observation => write!(f, "Observation"),
            Self::Analysis => write!(f, "Analysis"),
            Self::Planning => write!(f, "Planning"),
            Self::Decision => write!(f, "Decision"),
            Self::Execution => write!(f, "Execution"),
            Self::Reflection => write!(f, "Reflection"),
            Self::Revision => write!(f, "Revision"),
        }
    }
}

// ── ReasoningStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReasoningStatus {
    Active,
    Completed,
    Failed { reason: String },
    Paused { reason: String },
    Abandoned { reason: String },
}

impl fmt::Display for ReasoningStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Completed => write!(f, "Completed"),
            Self::Failed { reason } => write!(f, "Failed: {reason}"),
            Self::Paused { reason } => write!(f, "Paused: {reason}"),
            Self::Abandoned { reason } => write!(f, "Abandoned: {reason}"),
        }
    }
}

// ── ReasoningStep ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    pub step_number: u32,
    pub description: String,
    pub step_type: StepType,
    pub input: Option<String>,
    pub output: Option<String>,
    pub confidence: f64,
    pub reasoning: String,
    pub alternatives_considered: Vec<String>,
    pub timestamp: i64,
    pub duration_ms: u64,
    pub action_id: Option<ActionId>,
}

impl ReasoningStep {
    pub fn new(
        step_number: u32,
        description: impl Into<String>,
        step_type: StepType,
        confidence: f64,
        reasoning: impl Into<String>,
        timestamp: i64,
    ) -> Self {
        Self {
            step_number,
            description: description.into(),
            step_type,
            input: None,
            output: None,
            confidence,
            reasoning: reasoning.into(),
            alternatives_considered: Vec::new(),
            timestamp,
            duration_ms: 0,
            action_id: None,
        }
    }

    pub fn with_input(mut self, input: impl Into<String>) -> Self {
        self.input = Some(input.into());
        self
    }

    pub fn with_output(mut self, output: impl Into<String>) -> Self {
        self.output = Some(output.into());
        self
    }

    pub fn with_alternatives(mut self, alts: Vec<String>) -> Self {
        self.alternatives_considered = alts;
        self
    }

    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = ms;
        self
    }
}

// ── ReasoningChain ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningChain {
    pub id: ReasoningChainId,
    pub agent_id: AgentId,
    pub goal: String,
    pub steps: Vec<ReasoningStep>,
    pub status: ReasoningStatus,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub outcome: Option<String>,
    pub total_confidence: f64,
}

impl ReasoningChain {
    fn recalculate_confidence(&mut self) {
        if self.steps.is_empty() {
            self.total_confidence = 0.0;
        } else {
            // Use minimum confidence — the chain is only as strong as the weakest link
            self.total_confidence = self
                .steps
                .iter()
                .map(|s| s.confidence)
                .fold(f64::INFINITY, f64::min);
        }
    }
}

// ── ReasoningStore ───────────────────────────────────────────────────

pub struct ReasoningStore {
    chains: HashMap<ReasoningChainId, ReasoningChain>,
    counter: u64,
}

impl ReasoningStore {
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
            counter: 0,
        }
    }

    pub fn start_chain(
        &mut self,
        agent_id: AgentId,
        goal: &str,
        now: i64,
    ) -> ReasoningChainId {
        self.counter += 1;
        let id = ReasoningChainId::new(format!("rc_{:08x}", self.counter));
        let chain = ReasoningChain {
            id: id.clone(),
            agent_id,
            goal: goal.into(),
            steps: Vec::new(),
            status: ReasoningStatus::Active,
            started_at: now,
            completed_at: None,
            outcome: None,
            total_confidence: 0.0,
        };
        self.chains.insert(id.clone(), chain);
        id
    }

    pub fn add_step(
        &mut self,
        chain_id: &ReasoningChainId,
        step: ReasoningStep,
    ) -> Result<(), AgentError> {
        let chain = self
            .chains
            .get_mut(chain_id)
            .ok_or_else(|| AgentError::ReasoningChainNotFound(chain_id.0.clone()))?;
        if !matches!(chain.status, ReasoningStatus::Active) {
            return Err(AgentError::ReasoningChainNotActive(chain_id.0.clone()));
        }
        chain.steps.push(step);
        chain.recalculate_confidence();
        Ok(())
    }

    pub fn complete_chain(
        &mut self,
        chain_id: &ReasoningChainId,
        outcome: &str,
        now: i64,
    ) -> Result<(), AgentError> {
        let chain = self
            .chains
            .get_mut(chain_id)
            .ok_or_else(|| AgentError::ReasoningChainNotFound(chain_id.0.clone()))?;
        if !matches!(chain.status, ReasoningStatus::Active) {
            return Err(AgentError::ReasoningChainNotActive(chain_id.0.clone()));
        }
        chain.status = ReasoningStatus::Completed;
        chain.completed_at = Some(now);
        chain.outcome = Some(outcome.into());
        Ok(())
    }

    pub fn fail_chain(
        &mut self,
        chain_id: &ReasoningChainId,
        reason: &str,
        now: i64,
    ) -> Result<(), AgentError> {
        let chain = self
            .chains
            .get_mut(chain_id)
            .ok_or_else(|| AgentError::ReasoningChainNotFound(chain_id.0.clone()))?;
        chain.status = ReasoningStatus::Failed {
            reason: reason.into(),
        };
        chain.completed_at = Some(now);
        Ok(())
    }

    pub fn get(&self, id: &ReasoningChainId) -> Option<&ReasoningChain> {
        self.chains.get(id)
    }

    pub fn chains_for_agent(&self, agent_id: &AgentId) -> Vec<&ReasoningChain> {
        self.chains
            .values()
            .filter(|c| &c.agent_id == agent_id)
            .collect()
    }

    pub fn active_chains(&self) -> Vec<&ReasoningChain> {
        self.chains
            .values()
            .filter(|c| matches!(c.status, ReasoningStatus::Active))
            .collect()
    }

    pub fn chain_depth(&self, id: &ReasoningChainId) -> Option<usize> {
        self.chains.get(id).map(|c| c.steps.len())
    }

    pub fn low_confidence_steps(
        &self,
        id: &ReasoningChainId,
        threshold: f64,
    ) -> Vec<&ReasoningStep> {
        self.chains
            .get(id)
            .map(|c| {
                c.steps
                    .iter()
                    .filter(|s| s.confidence < threshold)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn count(&self) -> usize {
        self.chains.len()
    }
}

impl Default for ReasoningStore {
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
    fn test_start_chain() {
        let mut store = ReasoningStore::new();
        let id = store.start_chain(AgentId::new("a1"), "analyze data", 1000);
        assert!(store.get(&id).is_some());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_add_step() {
        let mut store = ReasoningStore::new();
        let id = store.start_chain(AgentId::new("a1"), "test", 1000);
        let step = ReasoningStep::new(1, "observe", StepType::Observation, 0.9, "looking around", 1001);
        store.add_step(&id, step).unwrap();
        assert_eq!(store.chain_depth(&id), Some(1));
    }

    #[test]
    fn test_complete_chain() {
        let mut store = ReasoningStore::new();
        let id = store.start_chain(AgentId::new("a1"), "test", 1000);
        store.complete_chain(&id, "success", 2000).unwrap();
        let chain = store.get(&id).unwrap();
        assert_eq!(chain.status, ReasoningStatus::Completed);
        assert_eq!(chain.outcome.as_deref(), Some("success"));
    }

    #[test]
    fn test_fail_chain() {
        let mut store = ReasoningStore::new();
        let id = store.start_chain(AgentId::new("a1"), "test", 1000);
        store.fail_chain(&id, "error occurred", 2000).unwrap();
        assert!(matches!(store.get(&id).unwrap().status, ReasoningStatus::Failed { .. }));
    }

    #[test]
    fn test_chains_for_agent() {
        let mut store = ReasoningStore::new();
        store.start_chain(AgentId::new("a1"), "task1", 1000);
        store.start_chain(AgentId::new("a2"), "task2", 1000);
        store.start_chain(AgentId::new("a1"), "task3", 1000);
        assert_eq!(store.chains_for_agent(&AgentId::new("a1")).len(), 2);
    }

    #[test]
    fn test_active_chains() {
        let mut store = ReasoningStore::new();
        let id1 = store.start_chain(AgentId::new("a1"), "task1", 1000);
        store.start_chain(AgentId::new("a2"), "task2", 1000);
        store.complete_chain(&id1, "done", 2000).unwrap();
        assert_eq!(store.active_chains().len(), 1);
    }

    #[test]
    fn test_chain_depth() {
        let mut store = ReasoningStore::new();
        let id = store.start_chain(AgentId::new("a1"), "test", 1000);
        store.add_step(&id, ReasoningStep::new(1, "s1", StepType::Observation, 0.9, "r1", 1001)).unwrap();
        store.add_step(&id, ReasoningStep::new(2, "s2", StepType::Analysis, 0.8, "r2", 1002)).unwrap();
        assert_eq!(store.chain_depth(&id), Some(2));
    }

    #[test]
    fn test_low_confidence_steps() {
        let mut store = ReasoningStore::new();
        let id = store.start_chain(AgentId::new("a1"), "test", 1000);
        store.add_step(&id, ReasoningStep::new(1, "sure", StepType::Decision, 0.95, "confident", 1001)).unwrap();
        store.add_step(&id, ReasoningStep::new(2, "unsure", StepType::Decision, 0.3, "guessing", 1002)).unwrap();
        store.add_step(&id, ReasoningStep::new(3, "maybe", StepType::Decision, 0.6, "moderate", 1003)).unwrap();
        let low = store.low_confidence_steps(&id, 0.5);
        assert_eq!(low.len(), 1);
        assert_eq!(low[0].step_number, 2);
    }

    #[test]
    fn test_reasoning_step_construction() {
        let step = ReasoningStep::new(1, "test step", StepType::Analysis, 0.85, "analyzing data", 1000)
            .with_input("raw data")
            .with_output("cleaned data")
            .with_alternatives(vec!["option A".into(), "option B".into()])
            .with_duration(150);
        assert_eq!(step.step_number, 1);
        assert_eq!(step.confidence, 0.85);
        assert_eq!(step.input.as_deref(), Some("raw data"));
        assert_eq!(step.alternatives_considered.len(), 2);
        assert_eq!(step.duration_ms, 150);
    }

    #[test]
    fn test_step_type_display() {
        let types = vec![
            StepType::Observation,
            StepType::Analysis,
            StepType::Planning,
            StepType::Decision,
            StepType::Execution,
            StepType::Reflection,
            StepType::Revision,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 7);
    }

    #[test]
    fn test_reasoning_status_display() {
        let statuses = vec![
            ReasoningStatus::Active,
            ReasoningStatus::Completed,
            ReasoningStatus::Failed { reason: "err".into() },
            ReasoningStatus::Paused { reason: "wait".into() },
            ReasoningStatus::Abandoned { reason: "quit".into() },
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 5);
    }

    #[test]
    fn test_chain_total_confidence() {
        let mut store = ReasoningStore::new();
        let id = store.start_chain(AgentId::new("a1"), "test", 1000);
        store.add_step(&id, ReasoningStep::new(1, "s1", StepType::Decision, 0.9, "r", 1001)).unwrap();
        store.add_step(&id, ReasoningStep::new(2, "s2", StepType::Decision, 0.6, "r", 1002)).unwrap();
        store.add_step(&id, ReasoningStep::new(3, "s3", StepType::Decision, 0.8, "r", 1003)).unwrap();
        let chain = store.get(&id).unwrap();
        // Min confidence = 0.6
        assert!((chain.total_confidence - 0.6).abs() < 0.01);
    }
}
