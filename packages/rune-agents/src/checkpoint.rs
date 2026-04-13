// ═══════════════════════════════════════════════════════════════════════
// Checkpoint — Human-in-the-loop checkpoints and approval gates.
// Gates where agent execution pauses for human review and approval.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::action::{ActionId, ActionRisk, AgentAction};
use crate::agent::{Agent, AgentId};
use crate::error::AgentError;

// ── CheckpointId ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckpointId(pub String);

impl CheckpointId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for CheckpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── CheckpointTrigger ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CheckpointTrigger {
    RiskThreshold { min_risk: ActionRisk },
    ActionType { action_type: String },
    ResourceAccess { resource: String },
    BudgetThreshold { percent_used: f64 },
    ConfidenceBelow { threshold: f64 },
    EveryNActions { n: u64 },
    Always,
    Custom(String),
}

impl fmt::Display for CheckpointTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RiskThreshold { min_risk } => write!(f, "RiskThreshold(>={min_risk})"),
            Self::ActionType { action_type } => write!(f, "ActionType({action_type})"),
            Self::ResourceAccess { resource } => write!(f, "ResourceAccess({resource})"),
            Self::BudgetThreshold { percent_used } => {
                write!(f, "BudgetThreshold({percent_used:.0}%)")
            }
            Self::ConfidenceBelow { threshold } => write!(f, "ConfidenceBelow({threshold:.2})"),
            Self::EveryNActions { n } => write!(f, "EveryNActions({n})"),
            Self::Always => write!(f, "Always"),
            Self::Custom(desc) => write!(f, "Custom({desc})"),
        }
    }
}

// ── CheckpointPriority ───────────────────────────────────────────────

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum CheckpointPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for CheckpointPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

// ── CheckpointDefault ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointDefault {
    Deny,
    Allow,
    Escalate { to: String },
}

impl fmt::Display for CheckpointDefault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deny => write!(f, "Deny"),
            Self::Allow => write!(f, "Allow"),
            Self::Escalate { to } => write!(f, "Escalate(to={to})"),
        }
    }
}

// ── Checkpoint ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub id: CheckpointId,
    pub name: String,
    pub description: String,
    pub trigger: CheckpointTrigger,
    pub priority: CheckpointPriority,
    pub timeout_ms: Option<i64>,
    pub default_action: CheckpointDefault,
    pub enabled: bool,
}

impl Checkpoint {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        trigger: CheckpointTrigger,
        priority: CheckpointPriority,
    ) -> Self {
        Self {
            id: CheckpointId::new(id),
            name: name.into(),
            description: String::new(),
            trigger,
            priority,
            timeout_ms: None,
            default_action: CheckpointDefault::Deny,
            enabled: true,
        }
    }

    pub fn with_timeout(mut self, ms: i64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    pub fn with_default(mut self, default: CheckpointDefault) -> Self {
        self.default_action = default;
        self
    }
}

// ── CheckpointOutcome ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointOutcome {
    Approved,
    Denied { reason: String },
    Modified { changes: String },
    Escalated { to: String },
    TimedOut { default_applied: String },
}

impl fmt::Display for CheckpointOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved => write!(f, "Approved"),
            Self::Denied { reason } => write!(f, "Denied: {reason}"),
            Self::Modified { changes } => write!(f, "Modified: {changes}"),
            Self::Escalated { to } => write!(f, "Escalated(to={to})"),
            Self::TimedOut { default_applied } => {
                write!(f, "TimedOut(default={default_applied})")
            }
        }
    }
}

// ── CheckpointResolution ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CheckpointResolution {
    pub outcome: CheckpointOutcome,
    pub resolved_by: String,
    pub resolved_at: i64,
    pub notes: Option<String>,
}

// ── CheckpointEvent ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CheckpointEvent {
    pub checkpoint_id: CheckpointId,
    pub agent_id: AgentId,
    pub action_id: Option<ActionId>,
    pub triggered_at: i64,
    pub context: String,
    pub resolution: Option<CheckpointResolution>,
}

// ── CheckpointManager ────────────────────────────────────────────────

pub struct CheckpointManager {
    checkpoints: Vec<Checkpoint>,
    events: Vec<CheckpointEvent>,
    counter: u64,
}

impl CheckpointManager {
    pub fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
            events: Vec::new(),
            counter: 0,
        }
    }

    pub fn add_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.checkpoints.push(checkpoint);
    }

    pub fn should_checkpoint(
        &self,
        agent: &Agent,
        action: &AgentAction,
        reasoning_confidence: Option<f64>,
    ) -> Option<&Checkpoint> {
        let mut triggered: Vec<&Checkpoint> = self
            .checkpoints
            .iter()
            .filter(|cp| cp.enabled && self.trigger_matches(cp, agent, action, reasoning_confidence))
            .collect();
        triggered.sort_by(|a, b| b.priority.cmp(&a.priority));
        triggered.into_iter().next()
    }

    fn trigger_matches(
        &self,
        cp: &Checkpoint,
        agent: &Agent,
        action: &AgentAction,
        reasoning_confidence: Option<f64>,
    ) -> bool {
        match &cp.trigger {
            CheckpointTrigger::RiskThreshold { min_risk } => action.risk_level >= *min_risk,
            CheckpointTrigger::ActionType { action_type } => {
                action.action_type.as_str() == *action_type
            }
            CheckpointTrigger::ResourceAccess { resource } => {
                action.target_resource.as_deref() == Some(resource.as_str())
            }
            CheckpointTrigger::BudgetThreshold { percent_used } => {
                if let Some(max) = agent.max_actions_per_session {
                    let used_pct = agent.actions_taken as f64 / max as f64;
                    used_pct >= *percent_used
                } else {
                    false
                }
            }
            CheckpointTrigger::ConfidenceBelow { threshold } => {
                reasoning_confidence.is_some_and(|c| c < *threshold)
            }
            CheckpointTrigger::EveryNActions { n } => {
                *n > 0 && agent.actions_taken > 0 && agent.actions_taken % n == 0
            }
            CheckpointTrigger::Always => true,
            CheckpointTrigger::Custom(_) => false,
        }
    }

    pub fn trigger_checkpoint(
        &mut self,
        checkpoint: &Checkpoint,
        agent_id: &AgentId,
        action_id: Option<&ActionId>,
        context: &str,
        now: i64,
    ) -> CheckpointEvent {
        self.counter += 1;
        let event = CheckpointEvent {
            checkpoint_id: checkpoint.id.clone(),
            agent_id: agent_id.clone(),
            action_id: action_id.cloned(),
            triggered_at: now,
            context: context.into(),
            resolution: None,
        };
        self.events.push(event.clone());
        event
    }

    pub fn resolve(
        &mut self,
        event_index: usize,
        outcome: CheckpointOutcome,
        resolved_by: &str,
        notes: Option<&str>,
        now: i64,
    ) -> Result<(), AgentError> {
        let event = self
            .events
            .get_mut(event_index)
            .ok_or_else(|| AgentError::CheckpointNotFound(format!("index {event_index}")))?;
        if event.resolution.is_some() {
            return Err(AgentError::CheckpointAlreadyResolved(
                event.checkpoint_id.0.clone(),
            ));
        }
        event.resolution = Some(CheckpointResolution {
            outcome,
            resolved_by: resolved_by.into(),
            resolved_at: now,
            notes: notes.map(String::from),
        });
        Ok(())
    }

    pub fn pending_checkpoints(&self) -> Vec<&CheckpointEvent> {
        self.events
            .iter()
            .filter(|e| e.resolution.is_none())
            .collect()
    }

    pub fn pending_for_agent(&self, agent_id: &AgentId) -> Vec<&CheckpointEvent> {
        self.events
            .iter()
            .filter(|e| e.resolution.is_none() && &e.agent_id == agent_id)
            .collect()
    }

    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }
}

impl Default for CheckpointManager {
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
    use crate::action::{ActionStatus, ActionType};
    use crate::agent::{AgentStatus, AgentType};
    use crate::autonomy::AutonomyLevel;
    use std::collections::HashMap;

    fn test_agent() -> Agent {
        let mut a = Agent::new("a1", "Test", AgentType::SemiAutonomous, "owner", AutonomyLevel::ActMediumRisk, 1000);
        a.status = AgentStatus::Active;
        a.max_actions_per_session = Some(10);
        a.actions_taken = 5;
        a
    }

    fn test_action(risk: ActionRisk) -> AgentAction {
        AgentAction {
            id: ActionId::new("act1"),
            agent_id: AgentId::new("a1"),
            action_type: ActionType::Write,
            description: "test".into(),
            target_resource: Some("database".into()),
            risk_level: risk,
            parameters: HashMap::new(),
            justification: None,
            status: ActionStatus::Authorized,
            requested_at: 1000,
            authorized_at: Some(1000),
            completed_at: None,
            authorized_by: Some("system".into()),
            result: None,
            parent_action_id: None,
        }
    }

    #[test]
    fn test_add_checkpoint() {
        let mut mgr = CheckpointManager::new();
        mgr.add_checkpoint(Checkpoint::new(
            "cp1", "High risk check",
            CheckpointTrigger::RiskThreshold { min_risk: ActionRisk::High },
            CheckpointPriority::High,
        ));
        assert_eq!(mgr.checkpoint_count(), 1);
    }

    #[test]
    fn test_should_checkpoint_risk_threshold() {
        let mut mgr = CheckpointManager::new();
        mgr.add_checkpoint(Checkpoint::new(
            "cp1", "High risk",
            CheckpointTrigger::RiskThreshold { min_risk: ActionRisk::High },
            CheckpointPriority::High,
        ));
        let agent = test_agent();
        let action = test_action(ActionRisk::Critical);
        assert!(mgr.should_checkpoint(&agent, &action, None).is_some());
    }

    #[test]
    fn test_should_checkpoint_returns_none() {
        let mut mgr = CheckpointManager::new();
        mgr.add_checkpoint(Checkpoint::new(
            "cp1", "High risk",
            CheckpointTrigger::RiskThreshold { min_risk: ActionRisk::High },
            CheckpointPriority::High,
        ));
        let agent = test_agent();
        let action = test_action(ActionRisk::Low);
        assert!(mgr.should_checkpoint(&agent, &action, None).is_none());
    }

    #[test]
    fn test_should_checkpoint_highest_priority() {
        let mut mgr = CheckpointManager::new();
        mgr.add_checkpoint(Checkpoint::new(
            "cp1", "Low priority",
            CheckpointTrigger::Always,
            CheckpointPriority::Low,
        ));
        mgr.add_checkpoint(Checkpoint::new(
            "cp2", "Critical priority",
            CheckpointTrigger::Always,
            CheckpointPriority::Critical,
        ));
        let agent = test_agent();
        let action = test_action(ActionRisk::Low);
        let cp = mgr.should_checkpoint(&agent, &action, None).unwrap();
        assert_eq!(cp.id.0, "cp2");
    }

    #[test]
    fn test_trigger_checkpoint_creates_event() {
        let mut mgr = CheckpointManager::new();
        let cp = Checkpoint::new(
            "cp1", "Test",
            CheckpointTrigger::Always,
            CheckpointPriority::Medium,
        );
        mgr.add_checkpoint(cp.clone());
        mgr.trigger_checkpoint(&cp, &AgentId::new("a1"), None, "test context", 1000);
        assert_eq!(mgr.pending_checkpoints().len(), 1);
    }

    #[test]
    fn test_resolve_checkpoint() {
        let mut mgr = CheckpointManager::new();
        let cp = Checkpoint::new("cp1", "Test", CheckpointTrigger::Always, CheckpointPriority::Medium);
        mgr.trigger_checkpoint(&cp, &AgentId::new("a1"), None, "test", 1000);
        mgr.resolve(0, CheckpointOutcome::Approved, "admin", Some("looks good"), 2000).unwrap();
        assert_eq!(mgr.pending_checkpoints().len(), 0);
    }

    #[test]
    fn test_pending_for_agent() {
        let mut mgr = CheckpointManager::new();
        let cp = Checkpoint::new("cp1", "Test", CheckpointTrigger::Always, CheckpointPriority::Medium);
        mgr.trigger_checkpoint(&cp, &AgentId::new("a1"), None, "test", 1000);
        mgr.trigger_checkpoint(&cp, &AgentId::new("a2"), None, "test", 1000);
        assert_eq!(mgr.pending_for_agent(&AgentId::new("a1")).len(), 1);
    }

    #[test]
    fn test_every_n_actions_trigger() {
        let mut mgr = CheckpointManager::new();
        mgr.add_checkpoint(Checkpoint::new(
            "cp1", "Every 5",
            CheckpointTrigger::EveryNActions { n: 5 },
            CheckpointPriority::Low,
        ));
        let mut agent = test_agent();
        let action = test_action(ActionRisk::Low);
        agent.actions_taken = 5;
        assert!(mgr.should_checkpoint(&agent, &action, None).is_some());
        agent.actions_taken = 3;
        assert!(mgr.should_checkpoint(&agent, &action, None).is_none());
    }

    #[test]
    fn test_confidence_below_trigger() {
        let mut mgr = CheckpointManager::new();
        mgr.add_checkpoint(Checkpoint::new(
            "cp1", "Low confidence",
            CheckpointTrigger::ConfidenceBelow { threshold: 0.5 },
            CheckpointPriority::High,
        ));
        let agent = test_agent();
        let action = test_action(ActionRisk::Low);
        assert!(mgr.should_checkpoint(&agent, &action, Some(0.3)).is_some());
        assert!(mgr.should_checkpoint(&agent, &action, Some(0.8)).is_none());
    }

    #[test]
    fn test_checkpoint_priority_ordering() {
        assert!(CheckpointPriority::Low < CheckpointPriority::Medium);
        assert!(CheckpointPriority::Medium < CheckpointPriority::High);
        assert!(CheckpointPriority::High < CheckpointPriority::Critical);
    }

    #[test]
    fn test_checkpoint_default_display() {
        let defaults = vec![
            CheckpointDefault::Deny,
            CheckpointDefault::Allow,
            CheckpointDefault::Escalate { to: "admin".into() },
        ];
        for d in &defaults {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(defaults.len(), 3);
    }

    #[test]
    fn test_checkpoint_outcome_display() {
        let outcomes = vec![
            CheckpointOutcome::Approved,
            CheckpointOutcome::Denied { reason: "no".into() },
            CheckpointOutcome::Modified { changes: "reduced scope".into() },
            CheckpointOutcome::Escalated { to: "manager".into() },
            CheckpointOutcome::TimedOut { default_applied: "deny".into() },
        ];
        for o in &outcomes {
            assert!(!o.to_string().is_empty());
        }
        assert_eq!(outcomes.len(), 5);
    }

    #[test]
    fn test_timeout_default_action() {
        let cp = Checkpoint::new("cp1", "Test", CheckpointTrigger::Always, CheckpointPriority::Medium)
            .with_timeout(5000)
            .with_default(CheckpointDefault::Deny);
        assert_eq!(cp.timeout_ms, Some(5000));
        assert_eq!(cp.default_action, CheckpointDefault::Deny);
    }
}
