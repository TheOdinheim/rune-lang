// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — AutonomyLevelController trait for evaluating and managing
// agent autonomy levels: level assessment, escalation detection,
// level change recommendations. Autonomy levels are opaque strings
// (not the L1 AutonomyLevel enum) for extensibility.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::AgentError;

// ── AutonomyEvaluation ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutonomyEvaluation {
    pub agent_id: String,
    pub current_level: String,
    pub evaluated_action: String,
    pub decision: AutonomyDecision,
    pub escalation_target: Option<String>,
    pub justification: String,
    pub evaluated_at: i64,
}

// ── AutonomyDecision ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AutonomyDecision {
    Permit,
    Deny,
    Escalate,
    RequireHumanApproval,
    DegradeAutonomy,
}

impl fmt::Display for AutonomyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Permit => "Permit",
            Self::Deny => "Deny",
            Self::Escalate => "Escalate",
            Self::RequireHumanApproval => "RequireHumanApproval",
            Self::DegradeAutonomy => "DegradeAutonomy",
        };
        f.write_str(s)
    }
}

// ── LevelChangeRecommendation ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LevelChangeRecommendation {
    pub agent_id: String,
    pub current_level: String,
    pub recommended_level: String,
    pub reason: String,
    pub confidence: String,
}

// ── AutonomyLevelController trait ───────────────────────────────────

pub trait AutonomyLevelController {
    fn evaluate_autonomy(
        &self,
        agent_id: &str,
        action: &str,
        context: &HashMap<String, String>,
    ) -> Result<AutonomyEvaluation, AgentError>;

    fn recommend_level_change(
        &self,
        agent_id: &str,
    ) -> Result<Option<LevelChangeRecommendation>, AgentError>;

    fn check_escalation_required(
        &self,
        agent_id: &str,
        action: &str,
    ) -> Result<bool, AgentError>;

    fn register_agent_level(
        &mut self,
        agent_id: &str,
        level: &str,
        escalation_target: &str,
    ) -> Result<(), AgentError>;

    fn list_active_levels(&self) -> Vec<(String, String)>;

    fn controller_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryAutonomyLevelController ─────────────────────────────────

struct AgentAutonomyEntry {
    level: String,
    #[allow(dead_code)]
    escalation_target: String,
    action_history: Vec<String>,
}

pub struct InMemoryAutonomyLevelController {
    id: String,
    agents: HashMap<String, AgentAutonomyEntry>,
    deny_patterns: Vec<String>,
}

impl InMemoryAutonomyLevelController {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            agents: HashMap::new(),
            deny_patterns: Vec::new(),
        }
    }

    pub fn add_deny_pattern(&mut self, pattern: impl Into<String>) {
        self.deny_patterns.push(pattern.into());
    }
}

impl AutonomyLevelController for InMemoryAutonomyLevelController {
    fn evaluate_autonomy(
        &self,
        agent_id: &str,
        action: &str,
        _context: &HashMap<String, String>,
    ) -> Result<AutonomyEvaluation, AgentError> {
        let entry = self.agents.get(agent_id).ok_or_else(|| {
            AgentError::AgentNotFound(agent_id.into())
        })?;

        // Check deny patterns
        for pattern in &self.deny_patterns {
            if action.contains(pattern.as_str()) {
                return Ok(AutonomyEvaluation {
                    agent_id: agent_id.into(),
                    current_level: entry.level.clone(),
                    evaluated_action: action.into(),
                    decision: AutonomyDecision::Deny,
                    escalation_target: None,
                    justification: format!("Action matches deny pattern: {pattern}"),
                    evaluated_at: 0,
                });
            }
        }

        Ok(AutonomyEvaluation {
            agent_id: agent_id.into(),
            current_level: entry.level.clone(),
            evaluated_action: action.into(),
            decision: AutonomyDecision::Permit,
            escalation_target: None,
            justification: "Action permitted at current autonomy level".into(),
            evaluated_at: 0,
        })
    }

    fn recommend_level_change(
        &self,
        agent_id: &str,
    ) -> Result<Option<LevelChangeRecommendation>, AgentError> {
        let entry = self.agents.get(agent_id).ok_or_else(|| {
            AgentError::AgentNotFound(agent_id.into())
        })?;
        if entry.action_history.len() > 100 {
            return Ok(Some(LevelChangeRecommendation {
                agent_id: agent_id.into(),
                current_level: entry.level.clone(),
                recommended_level: "ActHighRisk".into(),
                reason: "Sustained successful operation history".into(),
                confidence: "0.75".into(),
            }));
        }
        Ok(None)
    }

    fn check_escalation_required(
        &self,
        agent_id: &str,
        action: &str,
    ) -> Result<bool, AgentError> {
        let entry = self.agents.get(agent_id).ok_or_else(|| {
            AgentError::AgentNotFound(agent_id.into())
        })?;
        // Escalate if action contains "high_risk" and level is low
        Ok(action.contains("high_risk") && entry.level.contains("Low"))
    }

    fn register_agent_level(
        &mut self,
        agent_id: &str,
        level: &str,
        escalation_target: &str,
    ) -> Result<(), AgentError> {
        self.agents.insert(
            agent_id.into(),
            AgentAutonomyEntry {
                level: level.into(),
                escalation_target: escalation_target.into(),
                action_history: Vec::new(),
            },
        );
        Ok(())
    }

    fn list_active_levels(&self) -> Vec<(String, String)> {
        self.agents
            .iter()
            .map(|(id, entry)| (id.clone(), entry.level.clone()))
            .collect()
    }

    fn controller_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── AlwaysEscalateAutonomyController ────────────────────────────────
// EU AI Act Article 14 compliance: every action requires human oversight.

pub struct AlwaysEscalateAutonomyController {
    id: String,
    escalation_target: String,
}

impl AlwaysEscalateAutonomyController {
    pub fn new(id: impl Into<String>, escalation_target: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            escalation_target: escalation_target.into(),
        }
    }
}

impl AutonomyLevelController for AlwaysEscalateAutonomyController {
    fn evaluate_autonomy(
        &self,
        agent_id: &str,
        action: &str,
        _context: &HashMap<String, String>,
    ) -> Result<AutonomyEvaluation, AgentError> {
        Ok(AutonomyEvaluation {
            agent_id: agent_id.into(),
            current_level: "human-supervised".into(),
            evaluated_action: action.into(),
            decision: AutonomyDecision::RequireHumanApproval,
            escalation_target: Some(self.escalation_target.clone()),
            justification: "All actions require human approval (EU AI Act Article 14)".into(),
            evaluated_at: 0,
        })
    }

    fn recommend_level_change(
        &self,
        agent_id: &str,
    ) -> Result<Option<LevelChangeRecommendation>, AgentError> {
        Ok(Some(LevelChangeRecommendation {
            agent_id: agent_id.into(),
            current_level: "human-supervised".into(),
            recommended_level: "human-supervised".into(),
            reason: "EU AI Act Article 14 mandates human oversight".into(),
            confidence: "1.0000".into(),
        }))
    }

    fn check_escalation_required(
        &self,
        _agent_id: &str,
        _action: &str,
    ) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn register_agent_level(
        &mut self,
        _agent_id: &str,
        _level: &str,
        _escalation_target: &str,
    ) -> Result<(), AgentError> {
        Ok(())
    }

    fn list_active_levels(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    fn controller_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── NullAutonomyLevelController ─────────────────────────────────────

pub struct NullAutonomyLevelController;

impl AutonomyLevelController for NullAutonomyLevelController {
    fn evaluate_autonomy(
        &self,
        agent_id: &str,
        action: &str,
        _context: &HashMap<String, String>,
    ) -> Result<AutonomyEvaluation, AgentError> {
        Ok(AutonomyEvaluation {
            agent_id: agent_id.into(),
            current_level: "uncontrolled".into(),
            evaluated_action: action.into(),
            decision: AutonomyDecision::Permit,
            escalation_target: None,
            justification: "Null controller — no autonomy governance".into(),
            evaluated_at: 0,
        })
    }

    fn recommend_level_change(
        &self,
        _agent_id: &str,
    ) -> Result<Option<LevelChangeRecommendation>, AgentError> {
        Ok(None)
    }

    fn check_escalation_required(
        &self,
        _agent_id: &str,
        _action: &str,
    ) -> Result<bool, AgentError> {
        Ok(false)
    }

    fn register_agent_level(
        &mut self,
        _agent_id: &str,
        _level: &str,
        _escalation_target: &str,
    ) -> Result<(), AgentError> {
        Ok(())
    }

    fn list_active_levels(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    fn controller_id(&self) -> &str {
        "null-autonomy-controller"
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

    #[test]
    fn test_in_memory_evaluate_permits() {
        let mut ctrl = InMemoryAutonomyLevelController::new("ctrl-1");
        ctrl.register_agent_level("a1", "ActMediumRisk", "operator")
            .unwrap();
        let eval = ctrl
            .evaluate_autonomy("a1", "read_data", &HashMap::new())
            .unwrap();
        assert_eq!(eval.decision, AutonomyDecision::Permit);
    }

    #[test]
    fn test_in_memory_evaluate_denies() {
        let mut ctrl = InMemoryAutonomyLevelController::new("ctrl-1");
        ctrl.register_agent_level("a1", "ActLowRisk", "operator")
            .unwrap();
        ctrl.add_deny_pattern("delete");
        let eval = ctrl
            .evaluate_autonomy("a1", "delete_records", &HashMap::new())
            .unwrap();
        assert_eq!(eval.decision, AutonomyDecision::Deny);
    }

    #[test]
    fn test_in_memory_unknown_agent() {
        let ctrl = InMemoryAutonomyLevelController::new("ctrl-1");
        assert!(ctrl
            .evaluate_autonomy("unknown", "read", &HashMap::new())
            .is_err());
    }

    #[test]
    fn test_in_memory_escalation_check() {
        let mut ctrl = InMemoryAutonomyLevelController::new("ctrl-1");
        ctrl.register_agent_level("a1", "ActLowRisk", "operator")
            .unwrap();
        assert!(ctrl
            .check_escalation_required("a1", "high_risk_deploy")
            .unwrap());
        assert!(!ctrl
            .check_escalation_required("a1", "read_data")
            .unwrap());
    }

    #[test]
    fn test_in_memory_list_active_levels() {
        let mut ctrl = InMemoryAutonomyLevelController::new("ctrl-1");
        ctrl.register_agent_level("a1", "ActLowRisk", "op1")
            .unwrap();
        ctrl.register_agent_level("a2", "Full", "op2").unwrap();
        let levels = ctrl.list_active_levels();
        assert_eq!(levels.len(), 2);
    }

    #[test]
    fn test_in_memory_recommend_no_change() {
        let mut ctrl = InMemoryAutonomyLevelController::new("ctrl-1");
        ctrl.register_agent_level("a1", "ActLowRisk", "op")
            .unwrap();
        let rec = ctrl.recommend_level_change("a1").unwrap();
        assert!(rec.is_none());
    }

    #[test]
    fn test_always_escalate_all_actions() {
        let ctrl = AlwaysEscalateAutonomyController::new("strict", "human-operator");
        let eval = ctrl
            .evaluate_autonomy("a1", "read_data", &HashMap::new())
            .unwrap();
        assert_eq!(eval.decision, AutonomyDecision::RequireHumanApproval);
        assert_eq!(eval.escalation_target, Some("human-operator".into()));
    }

    #[test]
    fn test_always_escalate_check() {
        let ctrl = AlwaysEscalateAutonomyController::new("strict", "human");
        assert!(ctrl.check_escalation_required("a1", "anything").unwrap());
    }

    #[test]
    fn test_always_escalate_recommend() {
        let ctrl = AlwaysEscalateAutonomyController::new("strict", "human");
        let rec = ctrl.recommend_level_change("a1").unwrap();
        assert!(rec.is_some());
        assert_eq!(rec.unwrap().recommended_level, "human-supervised");
    }

    #[test]
    fn test_null_controller() {
        let mut ctrl = NullAutonomyLevelController;
        assert!(!ctrl.is_active());
        assert_eq!(ctrl.controller_id(), "null-autonomy-controller");
        let eval = ctrl
            .evaluate_autonomy("a1", "anything", &HashMap::new())
            .unwrap();
        assert_eq!(eval.decision, AutonomyDecision::Permit);
        assert!(!ctrl.check_escalation_required("a1", "x").unwrap());
        assert!(ctrl.recommend_level_change("a1").unwrap().is_none());
        ctrl.register_agent_level("a1", "x", "y").unwrap();
        assert!(ctrl.list_active_levels().is_empty());
    }

    #[test]
    fn test_autonomy_decision_display() {
        let decisions = vec![
            AutonomyDecision::Permit,
            AutonomyDecision::Deny,
            AutonomyDecision::Escalate,
            AutonomyDecision::RequireHumanApproval,
            AutonomyDecision::DegradeAutonomy,
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(decisions.len(), 5);
    }

    #[test]
    fn test_controller_id() {
        let ctrl = InMemoryAutonomyLevelController::new("my-ctrl");
        assert_eq!(ctrl.controller_id(), "my-ctrl");
        assert!(ctrl.is_active());
    }
}
