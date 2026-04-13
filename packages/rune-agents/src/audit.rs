// ═══════════════════════════════════════════════════════════════════════
// Audit — Agent-specific audit events for action authorization,
// reasoning chains, tool use, checkpoints, and coordination.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use rune_security::SecuritySeverity;

use crate::agent::AgentId;

// ── AgentEventType ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentEventType {
    AgentRegistered { agent_type: String },
    AgentActivated,
    AgentSuspended { reason: String },
    AgentTerminated { reason: String },
    ActionAuthorized { action_type: String, risk: String },
    ActionDenied { action_type: String, reason: String },
    ActionCompleted { action_type: String, success: bool },
    ReasoningStepRecorded { step_type: String, confidence: f64 },
    ToolInvoked { tool_name: String },
    ToolDenied { tool_name: String, reason: String },
    CheckpointTriggered { checkpoint_name: String },
    CheckpointResolved { outcome: String },
    DelegationCreated { from: String, to: String, task: String },
    DelegationCompleted { success: bool },
    MessageSent { from: String, to: String, message_type: String },
    MessageBlocked { from: String, to: String, reason: String },
    CollectiveDecisionMade { outcome: String },
    AutonomyBoundaryViolation { boundary: String, action: String },
}

impl fmt::Display for AgentEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentRegistered { agent_type } => write!(f, "AgentRegistered({agent_type})"),
            Self::AgentActivated => write!(f, "AgentActivated"),
            Self::AgentSuspended { reason } => write!(f, "AgentSuspended({reason})"),
            Self::AgentTerminated { reason } => write!(f, "AgentTerminated({reason})"),
            Self::ActionAuthorized { action_type, risk } => {
                write!(f, "ActionAuthorized({action_type}, risk={risk})")
            }
            Self::ActionDenied { action_type, reason } => {
                write!(f, "ActionDenied({action_type}): {reason}")
            }
            Self::ActionCompleted { action_type, success } => {
                write!(f, "ActionCompleted({action_type}, success={success})")
            }
            Self::ReasoningStepRecorded { step_type, confidence } => {
                write!(f, "ReasoningStep({step_type}, confidence={confidence:.2})")
            }
            Self::ToolInvoked { tool_name } => write!(f, "ToolInvoked({tool_name})"),
            Self::ToolDenied { tool_name, reason } => {
                write!(f, "ToolDenied({tool_name}): {reason}")
            }
            Self::CheckpointTriggered { checkpoint_name } => {
                write!(f, "CheckpointTriggered({checkpoint_name})")
            }
            Self::CheckpointResolved { outcome } => {
                write!(f, "CheckpointResolved({outcome})")
            }
            Self::DelegationCreated { from, to, task } => {
                write!(f, "DelegationCreated({from}→{to}: {task})")
            }
            Self::DelegationCompleted { success } => {
                write!(f, "DelegationCompleted(success={success})")
            }
            Self::MessageSent { from, to, message_type } => {
                write!(f, "MessageSent({from}→{to}: {message_type})")
            }
            Self::MessageBlocked { from, to, reason } => {
                write!(f, "MessageBlocked({from}→{to}): {reason}")
            }
            Self::CollectiveDecisionMade { outcome } => {
                write!(f, "CollectiveDecision({outcome})")
            }
            Self::AutonomyBoundaryViolation { boundary, action } => {
                write!(f, "AutonomyViolation({boundary}: {action})")
            }
        }
    }
}

// ── AgentAuditEvent ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AgentAuditEvent {
    pub event_type: AgentEventType,
    pub severity: SecuritySeverity,
    pub timestamp: i64,
    pub agent_id: Option<AgentId>,
    pub detail: String,
}

// ── AgentAuditLog ────────────────────────────────────────────────────

pub struct AgentAuditLog {
    events: Vec<AgentAuditEvent>,
}

impl AgentAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, event: AgentAuditEvent) {
        self.events.push(event);
    }

    pub fn events_for_agent(&self, id: &AgentId) -> Vec<&AgentAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.agent_id.as_ref() == Some(id))
            .collect()
    }

    pub fn events_by_severity(&self, severity: SecuritySeverity) -> Vec<&AgentAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == severity)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&AgentAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn action_events(&self) -> Vec<&AgentAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    AgentEventType::ActionAuthorized { .. }
                        | AgentEventType::ActionDenied { .. }
                        | AgentEventType::ActionCompleted { .. }
                )
            })
            .collect()
    }

    pub fn checkpoint_events(&self) -> Vec<&AgentAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    AgentEventType::CheckpointTriggered { .. }
                        | AgentEventType::CheckpointResolved { .. }
                )
            })
            .collect()
    }

    pub fn delegation_events(&self) -> Vec<&AgentAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    AgentEventType::DelegationCreated { .. }
                        | AgentEventType::DelegationCompleted { .. }
                )
            })
            .collect()
    }

    pub fn coordination_events(&self) -> Vec<&AgentAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    AgentEventType::MessageSent { .. }
                        | AgentEventType::MessageBlocked { .. }
                        | AgentEventType::CollectiveDecisionMade { .. }
                )
            })
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for AgentAuditLog {
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

    fn sample_event(event_type: AgentEventType, severity: SecuritySeverity, agent_id: Option<&str>) -> AgentAuditEvent {
        AgentAuditEvent {
            event_type,
            severity,
            timestamp: 1000,
            agent_id: agent_id.map(AgentId::new),
            detail: "test".into(),
        }
    }

    #[test]
    fn test_record_and_retrieve() {
        let mut log = AgentAuditLog::new();
        log.record(sample_event(AgentEventType::AgentActivated, SecuritySeverity::Info, Some("a1")));
        assert_eq!(log.event_count(), 1);
    }

    #[test]
    fn test_events_for_agent() {
        let mut log = AgentAuditLog::new();
        log.record(sample_event(AgentEventType::AgentActivated, SecuritySeverity::Info, Some("a1")));
        log.record(sample_event(AgentEventType::AgentActivated, SecuritySeverity::Info, Some("a2")));
        assert_eq!(log.events_for_agent(&AgentId::new("a1")).len(), 1);
    }

    #[test]
    fn test_events_by_severity() {
        let mut log = AgentAuditLog::new();
        log.record(sample_event(AgentEventType::AgentActivated, SecuritySeverity::Info, Some("a1")));
        log.record(sample_event(
            AgentEventType::ActionDenied { action_type: "delete".into(), reason: "no".into() },
            SecuritySeverity::High,
            Some("a1"),
        ));
        assert_eq!(log.events_by_severity(SecuritySeverity::Info).len(), 1);
        assert_eq!(log.events_by_severity(SecuritySeverity::High).len(), 1);
    }

    #[test]
    fn test_action_events() {
        let mut log = AgentAuditLog::new();
        log.record(sample_event(
            AgentEventType::ActionAuthorized { action_type: "read".into(), risk: "low".into() },
            SecuritySeverity::Info, Some("a1"),
        ));
        log.record(sample_event(AgentEventType::AgentActivated, SecuritySeverity::Info, Some("a1")));
        assert_eq!(log.action_events().len(), 1);
    }

    #[test]
    fn test_checkpoint_events() {
        let mut log = AgentAuditLog::new();
        log.record(sample_event(
            AgentEventType::CheckpointTriggered { checkpoint_name: "cp1".into() },
            SecuritySeverity::Medium, Some("a1"),
        ));
        log.record(sample_event(
            AgentEventType::CheckpointResolved { outcome: "approved".into() },
            SecuritySeverity::Info, Some("a1"),
        ));
        assert_eq!(log.checkpoint_events().len(), 2);
    }

    #[test]
    fn test_delegation_events() {
        let mut log = AgentAuditLog::new();
        log.record(sample_event(
            AgentEventType::DelegationCreated { from: "a1".into(), to: "a2".into(), task: "t".into() },
            SecuritySeverity::Info, None,
        ));
        assert_eq!(log.delegation_events().len(), 1);
    }

    #[test]
    fn test_coordination_events() {
        let mut log = AgentAuditLog::new();
        log.record(sample_event(
            AgentEventType::MessageSent { from: "a1".into(), to: "a2".into(), message_type: "query".into() },
            SecuritySeverity::Info, None,
        ));
        log.record(sample_event(
            AgentEventType::MessageBlocked { from: "a1".into(), to: "a3".into(), reason: "denied".into() },
            SecuritySeverity::Medium, None,
        ));
        assert_eq!(log.coordination_events().len(), 2);
    }

    #[test]
    fn test_event_type_display_all_variants() {
        let types: Vec<AgentEventType> = vec![
            AgentEventType::AgentRegistered { agent_type: "Autonomous".into() },
            AgentEventType::AgentActivated,
            AgentEventType::AgentSuspended { reason: "policy".into() },
            AgentEventType::AgentTerminated { reason: "done".into() },
            AgentEventType::ActionAuthorized { action_type: "read".into(), risk: "low".into() },
            AgentEventType::ActionDenied { action_type: "delete".into(), reason: "forbidden".into() },
            AgentEventType::ActionCompleted { action_type: "write".into(), success: true },
            AgentEventType::ReasoningStepRecorded { step_type: "Decision".into(), confidence: 0.9 },
            AgentEventType::ToolInvoked { tool_name: "search".into() },
            AgentEventType::ToolDenied { tool_name: "deploy".into(), reason: "no access".into() },
            AgentEventType::CheckpointTriggered { checkpoint_name: "risk_gate".into() },
            AgentEventType::CheckpointResolved { outcome: "approved".into() },
            AgentEventType::DelegationCreated { from: "a1".into(), to: "a2".into(), task: "analyze".into() },
            AgentEventType::DelegationCompleted { success: true },
            AgentEventType::MessageSent { from: "a1".into(), to: "a2".into(), message_type: "query".into() },
            AgentEventType::MessageBlocked { from: "a1".into(), to: "a3".into(), reason: "denied".into() },
            AgentEventType::CollectiveDecisionMade { outcome: "approved".into() },
            AgentEventType::AutonomyBoundaryViolation { boundary: "b1".into(), action: "delete".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 18);
    }
}
