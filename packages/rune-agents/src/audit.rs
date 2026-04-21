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
    // Layer 2
    CoordinationProtocolRegistered { protocol_id: String, protocol_type: String },
    CoordinationSessionStarted { session_id: String, protocol_id: String },
    CoordinationSessionCompleted { session_id: String, message_count: String },
    CoordinationMessageSent { session_id: String, from: String, to: String },
    CapabilityGranted { agent_id: String, capability_id: String, risk_level: String },
    CapabilityRevoked { agent_id: String, capability_id: String },
    CommunicationChainAppended { from: String, to: String, chain_length: String },
    CommunicationChainVerified { valid: bool, verified_links: String },
    TrustScoreUpdated { agent_id: String, score: String },
    TrustDecayApplied { agents_affected: String },
    TaskDelegated { task_id: String, delegator: String, delegatee: String },
    TaskCompleted { task_id: String, success: bool },
    TaskRedelegated { task_id: String, new_delegatee: String },
    BehavioralPolicyEvaluated { agent_id: String, action: String, allowed: bool },
    BehavioralViolationRecorded { policy_id: String, agent_id: String },
    // Layer 3
    StoredGovernanceProfileCreated { profile_id: String, agent_id: String },
    StoredGovernanceProfileUpdated { profile_id: String, agent_id: String },
    StoredGovernanceProfileSuspended { profile_id: String, agent_id: String },
    StoredGovernanceProfileDecommissioned { profile_id: String, agent_id: String },
    AutonomyLevelEvaluated { agent_id: String, action: String, decision: String },
    AutonomyLevelChanged { agent_id: String, from_level: String, to_level: String },
    AutonomyEscalationTriggered { agent_id: String, action: String, escalation_target: String },
    StoredAutonomyConfigurationCreated { config_id: String, agent_id: String },
    ToolGovernancePolicyRegistered { agent_id: String, tool_ref: String, decision: String },
    ToolGovernancePolicyRemoved { agent_id: String, tool_ref: String },
    ToolGovernanceRequestEvaluated { agent_id: String, tool_ref: String, decision: String },
    ToolGovernanceRequestDenied { agent_id: String, tool_ref: String, reason: String },
    StoredDelegationChainRecorded { chain_id: String, delegator_id: String, delegatee_id: String },
    DelegationDepthLimitEnforced { delegator_id: String, current_depth: String, max_depth: String },
    DelegationGovernanceApproved { delegator_id: String, delegatee_id: String, task: String },
    DelegationGovernanceDenied { delegator_id: String, delegatee_id: String, reason: String },
    AgentGovernanceExported { format: String, agent_id: String },
    AgentGovernanceExportFailed { format: String, reason: String },
    StoredGovernanceSnapshotCaptured { snapshot_id: String, agent_id: String },
    OperationalAgentMetricsComputed { agent_id: String, metric_type: String },
    AgentGovernanceFlushed { record_count: String },
    HumanOversightReportGenerated { agent_id: String, format: String },
    AutonomyAssessmentExported { agent_id: String, framework: String },
    AgentCardExported { agent_id: String },
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
            Self::CoordinationProtocolRegistered { protocol_id, protocol_type } => {
                write!(f, "CoordinationProtocolRegistered({protocol_id}, {protocol_type})")
            }
            Self::CoordinationSessionStarted { session_id, protocol_id } => {
                write!(f, "CoordinationSessionStarted({session_id}, {protocol_id})")
            }
            Self::CoordinationSessionCompleted { session_id, message_count } => {
                write!(f, "CoordinationSessionCompleted({session_id}, msgs={message_count})")
            }
            Self::CoordinationMessageSent { session_id, from, to } => {
                write!(f, "CoordinationMessageSent({session_id}, {from}→{to})")
            }
            Self::CapabilityGranted { agent_id, capability_id, risk_level } => {
                write!(f, "CapabilityGranted({agent_id}, {capability_id}, risk={risk_level})")
            }
            Self::CapabilityRevoked { agent_id, capability_id } => {
                write!(f, "CapabilityRevoked({agent_id}, {capability_id})")
            }
            Self::CommunicationChainAppended { from, to, chain_length } => {
                write!(f, "CommunicationChainAppended({from}→{to}, len={chain_length})")
            }
            Self::CommunicationChainVerified { valid, verified_links } => {
                write!(f, "CommunicationChainVerified(valid={valid}, links={verified_links})")
            }
            Self::TrustScoreUpdated { agent_id, score } => {
                write!(f, "TrustScoreUpdated({agent_id}, score={score})")
            }
            Self::TrustDecayApplied { agents_affected } => {
                write!(f, "TrustDecayApplied(agents={agents_affected})")
            }
            Self::TaskDelegated { task_id, delegator, delegatee } => {
                write!(f, "TaskDelegated({task_id}, {delegator}→{delegatee})")
            }
            Self::TaskCompleted { task_id, success } => {
                write!(f, "TaskCompleted({task_id}, success={success})")
            }
            Self::TaskRedelegated { task_id, new_delegatee } => {
                write!(f, "TaskRedelegated({task_id}, →{new_delegatee})")
            }
            Self::BehavioralPolicyEvaluated { agent_id, action, allowed } => {
                write!(f, "BehavioralPolicyEvaluated({agent_id}, {action}, allowed={allowed})")
            }
            Self::BehavioralViolationRecorded { policy_id, agent_id } => {
                write!(f, "BehavioralViolationRecorded({policy_id}, {agent_id})")
            }
            // Layer 3 — delegate to type_name()
            _ => f.write_str(self.type_name()),
        }
    }
}

impl AgentEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::AgentRegistered { .. } => "AgentRegistered",
            Self::AgentActivated => "AgentActivated",
            Self::AgentSuspended { .. } => "AgentSuspended",
            Self::AgentTerminated { .. } => "AgentTerminated",
            Self::ActionAuthorized { .. } => "ActionAuthorized",
            Self::ActionDenied { .. } => "ActionDenied",
            Self::ActionCompleted { .. } => "ActionCompleted",
            Self::ReasoningStepRecorded { .. } => "ReasoningStepRecorded",
            Self::ToolInvoked { .. } => "ToolInvoked",
            Self::ToolDenied { .. } => "ToolDenied",
            Self::CheckpointTriggered { .. } => "CheckpointTriggered",
            Self::CheckpointResolved { .. } => "CheckpointResolved",
            Self::DelegationCreated { .. } => "DelegationCreated",
            Self::DelegationCompleted { .. } => "DelegationCompleted",
            Self::MessageSent { .. } => "MessageSent",
            Self::MessageBlocked { .. } => "MessageBlocked",
            Self::CollectiveDecisionMade { .. } => "CollectiveDecisionMade",
            Self::AutonomyBoundaryViolation { .. } => "AutonomyBoundaryViolation",
            Self::CoordinationProtocolRegistered { .. } => "CoordinationProtocolRegistered",
            Self::CoordinationSessionStarted { .. } => "CoordinationSessionStarted",
            Self::CoordinationSessionCompleted { .. } => "CoordinationSessionCompleted",
            Self::CoordinationMessageSent { .. } => "CoordinationMessageSent",
            Self::CapabilityGranted { .. } => "CapabilityGranted",
            Self::CapabilityRevoked { .. } => "CapabilityRevoked",
            Self::CommunicationChainAppended { .. } => "CommunicationChainAppended",
            Self::CommunicationChainVerified { .. } => "CommunicationChainVerified",
            Self::TrustScoreUpdated { .. } => "TrustScoreUpdated",
            Self::TrustDecayApplied { .. } => "TrustDecayApplied",
            Self::TaskDelegated { .. } => "TaskDelegated",
            Self::TaskCompleted { .. } => "TaskCompleted",
            Self::TaskRedelegated { .. } => "TaskRedelegated",
            Self::BehavioralPolicyEvaluated { .. } => "BehavioralPolicyEvaluated",
            Self::BehavioralViolationRecorded { .. } => "BehavioralViolationRecorded",
            Self::StoredGovernanceProfileCreated { .. } => "StoredGovernanceProfileCreated",
            Self::StoredGovernanceProfileUpdated { .. } => "StoredGovernanceProfileUpdated",
            Self::StoredGovernanceProfileSuspended { .. } => "StoredGovernanceProfileSuspended",
            Self::StoredGovernanceProfileDecommissioned { .. } => "StoredGovernanceProfileDecommissioned",
            Self::AutonomyLevelEvaluated { .. } => "AutonomyLevelEvaluated",
            Self::AutonomyLevelChanged { .. } => "AutonomyLevelChanged",
            Self::AutonomyEscalationTriggered { .. } => "AutonomyEscalationTriggered",
            Self::StoredAutonomyConfigurationCreated { .. } => "StoredAutonomyConfigurationCreated",
            Self::ToolGovernancePolicyRegistered { .. } => "ToolGovernancePolicyRegistered",
            Self::ToolGovernancePolicyRemoved { .. } => "ToolGovernancePolicyRemoved",
            Self::ToolGovernanceRequestEvaluated { .. } => "ToolGovernanceRequestEvaluated",
            Self::ToolGovernanceRequestDenied { .. } => "ToolGovernanceRequestDenied",
            Self::StoredDelegationChainRecorded { .. } => "StoredDelegationChainRecorded",
            Self::DelegationDepthLimitEnforced { .. } => "DelegationDepthLimitEnforced",
            Self::DelegationGovernanceApproved { .. } => "DelegationGovernanceApproved",
            Self::DelegationGovernanceDenied { .. } => "DelegationGovernanceDenied",
            Self::AgentGovernanceExported { .. } => "AgentGovernanceExported",
            Self::AgentGovernanceExportFailed { .. } => "AgentGovernanceExportFailed",
            Self::StoredGovernanceSnapshotCaptured { .. } => "StoredGovernanceSnapshotCaptured",
            Self::OperationalAgentMetricsComputed { .. } => "OperationalAgentMetricsComputed",
            Self::AgentGovernanceFlushed { .. } => "AgentGovernanceFlushed",
            Self::HumanOversightReportGenerated { .. } => "HumanOversightReportGenerated",
            Self::AutonomyAssessmentExported { .. } => "AutonomyAssessmentExported",
            Self::AgentCardExported { .. } => "AgentCardExported",
        }
    }

    pub fn kind(&self) -> &str {
        match self {
            Self::AgentRegistered { .. }
            | Self::AgentActivated
            | Self::AgentSuspended { .. }
            | Self::AgentTerminated { .. } => "agent_lifecycle",
            Self::ActionAuthorized { .. }
            | Self::ActionDenied { .. }
            | Self::ActionCompleted { .. } => "action",
            Self::ReasoningStepRecorded { .. } => "reasoning",
            Self::ToolInvoked { .. } | Self::ToolDenied { .. } => "tool",
            Self::CheckpointTriggered { .. } | Self::CheckpointResolved { .. } => "checkpoint",
            Self::DelegationCreated { .. } | Self::DelegationCompleted { .. } => "delegation",
            Self::MessageSent { .. }
            | Self::MessageBlocked { .. }
            | Self::CollectiveDecisionMade { .. } => "coordination",
            Self::AutonomyBoundaryViolation { .. } => "autonomy",
            Self::CoordinationProtocolRegistered { .. }
            | Self::CoordinationSessionStarted { .. }
            | Self::CoordinationSessionCompleted { .. }
            | Self::CoordinationMessageSent { .. } => "l2_coordination",
            Self::CapabilityGranted { .. } | Self::CapabilityRevoked { .. } => "capability",
            Self::CommunicationChainAppended { .. }
            | Self::CommunicationChainVerified { .. } => "communication_chain",
            Self::TrustScoreUpdated { .. } | Self::TrustDecayApplied { .. } => "trust",
            Self::TaskDelegated { .. }
            | Self::TaskCompleted { .. }
            | Self::TaskRedelegated { .. } => "l2_delegation",
            Self::BehavioralPolicyEvaluated { .. }
            | Self::BehavioralViolationRecorded { .. } => "behavioral",
            // Layer 3
            Self::StoredGovernanceProfileCreated { .. }
            | Self::StoredGovernanceProfileUpdated { .. }
            | Self::StoredGovernanceProfileSuspended { .. }
            | Self::StoredGovernanceProfileDecommissioned { .. }
            | Self::AgentGovernanceFlushed { .. } => "governance_backend",
            Self::AutonomyLevelEvaluated { .. }
            | Self::AutonomyLevelChanged { .. }
            | Self::AutonomyEscalationTriggered { .. }
            | Self::StoredAutonomyConfigurationCreated { .. } => "autonomy_governance",
            Self::ToolGovernancePolicyRegistered { .. }
            | Self::ToolGovernancePolicyRemoved { .. }
            | Self::ToolGovernanceRequestEvaluated { .. }
            | Self::ToolGovernanceRequestDenied { .. } => "tool_governance",
            Self::StoredDelegationChainRecorded { .. }
            | Self::DelegationDepthLimitEnforced { .. }
            | Self::DelegationGovernanceApproved { .. }
            | Self::DelegationGovernanceDenied { .. } => "delegation_governance",
            Self::AgentGovernanceExported { .. }
            | Self::AgentGovernanceExportFailed { .. }
            | Self::HumanOversightReportGenerated { .. }
            | Self::AutonomyAssessmentExported { .. }
            | Self::AgentCardExported { .. } => "governance_export",
            Self::StoredGovernanceSnapshotCaptured { .. } => "governance_snapshot",
            Self::OperationalAgentMetricsComputed { .. } => "governance_metrics",
        }
    }

    pub fn is_backend_event(&self) -> bool {
        matches!(
            self,
            Self::StoredGovernanceProfileCreated { .. }
                | Self::StoredGovernanceProfileUpdated { .. }
                | Self::StoredGovernanceProfileSuspended { .. }
                | Self::StoredGovernanceProfileDecommissioned { .. }
                | Self::StoredAutonomyConfigurationCreated { .. }
                | Self::StoredDelegationChainRecorded { .. }
                | Self::StoredGovernanceSnapshotCaptured { .. }
                | Self::AgentGovernanceFlushed { .. }
        )
    }

    pub fn is_autonomy_governance_event(&self) -> bool {
        matches!(
            self,
            Self::AutonomyLevelEvaluated { .. }
                | Self::AutonomyLevelChanged { .. }
                | Self::AutonomyEscalationTriggered { .. }
                | Self::StoredAutonomyConfigurationCreated { .. }
        )
    }

    pub fn is_tool_governance_event(&self) -> bool {
        matches!(
            self,
            Self::ToolGovernancePolicyRegistered { .. }
                | Self::ToolGovernancePolicyRemoved { .. }
                | Self::ToolGovernanceRequestEvaluated { .. }
                | Self::ToolGovernanceRequestDenied { .. }
        )
    }

    pub fn is_delegation_governance_event(&self) -> bool {
        matches!(
            self,
            Self::StoredDelegationChainRecorded { .. }
                | Self::DelegationDepthLimitEnforced { .. }
                | Self::DelegationGovernanceApproved { .. }
                | Self::DelegationGovernanceDenied { .. }
        )
    }

    pub fn is_governance_export_event(&self) -> bool {
        matches!(
            self,
            Self::AgentGovernanceExported { .. }
                | Self::AgentGovernanceExportFailed { .. }
                | Self::HumanOversightReportGenerated { .. }
                | Self::AutonomyAssessmentExported { .. }
                | Self::AgentCardExported { .. }
        )
    }

    pub fn is_governance_metrics_event(&self) -> bool {
        matches!(self, Self::OperationalAgentMetricsComputed { .. })
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
            // Layer 2
            AgentEventType::CoordinationProtocolRegistered { protocol_id: "p1".into(), protocol_type: "Consensus".into() },
            AgentEventType::CoordinationSessionStarted { session_id: "s1".into(), protocol_id: "p1".into() },
            AgentEventType::CoordinationSessionCompleted { session_id: "s1".into(), message_count: "5".into() },
            AgentEventType::CoordinationMessageSent { session_id: "s1".into(), from: "a1".into(), to: "a2".into() },
            AgentEventType::CapabilityGranted { agent_id: "a1".into(), capability_id: "c1".into(), risk_level: "High".into() },
            AgentEventType::CapabilityRevoked { agent_id: "a1".into(), capability_id: "c1".into() },
            AgentEventType::CommunicationChainAppended { from: "a1".into(), to: "a2".into(), chain_length: "10".into() },
            AgentEventType::CommunicationChainVerified { valid: true, verified_links: "10".into() },
            AgentEventType::TrustScoreUpdated { agent_id: "a1".into(), score: "0.85".into() },
            AgentEventType::TrustDecayApplied { agents_affected: "3".into() },
            AgentEventType::TaskDelegated { task_id: "t1".into(), delegator: "a1".into(), delegatee: "a2".into() },
            AgentEventType::TaskCompleted { task_id: "t1".into(), success: true },
            AgentEventType::TaskRedelegated { task_id: "t1".into(), new_delegatee: "a3".into() },
            AgentEventType::BehavioralPolicyEvaluated { agent_id: "a1".into(), action: "delete".into(), allowed: false },
            AgentEventType::BehavioralViolationRecorded { policy_id: "p1".into(), agent_id: "a1".into() },
            // Layer 3
            AgentEventType::StoredGovernanceProfileCreated { profile_id: "p1".into(), agent_id: "a1".into() },
            AgentEventType::StoredGovernanceProfileUpdated { profile_id: "p1".into(), agent_id: "a1".into() },
            AgentEventType::StoredGovernanceProfileSuspended { profile_id: "p1".into(), agent_id: "a1".into() },
            AgentEventType::StoredGovernanceProfileDecommissioned { profile_id: "p1".into(), agent_id: "a1".into() },
            AgentEventType::AutonomyLevelEvaluated { agent_id: "a1".into(), action: "read".into(), decision: "Permit".into() },
            AgentEventType::AutonomyLevelChanged { agent_id: "a1".into(), from_level: "Low".into(), to_level: "Medium".into() },
            AgentEventType::AutonomyEscalationTriggered { agent_id: "a1".into(), action: "deploy".into(), escalation_target: "human".into() },
            AgentEventType::StoredAutonomyConfigurationCreated { config_id: "c1".into(), agent_id: "a1".into() },
            AgentEventType::ToolGovernancePolicyRegistered { agent_id: "a1".into(), tool_ref: "search".into(), decision: "Permit".into() },
            AgentEventType::ToolGovernancePolicyRemoved { agent_id: "a1".into(), tool_ref: "search".into() },
            AgentEventType::ToolGovernanceRequestEvaluated { agent_id: "a1".into(), tool_ref: "search".into(), decision: "Permit".into() },
            AgentEventType::ToolGovernanceRequestDenied { agent_id: "a1".into(), tool_ref: "deploy".into(), reason: "policy".into() },
            AgentEventType::StoredDelegationChainRecorded { chain_id: "ch1".into(), delegator_id: "a1".into(), delegatee_id: "a2".into() },
            AgentEventType::DelegationDepthLimitEnforced { delegator_id: "a1".into(), current_depth: "3".into(), max_depth: "2".into() },
            AgentEventType::DelegationGovernanceApproved { delegator_id: "a1".into(), delegatee_id: "a2".into(), task: "analyze".into() },
            AgentEventType::DelegationGovernanceDenied { delegator_id: "a1".into(), delegatee_id: "a2".into(), reason: "untrusted".into() },
            AgentEventType::AgentGovernanceExported { format: "JSON".into(), agent_id: "a1".into() },
            AgentEventType::AgentGovernanceExportFailed { format: "JSON".into(), reason: "err".into() },
            AgentEventType::StoredGovernanceSnapshotCaptured { snapshot_id: "s1".into(), agent_id: "a1".into() },
            AgentEventType::OperationalAgentMetricsComputed { agent_id: "a1".into(), metric_type: "escalation_rate".into() },
            AgentEventType::AgentGovernanceFlushed { record_count: "42".into() },
            AgentEventType::HumanOversightReportGenerated { agent_id: "a1".into(), format: "Markdown".into() },
            AgentEventType::AutonomyAssessmentExported { agent_id: "a1".into(), framework: "NIST AI RMF".into() },
            AgentEventType::AgentCardExported { agent_id: "a1".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 57);
    }

    #[test]
    fn test_l3_type_name_and_kind() {
        let variants = vec![
            AgentEventType::StoredGovernanceProfileCreated { profile_id: "p1".into(), agent_id: "a1".into() },
            AgentEventType::AutonomyLevelEvaluated { agent_id: "a1".into(), action: "read".into(), decision: "Permit".into() },
            AgentEventType::ToolGovernancePolicyRegistered { agent_id: "a1".into(), tool_ref: "s".into(), decision: "Permit".into() },
            AgentEventType::StoredDelegationChainRecorded { chain_id: "c".into(), delegator_id: "a".into(), delegatee_id: "b".into() },
            AgentEventType::AgentGovernanceExported { format: "JSON".into(), agent_id: "a1".into() },
            AgentEventType::OperationalAgentMetricsComputed { agent_id: "a1".into(), metric_type: "x".into() },
        ];
        for v in &variants {
            assert!(!v.type_name().is_empty());
            assert!(!v.kind().is_empty());
        }
    }

    #[test]
    fn test_l3_classification_methods() {
        let backend = AgentEventType::StoredGovernanceProfileCreated { profile_id: "p".into(), agent_id: "a".into() };
        assert!(backend.is_backend_event());
        assert!(!backend.is_tool_governance_event());

        let autonomy = AgentEventType::AutonomyEscalationTriggered { agent_id: "a".into(), action: "x".into(), escalation_target: "h".into() };
        assert!(autonomy.is_autonomy_governance_event());

        let tool = AgentEventType::ToolGovernanceRequestDenied { agent_id: "a".into(), tool_ref: "t".into(), reason: "r".into() };
        assert!(tool.is_tool_governance_event());

        let delegation = AgentEventType::DelegationDepthLimitEnforced { delegator_id: "a".into(), current_depth: "3".into(), max_depth: "2".into() };
        assert!(delegation.is_delegation_governance_event());

        let export = AgentEventType::HumanOversightReportGenerated { agent_id: "a".into(), format: "md".into() };
        assert!(export.is_governance_export_event());

        let metrics = AgentEventType::OperationalAgentMetricsComputed { agent_id: "a".into(), metric_type: "x".into() };
        assert!(metrics.is_governance_metrics_event());
    }
}
