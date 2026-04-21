// ═══════════════════════════════════════════════════════════════════════
// rune-agents — Agent governance, action authorization, autonomy
// boundaries, reasoning chain auditing, tool-use permissions,
// human-in-the-loop checkpoints, task delegation, and multi-agent
// coordination for the RUNE governance ecosystem.
// ═══════════════════════════════════════════════════════════════════════

pub mod action;
pub mod agent;
pub mod audit;
pub mod autonomy;
pub mod checkpoint;
pub mod coordination;
pub mod delegation;
pub mod error;
pub mod reasoning;
pub mod tool;

// Layer 2 modules
pub mod l2_behavioral;
pub mod l2_capability;
pub mod l2_comm_chain;
pub mod l2_coordination;
pub mod l2_delegation;
pub mod l2_trust;

// Layer 3 modules
pub mod agent_export;
pub mod agent_metrics;
pub mod agent_stream;
pub mod autonomy_controller;
pub mod backend;
pub mod delegation_manager;
pub mod tool_governance;

// ── Re-exports ───────────────────────────────────────────────────────

pub use action::{
    ActionAuthorizer, ActionId, ActionRisk, ActionStatus, ActionType, AgentAction,
};
pub use agent::{Agent, AgentId, AgentRegistry, AgentStatus, AgentType};
pub use audit::{AgentAuditEvent, AgentAuditLog, AgentEventType};
pub use autonomy::{
    AutonomyBoundary, AutonomyCheck, AutonomyEnvelope, AutonomyLevel, AutonomyOutcome,
    TimeWindow,
};
pub use checkpoint::{
    Checkpoint, CheckpointDefault, CheckpointEvent, CheckpointId, CheckpointManager,
    CheckpointOutcome, CheckpointPriority, CheckpointResolution, CheckpointTrigger,
};
pub use coordination::{
    AgentMessage, CollectiveDecision, CollectiveStatus, CoordinationGovernor,
    CoordinationPolicy, CoordinationResult, MessageType, Vote, VoteDecision, VoteTally,
    tally_votes,
};
pub use delegation::{
    Delegation, DelegationConstraints, DelegationId, DelegationManager, DelegationStatus,
};
pub use error::AgentError;
pub use reasoning::{
    ReasoningChain, ReasoningChainId, ReasoningStatus, ReasoningStep, ReasoningStore, StepType,
};
pub use tool::{
    ToolDefinition, ToolId, ToolInvocation, ToolInvocationStatus, ToolPermission,
    ToolPermissionOutcome, ToolRegistry,
};

// ── Layer 2 re-exports ──────────────────────────────────────────────

pub use l2_behavioral::{
    BehavioralPolicy, BehavioralPolicyEngine, BehavioralRule, BehavioralViolation,
    PolicyEnforcement, PolicyEvaluation, RuleAction,
};
pub use l2_capability::{
    AgentCapability, AgentCapabilityRegistry, CapabilityRiskLevel, CapabilityType,
};
pub use l2_comm_chain::{ChainVerification, CommunicationChain, CommunicationRecord};
pub use l2_coordination::{
    CoordinationMessage, L2CoordinationManager, L2CoordinationProtocol,
    L2CoordinationSession, L2MessageType, ProtocolType, SessionStatus,
};
pub use l2_delegation::{
    DelegatedTask, L2DelegationManager, L2DelegationStatus, TaskPriority,
};
pub use l2_trust::{AgentTrustEngine, AgentTrustProfile};

// ── Layer 3 re-exports ──────────────────────────────────────────────

pub use agent_export::{
    AgentCardExporter, AgentGovernanceExporter, AutonomyAssessmentExporter,
    DelegationChainExporter, HumanOversightReportExporter, JsonAgentGovernanceExporter,
};
pub use agent_metrics::{
    AgentGovernanceMetricSnapshot, AgentGovernanceMetricsCollector, EscalationRecord,
    InMemoryAgentGovernanceMetricsCollector, NullAgentGovernanceMetricsCollector,
    ToolDenialRecord,
};
pub use agent_stream::{
    AgentGovernanceEventCollector, AgentGovernanceLifecycleEvent,
    AgentGovernanceLifecycleEventType, AgentLifecycleEventSubscriber,
    AgentLifecycleEventSubscriberRegistry, FilteredAgentLifecycleEventSubscriber,
};
pub use autonomy_controller::{
    AlwaysEscalateAutonomyController, AutonomyDecision, AutonomyEvaluation,
    AutonomyLevelController, InMemoryAutonomyLevelController, LevelChangeRecommendation,
    NullAutonomyLevelController,
};
pub use backend::{
    AgentGovernanceBackend, InMemoryAgentGovernanceBackend, StoredAgentGovernanceProfile,
    StoredAgentGovernanceStatus, StoredAutonomyConfiguration, StoredDelegationChainRecord,
    StoredDelegationChainStatus, StoredGovernanceSnapshot, StoredToolPolicy,
    StoredToolPolicyDecision,
};
pub use delegation_manager::{
    DelegationChainEntry, DelegationEvaluation, DelegationGovernor,
    DelegationRequestDecision, DepthLimitedDelegationGovernor, InMemoryDelegationGovernor,
    NullDelegationGovernor,
};
pub use tool_governance::{
    DenyAllToolUseGovernor, InMemoryToolUseGovernor, NullToolUseGovernor,
    ToolGovernanceDecision, ToolGovernanceEvaluation, ToolPolicyEntry, ToolUseGovernor,
};
