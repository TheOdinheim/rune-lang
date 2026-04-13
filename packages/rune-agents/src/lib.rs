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
