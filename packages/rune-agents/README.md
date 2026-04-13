# rune-agents

Agent governance, action authorization, autonomy boundaries, reasoning chain
auditing, tool-use permissions, human-in-the-loop checkpoints, task delegation,
and multi-agent coordination for the RUNE governance ecosystem.

## Overview

`rune-agents` provides the governance layer for autonomous and semi-autonomous
agents (GUNGNIR) operating within RUNE. Every agent action must be authorized,
every reasoning step auditable, and every delegation constrained by governance
inheritance.

## Modules

| Module | Purpose |
|---|---|
| `agent` | Agent identity, registration, type classification, status lifecycle |
| `autonomy` | Autonomy levels (None→Full), boundaries, envelopes, time windows |
| `action` | Action authorization, risk classification, execution tracking |
| `reasoning` | Reasoning chain auditing, step types, confidence tracking |
| `tool` | Tool registration, permission checking, invocation governance |
| `checkpoint` | Human-in-the-loop checkpoints, triggers, priority-based resolution |
| `delegation` | Task delegation with governance constraint inheritance |
| `coordination` | Multi-agent communication governance, collective decision-making, voting |
| `audit` | Agent-specific audit events (18 event types) |
| `error` | `AgentError` with 18 domain-specific variants |

## Key Concepts

### Autonomy Levels

Seven ordered levels control what agents can do:

`None` < `Observe` < `Suggest` < `ActLowRisk` < `ActMediumRisk` < `ActHighRisk` < `Full`

Each level defines observation, suggestion, and action capabilities, plus a
maximum risk level the agent may authorize independently.

### Autonomy Envelopes

An `AutonomyEnvelope` wraps an agent's boundaries — denied/allowed actions,
denied resources, required justification thresholds, escalation targets — and
checks each proposed action against them.

### Action Authorization

Every agent action flows through `ActionAuthorizer`:
1. Agent status check (must be operational)
2. Budget check (actions taken vs max allowed)
3. Autonomy envelope check (risk, boundaries, escalation)

### Reasoning Chains

Auditable chains of reasoning steps (`Observation` → `Analysis` → `Planning` →
`Decision` → `Execution` → `Reflection` → `Revision`) with per-step confidence
scores. Chain confidence is the minimum of all step confidences.

### Tool Permissions

Tools are registered with `ToolRegistry` and checked against agent-specific
allow/deny lists. Tools may require explicit approval before invocation.

### Checkpoints

Human-in-the-loop checkpoints trigger on configurable conditions:
- Risk threshold exceeded
- Specific action types
- Resource access
- Budget thresholds
- Confidence below minimum
- Every N actions
- Always (for critical paths)

Checkpoints have priority ordering (`Low` < `Normal` < `High` < `Critical`)
and configurable defaults (`Deny`, `Allow`, `Escalate`) for timeout scenarios.

### Delegation

When one agent delegates to another, governance constraints flow:
- Maximum autonomy level
- Allowed/denied actions and tools
- Checkpoint requirements
- Trust inheritance
- Sub-delegation limits
- Reporting requirements

Delegation depth is tracked with cycle detection.

### Multi-Agent Coordination

`CoordinationGovernor` enforces communication policies between agents:
- Denied/allowed communication pairs (bidirectional)
- Message routing and filtering
- `CollectiveDecision` with voting (abstain does not count toward majority)

## Dependencies

- `rune-lang` — Core language types (no default features)
- `rune-security` — `SecuritySeverity` for audit events
- `serde` / `serde_json` — Serialization

Cross-crate integration uses string-based context maps (`HashMap<String, String>`).

## Tests

106 unit tests covering all modules. Run with:

```sh
cargo test -p rune-agents
```
