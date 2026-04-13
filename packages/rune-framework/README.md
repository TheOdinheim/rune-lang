# rune-framework

Governance pipeline orchestration, component registry, workflow templates, and health aggregation for the RUNE governance ecosystem.

## Overview

`rune-framework` is the integration surface that ties the RUNE crate ecosystem together into end-to-end governance workflows. Rather than depending on every crate, it uses function pointers (`StageFn`) and string-based context flags to keep the dependency graph minimal — only `rune-lang`, `rune-security`, and `rune-audit-ext` are compile-time dependencies. Pipeline stages read and write a shared `GovernanceContext` as they execute, accumulating flags, risk scores, trust scores, threat indicators, and explanation fragments. The pipeline produces a `GovernanceDecisionResult` with a `GovernanceOutcome` that maps to the architecture spec's `PolicyDecision` via `to_decision_code()`.

## Modules

| Module | Purpose |
|--------|---------|
| `request` | GovernanceRequestId (newtype), GovernanceRequest with SubjectInfo/ResourceInfo/RequestContext, GovernanceDecisionResult, GovernanceOutcome (6 variants: Permit/Deny/ConditionalPermit/Escalate/Audit/NotApplicable with is_permitted/is_denied/requires_action/to_decision_code), StageResult, StageOutcome (5 variants) |
| `stage` | StageType (8 variants: Identity/Permission/Policy/Privacy/Shield/Trust/Detection/Compliance), StageDefinition, FailAction (4 variants: Block/Continue/Escalate/Abort), StageFn function pointer, 5 built-in stage evaluators (identity_stage/policy_stage/shield_stage/trust_stage/compliance_stage) |
| `context` | GovernanceContext with mutable state: flags (set/get/has), risk_score, trust_score, policy_decision, shield_verdict, warnings, threat_indicators, explanation_fragments, stage_log, has_blocking_failure/first_failure/build_explanation/to_flat_map |
| `pipeline` | GovernancePipeline with PipelineStageEntry, evaluate()/dry_run() with stage ordering/timeout/fail-closed semantics, risk_threshold for ConditionalPermit, stage_count/enabled_stages/stage_names |
| `registry` | ComponentId (newtype), ComponentInfo, ComponentType (10 variants), ComponentStatus (4 variants: Available/Degraded/Unavailable/Unknown), ComponentRegistry (register/deregister/heartbeat/update_status/by_type/available_components/stale_components/system_readiness), SystemReadiness |
| `config` | FrameworkConfig with Environment (5 variants), 4 presets (production/development/air_gapped/testing), validate() with ConfigValidation/ConfigSeverity |
| `health` | FrameworkHealth, FrameworkHealthStatus (4 variants), ComponentHealthEntry, PipelineHealth, PipelineStats (record_evaluation/success_rate/denial_rate/error_rate/avg_duration_ms), FrameworkHealthAssessor |
| `workflow` | WorkflowTemplate with WorkflowStage, 5 built-in templates (inference_protection/data_access/model_deployment/admin_action/minimal), build_pipeline_from_template, default_evaluator_registry, StageEvaluatorRegistry |
| `audit` | FrameworkEventType (10 variants), FrameworkAuditEvent, FrameworkAuditLog (events_by_type/events_since/pipeline_events/component_events) |
| `error` | FrameworkError with 11 typed variants |

## Four-pillar alignment

- **Security Baked In**: Pipeline is fail-closed by default — any stage failure blocks the request unless explicitly configured as fail-open. Production config enforces identity verification, audit logging, and strict risk thresholds. Configuration validation warns when production settings deviate from secure defaults.
- **Assumed Breach**: Shield stage checks for active threats; trust stage enforces minimum trust scores; risk scores accumulate across stages and trigger ConditionalPermit when thresholds are exceeded. Component registry tracks stale heartbeats to detect component failures. Health assessor surfaces unhealthy/degraded status.
- **Zero Trust Throughout**: Every request carries subject identity, resource classification, and action context. Identity stage verifies subject presence before any other checks. Pipeline stages execute in defined order — no stage can be bypassed. Governance outcome maps to explicit decision codes (PERMIT/DENY/ESCALATE).
- **No Single Points of Failure**: Component registry tracks multiple instances per type; system readiness requires all components available. Five workflow templates cover different governance scenarios. Four environment presets (production/development/air_gapped/testing) with validation. Five built-in stage evaluators with extensible StageFn function pointer mechanism.

## Test summary

105 tests covering all modules:

| Module | Tests |
|--------|-------|
| error | 1 |
| request | 13 |
| stage | 15 |
| context | 11 |
| pipeline | 12 |
| registry | 15 |
| config | 11 |
| health | 8 |
| workflow | 11 |
| audit | 6 |
