# Build Log 11

> Previous file: [BUILD_LOG_10.md](BUILD_LOG_10.md)

## 2026-04-12 — rune-audit-ext Layer 1: Unified Audit Store, Cross-Crate Correlation, Query Engine, Export, Retention, Chain Integrity

### What was built

New workspace crate `packages/rune-audit-ext/` providing unified audit aggregation across all RUNE crates. Normalizes per-crate audit events into 14-field `UnifiedEvent` records with a common schema. String-based ingestion helpers (10 free functions) allow callers to create events without depending on every source crate. Cross-crate correlation discovers event chains by correlation_id grouping and parent_event_id causal walks. Composable query engine supports And/Or/Not combinators with 12 leaf filters and 4 sort modes. Four export formats (JSON Lines, CEF for SIEM, CSV, Summary) with CEF severity mapping. Retention enforcement applies time-based policies with scope filtering, Critical+ event preservation, and preview-before-apply. SHA3-256 hash chains provide tamper-evident integrity verification. Timeline construction builds event sequences from store, correlation, or subject, with histogram bucketing.

### Four-pillar alignment

- **Security Baked In**: SHA3-256 hash chains create tamper-evident audit trails; every event has severity, category, and outcome fields; ingestion rejects duplicates; chain verification detects insertions, deletions, and modifications.
- **Assumed Breach**: Cross-crate correlation discovers attack paths spanning multiple subsystems; find_gaps detects suspicious timeline discontinuities; retention policies preserve Critical+ events permanently regardless of age; CEF export enables SIEM integration for real-time monitoring.
- **Zero Trust Throughout**: No event is trusted in isolation — correlation links events across crate boundaries; query combinators (And/Or/Not) enable arbitrary investigation filters; every store mutation validates preconditions; retention previews show impact before applying.
- **No Single Points of Failure**: 10 independent ingestion helpers normalize events from any source crate; 4 export formats ensure data is accessible from any tool; 3 built-in retention policies cover common regulatory requirements; timeline construction works from store, correlation, or subject.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Add rune-audit-ext to workspace members | +1 line |
| packages/rune-audit-ext/Cargo.toml | Crate manifest: rune-lang, rune-security, serde, serde_json, sha3, hex | New |
| packages/rune-audit-ext/src/lib.rs | Module declarations + re-exports | New |
| packages/rune-audit-ext/src/error.rs | AuditExtError — 9 variants | New |
| packages/rune-audit-ext/src/event.rs | UnifiedEventId, UnifiedEvent (14 fields), SourceCrate (14), EventCategory (14), EventOutcome (7), UnifiedEventBuilder | New |
| packages/rune-audit-ext/src/store.rs | AuditStore (ingest/get/latest/events_since/between/by_source/category/severity/actor/subject/correlation, distributions, events_per_second, remove_where with Critical+ guard), 10 ingestion helpers | New |
| packages/rune-audit-ext/src/correlation.rs | CorrelationChain, CorrelationEngine (correlate, find_causal_chain, find_children, active_correlations, cross_crate_chains, correlate_by_time_window, correlate_by_subject) | New |
| packages/rune-audit-ext/src/query.rs | AuditQuery, QueryFilter (And/Or/Not + 12 leaves), QuerySort (4 modes), QueryResult (pagination), QueryEngine (execute, count) | New |
| packages/rune-audit-ext/src/export.rs | ExportFormat (4 variants), AuditExporter (json_lines, cef, csv, summary), CEF severity mapping | New |
| packages/rune-audit-ext/src/retention.rs | AuditRetentionPolicy, RetentionScope (4 variants), RetentionAction (3 variants), RetentionManager (apply, preview), 3 built-in policies, Critical+ preservation | New |
| packages/rune-audit-ext/src/integrity.rs | compute_event_hash (SHA3-256), verify_chain, verify_range, find_gaps, chain_health, ChainStatus, ChainHealth | New |
| packages/rune-audit-ext/src/timeline.rs | Timeline, TimelineEntry, TimelineBuilder (from_store, from_correlation, from_subject), bucketize | New |
| packages/rune-audit-ext/src/audit.rs | AuditExtEventType (8 variants), AuditExtAuditEvent, AuditExtLog | New |
| packages/rune-audit-ext/README.md | Crate documentation | New |
| docs/dev/PROGRESS_02.md | Continued progress tracking | New |
| docs/dev/BUILD_LOG_11.md | This build log | New |

### Test summary

87 tests, 0 failures:

| Module | Tests | What's covered |
|--------|-------|----------------|
| error | 1 | Display for all 9 variants |
| event | 9 | UnifiedEventId display/equality, SourceCrate 14 variants display, EventCategory 14 variants, EventOutcome 7 variants, builder defaults, builder full, source crate Hash |
| store | 14 | Ingest/get, duplicate rejection, store full, latest, events_since, events_between, events_by_source, events_by_actor, distribution, events_per_second, ingest_batch, remove_where preserves Critical+, 10 ingestion helpers, chain enabled |
| correlation | 10 | Correlate groups by id, chain span, cross-crate detection, find_causal_chain, find_children, active_correlations, cross_crate_chains, correlate_by_time_window, correlate_by_subject, causal chain from root |
| query | 12 | No filters, by source, severity_at_least, And combinator, Or combinator, Not combinator, sort severity desc, pagination, count, detail contains, has_correlation, has_tag |
| export | 9 | JSON Lines, CEF format, CSV format, summary, dispatch, CEF severity mapping, format display, empty summary, csv_escape |
| retention | 8 | Apply deletes old non-critical, Critical+ never deleted, preview non-modifying, scope source filter, scope severity_below, built-in policies, retention action variants, multiple policies |
| integrity | 10 | Hash deterministic, hash changes with previous, hash changes with different events, verify chain empty/single/valid, verify range, find gaps, chain health valid/empty |
| timeline | 9 | From store, from correlation, from subject, empty timeline, entry summary, bucketize, single bucket, empty bucketize, entry empty detail |
| audit | 5 | Record/retrieve, events_by_type, since filter, all 8 event type displays, retention/correlation events |

### Decisions

- **String-based ingestion (no cross-crate type dependencies)**: The 10 ingestion helper functions accept strings and SecuritySeverity, not types from rune-identity, rune-detection, etc. This keeps the dependency graph minimal — rune-audit-ext depends only on rune-lang and rune-security. Callers translate their domain events to strings before ingestion.
- **Critical+ events are never deleted**: AuditStore.remove_where() hard-codes a check that Critical and Emergency severity events survive any removal operation. This is a non-negotiable safety invariant — no retention policy, no manual cleanup, nothing can delete a Critical+ event. The check lives in the store, not in the retention manager, so it cannot be bypassed.
- **QueryFilter uses recursive And/Or/Not**: Rather than a flat filter list, QueryFilter supports arbitrarily nested combinators. This makes the query language expressive enough for forensic investigations (e.g., "events from rune-security OR rune-detection, AND severity >= High, NOT actor = system"). The tradeoff is recursive evaluation, but audit queries are never performance-critical compared to ingestion.
- **CEF severity mapping uses 1-10 scale**: The mapping (Info=1, Low=3, Medium=5, High=7, Critical=9, Emergency=10) follows the CEF specification's 0-10 range. The values are chosen to align with common SIEM severity thresholds.
- **Chain verification recomputes from scratch**: verify_chain() recomputes all hashes from the first event rather than storing hashes alongside events. This is intentional — stored hashes could themselves be tampered with. Recomputation is the only way to truly verify integrity.
- **Retention preview is read-only**: RetentionManager.preview() counts events that would be affected without modifying the store. This follows the zero-trust principle — operators should see the impact before committing to destructive actions.

## 2026-04-12 — rune-policy-ext Layer 1: Policy Versioning, Composition, Conflict Detection, Simulation, Lifecycle Management

### What was built

New workspace crate `packages/rune-policy-ext/` extending rune-security's `SecurityPolicy`/`SecurityRule` evaluation engine into a full policy management system. ManagedPolicy adds versioning (semver), ownership, lifecycle metadata, framework bindings, and review intervals. PolicyVersionHistory tracks snapshots with diff and rollback. PolicyComposer evaluates composed policy sets using four strategies (MostRestrictive, LeastRestrictive, PriorityBased, FirstMatch) with RuleExpression evaluation (13 expression types including And/Or/Not). ConflictDetector finds contradictions between policies using conservative condition-overlap heuristics. PolicySimulator predicts change impact by evaluating test cases against current and proposed policies. LifecycleManager enforces a state machine (Draft→UnderReview→Approved→Active→Suspended→Deprecated→Retired) with transition validation. Import/export supports JSON roundtrip, YAML-like, and summary formats. FrameworkBindingRegistry maps policies to regulatory requirements (GDPR, NIST AI RMF, CMMC, etc.) with coverage tracking and gap detection.

### Four-pillar alignment

- **Security Baked In**: Policy versioning creates immutable history; lifecycle state machine enforces review/approval gates; conflict detection prevents contradictory policies from coexisting.
- **Assumed Breach**: Simulation quantifies impact before deployment; rollback enables instant revert; framework bindings track compliance gaps explicitly.
- **Zero Trust Throughout**: Every transition requires explicit actor ID; approval tracked with identity and timestamp; composition resolves conflicts deterministically; conflict detector surfaces contradictions.
- **No Single Points of Failure**: Four composition strategies; four export formats; binding registry maps to multiple frameworks; lifecycle supports human-driven and automated transitions.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Add rune-policy-ext to workspace members | +1 line |
| packages/rune-policy-ext/Cargo.toml | Crate manifest: rune-lang, rune-security, serde, serde_json | New |
| packages/rune-policy-ext/src/lib.rs | Module declarations + re-exports | New |
| packages/rune-policy-ext/src/error.rs | PolicyExtError — 11 variants | New |
| packages/rune-policy-ext/src/policy.rs | ManagedPolicyId, ManagedPolicy (18 fields), PolicyDomain (11), PolicyVersion (semver), PolicyStatus (7), PolicyRule, RuleExpression (13), PolicyAction (12), ManagedPolicyStore | New |
| packages/rune-policy-ext/src/version.rs | PolicySnapshot, PolicyDiff, PolicyChange, ChangeType (8), PolicyVersionHistory, VersionStore | New |
| packages/rune-policy-ext/src/composition.rs | ComposedPolicySet, CompositionStrategy (4), ComposedEvaluation, MatchedRule, PolicyComposer, evaluate_rule_expression | New |
| packages/rune-policy-ext/src/conflict.rs | PolicyConflict, ConflictType (5), ConflictSeverity (4), ConflictResolution, ResolutionType (5), ConflictDetector | New |
| packages/rune-policy-ext/src/simulation.rs | SimulationRun, SimulationTestCase, SimulationResult, SimulationImpact, SimulationRisk (3), PolicySimulator | New |
| packages/rune-policy-ext/src/lifecycle.rs | LifecycleTransition, LifecycleManager with enforced state machine | New |
| packages/rune-policy-ext/src/import_export.rs | PolicyFormat (4), PolicyExporter (json/yaml/summary), PolicyImporter (json/batch) | New |
| packages/rune-policy-ext/src/binding.rs | FrameworkBinding, BindingCoverage (4), FrameworkBindingRegistry, FrameworkCoverageSummary | New |
| packages/rune-policy-ext/src/audit.rs | PolicyExtEventType (11 variants), PolicyExtAuditEvent, PolicyExtAuditLog | New |
| packages/rune-policy-ext/README.md | Crate documentation | New |

### Test summary

93 tests, 0 failures:

| Module | Tests | What's covered |
|--------|-------|----------------|
| error | 1 | Display for all 11 variants |
| policy | 13 | ManagedPolicyId display, construction, PolicyDomain display (11 variants), PolicyVersion display/ordering/bumps, PolicyStatus predicates, PolicyAction display, store add/get/duplicate/by_domain/by_status/active/search/policies_due_review/remove |
| version | 13 | Record snapshot, latest, at_version, diff name change, diff rule additions/removals, diff status change, rollback_to, all_versions, changes_since, VersionStore record/diff/rollback |
| composition | 10 | Compose creates set, MostRestrictive/LeastRestrictive/PriorityBased/FirstMatch evaluation, conflict reporting, merge_rules, evaluate_rule_expression Equals/And/missing field |
| conflict | 11 | Direct contradiction, redundant rules, detect_in_set, no conflicts, resolve, unresolved, by_severity, conflicts_for_policy, ConflictType display, ConflictSeverity ordering, ResolutionType display |
| simulation | 10 | Identical policies 0 changes, different policies, newly denied/permitted, risk Safe/High, impact_summary, generate_test_cases, result changed flag, empty test cases |
| lifecycle | 13 | Draft→UnderReview, UnderReview→Approved, Approved→Active, Active→Suspended/Deprecated, Deprecated→Retired, Retired terminal, Draft→Active fails, Active→Draft fails, valid_transitions, history, transition_with_approval, policies_needing_review |
| import_export | 8 | export_json valid, JSON roundtrip, export_yaml_like, export_summary, import_json, import_json invalid, import_batch_json, PolicyFormat display |
| binding | 8 | bind/bindings_for, policies_for_framework, policies_for_requirement, coverage_summary, gaps, unbound_policies, BindingCoverage display, FrameworkCoverageSummary display |
| audit | 6 | Record/retrieve, events_for_policy, conflict_events, lifecycle_events, simulation_events, all 11 event type displays |

### Decisions

- **Own RuleExpression instead of reusing rune-security's RuleCondition**: rune-security's RuleCondition evaluates against `SecurityContext` (with typed `risk_level`, `clearance`, `active_threats`). rune-policy-ext needs string-keyed evaluation for cross-framework compatibility — policies from different domains use arbitrary field names, not a fixed security context. RuleExpression evaluates against `HashMap<String, String>`, making it framework-agnostic.
- **Conservative condition-overlap heuristic for conflict detection**: Exact condition overlap is undecidable for arbitrary expression trees. Layer 1 uses a simple heuristic: Always overlaps with everything, same-field Equals overlap if same value, And/Or trees overlap if they share field names. False negatives are acceptable (missing some subtle conflicts) — Layer 2 can use SMT for full analysis.
- **Lifecycle state machine is enforced, not advisory**: `transition()` returns `Err(InvalidTransition)` for invalid paths. You cannot skip from Draft to Active. This is deliberate — the governance model requires human review gates. The machine is intentionally restrictive: Retired is terminal with no exit.
- **Simulation uses highest-priority-wins within a single policy**: When evaluating a policy against a test case, if multiple rules match, the highest priority rule's action is used. This mirrors how PriorityBased composition works and gives deterministic results.
- **Import/export uses serde for JSON roundtrip**: ManagedPolicy and all nested types derive Serialize/Deserialize. The JSON format is the canonical interchange format. YAML-like export is simplified (not a full YAML parser) for human readability.
- **FrameworkBinding uses string framework names**: Rather than an enum of known frameworks, binding uses `String` for framework names. This allows binding to any regulatory framework including organization-specific ones, without requiring code changes for each new framework.

## 2026-04-12 — rune-framework Layer 1: Governance Pipeline Orchestration, Component Registry, Workflow Templates, Health Aggregation

### What was built

New workspace crate `packages/rune-framework/` providing governance pipeline orchestration for end-to-end request evaluation. GovernanceRequest carries subject/resource/context; GovernancePipeline executes stages in order with fail-closed/fail-open/escalate/abort semantics. Five built-in stage evaluators (identity, policy, shield, trust, compliance) use string-based context flags via GovernanceContext rather than importing every crate. ComponentRegistry tracks crate availability with heartbeat-based staleness detection. FrameworkConfig provides environment presets (production/development/air_gapped/testing) with validation. FrameworkHealthAssessor aggregates component and pipeline health. Five WorkflowTemplates (inference_protection, data_access, model_deployment, admin_action, minimal) build pipelines from template definitions using a StageEvaluatorRegistry.

### Four-pillar alignment

- **Security Baked In**: Pipeline is fail-closed by default; production config enforces identity verification, audit logging, and strict risk thresholds; configuration validation warns on deviations from secure defaults.
- **Assumed Breach**: Shield stage checks active threats; trust stage enforces minimum scores; risk accumulates across stages triggering ConditionalPermit; component registry detects stale heartbeats; health assessor surfaces degraded/unhealthy status.
- **Zero Trust Throughout**: Every request carries subject identity, resource classification, and action context; identity stage verifies subject before other checks; pipeline stages execute in strict order; governance outcomes map to explicit decision codes.
- **No Single Points of Failure**: Component registry tracks multiple instances per type; five workflow templates cover different scenarios; four environment presets with validation; extensible StageFn function pointer mechanism.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Add rune-framework to workspace members | +1 member |
| packages/rune-framework/Cargo.toml | Crate manifest: rune-lang, rune-security, rune-audit-ext, serde, serde_json | New |
| packages/rune-framework/src/lib.rs | Module declarations + re-exports | New |
| packages/rune-framework/src/error.rs | FrameworkError — 11 variants | New |
| packages/rune-framework/src/request.rs | GovernanceRequestId, GovernanceRequest (SubjectInfo/ResourceInfo/RequestContext), GovernanceDecisionResult, GovernanceOutcome (6 variants), StageResult, StageOutcome (5 variants) | New |
| packages/rune-framework/src/stage.rs | StageType (8 variants), StageDefinition, FailAction (4 variants), StageFn function pointer, 5 built-in evaluators (identity/policy/shield/trust/compliance) | New |
| packages/rune-framework/src/context.rs | GovernanceContext with mutable state: flags, risk_score, trust_score, policy_decision, shield_verdict, warnings, threat_indicators, explanation_fragments, stage_log, to_flat_map | New |
| packages/rune-framework/src/pipeline.rs | GovernancePipeline with PipelineStageEntry, evaluate()/dry_run(), stage ordering, fail-closed semantics, risk_threshold ConditionalPermit | New |
| packages/rune-framework/src/registry.rs | ComponentId, ComponentInfo, ComponentType (10 variants), ComponentStatus (4 variants), ComponentRegistry (register/deregister/heartbeat/update_status/by_type/available/stale/system_readiness), SystemReadiness | New |
| packages/rune-framework/src/config.rs | FrameworkConfig with Environment (5 variants), 4 presets (production/development/air_gapped/testing), validate(), ConfigValidation, ConfigSeverity | New |
| packages/rune-framework/src/health.rs | FrameworkHealth, FrameworkHealthStatus (4 variants), ComponentHealthEntry, PipelineHealth, PipelineStats, FrameworkHealthAssessor | New |
| packages/rune-framework/src/workflow.rs | WorkflowTemplate, WorkflowStage, 5 built-in templates, build_pipeline_from_template, default_evaluator_registry, StageEvaluatorRegistry | New |
| packages/rune-framework/src/audit.rs | FrameworkEventType (10 variants), FrameworkAuditEvent, FrameworkAuditLog | New |
| packages/rune-framework/README.md | Crate documentation | New |

### Test summary

105 tests, 0 failures:

| Module | Tests | What's covered |
|--------|-------|----------------|
| error | 1 | Display for all 11 variants |
| request | 13 | GovernanceRequestId display, request construction, GovernanceOutcome 6 variants (permit/deny/conditional/escalate/audit/NA) with predicates/decision codes, StageOutcome blocking, StageResult builders (pass/fail/severity/detail/duration), GovernanceDecisionResult methods (stage_count/failed_stages/all_passed), RequestContext metadata |
| stage | 15 | StageType 8 variants display, FailAction 4 variants display, StageDefinition builder, identity_stage pass/fail, policy_stage deny/risk/pass, shield_stage clear/threat, trust_stage default/low, compliance_stage no-req/present/missing |
| context | 11 | Defaults, flag ops (set/get/has/count), warnings+threats, increase_risk capped at 1.0, record_stage/failure detection, build_explanation (fragments/stage_log/empty), to_flat_map, Default trait |
| pipeline | 12 | Empty pipeline error, single stage pass, multi-stage all pass, fail-closed blocks, fail-open continues, escalate action, disabled skipped, dry-run no short-circuit, stage ordering, risk threshold ConditionalPermit, pipeline metadata, overall severity tracking |
| registry | 15 | ComponentId display, ComponentType 10 variants, ComponentStatus 4 variants, register/get/duplicate/deregister, heartbeat, update_status, by_type, available_components, stale_components, system_readiness (ready/not-ready/empty), display, metadata |
| config | 11 | Environment 5 variants display, 4 presets (production/development/air_gapped/testing), validate bad risk/trust/timeout, production warnings, ConfigValidation display, ConfigSeverity ordering |
| health | 8 | HealthStatus 4 variants display, PipelineStats new/record/rates, assess healthy/degraded-stale/degraded-status/unhealthy/unknown, display |
| workflow | 11 | 5 templates (inference/data_access/model_deployment/admin/minimal), build_pipeline_from_template success/missing, build_and_evaluate, template display, template with config, default_evaluator_registry |
| audit | 6 | EventType 10 variants display, record/retrieve, events_by_type, events_since, pipeline_events, component_events |

### Decisions

- **StageFn function pointers instead of trait objects**: `StageFn = fn(&GovernanceRequest, &mut GovernanceContext, &HashMap<String, String>) -> StageResult`. Function pointers are simpler than trait objects (no dyn dispatch, no lifetime parameters, Copy), and the evaluators don't need mutable state. Each stage gets the request (immutable), the context (mutable accumulator), and its config (immutable). This keeps the pipeline zero-allocation beyond the context itself.
- **Minimal dependency graph (rune-lang, rune-security, rune-audit-ext only)**: The framework does NOT depend on rune-identity, rune-detection, rune-shield, etc. Built-in stage evaluators use string-based context flags ("identity_verified", "threat_active", "trust_score") rather than actual crate types. Callers wire up their own evaluators that import the crates they need.
- **Fail-closed is the default, fail-open requires explicit opt-in**: `StageDefinition.fail_action` defaults to `Block`. You must explicitly set `FailAction::Continue` to make a stage fail-open. This matches the zero-trust principle — deny by default, permit only by explicit decision.
- **Dry-run does not short-circuit**: `dry_run()` executes ALL stages even after failures. This provides complete diagnostic information for what-if analysis without affecting the actual decision. The result is marked `dry_run: true` so callers know it's non-binding.
- **GovernanceOutcome maps to architecture spec decision codes**: `to_decision_code()` returns PERMIT/DENY/CONDITIONAL_PERMIT/ESCALATE/AUDIT/NOT_APPLICABLE. These align with the embedding API contract's PolicyDecision from Section 8 of the architecture spec.
- **Risk threshold triggers ConditionalPermit**: When all stages pass but `GovernanceContext.risk_score` exceeds `pipeline.risk_threshold`, the outcome is ConditionalPermit (not Permit). This implements the graduated response model — high risk doesn't necessarily mean denial, but requires additional review.

## 2026-04-12 — rune-safety Layer 1: Safety Constraints, Safety Cases, Hazard Analysis, Fail-Safe Behaviors, Safety Integrity Levels

### What was built

New workspace crate `packages/rune-safety/` encoding safety properties for AI systems as typed, verifiable constructs. Safety integrity levels cover three standards: IEC 61508 SIL (0-4 with failure rate targets and test coverage requirements), DO-178C DAL (E-A with structural coverage and independence requirements), and ISO 26262 ASIL (QM through D). SafetyClassification combines all three with cross-standard formal verification detection. SafetyConstraint defines typed safety predicates (8 constraint types, 11 condition variants including And/Or/Not) evaluated against string-keyed contexts. SafetyCase provides GSN-inspired structured safety arguments with recursive goals, strategies, evidence, and completeness tracking. SafetyMonitorEngine watches for constraint violations with configurable consecutive-violation thresholds before triggering responses. FailsafeRegistry maps triggers to prioritized fail-safe behaviors with recovery procedures and test scheduling. HazardRegistry performs systematic hazard identification with a severity×likelihood risk matrix and mitigation tracking. SafetyBoundarySet defines operating envelopes with limit checking and approach detection. SafetyAssessor combines all signals into an overall SafetyLevel (Safe/ConditionalSafe/Degraded/Unsafe/Unknown) with recommendation generation.

### Four-pillar alignment

- **Security Baked In**: Safety constraints encode invariants, preconditions, and postconditions as typed predicates. Safety integrity levels mandate test coverage (90-99.9%), structural coverage, and independent verification based on criticality classification.
- **Assumed Breach**: Safety monitors watch for violations with consecutive-violation thresholds. Fail-safe behaviors define automatic responses (safe mode, rate limiting, graceful shutdown). Hazard analysis tracks mitigations and residual risk. Recovery procedures support auto-recovery and human-approval gates.
- **Zero Trust Throughout**: Safety assessor trusts no single signal — combines constraint evaluations, safety case completeness, hazard status, monitor state, and boundary checks. Critical constraint violations or boundary breaches immediately produce Unsafe status regardless of other signals.
- **No Single Points of Failure**: Multiple mitigation types per hazard (elimination through personal protection). Multiple fail-safe responses per trigger sorted by priority. Cross-standard classification (SIL + DAL + ASIL simultaneously). Safety boundaries with approach warnings before breach detection.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Add rune-safety to workspace members | +1 member |
| packages/rune-safety/Cargo.toml | Crate manifest: rune-lang (no default features), rune-security, serde, serde_json | New |
| packages/rune-safety/src/lib.rs | Module declarations + re-exports | New |
| packages/rune-safety/src/error.rs | SafetyError — 14 variants | New |
| packages/rune-safety/src/integrity.rs | SafetyIntegrityLevel (SIL 0-4), DesignAssuranceLevel (DAL E-A), AutomotiveSafetyLevel (QM/ASIL A-D), SafetyClassification | New |
| packages/rune-safety/src/constraint.rs | ConstraintId, SafetyConstraint (12 fields), ConstraintType (8 variants), SafetyCondition (11 variants), ConstraintSeverity (5 levels), evaluate_safety_condition, ConstraintEvaluation, ConstraintStore | New |
| packages/rune-safety/src/safety_case.rs | SafetyCaseId, SafetyCase, SafetyGoal (recursive), SafetyStrategy, SafetyEvidence, EvidenceType (7), EvidenceStrength (4), GoalStatus (5), SafetyCaseStatus (5), SafetyCaseStore | New |
| packages/rune-safety/src/monitor.rs | SafetyMonitorId, SafetyMonitor, MonitorResponse (6 variants), MonitorStatus (4 variants), MonitorCheckResult, SafetyMonitorEngine | New |
| packages/rune-safety/src/failsafe.rs | FailsafeId, FailsafeBehavior, FailsafeTrigger (7 variants), FailsafeAction (8 variants), RecoveryProcedure, FailsafeRegistry | New |
| packages/rune-safety/src/hazard.rs | HazardId, Hazard, HazardType (8 variants), HazardLikelihood (6 levels), RiskLevel (4 levels with risk matrix), HazardMitigation, MitigationType (7), MitigationEffectiveness (4), HazardStatus (5), HazardRegistry | New |
| packages/rune-safety/src/boundary.rs | SafetyBoundary, BoundaryType (5 variants), OperatingLimit, BoundaryStatus (4 variants), BoundaryCheckResult, SafetyBoundarySet | New |
| packages/rune-safety/src/assessment.rs | SafetyAssessment, SafetyLevel (5 variants), HazardSummary, MonitorSummary, SafetyAssessor | New |
| packages/rune-safety/src/audit.rs | SafetyEventType (11 variants), SafetyAuditEvent, SafetyAuditLog | New |
| packages/rune-safety/README.md | Crate documentation | New |

### Test summary

106 tests, 0 failures:

| Module | Tests | What's covered |
|--------|-------|----------------|
| error | 1 | Display for all 14 variants |
| integrity | 11 | SIL ordering, failure_rate_target, requires_independent_verification, min_test_coverage, DAL ordering, structural_coverage_required, independence_required, ASIL ordering, SafetyClassification with_sil/with_dal, requires_formal_verification (SIL4/DalA/AsilD), highest_level_name |
| constraint | 17 | Construction, ConstraintType 8 variants display, ConstraintSeverity ordering, evaluate ValueInRange satisfied/violated, ValueAbove/Below, ValueEquals, FieldPresent/Absent, LatencyBelow, And/Or/Not combinators, ConstraintStore add/get/evaluate_all/violated/by_type/by_severity+integrity/verified+unverified |
| safety_case | 11 | Construction with goals, nested goal structure, store add/get, completeness mixed/all-supported, unsupported_goals, evidence_count recursive, GoalStatus 5 display, SafetyCaseStatus 5 display, EvidenceType 7 display, EvidenceStrength ordering |
| monitor | 12 | Register/get, check satisfied/violated, consecutive violations trigger response, satisfaction resets count, check_all, triggered/active monitors, reset, MonitorResponse 6 display, MonitorStatus 4 display, max_consecutive_before_action |
| failsafe | 11 | Register/get, trigger sorted by priority, ConstraintViolation/MonitorTriggered match, no match empty, untested, overdue_testing, by_priority, FailsafeTrigger 7 display, FailsafeAction 8 display, RecoveryProcedure construction |
| hazard | 14 | Register/get, by_type/risk_level/status, intolerable_hazards, unmitigated_hazards, risk_matrix, from_severity_likelihood (6 combinations), HazardType 8 display, HazardLikelihood ordering, RiskLevel ordering, MitigationType 7 display, MitigationEffectiveness ordering, HazardStatus 5 display |
| boundary | 9 | Add/get, check_all within_limits/approaching/breached, breached/approaching filters, OperatingLimit is_within, BoundaryType 5 display, BoundaryStatus 4 display |
| assessment | 10 | All safe→Safe, critical violation→Unsafe, triggered monitor→Degraded, breached boundary→Unsafe, intolerable unmitigated→Unsafe, low completeness→ConditionalSafe, generates recommendations, SafetyLevel 5 display, HazardSummary/MonitorSummary construction |
| audit | 8 | Record/retrieve, events_by_severity, constraint/monitor/hazard/boundary_events filters, critical_events (severity≥Critical), SafetyEventType 11 display, since filter |

### Decisions

- **Safety is not security**: This crate intentionally separates safety concerns from security concerns. rune-security handles adversarial threats; rune-safety handles accidental failures, unintended consequences, and operating envelope violations. The two are complementary — a system needs both. Safety constraints use ConstraintSeverity (Advisory→Catastrophic), not SecuritySeverity (Info→Emergency), because the severity scales represent different risk domains.
- **Three-standard safety integrity classification**: Rather than picking one standard, SafetyClassification supports IEC 61508 SIL (industrial), DO-178C DAL (avionics), and ISO 26262 ASIL (automotive) simultaneously. A defense system might be SIL 3 + DAL B; an autonomous vehicle might be ASIL D + SIL 4. The `requires_formal_verification()` method checks all three standards to determine if formal methods are mandatory.
- **Consecutive-violation threshold for monitors**: SafetyMonitor.max_consecutive_before_action prevents spurious single-sample violations from triggering responses. This is critical for noisy real-world environments where sensors occasionally produce bad readings. The default is 1 (immediate response), but safety engineers can increase it for specific monitors.
- **Fail-safe registry matches on trigger equality, not type**: `FailsafeRegistry.trigger()` compares the full FailsafeTrigger value (including constraint_id/monitor_id), not just the variant type. A fail-safe registered for ConstraintViolation("c1") will not fire for ConstraintViolation("c2"). This is intentional — different constraints may require different fail-safe responses.
- **Risk matrix uses severity × likelihood with threshold rules**: RiskLevel::from_severity_likelihood uses simple threshold rules rather than a full matrix lookup table. Critical+Occasional or worse = Intolerable. This is conservative — edge cases default to higher risk levels. Layer 2 can add configurable risk matrices for organization-specific risk appetite.
- **SafetyAssessor skips completeness check when no safety case is specified**: When `safety_case_id` is None, the assessor does not penalize for missing safety case completeness. This allows systems without formal safety cases to still be assessed. When a safety case ID is provided but completeness is below 50%, the system is ConditionalSafe.

---

## rune-web Layer 1

**Date**: 2026-04-13
**Commit**: (pending)
**Tests**: 107 passed, 0 failed

### What was built

API gateway protection, HTTP request/response governance, endpoint classification, request signing, web threat mitigation, and session governance. This crate governs the HTTP boundary — the web-specific counterpart to rune-shield's inference boundary.

### Module inventory

| Module | Key types | Tests |
|--------|-----------|-------|
| error | WebError (13 variants) | 1 |
| endpoint | EndpointId, Endpoint (14 fields), HttpMethod (7 variants), EndpointClassification (6 levels: Public→Critical with Ord), RateLimitConfig (3 presets), EndpointRegistry (match_path with pattern matching) | 13 |
| request | WebRequest (10 fields), RequestValidation, RequestValidator (9 checks: path length/traversal/blocked/header count+size/required headers/query params/body size/content-type, with_defaults per classification), sanitize_path, is_path_traversal | 13 |
| response | WebResponse, ResponsePolicy (strict preset), ResponseGovernor (security header injection, server stripping, data leakage scanning), DataLeakageType (5 variants), DataLeakageFind, ResponseGovernanceResult | 13 |
| gateway | GatewayConfig, RateLimiter (token bucket algorithm), ApiGateway (process_request/process_response/stats), GatewayOutcome (7 variants: Allow/Deny/RateLimited/AuthRequired/MfaRequired/EndpointNotFound/MethodNotAllowed), GatewayDecision, GatewayStats | 14 |
| signing | SigningAlgorithm (HmacSha3_256/HmacSha256), SigningConfig, RequestSigner (canonical string construction, HMAC signing, constant-time verification, clock skew protection), SignedRequest, SignatureVerification | 9 |
| threat | WebThreatType (8 variants: Csrf/Clickjacking/ContentInjection/OpenRedirect/HttpMethodOverride/HeaderInjection/HostHeaderAttack/SlowlorisAttack), WebThreatDetector (scan_request with 6 active checks), csrf_token_present, check_open_redirect | 10 |
| session | SameSitePolicy (3 variants), WebSessionConfig (9 fields), WebSession, WebSessionStore (create/validate/touch/authenticate with session regeneration/verify_mfa/invalidate/invalidate_all_for_identity/cleanup_expired/cookie_attributes), SessionValidation | 16 |
| cors | CorsPolicy (3 presets: permissive/strict/none), CorsChecker (check_preflight/check_simple/response_headers), CorsResult | 10 |
| audit | WebEventType (15 variants), WebAuditEvent, WebAuditLog (8 query methods) | 8 |

### Architecture alignment

- **HTTP boundary governance**: Every request passes through endpoint classification → auth check → MFA check → rate limiting → request validation → role check. Fail-closed by default (require_auth_by_default: true).
- **Response hardening**: Automatic security header injection (HSTS, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy), server fingerprint stripping, data leakage scanning (internal IPs, stack traces, file paths, credentials, debug info).
- **Token bucket rate limiting**: Configurable per-IP, per-identity, or global. Three presets (public: 60/min burst 10, authenticated: 300/min burst 30, internal: 1000/min burst 100). Tokens refill continuously.
- **Request signing**: Canonical string construction (method + path + sorted headers + body hash), HMAC-based signing, constant-time signature comparison, clock skew enforcement (default 5-minute window).
- **Session governance**: Secure defaults (HttpOnly, Secure, SameSite=Strict), session regeneration on authentication (prevents fixation), idle timeout (30 min default), max lifetime (24 hours), concurrent session limits per identity, bulk invalidation.
- **CORS enforcement**: Three policy presets (permissive/strict/none), preflight and simple request checking, credential+wildcard safety (credentials disabled when origin is "*").
- **Web threat detection**: CSRF token enforcement on state-changing methods, open redirect detection, HTTP method override blocking, CRLF header injection detection, Host header attack detection, content-type mismatch detection.

### Dependencies

- rune-lang (no default features) — core language types
- rune-security — SecuritySeverity for audit events and data leakage findings
- serde + serde_json — serialization

### Decisions

- **Web boundary vs inference boundary**: rune-web guards the HTTP boundary (API endpoints, browsers, external clients), rune-shield guards the AI model boundary (inference requests, prompt injection, model outputs). They are complementary — a typical deployment uses both. rune-web does not depend on rune-shield; integration happens through rune-framework's governance pipeline.
- **String-based cross-crate integration**: Like rune-framework, rune-web uses string-based context (HashMap<String, String>) rather than importing identity/shield/policy crate types directly. Roles come via X-Roles header, MFA status via X-MFA-Verified header. This keeps dependencies minimal and allows embedding in systems that don't use the full RUNE stack.
- **Simplified HMAC for Layer 1**: The signing module uses a deterministic hash function that captures the full API shape (canonical string construction, clock skew, constant-time comparison) without importing a full cryptographic HMAC implementation. Layer 2 will use SHA3-256 HMAC from a proper crypto crate. The API surface and security properties (determinism, key sensitivity, tamper detection) are fully tested.
- **EndpointClassification as ordered enum**: Public < Authenticated < Privileged < Internal < Sensitive < Critical. This allows `>=` comparisons for access control (e.g., sensitive_endpoints returns everything >= Sensitive). The ordering reflects increasing restriction, not importance.
- **Data leakage scanning is heuristic, not regex-heavy**: The response governor checks for common patterns (internal IP ranges, stack trace keywords, file system paths, secret keywords) rather than complex regex. This keeps Layer 1 simple and fast. Layer 2 can add configurable pattern sets and ML-based detection.
- **Session regeneration prevents fixation attacks**: When regenerate_on_auth is true (default), authenticating a session creates a new session ID and migrates all data. The old session ID becomes invalid. This is a critical defense against session fixation attacks where an attacker pre-sets a victim's session ID.

---

## rune-agents — Layer 1

**Date**: 2026-04-12
**Tests**: 106 passing
**Commit**: (pending)

### What it does

Agent governance for the RUNE ecosystem (GUNGNIR governance layer). Provides action authorization, autonomy boundaries, reasoning chain auditing, tool-use permissions, human-in-the-loop checkpoints, task delegation with governance inheritance, and multi-agent coordination governance.

### Modules (10)

| Module | Key types | Tests |
|---|---|---|
| `agent` | AgentId, Agent (16 fields), AgentType (6 variants), AgentStatus (5 variants), AgentRegistry | 12 |
| `autonomy` | AutonomyLevel (7 ordered levels None→Full), AutonomyBoundary (12 fields), AutonomyEnvelope, AutonomyOutcome (7 variants), TimeWindow | 11 |
| `action` | ActionId, ActionType (9 variants), ActionRisk (5 levels), ActionStatus (7 variants), AgentAction (15 fields), ActionAuthorizer | 12 |
| `reasoning` | ReasoningChainId, ReasoningChain (9 fields), ReasoningStep (11 fields), StepType (7 variants), ReasoningStore | 12 |
| `tool` | ToolId, ToolDefinition (11 fields), ToolInvocation (9 fields), ToolPermissionOutcome (5 variants), ToolRegistry | 11 |
| `checkpoint` | CheckpointId, Checkpoint, CheckpointTrigger (8 variants), CheckpointPriority (4 levels), CheckpointManager | 14 |
| `delegation` | DelegationId, Delegation (11 fields), DelegationConstraints (8 fields), DelegationManager (cycle detection) | 13 |
| `coordination` | CoordinationGovernor, CoordinationPolicy, AgentMessage, CollectiveDecision, VoteTally, tally_votes | 14 |
| `audit` | AgentEventType (18 variants), AgentAuditEvent (5 fields), AgentAuditLog (8 query methods) | 8 |
| `error` | AgentError (18 variants) | 1 |

### Architecture

- **Autonomy levels as ordered enum**: None(0) < Observe(1) < Suggest(2) < ActLowRisk(3) < ActMediumRisk(4) < ActHighRisk(5) < Full(6). Each level defines maximum risk an agent can authorize independently. AutonomyLevel implements Ord via numeric discriminant.
- **Three-stage action authorization**: (1) Agent status check (must be operational), (2) Budget check (actions_taken vs max_actions_per_session), (3) Autonomy envelope check with risk comparison, denied/allowed action lists, justification thresholds, and escalation.
- **Reasoning chain confidence**: Chain confidence = minimum of all step confidences. This is deliberately conservative — a single low-confidence step drags down the whole chain.
- **Checkpoint trigger matching**: CheckpointManager evaluates all registered checkpoints against an action, returns the highest-priority matching checkpoint. Trigger types: RiskThreshold, ActionType, ResourceAccess, BudgetThreshold, ConfidenceBelow, EveryNActions, Always, Custom.
- **Governance inheritance through delegation**: DelegationConstraints flow from delegator to delegate — max autonomy, allowed/denied actions, tool restrictions, checkpoint requirements, trust inheritance, sub-delegation limits, reporting. Delegation depth tracked with cycle detection via visited set.
- **Collective decision-making**: tally_votes counts approve/reject/abstain. Abstain does NOT count toward the majority denominator (votes_cast = approve + reject only). Majority = approve > votes_cast / 2.
- **Bidirectional communication governance**: CoordinationGovernor checks denied_pairs in both directions (a→b and b→a). If allowed_pairs is non-empty, only listed pairs can communicate.

### Dependencies

- rune-lang (no default features) — core types
- rune-security — SecuritySeverity for audit events
- serde + serde_json — serialization

### Decisions

- **AutonomyOutcome derives PartialEq but not Eq**: The ExceedsBudget variant contains f64 (budget limit), which does not implement Eq. This is intentional — f64 budget thresholds need PartialEq for testing but Eq is unsound for floating-point.
- **String-based cross-crate integration**: Like all Layer 1 crates, rune-agents uses string-based context rather than importing types from other crates. Agent domains, capabilities, and tool names are all String. Integration with rune-framework's governance pipeline uses HashMap<String, String>.
- **Delegation depth with cycle detection**: delegation_depth walks the delegator chain using a visited HashSet to prevent infinite loops if a delegation cycle exists. This is defensive — the manager shouldn't allow cycles, but the depth calculation is safe regardless.
- **CheckpointTrigger derives PartialEq but not Eq**: BudgetThreshold and ConfidenceBelow variants contain f64 values. Same rationale as AutonomyOutcome.
- **ActionType::ToolInvocation carries tool_name**: Unlike other ActionType variants that are unit variants, ToolInvocation includes the tool name for audit trail purposes. This allows the action authorizer to log which specific tool was requested without needing a separate lookup.
