# rune-policy-ext

Policy versioning, composition, conflict detection, simulation, import/export, and lifecycle management for the RUNE governance ecosystem.

## Overview

`rune-policy-ext` extends rune-security's basic `SecurityPolicy`/`SecurityRule` evaluation engine into a full policy management system. Where rune-security provides the *what* (composable conditions and rule evaluation), rune-policy-ext adds the *around*: versioning policies so you can diff and rollback, composing policies from multiple frameworks into unified policy sets, detecting conflicts between policies that contradict each other, simulating policy changes to predict impact before deployment, importing/exporting policies for regulatory mapping, and managing the full policy lifecycle from draft through retirement.

## Modules

| Module | Purpose |
|--------|---------|
| `policy` | ManagedPolicyId (newtype), ManagedPolicy (18 fields), PolicyDomain (11 variants), PolicyVersion (semver with bumps), PolicyStatus (7 variants with is_enforceable/is_editable/is_terminal), PolicyRule with RuleExpression (13 variants including And/Or/Not), PolicyAction (12 variants), ManagedPolicyStore |
| `version` | PolicySnapshot, PolicyDiff, PolicyChange, ChangeType (8 variants), PolicyVersionHistory (record_snapshot/diff/rollback_to/changes_since), VersionStore |
| `composition` | ComposedPolicySet, CompositionStrategy (4: MostRestrictive/LeastRestrictive/PriorityBased/FirstMatch), ComposedEvaluation, MatchedRule, PolicyComposer (compose/evaluate/merge_rules), evaluate_rule_expression |
| `conflict` | PolicyConflict, ConflictType (5 variants), ConflictSeverity (4 levels), ConflictResolution, ResolutionType (5 variants), ConflictDetector (detect/detect_in_set/resolve/unresolved/by_severity/conflicts_for_policy) with conservative overlap heuristic |
| `simulation` | SimulationRun, SimulationTestCase, SimulationResult, SimulationImpact, SimulationRisk (Safe/Moderate/High), PolicySimulator (simulate/generate_test_cases/impact_summary) |
| `lifecycle` | LifecycleTransition, LifecycleManager (transition/transition_with_approval/valid_transitions/history/policies_needing_review/time_in_status) with enforced state machine: Draft→UnderReview→Approved→Active→Deprecated→Retired |
| `import_export` | PolicyFormat (Json/Yaml/Rego/Summary), PolicyExporter (export_json/export_yaml_like/export_summary), PolicyImporter (import_json/import_batch_json) |
| `binding` | FrameworkBinding, BindingCoverage (Full/Partial/Planned/NotApplicable), FrameworkBindingRegistry (bind/bindings_for/policies_for_framework/policies_for_requirement/coverage_summary/unbound_policies/gaps), FrameworkCoverageSummary |
| `audit` | PolicyExtEventType (11 variants), PolicyExtAuditEvent, PolicyExtAuditLog (events_for_policy/conflict_events/lifecycle_events/simulation_events) |
| `error` | PolicyExtError with 11 typed variants |

## Four-pillar alignment

- **Security Baked In**: Policy versioning creates an immutable history of every policy change; the lifecycle state machine enforces that policies cannot go from Draft directly to Active — they must pass through review and approval; conflict detection prevents contradictory policies from coexisting silently.
- **Assumed Breach**: Simulation quantifies the impact of policy changes before deployment, catching regressions before they reach production; rollback enables instant revert to any prior policy version when a new policy causes problems; framework bindings track compliance gaps explicitly rather than assuming coverage.
- **Zero Trust Throughout**: Every policy transition requires explicit actor identification; approval is a first-class concept tracked with approver identity and timestamp; composition strategies resolve conflicts deterministically rather than silently dropping rules; the conflict detector surfaces contradictions that would otherwise cause unpredictable enforcement.
- **No Single Points of Failure**: Four composition strategies (MostRestrictive, LeastRestrictive, PriorityBased, FirstMatch) ensure policies can be combined regardless of organizational structure; four export formats maintain policy portability; the binding registry maps policies to multiple compliance frameworks simultaneously; lifecycle management supports both human-driven and automated transitions.

## Test summary

93 tests covering all modules:

| Module | Tests |
|--------|-------|
| error | 1 |
| policy | 13 |
| version | 13 |
| composition | 10 |
| conflict | 11 |
| simulation | 10 |
| lifecycle | 13 |
| import_export | 8 |
| binding | 8 |
| audit | 6 |
