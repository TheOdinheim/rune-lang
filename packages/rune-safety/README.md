# rune-safety

Safety constraints, safety cases, hazard analysis, fail-safe behaviors, safety integrity levels, and safety monitors for the RUNE governance ecosystem.

## Overview

`rune-safety` encodes safety properties for AI systems as typed, verifiable constructs. Safety is distinct from security — security protects against adversaries, safety protects against accidents, failures, and unintended consequences. This crate provides safety constraints that can be verified at compile time or evaluated at runtime, structured safety cases (GSN-inspired) that argue a system is acceptably safe, safety monitors that watch for unsafe conditions, fail-safe behaviors that define what happens when things go wrong, safety integrity levels (IEC 61508 SIL, DO-178C DAL, ISO 26262 ASIL) that classify system criticality, and hazard analysis that systematically identifies what could go wrong.

Maps to DO-178C (avionics), IEC 61508 (industrial), ISO 26262 (automotive), and the RUNE architecture's pillar enforcement.

## Modules

| Module | Purpose |
|--------|---------|
| `integrity` | SafetyIntegrityLevel (SIL 0-4 with failure_rate_target/requires_independent_verification/min_test_coverage), DesignAssuranceLevel (DAL E-A with structural_coverage_required/independence_required), AutomotiveSafetyLevel (QM/ASIL A-D), SafetyClassification (cross-standard with highest_level_name/requires_formal_verification) |
| `constraint` | ConstraintId (newtype), SafetyConstraint (12 fields), ConstraintType (8 variants), SafetyCondition (11 variants with And/Or/Not), ConstraintSeverity (5 levels: Advisory→Catastrophic), evaluate_safety_condition, ConstraintEvaluation, ConstraintStore (add/get/evaluate_all/violated/by_type/by_severity/by_integrity_level/verified/unverified) |
| `safety_case` | SafetyCaseId (newtype), SafetyCase with SafetyGoal (recursive sub-goals), SafetyStrategy, SafetyEvidence with EvidenceType (7 variants) and EvidenceStrength (4 levels), GoalStatus (5 variants), SafetyCaseStatus (5 variants), SafetyCaseStore (add/get/completeness/unsupported_goals/evidence_count/by_status) |
| `monitor` | SafetyMonitorId (newtype), SafetyMonitor with consecutive violation tracking, MonitorResponse (6 variants), MonitorStatus (4 variants), MonitorCheckResult, SafetyMonitorEngine (register/check/check_all/triggered_monitors/active_monitors/reset) |
| `failsafe` | FailsafeId (newtype), FailsafeBehavior with FailsafeTrigger (7 variants), FailsafeAction (8 variants), RecoveryProcedure, FailsafeRegistry (register/trigger/untested/overdue_testing/by_priority) |
| `hazard` | HazardId (newtype), Hazard with HazardType (8 variants), HazardLikelihood (6 levels), RiskLevel (4 levels with from_severity_likelihood risk matrix), HazardMitigation with MitigationType (7 variants) and MitigationEffectiveness (4 levels), HazardStatus (5 variants), HazardRegistry (register/by_type/by_risk_level/intolerable_hazards/unmitigated_hazards/risk_matrix) |
| `boundary` | SafetyBoundary with BoundaryType (5 variants), OperatingLimit (is_within), BoundaryStatus (4 variants), BoundaryCheckResult, SafetyBoundarySet (add/check_all/breached/approaching) |
| `assessment` | SafetyAssessment combining all signals, SafetyLevel (5 variants: Safe/ConditionalSafe/Degraded/Unsafe/Unknown), HazardSummary, MonitorSummary, SafetyAssessor (full assessment with recommendation generation) |
| `audit` | SafetyEventType (11 variants), SafetyAuditEvent, SafetyAuditLog (events_by_severity/since/constraint_events/monitor_events/hazard_events/boundary_events/critical_events) |
| `error` | SafetyError with 14 typed variants |

## Four-pillar alignment

- **Security Baked In**: Safety constraints encode invariants, preconditions, and postconditions as typed predicates that can be verified at compile time or evaluated at runtime. Safety integrity levels (SIL/DAL/ASIL) classify system criticality and mandate test coverage levels, structural coverage, and independent verification.
- **Assumed Breach**: Safety monitors watch for constraint violations with configurable consecutive-violation thresholds. Fail-safe behaviors define automatic responses to failures (safe mode, rate limiting, graceful shutdown). Hazard analysis systematically identifies what could go wrong and tracks mitigations.
- **Zero Trust Throughout**: The safety assessor trusts no single signal — it combines constraint evaluations, safety case completeness, hazard status, monitor state, and boundary checks to produce an overall safety level. Critical constraint violations or boundary breaches immediately produce Unsafe status regardless of other signals.
- **No Single Points of Failure**: Multiple mitigation types (elimination, reduction, isolation, design control, procedural control, warning). Multiple fail-safe responses per trigger. Recovery procedures with auto-recovery and human-approval options. Cross-standard classification (SIL + DAL + ASIL simultaneously).

## Test summary

106 tests covering all modules:

| Module | Tests |
|--------|-------|
| error | 1 |
| integrity | 11 |
| constraint | 17 |
| safety_case | 11 |
| monitor | 12 |
| failsafe | 11 |
| hazard | 14 |
| boundary | 9 |
| assessment | 10 |
| audit | 8 |
