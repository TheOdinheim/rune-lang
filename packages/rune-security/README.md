# rune-security

Threat modeling, vulnerability scoring, and security context for the RUNE governance ecosystem.

## Overview

`rune-security` defines the common security vocabulary and posture assessment system used throughout the RUNE ecosystem. Every other Tier 2+ security library speaks in rune-security's types: `rune-detection` raises alerts using `SecuritySeverity`, `rune-shield` applies responses using `ThreatCategory`, `rune-monitoring` tracks metrics using `SecurityMetric`. This is the common language of active defense.

## Modules

| Module | Purpose |
|--------|---------|
| `severity` | `SecuritySeverity` (Info–Emergency), score-to-severity mapping, response SLAs, `SeverityChange` tracking |
| `threat` | STRIDE + AI-specific threat categories, threat actors, attack surfaces, `ThreatModelBuilder` |
| `vulnerability` | CVSS v3.1 adapted scoring with AI impact metrics, `VulnerabilityDatabase` with filters |
| `posture` | Security posture grading (A–F), weighted dimensional scoring, recommendation generation |
| `context` | `SecurityContext` propagation, `ContextStack` with most-restrictive clearance and worst-case risk |
| `incident` | Incident lifecycle with state-machine transitions, `EscalationPolicy`, MTTA/MTTR metrics |
| `policy` | Composable `RuleCondition` (And/Or/Not), rule evaluation, built-in templates (network, data, AI) |
| `metrics` | MTTD/MTTR/MTTC, patch coverage, detection coverage, trend analysis, `SecurityDashboard` |
| `audit` | `SecurityAuditEvent` log with filters by type, severity, time |
| `error` | `SecurityError` with 12 typed variants |

## Four-Pillar Alignment

- **Security Baked In**: Every threat category maps to one or more RUNE pillars via `ThreatCategory::affected_pillar()`. Rule evaluation auto-audits policy decisions.
- **Assumed Breach**: `SecurityContext` tracks active threats and propagates through call chains. `ContextStack::effective_risk()` returns the worst case across all nested contexts. Incident tracker enforces valid state transitions.
- **Zero Trust Throughout**: `SecurityContext::restrict()` only narrows clearance (never widens). `SecurityContext::elevate_risk()` only raises risk (never lowers). Most-restrictive clearance wins in a context stack.
- **No Single Points of Failure**: Multiple independent posture dimensions (AccessControl, DataProtection, ThreatManagement, IncidentResponse, Compliance, AiGovernance, OperationalResilience). Multiple escalation levels per severity.

## Usage

```rust
use rune_security::*;
use rune_permissions::ClassificationLevel;

// Build a threat model
let mut builder = ThreatModelBuilder::new("API Gateway", "security-team");
builder.description("External-facing API")
    .add_threat(IdentifiedThreat {
        id: "t1".into(),
        category: ThreatCategory::PromptInjection,
        description: "LLM prompt injection via query parameters".into(),
        target_surface: "api".into(),
        actor_type: Some(ThreatActorType::Hacktivist),
        likelihood: SecuritySeverity::High,
        impact: SecuritySeverity::Critical,
        overall_risk: SecuritySeverity::Critical,
        mitigations: vec!["input validation".into()],
        status: ThreatStatus::Identified,
    });

// Propagate security context through a call chain
let ctx = SecurityContext::new("req-001")
    .subject("user:alice")
    .clearance(ClassificationLevel::Confidential)
    .authenticated(true)
    .mfa(true)
    .risk_level(SecuritySeverity::Low);

let child = ctx.derive_child("inner").elevate_risk(SecuritySeverity::High);

// Track an incident
let mut tracker = IncidentTracker::new(EscalationPolicy::new());
let incident = tracker.report(
    "Suspicious auth attempts",
    "15 failed logins in 30s",
    SecuritySeverity::High,
    ThreatCategory::Spoofing,
    "detector",
);
```

## Tests

108 tests across all modules, covering severity ordering and score mapping, STRIDE/AI threat taxonomy, CVSS base score calculation (including scope-changed formula), posture grading, context propagation semantics, incident state machine, rule evaluation combinators, metric trend analysis, and audit log filters.
