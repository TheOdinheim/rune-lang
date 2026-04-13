# rune-explainability

Decision traces, factor attribution, counterfactual analysis, transparency reports, and human-readable explanations for the RUNE governance ecosystem.

## Overview

`rune-explainability` makes governance decisions interpretable. Given a decision (access denied, risk escalated, compliance flagged), this crate traces the factors that drove it, ranks their influence, generates counterfactuals ("what would need to change"), adapts explanations for different audiences, and produces structured transparency reports. It sits downstream of `rune-truth` (which verifies output trustworthiness) and `rune-provenance` (which tracks data lineage). Without explainability, governance is a black box — decisions happen but nobody can articulate why.

## Modules

| Module | Purpose |
|--------|---------|
| `decision` | Core decision records — DecisionId (newtype), Decision with 11 DecisionType variants, 6 DecisionOutcome variants, DecisionContext, DecisionFactor with 11 FactorType variants and 3 FactorDirection variants, DecisionStore with duplicate-rejecting registration |
| `trace` | Decision trace reconstruction — DecisionTracer walks backward from outcome through factors, produces TraceSteps with normalized contributions, identifies RootCauses (11 RootCauseType variants) |
| `factor` | Factor attribution — FactorAnalyzer normalizes weights, ranks by importance, identifies decisive factor, compares factor profiles across decisions to find DivergentFactors |
| `counterfactual` | Counterfactual analysis — CounterfactualGenerator identifies RequiredChanges to flip outcomes, with ChangeDifficulty (Easy/Moderate/Hard/Impossible) and CounterfactualFeasibility assessment |
| `narrative` | Narrative generation — NarrativeGenerator produces structured Narratives with sections at configurable DetailLevel (Summary/Standard/Detailed) |
| `audience` | Audience-adapted explanations — AudienceAdapter transforms outcomes, factors, and severity for 5 audiences (Technical/Executive/Regulatory/Operator/DataSubject) |
| `transparency` | Transparency reports — TransparencyReportBuilder collects decisions, computes summary statistics, renders JSON, with governance and compliance templates |
| `audit` | Explainability audit events — 8 event types with decision/type/trace/error filters |
| `error` | ExplainabilityError enum with 10 typed variants |

## Four-pillar alignment

- **Security Baked In**: Every decision is recorded with full factor attribution; the trace mechanism ensures no decision passes without an auditable explanation chain; transparency reports automatically flag decisions with no rationale.
- **Assumed Breach**: Factor analysis detects when a single factor dominates decisions (potential manipulation); counterfactual analysis reveals the minimum changes an attacker would need; audience adaptation ensures that even non-technical reviewers (regulators, data subjects) can understand what happened.
- **Zero Trust Throughout**: No decision is treated as self-evidently correct — every outcome must be traceable to specific factors with quantified weights; the DivergentFactor comparison catches decisions that deviate from established patterns; DecisionStore rejects duplicate registrations to prevent replay.
- **No Single Points of Failure**: Multiple independent explanation paths (trace, factor analysis, counterfactual, narrative) each provide a different lens on the same decision; transparency reports aggregate across many decisions so systemic issues surface even if individual explanations look reasonable; five audience adaptations ensure no single communication failure blocks understanding.

## Test summary

88 tests covering all modules:

| Module | Tests |
|--------|-------|
| decision | 15 |
| trace | 11 |
| factor | 10 |
| counterfactual | 11 |
| narrative | 10 |
| audience | 11 |
| transparency | 12 |
| audit | 7 |
| error | 1 |
