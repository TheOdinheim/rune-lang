# rune-truth

Output trustworthiness verification — confidence scoring, consistency checking, source attribution, contradiction detection, and ground truth comparison for the RUNE governance ecosystem.

## Overview

`rune-truth` verifies output trustworthiness. Given a model output, how confident should we be? Is it consistent with prior outputs? Which training data influenced it? Does it contradict known facts? This crate sits between `rune-provenance` (which tracks where things came from) and `rune-explainability` (which explains why decisions were made). Without truth verification, provenance is just paperwork — you know where something came from but not whether to believe it.

## Modules

| Module | Purpose |
|--------|---------|
| `confidence` | Weighted confidence scoring with configurable factors (calibration, entropy, consistency, source quality, provenance, ground truth, expert agreement, temporal stability) |
| `consistency` | Output consistency checking — tracks outputs by input hash, measures dominant-output ratio and Jaccard word similarity |
| `attribution` | Source attribution — computes influence scores between outputs and candidate sources via token overlap, normalizes to sum ~1.0 |
| `contradiction` | Contradiction detection — keyword overlap + negation indicators for direct negation, numeric disagreement, and self-consistency checking |
| `ground_truth` | Ground truth comparison — exact, partial, semantic (Jaccard >= 0.7) matching with accuracy metrics by category |
| `trust_score` | Aggregate trust assessment — combines all signals with configurable weights into trust level, flags, and recommendation (Accept/AcceptWithCaveat/ManualReview/Reject) |
| `claim` | Verifiable truth claims — structured assertions with evidence, lifecycle (Pending/Verified/Disputed/Retracted/Expired) |
| `audit` | Truth audit events — 10 event types with output/type/contradiction/assessment/claim filters |
| `error` | TruthError enum with 12 typed variants |

## Four-pillar alignment

- **Security Baked In**: Every output gets a confidence score before use; the TruthAssessor generates flags automatically for low confidence, inconsistency, unattributed content, and contradictions; Critical contradictions force Reject regardless of overall score.
- **Assumed Breach**: Contradiction detection checks outputs against known facts and prior outputs, catching compromised or hallucinating models; self-consistency checking detects outputs that contradict themselves internally; immune to single-source manipulation because trust scores combine six independent signals.
- **Zero Trust Throughout**: No output is trusted by default — TruthAssessor requires positive evidence across multiple dimensions; missing ground truth generates a NoGroundTruth flag rather than assuming correctness; unattributed content is flagged, not silently accepted.
- **No Single Points of Failure**: Six independent truth signals (confidence, consistency, attribution, contradiction-free, ground truth, provenance) each contribute independently; a gap in one signal (e.g., no ground truth available) reduces the score but doesn't disable verification; TruthClaimRegistry provides a separate evidence-based verification path.

## Test summary

87 tests covering all modules:

| Module | Tests |
|--------|-------|
| confidence | 11 |
| consistency | 11 |
| attribution | 9 |
| contradiction | 13 |
| ground_truth | 11 |
| trust_score | 11 |
| claim | 14 |
| audit | 6 |
| error | 1 |
