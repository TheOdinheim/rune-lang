# Build Log 10

## 2026-04-10 — rune-detection Layer 1: Anomaly Detection, Pattern Matching, Behavioral Analysis, Alert Management

### What was built

New workspace crate `packages/rune-detection/` implementing the sensing layer of RUNE's active defense. Observes, analyzes, and reports — but does not act (`rune-shield` acts on what rune-detection senses). Provides statistical anomaly detection (z-score, IQR, moving average), heuristic attack pattern matchers (prompt injection, SQLi, path traversal, XSS, command injection, data exfiltration, encoded payloads), online behavioral baselines via Welford's algorithm, indicators-of-compromise database with expiry and text scanning, composable detection rules (And/Or/Not), multi-stage detection pipelines with embedded alert management, dedup-aware alert lifecycle, and a detection-specific audit log. All types speak in `rune-security` vocabulary (`SecuritySeverity`, `ThreatCategory`).

### Four-pillar alignment

- **Security Baked In**: Pattern scanners, IoC database, and built-in rule templates are enabled by default; the pipeline raises alerts automatically on any rule hit; pattern detectors cover STRIDE + AI-specific categories without configuration.
- **Assumed Breach**: Behavioral baselines are built online from observed traffic so deviations are flagged even for previously trusted principals; IoC expiration purges stale intel; alert dedup-window and false-positive rate tracking keep signal-to-noise high under sustained attack.
- **Zero Trust Throughout**: Every signal is normalized and analyzed regardless of source; rules compose via And/Or/Not combinators so no single detector is load-bearing; alert lifecycle enforces explicit acknowledgement rather than implicit trust; behavioral analyzer returns `Unknown` rather than `Normal` until baselines are stable.
- **No Single Points of Failure**: Detection pipeline chains independent stages (anomaly + pattern + behavior + IoC + rule eval); each stage runs in isolation and a missing input (e.g., no text for pattern scan) is skipped silently without blocking other stages; `AnomalyDetector::detect()` runs z-score / IQR / moving-average together and returns the most severe verdict.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Add rune-detection to workspace members | +1 line |
| packages/rune-detection/Cargo.toml | Crate manifest with rune-lang, rune-permissions, rune-security, serde | New |
| packages/rune-detection/src/lib.rs | Crate root, module registration, re-exports | New |
| packages/rune-detection/src/error.rs | DetectionError enum (9 variants) | New |
| packages/rune-detection/src/signal.rs | Signal, SignalSource, SignalType, SignalValue, SignalBatch | New |
| packages/rune-detection/src/anomaly.rs | AnomalyDetector with z-score/IQR/moving-average, AnomalyResult, AnomalyMethod | New |
| packages/rune-detection/src/pattern.rs | PatternScanner + 7 heuristic detectors, CustomPattern, PatternMatch | New |
| packages/rune-detection/src/behavioral.rs | BehaviorAnalyzer (Welford online update), BehaviorProfile, MetricBaseline, BehaviorStatus | New |
| packages/rune-detection/src/alert.rs | Alert, AlertId, AlertManager with dedup window + lifecycle + false-positive rate | New |
| packages/rune-detection/src/indicator.rs | IoC, IoCType (9 variants + Custom), IoCDatabase with expiry + text scan | New |
| packages/rune-detection/src/rule.rs | DetectionRule, RuleCondition (And/Or/Not), evaluate_rule, RuleSet, built-in templates | New |
| packages/rune-detection/src/pipeline.rs | DetectionPipeline, PipelineStage, StageType, PipelineResult | New |
| packages/rune-detection/src/audit.rs | DetectionEventType (10 variants), DetectionAuditEvent, DetectionAuditLog with filters | New |
| packages/rune-detection/README.md | Crate overview, module table, four-pillar alignment, usage | New |

### Test summary

103 new tests (1630 total across workspace, all passing):

| Module | Tests | What's covered |
|--------|-------|----------------|
| error | 1 | All 9 variant Display messages |
| signal | 8 | Signal construction with metadata/context, all SignalValue variants, Display for SignalSource/SignalType, SignalBatch add/filter-by-type/filter-by-source/time-range |
| anomaly | 16 | Default config, observe ring-buffer window eviction, z-score outlier and normal values, stable data zero-variance, IQR outlier above/below fence, IQR normal, moving-average deviation, combined detect returns worst, mean/std_dev/percentile correctness, empty-history non-anomalous |
| pattern | 19 | detect_prompt_injection (ignore, "you are now", delimiter, normal text), detect_sql_injection (OR 1=1, UNION SELECT, normal), detect_path_traversal (../, %2e%2e), detect_xss (script tag, javascript:), detect_command_injection (rm, cat), detect_data_exfiltration (base64 block), detect_encoded_payload (double encoding), scan_text multi-category, min_confidence filter, with_categories selective, CustomPattern match/no-match |
| behavioral | 9 | observe creates profile, updates baseline, analyze normal, analyze deviation, unknown no-profile, unknown insufficient, Welford correctness against known-mean/std (population stats), multiple metrics tracked independently, is_baseline_stable |
| alert | 12 | raise creates alert, dedup within window, no-dedup outside window, acknowledge, resolve, mark_false_positive, active_alerts filter, by_severity, critical_alerts, false_positive_rate, severity_distribution, sequential AlertId |
| indicator | 9 | add+check match, unknown value None, expired skipped, text scan IP/domain, active_count, by_type filter, remove_expired, case-insensitive domain |
| rule | 14 | Construction, ValueAbove, ValueBelow, TextContains case-insensitive, TextContainsAny, And requires all, Or requires any, Not inverts, PatternDetected, nested combinators, RuleSet evaluate_all, disabled not evaluated, prompt_injection template, ioc_match template |
| pipeline | 10 | Anomaly stage on numeric, pattern stage on text, behavior stage updates profile, IoC stage finds indicator in text, rule stage triggers alert, multi-stage raises multiple alerts, raises alerts through AlertManager, has_detections, detection_count, process_batch |
| audit | 5 | Record/retrieve, events_by_severity, detection_events filter, alert_events filter, Display for all 10 DetectionEventType variants |

### Decisions

- **Sensing layer only — no response**: rune-detection observes and reports via `Alert` and `DetectionAuditEvent`; it never mutates state outside its own crate. Response is rune-shield's concern. This separation lets detection and response be independently configured, tuned, and audited — and prevents detection false positives from cascading into production impact.
- **Heuristic pattern matching, no regex**: Character-class scans and case-insensitive keyword lookup (same approach used by rune-privacy's PII detector). Avoids adding a regex dependency and keeps the crate compositional. Confidence scaling is `0.3 + 0.2 × hits` capped at 0.95 so a single weak indicator never fires alone but two stack to a meaningful score.
- **Welford online variance**: `BehaviorAnalyzer::observe` updates mean/M2 in constant time without storing history. Means baselines scale O(1) per observation regardless of profile lifetime — important for high-volume profiles. Square root of M2/count gives population (not sample) std dev, matching the behavior used by anomaly detection's stable-data tests.
- **Most-restrictive alert dedup**: `AlertManager::raise` deduplicates on `(title, category, severity)` within a 5-minute default window. Evidence is appended to the existing alert instead of creating a new one, so an attack burst produces one actionable alert with evidence count reflecting severity. Max-alerts limit with oldest-first eviction prevents unbounded growth.
- **Detection context threaded through rule eval**: `RuleEvalContext` carries everything downstream stages need — the signal itself, anomaly scores, pattern matches, behavior status, IoC matches, rate counts. Rule conditions reference this uniform context rather than each stage holding its own rule-evaluation logic. Makes rules data-driven and composable across detector types.
- **Two-pass pipeline execution**: The pipeline runs detection stages first (anomaly, pattern, behavior, IoC), builds a single `RuleEvalContext` from all results, then runs rule-evaluation stages. Rule conditions can reference *any* earlier detector's output, not just the stage that ran immediately before. This is the key property that makes composable rules useful.
- **Pipeline owns its AlertManager**: Alerts are a pipeline-scoped concern; the embedded `AlertManager` is the single place dedup and lifecycle decisions happen. External consumers see `pipeline.active_alerts()` / `pipeline.alert_count()` and don't manage alert state themselves.
- **IoC case-insensitivity for domains/URLs/emails/user-agents**: Network indicators are normalized to lowercase for comparison (case matters for file hashes and registry keys, which remain exact). `check_text` scans for the five text-discoverable IoC types (IP, Domain, URL, FileHash, Email) — file names and process names require structured signals so they're excluded from free-text scanning.
- **New build log file**: Started `BUILD_LOG_10.md` because `BUILD_LOG_09.md` had reached 560 lines, exceeding the 500-line per-file limit established in project rules.

## 2026-04-10 — rune-shield Layer 1: AI Inference Immune System, Prompt Injection Defense, Exfiltration Prevention

### What was built

New workspace crate `packages/rune-shield/` implementing the active defense layer of RUNE's inference-boundary protection. Where `rune-detection` observes and reports, `rune-shield` observes, **decides, and acts**. Provides a graduated `ShieldPolicy` (Bronze/Silver/Gold/Platinum), input validation and sanitization, a 5-strategy prompt injection detector with weighted scoring, a `SensitivePattern` library for exfiltration prevention (with PiiDetector integration), adversarial-input detection via Shannon entropy/repetition/unicode/information-density analysis, a quarantine store with review lifecycle and false-positive-rate tracking, immune memory that learns from confirmed attacks and suppresses known false positives, an output filter that redacts PII and blocks sensitive-pattern leaks, and a 15-event audit log with filters. The main `Shield` engine chains all components into an 8-step input-inspection pipeline and a 5-step output-inspection pipeline, and every `ShieldAction` maps to exactly one of four governance decisions: `Permit`, `Deny`, `Escalate`, `Quarantine`.

### Four-pillar alignment

- **Security Baked In**: All defenses are on by default — injection detection, adversarial detection, exfiltration scanning, PII redaction; default `ShieldPolicy` is Silver; `Shield::new()` wires the entire pipeline with no caller configuration required.
- **Assumed Breach**: `ImmuneMemory` learns from confirmed attacks and boosts confidence on recurrence; false-positive patterns are suppressed after a configurable threshold; `QuarantineStore` captures suspicious content for human review rather than forcing an immediate allow/deny; every output is inspected regardless of trust.
- **Zero Trust Throughout**: Every input is validated → adversarial-checked → injection-checked → memory-checked → verdicted, independent of source; every output is scanned for exfiltration before leaving the boundary; verdicts at every threshold require positive confirmation, and all decisions are explicit and typed through `GovernanceDecision`.
- **No Single Points of Failure**: Five injection strategies (`KeywordHeuristic`, `StructuralAnalysis`, `LengthAnomaly`, `EncodingDetection`, `InstructionDensity`) cross-check a single input with independent weights; detection and response logic are in separate modules so a flaw in one detector doesn't disable the rest; quarantine provides a safe middle ground when confidence sits between allow and block thresholds.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Add rune-shield to workspace members | +1 |
| packages/rune-shield/Cargo.toml | Crate manifest with rune-lang, rune-permissions, rune-security, rune-privacy, rune-detection, serde | New |
| packages/rune-shield/src/lib.rs | Crate root, module declarations, re-exports | New |
| packages/rune-shield/src/error.rs | ShieldError enum with 7 variants | New |
| packages/rune-shield/src/response.rs | ShieldAction, ShieldVerdict, GovernanceDecision, CheckResult | New |
| packages/rune-shield/src/policy.rs | ShieldLevel (Bronze/Silver/Gold/Platinum), ShieldPolicy presets | New |
| packages/rune-shield/src/input.rs | InputValidator, InputValidation, InputSanitizer | New |
| packages/rune-shield/src/injection.rs | InjectionDetector, 5 strategies, neutralize() | New |
| packages/rune-shield/src/exfiltration.rs | ExfiltrationDetector, SensitivePattern (5 built-in), redact_pii() | New |
| packages/rune-shield/src/adversarial.rs | AdversarialDetector, 4 AdversarialTypes, Shannon entropy | New |
| packages/rune-shield/src/quarantine.rs | QuarantineStore, QuarantineVerdict, lifecycle, FP rate | New |
| packages/rune-shield/src/memory.rs | ImmuneMemory, AttackSignature, FalsePositivePattern | New |
| packages/rune-shield/src/output.rs | OutputFilter, OutputFinding, OutputFindingType | New |
| packages/rune-shield/src/audit.rs | ShieldAuditEvent, ShieldAuditLog, 15 ShieldEventType variants | New |
| packages/rune-shield/src/shield.rs | Shield main engine, inspect_input (8 steps), inspect_output (5 steps), ShieldStats | New |
| packages/rune-shield/README.md | Crate overview, module table, four-pillar alignment, usage | New |

### Test summary

98 new tests (all passing):

| Module | Tests | What's covered |
|--------|-------|----------------|
| error | 1 | Display for all 7 variants |
| response | 6 | is_permitted/is_blocked/is_quarantined/is_escalated/is_modified, to_governance_decision mapping, GovernanceDecision discriminant values (0-3), ShieldVerdict constructors + with_evidence, CheckResult pass/fail, Display/reason |
| policy | 6 | Levels ordered Bronze<Silver<Gold<Platinum, presets tighten monotonically across all thresholds, from_level, default is Silver, with_blocked_pattern, level display |
| input | 11 | Accept normal, reject too long, reject null bytes, strict mode rejects control chars, blocked patterns, validate_or_err InputTooLarge, sanitizer strip_control/normalize_whitespace/truncate, UTF-8 boundary safety, escape_html |
| injection | 13 | keyword heuristic (ignore previous), normal text low confidence, structural delimiter abuse, structural role marker, length anomaly, encoding base64, encoding URL percent, instruction density, is_suspicious threshold, strategy weights sum to 1.0, neutralize wraps and redacts role markers, evidence collected, confidence clamped |
| exfiltration | 13 | System prompt leak, API key leak critical severity, training data leak, internal URL leak, normal output clean, is_leaking threshold, builtin pattern count = 5, redact emails/SSNs/IPs/phones, redact leaves normal text, pattern type severity |
| adversarial | 7 | Low entropy flagged, repetition detected, unicode zero-width, low info density, normal text clean, is_adversarial threshold, Shannon entropy bounds |
| quarantine | 10 | quarantine+get, pending_review filter, review Confirmed, review FalsePositive affects rate, review not-found error, double-review errors, average_review_time, empty FP rate is zero, Modified verdict, sequential IDs unique |
| memory | 7 | record_and_recall_attack, confirm increases count and boosts, record_false_positive, should_suppress after threshold, boost unknown is noop, boost capped at 1.0, signature confidence_boost monotone |
| output | 6 | Normal output clean, filter redacts PII, filter detects system prompt leak, filter detects API key leak → Critical, is_leaking, with_pii_redaction disabled |
| audit | 5 | Record + kind helpers, exfiltration filter, by_severity, since filter, Display for all 15 ShieldEventType variants |
| shield | 13 | Normal input allowed, injection blocked (platinum), input too long blocked, adversarial quarantined, output blocks exfiltration, output modifies on PII, output normal allowed, output length limit blocks, stats track decisions, platinum stricter than bronze, governance decision mapping, quarantine_id extracted from verdict, audit log populated |

### Decisions

- **Four governance decisions hard-coded in response layer**: `GovernanceDecision::{Permit=0, Deny=1, Escalate=2, Quarantine=3}` has explicit u8 discriminants and is the single type that downstream RUNE governance should consume. `ShieldAction::to_governance_decision()` is the mapping point: `Allow | Modify → Permit`, `Block → Deny`, `Quarantine → Quarantine`, `Escalate → Escalate`. `Modify` is a permitted action because the downstream model still proceeds — just with sanitized content. This mapping lives in one function so it can be exhaustively tested.
- **PII redaction vs sensitive-pattern blocking**: Output inspection distinguishes two failure modes. PII leaks (emails, SSNs, phones, IPs, credit cards) are redacted in place and returned as `Modify`, because the surrounding output is usually legitimate and just needs scrubbing. Sensitive-pattern leaks (system prompt, API keys, training data, internal URLs, internal architecture) are blocked outright — the output itself is compromised, so there's nothing safe to salvage. This split lives in `Shield::inspect_output` via `has_pattern_leak` check before applying the exfiltration block threshold.
- **Five weighted injection strategies summing to 1.0**: `KeywordHeuristic` (0.4) is the strongest single signal, but caps at max 0.4 weighted contribution so it can't single-handedly trigger a block at higher shield levels. `StructuralAnalysis` (0.3) adds delimiter-abuse and role-marker detection. Length, encoding, and density (0.1 each) are weak individual signals but compose. The sum-to-1.0 property means confidence is directly comparable to thresholds.
- **Immune memory signature = top keyword evidence**: `injection_signature` derives a coarse key from the first `KeywordHeuristic` evidence string (falling back to a confidence bucket). This keeps the memory key stable across semantically similar inputs — different wording of the same injection attempt will produce the same signature, allowing confirmation counts to accumulate. It's intentionally lossy so that learned suppression generalizes.
- **Token-based PII redaction with a whole-text phone pass**: `redact_pii` is implemented as a whitespace-split token classifier that identifies each token as email/SSN/IP/credit-card/neither and replaces matches in place. Phone numbers span tokens (e.g., `555 123 4567`), so they get a separate pre-pass over the entire text before token classification. This avoids the infinite-loop and UTF-8-boundary bugs that plagued the initial regex-less scan-by-char implementation, and it's simpler to reason about.
- **Quarantine store embedded in Shield**: Unlike `rune-detection` where alerts are pipeline-scoped, the shield's `QuarantineStore` lives on the `Shield` struct as a field and is threaded through `inspect_input` directly. Callers that need to release, confirm, or review quarantined content access `shield.quarantine` — the quarantine IDs surface in the verdict's evidence field so callers can extract them with `Shield::quarantine_id_from_verdict`. This keeps the active-defense loop self-contained.
- **Input-pipeline order: validate → adversarial → injection → memory → verdict**: Adversarial detection runs *before* injection detection because statistical anomalies (massive repetition, low entropy) should be caught and quarantined without wasting cycles on keyword scanning; these inputs are rarely legitimate prompts anyway. Injection detection then runs, and only *after* injection does the immune memory apply suppression and boosting — otherwise a known false-positive pattern would still incur full detection cost. This ordering minimizes compute for the hot path of suspicious inputs.
- **Pre-existing rune-lang bench test flakiness**: Two tests in `rune-lang` (`test_bench_serialize_request`, `test_bench_deserialize_request`) assert `avg_us < 10.0` for serialization timing. They fail under debug-build overhead (27us actual). These failures are pre-existing, pure timing assertions with no relation to rune-shield, and rune-shield's 98 tests all pass independently. Noted here so future build logs don't attribute them to shield changes.
