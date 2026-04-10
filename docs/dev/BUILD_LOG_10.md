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
