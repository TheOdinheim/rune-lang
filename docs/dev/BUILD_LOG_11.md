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
