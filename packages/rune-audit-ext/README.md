# rune-audit-ext

Unified audit store, cross-crate event correlation, query engine, export formats, retention enforcement, and chain integrity verification for the RUNE governance ecosystem.

## Overview

`rune-audit-ext` aggregates audit events from all RUNE crates into a single store. Each crate has its own audit log with crate-specific event types; this crate normalizes them into `UnifiedEvent` records with a common schema (14 fields) so they can be correlated, queried, exported, and retained as a unified audit trail. String-based ingestion helpers avoid depending on every source crate — callers pass strings, not crate-specific types.

## Modules

| Module | Purpose |
|--------|---------|
| `event` | UnifiedEventId (newtype), UnifiedEvent (14 fields), SourceCrate (14 variants), EventCategory (14 variants), EventOutcome (7 variants), UnifiedEventBuilder |
| `store` | AuditStore with max_events/chain_enabled, ingest/ingest_batch/get/latest/events_since/events_between/events_by_source/category/severity/actor/subject/correlation, distribution methods, events_per_second, remove_where (preserves Critical+), 10 ingestion helper free functions |
| `correlation` | CorrelationChain (span, is_cross_crate), CorrelationEngine with correlate/find_causal_chain/find_children/active_correlations/cross_crate_chains/correlate_by_time_window/correlate_by_subject |
| `query` | AuditQuery with QueryFilter (And/Or/Not combinators, 12 leaf filters), QuerySort (4 modes), QueryResult with pagination, QueryEngine with execute/count |
| `export` | ExportFormat (JsonLines/Cef/Csv/Summary), AuditExporter with CEF severity mapping (Info=1, Low=3, Medium=5, High=7, Critical=9, Emergency=10) |
| `retention` | AuditRetentionPolicy, RetentionScope (All/Source/Category/SeverityBelow), RetentionAction (Delete/Archive/Anonymize), RetentionManager with apply/preview, Critical+ preservation rule, 3 built-in policies (default-90d, short-7d-info, compliance-365d) |
| `integrity` | SHA3-256 hash chains, compute_event_hash, verify_chain, verify_range, find_gaps, chain_health, ChainStatus (Valid/Broken/Empty/TooShort) |
| `timeline` | Timeline, TimelineEntry, TimelineBuilder with from_store/from_correlation/from_subject, bucketize for histograms |
| `audit` | AuditExtEventType (8 variants: EventIngested/BatchIngested/QueryExecuted/Exported/RetentionApplied/CorrelationRun/ChainVerified/TimelineGenerated), AuditExtLog |
| `error` | AuditExtError with 9 typed variants |

## Four-pillar alignment

- **Security Baked In**: SHA3-256 hash chains create tamper-evident audit trails; every event has severity, category, and outcome fields; ingestion rejects duplicates; chain verification detects insertions, deletions, and modifications.
- **Assumed Breach**: Cross-crate correlation discovers attack paths spanning multiple subsystems; find_gaps detects suspicious timeline discontinuities; retention policies preserve Critical+ events permanently regardless of age; CEF export enables SIEM integration for real-time monitoring.
- **Zero Trust Throughout**: No event is trusted in isolation — correlation links events across crate boundaries; query combinators (And/Or/Not) enable arbitrary investigation filters; every store mutation (ingest, retention, remove) validates preconditions; retention previews show impact before applying.
- **No Single Points of Failure**: 10 independent ingestion helpers normalize events from any source crate; 4 export formats (JSON Lines, CEF, CSV, Summary) ensure data is accessible from any tool; 3 built-in retention policies cover common regulatory requirements; timeline construction works from store, correlation, or subject.

## Test summary

87 tests covering all modules:

| Module | Tests |
|--------|-------|
| error | 1 |
| event | 9 |
| store | 14 |
| correlation | 10 |
| query | 12 |
| export | 9 |
| retention | 8 |
| integrity | 10 |
| timeline | 9 |
| audit | 5 |
