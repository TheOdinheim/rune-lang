# RUNE Build Log 13

> Previous file: [BUILD_LOG_12.md](BUILD_LOG_12.md)

---

## rune-audit-ext — Layer 2 Upgrade

**Date:** 2026-04-13
**Type:** Layer 2 (internal upgrade, backward-compatible)
**Tests:** 136 (87 existing + 49 new)
**Dependencies added:** hmac = "0.12"

### Overview

Upgraded `rune-audit-ext` with HMAC-SHA3-256 chain authentication,
storage abstraction, retention hardening with archive capability,
HashMap-based query indexing, condition-based event enrichment,
export format hardening with NDJSON/ECS support, and 7 new
meta-audit event types.

### Changes by Module

#### integrity.rs — HMAC Chain Authentication (PART 1)

- Added `ChainAuthenticator` struct with `chain_key: Vec<u8>`
- `compute_authenticated_hash()`: computes SHA3-256 base hash then
  applies HMAC-SHA3-256 with the chain key
- `verify_authenticated_chain()`: recomputes full chain with HMAC,
  returns `ChainStatus`
- `sign_chain_segment()`: signs a slice of events, returns Vec of
  HMAC signatures
- `verify_chain_segment()`: verifies signatures match events
- Uses `hmac::Hmac<Sha3_256>` type alias `HmacSha3_256`
- Different keys produce different hashes (prevents chain forgery)
- 7 new tests

#### store.rs — Storage Abstraction + Event Indexing (PARTS 2 & 4)

- Added `EventIndex` struct with `by_source`, `by_category`,
  `by_correlation`, `by_actor` HashMap<Key, Vec<usize>> fields
- `EventIndex::build()` and `EventIndex::add()` for construction
- `StorageStats` struct: total_events, unique_sources/categories/
  actors/correlations, oldest/newest timestamp, memory_estimate_bytes
- `AuditStore::storage_stats()`: aggregated statistics
- `AuditStore::memory_estimate()`: approximate memory usage in bytes
- `AuditStore::compact()`: shrinks internal allocations
- `AuditStore::snapshot()` / `restore()`: clone and rebuild
- `AuditStore::merge()`: merge another store, skip duplicates
- `AuditStore::rebuild_index()`: full reindex
- `AuditStore::archive_where()`: move events to archive instead of
  deleting (Critical+ events never archived)
- `AuditStore::archived_events()` / `archived_count()`: access archive
- `events_by_source/category/actor/correlation` now use EventIndex
  for O(1) lookup instead of linear scan
- Enricher integration: `with_enricher()` / `set_enricher()`, applied
  during `ingest()` before chain hashing
- 12 new tests

#### retention.rs — Retention Hardening (PART 3)

- `validate_policies()` -> `RetentionValidation`: checks non-positive
  max_age, empty names, duplicate names
- `RetentionValidation::is_valid()` predicate
- `dry_run()` -> `RetentionPreview`: total_affected, affected_sources
  HashMap, space_to_free_estimate
- `apply_with_archive()` -> `Vec<ArchiveResult>`: respects
  RetentionAction (Archive uses store.archive_where, Delete uses
  store.remove_where)
- `ArchiveResult` struct: policy_name, action, events_archived,
  events_deleted
- 7 new tests

#### enrichment.rs — Event Enrichment (PART 5, new module)

- `EnrichmentCondition` enum: SourceIs, CategoryIs, SeverityAtLeast,
  TagExists, Always
- `Enrichment` enum: AddTag (no duplicates), SetCorrelationId
  (no overwrite), EscalateSeverity (no downgrade), AddDetail (append)
- `EnrichmentRule`: name + condition + enrichments, returns count
  of applied enrichments
- `EventEnricher`: holds rules, `enrich()` applies all matching rules
- Integrated into `AuditStore::ingest()` — enrichment runs before
  chain hash computation
- 13 new tests

#### export.rs — Export Format Hardening (PART 6)

- CEF header: `CEF:0|RUNE|rune-audit-ext|1.0|action|detail|sev|ext`
  with proper pipe escaping via `cef_escape()`
- CEF correlation: `cs1Label=correlationId cs1=<id>` when present
- JSON Lines: `schema_version: "1.0"` and `export_timestamp` (ISO 8601)
  injected into each line
- NDJSON/ECS format: `@timestamp`, `event` (kind/category/outcome/
  action/severity), `source.component`, `user.name`, `message`,
  `labels` (rune_event_id/rune_subject), `tags`
- `ExportFormat::Ndjson` variant added
- `ExportValidation` struct: format, event_count, output_bytes, valid,
  issues
- `AuditExporter::validate_export()`: validates JSON parsability,
  CSV column consistency, CEF header presence
- `iso8601_from_epoch()` and `epoch_days_to_date()` civil calendar
  conversion helpers
- 10 new tests

#### audit.rs — New Meta-Audit Event Types (PART 7)

- 7 new `AuditExtEventType` variants: ChainAuthenticated,
  StorageCompacted, IndexRebuilt, EventEnriched, ArchiveCompleted,
  RetentionValidated, ExportValidated
- Display and type_name implementations for all 15 variants
- Existing test updated from 8 to 15 variant count
- 1 new test covering all 7 new event types

### README.md Fix

- Changed "21 Governance Libraries" to "19 Governance Libraries" in
  badge and status line (rune-rs and rune-python are FFI bridges, not
  governance libraries)

### Test Summary

```
cargo test -p rune-audit-ext
  136 passed; 0 failed

cargo test --workspace
  3,110 passed; 0 failed
```

### Four-Pillar Alignment

| Pillar | How This Upgrade Serves It |
|--------|---------------------------|
| Security/Privacy/Governance Baked In | HMAC chain auth prevents hash chain forgery without key; event enrichment auto-tags security events |
| Assumed Breach | Chain authentication detects tampered audit trails; archive preserves evidence |
| No Single Points of Failure | Storage snapshot/restore enables audit store replication; merge supports distributed collection |
| Zero Trust Throughout | HMAC requires explicit key; enrichment conditions are declarative and auditable |
