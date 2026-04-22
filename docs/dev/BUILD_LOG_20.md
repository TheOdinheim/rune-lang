# RUNE Build Log 20

> Previous file: [BUILD_LOG_19.md](BUILD_LOG_19.md)

---

## rune-data — Layer 3: Data Governance Integration Boundary

**Commit:** `feat(rune-data): Layer 3 — data governance backend, quality/lineage/schema governors, data governance exporters, data event streaming, data governance metrics collector`

**Test count:** 297 (198→297, +99 new)

### New Modules (7)

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `backend.rs` | Pluggable storage contract for all data governance entities | `DataGovernanceBackend` trait (35 methods), `StoredQualityRule`/`StoredClassification`/`StoredLineageRecord`/`StoredSchemaRecord`/`StoredCatalogEntry`/`StoredFreshnessAssessment` wrapper types with SHA3-256 hashing at storage time, `InMemoryDataGovernanceBackend` (13 HashMaps), `DataBackendInfo` |
| `quality_governor.rs` | Quality enforcement with pipeline-blocking semantics | `QualityGovernor` trait, `QualityGovernanceDecision` (QualityMet/QualityFailed/PipelineBlocked/InsufficientData), `InMemoryQualityGovernor` wrapping L2 `QualityEngine`, `NullQualityGovernor` |
| `lineage_governor.rs` | Lineage compliance verification at integration boundary | `LineageGovernor` trait, `LineageGovernanceDecision` (Compliant/NonCompliant/ChainBroken/InsufficientData), `InMemoryLineageGovernor` wrapping L2 `LineageVerifier`, `NullLineageGovernor` |
| `schema_governor.rs` | Schema evolution governance with health assessment | `SchemaGovernor` trait, `SchemaGovernanceDecision` (Approved/Rejected/RequiresMigrationPlan/RequiresDeprecationPeriod), `SchemaHealthStatus` (Healthy/Outdated/Incompatible/Unknown), `InMemorySchemaGovernor` wrapping L2 `SchemaCompatibilityChecker`, `NullSchemaGovernor` |
| `data_export.rs` | Five exporter implementations for governance reports | `DataGovernanceExporter` trait (8 methods), `JsonDataExporter`, `DataQualityReportExporter`, `DataLineageExporter`, `DataCatalogExporter`, `GdprDataMappingExporter` (GDPR Article 30 processing activities, filters Confidential/Restricted) |
| `data_stream.rs` | Event subscriber trait and registry for data governance lifecycle | `DataGovernanceEventSubscriber` trait, `DataGovernanceEventSubscriberRegistry`, `DataGovernanceEventCollector`, `FilteredDataGovernanceEventSubscriber` (event_type/dataset_ref/severity filters with let-chains), `DataGovernanceLifecycleEventType` (23 variants) |
| `data_governance_metrics.rs` | Metrics collector for data governance KPIs | `DataGovernanceMetricsCollector` trait (7 compute methods), `DataGovernanceMetricSnapshot`, `InMemoryDataGovernanceMetricsCollector`, `NullDataGovernanceMetricsCollector` |

### Audit Events

37 new `DataEventType` variants added (19 L2-era + 18 L3), bringing total from 24 to 61:

- **L2 engine variants (19):** DatasetHashComputed, SchemaHashComputed, LineageHashComputed, DataHashChainAppended, DataHashChainVerified, QualityRuleEvaluatedEngine, QualityPolicyEvaluatedEngine, DataClassificationInferred, ClassificationReviewChecked, ClassificationComplianceChecked, LineageChainVerifiedEngine, LineageGapDetectedEngine, LineageRecordComplianceChecked, DataAccessEvaluatedEngine, SchemaCompatibilityCheckedEngine, SchemaEvolutionDecided, FreshnessEvaluatedEngine, FreshnessAlertGenerated, DataMetricsComputed
- **L3 governance variants (18):** DataGovernanceBackendChanged, StoredQualityRuleCreated, StoredClassificationCreated, StoredLineageRecordCreated, StoredSchemaRecordCreated, StoredCatalogEntryCreated, QualityGovernanceEvaluated, QualityPipelineBlocked, LineageGovernanceEvaluated, LineageChainVerifiedGov, SchemaGovernanceEvaluated, SchemaHealthAssessedGov, DataGovernanceExported, DataGovernanceExportFailed, DataGovernanceMetricsComputed, DataGovernanceSubscriberRegistered, DataGovernanceSubscriberRemoved, DataGovernanceEventPublished

New `kind()` categories: `hashing`, `backend`, `export`, `streaming`, `metrics`. New classifier methods: `is_engine_event()`, `is_governance_event()`, `is_backend_event()`, `is_export_event()`, `is_streaming_event()`.

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Engine suffix for L2 audit variants** | Avoids collision with L1 `QualityRuleEvaluated`/`LineageChainVerified`/`SchemaCompatibilityChecked` etc. |
| **Gov suffix for L3 audit variants** | Avoids collision with both L1 and L2 variants (e.g., `LineageChainVerifiedGov` vs L1 `LineageChainVerified` vs L2 `LineageChainVerifiedEngine`) |
| **String for all numeric metrics** | Enables `Eq` derivation on metric snapshots and governance results without f64 equality issues |
| **dataset_ref filter on data_stream** | Unlike rune-ai's model_id filter, data governance events are dataset-scoped |
| **Separate data_governance_metrics.rs** | Named to avoid collision with L2 `data_metrics.rs` |

### Integration Points

- **rune-privacy**: `GdprDataMappingExporter` produces GDPR Article 30 processing activity records filtering Confidential/Restricted classifications
- **rune-provenance**: `StoredLineageRecord.lineage_hash` and `StoredSchemaRecord.schema_hash` produce SHA3-256 digests compatible with rune-provenance attestation verification
- **rune-monitoring**: `DataGovernanceMetricSnapshot` fields are String-valued for compatibility with rune-monitoring's MetricPoint surface
- **rune-ai**: Quality governor's pipeline-blocking can gate training data quality before rune-ai's model training approval

---

## Pre-Layer-4 Cleanup

**Commit:** `fix: pre-Layer-4 cleanup — add rune-permissions audit module, investigate compiler test delta, remove stray rust_out binary`

### ITEM 1: rune-permissions audit module

rune-permissions was the only governance library without a standalone `audit.rs`. The `PermissionEventType` enum (46 variants across L1/L2/L3) already existed in `store.rs` with `type_name()` and `is_*` classifiers, but was missing the `kind()` method that every other library provides.

**Changes:**

| File | Change |
|------|--------|
| `store.rs` | Added `kind()` method (12 categories: role, grant, access, registration, snapshot, maintenance, analysis, delegation, sod, backend, decision, export, streaming, external, capability) and `is_streaming_event()` classifier |
| `audit.rs` | New module: `PermissionsAuditEvent` (event, actor, timestamp, description), `PermissionsAuditLog` (new, record, events, events_by_kind, since, event_count, Default) |
| `lib.rs` | Added `pub mod audit;` declaration, `PermissionsAuditEvent` and `PermissionsAuditLog` re-exports |

**Test count:** 251 (224→251, +27 new)

### ITEM 2: Compiler test delta investigation

The M10 commit (e308a5b) message claimed 967 compiler tests, but current count is 936 unit + 15 integration = 951. Only one commit since M10 touched compiler source (`src/embedding/tests.rs`, 3 lines changed). Checking out the M10 revision shows the same 936+15 count — the "967" was a miscount in the commit message, not an actual regression. No tests were lost.

### ITEM 3: Stray `rust_out` binary

Deleted `rust_out` binary from workspace root (artifact from `rustc --edition 2024` one-off compilation). Added `rust_out` to `.gitignore` to prevent recurrence.
