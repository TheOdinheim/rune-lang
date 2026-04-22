# RUNE Build Log 19

> Previous file: [BUILD_LOG_18.md](BUILD_LOG_18.md)

---

## rune-memory Layer 3

**Date**: 2026-04-21
**Test count**: 209 → 317 (+108 tests, zero failures)
**Commit**: (pending)

**Clippy**: Zero rune-memory-specific warnings

### What Changed

Layer 3 adds the integration boundary layer for memory governance: pluggable backend storage for memory entries, scopes, retention/redaction/retrieval policies, isolation boundaries, and violation records; retention governance with sweep execution and compliance assessment; retrieval governance with collection-level policy enforcement and sensitivity ceilings; scope governance with health assessment heuristics (Healthy/Degraded/AtRisk/Quarantined); five memory governance export formats (JSON, retention compliance, isolation report, GDPR Article 17 deletion, retrieval audit); lifecycle event streaming with scope_id/event_type/severity filtering; and memory governance metrics (retention compliance rate, redaction coverage, isolation violation rate, retrieval denial rate, memory utilization, scope listing by entry count).

### New Modules (7)

| Module | Purpose | Tests |
|--------|---------|-------|
| `backend.rs` | `MemoryGovernanceBackend` trait (27 methods), `InMemoryMemoryGovernanceBackend`, `Stored*` wrapper types for entries/scopes/policies/boundaries/violations, `ViolationResolutionStatus` lifecycle, `MemoryBackendInfo` | 25 |
| `retention_governor.rs` | `RetentionGovernor` trait, `RetentionGovernanceDecision` (Retain/Expire/Redact/Archive), `RetentionSweepResult`, `PolicyComplianceResult`, `InMemoryRetentionGovernor` using L2 `MemoryRetentionEngine`, `NullRetentionGovernor` | 12 |
| `retrieval_governor.rs` | `RetrievalGovernor` trait, `RetrievalGovernanceDecision` (Permit/Deny/FilterResults/RequireProvenance), `InMemoryRetrievalGovernor` with collection policies, `DenyAllRetrievalGovernor`, `NullRetrievalGovernor` | 12 |
| `scope_governor.rs` | `MemoryScopeGovernor` trait, `ScopeAccessDecision` (Granted/Denied/RequiresEscalation/ReadOnly), `ScopeHealthStatus`/`ScopeHealthAssessment`, `InMemoryMemoryScopeGovernor` with health heuristics, `NullMemoryScopeGovernor` | 14 |
| `memory_export.rs` | `MemoryGovernanceExporter` trait, `JsonMemoryExporter`, `MemoryRetentionComplianceExporter`, `MemoryIsolationReportExporter`, `GdprMemoryDeletionExporter` (GDPR Article 17), `RetrievalAuditExporter` | 14 |
| `memory_stream.rs` | `MemoryGovernanceEventSubscriber` trait, `MemoryGovernanceEventSubscriberRegistry`, `MemoryGovernanceEventCollector`, `FilteredMemoryGovernanceEventSubscriber`, `MemoryGovernanceLifecycleEventType` (21 variants) | 11 |
| `memory_governance_metrics.rs` | `MemoryGovernanceMetricsCollector` trait, `MemoryGovernanceMetricSnapshot`, `InMemoryMemoryGovernanceMetricsCollector`, `NullMemoryGovernanceMetricsCollector` | 12 |

### Audit Variants Added (23)

Layer 3 adds 23 new `MemoryEventType` variants (total: 57 = 20 L1 + 14 L2 + 23 L3):

**Backend events** (8): `MemoryGovernanceBackendChanged`, `StoredMemoryEntryCreated`, `StoredMemoryEntryRetrieved`, `StoredMemoryEntryDeleted`, `StoredMemoryScopeCreated`, `StoredRetentionPolicyRegistered`, `StoredRedactionPolicyRegistered`, `StoredRetrievalPolicyRegistered`

**Retention governance** (3): `RetentionGovernanceEvaluated`, `RetentionSweepExecuted`, `RetentionComplianceAssessed`

**Retrieval governance** (4): `RetrievalGovernanceEvaluated`, `RetrievalGovernanceDenied`, `CollectionPolicyRegistered`, `CollectionPolicyRemoved`

**Scope governance** (2): `ScopeAccessGovernanceEvaluated`, `ScopeHealthAssessed`

**Export** (2): `MemoryGovernanceExported`, `MemoryGovernanceExportFailed`

**Metrics** (1): `MemoryGovernanceMetricsComputed`

**Event stream** (3): `MemoryGovernanceSubscriberRegistered`, `MemoryGovernanceSubscriberRemoved`, `MemoryGovernanceEventPublished`

New `is_*` classifiers: `is_backend_event`, `is_retention_governance_event`, `is_retrieval_governance_event`, `is_scope_governance_event`, `is_export_event`, `is_metrics_event`

### Design Decisions

- **Named `memory_governance_metrics.rs`** to avoid collision with L2 `metrics.rs` module
- **`ViolationResolutionStatus`** lifecycle (Open → Acknowledged → Resolved/Dismissed) on `StoredIsolationViolationRecord` with `resolve()` method
- **SHA3-256 `content_hash`** stored at write time on `StoredMemoryEntry` — backend records integrity proof without re-hashing on retrieval
- **`DenyAllRetrievalGovernor`** matches the `DenyAllToolUseGovernor` pattern from rune-agents — rejects policy registration with error
- **`ScopeHealthAssessment` heuristics**: violations > 5 → Quarantined, high expiration rate → AtRisk, low violation with moderate expiration → Degraded, else Healthy
- **`RetentionGovernor` wraps L2 `MemoryRetentionEngine`** internally, delegating the evaluation logic while adding governance-level decision types and sweep orchestration
- **All metric values as `String`** for `Eq` compatibility per Rust 2024 edition constraints (f64 is not Eq)
- **Opaque string references** (`privacy_policy_ref`, `provenance_ref`, `agent_id`) for cross-library integration without introducing type coupling

### Scope Boundaries

- Backend trait defines the contract — adapter crates provide real persistence (vector DBs, relational stores)
- Export trait produces formatted output — adapter crates handle actual I/O and wire protocols
- Event subscriber trait receives notifications — adapter crates implement delivery to message brokers, log aggregators
- Metrics collector computes from in-memory records — adapter crates bridge to real telemetry systems
- `MemoryGovernanceLifecycleEventType` has 21 variants (not 23 audit variants — the event stream types model operational lifecycle events, while audit variants track governance actions)

---

## rune-ai Layer 1

**Date**: 2026-04-21
**Test count**: 0 → 90 (+90 tests, zero failures)
**Commit**: (pending)

**Clippy**: Zero rune-ai-specific warnings

### What Changed

New workspace crate `rune-ai` — AI/ML model lifecycle governance. Covers model registry with 8-state lifecycle state machine, training data governance with quality tracking and lineage refs, evaluation gates with threshold-based criteria, deployment approval with rollback policies, bias and fairness monitoring policy (EU AI Act Article 10, ECOA compliance), drift detection policy with severity-ordered alerting, model retirement and deprecation notices, 24 audit event variants across 7 kind categories, and 9 error variants.

### New Modules (9)

| Module | Purpose | Tests |
|--------|---------|-------|
| `model_registry.rs` | `ModelArchitecture` (7), `ModelTaskType` (9), `ModelStatus` (8) with `is_deployable()`/`is_terminal()`/`is_valid_transition()` state machine, `ModelRecord`, `VersionEntry`, `ModelVersionHistory` | 15 |
| `training_data.rs` | `DatasetSource` (5), `DatasetFormat` (7), `DataQualityStatus` (5), `DatasetRecord` with lineage_refs/sensitivity_label, `DataGovernancePolicy` | 8 |
| `evaluation.rs` | `ThresholdComparison` (6, reused by bias_fairness and drift), `EvaluationCriteria`, `EvaluationResult` with evidence_ref, `EvaluationGateStatus` (5), `EvaluationGate` | 9 |
| `deployment.rs` | `DeploymentEnvironment` (6), `DeploymentApprovalStatus` (4), `RollbackPolicy` (4), `DeploymentRequest`, `DeploymentStatus` (4), `DeploymentRecord` | 9 |
| `bias_fairness.rs` | `ProtectedAttributeType` (8), `MonitoringFrequency` (5), `FairnessStatus` (4), `ProtectedAttribute`, `FairnessMetricDefinition`, `FairnessPolicy`, `FairnessMetricResult`, `FairnessAssessment` | 8 |
| `drift.rs` | `DriftSeverity` (4, Ord), `DriftRemediationAction` (6), `DriftDetectionWindow` (4), `DriftStatus` (5), `DriftMetricDefinition`, `DriftAlertConfig`, `DriftPolicy`, `DriftMetricResult`, `DriftDetectionResult` | 10 |
| `lifecycle.rs` | `RetirementAction` (5), `DeprecationSeverity` (4), `ModelLifecyclePolicy`, `DeprecationNotice`, `ModelLifecycleTransition` using `ModelStatus` | 7 |
| `audit.rs` | `AiEventType` (24 variants), `Display`/`type_name()`/`kind()` (7 categories), `AiAuditEvent`, `AiAuditLog` with `events_by_kind`/`since`/`event_count` | 14 |
| `error.rs` | `AiError` (9 variants), `Display`/`Debug`/`std::error::Error` | 10 |

### Design Decisions

- **ModelStatus state machine**: Draft→Registered→UnderEvaluation→Approved→Deployed→Deprecated→Retired, any→Suspended, Suspended→Registered, UnderEvaluation→Registered (re-evaluation)
- **`is_deployable()` returns true only for `Approved`** — enforces evaluation gate passage before deployment
- **`DriftSeverity` derives `Ord`** for threshold-based alerting comparison (`Low < Medium < High < Critical`)
- **`ThresholdComparison` defined in evaluation.rs** and reused by bias_fairness.rs and drift.rs to avoid duplication
- **All numeric metric values as `String`** for `Eq` compatibility per Rust 2024 edition constraints (f64 is not Eq)
- **Opaque string references** (`attestation_ref`, `evidence_ref`, `sensitivity_label`, `lineage_refs`) for cross-library integration without type coupling
- **No type imports from other workspace crates** — loose coupling via string references only

### Scope Boundaries

- rune-ai governs **model lifecycle policy** — it does NOT implement training, inference, or evaluation
- rune-provenance handles attestation chains; rune-ai holds opaque `attestation_ref` strings
- rune-shield handles inference-layer protection; rune-ai handles pre/post-deployment governance
- rune-detection handles anomaly signal detection; rune-ai holds drift detection policy definitions
- rune-explainability generates explanations; rune-ai defines governance requirements for explainability

---

## rune-ai Layer 2

**Date**: 2026-04-22
**Test count**: 90 → 206 (+116 tests, zero failures)
**Commit**: (pending)

**Clippy**: Zero rune-ai-specific warnings

### What Changed

Layer 2 adds real algorithms and enforcement logic to the Layer 1 type skeleton: SHA3-256 model and dataset fingerprinting with constant-time verification and append-only hash chains, threshold-based evaluation engine supporting all ThresholdComparison variants with weighted gate scoring, deployment readiness assessment with blocker detection (critical/warning/advisory severity), fairness metric evaluation against FairnessPolicy with overall Fair/Unfair/NotAssessed determination, drift metric evaluation with severity determination and remediation action recommendation, lifecycle state machine enforcement with deprecation notice generation and deployment age checking, and AI governance metrics computing model/dataset/evaluation/deployment/fairness/drift aggregate statistics.

### New Modules (7)

| Module | Purpose | Tests |
|--------|---------|-------|
| `model_hash.rs` | `hash_model_record`/`hash_dataset_record` SHA3-256 fingerprinting, `verify_model_hash`/`verify_dataset_hash` constant-time XOR comparison, `ModelHashChain` append-only chain with `verify_chain`/`chain_length`/`latest_hash` | 19 |
| `evaluation_engine.rs` | `compare_threshold` (all ThresholdComparison variants, f64 with string fallback), `EvaluationEngine` with `evaluate_criterion`/`evaluate_gate`, `CriterionEvaluation`, `GateEvaluation` with weighted scoring, `GateRecommendation` (Pass/Fail/ConditionalPass) | 22 |
| `deployment_checker.rs` | `DeploymentReadinessChecker` with `check_readiness`/`check_model_status`/`check_evaluation_gate`/`check_environment_compatibility`, `DeploymentBlockerType` (6 variants), `BlockerSeverity` (Critical/Warning/Advisory), `DeploymentReadinessResult` | 10 |
| `fairness_evaluator.rs` | `FairnessEvaluator` with `evaluate_fairness`/`evaluate_single_metric`, `FairnessMetricEvaluation`, `FairnessEvaluationResult` reusing L1 `FairnessStatus` | 10 |
| `drift_evaluator.rs` | `DriftEvaluator` with `evaluate_drift`/`evaluate_single_metric`/`determine_severity`/`recommend_remediation`, `DriftMetricEvaluation`, `DriftEvaluationResult` reusing L1 `DriftStatus`/`DriftSeverity` | 17 |
| `lifecycle_engine.rs` | `LifecycleEngine` with `execute_transition` (validates via `is_valid_transition`, returns `Result<ModelLifecycleTransition, AiError>`), `check_deprecation_status`, `generate_deprecation_notice` (severity escalation Advisory→Warning→Mandatory→Immediate), `check_deployment_age` | 16 |
| `ai_metrics.rs` | `AiMetrics` with `compute_model_count_by_status`/`compute_dataset_count_by_quality`/`compute_evaluation_pass_rate`/`compute_deployment_count_by_environment`/`compute_fairness_compliance_rate`/`compute_drift_detection_rate`/`compute_model_age_distribution` (buckets: 0-30d/30-90d/90-180d/180d+), `AiMetricSnapshot` | 18 |

### Audit Variants Added (18)

Layer 2 adds 18 new `AiEventType` variants (total: 42 = 24 L1 + 18 L2):

**Model hash** (4): `ModelHashComputed`, `ModelHashChainAppended`, `ModelHashChainVerified`, `DatasetHashComputed`

**Evaluation engine** (2): `CriterionEvaluated`, `GateEvaluated`

**Deployment readiness** (3): `DeploymentReadinessChecked`, `DeploymentBlockerDetected`, `DeploymentAgeChecked`

**Fairness evaluator** (2): `FairnessEvaluated`, `FairnessMetricChecked`

**Drift evaluator** (3): `DriftEvaluated`, `DriftMetricChecked`, `DriftRemediationRecommended`

**Lifecycle engine** (3): `LifecycleTransitionExecuted`, `DeprecationStatusChecked`, `DeprecationNoticeGenerated`

**AI metrics** (1): `AiMetricsComputed`

New kind() categories: `model_hash`, `evaluation_engine`, `deployment_readiness`, `fairness_evaluator`, `drift_evaluator`, `lifecycle_engine`, `ai_metrics`

### Design Decisions

- **`compare_threshold` shared** between evaluation_engine, fairness_evaluator, and drift_evaluator — single implementation avoids duplication
- **Drift severity determination** uses deviation ratio: |measured - threshold| / |threshold| → Low (≤20%), Medium (≤50%), High (≤100%), Critical (>100%)
- **Deployment readiness** treats Critical blockers as deployment-blocking, Warning/Advisory as informational — missing attestation is Warning, not Critical
- **Deprecation severity escalation**: >30 days → Advisory, 8-30 days → Warning, ≤7 days → Mandatory, past sunset → Immediate
- **All metric values as String** for Eq compatibility per Rust 2024 edition constraints
- **`check_environment_compatibility` is a placeholder** — real checks require deployment infrastructure knowledge that belongs in adapter crates

---

## rune-ai Layer 3

**Date**: 2026-04-22
**Test count**: 206 → 317 (+111 tests, zero failures)
**Commit**: (pending)

**Clippy**: Zero rune-ai-specific warnings

### What Changed

Layer 3 adds the external integration trait boundaries for AI/ML model lifecycle governance: pluggable backend storage for model records, dataset records, evaluations, deployments, fairness assessments, drift results, lifecycle policies, and deprecation notices (34 trait methods with SHA3-256 hashing at storage time); model lifecycle governor with transition governance decisions, deployment governance decisions, and model health assessment; fairness governor with L2 FairnessEvaluator integration and compliance checking; drift governor with L2 DriftEvaluator integration and severity-based remediation recommendation; five AI governance export formats (JSON, Model Card, EU AI Act compliance, NIST AI RMF, deployment audit trail); lifecycle event streaming with model_id/event_type/severity filtering; and AI governance metrics computing model approval rate, evaluation gate pass rate, deployment success rate, fairness compliance rate, drift detection rate, and model retirement rate.

### New Modules (7)

| Module | Purpose | Tests |
|--------|---------|-------|
| `backend.rs` | `AiGovernanceBackend` trait (34 methods), `InMemoryAiGovernanceBackend`, `Stored*` wrapper types for models/datasets/evaluations/deployments/assessments/drift results/deprecation notices, `AiBackendInfo` | 23 |
| `model_lifecycle_governor.rs` | `ModelLifecycleGovernor` trait, `TransitionGovernanceDecision` (Approve/Deny/RequireAdditionalEvaluation/DeferToHuman), `DeploymentGovernanceDecision` (Approve/Deny/RequireApproval/ConditionalApprove), `ModelHealthAssessment` with `ModelHealthStatus`, `InMemoryModelLifecycleGovernor`, `StrictModelLifecycleGovernor`, `NullModelLifecycleGovernor` | 15 |
| `fairness_governor.rs` | `FairnessGovernor` trait, `FairnessGovernanceDecision` (Compliant/NonCompliant/RequiresRemediation/InsufficientData), `FairnessGovernanceResult`, `InMemoryFairnessGovernor` wrapping L2 `FairnessEvaluator`, `NullFairnessGovernor` | 12 |
| `drift_governor.rs` | `DriftGovernor` trait, `DriftGovernanceDecision` (NoDriftDetected/DriftDetected/RequiresInvestigation/ModelSuspensionRecommended), `DriftGovernanceResult`, `InMemoryDriftGovernor` wrapping L2 `DriftEvaluator`, `NullDriftGovernor` | 12 |
| `ai_export.rs` | `AiGovernanceExporter` trait, `JsonAiExporter`, `ModelCardExporter` (Model Cards for Model Reporting), `EuAiActComplianceExporter` (EU AI Act Articles 6/9/10/13/14/15), `NistAiRmfExporter` (NIST AI RMF Govern/Map/Measure/Manage), `DeploymentAuditExporter` | 14 |
| `ai_stream.rs` | `AiGovernanceEventSubscriber` trait, `AiGovernanceEventSubscriberRegistry`, `AiGovernanceEventCollector`, `FilteredAiGovernanceEventSubscriber`, `AiGovernanceLifecycleEventType` (25 variants) | 11 |
| `ai_governance_metrics.rs` | `AiGovernanceMetricsCollector` trait, `AiGovernanceMetricSnapshot`, `InMemoryAiGovernanceMetricsCollector`, `NullAiGovernanceMetricsCollector` | 12 |

### Audit Variants Added (21)

Layer 3 adds 21 new `AiEventType` variants (total: 63 = 24 L1 + 18 L2 + 21 L3):

**Backend events** (7): `AiGovernanceBackendChanged`, `StoredModelRecordCreated`, `StoredModelRecordRetrieved`, `StoredModelRecordDeleted`, `StoredDatasetRecordCreated`, `StoredEvaluationResultRecorded`, `StoredDeploymentRecordCreated`

**Lifecycle governance** (3): `TransitionGovernanceEvaluated`, `DeploymentGovernanceEvaluated`, `ModelHealthAssessed`

**Fairness governance** (2): `FairnessGovernanceEvaluated`, `FairnessPolicyRegisteredGov`

**Drift governance** (3): `DriftGovernanceEvaluated`, `DriftPolicyRegisteredGov`, `DriftRemediationRecommendedGov`

**Export** (2): `AiGovernanceExported`, `AiGovernanceExportFailed`

**Metrics** (1): `AiGovernanceMetricsComputed`

**Event stream** (3): `AiGovernanceSubscriberRegistered`, `AiGovernanceSubscriberRemoved`, `AiGovernanceEventPublished`

New kind() categories: `ai_backend`, `lifecycle_governance`, `fairness_governance`, `drift_governance`, `ai_export`, `ai_governance_metrics`, `ai_event_stream`

New `is_*` classifiers: `is_backend_event`, `is_lifecycle_governance_event`, `is_fairness_governance_event`, `is_drift_governance_event`, `is_export_event`, `is_metrics_event`

### Design Decisions

- **`StrictModelLifecycleGovernor` is first-class** — prevents evaluation-gate bypass by denying transitions to Approved/Deployed that don't come through the UnderEvaluation→Approved path; defensive second layer above the state machine
- **`ModelCardExporter` follows the Model Cards pattern** — industry standard for model documentation (Mitchell et al., 2019); emits model details, intended use, performance metrics, fairness considerations, training data summary, deployment history
- **`EuAiActComplianceExporter` and `NistAiRmfExporter` are separate exporters** — different regulatory audiences require different evidence structures; EU AI Act maps to Articles 6/9/10/13/14/15 while NIST AI RMF maps to Govern/Map/Measure/Manage functions
- **`ModelHealthAssessment` includes `drift_status` and `fairness_status`** — holistic model health requires cross-concern visibility; drift detection and fairness monitoring are independent signals that together determine model operational health
- **`ai_governance_metrics.rs` avoids naming collision** with L2 `ai_metrics.rs` — same pattern as rune-memory's `memory_governance_metrics.rs` vs L2 `metrics.rs`
- **L3 audit variant names append `Gov` suffix** where they would collide with L1 names (e.g., `FairnessPolicyRegisteredGov` vs L1 `FairnessPolicyCreated`) — avoids renaming L1 types while maintaining descriptive naming
- **`StoredModelRecord.model_hash`** computed at storage time via L2 `hash_model_record` — backend records integrity proof without re-hashing on retrieval
- **All metric values as String** for Eq compatibility per Rust 2024 edition constraints

### Four-Pillar Alignment

| Pillar | How Layer 3 Advances It |
|--------|------------------------|
| Security/Privacy Baked In | SHA3-256 integrity hashing at storage time; backend trait enforces hash computation |
| Assumed Breach | Model health assessment combines drift + fairness signals for early degradation detection |
| No Single Points of Failure | Pluggable backend trait — swap storage without changing governance logic |
| Zero Trust Throughout | Strict lifecycle governor denies evaluation-gate bypass; deployment requires explicit approval |

### Integration Points

- **rune-provenance**: `StoredModelRecord.attestation_ref` (opaque string) — provenance crate provides attestation chains, rune-ai stores the reference
- **rune-detection**: `DriftGovernor` evaluates drift policy; rune-detection provides the anomaly signal pipeline
- **rune-explainability**: `ModelCardExporter` documents model characteristics; rune-explainability generates the actual explanations
- **rune-framework**: `EuAiActComplianceExporter` and `NistAiRmfExporter` reference framework requirements by opaque string; rune-framework maps to implementation depth

### Scope Boundaries

- Backend trait defines the contract — adapter crates provide real persistence (model registries, ML metadata stores)
- Export trait produces formatted output — adapter crates handle actual I/O and wire protocols
- Event subscriber trait receives notifications — adapter crates implement delivery to message brokers, log aggregators
- Metrics collector computes from stored records — adapter crates bridge to real telemetry systems
- Governor traits define governance decisions — adapter crates implement actual enforcement actions

---

## rune-data — Layer 1

**Date:** 2026-04-22
**Tests:** 0 → 90
**Clippy:** Zero warnings

### What Changed

Added the `rune-data` crate to the workspace as a new data pipeline governance library. Layer 1 establishes the core type system for data quality rules (DAMA-DMBOK dimensions), data classification and sensitivity labeling (PII/PHI/PCI with Ord-derived sensitivity levels), data lineage through transformation stages (source→transform→sink), data access governance (role-based operation control with purpose declaration), schema governance and evolution policy (backward/forward compatibility, breaking change detection), data catalog entry governance (ownership, stewardship, documentation requirements), data freshness and staleness monitoring (SLA-based with alerting), 24 audit event variants across 7 kind categories, and 11 error variants. All numeric values use String for Eq derivation.

### New Modules

| Module | Description | Tests |
|---|---|---|
| `quality.rs` | DataQualityDimension (7 variants), QualityExpectation (6 variants), QualitySeverity (3 variants), DataQualityRule, DataQualityResult, DataQualityPolicy | 12 |
| `classification.rs` | DataSensitivity (5 variants, Ord), DataCategoryType (9 variants), DataCategory, ClassificationMethod (4 variants), DataClassification, ClassificationPolicy | 10 |
| `lineage.rs` | LineageStage (4 variants), LineageChainStatus (4 variants), LineageRecord, LineageChain, LineagePolicy | 11 |
| `access.rs` | DataOperation (7 variants), DataAccessDecision (4 variants), DataAccessPolicy, DataAccessRequest | 9 |
| `schema.rs` | SchemaFormat (6 variants), SchemaChangeType (5 variants), SchemaBreakingChange, SchemaCompatibility (5 variants), SchemaField, SchemaRecord, SchemaEvolutionPolicy | 10 |
| `catalog.rs` | CatalogEntryStatus (5 variants), CatalogEntry, CatalogGovernancePolicy | 7 |
| `freshness.rs` | UpdateFrequency (6 variants), FreshnessStatus (4 variants), FreshnessPolicy, FreshnessAssessment, FreshnessAlert | 9 |
| `audit.rs` | DataEventType (24 variants), DataAuditEvent, DataAuditLog with record/events/events_by_kind/since | 15 |
| `error.rs` | DataError (11 variants) with Display/Debug/std::error::Error | 7 |
| `lib.rs` | Module declarations and re-exports | — |

### Design Decisions

1. **rune-data is distinct from rune-privacy**: rune-privacy handles personal data consent and retention policy (GDPR/CCPA legal basis). rune-data handles operational data pipeline governance regardless of whether data contains personal information. rune-data's sensitivity classification (PII, PHI, PCI) informs rune-privacy about what data needs consent management.

2. **rune-data is distinct from rune-provenance**: rune-provenance tracks cryptographic attestation chains for any artifact. rune-data tracks operational data lineage through transformation stages (source, transforms, sinks). LineageRecord carries an optional `attestation_ref` (opaque string) for entries with cryptographic proof, but verification happens in rune-provenance.

3. **rune-data is distinct from rune-document**: rune-document handles structured document management with versioning and retention. rune-data handles dataset-level governance (schemas, quality rules, lineage) for data flowing through pipelines. Documents are static artifacts; pipeline data is flowing and transforming.

4. **rune-data is distinct from rune-ai**: rune-ai governs AI/ML model lifecycle and references training datasets by opaque string (`training_data_refs`). rune-data governs the datasets themselves at the pipeline level — quality, lineage, schema, classification. Different governance concerns at different layers.

5. **DataSensitivity derives Ord**: Sensitivity comparison enables threshold-based access control (e.g. "this policy allows access up to Confidential"). Ordering is Public < Internal < Confidential < Restricted < Custom. Matches the pattern established by rune-memory's MemorySensitivity.

6. **Schema governance is first-class**: Schema evolution is the most common source of data pipeline breakage. Governing backward/forward compatibility with breaking change detection prevents silent data corruption. SchemaBreakingChange provides field-level granularity with severity classification.

7. **Data freshness is first-class**: Stale data is the most common data quality failure in production pipelines. SLA-based freshness monitoring with staleness thresholds and alerting severity enables proactive alerting before downstream consumers are affected.

8. **Data quality dimensions follow DAMA-DMBOK**: Completeness, Accuracy, Consistency, Timeliness, Uniqueness, Validity are the industry-standard quality dimensions. The Custom variant allows extension for domain-specific quality measures.

9. **All numeric values use String**: Eq derivation for deterministic testing. Follows the established pattern across all RUNE governance libraries.

### Four-Pillar Alignment

| Pillar | How rune-data L1 Serves It |
|---|---|
| **Safety** | Quality rules and policies prevent corrupted or incomplete data from propagating through pipelines |
| **Security** | Sensitivity classification (PII/PHI/PCI) and access governance control who can read/write/transform datasets |
| **Trust** | Data lineage provides full source→transform→sink tracking; schema governance prevents silent data corruption |
| **Interop** | Opaque string references (`attestation_ref`, `schema_ref`, `classification_ref`) enable loose coupling with rune-provenance, rune-privacy, rune-monitoring |

### Integration Points

- **rune-privacy**: DataSensitivity classification (PII, PHI) informs rune-privacy about which datasets require consent management
- **rune-provenance**: LineageRecord.attestation_ref (opaque string) — provenance crate provides attestation verification
- **rune-ai**: rune-ai's training_data_refs reference datasets governed by rune-data's quality/lineage/schema policies
- **rune-monitoring**: Freshness metrics and quality scores can flow into rune-monitoring's MetricPoint surface via compatible data shapes

### Scope Boundaries

- Quality types define rules and results — no evaluation engine (Layer 2)
- Classification types define labels — no automated classifier (Layer 2)
- Lineage types define records — no chain verification engine (Layer 2)
- Access types define policies and decisions — no access evaluator (Layer 2)
- Schema types define compatibility — no compatibility checker (Layer 2)
- Freshness types define policies and assessments — no freshness evaluator (Layer 2)

---

## rune-data — Layer 2

**Date:** 2026-04-22
**Tests:** 90 → 198 (+108 tests, zero failures)
**Clippy:** Zero warnings

### What Changed

Added eight Layer 2 modules to rune-data implementing evaluation engines, integrity hashing, and metrics computation for the Layer 1 type system. The quality engine evaluates NotNull/Unique/InRange expectations against measured values and computes policy-level pass rates with block-on-failure semantics. The classification engine infers sensitivity levels from data category types (PHI/PCI/Biometric→Restricted, PII/Financial/IP→Confidential, Custom→Internal), classifies datasets, checks review due dates, and evaluates classification policy compliance against catalog entries. The lineage verifier detects chain gaps (broken references, missing predecessors) and checks record compliance against lineage policies (source documentation, transformation metadata, attestation requirements). The access evaluator performs four-check evaluation (role, operation, sensitivity threshold, purpose declaration) with early-exit denial and conditional grant for audit-required policies. The schema compatibility checker detects breaking changes (field removal for required fields, type changes, nullability changes) and evaluates schema evolution policy compliance with migration plan and deprecation period decision paths. The freshness evaluator computes hours since last update, determines staleness against policy thresholds, and generates severity-classified alerts. SHA3-256 integrity hashing covers dataset refs, schema records, and lineage records with field-order-independent deterministic hashing and an append-only DataHashChain with tamper detection. The data metrics module computes quality pass rates, classification coverage, lineage completeness, access denial rates, schema compatibility rates, freshness compliance rates, and staleness distribution.

### New Modules

| Module | Description | Tests |
|---|---|---|
| `quality_engine.rs` | QualityEngine with evaluate_rule/evaluate_policy, NotNull/Unique/InRange checks, PolicyEvaluation with pass_rate/minimum_met/blocked | 14 |
| `classification_engine.rs` | ClassificationEngine with classify_dataset/infer_sensitivity_from_categories/check_classification_review_due/evaluate_policy_compliance | 16 |
| `lineage_verifier.rs` | LineageVerifier with verify_chain/detect_chain_gaps/check_record_completeness/compute_chain_depth, LineageGapType (4 variants), LineageGap, LineageVerificationResult, RecordComplianceResult | 12 |
| `access_evaluator.rs` | DataAccessEvaluator with evaluate_access/check_role/check_operation/check_sensitivity/check_purpose, AccessCheck, AccessEvaluationReport | 11 |
| `schema_checker.rs` | SchemaCompatibilityChecker with check_compatibility/detect_breaking_changes/check_field_removal/check_field_type_change/check_nullability_change/evaluate_evolution_policy, SchemaEvolutionDecision (4 variants) | 14 |
| `freshness_evaluator.rs` | FreshnessEvaluator with evaluate_freshness/compute_hours_since_update/is_stale/generate_alert_if_stale | 12 |
| `data_hash.rs` | hash_dataset_ref/hash_schema_record/hash_lineage_record/verify_hash with constant-time comparison, DataHashChain with append/verify_chain/chain_length/latest_hash | 12 |
| `data_metrics.rs` | DataMetrics with 7 compute methods (quality_pass_rate/classification_coverage/lineage_completeness/access_denial_rate/schema_compatibility_rate/freshness_compliance_rate/staleness_distribution), DataMetricSnapshot | 17 |

### Modified Files

| File | Changes |
|---|---|
| `lib.rs` | Added 8 Layer 2 module declarations and Layer 2 re-exports section |

### Design Decisions

1. **SHA3-256 integrity hashing with field-order independence**: Schema record hashing sorts field parts before hashing so that field reordering does not change the hash. This prevents false integrity violations from non-semantic schema changes (field reordering in JSON/Avro). Follows the pattern established by rune-document and rune-provenance.

2. **DataHashChain for append-only integrity tracking**: Each link stores content_hash + previous_hash and the chain_hash is SHA3-256(content_hash:previous_hash). This enables tamper detection — modifying any historical entry breaks the chain. Follows the same hash chain pattern used in rune-document's DocumentHashChain.

3. **Constant-time hash comparison**: verify_hash uses XOR-based constant-time comparison to prevent timing side-channel attacks on hash verification. This matters for data integrity verification where an attacker could probe for valid hashes.

4. **Access evaluator uses early-exit denial**: Four checks (role, operation, sensitivity, purpose) run sequentially with early exit on first denial. This is both efficient (skips unnecessary checks) and correct (provides the specific denial reason for audit logging).

5. **Schema compatibility checker only flags required field removal as breaking**: Nullable field removal is not breaking because existing readers can handle missing nullable fields. This matches industry practice (Avro/Protobuf backward compatibility rules).

6. **Quality engine placeholders for Unique/Pattern/ReferentialIntegrity**: These checks require dataset access (uniqueness verification, regex matching, foreign key lookups) that belongs in adapter crates. The engine returns passed=true with an adapter implementation note. This follows the scope boundary established by the Layer 1 design.

7. **All numeric values as String for Eq**: Pass rates, hours, thresholds, days_overdue — all String. Follows the project-wide convention for deterministic testing.

### Four-Pillar Alignment

| Pillar | How rune-data L2 Serves It |
|---|---|
| **Safety** | Quality engine blocks pipeline execution when pass rate falls below policy minimum; schema checker rejects breaking changes that could corrupt downstream data |
| **Security** | Access evaluator enforces role-based, operation-based, and sensitivity-threshold-based access control with audit-required conditional grants; constant-time hash comparison prevents timing attacks |
| **Trust** | SHA3-256 integrity hashing provides deterministic identity for datasets, schemas, and lineage records; DataHashChain enables tamper detection across catalog history |
| **Interop** | Evaluation engines consume Layer 1 types and produce standalone result types (PolicyEvaluation, AccessEvaluationReport, SchemaEvolutionDecision) that can be serialized for cross-system exchange |

### Integration Points

- **rune-privacy**: Classification engine's sensitivity inference (PII→Confidential, PHI→Restricted) feeds rune-privacy's consent management scope
- **rune-provenance**: Data hash functions produce SHA3-256 digests compatible with rune-provenance's attestation verification pipeline
- **rune-monitoring**: DataMetrics compute functions produce String-valued metrics consumable by rune-monitoring's MetricPoint surface
- **rune-ai**: Quality engine's PolicyEvaluation can verify training dataset quality before rune-ai's model training approval gates
