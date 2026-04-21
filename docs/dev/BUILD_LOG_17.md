# RUNE Build Log 17

> Previous file: [BUILD_LOG_16.md](BUILD_LOG_16.md)

---

## rune-security Layer 3

**Test count**: 156 → 245 (+89 tests, zero failures)

**Clippy**: Zero rune-security-specific warnings (pre-existing L1/L2 warnings untouched)

### New Modules (7)

| Module | Lines | Tests | Purpose |
|--------|-------|-------|---------|
| `backend.rs` | ~215 | 16 | SecurityPostureBackend trait + InMemorySecurityPostureBackend |
| `vulnerability_tracker.rs` | ~265 | 11 | VulnerabilityLifecycleTracker trait + SLA enforcement |
| `control_framework_mapper.rs` | ~215 | 10 | ControlFrameworkMapper trait + cross-framework mappings |
| `incident_response.rs` | ~290 | 10 | IncidentResponseWorkflow trait + NIST SP 800-61 enforcement |
| `security_export.rs` | ~340 | 14 | SecurityDataExporter trait + 5 format implementations |
| `security_stream.rs` | ~310 | 13 | SecurityEventSubscriber trait + registry + filtering |
| `posture_aggregator.rs` | ~280 | 12 | SecurityPostureAggregator trait + weighted averaging |

### Trait Contracts

- **SecurityPostureBackend**: 23 methods — store/retrieve/delete/list/count for vulnerability records, security control records, incident records, threat model records, posture snapshots, plus flush/backend_info. InMemorySecurityPostureBackend reference implementation. CvssSeverity 5-level enum with from_score_str, VulnerabilityStatus 7-variant enum, ControlImplementationStatus 4-variant enum, IncidentRecordStatus 7-variant enum mirroring NIST SP 800-61. StoredPostureSnapshot with PostureClass 5-variant enum (Strong/Adequate/Weak/Critical/Unknown) following honest-granularity pattern. All f64 subscores stored as String for Eq derivation.
- **VulnerabilityLifecycleTracker**: 10 methods — record_discovery/triage_vulnerability/plan_remediation/mark_remediated/verify_remediation/reopen_vulnerability/list_open_vulnerabilities/list_stale_vulnerabilities/tracker_id/is_active. TriageDecision 4-variant enum (ConfirmAndPrioritize/Dismiss/Defer/EscalateToIncident). TriagePriority 5-level enum. InMemoryVulnerabilityLifecycleTracker. SlaEnforcingVulnerabilityLifecycleTracker with SlaThresholds (Critical: 24h, High: 7d, Medium: 30d, Low: 90d).
- **ControlFrameworkMapper**: 6 methods — map_control/list_supported_frameworks/frameworks_mapping_to/confidence_of_mapping/mapper_id/is_active. MappingConfidence 5-level enum (Exact/Substantial/Partial/Related/Disputed). ControlEquivalence struct with rationale. InMemoryControlFrameworkMapper (linear scan) and TableLookupControlFrameworkMapper (HashMap-based O(1) lookup).
- **IncidentResponseWorkflow**: 12 methods — declare_incident/update_incident_state/record_response_action/record_containment/record_eradication/record_recovery/record_lessons_learned/close_incident/list_active_incidents/list_incidents_by_severity/workflow_id/is_active. IncidentState 7-variant enum with valid_transitions() enforcing NIST SP 800-61 lifecycle ordering (Declared→Triaging→Containing→Eradicating→Recovering→PostIncident→Closed). NistSp80061IncidentResponseWorkflow rejects invalid state transitions.
- **SecurityDataExporter**: 6 methods — export_vulnerability/export_incident/export_posture_snapshot/export_control_implementation/format_name/content_type. Five implementations: JsonSecurityExporter, StixCourseOfActionExporter (STIX 2.1 spec_version), CsafAdvisoryExporter (CSAF VEX category), VexStatementExporter (OpenVEX v0.2.0 with status mapping Remediated→fixed, FalsePositive→not_affected), OcsfSecurityFindingExporter (class_uid 2001). All preserve evidence_attestation_refs.
- **SecurityEventSubscriber**: 3 methods — on_event/subscriber_id/is_active. SecurityEventSubscriberRegistry with register/unregister/publish/subscriber_count/active_subscriber_count. SecurityEventCollector reference implementation. FilteredSecurityEventSubscriber with type/severity/artifact_ref filters. SecurityLifecycleEventType 18-variant enum with VulnerabilitySlaViolated and PostureDegradationDetected as first-class events. Classification methods: is_vulnerability_event/is_incident_event/is_control_event/is_posture_event/is_export_event.
- **SecurityPostureAggregator**: 5 methods — compute_posture_snapshot/compute_posture_delta/configure_weights/aggregator_id/is_active. PostureDelta with PostureChangeDirection (Improved/Degraded/Unchanged). PostureWeights with vulnerability/control/incident/threat_exposure weights as String for Eq. InMemorySecurityPostureAggregator (simple average). WeightedAverageSecurityPostureAggregator (configurable weights, default 0.30/0.25/0.25/0.20).

### Naming Collision Resolutions

- `IncidentStatus` (L1) → L3 uses `IncidentState` for NIST SP 800-61 lifecycle
- `ResponseAction` (L2 enum) → L3 uses `IncidentResponseAction` struct (different shape)
- `VulnStatus` (L1) → L3 uses `VulnerabilityStatus` for backend storage lifecycle
- `SecurityPosture` (L1 struct) → L3 uses `StoredPostureSnapshot` for backend storage
- `IncidentRecordStatus` (backend.rs) mirrors lifecycle states as separate storage-layer type

### Audit Events (+24 variants)

SecurityPostureBackendChanged, VulnerabilityRecorded, VulnerabilityTriaged, VulnerabilityRemediatedL3, VulnerabilityReopened, VulnerabilitySlaViolatedEvent, VulnerabilityStaleDetected, SecurityControlStored, SecurityControlStatusUpdated, ControlFrameworkMappingQueried, IncidentDeclaredL3, IncidentStateTransitioned, IncidentResponseActionRecorded, IncidentClosedL3, ThreatModelRecorded, ThreatModelReviewed, SecurityDataExported, SecurityDataExportFailed, SecuritySubscriberRegistered, SecuritySubscriberRemoved, SecurityEventPublishedEvent, PostureSnapshotCaptured, PostureDeltaComputed, PostureDegradationDetectedEvent

Classification methods: is_backend_event, is_vulnerability_event, is_control_event, is_incident_event, is_export_event, is_posture_event

### Integration Points

- **rune-provenance**: Loose coupling via opaque `evidence_attestation_refs: Vec<String>` on vulnerability and control records, preserved through all export formats
- **rune-framework**: PostureClass/PostureChangeDirection available for Layer 5 governance pipeline integration
- **rune-truth**: Follows same backend/export/stream/aggregator patterns

---

## Naming Discipline Correction — rune-truth classifiers

**Date**: 2026-04-20

### Renamed Methods

| Old name | New name | Rationale |
|----------|----------|-----------|
| `is_l3_claim_event` | `is_backend_claim_event` | House style requires descriptive qualifiers, not layer-number prefixes. The method selects events about claims flowing through the backend. |
| `is_l3_contradiction_event` | `is_contradiction_relation_event` | Captures the relational nature of the events (relationships between claims), not the layer they were introduced in. |

Test function `test_layer3_classification_methods` renamed to `test_classification_methods`.

**Test count**: 236 — unchanged before and after rename.

**Note**: The original rune-truth Layer 3 entry in BUILD_LOG_16.md remains in place for historical accuracy. This correction supersedes the old names; the original entry documents what shipped and this entry documents what was corrected.

---

## Naming Discipline Correction — rune-security audit variants

**Date**: 2026-04-20

### Renamed Variants

| Old name | New name | Rationale |
|----------|----------|-----------|
| `VulnerabilityRemediatedL3` | `BackendVulnerabilityRemediated` | `Backend` prefix follows the same convention as `BackendSessionCreated` in rune-web — describes the origin (backend operation), not the layer number. |
| `IncidentDeclaredL3` | `BackendIncidentDeclared` | Same rationale. The `L3` suffix was a layer-number qualifier; `Backend` is a descriptive qualifier. |
| `IncidentClosedL3` | `BackendIncidentClosed` | Same rationale. |

All occurrences updated in `audit.rs`: enum variant definitions, `kind()` match arms, `Display` impl match arms, `is_vulnerability_event`/`is_incident_event` classification methods, and test assertions.

**Test count**: 245 — unchanged before and after rename.

**Note**: The original rune-security Layer 3 entry earlier in this file lists the old variant names in the "Audit Events" section. That entry remains in place for historical accuracy. This correction supersedes the old names. This completes the naming discipline correction pass across rune-truth and rune-security, re-establishing the house style convention that all subsequent libraries (rune-monitoring onward) must follow: descriptive qualifiers only, no layer-number prefixes or suffixes.

---

## rune-monitoring Layer 3

**Test count**: 148 → 241 (+93 tests, zero failures)

**Clippy**: Zero rune-monitoring-specific warnings (pre-existing L1/L2 warnings untouched)

### New Modules (7)

| Module | Lines | Tests | Purpose |
|--------|-------|-------|---------|
| `backend.rs` | ~600 | 20 | MonitoringBackend trait + InMemoryMonitoringBackend |
| `metric_aggregator.rs` | ~420 | 14 | MetricAggregator trait + InMemoryMetricAggregator + StreamingMetricAggregator |
| `trace_context.rs` | ~415 | 12 | TraceContextPropagator trait + W3C/B3/Multi propagators |
| `log_ingestion.rs` | ~420 | 14 | StructuredLogIngestor trait + Logfmt/Syslog/JsonLines/Null ingestors |
| `telemetry_export.rs` | ~430 | 13 | TelemetryExporter trait + 7 format implementations |
| `monitoring_stream.rs` | ~380 | 13 | TelemetryEventSubscriber trait + registry + filtering |
| `health_check.rs` | ~280 | 13 | HealthCheckProbe trait + Composite/DependencyAware/Null probes |

### Trait Contracts

- **MonitoringBackend**: 23 methods — store/retrieve/delete/list/count for metric series, trace spans/traces, log records, health check results, alert rules, plus flush/backend_info. InMemoryMonitoringBackend reference implementation. MetricKind 4-variant enum (Counter/Gauge/Histogram/Summary). SpanStatus 3-variant enum (Ok/Error/Unset). LogSeverity 6-level enum (Trace/Debug/Info/Warn/Error/Fatal) with Ord derivation. MetricPoint.value as String for Eq derivation, compatible shape with rune-detection's TimeSeriesPoint (timestamp i64, value String, labels HashMap<String,String>). StoredHealthCheckResult with response_time as String for Eq.
- **MetricAggregator**: 5 methods — aggregate_window, downsample, compute_percentiles, aggregator_id, is_active. AggregationFunction 12-variant enum (Sum/Mean/Min/Max/Count/First/Last/P50/P75/P90/P95/P99). AggregatedMetricWindow with aggregated_value as String for Eq. PercentileSummary (p50/p75/p90/p95/p99 all as String). InMemoryMetricAggregator recomputes from stored points. StreamingMetricAggregator for incremental updates with ingest_point/streaming_value/reset and internal StreamingState.
- **TraceContextPropagator**: 4 methods — inject_context, extract_context, supported_formats, propagator_id. PropagationFormat 5-variant enum (W3cTraceContext/B3Single/B3Multi/Jaeger/Custom). TraceContext struct: trace_id, span_id, sampled, trace_flags, tracestate HashMap. Carrier trait for transport abstraction. W3cTraceContextPropagator (traceparent/tracestate). B3Propagator (single header + multi headers). MultiFormatPropagator injects all formats, extracts from first match.
- **StructuredLogIngestor**: 6 methods — ingest_log, ingest_batch, parse_log_line, supported_formats, ingestor_id, is_active. StructuredLogRecord follows ECS shape (timestamp, severity, service_name, message, fields HashMap). LogLineFormat 6-variant enum (EcsJson/LogfmtLine/SyslogRfc5424/CommonLogFormat/JsonLines/OtelLogRecord). IngestResult tracks ingested/failed counts. LogfmtIngestor with proper quoted-value parsing. SyslogRfc5424Ingestor with RFC 5424 priority-to-severity mapping. JsonLinesIngestor using serde_json. NullLogIngestor for testing.
- **TelemetryExporter**: 5 methods — export_metrics, export_traces, export_logs, format_name, content_type. Seven implementations: OtlpMetricsExporter (OTLP JSON with resourceMetrics/resourceSpans/resourceLogs envelopes), PrometheusExpositionExporter (text/plain; version=0.0.4), OpenMetricsExporter (application/openmetrics-text; version=1.0.0 with # EOF), JaegerThriftExporter (Jaeger JSON with processes), ZipkinV2Exporter (Zipkin v2 JSON spans with localEndpoint), EcsLogExporter (ECS 8.11), SplunkHecExporter (configurable sourcetype). All produce Vec<u8> — protobuf wire format belongs in adapter crates.
- **TelemetryEventSubscriber**: 3 methods — on_event, subscriber_id, is_active. TelemetryEventSubscriberRegistry with register/unregister/publish/subscriber_count/active_subscriber_count. TelemetryEventCollector reference implementation. FilteredTelemetryEventSubscriber with category/service_name/severity filters. TelemetryLifecycleEventType 16-variant enum with classification methods: is_metric_event, is_trace_event, is_log_event, is_health_event, is_alert_event, is_export_event.
- **HealthCheckProbe**: 4 methods — probe, probe_kind, probe_id, is_active. ProbeKind 3-variant enum matching Kubernetes semantics (Liveness/Readiness/Startup). HealthProbeStatus 4-variant enum (Healthy/Unhealthy/Degraded/Unknown). HealthProbeResult with response_time as String for Eq. CompositeHealthCheckProbe aggregates multiple probes with worst-status semantics. DependencyAwareHealthCheckProbe checks dependency first. NullHealthCheckProbe for testing.

### Naming Collision Resolutions

- `HealthCheckResult` (L1 in health.rs) → L3 uses `StoredHealthCheckResult` for backend storage, `HealthProbeResult` for probe results
- `HealthStatus` (L1 enum) → L3 uses `HealthProbeStatus` for probe-specific status
- `Histogram` (L2 struct in metric.rs) → L3 `MetricKind::Histogram` is an enum variant, not a struct collision

### Audit Events (+24 variants)

MonitoringBackendChanged, MetricSeriesStored, MetricSeriesDeleted, MetricWindowAggregated, MetricDownsampled, StreamingMetricUpdated, TraceSpanStored, TraceStored, TraceContextInjected, TraceContextExtracted, LogRecordStored, LogLineIngested, LogLineParseFailed, HealthProbeExecuted, HealthProbeFailed, CompositeProbeEvaluated, AlertRuleStored, AlertRuleTriggered, AlertRuleResolved, TelemetryExported, TelemetryExportFailed, TelemetrySubscriberRegistered, TelemetrySubscriberRemoved, TelemetryEventPublished

Classification methods on MonitoringEventType: kind(), is_backend_event, is_metric_event, is_trace_event, is_log_event, is_health_probe_event, is_alert_event, is_export_event

### Design Decisions

- **MetricPoint.value as String**: Follows the value-as-String pattern established across all RUNE backends for Eq derivation. Compatible shape with rune-detection's TimeSeriesPoint (timestamp i64, value String, labels HashMap<String,String>) so monitoring telemetry flows naturally into detection.
- **StreamingMetricAggregator**: Separate from InMemoryMetricAggregator because incremental aggregation of high-cardinality metric streams requires fundamentally different state management (running count/sum/min/max vs recomputing from stored points).
- **W3C Trace Context as default**: Industry-standard propagation format. MultiFormatPropagator writes all formats on injection and tries each on extraction for maximum interoperability with existing infrastructure.
- **ProbeKind matches Kubernetes semantics**: Liveness (is the process alive?), Readiness (can it accept traffic?), Startup (has it finished initialising?). These map directly to Kubernetes probe types.
- **7 telemetry exporters**: More than other libraries due to the observability standards surface area. All produce Vec<u8> UTF-8 text — actual protobuf wire format belongs in adapter crates, not the trait boundary.
- **OTLP as JSON, not protobuf**: The TelemetryExporter trait produces serialized bytes. OTLP structures are emitted as JSON following the OTLP/HTTP JSON encoding. Protobuf wire format requires protobuf compilation infrastructure that belongs in connector/adapter crates.
- **Scope boundary with rune-detection**: Data flow interop via compatible MetricPoint/TimeSeriesPoint shape, no trait coupling. Monitoring publishes metrics that detection can consume.
- **Scope boundary with rune-audit-ext**: Monitoring handles operational telemetry (metrics, traces, logs). rune-audit-ext handles forensic integrity (tamper-evident audit trails).

### Integration Points

- **rune-detection**: MetricPoint shape (timestamp i64, value String, labels HashMap) is compatible with TimeSeriesPoint for downstream anomaly detection
- **rune-framework**: TelemetryLifecycleEventType and MonitoringBackendInfo available for Layer 5 governance pipeline integration
- **rune-security**: Follows same backend/export/stream patterns established in rune-security L3

---

## rune-explainability Layer 3

**Test count**: 159 → 240 (+81 tests, zero failures)

**Clippy**: Zero rune-explainability-specific warnings (pre-existing L1/L2 warnings untouched)

### New Modules (7)

| Module | Lines | Tests | Purpose |
|--------|-------|-------|---------|
| `backend.rs` | ~600 | 16 | ExplanationBackend trait + InMemoryExplanationBackend |
| `reasoning_trace.rs` | ~340 | 9 | ReasoningTraceRecorder trait + InMemoryReasoningTraceRecorder + DepthLimitedReasoningTraceRecorder |
| `feature_attribution.rs` | ~420 | 8 | FeatureAttributionExplainer trait + LinearCoefficientExplainer + PermutationImportanceExplainer |
| `counterfactual_example.rs` | ~400 | 10 | CounterfactualExampleGenerator trait + NearestNeighborCounterfactualGenerator + FeaturePerturbationCounterfactualGenerator |
| `explanation_export.rs` | ~570 | 14 | ExplanationExporter trait + 5 format implementations |
| `explanation_stream.rs` | ~310 | 12 | ExplanationEventSubscriber trait + registry + filtering |
| `explanation_quality.rs` | ~310 | 10 | ExplanationQualityAssessor trait + StructuralFaithfulnessAssessor + ReadabilityAssessor |

### Trait Contracts

- **ExplanationBackend**: 23 methods — store/retrieve/delete/list/count for explanations, reasoning traces, feature attribution sets, counterfactual examples, rule firing records, plus flush/backend_info. SubjectIdRef newtype for opaque subject references (model prediction, policy decision, claim). ExplanationType 5-variant enum (FeatureAttribution/ReasoningTrace/Counterfactual/RuleBased/Composite). InMemoryExplanationBackend reference implementation. All f64 fields stored as String for Eq derivation.
- **ReasoningTraceRecorder**: 7 methods — begin_trace/record_step/record_conclusion/get_trace/list_active_traces/recorder_id/is_active. StepType 6-variant enum (Premise/Inference/RuleMatch/Query/Assumption/Constraint). ReasoningStep builder pattern with with_input/with_output. InMemoryReasoningTraceRecorder with auto-incrementing trace IDs. DepthLimitedReasoningTraceRecorder composable depth enforcement matching rune-provenance's DepthLimitedLineageTracker pattern.
- **FeatureAttributionExplainer**: 5 methods — compute_attributions/supported_attribution_methods/attribution_method_used/explainer_id/is_active. ExplainerAttributionMethod 8-variant enum (Shap/Lime/IntegratedGradients/GradCam/PermutationImportance/LinearCoefficients/TreeSplit/Custom). FeatureAttributionRecord with String values for Eq. LinearCoefficientExplainer (coefficient * feature value, sorted by magnitude). PermutationImportanceExplainer (uniform distribution of output diff from baseline). NullFeatureAttributionExplainer. SHAP/LIME belong in adapter crates.
- **CounterfactualExampleGenerator**: 4 methods — generate_counterfactuals/generator_id/supports_target_outcome/is_active. CounterfactualExample with distance_from_original as String. ActionableChange with constrained bool for immutable attributes (age, protected characteristics). ChangeDirection 3-variant enum (IncreaseRequired/DecreaseRequired/DiscreteChangeRequired). NearestNeighborCounterfactualGenerator (Euclidean distance, top-3). FeaturePerturbationCounterfactualGenerator (single-feature delta). NullCounterfactualExampleGenerator.
- **ExplanationExporter**: 5 methods — export_explanation/export_batch/export_explanation_with_subject_context/format_name/content_type. Five implementations: JsonExplanationExporter, GdprArticle22Exporter (GDPR Article 22 right to explanation with right_to_contest/right_to_human_review), EcoaAdverseActionExporter (ECOA adverse action notices with max 4 principal_reasons), W3cProvPredicateExporter (W3C PROV with prov:qualifiedInfluence), MarkdownExplanationExporter. All include confidence_score and generator_id.
- **ExplanationEventSubscriber**: 3 methods — on_explanation_event/subscriber_id/is_active. ExplanationEventSubscriberRegistry with register/notify/notify_batch/active_count/remove_inactive. ExplanationEventCollector reference implementation. FilteredExplanationEventSubscriber with explanation_type/generator_id/confidence threshold filters. ExplanationLifecycleEventType 16-variant enum with is_trace_event/is_attribution_event/is_counterfactual_event/is_quality_event/is_export_event/is_lifecycle_event classifiers.
- **ExplanationQualityAssessor**: 3 methods — assess_quality/assessor_id/is_active. QualityAssessment with four-dimensional scoring (faithfulness/stability/comprehensibility/actionability all as String for Eq). OverallQualityClass 4-variant enum (Excellent/Adequate/Poor/Unknown). StructuralFaithfulnessAssessor (non-empty factors, confidence parsing, summary length, direction coverage). ReadabilityAssessor (configurable max_factor_count/max_summary_words). NullExplanationQualityAssessor.

### Naming Collision Resolutions

- `counterfactual.rs` (L1 module) → L3 uses `counterfactual_example.rs`
- `CounterfactualGenerator` (L1 struct) → L3 uses `CounterfactualExampleGenerator` trait
- `AttributionMethod` (L2 enum, 5 variants) → L3 uses `ExplainerAttributionMethod` (8 variants)
- `FeatureAttribution` (L2 struct, f64 fields) → L3 uses `FeatureAttributionRecord` (String fields for Eq)
- `AttributionDirection` (L2) → L3 uses `AttributionValueDirection`
- `CounterfactualGenerated` (L1 audit variant) → L3 uses `BackendCounterfactualGenerated`
- `FeatureAttributionComputed` (L2 audit variant) → L3 uses `BackendFeatureAttributionComputed`

### Audit Events (+19 variants)

ExplanationBackendChanged, ExplanationStored, ExplanationRetrieved, ExplanationExported, ExplanationExportFailed, ReasoningTraceBegun, ReasoningStepRecorded, ReasoningTraceCompleted, ReasoningTraceAbandoned, BackendFeatureAttributionComputed, FeatureAttributionFailed, BackendCounterfactualGenerated, CounterfactualGenerationFailed, RuleFiringRecorded, ExplanationQualityAssessed, ExplanationQualityBreached, ExplanationSubscriberRegistered, ExplanationSubscriberRemoved, ExplanationEventPublished

Classification methods on ExplainabilityEventType: kind(), is_backend_event, is_trace_event, is_attribution_event, is_counterfactual_event, is_quality_event, is_export_event

### Design Decisions

- **No general-purpose model interpretability**: SHAP/LIME/integrated-gradients require optimization solvers and sampling infrastructure that belong in adapter crates, not the trait boundary. Only LinearCoefficientExplainer and PermutationImportanceExplainer are shipped as reference implementations.
- **Four-dimensional quality assessment**: Faithfulness, stability, comprehensibility, and actionability from the explainability literature. StructuralFaithfulnessAssessor and ReadabilityAssessor use structural proxies; full semantic assessment requires model-specific adapters.
- **ActionableChange.constrained**: Surfaces whether a suggested counterfactual change involves an immutable attribute (age, protected characteristics) — critical for fair lending and hiring contexts.
- **GDPR Article 22 and ECOA adverse action formats**: Regulated contexts where automated decision explanations have specific legal requirements. ECOA limits to 4 principal reasons per regulation.
- **DepthLimitedReasoningTraceRecorder**: Composable depth enforcement matching rune-provenance's DepthLimitedLineageTracker pattern for adversarially deep reasoning graphs.
- **SubjectIdRef newtype**: Opaque reference to the subject of an explanation — could be a model prediction, authorization decision, or truth claim. Enables cross-library integration without trait coupling.
- **ExplainerAttributionMethod distinct from L2 AttributionMethod**: L2's enum is for scoring/analysis (Shapley/Gradient/Perturbation/RuleBased/Manual); L3's enum names specific ML explainability techniques (Shap/Lime/IntegratedGradients/GradCam/PermutationImportance/LinearCoefficients/TreeSplit/Custom).

### Integration Points

- **rune-detection**: ExplanationBackend stores explanations for model predictions via SubjectIdRef
- **rune-permissions**: Authorization decision explanations via SubjectIdRef
- **rune-truth**: Claim justification explanations via SubjectIdRef
- **rune-provenance**: DepthLimitedReasoningTraceRecorder follows DepthLimitedLineageTracker pattern
- **rune-framework**: ExplanationLifecycleEventType and ExplanationBackendInfo available for Layer 5 governance pipeline integration

---

## rune-document Layer 3

**Test count**: 151 → 246 (+95 tests, zero failures)

### New Modules

| Module | Primary types |
|---|---|
| `backend.rs` | `DocumentBackend` trait (21 methods), `StoredDocumentCategory` (9 variants), `ClassificationLevel` (5 variants), `StoredDocumentRecord`, `StoredDocumentVersion`, `StoredContentBlob`, `StoredDocumentRetentionRecord`, `DocumentBackendInfo`, `InMemoryDocumentBackend` |
| `document_export.rs` | `DocumentExporter` trait (5 methods), `ExportableDocument`, `JsonDocumentExporter`, `PdfAExporter` (ISO 19005-3), `DitaTopicExporter` (OASIS DITA 1.3), `DocbookExporter` (DocBook 5.1), `AtomFeedExporter` (RFC 4287 Atom 1.0) |
| `content_ingestion.rs` | `ContentIngestor` trait (5 methods), `ContentSourceFormat` (10 variants), `NormalizedContent`, `MarkdownContentIngestor`, `PlainTextContentIngestor`, `HtmlContentIngestor` (entity decoding + whitespace collapse), `NullContentIngestor` |
| `version_control.rs` | `DocumentVersionController` trait (8 methods), `FieldChangeType` (3 variants), `MetadataFieldChange`, `ChronologicalOrder`, `VersionComparison`, `DocumentTag`, `InMemoryDocumentVersionController` (lineage chain), `LinearDocumentVersionController` (rejects branching), `NullDocumentVersionController` |
| `retention_integration.rs` | `RetentionPolicyLinker` trait (8 methods), `DisposalEligibility` (4 variants), `DisposalRecord` (reuses L2 `DisposalMethod`), `InMemoryRetentionPolicyLinker`, `LegalHoldAwareRetentionPolicyLinker` (composable wrapper blocking disposal under hold), `NullRetentionPolicyLinker` |
| `document_stream.rs` | `DocumentEventSubscriber` trait (3 methods), `DocumentEventSubscriberRegistry` (register/notify/notify_batch/active_count/remove_inactive), `DocumentEventCollector`, `FilteredDocumentEventSubscriber` (category/classification/event-type filters), `DocumentLifecycleEvent`, `DocumentLifecycleEventType` (18 variants) |
| `content_format_converter.rs` | `ContentFormatConverter` trait (4 methods), `ConversionPair`, `MarkdownToHtmlConverter` (headings/paragraphs/emphasis/code blocks/lists/links/images), `HtmlToPlainTextConverter` (tag stripping + entity decoding), `NullContentFormatConverter` |

### Audit Changes

22 new `DocumentEventType` variants: `DocumentBackendChanged`, `DocumentRecordStored`, `DocumentRecordRetrieved`, `DocumentRecordDeleted`, `DocumentVersionStored`, `ContentBlobStored`, `DocumentMetadataSearched`, `DocumentExported`, `DocumentExportFailed`, `ContentIngested`, `ContentIngestionFailed`, `VersionControllerActionPerformed`, `DocumentTagCreated`, `VersionComparisonComputed`, `RetentionPolicyLinked`, `RetentionPolicyUnlinked`, `DocumentDisposalRecorded`, `ContentFormatConverted`, `ContentFormatConversionFailed`, `DocumentSubscriberRegistered`, `DocumentSubscriberRemoved`, `DocumentEventPublished`.

Public `kind()` method and 6 classification methods: `is_backend_event`, `is_version_event`, `is_retention_event`, `is_ingestion_event`, `is_conversion_event`, `is_export_event`.

### Error Changes

Two new `DocumentError` variants: `SerializationFailed(String)`, `VersionNotFound(String)`.

### Naming Collision Resolution

| L2 type | L3 type | Rationale |
|---|---|---|
| `DocumentCategory` (sensitivity domains) | `StoredDocumentCategory` (functional purpose) | L2 classifies by data sensitivity; L3 categorizes for storage/retrieval |
| `SensitivityLevel` (with Ord scoring) | `ClassificationLevel` (storage label) | L2 drives risk calculations; L3 drives access control labels |
| `MetadataChangeType` (nested enums) | `FieldChangeType` (flat for Eq) | L3 flattened to derive Eq for backend compatibility |
| `MetadataChange` | `MetadataFieldChange` | Follows `FieldChangeType` renaming |
| `DocumentRetentionRecord` (L2) | `StoredDocumentRetentionRecord` (L3) | `Stored*` prefix for backend-persisted types |

### Design Decisions

- **DisposalMethod reused from L2**: `retention_integration.rs` imports `crate::retention::DisposalMethod` rather than duplicating the enum. DisposalRecord at L3 composes with the L2 enum.
- **LinearDocumentVersionController**: Wraps InMemoryDocumentVersionController and rejects version creation when a different version already exists for the document — enforces linear history for regulated environments.
- **LegalHoldAwareRetentionPolicyLinker**: Composable wrapper that short-circuits disposal eligibility to `OnLegalHold` and blocks `record_disposal` when a hold is active.
- **ContentIngestor scope**: Only Markdown, PlainText, and HTML ingestors shipped. PDF text extraction, DOCX parsing, and email MIME parsing require full format libraries belonging in adapter crates.
- **MarkdownToHtmlConverter**: Handles headings, paragraphs, emphasis, bold, inline code, fenced code blocks, unordered lists, links, and images using let-chains for Rust 2024 edition.
- **PDF/A, DITA, DocBook, Atom exporters**: Generate standard-conformant document structures (ISO 19005-3, OASIS DITA 1.3, DocBook 5.1, RFC 4287) with attestation_refs and retention_policy_ref preserved.

### Integration Points

- **rune-privacy**: DisposalRecord.retention_policy_ref is an opaque string for cross-library coupling with rune-privacy retention policies
- **rune-provenance**: ExportableDocument.attestation_refs preserved across all export formats for provenance chain continuity
- **rune-framework**: DocumentLifecycleEventType and DocumentBackendInfo available for Layer 5 governance pipeline integration

---

## rune-policy-ext — Layer 3

**Test count**: 140 → 235 (+95)

### Scope Boundary

rune-policy-ext handles policy packaging, versioning, distribution, and composition. It does NOT contain the decision engine — that belongs in rune-permissions. The `ExternalEvaluatorIntegration` trait only prepares, submits, and fetches evaluation results; no actual OPA/Cedar/XACML evaluation calls live here.

### New Modules

| Module | Key types |
|---|---|
| `backend.rs` | `PolicyPackageBackend` trait (17 methods), `StoredPolicyPackage` (11 fields), `PackageDependency`, `StoredRuleSet`, `StoredPolicyEvaluationRecord` (duration as String for Eq), `StoredPackageSignature`, `PolicyPackageBackendInfo`, `InMemoryPolicyPackageBackend` |
| `package_composer.rs` | `PolicyPackageComposer` trait (5 methods), `PackageCompositionStrategy` (Union/Intersection/Override/Explicit), `PackagePolicyConflict`, `PackageConflictCategory` (3 variants), `PackageConflictResolutionStrategy` (4 variants), `ComposedPackage`, `InMemoryPolicyPackageComposer` (heuristic overlap), `UnionPolicyPackageComposer`, `OverridePolicyPackageComposer`, `NullPolicyPackageComposer` |
| `package_registry.rs` | `PolicyPackageRegistry` trait (8 methods), `RegistryCredentials`, `PackageQuery` (builder pattern), `SubscriptionHandle`, `InMemoryPolicyPackageRegistry` (soft-delete), `ReadOnlyPolicyPackageRegistry<R>` (rejects writes), `CachedPolicyPackageRegistry<R>` (bounded cache, hit_rate), `NullPolicyPackageRegistry` |
| `policy_export.rs` | `PolicyPackageExporter` trait (5 methods), `JsonPolicyPackageExporter`, `OpaBundleExporter` (OPA bundle manifest with roots/revision), `CedarPolicyExporter` (Cedar @id annotations), `SignedBundleManifestExporter` (SHA256 file hashes), `XacmlPolicySetExporter` (XACML 3.0 PolicySet with deny-overrides) |
| `external_evaluator_integration.rs` | `ExternalEvaluatorIntegration` trait (7 methods), `EvaluatorType` (OpaRego/Cedar/XacmlPdp/InternalRune/Custom), `EvaluationPayload`, `EvaluationHandle`, `EvaluationResult`, `InMemoryExternalEvaluatorIntegration` (echo-loop), `NullExternalEvaluatorIntegration` |
| `policy_stream.rs` | `PolicyLifecycleEventSubscriber` trait (3 methods), `PolicyLifecycleEventSubscriberRegistry`, `PolicyLifecycleEventCollector`, `FilteredPolicyLifecycleEventSubscriber` (namespace/event-type/tag filters), `PolicyLifecycleEvent` (builder), `PolicyLifecycleEventType` (20 variants) |
| `policy_validation.rs` | `PolicyPackageValidator` trait (3 methods), `ValidationSeverity` (5-level with Ord), `ValidationCheckCategory` (5 variants), `ValidationCheckResult`, `PackageValidationReport` (helpers), `SyntacticPackageValidator`, `SecurityPackageValidator` (heuristic-only), `CompositePackageValidator`, `NullPolicyPackageValidator` |

### Audit Changes

26 new `PolicyExtEventType` variants: `PolicyPackageBackendChanged`, `PolicyPackageStored`, `PolicyPackageRetrieved`, `PolicyPackageDeleted`, `PolicyPackageListed`, `RuleSetStored`, `RuleSetRetrieved`, `EvaluationRecordStored`, `PackageSignatureStored`, `PolicyPackageComposed`, `PackageCompositionStrategyApplied`, `L3PolicyConflictDetected`, `L3PolicyConflictResolved`, `PolicyPackagePublished`, `PolicyPackageLookedUp`, `PolicyPackageSubscribed`, `PolicyPackageUnpublished`, `PolicyPackageIntegrityVerified`, `PolicyPackageExported`, `PolicyPackageExportFailed`, `ExternalEvaluationSubmitted`, `ExternalEvaluationCompleted`, `ExternalEvaluationCancelled`, `PolicyLifecycleEventPublished`, `PolicyPackageValidated`, `PolicyPackageValidationFailed`.

Public `kind()` method and 7 classification methods: `is_backend_event`, `is_package_event`, `is_composition_event`, `is_registry_event`, `is_evaluation_event`, `is_export_event`, `is_validation_event`.

### Error Changes

Two new `PolicyExtError` variants: `SerializationFailed(String)`, `PackageNotFound(String)`.

### Naming Collision Resolution

| L1/L2 type | L3 type | Rationale |
|---|---|---|
| `CompositionStrategy` (rule-level, 4 variants) | `PackageCompositionStrategy` (package-level) | L1 composes rules within a policy; L3 composes entire packages |
| `PolicyConflict` / `L2PolicyConflict` | `PackagePolicyConflict` | L3 detects conflicts between packages, not individual rules |
| `ConflictResolutionStrategy` (L2) | `PackageConflictResolutionStrategy` | Follows `PackagePolicyConflict` naming |
| `PolicyConflictDetected` / `PolicyConflictResolved` (L2 audit) | `L3PolicyConflictDetected` / `L3PolicyConflictResolved` | Only L3-prefixed variants — necessary to avoid audit collision |

### Design Decisions

- **Echo-loop InMemoryExternalEvaluatorIntegration**: Submit immediately produces a Permit result. Actual OPA/Cedar/XACML evaluation calls belong in adapter crates.
- **CachedPolicyPackageRegistry pattern**: Matches CachedRoleProvider from rune-permissions — bounded cache with hit_rate tracking and invalidate/invalidate_all.
- **ReadOnlyPolicyPackageRegistry**: Wraps any registry, rejects all write operations — for production read replicas.
- **SecurityPackageValidator**: Heuristic-only checks (unsigned packages, wildcard tags, all-optional dependencies). Full symbolic analysis belongs in Layer 5.
- **Industry standard formats**: OPA Rego bundle (manifest with roots/revision), OPA signed bundle manifest (SHA256 file hashes), AWS Cedar (@id annotations), OASIS XACML 3.0 (deny-overrides combining algorithm).

### Integration Points

- **rune-permissions**: ExternalEvaluatorIntegration prepares payloads but never decides — rune-permissions owns XACML four-outcome model (Permit/Deny/Indeterminate/NotApplicable)
- **rune-provenance**: StoredPackageSignature.signature_ref preserved across all export formats for provenance chain continuity
- **rune-framework**: PolicyLifecycleEventType and PolicyPackageBackendInfo available for Layer 5 governance pipeline integration
