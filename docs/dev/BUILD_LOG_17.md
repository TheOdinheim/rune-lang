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
