// ═══════════════════════════════════════════════════════════════════════
// Telemetry Exporter — Serialises metrics, traces, and logs into
// industry-standard wire formats.
//
// Seven implementations cover the major observability exposition
// standards.  All produce Vec<u8> (UTF-8 text) — actual protobuf
// wire format belongs in adapter crates, not the trait boundary.
//
// Metric formats:  OTLP (JSON), Prometheus exposition, OpenMetrics.
// Trace formats:   Jaeger Thrift (JSON sketch), Zipkin v2 (JSON).
// Log formats:     ECS JSON, Splunk HEC (JSON).
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::backend::{StoredLogRecord, StoredMetricSeries, StoredTrace};
use crate::error::MonitoringError;

// ── TelemetryExporter trait ─────────────────────────────────────

pub trait TelemetryExporter {
    fn export_metrics(&self, series: &[StoredMetricSeries]) -> Result<Vec<u8>, MonitoringError>;
    fn export_traces(&self, traces: &[StoredTrace]) -> Result<Vec<u8>, MonitoringError>;
    fn export_logs(&self, logs: &[StoredLogRecord]) -> Result<Vec<u8>, MonitoringError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── OtlpMetricsExporter ────────────────────────────────────────

pub struct OtlpMetricsExporter;

impl TelemetryExporter for OtlpMetricsExporter {
    fn export_metrics(&self, series: &[StoredMetricSeries]) -> Result<Vec<u8>, MonitoringError> {
        let metrics: Vec<serde_json::Value> = series.iter().map(|s| {
            let data_points: Vec<serde_json::Value> = s.points.iter().map(|p| {
                serde_json::json!({
                    "timeUnixNano": p.timestamp,
                    "asDouble": p.value,
                })
            }).collect();
            serde_json::json!({
                "name": s.metric_name,
                "unit": s.unit,
                "gauge": { "dataPoints": data_points },
            })
        }).collect();
        let envelope = serde_json::json!({
            "resourceMetrics": [{
                "scopeMetrics": [{
                    "metrics": metrics,
                }],
            }],
        });
        serde_json::to_vec_pretty(&envelope).map_err(|e| MonitoringError::InvalidConfiguration {
            reason: format!("OTLP serialization failed: {e}"),
        })
    }

    fn export_traces(&self, traces: &[StoredTrace]) -> Result<Vec<u8>, MonitoringError> {
        let resource_spans: Vec<serde_json::Value> = traces.iter().map(|t| {
            let spans: Vec<serde_json::Value> = t.spans.iter().map(|s| {
                serde_json::json!({
                    "traceId": s.trace_id,
                    "spanId": s.span_id,
                    "parentSpanId": s.parent_span_id,
                    "name": s.operation_name,
                    "startTimeUnixNano": s.start_time,
                    "endTimeUnixNano": s.end_time,
                    "status": { "code": format!("{}", s.status) },
                })
            }).collect();
            serde_json::json!({
                "scopeSpans": [{ "spans": spans }],
            })
        }).collect();
        let envelope = serde_json::json!({ "resourceSpans": resource_spans });
        serde_json::to_vec_pretty(&envelope).map_err(|e| MonitoringError::InvalidConfiguration {
            reason: format!("OTLP trace serialization failed: {e}"),
        })
    }

    fn export_logs(&self, logs: &[StoredLogRecord]) -> Result<Vec<u8>, MonitoringError> {
        let log_records: Vec<serde_json::Value> = logs.iter().map(|l| {
            serde_json::json!({
                "timeUnixNano": l.timestamp,
                "severityText": format!("{}", l.severity),
                "body": { "stringValue": l.message },
                "attributes": l.attributes,
            })
        }).collect();
        let envelope = serde_json::json!({
            "resourceLogs": [{
                "scopeLogs": [{ "logRecords": log_records }],
            }],
        });
        serde_json::to_vec_pretty(&envelope).map_err(|e| MonitoringError::InvalidConfiguration {
            reason: format!("OTLP log serialization failed: {e}"),
        })
    }

    fn format_name(&self) -> &str { "otlp-json" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── PrometheusExpositionExporter ────────────────────────────────

pub struct PrometheusExpositionExporter;

impl TelemetryExporter for PrometheusExpositionExporter {
    fn export_metrics(&self, series: &[StoredMetricSeries]) -> Result<Vec<u8>, MonitoringError> {
        let mut output = String::new();
        for s in series {
            output.push_str(&format!("# HELP {} {}\n", s.metric_name, s.unit));
            output.push_str(&format!("# TYPE {} {}\n", s.metric_name, prometheus_type(&s.metric_kind)));
            for p in &s.points {
                let labels = format_prometheus_labels(&s.labels);
                output.push_str(&format!("{}{} {} {}\n", s.metric_name, labels, p.value, p.timestamp));
            }
        }
        Ok(output.into_bytes())
    }

    fn export_traces(&self, _traces: &[StoredTrace]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"# Prometheus exposition format does not support traces\n".to_vec())
    }

    fn export_logs(&self, _logs: &[StoredLogRecord]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"# Prometheus exposition format does not support logs\n".to_vec())
    }

    fn format_name(&self) -> &str { "prometheus" }
    fn content_type(&self) -> &str { "text/plain; version=0.0.4; charset=utf-8" }
}

// ── OpenMetricsExporter ─────────────────────────────────────────

pub struct OpenMetricsExporter;

impl TelemetryExporter for OpenMetricsExporter {
    fn export_metrics(&self, series: &[StoredMetricSeries]) -> Result<Vec<u8>, MonitoringError> {
        let mut output = String::new();
        for s in series {
            output.push_str(&format!("# TYPE {} {}\n", s.metric_name, openmetrics_type(&s.metric_kind)));
            output.push_str(&format!("# UNIT {} {}\n", s.metric_name, s.unit));
            for p in &s.points {
                let labels = format_prometheus_labels(&s.labels);
                output.push_str(&format!("{}{} {} {}\n", s.metric_name, labels, p.value, p.timestamp));
            }
        }
        output.push_str("# EOF\n");
        Ok(output.into_bytes())
    }

    fn export_traces(&self, _traces: &[StoredTrace]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"# OpenMetrics does not support traces\n# EOF\n".to_vec())
    }

    fn export_logs(&self, _logs: &[StoredLogRecord]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"# OpenMetrics does not support logs\n# EOF\n".to_vec())
    }

    fn format_name(&self) -> &str { "openmetrics" }
    fn content_type(&self) -> &str { "application/openmetrics-text; version=1.0.0; charset=utf-8" }
}

// ── JaegerThriftExporter ────────────────────────────────────────

pub struct JaegerThriftExporter;

impl TelemetryExporter for JaegerThriftExporter {
    fn export_metrics(&self, _series: &[StoredMetricSeries]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"[]".to_vec()) // Jaeger does not handle metrics
    }

    fn export_traces(&self, traces: &[StoredTrace]) -> Result<Vec<u8>, MonitoringError> {
        let data: Vec<serde_json::Value> = traces.iter().map(|t| {
            let spans: Vec<serde_json::Value> = t.spans.iter().map(|s| {
                serde_json::json!({
                    "traceID": s.trace_id,
                    "spanID": s.span_id,
                    "operationName": s.operation_name,
                    "references": s.parent_span_id.as_ref().map(|pid| vec![
                        serde_json::json!({"refType": "CHILD_OF", "traceID": s.trace_id, "spanID": pid})
                    ]).unwrap_or_default(),
                    "startTime": s.start_time,
                    "duration": s.end_time - s.start_time,
                    "tags": s.attributes.iter().map(|(k, v)| serde_json::json!({"key": k, "type": "string", "value": v})).collect::<Vec<_>>(),
                    "processID": "p1",
                })
            }).collect();
            serde_json::json!({
                "traceID": t.trace_id,
                "spans": spans,
                "processes": { "p1": { "serviceName": t.service_name } },
            })
        }).collect();
        serde_json::to_vec_pretty(&serde_json::json!({"data": data}))
            .map_err(|e| MonitoringError::InvalidConfiguration {
                reason: format!("Jaeger serialization failed: {e}"),
            })
    }

    fn export_logs(&self, _logs: &[StoredLogRecord]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"[]".to_vec())
    }

    fn format_name(&self) -> &str { "jaeger-json" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── ZipkinV2Exporter ────────────────────────────────────────────

pub struct ZipkinV2Exporter;

impl TelemetryExporter for ZipkinV2Exporter {
    fn export_metrics(&self, _series: &[StoredMetricSeries]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"[]".to_vec())
    }

    fn export_traces(&self, traces: &[StoredTrace]) -> Result<Vec<u8>, MonitoringError> {
        let mut spans = Vec::new();
        for t in traces {
            for s in &t.spans {
                spans.push(serde_json::json!({
                    "traceId": s.trace_id,
                    "id": s.span_id,
                    "parentId": s.parent_span_id,
                    "name": s.operation_name,
                    "timestamp": s.start_time,
                    "duration": s.end_time - s.start_time,
                    "localEndpoint": { "serviceName": s.service_name },
                    "tags": s.attributes,
                }));
            }
        }
        serde_json::to_vec_pretty(&spans)
            .map_err(|e| MonitoringError::InvalidConfiguration {
                reason: format!("Zipkin serialization failed: {e}"),
            })
    }

    fn export_logs(&self, _logs: &[StoredLogRecord]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"[]".to_vec())
    }

    fn format_name(&self) -> &str { "zipkin-v2" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── EcsLogExporter ──────────────────────────────────────────────

pub struct EcsLogExporter;

impl TelemetryExporter for EcsLogExporter {
    fn export_metrics(&self, _series: &[StoredMetricSeries]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"[]".to_vec())
    }

    fn export_traces(&self, _traces: &[StoredTrace]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"[]".to_vec())
    }

    fn export_logs(&self, logs: &[StoredLogRecord]) -> Result<Vec<u8>, MonitoringError> {
        let records: Vec<serde_json::Value> = logs.iter().map(|l| {
            let mut obj = serde_json::json!({
                "@timestamp": l.timestamp,
                "log.level": format!("{}", l.severity),
                "message": l.message,
                "service.name": l.service_name,
                "ecs.version": "8.11",
            });
            if let Some(map) = obj.as_object_mut() {
                for (k, v) in &l.attributes {
                    map.insert(k.clone(), serde_json::Value::String(v.clone()));
                }
            }
            obj
        }).collect();
        serde_json::to_vec_pretty(&records)
            .map_err(|e| MonitoringError::InvalidConfiguration {
                reason: format!("ECS serialization failed: {e}"),
            })
    }

    fn format_name(&self) -> &str { "ecs-json" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── SplunkHecExporter ───────────────────────────────────────────

pub struct SplunkHecExporter {
    source_type: String,
}

impl SplunkHecExporter {
    pub fn new(source_type: &str) -> Self {
        Self { source_type: source_type.to_string() }
    }
}

impl Default for SplunkHecExporter {
    fn default() -> Self {
        Self::new("_json")
    }
}

impl TelemetryExporter for SplunkHecExporter {
    fn export_metrics(&self, series: &[StoredMetricSeries]) -> Result<Vec<u8>, MonitoringError> {
        let events: Vec<serde_json::Value> = series.iter().flat_map(|s| {
            s.points.iter().map(move |p| {
                serde_json::json!({
                    "time": p.timestamp,
                    "sourcetype": self.source_type,
                    "event": {
                        "metric_name": s.metric_name,
                        "value": p.value,
                        "labels": s.labels,
                    },
                })
            })
        }).collect();
        serde_json::to_vec_pretty(&events)
            .map_err(|e| MonitoringError::InvalidConfiguration {
                reason: format!("Splunk HEC serialization failed: {e}"),
            })
    }

    fn export_traces(&self, _traces: &[StoredTrace]) -> Result<Vec<u8>, MonitoringError> {
        Ok(b"[]".to_vec())
    }

    fn export_logs(&self, logs: &[StoredLogRecord]) -> Result<Vec<u8>, MonitoringError> {
        let events: Vec<serde_json::Value> = logs.iter().map(|l| {
            serde_json::json!({
                "time": l.timestamp,
                "sourcetype": self.source_type,
                "event": {
                    "severity": format!("{}", l.severity),
                    "message": l.message,
                    "service": l.service_name,
                    "attributes": l.attributes,
                },
            })
        }).collect();
        serde_json::to_vec_pretty(&events)
            .map_err(|e| MonitoringError::InvalidConfiguration {
                reason: format!("Splunk HEC log serialization failed: {e}"),
            })
    }

    fn format_name(&self) -> &str { "splunk-hec" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── helpers ─────────────────────────────────────────────────────

fn prometheus_type(kind: &crate::backend::MetricKind) -> &'static str {
    match kind {
        crate::backend::MetricKind::Counter => "counter",
        crate::backend::MetricKind::Gauge => "gauge",
        crate::backend::MetricKind::Histogram => "histogram",
        crate::backend::MetricKind::Summary => "summary",
    }
}

fn openmetrics_type(kind: &crate::backend::MetricKind) -> &'static str {
    match kind {
        crate::backend::MetricKind::Counter => "counter",
        crate::backend::MetricKind::Gauge => "gauge",
        crate::backend::MetricKind::Histogram => "histogram",
        crate::backend::MetricKind::Summary => "summary",
    }
}

fn format_prometheus_labels(labels: &std::collections::HashMap<String, String>) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let pairs: Vec<String> = labels.iter()
        .map(|(k, v)| format!("{k}=\"{v}\""))
        .collect();
    format!("{{{}}}", pairs.join(","))
}

impl fmt::Display for OtlpMetricsExporter { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "OtlpMetricsExporter") } }
impl fmt::Display for PrometheusExpositionExporter { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "PrometheusExpositionExporter") } }
impl fmt::Display for OpenMetricsExporter { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "OpenMetricsExporter") } }
impl fmt::Display for JaegerThriftExporter { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "JaegerThriftExporter") } }
impl fmt::Display for ZipkinV2Exporter { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "ZipkinV2Exporter") } }
impl fmt::Display for EcsLogExporter { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "EcsLogExporter") } }
impl fmt::Display for SplunkHecExporter { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "SplunkHecExporter") } }

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::*;
    use std::collections::HashMap;

    fn sample_series() -> Vec<StoredMetricSeries> {
        vec![StoredMetricSeries {
            series_id: "s1".to_string(),
            metric_name: "http_requests_total".to_string(),
            labels: HashMap::from([("method".to_string(), "GET".to_string())]),
            points: vec![MetricPoint::new(1000, "42.0")],
            unit: "requests".to_string(),
            metric_kind: MetricKind::Counter,
        }]
    }

    fn sample_trace() -> Vec<StoredTrace> {
        vec![StoredTrace {
            trace_id: "trace-1".to_string(),
            service_name: "api".to_string(),
            root_span_id: "span-1".to_string(),
            spans: vec![StoredTraceSpan {
                span_id: "span-1".to_string(),
                trace_id: "trace-1".to_string(),
                parent_span_id: None,
                service_name: "api".to_string(),
                operation_name: "GET /users".to_string(),
                start_time: 1000,
                end_time: 1050,
                attributes: HashMap::new(),
                status: SpanStatus::Ok,
            }],
            start_time: 1000,
            end_time: 1050,
        }]
    }

    fn sample_logs() -> Vec<StoredLogRecord> {
        vec![StoredLogRecord {
            log_id: "log-1".to_string(),
            timestamp: 1000,
            severity: LogSeverity::Info,
            service_name: "api".to_string(),
            message: "Request handled".to_string(),
            attributes: HashMap::new(),
        }]
    }

    #[test]
    fn test_otlp_export_metrics() {
        let exporter = OtlpMetricsExporter;
        let data = exporter.export_metrics(&sample_series()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("resourceMetrics"));
        assert!(text.contains("http_requests_total"));
    }

    #[test]
    fn test_otlp_export_traces() {
        let exporter = OtlpMetricsExporter;
        let data = exporter.export_traces(&sample_trace()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("resourceSpans"));
        assert!(text.contains("GET /users"));
    }

    #[test]
    fn test_otlp_export_logs() {
        let exporter = OtlpMetricsExporter;
        let data = exporter.export_logs(&sample_logs()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("resourceLogs"));
        assert!(text.contains("Request handled"));
    }

    #[test]
    fn test_prometheus_export() {
        let exporter = PrometheusExpositionExporter;
        let data = exporter.export_metrics(&sample_series()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("# HELP http_requests_total"));
        assert!(text.contains("# TYPE http_requests_total counter"));
        assert!(text.contains("42.0"));
    }

    #[test]
    fn test_openmetrics_export() {
        let exporter = OpenMetricsExporter;
        let data = exporter.export_metrics(&sample_series()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("# TYPE http_requests_total counter"));
        assert!(text.contains("# UNIT http_requests_total requests"));
        assert!(text.contains("# EOF"));
    }

    #[test]
    fn test_jaeger_export_traces() {
        let exporter = JaegerThriftExporter;
        let data = exporter.export_traces(&sample_trace()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("traceID"));
        assert!(text.contains("operationName"));
        assert!(text.contains("GET /users"));
    }

    #[test]
    fn test_zipkin_export_traces() {
        let exporter = ZipkinV2Exporter;
        let data = exporter.export_traces(&sample_trace()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("traceId"));
        assert!(text.contains("localEndpoint"));
    }

    #[test]
    fn test_ecs_export_logs() {
        let exporter = EcsLogExporter;
        let data = exporter.export_logs(&sample_logs()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("ecs.version"));
        assert!(text.contains("8.11"));
        assert!(text.contains("Request handled"));
    }

    #[test]
    fn test_splunk_hec_export_metrics() {
        let exporter = SplunkHecExporter::default();
        let data = exporter.export_metrics(&sample_series()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("sourcetype"));
        assert!(text.contains("_json"));
        assert!(text.contains("http_requests_total"));
    }

    #[test]
    fn test_splunk_hec_export_logs() {
        let exporter = SplunkHecExporter::new("myapp");
        let data = exporter.export_logs(&sample_logs()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("myapp"));
        assert!(text.contains("Request handled"));
    }

    #[test]
    fn test_format_names_and_content_types() {
        assert_eq!(OtlpMetricsExporter.format_name(), "otlp-json");
        assert_eq!(OtlpMetricsExporter.content_type(), "application/json");
        assert_eq!(PrometheusExpositionExporter.format_name(), "prometheus");
        assert!(PrometheusExpositionExporter.content_type().contains("0.0.4"));
        assert_eq!(OpenMetricsExporter.format_name(), "openmetrics");
        assert!(OpenMetricsExporter.content_type().contains("openmetrics"));
        assert_eq!(JaegerThriftExporter.format_name(), "jaeger-json");
        assert_eq!(ZipkinV2Exporter.format_name(), "zipkin-v2");
        assert_eq!(EcsLogExporter.format_name(), "ecs-json");
        assert_eq!(SplunkHecExporter::default().format_name(), "splunk-hec");
    }

    #[test]
    fn test_prometheus_labels_formatting() {
        let labels = HashMap::from([
            ("method".to_string(), "GET".to_string()),
        ]);
        let formatted = format_prometheus_labels(&labels);
        assert!(formatted.contains("method=\"GET\""));

        let empty = format_prometheus_labels(&HashMap::new());
        assert!(empty.is_empty());
    }
}
