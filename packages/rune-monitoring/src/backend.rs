// ═══════════════════════════════════════════════════════════════════════
// Monitoring Backend — pluggable storage for metric series, trace spans,
// log records, health check results, and alert rules.
//
// MetricPoint.value is String for Eq derivation, following the pattern
// established across all RUNE backends.  This shape is compatible with
// rune-detection's TimeSeriesPoint (same timestamp + String value +
// HashMap labels pattern) so that monitoring telemetry flows naturally
// into the detection layer's TimeSeriesIngestor.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::MonitoringError;

// ── MetricKind ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

impl fmt::Display for MetricKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── MetricPoint ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricPoint {
    pub timestamp: i64,
    pub value: String,
}

impl MetricPoint {
    pub fn new(timestamp: i64, value: &str) -> Self {
        Self {
            timestamp,
            value: value.to_string(),
        }
    }
}

// ── StoredMetricSeries ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMetricSeries {
    pub series_id: String,
    pub metric_name: String,
    pub labels: HashMap<String, String>,
    pub points: Vec<MetricPoint>,
    pub unit: String,
    pub metric_kind: MetricKind,
}

// ── SpanStatus ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpanStatus {
    Ok,
    Error,
    Unset,
}

impl fmt::Display for SpanStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── StoredTraceSpan ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTraceSpan {
    pub span_id: String,
    pub trace_id: String,
    pub parent_span_id: Option<String>,
    pub service_name: String,
    pub operation_name: String,
    pub start_time: i64,
    pub end_time: i64,
    pub attributes: HashMap<String, String>,
    pub status: SpanStatus,
}

// ── StoredTrace ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTrace {
    pub trace_id: String,
    pub service_name: String,
    pub root_span_id: String,
    pub spans: Vec<StoredTraceSpan>,
    pub start_time: i64,
    pub end_time: i64,
}

// ── LogSeverity ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LogSeverity {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl fmt::Display for LogSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── StoredLogRecord ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLogRecord {
    pub log_id: String,
    pub timestamp: i64,
    pub severity: LogSeverity,
    pub service_name: String,
    pub message: String,
    pub attributes: HashMap<String, String>,
}

// ── StoredHealthCheckResult ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHealthCheckResult {
    pub check_id: String,
    pub checked_at: i64,
    pub status: String,
    pub response_time: String,
    pub observations: HashMap<String, String>,
}

// ── StoredAlertRule ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAlertRule {
    pub rule_id: String,
    pub name: String,
    pub metric_name: String,
    pub condition: String,
    pub threshold: String,
    pub severity: String,
    pub enabled: bool,
}

// ── MonitoringBackendInfo ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringBackendInfo {
    pub backend_name: String,
    pub metric_series_count: usize,
    pub trace_count: usize,
    pub log_count: usize,
    pub health_check_count: usize,
    pub alert_rule_count: usize,
}

// ── MonitoringBackend trait ──────────────────────────────────────

pub trait MonitoringBackend {
    // Metric series
    fn store_metric_series(&mut self, series: StoredMetricSeries) -> Result<(), MonitoringError>;
    fn retrieve_metric_series(&self, series_id: &str) -> Result<StoredMetricSeries, MonitoringError>;
    fn list_metric_series_by_name(&self, metric_name: &str) -> Vec<&StoredMetricSeries>;
    fn list_metric_series_by_label(&self, key: &str, value: &str) -> Vec<&StoredMetricSeries>;
    fn delete_metric_series(&mut self, series_id: &str) -> Result<(), MonitoringError>;
    fn metric_series_count(&self) -> usize;

    // Trace spans and traces
    fn store_trace_span(&mut self, span: StoredTraceSpan) -> Result<(), MonitoringError>;
    fn retrieve_trace_span(&self, span_id: &str) -> Result<StoredTraceSpan, MonitoringError>;
    fn list_spans_for_trace(&self, trace_id: &str) -> Vec<&StoredTraceSpan>;
    fn store_trace(&mut self, trace: StoredTrace) -> Result<(), MonitoringError>;
    fn retrieve_trace(&self, trace_id: &str) -> Result<StoredTrace, MonitoringError>;
    fn list_traces_by_service(&self, service_name: &str) -> Vec<&StoredTrace>;

    // Log records
    fn store_log_record(&mut self, record: StoredLogRecord) -> Result<(), MonitoringError>;
    fn retrieve_log_record(&self, log_id: &str) -> Result<StoredLogRecord, MonitoringError>;
    fn query_logs_by_predicate(&self, service_name: &str, min_severity: &LogSeverity) -> Vec<&StoredLogRecord>;

    // Health check results
    fn store_health_check_result(&mut self, result: StoredHealthCheckResult) -> Result<(), MonitoringError>;
    fn retrieve_health_check_result(&self, check_id: &str) -> Result<StoredHealthCheckResult, MonitoringError>;
    fn list_health_check_history(&self, check_id: &str) -> Vec<&StoredHealthCheckResult>;

    // Alert rules
    fn store_alert_rule(&mut self, rule: StoredAlertRule) -> Result<(), MonitoringError>;
    fn retrieve_alert_rule(&self, rule_id: &str) -> Result<StoredAlertRule, MonitoringError>;
    fn list_alert_rules(&self) -> Vec<&StoredAlertRule>;

    // Management
    fn flush(&mut self);
    fn backend_info(&self) -> MonitoringBackendInfo;
}

// ── InMemoryMonitoringBackend ────────────────────────────────────

pub struct InMemoryMonitoringBackend {
    metric_series: HashMap<String, StoredMetricSeries>,
    spans: HashMap<String, StoredTraceSpan>,
    traces: HashMap<String, StoredTrace>,
    logs: HashMap<String, StoredLogRecord>,
    health_results: Vec<StoredHealthCheckResult>,
    alert_rules: HashMap<String, StoredAlertRule>,
}

impl InMemoryMonitoringBackend {
    pub fn new() -> Self {
        Self {
            metric_series: HashMap::new(),
            spans: HashMap::new(),
            traces: HashMap::new(),
            logs: HashMap::new(),
            health_results: Vec::new(),
            alert_rules: HashMap::new(),
        }
    }
}

impl Default for InMemoryMonitoringBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitoringBackend for InMemoryMonitoringBackend {
    fn store_metric_series(&mut self, series: StoredMetricSeries) -> Result<(), MonitoringError> {
        self.metric_series.insert(series.series_id.clone(), series);
        Ok(())
    }

    fn retrieve_metric_series(&self, series_id: &str) -> Result<StoredMetricSeries, MonitoringError> {
        self.metric_series.get(series_id).cloned()
            .ok_or_else(|| MonitoringError::MetricNotFound { id: series_id.to_string() })
    }

    fn list_metric_series_by_name(&self, metric_name: &str) -> Vec<&StoredMetricSeries> {
        self.metric_series.values().filter(|s| s.metric_name == metric_name).collect()
    }

    fn list_metric_series_by_label(&self, key: &str, value: &str) -> Vec<&StoredMetricSeries> {
        self.metric_series.values()
            .filter(|s| s.labels.get(key) == Some(&value.to_string()))
            .collect()
    }

    fn delete_metric_series(&mut self, series_id: &str) -> Result<(), MonitoringError> {
        self.metric_series.remove(series_id)
            .map(|_| ())
            .ok_or_else(|| MonitoringError::MetricNotFound { id: series_id.to_string() })
    }

    fn metric_series_count(&self) -> usize {
        self.metric_series.len()
    }

    fn store_trace_span(&mut self, span: StoredTraceSpan) -> Result<(), MonitoringError> {
        self.spans.insert(span.span_id.clone(), span);
        Ok(())
    }

    fn retrieve_trace_span(&self, span_id: &str) -> Result<StoredTraceSpan, MonitoringError> {
        self.spans.get(span_id).cloned()
            .ok_or_else(|| MonitoringError::ComponentNotFound { id: span_id.to_string() })
    }

    fn list_spans_for_trace(&self, trace_id: &str) -> Vec<&StoredTraceSpan> {
        self.spans.values().filter(|s| s.trace_id == trace_id).collect()
    }

    fn store_trace(&mut self, trace: StoredTrace) -> Result<(), MonitoringError> {
        self.traces.insert(trace.trace_id.clone(), trace);
        Ok(())
    }

    fn retrieve_trace(&self, trace_id: &str) -> Result<StoredTrace, MonitoringError> {
        self.traces.get(trace_id).cloned()
            .ok_or_else(|| MonitoringError::ComponentNotFound { id: trace_id.to_string() })
    }

    fn list_traces_by_service(&self, service_name: &str) -> Vec<&StoredTrace> {
        self.traces.values().filter(|t| t.service_name == service_name).collect()
    }

    fn store_log_record(&mut self, record: StoredLogRecord) -> Result<(), MonitoringError> {
        self.logs.insert(record.log_id.clone(), record);
        Ok(())
    }

    fn retrieve_log_record(&self, log_id: &str) -> Result<StoredLogRecord, MonitoringError> {
        self.logs.get(log_id).cloned()
            .ok_or_else(|| MonitoringError::ComponentNotFound { id: log_id.to_string() })
    }

    fn query_logs_by_predicate(&self, service_name: &str, min_severity: &LogSeverity) -> Vec<&StoredLogRecord> {
        self.logs.values()
            .filter(|r| r.service_name == service_name && r.severity >= *min_severity)
            .collect()
    }

    fn store_health_check_result(&mut self, result: StoredHealthCheckResult) -> Result<(), MonitoringError> {
        self.health_results.push(result);
        Ok(())
    }

    fn retrieve_health_check_result(&self, check_id: &str) -> Result<StoredHealthCheckResult, MonitoringError> {
        self.health_results.iter().rev()
            .find(|r| r.check_id == check_id)
            .cloned()
            .ok_or_else(|| MonitoringError::HealthCheckNotFound { id: check_id.to_string() })
    }

    fn list_health_check_history(&self, check_id: &str) -> Vec<&StoredHealthCheckResult> {
        self.health_results.iter().filter(|r| r.check_id == check_id).collect()
    }

    fn store_alert_rule(&mut self, rule: StoredAlertRule) -> Result<(), MonitoringError> {
        self.alert_rules.insert(rule.rule_id.clone(), rule);
        Ok(())
    }

    fn retrieve_alert_rule(&self, rule_id: &str) -> Result<StoredAlertRule, MonitoringError> {
        self.alert_rules.get(rule_id).cloned()
            .ok_or_else(|| MonitoringError::ComponentNotFound { id: rule_id.to_string() })
    }

    fn list_alert_rules(&self) -> Vec<&StoredAlertRule> {
        self.alert_rules.values().collect()
    }

    fn flush(&mut self) {
        self.metric_series.clear();
        self.spans.clear();
        self.traces.clear();
        self.logs.clear();
        self.health_results.clear();
        self.alert_rules.clear();
    }

    fn backend_info(&self) -> MonitoringBackendInfo {
        MonitoringBackendInfo {
            backend_name: "InMemoryMonitoringBackend".to_string(),
            metric_series_count: self.metric_series.len(),
            trace_count: self.traces.len(),
            log_count: self.logs.len(),
            health_check_count: self.health_results.len(),
            alert_rule_count: self.alert_rules.len(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_series() -> StoredMetricSeries {
        StoredMetricSeries {
            series_id: "s1".to_string(),
            metric_name: "http_requests_total".to_string(),
            labels: HashMap::from([("method".to_string(), "GET".to_string())]),
            points: vec![MetricPoint::new(1000, "42.0")],
            unit: "requests".to_string(),
            metric_kind: MetricKind::Counter,
        }
    }

    fn sample_span() -> StoredTraceSpan {
        StoredTraceSpan {
            span_id: "span-1".to_string(),
            trace_id: "trace-1".to_string(),
            parent_span_id: None,
            service_name: "api".to_string(),
            operation_name: "GET /users".to_string(),
            start_time: 1000,
            end_time: 1050,
            attributes: HashMap::new(),
            status: SpanStatus::Ok,
        }
    }

    fn sample_log() -> StoredLogRecord {
        StoredLogRecord {
            log_id: "log-1".to_string(),
            timestamp: 1000,
            severity: LogSeverity::Info,
            service_name: "api".to_string(),
            message: "Request handled".to_string(),
            attributes: HashMap::new(),
        }
    }

    #[test]
    fn test_store_and_retrieve_metric_series() {
        let mut backend = InMemoryMonitoringBackend::new();
        backend.store_metric_series(sample_series()).unwrap();
        let retrieved = backend.retrieve_metric_series("s1").unwrap();
        assert_eq!(retrieved.metric_name, "http_requests_total");
        assert_eq!(backend.metric_series_count(), 1);
    }

    #[test]
    fn test_list_metric_series_by_name() {
        let mut backend = InMemoryMonitoringBackend::new();
        backend.store_metric_series(sample_series()).unwrap();
        let results = backend.list_metric_series_by_name("http_requests_total");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_list_metric_series_by_label() {
        let mut backend = InMemoryMonitoringBackend::new();
        backend.store_metric_series(sample_series()).unwrap();
        assert_eq!(backend.list_metric_series_by_label("method", "GET").len(), 1);
        assert_eq!(backend.list_metric_series_by_label("method", "POST").len(), 0);
    }

    #[test]
    fn test_delete_metric_series() {
        let mut backend = InMemoryMonitoringBackend::new();
        backend.store_metric_series(sample_series()).unwrap();
        backend.delete_metric_series("s1").unwrap();
        assert_eq!(backend.metric_series_count(), 0);
    }

    #[test]
    fn test_store_and_retrieve_span() {
        let mut backend = InMemoryMonitoringBackend::new();
        backend.store_trace_span(sample_span()).unwrap();
        let span = backend.retrieve_trace_span("span-1").unwrap();
        assert_eq!(span.operation_name, "GET /users");
    }

    #[test]
    fn test_list_spans_for_trace() {
        let mut backend = InMemoryMonitoringBackend::new();
        backend.store_trace_span(sample_span()).unwrap();
        let mut child = sample_span();
        child.span_id = "span-2".to_string();
        child.parent_span_id = Some("span-1".to_string());
        backend.store_trace_span(child).unwrap();
        assert_eq!(backend.list_spans_for_trace("trace-1").len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_trace() {
        let mut backend = InMemoryMonitoringBackend::new();
        let trace = StoredTrace {
            trace_id: "trace-1".to_string(),
            service_name: "api".to_string(),
            root_span_id: "span-1".to_string(),
            spans: vec![sample_span()],
            start_time: 1000,
            end_time: 1050,
        };
        backend.store_trace(trace).unwrap();
        let retrieved = backend.retrieve_trace("trace-1").unwrap();
        assert_eq!(retrieved.spans.len(), 1);
    }

    #[test]
    fn test_list_traces_by_service() {
        let mut backend = InMemoryMonitoringBackend::new();
        let trace = StoredTrace {
            trace_id: "trace-1".to_string(),
            service_name: "api".to_string(),
            root_span_id: "span-1".to_string(),
            spans: vec![],
            start_time: 1000,
            end_time: 1050,
        };
        backend.store_trace(trace).unwrap();
        assert_eq!(backend.list_traces_by_service("api").len(), 1);
        assert_eq!(backend.list_traces_by_service("worker").len(), 0);
    }

    #[test]
    fn test_store_and_retrieve_log() {
        let mut backend = InMemoryMonitoringBackend::new();
        backend.store_log_record(sample_log()).unwrap();
        let log = backend.retrieve_log_record("log-1").unwrap();
        assert_eq!(log.message, "Request handled");
    }

    #[test]
    fn test_query_logs_by_predicate() {
        let mut backend = InMemoryMonitoringBackend::new();
        backend.store_log_record(sample_log()).unwrap();
        let mut error_log = sample_log();
        error_log.log_id = "log-2".to_string();
        error_log.severity = LogSeverity::Error;
        backend.store_log_record(error_log).unwrap();
        let results = backend.query_logs_by_predicate("api", &LogSeverity::Warn);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_health_check_result() {
        let mut backend = InMemoryMonitoringBackend::new();
        let result = StoredHealthCheckResult {
            check_id: "hc-1".to_string(),
            checked_at: 1000,
            status: "Healthy".to_string(),
            response_time: "5".to_string(),
            observations: HashMap::new(),
        };
        backend.store_health_check_result(result).unwrap();
        let retrieved = backend.retrieve_health_check_result("hc-1").unwrap();
        assert_eq!(retrieved.status, "Healthy");
    }

    #[test]
    fn test_list_health_check_history() {
        let mut backend = InMemoryMonitoringBackend::new();
        for i in 0..3 {
            let result = StoredHealthCheckResult {
                check_id: "hc-1".to_string(),
                checked_at: 1000 + i,
                status: "Healthy".to_string(),
                response_time: "5".to_string(),
                observations: HashMap::new(),
            };
            backend.store_health_check_result(result).unwrap();
        }
        assert_eq!(backend.list_health_check_history("hc-1").len(), 3);
    }

    #[test]
    fn test_store_and_retrieve_alert_rule() {
        let mut backend = InMemoryMonitoringBackend::new();
        let rule = StoredAlertRule {
            rule_id: "ar-1".to_string(),
            name: "High latency".to_string(),
            metric_name: "http_latency_ms".to_string(),
            condition: "Above".to_string(),
            threshold: "500".to_string(),
            severity: "High".to_string(),
            enabled: true,
        };
        backend.store_alert_rule(rule).unwrap();
        let retrieved = backend.retrieve_alert_rule("ar-1").unwrap();
        assert_eq!(retrieved.name, "High latency");
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemoryMonitoringBackend::new();
        backend.store_metric_series(sample_series()).unwrap();
        backend.store_log_record(sample_log()).unwrap();
        backend.flush();
        assert_eq!(backend.metric_series_count(), 0);
        assert!(backend.retrieve_log_record("log-1").is_err());
    }

    #[test]
    fn test_backend_info() {
        let backend = InMemoryMonitoringBackend::new();
        let info = backend.backend_info();
        assert_eq!(info.backend_name, "InMemoryMonitoringBackend");
        assert_eq!(info.metric_series_count, 0);
    }

    #[test]
    fn test_metric_kind_display() {
        assert_eq!(MetricKind::Counter.to_string(), "Counter");
        assert_eq!(MetricKind::Gauge.to_string(), "Gauge");
    }

    #[test]
    fn test_span_status_display() {
        assert_eq!(SpanStatus::Ok.to_string(), "Ok");
        assert_eq!(SpanStatus::Error.to_string(), "Error");
    }

    #[test]
    fn test_log_severity_ordering() {
        assert!(LogSeverity::Fatal > LogSeverity::Error);
        assert!(LogSeverity::Error > LogSeverity::Warn);
        assert!(LogSeverity::Warn > LogSeverity::Info);
        assert!(LogSeverity::Info > LogSeverity::Debug);
        assert!(LogSeverity::Debug > LogSeverity::Trace);
    }
}
