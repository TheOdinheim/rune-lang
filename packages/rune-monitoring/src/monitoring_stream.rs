// ═══════════════════════════════════════════════════════════════════════
// Monitoring Stream — Event subscriber infrastructure for telemetry
// lifecycle events.
//
// Mirrors the SecurityEventSubscriber pattern from rune-security.
// Subscribers register interest in telemetry lifecycle events and
// receive them via a synchronous callback.  The registry fans out
// each event to all active subscribers.
//
// TelemetryLifecycleEventType is a 16-variant enum covering the full
// monitoring lifecycle: metric ingestion through export, trace
// recording, log parsing, health checks, and alerting.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::error::MonitoringError;

// ── TelemetryLifecycleEventType ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryLifecycleEventType {
    MetricIngested,
    MetricAggregated,
    MetricDownsampled,
    TraceSpanRecorded,
    TraceCompleted,
    TraceContextInjected,
    TraceContextExtracted,
    LogRecordIngested,
    LogParsedSuccessfully,
    LogParseFailed,
    HealthCheckPerformed,
    HealthCheckFailed,
    AlertRuleTriggered,
    AlertRuleResolved,
    TelemetryExported,
    TelemetryExportFailed,
}

impl TelemetryLifecycleEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::MetricIngested => "metric_ingested",
            Self::MetricAggregated => "metric_aggregated",
            Self::MetricDownsampled => "metric_downsampled",
            Self::TraceSpanRecorded => "trace_span_recorded",
            Self::TraceCompleted => "trace_completed",
            Self::TraceContextInjected => "trace_context_injected",
            Self::TraceContextExtracted => "trace_context_extracted",
            Self::LogRecordIngested => "log_record_ingested",
            Self::LogParsedSuccessfully => "log_parsed_successfully",
            Self::LogParseFailed => "log_parse_failed",
            Self::HealthCheckPerformed => "health_check_performed",
            Self::HealthCheckFailed => "health_check_failed",
            Self::AlertRuleTriggered => "alert_rule_triggered",
            Self::AlertRuleResolved => "alert_rule_resolved",
            Self::TelemetryExported => "telemetry_exported",
            Self::TelemetryExportFailed => "telemetry_export_failed",
        }
    }

    pub fn is_metric_event(&self) -> bool {
        matches!(
            self,
            Self::MetricIngested | Self::MetricAggregated | Self::MetricDownsampled
        )
    }

    pub fn is_trace_event(&self) -> bool {
        matches!(
            self,
            Self::TraceSpanRecorded
                | Self::TraceCompleted
                | Self::TraceContextInjected
                | Self::TraceContextExtracted
        )
    }

    pub fn is_log_event(&self) -> bool {
        matches!(
            self,
            Self::LogRecordIngested | Self::LogParsedSuccessfully | Self::LogParseFailed
        )
    }

    pub fn is_health_event(&self) -> bool {
        matches!(
            self,
            Self::HealthCheckPerformed | Self::HealthCheckFailed
        )
    }

    pub fn is_alert_event(&self) -> bool {
        matches!(
            self,
            Self::AlertRuleTriggered | Self::AlertRuleResolved
        )
    }

    pub fn is_export_event(&self) -> bool {
        matches!(
            self,
            Self::TelemetryExported | Self::TelemetryExportFailed
        )
    }
}

impl fmt::Display for TelemetryLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.type_name())
    }
}

// ── TelemetryLifecycleEvent ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TelemetryLifecycleEvent {
    pub event_type: TelemetryLifecycleEventType,
    pub timestamp: i64,
    pub description: String,
    pub service_name: Option<String>,
    pub severity: Option<String>,
    pub metadata: Vec<(String, String)>,
}

impl TelemetryLifecycleEvent {
    pub fn new(event_type: TelemetryLifecycleEventType, timestamp: i64, description: &str) -> Self {
        Self {
            event_type,
            timestamp,
            description: description.to_string(),
            service_name: None,
            severity: None,
            metadata: Vec::new(),
        }
    }

    pub fn with_service_name(mut self, service_name: &str) -> Self {
        self.service_name = Some(service_name.to_string());
        self
    }

    pub fn with_severity(mut self, severity: &str) -> Self {
        self.severity = Some(severity.to_string());
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.push((key.to_string(), value.to_string()));
        self
    }
}

impl fmt::Display for TelemetryLifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} @ {}", self.event_type, self.description, self.timestamp)
    }
}

// ── TelemetryEventSubscriber trait ──────────────────────────────

pub trait TelemetryEventSubscriber {
    fn on_event(&mut self, event: &TelemetryLifecycleEvent) -> Result<(), MonitoringError>;
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── TelemetryEventSubscriberRegistry ────────────────────────────

pub struct TelemetryEventSubscriberRegistry {
    subscribers: Vec<Box<dyn TelemetryEventSubscriber>>,
}

impl TelemetryEventSubscriberRegistry {
    pub fn new() -> Self {
        Self { subscribers: Vec::new() }
    }

    pub fn register(&mut self, subscriber: Box<dyn TelemetryEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn unregister(&mut self, subscriber_id: &str) -> bool {
        let before = self.subscribers.len();
        self.subscribers.retain(|s| s.subscriber_id() != subscriber_id);
        self.subscribers.len() < before
    }

    pub fn publish(&mut self, event: &TelemetryLifecycleEvent) -> Result<(), MonitoringError> {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_event(event)?;
            }
        }
        Ok(())
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    pub fn active_subscriber_count(&self) -> usize {
        self.subscribers.iter().filter(|s| s.is_active()).count()
    }
}

impl Default for TelemetryEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── TelemetryEventCollector ─────────────────────────────────────

pub struct TelemetryEventCollector {
    id: String,
    events: Vec<TelemetryLifecycleEvent>,
}

impl TelemetryEventCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: Vec::new(),
        }
    }

    pub fn events(&self) -> &[TelemetryLifecycleEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl TelemetryEventSubscriber for TelemetryEventCollector {
    fn on_event(&mut self, event: &TelemetryLifecycleEvent) -> Result<(), MonitoringError> {
        self.events.push(event.clone());
        Ok(())
    }

    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── FilteredTelemetryEventSubscriber ────────────────────────────

pub struct FilteredTelemetryEventSubscriber {
    id: String,
    inner: Box<dyn TelemetryEventSubscriber>,
    accepted_categories: Option<Vec<TelemetryLifecycleEventType>>,
    accepted_service_names: Option<Vec<String>>,
    accepted_severities: Option<Vec<String>>,
}

impl FilteredTelemetryEventSubscriber {
    pub fn new(id: &str, inner: Box<dyn TelemetryEventSubscriber>) -> Self {
        Self {
            id: id.to_string(),
            inner,
            accepted_categories: None,
            accepted_service_names: None,
            accepted_severities: None,
        }
    }

    pub fn with_category_filter(mut self, types: Vec<TelemetryLifecycleEventType>) -> Self {
        self.accepted_categories = Some(types);
        self
    }

    pub fn with_service_name_filter(mut self, names: Vec<String>) -> Self {
        self.accepted_service_names = Some(names);
        self
    }

    pub fn with_severity_filter(mut self, severities: Vec<String>) -> Self {
        self.accepted_severities = Some(severities);
        self
    }

    fn matches(&self, event: &TelemetryLifecycleEvent) -> bool {
        if let Some(ref cats) = self.accepted_categories
            && !cats.contains(&event.event_type)
        {
            return false;
        }
        if let Some(ref names) = self.accepted_service_names {
            let Some(ref sn) = event.service_name else { return false; };
            if !names.contains(sn) { return false; }
        }
        if let Some(ref sevs) = self.accepted_severities {
            let Some(ref sev) = event.severity else { return false; };
            if !sevs.contains(sev) { return false; }
        }
        true
    }
}

impl TelemetryEventSubscriber for FilteredTelemetryEventSubscriber {
    fn on_event(&mut self, event: &TelemetryLifecycleEvent) -> Result<(), MonitoringError> {
        if self.matches(event) {
            self.inner.on_event(event)?;
        }
        Ok(())
    }

    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { self.inner.is_active() }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_names() {
        assert_eq!(TelemetryLifecycleEventType::MetricIngested.type_name(), "metric_ingested");
        assert_eq!(TelemetryLifecycleEventType::TelemetryExportFailed.type_name(), "telemetry_export_failed");
    }

    #[test]
    fn test_event_type_display() {
        let t = TelemetryLifecycleEventType::TraceCompleted;
        assert_eq!(t.to_string(), "trace_completed");
    }

    #[test]
    fn test_classification_methods() {
        assert!(TelemetryLifecycleEventType::MetricIngested.is_metric_event());
        assert!(TelemetryLifecycleEventType::MetricAggregated.is_metric_event());
        assert!(TelemetryLifecycleEventType::MetricDownsampled.is_metric_event());
        assert!(!TelemetryLifecycleEventType::MetricIngested.is_trace_event());

        assert!(TelemetryLifecycleEventType::TraceSpanRecorded.is_trace_event());
        assert!(TelemetryLifecycleEventType::TraceCompleted.is_trace_event());
        assert!(TelemetryLifecycleEventType::TraceContextInjected.is_trace_event());
        assert!(TelemetryLifecycleEventType::TraceContextExtracted.is_trace_event());

        assert!(TelemetryLifecycleEventType::LogRecordIngested.is_log_event());
        assert!(TelemetryLifecycleEventType::LogParsedSuccessfully.is_log_event());
        assert!(TelemetryLifecycleEventType::LogParseFailed.is_log_event());

        assert!(TelemetryLifecycleEventType::HealthCheckPerformed.is_health_event());
        assert!(TelemetryLifecycleEventType::HealthCheckFailed.is_health_event());

        assert!(TelemetryLifecycleEventType::AlertRuleTriggered.is_alert_event());
        assert!(TelemetryLifecycleEventType::AlertRuleResolved.is_alert_event());

        assert!(TelemetryLifecycleEventType::TelemetryExported.is_export_event());
        assert!(TelemetryLifecycleEventType::TelemetryExportFailed.is_export_event());
    }

    #[test]
    fn test_lifecycle_event_builder() {
        let event = TelemetryLifecycleEvent::new(
            TelemetryLifecycleEventType::MetricIngested,
            1000,
            "Ingested 100 points",
        )
        .with_service_name("api")
        .with_severity("info")
        .with_metadata("series_id", "s1");
        assert_eq!(event.service_name.as_deref(), Some("api"));
        assert_eq!(event.severity.as_deref(), Some("info"));
        assert_eq!(event.metadata.len(), 1);
    }

    #[test]
    fn test_lifecycle_event_display() {
        let event = TelemetryLifecycleEvent::new(
            TelemetryLifecycleEventType::TraceCompleted,
            2000,
            "trace finished",
        );
        let s = event.to_string();
        assert!(s.contains("trace_completed"));
        assert!(s.contains("trace finished"));
        assert!(s.contains("2000"));
    }

    #[test]
    fn test_registry_register_and_publish() {
        let mut registry = TelemetryEventSubscriberRegistry::new();
        registry.register(Box::new(TelemetryEventCollector::new("c1")));
        registry.register(Box::new(TelemetryEventCollector::new("c2")));
        assert_eq!(registry.subscriber_count(), 2);
        assert_eq!(registry.active_subscriber_count(), 2);

        let event = TelemetryLifecycleEvent::new(
            TelemetryLifecycleEventType::MetricIngested,
            1000,
            "test",
        );
        registry.publish(&event).unwrap();
    }

    #[test]
    fn test_registry_unregister() {
        let mut registry = TelemetryEventSubscriberRegistry::new();
        registry.register(Box::new(TelemetryEventCollector::new("c1")));
        registry.register(Box::new(TelemetryEventCollector::new("c2")));
        assert!(registry.unregister("c1"));
        assert_eq!(registry.subscriber_count(), 1);
        assert!(!registry.unregister("nonexistent"));
    }

    #[test]
    fn test_collector() {
        let mut collector = TelemetryEventCollector::new("c1");
        let event = TelemetryLifecycleEvent::new(
            TelemetryLifecycleEventType::LogRecordIngested,
            1000,
            "log received",
        );
        collector.on_event(&event).unwrap();
        assert_eq!(collector.event_count(), 1);
        assert_eq!(collector.events()[0].description, "log received");
        collector.clear();
        assert_eq!(collector.event_count(), 0);
    }

    #[test]
    fn test_filtered_subscriber_category_filter() {
        let collector = TelemetryEventCollector::new("inner");
        let mut filtered = FilteredTelemetryEventSubscriber::new("f1", Box::new(collector))
            .with_category_filter(vec![TelemetryLifecycleEventType::MetricIngested]);

        let metric_event = TelemetryLifecycleEvent::new(
            TelemetryLifecycleEventType::MetricIngested,
            1000,
            "metric",
        );
        let trace_event = TelemetryLifecycleEvent::new(
            TelemetryLifecycleEventType::TraceCompleted,
            1001,
            "trace",
        );
        filtered.on_event(&metric_event).unwrap();
        filtered.on_event(&trace_event).unwrap(); // Should be filtered out
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_subscriber_service_name_filter() {
        let collector = TelemetryEventCollector::new("inner");
        let mut filtered = FilteredTelemetryEventSubscriber::new("f1", Box::new(collector))
            .with_service_name_filter(vec!["api".to_string()]);

        let event_match = TelemetryLifecycleEvent::new(
            TelemetryLifecycleEventType::MetricIngested,
            1000,
            "test",
        ).with_service_name("api");
        let event_no_match = TelemetryLifecycleEvent::new(
            TelemetryLifecycleEventType::MetricIngested,
            1001,
            "test",
        ).with_service_name("worker");
        filtered.on_event(&event_match).unwrap();
        filtered.on_event(&event_no_match).unwrap();
    }

    #[test]
    fn test_filtered_subscriber_severity_filter() {
        let collector = TelemetryEventCollector::new("inner");
        let mut filtered = FilteredTelemetryEventSubscriber::new("f1", Box::new(collector))
            .with_severity_filter(vec!["error".to_string()]);

        let event = TelemetryLifecycleEvent::new(
            TelemetryLifecycleEventType::HealthCheckFailed,
            1000,
            "check failed",
        ).with_severity("error");
        filtered.on_event(&event).unwrap();
    }

    #[test]
    fn test_all_16_event_types() {
        let types = vec![
            TelemetryLifecycleEventType::MetricIngested,
            TelemetryLifecycleEventType::MetricAggregated,
            TelemetryLifecycleEventType::MetricDownsampled,
            TelemetryLifecycleEventType::TraceSpanRecorded,
            TelemetryLifecycleEventType::TraceCompleted,
            TelemetryLifecycleEventType::TraceContextInjected,
            TelemetryLifecycleEventType::TraceContextExtracted,
            TelemetryLifecycleEventType::LogRecordIngested,
            TelemetryLifecycleEventType::LogParsedSuccessfully,
            TelemetryLifecycleEventType::LogParseFailed,
            TelemetryLifecycleEventType::HealthCheckPerformed,
            TelemetryLifecycleEventType::HealthCheckFailed,
            TelemetryLifecycleEventType::AlertRuleTriggered,
            TelemetryLifecycleEventType::AlertRuleResolved,
            TelemetryLifecycleEventType::TelemetryExported,
            TelemetryLifecycleEventType::TelemetryExportFailed,
        ];
        assert_eq!(types.len(), 16);
        for t in &types {
            assert!(!t.type_name().is_empty());
            assert!(!t.to_string().is_empty());
        }
    }
}
