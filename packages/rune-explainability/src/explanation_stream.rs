// ═══════════════════════════════════════════════════════════════════════
// Explanation Event Streaming — Subscriber-based event distribution
// for explanation lifecycle events.
//
// Follows the same registry + filtered subscriber pattern established
// in rune-security, rune-monitoring, and rune-truth.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── ExplanationLifecycleEventType ──────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExplanationLifecycleEventType {
    ExplanationRequested,
    ExplanationGenerated,
    ExplanationCached,
    ExplanationEvicted,
    TraceStarted,
    TraceStepAdded,
    TraceCompleted,
    TraceAbandoned,
    AttributionComputed,
    AttributionFailed,
    CounterfactualGenerated,
    CounterfactualFailed,
    QualityAssessed,
    QualityBreached,
    ExplanationExported,
    ExplanationExportFailed,
}

impl fmt::Display for ExplanationLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExplanationRequested => write!(f, "explanation-requested"),
            Self::ExplanationGenerated => write!(f, "explanation-generated"),
            Self::ExplanationCached => write!(f, "explanation-cached"),
            Self::ExplanationEvicted => write!(f, "explanation-evicted"),
            Self::TraceStarted => write!(f, "trace-started"),
            Self::TraceStepAdded => write!(f, "trace-step-added"),
            Self::TraceCompleted => write!(f, "trace-completed"),
            Self::TraceAbandoned => write!(f, "trace-abandoned"),
            Self::AttributionComputed => write!(f, "attribution-computed"),
            Self::AttributionFailed => write!(f, "attribution-failed"),
            Self::CounterfactualGenerated => write!(f, "counterfactual-generated"),
            Self::CounterfactualFailed => write!(f, "counterfactual-failed"),
            Self::QualityAssessed => write!(f, "quality-assessed"),
            Self::QualityBreached => write!(f, "quality-breached"),
            Self::ExplanationExported => write!(f, "explanation-exported"),
            Self::ExplanationExportFailed => write!(f, "explanation-export-failed"),
        }
    }
}

impl ExplanationLifecycleEventType {
    pub fn is_trace_event(&self) -> bool {
        matches!(self,
            Self::TraceStarted | Self::TraceStepAdded |
            Self::TraceCompleted | Self::TraceAbandoned
        )
    }

    pub fn is_attribution_event(&self) -> bool {
        matches!(self, Self::AttributionComputed | Self::AttributionFailed)
    }

    pub fn is_counterfactual_event(&self) -> bool {
        matches!(self, Self::CounterfactualGenerated | Self::CounterfactualFailed)
    }

    pub fn is_quality_event(&self) -> bool {
        matches!(self, Self::QualityAssessed | Self::QualityBreached)
    }

    pub fn is_export_event(&self) -> bool {
        matches!(self, Self::ExplanationExported | Self::ExplanationExportFailed)
    }

    pub fn is_lifecycle_event(&self) -> bool {
        matches!(self,
            Self::ExplanationRequested | Self::ExplanationGenerated |
            Self::ExplanationCached | Self::ExplanationEvicted
        )
    }
}

// ── ExplanationLifecycleEvent ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplanationLifecycleEvent {
    pub event_type: ExplanationLifecycleEventType,
    pub explanation_type: Option<String>,
    pub generator_id: Option<String>,
    pub subject_id: Option<String>,
    pub confidence_score: Option<String>,
    pub message: String,
    pub occurred_at: i64,
}

impl ExplanationLifecycleEvent {
    pub fn new(
        event_type: ExplanationLifecycleEventType,
        message: &str,
        occurred_at: i64,
    ) -> Self {
        Self {
            event_type,
            explanation_type: None,
            generator_id: None,
            subject_id: None,
            confidence_score: None,
            message: message.to_string(),
            occurred_at,
        }
    }

    pub fn with_explanation_type(mut self, explanation_type: &str) -> Self {
        self.explanation_type = Some(explanation_type.to_string());
        self
    }

    pub fn with_generator_id(mut self, generator_id: &str) -> Self {
        self.generator_id = Some(generator_id.to_string());
        self
    }

    pub fn with_subject_id(mut self, subject_id: &str) -> Self {
        self.subject_id = Some(subject_id.to_string());
        self
    }

    pub fn with_confidence(mut self, confidence: &str) -> Self {
        self.confidence_score = Some(confidence.to_string());
        self
    }
}

// ── ExplanationEventSubscriber trait ───────────────────────────

pub trait ExplanationEventSubscriber {
    fn on_explanation_event(&mut self, event: &ExplanationLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── ExplanationEventSubscriberRegistry ─────────────────────────

#[derive(Default)]
pub struct ExplanationEventSubscriberRegistry {
    subscribers: Vec<Box<dyn ExplanationEventSubscriber>>,
}

impl ExplanationEventSubscriberRegistry {
    pub fn new() -> Self {
        Self { subscribers: Vec::new() }
    }

    pub fn register(&mut self, subscriber: Box<dyn ExplanationEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &ExplanationLifecycleEvent) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_explanation_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[ExplanationLifecycleEvent]) {
        for event in events {
            self.notify(event);
        }
    }

    pub fn active_count(&self) -> usize {
        self.subscribers.iter().filter(|s| s.is_active()).count()
    }

    pub fn remove_inactive(&mut self) {
        self.subscribers.retain(|s| s.is_active());
    }
}

// ── ExplanationEventCollector ──────────────────────────────────

pub struct ExplanationEventCollector {
    id: String,
    events: Vec<ExplanationLifecycleEvent>,
    active: bool,
}

impl ExplanationEventCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: Vec::new(),
            active: true,
        }
    }

    pub fn collected_events(&self) -> &[ExplanationLifecycleEvent] {
        &self.events
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl ExplanationEventSubscriber for ExplanationEventCollector {
    fn on_explanation_event(&mut self, event: &ExplanationLifecycleEvent) {
        self.events.push(event.clone());
    }

    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { self.active }
}

// ── FilteredExplanationEventSubscriber ─────────────────────────

pub struct FilteredExplanationEventSubscriber {
    inner: Box<dyn ExplanationEventSubscriber>,
    explanation_type_filter: Option<String>,
    generator_id_filter: Option<String>,
    min_confidence: Option<f64>,
}

impl FilteredExplanationEventSubscriber {
    pub fn new(inner: Box<dyn ExplanationEventSubscriber>) -> Self {
        Self {
            inner,
            explanation_type_filter: None,
            generator_id_filter: None,
            min_confidence: None,
        }
    }

    pub fn with_explanation_type_filter(mut self, explanation_type: &str) -> Self {
        self.explanation_type_filter = Some(explanation_type.to_string());
        self
    }

    pub fn with_generator_id_filter(mut self, generator_id: &str) -> Self {
        self.generator_id_filter = Some(generator_id.to_string());
        self
    }

    pub fn with_min_confidence(mut self, min_confidence: f64) -> Self {
        self.min_confidence = Some(min_confidence);
        self
    }

    fn matches(&self, event: &ExplanationLifecycleEvent) -> bool {
        if let Some(ref filter) = self.explanation_type_filter
            && event.explanation_type.as_deref() != Some(filter.as_str())
        {
            return false;
        }
        if let Some(ref filter) = self.generator_id_filter
            && event.generator_id.as_deref() != Some(filter.as_str())
        {
            return false;
        }
        if let Some(min) = self.min_confidence
            && let Some(ref score_str) = event.confidence_score
            && let Ok(score) = score_str.parse::<f64>()
            && score < min
        {
            return false;
        }
        true
    }
}

impl ExplanationEventSubscriber for FilteredExplanationEventSubscriber {
    fn on_explanation_event(&mut self, event: &ExplanationLifecycleEvent) {
        if self.matches(event) {
            self.inner.on_explanation_event(event);
        }
    }

    fn subscriber_id(&self) -> &str { self.inner.subscriber_id() }
    fn is_active(&self) -> bool { self.inner.is_active() }
}

// ── NullExplanationEventSubscriber ─────────────────────────────

pub struct NullExplanationEventSubscriber {
    id: String,
}

impl NullExplanationEventSubscriber {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ExplanationEventSubscriber for NullExplanationEventSubscriber {
    fn on_explanation_event(&mut self, _event: &ExplanationLifecycleEvent) {}
    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_event_type_display() {
        assert_eq!(ExplanationLifecycleEventType::ExplanationRequested.to_string(), "explanation-requested");
        assert_eq!(ExplanationLifecycleEventType::TraceStarted.to_string(), "trace-started");
        assert_eq!(ExplanationLifecycleEventType::AttributionComputed.to_string(), "attribution-computed");
        assert_eq!(ExplanationLifecycleEventType::CounterfactualGenerated.to_string(), "counterfactual-generated");
        assert_eq!(ExplanationLifecycleEventType::QualityAssessed.to_string(), "quality-assessed");
        assert_eq!(ExplanationLifecycleEventType::ExplanationExported.to_string(), "explanation-exported");
    }

    #[test]
    fn test_lifecycle_event_type_classification() {
        assert!(ExplanationLifecycleEventType::TraceStarted.is_trace_event());
        assert!(ExplanationLifecycleEventType::TraceCompleted.is_trace_event());
        assert!(!ExplanationLifecycleEventType::AttributionComputed.is_trace_event());

        assert!(ExplanationLifecycleEventType::AttributionComputed.is_attribution_event());
        assert!(ExplanationLifecycleEventType::CounterfactualGenerated.is_counterfactual_event());
        assert!(ExplanationLifecycleEventType::QualityAssessed.is_quality_event());
        assert!(ExplanationLifecycleEventType::ExplanationExported.is_export_event());
        assert!(ExplanationLifecycleEventType::ExplanationRequested.is_lifecycle_event());
    }

    #[test]
    fn test_lifecycle_event_builder() {
        let event = ExplanationLifecycleEvent::new(
            ExplanationLifecycleEventType::ExplanationGenerated,
            "explanation generated",
            1000,
        )
        .with_explanation_type("feature-attribution")
        .with_generator_id("lc-1")
        .with_subject_id("pred-1")
        .with_confidence("0.9");

        assert_eq!(event.explanation_type.as_deref(), Some("feature-attribution"));
        assert_eq!(event.generator_id.as_deref(), Some("lc-1"));
        assert_eq!(event.subject_id.as_deref(), Some("pred-1"));
        assert_eq!(event.confidence_score.as_deref(), Some("0.9"));
    }

    #[test]
    fn test_collector_receives_events() {
        let mut collector = ExplanationEventCollector::new("col-1");
        let event = ExplanationLifecycleEvent::new(
            ExplanationLifecycleEventType::ExplanationGenerated,
            "generated",
            1000,
        );
        collector.on_explanation_event(&event);
        assert_eq!(collector.collected_events().len(), 1);
        assert_eq!(collector.subscriber_id(), "col-1");
        assert!(collector.is_active());
    }

    #[test]
    fn test_collector_deactivate() {
        let mut collector = ExplanationEventCollector::new("col-1");
        collector.deactivate();
        assert!(!collector.is_active());
    }

    #[test]
    fn test_registry_notify() {
        let mut registry = ExplanationEventSubscriberRegistry::new();
        registry.register(Box::new(ExplanationEventCollector::new("col-1")));
        registry.register(Box::new(ExplanationEventCollector::new("col-2")));
        assert_eq!(registry.active_count(), 2);

        let event = ExplanationLifecycleEvent::new(
            ExplanationLifecycleEventType::TraceCompleted,
            "trace done",
            1000,
        );
        registry.notify(&event);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut registry = ExplanationEventSubscriberRegistry::new();
        registry.register(Box::new(ExplanationEventCollector::new("col-1")));

        let events = vec![
            ExplanationLifecycleEvent::new(ExplanationLifecycleEventType::TraceStarted, "start", 1000),
            ExplanationLifecycleEvent::new(ExplanationLifecycleEventType::TraceCompleted, "end", 1001),
        ];
        registry.notify_batch(&events);
    }

    #[test]
    fn test_registry_remove_inactive() {
        let mut registry = ExplanationEventSubscriberRegistry::new();
        registry.register(Box::new(ExplanationEventCollector::new("active")));
        registry.register(Box::new(NullExplanationEventSubscriber::new("inactive")));
        assert_eq!(registry.active_count(), 1);
        registry.remove_inactive();
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_filtered_subscriber_type_filter() {
        let inner = Box::new(ExplanationEventCollector::new("col-1"));
        let mut filtered = FilteredExplanationEventSubscriber::new(inner)
            .with_explanation_type_filter("feature-attribution");

        let matching = ExplanationLifecycleEvent::new(
            ExplanationLifecycleEventType::ExplanationGenerated,
            "generated",
            1000,
        ).with_explanation_type("feature-attribution");

        let non_matching = ExplanationLifecycleEvent::new(
            ExplanationLifecycleEventType::ExplanationGenerated,
            "generated",
            1001,
        ).with_explanation_type("counterfactual");

        filtered.on_explanation_event(&matching);
        filtered.on_explanation_event(&non_matching);
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_subscriber_generator_filter() {
        let inner = Box::new(ExplanationEventCollector::new("col-1"));
        let mut filtered = FilteredExplanationEventSubscriber::new(inner)
            .with_generator_id_filter("lc-1");

        let matching = ExplanationLifecycleEvent::new(
            ExplanationLifecycleEventType::AttributionComputed,
            "computed",
            1000,
        ).with_generator_id("lc-1");

        filtered.on_explanation_event(&matching);
    }

    #[test]
    fn test_filtered_subscriber_confidence_filter() {
        let inner = Box::new(ExplanationEventCollector::new("col-1"));
        let mut filtered = FilteredExplanationEventSubscriber::new(inner)
            .with_min_confidence(0.8);

        let high = ExplanationLifecycleEvent::new(
            ExplanationLifecycleEventType::ExplanationGenerated,
            "high confidence",
            1000,
        ).with_confidence("0.9");

        let low = ExplanationLifecycleEvent::new(
            ExplanationLifecycleEventType::ExplanationGenerated,
            "low confidence",
            1001,
        ).with_confidence("0.5");

        filtered.on_explanation_event(&high);
        filtered.on_explanation_event(&low);
    }

    #[test]
    fn test_null_subscriber() {
        let sub = NullExplanationEventSubscriber::new("null-1");
        assert!(!sub.is_active());
        assert_eq!(sub.subscriber_id(), "null-1");
    }

    fn _assert_send_sync()
    where
        ExplanationLifecycleEvent: Send + Sync,
        ExplanationLifecycleEventType: Send + Sync,
    {}
}
