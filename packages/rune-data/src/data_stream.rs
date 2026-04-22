// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — Data governance event streaming. Defines the event
// subscriber trait, subscriber registry, and lifecycle event types for
// data governance event delivery. Reference implementations:
// DataGovernanceEventCollector, FilteredDataGovernanceEventSubscriber.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── DataGovernanceLifecycleEventType ──────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataGovernanceLifecycleEventType {
    QualityRuleStored,
    QualityResultRecorded,
    QualityPolicyRegistered,
    QualityGovernanceEvaluated,
    QualityPipelineBlocked,
    ClassificationStored,
    ClassificationReviewed,
    LineageRecordStored,
    LineageChainVerified,
    LineageGovernanceEvaluated,
    SchemaRecordStored,
    SchemaGovernanceEvaluated,
    SchemaHealthAssessed,
    CatalogEntryStored,
    CatalogEntryDeprecated,
    FreshnessAssessmentStored,
    FreshnessAlertRaised,
    DataGovernanceExported,
    DataGovernanceExportFailed,
    DataGovernanceMetricsComputed,
    DataGovernanceSubscriberRegistered,
    DataGovernanceSubscriberRemoved,
    DataGovernanceBackendChanged,
}

impl fmt::Display for DataGovernanceLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::QualityRuleStored => "QualityRuleStored",
            Self::QualityResultRecorded => "QualityResultRecorded",
            Self::QualityPolicyRegistered => "QualityPolicyRegistered",
            Self::QualityGovernanceEvaluated => "QualityGovernanceEvaluated",
            Self::QualityPipelineBlocked => "QualityPipelineBlocked",
            Self::ClassificationStored => "ClassificationStored",
            Self::ClassificationReviewed => "ClassificationReviewed",
            Self::LineageRecordStored => "LineageRecordStored",
            Self::LineageChainVerified => "LineageChainVerified",
            Self::LineageGovernanceEvaluated => "LineageGovernanceEvaluated",
            Self::SchemaRecordStored => "SchemaRecordStored",
            Self::SchemaGovernanceEvaluated => "SchemaGovernanceEvaluated",
            Self::SchemaHealthAssessed => "SchemaHealthAssessed",
            Self::CatalogEntryStored => "CatalogEntryStored",
            Self::CatalogEntryDeprecated => "CatalogEntryDeprecated",
            Self::FreshnessAssessmentStored => "FreshnessAssessmentStored",
            Self::FreshnessAlertRaised => "FreshnessAlertRaised",
            Self::DataGovernanceExported => "DataGovernanceExported",
            Self::DataGovernanceExportFailed => "DataGovernanceExportFailed",
            Self::DataGovernanceMetricsComputed => "DataGovernanceMetricsComputed",
            Self::DataGovernanceSubscriberRegistered => "DataGovernanceSubscriberRegistered",
            Self::DataGovernanceSubscriberRemoved => "DataGovernanceSubscriberRemoved",
            Self::DataGovernanceBackendChanged => "DataGovernanceBackendChanged",
        };
        f.write_str(s)
    }
}

// ── DataGovernanceLifecycleEvent ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataGovernanceLifecycleEvent {
    pub event_type: DataGovernanceLifecycleEventType,
    pub timestamp: i64,
    pub dataset_ref: Option<String>,
    pub severity: Option<String>,
    pub detail: String,
}

impl DataGovernanceLifecycleEvent {
    pub fn new(
        event_type: DataGovernanceLifecycleEventType,
        timestamp: i64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp,
            dataset_ref: None,
            severity: None,
            detail: detail.into(),
        }
    }

    pub fn with_dataset_ref(mut self, dataset_ref: impl Into<String>) -> Self {
        self.dataset_ref = Some(dataset_ref.into());
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = Some(severity.into());
        self
    }
}

// ── DataGovernanceEventSubscriber trait ───────────────────────────

pub trait DataGovernanceEventSubscriber {
    fn on_data_governance_event(&mut self, event: &DataGovernanceLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── DataGovernanceEventSubscriberRegistry ─────────────────────────

pub struct DataGovernanceEventSubscriberRegistry {
    subscribers: Vec<Box<dyn DataGovernanceEventSubscriber>>,
}

impl DataGovernanceEventSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn DataGovernanceEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &DataGovernanceLifecycleEvent) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_data_governance_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[DataGovernanceLifecycleEvent]) {
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

impl Default for DataGovernanceEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── DataGovernanceEventCollector ──────────────────────────────────

pub struct DataGovernanceEventCollector {
    id: String,
    active: bool,
    events: Vec<DataGovernanceLifecycleEvent>,
}

impl DataGovernanceEventCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            events: Vec::new(),
        }
    }

    pub fn events(&self) -> &[DataGovernanceLifecycleEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl DataGovernanceEventSubscriber for DataGovernanceEventCollector {
    fn on_data_governance_event(&mut self, event: &DataGovernanceLifecycleEvent) {
        self.events.push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredDataGovernanceEventSubscriber ─────────────────────────

pub struct FilteredDataGovernanceEventSubscriber {
    id: String,
    active: bool,
    events: Vec<DataGovernanceLifecycleEvent>,
    filter_event_type: Option<DataGovernanceLifecycleEventType>,
    filter_dataset_ref: Option<String>,
    filter_severity: Option<String>,
}

impl FilteredDataGovernanceEventSubscriber {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            events: Vec::new(),
            filter_event_type: None,
            filter_dataset_ref: None,
            filter_severity: None,
        }
    }

    pub fn with_event_type_filter(mut self, event_type: DataGovernanceLifecycleEventType) -> Self {
        self.filter_event_type = Some(event_type);
        self
    }

    pub fn with_dataset_ref_filter(mut self, dataset_ref: impl Into<String>) -> Self {
        self.filter_dataset_ref = Some(dataset_ref.into());
        self
    }

    pub fn with_severity_filter(mut self, severity: impl Into<String>) -> Self {
        self.filter_severity = Some(severity.into());
        self
    }

    pub fn events(&self) -> &[DataGovernanceLifecycleEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    fn matches(&self, event: &DataGovernanceLifecycleEvent) -> bool {
        if let Some(ref et) = self.filter_event_type
            && &event.event_type != et
        {
            return false;
        }
        if let Some(ref dr) = self.filter_dataset_ref
            && event.dataset_ref.as_deref() != Some(dr.as_str())
        {
            return false;
        }
        if let Some(ref sev) = self.filter_severity
            && event.severity.as_deref() != Some(sev.as_str())
        {
            return false;
        }
        true
    }
}

impl DataGovernanceEventSubscriber for FilteredDataGovernanceEventSubscriber {
    fn on_data_governance_event(&mut self, event: &DataGovernanceLifecycleEvent) {
        if self.matches(event) {
            self.events.push(event.clone());
        }
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: DataGovernanceLifecycleEventType) -> DataGovernanceLifecycleEvent {
        DataGovernanceLifecycleEvent::new(event_type, 1000, "test event")
    }

    #[test]
    fn test_collector_receives_events() {
        let mut collector = DataGovernanceEventCollector::new("col-1");
        collector.on_data_governance_event(&make_event(DataGovernanceLifecycleEventType::QualityRuleStored));
        collector.on_data_governance_event(&make_event(DataGovernanceLifecycleEventType::LineageRecordStored));
        assert_eq!(collector.event_count(), 2);
        assert_eq!(collector.subscriber_id(), "col-1");
        assert!(collector.is_active());
    }

    #[test]
    fn test_registry_notify() {
        let mut registry = DataGovernanceEventSubscriberRegistry::new();
        registry.register(Box::new(DataGovernanceEventCollector::new("col-1")));
        registry.notify(&make_event(DataGovernanceLifecycleEventType::QualityRuleStored));
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut registry = DataGovernanceEventSubscriberRegistry::new();
        registry.register(Box::new(DataGovernanceEventCollector::new("col-1")));
        let events = vec![
            make_event(DataGovernanceLifecycleEventType::QualityRuleStored),
            make_event(DataGovernanceLifecycleEventType::SchemaRecordStored),
        ];
        registry.notify_batch(&events);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_filtered_by_event_type() {
        let mut filtered = FilteredDataGovernanceEventSubscriber::new("f-1")
            .with_event_type_filter(DataGovernanceLifecycleEventType::QualityPipelineBlocked);
        filtered.on_data_governance_event(&make_event(DataGovernanceLifecycleEventType::QualityRuleStored));
        filtered.on_data_governance_event(&make_event(DataGovernanceLifecycleEventType::QualityPipelineBlocked));
        assert_eq!(filtered.event_count(), 1);
    }

    #[test]
    fn test_filtered_by_dataset_ref() {
        let mut filtered = FilteredDataGovernanceEventSubscriber::new("f-1")
            .with_dataset_ref_filter("ds-1");
        let e1 = make_event(DataGovernanceLifecycleEventType::QualityRuleStored).with_dataset_ref("ds-1");
        let e2 = make_event(DataGovernanceLifecycleEventType::QualityRuleStored).with_dataset_ref("ds-2");
        filtered.on_data_governance_event(&e1);
        filtered.on_data_governance_event(&e2);
        assert_eq!(filtered.event_count(), 1);
    }

    #[test]
    fn test_filtered_by_severity() {
        let mut filtered = FilteredDataGovernanceEventSubscriber::new("f-1")
            .with_severity_filter("Critical");
        let e1 = make_event(DataGovernanceLifecycleEventType::FreshnessAlertRaised).with_severity("Critical");
        let e2 = make_event(DataGovernanceLifecycleEventType::FreshnessAlertRaised).with_severity("Low");
        filtered.on_data_governance_event(&e1);
        filtered.on_data_governance_event(&e2);
        assert_eq!(filtered.event_count(), 1);
    }

    #[test]
    fn test_event_type_display_all() {
        let types = vec![
            DataGovernanceLifecycleEventType::QualityRuleStored,
            DataGovernanceLifecycleEventType::QualityResultRecorded,
            DataGovernanceLifecycleEventType::QualityPolicyRegistered,
            DataGovernanceLifecycleEventType::QualityGovernanceEvaluated,
            DataGovernanceLifecycleEventType::QualityPipelineBlocked,
            DataGovernanceLifecycleEventType::ClassificationStored,
            DataGovernanceLifecycleEventType::ClassificationReviewed,
            DataGovernanceLifecycleEventType::LineageRecordStored,
            DataGovernanceLifecycleEventType::LineageChainVerified,
            DataGovernanceLifecycleEventType::LineageGovernanceEvaluated,
            DataGovernanceLifecycleEventType::SchemaRecordStored,
            DataGovernanceLifecycleEventType::SchemaGovernanceEvaluated,
            DataGovernanceLifecycleEventType::SchemaHealthAssessed,
            DataGovernanceLifecycleEventType::CatalogEntryStored,
            DataGovernanceLifecycleEventType::CatalogEntryDeprecated,
            DataGovernanceLifecycleEventType::FreshnessAssessmentStored,
            DataGovernanceLifecycleEventType::FreshnessAlertRaised,
            DataGovernanceLifecycleEventType::DataGovernanceExported,
            DataGovernanceLifecycleEventType::DataGovernanceExportFailed,
            DataGovernanceLifecycleEventType::DataGovernanceMetricsComputed,
            DataGovernanceLifecycleEventType::DataGovernanceSubscriberRegistered,
            DataGovernanceLifecycleEventType::DataGovernanceSubscriberRemoved,
            DataGovernanceLifecycleEventType::DataGovernanceBackendChanged,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 23);
    }

    #[test]
    fn test_event_builder_chain() {
        let event = DataGovernanceLifecycleEvent::new(
            DataGovernanceLifecycleEventType::QualityPipelineBlocked, 5000, "pipeline blocked",
        )
        .with_dataset_ref("ds-1")
        .with_severity("Critical");
        assert_eq!(event.dataset_ref, Some("ds-1".into()));
        assert_eq!(event.severity, Some("Critical".into()));
    }

    #[test]
    fn test_registry_default() {
        let registry = DataGovernanceEventSubscriberRegistry::default();
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn test_registry_remove_inactive() {
        let mut registry = DataGovernanceEventSubscriberRegistry::new();
        registry.register(Box::new(DataGovernanceEventCollector::new("col-1")));
        assert_eq!(registry.active_count(), 1);
        registry.remove_inactive();
        assert_eq!(registry.active_count(), 1);
    }
}
