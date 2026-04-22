// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — AI governance event streaming. Defines the event subscriber
// trait, subscriber registry, and lifecycle event types for AI
// governance event delivery. Reference implementations:
// AiGovernanceEventCollector, FilteredAiGovernanceEventSubscriber.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── AiGovernanceLifecycleEventType ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiGovernanceLifecycleEventType {
    ModelStored,
    ModelStatusChanged,
    ModelDeleted,
    DatasetStored,
    DatasetQualityChanged,
    EvaluationRecorded,
    EvaluationGatePassed,
    EvaluationGateFailed,
    DeploymentRequested,
    DeploymentApproved,
    DeploymentDenied,
    DeploymentExecuted,
    DeploymentRolledBack,
    FairnessPolicyRegistered,
    FairnessAssessed,
    FairnessViolationDetected,
    DriftPolicyRegistered,
    DriftDetected,
    DriftRemediationTriggered,
    DeprecationNoticeIssued,
    ModelRetired,
    AiDataExported,
    AiDataExportFailed,
    AiGovernanceSubscriberRegistered,
    AiGovernanceSubscriberRemoved,
}

impl fmt::Display for AiGovernanceLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ModelStored => "ModelStored",
            Self::ModelStatusChanged => "ModelStatusChanged",
            Self::ModelDeleted => "ModelDeleted",
            Self::DatasetStored => "DatasetStored",
            Self::DatasetQualityChanged => "DatasetQualityChanged",
            Self::EvaluationRecorded => "EvaluationRecorded",
            Self::EvaluationGatePassed => "EvaluationGatePassed",
            Self::EvaluationGateFailed => "EvaluationGateFailed",
            Self::DeploymentRequested => "DeploymentRequested",
            Self::DeploymentApproved => "DeploymentApproved",
            Self::DeploymentDenied => "DeploymentDenied",
            Self::DeploymentExecuted => "DeploymentExecuted",
            Self::DeploymentRolledBack => "DeploymentRolledBack",
            Self::FairnessPolicyRegistered => "FairnessPolicyRegistered",
            Self::FairnessAssessed => "FairnessAssessed",
            Self::FairnessViolationDetected => "FairnessViolationDetected",
            Self::DriftPolicyRegistered => "DriftPolicyRegistered",
            Self::DriftDetected => "DriftDetected",
            Self::DriftRemediationTriggered => "DriftRemediationTriggered",
            Self::DeprecationNoticeIssued => "DeprecationNoticeIssued",
            Self::ModelRetired => "ModelRetired",
            Self::AiDataExported => "AiDataExported",
            Self::AiDataExportFailed => "AiDataExportFailed",
            Self::AiGovernanceSubscriberRegistered => "AiGovernanceSubscriberRegistered",
            Self::AiGovernanceSubscriberRemoved => "AiGovernanceSubscriberRemoved",
        };
        f.write_str(s)
    }
}

// ── AiGovernanceLifecycleEvent ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiGovernanceLifecycleEvent {
    pub event_type: AiGovernanceLifecycleEventType,
    pub timestamp: i64,
    pub model_id: Option<String>,
    pub severity: Option<String>,
    pub detail: String,
}

impl AiGovernanceLifecycleEvent {
    pub fn new(
        event_type: AiGovernanceLifecycleEventType,
        timestamp: i64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp,
            model_id: None,
            severity: None,
            detail: detail.into(),
        }
    }

    pub fn with_model_id(mut self, model_id: impl Into<String>) -> Self {
        self.model_id = Some(model_id.into());
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = Some(severity.into());
        self
    }
}

// ── AiGovernanceEventSubscriber trait ──────────────────────────────

pub trait AiGovernanceEventSubscriber {
    fn on_ai_governance_event(&mut self, event: &AiGovernanceLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── AiGovernanceEventSubscriberRegistry ────────────────────────────

pub struct AiGovernanceEventSubscriberRegistry {
    subscribers: Vec<Box<dyn AiGovernanceEventSubscriber>>,
}

impl AiGovernanceEventSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn AiGovernanceEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &AiGovernanceLifecycleEvent) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_ai_governance_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[AiGovernanceLifecycleEvent]) {
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

impl Default for AiGovernanceEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── AiGovernanceEventCollector ─────────────────────────────────────

pub struct AiGovernanceEventCollector {
    id: String,
    active: bool,
    events: Vec<AiGovernanceLifecycleEvent>,
}

impl AiGovernanceEventCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            events: Vec::new(),
        }
    }

    pub fn events(&self) -> &[AiGovernanceLifecycleEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl AiGovernanceEventSubscriber for AiGovernanceEventCollector {
    fn on_ai_governance_event(&mut self, event: &AiGovernanceLifecycleEvent) {
        self.events.push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredAiGovernanceEventSubscriber ─────────────────────────────

pub struct FilteredAiGovernanceEventSubscriber {
    id: String,
    active: bool,
    events: Vec<AiGovernanceLifecycleEvent>,
    filter_event_type: Option<AiGovernanceLifecycleEventType>,
    filter_model_id: Option<String>,
    filter_severity: Option<String>,
}

impl FilteredAiGovernanceEventSubscriber {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            events: Vec::new(),
            filter_event_type: None,
            filter_model_id: None,
            filter_severity: None,
        }
    }

    pub fn with_event_type_filter(mut self, event_type: AiGovernanceLifecycleEventType) -> Self {
        self.filter_event_type = Some(event_type);
        self
    }

    pub fn with_model_id_filter(mut self, model_id: impl Into<String>) -> Self {
        self.filter_model_id = Some(model_id.into());
        self
    }

    pub fn with_severity_filter(mut self, severity: impl Into<String>) -> Self {
        self.filter_severity = Some(severity.into());
        self
    }

    pub fn events(&self) -> &[AiGovernanceLifecycleEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    fn matches(&self, event: &AiGovernanceLifecycleEvent) -> bool {
        if let Some(ref et) = self.filter_event_type
            && &event.event_type != et
        {
            return false;
        }
        if let Some(ref mid) = self.filter_model_id
            && event.model_id.as_deref() != Some(mid.as_str())
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

impl AiGovernanceEventSubscriber for FilteredAiGovernanceEventSubscriber {
    fn on_ai_governance_event(&mut self, event: &AiGovernanceLifecycleEvent) {
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

    fn make_event(event_type: AiGovernanceLifecycleEventType) -> AiGovernanceLifecycleEvent {
        AiGovernanceLifecycleEvent::new(event_type, 1000, "test event")
    }

    #[test]
    fn test_collector_receives_events() {
        let mut collector = AiGovernanceEventCollector::new("col-1");
        collector.on_ai_governance_event(&make_event(AiGovernanceLifecycleEventType::ModelStored));
        collector.on_ai_governance_event(&make_event(AiGovernanceLifecycleEventType::ModelDeleted));
        assert_eq!(collector.event_count(), 2);
        assert_eq!(collector.subscriber_id(), "col-1");
        assert!(collector.is_active());
    }

    #[test]
    fn test_registry_notify() {
        let mut registry = AiGovernanceEventSubscriberRegistry::new();
        registry.register(Box::new(AiGovernanceEventCollector::new("col-1")));
        registry.notify(&make_event(AiGovernanceLifecycleEventType::ModelStored));
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut registry = AiGovernanceEventSubscriberRegistry::new();
        registry.register(Box::new(AiGovernanceEventCollector::new("col-1")));
        let events = vec![
            make_event(AiGovernanceLifecycleEventType::ModelStored),
            make_event(AiGovernanceLifecycleEventType::DatasetStored),
        ];
        registry.notify_batch(&events);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_filtered_by_event_type() {
        let mut filtered = FilteredAiGovernanceEventSubscriber::new("f-1")
            .with_event_type_filter(AiGovernanceLifecycleEventType::DriftDetected);
        filtered.on_ai_governance_event(&make_event(AiGovernanceLifecycleEventType::ModelStored));
        filtered.on_ai_governance_event(&make_event(AiGovernanceLifecycleEventType::DriftDetected));
        assert_eq!(filtered.event_count(), 1);
    }

    #[test]
    fn test_filtered_by_model_id() {
        let mut filtered = FilteredAiGovernanceEventSubscriber::new("f-1")
            .with_model_id_filter("m-1");
        let e1 = make_event(AiGovernanceLifecycleEventType::ModelStored).with_model_id("m-1");
        let e2 = make_event(AiGovernanceLifecycleEventType::ModelStored).with_model_id("m-2");
        filtered.on_ai_governance_event(&e1);
        filtered.on_ai_governance_event(&e2);
        assert_eq!(filtered.event_count(), 1);
    }

    #[test]
    fn test_filtered_by_severity() {
        let mut filtered = FilteredAiGovernanceEventSubscriber::new("f-1")
            .with_severity_filter("Critical");
        let e1 = make_event(AiGovernanceLifecycleEventType::DriftDetected).with_severity("Critical");
        let e2 = make_event(AiGovernanceLifecycleEventType::DriftDetected).with_severity("Low");
        filtered.on_ai_governance_event(&e1);
        filtered.on_ai_governance_event(&e2);
        assert_eq!(filtered.event_count(), 1);
    }

    #[test]
    fn test_event_type_display_all() {
        let types = vec![
            AiGovernanceLifecycleEventType::ModelStored,
            AiGovernanceLifecycleEventType::ModelStatusChanged,
            AiGovernanceLifecycleEventType::ModelDeleted,
            AiGovernanceLifecycleEventType::DatasetStored,
            AiGovernanceLifecycleEventType::DatasetQualityChanged,
            AiGovernanceLifecycleEventType::EvaluationRecorded,
            AiGovernanceLifecycleEventType::EvaluationGatePassed,
            AiGovernanceLifecycleEventType::EvaluationGateFailed,
            AiGovernanceLifecycleEventType::DeploymentRequested,
            AiGovernanceLifecycleEventType::DeploymentApproved,
            AiGovernanceLifecycleEventType::DeploymentDenied,
            AiGovernanceLifecycleEventType::DeploymentExecuted,
            AiGovernanceLifecycleEventType::DeploymentRolledBack,
            AiGovernanceLifecycleEventType::FairnessPolicyRegistered,
            AiGovernanceLifecycleEventType::FairnessAssessed,
            AiGovernanceLifecycleEventType::FairnessViolationDetected,
            AiGovernanceLifecycleEventType::DriftPolicyRegistered,
            AiGovernanceLifecycleEventType::DriftDetected,
            AiGovernanceLifecycleEventType::DriftRemediationTriggered,
            AiGovernanceLifecycleEventType::DeprecationNoticeIssued,
            AiGovernanceLifecycleEventType::ModelRetired,
            AiGovernanceLifecycleEventType::AiDataExported,
            AiGovernanceLifecycleEventType::AiDataExportFailed,
            AiGovernanceLifecycleEventType::AiGovernanceSubscriberRegistered,
            AiGovernanceLifecycleEventType::AiGovernanceSubscriberRemoved,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 25);
    }

    #[test]
    fn test_event_builder_chain() {
        let event = AiGovernanceLifecycleEvent::new(
            AiGovernanceLifecycleEventType::DriftDetected, 5000, "drift detected",
        )
        .with_model_id("m-1")
        .with_severity("High");
        assert_eq!(event.model_id, Some("m-1".into()));
        assert_eq!(event.severity, Some("High".into()));
    }

    #[test]
    fn test_registry_default() {
        let registry = AiGovernanceEventSubscriberRegistry::default();
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn test_registry_remove_inactive() {
        let mut registry = AiGovernanceEventSubscriberRegistry::new();
        registry.register(Box::new(AiGovernanceEventCollector::new("col-1")));
        assert_eq!(registry.active_count(), 1);
        registry.remove_inactive();
        assert_eq!(registry.active_count(), 1);
    }
}
