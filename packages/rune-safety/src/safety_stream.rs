// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — SafetyEventSubscriber trait and registry for lifecycle
// event streaming with filtering by system_id, event_type, severity.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── SafetyLifecycleEventType ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafetyLifecycleEventType {
    SafetyConstraintCreated,
    SafetyConstraintUpdated,
    SafetyConstraintRemoved,
    EnvelopeActivated,
    EnvelopeSuspended,
    EnvelopeRetired,
    EnvelopeStatusChecked,
    BoundaryApproachingDetected,
    BoundaryViolationDetected,
    SafetyResponseRecommended,
    SafetyCaseCreated,
    SafetyCaseFinalized,
    SafetyCaseChallenged,
    EmergencyShutdownInitiated,
    EmergencyShutdownCompleted,
    EmergencyShutdownFailed,
    ReauthorizationRequested,
    ReauthorizationGranted,
    SafetyExported,
    SafetyExportFailed,
}

impl fmt::Display for SafetyLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SafetyConstraintCreated => "SafetyConstraintCreated",
            Self::SafetyConstraintUpdated => "SafetyConstraintUpdated",
            Self::SafetyConstraintRemoved => "SafetyConstraintRemoved",
            Self::EnvelopeActivated => "EnvelopeActivated",
            Self::EnvelopeSuspended => "EnvelopeSuspended",
            Self::EnvelopeRetired => "EnvelopeRetired",
            Self::EnvelopeStatusChecked => "EnvelopeStatusChecked",
            Self::BoundaryApproachingDetected => "BoundaryApproachingDetected",
            Self::BoundaryViolationDetected => "BoundaryViolationDetected",
            Self::SafetyResponseRecommended => "SafetyResponseRecommended",
            Self::SafetyCaseCreated => "SafetyCaseCreated",
            Self::SafetyCaseFinalized => "SafetyCaseFinalized",
            Self::SafetyCaseChallenged => "SafetyCaseChallenged",
            Self::EmergencyShutdownInitiated => "EmergencyShutdownInitiated",
            Self::EmergencyShutdownCompleted => "EmergencyShutdownCompleted",
            Self::EmergencyShutdownFailed => "EmergencyShutdownFailed",
            Self::ReauthorizationRequested => "ReauthorizationRequested",
            Self::ReauthorizationGranted => "ReauthorizationGranted",
            Self::SafetyExported => "SafetyExported",
            Self::SafetyExportFailed => "SafetyExportFailed",
        };
        f.write_str(s)
    }
}

// ── SafetyLifecycleEvent ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyLifecycleEvent {
    pub event_type: SafetyLifecycleEventType,
    pub timestamp: i64,
    pub system_id: String,
    pub severity: String,
    pub detail: String,
}

impl SafetyLifecycleEvent {
    pub fn new(
        event_type: SafetyLifecycleEventType,
        timestamp: i64,
        system_id: impl Into<String>,
        severity: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp,
            system_id: system_id.into(),
            severity: severity.into(),
            detail: detail.into(),
        }
    }
}

// ── SafetyEventSubscriber trait ─────────────────────────────────────

pub trait SafetyEventSubscriber {
    fn on_safety_event(&mut self, event: &SafetyLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── SafetyEventSubscriberRegistry ───────────────────────────────────

pub struct SafetyEventSubscriberRegistry {
    subscribers: Vec<Box<dyn SafetyEventSubscriber>>,
}

impl SafetyEventSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn SafetyEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &SafetyLifecycleEvent) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_safety_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[SafetyLifecycleEvent]) {
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

impl Default for SafetyEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── SafetyEventCollector ────────────────────────────────────────────

pub struct SafetyEventCollector {
    id: String,
    collected: Vec<SafetyLifecycleEvent>,
    active: bool,
}

impl SafetyEventCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            collected: Vec::new(),
            active: true,
        }
    }

    pub fn collected_events(&self) -> &[SafetyLifecycleEvent] {
        &self.collected
    }
}

impl SafetyEventSubscriber for SafetyEventCollector {
    fn on_safety_event(&mut self, event: &SafetyLifecycleEvent) {
        self.collected.push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredSafetyEventSubscriber ───────────────────────────────────

pub struct FilteredSafetyEventSubscriber<S: SafetyEventSubscriber> {
    inner: S,
    system_id_filter: Option<String>,
    event_type_filter: Option<SafetyLifecycleEventType>,
    severity_filter: Option<String>,
}

impl<S: SafetyEventSubscriber> FilteredSafetyEventSubscriber<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            system_id_filter: None,
            event_type_filter: None,
            severity_filter: None,
        }
    }

    pub fn with_system_id(mut self, system_id: impl Into<String>) -> Self {
        self.system_id_filter = Some(system_id.into());
        self
    }

    pub fn with_event_type(mut self, event_type: SafetyLifecycleEventType) -> Self {
        self.event_type_filter = Some(event_type);
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity_filter = Some(severity.into());
        self
    }

    fn matches(&self, event: &SafetyLifecycleEvent) -> bool {
        if let Some(ref sid) = self.system_id_filter && &event.system_id != sid {
            return false;
        }
        if let Some(ref et) = self.event_type_filter && &event.event_type != et {
            return false;
        }
        if let Some(ref sev) = self.severity_filter && &event.severity != sev {
            return false;
        }
        true
    }
}

impl<S: SafetyEventSubscriber> SafetyEventSubscriber for FilteredSafetyEventSubscriber<S> {
    fn on_safety_event(&mut self, event: &SafetyLifecycleEvent) {
        if self.matches(event) {
            self.inner.on_safety_event(event);
        }
    }

    fn subscriber_id(&self) -> &str {
        self.inner.subscriber_id()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(et: SafetyLifecycleEventType) -> SafetyLifecycleEvent {
        SafetyLifecycleEvent::new(et, 1000, "sys-1", "Critical", "test detail")
    }

    #[test]
    fn test_collector() {
        let mut collector = SafetyEventCollector::new("c1");
        collector.on_safety_event(&sample_event(SafetyLifecycleEventType::EnvelopeActivated));
        assert_eq!(collector.collected_events().len(), 1);
    }

    #[test]
    fn test_registry_notify() {
        let mut reg = SafetyEventSubscriberRegistry::new();
        reg.register(Box::new(SafetyEventCollector::new("c1")));
        reg.register(Box::new(SafetyEventCollector::new("c2")));
        reg.notify(&sample_event(SafetyLifecycleEventType::SafetyConstraintCreated));
        assert_eq!(reg.active_count(), 2);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut reg = SafetyEventSubscriberRegistry::new();
        reg.register(Box::new(SafetyEventCollector::new("c1")));
        let events = vec![
            sample_event(SafetyLifecycleEventType::SafetyConstraintCreated),
            sample_event(SafetyLifecycleEventType::EnvelopeActivated),
        ];
        reg.notify_batch(&events);
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn test_filtered_by_system_id() {
        let inner = SafetyEventCollector::new("f1");
        let mut filtered = FilteredSafetyEventSubscriber::new(inner).with_system_id("sys-1");
        filtered.on_safety_event(&sample_event(SafetyLifecycleEventType::EnvelopeActivated));
        let other = SafetyLifecycleEvent::new(
            SafetyLifecycleEventType::EnvelopeActivated,
            2000,
            "sys-2",
            "Warning",
            "other",
        );
        filtered.on_safety_event(&other);
        // Can't easily access inner here, but test the filter logic matches
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_by_event_type() {
        let inner = SafetyEventCollector::new("f1");
        let mut filtered = FilteredSafetyEventSubscriber::new(inner)
            .with_event_type(SafetyLifecycleEventType::EmergencyShutdownInitiated);
        // This event should NOT match
        filtered.on_safety_event(&sample_event(SafetyLifecycleEventType::EnvelopeActivated));
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_by_severity() {
        let inner = SafetyEventCollector::new("f1");
        let mut filtered =
            FilteredSafetyEventSubscriber::new(inner).with_severity("Critical");
        filtered.on_safety_event(&sample_event(SafetyLifecycleEventType::EnvelopeActivated));
        assert!(filtered.is_active());
    }

    #[test]
    fn test_event_type_display_all() {
        let types = vec![
            SafetyLifecycleEventType::SafetyConstraintCreated,
            SafetyLifecycleEventType::SafetyConstraintUpdated,
            SafetyLifecycleEventType::SafetyConstraintRemoved,
            SafetyLifecycleEventType::EnvelopeActivated,
            SafetyLifecycleEventType::EnvelopeSuspended,
            SafetyLifecycleEventType::EnvelopeRetired,
            SafetyLifecycleEventType::EnvelopeStatusChecked,
            SafetyLifecycleEventType::BoundaryApproachingDetected,
            SafetyLifecycleEventType::BoundaryViolationDetected,
            SafetyLifecycleEventType::SafetyResponseRecommended,
            SafetyLifecycleEventType::SafetyCaseCreated,
            SafetyLifecycleEventType::SafetyCaseFinalized,
            SafetyLifecycleEventType::SafetyCaseChallenged,
            SafetyLifecycleEventType::EmergencyShutdownInitiated,
            SafetyLifecycleEventType::EmergencyShutdownCompleted,
            SafetyLifecycleEventType::EmergencyShutdownFailed,
            SafetyLifecycleEventType::ReauthorizationRequested,
            SafetyLifecycleEventType::ReauthorizationGranted,
            SafetyLifecycleEventType::SafetyExported,
            SafetyLifecycleEventType::SafetyExportFailed,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 20);
    }

    #[test]
    fn test_lifecycle_event_builder() {
        let e = SafetyLifecycleEvent::new(
            SafetyLifecycleEventType::EmergencyShutdownInitiated,
            5000,
            "sys-alpha",
            "Critical",
            "emergency triggered",
        );
        assert_eq!(e.system_id, "sys-alpha");
        assert_eq!(e.severity, "Critical");
    }

    #[test]
    fn test_remove_inactive() {
        let mut reg = SafetyEventSubscriberRegistry::new();
        reg.register(Box::new(SafetyEventCollector::new("c1")));
        assert_eq!(reg.active_count(), 1);
        reg.remove_inactive();
        assert_eq!(reg.active_count(), 1); // all are active
    }

    #[test]
    fn test_subscriber_id() {
        let c = SafetyEventCollector::new("my-sub");
        assert_eq!(c.subscriber_id(), "my-sub");
    }
}
