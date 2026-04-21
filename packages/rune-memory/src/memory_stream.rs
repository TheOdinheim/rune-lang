// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — MemoryGovernanceEventSubscriber trait and registry for
// lifecycle event streaming with filtering by scope_id, event_type,
// severity.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── MemoryGovernanceLifecycleEventType ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryGovernanceLifecycleEventType {
    MemoryEntryStored,
    MemoryEntryRetrieved,
    MemoryEntryDeleted,
    MemoryScopeCreated,
    MemoryScopeAccessEvaluated,
    RetentionPolicyRegistered,
    RetentionGovernanceEvaluated,
    RetentionSweepExecuted,
    RetentionComplianceAssessed,
    RedactionPolicyRegistered,
    RetrievalGovernanceEvaluated,
    RetrievalGovernanceDenied,
    CollectionPolicyRegistered,
    CollectionPolicyRemoved,
    IsolationBoundaryStored,
    IsolationViolationRecorded,
    ScopeAccessGovernanceEvaluated,
    ScopeHealthAssessed,
    GovernanceExported,
    GovernanceExportFailed,
    GovernanceMetricsComputed,
}

impl fmt::Display for MemoryGovernanceLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MemoryEntryStored => "MemoryEntryStored",
            Self::MemoryEntryRetrieved => "MemoryEntryRetrieved",
            Self::MemoryEntryDeleted => "MemoryEntryDeleted",
            Self::MemoryScopeCreated => "MemoryScopeCreated",
            Self::MemoryScopeAccessEvaluated => "MemoryScopeAccessEvaluated",
            Self::RetentionPolicyRegistered => "RetentionPolicyRegistered",
            Self::RetentionGovernanceEvaluated => "RetentionGovernanceEvaluated",
            Self::RetentionSweepExecuted => "RetentionSweepExecuted",
            Self::RetentionComplianceAssessed => "RetentionComplianceAssessed",
            Self::RedactionPolicyRegistered => "RedactionPolicyRegistered",
            Self::RetrievalGovernanceEvaluated => "RetrievalGovernanceEvaluated",
            Self::RetrievalGovernanceDenied => "RetrievalGovernanceDenied",
            Self::CollectionPolicyRegistered => "CollectionPolicyRegistered",
            Self::CollectionPolicyRemoved => "CollectionPolicyRemoved",
            Self::IsolationBoundaryStored => "IsolationBoundaryStored",
            Self::IsolationViolationRecorded => "IsolationViolationRecorded",
            Self::ScopeAccessGovernanceEvaluated => "ScopeAccessGovernanceEvaluated",
            Self::ScopeHealthAssessed => "ScopeHealthAssessed",
            Self::GovernanceExported => "GovernanceExported",
            Self::GovernanceExportFailed => "GovernanceExportFailed",
            Self::GovernanceMetricsComputed => "GovernanceMetricsComputed",
        };
        f.write_str(s)
    }
}

// ── MemoryGovernanceLifecycleEvent ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGovernanceLifecycleEvent {
    pub event_type: MemoryGovernanceLifecycleEventType,
    pub timestamp: i64,
    pub scope_id: String,
    pub severity: String,
    pub detail: String,
}

impl MemoryGovernanceLifecycleEvent {
    pub fn new(
        event_type: MemoryGovernanceLifecycleEventType,
        timestamp: i64,
        scope_id: impl Into<String>,
        severity: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp,
            scope_id: scope_id.into(),
            severity: severity.into(),
            detail: detail.into(),
        }
    }
}

// ── MemoryGovernanceEventSubscriber trait ───────────────────────────

pub trait MemoryGovernanceEventSubscriber {
    fn on_memory_governance_event(&mut self, event: &MemoryGovernanceLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── MemoryGovernanceEventSubscriberRegistry ─────────────────────────

pub struct MemoryGovernanceEventSubscriberRegistry {
    subscribers: Vec<Box<dyn MemoryGovernanceEventSubscriber>>,
}

impl MemoryGovernanceEventSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn MemoryGovernanceEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &MemoryGovernanceLifecycleEvent) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_memory_governance_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[MemoryGovernanceLifecycleEvent]) {
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

impl Default for MemoryGovernanceEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── MemoryGovernanceEventCollector ──────────────────────────────────

pub struct MemoryGovernanceEventCollector {
    id: String,
    collected: Vec<MemoryGovernanceLifecycleEvent>,
    active: bool,
}

impl MemoryGovernanceEventCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            collected: Vec::new(),
            active: true,
        }
    }

    pub fn collected_events(&self) -> &[MemoryGovernanceLifecycleEvent] {
        &self.collected
    }
}

impl MemoryGovernanceEventSubscriber for MemoryGovernanceEventCollector {
    fn on_memory_governance_event(&mut self, event: &MemoryGovernanceLifecycleEvent) {
        self.collected.push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredMemoryGovernanceEventSubscriber ─────────────────────────

pub struct FilteredMemoryGovernanceEventSubscriber<S: MemoryGovernanceEventSubscriber> {
    inner: S,
    scope_id_filter: Option<String>,
    event_type_filter: Option<MemoryGovernanceLifecycleEventType>,
    severity_filter: Option<String>,
}

impl<S: MemoryGovernanceEventSubscriber> FilteredMemoryGovernanceEventSubscriber<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            scope_id_filter: None,
            event_type_filter: None,
            severity_filter: None,
        }
    }

    pub fn with_scope_id(mut self, scope_id: impl Into<String>) -> Self {
        self.scope_id_filter = Some(scope_id.into());
        self
    }

    pub fn with_event_type(mut self, event_type: MemoryGovernanceLifecycleEventType) -> Self {
        self.event_type_filter = Some(event_type);
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity_filter = Some(severity.into());
        self
    }

    fn matches(&self, event: &MemoryGovernanceLifecycleEvent) -> bool {
        if let Some(ref sid) = self.scope_id_filter && &event.scope_id != sid {
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

impl<S: MemoryGovernanceEventSubscriber> MemoryGovernanceEventSubscriber
    for FilteredMemoryGovernanceEventSubscriber<S>
{
    fn on_memory_governance_event(&mut self, event: &MemoryGovernanceLifecycleEvent) {
        if self.matches(event) {
            self.inner.on_memory_governance_event(event);
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

    fn sample_event(
        et: MemoryGovernanceLifecycleEventType,
    ) -> MemoryGovernanceLifecycleEvent {
        MemoryGovernanceLifecycleEvent::new(et, 1000, "scope-1", "Critical", "test detail")
    }

    #[test]
    fn test_collector() {
        let mut collector = MemoryGovernanceEventCollector::new("c1");
        collector.on_memory_governance_event(&sample_event(
            MemoryGovernanceLifecycleEventType::MemoryEntryStored,
        ));
        assert_eq!(collector.collected_events().len(), 1);
    }

    #[test]
    fn test_registry_notify() {
        let mut reg = MemoryGovernanceEventSubscriberRegistry::new();
        reg.register(Box::new(MemoryGovernanceEventCollector::new("c1")));
        reg.register(Box::new(MemoryGovernanceEventCollector::new("c2")));
        reg.notify(&sample_event(
            MemoryGovernanceLifecycleEventType::RetentionGovernanceEvaluated,
        ));
        assert_eq!(reg.active_count(), 2);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut reg = MemoryGovernanceEventSubscriberRegistry::new();
        reg.register(Box::new(MemoryGovernanceEventCollector::new("c1")));
        let events = vec![
            sample_event(MemoryGovernanceLifecycleEventType::CollectionPolicyRegistered),
            sample_event(MemoryGovernanceLifecycleEventType::ScopeHealthAssessed),
        ];
        reg.notify_batch(&events);
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn test_filtered_by_scope_id() {
        let inner = MemoryGovernanceEventCollector::new("f1");
        let mut filtered =
            FilteredMemoryGovernanceEventSubscriber::new(inner).with_scope_id("scope-1");
        filtered.on_memory_governance_event(&sample_event(
            MemoryGovernanceLifecycleEventType::MemoryEntryStored,
        ));
        let other = MemoryGovernanceLifecycleEvent::new(
            MemoryGovernanceLifecycleEventType::MemoryEntryStored,
            2000,
            "scope-2",
            "Warning",
            "other",
        );
        filtered.on_memory_governance_event(&other);
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_by_event_type() {
        let inner = MemoryGovernanceEventCollector::new("f1");
        let mut filtered = FilteredMemoryGovernanceEventSubscriber::new(inner)
            .with_event_type(MemoryGovernanceLifecycleEventType::RetentionSweepExecuted);
        filtered.on_memory_governance_event(&sample_event(
            MemoryGovernanceLifecycleEventType::MemoryEntryStored,
        ));
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_by_severity() {
        let inner = MemoryGovernanceEventCollector::new("f1");
        let mut filtered =
            FilteredMemoryGovernanceEventSubscriber::new(inner).with_severity("Critical");
        filtered.on_memory_governance_event(&sample_event(
            MemoryGovernanceLifecycleEventType::IsolationViolationRecorded,
        ));
        assert!(filtered.is_active());
    }

    #[test]
    fn test_event_type_display_all() {
        let types = vec![
            MemoryGovernanceLifecycleEventType::MemoryEntryStored,
            MemoryGovernanceLifecycleEventType::MemoryEntryRetrieved,
            MemoryGovernanceLifecycleEventType::MemoryEntryDeleted,
            MemoryGovernanceLifecycleEventType::MemoryScopeCreated,
            MemoryGovernanceLifecycleEventType::MemoryScopeAccessEvaluated,
            MemoryGovernanceLifecycleEventType::RetentionPolicyRegistered,
            MemoryGovernanceLifecycleEventType::RetentionGovernanceEvaluated,
            MemoryGovernanceLifecycleEventType::RetentionSweepExecuted,
            MemoryGovernanceLifecycleEventType::RetentionComplianceAssessed,
            MemoryGovernanceLifecycleEventType::RedactionPolicyRegistered,
            MemoryGovernanceLifecycleEventType::RetrievalGovernanceEvaluated,
            MemoryGovernanceLifecycleEventType::RetrievalGovernanceDenied,
            MemoryGovernanceLifecycleEventType::CollectionPolicyRegistered,
            MemoryGovernanceLifecycleEventType::CollectionPolicyRemoved,
            MemoryGovernanceLifecycleEventType::IsolationBoundaryStored,
            MemoryGovernanceLifecycleEventType::IsolationViolationRecorded,
            MemoryGovernanceLifecycleEventType::ScopeAccessGovernanceEvaluated,
            MemoryGovernanceLifecycleEventType::ScopeHealthAssessed,
            MemoryGovernanceLifecycleEventType::GovernanceExported,
            MemoryGovernanceLifecycleEventType::GovernanceExportFailed,
            MemoryGovernanceLifecycleEventType::GovernanceMetricsComputed,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 21);
    }

    #[test]
    fn test_lifecycle_event_builder() {
        let e = MemoryGovernanceLifecycleEvent::new(
            MemoryGovernanceLifecycleEventType::RetentionSweepExecuted,
            5000,
            "scope-alpha",
            "Critical",
            "sweep triggered",
        );
        assert_eq!(e.scope_id, "scope-alpha");
        assert_eq!(e.severity, "Critical");
    }

    #[test]
    fn test_remove_inactive() {
        let mut reg = MemoryGovernanceEventSubscriberRegistry::new();
        reg.register(Box::new(MemoryGovernanceEventCollector::new("c1")));
        assert_eq!(reg.active_count(), 1);
        reg.remove_inactive();
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn test_subscriber_id() {
        let c = MemoryGovernanceEventCollector::new("my-sub");
        assert_eq!(c.subscriber_id(), "my-sub");
    }

    #[test]
    fn test_registry_default() {
        let reg = MemoryGovernanceEventSubscriberRegistry::default();
        assert_eq!(reg.active_count(), 0);
    }
}
