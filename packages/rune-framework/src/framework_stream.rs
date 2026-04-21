// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — FrameworkLifecycleEventSubscriber trait, registry,
// collector, and filtered subscriber for framework lifecycle streaming.
// ═══════════════════════════════════════════════════════════════════════

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::backend::{FrameworkDomain, Jurisdiction};

// ── FrameworkLifecycleEventType ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrameworkLifecycleEventType {
    FrameworkRegistered,
    FrameworkRetrieved,
    FrameworkUnregistered,
    FrameworkVersionResolved,
    FrameworkUpdated,
    RequirementAdded,
    RequirementUpdated,
    RequirementRemoved,
    CrossFrameworkMappingRegistered,
    CrossFrameworkMappingDisputed,
    CrossFrameworkMappingResolved,
    ComplianceEvidenceRecorded,
    ComplianceEvidenceExpired,
    FrameworkExported,
    FrameworkExportFailed,
    FrameworkValidated,
    FrameworkValidationFailed,
    FrameworkSubscriberRegistered,
    FrameworkSubscriberRemoved,
    FrameworkEventPublished,
}

impl std::fmt::Display for FrameworkLifecycleEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::FrameworkRegistered => "FrameworkRegistered",
            Self::FrameworkRetrieved => "FrameworkRetrieved",
            Self::FrameworkUnregistered => "FrameworkUnregistered",
            Self::FrameworkVersionResolved => "FrameworkVersionResolved",
            Self::FrameworkUpdated => "FrameworkUpdated",
            Self::RequirementAdded => "RequirementAdded",
            Self::RequirementUpdated => "RequirementUpdated",
            Self::RequirementRemoved => "RequirementRemoved",
            Self::CrossFrameworkMappingRegistered => "CrossFrameworkMappingRegistered",
            Self::CrossFrameworkMappingDisputed => "CrossFrameworkMappingDisputed",
            Self::CrossFrameworkMappingResolved => "CrossFrameworkMappingResolved",
            Self::ComplianceEvidenceRecorded => "ComplianceEvidenceRecorded",
            Self::ComplianceEvidenceExpired => "ComplianceEvidenceExpired",
            Self::FrameworkExported => "FrameworkExported",
            Self::FrameworkExportFailed => "FrameworkExportFailed",
            Self::FrameworkValidated => "FrameworkValidated",
            Self::FrameworkValidationFailed => "FrameworkValidationFailed",
            Self::FrameworkSubscriberRegistered => "FrameworkSubscriberRegistered",
            Self::FrameworkSubscriberRemoved => "FrameworkSubscriberRemoved",
            Self::FrameworkEventPublished => "FrameworkEventPublished",
        };
        f.write_str(s)
    }
}

// ── FrameworkLifecycleEvent ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkLifecycleEvent {
    pub event_type: FrameworkLifecycleEventType,
    pub timestamp: i64,
    pub framework_id: Option<String>,
    pub jurisdiction: Option<Jurisdiction>,
    pub domain: Option<FrameworkDomain>,
    pub tag: Option<String>,
    pub detail: String,
}

impl FrameworkLifecycleEvent {
    pub fn new(
        event_type: FrameworkLifecycleEventType,
        timestamp: i64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp,
            framework_id: None,
            jurisdiction: None,
            domain: None,
            tag: None,
            detail: detail.into(),
        }
    }

    pub fn with_framework_id(mut self, id: impl Into<String>) -> Self {
        self.framework_id = Some(id.into());
        self
    }

    pub fn with_jurisdiction(mut self, jurisdiction: Jurisdiction) -> Self {
        self.jurisdiction = Some(jurisdiction);
        self
    }

    pub fn with_domain(mut self, domain: FrameworkDomain) -> Self {
        self.domain = Some(domain);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }
}

// ── FrameworkLifecycleEventSubscriber trait ───────────────────────────

pub trait FrameworkLifecycleEventSubscriber {
    fn on_framework_event(&mut self, event: &FrameworkLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── FrameworkLifecycleEventSubscriberRegistry ─────────────────────────

pub struct FrameworkLifecycleEventSubscriberRegistry {
    subscribers: Vec<Box<dyn FrameworkLifecycleEventSubscriber>>,
}

impl FrameworkLifecycleEventSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn FrameworkLifecycleEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &FrameworkLifecycleEvent) {
        for subscriber in &mut self.subscribers {
            if subscriber.is_active() {
                subscriber.on_framework_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[FrameworkLifecycleEvent]) {
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

impl Default for FrameworkLifecycleEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── FrameworkLifecycleEventCollector ──────────────────────────────────

pub struct FrameworkLifecycleEventCollector {
    id: String,
    events: Mutex<Vec<FrameworkLifecycleEvent>>,
    active: bool,
}

impl FrameworkLifecycleEventCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            events: Mutex::new(Vec::new()),
            active: true,
        }
    }

    pub fn collected(&self) -> Vec<FrameworkLifecycleEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn collected_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl FrameworkLifecycleEventSubscriber for FrameworkLifecycleEventCollector {
    fn on_framework_event(&mut self, event: &FrameworkLifecycleEvent) {
        self.events.lock().unwrap().push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredFrameworkLifecycleEventSubscriber ─────────────────────────

pub struct FilteredFrameworkLifecycleEventSubscriber<S: FrameworkLifecycleEventSubscriber> {
    inner: S,
    jurisdiction_filter: Option<Jurisdiction>,
    domain_filter: Option<FrameworkDomain>,
    framework_id_filter: Option<String>,
    event_type_filter: Option<FrameworkLifecycleEventType>,
}

impl<S: FrameworkLifecycleEventSubscriber> FilteredFrameworkLifecycleEventSubscriber<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            jurisdiction_filter: None,
            domain_filter: None,
            framework_id_filter: None,
            event_type_filter: None,
        }
    }

    pub fn with_jurisdiction_filter(mut self, jurisdiction: Jurisdiction) -> Self {
        self.jurisdiction_filter = Some(jurisdiction);
        self
    }

    pub fn with_domain_filter(mut self, domain: FrameworkDomain) -> Self {
        self.domain_filter = Some(domain);
        self
    }

    pub fn with_framework_id_filter(mut self, framework_id: impl Into<String>) -> Self {
        self.framework_id_filter = Some(framework_id.into());
        self
    }

    pub fn with_event_type_filter(mut self, event_type: FrameworkLifecycleEventType) -> Self {
        self.event_type_filter = Some(event_type);
        self
    }

    fn matches(&self, event: &FrameworkLifecycleEvent) -> bool {
        if let Some(ref j) = self.jurisdiction_filter {
            if let Some(ref ej) = event.jurisdiction {
                if ej != j {
                    return false;
                }
            } else {
                return false;
            }
        }
        if let Some(ref d) = self.domain_filter {
            if let Some(ref ed) = event.domain {
                if ed != d {
                    return false;
                }
            } else {
                return false;
            }
        }
        if let Some(ref fid) = self.framework_id_filter {
            if let Some(ref efid) = event.framework_id {
                if efid != fid {
                    return false;
                }
            } else {
                return false;
            }
        }
        if let Some(ref et) = self.event_type_filter {
            if &event.event_type != et {
                return false;
            }
        }
        true
    }
}

impl<S: FrameworkLifecycleEventSubscriber> FrameworkLifecycleEventSubscriber
    for FilteredFrameworkLifecycleEventSubscriber<S>
{
    fn on_framework_event(&mut self, event: &FrameworkLifecycleEvent) {
        if self.matches(event) {
            self.inner.on_framework_event(event);
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

    #[test]
    fn test_lifecycle_event_type_display() {
        let types = vec![
            FrameworkLifecycleEventType::FrameworkRegistered,
            FrameworkLifecycleEventType::FrameworkRetrieved,
            FrameworkLifecycleEventType::FrameworkUnregistered,
            FrameworkLifecycleEventType::FrameworkVersionResolved,
            FrameworkLifecycleEventType::FrameworkUpdated,
            FrameworkLifecycleEventType::RequirementAdded,
            FrameworkLifecycleEventType::RequirementUpdated,
            FrameworkLifecycleEventType::RequirementRemoved,
            FrameworkLifecycleEventType::CrossFrameworkMappingRegistered,
            FrameworkLifecycleEventType::CrossFrameworkMappingDisputed,
            FrameworkLifecycleEventType::CrossFrameworkMappingResolved,
            FrameworkLifecycleEventType::ComplianceEvidenceRecorded,
            FrameworkLifecycleEventType::ComplianceEvidenceExpired,
            FrameworkLifecycleEventType::FrameworkExported,
            FrameworkLifecycleEventType::FrameworkExportFailed,
            FrameworkLifecycleEventType::FrameworkValidated,
            FrameworkLifecycleEventType::FrameworkValidationFailed,
            FrameworkLifecycleEventType::FrameworkSubscriberRegistered,
            FrameworkLifecycleEventType::FrameworkSubscriberRemoved,
            FrameworkLifecycleEventType::FrameworkEventPublished,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 20);
    }

    #[test]
    fn test_event_builder() {
        let event = FrameworkLifecycleEvent::new(
            FrameworkLifecycleEventType::FrameworkRegistered,
            1000,
            "registered CJIS v6.0",
        )
        .with_framework_id("cjis-v6.0")
        .with_jurisdiction(Jurisdiction::UnitedStates)
        .with_tag("cjis");
        assert_eq!(event.framework_id, Some("cjis-v6.0".to_string()));
        assert_eq!(event.jurisdiction, Some(Jurisdiction::UnitedStates));
        assert_eq!(event.tag, Some("cjis".to_string()));
    }

    #[test]
    fn test_collector() {
        let mut collector = FrameworkLifecycleEventCollector::new("test-collector");
        let event = FrameworkLifecycleEvent::new(
            FrameworkLifecycleEventType::FrameworkRegistered,
            1000,
            "test",
        );
        collector.on_framework_event(&event);
        assert_eq!(collector.collected_count(), 1);
        assert!(collector.is_active());
    }

    #[test]
    fn test_collector_deactivate() {
        let mut collector = FrameworkLifecycleEventCollector::new("test");
        collector.deactivate();
        assert!(!collector.is_active());
    }

    #[test]
    fn test_registry_notify() {
        let mut registry = FrameworkLifecycleEventSubscriberRegistry::new();
        let collector = FrameworkLifecycleEventCollector::new("c-1");
        registry.register(Box::new(collector));
        assert_eq!(registry.active_count(), 1);

        let event = FrameworkLifecycleEvent::new(
            FrameworkLifecycleEventType::FrameworkRegistered,
            1000,
            "test",
        );
        registry.notify(&event);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut registry = FrameworkLifecycleEventSubscriberRegistry::new();
        registry.register(Box::new(FrameworkLifecycleEventCollector::new("c-1")));

        let events = vec![
            FrameworkLifecycleEvent::new(
                FrameworkLifecycleEventType::FrameworkRegistered,
                1000,
                "a",
            ),
            FrameworkLifecycleEvent::new(
                FrameworkLifecycleEventType::FrameworkUpdated,
                1001,
                "b",
            ),
        ];
        registry.notify_batch(&events);
    }

    #[test]
    fn test_filtered_subscriber_jurisdiction() {
        let collector = FrameworkLifecycleEventCollector::new("filtered");
        let mut filtered =
            FilteredFrameworkLifecycleEventSubscriber::new(collector)
                .with_jurisdiction_filter(Jurisdiction::UnitedStates);

        let us_event = FrameworkLifecycleEvent::new(
            FrameworkLifecycleEventType::FrameworkRegistered,
            1000,
            "US",
        )
        .with_jurisdiction(Jurisdiction::UnitedStates);

        let eu_event = FrameworkLifecycleEvent::new(
            FrameworkLifecycleEventType::FrameworkRegistered,
            1001,
            "EU",
        )
        .with_jurisdiction(Jurisdiction::EuropeanUnion);

        filtered.on_framework_event(&us_event);
        filtered.on_framework_event(&eu_event);
        assert_eq!(filtered.inner.collected_count(), 1);
    }

    #[test]
    fn test_filtered_subscriber_event_type() {
        let collector = FrameworkLifecycleEventCollector::new("filtered");
        let mut filtered = FilteredFrameworkLifecycleEventSubscriber::new(collector)
            .with_event_type_filter(FrameworkLifecycleEventType::FrameworkExported);

        let export = FrameworkLifecycleEvent::new(
            FrameworkLifecycleEventType::FrameworkExported,
            1000,
            "exported",
        );
        let register = FrameworkLifecycleEvent::new(
            FrameworkLifecycleEventType::FrameworkRegistered,
            1001,
            "registered",
        );

        filtered.on_framework_event(&export);
        filtered.on_framework_event(&register);
        assert_eq!(filtered.inner.collected_count(), 1);
    }

    #[test]
    fn test_filtered_subscriber_framework_id() {
        let collector = FrameworkLifecycleEventCollector::new("filtered");
        let mut filtered = FilteredFrameworkLifecycleEventSubscriber::new(collector)
            .with_framework_id_filter("cjis-v6.0");

        let cjis_event = FrameworkLifecycleEvent::new(
            FrameworkLifecycleEventType::FrameworkRegistered,
            1000,
            "cjis",
        )
        .with_framework_id("cjis-v6.0");

        let gdpr_event = FrameworkLifecycleEvent::new(
            FrameworkLifecycleEventType::FrameworkRegistered,
            1001,
            "gdpr",
        )
        .with_framework_id("gdpr");

        filtered.on_framework_event(&cjis_event);
        filtered.on_framework_event(&gdpr_event);
        assert_eq!(filtered.inner.collected_count(), 1);
    }

    #[test]
    fn test_remove_inactive() {
        let mut registry = FrameworkLifecycleEventSubscriberRegistry::new();
        let mut collector = FrameworkLifecycleEventCollector::new("c-1");
        collector.deactivate();
        registry.register(Box::new(collector));
        registry.register(Box::new(FrameworkLifecycleEventCollector::new("c-2")));
        assert_eq!(registry.active_count(), 1);
        registry.remove_inactive();
        assert_eq!(registry.active_count(), 1);
    }
}
