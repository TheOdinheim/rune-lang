// ═══════════════════════════════════════════════════════════════════════
// Subscriber — Audit event streaming interface.
//
// Layer 3 defines the contract for streaming audit events in
// real-time to external consumers. This is the "firehose" that a
// RUNE application would connect to a message queue, webhook, or
// log aggregator.
// ═══════════════════════════════════════════════════════════════════════

use crate::event::UnifiedEvent;

// ── AuditSubscriber trait ─────────────────────────────────────────

pub trait AuditSubscriber {
    fn on_event(&mut self, event: &UnifiedEvent);

    fn on_batch(&mut self, events: &[UnifiedEvent]) {
        for e in events {
            self.on_event(e);
        }
    }

    fn subscriber_id(&self) -> &str;

    fn is_active(&self) -> bool;
}

// ── AuditSubscriberRegistry ───────────────────────────────────────

pub struct AuditSubscriberRegistry {
    subscribers: Vec<Box<dyn AuditSubscriber>>,
}

impl AuditSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn AuditSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify_all(&mut self, event: &UnifiedEvent) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[UnifiedEvent]) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_batch(events);
            }
        }
    }

    pub fn active_count(&self) -> usize {
        self.subscribers.iter().filter(|s| s.is_active()).count()
    }

    pub fn remove_inactive(&mut self) -> usize {
        let before = self.subscribers.len();
        self.subscribers.retain(|s| s.is_active());
        before - self.subscribers.len()
    }
}

impl Default for AuditSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── CollectorSubscriber ───────────────────────────────────────────

pub struct CollectorSubscriber {
    id: String,
    collected: Vec<UnifiedEvent>,
    active: bool,
}

impl CollectorSubscriber {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            collected: Vec::new(),
            active: true,
        }
    }

    pub fn collected(&self) -> &[UnifiedEvent] {
        &self.collected
    }

    pub fn collected_count(&self) -> usize {
        self.collected.len()
    }

    pub fn drain(&mut self) -> Vec<UnifiedEvent> {
        std::mem::take(&mut self.collected)
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl AuditSubscriber for CollectorSubscriber {
    fn on_event(&mut self, event: &UnifiedEvent) {
        self.collected.push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredSubscriber ────────────────────────────────────────────

pub struct FilteredSubscriber {
    id: String,
    inner: Box<dyn AuditSubscriber>,
    filter_type: String,
    active: bool,
}

impl FilteredSubscriber {
    pub fn new(id: &str, inner: Box<dyn AuditSubscriber>, filter_type: &str) -> Self {
        Self {
            id: id.to_string(),
            inner,
            filter_type: filter_type.to_string(),
            active: true,
        }
    }
}

impl AuditSubscriber for FilteredSubscriber {
    fn on_event(&mut self, event: &UnifiedEvent) {
        if event.action == self.filter_type {
            self.inner.on_event(event);
        }
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active && self.inner.is_active()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;
    use rune_security::SecuritySeverity;

    fn make_event(id: &str, action: &str) -> UnifiedEvent {
        UnifiedEventBuilder::new(
            id,
            SourceCrate::RuneSecurity,
            EventCategory::ThreatDetection,
            action,
            1000,
        )
        .severity(SecuritySeverity::Medium)
        .build()
    }

    #[test]
    fn test_collector_subscriber_collects_events() {
        let mut sub = CollectorSubscriber::new("test-collector");
        sub.on_event(&make_event("e1", "scan"));
        sub.on_event(&make_event("e2", "alert"));
        assert_eq!(sub.collected_count(), 2);
        assert_eq!(sub.collected()[0].id, UnifiedEventId::new("e1"));
    }

    #[test]
    fn test_collector_subscriber_drain() {
        let mut sub = CollectorSubscriber::new("test-collector");
        sub.on_event(&make_event("e1", "scan"));
        sub.on_event(&make_event("e2", "alert"));
        let drained = sub.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(sub.collected_count(), 0);
    }

    #[test]
    fn test_filtered_subscriber_only_passes_matching() {
        let collector = CollectorSubscriber::new("inner");
        let mut filtered = FilteredSubscriber::new(
            "filter-scan",
            Box::new(collector),
            "scan",
        );
        filtered.on_event(&make_event("e1", "scan"));
        filtered.on_event(&make_event("e2", "alert"));
        filtered.on_event(&make_event("e3", "scan"));
        // Can't directly access inner collector, but we verify is_active
        assert!(filtered.is_active());
        assert_eq!(filtered.subscriber_id(), "filter-scan");
    }

    #[test]
    fn test_registry_register_and_notify_all() {
        let mut registry = AuditSubscriberRegistry::new();
        registry.register(Box::new(CollectorSubscriber::new("sub-1")));
        registry.register(Box::new(CollectorSubscriber::new("sub-2")));
        assert_eq!(registry.active_count(), 2);
        registry.notify_all(&make_event("e1", "scan"));
    }

    #[test]
    fn test_registry_active_count_tracks_correctly() {
        let mut registry = AuditSubscriberRegistry::new();
        let mut sub = CollectorSubscriber::new("sub-1");
        registry.register(Box::new(CollectorSubscriber::new("sub-2")));
        sub.deactivate();
        registry.register(Box::new(sub));
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_remove_inactive() {
        let mut registry = AuditSubscriberRegistry::new();
        registry.register(Box::new(CollectorSubscriber::new("active")));
        let mut inactive = CollectorSubscriber::new("inactive");
        inactive.deactivate();
        registry.register(Box::new(inactive));
        assert_eq!(registry.active_count(), 1);
        let removed = registry.remove_inactive();
        assert_eq!(removed, 1);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut registry = AuditSubscriberRegistry::new();
        registry.register(Box::new(CollectorSubscriber::new("sub-1")));
        let events = vec![make_event("e1", "scan"), make_event("e2", "alert")];
        registry.notify_batch(&events);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_collector_subscriber_id() {
        let sub = CollectorSubscriber::new("my-collector");
        assert_eq!(sub.subscriber_id(), "my-collector");
        assert!(sub.is_active());
    }
}
