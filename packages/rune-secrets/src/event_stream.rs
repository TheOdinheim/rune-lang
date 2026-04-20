// ═══════════════════════════════════════════════════════════════════════
// Event Stream — Secret lifecycle event streaming.
//
// Layer 3 defines the contract for streaming secret lifecycle events
// (rotation, expiration, access) to external systems. Follows the
// same subscriber pattern established in rune-audit-ext Layer 3.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── SecretLifecycleEventType ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretLifecycleEventType {
    Created,
    Accessed,
    Rotated,
    Expired,
    Deleted,
    ClassificationChanged,
    ExpirationWarning { days_remaining: u32 },
    AccessDenied { reason: String },
    BackupCreated,
    Restored,
}

impl fmt::Display for SecretLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpirationWarning { days_remaining } => {
                write!(f, "ExpirationWarning({days_remaining}d)")
            }
            Self::AccessDenied { reason } => write!(f, "AccessDenied({reason})"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ── SecretLifecycleEvent ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecretLifecycleEvent {
    pub event_id: String,
    pub event_type: SecretLifecycleEventType,
    pub secret_id: String,
    pub timestamp: i64,
    pub actor: Option<String>,
    pub detail: String,
}

impl SecretLifecycleEvent {
    pub fn new(
        event_id: &str,
        event_type: SecretLifecycleEventType,
        secret_id: &str,
        timestamp: i64,
        detail: &str,
    ) -> Self {
        Self {
            event_id: event_id.to_string(),
            event_type,
            secret_id: secret_id.to_string(),
            timestamp,
            actor: None,
            detail: detail.to_string(),
        }
    }

    pub fn with_actor(mut self, actor: &str) -> Self {
        self.actor = Some(actor.to_string());
        self
    }
}

// ── SecretEventSubscriber trait ──────────────────────────────────

pub trait SecretEventSubscriber {
    fn on_event(&mut self, event: &SecretLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── SecretEventRegistry ──────────────────────────────────────────

pub struct SecretEventRegistry {
    subscribers: Vec<Box<dyn SecretEventSubscriber>>,
}

impl SecretEventRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn SecretEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &SecretLifecycleEvent) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_event(event);
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

impl Default for SecretEventRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── SecretEventCollector (reference implementation) ──────────────

pub struct SecretEventCollector {
    id: String,
    events: Vec<SecretLifecycleEvent>,
    active: bool,
}

impl SecretEventCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: Vec::new(),
            active: true,
        }
    }

    pub fn events(&self) -> &[SecretLifecycleEvent] {
        &self.events
    }

    pub fn events_for_secret(&self, secret_id: &str) -> Vec<&SecretLifecycleEvent> {
        self.events
            .iter()
            .filter(|e| e.secret_id == secret_id)
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn drain(&mut self) -> Vec<SecretLifecycleEvent> {
        self.events.drain(..).collect()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl SecretEventSubscriber for SecretEventCollector {
    fn on_event(&mut self, event: &SecretLifecycleEvent) {
        self.events.push(event.clone());
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

    fn make_event(id: &str, etype: SecretLifecycleEventType, secret_id: &str) -> SecretLifecycleEvent {
        SecretLifecycleEvent::new(id, etype, secret_id, 1000, "test detail")
    }

    #[test]
    fn test_collector_collects_events() {
        let mut collector = SecretEventCollector::new("c1");
        let event = make_event("e1", SecretLifecycleEventType::Created, "s1");
        collector.on_event(&event);
        assert_eq!(collector.event_count(), 1);
        assert_eq!(collector.events()[0].event_id, "e1");
    }

    #[test]
    fn test_collector_events_for_secret() {
        let mut collector = SecretEventCollector::new("c1");
        collector.on_event(&make_event("e1", SecretLifecycleEventType::Created, "s1"));
        collector.on_event(&make_event("e2", SecretLifecycleEventType::Accessed, "s2"));
        collector.on_event(&make_event("e3", SecretLifecycleEventType::Rotated, "s1"));
        let s1_events = collector.events_for_secret("s1");
        assert_eq!(s1_events.len(), 2);
    }

    #[test]
    fn test_collector_drain() {
        let mut collector = SecretEventCollector::new("c1");
        collector.on_event(&make_event("e1", SecretLifecycleEventType::Created, "s1"));
        collector.on_event(&make_event("e2", SecretLifecycleEventType::Deleted, "s1"));
        let drained = collector.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(collector.event_count(), 0);
    }

    #[test]
    fn test_registry_register_and_notify() {
        let mut registry = SecretEventRegistry::new();
        registry.register(Box::new(SecretEventCollector::new("c1")));
        let event = make_event("e1", SecretLifecycleEventType::Created, "s1");
        registry.notify(&event);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_active_count() {
        let mut registry = SecretEventRegistry::new();
        registry.register(Box::new(SecretEventCollector::new("c1")));
        registry.register(Box::new(SecretEventCollector::new("c2")));
        assert_eq!(registry.active_count(), 2);
    }

    #[test]
    fn test_registry_remove_inactive() {
        let mut registry = SecretEventRegistry::new();
        let mut collector = SecretEventCollector::new("c1");
        collector.deactivate();
        registry.register(Box::new(collector));
        registry.register(Box::new(SecretEventCollector::new("c2")));
        let removed = registry.remove_inactive();
        assert_eq!(removed, 1);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_lifecycle_event_all_types() {
        let types = vec![
            SecretLifecycleEventType::Created,
            SecretLifecycleEventType::Accessed,
            SecretLifecycleEventType::Rotated,
            SecretLifecycleEventType::Expired,
            SecretLifecycleEventType::Deleted,
            SecretLifecycleEventType::ClassificationChanged,
            SecretLifecycleEventType::ExpirationWarning { days_remaining: 7 },
            SecretLifecycleEventType::AccessDenied {
                reason: "insufficient clearance".to_string(),
            },
            SecretLifecycleEventType::BackupCreated,
            SecretLifecycleEventType::Restored,
        ];
        for etype in types {
            let event = make_event("e1", etype.clone(), "s1");
            assert_eq!(event.secret_id, "s1");
            // Verify Display works
            let _display = format!("{etype}");
        }
    }

    #[test]
    fn test_lifecycle_event_with_actor() {
        let event = make_event("e1", SecretLifecycleEventType::Created, "s1")
            .with_actor("admin");
        assert_eq!(event.actor.as_deref(), Some("admin"));
    }
}
