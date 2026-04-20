// ═══════════════════════════════════════════════════════════════════════
// Identity Event Streaming — Subscriber trait and registry.
//
// Layer 3 defines the contract for subscribing to identity lifecycle
// events. IdentityEventSubscriber receives events; the registry
// manages dispatch. FilteredIdentityEventSubscriber demonstrates
// event filtering by type.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── IdentityLifecycleEventType ───────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdentityLifecycleEventType {
    Created,
    Updated,
    Suspended,
    Locked,
    Reactivated,
    Revoked,
    Deleted,
    CredentialAdded,
    CredentialRemoved,
    MfaEnrolled,
    MfaUnenrolled,
    SessionStarted,
    SessionEnded,
    TrustChanged,
    FederationLinked,
}

impl fmt::Display for IdentityLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Created => "Created",
            Self::Updated => "Updated",
            Self::Suspended => "Suspended",
            Self::Locked => "Locked",
            Self::Reactivated => "Reactivated",
            Self::Revoked => "Revoked",
            Self::Deleted => "Deleted",
            Self::CredentialAdded => "CredentialAdded",
            Self::CredentialRemoved => "CredentialRemoved",
            Self::MfaEnrolled => "MfaEnrolled",
            Self::MfaUnenrolled => "MfaUnenrolled",
            Self::SessionStarted => "SessionStarted",
            Self::SessionEnded => "SessionEnded",
            Self::TrustChanged => "TrustChanged",
            Self::FederationLinked => "FederationLinked",
        };
        write!(f, "{s}")
    }
}

// ── IdentityLifecycleEvent ───────────────────────────────────

#[derive(Debug, Clone)]
pub struct IdentityLifecycleEvent {
    pub event_type: IdentityLifecycleEventType,
    pub identity_id: String,
    pub timestamp: i64,
    pub detail: String,
}

impl IdentityLifecycleEvent {
    pub fn new(
        event_type: IdentityLifecycleEventType,
        identity_id: &str,
        timestamp: i64,
        detail: &str,
    ) -> Self {
        Self {
            event_type,
            identity_id: identity_id.to_string(),
            timestamp,
            detail: detail.to_string(),
        }
    }
}

impl fmt::Display for IdentityLifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "[{}] {} {} — {}",
            self.timestamp, self.event_type, self.identity_id, self.detail
        )
    }
}

// ── IdentityEventSubscriber trait ────────────────────────────

pub trait IdentityEventSubscriber {
    fn on_event(&mut self, event: &IdentityLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── IdentityEventSubscriberRegistry ──────────────────────────

pub struct IdentityEventSubscriberRegistry {
    subscribers: Vec<Box<dyn IdentityEventSubscriber>>,
}

impl IdentityEventSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn IdentityEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn unregister(&mut self, subscriber_id: &str) -> bool {
        let before = self.subscribers.len();
        self.subscribers.retain(|s| s.subscriber_id() != subscriber_id);
        self.subscribers.len() < before
    }

    pub fn publish(&mut self, event: &IdentityLifecycleEvent) {
        for subscriber in &mut self.subscribers {
            if subscriber.is_active() {
                subscriber.on_event(event);
            }
        }
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    pub fn active_subscriber_count(&self) -> usize {
        self.subscribers.iter().filter(|s| s.is_active()).count()
    }
}

impl Default for IdentityEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── IdentityEventCollector ───────────────────────────────────

pub struct IdentityEventCollector {
    id: String,
    events: Vec<IdentityLifecycleEvent>,
    active: bool,
}

impl IdentityEventCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: Vec::new(),
            active: true,
        }
    }

    pub fn collected(&self) -> &[IdentityLifecycleEvent] {
        &self.events
    }

    pub fn count(&self) -> usize {
        self.events.len()
    }

    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }
}

impl IdentityEventSubscriber for IdentityEventCollector {
    fn on_event(&mut self, event: &IdentityLifecycleEvent) {
        self.events.push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredIdentityEventSubscriber ──────────────────────────

pub struct FilteredIdentityEventSubscriber {
    id: String,
    accepted_types: Vec<IdentityLifecycleEventType>,
    events: Vec<IdentityLifecycleEvent>,
    active: bool,
}

impl FilteredIdentityEventSubscriber {
    pub fn new(id: &str, accepted_types: Vec<IdentityLifecycleEventType>) -> Self {
        Self {
            id: id.to_string(),
            accepted_types,
            events: Vec::new(),
            active: true,
        }
    }

    pub fn collected(&self) -> &[IdentityLifecycleEvent] {
        &self.events
    }

    pub fn count(&self) -> usize {
        self.events.len()
    }
}

impl IdentityEventSubscriber for FilteredIdentityEventSubscriber {
    fn on_event(&mut self, event: &IdentityLifecycleEvent) {
        if self.accepted_types.contains(&event.event_type) {
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

    fn make_event(etype: IdentityLifecycleEventType, id: &str, ts: i64) -> IdentityLifecycleEvent {
        IdentityLifecycleEvent::new(etype, id, ts, "test")
    }

    #[test]
    fn test_lifecycle_event_type_display() {
        assert_eq!(IdentityLifecycleEventType::Created.to_string(), "Created");
        assert_eq!(IdentityLifecycleEventType::FederationLinked.to_string(), "FederationLinked");
    }

    #[test]
    fn test_lifecycle_event_all_15_variants() {
        let variants = vec![
            IdentityLifecycleEventType::Created,
            IdentityLifecycleEventType::Updated,
            IdentityLifecycleEventType::Suspended,
            IdentityLifecycleEventType::Locked,
            IdentityLifecycleEventType::Reactivated,
            IdentityLifecycleEventType::Revoked,
            IdentityLifecycleEventType::Deleted,
            IdentityLifecycleEventType::CredentialAdded,
            IdentityLifecycleEventType::CredentialRemoved,
            IdentityLifecycleEventType::MfaEnrolled,
            IdentityLifecycleEventType::MfaUnenrolled,
            IdentityLifecycleEventType::SessionStarted,
            IdentityLifecycleEventType::SessionEnded,
            IdentityLifecycleEventType::TrustChanged,
            IdentityLifecycleEventType::FederationLinked,
        ];
        assert_eq!(variants.len(), 15);
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn test_lifecycle_event_display() {
        let event = make_event(IdentityLifecycleEventType::Created, "user:alice", 1000);
        let s = event.to_string();
        assert!(s.contains("1000"));
        assert!(s.contains("Created"));
        assert!(s.contains("user:alice"));
    }

    #[test]
    fn test_collector_receives_events() {
        let mut collector = IdentityEventCollector::new("c1");
        collector.on_event(&make_event(IdentityLifecycleEventType::Created, "user:alice", 1000));
        collector.on_event(&make_event(IdentityLifecycleEventType::Updated, "user:alice", 2000));
        assert_eq!(collector.count(), 2);
        assert_eq!(collector.collected()[0].event_type, IdentityLifecycleEventType::Created);
    }

    #[test]
    fn test_collector_inactive_skipped() {
        let mut registry = IdentityEventSubscriberRegistry::new();
        let mut collector = IdentityEventCollector::new("c1");
        collector.set_active(false);
        registry.register(Box::new(collector));
        registry.publish(&make_event(IdentityLifecycleEventType::Created, "user:alice", 1000));
        assert_eq!(registry.active_subscriber_count(), 0);
    }

    #[test]
    fn test_registry_register_and_publish() {
        let mut registry = IdentityEventSubscriberRegistry::new();
        registry.register(Box::new(IdentityEventCollector::new("c1")));
        registry.register(Box::new(IdentityEventCollector::new("c2")));
        assert_eq!(registry.subscriber_count(), 2);
        assert_eq!(registry.active_subscriber_count(), 2);
        registry.publish(&make_event(IdentityLifecycleEventType::Created, "user:alice", 1000));
    }

    #[test]
    fn test_registry_unregister() {
        let mut registry = IdentityEventSubscriberRegistry::new();
        registry.register(Box::new(IdentityEventCollector::new("c1")));
        registry.register(Box::new(IdentityEventCollector::new("c2")));
        assert!(registry.unregister("c1"));
        assert_eq!(registry.subscriber_count(), 1);
        assert!(!registry.unregister("c1"));
    }

    #[test]
    fn test_filtered_subscriber_accepts() {
        let mut sub = FilteredIdentityEventSubscriber::new(
            "f1",
            vec![IdentityLifecycleEventType::Created, IdentityLifecycleEventType::Deleted],
        );
        sub.on_event(&make_event(IdentityLifecycleEventType::Created, "user:alice", 1000));
        sub.on_event(&make_event(IdentityLifecycleEventType::Updated, "user:alice", 2000));
        sub.on_event(&make_event(IdentityLifecycleEventType::Deleted, "user:alice", 3000));
        assert_eq!(sub.count(), 2);
    }

    #[test]
    fn test_filtered_subscriber_in_registry() {
        let mut registry = IdentityEventSubscriberRegistry::new();
        registry.register(Box::new(FilteredIdentityEventSubscriber::new(
            "security",
            vec![IdentityLifecycleEventType::Locked, IdentityLifecycleEventType::Revoked],
        )));
        registry.publish(&make_event(IdentityLifecycleEventType::Created, "user:alice", 1000));
        registry.publish(&make_event(IdentityLifecycleEventType::Locked, "user:alice", 2000));
        assert_eq!(registry.subscriber_count(), 1);
    }

    #[test]
    fn test_registry_default() {
        let registry = IdentityEventSubscriberRegistry::default();
        assert_eq!(registry.subscriber_count(), 0);
    }

    #[test]
    fn test_event_new() {
        let event = IdentityLifecycleEvent::new(
            IdentityLifecycleEventType::MfaEnrolled,
            "user:bob",
            5000,
            "enrolled totp",
        );
        assert_eq!(event.identity_id, "user:bob");
        assert_eq!(event.timestamp, 5000);
        assert_eq!(event.detail, "enrolled totp");
    }
}
