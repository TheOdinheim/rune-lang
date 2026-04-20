// ═══════════════════════════════════════════════════════════════════════
// Decision Streaming — Subscriber trait and registry.
//
// Layer 3 defines the contract for subscribing to authorization
// decision lifecycle events. Mirrors IdentityEventSubscriber from
// rune-identity.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── DecisionLifecycleEventType ───────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DecisionLifecycleEventType {
    AuthorizationRequested,
    PermissionGranted,
    PermissionDenied,
    DecisionIndeterminate,
    DecisionNotApplicable,
    PolicyMatched,
    PolicyDefinitionAdded,
    PolicyDefinitionRemoved,
    RoleAssigned,
    RoleRevoked,
    PermissionGrantCreated,
    PermissionGrantRevoked,
    DecisionEngineChanged,
    ExternalEvaluatorInvoked,
    CapabilityTokenIssued,
    CapabilityTokenVerified,
    CapabilityTokenRejected,
}

impl fmt::Display for DecisionLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AuthorizationRequested => "AuthorizationRequested",
            Self::PermissionGranted => "PermissionGranted",
            Self::PermissionDenied => "PermissionDenied",
            Self::DecisionIndeterminate => "DecisionIndeterminate",
            Self::DecisionNotApplicable => "DecisionNotApplicable",
            Self::PolicyMatched => "PolicyMatched",
            Self::PolicyDefinitionAdded => "PolicyDefinitionAdded",
            Self::PolicyDefinitionRemoved => "PolicyDefinitionRemoved",
            Self::RoleAssigned => "RoleAssigned",
            Self::RoleRevoked => "RoleRevoked",
            Self::PermissionGrantCreated => "PermissionGrantCreated",
            Self::PermissionGrantRevoked => "PermissionGrantRevoked",
            Self::DecisionEngineChanged => "DecisionEngineChanged",
            Self::ExternalEvaluatorInvoked => "ExternalEvaluatorInvoked",
            Self::CapabilityTokenIssued => "CapabilityTokenIssued",
            Self::CapabilityTokenVerified => "CapabilityTokenVerified",
            Self::CapabilityTokenRejected => "CapabilityTokenRejected",
        };
        write!(f, "{s}")
    }
}

// ── DecisionLifecycleEvent ───────────────────────────────────

#[derive(Debug, Clone)]
pub struct DecisionLifecycleEvent {
    pub event_type: DecisionLifecycleEventType,
    pub subject_id: String,
    pub timestamp: i64,
    pub detail: String,
}

impl DecisionLifecycleEvent {
    pub fn new(
        event_type: DecisionLifecycleEventType,
        subject_id: &str,
        timestamp: i64,
        detail: &str,
    ) -> Self {
        Self {
            event_type,
            subject_id: subject_id.to_string(),
            timestamp,
            detail: detail.to_string(),
        }
    }
}

impl fmt::Display for DecisionLifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "[{}] {} {} — {}",
            self.timestamp, self.event_type, self.subject_id, self.detail
        )
    }
}

// ── DecisionSubscriber trait ─────────────────────────────────

pub trait DecisionSubscriber {
    fn on_decision_event(&mut self, event: &DecisionLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── DecisionSubscriberRegistry ───────────────────────────────

pub struct DecisionSubscriberRegistry {
    subscribers: Vec<Box<dyn DecisionSubscriber>>,
}

impl DecisionSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn DecisionSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &DecisionLifecycleEvent) {
        for subscriber in &mut self.subscribers {
            if subscriber.is_active() {
                subscriber.on_decision_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[DecisionLifecycleEvent]) {
        for event in events {
            self.notify(event);
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

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }
}

impl Default for DecisionSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── DecisionCollector ────────────────────────────────────────

pub struct DecisionCollector {
    id: String,
    events: Vec<DecisionLifecycleEvent>,
    active: bool,
}

impl DecisionCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: Vec::new(),
            active: true,
        }
    }

    pub fn collected(&self) -> &[DecisionLifecycleEvent] {
        &self.events
    }

    pub fn count(&self) -> usize {
        self.events.len()
    }

    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }
}

impl DecisionSubscriber for DecisionCollector {
    fn on_decision_event(&mut self, event: &DecisionLifecycleEvent) {
        self.events.push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredDecisionSubscriber ───────────────────────────────

pub struct FilteredDecisionSubscriber {
    id: String,
    accepted_types: Vec<DecisionLifecycleEventType>,
    subject_pattern: Option<String>,
    action_pattern: Option<String>,
    events: Vec<DecisionLifecycleEvent>,
    active: bool,
}

impl FilteredDecisionSubscriber {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            accepted_types: Vec::new(),
            subject_pattern: None,
            action_pattern: None,
            events: Vec::new(),
            active: true,
        }
    }

    pub fn with_event_types(mut self, types: Vec<DecisionLifecycleEventType>) -> Self {
        self.accepted_types = types;
        self
    }

    pub fn with_subject_pattern(mut self, pattern: &str) -> Self {
        self.subject_pattern = Some(pattern.to_string());
        self
    }

    pub fn with_action_pattern(mut self, pattern: &str) -> Self {
        self.action_pattern = Some(pattern.to_string());
        self
    }

    pub fn collected(&self) -> &[DecisionLifecycleEvent] {
        &self.events
    }

    pub fn count(&self) -> usize {
        self.events.len()
    }

    fn matches(&self, event: &DecisionLifecycleEvent) -> bool {
        if !self.accepted_types.is_empty() && !self.accepted_types.contains(&event.event_type) {
            return false;
        }
        if let Some(ref pattern) = self.subject_pattern {
            if !event.subject_id.contains(pattern) {
                return false;
            }
        }
        if let Some(ref pattern) = self.action_pattern {
            if !event.detail.contains(pattern) {
                return false;
            }
        }
        true
    }
}

impl DecisionSubscriber for FilteredDecisionSubscriber {
    fn on_decision_event(&mut self, event: &DecisionLifecycleEvent) {
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

    fn make_event(etype: DecisionLifecycleEventType, subject: &str, ts: i64) -> DecisionLifecycleEvent {
        DecisionLifecycleEvent::new(etype, subject, ts, "test detail")
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(DecisionLifecycleEventType::AuthorizationRequested.to_string(), "AuthorizationRequested");
        assert_eq!(DecisionLifecycleEventType::CapabilityTokenRejected.to_string(), "CapabilityTokenRejected");
    }

    #[test]
    fn test_all_17_variants() {
        let variants = vec![
            DecisionLifecycleEventType::AuthorizationRequested,
            DecisionLifecycleEventType::PermissionGranted,
            DecisionLifecycleEventType::PermissionDenied,
            DecisionLifecycleEventType::DecisionIndeterminate,
            DecisionLifecycleEventType::DecisionNotApplicable,
            DecisionLifecycleEventType::PolicyMatched,
            DecisionLifecycleEventType::PolicyDefinitionAdded,
            DecisionLifecycleEventType::PolicyDefinitionRemoved,
            DecisionLifecycleEventType::RoleAssigned,
            DecisionLifecycleEventType::RoleRevoked,
            DecisionLifecycleEventType::PermissionGrantCreated,
            DecisionLifecycleEventType::PermissionGrantRevoked,
            DecisionLifecycleEventType::DecisionEngineChanged,
            DecisionLifecycleEventType::ExternalEvaluatorInvoked,
            DecisionLifecycleEventType::CapabilityTokenIssued,
            DecisionLifecycleEventType::CapabilityTokenVerified,
            DecisionLifecycleEventType::CapabilityTokenRejected,
        ];
        assert_eq!(variants.len(), 17);
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn test_event_display() {
        let event = make_event(DecisionLifecycleEventType::PermissionGranted, "alice", 1000);
        let s = event.to_string();
        assert!(s.contains("PermissionGranted"));
        assert!(s.contains("alice"));
    }

    #[test]
    fn test_collector() {
        let mut collector = DecisionCollector::new("c1");
        collector.on_decision_event(&make_event(DecisionLifecycleEventType::AuthorizationRequested, "a", 1000));
        collector.on_decision_event(&make_event(DecisionLifecycleEventType::PermissionGranted, "a", 2000));
        assert_eq!(collector.count(), 2);
    }

    #[test]
    fn test_collector_inactive() {
        let mut collector = DecisionCollector::new("c1");
        collector.set_active(false);
        assert!(!collector.is_active());
    }

    #[test]
    fn test_registry_publish() {
        let mut registry = DecisionSubscriberRegistry::new();
        registry.register(Box::new(DecisionCollector::new("c1")));
        registry.register(Box::new(DecisionCollector::new("c2")));
        assert_eq!(registry.subscriber_count(), 2);
        assert_eq!(registry.active_count(), 2);
        registry.notify(&make_event(DecisionLifecycleEventType::AuthorizationRequested, "a", 1000));
    }

    #[test]
    fn test_registry_remove_inactive() {
        let mut registry = DecisionSubscriberRegistry::new();
        let mut c = DecisionCollector::new("c1");
        c.set_active(false);
        registry.register(Box::new(c));
        registry.register(Box::new(DecisionCollector::new("c2")));
        let removed = registry.remove_inactive();
        assert_eq!(removed, 1);
        assert_eq!(registry.subscriber_count(), 1);
    }

    #[test]
    fn test_filtered_subscriber_by_type() {
        let mut sub = FilteredDecisionSubscriber::new("f1")
            .with_event_types(vec![
                DecisionLifecycleEventType::PermissionGranted,
                DecisionLifecycleEventType::PermissionDenied,
            ]);
        sub.on_decision_event(&make_event(DecisionLifecycleEventType::PermissionGranted, "a", 1));
        sub.on_decision_event(&make_event(DecisionLifecycleEventType::AuthorizationRequested, "a", 2));
        sub.on_decision_event(&make_event(DecisionLifecycleEventType::PermissionDenied, "a", 3));
        assert_eq!(sub.count(), 2);
    }

    #[test]
    fn test_filtered_subscriber_by_subject() {
        let mut sub = FilteredDecisionSubscriber::new("f1")
            .with_subject_pattern("admin");
        sub.on_decision_event(&make_event(DecisionLifecycleEventType::PermissionGranted, "admin", 1));
        sub.on_decision_event(&make_event(DecisionLifecycleEventType::PermissionGranted, "user", 2));
        assert_eq!(sub.count(), 1);
    }

    #[test]
    fn test_notify_batch() {
        let mut registry = DecisionSubscriberRegistry::new();
        registry.register(Box::new(DecisionCollector::new("c1")));
        let events = vec![
            make_event(DecisionLifecycleEventType::AuthorizationRequested, "a", 1),
            make_event(DecisionLifecycleEventType::PermissionGranted, "a", 2),
        ];
        registry.notify_batch(&events);
    }

    #[test]
    fn test_registry_default() {
        let registry = DecisionSubscriberRegistry::default();
        assert_eq!(registry.subscriber_count(), 0);
    }
}
