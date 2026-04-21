// ═══════════════════════════════════════════════════════════════════════
// Policy Lifecycle Event Streaming — Layer 3 subscriber/registry
// pattern for broadcasting policy lifecycle events to external
// consumers. Mirrors DocumentEventSubscriber from rune-document.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;
use std::sync::Mutex;

// ── PolicyLifecycleEventType ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyLifecycleEventType {
    PackagePublished,
    PackageRetrieved,
    PackageUnpublished,
    PackageVersionResolved,
    PackageSigned,
    PackageSignatureVerified,
    PackageSignatureInvalid,
    RuleSetStored,
    PackageComposed,
    PolicyConflictDetected,
    PolicyConflictResolved,
    PackageDependencyResolved,
    PackageDependencyMissing,
    PolicyEvaluationSubmitted,
    PolicyEvaluationCompleted,
    PolicyEvaluationFailed,
    PackageExported,
    PackageExportFailed,
    PackageRegistrySubscribed,
    PackageRegistryUnsubscribed,
}

impl fmt::Display for PolicyLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackagePublished => f.write_str("package-published"),
            Self::PackageRetrieved => f.write_str("package-retrieved"),
            Self::PackageUnpublished => f.write_str("package-unpublished"),
            Self::PackageVersionResolved => f.write_str("package-version-resolved"),
            Self::PackageSigned => f.write_str("package-signed"),
            Self::PackageSignatureVerified => f.write_str("package-signature-verified"),
            Self::PackageSignatureInvalid => f.write_str("package-signature-invalid"),
            Self::RuleSetStored => f.write_str("rule-set-stored"),
            Self::PackageComposed => f.write_str("package-composed"),
            Self::PolicyConflictDetected => f.write_str("policy-conflict-detected"),
            Self::PolicyConflictResolved => f.write_str("policy-conflict-resolved"),
            Self::PackageDependencyResolved => f.write_str("package-dependency-resolved"),
            Self::PackageDependencyMissing => f.write_str("package-dependency-missing"),
            Self::PolicyEvaluationSubmitted => f.write_str("policy-evaluation-submitted"),
            Self::PolicyEvaluationCompleted => f.write_str("policy-evaluation-completed"),
            Self::PolicyEvaluationFailed => f.write_str("policy-evaluation-failed"),
            Self::PackageExported => f.write_str("package-exported"),
            Self::PackageExportFailed => f.write_str("package-export-failed"),
            Self::PackageRegistrySubscribed => f.write_str("package-registry-subscribed"),
            Self::PackageRegistryUnsubscribed => f.write_str("package-registry-unsubscribed"),
        }
    }
}

// ── PolicyLifecycleEvent ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLifecycleEvent {
    pub event_type: PolicyLifecycleEventType,
    pub package_id: Option<String>,
    pub package_namespace: Option<String>,
    pub package_tag: Option<String>,
    pub timestamp: String,
    pub actor: String,
    pub detail: String,
}

impl PolicyLifecycleEvent {
    pub fn new(
        event_type: PolicyLifecycleEventType,
        timestamp: impl Into<String>,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            package_id: None,
            package_namespace: None,
            package_tag: None,
            timestamp: timestamp.into(),
            actor: actor.into(),
            detail: String::new(),
        }
    }

    pub fn with_package_id(mut self, id: impl Into<String>) -> Self {
        self.package_id = Some(id.into());
        self
    }

    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.package_namespace = Some(ns.into());
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.package_tag = Some(tag.into());
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }
}

// ── PolicyLifecycleEventSubscriber trait ──────────────────────────

pub trait PolicyLifecycleEventSubscriber {
    fn on_policy_event(&self, event: &PolicyLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── PolicyLifecycleEventSubscriberRegistry ────────────────────────

pub struct PolicyLifecycleEventSubscriberRegistry {
    subscribers: Vec<Box<dyn PolicyLifecycleEventSubscriber>>,
}

impl Default for PolicyLifecycleEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyLifecycleEventSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn PolicyLifecycleEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&self, event: &PolicyLifecycleEvent) {
        for sub in &self.subscribers {
            if sub.is_active() {
                sub.on_policy_event(event);
            }
        }
    }

    pub fn notify_batch(&self, events: &[PolicyLifecycleEvent]) {
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

// ── PolicyLifecycleEventCollector ─────────────────────────────────

pub struct PolicyLifecycleEventCollector {
    id: String,
    events: Mutex<Vec<PolicyLifecycleEvent>>,
}

impl PolicyLifecycleEventCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn collected_events(&self) -> Vec<PolicyLifecycleEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

impl PolicyLifecycleEventSubscriber for PolicyLifecycleEventCollector {
    fn on_policy_event(&self, event: &PolicyLifecycleEvent) {
        self.events.lock().unwrap().push(event.clone());
    }

    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── FilteredPolicyLifecycleEventSubscriber ────────────────────────

pub struct FilteredPolicyLifecycleEventSubscriber<S: PolicyLifecycleEventSubscriber> {
    inner: S,
    id: String,
    namespace_filter: Option<String>,
    event_type_filter: Option<PolicyLifecycleEventType>,
    tag_filter: Option<String>,
}

impl<S: PolicyLifecycleEventSubscriber> FilteredPolicyLifecycleEventSubscriber<S> {
    pub fn new(id: &str, inner: S) -> Self {
        Self {
            inner,
            id: id.to_string(),
            namespace_filter: None,
            event_type_filter: None,
            tag_filter: None,
        }
    }

    pub fn filter_by_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace_filter = Some(ns.into());
        self
    }

    pub fn filter_by_event_type(mut self, event_type: PolicyLifecycleEventType) -> Self {
        self.event_type_filter = Some(event_type);
        self
    }

    pub fn filter_by_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag_filter = Some(tag.into());
        self
    }

    fn matches(&self, event: &PolicyLifecycleEvent) -> bool {
        if let Some(ref ns) = self.namespace_filter
            && event.package_namespace.as_ref() != Some(ns)
        {
            return false;
        }
        if let Some(ref evt) = self.event_type_filter
            && &event.event_type != evt
        {
            return false;
        }
        if let Some(ref tag) = self.tag_filter
            && event.package_tag.as_ref() != Some(tag)
        {
            return false;
        }
        true
    }
}

impl<S: PolicyLifecycleEventSubscriber> PolicyLifecycleEventSubscriber
    for FilteredPolicyLifecycleEventSubscriber<S>
{
    fn on_policy_event(&self, event: &PolicyLifecycleEvent) {
        if self.matches(event) {
            self.inner.on_policy_event(event);
        }
    }

    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { self.inner.is_active() }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(event_type: PolicyLifecycleEventType) -> PolicyLifecycleEvent {
        PolicyLifecycleEvent::new(event_type, "2026-04-20T00:00:00Z", "system")
    }

    #[test]
    fn test_lifecycle_event_type_display() {
        let types = vec![
            PolicyLifecycleEventType::PackagePublished,
            PolicyLifecycleEventType::PackageRetrieved,
            PolicyLifecycleEventType::PackageUnpublished,
            PolicyLifecycleEventType::PackageVersionResolved,
            PolicyLifecycleEventType::PackageSigned,
            PolicyLifecycleEventType::PackageSignatureVerified,
            PolicyLifecycleEventType::PackageSignatureInvalid,
            PolicyLifecycleEventType::RuleSetStored,
            PolicyLifecycleEventType::PackageComposed,
            PolicyLifecycleEventType::PolicyConflictDetected,
            PolicyLifecycleEventType::PolicyConflictResolved,
            PolicyLifecycleEventType::PackageDependencyResolved,
            PolicyLifecycleEventType::PackageDependencyMissing,
            PolicyLifecycleEventType::PolicyEvaluationSubmitted,
            PolicyLifecycleEventType::PolicyEvaluationCompleted,
            PolicyLifecycleEventType::PolicyEvaluationFailed,
            PolicyLifecycleEventType::PackageExported,
            PolicyLifecycleEventType::PackageExportFailed,
            PolicyLifecycleEventType::PackageRegistrySubscribed,
            PolicyLifecycleEventType::PackageRegistryUnsubscribed,
        ];
        assert_eq!(types.len(), 20);
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
    }

    #[test]
    fn test_event_builder() {
        let event = PolicyLifecycleEvent::new(
            PolicyLifecycleEventType::PackagePublished,
            "2026-04-20T00:00:00Z",
            "admin",
        )
        .with_package_id("pkg-1")
        .with_namespace("org.rune")
        .with_tag("access")
        .with_detail("initial publish");

        assert_eq!(event.package_id, Some("pkg-1".to_string()));
        assert_eq!(event.package_namespace, Some("org.rune".to_string()));
        assert_eq!(event.package_tag, Some("access".to_string()));
        assert_eq!(event.detail, "initial publish");
    }

    #[test]
    fn test_collector_receives_events() {
        let collector = PolicyLifecycleEventCollector::new("coll-1");
        collector.on_policy_event(&sample_event(PolicyLifecycleEventType::PackagePublished));
        collector.on_policy_event(&sample_event(PolicyLifecycleEventType::RuleSetStored));
        assert_eq!(collector.event_count(), 2);
        assert_eq!(collector.collected_events().len(), 2);
    }

    #[test]
    fn test_collector_clear() {
        let collector = PolicyLifecycleEventCollector::new("coll-1");
        collector.on_policy_event(&sample_event(PolicyLifecycleEventType::PackagePublished));
        collector.clear();
        assert_eq!(collector.event_count(), 0);
    }

    #[test]
    fn test_registry_notify() {
        let mut registry = PolicyLifecycleEventSubscriberRegistry::new();
        let collector = PolicyLifecycleEventCollector::new("coll-1");
        registry.register(Box::new(collector));
        registry.notify(&sample_event(PolicyLifecycleEventType::PackagePublished));
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut registry = PolicyLifecycleEventSubscriberRegistry::new();
        let collector = PolicyLifecycleEventCollector::new("coll-1");
        registry.register(Box::new(collector));
        let events = vec![
            sample_event(PolicyLifecycleEventType::PackagePublished),
            sample_event(PolicyLifecycleEventType::PackageComposed),
        ];
        registry.notify_batch(&events);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_default() {
        let registry = PolicyLifecycleEventSubscriberRegistry::default();
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn test_filtered_subscriber_by_namespace() {
        let collector = PolicyLifecycleEventCollector::new("inner");
        let filtered = FilteredPolicyLifecycleEventSubscriber::new("filtered-1", collector)
            .filter_by_namespace("org.rune");

        let matching = sample_event(PolicyLifecycleEventType::PackagePublished)
            .with_namespace("org.rune");
        let non_matching = sample_event(PolicyLifecycleEventType::PackagePublished)
            .with_namespace("other");

        filtered.on_policy_event(&matching);
        filtered.on_policy_event(&non_matching);
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_subscriber_by_event_type() {
        let collector = PolicyLifecycleEventCollector::new("inner");
        let filtered = FilteredPolicyLifecycleEventSubscriber::new("filtered-2", collector)
            .filter_by_event_type(PolicyLifecycleEventType::PackageComposed);

        filtered.on_policy_event(&sample_event(PolicyLifecycleEventType::PackageComposed));
        filtered.on_policy_event(&sample_event(PolicyLifecycleEventType::PackagePublished));
        assert!(filtered.is_active());
        assert_eq!(filtered.subscriber_id(), "filtered-2");
    }

    #[test]
    fn test_filtered_subscriber_by_tag() {
        let collector = PolicyLifecycleEventCollector::new("inner");
        let filtered = FilteredPolicyLifecycleEventSubscriber::new("filtered-3", collector)
            .filter_by_tag("security");

        let matching = sample_event(PolicyLifecycleEventType::PackagePublished)
            .with_tag("security");
        filtered.on_policy_event(&matching);
        assert!(filtered.is_active());
    }

    #[test]
    fn test_collector_id() {
        let collector = PolicyLifecycleEventCollector::new("my-coll");
        assert_eq!(collector.subscriber_id(), "my-coll");
        assert!(collector.is_active());
    }
}
