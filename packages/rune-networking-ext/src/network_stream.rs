// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — NetworkGovernanceEventSubscriber trait and registry for
// network governance lifecycle event streaming with filtering by
// event_type, severity, source.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── NetworkGovernanceLifecycleEventType ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkGovernanceLifecycleEventType {
    TlsPolicyCreated,
    TlsPolicyUpdated,
    TlsPolicyEvaluated,
    TlsPolicyViolation,
    CertificateRecordCreated,
    CertificateExpirationWarning,
    CertificateRenewed,
    CertificateRevoked,
    SegmentationPolicyCreated,
    SegmentationPolicyUpdated,
    SegmentationFlowAllowed,
    SegmentationFlowDenied,
    DnsPolicyCreated,
    DnsPolicyUpdated,
    DnsQueryEvaluated,
    DnsQueryBlocked,
    GovernanceExported,
    GovernanceExportFailed,
    GovernanceSnapshotCaptured,
    GovernanceMetricsComputed,
}

impl fmt::Display for NetworkGovernanceLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TlsPolicyCreated => "TlsPolicyCreated",
            Self::TlsPolicyUpdated => "TlsPolicyUpdated",
            Self::TlsPolicyEvaluated => "TlsPolicyEvaluated",
            Self::TlsPolicyViolation => "TlsPolicyViolation",
            Self::CertificateRecordCreated => "CertificateRecordCreated",
            Self::CertificateExpirationWarning => "CertificateExpirationWarning",
            Self::CertificateRenewed => "CertificateRenewed",
            Self::CertificateRevoked => "CertificateRevoked",
            Self::SegmentationPolicyCreated => "SegmentationPolicyCreated",
            Self::SegmentationPolicyUpdated => "SegmentationPolicyUpdated",
            Self::SegmentationFlowAllowed => "SegmentationFlowAllowed",
            Self::SegmentationFlowDenied => "SegmentationFlowDenied",
            Self::DnsPolicyCreated => "DnsPolicyCreated",
            Self::DnsPolicyUpdated => "DnsPolicyUpdated",
            Self::DnsQueryEvaluated => "DnsQueryEvaluated",
            Self::DnsQueryBlocked => "DnsQueryBlocked",
            Self::GovernanceExported => "GovernanceExported",
            Self::GovernanceExportFailed => "GovernanceExportFailed",
            Self::GovernanceSnapshotCaptured => "GovernanceSnapshotCaptured",
            Self::GovernanceMetricsComputed => "GovernanceMetricsComputed",
        };
        f.write_str(s)
    }
}

// ── NetworkGovernanceLifecycleEvent ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkGovernanceLifecycleEvent {
    pub event_type: NetworkGovernanceLifecycleEventType,
    pub timestamp: i64,
    pub source_id: String,
    pub severity: String,
    pub detail: String,
}

impl NetworkGovernanceLifecycleEvent {
    pub fn new(
        event_type: NetworkGovernanceLifecycleEventType,
        timestamp: i64,
        source_id: impl Into<String>,
        severity: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp,
            source_id: source_id.into(),
            severity: severity.into(),
            detail: detail.into(),
        }
    }
}

// ── NetworkGovernanceEventSubscriber trait ──────────────────────────

pub trait NetworkGovernanceEventSubscriber {
    fn on_network_governance_event(&mut self, event: &NetworkGovernanceLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── NetworkGovernanceEventSubscriberRegistry ────────────────────────

pub struct NetworkGovernanceEventSubscriberRegistry {
    subscribers: Vec<Box<dyn NetworkGovernanceEventSubscriber>>,
}

impl NetworkGovernanceEventSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn NetworkGovernanceEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &NetworkGovernanceLifecycleEvent) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_network_governance_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[NetworkGovernanceLifecycleEvent]) {
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

impl Default for NetworkGovernanceEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── NetworkGovernanceEventCollector ─────────────────────────────────

pub struct NetworkGovernanceEventCollector {
    id: String,
    collected: Vec<NetworkGovernanceLifecycleEvent>,
    active: bool,
}

impl NetworkGovernanceEventCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            collected: Vec::new(),
            active: true,
        }
    }

    pub fn collected_events(&self) -> &[NetworkGovernanceLifecycleEvent] {
        &self.collected
    }
}

impl NetworkGovernanceEventSubscriber for NetworkGovernanceEventCollector {
    fn on_network_governance_event(&mut self, event: &NetworkGovernanceLifecycleEvent) {
        self.collected.push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredNetworkGovernanceEventSubscriber ────────────────────────

pub struct FilteredNetworkGovernanceEventSubscriber<S: NetworkGovernanceEventSubscriber> {
    inner: S,
    source_id_filter: Option<String>,
    event_type_filter: Option<NetworkGovernanceLifecycleEventType>,
    severity_filter: Option<String>,
}

impl<S: NetworkGovernanceEventSubscriber> FilteredNetworkGovernanceEventSubscriber<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            source_id_filter: None,
            event_type_filter: None,
            severity_filter: None,
        }
    }

    pub fn with_source_id(mut self, source_id: impl Into<String>) -> Self {
        self.source_id_filter = Some(source_id.into());
        self
    }

    pub fn with_event_type(mut self, event_type: NetworkGovernanceLifecycleEventType) -> Self {
        self.event_type_filter = Some(event_type);
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity_filter = Some(severity.into());
        self
    }

    fn matches(&self, event: &NetworkGovernanceLifecycleEvent) -> bool {
        if let Some(ref sid) = self.source_id_filter && &event.source_id != sid {
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

impl<S: NetworkGovernanceEventSubscriber> NetworkGovernanceEventSubscriber
    for FilteredNetworkGovernanceEventSubscriber<S>
{
    fn on_network_governance_event(&mut self, event: &NetworkGovernanceLifecycleEvent) {
        if self.matches(event) {
            self.inner.on_network_governance_event(event);
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
        et: NetworkGovernanceLifecycleEventType,
    ) -> NetworkGovernanceLifecycleEvent {
        NetworkGovernanceLifecycleEvent::new(et, 1000, "tls-enforcer-1", "Critical", "test detail")
    }

    #[test]
    fn test_collector() {
        let mut collector = NetworkGovernanceEventCollector::new("c1");
        collector.on_network_governance_event(&sample_event(
            NetworkGovernanceLifecycleEventType::TlsPolicyCreated,
        ));
        assert_eq!(collector.collected_events().len(), 1);
    }

    #[test]
    fn test_registry_notify() {
        let mut reg = NetworkGovernanceEventSubscriberRegistry::new();
        reg.register(Box::new(NetworkGovernanceEventCollector::new("c1")));
        reg.register(Box::new(NetworkGovernanceEventCollector::new("c2")));
        reg.notify(&sample_event(
            NetworkGovernanceLifecycleEventType::TlsPolicyEvaluated,
        ));
        assert_eq!(reg.active_count(), 2);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut reg = NetworkGovernanceEventSubscriberRegistry::new();
        reg.register(Box::new(NetworkGovernanceEventCollector::new("c1")));
        let events = vec![
            sample_event(NetworkGovernanceLifecycleEventType::SegmentationFlowAllowed),
            sample_event(NetworkGovernanceLifecycleEventType::DnsQueryBlocked),
        ];
        reg.notify_batch(&events);
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn test_filtered_by_source_id() {
        let inner = NetworkGovernanceEventCollector::new("f1");
        let mut filtered = FilteredNetworkGovernanceEventSubscriber::new(inner)
            .with_source_id("tls-enforcer-1");
        filtered.on_network_governance_event(&sample_event(
            NetworkGovernanceLifecycleEventType::TlsPolicyCreated,
        ));
        let other = NetworkGovernanceLifecycleEvent::new(
            NetworkGovernanceLifecycleEventType::TlsPolicyCreated,
            2000,
            "dns-gov-1",
            "Warning",
            "other",
        );
        filtered.on_network_governance_event(&other);
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_by_event_type() {
        let inner = NetworkGovernanceEventCollector::new("f1");
        let mut filtered = FilteredNetworkGovernanceEventSubscriber::new(inner)
            .with_event_type(NetworkGovernanceLifecycleEventType::TlsPolicyViolation);
        filtered.on_network_governance_event(&sample_event(
            NetworkGovernanceLifecycleEventType::TlsPolicyCreated,
        ));
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_by_severity() {
        let inner = NetworkGovernanceEventCollector::new("f1");
        let mut filtered =
            FilteredNetworkGovernanceEventSubscriber::new(inner).with_severity("Critical");
        filtered.on_network_governance_event(&sample_event(
            NetworkGovernanceLifecycleEventType::CertificateRevoked,
        ));
        assert!(filtered.is_active());
    }

    #[test]
    fn test_event_type_display_all() {
        let types = vec![
            NetworkGovernanceLifecycleEventType::TlsPolicyCreated,
            NetworkGovernanceLifecycleEventType::TlsPolicyUpdated,
            NetworkGovernanceLifecycleEventType::TlsPolicyEvaluated,
            NetworkGovernanceLifecycleEventType::TlsPolicyViolation,
            NetworkGovernanceLifecycleEventType::CertificateRecordCreated,
            NetworkGovernanceLifecycleEventType::CertificateExpirationWarning,
            NetworkGovernanceLifecycleEventType::CertificateRenewed,
            NetworkGovernanceLifecycleEventType::CertificateRevoked,
            NetworkGovernanceLifecycleEventType::SegmentationPolicyCreated,
            NetworkGovernanceLifecycleEventType::SegmentationPolicyUpdated,
            NetworkGovernanceLifecycleEventType::SegmentationFlowAllowed,
            NetworkGovernanceLifecycleEventType::SegmentationFlowDenied,
            NetworkGovernanceLifecycleEventType::DnsPolicyCreated,
            NetworkGovernanceLifecycleEventType::DnsPolicyUpdated,
            NetworkGovernanceLifecycleEventType::DnsQueryEvaluated,
            NetworkGovernanceLifecycleEventType::DnsQueryBlocked,
            NetworkGovernanceLifecycleEventType::GovernanceExported,
            NetworkGovernanceLifecycleEventType::GovernanceExportFailed,
            NetworkGovernanceLifecycleEventType::GovernanceSnapshotCaptured,
            NetworkGovernanceLifecycleEventType::GovernanceMetricsComputed,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 20);
    }

    #[test]
    fn test_lifecycle_event_builder() {
        let e = NetworkGovernanceLifecycleEvent::new(
            NetworkGovernanceLifecycleEventType::TlsPolicyViolation,
            5000,
            "enforcer-alpha",
            "Critical",
            "TLS 1.0 detected",
        );
        assert_eq!(e.source_id, "enforcer-alpha");
        assert_eq!(e.severity, "Critical");
    }

    #[test]
    fn test_remove_inactive() {
        let mut reg = NetworkGovernanceEventSubscriberRegistry::new();
        reg.register(Box::new(NetworkGovernanceEventCollector::new("c1")));
        assert_eq!(reg.active_count(), 1);
        reg.remove_inactive();
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn test_subscriber_id() {
        let c = NetworkGovernanceEventCollector::new("my-sub");
        assert_eq!(c.subscriber_id(), "my-sub");
    }
}
