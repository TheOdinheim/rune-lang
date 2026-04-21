// ═══════════════════════════════════════════════════════════════════════
// Truth Stream — Event subscriber infrastructure for truth lifecycle
// events.
//
// Mirrors the ProvenanceEventSubscriber pattern from rune-provenance.
// Subscribers register interest in truth lifecycle events and receive
// them via a synchronous callback.  The registry fans out each event
// to all active subscribers.
//
// TruthLifecycleEventType is a 15-variant enum covering the full
// claim lifecycle: creation, retrieval, retraction, consistency
// checks, contradiction detection/resolution, evidence linking,
// export, reliability updates, and backend changes.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::error::TruthError;

// ── TruthLifecycleEventType ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TruthLifecycleEventType {
    ClaimPersisted,
    ClaimRetrieved,
    ClaimRetracted,
    ConsistencyCheckPassed,
    ConsistencyCheckFailed,
    ContradictionDetected,
    ContradictionResolved,
    CorroborationRecorded,
    EvidenceLinkCreated,
    EvidenceLinkRemoved,
    EvidenceAdequacyAssessed,
    ClaimExported,
    SourceReliabilityUpdated,
    SubscriberRegistered,
    SubscriberRemoved,
}

impl TruthLifecycleEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::ClaimPersisted => "claim_persisted",
            Self::ClaimRetrieved => "claim_retrieved",
            Self::ClaimRetracted => "claim_retracted",
            Self::ConsistencyCheckPassed => "consistency_check_passed",
            Self::ConsistencyCheckFailed => "consistency_check_failed",
            Self::ContradictionDetected => "contradiction_detected",
            Self::ContradictionResolved => "contradiction_resolved",
            Self::CorroborationRecorded => "corroboration_recorded",
            Self::EvidenceLinkCreated => "evidence_link_created",
            Self::EvidenceLinkRemoved => "evidence_link_removed",
            Self::EvidenceAdequacyAssessed => "evidence_adequacy_assessed",
            Self::ClaimExported => "claim_exported",
            Self::SourceReliabilityUpdated => "source_reliability_updated",
            Self::SubscriberRegistered => "subscriber_registered",
            Self::SubscriberRemoved => "subscriber_removed",
        }
    }

    pub fn is_claim_event(&self) -> bool {
        matches!(
            self,
            Self::ClaimPersisted | Self::ClaimRetrieved | Self::ClaimRetracted
        )
    }

    pub fn is_contradiction_event(&self) -> bool {
        matches!(
            self,
            Self::ContradictionDetected
                | Self::ContradictionResolved
                | Self::CorroborationRecorded
        )
    }

    pub fn is_evidence_event(&self) -> bool {
        matches!(
            self,
            Self::EvidenceLinkCreated
                | Self::EvidenceLinkRemoved
                | Self::EvidenceAdequacyAssessed
        )
    }
}

impl fmt::Display for TruthLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.type_name())
    }
}

// ── TruthLifecycleEvent ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TruthLifecycleEvent {
    pub event_type: TruthLifecycleEventType,
    pub timestamp: i64,
    pub description: String,
    pub claim_id: Option<String>,
    pub metadata: Vec<(String, String)>,
}

impl TruthLifecycleEvent {
    pub fn new(event_type: TruthLifecycleEventType, timestamp: i64, description: &str) -> Self {
        Self {
            event_type,
            timestamp,
            description: description.to_string(),
            claim_id: None,
            metadata: Vec::new(),
        }
    }

    pub fn with_claim_id(mut self, claim_id: &str) -> Self {
        self.claim_id = Some(claim_id.to_string());
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.push((key.to_string(), value.to_string()));
        self
    }
}

impl fmt::Display for TruthLifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} @ {}", self.event_type, self.description, self.timestamp)
    }
}

// ── TruthEventSubscriber trait ────────────────────────────────────

pub trait TruthEventSubscriber {
    fn on_event(&mut self, event: &TruthLifecycleEvent) -> Result<(), TruthError>;
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── TruthEventSubscriberRegistry ──────────────────────────────────

pub struct TruthEventSubscriberRegistry {
    subscribers: Vec<Box<dyn TruthEventSubscriber>>,
}

impl TruthEventSubscriberRegistry {
    pub fn new() -> Self {
        Self { subscribers: Vec::new() }
    }

    pub fn register(&mut self, subscriber: Box<dyn TruthEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn unregister(&mut self, subscriber_id: &str) -> bool {
        let before = self.subscribers.len();
        self.subscribers.retain(|s| s.subscriber_id() != subscriber_id);
        self.subscribers.len() < before
    }

    pub fn publish(&mut self, event: &TruthLifecycleEvent) -> Result<(), TruthError> {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_event(event)?;
            }
        }
        Ok(())
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    pub fn active_subscriber_count(&self) -> usize {
        self.subscribers.iter().filter(|s| s.is_active()).count()
    }
}

impl Default for TruthEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── TruthEventCollector ───────────────────────────────────────────
// A subscriber that collects all events for later inspection.

pub struct TruthEventCollector {
    id: String,
    events: Vec<TruthLifecycleEvent>,
}

impl TruthEventCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: Vec::new(),
        }
    }

    pub fn events(&self) -> &[TruthLifecycleEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl TruthEventSubscriber for TruthEventCollector {
    fn on_event(&mut self, event: &TruthLifecycleEvent) -> Result<(), TruthError> {
        self.events.push(event.clone());
        Ok(())
    }

    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── FilteredTruthEventSubscriber ──────────────────────────────────
// Wraps another subscriber, only forwarding events whose type passes
// a filter predicate.

pub struct FilteredTruthEventSubscriber {
    id: String,
    inner: Box<dyn TruthEventSubscriber>,
    accepted_types: Vec<TruthLifecycleEventType>,
}

impl FilteredTruthEventSubscriber {
    pub fn new(
        id: &str,
        inner: Box<dyn TruthEventSubscriber>,
        accepted_types: Vec<TruthLifecycleEventType>,
    ) -> Self {
        Self {
            id: id.to_string(),
            inner,
            accepted_types,
        }
    }
}

impl TruthEventSubscriber for FilteredTruthEventSubscriber {
    fn on_event(&mut self, event: &TruthLifecycleEvent) -> Result<(), TruthError> {
        if self.accepted_types.contains(&event.event_type) {
            self.inner.on_event(event)?;
        }
        Ok(())
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

    fn make_event(etype: TruthLifecycleEventType) -> TruthLifecycleEvent {
        TruthLifecycleEvent::new(etype, 1000, "test event")
    }

    #[test]
    fn test_event_type_name() {
        assert_eq!(TruthLifecycleEventType::ClaimPersisted.type_name(), "claim_persisted");
        assert_eq!(TruthLifecycleEventType::ContradictionResolved.type_name(), "contradiction_resolved");
    }

    #[test]
    fn test_event_type_classification() {
        assert!(TruthLifecycleEventType::ClaimPersisted.is_claim_event());
        assert!(!TruthLifecycleEventType::ClaimPersisted.is_contradiction_event());

        assert!(TruthLifecycleEventType::ContradictionDetected.is_contradiction_event());
        assert!(TruthLifecycleEventType::ContradictionResolved.is_contradiction_event());

        assert!(TruthLifecycleEventType::EvidenceLinkCreated.is_evidence_event());
        assert!(!TruthLifecycleEventType::ClaimExported.is_evidence_event());
    }

    #[test]
    fn test_event_display() {
        let e = TruthLifecycleEvent::new(
            TruthLifecycleEventType::ClaimPersisted,
            1000,
            "claim stored",
        );
        let s = e.to_string();
        assert!(s.contains("claim_persisted"));
        assert!(s.contains("1000"));
    }

    #[test]
    fn test_event_builder() {
        let e = TruthLifecycleEvent::new(
            TruthLifecycleEventType::ClaimPersisted,
            1000,
            "stored",
        )
        .with_claim_id("c1")
        .with_metadata("format", "json");

        assert_eq!(e.claim_id.as_deref(), Some("c1"));
        assert_eq!(e.metadata.len(), 1);
    }

    #[test]
    fn test_collector() {
        let mut collector = TruthEventCollector::new("col-1");
        collector.on_event(&make_event(TruthLifecycleEventType::ClaimPersisted)).unwrap();
        collector.on_event(&make_event(TruthLifecycleEventType::ClaimRetracted)).unwrap();
        assert_eq!(collector.event_count(), 2);
        collector.clear();
        assert_eq!(collector.event_count(), 0);
    }

    #[test]
    fn test_registry_publish() {
        let mut registry = TruthEventSubscriberRegistry::new();
        registry.register(Box::new(TruthEventCollector::new("col-1")));
        registry.register(Box::new(TruthEventCollector::new("col-2")));

        assert_eq!(registry.subscriber_count(), 2);
        assert_eq!(registry.active_subscriber_count(), 2);

        let event = make_event(TruthLifecycleEventType::ClaimPersisted);
        registry.publish(&event).unwrap();
    }

    #[test]
    fn test_registry_unregister() {
        let mut registry = TruthEventSubscriberRegistry::new();
        registry.register(Box::new(TruthEventCollector::new("col-1")));
        registry.register(Box::new(TruthEventCollector::new("col-2")));

        assert!(registry.unregister("col-1"));
        assert_eq!(registry.subscriber_count(), 1);
        assert!(!registry.unregister("nonexistent"));
    }

    #[test]
    fn test_filtered_subscriber() {
        let collector = TruthEventCollector::new("inner");
        let mut filtered = FilteredTruthEventSubscriber::new(
            "filter-1",
            Box::new(collector),
            vec![TruthLifecycleEventType::ClaimPersisted],
        );

        // Accepted event
        filtered.on_event(&make_event(TruthLifecycleEventType::ClaimPersisted)).unwrap();
        // Rejected event
        filtered.on_event(&make_event(TruthLifecycleEventType::ClaimRetracted)).unwrap();

        assert!(filtered.is_active());
        assert_eq!(filtered.subscriber_id(), "filter-1");
    }

    #[test]
    fn test_all_event_types_have_names() {
        let types = [
            TruthLifecycleEventType::ClaimPersisted,
            TruthLifecycleEventType::ClaimRetrieved,
            TruthLifecycleEventType::ClaimRetracted,
            TruthLifecycleEventType::ConsistencyCheckPassed,
            TruthLifecycleEventType::ConsistencyCheckFailed,
            TruthLifecycleEventType::ContradictionDetected,
            TruthLifecycleEventType::ContradictionResolved,
            TruthLifecycleEventType::CorroborationRecorded,
            TruthLifecycleEventType::EvidenceLinkCreated,
            TruthLifecycleEventType::EvidenceLinkRemoved,
            TruthLifecycleEventType::EvidenceAdequacyAssessed,
            TruthLifecycleEventType::ClaimExported,
            TruthLifecycleEventType::SourceReliabilityUpdated,
            TruthLifecycleEventType::SubscriberRegistered,
            TruthLifecycleEventType::SubscriberRemoved,
        ];
        for t in &types {
            assert!(!t.type_name().is_empty());
            assert!(!t.to_string().is_empty());
        }
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(
            TruthLifecycleEventType::ClaimPersisted.to_string(),
            "claim_persisted"
        );
    }

    #[test]
    fn test_registry_default() {
        let registry = TruthEventSubscriberRegistry::default();
        assert_eq!(registry.subscriber_count(), 0);
    }
}
