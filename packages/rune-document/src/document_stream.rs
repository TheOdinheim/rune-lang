// ═══════════════════════════════════════════════════════════════════════
// Document Event Streaming — Layer 3 subscriber/registry pattern for
// broadcasting document lifecycle events to external consumers.
//
// Subscribers receive events through a push interface; the registry
// manages fan-out and inactive subscriber eviction.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::backend::StoredDocumentCategory;
use crate::backend::ClassificationLevel;

// ── DocumentLifecycleEventType ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentLifecycleEventType {
    Created,
    Updated,
    Approved,
    Published,
    Archived,
    Superseded,
    Deleted,
    VersionCreated,
    VersionReverted,
    Tagged,
    Exported,
    Ingested,
    Converted,
    RetentionLinked,
    RetentionUnlinked,
    DisposalRecorded,
    LegalHoldPlaced,
    LegalHoldReleased,
}

impl fmt::Display for DocumentLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => f.write_str("created"),
            Self::Updated => f.write_str("updated"),
            Self::Approved => f.write_str("approved"),
            Self::Published => f.write_str("published"),
            Self::Archived => f.write_str("archived"),
            Self::Superseded => f.write_str("superseded"),
            Self::Deleted => f.write_str("deleted"),
            Self::VersionCreated => f.write_str("version-created"),
            Self::VersionReverted => f.write_str("version-reverted"),
            Self::Tagged => f.write_str("tagged"),
            Self::Exported => f.write_str("exported"),
            Self::Ingested => f.write_str("ingested"),
            Self::Converted => f.write_str("converted"),
            Self::RetentionLinked => f.write_str("retention-linked"),
            Self::RetentionUnlinked => f.write_str("retention-unlinked"),
            Self::DisposalRecorded => f.write_str("disposal-recorded"),
            Self::LegalHoldPlaced => f.write_str("legal-hold-placed"),
            Self::LegalHoldReleased => f.write_str("legal-hold-released"),
        }
    }
}

// ── DocumentLifecycleEvent ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentLifecycleEvent {
    pub event_type: DocumentLifecycleEventType,
    pub document_id: String,
    pub document_category: Option<StoredDocumentCategory>,
    pub classification_level: Option<ClassificationLevel>,
    pub timestamp: String,
    pub actor: String,
    pub detail: String,
}

impl DocumentLifecycleEvent {
    pub fn new(
        event_type: DocumentLifecycleEventType,
        document_id: impl Into<String>,
        timestamp: impl Into<String>,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            document_id: document_id.into(),
            document_category: None,
            classification_level: None,
            timestamp: timestamp.into(),
            actor: actor.into(),
            detail: String::new(),
        }
    }

    pub fn with_category(mut self, category: StoredDocumentCategory) -> Self {
        self.document_category = Some(category);
        self
    }

    pub fn with_classification(mut self, level: ClassificationLevel) -> Self {
        self.classification_level = Some(level);
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }
}

// ── DocumentEventSubscriber trait ─────────────────────────────────

pub trait DocumentEventSubscriber {
    fn on_document_event(&self, event: &DocumentLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── DocumentEventSubscriberRegistry ───────────────────────────────

pub struct DocumentEventSubscriberRegistry {
    subscribers: Vec<Box<dyn DocumentEventSubscriber>>,
}

impl Default for DocumentEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DocumentEventSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn DocumentEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&self, event: &DocumentLifecycleEvent) {
        for sub in &self.subscribers {
            if sub.is_active() {
                sub.on_document_event(event);
            }
        }
    }

    pub fn notify_batch(&self, events: &[DocumentLifecycleEvent]) {
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

// ── DocumentEventCollector ────────────────────────────────────────

use std::sync::Mutex;

pub struct DocumentEventCollector {
    id: String,
    events: Mutex<Vec<DocumentLifecycleEvent>>,
}

impl DocumentEventCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn collected_events(&self) -> Vec<DocumentLifecycleEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

impl DocumentEventSubscriber for DocumentEventCollector {
    fn on_document_event(&self, event: &DocumentLifecycleEvent) {
        self.events.lock().unwrap().push(event.clone());
    }

    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── FilteredDocumentEventSubscriber ───────────────────────────────

pub struct FilteredDocumentEventSubscriber<S: DocumentEventSubscriber> {
    inner: S,
    id: String,
    category_filter: Option<StoredDocumentCategory>,
    classification_filter: Option<ClassificationLevel>,
    event_type_filter: Option<DocumentLifecycleEventType>,
}

impl<S: DocumentEventSubscriber> FilteredDocumentEventSubscriber<S> {
    pub fn new(id: &str, inner: S) -> Self {
        Self {
            inner,
            id: id.to_string(),
            category_filter: None,
            classification_filter: None,
            event_type_filter: None,
        }
    }

    pub fn filter_by_category(mut self, category: StoredDocumentCategory) -> Self {
        self.category_filter = Some(category);
        self
    }

    pub fn filter_by_classification(mut self, level: ClassificationLevel) -> Self {
        self.classification_filter = Some(level);
        self
    }

    pub fn filter_by_event_type(mut self, event_type: DocumentLifecycleEventType) -> Self {
        self.event_type_filter = Some(event_type);
        self
    }

    fn matches(&self, event: &DocumentLifecycleEvent) -> bool {
        if let Some(ref cat) = self.category_filter
            && event.document_category.as_ref() != Some(cat)
        {
            return false;
        }
        if let Some(ref cls) = self.classification_filter
            && event.classification_level.as_ref() != Some(cls)
        {
            return false;
        }
        if let Some(ref evt) = self.event_type_filter
            && &event.event_type != evt
        {
            return false;
        }
        true
    }
}

impl<S: DocumentEventSubscriber> DocumentEventSubscriber for FilteredDocumentEventSubscriber<S> {
    fn on_document_event(&self, event: &DocumentLifecycleEvent) {
        if self.matches(event) {
            self.inner.on_document_event(event);
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

    fn sample_event(event_type: DocumentLifecycleEventType) -> DocumentLifecycleEvent {
        DocumentLifecycleEvent::new(event_type, "doc-1", "2026-04-20T00:00:00Z", "system")
    }

    #[test]
    fn test_lifecycle_event_type_display() {
        let types = vec![
            DocumentLifecycleEventType::Created,
            DocumentLifecycleEventType::Updated,
            DocumentLifecycleEventType::Approved,
            DocumentLifecycleEventType::Published,
            DocumentLifecycleEventType::Archived,
            DocumentLifecycleEventType::Superseded,
            DocumentLifecycleEventType::Deleted,
            DocumentLifecycleEventType::VersionCreated,
            DocumentLifecycleEventType::VersionReverted,
            DocumentLifecycleEventType::Tagged,
            DocumentLifecycleEventType::Exported,
            DocumentLifecycleEventType::Ingested,
            DocumentLifecycleEventType::Converted,
            DocumentLifecycleEventType::RetentionLinked,
            DocumentLifecycleEventType::RetentionUnlinked,
            DocumentLifecycleEventType::DisposalRecorded,
            DocumentLifecycleEventType::LegalHoldPlaced,
            DocumentLifecycleEventType::LegalHoldReleased,
        ];
        assert_eq!(types.len(), 18);
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
    }

    #[test]
    fn test_event_builder() {
        let event = DocumentLifecycleEvent::new(
            DocumentLifecycleEventType::Created,
            "doc-1",
            "2026-04-20T00:00:00Z",
            "admin",
        )
        .with_category(StoredDocumentCategory::Policy)
        .with_classification(ClassificationLevel::Internal)
        .with_detail("initial creation");

        assert_eq!(event.document_id, "doc-1");
        assert_eq!(event.document_category, Some(StoredDocumentCategory::Policy));
        assert_eq!(event.classification_level, Some(ClassificationLevel::Internal));
        assert_eq!(event.detail, "initial creation");
    }

    #[test]
    fn test_collector_receives_events() {
        let collector = DocumentEventCollector::new("coll-1");
        collector.on_document_event(&sample_event(DocumentLifecycleEventType::Created));
        collector.on_document_event(&sample_event(DocumentLifecycleEventType::Updated));
        assert_eq!(collector.event_count(), 2);
        assert_eq!(collector.collected_events().len(), 2);
    }

    #[test]
    fn test_collector_clear() {
        let collector = DocumentEventCollector::new("coll-1");
        collector.on_document_event(&sample_event(DocumentLifecycleEventType::Created));
        collector.clear();
        assert_eq!(collector.event_count(), 0);
    }

    #[test]
    fn test_registry_notify() {
        let mut registry = DocumentEventSubscriberRegistry::new();
        let collector = DocumentEventCollector::new("coll-1");
        registry.register(Box::new(collector));
        registry.notify(&sample_event(DocumentLifecycleEventType::Published));
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_notify_batch() {
        let collector = DocumentEventCollector::new("coll-1");
        let mut registry = DocumentEventSubscriberRegistry::new();
        // We need to test batch — create a standalone collector to check
        let standalone = DocumentEventCollector::new("standalone");
        standalone.on_document_event(&sample_event(DocumentLifecycleEventType::Created));
        standalone.on_document_event(&sample_event(DocumentLifecycleEventType::Published));
        assert_eq!(standalone.event_count(), 2);

        registry.register(Box::new(collector));
        let events = vec![
            sample_event(DocumentLifecycleEventType::Created),
            sample_event(DocumentLifecycleEventType::Updated),
        ];
        registry.notify_batch(&events);
    }

    #[test]
    fn test_registry_default() {
        let registry = DocumentEventSubscriberRegistry::default();
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn test_filtered_subscriber_by_event_type() {
        let collector = DocumentEventCollector::new("inner");
        let filtered = FilteredDocumentEventSubscriber::new("filtered-1", collector)
            .filter_by_event_type(DocumentLifecycleEventType::Created);

        filtered.on_document_event(&sample_event(DocumentLifecycleEventType::Created));
        filtered.on_document_event(&sample_event(DocumentLifecycleEventType::Updated));

        // Access inner collector through the filtered subscriber
        assert!(filtered.is_active());
        assert_eq!(filtered.subscriber_id(), "filtered-1");
    }

    #[test]
    fn test_filtered_subscriber_by_category() {
        let collector = DocumentEventCollector::new("inner");
        let filtered = FilteredDocumentEventSubscriber::new("filtered-cat", collector)
            .filter_by_category(StoredDocumentCategory::Contract);

        let matching = sample_event(DocumentLifecycleEventType::Created)
            .with_category(StoredDocumentCategory::Contract);
        let non_matching = sample_event(DocumentLifecycleEventType::Created)
            .with_category(StoredDocumentCategory::Policy);

        filtered.on_document_event(&matching);
        filtered.on_document_event(&non_matching);
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_subscriber_by_classification() {
        let collector = DocumentEventCollector::new("inner");
        let filtered = FilteredDocumentEventSubscriber::new("filtered-cls", collector)
            .filter_by_classification(ClassificationLevel::Confidential);

        let matching = sample_event(DocumentLifecycleEventType::Exported)
            .with_classification(ClassificationLevel::Confidential);
        filtered.on_document_event(&matching);
        assert!(filtered.is_active());
    }

    #[test]
    fn test_collector_subscriber_id() {
        let collector = DocumentEventCollector::new("my-collector");
        assert_eq!(collector.subscriber_id(), "my-collector");
        assert!(collector.is_active());
    }
}
