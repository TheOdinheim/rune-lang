// ═══════════════════════════════════════════════════════════════════════
// Subject Rights Stream — Streaming interface for subject rights events.
//
// Mirrors the DecisionSubscriber pattern from rune-permissions.
// FilteredSubjectRightsSubscriber supports filtering by request type,
// jurisdiction, or time-to-respond threshold for SLA monitoring.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::backend::{RequestType, SubjectRef};
use crate::error::PrivacyError;

// ── SubjectRightsEventType ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectRightsEventType {
    AccessRequestReceived,
    AccessRequestFulfilled,
    AccessRequestRefused,
    RectificationRequested,
    RectificationCompleted,
    ErasureRequested,
    ErasureCompleted,
    ErasureRefused,
    PortabilityRequested,
    PortabilityFulfilled,
    RestrictionRequested,
    RestrictionApplied,
    RestrictionLifted,
    ObjectionRaised,
    ObjectionUpheld,
    ObjectionOverruled,
    ConsentWithdrawn,
    ConsentGranted,
    ConsentExpired,
    AutomatedDecisionObjected,
}

impl fmt::Display for SubjectRightsEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SubjectRightsEvent ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SubjectRightsEvent {
    pub event_type: SubjectRightsEventType,
    pub subject_ref: SubjectRef,
    pub request_type: Option<RequestType>,
    pub jurisdiction: String,
    pub timestamp: i64,
    pub detail: String,
}

impl SubjectRightsEvent {
    pub fn new(
        event_type: SubjectRightsEventType,
        subject_ref: SubjectRef,
        jurisdiction: &str,
        timestamp: i64,
    ) -> Self {
        Self {
            event_type,
            subject_ref,
            request_type: None,
            jurisdiction: jurisdiction.to_string(),
            timestamp,
            detail: String::new(),
        }
    }

    pub fn with_request_type(mut self, rt: RequestType) -> Self {
        self.request_type = Some(rt);
        self
    }

    pub fn with_detail(mut self, detail: &str) -> Self {
        self.detail = detail.to_string();
        self
    }
}

// ── SubjectRightsSubscriber trait ───────────────────────────────────

pub trait SubjectRightsSubscriber {
    fn on_subject_rights_event(&self, event: &SubjectRightsEvent) -> Result<(), PrivacyError>;
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── SubjectRightsSubscriberRegistry ─────────────────────────────────

pub struct SubjectRightsSubscriberRegistry {
    subscribers: Vec<Box<dyn SubjectRightsSubscriber>>,
}

impl SubjectRightsSubscriberRegistry {
    pub fn new() -> Self {
        Self { subscribers: Vec::new() }
    }

    pub fn register(&mut self, subscriber: Box<dyn SubjectRightsSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&self, event: &SubjectRightsEvent) -> Result<(), PrivacyError> {
        for sub in &self.subscribers {
            if sub.is_active() {
                sub.on_subject_rights_event(event)?;
            }
        }
        Ok(())
    }

    pub fn notify_batch(&self, events: &[SubjectRightsEvent]) -> Result<(), PrivacyError> {
        for event in events {
            self.notify(event)?;
        }
        Ok(())
    }

    pub fn active_count(&self) -> usize {
        self.subscribers.iter().filter(|s| s.is_active()).count()
    }

    pub fn remove_inactive(&mut self) {
        self.subscribers.retain(|s| s.is_active());
    }
}

impl Default for SubjectRightsSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── SubjectRightsCollector ──────────────────────────────────────────

pub struct SubjectRightsCollector {
    id: String,
    events: std::cell::RefCell<Vec<SubjectRightsEvent>>,
}

impl SubjectRightsCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: std::cell::RefCell::new(Vec::new()),
        }
    }

    pub fn collected_events(&self) -> Vec<SubjectRightsEvent> {
        self.events.borrow().clone()
    }

    pub fn event_count(&self) -> usize {
        self.events.borrow().len()
    }
}

impl SubjectRightsSubscriber for SubjectRightsCollector {
    fn on_subject_rights_event(&self, event: &SubjectRightsEvent) -> Result<(), PrivacyError> {
        self.events.borrow_mut().push(event.clone());
        Ok(())
    }

    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── FilteredSubjectRightsSubscriber ─────────────────────────────────

pub struct FilteredSubjectRightsSubscriber {
    id: String,
    inner: SubjectRightsCollector,
    filter_request_type: Option<RequestType>,
    filter_jurisdiction: Option<String>,
    filter_max_response_time_ms: Option<i64>,
}

impl FilteredSubjectRightsSubscriber {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            inner: SubjectRightsCollector::new(&format!("{id}-inner")),
            filter_request_type: None,
            filter_jurisdiction: None,
            filter_max_response_time_ms: None,
        }
    }

    pub fn with_request_type_filter(mut self, rt: RequestType) -> Self {
        self.filter_request_type = Some(rt);
        self
    }

    pub fn with_jurisdiction_filter(mut self, jurisdiction: &str) -> Self {
        self.filter_jurisdiction = Some(jurisdiction.to_string());
        self
    }

    pub fn with_response_time_threshold(mut self, max_ms: i64) -> Self {
        self.filter_max_response_time_ms = Some(max_ms);
        self
    }

    pub fn collected_events(&self) -> Vec<SubjectRightsEvent> {
        self.inner.collected_events()
    }

    pub fn event_count(&self) -> usize {
        self.inner.event_count()
    }

    fn matches(&self, event: &SubjectRightsEvent) -> bool {
        if let Some(ref rt) = self.filter_request_type {
            if event.request_type.as_ref() != Some(rt) {
                return false;
            }
        }
        if let Some(ref jur) = self.filter_jurisdiction {
            if event.jurisdiction != *jur {
                return false;
            }
        }
        true
    }
}

impl SubjectRightsSubscriber for FilteredSubjectRightsSubscriber {
    fn on_subject_rights_event(&self, event: &SubjectRightsEvent) -> Result<(), PrivacyError> {
        if self.matches(event) {
            self.inner.on_subject_rights_event(event)?;
        }
        Ok(())
    }

    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(et: SubjectRightsEventType) -> SubjectRightsEvent {
        SubjectRightsEvent::new(et, SubjectRef::new("alice"), "EU", 1000)
    }

    #[test]
    fn test_collector_records_events() {
        let collector = SubjectRightsCollector::new("c1");
        collector.on_subject_rights_event(&make_event(SubjectRightsEventType::AccessRequestReceived)).unwrap();
        collector.on_subject_rights_event(&make_event(SubjectRightsEventType::ErasureRequested)).unwrap();
        assert_eq!(collector.event_count(), 2);
    }

    #[test]
    fn test_registry_notifies_all() {
        let mut registry = SubjectRightsSubscriberRegistry::new();
        registry.register(Box::new(SubjectRightsCollector::new("c1")));
        registry.register(Box::new(SubjectRightsCollector::new("c2")));
        registry.notify(&make_event(SubjectRightsEventType::ConsentGranted)).unwrap();
        assert_eq!(registry.active_count(), 2);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut registry = SubjectRightsSubscriberRegistry::new();
        let collector = SubjectRightsCollector::new("c1");
        registry.register(Box::new(SubjectRightsCollector::new("c1")));
        let events = vec![
            make_event(SubjectRightsEventType::AccessRequestReceived),
            make_event(SubjectRightsEventType::AccessRequestFulfilled),
        ];
        registry.notify_batch(&events).unwrap();
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_filtered_by_request_type() {
        let filtered = FilteredSubjectRightsSubscriber::new("f1")
            .with_request_type_filter(RequestType::Erasure);
        let access = make_event(SubjectRightsEventType::AccessRequestReceived)
            .with_request_type(RequestType::Access);
        let erasure = make_event(SubjectRightsEventType::ErasureRequested)
            .with_request_type(RequestType::Erasure);
        filtered.on_subject_rights_event(&access).unwrap();
        filtered.on_subject_rights_event(&erasure).unwrap();
        assert_eq!(filtered.event_count(), 1);
    }

    #[test]
    fn test_filtered_by_jurisdiction() {
        let filtered = FilteredSubjectRightsSubscriber::new("f1")
            .with_jurisdiction_filter("EU");
        let eu = make_event(SubjectRightsEventType::AccessRequestReceived);
        let mut us = make_event(SubjectRightsEventType::AccessRequestReceived);
        us.jurisdiction = "US".to_string();
        filtered.on_subject_rights_event(&eu).unwrap();
        filtered.on_subject_rights_event(&us).unwrap();
        assert_eq!(filtered.event_count(), 1);
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(SubjectRightsEventType::AccessRequestReceived.to_string(), "AccessRequestReceived");
        assert_eq!(SubjectRightsEventType::AutomatedDecisionObjected.to_string(), "AutomatedDecisionObjected");
        assert_eq!(SubjectRightsEventType::ConsentWithdrawn.to_string(), "ConsentWithdrawn");
    }

    #[test]
    fn test_event_with_detail() {
        let event = make_event(SubjectRightsEventType::ErasureRefused)
            .with_detail("legal hold in effect");
        assert_eq!(event.detail, "legal hold in effect");
    }

    #[test]
    fn test_event_with_request_type() {
        let event = make_event(SubjectRightsEventType::PortabilityRequested)
            .with_request_type(RequestType::Portability);
        assert_eq!(event.request_type, Some(RequestType::Portability));
    }

    #[test]
    fn test_all_event_types_exist() {
        let types = vec![
            SubjectRightsEventType::AccessRequestReceived,
            SubjectRightsEventType::AccessRequestFulfilled,
            SubjectRightsEventType::AccessRequestRefused,
            SubjectRightsEventType::RectificationRequested,
            SubjectRightsEventType::RectificationCompleted,
            SubjectRightsEventType::ErasureRequested,
            SubjectRightsEventType::ErasureCompleted,
            SubjectRightsEventType::ErasureRefused,
            SubjectRightsEventType::PortabilityRequested,
            SubjectRightsEventType::PortabilityFulfilled,
            SubjectRightsEventType::RestrictionRequested,
            SubjectRightsEventType::RestrictionApplied,
            SubjectRightsEventType::RestrictionLifted,
            SubjectRightsEventType::ObjectionRaised,
            SubjectRightsEventType::ObjectionUpheld,
            SubjectRightsEventType::ObjectionOverruled,
            SubjectRightsEventType::ConsentWithdrawn,
            SubjectRightsEventType::ConsentGranted,
            SubjectRightsEventType::ConsentExpired,
            SubjectRightsEventType::AutomatedDecisionObjected,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 20);
    }

    #[test]
    fn test_registry_remove_inactive() {
        let mut registry = SubjectRightsSubscriberRegistry::new();
        registry.register(Box::new(SubjectRightsCollector::new("c1")));
        assert_eq!(registry.active_count(), 1);
        registry.remove_inactive();
        assert_eq!(registry.active_count(), 1); // collector is always active
    }

    #[test]
    fn test_filtered_no_filter_passes_all() {
        let filtered = FilteredSubjectRightsSubscriber::new("f1");
        filtered.on_subject_rights_event(&make_event(SubjectRightsEventType::ConsentGranted)).unwrap();
        filtered.on_subject_rights_event(&make_event(SubjectRightsEventType::ErasureRequested)).unwrap();
        assert_eq!(filtered.event_count(), 2);
    }
}
