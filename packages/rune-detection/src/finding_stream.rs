// ═══════════════════════════════════════════════════════════════════════
// Finding Stream — Finding event streaming and subscriber registry.
//
// Layer 3 defines the contract for streaming detection findings to
// external consumers. Mirrors the VerdictSubscriber pattern from
// rune-shield. RUNE provides the shaped hole — the customer provides
// the subscriber implementation.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::backend::DetectionFinding;

// ── FindingLifecycleEventType ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingLifecycleEventType {
    FindingGenerated,
    FindingPromoted,
    FindingDismissed,
    FindingCorrelated { correlation_id: String },
    FindingEscalated,
    FindingMarkedFalsePositive,
    FindingResolved,
}

impl fmt::Display for FindingLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FindingCorrelated { correlation_id } => {
                write!(f, "FindingCorrelated({correlation_id})")
            }
            other => write!(f, "{other:?}"),
        }
    }
}

// ── FindingLifecycleEvent ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FindingLifecycleEvent {
    pub event_id: String,
    pub event_type: FindingLifecycleEventType,
    pub finding_id: String,
    pub timestamp: i64,
    pub detail: String,
}

impl FindingLifecycleEvent {
    pub fn new(
        event_id: &str,
        event_type: FindingLifecycleEventType,
        finding_id: &str,
        timestamp: i64,
        detail: &str,
    ) -> Self {
        Self {
            event_id: event_id.to_string(),
            event_type,
            finding_id: finding_id.to_string(),
            timestamp,
            detail: detail.to_string(),
        }
    }
}

// ── FindingSubscriber trait ────────────────────────────────────

pub trait FindingSubscriber {
    fn on_finding(&mut self, finding: &DetectionFinding);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── FindingSubscriberRegistry ──────────────────────────────────

pub struct FindingSubscriberRegistry {
    subscribers: Vec<Box<dyn FindingSubscriber>>,
}

impl FindingSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn FindingSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, finding: &DetectionFinding) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_finding(finding);
            }
        }
    }

    pub fn notify_batch(&mut self, findings: &[&DetectionFinding]) {
        for finding in findings {
            self.notify(finding);
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

impl Default for FindingSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── FindingCollector (reference implementation) ────────────────

pub struct FindingCollector {
    id: String,
    findings: Vec<DetectionFinding>,
    active: bool,
}

impl FindingCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            findings: Vec::new(),
            active: true,
        }
    }

    pub fn findings(&self) -> &[DetectionFinding] {
        &self.findings
    }

    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    pub fn drain(&mut self) -> Vec<DetectionFinding> {
        self.findings.drain(..).collect()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl FindingSubscriber for FindingCollector {
    fn on_finding(&mut self, finding: &DetectionFinding) {
        self.findings.push(finding.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredFindingSubscriber ──────────────────────────────────

/// Filters findings before forwarding to an inner collector.
/// Supports filtering by minimum severity, detection category,
/// or source system.
pub struct FilteredFindingSubscriber {
    id: String,
    inner: FindingCollector,
    min_severity: Option<rune_security::SecuritySeverity>,
    category_filter: Option<String>,
    source_filter: Option<String>,
    active: bool,
}

impl FilteredFindingSubscriber {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            inner: FindingCollector::new(&format!("{id}-inner")),
            min_severity: None,
            category_filter: None,
            source_filter: None,
            active: true,
        }
    }

    pub fn with_min_severity(mut self, severity: rune_security::SecuritySeverity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    pub fn with_category_filter(mut self, category: &str) -> Self {
        self.category_filter = Some(category.to_string());
        self
    }

    pub fn with_source_filter(mut self, source: &str) -> Self {
        self.source_filter = Some(source.to_string());
        self
    }

    pub fn collected(&self) -> &[DetectionFinding] {
        self.inner.findings()
    }

    pub fn collected_count(&self) -> usize {
        self.inner.finding_count()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }

    fn matches(&self, finding: &DetectionFinding) -> bool {
        if let Some(min) = self.min_severity
            && (finding.severity as u8) < (min as u8)
        {
            return false;
        }
        if let Some(ref cat) = self.category_filter
            && finding.category != *cat
        {
            return false;
        }
        if let Some(ref src) = self.source_filter
            && finding.source != *src
        {
            return false;
        }
        true
    }
}

impl FindingSubscriber for FilteredFindingSubscriber {
    fn on_finding(&mut self, finding: &DetectionFinding) {
        if self.matches(finding) {
            self.inner.on_finding(finding);
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
    use rune_security::SecuritySeverity;

    fn make_finding(id: &str, severity: SecuritySeverity) -> DetectionFinding {
        DetectionFinding::new(id, "Test Finding", severity, 1000)
            .with_category("injection")
            .with_source("pipeline-1")
    }

    #[test]
    fn test_collector_collects_findings() {
        let mut collector = FindingCollector::new("c1");
        collector.on_finding(&make_finding("f1", SecuritySeverity::High));
        assert_eq!(collector.finding_count(), 1);
        assert_eq!(collector.findings()[0].id, "f1");
    }

    #[test]
    fn test_collector_drain() {
        let mut collector = FindingCollector::new("c1");
        collector.on_finding(&make_finding("f1", SecuritySeverity::High));
        collector.on_finding(&make_finding("f2", SecuritySeverity::Low));
        let drained = collector.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(collector.finding_count(), 0);
    }

    #[test]
    fn test_registry_notify() {
        let mut registry = FindingSubscriberRegistry::new();
        registry.register(Box::new(FindingCollector::new("c1")));
        registry.notify(&make_finding("f1", SecuritySeverity::High));
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut registry = FindingSubscriberRegistry::new();
        registry.register(Box::new(FindingCollector::new("c1")));
        let f1 = make_finding("f1", SecuritySeverity::High);
        let f2 = make_finding("f2", SecuritySeverity::Low);
        registry.notify_batch(&[&f1, &f2]);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_remove_inactive() {
        let mut registry = FindingSubscriberRegistry::new();
        let mut collector = FindingCollector::new("c1");
        collector.deactivate();
        registry.register(Box::new(collector));
        registry.register(Box::new(FindingCollector::new("c2")));
        let removed = registry.remove_inactive();
        assert_eq!(removed, 1);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_filtered_subscriber_min_severity() {
        let mut sub = FilteredFindingSubscriber::new("f1")
            .with_min_severity(SecuritySeverity::High);
        sub.on_finding(&make_finding("low", SecuritySeverity::Low));
        sub.on_finding(&make_finding("high", SecuritySeverity::High));
        assert_eq!(sub.collected_count(), 1);
        assert_eq!(sub.collected()[0].id, "high");
    }

    #[test]
    fn test_filtered_subscriber_category_filter() {
        let mut sub = FilteredFindingSubscriber::new("f1")
            .with_category_filter("injection");
        sub.on_finding(&make_finding("f1", SecuritySeverity::High));
        sub.on_finding(
            &DetectionFinding::new("f2", "Other", SecuritySeverity::High, 1000)
                .with_category("exfiltration"),
        );
        assert_eq!(sub.collected_count(), 1);
    }

    #[test]
    fn test_filtered_subscriber_source_filter() {
        let mut sub = FilteredFindingSubscriber::new("f1")
            .with_source_filter("pipeline-1");
        sub.on_finding(&make_finding("f1", SecuritySeverity::High));
        sub.on_finding(
            &DetectionFinding::new("f2", "Other", SecuritySeverity::High, 1000)
                .with_source("pipeline-2"),
        );
        assert_eq!(sub.collected_count(), 1);
    }

    #[test]
    fn test_lifecycle_event_types() {
        let types = vec![
            FindingLifecycleEventType::FindingGenerated,
            FindingLifecycleEventType::FindingPromoted,
            FindingLifecycleEventType::FindingDismissed,
            FindingLifecycleEventType::FindingCorrelated {
                correlation_id: "cor-1".into(),
            },
            FindingLifecycleEventType::FindingEscalated,
            FindingLifecycleEventType::FindingMarkedFalsePositive,
            FindingLifecycleEventType::FindingResolved,
        ];
        for t in &types {
            let event = FindingLifecycleEvent::new("e1", t.clone(), "f1", 1000, "test");
            assert_eq!(event.finding_id, "f1");
            assert!(!t.to_string().is_empty());
        }
    }

    #[test]
    fn test_deactivated_subscriber_skipped() {
        let mut registry = FindingSubscriberRegistry::new();
        let mut sub = FilteredFindingSubscriber::new("f1");
        sub.deactivate();
        registry.register(Box::new(sub));
        registry.notify(&make_finding("f1", SecuritySeverity::High));
        assert_eq!(registry.active_count(), 0);
    }
}
