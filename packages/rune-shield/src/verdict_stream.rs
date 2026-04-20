// ═══════════════════════════════════════════════════════════════════════
// Verdict Stream — Verdict event streaming and subscriber registry.
//
// Layer 3 defines the contract for streaming shield verdicts to
// external consumers. Mirrors the AuditSubscriber pattern from
// rune-audit-ext. RUNE provides the shaped hole — the customer
// provides the subscriber implementation.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::response::{ShieldAction, ShieldVerdict};

// ── VerdictLifecycleEventType ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictLifecycleEventType {
    VerdictGenerated,
    VerdictEscalated,
    VerdictOverridden,
    MitigationApplied,
    MitigationFailed { reason: String },
    FalsePositiveReported,
    RuleHitRecorded { rule_id: String },
}

impl fmt::Display for VerdictLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MitigationFailed { reason } => write!(f, "MitigationFailed({reason})"),
            Self::RuleHitRecorded { rule_id } => write!(f, "RuleHitRecorded({rule_id})"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ── VerdictLifecycleEvent ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerdictLifecycleEvent {
    pub event_id: String,
    pub event_type: VerdictLifecycleEventType,
    pub verdict_id: String,
    pub timestamp: i64,
    pub detail: String,
}

impl VerdictLifecycleEvent {
    pub fn new(
        event_id: &str,
        event_type: VerdictLifecycleEventType,
        verdict_id: &str,
        timestamp: i64,
        detail: &str,
    ) -> Self {
        Self {
            event_id: event_id.to_string(),
            event_type,
            verdict_id: verdict_id.to_string(),
            timestamp,
            detail: detail.to_string(),
        }
    }
}

// ── VerdictSubscriber trait ─────────────────────────────────────

pub trait VerdictSubscriber {
    fn on_verdict(&mut self, verdict: &ShieldVerdict);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── VerdictSubscriberRegistry ───────────────────────────────────

pub struct VerdictSubscriberRegistry {
    subscribers: Vec<Box<dyn VerdictSubscriber>>,
}

impl VerdictSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn VerdictSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, verdict: &ShieldVerdict) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_verdict(verdict);
            }
        }
    }

    pub fn notify_batch(&mut self, verdicts: &[&ShieldVerdict]) {
        for verdict in verdicts {
            self.notify(verdict);
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

impl Default for VerdictSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── VerdictCollector (reference implementation) ─────────────────

pub struct VerdictCollector {
    id: String,
    verdicts: Vec<ShieldVerdict>,
    active: bool,
}

impl VerdictCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            verdicts: Vec::new(),
            active: true,
        }
    }

    pub fn verdicts(&self) -> &[ShieldVerdict] {
        &self.verdicts
    }

    pub fn verdict_count(&self) -> usize {
        self.verdicts.len()
    }

    pub fn drain(&mut self) -> Vec<ShieldVerdict> {
        self.verdicts.drain(..).collect()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl VerdictSubscriber for VerdictCollector {
    fn on_verdict(&mut self, verdict: &ShieldVerdict) {
        self.verdicts.push(verdict.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredVerdictSubscriber ───────────────────────────────────

/// Filters verdicts before forwarding to an inner collector.
/// Supports filtering by minimum severity, action type, or rule id.
pub struct FilteredVerdictSubscriber {
    id: String,
    inner: VerdictCollector,
    min_severity: Option<rune_security::SecuritySeverity>,
    action_filter: Option<String>,
    rule_id_filter: Option<String>,
    active: bool,
}

impl FilteredVerdictSubscriber {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            inner: VerdictCollector::new(&format!("{id}-inner")),
            min_severity: None,
            action_filter: None,
            rule_id_filter: None,
            active: true,
        }
    }

    pub fn with_min_severity(mut self, severity: rune_security::SecuritySeverity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    pub fn with_action_filter(mut self, action_type: &str) -> Self {
        self.action_filter = Some(action_type.to_string());
        self
    }

    pub fn with_rule_id_filter(mut self, rule_id: &str) -> Self {
        self.rule_id_filter = Some(rule_id.to_string());
        self
    }

    pub fn collected(&self) -> &[ShieldVerdict] {
        self.inner.verdicts()
    }

    pub fn collected_count(&self) -> usize {
        self.inner.verdict_count()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }

    fn matches(&self, verdict: &ShieldVerdict) -> bool {
        if let Some(min) = self.min_severity
            && (verdict.severity as u8) < (min as u8)
        {
            return false;
        }
        if let Some(ref action_type) = self.action_filter {
            let action_name = match &verdict.action {
                ShieldAction::Allow => "Allow",
                ShieldAction::Block { .. } => "Block",
                ShieldAction::Quarantine { .. } => "Quarantine",
                ShieldAction::Escalate { .. } => "Escalate",
                ShieldAction::Modify { .. } => "Modify",
            };
            if action_name != action_type {
                return false;
            }
        }
        if let Some(ref rule_id) = self.rule_id_filter
            && !verdict.evidence.iter().any(|e| e.contains(rule_id.as_str()))
        {
            return false;
        }
        true
    }
}

impl VerdictSubscriber for FilteredVerdictSubscriber {
    fn on_verdict(&mut self, verdict: &ShieldVerdict) {
        if self.matches(verdict) {
            self.inner.on_verdict(verdict);
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

    fn make_block_verdict() -> ShieldVerdict {
        ShieldVerdict::block("injection", SecuritySeverity::High, 0.9)
            .with_evidence("rule-r1")
    }

    #[test]
    fn test_collector_collects_verdicts() {
        let mut collector = VerdictCollector::new("c1");
        collector.on_verdict(&make_block_verdict());
        assert_eq!(collector.verdict_count(), 1);
        assert!(collector.verdicts()[0].action.is_blocked());
    }

    #[test]
    fn test_collector_drain() {
        let mut collector = VerdictCollector::new("c1");
        collector.on_verdict(&make_block_verdict());
        collector.on_verdict(&ShieldVerdict::allow());
        let drained = collector.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(collector.verdict_count(), 0);
    }

    #[test]
    fn test_registry_notify() {
        let mut registry = VerdictSubscriberRegistry::new();
        registry.register(Box::new(VerdictCollector::new("c1")));
        registry.notify(&make_block_verdict());
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut registry = VerdictSubscriberRegistry::new();
        registry.register(Box::new(VerdictCollector::new("c1")));
        let v1 = make_block_verdict();
        let v2 = ShieldVerdict::allow();
        registry.notify_batch(&[&v1, &v2]);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_remove_inactive() {
        let mut registry = VerdictSubscriberRegistry::new();
        let mut collector = VerdictCollector::new("c1");
        collector.deactivate();
        registry.register(Box::new(collector));
        registry.register(Box::new(VerdictCollector::new("c2")));
        let removed = registry.remove_inactive();
        assert_eq!(removed, 1);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_filtered_subscriber_min_severity() {
        let mut sub = FilteredVerdictSubscriber::new("f1")
            .with_min_severity(SecuritySeverity::High);
        sub.on_verdict(&ShieldVerdict::block("low", SecuritySeverity::Low, 0.5));
        sub.on_verdict(&ShieldVerdict::block("high", SecuritySeverity::High, 0.9));
        assert_eq!(sub.collected_count(), 1);
    }

    #[test]
    fn test_filtered_subscriber_action_filter() {
        let mut sub = FilteredVerdictSubscriber::new("f1")
            .with_action_filter("Block");
        sub.on_verdict(&ShieldVerdict::allow());
        sub.on_verdict(&make_block_verdict());
        assert_eq!(sub.collected_count(), 1);
    }

    #[test]
    fn test_filtered_subscriber_rule_id_filter() {
        let mut sub = FilteredVerdictSubscriber::new("f1")
            .with_rule_id_filter("r1");
        sub.on_verdict(&ShieldVerdict::allow()); // no evidence with r1
        sub.on_verdict(&make_block_verdict()); // has "rule-r1" in evidence
        assert_eq!(sub.collected_count(), 1);
    }

    #[test]
    fn test_lifecycle_event_types() {
        let types = vec![
            VerdictLifecycleEventType::VerdictGenerated,
            VerdictLifecycleEventType::VerdictEscalated,
            VerdictLifecycleEventType::VerdictOverridden,
            VerdictLifecycleEventType::MitigationApplied,
            VerdictLifecycleEventType::MitigationFailed { reason: "timeout".into() },
            VerdictLifecycleEventType::FalsePositiveReported,
            VerdictLifecycleEventType::RuleHitRecorded { rule_id: "r1".into() },
        ];
        for t in &types {
            let event = VerdictLifecycleEvent::new("e1", t.clone(), "v1", 1000, "test");
            assert_eq!(event.verdict_id, "v1");
            assert!(!t.to_string().is_empty());
        }
    }
}
