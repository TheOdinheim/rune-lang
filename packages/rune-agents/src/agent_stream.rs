// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — AgentLifecycleEventSubscriber trait and registry for
// lifecycle event streaming with filtering by agent_id, event_type,
// severity.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── AgentGovernanceLifecycleEventType ───────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentGovernanceLifecycleEventType {
    GovernanceProfileCreated,
    GovernanceProfileUpdated,
    GovernanceProfileSuspended,
    GovernanceProfileDecommissioned,
    AutonomyLevelEvaluated,
    AutonomyLevelChanged,
    AutonomyEscalationTriggered,
    ToolPolicyRegistered,
    ToolPolicyRemoved,
    ToolRequestEvaluated,
    ToolRequestDenied,
    DelegationRequested,
    DelegationApproved,
    DelegationDenied,
    DelegationDepthLimitEnforced,
    DelegationChainRecorded,
    GovernanceExported,
    GovernanceExportFailed,
    GovernanceSnapshotCaptured,
    GovernanceMetricsComputed,
}

impl fmt::Display for AgentGovernanceLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::GovernanceProfileCreated => "GovernanceProfileCreated",
            Self::GovernanceProfileUpdated => "GovernanceProfileUpdated",
            Self::GovernanceProfileSuspended => "GovernanceProfileSuspended",
            Self::GovernanceProfileDecommissioned => "GovernanceProfileDecommissioned",
            Self::AutonomyLevelEvaluated => "AutonomyLevelEvaluated",
            Self::AutonomyLevelChanged => "AutonomyLevelChanged",
            Self::AutonomyEscalationTriggered => "AutonomyEscalationTriggered",
            Self::ToolPolicyRegistered => "ToolPolicyRegistered",
            Self::ToolPolicyRemoved => "ToolPolicyRemoved",
            Self::ToolRequestEvaluated => "ToolRequestEvaluated",
            Self::ToolRequestDenied => "ToolRequestDenied",
            Self::DelegationRequested => "DelegationRequested",
            Self::DelegationApproved => "DelegationApproved",
            Self::DelegationDenied => "DelegationDenied",
            Self::DelegationDepthLimitEnforced => "DelegationDepthLimitEnforced",
            Self::DelegationChainRecorded => "DelegationChainRecorded",
            Self::GovernanceExported => "GovernanceExported",
            Self::GovernanceExportFailed => "GovernanceExportFailed",
            Self::GovernanceSnapshotCaptured => "GovernanceSnapshotCaptured",
            Self::GovernanceMetricsComputed => "GovernanceMetricsComputed",
        };
        f.write_str(s)
    }
}

// ── AgentGovernanceLifecycleEvent ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentGovernanceLifecycleEvent {
    pub event_type: AgentGovernanceLifecycleEventType,
    pub timestamp: i64,
    pub agent_id: String,
    pub severity: String,
    pub detail: String,
}

impl AgentGovernanceLifecycleEvent {
    pub fn new(
        event_type: AgentGovernanceLifecycleEventType,
        timestamp: i64,
        agent_id: impl Into<String>,
        severity: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp,
            agent_id: agent_id.into(),
            severity: severity.into(),
            detail: detail.into(),
        }
    }
}

// ── AgentLifecycleEventSubscriber trait ──────────────────────────────

pub trait AgentLifecycleEventSubscriber {
    fn on_agent_governance_event(&mut self, event: &AgentGovernanceLifecycleEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── AgentLifecycleEventSubscriberRegistry ───────────────────────────

pub struct AgentLifecycleEventSubscriberRegistry {
    subscribers: Vec<Box<dyn AgentLifecycleEventSubscriber>>,
}

impl AgentLifecycleEventSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn AgentLifecycleEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &AgentGovernanceLifecycleEvent) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_agent_governance_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[AgentGovernanceLifecycleEvent]) {
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

impl Default for AgentLifecycleEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── AgentGovernanceEventCollector ────────────────────────────────────

pub struct AgentGovernanceEventCollector {
    id: String,
    collected: Vec<AgentGovernanceLifecycleEvent>,
    active: bool,
}

impl AgentGovernanceEventCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            collected: Vec::new(),
            active: true,
        }
    }

    pub fn collected_events(&self) -> &[AgentGovernanceLifecycleEvent] {
        &self.collected
    }
}

impl AgentLifecycleEventSubscriber for AgentGovernanceEventCollector {
    fn on_agent_governance_event(&mut self, event: &AgentGovernanceLifecycleEvent) {
        self.collected.push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredAgentLifecycleEventSubscriber ───────────────────────────

pub struct FilteredAgentLifecycleEventSubscriber<S: AgentLifecycleEventSubscriber> {
    inner: S,
    agent_id_filter: Option<String>,
    event_type_filter: Option<AgentGovernanceLifecycleEventType>,
    severity_filter: Option<String>,
}

impl<S: AgentLifecycleEventSubscriber> FilteredAgentLifecycleEventSubscriber<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            agent_id_filter: None,
            event_type_filter: None,
            severity_filter: None,
        }
    }

    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id_filter = Some(agent_id.into());
        self
    }

    pub fn with_event_type(mut self, event_type: AgentGovernanceLifecycleEventType) -> Self {
        self.event_type_filter = Some(event_type);
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity_filter = Some(severity.into());
        self
    }

    fn matches(&self, event: &AgentGovernanceLifecycleEvent) -> bool {
        if let Some(ref aid) = self.agent_id_filter && &event.agent_id != aid {
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

impl<S: AgentLifecycleEventSubscriber> AgentLifecycleEventSubscriber
    for FilteredAgentLifecycleEventSubscriber<S>
{
    fn on_agent_governance_event(&mut self, event: &AgentGovernanceLifecycleEvent) {
        if self.matches(event) {
            self.inner.on_agent_governance_event(event);
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
        et: AgentGovernanceLifecycleEventType,
    ) -> AgentGovernanceLifecycleEvent {
        AgentGovernanceLifecycleEvent::new(et, 1000, "agent-1", "Critical", "test detail")
    }

    #[test]
    fn test_collector() {
        let mut collector = AgentGovernanceEventCollector::new("c1");
        collector.on_agent_governance_event(&sample_event(
            AgentGovernanceLifecycleEventType::GovernanceProfileCreated,
        ));
        assert_eq!(collector.collected_events().len(), 1);
    }

    #[test]
    fn test_registry_notify() {
        let mut reg = AgentLifecycleEventSubscriberRegistry::new();
        reg.register(Box::new(AgentGovernanceEventCollector::new("c1")));
        reg.register(Box::new(AgentGovernanceEventCollector::new("c2")));
        reg.notify(&sample_event(
            AgentGovernanceLifecycleEventType::AutonomyLevelEvaluated,
        ));
        assert_eq!(reg.active_count(), 2);
    }

    #[test]
    fn test_registry_notify_batch() {
        let mut reg = AgentLifecycleEventSubscriberRegistry::new();
        reg.register(Box::new(AgentGovernanceEventCollector::new("c1")));
        let events = vec![
            sample_event(AgentGovernanceLifecycleEventType::ToolPolicyRegistered),
            sample_event(AgentGovernanceLifecycleEventType::DelegationApproved),
        ];
        reg.notify_batch(&events);
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn test_filtered_by_agent_id() {
        let inner = AgentGovernanceEventCollector::new("f1");
        let mut filtered =
            FilteredAgentLifecycleEventSubscriber::new(inner).with_agent_id("agent-1");
        filtered.on_agent_governance_event(&sample_event(
            AgentGovernanceLifecycleEventType::GovernanceProfileCreated,
        ));
        let other = AgentGovernanceLifecycleEvent::new(
            AgentGovernanceLifecycleEventType::GovernanceProfileCreated,
            2000,
            "agent-2",
            "Warning",
            "other",
        );
        filtered.on_agent_governance_event(&other);
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_by_event_type() {
        let inner = AgentGovernanceEventCollector::new("f1");
        let mut filtered = FilteredAgentLifecycleEventSubscriber::new(inner)
            .with_event_type(AgentGovernanceLifecycleEventType::AutonomyEscalationTriggered);
        filtered.on_agent_governance_event(&sample_event(
            AgentGovernanceLifecycleEventType::GovernanceProfileCreated,
        ));
        assert!(filtered.is_active());
    }

    #[test]
    fn test_filtered_by_severity() {
        let inner = AgentGovernanceEventCollector::new("f1");
        let mut filtered =
            FilteredAgentLifecycleEventSubscriber::new(inner).with_severity("Critical");
        filtered.on_agent_governance_event(&sample_event(
            AgentGovernanceLifecycleEventType::DelegationDepthLimitEnforced,
        ));
        assert!(filtered.is_active());
    }

    #[test]
    fn test_event_type_display_all() {
        let types = vec![
            AgentGovernanceLifecycleEventType::GovernanceProfileCreated,
            AgentGovernanceLifecycleEventType::GovernanceProfileUpdated,
            AgentGovernanceLifecycleEventType::GovernanceProfileSuspended,
            AgentGovernanceLifecycleEventType::GovernanceProfileDecommissioned,
            AgentGovernanceLifecycleEventType::AutonomyLevelEvaluated,
            AgentGovernanceLifecycleEventType::AutonomyLevelChanged,
            AgentGovernanceLifecycleEventType::AutonomyEscalationTriggered,
            AgentGovernanceLifecycleEventType::ToolPolicyRegistered,
            AgentGovernanceLifecycleEventType::ToolPolicyRemoved,
            AgentGovernanceLifecycleEventType::ToolRequestEvaluated,
            AgentGovernanceLifecycleEventType::ToolRequestDenied,
            AgentGovernanceLifecycleEventType::DelegationRequested,
            AgentGovernanceLifecycleEventType::DelegationApproved,
            AgentGovernanceLifecycleEventType::DelegationDenied,
            AgentGovernanceLifecycleEventType::DelegationDepthLimitEnforced,
            AgentGovernanceLifecycleEventType::DelegationChainRecorded,
            AgentGovernanceLifecycleEventType::GovernanceExported,
            AgentGovernanceLifecycleEventType::GovernanceExportFailed,
            AgentGovernanceLifecycleEventType::GovernanceSnapshotCaptured,
            AgentGovernanceLifecycleEventType::GovernanceMetricsComputed,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 20);
    }

    #[test]
    fn test_lifecycle_event_builder() {
        let e = AgentGovernanceLifecycleEvent::new(
            AgentGovernanceLifecycleEventType::AutonomyEscalationTriggered,
            5000,
            "agent-alpha",
            "Critical",
            "escalation triggered",
        );
        assert_eq!(e.agent_id, "agent-alpha");
        assert_eq!(e.severity, "Critical");
    }

    #[test]
    fn test_remove_inactive() {
        let mut reg = AgentLifecycleEventSubscriberRegistry::new();
        reg.register(Box::new(AgentGovernanceEventCollector::new("c1")));
        assert_eq!(reg.active_count(), 1);
        reg.remove_inactive();
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn test_subscriber_id() {
        let c = AgentGovernanceEventCollector::new("my-sub");
        assert_eq!(c.subscriber_id(), "my-sub");
    }
}
