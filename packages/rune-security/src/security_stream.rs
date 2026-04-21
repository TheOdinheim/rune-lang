// ═══════════════════════════════════════════════════════════════════════
// Security Stream — Event subscriber infrastructure for security
// lifecycle events.
//
// Mirrors the TruthEventSubscriber pattern from rune-truth.
// Subscribers register interest in security lifecycle events and
// receive them via a synchronous callback.  The registry fans out
// each event to all active subscribers.
//
// SecurityLifecycleEventType is an 18-variant enum covering the full
// security lifecycle: vulnerability discovery through remediation,
// incident response, control validation, posture assessment, export,
// and subscriber management.
//
// VulnerabilitySlaViolated and PostureDegradationDetected are
// first-class lifecycle events, not afterthoughts.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::error::SecurityError;

// ── SecurityLifecycleEventType ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityLifecycleEventType {
    VulnerabilityDiscovered,
    VulnerabilityTriaged,
    VulnerabilityRemediated,
    VulnerabilityReopened,
    VulnerabilitySlaViolated,
    IncidentDeclared,
    IncidentStateChanged,
    IncidentClosed,
    ControlValidated,
    ControlStatusChanged,
    FrameworkMappingQueried,
    PostureSnapshotCaptured,
    PostureDegradationDetected,
    ThreatModelRecorded,
    SecurityDataExported,
    SecurityDataExportFailed,
    SubscriberRegistered,
    SubscriberRemoved,
}

impl SecurityLifecycleEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::VulnerabilityDiscovered => "vulnerability_discovered",
            Self::VulnerabilityTriaged => "vulnerability_triaged",
            Self::VulnerabilityRemediated => "vulnerability_remediated",
            Self::VulnerabilityReopened => "vulnerability_reopened",
            Self::VulnerabilitySlaViolated => "vulnerability_sla_violated",
            Self::IncidentDeclared => "incident_declared",
            Self::IncidentStateChanged => "incident_state_changed",
            Self::IncidentClosed => "incident_closed",
            Self::ControlValidated => "control_validated",
            Self::ControlStatusChanged => "control_status_changed",
            Self::FrameworkMappingQueried => "framework_mapping_queried",
            Self::PostureSnapshotCaptured => "posture_snapshot_captured",
            Self::PostureDegradationDetected => "posture_degradation_detected",
            Self::ThreatModelRecorded => "threat_model_recorded",
            Self::SecurityDataExported => "security_data_exported",
            Self::SecurityDataExportFailed => "security_data_export_failed",
            Self::SubscriberRegistered => "subscriber_registered",
            Self::SubscriberRemoved => "subscriber_removed",
        }
    }

    pub fn is_vulnerability_event(&self) -> bool {
        matches!(
            self,
            Self::VulnerabilityDiscovered
                | Self::VulnerabilityTriaged
                | Self::VulnerabilityRemediated
                | Self::VulnerabilityReopened
                | Self::VulnerabilitySlaViolated
        )
    }

    pub fn is_incident_event(&self) -> bool {
        matches!(
            self,
            Self::IncidentDeclared | Self::IncidentStateChanged | Self::IncidentClosed
        )
    }

    pub fn is_control_event(&self) -> bool {
        matches!(
            self,
            Self::ControlValidated | Self::ControlStatusChanged | Self::FrameworkMappingQueried
        )
    }

    pub fn is_posture_event(&self) -> bool {
        matches!(
            self,
            Self::PostureSnapshotCaptured | Self::PostureDegradationDetected
        )
    }

    pub fn is_export_event(&self) -> bool {
        matches!(
            self,
            Self::SecurityDataExported | Self::SecurityDataExportFailed
        )
    }
}

impl fmt::Display for SecurityLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.type_name())
    }
}

// ── SecurityLifecycleEvent ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecurityLifecycleEvent {
    pub event_type: SecurityLifecycleEventType,
    pub timestamp: i64,
    pub description: String,
    pub artifact_ref: Option<String>,
    pub severity: Option<String>,
    pub metadata: Vec<(String, String)>,
}

impl SecurityLifecycleEvent {
    pub fn new(event_type: SecurityLifecycleEventType, timestamp: i64, description: &str) -> Self {
        Self {
            event_type,
            timestamp,
            description: description.to_string(),
            artifact_ref: None,
            severity: None,
            metadata: Vec::new(),
        }
    }

    pub fn with_artifact_ref(mut self, artifact_ref: &str) -> Self {
        self.artifact_ref = Some(artifact_ref.to_string());
        self
    }

    pub fn with_severity(mut self, severity: &str) -> Self {
        self.severity = Some(severity.to_string());
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.push((key.to_string(), value.to_string()));
        self
    }
}

impl fmt::Display for SecurityLifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} @ {}", self.event_type, self.description, self.timestamp)
    }
}

// ── SecurityEventSubscriber trait ────────────────────────────────

pub trait SecurityEventSubscriber {
    fn on_event(&mut self, event: &SecurityLifecycleEvent) -> Result<(), SecurityError>;
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── SecurityEventSubscriberRegistry ──────────────────────────────

pub struct SecurityEventSubscriberRegistry {
    subscribers: Vec<Box<dyn SecurityEventSubscriber>>,
}

impl SecurityEventSubscriberRegistry {
    pub fn new() -> Self {
        Self { subscribers: Vec::new() }
    }

    pub fn register(&mut self, subscriber: Box<dyn SecurityEventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn unregister(&mut self, subscriber_id: &str) -> bool {
        let before = self.subscribers.len();
        self.subscribers.retain(|s| s.subscriber_id() != subscriber_id);
        self.subscribers.len() < before
    }

    pub fn publish(&mut self, event: &SecurityLifecycleEvent) -> Result<(), SecurityError> {
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

impl Default for SecurityEventSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── SecurityEventCollector ───────────────────────────────────────
// A subscriber that collects all events for later inspection.

pub struct SecurityEventCollector {
    id: String,
    events: Vec<SecurityLifecycleEvent>,
}

impl SecurityEventCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: Vec::new(),
        }
    }

    pub fn events(&self) -> &[SecurityLifecycleEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl SecurityEventSubscriber for SecurityEventCollector {
    fn on_event(&mut self, event: &SecurityLifecycleEvent) -> Result<(), SecurityError> {
        self.events.push(event.clone());
        Ok(())
    }

    fn subscriber_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── FilteredSecurityEventSubscriber ──────────────────────────────
// Wraps another subscriber, only forwarding events that match
// severity, event_type, or artifact_ref filters.

pub struct FilteredSecurityEventSubscriber {
    id: String,
    inner: Box<dyn SecurityEventSubscriber>,
    accepted_types: Option<Vec<SecurityLifecycleEventType>>,
    accepted_severities: Option<Vec<String>>,
    accepted_artifact_refs: Option<Vec<String>>,
}

impl FilteredSecurityEventSubscriber {
    pub fn new(id: &str, inner: Box<dyn SecurityEventSubscriber>) -> Self {
        Self {
            id: id.to_string(),
            inner,
            accepted_types: None,
            accepted_severities: None,
            accepted_artifact_refs: None,
        }
    }

    pub fn with_type_filter(mut self, types: Vec<SecurityLifecycleEventType>) -> Self {
        self.accepted_types = Some(types);
        self
    }

    pub fn with_severity_filter(mut self, severities: Vec<String>) -> Self {
        self.accepted_severities = Some(severities);
        self
    }

    pub fn with_artifact_ref_filter(mut self, refs: Vec<String>) -> Self {
        self.accepted_artifact_refs = Some(refs);
        self
    }

    fn matches(&self, event: &SecurityLifecycleEvent) -> bool {
        if let Some(types) = &self.accepted_types
            && !types.contains(&event.event_type)
        {
            return false;
        }
        if let Some(severities) = &self.accepted_severities {
            if let Some(sev) = &event.severity {
                if !severities.contains(sev) {
                    return false;
                }
            } else {
                return false;
            }
        }
        if let Some(refs) = &self.accepted_artifact_refs {
            if let Some(aref) = &event.artifact_ref {
                if !refs.contains(aref) {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

impl SecurityEventSubscriber for FilteredSecurityEventSubscriber {
    fn on_event(&mut self, event: &SecurityLifecycleEvent) -> Result<(), SecurityError> {
        if self.matches(event) {
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

    fn make_event(etype: SecurityLifecycleEventType) -> SecurityLifecycleEvent {
        SecurityLifecycleEvent::new(etype, 1000, "test event")
    }

    #[test]
    fn test_event_type_name() {
        assert_eq!(SecurityLifecycleEventType::VulnerabilityDiscovered.type_name(), "vulnerability_discovered");
        assert_eq!(SecurityLifecycleEventType::PostureDegradationDetected.type_name(), "posture_degradation_detected");
    }

    #[test]
    fn test_event_type_classification() {
        assert!(SecurityLifecycleEventType::VulnerabilityDiscovered.is_vulnerability_event());
        assert!(SecurityLifecycleEventType::VulnerabilitySlaViolated.is_vulnerability_event());
        assert!(!SecurityLifecycleEventType::VulnerabilityDiscovered.is_incident_event());

        assert!(SecurityLifecycleEventType::IncidentDeclared.is_incident_event());
        assert!(SecurityLifecycleEventType::IncidentClosed.is_incident_event());

        assert!(SecurityLifecycleEventType::ControlValidated.is_control_event());
        assert!(SecurityLifecycleEventType::FrameworkMappingQueried.is_control_event());

        assert!(SecurityLifecycleEventType::PostureSnapshotCaptured.is_posture_event());
        assert!(SecurityLifecycleEventType::PostureDegradationDetected.is_posture_event());

        assert!(SecurityLifecycleEventType::SecurityDataExported.is_export_event());
        assert!(SecurityLifecycleEventType::SecurityDataExportFailed.is_export_event());
    }

    #[test]
    fn test_event_display() {
        let e = SecurityLifecycleEvent::new(
            SecurityLifecycleEventType::VulnerabilityDiscovered,
            1000,
            "vuln found",
        );
        let s = e.to_string();
        assert!(s.contains("vulnerability_discovered"));
        assert!(s.contains("1000"));
    }

    #[test]
    fn test_event_builder() {
        let e = SecurityLifecycleEvent::new(
            SecurityLifecycleEventType::IncidentDeclared,
            2000,
            "incident declared",
        )
        .with_artifact_ref("art-1")
        .with_severity("High")
        .with_metadata("source", "scanner");

        assert_eq!(e.artifact_ref.as_deref(), Some("art-1"));
        assert_eq!(e.severity.as_deref(), Some("High"));
        assert_eq!(e.metadata.len(), 1);
    }

    #[test]
    fn test_collector() {
        let mut collector = SecurityEventCollector::new("col-1");
        collector.on_event(&make_event(SecurityLifecycleEventType::VulnerabilityDiscovered)).unwrap();
        collector.on_event(&make_event(SecurityLifecycleEventType::IncidentDeclared)).unwrap();
        assert_eq!(collector.event_count(), 2);
        collector.clear();
        assert_eq!(collector.event_count(), 0);
    }

    #[test]
    fn test_registry_publish() {
        let mut registry = SecurityEventSubscriberRegistry::new();
        registry.register(Box::new(SecurityEventCollector::new("col-1")));
        registry.register(Box::new(SecurityEventCollector::new("col-2")));

        assert_eq!(registry.subscriber_count(), 2);
        assert_eq!(registry.active_subscriber_count(), 2);

        let event = make_event(SecurityLifecycleEventType::VulnerabilityDiscovered);
        registry.publish(&event).unwrap();
    }

    #[test]
    fn test_registry_unregister() {
        let mut registry = SecurityEventSubscriberRegistry::new();
        registry.register(Box::new(SecurityEventCollector::new("col-1")));
        registry.register(Box::new(SecurityEventCollector::new("col-2")));

        assert!(registry.unregister("col-1"));
        assert_eq!(registry.subscriber_count(), 1);
        assert!(!registry.unregister("nonexistent"));
    }

    #[test]
    fn test_filtered_subscriber_by_type() {
        let collector = SecurityEventCollector::new("inner");
        let mut filtered = FilteredSecurityEventSubscriber::new("filter-1", Box::new(collector))
            .with_type_filter(vec![SecurityLifecycleEventType::VulnerabilityDiscovered]);

        // Accepted
        filtered.on_event(&make_event(SecurityLifecycleEventType::VulnerabilityDiscovered)).unwrap();
        // Rejected
        filtered.on_event(&make_event(SecurityLifecycleEventType::IncidentDeclared)).unwrap();

        assert!(filtered.is_active());
        assert_eq!(filtered.subscriber_id(), "filter-1");
    }

    #[test]
    fn test_filtered_subscriber_by_severity() {
        let collector = SecurityEventCollector::new("inner");
        let mut filtered = FilteredSecurityEventSubscriber::new("filter-2", Box::new(collector))
            .with_severity_filter(vec!["High".to_string()]);

        let event_high = SecurityLifecycleEvent::new(
            SecurityLifecycleEventType::VulnerabilityDiscovered, 1000, "test",
        ).with_severity("High");
        let event_low = SecurityLifecycleEvent::new(
            SecurityLifecycleEventType::VulnerabilityDiscovered, 1000, "test",
        ).with_severity("Low");

        filtered.on_event(&event_high).unwrap();
        filtered.on_event(&event_low).unwrap();
    }

    #[test]
    fn test_filtered_subscriber_by_artifact_ref() {
        let collector = SecurityEventCollector::new("inner");
        let mut filtered = FilteredSecurityEventSubscriber::new("filter-3", Box::new(collector))
            .with_artifact_ref_filter(vec!["art-1".to_string()]);

        let event_match = SecurityLifecycleEvent::new(
            SecurityLifecycleEventType::VulnerabilityDiscovered, 1000, "test",
        ).with_artifact_ref("art-1");
        let event_miss = SecurityLifecycleEvent::new(
            SecurityLifecycleEventType::VulnerabilityDiscovered, 1000, "test",
        ).with_artifact_ref("art-2");

        filtered.on_event(&event_match).unwrap();
        filtered.on_event(&event_miss).unwrap();
    }

    #[test]
    fn test_all_event_types_have_names() {
        let types = [
            SecurityLifecycleEventType::VulnerabilityDiscovered,
            SecurityLifecycleEventType::VulnerabilityTriaged,
            SecurityLifecycleEventType::VulnerabilityRemediated,
            SecurityLifecycleEventType::VulnerabilityReopened,
            SecurityLifecycleEventType::VulnerabilitySlaViolated,
            SecurityLifecycleEventType::IncidentDeclared,
            SecurityLifecycleEventType::IncidentStateChanged,
            SecurityLifecycleEventType::IncidentClosed,
            SecurityLifecycleEventType::ControlValidated,
            SecurityLifecycleEventType::ControlStatusChanged,
            SecurityLifecycleEventType::FrameworkMappingQueried,
            SecurityLifecycleEventType::PostureSnapshotCaptured,
            SecurityLifecycleEventType::PostureDegradationDetected,
            SecurityLifecycleEventType::ThreatModelRecorded,
            SecurityLifecycleEventType::SecurityDataExported,
            SecurityLifecycleEventType::SecurityDataExportFailed,
            SecurityLifecycleEventType::SubscriberRegistered,
            SecurityLifecycleEventType::SubscriberRemoved,
        ];
        for t in &types {
            assert!(!t.type_name().is_empty());
            assert!(!t.to_string().is_empty());
        }
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(
            SecurityLifecycleEventType::VulnerabilitySlaViolated.to_string(),
            "vulnerability_sla_violated"
        );
    }

    #[test]
    fn test_registry_default() {
        let registry = SecurityEventSubscriberRegistry::default();
        assert_eq!(registry.subscriber_count(), 0);
    }
}
