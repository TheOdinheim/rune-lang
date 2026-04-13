// ═══════════════════════════════════════════════════════════════════════
// Event — Unified event type for cross-crate audit correlation.
//
// UnifiedEvent normalizes audit events from all RUNE crates into a
// single schema. SourceCrate identifies the origin, EventCategory
// classifies the action, and EventOutcome captures the result.
// All fields are strings so this crate does not depend on every
// other crate in the ecosystem.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use rune_security::SecuritySeverity;

// ── UnifiedEventId ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnifiedEventId(pub String);

impl UnifiedEventId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for UnifiedEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── SourceCrate ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceCrate {
    RuneLang,
    RunePermissions,
    RuneSecrets,
    RuneIdentity,
    RunePrivacy,
    RuneSecurity,
    RuneDetection,
    RuneShield,
    RuneMonitoring,
    RuneProvenance,
    RuneTruth,
    RuneExplainability,
    RuneDocument,
    RuneAuditExt,
}

impl fmt::Display for SourceCrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RuneLang => "rune-lang",
            Self::RunePermissions => "rune-permissions",
            Self::RuneSecrets => "rune-secrets",
            Self::RuneIdentity => "rune-identity",
            Self::RunePrivacy => "rune-privacy",
            Self::RuneSecurity => "rune-security",
            Self::RuneDetection => "rune-detection",
            Self::RuneShield => "rune-shield",
            Self::RuneMonitoring => "rune-monitoring",
            Self::RuneProvenance => "rune-provenance",
            Self::RuneTruth => "rune-truth",
            Self::RuneExplainability => "rune-explainability",
            Self::RuneDocument => "rune-document",
            Self::RuneAuditExt => "rune-audit-ext",
        };
        f.write_str(s)
    }
}

// ── EventCategory ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    PolicyEnforcement,
    ThreatDetection,
    ThreatResponse,
    Compliance,
    Privacy,
    Integrity,
    Availability,
    Configuration,
    Lifecycle,
    Audit,
}

impl fmt::Display for EventCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::DataAccess => "data-access",
            Self::DataModification => "data-modification",
            Self::PolicyEnforcement => "policy-enforcement",
            Self::ThreatDetection => "threat-detection",
            Self::ThreatResponse => "threat-response",
            Self::Compliance => "compliance",
            Self::Privacy => "privacy",
            Self::Integrity => "integrity",
            Self::Availability => "availability",
            Self::Configuration => "configuration",
            Self::Lifecycle => "lifecycle",
            Self::Audit => "audit",
        };
        f.write_str(s)
    }
}

// ── EventOutcome ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventOutcome {
    Success,
    Failure,
    Denied,
    Error,
    Timeout,
    Partial,
    Unknown,
}

impl fmt::Display for EventOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

// ── UnifiedEvent ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedEvent {
    pub id: UnifiedEventId,
    pub timestamp: i64,
    pub source: SourceCrate,
    pub category: EventCategory,
    pub severity: SecuritySeverity,
    pub outcome: EventOutcome,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub detail: String,
    pub correlation_id: Option<String>,
    pub parent_event_id: Option<String>,
    pub tags: Vec<String>,
    pub metadata: std::collections::HashMap<String, String>,
}

// ── UnifiedEventBuilder ─────────────────────────────────────────────

pub struct UnifiedEventBuilder {
    id: String,
    timestamp: i64,
    source: SourceCrate,
    category: EventCategory,
    severity: SecuritySeverity,
    outcome: EventOutcome,
    actor: String,
    action: String,
    subject: String,
    detail: String,
    correlation_id: Option<String>,
    parent_event_id: Option<String>,
    tags: Vec<String>,
    metadata: std::collections::HashMap<String, String>,
}

impl UnifiedEventBuilder {
    pub fn new(
        id: impl Into<String>,
        source: SourceCrate,
        category: EventCategory,
        action: impl Into<String>,
        timestamp: i64,
    ) -> Self {
        Self {
            id: id.into(),
            timestamp,
            source,
            category,
            severity: SecuritySeverity::Info,
            outcome: EventOutcome::Success,
            actor: String::new(),
            action: action.into(),
            subject: String::new(),
            detail: String::new(),
            correlation_id: None,
            parent_event_id: None,
            tags: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn severity(mut self, severity: SecuritySeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn outcome(mut self, outcome: EventOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    pub fn parent_event_id(mut self, id: impl Into<String>) -> Self {
        self.parent_event_id = Some(id.into());
        self
    }

    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> UnifiedEvent {
        UnifiedEvent {
            id: UnifiedEventId::new(self.id),
            timestamp: self.timestamp,
            source: self.source,
            category: self.category,
            severity: self.severity,
            outcome: self.outcome,
            actor: self.actor,
            action: self.action,
            subject: self.subject,
            detail: self.detail,
            correlation_id: self.correlation_id,
            parent_event_id: self.parent_event_id,
            tags: self.tags,
            metadata: self.metadata,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_event_id_display() {
        let id = UnifiedEventId::new("evt-001");
        assert_eq!(id.to_string(), "evt-001");
    }

    #[test]
    fn test_source_crate_display() {
        assert_eq!(SourceCrate::RuneLang.to_string(), "rune-lang");
        assert_eq!(SourceCrate::RuneAuditExt.to_string(), "rune-audit-ext");
        assert_eq!(SourceCrate::RuneDetection.to_string(), "rune-detection");
    }

    #[test]
    fn test_all_14_source_crates() {
        let crates = [
            SourceCrate::RuneLang,
            SourceCrate::RunePermissions,
            SourceCrate::RuneSecrets,
            SourceCrate::RuneIdentity,
            SourceCrate::RunePrivacy,
            SourceCrate::RuneSecurity,
            SourceCrate::RuneDetection,
            SourceCrate::RuneShield,
            SourceCrate::RuneMonitoring,
            SourceCrate::RuneProvenance,
            SourceCrate::RuneTruth,
            SourceCrate::RuneExplainability,
            SourceCrate::RuneDocument,
            SourceCrate::RuneAuditExt,
        ];
        assert_eq!(crates.len(), 14);
        for c in &crates {
            assert!(!c.to_string().is_empty());
        }
    }

    #[test]
    fn test_all_14_event_categories() {
        let cats = [
            EventCategory::Authentication,
            EventCategory::Authorization,
            EventCategory::DataAccess,
            EventCategory::DataModification,
            EventCategory::PolicyEnforcement,
            EventCategory::ThreatDetection,
            EventCategory::ThreatResponse,
            EventCategory::Compliance,
            EventCategory::Privacy,
            EventCategory::Integrity,
            EventCategory::Availability,
            EventCategory::Configuration,
            EventCategory::Lifecycle,
            EventCategory::Audit,
        ];
        assert_eq!(cats.len(), 14);
        for c in &cats {
            assert!(!c.to_string().is_empty());
        }
    }

    #[test]
    fn test_all_7_event_outcomes() {
        let outcomes = [
            EventOutcome::Success,
            EventOutcome::Failure,
            EventOutcome::Denied,
            EventOutcome::Error,
            EventOutcome::Timeout,
            EventOutcome::Partial,
            EventOutcome::Unknown,
        ];
        assert_eq!(outcomes.len(), 7);
        for o in &outcomes {
            assert!(!o.to_string().is_empty());
        }
    }

    #[test]
    fn test_builder_defaults() {
        let evt = UnifiedEventBuilder::new(
            "e1",
            SourceCrate::RuneSecurity,
            EventCategory::ThreatDetection,
            "scan",
            1000,
        )
        .build();
        assert_eq!(evt.id, UnifiedEventId::new("e1"));
        assert_eq!(evt.severity, SecuritySeverity::Info);
        assert_eq!(evt.outcome, EventOutcome::Success);
        assert!(evt.actor.is_empty());
        assert!(evt.tags.is_empty());
        assert!(evt.metadata.is_empty());
    }

    #[test]
    fn test_builder_full() {
        let evt = UnifiedEventBuilder::new(
            "e2",
            SourceCrate::RuneIdentity,
            EventCategory::Authentication,
            "login",
            2000,
        )
        .severity(SecuritySeverity::Medium)
        .outcome(EventOutcome::Denied)
        .actor("alice")
        .subject("session-42")
        .detail("bad password")
        .correlation_id("corr-1")
        .parent_event_id("e1")
        .tag("auth")
        .tag("failed")
        .meta("ip", "10.0.0.1")
        .build();

        assert_eq!(evt.severity, SecuritySeverity::Medium);
        assert_eq!(evt.outcome, EventOutcome::Denied);
        assert_eq!(evt.actor, "alice");
        assert_eq!(evt.subject, "session-42");
        assert_eq!(evt.correlation_id, Some("corr-1".into()));
        assert_eq!(evt.parent_event_id, Some("e1".into()));
        assert_eq!(evt.tags.len(), 2);
        assert_eq!(evt.metadata.get("ip").unwrap(), "10.0.0.1");
    }

    #[test]
    fn test_unified_event_id_equality() {
        let a = UnifiedEventId::new("x");
        let b = UnifiedEventId::new("x");
        let c = UnifiedEventId::new("y");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_source_crate_eq_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SourceCrate::RuneLang);
        set.insert(SourceCrate::RuneLang);
        assert_eq!(set.len(), 1);
    }
}
