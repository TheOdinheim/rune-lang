// ═══════════════════════════════════════════════════════════════════════
// Secret Audit — Event Logging for Secret Operations
//
// Records creation, access, rotation, compromise, and destruction
// events for secrets. Supports filtering, export, and chain integrity.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;
use serde::{Deserialize, Serialize};

use crate::secret::SecretId;

// ── Event types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretEventType {
    Created,
    Accessed,
    Updated,
    Rotated,
    Shared,
    Compromised,
    Destroyed,
    ExportAttempt,
    AccessDenied,
    ClassificationChanged,
    KeyRotated,
    SecretExpired,
    Zeroized,
    KeyDerived,
    DecryptionFailed,
    ShamirReconstructed,
}

impl fmt::Display for SecretEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SecretEvent ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEvent {
    pub event_type: SecretEventType,
    pub secret_id: SecretId,
    pub timestamp: i64,
    pub actor: String,
    pub detail: String,
}

impl SecretEvent {
    pub fn new(
        event_type: SecretEventType,
        secret_id: SecretId,
        timestamp: i64,
        actor: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            secret_id,
            timestamp,
            actor: actor.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for SecretEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {} by {}: {}",
            self.timestamp, self.event_type, self.secret_id, self.actor, self.detail
        )
    }
}

// ── SecretAuditLog ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SecretAuditLog {
    events: Vec<SecretEvent>,
}

impl SecretAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, event: SecretEvent) {
        self.events.push(event);
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn all(&self) -> &[SecretEvent] {
        &self.events
    }

    /// Events for a specific secret.
    pub fn for_secret(&self, id: &SecretId) -> Vec<&SecretEvent> {
        self.events.iter().filter(|e| &e.secret_id == id).collect()
    }

    /// Events of a specific type.
    pub fn by_type(&self, event_type: &SecretEventType) -> Vec<&SecretEvent> {
        self.events.iter().filter(|e| &e.event_type == event_type).collect()
    }

    /// Events since a given timestamp.
    pub fn since(&self, timestamp: i64) -> Vec<&SecretEvent> {
        self.events.iter().filter(|e| e.timestamp >= timestamp).collect()
    }

    /// Events by a specific actor.
    pub fn by_actor(&self, actor: &str) -> Vec<&SecretEvent> {
        self.events.iter().filter(|e| e.actor == actor).collect()
    }

    /// Count of access-denied events (security metric).
    pub fn denied_count(&self) -> usize {
        self.events.iter().filter(|e| e.event_type == SecretEventType::AccessDenied).count()
    }

    /// Count of compromise events (critical security metric).
    pub fn compromise_count(&self) -> usize {
        self.events.iter().filter(|e| e.event_type == SecretEventType::Compromised).count()
    }

    /// Export events as JSON lines.
    pub fn to_json_lines(&self) -> String {
        self.events
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(etype: SecretEventType, id: &str, ts: i64, actor: &str) -> SecretEvent {
        SecretEvent::new(etype, SecretId::new(id), ts, actor, "test")
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(SecretEventType::Created.to_string(), "Created");
        assert_eq!(SecretEventType::Compromised.to_string(), "Compromised");
        assert_eq!(SecretEventType::AccessDenied.to_string(), "AccessDenied");
    }

    #[test]
    fn test_event_display() {
        let e = make_event(SecretEventType::Accessed, "k1", 100, "alice");
        let s = e.to_string();
        assert!(s.contains("100"));
        assert!(s.contains("Accessed"));
        assert!(s.contains("k1"));
        assert!(s.contains("alice"));
    }

    #[test]
    fn test_audit_log_new_empty() {
        let log = SecretAuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_audit_log_record() {
        let mut log = SecretAuditLog::new();
        log.record(make_event(SecretEventType::Created, "k1", 1, "admin"));
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn test_audit_log_for_secret() {
        let mut log = SecretAuditLog::new();
        log.record(make_event(SecretEventType::Created, "k1", 1, "admin"));
        log.record(make_event(SecretEventType::Created, "k2", 2, "admin"));
        log.record(make_event(SecretEventType::Accessed, "k1", 3, "user"));
        let k1_events = log.for_secret(&SecretId::new("k1"));
        assert_eq!(k1_events.len(), 2);
    }

    #[test]
    fn test_audit_log_by_type() {
        let mut log = SecretAuditLog::new();
        log.record(make_event(SecretEventType::Created, "k1", 1, "admin"));
        log.record(make_event(SecretEventType::Accessed, "k1", 2, "user"));
        log.record(make_event(SecretEventType::Accessed, "k2", 3, "user"));
        let accessed = log.by_type(&SecretEventType::Accessed);
        assert_eq!(accessed.len(), 2);
    }

    #[test]
    fn test_audit_log_since() {
        let mut log = SecretAuditLog::new();
        log.record(make_event(SecretEventType::Created, "k1", 10, "a"));
        log.record(make_event(SecretEventType::Accessed, "k1", 20, "b"));
        log.record(make_event(SecretEventType::Rotated, "k1", 30, "c"));
        assert_eq!(log.since(20).len(), 2);
        assert_eq!(log.since(30).len(), 1);
    }

    #[test]
    fn test_audit_log_by_actor() {
        let mut log = SecretAuditLog::new();
        log.record(make_event(SecretEventType::Created, "k1", 1, "alice"));
        log.record(make_event(SecretEventType::Created, "k2", 2, "bob"));
        log.record(make_event(SecretEventType::Accessed, "k1", 3, "alice"));
        assert_eq!(log.by_actor("alice").len(), 2);
        assert_eq!(log.by_actor("bob").len(), 1);
    }

    #[test]
    fn test_audit_log_denied_count() {
        let mut log = SecretAuditLog::new();
        log.record(make_event(SecretEventType::Accessed, "k1", 1, "user"));
        log.record(make_event(SecretEventType::AccessDenied, "k1", 2, "attacker"));
        log.record(make_event(SecretEventType::AccessDenied, "k2", 3, "attacker"));
        assert_eq!(log.denied_count(), 2);
    }

    #[test]
    fn test_audit_log_compromise_count() {
        let mut log = SecretAuditLog::new();
        log.record(make_event(SecretEventType::Compromised, "k1", 1, "sys"));
        assert_eq!(log.compromise_count(), 1);
    }

    #[test]
    fn test_audit_log_to_json_lines() {
        let mut log = SecretAuditLog::new();
        log.record(make_event(SecretEventType::Created, "k1", 1, "admin"));
        log.record(make_event(SecretEventType::Accessed, "k1", 2, "user"));
        let json = log.to_json_lines();
        let lines: Vec<&str> = json.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Created"));
        assert!(lines[1].contains("Accessed"));
    }

    #[test]
    fn test_audit_log_all() {
        let mut log = SecretAuditLog::new();
        log.record(make_event(SecretEventType::Created, "k1", 1, "admin"));
        assert_eq!(log.all().len(), 1);
    }
}
