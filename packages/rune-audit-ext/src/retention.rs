// ═══════════════════════════════════════════════════════════════════════
// Retention — Policy-based event retention enforcement.
//
// RetentionManager applies retention policies to the audit store.
// Critical and Emergency events are NEVER deleted regardless of policy.
// ═══════════════════════════════════════════════════════════════════════

use rune_security::SecuritySeverity;

use crate::event::*;
use crate::store::AuditStore;

// ── RetentionAction ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionAction {
    Delete,
    Archive,
    Anonymize,
}

// ── RetentionScope ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum RetentionScope {
    All,
    Source(SourceCrate),
    Category(EventCategory),
    SeverityBelow(SecuritySeverity),
}

impl RetentionScope {
    pub fn matches(&self, event: &UnifiedEvent) -> bool {
        match self {
            Self::All => true,
            Self::Source(s) => event.source == *s,
            Self::Category(c) => event.category == *c,
            Self::SeverityBelow(s) => event.severity < *s,
        }
    }
}

// ── AuditRetentionPolicy ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AuditRetentionPolicy {
    pub name: String,
    pub scope: RetentionScope,
    pub max_age_seconds: i64,
    pub action: RetentionAction,
}

impl AuditRetentionPolicy {
    pub fn new(
        name: impl Into<String>,
        scope: RetentionScope,
        max_age_seconds: i64,
        action: RetentionAction,
    ) -> Self {
        Self {
            name: name.into(),
            scope,
            max_age_seconds,
            action,
        }
    }
}

// ── RetentionResult ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct RetentionResult {
    pub policy_name: String,
    pub events_affected: usize,
    pub events_preserved: usize,
    pub action: RetentionAction,
}

// ── RetentionManager ────────────────────────────────────────────────

pub struct RetentionManager {
    policies: Vec<AuditRetentionPolicy>,
}

impl RetentionManager {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn add_policy(&mut self, policy: AuditRetentionPolicy) {
        self.policies.push(policy);
    }

    pub fn policies(&self) -> &[AuditRetentionPolicy] {
        &self.policies
    }

    /// Apply all retention policies. Returns results per policy.
    /// Critical+ events are NEVER deleted.
    pub fn apply(&self, store: &mut AuditStore, now: i64) -> Vec<RetentionResult> {
        let mut results = Vec::new();
        for policy in &self.policies {
            let cutoff = now - policy.max_age_seconds;
            let before = store.count();
            let removed = store.remove_where(|e| {
                e.timestamp < cutoff && policy.scope.matches(e)
            });
            // Critical+ are preserved by store.remove_where
            let preserved = before - store.count();
            let critical_preserved = removed.abs_diff(preserved);
            results.push(RetentionResult {
                policy_name: policy.name.clone(),
                events_affected: removed,
                events_preserved: critical_preserved,
                action: policy.action,
            });
        }
        results
    }

    /// Preview how many events would be affected without modifying the store.
    pub fn preview(&self, store: &AuditStore, now: i64) -> Vec<(String, usize)> {
        let mut previews = Vec::new();
        for policy in &self.policies {
            let cutoff = now - policy.max_age_seconds;
            let count = store
                .all_events()
                .iter()
                .filter(|e| {
                    e.timestamp < cutoff
                        && policy.scope.matches(e)
                        && e.severity < SecuritySeverity::Critical
                })
                .count();
            previews.push((policy.name.clone(), count));
        }
        previews
    }
}

impl Default for RetentionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Built-in policies ───────────────────────────────────────────────

/// 90-day retention for low-severity events.
pub fn default_retention_policy() -> AuditRetentionPolicy {
    AuditRetentionPolicy::new(
        "default-90d",
        RetentionScope::SeverityBelow(SecuritySeverity::Medium),
        90 * 24 * 3600,
        RetentionAction::Delete,
    )
}

/// 7-day retention for info-level events.
pub fn short_retention_policy() -> AuditRetentionPolicy {
    AuditRetentionPolicy::new(
        "short-7d-info",
        RetentionScope::SeverityBelow(SecuritySeverity::Low),
        7 * 24 * 3600,
        RetentionAction::Delete,
    )
}

/// 365-day archive for compliance events.
pub fn compliance_retention_policy() -> AuditRetentionPolicy {
    AuditRetentionPolicy::new(
        "compliance-365d",
        RetentionScope::Category(EventCategory::Compliance),
        365 * 24 * 3600,
        RetentionAction::Archive,
    )
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_ages() -> AuditStore {
        let mut store = AuditStore::new();
        // Old info event (timestamp 100)
        store
            .ingest(
                UnifiedEventBuilder::new("old-info", SourceCrate::RuneMonitoring, EventCategory::Availability, "health", 100)
                    .severity(SecuritySeverity::Info)
                    .build(),
            )
            .unwrap();
        // Old critical event (timestamp 100)
        store
            .ingest(
                UnifiedEventBuilder::new("old-critical", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "breach", 100)
                    .severity(SecuritySeverity::Critical)
                    .build(),
            )
            .unwrap();
        // Recent event (timestamp 9000)
        store
            .ingest(
                UnifiedEventBuilder::new("recent", SourceCrate::RuneIdentity, EventCategory::Authentication, "login", 9000)
                    .severity(SecuritySeverity::Info)
                    .build(),
            )
            .unwrap();
        store
    }

    #[test]
    fn test_apply_deletes_old_non_critical() {
        let mut store = store_with_ages();
        let mut mgr = RetentionManager::new();
        mgr.add_policy(AuditRetentionPolicy::new(
            "test",
            RetentionScope::All,
            1000, // max age 1000s
            RetentionAction::Delete,
        ));
        let results = mgr.apply(&mut store, 10000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].events_affected, 1); // only old-info removed
        assert_eq!(store.count(), 2); // old-critical + recent remain
    }

    #[test]
    fn test_critical_never_deleted() {
        let mut store = store_with_ages();
        let mut mgr = RetentionManager::new();
        mgr.add_policy(AuditRetentionPolicy::new(
            "aggressive",
            RetentionScope::All,
            1, // everything older than 1s
            RetentionAction::Delete,
        ));
        mgr.apply(&mut store, 10000);
        // old-critical must survive
        assert!(store.get(&UnifiedEventId::new("old-critical")).is_some());
    }

    #[test]
    fn test_preview_does_not_modify() {
        let store = store_with_ages();
        let mut mgr = RetentionManager::new();
        mgr.add_policy(AuditRetentionPolicy::new(
            "test",
            RetentionScope::All,
            1000,
            RetentionAction::Delete,
        ));
        let preview = mgr.preview(&store, 10000);
        assert_eq!(preview[0].1, 1); // old-info would be affected
        assert_eq!(store.count(), 3); // no changes
    }

    #[test]
    fn test_scope_source_filter() {
        let mut store = store_with_ages();
        let mut mgr = RetentionManager::new();
        mgr.add_policy(AuditRetentionPolicy::new(
            "monitoring-only",
            RetentionScope::Source(SourceCrate::RuneMonitoring),
            1000,
            RetentionAction::Delete,
        ));
        mgr.apply(&mut store, 10000);
        assert_eq!(store.count(), 2); // old-info (monitoring) removed
    }

    #[test]
    fn test_scope_severity_below() {
        let scope = RetentionScope::SeverityBelow(SecuritySeverity::Medium);
        let info_event = UnifiedEventBuilder::new("x", SourceCrate::RuneLang, EventCategory::Audit, "a", 0)
            .severity(SecuritySeverity::Info)
            .build();
        let high_event = UnifiedEventBuilder::new("y", SourceCrate::RuneLang, EventCategory::Audit, "a", 0)
            .severity(SecuritySeverity::High)
            .build();
        assert!(scope.matches(&info_event));
        assert!(!scope.matches(&high_event));
    }

    #[test]
    fn test_built_in_policies() {
        let p1 = default_retention_policy();
        assert_eq!(p1.max_age_seconds, 90 * 24 * 3600);
        let p2 = short_retention_policy();
        assert_eq!(p2.max_age_seconds, 7 * 24 * 3600);
        let p3 = compliance_retention_policy();
        assert_eq!(p3.max_age_seconds, 365 * 24 * 3600);
    }

    #[test]
    fn test_retention_action_variants() {
        assert_ne!(RetentionAction::Delete, RetentionAction::Archive);
        assert_ne!(RetentionAction::Archive, RetentionAction::Anonymize);
    }

    #[test]
    fn test_multiple_policies() {
        let mut store = store_with_ages();
        let mut mgr = RetentionManager::new();
        mgr.add_policy(AuditRetentionPolicy::new(
            "p1",
            RetentionScope::Source(SourceCrate::RuneMonitoring),
            1000,
            RetentionAction::Delete,
        ));
        mgr.add_policy(AuditRetentionPolicy::new(
            "p2",
            RetentionScope::Source(SourceCrate::RuneIdentity),
            500,
            RetentionAction::Delete,
        ));
        let results = mgr.apply(&mut store, 10000);
        assert_eq!(results.len(), 2);
    }
}
