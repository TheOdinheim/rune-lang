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

    pub fn validate_policies(&self) -> RetentionValidation {
        let mut issues = Vec::new();
        for (i, policy) in self.policies.iter().enumerate() {
            if policy.max_age_seconds <= 0 {
                issues.push(format!("policy '{}' has non-positive max_age_seconds", policy.name));
            }
            if policy.name.is_empty() {
                issues.push(format!("policy at index {i} has empty name"));
            }
            for (j, other) in self.policies.iter().enumerate() {
                if i != j && policy.name == other.name {
                    issues.push(format!("duplicate policy name: '{}'", policy.name));
                    break;
                }
            }
        }
        RetentionValidation {
            policy_count: self.policies.len(),
            issues,
        }
    }

    pub fn dry_run(&self, store: &AuditStore, now: i64) -> RetentionPreview {
        let mut affected_sources = std::collections::HashMap::new();
        let mut total_affected = 0usize;
        for policy in &self.policies {
            let cutoff = now - policy.max_age_seconds;
            for event in store.all_events() {
                if event.timestamp < cutoff
                    && policy.scope.matches(event)
                    && event.severity < SecuritySeverity::Critical
                {
                    *affected_sources.entry(event.source.to_string()).or_insert(0usize) += 1;
                    total_affected += 1;
                }
            }
        }
        let space_to_free_estimate = total_affected * 256;
        RetentionPreview {
            total_affected,
            affected_sources,
            space_to_free_estimate,
        }
    }

    pub fn apply_with_archive(&self, store: &mut AuditStore, now: i64) -> Vec<ArchiveResult> {
        let mut results = Vec::new();
        for policy in &self.policies {
            let cutoff = now - policy.max_age_seconds;
            match policy.action {
                RetentionAction::Archive => {
                    let archived = store.archive_where(|e| {
                        e.timestamp < cutoff && policy.scope.matches(e)
                    });
                    results.push(ArchiveResult {
                        policy_name: policy.name.clone(),
                        action: policy.action,
                        events_archived: archived,
                        events_deleted: 0,
                    });
                }
                RetentionAction::Delete => {
                    let removed = store.remove_where(|e| {
                        e.timestamp < cutoff && policy.scope.matches(e)
                    });
                    results.push(ArchiveResult {
                        policy_name: policy.name.clone(),
                        action: policy.action,
                        events_archived: 0,
                        events_deleted: removed,
                    });
                }
                RetentionAction::Anonymize => {
                    results.push(ArchiveResult {
                        policy_name: policy.name.clone(),
                        action: policy.action,
                        events_archived: 0,
                        events_deleted: 0,
                    });
                }
            }
        }
        results
    }
}

impl Default for RetentionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── RetentionValidation ────────────────────────────────────────────

#[derive(Debug)]
pub struct RetentionValidation {
    pub policy_count: usize,
    pub issues: Vec<String>,
}

impl RetentionValidation {
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }
}

// ── RetentionPreview ───────────────────────────────────────────────

#[derive(Debug)]
pub struct RetentionPreview {
    pub total_affected: usize,
    pub affected_sources: std::collections::HashMap<String, usize>,
    pub space_to_free_estimate: usize,
}

// ── ArchiveResult ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct ArchiveResult {
    pub policy_name: String,
    pub action: RetentionAction,
    pub events_archived: usize,
    pub events_deleted: usize,
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

    // ── Layer 2 retention tests ────────────────────────────────────

    #[test]
    fn test_validate_policies_valid() {
        let mut mgr = RetentionManager::new();
        mgr.add_policy(default_retention_policy());
        let validation = mgr.validate_policies();
        assert!(validation.is_valid());
        assert_eq!(validation.policy_count, 1);
    }

    #[test]
    fn test_validate_policies_duplicate_name() {
        let mut mgr = RetentionManager::new();
        mgr.add_policy(AuditRetentionPolicy::new("dup", RetentionScope::All, 1000, RetentionAction::Delete));
        mgr.add_policy(AuditRetentionPolicy::new("dup", RetentionScope::All, 2000, RetentionAction::Delete));
        let validation = mgr.validate_policies();
        assert!(!validation.is_valid());
        assert!(!validation.issues.is_empty());
    }

    #[test]
    fn test_validate_policies_non_positive_age() {
        let mut mgr = RetentionManager::new();
        mgr.add_policy(AuditRetentionPolicy::new("bad", RetentionScope::All, 0, RetentionAction::Delete));
        let validation = mgr.validate_policies();
        assert!(!validation.is_valid());
    }

    #[test]
    fn test_dry_run_preview() {
        let store = store_with_ages();
        let mut mgr = RetentionManager::new();
        mgr.add_policy(AuditRetentionPolicy::new("test", RetentionScope::All, 1000, RetentionAction::Delete));
        let preview = mgr.dry_run(&store, 10000);
        assert_eq!(preview.total_affected, 1); // old-info
        assert!(preview.space_to_free_estimate > 0);
        assert!(!preview.affected_sources.is_empty());
    }

    #[test]
    fn test_apply_with_archive() {
        let mut store = store_with_ages();
        let mut mgr = RetentionManager::new();
        mgr.add_policy(AuditRetentionPolicy::new(
            "archive-old",
            RetentionScope::All,
            1000,
            RetentionAction::Archive,
        ));
        let results = mgr.apply_with_archive(&mut store, 10000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].events_archived, 1); // old-info archived
        assert_eq!(store.archived_count(), 1);
        assert_eq!(store.count(), 2); // old-critical + recent
    }

    #[test]
    fn test_apply_with_archive_delete_action() {
        let mut store = store_with_ages();
        let mut mgr = RetentionManager::new();
        mgr.add_policy(AuditRetentionPolicy::new(
            "delete-old",
            RetentionScope::All,
            1000,
            RetentionAction::Delete,
        ));
        let results = mgr.apply_with_archive(&mut store, 10000);
        assert_eq!(results[0].events_deleted, 1);
        assert_eq!(results[0].events_archived, 0);
        assert_eq!(store.archived_count(), 0);
    }

    #[test]
    fn test_retention_preview_struct() {
        let preview = RetentionPreview {
            total_affected: 5,
            affected_sources: std::collections::HashMap::new(),
            space_to_free_estimate: 1280,
        };
        assert_eq!(preview.total_affected, 5);
        assert_eq!(preview.space_to_free_estimate, 1280);
    }
}
