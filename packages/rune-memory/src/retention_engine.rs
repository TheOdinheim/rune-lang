// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Retention policy enforcement engine. Evaluates
// MemoryRetentionPolicy against MemoryEntry instances, scanning for
// expired entries, applying count limits, and enforcing sensitivity-
// based shorter retention.
// ═══════════════════════════════════════════════════════════════════════

use crate::memory::{MemoryEntry, MemorySensitivity};
use crate::retention::MemoryRetentionPolicy;

// ── RetentionOutcome ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionOutcome {
    Retain,
    Expire,
    Redact,
    Archive,
    Summarize,
}

impl std::fmt::Display for RetentionOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Retain => "Retain",
            Self::Expire => "Expire",
            Self::Redact => "Redact",
            Self::Archive => "Archive",
            Self::Summarize => "Summarize",
        };
        f.write_str(s)
    }
}

// ── RetentionEvaluation ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetentionEvaluation {
    pub entry_id: String,
    pub outcome: RetentionOutcome,
    pub reason: String,
    pub policy_id: String,
    pub evaluated_at: i64,
    pub remaining_seconds: Option<i64>,
}

impl RetentionEvaluation {
    pub fn new(
        entry_id: impl Into<String>,
        outcome: RetentionOutcome,
        reason: impl Into<String>,
        policy_id: impl Into<String>,
        evaluated_at: i64,
    ) -> Self {
        Self {
            entry_id: entry_id.into(),
            outcome,
            reason: reason.into(),
            policy_id: policy_id.into(),
            evaluated_at,
            remaining_seconds: None,
        }
    }

    pub fn with_remaining(mut self, seconds: i64) -> Self {
        self.remaining_seconds = Some(seconds);
        self
    }
}

// ── MemoryRetentionEngine ─────────────────────────────────────────

pub struct MemoryRetentionEngine;

impl MemoryRetentionEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a single entry against a retention policy at the given timestamp.
    pub fn evaluate_entry(
        &self,
        entry: &MemoryEntry,
        policy: &MemoryRetentionPolicy,
        now: i64,
    ) -> RetentionEvaluation {
        // Check explicit expiry first
        if entry.is_expired(now) {
            return RetentionEvaluation::new(
                &entry.entry_id,
                outcome_from_expiry_action(&policy.on_expiry),
                "entry has reached its explicit expiry time",
                &policy.policy_id,
                now,
            );
        }

        // Check max age
        if let Some(max_age) = policy.max_age_seconds {
            let age = now - entry.created_at;
            if age >= max_age {
                return RetentionEvaluation::new(
                    &entry.entry_id,
                    outcome_from_expiry_action(&policy.on_expiry),
                    format!("entry age {age}s exceeds max_age {max_age}s"),
                    &policy.policy_id,
                    now,
                );
            }
            let remaining = max_age - age;
            return RetentionEvaluation::new(
                &entry.entry_id,
                RetentionOutcome::Retain,
                format!("{remaining}s remaining before max_age"),
                &policy.policy_id,
                now,
            )
            .with_remaining(remaining);
        }

        // Check sensitivity threshold for shorter retention
        if let Some(ref threshold) = policy.sensitivity_threshold
            && entry.sensitivity_level >= *threshold
        {
            return RetentionEvaluation::new(
                &entry.entry_id,
                RetentionOutcome::Redact,
                format!(
                    "sensitivity {} meets/exceeds threshold {}",
                    entry.sensitivity_level, threshold
                ),
                &policy.policy_id,
                now,
            );
        }

        RetentionEvaluation::new(
            &entry.entry_id,
            RetentionOutcome::Retain,
            "entry passes all retention checks",
            &policy.policy_id,
            now,
        )
    }

    /// Scan entries and return IDs that should expire based on age and count limits.
    pub fn scan_for_expired(
        &self,
        entries: &[MemoryEntry],
        policy: &MemoryRetentionPolicy,
        now: i64,
    ) -> Vec<String> {
        let mut expired_ids = Vec::new();

        for entry in entries {
            // Explicit expiry
            if entry.is_expired(now) {
                expired_ids.push(entry.entry_id.clone());
                continue;
            }
            // Max age
            if let Some(max_age) = policy.max_age_seconds {
                let age = now - entry.created_at;
                if age >= max_age {
                    expired_ids.push(entry.entry_id.clone());
                    continue;
                }
            }
        }

        // Count limit — oldest entries first
        if let Some(max_entries) = policy.max_entries {
            let non_expired: Vec<&MemoryEntry> = entries
                .iter()
                .filter(|e| !expired_ids.contains(&e.entry_id))
                .collect();
            if non_expired.len() > max_entries {
                let excess = non_expired.len() - max_entries;
                let mut sorted: Vec<&MemoryEntry> = non_expired;
                sorted.sort_by_key(|e| e.created_at);
                for e in sorted.iter().take(excess) {
                    expired_ids.push(e.entry_id.clone());
                }
            }
        }

        expired_ids
    }

    /// Given entries sorted by created_at, return entry IDs that exceed max_entries.
    pub fn apply_count_limit(
        &self,
        entries: &[MemoryEntry],
        max_entries: usize,
    ) -> Vec<String> {
        if entries.len() <= max_entries {
            return Vec::new();
        }
        let mut sorted: Vec<&MemoryEntry> = entries.iter().collect();
        sorted.sort_by_key(|e| e.created_at);
        let excess = sorted.len() - max_entries;
        sorted.iter().take(excess).map(|e| e.entry_id.clone()).collect()
    }

    /// Check whether an entry's sensitivity meets or exceeds the policy threshold.
    pub fn evaluate_sensitivity_threshold(
        &self,
        entry: &MemoryEntry,
        threshold: &MemorySensitivity,
    ) -> bool {
        entry.sensitivity_level >= *threshold
    }
}

impl Default for MemoryRetentionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── helpers ───────────────────────────────────────────────────────

fn outcome_from_expiry_action(action: &crate::retention::ExpiryAction) -> RetentionOutcome {
    match action {
        crate::retention::ExpiryAction::Delete => RetentionOutcome::Expire,
        crate::retention::ExpiryAction::Archive => RetentionOutcome::Archive,
        crate::retention::ExpiryAction::Redact => RetentionOutcome::Redact,
        crate::retention::ExpiryAction::Summarize => RetentionOutcome::Summarize,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryContentType;
    use crate::retention::ExpiryAction;

    fn make_entry(id: &str, created_at: i64, sensitivity: MemorySensitivity) -> MemoryEntry {
        MemoryEntry::new(
            id, "scope-1", "content",
            MemoryContentType::ConversationTurn,
            sensitivity, "agent-1", created_at,
        )
    }

    fn make_policy() -> MemoryRetentionPolicy {
        MemoryRetentionPolicy::new("rp-1", "scope-*", ExpiryAction::Delete, 1000)
    }

    #[test]
    fn test_retention_outcome_display() {
        let outcomes = vec![
            RetentionOutcome::Retain,
            RetentionOutcome::Expire,
            RetentionOutcome::Redact,
            RetentionOutcome::Archive,
            RetentionOutcome::Summarize,
        ];
        for o in &outcomes {
            assert!(!o.to_string().is_empty());
        }
        assert_eq!(outcomes.len(), 5);
    }

    #[test]
    fn test_evaluation_construction() {
        let eval = RetentionEvaluation::new(
            "e1", RetentionOutcome::Retain, "ok", "rp-1", 5000,
        );
        assert_eq!(eval.entry_id, "e1");
        assert_eq!(eval.outcome, RetentionOutcome::Retain);
        assert!(eval.remaining_seconds.is_none());
    }

    #[test]
    fn test_evaluation_with_remaining() {
        let eval = RetentionEvaluation::new(
            "e1", RetentionOutcome::Retain, "ok", "rp-1", 5000,
        )
        .with_remaining(3600);
        assert_eq!(eval.remaining_seconds, Some(3600));
    }

    #[test]
    fn test_evaluate_entry_retains_fresh() {
        let engine = MemoryRetentionEngine::new();
        let entry = make_entry("e1", 1000, MemorySensitivity::Public);
        let policy = make_policy().with_max_age(86400);
        let eval = engine.evaluate_entry(&entry, &policy, 2000);
        assert_eq!(eval.outcome, RetentionOutcome::Retain);
        assert_eq!(eval.remaining_seconds, Some(85400));
    }

    #[test]
    fn test_evaluate_entry_expires_old() {
        let engine = MemoryRetentionEngine::new();
        let entry = make_entry("e1", 1000, MemorySensitivity::Public);
        let policy = make_policy().with_max_age(3600);
        let eval = engine.evaluate_entry(&entry, &policy, 5000);
        assert_eq!(eval.outcome, RetentionOutcome::Expire);
    }

    #[test]
    fn test_evaluate_entry_explicit_expiry() {
        let engine = MemoryRetentionEngine::new();
        let entry = make_entry("e1", 1000, MemorySensitivity::Public).with_expiry(3000);
        let policy = make_policy();
        let eval = engine.evaluate_entry(&entry, &policy, 4000);
        assert_eq!(eval.outcome, RetentionOutcome::Expire);
    }

    #[test]
    fn test_evaluate_entry_archive_action() {
        let engine = MemoryRetentionEngine::new();
        let entry = make_entry("e1", 1000, MemorySensitivity::Public).with_expiry(2000);
        let policy = MemoryRetentionPolicy::new("rp-1", "*", ExpiryAction::Archive, 1000);
        let eval = engine.evaluate_entry(&entry, &policy, 3000);
        assert_eq!(eval.outcome, RetentionOutcome::Archive);
    }

    #[test]
    fn test_evaluate_entry_sensitivity_threshold() {
        let engine = MemoryRetentionEngine::new();
        let entry = make_entry("e1", 1000, MemorySensitivity::Restricted);
        let policy = make_policy().with_sensitivity_threshold(MemorySensitivity::Sensitive);
        let eval = engine.evaluate_entry(&entry, &policy, 2000);
        assert_eq!(eval.outcome, RetentionOutcome::Redact);
    }

    #[test]
    fn test_evaluate_entry_sensitivity_below_threshold() {
        let engine = MemoryRetentionEngine::new();
        let entry = make_entry("e1", 1000, MemorySensitivity::Public);
        let policy = make_policy().with_sensitivity_threshold(MemorySensitivity::Sensitive);
        let eval = engine.evaluate_entry(&entry, &policy, 2000);
        assert_eq!(eval.outcome, RetentionOutcome::Retain);
    }

    #[test]
    fn test_scan_for_expired_by_age() {
        let engine = MemoryRetentionEngine::new();
        let entries = vec![
            make_entry("e1", 100, MemorySensitivity::Public),
            make_entry("e2", 500, MemorySensitivity::Public),
            make_entry("e3", 900, MemorySensitivity::Public),
        ];
        let policy = make_policy().with_max_age(500);
        let expired = engine.scan_for_expired(&entries, &policy, 1000);
        assert!(expired.contains(&"e1".to_string()));
        assert!(expired.contains(&"e2".to_string()));
        assert!(!expired.contains(&"e3".to_string()));
    }

    #[test]
    fn test_scan_for_expired_by_count() {
        let engine = MemoryRetentionEngine::new();
        let entries = vec![
            make_entry("e1", 100, MemorySensitivity::Public),
            make_entry("e2", 200, MemorySensitivity::Public),
            make_entry("e3", 300, MemorySensitivity::Public),
            make_entry("e4", 400, MemorySensitivity::Public),
        ];
        let policy = make_policy().with_max_entries(2);
        let expired = engine.scan_for_expired(&entries, &policy, 500);
        assert_eq!(expired.len(), 2);
        assert!(expired.contains(&"e1".to_string()));
        assert!(expired.contains(&"e2".to_string()));
    }

    #[test]
    fn test_scan_for_expired_explicit_expiry() {
        let engine = MemoryRetentionEngine::new();
        let entries = vec![
            make_entry("e1", 100, MemorySensitivity::Public).with_expiry(500),
            make_entry("e2", 200, MemorySensitivity::Public),
        ];
        let policy = make_policy();
        let expired = engine.scan_for_expired(&entries, &policy, 600);
        assert_eq!(expired, vec!["e1".to_string()]);
    }

    #[test]
    fn test_scan_for_expired_none() {
        let engine = MemoryRetentionEngine::new();
        let entries = vec![
            make_entry("e1", 900, MemorySensitivity::Public),
        ];
        let policy = make_policy().with_max_age(86400);
        let expired = engine.scan_for_expired(&entries, &policy, 1000);
        assert!(expired.is_empty());
    }

    #[test]
    fn test_apply_count_limit_no_excess() {
        let engine = MemoryRetentionEngine::new();
        let entries = vec![
            make_entry("e1", 100, MemorySensitivity::Public),
            make_entry("e2", 200, MemorySensitivity::Public),
        ];
        let removed = engine.apply_count_limit(&entries, 5);
        assert!(removed.is_empty());
    }

    #[test]
    fn test_apply_count_limit_removes_oldest() {
        let engine = MemoryRetentionEngine::new();
        let entries = vec![
            make_entry("e3", 300, MemorySensitivity::Public),
            make_entry("e1", 100, MemorySensitivity::Public),
            make_entry("e2", 200, MemorySensitivity::Public),
        ];
        let removed = engine.apply_count_limit(&entries, 1);
        assert_eq!(removed.len(), 2);
        assert!(removed.contains(&"e1".to_string()));
        assert!(removed.contains(&"e2".to_string()));
    }

    #[test]
    fn test_evaluate_sensitivity_threshold_meets() {
        let engine = MemoryRetentionEngine::new();
        let entry = make_entry("e1", 1000, MemorySensitivity::Sensitive);
        assert!(engine.evaluate_sensitivity_threshold(&entry, &MemorySensitivity::Sensitive));
        assert!(engine.evaluate_sensitivity_threshold(&entry, &MemorySensitivity::Internal));
    }

    #[test]
    fn test_evaluate_sensitivity_threshold_below() {
        let engine = MemoryRetentionEngine::new();
        let entry = make_entry("e1", 1000, MemorySensitivity::Public);
        assert!(!engine.evaluate_sensitivity_threshold(&entry, &MemorySensitivity::Sensitive));
    }

    #[test]
    fn test_engine_default() {
        let _engine = MemoryRetentionEngine;
    }

    #[test]
    fn test_evaluate_entry_summarize_action() {
        let engine = MemoryRetentionEngine::new();
        let entry = make_entry("e1", 1000, MemorySensitivity::Public).with_expiry(2000);
        let policy = MemoryRetentionPolicy::new("rp-1", "*", ExpiryAction::Summarize, 1000);
        let eval = engine.evaluate_entry(&entry, &policy, 3000);
        assert_eq!(eval.outcome, RetentionOutcome::Summarize);
    }

    #[test]
    fn test_scan_combined_age_and_count() {
        let engine = MemoryRetentionEngine::new();
        let entries = vec![
            make_entry("e1", 100, MemorySensitivity::Public),
            make_entry("e2", 200, MemorySensitivity::Public),
            make_entry("e3", 800, MemorySensitivity::Public),
            make_entry("e4", 900, MemorySensitivity::Public),
        ];
        // e1 and e2 expire by age, then e3 exceeds count limit of 1
        let policy = make_policy().with_max_age(500).with_max_entries(1);
        let expired = engine.scan_for_expired(&entries, &policy, 1000);
        assert!(expired.contains(&"e1".to_string()));
        assert!(expired.contains(&"e2".to_string()));
        assert!(expired.contains(&"e3".to_string()));
        assert!(!expired.contains(&"e4".to_string()));
    }
}
