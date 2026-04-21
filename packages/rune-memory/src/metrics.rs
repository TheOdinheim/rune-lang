// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Memory governance metrics. Computes aggregate statistics
// over memory entries, retention compliance, isolation violations,
// and sensitivity distribution. All numeric values stored as String
// for Eq compatibility.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::isolation::IsolationViolation;
use crate::memory::MemoryEntry;
use crate::retention::MemoryRetentionPolicy;

// ── MemoryMetricSnapshot ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryMetricSnapshot {
    pub metric_name: String,
    pub value: String,
    pub labels: HashMap<String, String>,
    pub computed_at: i64,
}

impl MemoryMetricSnapshot {
    pub fn new(
        metric_name: impl Into<String>,
        value: impl Into<String>,
        computed_at: i64,
    ) -> Self {
        Self {
            metric_name: metric_name.into(),
            value: value.into(),
            labels: HashMap::new(),
            computed_at,
        }
    }

    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

// ── MemoryMetrics ─────────────────────────────────────────────────

pub struct MemoryMetrics;

impl MemoryMetrics {
    pub fn new() -> Self {
        Self
    }

    /// Count entries grouped by scope_id.
    pub fn compute_entry_count_by_scope(
        &self,
        entries: &[MemoryEntry],
        now: i64,
    ) -> Vec<MemoryMetricSnapshot> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for entry in entries {
            *counts.entry(&entry.scope_id).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(scope, count)| {
                MemoryMetricSnapshot::new("memory_entry_count", count.to_string(), now)
                    .with_label("scope_id", scope)
            })
            .collect()
    }

    /// Count entries grouped by content type.
    pub fn compute_entry_count_by_type(
        &self,
        entries: &[MemoryEntry],
        now: i64,
    ) -> Vec<MemoryMetricSnapshot> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for entry in entries {
            *counts.entry(entry.content_type.to_string()).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(ct, count)| {
                MemoryMetricSnapshot::new("memory_entry_count_by_type", count.to_string(), now)
                    .with_label("content_type", ct)
            })
            .collect()
    }

    /// Distribution of entries by sensitivity level.
    pub fn compute_sensitivity_distribution(
        &self,
        entries: &[MemoryEntry],
        now: i64,
    ) -> Vec<MemoryMetricSnapshot> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for entry in entries {
            *counts
                .entry(entry.sensitivity_level.to_string())
                .or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(level, count)| {
                MemoryMetricSnapshot::new(
                    "memory_sensitivity_distribution",
                    count.to_string(),
                    now,
                )
                .with_label("sensitivity_level", level)
            })
            .collect()
    }

    /// Average age of entries in seconds (as String).
    pub fn compute_average_entry_age(
        &self,
        entries: &[MemoryEntry],
        now: i64,
    ) -> MemoryMetricSnapshot {
        if entries.is_empty() {
            return MemoryMetricSnapshot::new("memory_average_entry_age_seconds", "0", now);
        }
        let total_age: i64 = entries.iter().map(|e| now - e.created_at).sum();
        let avg = total_age / entries.len() as i64;
        MemoryMetricSnapshot::new("memory_average_entry_age_seconds", avg.to_string(), now)
    }

    /// Fraction of entries that comply with a retention policy (not expired).
    /// Returns a value between "0.0" and "1.0".
    pub fn compute_retention_compliance(
        &self,
        entries: &[MemoryEntry],
        policy: &MemoryRetentionPolicy,
        now: i64,
    ) -> MemoryMetricSnapshot {
        if entries.is_empty() {
            return MemoryMetricSnapshot::new("memory_retention_compliance", "1.0", now)
                .with_label("policy_id", &policy.policy_id);
        }

        let compliant = entries
            .iter()
            .filter(|e| {
                // Entry is compliant if it's not expired by policy age limit
                if let Some(max_age) = policy.max_age_seconds {
                    let age = now - e.created_at;
                    if age >= max_age {
                        return false;
                    }
                }
                // Entry is compliant if it hasn't passed its explicit expiry
                !e.is_expired(now)
            })
            .count();

        let ratio = compliant as f64 / entries.len() as f64;
        // Format to 2 decimal places then store as String
        let value = format!("{ratio:.2}");
        MemoryMetricSnapshot::new("memory_retention_compliance", value, now)
            .with_label("policy_id", &policy.policy_id)
    }

    /// Violation rate: violations per entry (as String ratio).
    pub fn compute_isolation_violation_rate(
        &self,
        violations: &[IsolationViolation],
        total_access_count: usize,
        now: i64,
    ) -> MemoryMetricSnapshot {
        if total_access_count == 0 {
            return MemoryMetricSnapshot::new("memory_isolation_violation_rate", "0.00", now);
        }
        let rate = violations.len() as f64 / total_access_count as f64;
        let value = format!("{rate:.2}");
        MemoryMetricSnapshot::new("memory_isolation_violation_rate", value, now)
    }
}

impl Default for MemoryMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::IsolationViolationType;
    use crate::memory::{MemoryContentType, MemorySensitivity};
    use crate::retention::ExpiryAction;

    fn make_entry(
        id: &str,
        scope: &str,
        ct: MemoryContentType,
        sensitivity: MemorySensitivity,
        created_at: i64,
    ) -> MemoryEntry {
        MemoryEntry::new(id, scope, "content", ct, sensitivity, "agent-1", created_at)
    }

    fn make_violation(id: &str) -> IsolationViolation {
        IsolationViolation::new(
            id, "ib-1", "agent-rogue", "scope-x",
            IsolationViolationType::CrossScopeRead,
            2000, MemorySensitivity::Sensitive,
        )
    }

    #[test]
    fn test_metric_snapshot_construction() {
        let snap = MemoryMetricSnapshot::new("test_metric", "42", 1000);
        assert_eq!(snap.metric_name, "test_metric");
        assert_eq!(snap.value, "42");
        assert_eq!(snap.computed_at, 1000);
        assert!(snap.labels.is_empty());
    }

    #[test]
    fn test_metric_snapshot_with_label() {
        let snap = MemoryMetricSnapshot::new("m", "1", 1000)
            .with_label("scope", "s1")
            .with_label("type", "t1");
        assert_eq!(snap.labels.len(), 2);
        assert_eq!(snap.labels.get("scope"), Some(&"s1".to_string()));
    }

    #[test]
    fn test_entry_count_by_scope() {
        let metrics = MemoryMetrics::new();
        let entries = vec![
            make_entry("e1", "scope-a", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 100),
            make_entry("e2", "scope-a", MemoryContentType::Summary, MemorySensitivity::Public, 200),
            make_entry("e3", "scope-b", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 300),
        ];
        let snapshots = metrics.compute_entry_count_by_scope(&entries, 1000);
        assert_eq!(snapshots.len(), 2);
        let scope_a = snapshots
            .iter()
            .find(|s| s.labels.get("scope_id") == Some(&"scope-a".to_string()))
            .unwrap();
        assert_eq!(scope_a.value, "2");
    }

    #[test]
    fn test_entry_count_by_type() {
        let metrics = MemoryMetrics::new();
        let entries = vec![
            make_entry("e1", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 100),
            make_entry("e2", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 200),
            make_entry("e3", "s", MemoryContentType::Embedding, MemorySensitivity::Public, 300),
        ];
        let snapshots = metrics.compute_entry_count_by_type(&entries, 1000);
        assert_eq!(snapshots.len(), 2);
    }

    #[test]
    fn test_sensitivity_distribution() {
        let metrics = MemoryMetrics::new();
        let entries = vec![
            make_entry("e1", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 100),
            make_entry("e2", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 200),
            make_entry("e3", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Restricted, 300),
        ];
        let snapshots = metrics.compute_sensitivity_distribution(&entries, 1000);
        assert_eq!(snapshots.len(), 2);
        let public = snapshots
            .iter()
            .find(|s| s.labels.get("sensitivity_level") == Some(&"Public".to_string()))
            .unwrap();
        assert_eq!(public.value, "2");
    }

    #[test]
    fn test_average_entry_age() {
        let metrics = MemoryMetrics::new();
        let entries = vec![
            make_entry("e1", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 500),
            make_entry("e2", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 700),
        ];
        // ages: 500, 300 → avg = 400
        let snap = metrics.compute_average_entry_age(&entries, 1000);
        assert_eq!(snap.value, "400");
    }

    #[test]
    fn test_average_entry_age_empty() {
        let metrics = MemoryMetrics::new();
        let snap = metrics.compute_average_entry_age(&[], 1000);
        assert_eq!(snap.value, "0");
    }

    #[test]
    fn test_retention_compliance_all_compliant() {
        let metrics = MemoryMetrics::new();
        let entries = vec![
            make_entry("e1", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 900),
        ];
        let policy = MemoryRetentionPolicy::new("rp-1", "*", ExpiryAction::Delete, 500)
            .with_max_age(86400);
        let snap = metrics.compute_retention_compliance(&entries, &policy, 1000);
        assert_eq!(snap.value, "1.00");
    }

    #[test]
    fn test_retention_compliance_half_expired() {
        let metrics = MemoryMetrics::new();
        let entries = vec![
            make_entry("e1", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 100),
            make_entry("e2", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 900),
        ];
        // max_age=500 → e1 age=900 (expired), e2 age=100 (ok)
        let policy = MemoryRetentionPolicy::new("rp-1", "*", ExpiryAction::Delete, 500)
            .with_max_age(500);
        let snap = metrics.compute_retention_compliance(&entries, &policy, 1000);
        assert_eq!(snap.value, "0.50");
    }

    #[test]
    fn test_retention_compliance_empty() {
        let metrics = MemoryMetrics::new();
        let policy = MemoryRetentionPolicy::new("rp-1", "*", ExpiryAction::Delete, 500);
        let snap = metrics.compute_retention_compliance(&[], &policy, 1000);
        assert_eq!(snap.value, "1.0");
    }

    #[test]
    fn test_isolation_violation_rate() {
        let metrics = MemoryMetrics::new();
        let violations = vec![make_violation("iv-1"), make_violation("iv-2")];
        let snap = metrics.compute_isolation_violation_rate(&violations, 10, 1000);
        assert_eq!(snap.value, "0.20");
    }

    #[test]
    fn test_isolation_violation_rate_zero_accesses() {
        let metrics = MemoryMetrics::new();
        let snap = metrics.compute_isolation_violation_rate(&[], 0, 1000);
        assert_eq!(snap.value, "0.00");
    }

    #[test]
    fn test_isolation_violation_rate_no_violations() {
        let metrics = MemoryMetrics::new();
        let snap = metrics.compute_isolation_violation_rate(&[], 100, 1000);
        assert_eq!(snap.value, "0.00");
    }

    #[test]
    fn test_metrics_default() {
        let _metrics = MemoryMetrics;
    }

    #[test]
    fn test_metric_snapshot_eq() {
        let s1 = MemoryMetricSnapshot::new("m", "1", 1000);
        assert_eq!(s1, s1.clone());
    }

    #[test]
    fn test_entry_count_by_scope_empty() {
        let metrics = MemoryMetrics::new();
        let snapshots = metrics.compute_entry_count_by_scope(&[], 1000);
        assert!(snapshots.is_empty());
    }

    #[test]
    fn test_retention_compliance_explicit_expiry() {
        let metrics = MemoryMetrics::new();
        let entries = vec![
            make_entry("e1", "s", MemoryContentType::ConversationTurn, MemorySensitivity::Public, 500)
                .with_expiry(800),
        ];
        let policy = MemoryRetentionPolicy::new("rp-1", "*", ExpiryAction::Delete, 500);
        let snap = metrics.compute_retention_compliance(&entries, &policy, 1000);
        assert_eq!(snap.value, "0.00");
    }
}
