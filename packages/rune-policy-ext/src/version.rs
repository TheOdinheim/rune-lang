// ═══════════════════════════════════════════════════════════════════════
// Version — Policy version history, diff, and rollback.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::policy::*;

// ── PolicySnapshot ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub policy_id: ManagedPolicyId,
    pub version: PolicyVersion,
    pub snapshot: ManagedPolicy,
    pub created_at: i64,
    pub created_by: String,
    pub change_summary: String,
}

// ── ChangeType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
    RuleAdded { rule_id: String },
    RuleRemoved { rule_id: String },
    RuleModified { rule_id: String },
    StatusChanged { from: String, to: String },
    VersionBumped,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added => f.write_str("added"),
            Self::Removed => f.write_str("removed"),
            Self::Modified => f.write_str("modified"),
            Self::RuleAdded { rule_id } => write!(f, "rule-added:{rule_id}"),
            Self::RuleRemoved { rule_id } => write!(f, "rule-removed:{rule_id}"),
            Self::RuleModified { rule_id } => write!(f, "rule-modified:{rule_id}"),
            Self::StatusChanged { from, to } => write!(f, "status:{from}→{to}"),
            Self::VersionBumped => f.write_str("version-bumped"),
        }
    }
}

// ── PolicyChange ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyChange {
    pub change_type: ChangeType,
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub detail: String,
}

// ── PolicyDiff ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyDiff {
    pub policy_id: ManagedPolicyId,
    pub from_version: PolicyVersion,
    pub to_version: PolicyVersion,
    pub changes: Vec<PolicyChange>,
    pub summary: String,
}

// ── PolicyVersionHistory ────────────────────────────────────────────

pub struct PolicyVersionHistory {
    pub policy_id: ManagedPolicyId,
    pub snapshots: Vec<PolicySnapshot>,
}

impl PolicyVersionHistory {
    pub fn new(policy_id: ManagedPolicyId) -> Self {
        Self {
            policy_id,
            snapshots: Vec::new(),
        }
    }

    pub fn record_snapshot(
        &mut self,
        policy: &ManagedPolicy,
        changed_by: &str,
        summary: &str,
        now: i64,
    ) {
        self.snapshots.push(PolicySnapshot {
            policy_id: self.policy_id.clone(),
            version: policy.version.clone(),
            snapshot: policy.clone(),
            created_at: now,
            created_by: changed_by.into(),
            change_summary: summary.into(),
        });
    }

    pub fn latest(&self) -> Option<&PolicySnapshot> {
        self.snapshots.last()
    }

    pub fn at_version(&self, version: &PolicyVersion) -> Option<&PolicySnapshot> {
        self.snapshots.iter().find(|s| s.version == *version)
    }

    pub fn diff(&self, from: &PolicyVersion, to: &PolicyVersion) -> Option<PolicyDiff> {
        let from_snap = self.at_version(from)?;
        let to_snap = self.at_version(to)?;
        Some(compute_diff(
            &self.policy_id,
            from,
            to,
            &from_snap.snapshot,
            &to_snap.snapshot,
        ))
    }

    pub fn rollback_to(&self, version: &PolicyVersion) -> Option<ManagedPolicy> {
        self.at_version(version).map(|s| s.snapshot.clone())
    }

    pub fn version_count(&self) -> usize {
        self.snapshots.len()
    }

    pub fn all_versions(&self) -> Vec<&PolicyVersion> {
        self.snapshots.iter().map(|s| &s.version).collect()
    }

    pub fn changes_since(&self, version: &PolicyVersion) -> Vec<&PolicySnapshot> {
        self.snapshots.iter().filter(|s| s.version > *version).collect()
    }
}

fn compute_diff(
    policy_id: &ManagedPolicyId,
    from: &PolicyVersion,
    to: &PolicyVersion,
    old: &ManagedPolicy,
    new: &ManagedPolicy,
) -> PolicyDiff {
    let mut changes = Vec::new();
    let mut summary_parts = Vec::new();

    // Name
    if old.name != new.name {
        changes.push(PolicyChange {
            change_type: ChangeType::Modified,
            field: "name".into(),
            old_value: Some(old.name.clone()),
            new_value: Some(new.name.clone()),
            detail: "Name changed".into(),
        });
        summary_parts.push("name changed".to_string());
    }

    // Description
    if old.description != new.description {
        changes.push(PolicyChange {
            change_type: ChangeType::Modified,
            field: "description".into(),
            old_value: Some(old.description.clone()),
            new_value: Some(new.description.clone()),
            detail: "Description changed".into(),
        });
        summary_parts.push("description changed".to_string());
    }

    // Status
    if old.status != new.status {
        changes.push(PolicyChange {
            change_type: ChangeType::StatusChanged {
                from: old.status.to_string(),
                to: new.status.to_string(),
            },
            field: "status".into(),
            old_value: Some(old.status.to_string()),
            new_value: Some(new.status.to_string()),
            detail: format!("Status: {} → {}", old.status, new.status),
        });
        summary_parts.push(format!("status {} → {}", old.status, new.status));
    }

    // Version
    if old.version != new.version {
        changes.push(PolicyChange {
            change_type: ChangeType::VersionBumped,
            field: "version".into(),
            old_value: Some(old.version.to_string()),
            new_value: Some(new.version.to_string()),
            detail: format!("Version: {} → {}", old.version, new.version),
        });
    }

    // Rules: added
    let old_rule_ids: Vec<&str> = old.rules.iter().map(|r| r.id.as_str()).collect();
    let new_rule_ids: Vec<&str> = new.rules.iter().map(|r| r.id.as_str()).collect();

    for rule in &new.rules {
        if !old_rule_ids.contains(&rule.id.as_str()) {
            changes.push(PolicyChange {
                change_type: ChangeType::RuleAdded { rule_id: rule.id.clone() },
                field: "rules".into(),
                old_value: None,
                new_value: Some(rule.name.clone()),
                detail: format!("Rule added: {}", rule.name),
            });
            summary_parts.push(format!("added rule {}", rule.id));
        }
    }

    // Rules: removed
    for rule in &old.rules {
        if !new_rule_ids.contains(&rule.id.as_str()) {
            changes.push(PolicyChange {
                change_type: ChangeType::RuleRemoved { rule_id: rule.id.clone() },
                field: "rules".into(),
                old_value: Some(rule.name.clone()),
                new_value: None,
                detail: format!("Rule removed: {}", rule.name),
            });
            summary_parts.push(format!("removed rule {}", rule.id));
        }
    }

    // Rules: modified (same id, different content)
    for new_rule in &new.rules {
        if let Some(old_rule) = old.rules.iter().find(|r| r.id == new_rule.id) {
            if old_rule != new_rule {
                changes.push(PolicyChange {
                    change_type: ChangeType::RuleModified { rule_id: new_rule.id.clone() },
                    field: "rules".into(),
                    old_value: Some(old_rule.name.clone()),
                    new_value: Some(new_rule.name.clone()),
                    detail: format!("Rule modified: {}", new_rule.id),
                });
                summary_parts.push(format!("modified rule {}", new_rule.id));
            }
        }
    }

    let summary = if summary_parts.is_empty() {
        "No changes".to_string()
    } else {
        summary_parts.join("; ")
    };

    PolicyDiff {
        policy_id: policy_id.clone(),
        from_version: from.clone(),
        to_version: to.clone(),
        changes,
        summary,
    }
}

// ── VersionStore ────────────────────────────────────────────────────

pub struct VersionStore {
    histories: HashMap<ManagedPolicyId, PolicyVersionHistory>,
}

impl VersionStore {
    pub fn new() -> Self {
        Self {
            histories: HashMap::new(),
        }
    }

    pub fn record(
        &mut self,
        policy: &ManagedPolicy,
        changed_by: &str,
        summary: &str,
        now: i64,
    ) {
        let history = self
            .histories
            .entry(policy.id.clone())
            .or_insert_with(|| PolicyVersionHistory::new(policy.id.clone()));
        history.record_snapshot(policy, changed_by, summary, now);
    }

    pub fn history_for(&self, id: &ManagedPolicyId) -> Option<&PolicyVersionHistory> {
        self.histories.get(id)
    }

    pub fn diff(
        &self,
        id: &ManagedPolicyId,
        from: &PolicyVersion,
        to: &PolicyVersion,
    ) -> Option<PolicyDiff> {
        self.histories.get(id)?.diff(from, to)
    }

    pub fn rollback(
        &self,
        id: &ManagedPolicyId,
        version: &PolicyVersion,
    ) -> Option<ManagedPolicy> {
        self.histories.get(id)?.rollback_to(version)
    }
}

impl Default for VersionStore {
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

    fn make_policy(id: &str, ver: PolicyVersion) -> ManagedPolicy {
        let mut p = ManagedPolicy::new(id, "Test", PolicyDomain::AccessControl, "team", 1000);
        p.version = ver;
        p
    }

    #[test]
    fn test_record_snapshot() {
        let p = make_policy("p1", PolicyVersion::initial());
        let mut history = PolicyVersionHistory::new(ManagedPolicyId::new("p1"));
        history.record_snapshot(&p, "alice", "initial", 1000);
        assert_eq!(history.version_count(), 1);
    }

    #[test]
    fn test_latest() {
        let mut history = PolicyVersionHistory::new(ManagedPolicyId::new("p1"));
        let p1 = make_policy("p1", PolicyVersion::initial());
        history.record_snapshot(&p1, "alice", "v1", 1000);
        let mut p2 = make_policy("p1", PolicyVersion::new(0, 2, 0));
        p2.name = "Updated".into();
        history.record_snapshot(&p2, "bob", "v2", 2000);
        assert_eq!(history.latest().unwrap().version, PolicyVersion::new(0, 2, 0));
    }

    #[test]
    fn test_at_version() {
        let mut history = PolicyVersionHistory::new(ManagedPolicyId::new("p1"));
        let p = make_policy("p1", PolicyVersion::initial());
        history.record_snapshot(&p, "alice", "v1", 1000);
        assert!(history.at_version(&PolicyVersion::initial()).is_some());
        assert!(history.at_version(&PolicyVersion::new(9, 9, 9)).is_none());
    }

    #[test]
    fn test_diff_detects_name_change() {
        let mut history = PolicyVersionHistory::new(ManagedPolicyId::new("p1"));
        let p1 = make_policy("p1", PolicyVersion::initial());
        history.record_snapshot(&p1, "alice", "v1", 1000);
        let mut p2 = make_policy("p1", PolicyVersion::new(0, 2, 0));
        p2.name = "New Name".into();
        history.record_snapshot(&p2, "bob", "renamed", 2000);
        let diff = history.diff(&PolicyVersion::initial(), &PolicyVersion::new(0, 2, 0)).unwrap();
        assert!(diff.changes.iter().any(|c| c.field == "name"));
        assert!(diff.summary.contains("name changed"));
    }

    #[test]
    fn test_diff_detects_rule_additions() {
        let mut history = PolicyVersionHistory::new(ManagedPolicyId::new("p1"));
        let p1 = make_policy("p1", PolicyVersion::initial());
        history.record_snapshot(&p1, "alice", "v1", 1000);
        let mut p2 = make_policy("p1", PolicyVersion::new(0, 2, 0));
        p2.rules.push(PolicyRule::new("r1", "New Rule", RuleExpression::Always, PolicyAction::Deny));
        history.record_snapshot(&p2, "bob", "added rule", 2000);
        let diff = history.diff(&PolicyVersion::initial(), &PolicyVersion::new(0, 2, 0)).unwrap();
        assert!(diff.changes.iter().any(|c| matches!(&c.change_type, ChangeType::RuleAdded { rule_id } if rule_id == "r1")));
    }

    #[test]
    fn test_diff_detects_rule_removals() {
        let mut history = PolicyVersionHistory::new(ManagedPolicyId::new("p1"));
        let mut p1 = make_policy("p1", PolicyVersion::initial());
        p1.rules.push(PolicyRule::new("r1", "Old Rule", RuleExpression::Always, PolicyAction::Allow));
        history.record_snapshot(&p1, "alice", "v1", 1000);
        let p2 = make_policy("p1", PolicyVersion::new(0, 2, 0)); // no rules
        history.record_snapshot(&p2, "bob", "removed rule", 2000);
        let diff = history.diff(&PolicyVersion::initial(), &PolicyVersion::new(0, 2, 0)).unwrap();
        assert!(diff.changes.iter().any(|c| matches!(&c.change_type, ChangeType::RuleRemoved { rule_id } if rule_id == "r1")));
    }

    #[test]
    fn test_diff_detects_status_change() {
        let mut history = PolicyVersionHistory::new(ManagedPolicyId::new("p1"));
        let p1 = make_policy("p1", PolicyVersion::initial());
        history.record_snapshot(&p1, "alice", "v1", 1000);
        let mut p2 = make_policy("p1", PolicyVersion::new(0, 2, 0));
        p2.status = PolicyStatus::Active;
        history.record_snapshot(&p2, "bob", "activated", 2000);
        let diff = history.diff(&PolicyVersion::initial(), &PolicyVersion::new(0, 2, 0)).unwrap();
        assert!(diff.changes.iter().any(|c| matches!(&c.change_type, ChangeType::StatusChanged { .. })));
    }

    #[test]
    fn test_rollback_to() {
        let mut history = PolicyVersionHistory::new(ManagedPolicyId::new("p1"));
        let p1 = make_policy("p1", PolicyVersion::initial());
        history.record_snapshot(&p1, "alice", "v1", 1000);
        let mut p2 = make_policy("p1", PolicyVersion::new(0, 2, 0));
        p2.name = "Changed".into();
        history.record_snapshot(&p2, "bob", "v2", 2000);
        let rolled = history.rollback_to(&PolicyVersion::initial()).unwrap();
        assert_eq!(rolled.name, "Test");
    }

    #[test]
    fn test_all_versions() {
        let mut history = PolicyVersionHistory::new(ManagedPolicyId::new("p1"));
        history.record_snapshot(&make_policy("p1", PolicyVersion::initial()), "a", "v1", 1000);
        history.record_snapshot(&make_policy("p1", PolicyVersion::new(0, 2, 0)), "b", "v2", 2000);
        let versions = history.all_versions();
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn test_changes_since() {
        let mut history = PolicyVersionHistory::new(ManagedPolicyId::new("p1"));
        history.record_snapshot(&make_policy("p1", PolicyVersion::initial()), "a", "v1", 1000);
        history.record_snapshot(&make_policy("p1", PolicyVersion::new(0, 2, 0)), "b", "v2", 2000);
        history.record_snapshot(&make_policy("p1", PolicyVersion::new(0, 3, 0)), "c", "v3", 3000);
        let changes = history.changes_since(&PolicyVersion::initial());
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn test_version_store_record_and_history() {
        let mut vs = VersionStore::new();
        let p = make_policy("p1", PolicyVersion::initial());
        vs.record(&p, "alice", "initial", 1000);
        assert!(vs.history_for(&ManagedPolicyId::new("p1")).is_some());
    }

    #[test]
    fn test_version_store_diff() {
        let mut vs = VersionStore::new();
        let p1 = make_policy("p1", PolicyVersion::initial());
        vs.record(&p1, "alice", "v1", 1000);
        let mut p2 = make_policy("p1", PolicyVersion::new(0, 2, 0));
        p2.name = "Changed".into();
        vs.record(&p2, "bob", "v2", 2000);
        let diff = vs.diff(&ManagedPolicyId::new("p1"), &PolicyVersion::initial(), &PolicyVersion::new(0, 2, 0));
        assert!(diff.is_some());
    }

    #[test]
    fn test_version_store_rollback() {
        let mut vs = VersionStore::new();
        let p = make_policy("p1", PolicyVersion::initial());
        vs.record(&p, "alice", "v1", 1000);
        let rolled = vs.rollback(&ManagedPolicyId::new("p1"), &PolicyVersion::initial());
        assert!(rolled.is_some());
    }
}
