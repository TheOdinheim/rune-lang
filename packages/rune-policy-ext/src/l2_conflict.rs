// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Enhanced policy conflict detection and resolution.
//
// Structured conflict detection with resource-level granularity,
// typed conflict categories, and multiple resolution strategies.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── PolicyConflictType ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyConflictType {
    DirectContradiction,
    OverlapAmbiguity,
    PriorityConflict,
    ScopeOverlap,
    TemporalConflict,
}

impl fmt::Display for PolicyConflictType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::DirectContradiction => "direct-contradiction",
            Self::OverlapAmbiguity => "overlap-ambiguity",
            Self::PriorityConflict => "priority-conflict",
            Self::ScopeOverlap => "scope-overlap",
            Self::TemporalConflict => "temporal-conflict",
        };
        f.write_str(s)
    }
}

// ── L2ConflictSeverity ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum L2ConflictSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for L2ConflictSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        f.write_str(s)
    }
}

// ── PolicyEffect ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEffect {
    Permit,
    Deny,
}

impl fmt::Display for PolicyEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permit => f.write_str("Permit"),
            Self::Deny => f.write_str("Deny"),
        }
    }
}

// ── PolicyRecord ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyRecord {
    pub id: String,
    pub name: String,
    pub effect: PolicyEffect,
    pub resources: Vec<String>,
    pub priority: i32,
    pub conditions: Vec<String>,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
}

impl PolicyRecord {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        effect: PolicyEffect,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            effect,
            resources: Vec::new(),
            priority: 0,
            conditions: Vec::new(),
            valid_from: None,
            valid_until: None,
        }
    }

    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resources.push(resource.into());
        self
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_validity(mut self, from: i64, until: i64) -> Self {
        self.valid_from = Some(from);
        self.valid_until = Some(until);
        self
    }
}

// ── L2PolicyConflict ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2PolicyConflict {
    pub id: String,
    pub policy_a_id: String,
    pub policy_b_id: String,
    pub conflict_type: PolicyConflictType,
    pub affected_resources: Vec<String>,
    pub severity: L2ConflictSeverity,
    pub description: String,
    pub detected_at: i64,
}

// ── L2ConflictDetector ─────────────────────────────────────────────

pub struct L2ConflictDetector {
    policies: Vec<PolicyRecord>,
}

impl L2ConflictDetector {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn add_policy(&mut self, policy: PolicyRecord) {
        self.policies.push(policy);
    }

    pub fn detect_conflicts(&self) -> Vec<L2PolicyConflict> {
        let mut conflicts = Vec::new();
        let mut counter = 0u64;

        for i in 0..self.policies.len() {
            for j in (i + 1)..self.policies.len() {
                let a = &self.policies[i];
                let b = &self.policies[j];

                let shared_resources: Vec<String> = a
                    .resources
                    .iter()
                    .filter(|r| b.resources.contains(r))
                    .cloned()
                    .collect();

                if shared_resources.is_empty() {
                    continue;
                }

                // Direct contradiction: same resources, opposite effects
                if a.effect != b.effect {
                    counter += 1;
                    let severity = if a.priority == b.priority {
                        L2ConflictSeverity::Critical
                    } else {
                        L2ConflictSeverity::High
                    };
                    conflicts.push(L2PolicyConflict {
                        id: format!("l2-conflict-{counter}"),
                        policy_a_id: a.id.clone(),
                        policy_b_id: b.id.clone(),
                        conflict_type: PolicyConflictType::DirectContradiction,
                        affected_resources: shared_resources.clone(),
                        severity,
                        description: format!(
                            "{} ({}) vs {} ({}) on shared resources",
                            a.id, a.effect, b.id, b.effect
                        ),
                        detected_at: 0,
                    });
                }

                // Scope overlap: same effect, same resources
                if a.effect == b.effect && !shared_resources.is_empty() {
                    let a_only = a.resources.iter().any(|r| !b.resources.contains(r));
                    let b_only = b.resources.iter().any(|r| !a.resources.contains(r));
                    if a_only || b_only {
                        counter += 1;
                        conflicts.push(L2PolicyConflict {
                            id: format!("l2-conflict-{counter}"),
                            policy_a_id: a.id.clone(),
                            policy_b_id: b.id.clone(),
                            conflict_type: PolicyConflictType::ScopeOverlap,
                            affected_resources: shared_resources.clone(),
                            severity: L2ConflictSeverity::Low,
                            description: format!(
                                "{} and {} have overlapping but not identical scopes",
                                a.id, b.id
                            ),
                            detected_at: 0,
                        });
                    }
                }

                // Temporal conflict: overlapping time windows with different effects
                if a.effect != b.effect {
                    if let (Some(a_from), Some(a_until), Some(b_from), Some(b_until)) =
                        (a.valid_from, a.valid_until, b.valid_from, b.valid_until)
                    {
                        if a_from < b_until && b_from < a_until {
                            counter += 1;
                            conflicts.push(L2PolicyConflict {
                                id: format!("l2-conflict-{counter}"),
                                policy_a_id: a.id.clone(),
                                policy_b_id: b.id.clone(),
                                conflict_type: PolicyConflictType::TemporalConflict,
                                affected_resources: shared_resources,
                                severity: L2ConflictSeverity::Medium,
                                description: format!(
                                    "{} and {} have overlapping time windows with different effects",
                                    a.id, b.id
                                ),
                                detected_at: 0,
                            });
                        }
                    }
                }
            }
        }

        conflicts
    }

    pub fn conflicts_for_resource(&self, resource: &str) -> Vec<L2PolicyConflict> {
        self.detect_conflicts()
            .into_iter()
            .filter(|c| c.affected_resources.iter().any(|r| r == resource))
            .collect()
    }

    pub fn conflict_count(&self) -> usize {
        self.detect_conflicts().len()
    }
}

impl Default for L2ConflictDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── ConflictResolutionStrategy ─────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ConflictResolutionStrategy {
    HighestPriority,
    MostSpecific,
    MostRecent,
    DenyOverrides,
    PermitOverrides,
    Manual { resolver: String, rationale: String },
}

impl fmt::Display for ConflictResolutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HighestPriority => f.write_str("highest-priority"),
            Self::MostSpecific => f.write_str("most-specific"),
            Self::MostRecent => f.write_str("most-recent"),
            Self::DenyOverrides => f.write_str("deny-overrides"),
            Self::PermitOverrides => f.write_str("permit-overrides"),
            Self::Manual { .. } => f.write_str("manual"),
        }
    }
}

// ── L2ConflictResolution ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2ConflictResolution {
    pub conflict_id: String,
    pub strategy: ConflictResolutionStrategy,
    pub winning_policy_id: String,
    pub resolved_by: String,
    pub resolved_at: i64,
    pub rationale: String,
}

pub fn resolve_conflict(
    conflict: &L2PolicyConflict,
    policies: &[&PolicyRecord],
    strategy: &ConflictResolutionStrategy,
    by: &str,
    now: i64,
) -> L2ConflictResolution {
    let policy_a = policies.iter().find(|p| p.id == conflict.policy_a_id);
    let policy_b = policies.iter().find(|p| p.id == conflict.policy_b_id);

    let (winner_id, rationale) = match strategy {
        ConflictResolutionStrategy::HighestPriority => {
            let a_prio = policy_a.map(|p| p.priority).unwrap_or(0);
            let b_prio = policy_b.map(|p| p.priority).unwrap_or(0);
            if a_prio >= b_prio {
                (conflict.policy_a_id.clone(), format!("priority {} >= {}", a_prio, b_prio))
            } else {
                (conflict.policy_b_id.clone(), format!("priority {} > {}", b_prio, a_prio))
            }
        }
        ConflictResolutionStrategy::MostSpecific => {
            let a_res = policy_a.map(|p| p.resources.len()).unwrap_or(0);
            let b_res = policy_b.map(|p| p.resources.len()).unwrap_or(0);
            // Fewer resources = more specific
            if a_res <= b_res {
                (conflict.policy_a_id.clone(), format!("{} resources (more specific)", a_res))
            } else {
                (conflict.policy_b_id.clone(), format!("{} resources (more specific)", b_res))
            }
        }
        ConflictResolutionStrategy::MostRecent => {
            // Use policy_b as "more recent" by convention (later in list)
            (conflict.policy_b_id.clone(), "most recent policy wins".into())
        }
        ConflictResolutionStrategy::DenyOverrides => {
            let a_deny = policy_a.map(|p| p.effect == PolicyEffect::Deny).unwrap_or(false);
            if a_deny {
                (conflict.policy_a_id.clone(), "deny overrides permit".into())
            } else {
                (conflict.policy_b_id.clone(), "deny overrides permit".into())
            }
        }
        ConflictResolutionStrategy::PermitOverrides => {
            let a_permit = policy_a.map(|p| p.effect == PolicyEffect::Permit).unwrap_or(false);
            if a_permit {
                (conflict.policy_a_id.clone(), "permit overrides deny".into())
            } else {
                (conflict.policy_b_id.clone(), "permit overrides deny".into())
            }
        }
        ConflictResolutionStrategy::Manual { resolver, rationale } => {
            (conflict.policy_a_id.clone(), format!("manual resolution by {}: {}", resolver, rationale))
        }
    };

    L2ConflictResolution {
        conflict_id: conflict.id.clone(),
        strategy: strategy.clone(),
        winning_policy_id: winner_id,
        resolved_by: by.into(),
        resolved_at: now,
        rationale,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn permit_policy(id: &str, resources: &[&str]) -> PolicyRecord {
        let mut p = PolicyRecord::new(id, format!("{id} policy"), PolicyEffect::Permit);
        for r in resources {
            p.resources.push(r.to_string());
        }
        p
    }

    fn deny_policy(id: &str, resources: &[&str]) -> PolicyRecord {
        let mut p = PolicyRecord::new(id, format!("{id} policy"), PolicyEffect::Deny);
        for r in resources {
            p.resources.push(r.to_string());
        }
        p
    }

    #[test]
    fn test_detect_conflicts_finds_direct_contradiction() {
        let mut detector = L2ConflictDetector::new();
        detector.add_policy(permit_policy("p1", &["db:users"]));
        detector.add_policy(deny_policy("p2", &["db:users"]));
        let conflicts = detector.detect_conflicts();
        assert!(conflicts.iter().any(|c| c.conflict_type == PolicyConflictType::DirectContradiction));
    }

    #[test]
    fn test_detect_conflicts_finds_scope_overlap() {
        let mut detector = L2ConflictDetector::new();
        detector.add_policy(permit_policy("p1", &["db:users", "db:orders"]));
        detector.add_policy(permit_policy("p2", &["db:users", "db:logs"]));
        let conflicts = detector.detect_conflicts();
        assert!(conflicts.iter().any(|c| c.conflict_type == PolicyConflictType::ScopeOverlap));
    }

    #[test]
    fn test_detect_conflicts_returns_empty_for_non_overlapping() {
        let mut detector = L2ConflictDetector::new();
        detector.add_policy(permit_policy("p1", &["db:users"]));
        detector.add_policy(deny_policy("p2", &["db:orders"]));
        let conflicts = detector.detect_conflicts();
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_conflicts_for_resource_filters_by_resource() {
        let mut detector = L2ConflictDetector::new();
        detector.add_policy(permit_policy("p1", &["db:users", "db:orders"]));
        detector.add_policy(deny_policy("p2", &["db:users"]));
        detector.add_policy(deny_policy("p3", &["db:orders"]));
        let user_conflicts = detector.conflicts_for_resource("db:users");
        assert!(!user_conflicts.is_empty());
        for c in &user_conflicts {
            assert!(c.affected_resources.contains(&"db:users".to_string()));
        }
    }

    #[test]
    fn test_resolve_conflict_highest_priority_picks_correct_winner() {
        let mut detector = L2ConflictDetector::new();
        let p1 = permit_policy("p1", &["db:users"]).with_priority(10);
        let p2 = deny_policy("p2", &["db:users"]).with_priority(5);
        detector.add_policy(p1.clone());
        detector.add_policy(p2.clone());
        let conflicts = detector.detect_conflicts();
        let contradiction = conflicts.iter().find(|c| c.conflict_type == PolicyConflictType::DirectContradiction).unwrap();
        let resolution = resolve_conflict(contradiction, &[&p1, &p2], &ConflictResolutionStrategy::HighestPriority, "admin", 1000);
        assert_eq!(resolution.winning_policy_id, "p1");
    }

    #[test]
    fn test_resolve_conflict_deny_overrides_picks_deny() {
        let mut detector = L2ConflictDetector::new();
        let p1 = permit_policy("p1", &["db:users"]);
        let p2 = deny_policy("p2", &["db:users"]);
        detector.add_policy(p1.clone());
        detector.add_policy(p2.clone());
        let conflicts = detector.detect_conflicts();
        let contradiction = conflicts.iter().find(|c| c.conflict_type == PolicyConflictType::DirectContradiction).unwrap();
        let resolution = resolve_conflict(contradiction, &[&p1, &p2], &ConflictResolutionStrategy::DenyOverrides, "admin", 1000);
        assert_eq!(resolution.winning_policy_id, "p2");
    }

    #[test]
    fn test_resolve_conflict_permit_overrides_picks_permit() {
        let mut detector = L2ConflictDetector::new();
        let p1 = permit_policy("p1", &["db:users"]);
        let p2 = deny_policy("p2", &["db:users"]);
        detector.add_policy(p1.clone());
        detector.add_policy(p2.clone());
        let conflicts = detector.detect_conflicts();
        let contradiction = conflicts.iter().find(|c| c.conflict_type == PolicyConflictType::DirectContradiction).unwrap();
        let resolution = resolve_conflict(contradiction, &[&p1, &p2], &ConflictResolutionStrategy::PermitOverrides, "admin", 1000);
        assert_eq!(resolution.winning_policy_id, "p1");
    }

    #[test]
    fn test_conflict_resolution_records_resolver_and_rationale() {
        let conflict = L2PolicyConflict {
            id: "c1".into(),
            policy_a_id: "p1".into(),
            policy_b_id: "p2".into(),
            conflict_type: PolicyConflictType::DirectContradiction,
            affected_resources: vec!["res1".into()],
            severity: L2ConflictSeverity::High,
            description: "test".into(),
            detected_at: 1000,
        };
        let p1 = PolicyRecord::new("p1", "Policy 1", PolicyEffect::Permit);
        let p2 = PolicyRecord::new("p2", "Policy 2", PolicyEffect::Deny);
        let resolution = resolve_conflict(&conflict, &[&p1, &p2], &ConflictResolutionStrategy::DenyOverrides, "alice", 2000);
        assert_eq!(resolution.resolved_by, "alice");
        assert_eq!(resolution.resolved_at, 2000);
        assert!(!resolution.rationale.is_empty());
    }
}
