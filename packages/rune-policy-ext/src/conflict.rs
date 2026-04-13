// ═══════════════════════════════════════════════════════════════════════
// Conflict — Detect when policies contradict each other.
//
// ConflictDetector compares rule pairs across policies using a
// conservative heuristic for condition overlap. Layer 1 catches
// obvious conflicts (same-field rules with contradicting actions).
// Layer 2 can use SMT for full overlap analysis.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::PolicyExtError;
use crate::policy::*;

// ── ConflictType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictType {
    DirectContradiction,
    ActionMismatch,
    OverlapWithDifferentPriority,
    ScopeConflict,
    RedundantRule,
}

impl fmt::Display for ConflictType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::DirectContradiction => "direct-contradiction",
            Self::ActionMismatch => "action-mismatch",
            Self::OverlapWithDifferentPriority => "overlap-different-priority",
            Self::ScopeConflict => "scope-conflict",
            Self::RedundantRule => "redundant-rule",
        };
        f.write_str(s)
    }
}

// ── ConflictSeverity ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConflictSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for ConflictSeverity {
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

// ── ResolutionType ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionType {
    PolicyAWins,
    PolicyBWins,
    Merged,
    RuleDisabled,
    Accepted,
}

impl fmt::Display for ResolutionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PolicyAWins => "policy-a-wins",
            Self::PolicyBWins => "policy-b-wins",
            Self::Merged => "merged",
            Self::RuleDisabled => "rule-disabled",
            Self::Accepted => "accepted",
        };
        f.write_str(s)
    }
}

// ── ConflictResolution ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConflictResolution {
    pub resolution_type: ResolutionType,
    pub resolved_by: String,
    pub resolved_at: i64,
    pub explanation: String,
}

// ── PolicyConflict ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyConflict {
    pub id: String,
    pub conflict_type: ConflictType,
    pub policy_a: ManagedPolicyId,
    pub rule_a: String,
    pub policy_b: ManagedPolicyId,
    pub rule_b: String,
    pub description: String,
    pub severity: ConflictSeverity,
    pub resolution: Option<ConflictResolution>,
    pub detected_at: i64,
}

// ── ConflictDetector ────────────────────────────────────────────────

pub struct ConflictDetector {
    detected: Vec<PolicyConflict>,
    counter: u64,
}

impl ConflictDetector {
    pub fn new() -> Self {
        Self {
            detected: Vec::new(),
            counter: 0,
        }
    }

    pub fn detect(
        &mut self,
        policy_a: &ManagedPolicy,
        policy_b: &ManagedPolicy,
        now: i64,
    ) -> Vec<PolicyConflict> {
        let mut new_conflicts = Vec::new();

        for rule_a in &policy_a.rules {
            if !rule_a.enabled {
                continue;
            }
            for rule_b in &policy_b.rules {
                if !rule_b.enabled {
                    continue;
                }

                if !conditions_may_overlap(&rule_a.condition, &rule_b.condition) {
                    continue;
                }

                let conflict = if rule_a.condition == rule_b.condition && rule_a.action == rule_b.action {
                    // Identical condition and action → redundant
                    Some(self.make_conflict(
                        ConflictType::RedundantRule,
                        &policy_a.id,
                        &rule_a.id,
                        &policy_b.id,
                        &rule_b.id,
                        "Redundant: identical condition and action",
                        ConflictSeverity::Low,
                        now,
                    ))
                } else if is_allow_deny_pair(&rule_a.action, &rule_b.action) {
                    // Allow vs Deny → direct contradiction
                    let sev = if is_safety_critical_domain(&policy_a.category)
                        || is_safety_critical_domain(&policy_b.category)
                    {
                        ConflictSeverity::Critical
                    } else {
                        ConflictSeverity::High
                    };
                    Some(self.make_conflict(
                        ConflictType::DirectContradiction,
                        &policy_a.id,
                        &rule_a.id,
                        &policy_b.id,
                        &rule_b.id,
                        &format!(
                            "Direct contradiction: {} vs {} on overlapping conditions",
                            rule_a.action, rule_b.action
                        ),
                        sev,
                        now,
                    ))
                } else if rule_a.action != rule_b.action {
                    // Different non-opposite actions
                    Some(self.make_conflict(
                        ConflictType::ActionMismatch,
                        &policy_a.id,
                        &rule_a.id,
                        &policy_b.id,
                        &rule_b.id,
                        &format!(
                            "Action mismatch: {} vs {} on overlapping conditions",
                            rule_a.action, rule_b.action
                        ),
                        ConflictSeverity::Medium,
                        now,
                    ))
                } else {
                    None
                };

                if let Some(c) = conflict {
                    new_conflicts.push(c);
                }
            }
        }

        self.detected.extend(new_conflicts.clone());
        new_conflicts
    }

    pub fn detect_in_set(
        &mut self,
        policies: &[&ManagedPolicy],
        now: i64,
    ) -> Vec<PolicyConflict> {
        let mut all = Vec::new();
        for i in 0..policies.len() {
            for j in (i + 1)..policies.len() {
                let conflicts = self.detect(policies[i], policies[j], now);
                all.extend(conflicts);
            }
        }
        all
    }

    pub fn resolve(
        &mut self,
        conflict_id: &str,
        resolution: ConflictResolution,
    ) -> Result<(), PolicyExtError> {
        for c in &mut self.detected {
            if c.id == conflict_id {
                if c.resolution.is_some() {
                    return Err(PolicyExtError::ConflictAlreadyResolved(conflict_id.into()));
                }
                c.resolution = Some(resolution);
                return Ok(());
            }
        }
        Err(PolicyExtError::ConflictNotFound(conflict_id.into()))
    }

    pub fn unresolved(&self) -> Vec<&PolicyConflict> {
        self.detected.iter().filter(|c| c.resolution.is_none()).collect()
    }

    pub fn by_severity(&self, severity: ConflictSeverity) -> Vec<&PolicyConflict> {
        self.detected.iter().filter(|c| c.severity == severity).collect()
    }

    pub fn conflicts_for_policy(&self, id: &ManagedPolicyId) -> Vec<&PolicyConflict> {
        self.detected
            .iter()
            .filter(|c| c.policy_a == *id || c.policy_b == *id)
            .collect()
    }

    pub fn conflict_count(&self) -> usize {
        self.detected.len()
    }

    fn make_conflict(
        &mut self,
        conflict_type: ConflictType,
        policy_a: &ManagedPolicyId,
        rule_a: &str,
        policy_b: &ManagedPolicyId,
        rule_b: &str,
        description: &str,
        severity: ConflictSeverity,
        now: i64,
    ) -> PolicyConflict {
        self.counter += 1;
        PolicyConflict {
            id: format!("conflict-{}", self.counter),
            conflict_type,
            policy_a: policy_a.clone(),
            rule_a: rule_a.into(),
            policy_b: policy_b.clone(),
            rule_b: rule_b.into(),
            description: description.into(),
            severity,
            resolution: None,
            detected_at: now,
        }
    }
}

impl Default for ConflictDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Heuristics ──────────────────────────────────────────────────────

fn conditions_may_overlap(a: &RuleExpression, b: &RuleExpression) -> bool {
    // Conservative heuristic for Layer 1:
    // Always overlaps with anything
    if matches!(a, RuleExpression::Always) || matches!(b, RuleExpression::Always) {
        return true;
    }
    // Same field Equals with same value
    if let (
        RuleExpression::Equals { field: fa, value: va },
        RuleExpression::Equals { field: fb, value: vb },
    ) = (a, b)
    {
        return fa == fb && va == vb;
    }
    // And/Or trees: overlap if they share any leaf field names
    let fields_a = collect_fields(a);
    let fields_b = collect_fields(b);
    fields_a.iter().any(|f| fields_b.contains(f))
}

fn collect_fields(expr: &RuleExpression) -> Vec<String> {
    match expr {
        RuleExpression::Equals { field, .. }
        | RuleExpression::NotEquals { field, .. }
        | RuleExpression::Contains { field, .. }
        | RuleExpression::GreaterThan { field, .. }
        | RuleExpression::LessThan { field, .. }
        | RuleExpression::InList { field, .. } => vec![field.clone()],
        RuleExpression::And(exprs) | RuleExpression::Or(exprs) => {
            exprs.iter().flat_map(collect_fields).collect()
        }
        RuleExpression::Not(expr) => collect_fields(expr),
        _ => Vec::new(),
    }
}

fn is_allow_deny_pair(a: &PolicyAction, b: &PolicyAction) -> bool {
    (matches!(a, PolicyAction::Allow) && matches!(b, PolicyAction::Deny))
        || (matches!(a, PolicyAction::Deny) && matches!(b, PolicyAction::Allow))
}

fn is_safety_critical_domain(domain: &PolicyDomain) -> bool {
    matches!(
        domain,
        PolicyDomain::AiGovernance | PolicyDomain::IncidentResponse | PolicyDomain::DataProtection
    )
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_policy(id: &str) -> ManagedPolicy {
        ManagedPolicy::new(id, "Allow", PolicyDomain::AccessControl, "team", 1000)
            .with_rule(PolicyRule::new("r1", "Allow all", RuleExpression::Always, PolicyAction::Allow))
    }

    fn deny_policy(id: &str) -> ManagedPolicy {
        ManagedPolicy::new(id, "Deny", PolicyDomain::AccessControl, "team", 1000)
            .with_rule(PolicyRule::new("r1", "Deny all", RuleExpression::Always, PolicyAction::Deny))
    }

    #[test]
    fn test_detect_direct_contradiction() {
        let mut detector = ConflictDetector::new();
        let conflicts = detector.detect(&allow_policy("p1"), &deny_policy("p2"), 1000);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].conflict_type, ConflictType::DirectContradiction);
    }

    #[test]
    fn test_detect_redundant_rules() {
        let mut detector = ConflictDetector::new();
        let conflicts = detector.detect(&allow_policy("p1"), &allow_policy("p2"), 1000);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].conflict_type, ConflictType::RedundantRule);
    }

    #[test]
    fn test_detect_in_set() {
        let p1 = allow_policy("p1");
        let p2 = deny_policy("p2");
        let p3 = allow_policy("p3");
        let mut detector = ConflictDetector::new();
        let conflicts = detector.detect_in_set(&[&p1, &p2, &p3], 1000);
        assert!(conflicts.len() >= 2); // p1-p2 contradiction + p1-p3 redundant
    }

    #[test]
    fn test_detect_no_conflicts() {
        let p1 = ManagedPolicy::new("p1", "A", PolicyDomain::AccessControl, "t", 1000)
            .with_rule(PolicyRule::new(
                "r1",
                "Check env",
                RuleExpression::Equals { field: "env".into(), value: "prod".into() },
                PolicyAction::Audit,
            ));
        let p2 = ManagedPolicy::new("p2", "B", PolicyDomain::AccessControl, "t", 1000)
            .with_rule(PolicyRule::new(
                "r2",
                "Check role",
                RuleExpression::Equals { field: "role".into(), value: "admin".into() },
                PolicyAction::Allow,
            ));
        let mut detector = ConflictDetector::new();
        let conflicts = detector.detect(&p1, &p2, 1000);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_resolve_conflict() {
        let mut detector = ConflictDetector::new();
        detector.detect(&allow_policy("p1"), &deny_policy("p2"), 1000);
        let cid = detector.unresolved()[0].id.clone();
        detector
            .resolve(
                &cid,
                ConflictResolution {
                    resolution_type: ResolutionType::PolicyBWins,
                    resolved_by: "alice".into(),
                    resolved_at: 2000,
                    explanation: "deny takes precedence".into(),
                },
            )
            .unwrap();
        assert!(detector.unresolved().is_empty());
    }

    #[test]
    fn test_unresolved() {
        let mut detector = ConflictDetector::new();
        detector.detect(&allow_policy("p1"), &deny_policy("p2"), 1000);
        assert_eq!(detector.unresolved().len(), 1);
    }

    #[test]
    fn test_by_severity() {
        let mut detector = ConflictDetector::new();
        detector.detect(&allow_policy("p1"), &deny_policy("p2"), 1000);
        assert_eq!(detector.by_severity(ConflictSeverity::High).len(), 1);
        assert_eq!(detector.by_severity(ConflictSeverity::Low).len(), 0);
    }

    #[test]
    fn test_conflicts_for_policy() {
        let mut detector = ConflictDetector::new();
        detector.detect(&allow_policy("p1"), &deny_policy("p2"), 1000);
        assert_eq!(
            detector.conflicts_for_policy(&ManagedPolicyId::new("p1")).len(),
            1
        );
    }

    #[test]
    fn test_conflict_type_display() {
        assert_eq!(ConflictType::DirectContradiction.to_string(), "direct-contradiction");
        assert_eq!(ConflictType::ActionMismatch.to_string(), "action-mismatch");
        assert_eq!(ConflictType::RedundantRule.to_string(), "redundant-rule");
        assert_eq!(ConflictType::OverlapWithDifferentPriority.to_string(), "overlap-different-priority");
        assert_eq!(ConflictType::ScopeConflict.to_string(), "scope-conflict");
    }

    #[test]
    fn test_conflict_severity_ordering() {
        assert!(ConflictSeverity::Low < ConflictSeverity::Medium);
        assert!(ConflictSeverity::Medium < ConflictSeverity::High);
        assert!(ConflictSeverity::High < ConflictSeverity::Critical);
    }

    #[test]
    fn test_resolution_type_display() {
        assert_eq!(ResolutionType::PolicyAWins.to_string(), "policy-a-wins");
        assert_eq!(ResolutionType::Merged.to_string(), "merged");
        assert_eq!(ResolutionType::Accepted.to_string(), "accepted");
        assert_eq!(ResolutionType::RuleDisabled.to_string(), "rule-disabled");
        assert_eq!(ResolutionType::PolicyBWins.to_string(), "policy-b-wins");
    }
}
