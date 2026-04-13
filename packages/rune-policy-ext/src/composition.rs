// ═══════════════════════════════════════════════════════════════════════
// Composition — Compose policies from multiple sources into unified
// policy sets with configurable conflict resolution strategies.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::policy::*;

// ── CompositionStrategy ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompositionStrategy {
    MostRestrictive,
    LeastRestrictive,
    PriorityBased,
    FirstMatch,
}

impl fmt::Display for CompositionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MostRestrictive => "most-restrictive",
            Self::LeastRestrictive => "least-restrictive",
            Self::PriorityBased => "priority-based",
            Self::FirstMatch => "first-match",
        };
        f.write_str(s)
    }
}

// ── MatchedRule ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MatchedRule {
    pub policy_id: ManagedPolicyId,
    pub rule_id: String,
    pub rule_name: String,
    pub action: PolicyAction,
    pub priority: u32,
}

// ── ComposedEvaluation ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComposedEvaluation {
    pub matched_rules: Vec<MatchedRule>,
    pub final_action: PolicyAction,
    pub strategy_used: CompositionStrategy,
    pub conflicts_detected: Vec<String>,
    pub detail: String,
}

// ── ComposedPolicySet ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComposedPolicySet {
    pub id: String,
    pub name: String,
    pub description: String,
    pub policies: Vec<ManagedPolicyId>,
    pub composition_strategy: CompositionStrategy,
    pub created_at: i64,
}

// ── PolicyComposer ──────────────────────────────────────────────────

pub struct PolicyComposer;

impl PolicyComposer {
    pub fn new() -> Self {
        Self
    }

    pub fn compose(
        &self,
        policies: &[&ManagedPolicy],
        strategy: CompositionStrategy,
    ) -> ComposedPolicySet {
        ComposedPolicySet {
            id: format!("composed-{}", policies.len()),
            name: format!("Composed set ({} policies)", policies.len()),
            description: String::new(),
            policies: policies.iter().map(|p| p.id.clone()).collect(),
            composition_strategy: strategy,
            created_at: 0,
        }
    }

    pub fn evaluate(
        &self,
        set: &ComposedPolicySet,
        store: &ManagedPolicyStore,
        context: &HashMap<String, String>,
    ) -> ComposedEvaluation {
        let mut matched = Vec::new();

        for pid in &set.policies {
            if let Some(policy) = store.get(pid) {
                for rule in &policy.rules {
                    if !rule.enabled {
                        continue;
                    }
                    if evaluate_rule_expression(&rule.condition, context) {
                        matched.push(MatchedRule {
                            policy_id: policy.id.clone(),
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            action: rule.action.clone(),
                            priority: rule.priority,
                        });
                    }
                }
            }
        }

        // Detect conflicts
        let mut conflicts = Vec::new();
        let has_allow = matched.iter().any(|m| m.action == PolicyAction::Allow);
        let has_deny = matched.iter().any(|m| m.action == PolicyAction::Deny);
        if has_allow && has_deny {
            conflicts.push("Allow vs Deny conflict detected".to_string());
        }

        let final_action = resolve_action(&matched, &set.composition_strategy);

        let detail = format!(
            "{} rules matched, {} conflicts, final action: {}",
            matched.len(),
            conflicts.len(),
            final_action
        );

        ComposedEvaluation {
            matched_rules: matched,
            final_action,
            strategy_used: set.composition_strategy.clone(),
            conflicts_detected: conflicts,
            detail,
        }
    }

    pub fn merge_rules(&self, policies: &[&ManagedPolicy]) -> Vec<PolicyRule> {
        let mut rules: Vec<PolicyRule> = policies
            .iter()
            .flat_map(|p| p.rules.clone())
            .collect();
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        rules
    }
}

impl Default for PolicyComposer {
    fn default() -> Self {
        Self::new()
    }
}

fn resolve_action(matched: &[MatchedRule], strategy: &CompositionStrategy) -> PolicyAction {
    if matched.is_empty() {
        return PolicyAction::Allow; // default: no matching rule → allow
    }

    match strategy {
        CompositionStrategy::MostRestrictive => {
            // Deny > Quarantine > RequireMfa > RequireApproval > Encrypt > Audit > Allow
            if matched.iter().any(|m| m.action == PolicyAction::Deny) {
                PolicyAction::Deny
            } else if matched.iter().any(|m| m.action == PolicyAction::Quarantine) {
                PolicyAction::Quarantine
            } else if matched.iter().any(|m| m.action == PolicyAction::RequireMfa) {
                PolicyAction::RequireMfa
            } else if matched.iter().any(|m| m.action == PolicyAction::Encrypt) {
                PolicyAction::Encrypt
            } else if matched.iter().any(|m| m.action == PolicyAction::Audit) {
                PolicyAction::Audit
            } else {
                matched[0].action.clone()
            }
        }
        CompositionStrategy::LeastRestrictive => {
            if matched.iter().any(|m| m.action == PolicyAction::Allow) {
                PolicyAction::Allow
            } else if matched.iter().any(|m| m.action == PolicyAction::Audit) {
                PolicyAction::Audit
            } else {
                matched[0].action.clone()
            }
        }
        CompositionStrategy::PriorityBased => {
            // Already sorted by evaluate, but find highest priority
            matched
                .iter()
                .max_by_key(|m| m.priority)
                .map(|m| m.action.clone())
                .unwrap_or(PolicyAction::Allow)
        }
        CompositionStrategy::FirstMatch => matched[0].action.clone(),
    }
}

// ── Rule Expression Evaluation ──────────────────────────────────────

pub fn evaluate_rule_expression(expr: &RuleExpression, context: &HashMap<String, String>) -> bool {
    match expr {
        RuleExpression::Always => true,
        RuleExpression::Never => false,
        RuleExpression::Equals { field, value } => {
            context.get(field).map_or(false, |v| v == value)
        }
        RuleExpression::NotEquals { field, value } => {
            context.get(field).map_or(true, |v| v != value)
        }
        RuleExpression::Contains { field, value } => {
            context.get(field).map_or(false, |v| v.contains(value.as_str()))
        }
        RuleExpression::GreaterThan { field, value } => {
            context
                .get(field)
                .and_then(|v| v.parse::<f64>().ok())
                .map_or(false, |v| v > *value)
        }
        RuleExpression::LessThan { field, value } => {
            context
                .get(field)
                .and_then(|v| v.parse::<f64>().ok())
                .map_or(false, |v| v < *value)
        }
        RuleExpression::InList { field, values } => {
            context.get(field).map_or(false, |v| values.contains(v))
        }
        RuleExpression::SeverityAtLeast(min) => {
            let levels = ["Info", "Low", "Medium", "High", "Critical", "Emergency"];
            let ctx_sev = context.get("severity").map(|s| s.as_str()).unwrap_or("Info");
            let min_idx = levels.iter().position(|l| l.eq_ignore_ascii_case(min)).unwrap_or(0);
            let ctx_idx = levels.iter().position(|l| l.eq_ignore_ascii_case(ctx_sev)).unwrap_or(0);
            ctx_idx >= min_idx
        }
        RuleExpression::ClassificationAtLeast(min) => {
            let levels = ["Public", "Internal", "Confidential", "Restricted", "TopSecret"];
            let ctx_cls = context.get("classification").map(|s| s.as_str()).unwrap_or("Public");
            let min_idx = levels.iter().position(|l| l.eq_ignore_ascii_case(min)).unwrap_or(0);
            let ctx_idx = levels.iter().position(|l| l.eq_ignore_ascii_case(ctx_cls)).unwrap_or(0);
            ctx_idx >= min_idx
        }
        RuleExpression::And(exprs) => exprs.iter().all(|e| evaluate_rule_expression(e, context)),
        RuleExpression::Or(exprs) => exprs.iter().any(|e| evaluate_rule_expression(e, context)),
        RuleExpression::Not(expr) => !evaluate_rule_expression(expr, context),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_policy(id: &str) -> ManagedPolicy {
        ManagedPolicy::new(id, "Allow Policy", PolicyDomain::AccessControl, "team", 1000)
            .with_rule(PolicyRule::new("r-allow", "Allow all", RuleExpression::Always, PolicyAction::Allow).with_priority(5))
    }

    fn deny_policy(id: &str) -> ManagedPolicy {
        ManagedPolicy::new(id, "Deny Policy", PolicyDomain::AccessControl, "team", 1000)
            .with_rule(PolicyRule::new("r-deny", "Deny all", RuleExpression::Always, PolicyAction::Deny).with_priority(10))
    }

    #[test]
    fn test_compose_creates_set() {
        let p1 = allow_policy("p1");
        let p2 = deny_policy("p2");
        let composer = PolicyComposer::new();
        let set = composer.compose(&[&p1, &p2], CompositionStrategy::MostRestrictive);
        assert_eq!(set.policies.len(), 2);
    }

    #[test]
    fn test_evaluate_most_restrictive() {
        let p1 = allow_policy("p1");
        let p2 = deny_policy("p2");
        let composer = PolicyComposer::new();
        let set = composer.compose(&[&p1, &p2], CompositionStrategy::MostRestrictive);
        let mut store = ManagedPolicyStore::new();
        store.add(p1).unwrap();
        store.add(p2).unwrap();
        let ctx = HashMap::new();
        let result = composer.evaluate(&set, &store, &ctx);
        assert_eq!(result.final_action, PolicyAction::Deny);
    }

    #[test]
    fn test_evaluate_least_restrictive() {
        let p1 = allow_policy("p1");
        let p2 = deny_policy("p2");
        let composer = PolicyComposer::new();
        let set = composer.compose(&[&p1, &p2], CompositionStrategy::LeastRestrictive);
        let mut store = ManagedPolicyStore::new();
        store.add(p1).unwrap();
        store.add(p2).unwrap();
        let ctx = HashMap::new();
        let result = composer.evaluate(&set, &store, &ctx);
        assert_eq!(result.final_action, PolicyAction::Allow);
    }

    #[test]
    fn test_evaluate_priority_based() {
        let p1 = allow_policy("p1"); // priority 5
        let p2 = deny_policy("p2"); // priority 10
        let composer = PolicyComposer::new();
        let set = composer.compose(&[&p1, &p2], CompositionStrategy::PriorityBased);
        let mut store = ManagedPolicyStore::new();
        store.add(p1).unwrap();
        store.add(p2).unwrap();
        let ctx = HashMap::new();
        let result = composer.evaluate(&set, &store, &ctx);
        assert_eq!(result.final_action, PolicyAction::Deny); // higher priority
    }

    #[test]
    fn test_evaluate_first_match() {
        let p1 = allow_policy("p1");
        let p2 = deny_policy("p2");
        let composer = PolicyComposer::new();
        let set = composer.compose(&[&p1, &p2], CompositionStrategy::FirstMatch);
        let mut store = ManagedPolicyStore::new();
        store.add(p1).unwrap();
        store.add(p2).unwrap();
        let ctx = HashMap::new();
        let result = composer.evaluate(&set, &store, &ctx);
        assert_eq!(result.final_action, PolicyAction::Allow); // first match
    }

    #[test]
    fn test_evaluate_reports_conflicts() {
        let p1 = allow_policy("p1");
        let p2 = deny_policy("p2");
        let composer = PolicyComposer::new();
        let set = composer.compose(&[&p1, &p2], CompositionStrategy::MostRestrictive);
        let mut store = ManagedPolicyStore::new();
        store.add(p1).unwrap();
        store.add(p2).unwrap();
        let ctx = HashMap::new();
        let result = composer.evaluate(&set, &store, &ctx);
        assert!(!result.conflicts_detected.is_empty());
    }

    #[test]
    fn test_merge_rules_sorted() {
        let p1 = allow_policy("p1"); // priority 5
        let p2 = deny_policy("p2"); // priority 10
        let composer = PolicyComposer::new();
        let merged = composer.merge_rules(&[&p1, &p2]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].priority, 10); // highest first
    }

    #[test]
    fn test_evaluate_rule_expression_equals() {
        let mut ctx = HashMap::new();
        ctx.insert("env".into(), "prod".into());
        assert!(evaluate_rule_expression(
            &RuleExpression::Equals { field: "env".into(), value: "prod".into() },
            &ctx,
        ));
        assert!(!evaluate_rule_expression(
            &RuleExpression::Equals { field: "env".into(), value: "dev".into() },
            &ctx,
        ));
    }

    #[test]
    fn test_evaluate_rule_expression_and() {
        let mut ctx = HashMap::new();
        ctx.insert("env".into(), "prod".into());
        ctx.insert("role".into(), "admin".into());
        let expr = RuleExpression::And(vec![
            RuleExpression::Equals { field: "env".into(), value: "prod".into() },
            RuleExpression::Equals { field: "role".into(), value: "admin".into() },
        ]);
        assert!(evaluate_rule_expression(&expr, &ctx));
    }

    #[test]
    fn test_evaluate_rule_expression_missing_field() {
        let ctx = HashMap::new();
        assert!(!evaluate_rule_expression(
            &RuleExpression::Equals { field: "missing".into(), value: "x".into() },
            &ctx,
        ));
    }
}
