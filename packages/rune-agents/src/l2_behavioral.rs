// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Agent behavioral policy enforcement.
//
// Structured behavioral policies that define and enforce acceptable
// agent behavior patterns with violation tracking.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── RuleAction ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
    RequireApproval,
    RateLimit { max_per_hour: u64 },
    Log,
    Quarantine,
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Allow => "Allow",
            Self::Deny => "Deny",
            Self::RequireApproval => "RequireApproval",
            Self::RateLimit { .. } => "RateLimit",
            Self::Log => "Log",
            Self::Quarantine => "Quarantine",
        };
        f.write_str(s)
    }
}

// ── PolicyEnforcement ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEnforcement {
    Strict,
    Permissive,
    AuditOnly,
}

impl fmt::Display for PolicyEnforcement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Strict => "Strict",
            Self::Permissive => "Permissive",
            Self::AuditOnly => "AuditOnly",
        };
        f.write_str(s)
    }
}

// ── BehavioralRule ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BehavioralRule {
    pub id: String,
    pub condition: String,
    pub action: RuleAction,
    pub priority: u32,
}

// ── BehavioralPolicy ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BehavioralPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub rules: Vec<BehavioralRule>,
    pub applies_to: Vec<String>,
    pub enforcement: PolicyEnforcement,
    pub created_at: i64,
}

impl BehavioralPolicy {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        enforcement: PolicyEnforcement,
        created_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            rules: Vec::new(),
            applies_to: vec!["*".to_string()],
            enforcement,
            created_at,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_rules(mut self, rules: Vec<BehavioralRule>) -> Self {
        self.rules = rules;
        self
    }

    pub fn with_applies_to(mut self, agents: Vec<String>) -> Self {
        self.applies_to = agents;
        self
    }

    fn applies_to_agent(&self, agent_id: &str) -> bool {
        self.applies_to.iter().any(|a| a == "*" || a == agent_id)
    }
}

// ── BehavioralViolation ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BehavioralViolation {
    pub policy_id: String,
    pub rule_id: String,
    pub agent_id: String,
    pub action_attempted: String,
    pub enforcement_result: String,
    pub timestamp: i64,
}

// ── PolicyEvaluation ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyEvaluation {
    pub allowed: bool,
    pub matched_rules: Vec<String>,
    pub enforcement: PolicyEnforcement,
    pub requires_approval: bool,
    pub rate_limited: bool,
}

// ── BehavioralPolicyEngine ────────────────────────────────────────

#[derive(Debug, Default)]
pub struct BehavioralPolicyEngine {
    policies: Vec<BehavioralPolicy>,
    violation_log: Vec<BehavioralViolation>,
}

impl BehavioralPolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_policy(&mut self, policy: BehavioralPolicy) {
        self.policies.push(policy);
    }

    pub fn evaluate(&self, agent_id: &str, action: &str) -> PolicyEvaluation {
        let mut allowed = true;
        let mut matched_rules = Vec::new();
        let mut requires_approval = false;
        let mut rate_limited = false;
        let mut enforcement = PolicyEnforcement::Permissive;

        for policy in &self.policies {
            if !policy.applies_to_agent(agent_id) {
                continue;
            }

            let mut rules: Vec<&BehavioralRule> = policy.rules.iter().collect();
            rules.sort_by(|a, b| b.priority.cmp(&a.priority));

            for rule in rules {
                // Simple keyword matching on condition
                if rule.condition == "*" || action.contains(&rule.condition) {
                    matched_rules.push(rule.id.clone());
                    enforcement = policy.enforcement.clone();

                    match &rule.action {
                        RuleAction::Deny => {
                            if policy.enforcement == PolicyEnforcement::Strict {
                                allowed = false;
                            }
                        }
                        RuleAction::RequireApproval => {
                            requires_approval = true;
                        }
                        RuleAction::RateLimit { .. } => {
                            rate_limited = true;
                        }
                        RuleAction::Quarantine => {
                            if policy.enforcement == PolicyEnforcement::Strict {
                                allowed = false;
                            }
                        }
                        RuleAction::Allow | RuleAction::Log => {}
                    }
                }
            }
        }

        PolicyEvaluation {
            allowed,
            matched_rules,
            enforcement,
            requires_approval,
            rate_limited,
        }
    }

    pub fn record_violation(&mut self, violation: BehavioralViolation) {
        self.violation_log.push(violation);
    }

    pub fn violations_for_agent(&self, agent_id: &str) -> Vec<&BehavioralViolation> {
        self.violation_log
            .iter()
            .filter(|v| v.agent_id == agent_id)
            .collect()
    }

    pub fn violations_for_policy(&self, policy_id: &str) -> Vec<&BehavioralViolation> {
        self.violation_log
            .iter()
            .filter(|v| v.policy_id == policy_id)
            .collect()
    }

    pub fn most_violated_policies(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for v in &self.violation_log {
            *counts.entry(v.policy_id.clone()).or_insert(0) += 1;
        }
        let mut pairs: Vec<(String, usize)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    pub fn agents_with_violations(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for v in &self.violation_log {
            *counts.entry(v.agent_id.clone()).or_insert(0) += 1;
        }
        let mut pairs: Vec<(String, usize)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs
    }

    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    pub fn violation_count(&self) -> usize {
        self.violation_log.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(id: &str, rules: Vec<BehavioralRule>, applies_to: Vec<String>, enforcement: PolicyEnforcement) -> BehavioralPolicy {
        BehavioralPolicy::new(id, format!("Policy {id}"), enforcement, 1000)
            .with_rules(rules)
            .with_applies_to(applies_to)
    }

    #[test]
    fn test_evaluate_matches_allow_rule() {
        let mut engine = BehavioralPolicyEngine::new();
        engine.add_policy(make_policy("p1", vec![
            BehavioralRule { id: "r1".into(), condition: "read".into(), action: RuleAction::Allow, priority: 1 },
        ], vec!["a1".into()], PolicyEnforcement::Strict));
        let eval = engine.evaluate("a1", "read data");
        assert!(eval.allowed);
        assert!(eval.matched_rules.contains(&"r1".to_string()));
    }

    #[test]
    fn test_evaluate_matches_deny_rule() {
        let mut engine = BehavioralPolicyEngine::new();
        engine.add_policy(make_policy("p1", vec![
            BehavioralRule { id: "r1".into(), condition: "delete".into(), action: RuleAction::Deny, priority: 1 },
        ], vec!["a1".into()], PolicyEnforcement::Strict));
        let eval = engine.evaluate("a1", "delete records");
        assert!(!eval.allowed);
    }

    #[test]
    fn test_evaluate_require_approval_sets_flag() {
        let mut engine = BehavioralPolicyEngine::new();
        engine.add_policy(make_policy("p1", vec![
            BehavioralRule { id: "r1".into(), condition: "deploy".into(), action: RuleAction::RequireApproval, priority: 1 },
        ], vec!["a1".into()], PolicyEnforcement::Strict));
        let eval = engine.evaluate("a1", "deploy model");
        assert!(eval.requires_approval);
    }

    #[test]
    fn test_wildcard_applies_to_all_agents() {
        let mut engine = BehavioralPolicyEngine::new();
        engine.add_policy(make_policy("p1", vec![
            BehavioralRule { id: "r1".into(), condition: "shutdown".into(), action: RuleAction::Deny, priority: 1 },
        ], vec!["*".into()], PolicyEnforcement::Strict));
        let eval = engine.evaluate("any-agent", "shutdown system");
        assert!(!eval.allowed);
    }

    #[test]
    fn test_record_violation_stores() {
        let mut engine = BehavioralPolicyEngine::new();
        engine.record_violation(BehavioralViolation {
            policy_id: "p1".into(),
            rule_id: "r1".into(),
            agent_id: "a1".into(),
            action_attempted: "delete".into(),
            enforcement_result: "Denied".into(),
            timestamp: 1000,
        });
        assert_eq!(engine.violation_count(), 1);
    }

    #[test]
    fn test_violations_for_agent() {
        let mut engine = BehavioralPolicyEngine::new();
        engine.record_violation(BehavioralViolation {
            policy_id: "p1".into(), rule_id: "r1".into(), agent_id: "a1".into(),
            action_attempted: "delete".into(), enforcement_result: "Denied".into(), timestamp: 1000,
        });
        engine.record_violation(BehavioralViolation {
            policy_id: "p1".into(), rule_id: "r1".into(), agent_id: "a2".into(),
            action_attempted: "delete".into(), enforcement_result: "Denied".into(), timestamp: 1001,
        });
        assert_eq!(engine.violations_for_agent("a1").len(), 1);
    }

    #[test]
    fn test_most_violated_policies_sorted() {
        let mut engine = BehavioralPolicyEngine::new();
        for _ in 0..3 {
            engine.record_violation(BehavioralViolation {
                policy_id: "p1".into(), rule_id: "r1".into(), agent_id: "a1".into(),
                action_attempted: "x".into(), enforcement_result: "Denied".into(), timestamp: 1000,
            });
        }
        engine.record_violation(BehavioralViolation {
            policy_id: "p2".into(), rule_id: "r1".into(), agent_id: "a1".into(),
            action_attempted: "x".into(), enforcement_result: "Denied".into(), timestamp: 1001,
        });
        let top = engine.most_violated_policies(2);
        assert_eq!(top[0].0, "p1");
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn test_agents_with_violations_returns_all() {
        let mut engine = BehavioralPolicyEngine::new();
        engine.record_violation(BehavioralViolation {
            policy_id: "p1".into(), rule_id: "r1".into(), agent_id: "a1".into(),
            action_attempted: "x".into(), enforcement_result: "Denied".into(), timestamp: 1000,
        });
        engine.record_violation(BehavioralViolation {
            policy_id: "p1".into(), rule_id: "r1".into(), agent_id: "a2".into(),
            action_attempted: "x".into(), enforcement_result: "Denied".into(), timestamp: 1001,
        });
        let agents = engine.agents_with_violations();
        assert_eq!(agents.len(), 2);
    }
}
