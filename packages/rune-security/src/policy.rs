// ═══════════════════════════════════════════════════════════════════════
// Security Policy Templates and Rule Evaluation
//
// SecurityPolicy + SecurityRule with composable conditions (And/Or/Not),
// rule evaluation against SecurityContext, and built-in templates for
// common policy categories.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_permissions::ClassificationLevel;
use serde::{Deserialize, Serialize};

use crate::context::SecurityContext;
use crate::severity::SecuritySeverity;
use crate::threat::ThreatCategory;

// ── PolicyCategory ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyCategory {
    NetworkSecurity,
    DataProtection,
    AccessControl,
    AiGovernance,
    OperationalSecurity,
    PhysicalSecurity,
}

impl fmt::Display for PolicyCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── RuleCondition ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RuleCondition {
    Always,
    SeverityAbove(SecuritySeverity),
    ClassificationAbove(ClassificationLevel),
    ThreatActive(ThreatCategory),
    ContextMatch { key: String, value: String },
    And(Vec<RuleCondition>),
    Or(Vec<RuleCondition>),
    Not(Box<RuleCondition>),
}

// ── RuleAction ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RuleAction {
    Allow,
    Deny,
    RequireMfa,
    RequireApproval { approver: String },
    Encrypt,
    Audit,
    Alert { severity: SecuritySeverity },
    Quarantine,
    RateLimit { max_per_minute: u64 },
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::Deny => write!(f, "Deny"),
            Self::RequireMfa => write!(f, "RequireMfa"),
            Self::RequireApproval { approver } => write!(f, "RequireApproval({approver})"),
            Self::Encrypt => write!(f, "Encrypt"),
            Self::Audit => write!(f, "Audit"),
            Self::Alert { severity } => write!(f, "Alert({severity})"),
            Self::Quarantine => write!(f, "Quarantine"),
            Self::RateLimit { max_per_minute } => {
                write!(f, "RateLimit({max_per_minute}/min)")
            }
        }
    }
}

// ── SecurityRule ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecurityRule {
    pub id: String,
    pub description: String,
    pub condition: RuleCondition,
    pub action: RuleAction,
    pub enabled: bool,
}

// ── SecurityPolicy ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: PolicyCategory,
    pub rules: Vec<SecurityRule>,
    pub severity_on_violation: SecuritySeverity,
    pub active: bool,
    pub created_at: i64,
}

impl SecurityPolicy {
    pub fn default_network() -> Self {
        Self {
            id: "policy-network-default".into(),
            name: "Default Network Security".into(),
            description: "TLS required, block plaintext, rate-limit public endpoints".into(),
            category: PolicyCategory::NetworkSecurity,
            rules: vec![
                SecurityRule {
                    id: "net-1".into(),
                    description: "Require TLS for all network traffic".into(),
                    condition: RuleCondition::Always,
                    action: RuleAction::Encrypt,
                    enabled: true,
                },
                SecurityRule {
                    id: "net-2".into(),
                    description: "Deny when high risk and unauthenticated".into(),
                    condition: RuleCondition::SeverityAbove(SecuritySeverity::Medium),
                    action: RuleAction::Deny,
                    enabled: true,
                },
                SecurityRule {
                    id: "net-3".into(),
                    description: "Rate-limit public endpoints".into(),
                    condition: RuleCondition::Always,
                    action: RuleAction::RateLimit { max_per_minute: 600 },
                    enabled: true,
                },
            ],
            severity_on_violation: SecuritySeverity::High,
            active: true,
            created_at: 0,
        }
    }

    pub fn default_data_protection() -> Self {
        Self {
            id: "policy-data-default".into(),
            name: "Default Data Protection".into(),
            description: "Encrypt Confidential+, audit Restricted+".into(),
            category: PolicyCategory::DataProtection,
            rules: vec![
                SecurityRule {
                    id: "data-1".into(),
                    description: "Encrypt Confidential and above".into(),
                    condition: RuleCondition::ClassificationAbove(ClassificationLevel::Internal),
                    action: RuleAction::Encrypt,
                    enabled: true,
                },
                SecurityRule {
                    id: "data-2".into(),
                    description: "Audit all access to Restricted and above".into(),
                    condition: RuleCondition::ClassificationAbove(
                        ClassificationLevel::Confidential,
                    ),
                    action: RuleAction::Audit,
                    enabled: true,
                },
            ],
            severity_on_violation: SecuritySeverity::High,
            active: true,
            created_at: 0,
        }
    }

    pub fn default_ai_governance() -> Self {
        Self {
            id: "policy-ai-default".into(),
            name: "Default AI Governance".into(),
            description: "Require attestation, audit inference, quarantine untrusted".into(),
            category: PolicyCategory::AiGovernance,
            rules: vec![
                SecurityRule {
                    id: "ai-1".into(),
                    description: "Require model attestation".into(),
                    condition: RuleCondition::Always,
                    action: RuleAction::RequireApproval {
                        approver: "model-governance".into(),
                    },
                    enabled: true,
                },
                SecurityRule {
                    id: "ai-2".into(),
                    description: "Audit all inference operations".into(),
                    condition: RuleCondition::Always,
                    action: RuleAction::Audit,
                    enabled: true,
                },
                SecurityRule {
                    id: "ai-3".into(),
                    description: "Quarantine on active prompt injection".into(),
                    condition: RuleCondition::ThreatActive(ThreatCategory::PromptInjection),
                    action: RuleAction::Quarantine,
                    enabled: true,
                },
            ],
            severity_on_violation: SecuritySeverity::Critical,
            active: true,
            created_at: 0,
        }
    }
}

// ── Rule Evaluation ───────────────────────────────────────────────────

pub fn evaluate_rule(rule: &SecurityRule, context: &SecurityContext) -> bool {
    if !rule.enabled {
        return false;
    }
    evaluate_condition(&rule.condition, context)
}

fn evaluate_condition(condition: &RuleCondition, context: &SecurityContext) -> bool {
    match condition {
        RuleCondition::Always => true,
        RuleCondition::SeverityAbove(s) => context.risk_level > *s,
        RuleCondition::ClassificationAbove(c) => context.clearance > *c,
        RuleCondition::ThreatActive(t) => context.active_threats.contains(t),
        RuleCondition::ContextMatch { key, value } => {
            context.metadata.get(key).map(|v| v == value).unwrap_or(false)
        }
        RuleCondition::And(conds) => conds.iter().all(|c| evaluate_condition(c, context)),
        RuleCondition::Or(conds) => conds.iter().any(|c| evaluate_condition(c, context)),
        RuleCondition::Not(c) => !evaluate_condition(c, context),
    }
}

// ── SecurityPolicySet ─────────────────────────────────────────────────

#[derive(Default)]
pub struct SecurityPolicySet {
    pub policies: Vec<SecurityPolicy>,
}

impl SecurityPolicySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_policy(&mut self, policy: SecurityPolicy) {
        self.policies.push(policy);
    }

    pub fn evaluate(&self, context: &SecurityContext) -> Vec<RuleAction> {
        let mut actions = Vec::new();
        for policy in &self.policies {
            if !policy.active {
                continue;
            }
            for rule in &policy.rules {
                if evaluate_rule(rule, context) {
                    actions.push(rule.action.clone());
                }
            }
        }
        actions
    }

    pub fn violations(&self, context: &SecurityContext) -> Vec<&SecurityRule> {
        let mut vs = Vec::new();
        for policy in &self.policies {
            if !policy.active {
                continue;
            }
            for rule in &policy.rules {
                if matches!(rule.action, RuleAction::Deny) && evaluate_rule(rule, context) {
                    vs.push(rule);
                }
            }
        }
        vs
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, cond: RuleCondition, action: RuleAction) -> SecurityRule {
        SecurityRule {
            id: id.into(),
            description: "test".into(),
            condition: cond,
            action,
            enabled: true,
        }
    }

    #[test]
    fn test_security_policy_construction() {
        let p = SecurityPolicy::default_network();
        assert_eq!(p.category, PolicyCategory::NetworkSecurity);
        assert!(!p.rules.is_empty());
    }

    #[test]
    fn test_always_condition_matches() {
        let ctx = SecurityContext::new("c");
        let r = rule("r1", RuleCondition::Always, RuleAction::Allow);
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_severity_above_filters() {
        let ctx = SecurityContext::new("c").risk_level(SecuritySeverity::High);
        let r1 = rule(
            "r1",
            RuleCondition::SeverityAbove(SecuritySeverity::Medium),
            RuleAction::Deny,
        );
        let r2 = rule(
            "r2",
            RuleCondition::SeverityAbove(SecuritySeverity::Critical),
            RuleAction::Deny,
        );
        assert!(evaluate_rule(&r1, &ctx));
        assert!(!evaluate_rule(&r2, &ctx));
    }

    #[test]
    fn test_classification_above() {
        let ctx = SecurityContext::new("c").clearance(ClassificationLevel::Restricted);
        let r = rule(
            "r",
            RuleCondition::ClassificationAbove(ClassificationLevel::Confidential),
            RuleAction::Audit,
        );
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_threat_active() {
        let ctx = SecurityContext::new("c").add_threat(ThreatCategory::PromptInjection);
        let r = rule(
            "r",
            RuleCondition::ThreatActive(ThreatCategory::PromptInjection),
            RuleAction::Quarantine,
        );
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_and_combinator() {
        let ctx = SecurityContext::new("c")
            .risk_level(SecuritySeverity::High)
            .clearance(ClassificationLevel::Restricted);
        let r = rule(
            "r",
            RuleCondition::And(vec![
                RuleCondition::SeverityAbove(SecuritySeverity::Medium),
                RuleCondition::ClassificationAbove(ClassificationLevel::Confidential),
            ]),
            RuleAction::Deny,
        );
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_or_combinator() {
        let ctx = SecurityContext::new("c").risk_level(SecuritySeverity::High);
        let r = rule(
            "r",
            RuleCondition::Or(vec![
                RuleCondition::SeverityAbove(SecuritySeverity::Critical),
                RuleCondition::SeverityAbove(SecuritySeverity::Medium),
            ]),
            RuleAction::Deny,
        );
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_not_combinator() {
        let ctx = SecurityContext::new("c");
        let r = rule(
            "r",
            RuleCondition::Not(Box::new(RuleCondition::ThreatActive(
                ThreatCategory::Spoofing,
            ))),
            RuleAction::Allow,
        );
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_disabled_rule_does_not_match() {
        let ctx = SecurityContext::new("c");
        let mut r = rule("r", RuleCondition::Always, RuleAction::Allow);
        r.enabled = false;
        assert!(!evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_evaluate_returns_matching_actions() {
        let ctx = SecurityContext::new("c").clearance(ClassificationLevel::Restricted);
        let mut set = SecurityPolicySet::new();
        set.add_policy(SecurityPolicy::default_data_protection());
        let actions = set.evaluate(&ctx);
        assert!(actions.contains(&RuleAction::Encrypt));
        assert!(actions.contains(&RuleAction::Audit));
    }

    #[test]
    fn test_violations_returns_deny_rules() {
        let ctx = SecurityContext::new("c").risk_level(SecuritySeverity::High);
        let mut set = SecurityPolicySet::new();
        set.add_policy(SecurityPolicy::default_network());
        let vs = set.violations(&ctx);
        assert!(!vs.is_empty());
    }

    #[test]
    fn test_default_network_has_rules() {
        let p = SecurityPolicy::default_network();
        assert!(p.rules.iter().any(|r| matches!(r.action, RuleAction::Encrypt)));
    }

    #[test]
    fn test_default_ai_governance_requires_attestation() {
        let p = SecurityPolicy::default_ai_governance();
        assert!(p
            .rules
            .iter()
            .any(|r| matches!(r.action, RuleAction::RequireApproval { .. })));
    }

    #[test]
    fn test_context_match_condition() {
        let ctx = SecurityContext::new("c").metadata("env", "prod");
        let r = rule(
            "r",
            RuleCondition::ContextMatch {
                key: "env".into(),
                value: "prod".into(),
            },
            RuleAction::Audit,
        );
        assert!(evaluate_rule(&r, &ctx));
    }
}
