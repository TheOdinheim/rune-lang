// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Network policy enforcement with allow/deny lists.
//
// Structured network policies with priority-ordered rule evaluation,
// direction-aware matching, and enforcement decisions.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── NetworkAction ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAction {
    Allow,
    Deny,
    Log,
    RateLimit { max_per_second: u64 },
}

impl fmt::Display for NetworkAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::Deny => write!(f, "Deny"),
            Self::Log => write!(f, "Log"),
            Self::RateLimit { max_per_second } => {
                write!(f, "RateLimit({max_per_second}/s)")
            }
        }
    }
}

// ── TrafficDirection ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Both,
}

impl fmt::Display for TrafficDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inbound => write!(f, "Inbound"),
            Self::Outbound => write!(f, "Outbound"),
            Self::Both => write!(f, "Both"),
        }
    }
}

// ── NetworkMatch ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum NetworkMatch {
    Any,
    IpAddress(String),
    IpRange { start: String, end: String },
    Hostname(String),
    Tag(String),
}

// ── NetworkRule ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NetworkRule {
    pub id: String,
    pub direction: TrafficDirection,
    pub source: NetworkMatch,
    pub destination: NetworkMatch,
    pub protocol: Option<String>,
    pub port_range: Option<(u16, u16)>,
    pub action: NetworkAction,
}

impl NetworkRule {
    fn matches_addr(pattern: &NetworkMatch, addr: &str) -> bool {
        match pattern {
            NetworkMatch::Any => true,
            NetworkMatch::IpAddress(ip) => addr == ip,
            NetworkMatch::Hostname(host) => addr == host,
            NetworkMatch::Tag(tag) => addr.contains(tag.as_str()),
            NetworkMatch::IpRange { start, end } => {
                addr >= start.as_str() && addr <= end.as_str()
            }
        }
    }

    fn matches(&self, direction: &TrafficDirection, source: &str, destination: &str, port: u16) -> bool {
        // Direction check
        let dir_match = self.direction == TrafficDirection::Both
            || self.direction == *direction;
        if !dir_match {
            return false;
        }

        // Source/destination match
        if !Self::matches_addr(&self.source, source) {
            return false;
        }
        if !Self::matches_addr(&self.destination, destination) {
            return false;
        }

        // Port range check
        if let Some((lo, hi)) = self.port_range {
            if port < lo || port > hi {
                return false;
            }
        }

        true
    }
}

// ── NetworkPolicy ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2NetworkPolicy {
    pub id: String,
    pub name: String,
    pub default_action: NetworkAction,
    pub rules: Vec<NetworkRule>,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: i64,
}

impl L2NetworkPolicy {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        default_action: NetworkAction,
        priority: i32,
        created_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            default_action,
            rules: Vec::new(),
            priority,
            enabled: true,
            created_at,
        }
    }

    pub fn with_rules(mut self, rules: Vec<NetworkRule>) -> Self {
        self.rules = rules;
        self
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

// ── NetworkPolicyDecision ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NetworkPolicyDecision {
    pub action: NetworkAction,
    pub matched_policy_id: Option<String>,
    pub matched_rule_id: Option<String>,
    pub reason: String,
}

// ── NetworkPolicyEngine ──────────────────────────────────────────

#[derive(Debug, Default)]
pub struct NetworkPolicyEngine {
    policies: Vec<L2NetworkPolicy>,
}

impl NetworkPolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_policy(&mut self, policy: L2NetworkPolicy) {
        self.policies.push(policy);
        // Sort by priority (higher priority = lower number = first)
        self.policies.sort_by(|a, b| a.priority.cmp(&b.priority));
    }

    pub fn evaluate(
        &self,
        direction: &TrafficDirection,
        source: &str,
        destination: &str,
        port: u16,
    ) -> NetworkPolicyDecision {
        for policy in &self.policies {
            if !policy.enabled {
                continue;
            }

            for rule in &policy.rules {
                if rule.matches(direction, source, destination, port) {
                    return NetworkPolicyDecision {
                        action: rule.action.clone(),
                        matched_policy_id: Some(policy.id.clone()),
                        matched_rule_id: Some(rule.id.clone()),
                        reason: format!("Matched rule {} in policy {}", rule.id, policy.id),
                    };
                }
            }
        }

        // No match — use the first enabled policy's default or Allow
        let default_action = self
            .policies
            .iter()
            .find(|p| p.enabled)
            .map(|p| p.default_action.clone())
            .unwrap_or(NetworkAction::Allow);

        NetworkPolicyDecision {
            action: default_action,
            matched_policy_id: None,
            matched_rule_id: None,
            reason: "No matching rule, using default action".into(),
        }
    }

    pub fn enabled_policies(&self) -> Vec<&L2NetworkPolicy> {
        self.policies.iter().filter(|p| p.enabled).collect()
    }

    pub fn rules_for_destination(&self, destination: &str) -> Vec<&NetworkRule> {
        self.policies
            .iter()
            .filter(|p| p.enabled)
            .flat_map(|p| p.rules.iter())
            .filter(|r| NetworkRule::matches_addr(&r.destination, destination))
            .collect()
    }

    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_rule(id: &str, dest: &str) -> NetworkRule {
        NetworkRule {
            id: id.into(),
            direction: TrafficDirection::Both,
            source: NetworkMatch::Any,
            destination: NetworkMatch::IpAddress(dest.into()),
            protocol: None,
            port_range: None,
            action: NetworkAction::Allow,
        }
    }

    fn deny_rule(id: &str, dest: &str) -> NetworkRule {
        NetworkRule {
            id: id.into(),
            direction: TrafficDirection::Inbound,
            source: NetworkMatch::Any,
            destination: NetworkMatch::IpAddress(dest.into()),
            protocol: None,
            port_range: None,
            action: NetworkAction::Deny,
        }
    }

    #[test]
    fn test_evaluate_matches_allow_rule() {
        let mut engine = NetworkPolicyEngine::new();
        engine.add_policy(
            L2NetworkPolicy::new("p1", "Policy 1", NetworkAction::Deny, 1, 1000)
                .with_rules(vec![allow_rule("r1", "10.0.0.1")]),
        );
        let decision = engine.evaluate(&TrafficDirection::Inbound, "1.2.3.4", "10.0.0.1", 443);
        assert_eq!(decision.action, NetworkAction::Allow);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("r1"));
    }

    #[test]
    fn test_evaluate_matches_deny_rule() {
        let mut engine = NetworkPolicyEngine::new();
        engine.add_policy(
            L2NetworkPolicy::new("p1", "Policy 1", NetworkAction::Allow, 1, 1000)
                .with_rules(vec![deny_rule("r1", "10.0.0.1")]),
        );
        let decision = engine.evaluate(&TrafficDirection::Inbound, "1.2.3.4", "10.0.0.1", 443);
        assert_eq!(decision.action, NetworkAction::Deny);
    }

    #[test]
    fn test_evaluate_uses_default_when_no_match() {
        let mut engine = NetworkPolicyEngine::new();
        engine.add_policy(
            L2NetworkPolicy::new("p1", "Policy 1", NetworkAction::Deny, 1, 1000)
                .with_rules(vec![allow_rule("r1", "10.0.0.1")]),
        );
        let decision = engine.evaluate(&TrafficDirection::Inbound, "1.2.3.4", "99.99.99.99", 443);
        assert_eq!(decision.action, NetworkAction::Deny);
        assert!(decision.matched_rule_id.is_none());
    }

    #[test]
    fn test_evaluate_respects_priority_order() {
        let mut engine = NetworkPolicyEngine::new();
        // Priority 2 (lower priority)
        engine.add_policy(
            L2NetworkPolicy::new("p2", "Low", NetworkAction::Allow, 2, 1000)
                .with_rules(vec![allow_rule("r1", "10.0.0.1")]),
        );
        // Priority 1 (higher priority, evaluated first)
        engine.add_policy(
            L2NetworkPolicy::new("p1", "High", NetworkAction::Deny, 1, 1000)
                .with_rules(vec![deny_rule("r2", "10.0.0.1")]),
        );
        let decision = engine.evaluate(&TrafficDirection::Inbound, "1.2.3.4", "10.0.0.1", 443);
        assert_eq!(decision.action, NetworkAction::Deny);
        assert_eq!(decision.matched_policy_id.as_deref(), Some("p1"));
    }

    #[test]
    fn test_enabled_policies_filters_disabled() {
        let mut engine = NetworkPolicyEngine::new();
        engine.add_policy(L2NetworkPolicy::new("p1", "A", NetworkAction::Allow, 1, 1000));
        engine.add_policy(L2NetworkPolicy::new("p2", "B", NetworkAction::Allow, 2, 1000).with_enabled(false));
        assert_eq!(engine.enabled_policies().len(), 1);
    }

    #[test]
    fn test_ip_address_matching() {
        let rule = allow_rule("r1", "10.0.0.1");
        assert!(rule.matches(&TrafficDirection::Inbound, "1.2.3.4", "10.0.0.1", 443));
        assert!(!rule.matches(&TrafficDirection::Inbound, "1.2.3.4", "10.0.0.2", 443));
    }

    #[test]
    fn test_hostname_matching() {
        let rule = NetworkRule {
            id: "r1".into(),
            direction: TrafficDirection::Both,
            source: NetworkMatch::Any,
            destination: NetworkMatch::Hostname("api.example.com".into()),
            protocol: None,
            port_range: None,
            action: NetworkAction::Allow,
        };
        assert!(rule.matches(&TrafficDirection::Inbound, "1.2.3.4", "api.example.com", 443));
        assert!(!rule.matches(&TrafficDirection::Inbound, "1.2.3.4", "other.com", 443));
    }

    #[test]
    fn test_decision_records_matched_ids() {
        let mut engine = NetworkPolicyEngine::new();
        engine.add_policy(
            L2NetworkPolicy::new("p1", "Policy", NetworkAction::Deny, 1, 1000)
                .with_rules(vec![allow_rule("r1", "10.0.0.1")]),
        );
        let decision = engine.evaluate(&TrafficDirection::Both, "1.2.3.4", "10.0.0.1", 80);
        assert_eq!(decision.matched_policy_id.as_deref(), Some("p1"));
        assert_eq!(decision.matched_rule_id.as_deref(), Some("r1"));
    }
}
