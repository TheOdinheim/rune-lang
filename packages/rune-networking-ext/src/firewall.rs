// ═══════════════════════════════════════════════════════════════════════
// Firewall — Software-defined firewall rules for packet-level governance.
// Evaluates inbound/outbound traffic against priority-ordered rules.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::connection::ConnectionProtocol;
use crate::traffic::is_in_cidr;

// ── Direction ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
    Both,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inbound => write!(f, "Inbound"),
            Self::Outbound => write!(f, "Outbound"),
            Self::Both => write!(f, "Both"),
        }
    }
}

// ── FirewallCondition ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FirewallCondition {
    SourceAddr(String),
    SourceCidr(String),
    DestAddr(String),
    DestCidr(String),
    DestPort(u16),
    DestPortRange { start: u16, end: u16 },
    Protocol(ConnectionProtocol),
    And(Vec<FirewallCondition>),
    Or(Vec<FirewallCondition>),
    Not(Box<FirewallCondition>),
    Any,
}

// ── FirewallAction ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallAction {
    Allow,
    Deny,
    Log,
    RateLimit { max_per_minute: u64 },
    Redirect { to_addr: String },
}

impl fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::Deny => write!(f, "Deny"),
            Self::Log => write!(f, "Log"),
            Self::RateLimit { max_per_minute } => write!(f, "RateLimit({max_per_minute}/min)"),
            Self::Redirect { to_addr } => write!(f, "Redirect({to_addr})"),
        }
    }
}

// ── FirewallRule ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub direction: Direction,
    pub condition: FirewallCondition,
    pub action: FirewallAction,
    pub priority: u32,
    pub enabled: bool,
    pub hit_count: u64,
    pub created_at: i64,
}

// ── FirewallDecision ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FirewallDecision {
    pub action: FirewallAction,
    pub matched_rule: Option<String>,
    pub detail: String,
}

// ── Condition evaluation ────────────────────────────────────────────

pub fn evaluate_firewall_condition(
    condition: &FirewallCondition,
    source: &str,
    dest: &str,
    dest_port: Option<u16>,
    protocol: &ConnectionProtocol,
) -> bool {
    match condition {
        FirewallCondition::SourceAddr(addr) => {
            let src_ip = source.split(':').next().unwrap_or(source);
            src_ip == addr
        }
        FirewallCondition::SourceCidr(cidr) => is_in_cidr(source, cidr),
        FirewallCondition::DestAddr(addr) => {
            let dst_ip = dest.split(':').next().unwrap_or(dest);
            dst_ip == addr
        }
        FirewallCondition::DestCidr(cidr) => is_in_cidr(dest, cidr),
        FirewallCondition::DestPort(port) => dest_port == Some(*port),
        FirewallCondition::DestPortRange { start, end } => {
            dest_port.is_some_and(|p| p >= *start && p <= *end)
        }
        FirewallCondition::Protocol(p) => protocol == p,
        FirewallCondition::And(conditions) => conditions
            .iter()
            .all(|c| evaluate_firewall_condition(c, source, dest, dest_port, protocol)),
        FirewallCondition::Or(conditions) => conditions
            .iter()
            .any(|c| evaluate_firewall_condition(c, source, dest, dest_port, protocol)),
        FirewallCondition::Not(inner) => {
            !evaluate_firewall_condition(inner, source, dest, dest_port, protocol)
        }
        FirewallCondition::Any => true,
    }
}

// ── Firewall ────────────────────────────────────────────────────────

pub struct Firewall {
    rules: Vec<FirewallRule>,
    default_action: FirewallAction,
}

impl Firewall {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: FirewallAction::Deny,
        }
    }

    pub fn with_default(action: FirewallAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action: action,
        }
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, id: &str) -> Option<FirewallRule> {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            Some(self.rules.remove(pos))
        } else {
            None
        }
    }

    pub fn evaluate(
        &mut self,
        direction: Direction,
        source: &str,
        dest: &str,
        dest_port: Option<u16>,
        protocol: &ConnectionProtocol,
    ) -> FirewallDecision {
        let mut sorted_indices: Vec<usize> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.enabled && (r.direction == direction || r.direction == Direction::Both))
            .map(|(i, _)| i)
            .collect();
        sorted_indices.sort_by(|a, b| self.rules[*b].priority.cmp(&self.rules[*a].priority));

        for idx in sorted_indices {
            if evaluate_firewall_condition(
                &self.rules[idx].condition,
                source,
                dest,
                dest_port,
                protocol,
            ) {
                self.rules[idx].hit_count += 1;
                let rule = &self.rules[idx];
                return FirewallDecision {
                    action: rule.action.clone(),
                    matched_rule: Some(rule.id.clone()),
                    detail: format!("Matched rule: {}", rule.name),
                };
            }
        }

        FirewallDecision {
            action: self.default_action.clone(),
            matched_rule: None,
            detail: "No rule matched, using default".into(),
        }
    }

    pub fn rules_by_priority(&self) -> Vec<&FirewallRule> {
        let mut sorted: Vec<&FirewallRule> = self.rules.iter().collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
        sorted
    }

    pub fn top_hit_rules(&self, n: usize) -> Vec<&FirewallRule> {
        let mut sorted: Vec<&FirewallRule> = self.rules.iter().collect();
        sorted.sort_by(|a, b| b.hit_count.cmp(&a.hit_count));
        sorted.into_iter().take(n).collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn enabled_rules(&self) -> Vec<&FirewallRule> {
        self.rules.iter().filter(|r| r.enabled).collect()
    }
}

impl Default for Firewall {
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

    fn make_rule(id: &str, condition: FirewallCondition, action: FirewallAction, priority: u32) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            name: id.into(),
            description: String::new(),
            direction: Direction::Inbound,
            condition,
            action,
            priority,
            enabled: true,
            hit_count: 0,
            created_at: 1000,
        }
    }

    #[test]
    fn test_evaluate_matches_by_priority() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule("low", FirewallCondition::Any, FirewallAction::Log, 1));
        fw.add_rule(make_rule("high", FirewallCondition::Any, FirewallAction::Allow, 100));
        let d = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", None, &ConnectionProtocol::Tcp);
        assert_eq!(d.action, FirewallAction::Allow);
        assert_eq!(d.matched_rule.as_deref(), Some("high"));
    }

    #[test]
    fn test_evaluate_returns_default_no_match() {
        let mut fw = Firewall::new(); // default Deny
        let d = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", None, &ConnectionProtocol::Tcp);
        assert_eq!(d.action, FirewallAction::Deny);
        assert!(d.matched_rule.is_none());
    }

    #[test]
    fn test_evaluate_increments_hit_count() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule("r1", FirewallCondition::Any, FirewallAction::Allow, 10));
        fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", None, &ConnectionProtocol::Tcp);
        fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", None, &ConnectionProtocol::Tcp);
        assert_eq!(fw.rules[0].hit_count, 2);
    }

    #[test]
    fn test_evaluate_source_addr() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule(
            "block_src",
            FirewallCondition::SourceAddr("1.2.3.4".into()),
            FirewallAction::Deny,
            10,
        ));
        let d = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", None, &ConnectionProtocol::Tcp);
        assert_eq!(d.action, FirewallAction::Deny);
        assert!(d.matched_rule.is_some());
    }

    #[test]
    fn test_evaluate_source_cidr() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule(
            "allow_internal",
            FirewallCondition::SourceCidr("10.0.0.0/8".into()),
            FirewallAction::Allow,
            10,
        ));
        let d = fw.evaluate(Direction::Inbound, "10.1.2.3", "5.6.7.8", None, &ConnectionProtocol::Tcp);
        assert_eq!(d.action, FirewallAction::Allow);
    }

    #[test]
    fn test_evaluate_dest_port() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule(
            "allow_https",
            FirewallCondition::DestPort(443),
            FirewallAction::Allow,
            10,
        ));
        let d = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", Some(443), &ConnectionProtocol::Tcp);
        assert_eq!(d.action, FirewallAction::Allow);
        let d2 = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", Some(80), &ConnectionProtocol::Tcp);
        assert_eq!(d2.action, FirewallAction::Deny); // default
    }

    #[test]
    fn test_evaluate_dest_port_range() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule(
            "allow_range",
            FirewallCondition::DestPortRange { start: 8000, end: 9000 },
            FirewallAction::Allow,
            10,
        ));
        let d = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", Some(8080), &ConnectionProtocol::Tcp);
        assert_eq!(d.action, FirewallAction::Allow);
        let d2 = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", Some(7999), &ConnectionProtocol::Tcp);
        assert_eq!(d2.action, FirewallAction::Deny);
    }

    #[test]
    fn test_evaluate_protocol() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule(
            "allow_tls",
            FirewallCondition::Protocol(ConnectionProtocol::Tls),
            FirewallAction::Allow,
            10,
        ));
        let d = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", None, &ConnectionProtocol::Tls);
        assert_eq!(d.action, FirewallAction::Allow);
        let d2 = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", None, &ConnectionProtocol::Tcp);
        assert_eq!(d2.action, FirewallAction::Deny);
    }

    #[test]
    fn test_evaluate_and_or_not() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule(
            "complex",
            FirewallCondition::And(vec![
                FirewallCondition::SourceCidr("10.0.0.0/8".into()),
                FirewallCondition::DestPort(443),
            ]),
            FirewallAction::Allow,
            10,
        ));
        let d = fw.evaluate(Direction::Inbound, "10.1.2.3", "5.6.7.8", Some(443), &ConnectionProtocol::Tcp);
        assert_eq!(d.action, FirewallAction::Allow);
        let d2 = fw.evaluate(Direction::Inbound, "10.1.2.3", "5.6.7.8", Some(80), &ConnectionProtocol::Tcp);
        assert_eq!(d2.action, FirewallAction::Deny);
    }

    #[test]
    fn test_evaluate_any_matches_everything() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule("catch_all", FirewallCondition::Any, FirewallAction::Log, 1));
        let d = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", None, &ConnectionProtocol::Tcp);
        assert_eq!(d.action, FirewallAction::Log);
    }

    #[test]
    fn test_rules_by_priority() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule("low", FirewallCondition::Any, FirewallAction::Log, 1));
        fw.add_rule(make_rule("high", FirewallCondition::Any, FirewallAction::Allow, 100));
        fw.add_rule(make_rule("mid", FirewallCondition::Any, FirewallAction::Deny, 50));
        let sorted = fw.rules_by_priority();
        assert_eq!(sorted[0].id, "high");
        assert_eq!(sorted[1].id, "mid");
        assert_eq!(sorted[2].id, "low");
    }

    #[test]
    fn test_top_hit_rules() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule("r1", FirewallCondition::Any, FirewallAction::Allow, 10));
        fw.add_rule(make_rule("r2", FirewallCondition::DestPort(80), FirewallAction::Log, 20));
        // r2 matches first (higher priority) when port is 80
        fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", Some(80), &ConnectionProtocol::Tcp);
        fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", Some(80), &ConnectionProtocol::Tcp);
        fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", Some(443), &ConnectionProtocol::Tcp);
        let top = fw.top_hit_rules(1);
        assert_eq!(top[0].id, "r2");
    }

    #[test]
    fn test_remove_rule() {
        let mut fw = Firewall::new();
        fw.add_rule(make_rule("r1", FirewallCondition::Any, FirewallAction::Allow, 10));
        assert_eq!(fw.rule_count(), 1);
        let removed = fw.remove_rule("r1");
        assert!(removed.is_some());
        assert_eq!(fw.rule_count(), 0);
    }

    #[test]
    fn test_direction_display() {
        let dirs = vec![Direction::Inbound, Direction::Outbound, Direction::Both];
        for d in &dirs {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(dirs.len(), 3);
    }

    #[test]
    fn test_firewall_action_display() {
        let actions = vec![
            FirewallAction::Allow,
            FirewallAction::Deny,
            FirewallAction::Log,
            FirewallAction::RateLimit { max_per_minute: 100 },
            FirewallAction::Redirect { to_addr: "10.0.0.1".into() },
        ];
        for a in &actions {
            assert!(!a.to_string().is_empty());
        }
        assert_eq!(actions.len(), 5);
    }

    #[test]
    fn test_default_deny_behavior() {
        let mut fw = Firewall::new();
        let d = fw.evaluate(Direction::Inbound, "1.2.3.4", "5.6.7.8", None, &ConnectionProtocol::Tcp);
        assert_eq!(d.action, FirewallAction::Deny);
    }
}
