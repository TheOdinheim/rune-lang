// ═══════════════════════════════════════════════════════════════════════
// Traffic — Traffic classification by trust level.
// Classifies network traffic using configurable rules to assign
// trust levels that drive downstream governance decisions.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::connection::ConnectionProtocol;

// ── TrustLevel ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    Untrusted = 0,
    Restricted = 1,
    Conditional = 2,
    Trusted = 3,
    Privileged = 4,
}

impl Ord for TrustLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl PartialOrd for TrustLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted => write!(f, "Untrusted"),
            Self::Restricted => write!(f, "Restricted"),
            Self::Conditional => write!(f, "Conditional"),
            Self::Trusted => write!(f, "Trusted"),
            Self::Privileged => write!(f, "Privileged"),
        }
    }
}

// ── TrafficCondition ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TrafficCondition {
    SourceInRange { cidr: String },
    SourceEquals { addr: String },
    DestinationPort { port: u16 },
    DestinationPortRange { start: u16, end: u16 },
    Protocol(ConnectionProtocol),
    HasIdentity,
    HasMtls,
    HeaderEquals { header: String, value: String },
    And(Vec<TrafficCondition>),
    Or(Vec<TrafficCondition>),
    Not(Box<TrafficCondition>),
}

// ── TrafficRule ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub condition: TrafficCondition,
    pub assigned_trust: TrustLevel,
    pub priority: u32,
    pub enabled: bool,
}

// ── TrafficClassification ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrafficClassification {
    pub trust_level: TrustLevel,
    pub matched_rule: Option<String>,
    pub detail: String,
}

// ── CIDR matching ───────────────────────────────────────────────────

pub fn is_in_cidr(addr: &str, cidr: &str) -> bool {
    // Strip port if present (e.g., "10.0.0.1:5000" → "10.0.0.1")
    let addr_ip = addr.split(':').next().unwrap_or(addr);

    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let base = parts[0];
    let prefix_len: u32 = match parts[1].parse() {
        Ok(p) if p <= 32 => p,
        _ => return false,
    };

    let addr_num = match ip_to_u32(addr_ip) {
        Some(n) => n,
        None => return false,
    };
    let base_num = match ip_to_u32(base) {
        Some(n) => n,
        None => return false,
    };

    if prefix_len == 0 {
        return true;
    }
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    (addr_num & mask) == (base_num & mask)
}

fn ip_to_u32(ip: &str) -> Option<u32> {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut result = 0u32;
    for octet in &octets {
        let val: u8 = octet.parse().ok()?;
        result = (result << 8) | val as u32;
    }
    Some(result)
}

// ── Condition evaluation ────────────────────────────────────────────

pub fn evaluate_traffic_condition(
    condition: &TrafficCondition,
    source: &str,
    dest_port: Option<u16>,
    protocol: &ConnectionProtocol,
    has_identity: bool,
    has_mtls: bool,
) -> bool {
    match condition {
        TrafficCondition::SourceInRange { cidr } => is_in_cidr(source, cidr),
        TrafficCondition::SourceEquals { addr } => {
            let source_ip = source.split(':').next().unwrap_or(source);
            source_ip == addr
        }
        TrafficCondition::DestinationPort { port } => dest_port == Some(*port),
        TrafficCondition::DestinationPortRange { start, end } => {
            dest_port.is_some_and(|p| p >= *start && p <= *end)
        }
        TrafficCondition::Protocol(p) => protocol == p,
        TrafficCondition::HasIdentity => has_identity,
        TrafficCondition::HasMtls => has_mtls,
        TrafficCondition::HeaderEquals { .. } => false, // headers not available at this level
        TrafficCondition::And(conditions) => conditions
            .iter()
            .all(|c| evaluate_traffic_condition(c, source, dest_port, protocol, has_identity, has_mtls)),
        TrafficCondition::Or(conditions) => conditions
            .iter()
            .any(|c| evaluate_traffic_condition(c, source, dest_port, protocol, has_identity, has_mtls)),
        TrafficCondition::Not(inner) => {
            !evaluate_traffic_condition(inner, source, dest_port, protocol, has_identity, has_mtls)
        }
    }
}

// ── TrafficClassifier ───────────────────────────────────────────────

pub struct TrafficClassifier {
    rules: Vec<TrafficRule>,
    default_trust: TrustLevel,
}

impl TrafficClassifier {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_trust: TrustLevel::Untrusted,
        }
    }

    pub fn with_default(trust: TrustLevel) -> Self {
        Self {
            rules: Vec::new(),
            default_trust: trust,
        }
    }

    pub fn add_rule(&mut self, rule: TrafficRule) {
        self.rules.push(rule);
    }

    pub fn classify(&self, connection: &crate::connection::Connection) -> TrafficClassification {
        let has_mtls = connection.protocol == ConnectionProtocol::MTls;
        let has_identity = connection.identity.is_some();
        // Extract port from dest_addr (e.g., "5.6.7.8:443" → 443)
        let dest_port = connection
            .dest_addr
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok());

        self.classify_by_attrs(
            &connection.source_addr,
            dest_port,
            &connection.protocol,
            has_identity,
            has_mtls,
        )
    }

    pub fn classify_by_attrs(
        &self,
        source: &str,
        dest_port: Option<u16>,
        protocol: &ConnectionProtocol,
        has_identity: bool,
        has_mtls: bool,
    ) -> TrafficClassification {
        let mut sorted: Vec<&TrafficRule> = self.rules.iter().filter(|r| r.enabled).collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in sorted {
            if evaluate_traffic_condition(
                &rule.condition,
                source,
                dest_port,
                protocol,
                has_identity,
                has_mtls,
            ) {
                return TrafficClassification {
                    trust_level: rule.assigned_trust,
                    matched_rule: Some(rule.id.clone()),
                    detail: format!("Matched rule: {}", rule.name),
                };
            }
        }
        TrafficClassification {
            trust_level: self.default_trust,
            matched_rule: None,
            detail: "No rule matched, using default".into(),
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for TrafficClassifier {
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

    fn make_rule(id: &str, condition: TrafficCondition, trust: TrustLevel, priority: u32) -> TrafficRule {
        TrafficRule {
            id: id.into(),
            name: id.into(),
            description: String::new(),
            condition,
            assigned_trust: trust,
            priority,
            enabled: true,
        }
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Untrusted < TrustLevel::Restricted);
        assert!(TrustLevel::Restricted < TrustLevel::Conditional);
        assert!(TrustLevel::Conditional < TrustLevel::Trusted);
        assert!(TrustLevel::Trusted < TrustLevel::Privileged);
    }

    #[test]
    fn test_classify_with_matching_rule() {
        let mut c = TrafficClassifier::new();
        c.add_rule(make_rule(
            "internal",
            TrafficCondition::SourceInRange { cidr: "10.0.0.0/8".into() },
            TrustLevel::Trusted,
            10,
        ));
        let result = c.classify_by_attrs("10.1.2.3", None, &ConnectionProtocol::Tcp, false, false);
        assert_eq!(result.trust_level, TrustLevel::Trusted);
        assert_eq!(result.matched_rule.as_deref(), Some("internal"));
    }

    #[test]
    fn test_classify_no_match_returns_default() {
        let c = TrafficClassifier::with_default(TrustLevel::Restricted);
        let result = c.classify_by_attrs("8.8.8.8", None, &ConnectionProtocol::Tcp, false, false);
        assert_eq!(result.trust_level, TrustLevel::Restricted);
        assert!(result.matched_rule.is_none());
    }

    #[test]
    fn test_classify_respects_priority() {
        let mut c = TrafficClassifier::new();
        c.add_rule(make_rule(
            "low",
            TrafficCondition::SourceInRange { cidr: "10.0.0.0/8".into() },
            TrustLevel::Restricted,
            1,
        ));
        c.add_rule(make_rule(
            "high",
            TrafficCondition::SourceInRange { cidr: "10.0.0.0/8".into() },
            TrustLevel::Privileged,
            100,
        ));
        let result = c.classify_by_attrs("10.1.2.3", None, &ConnectionProtocol::Tcp, false, false);
        assert_eq!(result.trust_level, TrustLevel::Privileged);
        assert_eq!(result.matched_rule.as_deref(), Some("high"));
    }

    #[test]
    fn test_source_in_range_matches_cidr() {
        assert!(evaluate_traffic_condition(
            &TrafficCondition::SourceInRange { cidr: "10.0.0.0/8".into() },
            "10.5.3.1", None, &ConnectionProtocol::Tcp, false, false,
        ));
    }

    #[test]
    fn test_source_equals_matches_exact() {
        assert!(evaluate_traffic_condition(
            &TrafficCondition::SourceEquals { addr: "1.2.3.4".into() },
            "1.2.3.4", None, &ConnectionProtocol::Tcp, false, false,
        ));
        assert!(!evaluate_traffic_condition(
            &TrafficCondition::SourceEquals { addr: "1.2.3.4".into() },
            "5.6.7.8", None, &ConnectionProtocol::Tcp, false, false,
        ));
    }

    #[test]
    fn test_destination_port_matches() {
        assert!(evaluate_traffic_condition(
            &TrafficCondition::DestinationPort { port: 443 },
            "1.2.3.4", Some(443), &ConnectionProtocol::Tcp, false, false,
        ));
        assert!(!evaluate_traffic_condition(
            &TrafficCondition::DestinationPort { port: 443 },
            "1.2.3.4", Some(80), &ConnectionProtocol::Tcp, false, false,
        ));
    }

    #[test]
    fn test_protocol_matches() {
        assert!(evaluate_traffic_condition(
            &TrafficCondition::Protocol(ConnectionProtocol::Tls),
            "1.2.3.4", None, &ConnectionProtocol::Tls, false, false,
        ));
        assert!(!evaluate_traffic_condition(
            &TrafficCondition::Protocol(ConnectionProtocol::Tls),
            "1.2.3.4", None, &ConnectionProtocol::Tcp, false, false,
        ));
    }

    #[test]
    fn test_has_identity_and_has_mtls() {
        assert!(evaluate_traffic_condition(
            &TrafficCondition::HasIdentity,
            "1.2.3.4", None, &ConnectionProtocol::Tcp, true, false,
        ));
        assert!(!evaluate_traffic_condition(
            &TrafficCondition::HasIdentity,
            "1.2.3.4", None, &ConnectionProtocol::Tcp, false, false,
        ));
        assert!(evaluate_traffic_condition(
            &TrafficCondition::HasMtls,
            "1.2.3.4", None, &ConnectionProtocol::MTls, false, true,
        ));
    }

    #[test]
    fn test_and_or_not_combinators() {
        let cond = TrafficCondition::And(vec![
            TrafficCondition::HasIdentity,
            TrafficCondition::Protocol(ConnectionProtocol::Tls),
        ]);
        assert!(evaluate_traffic_condition(&cond, "1.2.3.4", None, &ConnectionProtocol::Tls, true, false));
        assert!(!evaluate_traffic_condition(&cond, "1.2.3.4", None, &ConnectionProtocol::Tls, false, false));

        let or_cond = TrafficCondition::Or(vec![
            TrafficCondition::HasIdentity,
            TrafficCondition::HasMtls,
        ]);
        assert!(evaluate_traffic_condition(&or_cond, "1.2.3.4", None, &ConnectionProtocol::Tcp, true, false));
        assert!(evaluate_traffic_condition(&or_cond, "1.2.3.4", None, &ConnectionProtocol::Tcp, false, true));
        assert!(!evaluate_traffic_condition(&or_cond, "1.2.3.4", None, &ConnectionProtocol::Tcp, false, false));

        let not_cond = TrafficCondition::Not(Box::new(TrafficCondition::HasIdentity));
        assert!(evaluate_traffic_condition(&not_cond, "1.2.3.4", None, &ConnectionProtocol::Tcp, false, false));
        assert!(!evaluate_traffic_condition(&not_cond, "1.2.3.4", None, &ConnectionProtocol::Tcp, true, false));
    }

    #[test]
    fn test_is_in_cidr_10_0_0_0_8() {
        assert!(is_in_cidr("10.0.0.1", "10.0.0.0/8"));
        assert!(is_in_cidr("10.255.255.255", "10.0.0.0/8"));
        assert!(!is_in_cidr("11.0.0.1", "10.0.0.0/8"));
    }

    #[test]
    fn test_is_in_cidr_192_168_1_0_24() {
        assert!(is_in_cidr("192.168.1.100", "192.168.1.0/24"));
        assert!(is_in_cidr("192.168.1.0", "192.168.1.0/24"));
        assert!(!is_in_cidr("192.168.2.1", "192.168.1.0/24"));
    }

    #[test]
    fn test_is_in_cidr_rejects_out_of_range() {
        assert!(!is_in_cidr("172.16.0.1", "10.0.0.0/8"));
    }

    #[test]
    fn test_is_in_cidr_handles_invalid_input() {
        assert!(!is_in_cidr("not-an-ip", "10.0.0.0/8"));
        assert!(!is_in_cidr("10.0.0.1", "bad-cidr"));
        assert!(!is_in_cidr("10.0.0.1", "10.0.0.0/33"));
    }
}
