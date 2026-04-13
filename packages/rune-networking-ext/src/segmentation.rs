// ═══════════════════════════════════════════════════════════════════════
// Segmentation — Network segmentation policy enforcement.
// Controls which zones can communicate and under what conditions.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::connection::ConnectionProtocol;
use crate::traffic::{TrustLevel, is_in_cidr};

// ── ZoneType ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ZoneType {
    Public,
    Dmz,
    Internal,
    Restricted,
    AirGapped,
    Management,
    Custom(String),
}

impl fmt::Display for ZoneType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "Public"),
            Self::Dmz => write!(f, "DMZ"),
            Self::Internal => write!(f, "Internal"),
            Self::Restricted => write!(f, "Restricted"),
            Self::AirGapped => write!(f, "AirGapped"),
            Self::Management => write!(f, "Management"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ── NetworkZone ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkZone {
    pub id: String,
    pub name: String,
    pub description: String,
    pub zone_type: ZoneType,
    pub cidrs: Vec<String>,
    pub min_trust_level: TrustLevel,
    pub metadata: HashMap<String, String>,
}

// ── ZoneFlow ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneFlow {
    pub source_zone: String,
    pub dest_zone: String,
    pub allowed_ports: Vec<u16>,
    pub allowed_protocols: Vec<ConnectionProtocol>,
    pub requires_encryption: bool,
}

// ── SegmentationAction ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentationAction {
    Allow,
    Deny,
    Audit,
}

impl fmt::Display for SegmentationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::Deny => write!(f, "Deny"),
            Self::Audit => write!(f, "Audit"),
        }
    }
}

// ── SegmentationPolicy ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationPolicy {
    pub id: String,
    pub name: String,
    pub allowed_flows: Vec<ZoneFlow>,
    pub denied_flows: Vec<ZoneFlow>,
    pub default_action: SegmentationAction,
    pub metadata: HashMap<String, String>,
}

// ── SegmentationDecision ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SegmentationDecision {
    pub allowed: bool,
    pub source_zone: Option<String>,
    pub dest_zone: Option<String>,
    pub action: SegmentationAction,
    pub detail: String,
    pub matched_flow: Option<String>,
}

// ── SegmentationEnforcer ────────────────────────────────────────────

pub struct SegmentationEnforcer {
    zones: HashMap<String, NetworkZone>,
    policy: SegmentationPolicy,
}

impl SegmentationEnforcer {
    pub fn new(policy: SegmentationPolicy) -> Self {
        Self {
            zones: HashMap::new(),
            policy,
        }
    }

    pub fn add_zone(&mut self, zone: NetworkZone) {
        self.zones.insert(zone.id.clone(), zone);
    }

    pub fn get_zone(&self, id: &str) -> Option<&NetworkZone> {
        self.zones.get(id)
    }

    pub fn zone_for_addr(&self, addr: &str) -> Option<&NetworkZone> {
        self.zones.values().find(|z| {
            z.cidrs.iter().any(|cidr| is_in_cidr(addr, cidr))
        })
    }

    pub fn check_flow(
        &self,
        source_addr: &str,
        dest_addr: &str,
        dest_port: Option<u16>,
        protocol: &ConnectionProtocol,
    ) -> SegmentationDecision {
        let source_zone = self.zone_for_addr(source_addr);
        let dest_zone = self.zone_for_addr(dest_addr);

        let src_id = source_zone.map(|z| z.id.clone());
        let dst_id = dest_zone.map(|z| z.id.clone());

        // If either address is not in a known zone, use default action
        let (src, dst) = match (&src_id, &dst_id) {
            (Some(s), Some(d)) => (s.as_str(), d.as_str()),
            _ => {
                return SegmentationDecision {
                    allowed: self.policy.default_action != SegmentationAction::Deny,
                    source_zone: src_id,
                    dest_zone: dst_id,
                    action: self.policy.default_action.clone(),
                    detail: "One or both addresses not in a known zone".into(),
                    matched_flow: None,
                };
            }
        };

        // Check denied flows first (denied takes precedence)
        for flow in &self.policy.denied_flows {
            if flow.source_zone == src && flow.dest_zone == dst {
                if flow_matches_port_protocol(flow, dest_port, protocol) {
                    return SegmentationDecision {
                        allowed: false,
                        source_zone: Some(src.into()),
                        dest_zone: Some(dst.into()),
                        action: SegmentationAction::Deny,
                        detail: format!("Denied flow: {src}→{dst}"),
                        matched_flow: Some(format!("denied:{src}→{dst}")),
                    };
                }
            }
        }

        // Check allowed flows
        for flow in &self.policy.allowed_flows {
            if flow.source_zone == src && flow.dest_zone == dst {
                if flow_matches_port_protocol(flow, dest_port, protocol) {
                    return SegmentationDecision {
                        allowed: true,
                        source_zone: Some(src.into()),
                        dest_zone: Some(dst.into()),
                        action: SegmentationAction::Allow,
                        detail: format!("Allowed flow: {src}→{dst}"),
                        matched_flow: Some(format!("allowed:{src}→{dst}")),
                    };
                }
            }
        }

        // Default action
        SegmentationDecision {
            allowed: self.policy.default_action != SegmentationAction::Deny,
            source_zone: Some(src.into()),
            dest_zone: Some(dst.into()),
            action: self.policy.default_action.clone(),
            detail: format!("No matching flow rule for {src}→{dst}, using default"),
            matched_flow: None,
        }
    }

    pub fn allowed_destinations(&self, source_zone: &str) -> Vec<&str> {
        self.policy
            .allowed_flows
            .iter()
            .filter(|f| f.source_zone == source_zone)
            .map(|f| f.dest_zone.as_str())
            .collect()
    }

    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }
}

fn flow_matches_port_protocol(
    flow: &ZoneFlow,
    dest_port: Option<u16>,
    protocol: &ConnectionProtocol,
) -> bool {
    let port_ok = flow.allowed_ports.is_empty()
        || dest_port.is_some_and(|p| flow.allowed_ports.contains(&p));
    let proto_ok = flow.allowed_protocols.is_empty()
        || flow.allowed_protocols.contains(protocol);
    port_ok && proto_ok
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_zone(id: &str, zone_type: ZoneType, cidrs: Vec<&str>) -> NetworkZone {
        NetworkZone {
            id: id.into(),
            name: id.into(),
            description: String::new(),
            zone_type,
            cidrs: cidrs.into_iter().map(String::from).collect(),
            min_trust_level: TrustLevel::Untrusted,
            metadata: HashMap::new(),
        }
    }

    fn make_flow(src: &str, dst: &str) -> ZoneFlow {
        ZoneFlow {
            source_zone: src.into(),
            dest_zone: dst.into(),
            allowed_ports: Vec::new(),
            allowed_protocols: Vec::new(),
            requires_encryption: false,
        }
    }

    fn default_policy() -> SegmentationPolicy {
        SegmentationPolicy {
            id: "test".into(),
            name: "Test Policy".into(),
            allowed_flows: vec![make_flow("dmz", "internal")],
            denied_flows: Vec::new(),
            default_action: SegmentationAction::Deny,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_add_zone_and_get_zone() {
        let mut enforcer = SegmentationEnforcer::new(default_policy());
        enforcer.add_zone(make_zone("dmz", ZoneType::Dmz, vec!["172.16.0.0/16"]));
        assert!(enforcer.get_zone("dmz").is_some());
        assert!(enforcer.get_zone("unknown").is_none());
    }

    #[test]
    fn test_zone_for_addr_finds_correct_zone() {
        let mut enforcer = SegmentationEnforcer::new(default_policy());
        enforcer.add_zone(make_zone("dmz", ZoneType::Dmz, vec!["172.16.0.0/16"]));
        enforcer.add_zone(make_zone("internal", ZoneType::Internal, vec!["10.0.0.0/8"]));
        let z = enforcer.zone_for_addr("10.1.2.3").unwrap();
        assert_eq!(z.id, "internal");
    }

    #[test]
    fn test_check_flow_allows_permitted_flow() {
        let mut enforcer = SegmentationEnforcer::new(default_policy());
        enforcer.add_zone(make_zone("dmz", ZoneType::Dmz, vec!["172.16.0.0/16"]));
        enforcer.add_zone(make_zone("internal", ZoneType::Internal, vec!["10.0.0.0/8"]));
        let decision = enforcer.check_flow("172.16.1.1", "10.0.0.1", None, &ConnectionProtocol::Tcp);
        assert!(decision.allowed);
    }

    #[test]
    fn test_check_flow_denies_non_permitted() {
        let mut enforcer = SegmentationEnforcer::new(default_policy());
        enforcer.add_zone(make_zone("dmz", ZoneType::Dmz, vec!["172.16.0.0/16"]));
        enforcer.add_zone(make_zone("internal", ZoneType::Internal, vec!["10.0.0.0/8"]));
        // internal→dmz is not in allowed_flows, default is Deny
        let decision = enforcer.check_flow("10.0.0.1", "172.16.1.1", None, &ConnectionProtocol::Tcp);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_check_flow_uses_default_when_no_rule() {
        let policy = SegmentationPolicy {
            id: "p".into(),
            name: "P".into(),
            allowed_flows: Vec::new(),
            denied_flows: Vec::new(),
            default_action: SegmentationAction::Allow,
            metadata: HashMap::new(),
        };
        let mut enforcer = SegmentationEnforcer::new(policy);
        enforcer.add_zone(make_zone("a", ZoneType::Internal, vec!["10.0.0.0/8"]));
        enforcer.add_zone(make_zone("b", ZoneType::Dmz, vec!["172.16.0.0/16"]));
        let decision = enforcer.check_flow("10.0.0.1", "172.16.1.1", None, &ConnectionProtocol::Tcp);
        assert!(decision.allowed);
        assert_eq!(decision.action, SegmentationAction::Allow);
    }

    #[test]
    fn test_allowed_destinations() {
        let enforcer = SegmentationEnforcer::new(default_policy());
        let dests = enforcer.allowed_destinations("dmz");
        assert_eq!(dests, vec!["internal"]);
    }

    #[test]
    fn test_zone_type_display() {
        let types = vec![
            ZoneType::Public,
            ZoneType::Dmz,
            ZoneType::Internal,
            ZoneType::Restricted,
            ZoneType::AirGapped,
            ZoneType::Management,
            ZoneType::Custom("HQ".into()),
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 7);
    }

    #[test]
    fn test_segmentation_action_display() {
        let actions = vec![
            SegmentationAction::Allow,
            SegmentationAction::Deny,
            SegmentationAction::Audit,
        ];
        for a in &actions {
            assert!(!a.to_string().is_empty());
        }
        assert_eq!(actions.len(), 3);
    }

    #[test]
    fn test_zone_flow_with_port_and_protocol_restrictions() {
        let policy = SegmentationPolicy {
            id: "p".into(),
            name: "P".into(),
            allowed_flows: vec![ZoneFlow {
                source_zone: "dmz".into(),
                dest_zone: "internal".into(),
                allowed_ports: vec![443],
                allowed_protocols: vec![ConnectionProtocol::Tls],
                requires_encryption: true,
            }],
            denied_flows: Vec::new(),
            default_action: SegmentationAction::Deny,
            metadata: HashMap::new(),
        };
        let mut enforcer = SegmentationEnforcer::new(policy);
        enforcer.add_zone(make_zone("dmz", ZoneType::Dmz, vec!["172.16.0.0/16"]));
        enforcer.add_zone(make_zone("internal", ZoneType::Internal, vec!["10.0.0.0/8"]));

        // Allowed: TLS on port 443
        let d = enforcer.check_flow("172.16.1.1", "10.0.0.1", Some(443), &ConnectionProtocol::Tls);
        assert!(d.allowed);

        // Denied: wrong port
        let d = enforcer.check_flow("172.16.1.1", "10.0.0.1", Some(80), &ConnectionProtocol::Tls);
        assert!(!d.allowed);

        // Denied: wrong protocol
        let d = enforcer.check_flow("172.16.1.1", "10.0.0.1", Some(443), &ConnectionProtocol::Tcp);
        assert!(!d.allowed);
    }

    #[test]
    fn test_denied_flow_takes_precedence() {
        let policy = SegmentationPolicy {
            id: "p".into(),
            name: "P".into(),
            allowed_flows: vec![make_flow("dmz", "internal")],
            denied_flows: vec![make_flow("dmz", "internal")],
            default_action: SegmentationAction::Allow,
            metadata: HashMap::new(),
        };
        let mut enforcer = SegmentationEnforcer::new(policy);
        enforcer.add_zone(make_zone("dmz", ZoneType::Dmz, vec!["172.16.0.0/16"]));
        enforcer.add_zone(make_zone("internal", ZoneType::Internal, vec!["10.0.0.0/8"]));
        let d = enforcer.check_flow("172.16.1.1", "10.0.0.1", None, &ConnectionProtocol::Tcp);
        assert!(!d.allowed);
    }
}
