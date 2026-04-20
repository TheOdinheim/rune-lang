// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Network segmentation policy.
//
// Network segmentation with zone definitions, trust levels,
// inter-zone traffic policies, and violation detection.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::l2_policy::NetworkAction;

// ── ZoneTrustLevel ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZoneTrustLevel {
    Untrusted = 0,
    Dmz = 1,
    Internal = 2,
    Restricted = 3,
    HighSecurity = 4,
}

impl fmt::Display for ZoneTrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Untrusted => "Untrusted",
            Self::Dmz => "DMZ",
            Self::Internal => "Internal",
            Self::Restricted => "Restricted",
            Self::HighSecurity => "HighSecurity",
        };
        f.write_str(s)
    }
}

// ── L2NetworkZone ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2NetworkZone {
    pub id: String,
    pub name: String,
    pub trust_level: ZoneTrustLevel,
    pub allowed_egress_zones: Vec<String>,
    pub allowed_ingress_zones: Vec<String>,
    pub tags: Vec<String>,
}

impl L2NetworkZone {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        trust_level: ZoneTrustLevel,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            trust_level,
            allowed_egress_zones: Vec::new(),
            allowed_ingress_zones: Vec::new(),
            tags: Vec::new(),
        }
    }

    pub fn with_egress(mut self, zones: Vec<String>) -> Self {
        self.allowed_egress_zones = zones;
        self
    }

    pub fn with_ingress(mut self, zones: Vec<String>) -> Self {
        self.allowed_ingress_zones = zones;
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

// ── InterZoneRule ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InterZoneRule {
    pub from_zone: String,
    pub to_zone: String,
    pub action: NetworkAction,
    pub protocols: Vec<String>,
    pub justification: String,
}

// ── SegmentationViolation ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SegmentationViolation {
    pub from_zone: String,
    pub to_zone: String,
    pub violation_type: String,
    pub description: String,
}

// ── L2SegmentationPolicy ─────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2SegmentationPolicy {
    zones: HashMap<String, L2NetworkZone>,
    inter_zone_rules: Vec<InterZoneRule>,
}

impl L2SegmentationPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_zone(&mut self, zone: L2NetworkZone) {
        self.zones.insert(zone.id.clone(), zone);
    }

    pub fn add_rule(&mut self, rule: InterZoneRule) {
        self.inter_zone_rules.push(rule);
    }

    pub fn can_communicate(&self, from_zone: &str, to_zone: &str) -> bool {
        // Check egress/ingress lists
        let from = match self.zones.get(from_zone) {
            Some(z) => z,
            None => return false,
        };
        let to = match self.zones.get(to_zone) {
            Some(z) => z,
            None => return false,
        };

        let egress_ok = from.allowed_egress_zones.is_empty()
            || from.allowed_egress_zones.iter().any(|z| z == to_zone);
        let ingress_ok = to.allowed_ingress_zones.is_empty()
            || to.allowed_ingress_zones.iter().any(|z| z == from_zone);

        if !egress_ok || !ingress_ok {
            return false;
        }

        // Check inter-zone rules for explicit deny
        for rule in &self.inter_zone_rules {
            if rule.from_zone == from_zone && rule.to_zone == to_zone {
                return rule.action != NetworkAction::Deny;
            }
        }

        // If egress/ingress lists pass and no deny rule, allow
        true
    }

    pub fn zone_for_host(&self, host_tags: &[&str]) -> Option<&L2NetworkZone> {
        let mut best_zone: Option<&L2NetworkZone> = None;
        let mut best_count = 0;

        for zone in self.zones.values() {
            let match_count = zone
                .tags
                .iter()
                .filter(|t| host_tags.contains(&t.as_str()))
                .count();
            if match_count > best_count {
                best_count = match_count;
                best_zone = Some(zone);
            }
        }

        best_zone
    }

    pub fn violations(&self) -> Vec<SegmentationViolation> {
        let mut violations = Vec::new();

        for from_zone in self.zones.values() {
            for to_id in &from_zone.allowed_egress_zones {
                if let Some(to_zone) = self.zones.get(to_id) {
                    // Detect untrusted zone with egress to higher-trust zone without explicit rule
                    if to_zone.trust_level > from_zone.trust_level {
                        let has_rule = self.inter_zone_rules.iter().any(|r| {
                            r.from_zone == from_zone.id && r.to_zone == *to_id
                        });
                        if !has_rule {
                            violations.push(SegmentationViolation {
                                from_zone: from_zone.id.clone(),
                                to_zone: to_id.clone(),
                                violation_type: "egress_to_higher_trust".into(),
                                description: format!(
                                    "Zone {} ({}) has egress to higher-trust zone {} ({}) without explicit rule",
                                    from_zone.id, from_zone.trust_level,
                                    to_id, to_zone.trust_level
                                ),
                            });
                        }
                    }
                }
            }
        }

        violations
    }

    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_zone_and_can_communicate() {
        let mut policy = L2SegmentationPolicy::new();
        policy.add_zone(
            L2NetworkZone::new("dmz", "DMZ", ZoneTrustLevel::Dmz)
                .with_egress(vec!["internal".into()]),
        );
        policy.add_zone(
            L2NetworkZone::new("internal", "Internal", ZoneTrustLevel::Internal)
                .with_ingress(vec!["dmz".into()]),
        );
        assert!(policy.can_communicate("dmz", "internal"));
    }

    #[test]
    fn test_can_communicate_false_without_rule() {
        let mut policy = L2SegmentationPolicy::new();
        policy.add_zone(L2NetworkZone::new("dmz", "DMZ", ZoneTrustLevel::Dmz));
        policy.add_zone(
            L2NetworkZone::new("secure", "Secure", ZoneTrustLevel::HighSecurity)
                .with_ingress(vec!["internal".into()]),
        );
        // DMZ has no egress to secure, secure only accepts from internal
        assert!(!policy.can_communicate("dmz", "secure"));
    }

    #[test]
    fn test_zone_for_host_matches_tags() {
        let mut policy = L2SegmentationPolicy::new();
        policy.add_zone(
            L2NetworkZone::new("dmz", "DMZ", ZoneTrustLevel::Dmz)
                .with_tags(vec!["web".into(), "public".into()]),
        );
        policy.add_zone(
            L2NetworkZone::new("internal", "Internal", ZoneTrustLevel::Internal)
                .with_tags(vec!["app".into(), "private".into()]),
        );
        let zone = policy.zone_for_host(&["app", "private"]).unwrap();
        assert_eq!(zone.id, "internal");
    }

    #[test]
    fn test_violations_detects_egress_to_higher_trust() {
        let mut policy = L2SegmentationPolicy::new();
        policy.add_zone(
            L2NetworkZone::new("untrusted", "Untrusted", ZoneTrustLevel::Untrusted)
                .with_egress(vec!["highsec".into()]),
        );
        policy.add_zone(
            L2NetworkZone::new("highsec", "HighSec", ZoneTrustLevel::HighSecurity),
        );
        let violations = policy.violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation_type, "egress_to_higher_trust");
    }

    #[test]
    fn test_zone_trust_level_ordering() {
        assert!(ZoneTrustLevel::Untrusted < ZoneTrustLevel::Dmz);
        assert!(ZoneTrustLevel::Dmz < ZoneTrustLevel::Internal);
        assert!(ZoneTrustLevel::Internal < ZoneTrustLevel::Restricted);
        assert!(ZoneTrustLevel::Restricted < ZoneTrustLevel::HighSecurity);
    }

    #[test]
    fn test_zone_count() {
        let mut policy = L2SegmentationPolicy::new();
        policy.add_zone(L2NetworkZone::new("a", "A", ZoneTrustLevel::Untrusted));
        policy.add_zone(L2NetworkZone::new("b", "B", ZoneTrustLevel::Internal));
        assert_eq!(policy.zone_count(), 2);
    }
}
