// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — NetworkSegmentationVerifier trait for verifying network
// segmentation policies: zone flow verification, compliance assessment,
// improvement recommendations.
// Includes DenyByDefaultSegmentationVerifier composable wrapper.
//
// Named to avoid collision with L1 SegmentationEnforcer and
// SegmentationDecision structs.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;

// ── SegmentationVerificationDecision ───────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SegmentationVerificationDecision {
    Allowed,
    Denied,
    LogOnly,
    RequiresEncryption,
    EscalateToAdmin,
}

impl fmt::Display for SegmentationVerificationDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Allowed => "Allowed",
            Self::Denied => "Denied",
            Self::LogOnly => "LogOnly",
            Self::RequiresEncryption => "RequiresEncryption",
            Self::EscalateToAdmin => "EscalateToAdmin",
        };
        f.write_str(s)
    }
}

// ── SegmentationVerification ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentationVerification {
    pub source_zone: String,
    pub dest_zone: String,
    pub decision: SegmentationVerificationDecision,
    pub policy_ref: String,
    pub justification: String,
    pub verified_at: i64,
}

// ── SegmentationImprovement ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentationImprovement {
    pub zone_id: String,
    pub recommendation: String,
    pub severity: String,
    pub category: String,
}

// ── NetworkSegmentationVerifier trait ──────────────────────────────

pub trait NetworkSegmentationVerifier {
    fn verify_zone_flow(
        &self,
        source_zone: &str,
        dest_zone: &str,
        protocol: &str,
        port: Option<u16>,
    ) -> Result<SegmentationVerification, NetworkError>;

    fn assess_segmentation_compliance(
        &self,
    ) -> Result<Vec<SegmentationImprovement>, NetworkError>;

    fn is_zone_registered(&self, zone_id: &str) -> bool;

    fn list_zones(&self) -> Vec<(String, String)>;

    fn verifier_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryNetworkSegmentationVerifier ────────────────────────────

pub struct InMemoryNetworkSegmentationVerifier {
    id: String,
    zones: Vec<(String, String)>, // (zone_id, zone_type)
    allowed_flows: Vec<(String, String)>, // (source_zone, dest_zone)
    denied_flows: Vec<(String, String)>,
    default_decision: SegmentationVerificationDecision,
}

impl InMemoryNetworkSegmentationVerifier {
    pub fn new(
        id: impl Into<String>,
        default_decision: SegmentationVerificationDecision,
    ) -> Self {
        Self {
            id: id.into(),
            zones: Vec::new(),
            allowed_flows: Vec::new(),
            denied_flows: Vec::new(),
            default_decision,
        }
    }

    pub fn register_zone(&mut self, zone_id: impl Into<String>, zone_type: impl Into<String>) {
        self.zones.push((zone_id.into(), zone_type.into()));
    }

    pub fn add_allowed_flow(
        &mut self,
        source: impl Into<String>,
        dest: impl Into<String>,
    ) {
        self.allowed_flows.push((source.into(), dest.into()));
    }

    pub fn add_denied_flow(
        &mut self,
        source: impl Into<String>,
        dest: impl Into<String>,
    ) {
        self.denied_flows.push((source.into(), dest.into()));
    }
}

impl NetworkSegmentationVerifier for InMemoryNetworkSegmentationVerifier {
    fn verify_zone_flow(
        &self,
        source_zone: &str,
        dest_zone: &str,
        _protocol: &str,
        _port: Option<u16>,
    ) -> Result<SegmentationVerification, NetworkError> {
        // Check denied flows first
        if self
            .denied_flows
            .iter()
            .any(|(s, d)| s == source_zone && d == dest_zone)
        {
            return Ok(SegmentationVerification {
                source_zone: source_zone.into(),
                dest_zone: dest_zone.into(),
                decision: SegmentationVerificationDecision::Denied,
                policy_ref: self.id.clone(),
                justification: format!("Flow {source_zone}→{dest_zone} explicitly denied"),
                verified_at: 0,
            });
        }

        // Check allowed flows
        if self
            .allowed_flows
            .iter()
            .any(|(s, d)| s == source_zone && d == dest_zone)
        {
            return Ok(SegmentationVerification {
                source_zone: source_zone.into(),
                dest_zone: dest_zone.into(),
                decision: SegmentationVerificationDecision::Allowed,
                policy_ref: self.id.clone(),
                justification: format!("Flow {source_zone}→{dest_zone} explicitly allowed"),
                verified_at: 0,
            });
        }

        // Default
        Ok(SegmentationVerification {
            source_zone: source_zone.into(),
            dest_zone: dest_zone.into(),
            decision: self.default_decision.clone(),
            policy_ref: self.id.clone(),
            justification: format!(
                "No explicit rule for {source_zone}→{dest_zone}, using default"
            ),
            verified_at: 0,
        })
    }

    fn assess_segmentation_compliance(
        &self,
    ) -> Result<Vec<SegmentationImprovement>, NetworkError> {
        let mut improvements = Vec::new();
        if self.denied_flows.is_empty() {
            improvements.push(SegmentationImprovement {
                zone_id: "global".into(),
                recommendation: "No explicit deny rules defined".into(),
                severity: "Medium".into(),
                category: "segmentation_policy".into(),
            });
        }
        Ok(improvements)
    }

    fn is_zone_registered(&self, zone_id: &str) -> bool {
        self.zones.iter().any(|(id, _)| id == zone_id)
    }

    fn list_zones(&self) -> Vec<(String, String)> {
        self.zones.clone()
    }

    fn verifier_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── DenyByDefaultSegmentationVerifier ──────────────────────────────
// Composable wrapper that denies all flows not explicitly allowed.

pub struct DenyByDefaultSegmentationVerifier<V: NetworkSegmentationVerifier> {
    inner: V,
}

impl<V: NetworkSegmentationVerifier> DenyByDefaultSegmentationVerifier<V> {
    pub fn new(inner: V) -> Self {
        Self { inner }
    }
}

impl<V: NetworkSegmentationVerifier> NetworkSegmentationVerifier
    for DenyByDefaultSegmentationVerifier<V>
{
    fn verify_zone_flow(
        &self,
        source_zone: &str,
        dest_zone: &str,
        protocol: &str,
        port: Option<u16>,
    ) -> Result<SegmentationVerification, NetworkError> {
        let result = self
            .inner
            .verify_zone_flow(source_zone, dest_zone, protocol, port)?;
        // Override non-Allowed decisions to Denied (except explicit Allowed)
        if result.decision != SegmentationVerificationDecision::Allowed {
            return Ok(SegmentationVerification {
                decision: SegmentationVerificationDecision::Denied,
                justification: format!(
                    "DenyByDefaultSegmentationVerifier: flow {source_zone}→{dest_zone} not explicitly allowed"
                ),
                ..result
            });
        }
        Ok(result)
    }

    fn assess_segmentation_compliance(
        &self,
    ) -> Result<Vec<SegmentationImprovement>, NetworkError> {
        self.inner.assess_segmentation_compliance()
    }

    fn is_zone_registered(&self, zone_id: &str) -> bool {
        self.inner.is_zone_registered(zone_id)
    }

    fn list_zones(&self) -> Vec<(String, String)> {
        self.inner.list_zones()
    }

    fn verifier_id(&self) -> &str {
        self.inner.verifier_id()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── NullNetworkSegmentationVerifier ────────────────────────────────

pub struct NullNetworkSegmentationVerifier;

impl NetworkSegmentationVerifier for NullNetworkSegmentationVerifier {
    fn verify_zone_flow(
        &self,
        source_zone: &str,
        dest_zone: &str,
        _protocol: &str,
        _port: Option<u16>,
    ) -> Result<SegmentationVerification, NetworkError> {
        Ok(SegmentationVerification {
            source_zone: source_zone.into(),
            dest_zone: dest_zone.into(),
            decision: SegmentationVerificationDecision::Allowed,
            policy_ref: "null".into(),
            justification: "Null verifier — no segmentation verification".into(),
            verified_at: 0,
        })
    }

    fn assess_segmentation_compliance(
        &self,
    ) -> Result<Vec<SegmentationImprovement>, NetworkError> {
        Ok(Vec::new())
    }

    fn is_zone_registered(&self, _zone_id: &str) -> bool {
        false
    }

    fn list_zones(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    fn verifier_id(&self) -> &str {
        "null-segmentation-verifier"
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_verifier() -> InMemoryNetworkSegmentationVerifier {
        let mut v = InMemoryNetworkSegmentationVerifier::new(
            "v1",
            SegmentationVerificationDecision::LogOnly,
        );
        v.register_zone("dmz", "DMZ");
        v.register_zone("internal", "Internal");
        v.register_zone("restricted", "Restricted");
        v.add_allowed_flow("dmz", "internal");
        v.add_denied_flow("dmz", "restricted");
        v
    }

    #[test]
    fn test_allowed_flow() {
        let v = setup_verifier();
        let result = v.verify_zone_flow("dmz", "internal", "TCP", None).unwrap();
        assert_eq!(result.decision, SegmentationVerificationDecision::Allowed);
    }

    #[test]
    fn test_denied_flow() {
        let v = setup_verifier();
        let result = v
            .verify_zone_flow("dmz", "restricted", "TCP", None)
            .unwrap();
        assert_eq!(result.decision, SegmentationVerificationDecision::Denied);
    }

    #[test]
    fn test_default_decision() {
        let v = setup_verifier();
        let result = v
            .verify_zone_flow("internal", "restricted", "TCP", None)
            .unwrap();
        assert_eq!(result.decision, SegmentationVerificationDecision::LogOnly);
    }

    #[test]
    fn test_zone_registered() {
        let v = setup_verifier();
        assert!(v.is_zone_registered("dmz"));
        assert!(!v.is_zone_registered("unknown"));
    }

    #[test]
    fn test_list_zones() {
        let v = setup_verifier();
        assert_eq!(v.list_zones().len(), 3);
    }

    #[test]
    fn test_assess_compliance() {
        let v = setup_verifier();
        let improvements = v.assess_segmentation_compliance().unwrap();
        assert!(improvements.is_empty()); // has denied flows
    }

    #[test]
    fn test_assess_compliance_no_denies() {
        let v = InMemoryNetworkSegmentationVerifier::new(
            "v1",
            SegmentationVerificationDecision::Allowed,
        );
        let improvements = v.assess_segmentation_compliance().unwrap();
        assert_eq!(improvements.len(), 1);
    }

    #[test]
    fn test_deny_by_default_wrapper() {
        let inner = setup_verifier();
        let wrapped = DenyByDefaultSegmentationVerifier::new(inner);
        // Allowed flow passes through
        let r = wrapped
            .verify_zone_flow("dmz", "internal", "TCP", None)
            .unwrap();
        assert_eq!(r.decision, SegmentationVerificationDecision::Allowed);
        // Default (LogOnly) becomes Denied
        let r2 = wrapped
            .verify_zone_flow("internal", "restricted", "TCP", None)
            .unwrap();
        assert_eq!(r2.decision, SegmentationVerificationDecision::Denied);
    }

    #[test]
    fn test_deny_by_default_delegates() {
        let inner = setup_verifier();
        let wrapped = DenyByDefaultSegmentationVerifier::new(inner);
        assert!(wrapped.is_zone_registered("dmz"));
        assert_eq!(wrapped.list_zones().len(), 3);
        assert_eq!(wrapped.verifier_id(), "v1");
        assert!(wrapped.is_active());
    }

    #[test]
    fn test_null_verifier() {
        let v = NullNetworkSegmentationVerifier;
        assert!(!v.is_active());
        assert_eq!(v.verifier_id(), "null-segmentation-verifier");
        let r = v.verify_zone_flow("a", "b", "TCP", None).unwrap();
        assert_eq!(r.decision, SegmentationVerificationDecision::Allowed);
        assert!(!v.is_zone_registered("x"));
        assert!(v.list_zones().is_empty());
        assert!(v.assess_segmentation_compliance().unwrap().is_empty());
    }

    #[test]
    fn test_decision_display() {
        let decisions = vec![
            SegmentationVerificationDecision::Allowed,
            SegmentationVerificationDecision::Denied,
            SegmentationVerificationDecision::LogOnly,
            SegmentationVerificationDecision::RequiresEncryption,
            SegmentationVerificationDecision::EscalateToAdmin,
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(decisions.len(), 5);
    }

    #[test]
    fn test_verifier_id() {
        let v = setup_verifier();
        assert_eq!(v.verifier_id(), "v1");
        assert!(v.is_active());
    }
}
