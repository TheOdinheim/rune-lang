// ═══════════════════════════════════════════════════════════════════════
// Identity Claims — Verifiable Assertions
//
// Claims are signed assertions about an identity that can be verified
// independently. Used for role claims, attribute claims, delegation, etc.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_lang::stdlib::crypto::sign::hmac_sha3_256;
use serde::{Deserialize, Serialize};

use crate::identity::IdentityId;

// ── ClaimType ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimType {
    Role(String),
    Attribute(String),
    Membership(String),
    Qualification(String),
    Delegation(String),
    Custom(String),
}

impl ClaimType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::Role(_) => "Role",
            Self::Attribute(_) => "Attribute",
            Self::Membership(_) => "Membership",
            Self::Qualification(_) => "Qualification",
            Self::Delegation(_) => "Delegation",
            Self::Custom(_) => "Custom",
        }
    }
}

impl fmt::Display for ClaimType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Role(r) => write!(f, "Role:{r}"),
            Self::Attribute(a) => write!(f, "Attribute:{a}"),
            Self::Membership(m) => write!(f, "Membership:{m}"),
            Self::Qualification(q) => write!(f, "Qualification:{q}"),
            Self::Delegation(d) => write!(f, "Delegation:{d}"),
            Self::Custom(c) => write!(f, "Custom:{c}"),
        }
    }
}

// ── Claim ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub id: String,
    pub identity_id: IdentityId,
    pub claim_type: ClaimType,
    pub value: String,
    pub issuer: String,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub signature: String,
}

impl Claim {
    pub fn new(
        id: impl Into<String>,
        identity_id: IdentityId,
        claim_type: ClaimType,
        value: impl Into<String>,
        issuer: impl Into<String>,
        issued_at: i64,
        key: &[u8],
    ) -> Self {
        let id = id.into();
        let value = value.into();
        let issuer = issuer.into();
        let content = format!("{}:{}:{}:{}:{}:{}", id, identity_id, claim_type, value, issuer, issued_at);
        let signature = hex::encode(hmac_sha3_256(key, content.as_bytes()));
        Self {
            id,
            identity_id,
            claim_type,
            value,
            issuer,
            issued_at,
            expires_at: None,
            signature,
        }
    }

    pub fn with_expiry(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }

    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let content = format!(
            "{}:{}:{}:{}:{}:{}",
            self.id, self.identity_id, self.claim_type, self.value, self.issuer, self.issued_at
        );
        let expected = hex::encode(hmac_sha3_256(key, content.as_bytes()));
        expected == self.signature
    }
}

// ── ClaimSet ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ClaimSet {
    pub claims: Vec<Claim>,
}

impl ClaimSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, claim: Claim) {
        self.claims.push(claim);
    }

    pub fn claims_by_type(&self, type_name: &str) -> Vec<&Claim> {
        self.claims.iter()
            .filter(|c| c.claim_type.type_name() == type_name)
            .collect()
    }

    pub fn has_claim(&self, claim_type: &ClaimType) -> bool {
        self.claims.iter().any(|c| &c.claim_type == claim_type)
    }

    pub fn valid_claims(&self, now: i64) -> Vec<&Claim> {
        self.claims.iter().filter(|c| !c.is_expired(now)).collect()
    }

    pub fn verify_all(&self, key: &[u8]) -> Vec<(String, bool)> {
        self.claims.iter()
            .map(|c| (c.id.clone(), c.verify_signature(key)))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.claims.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![0xBB; 32]
    }

    fn test_claim(id: &str, claim_type: ClaimType) -> Claim {
        Claim::new(
            id,
            IdentityId::new("user:alice"),
            claim_type,
            "true",
            "admin",
            1000,
            &test_key(),
        )
    }

    #[test]
    fn test_claim_construction_and_expiry() {
        let claim = test_claim("c1", ClaimType::Role("admin".into()));
        assert!(!claim.is_expired(1500));
        let claim = claim.with_expiry(2000);
        assert!(!claim.is_expired(1500));
        assert!(claim.is_expired(2000));
    }

    #[test]
    fn test_claim_verify_signature() {
        let claim = test_claim("c1", ClaimType::Role("admin".into()));
        assert!(claim.verify_signature(&test_key()));
        assert!(!claim.verify_signature(b"wrong-key"));
    }

    #[test]
    fn test_claim_set_add_and_has() {
        let mut set = ClaimSet::new();
        set.add(test_claim("c1", ClaimType::Role("admin".into())));
        set.add(test_claim("c2", ClaimType::Membership("security-team".into())));
        assert_eq!(set.len(), 2);
        assert!(set.has_claim(&ClaimType::Role("admin".into())));
        assert!(!set.has_claim(&ClaimType::Role("viewer".into())));
    }

    #[test]
    fn test_claim_set_by_type() {
        let mut set = ClaimSet::new();
        set.add(test_claim("c1", ClaimType::Role("admin".into())));
        set.add(test_claim("c2", ClaimType::Role("viewer".into())));
        set.add(test_claim("c3", ClaimType::Membership("team".into())));
        assert_eq!(set.claims_by_type("Role").len(), 2);
        assert_eq!(set.claims_by_type("Membership").len(), 1);
    }

    #[test]
    fn test_claim_set_valid_claims() {
        let mut set = ClaimSet::new();
        set.add(test_claim("c1", ClaimType::Role("admin".into())));
        set.add(test_claim("c2", ClaimType::Role("viewer".into())).with_expiry(1500));
        assert_eq!(set.valid_claims(1200).len(), 2);
        assert_eq!(set.valid_claims(1600).len(), 1);
    }

    #[test]
    fn test_claim_set_verify_all() {
        let mut set = ClaimSet::new();
        set.add(test_claim("c1", ClaimType::Role("admin".into())));
        set.add(test_claim("c2", ClaimType::Membership("team".into())));
        let results = set.verify_all(&test_key());
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, valid)| *valid));

        let bad_results = set.verify_all(b"wrong");
        assert!(bad_results.iter().all(|(_, valid)| !*valid));
    }

    #[test]
    fn test_claim_type_display() {
        assert_eq!(ClaimType::Role("admin".into()).to_string(), "Role:admin");
        assert_eq!(ClaimType::Delegation("approver".into()).to_string(), "Delegation:approver");
    }
}
