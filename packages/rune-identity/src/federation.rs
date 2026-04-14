// ═══════════════════════════════════════════════════════════════════════
// Federation Interfaces — OIDC, SAML, Federated Identity
//
// Data types for federated identity protocols. Not full implementations;
// these are structures a federation adapter would use.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::identity::IdentityId;
use crate::trust::TrustLevel;

// ── OidcClaims ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

impl OidcClaims {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.exp
    }

    pub fn is_valid_audience(&self, expected: &str) -> bool {
        self.aud == expected
    }
}

// ── SamlAssertion ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub conditions_not_before: i64,
    pub conditions_not_after: i64,
    pub attributes: HashMap<String, Vec<String>>,
    pub signature: String,
}

impl SamlAssertion {
    pub fn is_valid_time(&self, now: i64) -> bool {
        now >= self.conditions_not_before && now < self.conditions_not_after
    }

    pub fn get_attribute(&self, name: &str) -> Option<&Vec<String>> {
        self.attributes.get(name)
    }
}

// ── FederationProtocol ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FederationProtocol {
    Oidc,
    Saml2,
    Custom(String),
}

impl fmt::Display for FederationProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oidc => write!(f, "OIDC"),
            Self::Saml2 => write!(f, "SAML 2.0"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ── FederationProvider ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationProvider {
    pub id: String,
    pub name: String,
    pub provider_type: FederationProtocol,
    pub issuer_url: String,
    pub trust_level: TrustLevel,
    pub active: bool,
}

// ── FederatedIdentity (Layer 2) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedIdentity {
    pub local_identity_id: IdentityId,
    pub provider: String,
    pub external_id: String,
    pub linked_at: i64,
    pub last_synced_at: i64,
    pub trust_modifier: f64,
}

#[derive(Debug, Clone, Default)]
pub struct FederatedIdentityStore {
    identities: Vec<FederatedIdentity>,
}

impl FederatedIdentityStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn link(
        &mut self,
        local_identity_id: IdentityId,
        provider: &str,
        external_id: &str,
        now: i64,
        trust_modifier: f64,
    ) -> &FederatedIdentity {
        self.identities.push(FederatedIdentity {
            local_identity_id,
            provider: provider.to_string(),
            external_id: external_id.to_string(),
            linked_at: now,
            last_synced_at: now,
            trust_modifier,
        });
        self.identities.last().unwrap()
    }

    pub fn unlink(&mut self, provider: &str, external_id: &str) -> bool {
        let len_before = self.identities.len();
        self.identities.retain(|fi| !(fi.provider == provider && fi.external_id == external_id));
        self.identities.len() < len_before
    }

    pub fn find_by_external_id(&self, provider: &str, external_id: &str) -> Option<&FederatedIdentity> {
        self.identities.iter().find(|fi| fi.provider == provider && fi.external_id == external_id)
    }

    pub fn identities_for(&self, local_id: &IdentityId) -> Vec<&FederatedIdentity> {
        self.identities.iter().filter(|fi| &fi.local_identity_id == local_id).collect()
    }

    pub fn len(&self) -> usize {
        self.identities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

// ── FederationTrustPolicy (Layer 2) ─────────────────────────────────

#[derive(Debug, Clone)]
pub struct FederationTrustPolicy {
    pub trusted_providers: HashMap<String, TrustLevel>,
}

impl FederationTrustPolicy {
    pub fn new() -> Self {
        Self { trusted_providers: HashMap::new() }
    }

    pub fn add_trusted_provider(&mut self, provider: &str, trust_level: TrustLevel) {
        self.trusted_providers.insert(provider.to_string(), trust_level);
    }

    pub fn is_trusted(&self, provider: &str) -> bool {
        self.trusted_providers.contains_key(provider)
    }

    pub fn trust_level_for(&self, provider: &str) -> Option<&TrustLevel> {
        self.trusted_providers.get(provider)
    }
}

impl Default for FederationTrustPolicy {
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

    #[test]
    fn test_oidc_claims_expired() {
        let claims = OidcClaims {
            sub: "user123".into(),
            iss: "https://idp.example.com".into(),
            aud: "my-app".into(),
            exp: 2000,
            iat: 1000,
            nonce: None,
            name: Some("Alice".into()),
            email: Some("alice@example.com".into()),
            email_verified: Some(true),
        };
        assert!(!claims.is_expired(1500));
        assert!(claims.is_expired(2000));
    }

    #[test]
    fn test_oidc_claims_valid_audience() {
        let claims = OidcClaims {
            sub: "user123".into(),
            iss: "https://idp.example.com".into(),
            aud: "my-app".into(),
            exp: 2000,
            iat: 1000,
            nonce: None,
            name: None,
            email: None,
            email_verified: None,
        };
        assert!(claims.is_valid_audience("my-app"));
        assert!(!claims.is_valid_audience("other-app"));
    }

    #[test]
    fn test_saml_assertion_valid_time() {
        let mut attrs = HashMap::new();
        attrs.insert("role".into(), vec!["admin".into(), "user".into()]);
        let assertion = SamlAssertion {
            id: "saml-1".into(),
            issuer: "https://idp.example.com".into(),
            subject: "user123".into(),
            conditions_not_before: 1000,
            conditions_not_after: 2000,
            attributes: attrs,
            signature: "sig".into(),
        };
        assert!(!assertion.is_valid_time(500));
        assert!(assertion.is_valid_time(1500));
        assert!(!assertion.is_valid_time(2000));
    }

    #[test]
    fn test_saml_assertion_get_attribute() {
        let mut attrs = HashMap::new();
        attrs.insert("role".into(), vec!["admin".into()]);
        let assertion = SamlAssertion {
            id: "saml-1".into(),
            issuer: "idp".into(),
            subject: "user".into(),
            conditions_not_before: 0,
            conditions_not_after: 9999,
            attributes: attrs,
            signature: String::new(),
        };
        assert_eq!(assertion.get_attribute("role").unwrap(), &vec!["admin".to_string()]);
        assert!(assertion.get_attribute("missing").is_none());
    }

    #[test]
    fn test_federation_provider_construction() {
        let provider = FederationProvider {
            id: "okta-1".into(),
            name: "Okta".into(),
            provider_type: FederationProtocol::Oidc,
            issuer_url: "https://okta.example.com".into(),
            trust_level: TrustLevel::High,
            active: true,
        };
        assert!(provider.active);
        assert_eq!(provider.provider_type.to_string(), "OIDC");
    }

    #[test]
    fn test_federation_protocol_display() {
        assert_eq!(FederationProtocol::Oidc.to_string(), "OIDC");
        assert_eq!(FederationProtocol::Saml2.to_string(), "SAML 2.0");
        assert_eq!(FederationProtocol::Custom("LDAP".into()).to_string(), "Custom(LDAP)");
    }

    // ── Part 6: Identity Federation Tests ────────────────────────────

    #[test]
    fn test_federated_identity_link() {
        let mut store = FederatedIdentityStore::new();
        let fi = store.link(
            IdentityId::new("user:alice"), "okta", "ext-123", 1000, 0.1,
        );
        assert_eq!(fi.provider, "okta");
        assert_eq!(fi.external_id, "ext-123");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_federated_identity_unlink() {
        let mut store = FederatedIdentityStore::new();
        store.link(IdentityId::new("user:alice"), "okta", "ext-123", 1000, 0.1);
        assert!(store.unlink("okta", "ext-123"));
        assert!(store.is_empty());
    }

    #[test]
    fn test_federated_identity_unlink_nonexistent() {
        let mut store = FederatedIdentityStore::new();
        assert!(!store.unlink("okta", "nonexistent"));
    }

    #[test]
    fn test_federated_identity_find_by_external_id() {
        let mut store = FederatedIdentityStore::new();
        store.link(IdentityId::new("user:alice"), "okta", "ext-123", 1000, 0.1);
        store.link(IdentityId::new("user:bob"), "google", "ext-456", 2000, 0.05);
        let found = store.find_by_external_id("okta", "ext-123").unwrap();
        assert_eq!(found.local_identity_id.as_str(), "user:alice");
        assert!(store.find_by_external_id("okta", "ext-999").is_none());
    }

    #[test]
    fn test_federated_identity_identities_for() {
        let mut store = FederatedIdentityStore::new();
        let id = IdentityId::new("user:alice");
        store.link(id.clone(), "okta", "ext-1", 1000, 0.1);
        store.link(id.clone(), "google", "ext-2", 2000, 0.05);
        store.link(IdentityId::new("user:bob"), "okta", "ext-3", 3000, 0.1);
        assert_eq!(store.identities_for(&id).len(), 2);
    }

    #[test]
    fn test_federation_trust_policy() {
        let mut policy = FederationTrustPolicy::new();
        policy.add_trusted_provider("okta", TrustLevel::High);
        policy.add_trusted_provider("google", TrustLevel::Medium);
        assert!(policy.is_trusted("okta"));
        assert!(!policy.is_trusted("unknown"));
        assert_eq!(policy.trust_level_for("okta"), Some(&TrustLevel::High));
    }

    #[test]
    fn test_federated_identity_trust_modifier() {
        let mut store = FederatedIdentityStore::new();
        let fi = store.link(
            IdentityId::new("user:alice"), "okta", "ext-123", 1000, 0.15,
        );
        assert!((fi.trust_modifier - 0.15).abs() < 0.001);
    }
}
