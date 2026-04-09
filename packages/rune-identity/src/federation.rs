// ═══════════════════════════════════════════════════════════════════════
// Federation Interfaces — OIDC, SAML, Federated Identity
//
// Data types for federated identity protocols. Not full implementations;
// these are structures a federation adapter would use.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

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
}
