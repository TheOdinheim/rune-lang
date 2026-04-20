// ═══════════════════════════════════════════════════════════════════════
// Federation Auth Provider — Pluggable federation trait boundary.
//
// Layer 3 defines the contract for federated authentication flows
// (OIDC, SAML, LDAP). Reference implementations are stubs that
// exercise the trait interface without depending on external IdPs.
//
// Named FederationAuthProvider to avoid collision with the existing
// FederationProvider struct in federation.rs (Layer 2).
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

use crate::error::IdentityError;

// ── ProviderType ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderType {
    Oidc,
    Saml,
    Ldap,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oidc => write!(f, "OIDC"),
            Self::Saml => write!(f, "SAML"),
            Self::Ldap => write!(f, "LDAP"),
        }
    }
}

// ── FlowContext ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub state_token: String,
    pub provider_id: String,
    pub initiated_at: i64,
    pub expires_at: i64,
}

impl FlowContext {
    pub fn new(provider_id: &str, initiated_at: i64, expires_at: i64, entropy: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(provider_id.as_bytes());
        hasher.update(initiated_at.to_le_bytes());
        hasher.update(entropy);
        Self {
            state_token: hex::encode(hasher.finalize()),
            provider_id: provider_id.to_string(),
            initiated_at,
            expires_at,
        }
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }
}

// ── ExternalIdentity ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExternalIdentity {
    pub external_id: String,
    pub issuer: String,
    pub claims: HashMap<String, String>,
    pub assertion_hash: String,
}

impl ExternalIdentity {
    pub fn new(external_id: &str, issuer: &str, assertion: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(assertion);
        Self {
            external_id: external_id.to_string(),
            issuer: issuer.to_string(),
            claims: HashMap::new(),
            assertion_hash: hex::encode(hasher.finalize()),
        }
    }

    pub fn with_claim(mut self, key: &str, value: &str) -> Self {
        self.claims.insert(key.to_string(), value.to_string());
        self
    }
}

// ── FederationAuthProvider trait ──────────────────────────────

pub trait FederationAuthProvider {
    fn begin_authentication_flow(
        &self,
        initiated_at: i64,
        entropy: &[u8],
    ) -> Result<FlowContext, IdentityError>;

    fn complete_authentication_flow(
        &self,
        flow: &FlowContext,
        assertion: &[u8],
        now: i64,
    ) -> Result<ExternalIdentity, IdentityError>;

    fn provider_id(&self) -> &str;
    fn provider_type(&self) -> ProviderType;
    fn supported_assertion_formats(&self) -> Vec<String>;
    fn is_active(&self) -> bool;
}

// ── InMemoryOidcFederationStub ───────────────────────────────

pub struct InMemoryOidcFederationStub {
    id: String,
    issuer: String,
    active: bool,
    flow_lifetime_seconds: i64,
}

impl InMemoryOidcFederationStub {
    pub fn new(id: &str, issuer: &str) -> Self {
        Self {
            id: id.to_string(),
            issuer: issuer.to_string(),
            active: true,
            flow_lifetime_seconds: 300,
        }
    }
}

impl FederationAuthProvider for InMemoryOidcFederationStub {
    fn begin_authentication_flow(
        &self,
        initiated_at: i64,
        entropy: &[u8],
    ) -> Result<FlowContext, IdentityError> {
        if !self.active {
            return Err(IdentityError::InvalidOperation("provider inactive".into()));
        }
        Ok(FlowContext::new(
            &self.id,
            initiated_at,
            initiated_at + self.flow_lifetime_seconds,
            entropy,
        ))
    }

    fn complete_authentication_flow(
        &self,
        flow: &FlowContext,
        assertion: &[u8],
        now: i64,
    ) -> Result<ExternalIdentity, IdentityError> {
        if flow.is_expired(now) {
            return Err(IdentityError::InvalidOperation("flow expired".into()));
        }
        if flow.provider_id != self.id {
            return Err(IdentityError::InvalidOperation("provider mismatch".into()));
        }
        // Stub: extract a synthetic external_id from the assertion bytes
        let ext_id = format!("oidc-{}", hex::encode(&assertion[..assertion.len().min(8)]));
        Ok(ExternalIdentity::new(&ext_id, &self.issuer, assertion)
            .with_claim("protocol", "oidc"))
    }

    fn provider_id(&self) -> &str {
        &self.id
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Oidc
    }

    fn supported_assertion_formats(&self) -> Vec<String> {
        vec!["jwt".to_string(), "id_token".to_string()]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── InMemorySamlFederationStub ───────────────────────────────

pub struct InMemorySamlFederationStub {
    id: String,
    issuer: String,
    active: bool,
    flow_lifetime_seconds: i64,
}

impl InMemorySamlFederationStub {
    pub fn new(id: &str, issuer: &str) -> Self {
        Self {
            id: id.to_string(),
            issuer: issuer.to_string(),
            active: true,
            flow_lifetime_seconds: 600,
        }
    }
}

impl FederationAuthProvider for InMemorySamlFederationStub {
    fn begin_authentication_flow(
        &self,
        initiated_at: i64,
        entropy: &[u8],
    ) -> Result<FlowContext, IdentityError> {
        if !self.active {
            return Err(IdentityError::InvalidOperation("provider inactive".into()));
        }
        Ok(FlowContext::new(
            &self.id,
            initiated_at,
            initiated_at + self.flow_lifetime_seconds,
            entropy,
        ))
    }

    fn complete_authentication_flow(
        &self,
        flow: &FlowContext,
        assertion: &[u8],
        now: i64,
    ) -> Result<ExternalIdentity, IdentityError> {
        if flow.is_expired(now) {
            return Err(IdentityError::InvalidOperation("flow expired".into()));
        }
        if flow.provider_id != self.id {
            return Err(IdentityError::InvalidOperation("provider mismatch".into()));
        }
        let ext_id = format!("saml-{}", hex::encode(&assertion[..assertion.len().min(8)]));
        Ok(ExternalIdentity::new(&ext_id, &self.issuer, assertion)
            .with_claim("protocol", "saml"))
    }

    fn provider_id(&self) -> &str {
        &self.id
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Saml
    }

    fn supported_assertion_formats(&self) -> Vec<String> {
        vec!["saml_response".to_string()]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── InMemoryLdapFederationStub ───────────────────────────────

pub struct InMemoryLdapFederationStub {
    id: String,
    base_dn: String,
    active: bool,
    flow_lifetime_seconds: i64,
}

impl InMemoryLdapFederationStub {
    pub fn new(id: &str, base_dn: &str) -> Self {
        Self {
            id: id.to_string(),
            base_dn: base_dn.to_string(),
            active: true,
            flow_lifetime_seconds: 120,
        }
    }
}

impl FederationAuthProvider for InMemoryLdapFederationStub {
    fn begin_authentication_flow(
        &self,
        initiated_at: i64,
        entropy: &[u8],
    ) -> Result<FlowContext, IdentityError> {
        if !self.active {
            return Err(IdentityError::InvalidOperation("provider inactive".into()));
        }
        Ok(FlowContext::new(
            &self.id,
            initiated_at,
            initiated_at + self.flow_lifetime_seconds,
            entropy,
        ))
    }

    fn complete_authentication_flow(
        &self,
        flow: &FlowContext,
        assertion: &[u8],
        now: i64,
    ) -> Result<ExternalIdentity, IdentityError> {
        if flow.is_expired(now) {
            return Err(IdentityError::InvalidOperation("flow expired".into()));
        }
        if flow.provider_id != self.id {
            return Err(IdentityError::InvalidOperation("provider mismatch".into()));
        }
        let ext_id = format!("ldap-{}", hex::encode(&assertion[..assertion.len().min(8)]));
        Ok(ExternalIdentity::new(&ext_id, &self.base_dn, assertion)
            .with_claim("protocol", "ldap"))
    }

    fn provider_id(&self) -> &str {
        &self.id
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Ldap
    }

    fn supported_assertion_formats(&self) -> Vec<String> {
        vec!["ldap_bind".to_string()]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_context_sha3_state_token() {
        let ctx = FlowContext::new("oidc-1", 1000, 1300, b"random-entropy");
        assert_eq!(ctx.state_token.len(), 64); // SHA3-256 hex
        assert_eq!(ctx.provider_id, "oidc-1");
        assert!(!ctx.is_expired(1200));
        assert!(ctx.is_expired(1300));
    }

    #[test]
    fn test_external_identity_assertion_hash() {
        let ext = ExternalIdentity::new("ext-1", "https://idp.example.com", b"assertion-data");
        assert_eq!(ext.assertion_hash.len(), 64);
        assert_eq!(ext.external_id, "ext-1");
        assert_eq!(ext.issuer, "https://idp.example.com");
    }

    #[test]
    fn test_external_identity_with_claims() {
        let ext = ExternalIdentity::new("ext-1", "issuer", b"data")
            .with_claim("email", "alice@example.com")
            .with_claim("name", "Alice");
        assert_eq!(ext.claims.len(), 2);
        assert_eq!(ext.claims["email"], "alice@example.com");
    }

    #[test]
    fn test_oidc_stub_full_flow() {
        let provider = InMemoryOidcFederationStub::new("oidc-1", "https://accounts.google.com");
        assert!(provider.is_active());
        assert_eq!(provider.provider_type(), ProviderType::Oidc);

        let flow = provider.begin_authentication_flow(1000, b"entropy").unwrap();
        assert_eq!(flow.provider_id, "oidc-1");
        assert!(!flow.is_expired(1100));

        let ext = provider.complete_authentication_flow(&flow, b"jwt-token-data", 1100).unwrap();
        assert!(ext.external_id.starts_with("oidc-"));
        assert_eq!(ext.claims["protocol"], "oidc");
    }

    #[test]
    fn test_saml_stub_full_flow() {
        let provider = InMemorySamlFederationStub::new("saml-1", "https://adfs.corp.com");
        assert_eq!(provider.provider_type(), ProviderType::Saml);

        let flow = provider.begin_authentication_flow(1000, b"entropy").unwrap();
        let ext = provider.complete_authentication_flow(&flow, b"saml-response-xml", 1200).unwrap();
        assert!(ext.external_id.starts_with("saml-"));
        assert_eq!(ext.claims["protocol"], "saml");
    }

    #[test]
    fn test_ldap_stub_full_flow() {
        let provider = InMemoryLdapFederationStub::new("ldap-1", "dc=corp,dc=com");
        assert_eq!(provider.provider_type(), ProviderType::Ldap);

        let flow = provider.begin_authentication_flow(1000, b"entropy").unwrap();
        let ext = provider.complete_authentication_flow(&flow, b"ldap-bind-result", 1050).unwrap();
        assert!(ext.external_id.starts_with("ldap-"));
        assert_eq!(ext.claims["protocol"], "ldap");
    }

    #[test]
    fn test_flow_expired_rejected() {
        let provider = InMemoryOidcFederationStub::new("oidc-1", "https://idp.example.com");
        let flow = provider.begin_authentication_flow(1000, b"entropy").unwrap();
        let result = provider.complete_authentication_flow(&flow, b"token", 2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_provider_mismatch_rejected() {
        let provider_a = InMemoryOidcFederationStub::new("oidc-a", "https://a.com");
        let provider_b = InMemoryOidcFederationStub::new("oidc-b", "https://b.com");
        let flow = provider_a.begin_authentication_flow(1000, b"entropy").unwrap();
        let result = provider_b.complete_authentication_flow(&flow, b"token", 1100);
        assert!(result.is_err());
    }

    #[test]
    fn test_supported_assertion_formats() {
        let oidc = InMemoryOidcFederationStub::new("o", "i");
        assert!(oidc.supported_assertion_formats().contains(&"jwt".to_string()));

        let saml = InMemorySamlFederationStub::new("s", "i");
        assert!(saml.supported_assertion_formats().contains(&"saml_response".to_string()));

        let ldap = InMemoryLdapFederationStub::new("l", "dc=x");
        assert!(ldap.supported_assertion_formats().contains(&"ldap_bind".to_string()));
    }

    #[test]
    fn test_provider_type_display() {
        assert_eq!(ProviderType::Oidc.to_string(), "OIDC");
        assert_eq!(ProviderType::Saml.to_string(), "SAML");
        assert_eq!(ProviderType::Ldap.to_string(), "LDAP");
    }

    #[test]
    fn test_deterministic_state_token() {
        let a = FlowContext::new("p", 1000, 2000, b"same");
        let b = FlowContext::new("p", 1000, 2000, b"same");
        assert_eq!(a.state_token, b.state_token);

        let c = FlowContext::new("p", 1000, 2000, b"different");
        assert_ne!(a.state_token, c.state_token);
    }
}
