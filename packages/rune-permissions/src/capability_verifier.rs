// ═══════════════════════════════════════════════════════════════════════
// Capability Verifier — Runtime capability token verification.
//
// Layer 3 defines the contract for verifying capability tokens at
// runtime, complementing the compile-time capability types described
// in the architecture specification (Section 3.2.1).
//
// ExpiryAwareCapabilityVerifier wraps another verifier rather than
// baking expiry into the base trait for composability — customers
// may want to apply expiry checks selectively.
// ═══════════════════════════════════════════════════════════════════════

use hmac::{Hmac, Mac};
use sha3::Sha3_256;

use crate::backend::IdentityRef;
use crate::error::PermissionError;

type HmacSha3_256 = Hmac<Sha3_256>;

// ── CapabilityToken ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CapabilityToken {
    pub token_id: String,
    pub subject: IdentityRef,
    pub granted_capabilities: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: Vec<u8>,
}

impl CapabilityToken {
    pub fn new(
        token_id: &str,
        subject: IdentityRef,
        capabilities: Vec<String>,
        issued_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            token_id: token_id.to_string(),
            subject,
            granted_capabilities: capabilities,
            issued_at,
            expires_at,
            signature: Vec::new(),
        }
    }

    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(self.token_id.as_bytes());
        payload.extend_from_slice(self.subject.as_str().as_bytes());
        for cap in &self.granted_capabilities {
            payload.extend_from_slice(cap.as_bytes());
        }
        payload.extend_from_slice(&self.issued_at.to_le_bytes());
        payload.extend_from_slice(&self.expires_at.to_le_bytes());
        payload
    }
}

// ── RequiredCapability ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RequiredCapability {
    pub capability: String,
    pub resource_scope: Option<String>,
}

impl RequiredCapability {
    pub fn new(capability: &str) -> Self {
        Self {
            capability: capability.to_string(),
            resource_scope: None,
        }
    }

    pub fn with_resource_scope(mut self, scope: &str) -> Self {
        self.resource_scope = Some(scope.to_string());
        self
    }
}

// ── CapabilityVerificationResult ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityVerificationResult {
    Valid { matched_capability: String },
    Invalid { reason: String },
    Expired,
    Revoked,
    InsufficientScope,
}

impl CapabilityVerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

impl std::fmt::Display for CapabilityVerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid { matched_capability } => write!(f, "Valid({matched_capability})"),
            Self::Invalid { reason } => write!(f, "Invalid({reason})"),
            Self::Expired => write!(f, "Expired"),
            Self::Revoked => write!(f, "Revoked"),
            Self::InsufficientScope => write!(f, "InsufficientScope"),
        }
    }
}

// ── CapabilityVerifier trait ─────────────────────────────────

pub trait CapabilityVerifier {
    fn verify_capability(
        &self,
        token: &CapabilityToken,
        required: &RequiredCapability,
    ) -> Result<CapabilityVerificationResult, PermissionError>;

    fn verifier_id(&self) -> &str;
    fn supported_capability_types(&self) -> Vec<String>;
    fn is_active(&self) -> bool;
}

// ── Constant-time comparison ─────────────────────────────────

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── HmacSha3CapabilityVerifier ───────────────────────────────

pub struct HmacSha3CapabilityVerifier {
    id: String,
    key: Vec<u8>,
}

impl HmacSha3CapabilityVerifier {
    pub fn new(id: &str, key: &[u8]) -> Self {
        Self {
            id: id.to_string(),
            key: key.to_vec(),
        }
    }

    pub fn sign_token(&self, token: &mut CapabilityToken) {
        let payload = token.signing_payload();
        let mut mac = HmacSha3_256::new_from_slice(&self.key)
            .expect("HMAC key can be any length");
        mac.update(&payload);
        token.signature = mac.finalize().into_bytes().to_vec();
    }
}

impl CapabilityVerifier for HmacSha3CapabilityVerifier {
    fn verify_capability(
        &self,
        token: &CapabilityToken,
        required: &RequiredCapability,
    ) -> Result<CapabilityVerificationResult, PermissionError> {
        // Verify signature
        let payload = token.signing_payload();
        let mut mac = HmacSha3_256::new_from_slice(&self.key)
            .expect("HMAC key can be any length");
        mac.update(&payload);
        let expected = mac.finalize().into_bytes();

        if !constant_time_eq(&token.signature, &expected) {
            return Ok(CapabilityVerificationResult::Invalid {
                reason: "signature verification failed".to_string(),
            });
        }

        // Check capability match
        let matched = token.granted_capabilities.iter().find(|cap| {
            **cap == required.capability || *cap == "*"
        });

        match matched {
            Some(cap) => Ok(CapabilityVerificationResult::Valid {
                matched_capability: cap.clone(),
            }),
            None => Ok(CapabilityVerificationResult::InsufficientScope),
        }
    }

    fn verifier_id(&self) -> &str {
        &self.id
    }

    fn supported_capability_types(&self) -> Vec<String> {
        vec!["hmac-sha3-256".to_string()]
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── ExpiryAwareCapabilityVerifier ────────────────────────────

pub struct ExpiryAwareCapabilityVerifier {
    id: String,
    inner: Box<dyn CapabilityVerifier>,
    now_fn: Box<dyn Fn() -> i64>,
}

impl ExpiryAwareCapabilityVerifier {
    pub fn new(id: &str, inner: Box<dyn CapabilityVerifier>) -> Self {
        Self {
            id: id.to_string(),
            inner,
            now_fn: Box::new(|| 0),
        }
    }

    pub fn with_clock(mut self, now_fn: impl Fn() -> i64 + 'static) -> Self {
        self.now_fn = Box::new(now_fn);
        self
    }
}

impl CapabilityVerifier for ExpiryAwareCapabilityVerifier {
    fn verify_capability(
        &self,
        token: &CapabilityToken,
        required: &RequiredCapability,
    ) -> Result<CapabilityVerificationResult, PermissionError> {
        let now = (self.now_fn)();
        if now >= token.expires_at {
            return Ok(CapabilityVerificationResult::Expired);
        }
        self.inner.verify_capability(token, required)
    }

    fn verifier_id(&self) -> &str {
        &self.id
    }

    fn supported_capability_types(&self) -> Vec<String> {
        self.inner.supported_capability_types()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── NullCapabilityVerifier ───────────────────────────────────

pub struct NullCapabilityVerifier {
    id: String,
}

impl NullCapabilityVerifier {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl CapabilityVerifier for NullCapabilityVerifier {
    fn verify_capability(
        &self,
        _token: &CapabilityToken,
        _required: &RequiredCapability,
    ) -> Result<CapabilityVerificationResult, PermissionError> {
        Ok(CapabilityVerificationResult::Invalid {
            reason: "null verifier always rejects".to_string(),
        })
    }

    fn verifier_id(&self) -> &str {
        &self.id
    }

    fn supported_capability_types(&self) -> Vec<String> {
        vec![]
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

    fn make_token() -> CapabilityToken {
        CapabilityToken::new(
            "tok-1",
            IdentityRef::new("alice"),
            vec!["file:read".to_string(), "file:write".to_string()],
            1000,
            5000,
        )
    }

    #[test]
    fn test_hmac_sign_and_verify() {
        let verifier = HmacSha3CapabilityVerifier::new("v1", b"secret-key");
        let mut token = make_token();
        verifier.sign_token(&mut token);
        assert!(!token.signature.is_empty());

        let result = verifier.verify_capability(&token, &RequiredCapability::new("file:read")).unwrap();
        assert!(result.is_valid());
        if let CapabilityVerificationResult::Valid { matched_capability } = &result {
            assert_eq!(matched_capability, "file:read");
        }
    }

    #[test]
    fn test_hmac_verify_wrong_key() {
        let signer = HmacSha3CapabilityVerifier::new("v1", b"key-a");
        let verifier = HmacSha3CapabilityVerifier::new("v2", b"key-b");
        let mut token = make_token();
        signer.sign_token(&mut token);

        let result = verifier.verify_capability(&token, &RequiredCapability::new("file:read")).unwrap();
        assert!(!result.is_valid());
        assert!(matches!(result, CapabilityVerificationResult::Invalid { .. }));
    }

    #[test]
    fn test_hmac_verify_insufficient_scope() {
        let verifier = HmacSha3CapabilityVerifier::new("v1", b"secret-key");
        let mut token = make_token();
        verifier.sign_token(&mut token);

        let result = verifier.verify_capability(&token, &RequiredCapability::new("admin:delete")).unwrap();
        assert!(matches!(result, CapabilityVerificationResult::InsufficientScope));
    }

    #[test]
    fn test_hmac_wildcard_capability() {
        let verifier = HmacSha3CapabilityVerifier::new("v1", b"secret-key");
        let mut token = CapabilityToken::new(
            "tok-w", IdentityRef::new("admin"),
            vec!["*".to_string()], 1000, 5000,
        );
        verifier.sign_token(&mut token);

        let result = verifier.verify_capability(&token, &RequiredCapability::new("anything")).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_expiry_aware_verifier_not_expired() {
        let inner = HmacSha3CapabilityVerifier::new("inner", b"secret-key");
        let mut token = make_token(); // expires_at = 5000
        inner.sign_token(&mut token);

        let expiry = ExpiryAwareCapabilityVerifier::new("exp-1", Box::new(
            HmacSha3CapabilityVerifier::new("inner", b"secret-key"),
        )).with_clock(|| 3000);

        let result = expiry.verify_capability(&token, &RequiredCapability::new("file:read")).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_expiry_aware_verifier_expired() {
        let inner = HmacSha3CapabilityVerifier::new("inner", b"secret-key");
        let mut token = make_token(); // expires_at = 5000
        inner.sign_token(&mut token);

        let expiry = ExpiryAwareCapabilityVerifier::new("exp-1", Box::new(
            HmacSha3CapabilityVerifier::new("inner", b"secret-key"),
        )).with_clock(|| 6000);

        let result = expiry.verify_capability(&token, &RequiredCapability::new("file:read")).unwrap();
        assert!(matches!(result, CapabilityVerificationResult::Expired));
    }

    #[test]
    fn test_null_verifier_always_rejects() {
        let verifier = NullCapabilityVerifier::new("null-1");
        let token = make_token();
        let result = verifier.verify_capability(&token, &RequiredCapability::new("file:read")).unwrap();
        assert!(!result.is_valid());
        assert!(!verifier.is_active());
    }

    #[test]
    fn test_verification_result_display() {
        assert!(CapabilityVerificationResult::Valid { matched_capability: "x".into() }.to_string().contains("Valid"));
        assert!(CapabilityVerificationResult::Invalid { reason: "bad".into() }.to_string().contains("Invalid"));
        assert!(CapabilityVerificationResult::Expired.to_string().contains("Expired"));
        assert!(CapabilityVerificationResult::Revoked.to_string().contains("Revoked"));
        assert!(CapabilityVerificationResult::InsufficientScope.to_string().contains("InsufficientScope"));
    }

    #[test]
    fn test_required_capability_with_scope() {
        let req = RequiredCapability::new("file:read")
            .with_resource_scope("/docs/*");
        assert_eq!(req.capability, "file:read");
        assert_eq!(req.resource_scope, Some("/docs/*".to_string()));
    }

    #[test]
    fn test_verifier_metadata() {
        let v = HmacSha3CapabilityVerifier::new("v1", b"key");
        assert_eq!(v.verifier_id(), "v1");
        assert!(v.is_active());
        assert!(v.supported_capability_types().contains(&"hmac-sha3-256".to_string()));
    }

    #[test]
    fn test_deterministic_signature() {
        let verifier = HmacSha3CapabilityVerifier::new("v1", b"key");
        let mut t1 = make_token();
        let mut t2 = make_token();
        verifier.sign_token(&mut t1);
        verifier.sign_token(&mut t2);
        assert_eq!(t1.signature, t2.signature);
    }
}
