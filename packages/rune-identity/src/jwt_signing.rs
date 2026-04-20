// ═══════════════════════════════════════════════════════════════════════
// JWT Signing and Verification — Signature-level JWT traits.
//
// Layer 3 defines the contract for JWT signing and signature
// verification. This is the complementary piece to rune-web's
// JwtStructureValidator: rune-web validates structure and claims
// presence, rune-identity validates signatures.
//
// Only HMAC-SHA3-256 has a reference implementation at this layer.
// Asymmetric JWT signing (RSA, ECDSA, EdDSA) requires ring or
// rustcrypto-sigs and belongs in adapter crates.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use hmac::{Hmac, Mac};
use sha3::Sha3_256;

type HmacSha3_256 = Hmac<Sha3_256>;

// ── JwtAlgorithm ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtAlgorithm {
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Rs384,
    Rs512,
    Es256,
    EdDsa,
    HmacSha3_256,
}

impl fmt::Display for JwtAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hs256 => write!(f, "HS256"),
            Self::Hs384 => write!(f, "HS384"),
            Self::Hs512 => write!(f, "HS512"),
            Self::Rs256 => write!(f, "RS256"),
            Self::Rs384 => write!(f, "RS384"),
            Self::Rs512 => write!(f, "RS512"),
            Self::Es256 => write!(f, "ES256"),
            Self::EdDsa => write!(f, "EdDSA"),
            Self::HmacSha3_256 => write!(f, "HMAC-SHA3-256"),
        }
    }
}

// ── JwtClaims ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct JwtClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub nbf: Option<i64>,
    pub iat: i64,
    pub jti: Option<String>,
    pub custom_claims: HashMap<String, String>,
}

impl JwtClaims {
    pub fn new(sub: &str, iss: &str, aud: &str, iat: i64, exp: i64) -> Self {
        Self {
            sub: sub.to_string(),
            iss: iss.to_string(),
            aud: aud.to_string(),
            exp,
            nbf: None,
            iat,
            jti: None,
            custom_claims: HashMap::new(),
        }
    }

    pub fn with_jti(mut self, jti: &str) -> Self {
        self.jti = Some(jti.to_string());
        self
    }

    pub fn with_nbf(mut self, nbf: i64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    pub fn with_claim(mut self, key: &str, value: &str) -> Self {
        self.custom_claims.insert(key.to_string(), value.to_string());
        self
    }

    fn to_json(&self) -> String {
        let mut parts = vec![
            format!("\"sub\":\"{}\"", self.sub),
            format!("\"iss\":\"{}\"", self.iss),
            format!("\"aud\":\"{}\"", self.aud),
            format!("\"exp\":{}", self.exp),
            format!("\"iat\":{}", self.iat),
        ];
        if let Some(nbf) = self.nbf {
            parts.push(format!("\"nbf\":{nbf}"));
        }
        if let Some(ref jti) = self.jti {
            parts.push(format!("\"jti\":\"{jti}\""));
        }
        for (k, v) in &self.custom_claims {
            parts.push(format!("\"{k}\":\"{v}\""));
        }
        format!("{{{}}}", parts.join(","))
    }
}

// ── SignatureVerification ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureVerification {
    Valid { algorithm: JwtAlgorithm },
    Invalid { reason: String },
    AlgorithmMismatch,
    Expired,
}

impl SignatureVerification {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

// ── JwtSigner trait ───────────────────────────────────────────

pub trait JwtSigner {
    fn sign_jwt(&self, claims: &JwtClaims, signing_key: &[u8]) -> String;
    fn supported_algorithms(&self) -> Vec<JwtAlgorithm>;
    fn signer_id(&self) -> &str;
}

// ── JwtSignatureVerifier trait ────────────────────────────────

pub trait JwtSignatureVerifier {
    fn verify_signature(&self, jwt: &str, verification_key: &[u8]) -> SignatureVerification;
    fn supported_algorithms(&self) -> Vec<JwtAlgorithm>;
    fn verifier_id(&self) -> &str;
}

// ── Base64url helpers ─────────────────────────────────────────

fn base64url_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        result.push(TABLE[b0 >> 2] as char);
        result.push(TABLE[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            result.push(TABLE[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        }
        if chunk.len() > 2 {
            result.push(TABLE[b2 & 0x3f] as char);
        }
    }
    result.replace('+', "-").replace('/', "_")
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut s = input.replace('-', "+").replace('_', "/");
    let pad = (4 - s.len() % 4) % 4;
    for _ in 0..pad {
        s.push('=');
    }
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    for chunk in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = TABLE.iter().position(|&c| c == b).unwrap_or(0) as u8;
        }
        output.push((buf[0] << 2) | (buf[1] >> 4));
        if chunk.len() > 2 {
            output.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if chunk.len() > 3 {
            output.push((buf[2] << 6) | buf[3]);
        }
    }
    Some(output)
}

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

// ── HmacSha3Sha256JwtSigner ──────────────────────────────────

pub struct HmacSha3Sha256JwtSigner {
    id: String,
}

impl HmacSha3Sha256JwtSigner {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }

    fn compute_signature(data: &[u8], key: &[u8]) -> String {
        let mut mac = HmacSha3_256::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(data);
        base64url_encode(&mac.finalize().into_bytes())
    }
}

impl JwtSigner for HmacSha3Sha256JwtSigner {
    fn sign_jwt(&self, claims: &JwtClaims, signing_key: &[u8]) -> String {
        let header = r#"{"alg":"HMAC-SHA3-256","typ":"JWT"}"#;
        let header_b64 = base64url_encode(header.as_bytes());
        let payload_b64 = base64url_encode(claims.to_json().as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = Self::compute_signature(signing_input.as_bytes(), signing_key);
        format!("{signing_input}.{signature}")
    }

    fn supported_algorithms(&self) -> Vec<JwtAlgorithm> {
        vec![JwtAlgorithm::HmacSha3_256]
    }

    fn signer_id(&self) -> &str {
        &self.id
    }
}

// ── HmacSha3Sha256JwtSignatureVerifier ────────────────────────

pub struct HmacSha3Sha256JwtSignatureVerifier {
    id: String,
}

impl HmacSha3Sha256JwtSignatureVerifier {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl JwtSignatureVerifier for HmacSha3Sha256JwtSignatureVerifier {
    fn verify_signature(&self, jwt: &str, verification_key: &[u8]) -> SignatureVerification {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return SignatureVerification::Invalid {
                reason: "JWT must have 3 parts".to_string(),
            };
        }

        // Check algorithm in header
        let header_bytes = match base64url_decode(parts[0]) {
            Some(b) => b,
            None => return SignatureVerification::Invalid {
                reason: "Invalid base64 in header".to_string(),
            },
        };
        let header_str = match String::from_utf8(header_bytes) {
            Ok(s) => s,
            Err(_) => return SignatureVerification::Invalid {
                reason: "Header is not valid UTF-8".to_string(),
            },
        };
        if !header_str.contains("HMAC-SHA3-256") {
            return SignatureVerification::AlgorithmMismatch;
        }

        // Check expiration from payload
        if let Some(payload_bytes) = base64url_decode(parts[1]) {
            if let Ok(payload_str) = String::from_utf8(payload_bytes) {
                if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
                        // We don't have a "now" parameter, so expiration check is
                        // deferred to the caller. This verifier focuses on signature.
                        let _ = exp;
                    }
                }
            }
        }

        // Recompute signature
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let expected = HmacSha3Sha256JwtSigner::compute_signature(signing_input.as_bytes(), verification_key);

        if constant_time_eq(expected.as_bytes(), parts[2].as_bytes()) {
            SignatureVerification::Valid {
                algorithm: JwtAlgorithm::HmacSha3_256,
            }
        } else {
            SignatureVerification::Invalid {
                reason: "Signature mismatch".to_string(),
            }
        }
    }

    fn supported_algorithms(&self) -> Vec<JwtAlgorithm> {
        vec![JwtAlgorithm::HmacSha3_256]
    }

    fn verifier_id(&self) -> &str {
        &self.id
    }
}

// ── NullJwtSigner ─────────────────────────────────────────────

pub struct NullJwtSigner {
    id: String,
}

impl NullJwtSigner {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl JwtSigner for NullJwtSigner {
    fn sign_jwt(&self, claims: &JwtClaims, _signing_key: &[u8]) -> String {
        let header = r#"{"alg":"none","typ":"JWT"}"#;
        let header_b64 = base64url_encode(header.as_bytes());
        let payload_b64 = base64url_encode(claims.to_json().as_bytes());
        format!("{header_b64}.{payload_b64}.")
    }

    fn supported_algorithms(&self) -> Vec<JwtAlgorithm> {
        vec![]
    }

    fn signer_id(&self) -> &str {
        &self.id
    }
}

// ── NullJwtSignatureVerifier ──────────────────────────────────

pub struct NullJwtSignatureVerifier {
    id: String,
}

impl NullJwtSignatureVerifier {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl JwtSignatureVerifier for NullJwtSignatureVerifier {
    fn verify_signature(&self, _jwt: &str, _verification_key: &[u8]) -> SignatureVerification {
        SignatureVerification::Invalid {
            reason: "null verifier always rejects".to_string(),
        }
    }

    fn supported_algorithms(&self) -> Vec<JwtAlgorithm> {
        vec![]
    }

    fn verifier_id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![0xAA; 32]
    }

    fn test_claims() -> JwtClaims {
        JwtClaims::new("user:alice", "rune-identity", "rune-web", 1000, 9999999999)
            .with_jti("jti-001")
            .with_claim("role", "admin")
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let key = test_key();
        let signer = HmacSha3Sha256JwtSigner::new("s1");
        let verifier = HmacSha3Sha256JwtSignatureVerifier::new("v1");

        let jwt = signer.sign_jwt(&test_claims(), &key);
        assert!(jwt.contains('.'));
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        let result = verifier.verify_signature(&jwt, &key);
        assert!(result.is_valid());
    }

    #[test]
    fn test_verify_wrong_key() {
        let signer = HmacSha3Sha256JwtSigner::new("s1");
        let verifier = HmacSha3Sha256JwtSignatureVerifier::new("v1");

        let jwt = signer.sign_jwt(&test_claims(), &test_key());
        let result = verifier.verify_signature(&jwt, b"wrong-key-000000000000000000000000");
        assert!(!result.is_valid());
    }

    #[test]
    fn test_verify_tampered_payload() {
        let signer = HmacSha3Sha256JwtSigner::new("s1");
        let verifier = HmacSha3Sha256JwtSignatureVerifier::new("v1");
        let key = test_key();

        let jwt = signer.sign_jwt(&test_claims(), &key);
        // Tamper with payload
        let parts: Vec<&str> = jwt.split('.').collect();
        let tampered = format!("{}.{}.{}", parts[0], "dGFtcGVyZWQ", parts[2]);
        let result = verifier.verify_signature(&tampered, &key);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_verify_algorithm_mismatch() {
        let verifier = HmacSha3Sha256JwtSignatureVerifier::new("v1");
        // JWT with HS256 algorithm header
        let header = base64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64url_encode(br#"{"sub":"user"}"#);
        let jwt = format!("{header}.{payload}.fakesig");
        let result = verifier.verify_signature(&jwt, &test_key());
        assert_eq!(result, SignatureVerification::AlgorithmMismatch);
    }

    #[test]
    fn test_verify_malformed_jwt() {
        let verifier = HmacSha3Sha256JwtSignatureVerifier::new("v1");
        let result = verifier.verify_signature("not-a-jwt", &test_key());
        assert!(!result.is_valid());
    }

    #[test]
    fn test_null_signer() {
        let signer = NullJwtSigner::new("null-s");
        let jwt = signer.sign_jwt(&test_claims(), &test_key());
        assert!(jwt.ends_with('.'));
        assert!(signer.supported_algorithms().is_empty());
    }

    #[test]
    fn test_null_verifier() {
        let verifier = NullJwtSignatureVerifier::new("null-v");
        let result = verifier.verify_signature("any.jwt.here", &test_key());
        assert!(!result.is_valid());
        assert!(verifier.supported_algorithms().is_empty());
    }

    #[test]
    fn test_jwt_claims_to_json() {
        let claims = test_claims();
        let json = claims.to_json();
        assert!(json.contains("\"sub\":\"user:alice\""));
        assert!(json.contains("\"iss\":\"rune-identity\""));
        assert!(json.contains("\"role\":\"admin\""));
        assert!(json.contains("\"jti\":\"jti-001\""));
    }

    #[test]
    fn test_jwt_algorithm_display() {
        assert_eq!(JwtAlgorithm::Hs256.to_string(), "HS256");
        assert_eq!(JwtAlgorithm::Rs256.to_string(), "RS256");
        assert_eq!(JwtAlgorithm::Es256.to_string(), "ES256");
        assert_eq!(JwtAlgorithm::EdDsa.to_string(), "EdDSA");
        assert_eq!(JwtAlgorithm::HmacSha3_256.to_string(), "HMAC-SHA3-256");
    }

    #[test]
    fn test_signature_verification_variants() {
        assert!(SignatureVerification::Valid { algorithm: JwtAlgorithm::HmacSha3_256 }.is_valid());
        assert!(!SignatureVerification::Invalid { reason: "bad".into() }.is_valid());
        assert!(!SignatureVerification::AlgorithmMismatch.is_valid());
        assert!(!SignatureVerification::Expired.is_valid());
    }

    #[test]
    fn test_signer_metadata() {
        let signer = HmacSha3Sha256JwtSigner::new("s1");
        assert_eq!(signer.signer_id(), "s1");
        assert_eq!(signer.supported_algorithms(), vec![JwtAlgorithm::HmacSha3_256]);
    }

    #[test]
    fn test_verifier_metadata() {
        let verifier = HmacSha3Sha256JwtSignatureVerifier::new("v1");
        assert_eq!(verifier.verifier_id(), "v1");
        assert_eq!(verifier.supported_algorithms(), vec![JwtAlgorithm::HmacSha3_256]);
    }

    #[test]
    fn test_deterministic_signing() {
        let signer = HmacSha3Sha256JwtSigner::new("s1");
        let key = test_key();
        let claims = test_claims();
        let jwt1 = signer.sign_jwt(&claims, &key);
        let jwt2 = signer.sign_jwt(&claims, &key);
        assert_eq!(jwt1, jwt2);
    }
}
