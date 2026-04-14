// ═══════════════════════════════════════════════════════════════════════
// Signing — HMAC-based request signing and verification for API
// authentication. Ensures request integrity and authenticity.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

type HmacSha3_256 = Hmac<Sha3_256>;

// ── SigningAlgorithm ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    HmacSha3_256,
    HmacSha256,
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HmacSha3_256 => write!(f, "HMAC-SHA3-256"),
            Self::HmacSha256 => write!(f, "HMAC-SHA256"),
        }
    }
}

// ── SigningConfig ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SigningConfig {
    pub algorithm: SigningAlgorithm,
    pub signed_headers: Vec<String>,
    pub signature_header: String,
    pub timestamp_header: String,
    pub max_clock_skew_ms: i64,
    pub key_id_header: String,
}

// ── SignedRequest ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SignedRequest {
    pub signature: String,
    pub key_id: String,
    pub timestamp: i64,
    pub headers_to_add: HashMap<String, String>,
}

// ── SignatureVerification ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SignatureVerification {
    pub valid: bool,
    pub reason: Option<String>,
    pub clock_skew_ms: i64,
    pub key_id: String,
}

// ── SignatureMetadata ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SignatureMetadata {
    pub algorithm: String,
    pub signed_headers: Vec<String>,
    pub timestamp: i64,
    pub key_id: String,
    pub body_hash: String,
}

// ── RequestSigner ────────────────────────────────────────────────────

pub struct RequestSigner {
    config: SigningConfig,
}

impl RequestSigner {
    pub fn new(config: SigningConfig) -> Self {
        Self { config }
    }

    pub fn default_config() -> SigningConfig {
        SigningConfig {
            algorithm: SigningAlgorithm::HmacSha3_256,
            signed_headers: vec!["host".into(), "content-type".into(), "x-date".into()],
            signature_header: "X-Signature".into(),
            timestamp_header: "X-Date".into(),
            max_clock_skew_ms: 300_000,
            key_id_header: "X-Key-Id".into(),
        }
    }

    pub fn sign(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
        key: &[u8],
        key_id: &str,
        now: i64,
    ) -> SignedRequest {
        let canonical = self.build_canonical_string(method, path, headers, body);
        let signature = self.hmac_sign(key, canonical.as_bytes());

        let mut headers_to_add = HashMap::new();
        headers_to_add.insert(
            self.config.signature_header.clone(),
            signature.clone(),
        );
        headers_to_add.insert(
            self.config.timestamp_header.clone(),
            now.to_string(),
        );
        headers_to_add.insert(
            self.config.key_id_header.clone(),
            key_id.to_string(),
        );

        SignedRequest {
            signature,
            key_id: key_id.into(),
            timestamp: now,
            headers_to_add,
        }
    }

    pub fn verify(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
        key: &[u8],
        signature: &str,
        request_timestamp: i64,
        now: i64,
    ) -> SignatureVerification {
        let key_id = headers
            .get(&self.config.key_id_header)
            .cloned()
            .unwrap_or_default();

        let clock_skew_ms = (now - request_timestamp).abs() * 1000;

        // Check clock skew
        if clock_skew_ms > self.config.max_clock_skew_ms {
            return SignatureVerification {
                valid: false,
                reason: Some(format!(
                    "Clock skew {}ms exceeds maximum {}ms",
                    clock_skew_ms, self.config.max_clock_skew_ms
                )),
                clock_skew_ms,
                key_id,
            };
        }

        // Recompute signature
        let canonical = self.build_canonical_string(method, path, headers, body);
        let expected = self.hmac_sign(key, canonical.as_bytes());

        // Constant-time comparison
        let valid = constant_time_eq(signature.as_bytes(), expected.as_bytes());

        SignatureVerification {
            valid,
            reason: if valid { None } else { Some("Signature mismatch".into()) },
            clock_skew_ms,
            key_id,
        }
    }

    fn build_canonical_string(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
    ) -> String {
        let mut canonical = String::new();
        canonical.push_str(method);
        canonical.push('\n');
        canonical.push_str(path);
        canonical.push('\n');

        // Signed headers sorted by name, lowercased, values trimmed
        let mut signed: Vec<(String, String)> = self
            .config
            .signed_headers
            .iter()
            .filter_map(|h| {
                let lower = h.to_lowercase();
                // Collect all matching headers (handles duplicates)
                let values: Vec<String> = headers
                    .iter()
                    .filter(|(k, _)| k.to_lowercase() == lower)
                    .map(|(_, v)| v.trim().to_string())
                    .collect();
                if values.is_empty() {
                    None
                } else {
                    Some((lower, values.join(",")))
                }
            })
            .collect();
        signed.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, value) in &signed {
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('\n');
        }

        // Body hash using SHA3-256
        let body_hash = sha3_256_hex(body.unwrap_or("").as_bytes());
        canonical.push_str(&body_hash);

        canonical
    }

    fn hmac_sign(&self, key: &[u8], message: &[u8]) -> String {
        let mut mac = HmacSha3_256::new_from_slice(key)
            .expect("HMAC accepts any key size");
        mac.update(message);
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn sign_with_metadata(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
        key: &[u8],
        key_id: &str,
        now: i64,
    ) -> (SignedRequest, SignatureMetadata) {
        let signed_request = self.sign(method, path, headers, body, key, key_id, now);
        let body_hash = sha3_256_hex(body.unwrap_or("").as_bytes());
        let signed_headers: Vec<String> = self.config.signed_headers.iter().map(|h| h.to_lowercase()).collect();
        let metadata = SignatureMetadata {
            algorithm: "HMAC-SHA3-256".into(),
            signed_headers,
            timestamp: now,
            key_id: key_id.into(),
            body_hash,
        };
        (signed_request, metadata)
    }
}

/// SHA3-256 hash, returned as hex.
fn sha3_256_hex(data: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Derive a purpose-specific signing key from a master key using HMAC-SHA3-256.
pub fn derive_signing_key(master_key: &[u8], context: &str) -> Vec<u8> {
    let mut mac = HmacSha3_256::new_from_slice(master_key)
        .expect("HMAC accepts any key size");
    mac.update(context.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time byte comparison.
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

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> RequestSigner {
        RequestSigner::new(RequestSigner::default_config())
    }

    fn test_headers() -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("Host".into(), "api.example.com".into());
        h.insert("Content-Type".into(), "application/json".into());
        h.insert("X-Date".into(), "1000".into());
        h
    }

    #[test]
    fn test_sign_deterministic() {
        let signer = test_signer();
        let headers = test_headers();
        let key = b"secret-key";
        let s1 = signer.sign("POST", "/api/v1/data", &headers, Some("body"), key, "k1", 1000);
        let s2 = signer.sign("POST", "/api/v1/data", &headers, Some("body"), key, "k1", 1000);
        assert_eq!(s1.signature, s2.signature);
    }

    #[test]
    fn test_sign_different_keys_different_signatures() {
        let signer = test_signer();
        let headers = test_headers();
        let s1 = signer.sign("POST", "/api", &headers, Some("body"), b"key1", "k1", 1000);
        let s2 = signer.sign("POST", "/api", &headers, Some("body"), b"key2", "k2", 1000);
        assert_ne!(s1.signature, s2.signature);
    }

    #[test]
    fn test_verify_correct_key() {
        let signer = test_signer();
        let mut headers = test_headers();
        let key = b"secret-key";
        let signed = signer.sign("POST", "/api", &headers, Some("body"), key, "k1", 1000);
        headers.extend(signed.headers_to_add.clone());
        let result = signer.verify("POST", "/api", &headers, Some("body"), key, &signed.signature, 1000, 1000);
        assert!(result.valid);
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_verify_wrong_key() {
        let signer = test_signer();
        let mut headers = test_headers();
        let signed = signer.sign("POST", "/api", &headers, Some("body"), b"key1", "k1", 1000);
        headers.extend(signed.headers_to_add.clone());
        let result = signer.verify("POST", "/api", &headers, Some("body"), b"wrong-key", &signed.signature, 1000, 1000);
        assert!(!result.valid);
    }

    #[test]
    fn test_verify_clock_skew_exceeded() {
        let signer = test_signer();
        let mut headers = test_headers();
        let key = b"secret-key";
        let signed = signer.sign("POST", "/api", &headers, Some("body"), key, "k1", 1000);
        headers.extend(signed.headers_to_add.clone());
        // 500 seconds of skew = 500000ms, exceeds 300000ms max
        let result = signer.verify("POST", "/api", &headers, Some("body"), key, &signed.signature, 1000, 1500);
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("Clock skew"));
    }

    #[test]
    fn test_verify_tampered_body() {
        let signer = test_signer();
        let mut headers = test_headers();
        let key = b"secret-key";
        let signed = signer.sign("POST", "/api", &headers, Some("original"), key, "k1", 1000);
        headers.extend(signed.headers_to_add.clone());
        let result = signer.verify("POST", "/api", &headers, Some("tampered"), key, &signed.signature, 1000, 1000);
        assert!(!result.valid);
    }

    #[test]
    fn test_signed_request_contains_headers() {
        let signer = test_signer();
        let headers = test_headers();
        let signed = signer.sign("GET", "/api", &headers, None, b"key", "k1", 1000);
        assert!(signed.headers_to_add.contains_key("X-Signature"));
        assert!(signed.headers_to_add.contains_key("X-Date"));
        assert!(signed.headers_to_add.contains_key("X-Key-Id"));
    }

    #[test]
    fn test_signing_algorithm_display() {
        assert_eq!(SigningAlgorithm::HmacSha3_256.to_string(), "HMAC-SHA3-256");
        assert_eq!(SigningAlgorithm::HmacSha256.to_string(), "HMAC-SHA256");
    }

    #[test]
    fn test_default_config_uses_hmac_sha3() {
        let config = RequestSigner::default_config();
        assert_eq!(config.algorithm, SigningAlgorithm::HmacSha3_256);
    }

    // ── Layer 2 signing tests ──────────────────────────────────────

    #[test]
    fn test_real_hmac_sha3_256_produces_64_char_hex() {
        let signer = test_signer();
        let headers = test_headers();
        let signed = signer.sign("POST", "/api", &headers, Some("body"), b"key", "k1", 1000);
        assert_eq!(signed.signature.len(), 64);
        assert!(signed.signature.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_different_bodies_different_signatures() {
        let signer = test_signer();
        let headers = test_headers();
        let key = b"secret-key";
        let s1 = signer.sign("POST", "/api", &headers, Some("body-a"), key, "k1", 1000);
        let s2 = signer.sign("POST", "/api", &headers, Some("body-b"), key, "k1", 1000);
        assert_ne!(s1.signature, s2.signature);
    }

    #[test]
    fn test_derive_signing_key_different_contexts() {
        let master = b"master-secret";
        let k1 = derive_signing_key(master, "api-signing");
        let k2 = derive_signing_key(master, "webhook-signing");
        assert_ne!(k1, k2);
        assert_eq!(k1.len(), 32); // SHA3-256 output
    }

    #[test]
    fn test_derive_signing_key_deterministic() {
        let master = b"master";
        let k1 = derive_signing_key(master, "ctx");
        let k2 = derive_signing_key(master, "ctx");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_sign_with_metadata() {
        let signer = test_signer();
        let headers = test_headers();
        let (signed, metadata) = signer.sign_with_metadata(
            "POST", "/api", &headers, Some("body"), b"key", "k1", 1000,
        );
        assert_eq!(metadata.algorithm, "HMAC-SHA3-256");
        assert!(!metadata.signed_headers.is_empty());
        assert_eq!(metadata.key_id, "k1");
        assert_eq!(metadata.timestamp, 1000);
        assert_eq!(metadata.body_hash.len(), 64);
        assert_eq!(signed.signature.len(), 64);
    }

    #[test]
    fn test_canonical_normalizes_header_names() {
        let signer = test_signer();
        let mut h1 = HashMap::new();
        h1.insert("HOST".into(), "example.com".into());
        h1.insert("CONTENT-TYPE".into(), "application/json".into());
        h1.insert("X-DATE".into(), "1000".into());

        let mut h2 = HashMap::new();
        h2.insert("host".into(), "example.com".into());
        h2.insert("content-type".into(), "application/json".into());
        h2.insert("x-date".into(), "1000".into());

        let s1 = signer.sign("GET", "/api", &h1, None, b"key", "k1", 1000);
        let s2 = signer.sign("GET", "/api", &h2, None, b"key", "k1", 1000);
        assert_eq!(s1.signature, s2.signature);
    }

    #[test]
    fn test_canonical_trims_header_whitespace() {
        let signer = test_signer();
        let mut h1 = HashMap::new();
        h1.insert("Host".into(), "  example.com  ".into());
        h1.insert("Content-Type".into(), "application/json".into());
        h1.insert("X-Date".into(), "1000".into());

        let mut h2 = HashMap::new();
        h2.insert("Host".into(), "example.com".into());
        h2.insert("Content-Type".into(), "application/json".into());
        h2.insert("X-Date".into(), "1000".into());

        let s1 = signer.sign("GET", "/api", &h1, None, b"key", "k1", 1000);
        let s2 = signer.sign("GET", "/api", &h2, None, b"key", "k1", 1000);
        assert_eq!(s1.signature, s2.signature);
    }
}
