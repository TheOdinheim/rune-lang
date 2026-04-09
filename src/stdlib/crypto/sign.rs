// ═══════════════════════════════════════════════════════════════════════
// Digital Signatures and MACs — PQC-First
//
// Default: ML-DSA-65 (FIPS 204) — post-quantum approved.
//   PLACEHOLDER: uses HMAC-SHA3-256 internally until stable ml-dsa crate.
//   Interface matches ML-DSA-65 so the swap is a single-file change.
//
// Always available:
//   HMAC-SHA3-256 — PQC-approved symmetric MAC
//   HMAC-SHA256   — classical MAC, backward compatible with M5 audit trail
//
// Effect requirement: all sign/verify functions require the `crypto` effect.
// ═══════════════════════════════════════════════════════════════════════

use hmac::{Hmac, Mac};

use super::error::CryptoError;

// ── Algorithm selection ─────────────────────────────────────────────

/// Signature algorithm selection. PQC-first: ML-DSA-65 is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ML-DSA-65 (FIPS 204) — PQC default.
    /// PLACEHOLDER: uses HMAC-SHA3-256 until stable crate available.
    MlDsa65,
    /// HMAC-SHA3-256 — PQC-approved symmetric MAC.
    HmacSha3_256,
    /// HMAC-SHA256 — classical symmetric MAC.
    HmacSha256,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::MlDsa65
    }
}

/// HMAC algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgorithm {
    /// HMAC-SHA3-256 (PQC-approved).
    Sha3_256,
    /// HMAC-SHA256 (classical).
    Sha256,
}

// ── HMAC types ──────────────────────────────────────────────────────

type HmacSha3_256 = Hmac<sha3::Sha3_256>;
type HmacSha256 = Hmac<sha2::Sha256>;

// ── ML-DSA placeholder ──────────────────────────────────────────────
//
// ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204) is the PQC-default signature.
// No stable Rust crate exists yet with NIST-approved ML-DSA-65.
// The interface below matches what the real implementation will provide.
// Internally uses HMAC-SHA3-256 as a deterministic stand-in.
// When a stable ml-dsa crate is available, replace the bodies below.

/// Sign data using ML-DSA-65 (FIPS 204).
/// PLACEHOLDER: uses HMAC-SHA3-256. Interface is correct for ML-DSA-65.
pub fn ml_dsa_sign(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_sha3_256(key, data)
}

/// Verify an ML-DSA-65 signature.
/// PLACEHOLDER: verifies HMAC-SHA3-256. Interface is correct for ML-DSA-65.
pub fn ml_dsa_verify(key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    hmac_verify(key, data, signature, HmacAlgorithm::Sha3_256)
}

// ── HMAC functions ──────────────────────────────────────────────────

/// Compute HMAC-SHA3-256. PQC-approved symmetric MAC.
pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha3_256::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Compute HMAC-SHA256. Classical MAC, backward compatible with M5 audit trail.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Verify an HMAC using the specified algorithm.
pub fn hmac_verify(key: &[u8], data: &[u8], mac_bytes: &[u8], algorithm: HmacAlgorithm) -> bool {
    let expected = match algorithm {
        HmacAlgorithm::Sha3_256 => hmac_sha3_256(key, data),
        HmacAlgorithm::Sha256 => hmac_sha256(key, data),
    };
    constant_time_eq(&expected, mac_bytes)
}

// ── Generic interface ───────────────────────────────────────────────

/// Sign data using the specified algorithm.
pub fn sign(
    algorithm: SignatureAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        SignatureAlgorithm::MlDsa65 => Ok(ml_dsa_sign(key, data)),
        SignatureAlgorithm::HmacSha3_256 => Ok(hmac_sha3_256(key, data)),
        SignatureAlgorithm::HmacSha256 => Ok(hmac_sha256(key, data)),
    }
}

/// Verify a signature using the specified algorithm.
pub fn verify(
    algorithm: SignatureAlgorithm,
    key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    match algorithm {
        SignatureAlgorithm::MlDsa65 => Ok(ml_dsa_verify(key, data, signature)),
        SignatureAlgorithm::HmacSha3_256 => {
            Ok(hmac_verify(key, data, signature, HmacAlgorithm::Sha3_256))
        }
        SignatureAlgorithm::HmacSha256 => {
            Ok(hmac_verify(key, data, signature, HmacAlgorithm::Sha256))
        }
    }
}

// ── Constant-time comparison ────────────────────────────────────────

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

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha3_256_consistent() {
        let key = b"secret-key";
        let data = b"hello world";
        assert_eq!(hmac_sha3_256(key, data), hmac_sha3_256(key, data));
    }

    #[test]
    fn test_hmac_sha3_256_different_keys_differ() {
        let data = b"hello";
        assert_ne!(hmac_sha3_256(b"key1", data), hmac_sha3_256(b"key2", data));
    }

    #[test]
    fn test_hmac_verify_correct_key() {
        let key = b"my-key";
        let data = b"test data";
        let mac = hmac_sha3_256(key, data);
        assert!(hmac_verify(key, data, &mac, HmacAlgorithm::Sha3_256));
    }

    #[test]
    fn test_hmac_verify_wrong_key() {
        let data = b"test data";
        let mac = hmac_sha3_256(b"right-key", data);
        assert!(!hmac_verify(b"wrong-key", data, &mac, HmacAlgorithm::Sha3_256));
    }

    #[test]
    fn test_hmac_sha256_consistent() {
        let key = b"key";
        let data = b"data";
        assert_eq!(hmac_sha256(key, data), hmac_sha256(key, data));
    }

    #[test]
    fn test_ml_dsa_sign_produces_output() {
        let sig = ml_dsa_sign(b"key", b"data");
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_ml_dsa_verify_correct_key() {
        let key = b"my-signing-key";
        let data = b"policy decision";
        let sig = ml_dsa_sign(key, data);
        assert!(ml_dsa_verify(key, data, &sig));
    }

    #[test]
    fn test_ml_dsa_verify_wrong_key() {
        let data = b"policy decision";
        let sig = ml_dsa_sign(b"real-key", data);
        assert!(!ml_dsa_verify(b"fake-key", data, &sig));
    }

    #[test]
    fn test_sign_ml_dsa_dispatches() {
        let key = b"key";
        let data = b"data";
        let sig = sign(SignatureAlgorithm::MlDsa65, key, data).unwrap();
        assert_eq!(sig, ml_dsa_sign(key, data));
    }

    #[test]
    fn test_verify_ml_dsa_dispatches() {
        let key = b"key";
        let data = b"data";
        let sig = ml_dsa_sign(key, data);
        let result = verify(SignatureAlgorithm::MlDsa65, key, data, &sig).unwrap();
        assert!(result);
    }

    #[test]
    fn test_default_algorithm_is_ml_dsa() {
        assert_eq!(SignatureAlgorithm::default(), SignatureAlgorithm::MlDsa65);
    }
}
