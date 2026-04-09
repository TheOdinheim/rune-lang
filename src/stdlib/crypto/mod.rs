// ═══════════════════════════════════════════════════════════════════════
// rune::crypto — PQC-First Cryptographic Primitives
//
// Post-quantum by default, classical as explicit fallback.
//
// Hashing:    SHA-3 (FIPS 202) default, SHA-256 classical fallback
// Signatures: ML-DSA-65 (FIPS 204) default (placeholder), HMAC-SHA3-256, HMAC-SHA256
// KEM:        ML-KEM-768 (FIPS 203) placeholder (interface defined)
//
// Effect requirement: all crypto operations carry the `crypto` effect.
// RUNE code calling these functions must declare `effects { crypto }`.
//
// Architecture: single-file swap for PQC implementations.
// When stable ml-dsa/ml-kem crates are available, replace sign.rs and
// kem.rs internals. No other code needs to change.
// ═══════════════════════════════════════════════════════════════════════

pub mod error;
pub mod hash;
pub mod sign;
pub mod verify;
pub mod kem;

// ── Re-exports ──────────────────────────────────────────────────────

pub use error::CryptoError;
pub use hash::{sha3_256, sha3_512, sha3_256_hex, sha256, sha256_hex, hash, hash_hex, HashAlgorithm};
pub use sign::{
    ml_dsa_sign, ml_dsa_verify,
    hmac_sha3_256, hmac_sha256, hmac_verify,
    sign as crypto_sign, verify as crypto_verify,
    SignatureAlgorithm, HmacAlgorithm,
};
pub use verify::{verify_hash, verify_signed_hash};
pub use kem::{kem_keygen, kem_encapsulate, kem_decapsulate, KemAlgorithm};

// ── Convenience defaults (PQC-first) ────────────────────────────────

/// Hash data using the PQC default (SHA3-256).
pub fn default_hash(data: &[u8]) -> Vec<u8> {
    sha3_256(data).to_vec()
}

/// Sign data using the PQC default (ML-DSA-65 placeholder).
pub fn default_sign(key: &[u8], data: &[u8]) -> Vec<u8> {
    ml_dsa_sign(key, data)
}

/// Verify a signature using the PQC default (ML-DSA-65 placeholder).
pub fn default_verify(key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    ml_dsa_verify(key, data, signature)
}

// ── Effect documentation ────────────────────────────────────────────

/// Documents the effect requirements for RUNE crypto operations.
/// When called from RUNE source via FFI, these functions require:
///   fn my_function() -> T with effects { ffi, crypto } { ... }
///
/// The effect enforcement is handled by the type checker's effect system
/// (M2 Layer 3). The `crypto` effect annotation is semantic — it marks
/// functions that perform cryptographic operations.
pub struct CryptoEffects;

impl CryptoEffects {
    /// Hash operations require: effects { crypto }
    pub const HASH: &'static str = "crypto";
    /// Sign operations require: effects { crypto }
    pub const SIGN: &'static str = "crypto";
    /// Verify operations require: effects { crypto }
    pub const VERIFY: &'static str = "crypto";
    /// KEM operations require: effects { crypto }
    pub const KEM: &'static str = "crypto";
}

// ── Module-level tests ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_hash_is_sha3_256() {
        let data = b"test";
        assert_eq!(default_hash(data), sha3_256(data).to_vec());
    }

    #[test]
    fn test_default_sign_is_ml_dsa() {
        let key = b"key";
        let data = b"data";
        assert_eq!(default_sign(key, data), ml_dsa_sign(key, data));
    }

    #[test]
    fn test_default_verify_is_ml_dsa() {
        let key = b"key";
        let data = b"data";
        let sig = default_sign(key, data);
        assert!(default_verify(key, data, &sig));
    }

    #[test]
    fn test_default_verify_wrong_key_fails() {
        let sig = default_sign(b"right-key", b"data");
        assert!(!default_verify(b"wrong-key", b"data", &sig));
    }

    // ── Backward compatibility with M5 audit trail ──────────────

    #[test]
    fn test_hmac_sha256_matches_audit_crypto() {
        // The existing audit::crypto::sign uses HMAC-SHA256.
        // Verify our stdlib hmac_sha256 produces the same output.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let key = b"test-signing-key";
        let data = b"record-hash-value";

        // Reproduce the exact logic from audit::crypto::sign
        type AuditHmac = Hmac<Sha256>;
        let mut mac = AuditHmac::new_from_slice(key).unwrap();
        mac.update(data);
        let audit_output = mac.finalize().into_bytes().to_vec();

        // Our stdlib function should match
        let stdlib_output = hmac_sha256(key, data);
        assert_eq!(audit_output, stdlib_output);
    }

    #[test]
    fn test_sha256_matches_audit_crypto_hash() {
        // The existing audit::crypto::hash uses SHA-256.
        // Verify our stdlib sha256 produces the same output.
        use sha2::Digest;

        let payload = "test payload";

        // Reproduce the exact logic from audit::crypto::hash
        let mut hasher = sha2::Sha256::new();
        hasher.update(payload.as_bytes());
        let audit_output = hex::encode(hasher.finalize());

        // Our stdlib function should match
        let stdlib_output = sha256_hex(payload.as_bytes());
        assert_eq!(audit_output, stdlib_output);
    }

    // ── Error type tests ────────────────────────────────────────

    #[test]
    fn test_crypto_error_display_invalid_key() {
        let err = CryptoError::InvalidKeyLength { expected: 32, actual: 16 };
        let msg = format!("{err}");
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn test_crypto_error_display_invalid_signature() {
        let err = CryptoError::InvalidSignatureLength { expected: 64, actual: 32 };
        let msg = format!("{err}");
        assert!(msg.contains("64"));
        assert!(msg.contains("32"));
    }

    #[test]
    fn test_crypto_error_display_verification_failed() {
        let err = CryptoError::VerificationFailed;
        assert_eq!(format!("{err}"), "verification failed");
    }

    #[test]
    fn test_crypto_error_display_unsupported() {
        let err = CryptoError::UnsupportedAlgorithm("XYZ".to_string());
        assert!(format!("{err}").contains("XYZ"));
    }

    #[test]
    fn test_crypto_error_display_not_implemented() {
        let err = CryptoError::NotImplemented("KEM".to_string());
        assert!(format!("{err}").contains("KEM"));
    }

    #[test]
    fn test_crypto_error_display_internal() {
        let err = CryptoError::InternalError("oops".to_string());
        assert!(format!("{err}").contains("oops"));
    }
}
