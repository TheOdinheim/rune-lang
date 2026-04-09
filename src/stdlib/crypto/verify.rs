// ═══════════════════════════════════════════════════════════════════════
// Verification Utilities
//
// Higher-level verification functions combining hash and signature checks.
// Used by the audit trail and attestation systems.
// ═══════════════════════════════════════════════════════════════════════

use super::error::CryptoError;
use super::hash::{sha3_256, HashAlgorithm};
use super::sign::{verify as sig_verify, SignatureAlgorithm};

/// Verify that data matches a given hash (hex-encoded).
pub fn verify_hash(data: &[u8], expected_hex: &str, algorithm: HashAlgorithm) -> bool {
    let actual_hex = super::hash::hash_hex(algorithm, data);
    constant_time_eq_str(&actual_hex, expected_hex)
}

/// Verify a signature over the SHA3-256 hash of data.
/// This is the standard pattern: hash-then-verify.
pub fn verify_signed_hash(
    key: &[u8],
    data: &[u8],
    signature: &[u8],
    algorithm: SignatureAlgorithm,
) -> Result<bool, CryptoError> {
    let hash = sha3_256(data);
    sig_verify(algorithm, key, &hash, signature)
}

fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::crypto::hash::sha3_256_hex;

    #[test]
    fn test_verify_hash_correct() {
        let data = b"hello";
        let expected = sha3_256_hex(data);
        assert!(verify_hash(data, &expected, HashAlgorithm::Sha3_256));
    }

    #[test]
    fn test_verify_hash_wrong_data() {
        let expected = sha3_256_hex(b"hello");
        assert!(!verify_hash(b"world", &expected, HashAlgorithm::Sha3_256));
    }

    #[test]
    fn test_verify_signed_hash() {
        use crate::stdlib::crypto::sign::ml_dsa_sign;
        let key = b"test-key";
        let data = b"important data";
        let hash = sha3_256(data);
        let sig = ml_dsa_sign(key, &hash);
        let result = verify_signed_hash(key, data, &sig, SignatureAlgorithm::MlDsa65).unwrap();
        assert!(result);
    }
}
