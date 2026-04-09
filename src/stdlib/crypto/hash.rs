// ═══════════════════════════════════════════════════════════════════════
// Cryptographic Hashing — PQC-First
//
// Default: SHA-3 (FIPS 202) — post-quantum approved.
// Fallback: SHA-256 — classical, for backward compatibility.
//
// Effect requirement: calling any hash function from RUNE source
// requires the `crypto` effect annotation.
// ═══════════════════════════════════════════════════════════════════════

use sha2::Digest as Sha2Digest;
use sha3::Digest as Sha3Digest;

// ── Algorithm selection ─────────────────────────────────────────────

/// Hash algorithm selection. PQC-first: SHA3-256 is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA3-256 (FIPS 202) — PQC default.
    Sha3_256,
    /// SHA3-512 (FIPS 202) — PQC, longer output.
    Sha3_512,
    /// SHA-256 — classical fallback for interoperability.
    Sha256,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha3_256
    }
}

// ── SHA-3 functions (PQC) ───────────────────────────────────────────

/// Compute SHA3-256 hash (FIPS 202). This is the PQC-approved default.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA3-512 hash (FIPS 202).
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA3-256 returning a lowercase hex string.
pub fn sha3_256_hex(data: &[u8]) -> String {
    hex::encode(sha3_256(data))
}

// ── SHA-256 functions (classical fallback) ──────────────────────────

/// Compute SHA-256 hash. Classical fallback for interoperability.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256 returning a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

// ── Generic interface ───────────────────────────────────────────────

/// Hash data using the specified algorithm. Default is SHA3-256 (PQC).
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha3_256 => sha3_256(data).to_vec(),
        HashAlgorithm::Sha3_512 => sha3_512(data).to_vec(),
        HashAlgorithm::Sha256 => sha256(data).to_vec(),
    }
}

/// Hash data returning a hex string.
pub fn hash_hex(algorithm: HashAlgorithm, data: &[u8]) -> String {
    hex::encode(hash(algorithm, data))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_produces_32_bytes() {
        let result = sha3_256(b"hello");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha3_256_deterministic() {
        assert_eq!(sha3_256(b"test"), sha3_256(b"test"));
    }

    #[test]
    fn test_sha3_256_different_inputs_differ() {
        assert_ne!(sha3_256(b"hello"), sha3_256(b"world"));
    }

    #[test]
    fn test_sha3_256_hex_produces_64_chars() {
        let hex = sha3_256_hex(b"hello");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sha3_512_produces_64_bytes() {
        let result = sha3_512(b"hello");
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_sha256_produces_32_bytes() {
        let result = sha256(b"hello");
        assert_eq!(result.len(), 32);
    }

    // NIST test vector: SHA-256("abc") = ba7816bf...
    #[test]
    fn test_sha256_known_vector() {
        let result = sha256_hex(b"abc");
        assert_eq!(
            result,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // NIST test vector: SHA3-256("abc") = 3a985da7...
    #[test]
    fn test_sha3_256_known_vector() {
        let result = sha3_256_hex(b"abc");
        assert_eq!(
            result,
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn test_hash_sha3_256_matches_direct() {
        let data = b"test data";
        assert_eq!(hash(HashAlgorithm::Sha3_256, data), sha3_256(data).to_vec());
    }

    #[test]
    fn test_hash_sha256_matches_direct() {
        let data = b"test data";
        assert_eq!(hash(HashAlgorithm::Sha256, data), sha256(data).to_vec());
    }

    #[test]
    fn test_default_algorithm_is_sha3_256() {
        assert_eq!(HashAlgorithm::default(), HashAlgorithm::Sha3_256);
    }
}
