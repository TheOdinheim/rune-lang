// ═══════════════════════════════════════════════════════════════════════
// Key Encapsulation Mechanism — ML-KEM (FIPS 203)
//
// PLACEHOLDER: Interface defined, implementation deferred until stable
// ml-kem Rust crate is available. All functions return NotImplemented.
//
// ML-KEM-768 is the PQC-default KEM. When implemented, this enables
// encrypted audit trail export and secure key exchange between RUNE
// policy modules.
// ═══════════════════════════════════════════════════════════════════════

use super::error::CryptoError;

/// KEM algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    /// ML-KEM-768 (FIPS 203) — PQC default.
    MlKem768,
}

impl Default for KemAlgorithm {
    fn default() -> Self {
        Self::MlKem768
    }
}

/// Generate a KEM keypair: (public_key, secret_key).
pub fn kem_keygen(_algorithm: KemAlgorithm) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    Err(CryptoError::NotImplemented(
        "ML-KEM-768 keygen — awaiting stable ml-kem crate".to_string(),
    ))
}

/// Encapsulate: given a public key, produce (ciphertext, shared_secret).
pub fn kem_encapsulate(
    _algorithm: KemAlgorithm,
    _public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    Err(CryptoError::NotImplemented(
        "ML-KEM-768 encapsulate — awaiting stable ml-kem crate".to_string(),
    ))
}

/// Decapsulate: given a secret key and ciphertext, recover the shared secret.
pub fn kem_decapsulate(
    _algorithm: KemAlgorithm,
    _secret_key: &[u8],
    _ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::NotImplemented(
        "ML-KEM-768 decapsulate — awaiting stable ml-kem crate".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_keygen_not_implemented() {
        let result = kem_keygen(KemAlgorithm::MlKem768);
        assert!(matches!(result, Err(CryptoError::NotImplemented(_))));
    }

    #[test]
    fn test_kem_encapsulate_not_implemented() {
        let result = kem_encapsulate(KemAlgorithm::MlKem768, b"fake-pk");
        assert!(matches!(result, Err(CryptoError::NotImplemented(_))));
    }

    #[test]
    fn test_kem_decapsulate_not_implemented() {
        let result = kem_decapsulate(KemAlgorithm::MlKem768, b"fake-sk", b"ct");
        assert!(matches!(result, Err(CryptoError::NotImplemented(_))));
    }
}
