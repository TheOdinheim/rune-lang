// ═══════════════════════════════════════════════════════════════════════
// Key Derivation — HKDF and Password Hashing
//
// HKDF (RFC 5869) using HMAC-SHA3-256 for deriving cryptographic keys.
// Argon2id interface defined but deferred to when argon2 crate is added.
// ═══════════════════════════════════════════════════════════════════════

use rune_lang::stdlib::crypto::sign::hmac_sha3_256;

use crate::error::SecretError;

// ── HKDF ──────────────────────────────────────────────────────────────

/// HKDF-Extract: PRK = HMAC-SHA3-256(salt, IKM)
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let effective_salt = if salt.is_empty() {
        vec![0u8; 32] // RFC 5869: use hash-length zero bytes if no salt
    } else {
        salt.to_vec()
    };
    hmac_sha3_256(&effective_salt, ikm)
}

/// HKDF-Expand: derive OKM of `length` bytes from PRK and info.
/// Maximum output: 255 * 32 = 8160 bytes.
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, SecretError> {
    let hash_len = 32; // SHA3-256 output
    let n = (length + hash_len - 1) / hash_len;
    if n > 255 {
        return Err(SecretError::KeyDerivationFailed(
            format!("requested {length} bytes exceeds HKDF maximum (8160)")
        ));
    }

    let mut okm = Vec::with_capacity(length);
    let mut t = Vec::new();

    for i in 1..=n {
        let mut input = Vec::new();
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(i as u8);
        t = hmac_sha3_256(prk, &input);
        okm.extend_from_slice(&t);
    }

    okm.truncate(length);
    Ok(okm)
}

/// Full HKDF: extract + expand in one call.
pub fn derive_key(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, SecretError> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

/// Derive multiple subkeys from the same IKM using different info strings.
pub fn derive_subkeys(
    salt: &[u8],
    ikm: &[u8],
    labels: &[&str],
    key_length: usize,
) -> Result<Vec<Vec<u8>>, SecretError> {
    let prk = hkdf_extract(salt, ikm);
    labels
        .iter()
        .map(|label| hkdf_expand(&prk, label.as_bytes(), key_length))
        .collect()
}

// ── Password hashing (Argon2id placeholder) ───────────────────────────

/// Hash a password using Argon2id. Placeholder — returns HKDF-derived key.
/// Real implementation requires the argon2 crate.
pub fn hash_password(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, SecretError> {
    // Placeholder: use HKDF with "argon2id-placeholder" info
    derive_key(salt, password, b"argon2id-placeholder", 32)
}

/// Verify a password against a stored hash.
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_password(password: &[u8], salt: &[u8], expected: &[u8]) -> Result<bool, SecretError> {
    let computed = hash_password(password, salt)?;
    Ok(constant_time_eq(&computed, expected))
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_extract_deterministic() {
        let prk1 = hkdf_extract(b"salt", b"input key material");
        let prk2 = hkdf_extract(b"salt", b"input key material");
        assert_eq!(prk1, prk2);
        assert_eq!(prk1.len(), 32);
    }

    #[test]
    fn test_hkdf_extract_different_salts() {
        let prk1 = hkdf_extract(b"salt-a", b"ikm");
        let prk2 = hkdf_extract(b"salt-b", b"ikm");
        assert_ne!(prk1, prk2);
    }

    #[test]
    fn test_hkdf_extract_empty_salt() {
        let prk = hkdf_extract(b"", b"ikm");
        assert_eq!(prk.len(), 32);
    }

    #[test]
    fn test_hkdf_expand_32_bytes() {
        let prk = hkdf_extract(b"salt", b"ikm");
        let okm = hkdf_expand(&prk, b"info", 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_expand_64_bytes() {
        let prk = hkdf_extract(b"salt", b"ikm");
        let okm = hkdf_expand(&prk, b"info", 64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_hkdf_expand_different_info() {
        let prk = hkdf_extract(b"salt", b"ikm");
        let k1 = hkdf_expand(&prk, b"encryption", 32).unwrap();
        let k2 = hkdf_expand(&prk, b"authentication", 32).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_hkdf_expand_too_long() {
        let prk = hkdf_extract(b"salt", b"ikm");
        let result = hkdf_expand(&prk, b"info", 9000);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_key_full() {
        let key = derive_key(b"salt", b"ikm", b"context", 48).unwrap();
        assert_eq!(key.len(), 48);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let k1 = derive_key(b"s", b"k", b"c", 32).unwrap();
        let k2 = derive_key(b"s", b"k", b"c", 32).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_subkeys() {
        let keys = derive_subkeys(b"salt", b"ikm", &["enc", "mac", "iv"], 32).unwrap();
        assert_eq!(keys.len(), 3);
        // All different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
        // All correct length
        for k in &keys {
            assert_eq!(k.len(), 32);
        }
    }

    #[test]
    fn test_hash_password() {
        let hash = hash_password(b"my-password", b"my-salt").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_verify_password_correct() {
        let hash = hash_password(b"correct-horse", b"salt").unwrap();
        assert!(verify_password(b"correct-horse", b"salt", &hash).unwrap());
    }

    #[test]
    fn test_verify_password_wrong() {
        let hash = hash_password(b"correct-horse", b"salt").unwrap();
        assert!(!verify_password(b"wrong-horse", b"salt", &hash).unwrap());
    }

    #[test]
    fn test_verify_password_wrong_salt() {
        let hash = hash_password(b"password", b"salt-1").unwrap();
        assert!(!verify_password(b"password", b"salt-2", &hash).unwrap());
    }

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"abc", b"abc"));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"ab", b"abc"));
    }
}
