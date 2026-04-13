// ═══════════════════════════════════════════════════════════════════════
// Envelope Encryption — DEK/KEK Pattern with ChaCha20-Poly1305 AEAD
//
// Each secret is encrypted with a unique data-encryption key (DEK).
// The DEK is then encrypted with a master key-encryption key (KEK).
// This allows key rotation without re-encrypting all secret data.
//
// Layer 2: real ChaCha20-Poly1305 AEAD (replaces XOR stream cipher).
// ═══════════════════════════════════════════════════════════════════════

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::Aead,
};
use rand::RngCore;
use zeroize::Zeroize;

use rune_lang::stdlib::crypto::hash::sha3_256;

use crate::error::SecretError;
use crate::secret::SecretId;

// ── EncryptedSecret ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EncryptedSecret {
    pub id: SecretId,
    pub ciphertext: Vec<u8>,
    pub encrypted_dek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub integrity_hash: String,
}

/// Derive a 12-byte AEAD nonce from an arbitrary-length input nonce and a label.
fn derive_aead_nonce(input_nonce: &[u8], label: &[u8]) -> [u8; 12] {
    let mut combined = Vec::with_capacity(input_nonce.len() + label.len());
    combined.extend_from_slice(input_nonce);
    combined.extend_from_slice(label);
    let hash = sha3_256(&combined);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash[..12]);
    nonce
}

/// Normalize any key to exactly 32 bytes using SHA3-256.
fn normalize_key(key: &[u8]) -> [u8; 32] {
    sha3_256(key)
}

/// Generate a DEK from seed material (SHA3-256 of seed).
pub fn generate_dek(seed: &[u8]) -> Vec<u8> {
    sha3_256(seed).to_vec()
}

/// Encrypt a secret value with the DEK/KEK envelope pattern.
/// Uses ChaCha20-Poly1305 AEAD for both plaintext and DEK encryption.
pub fn encrypt_secret(
    id: &SecretId,
    plaintext: &[u8],
    kek: &[u8],
    nonce: &[u8],
) -> Result<EncryptedSecret, SecretError> {
    if plaintext.is_empty() {
        return Err(SecretError::EncryptionFailed("empty plaintext".into()));
    }

    // Generate a random DEK
    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);

    // Derive 12-byte AEAD nonces from the input nonce
    let data_nonce = derive_aead_nonce(nonce, b"data");
    let dek_nonce = derive_aead_nonce(nonce, b"dek");

    // Encrypt plaintext with DEK (AEAD)
    let dek_key = normalize_key(&dek);
    let data_cipher = ChaCha20Poly1305::new((&dek_key).into());
    let ciphertext = data_cipher
        .encrypt((&data_nonce).into(), plaintext)
        .map_err(|e| SecretError::EncryptionFailed(format!("AEAD encrypt: {e}")))?;

    // Encrypt DEK with KEK (AEAD)
    let kek_key = normalize_key(kek);
    let kek_cipher = ChaCha20Poly1305::new((&kek_key).into());
    let encrypted_dek = kek_cipher
        .encrypt((&dek_nonce).into(), dek.as_ref())
        .map_err(|e| SecretError::EncryptionFailed(format!("DEK wrap: {e}")))?;

    // Integrity hash over ciphertext + encrypted_dek
    let mut integrity_input = Vec::new();
    integrity_input.extend_from_slice(&ciphertext);
    integrity_input.extend_from_slice(&encrypted_dek);
    let integrity_hash = hex::encode(sha3_256(&integrity_input));

    // Zeroize DEK
    dek.zeroize();

    Ok(EncryptedSecret {
        id: id.clone(),
        ciphertext,
        encrypted_dek,
        nonce: nonce.to_vec(),
        integrity_hash,
    })
}

/// Decrypt an envelope-encrypted secret.
pub fn decrypt_secret(
    encrypted: &EncryptedSecret,
    kek: &[u8],
) -> Result<Vec<u8>, SecretError> {
    // Verify integrity
    let mut integrity_input = Vec::new();
    integrity_input.extend_from_slice(&encrypted.ciphertext);
    integrity_input.extend_from_slice(&encrypted.encrypted_dek);
    let computed_hash = hex::encode(sha3_256(&integrity_input));

    if computed_hash != encrypted.integrity_hash {
        return Err(SecretError::IntegrityCheckFailed {
            expected: encrypted.integrity_hash.clone(),
            actual: computed_hash,
        });
    }

    // Derive nonces
    let dek_nonce = derive_aead_nonce(&encrypted.nonce, b"dek");
    let data_nonce = derive_aead_nonce(&encrypted.nonce, b"data");

    // Decrypt DEK with KEK (AEAD — fails with wrong KEK)
    let kek_key = normalize_key(kek);
    let kek_cipher = ChaCha20Poly1305::new((&kek_key).into());
    let mut dek = kek_cipher
        .decrypt((&dek_nonce).into(), encrypted.encrypted_dek.as_ref())
        .map_err(|_| SecretError::DecryptionFailed("DEK unwrap failed (wrong key or tampered)".into()))?;

    // Decrypt plaintext with DEK (AEAD)
    let dek_key = normalize_key(&dek);
    let data_cipher = ChaCha20Poly1305::new((&dek_key).into());
    let plaintext = data_cipher
        .decrypt((&data_nonce).into(), encrypted.ciphertext.as_ref())
        .map_err(|_| SecretError::DecryptionFailed("plaintext decryption failed".into()))?;

    dek.zeroize();

    if plaintext.is_empty() {
        return Err(SecretError::DecryptionFailed("empty result".into()));
    }

    Ok(plaintext)
}

/// Re-encrypt an existing envelope with a new KEK (key rotation).
/// The ciphertext remains unchanged — only the DEK wrapper changes.
pub fn re_encrypt_with_new_kek(
    encrypted: &EncryptedSecret,
    old_kek: &[u8],
    new_kek: &[u8],
) -> Result<EncryptedSecret, SecretError> {
    let dek_nonce = derive_aead_nonce(&encrypted.nonce, b"dek");

    // Decrypt DEK with old KEK
    let old_kek_key = normalize_key(old_kek);
    let old_cipher = ChaCha20Poly1305::new((&old_kek_key).into());
    let mut dek = old_cipher
        .decrypt((&dek_nonce).into(), encrypted.encrypted_dek.as_ref())
        .map_err(|_| SecretError::DecryptionFailed("old KEK unwrap failed".into()))?;

    // Re-encrypt DEK with new KEK
    let new_kek_key = normalize_key(new_kek);
    let new_cipher = ChaCha20Poly1305::new((&new_kek_key).into());
    let new_encrypted_dek = new_cipher
        .encrypt((&dek_nonce).into(), dek.as_ref())
        .map_err(|e| SecretError::EncryptionFailed(format!("new KEK wrap: {e}")))?;

    dek.zeroize();

    // Recompute integrity hash
    let mut integrity_input = Vec::new();
    integrity_input.extend_from_slice(&encrypted.ciphertext);
    integrity_input.extend_from_slice(&new_encrypted_dek);
    let integrity_hash = hex::encode(sha3_256(&integrity_input));

    Ok(EncryptedSecret {
        id: encrypted.id.clone(),
        ciphertext: encrypted.ciphertext.clone(),
        encrypted_dek: new_encrypted_dek,
        nonce: encrypted.nonce.clone(),
        integrity_hash,
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> Vec<u8> {
        vec![0xAA; 32]
    }

    fn test_nonce() -> Vec<u8> {
        vec![0xBB; 16]
    }

    #[test]
    fn test_generate_dek() {
        let dek = generate_dek(b"seed-1");
        assert_eq!(dek.len(), 32);
        let dek2 = generate_dek(b"seed-2");
        assert_ne!(dek, dek2);
    }

    #[test]
    fn test_aead_nonce_derivation() {
        let n1 = derive_aead_nonce(b"nonce", b"data");
        let n2 = derive_aead_nonce(b"nonce", b"dek");
        assert_eq!(n1.len(), 12);
        assert_eq!(n2.len(), 12);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let id = SecretId::new("test-secret");
        let plaintext = b"super secret value";
        let kek = test_kek();
        let nonce = test_nonce();

        let encrypted = encrypt_secret(&id, plaintext, &kek, &nonce).unwrap();
        assert_ne!(encrypted.ciphertext, plaintext);
        assert!(!encrypted.integrity_hash.is_empty());

        let decrypted = decrypt_secret(&encrypted, &kek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_empty_fails() {
        let id = SecretId::new("test");
        let result = encrypt_secret(&id, b"", &test_kek(), &test_nonce());
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_kek_fails_integrity() {
        let id = SecretId::new("test");
        let encrypted = encrypt_secret(&id, b"secret", &test_kek(), &test_nonce()).unwrap();
        // Tamper with the encrypted_dek to simulate corruption
        let mut tampered = encrypted.clone();
        tampered.encrypted_dek[0] ^= 0xFF;
        let result = decrypt_secret(&tampered, &test_kek());
        assert!(result.is_err());
    }

    #[test]
    fn test_integrity_check_detects_tamper() {
        let id = SecretId::new("test");
        let mut encrypted = encrypt_secret(&id, b"secret", &test_kek(), &test_nonce()).unwrap();
        encrypted.ciphertext[0] ^= 0xFF;
        let result = decrypt_secret(&encrypted, &test_kek());
        assert!(matches!(result, Err(SecretError::IntegrityCheckFailed { .. })));
    }

    #[test]
    fn test_re_encrypt_with_new_kek() {
        let id = SecretId::new("test");
        let plaintext = b"rotate me";
        let old_kek = test_kek();
        let new_kek = vec![0xCC; 32];
        let nonce = test_nonce();

        let encrypted = encrypt_secret(&id, plaintext, &old_kek, &nonce).unwrap();
        let re_encrypted = re_encrypt_with_new_kek(&encrypted, &old_kek, &new_kek).unwrap();

        // Ciphertext unchanged
        assert_eq!(re_encrypted.ciphertext, encrypted.ciphertext);
        // DEK wrapper changed
        assert_ne!(re_encrypted.encrypted_dek, encrypted.encrypted_dek);
        // Can decrypt with new KEK
        let decrypted = decrypt_secret(&re_encrypted, &new_kek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_re_encrypt_old_kek_produces_wrong_data() {
        let id = SecretId::new("test");
        let plaintext = b"data";
        let old_kek = test_kek();
        let new_kek = vec![0xCC; 32];
        let nonce = test_nonce();

        let encrypted = encrypt_secret(&id, plaintext, &old_kek, &nonce).unwrap();
        let re_encrypted = re_encrypt_with_new_kek(&encrypted, &old_kek, &new_kek).unwrap();

        // Old KEK cannot decrypt re-encrypted DEK — AEAD rejects wrong key
        let result = decrypt_secret(&re_encrypted, &old_kek);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertexts() {
        let id = SecretId::new("test");
        let kek = test_kek();
        let e1 = encrypt_secret(&id, b"same", &kek, &[1; 16]).unwrap();
        let e2 = encrypt_secret(&id, b"same", &kek, &[2; 16]).unwrap();
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn test_large_plaintext() {
        let id = SecretId::new("big");
        let plaintext = vec![0x42; 4096];
        let kek = test_kek();
        let nonce = test_nonce();

        let encrypted = encrypt_secret(&id, &plaintext, &kek, &nonce).unwrap();
        let decrypted = decrypt_secret(&encrypted, &kek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_kek_rejected_by_aead() {
        let id = SecretId::new("test");
        let kek = test_kek();
        let wrong_kek = vec![0xDD; 32];
        let nonce = test_nonce();

        let encrypted = encrypt_secret(&id, b"secret data", &kek, &nonce).unwrap();
        let result = decrypt_secret(&encrypted, &wrong_kek);
        assert!(matches!(result, Err(SecretError::DecryptionFailed(_))));
    }

    #[test]
    fn test_ciphertext_includes_auth_tag() {
        let id = SecretId::new("test");
        let plaintext = b"hello";
        let kek = test_kek();
        let nonce = test_nonce();

        let encrypted = encrypt_secret(&id, plaintext, &kek, &nonce).unwrap();
        // ChaCha20-Poly1305 appends a 16-byte auth tag
        assert_eq!(encrypted.ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_dek_zeroized_after_encrypt() {
        // This test verifies the encrypt path completes without error
        // (zeroization is best-effort verified by code inspection)
        let id = SecretId::new("z");
        let encrypted = encrypt_secret(&id, b"data", &test_kek(), &test_nonce()).unwrap();
        let decrypted = decrypt_secret(&encrypted, &test_kek()).unwrap();
        assert_eq!(decrypted, b"data");
    }
}
