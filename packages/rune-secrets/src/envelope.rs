// ═══════════════════════════════════════════════════════════════════════
// Envelope Encryption — DEK/KEK Pattern
//
// Each secret is encrypted with a unique data-encryption key (DEK).
// The DEK is then encrypted with a master key-encryption key (KEK).
// This allows key rotation without re-encrypting all secret data.
//
// Placeholder cipher: HMAC-SHA3-256 XOR stream (symmetric, deterministic).
// Real implementation will swap in AES-256-GCM or similar AEAD.
// ═══════════════════════════════════════════════════════════════════════

use rune_lang::stdlib::crypto::sign::hmac_sha3_256;
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

/// Generate a DEK from random-ish material (placeholder: SHA3-256 of seed).
pub fn generate_dek(seed: &[u8]) -> Vec<u8> {
    sha3_256(seed).to_vec()
}

/// Encrypt plaintext with a key using HMAC-SHA3-256 XOR stream cipher.
/// This is a placeholder — real implementation uses AES-256-GCM.
fn xor_cipher(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut counter = 0u64;
    let mut offset = 0;

    while offset < data.len() {
        let mut block_input = Vec::new();
        block_input.extend_from_slice(nonce);
        block_input.extend_from_slice(&counter.to_le_bytes());
        let stream_block = hmac_sha3_256(key, &block_input);

        let remaining = data.len() - offset;
        let take = remaining.min(stream_block.len());
        for i in 0..take {
            output.push(data[offset + i] ^ stream_block[i]);
        }
        offset += take;
        counter += 1;
    }
    output
}

/// Encrypt a secret value with the DEK/KEK envelope pattern.
pub fn encrypt_secret(
    id: &SecretId,
    plaintext: &[u8],
    kek: &[u8],
    nonce: &[u8],
) -> Result<EncryptedSecret, SecretError> {
    if plaintext.is_empty() {
        return Err(SecretError::EncryptionFailed("empty plaintext".into()));
    }

    // Generate a unique DEK from the nonce + id
    let dek_seed: Vec<u8> = [nonce, id.as_str().as_bytes()].concat();
    let dek = generate_dek(&dek_seed);

    // Encrypt plaintext with DEK
    let ciphertext = xor_cipher(&dek, nonce, plaintext);

    // Encrypt DEK with KEK
    let encrypted_dek = xor_cipher(kek, nonce, &dek);

    // Integrity hash over ciphertext + encrypted_dek
    let mut integrity_input = Vec::new();
    integrity_input.extend_from_slice(&ciphertext);
    integrity_input.extend_from_slice(&encrypted_dek);
    let integrity_hash = hex::encode(sha3_256(&integrity_input));

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

    // Decrypt DEK with KEK
    let dek = xor_cipher(kek, &encrypted.nonce, &encrypted.encrypted_dek);

    // Decrypt plaintext with DEK
    let plaintext = xor_cipher(&dek, &encrypted.nonce, &encrypted.ciphertext);

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
    // Decrypt DEK with old KEK
    let dek = xor_cipher(old_kek, &encrypted.nonce, &encrypted.encrypted_dek);

    // Re-encrypt DEK with new KEK
    let new_encrypted_dek = xor_cipher(new_kek, &encrypted.nonce, &dek);

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
    fn test_xor_cipher_roundtrip() {
        let key = vec![0xCC; 32];
        let nonce = vec![0xDD; 16];
        let data = b"hello world, this is a secret message that spans multiple blocks!";
        let encrypted = xor_cipher(&key, &nonce, data);
        assert_ne!(encrypted, data);
        let decrypted = xor_cipher(&key, &nonce, &encrypted);
        assert_eq!(decrypted, data);
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
        // Tamper with the encrypted_dek to simulate wrong KEK result
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

        // Old KEK derives wrong DEK → produces garbage, not the original plaintext
        let decrypted = decrypt_secret(&re_encrypted, &old_kek).unwrap();
        assert_ne!(decrypted, plaintext);
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
}
