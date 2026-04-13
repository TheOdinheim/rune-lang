// ═══════════════════════════════════════════════════════════════════════
// Transit Encryption — Cross-Boundary Secret Transfer
//
// Package secrets for transit between systems with:
// - Derived transit key (HKDF)
// - Integrity hash
// - Expiration (5-minute default)
// ═══════════════════════════════════════════════════════════════════════

use rune_lang::stdlib::crypto::hash::sha3_256_hex;

use crate::derivation::derive_key;
use crate::envelope::{encrypt_secret, decrypt_secret, EncryptedSecret};
use crate::error::SecretError;
use crate::secret::SecretId;

/// Default transit expiration: 5 minutes (300 seconds).
pub const TRANSIT_EXPIRY_SECS: i64 = 300;

// ── TransitPackage ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TransitPackage {
    pub encrypted: EncryptedSecret,
    pub created_at: i64,
    pub expires_at: i64,
    pub source: String,
    pub destination: String,
    pub integrity_hash: String,
}

impl TransitPackage {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }
}

/// Derive a transit-specific key from master key and route info.
fn derive_transit_key(
    master_key: &[u8],
    source: &str,
    destination: &str,
    created_at: i64,
) -> Result<Vec<u8>, SecretError> {
    let info = format!("transit:{source}:{destination}:{created_at}");
    derive_key(b"rune-transit-salt", master_key, info.as_bytes(), 32)
}

/// Package a secret for transit between two systems.
pub fn package_for_transit(
    id: &SecretId,
    plaintext: &[u8],
    master_key: &[u8],
    source: impl Into<String>,
    destination: impl Into<String>,
    now: i64,
) -> Result<TransitPackage, SecretError> {
    let source = source.into();
    let destination = destination.into();

    let transit_key = derive_transit_key(master_key, &source, &destination, now)?;
    let nonce = sha3_256_hex(format!("{source}:{destination}:{now}").as_bytes());
    let nonce_bytes = &nonce.as_bytes()[..16];

    let encrypted = encrypt_secret(id, plaintext, &transit_key, nonce_bytes)?;

    // Integrity hash over the whole package
    let mut integrity_input = Vec::new();
    integrity_input.extend_from_slice(&encrypted.ciphertext);
    integrity_input.extend_from_slice(source.as_bytes());
    integrity_input.extend_from_slice(destination.as_bytes());
    integrity_input.extend_from_slice(&now.to_le_bytes());
    let integrity_hash = sha3_256_hex(&integrity_input);

    Ok(TransitPackage {
        encrypted,
        created_at: now,
        expires_at: now + TRANSIT_EXPIRY_SECS,
        source,
        destination,
        integrity_hash,
    })
}

/// Unpackage a transit-encrypted secret, checking expiration and integrity.
pub fn unpackage_transit(
    package: &TransitPackage,
    master_key: &[u8],
    now: i64,
) -> Result<Vec<u8>, SecretError> {
    // Check expiration
    if package.is_expired(now) {
        return Err(SecretError::TransitExpired {
            created_at: package.created_at,
            expired_at: package.expires_at,
        });
    }

    // Verify integrity
    let mut integrity_input = Vec::new();
    integrity_input.extend_from_slice(&package.encrypted.ciphertext);
    integrity_input.extend_from_slice(package.source.as_bytes());
    integrity_input.extend_from_slice(package.destination.as_bytes());
    integrity_input.extend_from_slice(&package.created_at.to_le_bytes());
    let computed_hash = sha3_256_hex(&integrity_input);

    if computed_hash != package.integrity_hash {
        return Err(SecretError::IntegrityCheckFailed {
            expected: package.integrity_hash.clone(),
            actual: computed_hash,
        });
    }

    // Derive the same transit key
    let transit_key = derive_transit_key(
        master_key,
        &package.source,
        &package.destination,
        package.created_at,
    )?;

    decrypt_secret(&package.encrypted, &transit_key)
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

    #[test]
    fn test_package_and_unpackage() {
        let id = SecretId::new("transit-1");
        let secret = b"sensitive data";
        let key = test_key();

        let pkg = package_for_transit(&id, secret, &key, "system-a", "system-b", 1000).unwrap();
        assert_eq!(pkg.source, "system-a");
        assert_eq!(pkg.destination, "system-b");
        assert_eq!(pkg.created_at, 1000);
        assert_eq!(pkg.expires_at, 1000 + TRANSIT_EXPIRY_SECS);

        let decrypted = unpackage_transit(&pkg, &key, 1100).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_transit_expired() {
        let id = SecretId::new("transit-2");
        let key = test_key();

        let pkg = package_for_transit(&id, b"data", &key, "a", "b", 1000).unwrap();
        let result = unpackage_transit(&pkg, &key, 1000 + TRANSIT_EXPIRY_SECS);
        assert!(matches!(result, Err(SecretError::TransitExpired { .. })));
    }

    #[test]
    fn test_transit_not_expired_just_before() {
        let id = SecretId::new("transit-3");
        let key = test_key();

        let pkg = package_for_transit(&id, b"data", &key, "a", "b", 1000).unwrap();
        let result = unpackage_transit(&pkg, &key, 1000 + TRANSIT_EXPIRY_SECS - 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transit_integrity_tampered() {
        let id = SecretId::new("transit-4");
        let key = test_key();

        let mut pkg = package_for_transit(&id, b"data", &key, "a", "b", 1000).unwrap();
        pkg.source = "tampered".into();
        let result = unpackage_transit(&pkg, &key, 1050);
        assert!(matches!(result, Err(SecretError::IntegrityCheckFailed { .. })));
    }

    #[test]
    fn test_transit_wrong_key_rejected() {
        let id = SecretId::new("transit-5");
        let key = test_key();
        let wrong_key = vec![0xBB; 32];
        let plaintext = b"data";

        let pkg = package_for_transit(&id, plaintext, &key, "a", "b", 1000).unwrap();
        // Wrong key derives different transit key → AEAD rejects decryption
        let result = unpackage_transit(&pkg, &wrong_key, 1050);
        assert!(result.is_err());
    }

    #[test]
    fn test_transit_is_expired() {
        let id = SecretId::new("t");
        let key = test_key();
        let pkg = package_for_transit(&id, b"x", &key, "a", "b", 100).unwrap();
        assert!(!pkg.is_expired(200));
        assert!(pkg.is_expired(100 + TRANSIT_EXPIRY_SECS));
    }

    #[test]
    fn test_different_routes_different_ciphertext() {
        let id = SecretId::new("t");
        let key = test_key();
        let pkg1 = package_for_transit(&id, b"same", &key, "a", "b", 1000).unwrap();
        let pkg2 = package_for_transit(&id, b"same", &key, "a", "c", 1000).unwrap();
        assert_ne!(pkg1.encrypted.ciphertext, pkg2.encrypted.ciphertext);
    }
}
