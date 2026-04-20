// ═══════════════════════════════════════════════════════════════════════
// Credential Material Store — Pluggable credential material storage.
//
// Layer 3 separates credential material (password hashes, TOTP
// secret hashes, WebAuthn public keys, recovery code hashes) from
// identity metadata stored in IdentityBackend. This reflects the
// distinct access patterns: credential material requires stricter
// access controls and has a different rotation lifecycle.
//
// All material stored here is SHA3-256 hashed (except WebAuthn
// public keys, which are not secret). Recovery codes are hashed
// individually so consume_recovery_code can verify by hashing
// and comparing with constant-time equality.
//
// Named CredentialMaterialStore to avoid collision with the existing
// CredentialStore struct in credential.rs (Layer 1).
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

use crate::error::IdentityError;

// ── PasswordHashRecord ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHashRecord {
    pub identity_id: String,
    pub hash: String,
    pub salt: String,
    pub algorithm: String,
    pub created_at: i64,
}

// ── TotpSecretHashRecord ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSecretHashRecord {
    pub identity_id: String,
    pub secret_hash: String,
    pub algorithm: String,
    pub digits: u32,
    pub period_seconds: u64,
    pub created_at: i64,
}

// ── WebAuthnPublicKeyRecord ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnPublicKeyRecord {
    pub credential_id: String,
    pub identity_id: String,
    pub public_key: String,
    pub attestation_format: String,
    pub created_at: i64,
}

// ── RecoveryCodeSet ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredRecoveryCodeSet {
    pub identity_id: String,
    pub code_hashes: Vec<String>,
    pub used: Vec<bool>,
    pub created_at: i64,
}

impl StoredRecoveryCodeSet {
    pub fn remaining(&self) -> usize {
        self.used.iter().filter(|u| !**u).count()
    }
}

// ── CredentialStoreInfo ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialStoreInfo {
    pub store_type: String,
    pub supports_webauthn: bool,
    pub supports_recovery_codes: bool,
}

// ── Constant-time comparison ──────────────────────────────────

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

fn sha3_hex(input: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

// ── CredentialMaterialStore trait ──────────────────────────────

pub trait CredentialMaterialStore {
    fn store_password_hash(&mut self, record: &PasswordHashRecord) -> Result<(), IdentityError>;
    fn retrieve_password_hash(&self, identity_id: &str) -> Option<&PasswordHashRecord>;
    fn update_password_hash(&mut self, record: &PasswordHashRecord) -> Result<(), IdentityError>;
    fn delete_password_hash(&mut self, identity_id: &str) -> Result<bool, IdentityError>;

    fn store_totp_secret_hash(&mut self, record: &TotpSecretHashRecord) -> Result<(), IdentityError>;
    fn retrieve_totp_secret_hash(&self, identity_id: &str) -> Option<&TotpSecretHashRecord>;

    fn store_webauthn_public_key(&mut self, record: &WebAuthnPublicKeyRecord) -> Result<(), IdentityError>;
    fn retrieve_webauthn_public_keys_for_identity(&self, identity_id: &str) -> Vec<&WebAuthnPublicKeyRecord>;
    fn delete_webauthn_public_key(&mut self, credential_id: &str) -> Result<bool, IdentityError>;

    fn store_recovery_codes(&mut self, identity_id: &str, code_hashes: Vec<String>, now: i64) -> Result<(), IdentityError>;
    fn consume_recovery_code(&mut self, identity_id: &str, presented_code: &str) -> Result<bool, IdentityError>;
    fn list_unused_recovery_codes_count(&self, identity_id: &str) -> usize;

    fn backend_info(&self) -> CredentialStoreInfo;
}

// ── InMemoryCredentialMaterialStore ───────────────────────────

pub struct InMemoryCredentialMaterialStore {
    password_hashes: HashMap<String, PasswordHashRecord>,
    totp_secrets: HashMap<String, TotpSecretHashRecord>,
    webauthn_keys: HashMap<String, WebAuthnPublicKeyRecord>,
    recovery_codes: HashMap<String, StoredRecoveryCodeSet>,
}

impl InMemoryCredentialMaterialStore {
    pub fn new() -> Self {
        Self {
            password_hashes: HashMap::new(),
            totp_secrets: HashMap::new(),
            webauthn_keys: HashMap::new(),
            recovery_codes: HashMap::new(),
        }
    }
}

impl Default for InMemoryCredentialMaterialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialMaterialStore for InMemoryCredentialMaterialStore {
    fn store_password_hash(&mut self, record: &PasswordHashRecord) -> Result<(), IdentityError> {
        self.password_hashes.insert(record.identity_id.clone(), record.clone());
        Ok(())
    }

    fn retrieve_password_hash(&self, identity_id: &str) -> Option<&PasswordHashRecord> {
        self.password_hashes.get(identity_id)
    }

    fn update_password_hash(&mut self, record: &PasswordHashRecord) -> Result<(), IdentityError> {
        if !self.password_hashes.contains_key(&record.identity_id) {
            return Err(IdentityError::InvalidOperation(
                format!("no password hash for identity {}", record.identity_id),
            ));
        }
        self.password_hashes.insert(record.identity_id.clone(), record.clone());
        Ok(())
    }

    fn delete_password_hash(&mut self, identity_id: &str) -> Result<bool, IdentityError> {
        Ok(self.password_hashes.remove(identity_id).is_some())
    }

    fn store_totp_secret_hash(&mut self, record: &TotpSecretHashRecord) -> Result<(), IdentityError> {
        self.totp_secrets.insert(record.identity_id.clone(), record.clone());
        Ok(())
    }

    fn retrieve_totp_secret_hash(&self, identity_id: &str) -> Option<&TotpSecretHashRecord> {
        self.totp_secrets.get(identity_id)
    }

    fn store_webauthn_public_key(&mut self, record: &WebAuthnPublicKeyRecord) -> Result<(), IdentityError> {
        self.webauthn_keys.insert(record.credential_id.clone(), record.clone());
        Ok(())
    }

    fn retrieve_webauthn_public_keys_for_identity(&self, identity_id: &str) -> Vec<&WebAuthnPublicKeyRecord> {
        self.webauthn_keys.values()
            .filter(|r| r.identity_id == identity_id)
            .collect()
    }

    fn delete_webauthn_public_key(&mut self, credential_id: &str) -> Result<bool, IdentityError> {
        Ok(self.webauthn_keys.remove(credential_id).is_some())
    }

    fn store_recovery_codes(&mut self, identity_id: &str, code_hashes: Vec<String>, now: i64) -> Result<(), IdentityError> {
        let count = code_hashes.len();
        self.recovery_codes.insert(identity_id.to_string(), StoredRecoveryCodeSet {
            identity_id: identity_id.to_string(),
            code_hashes,
            used: vec![false; count],
            created_at: now,
        });
        Ok(())
    }

    fn consume_recovery_code(&mut self, identity_id: &str, presented_code: &str) -> Result<bool, IdentityError> {
        let Some(code_set) = self.recovery_codes.get_mut(identity_id) else {
            return Ok(false);
        };
        let presented_hash = sha3_hex(presented_code.as_bytes());
        for (i, stored_hash) in code_set.code_hashes.iter().enumerate() {
            if !code_set.used[i] && constant_time_eq(presented_hash.as_bytes(), stored_hash.as_bytes()) {
                code_set.used[i] = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn list_unused_recovery_codes_count(&self, identity_id: &str) -> usize {
        self.recovery_codes.get(identity_id)
            .map(|cs| cs.remaining())
            .unwrap_or(0)
    }

    fn backend_info(&self) -> CredentialStoreInfo {
        CredentialStoreInfo {
            store_type: "in-memory".to_string(),
            supports_webauthn: true,
            supports_recovery_codes: true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve_password_hash() {
        let mut store = InMemoryCredentialMaterialStore::new();
        let record = PasswordHashRecord {
            identity_id: "user:alice".into(),
            hash: "abc123".into(),
            salt: "salt1".into(),
            algorithm: "SHA3-256".into(),
            created_at: 1000,
        };
        store.store_password_hash(&record).unwrap();
        let retrieved = store.retrieve_password_hash("user:alice").unwrap();
        assert_eq!(retrieved.hash, "abc123");
    }

    #[test]
    fn test_update_password_hash() {
        let mut store = InMemoryCredentialMaterialStore::new();
        let record = PasswordHashRecord {
            identity_id: "user:alice".into(),
            hash: "old".into(),
            salt: "s".into(),
            algorithm: "SHA3-256".into(),
            created_at: 1000,
        };
        store.store_password_hash(&record).unwrap();
        let updated = PasswordHashRecord {
            identity_id: "user:alice".into(),
            hash: "new".into(),
            salt: "s2".into(),
            algorithm: "SHA3-256".into(),
            created_at: 2000,
        };
        store.update_password_hash(&updated).unwrap();
        assert_eq!(store.retrieve_password_hash("user:alice").unwrap().hash, "new");
    }

    #[test]
    fn test_update_password_hash_nonexistent() {
        let mut store = InMemoryCredentialMaterialStore::new();
        let record = PasswordHashRecord {
            identity_id: "user:nobody".into(),
            hash: "h".into(),
            salt: "s".into(),
            algorithm: "SHA3-256".into(),
            created_at: 1000,
        };
        assert!(store.update_password_hash(&record).is_err());
    }

    #[test]
    fn test_delete_password_hash() {
        let mut store = InMemoryCredentialMaterialStore::new();
        let record = PasswordHashRecord {
            identity_id: "user:alice".into(),
            hash: "h".into(),
            salt: "s".into(),
            algorithm: "SHA3-256".into(),
            created_at: 1000,
        };
        store.store_password_hash(&record).unwrap();
        assert!(store.delete_password_hash("user:alice").unwrap());
        assert!(!store.delete_password_hash("user:alice").unwrap());
    }

    #[test]
    fn test_totp_secret_hash() {
        let mut store = InMemoryCredentialMaterialStore::new();
        let record = TotpSecretHashRecord {
            identity_id: "user:alice".into(),
            secret_hash: sha3_hex(b"totp-secret"),
            algorithm: "HMAC-SHA3-256".into(),
            digits: 6,
            period_seconds: 30,
            created_at: 1000,
        };
        store.store_totp_secret_hash(&record).unwrap();
        let retrieved = store.retrieve_totp_secret_hash("user:alice").unwrap();
        assert_eq!(retrieved.digits, 6);
    }

    #[test]
    fn test_webauthn_public_key() {
        let mut store = InMemoryCredentialMaterialStore::new();
        let record = WebAuthnPublicKeyRecord {
            credential_id: "wak-1".into(),
            identity_id: "user:alice".into(),
            public_key: "pk-base64-data".into(),
            attestation_format: "packed".into(),
            created_at: 1000,
        };
        store.store_webauthn_public_key(&record).unwrap();
        let keys = store.retrieve_webauthn_public_keys_for_identity("user:alice");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].public_key, "pk-base64-data");
    }

    #[test]
    fn test_webauthn_multiple_keys() {
        let mut store = InMemoryCredentialMaterialStore::new();
        store.store_webauthn_public_key(&WebAuthnPublicKeyRecord {
            credential_id: "wak-1".into(),
            identity_id: "user:alice".into(),
            public_key: "pk1".into(),
            attestation_format: "packed".into(),
            created_at: 1000,
        }).unwrap();
        store.store_webauthn_public_key(&WebAuthnPublicKeyRecord {
            credential_id: "wak-2".into(),
            identity_id: "user:alice".into(),
            public_key: "pk2".into(),
            attestation_format: "tpm".into(),
            created_at: 2000,
        }).unwrap();
        assert_eq!(store.retrieve_webauthn_public_keys_for_identity("user:alice").len(), 2);
    }

    #[test]
    fn test_delete_webauthn_public_key() {
        let mut store = InMemoryCredentialMaterialStore::new();
        store.store_webauthn_public_key(&WebAuthnPublicKeyRecord {
            credential_id: "wak-1".into(),
            identity_id: "user:alice".into(),
            public_key: "pk1".into(),
            attestation_format: "packed".into(),
            created_at: 1000,
        }).unwrap();
        assert!(store.delete_webauthn_public_key("wak-1").unwrap());
        assert!(!store.delete_webauthn_public_key("wak-1").unwrap());
    }

    #[test]
    fn test_recovery_codes_store_and_consume() {
        let mut store = InMemoryCredentialMaterialStore::new();
        let raw_codes = vec!["code-aaa".to_string(), "code-bbb".to_string(), "code-ccc".to_string()];
        let hashes: Vec<String> = raw_codes.iter().map(|c| sha3_hex(c.as_bytes())).collect();
        store.store_recovery_codes("user:alice", hashes, 1000).unwrap();
        assert_eq!(store.list_unused_recovery_codes_count("user:alice"), 3);

        assert!(store.consume_recovery_code("user:alice", "code-aaa").unwrap());
        assert_eq!(store.list_unused_recovery_codes_count("user:alice"), 2);

        // Cannot reuse
        assert!(!store.consume_recovery_code("user:alice", "code-aaa").unwrap());
        assert_eq!(store.list_unused_recovery_codes_count("user:alice"), 2);
    }

    #[test]
    fn test_recovery_code_wrong_code() {
        let mut store = InMemoryCredentialMaterialStore::new();
        let hashes = vec![sha3_hex(b"code-xxx")];
        store.store_recovery_codes("user:alice", hashes, 1000).unwrap();
        assert!(!store.consume_recovery_code("user:alice", "wrong-code").unwrap());
    }

    #[test]
    fn test_recovery_codes_nonexistent_identity() {
        let mut store = InMemoryCredentialMaterialStore::new();
        assert!(!store.consume_recovery_code("user:nobody", "code").unwrap());
        assert_eq!(store.list_unused_recovery_codes_count("user:nobody"), 0);
    }

    #[test]
    fn test_credential_store_info() {
        let store = InMemoryCredentialMaterialStore::new();
        let info = store.backend_info();
        assert_eq!(info.store_type, "in-memory");
        assert!(info.supports_webauthn);
        assert!(info.supports_recovery_codes);
    }
}
