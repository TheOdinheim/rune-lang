// ═══════════════════════════════════════════════════════════════════════
// KMS — Key Management Service trait and in-memory reference
// implementation.
//
// Layer 3 defines the trait boundary for external key management
// systems. RUNE doesn't implement KMS — it defines the interface
// that KMS integrations must satisfy.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_lang::stdlib::crypto::hash::sha3_256;

use crate::error::SecretError;

// ── KeyStatus ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Disabled,
    PendingDeletion,
    Destroyed,
}

impl fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── KeyHandle ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct KeyHandle {
    pub key_id: String,
    pub algorithm: String,
    pub key_size_bits: u32,
    pub created_at: i64,
    pub rotated_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub version: u32,
    pub status: KeyStatus,
}

// ── KmsInfo ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct KmsInfo {
    pub provider: String,
    pub supports_rotation: bool,
    pub supports_versioning: bool,
    pub max_key_size_bits: u32,
}

// ── KeyManagementService trait ───────────────────────────────────

pub trait KeyManagementService {
    fn generate_key(
        &mut self,
        key_id: &str,
        algorithm: &str,
        key_size_bits: u32,
    ) -> Result<KeyHandle, SecretError>;
    fn get_key(&self, key_id: &str) -> Result<Option<&KeyHandle>, SecretError>;
    fn rotate_key(&mut self, key_id: &str) -> Result<KeyHandle, SecretError>;
    fn delete_key(&mut self, key_id: &str) -> Result<bool, SecretError>;
    fn list_keys(&self) -> Vec<&str>;
    fn key_status(&self, key_id: &str) -> Option<KeyStatus>;
    fn encrypt_with_key(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, SecretError>;
    fn decrypt_with_key(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError>;
    fn service_info(&self) -> KmsInfo;
}

// ── InMemoryKms ──────────────────────────────────────────────────

/// Reference KMS implementation for testing.
/// Uses SHA3-256 XOR for placeholder encryption — NOT secure.
pub struct InMemoryKms {
    keys: HashMap<String, KeyHandle>,
    key_material: HashMap<String, Vec<u8>>,
}

impl InMemoryKms {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            key_material: HashMap::new(),
        }
    }

    /// Derive placeholder key material from key_id and version.
    fn derive_material(key_id: &str, version: u32) -> Vec<u8> {
        let input = format!("{key_id}:v{version}:material");
        sha3_256(input.as_bytes()).to_vec()
    }

    /// XOR-based placeholder encryption (NOT secure — testing only).
    fn xor_with_key(material: &[u8], data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ material[i % material.len()])
            .collect()
    }
}

impl Default for InMemoryKms {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyManagementService for InMemoryKms {
    fn generate_key(
        &mut self,
        key_id: &str,
        algorithm: &str,
        key_size_bits: u32,
    ) -> Result<KeyHandle, SecretError> {
        if self.keys.contains_key(key_id) {
            return Err(SecretError::EncryptionFailed(format!(
                "key already exists: {key_id}"
            )));
        }
        let handle = KeyHandle {
            key_id: key_id.to_string(),
            algorithm: algorithm.to_string(),
            key_size_bits,
            created_at: 0,
            rotated_at: None,
            expires_at: None,
            version: 1,
            status: KeyStatus::Active,
        };
        let material = Self::derive_material(key_id, 1);
        self.keys.insert(key_id.to_string(), handle.clone());
        self.key_material.insert(key_id.to_string(), material);
        Ok(handle)
    }

    fn get_key(&self, key_id: &str) -> Result<Option<&KeyHandle>, SecretError> {
        Ok(self.keys.get(key_id))
    }

    fn rotate_key(&mut self, key_id: &str) -> Result<KeyHandle, SecretError> {
        let handle = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| SecretError::EncryptionFailed(format!("key not found: {key_id}")))?;
        handle.version += 1;
        handle.rotated_at = Some(handle.created_at);
        let new_material = Self::derive_material(key_id, handle.version);
        self.key_material.insert(key_id.to_string(), new_material);
        Ok(handle.clone())
    }

    fn delete_key(&mut self, key_id: &str) -> Result<bool, SecretError> {
        let removed = self.keys.remove(key_id).is_some();
        self.key_material.remove(key_id);
        Ok(removed)
    }

    fn list_keys(&self) -> Vec<&str> {
        self.keys.keys().map(|k| k.as_str()).collect()
    }

    fn key_status(&self, key_id: &str) -> Option<KeyStatus> {
        self.keys.get(key_id).map(|h| h.status.clone())
    }

    fn encrypt_with_key(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        let material = self
            .key_material
            .get(key_id)
            .ok_or_else(|| SecretError::EncryptionFailed(format!("key not found: {key_id}")))?;
        Ok(Self::xor_with_key(material, plaintext))
    }

    fn decrypt_with_key(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
        // XOR is its own inverse
        self.encrypt_with_key(key_id, ciphertext)
    }

    fn service_info(&self) -> KmsInfo {
        KmsInfo {
            provider: "in-memory".to_string(),
            supports_rotation: true,
            supports_versioning: true,
            max_key_size_bits: 4096,
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
    fn test_in_memory_kms_generate_key() {
        let mut kms = InMemoryKms::new();
        let handle = kms.generate_key("k1", "AES-256", 256).unwrap();
        assert_eq!(handle.key_id, "k1");
        assert_eq!(handle.algorithm, "AES-256");
        assert_eq!(handle.key_size_bits, 256);
        assert_eq!(handle.version, 1);
        assert_eq!(handle.status, KeyStatus::Active);
    }

    #[test]
    fn test_in_memory_kms_get_key() {
        let mut kms = InMemoryKms::new();
        kms.generate_key("k1", "AES-256", 256).unwrap();
        let handle = kms.get_key("k1").unwrap();
        assert!(handle.is_some());
        assert_eq!(handle.unwrap().key_id, "k1");
        let missing = kms.get_key("nope").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_in_memory_kms_rotate_key() {
        let mut kms = InMemoryKms::new();
        kms.generate_key("k1", "AES-256", 256).unwrap();
        let rotated = kms.rotate_key("k1").unwrap();
        assert_eq!(rotated.version, 2);
    }

    #[test]
    fn test_in_memory_kms_delete_key() {
        let mut kms = InMemoryKms::new();
        kms.generate_key("k1", "AES-256", 256).unwrap();
        assert!(kms.delete_key("k1").unwrap());
        assert!(!kms.delete_key("k1").unwrap());
        assert!(kms.get_key("k1").unwrap().is_none());
    }

    #[test]
    fn test_in_memory_kms_encrypt_decrypt_roundtrip() {
        let mut kms = InMemoryKms::new();
        kms.generate_key("k1", "AES-256", 256).unwrap();
        let plaintext = b"hello secret world";
        let ciphertext = kms.encrypt_with_key("k1", plaintext).unwrap();
        assert_ne!(&ciphertext, plaintext);
        let decrypted = kms.decrypt_with_key("k1", &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_in_memory_kms_key_status() {
        let mut kms = InMemoryKms::new();
        assert!(kms.key_status("k1").is_none());
        kms.generate_key("k1", "AES-256", 256).unwrap();
        assert_eq!(kms.key_status("k1"), Some(KeyStatus::Active));
    }

    #[test]
    fn test_in_memory_kms_service_info() {
        let kms = InMemoryKms::new();
        let info = kms.service_info();
        assert_eq!(info.provider, "in-memory");
        assert!(info.supports_rotation);
        assert!(info.supports_versioning);
    }

    #[test]
    fn test_in_memory_kms_list_keys() {
        let mut kms = InMemoryKms::new();
        kms.generate_key("k1", "AES-256", 256).unwrap();
        kms.generate_key("k2", "RSA", 2048).unwrap();
        let mut keys = kms.list_keys();
        keys.sort();
        assert_eq!(keys, vec!["k1", "k2"]);
    }

    #[test]
    fn test_in_memory_kms_duplicate_key_rejected() {
        let mut kms = InMemoryKms::new();
        kms.generate_key("k1", "AES-256", 256).unwrap();
        let result = kms.generate_key("k1", "AES-256", 256);
        assert!(result.is_err());
    }
}
