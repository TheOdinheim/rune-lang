// ═══════════════════════════════════════════════════════════════════════
// Backend — Secret storage backend trait and in-memory reference
// implementation.
//
// Layer 3 extracts the storage contract into a trait so customers
// can provide their own persistence backend (encrypted SQLite,
// cloud secret managers, HSMs, etc.). RUNE provides the contract —
// the customer provides the transport.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::SecretError;
use crate::secret::{SecretEntry, SecretId};

// ── BackendInfo ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub backend_type: String,
    pub supports_encryption_at_rest: bool,
    pub supports_versioning: bool,
    pub supports_audit: bool,
    pub max_secret_size_bytes: Option<usize>,
}

// ── SecretBackend trait ──────────────────────────────────────────

pub trait SecretBackend {
    fn store_secret(&mut self, id: &str, secret: &SecretEntry) -> Result<(), SecretError>;
    fn retrieve_secret(&self, id: &str) -> Option<&SecretEntry>;
    fn delete_secret(&mut self, id: &str) -> Result<bool, SecretError>;
    fn list_secrets(&self) -> Vec<&str>;
    fn secret_count(&self) -> usize;
    fn secret_exists(&self, id: &str) -> bool;
    fn rotate_secret(&mut self, id: &str, new_secret: &SecretEntry) -> Result<(), SecretError>;
    fn secrets_expiring_within(&self, now: i64, window_ms: i64) -> Vec<&str>;
    fn flush(&mut self) -> Result<(), SecretError>;
    fn backend_info(&self) -> BackendInfo;
}

// ── InMemorySecretBackend ────────────────────────────────────────

pub struct InMemorySecretBackend {
    secrets: HashMap<String, SecretEntry>,
}

impl InMemorySecretBackend {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }
}

impl Default for InMemorySecretBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBackend for InMemorySecretBackend {
    fn store_secret(&mut self, id: &str, secret: &SecretEntry) -> Result<(), SecretError> {
        if self.secrets.contains_key(id) {
            return Err(SecretError::SecretAlreadyExists(SecretId::new(id)));
        }
        self.secrets.insert(id.to_string(), secret.clone());
        Ok(())
    }

    fn retrieve_secret(&self, id: &str) -> Option<&SecretEntry> {
        self.secrets.get(id)
    }

    fn delete_secret(&mut self, id: &str) -> Result<bool, SecretError> {
        Ok(self.secrets.remove(id).is_some())
    }

    fn list_secrets(&self) -> Vec<&str> {
        self.secrets.keys().map(|k| k.as_str()).collect()
    }

    fn secret_count(&self) -> usize {
        self.secrets.len()
    }

    fn secret_exists(&self, id: &str) -> bool {
        self.secrets.contains_key(id)
    }

    fn rotate_secret(&mut self, id: &str, new_secret: &SecretEntry) -> Result<(), SecretError> {
        if !self.secrets.contains_key(id) {
            return Err(SecretError::SecretNotFound(SecretId::new(id)));
        }
        self.secrets.insert(id.to_string(), new_secret.clone());
        Ok(())
    }

    fn secrets_expiring_within(&self, now: i64, window_ms: i64) -> Vec<&str> {
        self.secrets
            .iter()
            .filter(|(_, entry)| {
                entry
                    .metadata
                    .expires_at
                    .is_some_and(|exp| exp > now && exp <= now + window_ms)
            })
            .map(|(k, _)| k.as_str())
            .collect()
    }

    fn flush(&mut self) -> Result<(), SecretError> {
        // In-memory: no-op
        Ok(())
    }

    fn backend_info(&self) -> BackendInfo {
        BackendInfo {
            backend_type: "in-memory".to_string(),
            supports_encryption_at_rest: false,
            supports_versioning: false,
            supports_audit: false,
            max_secret_size_bytes: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{SecretMetadata, SecretType, SecretValue};
    use rune_permissions::ClassificationLevel;

    fn make_entry(id: &str) -> SecretEntry {
        SecretEntry::new(
            SecretId::new(id),
            SecretValue::from_str("test-value"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "admin")
                .with_timestamps(100, 100),
        )
    }

    fn make_expiring_entry(id: &str, expires_at: i64) -> SecretEntry {
        SecretEntry::new(
            SecretId::new(id),
            SecretValue::from_str("test-value"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "admin")
                .with_timestamps(100, 100)
                .with_expires_at(expires_at),
        )
    }

    #[test]
    fn test_in_memory_backend_implements_trait() {
        let backend = InMemorySecretBackend::new();
        assert_eq!(backend.secret_count(), 0);
    }

    #[test]
    fn test_in_memory_backend_store_and_retrieve() {
        let mut backend = InMemorySecretBackend::new();
        let entry = make_entry("k1");
        backend.store_secret("k1", &entry).unwrap();
        let retrieved = backend.retrieve_secret("k1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id.as_str(), "k1");
    }

    #[test]
    fn test_in_memory_backend_delete() {
        let mut backend = InMemorySecretBackend::new();
        backend.store_secret("k1", &make_entry("k1")).unwrap();
        assert!(backend.delete_secret("k1").unwrap());
        assert!(!backend.secret_exists("k1"));
        assert!(!backend.delete_secret("k1").unwrap());
    }

    #[test]
    fn test_in_memory_backend_list_secrets() {
        let mut backend = InMemorySecretBackend::new();
        backend.store_secret("k1", &make_entry("k1")).unwrap();
        backend.store_secret("k2", &make_entry("k2")).unwrap();
        let mut ids = backend.list_secrets();
        ids.sort();
        assert_eq!(ids, vec!["k1", "k2"]);
    }

    #[test]
    fn test_in_memory_backend_secret_exists() {
        let mut backend = InMemorySecretBackend::new();
        assert!(!backend.secret_exists("k1"));
        backend.store_secret("k1", &make_entry("k1")).unwrap();
        assert!(backend.secret_exists("k1"));
    }

    #[test]
    fn test_in_memory_backend_flush() {
        let mut backend = InMemorySecretBackend::new();
        assert!(backend.flush().is_ok());
    }

    #[test]
    fn test_in_memory_backend_info() {
        let backend = InMemorySecretBackend::new();
        let info = backend.backend_info();
        assert_eq!(info.backend_type, "in-memory");
        assert!(!info.supports_encryption_at_rest);
    }

    #[test]
    fn test_in_memory_backend_rotate_secret() {
        let mut backend = InMemorySecretBackend::new();
        backend.store_secret("k1", &make_entry("k1")).unwrap();
        let new_entry = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("new-value"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "admin")
                .with_timestamps(200, 200),
        );
        backend.rotate_secret("k1", &new_entry).unwrap();
        let retrieved = backend.retrieve_secret("k1").unwrap();
        retrieved.value.expose_for(|bytes| assert_eq!(bytes, b"new-value"));
    }

    #[test]
    fn test_in_memory_backend_rotate_not_found() {
        let mut backend = InMemorySecretBackend::new();
        let result = backend.rotate_secret("nope", &make_entry("nope"));
        assert!(matches!(result, Err(SecretError::SecretNotFound(_))));
    }

    #[test]
    fn test_in_memory_backend_secrets_expiring_within() {
        let mut backend = InMemorySecretBackend::new();
        backend
            .store_secret("k1", &make_expiring_entry("k1", 500))
            .unwrap();
        backend
            .store_secret("k2", &make_expiring_entry("k2", 10000))
            .unwrap();
        backend
            .store_secret("k3", &make_entry("k3"))
            .unwrap();
        let expiring = backend.secrets_expiring_within(400, 200);
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0], "k1");
    }

    #[test]
    fn test_in_memory_backend_store_duplicate_rejected() {
        let mut backend = InMemorySecretBackend::new();
        backend.store_secret("k1", &make_entry("k1")).unwrap();
        let result = backend.store_secret("k1", &make_entry("k1"));
        assert!(matches!(result, Err(SecretError::SecretAlreadyExists(_))));
    }
}
