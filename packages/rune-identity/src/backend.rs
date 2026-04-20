// ═══════════════════════════════════════════════════════════════════════
// Identity Backend — Pluggable identity storage trait.
//
// Layer 3 defines the contract for storing and retrieving identity
// records, credential pointers, and MFA enrollment metadata.
// The actual credential material (password hashes, TOTP secrets,
// WebAuthn keys) lives in CredentialMaterialStore, not here.
// This separation reflects different lifecycle and access patterns:
// identity metadata is read-heavy, credential material is
// write-heavy with stricter access controls.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::IdentityError;
use crate::identity::{Identity, IdentityId};

// ── CredentialRecord (metadata pointer, not material) ─────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    pub record_id: String,
    pub identity_id: String,
    pub credential_type: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub metadata: HashMap<String, String>,
}

impl CredentialRecord {
    pub fn new(record_id: &str, identity_id: &str, credential_type: &str, created_at: i64) -> Self {
        Self {
            record_id: record_id.to_string(),
            identity_id: identity_id.to_string(),
            credential_type: credential_type.to_string(),
            created_at,
            expires_at: None,
            revoked: false,
            metadata: HashMap::new(),
        }
    }

    pub fn with_expires_at(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }
}

// ── MfaEnrollment ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaEnrollment {
    pub enrollment_id: String,
    pub identity_id: String,
    pub factor_type: String,
    pub enrolled_at: i64,
    pub active: bool,
    pub metadata: HashMap<String, String>,
}

impl MfaEnrollment {
    pub fn new(enrollment_id: &str, identity_id: &str, factor_type: &str, enrolled_at: i64) -> Self {
        Self {
            enrollment_id: enrollment_id.to_string(),
            identity_id: identity_id.to_string(),
            factor_type: factor_type.to_string(),
            enrolled_at,
            active: true,
            metadata: HashMap::new(),
        }
    }
}

// ── BackendInfo ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityBackendInfo {
    pub backend_type: String,
    pub supports_mfa_enrollment: bool,
}

// ── IdentityBackend trait ─────────────────────────────────────

pub trait IdentityBackend {
    fn store_identity(&mut self, identity: &Identity) -> Result<(), IdentityError>;
    fn retrieve_identity(&self, id: &IdentityId) -> Option<&Identity>;
    fn delete_identity(&mut self, id: &IdentityId) -> Result<bool, IdentityError>;
    fn list_identities(&self) -> Vec<&str>;
    fn identity_count(&self) -> usize;
    fn identity_exists(&self, id: &IdentityId) -> bool;

    fn store_credential_record(&mut self, record: &CredentialRecord) -> Result<(), IdentityError>;
    fn retrieve_credential_record(&self, record_id: &str) -> Option<&CredentialRecord>;
    fn list_credential_records_for_identity(&self, identity_id: &str) -> Vec<&CredentialRecord>;
    fn revoke_credential_record(&mut self, record_id: &str) -> Result<bool, IdentityError>;

    fn store_mfa_enrollment(&mut self, enrollment: &MfaEnrollment) -> Result<(), IdentityError>;
    fn retrieve_mfa_enrollment(&self, enrollment_id: &str) -> Option<&MfaEnrollment>;
    fn list_mfa_enrollments_for_identity(&self, identity_id: &str) -> Vec<&MfaEnrollment>;
    fn delete_mfa_enrollment(&mut self, enrollment_id: &str) -> Result<bool, IdentityError>;

    fn flush(&mut self);
    fn backend_info(&self) -> IdentityBackendInfo;
}

// ── InMemoryIdentityBackend ───────────────────────────────────

pub struct InMemoryIdentityBackend {
    identities: HashMap<String, Identity>,
    credential_records: HashMap<String, CredentialRecord>,
    mfa_enrollments: HashMap<String, MfaEnrollment>,
}

impl InMemoryIdentityBackend {
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            credential_records: HashMap::new(),
            mfa_enrollments: HashMap::new(),
        }
    }
}

impl Default for InMemoryIdentityBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityBackend for InMemoryIdentityBackend {
    fn store_identity(&mut self, identity: &Identity) -> Result<(), IdentityError> {
        self.identities.insert(identity.id.as_str().to_string(), identity.clone());
        Ok(())
    }

    fn retrieve_identity(&self, id: &IdentityId) -> Option<&Identity> {
        self.identities.get(id.as_str())
    }

    fn delete_identity(&mut self, id: &IdentityId) -> Result<bool, IdentityError> {
        Ok(self.identities.remove(id.as_str()).is_some())
    }

    fn list_identities(&self) -> Vec<&str> {
        self.identities.keys().map(|k| k.as_str()).collect()
    }

    fn identity_count(&self) -> usize {
        self.identities.len()
    }

    fn identity_exists(&self, id: &IdentityId) -> bool {
        self.identities.contains_key(id.as_str())
    }

    fn store_credential_record(&mut self, record: &CredentialRecord) -> Result<(), IdentityError> {
        self.credential_records.insert(record.record_id.clone(), record.clone());
        Ok(())
    }

    fn retrieve_credential_record(&self, record_id: &str) -> Option<&CredentialRecord> {
        self.credential_records.get(record_id)
    }

    fn list_credential_records_for_identity(&self, identity_id: &str) -> Vec<&CredentialRecord> {
        self.credential_records.values()
            .filter(|r| r.identity_id == identity_id)
            .collect()
    }

    fn revoke_credential_record(&mut self, record_id: &str) -> Result<bool, IdentityError> {
        if let Some(record) = self.credential_records.get_mut(record_id) {
            record.revoked = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn store_mfa_enrollment(&mut self, enrollment: &MfaEnrollment) -> Result<(), IdentityError> {
        self.mfa_enrollments.insert(enrollment.enrollment_id.clone(), enrollment.clone());
        Ok(())
    }

    fn retrieve_mfa_enrollment(&self, enrollment_id: &str) -> Option<&MfaEnrollment> {
        self.mfa_enrollments.get(enrollment_id)
    }

    fn list_mfa_enrollments_for_identity(&self, identity_id: &str) -> Vec<&MfaEnrollment> {
        self.mfa_enrollments.values()
            .filter(|e| e.identity_id == identity_id)
            .collect()
    }

    fn delete_mfa_enrollment(&mut self, enrollment_id: &str) -> Result<bool, IdentityError> {
        Ok(self.mfa_enrollments.remove(enrollment_id).is_some())
    }

    fn flush(&mut self) {
        self.identities.clear();
        self.credential_records.clear();
        self.mfa_enrollments.clear();
    }

    fn backend_info(&self) -> IdentityBackendInfo {
        IdentityBackendInfo {
            backend_type: "in-memory".to_string(),
            supports_mfa_enrollment: true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_type::IdentityType;

    fn make_identity(id: &str) -> Identity {
        Identity::new(IdentityId::new(id), IdentityType::default_user())
            .display_name("Test User")
            .created_at(1000)
            .build()
    }

    #[test]
    fn test_store_and_retrieve_identity() {
        let mut backend = InMemoryIdentityBackend::new();
        let identity = make_identity("user:alice");
        backend.store_identity(&identity).unwrap();
        let retrieved = backend.retrieve_identity(&IdentityId::new("user:alice")).unwrap();
        assert_eq!(retrieved.id.as_str(), "user:alice");
    }

    #[test]
    fn test_delete_identity() {
        let mut backend = InMemoryIdentityBackend::new();
        backend.store_identity(&make_identity("user:alice")).unwrap();
        assert!(backend.delete_identity(&IdentityId::new("user:alice")).unwrap());
        assert!(!backend.delete_identity(&IdentityId::new("user:alice")).unwrap());
    }

    #[test]
    fn test_identity_count_and_exists() {
        let mut backend = InMemoryIdentityBackend::new();
        backend.store_identity(&make_identity("user:alice")).unwrap();
        backend.store_identity(&make_identity("user:bob")).unwrap();
        assert_eq!(backend.identity_count(), 2);
        assert!(backend.identity_exists(&IdentityId::new("user:alice")));
        assert!(!backend.identity_exists(&IdentityId::new("user:nobody")));
    }

    #[test]
    fn test_list_identities() {
        let mut backend = InMemoryIdentityBackend::new();
        backend.store_identity(&make_identity("user:alice")).unwrap();
        assert_eq!(backend.list_identities().len(), 1);
    }

    #[test]
    fn test_credential_record_store_and_retrieve() {
        let mut backend = InMemoryIdentityBackend::new();
        let record = CredentialRecord::new("cr-1", "user:alice", "password", 1000);
        backend.store_credential_record(&record).unwrap();
        let retrieved = backend.retrieve_credential_record("cr-1").unwrap();
        assert_eq!(retrieved.credential_type, "password");
    }

    #[test]
    fn test_credential_records_for_identity() {
        let mut backend = InMemoryIdentityBackend::new();
        backend.store_credential_record(&CredentialRecord::new("cr-1", "user:alice", "password", 1000)).unwrap();
        backend.store_credential_record(&CredentialRecord::new("cr-2", "user:alice", "totp", 1000)).unwrap();
        backend.store_credential_record(&CredentialRecord::new("cr-3", "user:bob", "password", 1000)).unwrap();
        assert_eq!(backend.list_credential_records_for_identity("user:alice").len(), 2);
    }

    #[test]
    fn test_revoke_credential_record() {
        let mut backend = InMemoryIdentityBackend::new();
        backend.store_credential_record(&CredentialRecord::new("cr-1", "user:alice", "password", 1000)).unwrap();
        assert!(backend.revoke_credential_record("cr-1").unwrap());
        assert!(backend.retrieve_credential_record("cr-1").unwrap().revoked);
        assert!(!backend.revoke_credential_record("nonexistent").unwrap());
    }

    #[test]
    fn test_mfa_enrollment_store_and_retrieve() {
        let mut backend = InMemoryIdentityBackend::new();
        let enrollment = MfaEnrollment::new("mfa-1", "user:alice", "totp", 1000);
        backend.store_mfa_enrollment(&enrollment).unwrap();
        let retrieved = backend.retrieve_mfa_enrollment("mfa-1").unwrap();
        assert_eq!(retrieved.factor_type, "totp");
    }

    #[test]
    fn test_mfa_enrollments_for_identity() {
        let mut backend = InMemoryIdentityBackend::new();
        backend.store_mfa_enrollment(&MfaEnrollment::new("mfa-1", "user:alice", "totp", 1000)).unwrap();
        backend.store_mfa_enrollment(&MfaEnrollment::new("mfa-2", "user:alice", "webauthn", 1000)).unwrap();
        assert_eq!(backend.list_mfa_enrollments_for_identity("user:alice").len(), 2);
    }

    #[test]
    fn test_delete_mfa_enrollment() {
        let mut backend = InMemoryIdentityBackend::new();
        backend.store_mfa_enrollment(&MfaEnrollment::new("mfa-1", "user:alice", "totp", 1000)).unwrap();
        assert!(backend.delete_mfa_enrollment("mfa-1").unwrap());
        assert!(!backend.delete_mfa_enrollment("mfa-1").unwrap());
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemoryIdentityBackend::new();
        backend.store_identity(&make_identity("user:alice")).unwrap();
        backend.store_credential_record(&CredentialRecord::new("cr-1", "user:alice", "password", 1000)).unwrap();
        backend.store_mfa_enrollment(&MfaEnrollment::new("mfa-1", "user:alice", "totp", 1000)).unwrap();
        backend.flush();
        assert_eq!(backend.identity_count(), 0);
    }

    #[test]
    fn test_backend_info() {
        let backend = InMemoryIdentityBackend::new();
        let info = backend.backend_info();
        assert_eq!(info.backend_type, "in-memory");
        assert!(info.supports_mfa_enrollment);
    }

    #[test]
    fn test_credential_record_expiry() {
        let record = CredentialRecord::new("cr-1", "user:alice", "password", 1000)
            .with_expires_at(5000);
        assert!(!record.is_expired(3000));
        assert!(record.is_expired(5000));
    }

    #[test]
    fn test_credential_record_no_expiry() {
        let record = CredentialRecord::new("cr-1", "user:alice", "password", 1000);
        assert!(!record.is_expired(999999));
    }
}
